# Improvement Plan

This document turns the high-level production backlog into an execution plan. It is intended to
answer two questions:

1. What is already implemented?
2. What should be built next, in what order, and with what shape?

For backup, restore, and replication planning, see `docs/backup-replication-roadmap.md`.

## Current Capability Snapshot

### Compression and static delivery

- Dynamic HTTP response compression is now wired into emitted servers through
  `runtime.compression.enabled`.
- Generated static mounts now serve `.br` and `.gz` companion files when
  `runtime.compression.static_precompressed` is enabled.
- Static files are served from the filesystem only.
- Static responses already support:
  - `ETag`
  - `Last-Modified`
  - `Cache-Control` profiles: `no-store`, `revalidate`, `immutable`
  - SPA fallback for HTML navigation requests
- `Vary: Accept-Encoding` when precompressed companion lookup is enabled
- `vsr build` now generates `.br` and `.gz` companion files into `<binary>.bundle/` when
  `runtime.compression.static_precompressed` is enabled.

### Existing runtime and security features

- JSON body size limits
- CORS configuration
- trusted proxy resolution
- built-in auth login and register rate limits
- security response headers
- built-in auth JWT settings
- TLS configuration
- static mount configuration for directory and SPA modes

### Known gaps

- no request/read timeout config
- no readiness/liveness endpoints
- no structured tracing or metrics hooks
- no embedded asset mode
- no distributed auth rate limiting
- no JWT key rotation
- no stronger CSP/Permissions-Policy support
- no broad Postgres/MySQL runtime coverage in CI

## Recommended Priority Order

### Phase 1: Compression and server operability

This is the highest-value near-term work because it improves production readiness without changing
the resource model or data contract.

Deliverables:

- response compression support
- precompressed static asset support
- request/read timeout configuration
- graceful shutdown support
- readiness and liveness endpoints

### Phase 2: Observability and deployment posture

Deliverables:

- structured request logging and tracing configuration
- metrics hook or metrics endpoint
- embedded asset mode for emitted servers
- stronger static/SPA deployment guidance

### Phase 3: Security hardening

Deliverables:

- distributed rate limiting
- JWT key rotation
- CSP and Permissions-Policy support
- configurable password policy

### Phase 4: Data and compatibility hardening

Deliverables:

- stronger migration diffing
- Postgres/MySQL drift inspection and runtime coverage
- OpenAPI error schema completeness
- compatibility testing for generated server output

### Phase 5: Durability and recovery posture

Deliverables:

- backup and restore contract under `database`
- backend-aware backup planning and doctor commands
- SQLite/TursoLocal snapshot + restore verification
- Postgres/MySQL replication and recovery guidance

## Compression MVP

### Goal

Add compression in a way that works for both dynamic API responses and static frontend assets,
while preserving the current caching model.

### What to build

1. Dynamic response compression for normal HTTP responses.
2. Precompressed static asset serving for frontend bundles.
3. Optional build-time asset compression in `vsr build`.

### Recommended config shape

Compression should not be added under `security`. It is transport/runtime behavior, not a security
policy.

Recommended new top-level block:

```eon
runtime: {
    compression: {
        mode: "dynamic"
        dynamic: {
            enabled: true
        }
        static: {
            precompressed: true
            gzip: true
            brotli: true
        }
    }
}
```

Recommended evolution path:

- MVP:
  - `runtime.compression.enabled: bool`
  - `runtime.compression.static_precompressed: bool`
- Follow-up:
  - `mode`
  - per-codec toggles
  - minimum size threshold
  - content-type allowlist

This keeps the first implementation small while leaving room for richer policy later.

### Recommended codec support

MVP:

- `gzip`
- `brotli`

Follow-up optional:

- `zstd`

Do not prioritize `deflate` unless a concrete compatibility need appears.

### Runtime behavior

#### Dynamic responses

- Add compression middleware to generated and emitted Actix servers.
- Keep it opt-in initially, then consider enabling it by default for production-focused templates.
- Ensure already encoded responses are not double-compressed.

#### Static responses

When a request targets a static asset:

1. Look at `Accept-Encoding`.
2. Prefer a precompressed variant when available.
3. Serve the compressed variant with:
   - `Content-Encoding`
   - `Vary: Accept-Encoding`
   - the existing `Cache-Control` policy
4. Fall back to the original file when no encoded variant exists.

Recommended preference order:

1. `br`
2. `gzip`
3. identity

### Build-time behavior

Extend `vsr build` so it can optionally emit:

- `*.br`
- `*.gz`

Recommended scope:

- JS
- CSS
- HTML
- SVG
- JSON manifests

Avoid compressing already compressed formats such as:

- PNG
- JPEG
- WebP
- MP4
- ZIP

### Source areas affected

- `crates/rest_macro_core/src/compiler/model.rs`
  Add runtime/compression config types.
- `crates/rest_macro_core/src/compiler/eon_parser.rs`
  Parse and validate the new config.
- `crates/rest_macro_core/src/compiler/codegen.rs`
  Emit runtime config into generated servers.
- `crates/rest_macro_core/src/static_files.rs`
  Add precompressed asset resolution and response headers.
- `crates/rest_macro_core/src/security.rs` or a new runtime/http module
  Add dynamic compression middleware helper if we want to keep the server bootstrap clean.
- `crates/rest_api_cli/src/commands/server.rs`
  Apply compression in emitted server scaffolding.
- `crates/rest_api_cli/src/commands/build/...`
  Add bundle compression during build, if the build pipeline is where assets are materialized.

## Compression Acceptance Criteria

- `Accept-Encoding: br` serves `.br` when present.
- `Accept-Encoding: gzip` serves `.gz` when present.
- compressed static responses include `Vary: Accept-Encoding`.
- existing cache profiles still apply correctly.
- SPA fallback still works for HTML navigation.
- missing assets still return `404` and do not fall through incorrectly.
- HEAD requests behave consistently.
- dynamic API responses are compressed when enabled.
- responses are not double-compressed.

## Suggested Task Breakdown

### Task 1: Runtime config model

- add `RuntimeConfig` to the compiler model
- add `CompressionConfig`
- keep defaults disabled for the first release

### Task 2: Dynamic compression

- add server middleware wiring
- add tests for API route compression
- document default behavior

Status: implemented for emitted servers and exposed for manual apps through
`core::runtime::compression_middleware(&module::runtime())`.

### Task 3: Precompressed static resolution

- extend static file resolution to look for `.br` and `.gz`
- add `Vary` and `Content-Encoding`
- add tests around negotiation and SPA fallback

Status: implemented for generated static mounts and the core static-file runtime. The remaining
compression follow-up is build-time asset generation in `vsr build`.

### Task 4: Build pipeline support

- add optional asset compression to `vsr build`
- skip already compressed file types
- document expected bundle layout

Status: implemented for `vsr build` bundle export. The remaining static/frontend follow-up is
deployment guidance and any future knobs for thresholds or codec policy.

### Task 5: Docs and examples

- add a compression example in `.eon`
- document deployment expectations behind a reverse proxy/CDN
- document cache strategy for hashed assets versus SPA shell HTML

## Other Recommended Near-Term Improvements

After compression, the next best return-on-effort items are:

1. timeouts
2. readiness/liveness endpoints
3. structured tracing configuration
4. metrics hook
5. embedded asset mode

These are operationally important and fit the same future `runtime` configuration family.
