# HTTP Backend Abstraction: Review And Completion Plan

Status: in progress; transport, request-auth, account, recovery-consumption, email-issuance and registration milestones
implemented on 2026-09-08. Full native/generated backend selection is not complete.
Reviewed: 2026-09-07. This extends architecture roadmap sections 4.12,
Phase 3, and 15.2; it does not replace the broader migration plan.

## Implementation Progress (2026-09-08)

- [x] Commit the review snapshot and probes before implementation (`37ec77559`).
- [x] Repair query decoding, raw-path contract, repeated headers and JSON errors.
- [x] Add a validated common route table and canonical identity type.
- [x] Implement Axum HTTP/TLS, middleware, body limits and observable lifecycle.
- [x] Run the shared conformance suite on both transports, including cancellation.
- [x] Add feature-isolated consumers, an embedding example and CI parity jobs.
- [ ] Complete streaming and shared built-in authentication/policy integration.
- [x] Prove an EON-defined authenticated database-backed CRUD example on both transports.
- [x] Merge the reviewed baseline into `v1` (`f4421989d`, fast-forward).
- [x] Extract built-in credential/CSRF/account-state policy and bounded password work.
- [x] Delegate native/generated `UserContext` and password helpers to shared runtime code.
- [x] Prove real built-in login/account revocation across native Actix and both adapters.
- [x] Commit the request-auth extraction on local `v1` (`fa6c1e6e4`).
- [x] Move login, account reads and password-change policy into the shared runtime.
- [x] Make password changes conditional and prove concurrency/revocation behavior.
- [x] Prove shared account operations over native Actix and both runtime transports.
- [x] Commit the account-service milestone on local `v1` (`99c1f51b9`).
- [x] Share verification/reset consumption and its transaction sequencing.
- [x] Enforce email binding and prove expiry, single use, rollback and cancellation.
- [x] Prove recovery and session revocation over native Actix and both runtime transports.
- [x] Commit and push request-auth/account/recovery milestones to `origin/v1` (`edad7d389`).
- [x] Extract recovery issuance, templates, delivery and anonymous request orchestration.
- [x] Require trusted email-link configuration, checked expiry and bounded/redacted delivery.
- [x] Prove actual issued email links over native Actix and both runtime transports.
- [x] Merge the verified baseline into `main` (`3ac6ffd78`, 27 CI jobs passed).
- [x] Move self-registration policy and transaction ownership into the shared runtime.
- [x] Prove registration rollback, cancellation, schema compatibility and HTTP parity.
- [ ] Migrate shared built-in policy services and native/generated application wiring.
- [ ] Execute external database/platform CI and production workload parity gates.

The adapters deliberately share a `matchit`-backed VSR route table instead of
duplicating native router translation. Their framework-native fallback services
provide transport, while one table defines validation, captures, precedence,
HEAD/OPTIONS and method errors. This refines the original target design below.
See [HTTP backend options](../../src/http_backends.md) for current scope and
compatibility. Actix remains the native/generated application implementation;
this milestone does not complete Phase 3 or add a CLI backend switch.

The [enterprise API example](../../../examples/enterprise_api/README.md) adds
the first database-backed slice. It compiles standard VSR EON resource policies
at build time and uses an example-local bearer verifier, live SQL grants and
transactional audit boundary. This does not migrate legacy built-in auth.
See its [local proof record](../../reviews/2026-09-08-enterprise-axum-proof.md).

The request-auth extraction moves built-in request policy, token claims and the existing
account-state fingerprint into `vsr-runtime::auth` with `auth-builtin`. The legacy
`UserContext` extractor is now a transport adapter over that policy, and password
helpers delegate to the shared bounded Tokio worker pool. A narrow
`RequestAuthenticator` and `require_authentication` wrapper support neutral
handlers without pretending the complete `AuthProvider` lifecycle is implemented.

`rest_macro_core::auth::builtin_request_authenticator` temporarily supplies key
configuration and the existing SQLx/Turso account repository. This bridge still
links the legacy facade; only the runtime policy itself is framework-independent.
Login, account-read and password-change business logic now lives in
`vsr-runtime::auth::accounts::AccountService`, with injected repository, signer,
policy and clock. Existing Actix endpoints delegate to it. Password changes use
an atomic old-hash/revision condition, preventing stale concurrent writes.
The SQLx/Turso and configured-signing adapters remain in the legacy facade via
`builtin_account_service`; this is not an Actix-free production application yet.
See the [account-service proof](../../reviews/2026-09-08-account-service-migration-proof.md).

Verification and reset consumption now live in `RecoveryService`, with driver-owned
transactions and shared expiry, token hashing, email binding and outcome mapping.
The SQLite/Turso bridge acquires a write reservation before token reads, and
Turso transaction-control awaits discard unfinished leases on cancellation.
See the [recovery proof](../../reviews/2026-09-08-recovery-service-migration-proof.md).

Recovery issuance and anonymous request orchestration now live in `RecoveryEmailService`.
Existing registration/admin transactions reuse `RecoveryEmailSender`, with the
configured provider bridge implementing the existing `Mailer` interface. This
preserves send-before-commit behavior, not durable/outbox delivery. Trusted public
URLs are now required; provider errors are redacted and delivery waits are bounded.
See the [email proof](../../reviews/2026-09-08-recovery-email-migration-proof.md).

Self-registration now lives in `RegistrationService`, including bounded password
hashing, the server-selected user role, account initialization, verification and
commit/rollback sequencing. The native handler retains extraction, trusted URL
resolution and rate limiting. Legacy base schemas remain supported without email;
partial schemas and initialization failures now fail closed. See the
[registration proof](../../reviews/2026-09-08-registration-migration-proof.md).

Next: extract admin changes while preserving authorization and transaction
boundaries. Durable recovery delivery and abuse/enumeration resistance remain
hardening gates. Shared cookie/extraction/rate-limit routing, row authorization,
streaming and native/generated bootstrap remain required. No CLI backend switch
is added by these milestones. See [HTTP backend options](../../src/http_backends.md#shared-account-operations).

## Review Snapshot And Scope (2026-09-07)

The following findings and verification describe `7c27c9bb3`, before the
implementation above. They are retained as the original review evidence.

The project has a usable low-level HTTP contract and one Actix implementation,
but not a backend-independent application server. Axum cannot currently replace
Actix through a feature flag or builder selection. Complete the existing
abstraction rather than introduce a second runtime or duplicate CRUD handlers.

Fresh `git fetch origin --prune` produced these relevant snapshots:

| Reference | Commit | HTTP backend state |
| --- | --- | --- |
| Local main / origin/main | f78d924d4 | Legacy Actix server; no vsr-runtime HTTP abstraction |
| origin/v1 | 7bd9fa0e2 | Neutral HTTP types and Actix adapter; incomplete production wiring |
| origin/phase2-auth-split-plan | 7b95551a4 | Same HTTP implementation as v1; adds auth facade notes and a Phase 2 plan |
| Local / origin/codex/dependency-upgrade-review | 7c27c9bb3 | Hardened Actix adapter; still no Axum adapter or production integration |

The other fetched branches (`worktree-phase0-vsr-core`, `macro_dev`, `demo`,
and `codex/v1-review-blockers`) contain no Axum adapter either. Only `origin`
is configured; this is a review of its fetched branches, not all external forks
or unadvertised PR refs. The latest Phase 2 plan does not implement the HTTP
replacement. The overarching roadmap was last committed at `9b7d3a970`.

Executable checks below used the review worktree at `7c27c9bb3`, not main/v1.
No production source, branch ancestry, existing service, or database was changed.

## What Exists

- `crates/vsr-runtime/src/http/mod.rs` defines `HttpServer`, `RouteRegistry`,
  `Handler`, request/response types, server configuration, and middleware policy.
  The contract-only crate builds with no default features and no HTTP framework
  in its normal dependency tree.
- `http/actix_adapter.rs` implements binding, handlers, TLS, CORS, compression,
  security headers, body limits, health probes, readiness, and graceful drain
  on the review branch. It is a useful starting point, not production parity.
- `http-axum` enables optional Axum/Tower dependencies only. There is no
  `AxumHttpServer`, Axum module, or second `HttpServer` implementation.
- `RouteRegistry` has no in-tree implementation or generated-code consumer;
  `HttpServer::serve` consumes a vector directly. The documented
  `MiddlewareAdapter` does not exist. Generic handlers can capture dependencies,
  but no shared built-in authentication pipeline connects them to those traits.

## Review Findings

### P1: The Live And Emitted Servers Bypass The Contract

`crates/rest_api_cli/src/commands/serve.rs:9,165` directly imports and constructs
Actix. The CLI has an unconditional Actix dependency and no HTTP-backend feature
selection. `commands/server.rs:1500,1564` emits `#[actix_web::main]` and an Actix
server. `rest_macro_core/src/compiler/codegen.rs:335,356` emits `ServiceConfig`
and imports the Actix re-export; `codegen/resource_impl.rs` emits Actix handlers.

Consequently adding only `AxumHttpServer` would not switch native serving,
emitted applications, auth, or storage routes. This is an architectural blocker,
not evidence that today's active server uses the new adapter.

### P1: Upstream v1 Still Has The Unhardened Adapter

At `origin/v1`, `actix_adapter.rs:76-168` ignores `_middleware`, always uses
plaintext `.bind`, and always returns readiness 200. TLS configuration is not
honored. The fixes in `7c27c9bb3` are not ancestors of `origin/v1`.

This finding is specific to the upstream adapter, not the review branch and
not proof of a TLS bypass in the legacy CLI. Any implementation branch based
on v1 must first carry forward the reviewed hardening and compatibility notes.

### P2: Authentication And Streaming Are Not Ready For Production Migration

`http/actix_adapter.rs:353-360` always constructs `identity: None`.
`http::AuthenticatedIdentity` and `auth::AuthenticatedIdentity` are separate,
incompatible types. No concrete `AuthProvider` or common request policy chain
is wired here. A consumer can write a handler wrapper, but built-in auth is
not automatically applied. `RequestContext` lacks peer address and matched
route information; trusted-proxy settings are explicitly rejected in this
adapter. Do not weaken that rejection until verified client identity exists.

`http/mod.rs:98-114,163-172` only supports buffered request/response bodies.
Current multipart/static delivery is still coupled to Actix in legacy modules.
Streaming uploads, large downloads, ranges and cancellation need an explicit
contract before those routes move. These are source-confirmed migration gaps,
not newly demonstrated vulnerabilities in the legacy application.

### P2: Request Decoding Does Not Match The Intended Contract

`http/actix_adapter.rs:321-331,416-438` preserves encoded query names/values.
A live probe of `?x=a+b&x=a%2Bb&na%6De=value` returns `a+b`, `a%2Bb`, and
`na%6De`, instead of form-decoded values and `name`. Filters/search parameters
would differ from the existing CLI, which uses `url::form_urlencoded`.

The public `path` is documented as decoded (`http/mod.rs:101`) but the live
probe returns `/inspect/a%20b`. Define raw target and decoded captures separately;
do not fix this by decoding an entire routing path or decoding twice. Encoded
slashes, traversal, malformed escapes and Unicode need explicit parity tests.

### P2: Response Headers Cannot Preserve Repeated Fields

`http/mod.rs:125-126` uses a single-value map and
`http/actix_adapter.rs:373-374` uses replacement insertion. Two `Set-Cookie`
fields, even represented with different casing, become one on the wire.
This blocks faithful session plus CSRF-cookie responses. Use a validated,
case-insensitive multi-value representation and append repeated response fields;
do not comma-join cookies. Incoming non-text header values are also currently
dropped by `to_str().ok()` and need an explicit preservation/rejection policy.

### P2: JSON Serialization Failure Is Reported As Success

`http/mod.rs:133-138` turns a serialization error into empty bytes with status
200 using `unwrap_or_default`. A custom failing serializer reproduces it.
Provide a fallible JSON constructor or centrally map this error to a stable 500
response. This must be shared behavior, not fixed independently in each adapter.

## Verification

| Check on 7c27c9bb3 | Result |
| --- | --- |
| `cargo +stable check -p vsr-runtime --no-default-features --locked` | Passed |
| Same with `--features http-axum` | Passed; dependency feature only |
| Axum-only consumer referring to `http::AxumHttpServer` | Failed with E0425: type does not exist |
| Existing all-feature HTTP adapter unit/integration tests | 14 passed, 0 failed |
| Additional public-API contract probes | 2 passed, 4 failed as described above |
| Shared-path GET/POST dispatch and in-flight graceful drain | Passed |

The first sandboxed HTTP test attempt could not bind loopback ports; its four
listener failures were environmental. The approved rerun passed all 14 tests,
including HTTPS with certificate verification, TLS/plaintext rejection, CORS,
compression, payload limit, and readiness. The four new failures persisted with
network permission and are contract findings, not sandbox failures.

Review-only reproducer sources are retained outside Cargo's test discovery:

- `docs/reviews/probes/http_backend_contract.rs`: six public-API tests.
- `docs/reviews/probes/http_backend_selection.rs`: missing-Axum compile probe.

They were temporarily installed as
`crates/vsr-runtime/tests/http_backend_review_probe.rs` and
`crates/vsr-runtime/examples/http_backend_selection_probe.rs`, then removed from
those locations. Commands used, with stable toolchain and debug information off:

```sh
cargo +stable test -p vsr-runtime --all-features http:: -- --nocapture
cargo +stable test -p vsr-runtime --all-features --test http_backend_review_probe -- --nocapture
cargo +stable check -p vsr-runtime --no-default-features --features http-axum --example http_backend_selection_probe --locked
```

Local evidence logs are `/private/tmp/vsr-http-existing-tests.log`,
`/private/tmp/vsr-http-contract-probes.log`, and
`/private/tmp/vsr-http-axum-implementation-probe.log`. No Axum HTTP, cross-platform,
external database, production-load or full workspace regression run was performed
in this review. Earlier broad test results do not establish backend parity.

## Target Design

Keep `vsr-core` foundational and the HTTP boundary in `vsr-runtime`. Do not add
a runtime dependency on `rest_macro_core`: it already depends on `vsr-runtime`
for storage, so that creates a cycle. The compiler/CLI should lower `ServiceSpec`
to a small runtime-owned service description, not move parser/Syn types into
the runtime. Emitters construct the same description or neutral handlers.

```text
compiler ServiceSpec -> runtime service description + route registrations
                             |
             shared auth/authz/CRUD/storage/audit services
                             |
                 RequestContext -> ResponseEnvelope
                             |
                  Actix adapter | Axum adapter
```

Reuse `Handler` and static `HttpServer` selection. Make `RouteRegistry` usable
with a validated `RouteTable` implementation and an error-returning registration
API. Keep framework state and extractors private. Use one canonical identity,
multi-value headers, a bounded streaming-body abstraction, raw target plus
decoded parameters, peer/client addresses, matched route, and request tracing
metadata. Shared policy wrappers authenticate and authorize before protected
handlers; adapters only implement transport and middleware mechanics.

Expose listener addresses, completion/failure, readiness and bounded draining
through a backend-neutral handle contract. The embedding application owns OS
signals and runtime setup. Clarify that Actix worker counts and Tokio executor
threads are not interchangeable; unsupported settings must error, not disappear.

## Implementation Sequence

### 1. Lock Down Contracts And Fix The Existing Adapter

Files: `vsr-runtime/src/http/{mod,actix_adapter}.rs`, `auth/mod.rs`, new common
HTTP contract tests, and associated documentation.

- Carry forward reviewed hardening before starting from v1. Preserve legacy
  compatibility; this plan authorizes no branch merge or publication.
- Promote the six probes into regression/conformance tests. Correct the raw-path
  contract explicitly rather than adopting the probe's whole-path decoding as
  the implementation. Fix query parsing, repeated headers and JSON errors.
- Implement validated routes: duplicate method/path errors, reserved probes,
  deterministic precedence, captures, catch-all grammar, HEAD/OPTIONS, 404/405
  and Allow behavior. Reject unsupported framework-specific route syntax early.
- Consolidate identity types and define auth, anonymous-client, CSRF, rate-limit,
  request-size, telemetry and error-mapping order. Fix placeholder documentation;
  add a middleware trait only if configuration plus shared wrappers is inadequate.

Gate: all existing Actix tests plus common protocol tests pass. Invalid startup
configuration fails before reporting a usable server; no silently ignored options.

### 2. Prove A Real Axum Adapter On The Same Handlers

Files: new `vsr-runtime/src/http/axum_adapter.rs`, HTTP exports, manifest features,
neutral test server support, and an example with the same handler/route factory.

- Implement `HttpServer` and the common lifecycle/route contracts. Keep Axum,
  Tower and Hyper types inside adapter code and feature dependencies.
- Use Axum's supported routing and graceful-shutdown APIs. Axum 0.8 uses
  `/{id}` and `/{*tail}`, not the `:id` syntax still mentioned in VSR docs.
  Its router does not support Actix-style regex captures. Validate/translate a
  VSR route grammar rather than passing framework patterns through unchanged.
  [Axum Router documentation](https://docs.rs/axum/latest/axum/struct.Router.html).
- Implement verified TLS and the same CORS/header/compression/body-limit rules.
  Wire readiness, completion and drain to the lifecycle contract; a plain HTTP
  hello-world is not acceptance. Use the native shutdown signal integration.
  [Axum Serve documentation](https://docs.rs/axum/latest/axum/serve/struct.Serve.html).

Gate: the same conformance suite runs against each backend; an Axum-only consumer
can bind, serve a real request and shut down without linking Actix. Also compile
both features together for comparison tests. Reject selected-but-disabled backends.

### 3. Move One Authenticated CRUD Slice Through Shared Services

Files: legacy `auth/*`, `authorization/*`, `commands/serve.rs`, new focused
`vsr-runtime` service modules, and DB interface/adapter code where necessary.

- Lower one actual resource from `ServiceSpec` into the runtime model. Move its
  validation, query, transaction, policy and audit behavior out of HTTP extractors.
- Separate built-in account/token operations from Actix `FromRequest`, request
  state and `HttpResponse`. Preserve account-state revocation, one-use token
  claims, bounded password work and fail-closed authorization.
- Adapt existing database contracts where required; do not add reverse crate
  dependencies or duplicate business rules per framework. Keep facade exports
  temporarily for existing Actix consumers and document their compatibility scope.

Gate: the same database-backed create/list/read/update/delete plus protected-route
tests pass on Actix and Axum, including demotion/deletion/password-reset revocation,
tenant/row rules, validation errors and audit outcomes. A public echo route is not
enough evidence to begin full migration.

### 4. Complete Native And Generated Application Integration

Files: `commands/{serve,server}.rs`, `compiler/codegen.rs`, `codegen/*`, runtime
storage/static/security modules, facade and CLI manifests.

- Migrate remaining handlers and managed-server lifecycle to shared runtime
  services. Retain CLI duties: configuration, database bootstrap, diagnostics,
  process management, signals, and backend selection.
- Change emitted resource handlers and built-in route registration to the same
  neutral interfaces. Backend choice changes bootstrap and Cargo features only,
  not business-handler source. Preserve deterministic expanded-code snapshots.
- Move multipart/static/range/conditional/S3-compatible HTTP transport behind
  adapters while retaining existing storage consistency/security rules. Bound
  memory with streaming and backpressure; propagate cancellation and errors.
- Keep Actix the default CLI/backend choice initially. Add explicit opt-in Axum
  selection to native and emitted paths, with feature validation. Both-enabled
  builds must have deterministic selection, not silently choose a different engine.
- Isolate legacy Actix facades from the Axum dependency graph; otherwise an
  Axum bootstrap would still compile the old framework through re-exports.

Gate: a representative native service and emitted CMS application pass the same
black-box suite on both backends. Their Axum-only normal dependency trees contain
no Actix. No HTTP framework types appear in shared services or emitted handlers.

### 5. Establish CI Parity And Rollout Gates

Files: `.github/workflows/generated-code-quality.yml`, focused backend conformance
tests, generated-project checks, migration notes, and the architecture roadmap.

- Matrix: runtime contracts only, Actix only, Axum only, both; native and emitted
  consumers; supported platforms and database profiles. Exercise isolated live
  PostgreSQL/MySQL jobs rather than infer parity from local SQLite/Turso tests.
- Cover Unicode/escapes, repeated query/header values, cookies/CSRF, trusted proxy
  chains, auth failures, request/decompression limits, streaming cancellation,
  range/HEAD/static responses, TLS, probes, startup errors and in-flight shutdown.
- Benchmark representative CRUD, authenticated requests and streamed uploads
  using identical data, limits and concurrency; compare latency, throughput and
  peak memory. Agree acceptance thresholds before using performance to choose
  a default. No default-backend switch is part of this plan.
- Document API changes to the experimental HTTP contract, readiness and runtime
  ownership. Keep an Actix rollback path during Axum opt-in rollout. Update Phase 3
  status only after native and emitted integration gates actually pass.

Completion means backend selection is a feature/bootstrap change with no handler
rewrite, and the parity matrix verifies that claim. An Axum feature that merely
compiles dependencies, or a standalone adapter disconnected from VSR services,
does not satisfy the requirement.
