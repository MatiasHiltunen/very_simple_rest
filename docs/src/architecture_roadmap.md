# Architecture Roadmap

Status: proposed
Owner: core engineering
Target horizon: 6–12 months, revisited quarterly

## 1. Purpose Of This Document

VSR has grown fast. The surface is now large enough — `.eon` parser, code generator,
emitted server projects, native runtime, OpenAPI, TypeScript client, authn/authz,
backup, migrations, secrets, TLS — that the next feature wave (aggregates, relation
embeds, viewer relations, public-ingest, and eventually GraphQL) will not fit cleanly
without a deliberate architectural pass.

This roadmap:

1. Sets the product thesis and the architectural principles that follow from it.
2. Catalogs the current structure honestly, including the files and boundaries that
   have outgrown their shape.
3. Proposes a target crate graph, module layout, CLI layout, feature-flag strategy,
   testing strategy, and observability strategy.
4. Stages the migration as small, independently shippable increments so we never
   stop the product from moving.

It is not a commitment to freeze features. It is a commitment to pay the
structural cost in the order that hurts the product least.

## 2. Product Thesis

VSR exists to let a small team (or a single operator plus AI) ship extremely
efficient, reliable, operationally boring backend services from a single
contract, and to keep supporting them for years without drifting from that
contract.

What that means in practice:

- **Data is the most valuable asset.** VSR's job is to guard it: correct
  migrations, strong authz, audit, backups that verify themselves, and a schema
  contract that does not lie.
- **A prototype on day one should still be correct on day 1000.** The same
  `.eon` that runs `vsr serve` in 10 seconds should emit a production server
  binary with the same behavior and semantics.
- **Close to the machine, light on infrastructure.** Single-binary deploys,
  SQLite/TursoLocal for local and edge, Postgres/MySQL for larger setups,
  object storage for assets and backups — all without a multi-container stack
  to boot the thing.
- **Prototype fast with AI, operate with confidence forever.** The declarative
  `.eon` contract is what an AI can reliably generate and reason about; the
  CLI is the operator's stable handle on what it produced.
- **Seamless portability across databases.** The same contract should target
  SQLite, TursoLocal, Postgres, and MySQL with runtime parity, and that parity
  should be enforced by CI, not by hope.
- **Modern Rust should make the architecture smaller, not cleverer.** Stable
  features such as async functions in traits, associated types, typed
  newtypes, `impl Trait`, `OnceLock`, and structured concurrency should reduce
  framework glue and macro magic. They are tools for clearer boundaries, not
  excuses for abstraction.

Every architectural decision in this document is evaluated against those goals.
If a decision does not make one of them better (or stop one from getting
worse), we do not do it yet.

## 3. Current State Assessment

### 3.1 Workspace Shape

Members currently declared in [Cargo.toml](../../Cargo.toml):

- `crates/rest_api_cli` — the `vsr` binary (package name `vsra`, default-run `vsr`)
- `crates/rest_macro` — the proc-macro facade (`#[derive(RestApi)]`, `rest_api_from_eon!`)
- `crates/rest_macro_core` — the compiler and runtime support library
- `examples/demo` — a derive-macro example
- top-level `very_simple_rest` crate — re-exports of runtime types

Not in the workspace:

- `crates/rest_macro_admin_ui_egui_final/` — orphaned egui/wasm admin UI stub; unused.
- `crates/rest_macro/src/authold` and `src/lib_fixed.rs` — dead files.
- `examples/family_app/family_app.expanded.rs` — generated artifact checked into tree.

This is the first signal that the workspace is carrying inventory it no longer
ships — easy to miss in code review, easy to break in CI, easy for a new
contributor to misread.

### 3.2 File Size Hot Spots

Measured in lines of code (`wc -l`) of current source, non-test-generated:

| File | LOC | What lives there today |
|---|---:|---|
| `crates/rest_macro_core/src/compiler/eon_parser.rs` | 11,455 | `.eon` syntax loading, validation, error reporting, tests |
| `crates/rest_macro_core/src/compiler/codegen.rs` | 10,317 | All `TokenStream` emission — resources, services, security, auth, authz, runtime, storage, migrations, OpenAPI glue |
| `crates/rest_api_cli/src/commands/serve.rs` | 7,278 | Native runtime: HTTP wiring, background lifecycle, signal handling, request paths, middleware |
| `crates/rest_macro_core/src/auth.rs` | 5,570 | JWT, password hashing, email OTP, session cookies, CSRF, user queries, admin bootstrap |
| `crates/rest_macro_core/src/authorization.rs` | 4,448 | Hybrid + RBAC models, scoped assignments, runtime checks, simulation |
| `crates/rest_macro_core/src/compiler/model.rs` | 4,103 | `.eon` shared AST + validation helpers |
| `crates/rest_macro_core/src/compiler/openapi.rs` | 3,984 | OpenAPI 3.x JSON rendering |
| `crates/rest_api_cli/src/commands/server.rs` | 3,974 | `server emit|expand|build|serve` orchestration |
| `crates/rest_api_cli/src/commands/client.rs` | 3,969 | TypeScript client generation + self-tests |
| `crates/rest_api_cli/src/commands/docs.rs` | 3,276 | `.eon` reference doc generator |
| `crates/rest_api_cli/src/commands/backup.rs` | 3,141 | Plan, doctor, snapshot, export, verify-restore, push, pull |
| `crates/rest_api_cli/src/commands/authz.rs` | 2,314 | `authz explain|simulate|runtime …` |
| `crates/rest_api_cli/src/commands/check.rs` | 2,232 | Strict schema validation + diagnostics |
| `crates/rest_api_cli/src/commands/migrate.rs` | 2,181 | Migration generation and drift checks |
| `crates/rest_api_cli/src/main.rs` | 2,700+ | Clap definitions + dispatch for every subcommand |

Total tracked workspace source is ~84k LOC. Roughly 65 % of that lives in nine
files. This is the central structural debt — unit testing a 10k-line `codegen.rs`
or a 7k-line `serve.rs` is not a thing humans or AI do well.

### 3.3 Module Boundaries As They Stand

`rest_macro_core` exposes: `auth`, `authorization`, `database`, `db`, `errors`,
`logging`, `runtime`, `secret`, `security`, `static_files`, `storage`, `tls`, and
(behind `codegen`) `compiler`. The `email` module is private. That public
surface mixes three genuinely distinct concerns that happen to sit in one crate:

1. **Runtime primitives** used by emitted servers and `vsr serve` alike —
   `auth`, `authorization`, `db`, `security`, `static_files`, `storage`, `tls`,
   `logging`, `runtime`, `secret`, `email`.
2. **Compiler** — parser, model, codegen, migrations, OpenAPI, derive parsing,
   source loading. All code that runs *before* the server runs.
3. **CLI plumbing leaking in** — `rpassword` in dependencies, interactive
   prompts referenced from runtime-facing files, etc.

`rest_api_cli` then re-hosts a second runtime inside `commands/serve.rs` — the
native `vsr serve` path is an entire Actix server built on top of
`rest_macro_core`'s primitives. That is why `serve.rs` is 7k LOC: it is not a
CLI command, it is a runtime.

### 3.4 CLI Surface

`vsr --help` today exposes 24 top-level commands and dozens of subcommands.
Categorized:

- Project lifecycle: `init`, `setup`, `create-admin`, `check-db`, `gen-env`.
- Code generation: `server {emit,expand,build}`, `client ts`, `openapi`, `docs`.
- Runtime: `serve`, `server serve`, `status`, `kill`, `reset`, `build`,
  `server build`, `clean`.
- Data: `migrate {auth,authz,derive,generate,check,check-derive,diff,inspect,apply}`,
  `check`.
- Operations: `doctor secrets`, `backup {plan,doctor,snapshot,export,verify-restore,push,pull}`,
  `replication doctor`.
- Authz: `authz {explain,simulate,runtime {list,create,delete,revoke,renew,history,evaluate}}`.
- Infra: `secrets infisical scaffold`, `tls self-signed`.

Problems visible from this layout:

- `vsr build` duplicates `vsr server build`. Same for `vsr serve` and
  `vsr server serve`. One of each is an alias with slightly different flag
  defaults, which is harder to document than just having one canonical form.
- Diagnostic tooling (`doctor`) is scattered: `backup doctor`,
  `doctor secrets`, `replication doctor` all exist. A user looking for "is my
  setup healthy?" has to know three places to look.
- `check-db`, `check`, `migrate check`, `migrate check-derive`, `backup
  verify-restore`, `doctor secrets`, `replication doctor`, `authz explain`,
  `authz simulate` all do some form of *validate a static or dynamic
  property*, but the vocabulary mixes `check`, `doctor`, `verify-restore`,
  `explain`, and `simulate`.
- `create-admin` is a top-level command; `setup` also creates an admin user;
  `init` creates a project. A user hitting `vsr --help` cold has to figure out
  which one to run first.
- Eight commands repeat identical `--with-auth` (hidden, deprecated) and
  `--without-auth` flag pairs.
- `secrets infisical scaffold` is three levels deep for one provider; the
  nesting implies a plurality we have not built yet.

### 3.5 Feature Flags

Current flags:

- `rest_macro_core`: `codegen`, `sqlite`, `turso-local`, `postgres`, `mysql`.
- `vsra` (CLI): `sqlite`, `postgres`, `mysql`, `turso-local`, `aws-sdk-s3-backup`,
  `s3-backup`.
- `very_simple_rest`: `macros`, `sqlite`, `postgres`, `mysql`, `turso-local`.

Things that should be feature-gated but are not:

- `lettre` (email) is a mandatory dependency of `rest_macro_core` even when a
  service has no email/OTP flows.
- `object_store` and `reqwest` (HTTP client used by storage, backup, secrets)
  are mandatory.
- `rustls` + `rcgen` (TLS cert generation) are mandatory.
- `turso-local` is the only database feature with a distinct runtime code path;
  `postgres` and `mysql` are only wired through `sqlx` features and runtime URL
  parsing.

Things that should be features but do not exist:

- No `tracing`, `metrics`, `observability`, `otel` feature (grep confirms zero
  imports of `tracing`, `opentelemetry`, `metrics`, or `prometheus` anywhere).
- No `backup` feature; backup and replication subcommands always compile.
- No `admin-ui` feature; the admin dashboard is always linked.
- No placeholder `graphql` feature; the planned GraphQL surface has nowhere to
  live yet.

Net effect: `cargo build` of `vsra` pulls every optional capability in whether
or not the operator wants it, which makes a "minimum viable backend service"
binary larger and slower to compile than it needs to be.

### 3.6 Cross-Platform Story

Observed:

- `.github/workflows/generated-code-quality.yml` runs only on
  `ubuntu-latest`. There is no CI job for macOS or Windows.
- `crates/rest_api_cli/src/main.rs` has to gate out `#[tokio::main]` on
  Windows ARM64 (line 2424) because of known regressions.
- `commands/serve.rs`, `commands/serve_manager.rs`, `commands/client.rs`,
  `commands/tls.rs` all contain `cfg(windows)` / `cfg(unix)` branches for
  process lifecycle, signals, and permission bits.
- Recent commits explicitly mention "Windows ARM64 serve regressions" and
  "CLI process dying during Tokio" — cross-platform is not theoretical pain,
  it is shipping pain.

We are advertising portability but not enforcing it.

### 3.7 Test Story

Root `tests/` has ~44 integration files exercising generated services. This is
a real asset — the macro surface is heavily covered end-to-end. What is
missing:

- Almost no pure unit tests for the parser (`eon_parser.rs` has 109
  `#[cfg(test)]` mentions but no isolated test crate).
- No property/fuzz coverage for `.eon` parsing — valuable given that AIs and
  humans both generate it.
- No runtime integration for Postgres/MySQL in CI (SQLite only).
- No emitted-server smoke test on Windows or macOS.
- No compatibility snapshot for OpenAPI output — any accidental change is
  invisible until a downstream client breaks.
- `examples/family_app/family_app.expanded.rs` is checked in (7 lines in git
  status show it unstaged) — an accidentally drifting snapshot.

### 3.8 Summary Of Structural Debt

Ranked by how much it blocks the next feature wave:

1. Monolithic `codegen.rs`, `eon_parser.rs`, `serve.rs`, `auth.rs`. These will
   fight every new primitive (aggregates, embeds, GraphQL, audit envelopes).
2. CLI that grew by accretion. New operators cannot model the tool from
   `--help`.
3. No observability spine. We cannot responsibly ship multi-tenant production
   guidance without structured logs, metrics, and request tracing.
4. Cross-platform is a CI blind spot.
5. Feature flags do not express optionality, so every service pays for every
   capability.
6. No layering between "compiler that runs at build-time" and "runtime that
   runs in prod". They share a crate but have very different change rates,
   binary-size contributions, and test strategies.

## 4. Architectural Principles

These are the rules of the road. Future PRs should be able to cite them.

### 4.1 Contract First, Always

The `.eon` file is the single source of truth. Every generated artifact —
migrations, emitted servers, OpenAPI, `.proto`, GraphQL schema, generated
clients, docs — is a pure function of that contract plus a versioned compiler.
No feature ships that violates this.

Why: this is what lets AI co-development work. The model generates the
contract; the compiler produces everything downstream; the operator audits the
contract, not 40 generated files.

### 4.2 One IR, Many Backends

New API-shape or schema-shape features must compile into a shared normalized
IR before branching into:

- macro codegen
- emitted-server codegen
- native `vsr serve` runtime
- OpenAPI rendering
- Protobuf / `.proto` rendering
- TypeScript client rendering
- Rust client rendering
- additional client-language emitters
- docs/reference rendering
- (future) GraphQL schema rendering
- (future) gRPC server rendering

This is already the stated rule in
[`docs/src/roadmaps/eon-vnext.md`](roadmaps/eon-vnext.md#shared-normalized-ir-first)
and [`docs/src/roadmaps/nordic-bridge-api-primitives.md`](roadmaps/nordic-bridge-api-primitives.md).
We promote it here to a workspace-wide invariant.

Why: GraphQL, gRPC, relation embeds, aggregates, and generated clients cannot
be implemented separately per surface. If they can be implemented separately,
they will drift, and the contract-first promise breaks.

### 4.3 Native `vsr serve` And Emitted Servers Must Be Behavior-Identical

For every runtime feature, the definition of done includes:

- runtime path wired and tested in `vsr serve`
- runtime path wired and tested in emitted server
- OpenAPI and generated clients updated
- at least one integration test that exercises the feature in both paths

Why: the dev loop uses `vsr serve`; production uses the emitted binary. If
they drift, we mis-sell the product. This is already VSR's hardest-won
invariant and we should not weaken it.

### 4.4 Layered, Not Monolithic

We adopt a clear layering:

```
+-----------------------------------------------------+
| vsr CLI (clap, UX, orchestration)                   |
+-----------------------------------------------------+
| vsr-ops (backup, secrets, migrations, tls, doctor)  |
+-----------------------------------------------------+
| vsr-codegen (parser, model, codegen, openapi, docs) |   <- build-time only
+-----------------------------------------------------+
| vsr-runtime (http, auth, authz, storage, static)    |   <- runtime only
+-----------------------------------------------------+
| vsr-core (errors, secret, config, db, tls, telemetry)|
+-----------------------------------------------------+
```

Lower layers never depend on higher layers. `vsr-runtime` does not know
`vsr-codegen` exists. `vsr-core` does not know `vsr-runtime` exists. This is
the structural change that lets us test layers in isolation.

Why: layer A should compile, test, and benchmark without layer B. Today
`rest_macro_core` forces every consumer to pull both the compiler and the
runtime. That is the single biggest reason we have 10k-line files: nobody can
pull on a thread without pulling the whole ball.

### 4.5 Feature Flags Are Architectural, Not Cosmetic

Every optional capability gets a feature flag. The rule is:

- A user who does not need email auth should not compile `lettre`.
- A user who does not need S3 backups should not compile `aws-sdk-s3`.
- A user who builds an emitted server should not compile the compiler.
- A user who does not use Postgres should not compile `sqlx/postgres`.

Feature flags are how we keep the binary honest.

Why: binary size and compile time compound. One capability added without a
feature flag taxes every deploy forever. A unified feature-flag policy also
lets us deprecate cleanly: "feature `legacy-derive-macro` is off by default in
0.3; removed in 0.4."

### 4.6 Cross-Platform Is A Contract

We support Linux, macOS (Apple Silicon + Intel), and Windows (x86_64 + ARM64).
That means:

- CI matrix covers all four.
- Platform-specific code lives in named modules
  (`platform::{unix,windows}::...`), not `cfg` islands scattered through
  business logic.
- The test suite has smoke coverage for the quirks that bit us before:
  process lifecycle, signals, path separators, cert stores, tokio runtime
  flavor on Windows ARM64.

Why: Windows regressions are recurring because Linux is the only enforced
platform. Nordic Bridge and similar real-world consumers run on Windows or
macOS. A portability promise we do not enforce costs trust.

### 4.7 Observability Is A Day-One Concern, Not A Day-Ninety One

Structured tracing, metrics, and request logging are runtime primitives, not
add-ons. They ship behind a feature flag, but the feature is on by default for
production templates.

Why: the top-line product promise includes "operational support during the
entire lifetime of the service". That is not credible without spans, metrics,
and at least one standard integration point (OpenTelemetry).

### 4.8 No Half-Deprecations

Deprecated flags, commands, and code paths get a version gate and a removal
date. We either:

- hide them and remove in the next minor (current `--with-auth` pattern), or
- emit a warning with a migration hint and remove in the following minor.

Why: the current CLI has eight copies of `--with-auth` hidden forever. That
is a permanent tax on reading the code.

### 4.9 The Most Valuable Asset Is The Data

Everything that touches data — migrations, authz, backups, audit, restore
verification — is treated as a *safety-critical* subsystem. That means:

- test coverage is an acceptance criterion, not a follow-up.
- defaults are conservative (deny-by-default authz, require opt-in for
  destructive ops, `--force` required for clobbering files).
- schema changes are diffable and auditable, not implicit.
- backups that cannot `verify-restore` are not backups.

Why: this is the product promise. Everything else is in service of it.

### 4.10 Diagnostics Are The Product

When `vsr check` rejects an `.eon` file or `vsr serve` refuses to start, the
error message *is* the user experience at that moment. We treat diagnostics
with the same rigor as features:

- Every parser error carries a source span (file, line, column, snippet) and
  a suggested fix when one is obvious.
- Every runtime failure-to-start emits a single structured cause
  (configuration, secrets, database, TLS, port-in-use) rather than a Rust
  panic chain.
- `doctor` subcommands emit machine-readable JSON in addition to human text,
  so AIs and CI pipelines can consume them.
- Error codes are stable (e.g. `EON-E0023`) and documented in the reference
  so searches find authoritative explanations.

Why: an operator debugging a prod incident at 3 AM and an AI agent diagnosing
a failed build consume the same error text. Poor diagnostics cost hours in
both cases. Our contract-first promise only holds if compiler and runtime
errors are precise enough to act on without reading our source.

### 4.11 Diagnostics And Codegen Must Be Deterministic

Given the same `.eon`, the same compiler version, and the same feature set,
the compiler produces byte-identical output: identical generated Rust,
identical migrations, identical OpenAPI, identical TypeScript. No timestamps,
no HashMap iteration order, no absolute paths leaked into artifacts.

Why: determinism makes snapshot tests viable, diffs reviewable, and caches
sound. It also is the only way a user can trust that `git diff` on a
generated file reflects their contract change, nothing else.

### 4.12 Trait Seams Over Concrete Types

Every major subsystem is consumed through a trait, not a concrete type.
Default implementations ship in-tree; alternative implementations are
compile-time swappable via feature flags or dependency injection. The
architectural contract — not a specific implementation — is what the rest of
the system depends on.

These traits are not placeholder abstractions. They are the vocabulary of the
runtime: request context, database dialect, authenticated identity, policy
decision, response envelope, emitted artifact, and service lifecycle. No
framework or vendor type (`actix_web::HttpRequest`, `axum::Router`,
`sqlx::Pool`, S3 client, etc.) crosses a public VSR seam. Those types are
contained in adapter modules.

Mandatory trait seams:

- `HttpServer` — build an HTTP app from a `ServiceSpec`. Default: actix.
  Swappable: axum.
- `DbPool` + `DbDialect` — connection pool and dialect adapter. Default:
  `sqlx`-backed. Swappable: Turso's native driver, future native Postgres.
- `AuthProvider` — JWT / password / session / OTP identity. Default: the
  built-in in-process provider. Swappable: external OIDC, SSO.
- `AuthzEngine` — evaluate hybrid + RBAC + row-policy checks. Default: the
  built-in engine. Swappable: external policy engine (OPA, Cedar) via a
  bridging adapter.
- `ObjectStorage` — local FS, S3-compat, Azure, GCS. Default: local FS.
  Swappable: via `object_store`.
- `SecretProvider` — env, Infisical, Vault, AWS Secrets Manager. Default:
  env + `.env`.
- `RateLimitStore` — in-process (default) or distributed (Redis).
- `AuditSink` — transactional DB sink (default), append-only log, external
  SIEM.
- `BackupTarget` — object store, local FS, stdout.
- `TelemetrySink` — `tracing` subscriber + metrics registry. Default:
  stdout + Prometheus. Swappable: OTel collector.
- `MigrationEngine` — forward/diff/apply over a dialect.
- `Clock` and `IdGenerator` — injectable for determinism in tests.

For HTTP specifically, the seam is split into three layers:

- `RouteRegistry` receives generated resource routes and handlers written
  against VSR-owned request/response types.
- `HttpServer` owns binding, listener lifecycle, graceful shutdown, and
  readiness.
- `MiddlewareAdapter` maps framework-agnostic middleware logic into the
  selected framework's layer/middleware model.

Actix and axum then become implementations of the same contract. Handlers,
auth, authz, storage, audit, and generated CRUD logic are written once.

Rules:

- The trait lives in `vsr-core` (or `vsr-runtime` when it only matters at
  request time). The default implementation lives behind a default-on
  feature flag. Alternatives live behind their own features and never leak
  types across the seam.
- Trait APIs speak in VSR domain types (`ServiceSpec`, `RequestContext`,
  `ResponseEnvelope`, `DbDialect`, `PolicyDecision`, `AuditEvent`). Adapter
  modules translate to and from framework/vendor types at the edge.
- Traits favor `async fn` (stable since Rust 1.75) where the operation is
  genuinely async. Sync operations stay sync. Avoid `async_trait` macro —
  it hides boxing we do not need.
- Associated types carry implementation-specific handles and streams without
  exposing their concrete crates. Use GATs where borrowed row/stream lifetimes
  make the contract more precise than boxing.
- Prefer static dispatch (`impl Trait`, generic builders, sealed extension
  traits) inside a selected backend. Use trait objects only at explicit
  runtime-selection boundaries.
- Each seam has a `Null`/`InMemory` implementation in `vsr-core::testing`
  so every consumer can unit-test against a fake.
- Swapping a seam is a `Cargo.toml` edit plus (for runtime-chosen seams) a
  single builder call — never a source rewrite.

Why: this is how we earn the right to say "actix now, axum later" without
pretending it is a free swap. A genuine seam makes the swap mechanical —
one implementation, one integration test per backend, done. It also makes
VSR embeddable: a consumer replacing our auth with their SSO shim is a
supported path, not a fork.

### 4.13 Compiler-Generated Source Over Proc-Macros

VSR has two ways to turn a contract into a running service today:

1. `#[derive(RestApi)]` / `rest_api_from_eon!` — proc-macros that expand
   `.eon` into Rust at compile time inside the consumer crate.
2. `vsr server emit` — the CLI compiler that writes a plain Rust project to
   disk.

Long-term direction: **the CLI compiler is the primary path. The proc-macro
path is maintained as a thin convenience wrapper that re-enters the same
codegen library, and is a candidate for sunset.**

Reasons:

- **Readability.** Generated source on disk is reviewable by humans, AIs,
  `rustdoc`, and IDEs. Proc-macro output requires `cargo expand` and arrives
  as one large `TokenStream` with no structure. When things go wrong at 3
  AM, a file you can open beats a macro you cannot.
- **Compile time.** Proc-macros force `syn` + `quote` + full macro
  expansion into every consumer build. The CLI-emitted path pays that cost
  once, commits the output, and every subsequent `cargo build` is just
  compiling Rust. For a medium service this is the difference between a 90
  s cold build and a 25 s one.
- **Debuggability.** Stepping into generated code in `gdb`/`lldb`/`rust-
  analyzer` works. Stepping into `derive` expansion does not, reliably,
  across toolchains and IDEs.
- **Auditability.** Security and compliance reviews can diff generated Rust.
  They cannot meaningfully diff proc-macro token streams.
- **AI ergonomics.** AI agents read and edit Rust source files
  confidently; they hallucinate less when the output is a file they can
  list, open, and `grep`. Procedural macros are adversarial to that.
- **Determinism.** §4.11 is much easier to enforce on emitted source (read
  the file back, compare) than on macro output across compiler versions.
- **IR and source sharing.** Both paths funnel through the same `vsr-codegen`
  IR and source-first emitters. The proc-macro path may lower generated files
  into a token stream for compatibility, but it must not own a second emitter.
  If that adapter becomes unreadable or macro-specific, we sunset it instead
  of preserving two generators.

What we are *not* doing:

- We are not ripping out `#[derive(RestApi)]` before consumers have
  migrated. See the sunset plan in §9.
- We are not banning proc-macros where they earn their keep (e.g. small
  derive macros for boilerplate on hand-written `vsr-runtime` types).

Why: the product promise is "efficient, reliable, operationally boring
services from a contract." Emitted Rust source *is* that contract in a form
every tool understands. Proc-macros were a useful prototype; they are no
longer the right product shape.

### 4.14 Modern Stable Rust Is A Design Tool

The refactor should lean on modern stable Rust where it removes whole classes
of glue code:

- `async fn` in traits for runtime adapters instead of `async_trait` wrappers.
- Associated types and GATs for database rows, pagination streams, storage
  cursors, and framework handles.
- `impl Trait` return types and sealed traits for internal static dispatch.
- `#[non_exhaustive]` config and IR structs so generated code can evolve
  without forcing every consumer to rebuild their constructors.
- Newtypes for IDs, tenant keys, secrets, policy names, and generated symbol
  names so compiler errors catch cross-domain mistakes.
- `OnceLock`/`LazyLock` for process-wide registries instead of ad hoc globals.
- `tokio::task::JoinSet` and cancellation tokens for server/background task
  lifecycles.
- `Cow`, `Arc<str>`, and borrowed views in hot parser/codegen paths where
  they reduce allocation without making APIs obscure.

Rules:

- Stay on stable Rust; no nightly-only architecture.
- Modern features must make generated code smaller, trait contracts clearer,
  or tests simpler. Otherwise use the plain version.
- Runtime traits must be understandable from `cargo doc` without reading an
  adapter implementation.

### 4.15 Protocol And Client Generation Are Extension Points

REST is the current production surface. GraphQL, protobuf, and gRPC are future
surfaces that must be made possible by the groundwork, not bolted on later.
The compiler therefore exposes two explicit extension contracts:

- `ProtocolEmitter` — turns IR into a protocol artifact: OpenAPI, GraphQL SDL,
  `.proto`, or future protocol descriptions.
- `ClientGenerator` — turns IR plus a selected protocol surface into a
  language client: TypeScript today, Rust next, then additional languages such
  as Go, Python, Kotlin, or Swift when demand justifies them.

Rules:

- Client generators consume the same normalized IR and capability metadata as
  OpenAPI and server generation. They do not parse generated Rust, OpenAPI, or
  each other's output as their source of truth.
- Rust is the next client target after TypeScript because it unlocks
  multi-service VSR systems without hand-writing HTTP bindings between
  services.
- `.proto` generation is treated as a protocol artifact even before a gRPC
  server exists. The `.proto` output lets us validate naming, scalar mapping,
  streaming boundaries, and backward-compatibility rules early.
- A future gRPC server is an adapter over the same service/action IR used by
  REST and GraphQL. Resource semantics, auth, authz, audit, validation, and
  database behavior stay in VSR-owned runtime logic.
- Future `.eon` service-to-service declarations should describe dependencies
  at the contract level: remote service name, generated client target,
  protocol preference, timeout/retry policy, auth mechanism, and version
  compatibility. This roadmap does not implement that syntax, but the IR and
  generator registry must leave room for it.

Why: multi-service architecture should be designed around contracts, not
around hand-written HTTP clients. If the first extra client or protocol
requires special paths, every later language and protocol will inherit that
debt.

## 5. Target Workspace Structure

The target workspace, after migration. Names are subject to bikeshedding; the
structure is not.

```
very_simple_rest/
├── crates/
│   ├── vsr-core/               # errors, config, secret, db, tls primitives, telemetry hooks
│   ├── vsr-runtime/            # framework-neutral HTTP adapters, auth, authz, storage, middleware
│   ├── vsr-codegen/            # parser, model, codegen, openapi, docs, migrations
│   ├── vsr-ops/                # backup, secrets, doctor, replication
│   ├── vsr-cli/                # the `vsr` binary — thin dispatcher over vsr-codegen and vsr-ops
│   ├── vsr-macro/              # proc-macro facade (#[derive(RestApi)], rest_api_from_eon!)
│   └── vsr/                    # top-level facade crate: re-exports + default features
├── examples/
│   ├── minimal/                # smallest runnable .eon + README
│   ├── cms/                    # replaces current cms example
│   ├── family_app/             # authorization-heavy
│   └── bridgeboard/            # large consumer snapshot
├── tests/
│   ├── contract/               # .eon → generated artifact snapshot tests
│   ├── runtime/                # vsr serve + emitted-server parity
│   ├── cross_backend/          # same .eon against sqlite/postgres/mysql/turso-local
│   └── platform/               # windows/macos/linux smoke tests
├── docs/
└── scripts/
```

Notes:

- Package names use hyphens (`vsr-core`) so the crate-path spelling (`vsr_core`)
  is unambiguous. The published names can still be `vsra`, `very_simple_rest`,
  etc. if crates.io ownership makes renaming expensive; the workspace layout is
  what matters.
- `vsr` at the top is a facade crate that chooses a default feature set and
  re-exports the minimum types an application needs. Consumers depend on `vsr`,
  not on the individual layers, unless they want to.
- `examples/demo` and the dead `authold`/`lib_fixed.rs`/`rest_macro_admin_ui_egui_final`
  artifacts are deleted as part of the migration.

### 5.1 `vsr-core`

Owns primitives that every other layer needs and nothing else:

- `error` — shared error type, conversion traits, diagnostic spans.
- `config` — env parsing, `.env` loading, config source precedence.
- `secret` — `SecretRef`, provider registry, redaction.
- `db` — connection pool abstraction with per-backend adapters (SQLite,
  TursoLocal, Postgres, MySQL) behind feature flags. No business logic.
- `tls` — cert/key loading, no rcgen generation (that moves to `vsr-ops`).
- `telemetry` — `tracing` subscriber setup, metrics registry, request-scoped
  context. Feature-gated; stubs compile to no-ops when disabled.

Deliberately excluded: no HTTP, no auth, no codegen, no CLI.

### 5.2 `vsr-runtime`

Owns the long-running server. Everything that ends up inside a running binary
— whether generated, emitted, or run via `vsr serve` — comes from here.
The public API is framework-neutral: Actix is the default adapter, not the
runtime contract.

**Public shape is the trait seams defined in §4.12.** Modules below are the
default implementations; consumers depend on the traits, not on these
modules. Swapping actix for axum, or the default authz engine for Cedar, is
a matter of enabling a different feature and wiring a different impl.

Module map (replaces current `rest_macro_core` runtime surface):

- `http/` — defines the `HttpServer` trait; ships the actix implementation
  behind `http-actix` (default). An `http-axum` implementation lives next to
  it behind a feature of the same name.
  - `http/server.rs` — `HttpServer` trait and the `ServiceSpec → App`
    builder.
  - `http/route.rs` — `RouteRegistry`, `RequestContext`, `ResponseEnvelope`,
    and generated-handler signatures. No actix/axum types live here.
  - `http/adapter.rs` — `MiddlewareAdapter` and framework bridge traits.
  - `http/actix/` — actix wiring, middleware stack.
  - `http/axum/` — axum wiring (added when §15.2 decides).
  - `http/middleware/` — framework-agnostic middleware *logic*; thin
    framework-specific adapters in `actix/`/`axum/`.
  - `http/health.rs` — readiness/liveness endpoints (new, framework-agnostic).
  - `http/shutdown.rs` — graceful shutdown helper (new, uses
    `tokio::task::JoinSet` for structured concurrency).
- `auth/` — defines the `AuthProvider` trait; splits the current 5,570-line
  `auth.rs` into:
  - `auth/jwt.rs` — JWT signing/verification, `KeyProvider` trait for
    rotation seams.
  - `auth/password.rs` — bcrypt, `PasswordPolicy` trait.
  - `auth/sessions.rs` — cookie + CSRF.
  - `auth/email.rs` — OTP and verification emails, `Mailer` trait.
  - `auth/handlers.rs` — login/register/logout/management routes — written
    once against `AuthProvider`, wired per-framework via `http/*/adapters`.
  - `auth/admin.rs` — built-in admin bootstrap.
  - `auth/settings.rs` — `AuthSettings` and related config types.
- `authz/` — defines the `AuthzEngine` trait; splits the 4,448-line
  `authorization.rs`:
  - `authz/model.rs` — compiled authz model types.
  - `authz/eval.rs` — default `AuthzEngine` implementation (hybrid + RBAC).
  - `authz/rbac.rs`, `authz/hybrid.rs` — helpers.
  - `authz/assignments.rs` — persisted runtime assignment CRUD.
  - `authz/audit.rs` — emission to the `AuditSink` trait.
  - `authz/external/` — adapter stubs for OPA and Cedar (behind
    `authz-opa` / `authz-cedar` features). Not built day one; the trait
    makes them possible.
- `storage/` — `ObjectStorage` trait; per-backend adapters (local FS,
  `object_store`, direct S3).
- `static_files/` — folder-ized; uses `ObjectStorage` for source.
- `rate_limit/` — `RateLimitStore` trait; in-process default, Redis impl
  behind `rate-limit-redis`.
- `middleware/security.rs` — CORS, trusted proxies, security headers —
  framework-agnostic logic, thin per-framework adapters.
- `audit/` — `AuditSink` trait; transactional DB sink as default.

Rationale: every sub-module becomes independently testable against trait
fakes from `vsr-core::testing`. Splitting `auth.rs` along JWT vs password vs
sessions vs handlers gives us natural fault lines for unit tests that do
not need a live database or a specific HTTP framework.

### 5.3 `vsr-codegen`

Owns the compiler. Nothing in this crate ever runs at server time.

Module map:

- `parser/` — today's `eon_parser.rs` (11,455 lines) split into:
  - `parser/lexer.rs`
  - `parser/syntax.rs` (top-level grammar)
  - `parser/resources.rs`, `parser/security.rs`, `parser/runtime.rs`,
    `parser/database.rs`, `parser/authz.rs` — sub-grammars per top-level key.
  - `parser/diagnostics.rs` — strict-mode warnings, error rendering.
  - `parser/validation.rs` — semantic checks that need the full model.
- `ir/` — the shared model (today's `compiler/model.rs`, 4,103 lines). This
  is the IR that principle 4.2 references. It owns:
  - `ir/resource.rs`, `ir/field.rs`, `ir/relation.rs`, `ir/policy.rs`,
    `ir/auth.rs`, `ir/runtime.rs`, `ir/database.rs`.
  - `ir/action.rs` — service/action shape shared by REST, GraphQL, and future
    gRPC surfaces.
  - `ir/service_link.rs` — future placeholder for `.eon`-declared
    service-to-service dependencies and generated-client wiring.
  - `ir/projection.rs` — new. Shared read-augmentation IR
    (`From`, `Template`, `AggregateCount`, `Exists`, `Embed`) per the
    Nordic Bridge roadmap.
- `emit/` — today's `codegen.rs` (10,317 lines) split by emitter:
  - `emit/resource.rs`, `emit/service.rs`, `emit/auth.rs`, `emit/authz.rs`,
    `emit/runtime.rs`, `emit/storage.rs`, `emit/security.rs`,
    `emit/migrations.rs`.
  - `emit/helpers.rs` — `quote!` helpers and token utilities (the current
    `option_string_tokens`, `vec_string_tokens`, etc.).
  - `emit/source.rs` — source-first `GeneratedProject` / `GeneratedFile`
    writer. It owns stable filenames, module layout, comments, `rustfmt`
    invocation, and snapshot-friendly formatting.
  - `emit/proc_macro.rs` — compatibility adapter that turns source-first
    output into the proc-macro-facing token stream while that surface exists.
- `protocol/` — protocol artifact emitters:
  - `protocol/openapi/` — today's 3,984-line `compiler/openapi.rs` split:
    `paths.rs`, `schemas.rs`, `security.rs`, `auth.rs`, `snapshot.rs`.
  - `protocol/graphql/` — future SDL/runtime schema emitter.
  - `protocol/protobuf/` — future `.proto` emitter, including scalar mapping,
    package naming, service/action mapping, and backward-compatibility checks.
- `clients/` — language client generators behind a `ClientGenerator` trait:
  - `clients/typescript/` — today's TypeScript generator.
  - `clients/rust/` — next target; emits a typed Rust client suitable for
    VSR-to-VSR service calls.
  - `clients/registry.rs` — dispatch, feature gating, and shared naming rules.
- `docs/` — today's 3,276-line `commands/docs.rs`, moved out of the CLI.
  The CLI keeps a thin wrapper that calls it.
- `derive/` — today's `compiler/derive_parser.rs` and the derive path.
  Long term this is a compatibility shim; no new feature is allowed to exist
  only in derive/proc-macro form.
- `migrations/` — today's `compiler/migrations.rs`, grown to include diffing,
  down-migration stubs, and drift inspection.

Every module in `emit/` is a pure function from IR to a typed generated
artifact (`GeneratedProject`, `GeneratedFile`, or a smaller emitter-specific
unit). `TokenStream` is an output adapter, not the compiler's internal shape.
That is how we write unit tests for it; today, testing `codegen.rs` requires
a whole service.

### 5.4 `vsr-ops`

Operational tooling. Everything the CLI calls that is not "serve a request"
or "emit code" lives here.

- `backup/` — today's `commands/backup.rs` (3,141 lines) split by verb:
  - `backup/plan.rs`, `backup/doctor.rs`, `backup/snapshot.rs`,
    `backup/export.rs`, `backup/verify_restore.rs`, `backup/push.rs`,
    `backup/pull.rs`.
- `secrets/` — today's `commands/secrets.rs`; grows a trait for providers
  beyond Infisical (Vault, AWS Secrets Manager, env-only) while keeping the
  current Infisical path as the default.
- `doctor/` — today's scattered doctor commands, consolidated. One place
  for every "is my setup healthy" check: `doctor secrets`, `doctor backup`,
  `doctor replication`, `doctor tls`, `doctor db`.
- `migrate/` — CLI-side migration orchestration (generate/check/diff/apply
  calling into `vsr-codegen`).
- `tls/` — the `vsr tls self-signed` path: `rcgen` cert generation. Kept here
  rather than `vsr-core` because cert generation is an operator action.
- `replication/` — `replication doctor` + future topology validation.

### 5.5 `vsr-cli`

Thin. Every `vsr <cmd>` handler is under 100 lines that parses flags, loads
the service, and calls into `vsr-codegen` or `vsr-ops`. Today's `serve.rs`
(7,278 lines) collapses dramatically because it moves to `vsr-runtime::http`.

### 5.6 `vsr-macro`

Replaces today's `crates/rest_macro`. Role unchanged — thin proc-macro
wrappers (`#[derive(RestApi)]`, `rest_api_from_eon!`). Gains dead-file
cleanup (`authold`, `lib_fixed.rs`) during the rename.

### 5.7 `vsr` (Facade)

Replaces today's top-level `very_simple_rest` crate. An application depends
on `vsr` when it wants the maintained library surface (derive macro or
`rest_api_from_eon!` + runtime). Expresses the default feature set and
re-exports the minimum useful types.

### 5.8 Crates.io Naming Strategy

The workspace crate names above are the aspirational target. Published names
are a separate decision because crates.io names are sticky:

- `vsra` (the current binary package) becomes `vsr` on publish if the
  crates.io `vsr` name is acquirable; otherwise we keep the binary named
  `vsr` while the package stays `vsra` and document that mismatch prominently.
- `very_simple_rest` (top-level) becomes `vsr` as the facade if we can. If
  not, we publish as `very_simple_rest` with the same internal module shape
  and re-export `vsr::*` as the documented entry point.
- Internal crates (`vsr-core`, `vsr-runtime`, `vsr-codegen`, `vsr-ops`,
  `vsr-macro`) are new names and can be registered fresh.

See Open Question §15.1 for the `vsr`-name decision window.

## 6. CLI Redesign

Target `vsr --help`, grouped by *what the user is doing*, not by what internal
module owns it:

```
vsr
├── init                   # Create a new project
├── new                    # Alias for init (kept during migration, removed in 0.4)
├── serve [FILE]           # Run a .eon service locally (canonical)
├── build [FILE]           # Build a production binary from a .eon service (canonical)
├── status                 # Show tracked serve instances
├── stop                   # (renamed from `kill`) Stop tracked serve instances
├── reset                  # Destroy local dev state
│
├── check [FILE]           # Strict static validation of a .eon service (merges check-db)
├── doctor                 # One place for runtime diagnostics
│   ├── all                # Run every doctor
│   ├── db                 # Current `check-db`
│   ├── secrets            # Current `doctor secrets`
│   ├── backup             # Current `backup doctor`
│   ├── replication        # Current `replication doctor`
│   └── tls                # Validate TLS config + expiry
│
├── schema                 # Everything about DB schema
│   ├── generate           # Current `migrate generate`
│   ├── diff               # Current `migrate diff`
│   ├── apply              # Current `migrate apply`
│   ├── inspect            # Current `migrate inspect`
│   └── auth               # Current `migrate auth` (still named for discoverability)
│
├── gen                    # All code generation (replaces scattered `server emit`, `client ts`, etc.)
│   ├── server             # Emit Rust project (current `server emit`)
│   ├── expand             # Current `server expand`
│   ├── client ts          # Current `client ts`
│   ├── client rust        # Future typed Rust client for service-to-service use
│   ├── openapi            # Current `openapi`
│   ├── proto              # Future `.proto` artifact generation
│   ├── graphql            # Future GraphQL schema generation
│   ├── docs               # Current `docs`
│   └── env                # Current `gen-env`
│
├── authz                  # Compiled authz tooling
│   ├── explain
│   ├── simulate
│   └── grants             # Renamed from `authz runtime`
│       ├── list, create, delete, revoke, renew, history, evaluate
│
├── backup                 # Data protection only
│   ├── plan, snapshot, export, verify, push, pull
│   # (`backup doctor` moved to `doctor backup`)
│
├── secrets                # Secret manager integration
│   ├── infisical scaffold
│   # Future providers plug in here
│
├── tls                    # Operator cert tooling
│   └── self-signed
│
└── admin                  # Built-in admin ops (replaces top-level create-admin + parts of setup)
    ├── create
    ├── reset-password
    └── list
```

Key principles applied:

- **One verb per concept.** `serve` exists once. `build` exists once.
  (Current duplication under `server {build,serve}` is kept as hidden aliases
  through 0.3 and removed in 0.4.)
- **One home for diagnostics.** Every "is this healthy?" answer lives under
  `doctor`. Searchable, documentable.
- **`gen` groups all generation.** New protocol artifacts and clients fit
  there naturally (`gen proto`, `gen graphql`, `gen client rust`,
  `gen client swift`) without a new top-level command.
- **`schema` subsumes `migrate`.** The word "migrate" implies a verb;
  "schema" describes what you are working on, and verbs go under it.
- **`grants` renames `authz runtime`.** Users do not think of persisted
  authz assignments as "runtime"; they think of them as grants.

Migration plan for the CLI is in §9.

## 7. Feature Flag Strategy

### 7.1 Axes

Feature flags fall on four independent axes.

1. **Database backend** — `sqlite`, `postgres`, `mysql`, `turso-local`.
   At least one must be enabled.
2. **Capabilities** — `auth-email`, `storage-local`, `storage-s3`,
   `storage-azure`, `storage-gcs`, `tls`, `compression`, `admin-ui`,
   `backup`, `replication`, `secrets-infisical`, `secrets-vault`,
   `secrets-aws`.
3. **Observability** — `tracing`, `metrics`, `otel`. All no-ops when off.
4. **Forward-looking** — `graphql` (placeholder, compiles empty), `proto`
   (protocol artifact generation), `grpc` (possible future RPC surface),
   `rust-client` (next client target), and `ws` (for eventual websocket
   subscriptions).

### 7.2 Per-Crate Feature Tables

`vsr-core`:

```
default = []
tls = ["rustls"]
tracing = ["dep:tracing", "dep:tracing-subscriber"]
metrics = ["dep:metrics", "dep:metrics-exporter-prometheus"]
otel = ["dep:opentelemetry", "tracing"]
sqlite = ["sqlx/sqlite"]
postgres = ["sqlx/postgres"]
mysql = ["sqlx/mysql"]
turso-local = ["sqlite", "dep:turso"]
```

`vsr-runtime`:

```
default = ["tls"]
tls = ["vsr-core/tls"]
auth-email = ["dep:lettre"]
storage-local = []
storage-s3 = ["dep:object_store"]
compression = ["actix-web/compress-brotli", "actix-web/compress-gzip"]
admin-ui = []
graphql = []
# database features re-exported from vsr-core
sqlite = ["vsr-core/sqlite"]
postgres = ["vsr-core/postgres"]
mysql = ["vsr-core/mysql"]
turso-local = ["vsr-core/turso-local"]
```

`vsr-codegen`:

```
default = []
openapi = []
typescript-client = []
rust-client = []
proto = []
graphql-schema = []
rust-emit = []
derive = ["dep:syn", "dep:quote", "dep:proc-macro2"]
```

`vsr-ops`:

```
default = ["backup", "secrets-infisical"]
backup = []
s3 = ["dep:aws-sdk-s3", "dep:aws-config"]
secrets-infisical = []
secrets-vault = []
secrets-aws = []
replication = []
```

`vsr-cli`:

```
default = [
  "sqlite", "turso-local", "postgres",
  "vsr-runtime/auth-email",
  "vsr-runtime/storage-local",
  "vsr-runtime/storage-s3",
  "vsr-codegen/openapi",
  "vsr-codegen/typescript-client",
  "vsr-codegen/rust-emit",
  "vsr-ops/backup",
  "vsr-ops/secrets-infisical",
  "tracing", "metrics",
]
# Minimal CLI for embedded/edge deployments:
minimal = ["sqlite"]
```

### 7.3 Feature Flag Rules

1. Every optional dep in `Cargo.toml` must be reachable from a feature.
2. No `default = ["everything"]`. Defaults reflect what a new user expects;
   power users opt out, not in.
3. CI builds `--no-default-features`, `--all-features`, and the `minimal`
   profile for each crate. Each must compile and pass its unit tests.
4. Features never change public types. Adding a feature adds code paths;
   turning it off compiles to stubs or omits the code, but never changes the
   shape of a function that was otherwise callable.

## 8. Cross-Platform Strategy

### 8.1 CI Matrix

CI expands to:

- ubuntu-latest (x86_64)
- macos-latest (aarch64)
- windows-latest (x86_64)
- windows-11-arm (aarch64) — as soon as GitHub exposes the runner reliably;
  until then, a nightly self-hosted runner on the team's dev hardware.

Every matrix cell runs:

- `cargo check --workspace --all-features`
- `cargo test --workspace` (sqlite only)
- `cargo test -p vsr-runtime --features postgres` against a Postgres
  service container
- `cargo test -p vsr-runtime --features mysql` against a MySQL service
  container
- `vsr check` on every `examples/*/api.eon`
- a smoke test for `vsr serve` + `vsr build` + running the built binary

### 8.2 Platform Isolation

Every `cfg(windows)`/`cfg(unix)` branch of more than a few lines moves to
`platform/{windows,unix}.rs`. Business logic calls a trait; the platform file
supplies the implementation. This is the pattern `serve_manager.rs` is 80 %
of the way to already — finish it and apply everywhere.

### 8.3 Known Windows Hazards

- tokio runtime flavor on Windows ARM64 (already handled in
  `main.rs:2424`). We document the reason and add a test that fails loudly if
  someone removes the cfg.
- Path separators in generated code (`PathBuf` everywhere; never concatenate
  paths with `/`).
- File locks on Windows when moving generated build artifacts. The ops
  layer should retry on `ERROR_SHARING_VIOLATION` or use rename-to-temp.
- `rustls` native cert store access on Windows — document the supported
  approaches and add a doctor check for it.

### 8.4 Cross-Backend SQL Portability

Portability across SQLite, TursoLocal, Postgres, and MySQL is a promise we
cannot keep with `sqlx` macros alone. Concrete rules:

- **JSON.** SQLite/Turso use `json` functions; Postgres uses `jsonb`
  operators; MySQL uses `JSON_*` functions. The IR expresses "JSON object
  field access"; the codegen chooses the dialect. No raw SQL with dialect
  assumptions appears in `.eon` or in emitted services.
- **Returning clauses.** SQLite ≥ 3.35 and Postgres support `RETURNING`;
  MySQL does not. Codegen emits a fetch-after-mutation path for MySQL.
- **Upsert.** `ON CONFLICT` (SQLite, Postgres) vs `ON DUPLICATE KEY UPDATE`
  (MySQL). Handled by the IR's `UpsertSpec` and dialect-specific emit.
- **Case-insensitive text.** SQLite `NOCASE`, Postgres `CITEXT`/`ILIKE`,
  MySQL `utf8mb4_*_ci`. The IR declares intent; the schema generator
  materializes it per backend.
- **Timestamps.** `TIMESTAMPTZ` in Postgres, `TIMESTAMP` in MySQL,
  `TEXT`/`INTEGER` epochs in SQLite. We normalize to UTC ISO-8601 in the
  API surface; storage type is backend-specific.
- **Transaction isolation defaults.** Documented per backend; the runtime
  asserts a minimum level at startup and refuses to run if the database is
  configured below it.

A matrix integration test fixture runs the same `.eon` against all four
backends and asserts identical HTTP responses for a canonical CRUD suite.
Divergence is a CI failure, not a wontfix.

## 9. Phased Migration Plan

This is explicit: we refactor in increments. At no point does `main` stop
shipping.

### Phase Dependency Graph

Phases are not strictly sequential. Parallelism where it exists:

```
Phase 0 ──▶ Phase 1 ─┬─▶ Phase 2 ──▶ Phase 3 ──▶ Phase 4 ──▶ Phase 5 ──▶ Phase 6 ──▶ Phase 7
                     │                                                                   ▲
                     └───────────── Phase 8 prep ─────────────────────────────────────────┘
                              (protocol/client IR sketches, no runtime code)
```

- Phase 1 (observability) and Phase 2 (auth split) can run in parallel with
  different owners; they touch different files.
- Phase 4 (codegen extract) unblocks Phase 7 (new primitives), but Phase 7
  design work (IR additions) can begin during Phase 4.
- Phase 5 (ops extract) is mostly independent of Phase 4 and can overlap.
- Phase 6 (CLI redesign) waits on Phases 3–5 so the handlers have stable
  destinations, but the naming proposal and deprecation wiring can land in
  Phase 1.

### Migration Commitments To Users

During the migration, we promise:

1. `main` is always releasable. Every phase lands behind tests; no long-lived
   refactor branches.
2. Public types in `very_simple_rest::*` remain importable at the same paths
   until a documented deprecation cycle ends.
3. CLI commands keep working under both old and new names for at least one
   minor release after a rename.
4. `.eon` files that parse today continue to parse — or fail with a
   diagnostic that names the replacement construct and the version it
   appeared in.
5. Generated artifacts (OpenAPI, TS client) remain structurally
   backward-compatible within a minor version; breaking changes bump the
   minor and ship a migration note.

### Phase 0 — Inventory And Preconditions (week 0)

- Delete dead code: `crates/rest_macro/src/authold`, `lib_fixed.rs`,
  `crates/rest_macro_admin_ui_egui_final/`,
  `examples/family_app/family_app.expanded.rs`.
- Turn on `cargo clippy -- -D warnings` in CI for every crate.
- Add `--no-default-features` and `--all-features` matrix jobs now, even
  though they will reveal breakage; fix that breakage in Phase 1.
- Add macOS and Windows to the CI matrix for `cargo check` only (tests follow
  in Phase 1).

Deliverable: cleaner tree, stricter baseline.

### Phase 1 — Observability Spine And Feature-Flag Hygiene (weeks 1–2)

- Add `vsr-core::telemetry` behind `tracing` + `metrics` features. Wire it
  into `vsr serve` first; emitted servers follow in Phase 3.
- Make `lettre`, `object_store`, `aws-sdk-s3` optional behind named features.
- Add structured request logging and `/healthz` + `/readyz` endpoints.
- Expand CI matrix to full platform × feature-set coverage.

Deliverable: observable `vsr serve`, honest binary sizes, green CI on all
platforms.

### Phase 2 — Split `auth.rs` And `authorization.rs` (weeks 3–4)

- In-place move `rest_macro_core::auth` → `rest_macro_core::auth::{jwt,
  password, sessions, email, handlers, admin, settings}`, preserving the
  public re-exports so nothing outside the crate notices.
- Same for `authorization.rs` → `authorization::{model, eval, rbac, hybrid,
  assignments, audit}`.
- Add unit tests per submodule (jwt, password, rbac, hybrid — the natural
  units).
- Reason to do this second: it is the highest-leverage split because every
  future authz/auth feature pays compounding interest against it.

Deliverable: two 4–5k-line files become ~12 sub-1k-line files with their
own tests.

### Phase 3 — Extract `vsr-runtime` From `rest_macro_core` (weeks 5–7)

- Create the `vsr-runtime` crate.
- Define the runtime contracts before moving implementations:
  `HttpServer`, `RouteRegistry`, `MiddlewareAdapter`, `AuthProvider`,
  `AuthzEngine`, `ObjectStorage`, `AuditSink`, `RateLimitStore`, and the
  VSR-owned request/response domain types they share.
- Move `auth/`, `authz/`, `storage/`, `static_files/`, `security/`, `tls/`
  (runtime parts), `http/` scaffolding into it.
- Move `commands/serve.rs` HTTP wiring into `vsr-runtime::http`. The CLI
  keeps a ~200-line command that builds the runtime from a `ServiceSpec` and
  starts it.
- Keep Actix as the default `http-actix` adapter, but make generated handlers
  compile without importing Actix types. Add an `http-axum` spike against one
  small example to validate the seam before the Phase 3 decision window closes.
- Emitted servers depend on `vsr-runtime`, not on the old
  `rest_macro_core` runtime path.

Deliverable: `serve.rs` ≤ 500 LOC; runtime testable without the compiler.

### Phase 4 — Extract `vsr-codegen` (weeks 8–10)

- Create the `vsr-codegen` crate.
- Move `compiler/` into it.
- Split `codegen.rs` by emitter (resource, service, auth, authz, migrations,
  runtime, storage, security, helpers). Tests move with each emitter.
- Introduce `GeneratedProject` / `GeneratedFile` as the source-first emitter
  contract. Emitted Rust is a stable module tree on disk, formatted by
  `rustfmt`, with deterministic comments and import ordering.
- Introduce `ProtocolEmitter` and `ClientGenerator` traits, with TypeScript
  moved behind the same registry that will later host Rust, `.proto`, GraphQL,
  and other language/protocol emitters.
- Add placeholder IR for service actions and future service-to-service links
  so multi-service `.eon` declarations do not require another compiler
  restructuring later.
- Turn the proc-macro path into an adapter over the source-first emitter, or
  document why that is not feasible and produce a sunset plan with migration
  tooling.
- Split `eon_parser.rs` into sub-grammars. Add property tests for the
  lexer and for the round-trip `.eon → IR → .eon` where that makes sense.
- Move `commands/docs.rs` content here.

Deliverable: 10k + 11k LOC files are now ~20 files averaging ~1k LOC each,
with ownable test boundaries; generated Rust is reviewable source first,
proc-macro output second; new protocol/client emitters have a documented
registry contract.

### Phase 5 — Extract `vsr-ops` (weeks 11–12)

- Create the `vsr-ops` crate.
- Move `backup/`, `secrets/`, `replication/`, `tls/` (cert gen),
  `doctor/` into it.
- Split `commands/backup.rs` by verb.
- Consolidate `doctor` commands under a single top-level subcommand.

Deliverable: CLI's `commands/` folder becomes thin wrappers over
`vsr-ops` and `vsr-codegen`.

### Phase 6 — CLI Redesign (weeks 13–14)

- Implement the target CLI tree from §6.
- Keep old commands as hidden aliases (with deprecation warnings) for one
  release.
- Rewrite `docs/src/cli.md` to match.

Deliverable: clean `vsr --help`, published migration guide.

### Phase 7 — Projection IR And Aggregate/Embed/Viewer Primitives (weeks 15–18)

This is when we start shipping the Nordic Bridge API primitives roadmap, now
on top of a layered and feature-flagged base. It is deliberately last so that
§4.2 is a structural fact, not a wish.

Deliverable: `aggregate`, `embed`, `viewer_relation` and related primitives
shipped with native/emitted parity, OpenAPI parity, and unit tests per layer.

### Phase 8 — Additional Protocol Surfaces (separate roadmaps)

Out of scope here but enabled by Phases 4 and 7:

- `gen graphql` emits a GraphQL schema from the shared IR; a `graphql`
  feature adds a runtime executor.
- `gen proto` emits `.proto` files from the shared service/action IR.
- A future `grpc` feature adds a gRPC server adapter over the same runtime
  logic used by REST and GraphQL.
- `gen client rust` emits the first non-TypeScript client and proves the
  `ClientGenerator` contract for later languages.

Design for each surface follows in dedicated roadmaps. The commitment in this
roadmap is the groundwork: shared IR, generator registry, deterministic
artifact contracts, and tests that make later surfaces additive.

## 10. Testing Strategy

Target layout for `tests/`:

- `tests/contract/` — snapshot tests: given `.eon`, check generated
  OpenAPI, generated `.proto` (once implemented), generated TypeScript client,
  generated Rust client, generated Rust server module, generated migrations.
  Snapshots live under `tests/snapshots/`. `cargo insta` (or a home-grown
  snapshot) enforces parity.
- `tests/runtime/` — end-to-end integration tests that boot `vsr serve` *and*
  the emitted binary for the same `.eon` and run the same assertions against
  both. This is how principle 4.3 becomes enforceable.
- `tests/cross_backend/` — matrix: same `.eon` × `{sqlite, turso-local,
  postgres, mysql}`. Currently this is mostly sqlite; the matrix reveals
  drift.
- `tests/platform/` — OS-specific smoke: Windows signal handling,
  macOS keychain access, Linux fs permissions.
- `tests/property/` — proptest/fuzz for `.eon` parsing, for query pagination,
  for row-policy evaluation.

Unit tests live next to the code they test (`#[cfg(test)] mod tests`) and
cover modules after the Phase 2–5 splits make them small enough to test in
isolation.

CI enforces:

- platform × feature matrix (§8.1)
- snapshot tests
- generated-code warning and clippy cleanliness (already present)
- `mdbook build docs` (already present)
- a runtime parity suite that fails if `vsr serve` and emitted-server
  behavior diverge on any of a fixed list of resource shapes.
- a generator contract suite that runs every registered `ClientGenerator` and
  `ProtocolEmitter` against the same IR fixtures, so adding Rust, `.proto`,
  or a later language cannot bypass naming, determinism, or capability rules.

## 11. Observability Strategy

Primitives added to `vsr-core::telemetry`:

- `tracing` subscriber factory — JSON for production templates, pretty for
  local. Controlled by env (`VSR_LOG_FORMAT=json|pretty`).
- `metrics` registry with default exporter (Prometheus text endpoint) and
  an OpenTelemetry exporter behind the `otel` feature.
- Request-scoped context: route, resource, action, user id, tenant id,
  request id. Emitted as span fields and as log fields.
- Standard metrics: request count, request latency histogram, auth
  success/failure counts, authz deny count, migration duration, backup
  duration, backup restore success/failure, database pool utilization.
- `/healthz` (process alive) and `/readyz` (DB and required deps reachable)
  endpoints.

Rules:

- No new runtime code path is considered complete without either a span or
  a metric (or both) when it matters for operations.
- Logs never include secrets. `secret::SecretRef`'s Display is
  `"<secret:{name}>"`; we lint for accidental leakage via `tracing` field
  patterns.
- Audit remains a separate sink. Observability answers "is the service
  healthy"; audit answers "what happened, who did it, when". They share
  plumbing but not guarantees.

## 12. Security Posture

Load-bearing. Informed by the product thesis.

### 12.1 Defaults

- Deny-by-default authz (already the case; document and hold the line).
- JWT key rotation-ready: multiple active verification keys, kid support.
- Password policy configurable per service; never zero.
- Rate limits: in-process by default, pluggable shared store for
  multi-instance.
- Security headers on by default; CSP configurable; Permissions-Policy
  supported.
- TLS required in production templates; plain HTTP allowed only in dev
  templates.

### 12.2 Seams

- `vsr-runtime::auth::jwt` exposes a `KeyProvider` trait. A file-based
  implementation is the default. Rotating provider implementations (KMS,
  Infisical) plug in via the `secret` layer.
- `vsr-runtime::rate_limit::Store` trait. Memory store default; a Redis
  store is an opt-in feature that emitted servers can pull in.
- `vsr-runtime::authz` supports per-resource row policies today; a future
  `policies-native-pg` feature will emit Postgres-native `CREATE POLICY` SQL
  alongside the app-layer engine.

### 12.3 Audit

The current audit sink work (recent commit
`Add transactional CRUD audit sinks`) is the right direction. We formalize
it as an explicit subsystem:

- `vsr-runtime::audit` — envelope, sinks, batching.
- `vsr-ops::audit` — tooling for integrity verification (tamper-evident
  chaining is on the roadmap).
- Audit events are append-only, transactional with the row they describe,
  and never silently dropped.

## 13. Data & Backup Posture

Already described in [`roadmaps/backup-replication.md`](roadmaps/backup-replication.md).
The architectural change in this roadmap is only that the work moves into
`vsr-ops::backup` with per-verb modules, and that `backup verify-restore`
becomes part of CI: a nightly job runs a snapshot against a disposable
database and asserts the restore succeeds.

## 14. Documentation Strategy

- `docs/src/` stays the human-facing book.
- `docs/src/architecture_roadmap.md` (this document) is the architectural
  source of truth; it is revised quarterly.
- `vsr docs` continues to emit the AI-facing `.eon` reference.
- Every crate gets a `README.md` that explains its role in one paragraph and
  links here. `cargo doc` becomes navigable at the crate level.
- CLI changes ship with matching `docs/src/cli.md` updates as part of the
  PR, not as follow-up.

## 15. Open Questions

Listed here so reviewers have a place to push back. Each carries a
**decision window** — the phase by which we commit, one way or the other.

1. **Crates.io rename (`vsra` → `vsr`).** *Decide by end of Phase 0.* The
   new workspace structure is the cheapest moment to take new names; delaying
   means every downstream `Cargo.toml` edit twice.
2. **HTTP framework (`actix-web` vs `axum`).** *Decide by end of Phase 3.*
   Phase 3 extracts the HTTP seam into `vsr-runtime::http`. After the seam is
   clean, we can evaluate a controlled experiment: port one example app to
   axum, benchmark, and decide. Until then, actix stays.
3. **Secret providers beyond Infisical.** *Decide by start of Phase 5.*
   Vault, AWS Secrets Manager, and plain-env fallback are the obvious first
   three. Choosing which to build first follows user demand and what
   `vsr-ops/secrets-*` needs to look like as a trait.
4. **WASM target for `vsr-core`.** *Decide by end of Phase 1.* Not a
   near-term product requirement; making a position explicit prevents
   accidental non-WASM deps from creeping into `vsr-core`. Default position:
   `vsr-core` must `cargo check` for `wasm32-unknown-unknown`; heavier crates
   are not required to.
5. **Hand-written Rust services on `vsr-runtime`.** *Decide by end of
   Phase 3.* Do we grow the `#[derive(RestApi)]` path as a first-class way to
   write services, or sunset it in favor of `.eon`-only? Answer affects what
   `vsr-runtime` exports publicly. Default position: keep derive as a
   supported but secondary path; do not spend on new derive-only features.
6. **Proc-macro sunset path.** *Decide by end of Phase 4.* Does `vsr-macro`
   remain a long-term compatibility wrapper, move behind a
   `legacy-proc-macro` feature, or deprecate on a timed schedule? The spike
   must compare compile time, generated source cleanliness, IDE support, and
   migration effort. Default position: CLI-emitted source is canonical; no new
   primary feature depends on proc-macro expansion.
7. **Minimum supported Rust version (MSRV).** *Decide by end of Phase 0.*
   Current baseline is implicit. Make it explicit (likely stable − 2), pin
   in CI, and document the bump cadence.
8. **Single-binary vs per-capability binaries.** *Decide by end of Phase 6.*
   The `minimal` feature produces a small binary; do we also ship
   capability-segmented binaries (e.g. `vsr-backup`, `vsr-doctor`) for
   constrained environments? Default position: one binary, many features.
9. **Client language order after Rust.** *Decide by end of Phase 7.* Rust is
   the next client target because it unlocks VSR-to-VSR service calls. After
   that, choose based on real consumers rather than novelty. Likely candidates:
   Go for backend services, Python for automation/AI workflows, Kotlin/Swift
   for mobile clients.
10. **Protocol surface order (`graphql`, `.proto`, `grpc`).** *Decide by end
   of Phase 7.* GraphQL and `.proto` can begin as generated artifacts. gRPC is
   larger because it requires a server adapter and streaming/error semantics.
   Default position: artifact emitters first, runtime protocols second.
11. **Service-to-service declarations in `.eon`.** *Decide in the protocol
   roadmap, after Phase 7.* We need a contract for declaring remote services,
   generated clients, protocol preference, auth, timeouts, retries, and version
   compatibility. Default position: reserve IR shape now; do not add syntax
   until the Rust client and at least one protocol artifact are proven.

## 16. Non-Goals (For This Roadmap)

- Replacing the `.eon` format with a different DSL.
- Changing the storage-first model of `.eon` resources.
- Shipping production gRPC, WebSocket, or GraphQL runtimes in this roadmap.
  The groundwork belongs here; the runtime surfaces get separate roadmaps.
- Adding a plugin system with dynamic loading.
- Adding `.eon` service-to-service syntax as part of these phases.

## 17. Acceptance Criteria For "This Roadmap Is Done"

This document's success state is not "we executed every phase". It is:

1. `vsr --help` fits on a screen (80×24) and groups commands by intent.
2. No hand-written source file in the workspace exceeds 2,000 LOC. Test
   fixtures, snapshot data, and generated artifacts are exempt; a one-line
   comment at the top of any exempted file states why.
3. `cargo build -p vsr-cli --no-default-features --features minimal` produces
   a working SQLite-only release binary within the size target in §18.
4. `cargo test --workspace` runs green on Linux, macOS, and Windows, x86_64
   and aarch64, with the full feature matrix exercised in CI.
5. `vsr serve` and the emitted binary produce byte-identical OpenAPI and
   structurally identical responses for every example service, enforced in
   CI.
6. A new contributor can pick up any individual crate and understand its
   job in under 30 minutes, measured by onboarding retros (informal) and by
   the presence of a per-crate `README.md` ≤ 200 lines.
7. Adding a new API primitive (next candidate: `aggregate`) requires edits
   in one parser submodule, one IR submodule, and one codegen submodule —
   not in a single 10k-line file.
8. No generated handler or public runtime trait exposes Actix, axum, sqlx, or
   other framework/vendor types. Adding an `http-axum` backend requires an
   adapter module plus parity tests, not generated-handler rewrites.
9. Generated Rust is source-first, `rustfmt`-clean, deterministic, and
   reviewable without `cargo expand`. The proc-macro path is either a thin
   documented compatibility adapter or has an accepted sunset plan.
10. TypeScript, Rust-client, OpenAPI, and future `.proto`/GraphQL emitters
    plug into a common generator registry and pass the same determinism,
    naming, and capability tests.
11. The IR contains an explicit place for service/action shape and future
    service-to-service links, so adding `.eon` service connections does not
    require another compiler split.
12. The non-functional targets in §18 hold, verified by CI benchmarks.
13. Every risk in §19 has either been mitigated or has an accepted
   contingency plan documented.

When those hold, we have the architecture we need to ship the next two years
of VSR.

## 18. Non-Functional Targets

These numbers are commitments, not aspirations. CI enforces them as hard
failures after Phase 1. They are reviewed quarterly and tightened as the
baseline improves.

### 18.1 Binary Size (Release, Stripped)

| Build | Target | Rationale |
|---|---:|---|
| `vsr --features minimal` (SQLite only, no backup/secrets/TLS) | ≤ 15 MB | Edge/embedded-class deploy. |
| `vsr` default features (SQLite, Turso, Postgres, backup, Infisical) | ≤ 45 MB | Typical operator workstation. |
| `vsr --all-features` | ≤ 80 MB | Reference upper bound; worth auditing if exceeded. |
| Emitted server, SQLite-only | ≤ 20 MB | User-facing claim: "small prod binary." |

### 18.2 Startup Time

| Operation | Target (p95, warm disk) |
|---|---:|
| `vsr serve examples/minimal/api.eon` cold start → `/healthz` 200 | ≤ 300 ms |
| Emitted server → `/readyz` 200 | ≤ 200 ms |
| `vsr check` on a 500-resource `.eon` | ≤ 500 ms |

### 18.3 Compile Time (Developer Loop)

| Action | Target |
|---|---:|
| `cargo check -p vsr-codegen` incremental | ≤ 5 s |
| `cargo check -p vsr-runtime` incremental | ≤ 5 s |
| `cargo build -p vsr-cli --features minimal` from cold | ≤ 90 s on M-series / 8-core x86_64 |

### 18.4 Request Latency Budget (vsr serve, SQLite, no auth)

| Path | Target (p99, local loop) |
|---|---:|
| `GET /resource` (indexed lookup) | ≤ 2 ms |
| `POST /resource` (single row insert) | ≤ 5 ms |
| `GET /resource?filter=…` (10-row page) | ≤ 8 ms |

These are smoke-grade numbers, not SLAs. They exist to catch regressions
(a 10× jump) not to compete on benchmark.

## 19. Risk Register

Ordered by product impact × likelihood. Each risk has an owner (TBD during
phase kickoff), a trigger condition that escalates it, and a contingency.

| # | Risk | Likelihood | Impact | Mitigation | Contingency |
|---:|---|---|---|---|---|
| 1 | Monolithic `codegen.rs` / `eon_parser.rs` split stalls partway, leaving two parallel code paths. | Medium | High | Phases 2–4 split file-by-file, each with a green CI run; no phase merges until the file it targets is fully migrated. | Freeze new features in the affected area until split completes. |
| 2 | CI matrix expansion (§8.1) reveals latent platform bugs faster than we can fix them. | High | Medium | Add platforms to `cargo check` first, `cargo test` second. Keep a known-failures allowlist that shrinks each phase. | Temporarily gate tests by platform with a sunset date in the allowlist. |
| 3 | `actix-web` upstream stagnates or breaks; `axum` gains features we need. | Low | High | §15.2 decision window at end of Phase 3. Keep `vsr-runtime::http` framework-agnostic at the seam. | Port one example to axum behind `http-axum` feature; decide based on diff size. |
| 4 | New IR design (Phase 7) proves too expressive for some existing primitives, forcing a re-lifting of already-working features. | Medium | Medium | IR additions are additive. Existing primitives lift into IR one at a time with a green parity test. | Keep the legacy codepath alive behind a feature until the IR lift ships. |
| 5 | Cross-backend parity (§8.4) reveals behavior divergence we cannot reconcile without IR changes. | Medium | Medium | Per-backend adapter trait with a documented semantic contract; adapters document every deviation. | Publish a "backends: supported feature matrix" and mark the divergence explicitly. |
| 6 | Observability rollout leaks PII into logs. | Medium | High | `secret::SecretRef` redaction; tracing-field lints in CI; security review per structured-log addition. | Incident playbook + log rotation/redaction tooling shipped in `vsr-ops`. |
| 7 | Crates.io name acquisition blocked; forced to keep confusing `vsra`/`very_simple_rest` names. | Medium | Low | §15.1 decision at end of Phase 0. | Document the binary/package split prominently; provide `cargo install vsra --bin vsr` onboarding alias. |
| 8 | Feature-flag matrix grows faster than we can test it (N features → 2^N combinations). | High | Medium | CI tests `{default, no-default, minimal, all}` only; additional combos tested on demand. Features are orthogonal by construction. | Add a combinatorial smoke job (nightly, sampling) when the matrix exceeds 8 features per crate. |
| 9 | AI-generated `.eon` files exploit undocumented parser corners, producing unsafe codegen. | Medium | High | Property tests on the parser (Phase 4); strict-mode validation on by default; fuzz target. | Block-list ambiguous constructs in the parser with a migration diagnostic. |
| 10 | Migration phases drag past horizon, blocking feature work indefinitely. | Medium | High | Every phase has a 2–4 week budget; overruns trigger a roadmap review, not a silent extension. | Cut scope of the overrunning phase; re-plan remaining items as a new phase. |

## 20. Schema Version Policy

`.eon` is a contract, which means *its own evolution* is a contract. We
commit to the following:

### 20.1 Version Declaration

Every `.eon` file declares a schema version in its `metadata` block:

```eon
metadata:
  schema_version: "1.0"
```

Missing version is treated as `"1.0"` during 0.x; mandatory in 1.0.

### 20.2 Semver For The Language

- **Major (1.x → 2.x).** Breaking syntax or semantics. A 1.x file is not
  guaranteed to parse under 2.x; the compiler emits a directed migration
  diagnostic when it can, and `vsr schema migrate-eon` is the operator tool.
- **Minor (1.0 → 1.1).** Additive. A 1.1 file may use new constructs; a 1.0
  file parses unchanged under 1.1.
- **Patch (1.0.0 → 1.0.1).** Diagnostic or error-message changes only.

### 20.3 Compiler Compatibility Window

A VSR release supports parsing `.eon` files from:

- the current schema major,
- the most recent prior major (read-only: accepted, with a deprecation
  diagnostic and a suggested migration).

Files two majors old are rejected with an explicit "run `vsr schema
migrate-eon` with VSR 1.x" message.

### 20.4 Deprecation Lifecycle

A language construct lifecycle: **introduced → stable → deprecated →
removed**.

- A construct enters *deprecated* for at least one minor release before
  *removed*.
- Deprecated constructs emit a diagnostic pointing at the replacement and
  the removal version.
- Removal requires a major bump.

### 20.5 Generated Artifact Compatibility

- OpenAPI output: structurally backward-compatible within a minor; breaking
  changes bump minor and appear in the CHANGELOG.
- Generated clients: public API backward-compatible within a minor for each
  language target; private internals may change. Rust client follows normal
  Rust semver expectations for public types and traits.
- `.proto` output: package, message, field number, and service naming changes
  are compatibility-sensitive. Once published, field numbers are never reused.
- Migrations: forward-only by default; `vsr schema diff` shows destructive
  changes requiring `--allow-destructive`.

## 21. AI-Assisted Development Architecture

VSR's product thesis hinges on AI agents being able to author and iterate on
`.eon` contracts reliably. That puts specific demands on the architecture:

### 21.1 AI-Friendly Diagnostics

- All `vsr check`, `vsr doctor`, and codegen errors emit JSON on `--json`.
  JSON carries: error code, human message, file/line/column, the offending
  source snippet, and a structured `suggested_fix` when one is mechanical.
- Error codes are stable and URL-resolvable (`docs/errors/EON-E0023.html`).
  An AI handed an error code can fetch the canonical explanation.

### 21.2 Machine-Consumable Reference

- `vsr docs --format json` emits a complete, versioned `.eon` grammar +
  semantics reference. AIs train on the grammar directly instead of
  reverse-engineering examples.
- The grammar is generated from the parser, not hand-written, eliminating
  drift between what the parser accepts and what the docs claim.

### 21.3 Deterministic Codegen (reiterated from §4.11)

AIs diff generated files to verify their contract change produced only the
expected downstream edits. Non-determinism (timestamps, iteration order,
absolute paths) destroys that signal.

### 21.4 Low-Cardinality Verbs

CLI redesign (§6) collapses 24 top-level commands into roughly a dozen,
grouped by intent. AIs operating the CLI via shell commands benefit from a
small, orthogonal verb set more than humans do — there is no muscle memory
to fall back on.

### 21.5 Safe-By-Default Destructive Ops

Any command that can destroy data (`vsr reset`, `vsr schema apply` against a
populated DB, `vsr backup pull` over a live DB) requires an explicit
`--confirm` or equivalent. An AI agent does not benefit from shortcuts here;
the product's promise of data safety is what makes trusting AI-driven
workflows acceptable.

### 21.6 Stable Output Contracts

- `vsr <cmd> --json` outputs a schema-versioned envelope:

  ```json
  {"vsr_version": "0.3.0", "output_version": "1", "data": {...}}
  ```

- `output_version` bumps follow the same rules as §20.

## 22. Benchmarking And Performance Regression

The non-functional targets in §18 exist because someone measures them.

### 22.1 Benchmark Suite

- `benches/` (using `criterion`) in `vsr-codegen` covers parser, IR
  lowering, and each emitter. Regression threshold: 10 % slowdown fails CI.
- `benches/` in `vsr-runtime` covers HTTP hot paths (route match, auth
  check, authz evaluation, row-policy filter). Runs against an in-memory
  SQLite so timing is deterministic.
- A `benches/startup/` harness measures `vsr serve` cold start.

### 22.2 CI Integration

- Benchmarks run on a single reference GitHub runner (ubuntu-latest, 4
  vCPU). Numbers are not absolute; regressions are measured against the
  previous main-branch run.
- A nightly job posts benchmark deltas to `docs/src/perf-history.md` as an
  append-only ledger, so performance drift over months is visible.

### 22.3 Binary-Size Budgeting

- `cargo bloat --release --crates` is run per feature profile in CI.
- A single workspace file `scripts/size-budget.toml` lists the §18.1
  targets; the CI job fails if any exceed.

### 22.4 Perf-Sensitive Code Locations

Documented in per-crate `README.md`:

- `vsr-codegen::parser::lexer` (hot during large-service compilation).
- `vsr-runtime::authz::eval` (runs per request).
- `vsr-runtime::http::middleware::request_log` (runs per request; must be
  zero-allocation in the fast path).

These get extra review scrutiny and benchmark coverage.

## 23. Dependency Policy

A deliberately small, slow-changing dependency graph protects the product
promise of long-term operability.

### 23.1 Allowlist Principle

Each crate's `Cargo.toml` should have a short list of intentional
dependencies. New deps require:

- a one-line justification in the PR description,
- a maintenance signal (last release, open issue count, audit status),
- a feature flag if the dep supports optional capability.

### 23.2 Forbidden Categories

- No `unsafe` deps without an audit note and a feature flag.
- No deps that pull in `openssl-sys` transitively without opt-in; `rustls`
  is the default TLS stack.
- No deps that require a build-time C compiler for default features; that
  breaks our Windows cross-compilation story.
- No GPL/AGPL deps anywhere in the workspace.

### 23.3 Update Cadence

- `cargo update` on `Cargo.lock` weekly, via a bot PR; human review for
  major-version bumps, auto-merge allowed for patch versions once CI passes.
- `cargo audit` runs on every CI job; unfixed RUSTSEC advisories block
  merge unless explicitly waived with a sunset date.

### 23.4 Pinned Exceptions

The current `vendor/sqlx-mysql` patch is one such pinned exception. Every
such pin is documented in `docs/src/dependencies.md` with: what it pins,
why, and the condition under which we unpin.
