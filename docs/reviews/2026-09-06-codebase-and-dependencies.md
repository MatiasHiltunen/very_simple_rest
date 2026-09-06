# Codebase And Dependency Review

Reviewed 2026-09-06 on `codex/dependency-upgrade-review`, based on
`3efc9713a7acfb7bbe329b7baff8b87306d1a0cc` (`codex/v1-review-blockers`).
The checkout includes the earlier migration-blocker fixes. Fetched `origin/v1`
was `7bd9fa0e2`; the main checkout and its unrelated local work were preserved.
This is a source and test review, not a penetration test or production approval.

## Remediation

The eight findings below now have scoped source fixes and regression coverage:
account-state-bound JWT extraction, trusted-suffix proxy parsing, conditional
single-use token claims, shared journaled local storage, migration checksums
and locking, bounded blocking password work, HTTP configuration/readiness
enforcement, and inherited workspace lint policy. Clippy also exposed an
always-returning audit-validator loop, now expressed as a first-element check.

See [migration and compatibility guidance](../src/migrations.md) before rolling
out, especially old-token reauthentication, legacy migration baselines, MySQL
repair, storage writer compatibility, and application-controlled readiness.
PostgreSQL/MySQL concurrency tests are wired to isolated CI services but have
not been run locally; Docker's daemon is stopped on this machine. Upstream
dependency audit findings remain unsuppressed. These changes do not complete
the architecture migration or establish production readiness.

## Original Findings (Before Remediation)

The following code references and descriptions describe the pre-fix snapshot,
not current line numbers or a list of defects still present unchanged.

### P1: Account changes do not revoke existing JWT privileges

`crates/rest_macro_core/src/auth/user.rs:44-102` constructs `UserContext`
exclusively from the signed token. It checks neither current account existence
nor current role/claims nor a session version. Admin handlers such as
`auth/handlers.rs:771-812` authorize that token role before querying data.
Updating/deleting an account or resetting its password therefore does not
invalidate an already-issued token. A demoted/deleted admin can continue
calling admin endpoints; old workspace claims also remain authoritative.
The default access-token lifetime is 24 hours (`auth/settings.rs:196`).

Add a session/account version or revocation mechanism checked at extraction,
and invalidate it on password reset, deletion, role and authorization-claim
changes. Test an old token against protected endpoints after each operation.
This is established from the request/management code paths, not a live attack.

### P1: Proxy header chains allow client-IP spoofing

`crates/rest_macro_core/src/security.rs:380-390` verifies only the immediate
peer, then `:451-479` takes the first parseable `Forwarded` or X-Forwarded-For
entry. If a trusted proxy appends its observed client to an existing header,
an attacker controls the selected leftmost value. `auth/helpers.rs:248-262`
uses that value as the login/registration rate-limit key.

For example, a trusted peer with X-Forwarded-For
`198.51.100.66, 203.0.113.20` is attributed to the first address even when the
proxy observed the second. Walk the chain right-to-left, discarding only known
trusted proxies, and stop at the first untrusted hop. Reject ambiguous/malformed
chains and do not trust forwarding headers when the peer is unavailable.
Until fixed, the ingress proxy must strip and rebuild all accepted forwarding
headers. Add append-mode, multiple-header, malformed-hop, and IPv6 tests.

### P1: Password-reset tokens are not consumed atomically

`auth/tokens.rs:44-70` loads an unused token, changes the password, then marks
and deletes the token. `auth/db_ops.rs:318-336` uses a normal SELECT, and
`:352-365` updates by ID without `used_at IS NULL` or affected-row validation.
On PostgreSQL/MySQL, two transactions can both read the token before either
changes it. The second can update the password after the first commits even
though its later token update affects zero rows. Both paths report success.

Claim the token with a conditional update/delete and require exactly one
affected row in the same transaction before mutating the account, or use
appropriate backend row locking. Add a synchronized two-connection test for
each backend. The interleaving is a code-derived finding; external database
concurrency was not exercised on this machine.

### P2: Object replacement and metadata are not crash-consistent

`crates/rest_macro_core/src/storage.rs:404-435` writes directly over the final
object and then writes its sidecar. A partial write or sidecar failure can
destroy the previous object or leave stale size/ETag/content-type metadata.
The new `vsr-runtime/src/storage/local.rs:327-345` repeats the two-write model,
so migrating to that implementation alone does not resolve it.

Use staged, durable replacement with a well-defined object/metadata generation
and recovery policy. Test disk-write/metadata failures, replacement with
concurrent readers, and interrupted commits. The active legacy backend also
uses path resolution plus ordinary filesystem operations without the new
adapter's symlink checks: storage roots must not be writable by untrusted local
processes while the implementations remain separate.

### P2: Database migrations neither detect drift nor serialize runners

`crates/rest_api_cli/src/commands/migrate.rs:1183-1218` records only migration
names and timestamps. `:1253-1286` checks the name outside the transaction,
then applies SQL and records it. Editing an applied migration silently skips
the changed SQL, and concurrent startup runners can both attempt the same
migration. MySQL DDL also cannot be assumed to obey the surrounding transaction
as a single rollback unit.

Store and verify checksums, lock migration execution per database, and specify
backend-specific DDL failure/recovery behavior. Add checksum-mismatch and
two-runner tests instead of relying only on sequential apply/skip tests.

### P2: Expensive password work blocks request workers

`crates/rest_macro_core/src/auth/handlers.rs:61`, `:183`, `:341-345`, and `:589`
call synchronous bcrypt hashing/verification from async Actix handlers. Cost-12
work occupies the worker thread, delaying unrelated requests under concurrent
authentication traffic. The per-client rate limiter does not bound global
password-work concurrency.

Move these operations onto a bounded blocking executor, with backpressure and
shutdown handling. Load-test unrelated request latency while login, signup,
password changes, and password-reset requests are concurrent.

### P2: The new HTTP adapter silently ignores security configuration

`crates/vsr-runtime/src/http/actix_adapter.rs:80-137` accepts `_middleware`
without using it and always performs plain `.bind(config.addr)`, ignoring
`ServerConfig.tls`. Its readiness handler at `:152-157` always returns 200.
Using this adapter as the production replacement would silently omit requested
TLS and middleware controls and report ready without dependency checks.

Implement configuration parity or reject unsupported settings at startup.
Readiness needs actual dependency/lifecycle state. This remains a migration
blocker, not a claim that today's native CLI is using this incomplete adapter.

### P2: Workspace lint policy is declared but not inherited

`Cargo.toml:18-39` says all crates inherit workspace lints, but no member opts
in with `[lints] workspace = true`. Consequently the declared unsafe-code and
correctness policies are not enforced by that table. The CI feature matrix
mostly runs `cargo check`, which does not enable Clippy policy either.

Opt crates in deliberately, account for existing platform/environment unsafe
code, and add explicit CI checks. Do not equate a green build with enforcement
of the architecture roadmap's lint/security policy.

## Architecture Status

The latest architecture plan in this checkout is
[`docs/src/architecture_roadmap.md`](../src/architecture_roadmap.md), last
changed by `9b7d3a970` on 2026-04-24. It describes target architecture, not a
completed migration checklist. The layered `vsr-core`/`vsr-runtime` foundation
exists, and auth/authorization/compiler modules have been split. However,
the live facade and native CLI still depend on `rest_macro_core`; `vsr-codegen`,
`vsr-ops`, and a fully integrated replacement runtime are not workspace members.
Native and generated implementations still require parity tests.

Prioritize lifecycle/security contracts and parity gates before moving more
files. The runtime adapter findings and duplicated storage behavior are concrete
examples of why the presence of a new crate is not evidence of production parity.
PR #8 was already merged in the reviewed history; this review is grounded in
the current branch code, not the old PR diff.

## Implemented In This Branch

- Upgraded all direct Rust crates to latest stable resolutions, including major
  API migrations in SQLx, JWT/JWKS, static files, SHA-2, Turso, and generated
  project manifests. Removed the obsolete vendored MySQL 0.8.6 driver.
- Upgraded the CMS and npm workspace dependencies. Migrated MUI slots/system
  props/theme selectors and fixed newly surfaced lint errors.
- Stopped relation-data refreshes from blindly overwriting edited draft fields;
  kept server-derived baseline state separate from local edits.
- Corrected editor grid breakpoints and stretched action buttons. Added a
  repeatable browser smoke test for login, save, controls, and desktop/mobile
  page rendering using mocked backend responses. Added CMS build/lint/browser
  checks to the existing CI workflow; the remote workflow itself was not run.
- Recorded compatibility pins and unsuppressed upstream audit findings in
  [`Dependencies`](../src/dependencies.md). The runtime fixes are separate from
  dependency updates and documented in the remediation section.

## Verification And Limits

| Check | Result |
| --- | --- |
| Stable Rust workspace, all features, unit/integration/doc tests | 648 passed, 0 failed, 16 explicitly ignored |
| Stable Rust workspace default and no-default-feature checks | Passed |
| Workspace Clippy, all features and targets | Passed with existing pedantic/documentation warnings; correctness is denied |
| Generated CMS binary, warnings denied on emitted code | Passed separately; dependency warnings remain under workspace policy |
| Generated CMS Clippy and expansion snapshots | Passed separately; only the documented generated `HttpResponse` size exception is allowed |
| Local storage redo journal, concurrent readers/writers, metadata/list/delete | Passed; deterministic recovery boundaries, not real power-loss testing |
| New adapter HTTP/TLS, CORS, compression, body limits, readiness | Passed with temporary listeners and verified self-signed test certificate |
| Account mutation revocation, reset token single-use, bounded password workers | Passed on local SQLite/Turso coverage |
| PostgreSQL/MySQL migration and reset-token concurrency | Compiled and added to isolated CI service jobs; not locally executed |
| Rust-to-TypeScript generated schema drift check | Passed, no generated schema changes |
| npm wrapper and TypeScript 7 types | Passed; 5 wrapper tests |
| npm wrapper tests on Node 22.23.2 and Node 25.9.0 | Passed with tsx 4.21.0 and esbuild override |
| CMS TypeScript build and ESLint | Passed |
| CMS Chromium smoke tests | Passed at widths 390, 850, 1190, 1440, 1800, and 2100; login, topics save, assets select, entries, users, workspaces |
| mdBook documentation build | Passed |
| Root and CMS npm audits including dev dependencies | Zero vulnerabilities in both workspace lockfiles |
| Rust audit | Not clean: 3 vulnerability entries and 2 informational warnings; see Dependencies |

The Rust suite includes SQLite/Turso operations, authorization and transaction
behavior, storage/static delivery, generated clients, snapshots, and all 27
spawned-server tests. Local testing was on macOS arm64, Rust 1.98.1 and Node
25.9.0; Node 22 wrapper verification was performed during the dependency pass.
PostgreSQL/MySQL were compiled, not exercised against live services. External
S3/SMTP, Linux/Windows execution, production load testing, real power-loss
recovery, and production deployments remain unverified. Journal interruption
boundaries and cooperating concurrent readers/writers were exercised locally.
Existing compiler warnings remain visible under the newly inherited policy.

No commit, push, PR operation, production deployment, or database mutation was
performed against the user's existing services for this review. Build/test
servers and datasets were temporary.
