# EON Enterprise API: Local Proof

Date: 2026-09-08. Platform: macOS, stable Rust toolchain.
Checkout: `codex/dependency-upgrade-review`, based on `37ec77559` plus the
uncommitted Axum transport and enterprise example changes. No remote CI result
or production certification is claimed.

## Executed Checks

| Check | Result |
| --- | --- |
| `cargo +stable test -p enterprise-api --all-features --offline` | 12 passed, 0 failed |
| `bash examples/enterprise_api/prove.sh` | 7 passed with Axum only; 7 passed with Actix only |
| Axum-only normal dependency graph | No Actix packages; compiler remains build-only |
| `cargo +stable test --workspace --all-features --no-fail-fast --locked` | 684 passed, 0 failed, 16 ignored |
| `cargo +stable clippy -p enterprise-api --all-features --all-targets --locked` | Completed; documentation/pedantic/test warnings remain |
| Workflow YAML, proof shell syntax, scoped Rust formatting, `git diff --check` | Passed |

The 12 example tests comprise two build-contract tests and five HTTP scenarios
instantiated for each backend. The compiler tests modify actual EON files in
temporary directories: renamed resources change SQL tables/routes, changed
roles change the emitted contract, and unsafe or unsupported configurations
are rejected. The network tests use genuine ES256 signatures and separate
SQLite files, not mocked authorization decisions.

## Exercised Boundaries

- Anonymous and cookie-only access; repeated Authorization headers; invalid
  signatures, issuer, audience, type, key ID, expiry, not-before, lifetime and
  subject representation; signed role/admin claims do not elevate privileges.
- Current grant deletion/expiry, account disablement, account-token version
  changes and individual token revocation take effect without token refresh.
- Tenant-filtered lists/items, owner-only mutation/private reads, manager limits,
  mass-assignment rejection and same-tenant authorized parent references.
- Bounded keyset pagination, duplicate/unknown query and JSON fields, input/body
  limits, strict content types and parameterized SQL handling.
- ETag requirements, one winner among simultaneous updates, nonreused IDs,
  restrictive parent deletion, audit failure rollback, append-only audit guards,
  tenant-scoped audit access, restart persistence and schema-drift refusal.
- Required database table availability and fail-closed dependency responses.

## Real Launcher Smoke Test

`cargo +stable run -p enterprise-api -- demo-init` initialized the explicit local
demo. `target/debug/enterprise-api serve` read the checked-in `server.eon` and
reported `Axum enterprise API listening on 127.0.0.1:8091`.

| Request | Observed result |
| --- | --- |
| Anonymous GET `/api/v1/project` | 401 plus Bearer challenge |
| Alice POST project | 201; server assigned tenant 1 and owner 1; ETag `"project:1:1"` |
| GET `/readyz` | 200 |
| Dana, tenant 2, GET project 1 | 404 |
| Bob, another tenant-1 editor, PATCH project 1 | 404 |
| Alice PATCH with matching ETag | 200; ETag advanced to `"project:1:2"` |
| SIGTERM to the started process | Exit 0; listener closed |

Private-key and token files had Unix mode 0600. They are ignored local demo
artifacts, not committed fixtures. No real credentials or external service
accounts were used.

## Limits

The example demonstrates an enterprise-oriented authorization boundary, not
enterprise scale or full VSR backend interchangeability. Native/generated CLI
servers remain Actix. External IdP integration, production-database/HA/load
tests, retry idempotency, audited identity/grant provisioning, external audit
retention and domain approval workflows remain future work. The 16 ignored
workspace tests are not counted as passing. Dependency advisory debt is not
resolved or certified by these HTTP tests. See the example README for the full
operational boundary and reproduction commands.
