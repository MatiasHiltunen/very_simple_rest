# Shared Built-in Account Service: Migration Proof

Date: 2026-09-08. Baseline: local `v1` commit `fa6c1e6e4` (request-auth
extraction). The account-service changes described here are the next working-tree
milestone, not evidence that the full architecture migration is complete.

## Scope

`vsr-runtime::auth::accounts` owns login policy, token-claim construction,
current-account reads and password changes. Storage and signing are injected
through narrow traits; time is injectable. Existing Actix facade signatures and
account JSON remain compatible. The legacy configured-key and SQLx/Turso bridges
are exposed through `rest_macro_core::auth::builtin_account_service`.

The service preserves current-password verification, bcrypt cost 12 for new
hashes, mapped claims and state-bound tokens. It rejects nonpositive token TTLs,
invalid subject/clock values and expiration overflow. Login/current-password
inputs over 72 bytes are now rejected explicitly, consistent with the existing
new-password limit. Signing failures no longer expose key-configuration details
in public error messages.

Password changes now use one bound conditional UPDATE matching ID, old password
hash and management revision. A stale snapshot returns `409 account_changed`.
NULL revisions use an explicit `IS NULL` condition; base schemas use ID and hash.
Database errors never fall back to a weaker update after loading a revision.
Password-reset transactions retain their existing implementation in this step.

The requirement to authenticate a password change and verify the current
password aligns with the
[OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
This is a scoped migration check, not a full compliance or production security
assessment.

## Executable Evidence

- Runtime account tests cover exact normalized login claims, deterministic expiry,
  state binding, invalid credentials, verification/schema policy, signer/repository
  errors, deleted accounts, public responses, password validation and failed CAS.
- SQLite tests exercise base schemas, NULL and non-NULL revisions, stale hashes,
  stale management revisions, deletion and database failures. Concurrent requests
  with the same old snapshot produce exactly one successful password change and
  one conflict; the stored hash matches the winner and changes the session state.
- `builtin_auth_runtime` uses real loopback HTTP listeners, SQLite and configured
  JWT signing. Native Actix and shared-service handlers behind Actix/Axum all log
  in, accept one another's tokens and return identical account JSON. Each path
  changes the password in turn; all previously issued tokens are then rejected
  by all three paths. Incorrect passwords, invalid new passwords, anonymous
  requests, deletion and a dropped account table fail closed. A body-supplied
  account ID cannot redirect a password change.
- The existing cookie/CSRF/live-revocation HTTP test remains enabled in the same
  integration target. Neutral account-operation routes in the new test are
  deliberately test-only bearer adapters, not a production route implementation.

Commands use Rust stable with `RUSTUP_TOOLCHAIN=stable`,
`CARGO_PROFILE_DEV_DEBUG=0` and `CARGO_PROFILE_TEST_DEBUG=0`:

```sh
cargo +stable test -p vsr-runtime -p rest_macro_core --all-features --lib accounts --locked
cargo +stable test -p rest_macro_core --all-features --test builtin_auth_runtime --locked
cargo +stable test --workspace --all-features --locked
```

Local macOS results:

| Check | Result |
| --- | --- |
| Focused account/service/database unit tests | 12 passed |
| Real built-in HTTP integration, all features | 2 passed |
| Full all-feature workspace suite | 705 passed, 0 failed, 16 ignored |
| Runtime `auth-builtin` only, no default features | 24 passed |
| Minimal SQLite profile, account database unit tests | 2 passed |
| Minimal SQLite profile, real built-in HTTP integration | 2 passed |
| Clippy, both affected crates, all-feature libraries/tests | Passed with warnings; not warning-clean |
| Runtime auth-only normal dependency graph | Neither Actix nor Axum present |
| Enterprise Axum-only normal dependency graph | No Actix or `rest_macro_core` runtime dependency |
| mdBook and whitespace checks | Passed |

The full run includes existing native/generated Actix, account lifecycle,
enterprise backend and transport conformance tests. Existing compiler/doc and
test-style lint warnings remain. Local logs are
`/private/tmp/vsr-account-workspace.log`, `/private/tmp/vsr-account-unit.log`,
`/private/tmp/vsr-account-http.log`, `/private/tmp/vsr-account-isolated-auth.log`,
`/private/tmp/vsr-account-isolated-core.log`, `/private/tmp/vsr-account-isolated-http.log`
and `/private/tmp/vsr-account-clippy.log`.

## Remaining Gates

Registration, reset/verification token consumption, managed-account operations,
email delivery and authorization remain in the legacy implementation. Production
cookie responses, rate limiting and extraction have not moved to neutral routes.
The SQL/key bridge still links Actix; the runtime service itself does not.

No CLI backend switch, generated-bootstrap migration, streaming implementation,
remote CI result, external PostgreSQL/MySQL run or production load test is
claimed here. CI includes the expanded HTTP integration target, SQLite password
concurrency/schema tests and framework-isolated runtime unit tests on Linux,
macOS and Windows; configured
jobs are not evidence that those remote runs have completed.
