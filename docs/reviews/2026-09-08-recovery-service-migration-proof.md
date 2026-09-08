# Shared Recovery Consumption: Migration Proof

Date: 2026-09-08. Baseline: local `v1` commit `99c1f51b9`, the committed shared
account-service milestone. This record describes the next working-tree milestone;
it does not claim complete native/generated backend migration.

## Implementation

`vsr-runtime::auth::recovery` owns the verification/reset state machine: normalize
input, validate/hash new passwords, select the server-defined purpose, hash the
credential, evaluate expiry, claim once, apply the account mutation and invalidate
sibling tokens of the same purpose. `RecoveryRepository`/`RecoveryTransaction`
separate SQL from transaction policy. The existing Actix JSON handlers and HTML
verification flow delegate to the same service used by neutral test handlers.

The temporary facade still supplies SQLx/Turso and links Actix. Issuance, email
delivery, registration, admin actions, production JSON/cookie/rate-limit wiring,
streaming and native/emitted backend selection remain outside this step.

## Corrections

- The previous token loader selected `requested_email` but discarded it. Token
  application updated by ID alone. The shared record retains the address and
  mutation now atomically matches ID and email. Missing/empty bindings and absent
  account rows are invalid, not successful operations. Invalid bound tokens are
  removed so changing an email back does not revive an already rejected link.
- The new eight-consumer regression initially produced one SQLite success,
  four invalid results and three database errors. Recovery now starts a SQLite/
  Turso immediate transaction before reading. The same test passes on both local
  drivers with exactly one Applied outcome and seven Invalid outcomes.
- Expiration is checked at the exact microsecond deadline and after claiming,
  including time spent waiting on a competing transaction. Malformed dates expire
  closed. An additive core clock method preserves subsecond production precision.
- All account writes and token consumption share a commit. Errors explicitly roll
  back; cancelled operations discard unfinished transactions. Turso leases remain
  non-reusable across BEGIN/COMMIT/ROLLBACK awaits until control completes, avoiding
  returning an interrupted transaction to the pool.

Normal email issuance already binds tokens to the requested email. Legacy manually
created NULL/empty-email tokens are now rejected; users must request fresh links.
Raw credentials, signing configuration and database error details are not included
in the shared public outcome bodies. Existing SHA-256 storage format, bcrypt cost
12, account-state revocation and successful HTTP status codes remain unchanged.

Single-use, expiring, user-bound credentials and session invalidation follow the
[OWASP recovery guidance](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).
This is scoped local verification, not a complete production security assessment.

## Evidence

- Eight runtime policy tests cover ordered commit, subsecond expiry, expiry during
  claim, invalid bindings, missing/reused tokens, every storage failure, cancellation,
  password validation/hashing and stable public error codes.
- Six database tests cover SQLite and local Turso bindings, purpose isolation,
  expired/malformed timestamps, eight concurrent consumers, deleted accounts and
  cancellation while waiting for a write lock. A SQLite trigger injects an account
  update failure to prove that the token claim rolls back and can be retried.
- A real HTTP test runs verification and password-reset consumption through native
  Actix and both shared adapters. Each path performs both operations, accepts a new
  login afterward and invalidates old sessions on all three paths. Reuse, sibling
  tokens, wrong-purpose attempts, invalid input, expired dates and stale email links
  are rejected. This test inserts controlled credentials using the real storage
  format; it does not claim SMTP delivery from the neutral routes.

Local macOS verification:

| Check | Result |
| --- | --- |
| Full all-feature workspace suite | 722 passed, 0 failed, 16 ignored |
| Runtime recovery policy tests | 8 passed |
| SQLite/local-Turso recovery transaction tests | 6 passed |
| Real built-in HTTP suite, minimal SQLite features | 3 passed |
| Runtime auth-only feature profile | 32 passed |
| SQLite-only recovery transaction profile | 6 passed |
| Framework-free runtime contract build | Passed |
| Auth-only normal dependency graph | Neither HTTP framework present |
| Enterprise Axum normal dependency graph | No Actix or legacy facade dependency |
| Clippy for core/runtime/facade libraries and tests | Passed with warnings; not warning-clean |
| Focused formatting, whitespace, CI YAML and mdBook | Passed |

The full run includes existing native/generated Actix, email/account lifecycle,
enterprise and transport tests. Local evidence logs use the prefix
`/private/tmp/vsr-recovery-`: `workspace.log`, `unit.log`, `db.log`, `http.log`,
`isolated-auth.log`, `isolated-db.log`, `isolated-http.log`, `contract.log`,
`clippy.log` and `docs.log`.

Commands use Rust stable,
`RUSTUP_TOOLCHAIN=stable`, `CARGO_PROFILE_DEV_DEBUG=0` and `CARGO_PROFILE_TEST_DEBUG=0`:

```sh
cargo +stable test -p vsr-runtime --no-default-features --features auth-builtin --lib recovery --locked
cargo +stable test -p rest_macro_core --all-features --lib auth::tokens::tests --locked
cargo +stable test -p rest_macro_core --all-features --test builtin_auth_runtime recovery_tokens --locked
cargo +stable test --workspace --all-features --locked
```

CI adds SQLite recovery transaction tests to the Linux/macOS/Windows auth matrix
and a local-Turso recovery profile on Linux. The existing external database token
consumption test now uses a bound credential. Neither configured CI jobs nor local
SQLite/Turso results establish external PostgreSQL/MySQL, remote-platform or
production-load parity. Those remain separate gates.
