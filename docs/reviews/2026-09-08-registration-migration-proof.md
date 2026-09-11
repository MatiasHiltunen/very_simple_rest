# Shared Registration Migration Proof

Date: 2026-09-08. Baseline: `3ac6ffd78` on `v1` and `main`.
Scope: self-registration, not admin management or production Axum bootstrap.

## Implementation

- `vsr-runtime::auth::registration::RegistrationService` owns normalization,
  password validation and bounded bcrypt hashing, the fixed `user` role,
  management-schema policy, verification delivery and commit/rollback sequencing.
- `RegistrationRepository` and `RegistrationTransaction` expose bound account
  writes without HTTP, SQLx, EON or Actix types. The transaction also implements
  the existing `RecoveryTokenStore`, so email issuance reuses the shared sender.
- `rest_macro_core::auth::builtin_registration_service` supplies the temporary
  configured SQLx/Turso and provider bridge. Its SQLite/Turso transaction begins
  with a write reservation. Database uniqueness resolves competing registrations
  without a pre-insert existence check. All writes use the same transaction.
- Native registration delegates to the shared service. JSON extraction, rate
  limiting, trusted public URL resolution and the empty HTTP 201 response remain
  in the adapter. Generated Actix applications continue using this same facade.

## Compatibility And Hardening

The normal success, field-validation and duplicate-email contracts remain 201,
400 `validation_error`, and 409 `duplicate_email`. Submitted account IDs, roles,
tenant claims, hashes and verification timestamps do not enter service input.
Registration issues neither a login token nor a session cookie.

Full management schemas initialize timestamps and either issue verification mail
or retain automatic verification when email is not configured. Fully legacy base
schemas remain supported without email. Partially applied management schemas now
fail closed, and real timestamp-write errors are no longer ignored. Programmatic
configuration requiring email verification without a sender is rejected, matching
the existing EON validation. A password-reset sender cannot be used for registration.
Clock values are checked before password work or opening a transaction.

Only the token digest is persisted. A provider failure, timeout, insert failure,
initialization failure or cancellation rolls back the new account and token.
Commit and rollback failures are not reported as success. The duplicate-email
constraint remains the authority when normalized requests race.

## Local Verification

Commands use stable Rust with debug information disabled and `--locked`.

| Check | Result |
| --- | --- |
| Runtime-only auth library, no HTTP features | 46 passed |
| Registration repository tests with SQLite and Turso | 2 passed, each exercises both local drivers |
| Native Actix and both runtime transports, real HTTP | 7 passed |
| Shared auth normal dependency graph | Neither Actix nor Axum present |
| Runtime contract-only build, no default features | Passed |
| New Rust modules, scoped rustfmt check | Passed |
| Full all-feature workspace regression | 746 passed, 0 failed, 16 ignored |
| Workspace Clippy, all features and targets | Passed with repository/test-style warnings |
| mdBook build and diff whitespace check | Passed |

Runtime tests cover validation before transactions, server-selected roles, bcrypt
hashing, exact clock precision, base/full/partial schema policy, token hashing and
purpose, delivery ordering, failed writes/commit/rollback, timeout and cancellation.
Database tests use temporary files and failure-injection triggers to prove that
the account and token disappear together on failure. A two-request race produces
one account, one accepted email and one duplicate error. The issued token verifies
the account exactly once.

The real HTTP proof exercises registrations both with and without email through
native Actix, the neutral Actix adapter and Axum. It attempts privilege injection,
checks live account claims and denied admin access, verifies duplicate responses,
and logs in across transports. The local mock Resend provider rejects a request
to prove rollback, then accepts a retry. Verification is consumed through a
different transport; login is rejected before verification and succeeds afterward.
Submitted Host headers do not change the configured link origin.

Logs: `/private/tmp/vsr-registration-runtime.log`,
`/private/tmp/vsr-registration-sql.log`, `/private/tmp/vsr-registration-http.log`,
`/private/tmp/vsr-registration-workspace-retry.log`,
`/private/tmp/vsr-registration-clippy-retry.log`, and
`/private/tmp/vsr-registration-contract.log`.

The first broad test and Clippy runs stopped when the local disk filled. Only
this worktree's disposable `target/debug/incremental` cache was removed, recovering
about 48 GiB. The successful full rerun used `CARGO_INCREMENTAL=0`; the unrelated
SQLite test that could not open its file then passed. No source or application
data was removed for space recovery.

## Remaining Gates

The new SQLite registration tests are configured on Linux, macOS and Windows;
Turso runs on Linux. The existing ignored PostgreSQL/MySQL concurrency test now
also checks duplicate registration and initialized account state. These additions
have not been executed remotely for this uncommitted milestone. Prior green CI
on the baseline is not proof of the new registration checks.

The infrastructure bridge still links Actix. Admin lifecycle operations,
production cookie/extractor/rate-limit routing, row authorization, streaming,
and native/generated backend selection remain incomplete. Actix stays the default.

Email acceptance is not atomic with database commit: commit failure or cancellation
after acceptance can leave an unusable delivered link. No durable outbox, external
SMTP/inbox acceptance, timing-equivalent duplicate response, per-account abuse
controls, power-loss recovery or production-load result is claimed. Existing
dependency advisories remain tracked separately in `docs/src/dependencies.md`.
