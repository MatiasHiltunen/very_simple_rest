# Shared Recovery Email: Migration Proof

Date: 2026-09-08. Baseline: `v1` / `origin/v1` at
`edad7d3892652d43d4c1d23893d1e27ee076e5f0`. The request-auth, account-service and
recovery-consumption milestones were committed and pushed before this work.
This record describes the recovery-email migration milestone built on that baseline.

## Scope

`vsr-runtime::auth::recovery_email` now owns anonymous verification-resend and
password-reset request orchestration, token generation, expiry calculation,
templates and bounded asynchronous delivery through the existing `Mailer` trait.
The service has injected repository, mailer and clock boundaries. SQL and configured
SMTP/Resend adapters remain in the legacy facade; its public bridge still links Actix.

Native anonymous handlers delegate to the service. Registration, account verification
and admin verification helpers reuse the shared sender inside their existing
transactions. Their broader lifecycle/authorization and transaction ownership are
not migrated. No native/emitted CLI backend switch is added.

## Corrections And Compatibility

- Recovery link origins no longer fall back to client-controlled Host/Forwarded
  headers. `security.auth.email.public_base_url` is required for delivery, with
  HTTPS except literal loopback/localhost development. Scope prefixes remain.
- Recovery credentials now use 256 bits of OS entropy, encoded as 64 hex characters.
  Only SHA-256 digests and checked RFC3339 microsecond expiries are persisted.
  Existing unexpired email-bound tokens retain compatibility.
- Invalid TTL/clock arithmetic fails without clamping or panic. Email-provider
  failures are redacted; asynchronous delivery waits are limited to 30 seconds
  by the facade. MailMessage Debug output is redacted.
- Anonymous requests read recipients in a transaction. SQLite/local Turso acquire
  a write reservation; PostgreSQL/MySQL lock the account row, including first issuance.
  The latter SQL paths are compiled but not verified against external databases.
- The generated lifecycle fixture and Bridgeboard EON example now configure a
  trusted public base URL. The full-suite failure exposed that generated scope
  configuration superseded an ineffective test-local auth override; the fixture
  now supplies the authoritative setting and asserts the resulting email origin.

## Evidence

Seven runtime policy tests exercise checked expiry/entropy failure, secure URL
validation, request normalization/suppression, both templates, HTML escaping,
redaction, repository/delivery/timeout/commit/rollback failures and cancellation.

Two facade tests cover trusted-origin/scoped URL lowering and real SQLite/local
Turso transactions: missing accounts, verified-account suppression, current-email
binding, provider failure, insert failure after deletion, cancellation during
delivery, concurrent replacement, digest-only persistence and successful consumption
of only the newest link. Insert failure and cancellation preserve the previous token.

A real HTTP test runs native Actix, neutral Actix and Axum against the same database.
Every path requests verification and reset mail through a local mock Resend endpoint,
extracts the actual emailed token, consumes it through another backend, rejects reuse,
and proves password replacement and old-session revocation on all three paths.
Spoofed Host/Forwarded headers do not change the email origin. Provider failures
return redacted errors and preserve the preceding link. Native registration also
issues through the shared sender. Sender and reply-to compatibility are asserted.

The existing generated Actix lifecycle test separately covers captured email,
account/admin operations and browser pages with the migrated EON configuration.
Neither proof establishes external inbox receipt or SMTP provider availability.

Local macOS validation:

| Check | Result |
| --- | --- |
| Targeted runtime and SQLite/local-Turso issuance tests | 9 passed |
| New real HTTP email flow | Passed |
| Generated Actix auth/account/email lifecycle | Passed |
| Auth-only runtime library profile | 39 passed |
| Full all-feature workspace suite | 732 passed, 0 failed, 16 ignored |
| Minimal SQLite/provider real HTTP profile | 4 passed |
| SQLite-only issuance database profile | 2 passed |
| Framework-free contract build | Passed |
| Clippy for core/runtime/facade libraries and tests | Passed with warnings; not warning-clean |
| Focused formatting, whitespace, CI YAML and mdBook | Passed |
| Auth-only normal dependency graph | Neither HTTP framework present |
| Enterprise Axum normal dependency graph | No Actix or legacy facade dependency |

Commands use stable Rust with `RUSTUP_TOOLCHAIN=stable`,
`CARGO_PROFILE_DEV_DEBUG=0` and `CARGO_PROFILE_TEST_DEBUG=0`:

```sh
cargo +stable test -p vsr-runtime --no-default-features --features auth-builtin --lib --locked
cargo +stable test -p rest_macro_core --all-features --lib auth::recovery_email::tests --locked
cargo +stable test -p rest_macro_core --no-default-features --features sqlite,auth-email --test builtin_auth_runtime --locked
cargo +stable test -p very_simple_rest --all-features --test auth_management --locked
cargo +stable test --workspace --all-features --locked
```

Evidence logs use `/private/tmp/vsr-email-` prefixes. CI adds issuance replacement
tests to the Linux/macOS/Windows auth matrix, includes the real email HTTP test,
and adds local Turso issuance tests on Linux. Configured CI is not executed CI.

## Remaining Gates

Delivery still occurs before commit, not through a durable outbox. Mail acceptance
and database commit cannot be atomic: cancellation or commit failure after delivery
can produce an unusable link. Async timeouts require cooperative mailer implementations;
existing local secret-file/capture I/O remains synchronous in the facade.

Missing-account success bodies are identical, but response timing and provider
failures can disclose account existence. Durable asynchronous delivery, per-account
recovery abuse controls, timing resistance and reset-notification mail remain
production hardening work. These are distinct requirements in the
[OWASP recovery guidance](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html),
not satisfied by this extraction alone.

Registration/admin lifecycle extraction, production cookie/CSRF/extraction/rate-limit
routing, row authorization, streaming and Actix-free native/emitted selection remain
incomplete. External PostgreSQL/MySQL, remote platforms, real SMTP and production
load also remain unverified. Phase 3 is not complete.
