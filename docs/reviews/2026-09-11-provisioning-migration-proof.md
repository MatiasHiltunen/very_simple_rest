# Shared Provisioning Migration Proof

Date: 2026-09-11. Continues the uncommitted admin-management milestone on local
`v1`, following committed self-registration `723f711cf`. No commit or push was
requested or performed for this continuation. Main's unrelated reports are preserved.

## Implementation

- `vsr-runtime::auth::provisioning::ProvisioningService` owns admin account
  creation/invitations and authenticated account/admin verification resend.
- `ProvisioningTransaction` extends the existing management transaction with
  insertion and token writes. It reuses locked live-role checks, transaction
  finalization and `RecoveryEmailSender`; no SQL/HTTP/EON types enter policy.
- Creation validates/normalizes input, hashes with the bounded bcrypt pool, then
  rechecks the admin under lock. It requires full schema capabilities before
  insertion and validates the returned initialized account. The public snapshot
  is read before commit, eliminating the former post-commit response reload.
- Resend locks current account state before checking verification or replacing
  tokens. Self-service accepts no target ID/address. Admin resend holds ordered
  actor/target locks. Provider failure preserves the prior token on rollback.
- Native Actix retains public handler signatures, input re-exports, JSON/status
  contracts and scoped Location headers. Obsolete facade-only password, input
  validation and email-transaction helpers were removed after callers migrated.

## Compatibility And Limits

Create returns 201 with public account JSON and Location. Duplicate email is 409;
validation is 400; mutually exclusive verification/invitation flags return 400
`invalid_invite_state`. Omitted or blank role remains `user`. Verification and
invitation default to false, including installations without email. Only the
authenticated current global admin can choose a role. Request IDs, hashes and
custom claims are ignored as before; configured database defaults initialize claims.
Create-input Debug output now redacts the password while retaining the Debug API.

Resend success is empty 202; already verified is empty 204 without token/mail writes.
Missing email is 503. Native handlers validate trusted link configuration before
dispatch, even when the account is already verified; invalid configuration now
fails closed instead of returning a no-op. Complete management schema is required.
Partial/base schemas return the shared MissingSchema failure before insertion.

This remains global built-in administration, not tenant-admin delegation. The
request wrapper must validate credentials, expiry, token state and cookie CSRF.
Delivery is accepted before commit for existing rollback compatibility. It is
not an outbox: an accepted message may become unusable if commit fails, and loss
of commit acknowledgement can leave the outcome unknown. No external SMTP/inbox,
abuse-resistance, idempotency, durable audit or production-load claim is made.

## Local Verification

Commands use stable Rust with `--locked`, disabled debug information and
`CARGO_INCREMENTAL=0` to control disk usage.

| Check | Result |
| --- | --- |
| Runtime auth library without HTTP features | 60 passed |
| Provisioning repository tests | 4 passed, each on SQLite and Turso |
| SQLite-only CI feature configuration | 4 passed |
| New real HTTP provisioning test | Passed on native Actix/shared Actix/Axum |
| Full workspace regression | 770 passed, 0 failed, 16 ignored across 71 suites |
| Final SQL/facade auth rerun | 40 passed, 1 external-database test ignored |
| Workspace Clippy, all features and targets | Passed with existing workspace/test warnings; none in the new production management/provisioning modules |
| Framework isolation and contract-only build | Passed; no Actix/Axum normal dependencies with only `auth-builtin` |
| Scoped rustfmt, mdBook build and diff whitespace | Passed |

After the full workspace run, independent password-using auth unit tests were
serialized to avoid competing for the intentionally bounded production worker
pool. The runtime auth suite and SQL/facade auth suite passed again after this
test-only adjustment. The SQLite-only configuration and final Clippy run also
passed after the final documentation/formatting edits. Existing concurrency
checks within each test remain concurrent; production admission behavior was not
changed. The workspace run exercised all nine built-in-auth HTTP tests.

Runtime tests cover password hashing/redaction, normalization, role defaults,
invalid state/configuration/clock, live demotion/deletion, initialized account
checks, email-bound token digests, current-recipient lookup, verified no-op,
provider/write/commit/rollback errors, timeout and cancellation.

Repository tests prove actual rollback of new accounts/tokens after provider
failure, token-write failure and cancellation during mail delivery. They also
cover normalized duplicate races, initialized claims/timestamps, real password
verification, changed-recipient binding, replacement/replay behavior, previous
token preservation on failure and complete-schema requirements. An initial
legacy-schema test found driver-specific insertion error mapping; the service
now checks the locked administrator's schema capabilities before any insertion.

Real HTTP tests exercise both configured-email and no-email modes. They verify
201/Location, duplicate responses, ordinary-user denials, ignored privileged
fields, optional-verification login, provider failure/retry, self-service target
isolation, trusted links despite spoofed Host, cross-transport token consumption,
replay rejection and session revocation. A local mock Resend endpoint supplies
the delivery evidence; it is not an external provider/inbox acceptance test.

Logs use the `/private/tmp/vsr-provisioning-` prefix:
`runtime-final.log`, `sql.log`, `auth-final.log`, `sqlite-minimal.log`, `http.log`,
`workspace.log`, `clippy.log`, `contract.log`, `dependencies.txt` and `docs.log`.

## Remaining Migration Gates

CI now includes provisioning checks on the SQLite platform matrix and local Turso.
The existing isolated PostgreSQL/MySQL test additionally exercises admin creation
races, resend replacement, failed-delivery rollback and consumption of the issued
token. These remote additions have not run for the unpushed work. Their presence
does not establish external database or other-platform compatibility.

Production route extraction, cookie/session presentation, rate-limit composition,
shared row-authorization wiring, streaming and native/generated Axum bootstrap
still need integration. Dashboard/portal HTML presentation remains native. The
SQL/provider bridge still links Actix; Actix remains the default. The complete
AuthProvider target and Phase 3 are not declared finished.
