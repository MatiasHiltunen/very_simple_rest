# Shared Admin Management Migration Proof

Date: 2026-09-11. Baseline: local `v1` commit `723f711cf`, the committed
self-registration milestone. Neither that commit nor this follow-on work was
pushed as part of this task. `main` and its unrelated report files are untouched.

## Scope And Implementation

- `vsr-runtime::auth::management::ManagementService` owns built-in admin
  list/read/update/delete policy and transaction sequencing. Input types and
  stable error responses have no Actix, Axum, SQLx or EON types.
- The trusted request layer supplies the authenticated identity. A positive ID
  and exact `admin` role are required before repository access. The service then
  locks and checks the current actor row. A demoted/deleted actor is rejected
  even if its already-extracted identity still says admin.
- The SQL bridge reserves SQLite/Turso transactions and uses ordered row locks
  for PostgreSQL/MySQL. Actor/target locks, metadata, writes and response reloads
  remain on one transaction. No second pool acquisition occurs within it.
- Claim policy enforces configured names, scalar types and actual nullability;
  defaults are not permission to clear a NOT NULL column. The bridge rejects
  reserved account/JWT mappings and duplicate aliases. Values are bound and
  configured column names are quoted.
- Public responses omit salted hashes and fingerprints. Native Actix delegates
  through unchanged public handler signatures. Admin input types retain their
  facade re-exports, JSON shapes and pagination/self-deletion contracts.

## Compatibility And Hardening

All admin updates now require the complete management schema, including
claim-only writes. Legacy base-schema reads and deletion remain supported.
The revision advances beyond its previous timestamp even with equal/backward
clock readings. Restoring a previous role/claim no longer revives its token.

The service rechecks the live role inside the operation transaction, but does
not itself authenticate JWTs or revalidate every previously authenticated claim.
The caller must keep the existing request verifier, live token-state check,
expiry policy and cookie CSRF checks. Global built-in admins are not tenant
administrators. This milestone preserves self-demotion and does not add
last-administrator protection, a management audit log or a new deletion policy.

## Local Verification

Commands use stable Rust, `--locked`, disabled debug information and
`CARGO_INCREMENTAL=0` to keep disk use bounded.

| Check | Result |
| --- | --- |
| Runtime auth library without HTTP features | 53 passed |
| New SQL management tests | 4 passed, each on SQLite and Turso |
| New real HTTP admin parity test | Passed on native Actix/shared Actix/Axum |
| Complete built-in auth HTTP regression binary | 8 passed |
| Full workspace regression | 758 passed, 0 failed, 16 ignored |
| Workspace Clippy, all features/targets | Passed with repository/test-style warnings |
| Contract-only build and framework isolation | Passed; auth-only graph has neither Actix nor Axum |
| Scoped formatting, documentation build and whitespace | Passed |

Runtime tests verify authorization before storage, untrusted admin flags,
invalid identity IDs, locked demoted/deleted actors, sorted/deduplicated locks,
bounded lists, safe response fields, typed/null/unknown claims, missing schemas,
self-deletion, monotonic clocks, failed writes/commit/rollback and cancellation.

Local driver tests verify mapped integer/string/boolean claims, null handling,
filter binding, partial-write rollback, simultaneous updates, stale admin roles,
deletion/not-found behavior, configuration guards, cancellation after actual
writes and foreign-key restriction rollback. Full and legacy schemas use
separate databases; SQLite boolean storage follows the existing generated
INTEGER representation. Hot schema changes on a prepared-statement pool are
not claimed as verified by these fixtures.

The HTTP test denies ordinary users on every admin route, checks pagination and
error contracts, applies updates from every transport and reads identical results
through the others. It verifies old-token revocation after changes and reversions,
concurrent native/Axum update snapshots, deletion and demotion. Other existing
HTTP tests continue to cover login, cookies/CSRF, registration and recovery.

Logs: `/private/tmp/vsr-management-runtime.log`, `/private/tmp/vsr-management-sql.log`,
`/private/tmp/vsr-management-http.log`, `/private/tmp/vsr-management-workspace.log`,
`/private/tmp/vsr-management-clippy.log`, `/private/tmp/vsr-management-contract.log`,
`/private/tmp/vsr-management-dependencies.txt`, `/private/tmp/vsr-management-docs.log`.
No Clippy warning points to either new production `auth/management.rs` module.

## Remaining Gates

CI now includes these SQLite tests on Linux/macOS/Windows and Turso on Linux.
The existing isolated PostgreSQL/MySQL test also checks admin read/update/delete,
simultaneous revision changes and stale-role rejection. These new remote checks
have not run for this unpushed work. Local driver checks do not establish remote
database, other-platform or production-load parity.

Cancellation rolls back unfinished work, but a lost acknowledgement of a database
commit can leave its outcome unknown to the caller. Commit errors are not reported
as success; this milestone does not add request idempotency or commit-outcome recovery.

Admin creation, invitation delivery, account/admin verification resend and
dashboard presentation remain in the native facade. Production cookie/extraction/
rate-limit routing, row authorization, streaming and native/emitted Axum selection
remain incomplete. The temporary infrastructure bridge still links Actix. Actix
remains the default, and no production-backend replacement is claimed.
