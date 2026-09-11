# Migration Integrity And Runtime Upgrade

## SQL Migration Tracking

New migrations record a SHA-256 checksum of the exact SQL bytes alongside the
existing `_vsr_migrations` history. Editing an applied file, including comments
or line endings, is an error. Restore the original file and add a new migration.

PostgreSQL and MySQL use database-scoped advisory locks. Lock connections are
closed rather than returned to the pool, including on cancellation. SQLite and
Turso acquire their transaction's write lock before reading migration status.
A second runner cannot apply the same migration twice. A lock timeout or busy
database can still require the caller to retry.

### Existing Databases

Old name-only records cannot prove which SQL was deployed. The CLI refuses to
silently invent that evidence. After checking the original file against the
deployed schema and historical release, explicitly establish its baseline:

```sh
vsr migrate baseline --file migrations/0000_builtin_auth.sql
```

Use the same database/config options as the normal migration command. The
filename must match an already applied migration. Baseline records the current
file's checksum; it does not execute SQL or verify historical equivalence.
It cannot replace existing integrity metadata, accept a changed checksum, or
clear a failed migration. Preserve exact original built-in migration files too.

### Interrupted MySQL DDL

MySQL DDL may commit implicitly. Before executing it, VSR durably records the
checksum and marks the attempt dirty. A failure or interrupted process leaves
that record in place, and subsequent runners stop instead of replaying SQL over
an unknown partial schema. PostgreSQL/SQLite/Turso use transactional application.

To recover a dirty MySQL migration:

1. Stop automatic migration runners and take a backup.
2. Compare the actual schema and data with every statement in the original SQL.
3. Either restore the pre-migration database and remove the failed attempt after
   verifying restoration, or complete the remaining changes manually.
4. Only after verifying complete application, atomically record the matching
   `_vsr_migrations` name and clear `dirty` in `_vsr_migration_integrity`, retaining
   the original checksum. Have the repair reviewed before resuming runners.

There is deliberately no automatic repair/force flag. Changing migration SQL
to make a retry pass is not recovery. Migration scripts must not contain their
own transaction-control statements or alter VSR tracking tables.

## Authentication Compatibility

Built-in access tokens carry a reserved `_vsr_auth_state` fingerprint binding
the token to the account's salted password hash, role, configured claims, email,
verification state, and management timestamps. Extraction checks current account
state in the database. Account deletion, password changes/resets, or managed
role/claim updates invalidate previous tokens. Database errors fail closed.

Existing built-in tokens must be replaced by logging in after this upgrade.
Mount `web::Data<DbPool>` at the application level when registering protected
built-in HTML pages outside the API scope. Native and emitted servers do this
automatically. Explicit external/stateless JWT integrations without built-in
auth retain their existing extraction behavior. This is account-state binding,
not a per-session logout blacklist. Direct SQL administration should update
`updated_at` as well as account fields; restoring identical historical account
state cannot be distinguished from that original state.

Password work runs in blocking jobs with a process-wide cap of 1 to 8 jobs,
based on available parallelism. Saturation returns HTTP 503 `auth_busy` rather
than queuing unlimited expensive work. Cancellation does not release a running
job's permit. Running bcrypt jobs finish on runtime shutdown; they are not
interruptible mid-hash.

Applications using built-in verification or password-reset email must configure
`security.auth.email.public_base_url` before upgrading. It must be a trusted
HTTPS base URL (HTTP is allowed only for loopback development). Authentication
links no longer derive their origin from `Host` or forwarding headers. Include
the externally visible application prefix and check the resulting verification
and reset links behind the deployed reverse proxy. Missing configuration fails
closed instead of sending a request-controlled link.

Self-registration now rejects partially applied management schemas and propagates
timestamp-write failures instead of silently committing an incomplete account.
Apply the complete built-in auth management migration before enabling email.
The original base user schema remains supported without email. Programmatic
configuration, like EON configuration, may not require verification without a
configured email provider; it no longer silently auto-verifies such accounts.

Built-in admin list/read/update/delete operations now recheck the caller's live
admin role inside the operation's transaction. A stale or deleted administrator
cannot rely on a previously extracted role. Admin updates, including claim-only
changes, require the complete management schema; legacy base-schema reads and
deletion remain supported. The update revision advances monotonically even
with a repeated or backward clock, so restoring earlier claims does not revive
an old session. Reserved account/JWT claim mappings and duplicate column aliases
are rejected by the management bridge. Null claim input follows actual column
nullability, not whether an insert default exists.

Admin creation/invitations and authenticated account/admin verification resend
now use shared transactions and locked account state. The full management schema
is required before provisioning. Native resend handlers validate trusted link
configuration even when the target is already verified; invalid configuration
now fails instead of returning a no-op 204. Account IDs and recipient addresses
for self-service resend come only from the authenticated identity/current row,
not the request body. Creation retains default `user` roles and explicit opt-in
verification/invitation flags, including when email delivery is not configured.

Session login/logout responses now use shared framework-neutral presentation.
Successful responses add `Cache-Control: no-store`; cookie names, flags and JSON
field names remain unchanged. Treat CSRF values as opaque: newly issued values
are now 64 hexadecimal characters from 256 bits of OS randomness. EON and
programmatic cookie configuration reject attribute injection, percent-escaped
names, unsafe paths, reserved credential/CSRF header collisions and insecure
cookie prefixes. Login fails closed if configuration or entropy is invalid.
Logout rejects ambiguous/malformed cookies with 403 instead of selecting a first
cookie or treating a parsing failure as absence. Cookie clearing still requires
CSRF when any session cookie is present, even alongside a Bearer header. Logout
does not revoke a copied bearer token; account-state revocation is unchanged.

Login/registration now share bounded admission policy. Native CLI and newly
emitted servers enforce one in-process budget across workers instead of one per
worker, so multi-worker deployments may reach the configured quota sooner.
Exhausted quotas retain 429 with a rounded-up `Retry-After`; missing or failed
configured stores and capacity exhaustion now return 503 instead of bypassing
enforcement or growing an unbounded client map. Defaults cap resident keys at
10,000 and accepted timestamps at 100,000. Requests above the timestamp capacity
cannot be served. Absent rules still disable enforcement. Re-emit generated
servers to adopt shared worker state. Hand-built multi-worker apps should pass
one externally created `web::Data<auth::AuthRateLimiter>` to
`auth_api_routes_with_settings_and_limiter`; legacy helpers still allocate one
store per registration. These budgets are not shared across processes. See
[shared admission](http_backends.md#shared-authentication-admission) for capacity,
proxy and extraction-order limitations.

Trusted proxy chains are evaluated from the immediate peer right-to-left.
Malformed chains, conflicting forwarding header families, or a missing peer
never yield an attacker-supplied identity. Configure every trusted proxy and
have ingress strip or rebuild forwarded headers consistently.

## Local Storage Recovery

Both local implementations use the same durable redo-journal implementation in
`vsr-runtime`. Object bytes remain ordinary files. Metadata and object staging
files are synced before publishing a journal in `.vsr-meta/.vsr-transaction`.
An OS file lock serializes cooperating processes; the next API operation
finishes an interrupted publication or deletion before serving a pair.
S3-compatible GET reads bytes and metadata under one lock.

A failed write before journal publication leaves the previous object intact.
An error after journal publication has an uncertain commit outcome: recovery
may complete the new version. Retry only with that behavior in mind. Do not
manually remove the journal or staging files to dismiss an error. Backups must
include `.vsr-meta` and should run with writers stopped.

Symlink and normalized-path checks reject existing unsafe object/sidecar paths.
The storage root must be writable and exclusively managed by VSR: path checks are not
a defense against a hostile local process replacing directories concurrently.
All writers must use the new implementation; mixed old/new writer processes
do not share its lock protocol. Directory syncing is implemented on Unix.
Windows has atomic rename but the same power-loss durability has not been
established with portable `std` directory operations.

## New HTTP Adapter

The opt-in Actix adapter applies TLS, compression, CORS and security headers.
Invalid TLS and middleware settings fail before binding. Nonempty
`trusted_proxies` is explicitly unsupported until this adapter exposes verified
client identity; it is not silently ignored. This does not affect the existing
native CLI proxy implementation.

`ServerConfig.readiness` starts false. Applications must check required
dependencies and call `set_ready(true)`, then clear it if checks fail.
`/readyz` returns 503 while false; shutdown also clears it. `/healthz` reports
process liveness. The adapter does not invent database health on the caller's
behalf.

## Lint Enforcement

Every workspace member explicitly inherits the lint table. CI runs Clippy for
all targets/features and denies correctness violations. Unsafe code is denied
with scoped exceptions for existing environment-bootstrap tests and Win32 FFI.
The legacy CLI environment loader is a documented bootstrap-only exception;
it must run before workers start. New core/runtime crates retain their own
stronger unsafe-code prohibition. Pedantic and missing-documentation warnings
remain visible technical debt, not a warning-clean claim.

Generated HTTP implementation modules have a documented exception for
`clippy::result_large_err`: their existing `Result<T, HttpResponse>` contract
returns the complete Actix response without another allocation. Other generated
code warnings remain denied by the emitted-binary/Clippy checks. Those checks
apply `-D warnings` to the emitted target, not globally to path dependencies;
workspace dependency lint debt remains visible in its separate CI job.
