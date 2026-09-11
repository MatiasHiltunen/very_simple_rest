# HTTP Backend Options

## Current Scope

`vsr-runtime` offers Actix and Axum transports for the same VSR `Handler`,
`RouteTable`, `RequestContext` and `ResponseEnvelope` contracts. Select
`http-actix` or `http-axum` in that crate's features. Both can be compiled
together without changing handlers. An Axum-only runtime consumer does not
depend on Actix. The contract-only build enables neither framework.

This is the first transport milestone of the architecture migration, not an
Axum replacement for the native CLI. `vsr serve`, generated applications,
built-in account endpoints, and existing multipart/static routes still use their
established Actix paths. No CLI `--http-backend` switch is provided yet.
Those paths and their configuration have not been switched to the new adapter.

## Embedding Example

From the workspace, the same example can run with either transport:

```sh
cargo run -p vsr-runtime --no-default-features --features http-actix --example http_backend -- actix
cargo run -p vsr-runtime --no-default-features --features http-axum --example http_backend -- axum
```

Each invocation prints its loopback URL on an OS-assigned port. The example
sets readiness after initialization and drains the server on Ctrl-C. In a
both-enabled build the example defaults to Actix unless Axum is explicitly
selected. A selected backend that was not compiled in is an error.

Application code calls `ActixHttpServer::serve` or `AxumHttpServer::serve` with
the same route registrations. Dependency state can be captured by `make_handler`
closures. Use `ServerHandle::wait_for_exit` to observe unexpected completion and
`HttpServer::shutdown` to collect its result or request graceful shutdown.

## Shared Protocol Contract

- Registrations are validated before binding, using a shared `matchit` table.
  Use full-segment `{name}` captures and terminal, nonempty `{*tail}` captures.
  Regex and partial-segment captures are not portable and are rejected.
  Duplicate method/path registrations and conflicting capture names fail.
  Capture names must be unique within a template. Static segments use unescaped
  ASCII URI path characters; Unicode values are supported in captures.
  `/healthz` and `/readyz` are reserved and cannot be shadowed by catch-alls.
- GET implies HEAD when no explicit HEAD handler exists. OPTIONS reports the
  supported methods unless explicitly registered. Unsupported methods on known
  paths return 405 with Allow; unknown paths return 404. Methods never silently
  become GET.
- `RequestContext.path` retains the raw percent-encoded path. Captures are decoded
  exactly once after matching. Query names and repeated values use form decoding;
  `raw_query` remains available. Malformed percent escapes and invalid encoded
  query/capture UTF-8 return 400. Do not decode a whole routing path or decode
  captures again.
- `HeaderFields` validates names and values, preserves repeated fields and opaque
  bytes, and uses case-insensitive lookup. Responses append separate Set-Cookie
  fields rather than replacing them. Request headers retain original encoding
  and length fields even when a supported content encoding is decompressed.
- `ResponseEnvelope::try_json` propagates serialization errors;
  `ResponseEnvelope::json` maps them to a JSON 500 response, never an empty 200.
- Context includes the direct peer address, matched route template and a
  server-issued request ID. Caller-provided request IDs remain available in the
  original headers; they do not replace the server's ID.

## Security And Lifecycle

Both transports honor configured TLS, CORS, security headers, compression and
body limits. TLS uses an explicit Rustls ring provider and configured certificate
chain/private key. Axum uses `axum-server` for TLS connections and draining,
and Tower HTTP for compression, decompression and CORS headers. Forbidden CORS
origins/preflights are explicitly rejected, matching the Actix policy.

`max_body_bytes` bounds the buffered, decompressed body, including bodies without
a usable original content length. The boundary still buffers requests/responses;
streaming and the migration of large-file/static/multipart behavior are future
work. A body limit is not a complete production denial-of-service control: request
deadlines, concurrency budgets and full application rate limiting also need to be
integrated before the new runtime replaces current production wiring.

Readiness starts false. The application must set it after checking dependencies
and clear it when they become unavailable. Shutdown and server task exit clear
it automatically. Liveness is independent of readiness.

Explicit shutdown drains active requests up to `shutdown_timeout` (default 30
seconds); Actix rounds the duration up to a whole second. Dropping a handle asks
the transport to stop immediately and cancel active handlers. The embedding
application owns OS signals and Tokio runtime initialization. Actix does not
install its own signal handlers in this adapter.

An explicit `workers` value is Actix-specific. Axum runs on the caller's Tokio
executor and rejects this setting; it is not silently interpreted as an executor
thread count. Both adapters reject nonempty `trusted_proxies` until verified
forwarded client identity is implemented. Raw forwarding headers are not trusted.

The HTTP identity type aliases `auth::AuthenticatedIdentity`. This unifies the
data model but does not automatically authenticate a request. Unwrapped handlers
receive no identity. Use the explicit request-authentication wrapper described
below and supply authorization before exposing protected application handlers.
Anonymous-client policy and full application rate limiting still need migration.

## Built-in Request Authentication

The `auth-builtin` feature now owns the existing access-token claims format,
account-state fingerprint, live-state validation policy, Bearer/cookie selection,
CSRF checks and bounded password worker pool. It does not depend on Actix or Axum.
The no-default-features runtime remains a lightweight contract-only consumer.

`auth::request::RequestAuthenticator` is the request-only interface.
`require_authentication(Arc<Authenticator>, handler)` authenticates on every
request, discards any preexisting identity, and sets the canonical identity only
after success. Rejections do not invoke the handler. The handler must still check
operation permissions and row visibility; authentication is not authorization.

`auth::builtin::BuiltinRequestAuth` requires an `AccessBackend` that verifies JWT
signatures/algorithm/expiry/issuer/audience and reads current account state. It
requires live state by default. The explicit `IfPresent` compatibility policy is
only for externally issued tokens: it never bypasses a state claim when present.
Do not select that mode for built-in account routes.

`rest_macro_core::auth::builtin_request_authenticator(db, settings)` supplies the
existing configured-key and SQL account adapters. The native/generated Actix
`UserContext` extractor now delegates to exactly the same shared policy. Its
serialized ID, roles and custom claims remain compatible, and account-state
fingerprints remain byte-compatible with previously issued tokens. Password
changes and account operations use the shared worker pool and account service.

Credential ambiguity is rejected consistently: repeated Authorization headers,
duplicate session/CSRF cookies (including encoded aliases), duplicate CSRF headers
and malformed Authorization values do not select an arbitrary credential. A
present invalid Authorization header never falls back to a valid cookie. Bearer
scheme matching is case-insensitive; cookie-based unsafe methods still require
the configured CSRF pair. Nonpositive built-in numeric subjects are rejected.
Authentication failures retain existing JSON codes and now include a Bearer
challenge on 401 responses in both native and neutral paths.

Password work uses a shared bounded pool with no unbounded admission queue.
Cancelling a request does not release a running job's permit: started
[`spawn_blocking` tasks cannot be aborted](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html).

This is an incremental extraction, not a complete `BuiltinAuthProvider` or a CLI
backend selector. Key loading/signing, account HTTP adapters, the SQL repository
and row-policy integration remain in the legacy facade. The
bridge therefore still links Actix even when a neutral route runs on Axum; the
runtime-only policy and enterprise example retain their isolated dependency graphs.

The extraction passed the 692-test workspace suite (16 ignored), including a
real-login/SQLite comparison of native Actix and both adapters. The proof is
recorded in `docs/reviews/2026-09-08-builtin-auth-migration-proof.md`.

## Shared Account Operations

`auth::accounts::AccountService` (feature `auth-builtin`) now owns login,
account reads and password changes. It receives an `AccountRepository`, an
`AccessTokenIssuer`, an `AccountPolicy` and an injectable clock. The service has
no HTTP framework, SQL driver or configuration-parser dependency.

Login normalizes email, verifies the password using the bounded pool, applies
email-verification policy and supplies the signer with the existing state-bound
JWT claims. TTLs must be positive; expiration arithmetic is checked. Login and
current-password input are capped at bcrypt's 72-byte boundary. New passwords
retain the existing minimum of eight characters and maximum of 72 bytes.

Account reads return current public fields and mapped claims, without password
hashes or session fingerprints. Protected operations must receive the user ID
from successful request authentication, never from a request-body account ID.
Password changes verify the current password and conditionally update the stored
hash. The repository must match the account ID, old hash and management revision
atomically. A concurrent change/deletion returns `409 account_changed`, not a
successful overwrite. Base schemas and NULL revisions remain supported; a schema
error during the update does not trigger a weaker fallback query.

`rest_macro_core::auth::builtin_account_service(db, settings)` supplies the
temporary configured-key and SQLx/Turso adapters. Existing public Actix login,
account and password-change handler signatures remain unchanged and delegate to
the service. Cookie issuance and logout policy use the shared session presentation
below. JSON extraction remains in the HTTP layer; admission uses shared policy.
the account service is not a production route installer.

This account milestone does not itself migrate admin operations or application
authorization. Registration, verification/reset consumption and email delivery
are covered by the following sections. Native/emitted servers
still use Actix. The account service itself is framework-independent, but its
temporary legacy infrastructure bridge still links Actix. Verification and
remaining gates are recorded in
`docs/reviews/2026-09-08-account-service-migration-proof.md`.

## Shared Session Presentation

`auth::session::SessionPresentation` (feature `auth-builtin`) presents successfully
issued access tokens and clears browser cookies without depending on Actix or Axum.
`rest_macro_core::auth::builtin_session_presentation(settings)` maps existing
EON/programmatic settings into this policy. Native login/logout now delegate to it.
Public handler signatures and existing bearer/cookie JSON fields are unchanged.

Cookie mode returns two separate `Set-Cookie` headers: an HttpOnly session cookie
and a readable CSRF cookie, with matching configured path, Secure, SameSite and
Max-Age attributes. No Domain is emitted. CSRF tokens now use 32 bytes of fallible
OS randomness encoded as 64 hexadecimal characters; clients must treat them as
opaque. Entropy failure does not issue a partial response. Each serialized cookie
is limited to 4096 bytes by application policy. Bearer-only mode returns only the
token JSON without generating CSRF material. Successful login/logout responses
include `Cache-Control: no-store`.

EON and programmatic cookie configuration reject unsafe/ambiguous names, percent
escapes in names, invalid paths, credential headers reused as CSRF headers, and
insecure `__Host-`/`__Secure-` prefixes. SameSite=None requires Secure. Paths must
be absolute visible ASCII without semicolons, query/fragment markers or backslashes.
Programmatic configuration is validated before native login calls the account service.

Logout checks every Cookie header through the same parser as request authentication.
Any session cookie, including an empty or expired token, requires exactly one
matching CSRF cookie/header. Duplicate/encoded-alias session cookies, duplicate
CSRF fields and malformed cookies fail with 403 and no clearing cookies. A Bearer
header does not bypass cookie-clearing CSRF checks. Without a session cookie,
logout remains idempotent; without cookie configuration, it returns empty 204.
Deletion uses the same attributes and scope as issuance with empty values and
Max-Age=0. It does not require a valid, unexpired JWT.

This is stateless presentation, not server-side session storage or per-token
revocation. A copied bearer token remains valid after logout until expiry or an
account-state change. Real HTTP tests prove cross-transport presentation and
CSRF behavior, not browser SameSite/Secure enforcement. Full route extraction,
installation and native/generated Axum selection still remain. See
`docs/reviews/2026-09-11-session-migration-proof.md`.

## Shared Authentication Admission

`auth::admission` (feature `auth-builtin`) supplies `check_auth_rate_limit` and the
`rate_limit_authentication` handler wrapper for login and registration. The
wrapper uses the direct socket IP, ignoring forwarding headers and supplied
identities. A missing peer shares an `unknown` bucket. Proxy-aware consumers must
explicitly resolve a trusted chain before calling the check function. Native
Actix retains its existing trusted-proxy resolver; the neutral transports still
reject nonempty `MiddlewareConfig.trusted_proxies`.

`rate_limit::MemoryRateLimitStore` is a mutex-serialized sliding window with
monotonic expiry and independent login/register keys. Successful and unsuccessful
admitted attempts consume quota; denied attempts do not extend it. Exhaustion
returns `429 rate_limited` with a rounded-up `Retry-After`. Store errors, missing
configured native stores and capacity exhaustion return a redacted
`503 auth_rate_limit_unavailable` with `Retry-After: 1`. Zero-valued rules are
invalid, not a way to disable enforcement; absent EON rules remain disabled.

Default capacity is 10,000 keys, 100,000 accepted timestamps and 1,024 string bytes
per key. These are count limits, not a byte-exact memory budget. Expired bursts
release excess queue allocation. Live counters are never evicted to admit a new
key, and changing a live key's rule fails closed until its old events expire or
an operator explicitly resets it. Cold expired keys are swept at most once per
second, so capacity recovery can lag expiry by up to that interval. A per-key
request limit above the store's total event capacity cannot be served.

Native `vsr serve` and newly emitted Actix servers create one store outside their
worker factories. Hand-built multi-worker apps must create one
`web::Data<auth::AuthRateLimiter>` outside `HttpServer::new` and pass clones to
`auth_api_routes_with_settings_and_limiter`. The older route helpers preserve
their signatures but still create a fresh per-registration store. Explicit
consumers may configure `MemoryRateLimitCapacity` through the store constructor;
there are no EON capacity overrides yet.

This is a single-process quota, reset on restart, not a distributed Redis store
or complete abuse prevention. Use a shared-store adapter or ingress policy for
multi-process deployments. Authentication admission does not itself authenticate
a request. Native JSON extraction still precedes its handler check. Placing the
neutral wrapper outside extraction charges malformed JSON that native Actix
rejects first; complete extraction/installation parity remains migration work.
Live tests share one store across four native workers and both neutral
transports. See `docs/reviews/2026-09-11-admission-migration-proof.md`.

## Shared Recovery Operations

`auth::recovery::RecoveryService` owns email verification and password-reset
consumption. `RecoveryRepository` supplies a transaction whose token lookup,
conditional claim, account mutation and token deletion share one commit boundary.
An error rolls the transaction back; cancellation drops an unfinished transaction.
Adapters must implement rollback-on-drop and must not report success when no
account row was updated.

Expiry retains RFC3339 microsecond precision, rejects malformed dates and expires
at the exact deadline. The service checks again after claiming because a claim
can wait behind another transaction. The additive `Clock::now_unix_micros` method
allows deterministic tests without reducing production precision. Recovery token
hashes retain the existing SHA-256 format; the database receives only the digest.

Tokens now require their stored `requested_email` to match the current account
email atomically. Missing bindings, changed email addresses and deleted accounts
cannot produce successful verification/reset. A mismatched token is removed, so
restoring the old address cannot revive it. Existing normal email issuance already
stores this binding. Legacy manually created tokens with NULL/empty bindings are
now rejected; request a new email instead of rewriting stored recovery tokens.

`rest_macro_core::auth::builtin_recovery_service(db)` supplies the temporary
SQLx/Turso bridge. SQLite and local Turso reserve the write transaction before
reading to avoid read-to-write lock-upgrade failures under competing consumers.
Other databases retain their existing transaction/conditional-claim mechanism.
Password validation and bounded bcrypt work run before opening the transaction.
Resetting a password changes the account fingerprint, invalidating old sessions.

Existing Actix JSON endpoints and the verification HTML page delegate to this
service without changing their public handler signatures or response codes.
Real HTTP tests also mount the service behind both runtime adapters. These remain
test-only route adapters: production extraction and route installation still need
migration. Recovery abuse controls remain separate from login/register admission.
Email issuance, registration and provisioning are covered by the
following sections. Native/emitted
backend selection and the Actix-free infrastructure bridge remain incomplete.
See `docs/reviews/2026-09-08-recovery-service-migration-proof.md`.

## Shared Recovery Email

`auth::recovery_email::RecoveryEmailService` now owns anonymous verification-resend
and password-reset requests. It normalizes the submitted email, reads the current
recipient inside a driver transaction, suppresses absent/already-verified
verification recipients, replaces the email-bound token, sends the message and
commits. Both normal and suppressed requests return an empty 202 response.

`RecoveryEmailSender` is also used inside shared registration and provisioning
transactions. It uses the existing neutral `Mailer` interface,
shared text/HTML templates, 256 bits of fallible OS entropy, SHA-256 token digests,
checked microsecond expiry arithmetic and a bounded delivery wait. The facade
uses a 30-second delivery timeout and retains configured SMTP, Resend, sender,
reply-to and capture-file support. Provider errors are redacted in public errors;
`MailMessage` Debug output no longer contains addresses or credential-bearing bodies.

`rest_macro_core::auth::builtin_recovery_email_service` supplies the temporary SQL
and provider bridge. SQLite/Turso anonymous requests reserve the write transaction
before reading; PostgreSQL/MySQL use an account-row lock, including first issuance
where no token row exists. Only local SQLite and Turso concurrency is verified.
Registration, managed reads/updates/deletion, admin creation and authenticated
verification resend now have shared transaction ownership, covered below.

Compatibility change: `security.auth.email.public_base_url` must now be configured
to send authentication emails, even inside an HTTP request. Links never fall back
to Host or Forwarded headers. Use HTTPS; HTTP is accepted only for literal
loopback addresses or `localhost` development. Credential-bearing URLs are rejected.
Application scope prefixes remain supported. Missing/invalid configuration fails
before issuing a token; existing configuration documents still deserialize.
Tokens remain opaque to clients; newly issued tokens are 64 hex characters rather
than 48 alphanumeric characters. Existing unexpired, email-bound tokens still work.

This is not a durable outbox: mail acceptance and database commit are not atomic.
Commit failure or cancellation after acceptance can leave a delivered link unusable;
retry requests replace earlier links. Missing-account responses, provider failures
and response timing can still disclose account existence. Per-account recovery
abuse controls, timing-resistant asynchronous delivery and reset-notification mail
remain production hardening gates. These limits matter alongside the
[OWASP recovery guidance](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).

The real HTTP proof uses a local mock Resend provider, not an external inbox or
SMTP acceptance test. See `docs/reviews/2026-09-08-recovery-email-migration-proof.md`.

## Shared Registration

`auth::registration::RegistrationService` owns self-registration validation,
bounded bcrypt work, the fixed `user` role, schema policy and transaction sequencing.
`RegistrationRepository` supplies a transaction that creates and reads the account,
initializes timestamps, sets verification state and writes recovery tokens. Password
hashing happens before acquiring the transaction. No client-selected role, account
ID, verification state or application claim is accepted by the service.

With configured email, registration reuses `RecoveryEmailSender` and commits only
after provider acceptance. The account stays unverified until its email-bound
single-use token is consumed. Without email, full-schema accounts retain the
existing automatic-verification behavior. A wholly legacy base schema is supported
only without email. Partial management schemas now return `MissingSchema`; failed
timestamp writes are no longer ignored. Requiring verification without a sender
is rejected even when configuring the runtime directly, matching EON validation.

`rest_macro_core::auth::builtin_registration_service(db, settings, verification_url)`
provides the temporary SQLx/Turso/provider bridge. The optional URL is required
when email is enabled and must be a trusted configured verification endpoint.
The existing Actix handlers delegate without changing their public signatures:
success remains an empty 201, duplicate email remains 409 `duplicate_email`, and
field validation remains 400. The database unique constraint arbitrates concurrent
normalized registrations; errors and cancellation roll back the entire account
and token transaction. Registration rate limits now delegate to shared admission.

This registration milestone does not install production Axum routes. The
infrastructure bridge still links Actix. Mail acceptance is still not atomic with
commit, duplicate/timing responses still disclose account existence, and the caller
must control registration exposure and abuse. See the local proof and remaining
gates in `docs/reviews/2026-09-08-registration-migration-proof.md`.

## Shared Admin Operations

`auth::management::ManagementService` owns built-in global-admin list/read,
role/verification/claim updates, and deletion. Its input accepts an authenticated
identity from the trusted request wrapper, never an actor ID from request JSON.
The role must include exactly `admin`; the convenience `is_admin` flag alone
does not authorize anything. The service also locks and reloads the caller's
account and requires its current role to be `admin` before accessing the result
or making changes. This is additional live-role authorization, not a substitute
for token verification, expiry, account-state checks or cookie CSRF validation.

`rest_macro_core::auth::builtin_management_service(db, settings)` provides the
temporary SQLx/Turso bridge. SQLite/Turso reserve the write transaction; the
PostgreSQL/MySQL implementation uses ordered account-row locks. The actor and
target stay locked until commit/rollback. Claim metadata, all writes and response
reloads use that transaction, without acquiring another pooled connection.
Unfinished transactions roll back on errors/cancellation; failed commits are not
success responses. A lost database commit acknowledgement can leave the outcome unknown.
The existing native Actix function signatures, public input paths, response
shapes, pagination limits and self-deletion prohibition remain intact.

Only explicitly configured, typed application claims are writable. Storage
nullability is independent of defaults: a `NOT NULL DEFAULT ...` column rejects
null input. Reserved account/JWT fields and ambiguous column aliases are rejected
by this bridge. SQL identifiers come from validated server configuration, and
values remain bound parameters. Account responses omit password hashes and
session fingerprints.

Updates now require the full management schema, including claim-only changes.
Every successful update advances `updated_at` beyond the previous revision even
when the clock repeats or moves backward. Restoring prior role/claim values does
not revive old tokens. Legacy base-schema reads/deletion remain available, but
apply the management migration before attempting updates.

Local tests cover runtime policy, SQLite/Turso transactions and real native
Actix/shared Actix/Axum HTTP parity. The new PostgreSQL/MySQL concurrency checks
and platform matrix have not run remotely for this unpushed milestone. See
`docs/reviews/2026-09-11-admin-management-migration-proof.md`.

Admin creation and authenticated verification resend are covered below; dashboard
rendering remains in the native facade. These are global administrators, not
tenant-scoped admin roles. No new last-administrator protection or audit/outbox
policy is introduced.
The bridge still links Actix; production route extraction, streaming and native/
generated Axum backend selection remain incomplete. Actix stays the default.

## Shared Provisioning

`auth::provisioning::ProvisioningService` owns admin account creation/invitations,
authenticated account verification resend and admin verification resend. It reuses
the management transaction and live-role authorization instead of duplicating
per-framework policy. The additional `ProvisioningTransaction` adds account insertion
and token replacement capabilities without adding email dependencies to admin reads.

Creation normalizes email, validates passwords/roles and uses bounded bcrypt work
before opening a transaction. It then locks/rechecks the global admin, requires
the complete management schema, inserts the initialized account, optionally sends
verification mail and commits. The public account snapshot is read before commit.
Concurrent normalized duplicates retain the 409 contract. Omitted/blank roles
default to `user`; verification and invitation both default to false. Specifying
both as true returns 400 `invalid_invite_state`. Only a current global admin may
select the new role. Submitted account IDs, password hashes and custom claims are
not accepted; configured database defaults initialize custom claims.

Self-service resend accepts only the authenticated identity, not a target ID or
email. Admin resend uses ordered actor/target locks and live admin authorization.
Both read verification state and the current recipient address under lock before
replacing a token. Success remains empty 202; already verified accounts return
empty 204 without mail/token writes. Missing-email configuration returns 503.
Failed delivery rolls back the new account or token replacement, preserving an
earlier token on failed resend. Debug output for the create input redacts passwords.

`rest_macro_core::auth::builtin_provisioning_service(db, settings, verification_url)`
provides the temporary SQL/provider bridge. Pass a trusted configured URL to enable
delivery, or None for creation without email. Native handlers keep their public
signatures and scoped Location headers. They resolve trusted email configuration
before dispatch, even for an already-verified resend: invalid link configuration
now fails closed instead of returning a no-op response. Base and partial legacy
schemas cannot be used for provisioning; apply the complete management migration.

The local proof covers SQLite/Turso and real native Actix/shared Actix/Axum requests,
including a mock Resend provider. This is not external inbox/SMTP acceptance, a
durable outbox or production-load proof. Mail accepted before a failed commit may
produce an unusable delivered link, and a lost commit acknowledgement may leave
the outcome unknown. Abuse controls and request idempotency remain separate gates.
See `docs/reviews/2026-09-11-provisioning-migration-proof.md`.

## Experimental API Changes

The new `vsr-runtime::http` surface is still under construction. Consumers of
its previous scaffold must adapt to these changes:

- Header maps become `HeaderFields`; use `append`, `get`, `get_all` and `iter`.
- Context gains raw-query, peer and matched-route fields; path is explicitly raw.
- Identity uses the canonical auth type, including email and expiry fields.
- `RouteRegistry::add_route` returns a validation result.
- Server configuration adds `shutdown_timeout`; handles implement `ServerHandle`.
- The shared route grammar replaces unvalidated Actix-specific route patterns.

These changes do not alter existing `rest_macro_core` Actix facade APIs.

## Verification And Remaining Work

The conformance suite runs the same encoding, header/error, route, CORS,
decompressed-body, verified TLS, readiness, shutdown, deadline cancellation,
drop cleanup and invalid-startup cases against both transports. CI includes
Actix-only, Axum-only and both-enabled profiles across Linux, macOS and Windows,
plus an Axum-only dependency graph check. Configuring these jobs is not evidence
that the remote matrix has already run.

Local verification on macOS (2026-09-08): the all-feature workspace suite passed
672 tests with 16 ignored. The shared conformance suite passed 22 tests with both
backends enabled and 11 tests each in separate Actix-only and Axum-only builds.
The contract-only build, Axum-only normal dependency graph and mdBook build also
passed. External database and remote operating-system checks remain separate.

An EON-defined enterprise example now supplies an authenticated, database-backed
CRUD slice on both transports. Its standard service schema is compiled by the
existing VSR compiler; the Axum binary has no Actix runtime dependency. The
example-local verifier and database grants are not replacements for the legacy
built-in auth implementation. See `examples/enterprise_api/README.md` and the
recorded proof in `docs/reviews/2026-09-08-enterprise-axum-proof.md`.

Streaming, complete shared policy integration, and native/emitted backend
selection remain required before declaring Phase 3 complete.
