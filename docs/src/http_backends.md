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
the service. Cookie issuance, CSRF presentation, JSON extraction and login rate
limiting remain in their existing HTTP layer. A neutral consumer must supply
these controls itself; the service is not a production route installer.

This milestone does not migrate registration, verification/reset tokens, admin
operations, email delivery or application authorization. Native/emitted servers
still use Actix. The account service itself is framework-independent, but its
temporary legacy infrastructure bridge still links Actix. Verification and
remaining gates are recorded in
`docs/reviews/2026-09-08-account-service-migration-proof.md`.

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
