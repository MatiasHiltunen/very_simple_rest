# HTTP Backend Options

## Current Scope

`vsr-runtime` offers Actix and Axum transports for the same VSR `Handler`,
`RouteTable`, `RequestContext` and `ResponseEnvelope` contracts. Select
`http-actix` or `http-axum` in that crate's features. Both can be compiled
together without changing handlers. An Axum-only runtime consumer does not
depend on Actix. The contract-only build enables neither framework.

This is the first transport milestone of the architecture migration, not an
Axum replacement for the native CLI. `vsr serve`, generated applications,
built-in authentication, and existing multipart/static routes still use their
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

The HTTP identity type now aliases `auth::AuthenticatedIdentity`. This unifies
the data model but does not automatically authenticate a request. Unwrapped
handlers receive no identity; built-in token verification, CSRF, anonymous-client
policy, rate limiting and authorization still need shared runtime integration.
Do not expose protected application handlers until those checks are supplied.

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
