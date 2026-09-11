# Shared Session Presentation Migration Proof

Date: 2026-09-11. The preceding admin-management/provisioning changes were committed
on local `v1` as `499e61857916e082c88ef03654ed79fdad741b72` before this continuation.
No push was requested or performed. This session milestone remains uncommitted.
Main and its unrelated Bridgeboard reports are preserved.

## Implementation

- `vsr-runtime::auth::session::SessionPresentation` owns successful login response
  presentation, cookie issuance/deletion and logout CSRF policy behind `auth-builtin`.
- `SessionCookiePolicy` validates trusted names, path, header and security attributes.
  Existing EON validation retains specific diagnostics and additionally uses this
  shared policy. The facade's `builtin_session_presentation` maps existing settings.
- Native Actix login/logout delegate to the shared policy without changing public
  handler signatures. Login validates configuration before invoking account login.
  Private Actix cookie builders and obsolete random/CSRF wrappers were removed.
- The existing Cookie parser and duplicate checks are reused by logout; no parallel
  parser was added. Repeated `Set-Cookie` fields are appended, never comma-joined.
- Tokens and CSRF material are not stored in the presentation object. Entropy comes
  from the OS through a fallible call; deterministic failure tests use a private hook.

## Compatibility And Hardening

Successful login remains 200 with token JSON. Cookie mode also includes `csrf_token`
and two separate cookies. Existing names, configured path/Secure/SameSite, HttpOnly
session and readable CSRF flags are retained. Logout remains empty 204 with matching
empty cookies and Max-Age=0. No Domain attribute is emitted. Bearer-only mode has no
cookies. Both successful endpoints now include `Cache-Control: no-store`.

New CSRF values are opaque 64-character hex encodings of 256 random bits, replacing
the previous 32-character alphanumeric values. Positive login TTL and safe token
representation are required. Each complete serialized cookie is limited to 4096
bytes by application policy; failed generation/serialization does not return a
partially populated response to the caller.

Configuration validation rejects duplicate/unsafe/percent-escaped names, invalid
CSRF header names and credential-header collisions, unsafe paths, SameSite=None
without Secure, and insecure `__Host-`/`__Secure-` prefix combinations. This is a
stricter supported configuration surface, not automatic rewriting of bad settings.

Logout with any session cookie, including empty or expired tokens, requires a
unique matching CSRF cookie/header. Bearer credentials do not bypass this check.
Malformed cookies and duplicate/encoded-alias session cookies now fail closed
with 403 and no clearing cookies. Absence of a session cookie remains idempotent;
cookie-disabled logout ignores cookie input. Logout deliberately does not verify
JWT expiry, allowing expired browser credentials to be removed.

Logout is not token revocation: a copied bearer JWT still works until expiry or
an account-state change. No refresh tokens, session database, denylist, signed
double-submit redesign, or login-CSRF/abuse-policy changes are claimed here.

## Local Verification

Commands use stable Rust, `--locked`, disabled debug information and
`CARGO_INCREMENTAL=0`.

| Check | Result |
| --- | --- |
| Runtime auth library without HTTP features | 65 passed, including 5 new session tests |
| Real HTTP session tests | 2 passed across native Actix/shared Actix/Axum and invalid direct configuration |
| EON and runtime configuration parity (`sqlite,codegen`) | 1 passed |
| Full workspace regression | 778 passed, 0 failed, 16 ignored across 71 suites |
| Workspace Clippy, all features and targets | Passed with workspace/test-style warnings; none in the new production session modules |
| Contract-only build and framework isolation | Passed; no Actix/Axum normal dependencies with only `auth-builtin` |
| Scoped rustfmt, mdBook and whitespace checks | Passed |

After the full workspace run, the final Clippy review replaced a static-header
`expect` with error propagation. All 65 runtime auth tests and both session HTTP
tests passed again after that change. All eleven built-in auth HTTP tests passed
in the full workspace run. Existing ignored tests remain excluded; this does not
establish external database or production readiness.

Runtime tests cover all supported SameSite/Secure combinations, scoped deletion,
HttpOnly attributes, repeated fields, entropy failure, token/TTL/size rejection,
unique CSRF generation, malformed/duplicate/encoded cookie names, duplicate CSRF
headers, Bearer precedence for logout and cookie-disabled behavior. An initial
test assumed the envelope kept a JSON value; it now decodes the actual serialized
byte body, matching the existing response contract.

HTTP tests use real database-backed login and the existing authentication wrappers,
custom cookie/header names, all three server paths and cross-transport consumption.
They verify failed login emits no cookies, CSRF failures never clear cookies,
expired-token clearing, stateless logout and account-change revocation. The neutral
mounting/extraction functions are still test adapters, not a production route installer.
These raw HTTP checks do not prove browser cookie-jar or SameSite/Secure enforcement.

Logs use `/private/tmp/vsr-session-` with `runtime.log`, `http.log`, `config.log`,
`workspace.log`, `clippy.log`, `contract.log`, `dependencies.txt` and `docs.log`.

## Remaining Gates

Production request extraction, rate-limit composition, row-policy integration,
streaming and native/generated Axum bootstrap remain incomplete. Actix remains
the default; the SQL/key/configuration facade still links it. Existing CI already
runs the auth and real HTTP suites across platforms; an EON session-validation
step was added. No remote CI, external database, browser or production-load run
has been performed for this unpushed milestone.
