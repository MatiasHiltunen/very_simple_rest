# Built-in Request Authentication: Migration Proof

Date: 2026-09-08. Local platform: macOS, stable Rust.

## Publication And Scope

The reviewed baseline was fast-forwarded from `origin/v1` at `7bd9fa0e2` to
`f4421989d` and pushed to `origin/v1`. That includes the dependency/security
hardening, HTTP backend plan, Actix/Axum transports and EON enterprise example.
Local and remote SHA equality was verified. The main checkout was not changed.

The subsequent request-auth extraction is a separate working-tree milestone on
`v1`. It moves real native/generated behavior, not only a demonstration:

- Built-in claims and byte-compatible account-state fingerprints are runtime-owned.
- Credential selection, CSRF and live-state enforcement are framework-neutral.
- Native/generated `UserContext` delegates to the shared request policy.
- All legacy password helpers delegate to the runtime's bounded blocking pool.
- Neutral handlers can use the same policy through `require_authentication` and
  the temporary `rest_macro_core::auth::builtin_request_authenticator` bridge.

## Executed Checks

Commands used `RUSTUP_TOOLCHAIN=stable`, `CARGO_PROFILE_DEV_DEBUG=0` and
`CARGO_PROFILE_TEST_DEBUG=0` where applicable.

| Check | Local result |
| --- | --- |
| `cargo +stable test --workspace --all-features --no-fail-fast --locked` | 692 passed, 0 failed, 16 ignored |
| Final core/runtime library, built-in HTTP and transport conformance rerun | 329 passed, 0 failed, 1 ignored |
| `cargo +stable test -p vsr-runtime --no-default-features --features auth-builtin` | 14 unit tests and 1 doctest passed |
| `cargo +stable test -p rest_macro_core --no-default-features --features sqlite --test builtin_auth_runtime` | Real HTTP comparison passed |
| `cargo +stable check -p vsr-runtime --no-default-features --locked` | Passed |
| Authentication-only normal dependency graph | No Actix or Axum |
| Enterprise Axum-only normal dependency graph | No Actix or legacy runtime facade |
| Runtime Clippy, all features/targets | Completed; existing and test/style warnings remain |
| Workflow YAML, scoped formatting, mdBook, `git diff --check` | Passed |

The workspace run includes native spawned-server and generated-client tests.
The 16 ignored tests remain unverified, not passing. CI jobs were added for the
new auth boundary on Linux, macOS and Windows; no remote CI result is claimed.

## Security And Compatibility Evidence

The new HTTP test starts the existing built-in Actix login/account endpoints plus
protected handlers on both adapters, using a real temporary SQLite account table
and signed login-issued tokens. All three paths agree on public identity JSON,
anonymous/invalid credentials, duplicate headers/cookies, cookie CSRF, configured
issuer/audience/expiry, missing state, nonpositive subjects and wrong signatures.

Role demotion/restoration, changed tenant claims, the real password-change
endpoint and account deletion revoke old tokens on all three paths. Dropping the
account table fails closed with a generic 500. Unit tests separately verify the
legacy fingerprint bytes, explicit external-token compatibility, every-request
state reads and retention of the password-worker permit after cancellation.

The migration deliberately rejects ambiguous Authorization and CSRF inputs and
does not fall back to cookies after a present invalid Authorization header.
401 request-auth responses now include a Bearer challenge. Valid token formats,
identity JSON, configured keys and account-state fingerprints remain compatible.

## Remaining Work

Key loading/issuance, account endpoint handlers and the SQL repository still live
in the facade. The bridge therefore still links Actix; the runtime authentication
policy itself does not. Shared row authorization, full account lifecycle,
streaming and native/generated backend selection remain Phase 3 work. The EON
enterprise example retains its distinct stricter authentication profile.

This milestone does not prove external database parity, cross-platform runtime
behavior, production capacity, external IdP integration or dependency-advisory
resolution. The full `AuthProvider` trait is still a target, not an implemented
account lifecycle service.
