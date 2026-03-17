# Security Hardening Plan

This document tracks the security posture and planned hardening work for generated
`very_simple_rest` APIs and the shared runtime.

## Current Baseline

- SQL request values are bound parameters, not interpolated.
- Schema-derived SQL identifiers are validated before code generation.
- Built-in auth requires an explicit JWT secret at runtime.
- Local Turso defaults to encrypted storage for bare SQLite `.eon` services.
- Generated servers emit security middleware for request limits, CORS, trusted proxies, and
  response headers from `security` settings.

## Implemented In This Pass

- Shared secret loading now supports `ENV_VAR` or `ENV_VAR_FILE` for mounted secrets.
  This currently covers `JWT_SECRET` / `JWT_SECRET_FILE` and
  `TURSO_ENCRYPTION_KEY` / `TURSO_ENCRYPTION_KEY_FILE`.
- Built-in auth supports optional browser-session cookies through
  `security.auth.session_cookie`.
- Session-cookie auth uses:
  - `HttpOnly` auth cookies
  - configurable `SameSite`
  - configurable `Secure`
  - CSRF protection for unsafe methods via a double-submit token
- Built-in auth now exposes `POST /auth/logout` to clear session cookies.
- The `examples/todo_app` browser client now uses same-origin cookie auth instead of storing
  bearer tokens in `localStorage`.

## Phase 1: Browser-Safe Defaults

Status: partially implemented

- Done:
  - optional session-cookie auth
  - CSRF enforcement for unsafe cookie-authenticated requests
  - logout route for session-cookie mode
  - secret-file support for mounted runtime secrets
- Next:
  - add generated-server presets for browser-first apps so emitted `.eon` servers can opt into
    session cookies intentionally instead of wiring it manually
  - surface cookie/session settings in generated docs and OpenAPI more explicitly
  - add cookie-auth coverage for generated server build smoke tests

## Phase 2: Secret Management

Status: planned

- Add a `SecretProvider` abstraction with providers for:
  - environment variables
  - mounted secret files
  - command/exec providers for secret fetch wrappers
  - cloud secret backends behind feature flags
- Add key rotation support for JWT signing:
  - active signing key plus verification key set
  - `kid` headers for asymmetric or rolling symmetric keys
- Extend secret-provider support to:
  - OAuth/OIDC client secrets
  - webhook secrets
  - SMTP / outbound integration secrets

## Phase 3: Modern Auth Flows

Status: planned

- Add OIDC Authorization Code + PKCE integration for browser and native clients.
- Add a backend-for-frontend mode for generated browser apps so browsers never need direct bearer
  token handling.
- Add provider-agnostic OAuth configuration with strict issuer and audience validation.
- Add optional refresh token rotation and reuse detection where long-lived sessions are needed.

## Phase 4: Stronger Account Security

Status: planned

- Migrate password hashing from bcrypt-only to Argon2id for new passwords.
- Rehash legacy bcrypt passwords on successful login.
- Add step-up auth hooks for privileged operations.
- Add passkey / WebAuthn support, at least for admin accounts first.

## Phase 5: API Surface Hardening

Status: planned

- Add stricter generated defaults for:
  - CSP on browser-facing pages
  - HSTS presets for TLS deployments
  - Permissions-Policy / COOP / CORP where appropriate
- Add explicit origin validation guidance for browser-facing deployments.
- Expand audit logging around auth events:
  - login success / failure
  - admin bootstrap
  - logout
  - CSRF failures

## Phase 6: Operational Security

Status: planned

- Add dependency and supply-chain checks to CI.
- Add release artifacts with provenance and SBOM generation.
- Document key rotation, secret rotation, and incident-response runbooks.

## Design Constraints

- Browser-friendly defaults must not silently weaken API-client use cases.
- New auth modes should remain opt-in unless the generated artifact clearly targets a browser app.
- Secret handling must fail closed on missing or malformed secrets.
- Generated code and emitted OpenAPI should stay aligned with runtime behavior.
