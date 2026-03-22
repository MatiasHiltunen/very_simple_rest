# Production Grade TODO

This checklist tracks the remaining work needed before `very_simple_rest` should be treated as
production-grade for public multi-tenant deployments.

For a phased roadmap and a concrete compression MVP design, see `IMPROVEMENT_PLAN.md`.

## Security

- [ ] Add distributed rate limiting support.
  Current built-in auth limiting is process-local memory only. Add a pluggable shared store
  option for multi-instance deployments.
- [ ] Add security config for CORS allowlist reload strategy.
  Support predictable env-driven reload/restart expectations and document them clearly.
- [ ] Add configurable password policy for built-in auth.
  Minimum length, breach/weak-password hooks, and optional complexity rules.
- [ ] Add login/register abuse defenses beyond simple request limits.
  Consider per-account throttling, temporary lockouts, and audit logging for repeated failures.
- [ ] Add explicit JWT key rotation support.
  Support key ids, multiple active verification keys, and migration from symmetric secret-only
  mode.
- [ ] Add configurable cookie/session auth mode or explicitly document bearer-token-only posture.
- [ ] Add security headers for CSP and Permissions-Policy.
  These need careful SPA/static asset compatibility rules rather than permissive defaults.

## Auth And Identity

- [ ] Add first-class account-management endpoints.
  Password change, profile update, token introspection/session metadata, and claim inspection.
- [ ] Add configurable claim mapping beyond numeric DB columns.
  Support string/bool claims and explicit column-to-claim mappings.
- [ ] Add email-verification and password-reset extension points for built-in auth.
- [ ] Add optional registration disable/invite-only modes in `.eon` security config.

## Policies And Data Protection

- [ ] Add richer portable row-policy operators.
  Support nullable checks, multi-field conjunctions/disjunctions, and safer tenant/admin
  combinations without raw SQL.
- [ ] Add optional Postgres-native RLS generation.
  Generate `CREATE POLICY` SQL and per-request session setup on top of the existing app-layer
  policy engine.
- [ ] Add policy-aware data export/audit hooks for sensitive resources.

## Schema And Migrations

- [ ] Extend migration diffing beyond additive changes.
  At minimum, detect unsupported changes with precise remediation guidance for relations, indexes,
  constraints, and policy-affecting columns.
- [ ] Add live drift inspection coverage for Postgres and MySQL.
  Current runtime confidence is still SQLite-heavy.
- [ ] Add explicit schema constraints for validations where possible.
  Mirror application-level validation into database constraints when safe.
- [ ] Add rollback/down-migration guidance or generated stubs.

## API Contract

- [ ] Add documented stable error schemas for every built-in auth and generated route in OpenAPI.
  The runtime is close, but the spec should be complete and explicit.
- [ ] Add request validation features beyond min/max and numeric bounds.
  Email, UUID, regex/pattern, enum constraints, and custom validators.
- [ ] Add cursor pagination docs/examples for multi-column stable sorts and known limitations.
- [ ] Add versioning strategy for generated APIs and emitted server projects.

## Server Runtime

- [ ] Add request timeout and body/read timeout configuration in `.eon`.
- [ ] Add connection pool sizing/timeouts and startup validation guidance in emitted servers.
- [ ] Add graceful shutdown and readiness/liveness helpers for emitted servers.
- [ ] Add structured request logging and tracing configuration in `.eon`.
- [ ] Add metrics endpoint/instrumentation hooks.

## Static And Frontend Serving

- [ ] Add embedded asset mode for `vsr server build`.
  Current static serving is filesystem-based only.
- [ ] Add cache-safe SPA deployment guidance for generated static bundles.
- [ ] Add stronger CSP integration for emitted static/SPA servers.

## Testing And Release Quality

- [ ] Add runtime integration coverage for Postgres and MySQL.
- [ ] Add emitted-server smoke tests that exercise the generated binary with security config.
- [ ] Add property/fuzz coverage for `.eon` parsing and generated list/query handling.
- [ ] Add compatibility tests for OpenAPI output stability.
- [ ] Add release CI matrix for supported databases and server emit/build workflows.

## Operations And Documentation

- [ ] Add deployment guides for single-node SQLite and multi-node Postgres setups.
- [ ] Add production example apps with migrations, auth, security config, and static assets.
- [ ] Add explicit support policy and semver guarantees for macros, `.eon`, CLI, and generated API
  contracts.
- [ ] Add upgrade notes template for schema/codegen breaking changes.

## Recommended Order

1. Distributed rate limiting and JWT key rotation.
2. Postgres/MySQL runtime coverage and drift inspection hardening.
3. Timeouts, tracing, metrics, and readiness/liveness support.
4. Richer validation + schema constraints.
5. Account-management flows and native Postgres RLS option.
