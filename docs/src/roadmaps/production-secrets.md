# Production Secrets Roadmap

This document defines the production direction for secrets and other sensitive runtime inputs in
`very_simple_rest`.

## Goals

- Keep local development simple.
- Make production deployments fail fast when required secrets are unresolved.
- Prefer identity-backed or mounted-file secret delivery over inline environment values.
- Keep secret handling consistent across built-in auth, database, email, backups, TLS, and future
  integrations.

## Current Baseline

Today the runtime already supports `<VAR>` and `<VAR>_FILE` loading for secret values through the
shared loader in `rest_macro_core::secret`.

Phase 1 now adds:

- `vsr setup --production`
- `vsr gen-env --production`
- `vsr doctor secrets`
- production-safe `.env` templates that do not write live secrets
- fail-fast validation for required production secrets before setup continues
- `DATABASE_URL_FILE` support in the CLI path resolution

This means production deployments can already prefer mounted secret files while local development
can keep using `.env`.

For Infisical specifically, `vsr secrets infisical scaffold` now generates Infisical Agent
templates plus a VSR-compatible `runtime.env` file. See `docs/infisical.md`.

## Secret Source Priority

The intended production order is:

1. Workload identity / managed identity / IAM role
2. Runtime retrieval from a secret manager
3. Mounted secret files or OS/orchestrator credential facilities
4. Inline environment variables only as compatibility fallback

For current releases, mounted secret files are the preferred production mechanism because they are
available today across the runtime and CLI.

## What Belongs Where

Static configuration in `.eon` should declare:

- which secrets exist
- what subsystem consumes them
- whether the value is required

Runtime secret storage should provide:

- the actual JWT signing secret
- database passwords or tokens
- SMTP / Resend credentials
- Turso local encryption keys
- backup encryption material
- S3 access credentials

Plain `.env` files should be treated as development-only convenience, not as the production system
of record.

## Recommended Deployment Patterns

### systemd

- Use `LoadCredential=` / `LoadCredentialEncrypted=`
- Point runtime vars such as `JWT_SECRET_FILE` to `/run/credentials/...`

### Docker / Compose / Swarm

- Mount secrets into `/run/secrets/...`
- Set `*_FILE` variables instead of putting secret values directly in the container environment

### Kubernetes

- Prefer Secret volumes, CSI drivers, or external secret sync
- Point `*_FILE` variables at mounted paths
- Avoid long-lived inline secret env values for high-value secrets

### Cloud-managed platforms

- Prefer workload identity plus the provider’s secret manager
- Use file/env compatibility only when direct runtime retrieval is not available yet

## Phased Plan

### Phase 1

- Production-safe setup and env generation
- Shared secret-source helpers
- `DATABASE_URL_FILE` support

### Phase 2

- Introduce typed `SecretRef` support in `.eon`
- Normalize secret handling across JWT, database, email, backups, TLS, and storage
- Add `vsr doctor secrets`

### Phase 3

- Asymmetric JWT signing with key rotation and `kid`
- Structured database connection config with secret references for passwords/tokens
- Secret rotation helpers and audit-friendly diagnostics

### Phase 4

- Native secret-manager providers
- Managed-identity-first deployment templates
- Key-management-service backed signing

## Safety Rules

- Production setup must never generate live secrets into `.env`.
- Production deployments must fail fast if required secrets are missing.
- Bootstrap credentials should be one-shot and not remain in steady-state runtime configuration.
- Permissions and scoped grants belong in authz tables, not in the built-in auth `user` row.
- Secret rotation and backup verification should become part of deployment readiness checks.

## Current Recommendation

For production today:

1. Use `vsr gen-env --production` or `vsr setup --production`.
2. Resolve `JWT_SECRET`, database credentials, Turso keys, and mail credentials via mounted
   `*_FILE` bindings.
3. Keep `.env` for local development only.
4. Treat inline env secrets as a fallback, not the preferred deployment model.
