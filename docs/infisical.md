# Infisical Integration

`very_simple_rest` does not yet fetch secrets directly from Infisical at runtime. The recommended
pattern is:

1. Use Infisical Agent to render secret files.
2. Point the VSR runtime at those files with `*_FILE` bindings.

This fits the current runtime directly because VSR already supports:

- `JWT_SECRET_FILE`
- `DATABASE_URL_FILE`
- `TURSO_ENCRYPTION_KEY_FILE`
- provider-specific mail `*_FILE` bindings

## Generate Scaffold

Generate Infisical scaffolding from a `.eon` service:

```bash
vsr secrets infisical scaffold --input api.eon --project my-project --environment prod
```

If your Infisical auth path is machine-identity based and you already know the project UUID,
prefer passing it too:

```bash
vsr secrets infisical scaffold \
  --input api.eon \
  --project my-project \
  --project-id 2435f6d5-14d0-4429-b1e6-172b497f2c17 \
  --environment prod
```

This writes:

- `infisical-agent.yaml`
- `runtime.env`
- `expected-secrets.env`
- `templates/*.tpl`
- `auth/README.md`

By default the scaffold is written to `deploy/infisical` next to the selected `.eon` file.

Validate the runtime bindings and scaffold afterwards:

```bash
vsr doctor secrets --input api.eon --infisical-dir deploy/infisical
```

## What The Files Do

### `expected-secrets.env`

Import-ready list of the secret keys that should exist in Infisical for the service.

### `templates/*.tpl`

One template per secret key. Infisical Agent uses these templates to render the actual secret
files. When `--project-id` is provided, VSR generates single-secret templates using the project
UUID, which is the more robust path for machine-identity agent setups.

### `infisical-agent.yaml`

Agent configuration with:

- chosen auth method skeleton
- one template entry per VSR secret binding
- destination paths under `/run/secrets/vsr` by default

### `runtime.env`

Static `*_FILE` bindings for the VSR runtime and CLI. Example:

```dotenv
DATABASE_URL_FILE=/run/secrets/vsr/DATABASE_URL
JWT_SECRET_FILE=/run/secrets/vsr/JWT_SECRET
```

Load this into systemd, Docker, Kubernetes, or another deployment environment.

## Recommended Usage

### Local development

For quick local work, direct env injection is still fine:

```bash
infisical run -- vsr serve api.eon
```

### Production

Prefer Infisical Agent plus rendered files:

1. Create/import the secrets in Infisical.
2. Provision the auth files described in `auth/README.md`.
3. Start the agent from the scaffold directory.
4. Load `runtime.env` into the app environment.
5. Run `vsr setup --production` or the built server with those `*_FILE` bindings.
6. Run `vsr doctor secrets --input api.eon --infisical-dir deploy/infisical` before promotion.

## Current Boundary

This is scaffolding, not native provider integration. The app still reads environment variables
and mounted files, not Infisical APIs directly.
