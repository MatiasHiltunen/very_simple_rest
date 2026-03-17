# REST API CLI Tool

A command-line interface for managing `very_simple_rest` API deployments.

## Overview

This CLI tool simplifies the setup and management of `very_simple_rest` API applications, with a focus on secure user management and configuration.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/MatiasHiltunen/very_simple_rest.git
cd very_simple_rest

# Build the CLI tool
cargo build --release -p rest_api_cli

# Run the CLI
./target/release/vsr --help
```

### Cargo Install

```bash
cargo install --path crates/rest_api_cli
```

## Commands

### Init

Scaffold a starter project from the bundled template:

```bash
vsr init my-api
```

The starter template now uses local Turso by default and wires in the shared runtime security
helpers for request limits, CORS, trusted proxies, auth rate limits, and response headers.

### Setup

Initialize a new API deployment with interactive prompts:

```bash
vsr setup
```

This command will:
1. Check your database connection
2. Create necessary tables if they don't exist
3. Help you create an admin user
4. Generate a `.env` template file

For non-interactive setup (e.g., in CI/CD pipelines):

```bash
vsr setup --non-interactive
```

If you run `vsr` from a directory containing exactly one `.eon` service, the CLI auto-discovers
it for `setup`, `create-admin`, `check-db`, and `gen-env`. You can still pass `--config`
explicitly when you want a non-default file:

```bash
vsr setup
vsr create-admin --email admin@example.com --password change-me
vsr check-db

vsr --config api.eon setup
vsr --config api.eon create-admin --email admin@example.com --password change-me
vsr --config api.eon check-db
```

When `--config` points to a `.eon` service and `--database-url` / `DATABASE_URL` are both absent,
the CLI uses the service’s compiled default database URL. For SQLite services, that now defaults
to encrypted `database.engine = TursoLocal`, which resolves to the matching SQLite-compatible file
URL and the default `TURSO_ENCRYPTION_KEY` env var.

### Env Generation

Generate a `.env` file directly:

```bash
vsr gen-env
vsr --config api.eon gen-env --path .env.local
```

When `--config` points to a `.eon` service, the generated file mirrors the compiled default
database URL plus the required/default Turso and security env vars such as
`TURSO_ENCRYPTION_KEY`, `CORS_ORIGINS`, `TRUSTED_PROXIES`, and the configured logging filter env
var when those are referenced by the service.

### Server Generation

Generate a runnable Rust server project from a bare `.eon` service:

```bash
vsr server emit --input api.eon --output-dir generated-api
```

This emits:

- `Cargo.toml`
- `src/main.rs`
- the copied `.eon` file
- `.env.example`
- `openapi.json`
- `migrations/0000_auth.sql` with built-in auth enabled by default
- `migrations/0001_service.sql`

You can also build a server binary directly:

```bash
vsr build api.eon --release
```

Useful options:

- `--without-auth` excludes the built-in auth/account routes and omits `migrations/0000_auth.sql`
- `--package-name` overrides the generated Cargo package name
- `--build-dir` keeps the temporary Cargo project in a known location
- `--keep-build-dir` preserves the generated build project after compilation
- `--output dist` writes the binary into an existing directory; otherwise it defaults to the
  current directory and names the binary after the `.eon` file stem

Built-in auth is enabled by default. If the `.eon` service already defines a `user` table, re-run
with `--without-auth` because the built-in auth migration owns that table name.

`vsr build` also exports the generated runtime artifacts next to the binary in
`<binary>.bundle/`, including `.env.example`, `openapi.json`, the copied `.eon` file, `README.md`,
and `migrations/`.

The generated server fails fast if built-in auth is enabled and `JWT_SECRET` is missing. `vsr
gen-env` and emitted `.env.example` files still help by generating or surfacing the required env
vars, but runtime auth is no longer allowed to fall back to a random secret.

Generated server projects serve the OpenAPI document at `/openapi.json` and Swagger UI at `/docs`.
When a `.eon` service defines static mounts, `vsr server emit` also copies those directories into
the generated project and wires the generated server to serve them. When a `.eon` service defines
`security`, the emitted server also applies the compiled JSON body limit, CORS policy,
trusted-proxy handling, auth rate limits, security headers, and built-in auth token settings
automatically. When a `.eon` service defines `database.engine`, the emitted server also carries
that runtime engine config into the project, including encrypted local Turso bootstrap by default
for bare SQLite `.eon` services. When a `.eon` service defines `logging`, the emitted server also
uses the compiled log env var, default filter, and timestamp precision instead of hard-coded
logger defaults.

### OpenAPI Generation

Render an OpenAPI document from either a `.eon` service or derive-based Rust resources:

```bash
vsr openapi --input api.eon --output openapi.json
vsr openapi --input src --exclude-table user --output openapi.json
vsr openapi --input api.eon --without-auth --output openapi-no-auth.json
```

Useful options:

- `--title` overrides the document title
- `--version` overrides the OpenAPI version string in `info.version`
- `--server-url` changes the generated server URL, which defaults to `/api`
- built-in `/auth/register`, `/auth/login`, and `/auth/me` routes are included by default, with
  `/auth/me` grouped under `Account` in Swagger
- `--without-auth` removes those built-in auth/account routes from the document
- `--exclude-table` removes specific tables from the document

### Static Files In `.eon`

Bare `.eon` services can define service-level static mounts:

```eon
static: {
    mounts: [
        {
            mount: "/assets"
            dir: "public/assets"
            mode: Directory
            cache: Immutable
        }
        {
            mount: "/"
            dir: "public"
            mode: Spa
            index_file: "index.html"
            fallback_file: "index.html"
            cache: NoStore
        }
    ]
}
```

Supported options:

- `mount`: URL prefix such as `/assets` or `/`
- `dir`: directory relative to the `.eon` file
- `mode`: `Directory` or `Spa`
- `index_file`: optional directory index file
- `fallback_file`: SPA fallback file
- `cache`: `NoStore`, `Revalidate`, or `Immutable`

The loader rejects mounts that escape the `.eon` root or conflict with reserved routes such as
`/api`, `/auth`, `/docs`, and `/openapi.json`.

### Database Engine In `.eon`

Bare `.eon` services can also define a service-level database engine. For SQLite services, the
default when this block is omitted is:

```eon
database: {
    engine: {
        kind: TursoLocal
        path: "var/data/<module>.db"
        encryption_key_env: "TURSO_ENCRYPTION_KEY"
    }
}
```

You can still override it explicitly:

```eon
database: {
    engine: {
        kind: TursoLocal
        path: "var/data/app.db"
        encryption_key_env: "TURSO_ENCRYPTION_KEY"
    }
}
```

Current support:

- `Sqlx`: the legacy runtime path; use this explicitly if you want plain SQLx SQLite for a
  SQLite `.eon` service
- `TursoLocal`: bootstraps a local Turso database file and uses the project runtime database
  adapter with SQLite-compatible SQL
- `TursoLocal.encryption_key_env`: reads a hex key from the named environment variable and uses
  Turso local encryption with the current default cipher (`aegis256`) during bootstrap

Current limitation:

- This is still a project-local runtime adapter, not a true upstream SQLx `Any` driver.

### Security In `.eon`

Bare `.eon` services can also define service-level security defaults:

```eon
security: {
    requests: { json_max_bytes: 1048576 }
    cors: {
        origins: ["http://localhost:3000"]
        origins_env: "CORS_ORIGINS"
        allow_credentials: true
        allow_methods: ["GET", "POST", "OPTIONS"]
        allow_headers: ["authorization", "content-type"]
    }
    trusted_proxies: {
        proxies: ["127.0.0.1", "::1"]
        proxies_env: "TRUSTED_PROXIES"
    }
    rate_limits: {
        login: { requests: 10, window_seconds: 60 }
        register: { requests: 5, window_seconds: 300 }
    }
    headers: {
        frame_options: Deny
        content_type_options: true
        referrer_policy: StrictOriginWhenCrossOrigin
    }
    auth: {
        issuer: "very_simple_rest"
        audience: "public-api"
        access_token_ttl_seconds: 3600
    }
}
```

This config currently controls:

- JSON body size limits for generated resource and built-in auth routes
- CORS origins, headers, methods, credentials, and preflight caching on the emitted server
- trusted-proxy IP handling for forwarded client addresses
- in-memory built-in auth login and registration rate limits
- security response headers on the emitted server
- built-in auth JWT `iss`, `aud`, and token TTL defaults

Secrets such as `JWT_SECRET` remain environment-driven. The current auth rate limiter is
process-local rather than distributed.

### Create Admin

Create a new admin user:

```bash
# Interactive mode with prompts
vsr create-admin

# Non-interactive mode with parameters
vsr create-admin --email admin@example.com --password secure_password
```

If the built-in auth `user` table has extra numeric claim columns such as `tenant_id`,
`org_id`, or `claim_workspace_id`, the CLI detects them automatically. Interactive admin creation
prompts for those values, and non-interactive flows accept environment variables named
`ADMIN_<COLUMN_NAME>`, for example `ADMIN_TENANT_ID=1`.

### Check Database

Verify database connection and schema:

```bash
vsr check-db
```

This will:
- Test the database connection
- Check if required tables exist
- Count existing users and admins
- Provide recommendations based on findings

### Generate .env Template

Create a template `.env` file with common configuration options:

```bash
vsr gen-env
```

## Environment Variables

The CLI tool respects the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | Derived from `--config` or a single local `.eon`; otherwise `sqlite:var/data/app.db?mode=rwc` |
| `ADMIN_EMAIL` | Default admin email address | None |
| `ADMIN_PASSWORD` | Default admin password | None |
| `ADMIN_<COLUMN_NAME>` | Optional built-in auth claim column value, for example `ADMIN_TENANT_ID` | None |
| `JWT_SECRET` | Secret key for JWT tokens | Required for built-in auth at runtime |

## Examples

### Complete Setup Example

```bash
# Set database URL
export DATABASE_URL="sqlite:var/data/my_app.db?mode=rwc"
export JWT_SECRET="replace-me"

# Initialize the application
vsr setup

# Check database status
vsr check-db
```

### `.eon`-Driven Local Turso Example

```bash
# Use the compiled database settings from a bare .eon service explicitly
vsr --config tests/fixtures/turso_local_api.eon check-db
vsr --config tests/fixtures/turso_local_api.eon migrate apply --dir migrations
```

### Creating Admin in CI/CD Pipeline

```bash
# Set required variables
export DATABASE_URL="sqlite:var/data/app.db?mode=rwc"
export ADMIN_EMAIL="admin@example.com"
export ADMIN_PASSWORD="secure_random_password"
export ADMIN_TENANT_ID="1"
export JWT_SECRET="replace-me"

# Create admin non-interactively
vsr create-admin --email $ADMIN_EMAIL --password $ADMIN_PASSWORD
```

## Security Best Practices

- Never store admin credentials in version control
- Use environment variables or a secure secret management system
- Change default admin passwords immediately in production
- Use strong, unique passwords
- Consider setting up a dedicated admin user for each team member

## Troubleshooting

### Common Issues

**Database Connection Errors**
- Verify the database URL format
- Ensure the database server is running
- Check file permissions for SQLite databases

**Admin Creation Fails**
- Ensure both email and password are provided
- Verify the database is accessible and writable
- Check if an admin with the same email already exists

## Related Documentation

- [Main Project README](../../README.md)
- [API Documentation](../../docs/api.md)
- [Environment Configuration](../../docs/configuration.md) 
