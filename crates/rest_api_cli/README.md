# vsr CLI

A command-line interface for managing `very_simple_rest` API deployments.

## Overview

`vsr` is the main entry point for `.eon`-driven VSR services. It can scaffold a project, serve a
service directly at runtime, emit a Rust server project, build a standalone binary, generate
OpenAPI and `.eon` reference docs, and manage setup/auth flows.

The published crate is `vsra`; the installed binary is `vsr`.

## Quick Start

```bash
cargo install vsra --locked

vsr init my-api
vsr init my-api --starter minimal
vsr serve api.eon
vsr server expand --input api.eon --output api.expanded.rs
vsr server emit --input api.eon --output-dir generated-api
vsr build api.eon --release
vsr client ts --input api.eon --output web/src/gen/client
vsr openapi --input api.eon --output openapi.json
vsr docs --output docs/eon-reference.md
```

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/MatiasHiltunen/very_simple_rest.git
cd very_simple_rest

# Build the CLI tool
cargo build --release

# Run the CLI
./target/release/vsr --help
```

The workspace default member is the CLI package, so `cargo build` and `cargo run` from the
repository root target `vsr`. Use `cargo build --workspace` when you want the full workspace, or
`cargo build -p very_simple_rest` for the library package.

### Cargo Install

```bash
cargo install vsra --locked
```

For an unpublished local checkout:

```bash
cargo install --path crates/rest_api_cli
```

## Commands

### Init

Generate a local starter project:

```bash
vsr init my-api
vsr init my-api --starter minimal
```

By default, `vsr init` prompts in a terminal and falls back to the recommended comment-rich
starter in non-interactive use. The generated project is local-only and does not copy app code
from `examples/` or fetch from GitHub.

The generated project includes:

- `api.eon`
- `.env.example`
- `README.md`
- `.gitignore`
- `migrations/`
- `var/data/`

The default commented starter uses local Turso/SQLite defaults and includes commented examples for
current `.eon` features such as typed `Object` / `List` / JSON fields, API projections and
contexts, enums, indexes, many-to-many join resources, transforms, and declarative actions.

### Setup

Initialize a new API deployment with interactive prompts:

```bash
vsr setup
vsr setup --production
```

This command will:
1. Generate or load `.env` before any database work when a `.eon` service is in use
2. Generate local self-signed TLS certs when the service enables `tls` and dev cert files are missing
3. Check your database connection and apply setup migrations
4. Help you create or verify an admin user

When `setup` generates or refreshes `.env`, it writes the file next to the selected `.eon`
service, loads it into the current setup process immediately, and prints a summary with the exact
paths it touched. If it refreshes an existing file, the previous contents are backed up to
`.env.backup`.

`vsr setup --production` switches to production-safe behavior:

- it does not write live secrets into `.env`
- it does not generate self-signed dev TLS certs
- it refuses to continue when required production secrets are unresolved

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

In non-interactive mode, `setup` will bootstrap `.env` automatically when it is missing or when a
required local Turso encryption key is absent. If the service also enables `tls: {}` with the
default dev cert paths, `setup --non-interactive` generates those PEM files before the database
connection step so HTTPS can work immediately.

### Env Generation

Generate a `.env` file directly:

```bash
vsr gen-env
vsr gen-env --production
vsr --config api.eon gen-env --path .env.local
```

When `--config` points to a `.eon` service, the generated file mirrors the compiled default
database URL plus the required/default Turso and security env vars such as
`TURSO_ENCRYPTION_KEY`, `CORS_ORIGINS`, `TRUSTED_PROXIES`, and the configured logging filter env
var when those are referenced by the service. For `database.engine = TursoLocal`, `vsr gen-env`
now writes a real 64-hex-character local encryption key instead of a placeholder. By default, the
generated `.env` is written next to the `.eon` file when `--config` is used.

`vsr gen-env --production` keeps the same shape but comments out live secret values instead of
writing them. Use that mode for deployment templates and prefer mounted `*_FILE` bindings or a
secret manager for the real values.

### Infisical Scaffolding

Generate Infisical Agent/runtime scaffolding directly from a `.eon` service:

```bash
vsr secrets infisical scaffold --input api.eon --project my-project
vsr secrets infisical scaffold --input api.eon --project my-project --project-id <project-uuid>
vsr doctor secrets --input api.eon --infisical-dir deploy/infisical
```

The scaffold includes:

- `infisical-agent.yaml`
- `runtime.env`
- `expected-secrets.env`
- `templates/*.tpl`
- `auth/README.md`

This is designed around the existing VSR `*_FILE` support. Infisical Agent renders secret files,
and the generated `runtime.env` points VSR at those files. See
[../../docs/infisical.md](../../docs/infisical.md).

`vsr doctor secrets` validates:

- currently resolved `*_FILE` / inline bindings for the service
- service-required secret inputs such as the configured JWT signing key, mail credentials, and
  Turso keys
- optional Infisical scaffold completeness when `--infisical-dir` is provided

### Strict Service Checks

Run compiler-facing schema diagnostics:

```bash
vsr check --input api.eon
vsr check --input api.eon --strict --format json
```

The first strict slice reports high-confidence warnings for:

- TLS certificate/key paths that do not exist yet
- authorization contracts that do not affect generated runtime behavior
- declared authorization scopes that are not referenced anywhere else
- legacy `security.auth.jwt_secret` usage when the service could move to asymmetric JWT config
- asymmetric JWT setups that publish only a single verification key and therefore have no rotation
  overlap window
- auth email `public_base_url` values that still point at localhost/loopback hosts or use a
  non-HTTPS public origin
- built-in auth portal/admin UI paths that overlap generated `/api` namespaces or root-level
  static mounts
- row-policy, nested-route, `exists`, or hybrid scope lookup fields that rely on inferred indexes
  without an explicit `.eon` index declaration
- empty declared build-artifact env overrides, binary/bundle path collisions, and cache/output
  path overlaps that can make `vsr build` or `vsr clean` unsafe

`--strict` turns those warnings into a failing exit status so the command can be used in CI.

### Serve, Emit, and Build

Serve a bare `.eon` service directly through the native runtime:

```bash
vsr serve api.eon
vsr server serve --input api.eon
```

This is the fastest local development loop. The runtime serves the compiled API surface directly
from the `.eon` file, including `/openapi.json`, `/docs`, static mounts, built-in auth, runtime
authorization management routes, compiled database engine settings, and TLS when configured.

`vsr serve` also loads the `.env` next to the selected `.eon` service before startup, even when
you launch the command from another working directory. In an interactive terminal, it offers to
run local `setup` only when the selected service is missing development inputs that setup can
actually fix, such as a built-in auth signing secret, a local Turso encryption key, or the
default dev TLS certificate files.

Built-in auth is enabled by default. If the `.eon` service already defines a `user` table, re-run
with `--without-auth` because the built-in auth migration owns that table name:

```bash
vsr serve api.eon --without-auth
```

If you want a runnable Rust project you can inspect or modify, emit one instead:

```bash
vsr server emit --input api.eon --output-dir generated-api
```

If you want to inspect the full macro-expanded Rust module directly without creating a Cargo
project first, expand it to a single source file:

```bash
vsr server expand --input api.eon --output api.expanded.rs
```

When `--output` is omitted, `vsr server expand` writes `<input-stem>.expanded.rs` next to the
`.eon` file. `--output-dir generated-api` is also accepted as a compatibility alias and writes
`generated-api/<input-stem>.expanded.rs`.

This emits:

- `Cargo.toml`
- `src/main.rs`
- the copied `.eon` file
- `.env.example`
- `openapi.json`
- `migrations/0000_auth.sql` with built-in auth enabled by default
- `migrations/0001_service.sql`

If you want a standalone binary directly from the same contract, build it:

```bash
vsr build api.eon --release
```

Useful options:

- `--without-auth` excludes the built-in auth/account routes and omits `migrations/0000_auth.sql`
- `--package-name` overrides the generated Cargo package name
- `--build-dir` keeps the temporary Cargo project in a known location
- `--keep-build-dir` preserves the generated build project after compilation
- `--output dist` writes the binary into an existing directory; otherwise it defaults to the
  `.eon` service directory and names the binary after the `.eon` file stem

`vsr build` also exports the generated runtime artifacts next to the binary in
`<binary>.bundle/`, including `.env.example`, `openapi.json`, the copied `.eon` file, `README.md`,
`migrations/`, and relative TLS certificate files when they exist at build time. When
`runtime.compression.static_precompressed = true`, `vsr build` also generates `.br` and `.gz`
companion files for copied static assets inside that bundle.

`.eon` services can declare build artifact locations under `build.artifacts`. Each artifact path
resolves with this precedence: CLI override, then the declared env var override, then the literal
`.eon` path, then the service-relative default. No build-path env vars are read unless the `.eon`
file explicitly names them.

`vsr clean --input api.eon` removes the same resolved build cache that `vsr build api.eon` uses.
Without `--input` or `--build-dir`, `vsr clean` keeps the legacy `./.vsr-build` current-directory
fallback.

The generated server fails fast if built-in auth is enabled and the configured JWT signing
material is missing. `vsr gen-env` and emitted `.env.example` files still help by generating or
surfacing the required env vars, but runtime auth is no longer allowed to fall back to a random
secret.

Generated server projects serve the OpenAPI document at `/openapi.json` and Swagger UI at `/docs`.
When a `.eon` service defines static mounts, `vsr server emit` also copies those directories into
the generated project and wires the generated server to serve them. When a `.eon` service defines
`security`, the emitted server also applies the compiled JSON body limit, CORS policy,
trusted-proxy handling, auth rate limits, security headers, and built-in auth token settings
automatically. When a `.eon` service defines `database.engine`, the emitted server also carries
that runtime engine config into the project, including encrypted local Turso bootstrap by default
for bare SQLite `.eon` services. When a `.eon` service defines `logging`, the emitted server also
uses the compiled log env var, default filter, and timestamp precision instead of hard-coded
logger defaults. When a `.eon` service defines `tls`, the emitted server binds HTTPS with Rustls
and HTTP/2, defaults `BIND_ADDR` to `127.0.0.1:8443`, and can use `vsr tls self-signed` to
generate local certificate PEM files.

### TLS Certificate Generation

Generate a self-signed certificate and private key for local development:

```bash
vsr tls self-signed
vsr --config api.eon tls self-signed --force
vsr tls self-signed --cert-path certs/dev-cert.pem --key-path certs/dev-key.pem --host localhost --host 127.0.0.1
```

Behavior:

- with `--config api.eon`, the command uses the configured `.eon` `tls.cert_path` and
  `tls.key_path`
- with no config and no explicit output paths, it defaults to `certs/dev-cert.pem` and
  `certs/dev-key.pem` in the current directory
- default SANs are `localhost`, `127.0.0.1`, and `::1`
- private keys are written with restrictive permissions on Unix

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

### TypeScript Client Generation

Generate a fetch-based TypeScript client package from the same service contract:

```bash
vsr client ts --input api.eon
vsr client ts --input api.eon --output web/src/gen/client
vsr client ts --input api.eon --without-auth
vsr client ts --input api.eon --self-test
vsr client ts --input public_catalog_api.eon --without-auth --self-test --self-test-base-url http://127.0.0.1:8080
vsr client ts --input bridgeboard.eon --self-test --self-test-base-url https://127.0.0.1:8080 --self-test-insecure-tls
```

The current generator writes:

- `client.ts` with `createClient`, bearer-token support, CSRF header injection, multipart upload
  helpers, and `ApiError`
- `types.ts` from OpenAPI component schemas
- `operations.ts` with one typed function per OpenAPI operation
- `index.ts`, a minimal `package.json`, and a dependency-free `tsconfig.json`
- optional browser-ready `index.js`, `client.js`, and `operations.js` when `--emit-js` or
  `clients.ts.emit_js` is enabled

It works from either `.eon` services or derive-based Rust resources and follows the same OpenAPI
surface that `vsr openapi` publishes. That means endpoints that currently advertise empty success
responses are typed as `void`.

`.eon` services can also declare TypeScript client defaults and build automation under `clients.ts`.
Output paths and package names resolve with this precedence: CLI override, then the declared env
var override, then the literal `.eon` value, then the service-relative default. No
client-generation env vars are read unless the `.eon` file explicitly names them.

```eon
clients: {
    ts: {
        output_dir: {
            path: "web/src/gen/client"
            env: "CMS_TS_CLIENT_OUT"
        }
        package_name: "@cms/api-client"
        server_url: "/api"
        emit_js: true
        include_builtin_auth: true
        exclude_tables: ["audit_log"]
        automation: {
            on_build: true
            self_test: true
            self_test_report: {
                path: "reports/client-self-test.json"
            }
        }
    }
}
```

When `clients.ts.automation.on_build` is enabled, `vsr build` and `vsr server build` regenerate
the TypeScript client automatically after a successful server build. Automated client generation
always refreshes the configured client output directory, and automated self-test runs the same
dependency-free static checks as `vsr client ts --self-test`.

`--self-test` adds an optional automated validation pass for the generated client and writes a
JSON report. The self-test currently checks:

- dependency-free `package.json`
- relative-only module imports inside generated `.ts` and `.js` files
- `tsc -p <client-dir>` when a TypeScript compiler is available
- Node.js import smoke for the generated runtime
- safe anonymous `GET` operation probes through the generated client when
  `--self-test-base-url` is provided
- optional insecure TLS acceptance for those runtime probes when
  `--self-test-insecure-tls` is set

The report defaults to `<client-dir>/self-test-report.json`, or you can override it with
`--self-test-report`. If any self-test check fails, VSR still writes the report and then exits
nonzero so the command can be used directly in CI.

### `.eon` Reference Docs

Generate a Markdown reference for the currently supported `.eon` feature set:

```bash
vsr docs --output docs/eon-reference.md
```

The checked-in reference document lives at `docs/eon-reference.md`.

### Authorization Explain

Inspect how a `.eon` service compiles into the current internal authorization model:

```bash
vsr authz explain --input api.eon
vsr authz explain --input api.eon --format json --output docs/authz.json
```

When `--input` is omitted, `vsr` falls back to the same autodiscovered or explicit `--config`
path used by the other `.eon`-aware commands.

You can also simulate a single authorization decision:

```bash
vsr authz simulate --input api.eon --resource ScopedDoc --action read --user-id 7 --claim tenant_id=3 --row tenant_id=3
vsr authz simulate --input api.eon --resource ScopedDoc --action create --role admin --proposed tenant_id=42 --format json
vsr authz simulate --input api.eon --resource ScopedDoc --action read --scope Family=42 --scoped-assignment template:FamilyMember@Family=42
vsr authz simulate --input api.eon --resource ScopedDoc --action read --role member --row user_id=1 --row family_id=42 --hybrid-source item --scoped-assignment template:FamilyMember@Family=42
vsr authz simulate --input api.eon --resource ScopedDoc --action read --role member --scope Family=42 --hybrid-source collection_filter --scoped-assignment template:FamilyMember@Family=42
vsr authz simulate --input api.eon --resource SharedDoc --action read --user-id 7 --row family_id=42 --related-row FamilyMember:family_id=42,user_id=7
vsr --database-url sqlite:app.db?mode=rwc authz simulate --config api.eon --resource ScopedDoc --action read --user-id 7 --scope Family=42 --load-runtime-assignments
```

Repeated `--claim`, `--row`, and `--proposed` arguments use `key=value` syntax. Values are
inferred as `null`, `bool`, `i64`, or `String`. Repeated `--related-row` arguments use
`Resource:key=value,other=value` syntax so the simulator can evaluate relation-aware `exists`
predicates against explicit related rows. `--scope` uses `ScopeName=value`, and repeated
`--scoped-assignment` arguments use `permission:Name@Scope=value` or
`template:Name@Scope=value`. `--load-runtime-assignments` loads stored assignments for
`--user-id` from the configured database, using the table created by `vsr migrate authz`.
These runtime scoped assignments are validated and resolved by the simulator. `--hybrid-source`
adds a second, generated-handler view for `item`, `collection_filter`, `nested_parent`, or
`create_payload` scope derivation when the resource declares
`authorization.hybrid_enforcement`. Stored assignments include `created_at`,
`created_by_user_id`, and optional `expires_at`; expired assignments are ignored by runtime
simulation and runtime access checks.

You can also manage those persisted runtime assignments directly from the CLI:

```bash
vsr --database-url sqlite:app.db?mode=rwc authz runtime list --user-id 7
vsr --database-url sqlite:app.db?mode=rwc authz runtime create --config api.eon --user-id 7 --assignment template:FamilyMember@Family=42 --created-by-user-id 1
vsr --database-url sqlite:app.db?mode=rwc authz runtime evaluate --config api.eon --resource ScopedDoc --action read --user-id 7 --scope Family=42
vsr --database-url sqlite:app.db?mode=rwc authz runtime revoke --id runtime.assignment.123 --actor-user-id 1 --reason suspended
vsr --database-url sqlite:app.db?mode=rwc authz runtime renew --id runtime.assignment.123 --expires-at 2026-03-31T00:00:00Z --actor-user-id 1 --reason restored
vsr --database-url sqlite:app.db?mode=rwc authz runtime history --user-id 7
vsr --database-url sqlite:app.db?mode=rwc authz runtime delete --id runtime.assignment.123 --actor-user-id 1 --reason cleanup
```

`authz runtime create` validates the requested permission/template and scope against the static
`.eon` authorization contract before inserting the row. `authz runtime evaluate` loads stored
assignments for the user and evaluates only the runtime grant layer; it does not apply the
static CRUD role and row-policy checks. `authz runtime revoke` deactivates an assignment by
setting its expiration to the current time without deleting its record, and `authz runtime renew`
sets a new future expiration. `authz runtime history` reads the append-only assignment event log,
which now records `created`, `revoked`, `renewed`, and `deleted` events with actor and optional
reason data.

Static `.eon` row policies also support `all_of`, `any_of`, `not`, and a first bounded
relation-aware `exists` form. `vsr authz simulate` can fully evaluate `exists` predicates when
you supply matching related rows with repeated `--related-row` arguments; otherwise the trace
stays incomplete and reports the missing related resource data.

The `.eon` format also supports an optional static `authorization` block for declaring scopes,
permissions, templates, and an opt-in runtime management mount. The scope/permission/template
portion is still contract-only by itself for generated CRUD enforcement: validated and surfaced by
the diagnostic commands. Request-time behavior changes only when you opt into runtime management
or hybrid enforcement.

Generated item-scoped CRUD handlers can now also opt into the first hybrid-enforcement slice:

```eon
authorization: {
    scopes: {
        Family: {}
    }
    permissions: {
        FamilyManage: {
            actions: ["Create", "Read", "Update", "Delete"]
            resources: ["ScopedDoc"]
            scopes: ["Family"]
        }
    }
    hybrid_enforcement: {
        resources: {
            ScopedDoc: {
                scope: "Family"
                scope_field: "family_id"
                scope_sources: {
                    item: true
                    collection_filter: true
                    nested_parent: true
                    create_payload: true
                }
                actions: ["Create", "Read", "Update", "Delete"]
            }
        }
    }
}
```

This is additive only. Generated `GET /resource/{id}`, `PUT /resource/{id}`, and
`DELETE /resource/{id}` still require the static role check to pass first. When the static row
policy denies the row, the handler can derive a runtime scope from the stored row and consult the
persisted runtime assignment layer. Top-level `GET /resource` can also use runtime `Read` grants,
but only when the request includes an exact `filter_<scope_field>=...` value so the handler can
derive one concrete scope from the query and `scope_sources.collection_filter = true`. Nested
collection routes can also use runtime `Read` grants when `scope_sources.nested_parent = true`
and the nested parent filter is the configured `scope_field`. Generated `POST /resource` can also
opt into a narrow hybrid create fallback, and when the created row is only runtime-readable the
generated `201` response can still return the created item through the same hybrid read fallback.
The create path remains narrow:
the handler only opens the configured scope field when it is already assigned from a claim in
`policies.create`; in that case the create DTO exposes that one field as an optional fallback and
the handler uses it only when the claim is missing and a matching runtime `Create` grant exists
for the supplied scope.

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
        encryption_key: { env_or_file: "TURSO_ENCRYPTION_KEY" }
    }
}
```

You can still override it explicitly:

```eon
database: {
    engine: {
        kind: TursoLocal
        path: "var/data/app.db"
        encryption_key: { env_or_file: "TURSO_ENCRYPTION_KEY" }
    }
}
```

Current support:

- `Sqlx`: the legacy runtime path; use this explicitly if you want plain SQLx SQLite for a
  SQLite `.eon` service
- `TursoLocal`: bootstraps a local Turso database file and uses the project runtime database
  adapter with SQLite-compatible SQL
- `TursoLocal.encryption_key`: typed secret ref for the local Turso hex key; the preferred form is
  `{ env_or_file: "TURSO_ENCRYPTION_KEY" }`
- `TursoLocal.encryption_key_env`: legacy shorthand still accepted for backward compatibility

Current limitation:

- This is still a project-local runtime adapter, not a true upstream SQLx `Any` driver.

### Backup And Replication Planning

`.eon` services can now declare an optional `database.resilience` contract for backup and
replication intent. This is a planning surface first, not a job scheduler.

```eon
database: {
    engine: {
        kind: Sqlx
    }
    resilience: {
        profile: Pitr
        backup: {
            mode: Pitr
            target: S3
            verify_restore: true
            max_age: "24h"
            encryption_key: { env_or_file: "BACKUP_ENCRYPTION_KEY" }
        }
        replication: {
            mode: ReadReplica
            read_routing: Explicit
            read_url: { env_or_file: "DATABASE_READ_URL" }
            max_lag: "30s"
        }
    }
}
```

Use:

```bash
vsr backup plan --input api.eon
vsr backup plan --input api.eon --format json
vsr backup doctor --input api.eon
vsr replication doctor --input api.eon --read-database-url postgres://reader@127.0.0.1/app
vsr backup snapshot --input api.eon --output backups/run1
vsr backup export --input api.eon --output backups/run1
vsr backup verify-restore --artifact backups/run1 --format json
vsr backup push --artifact backups/run1 --remote s3://my-bucket/backups/run1
vsr backup pull --remote s3://my-bucket/backups/run1 --output restored/run1
```

Current scope:

- backend-aware backup and replication guidance
- doctor commands for obvious env and topology validation
- live Postgres/MySQL role-state checks in `vsr replication doctor`
- snapshot artifact creation and restore verification for SQLite/TursoLocal services
- Postgres/MySQL logical dump artifact creation with native tools or Docker client fallbacks
- Postgres/MySQL logical dump restore verification in disposable local Docker databases
- S3-compatible artifact push/pull around the local snapshot format
- checked `.eon` resilience vocabulary
- no scheduling, failover orchestration, or automatic read routing yet

For MinIO or another S3-compatible endpoint:

```bash
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin
export AWS_REGION=us-east-1
vsr backup push \
  --artifact backups/run1 \
  --remote s3://my-bucket/backups/run1 \
  --endpoint-url http://127.0.0.1:9000 \
  --path-style
```

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

Secrets are still configured via environment names today, but production deployments should prefer
mounted `*_FILE` bindings or a secret manager over inline `.env` values. The Phase 1 roadmap is in
[../../docs/production-secrets-roadmap.md](../../docs/production-secrets-roadmap.md). The current
auth rate limiter is process-local rather than distributed.

### Runtime In `.eon`

Bare `.eon` services can also define runtime defaults:

```eon
runtime: {
    compression: {
        enabled: true
        static_precompressed: true
    }
}
```

Generated modules expose this through `module::runtime()`. The parsed runtime options are:

- `compression.enabled`: emitted servers now apply dynamic HTTP response compression from this flag
- `compression.static_precompressed`: generated static mounts now serve `.br` and `.gz` companion
  files when present and add `Vary: Accept-Encoding`

`vsr build` now generates those companion files into `<binary>.bundle/` when this flag is enabled.
`vsr server emit` still copies the source static directories as-is.

Generated `.eon` modules also expose the compiled authorization model through
`module::authorization()`. That includes the optional static `authorization` contract and the
resource/action policy view used by `vsr authz explain`, which makes it suitable for custom
policy-management and diagnostics endpoints in emitted or manual servers. They also expose
`module::authorization_runtime(db)`, and `module::configure(...)` now registers that runtime
service as Actix app data for the configured scope. For a basic opt-in runtime assignment API,
generated modules also expose `module::configure_authorization_management(cfg, db)`, which mounts
`POST /authz/runtime/evaluate` plus admin-oriented
`GET /authz/runtime/assignment-events`, `GET/POST/DELETE /authz/runtime/assignments...`, and
`POST /authz/runtime/assignments/{id}/revoke|renew` endpoints backed by the shared authorization
runtime. The evaluate endpoint resolves persisted scoped permissions for an explicit
resource/action/scope request, but it does not apply static CRUD policy checks.
Custom handlers can also enforce persisted runtime grants directly through
`AuthorizationRuntime::enforce_runtime_access(...)` after injecting the shared runtime as Actix
app data.

### Create Admin

Create a new admin user:

```bash
# Interactive mode with prompts
vsr create-admin

# Non-interactive mode with parameters
vsr create-admin --email admin@example.com --password secure_password
```

If the built-in auth `user` table has auth claim columns, the CLI detects them automatically.
That includes legacy implicit numeric claim columns such as `tenant_id`, `org_id`, or
`claim_workspace_id`, plus explicit `security.auth.claims` mappings from your `.eon` service. 
Interactive admin creation prompts for those values, and non-interactive flows accept environment
variables named `ADMIN_<COLUMN_NAME>`, for example `ADMIN_TENANT_ID=1` or `ADMIN_IS_STAFF=true`.

For `.eon` services with explicit `security.auth.claims`, `vsr setup` also generates those mapped
`user` columns automatically as part of the built-in auth migration flow. You do not need to ship
manual SQL just to add auth claim columns.

Use explicit auth claims for stable user/session attributes. For permissions, delegated access,
and scoped grants, prefer the runtime authorization tables and the `.eon` `authorization`
contract instead of storing permission state on the built-in auth `user` row.

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
vsr gen-env --production
```

## Environment Variables

The CLI tool respects the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` / `DATABASE_URL_FILE` | Database connection string or mounted file containing it | Derived from `--config` or a single local `.eon`; otherwise `sqlite:var/data/app.db?mode=rwc` |
| `ADMIN_EMAIL` | Default admin email address | None |
| `ADMIN_PASSWORD` | Default admin password | None |
| `ADMIN_<COLUMN_NAME>` | Optional built-in auth claim column value, for example `ADMIN_TENANT_ID` or `ADMIN_IS_STAFF` | None |
| `JWT_SECRET` / `JWT_SECRET_FILE` | Legacy shared-secret JWT signing key or mounted file containing it | Required only when built-in auth uses the legacy `security.auth.jwt_secret` path |

For asymmetric `security.auth.jwt` configs, prefer `JWT_SIGNING_KEY_FILE` plus one file-backed
environment variable for each public verification key, for example
`JWT_PUBLIC_KEY_FILE` and `JWT_PUBLIC_KEY_PREVIOUS_FILE`. The built-in auth runtime exposes
`/.well-known/jwks.json` from those verification keys, so the safest rotation sequence is:

1. add the new public key to `verification_keys`
2. switch `active_kid` and `signing_key` to the new keypair
3. deploy and wait for the old token TTL window to pass
4. remove the old verification key

`vsr check --strict` warns when an asymmetric config still has only one verification key and
therefore has no overlap window for safe rotation.

## Examples

### Starter Contract Example

The repository starter example now lives at `examples/template` and is contract-first rather than a
Rust app skeleton:

```bash
cd examples/template
cp .env.example .env
vsr migrate generate --input api.eon --output migrations/0001_init.sql
vsr serve api.eon
```

### CMS Example

For a larger `.eon`-driven example with a Material studio client and local S3-compatible storage:

```bash
cd examples/cms/web
npm install
npm run build
cd ..
vsr setup
vsr serve api.eon
```

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

For production, prefer:

```bash
export DATABASE_URL_FILE=/run/secrets/DATABASE_URL
export JWT_SECRET_FILE=/run/secrets/JWT_SECRET

vsr setup --production
```

Or, for asymmetric JWT signing:

```bash
export DATABASE_URL_FILE=/run/secrets/DATABASE_URL
export JWT_SIGNING_KEY_FILE=/run/secrets/JWT_SIGNING_KEY
export JWT_VERIFYING_KEY_FILE=/run/secrets/JWT_VERIFYING_KEY

vsr setup --production
```

### `.eon`-Driven Local Turso Example

```bash
# Use the compiled database settings from a bare .eon service explicitly
vsr --config tests/fixtures/turso_local_api.eon check-db
vsr --config tests/fixtures/turso_local_api.eon migrate authz --output migrations/0001_authz.sql
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
- Use mounted secret files or a secure secret management system for JWT keys and other high-value
  secrets
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
