# VSR

<img width="250" height="256" alt="Method Draw Image" src="https://github.com/user-attachments/assets/dacb8710-1160-449b-88c1-577d722f37a4" />

A Rust toolkit for declaring REST APIs in Rust or [`.eon`](https://github.com/emilk/eon) and running them through a CLI-first workflow on top of Actix Web and SQLx.


> **Note**: This project is currently very much in progress and under active development. APIs will change, and features are incomplete.



> VSR started as a derive-macro shortcut for rapid API prototypes. The project is now centered on full `.eon` service definitions, built-in auth and admin flows, explicit migrations, and a native `vsr` runtime that can serve, emit, and build APIs from the same contract.

## VSR CLI

The main entry point is the `vsr` command-line tool. The published crate is `vsra`; the installed binary is `vsr`.

```bash
cargo install vsra --locked

vsr init my-api
vsr init my-api --starter minimal
vsr serve api.eon
vsr server expand --input api.eon --output api.expanded.rs
vsr server emit --input api.eon --output-dir generated-api
vsr build api.eon --release
vsr docs --output docs/eon-reference.md
```

Core CLI workflows:

- `vsr init my-api` generates a local starter project with `api.eon`, `.env.example`, `migrations/`, and a comment-rich default service contract
- `vsr serve api.eon` runs a native server directly from `.eon` for the fastest local development loop
- `vsr server expand ...` writes the fully expanded Rust module source so you can inspect the compiler output directly
- `vsr server emit ...` exports an inspectable Rust server project
- `vsr build ...` produces a standalone binary plus a `<binary>.bundle/` runtime bundle
- `vsr openapi ...`, `vsr docs ...`, `vsr authz ...`, and `vsr backup ...` generate docs, diagnostics, and deployment guidance from the same service contract

See the full command reference in [crates/rest_api_cli/README.md](crates/rest_api_cli/README.md).

## Features

- **CLI-first workflow**: Scaffold, serve, emit, build, inspect, and document services with `vsr`
- **Native `.eon` runtime**: `vsr serve <service.eon>` serves the same API shape directly without generating or compiling a Rust project first
- **Zero-boilerplate REST APIs**: Create complete CRUD endpoints with a single derive macro
- **Typed write DTOs**: The derive macro and `.eon` macro both generate `Create` and `Update` payload types
- **Compile-time `.eon` services**: Generate strongly typed resources and DTOs from a minimal `.eon` service file
- **Migration generation**: Generate explicit SQL migrations from `.eon` service definitions
- **Field validation**: Enforce string length and numeric range constraints in generated handlers and OpenAPI
- **Stable error envelope**: Generated resource handlers return JSON errors with `code`, `message`, and optional `field`
- **Typed list queries**: Generated collection routes support typed `limit`, `offset`, `sort`, `order`, exact-match `filter_<field>` params, and paged response envelopes
- **Built-in authentication**: JWT-based authentication with role management
- **Role-Based Access Control**: Declarative protection for your endpoints with role requirements
- **Database Agnostic**: Currently defaults to SQLite, with plans to support all SQLx targets
- **Relationship Handling**: Define foreign keys and nested routes between resources
- **Referential Actions**: Configure relation delete behavior with `Cascade`, `Restrict`, `SetNull`, or `NoAction`

## Installation

### CLI

Install the `vsr` command-line tool from crates.io:

```bash
cargo install vsra --locked
```

If you are working from a checkout of this repository, the workspace defaults to the CLI package,
so a plain root build produces `target/release/vsr`:

```bash
git clone https://github.com/MatiasHiltunen/very_simple_rest.git
cd very_simple_rest
cargo build --release
./target/release/vsr --help
```

Use `cargo build --workspace` when you want all workspace crates, or
`cargo build -p very_simple_rest` when you want only the library package.

### Library

You can include this library in your project by adding it as a git dependency in your `Cargo.toml`:

_Note that you need to add the other dependencies aswell_

```toml
[dependencies]
very_simple_rest = { git = "https://github.com/MatiasHiltunen/very_simple_rest.git" }
serde = { version = "1", features = ["derive"] }
sqlx = { version = "0.7", features = ["macros", "runtime-tokio", "sqlite"] }
actix-web = "4"
env_logger = "0.10"
log = "0.4"
```

## Documentation

- [CLI tool guide](crates/rest_api_cli/README.md)
- [.eon reference](docs/eon-reference.md)
- [.eon vNext roadmap](docs/eon-vnext-roadmap.md)
- [Authorization roadmap](docs/authorization-roadmap.md)
- [Backup and replication roadmap](docs/backup-replication-roadmap.md)

## Examples

The repository includes:

- `examples/template`: the current `.eon`-first starter example used as the reference shape for `vsr init`
- `examples/cms`: a full contract-first CMS example with a Material studio client and local S3-compatible storage
- `examples/demo`: the older Rust example binary

To run the starter contract example:

```sh
cd examples/template
cp .env.example .env
vsr migrate generate --input api.eon --output migrations/0001_init.sql
vsr serve api.eon
```

To run the CMS example:

```sh
cd examples/cms/web
npm install
npm run build
cd ..
vsr setup
vsr serve api.eon
```

To run the Rust demo example from the project root:

```sh
cargo run --example demo
```

## Quick Start

```rust
use very_simple_rest::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
#[rest_api(table = "post", id = "id", db = "sqlite")]
#[require_role(read = "user", update = "user", delete = "user")]
pub struct Post {
    pub id: Option<i64>,
    pub title: String,
    pub content: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
#[rest_api(table = "comment", id = "id", db = "sqlite")]
#[require_role(read = "user", update = "user", delete = "user")]
pub struct Comment {
    pub id: Option<i64>,
    pub title: String,
    pub content: String,
    #[relation(references = "post.id", nested_route = "true")]
    pub post_id: i64,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
#[rest_api(table = "user", id = "id", db = "sqlite")]
#[require_role(read = "admin", update = "admin", delete = "admin")]
pub struct User {
    pub id: Option<i64>,
    pub email: String,
    pub password_hash: String,
    pub role: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Logging and DB setup
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    sqlx::any::install_default_drivers();
    let pool = AnyPool::connect("sqlite:app.db?mode=rwc").await.unwrap();

    // Apply migrations before starting the server in production.
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Cors::permissive())
            .wrap(DefaultHeaders::new().add(("X-Version", "0.1.0")))
            .service(
                scope("/api")
                    .configure(|cfg| auth::auth_routes(cfg, pool.clone()))
                    .configure(|cfg| User::configure(cfg, pool.clone()))
                    .configure(|cfg| Post::configure(cfg, pool.clone()))
                    .configure(|cfg| Comment::configure(cfg, pool.clone())),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

## Authentication

The library provides these authentication endpoints out of the box:

- **POST /api/auth/register** - Register a new user
- **POST /api/auth/login** - Login and get a JWT token
- **GET /api/auth/me** - Get information about the authenticated account

Built-in auth failures now also use the shared JSON error envelope. For example, invalid login
returns:

```json
{
  "code": "invalid_credentials",
  "message": "Invalid credentials"
}
```

When you create built-in admin users through `vsr create-admin` or `vsr setup`, the CLI now
inspects the built-in auth claim columns and can populate them during admin creation. With legacy
implicit claims, that means numeric columns such as `tenant_id`, `org_id`, or
`claim_workspace_id`. With explicit `security.auth.claims`, it uses the mapped `user` table
columns instead, including `String` and `Bool` claim types. Interactive flows prompt for those
values, and non-interactive flows accept environment variables named `ADMIN_<COLUMN_NAME>`, such
as `ADMIN_TENANT_ID=1` or `ADMIN_IS_STAFF=true`.

When `security.auth.claims` is configured on a `.eon` service, `vsr setup` now extends the
built-in auth `user` table with those mapped columns automatically before admin creation. Manual
claim-column SQL is no longer required for `.eon`-driven services.

Use that for stable user/session attributes. For permissions, delegated access, and scope-bound
grants, prefer the runtime authorization tables and `authorization` contract instead of adding
permission state to the built-in auth `user` row.

For services that expose the built-in auth admin routes, `PATCH /api/auth/admin/users/{id}` can
also update configured `security.auth.claims` values on existing users. That makes it possible to
bootstrap claim-scoped examples and policy-heavy services through HTTP instead of direct SQL
updates.

### JWT Secret Configuration

Built-in auth now requires a JWT signing secret before the server starts. In `.eon`, prefer the
typed form:

```eon
security: {
    auth: {
        jwt_secret: { env_or_file: "JWT_SECRET" }
    }
}
```

Supported runtime sources:

1. Environment variable: `JWT_SECRET=your_secret_here`
2. Mounted secret file: `JWT_SECRET_FILE=/run/secrets/JWT_SECRET`
3. systemd credential via `jwt_secret: { systemd_credential: "jwt_secret" }`
4. `.env` file in your project root: `JWT_SECRET=your_secret_here`

The runtime no longer generates a random fallback secret, so tokens remain valid across restarts
and multi-instance deployments only when you provide an explicit secret.

For production, prefer secret files or a secret manager over inline `.env` values. The current
production-secrets plan is in
[docs/production-secrets-roadmap.md](docs/production-secrets-roadmap.md).

### Example login:

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "password123"}'
```

## User Management

The library provides two methods for creating admin users:

### 1. Environment Variables (Non-Interactive)

Set these environment variables before starting your application:

```
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=securepassword
ADMIN_TENANT_ID=1
```

After the built-in auth schema has been migrated, `ensure_admin_exists` can create the first admin
user automatically with these credentials. If the `user` table also has numeric claim columns such
as `tenant_id`, `org_id`, or `claim_workspace_id`, `ensure_admin_exists` now reads matching
`ADMIN_<COLUMN_NAME>` variables and stores them on the admin row too. The CLI uses the same
`ADMIN_<COLUMN_NAME>` convention for explicit `security.auth.claims` mappings.

If your app startup already has an explicit `AuthSettings` value, prefer
`auth::ensure_admin_exists_with_settings(&pool, &settings)` so admin bootstrap follows the same
configured claim mappings as login and `/api/auth/me`.

### 2. CLI Tool (Interactive)

The library includes a CLI tool for managing your API, with specific commands for user management:

```bash
# Generate a migration for the built-in auth schema
vsr migrate auth --output migrations/0000_auth.sql

# Generate the runtime authorization assignment schema used by authz simulation and future policy APIs
vsr migrate authz --output migrations/0001_authz.sql

# Emit a standalone Rust server project from a bare .eon service
vsr server emit --input api.eon --output-dir generated-api

# Build a server binary directly from a bare .eon service
vsr build api.eon --release

# Setup wizard with interactive prompts
vsr setup

# Production-safe setup: do not write live secrets into `.env`
vsr setup --production

# Create an admin user
vsr create-admin

# Create an admin with specific credentials
vsr create-admin --email admin@example.com --password securepassword

# Check database status including admin users
vsr check-db

# Generate a .env template file
vsr gen-env

# Generate a production-safe env template
vsr gen-env --production

# Generate Infisical Agent/runtime scaffolding from a `.eon` service
vsr secrets infisical scaffold --input api.eon --project my-project

# For machine-identity agent flows, prefer adding the Infisical project UUID too
vsr secrets infisical scaffold --input api.eon --project my-project --project-id <project-uuid>

# Validate resolved secret bindings and optional Infisical scaffold files
vsr doctor secrets --input api.eon --infisical-dir deploy/infisical

# Run compiler-facing schema diagnostics
vsr check --input api.eon
vsr check --input api.eon --strict --format json

# Render a backend-aware backup/replication plan from a `.eon` service
vsr backup plan --input api.eon
```

The CLI tool provides a secure way to set up admin users with password confirmation and validation.

When you run `vsr` from a directory containing exactly one `.eon` file, commands such as `setup`,
`create-admin`, `check-db`, and `gen-env` now auto-discover that service and derive the default
database URL from it.

For `.eon` services, `vsr gen-env` now writes a real local Turso encryption key when
`database.engine = TursoLocal` is in use, and `vsr setup` now bootstraps local runtime inputs
before database work: it generates or loads `.env`, can create self-signed dev TLS certs from the
service `tls` config, and prints the exact paths it generated or reused.

For production, `vsr setup --production` and `vsr gen-env --production` switch to template-only
secret handling: they do not write live JWT/database/mail secrets into `.env`, and setup refuses
to continue when required production secrets are unresolved. The CLI and runtime also honor
`DATABASE_URL_FILE` when you prefer mounted secret files over inline connection URLs.

For Infisical, `vsr secrets infisical scaffold` now generates an Infisical Agent config, per-secret
templates, and a `runtime.env` file with the `*_FILE` bindings the VSR runtime already understands.
`vsr doctor secrets` validates the currently resolved bindings and can also verify that the
generated Infisical scaffold directory is complete. See [docs/infisical.md](docs/infisical.md).

`vsr check` now runs compiler-facing diagnostics over `.eon` or derive-backed schema sources.
The first strict slice focuses on high-confidence issues: TLS file paths that do not exist,
authorization contracts that do not affect generated runtime behavior, unused declared scopes, and
policy, nested-route, `exists`, and hybrid lookup fields that rely on inferred indexes without an
explicit `.eon` declaration. It also flags build-artifact misconfigurations such as empty declared
env overrides, binary/bundle path collisions, and resolved cache/output overlaps.
Add `--strict` to fail the command when any warning is reported.

For detailed instructions on using the CLI tool, see the [CLI Tool Documentation](crates/rest_api_cli/README.md).

## Server Generation

The CLI can serve a bare `.eon` service directly, emit an inspectable Actix server project, or
build a compiled binary from the same contract:

```bash
# Run the API directly from the .eon service for fast local iteration
vsr serve tests/fixtures/blog_api.eon

# Generate a local Rust project you can inspect and edit
vsr server emit --input tests/fixtures/blog_api.eon --output-dir generated-api

# Build a binary directly from the same .eon file
vsr build tests/fixtures/blog_api.eon --release
```

`vsr serve` is the fastest development loop. It serves the compiled API surface directly from the
`.eon` file, including `/openapi.json`, `/docs`, static mounts, built-in auth, runtime authz
management routes, compiled database settings, and TLS when configured.

The emitted project includes:

- `Cargo.toml` with the required runtime dependencies
- `src/main.rs` wired to `rest_api_from_eon!`
- the copied `.eon` file
- `.env.example`
- `openapi.json`
- `migrations/0000_auth.sql` with built-in auth enabled by default
- `migrations/0001_service.sql`

Built-in auth and account routes are enabled by default for generated servers and documents. Use
`--without-auth` if your `.eon` service defines its own `user` table or if you want to omit the
shared `/auth` routes and `migrations/0000_auth.sql`.

`vsr build <service.eon>` now writes the binary next to the `.eon` file by default, naming it
after the `.eon` file stem. For example, `vsr build examples/cms/api.eon` produces
`examples/cms/api` and uses `examples/cms/.vsr-build/` for its reusable generated-project cache.
If `--output` points to an existing directory, the binary is placed inside that directory using
the same default name.

The build command also exports the generated runtime assets next to the binary in
`<binary>.bundle/`, including `.env.example`, `openapi.json`, the copied `.eon` file,
`README.md`, `migrations/`, and relative TLS certificate files when they exist at build time.
When `runtime.compression.static_precompressed = true`, `vsr build` also generates `.br` and
`.gz` companion files for copied static assets inside that bundle.

`.eon` services can now also declare build artifact locations under `build.artifacts`, with the
following precedence for each artifact path: explicit CLI override, then a declared env var
override, then the literal `.eon` path, then the service-relative default. If a build artifact
does not declare an env var in `.eon`, `vsr` does not attempt to read one implicitly.

`vsr clean --input <service.eon>` now resolves and removes that same service-specific build cache.
Without `--input` or `--build-dir`, it preserves the legacy fallback of cleaning `./.vsr-build`
from the current working directory.

Generated server projects serve the OpenAPI document at `/openapi.json` and a Swagger UI page at
`/docs`.

When a `.eon` service defines static mounts, `vsr server emit` also copies those directories into
the generated project so the emitted server can serve them without extra setup.

When a `.eon` service defines `security`, `vsr server emit` also applies the compiled JSON body
limits, CORS policy, trusted-proxy handling, auth rate limits, security headers, and built-in
auth token settings automatically in the emitted server.

When a `.eon` service defines `tls`, `vsr server emit` also wires Rustls-based HTTPS with HTTP/2
in the emitted server, defaults `BIND_ADDR` to `127.0.0.1:8443`, and lets you generate local
certificate PEM files with `vsr tls self-signed`.

`vsr server emit` also carries the compiled `.eon` database engine config into the generated
project. SQLite services now default to encrypted `database.engine = TursoLocal`, using
`var/data/<module>.db` and `TURSO_ENCRYPTION_KEY` unless you override it explicitly. You can still
opt back into the legacy runtime path with `database.engine.kind = Sqlx`.

## OpenAPI

You can also render an OpenAPI document directly from either a `.eon` file or derive-based Rust
sources:

```bash
# Generate OpenAPI JSON from a bare .eon service
vsr openapi --input tests/fixtures/blog_api.eon --output openapi.json

# Generate the same kind of document from #[derive(RestApi)] resources
vsr openapi --input src --exclude-table user --output openapi.json

# Omit built-in auth and account routes if your service owns the user model
vsr openapi --input tests/fixtures/blog_api.eon --without-auth --output openapi-no-auth.json
```

The current generator covers generated resource routes, DTO schemas, nested collection routes, JWT
bearer auth, the `/api` server base URL, and built-in auth/account routes by default. Use
`--without-auth` to omit them. In Swagger, login and registration appear under `Auth`, while the
current-user endpoint appears under `Account`. Generated server projects reuse the same document.
Collection and nested collection routes also document their typed list query parameters and their
paged response envelopes, including pagination, sorting, cursor pagination, exact-match field
filters, `total`, `next_offset`, and `next_cursor`.

## `.eon` Reference Docs

You can generate a Markdown reference for the full currently supported `.eon` surface:

```bash
vsr docs --output docs/eon-reference.md
```

The generated document is intended to be precise enough for AI agents and still readable for
humans. The checked-in reference lives at `docs/eon-reference.md`.
The staged authorization architecture plan lives at `docs/authorization-roadmap.md`.

## Authorization Explain

You can inspect how the current `.eon` roles and row policies compile into the internal
authorization model:

```bash
vsr authz explain --input api.eon
vsr authz explain --input api.eon --format json --output docs/authz.json
```

This is intended as the first correctness-oriented diagnostic step before richer policy features
such as simulation and runtime-managed assignments.

You can also simulate one authorization decision against that compiled model:

```bash
vsr authz simulate --input api.eon --resource ScopedDoc --action read --user-id 7 --claim tenant_id=3 --row tenant_id=3
vsr authz simulate --input api.eon --resource ScopedDoc --action create --role admin --proposed tenant_id=42 --format json
vsr authz simulate --input api.eon --resource ScopedDoc --action read --scope Family=42 --scoped-assignment template:FamilyMember@Family=42
vsr authz simulate --input api.eon --resource ScopedDoc --action read --role member --row user_id=1 --row family_id=42 --hybrid-source item --scoped-assignment template:FamilyMember@Family=42
vsr authz simulate --input api.eon --resource ScopedDoc --action read --role member --scope Family=42 --hybrid-source collection_filter --scoped-assignment template:FamilyMember@Family=42
vsr authz simulate --input api.eon --resource SharedDoc --action read --user-id 7 --row family_id=42 --related-row FamilyMember:family_id=42,user_id=7
vsr --database-url sqlite:app.db?mode=rwc authz simulate --config api.eon --resource ScopedDoc --action read --user-id 7 --scope Family=42 --load-runtime-assignments
```

`--claim`, `--row`, and `--proposed` accept repeated `key=value` pairs. Values are inferred as
`null`, `bool`, `i64`, or `String`. Repeated `--related-row` values use
`Resource:key=value,other=value` syntax so the simulator can evaluate relation-aware `exists`
predicates against explicit related rows. `--scope` accepts `ScopeName=value`, and repeated
`--scoped-assignment` values accept `permission:Name@Scope=value` or
`template:Name@Scope=value`. `--load-runtime-assignments` fetches stored assignments for
`--user-id` from the configured database, using the runtime authz table created by
`vsr migrate authz`. Runtime scoped assignments are resolved and validated against the static
`authorization` contract in the simulator. `--hybrid-source` adds a second, generated-handler
view for `item`, `collection_filter`, `nested_parent`, or `create_payload` scope derivation when
the resource declares `authorization.hybrid_enforcement`.
Stored runtime assignments now include `created_at`, `created_by_user_id`, and optional
`expires_at`; expired assignments are ignored by runtime simulation and runtime access checks.

The same persisted runtime-assignment layer is also manageable directly from the CLI:

```bash
vsr --database-url sqlite:app.db?mode=rwc authz runtime list --user-id 7
vsr --database-url sqlite:app.db?mode=rwc authz runtime create --config api.eon --user-id 7 --assignment template:FamilyMember@Family=42 --created-by-user-id 1
vsr --database-url sqlite:app.db?mode=rwc authz runtime evaluate --config api.eon --resource ScopedDoc --action read --user-id 7 --scope Family=42
vsr --database-url sqlite:app.db?mode=rwc authz runtime revoke --id runtime.assignment.123 --actor-user-id 1 --reason suspended
vsr --database-url sqlite:app.db?mode=rwc authz runtime renew --id runtime.assignment.123 --expires-at 2026-03-31T00:00:00Z --actor-user-id 1 --reason restored
vsr --database-url sqlite:app.db?mode=rwc authz runtime history --user-id 7
vsr --database-url sqlite:app.db?mode=rwc authz runtime delete --id runtime.assignment.123 --actor-user-id 1 --reason cleanup
```

`authz runtime create` validates the target permission/template and scope against the static
`.eon` authorization contract before persisting the assignment. `authz runtime evaluate` loads
stored assignments for the user and evaluates only the runtime grant layer; it does not run the
static CRUD role and row-policy checks. `authz runtime revoke` deactivates an assignment by
setting its expiration to the current time without deleting its record, and `authz runtime renew`
sets a new future expiration. `authz runtime history` reads the append-only assignment event log,
which now records `created`, `revoked`, `renewed`, and `deleted` events with actor and optional
reason data.

`.eon` also now accepts an optional static `authorization` block for declaring scopes,
permissions, templates, and an opt-in runtime authorization management API. The scope /
permission / template part is still contract-only by itself: it is validated, included in the
compiled authorization model, and shown by `vsr authz explain`. Request-time behavior changes
only when you explicitly opt into either the management API or hybrid enforcement. The management
API can be enabled explicitly:

```eon
authorization: {
    management_api: {
        mount: "/authz/runtime"
    }
    scopes: {
        Family: {}
    }
    permissions: {
        FamilyRead: {
            actions: ["Read"]
            resources: ["ScopedDoc"]
            scopes: ["Family"]
        }
    }
}
```

For generated routes, `.eon` can also opt into the first hybrid-enforcement slice:

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

In this mode, generated `GET /resource/{id}`, `PUT /resource/{id}`, and `DELETE /resource/{id}`
still apply the normal static role checks first. If the static row-policy path denies the row,
the handler can then derive a runtime scope from the stored row, such as `Family=42` from
`family_id`, and consult persisted runtime scoped grants through `AuthorizationRuntime`.

Generated `POST /resource` can also opt into the first hybrid create slice, but only when the
configured `scope_field` is already claim-controlled in `policies.create`. In that case, the
generated create DTO exposes that one field as an optional fallback, and the handler uses it only
when the claim is missing and a matching runtime scoped `Create` grant exists for the supplied
scope.

Top-level `GET /resource` can also use runtime `Read` grants when the request includes an exact
`filter_<scope_field>=...` value, and nested collection routes such as
`GET /parent/{id}/resource` can do the same when `scope_sources.nested_parent = true` and the
nested parent filter is the configured `scope_field`. When a `POST /resource` request creates a
row that is only runtime-readable, the created response can also render that row through the same
hybrid read fallback instead of returning an empty `201`.

This is additive only: it does not bypass static role requirements, it still needs one concrete
scope per request, and it does not let runtime grants override unrelated create assignments.

Generated `.eon` modules expose the compiled authorization view through `module::authorization()`
so manual apps or emitted servers can build custom policy-management and diagnostics surfaces on
top of the same typed model. They also expose `module::authorization_runtime(db)` and
`module::authorization_management()`. `module::configure(...)` now registers the runtime service
as Actix app data so custom handlers can load, persist, and simulate runtime scoped assignments
without duplicating storage logic. When `authorization.management_api` is enabled in `.eon`,
generated `configure(...)` also mounts the runtime management routes automatically at the
configured mount. You can still call `module::configure_authorization_management(cfg, db)` for an
explicit mount using the same configured path:

- `POST <mount>/evaluate`
- `GET <mount>/assignments?user_id=...`
- `GET <mount>/assignment-events?user_id=...`
- `POST <mount>/assignments`
- `POST <mount>/assignments/{id}/revoke`
- `POST <mount>/assignments/{id}/renew`
- `DELETE <mount>/assignments/{id}`

Those endpoints manage persisted scoped permission/template assignments through the shared
authorization runtime. Assignment records include `created_at`, `created_by_user_id`, and an
optional `expires_at`, and expired assignments are ignored by runtime evaluation. The append-only
assignment event stream records `created`, `revoked`, `renewed`, and `deleted` events with actor
metadata, and is available from `GET <mount>/assignment-events?user_id=...`. `POST
/authz/runtime/evaluate` checks which persisted scoped permissions apply to an explicit
`resource + action + scope` for the current user or an admin-selected user. It still does not
run static role checks, row policies, or create-time assignments, so CRUD enforcement remains
unchanged.

For real custom endpoint enforcement, handlers can inject
`web::Data<very_simple_rest::authorization::AuthorizationRuntime>` and call
`runtime.enforce_runtime_access(&user, "ResourceName", AuthorizationAction::Read, scope).await`.
That enforces persisted runtime scoped permissions for the current user, while still leaving
generated CRUD handlers on their existing static authorization path.

## Static Files In `.eon`

Bare `.eon` services can configure static file serving at the service level:

```eon
module: "static_site_api"
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
resources: [
    {
        name: "Page"
        fields: [
            { name: "title", type: "String" }
        ]
    }
]
```

Supported static mount options:

- `mount`: URL prefix such as `/assets` or `/`
- `dir`: directory relative to the `.eon` file
- `mode`: `Directory` or `Spa`
- `index_file`: optional directory index file, defaulting to `index.html` for `Spa`
- `fallback_file`: SPA fallback target, defaulting to `index.html` for `Spa`
- `cache`: `NoStore`, `Revalidate`, or `Immutable`

The loader validates that:

- static directories stay under the `.eon` service root
- reserved routes such as `/api`, `/auth`, `/docs`, and `/openapi.json` are not shadowed
- SPA fallback only applies to `GET` and `HEAD` HTML navigations, not missing asset files
- symlinked directories are rejected during emitted-project copying

## Database Engine In `.eon`

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

`.eon` can now also declare an optional resilience contract under `database.resilience`. This is a
planning/documentation surface first: it lets `vsr` explain the intended backup and replication
posture without embedding deployment-specific schedules into the schema.

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

The first implementation is intentionally conservative:

- it renders backend-aware backup and replication guidance
- it can validate obvious env and connectivity gaps with the doctor commands
- `vsr replication doctor` can inspect live Postgres/MySQL role signals (`pg_is_in_recovery()`, `read_only`) for declared primary/read URLs
- it can create and verify snapshot artifacts for SQLite/TursoLocal services
- it can create Postgres/MySQL logical dump artifacts with `pg_dump` / `mysqldump`, falling back to official Docker client images when those tools are not installed locally
- `vsr backup verify-restore` can now restore those Postgres/MySQL dump artifacts into disposable local Docker databases and validate the restored schema
- it can push and pull backup artifact directories to S3-compatible storage
- it does not schedule jobs or orchestrate failover
- runtime read-routing is still future work

For S3-compatible providers such as MinIO, pass an endpoint override and path-style requests:

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

## TLS In `.eon`

Bare `.eon` services can also enable Rustls-based HTTPS for generated Actix servers:

```eon
tls: {
    cert_path: "certs/dev-cert.pem"
    key_path: "certs/dev-key.pem"
    cert_path_env: "TLS_CERT_PATH"
    key_path_env: "TLS_KEY_PATH"
}
```

Notes:

- When `tls` is present, generated servers bind with Rustls and enable HTTP/2 automatically.
- Relative certificate paths are resolved from the emitted project directory, or from
  `<binary>.bundle/` for built binaries.
- `vsr tls self-signed --config service.eon` generates compatible local PEM files using those
  configured paths. With a single `.eon` file in the current directory, `vsr tls self-signed`
  auto-discovers it.
- `BIND_ADDR` defaults to `127.0.0.1:8443` for TLS-enabled services.

## Security In `.eon`

Bare `.eon` services can also define service-level server security defaults:

```eon
security: {
    requests: {
        json_max_bytes: 1048576
    }
    cors: {
        origins: ["http://localhost:3000"]
        origins_env: "CORS_ORIGINS"
        allow_credentials: true
        allow_methods: ["GET", "POST", "OPTIONS"]
        allow_headers: ["authorization", "content-type"]
        expose_headers: ["x-total-count"]
        max_age_seconds: 600
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
        hsts: {
            max_age_seconds: 31536000
            include_subdomains: true
        }
    }
    auth: {
        issuer: "very_simple_rest"
        audience: "public-api"
        access_token_ttl_seconds: 3600
    }
}
```

Supported security options:

- `requests.json_max_bytes`: JSON body limit for generated resource and built-in auth routes
- `cors.origins`: explicit allowed origins, or `["*"]` when credentials are disabled
- `cors.origins_env`: optional comma-separated origin list loaded from an environment variable
- `cors.allow_credentials`: emits `Access-Control-Allow-Credentials: true`
- `cors.allow_methods`: allowed preflight methods, defaulting to common REST verbs when omitted
- `cors.allow_headers`: allowed request headers, defaulting to `authorization`, `content-type`, and `accept`
- `cors.expose_headers`: response headers exposed to the browser
- `cors.max_age_seconds`: optional preflight cache duration
- `trusted_proxies.proxies`: exact proxy IPs whose forwarded headers should be trusted
- `trusted_proxies.proxies_env`: optional comma-separated trusted proxy IP list loaded from env
- `rate_limits.login`: built-in auth login rate limit by resolved client IP
- `rate_limits.register`: built-in auth registration rate limit by resolved client IP
- `headers.frame_options`: `Deny` or `SameOrigin`
- `headers.content_type_options`: emits `X-Content-Type-Options: nosniff`
- `headers.referrer_policy`: values such as `NoReferrer` or `StrictOriginWhenCrossOrigin`
- `headers.hsts`: optional `Strict-Transport-Security` configuration
- `auth.issuer`: built-in auth JWT `iss` claim
- `auth.audience`: built-in auth JWT `aud` claim
- `auth.access_token_ttl_seconds`: built-in auth token lifetime

Generated `.eon` modules expose the compiled settings through `module::security()` and
`module::configure_security(...)`. Secrets such as `JWT_SECRET` still belong in the environment,
not in `.eon`. The current rate-limit implementation is in-memory and process-local, so it is a
good default for a single binary but not a shared distributed limiter.

## Runtime In `.eon`

`.eon` services can also define service-level runtime defaults:

```eon
runtime: {
    compression: {
        enabled: true
        static_precompressed: true
    }
}
```

Generated `.eon` modules expose this through `module::runtime()`. The currently parsed runtime
options are:

- `compression.enabled`: enables dynamic HTTP response compression on emitted servers and can be
  applied manually with `very_simple_rest::core::runtime::compression_middleware(&module::runtime())`
- `compression.static_precompressed`: enables `.br` and `.gz` companion-file lookup for generated
  static mounts, adds `Vary: Accept-Encoding`, and preserves the existing cache policy when an
  encoded asset is served

`vsr build` now generates those companion files into `<binary>.bundle/` when this flag is enabled.
`vsr server emit` still copies the source static directories as-is.

## Migrations

Generated REST resources no longer run `CREATE TABLE IF NOT EXISTS` at startup. For `.eon`
services, generate explicit SQL and apply it before serving traffic:

```bash
# Generate the built-in auth migration
vsr migrate auth --output migrations/0000_auth.sql

# Generate the runtime authorization assignment migration
vsr migrate authz --output migrations/0001_authz.sql

# Generate migrations from Rust `#[derive(RestApi)]` resources
vsr migrate derive --input src --exclude-table user --output migrations/0002_resources.sql

# Generate an additive migration between two schema versions
vsr migrate diff --from schema_v1.eon --to schema_v2.eon --output migrations/0003_additive.sql

# Inspect a live database against a schema source
vsr --database-url sqlite:app.db?mode=rwc migrate inspect --input src --exclude-table user

# Generate a deterministic migration file from a .eon service
vsr migrate generate --input tests/fixtures/blog_api.eon --output migrations/0002_init.sql

# Verify that the checked-in SQL still matches the .eon schema
vsr migrate check --input tests/fixtures/blog_api.eon --output migrations/0002_init.sql

# Apply migrations to the configured database
vsr --database-url sqlite:app.db?mode=rwc migrate apply --dir migrations

# Or derive the database URL from a bare .eon service, including TursoLocal paths
vsr --config tests/fixtures/turso_local_api.eon migrate apply --dir migrations
```

The generated SQL includes:

- `CREATE TABLE` statements for each resource
- Foreign keys for declared relations
- Indexes for relation fields, direct row-policy fields, and `exists` target fields

Built-in auth now has the same explicit schema path:

- `vsr migrate auth` generates the `user` table migration
- `vsr migrate authz` generates the runtime authorization assignment table, including audit and expiry columns used by authz diagnostics and policy-management APIs
- `vsr setup` applies that auth migration before prompting for the first admin user
- `ensure_admin_exists` no longer creates tables at server startup

Derive-based resources can now use the same flow:

- `vsr migrate derive --input src --output migrations/...` scans Rust sources for `#[derive(RestApi)]`
- `--exclude-table user` avoids colliding with the built-in auth migration when your project also exposes `User`
- `vsr migrate check-derive` verifies checked-in SQL against the current Rust resource definitions

For additive schema evolution, `vsr migrate diff` compares two schema sources and emits only:

- new tables
- new indexes
- safe added columns that are nullable or have generated timestamp defaults

It intentionally rejects destructive or ambiguous changes such as removed fields, type changes,
required backfilled columns, or new relation columns. Those still require a manual SQL migration.

For live databases, `vsr migrate inspect` compares the current schema to a `.eon` file, a Rust
source file, or a Rust source directory and reports missing tables, missing columns, missing
indexes, foreign-key target drift, `ON DELETE` drift, type/nullability mismatches, and missing
timestamp defaults.

For a larger SQLite benchmark fixture with deep relations and a deterministic seed script, see
`examples/sqlite_bench/`.

For a policy-heavy `.eon` example with tenant claims, owner-scoped writes, and self-scoped
resources, see `examples/fine_grained_policies/`.

For a family-management example that combines relation-aware `exists` policies, `create.require`,
runtime templates/scopes, hybrid enforcement, and a same-origin browser SPA, see
`examples/family_app/`.

For a minimal `.eon`-only app with built-in auth, owner-scoped todos, admin visibility across all
rows, and a static browser client, see `examples/todo_app/`.

For a real-world single-`.eon` example with public catalog discovery, built-in account
management, admin-curated thesis topics, owner-scoped collaboration requests, and a same-origin
browser client, see `examples/bridgeboard/`.

For a larger editorial example with a Material studio client, built-in auth, local object storage,
and a local S3-compatible upload workflow, see `examples/cms/`.

## RBAC Attributes

Protect your endpoints with declarative role requirements:

```rust
#[require_role(read = "user", update = "admin", delete = "admin")]
```

This will:
- Allow users with the "user" role to read data
- Restrict update/delete operations to users with the "admin" role
- Return 403 Forbidden if the user lacks the required role

## Row Policies

Portable row-level policies can be generated at the macro layer. They work for SQLite too,
because the generated handlers enforce them in application code instead of relying on
database-native RLS.

For derive-based resources:

```rust
#[row_policy(
    read = "owner:user_id",
    create = "set_owner:user_id",
    update = "owner:user_id",
    delete = "owner:user_id"
)]
```

This makes the generated handlers:

- Filter reads to rows owned by the authenticated user
- Bind `user.id` into `user_id` on create
- Prevent ownership changes through update payloads
- Return `404` for update/delete when the row is outside the caller's scope

The same attribute also supports claim-based scoping and explicit admin bypass control:

```rust
#[row_policy(
    read = "tenant_id=claim.tenant_id",
    create = "user_id=user.id; tenant_id=claim.tenant_id",
    update = "tenant_id=claim.tenant_id",
    delete = "tenant_id=claim.tenant_id",
    admin_bypass = false
)]
```

This makes the generated handlers:

- Read `tenant_id` from the JWT claims in `UserContext`
- Force `user_id` and `tenant_id` on create, regardless of request payload
- Keep tenant-scoped fields out of generated `Create`/`Update` DTOs
- Apply the same tenant filter to admin users when `admin_bypass = false`

In `.eon`, `read`, `update`, and `delete` filters can also use boolean composition. A single
policy entry stays as-is, arrays imply `all_of`, and you can nest `all_of`, `any_of`, `not`, and
`exists` explicitly. Leaf filters support equality plus `is_null` / `is_not_null` checks on
nullable fields. `create` still supports the legacy flat assignment list, and it can now also use
`{ assign, require }` so create-time preconditions stay declarative.

```eon
policies: {
    admin_bypass: false
    read: {
        any_of: [
            "owner_id=user.id"
            { field: "archived_at", is_null: true }
            {
                all_of: [
                    "tenant_id=claim.tenant_id"
                    { not: "blocked_user_id=user.id" }
                ]
            }
        ]
    }
    create: [
        "owner_id=user.id"
        { field: "tenant_id", value: "claim.tenant_id" }
    ]
    update: {
        any_of: [
            "owner_id=user.id"
            { field: "archived_at", is_not_null: true }
        ]
    }
    delete: "Owner:owner_id"
}
```

The first relation-aware form is `exists`, which compiles to a correlated subquery against another
declared resource:

```eon
read: {
    exists: {
        resource: "FamilyMember"
        where: [
            { field: "family_id", equals_field: "family_id" }
            {
                any_of: [
                    "user_id=user.id"
                    "delegate_user_id=user.id"
                ]
            }
        ]
    }
}
```

That shape is intentionally narrow for now:

- `exists` targets another declared resource
- `where` accepts leaf comparisons plus nested `all_of`, `any_of`, and `not` groups
- list entries inside `where` still imply `AND`
- each condition is either `related_field = user.id` / `claim.<name>` / `input.<field>`,
  `related_field = row.<current_field>`, or a nullable `IS NULL` / `IS NOT NULL` check

Create-time requirements use the same tree:

```eon
create: {
    assign: [
        "created_by_user_id=user.id"
    ]
    require: {
        exists: {
            resource: "Family"
            where: [
                { field: "id", equals: "input.family_id" }
                "owner_user_id=user.id"
            ]
        }
    }
}
```

That lets `.eon` express bounded onboarding rules such as “you may add a family member only to a
family you own” without falling back to handwritten handlers.

When you use the built-in auth routes, `/auth/login` now emits numeric claims automatically from
the `user` row. You can also make those claim names explicit in `.eon`:

```eon
security: {
    auth: {
        claims: {
            tenant_id: { column: "tenant_scope", type: I64 }
            workspace_id: "claim_workspace_id"
            staff: { column: "is_staff", type: Bool }
            plan: String
        }
    }
}
```

Supported claim-mapping forms:

- `tenant_id: I64` means `claim.tenant_id` comes from `user.tenant_id`
- `workspace_id: "claim_workspace_id"` means `claim.workspace_id` comes from `user.claim_workspace_id`
- `staff: { column: "is_staff", type: Bool }` uses a custom column and non-integer type

If you do not configure `security.auth.claims`, the legacy implicit behavior still applies:

- Any numeric column ending in `_id` becomes a claim with the same name, such as `tenant_id` or `org_id`
- Any numeric column named `claim_<name>` becomes a claim named `<name>`

That lets claim-scoped policies work without a custom token issuer, as long as your user records
carry the relevant columns. Row policies can now consume explicit `I64`, `String`, and `Bool`
claims when the target resource field uses the matching type. The legacy implicit claim path
remains numeric-only, so undeclared `claim.<name>` usage is still limited to `*_id`-style claims.
Policy comparisons are still equality-only today; boolean composition and `exists` change how
filters combine, not which operators are available. `vsr authz simulate` can fully evaluate
`exists` predicates when you provide related rows with repeated `--related-row` arguments; if you
omit them, the trace stays incomplete and tells you which related resource data is missing.

## Relationships

Define relationships between entities:

```rust
#[relation(
    references = "post.id",
    nested_route = "true",
    on_delete = "cascade"
)]
pub post_id: i64,
```

This generates nested routes like `/api/post/{post_id}/comment` automatically.

Relation delete behavior is schema-driven and ends up in the generated foreign key:

- `Cascade`
- `Restrict`
- `SetNull`
- `NoAction`

`SetNull` is only allowed on nullable foreign-key fields.

Custom relation column renames are not supported. The Rust field name is the database column name.

## Validation

Generated `Create` and `Update` handlers can enforce field-level validation before SQL execution.

Derive example:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
pub struct Post {
    pub id: Option<i64>,
    #[validate(min_length = 3, max_length = 120)]
    pub title: String,
    #[validate(minimum = 1, maximum = 10)]
    pub score: i64,
}
```

`.eon` example:

```eon
{
    name: "Post"
    fields: [
        { name: "id", type: I64 }
        {
            name: "title"
            type: String
            validate: {
                min_length: 3
                max_length: 120
            }
        }
        {
            name: "score"
            type: I64
            validate: {
                minimum: 1
                maximum: 10
            }
        }
    ]
}
```

Supported constraints:

- `min_length` and `max_length` for string-like fields
- `minimum` and `maximum` for integer and floating-point fields

These constraints are reflected in generated OpenAPI schemas as `minLength`, `maxLength`,
`minimum`, and `maximum`.

## Error Responses

Generated resource handlers now use a stable JSON error body for validation and common CRUD
failures:

```json
{
  "code": "validation_error",
  "message": "Field `title` must have at least 3 characters",
  "field": "title"
}
```

The current resource-level envelope fields are:

- `code`
- `message`
- `field` for field-specific validation failures

Generated collection routes also accept typed query parameters:

- `limit` and `offset` for pagination
- `cursor=<token>` for keyset pagination
- `sort=<field>` and `order=asc|desc` for safe sorting
- `filter_<field>=...` for exact-match filtering on generated resource fields

Per-resource page defaults and caps can be configured from either generation path:

```rust
#[derive(RestApi)]
#[list(default_limit = 25, max_limit = 100)]
struct Post {
    id: Option<i64>,
    title: String,
}
```

```eon
resources: [
    {
        name: "Post"
        list: {
            default_limit: 25
            max_limit: 100
        }
        fields: [
            { name: "id", type: I64 }
            { name: "title", type: String }
        ]
    }
]
```

Collection responses now return a metadata envelope instead of a bare JSON array:

```json
{
  "items": [],
  "total": 0,
  "count": 0,
  "limit": 20,
  "offset": 0,
  "next_offset": null,
  "next_cursor": null
}
```

Unknown query keys, invalid typed values, and unsupported combinations such as `offset` without
`limit` return the same JSON error envelope with `invalid_query` or `invalid_pagination`. When a
resource has `max_limit` configured, oversized `limit` values are capped to that maximum rather
than rejected. Cursor tokens are opaque, URL-safe strings; they cannot be combined with `offset`,
`sort`, or `order`, because they already encode the current keyset position and sort direction.

OpenAPI documents expose this as `ApiErrorResponse` and use it for generated `400`, `403`, `404`,
and `500` resource responses where applicable. Built-in auth routes use the same envelope for
login failures, duplicate registration, and token/authentication failures.

Malformed JSON bodies now also use the same envelope, for example:

```json
{
  "code": "invalid_json",
  "message": "Request body is not valid JSON"
}
```

Invalid path and query parsing now use the same contract too, with codes like:

- `invalid_path`
- `invalid_query`

## EON Service Macro

You can also generate a typed REST module from a `.eon` file at compile time:

```rust
use very_simple_rest::prelude::*;

rest_api_from_eon!("tests/fixtures/blog_api.eon");

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    sqlx::any::install_default_drivers();
    let pool = AnyPool::connect("sqlite:app.db?mode=rwc").await.unwrap();

    HttpServer::new(move || {
        App::new().service(scope("/api").configure(|cfg| blog_api::configure(cfg, pool.clone())))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Minimal `.eon` schema:

```eon
resources: [
    {
        name: "Post"
        roles: {
            read: "user"
            create: "user"
            update: "user"
            delete: "user"
        }
        policies: {
            admin_bypass: false
            read: [
                "user_id=user.id"
                { field: "tenant_id", equals: "claim.tenant_id" }
            ]
            create: [
                "user_id=user.id"
                { field: "tenant_id", value: "claim.tenant_id" }
            ]
            update: [
                "user_id=user.id"
                { field: "tenant_id", equals: "claim.tenant_id" }
            ]
            delete: { field: "tenant_id", equals: "claim.tenant_id" }
        }
        fields: [
            { name: "id", type: I64 }
            { name: "title", type: String }
            { name: "content", type: String }
            { name: "user_id", type: I64 }
            { name: "created_at", type: String }
            { name: "updated_at", type: String }
        ]
    }
]
```

Relations in `.eon` support the same delete actions:

```eon
{
    name: "Comment"
    fields: [
        { name: "id", type: I64 }
        {
            name: "post_id"
            type: I64
            relation: {
                references: "post.id"
                nested_route: true
                on_delete: Cascade
            }
        }
        { name: "body", type: String }
    ]
}
```

This generates:

- `blog_api::Post`
- `blog_api::PostCreate`
- `blog_api::PostUpdate`
- `blog_api::configure`

The workspace uses the `eon` crate for parsing. For formatting `.eon` files, install the external formatter:

```sh
cargo install eonfmt
eonfmt path/to/api.eon
```

## Roadmap

- Support for all SQLx database backends
- More flexible role definitions
- Custom validation rules
- Richer OpenAPI response metadata and more detailed validation/error schemas

## Contributions

Contributions are welcome! Feel free to submit issues and pull requests.

## AI Assistance

This library has been built with assistance from OpenAI's o4 and Anthropic's Claude 3.5 Sonnet.

## License

MIT 
