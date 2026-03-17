# REST Macro - Opinionated API Builder

> **Note**: This project is currently very much in progress and under active development. APIs will change, and features are incomplete.

A Rust library providing an opinionated higher-level macro wrapper for Actix Web and SQLx, designed for rapid API prototyping.

## Features

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

## Examples


The code includes example project `demo`. To run it, clone the repo and run from project's root:

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
inspects the live `user` table and also populates numeric claim columns such as `tenant_id`,
`org_id`, or `claim_workspace_id`. Interactive flows prompt for those values, and non-interactive
flows accept environment variables named `ADMIN_<COLUMN_NAME>`, such as `ADMIN_TENANT_ID=1`.

### JWT Secret Configuration

The library supports the following methods for setting the JWT secret (in order of precedence):

1. Environment variable: `JWT_SECRET=your_secret_here`
2. `.env` file in your project root: `JWT_SECRET=your_secret_here`
3. If no secret is provided, a random secret is generated at startup (not recommended for production)

For production environments, it's strongly recommended to set a persistent secret using one of the first two methods.

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
`ADMIN_<COLUMN_NAME>` variables and stores them on the admin row too.

### 2. CLI Tool (Interactive)

The library includes a CLI tool for managing your API, with specific commands for user management:

```bash
# Generate a migration for the built-in auth schema
vsr migrate auth --output migrations/0000_auth.sql

# Emit a standalone Rust server project from a bare .eon service
vsr server emit --input api.eon --output-dir generated-api

# Build a server binary directly from a bare .eon service
vsr server build --input api.eon --output dist/api-server --release

# Setup wizard with interactive prompts
vsr setup

# Create an admin user
vsr create-admin

# Create an admin with specific credentials
vsr create-admin --email admin@example.com --password securepassword

# Check database status including admin users
vsr check-db

# Generate a .env template file
vsr gen-env
```

The CLI tool provides a secure way to set up admin users with password confirmation and validation.

For detailed instructions on using the CLI tool, see the [CLI Tool Documentation](crates/rest_api_cli/README.md).

## Server Generation

The CLI can also turn a bare `.eon` service definition into a runnable Actix server project or a
compiled binary:

```bash
# Generate a local Rust project you can inspect and edit
vsr server emit --input tests/fixtures/blog_api.eon --output-dir generated-api

# Build a binary directly from the same .eon file
vsr server build --input tests/fixtures/blog_api.eon --output dist/blog-api --release
```

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

`vsr server build` also exports the generated runtime assets next to the binary in
`<binary>.bundle/`, including `.env.example`, `openapi.json`, the copied `.eon` file,
`README.md`, and `migrations/`.

Generated server projects serve the OpenAPI document at `/openapi.json` and a Swagger UI page at
`/docs`.

When a `.eon` service defines static mounts, `vsr server emit` also copies those directories into
the generated project so the emitted server can serve them without extra setup.

When a `.eon` service defines `security`, `vsr server emit` also applies the compiled JSON body
limits, CORS policy, trusted-proxy handling, auth rate limits, security headers, and built-in
auth token settings automatically in the emitted server.

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

## Migrations

Generated REST resources no longer run `CREATE TABLE IF NOT EXISTS` at startup. For `.eon`
services, generate explicit SQL and apply it before serving traffic:

```bash
# Generate the built-in auth migration
vsr migrate auth --output migrations/0000_auth.sql

# Generate migrations from Rust `#[derive(RestApi)]` resources
vsr migrate derive --input src --exclude-table user --output migrations/0001_resources.sql

# Generate an additive migration between two schema versions
vsr migrate diff --from schema_v1.eon --to schema_v2.eon --output migrations/0002_additive.sql

# Inspect a live database against a schema source
vsr --database-url sqlite:app.db?mode=rwc migrate inspect --input src --exclude-table user

# Generate a deterministic migration file from a .eon service
vsr migrate generate --input tests/fixtures/blog_api.eon --output migrations/0001_init.sql

# Verify that the checked-in SQL still matches the .eon schema
vsr migrate check --input tests/fixtures/blog_api.eon --output migrations/0001_init.sql

# Apply migrations to the configured database
vsr --database-url sqlite:app.db?mode=rwc migrate apply --dir migrations

# Or derive the database URL from a bare .eon service, including TursoLocal paths
vsr --config tests/fixtures/turso_local_api.eon migrate apply --dir migrations
```

The generated SQL includes:

- `CREATE TABLE` statements for each resource
- Foreign keys for declared relations
- Indexes for relation fields and row-policy fields

Built-in auth now has the same explicit schema path:

- `vsr migrate auth` generates the `user` table migration
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

For a minimal `.eon`-only app with built-in auth, owner-scoped todos, admin visibility across all
rows, and a static browser client, see `examples/todo_app/`.

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

When you use the built-in auth routes, `/auth/login` now emits numeric claims automatically from
the `user` row:

- Any numeric column ending in `_id` becomes a claim with the same name, such as `tenant_id` or `org_id`
- Any numeric column named `claim_<name>` becomes a claim named `<name>`

That lets claim-scoped policies work without a custom token issuer, as long as your user records
carry the relevant columns.

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
