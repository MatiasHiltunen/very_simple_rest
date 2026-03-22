/*!
# REST API Library

A declarative library for building REST APIs with Actix Web and SQLx.

## Overview

This library provides a high-level, opinionated approach to creating REST APIs in Rust.
With just a few derive macros, you can generate complete CRUD endpoints with authentication,
authorization, and relationship handling.

## Features

- Zero-boilerplate REST APIs with a single derive macro
- Typed `Create` / `Update` DTO generation for derive and `.eon` resources
- Explicit SQL migration generation for `.eon` services
- Field-level validation for generated `Create` / `Update` handlers and OpenAPI schemas
- Stable JSON error responses for generated resource handlers
- Typed list query params and paged response envelopes for generated collection routes (`limit`,
  `offset`, `cursor`, `sort`, `order`, and `filter_<field>`)
- JWT-based authentication with role management
- Role-Based Access Control (RBAC) for endpoint protection
- Relationship handling with nested routes and configurable relation delete actions
- Support for SQLite, PostgreSQL, and MySQL (via feature flags)

## Quick Start

```no_run
use very_simple_rest::prelude::*;

// Define your data models with RBAC
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = connect("sqlite:app.db?mode=rwc").await.unwrap();

    // Apply migrations before starting the server in production.
    HttpServer::new(move || {
        App::new()
            .service(
                web::scope("/api")
                    .configure(|cfg| auth::auth_routes(cfg, pool.clone()))
                    .configure(|cfg| Post::configure(cfg, pool.clone()))
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

## EON Macro

The crate also exposes `rest_api_from_eon!` and `rest_api_eon!` for compile-time generation from
minimal `.eon` service definitions. The generated module includes resource structs, `Create` and
`Update` DTOs, a module-level `configure` function, a matching `configure_static` hook for
service-level static mounts, and optional portable row policies based on `user.id` and JWT
claims. Relations can also declare `on_delete` as `Cascade`, `Restrict`, `SetNull`, or
`NoAction`; `SetNull` is rejected on non-nullable foreign-key fields. Custom relation column
renames are not supported; relation fields map to columns with the same name.

Field validations can be declared with `#[validate(...)]` on derive-based resources or
`validate: { ... }` in `.eon` fields. The current supported keys are `min_length`,
`max_length`, `minimum`, and `maximum`, and the generated OpenAPI schema mirrors them as
`minLength`, `maxLength`, `minimum`, and `maximum`.

Generated resource handlers also use a stable JSON error body with `code`, `message`, and an
optional `field`. OpenAPI documents expose this schema as `ApiErrorResponse` for generated
resource `400`, `403`, `404`, and `500` responses. Built-in auth routes also use the same JSON
envelope for invalid credentials, duplicate registration, malformed JSON bodies, and missing or
invalid bearer tokens. Path and query extraction failures now also map to the same envelope with
codes such as `invalid_path` and `invalid_query`.

Generated collection and nested collection routes also accept typed query parameters for
pagination, sorting, and exact-match field filters. OpenAPI documents expose those parameters in
`/docs`, and invalid values such as `limit=abc` or `sort=missing_field` resolve through the same
JSON error envelope. Those list routes now return an envelope with `items`, `total`, `count`,
`limit`, `offset`, `next_offset`, and `next_cursor` instead of a bare array. They also support
opaque cursor tokens for keyset pagination. You can configure per-resource page defaults and caps
with `#[list(default_limit = 25, max_limit = 100)]` on derive-based resources or
`list: { default_limit: 25 max_limit: 100 }` in `.eon`; oversized `limit` values are capped to
`max_limit`.

Generated REST resources do not perform runtime schema creation. For `.eon` services, use the
`vsr migrate generate`, `vsr migrate check`, and `vsr migrate apply` commands to manage schema
explicitly.

For generated resource routes, `vsr openapi --input ... --output openapi.json` renders an OpenAPI
document, and `vsr server emit` projects serve that same document at `/openapi.json` with Swagger
UI at `/docs`. Built-in auth/account routes are included by default; add `--without-auth` to omit
them when your service owns the `user` model. In Swagger, `/auth/register` and `/auth/login`
appear under `Auth`, while `/auth/me` appears under `Account`.

`.eon` services can also define `static.mounts` with `Directory` or `Spa` modes. Static
directories are resolved relative to the `.eon` file, reserved routes like `/api` and `/docs`
cannot be shadowed, and `vsr server emit` copies the declared static directories into the emitted
project automatically.

SQLite `.eon` services now default to `database.engine = TursoLocal`, using a per-service
`var/data/<module>.db` path unless you override it explicitly. You can still opt back into the
legacy runtime path with `database.engine.kind = Sqlx`. `TursoLocal` bootstraps a local Turso
database file before the emitted server connects through the project runtime's database adapter
while keeping the SQL dialect as SQLite. `TursoLocal` can also carry `encryption_key_env`, which
is read from the environment as a hex key for local Turso bootstrap and encrypted local database
access.

`.eon` services can also define service-level `logging`, `runtime`, and `security` defaults.
Logging controls the emitted server's filter env var, default filter, and timestamp precision
through `module::logging()`. `runtime` exposes compression defaults through `module::runtime()`;
emitted servers now apply dynamic HTTP response compression from `runtime.compression.enabled`,
manual apps can use `core::runtime::compression_middleware(&module::runtime())`, and generated
static mounts can serve `.br` and `.gz` companion assets when
`runtime.compression.static_precompressed` is enabled. `security`
covers JSON body limits, CORS, trusted-proxy handling, auth rate limits, security headers, and
built-in auth token settings through `module::security()` and `module::configure_security(...)`.
Generated modules also expose the compiled authorization model through `module::authorization()`,
which is useful when building custom diagnostics or runtime-managed policy APIs on top of the
static `.eon` contract. They also expose `module::authorization_runtime(db)` and register that
runtime service as Actix app data from `module::configure(...)`, so custom handlers can load,
persist, and simulate scoped assignments through one shared runtime object. For a basic opt-in
runtime assignment API, generated modules also expose
`module::configure_authorization_management(cfg, db)`, including a request-time runtime access
evaluation endpoint for explicit `resource + action + scope` checks. Custom handlers can also call
`AuthorizationRuntime::enforce_runtime_access(...)` for real request-time runtime permission
enforcement.
Secrets such as `JWT_SECRET` still belong in the environment.

For the built-in auth schema, use `vsr migrate auth` before relying on `ensure_admin_exists` or
the `/auth/register` and `/auth/login` routes in a fresh database.

When `ensure_admin_exists` or the CLI admin bootstrap creates the first admin user, numeric auth
claim columns on `user` such as `tenant_id`, `org_id`, or `claim_workspace_id` can be supplied
through matching `ADMIN_<COLUMN_NAME>` environment variables.
When your app uses explicit `AuthSettings`, call `ensure_admin_exists_with_settings` so the admin
bootstrap path honors configured `security.auth.claims` mappings too.

For derive-based resources, use `vsr migrate derive --input src` and optionally
`--exclude-table user` when the built-in auth migration already owns that table.

For additive evolution between schema versions, `vsr migrate diff` emits only new tables, new
indexes, and safe nullable/defaulted columns; destructive changes remain manual by design.

For live drift checks, `vsr migrate inspect` compares the current database to a schema source and
reports mismatches in columns, indexes, foreign keys, and `ON DELETE` actions without generating
SQL.

## JWT Secret Configuration

Built-in auth requires `JWT_SECRET` to be set, either through the environment or a `.env` file
in your project root. The runtime now fails closed instead of generating a random secret at
startup, so tokens remain stable across restarts and multi-instance deployments.

The built-in auth login route will also emit numeric claims automatically from `user` table
columns such as `tenant_id`, `org_id`, or `claim_workspace_id`.
*/

extern crate self as very_simple_rest;

pub use rest_macro::{RestApi, rest_api_eon, rest_api_from_eon};
pub use rest_macro_core as core;

pub mod auth {
    pub use rest_macro_core::auth::{
        AccountInfo, AuthEmailProvider, AuthEmailSettings, AuthSettings, AuthUiPageSettings,
        ChangePasswordInput, CreateManagedUserInput, LoginInput, PasswordResetConfirmInput,
        PasswordResetRequestInput, RegisterInput, SessionCookieSameSite, SessionCookieSettings,
        UpdateManagedUserInput, User, UserContext, VerificationResendInput, VerifyEmailInput,
        account, auth_routes, auth_routes_with_settings, change_password, confirm_password_reset,
        create_managed_user, delete_managed_user, ensure_admin_exists,
        ensure_admin_exists_with_settings, ensure_jwt_secret_configured, list_managed_users, login,
        login_with_request, logout, managed_user, me, register, request_password_reset,
        resend_account_verification, resend_managed_user_verification, resend_verification,
        update_managed_user, validate_auth_claim_mappings, verify_email_page, verify_email_token,
    };
}

pub mod authorization {
    pub use rest_macro_core::authorization::{
        AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE, ActionAuthorization, AuthorizationAction,
        AuthorizationAssignment, AuthorizationAssignmentTrace, AuthorizationCondition,
        AuthorizationConditionTrace, AuthorizationContract, AuthorizationMatch, AuthorizationModel,
        AuthorizationOperator, AuthorizationOutcome, AuthorizationPermission, AuthorizationRuntime,
        AuthorizationRuntimeAccessInput, AuthorizationRuntimeAccessResult, AuthorizationScope,
        AuthorizationScopeBinding, AuthorizationScopedAssignment,
        AuthorizationScopedAssignmentCreateInput, AuthorizationScopedAssignmentListQuery,
        AuthorizationScopedAssignmentRecord, AuthorizationScopedAssignmentTarget,
        AuthorizationScopedAssignmentTrace, AuthorizationSimulationInput,
        AuthorizationSimulationResult, AuthorizationTemplate, AuthorizationValueSource,
        ResourceAuthorization, authorization_management_routes,
        authorization_runtime_migration_sql, delete_runtime_assignment, insert_runtime_assignment,
        list_runtime_assignments_for_user, load_runtime_assignments_for_user,
        new_runtime_assignment_id,
    };
}

pub mod database {
    pub use rest_macro_core::database::{
        DatabaseConfig, DatabaseEngine, TursoLocalConfig, prepare_database_engine,
        sqlite_url_for_path,
    };
}

pub mod db {
    pub use rest_macro_core::db::{
        DbPool, DbQueryResult, DbTransaction, IntoDbValue, connect, connect_with_config, query,
        query_as, query_scalar,
    };
}

pub mod logging {
    pub use rest_macro_core::logging::{LogTimestampPrecision, LoggingConfig};
}

pub mod runtime {
    pub use rest_macro_core::runtime::{CompressionConfig, RuntimeConfig};
}

pub mod tls {
    pub use rest_macro_core::tls::{
        DEFAULT_TLS_CERT_PATH, DEFAULT_TLS_CERT_PATH_ENV, DEFAULT_TLS_KEY_PATH,
        DEFAULT_TLS_KEY_PATH_ENV, ResolvedTlsPaths, TlsConfig, load_rustls_server_config,
        resolve_tls_config,
    };
}

pub use actix_cors;
pub use actix_files;
pub use actix_web;
pub use base64;
pub use chrono;
pub use env_logger;
pub use log;
pub use rust_decimal;
pub use serde;
pub use serde_json;
pub use sqlx;
pub use uuid;

pub mod prelude {
    pub use crate::auth;
    pub use crate::auth::{AuthSettings, UserContext};
    pub use crate::authorization;
    pub use crate::core;
    pub use crate::database;
    pub use crate::db;
    pub use crate::logging;
    pub use crate::runtime;
    pub use crate::tls;
    pub use crate::{RestApi, rest_api_eon, rest_api_from_eon};

    pub use actix_web::{
        App, HttpResponse, HttpServer, Responder,
        middleware::{DefaultHeaders, Logger},
        web::{self, scope},
    };

    pub use actix_cors::Cors;
    pub use actix_files as fs;
    pub use env_logger::Env;
    pub use log::{debug, error, info, trace, warn};
    pub use rest_macro_core::db::{
        DbPool, connect, connect_with_config, query, query_as, query_scalar,
    };
    pub use serde::{Deserialize, Serialize};
    pub use sqlx::{AnyPool, FromRow};
}
