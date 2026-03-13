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
- JWT-based authentication with role management
- Role-Based Access Control (RBAC) for endpoint protection
- Relationship handling with nested routes and configurable relation delete actions
- Support for SQLite, PostgreSQL, and MySQL (via feature flags)

## Quick Start

```rust
use actix_web::{App, HttpServer, web};
use serde::{Deserialize, Serialize};
use sqlx::{AnyPool, FromRow};
use rest_api::prelude::*;

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
    sqlx::any::install_default_drivers();

    let pool = AnyPool::connect("sqlite:app.db?mode=rwc").await.unwrap();

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
`NoAction`; `SetNull` is rejected on non-nullable foreign-key fields.

Generated REST resources do not perform runtime schema creation. For `.eon` services, use the
`vsr migrate generate`, `vsr migrate check`, and `vsr migrate apply` commands to manage schema
explicitly.

For generated resource routes, `vsr openapi --input ... --output openapi.json` renders an OpenAPI
document, and `vsr server emit` projects serve that same document at `/openapi.json` with Swagger
UI at `/docs`. Add `--with-auth` when you also want the built-in auth/account routes in the
document. In Swagger, `/auth/register` and `/auth/login` appear under `Auth`, while `/auth/me`
appears under `Account`.

`.eon` services can also define `static.mounts` with `Directory` or `Spa` modes. Static
directories are resolved relative to the `.eon` file, reserved routes like `/api` and `/docs`
cannot be shadowed, and `vsr server emit` copies the declared static directories into the emitted
project automatically.

For the built-in auth schema, use `vsr migrate auth` before relying on `ensure_admin_exists` or
the `/auth/register` and `/auth/login` routes in a fresh database.

When `ensure_admin_exists` or the CLI admin bootstrap creates the first admin user, numeric auth
claim columns on `user` such as `tenant_id`, `org_id`, or `claim_workspace_id` can be supplied
through matching `ADMIN_<COLUMN_NAME>` environment variables.

For derive-based resources, use `vsr migrate derive --input src` and optionally
`--exclude-table user` when the built-in auth migration already owns that table.

For additive evolution between schema versions, `vsr migrate diff` emits only new tables, new
indexes, and safe nullable/defaulted columns; destructive changes remain manual by design.

For live drift checks, `vsr migrate inspect` compares the current database to a schema source and
reports mismatches in columns, indexes, foreign keys, and `ON DELETE` actions without generating
SQL.

## JWT Secret Configuration

The library supports the following methods for setting the JWT secret (in order of precedence):

1. Environment variable: `JWT_SECRET=your_secret_here`
2. `.env` file in your project root: `JWT_SECRET=your_secret_here`
3. If no secret is provided, a random secret is generated at startup (not recommended for production)

For production environments, it's strongly recommended to set a persistent secret using one of the first two methods.

The built-in auth login route will also emit numeric claims automatically from `user` table
columns such as `tenant_id`, `org_id`, or `claim_workspace_id`.
*/

extern crate self as very_simple_rest;

pub use rest_macro::{RestApi, rest_api_eon, rest_api_from_eon};
pub use rest_macro_core as core;

pub mod auth {
    pub use rest_macro_core::auth::{
        LoginInput, RegisterInput, User, UserContext, auth_routes, ensure_admin_exists, login, me,
        register,
    };
}

pub use actix_cors;
pub use actix_files;
pub use actix_web;
pub use env_logger;
pub use log;
pub use serde;
pub use sqlx;

pub mod prelude {
    pub use crate::auth;
    pub use crate::auth::UserContext;
    pub use crate::core;
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
    pub use serde::{Deserialize, Serialize};
    pub use sqlx::{AnyPool, FromRow};
}
