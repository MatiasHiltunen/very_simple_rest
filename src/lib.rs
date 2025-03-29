/*!
# REST API Library

A declarative library for building REST APIs with Actix Web and SQLx.

## Overview

This library provides a high-level, opinionated approach to creating REST APIs in Rust.
With just a few derive macros, you can generate complete CRUD endpoints with authentication,
authorization, and relationship handling.

## Features

- Zero-boilerplate REST APIs with a single derive macro
- JWT-based authentication with role management
- Role-Based Access Control (RBAC) for endpoint protection
- Automatic database schema generation
- Relationship handling with nested routes
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

## JWT Secret Configuration

The library supports the following methods for setting the JWT secret (in order of precedence):

1. Environment variable: `JWT_SECRET=your_secret_here`
2. `.env` file in your project root: `JWT_SECRET=your_secret_here`
3. If no secret is provided, a random secret is generated at startup (not recommended for production)

For production environments, it's strongly recommended to set a persistent secret using one of the first two methods.
*/

// Re-export the RestApi derive macro
pub use rest_macro::RestApi;

// Re-export core module to make it available to the macro implementation
pub use rest_macro_core as core;

// Re-export authentication module with improved type organization
pub mod auth {
    pub use rest_macro_core::auth::{
        auth_routes, 
        me, 
        login, 
        register, 
        UserContext, 
        User,
        RegisterInput, 
        LoginInput
    };
}

/// A convenience module that re-exports all the common types
pub mod prelude {
    pub use crate::RestApi;
    pub use crate::auth;
    pub use crate::auth::UserContext;
    // Also make core module available to users
    pub use crate::core;
} 