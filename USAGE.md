# Using REST Macro in Your Project

This guide shows how to use the REST API macro library in your own projects, either from the published crate on crates.io or directly from a Git repository.

## Adding the Dependency

### From crates.io (Recommended)

Add the following to your `Cargo.toml`:

```toml
[dependencies]
rest_api = "0.1.0"
```

### From Git Repository

```toml
[dependencies]
rest_api = { git = "https://github.com/yourusername/rest_macro" }
```

## Basic Usage

The library is designed to be simple to use with a single import and derive macro:

```rust
use actix_web::{App, HttpServer, web};
use serde::{Deserialize, Serialize};
use sqlx::{AnyPool, FromRow};
use rest_api::prelude::*;

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

For secure authentication, configure the JWT secret using one of these methods:

1. Environment variable: `JWT_SECRET=your_secret_here`
2. `.env` file in your project root: `JWT_SECRET=your_secret_here`
3. If no secret is provided, a random secret is generated at startup (not recommended for production)

For production environments, always set a secure, persistent secret.

## Database Support

Choose your database backend using feature flags:

```toml
[dependencies]
rest_api = { version = "0.1.0", features = ["postgres"] }
```

Available features:
- `sqlite` (default)
- `postgres`
- `mysql`

## Complete Documentation

For more detailed usage instructions, see the [main README](README.md) and the [demo example](examples/demo/README.md). 