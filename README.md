# REST Macro - Opinionated API Builder

> **Note**: This project is currently very much in progress and under active development. APIs will change, and features are incomplete.

A Rust library providing an opinionated higher-level macro wrapper for Actix Web and SQLx, designed for rapid API prototyping.

## Features

- **Zero-boilerplate REST APIs**: Create complete CRUD endpoints with a single derive macro
- **Built-in authentication**: JWT-based authentication with role management
- **Role-Based Access Control**: Declarative protection for your endpoints with role requirements
- **Automatic Schema Generation**: Tables are created based on your Rust structs
- **Database Agnostic**: Currently defaults to SQLite, with plans to support all SQLx targets
- **Relationship Handling**: Define foreign keys and nested routes between resources

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
    #[relation(foreign_key = "post_id", references = "post.id", nested_route = "true")]
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

    // Start server
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
- **GET /api/auth/me** - Get information about the authenticated user

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

## RBAC Attributes

Protect your endpoints with declarative role requirements:

```rust
#[require_role(read = "user", update = "admin", delete = "admin")]
```

This will:
- Allow users with the "user" role to read data
- Restrict update/delete operations to users with the "admin" role
- Return 403 Forbidden if the user lacks the required role

## Relationships

Define relationships between entities:

```rust
#[relation(foreign_key = "post_id", references = "post.id", nested_route = "true")]
pub post_id: i64,
```

This generates nested routes like `/api/post/{post_id}/comment` automatically.

## Roadmap

- Support for all SQLx database backends
- More flexible role definitions
- Custom validation rules
- Swagger/OpenAPI documentation generation

## Contributions

Contributions are welcome! Feel free to submit issues and pull requests.

## AI Assistance

This library has been built with assistance from OpenAI's o4 and Anthropic's Claude 3.5 Sonnet.

## License

MIT 