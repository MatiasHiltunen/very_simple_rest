use actix_web::{App, HttpServer, middleware::Logger};
use serde::{Deserialize, Serialize};
use sqlx::{AnyPool, FromRow};
use rest_macro::RestApi;
use rest_macro_core::auth;
use log::{info, warn, debug, LevelFilter};
use env_logger::Env;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
#[rest_api(table = "posts", id = "id", db = "sqlite")]
#[require_role(read = "user", update = "user", delete = "user")]
pub struct Post {
    pub id: Option<i64>,
    pub title: String,
    pub content: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
#[rest_api(table = "comments", id = "id", db = "sqlite")]
#[require_role(read = "user", update = "user", delete = "user")]
pub struct Comment {
    pub id: Option<i64>,
    pub title: String,
    pub content: String,
    #[relation(foreign_key = "post_id", references = "posts.id", nested_route = "true")]
    pub post_id: i64,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}



#[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
#[rest_api(table = "users", id = "id", db = "sqlite")]
#[require_role(read = "admin", update = "admin", delete = "admin")]
pub struct User {
    pub id: Option<i64>,
    pub email: String,
    pub password_hash: String,
    pub role: String,
}

fn log_available_endpoints() {

    let id = "1";
    info!("===== Available API Endpoints =====");
    
    // Auth endpoints
    info!("Authentication:");
    info!("  POST   /auth/register  - Register a new user");
    info!("  POST   /auth/login     - Login and get a JWT token");
    info!("  GET    /auth/me        - Get authenticated user info");
    
    // User endpoints
    info!("Users (requires admin role):");
    info!("  GET    /users          - Get all users");
    info!("  GET    /users/{id}     - Get user by ID");
    info!("  POST   /users          - Create a new user");
    info!("  PUT    /users/{id}     - Update user");
    info!("  DELETE /users/{id}     - Delete user");
    
    // Post endpoints
    info!("Posts (requires user role):");
    info!("  GET    /posts          - Get all posts");
    info!("  GET    /posts/{id}     - Get post by ID");
    info!("  POST   /posts          - Create a new post");
    info!("  PUT    /posts/{id}     - Update post");
    info!("  DELETE /posts/{id}     - Delete post");
    
    // Comment endpoints
    info!("Comments (requires user role):");
    info!("  GET    /comments         - Get all comments");
    info!("  GET    /comments/{id}    - Get comment by ID");
    info!("  POST   /comments         - Create a new comment");
    info!("  PUT    /comments/{id}    - Update comment");
    info!("  DELETE /comments/{id}    - Delete comment");
    info!("  GET    /posts/{id}/comments - Get comments for a post");
    
    info!("=====================================");
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();
    
    info!("Initializing REST API server...");
    
    sqlx::any::install_default_drivers();
    
    info!("Connecting to database...");
    let pool = AnyPool::connect("sqlite:app.db?mode=rwc").await.unwrap();
    info!("Database connection established");
    
    // Tables will be automatically created by the RestApi macro
    info!("Tables will be created automatically by the RestApi macro");
    
    // Log available endpoints
    log_available_endpoints();
    
    let server = HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .configure(|cfg| auth::auth_routes(cfg, pool.clone()))
            .configure(|cfg| User::configure(cfg, pool.clone()))
            .configure(|cfg| Post::configure(cfg, pool.clone()))
            .configure(|cfg| Comment::configure(cfg, pool.clone()))
    })
    .bind(("127.0.0.1", 8080))?;
    
    info!("Server starting at http://127.0.0.1:8080");
    server.run().await
}
