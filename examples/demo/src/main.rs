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

fn log_available_endpoints() {
    let id = "1";
    info!("===== Available API Endpoints =====");

    // Auth endpoints
    info!("Authentication:");
    info!("  POST   /api/auth/register  - Register a new user");
    info!("  POST   /api/auth/login     - Login and get a JWT token");
    info!("  GET    /api/auth/me        - Get authenticated user info");

    // User endpoints
    info!("Users (requires admin role):");
    info!("  GET    /api/user          - Get all users");
    info!("  GET    /api/user/{id}     - Get user by ID");
    info!("  POST   /api/user          - Create a new user");
    info!("  PUT    /api/user/{id}     - Update user");
    info!("  DELETE /api/user/{id}     - Delete user");

    // Post endpoints
    info!("Posts (requires user role):");
    info!("  GET    /api/post          - Get all posts");
    info!("  GET    /api/post/{id}     - Get post by ID");
    info!("  POST   /api/post          - Create a new post");
    info!("  PUT    /api/post/{id}     - Update post");
    info!("  DELETE /api/post/{id}     - Delete post");

    // Comment endpoints
    info!("Comments (requires user role):");
    info!("  GET    /api/comment         - Get all comments");
    info!("  GET    /api/comment/{id}    - Get comment by ID");
    info!("  POST   /api/comment         - Create a new comment");
    info!("  PUT    /api/comment/{id}    - Update comment");
    info!("  DELETE /api/comment/{id}    - Delete comment");
    info!("  GET    /api/post/{id}/comment - Get comments for a post");

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
    info!("Configuring server with automatic table creation...");

    let server_pool = pool.clone();
    let server = HttpServer::new(move || {
        // Configure CORS for frontend
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .wrap(DefaultHeaders::new().add(("X-Version", "0.1.0")))
            // Api routes
            .service(
                scope("/api")
                    .configure(|cfg| auth::auth_routes(cfg, server_pool.clone()))
                    .configure(|cfg| User::configure(cfg, server_pool.clone()))
                    .configure(|cfg| Post::configure(cfg, server_pool.clone()))
                    .configure(|cfg| Comment::configure(cfg, server_pool.clone())),
            )
            // Serve static files from the public directory
            .service(fs::Files::new("/", "examples/demo/public").index_file("index.html"))
    })
    .bind(("127.0.0.1", 8080))?;

    // Check for admin user or create one interactively if needed
    info!("Checking for admin user...");
    match auth::ensure_admin_exists(&pool).await {
        Ok(true) => info!("Admin user is ready for login"),
        Ok(false) => {
            error!("Failed to create admin user - shutting down");
            return Ok(());
        }
        Err(e) => {
            error!(
                "Database error when checking/creating admin user: {} - shutting down",
                e
            );
            return Ok(());
        }
    }

    // Log available endpoints
    log_available_endpoints();

    info!("Server starting at http://127.0.0.1:8080");
    server.run().await
}
