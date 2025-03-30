use very_simple_rest::prelude::*;
use very_simple_rest::core;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

// User model with role-based access control
#[derive(Debug, Serialize, Deserialize, Clone, SqlTable)]
#[table(name = "user")]
pub struct User {
    #[column(primary_key)]
    pub id: Uuid,
    pub email: String,
    #[column(json)]
    pub roles: Vec<String>,
    #[column(excluded)]
    pub password: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Post model with user relationship
#[derive(Debug, Serialize, Deserialize, Clone, SqlTable)]
#[table(name = "post")]
pub struct Post {
    #[column(primary_key)]
    pub id: Uuid,
    pub title: String,
    pub content: String,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// User context for authentication
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserContext {
    pub user_id: Uuid,
    pub email: String,
    pub roles: Vec<String>,
}

// POST /api/auth/register
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

// POST /api/auth/login
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

// POST /api/post
#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePostRequest {
    pub title: String,
    pub content: String,
}

// Configure and start the application
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize environment variables and logging
    dotenvy::dotenv().ok();
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Initialize database
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = core::db::init_db_pool(&db_url).await?;

    // Create admin user if environment variables are set
    if let (Ok(email), Ok(password)) = (std::env::var("ADMIN_EMAIL"), std::env::var("ADMIN_PASSWORD")) {
        log::info!("Creating admin user from environment variables");
        let admin_id = Uuid::new_v4();
        let hashed_password = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
        
        sqlx::query(
            r#"
            INSERT INTO user (id, email, password, roles, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(email) DO NOTHING
            "#,
        )
        .bind(admin_id.to_string())
        .bind(&email)
        .bind(&hashed_password)
        .bind(serde_json::to_string(&vec!["admin", "user"])?)
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&pool)
        .await?;
    }

    // Create REST API
    let rest_api = RestApiBuilder::new()
        .with_db_pool(pool.clone())
        .with_jwt_secret(std::env::var("JWT_SECRET").expect("JWT_SECRET must be set"))
        .with_auth::<UserContext>()
        .with_cors(
            actix_cors::Cors::default()
                .allowed_origin_fn(|origin, _req_head| {
                    origin.as_bytes().starts_with(b"http://localhost")
                        || origin.as_bytes().starts_with(b"https://localhost")
                })
                .allow_any_method()
                .allow_any_header()
                .supports_credentials()
                .max_age(3600),
        )
        .build();

    // Register resources
    rest_api
        // User resource with authentication
        .resource::<User>()
        .auth_middleware()
        .register()
        .await?;

    // Post resource with authentication
    rest_api
        .resource::<Post>()
        .auth_middleware()
        .register()
        .await?;

    // Custom authentication routes
    rest_api
        .route("/api/auth/register")
        .post::<RegisterRequest, core::auth::TokenResponse>(register_handler)
        .register()
        .await?;

    rest_api
        .route("/api/auth/login")
        .post::<LoginRequest, core::auth::TokenResponse>(login_handler)
        .register()
        .await?;

    rest_api
        .route("/api/auth/me")
        .get::<(), User>(me_handler)
        .auth_middleware()
        .register()
        .await?;

    // Static file server for the front-end
    rest_api.serve_static_files("public");

    // Start the server
    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let address = format!("{}:{}", host, port);
    
    log::info!("Starting server at http://{}", address);
    rest_api.start(address).await?;

    Ok(())
}

// Handler for user registration
async fn register_handler(
    req: RegisterRequest,
    ctx: RouteContext<()>,
) -> core::Result<core::auth::TokenResponse> {
    let db = ctx.db_pool();
    let user_id = Uuid::new_v4();
    let hashed_password = bcrypt::hash(&req.password, bcrypt::DEFAULT_COST)?;
    let now = Utc::now();
    
    // Insert new user with 'user' role
    sqlx::query(
        r#"
        INSERT INTO user (id, email, password, roles, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(user_id.to_string())
    .bind(&req.email)
    .bind(&hashed_password)
    .bind(serde_json::to_string(&vec!["user"])?)
    .bind(now)
    .bind(now)
    .execute(db)
    .await?;

    // Generate JWT token
    let user_context = UserContext {
        user_id,
        email: req.email,
        roles: vec!["user".to_string()],
    };

    core::auth::generate_token(&user_context, &ctx.jwt_secret())
}

// Handler for user login
async fn login_handler(
    req: LoginRequest,
    ctx: RouteContext<()>,
) -> core::Result<core::auth::TokenResponse> {
    let db = ctx.db_pool();
    
    // Find user by email
    let user = sqlx::query_as::<_, User>(
        r#"SELECT * FROM user WHERE email = ?"#,
    )
    .bind(&req.email)
    .fetch_optional(db)
    .await?
    .ok_or_else(|| core::error::Error::Authentication("Invalid email or password".to_string()))?;

    // Verify password
    if !bcrypt::verify(&req.password, &user.password)? {
        return Err(core::error::Error::Authentication("Invalid email or password".to_string()));
    }

    // Generate JWT token
    let user_context = UserContext {
        user_id: user.id,
        email: user.email,
        roles: user.roles,
    };

    core::auth::generate_token(&user_context, &ctx.jwt_secret())
}

// Handler to get current user details
async fn me_handler(
    _req: (),
    ctx: RouteContext<UserContext>,
) -> core::Result<User> {
    let db = ctx.db_pool();
    let user_context = ctx.auth_context().ok_or_else(|| {
        core::error::Error::Authentication("Authentication required".to_string())
    })?;
    
    // Find user by ID
    let user = sqlx::query_as::<_, User>(
        r#"SELECT * FROM user WHERE id = ?"#,
    )
    .bind(user_context.user_id.to_string())
    .fetch_one(db)
    .await?;
    
    Ok(user)
} 