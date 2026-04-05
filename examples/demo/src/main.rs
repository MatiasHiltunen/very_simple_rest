use std::env;

use very_simple_rest::prelude::*;

const DEFAULT_DB_PATH: &str = "var/data/demo.db";
const PUBLIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/public");

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

fn database_config() -> database::DatabaseConfig {
    database::DatabaseConfig {
        engine: database::DatabaseEngine::TursoLocal(database::TursoLocalConfig {
            path: DEFAULT_DB_PATH.to_owned(),
            encryption_key: env::var_os("TURSO_ENCRYPTION_KEY")
                .map(|_| very_simple_rest::core::secret::SecretRef::env_or_file("TURSO_ENCRYPTION_KEY")),
        }),
        resilience: None,
    }
}

fn default_database_url(config: &database::DatabaseConfig) -> String {
    match &config.engine {
        database::DatabaseEngine::TursoLocal(engine) => database::sqlite_url_for_path(&engine.path),
        database::DatabaseEngine::Sqlx => "sqlite:app.db?mode=rwc".to_owned(),
    }
}

fn security_config() -> core::security::SecurityConfig {
    core::security::SecurityConfig {
        requests: core::security::RequestSecurity {
            json_max_bytes: Some(262_144),
        },
        cors: core::security::CorsSecurity {
            origins: vec!["http://127.0.0.1:8080".to_owned()],
            origins_env: Some("CORS_ORIGINS".to_owned()),
            allow_credentials: true,
            allow_methods: vec![
                "GET".to_owned(),
                "POST".to_owned(),
                "PUT".to_owned(),
                "PATCH".to_owned(),
                "DELETE".to_owned(),
                "OPTIONS".to_owned(),
            ],
            allow_headers: vec![
                "authorization".to_owned(),
                "content-type".to_owned(),
                "accept".to_owned(),
            ],
            expose_headers: vec!["x-total-count".to_owned()],
            max_age_seconds: Some(600),
        },
        trusted_proxies: core::security::TrustedProxySecurity {
            proxies: vec!["127.0.0.1".to_owned(), "::1".to_owned()],
            proxies_env: Some("TRUSTED_PROXIES".to_owned()),
        },
        rate_limits: core::security::RateLimitSecurity {
            login: Some(core::security::RateLimitRule {
                requests: 10,
                window_seconds: 60,
            }),
            register: Some(core::security::RateLimitRule {
                requests: 5,
                window_seconds: 300,
            }),
        },
        headers: core::security::HeaderSecurity {
            frame_options: Some(core::security::FrameOptions::Deny),
            content_type_options: true,
            referrer_policy: Some(core::security::ReferrerPolicy::StrictOriginWhenCrossOrigin),
            hsts: None,
        },
        auth: auth::AuthSettings {
            issuer: Some("very_simple_rest_demo".to_owned()),
            audience: Some("demo-clients".to_owned()),
            access_token_ttl_seconds: 3600,
            session_cookie: None,
            ..auth::AuthSettings::default()
        },
    }
}

fn log_available_endpoints(bind_addr: &str) {
    let id = "1";
    info!("===== Available API Endpoints =====");
    info!("Database engine: TursoLocal ({DEFAULT_DB_PATH})");
    info!(
        "Security defaults: auth rate limits, CORS env override (CORS_ORIGINS), trusted proxies (TRUSTED_PROXIES), and response headers"
    );
    info!("Authentication:");
    info!("  POST   /api/auth/register   - Register a new user");
    info!("  POST   /api/auth/login      - Login and get a JWT token");
    info!("  GET    /api/auth/me         - Get authenticated user info and numeric claims");
    info!("Users (requires admin role):");
    info!("  GET    /api/user");
    info!("  GET    /api/user/{id}");
    info!("  POST   /api/user");
    info!("  PUT    /api/user/{id}");
    info!("  DELETE /api/user/{id}");
    info!("Posts (requires user role):");
    info!("  GET    /api/post");
    info!("  GET    /api/post/{id}");
    info!("  POST   /api/post");
    info!("  PUT    /api/post/{id}");
    info!("  DELETE /api/post/{id}");
    info!("Comments (requires user role):");
    info!("  GET    /api/comment");
    info!("  GET    /api/comment/{id}");
    info!("  POST   /api/comment");
    info!("  PUT    /api/comment/{id}");
    info!("  DELETE /api/comment/{id}");
    info!("  GET    /api/post/{id}/comment");
    info!("Frontend: http://{bind_addr}");
    info!("=====================================");
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let _ = dotenv::dotenv();
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let database_config = database_config();
    let database_url = match env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            database::prepare_database_engine(&database_config)
                .await
                .map_err(|error| {
                    std::io::Error::other(format!("database bootstrap failed: {error}"))
                })?;
            default_database_url(&database_config)
        }
    };
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let security = security_config();

    info!("Initializing REST API server...");
    info!("Connecting to database at {database_url}...");
    let pool = connect_with_config(&database_url, &database_config)
        .await
        .map_err(|error| std::io::Error::other(format!("database connection failed: {error}")))?;
    info!("Database connection established");

    let server_pool = pool.clone();
    let server_security = security.clone();
    let server = HttpServer::new(move || {
        let security = server_security.clone();
        App::new()
            .wrap(Logger::default())
            .wrap(core::security::cors_middleware(&security))
            .wrap(core::security::security_headers_middleware(&security))
            .service(
                scope("/api")
                    .configure(|cfg| core::security::configure_scope_security(cfg, &security))
                    .configure(|cfg| {
                        auth::auth_routes_with_settings(
                            cfg,
                            server_pool.clone(),
                            security.auth.clone(),
                        )
                    })
                    .configure(|cfg| User::configure(cfg, server_pool.clone()))
                    .configure(|cfg| Post::configure(cfg, server_pool.clone()))
                    .configure(|cfg| Comment::configure(cfg, server_pool.clone())),
            )
            .service(fs::Files::new("/", PUBLIC_DIR).index_file("index.html"))
    })
    .bind(&bind_addr)?;

    info!("Checking for admin user...");
    match auth::ensure_admin_exists_with_settings(&pool, &security.auth).await {
        Ok(true) => info!("Admin user is ready for login"),
        Ok(false) => {
            error!("Failed to create admin user - shutting down");
            return Ok(());
        }
        Err(error) => {
            error!("Database error when checking/creating admin user: {error} - shutting down");
            return Ok(());
        }
    }

    log_available_endpoints(&bind_addr);
    info!("Server starting at http://{bind_addr}");
    server.run().await
}
