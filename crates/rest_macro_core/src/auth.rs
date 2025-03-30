use actix_web::{web, Responder, HttpResponse};
use actix_web::{FromRequest, HttpRequest};
use actix_web::dev::Payload;
use serde::{Serialize, Deserialize};
use std::future::{ready, Ready};
use sqlx::{FromRow, AnyPool};
use jsonwebtoken::{encode, decode, EncodingKey, DecodingKey, Header, Validation};
use chrono::{Utc, Duration};
use bcrypt::{hash, verify};
use dotenv::dotenv;
use std::env;
use rand::{rng, Rng};
use rand::distr::Alphanumeric;
use std::sync::OnceLock;

// Function to get JWT secret from environment or generate a random one
fn get_jwt_secret() -> &'static [u8] {
    static JWT_SECRET: OnceLock<Vec<u8>> = OnceLock::new();
    
    JWT_SECRET.get_or_init(|| {
        // Try loading from .env file
        let _ = dotenv();
        
        // Try to get from environment variable
        match env::var("JWT_SECRET") {
            Ok(secret) => {
                if !secret.is_empty() {
                    return secret.into_bytes();
                }
                // Fall through to random generation if empty
            }
            Err(_) => {
                // Fall through to random generation
            }
        }
        
        // Generate random secret (32 characters)
        let random_secret: String = rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        
        eprintln!("WARNING: No JWT_SECRET found in environment. Using random secret (will change on restart)");
        random_secret.into_bytes()
    }).as_slice()
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[derive(Clone, Serialize)]
pub struct UserContext {
    pub id: i64,
    pub roles: Vec<String>,
}

impl FromRequest for UserContext {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        use actix_web::{error::ErrorUnauthorized, http::header};

        let token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_string());

        if let Some(token) = token {
            match decode::<Claims>(&token, &DecodingKey::from_secret(get_jwt_secret()), &Validation::default()) {
                Ok(data) => {
                    let claims = data.claims;
                    return ready(Ok(UserContext {
                        id: claims.sub,
                        roles: claims.roles,
                    }));
                }
                Err(_) => return ready(Err(ErrorUnauthorized("Invalid token"))),
            }
        }

        ready(Err(ErrorUnauthorized("Missing token")))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Option<i64>,
    pub email: String,
    pub password_hash: String,
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterInput {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginInput {
    pub email: String,
    pub password: String,
}

pub async fn register(input: web::Json<RegisterInput>, db: web::Data<AnyPool>) -> impl Responder {
    let password_hash = match hash(&input.password, 12) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().body("Hashing error"),
    };

    let result = sqlx::query("INSERT INTO user (email, password_hash, role) VALUES (?, ?, ?)")
        .bind(&input.email)
        .bind(password_hash)
        .bind("user")
        .execute(db.get_ref())
        .await;

    match result {
        Ok(_) => HttpResponse::Created().finish(),
        Err(e) => HttpResponse::InternalServerError().body(format!("DB error: {}", e)),
    }
}

pub async fn login(input: web::Json<LoginInput>, db: web::Data<AnyPool>) -> impl Responder {
    let row = sqlx::query_as::<_, User>("SELECT * FROM user WHERE email = ?")
        .bind(&input.email)
        .fetch_optional(db.get_ref())
        .await;

    let user = match row {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Unauthorized().body("Invalid credentials"),
    };

    if verify(&input.password, &user.password_hash).unwrap_or(false) {
        let claims = Claims {
            sub: user.id.unwrap(),
            roles: vec![user.role.clone()],
            exp: (Utc::now() + Duration::hours(24)).timestamp() as usize,
        };

        match encode(&Header::default(), &claims, &EncodingKey::from_secret(get_jwt_secret())) {
            Ok(token) => HttpResponse::Ok().json(serde_json::json!({ "token": token })),
            Err(_) => HttpResponse::InternalServerError().body("Token generation failed"),
        }
    } else {
        HttpResponse::Unauthorized().body("Invalid credentials")
    }
}

pub async fn me(user: UserContext) -> impl Responder {
    HttpResponse::Ok().json(user)
}

/// Check if an admin user exists, and create one from environment variables if not
/// 
/// This is meant to be called programmatically, not interactively.
/// It will only create an admin user if both ADMIN_EMAIL and ADMIN_PASSWORD
/// environment variables are set.
/// 
/// Returns true if an admin exists (either previously or newly created),
/// false otherwise.
pub async fn ensure_admin_exists(pool: &AnyPool) -> Result<bool, sqlx::Error> {
    // Check if any admin exists
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user WHERE role = 'admin'")
        .fetch_one(pool)
        .await?;
    
    let admin_exists = count > 0;
    
    if admin_exists {
        return Ok(true);
    }
    
    // Try to get admin credentials from environment
    let admin_email = match std::env::var("ADMIN_EMAIL") {
        Ok(email) if !email.is_empty() => email,
        _ => return Ok(false), // Don't create admin if no email specified
    };
    
    let admin_password = match std::env::var("ADMIN_PASSWORD") {
        Ok(password) if !password.is_empty() => password,
        _ => return Ok(false), // Don't create admin if no password specified
    };
    
    // Create the admin user
    let password_hash = match hash(&admin_password, 12) {
        Ok(hash) => hash,
        Err(_) => return Ok(false),
    };
    
    let result = sqlx::query("INSERT INTO user (email, password_hash, role) VALUES (?, ?, ?)")
        .bind(&admin_email)
        .bind(password_hash)
        .bind("admin")
        .execute(pool)
        .await;
    
    match result {
        Ok(_) => {
            println!("Created admin user with email: {}", admin_email);
            Ok(true)
        },
        Err(_) => Ok(false),
    }
}

pub fn auth_routes(cfg: &mut web::ServiceConfig, db: AnyPool) {
    let db = web::Data::new(db);
    cfg.app_data(db.clone());

    cfg.route("/auth/register", web::post().to(register));
    cfg.route("/auth/login", web::post().to(login));
    cfg.route("/auth/me", web::get().to(me));
}
