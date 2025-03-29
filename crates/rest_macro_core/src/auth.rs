use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use actix_web::{FromRequest, HttpRequest};
use actix_web::dev::Payload;
use serde::{Serialize, Deserialize};
use std::future::{ready, Ready};
use sqlx::{FromRow, AnyPool, Row};
use jsonwebtoken::{encode, decode, EncodingKey, DecodingKey, Header, Validation};
use chrono::{Utc, Duration};
use bcrypt::{hash, verify};

const SECRET: &[u8] = b"super-secret-key";

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
            match decode::<Claims>(&token, &DecodingKey::from_secret(SECRET), &Validation::default()) {
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

        match encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET)) {
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

pub fn auth_routes(cfg: &mut web::ServiceConfig, db: AnyPool) {
    let db = web::Data::new(db);
    cfg.app_data(db.clone());

    cfg.route("/auth/register", web::post().to(register));
    cfg.route("/auth/login", web::post().to(login));
    cfg.route("/auth/me", web::get().to(me));
}
