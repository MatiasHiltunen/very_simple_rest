use std::{
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::prelude::*;
use very_simple_rest::sqlx::any::AnyPoolOptions;

use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/security_api.eon");

#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    code: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct TokenClaims {
    sub: i64,
    roles: Vec<String>,
    iss: Option<String>,
    aud: Option<String>,
    exp: usize,
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[actix_web::test]
async fn eon_security_config_applies_headers_request_limits_and_auth_settings() {
    sqlx::any::install_default_drivers();

    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("JWT_SECRET", "security-test-secret");
        std::env::set_var("CORS_ORIGINS", "https://app.example.com");
        std::env::set_var("TRUSTED_PROXIES", "10.0.0.1");
    }

    let database_url = unique_sqlite_url("service_security");
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("database should connect");

    sqlx::raw_sql(&very_simple_rest::core::auth::auth_migration_sql(
        very_simple_rest::core::auth::AuthDbBackend::Sqlite,
    ))
    .execute(&pool)
    .await
    .expect("auth migration should apply");

    let security = security_api::security();
    let app = test::init_service(
        App::new()
            .wrap(very_simple_rest::core::security::cors_middleware(&security))
            .wrap(very_simple_rest::core::security::security_headers_middleware(&security))
            .service(scope("/api").configure(|cfg| {
                auth::auth_routes_with_settings(cfg, pool.clone(), security.auth.clone());
                security_api::configure(cfg, pool.clone());
            })),
    )
    .await;

    let register = test::TestRequest::post()
        .uri("/api/auth/register")
        .peer_addr("127.0.0.1:40001".parse().expect("peer addr should parse"))
        .insert_header(("X-Forwarded-For", "203.0.113.10"))
        .set_json(&auth::RegisterInput {
            email: "alice@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let register_response = test::call_service(&app, register).await;
    assert_eq!(register_response.status(), StatusCode::CREATED);
    assert_eq!(
        header_value(&register_response, "x-frame-options"),
        Some("DENY")
    );
    assert_eq!(
        header_value(&register_response, "x-content-type-options"),
        Some("nosniff")
    );
    assert_eq!(
        header_value(&register_response, "referrer-policy"),
        Some("strict-origin-when-cross-origin")
    );
    assert_eq!(
        header_value(&register_response, "strict-transport-security"),
        Some("max-age=31536000; includeSubDomains")
    );

    let second_register = test::TestRequest::post()
        .uri("/api/auth/register")
        .peer_addr("127.0.0.1:40001".parse().expect("peer addr should parse"))
        .insert_header(("X-Forwarded-For", "203.0.113.10"))
        .set_json(&auth::RegisterInput {
            email: "bob@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let second_register_response = test::call_service(&app, second_register).await;
    assert_eq!(second_register_response.status(), StatusCode::CREATED);

    let third_register = test::TestRequest::post()
        .uri("/api/auth/register")
        .peer_addr("127.0.0.1:40001".parse().expect("peer addr should parse"))
        .insert_header(("X-Forwarded-For", "203.0.113.10"))
        .set_json(&auth::RegisterInput {
            email: "carol@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let third_register_response = test::call_service(&app, third_register).await;
    assert_eq!(
        third_register_response.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert!(header_value(&third_register_response, "retry-after").is_some());
    let third_register_body: ApiErrorResponse = test::read_body_json(third_register_response).await;
    assert_eq!(third_register_body.code, "rate_limited");

    let forwarded_ip_bypass_register = test::TestRequest::post()
        .uri("/api/auth/register")
        .peer_addr("127.0.0.1:40001".parse().expect("peer addr should parse"))
        .insert_header(("X-Forwarded-For", "203.0.113.11"))
        .set_json(&auth::RegisterInput {
            email: "dave@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let forwarded_ip_bypass_response = test::call_service(&app, forwarded_ip_bypass_register).await;
    assert_eq!(forwarded_ip_bypass_response.status(), StatusCode::CREATED);

    let oversized_json = format!(
        "{{\"email\":\"{}\",\"password\":\"password123\"}}",
        "a".repeat(256)
    );
    let oversized_request = test::TestRequest::post()
        .uri("/api/auth/register")
        .insert_header(("Content-Type", "application/json"))
        .set_payload(oversized_json)
        .to_request();
    let oversized_response = test::call_service(&app, oversized_request).await;
    assert_eq!(oversized_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let oversized_body: ApiErrorResponse = test::read_body_json(oversized_response).await;
    assert_eq!(oversized_body.code, "payload_too_large");
    assert_eq!(oversized_body.message, "JSON payload is too large");

    let preflight = test::TestRequest::default()
        .method(very_simple_rest::actix_web::http::Method::OPTIONS)
        .uri("/api/note")
        .insert_header(("Origin", "https://app.example.com"))
        .insert_header(("Access-Control-Request-Method", "POST"))
        .insert_header((
            "Access-Control-Request-Headers",
            "authorization,content-type",
        ))
        .to_request();
    let preflight_response = test::call_service(&app, preflight).await;
    assert_eq!(preflight_response.status(), StatusCode::OK);
    assert_eq!(
        header_value(&preflight_response, "access-control-allow-origin"),
        Some("https://app.example.com")
    );
    assert_eq!(
        header_value(&preflight_response, "access-control-allow-credentials"),
        Some("true")
    );
    let allowed_methods = header_value(&preflight_response, "access-control-allow-methods")
        .expect("cors preflight should include allowed methods");
    assert!(allowed_methods.contains("POST"));
    let allowed_headers = header_value(&preflight_response, "access-control-allow-headers")
        .expect("cors preflight should include allowed headers");
    assert!(
        allowed_headers
            .to_ascii_lowercase()
            .contains("authorization")
    );

    let login = test::TestRequest::post()
        .uri("/api/auth/login")
        .peer_addr("127.0.0.1:40001".parse().expect("peer addr should parse"))
        .insert_header(("X-Forwarded-For", "198.51.100.20"))
        .set_json(&auth::LoginInput {
            email: "alice@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let login_response = test::call_service(&app, login).await;
    assert_eq!(login_response.status(), StatusCode::OK);
    let token_body: TokenResponse = test::read_body_json(login_response).await;

    let mut validation = Validation::default();
    validation.set_issuer(&["very_simple_rest_tests"]);
    validation.set_audience(&["api_clients"]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    let token = decode::<TokenClaims>(
        &token_body.token,
        &DecodingKey::from_secret(b"security-test-secret"),
        &validation,
    )
    .expect("token should match configured issuer and audience");
    assert_eq!(token.claims.iss.as_deref(), Some("very_simple_rest_tests"));
    assert_eq!(token.claims.aud.as_deref(), Some("api_clients"));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be valid")
        .as_secs() as usize;
    assert!(token.claims.exp >= now + 840);
    assert!(token.claims.exp <= now + 960);

    let second_login = test::TestRequest::post()
        .uri("/api/auth/login")
        .peer_addr("127.0.0.1:40001".parse().expect("peer addr should parse"))
        .insert_header(("X-Forwarded-For", "198.51.100.20"))
        .set_json(&auth::LoginInput {
            email: "alice@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let second_login_response = test::call_service(&app, second_login).await;
    assert_eq!(second_login_response.status(), StatusCode::OK);

    let third_login = test::TestRequest::post()
        .uri("/api/auth/login")
        .peer_addr("127.0.0.1:40001".parse().expect("peer addr should parse"))
        .insert_header(("X-Forwarded-For", "198.51.100.20"))
        .set_json(&auth::LoginInput {
            email: "alice@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let third_login_response = test::call_service(&app, third_login).await;
    assert_eq!(third_login_response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(header_value(&third_login_response, "retry-after").is_some());
    let third_login_body: ApiErrorResponse = test::read_body_json(third_login_response).await;
    assert_eq!(third_login_body.code, "rate_limited");

    let me = test::TestRequest::get()
        .uri("/api/auth/me")
        .insert_header(("Authorization", format!("Bearer {}", token_body.token)))
        .to_request();
    let me_response = test::call_service(&app, me).await;
    assert_eq!(me_response.status(), StatusCode::OK);

    unsafe {
        std::env::remove_var("TRUSTED_PROXIES");
    }
}

fn header_value<'a, B>(
    response: &'a very_simple_rest::actix_web::dev::ServiceResponse<B>,
    name: &str,
) -> Option<&'a str> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}
