use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;

#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    code: String,
    message: String,
    field: Option<String>,
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[actix_web::test]
async fn built_in_auth_uses_json_error_envelope() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("JWT_SECRET", "auth-errors-secret");
    }

    let database_url = unique_sqlite_url("auth_errors");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    let migration = very_simple_rest::core::auth::auth_migration_sql(
        very_simple_rest::core::auth::AuthDbBackend::Sqlite,
    );
    for statement in migration
        .split(';')
        .map(str::trim)
        .filter(|stmt| !stmt.is_empty())
    {
        query(statement)
            .execute(&pool)
            .await
            .expect("auth migration should apply");
    }

    let app = test::init_service(
        App::new().service(scope("/api").configure(|cfg| auth::auth_routes(cfg, pool.clone()))),
    )
    .await;

    let register = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&auth::RegisterInput {
            email: "alice@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let register_response = test::call_service(&app, register).await;
    assert_eq!(register_response.status(), StatusCode::CREATED);

    let duplicate_register = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&auth::RegisterInput {
            email: "alice@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let duplicate_register_response = test::call_service(&app, duplicate_register).await;
    assert_eq!(duplicate_register_response.status(), StatusCode::CONFLICT);
    let duplicate_body: ApiErrorResponse = test::read_body_json(duplicate_register_response).await;
    assert_eq!(duplicate_body.code, "duplicate_email");
    assert!(duplicate_body.message.contains("already exists"));
    assert_eq!(duplicate_body.field, None);

    let invalid_login = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "alice@example.com".to_owned(),
            password: "wrong-password".to_owned(),
        })
        .to_request();
    let invalid_login_response = test::call_service(&app, invalid_login).await;
    assert_eq!(invalid_login_response.status(), StatusCode::UNAUTHORIZED);
    let invalid_login_body: ApiErrorResponse = test::read_body_json(invalid_login_response).await;
    assert_eq!(invalid_login_body.code, "invalid_credentials");
    assert_eq!(invalid_login_body.message, "Invalid credentials");
    assert_eq!(invalid_login_body.field, None);

    let malformed_login = test::TestRequest::post()
        .uri("/api/auth/login")
        .insert_header(("Content-Type", "application/json"))
        .set_payload("{not valid json")
        .to_request();
    let malformed_login_response = test::call_service(&app, malformed_login).await;
    assert_eq!(malformed_login_response.status(), StatusCode::BAD_REQUEST);
    let malformed_login_body: ApiErrorResponse =
        test::read_body_json(malformed_login_response).await;
    assert_eq!(malformed_login_body.code, "invalid_json");
    assert_eq!(
        malformed_login_body.message,
        "Request body is not valid JSON"
    );
    assert_eq!(malformed_login_body.field, None);

    let missing_token = test::TestRequest::get().uri("/api/auth/me").to_request();
    let missing_token_response = test::call_service(&app, missing_token).await;
    assert_eq!(missing_token_response.status(), StatusCode::UNAUTHORIZED);
    let missing_token_body: ApiErrorResponse = test::read_body_json(missing_token_response).await;
    assert_eq!(missing_token_body.code, "missing_token");
    assert_eq!(missing_token_body.message, "Missing token");
    assert_eq!(missing_token_body.field, None);

    let invalid_token = test::TestRequest::get()
        .uri("/api/auth/me")
        .insert_header(("Authorization", "Bearer not-a-valid-jwt"))
        .to_request();
    let invalid_token_response = test::call_service(&app, invalid_token).await;
    assert_eq!(invalid_token_response.status(), StatusCode::UNAUTHORIZED);
    let invalid_token_body: ApiErrorResponse = test::read_body_json(invalid_token_response).await;
    assert_eq!(invalid_token_body.code, "invalid_token");
    assert_eq!(invalid_token_body.message, "Invalid token");
    assert_eq!(invalid_token_body.field, None);

    unsafe {
        std::env::remove_var("JWT_SECRET");
    }
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}
