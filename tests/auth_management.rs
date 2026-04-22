use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use very_simple_rest::actix_web::{
    App, cookie::Cookie, dev::ServiceResponse, http::StatusCode, test,
};
use very_simple_rest::auth::AccountInfo;
use very_simple_rest::db::{connect, query, query_scalar};
use very_simple_rest::prelude::*;

use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/auth_management_api.eon");

#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    code: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_auth_management_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}

fn unique_capture_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    std::env::temp_dir().join(format!("vsr_auth_capture_{prefix}_{nanos}"))
}

fn response_cookie(response: &ServiceResponse, name: &str) -> Option<Cookie<'static>> {
    response
        .response()
        .cookies()
        .find(|cookie| cookie.name() == name)
        .map(|cookie| cookie.into_owned())
}

fn capture_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = std::fs::read_dir(dir)
        .expect("capture dir should exist")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn extract_token_from_text(text: &str) -> String {
    let start = text
        .find("token=")
        .expect("email should contain a token parameter")
        + "token=".len();
    text[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .collect()
}

fn extract_url_from_text(text: &str) -> String {
    let start = text
        .find("http://")
        .or_else(|| text.find("https://"))
        .expect("email should contain an absolute URL");
    text[start..]
        .lines()
        .next()
        .expect("email URL line should exist")
        .trim()
        .to_owned()
}

fn path_and_query_from_url(url: &str) -> String {
    let authority_start = url.find("://").map(|index| index + 3).unwrap_or(0);
    let path_start = url[authority_start..]
        .find('/')
        .map(|index| authority_start + index);
    match path_start {
        Some(index) => url[index..].to_owned(),
        None => "/".to_owned(),
    }
}

fn token_from_capture(path: &Path) -> String {
    let body = std::fs::read_to_string(path).expect("capture file should be readable");
    let payload: Value = serde_json::from_str(&body).expect("capture file should be JSON");
    let text_body = payload
        .get("text_body")
        .and_then(Value::as_str)
        .expect("capture payload should contain text_body");
    extract_token_from_text(text_body)
}

fn url_from_capture(path: &Path) -> String {
    let body = std::fs::read_to_string(path).expect("capture file should be readable");
    let payload: Value = serde_json::from_str(&body).expect("capture file should be JSON");
    let text_body = payload
        .get("text_body")
        .and_then(Value::as_str)
        .expect("capture payload should contain text_body");
    extract_url_from_text(text_body)
}

#[actix_web::test]
async fn built_in_auth_management_supports_verification_reset_and_dashboards() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    let capture_dir = unique_capture_dir("management");
    std::fs::create_dir_all(&capture_dir).expect("capture dir should be created");

    unsafe {
        std::env::set_var("JWT_SECRET", "auth-management-secret");
        std::env::set_var("VSR_AUTH_EMAIL_CAPTURE_DIR", &capture_dir);
    }

    let database_url = unique_sqlite_url("management");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    for statement in very_simple_rest::core::auth::auth_migration_sql(
        very_simple_rest::core::auth::AuthDbBackend::Sqlite,
    )
    .split(';')
    .map(str::trim)
    .filter(|statement| !statement.is_empty())
    {
        query(statement)
            .execute(&pool)
            .await
            .expect("base auth migration should apply");
    }
    for statement in very_simple_rest::core::auth::auth_management_migration_sql(
        very_simple_rest::core::auth::AuthDbBackend::Sqlite,
    )
    .split(';')
    .map(str::trim)
    .filter(|statement| !statement.is_empty())
    {
        query(statement)
            .execute(&pool)
            .await
            .expect("auth management migration should apply");
    }

    let mut security = auth_management_api::security();
    security
        .auth
        .email
        .as_mut()
        .expect("auth management fixture should define email settings")
        .public_base_url = Some("https://app.example".to_owned());
    let app = test::init_service(
        App::new()
            .configure(|cfg| {
                auth::register_builtin_auth_html_pages(cfg, security.auth.clone());
            })
            .service(scope("/api").configure(|cfg| {
                auth::auth_routes_with_settings(cfg, pool.clone(), security.auth.clone());
                auth_management_api::configure(cfg, pool.clone());
            })),
    )
    .await;

    let register_alice = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&auth::RegisterInput {
            email: "alice@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let register_alice_response = test::call_service(&app, register_alice).await;
    assert_eq!(register_alice_response.status(), StatusCode::CREATED);

    let captured = capture_files(&capture_dir);
    assert_eq!(captured.len(), 1);
    let verification_token = token_from_capture(&captured[0]);

    let login_before_verify = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "alice@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let login_before_verify_response = test::call_service(&app, login_before_verify).await;
    assert_eq!(login_before_verify_response.status(), StatusCode::FORBIDDEN);
    let login_before_verify_body: ApiErrorResponse =
        test::read_body_json(login_before_verify_response).await;
    assert_eq!(login_before_verify_body.code, "email_not_verified");
    assert!(login_before_verify_body.message.contains("verified"));

    let verify_alice = test::TestRequest::post()
        .uri("/api/auth/verify-email")
        .set_json(&auth::VerifyEmailInput {
            token: verification_token,
        })
        .to_request();
    let verify_alice_response = test::call_service(&app, verify_alice).await;
    assert_eq!(verify_alice_response.status(), StatusCode::NO_CONTENT);

    let verified_at = query_scalar::<sqlx::Any, Option<String>>(
        "SELECT email_verified_at FROM user WHERE email = ?",
    )
    .bind("alice@example.com")
    .fetch_one(&pool)
    .await
    .expect("verified timestamp should be queryable");
    assert!(verified_at.is_some());

    let alice_id: i64 = query_scalar::<sqlx::Any, i64>("SELECT id FROM user WHERE email = ?")
        .bind("alice@example.com")
        .fetch_one(&pool)
        .await
        .expect("alice id should be queryable");
    query("UPDATE user SET role = ?, updated_at = ? WHERE id = ?")
        .bind("admin")
        .bind(Utc::now().to_rfc3339())
        .bind(alice_id)
        .execute(&pool)
        .await
        .expect("alice role should update to admin");

    let login_alice = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "alice@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let login_alice_response = test::call_service(&app, login_alice).await;
    assert_eq!(login_alice_response.status(), StatusCode::OK);
    let session_cookie =
        response_cookie(&login_alice_response, "vsr_session").expect("session cookie should exist");
    let token_body: TokenResponse = test::read_body_json(login_alice_response).await;

    let account_request = test::TestRequest::get()
        .uri("/api/auth/account")
        .cookie(session_cookie.clone())
        .to_request();
    let account_response = test::call_service(&app, account_request).await;
    assert_eq!(account_response.status(), StatusCode::OK);
    let account_body: AccountInfo = test::read_body_json(account_response).await;
    assert_eq!(account_body.email, "alice@example.com");
    assert_eq!(account_body.role, "admin");
    assert!(account_body.email_verified);

    let portal_request = test::TestRequest::get()
        .uri("/auth/portal")
        .to_request();
    let portal_response = test::call_service(&app, portal_request).await;
    assert_eq!(portal_response.status(), StatusCode::OK);
    let portal_body = String::from_utf8(test::read_body(portal_response).await.to_vec())
        .expect("portal HTML should decode");
    assert!(portal_body.contains("Account Portal"));

    let register_bob = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&auth::RegisterInput {
            email: "bob@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let register_bob_response = test::call_service(&app, register_bob).await;
    assert_eq!(register_bob_response.status(), StatusCode::CREATED);
    let bob_id: i64 = query_scalar::<sqlx::Any, i64>("SELECT id FROM user WHERE email = ?")
        .bind("bob@example.com")
        .fetch_one(&pool)
        .await
        .expect("bob id should be queryable");

    let admin_users_request = test::TestRequest::get()
        .uri("/api/auth/admin/users")
        .insert_header(("Authorization", format!("Bearer {}", token_body.token)))
        .to_request();
    let admin_users_response = test::call_service(&app, admin_users_request).await;
    assert_eq!(admin_users_response.status(), StatusCode::OK);

    let patch_bob_request = test::TestRequest::patch()
        .uri(&format!("/api/auth/admin/users/{bob_id}"))
        .insert_header(("Authorization", format!("Bearer {}", token_body.token)))
        .set_json(&auth::UpdateManagedUserInput {
            role: Some("moderator".to_owned()),
            email_verified: Some(true),
            claims: BTreeMap::new(),
        })
        .to_request();
    let patch_bob_response = test::call_service(&app, patch_bob_request).await;
    assert_eq!(patch_bob_response.status(), StatusCode::OK);
    let patch_bob_body: AccountInfo = test::read_body_json(patch_bob_response).await;
    assert_eq!(patch_bob_body.role, "moderator");
    assert!(patch_bob_body.email_verified);

    let create_carol_request = test::TestRequest::post()
        .uri("/api/auth/admin/users")
        .insert_header(("Authorization", format!("Bearer {}", token_body.token)))
        .set_json(&auth::CreateManagedUserInput {
            email: "carol@example.com".to_owned(),
            password: "password789".to_owned(),
            role: Some("reviewer".to_owned()),
            email_verified: Some(false),
            send_verification_email: Some(true),
        })
        .to_request();
    let create_carol_response = test::call_service(&app, create_carol_request).await;
    assert_eq!(create_carol_response.status(), StatusCode::CREATED);
    let create_carol_location = create_carol_response
        .headers()
        .get("Location")
        .and_then(|value| value.to_str().ok())
        .expect("created managed user should expose a location")
        .to_owned();
    let carol_body: AccountInfo = test::read_body_json(create_carol_response).await;
    assert_eq!(carol_body.email, "carol@example.com");
    assert_eq!(carol_body.role, "reviewer");
    assert!(!carol_body.email_verified);
    assert_eq!(
        create_carol_location,
        format!("/api/auth/admin/users/{}", carol_body.id)
    );

    let admin_page_request = test::TestRequest::get()
        .uri("/auth/admin")
        .insert_header(("Authorization", format!("Bearer {}", token_body.token)))
        .to_request();
    let admin_page_response = test::call_service(&app, admin_page_request).await;
    assert_eq!(admin_page_response.status(), StatusCode::OK);
    let admin_page_body = String::from_utf8(test::read_body(admin_page_response).await.to_vec())
        .expect("admin HTML should decode");
    assert!(admin_page_body.contains("Admin Dashboard"));
    assert!(admin_page_body.contains("Create user"));

    let captured = capture_files(&capture_dir);
    assert_eq!(captured.len(), 3);
    let carol_verification_capture = captured
        .iter()
        .find(|path| {
            let path_text = std::fs::read_to_string(path).expect("capture file should be readable");
            path_text.contains("carol@example.com")
        })
        .expect("admin-created user verification email should be captured");
    let carol_verification_url = url_from_capture(carol_verification_capture);
    assert!(
        carol_verification_url.contains("/api/auth/verify-email?token="),
        "unexpected verification url: {carol_verification_url}"
    );

    let delete_carol_request = test::TestRequest::delete()
        .uri(&format!("/api/auth/admin/users/{}", carol_body.id))
        .insert_header(("Authorization", format!("Bearer {}", token_body.token)))
        .to_request();
    let delete_carol_response = test::call_service(&app, delete_carol_request).await;
    assert_eq!(delete_carol_response.status(), StatusCode::NO_CONTENT);

    let get_deleted_carol_request = test::TestRequest::get()
        .uri(&format!("/api/auth/admin/users/{}", carol_body.id))
        .insert_header(("Authorization", format!("Bearer {}", token_body.token)))
        .to_request();
    let get_deleted_carol_response = test::call_service(&app, get_deleted_carol_request).await;
    assert_eq!(get_deleted_carol_response.status(), StatusCode::NOT_FOUND);

    let password_reset_request = test::TestRequest::post()
        .uri("/api/auth/password-reset/request")
        .set_json(&auth::PasswordResetRequestInput {
            email: "alice@example.com".to_owned(),
        })
        .to_request();
    let password_reset_response = test::call_service(&app, password_reset_request).await;
    assert_eq!(password_reset_response.status(), StatusCode::ACCEPTED);

    let captured = capture_files(&capture_dir);
    assert_eq!(captured.len(), 4);
    let reset_capture = captured
        .iter()
        .find(|path| url_from_capture(path).contains("/password-reset?token="))
        .expect("reset email should be captured");
    let reset_token = token_from_capture(reset_capture);
    let reset_url = url_from_capture(reset_capture);
    let reset_page_path = path_and_query_from_url(&reset_url);
    assert!(
        reset_page_path.starts_with("/api/auth/password-reset?token="),
        "unexpected reset url: {reset_url}"
    );
    let reset_page_request = test::TestRequest::get().uri(&reset_page_path).to_request();
    let reset_page_response = test::call_service(&app, reset_page_request).await;
    assert_eq!(reset_page_response.status(), StatusCode::OK);
    let reset_page_body = String::from_utf8(test::read_body(reset_page_response).await.to_vec())
        .expect("password reset page HTML should decode");
    assert!(reset_page_body.contains("Choose A New Password"));

    let confirm_reset_request = test::TestRequest::post()
        .uri("/api/auth/password-reset/confirm")
        .set_json(&auth::PasswordResetConfirmInput {
            token: reset_token,
            new_password: "password456".to_owned(),
        })
        .to_request();
    let confirm_reset_response = test::call_service(&app, confirm_reset_request).await;
    assert_eq!(confirm_reset_response.status(), StatusCode::NO_CONTENT);

    let old_password_login = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "alice@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let old_password_login_response = test::call_service(&app, old_password_login).await;
    assert_eq!(
        old_password_login_response.status(),
        StatusCode::UNAUTHORIZED
    );

    let new_password_login = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "alice@example.com".to_owned(),
            password: "password456".to_owned(),
        })
        .to_request();
    let new_password_login_response = test::call_service(&app, new_password_login).await;
    assert_eq!(new_password_login_response.status(), StatusCode::OK);

    unsafe {
        std::env::remove_var("JWT_SECRET");
        std::env::remove_var("VSR_AUTH_EMAIL_CAPTURE_DIR");
    }
    let _ = std::fs::remove_dir_all(capture_dir);
}
