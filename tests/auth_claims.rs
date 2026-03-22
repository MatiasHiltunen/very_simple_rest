use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use serde_json::Value;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::auth::AccountInfo;
use very_simple_rest::db::{connect, query, query_scalar};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/auth_claims_api.eon");

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(Debug, Deserialize)]
struct MeResponse {
    id: i64,
    roles: Vec<String>,
    #[serde(flatten)]
    claims: BTreeMap<String, Value>,
}

#[actix_web::test]
async fn auth_claim_mapping_emits_explicit_claims_and_powers_claim_scoped_resources() {
    unsafe {
        std::env::set_var("JWT_SECRET", "auth-claims-secret");
    }

    let database_url = unique_sqlite_url("auth_claims");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            tenant_scope INTEGER,
            claim_workspace_id INTEGER,
            is_staff INTEGER,
            plan TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("user table should be created");

    query(
        "CREATE TABLE scoped_doc (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            title TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("scoped_doc table should be created");

    let security = auth_claims_api::security();
    let app = test::init_service(App::new().service(scope("/api").configure(|cfg| {
        auth::auth_routes_with_settings(cfg, pool.clone(), security.auth.clone());
        auth_claims_api::configure(cfg, pool.clone());
    })))
    .await;

    let register_request = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&auth::RegisterInput {
            email: "claims@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let register_response = test::call_service(&app, register_request).await;
    assert_eq!(register_response.status(), StatusCode::CREATED);

    query(
        "UPDATE user
         SET tenant_scope = ?, claim_workspace_id = ?, is_staff = ?, plan = ?
         WHERE email = ?",
    )
    .bind(7_i64)
    .bind(42_i64)
    .bind(true)
    .bind("pro")
    .bind("claims@example.com")
    .execute(&pool)
    .await
    .expect("mapped claim columns should update");

    let login_request = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "claims@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let token_response: TokenResponse = test::call_and_read_body_json(&app, login_request).await;

    let me_request = test::TestRequest::get()
        .uri("/api/auth/me")
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .to_request();
    let me_response: MeResponse = test::call_and_read_body_json(&app, me_request).await;
    assert!(me_response.id > 0);
    assert_eq!(me_response.roles, vec!["user".to_owned()]);
    assert_eq!(
        me_response.claims.get("tenant_id").and_then(Value::as_i64),
        Some(7)
    );
    assert_eq!(
        me_response
            .claims
            .get("workspace_id")
            .and_then(Value::as_i64),
        Some(42)
    );
    assert_eq!(
        me_response.claims.get("staff").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        me_response.claims.get("plan").and_then(Value::as_str),
        Some("pro")
    );
    assert!(!me_response.claims.contains_key("tenant_scope"));
    assert!(!me_response.claims.contains_key("claim_workspace_id"));

    let account_request = test::TestRequest::get()
        .uri("/api/auth/account")
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .to_request();
    let account_response: AccountInfo = test::call_and_read_body_json(&app, account_request).await;
    assert_eq!(
        account_response
            .claims
            .get("tenant_id")
            .and_then(Value::as_i64),
        Some(7)
    );
    assert_eq!(
        account_response.claims.get("plan").and_then(Value::as_str),
        Some("pro")
    );

    let create_request = test::TestRequest::post()
        .uri("/api/scoped_doc")
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .set_json(&auth_claims_api::ScopedDocCreate {
            tenant_id: None,
            title: "mapped claims".to_owned(),
        })
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let tenant_id: i64 = query_scalar::<sqlx::Any, i64>("SELECT tenant_id FROM scoped_doc LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("created row should exist");
    assert_eq!(tenant_id, 7);

    let list_request = test::TestRequest::get()
        .uri("/api/scoped_doc")
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .to_request();
    let list_response: auth_claims_api::ScopedDocListResponse =
        test::call_and_read_body_json(&app, list_request).await;
    assert_eq!(list_response.total, 1);
    assert_eq!(list_response.count, 1);
    assert_eq!(list_response.items[0].tenant_id, 7);
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}
