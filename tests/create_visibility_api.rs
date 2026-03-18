use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "create-visibility-secret";

rest_api_from_eon!("tests/fixtures/create_visibility_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn create_responses_do_not_leak_resources_that_caller_cannot_read() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("create_visibility");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE lead (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            message TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("lead schema should apply");

    let app = test::init_service(App::new().service(
        scope("/api").configure(|cfg| create_visibility_api::configure(cfg, pool.clone())),
    ))
    .await;

    let user_token = issue_token(7, &["user"]);
    let create_request = test::TestRequest::post()
        .uri("/api/lead")
        .insert_header(("Authorization", format!("Bearer {}", user_token.as_str())))
        .set_json(&create_visibility_api::LeadCreate {
            title: "Undisclosed lead".to_owned(),
            message: "This should be created without becoming readable to the creator.".to_owned(),
        })
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    assert!(
        create_response.headers().get("Location").is_none(),
        "unreadable create response should not expose a location"
    );
    let create_body = test::read_body(create_response).await;
    assert!(create_body.is_empty());

    let user_get_request = test::TestRequest::get()
        .uri("/api/lead/1")
        .insert_header(("Authorization", format!("Bearer {}", user_token.as_str())))
        .to_request();
    let user_get_response = test::call_service(&app, user_get_request).await;
    assert_eq!(user_get_response.status(), StatusCode::FORBIDDEN);

    let admin_token = issue_token(1, &["admin"]);
    let admin_get_request = test::TestRequest::get()
        .uri("/api/lead/1")
        .insert_header(("Authorization", format!("Bearer {}", admin_token.as_str())))
        .to_request();
    let admin_get_response = test::call_service(&app, admin_get_request).await;
    assert_eq!(admin_get_response.status(), StatusCode::OK);
    let lead: create_visibility_api::Lead = test::read_body_json(admin_get_response).await;
    assert_eq!(lead.title, "Undisclosed lead");
}

fn issue_token(user_id: i64, roles: &[&str]) -> String {
    encode(
        &Header::default(),
        &TestClaims {
            sub: user_id,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            exp: 4_102_444_800,
        },
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("test token should encode")
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}
