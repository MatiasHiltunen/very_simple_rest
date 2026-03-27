use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value, json};
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "enum-fields-api-secret";

rest_api_from_eon!("tests/fixtures/enum_fields_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn generated_handlers_validate_and_filter_enum_fields() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("enum_fields_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE blog_post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            status TEXT NOT NULL,
            workflow TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    query("INSERT INTO blog_post (id, title, status, workflow) VALUES (?, ?, ?, ?)")
        .bind(1_i64)
        .bind("Alpha")
        .bind("published")
        .bind(r#"{"current":"published","previous":"draft"}"#)
        .execute(&pool)
        .await
        .expect("seed row should insert");

    let app = test::init_service(
        App::new().service(scope("/api").configure(|cfg| enum_fields_api::configure(cfg, pool.clone()))),
    )
    .await;
    let token = issue_token(1, &["user"]);

    let list_request = test::TestRequest::get()
        .uri("/api/posts?filter_status=published")
        .to_request();
    let list_response = test::call_service(&app, list_request).await;
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body: Value = test::read_body_json(list_response).await;
    assert_eq!(list_body["items"][0]["status"], "published");
    assert_eq!(list_body["items"][0]["workflow"]["current"], "published");

    let invalid_filter_request = test::TestRequest::get()
        .uri("/api/posts?filter_status=invalid")
        .to_request();
    let invalid_filter_response = test::call_service(&app, invalid_filter_request).await;
    assert_eq!(invalid_filter_response.status(), StatusCode::BAD_REQUEST);

    let contains_request = test::TestRequest::get()
        .uri("/api/posts?filter_status_contains=pub")
        .to_request();
    let contains_response = test::call_service(&app, contains_request).await;
    assert_eq!(contains_response.status(), StatusCode::BAD_REQUEST);

    let create_request = test::TestRequest::post()
        .uri("/api/posts")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "title": "Beta",
            "status": "draft",
            "workflow": {
                "current": "draft"
            }
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let create_body: Value = test::read_body_json(create_response).await;
    assert_eq!(create_body["status"], "draft");

    let invalid_create_request = test::TestRequest::post()
        .uri("/api/posts")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "title": "Gamma",
            "status": "wrong"
        }))
        .to_request();
    let invalid_create_response = test::call_service(&app, invalid_create_request).await;
    assert_eq!(invalid_create_response.status(), StatusCode::BAD_REQUEST);
    let invalid_create_body: Value = test::read_body_json(invalid_create_response).await;
    assert_eq!(invalid_create_body["code"], "validation_error");
    assert_eq!(invalid_create_body["field"], "status");

    let invalid_nested_request = test::TestRequest::post()
        .uri("/api/posts")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "title": "Delta",
            "status": "draft",
            "workflow": {
                "current": "wrong"
            }
        }))
        .to_request();
    let invalid_nested_response = test::call_service(&app, invalid_nested_request).await;
    assert_eq!(invalid_nested_response.status(), StatusCode::BAD_REQUEST);
    let invalid_nested_body: Value = test::read_body_json(invalid_nested_response).await;
    assert_eq!(invalid_nested_body["code"], "validation_error");
    assert_eq!(invalid_nested_body["field"], "workflow.current");
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
