use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value, json};
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "resource-actions-api-secret";

rest_api_from_eon!("tests/fixtures/resource_actions_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn generated_handlers_apply_resource_actions() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("resource_actions_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            slug TEXT NOT NULL,
            status TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    query("INSERT INTO post (id, title, slug, status) VALUES (?, ?, ?, ?)")
        .bind(1_i64)
        .bind("Draft")
        .bind("draft")
        .bind("draft")
        .execute(&pool)
        .await
        .expect("seed row should insert");

    let app = test::init_service(App::new().service(
        scope("/api").configure(|cfg| resource_actions_api::configure(cfg, pool.clone())),
    ))
    .await;
    let token = issue_token(1, &["editor"]);

    let action_request = test::TestRequest::post()
        .uri("/api/posts/1/go-live")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let action_response = test::call_service(&app, action_request).await;
    assert_eq!(action_response.status(), StatusCode::OK);
    assert!(test::read_body(action_response).await.is_empty());

    let rename_request = test::TestRequest::post()
        .uri("/api/posts/1/rename")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "newTitle": "Fresh Launch",
            "newSlug": " Fresh   Launch! ",
            "newStatus": " REVIEW "
        }))
        .to_request();
    let rename_response = test::call_service(&app, rename_request).await;
    assert_eq!(rename_response.status(), StatusCode::OK);
    assert!(test::read_body(rename_response).await.is_empty());

    let invalid_rename_request = test::TestRequest::post()
        .uri("/api/posts/1/rename")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "newTitle": "bad",
            "newSlug": "still-valid",
            "newStatus": "draft"
        }))
        .to_request();
    let invalid_rename_response = test::call_service(&app, invalid_rename_request).await;
    assert_eq!(invalid_rename_response.status(), StatusCode::BAD_REQUEST);
    let invalid_rename_body: Value = test::read_body_json(invalid_rename_response).await;
    assert_eq!(invalid_rename_body["code"], "validation_error");
    assert_eq!(invalid_rename_body["field"], "newTitle");

    let get_request = test::TestRequest::get().uri("/api/posts/1").to_request();
    let get_response = test::call_service(&app, get_request).await;
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body: Value = test::read_body_json(get_response).await;
    assert_eq!(
        get_body,
        json!({
            "id": 1,
            "title": "Fresh Launch",
            "slug": "fresh-launch",
            "status": "review"
        })
    );

    let purge_request = test::TestRequest::post()
        .uri("/api/posts/1/purge")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let purge_response = test::call_service(&app, purge_request).await;
    assert_eq!(purge_response.status(), StatusCode::OK);

    let missing_request = test::TestRequest::get().uri("/api/posts/1").to_request();
    let missing_response = test::call_service(&app, missing_request).await;
    assert_eq!(missing_response.status(), StatusCode::NOT_FOUND);
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
