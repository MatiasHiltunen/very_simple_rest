use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value, json};
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "api-contexts-api-secret";

rest_api_from_eon!("tests/fixtures/api_contexts_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn generated_handlers_apply_response_contexts_over_projected_fields() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("api_contexts_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE blog_post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title_text TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            draft_body TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    query("INSERT INTO blog_post (id, title_text, author_id, draft_body) VALUES (?, ?, ?, ?)")
        .bind(1_i64)
        .bind("Alpha")
        .bind(7_i64)
        .bind("secret alpha")
        .execute(&pool)
        .await
        .expect("seed row should insert");

    let app = test::init_service(
        App::new().service(scope("/api").configure(|cfg| api_contexts_api::configure(cfg, pool.clone()))),
    )
    .await;
    let token = issue_token(1, &["user"]);

    let item_request = test::TestRequest::get().uri("/api/posts/1").to_request();
    let item_response = test::call_service(&app, item_request).await;
    assert_eq!(item_response.status(), StatusCode::OK);
    let item_body: Value = test::read_body_json(item_response).await;
    assert_eq!(item_body["title"], "Alpha");
    assert!(item_body.get("secret").is_none());

    let edit_request = test::TestRequest::get()
        .uri("/api/posts/1?context=edit")
        .to_request();
    let edit_response = test::call_service(&app, edit_request).await;
    assert_eq!(edit_response.status(), StatusCode::OK);
    let edit_body: Value = test::read_body_json(edit_response).await;
    assert_eq!(edit_body["secret"], "secret alpha");

    let list_request = test::TestRequest::get().uri("/api/posts?sort=title").to_request();
    let list_response = test::call_service(&app, list_request).await;
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body: Value = test::read_body_json(list_response).await;
    assert_eq!(list_body["items"][0]["title"], "Alpha");
    assert!(list_body["items"][0].get("secret").is_none());

    let create_request = test::TestRequest::post()
        .uri("/api/posts?context=edit")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "title": "Beta",
            "author": 9,
            "secret": "secret beta"
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let create_body: Value = test::read_body_json(create_response).await;
    assert_eq!(create_body["secret"], "secret beta");

    let invalid_request = test::TestRequest::get()
        .uri("/api/posts/1?context=unknown")
        .to_request();
    let invalid_response = test::call_service(&app, invalid_request).await;
    assert_eq!(invalid_response.status(), StatusCode::BAD_REQUEST);
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
