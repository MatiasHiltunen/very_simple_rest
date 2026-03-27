use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value, json};
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "api-name-alias-api-secret";

rest_api_from_eon!("tests/fixtures/api_name_alias_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn generated_handlers_expose_api_aliases_for_routes_payloads_and_queries() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("api_name_alias_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE blog_post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title_text TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            created_at TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("post schema should apply");

    query(
        "CREATE TABLE comment_row (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            body_text TEXT NOT NULL,
            post_id INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("comment schema should apply");

    query("INSERT INTO blog_post (id, title_text, author_id, created_at) VALUES (?, ?, ?, ?)")
        .bind(1_i64)
        .bind("Alpha")
        .bind(7_i64)
        .bind("2026-03-26T10:00:00Z")
        .execute(&pool)
        .await
        .expect("first seed row should insert");
    query("INSERT INTO blog_post (id, title_text, author_id, created_at) VALUES (?, ?, ?, ?)")
        .bind(2_i64)
        .bind("Beta")
        .bind(9_i64)
        .bind("2026-03-26T11:00:00Z")
        .execute(&pool)
        .await
        .expect("second seed row should insert");
    query("INSERT INTO comment_row (id, body_text, post_id) VALUES (?, ?, ?)")
        .bind(1_i64)
        .bind("First comment")
        .bind(1_i64)
        .execute(&pool)
        .await
        .expect("comment seed row should insert");

    let app = test::init_service(
        App::new().service(scope("/api").configure(|cfg| api_name_alias_api::configure(cfg, pool.clone()))),
    )
    .await;

    let token = issue_token(1, &["user"]);

    let create_request = test::TestRequest::post()
        .uri("/api/posts")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "title": "Gamma",
            "author": 7,
            "createdAt": "2026-03-26T12:00:00Z"
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created: Value = test::read_body_json(create_response).await;
    assert_eq!(created["title"], "Gamma");
    assert_eq!(created["author"], 7);
    assert!(created.get("title_text").is_none());
    assert!(created.get("author_id").is_none());

    let list_request = test::TestRequest::get()
        .uri("/api/posts?filter_author=7&sort=title&limit=1")
        .to_request();
    let list_response = test::call_service(&app, list_request).await;
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body: Value = test::read_body_json(list_response).await;
    assert_eq!(list_body["total"], 2);
    assert_eq!(list_body["items"][0]["title"], "Alpha");
    let next_cursor = list_body["next_cursor"]
        .as_str()
        .expect("next cursor should exist")
        .to_owned();

    let cursor_request = test::TestRequest::get()
        .uri(format!("/api/posts?filter_author=7&limit=1&cursor={next_cursor}").as_str())
        .to_request();
    let cursor_response = test::call_service(&app, cursor_request).await;
    assert_eq!(cursor_response.status(), StatusCode::OK);
    let cursor_body: Value = test::read_body_json(cursor_response).await;
    assert_eq!(cursor_body["items"][0]["title"], "Gamma");

    let nested_request = test::TestRequest::get().uri("/api/posts/1/comments").to_request();
    let nested_response = test::call_service(&app, nested_request).await;
    assert_eq!(nested_response.status(), StatusCode::OK);
    let nested_body: Value = test::read_body_json(nested_response).await;
    assert_eq!(nested_body["items"][0]["body"], "First comment");
    assert_eq!(nested_body["items"][0]["post"], 1);
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
