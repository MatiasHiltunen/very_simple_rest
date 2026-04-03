use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value, json};
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "api-projection-api-secret";

rest_api_from_eon!("tests/fixtures/api_projection_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn generated_handlers_apply_resource_api_field_projections() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("api_projection_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE blog_post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title_text TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            draft_body TEXT,
            internal_note TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    query(
        "INSERT INTO blog_post (id, title_text, author_id, draft_body, internal_note) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(1_i64)
    .bind("Alpha")
    .bind(7_i64)
    .bind("secret draft")
    .bind("internal only")
    .execute(&pool)
    .await
    .expect("seed row should insert");

    let app =
        test::init_service(App::new().service(
            scope("/api").configure(|cfg| api_projection_api::configure(cfg, pool.clone())),
        ))
        .await;

    let token = issue_token(1, &["user"]);

    let create_request = test::TestRequest::post()
        .uri("/api/posts")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "title": "Gamma",
            "author": 7
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created: Value = test::read_body_json(create_response).await;
    assert_eq!(created["title"], "Gamma");
    assert_eq!(created["author"], 7);
    assert!(created.get("title_text").is_none());
    assert!(created.get("draft_body").is_none());
    assert!(created.get("internal_note").is_none());

    let list_request = test::TestRequest::get()
        .uri("/api/posts?filter_author=7&sort=title")
        .to_request();
    let list_response = test::call_service(&app, list_request).await;
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body: Value = test::read_body_json(list_response).await;
    assert_eq!(list_body["total"], 2);
    assert_eq!(list_body["items"][0]["title"], "Alpha");
    assert_eq!(list_body["items"][1]["title"], "Gamma");
    assert!(list_body["items"][0].get("draft_body").is_none());
    assert!(list_body["items"][0].get("internal_note").is_none());
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
