use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value, json};
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "api-computed-fields-api-secret";

rest_api_from_eon!("tests/fixtures/api_computed_fields_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn generated_handlers_serialize_computed_api_fields() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("api_computed_fields_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    query("INSERT INTO post (id, slug, title, summary) VALUES (?, ?, ?, ?)")
        .bind(1_i64)
        .bind("alpha")
        .bind("Alpha")
        .bind("Intro")
        .execute(&pool)
        .await
        .expect("seed row should insert");

    let app = test::init_service(App::new().service(
        scope("/api").configure(|cfg| api_computed_fields_api::configure(cfg, pool.clone())),
    ))
    .await;
    let token = issue_token(1, &["user"]);

    let get_request = test::TestRequest::get().uri("/api/posts/1").to_request();
    let get_response = test::call_service(&app, get_request).await;
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body: Value = test::read_body_json(get_response).await;
    assert_eq!(get_body["permalink"], "/posts/alpha");
    assert_eq!(get_body["preview"], "alpha:Intro");

    let create_request = test::TestRequest::post()
        .uri("/api/posts")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "slug": "beta",
            "title": "Beta"
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let create_body: Value = test::read_body_json(create_response).await;
    assert_eq!(create_body["permalink"], "/posts/beta");
    assert!(create_body["preview"].is_null());

    let compact_request = test::TestRequest::get()
        .uri("/api/posts?context=compact")
        .to_request();
    let compact_response = test::call_service(&app, compact_request).await;
    assert_eq!(compact_response.status(), StatusCode::OK);
    let compact_body: Value = test::read_body_json(compact_response).await;
    assert_eq!(compact_body["items"][0]["id"], 1);
    assert_eq!(compact_body["items"][0]["permalink"], "/posts/alpha");
    assert!(compact_body["items"][0].get("title").is_none());
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
