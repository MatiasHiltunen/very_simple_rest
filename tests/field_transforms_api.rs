use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value, json};
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "field-transforms-api-secret";

rest_api_from_eon!("tests/fixtures/field_transforms_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn generated_handlers_apply_text_transforms_on_create_and_update() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("field_transforms_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL,
            status TEXT NOT NULL,
            title TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    let app = test::init_service(App::new().service(
        scope("/api").configure(|cfg| field_transforms_api::configure(cfg, pool.clone())),
    ))
    .await;
    let token = issue_token(1, &["user"]);

    let create_request = test::TestRequest::post()
        .uri("/api/posts")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "slug": "  Hello,   World!  ",
            "status": " DRAFT ",
            "title": {
                "raw": "  Hello   world \n again  ",
                "rendered": "  <p>Hello world</p>  "
            }
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created: field_transforms_api::Post = test::read_body_json(create_response).await;
    assert_eq!(created.slug, "hello-world");
    assert_eq!(created.status, "draft");
    assert_eq!(created.title["raw"], "Hello world again");
    assert_eq!(created.title["rendered"], "<p>Hello world</p>");

    let update_request = test::TestRequest::put()
        .uri("/api/posts/1")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "slug": "  Next__Post!!!  ",
            "status": " PUBLISHED ",
            "title": {
                "raw": "  Updated   title\t\tagain  ",
                "rendered": "  <p>Updated title</p>  "
            }
        }))
        .to_request();
    let update_response = test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::OK);

    let get_request = test::TestRequest::get().uri("/api/posts/1").to_request();
    let get_response = test::call_service(&app, get_request).await;
    assert_eq!(get_response.status(), StatusCode::OK);
    let updated: Value = test::read_body_json(get_response).await;
    assert_eq!(updated["slug"], "next-post");
    assert_eq!(updated["status"], "published");
    assert_eq!(updated["title"]["raw"], "Updated title again");
    assert_eq!(updated["title"]["rendered"], "<p>Updated title</p>");
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
