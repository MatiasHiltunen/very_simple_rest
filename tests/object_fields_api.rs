use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::json;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "object-fields-api-secret";

rest_api_from_eon!("tests/fixtures/object_fields_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[derive(Debug, serde::Deserialize)]
struct ApiErrorResponse {
    code: String,
    message: String,
    field: Option<String>,
}

#[actix_web::test]
async fn generated_handlers_support_typed_object_payloads() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("object_fields_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE entry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            settings TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    query("INSERT INTO entry (title, settings) VALUES (?, ?)")
        .bind(r#"{"raw":"Hello world","rendered":"<p>Hello world</p>"}"#)
        .bind(r#"{"featured":true,"categories":[1,2],"seo":{"slug":"hello-world"}}"#)
        .execute(&pool)
        .await
        .expect("seed row should insert");

    let app =
        test::init_service(App::new().service(
            scope("/api").configure(|cfg| object_fields_api::configure(cfg, pool.clone())),
        ))
        .await;

    let token = issue_token(1, &["user"]);

    let create_request = test::TestRequest::post()
        .uri("/api/entry")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "title": {
                "raw": "Typed object title",
                "rendered": "<p>Typed object title</p>"
            },
            "settings": {
                "featured": false,
                "categories": [5, 8],
                "seo": {
                    "slug": "typed-object-title"
                }
            }
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created: object_fields_api::Entry = test::read_body_json(create_response).await;
    assert_eq!(created.title["raw"], "Typed object title");
    assert_eq!(
        created.settings.as_ref().expect("settings should exist")["seo"]["slug"],
        "typed-object-title"
    );

    let list_request = test::TestRequest::get()
        .uri("/api/entry")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let list_response = test::call_service(&app, list_request).await;
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_page: object_fields_api::EntryListResponse = test::read_body_json(list_response).await;
    assert_eq!(list_page.total, 2);
    assert_eq!(list_page.items[0].title["rendered"], "<p>Hello world</p>");
    assert_eq!(
        list_page.items[1]
            .settings
            .as_ref()
            .expect("settings should exist")["categories"][1],
        8
    );

    let invalid_request = test::TestRequest::post()
        .uri("/api/entry")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "title": {
                "raw": "no"
            }
        }))
        .to_request();
    let invalid_response = test::call_service(&app, invalid_request).await;
    assert_eq!(invalid_response.status(), StatusCode::BAD_REQUEST);
    let invalid_body: ApiErrorResponse = test::read_body_json(invalid_response).await;
    assert_eq!(invalid_body.code, "validation_error");
    assert_eq!(invalid_body.field.as_deref(), Some("title.raw"));
    assert_eq!(
        invalid_body.message,
        "Field `title.raw` must have at least 3 characters"
    );
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
