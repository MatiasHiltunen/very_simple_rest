use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::json;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "list-fields-api-secret";

rest_api_from_eon!("tests/fixtures/list_fields_api.eon");

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
async fn generated_handlers_support_typed_list_payloads() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("list_fields_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE entry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            categories TEXT NOT NULL,
            tags TEXT NOT NULL,
            blocks TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    query("INSERT INTO entry (categories, tags, blocks) VALUES (?, ?, ?)")
        .bind("[1,2]")
        .bind(r#"["alpha","beta"]"#)
        .bind(r#"[{"name":"core/paragraph"}]"#)
        .execute(&pool)
        .await
        .expect("seed row should insert");

    let app = test::init_service(
        App::new().service(scope("/api").configure(|cfg| list_fields_api::configure(cfg, pool.clone()))),
    )
    .await;

    let token = issue_token(1, &["user"]);

    let create_request = test::TestRequest::post()
        .uri("/api/entry")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "categories": [5, 8],
            "tags": ["news", "ai"],
            "blocks": [
                {
                    "name": "core/heading",
                    "level": 2
                }
            ]
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created: list_fields_api::Entry = test::read_body_json(create_response).await;
    assert_eq!(created.categories, vec![5, 8]);
    assert_eq!(created.tags, vec!["news".to_owned(), "ai".to_owned()]);
    assert_eq!(
        created
            .blocks
            .expect("blocks should be present")
            .first()
            .expect("block should exist")["name"],
        "core/heading"
    );

    let list_request = test::TestRequest::get()
        .uri("/api/entry")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let list_response = test::call_service(&app, list_request).await;
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_page: list_fields_api::EntryListResponse = test::read_body_json(list_response).await;
    assert_eq!(list_page.total, 2);
    assert_eq!(list_page.items[0].categories, vec![1, 2]);
    assert_eq!(list_page.items[1].tags, vec!["news".to_owned(), "ai".to_owned()]);

    let invalid_filter_request = test::TestRequest::get()
        .uri("/api/entry?filter_categories=1")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let invalid_filter_response = test::call_service(&app, invalid_filter_request).await;
    assert_eq!(invalid_filter_response.status(), StatusCode::BAD_REQUEST);
    let invalid_filter_body: ApiErrorResponse = test::read_body_json(invalid_filter_response).await;
    assert_eq!(invalid_filter_body.code, "invalid_query");
    assert_eq!(invalid_filter_body.message, "Query parameters are invalid");
    assert_eq!(invalid_filter_body.field, None);
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
