use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "list-pagination-secret";

rest_api_from_eon!("tests/fixtures/paged_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn list_config_applies_default_and_max_page_sizes() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("list_pagination");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE item (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            score INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    query(
        "INSERT INTO item (title, score) VALUES
            ('alpha', 10),
            ('beta', 20),
            ('gamma', 30),
            ('delta', 40)",
    )
    .execute(&pool)
    .await
    .expect("schema and seed data should apply");

    let app = test::init_service(
        App::new().service(scope("/api").configure(|cfg| paged_api::configure(cfg, pool.clone()))),
    )
    .await;

    let token = issue_token(1, &["user"]);

    let default_page_request = test::TestRequest::get()
        .uri("/api/item?sort=score&order=asc")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let default_page_response = test::call_service(&app, default_page_request).await;
    assert_eq!(default_page_response.status(), StatusCode::OK);
    let default_page: paged_api::ItemListResponse =
        test::read_body_json(default_page_response).await;
    assert_eq!(default_page.total, 4);
    assert_eq!(default_page.count, 2);
    assert_eq!(default_page.limit, Some(2));
    assert_eq!(default_page.offset, 0);
    assert_eq!(default_page.next_offset, Some(2));
    assert!(default_page.next_cursor.is_some());
    assert_eq!(default_page.items[0].title, "alpha");
    assert_eq!(default_page.items[1].title, "beta");

    let clamped_page_request = test::TestRequest::get()
        .uri("/api/item?limit=99&sort=score&order=asc")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let clamped_page_response = test::call_service(&app, clamped_page_request).await;
    assert_eq!(clamped_page_response.status(), StatusCode::OK);
    let clamped_page: paged_api::ItemListResponse =
        test::read_body_json(clamped_page_response).await;
    assert_eq!(clamped_page.total, 4);
    assert_eq!(clamped_page.count, 3);
    assert_eq!(clamped_page.limit, Some(3));
    assert_eq!(clamped_page.offset, 0);
    assert_eq!(clamped_page.next_offset, Some(3));
    assert!(clamped_page.next_cursor.is_some());
    assert_eq!(clamped_page.items[2].title, "gamma");

    let offset_with_default_request = test::TestRequest::get()
        .uri("/api/item?offset=2&sort=score&order=asc")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let offset_with_default_response = test::call_service(&app, offset_with_default_request).await;
    assert_eq!(offset_with_default_response.status(), StatusCode::OK);
    let offset_with_default: paged_api::ItemListResponse =
        test::read_body_json(offset_with_default_response).await;
    assert_eq!(offset_with_default.total, 4);
    assert_eq!(offset_with_default.count, 2);
    assert_eq!(offset_with_default.limit, Some(2));
    assert_eq!(offset_with_default.offset, 2);
    assert_eq!(offset_with_default.next_offset, None);
    assert_eq!(offset_with_default.next_cursor, None);
    assert_eq!(offset_with_default.items[0].title, "gamma");
    assert_eq!(offset_with_default.items[1].title, "delta");

    let cursor = default_page
        .next_cursor
        .clone()
        .expect("first page should return a next cursor");
    let cursor_page_request = test::TestRequest::get()
        .uri(&format!("/api/item?cursor={cursor}"))
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let cursor_page_response = test::call_service(&app, cursor_page_request).await;
    assert_eq!(cursor_page_response.status(), StatusCode::OK);
    let cursor_page: paged_api::ItemListResponse = test::read_body_json(cursor_page_response).await;
    assert_eq!(cursor_page.total, 4);
    assert_eq!(cursor_page.count, 2);
    assert_eq!(cursor_page.limit, Some(2));
    assert_eq!(cursor_page.offset, 0);
    assert_eq!(cursor_page.next_offset, None);
    assert_eq!(cursor_page.next_cursor, None);
    assert_eq!(cursor_page.items[0].title, "gamma");
    assert_eq!(cursor_page.items[1].title, "delta");

    let invalid_cursor_request = test::TestRequest::get()
        .uri("/api/item?cursor=not-a-valid-cursor")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let invalid_cursor_response = test::call_service(&app, invalid_cursor_request).await;
    assert_eq!(invalid_cursor_response.status(), StatusCode::BAD_REQUEST);

    let cursor_with_offset_request = test::TestRequest::get()
        .uri(&format!("/api/item?cursor={cursor}&offset=2"))
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let cursor_with_offset_response = test::call_service(&app, cursor_with_offset_request).await;
    assert_eq!(
        cursor_with_offset_response.status(),
        StatusCode::BAD_REQUEST
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
