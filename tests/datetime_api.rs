use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "datetime-api-secret";

rest_api_from_eon!("tests/fixtures/datetime_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    code: String,
    message: String,
    field: Option<String>,
}

#[actix_web::test]
async fn generated_handlers_support_datetime_payloads_filters_and_cursors() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("datetime_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE event (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            starts_at TEXT NOT NULL,
            ends_at TEXT,
            created_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now')),
            updated_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now'))
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    let beta_start = parse_datetime("2026-03-17T12:00:00Z");
    let gamma_start = parse_datetime("2026-03-17T14:00:00Z");

    query("INSERT INTO event (title, starts_at, ends_at) VALUES (?, ?, ?)")
        .bind("beta")
        .bind(beta_start)
        .bind(Option::<very_simple_rest::chrono::DateTime<very_simple_rest::chrono::Utc>>::None)
        .execute(&pool)
        .await
        .expect("beta row should insert");

    query("INSERT INTO event (title, starts_at, ends_at) VALUES (?, ?, ?)")
        .bind("gamma")
        .bind(gamma_start)
        .bind(Some(parse_datetime("2026-03-17T15:00:00Z")))
        .execute(&pool)
        .await
        .expect("gamma row should insert");

    let app = test::init_service(
        App::new()
            .service(scope("/api").configure(|cfg| datetime_api::configure(cfg, pool.clone()))),
    )
    .await;

    let token = issue_token(1, &["user"]);

    let create_request = test::TestRequest::post()
        .uri("/api/event")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "title": "alpha",
            "starts_at": "2026-03-17T10:00:00Z",
            "ends_at": "2026-03-17T11:00:00Z"
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let exact_request = test::TestRequest::get()
        .uri("/api/event?filter_starts_at=2026-03-17T10:00:00Z")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let exact_response = test::call_service(&app, exact_request).await;
    assert_eq!(exact_response.status(), StatusCode::OK);
    let exact_page: datetime_api::EventListResponse = test::read_body_json(exact_response).await;
    assert_eq!(exact_page.total, 1);
    assert_eq!(exact_page.items[0].title, "alpha");
    assert_eq!(
        exact_page.items[0].starts_at,
        parse_datetime("2026-03-17T10:00:00Z")
    );
    assert_eq!(
        exact_page.items[0].ends_at,
        Some(parse_datetime("2026-03-17T11:00:00Z"))
    );
    assert!(exact_page.items[0].created_at.is_some());
    assert!(exact_page.items[0].updated_at.is_some());

    let ranged_request = test::TestRequest::get()
        .uri("/api/event?filter_starts_at_gte=2026-03-17T11:00:00Z&filter_starts_at_lt=2026-03-17T14:00:00Z&sort=starts_at&order=asc")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let ranged_response = test::call_service(&app, ranged_request).await;
    assert_eq!(ranged_response.status(), StatusCode::OK);
    let ranged_page: datetime_api::EventListResponse = test::read_body_json(ranged_response).await;
    assert_eq!(ranged_page.total, 1);
    assert_eq!(ranged_page.items[0].title, "beta");
    assert_eq!(ranged_page.items[0].starts_at, beta_start);

    let first_cursor_request = test::TestRequest::get()
        .uri("/api/event?limit=1&sort=starts_at&order=asc")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let first_cursor_response = test::call_service(&app, first_cursor_request).await;
    assert_eq!(first_cursor_response.status(), StatusCode::OK);
    let first_cursor_page: datetime_api::EventListResponse =
        test::read_body_json(first_cursor_response).await;
    assert_eq!(first_cursor_page.items[0].title, "alpha");
    assert_eq!(first_cursor_page.next_offset, Some(1));
    let next_cursor = first_cursor_page
        .next_cursor
        .clone()
        .expect("first page should return a cursor");

    let second_cursor_request = test::TestRequest::get()
        .uri(&format!("/api/event?cursor={next_cursor}"))
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let second_cursor_response = test::call_service(&app, second_cursor_request).await;
    assert_eq!(second_cursor_response.status(), StatusCode::OK);
    let second_cursor_page: datetime_api::EventListResponse =
        test::read_body_json(second_cursor_response).await;
    assert_eq!(second_cursor_page.items[0].title, "beta");
    assert_eq!(second_cursor_page.items[0].starts_at, beta_start);

    let invalid_datetime_request = test::TestRequest::get()
        .uri("/api/event?filter_starts_at_gt=not-a-datetime")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let invalid_datetime_response = test::call_service(&app, invalid_datetime_request).await;
    assert_eq!(invalid_datetime_response.status(), StatusCode::BAD_REQUEST);
    let invalid_datetime_body: ApiErrorResponse =
        test::read_body_json(invalid_datetime_response).await;
    assert_eq!(invalid_datetime_body.code, "invalid_query");
    assert_eq!(
        invalid_datetime_body.message,
        "Query parameters are invalid"
    );
    assert_eq!(invalid_datetime_body.field, None);
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

fn parse_datetime(
    value: &str,
) -> very_simple_rest::chrono::DateTime<very_simple_rest::chrono::Utc> {
    value.parse().expect("datetime should parse")
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}
