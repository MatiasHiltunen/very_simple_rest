use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "scalar-types-api-secret";

rest_api_from_eon!("tests/fixtures/scalar_types_api.eon");

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
async fn generated_handlers_support_portable_scalar_payloads_filters_and_cursors() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("scalar_types_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_on TEXT NOT NULL,
            run_at TEXT NOT NULL,
            external_id TEXT NOT NULL,
            amount TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    let beta_uuid = parse_uuid("11111111-1111-4111-8111-111111111111");
    let gamma_uuid = parse_uuid("22222222-2222-4222-8222-222222222222");
    let alpha_uuid = parse_uuid("33333333-3333-4333-8333-333333333333");

    query("INSERT INTO schedule (run_on, run_at, external_id, amount) VALUES (?, ?, ?, ?)")
        .bind(parse_date("2026-03-18"))
        .bind(parse_time("09:30:00"))
        .bind(beta_uuid.clone())
        .bind(parse_decimal("12.3400"))
        .execute(&pool)
        .await
        .expect("beta row should insert");

    query("INSERT INTO schedule (run_on, run_at, external_id, amount) VALUES (?, ?, ?, ?)")
        .bind(parse_date("2026-03-19"))
        .bind(parse_time("14:15:30.25"))
        .bind(gamma_uuid)
        .bind(parse_decimal("99.900"))
        .execute(&pool)
        .await
        .expect("gamma row should insert");

    let app = test::init_service(
        App::new()
            .service(scope("/api").configure(|cfg| scalar_types_api::configure(cfg, pool.clone()))),
    )
    .await;

    let token = issue_token(1, &["user"]);

    let create_request = test::TestRequest::post()
        .uri("/api/schedule")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "run_on": "2026-03-17",
            "run_at": "08:00:00",
            "external_id": alpha_uuid.to_string(),
            "amount": "1.5000"
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let alpha_filter_request = test::TestRequest::get()
        .uri(&format!("/api/schedule?filter_external_id={alpha_uuid}"))
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let alpha_filter_response = test::call_service(&app, alpha_filter_request).await;
    assert_eq!(alpha_filter_response.status(), StatusCode::OK);
    let alpha_filter_page: scalar_types_api::ScheduleListResponse =
        test::read_body_json(alpha_filter_response).await;
    assert_eq!(alpha_filter_page.total, 1);
    assert_eq!(alpha_filter_page.items[0].run_on, parse_date("2026-03-17"));
    assert_eq!(alpha_filter_page.items[0].run_at, parse_time("08:00:00"));
    assert_eq!(alpha_filter_page.items[0].external_id, alpha_uuid);
    assert_eq!(alpha_filter_page.items[0].amount, parse_decimal("1.5"));

    let uuid_filter_request = test::TestRequest::get()
        .uri(&format!("/api/schedule?filter_external_id={beta_uuid}"))
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let uuid_filter_response = test::call_service(&app, uuid_filter_request).await;
    assert_eq!(uuid_filter_response.status(), StatusCode::OK);
    let uuid_filter_page: scalar_types_api::ScheduleListResponse =
        test::read_body_json(uuid_filter_response).await;
    assert_eq!(uuid_filter_page.total, 1);
    assert_eq!(uuid_filter_page.items[0].external_id, beta_uuid);

    let amount_filter_request = test::TestRequest::get()
        .uri("/api/schedule?filter_amount=12.34")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let amount_filter_response = test::call_service(&app, amount_filter_request).await;
    assert_eq!(amount_filter_response.status(), StatusCode::OK);
    let amount_filter_page: scalar_types_api::ScheduleListResponse =
        test::read_body_json(amount_filter_response).await;
    assert_eq!(amount_filter_page.total, 1);
    assert_eq!(amount_filter_page.items[0].amount, parse_decimal("12.34"));

    let date_range_request = test::TestRequest::get()
        .uri("/api/schedule?limit=10&filter_run_on_gte=2026-03-18&filter_run_on_lt=2026-03-20&sort=run_on&order=asc")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let date_range_response = test::call_service(&app, date_range_request).await;
    assert_eq!(date_range_response.status(), StatusCode::OK);
    let date_range_page: scalar_types_api::ScheduleListResponse =
        test::read_body_json(date_range_response).await;
    assert_eq!(date_range_page.total, 2);
    assert_eq!(date_range_page.items[0].run_on, parse_date("2026-03-18"));
    assert_eq!(date_range_page.items[1].run_on, parse_date("2026-03-19"));

    let time_range_request = test::TestRequest::get()
        .uri("/api/schedule?limit=10&filter_run_at_gt=09:00:00&filter_run_at_lte=14:15:30.250000&sort=run_at&order=asc")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let time_range_response = test::call_service(&app, time_range_request).await;
    assert_eq!(time_range_response.status(), StatusCode::OK);
    let time_range_page: scalar_types_api::ScheduleListResponse =
        test::read_body_json(time_range_response).await;
    assert_eq!(time_range_page.total, 2);
    assert_eq!(time_range_page.items[0].run_at, parse_time("09:30:00"));
    assert_eq!(time_range_page.items[1].run_at, parse_time("14:15:30.25"));

    let first_cursor_request = test::TestRequest::get()
        .uri("/api/schedule?limit=1&sort=run_at&order=asc")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let first_cursor_response = test::call_service(&app, first_cursor_request).await;
    assert_eq!(first_cursor_response.status(), StatusCode::OK);
    let first_cursor_page: scalar_types_api::ScheduleListResponse =
        test::read_body_json(first_cursor_response).await;
    assert_eq!(first_cursor_page.items[0].run_at, parse_time("08:00:00"));
    let next_cursor = first_cursor_page
        .next_cursor
        .clone()
        .expect("first page should return a cursor");

    let second_cursor_request = test::TestRequest::get()
        .uri(&format!("/api/schedule?cursor={next_cursor}"))
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let second_cursor_response = test::call_service(&app, second_cursor_request).await;
    assert_eq!(second_cursor_response.status(), StatusCode::OK);
    let second_cursor_page: scalar_types_api::ScheduleListResponse =
        test::read_body_json(second_cursor_response).await;
    assert_eq!(second_cursor_page.items[0].run_at, parse_time("09:30:00"));

    let invalid_uuid_request = test::TestRequest::get()
        .uri("/api/schedule?filter_external_id=not-a-uuid")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let invalid_uuid_response = test::call_service(&app, invalid_uuid_request).await;
    assert_eq!(invalid_uuid_response.status(), StatusCode::BAD_REQUEST);
    let invalid_uuid_body: ApiErrorResponse = test::read_body_json(invalid_uuid_response).await;
    assert_eq!(invalid_uuid_body.code, "invalid_query");
    assert_eq!(invalid_uuid_body.message, "Query parameters are invalid");
    assert_eq!(invalid_uuid_body.field, None);

    let unsupported_sort_request = test::TestRequest::get()
        .uri("/api/schedule?sort=amount")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let unsupported_sort_response = test::call_service(&app, unsupported_sort_request).await;
    assert_eq!(unsupported_sort_response.status(), StatusCode::BAD_REQUEST);
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

fn parse_date(value: &str) -> very_simple_rest::chrono::NaiveDate {
    value.parse().expect("date should parse")
}

fn parse_time(value: &str) -> very_simple_rest::chrono::NaiveTime {
    value.parse().expect("time should parse")
}

fn parse_uuid(value: &str) -> very_simple_rest::uuid::Uuid {
    value.parse().expect("uuid should parse")
}

fn parse_decimal(value: &str) -> very_simple_rest::rust_decimal::Decimal {
    value.parse().expect("decimal should parse")
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}
