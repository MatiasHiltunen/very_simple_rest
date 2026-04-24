use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/batched_list_api.eon");

#[derive(Debug, Deserialize)]
struct CountResponse {
    count: i64,
}

#[actix_web::test]
async fn generated_handlers_support_filter_in_count_and_limit_zero() {
    let database_url = unique_sqlite_url("list_filter_in_count");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE entry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            score INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    query(
        "INSERT INTO entry (category, score) VALUES
            ('news', 2),
            ('docs', 7),
            ('news', 11)",
    )
    .execute(&pool)
    .await
    .expect("seed rows should insert");

    let app = test::init_service(
        App::new()
            .service(scope("/api").configure(|cfg| batched_list_api::configure(cfg, pool.clone()))),
    )
    .await;

    let filter_in_request = test::TestRequest::get()
        .uri("/api/entry?filter_score__in=2,7&sort=score")
        .to_request();
    let filter_in_response = test::call_service(&app, filter_in_request).await;
    assert_eq!(filter_in_response.status(), StatusCode::OK);
    let filter_in: batched_list_api::EntryListResponse =
        test::read_body_json(filter_in_response).await;
    assert_eq!(filter_in.total, 2);
    assert_eq!(filter_in.count, 2);
    assert_eq!(filter_in.items[0].score, 2);
    assert_eq!(filter_in.items[1].score, 7);

    let limit_zero_request = test::TestRequest::get()
        .uri("/api/entry?limit=0")
        .to_request();
    let limit_zero_response = test::call_service(&app, limit_zero_request).await;
    assert_eq!(limit_zero_response.status(), StatusCode::OK);
    let limit_zero: batched_list_api::EntryListResponse =
        test::read_body_json(limit_zero_response).await;
    assert_eq!(limit_zero.total, 3);
    assert_eq!(limit_zero.count, 0);
    assert_eq!(limit_zero.limit, Some(0));
    assert!(limit_zero.items.is_empty());
    assert_eq!(limit_zero.next_offset, None);
    assert_eq!(limit_zero.next_cursor, None);

    let count_request = test::TestRequest::get()
        .uri("/api/entry/count?filter_score__in=2,7")
        .to_request();
    let count_response = test::call_service(&app, count_request).await;
    assert_eq!(count_response.status(), StatusCode::OK);
    let count: CountResponse = test::read_body_json(count_response).await;
    assert_eq!(count.count, 2);

    let too_many_request = test::TestRequest::get()
        .uri("/api/entry?filter_score__in=2,7,11")
        .to_request();
    let too_many_response = test::call_service(&app, too_many_request).await;
    assert_eq!(too_many_response.status(), StatusCode::BAD_REQUEST);

    let not_configured_request = test::TestRequest::get()
        .uri("/api/entry?filter_category__in=news,docs")
        .to_request();
    let not_configured_response = test::call_service(&app, not_configured_request).await;
    assert_eq!(not_configured_response.status(), StatusCode::BAD_REQUEST);
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}
