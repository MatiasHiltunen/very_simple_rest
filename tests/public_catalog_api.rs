use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/public_catalog_api.eon");

#[actix_web::test]
async fn public_catalog_resources_allow_anonymous_reads_and_escaped_contains_search() {
    let database_url = unique_sqlite_url("public_catalog");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE organization (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            country TEXT NOT NULL,
            website_url TEXT NOT NULL,
            summary TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("organization schema should apply");
    query(
        "CREATE TABLE interest (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            organization_id INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("interest schema should apply");

    query(
        "INSERT INTO organization (name, country, website_url, summary) VALUES
            ('Nordic Bridge Institute', 'Finland', 'https://nordic.example', 'Cross-border education and industry matching'),
            ('Baltic Industry Lab', 'Estonia', 'https://baltic.example', 'Applied industrial collaboration partner')",
    )
    .execute(&pool)
    .await
    .expect("organization seed data should insert");
    query(
        "INSERT INTO interest (title, summary, organization_id) VALUES
            ('AI Thesis Co-Creation', 'Seeking thesis topics on trustworthy AI and shared supervision', 1),
            ('Mobility Pilot Ideas', 'Open to data-sharing pilots across campuses and ports', 1),
            ('Green Manufacturing Topics', 'Looking for thesis work on industrial decarbonization', 2)",
    )
    .execute(&pool)
    .await
    .expect("interest seed data should insert");

    let app =
        test::init_service(App::new().service(
            scope("/api").configure(|cfg| public_catalog_api::configure(cfg, pool.clone())),
        ))
        .await;

    let list_request = test::TestRequest::get()
        .uri("/api/organization")
        .to_request();
    let list_response = test::call_service(&app, list_request).await;
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body: public_catalog_api::OrganizationListResponse =
        test::read_body_json(list_response).await;
    assert_eq!(list_body.total, 2);
    assert_eq!(list_body.items[0].name, "Nordic Bridge Institute");

    let contains_request = test::TestRequest::get()
        .uri("/api/organization?filter_name_contains=BRIDGE")
        .to_request();
    let contains_response = test::call_service(&app, contains_request).await;
    assert_eq!(contains_response.status(), StatusCode::OK);
    let contains_body: public_catalog_api::OrganizationListResponse =
        test::read_body_json(contains_response).await;
    assert_eq!(contains_body.total, 1);
    assert_eq!(contains_body.items[0].country, "Finland");

    let escaped_percent_request = test::TestRequest::get()
        .uri("/api/organization?filter_name_contains=%25")
        .to_request();
    let escaped_percent_response = test::call_service(&app, escaped_percent_request).await;
    assert_eq!(escaped_percent_response.status(), StatusCode::OK);
    let escaped_percent_body: public_catalog_api::OrganizationListResponse =
        test::read_body_json(escaped_percent_response).await;
    assert_eq!(escaped_percent_body.total, 0);

    let get_one_request = test::TestRequest::get()
        .uri("/api/organization/1")
        .to_request();
    let get_one_response = test::call_service(&app, get_one_request).await;
    assert_eq!(get_one_response.status(), StatusCode::OK);
    let get_one_body: public_catalog_api::Organization =
        test::read_body_json(get_one_response).await;
    assert_eq!(get_one_body.name, "Nordic Bridge Institute");

    let nested_request = test::TestRequest::get()
        .uri("/api/organization/1/interest?filter_summary_contains=THESIS")
        .to_request();
    let nested_response = test::call_service(&app, nested_request).await;
    assert_eq!(nested_response.status(), StatusCode::OK);
    let nested_body: public_catalog_api::InterestListResponse =
        test::read_body_json(nested_response).await;
    assert_eq!(nested_body.total, 1);
    assert_eq!(nested_body.items[0].title, "AI Thesis Co-Creation");

    let create_request = test::TestRequest::post()
        .uri("/api/organization")
        .set_json(json!({
            "name": "Unauthorized Org",
            "country": "Sweden",
            "website_url": "https://unauthorized.example",
            "summary": "Should not be created anonymously"
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::UNAUTHORIZED);
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}
