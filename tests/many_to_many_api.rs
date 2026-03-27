use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/many_to_many_api.eon");

#[actix_web::test]
async fn generated_handlers_list_many_to_many_routes_via_join_resources() {
    let database_url = unique_sqlite_url("many_to_many_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("post schema should apply");
    query(
        "CREATE TABLE tag (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("tag schema should apply");
    query(
        "CREATE TABLE post_tag (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            tag_id INTEGER NOT NULL,
            FOREIGN KEY (post_id) REFERENCES post(id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id) REFERENCES tag(id) ON DELETE CASCADE
        )",
    )
    .execute(&pool)
    .await
    .expect("join schema should apply");

    query("INSERT INTO post (id, title) VALUES (?, ?), (?, ?)")
        .bind(1_i64)
        .bind("First")
        .bind(2_i64)
        .bind("Second")
        .execute(&pool)
        .await
        .expect("posts should insert");
    query("INSERT INTO tag (id, name) VALUES (?, ?), (?, ?), (?, ?)")
        .bind(1_i64)
        .bind("alpha")
        .bind(2_i64)
        .bind("beta")
        .bind(3_i64)
        .bind("gamma")
        .execute(&pool)
        .await
        .expect("tags should insert");
    query("INSERT INTO post_tag (post_id, tag_id) VALUES (?, ?), (?, ?), (?, ?)")
        .bind(1_i64)
        .bind(1_i64)
        .bind(1_i64)
        .bind(2_i64)
        .bind(2_i64)
        .bind(3_i64)
        .execute(&pool)
        .await
        .expect("join rows should insert");

    let app = test::init_service(
        App::new().service(scope("/api").configure(|cfg| many_to_many_api::configure(cfg, pool.clone()))),
    )
    .await;

    let list_request = test::TestRequest::get()
        .uri("/api/posts/1/tags?sort=name")
        .to_request();
    let list_response = test::call_service(&app, list_request).await;
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body: Value = test::read_body_json(list_response).await;
    assert_eq!(list_body["total"], 2);
    assert_eq!(list_body["items"][0]["name"], "alpha");
    assert_eq!(list_body["items"][1]["name"], "beta");

    let filtered_request = test::TestRequest::get()
        .uri("/api/posts/1/tags?filter_name=beta")
        .to_request();
    let filtered_response = test::call_service(&app, filtered_request).await;
    assert_eq!(filtered_response.status(), StatusCode::OK);
    let filtered_body: Value = test::read_body_json(filtered_response).await;
    assert_eq!(filtered_body["total"], 1);
    assert_eq!(filtered_body["items"][0]["name"], "beta");

    let second_post_request = test::TestRequest::get().uri("/api/posts/2/tags").to_request();
    let second_post_response = test::call_service(&app, second_post_request).await;
    assert_eq!(second_post_response.status(), StatusCode::OK);
    let second_post_body: Value = test::read_body_json(second_post_response).await;
    assert_eq!(second_post_body["total"], 1);
    assert_eq!(second_post_body["items"][0]["name"], "gamma");
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}
