use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "relation-delete-secret";

rest_api_from_eon!("tests/fixtures/cascade_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn deleting_parent_cascades_child_rows_in_sqlite() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("relation_delete");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE parent (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("parent table should be created");

    query(
        "CREATE TABLE child (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            FOREIGN KEY (parent_id) REFERENCES parent(id) ON DELETE CASCADE
        )",
    )
    .execute(&pool)
    .await
    .expect("child table should be created");

    let app = test::init_service(
        App::new()
            .service(scope("/api").configure(|cfg| cascade_api::configure(cfg, pool.clone()))),
    )
    .await;

    let token = issue_token(1, &["user"]);

    let create_parent = test::TestRequest::post()
        .uri("/api/parent")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(&cascade_api::ParentCreate {
            name: "parent".to_owned(),
        })
        .to_request();
    let create_parent_response = test::call_service(&app, create_parent).await;
    assert_eq!(create_parent_response.status(), StatusCode::CREATED);

    let parent_id: i64 = query_scalar::<sqlx::Any, i64>("SELECT id FROM parent LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("parent row should exist");

    let create_child = test::TestRequest::post()
        .uri("/api/child")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(&cascade_api::ChildCreate {
            parent_id,
            name: "child".to_owned(),
        })
        .to_request();
    let create_child_response = test::call_service(&app, create_child).await;
    assert_eq!(create_child_response.status(), StatusCode::CREATED);

    let child_count: i64 = query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM child")
        .fetch_one(&pool)
        .await
        .expect("child row count should be queryable");
    assert_eq!(child_count, 1);

    let delete_parent = test::TestRequest::delete()
        .uri(&format!("/api/parent/{parent_id}"))
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let delete_parent_response = test::call_service(&app, delete_parent).await;
    assert_eq!(delete_parent_response.status(), StatusCode::OK);

    let remaining_children: i64 = query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM child")
        .fetch_one(&pool)
        .await
        .expect("child row count should be queryable");
    assert_eq!(remaining_children, 0);
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
