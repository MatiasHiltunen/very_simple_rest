use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "exists-group-policies-secret";

rest_api_from_eon!("tests/fixtures/exists_group_policy_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn exists_row_policies_support_nested_any_of_membership_checks() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("exists_group_policies");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE family_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            family_id INTEGER NOT NULL,
            primary_user_id INTEGER NOT NULL,
            delegate_user_id INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("family_access table should be created");

    query(
        "CREATE TABLE shared_doc (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            family_id INTEGER NOT NULL,
            title TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("shared_doc table should be created");

    query(
        "INSERT INTO family_access (family_id, primary_user_id, delegate_user_id) VALUES (?, ?, ?), (?, ?, ?)",
    )
    .bind(1_i64)
    .bind(11_i64)
    .bind(12_i64)
    .bind(2_i64)
    .bind(21_i64)
    .bind(22_i64)
    .execute(&pool)
    .await
    .expect("family access rows should insert");

    query("INSERT INTO shared_doc (family_id, title) VALUES (?, ?), (?, ?)")
        .bind(1_i64)
        .bind("family one")
        .bind(2_i64)
        .bind("family two")
        .execute(&pool)
        .await
        .expect("shared docs should insert");

    let app = test::init_service(App::new().service(
        scope("/api").configure(|cfg| exists_group_policy_api::configure(cfg, pool.clone())),
    ))
    .await;

    for (user_id, expected_title) in [
        (11_i64, "family one"),
        (12_i64, "family one"),
        (21_i64, "family two"),
    ] {
        let token = issue_token(user_id, &[]);
        let request = test::TestRequest::get()
            .uri("/api/shared_doc")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();
        let response: exists_group_policy_api::SharedDocListResponse =
            test::call_and_read_body_json(&app, request).await;
        assert_eq!(
            response.total, 1,
            "unexpected visible row count for user {user_id}"
        );
        assert_eq!(response.items[0].title, expected_title);
    }

    let outsider = issue_token(99, &[]);
    let outsider_request = test::TestRequest::get()
        .uri("/api/shared_doc/1")
        .insert_header(("Authorization", format!("Bearer {}", outsider)))
        .to_request();
    let outsider_response = test::call_service(&app, outsider_request).await;
    assert_eq!(outsider_response.status(), StatusCode::NOT_FOUND);

    unsafe {
        std::env::remove_var("JWT_SECRET");
    }
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
