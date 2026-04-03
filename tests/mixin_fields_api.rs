use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::json;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "mixin-fields-api-secret";

rest_api_from_eon!("tests/fixtures/mixin_fields_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn generated_handlers_expand_local_mixins_into_runtime_schema() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("mixin_fields_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            slug TEXT NOT NULL,
            title TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now')),
            updated_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now'))
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    query(
        "INSERT INTO post (tenant_id, slug, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(7_i64)
    .bind("alpha")
    .bind("Alpha")
    .bind("2026-03-27T09:00:00Z")
    .bind("2026-03-27T09:15:00Z")
    .execute(&pool)
    .await
    .expect("seed row should insert");

    let app = test::init_service(
        App::new()
            .service(scope("/api").configure(|cfg| mixin_fields_api::configure(cfg, pool.clone()))),
    )
    .await;
    let token = issue_token(1, &["user"]);

    let create_request = test::TestRequest::post()
        .uri("/api/post")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "tenant_id": 7,
            "slug": "beta",
            "title": "Beta"
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    let create_status = create_response.status();
    let create_body = test::read_body(create_response).await;
    assert_eq!(
        create_status,
        StatusCode::CREATED,
        "unexpected create response: {}",
        String::from_utf8_lossy(&create_body)
    );
    let created: mixin_fields_api::Post =
        serde_json::from_slice(&create_body).expect("create response should be valid JSON");
    assert_eq!(created.slug, "beta");
    assert_eq!(created.tenant_id, 7);
    assert!(created.created_at.is_some());
    assert!(created.updated_at.is_some());

    let list_request = test::TestRequest::get()
        .uri("/api/post?filter_tenant_id=7&sort=slug")
        .to_request();
    let list_response = test::call_service(&app, list_request).await;
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_page: mixin_fields_api::PostListResponse = test::read_body_json(list_response).await;
    assert_eq!(list_page.total, 2);
    assert_eq!(list_page.items[0].slug, "alpha");
    assert_eq!(list_page.items[1].slug, "beta");
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
