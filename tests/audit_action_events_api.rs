use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::Row;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "audit-action-events-api-secret";

rest_api_from_eon!("tests/fixtures/audit_action_events_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn generated_handlers_write_audit_events_for_resource_actions() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("audit_action_events_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");
    pool.execute_batch(
        "CREATE TABLE post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            slug TEXT NOT NULL,
            status TEXT NOT NULL
        );
        CREATE TABLE audit_event (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_kind TEXT NOT NULL,
            resource_name TEXT NOT NULL,
            record_id INTEGER NOT NULL,
            actor_user_id INTEGER,
            actor_roles_json TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
    )
    .await
    .expect("schema should apply");

    query("INSERT INTO post (id, title, slug, status) VALUES (?, ?, ?, ?)")
        .bind(1_i64)
        .bind("Draft")
        .bind("draft")
        .bind("draft")
        .execute(&pool)
        .await
        .expect("seed row should insert");

    let app = test::init_service(App::new().service(
        scope("/api").configure(|cfg| audit_action_events_api::configure(cfg, pool.clone())),
    ))
    .await;
    let token = issue_token(7, &["editor"]);

    let publish_request = test::TestRequest::post()
        .uri("/api/posts/1/go-live")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let publish_response = test::call_service(&app, publish_request).await;
    assert_eq!(publish_response.status(), StatusCode::OK);

    let rename_request = test::TestRequest::post()
        .uri("/api/posts/1/rename")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(json!({
            "newTitle": "Fresh Launch",
            "newSlug": " Fresh   Launch! ",
            "newStatus": " REVIEW "
        }))
        .to_request();
    let rename_response = test::call_service(&app, rename_request).await;
    assert_eq!(rename_response.status(), StatusCode::OK);

    let purge_request = test::TestRequest::post()
        .uri("/api/posts/1/purge")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let purge_response = test::call_service(&app, purge_request).await;
    assert_eq!(purge_response.status(), StatusCode::OK);

    let audit_rows = query(
        "SELECT event_kind, resource_name, record_id, actor_user_id, actor_roles_json, payload_json \
         FROM audit_event ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("audit rows should query");
    assert_eq!(audit_rows.len(), 3);

    let event_kinds = audit_rows
        .iter()
        .map(|row| {
            row.try_get::<String, _>("event_kind")
                .expect("event kind should decode")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        event_kinds,
        vec!["action:publish", "update", "action:purge"]
    );

    for row in &audit_rows {
        assert_eq!(
            row.try_get::<String, _>("resource_name")
                .expect("resource name should decode"),
            "Post"
        );
        assert_eq!(
            row.try_get::<i64, _>("record_id")
                .expect("record id should decode"),
            1
        );
        assert_eq!(
            row.try_get::<i64, _>("actor_user_id")
                .expect("actor user id should decode"),
            7
        );
        assert_eq!(
            row.try_get::<String, _>("actor_roles_json")
                .expect("actor roles should decode"),
            r#"["editor"]"#
        );
    }

    let publish_payload: Value = serde_json::from_str(
        &audit_rows[0]
            .try_get::<String, _>("payload_json")
            .expect("publish payload should decode"),
    )
    .expect("publish payload should parse");
    assert_eq!(publish_payload["before"]["status"], "draft");
    assert_eq!(publish_payload["after"]["status"], "published");
    assert_eq!(publish_payload["after"]["slug"], "launch-post");

    let rename_payload: Value = serde_json::from_str(
        &audit_rows[1]
            .try_get::<String, _>("payload_json")
            .expect("rename payload should decode"),
    )
    .expect("rename payload should parse");
    assert_eq!(rename_payload["before"]["title"], "Draft");
    assert_eq!(rename_payload["after"]["title"], "Fresh Launch");
    assert_eq!(rename_payload["after"]["slug"], "fresh-launch");
    assert_eq!(rename_payload["after"]["status"], "review");

    let purge_payload: Value = serde_json::from_str(
        &audit_rows[2]
            .try_get::<String, _>("payload_json")
            .expect("purge payload should decode"),
    )
    .expect("purge payload should parse");
    assert_eq!(purge_payload["before"]["title"], "Fresh Launch");
    assert!(purge_payload.get("after").is_none());
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
