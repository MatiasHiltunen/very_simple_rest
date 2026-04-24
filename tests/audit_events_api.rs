use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::Row;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query, query_scalar};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "audit-events-api-secret";

rest_api_from_eon!("tests/fixtures/audit_events_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[actix_web::test]
async fn generated_handlers_write_audit_events_and_keep_sink_read_only() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("audit_events_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");
    pool.execute_batch(
        "CREATE TABLE post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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

    let app = test::init_service(
        App::new()
            .service(scope("/api").configure(|cfg| audit_events_api::configure(cfg, pool.clone()))),
    )
    .await;
    let user_token = issue_token(7, &["user"]);
    let admin_token = issue_token(1, &["admin"]);

    let create_request = test::TestRequest::post()
        .uri("/api/posts")
        .insert_header(("Authorization", format!("Bearer {}", user_token.as_str())))
        .set_json(json!({
            "title": "First title"
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let update_request = test::TestRequest::put()
        .uri("/api/posts/1")
        .insert_header(("Authorization", format!("Bearer {}", user_token.as_str())))
        .set_json(json!({
            "title": "Updated title"
        }))
        .to_request();
    let update_response = test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::OK);

    let delete_request = test::TestRequest::delete()
        .uri("/api/posts/1")
        .insert_header(("Authorization", format!("Bearer {}", user_token.as_str())))
        .to_request();
    let delete_response = test::call_service(&app, delete_request).await;
    assert_eq!(delete_response.status(), StatusCode::OK);

    let audit_count = query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM audit_event")
        .fetch_one(&pool)
        .await
        .expect("audit count should query");
    assert_eq!(audit_count, 3);

    let audit_rows = query(
        "SELECT event_kind, resource_name, record_id, actor_user_id, actor_roles_json, payload_json \
         FROM audit_event ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("audit rows should query");
    let event_kinds = audit_rows
        .iter()
        .map(|row| {
            row.try_get::<String, _>("event_kind")
                .expect("event kind should decode")
        })
        .collect::<Vec<_>>();
    assert_eq!(event_kinds, vec!["create", "update", "delete"]);
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
            r#"["user"]"#
        );
    }

    let create_payload: Value = serde_json::from_str(
        &audit_rows[0]
            .try_get::<String, _>("payload_json")
            .expect("create payload should decode"),
    )
    .expect("create payload should parse");
    assert_eq!(create_payload["after"]["title"], "First title");

    let update_payload: Value = serde_json::from_str(
        &audit_rows[1]
            .try_get::<String, _>("payload_json")
            .expect("update payload should decode"),
    )
    .expect("update payload should parse");
    assert_eq!(update_payload["before"]["title"], "First title");
    assert_eq!(update_payload["after"]["title"], "Updated title");

    let delete_payload: Value = serde_json::from_str(
        &audit_rows[2]
            .try_get::<String, _>("payload_json")
            .expect("delete payload should decode"),
    )
    .expect("delete payload should parse");
    assert_eq!(delete_payload["before"]["title"], "Updated title");
    assert!(delete_payload.get("after").is_none());

    let create_sink_request = test::TestRequest::post()
        .uri("/api/audit-events")
        .insert_header(("Authorization", format!("Bearer {}", admin_token.as_str())))
        .set_json(json!({
            "event_kind": "manual"
        }))
        .to_request();
    let create_sink_response = test::call_service(&app, create_sink_request).await;
    assert_eq!(
        create_sink_response.status(),
        StatusCode::METHOD_NOT_ALLOWED
    );

    let update_sink_request = test::TestRequest::put()
        .uri("/api/audit-events/1")
        .insert_header(("Authorization", format!("Bearer {}", admin_token.as_str())))
        .set_json(json!({
            "event_kind": "manual"
        }))
        .to_request();
    let update_sink_response = test::call_service(&app, update_sink_request).await;
    assert_eq!(
        update_sink_response.status(),
        StatusCode::METHOD_NOT_ALLOWED
    );

    let list_sink_request = test::TestRequest::get()
        .uri("/api/audit-events")
        .insert_header(("Authorization", format!("Bearer {}", admin_token.as_str())))
        .to_request();
    let list_sink_response = test::call_service(&app, list_sink_request).await;
    assert_eq!(list_sink_response.status(), StatusCode::OK);
    let list_sink_body: Value = test::read_body_json(list_sink_response).await;
    assert_eq!(list_sink_body["count"], 3);
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
