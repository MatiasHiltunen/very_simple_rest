use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "composed-policies-secret";

rest_api_from_eon!("tests/fixtures/composed_policy_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<i64>,
}

#[derive(Debug, Deserialize, sqlx::FromRow)]
struct DbSharedDoc {
    id: i64,
    owner_id: i64,
    tenant_id: i64,
    blocked_user_id: i64,
    title: String,
}

#[actix_web::test]
async fn composed_row_policies_support_any_of_and_not_with_missing_claim_fallbacks() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("composed_policies");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE shared_doc (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            tenant_id INTEGER NOT NULL,
            blocked_user_id INTEGER NOT NULL,
            title TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("shared_doc table should be created");

    let app =
        test::init_service(App::new().service(
            scope("/api").configure(|cfg| composed_policy_api::configure(cfg, pool.clone())),
        ))
        .await;

    let owner_tenant_1 = issue_token(11, &["user"], Some(1));
    let owner_tenant_1_missing_claim = issue_token(11, &["user"], None);
    let peer_tenant_1 = issue_token(12, &["user"], Some(1));
    let owner_tenant_2 = issue_token(21, &["user"], Some(2));

    let create_visible_to_tenant = test::TestRequest::post()
        .uri("/api/shared_doc")
        .insert_header((
            "Authorization",
            format!("Bearer {}", owner_tenant_1.as_str()),
        ))
        .set_json(&composed_policy_api::SharedDocCreate {
            blocked_user_id: 99,
            title: "visible to tenant".to_owned(),
        })
        .to_request();
    let create_visible_response = test::call_service(&app, create_visible_to_tenant).await;
    assert_eq!(create_visible_response.status(), StatusCode::CREATED);

    let create_blocked_for_peer = test::TestRequest::post()
        .uri("/api/shared_doc")
        .insert_header((
            "Authorization",
            format!("Bearer {}", owner_tenant_1.as_str()),
        ))
        .set_json(&composed_policy_api::SharedDocCreate {
            blocked_user_id: 12,
            title: "blocked for peer".to_owned(),
        })
        .to_request();
    let create_blocked_response = test::call_service(&app, create_blocked_for_peer).await;
    assert_eq!(create_blocked_response.status(), StatusCode::CREATED);

    let create_other_tenant = test::TestRequest::post()
        .uri("/api/shared_doc")
        .insert_header((
            "Authorization",
            format!("Bearer {}", owner_tenant_2.as_str()),
        ))
        .set_json(&composed_policy_api::SharedDocCreate {
            blocked_user_id: 0,
            title: "other tenant".to_owned(),
        })
        .to_request();
    let create_other_tenant_response = test::call_service(&app, create_other_tenant).await;
    assert_eq!(create_other_tenant_response.status(), StatusCode::CREATED);

    let docs: Vec<DbSharedDoc> = query_as::<sqlx::Any, DbSharedDoc>(
        "SELECT id, owner_id, tenant_id, blocked_user_id, title FROM shared_doc ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("created docs should exist");
    assert_eq!(docs.len(), 3);
    assert_eq!(docs[0].owner_id, 11);
    assert_eq!(docs[0].tenant_id, 1);
    assert_eq!(docs[1].blocked_user_id, 12);
    assert_eq!(docs[2].tenant_id, 2);

    let owner_missing_claim_list = test::TestRequest::get()
        .uri("/api/shared_doc")
        .insert_header((
            "Authorization",
            format!("Bearer {}", owner_tenant_1_missing_claim.as_str()),
        ))
        .to_request();
    let owner_missing_claim_response: composed_policy_api::SharedDocListResponse =
        test::call_and_read_body_json(&app, owner_missing_claim_list).await;
    assert_eq!(owner_missing_claim_response.total, 2);
    assert_eq!(owner_missing_claim_response.count, 2);

    let peer_list = test::TestRequest::get()
        .uri("/api/shared_doc")
        .insert_header((
            "Authorization",
            format!("Bearer {}", peer_tenant_1.as_str()),
        ))
        .to_request();
    let peer_response: composed_policy_api::SharedDocListResponse =
        test::call_and_read_body_json(&app, peer_list).await;
    assert_eq!(peer_response.total, 1);
    assert_eq!(peer_response.count, 1);
    assert_eq!(peer_response.items[0].title, "visible to tenant");

    let blocked_doc_id = docs[1].id;
    let blocked_get = test::TestRequest::get()
        .uri(&format!("/api/shared_doc/{blocked_doc_id}"))
        .insert_header((
            "Authorization",
            format!("Bearer {}", peer_tenant_1.as_str()),
        ))
        .to_request();
    let blocked_get_response = test::call_service(&app, blocked_get).await;
    assert_eq!(blocked_get_response.status(), StatusCode::NOT_FOUND);

    let visible_doc_id = docs[0].id;
    let peer_update = test::TestRequest::put()
        .uri(&format!("/api/shared_doc/{visible_doc_id}"))
        .insert_header((
            "Authorization",
            format!("Bearer {}", peer_tenant_1.as_str()),
        ))
        .set_json(&composed_policy_api::SharedDocUpdate {
            title: "tenant peer update".to_owned(),
        })
        .to_request();
    let peer_update_response = test::call_service(&app, peer_update).await;
    assert_eq!(peer_update_response.status(), StatusCode::OK);

    let updated_visible: DbSharedDoc = query_as::<sqlx::Any, DbSharedDoc>(
        "SELECT id, owner_id, tenant_id, blocked_user_id, title FROM shared_doc WHERE id = ?",
    )
    .bind(visible_doc_id)
    .fetch_one(&pool)
    .await
    .expect("updated visible doc should exist");
    assert_eq!(updated_visible.title, "tenant peer update");

    let blocked_update = test::TestRequest::put()
        .uri(&format!("/api/shared_doc/{blocked_doc_id}"))
        .insert_header((
            "Authorization",
            format!("Bearer {}", peer_tenant_1.as_str()),
        ))
        .set_json(&composed_policy_api::SharedDocUpdate {
            title: "should stay blocked".to_owned(),
        })
        .to_request();
    let blocked_update_response = test::call_service(&app, blocked_update).await;
    assert_eq!(blocked_update_response.status(), StatusCode::NOT_FOUND);

    let tenant_2_list = test::TestRequest::get()
        .uri("/api/shared_doc")
        .insert_header((
            "Authorization",
            format!("Bearer {}", owner_tenant_2.as_str()),
        ))
        .to_request();
    let tenant_2_response: composed_policy_api::SharedDocListResponse =
        test::call_and_read_body_json(&app, tenant_2_list).await;
    assert_eq!(tenant_2_response.total, 1);
    assert_eq!(tenant_2_response.count, 1);
    assert_eq!(tenant_2_response.items[0].title, "other tenant");
}

fn issue_token(user_id: i64, roles: &[&str], tenant_id: Option<i64>) -> String {
    encode(
        &Header::default(),
        &TestClaims {
            sub: user_id,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            exp: 4_102_444_800,
            tenant_id,
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
