use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "exists-policies-secret";

rest_api_from_eon!("tests/fixtures/exists_policy_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[derive(Debug, Deserialize, sqlx::FromRow)]
struct DbSharedDoc {
    id: i64,
    family_id: i64,
    title: String,
}

#[actix_web::test]
async fn exists_row_policies_allow_family_membership_checks() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("exists_policies");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE family_member (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            family_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("family_member table should be created");

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

    query("INSERT INTO family_member (family_id, user_id) VALUES (?, ?), (?, ?)")
        .bind(1_i64)
        .bind(11_i64)
        .bind(2_i64)
        .bind(21_i64)
        .execute(&pool)
        .await
        .expect("family memberships should insert");

    query("INSERT INTO shared_doc (family_id, title) VALUES (?, ?), (?, ?)")
        .bind(1_i64)
        .bind("family one")
        .bind(2_i64)
        .bind("family two")
        .execute(&pool)
        .await
        .expect("shared docs should insert");

    let app =
        test::init_service(App::new().service(
            scope("/api").configure(|cfg| exists_policy_api::configure(cfg, pool.clone())),
        ))
        .await;

    let family_one_user = issue_token(11, &[]);
    let family_two_user = issue_token(21, &[]);
    let outsider = issue_token(99, &[]);

    let family_one_list = test::TestRequest::get()
        .uri("/api/shared_doc")
        .insert_header(("Authorization", format!("Bearer {}", family_one_user)))
        .to_request();
    let family_one_response: exists_policy_api::SharedDocListResponse =
        test::call_and_read_body_json(&app, family_one_list).await;
    assert_eq!(family_one_response.total, 1);
    assert_eq!(family_one_response.items[0].title, "family one");

    let family_two_list = test::TestRequest::get()
        .uri("/api/shared_doc")
        .insert_header(("Authorization", format!("Bearer {}", family_two_user)))
        .to_request();
    let family_two_response: exists_policy_api::SharedDocListResponse =
        test::call_and_read_body_json(&app, family_two_list).await;
    assert_eq!(family_two_response.total, 1);
    assert_eq!(family_two_response.items[0].title, "family two");

    let outsider_list = test::TestRequest::get()
        .uri("/api/shared_doc")
        .insert_header(("Authorization", format!("Bearer {}", outsider)))
        .to_request();
    let outsider_response: exists_policy_api::SharedDocListResponse =
        test::call_and_read_body_json(&app, outsider_list).await;
    assert_eq!(outsider_response.total, 0);
    assert!(outsider_response.items.is_empty());

    let family_one_get = test::TestRequest::get()
        .uri("/api/shared_doc/1")
        .insert_header(("Authorization", format!("Bearer {}", family_one_user)))
        .to_request();
    let family_one_get_response = test::call_service(&app, family_one_get).await;
    assert_eq!(family_one_get_response.status(), StatusCode::OK);

    let blocked_get = test::TestRequest::get()
        .uri("/api/shared_doc/2")
        .insert_header(("Authorization", format!("Bearer {}", family_one_user)))
        .to_request();
    let blocked_get_response = test::call_service(&app, blocked_get).await;
    assert_eq!(blocked_get_response.status(), StatusCode::NOT_FOUND);

    let update_allowed = test::TestRequest::put()
        .uri("/api/shared_doc/1")
        .insert_header(("Authorization", format!("Bearer {}", family_one_user)))
        .set_json(&exists_policy_api::SharedDocUpdate {
            title: "family one updated".to_owned(),
        })
        .to_request();
    let update_allowed_response = test::call_service(&app, update_allowed).await;
    assert_eq!(update_allowed_response.status(), StatusCode::OK);

    let updated_doc: DbSharedDoc = query_as::<sqlx::Any, DbSharedDoc>(
        "SELECT id, family_id, title FROM shared_doc WHERE id = ?",
    )
    .bind(1_i64)
    .fetch_one(&pool)
    .await
    .expect("updated shared doc should load");
    assert_eq!(updated_doc.id, 1);
    assert_eq!(updated_doc.family_id, 1);
    assert_eq!(updated_doc.title, "family one updated");

    let update_denied = test::TestRequest::put()
        .uri("/api/shared_doc/2")
        .insert_header(("Authorization", format!("Bearer {}", family_one_user)))
        .set_json(&exists_policy_api::SharedDocUpdate {
            title: "should stay denied".to_owned(),
        })
        .to_request();
    let update_denied_response = test::call_service(&app, update_denied).await;
    assert_eq!(update_denied_response.status(), StatusCode::NOT_FOUND);

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
