use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/create_require_api.eon");

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_create_require_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}

#[actix_web::test]
async fn create_require_exists_allows_owner_bootstrap_and_blocks_outsiders() {
    unsafe {
        std::env::set_var("JWT_SECRET", "create-require-secret");
    }

    let database_url = unique_sqlite_url("family");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    for statement in very_simple_rest::core::auth::auth_migration_sql(
        very_simple_rest::core::auth::AuthDbBackend::Sqlite,
    )
    .split(';')
    .map(str::trim)
    .filter(|statement| !statement.is_empty())
    {
        query(statement)
            .execute(&pool)
            .await
            .expect("auth migration should apply");
    }

    query(
        "CREATE TABLE family (\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            owner_user_id INTEGER NOT NULL,\
            name TEXT NOT NULL\
        )",
    )
    .execute(&pool)
    .await
    .expect("family table should create");
    query(
        "CREATE TABLE family_member (\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            family_id INTEGER NOT NULL,\
            user_id INTEGER NOT NULL,\
            created_by_user_id INTEGER NOT NULL,\
            display_name TEXT NOT NULL\
        )",
    )
    .execute(&pool)
    .await
    .expect("family_member table should create");

    let app = test::init_service(App::new().service(scope("/api").configure(|cfg| {
        auth::auth_routes(cfg, pool.clone());
        create_require_api::configure(cfg, pool.clone());
    })))
    .await;

    for email in ["alice@example.com", "bob@example.com"] {
        let register = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(&auth::RegisterInput {
                email: email.to_owned(),
                password: "password123".to_owned(),
            })
            .to_request();
        let response = test::call_service(&app, register).await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let alice_login = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "alice@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let alice_token: TokenResponse = test::call_and_read_body_json(&app, alice_login).await;

    let bob_login = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "bob@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let bob_token: TokenResponse = test::call_and_read_body_json(&app, bob_login).await;

    let create_family = test::TestRequest::post()
        .uri("/api/family")
        .insert_header(("Authorization", format!("Bearer {}", alice_token.token)))
        .set_json(&create_require_api::FamilyCreate {
            name: "Alice Family".to_owned(),
        })
        .to_request();
    let family: create_require_api::Family =
        test::call_and_read_body_json(&app, create_family).await;
    let family_id = family.id.expect("family should expose id");

    let create_member_as_owner = test::TestRequest::post()
        .uri("/api/family_member")
        .insert_header(("Authorization", format!("Bearer {}", alice_token.token)))
        .set_json(&create_require_api::FamilyMemberCreate {
            family_id,
            user_id: 2,
            display_name: "Bob".to_owned(),
        })
        .to_request();
    let created_member_response = test::call_service(&app, create_member_as_owner).await;
    assert_eq!(created_member_response.status(), StatusCode::CREATED);

    let create_member_as_outsider = test::TestRequest::post()
        .uri("/api/family_member")
        .insert_header(("Authorization", format!("Bearer {}", bob_token.token)))
        .set_json(&create_require_api::FamilyMemberCreate {
            family_id,
            user_id: 1,
            display_name: "Alice".to_owned(),
        })
        .to_request();
    let outsider_response = test::call_service(&app, create_member_as_outsider).await;
    assert_eq!(outsider_response.status(), StatusCode::FORBIDDEN);
}
