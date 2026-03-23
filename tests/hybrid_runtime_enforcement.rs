use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::json;
use very_simple_rest::actix_web::{App, http::StatusCode, test, web};
use very_simple_rest::db::{connect, query, query_scalar};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/hybrid_runtime_api.eon");

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_hybrid_runtime_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}

#[actix_web::test]
async fn generated_item_routes_support_hybrid_runtime_enforcement() {
    unsafe {
        std::env::set_var("JWT_SECRET", "hybrid-runtime-secret");
    }

    let database_url = unique_sqlite_url("crud");
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
            .expect("base auth migration should apply");
    }

    pool.execute_batch(
        &very_simple_rest::authorization::authorization_runtime_migration_sql(
            very_simple_rest::core::auth::AuthDbBackend::Sqlite,
        ),
    )
    .await
    .expect("authz runtime migration should apply");
    query(
        "CREATE TABLE scoped_doc (\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            user_id INTEGER NOT NULL,\
            family_id INTEGER NOT NULL,\
            title TEXT NOT NULL\
        )",
    )
    .execute(&pool)
    .await
    .expect("scoped_doc table should create");

    let security = hybrid_runtime_api::security();
    let app = test::init_service(App::new().service(web::scope("/api").configure(|cfg| {
        auth::auth_routes_with_settings(cfg, pool.clone(), security.auth.clone());
        hybrid_runtime_api::configure(cfg, pool.clone());
    })))
    .await;

    let admin_register = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&auth::RegisterInput {
            email: "manager@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let admin_register_response = test::call_service(&app, admin_register).await;
    assert_eq!(admin_register_response.status(), StatusCode::CREATED);

    let member_register = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&auth::RegisterInput {
            email: "member@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let member_register_response = test::call_service(&app, member_register).await;
    assert_eq!(member_register_response.status(), StatusCode::CREATED);

    query("UPDATE user SET role = ? WHERE email = ?")
        .bind("admin")
        .bind("manager@example.com")
        .execute(&pool)
        .await
        .expect("admin role should update");
    query("UPDATE user SET role = ? WHERE email = ?")
        .bind("member")
        .bind("member@example.com")
        .execute(&pool)
        .await
        .expect("member role should update");

    let admin_user_id: i64 = query_scalar::<sqlx::Any, i64>("SELECT id FROM user WHERE email = ?")
        .bind("manager@example.com")
        .fetch_one(&pool)
        .await
        .expect("admin user id should be queryable");
    let member_user_id: i64 = query_scalar::<sqlx::Any, i64>("SELECT id FROM user WHERE email = ?")
        .bind("member@example.com")
        .fetch_one(&pool)
        .await
        .expect("member user id should be queryable");

    query("INSERT INTO scoped_doc (user_id, family_id, title) VALUES (?, ?, ?)")
        .bind(admin_user_id)
        .bind(42_i64)
        .bind("Shared household note")
        .execute(&pool)
        .await
        .expect("scoped doc should insert");
    let shared_doc_id =
        query_scalar::<sqlx::Any, i64>("SELECT id FROM scoped_doc WHERE family_id = ?")
            .bind(42_i64)
            .fetch_one(&pool)
            .await
            .expect("shared doc id should be queryable");

    query("INSERT INTO scoped_doc (user_id, family_id, title) VALUES (?, ?, ?)")
        .bind(admin_user_id)
        .bind(7_i64)
        .bind("Other family note")
        .execute(&pool)
        .await
        .expect("other doc should insert");
    let other_doc_id =
        query_scalar::<sqlx::Any, i64>("SELECT id FROM scoped_doc WHERE family_id = ?")
            .bind(7_i64)
            .fetch_one(&pool)
            .await
            .expect("other doc id should be queryable");

    let admin_login = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "manager@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let admin_token: TokenResponse = test::call_and_read_body_json(&app, admin_login).await;

    let member_login = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "member@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let member_token: TokenResponse = test::call_and_read_body_json(&app, member_login).await;

    let before_read_request = test::TestRequest::get()
        .uri(&format!("/api/scoped_doc/{shared_doc_id}"))
        .insert_header(("Authorization", format!("Bearer {}", member_token.token)))
        .to_request();
    let before_read_response = test::call_service(&app, before_read_request).await;
    assert_eq!(before_read_response.status(), StatusCode::NOT_FOUND);

    let create_before_assignment_request = test::TestRequest::post()
        .uri("/api/scoped_doc")
        .insert_header(("Authorization", format!("Bearer {}", member_token.token)))
        .set_json(json!({
            "family_id": 42,
            "title": "Runtime-created household note"
        }))
        .to_request();
    let create_before_assignment_response =
        test::call_service(&app, create_before_assignment_request).await;
    assert_eq!(
        create_before_assignment_response.status(),
        StatusCode::FORBIDDEN
    );

    let create_assignment_request = test::TestRequest::post()
        .uri("/api/authz/runtime/assignments")
        .insert_header(("Authorization", format!("Bearer {}", admin_token.token)))
        .set_json(json!({
            "user_id": member_user_id,
            "target": { "kind": "template", "name": "FamilyMember" },
            "scope": { "scope": "Family", "value": "42" }
        }))
        .to_request();
    let create_assignment_response = test::call_service(&app, create_assignment_request).await;
    assert_eq!(create_assignment_response.status(), StatusCode::CREATED);

    let create_after_assignment_request = test::TestRequest::post()
        .uri("/api/scoped_doc")
        .insert_header(("Authorization", format!("Bearer {}", member_token.token)))
        .set_json(json!({
            "family_id": 42,
            "title": "Runtime-created household note"
        }))
        .to_request();
    let created_doc: hybrid_runtime_api::ScopedDoc =
        test::call_and_read_body_json(&app, create_after_assignment_request).await;
    assert_eq!(created_doc.user_id, member_user_id);
    assert_eq!(created_doc.family_id, 42);
    assert_eq!(created_doc.title, "Runtime-created household note");

    let wrong_scope_create_request = test::TestRequest::post()
        .uri("/api/scoped_doc")
        .insert_header(("Authorization", format!("Bearer {}", member_token.token)))
        .set_json(json!({
            "family_id": 7,
            "title": "Should not be allowed"
        }))
        .to_request();
    let wrong_scope_create_response = test::call_service(&app, wrong_scope_create_request).await;
    assert_eq!(wrong_scope_create_response.status(), StatusCode::FORBIDDEN);

    let after_read_request = test::TestRequest::get()
        .uri(&format!("/api/scoped_doc/{shared_doc_id}"))
        .insert_header(("Authorization", format!("Bearer {}", member_token.token)))
        .to_request();
    let after_read: hybrid_runtime_api::ScopedDoc =
        test::call_and_read_body_json(&app, after_read_request).await;
    assert_eq!(after_read.id, Some(shared_doc_id));
    assert_eq!(after_read.family_id, 42);
    assert_eq!(after_read.title, "Shared household note");

    let other_read_request = test::TestRequest::get()
        .uri(&format!("/api/scoped_doc/{other_doc_id}"))
        .insert_header(("Authorization", format!("Bearer {}", member_token.token)))
        .to_request();
    let other_read_response = test::call_service(&app, other_read_request).await;
    assert_eq!(other_read_response.status(), StatusCode::NOT_FOUND);

    let update_before_delete_request = test::TestRequest::put()
        .uri(&format!("/api/scoped_doc/{shared_doc_id}"))
        .insert_header(("Authorization", format!("Bearer {}", member_token.token)))
        .set_json(json!({
            "family_id": 42,
            "title": "Updated by runtime grant"
        }))
        .to_request();
    let update_before_delete_response =
        test::call_service(&app, update_before_delete_request).await;
    assert_eq!(update_before_delete_response.status(), StatusCode::OK);

    let updated_title =
        query_scalar::<sqlx::Any, String>("SELECT title FROM scoped_doc WHERE id = ?")
            .bind(shared_doc_id)
            .fetch_one(&pool)
            .await
            .expect("updated title should be queryable");
    assert_eq!(updated_title, "Updated by runtime grant");

    let delete_request = test::TestRequest::delete()
        .uri(&format!("/api/scoped_doc/{shared_doc_id}"))
        .insert_header(("Authorization", format!("Bearer {}", member_token.token)))
        .to_request();
    let delete_response = test::call_service(&app, delete_request).await;
    assert_eq!(delete_response.status(), StatusCode::OK);

    let remaining = query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM scoped_doc WHERE id = ?")
        .bind(shared_doc_id)
        .fetch_one(&pool)
        .await
        .expect("remaining row count should be queryable");
    assert_eq!(remaining, 0);

    unsafe {
        std::env::remove_var("JWT_SECRET");
    }
}
