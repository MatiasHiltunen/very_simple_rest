use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query, query_scalar};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("examples/family_app/family_app.eon");

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_family_app_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}

#[actix_web::test]
async fn family_app_supports_family_bootstrap_and_runtime_scoped_access_through_http_api() {
    unsafe {
        std::env::set_var("JWT_SECRET", "family-app-secret");
    }

    let database_url = unique_sqlite_url("bootstrap");
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
    for statement in very_simple_rest::core::auth::auth_management_migration_sql(
        very_simple_rest::core::auth::AuthDbBackend::Sqlite,
    )
    .split(';')
    .map(str::trim)
    .filter(|statement| !statement.is_empty())
    {
        query(statement)
            .execute(&pool)
            .await
            .expect("auth management migration should apply");
    }
    for statement in very_simple_rest::authorization::authorization_runtime_migration_sql(
        very_simple_rest::core::auth::AuthDbBackend::Sqlite,
    )
    .split(';')
    .map(str::trim)
    .filter(|statement| !statement.is_empty())
    {
        query(statement)
            .execute(&pool)
            .await
            .expect("authz runtime migration should apply");
    }

    query(
        "CREATE TABLE family (\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            owner_user_id INTEGER NOT NULL,\
            slug TEXT NOT NULL,\
            name TEXT NOT NULL,\
            timezone TEXT NOT NULL\
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
            role_label TEXT NOT NULL,\
            display_name TEXT NOT NULL,\
            is_child INTEGER NOT NULL\
        )",
    )
    .execute(&pool)
    .await
    .expect("family_member table should create");

    query(
        "CREATE TABLE household (\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            family_id INTEGER NOT NULL,\
            created_by_user_id INTEGER NOT NULL,\
            slug TEXT NOT NULL,\
            label TEXT NOT NULL,\
            timezone TEXT NOT NULL\
        )",
    )
    .execute(&pool)
    .await
    .expect("household table should create");
    query(
        "CREATE TABLE shopping_item (\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            family_id INTEGER NOT NULL,\
            household_id INTEGER NOT NULL,\
            created_by_user_id INTEGER NOT NULL,\
            title TEXT NOT NULL,\
            completed INTEGER NOT NULL\
        )",
    )
    .execute(&pool)
    .await
    .expect("shopping_item table should create");

    let security = family_app_api::security();
    let app = test::init_service(App::new().service(scope("/api").configure(|cfg| {
        auth::auth_routes_with_settings(cfg, pool.clone(), security.auth.clone());
        family_app_api::configure(cfg, pool.clone());
    })))
    .await;

    for email in [
        "admin@example.com",
        "guardian@example.com",
        "spouse@example.com",
    ] {
        let register = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(&auth::RegisterInput {
                email: email.to_owned(),
                password: "password123".to_owned(),
            })
            .to_request();
        let register_response = test::call_service(&app, register).await;
        assert_eq!(register_response.status(), StatusCode::CREATED);
    }

    query("UPDATE user SET role = ? WHERE email = ?")
        .bind("admin")
        .bind("admin@example.com")
        .execute(&pool)
        .await
        .expect("admin role should update");

    let guardian_id: i64 = query_scalar::<sqlx::Any, i64>("SELECT id FROM user WHERE email = ?")
        .bind("guardian@example.com")
        .fetch_one(&pool)
        .await
        .expect("guardian id should be queryable");
    let spouse_id: i64 = query_scalar::<sqlx::Any, i64>("SELECT id FROM user WHERE email = ?")
        .bind("spouse@example.com")
        .fetch_one(&pool)
        .await
        .expect("spouse id should be queryable");

    let admin_login = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "admin@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let admin_token: TokenResponse = test::call_and_read_body_json(&app, admin_login).await;

    let guardian_login = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "guardian@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let guardian_token: TokenResponse = test::call_and_read_body_json(&app, guardian_login).await;

    let create_family = test::TestRequest::post()
        .uri("/api/family")
        .insert_header(("Authorization", format!("Bearer {}", guardian_token.token)))
        .set_json(&family_app_api::FamilyCreate {
            slug: "helsinki-household".to_owned(),
            name: "Helsinki Household".to_owned(),
            timezone: "Europe/Helsinki".to_owned(),
        })
        .to_request();
    let created_family: family_app_api::Family =
        test::call_and_read_body_json(&app, create_family).await;
    let family_id = created_family.id.expect("created family should expose id");
    assert_eq!(created_family.owner_user_id, guardian_id);

    let create_self_membership = test::TestRequest::post()
        .uri("/api/family_member")
        .insert_header(("Authorization", format!("Bearer {}", guardian_token.token)))
        .set_json(&family_app_api::FamilyMemberCreate {
            family_id,
            user_id: guardian_id,
            role_label: "guardian".to_owned(),
            display_name: "Guardian".to_owned(),
            is_child: false,
        })
        .to_request();
    let self_membership: family_app_api::FamilyMember =
        test::call_and_read_body_json(&app, create_self_membership).await;
    assert_eq!(self_membership.family_id, family_id);
    assert_eq!(self_membership.user_id, guardian_id);

    let create_spouse_membership = test::TestRequest::post()
        .uri("/api/family_member")
        .insert_header(("Authorization", format!("Bearer {}", guardian_token.token)))
        .set_json(&family_app_api::FamilyMemberCreate {
            family_id,
            user_id: spouse_id,
            role_label: "caregiver".to_owned(),
            display_name: "Spouse".to_owned(),
            is_child: false,
        })
        .to_request();
    let spouse_membership: family_app_api::FamilyMember =
        test::call_and_read_body_json(&app, create_spouse_membership).await;
    assert_eq!(spouse_membership.family_id, family_id);
    assert_eq!(spouse_membership.user_id, spouse_id);

    let create_household = test::TestRequest::post()
        .uri("/api/household")
        .insert_header(("Authorization", format!("Bearer {}", guardian_token.token)))
        .set_json(&family_app_api::HouseholdCreate {
            family_id,
            slug: "helsinki-flat".to_owned(),
            label: "Helsinki Flat".to_owned(),
            timezone: "Europe/Helsinki".to_owned(),
        })
        .to_request();
    let household: family_app_api::Household =
        test::call_and_read_body_json(&app, create_household).await;
    let household_id = household.id.expect("created household should expose id");

    let create_shopping_item = test::TestRequest::post()
        .uri("/api/shopping_item")
        .insert_header(("Authorization", format!("Bearer {}", guardian_token.token)))
        .set_json(&family_app_api::ShoppingItemCreate {
            family_id,
            household_id,
            title: "Buy oat milk".to_owned(),
            completed: false,
        })
        .to_request();
    let shopping_item: family_app_api::ShoppingItem =
        test::call_and_read_body_json(&app, create_shopping_item).await;
    let shopping_item_id = shopping_item.id.expect("shopping item should expose id");

    let spouse_login = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "spouse@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let spouse_token: TokenResponse = test::call_and_read_body_json(&app, spouse_login).await;

    let spouse_family_list = test::TestRequest::get()
        .uri("/api/family")
        .insert_header(("Authorization", format!("Bearer {}", spouse_token.token)))
        .to_request();
    let spouse_families: family_app_api::FamilyListResponse =
        test::call_and_read_body_json(&app, spouse_family_list).await;
    assert_eq!(spouse_families.total, 1);
    assert_eq!(spouse_families.count, 1);
    assert_eq!(spouse_families.items[0].id, Some(family_id));

    let spouse_households = test::TestRequest::get()
        .uri(&format!("/api/family/{family_id}/household"))
        .insert_header(("Authorization", format!("Bearer {}", spouse_token.token)))
        .to_request();
    let spouse_household_list: family_app_api::HouseholdListResponse =
        test::call_and_read_body_json(&app, spouse_households).await;
    assert_eq!(spouse_household_list.total, 1);
    assert_eq!(spouse_household_list.items[0].id, Some(household_id));

    let spouse_shopping_before = test::TestRequest::get()
        .uri(&format!("/api/family/{family_id}/shopping_item"))
        .insert_header(("Authorization", format!("Bearer {}", spouse_token.token)))
        .to_request();
    let spouse_shopping_before_list: family_app_api::ShoppingItemListResponse =
        test::call_and_read_body_json(&app, spouse_shopping_before).await;
    assert_eq!(spouse_shopping_before_list.total, 0);
    assert_eq!(spouse_shopping_before_list.count, 0);

    let runtime_assignment = test::TestRequest::post()
        .uri("/api/authz/runtime/assignments")
        .insert_header(("Authorization", format!("Bearer {}", admin_token.token)))
        .set_json(serde_json::json!({
            "user_id": spouse_id,
            "target": { "kind": "template", "name": "Caregiver" },
            "scope": { "scope": "Family", "value": family_id.to_string() }
        }))
        .to_request();
    let runtime_assignment_response = test::call_service(&app, runtime_assignment).await;
    assert_eq!(runtime_assignment_response.status(), StatusCode::CREATED);

    let spouse_shopping_after = test::TestRequest::get()
        .uri(&format!("/api/family/{family_id}/shopping_item"))
        .insert_header(("Authorization", format!("Bearer {}", spouse_token.token)))
        .to_request();
    let spouse_shopping_after_list: family_app_api::ShoppingItemListResponse =
        test::call_and_read_body_json(&app, spouse_shopping_after).await;
    assert_eq!(spouse_shopping_after_list.total, 1);
    assert_eq!(spouse_shopping_after_list.count, 1);
    assert_eq!(spouse_shopping_after_list.items[0].id, Some(shopping_item_id));

    unsafe {
        std::env::remove_var("JWT_SECRET");
    }
}
