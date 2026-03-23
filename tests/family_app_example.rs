use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use serde_json::Value;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query, query_scalar};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("examples/family_app/family_app.eon");

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(Debug, Deserialize)]
struct MeResponse {
    id: i64,
    #[serde(flatten)]
    claims: BTreeMap<String, Value>,
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
async fn family_app_supports_guardian_family_bootstrap_through_http_api() {
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
    for statement in include_str!("../examples/family_app/auth_extension.sql")
        .split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
    {
        query(statement)
            .execute(&pool)
            .await
            .expect("auth extension should apply");
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

    let create_member_before_claim = test::TestRequest::post()
        .uri("/api/family_member")
        .insert_header(("Authorization", format!("Bearer {}", guardian_token.token)))
        .set_json(&family_app_api::FamilyMemberCreate {
            family_id: None,
            user_id: guardian_id,
            role_label: "guardian".to_owned(),
            display_name: "Guardian".to_owned(),
            is_child: false,
        })
        .to_request();
    let create_member_before_claim_response =
        test::call_service(&app, create_member_before_claim).await;
    assert_eq!(
        create_member_before_claim_response.status(),
        StatusCode::FORBIDDEN
    );

    let patch_guardian_claims = test::TestRequest::patch()
        .uri(&format!("/api/auth/admin/users/{guardian_id}"))
        .insert_header(("Authorization", format!("Bearer {}", admin_token.token)))
        .set_json(&auth::UpdateManagedUserInput {
            role: None,
            email_verified: None,
            claims: BTreeMap::from([
                ("active_family_id".to_owned(), Value::from(family_id)),
                (
                    "preferred_household".to_owned(),
                    Value::from("helsinki-household"),
                ),
            ]),
        })
        .to_request();
    let patched_guardian: auth::AccountInfo =
        test::call_and_read_body_json(&app, patch_guardian_claims).await;
    assert_eq!(
        patched_guardian
            .claims
            .get("active_family_id")
            .and_then(Value::as_i64),
        Some(family_id)
    );

    let guardian_login_after_claim = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "guardian@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let guardian_token_after_claim: TokenResponse =
        test::call_and_read_body_json(&app, guardian_login_after_claim).await;

    let guardian_me = test::TestRequest::get()
        .uri("/api/auth/me")
        .insert_header((
            "Authorization",
            format!("Bearer {}", guardian_token_after_claim.token),
        ))
        .to_request();
    let guardian_me_body: MeResponse = test::call_and_read_body_json(&app, guardian_me).await;
    assert_eq!(guardian_me_body.id, guardian_id);
    assert_eq!(
        guardian_me_body
            .claims
            .get("active_family_id")
            .and_then(Value::as_i64),
        Some(family_id)
    );

    let create_self_membership = test::TestRequest::post()
        .uri("/api/family_member")
        .insert_header((
            "Authorization",
            format!("Bearer {}", guardian_token_after_claim.token),
        ))
        .set_json(&family_app_api::FamilyMemberCreate {
            family_id: None,
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
        .insert_header((
            "Authorization",
            format!("Bearer {}", guardian_token_after_claim.token),
        ))
        .set_json(&family_app_api::FamilyMemberCreate {
            family_id: None,
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

    unsafe {
        std::env::remove_var("JWT_SECRET");
    }
}
