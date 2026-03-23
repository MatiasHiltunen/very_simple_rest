use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use very_simple_rest::actix_web::{App, HttpResponse, http::StatusCode, test, web};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/authz_management_api.eon");

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    code: String,
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_authz_management_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}

#[actix_web::test]
async fn authorization_management_routes_allow_admin_runtime_assignment_crud() {
    unsafe {
        std::env::set_var("JWT_SECRET", "authz-management-secret");
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

    let security = authz_management_api::security();
    let app = test::init_service(App::new().service(scope("/api").configure(|cfg| {
        auth::auth_routes_with_settings(cfg, pool.clone(), security.auth.clone());
        authz_management_api::configure(cfg, pool.clone());
        cfg.route(
                    "/runtime-docs/{family_id}",
                    web::get().to(
                        |path: web::Path<i64>,
                         user: auth::UserContext,
                         runtime: web::Data<
                            very_simple_rest::authorization::AuthorizationRuntime,
                        >| async move {
                            match runtime
                                .enforce_runtime_access(
                                    &user,
                                    "ScopedDoc",
                                    very_simple_rest::authorization::AuthorizationAction::Read,
                                    very_simple_rest::authorization::AuthorizationScopeBinding {
                                        scope: "Family".to_owned(),
                                        value: path.into_inner().to_string(),
                                    },
                                )
                                .await
                            {
                                Ok(_) => HttpResponse::Ok().body("allowed"),
                                Err(response) => response,
                            }
                        },
                    ),
                );
    })))
    .await;

    let register_request = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&auth::RegisterInput {
            email: "manager@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let register_response = test::call_service(&app, register_request).await;
    assert_eq!(register_response.status(), StatusCode::CREATED);

    let create_without_admin = test::TestRequest::post()
        .uri("/api/authz/runtime/assignments")
        .set_json(json!({
            "user_id": 41,
            "target": { "kind": "template", "name": "FamilyMember" },
            "scope": { "scope": "Family", "value": "42" }
        }))
        .to_request();
    let create_without_admin_response = test::call_service(&app, create_without_admin).await;
    assert_eq!(
        create_without_admin_response.status(),
        StatusCode::UNAUTHORIZED
    );

    let register_member_request = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&auth::RegisterInput {
            email: "member@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let register_member_response = test::call_service(&app, register_member_request).await;
    assert_eq!(register_member_response.status(), StatusCode::CREATED);
    let member_user_id: i64 =
        very_simple_rest::db::query_scalar::<sqlx::Any, i64>("SELECT id FROM user WHERE email = ?")
            .bind("member@example.com")
            .fetch_one(&pool)
            .await
            .expect("member user id should be queryable");

    query("UPDATE user SET role = ? WHERE email = ?")
        .bind("admin")
        .bind("manager@example.com")
        .execute(&pool)
        .await
        .expect("admin role should update");
    let admin_user_id: i64 =
        very_simple_rest::db::query_scalar::<sqlx::Any, i64>("SELECT id FROM user WHERE email = ?")
            .bind("manager@example.com")
            .fetch_one(&pool)
            .await
            .expect("admin user id should be queryable");

    let login_request = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "manager@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let token_response: TokenResponse = test::call_and_read_body_json(&app, login_request).await;

    let member_login_request = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "member@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let member_token_response: TokenResponse =
        test::call_and_read_body_json(&app, member_login_request).await;

    let member_runtime_before_request = test::TestRequest::get()
        .uri("/api/runtime-docs/42")
        .insert_header((
            "Authorization",
            format!("Bearer {}", member_token_response.token.as_str()),
        ))
        .to_request();
    let member_runtime_before_response =
        test::call_service(&app, member_runtime_before_request).await;
    assert_eq!(
        member_runtime_before_response.status(),
        StatusCode::FORBIDDEN
    );

    let create_request = test::TestRequest::post()
        .uri("/api/authz/runtime/assignments")
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .set_json(json!({
            "user_id": member_user_id,
            "target": { "kind": "template", "name": "FamilyMember" },
            "scope": { "scope": "Family", "value": "42" },
            "expires_at": (Utc::now() + Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created: very_simple_rest::authorization::AuthorizationScopedAssignmentRecord =
        test::read_body_json(create_response).await;
    assert_eq!(created.user_id, member_user_id);
    assert_eq!(
        created.target,
        very_simple_rest::authorization::AuthorizationScopedAssignmentTarget::Template {
            name: "FamilyMember".to_owned(),
        }
    );
    assert_eq!(created.created_by_user_id, Some(admin_user_id));
    assert!(!created.created_at.is_empty());
    assert!(created.expires_at.is_some());
    assert_eq!(created.scope.scope, "Family");
    assert_eq!(created.scope.value, "42");

    let list_request = test::TestRequest::get()
        .uri(&format!(
            "/api/authz/runtime/assignments?user_id={member_user_id}"
        ))
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .to_request();
    let listed: Vec<very_simple_rest::authorization::AuthorizationScopedAssignmentRecord> =
        test::call_and_read_body_json(&app, list_request).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0], created);

    let event_list_request = test::TestRequest::get()
        .uri(&format!(
            "/api/authz/runtime/assignment-events?user_id={member_user_id}"
        ))
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .to_request();
    let events_after_create: Vec<
        very_simple_rest::authorization::AuthorizationScopedAssignmentEventRecord,
    > = test::call_and_read_body_json(&app, event_list_request).await;
    assert_eq!(events_after_create.len(), 1);
    assert_eq!(events_after_create[0].assignment_id, created.id);
    assert_eq!(
        events_after_create[0].event,
        very_simple_rest::authorization::AuthorizationScopedAssignmentEventKind::Created
    );
    assert_eq!(events_after_create[0].actor_user_id, Some(admin_user_id));

    let evaluate_request = test::TestRequest::post()
        .uri("/api/authz/runtime/evaluate")
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .set_json(json!({
            "resource": "ScopedDoc",
            "action": "read",
            "scope": { "scope": "Family", "value": "42" },
            "user_id": member_user_id
        }))
        .to_request();
    let evaluated: very_simple_rest::authorization::AuthorizationRuntimeAccessResult =
        test::call_and_read_body_json(&app, evaluate_request).await;
    assert!(evaluated.allowed);
    assert_eq!(evaluated.user_id, member_user_id);
    assert_eq!(evaluated.resolved_permissions, vec!["FamilyRead"]);
    assert_eq!(evaluated.resolved_templates, vec!["FamilyMember"]);

    let member_runtime_allowed_request = test::TestRequest::get()
        .uri("/api/runtime-docs/42")
        .insert_header((
            "Authorization",
            format!("Bearer {}", member_token_response.token.as_str()),
        ))
        .to_request();
    let member_runtime_allowed_response =
        test::call_service(&app, member_runtime_allowed_request).await;
    assert_eq!(member_runtime_allowed_response.status(), StatusCode::OK);

    let member_runtime_denied_request = test::TestRequest::get()
        .uri("/api/runtime-docs/7")
        .insert_header((
            "Authorization",
            format!("Bearer {}", member_token_response.token.as_str()),
        ))
        .to_request();
    let member_runtime_denied_response =
        test::call_service(&app, member_runtime_denied_request).await;
    assert_eq!(
        member_runtime_denied_response.status(),
        StatusCode::FORBIDDEN
    );

    let revoke_request = test::TestRequest::post()
        .uri(&format!(
            "/api/authz/runtime/assignments/{}/revoke",
            created.id
        ))
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .set_json(json!({
            "reason": "suspend"
        }))
        .to_request();
    let revoke_response = test::call_service(&app, revoke_request).await;
    assert_eq!(revoke_response.status(), StatusCode::OK);
    let revoked: very_simple_rest::authorization::AuthorizationScopedAssignmentRecord =
        test::read_body_json(revoke_response).await;
    assert_eq!(revoked.id, created.id);
    assert!(revoked.expires_at.is_some());

    let evaluate_after_revoke_request = test::TestRequest::post()
        .uri("/api/authz/runtime/evaluate")
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .set_json(json!({
            "resource": "ScopedDoc",
            "action": "read",
            "scope": { "scope": "Family", "value": "42" },
            "user_id": member_user_id
        }))
        .to_request();
    let evaluated_after_revoke: very_simple_rest::authorization::AuthorizationRuntimeAccessResult =
        test::call_and_read_body_json(&app, evaluate_after_revoke_request).await;
    assert!(!evaluated_after_revoke.allowed);

    let member_runtime_after_revoke_request = test::TestRequest::get()
        .uri("/api/runtime-docs/42")
        .insert_header((
            "Authorization",
            format!("Bearer {}", member_token_response.token.as_str()),
        ))
        .to_request();
    let member_runtime_after_revoke_response =
        test::call_service(&app, member_runtime_after_revoke_request).await;
    assert_eq!(
        member_runtime_after_revoke_response.status(),
        StatusCode::FORBIDDEN
    );

    let renewed_expires_at =
        (Utc::now() + Duration::days(2)).to_rfc3339_opts(chrono::SecondsFormat::Micros, false);
    let renew_request = test::TestRequest::post()
        .uri(&format!(
            "/api/authz/runtime/assignments/{}/renew",
            created.id
        ))
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .set_json(json!({
            "expires_at": renewed_expires_at,
            "reason": "restore"
        }))
        .to_request();
    let renew_response = test::call_service(&app, renew_request).await;
    assert_eq!(renew_response.status(), StatusCode::OK);
    let renewed: very_simple_rest::authorization::AuthorizationScopedAssignmentRecord =
        test::read_body_json(renew_response).await;
    assert_eq!(renewed.id, created.id);
    assert_eq!(
        renewed.expires_at.as_deref(),
        Some(renewed_expires_at.as_str())
    );

    let evaluate_after_renew_request = test::TestRequest::post()
        .uri("/api/authz/runtime/evaluate")
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .set_json(json!({
            "resource": "ScopedDoc",
            "action": "read",
            "scope": { "scope": "Family", "value": "42" },
            "user_id": member_user_id
        }))
        .to_request();
    let evaluated_after_renew: very_simple_rest::authorization::AuthorizationRuntimeAccessResult =
        test::call_and_read_body_json(&app, evaluate_after_renew_request).await;
    assert!(evaluated_after_renew.allowed);

    let self_assignment_request = test::TestRequest::post()
        .uri("/api/authz/runtime/assignments")
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .set_json(json!({
            "user_id": admin_user_id,
            "target": { "kind": "template", "name": "FamilyMember" },
            "scope": { "scope": "Family", "value": "7" }
        }))
        .to_request();
    let self_assignment_response = test::call_service(&app, self_assignment_request).await;
    assert_eq!(self_assignment_response.status(), StatusCode::CREATED);

    let invalid_create_request = test::TestRequest::post()
        .uri("/api/authz/runtime/assignments")
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .set_json(json!({
            "user_id": member_user_id,
            "target": { "kind": "template", "name": "FamilyMember" },
            "scope": { "scope": "Household", "value": "77" }
        }))
        .to_request();
    let invalid_create_response = test::call_service(&app, invalid_create_request).await;
    assert_eq!(invalid_create_response.status(), StatusCode::BAD_REQUEST);
    let invalid_body: ApiErrorResponse = test::read_body_json(invalid_create_response).await;
    assert_eq!(invalid_body.code, "invalid_runtime_assignment");

    let expired_create_request = test::TestRequest::post()
        .uri("/api/authz/runtime/assignments")
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .set_json(json!({
            "user_id": member_user_id,
            "target": { "kind": "template", "name": "FamilyMember" },
            "scope": { "scope": "Family", "value": "77" },
            "expires_at": (Utc::now() - Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
        }))
        .to_request();
    let expired_create_response = test::call_service(&app, expired_create_request).await;
    assert_eq!(expired_create_response.status(), StatusCode::BAD_REQUEST);
    let expired_body: ApiErrorResponse = test::read_body_json(expired_create_response).await;
    assert_eq!(expired_body.code, "invalid_runtime_assignment");

    let self_evaluate_request = test::TestRequest::post()
        .uri("/api/authz/runtime/evaluate")
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .set_json(json!({
            "resource": "ScopedDoc",
            "action": "read",
            "scope": { "scope": "Family", "value": "7" }
        }))
        .to_request();
    let self_evaluated: very_simple_rest::authorization::AuthorizationRuntimeAccessResult =
        test::call_and_read_body_json(&app, self_evaluate_request).await;
    assert!(self_evaluated.allowed);
    assert_eq!(self_evaluated.user_id, admin_user_id);

    let delete_request = test::TestRequest::delete()
        .uri(&format!("/api/authz/runtime/assignments/{}", created.id))
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .to_request();
    let delete_response = test::call_service(&app, delete_request).await;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    let list_after_delete_request = test::TestRequest::get()
        .uri(&format!(
            "/api/authz/runtime/assignments?user_id={member_user_id}"
        ))
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .to_request();
    let listed_after_delete: Vec<
        very_simple_rest::authorization::AuthorizationScopedAssignmentRecord,
    > = test::call_and_read_body_json(&app, list_after_delete_request).await;
    assert!(listed_after_delete.is_empty());

    let event_list_after_delete_request = test::TestRequest::get()
        .uri(&format!(
            "/api/authz/runtime/assignment-events?user_id={member_user_id}"
        ))
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .to_request();
    let events_after_delete: Vec<
        very_simple_rest::authorization::AuthorizationScopedAssignmentEventRecord,
    > = test::call_and_read_body_json(&app, event_list_after_delete_request).await;
    assert_eq!(events_after_delete.len(), 4);
    assert_eq!(events_after_delete[1].assignment_id, created.id);
    assert_eq!(
        events_after_delete[1].event,
        very_simple_rest::authorization::AuthorizationScopedAssignmentEventKind::Revoked
    );
    assert_eq!(events_after_delete[1].actor_user_id, Some(admin_user_id));
    assert_eq!(events_after_delete[1].reason.as_deref(), Some("suspend"));
    assert_eq!(events_after_delete[2].assignment_id, created.id);
    assert_eq!(
        events_after_delete[2].event,
        very_simple_rest::authorization::AuthorizationScopedAssignmentEventKind::Renewed
    );
    assert_eq!(events_after_delete[2].actor_user_id, Some(admin_user_id));
    assert_eq!(events_after_delete[2].reason.as_deref(), Some("restore"));
    assert_eq!(events_after_delete[3].assignment_id, created.id);
    assert_eq!(
        events_after_delete[3].event,
        very_simple_rest::authorization::AuthorizationScopedAssignmentEventKind::Deleted
    );
    assert_eq!(events_after_delete[3].actor_user_id, Some(admin_user_id));
    assert_eq!(events_after_delete[3].reason, None);

    unsafe {
        std::env::remove_var("JWT_SECRET");
    }
}
