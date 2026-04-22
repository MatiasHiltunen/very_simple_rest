#![allow(clippy::await_holding_lock)]

use std::{
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;
use very_simple_rest::sqlx::{self, FromRow};

const TEST_JWT_SECRET: &str = "fine-grained-policy-secret";
const TEST_JWT_ISSUER: &str = "ops_control_api";
const TEST_JWT_AUDIENCE: &str = "ops_control_clients";

rest_api_from_eon!("examples/fine_grained_policies/ops_control.eon");

#[derive(Debug, Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    iss: String,
    aud: String,
    exp: usize,
    tenant_id: Option<i64>,
}

#[derive(Debug, FromRow)]
struct DbWorkspace {
    id: i64,
    tenant_id: i64,
    owner_user_id: i64,
    slug: String,
    name: String,
    compliance_mode: String,
}

#[derive(Debug, FromRow)]
struct DbProject {
    id: i64,
    tenant_id: i64,
    workspace_id: i64,
    lead_user_id: i64,
    code: String,
    name: String,
    status: String,
}

#[derive(Debug, FromRow)]
struct DbOnCallSubscription {
    id: i64,
    tenant_id: i64,
    project_id: i64,
    subscriber_user_id: i64,
    channel: String,
    escalation_level: i64,
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[actix_web::test]
async fn fine_grained_policy_example_enforces_shared_and_self_scoped_routes() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("fine_grained_policies");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE workspace (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            owner_user_id INTEGER NOT NULL,
            slug TEXT NOT NULL,
            name TEXT NOT NULL,
            compliance_mode TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .expect("workspace table should be created");

    query(
        "CREATE TABLE project (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            workspace_id INTEGER NOT NULL,
            lead_user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (workspace_id) REFERENCES workspace(id)
        )",
    )
    .execute(&pool)
    .await
    .expect("project table should be created");

    query(
        "CREATE TABLE on_call_subscription (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            project_id INTEGER NOT NULL,
            subscriber_user_id INTEGER NOT NULL,
            channel TEXT NOT NULL,
            escalation_level INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES project(id)
        )",
    )
    .execute(&pool)
    .await
    .expect("on_call_subscription table should be created");

    let app = test::init_service(
        App::new()
            .service(scope("/api").configure(|cfg| ops_control_api::configure(cfg, pool.clone()))),
    )
    .await;

    let owner_token = issue_token(1, &["user"], Some(100));
    let peer_token = issue_token(2, &["user"], Some(100));
    let same_tenant_admin_token = issue_token(9, &["admin"], Some(100));
    let other_tenant_token = issue_token(3, &["user"], Some(200));
    let other_tenant_admin_token = issue_token(10, &["admin"], Some(200));
    let missing_claim_token = issue_token(11, &["user"], None);

    let missing_claim_list = test::TestRequest::get()
        .uri("/api/workspace")
        .insert_header((
            "Authorization",
            format!("Bearer {}", missing_claim_token.as_str()),
        ))
        .to_request();
    let missing_claim_response = test::call_service(&app, missing_claim_list).await;
    assert_eq!(missing_claim_response.status(), StatusCode::FORBIDDEN);

    let create_workspace = test::TestRequest::post()
        .uri("/api/workspace")
        .insert_header(("Authorization", format!("Bearer {}", owner_token.as_str())))
        .set_json(&ops_control_api::WorkspaceCreate {
            tenant_id: None,
            slug: "north-platform".to_owned(),
            name: "North Platform".to_owned(),
            compliance_mode: "strict".to_owned(),
        })
        .to_request();
    let create_workspace_response = test::call_service(&app, create_workspace).await;
    assert_eq!(create_workspace_response.status(), StatusCode::CREATED);

    let workspace: DbWorkspace = query_as::<sqlx::Any, DbWorkspace>(
        "SELECT id, tenant_id, owner_user_id, slug, name, compliance_mode FROM workspace",
    )
    .fetch_one(&pool)
    .await
    .expect("workspace row should exist");
    assert_eq!(workspace.tenant_id, 100);
    assert_eq!(workspace.owner_user_id, 1);
    assert_eq!(workspace.slug, "north-platform");
    assert_eq!(workspace.compliance_mode, "strict");

    let peer_list_request = test::TestRequest::get()
        .uri("/api/workspace")
        .insert_header(("Authorization", format!("Bearer {}", peer_token.as_str())))
        .to_request();
    let peer_workspaces: ops_control_api::WorkspaceListResponse =
        test::call_and_read_body_json(&app, peer_list_request).await;
    assert_eq!(peer_workspaces.total, 1);
    assert_eq!(peer_workspaces.count, 1);
    assert_eq!(peer_workspaces.items[0].id, Some(workspace.id));

    let other_tenant_list_request = test::TestRequest::get()
        .uri("/api/workspace")
        .insert_header((
            "Authorization",
            format!("Bearer {}", other_tenant_token.as_str()),
        ))
        .to_request();
    let other_tenant_workspaces: ops_control_api::WorkspaceListResponse =
        test::call_and_read_body_json(&app, other_tenant_list_request).await;
    assert_eq!(other_tenant_workspaces.total, 0);
    assert!(other_tenant_workspaces.items.is_empty());

    let peer_update_request = test::TestRequest::put()
        .uri(&format!("/api/workspace/{}", workspace.id))
        .insert_header(("Authorization", format!("Bearer {}", peer_token.as_str())))
        .set_json(&ops_control_api::WorkspaceUpdate {
            slug: "north-platform".to_owned(),
            name: "Peer Rename".to_owned(),
            compliance_mode: "moderate".to_owned(),
        })
        .to_request();
    let peer_update_response = test::call_service(&app, peer_update_request).await;
    assert_eq!(peer_update_response.status(), StatusCode::NOT_FOUND);

    let admin_update_request = test::TestRequest::put()
        .uri(&format!("/api/workspace/{}", workspace.id))
        .insert_header((
            "Authorization",
            format!("Bearer {}", same_tenant_admin_token.as_str()),
        ))
        .set_json(&ops_control_api::WorkspaceUpdate {
            slug: "north-platform-core".to_owned(),
            name: "North Platform Core".to_owned(),
            compliance_mode: "strict".to_owned(),
        })
        .to_request();
    let admin_update_response = test::call_service(&app, admin_update_request).await;
    assert_eq!(admin_update_response.status(), StatusCode::OK);

    let updated_workspace: DbWorkspace = query_as::<sqlx::Any, DbWorkspace>(
        "SELECT id, tenant_id, owner_user_id, slug, name, compliance_mode FROM workspace WHERE id = ?",
    )
    .bind(workspace.id)
    .fetch_one(&pool)
    .await
    .expect("updated workspace should exist");
    assert_eq!(updated_workspace.slug, "north-platform-core");
    assert_eq!(updated_workspace.name, "North Platform Core");
    assert_eq!(updated_workspace.owner_user_id, 1);

    let create_project = test::TestRequest::post()
        .uri("/api/project")
        .insert_header(("Authorization", format!("Bearer {}", owner_token.as_str())))
        .set_json(&ops_control_api::ProjectCreate {
            tenant_id: None,
            workspace_id: workspace.id,
            code: "NRT".to_owned(),
            name: "North Runtime".to_owned(),
            status: "active".to_owned(),
        })
        .to_request();
    let create_project_response = test::call_service(&app, create_project).await;
    assert_eq!(create_project_response.status(), StatusCode::CREATED);

    let project: DbProject = query_as::<sqlx::Any, DbProject>(
        "SELECT id, tenant_id, workspace_id, lead_user_id, code, name, status FROM project",
    )
    .fetch_one(&pool)
    .await
    .expect("project row should exist");
    assert_eq!(project.tenant_id, 100);
    assert_eq!(project.workspace_id, workspace.id);
    assert_eq!(project.lead_user_id, 1);
    assert_eq!(project.code, "NRT");
    assert_eq!(project.name, "North Runtime");
    assert_eq!(project.status, "active");

    let nested_project_request = test::TestRequest::get()
        .uri(&format!("/api/workspace/{}/project", workspace.id))
        .insert_header(("Authorization", format!("Bearer {}", peer_token.as_str())))
        .to_request();
    let nested_projects: ops_control_api::ProjectListResponse =
        test::call_and_read_body_json(&app, nested_project_request).await;
    assert_eq!(nested_projects.total, 1);
    assert_eq!(nested_projects.count, 1);
    assert_eq!(nested_projects.items[0].id, Some(project.id));

    let other_tenant_nested_request = test::TestRequest::get()
        .uri(&format!("/api/workspace/{}/project", workspace.id))
        .insert_header((
            "Authorization",
            format!("Bearer {}", other_tenant_token.as_str()),
        ))
        .to_request();
    let other_tenant_nested_projects: ops_control_api::ProjectListResponse =
        test::call_and_read_body_json(&app, other_tenant_nested_request).await;
    assert_eq!(other_tenant_nested_projects.total, 0);
    assert!(other_tenant_nested_projects.items.is_empty());

    let create_subscription = test::TestRequest::post()
        .uri("/api/on_call_subscription")
        .insert_header(("Authorization", format!("Bearer {}", owner_token.as_str())))
        .set_json(&ops_control_api::OnCallSubscriptionCreate {
            project_id: project.id,
            channel: "pagerduty".to_owned(),
            escalation_level: 1,
        })
        .to_request();
    let create_subscription_response = test::call_service(&app, create_subscription).await;
    assert_eq!(create_subscription_response.status(), StatusCode::CREATED);

    let subscription: DbOnCallSubscription = query_as::<sqlx::Any, DbOnCallSubscription>(
        "SELECT id, tenant_id, project_id, subscriber_user_id, channel, escalation_level FROM on_call_subscription",
    )
    .fetch_one(&pool)
    .await
    .expect("subscription row should exist");
    assert_eq!(subscription.tenant_id, 100);
    assert_eq!(subscription.project_id, project.id);
    assert_eq!(subscription.subscriber_user_id, 1);
    assert_eq!(subscription.channel, "pagerduty");
    assert_eq!(subscription.escalation_level, 1);

    let owner_subscription_request = test::TestRequest::get()
        .uri("/api/on_call_subscription")
        .insert_header(("Authorization", format!("Bearer {}", owner_token.as_str())))
        .to_request();
    let owner_subscriptions: ops_control_api::OnCallSubscriptionListResponse =
        test::call_and_read_body_json(&app, owner_subscription_request).await;
    assert_eq!(owner_subscriptions.total, 1);
    assert_eq!(owner_subscriptions.count, 1);
    assert_eq!(owner_subscriptions.items[0].id, Some(subscription.id));

    let peer_subscription_request = test::TestRequest::get()
        .uri("/api/on_call_subscription")
        .insert_header(("Authorization", format!("Bearer {}", peer_token.as_str())))
        .to_request();
    let peer_subscriptions: ops_control_api::OnCallSubscriptionListResponse =
        test::call_and_read_body_json(&app, peer_subscription_request).await;
    assert_eq!(peer_subscriptions.total, 0);
    assert!(peer_subscriptions.items.is_empty());

    let admin_subscription_request = test::TestRequest::get()
        .uri("/api/on_call_subscription")
        .insert_header((
            "Authorization",
            format!("Bearer {}", same_tenant_admin_token.as_str()),
        ))
        .to_request();
    let admin_subscriptions: ops_control_api::OnCallSubscriptionListResponse =
        test::call_and_read_body_json(&app, admin_subscription_request).await;
    assert_eq!(admin_subscriptions.total, 0);
    assert!(admin_subscriptions.items.is_empty());

    let cross_tenant_admin_workspace_get = test::TestRequest::get()
        .uri(&format!("/api/workspace/{}", workspace.id))
        .insert_header((
            "Authorization",
            format!("Bearer {}", other_tenant_admin_token.as_str()),
        ))
        .to_request();
    let cross_tenant_admin_workspace_response =
        test::call_service(&app, cross_tenant_admin_workspace_get).await;
    assert_eq!(
        cross_tenant_admin_workspace_response.status(),
        StatusCode::OK
    );

    let admin_subscription_update = test::TestRequest::put()
        .uri(&format!("/api/on_call_subscription/{}", subscription.id))
        .insert_header((
            "Authorization",
            format!("Bearer {}", same_tenant_admin_token.as_str()),
        ))
        .set_json(&ops_control_api::OnCallSubscriptionUpdate {
            project_id: project.id,
            channel: "sms".to_owned(),
            escalation_level: 2,
        })
        .to_request();
    let admin_subscription_update_response =
        test::call_service(&app, admin_subscription_update).await;
    assert_eq!(
        admin_subscription_update_response.status(),
        StatusCode::NOT_FOUND
    );

    let owner_subscription_update = test::TestRequest::put()
        .uri(&format!("/api/on_call_subscription/{}", subscription.id))
        .insert_header(("Authorization", format!("Bearer {}", owner_token.as_str())))
        .set_json(&ops_control_api::OnCallSubscriptionUpdate {
            project_id: project.id,
            channel: "slack".to_owned(),
            escalation_level: 2,
        })
        .to_request();
    let owner_subscription_update_response =
        test::call_service(&app, owner_subscription_update).await;
    assert_eq!(owner_subscription_update_response.status(), StatusCode::OK);

    let updated_subscription: DbOnCallSubscription =
        query_as::<sqlx::Any, DbOnCallSubscription>(
        "SELECT id, tenant_id, project_id, subscriber_user_id, channel, escalation_level FROM on_call_subscription WHERE id = ?",
        )
        .bind(subscription.id)
        .fetch_one(&pool)
        .await
        .expect("updated subscription should exist");
    assert_eq!(updated_subscription.channel, "slack");
    assert_eq!(updated_subscription.escalation_level, 2);
    assert_eq!(updated_subscription.subscriber_user_id, 1);

    let admin_subscription_delete = test::TestRequest::delete()
        .uri(&format!("/api/on_call_subscription/{}", subscription.id))
        .insert_header((
            "Authorization",
            format!("Bearer {}", same_tenant_admin_token.as_str()),
        ))
        .to_request();
    let admin_subscription_delete_response =
        test::call_service(&app, admin_subscription_delete).await;
    assert_eq!(
        admin_subscription_delete_response.status(),
        StatusCode::NOT_FOUND
    );

    let owner_subscription_delete = test::TestRequest::delete()
        .uri(&format!("/api/on_call_subscription/{}", subscription.id))
        .insert_header(("Authorization", format!("Bearer {}", owner_token.as_str())))
        .to_request();
    let owner_subscription_delete_response =
        test::call_service(&app, owner_subscription_delete).await;
    assert_eq!(owner_subscription_delete_response.status(), StatusCode::OK);

    let remaining_subscriptions: i64 =
        query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM on_call_subscription")
            .fetch_one(&pool)
            .await
            .expect("remaining rows should be queryable");
    assert_eq!(remaining_subscriptions, 0);

    unsafe {
        std::env::remove_var("JWT_SECRET");
    }
}

#[actix_web::test]
async fn admin_bypass_create_allows_manual_tenant_assignment_without_claims() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("fine_grained_admin_create");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE workspace (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            owner_user_id INTEGER NOT NULL,
            slug TEXT NOT NULL,
            name TEXT NOT NULL,
            compliance_mode TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .expect("workspace table should be created");

    let app = test::init_service(
        App::new()
            .service(scope("/api").configure(|cfg| ops_control_api::configure(cfg, pool.clone()))),
    )
    .await;

    let admin_without_claim_token = issue_token(99, &["admin"], None);

    let create_workspace = test::TestRequest::post()
        .uri("/api/workspace")
        .insert_header((
            "Authorization",
            format!("Bearer {}", admin_without_claim_token.as_str()),
        ))
        .set_json(&ops_control_api::WorkspaceCreate {
            tenant_id: Some(300),
            slug: "manual-admin".to_owned(),
            name: "Manual Admin".to_owned(),
            compliance_mode: "strict".to_owned(),
        })
        .to_request();
    let create_workspace_response = test::call_service(&app, create_workspace).await;
    assert_eq!(create_workspace_response.status(), StatusCode::CREATED);

    let workspace: DbWorkspace = query_as::<sqlx::Any, DbWorkspace>(
        "SELECT id, tenant_id, owner_user_id, slug, name, compliance_mode FROM workspace",
    )
    .fetch_one(&pool)
    .await
    .expect("workspace row should exist");
    assert_eq!(workspace.tenant_id, 300);
    assert_eq!(workspace.owner_user_id, 99);
    assert_eq!(workspace.slug, "manual-admin");

    unsafe {
        std::env::remove_var("JWT_SECRET");
    }
}

fn issue_token(user_id: i64, roles: &[&str], tenant_id: Option<i64>) -> String {
    encode(
        &Header::default(),
        &TestClaims {
            sub: user_id,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            iss: TEST_JWT_ISSUER.to_owned(),
            aud: TEST_JWT_AUDIENCE.to_owned(),
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
