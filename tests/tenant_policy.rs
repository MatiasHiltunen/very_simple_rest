use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::Value;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::prelude::*;

const TEST_JWT_SECRET: &str = "tenant-policy-secret";

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
#[rest_api(table = "tenant_post", id = "id", db = "sqlite")]
#[require_role(read = "user", create = "user", update = "user", delete = "user")]
#[row_policy(
    read = "tenant_id=claim.tenant_id",
    create = "user_id=user.id; tenant_id=claim.tenant_id",
    update = "tenant_id=claim.tenant_id",
    delete = "tenant_id=claim.tenant_id",
    admin_bypass = false
)]
struct TenantPost {
    id: Option<i64>,
    title: String,
    user_id: i64,
    tenant_id: i64,
    created_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Deserialize, sqlx::FromRow)]
struct DbTenantPost {
    id: i64,
    title: String,
    user_id: i64,
    tenant_id: i64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(Debug, Deserialize)]
struct MeResponse {
    id: i64,
    roles: Vec<String>,
    #[serde(flatten)]
    claims: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
    tenant_id: Option<i64>,
}

#[actix_web::test]
async fn tenant_claim_policy_scopes_access_without_native_rls() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("tenant_policy");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE tenant_post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            tenant_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .expect("tenant_post table should be created");

    let app = test::init_service(
        App::new().service(scope("/api").configure(|cfg| TenantPost::configure(cfg, pool.clone()))),
    )
    .await;

    let tenant1_user_token = issue_token(11, &["user"], Some(1));
    let tenant2_user_token = issue_token(22, &["user"], Some(2));
    let tenant1_admin_token = issue_token(91, &["admin"], Some(1));
    let tenant2_admin_token = issue_token(92, &["admin"], Some(2));
    let missing_claim_token = issue_token(33, &["user"], None);

    let missing_claim_list = test::TestRequest::get()
        .uri("/api/tenant_post")
        .insert_header((
            "Authorization",
            format!("Bearer {}", missing_claim_token.as_str()),
        ))
        .to_request();
    let missing_claim_response = test::call_service(&app, missing_claim_list).await;
    assert_eq!(missing_claim_response.status(), StatusCode::FORBIDDEN);

    let create_tenant1 = test::TestRequest::post()
        .uri("/api/tenant_post")
        .insert_header((
            "Authorization",
            format!("Bearer {}", tenant1_user_token.as_str()),
        ))
        .set_json(&TenantPostCreate {
            title: "tenant one".to_owned(),
        })
        .to_request();
    let create_tenant1_response = test::call_service(&app, create_tenant1).await;
    assert_eq!(create_tenant1_response.status(), StatusCode::CREATED);

    let create_tenant2 = test::TestRequest::post()
        .uri("/api/tenant_post")
        .insert_header((
            "Authorization",
            format!("Bearer {}", tenant2_user_token.as_str()),
        ))
        .set_json(&TenantPostCreate {
            title: "tenant two".to_owned(),
        })
        .to_request();
    let create_tenant2_response = test::call_service(&app, create_tenant2).await;
    assert_eq!(create_tenant2_response.status(), StatusCode::CREATED);

    let created_posts: Vec<DbTenantPost> = query_as::<sqlx::Any, DbTenantPost>(
        "SELECT id, title, user_id, tenant_id FROM tenant_post ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("tenant posts should exist");
    assert_eq!(created_posts.len(), 2);
    assert_eq!(created_posts[0].user_id, 11);
    assert_eq!(created_posts[0].tenant_id, 1);
    assert_eq!(created_posts[1].user_id, 22);
    assert_eq!(created_posts[1].tenant_id, 2);

    let tenant1_list = test::TestRequest::get()
        .uri("/api/tenant_post")
        .insert_header((
            "Authorization",
            format!("Bearer {}", tenant1_user_token.as_str()),
        ))
        .to_request();
    let tenant1_posts: TenantPostListResponse =
        test::call_and_read_body_json(&app, tenant1_list).await;
    assert_eq!(tenant1_posts.total, 1);
    assert_eq!(tenant1_posts.count, 1);
    assert!(tenant1_posts.items.iter().all(|post| post.tenant_id == 1));

    let tenant2_admin_list = test::TestRequest::get()
        .uri("/api/tenant_post")
        .insert_header((
            "Authorization",
            format!("Bearer {}", tenant2_admin_token.as_str()),
        ))
        .to_request();
    let tenant2_admin_posts: TenantPostListResponse =
        test::call_and_read_body_json(&app, tenant2_admin_list).await;
    assert_eq!(tenant2_admin_posts.total, 1);
    assert_eq!(tenant2_admin_posts.count, 1);
    assert!(
        tenant2_admin_posts
            .items
            .iter()
            .all(|post| post.tenant_id == 2)
    );

    let tenant1_id = created_posts[0].id;
    let tenant2_admin_get = test::TestRequest::get()
        .uri(&format!("/api/tenant_post/{tenant1_id}"))
        .insert_header((
            "Authorization",
            format!("Bearer {}", tenant2_admin_token.as_str()),
        ))
        .to_request();
    let tenant2_admin_get_response = test::call_service(&app, tenant2_admin_get).await;
    assert_eq!(tenant2_admin_get_response.status(), StatusCode::NOT_FOUND);

    let tenant2_admin_update = test::TestRequest::put()
        .uri(&format!("/api/tenant_post/{tenant1_id}"))
        .insert_header((
            "Authorization",
            format!("Bearer {}", tenant2_admin_token.as_str()),
        ))
        .set_json(&TenantPostUpdate {
            title: "cross-tenant update".to_owned(),
        })
        .to_request();
    let tenant2_admin_update_response = test::call_service(&app, tenant2_admin_update).await;
    assert_eq!(
        tenant2_admin_update_response.status(),
        StatusCode::NOT_FOUND
    );

    let tenant1_admin_update = test::TestRequest::put()
        .uri(&format!("/api/tenant_post/{tenant1_id}"))
        .insert_header((
            "Authorization",
            format!("Bearer {}", tenant1_admin_token.as_str()),
        ))
        .set_json(&TenantPostUpdate {
            title: "tenant one admin update".to_owned(),
        })
        .to_request();
    let tenant1_admin_update_response = test::call_service(&app, tenant1_admin_update).await;
    assert_eq!(tenant1_admin_update_response.status(), StatusCode::OK);

    let updated_tenant1: DbTenantPost = query_as::<sqlx::Any, DbTenantPost>(
        "SELECT id, title, user_id, tenant_id FROM tenant_post WHERE id = ?",
    )
    .bind(tenant1_id)
    .fetch_one(&pool)
    .await
    .expect("tenant one row should exist");
    assert_eq!(updated_tenant1.title, "tenant one admin update");
    assert_eq!(updated_tenant1.user_id, 11);
    assert_eq!(updated_tenant1.tenant_id, 1);

    let tenant2_delete_tenant1 = test::TestRequest::delete()
        .uri(&format!("/api/tenant_post/{tenant1_id}"))
        .insert_header((
            "Authorization",
            format!("Bearer {}", tenant2_user_token.as_str()),
        ))
        .to_request();
    let tenant2_delete_tenant1_response = test::call_service(&app, tenant2_delete_tenant1).await;
    assert_eq!(
        tenant2_delete_tenant1_response.status(),
        StatusCode::NOT_FOUND
    );

    let tenant1_admin_delete = test::TestRequest::delete()
        .uri(&format!("/api/tenant_post/{tenant1_id}"))
        .insert_header((
            "Authorization",
            format!("Bearer {}", tenant1_admin_token.as_str()),
        ))
        .to_request();
    let tenant1_admin_delete_response = test::call_service(&app, tenant1_admin_delete).await;
    assert_eq!(tenant1_admin_delete_response.status(), StatusCode::OK);

    let remaining_count: i64 = query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM tenant_post")
        .fetch_one(&pool)
        .await
        .expect("remaining row count should be queryable");
    assert_eq!(remaining_count, 1);
}

#[actix_web::test]
async fn auth_login_emits_tenant_claims_for_row_policies() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("tenant_policy_auth");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            tenant_id INTEGER
        )",
    )
    .execute(&pool)
    .await
    .expect("user table should be created");

    query(
        "CREATE TABLE tenant_post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            tenant_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .expect("tenant_post table should be created");

    let app = test::init_service(
        App::new().service(
            scope("/api")
                .configure(|cfg| auth::auth_routes(cfg, pool.clone()))
                .configure(|cfg| TenantPost::configure(cfg, pool.clone())),
        ),
    )
    .await;

    let register_alice = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&auth::RegisterInput {
            email: "alice@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let register_alice_response = test::call_service(&app, register_alice).await;
    assert_eq!(register_alice_response.status(), StatusCode::CREATED);

    let register_bob = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&auth::RegisterInput {
            email: "bob@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let register_bob_response = test::call_service(&app, register_bob).await;
    assert_eq!(register_bob_response.status(), StatusCode::CREATED);

    query("UPDATE user SET tenant_id = ? WHERE email = ?")
        .bind(1_i64)
        .bind("alice@example.com")
        .execute(&pool)
        .await
        .expect("alice tenant should be updated");
    query("UPDATE user SET tenant_id = ? WHERE email = ?")
        .bind(2_i64)
        .bind("bob@example.com")
        .execute(&pool)
        .await
        .expect("bob tenant should be updated");

    let login_alice = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "alice@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let alice_token: TokenResponse = test::call_and_read_body_json(&app, login_alice).await;
    let alice_token = alice_token.token;

    let login_bob = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "bob@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let bob_token: TokenResponse = test::call_and_read_body_json(&app, login_bob).await;
    let bob_token = bob_token.token;

    let me_request = test::TestRequest::get()
        .uri("/api/auth/me")
        .insert_header(("Authorization", format!("Bearer {}", alice_token.as_str())))
        .to_request();
    let me_response: MeResponse = test::call_and_read_body_json(&app, me_request).await;
    assert!(me_response.id > 0);
    assert_eq!(me_response.roles, vec!["user".to_owned()]);
    assert_eq!(
        me_response.claims.get("tenant_id").and_then(Value::as_i64),
        Some(1)
    );

    let create_alice = test::TestRequest::post()
        .uri("/api/tenant_post")
        .insert_header(("Authorization", format!("Bearer {}", alice_token.as_str())))
        .set_json(&TenantPostCreate {
            title: "alice tenant".to_owned(),
        })
        .to_request();
    let create_alice_response = test::call_service(&app, create_alice).await;
    assert_eq!(create_alice_response.status(), StatusCode::CREATED);

    let alice_id: i64 = query_scalar::<sqlx::Any, i64>("SELECT id FROM user WHERE email = ?")
        .bind("alice@example.com")
        .fetch_one(&pool)
        .await
        .expect("alice user id should exist");

    let created: DbTenantPost = query_as::<sqlx::Any, DbTenantPost>(
        "SELECT id, title, user_id, tenant_id FROM tenant_post LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("tenant post should exist");
    assert_eq!(created.user_id, alice_id);
    assert_eq!(created.tenant_id, 1);

    let bob_list = test::TestRequest::get()
        .uri("/api/tenant_post")
        .insert_header(("Authorization", format!("Bearer {}", bob_token.as_str())))
        .to_request();
    let bob_posts: TenantPostListResponse = test::call_and_read_body_json(&app, bob_list).await;
    assert_eq!(bob_posts.total, 0);
    assert_eq!(bob_posts.count, 0);
    assert!(bob_posts.items.is_empty());
}

#[actix_web::test]
async fn auth_login_emits_generic_numeric_claim_columns() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("generic_claims");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            org_id INTEGER,
            claim_workspace_id INTEGER,
            external_id TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("user table should be created");

    let app = test::init_service(
        App::new().service(scope("/api").configure(|cfg| auth::auth_routes(cfg, pool.clone()))),
    )
    .await;

    let register_request = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&auth::RegisterInput {
            email: "claims@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let register_response = test::call_service(&app, register_request).await;
    assert_eq!(register_response.status(), StatusCode::CREATED);

    query("UPDATE user SET org_id = ?, claim_workspace_id = ?, external_id = ? WHERE email = ?")
        .bind(7_i64)
        .bind(42_i64)
        .bind("text-only")
        .bind("claims@example.com")
        .execute(&pool)
        .await
        .expect("user claim columns should be updated");

    let login_request = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "claims@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let token_response: TokenResponse = test::call_and_read_body_json(&app, login_request).await;

    let me_request = test::TestRequest::get()
        .uri("/api/auth/me")
        .insert_header((
            "Authorization",
            format!("Bearer {}", token_response.token.as_str()),
        ))
        .to_request();
    let me_response: MeResponse = test::call_and_read_body_json(&app, me_request).await;

    assert_eq!(
        me_response.claims.get("org_id").and_then(Value::as_i64),
        Some(7)
    );
    assert_eq!(
        me_response
            .claims
            .get("workspace_id")
            .and_then(Value::as_i64),
        Some(42)
    );
    assert!(!me_response.claims.contains_key("claim_workspace_id"));
    assert!(!me_response.claims.contains_key("external_id"));
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
