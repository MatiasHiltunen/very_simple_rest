use std::time::{SystemTime, UNIX_EPOCH};

use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::prelude::*;
use very_simple_rest::sqlx::any::AnyPoolOptions;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
#[rest_api(table = "owned_post", id = "id", db = "sqlite")]
#[require_role(read = "user", create = "user", update = "user", delete = "user")]
#[row_policy(
    read = "owner:user_id",
    create = "set_owner:user_id",
    update = "owner:user_id",
    delete = "owner:user_id"
)]
struct OwnedPost {
    id: Option<i64>,
    title: String,
    user_id: i64,
    created_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(Debug, Deserialize, sqlx::FromRow)]
struct DbOwnedPost {
    id: i64,
    title: String,
    user_id: i64,
}

#[actix_web::test]
async fn row_policy_scopes_reads_and_mutations_across_auth_cases() {
    sqlx::any::install_default_drivers();

    let database_url = unique_sqlite_url("row_policy");
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("database should connect");

    sqlx::query(
        "CREATE TABLE user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("user table should be created");

    sqlx::query(
        "CREATE TABLE owned_post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .expect("owned_post table should be created");

    let app = test::init_service(
        App::new().service(
            scope("/api")
                .configure(|cfg| auth::auth_routes(cfg, pool.clone()))
                .configure(|cfg| OwnedPost::configure(cfg, pool.clone())),
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

    let register_admin = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&auth::RegisterInput {
            email: "admin@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let register_admin_response = test::call_service(&app, register_admin).await;
    assert_eq!(register_admin_response.status(), StatusCode::CREATED);

    sqlx::query("UPDATE user SET role = ? WHERE email = ?")
        .bind("admin")
        .bind("admin@example.com")
        .execute(&pool)
        .await
        .expect("admin role should be updated");

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

    let login_admin = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&auth::LoginInput {
            email: "admin@example.com".to_owned(),
            password: "password123".to_owned(),
        })
        .to_request();
    let admin_token: TokenResponse = test::call_and_read_body_json(&app, login_admin).await;
    let admin_token = admin_token.token;

    let alice_id: i64 = sqlx::query_scalar("SELECT id FROM user WHERE email = ?")
        .bind("alice@example.com")
        .fetch_one(&pool)
        .await
        .expect("alice id should exist");
    let bob_id: i64 = sqlx::query_scalar("SELECT id FROM user WHERE email = ?")
        .bind("bob@example.com")
        .fetch_one(&pool)
        .await
        .expect("bob id should exist");

    let unauthenticated_list = test::TestRequest::get().uri("/api/owned_post").to_request();
    let unauthenticated_list_response = test::call_service(&app, unauthenticated_list).await;
    assert_eq!(
        unauthenticated_list_response.status(),
        StatusCode::UNAUTHORIZED
    );

    let unauthenticated_create = test::TestRequest::post()
        .uri("/api/owned_post")
        .set_json(&OwnedPostCreate {
            title: "blocked".to_owned(),
        })
        .to_request();
    let unauthenticated_create_response = test::call_service(&app, unauthenticated_create).await;
    assert_eq!(
        unauthenticated_create_response.status(),
        StatusCode::UNAUTHORIZED
    );

    let create_alice_first = test::TestRequest::post()
        .uri("/api/owned_post")
        .insert_header(("Authorization", format!("Bearer {}", alice_token.as_str())))
        .set_json(&OwnedPostCreate {
            title: "alice first".to_owned(),
        })
        .to_request();
    let create_alice_first_response = test::call_service(&app, create_alice_first).await;
    assert_eq!(create_alice_first_response.status(), StatusCode::CREATED);

    let create_alice_second = test::TestRequest::post()
        .uri("/api/owned_post")
        .insert_header(("Authorization", format!("Bearer {}", alice_token.as_str())))
        .set_json(&OwnedPostCreate {
            title: "alice second".to_owned(),
        })
        .to_request();
    let create_alice_second_response = test::call_service(&app, create_alice_second).await;
    assert_eq!(create_alice_second_response.status(), StatusCode::CREATED);

    let create_bob = test::TestRequest::post()
        .uri("/api/owned_post")
        .insert_header(("Authorization", format!("Bearer {}", bob_token.as_str())))
        .set_json(&OwnedPostCreate {
            title: "bob only".to_owned(),
        })
        .to_request();
    let create_bob_response = test::call_service(&app, create_bob).await;
    assert_eq!(create_bob_response.status(), StatusCode::CREATED);

    let created_posts: Vec<DbOwnedPost> =
        sqlx::query_as("SELECT id, title, user_id FROM owned_post ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("created rows should exist");
    assert_eq!(created_posts.len(), 3);

    let alice_first_id = created_posts
        .iter()
        .find(|post| post.title == "alice first")
        .map(|post| post.id)
        .expect("alice first row should exist");
    let alice_second_id = created_posts
        .iter()
        .find(|post| post.title == "alice second")
        .map(|post| post.id)
        .expect("alice second row should exist");
    let bob_post_id = created_posts
        .iter()
        .find(|post| post.title == "bob only")
        .map(|post| post.id)
        .expect("bob row should exist");

    let alice_first = created_posts
        .iter()
        .find(|post| post.id == alice_first_id)
        .expect("alice first row should be queryable");
    assert_eq!(alice_first.user_id, alice_id);

    let bob_only = created_posts
        .iter()
        .find(|post| post.id == bob_post_id)
        .expect("bob row should be queryable");
    assert_eq!(bob_only.user_id, bob_id);

    let unauthenticated_delete = test::TestRequest::delete()
        .uri(&format!("/api/owned_post/{alice_first_id}"))
        .to_request();
    let unauthenticated_delete_response = test::call_service(&app, unauthenticated_delete).await;
    assert_eq!(
        unauthenticated_delete_response.status(),
        StatusCode::UNAUTHORIZED
    );

    let alice_list_request = test::TestRequest::get()
        .uri("/api/owned_post")
        .insert_header(("Authorization", format!("Bearer {}", alice_token.as_str())))
        .to_request();
    let alice_posts: Vec<OwnedPost> = test::call_and_read_body_json(&app, alice_list_request).await;
    assert_eq!(alice_posts.len(), 2);
    assert!(alice_posts.iter().all(|post| post.user_id == alice_id));

    let bob_list_request = test::TestRequest::get()
        .uri("/api/owned_post")
        .insert_header(("Authorization", format!("Bearer {}", bob_token.as_str())))
        .to_request();
    let bob_posts: Vec<OwnedPost> = test::call_and_read_body_json(&app, bob_list_request).await;
    assert_eq!(bob_posts.len(), 1);
    assert!(bob_posts.iter().all(|post| post.user_id == bob_id));

    let admin_list_request = test::TestRequest::get()
        .uri("/api/owned_post")
        .insert_header(("Authorization", format!("Bearer {}", admin_token.as_str())))
        .to_request();
    let admin_posts: Vec<OwnedPost> = test::call_and_read_body_json(&app, admin_list_request).await;
    assert_eq!(admin_posts.len(), 3);

    let bob_get_request = test::TestRequest::get()
        .uri(&format!("/api/owned_post/{alice_first_id}"))
        .insert_header(("Authorization", format!("Bearer {}", bob_token.as_str())))
        .to_request();
    let bob_get_response = test::call_service(&app, bob_get_request).await;
    assert_eq!(bob_get_response.status(), StatusCode::NOT_FOUND);

    let admin_get_request = test::TestRequest::get()
        .uri(&format!("/api/owned_post/{alice_first_id}"))
        .insert_header(("Authorization", format!("Bearer {}", admin_token.as_str())))
        .to_request();
    let admin_post: OwnedPost = test::call_and_read_body_json(&app, admin_get_request).await;
    assert_eq!(admin_post.id, Some(alice_first_id));
    assert_eq!(admin_post.user_id, alice_id);

    let bob_update_request = test::TestRequest::put()
        .uri(&format!("/api/owned_post/{alice_first_id}"))
        .insert_header(("Authorization", format!("Bearer {}", bob_token.as_str())))
        .set_json(&OwnedPostUpdate {
            title: "hacked".to_owned(),
        })
        .to_request();
    let bob_update_response = test::call_service(&app, bob_update_request).await;
    assert_eq!(bob_update_response.status(), StatusCode::NOT_FOUND);

    let alice_update_request = test::TestRequest::put()
        .uri(&format!("/api/owned_post/{alice_first_id}"))
        .insert_header(("Authorization", format!("Bearer {}", alice_token.as_str())))
        .set_json(&OwnedPostUpdate {
            title: "updated by owner".to_owned(),
        })
        .to_request();
    let alice_update_response = test::call_service(&app, alice_update_request).await;
    assert_eq!(alice_update_response.status(), StatusCode::OK);

    let admin_update_request = test::TestRequest::put()
        .uri(&format!("/api/owned_post/{bob_post_id}"))
        .insert_header(("Authorization", format!("Bearer {}", admin_token.as_str())))
        .set_json(&OwnedPostUpdate {
            title: "updated by admin".to_owned(),
        })
        .to_request();
    let admin_update_response = test::call_service(&app, admin_update_request).await;
    assert_eq!(admin_update_response.status(), StatusCode::OK);

    let updated_alice: DbOwnedPost =
        sqlx::query_as("SELECT id, title, user_id FROM owned_post WHERE id = ?")
            .bind(alice_first_id)
            .fetch_one(&pool)
            .await
            .expect("alice row should still exist");
    assert_eq!(updated_alice.user_id, alice_id);
    assert_eq!(updated_alice.title, "updated by owner");

    let updated_bob: DbOwnedPost =
        sqlx::query_as("SELECT id, title, user_id FROM owned_post WHERE id = ?")
            .bind(bob_post_id)
            .fetch_one(&pool)
            .await
            .expect("bob row should still exist");
    assert_eq!(updated_bob.user_id, bob_id);
    assert_eq!(updated_bob.title, "updated by admin");

    let bob_delete_request = test::TestRequest::delete()
        .uri(&format!("/api/owned_post/{alice_second_id}"))
        .insert_header(("Authorization", format!("Bearer {}", bob_token.as_str())))
        .to_request();
    let bob_delete_response = test::call_service(&app, bob_delete_request).await;
    assert_eq!(bob_delete_response.status(), StatusCode::NOT_FOUND);

    let alice_delete_request = test::TestRequest::delete()
        .uri(&format!("/api/owned_post/{alice_second_id}"))
        .insert_header(("Authorization", format!("Bearer {}", alice_token.as_str())))
        .to_request();
    let alice_delete_response = test::call_service(&app, alice_delete_request).await;
    assert_eq!(alice_delete_response.status(), StatusCode::OK);

    let admin_delete_request = test::TestRequest::delete()
        .uri(&format!("/api/owned_post/{bob_post_id}"))
        .insert_header(("Authorization", format!("Bearer {}", admin_token.as_str())))
        .to_request();
    let admin_delete_response = test::call_service(&app, admin_delete_request).await;
    assert_eq!(admin_delete_response.status(), StatusCode::OK);

    let remaining_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM owned_post")
        .fetch_one(&pool)
        .await
        .expect("remaining row count should be queryable");
    assert_eq!(remaining_count, 1);
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
}
