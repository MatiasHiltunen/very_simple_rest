use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::json;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::db::{connect, query};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "bridgeboard-example-secret";

rest_api_from_eon!("examples/bridgeboard/bridgeboard.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    iss: Option<String>,
    aud: Option<String>,
    exp: usize,
}

#[actix_web::test]
async fn bridgeboard_example_serves_public_catalog_static_assets_and_owner_scoped_requests() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("bridgeboard_example");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE organization (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL,
            name TEXT NOT NULL,
            country TEXT NOT NULL,
            city TEXT NOT NULL,
            website_url TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            collaboration_stage TEXT NOT NULL,
            summary TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now')),
            updated_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now'))
        )",
    )
    .execute(&pool)
    .await
    .expect("organization schema should apply");
    query(
        "CREATE TABLE interest (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            work_mode TEXT NOT NULL,
            summary TEXT NOT NULL,
            desired_start_on TEXT NULL,
            created_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now')),
            updated_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now'))
        )",
    )
    .execute(&pool)
    .await
    .expect("interest schema should apply");
    query(
        "CREATE TABLE thesis_topic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            discipline TEXT NOT NULL,
            location TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            summary TEXT NOT NULL,
            application_deadline TEXT NULL,
            created_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now')),
            updated_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now'))
        )",
    )
    .execute(&pool)
    .await
    .expect("thesis topic schema should apply");
    query(
        "CREATE TABLE collaboration_request (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            requester_user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL,
            preferred_start_on TEXT NULL,
            created_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now')),
            updated_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now'))
        )",
    )
    .execute(&pool)
    .await
    .expect("collaboration request schema should apply");

    query(
        "INSERT INTO organization (
            slug, name, country, city, website_url, contact_email, collaboration_stage, summary
        ) VALUES (
            'nordic-bridge',
            'Nordic Bridge Institute',
            'Finland',
            'Oulu',
            'https://bridge.example',
            'hello@bridge.example',
            'Open call',
            'Coordinates cross-border thesis work between applied research labs and regional industry partners.'
        )",
    )
    .execute(&pool)
    .await
    .expect("organization seed should insert");
    query(
        "INSERT INTO interest (organization_id, title, work_mode, summary, desired_start_on) VALUES (
            1,
            'Shared supervision for AI pilots',
            'Hybrid sprint',
            'Looking for thesis topics on trustworthy automation and international mentoring workflows.',
            '2026-09-01'
        )",
    )
    .execute(&pool)
    .await
    .expect("interest seed should insert");
    query(
        "INSERT INTO thesis_topic (
            organization_id, title, discipline, location, contact_email, summary, application_deadline
        ) VALUES (
            1,
            'Cross-border data trust for apprenticeships',
            'Data governance',
            'Oulu + remote',
            'mentor@bridge.example',
            'Map a practical trust model for sharing apprenticeship mobility data between campuses and employers.',
            '2026-08-30'
        )",
    )
    .execute(&pool)
    .await
    .expect("thesis topic seed should insert");

    let app = test::init_service(
        App::new()
            .configure(bridgeboard::configure_security)
            .service(scope("/api").configure(|cfg| bridgeboard::configure(cfg, pool.clone())))
            .configure(bridgeboard::configure_static),
    )
    .await;

    let root_request = test::TestRequest::get().uri("/").to_request();
    let root_response = test::call_service(&app, root_request).await;
    assert_eq!(root_response.status(), StatusCode::OK);
    let root_body = test::read_body(root_response).await;
    assert!(String::from_utf8_lossy(&root_body).contains("Bridgeboard"));

    let organization_request = test::TestRequest::get()
        .uri("/api/organization?filter_name_contains=bridge")
        .to_request();
    let organization_response = test::call_service(&app, organization_request).await;
    assert_eq!(organization_response.status(), StatusCode::OK);
    let organizations: bridgeboard::OrganizationListResponse =
        test::read_body_json(organization_response).await;
    assert_eq!(organizations.total, 1);
    assert_eq!(organizations.items[0].slug, "nordic-bridge");

    let nested_interest_request = test::TestRequest::get()
        .uri("/api/organization/1/interest?filter_title_contains=AI")
        .to_request();
    let nested_interest_response = test::call_service(&app, nested_interest_request).await;
    assert_eq!(nested_interest_response.status(), StatusCode::OK);
    let interests: bridgeboard::InterestListResponse =
        test::read_body_json(nested_interest_response).await;
    assert_eq!(interests.total, 1);

    let anonymous_request = test::TestRequest::post()
        .uri("/api/collaboration_request")
        .set_json(json!({
            "organization_id": 1,
            "title": "Unauthorized request",
            "message": "This should be rejected because the caller is anonymous and not allowed to create requests.",
            "status": "submitted",
            "preferred_start_on": "2026-09-15"
        }))
        .to_request();
    let anonymous_response = test::call_service(&app, anonymous_request).await;
    assert_eq!(anonymous_response.status(), StatusCode::UNAUTHORIZED);

    let user_token = issue_token(7, &["user"]);
    let create_request = test::TestRequest::post()
        .uri("/api/collaboration_request")
        .insert_header(("Authorization", format!("Bearer {}", user_token.as_str())))
        .set_json(json!({
            "organization_id": 1,
            "title": "Applied AI thesis partnership",
            "message": "We want to connect a student team with the organization to shape a shared supervision track around applied AI validation.",
            "status": "submitted",
            "preferred_start_on": "2026-09-15"
        }))
        .to_request();
    let create_response = test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let own_list_request = test::TestRequest::get()
        .uri("/api/collaboration_request?sort=created_at&order=desc")
        .insert_header(("Authorization", format!("Bearer {}", user_token.as_str())))
        .to_request();
    let own_list_response = test::call_service(&app, own_list_request).await;
    assert_eq!(own_list_response.status(), StatusCode::OK);
    let own_requests: bridgeboard::CollaborationRequestListResponse =
        test::read_body_json(own_list_response).await;
    assert_eq!(own_requests.total, 1);
    assert_eq!(own_requests.items[0].requester_user_id, 7);

    let other_user_token = issue_token(8, &["user"]);
    let other_list_request = test::TestRequest::get()
        .uri("/api/collaboration_request")
        .insert_header((
            "Authorization",
            format!("Bearer {}", other_user_token.as_str()),
        ))
        .to_request();
    let other_list_response = test::call_service(&app, other_list_request).await;
    assert_eq!(other_list_response.status(), StatusCode::OK);
    let other_requests: bridgeboard::CollaborationRequestListResponse =
        test::read_body_json(other_list_response).await;
    assert_eq!(other_requests.total, 0);

    let admin_token = issue_token(1, &["admin"]);
    let admin_list_request = test::TestRequest::get()
        .uri("/api/collaboration_request")
        .insert_header(("Authorization", format!("Bearer {}", admin_token.as_str())))
        .to_request();
    let admin_list_response = test::call_service(&app, admin_list_request).await;
    assert_eq!(admin_list_response.status(), StatusCode::OK);
    let admin_requests: bridgeboard::CollaborationRequestListResponse =
        test::read_body_json(admin_list_response).await;
    assert_eq!(admin_requests.total, 1);
}

fn issue_token(user_id: i64, roles: &[&str]) -> String {
    encode(
        &Header::default(),
        &TestClaims {
            sub: user_id,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            iss: Some("bridgeboard".to_owned()),
            aud: Some("bridgeboard_clients".to_owned()),
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
