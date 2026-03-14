use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "validation-api-secret";

rest_api_from_eon!("tests/fixtures/validated_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    code: String,
    message: String,
    field: Option<String>,
}

#[actix_web::test]
async fn generated_handlers_enforce_field_validation_rules() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let database_url = unique_sqlite_url("validation_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    query(
        "CREATE TABLE widget (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            score INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("schema should apply");

    let app = test::init_service(
        App::new()
            .service(scope("/api").configure(|cfg| validated_api::configure(cfg, pool.clone()))),
    )
    .await;

    let token = issue_token(1, &["user"]);

    let invalid_title = test::TestRequest::post()
        .uri("/api/widget")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(&validated_api::WidgetCreate {
            title: "hi".to_owned(),
            score: 5,
        })
        .to_request();
    let invalid_title_response = test::call_service(&app, invalid_title).await;
    assert_eq!(invalid_title_response.status(), StatusCode::BAD_REQUEST);
    let invalid_title_body: ApiErrorResponse = test::read_body_json(invalid_title_response).await;
    assert_eq!(invalid_title_body.code, "validation_error");
    assert_eq!(invalid_title_body.field.as_deref(), Some("title"));
    assert!(invalid_title_body.message.contains("at least 3 characters"));

    let malformed_create = test::TestRequest::post()
        .uri("/api/widget")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .insert_header(("Content-Type", "application/json"))
        .set_payload("{bad json")
        .to_request();
    let malformed_create_response = test::call_service(&app, malformed_create).await;
    assert_eq!(malformed_create_response.status(), StatusCode::BAD_REQUEST);
    let malformed_create_body: ApiErrorResponse =
        test::read_body_json(malformed_create_response).await;
    assert_eq!(malformed_create_body.code, "invalid_json");
    assert_eq!(
        malformed_create_body.message,
        "Request body is not valid JSON"
    );
    assert_eq!(malformed_create_body.field, None);

    let invalid_path = test::TestRequest::get()
        .uri("/api/widget/not-an-int")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let invalid_path_response = test::call_service(&app, invalid_path).await;
    assert_eq!(invalid_path_response.status(), StatusCode::BAD_REQUEST);
    let invalid_path_body: ApiErrorResponse = test::read_body_json(invalid_path_response).await;
    assert_eq!(invalid_path_body.code, "invalid_path");
    assert_eq!(invalid_path_body.message, "Path parameters are invalid");
    assert_eq!(invalid_path_body.field, None);

    let invalid_score = test::TestRequest::post()
        .uri("/api/widget")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(&validated_api::WidgetCreate {
            title: "valid".to_owned(),
            score: 0,
        })
        .to_request();
    let invalid_score_response = test::call_service(&app, invalid_score).await;
    assert_eq!(invalid_score_response.status(), StatusCode::BAD_REQUEST);
    let invalid_score_body: ApiErrorResponse = test::read_body_json(invalid_score_response).await;
    assert_eq!(invalid_score_body.code, "validation_error");
    assert_eq!(invalid_score_body.field.as_deref(), Some("score"));
    assert!(invalid_score_body.message.contains("at least 1"));

    let valid_create = test::TestRequest::post()
        .uri("/api/widget")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(&validated_api::WidgetCreate {
            title: "valid".to_owned(),
            score: 5,
        })
        .to_request();
    let valid_create_response = test::call_service(&app, valid_create).await;
    assert_eq!(valid_create_response.status(), StatusCode::CREATED);

    query("INSERT INTO widget (title, score) VALUES (?, ?), (?, ?)")
        .bind("alpha")
        .bind(7_i64)
        .bind("zeta")
        .bind(2_i64)
        .execute(&pool)
        .await
        .expect("extra widget rows should insert");

    let sorted_list = test::TestRequest::get()
        .uri("/api/widget?limit=2&sort=score&order=desc")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let sorted_list_response = test::call_service(&app, sorted_list).await;
    assert_eq!(sorted_list_response.status(), StatusCode::OK);
    let sorted_widgets: validated_api::WidgetListResponse =
        test::read_body_json(sorted_list_response).await;
    assert_eq!(sorted_widgets.total, 3);
    assert_eq!(sorted_widgets.count, 2);
    assert_eq!(sorted_widgets.limit, Some(2));
    assert_eq!(sorted_widgets.offset, 0);
    assert_eq!(sorted_widgets.next_offset, Some(2));
    assert_eq!(sorted_widgets.items[0].title, "alpha");
    assert_eq!(sorted_widgets.items[0].score, 7);
    assert_eq!(sorted_widgets.items[1].title, "valid");
    assert_eq!(sorted_widgets.items[1].score, 5);

    let filtered_list = test::TestRequest::get()
        .uri("/api/widget?filter_title=alpha")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let filtered_list_response = test::call_service(&app, filtered_list).await;
    assert_eq!(filtered_list_response.status(), StatusCode::OK);
    let filtered_widgets: validated_api::WidgetListResponse =
        test::read_body_json(filtered_list_response).await;
    assert_eq!(filtered_widgets.total, 1);
    assert_eq!(filtered_widgets.count, 1);
    assert_eq!(filtered_widgets.next_offset, None);
    assert_eq!(filtered_widgets.items[0].title, "alpha");

    let paged_list = test::TestRequest::get()
        .uri("/api/widget?limit=1&offset=1&sort=score&order=desc")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let paged_list_response = test::call_service(&app, paged_list).await;
    assert_eq!(paged_list_response.status(), StatusCode::OK);
    let paged_widgets: validated_api::WidgetListResponse =
        test::read_body_json(paged_list_response).await;
    assert_eq!(paged_widgets.total, 3);
    assert_eq!(paged_widgets.count, 1);
    assert_eq!(paged_widgets.limit, Some(1));
    assert_eq!(paged_widgets.offset, 1);
    assert_eq!(paged_widgets.next_offset, Some(2));
    assert_eq!(paged_widgets.items[0].title, "valid");

    let invalid_limit = test::TestRequest::get()
        .uri("/api/widget?limit=abc")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let invalid_limit_response = test::call_service(&app, invalid_limit).await;
    assert_eq!(invalid_limit_response.status(), StatusCode::BAD_REQUEST);
    let invalid_limit_body: ApiErrorResponse = test::read_body_json(invalid_limit_response).await;
    assert_eq!(invalid_limit_body.code, "invalid_query");
    assert_eq!(invalid_limit_body.message, "Query parameters are invalid");

    let invalid_sort = test::TestRequest::get()
        .uri("/api/widget?sort=missing")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let invalid_sort_response = test::call_service(&app, invalid_sort).await;
    assert_eq!(invalid_sort_response.status(), StatusCode::BAD_REQUEST);
    let invalid_sort_body: ApiErrorResponse = test::read_body_json(invalid_sort_response).await;
    assert_eq!(invalid_sort_body.code, "invalid_query");

    let invalid_offset = test::TestRequest::get()
        .uri("/api/widget?offset=1")
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .to_request();
    let invalid_offset_response = test::call_service(&app, invalid_offset).await;
    assert_eq!(invalid_offset_response.status(), StatusCode::BAD_REQUEST);
    let invalid_offset_body: ApiErrorResponse = test::read_body_json(invalid_offset_response).await;
    assert_eq!(invalid_offset_body.code, "invalid_pagination");
    assert_eq!(invalid_offset_body.message, "`offset` requires `limit`");

    let widget_id: i64 = query_scalar::<sqlx::Any, i64>("SELECT id FROM widget LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("widget row should exist");

    let invalid_update = test::TestRequest::put()
        .uri(&format!("/api/widget/{widget_id}"))
        .insert_header(("Authorization", format!("Bearer {}", token.as_str())))
        .set_json(&validated_api::WidgetUpdate {
            title: "too long title".to_owned(),
            score: 11,
        })
        .to_request();
    let invalid_update_response = test::call_service(&app, invalid_update).await;
    assert_eq!(invalid_update_response.status(), StatusCode::BAD_REQUEST);
    let invalid_update_body: ApiErrorResponse = test::read_body_json(invalid_update_response).await;
    assert_eq!(invalid_update_body.code, "validation_error");
    assert_eq!(invalid_update_body.field.as_deref(), Some("title"));
    assert!(
        invalid_update_body
            .message
            .contains("at most 10 characters")
    );
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
