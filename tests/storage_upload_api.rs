use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::core::storage::StorageUploadResponse;
use very_simple_rest::db::connect;
use very_simple_rest::prelude::*;
use very_simple_rest::rest_api_from_eon;

const TEST_JWT_SECRET: &str = "storage-upload-api-secret";

rest_api_from_eon!("tests/fixtures/storage_upload_api.eon");

#[derive(Serialize)]
struct TestClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn unique_sqlite_url(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("vsr_{prefix}_{nanos}.db"));
    format!("sqlite:{}?mode=rwc", path.display())
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

fn multipart_upload_payload(file_name: &str, body: &[u8]) -> (String, Vec<u8>) {
    let boundary = "----vsr-storage-upload";
    let mut payload = Vec::new();
    payload.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{file_name}\"\r\nContent-Type: text/plain\r\n\r\n"
        )
        .as_bytes(),
    );
    payload.extend_from_slice(body);
    payload.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), payload)
}

#[actix_web::test]
async fn generated_handlers_accept_storage_uploads() {
    unsafe {
        std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    }

    let uploads_dir = fixture_root().join("var/uploads");
    fs::create_dir_all(&uploads_dir).expect("uploads dir should exist");

    let database_url = unique_sqlite_url("storage_upload_api");
    let pool = connect(&database_url)
        .await
        .expect("database should connect");

    let app =
        test::init_service(App::new().service(
            scope("/api").configure(|cfg| storage_upload_api::configure(cfg, pool.clone())),
        ))
        .await;

    let token = issue_token(1, &["user"]);
    let (content_type, payload) = multipart_upload_payload("notes.txt", b"hello upload");
    let request = test::TestRequest::post()
        .uri("/api/uploads")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", content_type))
        .set_payload(payload)
        .to_request();
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body: StorageUploadResponse = test::read_body_json(response).await;
    assert_eq!(body.backend, "uploads");
    assert_eq!(body.file_name, "notes.txt");
    assert_eq!(
        body.public_url.as_deref().unwrap_or(""),
        &format!("/uploads/{}", body.object_key)
    );
    assert_eq!(body.size_bytes, 12);
    let stored_path = uploads_dir.join(&body.object_key);
    assert!(
        stored_path.is_file(),
        "uploaded object should exist on disk"
    );

    let (forbidden_content_type, forbidden_payload) = multipart_upload_payload("notes.txt", b"x");
    let forbidden_request = test::TestRequest::post()
        .uri("/api/uploads")
        .insert_header((
            "Authorization",
            format!("Bearer {}", issue_token(2, &["viewer"]).as_str()),
        ))
        .insert_header(("Content-Type", forbidden_content_type))
        .set_payload(forbidden_payload)
        .to_request();
    let forbidden_response = test::call_service(&app, forbidden_request).await;
    assert_eq!(forbidden_response.status(), StatusCode::FORBIDDEN);

    let _ = fs::remove_file(stored_path);
}
