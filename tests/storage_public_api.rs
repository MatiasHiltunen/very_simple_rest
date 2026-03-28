use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use very_simple_rest::actix_web::{App, http::StatusCode, test};
use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/storage_public_api.eon");

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn unique_name(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough")
        .as_nanos();
    format!("{prefix}_{nanos}.txt")
}

#[actix_web::test]
async fn generated_handlers_serve_storage_public_mounts() {
    let uploads_dir = fixture_root().join("var/uploads");
    fs::create_dir_all(&uploads_dir).expect("uploads dir should exist");
    let file_name = unique_name("generated_storage");
    let file_path = uploads_dir.join(&file_name);
    fs::write(&file_path, b"hello generated storage").expect("fixture object should write");

    let app = test::init_service(App::new().configure(storage_public_api::configure_static)).await;

    let request = test::TestRequest::get()
        .uri(&format!("/uploads/{file_name}"))
        .to_request();
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = test::read_body(response).await;
    assert_eq!(body.as_ref(), b"hello generated storage");

    let _ = fs::remove_file(file_path);
}
