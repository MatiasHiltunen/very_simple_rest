use std::{fs, path::PathBuf};

use very_simple_rest::actix_web::{
    App,
    http::{StatusCode, header},
    test,
};
use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/storage_s3_compat_api.eon");

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[actix_web::test]
async fn generated_handlers_serve_s3_compatible_storage_routes() {
    let uploads_dir = fixture_root().join("var/s3-uploads");
    let _ = fs::remove_dir_all(&uploads_dir);
    fs::create_dir_all(&uploads_dir).expect("uploads dir should exist");

    let app =
        test::init_service(App::new().configure(storage_s3_compat_api::configure_static)).await;

    let put = test::TestRequest::put()
        .uri("/_s3/media/logo.txt")
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .insert_header(("x-amz-meta-origin", "generated-test"))
        .set_payload("hello s3 compat")
        .to_request();
    let put_response = test::call_service(&app, put).await;
    assert_eq!(put_response.status(), StatusCode::OK);
    assert!(uploads_dir.join("assets/logo.txt").is_file());

    let head = test::TestRequest::default()
        .method(actix_web::http::Method::HEAD)
        .uri("/_s3/media/logo.txt")
        .to_request();
    let head_response = test::call_service(&app, head).await;
    assert_eq!(head_response.status(), StatusCode::OK);
    assert_eq!(
        head_response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("head content type should exist"),
        "text/plain"
    );
    assert_eq!(
        head_response
            .headers()
            .get("x-amz-meta-origin")
            .expect("head metadata should exist"),
        "generated-test"
    );

    let get = test::TestRequest::get()
        .uri("/_s3/media/logo.txt")
        .to_request();
    let get_response = test::call_service(&app, get).await;
    assert_eq!(get_response.status(), StatusCode::OK);
    let body = test::read_body(get_response).await;
    assert_eq!(body.as_ref(), b"hello s3 compat");

    let list = test::TestRequest::get()
        .uri("/_s3/media?list-type=2&prefix=logo")
        .to_request();
    let list_response = test::call_service(&app, list).await;
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = String::from_utf8(test::read_body(list_response).await.to_vec())
        .expect("list response should be utf-8");
    assert!(list_body.contains("<Key>logo.txt</Key>"));

    let delete = test::TestRequest::delete()
        .uri("/_s3/media/logo.txt")
        .to_request();
    let delete_response = test::call_service(&app, delete).await;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
    assert!(
        !uploads_dir.join("assets/logo.txt").exists(),
        "object should be removed after delete"
    );

    let _ = fs::remove_dir_all(&uploads_dir);
}
