use very_simple_rest::actix_web::{App, HttpResponse, http::StatusCode, test, web};
use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/runtime_api.eon");

#[actix_web::test]
async fn eon_runtime_config_enables_dynamic_response_compression() {
    let runtime = runtime_api::runtime();
    let app = test::init_service(
        App::new()
            .wrap(very_simple_rest::core::runtime::compression_middleware(
                &runtime,
            ))
            .route(
                "/payload",
                web::get().to(|| async { HttpResponse::Ok().body("x".repeat(4096)) }),
            ),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/payload")
        .insert_header(("Accept-Encoding", "gzip"))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-encoding")
            .and_then(|value| value.to_str().ok()),
        Some("gzip")
    );
}
