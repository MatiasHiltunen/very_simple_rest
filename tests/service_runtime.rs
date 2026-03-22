use very_simple_rest::actix_web::{App, HttpResponse, http::StatusCode, test, web};
use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/runtime_api.eon");
rest_api_from_eon!("tests/fixtures/authorization_contract_api.eon");

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

#[actix_web::test]
async fn eon_service_config_registers_authorization_runtime_app_data() {
    let pool = very_simple_rest::db::connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite should connect");
    let app = test::init_service(App::new().service(web::scope("/api").configure(|cfg| {
        authorization_contract_api::configure(cfg, pool.clone());
        cfg.route(
                    "/authz/runtime",
                    web::get().to(
                        |runtime: web::Data<
                            very_simple_rest::authorization::AuthorizationRuntime,
                        >| async move {
                            HttpResponse::Ok()
                                .content_type("text/plain; charset=utf-8")
                                .body(runtime.model().resources.len().to_string())
                        },
                    ),
                );
    })))
    .await;

    let request = test::TestRequest::get()
        .uri("/api/authz/runtime")
        .to_request();
    let response = test::call_service(&app, request).await;
    let body = test::read_body(response).await;

    assert_eq!(body.as_ref(), b"1");
}
