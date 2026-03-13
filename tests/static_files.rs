use very_simple_rest::actix_web::{App, HttpResponse, http::StatusCode, test, web};
use very_simple_rest::rest_api_from_eon;
use very_simple_rest::sqlx::any::AnyPoolOptions;

rest_api_from_eon!("tests/fixtures/static_site_api.eon");

#[actix_web::test]
async fn eon_static_config_serves_assets_and_spa_routes() {
    very_simple_rest::sqlx::any::install_default_drivers();

    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("database should connect");

    let app = test::init_service(
        App::new()
            .route(
                "/docs",
                web::get().to(|| async { HttpResponse::Ok().body("docs") }),
            )
            .service(
                web::scope("/api").configure(|cfg| static_site_api::configure(cfg, pool.clone())),
            )
            .configure(static_site_api::configure_static),
    )
    .await;

    let root_request = test::TestRequest::get().uri("/").to_request();
    let root_response = test::call_service(&app, root_request).await;
    assert_eq!(root_response.status(), StatusCode::OK);
    assert_eq!(
        root_response
            .headers()
            .get("cache-control")
            .expect("cache header should exist"),
        "no-store"
    );
    let root_body = test::read_body(root_response).await;
    assert!(String::from_utf8_lossy(&root_body).contains("Static Fixture"));

    let spa_request = test::TestRequest::get()
        .uri("/dashboard")
        .insert_header(("Accept", "text/html"))
        .to_request();
    let spa_response = test::call_service(&app, spa_request).await;
    assert_eq!(spa_response.status(), StatusCode::OK);
    let spa_body = test::read_body(spa_response).await;
    assert!(String::from_utf8_lossy(&spa_body).contains("Static Fixture"));

    let asset_request = test::TestRequest::get().uri("/assets/app.js").to_request();
    let asset_response = test::call_service(&app, asset_request).await;
    assert_eq!(asset_response.status(), StatusCode::OK);
    assert_eq!(
        asset_response
            .headers()
            .get("cache-control")
            .expect("asset cache header should exist"),
        "public, max-age=31536000, immutable"
    );
    let asset_body = test::read_body(asset_response).await;
    assert!(String::from_utf8_lossy(&asset_body).contains("static fixture"));

    let missing_asset_request = test::TestRequest::get().uri("/missing.js").to_request();
    let missing_asset_response = test::call_service(&app, missing_asset_request).await;
    assert_eq!(missing_asset_response.status(), StatusCode::NOT_FOUND);

    let docs_request = test::TestRequest::get().uri("/docs").to_request();
    let docs_response = test::call_service(&app, docs_request).await;
    assert_eq!(docs_response.status(), StatusCode::OK);
    let docs_body = test::read_body(docs_response).await;
    assert_eq!(String::from_utf8_lossy(&docs_body), "docs");

    let api_request = test::TestRequest::get().uri("/api/page").to_request();
    let api_response = test::call_service(&app, api_request).await;
    assert_eq!(api_response.status(), StatusCode::UNAUTHORIZED);
}
