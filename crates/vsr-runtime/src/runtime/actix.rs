//! Actix adapter for shared runtime settings.

use actix_web::middleware::{Compress, Condition};

use super::RuntimeConfig;

/// Apply HTTP response compression when configured.
pub fn compression_middleware(runtime: &RuntimeConfig) -> Condition<Compress> {
    Condition::new(runtime.compression.enabled, Compress::default())
}

#[cfg(test)]
mod tests {
    use actix_web::{App, HttpResponse, http::StatusCode, test, web};

    use super::compression_middleware;
    use crate::runtime::{CompressionConfig, RuntimeConfig};

    #[actix_web::test]
    async fn enabled_compression_sets_content_encoding() {
        let runtime = RuntimeConfig {
            compression: CompressionConfig {
                enabled: true,
                static_precompressed: false,
            },
        };

        let app = test::init_service(App::new().wrap(compression_middleware(&runtime)).route(
            "/payload",
            web::get().to(|| async { HttpResponse::Ok().body("x".repeat(4096)) }),
        ))
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
    async fn disabled_compression_skips_content_encoding() {
        let runtime = RuntimeConfig::default();

        let app = test::init_service(App::new().wrap(compression_middleware(&runtime)).route(
            "/payload",
            web::get().to(|| async { HttpResponse::Ok().body("x".repeat(4096)) }),
        ))
        .await;

        let request = test::TestRequest::get()
            .uri("/payload")
            .insert_header(("Accept-Encoding", "gzip"))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("content-encoding").is_none());
    }
}
