//! Actix bootstrap for native services that still register framework routes.
//!
//! Application route registration is supplied by the caller. Binding, common
//! middleware, documentation endpoints, and request telemetry live here while
//! native handlers move to the shared route contract.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use actix_web::{
    App, HttpResponse, HttpServer,
    dev::{Server, Service},
    middleware::Logger,
    web,
};
use vsr_core::{HttpRequestTelemetry, record_http_request};

use crate::{
    runtime::{RuntimeConfig, actix::compression_middleware},
    security::{
        SecurityConfig,
        actix::{cors_middleware, security_headers_middleware},
    },
};

/// Shared settings for the native Actix application server.
pub struct NativeActixServerConfig {
    /// Address passed to Actix binding, including a port.
    pub bind_addr: String,
    /// Optional explicit worker count.
    pub workers: Option<usize>,
    /// Optional Rustls configuration, loaded from service TLS settings.
    pub tls: Option<rustls::ServerConfig>,
    /// Response compression settings.
    pub runtime: RuntimeConfig,
    /// Cross-origin and browser security settings.
    pub security: SecurityConfig,
    /// Serialized OpenAPI document served at `/openapi.json`.
    pub openapi_json: Arc<String>,
    /// HTML document served at `/docs`.
    pub docs_html: Arc<String>,
}

/// A bound native server and the addresses assigned by the operating system.
pub struct BoundNativeActixServer {
    /// Future that serves until shutdown or error.
    pub server: Server,
    /// Bound addresses, including an OS-assigned port when requested.
    pub addresses: Vec<SocketAddr>,
}

/// Bind the native Actix application with shared middleware and caller routes.
///
/// The caller supplies service-specific auth, API, static, and storage routes
/// through `configure`. Binding happens before this function returns; the caller
/// runs the returned server and owns its lifecycle bookkeeping.
pub fn bind_native_actix_server<F>(
    config: NativeActixServerConfig,
    configure: F,
) -> std::io::Result<BoundNativeActixServer>
where
    F: Fn(&mut web::ServiceConfig) + Clone + Send + 'static,
{
    let NativeActixServerConfig {
        bind_addr,
        workers,
        tls,
        runtime,
        security,
        openapi_json,
        docs_html,
    } = config;
    let server = HttpServer::new(move || {
        let runtime = runtime.clone();
        let security = security.clone();
        let openapi_json = openapi_json.clone();
        let docs_html = docs_html.clone();
        let configure = configure.clone();

        App::new()
            .wrap(Logger::default())
            .wrap_fn(|req, service| {
                let method = req.method().as_str().to_owned();
                let route = req
                    .match_pattern()
                    .unwrap_or_else(|| "<unmatched>".to_owned());
                let started_at = Instant::now();
                let future = service.call(req);
                async move {
                    let response = future.await?;
                    record_http_request(&HttpRequestTelemetry::new(
                        method.as_str(),
                        route.as_str(),
                        response.status().as_u16(),
                        started_at.elapsed().as_secs_f64() * 1000.0,
                    ));
                    Ok(response)
                }
            })
            .wrap(compression_middleware(&runtime))
            .wrap(cors_middleware(&security))
            .wrap(security_headers_middleware(&security))
            .route("/healthz", web::get().to(healthz))
            .route("/readyz", web::get().to(readyz))
            .route(
                "/openapi.json",
                web::get().to(move || {
                    let openapi_json = openapi_json.clone();
                    async move {
                        HttpResponse::Ok()
                            .content_type("application/json")
                            .body(openapi_json.as_ref().clone())
                    }
                }),
            )
            .route(
                "/docs",
                web::get().to(move || {
                    let docs_html = docs_html.clone();
                    async move {
                        HttpResponse::Ok()
                            .content_type("text/html; charset=utf-8")
                            .body(docs_html.as_ref().clone())
                    }
                }),
            )
            .configure(move |cfg| configure(cfg))
    });
    let server = if let Some(workers) = workers {
        server.workers(workers)
    } else {
        server
    };
    let server = if let Some(tls) = tls {
        log::info!("Server listening on https://{bind_addr}");
        server.bind_rustls_0_23(&bind_addr, tls)?
    } else {
        log::info!("Server listening on http://{bind_addr}");
        server.bind(&bind_addr)?
    };
    let addresses = server.addrs();
    Ok(BoundNativeActixServer {
        server: server.run(),
        addresses,
    })
}

/// Choose the native default bind address for HTTP or HTTPS.
pub fn default_bind_addr(tls_enabled: bool) -> &'static str {
    if tls_enabled {
        "127.0.0.1:8443"
    } else {
        "127.0.0.1:8080"
    }
}

/// Parse the optional `VSR_HTTP_WORKERS` environment setting.
pub fn workers_from_env() -> Result<Option<usize>, String> {
    const ENV: &str = "VSR_HTTP_WORKERS";
    match std::env::var(ENV) {
        Ok(raw) => {
            let workers = raw.parse::<usize>().map_err(|error| {
                format!("{ENV} must be a positive integer, got `{raw}`: {error}")
            })?;
            if workers == 0 {
                return Err(format!("{ENV} must be greater than 0"));
            }
            Ok(Some(workers))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{ENV} must contain valid UTF-8")),
    }
}

async fn healthz() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(r#"{"status":"ok"}"#)
}

async fn readyz() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(r#"{"status":"ready"}"#)
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use actix_web::{HttpResponse, web};

    use super::{NativeActixServerConfig, bind_native_actix_server, default_bind_addr};
    use crate::{runtime::RuntimeConfig, security::SecurityConfig};

    #[test]
    fn native_defaults_keep_existing_ports() {
        assert_eq!(default_bind_addr(false), "127.0.0.1:8080");
        assert_eq!(default_bind_addr(true), "127.0.0.1:8443");
    }

    #[actix_web::test]
    async fn native_bootstrap_serves_shared_and_registered_routes() {
        let mut security = SecurityConfig::default();
        security.headers.content_type_options = true;
        let bound = bind_native_actix_server(
            NativeActixServerConfig {
                bind_addr: "127.0.0.1:0".into(),
                workers: Some(1),
                tls: None,
                runtime: RuntimeConfig::default(),
                security,
                openapi_json: Arc::new("{}".into()),
                docs_html: Arc::new("<h1>Docs</h1>".into()),
            },
            |cfg: &mut web::ServiceConfig| {
                cfg.route(
                    "/custom",
                    web::get().to(|| async { HttpResponse::Ok().body("custom") }),
                );
            },
        )
        .unwrap();
        let base = format!("http://{}", bound.addresses[0]);
        let handle = bound.server.handle();
        let task = actix_web::rt::spawn(bound.server);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        for (path, body) in [
            ("/healthz", r#"{"status":"ok"}"#),
            ("/readyz", r#"{"status":"ready"}"#),
            ("/openapi.json", "{}"),
            ("/docs", "<h1>Docs</h1>"),
            ("/custom", "custom"),
        ] {
            let response = client.get(format!("{base}{path}")).send().await.unwrap();
            assert_eq!(response.status(), 200, "{path}");
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert_eq!(response.text().await.unwrap(), body, "{path}");
        }

        handle.stop(true).await;
        task.await.unwrap().unwrap();
    }
}
