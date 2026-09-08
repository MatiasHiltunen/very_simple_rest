//! Actix transport for the shared VSR route and handler contracts.
//! Native CLI/generated applications retain their existing Actix wiring.

use std::{net::SocketAddr, sync::Arc};

use actix_web::{
    App, HttpRequest, HttpResponse,
    middleware::{Compress, Condition, DefaultHeaders},
    web,
};
use bytes::Bytes;
use vsr_core::error::{VsrError, VsrResult};

#[cfg(test)]
use super::transport::{new_request_id, parse_query_string};
use super::{
    Handler, HeaderFields, HttpMethod, HttpServer, MiddlewareConfig, Readiness, ResponseBody,
    ResponseEnvelope, RouteTable, ServerConfig, ServerHandle,
    transport::{self, ReadinessGuard, header_values, load_tls, validate_configuration},
};

/// Running Actix server. Explicit shutdown drains; dropping requests an immediate stop.
pub struct ActixServerHandle {
    inner: actix_web::dev::ServerHandle,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    readiness: Readiness,
    addresses: Vec<SocketAddr>,
    completion: tokio::sync::watch::Receiver<bool>,
}

impl ActixServerHandle {
    /// Bound addresses, including any OS-assigned port.
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

impl ServerHandle for ActixServerHandle {
    fn wait_for_exit(&self) -> impl std::future::Future<Output = ()> + Send {
        let mut completion = self.completion.clone();
        async move {
            let _ = completion.wait_for(|finished| *finished).await;
        }
    }
    fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
    fn is_finished(&self) -> bool {
        self.task
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
    }
}

impl std::fmt::Debug for ActixServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActixServerHandle")
            .field("addresses", &self.addresses)
            .finish_non_exhaustive()
    }
}

impl Drop for ActixServerHandle {
    fn drop(&mut self) {
        self.readiness.set_ready(false);
        if let Some(task) = self.task.take() {
            let stop = self.inner.stop(false);
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    stop.await;
                    task.abort();
                });
            } else {
                task.abort();
            }
        }
    }
}

/// Actix implementation of HttpServer. Framework-specific types stay in this module.
#[derive(Debug)]
pub struct ActixHttpServer;

impl HttpServer for ActixHttpServer {
    type Handle = ActixServerHandle;

    async fn serve(
        config: ServerConfig,
        middleware: MiddlewareConfig,
        routes: Vec<(HttpMethod, String, Handler)>,
    ) -> VsrResult<Self::Handle> {
        validate_configuration(&config, &middleware)?;
        let routes = Arc::new(RouteTable::from_routes(routes)?);
        let tls = config.tls.as_ref().map(load_tls).transpose()?;
        let max_body = config.max_body_bytes;
        let readiness = config.readiness.clone();
        let state = web::Data::new(State {
            routes,
            readiness: readiness.clone(),
        });
        let mut server = actix_web::HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .app_data(web::PayloadConfig::default().limit(max_body))
                .wrap(Condition::new(middleware.compression, Compress::default()))
                .wrap(Condition::new(
                    middleware.cors.is_some(),
                    cors_middleware(&middleware),
                ))
                .wrap(security_headers(&middleware))
                .default_service(web::to(dispatch))
        })
        .disable_signals()
        .shutdown_timeout(
            config
                .shutdown_timeout
                .as_secs()
                .saturating_add(u64::from(config.shutdown_timeout.subsec_nanos() > 0)),
        );
        if let Some(workers) = config.workers {
            server = server.workers(workers);
        }
        let server = match tls {
            Some(tls) => server.bind_rustls_0_23(config.addr, tls),
            None => server.bind(config.addr),
        }
        .map_err(|e| VsrError::Other(format!("failed to bind {}: {e}", config.addr).into()))?;
        let addresses = server.addrs();
        let running = server.run();
        let inner = running.handle();
        let (completed, completion) = tokio::sync::watch::channel(false);
        let guard = ReadinessGuard(readiness.clone(), completed);
        let task = tokio::spawn(async move {
            let _guard = guard;
            running.await
        });
        Ok(ActixServerHandle {
            inner,
            task: Some(task),
            readiness,
            addresses,
            completion,
        })
    }

    async fn shutdown(mut handle: Self::Handle) -> VsrResult<()> {
        handle.readiness.set_ready(false);
        handle.inner.stop(true).await;
        handle
            .task
            .take()
            .expect("running server task")
            .await
            .map_err(|e| VsrError::Other(format!("server task failed: {e}").into()))?
            .map_err(|e| VsrError::Other(format!("server failed: {e}").into()))
    }
}

struct State {
    routes: Arc<RouteTable>,
    readiness: Readiness,
}

async fn dispatch(
    req: HttpRequest,
    body: Result<Bytes, actix_web::Error>,
    state: web::Data<State>,
) -> HttpResponse {
    let body = match body {
        Ok(body) => body,
        Err(error) => {
            return envelope_to_response(ResponseEnvelope::error(
                error.as_response_error().status_code().as_u16(),
                "Invalid request body",
            ));
        }
    };
    let mut headers = HeaderFields::default();
    for (name, value) in req.headers() {
        if headers.append(name.as_str(), value.as_bytes()).is_err() {
            return envelope_to_response(ResponseEnvelope::error(400, "Invalid request headers"));
        }
    }
    let context = transport::request_context(
        req.method().as_str(),
        req.uri().path(),
        req.query_string(),
        headers,
        body,
        req.peer_addr(),
    );
    let response = match context {
        Ok(context) => transport::dispatch(&state.routes, &state.readiness, context).await,
        Err(response) => response,
    };
    envelope_to_response(response)
}

fn envelope_to_response(envelope: ResponseEnvelope) -> HttpResponse {
    let status = actix_web::http::StatusCode::from_u16(envelope.status)
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);
    for (name, value) in envelope.headers.iter() {
        builder.append_header((name, value));
    }
    match envelope.body {
        ResponseBody::Empty => builder.finish(),
        ResponseBody::Bytes(bytes) => builder.body(bytes),
        ResponseBody::Json(value) => {
            if envelope.headers.get("content-type").is_none() {
                builder.content_type("application/json");
            }
            builder.json(value)
        }
    }
}

fn security_headers(config: &MiddlewareConfig) -> DefaultHeaders {
    header_values(config)
        .into_iter()
        .fold(DefaultHeaders::new(), |headers, value| headers.add(value))
}

fn cors_middleware(config: &MiddlewareConfig) -> actix_cors::Cors {
    let Some(config) = &config.cors else {
        return actix_cors::Cors::default();
    };
    let mut cors = actix_cors::Cors::default().block_on_origin_mismatch(true);
    if let Some(origins) = &config.allowed_origins {
        for origin in origins {
            cors = cors.allowed_origin(origin);
        }
    } else {
        cors = cors.allow_any_origin();
    }
    let methods: Vec<_> = config
        .allowed_methods
        .iter()
        .map(ToString::to_string)
        .collect();
    cors = cors
        .allowed_methods(methods.iter().map(String::as_str))
        .allowed_headers(config.allowed_headers.iter().map(String::as_str))
        .max_age(config.max_age_secs as usize);
    if config.allow_credentials {
        cors = cors.supports_credentials();
    }
    cors
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn configured_tls_accepts_https_and_rejects_plain_http() {
        use super::*;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "vsr-adapter-tls-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
        let config = ServerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            workers: Some(1),
            tls: Some(crate::http::TlsConfig {
                cert_path,
                key_path,
            }),
            ..Default::default()
        };
        let server = ActixHttpServer::serve(config, MiddlewareConfig::default(), vec![])
            .await
            .unwrap();
        let port = server.addresses()[0].port();
        let trusted = reqwest::Certificate::from_pem(cert.cert.pem().as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(trusted)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        assert_eq!(
            client
                .get(format!("https://localhost:{port}/healthz"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert!(
            client
                .get(format!("http://127.0.0.1:{port}/healthz"))
                .send()
                .await
                .is_err()
        );
        ActixHttpServer::shutdown(server).await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn middleware_and_readiness_are_enforced_over_http() {
        use super::*;
        let config = ServerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            workers: Some(1),
            max_body_bytes: 64,
            ..Default::default()
        };
        let readiness = config.readiness.clone();
        let middleware = MiddlewareConfig {
            cors: Some(crate::http::CorsConfig {
                allowed_origins: Some(vec!["https://allowed.example".into()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let handler =
            crate::http::make_handler(|_| async { ResponseEnvelope::json("x".repeat(8192)) });
        let server = ActixHttpServer::serve(
            config,
            middleware,
            vec![
                (HttpMethod::Get, "/data".into(), handler.clone()),
                (HttpMethod::Post, "/data".into(), handler),
            ],
        )
        .await
        .unwrap();
        let base = format!("http://{}", server.addresses()[0]);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        assert_eq!(
            client
                .get(format!("{base}/healthz"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            client
                .get(format!("{base}/readyz"))
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        readiness.set_ready(true);
        assert_eq!(
            client
                .get(format!("{base}/readyz"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        let response = client
            .get(format!("{base}/data"))
            .header("origin", "https://allowed.example")
            .header("accept-encoding", "gzip")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-encoding"], "gzip");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(
            response.headers()["content-security-policy"],
            "default-src 'self'"
        );
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "https://allowed.example"
        );
        assert!(response.bytes().await.unwrap().len() < 8192);
        assert_eq!(
            client
                .get(format!("{base}/data"))
                .header("origin", "https://evil.example")
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
        assert_eq!(
            client
                .post(format!("{base}/data"))
                .body(vec![0; 65])
                .send()
                .await
                .unwrap()
                .status(),
            413
        );
        readiness.set_ready(false);
        assert_eq!(
            client
                .get(format!("{base}/readyz"))
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        ActixHttpServer::shutdown(server).await.unwrap();
        assert!(!readiness.is_ready());
    }

    #[tokio::test]
    async fn invalid_or_unsupported_security_configuration_fails_before_bind() {
        use super::*;
        let mut config = ServerConfig::default();
        config.workers = Some(0);
        assert!(
            ActixHttpServer::serve(config, MiddlewareConfig::default(), vec![])
                .await
                .is_err()
        );
        let middleware = MiddlewareConfig {
            trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
            ..Default::default()
        };
        assert!(
            ActixHttpServer::serve(ServerConfig::default(), middleware, vec![])
                .await
                .is_err()
        );
        let config = ServerConfig {
            tls: Some(crate::http::TlsConfig {
                cert_path: "missing-cert.pem".into(),
                key_path: "missing-key.pem".into(),
            }),
            ..Default::default()
        };
        assert!(
            ActixHttpServer::serve(config, MiddlewareConfig::default(), vec![])
                .await
                .is_err()
        );
        let middleware = MiddlewareConfig {
            cors: Some(crate::http::CorsConfig {
                allow_credentials: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            ActixHttpServer::serve(ServerConfig::default(), middleware, vec![])
                .await
                .is_err()
        );
    }

    use super::*;
    use crate::http::{MiddlewareConfig, ResponseEnvelope, ServerConfig, make_handler};

    // ── Unit: query string parsing ────────────────────────────────────────────

    #[test]
    fn query_empty_string_gives_empty_map() {
        assert!(parse_query_string("").is_empty());
    }

    #[test]
    fn query_single_pair() {
        let m = parse_query_string("foo=bar");
        assert_eq!(m.get("foo"), Some(&vec!["bar".to_owned()]));
    }

    #[test]
    fn query_repeated_key_collects_values() {
        let m = parse_query_string("x=1&x=2&y=3");
        assert_eq!(m.get("x"), Some(&vec!["1".to_owned(), "2".to_owned()]));
        assert_eq!(m.get("y"), Some(&vec!["3".to_owned()]));
    }

    #[test]
    fn query_key_without_equals_gets_empty_value() {
        let m = parse_query_string("flag");
        assert_eq!(m.get("flag"), Some(&vec![String::new()]));
    }

    // ── Unit: response conversion ─────────────────────────────────────────────

    #[test]
    fn envelope_200_json_converts_to_200() {
        let env = ResponseEnvelope::json(serde_json::json!({"status": "ok"}));
        let resp = envelope_to_response(env);
        assert_eq!(resp.status().as_u16(), 200);
    }

    #[test]
    fn envelope_204_empty_converts_to_204() {
        let env = ResponseEnvelope::status(204);
        let resp = envelope_to_response(env);
        assert_eq!(resp.status().as_u16(), 204);
    }

    #[test]
    fn envelope_404_error_converts_to_404() {
        let env = ResponseEnvelope::error(404, "not found");
        let resp = envelope_to_response(env);
        assert_eq!(resp.status().as_u16(), 404);
    }

    #[test]
    fn envelope_out_of_range_status_falls_back_to_500() {
        // The http crate accepts 100-999; anything outside that range is invalid
        // and our converter should fall back to 500.
        let env = ResponseEnvelope {
            status: 50, // below the valid 100-999 range
            headers: HeaderFields::default(),
            body: super::ResponseBody::Empty,
        };
        let resp = envelope_to_response(env);
        assert_eq!(resp.status().as_u16(), 500);
    }

    // ── Unit: request ID generation ───────────────────────────────────────────

    #[test]
    fn new_request_ids_are_unique() {
        let a = new_request_id();
        let b = new_request_id();
        assert_ne!(a, b, "consecutive request IDs must be distinct");
        assert!(a.starts_with("req-"), "request ID should start with req-");
    }

    // ── Integration: server lifecycle ─────────────────────────────────────────

    /// Start the server on an OS-assigned port, then stop it.
    ///
    /// This verifies the bind → spawn → graceful-shutdown lifecycle without
    /// making any HTTP connections (no HTTP client dep needed).
    #[tokio::test]
    async fn server_starts_and_shuts_down() {
        let config = ServerConfig {
            // Port 0 → OS picks a free ephemeral port; avoids conflicts in CI.
            addr: "127.0.0.1:0".parse().unwrap(),
            workers: Some(1),
            ..Default::default()
        };

        let handler = make_handler(|_ctx| async {
            ResponseEnvelope::json(serde_json::json!({"hello": "world"}))
        });

        let handle = ActixHttpServer::serve(
            config,
            MiddlewareConfig::default(),
            vec![(HttpMethod::Get, "/greet".to_string(), handler)],
        )
        .await
        .expect("server should bind and start");

        ActixHttpServer::shutdown(handle)
            .await
            .expect("graceful shutdown should succeed");
    }

    /// Verify that serving with an empty route list (only health probes) works.
    #[tokio::test]
    async fn server_with_no_routes_starts_and_stops() {
        let config = ServerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            workers: Some(1),
            ..Default::default()
        };

        let handle = ActixHttpServer::serve(config, MiddlewareConfig::default(), vec![])
            .await
            .expect("empty route list should still bind");

        ActixHttpServer::shutdown(handle)
            .await
            .expect("shutdown should succeed");
    }
}
