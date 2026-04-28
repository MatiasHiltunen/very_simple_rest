//! Actix-web 4 implementation of [`HttpServer`].
//!
//! Each route in the registry is wrapped in an actix handler closure. The
//! framework-agnostic [`RequestContext`] is assembled from the actix
//! [`actix_web::HttpRequest`] and body bytes before the application handler
//! runs. The returned [`ResponseEnvelope`] is converted back to an
//! [`actix_web::HttpResponse`].
//!
//! Health probes `/healthz` (liveness) and `/readyz` (readiness) are mounted
//! automatically regardless of the route registry contents.
//!
//! # Example
//!
//! ```rust,no_run
//! use vsr_runtime::http::{
//!     ActixHttpServer, HttpMethod, HttpServer, MiddlewareConfig, ResponseEnvelope,
//!     ServerConfig, make_handler,
//! };
//!
//! # async fn example() -> vsr_core::error::VsrResult<()> {
//! let routes = vec![(
//!     HttpMethod::Get,
//!     "/hello".to_string(),
//!     make_handler(|_ctx| async { ResponseEnvelope::json("hello") }),
//! )];
//!
//! let handle = ActixHttpServer::serve(
//!     ServerConfig::default(),
//!     MiddlewareConfig::default(),
//!     routes,
//! )
//! .await?;
//!
//! ActixHttpServer::shutdown(handle).await?;
//! # Ok(())
//! # }
//! ```

use std::{collections::HashMap, sync::Arc};

use actix_web::{App, HttpRequest, HttpResponse, web};
use actix_web::HttpServer as ActixWebServer;
use bytes::Bytes;
use vsr_core::error::{VsrError, VsrResult};

use super::{
    Handler, HttpMethod, HttpServer, MiddlewareConfig, RequestContext, ResponseBody,
    ResponseEnvelope, ServerConfig,
};

// ── Handle ────────────────────────────────────────────────────────────────────

/// Opaque handle to a running [`ActixHttpServer`].
///
/// Pass to [`ActixHttpServer::shutdown`] to trigger graceful drain.
pub struct ActixServerHandle {
    inner: actix_web::dev::ServerHandle,
}

impl std::fmt::Debug for ActixServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActixServerHandle").finish_non_exhaustive()
    }
}

// ── Server ────────────────────────────────────────────────────────────────────

/// Actix-web 4 implementation of the [`HttpServer`] trait.
///
/// Wraps each registered [`Handler`] in an actix closure, builds an
/// `actix_web::HttpServer`, binds it, and spawns it onto the current tokio
/// runtime via [`tokio::spawn`]. Health endpoints are added automatically.
#[derive(Debug)]
pub struct ActixHttpServer;

impl HttpServer for ActixHttpServer {
    type Handle = ActixServerHandle;

    async fn serve(
        config: ServerConfig,
        _middleware: MiddlewareConfig,
        routes: Vec<(HttpMethod, String, Handler)>,
    ) -> VsrResult<ActixServerHandle> {
        // Wrap in Arc so the factory closure (called once per worker) can clone
        // a cheap pointer each time without re-allocating the route list.
        let routes: Arc<Vec<(HttpMethod, String, Handler)>> = Arc::new(routes);
        let max_body = config.max_body_bytes;

        let server = ActixWebServer::new(move || {
            // Clone the Arc for this factory invocation.
            let routes = Arc::clone(&routes);

            App::new()
                .app_data(web::JsonConfig::default().limit(max_body))
                .app_data(web::PayloadConfig::default().limit(max_body))
                .route("/healthz", web::get().to(healthz))
                .route("/readyz", web::get().to(readyz))
                .configure(move |cfg| {
                    for (method, path, handler) in routes.iter() {
                        // Clone the Arc once per route so the closure is `Fn`
                        // (not `FnOnce`) and can be invoked on every request.
                        let handler = Arc::clone(handler);
                        let route = method_to_actix_route(method);
                        cfg.route(
                            path.as_str(),
                            route.to(move |req: HttpRequest, body: Bytes| {
                                // Clone again so the closure remains `Fn`.
                                let handler = Arc::clone(&handler);
                                async move {
                                    let ctx = build_request_context(req, body);
                                    let response = handler(ctx).await;
                                    envelope_to_response(response)
                                }
                            }),
                        );
                    }
                })
        });

        let server = match config.workers {
            Some(w) => server.workers(w),
            None => server,
        };

        let running = server
            .bind(config.addr)
            .map_err(|e| VsrError::Other(
                format!("failed to bind {}: {e}", config.addr).into(),
            ))?
            .run();

        let handle = running.handle();
        tokio::spawn(running);

        Ok(ActixServerHandle { inner: handle })
    }

    async fn shutdown(handle: ActixServerHandle) -> VsrResult<()> {
        handle.inner.stop(true).await;
        Ok(())
    }
}

// ── Health probes ─────────────────────────────────────────────────────────────

async fn healthz() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain")
        .body("ok")
}

async fn readyz() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain")
        .body("ok")
}

// ── Request conversion ────────────────────────────────────────────────────────

fn build_request_context(req: HttpRequest, body: Bytes) -> RequestContext {
    let method = actix_method_to_vsr(req.method());
    let path = req.path().to_owned();

    let path_params: HashMap<String, String> = req
        .match_info()
        .iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

    let query_params = parse_query_string(req.query_string());

    let headers: HashMap<String, Vec<String>> =
        req.headers()
            .iter()
            .filter_map(|(name, value)| {
                let key = name.as_str().to_lowercase();
                let val = value.to_str().ok()?.to_owned();
                Some((key, val))
            })
            .fold(HashMap::new(), |mut map, (k, v)| {
                map.entry(k).or_default().push(v);
                map
            });

    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
        .unwrap_or_else(new_request_id);

    RequestContext {
        method,
        path,
        path_params,
        query_params,
        headers,
        body: if body.is_empty() { None } else { Some(body) },
        identity: None,
        request_id,
    }
}

// ── Response conversion ───────────────────────────────────────────────────────

fn envelope_to_response(envelope: ResponseEnvelope) -> HttpResponse {
    let status = actix_web::http::StatusCode::from_u16(envelope.status)
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);

    let mut builder = HttpResponse::build(status);

    for (name, value) in &envelope.headers {
        builder.insert_header((name.as_str(), value.as_str()));
    }

    match envelope.body {
        ResponseBody::Empty => builder.finish(),
        ResponseBody::Bytes(bytes) => builder.body(bytes),
        ResponseBody::Json(value) => {
            let bytes = serde_json::to_vec(&value).unwrap_or_default();
            builder.body(bytes)
        }
    }
}

// ── Method helpers ────────────────────────────────────────────────────────────

fn method_to_actix_route(method: &HttpMethod) -> actix_web::Route {
    match method {
        HttpMethod::Get => web::get(),
        HttpMethod::Post => web::post(),
        HttpMethod::Put => web::put(),
        HttpMethod::Patch => web::patch(),
        HttpMethod::Delete => web::delete(),
        HttpMethod::Head => web::head(),
        HttpMethod::Options => web::method(actix_web::http::Method::OPTIONS),
    }
}

fn actix_method_to_vsr(method: &actix_web::http::Method) -> HttpMethod {
    match method.as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        _ => HttpMethod::Get,
    }
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

/// Parse a raw query string into a key → values map.
///
/// Multiple values for the same key are collected in order.
/// `+` and `%XX` sequences are **not** decoded here — add a proper
/// `form_urlencoded` pass if that is needed in production.
fn parse_query_string(qs: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    if qs.is_empty() {
        return map;
    }
    for pair in qs.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k.to_owned(), v.to_owned()),
            None => (pair.to_owned(), String::new()),
        };
        if !key.is_empty() {
            map.entry(key).or_default().push(value);
        }
    }
    map
}

/// Generate a monotone request ID without pulling in a uuid dependency.
fn new_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    format!("req-{n:016x}")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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
            headers: std::collections::HashMap::new(),
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

        let handle = ActixHttpServer::serve(
            config,
            MiddlewareConfig::default(),
            vec![],
        )
        .await
        .expect("empty route list should still bind");

        ActixHttpServer::shutdown(handle)
            .await
            .expect("shutdown should succeed");
    }
}
