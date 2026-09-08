//! Axum transport for the same VSR routes, handlers and security policy as Actix.
//! TLS and connection draining use axum-server; no server protocol is hand-rolled.

use std::{error::Error as _, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::Response,
};
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowOrigin, CorsLayer},
    decompression::RequestDecompressionLayer,
};
use vsr_core::error::{VsrError, VsrResult};

use super::{
    Handler, HeaderFields, HttpMethod, HttpServer, MiddlewareConfig, Readiness, ResponseBody,
    ResponseEnvelope, RouteTable, ServerConfig, ServerHandle,
    transport::{self, ReadinessGuard, header_values, load_tls, validate_configuration},
};

/// Running Axum transport. Explicit shutdown drains; dropping stops immediately.
pub struct AxumServerHandle {
    inner: axum_server::Handle<SocketAddr>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    addresses: Vec<SocketAddr>,
    readiness: Readiness,
    shutdown_timeout: Duration,
    completion: tokio::sync::watch::Receiver<bool>,
}

impl AxumServerHandle {
    /// Bound addresses, including any OS-assigned port.
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

impl ServerHandle for AxumServerHandle {
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

impl std::fmt::Debug for AxumServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AxumServerHandle")
            .field("addresses", &self.addresses)
            .finish_non_exhaustive()
    }
}

impl Drop for AxumServerHandle {
    fn drop(&mut self) {
        self.readiness.set_ready(false);
        self.inner.shutdown();
        // Let axum-server notify and drain its spawned connection tasks before
        // the server task exits; aborting it here would skip that cleanup.
    }
}

/// Opt-in Axum HTTP/HTTPS implementation, running on the caller's Tokio runtime.
#[derive(Debug)]
pub struct AxumHttpServer;

impl HttpServer for AxumHttpServer {
    type Handle = AxumServerHandle;

    async fn serve(
        config: ServerConfig,
        middleware: MiddlewareConfig,
        routes: Vec<(HttpMethod, String, Handler)>,
    ) -> VsrResult<Self::Handle> {
        validate_configuration(&config, &middleware)?;
        if config.workers.is_some() {
            return Err(VsrError::Other(
                "Axum uses the caller's Tokio runtime; workers is Actix-only".into(),
            ));
        }
        let routes = Arc::new(RouteTable::from_routes(routes)?);
        let tls = config.tls.as_ref().map(load_tls).transpose()?;
        let readiness = config.readiness.clone();
        let state = AppState {
            routes,
            readiness: readiness.clone(),
            max_body_bytes: config.max_body_bytes,
        };
        let mut app = Router::new()
            .fallback(dispatch)
            .with_state(state)
            .layer(RequestDecompressionLayer::new());
        if middleware.compression {
            app = app.layer(CompressionLayer::new());
        }
        if middleware.cors.is_some() {
            app = app.layer(cors_layer(&middleware)?);
        }
        app = app.layer(middleware::from_fn_with_state(
            Arc::new(middleware),
            apply_policy,
        ));

        let listener = std::net::TcpListener::bind(config.addr).map_err(VsrError::Io)?;
        listener.set_nonblocking(true).map_err(VsrError::Io)?;
        let address = listener.local_addr().map_err(VsrError::Io)?;
        let inner = axum_server::Handle::new();
        let (completed, completion) = tokio::sync::watch::channel(false);
        let guard = ReadinessGuard(readiness.clone(), completed);
        let task = match tls {
            Some(tls) => {
                let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls));
                let server = axum_server::from_tcp_rustls(listener, tls)
                    .map_err(VsrError::Io)?
                    .handle(inner.clone());
                tokio::spawn(async move {
                    let _guard = guard;
                    server
                        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                        .await
                })
            }
            None => {
                let server = axum_server::from_tcp(listener)
                    .map_err(VsrError::Io)?
                    .handle(inner.clone());
                tokio::spawn(async move {
                    let _guard = guard;
                    server
                        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                        .await
                })
            }
        };
        // Own the stop signal before awaiting startup so cancellation cannot
        // detach a bound server from its caller.
        let mut handle = AxumServerHandle {
            inner,
            task: Some(task),
            addresses: vec![address],
            readiness,
            shutdown_timeout: config.shutdown_timeout,
            completion,
        };
        let listening = tokio::select! {
            bound = handle.inner.listening() => bound.is_some(),
            _ = handle.task.as_mut().expect("running server task") => false,
        };
        if !listening {
            return Err(VsrError::Other("Axum server exited during startup".into()));
        }
        Ok(handle)
    }

    async fn shutdown(mut handle: Self::Handle) -> VsrResult<()> {
        handle.readiness.set_ready(false);
        handle
            .inner
            .graceful_shutdown(Some(handle.shutdown_timeout));
        handle
            .task
            .take()
            .expect("running server task")
            .await
            .map_err(|e| VsrError::Other(format!("server task failed: {e}").into()))?
            .map_err(VsrError::Io)
    }
}

#[derive(Clone)]
struct AppState {
    routes: Arc<RouteTable>,
    readiness: Readiness,
    max_body_bytes: usize,
}

#[derive(Clone)]
struct OriginalHeaders(HeaderFields);

async fn dispatch(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let headers = parts
        .extensions
        .remove::<OriginalHeaders>()
        .expect("transport header snapshot")
        .0;
    let body = match to_bytes(body, state.max_body_bytes).await {
        Ok(body) => body,
        Err(error) => {
            let too_large = error
                .source()
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>());
            return envelope_to_response(ResponseEnvelope::error(
                if too_large { 413 } else { 400 },
                "Invalid request body",
            ));
        }
    };
    let context = transport::request_context(
        parts.method.as_str(),
        parts.uri.path(),
        parts.uri.query().unwrap_or_default(),
        headers,
        body,
        peer,
    );
    let response = match context {
        Ok(context) => transport::dispatch(&state.routes, &state.readiness, context).await,
        Err(response) => response,
    };
    envelope_to_response(response)
}

fn envelope_to_response(envelope: ResponseEnvelope) -> Response {
    let is_json = matches!(envelope.body, ResponseBody::Json(_));
    let body = match envelope.body {
        ResponseBody::Empty => Body::empty(),
        ResponseBody::Bytes(bytes) => Body::from(bytes),
        ResponseBody::Json(ref value) => {
            Body::from(serde_json::to_vec(value).expect("JSON values serialize"))
        }
    };
    let mut response = Response::new(body);
    *response.status_mut() =
        StatusCode::from_u16(envelope.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    for (name, value) in envelope.headers.iter() {
        response.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("validated name"),
            HeaderValue::from_bytes(value).expect("validated value"),
        );
    }
    if is_json && !response.headers().contains_key("content-type") {
        response
            .headers_mut()
            .insert("content-type", HeaderValue::from_static("application/json"));
    }
    response
}

fn cors_layer(config: &MiddlewareConfig) -> VsrResult<CorsLayer> {
    let cors = config.cors.as_ref().expect("configured CORS");
    let methods: Vec<Method> = cors
        .allowed_methods
        .iter()
        .map(|m| m.to_string().parse().expect("validated method"))
        .collect();
    let headers: Vec<HeaderName> = cors
        .allowed_headers
        .iter()
        .map(|h| h.parse().expect("validated header"))
        .collect();
    let origins = match &cors.allowed_origins {
        Some(origins) => AllowOrigin::list(
            origins
                .iter()
                .map(|s| s.parse::<HeaderValue>().expect("validated origin")),
        ),
        None => AllowOrigin::mirror_request(),
    };
    Ok(CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(methods)
        .allow_headers(headers)
        .allow_credentials(cors.allow_credentials)
        .max_age(Duration::from_secs(u64::from(cors.max_age_secs))))
}

async fn apply_policy(
    State(config): State<Arc<MiddlewareConfig>>,
    mut req: Request,
    next: Next,
) -> Response {
    // Tower CORS adds browser policy headers but intentionally does not reject
    // forbidden origins. Match the existing Actix rejection policy explicitly.
    let permitted = cors_request_permitted(&config, &req);
    let mut original = HeaderFields::default();
    for (name, value) in req.headers() {
        if original.append(name.as_str(), value.as_bytes()).is_err() {
            return envelope_to_response(ResponseEnvelope::error(400, "Invalid request headers"));
        }
    }
    // Decompression transforms the body; preserve original encoding/length
    // fields for the application, as the Actix extractor does.
    req.extensions_mut().insert(OriginalHeaders(original));
    let mut response = if permitted {
        next.run(req).await
    } else {
        envelope_to_response(ResponseEnvelope::error(400, "CORS request denied"))
    };
    for (name, value) in header_values(&config) {
        if !response.headers().contains_key(name) {
            response.headers_mut().insert(
                HeaderName::from_static(name),
                value.parse().expect("validated security header"),
            );
        }
    }
    response
}

fn cors_request_permitted(config: &MiddlewareConfig, req: &Request) -> bool {
    let Some(cors) = &config.cors else {
        return true;
    };
    let origins: Vec<_> = req.headers().get_all("origin").iter().collect();
    if origins.is_empty() {
        return true;
    }
    if origins.len() != 1 {
        return false;
    }
    let Ok(origin) = origins[0].to_str() else {
        return false;
    };
    if cors
        .allowed_origins
        .as_ref()
        .is_some_and(|origins| !origins.iter().any(|s| s == origin))
    {
        return false;
    }
    if req.method() == Method::OPTIONS {
        if let Some(method) = req.headers().get("access-control-request-method") {
            let Ok(method) = method.to_str() else {
                return false;
            };
            if !cors.allowed_methods.iter().any(|m| m.to_string() == method) {
                return false;
            }
            for field in req.headers().get_all("access-control-request-headers") {
                let Ok(field) = field.to_str() else {
                    return false;
                };
                if !field.split(',').all(|name| {
                    cors.allowed_headers
                        .iter()
                        .any(|h| h.eq_ignore_ascii_case(name.trim()))
                }) {
                    return false;
                }
            }
        }
    }
    true
}
