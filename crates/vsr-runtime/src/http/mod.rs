//! HTTP server abstraction layer.
//!
//! # Implementations
//!
//! | Feature | Type | Notes |
//! |---|---|---|
//! | `http-actix` | `ActixHttpServer` | Opt-in library transport; actix-web 4 |
//! | `http-axum` | `AxumHttpServer` | Opt-in; same VSR route/handler contract |
//!
//! # Three shared contracts
//!
//! - [`RouteRegistry`] receives framework-agnostic [`Handler`] registrations.
//!   Both adapters dispatch through the same validated [`RouteTable`]. Legacy
//!   generated routes are not yet consumers of this contract.
//! - [`HttpServer`] — owns binding, listener lifecycle, graceful shutdown,
//!   TLS, and readiness. One implementation per HTTP framework.
//! - [`MiddlewareConfig`] supplies configuration for framework-agnostic
//!   middleware logic (CORS, security headers and compression).
//!   Framework adapters apply it via their native layer/middleware model.
//!   Trusted proxies are rejected until verified forwarding is implemented.
//!
//! **No framework types cross this boundary.** No `actix_web::HttpRequest`,
//! no `axum::Router`, no `tower::Layer` appears in the public API here.
//! Those types are contained in adapter modules behind feature flags.

// ── Concrete implementations ──────────────────────────────────────────────────

#[cfg(feature = "http-actix")]
pub mod actix_adapter;

#[cfg(feature = "http-actix")]
pub use actix_adapter::ActixHttpServer;

#[cfg(feature = "http-axum")]
pub mod axum_adapter;
#[cfg(feature = "http-axum")]
pub use axum_adapter::AxumHttpServer;

mod headers;
mod routes;
#[cfg(any(feature = "http-actix", feature = "http-axum"))]
mod transport;

pub use crate::auth::AuthenticatedIdentity;
pub use headers::HeaderFields;
pub use routes::RouteTable;

// ─────────────────────────────────────────────────────────────────────────────

use std::{collections::HashMap, future::Future, net::SocketAddr, pin::Pin, sync::Arc};

use bytes::Bytes;
use vsr_core::error::VsrResult;

// ─── Domain types ────────────────────────────────────────────────────────────

/// HTTP method, expressed without binding to any framework enum.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HttpMethod {
    /// HTTP GET
    Get,
    /// HTTP POST
    Post,
    /// HTTP PUT
    Put,
    /// HTTP PATCH
    Patch,
    /// HTTP DELETE
    Delete,
    /// HTTP HEAD
    Head,
    /// HTTP OPTIONS
    Options,
    /// An extension method, preserved rather than being treated as GET.
    Other(String),
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Other(method) => method.as_str(),
        };
        f.write_str(s)
    }
}

/// Framework-agnostic representation of an incoming HTTP request.
///
/// Populated by the framework adapter before calling the handler; the handler
/// never imports an actix or axum type.
#[derive(Debug)]
pub struct RequestContext {
    /// HTTP method.
    pub method: HttpMethod,
    /// Raw, percent-encoded request path without query. Never decode a whole
    /// path before routing; only matched parameter values are decoded once.
    pub path: String,
    /// Original query string, without the leading question mark.
    pub raw_query: String,
    /// Matched VSR route template, for bounded-cardinality telemetry.
    pub matched_route: Option<String>,
    /// Direct network peer. Forwarding headers never replace this value.
    pub peer_addr: Option<SocketAddr>,
    /// Path parameters extracted by the router (e.g. `{id}` → `"42"`).
    pub path_params: HashMap<String, String>,
    /// Query parameters. Multiple values per key are preserved.
    pub query_params: HashMap<String, Vec<String>>,
    /// Validated, case-insensitive headers, preserving repeats and raw bytes.
    pub headers: HeaderFields,
    /// Buffered body after supported content decompression, if nonempty.
    pub body: Option<Bytes>,
    /// Authenticated identity, if auth middleware ran and succeeded.
    pub identity: Option<AuthenticatedIdentity>,
    /// Server-issued request ID, independent of caller-provided headers.
    pub request_id: String,
}

/// Framework-agnostic HTTP response.
///
/// The framework adapter converts this into an `actix_web::HttpResponse`
/// or `axum::Response` before returning to the client.
#[derive(Debug)]
pub struct ResponseEnvelope {
    /// HTTP status code.
    pub status: u16,
    /// Validated response fields. Repeated fields such as Set-Cookie are appended.
    pub headers: HeaderFields,
    /// Response body.
    pub body: ResponseBody,
}

impl ResponseEnvelope {
    /// JSON response, or a stable 500 response if serialization fails.
    pub fn json(body: impl serde::Serialize) -> Self {
        Self::try_json(body).unwrap_or_else(|_| Self::error(500, "JSON serialization failed"))
    }

    /// Serialize a JSON 200 response without discarding serialization errors.
    pub fn try_json(body: impl serde::Serialize) -> Result<Self, serde_json::Error> {
        let bytes = serde_json::to_vec(&body)?;
        let mut headers = HeaderFields::default();
        headers
            .append("content-type", b"application/json")
            .expect("static header");
        Ok(Self {
            status: 200,
            headers,
            body: ResponseBody::Bytes(Bytes::from(bytes)),
        })
    }

    /// Convenience constructor for a status-only response with no body.
    pub fn status(code: u16) -> Self {
        Self {
            status: code,
            headers: HeaderFields::default(),
            body: ResponseBody::Empty,
        }
    }

    /// Convenience constructor for a JSON error response.
    pub fn error(status: u16, message: &str) -> Self {
        let body = serde_json::json!({"error": message});
        let mut response = Self::try_json(body).expect("JSON string values serialize");
        response.status = status;
        response
    }
}

/// The body of a [`ResponseEnvelope`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ResponseBody {
    /// No body (e.g. 204 No Content).
    Empty,
    /// Fully-buffered body bytes.
    Bytes(Bytes),
    /// A pre-serialized JSON value (adapter may skip re-serialization).
    Json(serde_json::Value),
}

// ─── Handler type ────────────────────────────────────────────────────────────

/// A framework-agnostic handler function.
///
/// Takes a [`RequestContext`] and returns a [`ResponseEnvelope`].
/// Both adapters use this type. Legacy generated and built-in handlers are
/// still being migrated; this alias does not imply that migration is complete.
pub type Handler = Arc<
    dyn Fn(RequestContext) -> Pin<Box<dyn Future<Output = ResponseEnvelope> + Send>> + Send + Sync,
>;

/// Convenience macro-free constructor for [`Handler`].
pub fn make_handler<F, Fut>(f: F) -> Handler
where
    F: Fn(RequestContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ResponseEnvelope> + Send + 'static,
{
    Arc::new(move |ctx| Box::pin(f(ctx)))
}

// ─── RouteRegistry trait ─────────────────────────────────────────────────────

/// Receives framework-agnostic route + handler pairs.
///
/// The shared RouteTable implements this contract and validates routes before
/// either framework binds. Legacy code generation is not yet a consumer.
pub trait RouteRegistry: Send + 'static {
    /// Register a handler for `method` at `path`.
    ///
    /// `path` uses the VSR path template syntax: `{param}` for required path
    /// parameters and `{*tail}` for a nonempty terminal catch-all. Regex and
    /// partial-segment captures are not part of the portable VSR grammar.
    fn add_route(&mut self, method: HttpMethod, path: &str, handler: Handler) -> VsrResult<()>;
}

// ─── HttpServer trait ─────────────────────────────────────────────────────────

/// Configuration passed to [`HttpServer::serve`].
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Shared dependency readiness. Starts false; the application marks it ready
    /// only after checking required resources, and clears it when they fail.
    pub readiness: Readiness,
    /// Listening address.
    pub addr: SocketAddr,
    /// Optional TLS configuration (PEM certificate and key file paths).
    pub tls: Option<TlsConfig>,
    /// Actix worker threads. Axum uses the caller's Tokio runtime and rejects
    /// an explicit worker count rather than silently ignoring it.
    pub workers: Option<usize>,
    /// Maximum graceful drain duration, rounded up to whole seconds on Actix.
    pub shutdown_timeout: std::time::Duration,
    /// Maximum body size in bytes accepted by the framework before the handler
    /// sees the request. Default: 4 MiB.
    pub max_body_bytes: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            readiness: Readiness::default(),
            addr: "0.0.0.0:8080".parse().unwrap(),
            tls: None,
            workers: None,
            shutdown_timeout: std::time::Duration::from_secs(30),
            max_body_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Application-controlled dependency readiness, shared with the server probes.
#[derive(Debug, Clone, Default)]
pub struct Readiness(Arc<std::sync::atomic::AtomicBool>);

impl Readiness {
    /// Change readiness after checking required application dependencies.
    pub fn set_ready(&self, ready: bool) {
        self.0.store(ready, std::sync::atomic::Ordering::Release);
    }
    /// Whether the application currently reports that dependencies are ready.
    pub fn is_ready(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// TLS configuration for an [`HttpServer`].
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to the PEM-encoded certificate chain.
    pub cert_path: std::path::PathBuf,
    /// Path to the PEM-encoded private key.
    pub key_path: std::path::PathBuf,
}

/// Builds and runs an HTTP server from a config and a populated registry.
///
/// Implementors:
/// - `ActixHttpServer` — behind the opt-in `http-actix` feature.
/// - `AxumHttpServer` — behind the opt-in `http-axum` feature.
/// Neither backend is enabled by default in this crate.
///
/// # Contract
///
/// - `serve` returns a running server handle after binding the listener.
/// - The implementation MUST serve `/healthz` (liveness) and `/readyz`
///   (readiness) regardless of what the registry contains.
/// - Graceful shutdown drains in-flight requests before returning.
pub trait HttpServer: Send + Sync + 'static {
    /// An opaque handle that can be used to trigger a graceful shutdown.
    type Handle: ServerHandle;

    /// Bind and start serving, returning a handle for graceful shutdown.
    ///
    /// `routes` supplies all application routes; the implementation adds
    /// its own health endpoints on top.
    fn serve(
        config: ServerConfig,
        middleware: MiddlewareConfig,
        routes: Vec<(HttpMethod, String, Handler)>,
    ) -> impl Future<Output = VsrResult<Self::Handle>> + Send;

    /// Signal the server to stop accepting new requests and drain gracefully.
    fn shutdown(handle: Self::Handle) -> impl Future<Output = VsrResult<()>> + Send;
}

/// Observable lifecycle shared by transport-specific running server handles.
/// Dropping a handle requests immediate shutdown; use HttpServer::shutdown to drain.
pub trait ServerHandle: Send + 'static {
    /// Bound addresses, including OS-assigned ports.
    fn addresses(&self) -> &[SocketAddr];
    /// Whether the server task has exited (success or failure).
    fn is_finished(&self) -> bool;
    /// Observe completion without consuming the handle, including task failure
    /// or cancellation. Call shutdown afterwards to collect the task result.
    fn wait_for_exit(&self) -> impl Future<Output = ()> + Send;
}

// ─── Middleware configuration ─────────────────────────────────────────────────

/// Framework-agnostic middleware configuration.
///
/// Framework adapters apply this using their own middleware model.
#[derive(Debug, Clone)]
pub struct MiddlewareConfig {
    /// Enable Brotli + gzip response compression.
    pub compression: bool,
    /// CORS configuration. `None` disables CORS middleware.
    pub cors: Option<CorsConfig>,
    /// Security header policy.
    pub security_headers: SecurityHeadersConfig,
    /// Reserved for verified reverse-proxy forwarding. Both adapters currently
    /// reject nonempty values instead of trusting raw forwarding headers.
    pub trusted_proxies: Vec<std::net::IpAddr>,
}

impl Default for MiddlewareConfig {
    fn default() -> Self {
        Self {
            compression: true,
            cors: None,
            security_headers: SecurityHeadersConfig::default(),
            trusted_proxies: vec![],
        }
    }
}

/// CORS policy for the middleware layer.
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins. `None` reflects any request origin and is rejected
    /// when credentialed CORS is enabled.
    pub allowed_origins: Option<Vec<String>>,
    /// Allowed HTTP methods.
    pub allowed_methods: Vec<HttpMethod>,
    /// Allowed request headers.
    pub allowed_headers: Vec<String>,
    /// Whether to allow credentialed (cookie) cross-origin requests.
    pub allow_credentials: bool,
    /// `Access-Control-Max-Age` in seconds.
    pub max_age_secs: u32,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: None,
            allowed_methods: vec![
                HttpMethod::Get,
                HttpMethod::Post,
                HttpMethod::Put,
                HttpMethod::Patch,
                HttpMethod::Delete,
                HttpMethod::Options,
            ],
            allowed_headers: vec![
                "authorization".into(),
                "content-type".into(),
                "x-request-id".into(),
            ],
            allow_credentials: false,
            max_age_secs: 3600,
        }
    }
}

/// Security response-header policy.
///
/// All fields default to safe values. Operators can relax or tighten them
/// in the `.eon` `runtime.security` block.
#[derive(Debug, Clone)]
pub struct SecurityHeadersConfig {
    /// `Strict-Transport-Security` max-age. `None` disables the header.
    pub hsts_max_age_secs: Option<u64>,
    /// `Content-Security-Policy` directive string. Empty string disables.
    pub csp: String,
    /// `X-Frame-Options` value (`DENY`, `SAMEORIGIN`, or empty to disable).
    pub x_frame_options: String,
    /// `Permissions-Policy` directive string.
    pub permissions_policy: String,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            hsts_max_age_secs: Some(63_072_000), // 2 years
            csp: "default-src 'self'".into(),
            x_frame_options: "DENY".into(),
            permissions_policy: "geolocation=(), microphone=(), camera=()".into(),
        }
    }
}
