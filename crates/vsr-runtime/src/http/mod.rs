//! HTTP server abstraction layer.
//!
//! # Implementations
//!
//! | Feature | Type | Notes |
//! |---|---|---|
//! | `http-actix` | [`actix_adapter::ActixHttpServer`] | Default; actix-web 4 |
//! | `http-axum` | *(future)* | Decision: end of Phase 3 |
//!
//! # The seam is split into three distinct contracts:
//!
//! - [`RouteRegistry`] — receives generated resource routes and their
//!   framework-agnostic [`Handler`]s. Framework adapters translate these into
//!   actix `Resource`s or axum `Router` entries.
//! - [`HttpServer`] — owns binding, listener lifecycle, graceful shutdown,
//!   TLS, and readiness. One implementation per HTTP framework.
//! - [`MiddlewareAdapter`] — supplies configuration for framework-agnostic
//!   middleware logic (CORS, security headers, compression, trusted proxies).
//!   Framework adapters apply it via their native layer/middleware model.
//!
//! **No framework types cross this boundary.** No `actix_web::HttpRequest`,
//! no `axum::Router`, no `tower::Layer` appears in the public API here.
//! Those types are contained in adapter modules behind feature flags.

// ── Concrete implementations ──────────────────────────────────────────────────

#[cfg(feature = "http-actix")]
pub mod actix_adapter;

#[cfg(feature = "http-actix")]
pub use actix_adapter::ActixHttpServer;

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
        };
        f.write_str(s)
    }
}

/// The authenticated identity attached to a request, if any.
///
/// Populated by the auth layer before the handler runs. `None` means
/// the request passed through without authentication (allowed on public routes).
#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity {
    /// Stable user ID (from the auth table or external provider).
    pub user_id: String,
    /// Roles attached to this identity at token-issue time.
    pub roles: Vec<String>,
    /// Additional JWT claims as raw JSON values.
    pub claims: HashMap<String, serde_json::Value>,
    /// Whether this identity carries admin privileges.
    pub is_admin: bool,
}

/// Framework-agnostic representation of an incoming HTTP request.
///
/// Populated by the framework adapter before calling the handler; the handler
/// never imports an actix or axum type.
#[derive(Debug)]
pub struct RequestContext {
    /// HTTP method.
    pub method: HttpMethod,
    /// Decoded request path (no query string).
    pub path: String,
    /// Path parameters extracted by the router (e.g. `{id}` → `"42"`).
    pub path_params: HashMap<String, String>,
    /// Query parameters. Multiple values per key are preserved.
    pub query_params: HashMap<String, Vec<String>>,
    /// Request headers, lower-cased names.
    pub headers: HashMap<String, Vec<String>>,
    /// Raw request body, if any.
    pub body: Option<Bytes>,
    /// Authenticated identity, if auth middleware ran and succeeded.
    pub identity: Option<AuthenticatedIdentity>,
    /// Unique request ID injected by middleware.
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
    /// Response headers. Values are raw strings; the adapter handles encoding.
    pub headers: HashMap<String, String>,
    /// Response body.
    pub body: ResponseBody,
}

impl ResponseEnvelope {
    /// Convenience constructor for a JSON 200 response.
    pub fn json(body: impl serde::Serialize) -> Self {
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        Self {
            status: 200,
            headers: [("content-type".into(), "application/json".into())].into(),
            body: ResponseBody::Bytes(Bytes::from(bytes)),
        }
    }

    /// Convenience constructor for a status-only response with no body.
    pub fn status(code: u16) -> Self {
        Self {
            status: code,
            headers: HashMap::new(),
            body: ResponseBody::Empty,
        }
    }

    /// Convenience constructor for a JSON error response.
    pub fn error(status: u16, message: &str) -> Self {
        let body = serde_json::json!({"error": message});
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        Self {
            status,
            headers: [("content-type".into(), "application/json".into())].into(),
            body: ResponseBody::Bytes(Bytes::from(bytes)),
        }
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
/// Generated resource handlers and built-in auth/authz handlers are all of
/// this type. The framework adapter wraps them in actix/axum extractors.
pub type Handler =
    Arc<dyn Fn(RequestContext) -> Pin<Box<dyn Future<Output = ResponseEnvelope> + Send>> + Send + Sync>;

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
/// Generated code calls this to register resource routes. Framework adapters
/// implement it by translating each entry into their native routing model
/// (actix `Resource`, axum `Router::route`, etc.).
pub trait RouteRegistry: Send + 'static {
    /// Register a handler for `method` at `path`.
    ///
    /// `path` uses the VSR path template syntax: `{param}` for required path
    /// parameters. Adapters translate to their native syntax (`:param` for
    /// axum, `{param}` for actix).
    fn add_route(&mut self, method: HttpMethod, path: &str, handler: Handler);
}

// ─── HttpServer trait ─────────────────────────────────────────────────────────

/// Configuration passed to [`HttpServer::serve`].
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Listening address.
    pub addr: SocketAddr,
    /// Optional TLS configuration (cert + key paths or PEM bytes).
    pub tls: Option<TlsConfig>,
    /// Number of worker threads. `None` means use the framework default.
    pub workers: Option<usize>,
    /// Maximum body size in bytes accepted by the framework before the handler
    /// sees the request. Default: 4 MiB.
    pub max_body_bytes: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            addr: "0.0.0.0:8080".parse().unwrap(),
            tls: None,
            workers: None,
            max_body_bytes: 4 * 1024 * 1024,
        }
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
/// - `ActixHttpServer` — behind `http-actix` feature (default).
/// - `AxumHttpServer` — behind `http-axum` feature (decision: end of Phase 3).
///
/// # Contract
///
/// - `serve` blocks until the server shuts down (via OS signal or
///   [`Self::Handle`]).
/// - The implementation MUST serve `/healthz` (liveness) and `/readyz`
///   (readiness) regardless of what the registry contains.
/// - Graceful shutdown drains in-flight requests before returning.
pub trait HttpServer: Send + Sync + 'static {
    /// An opaque handle that can be used to trigger a graceful shutdown.
    type Handle: Send + 'static;

    /// Start serving. Blocks until shutdown.
    ///
    /// `registry` supplies all application routes; the implementation adds
    /// its own health endpoints on top.
    fn serve(
        config: ServerConfig,
        middleware: MiddlewareConfig,
        routes: Vec<(HttpMethod, String, Handler)>,
    ) -> impl Future<Output = VsrResult<Self::Handle>> + Send;

    /// Signal the server to stop accepting new requests and drain gracefully.
    fn shutdown(handle: Self::Handle) -> impl Future<Output = VsrResult<()>> + Send;
}

// ─── Middleware configuration ─────────────────────────────────────────────────

/// Framework-agnostic middleware configuration.
///
/// Framework adapters apply this using their own middleware model.
/// Changing a field here does not require touching any framework-specific code.
#[derive(Debug, Clone)]
pub struct MiddlewareConfig {
    /// Enable Brotli + gzip response compression.
    pub compression: bool,
    /// CORS configuration. `None` disables CORS middleware.
    pub cors: Option<CorsConfig>,
    /// Security header policy.
    pub security_headers: SecurityHeadersConfig,
    /// Trusted reverse-proxy IP ranges (for `X-Forwarded-For` parsing).
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
    /// Allowed origins. `None` means `*` (not recommended for credentialed
    /// requests).
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

