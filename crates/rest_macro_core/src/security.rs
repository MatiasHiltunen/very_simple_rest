//! Compatibility facade for Actix security middleware in `vsr-runtime`.

use actix_web::web;

use crate::errors;

pub use vsr_runtime::security::actix::{
    RequireAnonClient, RequireAnonClientMiddleware, cors_middleware, request_client_ip,
    require_default_anon_client_middleware, resolved_default_anon_client_key,
    security_headers_middleware,
};
pub use vsr_runtime::security::{
    AccessSecurity, CorsSecurity, DEFAULT_ANON_CLIENT_FALLBACK_KEY,
    DEFAULT_ANON_CLIENT_HEADER_NAME, DEFAULT_ANON_CLIENT_KEY_ENV, DEFAULT_MAX_FILTER_IN_VALUES,
    DefaultReadAccess, FrameOptions, HeaderSecurity, Hsts, RateLimitRule, RateLimitSecurity,
    ReferrerPolicy, RequestSecurity, SecurityConfig, TrustedProxySecurity,
};

/// Attach security and authentication settings to the legacy Actix scope.
pub fn configure_scope_security(cfg: &mut web::ServiceConfig, security: &SecurityConfig) {
    errors::configure_extractor_errors_with_limit(cfg, security.requests.json_max_bytes);
    cfg.app_data(web::Data::new(security.clone()));
    cfg.app_data(web::Data::new(security.auth.clone()));
}
