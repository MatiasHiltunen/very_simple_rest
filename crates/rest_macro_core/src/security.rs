//! Compatibility facade for Actix security middleware in `vsr-runtime`.

pub use vsr_runtime::security::actix::{
    RequireAnonClient, RequireAnonClientMiddleware, configure_scope_security, cors_middleware,
    request_client_ip, require_default_anon_client_middleware, resolved_default_anon_client_key,
    security_headers_middleware,
};
pub use vsr_runtime::security::{
    AccessSecurity, CorsSecurity, DEFAULT_ANON_CLIENT_FALLBACK_KEY,
    DEFAULT_ANON_CLIENT_HEADER_NAME, DEFAULT_ANON_CLIENT_KEY_ENV, DEFAULT_MAX_FILTER_IN_VALUES,
    DefaultReadAccess, FrameOptions, HeaderSecurity, Hsts, RateLimitRule, RateLimitSecurity,
    ReferrerPolicy, RequestSecurity, SecurityConfig, TrustedProxySecurity,
};
