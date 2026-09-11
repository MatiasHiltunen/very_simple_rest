use std::{env, net::IpAddr, rc::Rc, str::FromStr};

use actix_cors::Cors;
use actix_web::{
    Error, HttpRequest,
    body::{EitherBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header::{HeaderName, HeaderValue},
    middleware::DefaultHeaders,
    web,
};
use dotenvy::dotenv;
use futures_util::future::{LocalBoxFuture, Ready, ready};

use crate::{
    auth::AuthSettings,
    errors,
    secret::{SecretRef, load_optional_secret},
};

pub const DEFAULT_ANON_CLIENT_HEADER_NAME: &str = "x-vsr-anon-key";
pub const DEFAULT_ANON_CLIENT_KEY_ENV: &str = "VSR_ANON_KEY";
pub const DEFAULT_ANON_CLIENT_FALLBACK_KEY: &str = "vsr-default-anon-client-key";
pub const DEFAULT_MAX_FILTER_IN_VALUES: usize = 100;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RequestSecurity {
    pub json_max_bytes: Option<usize>,
    pub max_filter_in_values: Option<usize>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CorsSecurity {
    pub origins: Vec<String>,
    pub origins_env: Option<String>,
    pub allow_credentials: bool,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub max_age_seconds: Option<usize>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustedProxySecurity {
    pub proxies: Vec<String>,
    pub proxies_env: Option<String>,
}

pub use vsr_runtime::auth::admission::AuthRateLimitRule as RateLimitRule;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RateLimitSecurity {
    pub login: Option<RateLimitRule>,
    pub register: Option<RateLimitRule>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DefaultReadAccess {
    #[default]
    Inferred,
    Authenticated,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccessSecurity {
    pub default_read: DefaultReadAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameOptions {
    Deny,
    SameOrigin,
}

impl FrameOptions {
    fn as_header_value(self) -> &'static str {
        match self {
            Self::Deny => "DENY",
            Self::SameOrigin => "SAMEORIGIN",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferrerPolicy {
    NoReferrer,
    SameOrigin,
    StrictOriginWhenCrossOrigin,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    UnsafeUrl,
}

impl ReferrerPolicy {
    fn as_header_value(self) -> &'static str {
        match self {
            Self::NoReferrer => "no-referrer",
            Self::SameOrigin => "same-origin",
            Self::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            Self::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            Self::Origin => "origin",
            Self::OriginWhenCrossOrigin => "origin-when-cross-origin",
            Self::UnsafeUrl => "unsafe-url",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hsts {
    pub max_age_seconds: u64,
    pub include_subdomains: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HeaderSecurity {
    pub frame_options: Option<FrameOptions>,
    pub content_type_options: bool,
    pub referrer_policy: Option<ReferrerPolicy>,
    pub hsts: Option<Hsts>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecurityConfig {
    pub requests: RequestSecurity,
    pub cors: CorsSecurity,
    pub trusted_proxies: TrustedProxySecurity,
    pub rate_limits: RateLimitSecurity,
    pub access: AccessSecurity,
    pub headers: HeaderSecurity,
    pub auth: AuthSettings,
}

#[derive(Clone, Debug)]
pub struct RequireAnonClient {
    header_name: HeaderName,
    expected_key: String,
}

impl RequireAnonClient {
    pub fn new(header_name: HeaderName, expected_key: impl Into<String>) -> Self {
        Self {
            header_name,
            expected_key: expected_key.into(),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequireAnonClient
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = RequireAnonClientMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequireAnonClientMiddleware {
            service: Rc::new(service),
            header_name: self.header_name.clone(),
            expected_key: self.expected_key.clone(),
        }))
    }
}

pub struct RequireAnonClientMiddleware<S> {
    service: Rc<S>,
    header_name: HeaderName,
    expected_key: String,
}

impl<S, B> Service<ServiceRequest> for RequireAnonClientMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let header_name = self.header_name.clone();
        let expected_key = self.expected_key.clone();
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            if !request_has_valid_anon_client_key(
                req.request(),
                &header_name,
                expected_key.as_str(),
            ) {
                let response = errors::unauthorized(
                    "invalid_anon_client",
                    "Missing or invalid anonymous client key",
                );
                return Ok(req.into_response(response).map_into_right_body());
            }

            service
                .call(req)
                .await
                .map(ServiceResponse::map_into_left_body)
        })
    }
}

pub fn configure_scope_security(cfg: &mut web::ServiceConfig, security: &SecurityConfig) {
    errors::configure_extractor_errors_with_limit(cfg, security.requests.json_max_bytes);
    cfg.app_data(web::Data::new(security.clone()));
    cfg.app_data(web::Data::new(security.auth.clone()));
}

pub fn require_default_anon_client_middleware() -> Result<RequireAnonClient, String> {
    let header_name = HeaderName::from_static(DEFAULT_ANON_CLIENT_HEADER_NAME);
    let expected_key = resolved_default_anon_client_key()?;
    Ok(RequireAnonClient::new(header_name, expected_key))
}

pub fn resolved_default_anon_client_key() -> Result<String, String> {
    let _ = dotenv();
    match load_optional_secret(
        &SecretRef::env_or_file(DEFAULT_ANON_CLIENT_KEY_ENV),
        "anonymous client key",
    ) {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Ok(DEFAULT_ANON_CLIENT_FALLBACK_KEY.to_owned()),
        Err(error) => Err(error.to_string()),
    }
}

pub fn security_headers_middleware(security: &SecurityConfig) -> DefaultHeaders {
    let mut headers = DefaultHeaders::new();

    if let Some(frame_options) = security.headers.frame_options {
        headers = headers.add((
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static(frame_options.as_header_value()),
        ));
    }

    if security.headers.content_type_options {
        headers = headers.add((
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ));
    }

    if let Some(referrer_policy) = security.headers.referrer_policy {
        headers = headers.add((
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static(referrer_policy.as_header_value()),
        ));
    }

    if let Some(hsts) = &security.headers.hsts {
        let mut value = format!("max-age={}", hsts.max_age_seconds);
        if hsts.include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers = headers.add((HeaderName::from_static("strict-transport-security"), value));
        }
    }

    headers
}

pub fn cors_middleware(security: &SecurityConfig) -> Cors {
    let mut cors = Cors::default();
    let origins = resolved_cors_origins(&security.cors);
    let allow_any_origin = origins.iter().any(|origin| origin == "*");

    if allow_any_origin && security.cors.allow_credentials {
        log::error!(
            "Ignoring wildcard CORS origin because `allow_credentials` is enabled; set explicit origins instead"
        );
    } else if allow_any_origin {
        cors = cors.allow_any_origin();
    }

    for origin in origins
        .iter()
        .filter(|origin| origin.as_str() != "*")
        .map(String::as_str)
    {
        cors = cors.allowed_origin(origin);
    }

    let methods = if security.cors.allow_methods.is_empty() {
        vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    } else {
        security
            .cors
            .allow_methods
            .iter()
            .map(String::as_str)
            .collect()
    };
    cors = if methods.contains(&"*") {
        cors.allow_any_method()
    } else {
        cors.allowed_methods(methods)
    };

    let headers = if security.cors.allow_headers.is_empty() {
        vec![
            "authorization",
            "content-type",
            "accept",
            DEFAULT_ANON_CLIENT_HEADER_NAME,
        ]
    } else {
        let mut headers = security
            .cors
            .allow_headers
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if !headers
            .iter()
            .any(|header| header.eq_ignore_ascii_case(DEFAULT_ANON_CLIENT_HEADER_NAME))
        {
            headers.push(DEFAULT_ANON_CLIENT_HEADER_NAME);
        }
        headers
    };
    cors = if headers.contains(&"*") {
        cors.allow_any_header()
    } else {
        cors.allowed_headers(headers)
    };

    if !security.cors.expose_headers.is_empty() {
        let expose_headers = security
            .cors
            .expose_headers
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        cors = if expose_headers.contains(&"*") {
            cors.expose_any_header()
        } else {
            cors.expose_headers(expose_headers)
        };
    }

    if security.cors.allow_credentials {
        cors = cors.supports_credentials();
    }

    if let Some(max_age_seconds) = security.cors.max_age_seconds {
        cors = cors.max_age(max_age_seconds);
    }

    cors
}

fn request_has_valid_anon_client_key(
    req: &HttpRequest,
    header_name: &HeaderName,
    expected_key: &str,
) -> bool {
    req.headers()
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected_key)
}

pub fn request_client_ip(req: &HttpRequest, security: &SecurityConfig) -> Option<IpAddr> {
    let peer_ip = req.peer_addr()?.ip();
    let trusted_proxies = resolved_trusted_proxies(&security.trusted_proxies);

    if !trusted_proxies.contains(&peer_ip) {
        return Some(peer_ip);
    }

    let forwarded = forwarded_chain(req, "forwarded");
    let xff = forwarded_chain(req, "x-forwarded-for");
    let chain = match (forwarded, xff) {
        (Ok(Some(a)), Ok(Some(b))) if a == b => a,
        (Ok(Some(a)), Ok(None)) | (Ok(None), Ok(Some(a))) => a,
        _ => return Some(peer_ip),
    };
    // Only the trusted suffix is authoritative; the client controls everything to its left.
    let mut client = peer_ip;
    for hop in chain.into_iter().rev() {
        if !trusted_proxies.contains(&client) {
            break;
        }
        client = hop;
    }
    Some(client)
}

fn resolved_cors_origins(cors: &CorsSecurity) -> Vec<String> {
    let mut origins = cors.origins.clone();

    if let Some(env_var) = &cors.origins_env
        && let Ok(value) = env::var(env_var)
    {
        origins.extend(
            value
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .map(ToOwned::to_owned),
        );
    }

    origins.sort();
    origins.dedup();
    origins
}

fn resolved_trusted_proxies(config: &TrustedProxySecurity) -> Vec<IpAddr> {
    let mut proxies = Vec::new();

    for proxy in &config.proxies {
        match IpAddr::from_str(proxy) {
            Ok(proxy) => proxies.push(proxy),
            Err(_) => log::warn!("Ignoring invalid trusted proxy IP `{proxy}`"),
        }
    }

    if let Some(env_var) = &config.proxies_env
        && let Ok(value) = env::var(env_var)
    {
        for proxy in value
            .split(',')
            .map(str::trim)
            .filter(|proxy| !proxy.is_empty())
        {
            match IpAddr::from_str(proxy) {
                Ok(proxy) => proxies.push(proxy),
                Err(_) => log::warn!(
                    "Ignoring invalid trusted proxy IP `{proxy}` from environment variable {env_var}"
                ),
            }
        }
    }

    proxies.sort();
    proxies.dedup();
    proxies
}

fn forwarded_chain(req: &HttpRequest, name: &str) -> Result<Option<Vec<IpAddr>>, ()> {
    let mut chain = Vec::new();
    for header in req.headers().get_all(name) {
        for entry in header.to_str().map_err(|_| ())?.split(',') {
            let value = if name == "forwarded" {
                let mut address = None;
                for part in entry.split(';') {
                    let (key, value) = part.trim().split_once('=').ok_or(())?;
                    if key.eq_ignore_ascii_case("for") {
                        if address.replace(value).is_some() {
                            return Err(());
                        }
                    }
                }
                address.ok_or(())?
            } else {
                entry
            };
            chain.push(parse_forwarded_ip(value).ok_or(())?);
        }
    }
    Ok((!chain.is_empty()).then_some(chain))
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    let value = if let Some(quoted) = value.strip_prefix('"') {
        quoted.strip_suffix('"')?
    } else {
        value
    };
    if value.is_empty() || value.eq_ignore_ascii_case("unknown") || value.starts_with('_') {
        return None;
    }

    if let Some(ipv6) = value.strip_prefix('[') {
        let end = ipv6.find(']')?;
        let suffix = &ipv6[end + 1..];
        if !suffix.is_empty() {
            suffix.strip_prefix(':')?.parse::<u16>().ok()?;
        }
        return IpAddr::from_str(&ipv6[..end]).ok();
    }

    if let Ok(ip) = IpAddr::from_str(value) {
        return Some(ip);
    }

    if value.matches(':').count() == 1
        && let Ok(addr) = std::net::SocketAddr::from_str(value)
    {
        return Some(addr.ip());
    }

    None
}

#[cfg(test)]
mod tests {
    #[actix_web::test]
    async fn proxy_identity_uses_only_the_trusted_suffix() {
        use super::*;
        use actix_web::test::TestRequest;
        let mut security = SecurityConfig::default();
        security.trusted_proxies.proxies = vec!["127.0.0.1".into(), "::1".into()];
        let peer = "127.0.0.1:8000".parse().unwrap();
        let client: IpAddr = "192.0.2.1".parse().unwrap();
        for (name, value) in [
            ("x-forwarded-for", "203.0.113.9, 192.0.2.1, ::1"),
            (
                "forwarded",
                "for=203.0.113.9, For=192.0.2.1;proto=https, for=\"[::1]:443\"",
            ),
        ] {
            let req = TestRequest::default()
                .peer_addr(peer)
                .insert_header((name, value))
                .to_http_request();
            assert_eq!(request_client_ip(&req, &security), Some(client));
        }
        let req = TestRequest::default()
            .peer_addr(peer)
            .append_header(("x-forwarded-for", "203.0.113.9, 192.0.2.1"))
            .append_header(("x-forwarded-for", "::1"))
            .to_http_request();
        assert_eq!(request_client_ip(&req, &security), Some(client));
        for value in [
            "unknown, 192.0.2.1",
            "192.0.2.1,",
            "[::1]garbage",
            "\"192.0.2.1",
            "[::1]:oops",
        ] {
            let req = TestRequest::default()
                .peer_addr(peer)
                .insert_header(("x-forwarded-for", value))
                .to_http_request();
            assert_eq!(request_client_ip(&req, &security), Some(peer.ip()));
        }
        let req = TestRequest::default()
            .peer_addr(peer)
            .insert_header(("forwarded", "for=203.0.113.9"))
            .insert_header(("x-forwarded-for", "192.0.2.1"))
            .to_http_request();
        assert_eq!(request_client_ip(&req, &security), Some(peer.ip()));
        let req = TestRequest::default()
            .insert_header(("x-forwarded-for", "192.0.2.1"))
            .to_http_request();
        assert_eq!(request_client_ip(&req, &security), None);
        let req = TestRequest::default()
            .peer_addr("198.51.100.1:1".parse().unwrap())
            .insert_header(("x-forwarded-for", "192.0.2.1"))
            .to_http_request();
        assert_eq!(
            request_client_ip(&req, &security),
            Some("198.51.100.1".parse().unwrap())
        );
    }

    use super::{CorsSecurity, DEFAULT_ANON_CLIENT_HEADER_NAME, SecurityConfig, cors_middleware};
    use actix_web::{
        App, HttpResponse,
        http::{Method, header},
        test, web,
    };

    #[actix_web::test]
    async fn cors_explicit_allow_headers_still_allows_anon_client_header() {
        let security = SecurityConfig {
            cors: CorsSecurity {
                origins: vec!["https://app.example".to_owned()],
                allow_headers: vec!["content-type".to_owned()],
                ..CorsSecurity::default()
            },
            ..SecurityConfig::default()
        };

        let app = test::init_service(App::new().wrap(cors_middleware(&security)).route(
            "/items",
            web::get().to(|| async { HttpResponse::Ok().finish() }),
        ))
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::default()
                .method(Method::OPTIONS)
                .uri("/items")
                .insert_header((header::ORIGIN, "https://app.example"))
                .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "GET"))
                .insert_header((
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    format!("content-type, {DEFAULT_ANON_CLIENT_HEADER_NAME}"),
                ))
                .to_request(),
        )
        .await;

        assert!(
            response.status().is_success(),
            "preflight should accept the anonymous client header"
        );
        let allow_headers = response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .and_then(|value| value.to_str().ok())
            .expect("preflight should advertise allowed headers")
            .to_ascii_lowercase();
        assert!(allow_headers.contains(DEFAULT_ANON_CLIENT_HEADER_NAME));
    }
}
