use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use vsr_core::error::{VsrError, VsrResult};

use super::{
    HeaderFields, HttpMethod, MiddlewareConfig, Readiness, RequestContext, ResponseBody,
    ResponseEnvelope, RouteTable, ServerConfig,
};

pub(super) fn validate_configuration(
    config: &ServerConfig,
    middleware: &MiddlewareConfig,
) -> VsrResult<()> {
    let invalid = |message: &str| VsrError::Other(message.to_owned().into());
    if config.workers == Some(0) || config.shutdown_timeout.is_zero() {
        return Err(invalid(
            "worker count and shutdown timeout must be positive",
        ));
    }
    if !middleware.trusted_proxies.is_empty() {
        return Err(invalid(
            "verified forwarded client IPs are not yet implemented; trusted_proxies is unsupported",
        ));
    }
    let mut headers = HeaderFields::default();
    for (name, value) in header_values(middleware) {
        headers.append(name, value)?;
    }
    if !matches!(
        middleware.security_headers.x_frame_options.as_str(),
        "" | "DENY" | "SAMEORIGIN"
    ) {
        return Err(invalid(
            "x_frame_options must be DENY, SAMEORIGIN, or empty",
        ));
    }
    if let Some(cors) = &middleware.cors {
        if cors.allow_credentials && cors.allowed_origins.is_none() {
            return Err(invalid("credentialed CORS requires explicit origins"));
        }
        for origin in cors.allowed_origins.iter().flatten() {
            let uri = origin
                .parse::<::http::Uri>()
                .map_err(|_| invalid("invalid CORS origin"))?;
            if !matches!(uri.scheme_str(), Some("http" | "https"))
                || uri.authority().is_none()
                || uri.authority().is_some_and(|a| a.as_str().contains('@'))
                || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
            {
                return Err(invalid(
                    "CORS origins must be HTTP(S) origins without user info or paths",
                ));
            }
        }
        for method in &cors.allowed_methods {
            ::http::Method::from_bytes(method.to_string().as_bytes())
                .map_err(|_| invalid("invalid CORS method"))?;
        }
        for header in &cors.allowed_headers {
            ::http::header::HeaderName::from_bytes(header.as_bytes())
                .map_err(|_| invalid("invalid CORS header name"))?;
        }
    }
    Ok(())
}

pub(super) fn header_values(middleware: &MiddlewareConfig) -> Vec<(&'static str, String)> {
    let security = &middleware.security_headers;
    let mut headers = vec![("x-content-type-options", "nosniff".into())];
    for (name, value) in [
        ("content-security-policy", &security.csp),
        ("x-frame-options", &security.x_frame_options),
        ("permissions-policy", &security.permissions_policy),
    ] {
        if !value.is_empty() {
            headers.push((name, value.clone()));
        }
    }
    if let Some(age) = security.hsts_max_age_secs {
        headers.push(("strict-transport-security", format!("max-age={age}")));
    }
    headers
}

pub(super) fn load_tls(config: &super::TlsConfig) -> VsrResult<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let load = || -> Result<_, Box<dyn std::error::Error>> {
        let certificates =
            CertificateDer::pem_file_iter(&config.cert_path)?.collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_file(&config.key_path)?;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    };
    load().map_err(|e| VsrError::Other(format!("invalid TLS configuration: {e}").into()))
}

pub(super) fn request_context(
    method: &str,
    path: &str,
    query: &str,
    headers: HeaderFields,
    body: Bytes,
    peer_addr: Option<SocketAddr>,
) -> Result<RequestContext, ResponseEnvelope> {
    if !super::routes::valid_percent_encoding(path)
        || !super::routes::valid_percent_encoding(query)
        || percent_encoding::percent_decode_str(query)
            .decode_utf8()
            .is_err()
    {
        return Err(ResponseEnvelope::error(400, "Invalid URL encoding"));
    }
    // Use a server-issued ID. A caller-provided ID is still available in headers.
    Ok(RequestContext {
        method: match method {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "PATCH" => HttpMethod::Patch,
            "DELETE" => HttpMethod::Delete,
            "HEAD" => HttpMethod::Head,
            "OPTIONS" => HttpMethod::Options,
            value => HttpMethod::Other(value.to_owned()),
        },
        path: path.to_owned(),
        raw_query: query.to_owned(),
        matched_route: None,
        peer_addr,
        path_params: HashMap::new(),
        query_params: parse_query_string(query),
        headers,
        body: (!body.is_empty()).then_some(body),
        identity: None,
        request_id: new_request_id(),
    })
}

pub(super) fn parse_query_string(query: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        map.entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    map
}

pub(super) fn new_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    format!(
        "req-{:x}-{:x}-{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        CTR.fetch_add(1, Ordering::Relaxed)
    )
}

pub(super) async fn dispatch(
    routes: &RouteTable,
    readiness: &Readiness,
    context: RequestContext,
) -> ResponseEnvelope {
    if matches!(context.path.as_str(), "/healthz" | "/readyz") {
        if !matches!(context.method, HttpMethod::Get | HttpMethod::Head) {
            let mut response = ResponseEnvelope::status(if context.method == HttpMethod::Options {
                204
            } else {
                405
            });
            response
                .headers
                .append("allow", "GET, HEAD, OPTIONS")
                .expect("static header");
            return response;
        }
        let ready = context.path == "/healthz" || readiness.is_ready();
        let mut response = ResponseEnvelope::status(if ready { 200 } else { 503 });
        response
            .headers
            .append("content-type", "text/plain")
            .expect("static header");
        response.body =
            ResponseBody::Bytes(Bytes::from_static(if ready { b"ok" } else { b"not ready" }));
        return response;
    }
    routes.dispatch(context).await
}

/// Reset readiness on normal exit, task cancellation, or panic.
pub(super) struct ReadinessGuard(pub Readiness, pub tokio::sync::watch::Sender<bool>);

impl Drop for ReadinessGuard {
    fn drop(&mut self) {
        self.0.set_ready(false);
        self.1.send_replace(true);
    }
}
