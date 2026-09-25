//! Framework-neutral security settings shared by native and emitted services.

use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use crate::{auth::settings::AuthSettings, http::HeaderFields};

pub use crate::rate_limit::AuthRateLimitRule as RateLimitRule;

/// Default header used to identify the anonymous VSR client.
pub const DEFAULT_ANON_CLIENT_HEADER_NAME: &str = "x-vsr-anon-key";
/// Environment variable containing the anonymous client key.
pub const DEFAULT_ANON_CLIENT_KEY_ENV: &str = "VSR_ANON_KEY";
/// Fallback anonymous client key used when none is configured.
pub const DEFAULT_ANON_CLIENT_FALLBACK_KEY: &str = "vsr-default-anon-client-key";
/// Default maximum number of values accepted by an `in` filter.
pub const DEFAULT_MAX_FILTER_IN_VALUES: usize = 100;

/// Limits applied to API requests.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RequestSecurity {
    /// Maximum JSON request body size in bytes.
    pub json_max_bytes: Option<usize>,
    /// Maximum number of values in an `in` filter.
    pub max_filter_in_values: Option<usize>,
}

/// Cross-origin resource sharing policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CorsSecurity {
    /// Explicit allowed origins.
    pub origins: Vec<String>,
    /// Optional environment variable with comma-separated allowed origins.
    pub origins_env: Option<String>,
    /// Whether credentials may accompany cross-origin requests.
    pub allow_credentials: bool,
    /// Explicit allowed methods.
    pub allow_methods: Vec<String>,
    /// Explicit allowed request headers.
    pub allow_headers: Vec<String>,
    /// Response headers exposed to browsers.
    pub expose_headers: Vec<String>,
    /// Browser preflight cache duration in seconds.
    pub max_age_seconds: Option<usize>,
}

/// Peers whose forwarding headers can be trusted.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustedProxySecurity {
    /// Explicit trusted proxy IP addresses.
    pub proxies: Vec<String>,
    /// Optional environment variable with comma-separated proxy addresses.
    pub proxies_env: Option<String>,
}

/// Rate limits for built-in authentication endpoints.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RateLimitSecurity {
    /// Login request limit.
    pub login: Option<RateLimitRule>,
    /// Registration request limit.
    pub register: Option<RateLimitRule>,
}

/// Fallback read access when a resource has no explicit read policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DefaultReadAccess {
    /// Infer access from the resource configuration.
    #[default]
    Inferred,
    /// Require an authenticated caller.
    Authenticated,
}

/// Default access policy settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccessSecurity {
    /// Fallback read access.
    pub default_read: DefaultReadAccess,
}

/// X-Frame-Options header policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameOptions {
    /// Disallow framing.
    Deny,
    /// Allow framing by the same origin.
    SameOrigin,
}

impl FrameOptions {
    /// Header value corresponding to this policy.
    pub fn as_header_value(self) -> &'static str {
        match self {
            Self::Deny => "DENY",
            Self::SameOrigin => "SAMEORIGIN",
        }
    }
}

/// Referrer-Policy header policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferrerPolicy {
    /// Never include a referrer.
    NoReferrer,
    /// Include a referrer only for the same origin.
    SameOrigin,
    /// Include the origin across secure origins and the full URL for the same origin.
    StrictOriginWhenCrossOrigin,
    /// Suppress the referrer when navigating to a less secure origin.
    NoReferrerWhenDowngrade,
    /// Include only the origin.
    Origin,
    /// Include the full URL for the same origin and otherwise the origin.
    OriginWhenCrossOrigin,
    /// Always include the full referrer URL.
    UnsafeUrl,
}

impl ReferrerPolicy {
    /// Header value corresponding to this policy.
    pub fn as_header_value(self) -> &'static str {
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

/// HTTP Strict Transport Security settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hsts {
    /// Duration for which browsers should require HTTPS.
    pub max_age_seconds: u64,
    /// Whether the policy applies to subdomains.
    pub include_subdomains: bool,
}

/// Browser-facing security response headers.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HeaderSecurity {
    /// Framing policy.
    pub frame_options: Option<FrameOptions>,
    /// Whether to emit `X-Content-Type-Options: nosniff`.
    pub content_type_options: bool,
    /// Referrer policy.
    pub referrer_policy: Option<ReferrerPolicy>,
    /// HTTP Strict Transport Security policy.
    pub hsts: Option<Hsts>,
}

/// Security configuration used by native and emitted services.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecurityConfig {
    /// Request body and query limits.
    pub requests: RequestSecurity,
    /// Cross-origin policy.
    pub cors: CorsSecurity,
    /// Trusted reverse proxies.
    pub trusted_proxies: TrustedProxySecurity,
    /// Authentication endpoint rate limits.
    pub rate_limits: RateLimitSecurity,
    /// Default resource access policy.
    pub access: AccessSecurity,
    /// Browser-facing security headers.
    pub headers: HeaderSecurity,
    /// Built-in authentication settings.
    pub auth: AuthSettings,
}

/// Resolve the caller IP from the direct peer and forwarding headers.
///
/// Forwarding headers are considered only when the direct peer is trusted. If
/// both `Forwarded` and `X-Forwarded-For` are present, they must agree. A
/// malformed or conflicting chain falls back to the direct peer.
pub fn resolve_client_ip(
    peer: Option<SocketAddr>,
    headers: &HeaderFields,
    trusted_proxies: &[IpAddr],
) -> Option<IpAddr> {
    let peer_ip = peer?.ip();
    if !trusted_proxies.contains(&peer_ip) {
        return Some(peer_ip);
    }

    let forwarded = forwarded_chain(headers, "forwarded");
    let xff = forwarded_chain(headers, "x-forwarded-for");
    let chain = match (forwarded, xff) {
        (Ok(Some(a)), Ok(Some(b))) if a == b => a,
        (Ok(Some(a)), Ok(None)) | (Ok(None), Ok(Some(a))) => a,
        _ => return Some(peer_ip),
    };
    let mut client = peer_ip;
    for hop in chain.into_iter().rev() {
        if !trusted_proxies.contains(&client) {
            break;
        }
        client = hop;
    }
    Some(client)
}

fn forwarded_chain(headers: &HeaderFields, name: &str) -> Result<Option<Vec<IpAddr>>, ()> {
    let mut chain = Vec::new();
    for header in headers.get_all(name) {
        for entry in std::str::from_utf8(header).map_err(|_| ())?.split(',') {
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
        && let Ok(addr) = SocketAddr::from_str(value)
    {
        return Some(addr.ip());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::resolve_client_ip;
    use crate::http::HeaderFields;
    use std::net::{IpAddr, SocketAddr};

    #[test]
    fn trusted_suffix_wins_over_client_supplied_hops() {
        let peer: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()];
        let mut headers = HeaderFields::default();
        headers
            .append("x-forwarded-for", "203.0.113.9, 192.0.2.1, ::1")
            .unwrap();
        headers
            .append(
                "forwarded",
                "for=203.0.113.9, For=192.0.2.1;proto=https, for=\"[::1]:443\"",
            )
            .unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some("192.0.2.1".parse().unwrap())
        );

        let untrusted: SocketAddr = "198.51.100.1:8000".parse().unwrap();
        assert_eq!(
            resolve_client_ip(Some(untrusted), &headers, &trusted),
            Some(untrusted.ip())
        );
    }

    #[test]
    fn conflicting_or_malformed_forwarding_falls_back_to_peer() {
        let peer: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let trusted = [peer.ip()];
        let mut headers = HeaderFields::default();
        headers.append("forwarded", "for=203.0.113.9").unwrap();
        headers.append("x-forwarded-for", "192.0.2.1").unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(peer.ip())
        );

        let mut headers = HeaderFields::default();
        headers.append("x-forwarded-for", [0x80]).unwrap();
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted),
            Some(peer.ip())
        );
    }
}
