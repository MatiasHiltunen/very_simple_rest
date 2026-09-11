//! Stateless login-cookie presentation and logout policy shared by transports.
//!
//! Logout clears browser cookies; it does not revoke an already-issued bearer
//! token. Authentication, login rate limits and JSON extraction remain separate.

use cookie::{Cookie, SameSite, time::Duration};

use super::{
    accounts::AccountError,
    builtin::{CookiePolicy, unique_cookie, validate_cookie_csrf},
    request::AuthFailure,
};
use crate::http::{HeaderFields, ResponseEnvelope};

/// Framework-independent `SameSite` setting for both session and CSRF cookies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionSameSite {
    /// Send cookies with same-site requests and eligible top-level navigation.
    Lax,
    /// Cross-site cookies; requires secure transport configuration.
    None,
    /// Restrict cookies to same-site requests.
    Strict,
}

/// Trusted server configuration. No domain attribute is emitted.
#[derive(Clone)]
pub struct SessionCookiePolicy {
    /// Names used by the existing request authentication/CSRF policy.
    pub request: CookiePolicy,
    /// Absolute cookie scope, identical for issuance and deletion.
    pub path: String,
    /// Emit the Secure attribute on both cookies.
    pub secure: bool,
    /// `SameSite` attribute for both cookies.
    pub same_site: SessionSameSite,
}

impl SessionCookiePolicy {
    /// Reject ambiguous names, attribute injection and insecure cookie prefixes.
    /// Apply this to programmatic configuration as well as parsed configuration.
    pub fn validate(&self) -> Result<(), AccountError> {
        let names = [&self.request.session_name, &self.request.csrf_cookie_name];
        if names[0] == names[1]
            || names.iter().any(|name| {
                name.is_empty()
                    || !name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || b"!#$&'*+-.^_`|~".contains(&byte)
                    })
                    || (name.starts_with("__Host-") && (!self.secure || self.path != "/"))
                    || (name.starts_with("__Secure-") && !self.secure)
            })
            || !self.path.starts_with('/')
            || !self
                .path
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !b";?#\\".contains(&byte))
            || (self.same_site == SessionSameSite::None && !self.secure)
        {
            return Err(AccountError::Configuration);
        }
        // Percent escapes in names are intentionally unsupported: request cookie
        // parsing decodes names once, so literal escaped names cannot round-trip.
        let header = http::header::HeaderName::from_bytes(self.request.csrf_header_name.as_bytes())
            .map_err(|_| AccountError::Configuration)?;
        if matches!(header.as_str(), "cookie" | "set-cookie" | "authorization") {
            return Err(AccountError::Configuration);
        }
        Ok(())
    }

    fn cookie(&self, name: &str, value: &str, http_only: bool, age: i64) -> String {
        let same_site = match self.same_site {
            SessionSameSite::Lax => SameSite::Lax,
            SessionSameSite::None => SameSite::None,
            SessionSameSite::Strict => SameSite::Strict,
        };
        Cookie::build(name, value)
            .path(&self.path)
            .http_only(http_only)
            .secure(self.secure)
            .same_site(same_site)
            .max_age(Duration::seconds(age))
            .finish()
            .to_string()
    }

    fn append_cookies(
        &self,
        response: &mut ResponseEnvelope,
        token: &str,
        csrf: &str,
        age: i64,
    ) -> Result<(), AccountError> {
        for (name, value, http_only) in [
            (&self.request.session_name, token, true),
            (&self.request.csrf_cookie_name, csrf, false),
        ] {
            let cookie = self.cookie(name, value, http_only, age);
            // Keep each serialized cookie within the application's browser budget.
            if cookie.len() > 4096 {
                return Err(AccountError::Configuration);
            }
            response
                .headers
                .append("set-cookie", cookie)
                .map_err(|_| AccountError::Configuration)?;
        }
        Ok(())
    }
}

/// Validated response policy; contains configuration, never issued credentials.
#[derive(Clone)]
pub struct SessionPresentation {
    cookies: Option<SessionCookiePolicy>,
}

impl SessionPresentation {
    /// Configure cookie presentation, or retain bearer-only responses with `None`.
    pub fn new(cookies: Option<SessionCookiePolicy>) -> Result<Self, AccountError> {
        if let Some(policy) = &cookies {
            policy.validate()?;
        }
        Ok(Self { cookies })
    }

    /// Present a token only after successful authentication and token issuance.
    /// Cookie CSRF secrets use 256 bits of fallible OS entropy, never a fallback.
    pub fn login(&self, token: &str, ttl_seconds: i64) -> Result<ResponseEnvelope, AccountError> {
        self.login_with(token, ttl_seconds, |bytes| {
            getrandom::fill(bytes).map_err(|_| AccountError::TokenGeneration)
        })
    }

    fn login_with(
        &self,
        token: &str,
        ttl_seconds: i64,
        fill: impl FnOnce(&mut [u8]) -> Result<(), AccountError>,
    ) -> Result<ResponseEnvelope, AccountError> {
        if ttl_seconds <= 0 {
            return Err(AccountError::Configuration);
        }
        if token.is_empty()
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/=".contains(&byte))
        {
            return Err(AccountError::TokenGeneration);
        }
        let mut response = ResponseEnvelope::json(serde_json::json!({"token": token}));
        if let Some(policy) = &self.cookies {
            let mut bytes = [0; 32];
            fill(&mut bytes)?;
            let csrf = hex::encode(bytes);
            response = ResponseEnvelope::json(serde_json::json!({
                "token": token, "csrf_token": csrf,
            }));
            policy.append_cookies(&mut response, token, &csrf, ttl_seconds)?;
        }
        no_store(response)
    }

    /// Clear cookies without requiring an unexpired token. Any session cookie,
    /// including an empty one, requires a unique matching CSRF cookie/header.
    /// Bearer credentials never bypass this check for a cookie-clearing request.
    pub fn logout(&self, headers: &HeaderFields) -> Result<ResponseEnvelope, AccountError> {
        let mut response = ResponseEnvelope::status(204);
        if let Some(policy) = &self.cookies {
            if unique_cookie(headers, &policy.request.session_name)
                .map_err(|()| AuthFailure::InvalidCsrf)?
                .is_some()
            {
                validate_cookie_csrf(headers, &policy.request)?;
            }
            policy.append_cookies(&mut response, "", "", 0)?;
        }
        no_store(response)
    }
}

fn no_store(mut response: ResponseEnvelope) -> Result<ResponseEnvelope, AccountError> {
    response
        .headers
        .append("cache-control", "no-store")
        .map_err(|_| AccountError::Configuration)?;
    Ok(response)
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
