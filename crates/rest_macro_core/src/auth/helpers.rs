use actix_web::{HttpRequest, HttpResponse, web};
use actix_web::cookie::SameSite;
use chrono::{SecondsFormat, Utc};
use rand::distr::{Alphanumeric, SampleString};
use rand::rng;
use sqlx::any::AnyRow;
use sqlx::{Column, Row};

use crate::{errors, security::{SecurityConfig, request_client_ip}};

use super::settings::{AuthSettings, SessionCookieSameSite, SessionCookieSettings};
use super::user::{AuthRateLimiter, AuthRateLimitScope, UserContext};

pub(crate) fn now_timestamp_string() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false)
}

pub(crate) fn service_unavailable(code: &'static str, message: impl Into<String>) -> HttpResponse {
    errors::error_response(
        actix_web::http::StatusCode::SERVICE_UNAVAILABLE,
        code,
        message,
    )
}

pub(crate) fn normalize_auth_email(raw: &str) -> Result<String, HttpResponse> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(errors::validation_error(
            "email",
            "Email address cannot be empty",
        ));
    }
    if normalized.contains(char::is_whitespace) {
        return Err(errors::validation_error(
            "email",
            "Email address cannot contain whitespace",
        ));
    }
    let mut parts = normalized.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if local.is_empty() || domain.is_empty() || parts.next().is_some() || !domain.contains('.') {
        return Err(errors::validation_error(
            "email",
            "Email address is not valid",
        ));
    }
    Ok(normalized)
}

pub(crate) fn validate_auth_password(password: &str) -> Result<(), HttpResponse> {
    let len = password.chars().count();
    if len < 8 {
        return Err(errors::validation_error(
            "password",
            "Password must be at least 8 characters long",
        ));
    }
    if password.len() > 72 {
        return Err(errors::validation_error(
            "password",
            "Password must be at most 72 bytes long",
        ));
    }
    Ok(())
}

pub(crate) fn normalize_auth_role(
    raw: Option<&str>,
    default_role: &str,
) -> Result<String, HttpResponse> {
    let role = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_role)
        .to_owned();
    if role.chars().any(char::is_whitespace) {
        return Err(errors::validation_error(
            "role",
            "Role cannot contain whitespace",
        ));
    }
    Ok(role)
}

pub(crate) fn hash_auth_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub(crate) fn is_missing_auth_management_schema(error: &sqlx::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("no such table: auth_user_token")
        || message.contains("relation \"auth_user_token\" does not exist")
        || message.contains("unknown table 'auth_user_token'")
        || message.contains("no such column: email_verified_at")
        || message.contains("column \"email_verified_at\" does not exist")
        || message.contains("unknown column 'email_verified_at'")
        || message.contains("no such column: created_at")
        || message.contains("column \"created_at\" does not exist")
        || message.contains("unknown column 'created_at'")
        || message.contains("no such column: updated_at")
        || message.contains("column \"updated_at\" does not exist")
        || message.contains("unknown column 'updated_at'")
}

pub(crate) fn missing_auth_management_schema_response() -> HttpResponse {
    errors::internal_error(
        "Built-in auth management schema is missing. Apply the built-in auth migration again to add email verification and password reset tables.",
    )
}

pub(crate) fn scope_prefix_from_request(
    req: &HttpRequest,
    current_route_path: Option<&str>,
) -> String {
    if let Some(route) = current_route_path
        && req.path().ends_with(route)
    {
        let prefix = req.path().trim_end_matches(route);
        return prefix.to_owned();
    }

    if let Some(index) = req.path().find("/auth/") {
        return req.path()[..index].to_owned();
    }

    String::new()
}

pub(crate) fn build_public_auth_url(
    req: Option<&HttpRequest>,
    settings: &AuthSettings,
    auth_path: &str,
    current_route_path: Option<&str>,
    query_pairs: &[(&str, &str)],
) -> Result<String, String> {
    let scope_prefix = req
        .map(|req| scope_prefix_from_request(req, current_route_path))
        .unwrap_or_default();
    let mut base_url = if let Some(public_base_url) = settings
        .email
        .as_ref()
        .and_then(|email| email.public_base_url.clone())
    {
        let mut url = url::Url::parse(&public_base_url)
            .map_err(|error| format!("invalid security.auth.email.public_base_url: {error}"))?;
        url.set_query(None);
        url.set_fragment(None);

        let base_path = url.path().trim_end_matches('/');
        let scope_prefix = scope_prefix.trim_end_matches('/');
        let scoped_path = if scope_prefix.is_empty() {
            base_path.to_owned()
        } else if base_path.is_empty() || base_path == "/" {
            scope_prefix.to_owned()
        } else if base_path.ends_with(scope_prefix) {
            base_path.to_owned()
        } else {
            format!("{base_path}{scope_prefix}")
        };
        if scoped_path.is_empty() {
            url.set_path("/");
        } else {
            url.set_path(&scoped_path);
        }
        url
    } else if let Some(req) = req {
        let info = req.connection_info();
        url::Url::parse(&format!(
            "{}://{}{}",
            info.scheme(),
            info.host(),
            scope_prefix.trim_end_matches('/')
        ))
        .map_err(|error| format!("failed to build auth base URL from request: {error}"))?
    } else {
        return Err(
            "security.auth.email.public_base_url is required when auth emails are sent outside an HTTP request context"
                .to_owned(),
        );
    };

    let base_path = base_url.path().trim_end_matches('/');
    let next_path = format!("{base_path}/{}", auth_path.trim_start_matches('/'));
    base_url.set_path(&next_path);

    if !query_pairs.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in query_pairs {
            serializer.append_pair(key, value);
        }
        base_url.set_query(Some(&serializer.finish()));
    } else {
        base_url.set_query(None);
    }

    Ok(base_url.to_string())
}

pub(crate) fn user_roles(role: &str) -> Vec<String> {
    vec![role.to_owned()]
}

pub(crate) fn user_is_admin(user: &UserContext) -> bool {
    user.roles.iter().any(|role| role == "admin")
}

pub(crate) fn optional_text_column(
    row: &AnyRow,
    column: &str,
) -> Result<Option<String>, sqlx::Error> {
    match row.try_get::<Option<String>, _>(column) {
        Ok(value) => Ok(value),
        Err(sqlx::Error::ColumnNotFound(_)) => Ok(None),
        Err(sqlx::Error::ColumnDecode { .. }) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn row_has_column(row: &AnyRow, column: &str) -> bool {
    row.columns()
        .iter()
        .any(|candidate| candidate.name().eq_ignore_ascii_case(column))
}

pub(crate) fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .map(sqlx::error::DatabaseError::is_unique_violation)
        .unwrap_or(false)
}

pub(crate) fn generate_ephemeral_secret(length: usize) -> String {
    let mut random = rng();
    Alphanumeric.sample_string(&mut random, length)
}

pub(crate) fn same_site_from_settings(value: SessionCookieSameSite) -> SameSite {
    match value {
        SessionCookieSameSite::Lax => SameSite::Lax,
        SessionCookieSameSite::None => SameSite::None,
        SessionCookieSameSite::Strict => SameSite::Strict,
    }
}

pub(crate) fn enforce_auth_rate_limit(
    req: &HttpRequest,
    scope: AuthRateLimitScope,
) -> Option<HttpResponse> {
    let security = security_from_request(req);
    let rule = match scope {
        AuthRateLimitScope::Login => security.rate_limits.login,
        AuthRateLimitScope::Register => security.rate_limits.register,
    }?;

    let limiter = req.app_data::<web::Data<AuthRateLimiter>>()?;
    let client_ip = request_client_ip(req, &security)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    let key = format!("{}:{client_ip}", scope.as_str());
    let retry_after = limiter.check(&key, rule)?;

    let mut response = errors::too_many_requests(
        "rate_limited",
        format!("Too many {} attempts. Try again later.", scope.as_str()),
    );
    if let Ok(value) = actix_web::http::header::HeaderValue::from_str(&retry_after.to_string()) {
        response
            .headers_mut()
            .insert(actix_web::http::header::RETRY_AFTER, value);
    }
    Some(response)
}

pub(crate) fn auth_settings_from_request(req: &HttpRequest) -> AuthSettings {
    req.app_data::<web::Data<AuthSettings>>()
        .map(|settings| settings.get_ref().clone())
        .unwrap_or_default()
}

pub(crate) fn security_from_request(req: &HttpRequest) -> SecurityConfig {
    req.app_data::<web::Data<SecurityConfig>>()
        .map(|security| security.get_ref().clone())
        .unwrap_or_else(|| SecurityConfig {
            auth: auth_settings_from_request(req),
            ..SecurityConfig::default()
        })
}

pub(crate) fn auth_api_base_path_for_page(req: &HttpRequest, page_path: Option<&str>) -> String {
    let scope_prefix = scope_prefix_from_request(req, page_path);
    if scope_prefix.is_empty() {
        "/auth".to_owned()
    } else {
        format!("{}/auth", scope_prefix.trim_end_matches('/'))
    }
}

pub(crate) fn validate_cookie_csrf(
    req: &HttpRequest,
    settings: &SessionCookieSettings,
) -> Result<(), HttpResponse> {
    let csrf_cookie = req
        .cookie(&settings.csrf_cookie_name)
        .ok_or_else(|| errors::forbidden("invalid_csrf", "Missing or invalid CSRF token"))?;
    let csrf_header = req
        .headers()
        .get(settings.csrf_header_name.as_str())
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| errors::forbidden("invalid_csrf", "Missing or invalid CSRF token"))?;

    if csrf_header == csrf_cookie.value() {
        Ok(())
    } else {
        Err(errors::forbidden(
            "invalid_csrf",
            "Missing or invalid CSRF token",
        ))
    }
}
