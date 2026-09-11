use actix_web::{HttpRequest, HttpResponse, web};
use chrono::{SecondsFormat, Utc};
use sqlx::any::AnyRow;
use sqlx::{Column, Row};

use crate::{errors, security::{SecurityConfig, request_client_ip}};

use super::settings::AuthSettings;
use super::user::{AuthRateLimiter, AuthRateLimitScope, UserContext};

pub(crate) fn now_timestamp_string() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false)
}

pub(crate) fn hash_auth_token(token: &str) -> String {
    vsr_runtime::auth::recovery::token_digest(token)
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
    } else {
        return Err(
            "security.auth.email.public_base_url is required for authentication email links".to_owned(),
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
