use actix_web::HttpRequest;
use vsr_runtime::auth::{accounts::AccountError, recovery::TokenPurpose};

use super::helpers::build_public_auth_url;
use super::settings::AuthSettings;

pub(crate) fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn action_url(
    request: Option<&HttpRequest>,
    settings: &AuthSettings,
    purpose: TokenPurpose,
    current_route_path: Option<&str>,
) -> Result<String, AccountError> {
    settings
        .email
        .as_ref()
        .ok_or(AccountError::EmailUnavailable)?;
    let path = match purpose {
        TokenPurpose::EmailVerification => "/auth/verify-email",
        TokenPurpose::PasswordReset => "/auth/password-reset",
    };
    build_public_auth_url(request, settings, path, current_route_path, &[])
        .map_err(|_| AccountError::Configuration)
}
