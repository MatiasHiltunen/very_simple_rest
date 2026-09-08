use actix_web::HttpRequest;
use vsr_runtime::auth::{
    accounts::AccountError, recovery::TokenPurpose, recovery_email::RecoveryRecipient,
};

use super::helpers::{build_public_auth_url, service_unavailable};
use super::settings::{AuthEmailSettings, AuthSettings};
use super::user::AuthenticatedUser;

pub(crate) fn configured_auth_email(
    settings: &AuthSettings,
) -> Result<&AuthEmailSettings, actix_web::HttpResponse> {
    settings.email.as_ref().ok_or_else(|| {
        service_unavailable(
            "auth_email_unavailable",
            "Built-in auth email delivery is not configured",
        )
    })
}

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

pub(crate) async fn send_verification_email_for_user<E>(
    db: &E,
    request: Option<&HttpRequest>,
    settings: &AuthSettings,
    user: &AuthenticatedUser,
    current_route_path: &str,
) -> Result<(), actix_web::HttpResponse>
where
    E: crate::db::DbExecutor + Sync + ?Sized,
{
    let purpose = TokenPurpose::EmailVerification;
    let url = action_url(request, settings, purpose, Some(current_route_path))
        .map_err(super::accounts::error_response)?;
    let sender = super::recovery_email::sender(settings, &url, purpose)
        .map_err(super::accounts::error_response)?;
    sender
        .send_in_transaction(
            &super::recovery_email::TokenStore(db),
            &RecoveryRecipient {
                id: user.id,
                email: user.email.clone(),
                verified: user.email_verified_at.is_some(),
            },
        )
        .await
        .map_err(super::accounts::error_response)
}
