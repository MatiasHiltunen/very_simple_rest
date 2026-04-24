use actix_web::HttpRequest;

use crate::email::{AuthEmailMessage, send_auth_email};
use crate::errors;

use super::db_ops::create_auth_token;
use super::helpers::{
    build_public_auth_url, is_missing_auth_management_schema,
    missing_auth_management_schema_response, service_unavailable,
};
use super::settings::{AuthEmailSettings, AuthSettings};
use super::user::{AuthTokenPurpose, AuthenticatedUser};

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

pub(crate) fn verification_email_message(email: &str, url: &str) -> AuthEmailMessage {
    AuthEmailMessage {
        to_email: email.to_owned(),
        to_name: None,
        subject: AuthTokenPurpose::EmailVerification.subject().to_owned(),
        text_body: format!(
            "Verify your email address by opening this link:\n\n{url}\n\nIf you did not create this account, you can ignore this message."
        ),
        html_body: format!(
            "<!doctype html><html><body><h1>Verify your email</h1><p>Open the link below to verify your email address.</p><p><a href=\"{url}\">{label}</a></p><p>If you did not create this account, you can ignore this message.</p></body></html>",
            url = escape_html(url),
            label = escape_html(url),
        ),
    }
}

pub(crate) fn password_reset_email_message(email: &str, url: &str) -> AuthEmailMessage {
    AuthEmailMessage {
        to_email: email.to_owned(),
        to_name: None,
        subject: AuthTokenPurpose::PasswordReset.subject().to_owned(),
        text_body: format!(
            "Reset your password by opening this link:\n\n{url}\n\nIf you did not request a password reset, you can ignore this message."
        ),
        html_body: format!(
            "<!doctype html><html><body><h1>Reset your password</h1><p>Open the link below to choose a new password.</p><p><a href=\"{url}\">{label}</a></p><p>If you did not request a password reset, you can ignore this message.</p></body></html>",
            url = escape_html(url),
            label = escape_html(url),
        ),
    }
}

pub(crate) async fn send_verification_email_for_user<E>(
    db: &E,
    request: Option<&HttpRequest>,
    settings: &AuthSettings,
    user: &AuthenticatedUser,
    current_route_path: &str,
) -> Result<(), actix_web::HttpResponse>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let email_settings = configured_auth_email(settings)?;
    let token = create_auth_token(
        db,
        user.id,
        AuthTokenPurpose::EmailVerification,
        Some(&user.email),
        settings.verification_token_ttl_seconds,
    )
    .await
    .map_err(|error| {
        if is_missing_auth_management_schema(&error) {
            missing_auth_management_schema_response()
        } else {
            errors::internal_error("Database error")
        }
    })?;
    let url = build_public_auth_url(
        request,
        settings,
        "/auth/verify-email",
        Some(current_route_path),
        &[("token", token.as_str())],
    )
    .map_err(errors::internal_error)?;
    let message = verification_email_message(&user.email, &url);
    send_auth_email(email_settings, &message)
        .await
        .map_err(|error| {
            errors::internal_error(format!("Failed to send verification email: {error}"))
        })
}

pub(crate) async fn send_password_reset_email_for_user<E>(
    db: &E,
    request: Option<&HttpRequest>,
    settings: &AuthSettings,
    user: &AuthenticatedUser,
) -> Result<(), actix_web::HttpResponse>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let email_settings = configured_auth_email(settings)?;
    let token = create_auth_token(
        db,
        user.id,
        AuthTokenPurpose::PasswordReset,
        Some(&user.email),
        settings.password_reset_token_ttl_seconds,
    )
    .await
    .map_err(|error| {
        if is_missing_auth_management_schema(&error) {
            missing_auth_management_schema_response()
        } else {
            errors::internal_error("Database error")
        }
    })?;
    let url = build_public_auth_url(
        request,
        settings,
        "/auth/password-reset",
        None,
        &[("token", token.as_str())],
    )
    .map_err(errors::internal_error)?;
    let message = password_reset_email_message(&user.email, &url);
    send_auth_email(email_settings, &message)
        .await
        .map_err(|error| {
            errors::internal_error(format!("Failed to send password reset email: {error}"))
        })
}
