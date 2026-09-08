//! Temporary key/SQL bridge to the framework-neutral request policy.
//! Native and emitted Actix extractors and neutral handlers use this same adapter.

use super::{AuthSettings, SessionCookieSettings};
use actix_web::{HttpRequest, HttpResponse, http::StatusCode};
use vsr_runtime::auth::{
    builtin::{AccessBackend, AccessClaims, AccountStatePolicy, BuiltinRequestAuth, CookiePolicy},
    request::{AuthFailure, RequestAuthenticator},
};
use vsr_runtime::http::HeaderFields;

struct LegacyAccessBackend {
    settings: AuthSettings,
    db: Option<crate::db::DbPool>,
}

impl AccessBackend for LegacyAccessBackend {
    fn verify(&self, token: &str) -> Result<AccessClaims, AuthFailure> {
        decode_claims(token, &self.settings)
    }

    async fn account_state(&self, user_id: i64) -> Result<Option<String>, AuthFailure> {
        let db = self.db.as_ref().ok_or(AuthFailure::RevokedToken)?;
        super::db_ops::load_authenticated_user_by_id_with_settings(db, user_id, &self.settings)
            .await
            .map(|account| account.as_ref().map(super::user::account_auth_state))
            .map_err(|_| AuthFailure::AccountValidation)
    }
}

/// Bridge existing key rotation and account storage into neutral protected routes.
/// The returned authenticator always requires a live built-in account revision.
/// The facade still links Actix; this is not yet an Axum-only application builder.
pub fn builtin_request_authenticator(
    db: crate::db::DbPool,
    settings: AuthSettings,
) -> impl RequestAuthenticator {
    request_authenticator(Some(db), settings, true)
}

pub(super) fn request_authenticator(
    db: Option<crate::db::DbPool>,
    settings: AuthSettings,
    builtin: bool,
) -> impl RequestAuthenticator {
    let cookies = settings.session_cookie.as_ref().map(cookie_policy);
    BuiltinRequestAuth::new(LegacyAccessBackend { settings, db }, cookies).with_state_policy(
        if builtin {
            AccountStatePolicy::Required
        } else {
            AccountStatePolicy::IfPresent
        },
    )
}

pub(super) fn decode_claims(
    token: &str,
    settings: &AuthSettings,
) -> Result<AccessClaims, AuthFailure> {
    let (key, validation) = super::jwt::configured_jwt_decoding_key(token, settings)
        .map_err(|_| AuthFailure::InvalidToken)?;
    jsonwebtoken::decode::<AccessClaims>(token, key.as_ref(), &validation)
        .map(|data| data.claims)
        .map_err(|_| AuthFailure::InvalidToken)
}

pub(super) fn cookie_policy(settings: &SessionCookieSettings) -> CookiePolicy {
    CookiePolicy {
        session_name: settings.name.clone(),
        csrf_cookie_name: settings.csrf_cookie_name.clone(),
        csrf_header_name: settings.csrf_header_name.clone(),
    }
}

pub(super) fn request_headers(req: &HttpRequest) -> Result<HeaderFields, AuthFailure> {
    let mut headers = HeaderFields::default();
    for (name, value) in req.headers() {
        headers
            .append(name.as_str(), value.as_bytes())
            .map_err(|_| AuthFailure::InvalidToken)?;
    }
    Ok(headers)
}

pub(super) fn failure_response(error: AuthFailure) -> HttpResponse {
    let status = StatusCode::from_u16(error.status()).expect("auth failure status is valid");
    let mut response = crate::errors::error_response(status, error.code(), error.message());
    if error.status() == 401 {
        response.headers_mut().insert(
            actix_web::http::header::WWW_AUTHENTICATE,
            actix_web::http::header::HeaderValue::from_static("Bearer"),
        );
    }
    response
}

pub(super) fn failure_error(error: AuthFailure) -> actix_web::Error {
    crate::errors::into_actix_error(failure_response(error))
}
