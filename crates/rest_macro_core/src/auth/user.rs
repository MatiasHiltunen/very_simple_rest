use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::{Ready, ready};
use std::sync::Mutex;
use std::time::Instant;

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest, http::Method};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;

use crate::errors;

use super::helpers::{auth_settings_from_request, validate_cookie_csrf};
use super::jwt::{Claims, configured_jwt_decoding_key};
use super::settings::AuthSettings;

#[derive(Clone, Serialize, Deserialize)]
pub struct UserContext {
    pub id: i64,
    pub roles: Vec<String>,
    #[serde(flatten)]
    pub claims: BTreeMap<String, Value>,
}

impl UserContext {
    pub fn claim_i64(&self, claim: &str) -> Option<i64> {
        self.claims.get(claim).and_then(Value::as_i64)
    }

    pub fn claim_bool(&self, claim: &str) -> Option<bool> {
        self.claims.get(claim).and_then(Value::as_bool)
    }

    pub fn claim_str(&self, claim: &str) -> Option<&str> {
        self.claims.get(claim).and_then(Value::as_str)
    }

    pub fn claim_value(&self, claim: &str) -> Option<&Value> {
        self.claims.get(claim)
    }
}

impl FromRequest for UserContext {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        use actix_web::http::header;

        let settings = auth_settings_from_request(req);
        let bearer_token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_string());

        if let Some(token) = bearer_token {
            return ready(decode_user_context_token(&token, &settings));
        }

        if let Some(cookie_settings) = &settings.session_cookie
            && let Some(cookie) = req.cookie(&cookie_settings.name)
        {
            if request_needs_csrf(req.method())
                && let Err(response) = validate_cookie_csrf(req, cookie_settings)
            {
                return ready(Err(errors::into_actix_error(response)));
            }

            return ready(decode_user_context_token(cookie.value(), &settings));
        }

        ready(Err(errors::into_actix_error(errors::unauthorized(
            "missing_token",
            "Missing token",
        ))))
    }
}

pub(crate) fn decode_user_context_token(
    token: &str,
    settings: &AuthSettings,
) -> Result<UserContext, actix_web::Error> {
    use jsonwebtoken::decode;

    let (decoding_key, validation) =
        configured_jwt_decoding_key(token, settings).map_err(|_| {
            errors::into_actix_error(errors::unauthorized("invalid_token", "Invalid token"))
        })?;
    let data = decode::<Claims>(token, decoding_key.as_ref(), &validation).map_err(|_| {
        errors::into_actix_error(errors::unauthorized("invalid_token", "Invalid token"))
    })?;
    let claims = data.claims;

    Ok(UserContext {
        id: claims.sub,
        roles: claims.roles,
        claims: claims.extra,
    })
}

pub(crate) fn request_needs_csrf(method: &Method) -> bool {
    !matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Option<i64>,
    pub email: String,
    pub password_hash: String,
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterInput {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginInput {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyEmailInput {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationResendInput {
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordResetRequestInput {
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordResetConfirmInput {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordInput {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateManagedUserInput {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub send_verification_email: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateManagedUserInput {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub id: i64,
    pub email: String,
    pub role: String,
    pub roles: Vec<String>,
    pub email_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(flatten)]
    pub claims: BTreeMap<String, Value>,
}

pub(crate) struct AuthenticatedUser {
    pub id: i64,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub email_verified_at: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub has_email_verified_at_column: bool,
    pub has_created_at_column: bool,
    pub has_updated_at_column: bool,
    pub claims: BTreeMap<String, Value>,
}

impl AuthenticatedUser {
    pub fn has_auth_management_schema(&self) -> bool {
        self.has_email_verified_at_column
            && self.has_created_at_column
            && self.has_updated_at_column
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthTokenPurpose {
    EmailVerification,
    PasswordReset,
}

impl AuthTokenPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmailVerification => "email_verification",
            Self::PasswordReset => "password_reset",
        }
    }

    pub fn subject(self) -> &'static str {
        match self {
            Self::EmailVerification => "Verify your email address",
            Self::PasswordReset => "Reset your password",
        }
    }
}

#[derive(Debug)]
pub(crate) struct StoredAuthToken {
    pub id: i64,
    pub user_id: i64,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthTokenQuery {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdminListQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub email: Option<String>,
}

#[derive(Default)]
pub(crate) struct AuthRateLimiter {
    pub entries: Mutex<HashMap<String, VecDeque<Instant>>>,
}

#[derive(Clone, Copy)]
pub(crate) enum AuthRateLimitScope {
    Login,
    Register,
}

impl AuthRateLimitScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Register => "register",
        }
    }
}

impl AuthRateLimiter {
    pub fn check(&self, key: &str, rule: crate::security::RateLimitRule) -> Option<u64> {
        use std::time::Duration as StdDuration;

        let now = Instant::now();
        let window = StdDuration::from_secs(rule.window_seconds);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let entry = entries.entry(key.to_owned()).or_default();

        while entry
            .front()
            .is_some_and(|instant| now.duration_since(*instant) >= window)
        {
            entry.pop_front();
        }

        if entry.len() >= rule.requests as usize {
            let retry_after = entry
                .front()
                .map(|oldest| {
                    window
                        .saturating_sub(now.duration_since(*oldest))
                        .as_secs()
                        .max(1)
                })
                .unwrap_or(rule.window_seconds);
            return Some(retry_after);
        }

        entry.push_back(now);
        None
    }
}
