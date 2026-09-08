use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Instant;

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest, web};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;

use super::helpers::auth_settings_from_request;
use super::runtime::{failure_error, request_authenticator, request_headers};
use vsr_runtime::auth::request::{AuthFailure, RequestAuthenticator};

pub(crate) struct BuiltinAuth;

// Include the salted password hash and management revision, never expose them in the JWT.
// updated_at prevents a managed role/claim change from reviving a token when reverted.
pub(crate) fn account_auth_state(user: &AuthenticatedUser) -> String {
    user.auth_state()
}

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
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let settings = auth_settings_from_request(req);
        let db = req
            .app_data::<web::Data<crate::db::DbPool>>()
            .map(|db| db.get_ref().clone());
        let builtin = req.app_data::<BuiltinAuth>().is_some();
        let method = req.method().as_str().to_owned();
        let headers = request_headers(req);
        Box::pin(async move {
            let headers = headers.map_err(failure_error)?;
            let identity = request_authenticator(db, settings, builtin)
                .authenticate(&method, &headers)
                .await
                .map_err(failure_error)?;
            Ok(Self {
                id: identity
                    .user_id
                    .parse()
                    .map_err(|_| failure_error(AuthFailure::InvalidToken))?,
                roles: identity.roles,
                claims: identity.claims.into_iter().collect(),
            })
        })
    }
}

#[cfg(test)]
pub(crate) fn decode_user_context_token(
    token: &str,
    settings: &super::settings::AuthSettings,
) -> Result<UserContext, actix_web::Error> {
    let claims = super::runtime::decode_claims(token, settings).map_err(failure_error)?;
    Ok(UserContext {
        id: claims.sub,
        roles: claims.roles,
        claims: claims.extra,
    })
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

pub use vsr_runtime::auth::accounts::AccountInfo;
pub(crate) use vsr_runtime::auth::accounts::Account as AuthenticatedUser;

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
