//! Built-in account operations, independent of SQL drivers and HTTP frameworks.
//!
//! Adapters own JSON extraction, cookies, rate limiting and key/storage access.
//! This service owns credential policy and never accepts a client-selected user
//! ID for protected operations: callers must use the authenticated identity.

use super::{
    builtin::{AccessClaims, AccountState},
    password,
    request::AuthFailure,
};
use crate::http::ResponseEnvelope;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, future::Future};
use vsr_core::clock::{Clock, SystemClock};

/// Account record returned only to trusted service code. Intentionally not Debug
/// or Serialize: the salted hash must not appear in logs or public responses.
pub struct Account {
    /// Numeric account identifier.
    pub id: i64,
    /// Current email address.
    pub email: String,
    /// Current salted password hash.
    pub password_hash: String,
    /// Current role.
    pub role: String,
    /// Verification timestamp, when verified.
    pub email_verified_at: Option<String>,
    /// Creation timestamp.
    pub created_at: Option<String>,
    /// Management revision used to invalidate old sessions.
    pub updated_at: Option<String>,
    /// Whether this repository has the verification column.
    pub has_email_verified_at_column: bool,
    /// Whether this repository has the creation column.
    pub has_created_at_column: bool,
    /// Whether this repository has the revision column.
    pub has_updated_at_column: bool,
    /// Typed application claims used in row policies.
    pub claims: BTreeMap<String, Value>,
}

impl Account {
    /// Legacy schema capability check; NULL values are not missing columns.
    pub fn has_auth_management_schema(&self) -> bool {
        self.has_email_verified_at_column
            && self.has_created_at_column
            && self.has_updated_at_column
    }

    /// Existing session revision fingerprint.
    pub fn auth_state(&self) -> String {
        AccountState {
            id: self.id,
            email: &self.email,
            password_hash: &self.password_hash,
            role: &self.role,
            claims: &self.claims,
            email_verified_at: self.email_verified_at.as_deref(),
            created_at: self.created_at.as_deref(),
            updated_at: self.updated_at.as_deref(),
        }
        .fingerprint()
    }
}

/// Public account response. Password material and session fingerprints are absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Account ID.
    pub id: i64,
    /// Email address.
    pub email: String,
    /// Primary role.
    pub role: String,
    /// Roles in the existing public format.
    pub roles: Vec<String>,
    /// Whether email verification has completed.
    pub email_verified: bool,
    /// Verification timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified_at: Option<String>,
    /// Creation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Management revision timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Existing flattened application claims.
    #[serde(flatten)]
    pub claims: BTreeMap<String, Value>,
}

impl From<Account> for AccountInfo {
    fn from(account: Account) -> Self {
        Self {
            id: account.id,
            email: account.email,
            roles: vec![account.role.clone()],
            role: account.role,
            email_verified: account.email_verified_at.is_some(),
            email_verified_at: account.email_verified_at,
            created_at: account.created_at,
            updated_at: account.updated_at,
            claims: account.claims,
        }
    }
}

/// Account failures use stable public codes without database/key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountError {
    /// Existing shared auth/password failure.
    Auth(AuthFailure),
    /// Invalid input field and its stable public message.
    Validation(&'static str, &'static str),
    /// Email or password is not accepted.
    InvalidCredentials,
    /// Current password was not accepted for a password change.
    InvalidCurrentPassword,
    /// The authenticated account no longer exists.
    MissingAccount,
    /// A required email verification has not completed.
    UnverifiedEmail,
    /// Management migrations are missing.
    MissingSchema,
    /// Repository access failed.
    Database,
    /// The configured signer could not issue a token.
    TokenGeneration,
    /// Invalid TTL, subject or clock value.
    Configuration,
    /// A concurrent account update invalidated the password-change snapshot.
    ConcurrentChange,
}

impl AccountError {
    /// Render existing client error JSON, including field-specific validation.
    pub fn response(self) -> ResponseEnvelope {
        if let Self::Auth(error) = self {
            return error.response();
        }
        let (status, code, message, field) = match self {
            Self::Validation(field, message) => (400, "validation_error", message, Some(field)),
            Self::InvalidCredentials => (401, "invalid_credentials", "Invalid credentials", None),
            Self::InvalidCurrentPassword => (
                401,
                "invalid_credentials",
                "Current password is incorrect",
                None,
            ),
            Self::MissingAccount => (401, "invalid_token", "Authenticated user not found", None),
            Self::UnverifiedEmail => (
                403,
                "email_not_verified",
                "Email address must be verified before logging in",
                None,
            ),
            Self::MissingSchema => (
                500,
                "internal_error",
                "Built-in auth management schema is missing. Apply the built-in auth migration again to add email verification and password reset tables.",
                None,
            ),
            Self::Database => (500, "internal_error", "Database error", None),
            Self::TokenGeneration => (500, "internal_error", "Token generation failed", None),
            Self::Configuration => (
                500,
                "internal_error",
                "Invalid account service configuration",
                None,
            ),
            Self::ConcurrentChange => (
                409,
                "account_changed",
                "Account changed; retry with current credentials",
                None,
            ),
            Self::Auth(_) => unreachable!(),
        };
        let mut body = serde_json::json!({"code": code, "message": message});
        if let Some(field) = field {
            body["field"] = Value::from(field);
        }
        let mut response = ResponseEnvelope::json(body);
        response.status = status;
        response
    }
}

impl From<AuthFailure> for AccountError {
    fn from(error: AuthFailure) -> Self {
        Self::Auth(error)
    }
}

/// Driver-owned repository; all input queries must bind their parameters.
pub trait AccountRepository: Send + Sync + 'static {
    /// Find the account for normalized email.
    fn by_email(
        &self,
        email: &str,
    ) -> impl Future<Output = Result<Option<Account>, AccountError>> + Send;
    /// Read current account state, never a cached token snapshot.
    fn by_id(&self, id: i64) -> impl Future<Output = Result<Option<Account>, AccountError>> + Send;
    /// Atomically update only if ID, password hash and management revision still
    /// match `expected`. Return false on deletion or concurrent change. A failed
    /// operation must not change the stored password or revive old sessions.
    fn compare_and_set_password(
        &self,
        expected: &Account,
        password_hash: &str,
    ) -> impl Future<Output = Result<bool, AccountError>> + Send;
}

/// Configured signer adapter; the service supplies all token claims.
pub trait AccessTokenIssuer: Send + Sync + 'static {
    /// Sign using server-selected algorithm/key, never a client-selected key.
    fn issue(&self, claims: &AccessClaims) -> Result<String, AccountError>;
}

/// Account policy lowered from service configuration, with no parser types.
#[derive(Clone)]
pub struct AccountPolicy {
    /// Access-token issuer.
    pub issuer: Option<String>,
    /// Access-token audience.
    pub audience: Option<String>,
    /// Positive access-token lifetime in seconds.
    pub access_token_ttl_seconds: i64,
    /// Whether unverified email blocks login.
    pub require_email_verification: bool,
}

/// Login, account-read and password-change service shared by both transports.
pub struct AccountService<R, S, C = SystemClock> {
    repository: R,
    signer: S,
    policy: AccountPolicy,
    clock: C,
}

impl<R: AccountRepository, S: AccessTokenIssuer> AccountService<R, S> {
    /// Construct with the real clock. Reject unusable TTLs before serving.
    pub fn new(repository: R, signer: S, policy: AccountPolicy) -> Result<Self, AccountError> {
        Self::with_clock(repository, signer, policy, SystemClock)
    }
}

impl<R: AccountRepository, S: AccessTokenIssuer, C: Clock> AccountService<R, S, C> {
    /// Inject a clock for deterministic token lifetime tests.
    pub fn with_clock(
        repository: R,
        signer: S,
        policy: AccountPolicy,
        clock: C,
    ) -> Result<Self, AccountError> {
        if policy.access_token_ttl_seconds <= 0 {
            return Err(AccountError::Configuration);
        }
        Ok(Self {
            repository,
            signer,
            policy,
            clock,
        })
    }

    /// Verify credentials and issue a token bound to the current account state.
    /// HTTP callers must apply their login rate limit before invoking this method.
    pub async fn login(&self, email: &str, candidate: &str) -> Result<String, AccountError> {
        let email = normalize_email(email)?;
        if candidate.is_empty() || candidate.len() > 72 {
            return Err(AccountError::InvalidCredentials);
        }
        let account = self
            .repository
            .by_email(&email)
            .await?
            .ok_or(AccountError::InvalidCredentials)?;
        if !password::verify(candidate, &account.password_hash).await? {
            return Err(AccountError::InvalidCredentials);
        }
        if self.policy.require_email_verification && account.email_verified_at.is_none() {
            return Err(if account.has_auth_management_schema() {
                AccountError::UnverifiedEmail
            } else {
                AccountError::MissingSchema
            });
        }
        let now = self.clock.now_unix();
        if account.id <= 0 || now < 0 {
            return Err(AccountError::Configuration);
        }
        let expires = now
            .checked_add(self.policy.access_token_ttl_seconds)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(AccountError::Configuration)?;
        let claims = AccessClaims {
            auth_state: Some(account.auth_state()),
            sub: account.id,
            roles: vec![account.role],
            iss: self.policy.issuer.clone(),
            aud: self.policy.audience.clone(),
            exp: expires,
            extra: account.claims,
        };
        self.signer.issue(&claims)
    }

    /// Read only the account ID obtained from successful request authentication.
    pub async fn account(&self, authenticated_user_id: i64) -> Result<AccountInfo, AccountError> {
        if authenticated_user_id <= 0 {
            return Err(AccountError::MissingAccount);
        }
        self.repository
            .by_id(authenticated_user_id)
            .await?
            .map(Into::into)
            .ok_or(AccountError::MissingAccount)
    }

    /// Change the authenticated account's password after current-password proof.
    /// CAS prevents a concurrent reset/change/deletion from being overwritten.
    pub async fn change_password(
        &self,
        authenticated_user_id: i64,
        current: &str,
        new: &str,
    ) -> Result<(), AccountError> {
        validate_password(new)?;
        if authenticated_user_id <= 0 {
            return Err(AccountError::MissingAccount);
        }
        if current.is_empty() || current.len() > 72 {
            return Err(AccountError::InvalidCurrentPassword);
        }
        let account = self
            .repository
            .by_id(authenticated_user_id)
            .await?
            .ok_or(AccountError::MissingAccount)?;
        if !password::verify(current, &account.password_hash).await? {
            return Err(AccountError::InvalidCurrentPassword);
        }
        let hash = password::hash(new, 12).await?;
        if !self
            .repository
            .compare_and_set_password(&account, &hash)
            .await?
        {
            return Err(AccountError::ConcurrentChange);
        }
        Ok(())
    }
}

/// Existing email normalization policy shared with registration/admin facades.
pub fn normalize_email(raw: &str) -> Result<String, AccountError> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(AccountError::Validation(
            "email",
            "Email address cannot be empty",
        ));
    }
    if normalized.contains(char::is_whitespace) {
        return Err(AccountError::Validation(
            "email",
            "Email address cannot contain whitespace",
        ));
    }
    let mut parts = normalized.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if local.is_empty() || domain.is_empty() || parts.next().is_some() || !domain.contains('.') {
        return Err(AccountError::Validation(
            "email",
            "Email address is not valid",
        ));
    }
    Ok(normalized)
}

/// Preserve the existing registration/password-reset policy and bcrypt bound.
pub fn validate_password(password: &str) -> Result<(), AccountError> {
    if password.chars().count() < 8 {
        return Err(AccountError::Validation(
            "password",
            "Password must be at least 8 characters long",
        ));
    }
    if password.len() > 72 {
        return Err(AccountError::Validation(
            "password",
            "Password must be at most 72 bytes long",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "accounts_tests.rs"]
mod tests;
