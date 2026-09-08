//! Single-use verification and password-reset consumption, without HTTP or SQL.

use super::{
    accounts::{AccountError, validate_password},
    password,
};
use crate::http::ResponseEnvelope;
use chrono::{DateTime, SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use std::future::Future;
use vsr_core::clock::{Clock, SystemClock};

/// Purpose is selected by the server's endpoint, never by a token request body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenPurpose {
    /// Prove access to an account's current email address.
    EmailVerification,
    /// Replace the account password using an emailed recovery credential.
    PasswordReset,
}

impl TokenPurpose {
    /// Existing storage discriminator.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmailVerification => "email_verification",
            Self::PasswordReset => "password_reset",
        }
    }

    /// Existing email subject used by the compatibility facade.
    pub fn subject(self) -> &'static str {
        match self {
            Self::EmailVerification => "Verify your email address",
            Self::PasswordReset => "Reset your password",
        }
    }
}

/// A trusted storage record. Never contains the raw emailed credential.
pub struct PendingToken {
    /// Token row identifier.
    pub id: i64,
    /// Account to which the credential was issued.
    pub user_id: i64,
    /// Address at issuance; absent bindings are invalid, not wildcard matches.
    pub requested_email: Option<String>,
    /// Existing RFC3339 expiry, preserving microsecond precision.
    pub expires_at: String,
}

/// Stable outcome shared by JSON routes and legacy HTML presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenActionOutcome {
    /// Account mutation and token consumption committed together.
    Applied,
    /// Missing, reused, wrong-purpose or incorrectly bound credential.
    Invalid,
    /// Expired or malformed stored expiration.
    Expired,
}

impl TokenActionOutcome {
    /// Existing HTTP status/code/message without duplicating policy per adapter.
    pub fn response(self, purpose: TokenPurpose) -> ResponseEnvelope {
        let (code, message) = match (self, purpose) {
            (Self::Invalid, TokenPurpose::EmailVerification) => {
                ("invalid_token", "Verification token is invalid")
            }
            (Self::Invalid, TokenPurpose::PasswordReset) => {
                ("invalid_token", "Password reset token is invalid")
            }
            (Self::Expired, TokenPurpose::EmailVerification) => {
                ("expired_token", "Verification token has expired")
            }
            (Self::Expired, TokenPurpose::PasswordReset) => {
                ("expired_token", "Password reset token has expired")
            }
            (Self::Applied, _) => return ResponseEnvelope::status(204),
        };
        let mut response =
            ResponseEnvelope::json(serde_json::json!({"code":code, "message":message}));
        response.status = 400;
        response
    }
}

/// Atomic storage unit. Dropping an unfinished transaction MUST roll back;
/// cancellation may happen at any await, including after claiming the token.
pub trait RecoveryTransaction: Send + Sync + 'static {
    /// Find an unused record by digest and server-selected purpose.
    fn pending(
        &self,
        digest: &str,
        purpose: TokenPurpose,
    ) -> impl Future<Output = Result<Option<PendingToken>, AccountError>> + Send;
    /// Atomically claim only an unused token; false means another request won.
    fn claim(
        &self,
        id: i64,
        used_at: &str,
    ) -> impl Future<Output = Result<bool, AccountError>> + Send;
    /// Mutate exactly the bound account, checking its current email atomically.
    /// False means deletion or an email mismatch. This must share the claim's
    /// transaction. Never report success when no account was updated.
    fn apply(
        &self,
        token: &PendingToken,
        purpose: TokenPurpose,
        hash: Option<&str>,
        changed_at: &str,
    ) -> impl Future<Output = Result<bool, AccountError>> + Send;
    /// Remove an invalid/expired credential without affecting sibling requests.
    fn delete(&self, id: i64) -> impl Future<Output = Result<(), AccountError>> + Send;
    /// Revoke all credentials of this purpose after a successful operation.
    fn delete_siblings(
        &self,
        user_id: i64,
        purpose: TokenPurpose,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;
    /// Commit all effects. A failure must never be reported as Applied.
    fn commit(self) -> impl Future<Output = Result<(), AccountError>> + Send;
    /// Undo all effects. A failure must not leave this transaction reusable.
    fn rollback(self) -> impl Future<Output = Result<(), AccountError>> + Send;
}

/// Starts a driver-owned atomic unit without introducing SQL into the service.
pub trait RecoveryRepository: Send + Sync + 'static {
    /// Transaction with rollback-on-drop semantics.
    type Transaction: RecoveryTransaction;
    /// Acquire a fresh transaction for one token operation.
    fn begin(&self) -> impl Future<Output = Result<Self::Transaction, AccountError>> + Send;
}

/// Verification/reset policy; email delivery and token issuance are separate.
pub struct RecoveryService<R, C = SystemClock> {
    repository: R,
    clock: C,
}

impl<R: RecoveryRepository> RecoveryService<R> {
    /// Construct using the real subsecond clock.
    pub fn new(repository: R) -> Self {
        Self::with_clock(repository, SystemClock)
    }
}

impl<R: RecoveryRepository, C: Clock> RecoveryService<R, C> {
    /// Inject time without changing storage or transport behavior.
    pub fn with_clock(repository: R, clock: C) -> Self {
        Self { repository, clock }
    }

    /// Verify the address bound to this credential.
    pub async fn verify_email(&self, raw: &str) -> Result<TokenActionOutcome, AccountError> {
        let raw = normalized_token(raw, TokenPurpose::EmailVerification)?;
        self.consume(raw, TokenPurpose::EmailVerification, None)
            .await
    }

    /// Validate and hash outside the transaction, then consume exactly once.
    /// HTTP adapters still own request limits/rate limiting and JSON extraction.
    pub async fn reset_password(
        &self,
        raw: &str,
        new: &str,
    ) -> Result<TokenActionOutcome, AccountError> {
        let raw = normalized_token(raw, TokenPurpose::PasswordReset)?;
        validate_password(new)?;
        let hash = password::hash(new, 12).await?;
        self.consume(raw, TokenPurpose::PasswordReset, Some(&hash))
            .await
    }

    /// Trusted infrastructure compatibility entry point for an already-hashed
    /// password. Never pass a client-supplied hash; HTTP routes use `reset_password`.
    pub async fn apply_password_reset_hash(
        &self,
        raw: &str,
        hash: &str,
    ) -> Result<TokenActionOutcome, AccountError> {
        let raw = normalized_token(raw, TokenPurpose::PasswordReset)?;
        self.consume(raw, TokenPurpose::PasswordReset, Some(hash))
            .await
    }

    async fn consume(
        &self,
        raw: &str,
        purpose: TokenPurpose,
        hash: Option<&str>,
    ) -> Result<TokenActionOutcome, AccountError> {
        let transaction = self.repository.begin().await?;
        match self
            .apply_in(&transaction, &token_digest(raw), purpose, hash)
            .await
        {
            Ok(outcome) => {
                transaction.commit().await?;
                Ok(outcome)
            }
            Err(error) => {
                transaction.rollback().await?;
                Err(error)
            }
        }
    }

    async fn apply_in(
        &self,
        transaction: &R::Transaction,
        digest: &str,
        purpose: TokenPurpose,
        hash: Option<&str>,
    ) -> Result<TokenActionOutcome, AccountError> {
        let Some(token) = transaction.pending(digest, purpose).await? else {
            return Ok(TokenActionOutcome::Invalid);
        };
        let now = self.clock.now_unix_micros();
        let Some(instant) = DateTime::<Utc>::from_timestamp_micros(now).filter(|_| now >= 0) else {
            return Err(AccountError::Configuration);
        };
        let expires = DateTime::parse_from_rfc3339(&token.expires_at).ok();
        if expires.is_none_or(|expiry| expiry <= instant) {
            transaction.delete(token.id).await?;
            return Ok(TokenActionOutcome::Expired);
        }
        if token.id <= 0
            || token.user_id <= 0
            || token.requested_email.as_deref().is_none_or(str::is_empty)
        {
            transaction.delete(token.id).await?;
            return Ok(TokenActionOutcome::Invalid);
        }
        let changed_at = instant.to_rfc3339_opts(SecondsFormat::Micros, false);
        if !transaction.claim(token.id, &changed_at).await? {
            return Ok(TokenActionOutcome::Invalid);
        }
        // The claim can wait behind another transaction. Do not apply a token
        // that expired while waiting, even if it was valid at the initial read.
        if expires.is_none_or(|expiry| expiry.timestamp_micros() <= self.clock.now_unix_micros()) {
            transaction.delete(token.id).await?;
            return Ok(TokenActionOutcome::Expired);
        }
        if !transaction
            .apply(&token, purpose, hash, &changed_at)
            .await?
        {
            transaction.delete(token.id).await?;
            return Ok(TokenActionOutcome::Invalid);
        }
        transaction.delete_siblings(token.user_id, purpose).await?;
        Ok(TokenActionOutcome::Applied)
    }
}

fn normalized_token(raw: &str, purpose: TokenPurpose) -> Result<&str, AccountError> {
    let token = raw.trim();
    if token.is_empty() {
        return Err(AccountError::Validation(
            "token",
            match purpose {
                TokenPurpose::EmailVerification => "Verification token cannot be empty",
                TokenPurpose::PasswordReset => "Reset token cannot be empty",
            },
        ));
    }
    Ok(token)
}

/// Existing SHA-256 storage format. Raw recovery credentials never reach queries.
pub fn token_digest(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
