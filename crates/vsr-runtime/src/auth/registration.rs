//! Transactional self-registration shared by native, Actix and Axum handlers.
//!
//! Callers own registration exposure, request limits and abuse controls. Client
//! input can select neither roles nor application claims. Mail is accepted before
//! commit for legacy rollback compatibility; this is not durable outbox delivery.

use std::future::Future;

use chrono::{DateTime, SecondsFormat};
use vsr_core::clock::{Clock, SystemClock};

use super::{
    Mailer,
    accounts::{Account, AccountError, normalize_email, validate_password},
    password,
    recovery::TokenPurpose,
    recovery_email::{RecoveryEmailSender, RecoveryRecipient, RecoveryTokenStore},
};

/// A driver-owned registration transaction. Every write must use this same
/// transaction; dropping it, including during cancellation, must roll it back.
pub trait RegistrationTransaction: RecoveryTokenStore + Sized + 'static {
    /// Insert a bound account and read it back with configured claim mappings.
    /// Uniqueness must be enforced by the database, not a pre-insert lookup.
    fn create(
        &self,
        email: &str,
        password_hash: &str,
        role: &str,
    ) -> impl Future<Output = Result<Account, AccountError>> + Send;
    /// Initialize management timestamps without overwriting existing values.
    fn initialize(
        &self,
        user_id: i64,
        timestamp: &str,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;
    /// Set verification and revision timestamps for installations without email.
    fn mark_verified(
        &self,
        user_id: i64,
        timestamp: &str,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;
    /// Commit only after account initialization and any email delivery succeed.
    fn commit(self) -> impl Future<Output = Result<(), AccountError>> + Send;
    /// Explicit rollback on errors. Drop must also roll back an unfinished call.
    fn rollback(self) -> impl Future<Output = Result<(), AccountError>> + Send;
}

/// Storage adapter for the complete account-creation transaction.
pub trait RegistrationRepository: Send + Sync + 'static {
    /// Transaction with cancellation-safe rollback.
    type Transaction: RegistrationTransaction;
    /// Begin a transaction after validation and bounded password hashing.
    fn begin(&self) -> impl Future<Output = Result<Self::Transaction, AccountError>> + Send;
}

/// Self-registration policy and transaction sequencing, with no HTTP/SQL types.
pub struct RegistrationService<R, M, C = SystemClock> {
    repository: R,
    verification: Option<RecoveryEmailSender<M, C>>,
    clock: C,
}

impl<R: RegistrationRepository, M: Mailer> RegistrationService<R, M> {
    /// Configure registration. A required verification may never fall back to
    /// automatic verification when email delivery is absent.
    pub fn new(
        repository: R,
        verification: Option<RecoveryEmailSender<M>>,
        require_email_verification: bool,
    ) -> Result<Self, AccountError> {
        Self::with_clock(
            repository,
            verification,
            require_email_verification,
            SystemClock,
        )
    }
}

impl<R: RegistrationRepository, M: Mailer, C: Clock> RegistrationService<R, M, C> {
    /// Inject a clock for deterministic management timestamps.
    pub fn with_clock(
        repository: R,
        verification: Option<RecoveryEmailSender<M, C>>,
        require_email_verification: bool,
        clock: C,
    ) -> Result<Self, AccountError> {
        if (require_email_verification && verification.is_none())
            || verification
                .as_ref()
                .is_some_and(|sender| sender.purpose() != TokenPurpose::EmailVerification)
        {
            return Err(AccountError::Configuration);
        }
        Ok(Self {
            repository,
            verification,
            clock,
        })
    }

    /// Create a normal user. Success maps to the existing empty HTTP 201 response.
    /// A duplicate retains the existing 409 contract, not enumeration resistance.
    pub async fn register(&self, email: &str, candidate: &str) -> Result<(), AccountError> {
        let email = normalize_email(email)?;
        validate_password(candidate)?;
        let now = self.clock.now_unix_micros();
        let instant = DateTime::from_timestamp_micros(now)
            .filter(|_| now >= 0)
            .ok_or(AccountError::Configuration)?;
        let timestamp = instant.to_rfc3339_opts(SecondsFormat::Micros, false);
        let hash = password::hash(candidate, 12).await?;
        self.register_hashed(&email, &hash, &timestamp).await
    }

    async fn register_hashed(
        &self,
        email: &str,
        hash: &str,
        timestamp: &str,
    ) -> Result<(), AccountError> {
        let tx = self.repository.begin().await?;
        let result = async {
            let account = tx.create(email, hash, "user").await?;
            if account.id <= 0 || account.email != email || account.role != "user" {
                return Err(AccountError::Database);
            }
            let managed = account.has_auth_management_schema();
            if !managed
                && (self.verification.is_some()
                    || account.has_email_verified_at_column
                    || account.has_created_at_column
                    || account.has_updated_at_column)
            {
                return Err(AccountError::MissingSchema);
            }
            if managed {
                tx.initialize(account.id, timestamp).await?;
            }
            if let Some(sender) = &self.verification {
                sender
                    .send_in_transaction(
                        &tx,
                        &RecoveryRecipient {
                            id: account.id,
                            email: account.email,
                            verified: account.email_verified_at.is_some(),
                        },
                    )
                    .await?;
            } else if managed {
                tx.mark_verified(account.id, timestamp).await?;
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => tx.commit().await,
            Err(error) => {
                tx.rollback().await?;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod tests;
