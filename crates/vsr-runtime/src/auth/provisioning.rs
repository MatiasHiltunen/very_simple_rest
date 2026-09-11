//! Admin creation/invitations and authenticated verification resend.
//!
//! Identity comes from the trusted authentication wrapper, never request JSON.
//! Account locks and commit/rollback sequencing are shared with management.
//! Email acceptance precedes commit for compatibility; this is not an outbox.

use super::{
    AuthenticatedIdentity, Mailer,
    accounts::{Account, AccountError, AccountInfo, normalize_email, validate_password},
    management::{
        ManagementError, ManagementRepository, ManagementTransaction, administrator_id,
        authenticated_account_id, authorized_accounts, finish, next_revision,
    },
    password,
    recovery::TokenPurpose,
    recovery_email::{RecoveryEmailSender, RecoveryRecipient, RecoveryTokenStore},
};
use crate::http::ResponseEnvelope;
use serde::{Deserialize, Serialize};
use std::{fmt, future::Future};
use vsr_core::clock::{Clock, SystemClock};

/// Existing admin-create JSON contract. IDs, hashes and application claims are
/// not accepted; configured database defaults provide initial custom claims.
#[derive(Serialize, Deserialize)]
pub struct CreateManagedUserInput {
    /// New account email, normalized by the service.
    pub email: String,
    /// Initial password, hashed in the shared bounded worker pool.
    pub password: String,
    /// Admin-selected role, defaulting to `user` when omitted or blank.
    #[serde(default)]
    pub role: Option<String>,
    /// Explicitly mark the new account verified; defaults to false.
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// Deliver a verification invitation; defaults to false.
    #[serde(default)]
    pub send_verification_email: Option<bool>,
}

impl fmt::Debug for CreateManagedUserInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateManagedUserInput")
            .field("email", &self.email)
            .field("password", &"[redacted]")
            .field("role", &self.role)
            .field("email_verified", &self.email_verified)
            .field("send_verification_email", &self.send_verification_email)
            .finish()
    }
}

/// Management transaction with the additional creation and token-write capability.
/// All writes and the resulting account snapshot must use that same transaction.
pub trait ProvisioningTransaction: ManagementTransaction + RecoveryTokenStore {
    /// Insert with full management timestamps and explicit verification state.
    /// Enforce email uniqueness in storage and return the initialized account.
    fn create(
        &self,
        email: &str,
        password_hash: &str,
        role: &str,
        timestamp: &str,
        verified: bool,
    ) -> impl Future<Output = Result<Account, ManagementError>> + Send;
}

/// Authenticated resend response, preserving the existing empty 202/204 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationDelivery {
    /// Verification mail was accepted and its token transaction committed.
    Sent,
    /// The locked account was already verified; no mail or token was written.
    AlreadyVerified,
}
impl VerificationDelivery {
    /// Render the existing empty response without exposing account information.
    pub fn response(self) -> ResponseEnvelope {
        ResponseEnvelope::status(match self {
            Self::Sent => 202,
            Self::AlreadyVerified => 204,
        })
    }
}

/// Shared account provisioning and authenticated verification-email policy.
pub struct ProvisioningService<R, M, C = SystemClock> {
    repository: R,
    verification: Option<RecoveryEmailSender<M, C>>,
    clock: C,
}
impl<R, M> ProvisioningService<R, M>
where
    R: ManagementRepository,
    R::Transaction: ProvisioningTransaction,
    M: Mailer,
{
    /// Configure optional verification delivery. Creation without email remains
    /// available when no sender is installed; invitation/resend fails with 503.
    pub fn new(
        repository: R,
        verification: Option<RecoveryEmailSender<M>>,
    ) -> Result<Self, ManagementError> {
        Self::with_clock(repository, verification, SystemClock)
    }
}
impl<R, M, C> ProvisioningService<R, M, C>
where
    R: ManagementRepository,
    R::Transaction: ProvisioningTransaction,
    M: Mailer,
    C: Clock,
{
    /// Inject a clock for deterministic account timestamps.
    pub fn with_clock(
        repository: R,
        verification: Option<RecoveryEmailSender<M, C>>,
        clock: C,
    ) -> Result<Self, ManagementError> {
        if verification
            .as_ref()
            .is_some_and(|sender| sender.purpose() != TokenPurpose::EmailVerification)
        {
            return Err(AccountError::Configuration.into());
        }
        Ok(Self {
            repository,
            verification,
            clock,
        })
    }

    /// Create an account after live global-admin authorization. Password hashing
    /// precedes the transaction; the actor is rechecked under lock afterward.
    pub async fn create(
        &self,
        actor: &AuthenticatedIdentity,
        input: &CreateManagedUserInput,
    ) -> Result<AccountInfo, ManagementError> {
        let actor_id = administrator_id(actor)?;
        let email = normalize_email(&input.email)?;
        validate_password(&input.password)?;
        let role = input
            .role
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("user");
        if role.chars().any(char::is_whitespace) {
            return Err(AccountError::Validation("role", "Role cannot contain whitespace").into());
        }
        let verified = input.email_verified.unwrap_or(false);
        let invite = input.send_verification_email.unwrap_or(false);
        if verified && invite {
            return Err(ManagementError::InvalidInviteState);
        }
        if invite && self.verification.is_none() {
            return Err(AccountError::EmailUnavailable.into());
        }
        let timestamp = next_revision(self.clock.now_unix_micros(), None)?;
        let hash = password::hash(&input.password, 12)
            .await
            .map_err(AccountError::from)?;
        self.create_hashed(actor_id, input, &email, &hash, role, &timestamp)
            .await
    }

    async fn create_hashed(
        &self,
        actor: i64,
        input: &CreateManagedUserInput,
        email: &str,
        hash: &str,
        role: &str,
        timestamp: &str,
    ) -> Result<AccountInfo, ManagementError> {
        let verified = input.email_verified.unwrap_or(false);
        let invite = input.send_verification_email.unwrap_or(false);
        let tx = self.repository.begin().await?;
        let result = async {
            let administrator = authorized_accounts(&tx, actor, Some(actor))
                .await?
                .ok_or(AccountError::MissingAccount)?;
            if !administrator.has_auth_management_schema() {
                return Err(AccountError::MissingSchema.into());
            }
            let account = tx.create(email, hash, role, timestamp, verified).await?;
            if !account.has_auth_management_schema() {
                return Err(AccountError::MissingSchema.into());
            }
            if account.id <= 0
                || account.id == actor
                || account.email != email
                || account.role != role
                || account.created_at.as_deref() != Some(timestamp)
                || account.updated_at.as_deref() != Some(timestamp)
                || account.email_verified_at.as_deref() != verified.then_some(timestamp)
            {
                return Err(AccountError::Database.into());
            }
            if invite {
                self.verification
                    .as_ref()
                    .ok_or(AccountError::EmailUnavailable)?
                    .send_in_transaction(&tx, &recipient(&account))
                    .await?;
            }
            Ok(account.into())
        }
        .await;
        finish(tx, result).await
    }

    /// Resend only for the authenticated account; no target ID is accepted.
    pub async fn resend_account(
        &self,
        actor: &AuthenticatedIdentity,
    ) -> Result<VerificationDelivery, ManagementError> {
        let id = authenticated_account_id(actor)?;
        self.resend(id, None).await
    }

    /// Resend for a target account after the locked actor is confirmed as admin.
    pub async fn resend_managed(
        &self,
        actor: &AuthenticatedIdentity,
        id: i64,
    ) -> Result<VerificationDelivery, ManagementError> {
        let actor_id = administrator_id(actor)?;
        self.resend(actor_id, Some(id)).await
    }

    async fn resend(
        &self,
        actor: i64,
        target: Option<i64>,
    ) -> Result<VerificationDelivery, ManagementError> {
        let sender = self
            .verification
            .as_ref()
            .ok_or(AccountError::EmailUnavailable)?;
        let tx = self.repository.begin().await?;
        let result = async {
            let account = if let Some(id) = target {
                authorized_accounts(&tx, actor, Some(id))
                    .await?
                    .ok_or(ManagementError::NotFound)?
            } else {
                tx.lock_accounts(&[actor])
                    .await?
                    .into_iter()
                    .find(|account| account.id == actor)
                    .ok_or(AccountError::MissingAccount)?
            };
            if !account.has_auth_management_schema() {
                return Err(AccountError::MissingSchema.into());
            }
            if account.email_verified_at.is_some() {
                return Ok(VerificationDelivery::AlreadyVerified);
            }
            sender
                .send_in_transaction(&tx, &recipient(&account))
                .await?;
            Ok(VerificationDelivery::Sent)
        }
        .await;
        finish(tx, result).await
    }
}

fn recipient(account: &Account) -> RecoveryRecipient {
    RecoveryRecipient {
        id: account.id,
        email: account.email.clone(),
        verified: account.email_verified_at.is_some(),
    }
}

#[cfg(test)]
#[path = "provisioning_tests.rs"]
mod tests;
