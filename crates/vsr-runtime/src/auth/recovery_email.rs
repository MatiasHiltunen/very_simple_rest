//! Recovery email issuance shared by native, Actix and Axum handlers.
//!
//! Delivery occurs before commit to preserve the existing rollback semantics.
//! SMTP/HTTP acceptance is not atomic with the database commit: this is not a
//! durable outbox. Callers must provide abuse controls; response timing and
//! delivery failures can still disclose account existence.

use std::{future::Future, time::Duration};

use chrono::{DateTime, SecondsFormat};
use url::Url;
use vsr_core::clock::{Clock, SystemClock};

use super::{
    MailMessage, Mailer,
    accounts::{AccountError, normalize_email},
    recovery::{TokenPurpose, token_digest},
};

/// Sensitive one-time credential. Only its digest and expiry belong in storage.
/// Intentionally has no Debug or Serialize implementation.
pub struct RecoveryToken {
    raw: String,
    digest: String,
    expires_at: String,
}

impl RecoveryToken {
    /// Generate 256 bits of OS entropy, rejecting invalid clock/TTL arithmetic.
    pub fn generate(ttl_seconds: i64, clock: &impl Clock) -> Result<Self, AccountError> {
        Self::generate_with(ttl_seconds, clock, |bytes| {
            getrandom::fill(bytes).map_err(|_| AccountError::TokenGeneration)
        })
    }

    fn generate_with(
        ttl_seconds: i64,
        clock: &impl Clock,
        fill: impl FnOnce(&mut [u8]) -> Result<(), AccountError>,
    ) -> Result<Self, AccountError> {
        let now = clock.now_unix_micros();
        if ttl_seconds <= 0 || now < 0 {
            return Err(AccountError::Configuration);
        }
        let expiry = ttl_seconds
            .checked_mul(1_000_000)
            .and_then(|ttl| now.checked_add(ttl))
            .and_then(DateTime::from_timestamp_micros)
            .ok_or(AccountError::Configuration)?;
        let mut bytes = [0u8; 32];
        fill(&mut bytes)?;
        let raw = hex::encode(bytes);
        Ok(Self {
            digest: token_digest(&raw),
            raw,
            expires_at: expiry.to_rfc3339_opts(SecondsFormat::Micros, false),
        })
    }

    /// Raw credential for delivery only. Never log or persist this value.
    pub fn raw(&self) -> &str {
        &self.raw
    }
    /// SHA-256 digest compatible with the existing recovery schema.
    pub fn digest(&self) -> &str {
        &self.digest
    }
    /// RFC3339 expiry with microsecond precision.
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }
}

/// Account information required to issue an email-bound token.
pub struct RecoveryRecipient {
    /// Stable database identifier.
    pub id: i64,
    /// Current, trusted database email, not the submitted request address.
    pub email: String,
    /// Whether verification requests should be silently suppressed.
    pub verified: bool,
}

/// Transaction-owned token writer. Replacement MUST atomically invalidate the
/// previous tokens for this user/purpose and insert the digest bound to `email`.
/// Never persist `token.raw()`. Rollback on errors and cancellation is required.
pub trait RecoveryTokenStore: Send + Sync {
    /// Replace a user's tokens for one purpose inside the caller's transaction.
    fn replace(
        &self,
        user_id: i64,
        email: &str,
        purpose: TokenPurpose,
        token: &RecoveryToken,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;
}

/// Transaction for anonymous recovery requests. Adapters must serialize
/// concurrent issuance for the same account, including when no token exists.
pub trait RecoveryEmailTransaction: RecoveryTokenStore + Sized + 'static {
    /// Read and lock the account until commit/rollback; bind all query inputs.
    fn recipient(
        &self,
        email: &str,
    ) -> impl Future<Output = Result<Option<RecoveryRecipient>, AccountError>> + Send;
    /// Commit the replacement after delivery has been accepted.
    fn commit(self) -> impl Future<Output = Result<(), AccountError>> + Send;
    /// Roll back. Drop must also roll back if the request is cancelled.
    fn rollback(self) -> impl Future<Output = Result<(), AccountError>> + Send;
}

/// Driver adapter for transactional recovery email requests.
pub trait RecoveryEmailRepository: Send + Sync + 'static {
    /// Transaction with cancellation-safe rollback.
    type Transaction: RecoveryEmailTransaction;
    /// Begin an issuance transaction.
    fn begin(&self) -> impl Future<Output = Result<Self::Transaction, AccountError>> + Send;
}

/// Trusted application configuration, never populated from request Host headers.
pub struct RecoveryEmailPolicy {
    /// Configured sender mailbox.
    pub from: String,
    /// Absolute action endpoint, including the application scope prefix.
    pub action_url: String,
    /// Purpose associated with this endpoint.
    pub purpose: TokenPurpose,
    /// Positive token lifetime, in seconds.
    pub ttl_seconds: i64,
    /// Maximum wait for the mail provider while a transaction is held.
    pub delivery_timeout: Duration,
}

/// Shared templates, token generation and bounded mail delivery.
pub struct RecoveryEmailSender<M, C = SystemClock> {
    mailer: M,
    policy: RecoveryEmailPolicy,
    action_url: Url,
    clock: C,
}

impl<M: Mailer> RecoveryEmailSender<M> {
    /// Configure an issuer using the system clock.
    pub fn new(mailer: M, policy: RecoveryEmailPolicy) -> Result<Self, AccountError> {
        Self::with_clock(mailer, policy, SystemClock)
    }
}

impl<M: Mailer, C: Clock> RecoveryEmailSender<M, C> {
    /// Use an injected clock for deterministic validation.
    pub fn with_clock(
        mailer: M,
        policy: RecoveryEmailPolicy,
        clock: C,
    ) -> Result<Self, AccountError> {
        let action_url = Url::parse(&policy.action_url).map_err(|_| AccountError::Configuration)?;
        let loopback = match action_url.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(host)) => host == "localhost",
            None => false,
        };
        if !(action_url.scheme() == "https" || (action_url.scheme() == "http" && loopback))
            || action_url.host().is_none()
            || !action_url.username().is_empty()
            || action_url.password().is_some()
            || action_url.query().is_some()
            || action_url.fragment().is_some()
            || policy.from.trim().is_empty()
            || policy.from.contains(['\r', '\n'])
            || policy.ttl_seconds <= 0
            || policy.ttl_seconds.checked_mul(1_000_000).is_none()
            || policy.delivery_timeout.is_zero()
        {
            return Err(AccountError::Configuration);
        }
        Ok(Self {
            mailer,
            policy,
            action_url,
            clock,
        })
    }

    /// Configured token purpose, for services that require a verification sender.
    pub fn purpose(&self) -> TokenPurpose {
        self.policy.purpose
    }

    /// Issue and deliver inside an existing transaction (registration/admin).
    /// The caller MUST roll back on error or cancellation and commit on success.
    pub async fn send_in_transaction(
        &self,
        transaction: &impl RecoveryTokenStore,
        recipient: &RecoveryRecipient,
    ) -> Result<(), AccountError> {
        if recipient.id <= 0 || normalize_email(&recipient.email)? != recipient.email {
            return Err(AccountError::Configuration);
        }
        let token = RecoveryToken::generate(self.policy.ttl_seconds, &self.clock)?;
        let mut url = self.action_url.clone();
        url.query_pairs_mut().append_pair("token", token.raw());
        let message = recovery_message(
            &self.policy.from,
            &recipient.email,
            self.policy.purpose,
            url.as_str(),
        );
        transaction
            .replace(recipient.id, &recipient.email, self.policy.purpose, &token)
            .await?;
        tokio::time::timeout(self.policy.delivery_timeout, self.mailer.send(message))
            .await
            .map_err(|_| AccountError::EmailDelivery)?
            .map_err(|_| AccountError::EmailDelivery)
    }
}

/// Anonymous verification-resend and password-reset request policy.
pub struct RecoveryEmailService<R, M, C = SystemClock> {
    repository: R,
    sender: RecoveryEmailSender<M, C>,
}

impl<R: RecoveryEmailRepository, M: Mailer, C: Clock> RecoveryEmailService<R, M, C> {
    /// Compose the repository and configured sender.
    pub fn new(repository: R, sender: RecoveryEmailSender<M, C>) -> Self {
        Self { repository, sender }
    }

    /// Success is HTTP 202 with no account data, including absent and already
    /// verified accounts. This does not promise timing-equivalent responses.
    pub async fn request(&self, email: &str) -> Result<(), AccountError> {
        let email = normalize_email(email)?;
        let tx = self.repository.begin().await?;
        let result = async {
            let Some(recipient) = tx.recipient(&email).await? else {
                return Ok(false);
            };
            if recipient.verified && self.sender.policy.purpose == TokenPurpose::EmailVerification {
                return Ok(false);
            }
            self.sender.send_in_transaction(&tx, &recipient).await?;
            Ok(true)
        }
        .await;
        match result {
            Ok(true) => tx.commit().await,
            Ok(false) => tx.rollback().await,
            Err(error) => {
                tx.rollback().await?;
                Err(error)
            }
        }
    }
}

fn recovery_message(from: &str, email: &str, purpose: TokenPurpose, url: &str) -> MailMessage {
    let (heading, intro, text, notice) = match purpose {
        TokenPurpose::EmailVerification => (
            "Verify your email",
            "Open the link below to verify your email address.",
            "Verify your email address by opening this link:",
            "If you did not create this account, you can ignore this message.",
        ),
        TokenPurpose::PasswordReset => (
            "Reset your password",
            "Open the link below to choose a new password.",
            "Reset your password by opening this link:",
            "If you did not request a password reset, you can ignore this message.",
        ),
    };
    let escaped = url
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");
    MailMessage {
        from: from.to_owned(),
        to: email.to_owned(),
        subject: purpose.subject().to_owned(),
        text_body: format!("{text}\n\n{url}\n\n{notice}"),
        html_body: Some(format!(
            "<!doctype html><html><body><h1>{heading}</h1><p>{intro}</p><p><a href=\"{escaped}\">{escaped}</a></p><p>{notice}</p></body></html>"
        )),
    }
}

#[cfg(test)]
#[path = "recovery_email_tests.rs"]
mod tests;
