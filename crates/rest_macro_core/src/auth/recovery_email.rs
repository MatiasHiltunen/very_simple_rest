//! SQL and configured-provider bridges for shared recovery email policy.

use std::time::Duration;

use sqlx::Row;
use vsr_runtime::auth::{
    MailMessage, Mailer,
    accounts::AccountError,
    recovery::TokenPurpose,
    recovery_email::{
        RecoveryEmailPolicy, RecoveryEmailRepository, RecoveryEmailSender, RecoveryEmailService,
        RecoveryEmailTransaction, RecoveryRecipient, RecoveryToken, RecoveryTokenStore,
    },
};

use super::{AuthDbBackend, AuthEmailSettings, AuthSettings};
use crate::db::{DbExecutor, DbPool, DbTransaction, query};

pub(super) fn database_error(error: sqlx::Error) -> AccountError {
    if super::helpers::is_missing_auth_management_schema(&error) {
        AccountError::MissingSchema
    } else {
        AccountError::Database
    }
}

pub(super) struct TokenStore<'a, E: ?Sized>(pub &'a E);

impl<E: DbExecutor + Sync + ?Sized> RecoveryTokenStore for TokenStore<'_, E> {
    async fn replace(
        &self,
        id: i64,
        email: &str,
        purpose: TokenPurpose,
        token: &RecoveryToken,
    ) -> Result<(), AccountError> {
        super::db_ops::replace_auth_token(self.0, id, purpose, Some(email), token)
            .await
            .map_err(database_error)
    }
}

struct Repository(DbPool);
struct Transaction {
    db: DbTransaction,
    backend: AuthDbBackend,
}

impl RecoveryEmailRepository for Repository {
    type Transaction = Transaction;
    async fn begin(&self) -> Result<Transaction, AccountError> {
        let backend = super::db_ops::detect_auth_backend(&self.0)
            .await
            .map_err(database_error)?;
        let db = if backend == AuthDbBackend::Sqlite {
            self.0.begin_immediate().await
        } else {
            self.0.begin().await
        }
        .map_err(database_error)?;
        Ok(Transaction { db, backend })
    }
}

impl RecoveryTokenStore for Transaction {
    async fn replace(
        &self,
        id: i64,
        email: &str,
        purpose: TokenPurpose,
        token: &RecoveryToken,
    ) -> Result<(), AccountError> {
        TokenStore(&self.db)
            .replace(id, email, purpose, token)
            .await
    }
}

impl RecoveryEmailTransaction for Transaction {
    async fn recipient(&self, email: &str) -> Result<Option<RecoveryRecipient>, AccountError> {
        let table = super::migrations::auth_user_table_ident(self.backend);
        // Lock the account, not the token row: the first issuance has no token.
        let lock = if self.backend == AuthDbBackend::Sqlite {
            ""
        } else {
            " FOR UPDATE"
        };
        let row = query(&format!(
            "SELECT id, email, email_verified_at FROM {table} WHERE email = ?{lock}"
        ))
        .bind(email)
        .fetch_optional(&self.db)
        .await
        .map_err(database_error)?;
        row.map(|row| {
            Ok(RecoveryRecipient {
                id: row.try_get("id")?,
                email: row.try_get("email")?,
                verified: row
                    .try_get::<Option<String>, _>("email_verified_at")?
                    .is_some(),
            })
        })
        .transpose()
        .map_err(database_error)
    }
    async fn commit(self) -> Result<(), AccountError> {
        self.db.commit().await.map_err(database_error)
    }
    async fn rollback(self) -> Result<(), AccountError> {
        self.db.rollback().await.map_err(database_error)
    }
}

pub(super) struct ProviderMailer(AuthEmailSettings);

impl Mailer for ProviderMailer {
    async fn send(&self, message: MailMessage) -> vsr_core::error::VsrResult<()> {
        crate::email::send_auth_email(
            &self.0,
            &crate::email::AuthEmailMessage {
                to_email: message.to,
                to_name: None,
                subject: message.subject,
                text_body: message.text_body,
                html_body: message.html_body.unwrap_or_default(),
            },
        )
        .await
        .map_err(|_| {
            vsr_core::error::VsrError::Other("Authentication email delivery failed".into())
        })
    }
}

pub(super) fn sender(
    settings: &AuthSettings,
    action_url: &str,
    purpose: TokenPurpose,
) -> Result<RecoveryEmailSender<ProviderMailer>, AccountError> {
    let email = settings
        .email
        .as_ref()
        .ok_or(AccountError::EmailUnavailable)?;
    RecoveryEmailSender::new(
        ProviderMailer(email.clone()),
        RecoveryEmailPolicy {
            from: crate::email::format_mailbox(email.from_name.as_deref(), &email.from_email),
            action_url: action_url.to_owned(),
            purpose,
            ttl_seconds: match purpose {
                TokenPurpose::EmailVerification => settings.verification_token_ttl_seconds,
                TokenPurpose::PasswordReset => settings.password_reset_token_ttl_seconds,
            },
            delivery_timeout: Duration::from_secs(30),
        },
    )
}

/// Shared anonymous recovery requests using the existing database and providers.
/// `action_url` MUST be a trusted configured endpoint, never a request Host value.
/// HTTP adapters still own extraction, abuse controls and 202/error responses.
/// This temporary infrastructure facade still links Actix.
pub fn builtin_recovery_email_service(
    db: DbPool,
    settings: &AuthSettings,
    action_url: &str,
    purpose: TokenPurpose,
) -> Result<RecoveryEmailService<impl RecoveryEmailRepository, impl Mailer>, AccountError> {
    Ok(RecoveryEmailService::new(
        Repository(db),
        sender(settings, action_url, purpose)?,
    ))
}

#[cfg(all(test, feature = "sqlite"))]
#[path = "recovery_email_tests.rs"]
mod tests;
