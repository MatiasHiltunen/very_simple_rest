//! SQL/configuration bridge for runtime-owned self-registration.

use vsr_runtime::auth::{
    Mailer,
    accounts::{Account, AccountError},
    recovery::TokenPurpose,
    recovery_email::{RecoveryToken, RecoveryTokenStore},
    registration::{RegistrationRepository, RegistrationService, RegistrationTransaction},
};

use super::{AuthDbBackend, AuthSettings, recovery_email::database_error};
use crate::db::{DbPool, DbTransaction, query};

struct Repository {
    db: DbPool,
    settings: AuthSettings,
}

struct Transaction {
    db: DbTransaction,
    backend: AuthDbBackend,
    settings: AuthSettings,
}

impl RegistrationRepository for Repository {
    type Transaction = Transaction;

    async fn begin(&self) -> Result<Transaction, AccountError> {
        let backend = super::db_ops::detect_auth_backend(&self.db)
            .await
            .map_err(database_error)?;
        let db = if backend == AuthDbBackend::Sqlite {
            self.db.begin_immediate().await
        } else {
            self.db.begin().await
        }
        .map_err(database_error)?;
        Ok(Transaction {
            db,
            backend,
            settings: self.settings.clone(),
        })
    }
}

impl RecoveryTokenStore for Transaction {
    async fn replace(
        &self,
        user_id: i64,
        email: &str,
        purpose: TokenPurpose,
        token: &RecoveryToken,
    ) -> Result<(), AccountError> {
        super::recovery_email::TokenStore(&self.db)
            .replace(user_id, email, purpose, token)
            .await
    }
}

impl RegistrationTransaction for Transaction {
    async fn create(&self, email: &str, hash: &str, role: &str) -> Result<Account, AccountError> {
        query(&format!(
            "INSERT INTO {} (email, password_hash, role) VALUES (?, ?, ?)",
            super::auth_user_table_ident(self.backend),
        ))
        .bind(email)
        .bind(hash)
        .bind(role)
        .execute(&self.db)
        .await
        .map_err(|error| {
            if super::helpers::is_unique_violation(&error) {
                AccountError::DuplicateEmail
            } else {
                database_error(error)
            }
        })?;
        super::db_ops::load_authenticated_user_by_email_with_settings_for_backend(
            &self.db,
            self.backend,
            email,
            &self.settings,
        )
        .await
        .map_err(database_error)?
        .ok_or(AccountError::Database)
    }

    async fn initialize(&self, id: i64, timestamp: &str) -> Result<(), AccountError> {
        super::db_ops::initialize_user_management_timestamps(&self.db, self.backend, id, timestamp)
            .await
            .map_err(database_error)
    }

    async fn mark_verified(&self, id: i64, timestamp: &str) -> Result<(), AccountError> {
        super::db_ops::mark_user_email_verified(&self.db, self.backend, id, timestamp)
            .await
            .map_err(database_error)
    }

    async fn commit(self) -> Result<(), AccountError> {
        self.db.commit().await.map_err(database_error)
    }

    async fn rollback(self) -> Result<(), AccountError> {
        self.db.rollback().await.map_err(database_error)
    }
}

/// Compose self-registration with the existing SQL drivers and email providers.
/// `verification_url` must be a trusted configured endpoint when email is enabled.
/// This bridge still links Actix; the registration service itself does not.
pub fn builtin_registration_service(
    db: DbPool,
    settings: &AuthSettings,
    verification_url: Option<&str>,
) -> Result<RegistrationService<impl RegistrationRepository, impl Mailer>, AccountError> {
    let verification = if settings.email.is_some() {
        Some(super::recovery_email::sender(
            settings,
            verification_url.ok_or(AccountError::Configuration)?,
            TokenPurpose::EmailVerification,
        )?)
    } else {
        None
    };
    RegistrationService::new(
        Repository {
            db,
            settings: settings.clone(),
        },
        verification,
        settings.require_email_verification,
    )
}

#[cfg(all(test, feature = "sqlite"))]
#[path = "registration_tests.rs"]
mod tests;
