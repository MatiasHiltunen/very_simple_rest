//! SQL infrastructure for framework-neutral recovery operations.

use super::{AuthDbBackend, helpers::is_missing_auth_management_schema};
use crate::db::{DbPool, DbTransaction, query};
pub(crate) use vsr_runtime::auth::recovery::TokenActionOutcome;
use vsr_runtime::auth::{
    accounts::AccountError,
    recovery::{
        PendingToken, RecoveryRepository, RecoveryService, RecoveryTransaction, TokenPurpose,
    },
};

struct Repository(DbPool);
struct Transaction {
    db: DbTransaction,
    backend: AuthDbBackend,
}

fn database_error(error: sqlx::Error) -> AccountError {
    if is_missing_auth_management_schema(&error) {
        AccountError::MissingSchema
    } else {
        AccountError::Database
    }
}

impl RecoveryRepository for Repository {
    type Transaction = Transaction;
    async fn begin(&self) -> Result<Transaction, AccountError> {
        let backend = super::db_ops::detect_auth_backend(&self.0)
            .await
            .map_err(database_error)?;
        Ok(Transaction {
            db: if backend == AuthDbBackend::Sqlite {
                self.0.begin_immediate().await
            } else {
                self.0.begin().await
            }
            .map_err(database_error)?,
            backend,
        })
    }
}

impl RecoveryTransaction for Transaction {
    async fn pending(
        &self,
        digest: &str,
        purpose: TokenPurpose,
    ) -> Result<Option<PendingToken>, AccountError> {
        super::db_ops::load_pending_auth_token_by_digest(&self.db, digest, purpose)
            .await
            .map_err(database_error)
    }
    async fn claim(&self, id: i64, used_at: &str) -> Result<bool, AccountError> {
        super::db_ops::mark_auth_token_used(&self.db, id, used_at)
            .await
            .map_err(database_error)
    }
    async fn apply(
        &self,
        token: &PendingToken,
        purpose: TokenPurpose,
        hash: Option<&str>,
        changed_at: &str,
    ) -> Result<bool, AccountError> {
        let table = super::migrations::auth_user_table_ident(self.backend);
        let Some(email) = token.requested_email.as_deref() else {
            return Ok(false);
        };
        let result = match purpose {
            TokenPurpose::EmailVerification => query(&format!("UPDATE {table} SET email_verified_at = ?, updated_at = ? WHERE id = ? AND email = ?"))
                .bind(changed_at).bind(changed_at).bind(token.user_id).bind(email).execute(&self.db).await,
            TokenPurpose::PasswordReset => query(&format!("UPDATE {table} SET password_hash = ?, updated_at = ? WHERE id = ? AND email = ?"))
                .bind(hash.ok_or(AccountError::Configuration)?).bind(changed_at).bind(token.user_id).bind(email).execute(&self.db).await,
        }.map_err(database_error)?;
        Ok(result.rows_affected() == 1)
    }
    async fn delete(&self, id: i64) -> Result<(), AccountError> {
        super::db_ops::delete_auth_token_by_id(&self.db, id)
            .await
            .map_err(database_error)
    }
    async fn delete_siblings(
        &self,
        user_id: i64,
        purpose: TokenPurpose,
    ) -> Result<(), AccountError> {
        super::db_ops::delete_auth_tokens_for_user_purpose(&self.db, user_id, purpose)
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

/// Shared verification/password-reset policy with the existing SQLx/Turso adapter.
/// HTTP adapters still own JSON extraction, rate limiting and HTML presentation.
pub fn builtin_recovery_service(db: DbPool) -> RecoveryService<impl RecoveryRepository> {
    RecoveryService::new(Repository(db))
}

pub(crate) async fn apply_email_verification_token(
    db: &DbPool,
    raw: &str,
) -> Result<TokenActionOutcome, AccountError> {
    builtin_recovery_service(db.clone()).verify_email(raw).await
}

#[cfg(test)]
pub(crate) async fn apply_password_reset_token(
    db: &DbPool,
    raw: &str,
    hash: &str,
) -> Result<TokenActionOutcome, AccountError> {
    builtin_recovery_service(db.clone())
        .apply_password_reset_hash(raw, hash)
        .await
}

#[cfg(all(test, feature = "sqlite"))]
#[path = "recovery_tests.rs"]
mod tests;
