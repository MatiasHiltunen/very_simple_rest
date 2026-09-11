//! Temporary SQL/configuration bridge for framework-neutral admin operations.

use super::{AuthClaimType, AuthDbBackend, AuthSettings, db_ops, recovery_email::database_error};
use crate::db::{DbPool, DbTransaction, query};
use std::collections::{BTreeMap, HashSet};
use vsr_runtime::auth::{
    Mailer,
    accounts::{Account, AccountError, AccountInfo},
    management::{
        ManagedClaim, ManagedClaimType, ManagementError, ManagementRepository, ManagementService,
        ManagementTransaction, UpdateManagedUserInput,
    },
    provisioning::{ProvisioningService, ProvisioningTransaction},
    recovery::TokenPurpose,
    recovery_email::{RecoveryToken, RecoveryTokenStore},
};

struct Repository {
    db: DbPool,
    settings: AuthSettings,
}
struct Transaction {
    db: DbTransaction,
    backend: AuthDbBackend,
    settings: AuthSettings,
}

fn storage_error(error: sqlx::Error) -> ManagementError {
    database_error(error).into()
}

fn validate_mappings(settings: &AuthSettings) -> Result<(), ManagementError> {
    let mut columns = HashSet::new();
    for (name, mapping) in &settings.claims {
        let reserved = |name: &str| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "id" | "email"
                    | "password_hash"
                    | "role"
                    | "roles"
                    | "email_verified"
                    | "email_verified_at"
                    | "created_at"
                    | "updated_at"
                    | "sub"
                    | "iss"
                    | "aud"
                    | "exp"
                    | "_vsr_auth_state"
            )
        };
        if reserved(name)
            || reserved(&mapping.column)
            || !columns.insert(mapping.column.to_ascii_lowercase())
        {
            return Err(AccountError::Configuration.into());
        }
    }
    Ok(())
}

impl ManagementRepository for Repository {
    type Transaction = Transaction;
    async fn begin(&self) -> Result<Transaction, ManagementError> {
        validate_mappings(&self.settings)?;
        let backend = db_ops::detect_auth_backend(&self.db)
            .await
            .map_err(storage_error)?;
        let db = if backend == AuthDbBackend::Sqlite {
            self.db.begin_immediate().await
        } else {
            self.db.begin().await
        }
        .map_err(storage_error)?;
        Ok(Transaction {
            db,
            backend,
            settings: self.settings.clone(),
        })
    }
}

impl ManagementTransaction for Transaction {
    async fn lock_accounts(&self, ids: &[i64]) -> Result<Vec<Account>, ManagementError> {
        let mut accounts = Vec::new();
        let suffix = if self.backend == AuthDbBackend::Sqlite {
            ""
        } else {
            " FOR UPDATE"
        };
        // The service supplies sorted, deduplicated IDs, including the actor.
        // Read the locked row itself: no earlier MySQL snapshot may authorize it.
        for id in ids {
            let row = query(&format!(
                "SELECT * FROM {} WHERE id = ?{suffix}",
                super::auth_user_table_ident(self.backend)
            ))
            .bind(*id)
            .fetch_optional(&self.db)
            .await
            .map_err(storage_error)?;
            if let Some(row) = row {
                accounts.push(
                    db_ops::authenticated_user_from_row_with_settings(&row, &self.settings)
                        .map_err(storage_error)?,
                );
            }
        }
        Ok(accounts)
    }

    async fn list(
        &self,
        limit: u32,
        offset: u32,
        email: Option<&str>,
    ) -> Result<Vec<AccountInfo>, ManagementError> {
        db_ops::list_authenticated_users_with_settings(
            &self.db,
            self.backend,
            limit,
            offset,
            email,
            &self.settings,
        )
        .await
        .map_err(storage_error)
    }

    async fn claim_schema(&self) -> Result<BTreeMap<String, ManagedClaim>, ManagementError> {
        if self.settings.claims.is_empty() {
            return Ok(BTreeMap::new());
        }
        let columns = db_ops::user_table_columns(&self.db, self.backend)
            .await
            .map_err(storage_error)?;
        super::admin::configured_admin_claim_columns(&columns, &self.settings.claims)
            .map_err(|error| ManagementError::Validation("claims".into(), error))?;
        self.settings
            .claims
            .iter()
            .map(|(name, mapping)| {
                let column = columns
                    .iter()
                    .find(|column| column.column_name == mapping.column)
                    .ok_or(AccountError::Configuration)?;
                let kind = match mapping.ty {
                    AuthClaimType::I64 => ManagedClaimType::I64,
                    AuthClaimType::String => ManagedClaimType::String,
                    AuthClaimType::Bool => ManagedClaimType::Bool,
                };
                Ok((
                    name.clone(),
                    ManagedClaim {
                        kind,
                        nullable: column.nullable,
                    },
                ))
            })
            .collect()
    }

    async fn update(
        &self,
        id: i64,
        input: &UpdateManagedUserInput,
        timestamp: &str,
    ) -> Result<Account, ManagementError> {
        let table = super::auth_user_table_ident(self.backend);
        let result = query(&format!(
            "UPDATE {table} SET role = CASE WHEN ? THEN ? ELSE role END, \
             email_verified_at = CASE WHEN ? THEN ? WHEN ? THEN NULL ELSE email_verified_at END, \
             updated_at = ? WHERE id = ?"
        ))
        .bind(input.role.is_some())
        .bind(input.role.as_deref().unwrap_or_default())
        .bind(input.email_verified == Some(true))
        .bind(timestamp)
        .bind(input.email_verified == Some(false))
        .bind(timestamp)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(storage_error)?;
        if result.rows_affected() != 1 {
            return Err(AccountError::Database.into());
        }
        for (name, value) in &input.claims {
            let mapping = self
                .settings
                .claims
                .get(name)
                .ok_or(AccountError::Configuration)?;
            let sql = format!(
                "UPDATE {table} SET {} = ? WHERE id = ?",
                self.backend.quote_ident(&mapping.column)
            );
            let update = query(&sql);
            let update = match mapping.ty {
                AuthClaimType::I64 => update.bind(value.as_i64()),
                AuthClaimType::String => update.bind(value.as_str()),
                AuthClaimType::Bool => update.bind(value.as_bool()),
            };
            update
                .bind(id)
                .execute(&self.db)
                .await
                .map_err(storage_error)?;
        }
        db_ops::load_authenticated_user_by_id_with_settings_for_backend(
            &self.db,
            self.backend,
            id,
            &self.settings,
        )
        .await
        .map_err(storage_error)?
        .ok_or_else(|| AccountError::Database.into())
    }

    async fn delete(&self, id: i64) -> Result<(), ManagementError> {
        if !db_ops::delete_user_row(&self.db, self.backend, id)
            .await
            .map_err(storage_error)?
        {
            return Err(AccountError::Database.into());
        }
        Ok(())
    }
    async fn commit(self) -> Result<(), ManagementError> {
        self.db.commit().await.map_err(storage_error)
    }
    async fn rollback(self) -> Result<(), ManagementError> {
        self.db.rollback().await.map_err(storage_error)
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
        super::recovery_email::TokenStore(&self.db)
            .replace(id, email, purpose, token)
            .await
    }
}

impl ProvisioningTransaction for Transaction {
    async fn create(
        &self,
        email: &str,
        hash: &str,
        role: &str,
        timestamp: &str,
        verified: bool,
    ) -> Result<Account, ManagementError> {
        query(&format!(
            "INSERT INTO {} \
             (email, password_hash, role, created_at, updated_at, email_verified_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
            super::auth_user_table_ident(self.backend),
        ))
        .bind(email)
        .bind(hash)
        .bind(role)
        .bind(timestamp)
        .bind(timestamp)
        .bind(verified.then_some(timestamp))
        .execute(&self.db)
        .await
        .map_err(|error| {
            if super::helpers::is_unique_violation(&error) {
                AccountError::DuplicateEmail.into()
            } else {
                storage_error(error)
            }
        })?;
        db_ops::load_authenticated_user_by_email_with_settings_for_backend(
            &self.db,
            self.backend,
            email,
            &self.settings,
        )
        .await
        .map_err(storage_error)?
        .ok_or_else(|| AccountError::Database.into())
    }
}

/// Compose admin creation/invitations and authenticated verification resend.
/// Supply a trusted configured verification URL to enable delivery. With `None`,
/// non-email creation works while invitation/resend returns `EmailUnavailable`.
/// This temporary infrastructure bridge still links Actix.
pub fn builtin_provisioning_service(
    db: DbPool,
    settings: &AuthSettings,
    verification_url: Option<&str>,
) -> Result<
    ProvisioningService<
        impl ManagementRepository<Transaction: ProvisioningTransaction>,
        impl Mailer,
    >,
    ManagementError,
> {
    let sender = verification_url
        .map(|url| super::recovery_email::sender(settings, url, TokenPurpose::EmailVerification))
        .transpose()?;
    ProvisioningService::new(
        Repository {
            db,
            settings: settings.clone(),
        },
        sender,
    )
}

/// Compose shared global-admin reads, updates and deletion with existing drivers.
/// This infrastructure bridge still links Actix; the policy does not.
pub fn builtin_management_service(
    db: DbPool,
    settings: &AuthSettings,
) -> ManagementService<impl ManagementRepository> {
    ManagementService::new(Repository {
        db,
        settings: settings.clone(),
    })
}

#[cfg(all(test, feature = "sqlite"))]
#[path = "management_tests.rs"]
pub(super) mod tests;

#[cfg(all(test, feature = "sqlite"))]
#[path = "provisioning_tests.rs"]
pub(super) mod provisioning_tests;
