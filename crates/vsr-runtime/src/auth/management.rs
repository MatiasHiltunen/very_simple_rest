//! Built-in admin reads, updates and deletion without HTTP or SQL types.
//!
//! Callers must authenticate (including live token state and cookie CSRF) before
//! passing an identity. This service additionally checks the current admin role
//! under the same lock as the operation. These are global built-in administrators,
//! not tenant-scoped roles. Creation and invitations use the companion
//! provisioning service; dashboard rendering remains in the legacy facade.

use std::{collections::BTreeMap, future::Future};

use chrono::{DateTime, SecondsFormat};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vsr_core::clock::{Clock, SystemClock};

use super::{
    AuthenticatedIdentity,
    accounts::{Account, AccountError, AccountInfo},
    request::AuthFailure,
};
use crate::http::ResponseEnvelope;

/// Existing JSON update contract. Column names and arbitrary account fields are
/// deliberately absent; repositories map only configured, validated claim names.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UpdateManagedUserInput {
    /// Optional replacement role; whitespace is trimmed.
    #[serde(default)]
    pub role: Option<String>,
    /// Explicit verification override by a global administrator.
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// Configured application claims to change, with null clearing nullable ones.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, Value>,
}

/// Existing list query contract; limits are bounded by the service.
#[derive(Debug, Default, Deserialize)]
pub struct AdminListQuery {
    /// Page size, default 50, clamped to 1..=100.
    pub limit: Option<u32>,
    /// Offset, default zero.
    pub offset: Option<u32>,
    /// Trimmed SQL LIKE substring filter, retaining the legacy wildcard behavior.
    pub email: Option<String>,
}

/// Bounded public page, never containing salted hashes or session fingerprints.
#[derive(Debug, Serialize)]
pub struct ManagedUserPage {
    /// Public account snapshots.
    pub items: Vec<AccountInfo>,
    /// Applied page size.
    pub limit: u32,
    /// Applied offset.
    pub offset: u32,
}

/// Scalar types accepted by configured claim mappings.
#[derive(Clone, Copy)]
pub enum ManagedClaimType {
    /// Signed 64-bit integer, without string/float coercion.
    I64,
    /// String, without scalar coercion.
    String,
    /// JSON boolean, not numeric or string truthiness.
    Bool,
}

/// Repository schema capability for a configured claim, not client input.
pub struct ManagedClaim {
    /// Configured scalar type, verified against storage metadata.
    pub kind: ManagedClaimType,
    /// Actual database nullability, independent of insert defaults.
    pub nullable: bool,
}

/// Stable management errors with no underlying driver details.
#[derive(Debug, PartialEq, Eq)]
pub enum ManagementError {
    /// Shared authentication/storage/configuration failure.
    Account(AccountError),
    /// The authenticated caller is not a current global administrator.
    Forbidden,
    /// Target account does not exist.
    NotFound,
    /// Self-deletion is prohibited by the existing admin contract.
    CannotDeleteSelf,
    /// No supported changes were supplied.
    MissingChanges,
    /// Claim writes require explicit server configuration.
    ClaimsNotConfigured,
    /// A verified account must not also request a verification invitation.
    InvalidInviteState,
    /// Field-specific public validation failure.
    Validation(String, String),
}

impl From<AccountError> for ManagementError {
    fn from(value: AccountError) -> Self {
        Self::Account(value)
    }
}

impl ManagementError {
    /// Existing status/code/message/field response shape.
    pub fn response(self) -> ResponseEnvelope {
        let (status, code, message, field) = match self {
            Self::Account(error) => return error.response(),
            Self::Forbidden => (403, "forbidden", "Admin role is required".into(), None),
            Self::NotFound => (404, "not_found", "User not found".into(), None),
            Self::CannotDeleteSelf => (400, "cannot_delete_self", "Admins cannot delete their own account from the admin dashboard".into(), None),
            Self::MissingChanges => (400, "missing_changes", "Provide `role`, `email_verified`, and/or `claims` to update the user".into(), None),
            Self::ClaimsNotConfigured => (400, "claims_not_configured", "This service does not declare `security.auth.claims`, so managed claim updates are unavailable".into(), None),
            Self::InvalidInviteState => (400, "invalid_invite_state", "A verified user does not need a verification email".into(), None),
            Self::Validation(field, message) => (400, "validation_error", message, Some(field)),
        };
        let mut body = serde_json::json!({"code": code, "message": message});
        if let Some(field) = field {
            body["field"] = field.into();
        }
        let mut response = ResponseEnvelope::json(body);
        response.status = status;
        response
    }
}

/// Driver transaction. All operations must use the same transaction/connection.
/// Drop must roll back unfinished work, including cancellation and panics.
/// A lost commit acknowledgement may leave its outcome unknown to the caller.
pub trait ManagementTransaction: Send + Sync + Sized + 'static {
    /// Lock and return current accounts in ascending ID order. Missing IDs are
    /// omitted. Locks must prevent modification/deletion until commit or rollback.
    fn lock_accounts(
        &self,
        ids: &[i64],
    ) -> impl Future<Output = Result<Vec<Account>, ManagementError>> + Send;
    /// Bounded list, ordered by ID, with bound filter/pagination values.
    fn list(
        &self,
        limit: u32,
        offset: u32,
        email: Option<&str>,
    ) -> impl Future<Output = Result<Vec<AccountInfo>, ManagementError>> + Send;
    /// Return configured and storage-validated claim types/nullability. Reject
    /// reserved account columns, ambiguous aliases and incompatible mappings.
    fn claim_schema(
        &self,
    ) -> impl Future<Output = Result<BTreeMap<String, ManagedClaim>, ManagementError>> + Send;
    /// Apply the validated update and reload the public result before commit.
    /// The target has already been locked and its management schema checked.
    fn update(
        &self,
        id: i64,
        input: &UpdateManagedUserInput,
        timestamp: &str,
    ) -> impl Future<Output = Result<Account, ManagementError>> + Send;
    /// Delete the locked account. Storage must enforce its dependent-row policy.
    fn delete(&self, id: i64) -> impl Future<Output = Result<(), ManagementError>> + Send;
    /// A failed commit must never be reported as a successful operation.
    fn commit(self) -> impl Future<Output = Result<(), ManagementError>> + Send;
    /// Roll back any writes on a policy or storage failure.
    fn rollback(self) -> impl Future<Output = Result<(), ManagementError>> + Send;
}

/// Repository for transactional built-in account administration.
pub trait ManagementRepository: Send + Sync + 'static {
    /// Cancellation-safe driver transaction.
    type Transaction: ManagementTransaction;
    /// Begin before locking the actor and target. SQLite needs a write reservation.
    fn begin(&self) -> impl Future<Output = Result<Self::Transaction, ManagementError>> + Send;
}

/// Shared global-administrator policy. No client-selected actor IDs are accepted.
pub struct ManagementService<R, C = SystemClock> {
    repository: R,
    clock: C,
}

impl<R: ManagementRepository> ManagementService<R> {
    /// Compose a driver adapter with the system clock.
    pub fn new(repository: R) -> Self {
        Self::with_clock(repository, SystemClock)
    }
}

impl<R: ManagementRepository, C: Clock> ManagementService<R, C> {
    /// Inject a deterministic clock for management revision checks.
    pub fn with_clock(repository: R, clock: C) -> Self {
        Self { repository, clock }
    }

    /// List after both authenticated-role and locked live-role authorization.
    pub async fn list(
        &self,
        actor: &AuthenticatedIdentity,
        query: &AdminListQuery,
    ) -> Result<ManagedUserPage, ManagementError> {
        let actor_id = administrator_id(actor)?;
        let tx = self.repository.begin().await?;
        let result = async {
            authorized_accounts(&tx, actor_id, None).await?;
            let limit = query.limit.unwrap_or(50).clamp(1, 100);
            let offset = query.offset.unwrap_or(0);
            let email = query
                .email
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let items = tx.list(limit, offset, email).await?;
            Ok(ManagedUserPage {
                items,
                limit,
                offset,
            })
        }
        .await;
        finish(tx, result).await
    }

    /// Read a target snapshot without exposing storage-only security fields.
    pub async fn get(
        &self,
        actor: &AuthenticatedIdentity,
        id: i64,
    ) -> Result<AccountInfo, ManagementError> {
        let actor_id = administrator_id(actor)?;
        let tx = self.repository.begin().await?;
        let result = authorized_accounts(&tx, actor_id, Some(id))
            .await
            .and_then(|account| account.map(Into::into).ok_or(ManagementError::NotFound));
        finish(tx, result).await
    }

    /// Update atomically. Full management columns are required even for claim-only
    /// changes so reverting a change cannot revive previously revoked sessions.
    pub async fn update(
        &self,
        actor: &AuthenticatedIdentity,
        id: i64,
        mut input: UpdateManagedUserInput,
    ) -> Result<AccountInfo, ManagementError> {
        let actor_id = administrator_id(actor)?;
        if let Some(role) = input.role.as_mut() {
            *role = role.trim().to_owned();
            if role.is_empty() {
                return Err(ManagementError::Validation(
                    "role".into(),
                    "Role cannot be empty".into(),
                ));
            }
        }
        if input.role.is_none() && input.email_verified.is_none() && input.claims.is_empty() {
            return Err(ManagementError::MissingChanges);
        }
        let tx = self.repository.begin().await?;
        let result = async {
            let current = authorized_accounts(&tx, actor_id, Some(id))
                .await?
                .ok_or(ManagementError::NotFound)?;
            if !current.has_auth_management_schema() {
                return Err(AccountError::MissingSchema.into());
            }
            if !input.claims.is_empty() {
                validate_claims(&tx.claim_schema().await?, &input.claims)?;
            }
            let timestamp =
                next_revision(self.clock.now_unix_micros(), current.updated_at.as_deref())?;
            let account = tx.update(id, &input, &timestamp).await?;
            if account.id != id || account.updated_at.as_deref() != Some(&timestamp) {
                return Err(AccountError::Database.into());
            }
            Ok(account.into())
        }
        .await;
        finish(tx, result).await
    }

    /// Delete another account, retaining the existing self-deletion prohibition.
    pub async fn delete(
        &self,
        actor: &AuthenticatedIdentity,
        id: i64,
    ) -> Result<(), ManagementError> {
        let actor_id = administrator_id(actor)?;
        if id == actor_id {
            return Err(ManagementError::CannotDeleteSelf);
        }
        let tx = self.repository.begin().await?;
        let result = async {
            authorized_accounts(&tx, actor_id, Some(id))
                .await?
                .ok_or(ManagementError::NotFound)?;
            tx.delete(id).await
        }
        .await;
        finish(tx, result).await
    }
}

pub(super) fn administrator_id(actor: &AuthenticatedIdentity) -> Result<i64, ManagementError> {
    if !actor.roles.iter().any(|role| role == "admin") {
        return Err(ManagementError::Forbidden);
    }
    authenticated_account_id(actor)
}

pub(super) fn authenticated_account_id(
    actor: &AuthenticatedIdentity,
) -> Result<i64, ManagementError> {
    actor
        .user_id
        .parse::<i64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| AccountError::Auth(AuthFailure::InvalidToken).into())
}

pub(super) async fn authorized_accounts<T: ManagementTransaction>(
    tx: &T,
    actor: i64,
    target: Option<i64>,
) -> Result<Option<Account>, ManagementError> {
    let mut ids = vec![actor];
    if let Some(target) = target {
        ids.push(target);
    }
    ids.sort_unstable();
    ids.dedup();
    let accounts = tx.lock_accounts(&ids).await?;
    let current = accounts
        .iter()
        .find(|account| account.id == actor)
        .ok_or(AccountError::MissingAccount)?;
    if current.role != "admin" {
        return Err(ManagementError::Forbidden);
    }
    Ok(accounts
        .into_iter()
        .find(|account| Some(account.id) == target))
}

pub(super) async fn finish<T: ManagementTransaction, V>(
    tx: T,
    result: Result<V, ManagementError>,
) -> Result<V, ManagementError> {
    match result {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

pub(super) fn next_revision(now: i64, previous: Option<&str>) -> Result<String, AccountError> {
    if now < 0 {
        return Err(AccountError::Configuration);
    }
    let previous = previous.and_then(|value| DateTime::parse_from_rfc3339(value).ok());
    let next = match previous {
        Some(previous) if previous.timestamp_micros() >= now => previous
            .timestamp_micros()
            .checked_add(1)
            .ok_or(AccountError::Configuration)?,
        _ => now,
    };
    DateTime::from_timestamp_micros(next)
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Micros, false))
        .ok_or(AccountError::Configuration)
}

fn validate_claims(
    schema: &BTreeMap<String, ManagedClaim>,
    claims: &BTreeMap<String, Value>,
) -> Result<(), ManagementError> {
    if schema.is_empty() {
        return Err(ManagementError::ClaimsNotConfigured);
    }
    for (name, value) in claims {
        let invalid = |message| ManagementError::Validation(format!("claims.{name}"), message);
        let claim = schema.get(name).ok_or_else(|| {
            invalid(format!(
                "Unknown managed auth claim `{name}`. Declare it under `security.auth.claims` first"
            ))
        })?;
        if value.is_null() {
            if !claim.nullable {
                return Err(invalid(format!(
                    "Managed auth claim `{name}` cannot be null"
                )));
            }
            continue;
        }
        let (valid, label) = match claim.kind {
            ManagedClaimType::I64 => (value.as_i64().is_some(), "an integer"),
            ManagedClaimType::String => (value.is_string(), "a string"),
            ManagedClaimType::Bool => (value.is_boolean(), "a boolean"),
        };
        if !valid {
            return Err(invalid(format!(
                "Managed auth claim `{name}` must be {label}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "management_tests.rs"]
mod tests;
