use std::collections::BTreeMap;

use serde_json::Value;
use sqlx::any::AnyRow;
use sqlx::{Column, Row};

use crate::db::{DbPool, query};

use super::helpers::{optional_text_column, row_has_column};
#[cfg(test)]
use super::helpers::hash_auth_token;
use super::migrations::{AuthDbBackend, auth_user_table_ident};
use super::settings::{AuthClaimType, AuthSettings};
use super::user::{AccountInfo, AuthTokenPurpose, AuthenticatedUser, StoredAuthToken};

pub(crate) fn authenticated_user_from_row_with_settings(
    row: &AnyRow,
    settings: &AuthSettings,
) -> Result<AuthenticatedUser, sqlx::Error> {
    Ok(AuthenticatedUser {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        password_hash: row.try_get("password_hash")?,
        role: row.try_get("role")?,
        email_verified_at: optional_text_column(row, "email_verified_at")?,
        created_at: optional_text_column(row, "created_at")?,
        updated_at: optional_text_column(row, "updated_at")?,
        has_email_verified_at_column: row_has_column(row, "email_verified_at"),
        has_created_at_column: row_has_column(row, "created_at"),
        has_updated_at_column: row_has_column(row, "updated_at"),
        claims: collect_user_claims_with_settings(row, settings)?,
    })
}

pub(crate) fn account_info_from_user(user: AuthenticatedUser) -> AccountInfo {
    user.into()
}

pub(crate) fn collect_user_claims_with_settings(
    row: &AnyRow,
    settings: &AuthSettings,
) -> Result<BTreeMap<String, Value>, sqlx::Error> {
    let mut claims = BTreeMap::new();

    for (claim_name, mapping) in &settings.claims {
        if let Some(value) = optional_claim_column(row, &mapping.column, mapping.ty)? {
            claims.insert(claim_name.clone(), value);
        }
    }

    for column in row.columns() {
        let column_name = column.name();
        let Some(claim_name) = explicit_claim_name(column_name) else {
            continue;
        };
        if let Some(value) = optional_i64_claim_column(row, column_name)? {
            claims.insert(claim_name, Value::from(value));
        }
    }

    for column in row.columns() {
        let column_name = column.name();
        let Some(claim_name) = implicit_claim_name(column_name) else {
            continue;
        };
        if claims.contains_key(&claim_name) {
            continue;
        }
        if let Some(value) = optional_i64_claim_column(row, column_name)? {
            claims.insert(claim_name, Value::from(value));
        }
    }

    Ok(claims)
}

pub(crate) fn explicit_claim_name(column: &str) -> Option<String> {
    column
        .strip_prefix("claim_")
        .filter(|claim| !claim.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn implicit_claim_name(column: &str) -> Option<String> {
    if matches!(column, "id" | "email" | "password_hash" | "role") {
        return None;
    }
    if column.starts_with("claim_") {
        return None;
    }

    column
        .ends_with("_id")
        .then(|| column.to_owned())
        .filter(|claim| claim != "id")
}

pub(crate) fn optional_i64_claim_column(
    row: &AnyRow,
    column: &str,
) -> Result<Option<i64>, sqlx::Error> {
    match row.try_get::<Option<i64>, _>(column) {
        Ok(value) => Ok(value),
        Err(sqlx::Error::ColumnNotFound(_)) => Ok(None),
        Err(sqlx::Error::ColumnDecode { .. }) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn optional_string_claim_column(
    row: &AnyRow,
    column: &str,
) -> Result<Option<String>, sqlx::Error> {
    match row.try_get::<Option<String>, _>(column) {
        Ok(value) => Ok(value),
        Err(sqlx::Error::ColumnNotFound(_)) => Ok(None),
        Err(sqlx::Error::ColumnDecode { .. }) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn optional_bool_claim_column(
    row: &AnyRow,
    column: &str,
) -> Result<Option<bool>, sqlx::Error> {
    match row.try_get::<Option<bool>, _>(column) {
        Ok(value) => Ok(value),
        Err(sqlx::Error::ColumnDecode { .. }) => match row.try_get::<Option<i64>, _>(column) {
            Ok(value) => Ok(value.map(|value| value != 0)),
            Err(sqlx::Error::ColumnNotFound(_)) => Ok(None),
            Err(sqlx::Error::ColumnDecode { .. }) => Ok(None),
            Err(error) => Err(error),
        },
        Err(sqlx::Error::ColumnNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn optional_claim_column(
    row: &AnyRow,
    column: &str,
    ty: AuthClaimType,
) -> Result<Option<Value>, sqlx::Error> {
    match ty {
        AuthClaimType::I64 => {
            optional_i64_claim_column(row, column).map(|value| value.map(Value::from))
        }
        AuthClaimType::String => {
            optional_string_claim_column(row, column).map(|value| value.map(Value::from))
        }
        AuthClaimType::Bool => {
            optional_bool_claim_column(row, column).map(|value| value.map(Value::from))
        }
    }
}

pub(crate) async fn load_authenticated_user_by_email_with_settings_for_backend<E>(
    db: &E,
    backend: AuthDbBackend,
    email: &str,
    settings: &AuthSettings,
) -> Result<Option<AuthenticatedUser>, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let row = query(&format!(
        "SELECT * FROM {} WHERE email = ?",
        auth_user_table_ident(backend)
    ))
    .bind(email)
    .fetch_optional(db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    authenticated_user_from_row_with_settings(&row, settings).map(Some)
}

pub(crate) async fn load_authenticated_user_by_email_with_settings(
    db: &DbPool,
    email: &str,
    settings: &AuthSettings,
) -> Result<Option<AuthenticatedUser>, sqlx::Error> {
    let backend = detect_auth_backend(db).await?;
    load_authenticated_user_by_email_with_settings_for_backend(db, backend, email, settings).await
}

pub(crate) async fn load_authenticated_user_by_id_with_settings_for_backend<E>(
    db: &E,
    backend: AuthDbBackend,
    user_id: i64,
    settings: &AuthSettings,
) -> Result<Option<AuthenticatedUser>, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let row = query(&format!(
        "SELECT * FROM {} WHERE id = ?",
        auth_user_table_ident(backend)
    ))
    .bind(user_id)
    .fetch_optional(db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    authenticated_user_from_row_with_settings(&row, settings).map(Some)
}

pub(crate) async fn load_authenticated_user_by_id_with_settings(
    db: &DbPool,
    user_id: i64,
    settings: &AuthSettings,
) -> Result<Option<AuthenticatedUser>, sqlx::Error> {
    let backend = detect_auth_backend(db).await?;
    load_authenticated_user_by_id_with_settings_for_backend(db, backend, user_id, settings).await
}

pub(crate) async fn list_authenticated_users_with_settings<E: crate::db::DbExecutor + ?Sized>(
    db: &E,
    backend: AuthDbBackend,
    limit: u32,
    offset: u32,
    email_filter: Option<&str>,
    settings: &AuthSettings,
) -> Result<Vec<AccountInfo>, sqlx::Error> {
    let rows = if let Some(email_filter) = email_filter {
        query(&format!(
            "SELECT * FROM {} WHERE email LIKE ? ORDER BY id LIMIT ? OFFSET ?",
            auth_user_table_ident(backend)
        ))
        .bind(format!("%{email_filter}%"))
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(db)
        .await?
    } else {
        query(&format!(
            "SELECT * FROM {} ORDER BY id LIMIT ? OFFSET ?",
            auth_user_table_ident(backend)
        ))
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(db)
        .await?
    };

    rows.into_iter()
        .map(|row| {
            authenticated_user_from_row_with_settings(&row, settings).map(account_info_from_user)
        })
        .collect()
}

#[cfg(test)]
pub(crate) async fn create_auth_token<E>(
    db: &E,
    user_id: i64,
    purpose: AuthTokenPurpose,
    requested_email: Option<&str>,
    ttl_seconds: i64,
) -> Result<String, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let token = vsr_runtime::auth::recovery_email::RecoveryToken::generate(
        ttl_seconds,
        &vsr_core::clock::SystemClock,
    )
    .map_err(|_| sqlx::Error::Protocol("Invalid recovery token configuration".to_owned()))?;
    replace_auth_token(db, user_id, purpose, requested_email, &token).await?;
    Ok(token.raw().to_owned())
}

pub(crate) async fn replace_auth_token<E>(
    db: &E,
    user_id: i64,
    purpose: AuthTokenPurpose,
    requested_email: Option<&str>,
    token: &vsr_runtime::auth::recovery_email::RecoveryToken,
) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    delete_auth_tokens_for_user_purpose(db, user_id, purpose).await?;
    query(
        "INSERT INTO auth_user_token (user_id, purpose, token_hash, requested_email, expires_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user_id).bind(purpose.as_str()).bind(token.digest())
    .bind(requested_email).bind(token.expires_at()).execute(db).await?;
    Ok(())
}

#[cfg(test)]
pub(crate) async fn load_pending_auth_token<E>(
    db: &E,
    raw_token: &str,
    purpose: AuthTokenPurpose,
) -> Result<Option<StoredAuthToken>, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let token_hash = hash_auth_token(raw_token);
    load_pending_auth_token_by_digest(db, &token_hash, purpose).await
}

pub(crate) async fn load_pending_auth_token_by_digest<E>(
    db: &E,
    token_hash: &str,
    purpose: AuthTokenPurpose,
) -> Result<Option<StoredAuthToken>, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let row = query(
        "SELECT id, user_id, purpose, requested_email, expires_at FROM auth_user_token WHERE token_hash = ? AND purpose = ? AND used_at IS NULL",
    )
    .bind(token_hash)
    .bind(purpose.as_str())
    .fetch_optional(db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    Ok(Some(StoredAuthToken {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        requested_email: row.try_get("requested_email")?,
        expires_at: row.try_get("expires_at")?,
    }))
}

pub(crate) async fn mark_auth_token_used<E>(
    db: &E,
    token_id: i64,
    used_at: &str,
) -> Result<bool, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let result = query("UPDATE auth_user_token SET used_at = ? WHERE id = ? AND used_at IS NULL")
        .bind(used_at)
        .bind(token_id)
        .execute(db)
        .await?;
    Ok(result.rows_affected() == 1)
}

pub(crate) async fn delete_auth_tokens_for_user_purpose<E>(
    db: &E,
    user_id: i64,
    purpose: AuthTokenPurpose,
) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query("DELETE FROM auth_user_token WHERE user_id = ? AND purpose = ?")
        .bind(user_id)
        .bind(purpose.as_str())
        .execute(db)
        .await?;
    Ok(())
}

pub(crate) async fn delete_auth_token_by_id<E>(db: &E, token_id: i64) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query("DELETE FROM auth_user_token WHERE id = ?")
        .bind(token_id)
        .execute(db)
        .await?;
    Ok(())
}

pub(crate) async fn mark_user_email_verified<E>(
    db: &E,
    backend: AuthDbBackend,
    user_id: i64,
    verified_at: &str,
) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query(&format!(
        "UPDATE {} SET email_verified_at = ?, updated_at = ? WHERE id = ?",
        auth_user_table_ident(backend)
    ))
    .bind(verified_at)
    .bind(verified_at)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

pub(crate) async fn initialize_user_management_timestamps<E>(
    db: &E,
    backend: AuthDbBackend,
    user_id: i64,
    timestamp: &str,
) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query(&format!(
        "UPDATE {} SET created_at = COALESCE(created_at, ?), updated_at = COALESCE(updated_at, ?) WHERE id = ?",
        auth_user_table_ident(backend)
    ))
        .bind(timestamp)
        .bind(timestamp)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}
pub(crate) async fn compare_and_set_user_password(
    db: &DbPool,
    backend: AuthDbBackend,
    expected: &AuthenticatedUser,
    password_hash: &str,
    updated_at: &str,
) -> Result<bool, sqlx::Error> {
    // One conditional statement avoids a password-reset/change race on every
    // supported driver. A dropped column is an error, not permission to retry
    // with a weaker condition; base-schema compatibility is explicit.
    let table = auth_user_table_ident(backend);
    let result = if expected.has_updated_at_column {
        let revision_predicate = if expected.updated_at.is_some() {
            "updated_at = ?"
        } else {
            "updated_at IS NULL"
        };
        let sql = format!("UPDATE {table} SET password_hash = ?, updated_at = ? WHERE id = ? AND password_hash = ? AND {revision_predicate}");
        let statement = query(&sql)
            .bind(password_hash)
            .bind(updated_at)
            .bind(expected.id)
            .bind(&expected.password_hash);
        let statement = if let Some(revision) = &expected.updated_at {
            statement.bind(revision)
        } else {
            statement
        };
        statement.execute(db).await?
    } else {
        query(&format!("UPDATE {table} SET password_hash = ? WHERE id = ? AND password_hash = ?"))
            .bind(password_hash)
            .bind(expected.id)
            .bind(&expected.password_hash)
            .execute(db)
            .await?
    };
    Ok(result.rows_affected() == 1)
}

pub(crate) async fn delete_user_row<E>(
    db: &E,
    backend: AuthDbBackend,
    user_id: i64,
) -> Result<bool, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let result = query(&format!(
        "DELETE FROM {} WHERE id = ?",
        auth_user_table_ident(backend)
    ))
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(result.rows_affected() != 0)
}

pub(crate) async fn detect_auth_backend(pool: &DbPool) -> Result<AuthDbBackend, sqlx::Error> {
    match pool {
        DbPool::Sqlx { pool, .. } => {
            let connection = pool.acquire().await?;
            let backend_name = connection.backend_name().to_ascii_lowercase();
            if backend_name.contains("postgres") {
                Ok(AuthDbBackend::Postgres)
            } else if backend_name.contains("mysql") {
                Ok(AuthDbBackend::Mysql)
            } else if backend_name.contains("sqlite") {
                Ok(AuthDbBackend::Sqlite)
            } else {
                Err(sqlx::Error::Protocol(format!(
                    "unsupported built-in auth backend `{backend_name}`"
                )))
            }
        }
        #[cfg(feature = "turso-local")]
        DbPool::TursoLocal(_) => Ok(AuthDbBackend::Sqlite),
    }
}

pub(crate) async fn user_table_columns<E: crate::db::DbExecutor + ?Sized>(
    pool: &E,
    backend: AuthDbBackend,
) -> Result<Vec<UserColumnMetadata>, sqlx::Error> {
    let rows = match backend {
        AuthDbBackend::Sqlite => query("PRAGMA table_info('user')").fetch_all(pool).await?,
        AuthDbBackend::Postgres => {
            query(
                "SELECT column_name::text AS column_name, \
                        data_type::text AS data_type, \
                        is_nullable::text AS is_nullable, \
                        column_default::text AS column_default \
             FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'user' \
             ORDER BY ordinal_position",
            )
            .fetch_all(pool)
            .await?
        }
        AuthDbBackend::Mysql => {
            query(
                "SELECT CAST(column_name AS CHAR(255)) AS column_name, \
                        CAST(data_type AS CHAR(255)) AS data_type, \
                        CAST(is_nullable AS CHAR(3)) AS is_nullable, \
                        CAST(column_default AS CHAR(255)) AS column_default \
             FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = 'user' \
             ORDER BY ordinal_position",
            )
            .fetch_all(pool)
            .await?
        }
    };

    let mut columns = Vec::new();
    for row in rows {
        columns.push(user_column_from_row(&row, backend)?);
    }

    Ok(columns)
}

pub(crate) fn user_column_from_row(
    row: &AnyRow,
    backend: AuthDbBackend,
) -> Result<UserColumnMetadata, sqlx::Error> {
    let (column_name, data_type, required, nullable) = match backend {
        AuthDbBackend::Sqlite => {
            let column_name: String = row.try_get("name")?;
            let data_type: String = row
                .try_get::<Option<String>, _>("type")?
                .unwrap_or_default()
                .to_ascii_lowercase();
            let notnull = row.try_get::<i64, _>("notnull")? != 0;
            let default_value = row.try_get::<Option<String>, _>("dflt_value")?;
            (
                column_name,
                data_type,
                notnull && default_value.is_none(),
                !notnull,
            )
        }
        AuthDbBackend::Postgres | AuthDbBackend::Mysql => {
            let column_name: String = row.try_get("column_name")?;
            let data_type: String = row.try_get::<String, _>("data_type")?.to_ascii_lowercase();
            let is_nullable = row.try_get::<String, _>("is_nullable")?;
            let default_value = row.try_get::<Option<String>, _>("column_default")?;
            (
                column_name,
                data_type,
                is_nullable.eq_ignore_ascii_case("NO") && default_value.is_none(),
                is_nullable.eq_ignore_ascii_case("YES"),
            )
        }
    };

    Ok(UserColumnMetadata {
        column_name,
        data_type,
        required,
        nullable,
    })
}

pub(crate) fn placeholder_for_backend(backend: AuthDbBackend, index: usize) -> String {
    match backend {
        AuthDbBackend::Postgres => format!("${index}"),
        AuthDbBackend::Sqlite | AuthDbBackend::Mysql => "?".to_owned(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UserColumnMetadata {
    pub column_name: String,
    pub data_type: String,
    pub required: bool,
    pub nullable: bool,
}
