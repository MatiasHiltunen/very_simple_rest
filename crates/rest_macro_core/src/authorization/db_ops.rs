use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::Row as _;
use uuid::Uuid;

use crate::db::{DbPool, query};

use super::types::{
    AuthorizationScopeBinding, AuthorizationScopedAssignment,
    AuthorizationScopedAssignmentEventKind, AuthorizationScopedAssignmentEventRecord,
    AuthorizationScopedAssignmentRecord, AuthorizationScopedAssignmentTarget,
    AUTHORIZATION_RUNTIME_ASSIGNMENT_EVENT_TABLE, AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE,
};

pub fn new_runtime_assignment_id() -> String {
    format!("runtime.assignment.{}", Uuid::new_v4())
}

pub fn new_runtime_assignment_event_id() -> String {
    format!("runtime.assignment_event.{}", Uuid::new_v4())
}

pub fn runtime_assignment_timestamp_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false)
}

pub async fn insert_runtime_assignment<E>(
    executor: &E,
    assignment: &AuthorizationScopedAssignmentRecord,
) -> Result<(), String>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let (target_kind, target_name) = runtime_assignment_target_parts(&assignment.target);
    query(&format!(
        "INSERT INTO {AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE} \
         (id, user_id, created_by_user_id, created_at, expires_at, target_kind, target_name, scope_name, scope_value) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ))
    .bind(&assignment.id)
    .bind(assignment.user_id)
    .bind(assignment.created_by_user_id)
    .bind(&assignment.created_at)
    .bind(&assignment.expires_at)
    .bind(target_kind)
    .bind(target_name)
    .bind(&assignment.scope.scope)
    .bind(&assignment.scope.value)
    .execute(executor)
    .await
    .map_err(runtime_assignment_storage_error)?;
    Ok(())
}

async fn update_runtime_assignment<E>(
    executor: &E,
    assignment: &AuthorizationScopedAssignmentRecord,
) -> Result<(), String>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query(&format!(
        "UPDATE {AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE} SET expires_at = ? WHERE id = ?"
    ))
    .bind(&assignment.expires_at)
    .bind(&assignment.id)
    .execute(executor)
    .await
    .map_err(runtime_assignment_storage_error)?;
    Ok(())
}

pub async fn insert_runtime_assignment_event<E>(
    executor: &E,
    event: &AuthorizationScopedAssignmentEventRecord,
) -> Result<(), String>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let (target_kind, target_name) = runtime_assignment_target_parts(&event.target);
    query(&format!(
        "INSERT INTO {AUTHORIZATION_RUNTIME_ASSIGNMENT_EVENT_TABLE} \
         (id, assignment_id, user_id, created_by_user_id, created_at, event_kind, target_kind, target_name, scope_name, scope_value, expires_at, reason) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ))
    .bind(&event.id)
    .bind(&event.assignment_id)
    .bind(event.user_id)
    .bind(event.actor_user_id)
    .bind(&event.occurred_at)
    .bind(runtime_assignment_event_kind_label(event.event))
    .bind(target_kind)
    .bind(target_name)
    .bind(&event.scope.scope)
    .bind(&event.scope.value)
    .bind(&event.expires_at)
    .bind(&event.reason)
    .execute(executor)
    .await
    .map_err(runtime_assignment_storage_error)?;
    Ok(())
}

pub async fn create_runtime_assignment_with_audit(
    pool: &DbPool,
    assignment: AuthorizationScopedAssignmentRecord,
) -> Result<(), String> {
    let tx = pool
        .begin()
        .await
        .map_err(runtime_assignment_storage_error)?;
    if let Err(error) = insert_runtime_assignment(&tx, &assignment).await {
        let _ = tx.rollback().await;
        return Err(error);
    }
    if let Err(error) = insert_runtime_assignment_event(
        &tx,
        &assignment.event(
            AuthorizationScopedAssignmentEventKind::Created,
            assignment.created_by_user_id,
            None,
        ),
    )
    .await
    {
        let _ = tx.rollback().await;
        return Err(error);
    }
    tx.commit()
        .await
        .map_err(runtime_assignment_storage_error)?;
    Ok(())
}

pub async fn list_runtime_assignments_for_user(
    pool: &DbPool,
    user_id: i64,
) -> Result<Vec<AuthorizationScopedAssignmentRecord>, String> {
    let rows = query(&format!(
        "SELECT id, user_id, created_by_user_id, created_at, expires_at, target_kind, target_name, scope_name, scope_value \
         FROM {AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE} WHERE user_id = ? ORDER BY created_at, id"
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(runtime_assignment_storage_error)?;

    rows.into_iter()
        .map(runtime_assignment_record_from_row)
        .collect()
}

pub async fn list_runtime_assignment_events_for_user(
    pool: &DbPool,
    user_id: i64,
) -> Result<Vec<AuthorizationScopedAssignmentEventRecord>, String> {
    let rows = query(&format!(
        "SELECT id, assignment_id, user_id, created_by_user_id, created_at, event_kind, target_kind, target_name, scope_name, scope_value, expires_at, reason \
         FROM {AUTHORIZATION_RUNTIME_ASSIGNMENT_EVENT_TABLE} WHERE user_id = ? ORDER BY created_at, id"
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(runtime_assignment_storage_error)?;

    rows.into_iter()
        .map(runtime_assignment_event_record_from_row)
        .collect()
}

pub async fn delete_runtime_assignment_with_audit(
    pool: &DbPool,
    assignment_id: &str,
    actor_user_id: Option<i64>,
    reason: Option<String>,
) -> Result<bool, String> {
    let tx = pool
        .begin()
        .await
        .map_err(runtime_assignment_storage_error)?;
    let Some(assignment) = fetch_runtime_assignment_by_id(&tx, assignment_id).await? else {
        let _ = tx.rollback().await;
        return Ok(false);
    };
    if let Err(error) = query(&format!(
        "DELETE FROM {AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE} WHERE id = ?"
    ))
    .bind(assignment_id)
    .execute(&tx)
    .await
    .map_err(runtime_assignment_storage_error)
    {
        let _ = tx.rollback().await;
        return Err(error);
    }
    if let Err(error) = insert_runtime_assignment_event(
        &tx,
        &assignment.event(
            AuthorizationScopedAssignmentEventKind::Deleted,
            actor_user_id,
            reason,
        ),
    )
    .await
    {
        let _ = tx.rollback().await;
        return Err(error);
    }
    tx.commit()
        .await
        .map_err(runtime_assignment_storage_error)?;
    Ok(true)
}

pub async fn revoke_runtime_assignment_with_audit(
    pool: &DbPool,
    assignment_id: &str,
    actor_user_id: Option<i64>,
    reason: Option<String>,
) -> Result<Option<AuthorizationScopedAssignmentRecord>, String> {
    let tx = pool
        .begin()
        .await
        .map_err(runtime_assignment_storage_error)?;
    let Some(mut assignment) = fetch_runtime_assignment_by_id(&tx, assignment_id).await? else {
        let _ = tx.rollback().await;
        return Ok(None);
    };
    let revoked_at = runtime_assignment_timestamp_now();
    let revoked_at_timestamp = parse_runtime_assignment_timestamp("revoked_at", &revoked_at)?;
    if !assignment.is_active_at(&revoked_at_timestamp)? {
        let _ = tx.rollback().await;
        return Err(format!(
            "runtime assignment `{assignment_id}` is already inactive"
        ));
    }
    assignment.expires_at = Some(revoked_at);
    assignment.validate()?;
    if let Err(error) = update_runtime_assignment(&tx, &assignment).await {
        let _ = tx.rollback().await;
        return Err(error);
    }
    if let Err(error) = insert_runtime_assignment_event(
        &tx,
        &assignment.event(
            AuthorizationScopedAssignmentEventKind::Revoked,
            actor_user_id,
            reason,
        ),
    )
    .await
    {
        let _ = tx.rollback().await;
        return Err(error);
    }
    tx.commit()
        .await
        .map_err(runtime_assignment_storage_error)?;
    Ok(Some(assignment))
}

pub async fn renew_runtime_assignment_with_audit(
    pool: &DbPool,
    assignment_id: &str,
    expires_at: &str,
    actor_user_id: Option<i64>,
    reason: Option<String>,
) -> Result<Option<AuthorizationScopedAssignmentRecord>, String> {
    let renewed_at = Utc::now();
    let next_expires_at = parse_runtime_assignment_timestamp("expires_at", expires_at)?
        .to_rfc3339_opts(SecondsFormat::Micros, false);
    let next_expires_at_timestamp =
        parse_runtime_assignment_timestamp("expires_at", &next_expires_at)?;
    if next_expires_at_timestamp <= renewed_at {
        return Err(
            "runtime assignment `expires_at` must be later than the current time".to_owned(),
        );
    }

    let tx = pool
        .begin()
        .await
        .map_err(runtime_assignment_storage_error)?;
    let Some(mut assignment) = fetch_runtime_assignment_by_id(&tx, assignment_id).await? else {
        let _ = tx.rollback().await;
        return Ok(None);
    };
    if let Some(current_expires_at) = assignment.expires_at.as_deref() {
        let current_expires_at =
            parse_runtime_assignment_timestamp("expires_at", current_expires_at)?;
        if current_expires_at >= next_expires_at_timestamp {
            let _ = tx.rollback().await;
            return Err(format!(
                "runtime assignment `{assignment_id}` already expires at or after `{next_expires_at}`"
            ));
        }
    }
    assignment.expires_at = Some(next_expires_at);
    assignment.validate()?;
    if let Err(error) = update_runtime_assignment(&tx, &assignment).await {
        let _ = tx.rollback().await;
        return Err(error);
    }
    if let Err(error) = insert_runtime_assignment_event(
        &tx,
        &assignment.event(
            AuthorizationScopedAssignmentEventKind::Renewed,
            actor_user_id,
            reason,
        ),
    )
    .await
    {
        let _ = tx.rollback().await;
        return Err(error);
    }
    tx.commit()
        .await
        .map_err(runtime_assignment_storage_error)?;
    Ok(Some(assignment))
}

pub async fn load_runtime_assignments_for_user(
    pool: &DbPool,
    user_id: i64,
) -> Result<Vec<AuthorizationScopedAssignment>, String> {
    let now = Utc::now();
    list_runtime_assignments_for_user(pool, user_id)
        .await
        .and_then(|assignments| {
            let active = assignments
                .into_iter()
                .filter_map(|assignment| match assignment.is_active_at(&now) {
                    Ok(true) => Some(Ok(assignment.scoped_assignment())),
                    Ok(false) => None,
                    Err(error) => Some(Err(error)),
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(active)
        })
}

fn parse_stored_scoped_assignment_target(
    assignment_id: &str,
    kind: &str,
    name: &str,
) -> Result<AuthorizationScopedAssignmentTarget, String> {
    match kind.trim().to_ascii_lowercase().as_str() {
        "permission" => Ok(AuthorizationScopedAssignmentTarget::Permission {
            name: name.to_owned(),
        }),
        "template" => Ok(AuthorizationScopedAssignmentTarget::Template {
            name: name.to_owned(),
        }),
        _ => Err(format!(
            "runtime assignment `{assignment_id}` has unsupported target kind `{kind}`"
        )),
    }
}

fn parse_runtime_assignment_event_kind(
    assignment_id: &str,
    value: &str,
) -> Result<AuthorizationScopedAssignmentEventKind, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "created" => Ok(AuthorizationScopedAssignmentEventKind::Created),
        "revoked" => Ok(AuthorizationScopedAssignmentEventKind::Revoked),
        "renewed" => Ok(AuthorizationScopedAssignmentEventKind::Renewed),
        "deleted" => Ok(AuthorizationScopedAssignmentEventKind::Deleted),
        _ => Err(format!(
            "runtime assignment event `{assignment_id}` has unsupported event kind `{value}`"
        )),
    }
}

fn runtime_assignment_target_parts(
    target: &AuthorizationScopedAssignmentTarget,
) -> (&'static str, &str) {
    match target {
        AuthorizationScopedAssignmentTarget::Permission { name } => ("permission", name.as_str()),
        AuthorizationScopedAssignmentTarget::Template { name } => ("template", name.as_str()),
    }
}

fn runtime_assignment_event_kind_label(
    kind: AuthorizationScopedAssignmentEventKind,
) -> &'static str {
    match kind {
        AuthorizationScopedAssignmentEventKind::Created => "created",
        AuthorizationScopedAssignmentEventKind::Revoked => "revoked",
        AuthorizationScopedAssignmentEventKind::Renewed => "renewed",
        AuthorizationScopedAssignmentEventKind::Deleted => "deleted",
    }
}

fn parse_runtime_assignment_timestamp(field: &str, value: &str) -> Result<DateTime<Utc>, String> {
    if value.trim().is_empty() {
        return Err(format!("runtime assignment `{field}` cannot be empty"));
    }
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| format!("runtime assignment `{field}` must be RFC3339: {error}"))
}

fn runtime_assignment_record_from_row(
    row: sqlx::any::AnyRow,
) -> Result<AuthorizationScopedAssignmentRecord, String> {
    let id: String = row.try_get("id").map_err(|error| error.to_string())?;
    let user_id: i64 = row.try_get("user_id").map_err(|error| error.to_string())?;
    let created_by_user_id: Option<i64> = row
        .try_get("created_by_user_id")
        .map_err(|error| error.to_string())?;
    let created_at: String = row
        .try_get("created_at")
        .map_err(|error| error.to_string())?;
    let expires_at: Option<String> = row
        .try_get("expires_at")
        .map_err(|error| error.to_string())?;
    let target_kind: String = row
        .try_get("target_kind")
        .map_err(|error| error.to_string())?;
    let target_name: String = row
        .try_get("target_name")
        .map_err(|error| error.to_string())?;
    let scope_name: String = row
        .try_get("scope_name")
        .map_err(|error| error.to_string())?;
    let scope_value: String = row
        .try_get("scope_value")
        .map_err(|error| error.to_string())?;
    let target = parse_stored_scoped_assignment_target(&id, &target_kind, &target_name)?;
    let record = AuthorizationScopedAssignmentRecord {
        id,
        user_id,
        target,
        scope: AuthorizationScopeBinding {
            scope: scope_name,
            value: scope_value,
        },
        created_at,
        created_by_user_id,
        expires_at,
    };
    record.validate()?;
    Ok(record)
}

fn runtime_assignment_event_record_from_row(
    row: sqlx::any::AnyRow,
) -> Result<AuthorizationScopedAssignmentEventRecord, String> {
    let id: String = row.try_get("id").map_err(|error| error.to_string())?;
    let assignment_id: String = row
        .try_get("assignment_id")
        .map_err(|error| error.to_string())?;
    let user_id: i64 = row.try_get("user_id").map_err(|error| error.to_string())?;
    let actor_user_id: Option<i64> = row
        .try_get("created_by_user_id")
        .map_err(|error| error.to_string())?;
    let occurred_at: String = row
        .try_get("created_at")
        .map_err(|error| error.to_string())?;
    let event_kind: String = row
        .try_get("event_kind")
        .map_err(|error| error.to_string())?;
    let target_kind: String = row
        .try_get("target_kind")
        .map_err(|error| error.to_string())?;
    let target_name: String = row
        .try_get("target_name")
        .map_err(|error| error.to_string())?;
    let scope_name: String = row
        .try_get("scope_name")
        .map_err(|error| error.to_string())?;
    let scope_value: String = row
        .try_get("scope_value")
        .map_err(|error| error.to_string())?;
    let expires_at: Option<String> = row
        .try_get("expires_at")
        .map_err(|error| error.to_string())?;
    let reason: Option<String> = row.try_get("reason").map_err(|error| error.to_string())?;
    Ok(AuthorizationScopedAssignmentEventRecord {
        id: id.clone(),
        assignment_id,
        user_id,
        event: parse_runtime_assignment_event_kind(&id, &event_kind)?,
        occurred_at,
        actor_user_id,
        target: parse_stored_scoped_assignment_target(&id, &target_kind, &target_name)?,
        scope: AuthorizationScopeBinding {
            scope: scope_name,
            value: scope_value,
        },
        expires_at,
        reason,
    })
}

async fn fetch_runtime_assignment_by_id<E>(
    executor: &E,
    assignment_id: &str,
) -> Result<Option<AuthorizationScopedAssignmentRecord>, String>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let row = query(&format!(
        "SELECT id, user_id, created_by_user_id, created_at, expires_at, target_kind, target_name, scope_name, scope_value \
         FROM {AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE} WHERE id = ?"
    ))
    .bind(assignment_id)
    .fetch_optional(executor)
    .await
    .map_err(runtime_assignment_storage_error)?;
    row.map(runtime_assignment_record_from_row).transpose()
}

fn runtime_assignment_storage_error(error: sqlx::Error) -> String {
    if is_missing_runtime_assignment_table(&error) {
        format!(
            "runtime authorization assignment tables `{AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE}` / `{AUTHORIZATION_RUNTIME_ASSIGNMENT_EVENT_TABLE}` do not exist; generate and apply the authz runtime migration first"
        )
    } else if is_outdated_runtime_assignment_table(&error) {
        "runtime authorization assignment tables are missing required lifecycle or audit columns; regenerate and apply the authz runtime migration".to_string()
    } else {
        error.to_string()
    }
}

fn is_missing_runtime_assignment_table(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(database_error) => {
            let message = database_error.message().to_ascii_lowercase();
            message.contains("no such table") || message.contains("does not exist")
        }
        _ => false,
    }
}

fn is_outdated_runtime_assignment_table(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(database_error) => {
            let message = database_error.message().to_ascii_lowercase();
            message.contains("no such column: created_at")
                || message.contains("column \"created_at\" does not exist")
                || message.contains("unknown column 'created_at'")
                || message.contains("no such column: created_by_user_id")
                || message.contains("column \"created_by_user_id\" does not exist")
                || message.contains("unknown column 'created_by_user_id'")
                || message.contains("no such column: expires_at")
                || message.contains("column \"expires_at\" does not exist")
                || message.contains("unknown column 'expires_at'")
                || message.contains("no such table: authz_scoped_assignment_event")
                || message.contains("table \"authz_scoped_assignment_event\" does not exist")
                || message.contains("no such column: event_kind")
                || message.contains("column \"event_kind\" does not exist")
                || message.contains("unknown column 'event_kind'")
                || message.contains("no such column: reason")
                || message.contains("column \"reason\" does not exist")
                || message.contains("unknown column 'reason'")
        }
        _ => false,
    }
}

