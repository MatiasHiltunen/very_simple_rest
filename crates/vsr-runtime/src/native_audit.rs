//! Native audit events and atomic write transaction orchestration.

use std::future::Future;

use serde_json::{Value, json};

use crate::{
    native_insert::{InsertExecutor, execute_insert},
    native_mutation::{MutationAction, MutationStatement},
    native_resource::{RuntimeBoundValue, RuntimeResource},
    native_write::PreparedCreate,
};

/// Principal fields recorded with a native audit event.
#[derive(Clone, Copy)]
pub struct AuditActor<'a> {
    /// Numeric user ID; zero represents an anonymous caller.
    pub user_id: i64,
    /// Role names recorded as a JSON array.
    pub roles: &'a [String],
}

/// Database operations within one native audit transaction.
///
/// Dropping an unfinished transaction must discard or roll back its writes.
pub trait AuditTransaction: InsertExecutor {
    /// Load the row snapshot using native response field names.
    fn snapshot(
        &self,
        resource: &RuntimeResource,
        record_id: i64,
    ) -> impl Future<Output = Result<Option<Value>, String>> + Send;

    /// Bind and execute a resource mutation or audit insert in this transaction.
    fn execute(
        &self,
        statement: &MutationStatement,
    ) -> impl Future<Output = Result<u64, String>> + Send;

    /// Commit the resource write and audit event together.
    fn commit(self) -> impl Future<Output = Result<(), String>> + Send;

    /// Discard an unsuccessful or unmatched attempt.
    fn rollback(self) -> impl Future<Output = Result<(), String>> + Send;
}

/// Starts native audit transactions without selecting a database driver.
pub trait AuditDatabase: Send + Sync {
    /// Driver adapter for the transaction's operations.
    type Transaction: AuditTransaction;

    /// Begin a fresh transaction for one write attempt.
    fn begin(&self) -> impl Future<Output = Result<Self::Transaction, String>> + Send;
}

/// One audited update/delete attempt and its request context.
pub struct AuditedMutation<'a> {
    /// Resource being changed.
    pub resource: &'a RuntimeResource,
    /// Caller recorded with the event.
    pub actor: AuditActor<'a>,
    /// CRUD or custom-action event kind.
    pub event_kind: &'a str,
    /// Existing row ID.
    pub record_id: i64,
    /// Determines which snapshots the event needs.
    pub action: MutationAction,
    /// Direct-policy or already-authorized hybrid statement.
    pub statement: &'a MutationStatement,
}

/// Insert a row, reload its snapshot, and commit its audit event atomically.
pub async fn execute_audited_insert(
    resource: &RuntimeResource,
    prepared: &PreparedCreate,
    actor: &AuditActor<'_>,
    event_kind: &str,
    database: &impl AuditDatabase,
) -> Result<i64, String> {
    let tx = database.begin().await?;
    let result = async {
        let id = execute_insert(resource, prepared, &tx)
            .await?
            .ok_or_else(|| "created row id was not returned".to_owned())?;
        let after = tx
            .snapshot(resource, id)
            .await?
            .ok_or_else(|| "created row could not be reloaded for audit".to_owned())?;
        append_event(&tx, resource, actor, event_kind, id, None, Some(&after)).await?;
        Ok(Some(id))
    }
    .await;
    finish_transaction(tx, result)
        .await?
        .ok_or_else(|| "created row id was not returned".to_owned())
}

/// Execute one write attempt with snapshots and an atomic audit event.
///
/// Unmatched attempts roll back before returning zero, so the mutation
/// dispatcher can resolve a hybrid grant and start a separate attempt.
pub async fn execute_audited_mutation(
    request: &AuditedMutation<'_>,
    database: &impl AuditDatabase,
) -> Result<u64, String> {
    let tx = database.begin().await?;
    let result = async {
        let before = tx.snapshot(request.resource, request.record_id).await?;
        let affected = tx.execute(request.statement).await?;
        if affected == 0 {
            return Ok(None);
        }
        let after = match request.action {
            MutationAction::Update => Some(
                tx.snapshot(request.resource, request.record_id)
                    .await?
                    .ok_or_else(|| "updated row could not be reloaded for audit".to_owned())?,
            ),
            MutationAction::Delete => {
                if before.is_none() {
                    return Err("deleted row could not be reloaded for audit".to_owned());
                }
                None
            }
        };
        append_event(
            &tx,
            request.resource,
            &request.actor,
            request.event_kind,
            request.record_id,
            before.as_ref(),
            after.as_ref(),
        )
        .await?;
        Ok(Some(affected))
    }
    .await;
    Ok(finish_transaction(tx, result).await?.unwrap_or(0))
}

async fn append_event(
    tx: &impl AuditTransaction,
    resource: &RuntimeResource,
    actor: &AuditActor<'_>,
    event_kind: &str,
    record_id: i64,
    before: Option<&Value>,
    after: Option<&Value>,
) -> Result<(), String> {
    if let Some(statement) = build_audit_plan(resource, actor, event_kind, record_id, before, after)
        .map_err(|error| error.to_string())?
    {
        tx.execute(&statement).await?;
    }
    Ok(())
}

async fn finish_transaction<T>(
    tx: impl AuditTransaction,
    result: Result<Option<T>, String>,
) -> Result<Option<T>, String> {
    match result {
        Ok(Some(value)) => {
            tx.commit().await?;
            Ok(Some(value))
        }
        Ok(None) => {
            tx.rollback().await?;
            Ok(None)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

/// Build an audit insert for the caller's existing write transaction.
///
/// Snapshots already use the native response field names. No event is planned
/// when the resource has no audit sink.
pub fn build_audit_plan(
    resource: &RuntimeResource,
    actor: &AuditActor<'_>,
    event_kind: &str,
    record_id: i64,
    before: Option<&Value>,
    after: Option<&Value>,
) -> Result<Option<MutationStatement>, serde_json::Error> {
    let Some(audit) = &resource.audit else {
        return Ok(None);
    };
    let payload = match (before, after) {
        (Some(before), Some(after)) => json!({"before": before, "after": after}),
        (Some(before), None) => json!({"before": before}),
        (None, Some(after)) => json!({"after": after}),
        (None, None) => json!({}),
    };
    Ok(Some(MutationStatement {
        sql: format!(
            "INSERT INTO {} (event_kind, resource_name, record_id, actor_user_id, actor_roles_json, payload_json) VALUES ({})",
            audit.sink_table_name,
            (1..=6)
                .map(|index| resource.db.placeholder(index))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        binds: vec![
            RuntimeBoundValue::Text(event_kind.to_owned()),
            RuntimeBoundValue::Text(resource.resource_name.clone()),
            RuntimeBoundValue::Integer(record_id),
            if actor.user_id == 0 {
                RuntimeBoundValue::Null
            } else {
                RuntimeBoundValue::Integer(actor.user_id)
            },
            RuntimeBoundValue::Text(serde_json::to_string(actor.roles)?),
            RuntimeBoundValue::Text(serde_json::to_string(&payload)?),
        ],
    }))
}
