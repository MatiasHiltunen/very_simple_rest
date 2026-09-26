//! Native audit event serialization and statement planning.

use serde_json::{Value, json};

use crate::{
    native_mutation::MutationStatement,
    native_resource::{RuntimeBoundValue, RuntimeResource},
};

/// Principal fields recorded with a native audit event.
pub struct AuditActor<'a> {
    /// Numeric user ID; zero represents an anonymous caller.
    pub user_id: i64,
    /// Role names recorded as a JSON array.
    pub roles: &'a [String],
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
