//! Shared audit insert planning for generated and native resource writes.

use serde_json::{Value, json};

use crate::native_resource::RuntimeBoundValue;

/// Resource, actor, and row snapshots for one audit event.
#[derive(Clone, Copy)]
pub struct AuditInsert<'a> {
    /// Validated audit sink table name.
    pub sink_table: &'a str,
    /// Public resource name stored with the event.
    pub resource_name: &'a str,
    /// CRUD or named action event kind.
    pub event_kind: &'a str,
    /// ID of the affected row.
    pub record_id: i64,
    /// Actor ID; `None` represents an anonymous caller.
    pub actor_user_id: Option<i64>,
    /// Actor roles stored as a JSON array.
    pub actor_roles: &'a [String],
    /// Snapshot before the write, serialized with the resource's response fields.
    pub before: Option<&'a Value>,
    /// Snapshot after the write, serialized with the resource's response fields.
    pub after: Option<&'a Value>,
}

/// SQL and ordered values for an audit insert.
pub struct AuditInsertPlan {
    /// Insert SQL using the resource backend's placeholders.
    pub sql: String,
    /// Event kind, resource, row ID, actor ID, roles, and payload in that order.
    pub binds: Vec<RuntimeBoundValue>,
}

/// Build the common audit insert without selecting a database driver.
///
/// The caller supplies already validated identifiers and the backend's
/// placeholder function. Snapshot serialization remains with the caller so
/// computed resource fields are included before planning the event.
pub fn plan_audit_insert(
    insert: AuditInsert<'_>,
    placeholder: impl Fn(usize) -> String,
) -> Result<AuditInsertPlan, serde_json::Error> {
    let payload = match (insert.before, insert.after) {
        (Some(before), Some(after)) => json!({"before": before, "after": after}),
        (Some(before), None) => json!({"before": before}),
        (None, Some(after)) => json!({"after": after}),
        (None, None) => json!({}),
    };
    let actor_roles_json = serde_json::to_string(insert.actor_roles)?;
    let payload_json = serde_json::to_string(&payload)?;
    let placeholders = (1..=6).map(placeholder).collect::<Vec<_>>().join(", ");
    Ok(AuditInsertPlan {
        sql: format!(
            "INSERT INTO {} (event_kind, resource_name, record_id, actor_user_id, actor_roles_json, payload_json) VALUES ({placeholders})",
            insert.sink_table,
        ),
        binds: vec![
            RuntimeBoundValue::Text(insert.event_kind.to_owned()),
            RuntimeBoundValue::Text(insert.resource_name.to_owned()),
            RuntimeBoundValue::Integer(insert.record_id),
            insert
                .actor_user_id
                .map_or(RuntimeBoundValue::Null, RuntimeBoundValue::Integer),
            RuntimeBoundValue::Text(actor_roles_json),
            RuntimeBoundValue::Text(payload_json),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_create_update_delete_and_anonymous_actor_with_ordered_binds() {
        let before = json!({"id": 7, "title": "old"});
        let after = json!({"id": 7, "title": "new"});
        let roles = vec!["editor".to_owned(), "a\"b".to_owned()];
        for (old, new, expected) in [
            (None, Some(&after), json!({"after": after})),
            (
                Some(&before),
                Some(&after),
                json!({"before": before, "after": after}),
            ),
            (Some(&before), None, json!({"before": before})),
            (None, None, json!({})),
        ] {
            let plan = plan_audit_insert(
                AuditInsert {
                    sink_table: "audit_event",
                    resource_name: "Post",
                    event_kind: "action:publish",
                    record_id: 7,
                    actor_user_id: None,
                    actor_roles: &roles,
                    before: old,
                    after: new,
                },
                |index| format!("${index}"),
            )
            .unwrap();
            assert_eq!(
                plan.sql,
                "INSERT INTO audit_event (event_kind, resource_name, record_id, actor_user_id, actor_roles_json, payload_json) VALUES ($1, $2, $3, $4, $5, $6)"
            );
            assert_eq!(plan.binds.len(), 6);
            assert_eq!(
                plan.binds[0],
                RuntimeBoundValue::Text("action:publish".into())
            );
            assert_eq!(plan.binds[1], RuntimeBoundValue::Text("Post".into()));
            assert_eq!(plan.binds[2], RuntimeBoundValue::Integer(7));
            assert_eq!(plan.binds[3], RuntimeBoundValue::Null);
            assert_eq!(
                plan.binds[4],
                RuntimeBoundValue::Text("[\"editor\",\"a\\\"b\"]".into())
            );
            let RuntimeBoundValue::Text(payload) = &plan.binds[5] else {
                panic!("payload must be JSON text");
            };
            assert_eq!(serde_json::from_str::<Value>(payload).unwrap(), expected);
        }
        let plan = plan_audit_insert(
            AuditInsert {
                sink_table: "events",
                resource_name: "Post",
                event_kind: "update",
                record_id: 9,
                actor_user_id: Some(42),
                actor_roles: &[],
                before: None,
                after: None,
            },
            |_| "?".to_owned(),
        )
        .unwrap();
        assert!(plan.sql.ends_with("VALUES (?, ?, ?, ?, ?, ?)"));
        assert_eq!(plan.binds[3], RuntimeBoundValue::Integer(42));
    }
}
