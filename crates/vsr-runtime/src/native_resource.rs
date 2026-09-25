//! Compiler-free descriptors used by the native resource engine.

use std::collections::{BTreeSet, HashMap};

use crate::{
    authz::{
        RoleRequirements,
        policy::{PolicyValueSource, RowPolicies},
    },
    field::RuntimeField,
    model::{ComputedFieldSpec, DbBackend, ResourceAuditActionSelection},
};

/// A resource lowered from a service definition for native request handling.
#[derive(Clone)]
pub struct RuntimeResource {
    /// Resource name used in diagnostics.
    pub resource_name: String,
    /// Database table name.
    pub table_name: String,
    /// Public API route name.
    pub api_name: String,
    /// Default named response projection.
    pub default_response_context: Option<String>,
    /// Internal ID field name.
    pub id_field: String,
    /// Public ID field name.
    pub id_api_name: String,
    /// Database dialect.
    pub db: DbBackend,
    /// Required CRUD roles.
    pub roles: RoleRequirements,
    /// Row-level access rules.
    pub policies: RowPolicies,
    /// Default collection page size.
    pub default_limit: Option<u32>,
    /// Maximum collection page size.
    pub max_limit: Option<u32>,
    /// Fields accepting multi-value exact filters.
    pub filterable_in: BTreeSet<String>,
    /// Whether the count endpoint is exposed.
    pub count_endpoint: bool,
    /// Values populated from principal claims or request fields during creation.
    pub create_assignment_sources: HashMap<String, PolicyValueSource>,
    /// Lowered stored fields.
    pub fields: Vec<RuntimeField>,
    /// Internal field-name lookup table.
    pub field_index: HashMap<String, usize>,
    /// Public field-name lookup table.
    pub api_field_index: HashMap<String, usize>,
    /// Named response projections.
    pub response_contexts: HashMap<String, Vec<String>>,
    /// Public computed fields.
    pub computed_fields: Vec<ComputedFieldSpec>,
    /// Create-time field rules.
    pub create_fields: Vec<RuntimeCreateFieldRule>,
    /// Fields writable during update.
    pub update_field_names: Vec<String>,
    /// Custom resource actions.
    pub actions: Vec<RuntimeResourceAction>,
    /// Audit event settings.
    pub audit: Option<RuntimeAuditConfig>,
    /// Whether this resource itself receives audit records.
    pub is_audit_sink: bool,
    /// Whether collection reads require a principal.
    pub read_requires_auth: bool,
    /// Hybrid authorization settings.
    pub hybrid: Option<RuntimeHybridResourceConfig>,
    /// Nested relation routes.
    pub nested_relations: Vec<RuntimeNestedRoute>,
    /// Many-to-many relation routes.
    pub many_to_many_routes: Vec<RuntimeManyToManyRoute>,
}

/// Audit destination and events for one native resource.
#[derive(Clone)]
pub struct RuntimeAuditConfig {
    /// Destination table for events.
    pub sink_table_name: String,
    /// Emit create events.
    pub create: bool,
    /// Emit update events.
    pub update: bool,
    /// Emit delete events.
    pub delete: bool,
    /// Custom actions that emit events.
    pub actions: Option<ResourceAuditActionSelection>,
}

impl RuntimeAuditConfig {
    /// Event kind for a creation, if enabled.
    pub fn create_event_kind(&self) -> Option<&'static str> {
        self.create.then_some("create")
    }

    /// Event kind for an update or named custom action, if enabled.
    pub fn update_event_kind(&self, action_name: Option<&str>) -> Option<String> {
        if let Some(action_name) = action_name
            && self
                .actions
                .as_ref()
                .is_some_and(|selection| selection.audits_action(action_name))
        {
            return Some(format!("action:{action_name}"));
        }
        self.update.then(|| "update".to_owned())
    }

    /// Event kind for a deletion or named custom action, if enabled.
    pub fn delete_event_kind(&self, action_name: Option<&str>) -> Option<String> {
        if let Some(action_name) = action_name
            && self
                .actions
                .as_ref()
                .is_some_and(|selection| selection.audits_action(action_name))
        {
            return Some(format!("action:{action_name}"));
        }
        self.delete.then(|| "delete".to_owned())
    }
}

/// Create-time handling for a field controlled by authorization rules.
#[derive(Clone)]
pub struct RuntimeCreateFieldRule {
    /// Internal field name.
    pub name: String,
    /// Whether an administrator may provide an overriding value.
    pub allow_admin_override: bool,
    /// Whether the hybrid runtime may supply the value.
    pub allow_hybrid_runtime: bool,
    /// Whether the request payload may omit the value.
    pub payload_optional: bool,
}

/// Hybrid authorization behavior for a resource.
#[derive(Clone)]
pub struct RuntimeHybridResourceConfig {
    /// Scope name.
    pub scope: String,
    /// Resource field that holds the scope value.
    pub scope_field: String,
    /// Apply the hybrid decision to item reads.
    pub item_read: bool,
    /// Apply the hybrid decision to collection reads.
    pub collection_read: bool,
    /// Apply the hybrid decision to nested reads.
    pub nested_read: bool,
    /// Apply the hybrid decision to create payloads.
    pub create_payload: bool,
    /// Apply the hybrid decision to updates.
    pub update: bool,
    /// Apply the hybrid decision to deletions.
    pub delete: bool,
}

/// Nested route derived from a foreign-key relation.
#[derive(Clone)]
pub struct RuntimeNestedRoute {
    /// Referencing field in the child resource.
    pub field_name: String,
    /// Public parent resource route name.
    pub parent_api_name: String,
}

/// Native route derived from a many-to-many relation.
#[derive(Clone)]
pub struct RuntimeManyToManyRoute {
    /// Public relation route name.
    pub relation_name: String,
    /// Public parent resource route name.
    pub parent_api_name: String,
    /// Join table name.
    pub through_table: String,
    /// Join-table field referring to the parent.
    pub source_field: String,
    /// Join-table field referring to the target.
    pub target_field: String,
}

/// Custom action lowered for native request handling.
#[derive(Clone)]
pub struct RuntimeResourceAction {
    /// Public action name.
    pub name: String,
    /// Route suffix.
    pub path: String,
    /// Write behavior.
    pub behavior: RuntimeResourceActionBehavior,
}

impl RuntimeResourceAction {
    /// Whether the action reads a value from the request body.
    pub fn requires_input(&self) -> bool {
        match &self.behavior {
            RuntimeResourceActionBehavior::UpdateFields { assignments } => {
                assignments.iter().any(|assignment| {
                    matches!(
                        assignment.source,
                        RuntimeActionAssignmentSource::InputField(_)
                    )
                })
            }
            RuntimeResourceActionBehavior::DeleteResource => false,
        }
    }
}

/// Write behavior of a custom native action.
#[derive(Clone)]
pub enum RuntimeResourceActionBehavior {
    /// Update selected fields on the item.
    UpdateFields {
        /// Values assigned to fields.
        assignments: Vec<RuntimeActionUpdateAssignment>,
    },
    /// Delete the item.
    DeleteResource,
}

/// Scalar value bound to a native SQL query.
#[derive(Clone, Debug, PartialEq)]
pub enum RuntimeBoundValue {
    /// SQL NULL.
    Null,
    /// Boolean value.
    Bool(bool),
    /// Signed integer.
    Integer(i64),
    /// Floating-point number.
    Real(f64),
    /// Text value.
    Text(String),
}

/// Value assigned during a custom native update action.
#[derive(Clone)]
pub struct RuntimeActionUpdateAssignment {
    /// Internal field name.
    pub field_name: String,
    /// Source of the assigned value.
    pub source: RuntimeActionAssignmentSource,
}

/// Source of a custom action assignment.
#[derive(Clone)]
pub enum RuntimeActionAssignmentSource {
    /// Fixed scalar value.
    Literal(RuntimeBoundValue),
    /// Named request input field.
    InputField(String),
}

#[cfg(test)]
mod tests {
    use crate::model::ResourceAuditActionSelection;

    use super::{
        RuntimeActionAssignmentSource, RuntimeActionUpdateAssignment, RuntimeAuditConfig,
        RuntimeBoundValue, RuntimeResourceAction, RuntimeResourceActionBehavior,
    };

    #[test]
    fn audit_and_action_descriptors_keep_named_action_behavior() {
        let audit = RuntimeAuditConfig {
            sink_table_name: "events".into(),
            create: true,
            update: false,
            delete: false,
            actions: Some(ResourceAuditActionSelection::Named(vec!["publish".into()])),
        };
        assert_eq!(audit.create_event_kind(), Some("create"));
        assert_eq!(
            audit.update_event_kind(Some("publish")),
            Some("action:publish".into())
        );
        assert_eq!(audit.update_event_kind(Some("archive")), None);

        let action = RuntimeResourceAction {
            name: "publish".into(),
            path: "publish".into(),
            behavior: RuntimeResourceActionBehavior::UpdateFields {
                assignments: vec![RuntimeActionUpdateAssignment {
                    field_name: "status".into(),
                    source: RuntimeActionAssignmentSource::InputField("status".into()),
                }],
            },
        };
        assert!(action.requires_input());
        let literal = RuntimeResourceAction {
            behavior: RuntimeResourceActionBehavior::UpdateFields {
                assignments: vec![RuntimeActionUpdateAssignment {
                    field_name: "status".into(),
                    source: RuntimeActionAssignmentSource::Literal(RuntimeBoundValue::Text(
                        "published".into(),
                    )),
                }],
            },
            ..action
        };
        assert!(!literal.requires_input());
    }
}
