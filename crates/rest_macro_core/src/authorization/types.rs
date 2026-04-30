use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::AuthClaimType;
use crate::db::DbPool;

use super::db_ops::{new_runtime_assignment_event_id, new_runtime_assignment_id, runtime_assignment_timestamp_now};
use super::engine::parse_runtime_assignment_timestamp;

pub const AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE: &str = "authz_scoped_assignment";
pub const AUTHORIZATION_RUNTIME_ASSIGNMENT_EVENT_TABLE: &str = "authz_scoped_assignment_event";
pub const DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT: &str = "/authz/runtime";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationAction {
    Read,
    Create,
    Update,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationOperator {
    Equals,
    IsNull,
    IsNotNull,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationContract {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<AuthorizationScope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<AuthorizationPermission>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<AuthorizationTemplate>,
    #[serde(
        default,
        skip_serializing_if = "AuthorizationHybridEnforcementConfig::is_empty"
    )]
    pub hybrid_enforcement: AuthorizationHybridEnforcementConfig,
    #[serde(
        default,
        skip_serializing_if = "AuthorizationManagementApiConfig::is_default"
    )]
    pub management_api: AuthorizationManagementApiConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationManagementApiConfig {
    pub enabled: bool,
    pub mount: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationHybridEnforcementConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<AuthorizationHybridResource>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationHybridScopeSources {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub item: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub collection_filter: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub nested_parent: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub create_payload: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationHybridSource {
    Item,
    CollectionFilter,
    NestedParent,
    CreatePayload,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationHybridResource {
    pub resource: String,
    pub scope: String,
    pub scope_field: String,
    #[serde(
        default,
        skip_serializing_if = "AuthorizationHybridScopeSources::is_default"
    )]
    pub scope_sources: AuthorizationHybridScopeSources,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<AuthorizationAction>,
}

impl Default for AuthorizationManagementApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mount: DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT.to_owned(),
        }
    }
}

impl AuthorizationManagementApiConfig {
    pub fn is_default(config: &Self) -> bool {
        !config.enabled && config.mount == DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT
    }
}

impl AuthorizationHybridEnforcementConfig {
    pub fn is_empty(config: &Self) -> bool {
        config.resources.is_empty()
    }

    pub fn resource(&self, name: &str) -> Option<&AuthorizationHybridResource> {
        self.resources
            .iter()
            .find(|resource| resource.resource == name)
    }
}

impl AuthorizationHybridScopeSources {
    pub fn is_default(config: &Self) -> bool {
        !config.item && !config.collection_filter && !config.nested_parent && !config.create_payload
    }

    pub fn labels(&self) -> Vec<&'static str> {
        let mut labels = Vec::new();
        if self.item {
            labels.push("item");
        }
        if self.collection_filter {
            labels.push("collection_filter");
        }
        if self.nested_parent {
            labels.push("nested_parent");
        }
        if self.create_payload {
            labels.push("create_payload");
        }
        labels
    }

    pub fn supports(&self, source: AuthorizationHybridSource) -> bool {
        match source {
            AuthorizationHybridSource::Item => self.item,
            AuthorizationHybridSource::CollectionFilter => self.collection_filter,
            AuthorizationHybridSource::NestedParent => self.nested_parent,
            AuthorizationHybridSource::CreatePayload => self.create_payload,
        }
    }
}

impl AuthorizationHybridResource {
    pub fn supports_action(&self, action: AuthorizationAction) -> bool {
        self.actions.contains(&action)
    }

    pub fn supports_item_action(&self, action: AuthorizationAction) -> bool {
        match action {
            AuthorizationAction::Read => self.scope_sources.item && self.supports_action(action),
            AuthorizationAction::Update => self.scope_sources.item && self.supports_action(action),
            AuthorizationAction::Delete => self.scope_sources.item && self.supports_action(action),
            AuthorizationAction::Create => {
                self.scope_sources.create_payload && self.supports_action(action)
            }
        }
    }

    pub fn supports_collection_read(&self) -> bool {
        self.scope_sources.collection_filter && self.supports_action(AuthorizationAction::Read)
    }

    pub fn supports_nested_read(&self) -> bool {
        self.scope_sources.nested_parent && self.supports_action(AuthorizationAction::Read)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScope {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationPermission {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<AuthorizationAction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationTemplate {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScopeBinding {
    pub scope: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthorizationScopedAssignmentTarget {
    Permission { name: String },
    Template { name: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScopedAssignment {
    pub id: String,
    pub target: AuthorizationScopedAssignmentTarget,
    pub scope: AuthorizationScopeBinding,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScopedAssignmentRecord {
    pub id: String,
    pub user_id: i64,
    pub target: AuthorizationScopedAssignmentTarget,
    pub scope: AuthorizationScopeBinding,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by_user_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationScopedAssignmentEventKind {
    Created,
    Revoked,
    Renewed,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScopedAssignmentEventRecord {
    pub id: String,
    pub assignment_id: String,
    pub user_id: i64,
    pub event: AuthorizationScopedAssignmentEventKind,
    pub occurred_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_user_id: Option<i64>,
    pub target: AuthorizationScopedAssignmentTarget,
    pub scope: AuthorizationScopeBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScopedAssignmentCreateInput {
    pub user_id: i64,
    pub target: AuthorizationScopedAssignmentTarget,
    pub scope: AuthorizationScopeBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScopedAssignmentRevokeInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScopedAssignmentRenewInput {
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScopedAssignmentListQuery {
    pub user_id: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationRuntimeAccessInput {
    pub resource: String,
    pub action: AuthorizationAction,
    pub scope: AuthorizationScopeBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationRuntimeAccessResult {
    pub user_id: i64,
    pub resource_id: String,
    pub resource: String,
    pub action_id: String,
    pub action: AuthorizationAction,
    pub scope: AuthorizationScopeBinding,
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_templates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_assignments: Vec<AuthorizationScopedAssignmentTrace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationModel {
    #[serde(default, skip_serializing_if = "AuthorizationContract::is_empty")]
    pub contract: AuthorizationContract,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceAuthorization>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceAuthorization {
    pub id: String,
    pub resource: String,
    pub table: String,
    #[serde(default = "default_admin_bypass")]
    pub admin_bypass: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ActionAuthorization>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionAuthorization {
    pub id: String,
    pub action: AuthorizationAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<AuthorizationCondition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assignments: Vec<AuthorizationAssignment>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthorizationCondition {
    Match(AuthorizationMatch),
    All {
        id: String,
        conditions: Vec<AuthorizationCondition>,
    },
    Any {
        id: String,
        conditions: Vec<AuthorizationCondition>,
    },
    Not {
        id: String,
        condition: Box<AuthorizationCondition>,
    },
    Exists {
        id: String,
        resource: String,
        table: String,
        conditions: Vec<AuthorizationExistsCondition>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationMatch {
    pub id: String,
    pub field: String,
    pub operator: AuthorizationOperator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<AuthorizationValueSource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthorizationExistsCondition {
    Match(AuthorizationMatch),
    CurrentRowField {
        id: String,
        field: String,
        row_field: String,
    },
    All {
        id: String,
        conditions: Vec<AuthorizationExistsCondition>,
    },
    Any {
        id: String,
        conditions: Vec<AuthorizationExistsCondition>,
    },
    Not {
        id: String,
        condition: Box<AuthorizationExistsCondition>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationAssignment {
    pub id: String,
    pub field: String,
    pub source: AuthorizationValueSource,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthorizationValueSource {
    UserId,
    Claim { name: String, ty: AuthClaimType },
    InputField { name: String },
    Literal { value: AuthorizationLiteralValue },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthorizationLiteralValue {
    String(String),
    I64(i64),
    Bool(bool),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationOutcome {
    Allowed,
    Denied,
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationSimulationInput {
    pub action: AuthorizationAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub row: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub proposed: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub related_rows: BTreeMap<String, Vec<BTreeMap<String, Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<AuthorizationScopeBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hybrid_source: Option<AuthorizationHybridSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scoped_assignments: Vec<AuthorizationScopedAssignment>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationSimulationResult {
    pub resource_id: String,
    pub resource: String,
    pub action_id: String,
    pub action: AuthorizationAction,
    pub outcome: AuthorizationOutcome,
    pub allowed: bool,
    pub admin: bool,
    pub role_check_passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_role: Option<String>,
    pub admin_bypass_applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<AuthorizationConditionTrace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assignments: Vec<AuthorizationAssignmentTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<AuthorizationScopeBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_assignments: Vec<AuthorizationScopedAssignmentTrace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_templates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub controlled_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hybrid: Option<AuthorizationHybridSimulationTrace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationHybridSimulationTrace {
    pub source: AuthorizationHybridSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<AuthorizationScopeBinding>,
    pub runtime_allowed: bool,
    pub effective_outcome: AuthorizationOutcome,
    pub effective_allowed: bool,
    pub fallback_applied: bool,
    pub skip_static_row_policy: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthorizationConditionTrace {
    Match {
        id: String,
        field: String,
        operator: AuthorizationOperator,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<AuthorizationValueSource>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        row_value: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_value: Option<Value>,
        matched: bool,
        indeterminate: bool,
        missing_field: bool,
        missing_source: bool,
    },
    All {
        id: String,
        matched: bool,
        indeterminate: bool,
        conditions: Vec<AuthorizationConditionTrace>,
    },
    Any {
        id: String,
        matched: bool,
        indeterminate: bool,
        conditions: Vec<AuthorizationConditionTrace>,
    },
    Not {
        id: String,
        matched: bool,
        indeterminate: bool,
        condition: Box<AuthorizationConditionTrace>,
    },
    Exists {
        id: String,
        resource: String,
        table: String,
        matched: bool,
        indeterminate: bool,
        related_row_count: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        matched_row_index: Option<usize>,
        missing_related_rows: bool,
        missing_related_fields: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        conditions: Vec<AuthorizationExistsConditionTrace>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationAssignmentTrace {
    pub id: String,
    pub field: String,
    pub source: AuthorizationValueSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_value: Option<Value>,
    pub admin_override_allowed: bool,
    pub admin_override_applied: bool,
    pub missing_source: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthorizationExistsConditionTrace {
    Match {
        id: String,
        field: String,
        operator: AuthorizationOperator,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<AuthorizationValueSource>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_value: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        related_value: Option<Value>,
        matched: bool,
        indeterminate: bool,
        missing_source: bool,
        missing_related_field: bool,
    },
    CurrentRowField {
        id: String,
        field: String,
        row_field: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        row_value: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        related_value: Option<Value>,
        matched: bool,
        indeterminate: bool,
        missing_row_field: bool,
        missing_related_field: bool,
    },
    All {
        id: String,
        matched: bool,
        indeterminate: bool,
        conditions: Vec<AuthorizationExistsConditionTrace>,
    },
    Any {
        id: String,
        matched: bool,
        indeterminate: bool,
        conditions: Vec<AuthorizationExistsConditionTrace>,
    },
    Not {
        id: String,
        matched: bool,
        indeterminate: bool,
        condition: Box<AuthorizationExistsConditionTrace>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScopedAssignmentTrace {
    pub id: String,
    pub target: AuthorizationScopedAssignmentTarget,
    pub scope: AuthorizationScopeBinding,
    pub scope_matched: bool,
    pub target_matched: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by_user_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub expired: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_template: Option<String>,
}

#[derive(Clone)]
pub struct AuthorizationRuntime {
    pub(super) model: AuthorizationModel,
    pub(super) pool: DbPool,
}

pub(super) const fn default_admin_bypass() -> bool {
    true
}

impl AuthorizationContract {
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
            && self.permissions.is_empty()
            && self.templates.is_empty()
            && self.hybrid_enforcement.resources.is_empty()
            && !self.management_api.enabled
    }

    pub fn scope(&self, name: &str) -> Option<&AuthorizationScope> {
        self.scopes.iter().find(|scope| scope.name == name)
    }

    pub fn permission(&self, name: &str) -> Option<&AuthorizationPermission> {
        self.permissions
            .iter()
            .find(|permission| permission.name == name)
    }

    pub fn template(&self, name: &str) -> Option<&AuthorizationTemplate> {
        self.templates.iter().find(|template| template.name == name)
    }

    pub fn hybrid_resource(&self, name: &str) -> Option<&AuthorizationHybridResource> {
        self.hybrid_enforcement.resource(name)
    }
}

impl AuthorizationScopedAssignmentRecord {
    pub fn new(
        user_id: i64,
        target: AuthorizationScopedAssignmentTarget,
        scope: AuthorizationScopeBinding,
    ) -> Self {
        Self {
            id: new_runtime_assignment_id(),
            user_id,
            target,
            scope,
            created_at: runtime_assignment_timestamp_now(),
            created_by_user_id: None,
            expires_at: None,
        }
    }

    pub fn with_created_by_user_id(mut self, created_by_user_id: i64) -> Self {
        self.created_by_user_id = Some(created_by_user_id);
        self
    }

    pub fn with_expires_at(mut self, expires_at: Option<String>) -> Self {
        self.expires_at = expires_at;
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        let created_at = parse_runtime_assignment_timestamp("created_at", &self.created_at)?;
        if let Some(expires_at) = &self.expires_at {
            let expires_at = parse_runtime_assignment_timestamp("expires_at", expires_at)?;
            if expires_at <= created_at {
                return Err(
                    "runtime assignment `expires_at` must be later than `created_at`".to_owned(),
                );
            }
        }
        Ok(())
    }

    pub fn is_active_at(&self, timestamp: &DateTime<Utc>) -> Result<bool, String> {
        match self.expires_at.as_deref() {
            Some(expires_at) => {
                Ok(parse_runtime_assignment_timestamp("expires_at", expires_at)? > *timestamp)
            }
            None => Ok(true),
        }
    }

    pub fn scoped_assignment(&self) -> AuthorizationScopedAssignment {
        AuthorizationScopedAssignment {
            id: self.id.clone(),
            target: self.target.clone(),
            scope: self.scope.clone(),
        }
    }

    pub fn event(
        &self,
        event: AuthorizationScopedAssignmentEventKind,
        actor_user_id: Option<i64>,
        reason: Option<String>,
    ) -> AuthorizationScopedAssignmentEventRecord {
        AuthorizationScopedAssignmentEventRecord {
            id: new_runtime_assignment_event_id(),
            assignment_id: self.id.clone(),
            user_id: self.user_id,
            event,
            occurred_at: runtime_assignment_timestamp_now(),
            actor_user_id,
            target: self.target.clone(),
            scope: self.scope.clone(),
            expires_at: self.expires_at.clone(),
            reason,
        }
    }
}

impl AuthorizationScopedAssignmentCreateInput {
    pub fn into_record(
        self,
        created_by_user_id: Option<i64>,
    ) -> Result<AuthorizationScopedAssignmentRecord, String> {
        let mut record =
            AuthorizationScopedAssignmentRecord::new(self.user_id, self.target, self.scope)
                .with_expires_at(self.expires_at);
        if let Some(created_by_user_id) = created_by_user_id {
            record = record.with_created_by_user_id(created_by_user_id);
        }
        record.validate()?;
        Ok(record)
    }
}

impl AuthorizationCondition {
    pub fn all(conditions: Vec<Self>) -> Option<Self> {
        collapse_conditions(conditions, |conditions| Self::All {
            id: "condition.all".to_owned(),
            conditions,
        })
    }

    pub fn any(conditions: Vec<Self>) -> Option<Self> {
        collapse_conditions(conditions, |conditions| Self::Any {
            id: "condition.any".to_owned(),
            conditions,
        })
    }

    pub(super) fn collect_fields(&self, fields: &mut BTreeSet<String>) {
        match self {
            Self::Match(rule) => {
                fields.insert(rule.field.clone());
            }
            Self::All { conditions, .. } | Self::Any { conditions, .. } => {
                for condition in conditions {
                    condition.collect_fields(fields);
                }
            }
            Self::Not { condition, .. } => condition.collect_fields(fields),
            Self::Exists { conditions, .. } => {
                for condition in conditions {
                    collect_exists_controlled_fields(condition, fields);
                }
            }
        }
    }
}

fn collect_exists_controlled_fields(
    condition: &AuthorizationExistsCondition,
    fields: &mut BTreeSet<String>,
) {
    match condition {
        AuthorizationExistsCondition::Match(_) => {}
        AuthorizationExistsCondition::CurrentRowField { row_field, .. } => {
            fields.insert(row_field.clone());
        }
        AuthorizationExistsCondition::All { conditions, .. }
        | AuthorizationExistsCondition::Any { conditions, .. } => {
            for condition in conditions {
                collect_exists_controlled_fields(condition, fields);
            }
        }
        AuthorizationExistsCondition::Not { condition, .. } => {
            collect_exists_controlled_fields(condition, fields)
        }
    }
}

fn collapse_conditions(
    mut conditions: Vec<AuthorizationCondition>,
    wrap: impl FnOnce(Vec<AuthorizationCondition>) -> AuthorizationCondition,
) -> Option<AuthorizationCondition> {
    match conditions.len() {
        0 => None,
        1 => conditions.pop(),
        _ => Some(wrap(conditions)),
    }
}

impl AuthorizationPermission {
    pub(crate) fn supports_scope(&self, scope_name: &str) -> bool {
        self.scopes.is_empty() || self.scopes.iter().any(|scope| scope == scope_name)
    }

    pub(crate) fn matches_resource_action(
        &self,
        resource: &str,
        action: AuthorizationAction,
    ) -> bool {
        self.resources.iter().any(|candidate| candidate == resource)
            && self.actions.contains(&action)
    }
}

impl AuthorizationTemplate {
    pub(super) fn supports_scope(&self, scope_name: &str) -> bool {
        self.scopes.is_empty() || self.scopes.iter().any(|scope| scope == scope_name)
    }
}

impl AuthorizationConditionTrace {
    pub fn matched(&self) -> bool {
        match self {
            Self::Match { matched, .. }
            | Self::All { matched, .. }
            | Self::Any { matched, .. }
            | Self::Not { matched, .. }
            | Self::Exists { matched, .. } => *matched,
        }
    }

    pub fn is_indeterminate(&self) -> bool {
        match self {
            Self::Match { indeterminate, .. }
            | Self::All { indeterminate, .. }
            | Self::Any { indeterminate, .. }
            | Self::Not { indeterminate, .. }
            | Self::Exists { indeterminate, .. } => *indeterminate,
        }
    }

    pub fn has_missing_field(&self) -> bool {
        match self {
            Self::Match { missing_field, .. } => *missing_field,
            Self::All { conditions, .. } | Self::Any { conditions, .. } => {
                conditions.iter().any(Self::has_missing_field)
            }
            Self::Not { condition, .. } => condition.has_missing_field(),
            Self::Exists { conditions, .. } => {
                conditions.iter().any(exists_trace_has_missing_field)
            }
        }
    }

    pub fn has_missing_source(&self) -> bool {
        match self {
            Self::Match { missing_source, .. } => *missing_source,
            Self::All { conditions, .. } | Self::Any { conditions, .. } => {
                conditions.iter().any(Self::has_missing_source)
            }
            Self::Not { condition, .. } => condition.has_missing_source(),
            Self::Exists { conditions, .. } => {
                conditions.iter().any(exists_trace_has_missing_source)
            }
        }
    }

    pub fn has_missing_related_rows(&self) -> bool {
        match self {
            Self::Match { .. } => false,
            Self::All { conditions, .. } | Self::Any { conditions, .. } => {
                conditions.iter().any(Self::has_missing_related_rows)
            }
            Self::Not { condition, .. } => condition.has_missing_related_rows(),
            Self::Exists {
                missing_related_rows,
                ..
            } => *missing_related_rows,
        }
    }

    pub fn has_missing_related_fields(&self) -> bool {
        match self {
            Self::Match { .. } => false,
            Self::All { conditions, .. } | Self::Any { conditions, .. } => {
                conditions.iter().any(Self::has_missing_related_fields)
            }
            Self::Not { condition, .. } => condition.has_missing_related_fields(),
            Self::Exists {
                missing_related_fields,
                conditions,
                ..
            } => {
                *missing_related_fields
                    || conditions
                        .iter()
                        .any(exists_trace_has_missing_related_field)
            }
        }
    }
}

pub(super) fn exists_trace_matched(trace: &AuthorizationExistsConditionTrace) -> bool {
    match trace {
        AuthorizationExistsConditionTrace::Match { matched, .. }
        | AuthorizationExistsConditionTrace::CurrentRowField { matched, .. }
        | AuthorizationExistsConditionTrace::All { matched, .. }
        | AuthorizationExistsConditionTrace::Any { matched, .. }
        | AuthorizationExistsConditionTrace::Not { matched, .. } => *matched,
    }
}

pub(super) fn exists_trace_is_indeterminate(trace: &AuthorizationExistsConditionTrace) -> bool {
    match trace {
        AuthorizationExistsConditionTrace::Match { indeterminate, .. }
        | AuthorizationExistsConditionTrace::CurrentRowField { indeterminate, .. }
        | AuthorizationExistsConditionTrace::All { indeterminate, .. }
        | AuthorizationExistsConditionTrace::Any { indeterminate, .. }
        | AuthorizationExistsConditionTrace::Not { indeterminate, .. } => *indeterminate,
    }
}

pub(super) fn exists_trace_has_missing_field(trace: &AuthorizationExistsConditionTrace) -> bool {
    match trace {
        AuthorizationExistsConditionTrace::Match { .. } => false,
        AuthorizationExistsConditionTrace::CurrentRowField {
            missing_row_field, ..
        } => *missing_row_field,
        AuthorizationExistsConditionTrace::All { conditions, .. }
        | AuthorizationExistsConditionTrace::Any { conditions, .. } => {
            conditions.iter().any(exists_trace_has_missing_field)
        }
        AuthorizationExistsConditionTrace::Not { condition, .. } => {
            exists_trace_has_missing_field(condition)
        }
    }
}

pub(super) fn exists_trace_has_missing_source(trace: &AuthorizationExistsConditionTrace) -> bool {
    match trace {
        AuthorizationExistsConditionTrace::Match { missing_source, .. } => *missing_source,
        AuthorizationExistsConditionTrace::CurrentRowField { .. } => false,
        AuthorizationExistsConditionTrace::All { conditions, .. }
        | AuthorizationExistsConditionTrace::Any { conditions, .. } => {
            conditions.iter().any(exists_trace_has_missing_source)
        }
        AuthorizationExistsConditionTrace::Not { condition, .. } => {
            exists_trace_has_missing_source(condition)
        }
    }
}

pub(super) fn exists_trace_has_missing_related_field(
    trace: &AuthorizationExistsConditionTrace,
) -> bool {
    match trace {
        AuthorizationExistsConditionTrace::Match {
            missing_related_field,
            ..
        }
        | AuthorizationExistsConditionTrace::CurrentRowField {
            missing_related_field,
            ..
        } => *missing_related_field,
        AuthorizationExistsConditionTrace::All { conditions, .. }
        | AuthorizationExistsConditionTrace::Any { conditions, .. } => conditions
            .iter()
            .any(exists_trace_has_missing_related_field),
        AuthorizationExistsConditionTrace::Not { condition, .. } => {
            exists_trace_has_missing_related_field(condition)
        }
    }
}

#[derive(Default)]
pub(super) struct ResolvedRuntimeAssignments {
    pub(super) traces: Vec<AuthorizationScopedAssignmentTrace>,
    pub(super) permissions: std::collections::BTreeSet<String>,
    pub(super) templates: std::collections::BTreeSet<String>,
}
