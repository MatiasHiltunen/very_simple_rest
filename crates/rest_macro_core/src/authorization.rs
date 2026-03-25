use std::collections::{BTreeMap, BTreeSet};

use actix_web::{HttpResponse, Responder, web};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    auth::{AuthClaimType, AuthDbBackend, UserContext},
    db::{DbPool, query},
    errors,
};

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
        self.actions.iter().any(|candidate| *candidate == action)
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
    model: AuthorizationModel,
    pool: DbPool,
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

impl ResourceAuthorization {
    pub fn action(&self, action: AuthorizationAction) -> Option<&ActionAuthorization> {
        self.actions
            .iter()
            .find(|candidate| candidate.action == action)
    }

    pub fn controlled_fields(&self) -> BTreeSet<String> {
        let mut fields = BTreeSet::new();
        for action in &self.actions {
            if let Some(filter) = &action.filter {
                filter.collect_fields(&mut fields);
            }
            for assignment in &action.assignments {
                fields.insert(assignment.field.clone());
            }
        }
        fields
    }

    pub fn simulate_action(
        &self,
        input: &AuthorizationSimulationInput,
    ) -> Option<AuthorizationSimulationResult> {
        let action = self.action(input.action)?;
        let admin = input.is_admin();
        let required_role = action.required_role.clone();
        let role_check_passed = required_role
            .as_deref()
            .map(|role| admin || input.roles.iter().any(|candidate| candidate == role))
            .unwrap_or(true);

        let mut notes = Vec::new();
        let mut filter_trace = None;
        let mut assignments = Vec::new();
        let mut outcome = if role_check_passed {
            AuthorizationOutcome::Allowed
        } else {
            notes.push(format!(
                "Missing required role `{}`",
                required_role.as_deref().unwrap_or("unknown")
            ));
            AuthorizationOutcome::Denied
        };

        let admin_bypass_applied =
            role_check_passed && admin && self.admin_bypass && action.filter.is_some();

        if role_check_passed {
            assignments = action
                .assignments
                .iter()
                .map(|assignment| evaluate_assignment_trace(self, input, admin, assignment))
                .collect();

            let filter_input = if input.action == AuthorizationAction::Create {
                create_filter_input(input, &assignments)
            } else {
                input.clone()
            };

            if admin_bypass_applied {
                notes.push("Admin bypass skipped row filter evaluation".to_owned());
            } else if let Some(filter) = &action.filter {
                let trace = evaluate_condition_trace(filter, &filter_input);
                if trace.is_indeterminate() && trace.has_missing_field() {
                    notes.push(if input.action == AuthorizationAction::Create {
                        "Simulation create payload is missing one or more fields required by create.require"
                            .to_owned()
                    } else {
                        "Simulation row is missing one or more policy fields".to_owned()
                    });
                    outcome = AuthorizationOutcome::Incomplete;
                } else if trace.is_indeterminate() && trace.has_missing_related_rows() {
                    notes.push(
                        if input.action == AuthorizationAction::Create {
                            "Simulation is missing related rows required by relation-aware create.require exists policies"
                                .to_owned()
                        } else {
                            "Simulation is missing related rows required by relation-aware exists policies"
                                .to_owned()
                        },
                    );
                    outcome = AuthorizationOutcome::Incomplete;
                } else if trace.is_indeterminate() && trace.has_missing_related_fields() {
                    notes.push(
                        if input.action == AuthorizationAction::Create {
                            "Related rows are missing one or more fields required by relation-aware create.require exists policies"
                                .to_owned()
                        } else {
                            "Related rows are missing one or more fields required by relation-aware exists policies"
                                .to_owned()
                        },
                    );
                    outcome = AuthorizationOutcome::Incomplete;
                } else if trace.is_indeterminate() && trace.has_missing_source() {
                    notes.push(if input.action == AuthorizationAction::Create {
                        "Missing principal or input values required by create.require".to_owned()
                    } else {
                        "Missing principal values required by the row policy".to_owned()
                    });
                    outcome = AuthorizationOutcome::Denied;
                } else if !trace.matched() {
                    notes.push(if input.action == AuthorizationAction::Create {
                        "Create requirement conditions did not match".to_owned()
                    } else {
                        "Row policy conditions did not match".to_owned()
                    });
                    outcome = AuthorizationOutcome::Denied;
                }
                filter_trace = Some(trace);
            }

            if assignments
                .iter()
                .any(|assignment| assignment.missing_source && !assignment.admin_override_applied)
            {
                notes.push(
                    "Missing principal values required by create-time assignments".to_owned(),
                );
                outcome = AuthorizationOutcome::Denied;
            }
        }

        let controlled_fields = self.controlled_fields().into_iter().collect::<Vec<_>>();

        Some(AuthorizationSimulationResult {
            resource_id: self.id.clone(),
            resource: self.resource.clone(),
            action_id: action.id.clone(),
            action: input.action,
            outcome,
            allowed: matches!(outcome, AuthorizationOutcome::Allowed),
            admin,
            role_check_passed,
            role_rule_id: action.role_rule_id.clone(),
            required_role,
            admin_bypass_applied,
            filter: filter_trace,
            assignments,
            scope: None,
            runtime_assignments: Vec::new(),
            resolved_permissions: Vec::new(),
            resolved_templates: Vec::new(),
            controlled_fields,
            hybrid: None,
            notes,
        })
    }
}

impl AuthorizationModel {
    pub fn resource(&self, name: &str) -> Option<&ResourceAuthorization> {
        self.resources
            .iter()
            .find(|resource| resource.resource == name || resource.table == name)
    }

    pub fn validate_scoped_assignments(
        &self,
        assignments: &[AuthorizationScopedAssignment],
    ) -> Result<(), String> {
        for assignment in assignments {
            if assignment.scope.scope.trim().is_empty() {
                return Err(format!(
                    "runtime assignment `{}` has an empty scope name",
                    assignment.id
                ));
            }
            if assignment.scope.value.trim().is_empty() {
                return Err(format!(
                    "runtime assignment `{}` has an empty scope value",
                    assignment.id
                ));
            }
            if self.contract.scope(&assignment.scope.scope).is_none() {
                return Err(format!(
                    "runtime assignment `{}` references undeclared scope `{}`",
                    assignment.id, assignment.scope.scope
                ));
            }

            match &assignment.target {
                AuthorizationScopedAssignmentTarget::Permission { name } => {
                    let permission = self.contract.permission(name).ok_or_else(|| {
                        format!(
                            "runtime assignment `{}` references undeclared permission `{name}`",
                            assignment.id
                        )
                    })?;
                    if !permission.supports_scope(&assignment.scope.scope) {
                        return Err(format!(
                            "runtime assignment `{}` uses scope `{}` but permission `{name}` only supports [{}]",
                            assignment.id,
                            assignment.scope.scope,
                            if permission.scopes.is_empty() {
                                "any".to_owned()
                            } else {
                                permission.scopes.join(", ")
                            }
                        ));
                    }
                }
                AuthorizationScopedAssignmentTarget::Template { name } => {
                    let template = self.contract.template(name).ok_or_else(|| {
                        format!(
                            "runtime assignment `{}` references undeclared template `{name}`",
                            assignment.id
                        )
                    })?;
                    if !template.supports_scope(&assignment.scope.scope) {
                        return Err(format!(
                            "runtime assignment `{}` uses scope `{}` but template `{name}` only supports [{}]",
                            assignment.id,
                            assignment.scope.scope,
                            if template.scopes.is_empty() {
                                "any".to_owned()
                            } else {
                                template.scopes.join(", ")
                            }
                        ));
                    }
                    for permission_name in &template.permissions {
                        let permission = self.contract.permission(permission_name).ok_or_else(|| {
                            format!(
                                "template `{name}` references undeclared permission `{permission_name}`"
                            )
                        })?;
                        if !permission.supports_scope(&assignment.scope.scope) {
                            return Err(format!(
                                "runtime assignment `{}` uses scope `{}` but template permission `{permission_name}` only supports [{}]",
                                assignment.id,
                                assignment.scope.scope,
                                if permission.scopes.is_empty() {
                                    "any".to_owned()
                                } else {
                                    permission.scopes.join(", ")
                                }
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn simulate_resource_action(
        &self,
        resource_name: Option<&str>,
        input: &AuthorizationSimulationInput,
    ) -> Result<AuthorizationSimulationResult, String> {
        let resource = match resource_name {
            Some(name) => self
                .resource(name)
                .ok_or_else(|| format!("resource `{name}` not found in authorization model"))?,
            None => match self.resources.as_slice() {
                [resource] => resource,
                _ => {
                    return Err(
                        "multiple resources found; pass --resource to select one".to_owned()
                    );
                }
            },
        };

        if !input.scoped_assignments.is_empty() && input.scope.is_none() {
            if input.hybrid_source.is_none() {
                return Err(
                    "runtime scoped assignments require a simulated scope; pass `--scope ScopeName=value`"
                        .to_owned(),
                );
            }
        }

        self.validate_scoped_assignments(&input.scoped_assignments)?;

        let mut result = resource.simulate_action(input).ok_or_else(|| {
            format!(
                "resource `{}` does not define the requested action",
                resource.resource
            )
        })?;

        let mut runtime_input = input.clone();
        let hybrid = if let Some(source) = input.hybrid_source {
            let hybrid = self.simulate_hybrid_resource_action(resource, &result, input, source)?;
            runtime_input.scope = hybrid.scope.clone();
            Some(hybrid)
        } else {
            None
        };

        let resolved = self.resolve_runtime_assignments(resource, &runtime_input);
        result.scope = runtime_input.scope.clone();
        result.runtime_assignments = resolved.traces;
        result.resolved_permissions = resolved.permissions.into_iter().collect();
        result.resolved_templates = resolved.templates.into_iter().collect();
        result.hybrid = hybrid;
        if result.hybrid.is_none() && !result.runtime_assignments.is_empty() {
            result.notes.push(
                "Resolved runtime scoped assignments; generated handlers do not enforce them yet"
                    .to_owned(),
            );
        }

        Ok(result)
    }

    pub fn evaluate_runtime_access(
        &self,
        resource_name: &str,
        action: AuthorizationAction,
        user_id: i64,
        scope: AuthorizationScopeBinding,
        scoped_assignments: &[AuthorizationScopedAssignment],
    ) -> Result<AuthorizationRuntimeAccessResult, String> {
        let resource = self.resource(resource_name).ok_or_else(|| {
            format!("resource `{resource_name}` not found in authorization model")
        })?;
        let action_model = resource.action(action).ok_or_else(|| {
            format!(
                "resource `{}` does not define the requested action",
                resource.resource
            )
        })?;

        if self.contract.scope(&scope.scope).is_none() {
            return Err(format!(
                "runtime access references undeclared scope `{}`",
                scope.scope
            ));
        }

        self.validate_scoped_assignments(scoped_assignments)?;
        let input = AuthorizationSimulationInput {
            action,
            user_id: Some(user_id),
            roles: Vec::new(),
            claims: BTreeMap::new(),
            row: BTreeMap::new(),
            proposed: BTreeMap::new(),
            related_rows: BTreeMap::new(),
            scope: Some(scope.clone()),
            hybrid_source: None,
            scoped_assignments: scoped_assignments.to_vec(),
        };
        let resolved = self.resolve_runtime_assignments(resource, &input);
        let mut notes = vec![
            "Runtime access evaluation only considers persisted scoped permissions and templates"
                .to_owned(),
            "Static roles, row policies, and create-time assignments are not evaluated here"
                .to_owned(),
        ];
        if resolved.permissions.is_empty() {
            notes.push(
                "No runtime scoped permissions resolved for the requested resource action"
                    .to_owned(),
            );
        }

        Ok(AuthorizationRuntimeAccessResult {
            user_id,
            resource_id: resource.id.clone(),
            resource: resource.resource.clone(),
            action_id: action_model.id.clone(),
            action,
            scope,
            allowed: !resolved.permissions.is_empty(),
            resolved_permissions: resolved.permissions.into_iter().collect(),
            resolved_templates: resolved.templates.into_iter().collect(),
            runtime_assignments: resolved.traces,
            notes,
        })
    }

    fn simulate_hybrid_resource_action(
        &self,
        resource: &ResourceAuthorization,
        static_result: &AuthorizationSimulationResult,
        input: &AuthorizationSimulationInput,
        source: AuthorizationHybridSource,
    ) -> Result<AuthorizationHybridSimulationTrace, String> {
        let hybrid = self
            .contract
            .hybrid_resource(&resource.resource)
            .ok_or_else(|| {
                format!(
                    "resource `{}` does not declare `authorization.hybrid_enforcement`",
                    resource.resource
                )
            })?;
        if !hybrid.scope_sources.supports(source) {
            return Err(format!(
                "resource `{}` does not allow hybrid source `{}`",
                resource.resource,
                hybrid_source_label(source)
            ));
        }
        if !hybrid_supports_action(hybrid, source, input.action) {
            return Err(format!(
                "hybrid source `{}` is not valid for `{} {}`",
                hybrid_source_label(source),
                resource.resource,
                authorization_action_label(input.action)
            ));
        }

        let mut notes = vec![format!(
            "Hybrid simulation models generated handler behavior for the `{}` source",
            hybrid_source_label(source)
        )];
        let scope = derive_hybrid_scope_binding(hybrid, input, source, &mut notes);
        let mut runtime_input = input.clone();
        runtime_input.scope = scope.clone();
        let resolved = self.resolve_runtime_assignments(resource, &runtime_input);
        let runtime_allowed = !resolved.permissions.is_empty();

        let (effective_outcome, fallback_applied, skip_static_row_policy) = match source {
            AuthorizationHybridSource::Item => simulate_item_hybrid_outcome(
                static_result,
                scope.as_ref(),
                runtime_allowed,
                &mut notes,
            ),
            AuthorizationHybridSource::CreatePayload => simulate_create_hybrid_outcome(
                static_result,
                scope.as_ref(),
                runtime_allowed,
                &hybrid.scope_field,
                &mut notes,
            ),
            AuthorizationHybridSource::CollectionFilter
            | AuthorizationHybridSource::NestedParent => simulate_collection_hybrid_outcome(
                static_result,
                scope.as_ref(),
                runtime_allowed,
                source,
                &mut notes,
            ),
        };

        Ok(AuthorizationHybridSimulationTrace {
            source,
            scope,
            runtime_allowed,
            effective_outcome,
            effective_allowed: matches!(effective_outcome, AuthorizationOutcome::Allowed),
            fallback_applied,
            skip_static_row_policy,
            notes,
        })
    }

    fn resolve_runtime_assignments(
        &self,
        resource: &ResourceAuthorization,
        input: &AuthorizationSimulationInput,
    ) -> ResolvedRuntimeAssignments {
        let mut resolved = ResolvedRuntimeAssignments::default();
        let Some(scope) = &input.scope else {
            return resolved;
        };

        for assignment in &input.scoped_assignments {
            let scope_matched = assignment.scope == *scope;
            let mut target_matched = false;
            let mut resolved_permissions = Vec::new();
            let mut resolved_template = None;

            if scope_matched {
                match &assignment.target {
                    AuthorizationScopedAssignmentTarget::Permission { name } => {
                        if let Some(permission) = self.contract.permission(name) {
                            if permission.matches_resource_action(&resource.resource, input.action)
                            {
                                target_matched = true;
                                resolved_permissions.push(permission.name.clone());
                                resolved.permissions.insert(permission.name.clone());
                            }
                        }
                    }
                    AuthorizationScopedAssignmentTarget::Template { name } => {
                        if let Some(template) = self.contract.template(name) {
                            let template_permissions = template
                                .permissions
                                .iter()
                                .filter_map(|permission_name| {
                                    self.contract.permission(permission_name)
                                })
                                .filter(|permission| {
                                    permission
                                        .matches_resource_action(&resource.resource, input.action)
                                })
                                .map(|permission| permission.name.clone())
                                .collect::<Vec<_>>();
                            if !template_permissions.is_empty() {
                                target_matched = true;
                                resolved
                                    .permissions
                                    .extend(template_permissions.iter().cloned());
                                resolved.templates.insert(template.name.clone());
                                resolved_permissions = template_permissions;
                                resolved_template = Some(template.name.clone());
                            }
                        }
                    }
                }
            }

            resolved.traces.push(AuthorizationScopedAssignmentTrace {
                id: assignment.id.clone(),
                target: assignment.target.clone(),
                scope: assignment.scope.clone(),
                scope_matched,
                target_matched,
                created_at: None,
                created_by_user_id: None,
                expires_at: None,
                expired: false,
                resolved_permissions,
                resolved_template,
            });
        }

        resolved
    }
}

impl AuthorizationRuntime {
    pub fn new(model: AuthorizationModel, pool: impl Into<DbPool>) -> Self {
        Self {
            model,
            pool: pool.into(),
        }
    }

    pub fn model(&self) -> &AuthorizationModel {
        &self.model
    }

    pub fn pool(&self) -> &DbPool {
        &self.pool
    }

    pub async fn list_assignments_for_user(
        &self,
        user_id: i64,
    ) -> Result<Vec<AuthorizationScopedAssignmentRecord>, String> {
        list_runtime_assignments_for_user(&self.pool, user_id).await
    }

    pub async fn list_assignment_events_for_user(
        &self,
        user_id: i64,
    ) -> Result<Vec<AuthorizationScopedAssignmentEventRecord>, String> {
        list_runtime_assignment_events_for_user(&self.pool, user_id).await
    }

    pub async fn create_assignment(
        &self,
        assignment: AuthorizationScopedAssignmentRecord,
    ) -> Result<AuthorizationScopedAssignmentRecord, String> {
        assignment.validate()?;
        self.model
            .validate_scoped_assignments(std::slice::from_ref(&assignment.scoped_assignment()))?;
        create_runtime_assignment_with_audit(&self.pool, assignment.clone()).await?;
        Ok(assignment)
    }

    pub async fn delete_assignment(&self, assignment_id: &str) -> Result<bool, String> {
        self.delete_assignment_with_audit(assignment_id, None, None)
            .await
    }

    pub async fn delete_assignment_with_audit(
        &self,
        assignment_id: &str,
        actor_user_id: Option<i64>,
        reason: Option<String>,
    ) -> Result<bool, String> {
        delete_runtime_assignment_with_audit(&self.pool, assignment_id, actor_user_id, reason).await
    }

    pub async fn revoke_assignment_with_audit(
        &self,
        assignment_id: &str,
        actor_user_id: Option<i64>,
        reason: Option<String>,
    ) -> Result<Option<AuthorizationScopedAssignmentRecord>, String> {
        revoke_runtime_assignment_with_audit(&self.pool, assignment_id, actor_user_id, reason).await
    }

    pub async fn renew_assignment_with_audit(
        &self,
        assignment_id: &str,
        expires_at: &str,
        actor_user_id: Option<i64>,
        reason: Option<String>,
    ) -> Result<Option<AuthorizationScopedAssignmentRecord>, String> {
        renew_runtime_assignment_with_audit(
            &self.pool,
            assignment_id,
            expires_at,
            actor_user_id,
            reason,
        )
        .await
    }

    pub async fn simulate_resource_action_with_user_assignments(
        &self,
        resource_name: Option<&str>,
        mut input: AuthorizationSimulationInput,
    ) -> Result<AuthorizationSimulationResult, String> {
        if let Some(user_id) = input.user_id {
            let mut stored = load_runtime_assignments_for_user(&self.pool, user_id).await?;
            input.scoped_assignments.append(&mut stored);
        }
        self.model
            .simulate_resource_action(resource_name, &input.normalized())
    }

    pub async fn evaluate_runtime_access_for_user(
        &self,
        user_id: i64,
        resource_name: &str,
        action: AuthorizationAction,
        scope: AuthorizationScopeBinding,
    ) -> Result<AuthorizationRuntimeAccessResult, String> {
        let assignments = load_runtime_assignments_for_user(&self.pool, user_id).await?;
        self.model
            .evaluate_runtime_access(resource_name, action, user_id, scope, &assignments)
    }

    pub async fn enforce_runtime_access(
        &self,
        user: &UserContext,
        resource_name: &str,
        action: AuthorizationAction,
        scope: AuthorizationScopeBinding,
    ) -> Result<AuthorizationRuntimeAccessResult, HttpResponse> {
        match self
            .evaluate_runtime_access_for_user(user.id, resource_name, action, scope)
            .await
        {
            Ok(result) if result.allowed => Ok(result),
            Ok(_) => Err(errors::forbidden(
                "runtime_access_denied",
                "Runtime authorization denied",
            )),
            Err(message) => Err(errors::internal_error(message)),
        }
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
            && self.actions.iter().any(|candidate| *candidate == action)
    }
}

impl AuthorizationTemplate {
    fn supports_scope(&self, scope_name: &str) -> bool {
        self.scopes.is_empty() || self.scopes.iter().any(|scope| scope == scope_name)
    }
}

pub fn authorization_runtime_migration_sql(backend: AuthDbBackend) -> String {
    let id_column = match backend {
        AuthDbBackend::Sqlite | AuthDbBackend::Postgres => "id TEXT PRIMARY KEY",
        AuthDbBackend::Mysql => "id VARCHAR(191) PRIMARY KEY",
    };
    let target_kind_column = match backend {
        AuthDbBackend::Sqlite | AuthDbBackend::Postgres => "target_kind TEXT NOT NULL",
        AuthDbBackend::Mysql => "target_kind VARCHAR(32) NOT NULL",
    };
    let target_name_column = match backend {
        AuthDbBackend::Sqlite | AuthDbBackend::Postgres => "target_name TEXT NOT NULL",
        AuthDbBackend::Mysql => "target_name VARCHAR(191) NOT NULL",
    };
    let scope_name_column = match backend {
        AuthDbBackend::Sqlite | AuthDbBackend::Postgres => "scope_name TEXT NOT NULL",
        AuthDbBackend::Mysql => "scope_name VARCHAR(191) NOT NULL",
    };
    let scope_value_column = match backend {
        AuthDbBackend::Sqlite | AuthDbBackend::Postgres => "scope_value TEXT NOT NULL",
        AuthDbBackend::Mysql => "scope_value VARCHAR(191) NOT NULL",
    };
    let user_id_column = match backend {
        AuthDbBackend::Sqlite => "user_id INTEGER NOT NULL",
        AuthDbBackend::Postgres | AuthDbBackend::Mysql => "user_id BIGINT NOT NULL",
    };
    let created_by_user_id_column = match backend {
        AuthDbBackend::Sqlite => "created_by_user_id INTEGER",
        AuthDbBackend::Postgres | AuthDbBackend::Mysql => "created_by_user_id BIGINT",
    };
    let created_at_column = match backend {
        AuthDbBackend::Sqlite | AuthDbBackend::Postgres => "created_at TEXT NOT NULL",
        AuthDbBackend::Mysql => "created_at VARCHAR(64) NOT NULL",
    };
    let expires_at_column = match backend {
        AuthDbBackend::Sqlite | AuthDbBackend::Postgres => "expires_at TEXT",
        AuthDbBackend::Mysql => "expires_at VARCHAR(64)",
    };
    let event_kind_column = match backend {
        AuthDbBackend::Sqlite | AuthDbBackend::Postgres => "event_kind TEXT NOT NULL",
        AuthDbBackend::Mysql => "event_kind VARCHAR(32) NOT NULL",
    };
    let assignment_id_column = match backend {
        AuthDbBackend::Sqlite | AuthDbBackend::Postgres => "assignment_id TEXT NOT NULL",
        AuthDbBackend::Mysql => "assignment_id VARCHAR(191) NOT NULL",
    };
    let reason_column = match backend {
        AuthDbBackend::Sqlite | AuthDbBackend::Postgres => "reason TEXT",
        AuthDbBackend::Mysql => "reason TEXT",
    };

    format!(
        "-- Generated by very_simple_rest for runtime authorization assignments.\n\n\
         CREATE TABLE {table} (\n\
             {id_column},\n\
             {user_id_column},\n\
             {created_by_user_id_column},\n\
             {created_at_column},\n\
             {expires_at_column},\n\
             {target_kind_column},\n\
             {target_name_column},\n\
             {scope_name_column},\n\
             {scope_value_column}\n\
         );\n\n\
         CREATE INDEX idx_{table}_user ON {table} (user_id);\n\
         CREATE INDEX idx_{table}_scope ON {table} (scope_name, scope_value);\n\n\
         CREATE TABLE {event_table} (\n\
             {id_column},\n\
             {assignment_id_column},\n\
             {user_id_column},\n\
             {created_by_user_id_column},\n\
             {created_at_column},\n\
             {event_kind_column},\n\
             {target_kind_column},\n\
             {target_name_column},\n\
             {scope_name_column},\n\
             {scope_value_column},\n\
             {expires_at_column},\n\
             {reason_column}\n\
         );\n\n\
         CREATE INDEX idx_{event_table}_user ON {event_table} (user_id, created_at);\n\
         CREATE INDEX idx_{event_table}_assignment ON {event_table} (assignment_id, created_at);\n",
        table = AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE,
        event_table = AUTHORIZATION_RUNTIME_ASSIGNMENT_EVENT_TABLE,
        assignment_id_column = assignment_id_column,
    )
}

pub fn authorization_management_routes(cfg: &mut web::ServiceConfig) {
    authorization_management_routes_at(cfg, DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT);
}

pub fn authorization_management_routes_at(cfg: &mut web::ServiceConfig, mount: &str) {
    errors::configure_extractor_errors(cfg);
    let mount = normalize_management_mount(mount);
    cfg.route(
        &format!("{mount}/evaluate"),
        web::post().to(evaluate_runtime_access_endpoint),
    );
    cfg.route(
        &format!("{mount}/assignments"),
        web::get().to(list_runtime_assignments_endpoint),
    );
    cfg.route(
        &format!("{mount}/assignments"),
        web::post().to(create_runtime_assignment_endpoint),
    );
    cfg.route(
        &format!("{mount}/assignment-events"),
        web::get().to(list_runtime_assignment_events_endpoint),
    );
    cfg.route(
        &format!("{mount}/assignments/{{id}}"),
        web::delete().to(delete_runtime_assignment_endpoint),
    );
    cfg.route(
        &format!("{mount}/assignments/{{id}}/revoke"),
        web::post().to(revoke_runtime_assignment_endpoint),
    );
    cfg.route(
        &format!("{mount}/assignments/{{id}}/renew"),
        web::post().to(renew_runtime_assignment_endpoint),
    );
}

fn normalize_management_mount(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT.to_owned();
    }
    if trimmed.ends_with('/') {
        trimmed.trim_end_matches('/').to_owned()
    } else {
        trimmed.to_owned()
    }
}

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

impl AuthorizationCondition {
    fn collect_fields(&self, fields: &mut BTreeSet<String>) {
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

impl AuthorizationSimulationInput {
    pub fn normalized(mut self) -> Self {
        self.roles.sort();
        self.roles.dedup();
        self
    }

    pub fn is_admin(&self) -> bool {
        self.roles.iter().any(|role| role == "admin")
    }

    pub fn related_rows_for(
        &self,
        resource: &str,
        table: &str,
    ) -> Option<&[BTreeMap<String, Value>]> {
        self.related_rows
            .get(resource)
            .or_else(|| self.related_rows.get(table))
            .map(Vec::as_slice)
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

#[derive(Default)]
struct ResolvedRuntimeAssignments {
    traces: Vec<AuthorizationScopedAssignmentTrace>,
    permissions: BTreeSet<String>,
    templates: BTreeSet<String>,
}

const fn default_admin_bypass() -> bool {
    true
}

fn evaluate_condition_trace(
    condition: &AuthorizationCondition,
    input: &AuthorizationSimulationInput,
) -> AuthorizationConditionTrace {
    match condition {
        AuthorizationCondition::Match(rule) => {
            let row_value = input.row.get(&rule.field).cloned();
            let source_value = rule
                .source
                .as_ref()
                .and_then(|source| resolve_source_value(source, input));
            let missing_field = row_value.is_none();
            let missing_source =
                matches!(rule.operator, AuthorizationOperator::Equals) && source_value.is_none();
            let indeterminate = missing_field || missing_source;
            let matched = match (&row_value, &source_value, rule.operator) {
                (Some(row_value), Some(source_value), AuthorizationOperator::Equals) => {
                    row_value == source_value
                }
                (Some(Value::Null), _, AuthorizationOperator::IsNull) => true,
                (Some(value), _, AuthorizationOperator::IsNotNull) => !value.is_null(),
                _ => false,
            };
            AuthorizationConditionTrace::Match {
                id: rule.id.clone(),
                field: rule.field.clone(),
                operator: rule.operator,
                source: rule.source.clone(),
                row_value,
                source_value,
                matched,
                indeterminate,
                missing_field,
                missing_source,
            }
        }
        AuthorizationCondition::All { id, conditions } => {
            let conditions = conditions
                .iter()
                .map(|condition| evaluate_condition_trace(condition, input))
                .collect::<Vec<_>>();
            let any_definite_false = conditions
                .iter()
                .any(|condition| !condition.matched() && !condition.is_indeterminate());
            let indeterminate = !any_definite_false
                && conditions
                    .iter()
                    .any(AuthorizationConditionTrace::is_indeterminate);
            let matched =
                !indeterminate && conditions.iter().all(AuthorizationConditionTrace::matched);
            AuthorizationConditionTrace::All {
                id: id.clone(),
                matched,
                indeterminate,
                conditions,
            }
        }
        AuthorizationCondition::Any { id, conditions } => {
            let conditions = conditions
                .iter()
                .map(|condition| evaluate_condition_trace(condition, input))
                .collect::<Vec<_>>();
            let matched = conditions.iter().any(AuthorizationConditionTrace::matched);
            let indeterminate = !matched
                && conditions
                    .iter()
                    .any(AuthorizationConditionTrace::is_indeterminate);
            AuthorizationConditionTrace::Any {
                id: id.clone(),
                matched,
                indeterminate,
                conditions,
            }
        }
        AuthorizationCondition::Not { id, condition } => {
            let condition = Box::new(evaluate_condition_trace(condition, input));
            let indeterminate = condition.is_indeterminate();
            let matched = !indeterminate && !condition.matched();
            AuthorizationConditionTrace::Not {
                id: id.clone(),
                matched,
                indeterminate,
                condition,
            }
        }
        AuthorizationCondition::Exists {
            id,
            resource,
            table,
            conditions,
        } => {
            let related_rows = input.related_rows_for(resource, table);
            let related_row_count = related_rows.map_or(0, |rows| rows.len());
            let mut matched_row_index = None;
            let mut missing_related_rows = false;
            let mut missing_related_fields = false;
            let mut condition_traces = None;
            match related_rows {
                Some(related_rows) => {
                    for (index, related_row) in related_rows.iter().enumerate() {
                        let traces = conditions
                            .iter()
                            .map(|condition| {
                                evaluate_exists_condition_trace(condition, input, Some(related_row))
                            })
                            .collect::<Vec<_>>();
                        if condition_traces.is_none() {
                            condition_traces = Some(traces.clone());
                        }
                        if traces.iter().any(exists_trace_has_missing_related_field) {
                            missing_related_fields = true;
                        }
                        let matched = traces.iter().all(exists_trace_matched)
                            && !traces.iter().any(exists_trace_is_indeterminate);
                        if matched {
                            matched_row_index = Some(index);
                            condition_traces = Some(traces);
                            break;
                        }
                    }
                }
                None => {
                    missing_related_rows = true;
                }
            }
            let conditions = condition_traces.unwrap_or_else(|| {
                conditions
                    .iter()
                    .map(|condition| evaluate_exists_condition_trace(condition, input, None))
                    .collect::<Vec<_>>()
            });
            let missing_source = conditions.iter().any(exists_trace_has_missing_source);
            let missing_row_field = conditions.iter().any(exists_trace_has_missing_field);

            let matched = matched_row_index.is_some();
            let indeterminate = !matched
                && (missing_source
                    || missing_row_field
                    || missing_related_rows
                    || missing_related_fields);
            let note = if matched {
                matched_row_index.map(|index| format!("Matched related row {}", index + 1))
            } else if missing_related_rows {
                Some(
                    "Provide related rows for this target resource to fully evaluate EXISTS"
                        .to_owned(),
                )
            } else if missing_related_fields {
                Some(
                    "One or more related rows were missing fields referenced by the EXISTS predicate"
                        .to_owned(),
                )
            } else if missing_source {
                Some("Exists predicate is missing one or more principal values".to_owned())
            } else if missing_row_field {
                Some(
                    "Simulation row is missing one or more fields referenced by the EXISTS predicate"
                        .to_owned(),
                )
            } else if related_row_count == 0 {
                Some("No related rows were supplied for the EXISTS predicate".to_owned())
            } else {
                Some("No related rows matched the EXISTS predicate".to_owned())
            };
            AuthorizationConditionTrace::Exists {
                id: id.clone(),
                resource: resource.clone(),
                table: table.clone(),
                matched,
                indeterminate,
                related_row_count,
                matched_row_index,
                missing_related_rows,
                missing_related_fields,
                conditions,
                note,
            }
        }
    }
}

fn authorization_action_label(action: AuthorizationAction) -> &'static str {
    match action {
        AuthorizationAction::Read => "read",
        AuthorizationAction::Create => "create",
        AuthorizationAction::Update => "update",
        AuthorizationAction::Delete => "delete",
    }
}

fn hybrid_source_label(source: AuthorizationHybridSource) -> &'static str {
    match source {
        AuthorizationHybridSource::Item => "item",
        AuthorizationHybridSource::CollectionFilter => "collection_filter",
        AuthorizationHybridSource::NestedParent => "nested_parent",
        AuthorizationHybridSource::CreatePayload => "create_payload",
    }
}

fn hybrid_supports_action(
    hybrid: &AuthorizationHybridResource,
    source: AuthorizationHybridSource,
    action: AuthorizationAction,
) -> bool {
    match source {
        AuthorizationHybridSource::Item => hybrid.supports_item_action(action),
        AuthorizationHybridSource::CollectionFilter => {
            action == AuthorizationAction::Read && hybrid.supports_collection_read()
        }
        AuthorizationHybridSource::NestedParent => {
            action == AuthorizationAction::Read && hybrid.supports_nested_read()
        }
        AuthorizationHybridSource::CreatePayload => hybrid.supports_item_action(action),
    }
}

fn derive_hybrid_scope_binding(
    hybrid: &AuthorizationHybridResource,
    input: &AuthorizationSimulationInput,
    source: AuthorizationHybridSource,
    notes: &mut Vec<String>,
) -> Option<AuthorizationScopeBinding> {
    match source {
        AuthorizationHybridSource::Item => derive_scope_from_map(
            &input.row,
            &hybrid.scope_field,
            &hybrid.scope,
            "simulation row",
            notes,
        ),
        AuthorizationHybridSource::CreatePayload => derive_scope_from_map(
            &input.proposed,
            &hybrid.scope_field,
            &hybrid.scope,
            "proposed create payload",
            notes,
        ),
        AuthorizationHybridSource::CollectionFilter | AuthorizationHybridSource::NestedParent => {
            match &input.scope {
                Some(scope) if scope.scope == hybrid.scope => Some(scope.clone()),
                Some(scope) => {
                    notes.push(format!(
                        "Simulated scope `{}` does not match configured hybrid scope `{}`",
                        scope.scope, hybrid.scope
                    ));
                    None
                }
                None => {
                    notes.push(format!(
                        "Hybrid `{}` simulation requires `--scope {}=<value>`",
                        hybrid_source_label(source),
                        hybrid.scope
                    ));
                    None
                }
            }
        }
    }
}

fn derive_scope_from_map(
    values: &BTreeMap<String, Value>,
    field: &str,
    scope_name: &str,
    label: &str,
    notes: &mut Vec<String>,
) -> Option<AuthorizationScopeBinding> {
    match values.get(field) {
        Some(Value::Null) => {
            notes.push(format!(
                "Hybrid scope field `{field}` is null in the {label}"
            ));
            None
        }
        Some(value) => Some(AuthorizationScopeBinding {
            scope: scope_name.to_owned(),
            value: hybrid_scope_value(value),
        }),
        None => {
            notes.push(format!(
                "Hybrid scope field `{field}` is missing from the {label}"
            ));
            None
        }
    }
}

fn hybrid_scope_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        other => other.to_string(),
    }
}

fn simulate_item_hybrid_outcome(
    static_result: &AuthorizationSimulationResult,
    scope: Option<&AuthorizationScopeBinding>,
    runtime_allowed: bool,
    notes: &mut Vec<String>,
) -> (AuthorizationOutcome, bool, bool) {
    if !static_result.role_check_passed {
        notes.push("Static role check failed before hybrid fallback could apply".to_owned());
        return (AuthorizationOutcome::Denied, false, false);
    }
    if scope.is_none() {
        return (AuthorizationOutcome::Incomplete, false, false);
    }
    if static_result.allowed {
        notes.push("Static item policy already allowed this request".to_owned());
        return (AuthorizationOutcome::Allowed, false, false);
    }
    if runtime_allowed {
        notes.push("Generated item handler would fall back to the runtime scoped grant".to_owned());
        return (AuthorizationOutcome::Allowed, true, false);
    }
    notes.push("No runtime scoped grant matched the derived item scope".to_owned());
    (AuthorizationOutcome::Denied, false, false)
}

fn simulate_create_hybrid_outcome(
    static_result: &AuthorizationSimulationResult,
    scope: Option<&AuthorizationScopeBinding>,
    runtime_allowed: bool,
    scope_field: &str,
    notes: &mut Vec<String>,
) -> (AuthorizationOutcome, bool, bool) {
    if !static_result.role_check_passed {
        notes.push("Static role check failed before hybrid create fallback could apply".to_owned());
        return (AuthorizationOutcome::Denied, false, false);
    }
    if scope.is_none() {
        return (AuthorizationOutcome::Incomplete, false, false);
    }
    let missing_non_scope_assignments = static_result.assignments.iter().any(|assignment| {
        assignment.missing_source
            && !assignment.admin_override_applied
            && assignment.field != scope_field
    });
    if missing_non_scope_assignments {
        notes.push(format!(
            "Hybrid create fallback only covers `{scope_field}`; other create-time assignments are still missing"
        ));
        return (AuthorizationOutcome::Denied, false, false);
    }
    if static_result.allowed {
        notes.push("Static create policy already allowed this request".to_owned());
        return (AuthorizationOutcome::Allowed, false, false);
    }
    if runtime_allowed {
        notes.push("Generated create handler would accept the proposed hybrid scope".to_owned());
        return (AuthorizationOutcome::Allowed, true, false);
    }
    notes.push("No runtime scoped grant matched the proposed create scope".to_owned());
    (AuthorizationOutcome::Denied, false, false)
}

fn simulate_collection_hybrid_outcome(
    static_result: &AuthorizationSimulationResult,
    scope: Option<&AuthorizationScopeBinding>,
    runtime_allowed: bool,
    source: AuthorizationHybridSource,
    notes: &mut Vec<String>,
) -> (AuthorizationOutcome, bool, bool) {
    if !static_result.role_check_passed {
        notes
            .push("Static role check failed before hybrid collection logic could apply".to_owned());
        return (AuthorizationOutcome::Denied, false, false);
    }
    if scope.is_none() {
        return (AuthorizationOutcome::Incomplete, false, false);
    }
    if runtime_allowed {
        notes.push(format!(
            "Generated `{}` read handler would skip the static read row policy for this scoped request",
            hybrid_source_label(source)
        ));
        return (AuthorizationOutcome::Allowed, false, true);
    }
    notes.push(format!(
        "No runtime scoped grant matched this `{}` request; generated handlers would keep the static read row policy",
        hybrid_source_label(source)
    ));
    (AuthorizationOutcome::Allowed, false, false)
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

fn exists_trace_matched(trace: &AuthorizationExistsConditionTrace) -> bool {
    match trace {
        AuthorizationExistsConditionTrace::Match { matched, .. }
        | AuthorizationExistsConditionTrace::CurrentRowField { matched, .. }
        | AuthorizationExistsConditionTrace::All { matched, .. }
        | AuthorizationExistsConditionTrace::Any { matched, .. }
        | AuthorizationExistsConditionTrace::Not { matched, .. } => *matched,
    }
}

fn exists_trace_is_indeterminate(trace: &AuthorizationExistsConditionTrace) -> bool {
    match trace {
        AuthorizationExistsConditionTrace::Match { indeterminate, .. }
        | AuthorizationExistsConditionTrace::CurrentRowField { indeterminate, .. }
        | AuthorizationExistsConditionTrace::All { indeterminate, .. }
        | AuthorizationExistsConditionTrace::Any { indeterminate, .. }
        | AuthorizationExistsConditionTrace::Not { indeterminate, .. } => *indeterminate,
    }
}

fn exists_trace_has_missing_field(trace: &AuthorizationExistsConditionTrace) -> bool {
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

fn exists_trace_has_missing_source(trace: &AuthorizationExistsConditionTrace) -> bool {
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

fn exists_trace_has_missing_related_field(trace: &AuthorizationExistsConditionTrace) -> bool {
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

fn evaluate_exists_condition_trace(
    condition: &AuthorizationExistsCondition,
    input: &AuthorizationSimulationInput,
    related_row: Option<&BTreeMap<String, Value>>,
) -> AuthorizationExistsConditionTrace {
    match condition {
        AuthorizationExistsCondition::Match(rule) => {
            let source_value = rule
                .source
                .as_ref()
                .and_then(|source| resolve_source_value(source, input));
            let related_value = related_row.and_then(|row| row.get(&rule.field).cloned());
            let missing_source =
                matches!(rule.operator, AuthorizationOperator::Equals) && source_value.is_none();
            let missing_related_field = related_row.is_some() && related_value.is_none();
            let indeterminate = missing_source || missing_related_field;
            let matched = match (&related_value, &source_value, rule.operator) {
                (Some(related_value), Some(source_value), AuthorizationOperator::Equals) => {
                    !indeterminate && related_value == source_value
                }
                (Some(Value::Null), _, AuthorizationOperator::IsNull) => !indeterminate,
                (Some(value), _, AuthorizationOperator::IsNotNull) => {
                    !indeterminate && !value.is_null()
                }
                _ => false,
            };
            AuthorizationExistsConditionTrace::Match {
                id: rule.id.clone(),
                field: rule.field.clone(),
                operator: rule.operator,
                source: rule.source.clone(),
                source_value,
                related_value,
                matched,
                indeterminate,
                missing_source,
                missing_related_field,
            }
        }
        AuthorizationExistsCondition::CurrentRowField {
            id,
            field,
            row_field,
        } => {
            let row_value = input.row.get(row_field).cloned();
            let related_value = related_row.and_then(|row| row.get(field).cloned());
            let missing_row_field = row_value.is_none();
            let missing_related_field = related_row.is_some() && related_value.is_none();
            let indeterminate = missing_row_field || missing_related_field;
            let matched = !indeterminate && related_value.as_ref() == row_value.as_ref();
            AuthorizationExistsConditionTrace::CurrentRowField {
                id: id.clone(),
                field: field.clone(),
                row_field: row_field.clone(),
                row_value,
                related_value,
                matched,
                indeterminate,
                missing_row_field,
                missing_related_field,
            }
        }
        AuthorizationExistsCondition::All { id, conditions } => {
            let conditions = conditions
                .iter()
                .map(|condition| evaluate_exists_condition_trace(condition, input, related_row))
                .collect::<Vec<_>>();
            let any_definite_false = conditions.iter().any(|condition| {
                !exists_trace_matched(condition) && !exists_trace_is_indeterminate(condition)
            });
            let indeterminate =
                !any_definite_false && conditions.iter().any(exists_trace_is_indeterminate);
            let matched = !indeterminate && conditions.iter().all(exists_trace_matched);
            AuthorizationExistsConditionTrace::All {
                id: id.clone(),
                matched,
                indeterminate,
                conditions,
            }
        }
        AuthorizationExistsCondition::Any { id, conditions } => {
            let conditions = conditions
                .iter()
                .map(|condition| evaluate_exists_condition_trace(condition, input, related_row))
                .collect::<Vec<_>>();
            let matched = conditions.iter().any(exists_trace_matched);
            let indeterminate = !matched && conditions.iter().any(exists_trace_is_indeterminate);
            AuthorizationExistsConditionTrace::Any {
                id: id.clone(),
                matched,
                indeterminate,
                conditions,
            }
        }
        AuthorizationExistsCondition::Not { id, condition } => {
            let condition = Box::new(evaluate_exists_condition_trace(
                condition,
                input,
                related_row,
            ));
            let indeterminate = exists_trace_is_indeterminate(&condition);
            let matched = !indeterminate && !exists_trace_matched(&condition);
            AuthorizationExistsConditionTrace::Not {
                id: id.clone(),
                matched,
                indeterminate,
                condition,
            }
        }
    }
}

fn evaluate_assignment_trace(
    resource: &ResourceAuthorization,
    input: &AuthorizationSimulationInput,
    admin: bool,
    assignment: &AuthorizationAssignment,
) -> AuthorizationAssignmentTrace {
    let source_value = resolve_source_value(&assignment.source, input);
    let proposed_value = input.proposed.get(&assignment.field).cloned();
    let admin_override_allowed = admin
        && resource.admin_bypass
        && matches!(assignment.source, AuthorizationValueSource::Claim { .. });
    let admin_override_applied = admin_override_allowed && proposed_value.is_some();
    let effective_value = if admin_override_applied {
        proposed_value.clone()
    } else {
        source_value.clone()
    };

    AuthorizationAssignmentTrace {
        id: assignment.id.clone(),
        field: assignment.field.clone(),
        source: assignment.source.clone(),
        source_value,
        proposed_value,
        effective_value: effective_value.clone(),
        admin_override_allowed,
        admin_override_applied,
        missing_source: effective_value.is_none(),
    }
}

fn resolve_source_value(
    source: &AuthorizationValueSource,
    input: &AuthorizationSimulationInput,
) -> Option<Value> {
    match source {
        AuthorizationValueSource::UserId => input.user_id.map(Value::from),
        AuthorizationValueSource::Claim { name, .. } => input.claims.get(name).cloned(),
        AuthorizationValueSource::InputField { name } => input.proposed.get(name).cloned(),
    }
}

fn create_filter_input(
    input: &AuthorizationSimulationInput,
    assignments: &[AuthorizationAssignmentTrace],
) -> AuthorizationSimulationInput {
    let mut create_row = input.proposed.clone();
    for assignment in assignments {
        if let Some(value) = &assignment.effective_value {
            create_row.insert(assignment.field.clone(), value.clone());
        }
    }

    let mut normalized = input.clone();
    normalized.row = create_row;
    normalized
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
        format!(
            "runtime authorization assignment tables are missing required lifecycle or audit columns; regenerate and apply the authz runtime migration"
        )
    } else {
        error.to_string()
    }
}

fn authorization_user_is_admin(user: &UserContext) -> bool {
    user.roles.iter().any(|role| role == "admin")
}

async fn evaluate_runtime_access_endpoint(
    user: UserContext,
    input: web::Json<AuthorizationRuntimeAccessInput>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    let input = input.into_inner();
    let target_user_id = input.user_id.unwrap_or(user.id);
    if target_user_id != user.id && !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    match runtime
        .evaluate_runtime_access_for_user(
            target_user_id,
            &input.resource,
            input.action,
            input.scope,
        )
        .await
    {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(message)
            if message.contains("undeclared")
                || message.contains("not found")
                || message.contains("does not define") =>
        {
            errors::bad_request("invalid_runtime_access", message)
        }
        Err(message) => errors::internal_error(message),
    }
}

async fn list_runtime_assignments_endpoint(
    user: UserContext,
    query: web::Query<AuthorizationScopedAssignmentListQuery>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    if !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    match runtime.list_assignments_for_user(query.user_id).await {
        Ok(assignments) => HttpResponse::Ok().json(assignments),
        Err(message) => errors::internal_error(message),
    }
}

async fn list_runtime_assignment_events_endpoint(
    user: UserContext,
    query: web::Query<AuthorizationScopedAssignmentListQuery>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    if !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    match runtime.list_assignment_events_for_user(query.user_id).await {
        Ok(events) => HttpResponse::Ok().json(events),
        Err(message) => errors::internal_error(message),
    }
}

async fn create_runtime_assignment_endpoint(
    user: UserContext,
    input: web::Json<AuthorizationScopedAssignmentCreateInput>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    if !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let record = match input.into_inner().into_record(Some(user.id)) {
        Ok(record) => record,
        Err(message) => return errors::bad_request("invalid_runtime_assignment", message),
    };

    match runtime.create_assignment(record).await {
        Ok(assignment) => HttpResponse::Created().json(assignment),
        Err(message) if message.contains("undeclared") || message.contains("only supports") => {
            errors::bad_request("invalid_runtime_assignment", message)
        }
        Err(message) => errors::internal_error(message),
    }
}

async fn delete_runtime_assignment_endpoint(
    user: UserContext,
    path: web::Path<String>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    if !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    match runtime
        .delete_assignment_with_audit(&path.into_inner(), Some(user.id), None)
        .await
    {
        Ok(true) => HttpResponse::NoContent().finish(),
        Ok(false) => errors::not_found("Runtime authorization assignment not found"),
        Err(message) => errors::internal_error(message),
    }
}

async fn revoke_runtime_assignment_endpoint(
    user: UserContext,
    path: web::Path<String>,
    input: web::Json<AuthorizationScopedAssignmentRevokeInput>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    if !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    match runtime
        .revoke_assignment_with_audit(&path.into_inner(), Some(user.id), input.into_inner().reason)
        .await
    {
        Ok(Some(assignment)) => HttpResponse::Ok().json(assignment),
        Ok(None) => errors::not_found("Runtime authorization assignment not found"),
        Err(message) if message.contains("already inactive") => {
            errors::bad_request("invalid_runtime_assignment", message)
        }
        Err(message) => errors::internal_error(message),
    }
}

async fn renew_runtime_assignment_endpoint(
    user: UserContext,
    path: web::Path<String>,
    input: web::Json<AuthorizationScopedAssignmentRenewInput>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    if !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let input = input.into_inner();
    match runtime
        .renew_assignment_with_audit(
            &path.into_inner(),
            &input.expires_at,
            Some(user.id),
            input.reason,
        )
        .await
    {
        Ok(Some(assignment)) => HttpResponse::Ok().json(assignment),
        Ok(None) => errors::not_found("Runtime authorization assignment not found"),
        Err(message)
            if message.contains("expires_at")
                || message.contains("already expires at or after") =>
        {
            errors::bad_request("invalid_runtime_assignment", message)
        }
        Err(message) => errors::internal_error(message),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn eq(field: &str) -> AuthorizationCondition {
        AuthorizationCondition::Match(AuthorizationMatch {
            id: format!("condition.{field}"),
            field: field.to_owned(),
            operator: AuthorizationOperator::Equals,
            source: Some(AuthorizationValueSource::UserId),
        })
    }

    fn exists_family_member() -> AuthorizationCondition {
        AuthorizationCondition::Exists {
            id: "condition.exists.family_member".to_owned(),
            resource: "FamilyMember".to_owned(),
            table: "family_member".to_owned(),
            conditions: vec![
                AuthorizationExistsCondition::CurrentRowField {
                    id: "condition.exists.family_member.1".to_owned(),
                    field: "family_id".to_owned(),
                    row_field: "family_id".to_owned(),
                },
                AuthorizationExistsCondition::Match(AuthorizationMatch {
                    id: "condition.exists.family_member.2".to_owned(),
                    field: "user_id".to_owned(),
                    operator: AuthorizationOperator::Equals,
                    source: Some(AuthorizationValueSource::UserId),
                }),
            ],
        }
    }

    fn exists_family_access_any_of() -> AuthorizationCondition {
        AuthorizationCondition::Exists {
            id: "condition.exists.family_access".to_owned(),
            resource: "FamilyAccess".to_owned(),
            table: "family_access".to_owned(),
            conditions: vec![AuthorizationExistsCondition::All {
                id: "condition.exists.family_access.1".to_owned(),
                conditions: vec![
                    AuthorizationExistsCondition::CurrentRowField {
                        id: "condition.exists.family_access.1.1".to_owned(),
                        field: "family_id".to_owned(),
                        row_field: "family_id".to_owned(),
                    },
                    AuthorizationExistsCondition::Any {
                        id: "condition.exists.family_access.1.2".to_owned(),
                        conditions: vec![
                            AuthorizationExistsCondition::Match(AuthorizationMatch {
                                id: "condition.exists.family_access.1.2.1".to_owned(),
                                field: "primary_user_id".to_owned(),
                                operator: AuthorizationOperator::Equals,
                                source: Some(AuthorizationValueSource::UserId),
                            }),
                            AuthorizationExistsCondition::Match(AuthorizationMatch {
                                id: "condition.exists.family_access.1.2.2".to_owned(),
                                field: "delegate_user_id".to_owned(),
                                operator: AuthorizationOperator::Equals,
                                source: Some(AuthorizationValueSource::UserId),
                            }),
                        ],
                    },
                ],
            }],
        }
    }

    #[test]
    fn all_collapses_empty_and_single_conditions() {
        assert_eq!(AuthorizationCondition::all(Vec::new()), None);
        assert_eq!(
            AuthorizationCondition::all(vec![eq("user_id")]),
            Some(eq("user_id"))
        );
    }

    #[test]
    fn controlled_fields_collect_filters_and_assignments() {
        let resource = ResourceAuthorization {
            id: "resource.tenant_post".to_owned(),
            resource: "TenantPost".to_owned(),
            table: "tenant_post".to_owned(),
            admin_bypass: false,
            actions: vec![
                ActionAuthorization {
                    id: "resource.tenant_post.action.read".to_owned(),
                    action: AuthorizationAction::Read,
                    role_rule_id: Some("resource.tenant_post.action.read.role".to_owned()),
                    required_role: Some("member".to_owned()),
                    filter: AuthorizationCondition::all(vec![eq("user_id"), eq("tenant_id")]),
                    assignments: Vec::new(),
                },
                ActionAuthorization {
                    id: "resource.tenant_post.action.create".to_owned(),
                    action: AuthorizationAction::Create,
                    role_rule_id: Some("resource.tenant_post.action.create.role".to_owned()),
                    required_role: Some("member".to_owned()),
                    filter: None,
                    assignments: vec![AuthorizationAssignment {
                        id: "resource.tenant_post.action.create.assignment.created_by".to_owned(),
                        field: "created_by".to_owned(),
                        source: AuthorizationValueSource::UserId,
                    }],
                },
            ],
        };

        assert_eq!(
            resource.controlled_fields().into_iter().collect::<Vec<_>>(),
            vec![
                "created_by".to_owned(),
                "tenant_id".to_owned(),
                "user_id".to_owned(),
            ]
        );
    }

    #[test]
    fn simulate_action_denies_when_required_role_is_missing() {
        let resource = ResourceAuthorization {
            id: "resource.owned_post".to_owned(),
            resource: "OwnedPost".to_owned(),
            table: "owned_post".to_owned(),
            admin_bypass: true,
            actions: vec![ActionAuthorization {
                id: "resource.owned_post.action.read".to_owned(),
                action: AuthorizationAction::Read,
                role_rule_id: Some("resource.owned_post.action.read.role".to_owned()),
                required_role: Some("user".to_owned()),
                filter: Some(eq("user_id")),
                assignments: Vec::new(),
            }],
        };

        let result = resource
            .simulate_action(&AuthorizationSimulationInput {
                action: AuthorizationAction::Read,
                user_id: Some(7),
                roles: vec!["viewer".to_owned()],
                claims: BTreeMap::new(),
                row: BTreeMap::from([("user_id".to_owned(), Value::from(7))]),
                proposed: BTreeMap::new(),
                related_rows: BTreeMap::new(),
                scope: None,
                hybrid_source: None,
                scoped_assignments: Vec::new(),
            })
            .expect("action should exist");

        assert_eq!(result.outcome, AuthorizationOutcome::Denied);
        assert!(!result.role_check_passed);
        assert_eq!(result.resource_id, "resource.owned_post");
        assert_eq!(result.action_id, "resource.owned_post.action.read");
        assert_eq!(
            result.role_rule_id.as_deref(),
            Some("resource.owned_post.action.read.role")
        );
    }

    #[test]
    fn simulate_action_marks_missing_row_fields_incomplete() {
        let resource = ResourceAuthorization {
            id: "resource.tenant_post".to_owned(),
            resource: "TenantPost".to_owned(),
            table: "tenant_post".to_owned(),
            admin_bypass: false,
            actions: vec![ActionAuthorization {
                id: "resource.tenant_post.action.read".to_owned(),
                action: AuthorizationAction::Read,
                role_rule_id: None,
                required_role: None,
                filter: AuthorizationCondition::all(vec![eq("user_id")]),
                assignments: Vec::new(),
            }],
        };

        let result = resource
            .simulate_action(&AuthorizationSimulationInput {
                action: AuthorizationAction::Read,
                user_id: Some(7),
                roles: Vec::new(),
                claims: BTreeMap::new(),
                row: BTreeMap::new(),
                proposed: BTreeMap::new(),
                related_rows: BTreeMap::new(),
                scope: None,
                hybrid_source: None,
                scoped_assignments: Vec::new(),
            })
            .expect("action should exist");

        assert_eq!(result.outcome, AuthorizationOutcome::Incomplete);
        assert!(
            result
                .filter
                .as_ref()
                .expect("filter trace should exist")
                .has_missing_field()
        );
    }

    #[test]
    fn simulate_action_allows_admin_bypass_for_filters() {
        let resource = ResourceAuthorization {
            id: "resource.tenant_post".to_owned(),
            resource: "TenantPost".to_owned(),
            table: "tenant_post".to_owned(),
            admin_bypass: true,
            actions: vec![ActionAuthorization {
                id: "resource.tenant_post.action.delete".to_owned(),
                action: AuthorizationAction::Delete,
                role_rule_id: Some("resource.tenant_post.action.delete.role".to_owned()),
                required_role: Some("manager".to_owned()),
                filter: AuthorizationCondition::all(vec![eq("user_id")]),
                assignments: Vec::new(),
            }],
        };

        let result = resource
            .simulate_action(&AuthorizationSimulationInput {
                action: AuthorizationAction::Delete,
                user_id: Some(99),
                roles: vec!["admin".to_owned()],
                claims: BTreeMap::new(),
                row: BTreeMap::from([("user_id".to_owned(), Value::from(7))]),
                proposed: BTreeMap::new(),
                related_rows: BTreeMap::new(),
                scope: None,
                hybrid_source: None,
                scoped_assignments: Vec::new(),
            })
            .expect("action should exist");

        assert_eq!(result.outcome, AuthorizationOutcome::Allowed);
        assert!(result.admin_bypass_applied);
    }

    #[test]
    fn simulate_action_allows_admin_claim_override_for_create_assignments() {
        let resource = ResourceAuthorization {
            id: "resource.scoped_doc".to_owned(),
            resource: "ScopedDoc".to_owned(),
            table: "scoped_doc".to_owned(),
            admin_bypass: true,
            actions: vec![ActionAuthorization {
                id: "resource.scoped_doc.action.create".to_owned(),
                action: AuthorizationAction::Create,
                role_rule_id: None,
                required_role: None,
                filter: None,
                assignments: vec![AuthorizationAssignment {
                    id: "resource.scoped_doc.action.create.assignment.tenant_id".to_owned(),
                    field: "tenant_id".to_owned(),
                    source: AuthorizationValueSource::Claim {
                        name: "tenant_id".to_owned(),
                        ty: AuthClaimType::I64,
                    },
                }],
            }],
        };

        let result = resource
            .simulate_action(&AuthorizationSimulationInput {
                action: AuthorizationAction::Create,
                user_id: Some(1),
                roles: vec!["admin".to_owned()],
                claims: BTreeMap::new(),
                row: BTreeMap::new(),
                proposed: BTreeMap::from([("tenant_id".to_owned(), Value::from(42))]),
                related_rows: BTreeMap::new(),
                scope: None,
                hybrid_source: None,
                scoped_assignments: Vec::new(),
            })
            .expect("action should exist");

        assert_eq!(result.outcome, AuthorizationOutcome::Allowed);
        assert_eq!(result.assignments.len(), 1);
        assert!(result.assignments[0].admin_override_applied);
        assert_eq!(result.assignments[0].effective_value, Some(Value::from(42)));
    }

    #[test]
    fn simulate_action_supports_is_null_filters() {
        let resource = ResourceAuthorization {
            id: "resource.note".to_owned(),
            resource: "Note".to_owned(),
            table: "note".to_owned(),
            admin_bypass: false,
            actions: vec![ActionAuthorization {
                id: "resource.note.action.read".to_owned(),
                action: AuthorizationAction::Read,
                role_rule_id: None,
                required_role: None,
                filter: Some(AuthorizationCondition::Match(AuthorizationMatch {
                    id: "resource.note.action.read.filter".to_owned(),
                    field: "archived_at".to_owned(),
                    operator: AuthorizationOperator::IsNull,
                    source: None,
                })),
                assignments: Vec::new(),
            }],
        };

        let allowed = resource
            .simulate_action(&AuthorizationSimulationInput {
                action: AuthorizationAction::Read,
                user_id: Some(7),
                roles: Vec::new(),
                claims: BTreeMap::new(),
                row: BTreeMap::from([("archived_at".to_owned(), Value::Null)]),
                proposed: BTreeMap::new(),
                related_rows: BTreeMap::new(),
                scope: None,
                hybrid_source: None,
                scoped_assignments: Vec::new(),
            })
            .expect("action should exist");
        assert_eq!(allowed.outcome, AuthorizationOutcome::Allowed);

        let denied = resource
            .simulate_action(&AuthorizationSimulationInput {
                action: AuthorizationAction::Read,
                user_id: Some(7),
                roles: Vec::new(),
                claims: BTreeMap::new(),
                row: BTreeMap::from([(
                    "archived_at".to_owned(),
                    Value::String("2026-03-23T00:00:00Z".to_owned()),
                )]),
                proposed: BTreeMap::new(),
                related_rows: BTreeMap::new(),
                scope: None,
                hybrid_source: None,
                scoped_assignments: Vec::new(),
            })
            .expect("action should exist");
        assert_eq!(denied.outcome, AuthorizationOutcome::Denied);
    }

    #[test]
    fn simulate_create_action_supports_input_field_exists_requirements() {
        let resource = ResourceAuthorization {
            id: "resource.family_member".to_owned(),
            resource: "FamilyMember".to_owned(),
            table: "family_member".to_owned(),
            admin_bypass: false,
            actions: vec![ActionAuthorization {
                id: "resource.family_member.action.create".to_owned(),
                action: AuthorizationAction::Create,
                role_rule_id: None,
                required_role: None,
                filter: Some(AuthorizationCondition::Exists {
                    id: "resource.family_member.action.create.filter".to_owned(),
                    resource: "Family".to_owned(),
                    table: "family".to_owned(),
                    conditions: vec![
                        AuthorizationExistsCondition::Match(AuthorizationMatch {
                            id: "resource.family_member.action.create.filter.1".to_owned(),
                            field: "id".to_owned(),
                            operator: AuthorizationOperator::Equals,
                            source: Some(AuthorizationValueSource::InputField {
                                name: "family_id".to_owned(),
                            }),
                        }),
                        AuthorizationExistsCondition::Match(AuthorizationMatch {
                            id: "resource.family_member.action.create.filter.2".to_owned(),
                            field: "owner_user_id".to_owned(),
                            operator: AuthorizationOperator::Equals,
                            source: Some(AuthorizationValueSource::UserId),
                        }),
                    ],
                }),
                assignments: vec![AuthorizationAssignment {
                    id: "resource.family_member.action.create.assignment.created_by_user_id"
                        .to_owned(),
                    field: "created_by_user_id".to_owned(),
                    source: AuthorizationValueSource::UserId,
                }],
            }],
        };

        let result = resource
            .simulate_action(&AuthorizationSimulationInput {
                action: AuthorizationAction::Create,
                user_id: Some(7),
                roles: Vec::new(),
                claims: BTreeMap::new(),
                row: BTreeMap::new(),
                proposed: BTreeMap::from([("family_id".to_owned(), Value::from(42))]),
                related_rows: BTreeMap::from([(
                    "Family".to_owned(),
                    vec![BTreeMap::from([
                        ("id".to_owned(), Value::from(42)),
                        ("owner_user_id".to_owned(), Value::from(7)),
                    ])],
                )]),
                scope: None,
                hybrid_source: None,
                scoped_assignments: Vec::new(),
            })
            .expect("action should exist");

        assert_eq!(result.outcome, AuthorizationOutcome::Allowed);
        assert_eq!(result.assignments[0].effective_value, Some(Value::from(7)));
    }

    #[test]
    fn simulate_action_allows_exists_predicate_when_related_row_matches() {
        let resource = ResourceAuthorization {
            id: "resource.shared_doc".to_owned(),
            resource: "SharedDoc".to_owned(),
            table: "shared_doc".to_owned(),
            admin_bypass: false,
            actions: vec![ActionAuthorization {
                id: "resource.shared_doc.action.read".to_owned(),
                action: AuthorizationAction::Read,
                role_rule_id: None,
                required_role: None,
                filter: Some(exists_family_member()),
                assignments: Vec::new(),
            }],
        };

        let result = resource
            .simulate_action(&AuthorizationSimulationInput {
                action: AuthorizationAction::Read,
                user_id: Some(7),
                roles: Vec::new(),
                claims: BTreeMap::new(),
                row: BTreeMap::from([("family_id".to_owned(), Value::from(42))]),
                proposed: BTreeMap::new(),
                related_rows: BTreeMap::from([(
                    "FamilyMember".to_owned(),
                    vec![BTreeMap::from([
                        ("family_id".to_owned(), Value::from(42)),
                        ("user_id".to_owned(), Value::from(7)),
                    ])],
                )]),
                scope: None,
                hybrid_source: None,
                scoped_assignments: Vec::new(),
            })
            .expect("action should exist");

        assert_eq!(result.outcome, AuthorizationOutcome::Allowed);
        let AuthorizationConditionTrace::Exists {
            matched,
            indeterminate,
            related_row_count,
            matched_row_index,
            ..
        } = result.filter.expect("filter trace should exist")
        else {
            panic!("filter trace should be exists");
        };
        assert!(matched);
        assert!(!indeterminate);
        assert_eq!(related_row_count, 1);
        assert_eq!(matched_row_index, Some(0));
    }

    #[test]
    fn simulate_action_marks_exists_predicate_incomplete_without_related_rows() {
        let resource = ResourceAuthorization {
            id: "resource.shared_doc".to_owned(),
            resource: "SharedDoc".to_owned(),
            table: "shared_doc".to_owned(),
            admin_bypass: false,
            actions: vec![ActionAuthorization {
                id: "resource.shared_doc.action.read".to_owned(),
                action: AuthorizationAction::Read,
                role_rule_id: None,
                required_role: None,
                filter: Some(exists_family_member()),
                assignments: Vec::new(),
            }],
        };

        let result = resource
            .simulate_action(&AuthorizationSimulationInput {
                action: AuthorizationAction::Read,
                user_id: Some(7),
                roles: Vec::new(),
                claims: BTreeMap::new(),
                row: BTreeMap::from([("family_id".to_owned(), Value::from(42))]),
                proposed: BTreeMap::new(),
                related_rows: BTreeMap::new(),
                scope: None,
                hybrid_source: None,
                scoped_assignments: Vec::new(),
            })
            .expect("action should exist");

        assert_eq!(result.outcome, AuthorizationOutcome::Incomplete);
        let filter = result.filter.expect("filter trace should exist");
        assert!(filter.has_missing_related_rows());
    }

    #[test]
    fn simulate_action_allows_exists_predicate_with_nested_any_of_match() {
        let resource = ResourceAuthorization {
            id: "resource.shared_doc".to_owned(),
            resource: "SharedDoc".to_owned(),
            table: "shared_doc".to_owned(),
            admin_bypass: false,
            actions: vec![ActionAuthorization {
                id: "resource.shared_doc.action.read".to_owned(),
                action: AuthorizationAction::Read,
                role_rule_id: None,
                required_role: None,
                filter: Some(exists_family_access_any_of()),
                assignments: Vec::new(),
            }],
        };

        let result = resource
            .simulate_action(&AuthorizationSimulationInput {
                action: AuthorizationAction::Read,
                user_id: Some(12),
                roles: Vec::new(),
                claims: BTreeMap::new(),
                row: BTreeMap::from([("family_id".to_owned(), Value::from(42))]),
                proposed: BTreeMap::new(),
                related_rows: BTreeMap::from([(
                    "FamilyAccess".to_owned(),
                    vec![BTreeMap::from([
                        ("family_id".to_owned(), Value::from(42)),
                        ("primary_user_id".to_owned(), Value::from(11)),
                        ("delegate_user_id".to_owned(), Value::from(12)),
                    ])],
                )]),
                scope: None,
                hybrid_source: None,
                scoped_assignments: Vec::new(),
            })
            .expect("action should exist");

        assert_eq!(result.outcome, AuthorizationOutcome::Allowed);
        let AuthorizationConditionTrace::Exists { conditions, .. } =
            result.filter.expect("filter trace should exist")
        else {
            panic!("filter trace should be exists");
        };
        assert!(matches!(
            &conditions[0],
            AuthorizationExistsConditionTrace::All { matched: true, .. }
        ));
    }

    #[test]
    fn model_simulation_resolves_runtime_template_assignments() {
        let model = AuthorizationModel {
            contract: AuthorizationContract {
                scopes: vec![AuthorizationScope {
                    name: "Family".to_owned(),
                    description: None,
                    parent: None,
                }],
                permissions: vec![AuthorizationPermission {
                    name: "FamilyRead".to_owned(),
                    description: None,
                    actions: vec![AuthorizationAction::Read],
                    resources: vec!["ScopedDoc".to_owned()],
                    scopes: vec!["Family".to_owned()],
                }],
                templates: vec![AuthorizationTemplate {
                    name: "FamilyMember".to_owned(),
                    description: None,
                    permissions: vec!["FamilyRead".to_owned()],
                    scopes: vec!["Family".to_owned()],
                }],
                hybrid_enforcement: AuthorizationHybridEnforcementConfig::default(),
                management_api: AuthorizationManagementApiConfig::default(),
            },
            resources: vec![ResourceAuthorization {
                id: "resource.scoped_doc".to_owned(),
                resource: "ScopedDoc".to_owned(),
                table: "scoped_doc".to_owned(),
                admin_bypass: false,
                actions: vec![ActionAuthorization {
                    id: "resource.scoped_doc.action.read".to_owned(),
                    action: AuthorizationAction::Read,
                    role_rule_id: None,
                    required_role: None,
                    filter: None,
                    assignments: Vec::new(),
                }],
            }],
        };

        let result = model
            .simulate_resource_action(
                Some("ScopedDoc"),
                &AuthorizationSimulationInput {
                    action: AuthorizationAction::Read,
                    user_id: Some(7),
                    roles: Vec::new(),
                    claims: BTreeMap::new(),
                    row: BTreeMap::new(),
                    proposed: BTreeMap::new(),
                    related_rows: BTreeMap::new(),
                    scope: Some(AuthorizationScopeBinding {
                        scope: "Family".to_owned(),
                        value: "42".to_owned(),
                    }),
                    hybrid_source: None,
                    scoped_assignments: vec![AuthorizationScopedAssignment {
                        id: "runtime.assignment.1".to_owned(),
                        target: AuthorizationScopedAssignmentTarget::Template {
                            name: "FamilyMember".to_owned(),
                        },
                        scope: AuthorizationScopeBinding {
                            scope: "Family".to_owned(),
                            value: "42".to_owned(),
                        },
                    }],
                },
            )
            .expect("simulation should resolve");

        assert_eq!(result.outcome, AuthorizationOutcome::Allowed);
        assert_eq!(result.resolved_permissions, vec!["FamilyRead".to_owned()]);
        assert_eq!(result.resolved_templates, vec!["FamilyMember".to_owned()]);
        assert_eq!(result.runtime_assignments.len(), 1);
        assert!(result.runtime_assignments[0].scope_matched);
        assert!(result.runtime_assignments[0].target_matched);
        assert!(
            result
                .notes
                .iter()
                .any(|note| note.contains("generated handlers do not enforce"))
        );
    }

    #[test]
    fn model_simulation_rejects_runtime_assignment_with_unknown_scope() {
        let model = AuthorizationModel {
            contract: AuthorizationContract {
                scopes: vec![AuthorizationScope {
                    name: "Family".to_owned(),
                    description: None,
                    parent: None,
                }],
                permissions: vec![AuthorizationPermission {
                    name: "FamilyRead".to_owned(),
                    description: None,
                    actions: vec![AuthorizationAction::Read],
                    resources: vec!["ScopedDoc".to_owned()],
                    scopes: vec!["Family".to_owned()],
                }],
                templates: Vec::new(),
                hybrid_enforcement: AuthorizationHybridEnforcementConfig::default(),
                management_api: AuthorizationManagementApiConfig::default(),
            },
            resources: vec![ResourceAuthorization {
                id: "resource.scoped_doc".to_owned(),
                resource: "ScopedDoc".to_owned(),
                table: "scoped_doc".to_owned(),
                admin_bypass: false,
                actions: vec![ActionAuthorization {
                    id: "resource.scoped_doc.action.read".to_owned(),
                    action: AuthorizationAction::Read,
                    role_rule_id: None,
                    required_role: None,
                    filter: None,
                    assignments: Vec::new(),
                }],
            }],
        };

        let error = model
            .simulate_resource_action(
                Some("ScopedDoc"),
                &AuthorizationSimulationInput {
                    action: AuthorizationAction::Read,
                    user_id: Some(7),
                    roles: Vec::new(),
                    claims: BTreeMap::new(),
                    row: BTreeMap::new(),
                    proposed: BTreeMap::new(),
                    related_rows: BTreeMap::new(),
                    scope: Some(AuthorizationScopeBinding {
                        scope: "Household".to_owned(),
                        value: "42".to_owned(),
                    }),
                    hybrid_source: None,
                    scoped_assignments: vec![AuthorizationScopedAssignment {
                        id: "runtime.assignment.1".to_owned(),
                        target: AuthorizationScopedAssignmentTarget::Permission {
                            name: "FamilyRead".to_owned(),
                        },
                        scope: AuthorizationScopeBinding {
                            scope: "Household".to_owned(),
                            value: "42".to_owned(),
                        },
                    }],
                },
            )
            .expect_err("unknown scope should fail validation");

        assert!(error.contains("undeclared scope `Household`"));
    }

    #[test]
    fn authorization_runtime_migration_sql_mentions_runtime_assignment_tables() {
        let sql = authorization_runtime_migration_sql(AuthDbBackend::Sqlite);
        assert!(sql.contains(&format!(
            "CREATE TABLE {AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE}"
        )));
        assert!(sql.contains(&format!(
            "CREATE TABLE {AUTHORIZATION_RUNTIME_ASSIGNMENT_EVENT_TABLE}"
        )));
        assert!(sql.contains("created_at"));
        assert!(sql.contains("expires_at"));
        assert!(sql.contains("target_kind"));
        assert!(sql.contains("event_kind"));
        assert!(sql.contains("reason"));
        assert!(sql.contains("scope_name"));
    }

    #[test]
    fn authorization_runtime_migration_sql_uses_mysql_safe_indexed_assignment_id() {
        let sql = authorization_runtime_migration_sql(AuthDbBackend::Mysql);
        assert!(sql.contains("assignment_id VARCHAR(191) NOT NULL"));
        assert!(!sql.contains("assignment_id TEXT NOT NULL"));
        assert!(sql.contains(&format!(
            "CREATE INDEX idx_{AUTHORIZATION_RUNTIME_ASSIGNMENT_EVENT_TABLE}_assignment ON {AUTHORIZATION_RUNTIME_ASSIGNMENT_EVENT_TABLE} (assignment_id, created_at);"
        )));
    }

    fn scoped_doc_runtime_model() -> AuthorizationModel {
        AuthorizationModel {
            contract: AuthorizationContract {
                scopes: vec![AuthorizationScope {
                    name: "Family".to_owned(),
                    description: None,
                    parent: None,
                }],
                permissions: vec![AuthorizationPermission {
                    name: "FamilyRead".to_owned(),
                    description: None,
                    actions: vec![AuthorizationAction::Read],
                    resources: vec!["ScopedDoc".to_owned()],
                    scopes: vec!["Family".to_owned()],
                }],
                templates: vec![AuthorizationTemplate {
                    name: "FamilyMember".to_owned(),
                    description: None,
                    permissions: vec!["FamilyRead".to_owned()],
                    scopes: vec!["Family".to_owned()],
                }],
                hybrid_enforcement: AuthorizationHybridEnforcementConfig::default(),
                management_api: AuthorizationManagementApiConfig::default(),
            },
            resources: vec![ResourceAuthorization {
                id: "resource.scoped_doc".to_owned(),
                resource: "ScopedDoc".to_owned(),
                table: "scoped_doc".to_owned(),
                admin_bypass: false,
                actions: vec![ActionAuthorization {
                    id: "resource.scoped_doc.action.read".to_owned(),
                    action: AuthorizationAction::Read,
                    role_rule_id: None,
                    required_role: None,
                    filter: None,
                    assignments: Vec::new(),
                }],
            }],
        }
    }

    fn hybrid_scoped_doc_runtime_model() -> AuthorizationModel {
        AuthorizationModel {
            contract: AuthorizationContract {
                scopes: vec![AuthorizationScope {
                    name: "Family".to_owned(),
                    description: None,
                    parent: None,
                }],
                permissions: vec![
                    AuthorizationPermission {
                        name: "FamilyRead".to_owned(),
                        description: None,
                        actions: vec![AuthorizationAction::Read],
                        resources: vec!["ScopedDoc".to_owned()],
                        scopes: vec!["Family".to_owned()],
                    },
                    AuthorizationPermission {
                        name: "FamilyManage".to_owned(),
                        description: None,
                        actions: vec![AuthorizationAction::Create],
                        resources: vec!["ScopedDoc".to_owned()],
                        scopes: vec!["Family".to_owned()],
                    },
                ],
                templates: vec![AuthorizationTemplate {
                    name: "FamilyMember".to_owned(),
                    description: None,
                    permissions: vec!["FamilyRead".to_owned(), "FamilyManage".to_owned()],
                    scopes: vec!["Family".to_owned()],
                }],
                hybrid_enforcement: AuthorizationHybridEnforcementConfig {
                    resources: vec![AuthorizationHybridResource {
                        resource: "ScopedDoc".to_owned(),
                        scope: "Family".to_owned(),
                        scope_field: "family_id".to_owned(),
                        scope_sources: AuthorizationHybridScopeSources {
                            item: true,
                            collection_filter: true,
                            nested_parent: false,
                            create_payload: true,
                        },
                        actions: vec![AuthorizationAction::Read, AuthorizationAction::Create],
                    }],
                },
                management_api: AuthorizationManagementApiConfig::default(),
            },
            resources: vec![ResourceAuthorization {
                id: "resource.scoped_doc".to_owned(),
                resource: "ScopedDoc".to_owned(),
                table: "scoped_doc".to_owned(),
                admin_bypass: false,
                actions: vec![
                    ActionAuthorization {
                        id: "resource.scoped_doc.action.read".to_owned(),
                        action: AuthorizationAction::Read,
                        role_rule_id: None,
                        required_role: None,
                        filter: Some(AuthorizationCondition::Match(AuthorizationMatch {
                            id: "resource.scoped_doc.action.read.filter.user_id".to_owned(),
                            field: "user_id".to_owned(),
                            operator: AuthorizationOperator::Equals,
                            source: Some(AuthorizationValueSource::UserId),
                        })),
                        assignments: Vec::new(),
                    },
                    ActionAuthorization {
                        id: "resource.scoped_doc.action.create".to_owned(),
                        action: AuthorizationAction::Create,
                        role_rule_id: None,
                        required_role: None,
                        filter: None,
                        assignments: vec![AuthorizationAssignment {
                            id: "resource.scoped_doc.action.create.assignment.family_id".to_owned(),
                            field: "family_id".to_owned(),
                            source: AuthorizationValueSource::Claim {
                                name: "family_id".to_owned(),
                                ty: AuthClaimType::I64,
                            },
                        }],
                    },
                ],
            }],
        }
    }

    #[test]
    fn model_simulation_reports_hybrid_item_runtime_fallback() {
        let model = hybrid_scoped_doc_runtime_model();

        let result = model
            .simulate_resource_action(
                Some("ScopedDoc"),
                &AuthorizationSimulationInput {
                    action: AuthorizationAction::Read,
                    user_id: Some(7),
                    roles: Vec::new(),
                    claims: BTreeMap::new(),
                    row: BTreeMap::from([
                        ("user_id".to_owned(), Value::from(1)),
                        ("family_id".to_owned(), Value::from(42)),
                    ]),
                    proposed: BTreeMap::new(),
                    related_rows: BTreeMap::new(),
                    scope: None,
                    hybrid_source: Some(AuthorizationHybridSource::Item),
                    scoped_assignments: vec![AuthorizationScopedAssignment {
                        id: "runtime.assignment.1".to_owned(),
                        target: AuthorizationScopedAssignmentTarget::Template {
                            name: "FamilyMember".to_owned(),
                        },
                        scope: AuthorizationScopeBinding {
                            scope: "Family".to_owned(),
                            value: "42".to_owned(),
                        },
                    }],
                },
            )
            .expect("simulation should resolve");

        assert_eq!(result.outcome, AuthorizationOutcome::Denied);
        let hybrid = result.hybrid.expect("hybrid trace should exist");
        assert_eq!(hybrid.source, AuthorizationHybridSource::Item);
        assert_eq!(
            hybrid.scope,
            Some(AuthorizationScopeBinding {
                scope: "Family".to_owned(),
                value: "42".to_owned(),
            })
        );
        assert!(hybrid.runtime_allowed);
        assert_eq!(hybrid.effective_outcome, AuthorizationOutcome::Allowed);
        assert!(hybrid.fallback_applied);
    }

    #[test]
    fn model_simulation_reports_hybrid_collection_read_widening() {
        let model = hybrid_scoped_doc_runtime_model();

        let result = model
            .simulate_resource_action(
                Some("ScopedDoc"),
                &AuthorizationSimulationInput {
                    action: AuthorizationAction::Read,
                    user_id: Some(7),
                    roles: Vec::new(),
                    claims: BTreeMap::new(),
                    row: BTreeMap::new(),
                    proposed: BTreeMap::new(),
                    related_rows: BTreeMap::new(),
                    scope: Some(AuthorizationScopeBinding {
                        scope: "Family".to_owned(),
                        value: "42".to_owned(),
                    }),
                    hybrid_source: Some(AuthorizationHybridSource::CollectionFilter),
                    scoped_assignments: vec![AuthorizationScopedAssignment {
                        id: "runtime.assignment.1".to_owned(),
                        target: AuthorizationScopedAssignmentTarget::Template {
                            name: "FamilyMember".to_owned(),
                        },
                        scope: AuthorizationScopeBinding {
                            scope: "Family".to_owned(),
                            value: "42".to_owned(),
                        },
                    }],
                },
            )
            .expect("simulation should resolve");

        assert_eq!(result.outcome, AuthorizationOutcome::Incomplete);
        let hybrid = result.hybrid.expect("hybrid trace should exist");
        assert_eq!(hybrid.source, AuthorizationHybridSource::CollectionFilter);
        assert!(hybrid.runtime_allowed);
        assert_eq!(hybrid.effective_outcome, AuthorizationOutcome::Allowed);
        assert!(hybrid.skip_static_row_policy);
    }

    #[test]
    fn model_simulation_reports_hybrid_create_runtime_fallback() {
        let model = hybrid_scoped_doc_runtime_model();

        let result = model
            .simulate_resource_action(
                Some("ScopedDoc"),
                &AuthorizationSimulationInput {
                    action: AuthorizationAction::Create,
                    user_id: Some(7),
                    roles: Vec::new(),
                    claims: BTreeMap::new(),
                    row: BTreeMap::new(),
                    proposed: BTreeMap::from([("family_id".to_owned(), Value::from(42))]),
                    related_rows: BTreeMap::new(),
                    scope: None,
                    hybrid_source: Some(AuthorizationHybridSource::CreatePayload),
                    scoped_assignments: vec![AuthorizationScopedAssignment {
                        id: "runtime.assignment.1".to_owned(),
                        target: AuthorizationScopedAssignmentTarget::Template {
                            name: "FamilyMember".to_owned(),
                        },
                        scope: AuthorizationScopeBinding {
                            scope: "Family".to_owned(),
                            value: "42".to_owned(),
                        },
                    }],
                },
            )
            .expect("simulation should resolve");

        assert_eq!(result.outcome, AuthorizationOutcome::Denied);
        let hybrid = result.hybrid.expect("hybrid trace should exist");
        assert_eq!(hybrid.source, AuthorizationHybridSource::CreatePayload);
        assert!(hybrid.runtime_allowed);
        assert_eq!(hybrid.effective_outcome, AuthorizationOutcome::Allowed);
        assert!(hybrid.fallback_applied);
    }

    #[actix_web::test]
    async fn authorization_runtime_persists_and_loads_scoped_assignments() {
        sqlx::any::install_default_drivers();

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let database_path = std::env::temp_dir().join(format!("vsr_authz_runtime_{stamp}.db"));
        let database_url = format!("sqlite:{}?mode=rwc", database_path.display());
        let pool = DbPool::connect(&database_url)
            .await
            .expect("database should connect");
        pool.execute_batch(&authorization_runtime_migration_sql(AuthDbBackend::Sqlite))
            .await
            .expect("runtime migration should apply");

        let runtime = AuthorizationRuntime::new(scoped_doc_runtime_model(), pool.clone());
        let expires_at =
            (Utc::now() + chrono::Duration::days(1)).to_rfc3339_opts(SecondsFormat::Micros, false);
        let assignment = AuthorizationScopedAssignmentRecord::new(
            7,
            AuthorizationScopedAssignmentTarget::Template {
                name: "FamilyMember".to_owned(),
            },
            AuthorizationScopeBinding {
                scope: "Family".to_owned(),
                value: "42".to_owned(),
            },
        )
        .with_created_by_user_id(3)
        .with_expires_at(Some(expires_at.clone()));

        let created = runtime
            .create_assignment(assignment.clone())
            .await
            .expect("assignment should persist");
        assert_eq!(created.user_id, 7);
        assert_eq!(created.created_by_user_id, Some(3));
        assert_eq!(created.expires_at.as_deref(), Some(expires_at.as_str()));

        let stored = runtime
            .list_assignments_for_user(7)
            .await
            .expect("assignments should load");
        assert_eq!(stored, vec![assignment.clone()]);
        let events = runtime
            .list_assignment_events_for_user(7)
            .await
            .expect("assignment events should load");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].assignment_id, assignment.id);
        assert_eq!(
            events[0].event,
            AuthorizationScopedAssignmentEventKind::Created
        );
        assert_eq!(events[0].actor_user_id, Some(3));

        let result = runtime
            .simulate_resource_action_with_user_assignments(
                Some("ScopedDoc"),
                AuthorizationSimulationInput {
                    action: AuthorizationAction::Read,
                    user_id: Some(7),
                    roles: Vec::new(),
                    claims: BTreeMap::new(),
                    row: BTreeMap::new(),
                    proposed: BTreeMap::new(),
                    related_rows: BTreeMap::new(),
                    scope: Some(AuthorizationScopeBinding {
                        scope: "Family".to_owned(),
                        value: "42".to_owned(),
                    }),
                    hybrid_source: None,
                    scoped_assignments: Vec::new(),
                },
            )
            .await
            .expect("runtime simulation should load stored assignments");
        assert_eq!(result.resolved_permissions, vec!["FamilyRead".to_owned()]);
        assert_eq!(result.resolved_templates, vec!["FamilyMember".to_owned()]);

        let runtime_access = runtime
            .evaluate_runtime_access_for_user(
                7,
                "ScopedDoc",
                AuthorizationAction::Read,
                AuthorizationScopeBinding {
                    scope: "Family".to_owned(),
                    value: "42".to_owned(),
                },
            )
            .await
            .expect("runtime access should evaluate");
        assert!(runtime_access.allowed);
        assert_eq!(
            runtime_access.resolved_permissions,
            vec!["FamilyRead".to_owned()]
        );
        assert_eq!(
            runtime_access.resolved_templates,
            vec!["FamilyMember".to_owned()]
        );

        let revoked = runtime
            .revoke_assignment_with_audit(&assignment.id, Some(9), Some("suspend".to_owned()))
            .await
            .expect("assignment should revoke")
            .expect("assignment should exist");
        assert_eq!(revoked.id, assignment.id);
        assert!(revoked.expires_at.is_some());
        let revoked_access = runtime
            .evaluate_runtime_access_for_user(
                7,
                "ScopedDoc",
                AuthorizationAction::Read,
                AuthorizationScopeBinding {
                    scope: "Family".to_owned(),
                    value: "42".to_owned(),
                },
            )
            .await
            .expect("runtime access should evaluate after revoke");
        assert!(!revoked_access.allowed);

        let renewed_expires_at =
            (Utc::now() + chrono::Duration::days(2)).to_rfc3339_opts(SecondsFormat::Micros, false);
        let renewed = runtime
            .renew_assignment_with_audit(
                &assignment.id,
                &renewed_expires_at,
                Some(10),
                Some("restore".to_owned()),
            )
            .await
            .expect("assignment should renew")
            .expect("assignment should still exist");
        assert_eq!(renewed.id, assignment.id);
        assert_eq!(
            renewed.expires_at.as_deref(),
            Some(renewed_expires_at.as_str())
        );
        let renewed_access = runtime
            .evaluate_runtime_access_for_user(
                7,
                "ScopedDoc",
                AuthorizationAction::Read,
                AuthorizationScopeBinding {
                    scope: "Family".to_owned(),
                    value: "42".to_owned(),
                },
            )
            .await
            .expect("runtime access should evaluate after renew");
        assert!(renewed_access.allowed);

        let events = runtime
            .list_assignment_events_for_user(7)
            .await
            .expect("assignment events should reload");
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].assignment_id, assignment.id);
        assert_eq!(
            events[1].event,
            AuthorizationScopedAssignmentEventKind::Revoked
        );
        assert_eq!(events[1].actor_user_id, Some(9));
        assert_eq!(events[1].reason.as_deref(), Some("suspend"));
        assert_eq!(events[2].assignment_id, assignment.id);
        assert_eq!(
            events[2].event,
            AuthorizationScopedAssignmentEventKind::Renewed
        );
        assert_eq!(events[2].actor_user_id, Some(10));
        assert_eq!(events[2].reason.as_deref(), Some("restore"));

        let deleted = runtime
            .delete_assignment_with_audit(&assignment.id, Some(11), Some("cleanup".to_owned()))
            .await
            .expect("assignment should delete");
        assert!(deleted);
        assert!(
            runtime
                .list_assignments_for_user(7)
                .await
                .expect("assignment list should reload")
                .is_empty()
        );
        let events = runtime
            .list_assignment_events_for_user(7)
            .await
            .expect("assignment events should reload after delete");
        assert_eq!(events.len(), 4);
        assert_eq!(events[3].assignment_id, assignment.id);
        assert_eq!(
            events[3].event,
            AuthorizationScopedAssignmentEventKind::Deleted
        );
        assert_eq!(events[3].actor_user_id, Some(11));
        assert_eq!(events[3].reason.as_deref(), Some("cleanup"));
    }

    #[actix_web::test]
    async fn authorization_runtime_rejects_expired_assignment_creation_and_ignores_expired_rows() {
        sqlx::any::install_default_drivers();

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let database_path =
            std::env::temp_dir().join(format!("vsr_authz_runtime_expired_{stamp}.db"));
        let database_url = format!("sqlite:{}?mode=rwc", database_path.display());
        let pool = DbPool::connect(&database_url)
            .await
            .expect("database should connect");
        pool.execute_batch(&authorization_runtime_migration_sql(AuthDbBackend::Sqlite))
            .await
            .expect("runtime migration should apply");

        let runtime = AuthorizationRuntime::new(scoped_doc_runtime_model(), pool.clone());
        let expired_assignment = AuthorizationScopedAssignmentRecord::new(
            7,
            AuthorizationScopedAssignmentTarget::Template {
                name: "FamilyMember".to_owned(),
            },
            AuthorizationScopeBinding {
                scope: "Family".to_owned(),
                value: "42".to_owned(),
            },
        )
        .with_expires_at(Some(
            (Utc::now() - chrono::Duration::minutes(5))
                .to_rfc3339_opts(SecondsFormat::Micros, false),
        ));

        let error = runtime
            .create_assignment(expired_assignment)
            .await
            .expect_err("expired assignments should be rejected on create");
        assert!(error.contains("expires_at"));

        let created_at =
            (Utc::now() - chrono::Duration::days(2)).to_rfc3339_opts(SecondsFormat::Micros, false);
        let expired_at =
            (Utc::now() - chrono::Duration::days(1)).to_rfc3339_opts(SecondsFormat::Micros, false);
        query(&format!(
            "INSERT INTO {AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE} \
             (id, user_id, created_by_user_id, created_at, expires_at, target_kind, target_name, scope_name, scope_value) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ))
        .bind("runtime.assignment.expired")
        .bind(7_i64)
        .bind(1_i64)
        .bind(created_at)
        .bind(expired_at)
        .bind("template")
        .bind("FamilyMember")
        .bind("Family")
        .bind("42")
        .execute(&pool)
        .await
        .expect("expired assignment should insert directly");

        let listed = runtime
            .list_assignments_for_user(7)
            .await
            .expect("expired assignments should still list");
        assert_eq!(listed.len(), 1);
        assert!(listed[0].expires_at.is_some());

        let result = runtime
            .simulate_resource_action_with_user_assignments(
                Some("ScopedDoc"),
                AuthorizationSimulationInput {
                    action: AuthorizationAction::Read,
                    user_id: Some(7),
                    roles: Vec::new(),
                    claims: BTreeMap::new(),
                    row: BTreeMap::new(),
                    proposed: BTreeMap::new(),
                    related_rows: BTreeMap::new(),
                    scope: Some(AuthorizationScopeBinding {
                        scope: "Family".to_owned(),
                        value: "42".to_owned(),
                    }),
                    hybrid_source: None,
                    scoped_assignments: Vec::new(),
                },
            )
            .await
            .expect("runtime simulation should ignore expired assignments");
        assert!(result.resolved_permissions.is_empty());
        assert!(result.resolved_templates.is_empty());
    }
}
