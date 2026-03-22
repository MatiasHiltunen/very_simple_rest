use std::collections::{BTreeMap, BTreeSet};

use actix_web::{HttpResponse, Responder, web};
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
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationContract {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<AuthorizationScope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<AuthorizationPermission>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<AuthorizationTemplate>,
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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScopedAssignmentCreateInput {
    pub user_id: i64,
    pub target: AuthorizationScopedAssignmentTarget,
    pub scope: AuthorizationScopeBinding,
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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationMatch {
    pub id: String,
    pub field: String,
    pub operator: AuthorizationOperator,
    pub source: AuthorizationValueSource,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<AuthorizationScopeBinding>,
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
        source: AuthorizationValueSource,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationScopedAssignmentTrace {
    pub id: String,
    pub target: AuthorizationScopedAssignmentTarget,
    pub scope: AuthorizationScopeBinding,
    pub scope_matched: bool,
    pub target_matched: bool,
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
        self.scopes.is_empty() && self.permissions.is_empty() && self.templates.is_empty()
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
        }
    }

    pub fn scoped_assignment(&self) -> AuthorizationScopedAssignment {
        AuthorizationScopedAssignment {
            id: self.id.clone(),
            target: self.target.clone(),
            scope: self.scope.clone(),
        }
    }
}

impl AuthorizationScopedAssignmentCreateInput {
    pub fn into_record(self) -> AuthorizationScopedAssignmentRecord {
        AuthorizationScopedAssignmentRecord::new(self.user_id, self.target, self.scope)
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
            if admin_bypass_applied {
                notes.push("Admin bypass skipped row filter evaluation".to_owned());
            } else if let Some(filter) = &action.filter {
                let trace = evaluate_condition_trace(filter, input);
                if trace.is_indeterminate() && trace.has_missing_field() {
                    notes.push("Simulation row is missing one or more policy fields".to_owned());
                    outcome = AuthorizationOutcome::Incomplete;
                } else if trace.is_indeterminate() && trace.has_missing_source() {
                    notes.push("Missing principal values required by the row policy".to_owned());
                    outcome = AuthorizationOutcome::Denied;
                } else if !trace.matched() {
                    notes.push("Row policy conditions did not match".to_owned());
                    outcome = AuthorizationOutcome::Denied;
                }
                filter_trace = Some(trace);
            }

            assignments = action
                .assignments
                .iter()
                .map(|assignment| evaluate_assignment_trace(self, input, admin, assignment))
                .collect();

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
            return Err(
                "runtime scoped assignments require a simulated scope; pass `--scope ScopeName=value`"
                    .to_owned(),
            );
        }

        self.validate_scoped_assignments(&input.scoped_assignments)?;

        let mut result = resource.simulate_action(input).ok_or_else(|| {
            format!(
                "resource `{}` does not define the requested action",
                resource.resource
            )
        })?;

        let resolved = self.resolve_runtime_assignments(resource, input);
        result.scope = input.scope.clone();
        result.runtime_assignments = resolved.traces;
        result.resolved_permissions = resolved.permissions.into_iter().collect();
        result.resolved_templates = resolved.templates.into_iter().collect();
        if !result.runtime_assignments.is_empty() {
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
            scope: Some(scope.clone()),
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

    pub async fn create_assignment(
        &self,
        assignment: AuthorizationScopedAssignmentRecord,
    ) -> Result<AuthorizationScopedAssignmentRecord, String> {
        self.model
            .validate_scoped_assignments(std::slice::from_ref(&assignment.scoped_assignment()))?;
        insert_runtime_assignment(&self.pool, &assignment).await?;
        Ok(assignment)
    }

    pub async fn delete_assignment(&self, assignment_id: &str) -> Result<bool, String> {
        delete_runtime_assignment(&self.pool, assignment_id).await
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
    fn supports_scope(&self, scope_name: &str) -> bool {
        self.scopes.is_empty() || self.scopes.iter().any(|scope| scope == scope_name)
    }

    fn matches_resource_action(&self, resource: &str, action: AuthorizationAction) -> bool {
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

    format!(
        "-- Generated by very_simple_rest for runtime authorization assignments.\n\n\
         CREATE TABLE {table} (\n\
             {id_column},\n\
             {user_id_column},\n\
             {target_kind_column},\n\
             {target_name_column},\n\
             {scope_name_column},\n\
             {scope_value_column}\n\
         );\n\n\
         CREATE INDEX idx_{table}_user ON {table} (user_id);\n\
         CREATE INDEX idx_{table}_scope ON {table} (scope_name, scope_value);\n",
        table = AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE,
    )
}

pub fn authorization_management_routes(cfg: &mut web::ServiceConfig) {
    errors::configure_extractor_errors(cfg);
    cfg.route(
        "/authz/runtime/evaluate",
        web::post().to(evaluate_runtime_access_endpoint),
    );
    cfg.route(
        "/authz/runtime/assignments",
        web::get().to(list_runtime_assignments_endpoint),
    );
    cfg.route(
        "/authz/runtime/assignments",
        web::post().to(create_runtime_assignment_endpoint),
    );
    cfg.route(
        "/authz/runtime/assignments/{id}",
        web::delete().to(delete_runtime_assignment_endpoint),
    );
}

pub fn new_runtime_assignment_id() -> String {
    format!("runtime.assignment.{}", Uuid::new_v4())
}

pub async fn insert_runtime_assignment(
    pool: &DbPool,
    assignment: &AuthorizationScopedAssignmentRecord,
) -> Result<(), String> {
    let (target_kind, target_name) = runtime_assignment_target_parts(&assignment.target);
    query(&format!(
        "INSERT INTO {AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE} \
         (id, user_id, target_kind, target_name, scope_name, scope_value) \
         VALUES (?, ?, ?, ?, ?, ?)"
    ))
    .bind(&assignment.id)
    .bind(assignment.user_id)
    .bind(target_kind)
    .bind(target_name)
    .bind(&assignment.scope.scope)
    .bind(&assignment.scope.value)
    .execute(pool)
    .await
    .map_err(runtime_assignment_storage_error)?;
    Ok(())
}

pub async fn list_runtime_assignments_for_user(
    pool: &DbPool,
    user_id: i64,
) -> Result<Vec<AuthorizationScopedAssignmentRecord>, String> {
    let rows = query(&format!(
        "SELECT id, user_id, target_kind, target_name, scope_name, scope_value \
         FROM {AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE} WHERE user_id = ? ORDER BY id"
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(runtime_assignment_storage_error)?;

    rows.into_iter()
        .map(runtime_assignment_record_from_row)
        .collect()
}

pub async fn delete_runtime_assignment(pool: &DbPool, assignment_id: &str) -> Result<bool, String> {
    let result = query(&format!(
        "DELETE FROM {AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE} WHERE id = ?"
    ))
    .bind(assignment_id)
    .execute(pool)
    .await
    .map_err(runtime_assignment_storage_error)?;
    Ok(result.rows_affected() != 0)
}

pub async fn load_runtime_assignments_for_user(
    pool: &DbPool,
    user_id: i64,
) -> Result<Vec<AuthorizationScopedAssignment>, String> {
    list_runtime_assignments_for_user(pool, user_id)
        .await
        .map(|assignments| {
            assignments
                .into_iter()
                .map(|assignment| assignment.scoped_assignment())
                .collect()
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
}

impl AuthorizationConditionTrace {
    pub fn matched(&self) -> bool {
        match self {
            Self::Match { matched, .. }
            | Self::All { matched, .. }
            | Self::Any { matched, .. }
            | Self::Not { matched, .. } => *matched,
        }
    }

    pub fn is_indeterminate(&self) -> bool {
        match self {
            Self::Match { indeterminate, .. }
            | Self::All { indeterminate, .. }
            | Self::Any { indeterminate, .. }
            | Self::Not { indeterminate, .. } => *indeterminate,
        }
    }

    pub fn has_missing_field(&self) -> bool {
        match self {
            Self::Match { missing_field, .. } => *missing_field,
            Self::All { conditions, .. } | Self::Any { conditions, .. } => {
                conditions.iter().any(Self::has_missing_field)
            }
            Self::Not { condition, .. } => condition.has_missing_field(),
        }
    }

    pub fn has_missing_source(&self) -> bool {
        match self {
            Self::Match { missing_source, .. } => *missing_source,
            Self::All { conditions, .. } | Self::Any { conditions, .. } => {
                conditions.iter().any(Self::has_missing_source)
            }
            Self::Not { condition, .. } => condition.has_missing_source(),
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
            let source_value = resolve_source_value(&rule.source, input);
            let missing_field = row_value.is_none();
            let missing_source = source_value.is_none();
            let indeterminate = missing_field || missing_source;
            let matched = match (&row_value, &source_value, rule.operator) {
                (Some(row_value), Some(source_value), AuthorizationOperator::Equals) => {
                    row_value == source_value
                }
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
    }
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

fn runtime_assignment_target_parts(
    target: &AuthorizationScopedAssignmentTarget,
) -> (&'static str, &str) {
    match target {
        AuthorizationScopedAssignmentTarget::Permission { name } => ("permission", name.as_str()),
        AuthorizationScopedAssignmentTarget::Template { name } => ("template", name.as_str()),
    }
}

fn runtime_assignment_record_from_row(
    row: sqlx::any::AnyRow,
) -> Result<AuthorizationScopedAssignmentRecord, String> {
    let id: String = row.try_get("id").map_err(|error| error.to_string())?;
    let user_id: i64 = row.try_get("user_id").map_err(|error| error.to_string())?;
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
    Ok(AuthorizationScopedAssignmentRecord {
        id,
        user_id,
        target,
        scope: AuthorizationScopeBinding {
            scope: scope_name,
            value: scope_value,
        },
    })
}

fn runtime_assignment_storage_error(error: sqlx::Error) -> String {
    if is_missing_runtime_assignment_table(&error) {
        format!(
            "runtime authorization assignment table `{AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE}` does not exist; generate and apply the authz runtime migration first"
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

async fn create_runtime_assignment_endpoint(
    user: UserContext,
    input: web::Json<AuthorizationScopedAssignmentCreateInput>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    if !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    match runtime
        .create_assignment(input.into_inner().into_record())
        .await
    {
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

    match runtime.delete_assignment(&path.into_inner()).await {
        Ok(true) => HttpResponse::NoContent().finish(),
        Ok(false) => errors::not_found("Runtime authorization assignment not found"),
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
            source: AuthorizationValueSource::UserId,
        })
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
                scope: None,
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
                scope: None,
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
                scope: None,
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
                scope: None,
                scoped_assignments: Vec::new(),
            })
            .expect("action should exist");

        assert_eq!(result.outcome, AuthorizationOutcome::Allowed);
        assert_eq!(result.assignments.len(), 1);
        assert!(result.assignments[0].admin_override_applied);
        assert_eq!(result.assignments[0].effective_value, Some(Value::from(42)));
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
                    scope: Some(AuthorizationScopeBinding {
                        scope: "Family".to_owned(),
                        value: "42".to_owned(),
                    }),
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
                    scope: Some(AuthorizationScopeBinding {
                        scope: "Household".to_owned(),
                        value: "42".to_owned(),
                    }),
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
    fn authorization_runtime_migration_sql_mentions_runtime_assignment_table() {
        let sql = authorization_runtime_migration_sql(AuthDbBackend::Sqlite);
        assert!(sql.contains(&format!(
            "CREATE TABLE {AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE}"
        )));
        assert!(sql.contains("target_kind"));
        assert!(sql.contains("scope_name"));
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
        let assignment = AuthorizationScopedAssignmentRecord::new(
            7,
            AuthorizationScopedAssignmentTarget::Template {
                name: "FamilyMember".to_owned(),
            },
            AuthorizationScopeBinding {
                scope: "Family".to_owned(),
                value: "42".to_owned(),
            },
        );

        let created = runtime
            .create_assignment(assignment.clone())
            .await
            .expect("assignment should persist");
        assert_eq!(created.user_id, 7);

        let stored = runtime
            .list_assignments_for_user(7)
            .await
            .expect("assignments should load");
        assert_eq!(stored, vec![assignment.clone()]);

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
                    scope: Some(AuthorizationScopeBinding {
                        scope: "Family".to_owned(),
                        value: "42".to_owned(),
                    }),
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

        let deleted = runtime
            .delete_assignment(&assignment.id)
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
    }
}
