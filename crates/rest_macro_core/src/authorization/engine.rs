use std::collections::{BTreeMap, BTreeSet};

use actix_web::HttpResponse;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{auth::UserContext, errors};

use super::db_ops::load_runtime_assignments_for_user;
use super::types::{
    ActionAuthorization, AuthorizationAction, AuthorizationAssignment, AuthorizationAssignmentTrace,
    AuthorizationCondition, AuthorizationConditionTrace, AuthorizationExistsCondition,
    AuthorizationExistsConditionTrace, AuthorizationHybridResource, AuthorizationHybridSimulationTrace,
    AuthorizationHybridSource, AuthorizationLiteralValue, AuthorizationModel,
    AuthorizationOperator, AuthorizationOutcome, AuthorizationRuntime,
    AuthorizationRuntimeAccessResult, AuthorizationScopeBinding, AuthorizationScopedAssignment,
    AuthorizationScopedAssignmentTarget, AuthorizationScopedAssignmentTrace,
    AuthorizationSimulationInput, AuthorizationSimulationResult,
    AuthorizationValueSource, ResolvedRuntimeAssignments, ResourceAuthorization,
    exists_trace_has_missing_field, exists_trace_has_missing_related_field,
    exists_trace_has_missing_source, exists_trace_is_indeterminate, exists_trace_matched,
};
use super::db_ops::{
    create_runtime_assignment_with_audit, delete_runtime_assignment_with_audit,
    list_runtime_assignment_events_for_user, list_runtime_assignments_for_user as list_assignments,
    renew_runtime_assignment_with_audit, revoke_runtime_assignment_with_audit,
};

pub fn parse_runtime_assignment_timestamp(field: &str, value: &str) -> Result<DateTime<Utc>, String> {
    if value.trim().is_empty() {
        return Err(format!("runtime assignment `{field}` cannot be empty"));
    }
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| format!("runtime assignment `{field}` must be RFC3339: {error}"))
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

        if !input.scoped_assignments.is_empty()
            && input.scope.is_none()
            && input.hybrid_source.is_none()
        {
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

    pub(super) fn resolve_runtime_assignments(
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
                        if let Some(permission) = self.contract.permission(name)
                            && permission.matches_resource_action(&resource.resource, input.action)
                        {
                            target_matched = true;
                            resolved_permissions.push(permission.name.clone());
                            resolved.permissions.insert(permission.name.clone());
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
    pub fn new(model: AuthorizationModel, pool: impl Into<crate::db::DbPool>) -> Self {
        Self {
            model,
            pool: pool.into(),
        }
    }

    pub fn model(&self) -> &AuthorizationModel {
        &self.model
    }

    pub fn pool(&self) -> &crate::db::DbPool {
        &self.pool
    }

    pub async fn list_assignments_for_user(
        &self,
        user_id: i64,
    ) -> Result<Vec<super::types::AuthorizationScopedAssignmentRecord>, String> {
        list_assignments(&self.pool, user_id).await
    }

    pub async fn list_assignment_events_for_user(
        &self,
        user_id: i64,
    ) -> Result<Vec<super::types::AuthorizationScopedAssignmentEventRecord>, String> {
        list_runtime_assignment_events_for_user(&self.pool, user_id).await
    }

    pub async fn create_assignment(
        &self,
        assignment: super::types::AuthorizationScopedAssignmentRecord,
    ) -> Result<super::types::AuthorizationScopedAssignmentRecord, String> {
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
    ) -> Result<Option<super::types::AuthorizationScopedAssignmentRecord>, String> {
        revoke_runtime_assignment_with_audit(&self.pool, assignment_id, actor_user_id, reason).await
    }

    pub async fn renew_assignment_with_audit(
        &self,
        assignment_id: &str,
        expires_at: &str,
        actor_user_id: Option<i64>,
        reason: Option<String>,
    ) -> Result<Option<super::types::AuthorizationScopedAssignmentRecord>, String> {
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

pub(super) fn evaluate_condition_trace(
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
        AuthorizationValueSource::Literal { value } => Some(match value {
            AuthorizationLiteralValue::String(value) => Value::String(value.clone()),
            AuthorizationLiteralValue::I64(value) => Value::from(*value),
            AuthorizationLiteralValue::Bool(value) => Value::from(*value),
        }),
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
