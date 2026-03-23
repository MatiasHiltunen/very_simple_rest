use heck::ToSnakeCase;

use crate::{
    auth::AuthClaimType,
    authorization::{
        ActionAuthorization, AuthorizationAction, AuthorizationAssignment, AuthorizationCondition,
        AuthorizationExistsCondition, AuthorizationMatch, AuthorizationModel,
        AuthorizationOperator, AuthorizationValueSource, ResourceAuthorization,
    },
    security::SecurityConfig,
};

use super::model::{
    PolicyAssignment, PolicyExistsCondition, PolicyFilter, PolicyFilterExpression,
    PolicyFilterOperator, PolicyValueSource, ResourceSpec, ServiceSpec,
};

pub fn compile_service_authorization(service: &ServiceSpec) -> AuthorizationModel {
    AuthorizationModel {
        contract: service.authorization.clone(),
        resources: service
            .resources
            .iter()
            .map(|resource| {
                compile_resource_authorization(resource, &service.resources, &service.security)
            })
            .collect(),
    }
}

pub fn compile_resource_authorization(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    security: &SecurityConfig,
) -> ResourceAuthorization {
    let resource_id = resource_rule_id(&resource.struct_ident.to_string());
    ResourceAuthorization {
        id: resource_id.clone(),
        resource: resource.struct_ident.to_string(),
        table: resource.table_name.clone(),
        admin_bypass: resource.policies.admin_bypass,
        actions: vec![
            compile_filter_action(
                &resource_id,
                AuthorizationAction::Read,
                resource.roles.read.as_deref(),
                resource.policies.read.as_ref(),
                resources,
                security,
            ),
            compile_assignment_action(
                &resource_id,
                AuthorizationAction::Create,
                resource.roles.create.as_deref(),
                &resource.policies.create,
                security,
            ),
            compile_filter_action(
                &resource_id,
                AuthorizationAction::Update,
                resource.roles.update.as_deref(),
                resource.policies.update.as_ref(),
                resources,
                security,
            ),
            compile_filter_action(
                &resource_id,
                AuthorizationAction::Delete,
                resource.roles.delete.as_deref(),
                resource.policies.delete.as_ref(),
                resources,
                security,
            ),
        ],
    }
}

fn compile_filter_action(
    resource_id: &str,
    action: AuthorizationAction,
    required_role: Option<&str>,
    filters: Option<&PolicyFilterExpression>,
    resources: &[ResourceSpec],
    security: &SecurityConfig,
) -> ActionAuthorization {
    let action_id = action_rule_id(resource_id, action);
    ActionAuthorization {
        id: action_id.clone(),
        action,
        role_rule_id: required_role.map(|_| format!("{action_id}.role")),
        required_role: required_role.map(ToOwned::to_owned),
        filter: compile_filter_group(&action_id, filters, resources, security),
        assignments: Vec::new(),
    }
}

fn compile_assignment_action(
    resource_id: &str,
    action: AuthorizationAction,
    required_role: Option<&str>,
    assignments: &[PolicyAssignment],
    security: &SecurityConfig,
) -> ActionAuthorization {
    let action_id = action_rule_id(resource_id, action);
    ActionAuthorization {
        id: action_id.clone(),
        action,
        role_rule_id: required_role.map(|_| format!("{action_id}.role")),
        required_role: required_role.map(ToOwned::to_owned),
        filter: None,
        assignments: assignments
            .iter()
            .map(|assignment| compile_assignment(&action_id, assignment, security))
            .collect(),
    }
}

fn compile_filter_group(
    action_id: &str,
    filters: Option<&PolicyFilterExpression>,
    resources: &[ResourceSpec],
    security: &SecurityConfig,
) -> Option<AuthorizationCondition> {
    filters.map(|filters| {
        compile_filter_expression(&format!("{action_id}.filter"), filters, resources, security)
    })
}

fn compile_filter_expression(
    rule_id: &str,
    filter: &PolicyFilterExpression,
    resources: &[ResourceSpec],
    security: &SecurityConfig,
) -> AuthorizationCondition {
    match filter {
        PolicyFilterExpression::Match(filter) => compile_filter(rule_id, filter, security),
        PolicyFilterExpression::All(filters) => AuthorizationCondition::All {
            id: rule_id.to_owned(),
            conditions: filters
                .iter()
                .enumerate()
                .map(|(index, filter)| {
                    compile_filter_expression(
                        &format!("{rule_id}.{}", index + 1),
                        filter,
                        resources,
                        security,
                    )
                })
                .collect(),
        },
        PolicyFilterExpression::Any(filters) => AuthorizationCondition::Any {
            id: rule_id.to_owned(),
            conditions: filters
                .iter()
                .enumerate()
                .map(|(index, filter)| {
                    compile_filter_expression(
                        &format!("{rule_id}.{}", index + 1),
                        filter,
                        resources,
                        security,
                    )
                })
                .collect(),
        },
        PolicyFilterExpression::Not(filter) => AuthorizationCondition::Not {
            id: rule_id.to_owned(),
            condition: Box::new(compile_filter_expression(
                &format!("{rule_id}.inner"),
                filter,
                resources,
                security,
            )),
        },
        PolicyFilterExpression::Exists(filter) => AuthorizationCondition::Exists {
            id: rule_id.to_owned(),
            resource: filter.resource.clone(),
            table: resources
                .iter()
                .find(|resource| {
                    resource.struct_ident.to_string() == filter.resource
                        || resource.table_name == filter.resource
                })
                .map(|resource| resource.table_name.clone())
                .unwrap_or_else(|| filter.resource.to_snake_case()),
            conditions: vec![compile_exists_condition(
                &format!("{rule_id}.1"),
                &filter.condition,
                security,
            )],
        },
    }
}

fn compile_filter(
    rule_id: &str,
    filter: &PolicyFilter,
    security: &SecurityConfig,
) -> AuthorizationCondition {
    AuthorizationCondition::Match(AuthorizationMatch {
        id: rule_id.to_owned(),
        field: filter.field.clone(),
        operator: match &filter.operator {
            PolicyFilterOperator::Equals(_) => AuthorizationOperator::Equals,
            PolicyFilterOperator::IsNull => AuthorizationOperator::IsNull,
            PolicyFilterOperator::IsNotNull => AuthorizationOperator::IsNotNull,
        },
        source: match &filter.operator {
            PolicyFilterOperator::Equals(source) => Some(compile_source(source, security)),
            PolicyFilterOperator::IsNull | PolicyFilterOperator::IsNotNull => None,
        },
    })
}

fn compile_exists_condition(
    rule_id: &str,
    condition: &PolicyExistsCondition,
    security: &SecurityConfig,
) -> AuthorizationExistsCondition {
    match condition {
        PolicyExistsCondition::Match(filter) => match compile_filter(rule_id, filter, security) {
            AuthorizationCondition::Match(rule) => AuthorizationExistsCondition::Match(rule),
            _ => unreachable!("exists condition match should compile to a leaf rule"),
        },
        PolicyExistsCondition::CurrentRowField { field, row_field } => {
            AuthorizationExistsCondition::CurrentRowField {
                id: rule_id.to_owned(),
                field: field.clone(),
                row_field: row_field.clone(),
            }
        }
        PolicyExistsCondition::All(conditions) => AuthorizationExistsCondition::All {
            id: rule_id.to_owned(),
            conditions: conditions
                .iter()
                .enumerate()
                .map(|(index, condition)| {
                    compile_exists_condition(
                        &format!("{rule_id}.{}", index + 1),
                        condition,
                        security,
                    )
                })
                .collect(),
        },
        PolicyExistsCondition::Any(conditions) => AuthorizationExistsCondition::Any {
            id: rule_id.to_owned(),
            conditions: conditions
                .iter()
                .enumerate()
                .map(|(index, condition)| {
                    compile_exists_condition(
                        &format!("{rule_id}.{}", index + 1),
                        condition,
                        security,
                    )
                })
                .collect(),
        },
        PolicyExistsCondition::Not(condition) => AuthorizationExistsCondition::Not {
            id: rule_id.to_owned(),
            condition: Box::new(compile_exists_condition(
                &format!("{rule_id}.inner"),
                condition,
                security,
            )),
        },
    }
}

fn compile_assignment(
    action_id: &str,
    assignment: &PolicyAssignment,
    security: &SecurityConfig,
) -> AuthorizationAssignment {
    AuthorizationAssignment {
        id: format!(
            "{action_id}.assignment.{}",
            stable_rule_segment(&assignment.field)
        ),
        field: assignment.field.clone(),
        source: compile_source(&assignment.source, security),
    }
}

fn compile_source(
    source: &PolicyValueSource,
    security: &SecurityConfig,
) -> AuthorizationValueSource {
    match source {
        PolicyValueSource::UserId => AuthorizationValueSource::UserId,
        PolicyValueSource::Claim(name) => AuthorizationValueSource::Claim {
            name: name.clone(),
            ty: configured_claim_type(name, security),
        },
    }
}

fn configured_claim_type(claim_name: &str, security: &SecurityConfig) -> AuthClaimType {
    security
        .auth
        .claims
        .get(claim_name)
        .map(|mapping| mapping.ty)
        .unwrap_or(AuthClaimType::I64)
}

fn resource_rule_id(resource_name: &str) -> String {
    format!("resource.{}", stable_rule_segment(resource_name))
}

fn action_rule_id(resource_id: &str, action: AuthorizationAction) -> String {
    format!("{resource_id}.action.{}", action_label(action))
}

fn action_label(action: AuthorizationAction) -> &'static str {
    match action {
        AuthorizationAction::Read => "read",
        AuthorizationAction::Create => "create",
        AuthorizationAction::Update => "update",
        AuthorizationAction::Delete => "delete",
    }
}

fn stable_rule_segment(value: &str) -> String {
    let snake = value.to_snake_case();
    let mut segment = String::with_capacity(snake.len());
    let mut last_was_separator = false;
    for ch in snake.chars() {
        let normalized = if ch.is_ascii_alphanumeric() { ch } else { '_' };
        if normalized == '_' {
            if !segment.is_empty() && !last_was_separator {
                segment.push('_');
            }
            last_was_separator = true;
        } else {
            segment.push(normalized);
            last_was_separator = false;
        }
    }
    while segment.ends_with('_') {
        segment.pop();
    }
    if segment.is_empty() {
        "rule".to_owned()
    } else {
        segment
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn fixture(path: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(path)
    }

    #[test]
    fn compiles_existing_tenant_policies_into_authorization_model() {
        let loaded = super::super::eon_parser::load_service_from_path(&fixture(
            "tests/fixtures/tenant_api.eon",
        ))
        .expect("fixture should parse");
        let model = compile_service_authorization(&loaded.service);

        let resource = model.resources.first().expect("resource should exist");
        assert_eq!(resource.id, "resource.tenant_post");
        assert_eq!(resource.resource, "TenantPost");
        assert!(!resource.admin_bypass);

        let read = resource
            .action(AuthorizationAction::Read)
            .expect("read action should exist");
        assert_eq!(read.id, "resource.tenant_post.action.read");
        assert_eq!(read.role_rule_id, None);
        assert_eq!(read.required_role, None);
        assert_eq!(
            read.filter,
            Some(AuthorizationCondition::All {
                id: "resource.tenant_post.action.read.filter".to_owned(),
                conditions: vec![
                    AuthorizationCondition::Match(AuthorizationMatch {
                        id: "resource.tenant_post.action.read.filter.1".to_owned(),
                        field: "user_id".to_owned(),
                        operator: AuthorizationOperator::Equals,
                        source: Some(AuthorizationValueSource::UserId),
                    }),
                    AuthorizationCondition::Match(AuthorizationMatch {
                        id: "resource.tenant_post.action.read.filter.2".to_owned(),
                        field: "tenant_id".to_owned(),
                        operator: AuthorizationOperator::Equals,
                        source: Some(AuthorizationValueSource::Claim {
                            name: "tenant_id".to_owned(),
                            ty: AuthClaimType::I64,
                        }),
                    }),
                ],
            })
        );

        let create = resource
            .action(AuthorizationAction::Create)
            .expect("create action should exist");
        assert_eq!(create.id, "resource.tenant_post.action.create");
        assert_eq!(create.filter, None);
        assert_eq!(
            create.assignments,
            vec![
                AuthorizationAssignment {
                    id: "resource.tenant_post.action.create.assignment.user_id".to_owned(),
                    field: "user_id".to_owned(),
                    source: AuthorizationValueSource::UserId,
                },
                AuthorizationAssignment {
                    id: "resource.tenant_post.action.create.assignment.tenant_id".to_owned(),
                    field: "tenant_id".to_owned(),
                    source: AuthorizationValueSource::Claim {
                        name: "tenant_id".to_owned(),
                        ty: AuthClaimType::I64,
                    },
                },
            ]
        );
    }

    #[test]
    fn compiles_explicit_claim_types_into_authorization_sources() {
        let loaded = super::super::eon_parser::load_service_from_path(&fixture(
            "tests/fixtures/auth_claims_api.eon",
        ))
        .expect("fixture should parse");
        let model = compile_service_authorization(&loaded.service);

        let scoped_doc = model
            .resource("ScopedDoc")
            .expect("scoped doc resource should exist");
        let read = scoped_doc
            .action(AuthorizationAction::Read)
            .expect("read action should exist");
        assert_eq!(
            read.filter,
            Some(AuthorizationCondition::Match(AuthorizationMatch {
                id: "resource.scoped_doc.action.read.filter".to_owned(),
                field: "tenant_id".to_owned(),
                operator: AuthorizationOperator::Equals,
                source: Some(AuthorizationValueSource::Claim {
                    name: "tenant_id".to_owned(),
                    ty: AuthClaimType::I64,
                }),
            }))
        );

        let plan_doc = model
            .resource("PlanDoc")
            .expect("plan doc resource should exist");
        let plan_read = plan_doc
            .action(AuthorizationAction::Read)
            .expect("plan read action should exist");
        assert_eq!(
            plan_read.filter,
            Some(AuthorizationCondition::Match(AuthorizationMatch {
                id: "resource.plan_doc.action.read.filter".to_owned(),
                field: "plan".to_owned(),
                operator: AuthorizationOperator::Equals,
                source: Some(AuthorizationValueSource::Claim {
                    name: "plan".to_owned(),
                    ty: AuthClaimType::String,
                }),
            }))
        );

        let staff_doc = model
            .resource("StaffDoc")
            .expect("staff doc resource should exist");
        let staff_read = staff_doc
            .action(AuthorizationAction::Read)
            .expect("staff read action should exist");
        assert_eq!(
            staff_read.filter,
            Some(AuthorizationCondition::Match(AuthorizationMatch {
                id: "resource.staff_doc.action.read.filter".to_owned(),
                field: "staff".to_owned(),
                operator: AuthorizationOperator::Equals,
                source: Some(AuthorizationValueSource::Claim {
                    name: "staff".to_owned(),
                    ty: AuthClaimType::Bool,
                }),
            }))
        );
    }

    #[test]
    fn compiles_boolean_filter_groups_into_authorization_conditions() {
        let loaded = super::super::eon_parser::load_service_from_path(&fixture(
            "tests/fixtures/composed_policy_api.eon",
        ))
        .expect("fixture should parse");
        let model = compile_service_authorization(&loaded.service);

        let shared_doc = model
            .resource("SharedDoc")
            .expect("shared doc resource should exist");
        let read = shared_doc
            .action(AuthorizationAction::Read)
            .expect("read action should exist");
        assert_eq!(
            read.filter,
            Some(AuthorizationCondition::Any {
                id: "resource.shared_doc.action.read.filter".to_owned(),
                conditions: vec![
                    AuthorizationCondition::Match(AuthorizationMatch {
                        id: "resource.shared_doc.action.read.filter.1".to_owned(),
                        field: "owner_id".to_owned(),
                        operator: AuthorizationOperator::Equals,
                        source: Some(AuthorizationValueSource::UserId),
                    }),
                    AuthorizationCondition::All {
                        id: "resource.shared_doc.action.read.filter.2".to_owned(),
                        conditions: vec![
                            AuthorizationCondition::Match(AuthorizationMatch {
                                id: "resource.shared_doc.action.read.filter.2.1".to_owned(),
                                field: "tenant_id".to_owned(),
                                operator: AuthorizationOperator::Equals,
                                source: Some(AuthorizationValueSource::Claim {
                                    name: "tenant_id".to_owned(),
                                    ty: AuthClaimType::I64,
                                }),
                            }),
                            AuthorizationCondition::Not {
                                id: "resource.shared_doc.action.read.filter.2.2".to_owned(),
                                condition: Box::new(AuthorizationCondition::Match(
                                    AuthorizationMatch {
                                        id: "resource.shared_doc.action.read.filter.2.2.inner"
                                            .to_owned(),
                                        field: "blocked_user_id".to_owned(),
                                        operator: AuthorizationOperator::Equals,
                                        source: Some(AuthorizationValueSource::UserId),
                                    },
                                )),
                            },
                        ],
                    },
                ],
            })
        );
    }

    #[test]
    fn compiles_exists_filter_groups_into_authorization_conditions() {
        let loaded = super::super::eon_parser::load_service_from_path(&fixture(
            "tests/fixtures/exists_policy_api.eon",
        ))
        .expect("fixture should parse");
        let model = compile_service_authorization(&loaded.service);

        let shared_doc = model
            .resource("SharedDoc")
            .expect("shared doc resource should exist");
        let read = shared_doc
            .action(AuthorizationAction::Read)
            .expect("read action should exist");
        assert_eq!(
            read.filter,
            Some(AuthorizationCondition::Exists {
                id: "resource.shared_doc.action.read.filter".to_owned(),
                resource: "FamilyMember".to_owned(),
                table: "family_member".to_owned(),
                conditions: vec![AuthorizationExistsCondition::All {
                    id: "resource.shared_doc.action.read.filter.1".to_owned(),
                    conditions: vec![
                        AuthorizationExistsCondition::CurrentRowField {
                            id: "resource.shared_doc.action.read.filter.1.1".to_owned(),
                            field: "family_id".to_owned(),
                            row_field: "family_id".to_owned(),
                        },
                        AuthorizationExistsCondition::Match(AuthorizationMatch {
                            id: "resource.shared_doc.action.read.filter.1.2".to_owned(),
                            field: "user_id".to_owned(),
                            operator: AuthorizationOperator::Equals,
                            source: Some(AuthorizationValueSource::UserId),
                        }),
                    ],
                }],
            })
        );
    }

    #[test]
    fn compiles_nested_exists_boolean_groups_into_authorization_conditions() {
        let loaded = super::super::eon_parser::load_service_from_path(&fixture(
            "tests/fixtures/exists_group_policy_api.eon",
        ))
        .expect("fixture should parse");
        let model = compile_service_authorization(&loaded.service);

        let shared_doc = model
            .resource("SharedDoc")
            .expect("shared doc resource should exist");
        let read = shared_doc
            .action(AuthorizationAction::Read)
            .expect("read action should exist");
        assert_eq!(
            read.filter,
            Some(AuthorizationCondition::Exists {
                id: "resource.shared_doc.action.read.filter".to_owned(),
                resource: "FamilyAccess".to_owned(),
                table: "family_access".to_owned(),
                conditions: vec![AuthorizationExistsCondition::All {
                    id: "resource.shared_doc.action.read.filter.1".to_owned(),
                    conditions: vec![
                        AuthorizationExistsCondition::CurrentRowField {
                            id: "resource.shared_doc.action.read.filter.1.1".to_owned(),
                            field: "family_id".to_owned(),
                            row_field: "family_id".to_owned(),
                        },
                        AuthorizationExistsCondition::Any {
                            id: "resource.shared_doc.action.read.filter.1.2".to_owned(),
                            conditions: vec![
                                AuthorizationExistsCondition::Match(AuthorizationMatch {
                                    id: "resource.shared_doc.action.read.filter.1.2.1".to_owned(),
                                    field: "primary_user_id".to_owned(),
                                    operator: AuthorizationOperator::Equals,
                                    source: Some(AuthorizationValueSource::UserId),
                                }),
                                AuthorizationExistsCondition::Match(AuthorizationMatch {
                                    id: "resource.shared_doc.action.read.filter.1.2.2".to_owned(),
                                    field: "delegate_user_id".to_owned(),
                                    operator: AuthorizationOperator::Equals,
                                    source: Some(AuthorizationValueSource::UserId),
                                }),
                            ],
                        },
                    ],
                }],
            })
        );
    }

    #[test]
    fn compiles_null_check_filters_into_authorization_conditions() {
        let loaded = super::super::eon_parser::load_service_from_path(&fixture(
            "tests/fixtures/null_policy_api.eon",
        ))
        .expect("fixture should parse");
        let model = compile_service_authorization(&loaded.service);

        let note = model.resource("Note").expect("note resource should exist");
        let read = note
            .action(AuthorizationAction::Read)
            .expect("read action should exist");
        assert_eq!(
            read.filter,
            Some(AuthorizationCondition::Match(AuthorizationMatch {
                id: "resource.note.action.read.filter".to_owned(),
                field: "archived_at".to_owned(),
                operator: AuthorizationOperator::IsNull,
                source: None,
            }))
        );
    }

    #[test]
    fn carries_static_authorization_contract_into_compiled_model() {
        let loaded = super::super::eon_parser::load_service_from_path(&fixture(
            "tests/fixtures/hybrid_runtime_api.eon",
        ))
        .expect("fixture should parse");
        let model = compile_service_authorization(&loaded.service);

        assert_eq!(model.contract.scopes.len(), 1);
        assert_eq!(model.contract.scopes[0].name, "Family");
        assert_eq!(model.contract.permissions.len(), 2);
        assert_eq!(model.contract.permissions[0].name, "FamilyManage");
        assert_eq!(
            model.contract.permissions[0].actions,
            vec![
                AuthorizationAction::Create,
                AuthorizationAction::Read,
                AuthorizationAction::Update,
                AuthorizationAction::Delete
            ]
        );
        assert_eq!(model.contract.templates.len(), 1);
        assert_eq!(model.contract.templates[0].name, "FamilyMember");
        assert_eq!(model.contract.hybrid_enforcement.resources.len(), 2);
        let scoped_doc = model
            .contract
            .hybrid_enforcement
            .resources
            .iter()
            .find(|resource| resource.resource == "ScopedDoc")
            .expect("scoped doc hybrid resource should exist");
        assert_eq!(scoped_doc.scope_field, "family_id");
        assert_eq!(
            scoped_doc.actions,
            vec![
                AuthorizationAction::Create,
                AuthorizationAction::Read,
                AuthorizationAction::Update,
                AuthorizationAction::Delete
            ]
        );
        let scoped_claim_doc = model
            .contract
            .hybrid_enforcement
            .resources
            .iter()
            .find(|resource| resource.resource == "ScopedClaimDoc")
            .expect("scoped claim doc hybrid resource should exist");
        assert_eq!(scoped_claim_doc.scope_field, "family_id");
        assert_eq!(
            scoped_claim_doc.actions,
            vec![AuthorizationAction::Create, AuthorizationAction::Read]
        );
    }

    #[test]
    fn generates_stable_role_and_assignment_rule_ids() {
        let loaded = super::super::eon_parser::load_service_from_path(&fixture(
            "tests/fixtures/tenant_api.eon",
        ))
        .expect("fixture should parse");
        let model = compile_service_authorization(&loaded.service);

        let resource = model.resources.first().expect("resource should exist");
        let create = resource
            .action(AuthorizationAction::Create)
            .expect("create action should exist");

        assert_eq!(resource.id, "resource.tenant_post");
        assert_eq!(create.id, "resource.tenant_post.action.create");
        assert_eq!(create.role_rule_id, None);
        assert_eq!(
            create.assignments[0].id,
            "resource.tenant_post.action.create.assignment.user_id"
        );
    }
}
