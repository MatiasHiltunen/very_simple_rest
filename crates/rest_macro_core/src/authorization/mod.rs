mod db_ops;
mod engine;
mod handlers;
mod migrations;
mod routing;
pub(crate) mod types;

pub use types::{
    ActionAuthorization,
    AuthorizationAction,
    AuthorizationAssignment,
    AuthorizationAssignmentTrace,
    AuthorizationCondition,
    AuthorizationConditionTrace,
    AuthorizationContract,
    AuthorizationExistsCondition,
    AuthorizationExistsConditionTrace,
    AuthorizationHybridEnforcementConfig,
    AuthorizationHybridResource,
    AuthorizationHybridSimulationTrace,
    AuthorizationHybridSource,
    AuthorizationHybridScopeSources,
    AuthorizationLiteralValue,
    AuthorizationManagementApiConfig,
    AuthorizationMatch,
    AuthorizationModel,
    AuthorizationOperator,
    AuthorizationOutcome,
    AuthorizationPermission,
    AuthorizationRuntime,
    AuthorizationRuntimeAccessInput,
    AuthorizationRuntimeAccessResult,
    AuthorizationScope,
    AuthorizationScopeBinding,
    AuthorizationScopedAssignment,
    AuthorizationScopedAssignmentCreateInput,
    AuthorizationScopedAssignmentEventKind,
    AuthorizationScopedAssignmentEventRecord,
    AuthorizationScopedAssignmentListQuery,
    AuthorizationScopedAssignmentRecord,
    AuthorizationScopedAssignmentRenewInput,
    AuthorizationScopedAssignmentRevokeInput,
    AuthorizationScopedAssignmentTarget,
    AuthorizationScopedAssignmentTrace,
    AuthorizationSimulationInput,
    AuthorizationSimulationResult,
    AuthorizationTemplate,
    AuthorizationValueSource,
    DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT,
    AUTHORIZATION_RUNTIME_ASSIGNMENT_TABLE,
    AUTHORIZATION_RUNTIME_ASSIGNMENT_EVENT_TABLE,
    ResourceAuthorization,
};

pub use migrations::authorization_runtime_migration_sql;

pub use routing::{authorization_management_routes, authorization_management_routes_at};

pub use db_ops::{
    create_runtime_assignment_with_audit,
    delete_runtime_assignment_with_audit,
    insert_runtime_assignment,
    insert_runtime_assignment_event,
    list_runtime_assignment_events_for_user,
    list_runtime_assignments_for_user,
    load_runtime_assignments_for_user,
    new_runtime_assignment_event_id,
    new_runtime_assignment_id,
    renew_runtime_assignment_with_audit,
    revoke_runtime_assignment_with_audit,
    runtime_assignment_timestamp_now,
};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use serde_json::Value;
    use super::*;
    use crate::auth::{AuthClaimType, AuthDbBackend};
    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    use crate::db::DbPool;
    #[cfg(feature = "turso-local")]
    use crate::database::{DatabaseConfig, DatabaseEngine, TursoLocalConfig};
    #[cfg(feature = "turso-local")]
    use crate::db::connect_with_config;

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    async fn runtime_test_pool(prefix: &str) -> DbPool {
        #[cfg(feature = "turso-local")]
        {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be valid")
                .as_nanos();
            let database_path =
                std::env::temp_dir().join(format!("vsr_authz_runtime_{prefix}_{stamp}.db"));
            let config = DatabaseConfig {
                engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                    path: database_path.to_string_lossy().into_owned(),
                    encryption_key: None,
                }),
                resilience: None,
            };
            return connect_with_config("sqlite:ignored.db?mode=rwc", &config)
                .await
                .expect("database should connect");
        }
        #[cfg(all(not(feature = "turso-local"), feature = "sqlite"))]
        {
            sqlx::any::install_default_drivers();

            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be valid")
                .as_nanos();
            let database_path =
                std::env::temp_dir().join(format!("vsr_authz_runtime_{prefix}_{stamp}.db"));
            let database_url = format!("sqlite:{}?mode=rwc", database_path.display());
            return DbPool::connect(&database_url)
                .await
                .expect("database should connect");
        }
    }

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

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
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

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    #[actix_web::test]
    async fn authorization_runtime_persists_and_loads_scoped_assignments() {
        let pool = runtime_test_pool("persist").await;
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

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    #[actix_web::test]
    async fn authorization_runtime_rejects_expired_assignment_creation_and_ignores_expired_rows() {
        let pool = runtime_test_pool("expired").await;
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
