//! Native update/delete planning and hybrid authorization dispatch.

use std::{future::Future, sync::Arc};

use crate::{
    authz::policy::PolicyFilterExpression,
    field::{FieldKind, GeneratedValue},
    model::GeneratedTemporalKind,
    native_policy_sql::{
        PlanOutcome, PolicyPrincipal, build_row_policy_plan, render_condition_with_placeholders,
    },
    native_resource::{RuntimeBoundValue, RuntimeResource},
    native_write::WriteAssignment,
};

/// Mutation being authorized and executed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationAction {
    /// Update stored fields, including a custom update action.
    Update,
    /// Delete the resource row, including a custom delete action.
    Delete,
}

/// SQL assembled from trusted resource identifiers with separate bound values.
#[derive(Clone, Debug, PartialEq)]
pub struct MutationStatement {
    /// SQL in the resource's database dialect.
    pub sql: String,
    /// Values in placeholder order.
    pub binds: Vec<RuntimeBoundValue>,
}

/// Direct policy check and an optional statement requiring a hybrid grant.
#[derive(Clone, Debug)]
pub struct MutationPlan {
    /// Action used for the scoped authorization decision.
    pub action: MutationAction,
    /// Row ID for the scoped authorization lookup.
    pub record_id: i64,
    /// Statement with the row policy, absent when required claims are missing.
    pub direct: Option<MutationStatement>,
    /// Unfiltered statement to execute only after the hybrid authorizer allows it.
    pub hybrid: Option<MutationStatement>,
}

/// Error while preparing a native update or delete.
#[derive(Debug)]
pub enum MutationPlanError {
    /// The update has no writable fields.
    NoUpdatableFields,
    /// Lowered resource or policy descriptors are inconsistent.
    InvalidDescriptor(String),
}

/// Outcome that the transport maps to its success or concealed-row response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationOutcome {
    /// At least one row was changed.
    Applied,
    /// No matching row or authorized hybrid scope was found.
    NotFound,
}

/// Executes one mutation attempt, optionally within an audit transaction.
pub trait MutationExecutor: Send + Sync {
    /// Return affected rows only after any required audit event has committed.
    /// A failed or unmatched audited attempt must roll back before returning.
    fn execute(
        &self,
        action: MutationAction,
        statement: &MutationStatement,
    ) -> impl Future<Output = Result<u64, String>> + Send;
}

/// Resolves a hybrid grant against the existing row's configured scope.
pub trait HybridMutationAuthorizer: Send + Sync {
    /// Return true only when the row exists and its scope grants this action.
    fn allows(
        &self,
        action: MutationAction,
        record_id: i64,
    ) -> impl Future<Output = Result<bool, String>> + Send;
}

/// Build an update from validated regular or custom action assignments.
pub fn build_update_plan(
    resource: &RuntimeResource,
    resources: &[Arc<RuntimeResource>],
    assignments: &[WriteAssignment],
    record_id: i64,
    principal: &PolicyPrincipal<'_>,
    is_admin: bool,
) -> Result<MutationPlan, MutationPlanError> {
    if assignments.is_empty() {
        return Err(MutationPlanError::NoUpdatableFields);
    }
    let mut parts = Vec::new();
    let mut binds = Vec::new();
    for assignment in assignments {
        parts.push(format!(
            "{} = {}",
            assignment.field_name,
            resource.db.placeholder(binds.len() + 1)
        ));
        binds.push(assignment.value.clone());
    }
    for field in &resource.fields {
        if field.generated == GeneratedValue::UpdatedAt {
            let kind = match field.kind {
                FieldKind::DateTime | FieldKind::Text => Some(GeneratedTemporalKind::DateTime),
                FieldKind::Date => Some(GeneratedTemporalKind::Date),
                FieldKind::Time => Some(GeneratedTemporalKind::Time),
                _ => None,
            };
            parts.push(format!(
                "{} = {}",
                field.name,
                resource.db.generated_temporal_expression(kind)
            ));
        }
    }
    let sql = format!(
        "UPDATE {} SET {} WHERE {} = {}",
        resource.table_name,
        parts.join(", "),
        resource.id_field,
        resource.db.placeholder(binds.len() + 1)
    );
    binds.push(RuntimeBoundValue::Integer(record_id));
    build_plan(
        resource,
        resources,
        MutationStatement { sql, binds },
        MutationAction::Update,
        record_id,
        principal,
        is_admin,
    )
}

/// Build a delete using the same row policy and hybrid dispatch as updates.
pub fn build_delete_plan(
    resource: &RuntimeResource,
    resources: &[Arc<RuntimeResource>],
    record_id: i64,
    principal: &PolicyPrincipal<'_>,
    is_admin: bool,
) -> Result<MutationPlan, MutationPlanError> {
    build_plan(
        resource,
        resources,
        MutationStatement {
            sql: format!(
                "DELETE FROM {} WHERE {} = {}",
                resource.table_name,
                resource.id_field,
                resource.db.placeholder(1)
            ),
            binds: vec![RuntimeBoundValue::Integer(record_id)],
        },
        MutationAction::Delete,
        record_id,
        principal,
        is_admin,
    )
}

fn build_plan(
    resource: &RuntimeResource,
    resources: &[Arc<RuntimeResource>],
    unfiltered: MutationStatement,
    action: MutationAction,
    record_id: i64,
    principal: &PolicyPrincipal<'_>,
    is_admin: bool,
) -> Result<MutationPlan, MutationPlanError> {
    let policy: Option<&PolicyFilterExpression> = match action {
        MutationAction::Update => resource.policies.update.as_ref(),
        MutationAction::Delete => resource.policies.delete.as_ref(),
    };
    let Some(policy) = policy.filter(|_| !(resource.policies.admin_bypass && is_admin)) else {
        return Ok(MutationPlan {
            action,
            record_id,
            direct: Some(unfiltered),
            hybrid: None,
        });
    };
    let direct = match build_row_policy_plan(resource, resources, policy, principal)
        .map_err(|error| MutationPlanError::InvalidDescriptor(error.to_string()))?
    {
        PlanOutcome::Resolved(policy) => {
            let mut statement = unfiltered.clone();
            statement.sql.push_str(" AND ");
            statement.sql.push_str(&render_condition_with_placeholders(
                &policy.condition,
                resource.db,
                statement.binds.len() + 1,
            ));
            statement.binds.extend(policy.binds);
            Some(statement)
        }
        PlanOutcome::Indeterminate => None,
    };
    Ok(MutationPlan {
        action,
        record_id,
        direct,
        hybrid: Some(unfiltered),
    })
}

/// Execute the direct policy first, then consult hybrid grants only on a miss.
///
/// Missing claims skip the direct statement. Execution and authorization errors
/// terminate dispatch; they never authorize an unfiltered retry. Role checks
/// remain the caller's responsibility before planning the mutation.
pub async fn execute_mutation(
    plan: &MutationPlan,
    executor: &impl MutationExecutor,
    authorizer: &impl HybridMutationAuthorizer,
) -> Result<MutationOutcome, String> {
    if let Some(statement) = &plan.direct
        && executor.execute(plan.action, statement).await? > 0
    {
        return Ok(MutationOutcome::Applied);
    }
    if let Some(statement) = &plan.hybrid
        && authorizer.allows(plan.action, plan.record_id).await?
        && executor.execute(plan.action, statement).await? > 0
    {
        return Ok(MutationOutcome::Applied);
    }
    Ok(MutationOutcome::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authz::{
            RoleRequirements,
            policy::{
                PolicyComparisonValue, PolicyFilter, PolicyFilterOperator, PolicyValueSource,
                RowPolicies,
            },
        },
        field::{FieldValidation, RuntimeField},
        model::DbBackend,
        native_resource::{RuntimeAuditConfig, RuntimeCreateFieldRule},
    };
    use serde_json::json;
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
        sync::Mutex,
    };
    fn field(name: &str, kind: FieldKind) -> RuntimeField {
        RuntimeField {
            name: name.into(),
            api_name: name.into(),
            expose_in_api: true,
            enum_values: None,
            transforms: Vec::new(),
            kind,
            list_item_kind: None,
            object_fields: None,
            optional: false,
            generated: GeneratedValue::None,
            validation: FieldValidation::default(),
            supports_exact_filters: false,
            supports_sort: false,
            supports_range_filters: false,
        }
    }

    fn resource(fields: Vec<RuntimeField>) -> RuntimeResource {
        let field_index = fields
            .iter()
            .enumerate()
            .map(|(index, field)| (field.name.clone(), index))
            .collect();
        let create_fields = fields
            .iter()
            .map(|field| RuntimeCreateFieldRule {
                name: field.name.clone(),
                allow_admin_override: false,
                allow_hybrid_runtime: false,
                payload_optional: field.optional,
            })
            .collect();
        RuntimeResource {
            resource_name: "Document".into(),
            table_name: "document".into(),
            api_name: "documents".into(),
            default_response_context: None,
            id_field: "id".into(),
            id_api_name: "id".into(),
            db: DbBackend::Sqlite,
            roles: RoleRequirements::default(),
            policies: RowPolicies::default(),
            default_limit: None,
            max_limit: None,
            filterable_in: BTreeSet::new(),
            count_endpoint: false,
            create_assignment_sources: HashMap::new(),
            fields,
            field_index,
            api_field_index: HashMap::new(),
            response_contexts: HashMap::new(),
            computed_fields: Vec::new(),
            create_fields,
            update_field_names: Vec::new(),
            actions: Vec::new(),
            audit: None,
            is_audit_sink: false,
            read_requires_auth: false,
            hybrid: None,
            nested_relations: Vec::new(),
            many_to_many_routes: Vec::new(),
        }
    }

    fn scoped(db: DbBackend) -> RuntimeResource {
        let mut resource = resource(vec![
            field("owner_id", FieldKind::Integer),
            field("tenant_id", FieldKind::Integer),
        ]);
        resource.db = db;
        let policy = PolicyFilterExpression::All(vec![
            PolicyFilterExpression::Match(PolicyFilter {
                field: "owner_id".into(),
                operator: PolicyFilterOperator::Equals(PolicyComparisonValue::Source(
                    PolicyValueSource::UserId,
                )),
            }),
            PolicyFilterExpression::Match(PolicyFilter {
                field: "tenant_id".into(),
                operator: PolicyFilterOperator::Equals(PolicyComparisonValue::Source(
                    PolicyValueSource::Claim("tenant".into()),
                )),
            }),
        ]);
        resource.policies.update = Some(policy.clone());
        resource.policies.delete = Some(policy);
        resource
    }

    #[test]
    fn mutation_binds_assignments_id_and_policy_values_in_order_for_each_dialect() {
        let claims = BTreeMap::from([("tenant".into(), json!(9))]);
        let principal = PolicyPrincipal {
            user_id: 7,
            claims: &claims,
        };
        let assignments = vec![
            WriteAssignment {
                field_name: "title_text".into(),
                value: RuntimeBoundValue::Text("'); DROP TABLE document; --".into()),
            },
            WriteAssignment {
                field_name: "optional_note".into(),
                value: RuntimeBoundValue::Null,
            },
        ];
        for db in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::Mysql] {
            let resource = scoped(db);
            let update =
                build_update_plan(&resource, &[], &assignments, 42, &principal, false).unwrap();
            let direct = update.direct.unwrap();
            assert_eq!(
                direct.binds,
                vec![
                    assignments[0].value.clone(),
                    RuntimeBoundValue::Null,
                    RuntimeBoundValue::Integer(42),
                    RuntimeBoundValue::Integer(7),
                    RuntimeBoundValue::Integer(9)
                ]
            );
            assert!(direct.sql.starts_with(&format!(
                "UPDATE document SET title_text = {}, optional_note = {} WHERE id = {} AND ",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3)
            )));
            assert!(
                direct
                    .sql
                    .contains(&format!("owner_id = {}", db.placeholder(4)))
            );
            assert!(
                direct
                    .sql
                    .contains(&format!("tenant_id = {}", db.placeholder(5)))
            );
            assert!(!direct.sql.contains("DROP TABLE"));
            assert_eq!(update.hybrid.unwrap().binds.len(), 3);
            let delete = build_delete_plan(&resource, &[], 42, &principal, false).unwrap();
            let direct = delete.direct.unwrap();
            assert!(direct.sql.starts_with(&format!(
                "DELETE FROM document WHERE id = {} AND ",
                db.placeholder(1)
            )));
            assert!(
                direct
                    .sql
                    .contains(&format!("tenant_id = {}", db.placeholder(3)))
            );
            assert_eq!(
                direct.binds,
                vec![
                    RuntimeBoundValue::Integer(42),
                    RuntimeBoundValue::Integer(7),
                    RuntimeBoundValue::Integer(9)
                ]
            );
        }
    }

    #[test]
    fn missing_or_wrong_type_claim_skips_direct_and_keeps_guarded_hybrid_dispatch() {
        let resource = scoped(DbBackend::Postgres);
        for claims in [
            BTreeMap::new(),
            BTreeMap::from([("tenant".into(), json!("9"))]),
        ] {
            let principal = PolicyPrincipal {
                user_id: 7,
                claims: &claims,
            };
            let plan = build_delete_plan(&resource, &[], 42, &principal, false).unwrap();
            assert!(plan.direct.is_none());
            assert_eq!(
                plan.hybrid.unwrap().sql,
                "DELETE FROM document WHERE id = $1"
            );
        }
    }

    #[test]
    fn admin_bypass_requires_both_configuration_and_admin_role() {
        let claims = BTreeMap::new();
        let principal = PolicyPrincipal {
            user_id: 7,
            claims: &claims,
        };
        for enabled in [false, true] {
            for admin in [false, true] {
                let mut resource = scoped(DbBackend::Sqlite);
                resource.policies.admin_bypass = enabled;
                let plan = build_delete_plan(&resource, &[], 42, &principal, admin).unwrap();
                assert_eq!(plan.direct.is_some(), enabled && admin);
                assert_eq!(plan.hybrid.is_none(), enabled && admin);
            }
        }
    }

    #[test]
    fn updates_generate_temporal_expressions_without_shifting_policy_binds() {
        let claims = BTreeMap::from([("tenant".into(), json!(9))]);
        let principal = PolicyPrincipal {
            user_id: 7,
            claims: &claims,
        };
        for db in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::Mysql] {
            for (kind, temporal_kind) in [
                (FieldKind::Text, GeneratedTemporalKind::DateTime),
                (FieldKind::DateTime, GeneratedTemporalKind::DateTime),
                (FieldKind::Date, GeneratedTemporalKind::Date),
                (FieldKind::Time, GeneratedTemporalKind::Time),
            ] {
                let mut resource = scoped(db);
                let mut generated = field("changed_at", kind);
                generated.generated = GeneratedValue::UpdatedAt;
                resource.fields.push(generated);
                let assignments = [WriteAssignment {
                    field_name: "title".into(),
                    value: RuntimeBoundValue::Text("new".into()),
                }];
                let plan =
                    build_update_plan(&resource, &[], &assignments, 42, &principal, false).unwrap();
                let direct = plan.direct.unwrap();
                assert!(direct.sql.contains(&format!(
                    "changed_at = {}",
                    db.generated_temporal_expression(Some(temporal_kind))
                )));
                assert_eq!(direct.binds.len(), 4);
                if db == DbBackend::Postgres {
                    assert!(direct.sql.contains("WHERE id = $2"));
                    assert!(direct.sql.contains("tenant_id = $4"));
                }
            }
        }
        assert!(matches!(
            build_update_plan(&scoped(DbBackend::Sqlite), &[], &[], 42, &principal, false),
            Err(MutationPlanError::NoUpdatableFields)
        ));
    }

    struct Dispatch {
        results: Mutex<VecDeque<Result<u64, String>>>,
        grant: Result<bool, String>,
        events: Mutex<Vec<String>>,
    }
    impl MutationExecutor for Dispatch {
        async fn execute(
            &self,
            action: MutationAction,
            statement: &MutationStatement,
        ) -> Result<u64, String> {
            self.events
                .lock()
                .unwrap()
                .push(format!("execute:{action:?}:{}", statement.binds.len()));
            self.results
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra write")
        }
    }
    impl HybridMutationAuthorizer for Dispatch {
        async fn allows(&self, action: MutationAction, id: i64) -> Result<bool, String> {
            self.events
                .lock()
                .unwrap()
                .push(format!("grant:{action:?}:{id}"));
            self.grant.clone()
        }
    }
    fn dispatch(results: Vec<Result<u64, String>>, grant: Result<bool, String>) -> Dispatch {
        Dispatch {
            results: Mutex::new(results.into()),
            grant,
            events: Mutex::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn direct_success_skips_grants_and_denied_grants_never_retry() {
        let claims = BTreeMap::from([("tenant".into(), json!(9))]);
        let principal = PolicyPrincipal {
            user_id: 7,
            claims: &claims,
        };
        let plan =
            build_delete_plan(&scoped(DbBackend::Postgres), &[], 42, &principal, false).unwrap();
        let direct = dispatch(vec![Ok(1)], Err("grant must not run".into()));
        assert_eq!(
            execute_mutation(&plan, &direct, &direct).await.unwrap(),
            MutationOutcome::Applied
        );
        assert_eq!(*direct.events.lock().unwrap(), ["execute:Delete:3"]);
        let denied = dispatch(vec![Ok(0)], Ok(false));
        assert_eq!(
            execute_mutation(&plan, &denied, &denied).await.unwrap(),
            MutationOutcome::NotFound
        );
        assert_eq!(
            *denied.events.lock().unwrap(),
            ["execute:Delete:3", "grant:Delete:42"]
        );
    }

    #[tokio::test]
    async fn granted_retry_uses_unfiltered_values_after_miss_and_preserves_not_found() {
        let claims = BTreeMap::from([("tenant".into(), json!(9))]);
        let principal = PolicyPrincipal {
            user_id: 7,
            claims: &claims,
        };
        let assignments = [WriteAssignment {
            field_name: "title".into(),
            value: RuntimeBoundValue::Text("new".into()),
        }];
        let plan = build_update_plan(
            &scoped(DbBackend::Postgres),
            &[],
            &assignments,
            42,
            &principal,
            false,
        )
        .unwrap();
        for (rows, outcome) in [
            (1, MutationOutcome::Applied),
            (0, MutationOutcome::NotFound),
        ] {
            let executor = dispatch(vec![Ok(0), Ok(rows)], Ok(true));
            assert_eq!(
                execute_mutation(&plan, &executor, &executor).await.unwrap(),
                outcome
            );
            assert_eq!(
                *executor.events.lock().unwrap(),
                ["execute:Update:4", "grant:Update:42", "execute:Update:2"]
            );
        }
    }

    #[tokio::test]
    async fn indeterminate_policies_require_a_grant_and_errors_stop_dispatch() {
        let claims = BTreeMap::new();
        let principal = PolicyPrincipal {
            user_id: 7,
            claims: &claims,
        };
        let plan =
            build_delete_plan(&scoped(DbBackend::Sqlite), &[], 42, &principal, false).unwrap();
        let granted = dispatch(vec![Ok(1)], Ok(true));
        assert_eq!(
            execute_mutation(&plan, &granted, &granted).await.unwrap(),
            MutationOutcome::Applied
        );
        assert_eq!(
            *granted.events.lock().unwrap(),
            ["grant:Delete:42", "execute:Delete:1"]
        );
        let failed = dispatch(vec![], Err("grants unavailable".into()));
        assert_eq!(
            execute_mutation(&plan, &failed, &failed).await.unwrap_err(),
            "grants unavailable"
        );
        let failed = dispatch(vec![Err("audit insert failed".into())], Ok(true));
        assert_eq!(
            execute_mutation(&plan, &failed, &failed).await.unwrap_err(),
            "audit insert failed"
        );
        let claims = BTreeMap::from([("tenant".into(), json!(9))]);
        let principal = PolicyPrincipal {
            user_id: 7,
            claims: &claims,
        };
        let plan =
            build_delete_plan(&scoped(DbBackend::Sqlite), &[], 42, &principal, false).unwrap();
        let failed = dispatch(vec![Err("transaction failed".into())], Ok(true));
        assert_eq!(
            execute_mutation(&plan, &failed, &failed).await.unwrap_err(),
            "transaction failed"
        );
        assert_eq!(*failed.events.lock().unwrap(), ["execute:Delete:3"]);
    }

    #[tokio::test]
    async fn resources_without_policy_do_not_consult_hybrid_grants_on_a_miss() {
        let resource = resource(vec![]);
        let claims = BTreeMap::new();
        let plan = build_delete_plan(
            &resource,
            &[],
            42,
            &PolicyPrincipal {
                user_id: 7,
                claims: &claims,
            },
            false,
        )
        .unwrap();
        let executor = dispatch(vec![Ok(0)], Err("unexpected grants".into()));
        assert_eq!(
            execute_mutation(&plan, &executor, &executor).await.unwrap(),
            MutationOutcome::NotFound
        );
        assert_eq!(*executor.events.lock().unwrap(), ["execute:Delete:1"]);
    }

    #[test]
    fn audit_plans_preserve_actor_snapshots_and_bound_values_for_all_dialects() {
        use crate::native_audit::{AuditActor, build_audit_plan};
        let roles = ["member".to_owned(), "admin".to_owned()];
        let before = json!({"publicTitle":"old"});
        let after = json!({"publicTitle":"new"});
        for db in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::Mysql] {
            let mut resource = scoped(db);
            resource.audit = Some(RuntimeAuditConfig {
                sink_table_name: "events".into(),
                create: true,
                update: true,
                delete: true,
                actions: None,
            });
            for (before, after, expected) in [
                (
                    Some(&before),
                    Some(&after),
                    json!({"before":before,"after":after}),
                ),
                (Some(&before), None, json!({"before":before})),
                (None, Some(&after), json!({"after":after})),
                (None, None, json!({})),
            ] {
                for user_id in [0, 7] {
                    let plan = build_audit_plan(
                        &resource,
                        &AuditActor {
                            user_id,
                            roles: &roles,
                        },
                        "action:archive",
                        42,
                        before,
                        after,
                    )
                    .unwrap()
                    .unwrap();
                    assert_eq!(
                        plan.binds[0],
                        RuntimeBoundValue::Text("action:archive".into())
                    );
                    assert_eq!(plan.binds[2], RuntimeBoundValue::Integer(42));
                    assert_eq!(
                        plan.binds[3],
                        if user_id == 0 {
                            RuntimeBoundValue::Null
                        } else {
                            RuntimeBoundValue::Integer(user_id)
                        }
                    );
                    assert_eq!(
                        plan.binds[4],
                        RuntimeBoundValue::Text(serde_json::to_string(&roles).unwrap())
                    );
                    let RuntimeBoundValue::Text(payload) = &plan.binds[5] else {
                        panic!("payload must be text")
                    };
                    assert_eq!(
                        serde_json::from_str::<serde_json::Value>(payload).unwrap(),
                        expected
                    );
                    assert!(!plan.sql.contains("archive"));
                    assert!(plan.sql.ends_with(&format!(
                            "VALUES ({})",
                            (1..=6)
                                .map(|index| db.placeholder(index))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )));
                }
            }
        }
        let resource = resource(vec![]);
        assert!(
            build_audit_plan(
                &resource,
                &AuditActor {
                    user_id: 7,
                    roles: &roles
                },
                "update",
                42,
                None,
                None
            )
            .unwrap()
            .is_none()
        );
    }

    #[derive(Clone)]
    struct AuditDriver {
        events: Arc<Mutex<Vec<String>>>,
        snapshots: Arc<Mutex<VecDeque<Result<Option<serde_json::Value>, String>>>>,
        audit_plans: Arc<Mutex<Vec<MutationStatement>>>,
        insert_result: Result<Option<i64>, String>,
        write_result: Result<u64, String>,
        audit_result: Result<u64, String>,
        begin_result: Result<(), String>,
        commit_result: Result<(), String>,
        rollback_result: Result<(), String>,
    }
    impl AuditDriver {
        fn new(snapshots: Vec<Result<Option<serde_json::Value>, String>>) -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                snapshots: Arc::new(Mutex::new(snapshots.into())),
                audit_plans: Arc::new(Mutex::new(Vec::new())),
                insert_result: Ok(Some(17)),
                write_result: Ok(1),
                audit_result: Ok(1),
                begin_result: Ok(()),
                commit_result: Ok(()),
                rollback_result: Ok(()),
            }
        }
    }
    impl crate::native_audit::AuditDatabase for AuditDriver {
        type Transaction = Self;
        async fn begin(&self) -> Result<Self, String> {
            self.events.lock().unwrap().push("begin".into());
            self.begin_result.clone()?;
            Ok(self.clone())
        }
    }
    impl crate::native_insert::InsertExecutor for AuditDriver {
        async fn insert(
            &self,
            _: &crate::native_insert::InsertPlan,
        ) -> Result<Option<i64>, String> {
            self.events.lock().unwrap().push("insert".into());
            self.insert_result.clone()
        }
    }
    impl crate::native_audit::AuditTransaction for AuditDriver {
        async fn snapshot(
            &self,
            _: &RuntimeResource,
            id: i64,
        ) -> Result<Option<serde_json::Value>, String> {
            self.events.lock().unwrap().push(format!("snapshot:{id}"));
            self.snapshots
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra snapshot")
        }
        async fn execute(&self, statement: &MutationStatement) -> Result<u64, String> {
            if statement.sql.starts_with("INSERT INTO events ") {
                self.events.lock().unwrap().push("audit".into());
                self.audit_plans.lock().unwrap().push(statement.clone());
                self.audit_result.clone()
            } else {
                self.events.lock().unwrap().push("write".into());
                self.write_result.clone()
            }
        }
        async fn commit(self) -> Result<(), String> {
            self.events.lock().unwrap().push("commit".into());
            self.commit_result.clone()
        }
        async fn rollback(self) -> Result<(), String> {
            self.events.lock().unwrap().push("rollback".into());
            self.rollback_result.clone()
        }
    }
    fn audited_resource() -> RuntimeResource {
        let mut resource = resource(vec![]);
        resource.audit = Some(RuntimeAuditConfig {
            sink_table_name: "events".into(),
            create: true,
            update: true,
            delete: true,
            actions: None,
        });
        resource
    }

    #[tokio::test]
    async fn audited_insert_requires_id_and_snapshot_and_commits_the_event_last() {
        use crate::native_audit::{AuditActor, execute_audited_insert};
        let resource = audited_resource();
        let prepared = crate::native_write::PreparedCreate {
            assignments: vec![],
        };
        let actor = AuditActor {
            user_id: 7,
            roles: &[],
        };
        let driver = AuditDriver::new(vec![Ok(Some(json!({"id":17,"title":"new"})))]);
        assert_eq!(
            execute_audited_insert(&resource, &prepared, &actor, "create", &driver)
                .await
                .unwrap(),
            17
        );
        assert_eq!(
            *driver.events.lock().unwrap(),
            ["begin", "insert", "snapshot:17", "audit", "commit"]
        );
        let plans = driver.audit_plans.lock().unwrap();
        let RuntimeBoundValue::Text(payload) = &plans[0].binds[5] else {
            panic!("payload must be text")
        };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(payload).unwrap(),
            json!({"after":{"id":17,"title":"new"}})
        );
        drop(plans);
        let mut driver = AuditDriver::new(vec![]);
        driver.insert_result = Ok(None);
        assert_eq!(
            execute_audited_insert(&resource, &prepared, &actor, "create", &driver)
                .await
                .unwrap_err(),
            "created row id was not returned"
        );
        assert_eq!(
            *driver.events.lock().unwrap(),
            ["begin", "insert", "rollback"]
        );
        let driver = AuditDriver::new(vec![Ok(None)]);
        assert_eq!(
            execute_audited_insert(&resource, &prepared, &actor, "create", &driver)
                .await
                .unwrap_err(),
            "created row could not be reloaded for audit"
        );
        assert_eq!(
            *driver.events.lock().unwrap(),
            ["begin", "insert", "snapshot:17", "rollback"]
        );
        let mut driver = AuditDriver::new(vec![Ok(Some(json!({"id":17})))]);
        driver.audit_result = Err("audit unavailable".into());
        driver.rollback_result = Err("rollback also failed".into());
        assert_eq!(
            execute_audited_insert(&resource, &prepared, &actor, "create", &driver)
                .await
                .unwrap_err(),
            "audit unavailable"
        );
        assert_eq!(
            *driver.events.lock().unwrap(),
            ["begin", "insert", "snapshot:17", "audit", "rollback"]
        );
    }

    #[tokio::test]
    async fn audited_mutations_capture_only_required_snapshots_and_roll_back_misses() {
        use crate::native_audit::{AuditActor, AuditedMutation, execute_audited_mutation};
        let resource = audited_resource();
        let statement = MutationStatement {
            sql: "resource write".into(),
            binds: vec![],
        };
        for action in [MutationAction::Update, MutationAction::Delete] {
            let request = AuditedMutation {
                resource: &resource,
                actor: AuditActor {
                    user_id: 7,
                    roles: &[],
                },
                event_kind: "action:change",
                record_id: 42,
                action,
                statement: &statement,
            };
            let before = json!({"title":"old"});
            let after = json!({"title":"new"});
            let snapshots = if action == MutationAction::Update {
                vec![Ok(Some(before.clone())), Ok(Some(after.clone()))]
            } else {
                vec![Ok(Some(before.clone()))]
            };
            let driver = AuditDriver::new(snapshots);
            assert_eq!(
                execute_audited_mutation(&request, &driver).await.unwrap(),
                1
            );
            let expected = if action == MutationAction::Update {
                vec![
                    "begin",
                    "snapshot:42",
                    "write",
                    "snapshot:42",
                    "audit",
                    "commit",
                ]
            } else {
                vec!["begin", "snapshot:42", "write", "audit", "commit"]
            };
            assert_eq!(*driver.events.lock().unwrap(), expected);
            let plans = driver.audit_plans.lock().unwrap();
            assert_eq!(
                plans[0].binds[0],
                RuntimeBoundValue::Text("action:change".into())
            );
            let RuntimeBoundValue::Text(payload) = &plans[0].binds[5] else {
                panic!("payload must be text")
            };
            let expected = if action == MutationAction::Update {
                json!({"before":before,"after":after})
            } else {
                json!({"before":before})
            };
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(payload).unwrap(),
                expected
            );
            drop(plans);
            let mut driver = AuditDriver::new(vec![Ok(None)]);
            driver.write_result = Ok(0);
            assert_eq!(
                execute_audited_mutation(&request, &driver).await.unwrap(),
                0
            );
            assert_eq!(
                *driver.events.lock().unwrap(),
                ["begin", "snapshot:42", "write", "rollback"]
            );
        }
    }

    #[tokio::test]
    async fn audited_mutation_failures_roll_back_and_preserve_the_original_error() {
        use crate::native_audit::{AuditActor, AuditedMutation, execute_audited_mutation};
        let resource = audited_resource();
        let statement = MutationStatement {
            sql: "resource write".into(),
            binds: vec![],
        };
        let mut request = AuditedMutation {
            resource: &resource,
            actor: AuditActor {
                user_id: 7,
                roles: &[],
            },
            event_kind: "update",
            record_id: 42,
            action: MutationAction::Update,
            statement: &statement,
        };
        let driver = AuditDriver::new(vec![Err("snapshot failed".into())]);
        assert_eq!(
            execute_audited_mutation(&request, &driver)
                .await
                .unwrap_err(),
            "snapshot failed"
        );
        assert_eq!(
            *driver.events.lock().unwrap(),
            ["begin", "snapshot:42", "rollback"]
        );
        let mut driver = AuditDriver::new(vec![Ok(Some(json!({})))]);
        driver.write_result = Err("write failed".into());
        assert_eq!(
            execute_audited_mutation(&request, &driver)
                .await
                .unwrap_err(),
            "write failed"
        );
        assert_eq!(
            *driver.events.lock().unwrap(),
            ["begin", "snapshot:42", "write", "rollback"]
        );
        let driver = AuditDriver::new(vec![Ok(Some(json!({}))), Ok(None)]);
        assert_eq!(
            execute_audited_mutation(&request, &driver)
                .await
                .unwrap_err(),
            "updated row could not be reloaded for audit"
        );
        assert_eq!(
            *driver.events.lock().unwrap(),
            ["begin", "snapshot:42", "write", "snapshot:42", "rollback"]
        );
        let mut driver = AuditDriver::new(vec![Ok(Some(json!({}))), Ok(Some(json!({})))]);
        driver.audit_result = Err("audit failed".into());
        assert_eq!(
            execute_audited_mutation(&request, &driver)
                .await
                .unwrap_err(),
            "audit failed"
        );
        assert_eq!(
            *driver.events.lock().unwrap(),
            [
                "begin",
                "snapshot:42",
                "write",
                "snapshot:42",
                "audit",
                "rollback"
            ]
        );
        request.action = MutationAction::Delete;
        let driver = AuditDriver::new(vec![Ok(None)]);
        assert_eq!(
            execute_audited_mutation(&request, &driver)
                .await
                .unwrap_err(),
            "deleted row could not be reloaded for audit"
        );
        assert_eq!(
            *driver.events.lock().unwrap(),
            ["begin", "snapshot:42", "write", "rollback"]
        );
    }

    #[tokio::test]
    async fn audit_transaction_begin_commit_and_rollback_errors_stop_processing() {
        use crate::native_audit::{AuditActor, AuditedMutation, execute_audited_mutation};
        let resource = audited_resource();
        let statement = MutationStatement {
            sql: "resource write".into(),
            binds: vec![],
        };
        let request = AuditedMutation {
            resource: &resource,
            actor: AuditActor {
                user_id: 7,
                roles: &[],
            },
            event_kind: "delete",
            record_id: 42,
            action: MutationAction::Delete,
            statement: &statement,
        };
        let mut driver = AuditDriver::new(vec![]);
        driver.begin_result = Err("begin failed".into());
        assert_eq!(
            execute_audited_mutation(&request, &driver)
                .await
                .unwrap_err(),
            "begin failed"
        );
        assert_eq!(*driver.events.lock().unwrap(), ["begin"]);
        let mut driver = AuditDriver::new(vec![Ok(Some(json!({})))]);
        driver.commit_result = Err("commit failed".into());
        assert_eq!(
            execute_audited_mutation(&request, &driver)
                .await
                .unwrap_err(),
            "commit failed"
        );
        assert_eq!(
            *driver.events.lock().unwrap(),
            ["begin", "snapshot:42", "write", "audit", "commit"]
        );
        let mut driver = AuditDriver::new(vec![Ok(None)]);
        driver.write_result = Ok(0);
        driver.rollback_result = Err("rollback failed".into());
        assert_eq!(
            execute_audited_mutation(&request, &driver)
                .await
                .unwrap_err(),
            "rollback failed"
        );
        assert_eq!(
            *driver.events.lock().unwrap(),
            ["begin", "snapshot:42", "write", "rollback"]
        );
    }
}
