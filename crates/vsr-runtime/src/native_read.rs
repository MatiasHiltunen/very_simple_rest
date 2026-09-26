//! Native item and collection reads through compiler-free executor and grant seams.

use std::{collections::HashMap, future::Future, sync::Arc};

use serde_json::Value;

use crate::{
    native_list::{ListPlanError, ListScope, build_list_plan, finalize_list_response},
    native_policy_sql::{
        PlanOutcome, PolicyPrincipal, build_row_policy_plan, render_condition_with_placeholders,
    },
    native_resource::{RuntimeBoundValue, RuntimeResource},
    native_response::RuntimeListResponse,
};

/// Principal data used by native read authorization.
pub struct ReadPrincipal<'a> {
    /// Typed claim and user ID inputs for row policies.
    pub policy: PolicyPrincipal<'a>,
    /// Roles carried by the authenticated principal.
    pub roles: &'a [String],
}

impl ReadPrincipal<'_> {
    fn is_admin(&self) -> bool {
        self.roles.iter().any(|role| role == "admin")
    }

    fn can_read(&self, resource: &RuntimeResource) -> bool {
        resource.roles.read.as_ref().is_none_or(|required| {
            self.roles
                .iter()
                .any(|role| role == required || role == "admin")
        })
    }
}

/// Read SQL and values bound in placeholder order.
#[derive(Clone, Debug)]
pub struct ReadStatement {
    /// Statement to execute.
    pub sql: String,
    /// Ordered bound values.
    pub binds: Vec<RuntimeBoundValue>,
}

/// Database operations needed by native read orchestration.
pub trait ReadExecutor: Send + Sync {
    /// Fetch an optional item and decode its public API fields.
    fn fetch_optional(
        &self,
        resource: &RuntimeResource,
        statement: &ReadStatement,
    ) -> impl Future<Output = Result<Option<Value>, String>> + Send;

    /// Fetch a page and decode its public API fields.
    fn fetch_all(
        &self,
        resource: &RuntimeResource,
        statement: &ReadStatement,
    ) -> impl Future<Output = Result<Vec<Value>, String>> + Send;

    /// Fetch the count for a collection predicate.
    fn count(&self, statement: &ReadStatement) -> impl Future<Output = Result<i64, String>> + Send;
}

/// Scope derived from a row or an enabled request source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadScopeBinding {
    /// Declared authorization scope.
    pub scope: String,
    /// Scalar value identifying the scope instance.
    pub value: String,
}

/// Read grant request passed to the authorization adapter.
pub struct ReadGrantRequest<'a> {
    /// Authenticated user ID.
    pub user_id: i64,
    /// Resource declaration name.
    pub resource_name: &'a str,
    /// Resolved scope name and value.
    pub binding: &'a ReadScopeBinding,
}

/// Adapter to runtime scoped grants for the read action.
pub trait ReadGrantAuthorizer: Send + Sync {
    /// Decide whether the principal has a read grant for this scope.
    fn allows_read(
        &self,
        request: ReadGrantRequest<'_>,
    ) -> impl Future<Output = Result<bool, String>> + Send;
}

/// Build the unfiltered item statement, also used for transaction snapshots.
pub fn unfiltered_item_statement(resource: &RuntimeResource, id: i64) -> ReadStatement {
    ReadStatement {
        sql: format!(
            "SELECT * FROM {} WHERE {} = {}",
            resource.table_name,
            resource.id_field,
            resource.db.placeholder(1),
        ),
        binds: vec![RuntimeBoundValue::Integer(id)],
    }
}

/// Resolve a row scope using the lowered public field name.
///
/// Null and structured values cannot identify a scope. Mutation grant adapters
/// can reuse this resolver after checking their action's source settings.
pub fn row_scope_binding(resource: &RuntimeResource, item: &Value) -> Option<ReadScopeBinding> {
    let hybrid = resource.hybrid.as_ref()?;
    let field = resource
        .fields
        .get(*resource.field_index.get(&hybrid.scope_field)?)?;
    let value = match item.get(&field.api_name)? {
        Value::String(value) => value.clone(),
        value @ (Value::Bool(_) | Value::Number(_)) => value.to_string(),
        _ => return None,
    };
    Some(ReadScopeBinding {
        scope: hybrid.scope.clone(),
        value,
    })
}

/// Read an item through the static row policy, then an enabled item grant.
///
/// Required read roles apply to both paths, including created-response reads.
/// Missing claims deny the static attempt. Database and grant errors stop the
/// operation without trying another authorization path.
pub async fn read_item(
    resource: &RuntimeResource,
    resources: &[Arc<RuntimeResource>],
    principal: &ReadPrincipal<'_>,
    id: i64,
    executor: &impl ReadExecutor,
    authorizer: &impl ReadGrantAuthorizer,
) -> Result<Option<Value>, String> {
    if !principal.can_read(resource) {
        return Ok(None);
    }
    let mut statement = unfiltered_item_statement(resource, id);
    let mut direct = true;
    if let Some(expression) = resource.policies.read.as_ref()
        && !(resource.policies.admin_bypass && principal.is_admin())
    {
        match build_row_policy_plan(resource, resources, expression, &principal.policy)
            .map_err(|error| error.to_string())?
        {
            PlanOutcome::Resolved(plan) => {
                statement.sql.push_str(" AND ");
                statement.sql.push_str(&render_condition_with_placeholders(
                    &plan.condition,
                    resource.db,
                    2,
                ));
                statement.binds.extend(plan.binds);
            }
            PlanOutcome::Indeterminate => direct = false,
        }
    }
    if direct && let Some(item) = executor.fetch_optional(resource, &statement).await? {
        return Ok(Some(item));
    }
    if principal.policy.user_id == 0
        || !resource
            .hybrid
            .as_ref()
            .is_some_and(|hybrid| hybrid.item_read)
    {
        return Ok(None);
    }
    let Some(item) = executor
        .fetch_optional(resource, &unfiltered_item_statement(resource, id))
        .await?
    else {
        return Ok(None);
    };
    let Some(binding) = row_scope_binding(resource, &item) else {
        return Ok(None);
    };
    if authorizer
        .allows_read(ReadGrantRequest {
            user_id: principal.policy.user_id,
            resource_name: &resource.resource_name,
            binding: &binding,
        })
        .await?
    {
        Ok(Some(item))
    } else {
        Ok(None)
    }
}

/// Inputs shared by collection and count execution.
pub struct CollectionRead<'a> {
    /// Resource being read.
    pub resource: &'a RuntimeResource,
    /// All resources available to related-row policy planning.
    pub resources: &'a [Arc<RuntimeResource>],
    /// Decoded request query values.
    pub query: HashMap<String, String>,
    /// Principal and roles.
    pub principal: &'a ReadPrincipal<'a>,
    /// Nested route constraint, when present.
    pub scope: Option<&'a ListScope>,
    /// Maximum number of values accepted by an IN filter.
    pub max_filter_in_values: usize,
}

fn collection_scope_binding(
    resource: &RuntimeResource,
    query: &HashMap<String, String>,
    scope: Option<&ListScope>,
) -> Option<ReadScopeBinding> {
    let hybrid = resource.hybrid.as_ref()?;
    match scope {
        None if !hybrid.collection_read => return None,
        Some(_) if !hybrid.nested_read => return None,
        Some(ListScope::ParentField { field_name, value }) if *field_name == hybrid.scope_field => {
            return Some(ReadScopeBinding {
                scope: hybrid.scope.clone(),
                value: value.to_string(),
            });
        }
        _ => {}
    }
    let field = resource
        .fields
        .get(*resource.field_index.get(&hybrid.scope_field)?)?;
    query
        .get(&format!("filter_{}", field.api_name))
        .map(|value| ReadScopeBinding {
            scope: hybrid.scope.clone(),
            value: value.clone(),
        })
}

async fn collection_plan(
    request: CollectionRead<'_>,
    authorizer: &impl ReadGrantAuthorizer,
) -> Result<crate::native_list::ListQueryPlan, ListPlanError> {
    if !request.principal.can_read(request.resource) {
        return Err(ListPlanError::Forbidden {
            code: "forbidden",
            message: "Insufficient privileges".into(),
        });
    }
    let binding = (request.principal.policy.user_id != 0)
        .then(|| collection_scope_binding(request.resource, &request.query, request.scope))
        .flatten();
    let skip_static = if let Some(binding) = binding {
        authorizer
            .allows_read(ReadGrantRequest {
                user_id: request.principal.policy.user_id,
                resource_name: &request.resource.resource_name,
                binding: &binding,
            })
            .await
            .map_err(ListPlanError::Internal)?
    } else {
        false
    };
    build_list_plan(
        request.resource,
        request.resources,
        request.query,
        &request.principal.policy,
        request.principal.is_admin(),
        request.scope,
        skip_static,
        request.max_filter_in_values,
    )
}

/// Authorize, count, select, and finalize a collection page.
pub async fn read_collection(
    request: CollectionRead<'_>,
    executor: &impl ReadExecutor,
    authorizer: &impl ReadGrantAuthorizer,
) -> Result<RuntimeListResponse, ListPlanError> {
    let resource = request.resource;
    let plan = collection_plan(request, authorizer).await?;
    let total = executor
        .count(&ReadStatement {
            sql: plan.count_sql.clone(),
            binds: plan.filter_binds.clone(),
        })
        .await
        .map_err(ListPlanError::Internal)?;
    let items = executor
        .fetch_all(
            resource,
            &ReadStatement {
                sql: plan.select_sql.clone(),
                binds: plan.select_binds.clone(),
            },
        )
        .await
        .map_err(ListPlanError::Internal)?;
    finalize_list_response(resource, plan, total, items)
}

/// Authorize and count a collection without selecting a page.
pub async fn read_count(
    request: CollectionRead<'_>,
    executor: &impl ReadExecutor,
    authorizer: &impl ReadGrantAuthorizer,
) -> Result<i64, ListPlanError> {
    let plan = collection_plan(request, authorizer).await?;
    executor
        .count(&ReadStatement {
            sql: plan.count_sql,
            binds: plan.filter_binds,
        })
        .await
        .map_err(ListPlanError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authz::{
            RoleRequirements,
            policy::{
                PolicyComparisonValue, PolicyFilter, PolicyFilterExpression, PolicyFilterOperator,
                PolicyValueSource, RowPolicies,
            },
        },
        field::{FieldKind, FieldValidation, GeneratedValue, RuntimeField},
        model::DbBackend,
        native_resource::RuntimeHybridResourceConfig,
    };
    use serde_json::json;
    use std::{
        collections::{BTreeMap, BTreeSet, VecDeque},
        sync::Mutex,
    };

    fn resource() -> RuntimeResource {
        let fields = [("id", "id"), ("owner_id", "owner"), ("tenant_id", "tenant")]
            .map(|(name, api)| RuntimeField {
                name: name.into(),
                api_name: api.into(),
                expose_in_api: true,
                enum_values: None,
                transforms: Vec::new(),
                kind: FieldKind::Integer,
                list_item_kind: None,
                object_fields: None,
                optional: false,
                generated: GeneratedValue::None,
                validation: FieldValidation::default(),
                supports_exact_filters: true,
                supports_sort: true,
                supports_range_filters: true,
            })
            .to_vec();
        RuntimeResource {
            resource_name: "Document".into(),
            table_name: "document".into(),
            api_name: "documents".into(),
            default_response_context: None,
            id_field: "id".into(),
            id_api_name: "id".into(),
            db: DbBackend::Sqlite,
            roles: RoleRequirements {
                read: Some("member".into()),
                ..RoleRequirements::default()
            },
            policies: RowPolicies {
                read: Some(PolicyFilterExpression::Match(PolicyFilter {
                    field: "owner_id".into(),
                    operator: PolicyFilterOperator::Equals(PolicyComparisonValue::Source(
                        PolicyValueSource::UserId,
                    )),
                })),
                ..RowPolicies::default()
            },
            default_limit: Some(2),
            max_limit: Some(10),
            filterable_in: BTreeSet::new(),
            count_endpoint: true,
            create_assignment_sources: HashMap::new(),
            field_index: fields
                .iter()
                .enumerate()
                .map(|(i, f)| (f.name.clone(), i))
                .collect(),
            api_field_index: fields
                .iter()
                .enumerate()
                .map(|(i, f)| (f.api_name.clone(), i))
                .collect(),
            fields,
            response_contexts: HashMap::new(),
            computed_fields: Vec::new(),
            create_fields: Vec::new(),
            update_field_names: Vec::new(),
            actions: Vec::new(),
            audit: None,
            is_audit_sink: false,
            read_requires_auth: true,
            hybrid: Some(RuntimeHybridResourceConfig {
                scope: "Tenant".into(),
                scope_field: "tenant_id".into(),
                item_read: true,
                collection_read: true,
                nested_read: true,
                create_payload: false,
                update: true,
                delete: true,
            }),
            nested_relations: Vec::new(),
            many_to_many_routes: Vec::new(),
        }
    }

    #[derive(Default)]
    struct Database {
        items: Mutex<VecDeque<Result<Option<Value>, String>>>,
        calls: Mutex<Vec<(String, ReadStatement)>>,
        count_error: Option<String>,
        page_error: Option<String>,
    }
    impl Database {
        fn items(items: impl IntoIterator<Item = Result<Option<Value>, String>>) -> Self {
            Self {
                items: Mutex::new(items.into_iter().collect()),
                ..Self::default()
            }
        }
    }
    impl ReadExecutor for Database {
        async fn fetch_optional(
            &self,
            _: &RuntimeResource,
            statement: &ReadStatement,
        ) -> Result<Option<Value>, String> {
            self.calls
                .lock()
                .unwrap()
                .push(("item".into(), statement.clone()));
            self.items
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected item query")
        }
        async fn fetch_all(
            &self,
            _: &RuntimeResource,
            statement: &ReadStatement,
        ) -> Result<Vec<Value>, String> {
            self.calls
                .lock()
                .unwrap()
                .push(("page".into(), statement.clone()));
            if let Some(error) = &self.page_error {
                return Err(error.clone());
            }
            Ok(
                if statement.sql.contains("LIMIT")
                    && statement.binds.last() == Some(&RuntimeBoundValue::Integer(0))
                {
                    Vec::new()
                } else {
                    vec![json!({"id": 5, "owner": 9, "tenant": 42})]
                },
            )
        }
        async fn count(&self, statement: &ReadStatement) -> Result<i64, String> {
            self.calls
                .lock()
                .unwrap()
                .push(("count".into(), statement.clone()));
            if let Some(error) = &self.count_error {
                Err(error.clone())
            } else {
                Ok(3)
            }
        }
    }

    struct Grants {
        decision: Result<bool, String>,
        calls: Mutex<Vec<(i64, String, ReadScopeBinding)>>,
    }
    impl Grants {
        fn new(decision: Result<bool, String>) -> Self {
            Self {
                decision,
                calls: Mutex::new(Vec::new()),
            }
        }
    }
    impl ReadGrantAuthorizer for Grants {
        async fn allows_read(&self, request: ReadGrantRequest<'_>) -> Result<bool, String> {
            self.calls.lock().unwrap().push((
                request.user_id,
                request.resource_name.into(),
                request.binding.clone(),
            ));
            self.decision.clone()
        }
    }

    fn principal<'a>(
        claims: &'a BTreeMap<String, Value>,
        roles: &'a [String],
    ) -> ReadPrincipal<'a> {
        ReadPrincipal {
            policy: PolicyPrincipal { user_id: 7, claims },
            roles,
        }
    }
    fn collection<'a>(
        resource: &'a RuntimeResource,
        principal: &'a ReadPrincipal<'a>,
        query: HashMap<String, String>,
        scope: Option<&'a ListScope>,
    ) -> CollectionRead<'a> {
        CollectionRead {
            resource,
            resources: &[],
            principal,
            query,
            scope,
            max_filter_in_values: 10,
        }
    }

    #[tokio::test]
    async fn direct_item_uses_id_then_policy_binds_in_each_dialect_without_grant() {
        let claims = BTreeMap::new();
        let roles = vec!["member".into()];
        let principal = principal(&claims, &roles);
        for db in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::Mysql] {
            let mut resource = resource();
            resource.db = db;
            let item = json!({"id": 5});
            let database = Database::items([Ok(Some(item.clone()))]);
            let grants = Grants::new(Err("must not evaluate".into()));
            assert_eq!(
                read_item(&resource, &[], &principal, 5, &database, &grants)
                    .await
                    .unwrap(),
                Some(item)
            );
            let calls = database.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert!(calls[0].1.sql.starts_with(&format!(
                "SELECT * FROM document WHERE id = {} AND ",
                db.placeholder(1)
            )));
            assert!(
                calls[0]
                    .1
                    .sql
                    .contains(&format!("owner_id = {}", db.placeholder(2)))
            );
            assert_eq!(
                calls[0].1.binds,
                vec![RuntimeBoundValue::Integer(5), RuntimeBoundValue::Integer(7)]
            );
            assert!(grants.calls.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn item_fallback_uses_public_scope_field_and_denies_missing_or_disabled_sources() {
        let claims = BTreeMap::new();
        let roles = vec!["member".into()];
        let principal = principal(&claims, &roles);
        for allowed in [false, true] {
            let resource = resource();
            let item = json!({"id": 5, "tenant": 42});
            let database = Database::items([Ok(None), Ok(Some(item.clone()))]);
            let grants = Grants::new(Ok(allowed));
            let result = read_item(&resource, &[], &principal, 5, &database, &grants)
                .await
                .unwrap();
            assert_eq!(result, allowed.then_some(item));
            assert_eq!(
                grants.calls.lock().unwrap()[0],
                (
                    7,
                    "Document".into(),
                    ReadScopeBinding {
                        scope: "Tenant".into(),
                        value: "42".into()
                    }
                )
            );
        }
        for item in [
            None,
            Some(json!({"tenant": null})),
            Some(json!({"tenant": {"id": 42}})),
            Some(json!({"tenant_id": 42})),
        ] {
            let database = Database::items([Ok(None), Ok(item)]);
            let grants = Grants::new(Ok(true));
            assert!(
                read_item(&resource(), &[], &principal, 5, &database, &grants)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(grants.calls.lock().unwrap().is_empty());
        }
        let mut resource = resource();
        resource.hybrid.as_mut().unwrap().item_read = false;
        let database = Database::items([Ok(None)]);
        let grants = Grants::new(Ok(true));
        assert!(
            read_item(&resource, &[], &principal, 5, &database, &grants)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(database.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn missing_claim_skips_static_item_and_errors_stop_fallback() {
        let claims = BTreeMap::new();
        let roles = vec!["member".into()];
        let principal = principal(&claims, &roles);
        let mut resource = resource();
        resource.policies.read = Some(PolicyFilterExpression::Match(PolicyFilter {
            field: "tenant_id".into(),
            operator: PolicyFilterOperator::Equals(PolicyComparisonValue::Source(
                PolicyValueSource::Claim("tenant".into()),
            )),
        }));
        let database = Database::items([Ok(Some(json!({"tenant": 42})))]);
        let grants = Grants::new(Ok(true));
        assert!(
            read_item(&resource, &[], &principal, 5, &database, &grants)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(database.calls.lock().unwrap().len(), 1);
        resource.policies.read = Some(PolicyFilterExpression::Match(PolicyFilter {
            field: "owner_id".into(),
            operator: PolicyFilterOperator::Equals(PolicyComparisonValue::Source(
                PolicyValueSource::UserId,
            )),
        }));
        for items in [
            vec![Err("database".into())],
            vec![Ok(None), Err("database".into())],
        ] {
            let database = Database::items(items);
            let grants = Grants::new(Ok(true));
            assert_eq!(
                read_item(&resource, &[], &principal, 5, &database, &grants)
                    .await
                    .unwrap_err(),
                "database"
            );
            assert!(grants.calls.lock().unwrap().is_empty());
        }
        let database = Database::items([Ok(None), Ok(Some(json!({"tenant": 42})))]);
        let grants = Grants::new(Err("grant".into()));
        assert_eq!(
            read_item(&resource, &[], &principal, 5, &database, &grants)
                .await
                .unwrap_err(),
            "grant"
        );
    }

    #[tokio::test]
    async fn roles_gate_both_item_paths_and_collection_before_io() {
        let claims = BTreeMap::new();
        let roles = vec!["writer".into()];
        let principal = principal(&claims, &roles);
        let resource = resource();
        let database = Database::default();
        let grants = Grants::new(Ok(true));
        assert!(
            read_item(&resource, &[], &principal, 5, &database, &grants)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            read_collection(
                collection(&resource, &principal, HashMap::new(), None),
                &database,
                &grants
            )
            .await,
            Err(ListPlanError::Forbidden {
                code: "forbidden",
                ..
            })
        ));
        assert!(database.calls.lock().unwrap().is_empty());
        assert!(grants.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn admin_bypasses_rows_only_when_configured_and_anonymous_never_uses_grants() {
        let claims = BTreeMap::new();
        let roles = vec!["admin".into()];
        let mut principal = principal(&claims, &roles);
        for bypass in [false, true] {
            let mut resource = resource();
            resource.policies.admin_bypass = bypass;
            let database = Database::items([Ok(Some(json!({"id": 5})))]);
            let grants = Grants::new(Ok(true));
            read_item(&resource, &[], &principal, 5, &database, &grants)
                .await
                .unwrap();
            assert_eq!(
                database.calls.lock().unwrap()[0].1.binds.len(),
                if bypass { 1 } else { 2 }
            );
        }
        principal.policy.user_id = 0;
        let mut resource = resource();
        resource.roles.read = None;
        let database = Database::items([Ok(None)]);
        let grants = Grants::new(Ok(true));
        assert!(
            read_item(&resource, &[], &principal, 5, &database, &grants)
                .await
                .unwrap()
                .is_none()
        );
        read_count(
            collection(
                &resource,
                &principal,
                HashMap::from([("filter_tenant".into(), "42".into())]),
                None,
            ),
            &database,
            &grants,
        )
        .await
        .unwrap();
        assert!(grants.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn collection_and_count_share_source_gates_and_retain_route_constraints() {
        let claims = BTreeMap::new();
        let roles = vec!["member".into()];
        let principal = principal(&claims, &roles);
        let parent = ListScope::ParentField {
            field_name: "tenant_id".into(),
            value: 42,
        };
        for collection_enabled in [false, true] {
            for nested_enabled in [false, true] {
                for scope in [None, Some(&parent)] {
                    let mut resource = resource();
                    let hybrid = resource.hybrid.as_mut().unwrap();
                    hybrid.collection_read = collection_enabled;
                    hybrid.nested_read = nested_enabled;
                    let database = Database::default();
                    let grants = Grants::new(Ok(true));
                    let query = || HashMap::from([("filter_tenant".into(), "42".into())]);
                    read_collection(
                        collection(&resource, &principal, query(), scope),
                        &database,
                        &grants,
                    )
                    .await
                    .unwrap();
                    read_count(
                        collection(&resource, &principal, query(), scope),
                        &database,
                        &grants,
                    )
                    .await
                    .unwrap();
                    let enabled = if scope.is_some() {
                        nested_enabled
                    } else {
                        collection_enabled
                    };
                    assert_eq!(
                        grants.calls.lock().unwrap().len(),
                        if enabled { 2 } else { 0 }
                    );
                    let calls = database.calls.lock().unwrap();
                    assert_eq!(
                        calls
                            .iter()
                            .map(|(kind, _)| kind.as_str())
                            .collect::<Vec<_>>(),
                        ["count", "page", "count"]
                    );
                    assert_eq!(calls[0].1.binds, calls[2].1.binds);
                    assert_eq!(calls[0].1.sql.contains("owner_id"), !enabled);
                    assert!(calls[0].1.sql.contains("tenant_id"));
                    if scope.is_some() {
                        assert_eq!(
                            calls[0]
                                .1
                                .binds
                                .iter()
                                .filter(|v| **v == RuntimeBoundValue::Integer(42))
                                .count(),
                            2
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn unscoped_and_many_to_many_requests_cannot_invent_scope_from_parent_id() {
        let claims = BTreeMap::new();
        let roles = vec!["member".into()];
        let principal = principal(&claims, &roles);
        let resource = resource();
        let join = ListScope::ManyToMany {
            through_table: "membership".into(),
            source_field: "group_id".into(),
            target_field: "doc_id".into(),
            parent_id: 42,
        };
        for scope in [None, Some(&join)] {
            let database = Database::default();
            let grants = Grants::new(Ok(true));
            read_count(
                collection(&resource, &principal, HashMap::new(), scope),
                &database,
                &grants,
            )
            .await
            .unwrap();
            assert!(grants.calls.lock().unwrap().is_empty());
            assert!(database.calls.lock().unwrap()[0].1.sql.contains("owner_id"));
        }
        let database = Database::default();
        let grants = Grants::new(Ok(true));
        read_count(
            collection(
                &resource,
                &principal,
                HashMap::from([("filter_tenant".into(), "43".into())]),
                Some(&join),
            ),
            &database,
            &grants,
        )
        .await
        .unwrap();
        let calls = database.calls.lock().unwrap();
        assert!(calls[0].1.sql.contains("membership"));
        assert!(calls[0].1.binds.contains(&RuntimeBoundValue::Integer(42)));
        assert!(calls[0].1.binds.contains(&RuntimeBoundValue::Integer(43)));
        assert_eq!(grants.calls.lock().unwrap()[0].2.value, "43");
    }

    #[tokio::test]
    async fn count_excludes_pagination_binds_and_limit_zero_preserves_total() {
        let claims = BTreeMap::new();
        let roles = vec!["member".into()];
        let principal = principal(&claims, &roles);
        let resource = resource();
        let database = Database::default();
        let grants = Grants::new(Ok(false));
        let response = read_collection(
            collection(
                &resource,
                &principal,
                HashMap::from([("limit".into(), "0".into())]),
                None,
            ),
            &database,
            &grants,
        )
        .await
        .unwrap();
        assert_eq!(response.total, 3);
        assert_eq!(response.count, 0);
        assert!(response.items.is_empty());
        let calls = database.calls.lock().unwrap();
        assert!(!calls[0].1.sql.contains("LIMIT"));
        assert!(
            calls[1].1.sql.contains("LIMIT")
                && calls[1].1.binds.last() == Some(&RuntimeBoundValue::Integer(0))
        );
    }

    #[tokio::test]
    async fn collection_errors_stop_before_later_queries_and_invalid_filters_never_reach_database()
    {
        let claims = BTreeMap::new();
        let roles = vec!["member".into()];
        let principal = principal(&claims, &roles);
        let resource = resource();
        for (database, expected_calls) in [
            (
                Database {
                    count_error: Some("count".into()),
                    ..Database::default()
                },
                1,
            ),
            (
                Database {
                    page_error: Some("page".into()),
                    ..Database::default()
                },
                2,
            ),
        ] {
            let grants = Grants::new(Ok(false));
            assert!(matches!(
                read_collection(
                    collection(&resource, &principal, HashMap::new(), None),
                    &database,
                    &grants
                )
                .await,
                Err(ListPlanError::Internal(_))
            ));
            assert_eq!(database.calls.lock().unwrap().len(), expected_calls);
        }
        let database = Database::default();
        let grants = Grants::new(Err("grant".into()));
        assert!(matches!(
            read_count(
                collection(
                    &resource,
                    &principal,
                    HashMap::from([("filter_tenant".into(), "42".into())]),
                    None
                ),
                &database,
                &grants
            )
            .await,
            Err(ListPlanError::Internal(_))
        ));
        let grants = Grants::new(Ok(true));
        assert!(matches!(
            read_count(
                collection(
                    &resource,
                    &principal,
                    HashMap::from([("filter_tenant".into(), "42 OR 1=1".into())]),
                    None
                ),
                &database,
                &grants
            )
            .await,
            Err(ListPlanError::BadRequest { .. })
        ));
        assert!(database.calls.lock().unwrap().is_empty());
    }
}
