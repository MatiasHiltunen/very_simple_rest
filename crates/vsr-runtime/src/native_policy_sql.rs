//! SQL planning for native row policies, independent of the compiler and HTTP adapter.

use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use crate::{
    authz::policy::{
        PolicyComparisonValue, PolicyExistsCondition, PolicyExistsFilter, PolicyFilterExpression,
        PolicyFilterOperator, PolicyLiteralValue, PolicyValueSource,
    },
    field::{FieldKind, RuntimeField},
    native_resource::{RuntimeBoundValue, RuntimeResource},
};

/// Symbolic placeholder used while native SQL predicates are assembled.
pub const BIND_MARKER: &str = "__vsr_bind__";

/// SQL predicate and values to bind in marker order.
#[derive(Clone, Debug)]
pub struct SqlPlan {
    /// SQL condition with symbolic bind markers.
    pub condition: String,
    /// Values corresponding to the markers in the condition.
    pub binds: Vec<RuntimeBoundValue>,
}

/// Missing principal values make a policy indeterminate and deny access.
#[derive(Clone, Debug)]
pub enum PlanOutcome {
    /// A fully resolved SQL predicate.
    Resolved(SqlPlan),
    /// One or more required principal values were missing.
    Indeterminate,
}

/// Borrowed principal data needed by the native row-policy planner.
pub struct PolicyPrincipal<'a> {
    /// Numeric user ID from the request principal.
    pub user_id: i64,
    /// Typed claims carried by the request principal.
    pub claims: &'a BTreeMap<String, Value>,
}

fn field<'a>(resource: &'a RuntimeResource, name: &str) -> Result<&'a RuntimeField> {
    let index = resource
        .field_index
        .get(name)
        .ok_or_else(|| anyhow!("field `{name}` not found in `{}`", resource.table_name))?;
    Ok(&resource.fields[*index])
}

fn source_value(
    source: &PolicyValueSource,
    field: &RuntimeField,
    principal: &PolicyPrincipal<'_>,
) -> Result<Option<RuntimeBoundValue>> {
    match source {
        PolicyValueSource::UserId => Ok(Some(RuntimeBoundValue::Integer(principal.user_id))),
        PolicyValueSource::Claim(name) => {
            let claim = principal.claims.get(name);
            Ok(match field.kind {
                FieldKind::Integer => claim
                    .and_then(Value::as_i64)
                    .map(RuntimeBoundValue::Integer),
                FieldKind::Boolean => claim.and_then(Value::as_bool).map(RuntimeBoundValue::Bool),
                _ => claim
                    .and_then(Value::as_str)
                    .map(|value| RuntimeBoundValue::Text(value.to_owned())),
            })
        }
        PolicyValueSource::InputField(_) => {
            bail!("input fields are not supported in row policy sources")
        }
    }
}

fn comparison_value(
    source: &PolicyComparisonValue,
    field: &RuntimeField,
    principal: &PolicyPrincipal<'_>,
) -> Result<Option<RuntimeBoundValue>> {
    match source {
        PolicyComparisonValue::Source(source) => source_value(source, field, principal),
        PolicyComparisonValue::Literal(value) => Ok(Some(match value {
            PolicyLiteralValue::String(value) => RuntimeBoundValue::Text(value.clone()),
            PolicyLiteralValue::I64(value) => RuntimeBoundValue::Integer(*value),
            PolicyLiteralValue::Bool(value) => RuntimeBoundValue::Bool(*value),
        })),
    }
}

/// Compile a row policy for reads, updates, and deletes. The caller renders bind
/// markers for its SQL dialect and treats `Indeterminate` as denied.
pub fn build_row_policy_plan(
    current: &RuntimeResource,
    resources: &[Arc<RuntimeResource>],
    expression: &PolicyFilterExpression,
    principal: &PolicyPrincipal<'_>,
) -> Result<PlanOutcome> {
    match expression {
        PolicyFilterExpression::Match(filter) => {
            let field = field(current, filter.field.as_str())?;
            match &filter.operator {
                PolicyFilterOperator::Equals(source) => {
                    let Some(value) = comparison_value(source, field, principal)? else {
                        return Ok(PlanOutcome::Indeterminate);
                    };
                    Ok(PlanOutcome::Resolved(SqlPlan {
                        condition: format!("{} = {BIND_MARKER}", field.name),
                        binds: vec![value],
                    }))
                }
                PolicyFilterOperator::IsNull => Ok(PlanOutcome::Resolved(SqlPlan {
                    condition: format!("{} IS NULL", field.name),
                    binds: Vec::new(),
                })),
                PolicyFilterOperator::IsNotNull => Ok(PlanOutcome::Resolved(SqlPlan {
                    condition: format!("{} IS NOT NULL", field.name),
                    binds: Vec::new(),
                })),
            }
        }
        PolicyFilterExpression::All(expressions) => {
            let plans = expressions
                .iter()
                .map(|expression| build_row_policy_plan(current, resources, expression, principal))
                .collect::<Result<Vec<_>>>()?;
            Ok(combine_all_plans(plans))
        }
        PolicyFilterExpression::Any(expressions) => {
            let plans = expressions
                .iter()
                .map(|expression| build_row_policy_plan(current, resources, expression, principal))
                .collect::<Result<Vec<_>>>()?;
            Ok(combine_any_plans(plans))
        }
        PolicyFilterExpression::Not(expression) => Ok(negate_plan(build_row_policy_plan(
            current, resources, expression, principal,
        )?)),
        PolicyFilterExpression::Exists(filter) => {
            build_row_exists_plan(current, resources, filter, principal)
        }
    }
}

fn build_row_exists_plan(
    current: &RuntimeResource,
    resources: &[Arc<RuntimeResource>],
    filter: &PolicyExistsFilter,
    principal: &PolicyPrincipal<'_>,
) -> Result<PlanOutcome> {
    let target = resources
        .iter()
        .find(|resource| {
            resource.resource_name == filter.resource || resource.table_name == filter.resource
        })
        .ok_or_else(|| anyhow!("resource `{}` not found", filter.resource))?;
    let alias = format!("{}_exists", target.table_name);
    let plan = build_row_exists_condition_plan(current, target, &filter.condition, principal, &alias)?;
    match plan {
        PlanOutcome::Resolved(plan) => Ok(PlanOutcome::Resolved(SqlPlan {
            condition: format!(
                "EXISTS (SELECT 1 FROM {} AS {} WHERE {})",
                target.table_name, alias, plan.condition
            ),
            binds: plan.binds,
        })),
        PlanOutcome::Indeterminate => Ok(PlanOutcome::Indeterminate),
    }
}

fn build_row_exists_condition_plan(
    current: &RuntimeResource,
    target: &RuntimeResource,
    condition: &PolicyExistsCondition,
    principal: &PolicyPrincipal<'_>,
    alias: &str,
) -> Result<PlanOutcome> {
    match condition {
        PolicyExistsCondition::Match(filter) => {
            let field = field(target, filter.field.as_str())?;
            match &filter.operator {
                PolicyFilterOperator::Equals(source) => {
                    let Some(value) = comparison_value(source, field, principal)? else {
                        return Ok(PlanOutcome::Indeterminate);
                    };
                    Ok(PlanOutcome::Resolved(SqlPlan {
                        condition: format!("{alias}.{} = {BIND_MARKER}", field.name),
                        binds: vec![value],
                    }))
                }
                PolicyFilterOperator::IsNull => Ok(PlanOutcome::Resolved(SqlPlan {
                    condition: format!("{alias}.{} IS NULL", field.name),
                    binds: Vec::new(),
                })),
                PolicyFilterOperator::IsNotNull => Ok(PlanOutcome::Resolved(SqlPlan {
                    condition: format!("{alias}.{} IS NOT NULL", field.name),
                    binds: Vec::new(),
                })),
            }
        }
        PolicyExistsCondition::CurrentRowField { field, row_field } => {
            Ok(PlanOutcome::Resolved(SqlPlan {
                condition: format!("{alias}.{field} = {}.{row_field}", current.table_name),
                binds: Vec::new(),
            }))
        }
        PolicyExistsCondition::All(conditions) => {
            let plans = conditions
                .iter()
                .map(|condition| {
                    build_row_exists_condition_plan(current, target, condition, principal, alias)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(combine_all_plans(plans))
        }
        PolicyExistsCondition::Any(conditions) => {
            let plans = conditions
                .iter()
                .map(|condition| {
                    build_row_exists_condition_plan(current, target, condition, principal, alias)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(combine_any_plans(plans))
        }
        PolicyExistsCondition::Not(condition) => Ok(negate_plan(build_row_exists_condition_plan(
            current, target, condition, principal, alias,
        )?)),
    }
}

/// Combine policy branches with AND, denying when any branch is indeterminate.
pub fn combine_all_plans(plans: Vec<PlanOutcome>) -> PlanOutcome {
    let mut conditions = Vec::new();
    let mut binds = Vec::new();
    for plan in plans {
        match plan {
            PlanOutcome::Resolved(plan) => {
                conditions.push(plan.condition);
                binds.extend(plan.binds);
            }
            PlanOutcome::Indeterminate => return PlanOutcome::Indeterminate,
        }
    }
    PlanOutcome::Resolved(SqlPlan {
        condition: format!("({})", conditions.join(" AND ")),
        binds,
    })
}

/// Combine resolved policy branches with OR, denying when none resolve.
pub fn combine_any_plans(plans: Vec<PlanOutcome>) -> PlanOutcome {
    let mut conditions = Vec::new();
    let mut binds = Vec::new();
    for plan in plans {
        if let PlanOutcome::Resolved(plan) = plan {
            conditions.push(plan.condition);
            binds.extend(plan.binds);
        }
    }
    if conditions.is_empty() {
        PlanOutcome::Indeterminate
    } else {
        PlanOutcome::Resolved(SqlPlan {
            condition: format!("({})", conditions.join(" OR ")),
            binds,
        })
    }
}

/// Negate a resolved policy branch while preserving indeterminacy.
pub fn negate_plan(plan: PlanOutcome) -> PlanOutcome {
    match plan {
        PlanOutcome::Resolved(plan) => PlanOutcome::Resolved(SqlPlan {
            condition: format!("NOT ({})", plan.condition),
            binds: plan.binds,
        }),
        PlanOutcome::Indeterminate => PlanOutcome::Indeterminate,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap},
        sync::Arc,
    };

    use serde_json::json;

    use super::*;
    use crate::{
        authz::{
            RoleRequirements,
            policy::{PolicyFilter, RowPolicies},
        },
        field::{FieldValidation, GeneratedValue},
        model::DbBackend,
    };

    fn resource(name: &str, fields: &[(&str, FieldKind)]) -> Arc<RuntimeResource> {
        let fields = fields
            .iter()
            .map(|(field_name, kind)| RuntimeField {
                name: (*field_name).to_owned(),
                api_name: (*field_name).to_owned(),
                expose_in_api: true,
                enum_values: None,
                transforms: Vec::new(),
                kind: *kind,
                list_item_kind: None,
                object_fields: None,
                optional: false,
                generated: GeneratedValue::None,
                validation: FieldValidation::default(),
                supports_exact_filters: true,
                supports_sort: false,
                supports_range_filters: false,
            })
            .collect::<Vec<_>>();
        let field_index = fields
            .iter()
            .enumerate()
            .map(|(index, field)| (field.name.clone(), index))
            .collect();
        Arc::new(RuntimeResource {
            resource_name: name.to_owned(),
            table_name: name.to_lowercase(),
            api_name: name.to_lowercase(),
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
            create_fields: Vec::new(),
            update_field_names: Vec::new(),
            actions: Vec::new(),
            audit: None,
            is_audit_sink: false,
            read_requires_auth: false,
            hybrid: None,
            nested_relations: Vec::new(),
            many_to_many_routes: Vec::new(),
        })
    }

    #[test]
    fn related_row_policy_keeps_correlation_and_bind_order() {
        let document = resource("Document", &[("owner_id", FieldKind::Integer)]);
        let membership = resource(
            "Membership",
            &[
                ("document_id", FieldKind::Integer),
                ("tenant_id", FieldKind::Integer),
            ],
        );
        let policy = PolicyFilterExpression::All(vec![
            PolicyFilterExpression::Match(PolicyFilter {
                field: "owner_id".into(),
                operator: PolicyFilterOperator::Equals(PolicyComparisonValue::Source(
                    PolicyValueSource::UserId,
                )),
            }),
            PolicyFilterExpression::Exists(PolicyExistsFilter {
                resource: "Membership".into(),
                condition: PolicyExistsCondition::All(vec![
                    PolicyExistsCondition::CurrentRowField {
                        field: "document_id".into(),
                        row_field: "id".into(),
                    },
                    PolicyExistsCondition::Match(PolicyFilter {
                        field: "tenant_id".into(),
                        operator: PolicyFilterOperator::Equals(PolicyComparisonValue::Source(
                            PolicyValueSource::Claim("tenant".into()),
                        )),
                    }),
                ]),
            }),
        ]);
        let claims = BTreeMap::from([("tenant".into(), json!(42))]);
        let plan = build_row_policy_plan(
            &document,
            &[document.clone(), membership],
            &policy,
            &PolicyPrincipal {
                user_id: 7,
                claims: &claims,
            },
        )
        .unwrap();
        let PlanOutcome::Resolved(plan) = plan else {
            panic!("policy should resolve")
        };
        assert_eq!(
            plan.condition,
            "(owner_id = __vsr_bind__ AND EXISTS (SELECT 1 FROM membership AS membership_exists WHERE (membership_exists.document_id = document.id AND membership_exists.tenant_id = __vsr_bind__)))"
        );
        assert_eq!(
            plan.binds,
            vec![
                RuntimeBoundValue::Integer(7),
                RuntimeBoundValue::Integer(42)
            ]
        );
    }

    #[test]
    fn missing_or_wrongly_typed_claim_denies_without_sql() {
        let document = resource("Document", &[("tenant_id", FieldKind::Integer)]);
        let policy = PolicyFilterExpression::Match(PolicyFilter {
            field: "tenant_id".into(),
            operator: PolicyFilterOperator::Equals(PolicyComparisonValue::Source(
                PolicyValueSource::Claim("tenant".into()),
            )),
        });
        for claims in [
            BTreeMap::new(),
            BTreeMap::from([("tenant".into(), json!("42"))]),
        ] {
            let plan = build_row_policy_plan(
                &document,
                &[document.clone()],
                &policy,
                &PolicyPrincipal {
                    user_id: 7,
                    claims: &claims,
                },
            )
            .unwrap();
            assert!(matches!(plan, PlanOutcome::Indeterminate));
        }
    }
}
