//! Row-policy parsing: converts `*PolicyDocument` types into the
//! canonical `RowPolicies` / `PolicyFilter` / `PolicyAssignment` model
//! types used by the code generator.
//!
//! Entry point: [`parse_row_policies`].

use proc_macro2::Span;

use super::super::model::{
    PolicyAssignment, PolicyComparisonValue, PolicyExistsCondition, PolicyExistsFilter,
    PolicyFilter, PolicyFilterExpression, PolicyFilterOperator, PolicyLiteralValue,
    PolicyValueSource, RowPolicies, RowPolicyKind,
};

use super::documents::{
    CreatePoliciesDocument, CreatePoliciesGroupDocument, ExistsPolicyDocument,
    ExistsPolicyEntriesDocument, ExistsPolicyEntryDocument, ExistsPolicyGroupDocument,
    FilterPoliciesDocument, FilterPolicyGroupDocument,
    PolicyComparisonValueDocument, PolicyEntryDocument,
    RowPoliciesDocument, ScopePoliciesDocument,
};

pub(super) fn parse_row_policies(policies: RowPoliciesDocument) -> syn::Result<RowPolicies> {
    let (create_require, create_assignments) = parse_create_policies(policies.create)?;
    Ok(RowPolicies {
        admin_bypass: policies.admin_bypass,
        read: parse_filter_policies("read", policies.read)?,
        create_require,
        create: create_assignments,
        update: parse_filter_policies("update", policies.update)?,
        delete: parse_filter_policies("delete", policies.delete)?,
    })
}

pub(super) fn default_admin_bypass() -> bool {
    true
}

pub(super) fn deserialize_create_policies_document<'de, D>(
    deserializer: D,
) -> Result<Option<CreatePoliciesDocument>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <Option<serde_json::Value> as serde::Deserialize>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        serde_json::Value::Object(map)
            if map.contains_key("assign") || map.contains_key("require") =>
        {
            serde_json::from_value::<CreatePoliciesGroupDocument>(serde_json::Value::Object(map))
                .map(CreatePoliciesDocument::Structured)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
        other => serde_json::from_value::<ScopePoliciesDocument>(other)
            .map(CreatePoliciesDocument::Assignments)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

fn parse_filter_policies(
    scope: &'static str,
    policies: Option<FilterPoliciesDocument>,
) -> syn::Result<Option<PolicyFilterExpression>> {
    policies
        .map(|policy| parse_filter_policy_expression(scope, policy))
        .transpose()
}

fn parse_assignment_policies(
    scope: &'static str,
    policies: Option<ScopePoliciesDocument>,
) -> syn::Result<Vec<PolicyAssignment>> {
    expand_policy_entries(policies)?
        .into_iter()
        .map(|policy| parse_assignment_policy(scope, policy))
        .collect()
}

fn parse_create_policies(
    policies: Option<CreatePoliciesDocument>,
) -> syn::Result<(Option<PolicyFilterExpression>, Vec<PolicyAssignment>)> {
    match policies {
        None => Ok((None, Vec::new())),
        Some(CreatePoliciesDocument::Assignments(assignments)) => Ok((
            None,
            parse_assignment_policies("create", Some(assignments))?,
        )),
        Some(CreatePoliciesDocument::Structured(group)) => {
            if group.assign.is_none() && group.require.is_none() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "create row policy groups must set at least one of `assign` or `require`",
                ));
            }
            Ok((
                parse_filter_policies("create.require", group.require)?,
                parse_assignment_policies("create", group.assign)?,
            ))
        }
    }
}

fn expand_policy_entries(
    policies: Option<ScopePoliciesDocument>,
) -> syn::Result<Vec<PolicyEntryDocument>> {
    let Some(policies) = policies else {
        return Ok(Vec::new());
    };

    let entries = match policies {
        ScopePoliciesDocument::Single(entry) => vec![entry],
        ScopePoliciesDocument::Many(entries) => entries,
    };

    if entries.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "row policy entries cannot be empty",
        ));
    }

    Ok(entries)
}

fn parse_filter_policy_expression(
    scope: &'static str,
    policy: FilterPoliciesDocument,
) -> syn::Result<PolicyFilterExpression> {
    match policy {
        FilterPoliciesDocument::Group(group) => parse_filter_policy_group(scope, group),
        FilterPoliciesDocument::Many(entries) => {
            if entries.is_empty() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "row policy entries cannot be empty",
                ));
            }
            let expressions = entries
                .into_iter()
                .map(|entry| parse_filter_policy_expression(scope, entry))
                .collect::<syn::Result<Vec<_>>>()?;
            PolicyFilterExpression::all(expressions).ok_or_else(|| {
                syn::Error::new(Span::call_site(), "row policy entries cannot be empty")
            })
        }
        FilterPoliciesDocument::Single(policy) => {
            parse_filter_policy(scope, policy).map(PolicyFilterExpression::Match)
        }
    }
}

fn parse_filter_policy_group(
    scope: &'static str,
    group: FilterPolicyGroupDocument,
) -> syn::Result<PolicyFilterExpression> {
    let present = usize::from(group.all_of.is_some())
        + usize::from(group.any_of.is_some())
        + usize::from(group.not.is_some())
        + usize::from(group.exists.is_some());
    if present != 1 {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "{scope} row policy groups must set exactly one of `all_of`, `any_of`, `not`, or `exists`"
            ),
        ));
    }

    if let Some(entries) = group.all_of {
        if entries.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy `all_of` entries cannot be empty"),
            ));
        }
        let expressions = entries
            .into_iter()
            .map(|entry| parse_filter_policy_expression(scope, entry))
            .collect::<syn::Result<Vec<_>>>()?;
        return PolicyFilterExpression::all(expressions).ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy `all_of` entries cannot be empty"),
            )
        });
    }

    if let Some(entries) = group.any_of {
        if entries.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy `any_of` entries cannot be empty"),
            ));
        }
        let expressions = entries
            .into_iter()
            .map(|entry| parse_filter_policy_expression(scope, entry))
            .collect::<syn::Result<Vec<_>>>()?;
        return PolicyFilterExpression::any(expressions).ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy `any_of` entries cannot be empty"),
            )
        });
    }

    let Some(policy) = group.not else {
        if let Some(filter) = group.exists {
            return parse_exists_policy(scope, filter);
        }
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "{scope} row policy groups must set exactly one of `all_of`, `any_of`, `not`, or `exists`"
            ),
        ));
    };
    Ok(PolicyFilterExpression::Not(Box::new(
        parse_filter_policy_expression(scope, *policy)?,
    )))
}

fn parse_exists_policy(
    scope: &'static str,
    policy: ExistsPolicyDocument,
) -> syn::Result<PolicyFilterExpression> {
    if policy.resource.trim().is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{scope} row policy exists resource cannot be empty"),
        ));
    }
    Ok(PolicyFilterExpression::Exists(PolicyExistsFilter {
        resource: policy.resource,
        condition: parse_exists_policy_expression(scope, policy.condition)?,
    }))
}

fn parse_exists_policy_expression(
    scope: &'static str,
    policy: Option<ExistsPolicyEntriesDocument>,
) -> syn::Result<PolicyExistsCondition> {
    let Some(policy) = policy else {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{scope} row policy exists conditions cannot be empty"),
        ));
    };
    parse_exists_policy_node(scope, policy)
}

fn parse_exists_policy_node(
    scope: &'static str,
    policy: ExistsPolicyEntriesDocument,
) -> syn::Result<PolicyExistsCondition> {
    match policy {
        ExistsPolicyEntriesDocument::Group(group) => parse_exists_policy_group(scope, group),
        ExistsPolicyEntriesDocument::Many(entries) => {
            if entries.is_empty() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!("{scope} row policy exists conditions cannot be empty"),
                ));
            }
            let expressions = entries
                .into_iter()
                .map(|entry| parse_exists_policy_node(scope, entry))
                .collect::<syn::Result<Vec<_>>>()?;
            PolicyExistsCondition::all(expressions).ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!("{scope} row policy exists conditions cannot be empty"),
                )
            })
        }
        ExistsPolicyEntriesDocument::Single(entry) => parse_exists_policy_entry(scope, entry),
    }
}

fn parse_exists_policy_group(
    scope: &'static str,
    group: ExistsPolicyGroupDocument,
) -> syn::Result<PolicyExistsCondition> {
    let present = usize::from(group.all_of.is_some())
        + usize::from(group.any_of.is_some())
        + usize::from(group.not.is_some());
    if present != 1 {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "{scope} row policy exists groups must set exactly one of `all_of`, `any_of`, or `not`"
            ),
        ));
    }

    if let Some(entries) = group.all_of {
        if entries.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy exists `all_of` entries cannot be empty"),
            ));
        }
        let expressions = entries
            .into_iter()
            .map(|entry| parse_exists_policy_node(scope, entry))
            .collect::<syn::Result<Vec<_>>>()?;
        return PolicyExistsCondition::all(expressions).ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy exists `all_of` entries cannot be empty"),
            )
        });
    }

    if let Some(entries) = group.any_of {
        if entries.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy exists `any_of` entries cannot be empty"),
            ));
        }
        let expressions = entries
            .into_iter()
            .map(|entry| parse_exists_policy_node(scope, entry))
            .collect::<syn::Result<Vec<_>>>()?;
        return PolicyExistsCondition::any(expressions).ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy exists `any_of` entries cannot be empty"),
            )
        });
    }

    let Some(policy) = group.not else {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "{scope} row policy exists groups must set exactly one of `all_of`, `any_of`, or `not`"
            ),
        ));
    };
    Ok(PolicyExistsCondition::Not(Box::new(
        parse_exists_policy_node(scope, *policy)?,
    )))
}

fn parse_exists_policy_entry(
    scope: &'static str,
    policy: ExistsPolicyEntryDocument,
) -> syn::Result<PolicyExistsCondition> {
    match policy {
        ExistsPolicyEntryDocument::Legacy(policy) => {
            let filter = parse_filter_policy(scope, PolicyEntryDocument::Legacy(policy))?;
            Ok(PolicyExistsCondition::Match(filter))
        }
        ExistsPolicyEntryDocument::Shorthand(policy) => {
            let filter = parse_filter_shorthand(scope, &policy)?;
            Ok(PolicyExistsCondition::Match(filter))
        }
        ExistsPolicyEntryDocument::Rule(policy) => {
            let present = usize::from(policy.equals.is_some())
                + usize::from(policy.equals_field.is_some())
                + usize::from(policy.is_null)
                + usize::from(policy.is_not_null);
            if present != 1 {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "{scope} row policy exists entries must set exactly one of `equals`, `equals_field`, `is_null`, or `is_not_null`"
                    ),
                ));
            }
            if let Some(source) = policy.equals {
                return Ok(PolicyExistsCondition::Match(PolicyFilter {
                    field: policy.field,
                    operator: PolicyFilterOperator::Equals(parse_policy_comparison_value(source)?),
                }));
            }
            if policy.is_null {
                return Ok(PolicyExistsCondition::Match(PolicyFilter {
                    field: policy.field,
                    operator: PolicyFilterOperator::IsNull,
                }));
            }
            if policy.is_not_null {
                return Ok(PolicyExistsCondition::Match(PolicyFilter {
                    field: policy.field,
                    operator: PolicyFilterOperator::IsNotNull,
                }));
            }
            Ok(PolicyExistsCondition::CurrentRowField {
                field: policy.field,
                row_field: policy.equals_field.expect("validated above"),
            })
        }
    }
}

fn parse_filter_policy(
    scope: &'static str,
    policy: PolicyEntryDocument,
) -> syn::Result<PolicyFilter> {
    match policy {
        PolicyEntryDocument::Legacy(policy) => {
            let kind = RowPolicyKind::parse(&policy.kind).ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        "row policy kind must be `Owner` or `SetOwner` (got `{}`)",
                        policy.kind
                    ),
                )
            })?;
            match kind {
                RowPolicyKind::Owner => Ok(PolicyFilter {
                    field: policy.field,
                    operator: PolicyFilterOperator::Equals(PolicyComparisonValue::Source(
                        PolicyValueSource::UserId,
                    )),
                }),
                RowPolicyKind::SetOwner => Err(syn::Error::new(
                    Span::call_site(),
                    format!("{scope} row policy must use `Owner` semantics"),
                )),
            }
        }
        PolicyEntryDocument::Rule(policy) => {
            let present = usize::from(policy.equals.is_some())
                + usize::from(policy.is_null)
                + usize::from(policy.is_not_null);
            if present != 1 {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "{scope} row policy entries must set exactly one of `equals`, `is_null`, or `is_not_null`"
                    ),
                ));
            }
            if let Some(source) = policy.equals {
                return Ok(PolicyFilter {
                    field: policy.field,
                    operator: PolicyFilterOperator::Equals(parse_policy_comparison_value(source)?),
                });
            }
            if policy.is_null {
                return Ok(PolicyFilter {
                    field: policy.field,
                    operator: PolicyFilterOperator::IsNull,
                });
            }
            Ok(PolicyFilter {
                field: policy.field,
                operator: PolicyFilterOperator::IsNotNull,
            })
        }
        PolicyEntryDocument::Shorthand(policy) => parse_filter_shorthand(scope, &policy),
    }
}

fn parse_assignment_policy(
    scope: &'static str,
    policy: PolicyEntryDocument,
) -> syn::Result<PolicyAssignment> {
    match policy {
        PolicyEntryDocument::Legacy(policy) => {
            let kind = RowPolicyKind::parse(&policy.kind).ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        "row policy kind must be `Owner` or `SetOwner` (got `{}`)",
                        policy.kind
                    ),
                )
            })?;
            match kind {
                RowPolicyKind::SetOwner => Ok(PolicyAssignment {
                    field: policy.field,
                    source: PolicyValueSource::UserId,
                }),
                RowPolicyKind::Owner => Err(syn::Error::new(
                    Span::call_site(),
                    "create row policy must use kind `SetOwner`",
                )),
            }
        }
        PolicyEntryDocument::Rule(policy) => {
            if policy.value.is_none()
                && policy.equals.is_none()
                && !policy.is_null
                && !policy.is_not_null
                && (policy.field.contains('=') || policy.field.contains(':'))
            {
                return parse_assignment_shorthand(&policy.field);
            }
            let source = policy.value.ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!("{scope} row policy entries must use `value`"),
                )
            })?;
            Ok(PolicyAssignment {
                field: policy.field,
                source: parse_policy_source(&source)?,
            })
        }
        PolicyEntryDocument::Shorthand(policy) => parse_assignment_shorthand(&policy),
    }
}

fn parse_filter_shorthand(scope: &'static str, value: &str) -> syn::Result<PolicyFilter> {
    if let Some(field) = parse_legacy_policy_field(value, RowPolicyKind::Owner) {
        return Ok(PolicyFilter {
            field,
            operator: PolicyFilterOperator::Equals(PolicyComparisonValue::Source(
                PolicyValueSource::UserId,
            )),
        });
    }

    if parse_legacy_policy_field(value, RowPolicyKind::SetOwner).is_some() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{scope} row policy must use `Owner` semantics"),
        ));
    }

    let (field, source) = parse_filter_expression(value)?;
    Ok(PolicyFilter {
        field,
        operator: PolicyFilterOperator::Equals(source),
    })
}

fn parse_assignment_shorthand(value: &str) -> syn::Result<PolicyAssignment> {
    if let Some(field) = parse_legacy_policy_field(value, RowPolicyKind::SetOwner) {
        return Ok(PolicyAssignment {
            field,
            source: PolicyValueSource::UserId,
        });
    }

    if parse_legacy_policy_field(value, RowPolicyKind::Owner).is_some() {
        return Err(syn::Error::new(
            Span::call_site(),
            "create row policy must use kind `SetOwner`",
        ));
    }

    let (field, source) = parse_assignment_expression(value)?;
    Ok(PolicyAssignment { field, source })
}

fn parse_legacy_policy_field(value: &str, kind: RowPolicyKind) -> Option<String> {
    let (parsed_kind, field) = value.split_once(':')?;
    let parsed_kind = RowPolicyKind::parse(parsed_kind.trim())?;
    if parsed_kind != kind {
        return None;
    }

    let field = field.trim();
    if field.is_empty() {
        None
    } else {
        Some(field.to_owned())
    }
}

fn parse_filter_expression(value: &str) -> syn::Result<(String, PolicyComparisonValue)> {
    let (field, source) = value.split_once('=').ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "row policy values must use `field=value`",
        )
    })?;
    let field = field.trim();
    if field.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "row policy field name cannot be empty",
        ));
    }

    Ok((
        field.to_owned(),
        parse_policy_string_comparison_value(source),
    ))
}

fn parse_assignment_expression(value: &str) -> syn::Result<(String, PolicyValueSource)> {
    let (field, source) = value.split_once('=').ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "row policy values must use `field=source`",
        )
    })?;
    let field = field.trim();
    if field.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "row policy field name cannot be empty",
        ));
    }

    Ok((field.to_owned(), parse_policy_source(source)?))
}

fn parse_policy_source(value: &str) -> syn::Result<PolicyValueSource> {
    PolicyValueSource::parse(value).ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "row policy source must be `user.id`, `claim.<name>`, or `input.<field>`",
        )
    })
}

fn parse_policy_string_comparison_value(value: &str) -> PolicyComparisonValue {
    PolicyValueSource::parse(value)
        .map(PolicyComparisonValue::Source)
        .unwrap_or_else(|| {
            PolicyComparisonValue::Literal(PolicyLiteralValue::String(value.to_owned()))
        })
}

fn parse_policy_comparison_value(
    value: PolicyComparisonValueDocument,
) -> syn::Result<PolicyComparisonValue> {
    Ok(match value {
        PolicyComparisonValueDocument::String(value) => {
            parse_policy_string_comparison_value(&value)
        }
        PolicyComparisonValueDocument::Integer(value) => {
            PolicyComparisonValue::Literal(PolicyLiteralValue::I64(value))
        }
        PolicyComparisonValueDocument::Bool(value) => {
            PolicyComparisonValue::Literal(PolicyLiteralValue::Bool(value))
        }
    })
}


