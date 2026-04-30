//! List-query token generators.
//!
//! Contains helpers that emit list-query types, bind-value enums,
//! filter conditions, cursor types, and query-plan types for resources.
//!
//! Extracted from `codegen.rs` to keep the parent module focused on
//! entry-point dispatch.

use std::collections::BTreeSet;
use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::Path;

use super::super::model::{
    FieldSpec, PolicyExistsCondition, PolicyFilterExpression, ResourceSpec,
    is_bool_type, is_integer_sql_type, is_structured_scalar_type,
    structured_scalar_kind, supports_contains_filters, supports_exact_filters, supports_range_filters,
};
use super::{
    field_supports_sort,
    resource_field,
    structured_scalar_to_text_tokens,
    structured_scalar_type_tokens,
};

pub(super) fn list_query_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListQuery", resource.struct_ident)
}

pub(super) fn list_query_type(resource: &ResourceSpec) -> TokenStream {
    let ident = list_query_ident(resource);
    quote!(#ident)
}

pub(super) fn list_sort_field_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListSortField", resource.struct_ident)
}

pub(super) fn list_sort_order_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListSortOrder", resource.struct_ident)
}

pub(super) fn list_bind_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListBindValue", resource.struct_ident)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum ListBindKind {
    Integer,
    Real,
    Boolean,
    Text,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PolicyHelperUsage {
    pub(super) needs_all: bool,
    pub(super) needs_any: bool,
    pub(super) needs_not: bool,
}

impl PolicyHelperUsage {
    pub(super) fn merge(self, other: Self) -> Self {
        Self {
            needs_all: self.needs_all || other.needs_all,
            needs_any: self.needs_any || other.needs_any,
            needs_not: self.needs_not || other.needs_not,
        }
    }
}

fn list_bind_kind_for_field(field: &FieldSpec) -> ListBindKind {
    if is_structured_scalar_type(&field.ty) {
        return ListBindKind::Text;
    }

    if is_bool_type(&field.ty) {
        return ListBindKind::Boolean;
    }

    match field.sql_type.as_str() {
        sql_type if is_integer_sql_type(sql_type) => ListBindKind::Integer,
        "REAL" => ListBindKind::Real,
        _ => ListBindKind::Text,
    }
}

fn collect_exists_condition_bind_kinds(
    resource: &ResourceSpec,
    target_resource: &ResourceSpec,
    condition: &PolicyExistsCondition,
    kinds: &mut BTreeSet<ListBindKind>,
) {
    match condition {
        PolicyExistsCondition::Match(filter) => {
            let field = resource_field(target_resource, &filter.field);
            kinds.insert(list_bind_kind_for_field(field));
        }
        PolicyExistsCondition::CurrentRowField { row_field, .. } => {
            let field = resource_field(resource, row_field);
            kinds.insert(list_bind_kind_for_field(field));
        }
        PolicyExistsCondition::All(conditions)
        | PolicyExistsCondition::Any(conditions) => {
            for condition in conditions {
                collect_exists_condition_bind_kinds(resource, target_resource, condition, kinds);
            }
        }
        PolicyExistsCondition::Not(condition) => {
            collect_exists_condition_bind_kinds(resource, target_resource, condition, kinds);
        }
    }
}

fn policy_exists_condition_helper_usage(
    condition: &PolicyExistsCondition,
) -> PolicyHelperUsage {
    match condition {
        PolicyExistsCondition::Match(_)
        | PolicyExistsCondition::CurrentRowField { .. } => {
            PolicyHelperUsage::default()
        }
        PolicyExistsCondition::All(conditions) => conditions.iter().fold(
            PolicyHelperUsage {
                needs_all: true,
                ..PolicyHelperUsage::default()
            },
            |usage, condition| usage.merge(policy_exists_condition_helper_usage(condition)),
        ),
        PolicyExistsCondition::Any(conditions) => conditions.iter().fold(
            PolicyHelperUsage {
                needs_any: true,
                ..PolicyHelperUsage::default()
            },
            |usage, condition| usage.merge(policy_exists_condition_helper_usage(condition)),
        ),
        PolicyExistsCondition::Not(condition) => PolicyHelperUsage {
            needs_not: true,
            ..policy_exists_condition_helper_usage(condition)
        },
    }
}

pub(super) fn policy_expression_helper_usage(expression: &PolicyFilterExpression) -> PolicyHelperUsage {
    match expression {
        PolicyFilterExpression::Match(_) => PolicyHelperUsage::default(),
        PolicyFilterExpression::All(expressions) => expressions.iter().fold(
            PolicyHelperUsage {
                needs_all: true,
                ..PolicyHelperUsage::default()
            },
            |usage, expression| usage.merge(policy_expression_helper_usage(expression)),
        ),
        PolicyFilterExpression::Any(expressions) => expressions.iter().fold(
            PolicyHelperUsage {
                needs_any: true,
                ..PolicyHelperUsage::default()
            },
            |usage, expression| usage.merge(policy_expression_helper_usage(expression)),
        ),
        PolicyFilterExpression::Not(expression) => PolicyHelperUsage {
            needs_not: true,
            ..policy_expression_helper_usage(expression)
        },
        PolicyFilterExpression::Exists(filter) => {
            policy_exists_condition_helper_usage(&filter.condition)
        }
    }
}

fn collect_policy_expression_bind_kinds(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    expression: &PolicyFilterExpression,
    kinds: &mut BTreeSet<ListBindKind>,
) {
    match expression {
        PolicyFilterExpression::Match(filter) => {
            let field = resource_field(resource, &filter.field);
            kinds.insert(list_bind_kind_for_field(field));
        }
        PolicyFilterExpression::All(expressions) | PolicyFilterExpression::Any(expressions) => {
            for expression in expressions {
                collect_policy_expression_bind_kinds(resource, resources, expression, kinds);
            }
        }
        PolicyFilterExpression::Not(expression) => {
            collect_policy_expression_bind_kinds(resource, resources, expression, kinds);
        }
        PolicyFilterExpression::Exists(filter) => {
            let target_resource = resources
                .iter()
                .find(|candidate| {
                    candidate.struct_ident == filter.resource.as_str()
                        || candidate.table_name == filter.resource
                })
                .unwrap_or_else(|| {
                    panic!(
                        "validated resource set is missing exists policy target `{}`",
                        filter.resource
                    )
                });
            collect_exists_condition_bind_kinds(
                resource,
                target_resource,
                &filter.condition,
                kinds,
            );
        }
    }
}

pub(super) fn list_bind_kinds(resource: &ResourceSpec, resources: &[ResourceSpec]) -> Vec<ListBindKind> {
    let mut kinds = BTreeSet::new();
    kinds.insert(ListBindKind::Integer);

    for field in resource.api_fields() {
        if supports_exact_filters(field) || field_supports_sort(field) {
            kinds.insert(list_bind_kind_for_field(field));
        }
        if supports_contains_filters(field) {
            kinds.insert(ListBindKind::Text);
        }
    }

    for expression in [
        resource.policies.read.as_ref(),
        resource.policies.update.as_ref(),
        resource.policies.delete.as_ref(),
        resource.policies.create_require.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        collect_policy_expression_bind_kinds(resource, resources, expression, &mut kinds);
    }

    kinds.into_iter().collect()
}

pub(super) fn list_bind_type(resource: &ResourceSpec) -> TokenStream {
    let ident = list_bind_ident(resource);
    quote!(#ident)
}

pub(super) fn option_u32_tokens(value: Option<u32>) -> TokenStream {
    match value {
        Some(value) => {
            let value = Literal::u32_unsuffixed(value);
            quote!(Some(#value))
        }
        None => quote!(None),
    }
}

pub(super) fn list_plan_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListQueryPlan", resource.struct_ident)
}

pub(super) fn list_plan_type(resource: &ResourceSpec) -> TokenStream {
    let ident = list_plan_ident(resource);
    quote!(#ident)
}

pub(super) fn list_response_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListResponse", resource.struct_ident)
}

pub(super) fn list_response_type(resource: &ResourceSpec) -> TokenStream {
    let ident = list_response_ident(resource);
    quote!(#ident)
}

pub(super) fn list_cursor_value_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}CursorValue", resource.struct_ident)
}

pub(super) fn list_cursor_payload_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}CursorPayload", resource.struct_ident)
}

pub(super) fn list_filter_field_ty(field: &FieldSpec, runtime_crate: &Path) -> TokenStream {
    if let Some(kind) = structured_scalar_kind(&field.ty) {
        return structured_scalar_type_tokens(kind, runtime_crate);
    }

    if is_bool_type(&field.ty) {
        return quote!(bool);
    }

    match field.sql_type.as_str() {
        sql_type if is_integer_sql_type(sql_type) => quote!(i64),
        "REAL" => quote!(f64),
        _ => quote!(String),
    }
}

pub(super) fn list_query_condition_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    let bind_ident = list_bind_ident(resource);
    resource
        .fields
        .iter()
        .map(|field| {
            if !field.expose_in_api() {
                return quote! {};
            }
            let field_name = Literal::string(&field.name());
            let contains_filter_tokens = if supports_contains_filters(field) {
                let contains_ident = format_ident!("filter_{}_contains", field.ident);
                quote! {
                    if let Some(value) = &query.#contains_ident {
                        conditions.push(format!(
                            "LOWER({}) LIKE {} ESCAPE '\\'",
                            #field_name,
                            Self::list_placeholder(filter_binds.len() + 1)
                        ));
                        filter_binds.push(#bind_ident::Text(Self::list_contains_pattern(value)));
                    }
                }
            } else {
                quote! {}
            };
            let exact_filter_tokens = if !supports_exact_filters(field) {
                quote! {}
            } else {
                let filter_ident = format_ident!("filter_{}", field.ident);
                if is_structured_scalar_type(&field.ty) {
                    let exact_value =
                        structured_scalar_to_text_tokens(&field.ty, quote!(value), runtime_crate);
                    let exact_value = exact_value.expect("structured scalar should render as text");
                    if supports_range_filters(&field.ty) {
                        let gt_ident = format_ident!("filter_{}_gt", field.ident);
                        let gte_ident = format_ident!("filter_{}_gte", field.ident);
                        let lt_ident = format_ident!("filter_{}_lt", field.ident);
                        let lte_ident = format_ident!("filter_{}_lte", field.ident);
                        quote! {
                            if let Some(value) = &query.#filter_ident {
                                conditions.push(format!(
                                    "{} = {}",
                                    #field_name,
                                    Self::list_placeholder(filter_binds.len() + 1)
                                ));
                                filter_binds.push(#bind_ident::Text(#exact_value));
                            }
                            if let Some(value) = &query.#gt_ident {
                                conditions.push(format!(
                                    "{} > {}",
                                    #field_name,
                                    Self::list_placeholder(filter_binds.len() + 1)
                                ));
                                filter_binds.push(#bind_ident::Text(#exact_value));
                            }
                            if let Some(value) = &query.#gte_ident {
                                conditions.push(format!(
                                    "{} >= {}",
                                    #field_name,
                                    Self::list_placeholder(filter_binds.len() + 1)
                                ));
                                filter_binds.push(#bind_ident::Text(#exact_value));
                            }
                            if let Some(value) = &query.#lt_ident {
                                conditions.push(format!(
                                    "{} < {}",
                                    #field_name,
                                    Self::list_placeholder(filter_binds.len() + 1)
                                ));
                                filter_binds.push(#bind_ident::Text(#exact_value));
                            }
                            if let Some(value) = &query.#lte_ident {
                                conditions.push(format!(
                                    "{} <= {}",
                                    #field_name,
                                    Self::list_placeholder(filter_binds.len() + 1)
                                ));
                                filter_binds.push(#bind_ident::Text(#exact_value));
                            }
                        }
                    } else {
                        quote! {
                            if let Some(value) = &query.#filter_ident {
                                conditions.push(format!(
                                    "{} = {}",
                                    #field_name,
                                    Self::list_placeholder(filter_binds.len() + 1)
                                ));
                                filter_binds.push(#bind_ident::Text(#exact_value));
                            }
                        }
                    }
                } else if is_bool_type(&field.ty) {
                    quote! {
                        if let Some(value) = query.#filter_ident {
                            conditions.push(format!(
                                "{} = {}",
                                #field_name,
                                Self::list_placeholder(filter_binds.len() + 1)
                            ));
                            filter_binds.push(#bind_ident::Boolean(value));
                        }
                    }
                } else {
                    match field.sql_type.as_str() {
                        sql_type if is_integer_sql_type(sql_type) => quote! {
                            if let Some(value) = query.#filter_ident {
                                conditions.push(format!(
                                    "{} = {}",
                                    #field_name,
                                    Self::list_placeholder(filter_binds.len() + 1)
                                ));
                                filter_binds.push(#bind_ident::Integer(value));
                            }
                        },
                        "REAL" => quote! {
                            if let Some(value) = query.#filter_ident {
                                conditions.push(format!(
                                    "{} = {}",
                                    #field_name,
                                    Self::list_placeholder(filter_binds.len() + 1)
                                ));
                                filter_binds.push(#bind_ident::Real(value));
                            }
                        },
                        _ => {
                            let enum_check = if let Some(enum_values) = field.enum_values() {
                                let enum_values = enum_values
                                    .iter()
                                    .map(|value| Literal::string(value.as_str()))
                                    .collect::<Vec<_>>();
                                quote! {
                                    if ![#(#enum_values),*].contains(&value.as_str()) {
                                        return Err(#runtime_crate::core::errors::bad_request(
                                            "invalid_query",
                                            "Query parameters are invalid",
                                        ));
                                    }
                                }
                            } else {
                                quote! {}
                            };
                            quote! {
                                if let Some(value) = &query.#filter_ident {
                                    #enum_check
                                    conditions.push(format!(
                                        "{} = {}",
                                        #field_name,
                                        Self::list_placeholder(filter_binds.len() + 1)
                                    ));
                                    filter_binds.push(#bind_ident::Text(value.clone()));
                                }
                            }
                        }
                    }
                }
            };
            quote! {
                #exact_filter_tokens
                #contains_filter_tokens
            }
        })
        .collect()
}

pub(super) fn list_bind_match_tokens(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    query_ident: &str,
) -> Vec<TokenStream> {
    let bind_ident = list_bind_ident(resource);
    let query_ident = syn::Ident::new(query_ident, proc_macro2::Span::call_site());
    list_bind_kinds(resource, resources)
        .into_iter()
        .map(|kind| match kind {
            ListBindKind::Integer => quote! {
                #bind_ident::Integer(value) => #query_ident.bind(value),
            },
            ListBindKind::Real => quote! {
                #bind_ident::Real(value) => #query_ident.bind(value),
            },
            ListBindKind::Boolean => quote! {
                #bind_ident::Boolean(value) => #query_ident.bind(value),
            },
            ListBindKind::Text => quote! {
                #bind_ident::Text(value) => #query_ident.bind(value),
            },
        })
        .collect()
}
