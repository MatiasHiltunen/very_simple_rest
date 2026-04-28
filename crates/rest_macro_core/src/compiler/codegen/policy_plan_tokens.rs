//! Policy-plan token generators and insertion/validation helpers.
//!
//! Extracted from [`super`] to keep the parent module focused on the
//! entry-point functions and resource-struct emission.
//!
//! ## Cohesion
//! Every function here is concerned with either:
//! - Emitting `PolicyFilterPlan` enums and their methods, or
//! - Computing insert/update helpers (validation tokens, field lists, bind values).

use std::collections::BTreeSet;

use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::Path;

use super::super::model::{
    FieldSpec, GeneratedValue, PolicyComparisonValue, PolicyExistsCondition, PolicyExistsFilter,
    PolicyFilter, PolicyFilterExpression, PolicyFilterOperator, PolicyLiteralValue,
    PolicyValueSource, ResourceSpec, WriteModelStyle,
    generated_temporal_kind_for_field, policy_field_claim_type,
};
use super::{
    // Helper functions that live in codegen.rs and are called from here.
    // Child modules may access private items from their parent.
    create_payload_field_is_optional, create_payload_fields, create_payload_type,
    hybrid_resource_enforcement, list_bind_ident, list_bind_match_tokens,
    policy_expression_helper_usage, typed_object_validator_ident,
    PolicyHelperUsage,
};
use crate::authorization::AuthorizationContract;
pub(super) fn validation_tokens(
    resource: &ResourceSpec,
    field: &FieldSpec,
    ident: &syn::Ident,
    optional: bool,
    runtime_crate: &Path,
) -> Option<TokenStream> {
    if field.object_fields.is_none() && field.enum_values().is_none() {
        return None;
    }

    let field_name = Literal::string(field.api_name());
    let checks = validation_checks(field, &field_name, runtime_crate);
    let object_checks = typed_object_payload_validation_tokens(resource, field, runtime_crate);
    if checks.is_empty() && object_checks.is_none() {
        return None;
    }

    Some(if optional {
        quote! {
            if let Some(value) = &item.#ident {
                #(#checks)*
                #object_checks
            }
        }
    } else {
        quote! {
            let value = &item.#ident;
            #(#checks)*
            #object_checks
        }
    })
}

pub(super) fn typed_object_payload_validation_tokens(
    resource: &ResourceSpec,
    field: &FieldSpec,
    runtime_crate: &Path,
) -> Option<TokenStream> {
    field.object_fields.as_ref()?;

    let field_name = field.api_name().to_owned();
    let field_name_lit = Literal::string(&field_name);
    let validator_ident = typed_object_validator_ident(resource, &[field.name()]);

    Some(quote! {
        let parsed: #validator_ident = match #runtime_crate::serde_json::from_value(value.clone()) {
            Ok(value) => value,
            Err(error) => {
                return #runtime_crate::core::errors::validation_error(
                    #field_name_lit,
                    format!("Field `{}` is invalid: {}", #field_name_lit, error),
                );
            }
        };
        if let Err((field_path, message)) = parsed.validate(#field_name_lit) {
            return #runtime_crate::core::errors::validation_error(field_path, message);
        }
    })
}

pub(super) fn enum_values_as_message(field: &FieldSpec) -> String {
    field
        .enum_values()
        .expect("enum-backed field should define enum values")
        .join(", ")
}

pub(super) fn validation_checks(
    field: &FieldSpec,
    field_name: &Literal,
    runtime_crate: &Path,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();

    if let Some(enum_values) = field.enum_values() {
        let enum_values = enum_values
            .iter()
            .map(|value| Literal::string(value.as_str()))
            .collect::<Vec<_>>();
        let enum_values_message = Literal::string(&enum_values_as_message(field));
        checks.push(quote! {
            if ![#(#enum_values),*].contains(&value.as_str()) {
                return #runtime_crate::core::errors::validation_error(
                    #field_name,
                    format!("Field `{}` must be one of: {}", #field_name, #enum_values_message),
                );
            }
        });
    }

    checks
}

pub(super) fn insert_fields(resource: &ResourceSpec) -> Vec<&FieldSpec> {
    resource
        .fields
        .iter()
        .filter(|field| !field.generated.skip_insert())
        .collect()
}

pub(super) fn policy_controlled_fields(resource: &ResourceSpec) -> BTreeSet<String> {
    resource
        .policies
        .controlled_filter_fields()
        .into_iter()
        .chain(
            resource
                .policies
                .iter_assignments()
                .map(|(_, policy)| policy.field.clone()),
        )
        .collect()
}

pub(super) fn create_assignment_source<'a>(
    resource: &'a ResourceSpec,
    field_name: &str,
) -> Option<&'a PolicyValueSource> {
    resource
        .policies
        .create
        .iter()
        .find(|policy| policy.field == field_name)
        .map(|policy| &policy.source)
}

pub(super) fn resource_field<'a>(resource: &'a ResourceSpec, field_name: &str) -> &'a FieldSpec {
    resource
        .fields
        .iter()
        .find(|field| field.name() == field_name)
        .unwrap_or_else(|| panic!("validated resource is missing policy field `{field_name}`"))
}

pub(super) fn claim_access_value_tokens(claim_name: &Literal, field: &FieldSpec) -> TokenStream {
    match policy_field_claim_type(&field.ty)
        .unwrap_or_else(|| panic!("unsupported row policy field type for `{}`", field.name()))
    {
        crate::auth::AuthClaimType::I64 => quote!(user.claim_i64(#claim_name)),
        crate::auth::AuthClaimType::Bool => quote!(user.claim_bool(#claim_name)),
        crate::auth::AuthClaimType::String => {
            quote!(user.claim_str(#claim_name).map(|value| value.to_owned()))
        }
    }
}

pub(super) fn policy_source_value(
    source: &PolicyValueSource,
    field: &FieldSpec,
    runtime_crate: &Path,
) -> TokenStream {
    match source {
        PolicyValueSource::UserId => quote!(user.id),
        PolicyValueSource::Claim(name) => {
            let claim_name = Literal::string(name);
            let claim_value = claim_access_value_tokens(&claim_name, field);
            quote! {
                {
                    match #claim_value {
                        Some(value) => value,
                        None => return #runtime_crate::core::errors::forbidden(
                            "missing_claim",
                            format!("Missing required claim `{}`", #claim_name),
                        ),
                    }
                }
            }
        }
        PolicyValueSource::InputField(_) => {
            panic!("validated create assignments cannot use input sources")
        }
    }
}

pub(super) fn optional_policy_source_value(
    source: &PolicyValueSource,
    field: &FieldSpec,
) -> TokenStream {
    match source {
        PolicyValueSource::UserId => quote!(Some(user.id)),
        PolicyValueSource::Claim(name) => {
            let claim_name = Literal::string(name);
            claim_access_value_tokens(&claim_name, field)
        }
        PolicyValueSource::InputField(_) => {
            panic!("validated create assignments cannot use input sources")
        }
    }
}

pub(super) fn policy_literal_value_tokens(value: &PolicyLiteralValue) -> TokenStream {
    match value {
        PolicyLiteralValue::String(value) => {
            let value = Literal::string(value);
            quote!(#value.to_owned())
        }
        PolicyLiteralValue::I64(value) => {
            let value = Literal::i64_unsuffixed(*value);
            quote!(#value)
        }
        PolicyLiteralValue::Bool(value) => quote!(#value),
    }
}

pub(super) fn list_bind_value_tokens(
    bind_ident: &syn::Ident,
    field: &FieldSpec,
    value: TokenStream,
) -> TokenStream {
    match policy_field_claim_type(&field.ty)
        .unwrap_or_else(|| panic!("unsupported row policy field type for `{}`", field.name()))
    {
        crate::auth::AuthClaimType::I64 => quote!(#bind_ident::Integer(#value)),
        crate::auth::AuthClaimType::Bool => quote!(#bind_ident::Boolean(#value)),
        crate::auth::AuthClaimType::String => quote!(#bind_ident::Text(#value)),
    }
}

pub(super) fn policy_plan_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}PolicyFilterPlan", resource.struct_ident)
}

pub(super) fn maybe_policy_comparison_value(
    source: &PolicyComparisonValue,
    field: &FieldSpec,
) -> TokenStream {
    match source {
        PolicyComparisonValue::Source(source) => match source {
            PolicyValueSource::UserId => quote!(Some(user.id)),
            PolicyValueSource::Claim(name) => {
                let claim_name = Literal::string(name);
                claim_access_value_tokens(&claim_name, field)
            }
            PolicyValueSource::InputField(_) => {
                panic!("read/update/delete row policies cannot use input sources")
            }
        },
        PolicyComparisonValue::Literal(value) => {
            let value = policy_literal_value_tokens(value);
            quote!(Some(#value))
        }
    }
}

pub(super) fn policy_plan_enum_tokens(resource: &ResourceSpec) -> TokenStream {
    if !resource.policies.has_read_filters()
        && !resource.policies.has_update_filters()
        && !resource.policies.has_delete_filters()
    {
        return quote!();
    }

    let bind_ident = list_bind_ident(resource);
    let plan_ident = policy_plan_ident(resource);

    quote! {
        #[derive(Debug, Clone)]
        enum #plan_ident {
            Resolved {
                condition: String,
                binds: Vec<#bind_ident>,
            },
            Indeterminate,
        }
    }
}

pub(super) fn policy_plan_method_tokens(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    runtime_crate: &Path,
) -> TokenStream {
    if !resource.policies.has_read_filters()
        && !resource.policies.has_update_filters()
        && !resource.policies.has_delete_filters()
    {
        return quote!();
    }

    let bind_ident = list_bind_ident(resource);
    let plan_ident = policy_plan_ident(resource);
    let read_method = resource.policies.read.as_ref().map(|expression| {
        single_policy_plan_method_tokens(
            "read",
            resource,
            resources,
            expression,
            &bind_ident,
            &plan_ident,
            runtime_crate,
        )
    });
    let update_method = resource.policies.update.as_ref().map(|expression| {
        single_policy_plan_method_tokens(
            "update",
            resource,
            resources,
            expression,
            &bind_ident,
            &plan_ident,
            runtime_crate,
        )
    });
    let delete_method = resource.policies.delete.as_ref().map(|expression| {
        single_policy_plan_method_tokens(
            "delete",
            resource,
            resources,
            expression,
            &bind_ident,
            &plan_ident,
            runtime_crate,
        )
    });
    let helper_usage = [
        resource.policies.read.as_ref(),
        resource.policies.update.as_ref(),
        resource.policies.delete.as_ref(),
    ]
    .into_iter()
    .flatten()
    .fold(PolicyHelperUsage::default(), |usage, expression| {
        usage.merge(policy_expression_helper_usage(expression))
    });
    let combine_all_helper = if helper_usage.needs_all {
        quote! {
            fn combine_all_policy_plans(plans: Vec<#plan_ident>) -> #plan_ident {
                let mut conditions = Vec::new();
                let mut binds = Vec::new();
                for plan in plans {
                    match plan {
                        #plan_ident::Resolved {
                            condition,
                            binds: mut plan_binds,
                        } => {
                            conditions.push(condition);
                            binds.append(&mut plan_binds);
                        }
                        #plan_ident::Indeterminate => return #plan_ident::Indeterminate,
                    }
                }

                #plan_ident::Resolved {
                    condition: format!("({})", conditions.join(" AND ")),
                    binds,
                }
            }
        }
    } else {
        quote!()
    };
    let combine_any_helper = if helper_usage.needs_any {
        quote! {
            fn combine_any_policy_plans(plans: Vec<#plan_ident>) -> #plan_ident {
                let mut conditions = Vec::new();
                let mut binds = Vec::new();
                for plan in plans {
                    match plan {
                        #plan_ident::Resolved {
                            condition,
                            binds: mut plan_binds,
                        } => {
                            conditions.push(condition);
                            binds.append(&mut plan_binds);
                        }
                        #plan_ident::Indeterminate => {}
                    }
                }

                if conditions.is_empty() {
                    #plan_ident::Indeterminate
                } else {
                    #plan_ident::Resolved {
                        condition: format!("({})", conditions.join(" OR ")),
                        binds,
                    }
                }
            }
        }
    } else {
        quote!()
    };
    let negate_helper = if helper_usage.needs_not {
        quote! {
            fn negate_policy_plan(plan: #plan_ident) -> #plan_ident {
                match plan {
                    #plan_ident::Resolved { condition, binds } => #plan_ident::Resolved {
                        condition: format!("NOT ({condition})"),
                        binds,
                    },
                    #plan_ident::Indeterminate => #plan_ident::Indeterminate,
                }
            }
        }
    } else {
        quote!()
    };
    quote! {
        #combine_all_helper
        #combine_any_helper
        #negate_helper

        #read_method
        #update_method
        #delete_method
    }
}

pub(super) fn single_policy_plan_method_tokens(
    scope: &str,
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    expression: &PolicyFilterExpression,
    bind_ident: &syn::Ident,
    plan_ident: &syn::Ident,
    runtime_crate: &Path,
) -> TokenStream {
    let method_ident = format_ident!("{}_policy_plan", scope);
    let next_index_ident = format_ident!("next_index");
    let current_table_name = Literal::string(&resource.table_name);
    let expression_tokens = policy_expression_plan_tokens(
        resource,
        resources,
        expression,
        bind_ident,
        plan_ident,
        &next_index_ident,
        &current_table_name,
        scope,
    );

    quote! {
        fn #method_ident(
            user: &#runtime_crate::core::auth::UserContext,
            start_index: usize,
        ) -> #plan_ident {
            let mut #next_index_ident = start_index;
            #expression_tokens
        }
    }
}

pub(super) fn create_requirement_method_tokens(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    authorization: Option<&AuthorizationContract>,
    runtime_crate: &Path,
) -> TokenStream {
    let Some(expression) = resource.policies.create_require.as_ref() else {
        return quote!();
    };

    let bind_ident = list_bind_ident(resource);
    let create_payload_ty = create_payload_type(resource);
    let next_index_ident = format_ident!("next_index");
    let bind_matches = list_bind_match_tokens(resource, resources, "q");
    let expression_tokens = create_requirement_expression_plan_tokens(
        resource,
        resources,
        authorization,
        expression,
        &bind_ident,
        &next_index_ident,
        runtime_crate,
        "create_require",
    );
    let helper_usage = policy_expression_helper_usage(expression);
    let combine_all_helper = if helper_usage.needs_all {
        quote! {
            fn combine_all_create_requirement_plans(
                plans: Vec<(String, Vec<#bind_ident>)>,
            ) -> (String, Vec<#bind_ident>) {
                let mut conditions = Vec::new();
                let mut binds = Vec::new();
                for (condition, mut plan_binds) in plans {
                    conditions.push(condition);
                    binds.append(&mut plan_binds);
                }
                (format!("({})", conditions.join(" AND ")), binds)
            }
        }
    } else {
        quote!()
    };
    let combine_any_helper = if helper_usage.needs_any {
        quote! {
            fn combine_any_create_requirement_plans(
                plans: Vec<(String, Vec<#bind_ident>)>,
            ) -> (String, Vec<#bind_ident>) {
                let mut conditions = Vec::new();
                let mut binds = Vec::new();
                for (condition, mut plan_binds) in plans {
                    conditions.push(condition);
                    binds.append(&mut plan_binds);
                }
                (format!("({})", conditions.join(" OR ")), binds)
            }
        }
    } else {
        quote!()
    };
    let negate_helper = if helper_usage.needs_not {
        quote! {
            fn negate_create_requirement_plan(
                plan: (String, Vec<#bind_ident>),
            ) -> (String, Vec<#bind_ident>) {
                let (condition, binds) = plan;
                (format!("NOT ({condition})"), binds)
            }
        }
    } else {
        quote!()
    };

    quote! {
        #combine_all_helper
        #combine_any_helper
        #negate_helper

        async fn create_require_matches(
            item: &#create_payload_ty,
            user: &#runtime_crate::core::auth::UserContext,
            db: &DbPool,
            runtime: Option<&#runtime_crate::core::authorization::AuthorizationRuntime>,
        ) -> Result<bool, HttpResponse> {
            let _ = &runtime;
            let mut #next_index_ident = 1usize;
            let (condition, binds) = #expression_tokens;
            let sql = format!("SELECT 1 WHERE {}", condition);
            let mut q = #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&sql);
            for bind in binds {
                q = match bind {
                    #(#bind_matches)*
                };
            }
            match q.fetch_optional(db).await {
                Ok(result) => Ok(result.is_some()),
                Err(error) => Err(#runtime_crate::core::errors::internal_error(error.to_string())),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn create_requirement_expression_plan_tokens(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    authorization: Option<&AuthorizationContract>,
    expression: &PolicyFilterExpression,
    bind_ident: &syn::Ident,
    next_index_ident: &syn::Ident,
    runtime_crate: &Path,
    path: &str,
) -> TokenStream {
    match expression {
        PolicyFilterExpression::Match(filter) => {
            let field = resource_field(resource, &filter.field);
            let field_value = create_effective_field_value_tokens(
                resource,
                authorization,
                field,
                true,
                runtime_crate,
            );
            match &filter.operator {
                PolicyFilterOperator::Equals(source) => {
                    let source_value = create_comparison_value_tokens(
                        resource,
                        authorization,
                        field,
                        source,
                        true,
                        runtime_crate,
                    );
                    let left_bind = list_bind_value_tokens(bind_ident, field, quote!(left_value));
                    let right_bind = list_bind_value_tokens(bind_ident, field, quote!(right_value));
                    quote! {
                        {
                            let left_value = #field_value;
                            let right_value = #source_value;
                            let left_placeholder = Self::take_list_placeholder(&mut #next_index_ident);
                            let right_placeholder = Self::take_list_placeholder(&mut #next_index_ident);
                            (format!("{left_placeholder} = {right_placeholder}"), vec![#left_bind, #right_bind])
                        }
                    }
                }
                PolicyFilterOperator::IsNull => {
                    let value = create_effective_field_value_tokens(
                        resource,
                        authorization,
                        field,
                        false,
                        runtime_crate,
                    );
                    quote! {
                        {
                            let value = #value;
                            (
                                if value.is_none() {
                                    "1 = 1".to_owned()
                                } else {
                                    "1 = 0".to_owned()
                                },
                                Vec::<#bind_ident>::new(),
                            )
                        }
                    }
                }
                PolicyFilterOperator::IsNotNull => {
                    let value = create_effective_field_value_tokens(
                        resource,
                        authorization,
                        field,
                        false,
                        runtime_crate,
                    );
                    quote! {
                        {
                            let value = #value;
                            (
                                if value.is_some() {
                                    "1 = 1".to_owned()
                                } else {
                                    "1 = 0".to_owned()
                                },
                                Vec::<#bind_ident>::new(),
                            )
                        }
                    }
                }
            }
        }
        PolicyFilterExpression::All(expressions) => {
            let expressions = expressions
                .iter()
                .enumerate()
                .map(|(index, expression)| {
                    create_requirement_expression_plan_tokens(
                        resource,
                        resources,
                        authorization,
                        expression,
                        bind_ident,
                        next_index_ident,
                        runtime_crate,
                        &format!("{path}_{}", index + 1),
                    )
                })
                .collect::<Vec<_>>();
            quote!(Self::combine_all_create_requirement_plans(
                vec![#(#expressions),*]
            ))
        }
        PolicyFilterExpression::Any(expressions) => {
            let expressions = expressions
                .iter()
                .enumerate()
                .map(|(index, expression)| {
                    create_requirement_expression_plan_tokens(
                        resource,
                        resources,
                        authorization,
                        expression,
                        bind_ident,
                        next_index_ident,
                        runtime_crate,
                        &format!("{path}_{}", index + 1),
                    )
                })
                .collect::<Vec<_>>();
            quote!(Self::combine_any_create_requirement_plans(
                vec![#(#expressions),*]
            ))
        }
        PolicyFilterExpression::Not(expression) => {
            let expression = create_requirement_expression_plan_tokens(
                resource,
                resources,
                authorization,
                expression,
                bind_ident,
                next_index_ident,
                runtime_crate,
                &format!("{path}_not"),
            );
            quote!(Self::negate_create_requirement_plan(#expression))
        }
        PolicyFilterExpression::Exists(filter) => {
            let alias = Literal::string(&format!("create_require_exists_{path}"));
            let target_resource = resources
                .iter()
                .find(|candidate| {
                    candidate.struct_ident == filter.resource.as_str()
                        || candidate.table_name == filter.resource
                })
                .unwrap_or_else(|| {
                    panic!(
                        "validated resource set is missing create.require exists target `{}`",
                        filter.resource
                    )
                });
            let target_table = Literal::string(&target_resource.table_name);
            let exists_condition = create_requirement_exists_condition_tokens(
                resource,
                target_resource,
                authorization,
                &filter.condition,
                bind_ident,
                next_index_ident,
                &alias,
                runtime_crate,
                &format!("{path}_exists"),
            );
            quote! {
                {
                    let (condition, binds) = #exists_condition;
                    (
                        format!(
                            "EXISTS (SELECT 1 FROM {} AS {} WHERE {})",
                            #target_table,
                            #alias,
                            condition
                        ),
                        binds,
                    )
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn create_requirement_exists_condition_tokens(
    resource: &ResourceSpec,
    target_resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
    condition: &PolicyExistsCondition,
    bind_ident: &syn::Ident,
    next_index_ident: &syn::Ident,
    alias: &Literal,
    runtime_crate: &Path,
    path: &str,
) -> TokenStream {
    match condition {
        PolicyExistsCondition::Match(filter) => {
            let field = resource_field(target_resource, &filter.field);
            let field_name = Literal::string(&filter.field);
            match &filter.operator {
                PolicyFilterOperator::Equals(source) => {
                    let source_value = create_comparison_value_tokens(
                        resource,
                        authorization,
                        field,
                        source,
                        true,
                        runtime_crate,
                    );
                    let bind_value = list_bind_value_tokens(bind_ident, field, quote!(value));
                    quote! {
                        {
                            let value = #source_value;
                            let placeholder = Self::take_list_placeholder(&mut #next_index_ident);
                            (
                                format!("{}.{} = {}", #alias, #field_name, placeholder),
                                vec![#bind_value],
                            )
                        }
                    }
                }
                PolicyFilterOperator::IsNull => {
                    quote!((format!("{}.{} IS NULL", #alias, #field_name), Vec::<#bind_ident>::new()))
                }
                PolicyFilterOperator::IsNotNull => {
                    quote!((format!("{}.{} IS NOT NULL", #alias, #field_name), Vec::<#bind_ident>::new()))
                }
            }
        }
        PolicyExistsCondition::CurrentRowField { field, row_field } => {
            let field_name = Literal::string(field);
            let row_field = resource_field(resource, row_field);
            let row_value = create_effective_field_value_tokens(
                resource,
                authorization,
                row_field,
                true,
                runtime_crate,
            );
            let bind_value = list_bind_value_tokens(bind_ident, row_field, quote!(value));
            quote! {
                {
                    let value = #row_value;
                    let placeholder = Self::take_list_placeholder(&mut #next_index_ident);
                    (
                        format!("{}.{} = {}", #alias, #field_name, placeholder),
                        vec![#bind_value],
                    )
                }
            }
        }
        PolicyExistsCondition::All(conditions) => {
            let conditions = conditions
                .iter()
                .enumerate()
                .map(|(index, condition)| {
                    create_requirement_exists_condition_tokens(
                        resource,
                        target_resource,
                        authorization,
                        condition,
                        bind_ident,
                        next_index_ident,
                        alias,
                        runtime_crate,
                        &format!("{path}_{}", index + 1),
                    )
                })
                .collect::<Vec<_>>();
            quote!(Self::combine_all_create_requirement_plans(
                vec![#(#conditions),*]
            ))
        }
        PolicyExistsCondition::Any(conditions) => {
            let conditions = conditions
                .iter()
                .enumerate()
                .map(|(index, condition)| {
                    create_requirement_exists_condition_tokens(
                        resource,
                        target_resource,
                        authorization,
                        condition,
                        bind_ident,
                        next_index_ident,
                        alias,
                        runtime_crate,
                        &format!("{path}_{}", index + 1),
                    )
                })
                .collect::<Vec<_>>();
            quote!(Self::combine_any_create_requirement_plans(
                vec![#(#conditions),*]
            ))
        }
        PolicyExistsCondition::Not(condition) => {
            let condition = create_requirement_exists_condition_tokens(
                resource,
                target_resource,
                authorization,
                condition,
                bind_ident,
                next_index_ident,
                alias,
                runtime_crate,
                &format!("{path}_not"),
            );
            quote!(Self::negate_create_requirement_plan(#condition))
        }
    }
}

pub(super) fn create_source_value_tokens(
    resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
    target_field: &FieldSpec,
    source: &PolicyValueSource,
    required: bool,
    runtime_crate: &Path,
) -> TokenStream {
    match source {
        PolicyValueSource::UserId => {
            if required {
                quote!(user.id)
            } else {
                quote!(Some(user.id))
            }
        }
        PolicyValueSource::Claim(_) => {
            create_claim_source_value_tokens(target_field, source, required, runtime_crate)
        }
        PolicyValueSource::InputField(name) => {
            let field = resource_field(resource, name);
            create_raw_input_field_value_tokens(
                resource,
                authorization,
                field,
                required,
                runtime_crate,
            )
        }
    }
}

pub(super) fn create_comparison_value_tokens(
    resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
    target_field: &FieldSpec,
    source: &PolicyComparisonValue,
    required: bool,
    runtime_crate: &Path,
) -> TokenStream {
    match source {
        PolicyComparisonValue::Source(source) => create_source_value_tokens(
            resource,
            authorization,
            target_field,
            source,
            required,
            runtime_crate,
        ),
        PolicyComparisonValue::Literal(value) => {
            let value = policy_literal_value_tokens(value);
            if required {
                value
            } else {
                quote!(Some(#value))
            }
        }
    }
}

pub(super) fn create_claim_source_value_tokens(
    target_field: &FieldSpec,
    source: &PolicyValueSource,
    required: bool,
    runtime_crate: &Path,
) -> TokenStream {
    let value = optional_policy_source_value(source, target_field);
    if required {
        let field_name = Literal::string(&target_field.name());
        if let PolicyValueSource::Claim(name) = source {
            let claim_name = Literal::string(name);
            quote! {
                match #value {
                    Some(value) => value,
                    None => {
                        return Err(#runtime_crate::core::errors::forbidden(
                            "missing_claim",
                            format!("Missing required claim `{}` for create requirement field `{}`", #claim_name, #field_name),
                        ));
                    }
                }
            }
        } else {
            quote!(match #value { Some(value) => value, None => unreachable!() })
        }
    } else {
        value
    }
}

pub(super) fn create_effective_field_value_tokens(
    resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
    field: &FieldSpec,
    required: bool,
    runtime_crate: &Path,
) -> TokenStream {
    let field_name = field.name();
    let field_name_lit = Literal::string(field.api_name());
    let ident = &field.ident;
    let is_admin = quote!(user.roles.iter().any(|candidate| candidate == "admin"));
    let hybrid_create_scope_field = hybrid_resource_enforcement(resource, authorization)
        .filter(|config| config.create_payload)
        .map(|config| config.scope_field.name());

    if let Some(source) = create_assignment_source(resource, &field_name) {
        match source {
            PolicyValueSource::UserId => {
                if required {
                    quote!(user.id)
                } else {
                    quote!(Some(user.id))
                }
            }
            PolicyValueSource::Claim(_) => {
                let claim_value = optional_policy_source_value(source, field);
                let allow_hybrid_runtime =
                    hybrid_create_scope_field.as_deref() == Some(field_name.as_str());
                let allow_admin_override = resource.policies.admin_bypass;
                if required {
                    if allow_hybrid_runtime {
                        if allow_admin_override {
                            quote! {
                                {
                                    if #is_admin {
                                        match &item.#ident {
                                            Some(value) => value.clone(),
                                            None => match #claim_value {
                                                Some(value) => value,
                                                None => {
                                                    return Err(#runtime_crate::core::errors::validation_error(
                                                        #field_name_lit,
                                                        format!("Missing required create field `{}`", #field_name_lit),
                                                    ));
                                                }
                                            },
                                        }
                                    } else {
                                        match #claim_value {
                                            Some(value) => value,
                                            None => match &item.#ident {
                                                Some(value) => match runtime {
                                                    Some(runtime) => match Self::hybrid_create_allows_item_scope(item, user, runtime).await {
                                                        Ok(true) => value.clone(),
                                                        Ok(false) => {
                                                            return Err(#runtime_crate::core::errors::forbidden(
                                                                "forbidden",
                                                                format!("Insufficient privileges for create scope field `{}`", #field_name_lit),
                                                            ));
                                                        }
                                                        Err(response) => return Err(response),
                                                    },
                                                    None => {
                                                        return Err(#runtime_crate::core::errors::internal_error(
                                                            "Hybrid create scope evaluation requested without runtime authorization state".to_owned(),
                                                        ));
                                                    }
                                                },
                                                None => {
                                                    return Err(#runtime_crate::core::errors::validation_error(
                                                        #field_name_lit,
                                                        format!("Missing required create field `{}`", #field_name_lit),
                                                    ));
                                                }
                                            },
                                        }
                                    }
                                }
                            }
                        } else {
                            quote! {
                                {
                                    match #claim_value {
                                        Some(value) => value,
                                        None => match &item.#ident {
                                            Some(value) => match runtime {
                                                Some(runtime) => match Self::hybrid_create_allows_item_scope(item, user, runtime).await {
                                                    Ok(true) => value.clone(),
                                                    Ok(false) => {
                                                        return Err(#runtime_crate::core::errors::forbidden(
                                                            "forbidden",
                                                            format!("Insufficient privileges for create scope field `{}`", #field_name_lit),
                                                        ));
                                                    }
                                                    Err(response) => return Err(response),
                                                },
                                                None => {
                                                    return Err(#runtime_crate::core::errors::internal_error(
                                                        "Hybrid create scope evaluation requested without runtime authorization state".to_owned(),
                                                    ));
                                                }
                                            },
                                            None => {
                                                return Err(#runtime_crate::core::errors::validation_error(
                                                    #field_name_lit,
                                                    format!("Missing required create field `{}`", #field_name_lit),
                                                ));
                                            }
                                        },
                                    }
                                }
                            }
                        }
                    } else if allow_admin_override {
                        quote! {
                            {
                                if #is_admin {
                                    match &item.#ident {
                                        Some(value) => value.clone(),
                                        None => match #claim_value {
                                            Some(value) => value,
                                            None => {
                                                return Err(#runtime_crate::core::errors::validation_error(
                                                    #field_name_lit,
                                                    format!("Missing required create field `{}`", #field_name_lit),
                                                ));
                                            }
                                        },
                                    }
                                } else {
                                    match #claim_value {
                                        Some(value) => value,
                                        None => {
                                            return Err(#runtime_crate::core::errors::forbidden(
                                                "missing_claim",
                                                format!("Missing required claim for create field `{}`", #field_name_lit),
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        let value = policy_source_value(source, field, runtime_crate);
                        quote!(#value)
                    }
                } else if allow_hybrid_runtime {
                    if allow_admin_override {
                        quote! {
                            {
                                if #is_admin {
                                    match &item.#ident {
                                        Some(value) => Some(value.clone()),
                                        None => #claim_value,
                                    }
                                } else {
                                    match #claim_value {
                                        Some(value) => Some(value),
                                        None => match &item.#ident {
                                            Some(value) => match runtime {
                                                Some(runtime) => match Self::hybrid_create_allows_item_scope(item, user, runtime).await {
                                                    Ok(true) => Some(value.clone()),
                                                    Ok(false) => {
                                                        return Err(#runtime_crate::core::errors::forbidden(
                                                            "forbidden",
                                                            format!("Insufficient privileges for create scope field `{}`", #field_name_lit),
                                                        ));
                                                    }
                                                    Err(response) => return Err(response),
                                                },
                                                None => {
                                                    return Err(#runtime_crate::core::errors::internal_error(
                                                        "Hybrid create scope evaluation requested without runtime authorization state".to_owned(),
                                                    ));
                                                }
                                            },
                                            None => None,
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        quote! {
                            {
                                match #claim_value {
                                    Some(value) => Some(value),
                                    None => match &item.#ident {
                                        Some(value) => match runtime {
                                            Some(runtime) => match Self::hybrid_create_allows_item_scope(item, user, runtime).await {
                                                Ok(true) => Some(value.clone()),
                                                Ok(false) => {
                                                    return Err(#runtime_crate::core::errors::forbidden(
                                                        "forbidden",
                                                        format!("Insufficient privileges for create scope field `{}`", #field_name_lit),
                                                    ));
                                                }
                                                Err(response) => return Err(response),
                                            },
                                            None => {
                                                return Err(#runtime_crate::core::errors::internal_error(
                                                    "Hybrid create scope evaluation requested without runtime authorization state".to_owned(),
                                                ));
                                            }
                                        },
                                        None => None,
                                    }
                                }
                            }
                        }
                    }
                } else if allow_admin_override {
                    quote! {
                        {
                            if #is_admin {
                                match &item.#ident {
                                    Some(value) => Some(value.clone()),
                                    None => #claim_value,
                                }
                            } else {
                                #claim_value
                            }
                        }
                    }
                } else {
                    claim_value
                }
            }
            PolicyValueSource::InputField(_) => {
                unreachable!("create assignments do not support input sources")
            }
        }
    } else {
        create_raw_input_field_value_tokens(resource, authorization, field, required, runtime_crate)
    }
}

pub(super) fn create_raw_input_field_value_tokens(
    resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
    field: &FieldSpec,
    required: bool,
    runtime_crate: &Path,
) -> TokenStream {
    let field_name = field.name();
    let field_name_lit = Literal::string(field.api_name());
    let ident = &field.ident;
    let payload_field = create_payload_fields(resource, authorization)
        .into_iter()
        .find(|candidate| candidate.field.name() == field_name);

    let Some(payload_field) = payload_field else {
        return if required {
            quote! {
                {
                    return Err(#runtime_crate::core::errors::validation_error(
                        #field_name_lit,
                        format!("Create field `{}` is not client-settable", #field_name_lit),
                    ));
                }
            }
        } else {
            quote!(None)
        };
    };

    if required {
        if create_payload_field_is_optional(&payload_field) {
            quote! {
                match &item.#ident {
                    Some(value) => value.clone(),
                    None => {
                        return Err(#runtime_crate::core::errors::validation_error(
                            #field_name_lit,
                            format!("Missing required create field `{}`", #field_name_lit),
                        ));
                    }
                }
            }
        } else {
            quote!(item.#ident.clone())
        }
    } else if create_payload_field_is_optional(&payload_field) {
        quote!(item.#ident.clone())
    } else {
        quote!(Some(item.#ident.clone()))
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn policy_expression_plan_tokens(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    expression: &PolicyFilterExpression,
    bind_ident: &syn::Ident,
    plan_ident: &syn::Ident,
    next_index_ident: &syn::Ident,
    current_table_name: &Literal,
    path: &str,
) -> TokenStream {
    match expression {
        PolicyFilterExpression::Match(filter) => {
            let field = resource_field(resource, &filter.field);
            let field_name = Literal::string(&filter.field);
            match &filter.operator {
                PolicyFilterOperator::Equals(source) => {
                    let value = maybe_policy_comparison_value(source, field);
                    let bind_value = list_bind_value_tokens(bind_ident, field, quote!(value));
                    quote! {
                        {
                            match #value {
                                Some(value) => {
                                    let placeholder = Self::take_list_placeholder(&mut #next_index_ident);
                                    #plan_ident::Resolved {
                                        condition: format!("{} = {}", #field_name, placeholder),
                                        binds: vec![#bind_value],
                                    }
                                }
                                None => #plan_ident::Indeterminate,
                            }
                        }
                    }
                }
                PolicyFilterOperator::IsNull => quote! {
                    #plan_ident::Resolved {
                        condition: format!("{} IS NULL", #field_name),
                        binds: Vec::<#bind_ident>::new(),
                    }
                },
                PolicyFilterOperator::IsNotNull => quote! {
                    #plan_ident::Resolved {
                        condition: format!("{} IS NOT NULL", #field_name),
                        binds: Vec::<#bind_ident>::new(),
                    }
                },
            }
        }
        PolicyFilterExpression::All(expressions) => {
            let expressions = expressions
                .iter()
                .enumerate()
                .map(|(index, expression)| {
                    policy_expression_plan_tokens(
                        resource,
                        resources,
                        expression,
                        bind_ident,
                        plan_ident,
                        next_index_ident,
                        current_table_name,
                        &format!("{path}_{}", index + 1),
                    )
                })
                .collect::<Vec<_>>();
            quote!(Self::combine_all_policy_plans(vec![#(#expressions),*]))
        }
        PolicyFilterExpression::Any(expressions) => {
            let expressions = expressions
                .iter()
                .enumerate()
                .map(|(index, expression)| {
                    policy_expression_plan_tokens(
                        resource,
                        resources,
                        expression,
                        bind_ident,
                        plan_ident,
                        next_index_ident,
                        current_table_name,
                        &format!("{path}_{}", index + 1),
                    )
                })
                .collect::<Vec<_>>();
            quote!(Self::combine_any_policy_plans(vec![#(#expressions),*]))
        }
        PolicyFilterExpression::Not(expression) => {
            let expression = policy_expression_plan_tokens(
                resource,
                resources,
                expression,
                bind_ident,
                plan_ident,
                next_index_ident,
                current_table_name,
                &format!("{path}_not"),
            );
            quote!(Self::negate_policy_plan(#expression))
        }
        PolicyFilterExpression::Exists(filter) => {
            let alias = Literal::string(&format!("policy_exists_{path}"));
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
            let target_table = Literal::string(&target_resource.table_name);
            let exists_condition = exists_condition_plan_tokens(
                target_resource,
                &filter.condition,
                bind_ident,
                plan_ident,
                next_index_ident,
                &alias,
                current_table_name,
                &format!("{path}_exists"),
            );
            quote! {
                {
                    match (#exists_condition) {
                        #plan_ident::Resolved { condition, binds } => #plan_ident::Resolved {
                            condition: format!(
                                "EXISTS (SELECT 1 FROM {} AS {} WHERE {})",
                                #target_table,
                                #alias,
                                condition
                            ),
                            binds,
                        },
                        #plan_ident::Indeterminate => #plan_ident::Indeterminate,
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn exists_condition_plan_tokens(
    target_resource: &ResourceSpec,
    condition: &PolicyExistsCondition,
    bind_ident: &syn::Ident,
    plan_ident: &syn::Ident,
    next_index_ident: &syn::Ident,
    alias: &Literal,
    current_table_name: &Literal,
    path: &str,
) -> TokenStream {
    match condition {
        PolicyExistsCondition::Match(filter) => {
            let field = resource_field(target_resource, &filter.field);
            let field_name = Literal::string(&filter.field);
            match &filter.operator {
                PolicyFilterOperator::Equals(source) => {
                    let value = maybe_policy_comparison_value(source, field);
                    let bind_value = list_bind_value_tokens(bind_ident, field, quote!(value));
                    quote! {
                        match #value {
                            Some(value) => {
                                let placeholder = Self::take_list_placeholder(&mut #next_index_ident);
                                #plan_ident::Resolved {
                                    condition: format!("{}.{} = {}", #alias, #field_name, placeholder),
                                    binds: vec![#bind_value],
                                }
                            }
                            None => #plan_ident::Indeterminate,
                        }
                    }
                }
                PolicyFilterOperator::IsNull => quote! {
                    #plan_ident::Resolved {
                        condition: format!("{}.{} IS NULL", #alias, #field_name),
                        binds: Vec::<#bind_ident>::new(),
                    }
                },
                PolicyFilterOperator::IsNotNull => quote! {
                    #plan_ident::Resolved {
                        condition: format!("{}.{} IS NOT NULL", #alias, #field_name),
                        binds: Vec::<#bind_ident>::new(),
                    }
                },
            }
        }
        PolicyExistsCondition::CurrentRowField { field, row_field } => {
            let field_name = Literal::string(field);
            let row_field_name = Literal::string(row_field);
            quote! {
                #plan_ident::Resolved {
                    condition: format!(
                        "{}.{} = {}.{}",
                        #alias,
                        #field_name,
                        #current_table_name,
                        #row_field_name
                    ),
                    binds: Vec::<#bind_ident>::new(),
                }
            }
        }
        PolicyExistsCondition::All(conditions) => {
            let conditions = conditions
                .iter()
                .enumerate()
                .map(|(index, condition)| {
                    exists_condition_plan_tokens(
                        target_resource,
                        condition,
                        bind_ident,
                        plan_ident,
                        next_index_ident,
                        alias,
                        current_table_name,
                        &format!("{path}_{}", index + 1),
                    )
                })
                .collect::<Vec<_>>();
            quote!(Self::combine_all_policy_plans(vec![#(#conditions),*]))
        }
        PolicyExistsCondition::Any(conditions) => {
            let conditions = conditions
                .iter()
                .enumerate()
                .map(|(index, condition)| {
                    exists_condition_plan_tokens(
                        target_resource,
                        condition,
                        bind_ident,
                        plan_ident,
                        next_index_ident,
                        alias,
                        current_table_name,
                        &format!("{path}_{}", index + 1),
                    )
                })
                .collect::<Vec<_>>();
            quote!(Self::combine_any_policy_plans(vec![#(#conditions),*]))
        }
        PolicyExistsCondition::Not(condition) => {
            let condition = exists_condition_plan_tokens(
                target_resource,
                condition,
                bind_ident,
                plan_ident,
                next_index_ident,
                alias,
                current_table_name,
                &format!("{path}_not"),
            );
            quote!(Self::negate_policy_plan(#condition))
        }
    }
}

pub(super) fn role_guard(runtime_crate: &Path, role: Option<&str>) -> TokenStream {
    match role {
        Some("admin") => quote! {
            if !user.roles.iter().any(|candidate| candidate == "admin") {
                return #runtime_crate::core::errors::forbidden(
                    "forbidden",
                    "Insufficient privileges",
                );
            }
        },
        Some(role) => quote! {
            if !user.roles.iter().any(|candidate| candidate == "admin" || candidate == #role) {
                return #runtime_crate::core::errors::forbidden(
                    "forbidden",
                    "Insufficient privileges",
                );
            }
        },
        None => quote! {},
    }
}

pub(super) struct UpdatePlan {
    pub(super) clauses: Vec<String>,
    pub(super) bind_fields: Vec<syn::Ident>,
    pub(super) where_index: usize,
}

pub(super) fn build_update_plan(resource: &ResourceSpec) -> UpdatePlan {
    let mut clauses = Vec::new();
    let mut bind_fields = Vec::new();
    let mut bind_index = 1;
    let controlled_fields = policy_controlled_fields(resource);

    for field in &resource.fields {
        if field.is_id || controlled_fields.contains(&field.name()) {
            continue;
        }

        let field_name = field.name();
        match field.generated {
            GeneratedValue::UpdatedAt => {
                clauses.push(format!(
                    "{field_name} = {}",
                    resource
                        .db
                        .generated_temporal_expression(
                            generated_temporal_kind_for_field(
                                &field.ty,
                                field.generated,
                            ),
                        )
                ));
            }
            GeneratedValue::AutoIncrement | GeneratedValue::CreatedAt => {}
            GeneratedValue::None => {
                clauses.push(format!(
                    "{field_name} = {}",
                    resource.db.placeholder(bind_index)
                ));
                bind_fields.push(field.ident.clone());
                bind_index += 1;
            }
        }
    }

    UpdatePlan {
        clauses,
        bind_fields,
        where_index: bind_index,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use syn::parse_str;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn compact_tokens(tokens: &proc_macro2::TokenStream) -> String {
        tokens
            .to_string()
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect()
    }

    #[test]
    fn simple_resources_use_direct_json_response_helpers() {
        let tokens = crate::compiler::expand_service_from_path(
            &fixture_path("build_config_api.eon"),
            parse_str("very_simple_rest").expect("runtime crate path should parse"),
        )
        .expect("fixture should expand");
        let compact = compact_tokens(&tokens);

        assert!(compact.contains("HttpResponse::Ok().json(item)"));
        assert!(compact.contains("HttpResponse::Ok().json(response)"));
        assert!(
            compact.contains(
                "HttpResponse::Created().append_header((\"Location\",Self::created_location(req,id))).json(item)"
            )
        );
    }

    #[test]
    fn computed_or_contextual_resources_keep_value_serialization_helpers() {
        let tokens = crate::compiler::expand_service_from_path(
            &fixture_path("api_computed_fields_api.eon"),
            parse_str("very_simple_rest").expect("runtime crate path should parse"),
        )
        .expect("fixture should expand");
        let compact = compact_tokens(&tokens);

        assert!(compact.contains(
            "fnitem_ok_response(item:&Self,requested:Option<&str>)->HttpResponse{matchSelf::serialize_item_response(item,requested){Ok(value)=>HttpResponse::Ok().json(value),Err(response)=>response,}}"
        ));
        assert!(compact.contains(
            "matchSelf::serialize_list_response(response,requested){Ok(value)=>HttpResponse::Ok().json(value),Err(response)=>response,}"
        ));
    }

}
