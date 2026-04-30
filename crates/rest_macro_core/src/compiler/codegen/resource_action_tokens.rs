//! Resource action token generators.
//!
//! Contains `resource_action_handler_tokens` and supporting helpers that
//! emit the Actix-web handler function for each custom resource action
//! (UpdateFields and DeleteResource behaviours).
//!
//! Extracted from `codegen.rs` to keep the parent module focused on
//! entry-point dispatch.

use heck::{ToSnakeCase, ToUpperCamelCase};
use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::Path;

use super::super::model::{
    GeneratedValue, ResourceActionAssignmentSpec, ResourceActionBehaviorSpec,
    ResourceActionSpec, ResourceActionValueSpec, ResourceSpec,
    generated_temporal_kind_for_field, is_optional_type,
};

use super::{
    bind_field_value_tokens,
    garde_field_attr_tokens,
    garde_validate_item_tokens,
    garde_validation_error_helper,
    HybridResourceEnforcement,
    normalization_tokens,
    policy_plan_ident,
    role_guard,
    validation_tokens,
};

pub(super) fn resource_action_input_ident(
    resource: &ResourceSpec,
    action: &ResourceActionSpec,
) -> syn::Ident {
    format_ident!(
        "{}{}ActionInput",
        resource.struct_ident,
        action.name.to_upper_camel_case()
    )
}

pub(super) fn resource_action_input_field_ident(index: usize) -> syn::Ident {
    format_ident!("field_{index}")
}

pub(super) fn resource_action_input_struct_tokens(
    resource: &ResourceSpec,
    action: &ResourceActionSpec,
    runtime_crate: &Path,
) -> Option<TokenStream> {
    if action.input_fields.is_empty() {
        return None;
    }

    let ident = resource_action_input_ident(resource, action);
    let fields = action
        .input_fields
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let target_field = resource
                .find_field(input.target_field.as_str())
                .expect("validated action input target field should exist");
            let field_ident = resource_action_input_field_ident(index);
            let ty = &target_field.ty;
            let rename = Literal::string(input.name.as_str());
            let garde_attr = garde_field_attr_tokens(
                target_field,
                is_optional_type(&target_field.ty),
                true,
            );
            quote! {
                #[serde(rename = #rename)]
                #garde_attr
                pub #field_ident: #ty,
            }
        })
        .collect::<Vec<_>>();

    Some(quote! {
        #[derive(
            Debug,
            Clone,
            #runtime_crate::serde::Serialize,
            #runtime_crate::serde::Deserialize,
            #runtime_crate::garde::Validate
        )]
        #[garde(allow_unvalidated)]
        pub struct #ident {
            #(#fields)*
        }
    })
}

pub(super) fn resource_action_handler_tokens(
    resource: &ResourceSpec,
    action: &ResourceActionSpec,
    hybrid: Option<HybridResourceEnforcement<'_>>,
    query_bind_matches: &[TokenStream],
    runtime_crate: &Path,
) -> TokenStream {
    let handler_ident = format_ident!("action_{}", action.name.to_snake_case());
    match &action.behavior {
        ResourceActionBehaviorSpec::UpdateFields { assignments } => {
            let update_check = role_guard(runtime_crate, resource.roles.update.as_deref());
            let action_input_ty = resource_action_input_ident(resource, action);
            let runtime_arg = if hybrid.map(|config| config.update).unwrap_or(false) {
                quote!(, runtime: web::Data<#runtime_crate::core::authorization::AuthorizationRuntime>)
            } else {
                quote!()
            };
            let action_payload_arg = if action.input_fields.is_empty() {
                quote!()
            } else {
                quote!(item: web::Json<#action_input_ty>,)
            };
            let action_normalization = action
                .input_fields
                .iter()
                .enumerate()
                .filter_map(|(index, input)| {
                    let field = resource
                        .find_field(input.target_field.as_str())
                        .expect("validated action input target field should exist");
                    let ident = resource_action_input_field_ident(index);
                    normalization_tokens(
                        resource,
                        field,
                        &ident,
                        is_optional_type(&field.ty),
                    )
                })
                .collect::<Vec<_>>();
            let action_validation = action
                .input_fields
                .iter()
                .enumerate()
                .filter_map(|(index, input)| {
                    let mut field = resource
                        .find_field(input.target_field.as_str())
                        .expect("validated action input target field should exist")
                        .clone();
                    field.api_name = input.name.clone();
                    let ident = resource_action_input_field_ident(index);
                    validation_tokens(
                        resource,
                        &field,
                        &ident,
                        is_optional_type(&field.ty),
                        runtime_crate,
                    )
                })
                .collect::<Vec<_>>();
            let garde_error_helper = garde_validation_error_helper(resource);
            let action_garde_validation = if action.input_fields.is_empty() {
                quote! {}
            } else {
                garde_validate_item_tokens(&garde_error_helper, runtime_crate)
            };
            let action_uses_input_assignments = match &action.behavior {
                ResourceActionBehaviorSpec::UpdateFields { assignments } => {
                    assignments.iter().any(|assignment| {
                        matches!(
                            assignment.value,
                            ResourceActionValueSpec::InputField(_)
                        )
                    })
                }
                ResourceActionBehaviorSpec::DeleteResource => false,
            };
            let action_payload_is_used = action_uses_input_assignments
                || !action.input_fields.is_empty()
                || !action_normalization.is_empty()
                || !action_validation.is_empty();
            let action_payload_binding = if !action_payload_is_used {
                quote!(let _ = item.into_inner();)
            } else if action_normalization.is_empty() {
                quote!(let item = item.into_inner();)
            } else {
                quote!(let mut item = item.into_inner();)
            };
            let action_payload_setup = if action.input_fields.is_empty() {
                quote!()
            } else {
                quote! {
                    let _ = &item;
                    #action_payload_binding
                    #(#action_normalization)*
                    #action_garde_validation
                    #(#action_validation)*
                }
            };
            let action_bind_statements = assignments
                .iter()
                .map(|assignment| resource_action_bind_statement(resource, action, assignment))
                .collect::<Vec<_>>();
            let mut update_clauses = assignments
                .iter()
                .enumerate()
                .map(|(index, assignment)| {
                    format!(
                        "{} = {}",
                        assignment.field,
                        resource.db.placeholder(index + 1)
                    )
                })
                .collect::<Vec<_>>();
            update_clauses.extend(
                resource
                    .fields
                    .iter()
                    .filter(|field| field.generated == GeneratedValue::UpdatedAt)
                    .map(|field| {
                        format!(
                            "{} = {}",
                            field.name(),
                            resource.db.generated_temporal_expression(
                                generated_temporal_kind_for_field(
                                    &field.ty,
                                    field.generated,
                                )
                            )
                        )
                    }),
            );
            let update_sql = update_clauses.join(", ");
            let where_index = assignments.len() + 1;
            let policy_start_index = Literal::usize_unsuffixed(assignments.len() + 2);
            let where_index_literal = Literal::usize_unsuffixed(where_index);
            let table_name = Literal::string(&resource.table_name);
            let id_field = Literal::string(&resource.id_field);
            let update_sql_literal = Literal::string(&update_sql);
            let admin_bypass = resource.policies.admin_bypass;
            let is_admin = quote! { user.roles.iter().any(|candidate| candidate == "admin") };

            if !resource.policies.has_update_filters() {
                let sql = format!(
                    "UPDATE {} SET {} WHERE {} = {}",
                    resource.table_name,
                    update_sql,
                    resource.id_field,
                    resource.db.placeholder(where_index)
                );
                quote! {
                    async fn #handler_ident(
                        path: web::Path<i64>,
                        user: #runtime_crate::core::auth::UserContext,
                        #action_payload_arg
                        db: web::Data<DbPool>
                        #runtime_arg
                    ) -> impl Responder {
                        let _ = (&path, &user, &db);
                        #update_check
                        let id = path.into_inner();
                        #action_payload_setup
                        let sql = #sql;
                        let mut q = #runtime_crate::db::query(sql);
                        #(#action_bind_statements)*
                        q = q.bind(id);
                        match q.execute(db.get_ref()).await {
                            Ok(result) if result.rows_affected() == 0 => {
                                #runtime_crate::core::errors::not_found("Not found")
                            }
                            Ok(_) => HttpResponse::Ok().finish(),
                            Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                        }
                    }
                }
            } else {
                let plan_ident = policy_plan_ident(resource);
                let admin_sql = format!(
                    "UPDATE {} SET {} WHERE {} = {}",
                    resource.table_name,
                    update_sql,
                    resource.id_field,
                    resource.db.placeholder(where_index)
                );
                let hybrid_update_fallback = if hybrid.map(|config| config.update).unwrap_or(false)
                {
                    quote! {
                        match Self::fetch_runtime_authorized_by_id(
                            id,
                            &user,
                            runtime.get_ref(),
                            db.get_ref(),
                            #runtime_crate::core::authorization::AuthorizationAction::Update,
                        )
                        .await
                        {
                            Ok(Some(_)) => {
                                let sql = #admin_sql;
                                let mut q = #runtime_crate::db::query(sql);
                                #(#action_bind_statements)*
                                q = q.bind(id);
                                match q.execute(db.get_ref()).await {
                                    Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                                    Ok(_) => HttpResponse::Ok().finish(),
                                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                                }
                            }
                            Ok(None) => #runtime_crate::core::errors::not_found("Not found"),
                            Err(response) => response,
                        }
                    }
                } else {
                    quote!(#runtime_crate::core::errors::not_found("Not found"))
                };
                let filtered_update = quote! {
                    match Self::update_policy_plan(&user, #policy_start_index) {
                        #plan_ident::Resolved { condition, binds } => {
                            let sql = format!(
                                "UPDATE {} SET {} WHERE {} = {} AND {}",
                                #table_name,
                                #update_sql_literal,
                                #id_field,
                                Self::list_placeholder(#where_index_literal),
                                condition
                            );
                            let mut q = #runtime_crate::db::query(&sql);
                            #(#action_bind_statements)*
                            q = q.bind(id);
                            for bind in binds {
                                q = match bind {
                                    #(#query_bind_matches)*
                                };
                            }
                            match q.execute(db.get_ref()).await {
                                Ok(result) if result.rows_affected() == 0 => #hybrid_update_fallback,
                                Ok(_) => HttpResponse::Ok().finish(),
                                Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                            }
                        }
                        #plan_ident::Indeterminate => #hybrid_update_fallback,
                    }
                };
                let action_body = if admin_bypass {
                    quote! {
                        let id = path.into_inner();
                        #action_payload_setup
                        if #is_admin {
                            let sql = #admin_sql;
                            let mut q = #runtime_crate::db::query(sql);
                            #(#action_bind_statements)*
                            q = q.bind(id);
                            match q.execute(db.get_ref()).await {
                                Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                                Ok(_) => HttpResponse::Ok().finish(),
                                Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                            }
                        } else {
                            #filtered_update
                        }
                    }
                } else {
                    quote! {
                        let id = path.into_inner();
                        #action_payload_setup
                        #filtered_update
                    }
                };
                quote! {
                    #[allow(clippy::collapsible_if)]
                    async fn #handler_ident(
                        path: web::Path<i64>,
                        user: #runtime_crate::core::auth::UserContext,
                        #action_payload_arg
                        db: web::Data<DbPool>
                        #runtime_arg
                    ) -> impl Responder {
                        let _ = (&path, &user, &db);
                        #update_check
                        #action_body
                    }
                }
            }
        }
        ResourceActionBehaviorSpec::DeleteResource => {
            let delete_check = role_guard(runtime_crate, resource.roles.delete.as_deref());
            let delete_runtime_arg = if hybrid.map(|config| config.delete).unwrap_or(false) {
                quote!(, runtime: web::Data<#runtime_crate::core::authorization::AuthorizationRuntime>)
            } else {
                quote!()
            };
            let table_name = Literal::string(&resource.table_name);
            let id_field = Literal::string(&resource.id_field);
            let admin_bypass = resource.policies.admin_bypass;
            let is_admin = quote! { user.roles.iter().any(|candidate| candidate == "admin") };

            if !resource.policies.has_delete_filters() {
                let id_placeholder = resource.db.placeholder(1);
                quote! {
                    async fn #handler_ident(
                        path: web::Path<i64>,
                        user: #runtime_crate::core::auth::UserContext,
                        db: web::Data<DbPool>
                        #delete_runtime_arg
                    ) -> impl Responder {
                        let _ = (&path, &user, &db);
                        #delete_check
                        let sql = format!(
                            "DELETE FROM {} WHERE {} = {}",
                            #table_name,
                            #id_field,
                            #id_placeholder
                        );
                        match #runtime_crate::db::query(&sql)
                            .bind(path.into_inner())
                            .execute(db.get_ref())
                            .await
                        {
                            Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                            Ok(_) => HttpResponse::Ok().finish(),
                            Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                        }
                    }
                }
            } else {
                let plan_ident = policy_plan_ident(resource);
                let admin_sql = format!(
                    "DELETE FROM {} WHERE {} = {}",
                    resource.table_name,
                    resource.id_field,
                    resource.db.placeholder(1)
                );
                let hybrid_delete_fallback = if hybrid.map(|config| config.delete).unwrap_or(false)
                {
                    quote! {
                        match Self::fetch_runtime_authorized_by_id(
                            id,
                            &user,
                            runtime.get_ref(),
                            db.get_ref(),
                            #runtime_crate::core::authorization::AuthorizationAction::Delete,
                        )
                        .await
                        {
                            Ok(Some(_)) => {
                                let sql = #admin_sql;
                                match #runtime_crate::db::query(&sql)
                                    .bind(id)
                                    .execute(db.get_ref())
                                    .await
                                {
                                    Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                                    Ok(_) => HttpResponse::Ok().finish(),
                                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                                }
                            }
                            Ok(None) => #runtime_crate::core::errors::not_found("Not found"),
                            Err(response) => response,
                        }
                    }
                } else {
                    quote!(#runtime_crate::core::errors::not_found("Not found"))
                };
                let filtered_delete = quote! {
                    match Self::delete_policy_plan(&user) {
                        #plan_ident::Resolved { condition, binds } => {
                            let sql = format!(
                                "DELETE FROM {} WHERE {} = {} AND {}",
                                #table_name,
                                #id_field,
                                Self::list_placeholder(1),
                                condition
                            );
                            let mut q = #runtime_crate::db::query(&sql).bind(id);
                            for bind in binds {
                                q = match bind {
                                    #(#query_bind_matches)*
                                };
                            }
                            match q.execute(db.get_ref()).await {
                                Ok(result) if result.rows_affected() == 0 => #hybrid_delete_fallback,
                                Ok(_) => HttpResponse::Ok().finish(),
                                Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                            }
                        }
                        #plan_ident::Indeterminate => #hybrid_delete_fallback,
                    }
                };
                let action_body = if admin_bypass {
                    quote! {
                        let id = path.into_inner();
                        if #is_admin {
                            let sql = #admin_sql;
                            match #runtime_crate::db::query(&sql)
                                .bind(id)
                                .execute(db.get_ref())
                                .await
                            {
                                Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                                Ok(_) => HttpResponse::Ok().finish(),
                                Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                            }
                        } else {
                            #filtered_delete
                        }
                    }
                } else {
                    quote! {
                        let id = path.into_inner();
                        #filtered_delete
                    }
                };
                quote! {
                    #[allow(clippy::collapsible_if)]
                    async fn #handler_ident(
                        path: web::Path<i64>,
                        user: #runtime_crate::core::auth::UserContext,
                        db: web::Data<DbPool>
                        #delete_runtime_arg
                    ) -> impl Responder {
                        let _ = (&path, &user, &db);
                        #delete_check
                        #action_body
                    }
                }
            }
        }
    }
}

fn resource_action_bind_statement(
    resource: &ResourceSpec,
    action: &ResourceActionSpec,
    assignment: &ResourceActionAssignmentSpec,
) -> TokenStream {
    match &assignment.value {
        ResourceActionValueSpec::Literal(serde_json::Value::Null) => quote! {
            q = q.bind::<Option<String>>(None);
        },
        ResourceActionValueSpec::Literal(serde_json::Value::Bool(value)) => quote! {
            q = q.bind(#value);
        },
        ResourceActionValueSpec::Literal(serde_json::Value::Number(value)) => {
            if let Some(integer) = value.as_i64() {
                quote! {
                    q = q.bind(#integer);
                }
            } else if let Some(real) = value.as_f64() {
                quote! {
                    q = q.bind(#real);
                }
            } else {
                unreachable!("action numeric values should be normalized to integers or reals")
            }
        }
        ResourceActionValueSpec::Literal(serde_json::Value::String(value)) => {
            let value = Literal::string(value);
            quote! {
                q = q.bind(#value);
            }
        }
        ResourceActionValueSpec::Literal(
            serde_json::Value::Array(_) | serde_json::Value::Object(_),
        ) => {
            unreachable!("structured action values are not supported in the first slice")
        }
        ResourceActionValueSpec::InputField(name) => {
            let index = action
                .input_fields
                .iter()
                .position(|field| field.name == *name)
                .expect("validated action input field should exist");
            let target_field = resource
                .find_field(action.input_fields[index].target_field.as_str())
                .expect("validated action input target field should exist");
            let ident = resource_action_input_field_ident(index);
            let bind_value = bind_field_value_tokens(target_field, quote!(item.#ident));
            quote! {
                q = q.bind(#bind_value);
            }
        }
    }
}
