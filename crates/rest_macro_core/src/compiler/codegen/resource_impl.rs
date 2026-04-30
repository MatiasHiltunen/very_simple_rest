//! Resource implementation token generation.
//!
//! Contains `resource_impl_tokens`, which generates the full `impl` block
//! for a resource: CRUD handlers, relation routes, many-to-many routes,
//! and action handlers.
//!
//! Extracted from `codegen.rs` to keep the parent module focused on
//! entry-point dispatch (`expand_resource_impl`, `expand_service_module`).

use heck::ToSnakeCase;
use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::Path;

use super::super::model::{PolicyValueSource, ResourceSpec};
use crate::authorization::AuthorizationContract;

// Parent-module (codegen.rs) helpers and sibling-module helpers accessed
// via the parent's glob re-exports. Child modules can call private parent
// items via `super::`, no pub(super) required.
use super::{
    bind_field_value_tokens,
    build_update_plan,
    create_assignment_source,
    create_normalization_tokens,
    create_payload_fields, create_payload_type,
    create_requirement_method_tokens,
    create_validation_tokens,
    field_supports_sort,
    garde_validate_item_tokens, garde_validation_error_helper,
    hybrid_resource_enforcement,
    insert_fields, integer_to_i64_tokens,
    json_bind_tokens,
    list_bind_match_tokens, list_bind_type,
    list_cursor_payload_ident, list_cursor_value_ident,
    list_plan_type,
    list_query_condition_tokens, list_query_type,
    list_response_ident, list_response_type,
    list_sort_field_ident, list_sort_order_ident,
    option_u32_tokens,
    optional_policy_source_value,
    policy_plan_enum_tokens, policy_plan_ident, policy_plan_method_tokens,
    policy_source_value,
    resource_action_handler_tokens,
    role_guard,
    structured_scalar_to_text_tokens,
    typed_object_normalizer_defs,
    update_normalization_tokens,
    update_payload_fields, update_payload_type,
    update_validation_tokens,
};

pub(super) fn resource_impl_tokens(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    authorization: Option<&AuthorizationContract>,
    runtime_crate: &Path,
) -> TokenStream {
    let struct_ident = &resource.struct_ident;
    let table_name = &resource.table_name;
    let resource_api_name = Literal::string(resource.api_name());
    let id_field = &resource.id_field;
    let read_requires_auth = super::super::model::read_requires_auth(resource);
    let create_payload_ty = create_payload_type(resource);
    let update_payload_ty = update_payload_type(resource);
    let list_query_ty = list_query_type(resource);
    let list_bind_ty = list_bind_type(resource);
    let list_plan_ty = list_plan_type(resource);
    let list_response_ty = list_response_type(resource);
    let list_response_struct_ident = list_response_ident(resource);
    let default_limit_tokens = option_u32_tokens(resource.list.default_limit);
    let max_limit_tokens = option_u32_tokens(resource.list.max_limit);
    let default_response_context_tokens = resource
        .default_response_context
        .as_deref()
        .map(Literal::string)
        .map(|context| quote!(Some(#context)))
        .unwrap_or_else(|| quote!(None));
    let supports_direct_json_responses = resource.computed_fields.is_empty()
        && resource.response_contexts.is_empty()
        && resource.default_response_context.is_none();
    let response_context_match_arms = resource.response_contexts.iter().map(|context| {
        let name = Literal::string(&context.name);
        let fields = context.fields.iter().map(|field| Literal::string(field));
        quote! {
            Some(#name) => Ok(Some(&[#(#fields),*])),
        }
    });
    let object_normalizer_defs = typed_object_normalizer_defs(resource, runtime_crate);
    let computed_field_insertions = resource.computed_fields.iter().map(|field| {
        let api_name = Literal::string(&field.api_name);
        let parts = field.parts.iter().map(|part| match part {
            super::super::model::ComputedFieldPart::Literal(value) => {
                if value.chars().count() == 1 {
                    let ch = Literal::character(value.chars().next().expect("single-char literal"));
                    quote! {
                        if !missing {
                            rendered.push(#ch);
                        }
                    }
                } else {
                    let value = Literal::string(value);
                    quote! {
                        if !missing {
                            rendered.push_str(#value);
                        }
                    }
                }
            }
            super::super::model::ComputedFieldPart::Field(name) => {
                let name = Literal::string(name);
                quote! {
                    if !missing {
                        match object.get(#name) {
                            Some(#runtime_crate::serde_json::Value::Null) | None => {
                                missing = true;
                            }
                            Some(#runtime_crate::serde_json::Value::String(value)) => {
                                rendered.push_str(value);
                            }
                            Some(#runtime_crate::serde_json::Value::Number(value)) => {
                                rendered.push_str(&value.to_string());
                            }
                            Some(#runtime_crate::serde_json::Value::Bool(value)) => {
                                rendered.push_str(&value.to_string());
                            }
                            Some(_) => {
                                missing = true;
                            }
                        }
                    }
                }
            }
        });
        quote! {
            {
                let mut rendered = String::new();
                let mut missing = false;
                #(#parts)*
                object.insert(
                    #api_name.to_owned(),
                    if missing {
                        #runtime_crate::serde_json::Value::Null
                    } else {
                        #runtime_crate::serde_json::Value::String(rendered)
                    },
                );
            }
        }
    });
    let item_ok_response_body = if supports_direct_json_responses {
        quote! {
            match Self::response_context_fields(requested) {
                Ok(_) => HttpResponse::Ok().json(item),
                Err(response) => response,
            }
        }
    } else {
        quote! {
            match Self::serialize_item_response(item, requested) {
                Ok(value) => HttpResponse::Ok().json(value),
                Err(response) => response,
            }
        }
    };
    let item_created_response_body = if supports_direct_json_responses {
        quote! {
            match Self::response_context_fields(requested) {
                Ok(_) => HttpResponse::Created()
                    .append_header(("Location", Self::created_location(req, id)))
                    .json(item),
                Err(response) => response,
            }
        }
    } else {
        quote! {
            match Self::serialize_item_response(item, requested) {
                Ok(value) => HttpResponse::Created()
                    .append_header(("Location", Self::created_location(req, id)))
                    .json(value),
                Err(response) => response,
            }
        }
    };
    let list_ok_response_body = if supports_direct_json_responses {
        quote! {
            match Self::response_context_fields(requested) {
                Ok(_) => HttpResponse::Ok().json(response),
                Err(response) => response,
            }
        }
    } else {
        quote! {
            match Self::serialize_list_response(response, requested) {
                Ok(value) => HttpResponse::Ok().json(value),
                Err(response) => response,
            }
        }
    };
    let allow_dead_serialize_helpers = if supports_direct_json_responses {
        quote!(#[allow(dead_code)])
    } else {
        quote!()
    };
    let create_check = role_guard(runtime_crate, resource.roles.create.as_deref());
    let read_check = role_guard(runtime_crate, resource.roles.read.as_deref());
    let update_check = role_guard(runtime_crate, resource.roles.update.as_deref());
    let delete_check = role_guard(runtime_crate, resource.roles.delete.as_deref());
    let create_normalization = create_normalization_tokens(resource, authorization);
    let update_normalization = update_normalization_tokens(resource);
    let garde_error_helper = garde_validation_error_helper(resource);
    let create_garde_validation = if create_payload_fields(resource, authorization).is_empty() {
        quote! {}
    } else {
        garde_validate_item_tokens(&garde_error_helper, runtime_crate)
    };
    let update_garde_validation = if update_payload_fields(resource).is_empty() {
        quote! {}
    } else {
        garde_validate_item_tokens(&garde_error_helper, runtime_crate)
    };
    let create_validation = create_validation_tokens(resource, authorization, runtime_crate);
    let update_validation = update_validation_tokens(resource, runtime_crate);
    let create_payload_is_used = !create_payload_fields(resource, authorization).is_empty()
        || !create_normalization.is_empty()
        || !create_validation.is_empty()
        || resource.policies.has_create_require_filters();
    let update_payload_is_used = !update_payload_fields(resource).is_empty()
        || !update_normalization.is_empty()
        || !update_validation.is_empty();
    let create_payload_binding = if !create_payload_is_used {
        quote!(let _ = item.into_inner();)
    } else if create_normalization.is_empty() {
        quote!(let item = item.into_inner();)
    } else {
        quote!(let mut item = item.into_inner();)
    };
    let update_payload_binding = if !update_payload_is_used {
        quote!(let _ = item.into_inner();)
    } else if update_normalization.is_empty() {
        quote!(let item = item.into_inner();)
    } else {
        quote!(let mut item = item.into_inner();)
    };
    let is_admin = quote! { user.roles.iter().any(|candidate| candidate == "admin") };
    let admin_bypass = resource.policies.admin_bypass;
    let hybrid = hybrid_resource_enforcement(resource, authorization);
    let hybrid_create_scope_field = hybrid
        .filter(|config| config.create_payload)
        .map(|config| config.scope_field.name());

    let insert_fields = insert_fields(resource);
    let insert_fields_csv = insert_fields
        .iter()
        .map(|field| field.name())
        .collect::<Vec<_>>()
        .join(", ");
    let insert_placeholders = insert_fields
        .iter()
        .enumerate()
        .map(|(index, _)| resource.db.placeholder(index + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let bind_fields_insert = insert_fields
        .iter()
        .map(|field| {
            let ident = &field.ident;
            let field_name = field.name();
            let api_field_name = field.api_name();
            if let Some(json_value) = json_bind_tokens(field, runtime_crate) {
                return quote! {
                    q = q.bind(#json_value);
                };
            }
            if let Some(source) = create_assignment_source(resource, &field_name) {
                if hybrid_create_scope_field.as_deref() == Some(field_name.as_str())
                    && matches!(source, PolicyValueSource::Claim(_))
                {
                    let value = optional_policy_source_value(source, field);
                    let field_name_lit = Literal::string(api_field_name);
                    quote! {
                        match #value {
                            Some(value) => {
                                q = q.bind(value);
                            }
                            None => match &item.#ident {
                                Some(value) => match Self::hybrid_create_allows_item_scope(
                                    &item,
                                    &user,
                                    runtime.get_ref(),
                                )
                                .await
                                {
                                    Ok(true) => {
                                        q = q.bind(value);
                                    }
                                    Ok(false) => {
                                        return #runtime_crate::core::errors::forbidden(
                                            "forbidden",
                                            format!(
                                                "Insufficient privileges for create scope field `{}`",
                                                #field_name_lit
                                            ),
                                        );
                                    }
                                    Err(response) => return response,
                                },
                                None => {
                                    return #runtime_crate::core::errors::validation_error(
                                        #field_name_lit,
                                        format!(
                                            "Missing required create field `{}`",
                                            #field_name_lit
                                        ),
                                    );
                                }
                            },
                        }
                    }
                } else {
                    let value = policy_source_value(source, field, runtime_crate);
                    quote! {
                        q = q.bind(#value);
                    }
                }
            } else {
                let bind_value = bind_field_value_tokens(field, quote!(item.#ident));
                quote! {
                    q = q.bind(#bind_value);
                }
            }
        })
        .collect::<Vec<_>>();
    let bind_fields_insert_admin = insert_fields
        .iter()
        .map(|field| {
            let ident = &field.ident;
            let field_name = field.name();
            let api_field_name = field.api_name();
            if let Some(json_value) = json_bind_tokens(field, runtime_crate) {
                return quote! {
                    q = q.bind(#json_value);
                };
            }
            if let Some(source) = create_assignment_source(resource, &field_name) {
                match source {
                    PolicyValueSource::Claim(_) => {
                        let value = optional_policy_source_value(source, field);
                        let field_name_lit = Literal::string(api_field_name);
                        quote! {
                            match &item.#ident {
                                Some(value) => {
                                    q = q.bind(value);
                                }
                                None => match #value {
                                    Some(value) => {
                                        q = q.bind(value);
                                    }
                                    None => {
                                        return #runtime_crate::core::errors::validation_error(
                                            #field_name_lit,
                                            format!("Missing required create field `{}`", #field_name_lit),
                                        );
                                    }
                                },
                            }
                        }
                    }
                    PolicyValueSource::UserId => {
                        let value = policy_source_value(source, field, runtime_crate);
                        quote! {
                            q = q.bind(#value);
                        }
                    }
                    PolicyValueSource::InputField(_) => {
                        panic!("validated create assignments cannot use input sources")
                    }
                }
            } else {
                let bind_value = bind_field_value_tokens(field, quote!(item.#ident));
                quote! {
                    q = q.bind(#bind_value);
                }
            }
        })
        .collect::<Vec<_>>();

    let update_plan = build_update_plan(resource);
    let update_sql = update_plan
        .clauses
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let update_where_index = Literal::usize_unsuffixed(update_plan.where_index);
    let update_policy_start_index = Literal::usize_unsuffixed(update_plan.where_index + 1);
    let bind_fields_update = update_plan
        .bind_fields
        .iter()
        .map(|ident| {
            let field = resource
                .fields
                .iter()
                .find(|field| field.ident == *ident)
                .expect("update field should exist");
            if let Some(json_value) = json_bind_tokens(field, runtime_crate) {
                quote! {
                    q = q.bind(#json_value);
                }
            } else {
                let bind_value = bind_field_value_tokens(field, quote!(item.#ident));
                quote! {
                    q = q.bind(#bind_value);
                }
            }
        })
        .collect::<Vec<_>>();
    let list_placeholder_body = match resource.db {
        super::super::model::DbBackend::Postgres => quote!(format!("${index}")),
        super::super::model::DbBackend::Sqlite | super::super::model::DbBackend::Mysql => {
            quote!({
                let _ = index;
                "?".to_owned()
            })
        }
    };
    let query_filter_conditions = list_query_condition_tokens(resource, runtime_crate);
    let list_bind_matches = list_bind_match_tokens(resource, resources, "q");
    let count_bind_matches = list_bind_match_tokens(resource, resources, "count_query");
    let query_bind_matches = list_bind_match_tokens(resource, resources, "q");
    let has_static_policy_filters = resource.policies.has_read_filters()
        || resource.policies.has_update_filters()
        || resource.policies.has_delete_filters();
    let policy_plan_enum = if has_static_policy_filters {
        policy_plan_enum_tokens(resource)
    } else {
        quote!()
    };
    let policy_plan_methods = if has_static_policy_filters {
        policy_plan_method_tokens(resource, resources, runtime_crate)
    } else {
        quote!()
    };
    let create_requirement_methods =
        create_requirement_method_tokens(resource, resources, authorization, runtime_crate);
    let next_list_placeholder_helper =
        if has_static_policy_filters || resource.policies.has_create_require_filters() {
            quote! {
                fn take_list_placeholder(next_index: &mut usize) -> String {
                    let placeholder = Self::list_placeholder(*next_index);
                    *next_index += 1;
                    placeholder
                }
            }
        } else {
            quote!()
        };
    let read_policy_list_conditions = if resource.policies.has_read_filters() {
        let plan_ident = policy_plan_ident(resource);
        quote! {
            match Self::read_policy_plan(user, filter_binds.len() + 1) {
                #plan_ident::Resolved { condition, binds } => {
                    conditions.push(condition);
                    filter_binds.extend(binds);
                }
                #plan_ident::Indeterminate => {
                    return Err(#runtime_crate::core::errors::forbidden(
                        "missing_claim",
                        "Missing required principal values for row policy",
                    ));
                }
            }
        }
    } else {
        quote!()
    };
    let apply_read_policy_list_conditions = if resource.policies.has_read_filters() {
        if admin_bypass {
            quote! {
                if !skip_static_read_policy && !is_admin {
                    #read_policy_list_conditions
                }
            }
        } else {
            quote! {
                if !skip_static_read_policy {
                    #read_policy_list_conditions
                }
            }
        }
    } else {
        quote!()
    };
    let skip_static_read_policy_usage = if resource.policies.has_read_filters() {
        quote!()
    } else {
        quote!(let _ = skip_static_read_policy;)
    };
    let user_usage = if resource.policies.has_read_filters() {
        quote!()
    } else {
        quote!(let _ = user;)
    };
    let is_admin_binding = if resource.policies.has_read_filters() && admin_bypass {
        quote!(let is_admin = #is_admin;)
    } else {
        quote!()
    };
    let create_admin_override =
        resource.policies.admin_bypass && !resource.policies.create.is_empty();
    let create_require_runtime = if hybrid.map(|config| config.create_payload).unwrap_or(false) {
        quote!(Some(runtime.get_ref()))
    } else {
        quote!(None)
    };
    let create_require_check = if resource.policies.has_create_require_filters() {
        quote! {
            match Self::create_require_matches(
                &item,
                &user,
                db.get_ref(),
                #create_require_runtime,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return #runtime_crate::core::errors::forbidden(
                        "forbidden",
                        "Create requirement conditions did not match",
                    );
                }
                Err(response) => return response,
            }
        }
    } else {
        quote!()
    };
    let create_insert_binds = if create_admin_override {
        quote! {
            if #is_admin {
                #(#bind_fields_insert_admin)*
            } else {
                #(#bind_fields_insert)*
            }
        }
    } else {
        quote! {
            #(#bind_fields_insert)*
        }
    };
    let contains_filter_helper = if resource
        .api_fields()
        .any(super::super::model::supports_contains_filters)
    {
        quote! {
            fn list_contains_pattern(value: &str) -> String {
                let lowered = value.to_lowercase();
                let mut pattern = String::with_capacity(lowered.len() + 2);
                pattern.push('%');
                for ch in lowered.chars() {
                    match ch {
                        '%' | '_' | '\\' => {
                            pattern.push('\\');
                            pattern.push(ch);
                        }
                        _ => pattern.push(ch),
                    }
                }
                pattern.push('%');
                pattern
            }
        }
    } else {
        quote! {}
    };
    let anonymous_user_context_fn = if read_requires_auth {
        quote! {}
    } else {
        quote! {
            fn anonymous_user_context() -> #runtime_crate::core::auth::UserContext {
                #runtime_crate::core::auth::UserContext {
                    id: 0,
                    roles: Vec::new(),
                    claims: ::std::collections::BTreeMap::new(),
                }
            }
        }
    };
    let sort_field_ty = {
        let ident = list_sort_field_ident(resource);
        quote!(#ident)
    };
    let sort_order_ty = {
        let ident = list_sort_order_ident(resource);
        quote!(#ident)
    };
    let cursor_value_ty = {
        let ident = list_cursor_value_ident(resource);
        quote!(#ident)
    };
    let cursor_payload_ty = {
        let ident = list_cursor_payload_ident(resource);
        quote!(#ident)
    };
    let id_field_spec = resource
        .find_field(id_field)
        .expect("resource id field should exist");
    let id_field_ident = &id_field_spec.ident;
    let id_field_name_lit = Literal::string(id_field);
    let id_field_api_name_lit = Literal::string(id_field_spec.api_name());
    let id_to_i64 = integer_to_i64_tokens(&id_field_spec.ty, quote!(value));
    let item_id_to_i64 = integer_to_i64_tokens(&id_field_spec.ty, quote!(item.#id_field_ident));
    let cursor_id_for_item_body = if super::super::model::is_optional_type(&id_field_spec.ty) {
        quote! {
            match item.#id_field_ident {
                Some(value) => Ok(#id_to_i64),
                None => Err(#runtime_crate::core::errors::internal_error(
                    format!("Cannot build cursor for `{}` without a persisted id", #id_field_api_name_lit),
                )),
            }
        }
    } else {
        quote! {
            Ok(#item_id_to_i64)
        }
    };
    let default_sort_variant =
        super::super::model::sanitize_struct_ident(&id_field_spec.name(), id_field_spec.ident.span());
    let sortable_fields = resource
        .api_fields()
        .filter(|field| field_supports_sort(field))
        .collect::<Vec<_>>();
    let cursor_support_arms = sortable_fields.iter().map(|field| {
        let variant_ident = super::super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let supported =
            field.name() == resource.id_field || !super::super::model::is_optional_type(&field.ty);
        quote! {
            #sort_field_ty::#variant_ident => #supported,
        }
    });
    let cursor_value_for_item_arms = sortable_fields.iter().map(|field| {
        let variant_ident = super::super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let ident = &field.ident;
        let field_name_lit = Literal::string(field.api_name());
        if field.name() == resource.id_field {
            if super::super::model::is_optional_type(&field.ty) {
                let value_to_i64 = integer_to_i64_tokens(&field.ty, quote!(value));
                quote! {
                    #sort_field_ty::#variant_ident => match item.#ident {
                        Some(value) => Ok(#cursor_value_ty::Integer(#value_to_i64)),
                        None => Err(#runtime_crate::core::errors::internal_error(
                            format!("Cannot build cursor for `{}` without a persisted id", #field_name_lit),
                        )),
                    },
                }
            } else {
                let item_value_to_i64 = integer_to_i64_tokens(&field.ty, quote!(item.#ident));
                quote! {
                    #sort_field_ty::#variant_ident => Ok(#cursor_value_ty::Integer(#item_value_to_i64)),
                }
            }
        } else if super::super::model::is_optional_type(&field.ty) {
            quote! {
                #sort_field_ty::#variant_ident => Err(#runtime_crate::core::errors::bad_request(
                    "invalid_cursor",
                    format!("Cursor pagination does not support nullable sort field `{}`", #field_name_lit),
                )),
            }
        } else {
            if let Some(text_value) =
                structured_scalar_to_text_tokens(&field.ty, quote!((&item.#ident)), runtime_crate)
            {
                quote! {
                    #sort_field_ty::#variant_ident => Ok(#cursor_value_ty::Text(#text_value)),
                }
            } else {
                if super::super::model::is_bool_type(&field.ty) {
                    quote! {
                        #sort_field_ty::#variant_ident => Ok(#cursor_value_ty::Boolean(item.#ident)),
                    }
                } else {
                    match field.sql_type.as_str() {
                    sql_type if super::super::model::is_integer_sql_type(sql_type) => {
                        let item_value_to_i64 = integer_to_i64_tokens(&field.ty, quote!(item.#ident));
                        quote! {
                            #sort_field_ty::#variant_ident => Ok(#cursor_value_ty::Integer(#item_value_to_i64)),
                        }
                    }
                    "REAL" => quote! {
                        #sort_field_ty::#variant_ident => Ok(#cursor_value_ty::Real(item.#ident as f64)),
                    },
                    _ => quote! {
                        #sort_field_ty::#variant_ident => Ok(#cursor_value_ty::Text(item.#ident.clone())),
                    },
                }
                }
            }
        }
    });
    let cursor_condition_arms = sortable_fields.iter().map(|field| {
        let variant_ident = super::super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name_lit = Literal::string(field.api_name());
        let field_column_lit = Literal::string(&field.name());
        if field.name() == resource.id_field {
            quote! {
                #sort_field_ty::#variant_ident => match &cursor_payload.value {
                    #cursor_value_ty::Integer(_) => {
                        let placeholder = Self::list_placeholder(
                            filter_binds.len() + select_only_binds.len() + 1
                        );
                        select_only_conditions.push(format!(
                            "{} {} {}",
                            #field_column_lit,
                            comparator,
                            placeholder
                        ));
                        select_only_binds.push(#list_bind_ty::Integer(cursor_payload.last_id));
                    }
                    _ => {
                        return Err(#runtime_crate::core::errors::bad_request(
                            "invalid_cursor",
                            "Cursor does not match the current sort field",
                        ));
                    }
                },
            }
        } else if super::super::model::is_optional_type(&field.ty) {
            quote! {
                #sort_field_ty::#variant_ident => {
                    return Err(#runtime_crate::core::errors::bad_request(
                        "invalid_cursor",
                        format!("Cursor pagination does not support nullable sort field `{}`", #field_name_lit),
                    ));
                }
            }
        } else {
            let bind_push = if super::super::model::is_bool_type(&field.ty) {
                quote! {
                    #cursor_value_ty::Boolean(value) => {
                        select_only_binds.push(#list_bind_ty::Boolean(*value));
                        select_only_binds.push(#list_bind_ty::Boolean(*value));
                    }
                }
            } else {
                match field.sql_type.as_str() {
                sql_type if super::super::model::is_integer_sql_type(sql_type) => quote! {
                    #cursor_value_ty::Integer(value) => {
                        select_only_binds.push(#list_bind_ty::Integer(*value));
                        select_only_binds.push(#list_bind_ty::Integer(*value));
                    }
                },
                "REAL" => quote! {
                    #cursor_value_ty::Real(value) => {
                        select_only_binds.push(#list_bind_ty::Real(*value));
                        select_only_binds.push(#list_bind_ty::Real(*value));
                    }
                },
                _ => quote! {
                    #cursor_value_ty::Text(value) => {
                        select_only_binds.push(#list_bind_ty::Text(value.clone()));
                        select_only_binds.push(#list_bind_ty::Text(value.clone()));
                    }
                },
                }
            };
            quote! {
                #sort_field_ty::#variant_ident => {
                    let first_index = filter_binds.len() + select_only_binds.len() + 1;
                    let first = Self::list_placeholder(first_index);
                    let second = Self::list_placeholder(first_index + 1);
                    let third = Self::list_placeholder(first_index + 2);
                    select_only_conditions.push(format!(
                        "(({} {} {}) OR ({} = {} AND {} {} {}))",
                        #field_column_lit,
                        comparator,
                        first,
                        #field_column_lit,
                        second,
                        #id_field_name_lit,
                        comparator,
                        third
                    ));
                    match &cursor_payload.value {
                        #bind_push
                        _ => {
                            return Err(#runtime_crate::core::errors::bad_request(
                                "invalid_cursor",
                                "Cursor does not match the current sort field",
                            ));
                        }
                    }
                    select_only_binds.push(#list_bind_ty::Integer(cursor_payload.last_id));
                }
            }
        }
    });

    let can_read_body = match resource.roles.read.as_deref() {
        Some("admin") => quote! {
            user.roles.iter().any(|candidate| candidate == "admin")
        },
        Some(role) => quote! {
            user.roles
                .iter()
                .any(|candidate| candidate == "admin" || candidate == #role)
        },
        None => quote!(true),
    };
    let hybrid_configure_app_data = if hybrid.is_some() {
        quote! {
            cfg.app_data(web::Data::new(authorization_runtime(db.get_ref().clone())));
        }
    } else {
        quote!()
    };
    let hybrid_helper_tokens = if let Some(hybrid) = hybrid {
        let scope_name = Literal::string(hybrid.scope);
        let resource_name = Literal::string(&resource.struct_ident.to_string());
        let scope_field_ident = &hybrid.scope_field.ident;
        let scope_field_name = Literal::string(&hybrid.scope_field.name());
        let scope_query_filter_ident = format_ident!("filter_{}", scope_field_ident);
        let scope_value = match super::super::model::policy_field_claim_type(&hybrid.scope_field.ty)
            .unwrap_or_else(|| panic!("validated hybrid scope field type is unsupported"))
        {
            crate::auth::AuthClaimType::I64 => {
                if super::super::model::is_optional_type(&hybrid.scope_field.ty) {
                    quote!(item.#scope_field_ident.map(|value| value.to_string()))
                } else {
                    quote!(Some(item.#scope_field_ident.to_string()))
                }
            }
            crate::auth::AuthClaimType::Bool => {
                if super::super::model::is_optional_type(&hybrid.scope_field.ty) {
                    quote!(item.#scope_field_ident.map(|value| value.to_string()))
                } else {
                    quote!(Some(item.#scope_field_ident.to_string()))
                }
            }
            crate::auth::AuthClaimType::String => {
                if super::super::model::is_optional_type(&hybrid.scope_field.ty) {
                    quote!(item.#scope_field_ident.clone())
                } else {
                    quote!(Some(item.#scope_field_ident.clone()))
                }
            }
        };
        let hybrid_item_read = hybrid.item_read;
        let hybrid_collection_read = hybrid.collection_read;
        let hybrid_nested_read = hybrid.nested_read;
        let hybrid_create = hybrid.create_payload;
        let hybrid_update = hybrid.update;
        let hybrid_delete = hybrid.delete;
        let list_scope_value = match super::super::model::policy_field_claim_type(&hybrid.scope_field.ty)
            .unwrap_or_else(|| panic!("validated hybrid scope field type is unsupported"))
        {
            crate::auth::AuthClaimType::I64 | crate::auth::AuthClaimType::Bool => {
                quote!(query.#scope_query_filter_ident.map(|value| value.to_string()))
            }
            crate::auth::AuthClaimType::String => {
                quote!(query.#scope_query_filter_ident.clone())
            }
        };
        let hybrid_create_scope_tokens = if hybrid_create {
            let create_scope_value =
                match super::super::model::policy_field_claim_type(&hybrid.scope_field.ty)
                    .unwrap_or_else(|| panic!("validated hybrid scope field type is unsupported"))
                {
                    crate::auth::AuthClaimType::I64 | crate::auth::AuthClaimType::Bool => {
                        quote!(item.#scope_field_ident.map(|value| value.to_string()))
                    }
                    crate::auth::AuthClaimType::String => {
                        quote!(item.#scope_field_ident.clone())
                    }
                };
            quote! {
                fn hybrid_scope_binding_for_create_item(
                    item: &#create_payload_ty,
                ) -> Option<#runtime_crate::core::authorization::AuthorizationScopeBinding> {
                    let value = #create_scope_value;
                    value.map(|value| #runtime_crate::core::authorization::AuthorizationScopeBinding {
                        scope: #scope_name.to_owned(),
                        value,
                    })
                }

                async fn hybrid_create_allows_item_scope(
                    item: &#create_payload_ty,
                    user: &#runtime_crate::core::auth::UserContext,
                    runtime: &#runtime_crate::core::authorization::AuthorizationRuntime,
                ) -> Result<bool, HttpResponse> {
                    if !Self::hybrid_runtime_supports_action(
                        #runtime_crate::core::authorization::AuthorizationAction::Create,
                    ) {
                        return Ok(false);
                    }
                    let Some(scope) = Self::hybrid_scope_binding_for_create_item(item) else {
                        return Ok(false);
                    };
                    match runtime
                        .evaluate_runtime_access_for_user(
                            user.id,
                            #resource_name,
                            #runtime_crate::core::authorization::AuthorizationAction::Create,
                            scope,
                        )
                        .await
                    {
                        Ok(result) => Ok(result.allowed),
                        Err(message) => Err(#runtime_crate::core::errors::internal_error(message)),
                    }
                }
            }
        } else {
            quote!()
        };
        let hybrid_list_scope_tokens = if hybrid_collection_read || hybrid_nested_read {
            quote! {
                fn hybrid_scope_binding_for_list_request(
                    query: &#list_query_ty,
                    parent_filter: Option<(&'static str, i64)>,
                ) -> Option<#runtime_crate::core::authorization::AuthorizationScopeBinding> {
                    if let Some((field_name, value)) = parent_filter
                        && field_name == #scope_field_name
                    {
                        return Some(#runtime_crate::core::authorization::AuthorizationScopeBinding {
                            scope: #scope_name.to_owned(),
                            value: value.to_string(),
                        });
                    }
                    let value = #list_scope_value;
                    value.map(|value| #runtime_crate::core::authorization::AuthorizationScopeBinding {
                        scope: #scope_name.to_owned(),
                        value,
                    })
                }

                async fn build_list_plan_with_hybrid_read(
                    query: &#list_query_ty,
                    user: &#runtime_crate::core::auth::UserContext,
                    runtime: &#runtime_crate::core::authorization::AuthorizationRuntime,
                    parent_filter: Option<(&'static str, i64)>,
                ) -> Result<#list_plan_ty, HttpResponse> {
                    let mut skip_static_read_policy = false;
                    if let Some(scope) = Self::hybrid_scope_binding_for_list_request(query, parent_filter) {
                        match runtime
                            .evaluate_runtime_access_for_user(
                                user.id,
                                #resource_name,
                                #runtime_crate::core::authorization::AuthorizationAction::Read,
                                scope,
                            )
                            .await
                        {
                            Ok(result) if result.allowed => {
                                skip_static_read_policy = true;
                            }
                            Ok(_) => {}
                            Err(message) => {
                                return Err(#runtime_crate::core::errors::internal_error(message));
                            }
                        }
                    }
                    Self::build_list_plan_internal(
                        query,
                        user,
                        parent_filter,
                        None,
                        skip_static_read_policy,
                    )
                }

                #[allow(dead_code)]
                async fn build_many_to_many_list_plan_with_hybrid_read(
                    query: &#list_query_ty,
                    user: &#runtime_crate::core::auth::UserContext,
                    runtime: &#runtime_crate::core::authorization::AuthorizationRuntime,
                    through_table: &'static str,
                    source_field: &'static str,
                    target_field: &'static str,
                    parent_id: i64,
                ) -> Result<#list_plan_ty, HttpResponse> {
                    let mut skip_static_read_policy = false;
                    if let Some(scope) = Self::hybrid_scope_binding_for_list_request(query, None) {
                        match runtime
                            .evaluate_runtime_access_for_user(
                                user.id,
                                #resource_name,
                                #runtime_crate::core::authorization::AuthorizationAction::Read,
                                scope,
                            )
                            .await
                        {
                            Ok(result) if result.allowed => {
                                skip_static_read_policy = true;
                            }
                            Ok(_) => {}
                            Err(message) => {
                                return Err(#runtime_crate::core::errors::internal_error(message));
                            }
                        }
                    }
                    Self::build_list_plan_internal(
                        query,
                        user,
                        None,
                        Some((through_table, source_field, target_field, parent_id)),
                        skip_static_read_policy,
                    )
                }
            }
        } else {
            quote!()
        };
        quote! {
            fn hybrid_runtime_supports_action(
                action: #runtime_crate::core::authorization::AuthorizationAction,
            ) -> bool {
                match action {
                    #runtime_crate::core::authorization::AuthorizationAction::Read => #hybrid_item_read,
                    #runtime_crate::core::authorization::AuthorizationAction::Create => #hybrid_create,
                    #runtime_crate::core::authorization::AuthorizationAction::Update => #hybrid_update,
                    #runtime_crate::core::authorization::AuthorizationAction::Delete => #hybrid_delete,
                }
            }

            async fn fetch_by_id_unfiltered(
                id: i64,
                db: &DbPool,
            ) -> Result<Option<Self>, #runtime_crate::sqlx::Error> {
                let sql = format!("SELECT * FROM {} WHERE {} = {}", #table_name, #id_field, Self::list_placeholder(1));
                #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&sql)
                    .bind(id)
                    .fetch_optional(db)
                    .await
            }

            fn hybrid_scope_binding_for_item(
                item: &Self,
            ) -> Option<#runtime_crate::core::authorization::AuthorizationScopeBinding> {
                let value = #scope_value;
                value.map(|value| #runtime_crate::core::authorization::AuthorizationScopeBinding {
                    scope: #scope_name.to_owned(),
                    value,
                })
            }

            #hybrid_create_scope_tokens
            #hybrid_list_scope_tokens

            async fn fetch_runtime_authorized_by_id(
                id: i64,
                user: &#runtime_crate::core::auth::UserContext,
                runtime: &#runtime_crate::core::authorization::AuthorizationRuntime,
                db: &DbPool,
                action: #runtime_crate::core::authorization::AuthorizationAction,
            ) -> Result<Option<Self>, HttpResponse> {
                if !Self::hybrid_runtime_supports_action(action) {
                    return Ok(None);
                }
                let item = Self::fetch_by_id_unfiltered(id, db)
                    .await
                    .map_err(|error| #runtime_crate::core::errors::internal_error(error.to_string()))?;
                let Some(item) = item else {
                    return Ok(None);
                };
                let Some(scope) = Self::hybrid_scope_binding_for_item(&item) else {
                    return Ok(None);
                };
                match runtime
                    .evaluate_runtime_access_for_user(user.id, #resource_name, action, scope)
                    .await
                {
                    Ok(result) if result.allowed => Ok(Some(item)),
                    Ok(_) => Ok(None),
                    Err(message) => Err(#runtime_crate::core::errors::internal_error(message)),
                }
            }
        }
    } else {
        quote!()
    };
    let fetch_readable_by_id_body = if !resource.policies.has_read_filters() {
        let id_placeholder = resource.db.placeholder(1);
        quote! {
            if !Self::can_read(user) {
                return Ok(None);
            }

            let sql = format!("SELECT * FROM {} WHERE {} = {}", #table_name, #id_field, #id_placeholder);
            #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&sql)
                .bind(id)
                .fetch_optional(db)
                .await
        }
    } else {
        let id_placeholder = resource.db.placeholder(1);
        let plan_ident = policy_plan_ident(resource);
        let filtered_read = quote! {
            match Self::read_policy_plan(user, 2) {
                #plan_ident::Resolved { condition, binds } => {
                    let filtered_sql = format!(
                        "SELECT * FROM {} WHERE {} = {} AND {}",
                        #table_name,
                        #id_field,
                        #id_placeholder,
                        condition
                    );
                    let mut q = #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&filtered_sql)
                        .bind(id);
                    for bind in binds {
                        q = match bind {
                            #(#query_bind_matches)*
                        };
                    }
                    q.fetch_optional(db).await
                }
                #plan_ident::Indeterminate => Ok(None),
            }
        };
        if admin_bypass {
            quote! {
                if !Self::can_read(user) {
                    return Ok(None);
                }

                let sql = format!("SELECT * FROM {} WHERE {} = {}", #table_name, #id_field, #id_placeholder);

                if #is_admin {
                    #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&sql)
                        .bind(id)
                        .fetch_optional(db)
                        .await
                } else {
                    #filtered_read
                }
            }
        } else {
            quote! {
                if !Self::can_read(user) {
                    return Ok(None);
                }

                #filtered_read
            }
        }
    };

    let get_one_body = quote! {
        let response_context = match Self::request_response_context(&req) {
            Ok(context) => context,
            Err(response) => return response,
        };
        match Self::fetch_readable_by_id(path.into_inner(), &user, db.get_ref()).await {
            Ok(Some(item)) => Self::item_ok_response(&item, response_context.as_deref()),
            Ok(None) => #runtime_crate::core::errors::not_found("Not found"),
            Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
        }
    };
    let created_response_fallback = if hybrid.map(|config| config.item_read).unwrap_or(false) {
        quote! {
            if let Some(runtime) = runtime {
                match Self::fetch_runtime_authorized_by_id(
                    id,
                    user,
                    runtime,
                    db,
                    #runtime_crate::core::authorization::AuthorizationAction::Read,
                )
                .await
                {
                    Ok(Some(item)) => {
                        Self::item_created_response(&item, req, id, response_context.as_deref())
                    }
                    Ok(None) => HttpResponse::Created().finish(),
                    Err(response) => response,
                }
            } else {
                HttpResponse::Created().finish()
            }
        }
    } else {
        quote!(HttpResponse::Created().finish())
    };
    let created_response_runtime = if hybrid
        .map(|config| config.item_read || config.create_payload)
        .unwrap_or(false)
    {
        quote!(Some(runtime.get_ref()))
    } else {
        quote!(None)
    };

    let create_body = match (resource.db, insert_fields.is_empty()) {
        (super::super::model::DbBackend::Postgres | super::super::model::DbBackend::Sqlite, true) => {
            quote! {
                let sql = format!("INSERT INTO {} DEFAULT VALUES RETURNING {}", #table_name, #id_field);
                match #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&sql)
                    .fetch_one(db.get_ref())
                    .await
                {
                    Ok(created_id) => Self::created_response(created_id, &req, &user, db.get_ref(), #created_response_runtime).await,
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }
        }
        (super::super::model::DbBackend::Postgres | super::super::model::DbBackend::Sqlite, false) => {
            quote! {
                let sql = format!(
                    "INSERT INTO {} ({}) VALUES ({}) RETURNING {}",
                    #table_name,
                    #insert_fields_csv,
                    #insert_placeholders,
                    #id_field
                );
                let mut q = #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&sql);
                #create_insert_binds
                match q.fetch_one(db.get_ref()).await {
                    Ok(created_id) => Self::created_response(created_id, &req, &user, db.get_ref(), #created_response_runtime).await,
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }
        }
        (_, true) => {
            quote! {
                let sql = format!("INSERT INTO {} DEFAULT VALUES", #table_name);
                match #runtime_crate::db::query(&sql).execute(db.get_ref()).await {
                    Ok(result) => match result.last_insert_rowid() {
                        Some(created_id) => {
                            Self::created_response(created_id, &req, &user, db.get_ref(), #created_response_runtime).await
                        }
                        None => HttpResponse::Created().finish(),
                    },
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }
        }
        (_, false) => {
            quote! {
                let sql = format!("INSERT INTO {} ({}) VALUES ({})", #table_name, #insert_fields_csv, #insert_placeholders);
                let mut q = #runtime_crate::db::query(&sql);
                #create_insert_binds
                match q.execute(db.get_ref()).await {
                    Ok(result) => match result.last_insert_rowid() {
                        Some(created_id) => {
                            Self::created_response(created_id, &req, &user, db.get_ref(), #created_response_runtime).await
                        }
                        None => HttpResponse::Created().finish(),
                    },
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }
        }
    };

    let update_body = if update_plan.clauses.is_empty() {
        quote! {
            #runtime_crate::core::errors::bad_request(
                "no_updatable_fields",
                "No updatable fields configured",
            )
        }
    } else {
        if !resource.policies.has_update_filters() {
            let sql = format!(
                "UPDATE {} SET {} WHERE {} = {}",
                resource.table_name,
                update_sql,
                resource.id_field,
                resource.db.placeholder(update_plan.where_index)
            );

            quote! {
                let sql = #sql;
                let mut q = #runtime_crate::db::query(sql);
                #(#bind_fields_update)*
                q = q.bind(path.into_inner());
                match q.execute(db.get_ref()).await {
                    Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                    Ok(_) => HttpResponse::Ok().finish(),
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }
        } else {
            let plan_ident = policy_plan_ident(resource);
            let admin_sql = format!(
                "UPDATE {} SET {} WHERE {} = {}",
                resource.table_name,
                update_sql,
                resource.id_field,
                resource.db.placeholder(update_plan.where_index)
            );
            let hybrid_update_fallback = if hybrid.map(|config| config.update).unwrap_or(false) {
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
                            #(#bind_fields_update)*
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
                match Self::update_policy_plan(&user, #update_policy_start_index) {
                    #plan_ident::Resolved { condition, binds } => {
                        let sql = format!(
                            "UPDATE {} SET {} WHERE {} = {} AND {}",
                            #table_name,
                            #update_sql,
                            #id_field,
                            Self::list_placeholder(#update_where_index),
                            condition
                        );
                        let mut q = #runtime_crate::db::query(&sql);
                        #(#bind_fields_update)*
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
            if admin_bypass {
                quote! {
                    let id = path.into_inner();
                    if #is_admin {
                        let sql = #admin_sql;
                        let mut q = #runtime_crate::db::query(sql);
                        #(#bind_fields_update)*
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
                    #filtered_update
                }
            }
        }
    };

    let delete_body = if !resource.policies.has_delete_filters() {
        let id_placeholder = resource.db.placeholder(1);
        quote! {
            let sql = format!("DELETE FROM {} WHERE {} = {}", #table_name, #id_field, #id_placeholder);
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
    } else {
        let plan_ident = policy_plan_ident(resource);
        let admin_sql = format!(
            "DELETE FROM {} WHERE {} = {}",
            resource.table_name,
            resource.id_field,
            resource.db.placeholder(1)
        );
        let hybrid_delete_fallback = if hybrid.map(|config| config.delete).unwrap_or(false) {
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
                        match #runtime_crate::db::query(sql)
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
            match Self::delete_policy_plan(&user, 2) {
                #plan_ident::Resolved { condition, binds } => {
                    let sql = format!(
                        "DELETE FROM {} WHERE {} = {} AND {}",
                        #table_name,
                        #id_field,
                        Self::list_placeholder(1),
                        condition
                    );
                    let mut q = #runtime_crate::db::query(&sql);
                    q = q.bind(id);
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
        if admin_bypass {
            quote! {
                let id = path.into_inner();
                if #is_admin {
                    let sql = #admin_sql;
                    match #runtime_crate::db::query(sql)
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
        }
    };

    let relation_routes = resource.fields.iter().filter_map(|field| {
        field
            .relation
            .as_ref()
            .filter(|relation| relation.nested_route)
            .map(|relation| {
                let parent_api_name = resources
                    .iter()
                    .find(|candidate| candidate.table_name == relation.references_table)
                    .map(|candidate| candidate.api_name.clone())
                    .unwrap_or_else(|| relation.references_table.clone());
                (
                    field.ident.clone(),
                    relation.references_table.clone(),
                    parent_api_name,
                )
            })
    });
    let many_to_many_routes = resources
        .iter()
        .flat_map(|source_resource| {
            source_resource
                .many_to_many
                .iter()
                .filter(move |relation| relation.target_table == resource.table_name)
                .map(move |relation| {
                    (
                        format_ident!(
                            "list_by_{}_{}",
                            source_resource.struct_ident.to_string().to_snake_case(),
                            relation.name.to_snake_case()
                        ),
                        source_resource.api_name.clone(),
                        relation.name.clone(),
                        relation.through_table.clone(),
                        relation.source_field.clone(),
                        relation.target_field.clone(),
                    )
                })
        })
        .collect::<Vec<_>>();
    let many_to_many_list_plan_helper = if many_to_many_routes.is_empty() {
        quote!()
    } else {
        quote! {
            #[allow(dead_code)]
            fn build_many_to_many_list_plan(
                query: &#list_query_ty,
                user: &#runtime_crate::core::auth::UserContext,
                through_table: &'static str,
                source_field: &'static str,
                target_field: &'static str,
                parent_id: i64,
            ) -> Result<#list_plan_ty, HttpResponse> {
                Self::build_list_plan_internal(
                    query,
                    user,
                    None,
                    Some((through_table, source_field, target_field, parent_id)),
                    false,
                )
            }
        }
    };
    let nested_route_registrations = relation_routes
        .clone()
        .map(|(field_ident, _parent_table, parent_api_name)| {
        let handler_ident = format_ident!("get_by_{}", field_ident);
        let resource_api_name = Literal::string(resource.api_name());
        let parent_api_name = Literal::string(&parent_api_name);
        quote! {
            cfg.service(
                web::resource(format!("/{}/{{parent_id}}/{}", #parent_api_name, #resource_api_name))
                    .route(web::get().to(Self::#handler_ident))
            );
        }
    });
    let many_to_many_route_registrations = many_to_many_routes.iter().map(
        |(handler_ident, parent_api_name, relation_name, _, _, _)| {
            let parent_api_name = Literal::string(parent_api_name);
            let relation_name = Literal::string(relation_name);
            quote! {
                cfg.service(
                    web::resource(format!("/{}/{{parent_id}}/{}", #parent_api_name, #relation_name))
                        .route(web::get().to(Self::#handler_ident))
                );
            }
        },
    );
    let resource_action_route_registrations = resource.actions.iter().map(|action| {
        let handler_ident = format_ident!("action_{}", action.name.to_snake_case());
        let resource_api_name = Literal::string(resource.api_name());
        let action_path = Literal::string(&action.path);
        quote! {
            cfg.service(
                web::resource(format!("/{}/{{id}}/{}", #resource_api_name, #action_path))
                    .route(web::post().to(Self::#handler_ident))
            );
        }
    });
    let nested_handlers = relation_routes.map(|(field_ident, _, _)| {
        let handler_ident = format_ident!("get_by_{}", field_ident);
        if read_requires_auth {
            if hybrid.map(|config| config.nested_read).unwrap_or(false) {
                quote! {
                    async fn #handler_ident(
                        path: web::Path<i64>,
                        query: web::Query<#list_query_ty>,
                        user: #runtime_crate::core::auth::UserContext,
                        db: web::Data<DbPool>,
                        runtime: web::Data<#runtime_crate::core::authorization::AuthorizationRuntime>,
                    ) -> impl Responder {
                        #read_check

                        let parent_id = path.into_inner();
                        let query = query.into_inner();
                        let parent_filter = Some((stringify!(#field_ident), parent_id));
                        let plan = match Self::build_list_plan_with_hybrid_read(
                            &query,
                            &user,
                            runtime.get_ref(),
                            parent_filter,
                        )
                        .await
                        {
                            Ok(parts) => parts,
                            Err(response) => return response,
                        };
                        let mut count_query =
                            #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&plan.count_sql);
                        for bind in &plan.filter_binds {
                            count_query = match bind.clone() {
                                #(#count_bind_matches)*
                            };
                        }
                        let total = match count_query.fetch_one(db.get_ref()).await {
                            Ok(total) => total,
                            Err(error) => return #runtime_crate::core::errors::internal_error(error.to_string()),
                        };
                        let mut q = #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&plan.select_sql);
                        for bind in &plan.select_binds {
                            q = match bind.clone() {
                                #(#list_bind_matches)*
                            };
                        }
                        match q.fetch_all(db.get_ref()).await {
                            Ok(items) => match Self::finalize_list_response(plan, total, items) {
                                Ok(response) => Self::list_ok_response(response, query.context.as_deref()),
                                Err(response) => response,
                            },
                            Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                        }
                    }
                }
            } else {
                quote! {
                    async fn #handler_ident(
                        path: web::Path<i64>,
                        query: web::Query<#list_query_ty>,
                        user: #runtime_crate::core::auth::UserContext,
                        db: web::Data<DbPool>,
                    ) -> impl Responder {
                        #read_check

                        let parent_id = path.into_inner();
                        let query = query.into_inner();
                        let plan = match Self::build_list_plan(
                            &query,
                            &user,
                            Some((stringify!(#field_ident), parent_id)),
                        ) {
                            Ok(parts) => parts,
                            Err(response) => return response,
                        };
                        let mut count_query =
                            #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&plan.count_sql);
                        for bind in &plan.filter_binds {
                            count_query = match bind.clone() {
                                #(#count_bind_matches)*
                            };
                        }
                        let total = match count_query.fetch_one(db.get_ref()).await {
                            Ok(total) => total,
                            Err(error) => return #runtime_crate::core::errors::internal_error(error.to_string()),
                        };
                        let mut q = #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&plan.select_sql);
                        for bind in &plan.select_binds {
                            q = match bind.clone() {
                                #(#list_bind_matches)*
                            };
                        }
                        match q.fetch_all(db.get_ref()).await {
                            Ok(items) => match Self::finalize_list_response(plan, total, items) {
                                Ok(response) => Self::list_ok_response(response, query.context.as_deref()),
                                Err(response) => response,
                            },
                            Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                        }
                    }
                }
            }
        } else {
            quote! {
                async fn #handler_ident(
                    path: web::Path<i64>,
                    query: web::Query<#list_query_ty>,
                    db: web::Data<DbPool>,
                ) -> impl Responder {
                    let parent_id = path.into_inner();
                    let query = query.into_inner();
                    let user = Self::anonymous_user_context();
                    let plan = match Self::build_list_plan(
                        &query,
                        &user,
                        Some((stringify!(#field_ident), parent_id)),
                    ) {
                        Ok(parts) => parts,
                        Err(response) => return response,
                    };
                    let mut count_query =
                        #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&plan.count_sql);
                    for bind in &plan.filter_binds {
                        count_query = match bind.clone() {
                            #(#count_bind_matches)*
                        };
                    }
                    let total = match count_query.fetch_one(db.get_ref()).await {
                        Ok(total) => total,
                        Err(error) => return #runtime_crate::core::errors::internal_error(error.to_string()),
                    };
                    let mut q = #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&plan.select_sql);
                    for bind in &plan.select_binds {
                        q = match bind.clone() {
                            #(#list_bind_matches)*
                        };
                    }
                    match q.fetch_all(db.get_ref()).await {
                        Ok(items) => match Self::finalize_list_response(plan, total, items) {
                            Ok(response) => Self::list_ok_response(response, query.context.as_deref()),
                            Err(response) => response,
                        },
                        Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                    }
                }
            }
        }
    });
    let many_to_many_handlers = many_to_many_routes.iter().map(
        |(handler_ident, _, _, through_table, source_field, target_field)| {
            let through_table = Literal::string(through_table);
            let source_field = Literal::string(source_field);
            let target_field = Literal::string(target_field);
            if read_requires_auth {
                if hybrid.map(|config| config.nested_read).unwrap_or(false) {
                    quote! {
                        async fn #handler_ident(
                            path: web::Path<i64>,
                            query: web::Query<#list_query_ty>,
                            user: #runtime_crate::core::auth::UserContext,
                            db: web::Data<DbPool>,
                            runtime: web::Data<#runtime_crate::core::authorization::AuthorizationRuntime>,
                        ) -> impl Responder {
                            #read_check

                            let parent_id = path.into_inner();
                            let query = query.into_inner();
                            let plan = match Self::build_many_to_many_list_plan_with_hybrid_read(
                                &query,
                                &user,
                                runtime.get_ref(),
                                #through_table,
                                #source_field,
                                #target_field,
                                parent_id,
                            )
                            .await
                            {
                                Ok(parts) => parts,
                                Err(response) => return response,
                            };
                            let mut count_query =
                                #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&plan.count_sql);
                            for bind in &plan.filter_binds {
                                count_query = match bind.clone() {
                                    #(#count_bind_matches)*
                                };
                            }
                            let total = match count_query.fetch_one(db.get_ref()).await {
                                Ok(total) => total,
                                Err(error) => return #runtime_crate::core::errors::internal_error(error.to_string()),
                            };
                            let mut q = #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&plan.select_sql);
                            for bind in &plan.select_binds {
                                q = match bind.clone() {
                                    #(#list_bind_matches)*
                                };
                            }
                            match q.fetch_all(db.get_ref()).await {
                                Ok(items) => match Self::finalize_list_response(plan, total, items) {
                                    Ok(response) => Self::list_ok_response(response, query.context.as_deref()),
                                    Err(response) => response,
                                },
                                Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                            }
                        }
                    }
                } else {
                    quote! {
                        async fn #handler_ident(
                            path: web::Path<i64>,
                            query: web::Query<#list_query_ty>,
                            user: #runtime_crate::core::auth::UserContext,
                            db: web::Data<DbPool>,
                        ) -> impl Responder {
                            #read_check

                            let parent_id = path.into_inner();
                            let query = query.into_inner();
                            let plan = match Self::build_many_to_many_list_plan(
                                &query,
                                &user,
                                #through_table,
                                #source_field,
                                #target_field,
                                parent_id,
                            ) {
                                Ok(parts) => parts,
                                Err(response) => return response,
                            };
                            let mut count_query =
                                #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&plan.count_sql);
                            for bind in &plan.filter_binds {
                                count_query = match bind.clone() {
                                    #(#count_bind_matches)*
                                };
                            }
                            let total = match count_query.fetch_one(db.get_ref()).await {
                                Ok(total) => total,
                                Err(error) => return #runtime_crate::core::errors::internal_error(error.to_string()),
                            };
                            let mut q = #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&plan.select_sql);
                            for bind in &plan.select_binds {
                                q = match bind.clone() {
                                    #(#list_bind_matches)*
                                };
                            }
                            match q.fetch_all(db.get_ref()).await {
                                Ok(items) => match Self::finalize_list_response(plan, total, items) {
                                    Ok(response) => Self::list_ok_response(response, query.context.as_deref()),
                                    Err(response) => response,
                                },
                                Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                            }
                        }
                    }
                }
            } else {
                quote! {
                    async fn #handler_ident(
                        path: web::Path<i64>,
                        query: web::Query<#list_query_ty>,
                        db: web::Data<DbPool>,
                    ) -> impl Responder {
                        let parent_id = path.into_inner();
                        let query = query.into_inner();
                        let user = Self::anonymous_user_context();
                        let plan = match Self::build_many_to_many_list_plan(
                            &query,
                            &user,
                            #through_table,
                            #source_field,
                            #target_field,
                            parent_id,
                        ) {
                            Ok(parts) => parts,
                            Err(response) => return response,
                        };
                        let mut count_query =
                            #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&plan.count_sql);
                        for bind in &plan.filter_binds {
                            count_query = match bind.clone() {
                                #(#count_bind_matches)*
                            };
                        }
                        let total = match count_query.fetch_one(db.get_ref()).await {
                            Ok(total) => total,
                            Err(error) => return #runtime_crate::core::errors::internal_error(error.to_string()),
                        };
                        let mut q = #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&plan.select_sql);
                        for bind in &plan.select_binds {
                            q = match bind.clone() {
                                #(#list_bind_matches)*
                            };
                        }
                        match q.fetch_all(db.get_ref()).await {
                            Ok(items) => match Self::finalize_list_response(plan, total, items) {
                                Ok(response) => Self::list_ok_response(response, query.context.as_deref()),
                                Err(response) => response,
                            },
                            Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                        }
                    }
                }
            }
        },
    );
    let resource_action_handlers = resource.actions.iter().map(|action| {
        resource_action_handler_tokens(resource, action, hybrid, &query_bind_matches, runtime_crate)
    });
    let get_all_handler = if read_requires_auth {
        if hybrid.map(|config| config.collection_read).unwrap_or(false) {
            quote! {
                async fn get_all(
                    query: web::Query<#list_query_ty>,
                    user: #runtime_crate::core::auth::UserContext,
                    db: web::Data<DbPool>,
                    runtime: web::Data<#runtime_crate::core::authorization::AuthorizationRuntime>,
                ) -> impl Responder {
                    #read_check
                    let query = query.into_inner();
                    let plan = match Self::build_list_plan_with_hybrid_read(
                        &query,
                        &user,
                        runtime.get_ref(),
                        None,
                    )
                    .await
                    {
                        Ok(parts) => parts,
                        Err(response) => return response,
                    };
                    let mut count_query =
                        #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&plan.count_sql);
                    for bind in &plan.filter_binds {
                        count_query = match bind.clone() {
                            #(#count_bind_matches)*
                        };
                    }
                    let total = match count_query.fetch_one(db.get_ref()).await {
                        Ok(total) => total,
                        Err(error) => return #runtime_crate::core::errors::internal_error(error.to_string()),
                    };
                    let mut q = #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&plan.select_sql);
                    for bind in &plan.select_binds {
                        q = match bind.clone() {
                            #(#list_bind_matches)*
                        };
                    }
                    match q.fetch_all(db.get_ref()).await {
                        Ok(items) => match Self::finalize_list_response(plan, total, items) {
                            Ok(response) => Self::list_ok_response(response, query.context.as_deref()),
                            Err(response) => response,
                        },
                        Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                    }
                }
            }
        } else {
            quote! {
                async fn get_all(
                    query: web::Query<#list_query_ty>,
                    user: #runtime_crate::core::auth::UserContext,
                    db: web::Data<DbPool>,
                ) -> impl Responder {
                    #read_check
                    let query = query.into_inner();
                    let plan = match Self::build_list_plan(&query, &user, None) {
                        Ok(parts) => parts,
                        Err(response) => return response,
                    };
                    let mut count_query =
                        #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&plan.count_sql);
                    for bind in &plan.filter_binds {
                        count_query = match bind.clone() {
                            #(#count_bind_matches)*
                        };
                    }
                    let total = match count_query.fetch_one(db.get_ref()).await {
                        Ok(total) => total,
                        Err(error) => return #runtime_crate::core::errors::internal_error(error.to_string()),
                    };
                    let mut q = #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&plan.select_sql);
                    for bind in &plan.select_binds {
                        q = match bind.clone() {
                            #(#list_bind_matches)*
                        };
                    }
                    match q.fetch_all(db.get_ref()).await {
                        Ok(items) => match Self::finalize_list_response(plan, total, items) {
                            Ok(response) => Self::list_ok_response(response, query.context.as_deref()),
                            Err(response) => response,
                        },
                        Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                    }
                }
            }
        }
    } else {
        quote! {
            async fn get_all(
                query: web::Query<#list_query_ty>,
                db: web::Data<DbPool>,
            ) -> impl Responder {
                let query = query.into_inner();
                let user = Self::anonymous_user_context();
                let plan = match Self::build_list_plan(&query, &user, None) {
                    Ok(parts) => parts,
                    Err(response) => return response,
                };
                let mut count_query =
                    #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&plan.count_sql);
                for bind in &plan.filter_binds {
                    count_query = match bind.clone() {
                        #(#count_bind_matches)*
                    };
                }
                let total = match count_query.fetch_one(db.get_ref()).await {
                    Ok(total) => total,
                    Err(error) => return #runtime_crate::core::errors::internal_error(error.to_string()),
                };
                let mut q = #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&plan.select_sql);
                for bind in &plan.select_binds {
                    q = match bind.clone() {
                        #(#list_bind_matches)*
                    };
                }
                match q.fetch_all(db.get_ref()).await {
                    Ok(items) => match Self::finalize_list_response(plan, total, items) {
                        Ok(response) => Self::list_ok_response(response, query.context.as_deref()),
                        Err(response) => response,
                    },
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }
        }
    };
    let get_one_handler = if read_requires_auth {
        if hybrid.map(|config| config.item_read).unwrap_or(false) {
            quote! {
                async fn get_one(
                    path: web::Path<i64>,
                    req: HttpRequest,
                    user: #runtime_crate::core::auth::UserContext,
                    db: web::Data<DbPool>,
                    runtime: web::Data<#runtime_crate::core::authorization::AuthorizationRuntime>,
                ) -> impl Responder {
                    #read_check
                    let response_context = match Self::request_response_context(&req) {
                        Ok(context) => context,
                        Err(response) => return response,
                    };
                    let id = path.into_inner();
                    match Self::fetch_readable_by_id(id, &user, db.get_ref()).await {
                        Ok(Some(item)) => Self::item_ok_response(&item, response_context.as_deref()),
                        Ok(None) => match Self::fetch_runtime_authorized_by_id(
                            id,
                            &user,
                            runtime.get_ref(),
                            db.get_ref(),
                            #runtime_crate::core::authorization::AuthorizationAction::Read,
                        )
                        .await
                        {
                            Ok(Some(item)) => Self::item_ok_response(&item, response_context.as_deref()),
                            Ok(None) => #runtime_crate::core::errors::not_found("Not found"),
                            Err(response) => response,
                        },
                        Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                    }
                }
            }
        } else {
            quote! {
                async fn get_one(
                    path: web::Path<i64>,
                    req: HttpRequest,
                    user: #runtime_crate::core::auth::UserContext,
                    db: web::Data<DbPool>,
                ) -> impl Responder {
                    #read_check
                    #get_one_body
                }
            }
        }
    } else {
        quote! {
            async fn get_one(
                path: web::Path<i64>,
                req: HttpRequest,
                db: web::Data<DbPool>,
            ) -> impl Responder {
                let user = Self::anonymous_user_context();
                #get_one_body
            }
        }
    };
    let update_runtime_arg = if hybrid.map(|config| config.update).unwrap_or(false) {
        quote!(, runtime: web::Data<#runtime_crate::core::authorization::AuthorizationRuntime>)
    } else {
        quote!()
    };
    let create_runtime_arg = if hybrid
        .map(|config| config.create_payload || config.item_read)
        .unwrap_or(false)
    {
        quote!(, runtime: web::Data<#runtime_crate::core::authorization::AuthorizationRuntime>)
    } else {
        quote!()
    };
    let delete_runtime_arg = if hybrid.map(|config| config.delete).unwrap_or(false) {
        quote!(, runtime: web::Data<#runtime_crate::core::authorization::AuthorizationRuntime>)
    } else {
        quote!()
    };

    quote! {
        use #runtime_crate::actix_web::{web, HttpRequest, HttpResponse, Responder};
        use #runtime_crate::db::DbPool;

        #policy_plan_enum

        impl #struct_ident {
            pub fn configure(cfg: &mut web::ServiceConfig, db: impl Into<DbPool>) {
                let db = web::Data::new(db.into());
                #runtime_crate::core::errors::configure_extractor_errors(cfg);
                cfg.app_data(db.clone());
                #hybrid_configure_app_data

                cfg.service(
                    web::resource(format!("/{}", #resource_api_name))
                        .route(web::get().to(Self::get_all))
                        .route(web::post().to(Self::create))
                )
                .service(
                    web::resource(format!("/{}/{{id}}", #resource_api_name))
                        .route(web::get().to(Self::get_one))
                        .route(web::put().to(Self::update))
                        .route(web::delete().to(Self::delete))
                );

                #(#nested_route_registrations)*
                #(#many_to_many_route_registrations)*
                #(#resource_action_route_registrations)*
            }

            #anonymous_user_context_fn

            #contains_filter_helper

            #(#many_to_many_handlers)*
            #(#resource_action_handlers)*
            #(#object_normalizer_defs)*

            fn can_read(user: &#runtime_crate::core::auth::UserContext) -> bool {
                let _ = user;
                #can_read_body
            }

            #hybrid_helper_tokens

            async fn fetch_readable_by_id(
                id: i64,
                user: &#runtime_crate::core::auth::UserContext,
                db: &DbPool,
            ) -> Result<Option<Self>, #runtime_crate::sqlx::Error> {
                #fetch_readable_by_id_body
            }

            fn request_response_context(req: &HttpRequest) -> Result<Option<String>, HttpResponse> {
                #runtime_crate::actix_web::web::Query::<::std::collections::HashMap<String, String>>::from_query(
                    req.query_string(),
                )
                .map(|query| query.get("context").cloned())
                .map_err(|_| {
                    #runtime_crate::core::errors::bad_request(
                        "invalid_context",
                        "Query parameters are invalid",
                    )
                })
            }

            fn response_context_fields(
                requested: Option<&str>,
            ) -> Result<Option<&'static [&'static str]>, HttpResponse> {
                let context_name = requested.or(#default_response_context_tokens);
                match context_name {
                    #(#response_context_match_arms)*
                    Some(value) => Err(#runtime_crate::core::errors::bad_request(
                        "invalid_context",
                        format!("Unknown response context `{}`", value),
                    )),
                    None => Ok(None),
                }
            }

            #allow_dead_serialize_helpers
            fn serialize_item_value(
                item: &Self,
                context_fields: Option<&'static [&'static str]>,
            ) -> Result<#runtime_crate::serde_json::Value, HttpResponse> {
                let mut value = #runtime_crate::serde_json::to_value(item).map_err(|error| {
                    #runtime_crate::core::errors::internal_error(error.to_string())
                })?;
                let object = value.as_object_mut().ok_or_else(|| {
                    #runtime_crate::core::errors::internal_error(
                        "response item must serialize to a JSON object",
                    )
                })?;
                #(#computed_field_insertions)*
                if let Some(fields) = context_fields {
                    object.retain(|key, _| fields.iter().any(|field| *field == key));
                }
                Ok(value)
            }

            #allow_dead_serialize_helpers
            fn serialize_item_response(
                item: &Self,
                requested: Option<&str>,
            ) -> Result<#runtime_crate::serde_json::Value, HttpResponse> {
                let context_fields = Self::response_context_fields(requested)?;
                Self::serialize_item_value(item, context_fields)
            }

            #allow_dead_serialize_helpers
            fn serialize_list_response(
                response: #list_response_ty,
                requested: Option<&str>,
            ) -> Result<#runtime_crate::serde_json::Value, HttpResponse> {
                let context_fields = Self::response_context_fields(requested)?;
                let #list_response_struct_ident {
                    items,
                    total,
                    count,
                    limit,
                    offset,
                    next_offset,
                    next_cursor,
                } = response;
                let items = items
                    .iter()
                    .map(|item| Self::serialize_item_value(item, context_fields))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(#runtime_crate::serde_json::json!({
                    "items": items,
                    "total": total,
                    "count": count,
                    "limit": limit,
                    "offset": offset,
                    "next_offset": next_offset,
                    "next_cursor": next_cursor,
                }))
            }

            fn item_ok_response(item: &Self, requested: Option<&str>) -> HttpResponse {
                #item_ok_response_body
            }

            fn item_created_response(
                item: &Self,
                req: &HttpRequest,
                id: i64,
                requested: Option<&str>,
            ) -> HttpResponse {
                #item_created_response_body
            }

            fn list_ok_response(
                response: #list_response_ty,
                requested: Option<&str>,
            ) -> HttpResponse {
                #list_ok_response_body
            }

            fn created_location(req: &HttpRequest, id: i64) -> String {
                format!("{}/{}", req.uri().path().trim_end_matches('/'), id)
            }

            async fn created_response(
                id: i64,
                req: &HttpRequest,
                user: &#runtime_crate::core::auth::UserContext,
                db: &DbPool,
                runtime: Option<&#runtime_crate::core::authorization::AuthorizationRuntime>,
            ) -> HttpResponse {
                let _ = &runtime;
                let response_context = match Self::request_response_context(req) {
                    Ok(context) => context,
                    Err(response) => return response,
                };
                match Self::fetch_readable_by_id(id, user, db).await {
                    Ok(Some(item)) => {
                        Self::item_created_response(&item, req, id, response_context.as_deref())
                    }
                    Ok(None) => #created_response_fallback,
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }

            fn list_placeholder(index: usize) -> String {
                #list_placeholder_body
            }

            #next_list_placeholder_helper

            #policy_plan_methods

            fn sort_supports_cursor(sort: &#sort_field_ty) -> bool {
                match sort {
                    #(#cursor_support_arms)*
                }
            }

            fn cursor_id_for_item(item: &Self) -> Result<i64, HttpResponse> {
                #cursor_id_for_item_body
            }

            fn cursor_value_for_item(
                item: &Self,
                sort: &#sort_field_ty,
            ) -> Result<#cursor_value_ty, HttpResponse> {
                match sort {
                    #(#cursor_value_for_item_arms)*
                }
            }

            fn encode_cursor(
                sort: &#sort_field_ty,
                order: &#sort_order_ty,
                item: &Self,
            ) -> Result<String, HttpResponse> {
                let payload = #cursor_payload_ty {
                    sort: sort.as_name().to_owned(),
                    order: order.as_str().to_owned(),
                    last_id: Self::cursor_id_for_item(item)?,
                    value: Self::cursor_value_for_item(item, sort)?,
                };
                let json = #runtime_crate::serde_json::to_vec(&payload).map_err(|error| {
                    #runtime_crate::core::errors::internal_error(error.to_string())
                })?;
                Ok(#runtime_crate::base64::Engine::encode(
                    &#runtime_crate::base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    json,
                ))
            }

            fn decode_cursor(value: &str) -> Result<#cursor_payload_ty, HttpResponse> {
                let bytes = #runtime_crate::base64::Engine::decode(
                    &#runtime_crate::base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    value,
                )
                .map_err(|_| {
                    #runtime_crate::core::errors::bad_request(
                        "invalid_cursor",
                        "Cursor is not valid",
                    )
                })?;
                #runtime_crate::serde_json::from_slice::<#cursor_payload_ty>(&bytes).map_err(|_| {
                    #runtime_crate::core::errors::bad_request(
                        "invalid_cursor",
                        "Cursor is not valid",
                    )
                })
            }

            fn build_list_plan_internal(
                query: &#list_query_ty,
                user: &#runtime_crate::core::auth::UserContext,
                parent_filter: Option<(&'static str, i64)>,
                many_to_many_scope: Option<(&'static str, &'static str, &'static str, i64)>,
                skip_static_read_policy: bool,
            ) -> Result<#list_plan_ty, HttpResponse> {
                let mut select_sql = format!("SELECT * FROM {}", #table_name);
                let mut count_sql = format!("SELECT COUNT(*) FROM {}", #table_name);
                let mut conditions: Vec<String> = Vec::new();
                let mut filter_binds: Vec<#list_bind_ty> = Vec::new();
                let mut select_only_conditions: Vec<String> = Vec::new();
                let mut select_only_binds: Vec<#list_bind_ty> = Vec::new();
                #user_usage
                #skip_static_read_policy_usage
                #is_admin_binding
                let requested_limit = query.limit.or(#default_limit_tokens);
                let effective_limit = match (requested_limit, #max_limit_tokens) {
                    (Some(limit), Some(max_limit)) => {
                        if limit == 0 {
                            return Err(#runtime_crate::core::errors::bad_request(
                                "invalid_pagination",
                                "`limit` must be greater than 0",
                            ));
                        }
                        Some(limit.min(max_limit))
                    }
                    (Some(limit), None) => {
                        if limit == 0 {
                            return Err(#runtime_crate::core::errors::bad_request(
                                "invalid_pagination",
                                "`limit` must be greater than 0",
                            ));
                        }
                        Some(limit)
                    }
                    (None, _) => None,
                };
                let offset = query.offset.unwrap_or(0);
                let cursor_payload = match &query.cursor {
                    Some(value) => Some(Self::decode_cursor(value)?),
                    None => None,
                };
                if query.cursor.is_some() && query.offset.is_some() {
                    return Err(#runtime_crate::core::errors::bad_request(
                        "invalid_cursor",
                        "`cursor` cannot be combined with `offset`",
                    ));
                }
                if query.cursor.is_some() && (query.sort.is_some() || query.order.is_some()) {
                    return Err(#runtime_crate::core::errors::bad_request(
                        "invalid_cursor",
                        "`cursor` cannot be combined with `sort` or `order`",
                    ));
                }
                let (sort, order, cursor_mode) = if let Some(cursor_payload) = &cursor_payload {
                    let sort = #sort_field_ty::from_name(&cursor_payload.sort).ok_or_else(|| {
                        #runtime_crate::core::errors::bad_request(
                            "invalid_cursor",
                            "Cursor references an unknown sort field",
                        )
                    })?;
                    let order = #sort_order_ty::parse(&cursor_payload.order).ok_or_else(|| {
                        #runtime_crate::core::errors::bad_request(
                            "invalid_cursor",
                            "Cursor references an unknown sort order",
                        )
                    })?;
                    (sort, order, true)
                } else {
                    match (&query.sort, &query.order) {
                        (Some(sort), Some(order)) => (sort.clone(), order.clone(), false),
                        (Some(sort), None) => (sort.clone(), #sort_order_ty::Asc, false),
                        (None, Some(_)) => {
                            return Err(#runtime_crate::core::errors::bad_request(
                                "invalid_sort",
                                "`order` requires `sort`",
                            ));
                        }
                        (None, None) => (
                            #sort_field_ty::#default_sort_variant,
                            #sort_order_ty::Asc,
                            false,
                        ),
                    }
                };
                if cursor_mode && effective_limit.is_none() {
                    return Err(#runtime_crate::core::errors::bad_request(
                        "invalid_cursor",
                        "`cursor` requires `limit` or a configured `default_limit`",
                    ));
                }
                if cursor_mode && !Self::sort_supports_cursor(&sort) {
                    return Err(#runtime_crate::core::errors::bad_request(
                        "invalid_cursor",
                        format!(
                            "Cursor pagination does not support sort field `{}`",
                            sort.as_name()
                        ),
                    ));
                }

                if let Some((field_name, value)) = parent_filter {
                    conditions.push(format!(
                        "{} = {}",
                        field_name,
                        Self::list_placeholder(filter_binds.len() + 1)
                    ));
                    filter_binds.push(#list_bind_ty::Integer(value));
                }
                if let Some((through_table, source_field, target_field, parent_id)) = many_to_many_scope {
                    conditions.push(format!(
                        "EXISTS (SELECT 1 FROM {} WHERE {}.{} = {}.{} AND {}.{} = {})",
                        through_table,
                        through_table,
                        target_field,
                        #table_name,
                        #id_field_name_lit,
                        through_table,
                        source_field,
                        Self::list_placeholder(filter_binds.len() + 1)
                    ));
                    filter_binds.push(#list_bind_ty::Integer(parent_id));
                }

                #apply_read_policy_list_conditions

                #(#query_filter_conditions)*

                if let Some(cursor_payload) = &cursor_payload {
                    let comparator = if matches!(order, #sort_order_ty::Asc) {
                        ">"
                    } else {
                        "<"
                    };
                    match &sort {
                        #(#cursor_condition_arms)*
                    }
                }

                if !conditions.is_empty() {
                    let where_sql = conditions.join(" AND ");
                    count_sql.push_str(" WHERE ");
                    count_sql.push_str(&where_sql);
                }

                let mut select_conditions = conditions.clone();
                select_conditions.extend(select_only_conditions);
                if !select_conditions.is_empty() {
                    let where_sql = select_conditions.join(" AND ");
                    select_sql.push_str(" WHERE ");
                    select_sql.push_str(&where_sql);
                }

                select_sql.push_str(" ORDER BY ");
                select_sql.push_str(sort.as_sql());
                select_sql.push(' ');
                select_sql.push_str(order.as_sql());
                if sort.as_name() != #id_field_api_name_lit {
                    select_sql.push_str(", ");
                    select_sql.push_str(#id_field_name_lit);
                    select_sql.push(' ');
                    select_sql.push_str(order.as_sql());
                }

                let query_limit = effective_limit.map(|limit| {
                    if cursor_mode {
                        limit.saturating_add(1)
                    } else {
                        limit
                    }
                });

                if query_limit.is_some() {
                    select_sql.push_str(" LIMIT ");
                    select_sql.push_str(&Self::list_placeholder(
                        filter_binds.len() + select_only_binds.len() + 1
                    ));
                }

                if query.offset.is_some() {
                    if effective_limit.is_none() {
                        return Err(#runtime_crate::core::errors::bad_request(
                            "invalid_pagination",
                            "`offset` requires `limit`",
                        ));
                    }
                    select_sql.push_str(" OFFSET ");
                    let placeholder_index = filter_binds.len() + select_only_binds.len() + 2;
                    select_sql.push_str(&Self::list_placeholder(placeholder_index));
                }

                let mut select_binds = filter_binds.clone();
                select_binds.extend(select_only_binds);
                if let Some(limit) = query_limit {
                    select_binds.push(#list_bind_ty::Integer(limit as i64));
                }
                if query.offset.is_some() {
                    select_binds.push(#list_bind_ty::Integer(offset as i64));
                }

                Ok(#list_plan_ty {
                    select_sql,
                    count_sql,
                    filter_binds,
                    select_binds,
                    limit: effective_limit,
                    offset,
                    sort,
                    order,
                    cursor_mode,
                })
            }

            #[allow(dead_code)]
            fn build_list_plan(
                query: &#list_query_ty,
                user: &#runtime_crate::core::auth::UserContext,
                parent_filter: Option<(&'static str, i64)>,
            ) -> Result<#list_plan_ty, HttpResponse> {
                Self::build_list_plan_internal(query, user, parent_filter, None, false)
            }

            #many_to_many_list_plan_helper

            #create_requirement_methods

            fn finalize_list_response(
                plan: #list_plan_ty,
                total: i64,
                mut items: Vec<Self>,
            ) -> Result<#list_response_ty, HttpResponse> {
                let mut has_more = false;
                if let Some(limit) = plan.limit.filter(|_| plan.cursor_mode)
                    && items.len() > limit as usize
                {
                    has_more = true;
                    items.pop();
                }

                let count = items.len();
                if !plan.cursor_mode {
                    has_more = match plan.limit {
                        Some(_) => (plan.offset as i64) + (count as i64) < total,
                        None => false,
                    };
                }

                let next_offset = if !plan.cursor_mode && has_more {
                    Some(plan.offset + count as u32)
                } else {
                    None
                };

                let next_cursor = if has_more && Self::sort_supports_cursor(&plan.sort) {
                    match items.last() {
                        Some(item) => Some(Self::encode_cursor(&plan.sort, &plan.order, item)?),
                        None => None,
                    }
                } else {
                    None
                };

                Ok(#list_response_ty {
                    items,
                    total,
                    count,
                    limit: plan.limit,
                    offset: plan.offset,
                    next_offset,
                    next_cursor,
                })
            }

            #get_all_handler

            #get_one_handler

            #[allow(clippy::collapsible_if)]
            async fn create(
                req: HttpRequest,
                item: web::Json<#create_payload_ty>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<DbPool>
                #create_runtime_arg
            ) -> impl Responder {
                let _ = (&req, &item, &user, &db);
                #create_check
                #create_payload_binding
                #(#create_normalization)*
                #create_garde_validation
                #(#create_validation)*
                #create_require_check
                #create_body
            }

            #[allow(clippy::collapsible_if)]
            async fn update(
                path: web::Path<i64>,
                item: web::Json<#update_payload_ty>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<DbPool>
                #update_runtime_arg
            ) -> impl Responder {
                let _ = (&path, &item, &user, &db);
                #update_check
                #update_payload_binding
                #(#update_normalization)*
                #update_garde_validation
                #(#update_validation)*
                #update_body
            }

            async fn delete(
                path: web::Path<i64>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<DbPool>
                #delete_runtime_arg
            ) -> impl Responder {
                let _ = (&path, &user, &db);
                #delete_check
                #delete_body
            }

            #(#nested_handlers)*
        }
    }
}
