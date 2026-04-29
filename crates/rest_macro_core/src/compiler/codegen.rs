use heck::{ToSnakeCase, ToUpperCamelCase};
use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::{Path, Type};

use super::model::{
    GeneratedValue, PolicyValueSource, ResourceSpec, ServiceSpec,
    StaticCacheProfile, StaticMode, WriteModelStyle,
    default_service_database_url,
};
use crate::authorization::AuthorizationContract;

pub fn expand_resource_impl(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    authorization: Option<&AuthorizationContract>,
    runtime_crate: &Path,
) -> syn::Result<TokenStream> {
    let impl_module_ident = &resource.impl_module_ident;
    let impl_body = resource_impl_tokens(resource, resources, authorization, runtime_crate);

    Ok(quote! {
        mod #impl_module_ident {
            use super::*;
            #impl_body
        }
    })
}

pub fn expand_derive_resource(
    resource: &ResourceSpec,
    runtime_crate: &Path,
) -> syn::Result<TokenStream> {
    let struct_tokens = resource_struct_tokens(
        resource,
        std::slice::from_ref(resource),
        None,
        runtime_crate,
    );
    let impl_tokens = expand_resource_impl(
        resource,
        std::slice::from_ref(resource),
        None,
        runtime_crate,
    )?;

    Ok(quote! {
        #struct_tokens
        #impl_tokens
    })
}

#[derive(Clone, Copy)]
struct HybridResourceEnforcement<'a> {
    scope: &'a str,
    scope_field: &'a super::model::FieldSpec,
    create_payload: bool,
    item_read: bool,
    collection_read: bool,
    nested_read: bool,
    update: bool,
    delete: bool,
}

fn hybrid_resource_enforcement<'a>(
    resource: &'a ResourceSpec,
    authorization: Option<&'a AuthorizationContract>,
) -> Option<HybridResourceEnforcement<'a>> {
    let config = authorization?.hybrid_resource(&resource.struct_ident.to_string())?;
    let scope_field = resource
        .find_field(&config.scope_field)
        .unwrap_or_else(|| panic!("validated hybrid scope field is missing"));
    Some(HybridResourceEnforcement {
        scope: &config.scope,
        scope_field,
        create_payload: config
            .supports_item_action(crate::authorization::AuthorizationAction::Create),
        item_read: config.supports_item_action(crate::authorization::AuthorizationAction::Read),
        collection_read: config.supports_collection_read(),
        nested_read: config.supports_nested_read(),
        update: config.supports_item_action(crate::authorization::AuthorizationAction::Update),
        delete: config.supports_item_action(crate::authorization::AuthorizationAction::Delete),
    })
}

pub fn expand_service_module(
    service: &ServiceSpec,
    runtime_crate: &Path,
    include_path: &str,
) -> syn::Result<TokenStream> {
    let module_ident = &service.module_ident;
    let datetime_alias_ident = format_ident!("{}", super::model::GENERATED_DATETIME_ALIAS);
    let date_alias_ident = format_ident!("{}", super::model::GENERATED_DATE_ALIAS);
    let time_alias_ident = format_ident!("{}", super::model::GENERATED_TIME_ALIAS);
    let uuid_alias_ident = format_ident!("{}", super::model::GENERATED_UUID_ALIAS);
    let decimal_alias_ident = format_ident!("{}", super::model::GENERATED_DECIMAL_ALIAS);
    let json_alias_ident = format_ident!("{}", super::model::GENERATED_JSON_ALIAS);
    let json_object_alias_ident = format_ident!("{}", super::model::GENERATED_JSON_OBJECT_ALIAS);
    let json_array_alias_ident = format_ident!("{}", super::model::GENERATED_JSON_ARRAY_ALIAS);
    let type_aliases = quote! {
        #[allow(non_camel_case_types)]
        type #datetime_alias_ident = #runtime_crate::chrono::DateTime<#runtime_crate::chrono::Utc>;
        #[allow(non_camel_case_types)]
        type #date_alias_ident = #runtime_crate::chrono::NaiveDate;
        #[allow(non_camel_case_types)]
        type #time_alias_ident = #runtime_crate::chrono::NaiveTime;
        #[allow(non_camel_case_types)]
        type #uuid_alias_ident = #runtime_crate::uuid::Uuid;
        #[allow(non_camel_case_types)]
        type #decimal_alias_ident = #runtime_crate::rust_decimal::Decimal;
        #[allow(non_camel_case_types)]
        type #json_alias_ident = #runtime_crate::serde_json::Value;
        #[allow(non_camel_case_types)]
        type #json_object_alias_ident = #runtime_crate::serde_json::Value;
        #[allow(non_camel_case_types)]
        type #json_array_alias_ident = #runtime_crate::serde_json::Value;
    };
    let include_path_lit = Literal::string(include_path);
    let resources = service
        .resources
        .iter()
        .map(|resource| {
            let struct_tokens = resource_struct_tokens(
                resource,
                &service.resources,
                Some(&service.authorization),
                runtime_crate,
            );
            let impl_tokens = expand_resource_impl(
                resource,
                &service.resources,
                Some(&service.authorization),
                runtime_crate,
            )?;
            Ok(quote! {
                #struct_tokens
                #impl_tokens
            })
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let configure_calls = service.resources.iter().map(|resource| {
        let struct_ident = &resource.struct_ident;
        quote! {
            #struct_ident::configure(cfg, db.clone());
        }
    });
    let static_mounts = service.static_mounts.iter().map(|mount| {
        let mount_path = Literal::string(&mount.mount_path);
        let source_dir = Literal::string(&mount.source_dir);
        let resolved_dir = Literal::string(&mount.resolved_dir);
        let index_file = match mount.index_file.as_deref() {
            Some(value) => {
                let value = Literal::string(value);
                quote!(Some(#value))
            }
            None => quote!(None),
        };
        let fallback_file = match mount.fallback_file.as_deref() {
            Some(value) => {
                let value = Literal::string(value);
                quote!(Some(#value))
            }
            None => quote!(None),
        };
        let mode = match mount.mode {
            StaticMode::Directory => {
                quote!(#runtime_crate::core::static_files::StaticMode::Directory)
            }
            StaticMode::Spa => quote!(#runtime_crate::core::static_files::StaticMode::Spa),
        };
        let cache = match mount.cache {
            StaticCacheProfile::NoStore => {
                quote!(#runtime_crate::core::static_files::StaticCacheProfile::NoStore)
            }
            StaticCacheProfile::Revalidate => {
                quote!(#runtime_crate::core::static_files::StaticCacheProfile::Revalidate)
            }
            StaticCacheProfile::Immutable => {
                quote!(#runtime_crate::core::static_files::StaticCacheProfile::Immutable)
            }
        };

        quote! {
            #runtime_crate::core::static_files::StaticMount {
                mount_path: #mount_path,
                source_dir: #source_dir,
                resolved_dir: #resolved_dir,
                mode: #mode,
                index_file: #index_file,
                fallback_file: #fallback_file,
                cache: #cache,
            }
        }
    });
    let configure_storage_public_mounts = if service.storage.public_mounts.is_empty() {
        quote! {}
    } else {
        quote! {
            {
                let storage_config = storage();
                let storage_registry = #runtime_crate::core::storage::StorageRegistry::from_config(
                    &storage_config,
                )
                .expect("generated storage config should be valid");
                #runtime_crate::core::storage::configure_public_mounts_with_runtime(
                    cfg,
                    &storage_registry,
                    storage_config.public_mounts.as_slice(),
                    &runtime,
                );
            }
        }
    };
    let configure_s3_compat = if service.storage.s3_compat.is_none() {
        quote! {}
    } else {
        quote! {
            {
                let storage_config = storage();
                let storage_registry = #runtime_crate::core::storage::StorageRegistry::from_config(
                    &storage_config,
                )
                .expect("generated storage config should be valid");
                #runtime_crate::core::storage::configure_s3_compat_with_runtime(
                    cfg,
                    &storage_registry,
                    storage_config.s3_compat.as_ref(),
                    &runtime,
                );
            }
        }
    };
    let configure_storage_uploads = if service.storage.uploads.is_empty() {
        quote! {}
    } else {
        quote! {
            {
                let storage_config = storage();
                let storage_registry = #runtime_crate::core::storage::StorageRegistry::from_config(
                    &storage_config,
                )
                .expect("generated storage config should be valid");
                #runtime_crate::core::storage::configure_upload_endpoints_with_runtime(
                    cfg,
                    &storage_registry,
                    storage_config.public_mounts.as_slice(),
                    storage_config.uploads.as_slice(),
                    &runtime(),
                );
            }
        }
    };
    let configure_static_mounts = if service.static_mounts.is_empty() {
        quote! {}
    } else {
        quote! {
            let mounts = [
                #(#static_mounts),*
            ];
            #runtime_crate::core::static_files::configure_static_mounts_with_runtime(
                cfg,
                &mounts,
                &runtime,
            );
        }
    };
    let configure_static_body = if service.static_mounts.is_empty()
        && service.storage.public_mounts.is_empty()
        && service.storage.s3_compat.is_none()
    {
        quote! {}
    } else {
        quote! {
            let runtime = runtime();
            #configure_storage_public_mounts
            #configure_s3_compat
            #configure_static_mounts
        }
    };
    let database = database_tokens(service, runtime_crate);
    let default_database_url = Literal::string(&default_service_database_url(service));
    let logging = logging_tokens(service, runtime_crate);
    let runtime = runtime_tokens(service, runtime_crate);
    let storage = storage_tokens(service, runtime_crate);
    let security = security_tokens(service, runtime_crate);
    let authorization = authorization_tokens(service, runtime_crate);
    let authorization_management = authorization_management_tokens(service, runtime_crate);
    let tls = tls_tokens(service, runtime_crate);
    let authorization_management_mount =
        Literal::string(&service.authorization.management_api.mount);
    let authorization_management_enabled = service.authorization.management_api.enabled;
    let configure_static_needs_cfg = !service.static_mounts.is_empty()
        || !service.storage.public_mounts.is_empty()
        || service.storage.s3_compat.is_some()
        || !service.storage.uploads.is_empty();
    let configure_static_arg = if configure_static_needs_cfg {
        quote!(cfg)
    } else {
        quote!(_cfg)
    };
    let storage_fn = if service.storage.is_empty() {
        quote!()
    } else {
        quote! {
            pub fn storage() -> #runtime_crate::core::storage::StorageConfig {
                #storage
            }
        }
    };
    let authorization_management_fn = if authorization_management_enabled {
        quote! {
            #[allow(dead_code)]
            pub fn authorization_management(
            ) -> #runtime_crate::core::authorization::AuthorizationManagementApiConfig {
                #authorization_management
            }
        }
    } else {
        quote!()
    };
    let tls_fn = if service.tls.is_enabled() {
        quote! {
            pub fn tls() -> #runtime_crate::core::tls::TlsConfig {
                #tls
            }
        }
    } else {
        quote!()
    };
    let configure_authorization_management_fn = if authorization_management_enabled {
        quote! {
            #[allow(dead_code)]
            pub fn configure_authorization_management(
                cfg: &mut web::ServiceConfig,
                db: impl Into<DbPool>,
            ) {
                let db = db.into();
                cfg.app_data(web::Data::new(authorization_runtime(db)));
                let management = authorization_management();
                #runtime_crate::core::authorization::authorization_management_routes_at(
                    cfg,
                    management.mount.as_str(),
                );
            }
        }
    } else {
        quote!()
    };

    Ok(quote! {
        pub mod #module_ident {
            const _: &str = include_str!(#include_path_lit);

            #type_aliases

            use #runtime_crate::actix_web::web;
            use #runtime_crate::db::DbPool;

            #(#resources)*

            pub fn configure(cfg: &mut web::ServiceConfig, db: impl Into<DbPool>) {
                let db = db.into();
                cfg.app_data(web::Data::new(authorization_runtime(db.clone())));
                #configure_storage_uploads
                #(#configure_calls)*
                configure_security(cfg);
                if #authorization_management_enabled {
                    #runtime_crate::core::authorization::authorization_management_routes_at(
                        cfg,
                        #authorization_management_mount,
                    );
                }
            }

            pub fn configure_static(#configure_static_arg: &mut web::ServiceConfig) {
                #configure_static_body
            }

            pub fn database() -> #runtime_crate::core::database::DatabaseConfig {
                #database
            }

            pub fn default_database_url() -> &'static str {
                #default_database_url
            }

            pub fn logging() -> #runtime_crate::core::logging::LoggingConfig {
                #logging
            }

            pub fn runtime() -> #runtime_crate::core::runtime::RuntimeConfig {
                #runtime
            }

            #storage_fn

            pub fn security() -> #runtime_crate::core::security::SecurityConfig {
                #security
            }

            pub fn authorization() -> #runtime_crate::core::authorization::AuthorizationModel {
                #authorization
            }

            #authorization_management_fn

            pub fn authorization_runtime(
                db: impl Into<DbPool>,
            ) -> #runtime_crate::core::authorization::AuthorizationRuntime {
                #runtime_crate::core::authorization::AuthorizationRuntime::new(
                    authorization(),
                    db,
                )
            }

            #tls_fn

            pub fn configure_security(cfg: &mut web::ServiceConfig) {
                let security = security();
                #runtime_crate::core::security::configure_scope_security(cfg, &security);
            }

            #configure_authorization_management_fn
        }
    })
}


mod service_tokens;
use self::service_tokens::*;



mod resource_struct_tokens;
use self::resource_struct_tokens::*;


mod resource_impl;
use self::resource_impl::*;

fn create_payload_type(resource: &ResourceSpec) -> TokenStream {
    match resource.write_style {
        WriteModelStyle::ExistingStructWithDtos | WriteModelStyle::GeneratedStructWithDtos => {
            let ident = format_ident!("{}Create", resource.struct_ident);
            quote!(#ident)
        }
    }
}

fn update_payload_type(resource: &ResourceSpec) -> TokenStream {
    match resource.write_style {
        WriteModelStyle::ExistingStructWithDtos | WriteModelStyle::GeneratedStructWithDtos => {
            let ident = format_ident!("{}Update", resource.struct_ident);
            quote!(#ident)
        }
    }
}

fn resource_action_input_ident(
    resource: &ResourceSpec,
    action: &super::model::ResourceActionSpec,
) -> syn::Ident {
    format_ident!(
        "{}{}ActionInput",
        resource.struct_ident,
        action.name.to_upper_camel_case()
    )
}

fn resource_action_input_field_ident(index: usize) -> syn::Ident {
    format_ident!("field_{index}")
}

fn resource_action_input_struct_tokens(
    resource: &ResourceSpec,
    action: &super::model::ResourceActionSpec,
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
                super::model::is_optional_type(&target_field.ty),
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

struct CreatePayloadField<'a> {
    field: &'a super::model::FieldSpec,
    allow_admin_override: bool,
    allow_hybrid_runtime: bool,
}

fn create_payload_fields<'a>(
    resource: &'a ResourceSpec,
    authorization: Option<&'a AuthorizationContract>,
) -> Vec<CreatePayloadField<'a>> {
    let hybrid_create_scope_field = hybrid_resource_enforcement(resource, authorization)
        .filter(|config| config.create_payload)
        .map(|config| config.scope_field.name());
    resource
        .fields
        .iter()
        .filter_map(|field| {
            if field.generated.skip_insert() {
                return None;
            }

            let controlled = create_assignment_source(resource, &field.name()).is_some();
            let allow_admin_override = controlled
                && resource.policies.admin_bypass
                && matches!(
                    create_assignment_source(resource, &field.name()),
                    Some(PolicyValueSource::Claim(_))
                );
            let allow_hybrid_runtime =
                controlled && hybrid_create_scope_field.as_deref() == Some(field.name().as_str());
            if controlled && !allow_admin_override && !allow_hybrid_runtime {
                return None;
            }

            Some(CreatePayloadField {
                field,
                allow_admin_override,
                allow_hybrid_runtime,
            })
        })
        .collect()
}

fn create_payload_field_ty(field: &CreatePayloadField<'_>) -> syn::Type {
    if (field.allow_admin_override || field.allow_hybrid_runtime)
        && !super::model::is_optional_type(&field.field.ty)
    {
        let ty = &field.field.ty;
        syn::parse_quote!(Option<#ty>)
    } else {
        field.field.ty.clone()
    }
}

fn create_payload_field_is_optional(field: &CreatePayloadField<'_>) -> bool {
    field.allow_admin_override
        || field.allow_hybrid_runtime
        || super::model::is_optional_type(&field.field.ty)
}

fn type_leaf_name(ty: &Type) -> Option<String> {
    match super::model::base_type(ty) {
        Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

fn type_is_copy_like(ty: &Type) -> bool {
    if super::model::structured_scalar_kind(ty).is_some() {
        return true;
    }

    matches!(
        type_leaf_name(ty).as_deref(),
        Some(
            "bool"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "isize"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "usize"
                | "f32"
                | "f64"
        )
    )
}

fn bind_field_value_tokens(field: &super::model::FieldSpec, expr: TokenStream) -> TokenStream {
    if type_is_copy_like(&field.ty) {
        quote!(#expr)
    } else {
        quote!((#expr).clone())
    }
}

fn integer_to_i64_tokens(ty: &Type, expr: TokenStream) -> TokenStream {
    match type_leaf_name(ty).as_deref() {
        Some("i64") => quote!(#expr),
        _ => quote!((#expr) as i64),
    }
}

fn update_payload_fields(resource: &ResourceSpec) -> Vec<&super::model::FieldSpec> {
    let controlled_fields = policy_controlled_fields(resource);
    resource
        .fields
        .iter()
        .filter(|field| {
            !field.is_id
                && !field.generated.skip_update_bind()
                && !controlled_fields.contains(&field.name())
        })
        .collect()
}

fn resource_action_handler_tokens(
    resource: &ResourceSpec,
    action: &super::model::ResourceActionSpec,
    hybrid: Option<HybridResourceEnforcement<'_>>,
    query_bind_matches: &[TokenStream],
    runtime_crate: &Path,
) -> TokenStream {
    let handler_ident = format_ident!("action_{}", action.name.to_snake_case());
    match &action.behavior {
        super::model::ResourceActionBehaviorSpec::UpdateFields { assignments } => {
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
                        super::model::is_optional_type(&field.ty),
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
                        super::model::is_optional_type(&field.ty),
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
                super::model::ResourceActionBehaviorSpec::UpdateFields { assignments } => {
                    assignments.iter().any(|assignment| {
                        matches!(
                            assignment.value,
                            super::model::ResourceActionValueSpec::InputField(_)
                        )
                    })
                }
                super::model::ResourceActionBehaviorSpec::DeleteResource => false,
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
                                super::model::generated_temporal_kind_for_field(
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
        super::model::ResourceActionBehaviorSpec::DeleteResource => {
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
                let delete_body = if admin_bypass {
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
                };
                quote! {
                    async fn #handler_ident(
                        path: web::Path<i64>,
                        user: #runtime_crate::core::auth::UserContext,
                        db: web::Data<DbPool>
                        #delete_runtime_arg
                    ) -> impl Responder {
                        let _ = (&path, &user, &db);
                        #delete_check
                        #delete_body
                    }
                }
            }
        }
    }
}

fn resource_action_bind_statement(
    resource: &ResourceSpec,
    action: &super::model::ResourceActionSpec,
    assignment: &super::model::ResourceActionAssignmentSpec,
) -> TokenStream {
    match &assignment.value {
        super::model::ResourceActionValueSpec::Literal(serde_json::Value::Null) => quote! {
            q = q.bind::<Option<String>>(None);
        },
        super::model::ResourceActionValueSpec::Literal(serde_json::Value::Bool(value)) => quote! {
            q = q.bind(#value);
        },
        super::model::ResourceActionValueSpec::Literal(serde_json::Value::Number(value)) => {
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
        super::model::ResourceActionValueSpec::Literal(serde_json::Value::String(value)) => {
            let value = Literal::string(value);
            quote! {
                q = q.bind(#value);
            }
        }
        super::model::ResourceActionValueSpec::Literal(
            serde_json::Value::Array(_) | serde_json::Value::Object(_),
        ) => {
            unreachable!("structured action values are not supported in the first slice")
        }
        super::model::ResourceActionValueSpec::InputField(name) => {
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

mod list_tokens;
use self::list_tokens::*;

fn garde_validate_item_tokens(error_helper: &syn::Ident, runtime_crate: &Path) -> TokenStream {
    quote! {
        if let Err(report) = #runtime_crate::garde::Validate::validate(&item) {
            let (field, message) = super::#error_helper(report);
            return match field {
                Some(field) => #runtime_crate::core::errors::validation_error(field, message),
                None => #runtime_crate::core::errors::bad_request("validation_error", message),
            };
        }
    }
}

fn create_validation_tokens(
    resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
    runtime_crate: &Path,
) -> Vec<TokenStream> {
    create_payload_fields(resource, authorization)
        .into_iter()
        .filter_map(|field| {
            validation_tokens(
                resource,
                field.field,
                &field.field.ident,
                create_payload_field_is_optional(&field),
                runtime_crate,
            )
        })
        .collect()
}

fn create_normalization_tokens(
    resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
) -> Vec<TokenStream> {
    create_payload_fields(resource, authorization)
        .into_iter()
        .filter_map(|field| {
            normalization_tokens(
                resource,
                field.field,
                &field.field.ident,
                create_payload_field_is_optional(&field),
            )
        })
        .collect()
}

fn update_normalization_tokens(resource: &ResourceSpec) -> Vec<TokenStream> {
    update_payload_fields(resource)
        .into_iter()
        .filter_map(|field| {
            normalization_tokens(
                resource,
                field,
                &field.ident,
                super::model::is_optional_type(&field.ty),
            )
        })
        .collect()
}

fn normalization_tokens(
    resource: &ResourceSpec,
    field: &super::model::FieldSpec,
    ident: &syn::Ident,
    optional: bool,
) -> Option<TokenStream> {
    if let Some(_nested_fields) = field.object_fields.as_deref() {
        if !field_needs_normalization(field) {
            return None;
        }
        let helper_ident = typed_object_normalizer_ident(resource, &[field.name()]);
        return Some(if optional {
            quote! {
                if let Some(value) = &mut item.#ident {
                    Self::#helper_ident(value);
                }
            }
        } else {
            quote! {
                Self::#helper_ident(&mut item.#ident);
            }
        });
    }

    if field.transforms().is_empty() {
        return None;
    }

    let transform_ops = string_transform_ops(field.transforms());
    Some(if optional {
        quote! {
            if let Some(value) = &mut item.#ident {
                #(#transform_ops)*
            }
        }
    } else {
        quote! {
            {
                let value = &mut item.#ident;
                #(#transform_ops)*
            }
        }
    })
}

fn update_validation_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    update_payload_fields(resource)
        .into_iter()
        .filter_map(|field| {
            validation_tokens(
                resource,
                field,
                &field.ident,
                super::model::is_optional_type(&field.ty),
                runtime_crate,
            )
        })
        .collect()
}

mod policy_plan_tokens;
use self::policy_plan_tokens::*;
