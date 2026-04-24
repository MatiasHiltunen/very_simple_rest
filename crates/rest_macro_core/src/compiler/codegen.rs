use std::collections::BTreeSet;

use heck::{ToSnakeCase, ToUpperCamelCase};
use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::{Path, Type};

use super::model::{
    GeneratedValue, PolicyComparisonValue, PolicyFilterExpression, PolicyLiteralValue,
    PolicyValueSource, ResourceSpec, ServiceSpec, StaticCacheProfile, StaticMode, WriteModelStyle,
    default_service_database_url,
};
use crate::{
    authorization::{
        ActionAuthorization, AuthorizationAssignment, AuthorizationCondition,
        AuthorizationContract, AuthorizationExistsCondition, AuthorizationLiteralValue,
        AuthorizationMatch, AuthorizationModel, AuthorizationOperator, AuthorizationValueSource,
        ResourceAuthorization,
    },
    database::{
        DatabaseBackupMode, DatabaseBackupTarget, DatabaseEngine, DatabaseReadRoutingMode,
        DatabaseReplicationMode, DatabaseResilienceProfile,
    },
    logging::LogTimestampPrecision,
    security::{DEFAULT_MAX_FILTER_IN_VALUES, DefaultReadAccess, FrameOptions, ReferrerPolicy},
};

pub fn expand_resource_impl(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    authorization: Option<&AuthorizationContract>,
    runtime_crate: &Path,
) -> syn::Result<TokenStream> {
    expand_resource_impl_with_options(
        resource,
        resources,
        authorization,
        DEFAULT_MAX_FILTER_IN_VALUES,
        runtime_crate,
    )
}

fn expand_resource_impl_with_options(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    authorization: Option<&AuthorizationContract>,
    max_filter_in_values: usize,
    runtime_crate: &Path,
) -> syn::Result<TokenStream> {
    let impl_module_ident = &resource.impl_module_ident;
    let impl_body = resource_impl_tokens(
        resource,
        resources,
        authorization,
        max_filter_in_values,
        runtime_crate,
    );

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
    let max_filter_in_values = service
        .security
        .requests
        .max_filter_in_values
        .unwrap_or(DEFAULT_MAX_FILTER_IN_VALUES);
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
            let impl_tokens = expand_resource_impl_with_options(
                resource,
                &service.resources,
                Some(&service.authorization),
                max_filter_in_values,
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

fn authorization_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
    let model = super::authorization::compile_service_authorization(service);
    authorization_model_tokens(&model, runtime_crate)
}

fn authorization_management_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
    let enabled = service.authorization.management_api.enabled;
    let mount = Literal::string(&service.authorization.management_api.mount);
    quote!(#runtime_crate::core::authorization::AuthorizationManagementApiConfig {
        enabled: #enabled,
        mount: #mount.to_owned(),
    })
}

fn authorization_model_tokens(model: &AuthorizationModel, runtime_crate: &Path) -> TokenStream {
    let management_enabled = model.contract.management_api.enabled;
    let management_mount = Literal::string(&model.contract.management_api.mount);
    let scopes = model.contract.scopes.iter().map(|scope| {
        let name = Literal::string(&scope.name);
        let description = option_string_tokens(scope.description.as_deref());
        let parent = option_string_tokens(scope.parent.as_deref());
        quote!(#runtime_crate::core::authorization::AuthorizationScope {
            name: #name.to_owned(),
            description: #description,
            parent: #parent,
        })
    });
    let permissions = model.contract.permissions.iter().map(|permission| {
        let name = Literal::string(&permission.name);
        let description = option_string_tokens(permission.description.as_deref());
        let actions = permission
            .actions
            .iter()
            .map(|action| authorization_action_tokens(*action, runtime_crate));
        let resources = permission.resources.iter().map(|resource| {
            let resource = Literal::string(resource);
            quote!(#resource.to_owned())
        });
        let scopes = permission.scopes.iter().map(|scope| {
            let scope = Literal::string(scope);
            quote!(#scope.to_owned())
        });
        quote!(#runtime_crate::core::authorization::AuthorizationPermission {
            name: #name.to_owned(),
            description: #description,
            actions: vec![#(#actions),*],
            resources: vec![#(#resources),*],
            scopes: vec![#(#scopes),*],
        })
    });
    let templates = model.contract.templates.iter().map(|template| {
        let name = Literal::string(&template.name);
        let description = option_string_tokens(template.description.as_deref());
        let permissions = template.permissions.iter().map(|permission| {
            let permission = Literal::string(permission);
            quote!(#permission.to_owned())
        });
        let scopes = template.scopes.iter().map(|scope| {
            let scope = Literal::string(scope);
            quote!(#scope.to_owned())
        });
        quote!(#runtime_crate::core::authorization::AuthorizationTemplate {
            name: #name.to_owned(),
            description: #description,
            permissions: vec![#(#permissions),*],
            scopes: vec![#(#scopes),*],
        })
    });
    let hybrid_resources = model
        .contract
        .hybrid_enforcement
        .resources
        .iter()
        .map(|resource| {
            let resource_name = Literal::string(&resource.resource);
            let scope = Literal::string(&resource.scope);
            let scope_field = Literal::string(&resource.scope_field);
            let item = resource.scope_sources.item;
            let collection_filter = resource.scope_sources.collection_filter;
            let nested_parent = resource.scope_sources.nested_parent;
            let create_payload = resource.scope_sources.create_payload;
            let actions = resource
                .actions
                .iter()
                .map(|action| authorization_action_tokens(*action, runtime_crate));
            quote!(#runtime_crate::core::authorization::AuthorizationHybridResource {
                resource: #resource_name.to_owned(),
                scope: #scope.to_owned(),
                scope_field: #scope_field.to_owned(),
                scope_sources: #runtime_crate::core::authorization::AuthorizationHybridScopeSources {
                    item: #item,
                    collection_filter: #collection_filter,
                    nested_parent: #nested_parent,
                    create_payload: #create_payload,
                },
                actions: vec![#(#actions),*],
            })
        });
    let resources = model
        .resources
        .iter()
        .map(|resource| resource_authorization_tokens(resource, runtime_crate));

    quote! {
        #runtime_crate::core::authorization::AuthorizationModel {
            contract: #runtime_crate::core::authorization::AuthorizationContract {
                scopes: vec![#(#scopes),*],
                permissions: vec![#(#permissions),*],
                templates: vec![#(#templates),*],
                hybrid_enforcement: #runtime_crate::core::authorization::AuthorizationHybridEnforcementConfig {
                    resources: vec![#(#hybrid_resources),*],
                },
                management_api: #runtime_crate::core::authorization::AuthorizationManagementApiConfig {
                    enabled: #management_enabled,
                    mount: #management_mount.to_owned(),
                },
            },
            resources: vec![#(#resources),*],
        }
    }
}

fn resource_authorization_tokens(
    resource: &ResourceAuthorization,
    runtime_crate: &Path,
) -> TokenStream {
    let resource_id = Literal::string(&resource.id);
    let resource_name = Literal::string(&resource.resource);
    let table = Literal::string(&resource.table);
    let admin_bypass = resource.admin_bypass;
    let actions = resource
        .actions
        .iter()
        .map(|action| action_authorization_tokens(action, runtime_crate));

    quote! {
        #runtime_crate::core::authorization::ResourceAuthorization {
            id: #resource_id.to_owned(),
            resource: #resource_name.to_owned(),
            table: #table.to_owned(),
            admin_bypass: #admin_bypass,
            actions: vec![#(#actions),*],
        }
    }
}

fn action_authorization_tokens(action: &ActionAuthorization, runtime_crate: &Path) -> TokenStream {
    let action_id = Literal::string(&action.id);
    let action_tokens = authorization_action_tokens(action.action, runtime_crate);
    let role_rule_id = option_string_tokens(action.role_rule_id.as_deref());
    let required_role = option_string_tokens(action.required_role.as_deref());
    let filter = option_condition_tokens(action.filter.as_ref(), runtime_crate);
    let assignments = action
        .assignments
        .iter()
        .map(|assignment| assignment_tokens(assignment, runtime_crate));

    quote! {
        #runtime_crate::core::authorization::ActionAuthorization {
            id: #action_id.to_owned(),
            action: #action_tokens,
            role_rule_id: #role_rule_id,
            required_role: #required_role,
            filter: #filter,
            assignments: vec![#(#assignments),*],
        }
    }
}

fn option_condition_tokens(
    condition: Option<&AuthorizationCondition>,
    runtime_crate: &Path,
) -> TokenStream {
    match condition {
        Some(condition) => {
            let condition = condition_tokens(condition, runtime_crate);
            quote!(Some(#condition))
        }
        None => quote!(None),
    }
}

fn condition_tokens(condition: &AuthorizationCondition, runtime_crate: &Path) -> TokenStream {
    match condition {
        AuthorizationCondition::Match(rule) => {
            let rule = match_tokens(rule, runtime_crate);
            quote!(#runtime_crate::core::authorization::AuthorizationCondition::Match(#rule))
        }
        AuthorizationCondition::All { id, conditions } => {
            let id = Literal::string(id);
            let conditions = conditions
                .iter()
                .map(|condition| condition_tokens(condition, runtime_crate));
            quote!(#runtime_crate::core::authorization::AuthorizationCondition::All {
                id: #id.to_owned(),
                conditions: vec![#(#conditions),*],
            })
        }
        AuthorizationCondition::Any { id, conditions } => {
            let id = Literal::string(id);
            let conditions = conditions
                .iter()
                .map(|condition| condition_tokens(condition, runtime_crate));
            quote!(#runtime_crate::core::authorization::AuthorizationCondition::Any {
                id: #id.to_owned(),
                conditions: vec![#(#conditions),*],
            })
        }
        AuthorizationCondition::Not { id, condition } => {
            let id = Literal::string(id);
            let condition = condition_tokens(condition, runtime_crate);
            quote!(#runtime_crate::core::authorization::AuthorizationCondition::Not {
                id: #id.to_owned(),
                condition: Box::new(#condition),
            })
        }
        AuthorizationCondition::Exists {
            id,
            resource,
            table,
            conditions,
        } => {
            let id = Literal::string(id);
            let resource = Literal::string(resource);
            let table = Literal::string(table);
            let conditions = conditions
                .iter()
                .map(|condition| exists_condition_tokens(condition, runtime_crate));
            quote!(#runtime_crate::core::authorization::AuthorizationCondition::Exists {
                id: #id.to_owned(),
                resource: #resource.to_owned(),
                table: #table.to_owned(),
                conditions: vec![#(#conditions),*],
            })
        }
    }
}

fn exists_condition_tokens(
    condition: &AuthorizationExistsCondition,
    runtime_crate: &Path,
) -> TokenStream {
    match condition {
        AuthorizationExistsCondition::Match(rule) => {
            let rule = match_tokens(rule, runtime_crate);
            quote!(#runtime_crate::core::authorization::AuthorizationExistsCondition::Match(#rule))
        }
        AuthorizationExistsCondition::CurrentRowField {
            id,
            field,
            row_field,
        } => {
            let id = Literal::string(id);
            let field = Literal::string(field);
            let row_field = Literal::string(row_field);
            quote!(#runtime_crate::core::authorization::AuthorizationExistsCondition::CurrentRowField {
                id: #id.to_owned(),
                field: #field.to_owned(),
                row_field: #row_field.to_owned(),
            })
        }
        AuthorizationExistsCondition::All { id, conditions } => {
            let id = Literal::string(id);
            let conditions = conditions
                .iter()
                .map(|condition| exists_condition_tokens(condition, runtime_crate));
            quote!(#runtime_crate::core::authorization::AuthorizationExistsCondition::All {
                id: #id.to_owned(),
                conditions: vec![#(#conditions),*],
            })
        }
        AuthorizationExistsCondition::Any { id, conditions } => {
            let id = Literal::string(id);
            let conditions = conditions
                .iter()
                .map(|condition| exists_condition_tokens(condition, runtime_crate));
            quote!(#runtime_crate::core::authorization::AuthorizationExistsCondition::Any {
                id: #id.to_owned(),
                conditions: vec![#(#conditions),*],
            })
        }
        AuthorizationExistsCondition::Not { id, condition } => {
            let id = Literal::string(id);
            let condition = exists_condition_tokens(condition, runtime_crate);
            quote!(#runtime_crate::core::authorization::AuthorizationExistsCondition::Not {
                id: #id.to_owned(),
                condition: Box::new(#condition),
            })
        }
    }
}

fn match_tokens(rule: &AuthorizationMatch, runtime_crate: &Path) -> TokenStream {
    let id = Literal::string(&rule.id);
    let field = Literal::string(&rule.field);
    let operator = authorization_operator_tokens(rule.operator, runtime_crate);
    let source = optional_value_source_tokens(rule.source.as_ref(), runtime_crate);

    quote! {
        #runtime_crate::core::authorization::AuthorizationMatch {
            id: #id.to_owned(),
            field: #field.to_owned(),
            operator: #operator,
            source: #source,
        }
    }
}

fn assignment_tokens(assignment: &AuthorizationAssignment, runtime_crate: &Path) -> TokenStream {
    let id = Literal::string(&assignment.id);
    let field = Literal::string(&assignment.field);
    let source = value_source_tokens(&assignment.source, runtime_crate);

    quote! {
        #runtime_crate::core::authorization::AuthorizationAssignment {
            id: #id.to_owned(),
            field: #field.to_owned(),
            source: #source,
        }
    }
}

fn authorization_action_tokens(
    action: crate::authorization::AuthorizationAction,
    runtime_crate: &Path,
) -> TokenStream {
    match action {
        crate::authorization::AuthorizationAction::Read => {
            quote!(#runtime_crate::core::authorization::AuthorizationAction::Read)
        }
        crate::authorization::AuthorizationAction::Create => {
            quote!(#runtime_crate::core::authorization::AuthorizationAction::Create)
        }
        crate::authorization::AuthorizationAction::Update => {
            quote!(#runtime_crate::core::authorization::AuthorizationAction::Update)
        }
        crate::authorization::AuthorizationAction::Delete => {
            quote!(#runtime_crate::core::authorization::AuthorizationAction::Delete)
        }
    }
}

fn authorization_operator_tokens(
    operator: AuthorizationOperator,
    runtime_crate: &Path,
) -> TokenStream {
    match operator {
        AuthorizationOperator::Equals => {
            quote!(#runtime_crate::core::authorization::AuthorizationOperator::Equals)
        }
        AuthorizationOperator::IsNull => {
            quote!(#runtime_crate::core::authorization::AuthorizationOperator::IsNull)
        }
        AuthorizationOperator::IsNotNull => {
            quote!(#runtime_crate::core::authorization::AuthorizationOperator::IsNotNull)
        }
    }
}

fn value_source_tokens(source: &AuthorizationValueSource, runtime_crate: &Path) -> TokenStream {
    match source {
        AuthorizationValueSource::UserId => {
            quote!(#runtime_crate::core::authorization::AuthorizationValueSource::UserId)
        }
        AuthorizationValueSource::Claim { name, ty } => {
            let name = Literal::string(name);
            let ty = auth_claim_type_tokens(*ty, runtime_crate);
            quote!(#runtime_crate::core::authorization::AuthorizationValueSource::Claim {
                name: #name.to_owned(),
                ty: #ty,
            })
        }
        AuthorizationValueSource::InputField { name } => {
            let name = Literal::string(name);
            quote!(#runtime_crate::core::authorization::AuthorizationValueSource::InputField {
                name: #name.to_owned(),
            })
        }
        AuthorizationValueSource::Literal { value } => {
            let value = authorization_literal_value_tokens(value, runtime_crate);
            quote!(#runtime_crate::core::authorization::AuthorizationValueSource::Literal {
                value: #value,
            })
        }
    }
}

fn authorization_literal_value_tokens(
    value: &AuthorizationLiteralValue,
    runtime_crate: &Path,
) -> TokenStream {
    match value {
        AuthorizationLiteralValue::String(value) => {
            let value = Literal::string(value);
            quote!(#runtime_crate::core::authorization::AuthorizationLiteralValue::String(
                #value.to_owned(),
            ))
        }
        AuthorizationLiteralValue::I64(value) => {
            let value = Literal::i64_unsuffixed(*value);
            quote!(#runtime_crate::core::authorization::AuthorizationLiteralValue::I64(#value))
        }
        AuthorizationLiteralValue::Bool(value) => quote!(
            #runtime_crate::core::authorization::AuthorizationLiteralValue::Bool(#value)
        ),
    }
}

fn optional_value_source_tokens(
    source: Option<&AuthorizationValueSource>,
    runtime_crate: &Path,
) -> TokenStream {
    match source {
        Some(source) => {
            let source = value_source_tokens(source, runtime_crate);
            quote!(Some(#source))
        }
        None => quote!(None),
    }
}

fn auth_claim_type_tokens(ty: crate::auth::AuthClaimType, runtime_crate: &Path) -> TokenStream {
    match ty {
        crate::auth::AuthClaimType::I64 => {
            quote!(#runtime_crate::core::auth::AuthClaimType::I64)
        }
        crate::auth::AuthClaimType::String => {
            quote!(#runtime_crate::core::auth::AuthClaimType::String)
        }
        crate::auth::AuthClaimType::Bool => {
            quote!(#runtime_crate::core::auth::AuthClaimType::Bool)
        }
    }
}

fn database_resilience_profile_tokens(
    profile: DatabaseResilienceProfile,
    runtime_crate: &Path,
) -> TokenStream {
    match profile {
        DatabaseResilienceProfile::SingleNode => {
            quote!(#runtime_crate::core::database::DatabaseResilienceProfile::SingleNode)
        }
        DatabaseResilienceProfile::Pitr => {
            quote!(#runtime_crate::core::database::DatabaseResilienceProfile::Pitr)
        }
        DatabaseResilienceProfile::Ha => {
            quote!(#runtime_crate::core::database::DatabaseResilienceProfile::Ha)
        }
    }
}

fn database_backup_mode_tokens(mode: DatabaseBackupMode, runtime_crate: &Path) -> TokenStream {
    match mode {
        DatabaseBackupMode::Snapshot => {
            quote!(#runtime_crate::core::database::DatabaseBackupMode::Snapshot)
        }
        DatabaseBackupMode::Logical => {
            quote!(#runtime_crate::core::database::DatabaseBackupMode::Logical)
        }
        DatabaseBackupMode::Physical => {
            quote!(#runtime_crate::core::database::DatabaseBackupMode::Physical)
        }
        DatabaseBackupMode::Pitr => {
            quote!(#runtime_crate::core::database::DatabaseBackupMode::Pitr)
        }
    }
}

fn database_backup_target_tokens(
    target: DatabaseBackupTarget,
    runtime_crate: &Path,
) -> TokenStream {
    match target {
        DatabaseBackupTarget::Local => {
            quote!(#runtime_crate::core::database::DatabaseBackupTarget::Local)
        }
        DatabaseBackupTarget::S3 => {
            quote!(#runtime_crate::core::database::DatabaseBackupTarget::S3)
        }
        DatabaseBackupTarget::Gcs => {
            quote!(#runtime_crate::core::database::DatabaseBackupTarget::Gcs)
        }
        DatabaseBackupTarget::AzureBlob => {
            quote!(#runtime_crate::core::database::DatabaseBackupTarget::AzureBlob)
        }
        DatabaseBackupTarget::Custom => {
            quote!(#runtime_crate::core::database::DatabaseBackupTarget::Custom)
        }
    }
}

fn database_replication_mode_tokens(
    mode: DatabaseReplicationMode,
    runtime_crate: &Path,
) -> TokenStream {
    match mode {
        DatabaseReplicationMode::None => {
            quote!(#runtime_crate::core::database::DatabaseReplicationMode::None)
        }
        DatabaseReplicationMode::ReadReplica => {
            quote!(#runtime_crate::core::database::DatabaseReplicationMode::ReadReplica)
        }
        DatabaseReplicationMode::HotStandby => {
            quote!(#runtime_crate::core::database::DatabaseReplicationMode::HotStandby)
        }
        DatabaseReplicationMode::ManagedExternal => {
            quote!(#runtime_crate::core::database::DatabaseReplicationMode::ManagedExternal)
        }
    }
}

fn database_read_routing_mode_tokens(
    mode: DatabaseReadRoutingMode,
    runtime_crate: &Path,
) -> TokenStream {
    match mode {
        DatabaseReadRoutingMode::Off => {
            quote!(#runtime_crate::core::database::DatabaseReadRoutingMode::Off)
        }
        DatabaseReadRoutingMode::Explicit => {
            quote!(#runtime_crate::core::database::DatabaseReadRoutingMode::Explicit)
        }
    }
}

fn database_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
    let engine = match &service.database.engine {
        DatabaseEngine::Sqlx => {
            quote!(#runtime_crate::core::database::DatabaseEngine::Sqlx)
        }
        DatabaseEngine::TursoLocal(engine) => {
            let path = Literal::string(&engine.path);
            let encryption_key =
                option_secret_ref_tokens(engine.encryption_key.as_ref(), runtime_crate);
            quote!(
                #runtime_crate::core::database::DatabaseEngine::TursoLocal(
                    #runtime_crate::core::database::TursoLocalConfig {
                        path: #path.to_owned(),
                        encryption_key: #encryption_key,
                    }
                )
            )
        }
    };
    let resilience = match &service.database.resilience {
        Some(resilience) => {
            let profile = database_resilience_profile_tokens(resilience.profile, runtime_crate);
            let backup = match &resilience.backup {
                Some(backup) => {
                    let required = backup.required;
                    let verify_restore = backup.verify_restore;
                    let mode = database_backup_mode_tokens(backup.mode, runtime_crate);
                    let target = database_backup_target_tokens(backup.target, runtime_crate);
                    let max_age = match backup.max_age.as_deref() {
                        Some(value) => {
                            let value = Literal::string(value);
                            quote!(Some(#value.to_owned()))
                        }
                        None => quote!(None),
                    };
                    let encryption_key =
                        option_secret_ref_tokens(backup.encryption_key.as_ref(), runtime_crate);
                    let retention = match &backup.retention {
                        Some(retention) => {
                            let daily = match retention.daily {
                                Some(value) => quote!(Some(#value)),
                                None => quote!(None),
                            };
                            let weekly = match retention.weekly {
                                Some(value) => quote!(Some(#value)),
                                None => quote!(None),
                            };
                            let monthly = match retention.monthly {
                                Some(value) => quote!(Some(#value)),
                                None => quote!(None),
                            };
                            quote!(Some(#runtime_crate::core::database::DatabaseBackupRetention {
                                daily: #daily,
                                weekly: #weekly,
                                monthly: #monthly,
                            }))
                        }
                        None => quote!(None),
                    };
                    quote!(Some(#runtime_crate::core::database::DatabaseBackupConfig {
                        required: #required,
                        mode: #mode,
                        target: #target,
                        verify_restore: #verify_restore,
                        max_age: #max_age,
                        encryption_key: #encryption_key,
                        retention: #retention,
                    }))
                }
                None => quote!(None),
            };
            let replication = match &resilience.replication {
                Some(replication) => {
                    let mode = database_replication_mode_tokens(replication.mode, runtime_crate);
                    let read_routing =
                        database_read_routing_mode_tokens(replication.read_routing, runtime_crate);
                    let read_url =
                        option_secret_ref_tokens(replication.read_url.as_ref(), runtime_crate);
                    let max_lag = match replication.max_lag.as_deref() {
                        Some(value) => {
                            let value = Literal::string(value);
                            quote!(Some(#value.to_owned()))
                        }
                        None => quote!(None),
                    };
                    let replicas_expected = match replication.replicas_expected {
                        Some(value) => quote!(Some(#value)),
                        None => quote!(None),
                    };
                    quote!(Some(#runtime_crate::core::database::DatabaseReplicationConfig {
                        mode: #mode,
                        read_routing: #read_routing,
                        read_url: #read_url,
                        max_lag: #max_lag,
                        replicas_expected: #replicas_expected,
                    }))
                }
                None => quote!(None),
            };

            quote!(Some(#runtime_crate::core::database::DatabaseResilienceConfig {
                profile: #profile,
                backup: #backup,
                replication: #replication,
            }))
        }
        None => quote!(None),
    };

    quote!(#runtime_crate::core::database::DatabaseConfig {
        engine: #engine,
        resilience: #resilience,
    })
}

fn logging_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
    let filter_env = Literal::string(&service.logging.filter_env);
    let default_filter = Literal::string(&service.logging.default_filter);
    let timestamp = match service.logging.timestamp {
        LogTimestampPrecision::None => {
            quote!(#runtime_crate::core::logging::LogTimestampPrecision::None)
        }
        LogTimestampPrecision::Seconds => {
            quote!(#runtime_crate::core::logging::LogTimestampPrecision::Seconds)
        }
        LogTimestampPrecision::Millis => {
            quote!(#runtime_crate::core::logging::LogTimestampPrecision::Millis)
        }
        LogTimestampPrecision::Micros => {
            quote!(#runtime_crate::core::logging::LogTimestampPrecision::Micros)
        }
        LogTimestampPrecision::Nanos => {
            quote!(#runtime_crate::core::logging::LogTimestampPrecision::Nanos)
        }
    };

    quote! {
        #runtime_crate::core::logging::LoggingConfig {
            filter_env: #filter_env.to_owned(),
            default_filter: #default_filter.to_owned(),
            timestamp: #timestamp,
        }
    }
}

fn tls_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
    let cert_path = option_string_tokens(service.tls.cert_path.as_deref());
    let key_path = option_string_tokens(service.tls.key_path.as_deref());
    let cert_path_env = option_string_tokens(service.tls.cert_path_env.as_deref());
    let key_path_env = option_string_tokens(service.tls.key_path_env.as_deref());

    quote! {
        #runtime_crate::core::tls::TlsConfig {
            cert_path: #cert_path,
            key_path: #key_path,
            cert_path_env: #cert_path_env,
            key_path_env: #key_path_env,
        }
    }
}

fn runtime_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
    let compression_enabled = service.runtime.compression.enabled;
    let static_precompressed = service.runtime.compression.static_precompressed;

    quote! {
        #runtime_crate::core::runtime::RuntimeConfig {
            compression: #runtime_crate::core::runtime::CompressionConfig {
                enabled: #compression_enabled,
                static_precompressed: #static_precompressed,
            },
        }
    }
}

fn storage_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
    let backends = service.storage.backends.iter().map(|backend| {
        let name = Literal::string(&backend.name);
        let root_dir = Literal::string(&backend.root_dir);
        let resolved_root_dir = Literal::string(&backend.resolved_root_dir);
        let kind = match backend.kind {
            crate::storage::StorageBackendKind::Local => {
                quote!(#runtime_crate::core::storage::StorageBackendKind::Local)
            }
        };
        quote! {
            #runtime_crate::core::storage::StorageBackendConfig {
                name: #name.to_owned(),
                kind: #kind,
                root_dir: #root_dir.to_owned(),
                resolved_root_dir: #resolved_root_dir.to_owned(),
            }
        }
    });
    let public_mounts = service.storage.public_mounts.iter().map(|mount| {
        let mount_path = Literal::string(&mount.mount_path);
        let backend = Literal::string(&mount.backend);
        let key_prefix = Literal::string(&mount.key_prefix);
        let cache = match mount.cache {
            crate::static_files::StaticCacheProfile::NoStore => {
                quote!(#runtime_crate::core::static_files::StaticCacheProfile::NoStore)
            }
            crate::static_files::StaticCacheProfile::Revalidate => {
                quote!(#runtime_crate::core::static_files::StaticCacheProfile::Revalidate)
            }
            crate::static_files::StaticCacheProfile::Immutable => {
                quote!(#runtime_crate::core::static_files::StaticCacheProfile::Immutable)
            }
        };
        quote! {
            #runtime_crate::core::storage::StoragePublicMount {
                mount_path: #mount_path.to_owned(),
                backend: #backend.to_owned(),
                key_prefix: #key_prefix.to_owned(),
                cache: #cache,
            }
        }
    });
    let uploads = service.storage.uploads.iter().map(|upload| {
        let name = Literal::string(&upload.name);
        let path = Literal::string(&upload.path);
        let backend = Literal::string(&upload.backend);
        let key_prefix = Literal::string(&upload.key_prefix);
        let max_bytes = upload.max_bytes;
        let require_auth = upload.require_auth;
        let roles = upload.roles.iter().map(|role| {
            let role = Literal::string(role);
            quote!(#role.to_owned())
        });

        quote! {
            #runtime_crate::core::storage::StorageUploadEndpoint {
                name: #name.to_owned(),
                path: #path.to_owned(),
                backend: #backend.to_owned(),
                key_prefix: #key_prefix.to_owned(),
                max_bytes: #max_bytes,
                require_auth: #require_auth,
                roles: vec![#(#roles),*],
            }
        }
    });
    let s3_compat = if let Some(s3_compat) = &service.storage.s3_compat {
        let mount_path = Literal::string(&s3_compat.mount_path);
        let buckets = s3_compat.buckets.iter().map(|bucket| {
            let name = Literal::string(&bucket.name);
            let backend = Literal::string(&bucket.backend);
            let key_prefix = Literal::string(&bucket.key_prefix);
            quote! {
                #runtime_crate::core::storage::StorageS3CompatBucket {
                    name: #name.to_owned(),
                    backend: #backend.to_owned(),
                    key_prefix: #key_prefix.to_owned(),
                }
            }
        });
        quote! {
            Some(#runtime_crate::core::storage::StorageS3CompatConfig {
                mount_path: #mount_path.to_owned(),
                buckets: vec![#(#buckets),*],
            })
        }
    } else {
        quote!(None)
    };

    quote! {
        #runtime_crate::core::storage::StorageConfig {
            backends: vec![#(#backends),*],
            public_mounts: vec![#(#public_mounts),*],
            uploads: vec![#(#uploads),*],
            s3_compat: #s3_compat,
        }
    }
}

fn security_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
    let security = &service.security;
    let json_max_bytes = option_usize_tokens(security.requests.json_max_bytes);
    let max_filter_in_values = option_usize_tokens(security.requests.max_filter_in_values);
    let cors_origins = vec_string_tokens(&security.cors.origins);
    let cors_origins_env = option_string_tokens(security.cors.origins_env.as_deref());
    let cors_allow_methods = vec_string_tokens(&security.cors.allow_methods);
    let cors_allow_headers = vec_string_tokens(&security.cors.allow_headers);
    let cors_expose_headers = vec_string_tokens(&security.cors.expose_headers);
    let cors_max_age_seconds = option_usize_tokens(security.cors.max_age_seconds);
    let cors_allow_credentials = security.cors.allow_credentials;
    let trusted_proxy_ips = vec_string_tokens(&security.trusted_proxies.proxies);
    let trusted_proxy_ips_env =
        option_string_tokens(security.trusted_proxies.proxies_env.as_deref());
    let login_rate_limit = option_rate_limit_tokens(security.rate_limits.login, runtime_crate);
    let register_rate_limit =
        option_rate_limit_tokens(security.rate_limits.register, runtime_crate);
    let frame_options = match security.headers.frame_options {
        Some(FrameOptions::Deny) => {
            quote!(Some(#runtime_crate::core::security::FrameOptions::Deny))
        }
        Some(FrameOptions::SameOrigin) => {
            quote!(Some(#runtime_crate::core::security::FrameOptions::SameOrigin))
        }
        None => quote!(None),
    };
    let referrer_policy = match security.headers.referrer_policy {
        Some(ReferrerPolicy::NoReferrer) => {
            quote!(Some(#runtime_crate::core::security::ReferrerPolicy::NoReferrer))
        }
        Some(ReferrerPolicy::SameOrigin) => {
            quote!(Some(#runtime_crate::core::security::ReferrerPolicy::SameOrigin))
        }
        Some(ReferrerPolicy::StrictOriginWhenCrossOrigin) => {
            quote!(Some(#runtime_crate::core::security::ReferrerPolicy::StrictOriginWhenCrossOrigin))
        }
        Some(ReferrerPolicy::NoReferrerWhenDowngrade) => {
            quote!(Some(#runtime_crate::core::security::ReferrerPolicy::NoReferrerWhenDowngrade))
        }
        Some(ReferrerPolicy::Origin) => {
            quote!(Some(#runtime_crate::core::security::ReferrerPolicy::Origin))
        }
        Some(ReferrerPolicy::OriginWhenCrossOrigin) => {
            quote!(Some(#runtime_crate::core::security::ReferrerPolicy::OriginWhenCrossOrigin))
        }
        Some(ReferrerPolicy::UnsafeUrl) => {
            quote!(Some(#runtime_crate::core::security::ReferrerPolicy::UnsafeUrl))
        }
        None => quote!(None),
    };
    let hsts = if let Some(hsts) = &security.headers.hsts {
        let max_age_seconds = Literal::u64_unsuffixed(hsts.max_age_seconds);
        let include_subdomains = hsts.include_subdomains;
        quote! {
            Some(#runtime_crate::core::security::Hsts {
                max_age_seconds: #max_age_seconds,
                include_subdomains: #include_subdomains,
            })
        }
    } else {
        quote!(None)
    };
    let issuer = option_string_tokens(security.auth.issuer.as_deref());
    let audience = option_string_tokens(security.auth.audience.as_deref());
    let access_token_ttl_seconds = Literal::i64_unsuffixed(security.auth.access_token_ttl_seconds);
    let require_email_verification = security.auth.require_email_verification;
    let verification_token_ttl_seconds =
        Literal::i64_unsuffixed(security.auth.verification_token_ttl_seconds);
    let password_reset_token_ttl_seconds =
        Literal::i64_unsuffixed(security.auth.password_reset_token_ttl_seconds);
    let jwt = option_auth_jwt_tokens(security.auth.jwt.as_ref(), runtime_crate);
    let jwt_secret = option_secret_ref_tokens(security.auth.jwt_secret.as_ref(), runtime_crate);
    let auth_claims = auth_claim_mappings_tokens(&security.auth.claims, runtime_crate);
    let session_cookie =
        option_session_cookie_tokens(security.auth.session_cookie.as_ref(), runtime_crate);
    let email = option_auth_email_tokens(security.auth.email.as_ref(), runtime_crate);
    let portal = option_auth_ui_page_tokens(security.auth.portal.as_ref(), runtime_crate);
    let admin_dashboard =
        option_auth_ui_page_tokens(security.auth.admin_dashboard.as_ref(), runtime_crate);
    let content_type_options = security.headers.content_type_options;
    let access_default_read = match security.access.default_read {
        DefaultReadAccess::Inferred => {
            quote!(#runtime_crate::core::security::DefaultReadAccess::Inferred)
        }
        DefaultReadAccess::Authenticated => {
            quote!(#runtime_crate::core::security::DefaultReadAccess::Authenticated)
        }
    };

    quote! {
        #runtime_crate::core::security::SecurityConfig {
            requests: #runtime_crate::core::security::RequestSecurity {
                json_max_bytes: #json_max_bytes,
                max_filter_in_values: #max_filter_in_values,
            },
            cors: #runtime_crate::core::security::CorsSecurity {
                origins: #cors_origins,
                origins_env: #cors_origins_env,
                allow_credentials: #cors_allow_credentials,
                allow_methods: #cors_allow_methods,
                allow_headers: #cors_allow_headers,
                expose_headers: #cors_expose_headers,
                max_age_seconds: #cors_max_age_seconds,
            },
            trusted_proxies: #runtime_crate::core::security::TrustedProxySecurity {
                proxies: #trusted_proxy_ips,
                proxies_env: #trusted_proxy_ips_env,
            },
            rate_limits: #runtime_crate::core::security::RateLimitSecurity {
                login: #login_rate_limit,
                register: #register_rate_limit,
            },
            access: #runtime_crate::core::security::AccessSecurity {
                default_read: #access_default_read,
            },
            headers: #runtime_crate::core::security::HeaderSecurity {
                frame_options: #frame_options,
                content_type_options: #content_type_options,
                referrer_policy: #referrer_policy,
                hsts: #hsts,
            },
            auth: #runtime_crate::core::auth::AuthSettings {
                issuer: #issuer,
                audience: #audience,
                access_token_ttl_seconds: #access_token_ttl_seconds,
                require_email_verification: #require_email_verification,
                verification_token_ttl_seconds: #verification_token_ttl_seconds,
                password_reset_token_ttl_seconds: #password_reset_token_ttl_seconds,
                jwt: #jwt,
                jwt_secret: #jwt_secret,
                claims: #auth_claims,
                session_cookie: #session_cookie,
                email: #email,
                portal: #portal,
                admin_dashboard: #admin_dashboard,
            },
        }
    }
}

fn option_string_tokens(value: Option<&str>) -> TokenStream {
    match value {
        Some(value) => {
            let value = Literal::string(value);
            quote!(Some(#value.to_owned()))
        }
        None => quote!(None),
    }
}

fn option_usize_tokens(value: Option<usize>) -> TokenStream {
    match value {
        Some(value) => {
            let value = Literal::usize_unsuffixed(value);
            quote!(Some(#value))
        }
        None => quote!(None),
    }
}

fn option_secret_ref_tokens(
    value: Option<&crate::secret::SecretRef>,
    runtime_crate: &Path,
) -> TokenStream {
    match value {
        Some(value) => {
            let secret = secret_ref_tokens(value, runtime_crate);
            quote!(Some(#secret))
        }
        None => quote!(None),
    }
}

fn secret_ref_tokens(value: &crate::secret::SecretRef, runtime_crate: &Path) -> TokenStream {
    match value {
        crate::secret::SecretRef::Env { var_name } => {
            let var_name = Literal::string(var_name);
            quote!(#runtime_crate::core::secret::SecretRef::Env {
                var_name: #var_name.to_owned(),
            })
        }
        crate::secret::SecretRef::EnvOrFile { var_name } => {
            let var_name = Literal::string(var_name);
            quote!(#runtime_crate::core::secret::SecretRef::EnvOrFile {
                var_name: #var_name.to_owned(),
            })
        }
        crate::secret::SecretRef::SystemdCredential { id } => {
            let id = Literal::string(id);
            quote!(#runtime_crate::core::secret::SecretRef::SystemdCredential {
                id: #id.to_owned(),
            })
        }
        crate::secret::SecretRef::External { provider, locator } => {
            let provider = Literal::string(provider);
            let locator = Literal::string(locator);
            quote!(#runtime_crate::core::secret::SecretRef::External {
                provider: #provider.to_owned(),
                locator: #locator.to_owned(),
            })
        }
        crate::secret::SecretRef::File { path } => {
            let path = Literal::string(&path.to_string_lossy());
            quote!(#runtime_crate::core::secret::SecretRef::File {
                path: ::std::path::PathBuf::from(#path),
            })
        }
    }
}

fn option_auth_jwt_tokens(
    value: Option<&crate::auth::AuthJwtSettings>,
    runtime_crate: &Path,
) -> TokenStream {
    match value {
        Some(value) => {
            let signing_key = secret_ref_tokens(&value.signing_key, runtime_crate);
            let active_kid = option_string_tokens(value.active_kid.as_deref());
            let algorithm = match value.algorithm {
                crate::auth::AuthJwtAlgorithm::Hs256 => {
                    quote!(#runtime_crate::core::auth::AuthJwtAlgorithm::Hs256)
                }
                crate::auth::AuthJwtAlgorithm::Hs384 => {
                    quote!(#runtime_crate::core::auth::AuthJwtAlgorithm::Hs384)
                }
                crate::auth::AuthJwtAlgorithm::Hs512 => {
                    quote!(#runtime_crate::core::auth::AuthJwtAlgorithm::Hs512)
                }
                crate::auth::AuthJwtAlgorithm::Es256 => {
                    quote!(#runtime_crate::core::auth::AuthJwtAlgorithm::Es256)
                }
                crate::auth::AuthJwtAlgorithm::Es384 => {
                    quote!(#runtime_crate::core::auth::AuthJwtAlgorithm::Es384)
                }
                crate::auth::AuthJwtAlgorithm::EdDsa => {
                    quote!(#runtime_crate::core::auth::AuthJwtAlgorithm::EdDsa)
                }
            };
            let verification_keys = value.verification_keys.iter().map(|key| {
                let kid = Literal::string(&key.kid);
                let key_ref = secret_ref_tokens(&key.key, runtime_crate);
                quote! {
                    #runtime_crate::core::auth::AuthJwtVerificationKey {
                        kid: #kid.to_owned(),
                        key: #key_ref,
                    }
                }
            });
            quote! {
                Some(#runtime_crate::core::auth::AuthJwtSettings {
                    algorithm: #algorithm,
                    active_kid: #active_kid,
                    signing_key: #signing_key,
                    verification_keys: vec![#(#verification_keys),*],
                })
            }
        }
        None => quote!(None),
    }
}

fn auth_claim_mappings_tokens(
    claims: &std::collections::BTreeMap<String, crate::auth::AuthClaimMapping>,
    runtime_crate: &Path,
) -> TokenStream {
    let entries = claims.iter().map(|(claim_name, mapping)| {
        let claim_name = Literal::string(claim_name);
        let column = Literal::string(&mapping.column);
        let ty = match mapping.ty {
            crate::auth::AuthClaimType::I64 => {
                quote!(#runtime_crate::core::auth::AuthClaimType::I64)
            }
            crate::auth::AuthClaimType::String => {
                quote!(#runtime_crate::core::auth::AuthClaimType::String)
            }
            crate::auth::AuthClaimType::Bool => {
                quote!(#runtime_crate::core::auth::AuthClaimType::Bool)
            }
        };
        quote! {
            claims.insert(
                #claim_name.to_owned(),
                #runtime_crate::core::auth::AuthClaimMapping {
                    column: #column.to_owned(),
                    ty: #ty,
                },
            );
        }
    });

    if claims.is_empty() {
        quote!(::std::collections::BTreeMap::new())
    } else {
        quote! {
            {
                let mut claims = ::std::collections::BTreeMap::new();
                #(#entries)*
                claims
            }
        }
    }
}

fn vec_string_tokens(values: &[String]) -> TokenStream {
    let values = values.iter().map(|value| {
        let value = Literal::string(value);
        quote!(#value.to_owned())
    });
    quote!(vec![#(#values),*])
}

fn option_rate_limit_tokens(
    value: Option<crate::security::RateLimitRule>,
    runtime_crate: &Path,
) -> TokenStream {
    match value {
        Some(value) => {
            let requests = Literal::u32_unsuffixed(value.requests);
            let window_seconds = Literal::u64_unsuffixed(value.window_seconds);
            quote! {
                Some(#runtime_crate::core::security::RateLimitRule {
                    requests: #requests,
                    window_seconds: #window_seconds,
                })
            }
        }
        None => quote!(None),
    }
}

fn option_session_cookie_tokens(
    value: Option<&crate::auth::SessionCookieSettings>,
    runtime_crate: &Path,
) -> TokenStream {
    match value {
        Some(value) => {
            let name = Literal::string(&value.name);
            let csrf_cookie_name = Literal::string(&value.csrf_cookie_name);
            let csrf_header_name = Literal::string(&value.csrf_header_name);
            let path = Literal::string(&value.path);
            let secure = value.secure;
            let same_site = match value.same_site {
                crate::auth::SessionCookieSameSite::Lax => {
                    quote!(#runtime_crate::core::auth::SessionCookieSameSite::Lax)
                }
                crate::auth::SessionCookieSameSite::None => {
                    quote!(#runtime_crate::core::auth::SessionCookieSameSite::None)
                }
                crate::auth::SessionCookieSameSite::Strict => {
                    quote!(#runtime_crate::core::auth::SessionCookieSameSite::Strict)
                }
            };
            quote! {
                Some(#runtime_crate::core::auth::SessionCookieSettings {
                    name: #name.to_owned(),
                    csrf_cookie_name: #csrf_cookie_name.to_owned(),
                    csrf_header_name: #csrf_header_name.to_owned(),
                    path: #path.to_owned(),
                    secure: #secure,
                    same_site: #same_site,
                })
            }
        }
        None => quote!(None),
    }
}

fn option_auth_email_tokens(
    value: Option<&crate::auth::AuthEmailSettings>,
    runtime_crate: &Path,
) -> TokenStream {
    match value {
        Some(value) => {
            let from_email = Literal::string(&value.from_email);
            let from_name = option_string_tokens(value.from_name.as_deref());
            let reply_to = option_string_tokens(value.reply_to.as_deref());
            let public_base_url = option_string_tokens(value.public_base_url.as_deref());
            let provider = match &value.provider {
                crate::auth::AuthEmailProvider::Resend {
                    api_key,
                    api_base_url,
                } => {
                    let api_key = secret_ref_tokens(api_key, runtime_crate);
                    let api_base_url = option_string_tokens(api_base_url.as_deref());
                    quote!(
                        #runtime_crate::core::auth::AuthEmailProvider::Resend {
                            api_key: #api_key,
                            api_base_url: #api_base_url,
                        }
                    )
                }
                crate::auth::AuthEmailProvider::Smtp { connection_url } => {
                    let connection_url = secret_ref_tokens(connection_url, runtime_crate);
                    quote!(
                        #runtime_crate::core::auth::AuthEmailProvider::Smtp {
                            connection_url: #connection_url,
                        }
                    )
                }
            };
            quote! {
                Some(#runtime_crate::core::auth::AuthEmailSettings {
                    from_email: #from_email.to_owned(),
                    from_name: #from_name,
                    reply_to: #reply_to,
                    public_base_url: #public_base_url,
                    provider: #provider,
                })
            }
        }
        None => quote!(None),
    }
}

fn option_auth_ui_page_tokens(
    value: Option<&crate::auth::AuthUiPageSettings>,
    runtime_crate: &Path,
) -> TokenStream {
    match value {
        Some(value) => {
            let path = Literal::string(&value.path);
            let title = Literal::string(&value.title);
            quote! {
                Some(#runtime_crate::core::auth::AuthUiPageSettings {
                    path: #path.to_owned(),
                    title: #title.to_owned(),
                })
            }
        }
        None => quote!(None),
    }
}

fn resource_struct_tokens(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    authorization: Option<&AuthorizationContract>,
    runtime_crate: &Path,
) -> TokenStream {
    let struct_ident = &resource.struct_ident;
    let create_ident = format_ident!("{struct_ident}Create");
    let update_ident = format_ident!("{struct_ident}Update");
    let garde_helper_defs = garde_validation_helper_defs(resource, runtime_crate);
    let action_input_structs = resource
        .actions
        .iter()
        .filter_map(|action| resource_action_input_struct_tokens(resource, action, runtime_crate))
        .collect::<Vec<_>>();
    let list_query_tokens = list_query_tokens(resource, resources, runtime_crate);
    let generated_from_row = generated_from_row_tokens(resource, runtime_crate);
    let object_validator_defs = typed_object_validator_defs(resource, runtime_crate);
    let fields = resource.api_fields().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        let rename_attr = serde_rename_attr(field.api_name(), &field.name());
        quote! {
            #rename_attr
            pub #ident: #ty,
        }
    });

    let create_fields = create_payload_fields(resource, authorization)
        .into_iter()
        .map(|field| {
            let ident = &field.field.ident;
            let ty = create_payload_field_ty(&field);
            let rename_attr = serde_rename_attr(field.field.api_name(), &field.field.name());
            let garde_attr = garde_field_attr_tokens(
                field.field,
                create_payload_field_is_optional(&field),
                super::model::is_optional_type(&field.field.ty),
            );
            quote! {
                #rename_attr
                #garde_attr
                pub #ident: #ty,
            }
        });
    let update_fields = update_payload_fields(resource).into_iter().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        let rename_attr = serde_rename_attr(field.api_name(), &field.name());
        let garde_attr =
            garde_field_attr_tokens(field, super::model::is_optional_type(&field.ty), true);
        quote! {
            #rename_attr
            #garde_attr
            pub #ident: #ty,
        }
    });

    match resource.write_style {
        WriteModelStyle::ExistingStructWithDtos => quote! {
            #(#garde_helper_defs)*
            #(#object_validator_defs)*

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize,
                #runtime_crate::garde::Validate
            )]
            #[garde(allow_unvalidated)]
            pub struct #create_ident {
                #(#create_fields)*
            }

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize,
                #runtime_crate::garde::Validate
            )]
            #[garde(allow_unvalidated)]
            pub struct #update_ident {
                #(#update_fields)*
            }

            #(#action_input_structs)*

            #list_query_tokens
        },
        WriteModelStyle::GeneratedStructWithDtos => quote! {
            #(#garde_helper_defs)*
            #(#object_validator_defs)*

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize
            )]
            pub struct #struct_ident {
                #(#fields)*
            }

            #generated_from_row

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize,
                #runtime_crate::garde::Validate
            )]
            #[garde(allow_unvalidated)]
            pub struct #create_ident {
                #(#create_fields)*
            }

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize,
                #runtime_crate::garde::Validate
            )]
            #[garde(allow_unvalidated)]
            pub struct #update_ident {
                #(#update_fields)*
            }

            #(#action_input_structs)*

            #list_query_tokens
        },
    }
}

fn serde_rename_attr(api_name: &str, storage_name: &str) -> TokenStream {
    if api_name == storage_name {
        quote! {}
    } else {
        let api_name = Literal::string(api_name);
        quote!(#[serde(rename = #api_name)])
    }
}

fn garde_validation_error_helper(resource: &ResourceSpec) -> syn::Ident {
    format_ident!(
        "garde_validation_error_{}",
        resource.struct_ident.to_string().to_snake_case()
    )
}

fn prefixed_garde_validation_error_helper(resource: &ResourceSpec) -> syn::Ident {
    format_ident!(
        "prefixed_garde_validation_error_{}",
        resource.struct_ident.to_string().to_snake_case()
    )
}

fn garde_validation_helper_defs(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    let error_helper = garde_validation_error_helper(resource);
    let prefixed_error_helper = prefixed_garde_validation_error_helper(resource);

    vec![
        quote! {
            #[allow(dead_code)]
            fn #error_helper(
                report: #runtime_crate::garde::Report,
            ) -> (Option<String>, String) {
                match report.iter().next() {
                    Some((path, error)) => {
                        let field = path.to_string();
                        let message = error.to_string();
                        if field.is_empty() {
                            (None, message)
                        } else {
                            (
                                Some(field.clone()),
                                format!("Field `{}` {}", field, message),
                            )
                        }
                    }
                    None => (None, "Validation failed".to_owned()),
                }
            }
        },
        quote! {
            #[allow(dead_code)]
            fn #prefixed_error_helper(
                base_path: &str,
                report: #runtime_crate::garde::Report,
            ) -> (String, String) {
                match report.iter().next() {
                    Some((path, error)) => {
                        let suffix = path.to_string();
                        let field_path = if suffix.is_empty() {
                            base_path.to_owned()
                        } else if base_path.is_empty() {
                            suffix
                        } else {
                            format!("{}.{}", base_path, suffix)
                        };
                        (
                            field_path.clone(),
                            format!("Field `{}` {}", field_path, error),
                        )
                    }
                    None => (
                        base_path.to_owned(),
                        format!("Field `{}` is invalid", base_path),
                    ),
                }
            }
        },
    ]
}

fn garde_field_attr_tokens(
    field: &super::model::FieldSpec,
    actual_optional: bool,
    emit_required: bool,
) -> TokenStream {
    let mut rules = Vec::new();
    if emit_required && field.validation.required {
        rules.push(quote!(required));
    }

    let nested_rules = garde_rule_tokens_from_validation(&field.validation, false);
    if actual_optional {
        if !nested_rules.is_empty() {
            rules.push(quote!(inner(#(#nested_rules),*)));
        }
    } else {
        rules.extend(nested_rules);
    }

    if rules.is_empty() {
        quote! {}
    } else {
        quote!(#[garde(#(#rules),*)])
    }
}

fn garde_rule_tokens_from_validation(
    validation: &super::model::FieldValidation,
    include_required: bool,
) -> Vec<TokenStream> {
    let mut rules = Vec::new();

    if include_required && validation.required {
        rules.push(quote!(required));
    }
    if validation.ascii {
        rules.push(quote!(ascii));
    }
    if validation.alphanumeric {
        rules.push(quote!(alphanumeric));
    }
    if validation.email {
        rules.push(quote!(email));
    }
    if validation.url {
        rules.push(quote!(url));
    }
    if validation.ip {
        rules.push(quote!(ip));
    }
    if validation.ipv4 {
        rules.push(quote!(ipv4));
    }
    if validation.ipv6 {
        rules.push(quote!(ipv6));
    }
    if validation.phone_number {
        rules.push(quote!(phone_number));
    }
    if validation.credit_card {
        rules.push(quote!(credit_card));
    }
    if let Some(value) = validation.contains.as_deref() {
        let value = Literal::string(value);
        rules.push(quote!(contains(#value)));
    }
    if let Some(value) = validation.prefix.as_deref() {
        let value = Literal::string(value);
        rules.push(quote!(prefix(#value)));
    }
    if let Some(value) = validation.suffix.as_deref() {
        let value = Literal::string(value);
        rules.push(quote!(suffix(#value)));
    }
    if let Some(value) = validation.pattern.as_deref() {
        let value = Literal::string(value);
        rules.push(quote!(pattern(#value)));
    }
    if let Some(length) = validation.length.as_ref() {
        rules.push(garde_length_rule_tokens(length));
    }
    if let Some(range) = validation.range.as_ref() {
        rules.push(garde_range_rule_tokens(range));
    }
    if let Some(inner) = validation.inner.as_deref() {
        let nested_rules = garde_rule_tokens_from_validation(inner, true);
        if !nested_rules.is_empty() {
            rules.push(quote!(inner(#(#nested_rules),*)));
        }
    }

    rules
}

fn garde_length_rule_tokens(length: &super::model::LengthValidation) -> TokenStream {
    let mode = length.mode.map(garde_length_mode_tokens);
    let min = length.min.map(Literal::usize_unsuffixed);
    let max = length.max.map(Literal::usize_unsuffixed);
    let equal = length.equal.map(Literal::usize_unsuffixed);

    let mut args = Vec::new();
    if let Some(mode) = mode {
        args.push(quote!(#mode));
    }
    if let Some(min) = min {
        args.push(quote!(min = #min));
    }
    if let Some(max) = max {
        args.push(quote!(max = #max));
    }
    if let Some(equal) = equal {
        args.push(quote!(equal = #equal));
    }

    quote!(length(#(#args),*))
}

fn garde_range_rule_tokens(range: &super::model::RangeValidation) -> TokenStream {
    let mut args = Vec::new();

    if let Some(min) = range.min.as_ref() {
        let min = numeric_bound_literal(min);
        args.push(quote!(min = #min));
    }
    if let Some(max) = range.max.as_ref() {
        let max = numeric_bound_literal(max);
        args.push(quote!(max = #max));
    }
    if let Some(equal) = range.equal.as_ref() {
        let equal = numeric_bound_literal(equal);
        args.push(quote!(equal = #equal));
    }

    quote!(range(#(#args),*))
}

fn garde_length_mode_tokens(mode: super::model::LengthMode) -> syn::Ident {
    match mode {
        super::model::LengthMode::Simple => format_ident!("simple"),
        super::model::LengthMode::Bytes => format_ident!("bytes"),
        super::model::LengthMode::Chars => format_ident!("chars"),
        super::model::LengthMode::Graphemes => format_ident!("graphemes"),
        super::model::LengthMode::Utf16 => format_ident!("utf16"),
    }
}

fn numeric_bound_literal(bound: &super::model::NumericBound) -> Literal {
    match bound {
        super::model::NumericBound::Integer(value) => Literal::i64_unsuffixed(*value),
        super::model::NumericBound::Float(value) => Literal::f64_unsuffixed(*value),
    }
}

fn typed_object_validator_defs(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    resource
        .api_fields()
        .flat_map(|field| {
            let path = vec![field.name()];
            collect_typed_object_validator_defs(resource, field, &path, runtime_crate)
        })
        .collect()
}

fn typed_object_normalizer_defs(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    resource
        .api_fields()
        .flat_map(|field| {
            let path = vec![field.name()];
            collect_typed_object_normalizer_defs(resource, field, &path, runtime_crate)
        })
        .collect()
}

fn field_needs_normalization(field: &super::model::FieldSpec) -> bool {
    !field.transforms().is_empty()
        || field
            .object_fields
            .as_deref()
            .map(|nested_fields| nested_fields.iter().any(field_needs_normalization))
            .unwrap_or(false)
}

fn collect_typed_object_normalizer_defs(
    resource: &ResourceSpec,
    field: &super::model::FieldSpec,
    path: &[String],
    runtime_crate: &Path,
) -> Vec<TokenStream> {
    let Some(nested_fields) = field.object_fields.as_deref() else {
        return Vec::new();
    };

    let mut definitions = Vec::new();
    for nested_field in nested_fields {
        let mut nested_path = path.to_vec();
        nested_path.push(nested_field.name());
        definitions.extend(collect_typed_object_normalizer_defs(
            resource,
            nested_field,
            &nested_path,
            runtime_crate,
        ));
    }

    let helper_ident = typed_object_normalizer_ident(resource, path);
    let statements = nested_fields
        .iter()
        .filter_map(|nested_field| {
            let field_name = Literal::string(nested_field.api_name());
            if nested_field.object_fields.is_some() {
                if !field_needs_normalization(nested_field) {
                    return None;
                }
                let mut nested_path = path.to_vec();
                nested_path.push(nested_field.name());
                let nested_helper_ident = typed_object_normalizer_ident(resource, &nested_path);
                Some(quote! {
                    if let Some(value) = object.get_mut(#field_name) {
                        Self::#nested_helper_ident(value);
                    }
                })
            } else if !nested_field.transforms().is_empty() {
                let transform_ops = string_transform_ops(nested_field.transforms());
                Some(quote! {
                    if let Some(value) = object.get_mut(#field_name) {
                        if let #runtime_crate::serde_json::Value::String(value) = value {
                            #(#transform_ops)*
                        }
                    }
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if statements.is_empty() {
        return definitions;
    }

    definitions.push(quote! {
        fn #helper_ident(value: &mut #runtime_crate::serde_json::Value) {
            let Some(object) = value.as_object_mut() else {
                return;
            };
            #(#statements)*
        }
    });

    definitions
}

fn collect_typed_object_validator_defs(
    resource: &ResourceSpec,
    field: &super::model::FieldSpec,
    path: &[String],
    runtime_crate: &Path,
) -> Vec<TokenStream> {
    let Some(nested_fields) = field.object_fields.as_deref() else {
        return Vec::new();
    };

    let mut definitions = Vec::new();
    for nested_field in nested_fields {
        let mut nested_path = path.to_vec();
        nested_path.push(nested_field.name());
        definitions.extend(collect_typed_object_validator_defs(
            resource,
            nested_field,
            &nested_path,
            runtime_crate,
        ));
    }

    let struct_ident = typed_object_validator_ident(resource, path);
    let field_defs = nested_fields.iter().map(|nested_field| {
        let ident = &nested_field.ident;
        let mut nested_path = path.to_vec();
        nested_path.push(nested_field.name());
        let ty = typed_object_validator_field_type_tokens(
            resource,
            nested_field,
            &nested_path,
            runtime_crate,
        );
        let rename_attr = serde_rename_attr(nested_field.api_name(), &nested_field.name());
        let garde_attr = garde_field_attr_tokens(
            nested_field,
            super::model::is_optional_type(&nested_field.ty),
            true,
        );
        if super::model::is_optional_type(&nested_field.ty) {
            quote! {
                #rename_attr
                #garde_attr
                #[serde(default)]
                pub #ident: #ty,
            }
        } else {
            quote! {
                #rename_attr
                #garde_attr
                pub #ident: #ty,
            }
        }
    });
    let validations = nested_fields
        .iter()
        .map(typed_object_validator_field_check_tokens);
    let prefixed_error_helper = prefixed_garde_validation_error_helper(resource);

    definitions.push(quote! {
        #[allow(dead_code)]
        #[derive(
            Debug,
            Clone,
            #runtime_crate::serde::Deserialize,
            #runtime_crate::garde::Validate
        )]
        #[garde(allow_unvalidated)]
        #[serde(deny_unknown_fields)]
        struct #struct_ident {
            #(#field_defs)*
        }

        impl #struct_ident {
            fn validate(&self, base_path: &str) -> Result<(), (String, String)> {
                if let Err(report) = #runtime_crate::garde::Validate::validate(self) {
                    return Err(#prefixed_error_helper(base_path, report));
                }
                #(#validations)*
                Ok(())
            }
        }
    });

    definitions
}

fn typed_object_validator_ident(resource: &ResourceSpec, path: &[String]) -> syn::Ident {
    let suffix = path
        .iter()
        .map(|segment| segment.to_upper_camel_case())
        .collect::<String>();
    format_ident!("{}{}ObjectSchema", resource.struct_ident, suffix)
}

fn typed_object_normalizer_ident(resource: &ResourceSpec, path: &[String]) -> syn::Ident {
    let suffix = path
        .iter()
        .map(|segment| segment.to_upper_camel_case())
        .collect::<String>();
    format_ident!(
        "normalize_{}_{}_object",
        resource.struct_ident.to_string().to_snake_case(),
        suffix.to_snake_case()
    )
}

fn string_transform_ops(transforms: &[super::model::FieldTransform]) -> Vec<TokenStream> {
    transforms
        .iter()
        .map(|transform| match transform {
            super::model::FieldTransform::Trim => quote! {
                *value = value.trim().to_owned();
            },
            super::model::FieldTransform::Lowercase => quote! {
                *value = value.to_lowercase();
            },
            super::model::FieldTransform::CollapseWhitespace => quote! {
                *value = value.split_whitespace().collect::<Vec<_>>().join(" ");
            },
            super::model::FieldTransform::Slugify => quote! {
                {
                    let mut slug = String::new();
                    let mut pending_dash = false;
                    for ch in value.chars() {
                        if ch.is_alphanumeric() {
                            if pending_dash && !slug.is_empty() {
                                slug.push('-');
                            }
                            pending_dash = false;
                            for lower in ch.to_lowercase() {
                                slug.push(lower);
                            }
                        } else if !slug.is_empty() {
                            pending_dash = true;
                        }
                    }
                    *value = slug;
                }
            },
        })
        .collect()
}

fn typed_object_validator_scalar_type_tokens(ty: &Type, runtime_crate: &Path) -> TokenStream {
    let base_ty = super::model::base_type(ty);
    if let Some(kind) = super::model::structured_scalar_kind(&base_ty) {
        return match kind {
            super::model::StructuredScalarKind::Json => {
                quote!(#runtime_crate::serde_json::Value)
            }
            super::model::StructuredScalarKind::JsonObject => {
                quote!(#runtime_crate::serde_json::Map<String, #runtime_crate::serde_json::Value>)
            }
            super::model::StructuredScalarKind::JsonArray => {
                quote!(Vec<#runtime_crate::serde_json::Value>)
            }
            _ => structured_scalar_type_tokens(kind, runtime_crate),
        };
    }

    if super::model::is_bool_type(&base_ty) {
        quote!(bool)
    } else {
        quote!(#base_ty)
    }
}

fn typed_object_validator_list_item_type_tokens(ty: &Type, runtime_crate: &Path) -> TokenStream {
    if let Some(kind) = super::model::structured_scalar_kind(ty) {
        return match kind {
            super::model::StructuredScalarKind::Json => {
                quote!(#runtime_crate::serde_json::Value)
            }
            super::model::StructuredScalarKind::JsonObject => {
                quote!(#runtime_crate::serde_json::Map<String, #runtime_crate::serde_json::Value>)
            }
            super::model::StructuredScalarKind::JsonArray => {
                quote!(Vec<#runtime_crate::serde_json::Value>)
            }
            _ => structured_scalar_type_tokens(kind, runtime_crate),
        };
    }

    if super::model::is_bool_type(ty) {
        quote!(bool)
    } else {
        quote!(#ty)
    }
}

fn typed_object_validator_field_type_tokens(
    resource: &ResourceSpec,
    field: &super::model::FieldSpec,
    path: &[String],
    runtime_crate: &Path,
) -> TokenStream {
    let inner_ty = if field.object_fields.is_some() {
        let ident = typed_object_validator_ident(resource, path);
        quote!(#ident)
    } else if let Some(item_ty) = field.list_item_ty.as_ref() {
        let item_ty = typed_object_validator_list_item_type_tokens(item_ty, runtime_crate);
        quote!(Vec<#item_ty>)
    } else {
        typed_object_validator_scalar_type_tokens(&field.ty, runtime_crate)
    };

    if super::model::is_optional_type(&field.ty) {
        quote!(Option<#inner_ty>)
    } else {
        inner_ty
    }
}

fn typed_object_validator_field_check_tokens(field: &super::model::FieldSpec) -> TokenStream {
    let ident = &field.ident;
    let field_name = field.api_name().to_owned();
    let field_name_lit = Literal::string(&field_name);

    if field.object_fields.is_some() {
        return if super::model::is_optional_type(&field.ty) {
            quote! {
                if let Some(value) = &self.#ident {
                    let nested_path = format!("{}.{}", base_path, #field_name_lit);
                    value.validate(nested_path.as_str())?;
                }
            }
        } else {
            quote! {
                let nested_path = format!("{}.{}", base_path, #field_name_lit);
                self.#ident.validate(nested_path.as_str())?;
            }
        };
    }

    if field.enum_values().is_none() {
        return quote! {};
    }

    let checks = typed_object_validator_scalar_checks(field);
    if checks.is_empty() {
        return quote! {};
    }

    if super::model::is_optional_type(&field.ty) {
        quote! {
            if let Some(value) = &self.#ident {
                let field_path = format!("{}.{}", base_path, #field_name_lit);
                #(#checks)*
            }
        }
    } else {
        quote! {
            let value = &self.#ident;
            let field_path = format!("{}.{}", base_path, #field_name_lit);
            #(#checks)*
        }
    }
}

fn typed_object_validator_scalar_checks(field: &super::model::FieldSpec) -> Vec<TokenStream> {
    let mut checks = Vec::new();

    if let Some(enum_values) = field.enum_values() {
        let enum_values = enum_values
            .iter()
            .map(|value| Literal::string(value.as_str()))
            .collect::<Vec<_>>();
        let enum_values_message = Literal::string(&enum_values_as_message(field));
        checks.push(quote! {
            if ![#(#enum_values),*].contains(&value.as_str()) {
                return Err((
                    field_path.clone(),
                    format!("Field `{}` must be one of: {}", field_path, #enum_values_message),
                ));
            }
        });
    }

    checks
}

fn structured_scalar_type_tokens(
    kind: super::model::StructuredScalarKind,
    runtime_crate: &Path,
) -> TokenStream {
    match kind {
        super::model::StructuredScalarKind::DateTime => {
            quote!(#runtime_crate::chrono::DateTime<#runtime_crate::chrono::Utc>)
        }
        super::model::StructuredScalarKind::Date => quote!(#runtime_crate::chrono::NaiveDate),
        super::model::StructuredScalarKind::Time => quote!(#runtime_crate::chrono::NaiveTime),
        super::model::StructuredScalarKind::Uuid => quote!(#runtime_crate::uuid::Uuid),
        super::model::StructuredScalarKind::Decimal => {
            quote!(#runtime_crate::rust_decimal::Decimal)
        }
        super::model::StructuredScalarKind::Json
        | super::model::StructuredScalarKind::JsonObject
        | super::model::StructuredScalarKind::JsonArray => {
            quote!(#runtime_crate::serde_json::Value)
        }
    }
}

fn structured_scalar_to_text_tokens(
    ty: &syn::Type,
    value: TokenStream,
    runtime_crate: &Path,
) -> Option<TokenStream> {
    match super::model::structured_scalar_kind(ty)? {
        super::model::StructuredScalarKind::DateTime => Some(quote! {
            #value.to_rfc3339_opts(#runtime_crate::chrono::SecondsFormat::Micros, false)
        }),
        super::model::StructuredScalarKind::Date => {
            Some(quote!(#value.format("%Y-%m-%d").to_string()))
        }
        super::model::StructuredScalarKind::Time => {
            Some(quote!(#value.format("%H:%M:%S.%6f").to_string()))
        }
        super::model::StructuredScalarKind::Uuid => {
            Some(quote!(#value.as_hyphenated().to_string()))
        }
        super::model::StructuredScalarKind::Decimal => Some(quote!(#value.normalize().to_string())),
        super::model::StructuredScalarKind::Json
        | super::model::StructuredScalarKind::JsonObject
        | super::model::StructuredScalarKind::JsonArray => Some(quote!(
            #runtime_crate::serde_json::to_string(#value).expect("JSON fields should serialize")
        )),
    }
}

fn json_bind_tokens(field: &super::model::FieldSpec, runtime_crate: &Path) -> Option<TokenStream> {
    if field.list_item_ty.is_some() {
        let ident = &field.ident;
        if super::model::is_optional_type(&field.ty) {
            return Some(quote! {
                item.#ident.as_ref().map(|value| {
                    #runtime_crate::serde_json::to_string(value)
                        .expect("list fields should serialize")
                })
            });
        }
        return Some(quote! {
            #runtime_crate::serde_json::to_string(&item.#ident)
                .expect("list fields should serialize")
        });
    }

    match super::model::structured_scalar_kind(&field.ty) {
        Some(
            super::model::StructuredScalarKind::Json
            | super::model::StructuredScalarKind::JsonObject
            | super::model::StructuredScalarKind::JsonArray,
        ) => {
            let ident = &field.ident;
            if super::model::is_optional_type(&field.ty) {
                Some(quote! {
                    item.#ident.as_ref().map(|value| {
                        #runtime_crate::serde_json::to_string(value)
                            .expect("JSON fields should serialize")
                    })
                })
            } else {
                Some(quote! {
                    #runtime_crate::serde_json::to_string(&item.#ident)
                        .expect("JSON fields should serialize")
                })
            }
        }
        _ => None,
    }
}

fn list_field_from_text_tokens(
    base_ty: &Type,
    value_ident: TokenStream,
    field_name_lit: &Literal,
    runtime_crate: &Path,
) -> TokenStream {
    quote! {
        #runtime_crate::serde_json::from_str::<#base_ty>(&#value_ident).map_err(
            |error| #runtime_crate::sqlx::Error::ColumnDecode {
                index: #field_name_lit.to_owned(),
                source: Box::new(error),
            }
        )?
    }
}

fn structured_scalar_from_text_tokens(
    kind: super::model::StructuredScalarKind,
    base_ty: &Type,
    value_ident: TokenStream,
    field_name_lit: &Literal,
    runtime_crate: &Path,
) -> TokenStream {
    match kind {
        super::model::StructuredScalarKind::DateTime
        | super::model::StructuredScalarKind::Date
        | super::model::StructuredScalarKind::Time
        | super::model::StructuredScalarKind::Uuid
        | super::model::StructuredScalarKind::Decimal => quote! {
            #value_ident.parse::<#base_ty>().map_err(|error| #runtime_crate::sqlx::Error::ColumnDecode {
                index: #field_name_lit.to_owned(),
                source: Box::new(error),
            })?
        },
        super::model::StructuredScalarKind::Json => quote! {
            #runtime_crate::serde_json::from_str::<#base_ty>(&#value_ident).map_err(
                |error| #runtime_crate::sqlx::Error::ColumnDecode {
                    index: #field_name_lit.to_owned(),
                    source: Box::new(error),
                }
            )?
        },
        super::model::StructuredScalarKind::JsonObject => quote! {{
            let parsed = #runtime_crate::serde_json::from_str::<#base_ty>(&#value_ident).map_err(
                |error| #runtime_crate::sqlx::Error::ColumnDecode {
                    index: #field_name_lit.to_owned(),
                    source: Box::new(error),
                }
            )?;
            if !matches!(parsed, #runtime_crate::serde_json::Value::Object(_)) {
                return Err(#runtime_crate::sqlx::Error::ColumnDecode {
                    index: #field_name_lit.to_owned(),
                    source: Box::new(::std::io::Error::new(
                        ::std::io::ErrorKind::InvalidData,
                        "expected JSON object",
                    )),
                });
            }
            parsed
        }},
        super::model::StructuredScalarKind::JsonArray => quote! {{
            let parsed = #runtime_crate::serde_json::from_str::<#base_ty>(&#value_ident).map_err(
                |error| #runtime_crate::sqlx::Error::ColumnDecode {
                    index: #field_name_lit.to_owned(),
                    source: Box::new(error),
                }
            )?;
            if !matches!(parsed, #runtime_crate::serde_json::Value::Array(_)) {
                return Err(#runtime_crate::sqlx::Error::ColumnDecode {
                    index: #field_name_lit.to_owned(),
                    source: Box::new(::std::io::Error::new(
                        ::std::io::ErrorKind::InvalidData,
                        "expected JSON array",
                    )),
                });
            }
            parsed
        }},
    }
}

fn field_supports_sort(field: &super::model::FieldSpec) -> bool {
    super::model::supports_field_sort(field)
}

fn audit_sink_resource<'a>(
    resource: &ResourceSpec,
    resources: &'a [ResourceSpec],
) -> Option<&'a ResourceSpec> {
    let audit = resource.audit.as_ref()?;
    resources.iter().find(|candidate| {
        candidate.struct_ident == audit.resource || candidate.table_name == audit.resource
    })
}

fn create_audit_event_kind(resource: &ResourceSpec) -> Option<String> {
    resource
        .audit
        .as_ref()
        .filter(|audit| audit.create)
        .map(|_| "create".to_owned())
}

fn update_audit_event_kind(resource: &ResourceSpec, action_name: Option<&str>) -> Option<String> {
    let audit = resource.audit.as_ref()?;
    if let Some(action_name) = action_name
        && audit
            .actions
            .as_ref()
            .is_some_and(|selection| selection.audits_action(action_name))
    {
        return Some(format!("action:{action_name}"));
    }

    audit.update.then(|| "update".to_owned())
}

fn delete_audit_event_kind(resource: &ResourceSpec, action_name: Option<&str>) -> Option<String> {
    let audit = resource.audit.as_ref()?;
    if let Some(action_name) = action_name
        && audit
            .actions
            .as_ref()
            .is_some_and(|selection| selection.audits_action(action_name))
    {
        return Some(format!("action:{action_name}"));
    }

    audit.delete.then(|| "delete".to_owned())
}

fn generated_from_row_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> TokenStream {
    let struct_ident = &resource.struct_ident;
    let field_extracts = resource.api_fields().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        let storage_field_name_lit = Literal::string(&field.name());
        let api_field_name_lit = Literal::string(field.api_name());

        if field.list_item_ty.is_some() {
            let base_ty = super::model::base_type(&field.ty);
            if super::model::is_optional_type(&field.ty) {
                let parsed_value = list_field_from_text_tokens(
                    &base_ty,
                    quote!(value),
                    &storage_field_name_lit,
                    runtime_crate,
                );
                quote! {
                    let #ident: #ty = match #runtime_crate::sqlx::Row::try_get::<Option<String>, _>(row, #storage_field_name_lit)? {
                        Some(value) => Some(#parsed_value),
                        None => None,
                    };
                }
            } else {
                let parsed_value = list_field_from_text_tokens(
                    &base_ty,
                    quote!(value),
                    &storage_field_name_lit,
                    runtime_crate,
                );
                quote! {
                    let #ident: #ty = {
                        let value = #runtime_crate::sqlx::Row::try_get::<String, _>(row, #storage_field_name_lit)?;
                        #parsed_value
                    };
                }
            }
        } else if super::model::is_structured_scalar_type(&field.ty) {
            let base_ty = super::model::base_type(&field.ty);
            let kind = super::model::structured_scalar_kind(&field.ty)
                .expect("structured scalar kind should exist");
            let parsed_value = if kind == super::model::StructuredScalarKind::JsonObject
                && field.object_fields.is_some()
            {
                let validator_ident =
                    typed_object_validator_ident(resource, &[field.name()]);
                quote! {{
                    let parsed = #runtime_crate::serde_json::from_str::<#base_ty>(&value).map_err(
                        |error| #runtime_crate::sqlx::Error::ColumnDecode {
                            index: #storage_field_name_lit.to_owned(),
                            source: Box::new(error),
                        }
                    )?;
                    let validated: #validator_ident = #runtime_crate::serde_json::from_value(parsed.clone()).map_err(
                        |error| #runtime_crate::sqlx::Error::ColumnDecode {
                            index: #storage_field_name_lit.to_owned(),
                            source: Box::new(::std::io::Error::new(
                                ::std::io::ErrorKind::InvalidData,
                                format!("Field `{}` is invalid: {}", #api_field_name_lit, error),
                            )),
                        }
                    )?;
                    if let Err((_field_path, message)) = validated.validate(#api_field_name_lit) {
                        return Err(#runtime_crate::sqlx::Error::ColumnDecode {
                            index: #storage_field_name_lit.to_owned(),
                            source: Box::new(::std::io::Error::new(
                                ::std::io::ErrorKind::InvalidData,
                                message,
                            )),
                        });
                    }
                    parsed
                }}
            } else {
                structured_scalar_from_text_tokens(
                    kind,
                    &base_ty,
                    quote!(value),
                    &storage_field_name_lit,
                    runtime_crate,
                )
            };
            if super::model::is_optional_type(&field.ty) {
                quote! {
                    let #ident: #ty = match #runtime_crate::sqlx::Row::try_get::<Option<String>, _>(row, #storage_field_name_lit)? {
                        Some(value) => Some(#parsed_value),
                        None => None,
                    };
                }
            } else {
                quote! {
                    let #ident: #ty = {
                        let value = #runtime_crate::sqlx::Row::try_get::<String, _>(row, #storage_field_name_lit)?;
                        #parsed_value
                    };
                }
            }
        } else if super::model::is_bool_type(&field.ty) {
            if super::model::is_optional_type(&field.ty) {
                quote! {
                    let #ident: #ty = match #runtime_crate::sqlx::Row::try_get::<Option<bool>, _>(row, #storage_field_name_lit) {
                        Ok(value) => value,
                        Err(#runtime_crate::sqlx::Error::ColumnDecode { .. }) => {
                            match #runtime_crate::sqlx::Row::try_get::<Option<i64>, _>(row, #storage_field_name_lit) {
                                Ok(value) => value.map(|value| value != 0),
                                Err(#runtime_crate::sqlx::Error::ColumnDecode { .. }) => {
                                    #runtime_crate::sqlx::Row::try_get::<Option<i32>, _>(row, #storage_field_name_lit)?
                                        .map(|value| value != 0)
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        Err(error) => return Err(error),
                    };
                }
            } else {
                quote! {
                    let #ident: #ty = match #runtime_crate::sqlx::Row::try_get::<bool, _>(row, #storage_field_name_lit) {
                        Ok(value) => value,
                        Err(#runtime_crate::sqlx::Error::ColumnDecode { .. }) => {
                            match #runtime_crate::sqlx::Row::try_get::<i64, _>(row, #storage_field_name_lit) {
                                Ok(value) => value != 0,
                                Err(#runtime_crate::sqlx::Error::ColumnDecode { .. }) => {
                                    #runtime_crate::sqlx::Row::try_get::<i32, _>(row, #storage_field_name_lit)? != 0
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        Err(error) => return Err(error),
                    };
                }
            }
        } else {
            quote! {
                let #ident: #ty = #runtime_crate::sqlx::Row::try_get(row, #storage_field_name_lit)?;
            }
        }
    });
    let field_names = resource.api_fields().map(|field| &field.ident);

    quote! {
        impl<'r> #runtime_crate::sqlx::FromRow<'r, #runtime_crate::sqlx::any::AnyRow> for #struct_ident {
            fn from_row(row: &'r #runtime_crate::sqlx::any::AnyRow) -> Result<Self, #runtime_crate::sqlx::Error> {
                #(#field_extracts)*

                Ok(Self {
                    #(#field_names),*
                })
            }
        }
    }
}

fn list_query_tokens(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    runtime_crate: &Path,
) -> TokenStream {
    let list_query_ident = list_query_ident(resource);
    let sort_field_ident = list_sort_field_ident(resource);
    let sort_order_ident = list_sort_order_ident(resource);
    let bind_ident = list_bind_ident(resource);
    let response_ident = list_response_ident(resource);
    let plan_ident = list_plan_ident(resource);
    let cursor_value_ident = list_cursor_value_ident(resource);
    let cursor_payload_ident = list_cursor_payload_ident(resource);
    let struct_ident = &resource.struct_ident;
    let bind_variants = list_bind_kinds(resource, resources)
        .into_iter()
        .map(|kind| match kind {
            ListBindKind::Integer => quote!(Integer(i64),),
            ListBindKind::Real => quote!(Real(f64),),
            ListBindKind::Boolean => quote!(Boolean(bool),),
            ListBindKind::Text => quote!(Text(String),),
        })
        .collect::<Vec<_>>();
    let sortable_fields = resource
        .api_fields()
        .filter(|field| field_supports_sort(field))
        .collect::<Vec<_>>();
    let filter_fields = resource.api_fields().flat_map(|field| {
        let mut tokens = Vec::new();

        if super::model::supports_exact_filters(field) {
            let filter_ident = format_ident!("filter_{}", field.ident);
            let base_ty = list_filter_field_ty(field, runtime_crate);
            let rename = Literal::string(&format!("filter_{}", field.api_name()));
            tokens.push(quote! {
                #[serde(rename = #rename)]
                pub #filter_ident: Option<#base_ty>,
            });

            if resource
                .list
                .filterable_in
                .iter()
                .any(|candidate| candidate == &field.name())
            {
                let filter_in_ident = format_ident!("filter_{}__in", field.ident);
                let rename = Literal::string(&format!("filter_{}__in", field.api_name()));
                tokens.push(quote! {
                    #[serde(rename = #rename)]
                    pub #filter_in_ident: Option<String>,
                });
            }
        }

        if super::model::supports_contains_filters(field) {
            let contains_ident = format_ident!("filter_{}_contains", field.ident);
            let rename = Literal::string(&format!("filter_{}_contains", field.api_name()));
            tokens.push(quote! {
                #[serde(rename = #rename)]
                pub #contains_ident: Option<String>,
            });
        }

        if super::model::supports_exact_filters(field)
            && super::model::supports_range_filters(&field.ty)
        {
            for suffix in ["gt", "gte", "lt", "lte"] {
                let ident = format_ident!("filter_{}_{}", field.ident, suffix);
                let range_ty = list_filter_field_ty(field, runtime_crate);
                let rename = Literal::string(&format!("filter_{}_{}", field.api_name(), suffix));
                tokens.push(quote! {
                    #[serde(rename = #rename)]
                    pub #ident: Option<#range_ty>,
                });
            }
        }

        tokens
    });
    let sort_variants = sortable_fields.iter().map(|field| {
        let variant_ident = super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name = Literal::string(field.api_name());
        quote! {
            #[serde(rename = #field_name)]
            #variant_ident,
        }
    });
    let sort_variant_sql = sortable_fields.iter().map(|field| {
        let variant_ident = super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name = Literal::string(&field.name());
        quote! {
            Self::#variant_ident => #field_name,
        }
    });
    let sort_variant_name = sortable_fields.iter().map(|field| {
        let variant_ident = super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name = Literal::string(field.api_name());
        quote! {
            Self::#variant_ident => #field_name,
        }
    });
    let sort_variant_parse = sortable_fields.iter().map(|field| {
        let variant_ident = super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name = Literal::string(field.api_name());
        quote! {
            #field_name => Some(Self::#variant_ident),
        }
    });

    quote! {
        #[derive(Debug, Clone, #runtime_crate::serde::Deserialize, Default)]
        #[serde(default, deny_unknown_fields)]
        pub struct #list_query_ident {
            pub limit: Option<u32>,
            pub offset: Option<u32>,
            pub sort: Option<#sort_field_ident>,
            pub order: Option<#sort_order_ident>,
            pub cursor: Option<String>,
            pub context: Option<String>,
            #(#filter_fields)*
        }

        #[derive(Debug, Clone, #runtime_crate::serde::Deserialize)]
        #[serde(rename_all = "lowercase")]
        pub enum #sort_order_ident {
            Asc,
            Desc,
        }

        impl #sort_order_ident {
            fn as_sql(&self) -> &'static str {
                match self {
                    Self::Asc => "ASC",
                    Self::Desc => "DESC",
                }
            }

            fn as_str(&self) -> &'static str {
                match self {
                    Self::Asc => "asc",
                    Self::Desc => "desc",
                }
            }

            fn parse(value: &str) -> Option<Self> {
                match value {
                    "asc" => Some(Self::Asc),
                    "desc" => Some(Self::Desc),
                    _ => None,
                }
            }
        }

        #[derive(Debug, Clone, #runtime_crate::serde::Deserialize)]
        pub enum #sort_field_ident {
            #(#sort_variants)*
        }

        impl #sort_field_ident {
            fn as_sql(&self) -> &'static str {
                match self {
                    #(#sort_variant_sql)*
                }
            }

            fn as_name(&self) -> &'static str {
                match self {
                    #(#sort_variant_name)*
                }
            }

            fn from_name(value: &str) -> Option<Self> {
                match value {
                    #(#sort_variant_parse)*
                    _ => None,
                }
            }
        }

        #[derive(Debug, Clone)]
        enum #bind_ident {
            #(#bind_variants)*
        }

        #[derive(Debug, Clone, #runtime_crate::serde::Serialize, #runtime_crate::serde::Deserialize)]
        enum #cursor_value_ident {
            Integer(i64),
            Real(f64),
            Boolean(bool),
            Text(String),
        }

        #[derive(Debug, Clone, #runtime_crate::serde::Serialize, #runtime_crate::serde::Deserialize)]
        struct #cursor_payload_ident {
            sort: String,
            order: String,
            last_id: i64,
            value: #cursor_value_ident,
        }

        #[derive(Debug)]
        struct #plan_ident {
            select_sql: String,
            count_sql: String,
            filter_binds: Vec<#bind_ident>,
            select_binds: Vec<#bind_ident>,
            limit: Option<u32>,
            offset: u32,
            sort: #sort_field_ident,
            order: #sort_order_ident,
            cursor_mode: bool,
        }

        #[derive(Debug, Clone, #runtime_crate::serde::Serialize, #runtime_crate::serde::Deserialize)]
        pub struct #response_ident {
            pub items: Vec<#struct_ident>,
            pub total: i64,
            pub count: usize,
            pub limit: Option<u32>,
            pub offset: u32,
            pub next_offset: Option<u32>,
            pub next_cursor: Option<String>,
        }
    }
}

fn resource_impl_tokens(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    authorization: Option<&AuthorizationContract>,
    max_filter_in_values: usize,
    runtime_crate: &Path,
) -> TokenStream {
    let struct_ident = &resource.struct_ident;
    let table_name = &resource.table_name;
    let resource_api_name = Literal::string(resource.api_name());
    let id_field = &resource.id_field;
    let read_requires_auth = super::model::read_requires_auth(resource);
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
            super::model::ComputedFieldPart::Literal(value) => {
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
            super::model::ComputedFieldPart::Field(name) => {
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
        super::model::DbBackend::Postgres => quote!(format!("${index}")),
        super::model::DbBackend::Sqlite | super::model::DbBackend::Mysql => {
            quote!({
                let _ = index;
                "?".to_owned()
            })
        }
    };
    let query_filter_conditions =
        list_query_condition_tokens(resource, max_filter_in_values, runtime_crate);
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
    let is_audit_sink = super::model::is_audit_sink_resource(resource, resources);
    let audit_sink_table =
        audit_sink_resource(resource, resources).map(|sink| Literal::string(&sink.table_name));
    let audit_resource_name = Literal::string(&resource.struct_ident.to_string());
    let create_audit_event_kind = create_audit_event_kind(resource)
        .as_deref()
        .map(Literal::string);
    let update_audit_event_kind = update_audit_event_kind(resource, None)
        .as_deref()
        .map(Literal::string);
    let delete_audit_event_kind = delete_audit_event_kind(resource, None)
        .as_deref()
        .map(Literal::string);
    let audit_helper_methods = if let Some(sink_table) = audit_sink_table {
        quote! {
            async fn fetch_unfiltered_by_id_for_audit<E>(
                id: i64,
                executor: &E,
            ) -> Result<Option<Self>, #runtime_crate::sqlx::Error>
            where
                E: #runtime_crate::db::DbExecutor + ?Sized,
            {
                let sql = format!(
                    "SELECT * FROM {} WHERE {} = {}",
                    #table_name,
                    #id_field,
                    Self::list_placeholder(1),
                );
                #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&sql)
                    .bind(id)
                    .fetch_optional(executor)
                    .await
            }

            fn audit_actor_user_id(user: &#runtime_crate::core::auth::UserContext) -> Option<i64> {
                (user.id != 0).then_some(user.id)
            }

            fn audit_payload_json(
                before: Option<&Self>,
                after: Option<&Self>,
            ) -> Result<String, HttpResponse> {
                let before = before
                    .map(|item| Self::serialize_item_value(item, None))
                    .transpose()?;
                let after = after
                    .map(|item| Self::serialize_item_value(item, None))
                    .transpose()?;
                #runtime_crate::serde_json::to_string(&match (before, after) {
                    (Some(before), Some(after)) => #runtime_crate::serde_json::json!({
                        "before": before,
                        "after": after,
                    }),
                    (Some(before), None) => #runtime_crate::serde_json::json!({
                        "before": before,
                    }),
                    (None, Some(after)) => #runtime_crate::serde_json::json!({
                        "after": after,
                    }),
                    (None, None) => #runtime_crate::serde_json::json!({}),
                })
                .map_err(|error| #runtime_crate::core::errors::internal_error(error.to_string()))
            }

            async fn insert_audit_event<E>(
                executor: &E,
                user: &#runtime_crate::core::auth::UserContext,
                event_kind: &str,
                record_id: i64,
                before: Option<&Self>,
                after: Option<&Self>,
            ) -> Result<(), HttpResponse>
            where
                E: #runtime_crate::db::DbExecutor + ?Sized,
            {
                let payload_json = Self::audit_payload_json(before, after)?;
                let actor_roles_json = #runtime_crate::serde_json::to_string(&user.roles)
                    .map_err(|error| {
                        #runtime_crate::core::errors::internal_error(error.to_string())
                    })?;
                let sql = format!(
                    "INSERT INTO {} (event_kind, resource_name, record_id, actor_user_id, actor_roles_json, payload_json) VALUES ({}, {}, {}, {}, {}, {})",
                    #sink_table,
                    Self::list_placeholder(1),
                    Self::list_placeholder(2),
                    Self::list_placeholder(3),
                    Self::list_placeholder(4),
                    Self::list_placeholder(5),
                    Self::list_placeholder(6),
                );
                #runtime_crate::db::query(&sql)
                    .bind(event_kind)
                    .bind(#audit_resource_name)
                    .bind(record_id)
                    .bind(Self::audit_actor_user_id(user))
                    .bind(actor_roles_json)
                    .bind(payload_json)
                    .execute(executor)
                    .await
                    .map_err(|error| {
                        #runtime_crate::core::errors::internal_error(error.to_string())
                    })?;
                Ok(())
            }
        }
    } else {
        quote!()
    };
    let contains_filter_helper = if resource
        .api_fields()
        .any(super::model::supports_contains_filters)
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
    let cursor_id_for_item_body = if super::model::is_optional_type(&id_field_spec.ty) {
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
        super::model::sanitize_struct_ident(&id_field_spec.name(), id_field_spec.ident.span());
    let sortable_fields = resource
        .api_fields()
        .filter(|field| field_supports_sort(field))
        .collect::<Vec<_>>();
    let cursor_support_arms = sortable_fields.iter().map(|field| {
        let variant_ident = super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let supported =
            field.name() == resource.id_field || !super::model::is_optional_type(&field.ty);
        quote! {
            #sort_field_ty::#variant_ident => #supported,
        }
    });
    let cursor_value_for_item_arms = sortable_fields.iter().map(|field| {
        let variant_ident = super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let ident = &field.ident;
        let field_name_lit = Literal::string(field.api_name());
        if field.name() == resource.id_field {
            if super::model::is_optional_type(&field.ty) {
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
        } else if super::model::is_optional_type(&field.ty) {
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
                if super::model::is_bool_type(&field.ty) {
                    quote! {
                        #sort_field_ty::#variant_ident => Ok(#cursor_value_ty::Boolean(item.#ident)),
                    }
                } else {
                    match field.sql_type.as_str() {
                    sql_type if super::model::is_integer_sql_type(sql_type) => {
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
        let variant_ident = super::model::sanitize_struct_ident(&field.name(), field.ident.span());
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
        } else if super::model::is_optional_type(&field.ty) {
            quote! {
                #sort_field_ty::#variant_ident => {
                    return Err(#runtime_crate::core::errors::bad_request(
                        "invalid_cursor",
                        format!("Cursor pagination does not support nullable sort field `{}`", #field_name_lit),
                    ));
                }
            }
        } else {
            let bind_push = if super::model::is_bool_type(&field.ty) {
                quote! {
                    #cursor_value_ty::Boolean(value) => {
                        select_only_binds.push(#list_bind_ty::Boolean(*value));
                        select_only_binds.push(#list_bind_ty::Boolean(*value));
                    }
                }
            } else {
                match field.sql_type.as_str() {
                sql_type if super::model::is_integer_sql_type(sql_type) => quote! {
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
        let scope_value = match super::model::policy_field_claim_type(&hybrid.scope_field.ty)
            .unwrap_or_else(|| panic!("validated hybrid scope field type is unsupported"))
        {
            crate::auth::AuthClaimType::I64 => {
                if super::model::is_optional_type(&hybrid.scope_field.ty) {
                    quote!(item.#scope_field_ident.map(|value| value.to_string()))
                } else {
                    quote!(Some(item.#scope_field_ident.to_string()))
                }
            }
            crate::auth::AuthClaimType::Bool => {
                if super::model::is_optional_type(&hybrid.scope_field.ty) {
                    quote!(item.#scope_field_ident.map(|value| value.to_string()))
                } else {
                    quote!(Some(item.#scope_field_ident.to_string()))
                }
            }
            crate::auth::AuthClaimType::String => {
                if super::model::is_optional_type(&hybrid.scope_field.ty) {
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
        let list_scope_value = match super::model::policy_field_claim_type(&hybrid.scope_field.ty)
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
                match super::model::policy_field_claim_type(&hybrid.scope_field.ty)
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

    let create_body = if let Some(event_kind) = create_audit_event_kind {
        match (resource.db, insert_fields.is_empty()) {
            (super::model::DbBackend::Postgres | super::model::DbBackend::Sqlite, true) => {
                quote! {
                    let tx = match db.get_ref().begin().await {
                        Ok(tx) => tx,
                        Err(error) => {
                            return #runtime_crate::core::errors::internal_error(error.to_string());
                        }
                    };
                    let sql = format!("INSERT INTO {} DEFAULT VALUES RETURNING {}", #table_name, #id_field);
                    match #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&sql)
                        .fetch_one(&tx)
                        .await
                    {
                        Ok(created_id) => {
                            let after = match Self::fetch_unfiltered_by_id_for_audit(created_id, &tx).await {
                                Ok(Some(item)) => item,
                                Ok(None) => {
                                    let _ = tx.rollback().await;
                                    return #runtime_crate::core::errors::internal_error(
                                        "created row could not be reloaded for audit",
                                    );
                                }
                                Err(error) => {
                                    let _ = tx.rollback().await;
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                            };
                            if let Err(response) = Self::insert_audit_event(
                                &tx,
                                &user,
                                #event_kind,
                                created_id,
                                None,
                                Some(&after),
                            )
                            .await
                            {
                                let _ = tx.rollback().await;
                                return response;
                            }
                            if let Err(error) = tx.commit().await {
                                return #runtime_crate::core::errors::internal_error(error.to_string());
                            }
                            Self::created_response(created_id, &req, &user, db.get_ref(), #created_response_runtime).await
                        }
                        Err(error) => {
                            let _ = tx.rollback().await;
                            #runtime_crate::core::errors::internal_error(error.to_string())
                        }
                    }
                }
            }
            (super::model::DbBackend::Postgres | super::model::DbBackend::Sqlite, false) => {
                quote! {
                    let tx = match db.get_ref().begin().await {
                        Ok(tx) => tx,
                        Err(error) => {
                            return #runtime_crate::core::errors::internal_error(error.to_string());
                        }
                    };
                    let sql = format!(
                        "INSERT INTO {} ({}) VALUES ({}) RETURNING {}",
                        #table_name,
                        #insert_fields_csv,
                        #insert_placeholders,
                        #id_field
                    );
                    let mut q = #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&sql);
                    #create_insert_binds
                    match q.fetch_one(&tx).await {
                        Ok(created_id) => {
                            let after = match Self::fetch_unfiltered_by_id_for_audit(created_id, &tx).await {
                                Ok(Some(item)) => item,
                                Ok(None) => {
                                    let _ = tx.rollback().await;
                                    return #runtime_crate::core::errors::internal_error(
                                        "created row could not be reloaded for audit",
                                    );
                                }
                                Err(error) => {
                                    let _ = tx.rollback().await;
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                            };
                            if let Err(response) = Self::insert_audit_event(
                                &tx,
                                &user,
                                #event_kind,
                                created_id,
                                None,
                                Some(&after),
                            )
                            .await
                            {
                                let _ = tx.rollback().await;
                                return response;
                            }
                            if let Err(error) = tx.commit().await {
                                return #runtime_crate::core::errors::internal_error(error.to_string());
                            }
                            Self::created_response(created_id, &req, &user, db.get_ref(), #created_response_runtime).await
                        }
                        Err(error) => {
                            let _ = tx.rollback().await;
                            #runtime_crate::core::errors::internal_error(error.to_string())
                        }
                    }
                }
            }
            (_, true) => {
                quote! {
                    let tx = match db.get_ref().begin().await {
                        Ok(tx) => tx,
                        Err(error) => {
                            return #runtime_crate::core::errors::internal_error(error.to_string());
                        }
                    };
                    let sql = format!("INSERT INTO {} DEFAULT VALUES", #table_name);
                    match #runtime_crate::db::query(&sql).execute(&tx).await {
                        Ok(result) => match result.last_insert_rowid() {
                            Some(created_id) => {
                                let after = match Self::fetch_unfiltered_by_id_for_audit(created_id, &tx).await {
                                    Ok(Some(item)) => item,
                                    Ok(None) => {
                                        let _ = tx.rollback().await;
                                        return #runtime_crate::core::errors::internal_error(
                                            "created row could not be reloaded for audit",
                                        );
                                    }
                                    Err(error) => {
                                        let _ = tx.rollback().await;
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                };
                                if let Err(response) = Self::insert_audit_event(
                                    &tx,
                                    &user,
                                    #event_kind,
                                    created_id,
                                    None,
                                    Some(&after),
                                )
                                .await
                                {
                                    let _ = tx.rollback().await;
                                    return response;
                                }
                                if let Err(error) = tx.commit().await {
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                                Self::created_response(created_id, &req, &user, db.get_ref(), #created_response_runtime).await
                            }
                            None => {
                                let _ = tx.rollback().await;
                                #runtime_crate::core::errors::internal_error("created row id was not returned")
                            }
                        },
                        Err(error) => {
                            let _ = tx.rollback().await;
                            #runtime_crate::core::errors::internal_error(error.to_string())
                        }
                    }
                }
            }
            (_, false) => {
                quote! {
                    let tx = match db.get_ref().begin().await {
                        Ok(tx) => tx,
                        Err(error) => {
                            return #runtime_crate::core::errors::internal_error(error.to_string());
                        }
                    };
                    let sql = format!("INSERT INTO {} ({}) VALUES ({})", #table_name, #insert_fields_csv, #insert_placeholders);
                    let mut q = #runtime_crate::db::query(&sql);
                    #create_insert_binds
                    match q.execute(&tx).await {
                        Ok(result) => match result.last_insert_rowid() {
                            Some(created_id) => {
                                let after = match Self::fetch_unfiltered_by_id_for_audit(created_id, &tx).await {
                                    Ok(Some(item)) => item,
                                    Ok(None) => {
                                        let _ = tx.rollback().await;
                                        return #runtime_crate::core::errors::internal_error(
                                            "created row could not be reloaded for audit",
                                        );
                                    }
                                    Err(error) => {
                                        let _ = tx.rollback().await;
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                };
                                if let Err(response) = Self::insert_audit_event(
                                    &tx,
                                    &user,
                                    #event_kind,
                                    created_id,
                                    None,
                                    Some(&after),
                                )
                                .await
                                {
                                    let _ = tx.rollback().await;
                                    return response;
                                }
                                if let Err(error) = tx.commit().await {
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                                Self::created_response(created_id, &req, &user, db.get_ref(), #created_response_runtime).await
                            }
                            None => {
                                let _ = tx.rollback().await;
                                #runtime_crate::core::errors::internal_error("created row id was not returned")
                            }
                        },
                        Err(error) => {
                            let _ = tx.rollback().await;
                            #runtime_crate::core::errors::internal_error(error.to_string())
                        }
                    }
                }
            }
        }
    } else {
        match (resource.db, insert_fields.is_empty()) {
            (super::model::DbBackend::Postgres | super::model::DbBackend::Sqlite, true) => {
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
            (super::model::DbBackend::Postgres | super::model::DbBackend::Sqlite, false) => {
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
        if let Some(event_kind) = update_audit_event_kind {
            if !resource.policies.has_update_filters() {
                let sql = format!(
                    "UPDATE {} SET {} WHERE {} = {}",
                    resource.table_name,
                    update_sql,
                    resource.id_field,
                    resource.db.placeholder(update_plan.where_index)
                );

                quote! {
                    let id = path.into_inner();
                    let tx = match db.get_ref().begin().await {
                        Ok(tx) => tx,
                        Err(error) => {
                            return #runtime_crate::core::errors::internal_error(error.to_string());
                        }
                    };
                    let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                        Ok(item) => item,
                        Err(error) => {
                            let _ = tx.rollback().await;
                            return #runtime_crate::core::errors::internal_error(error.to_string());
                        }
                    };
                    let sql = #sql;
                    let mut q = #runtime_crate::db::query(sql);
                    #(#bind_fields_update)*
                    q = q.bind(id);
                    match q.execute(&tx).await {
                        Ok(result) if result.rows_affected() == 0 => {
                            let _ = tx.rollback().await;
                            #runtime_crate::core::errors::not_found("Not found")
                        }
                        Ok(_) => {
                            let after = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                Ok(Some(item)) => item,
                                Ok(None) => {
                                    let _ = tx.rollback().await;
                                    return #runtime_crate::core::errors::internal_error(
                                        "updated row could not be reloaded for audit",
                                    );
                                }
                                Err(error) => {
                                    let _ = tx.rollback().await;
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                            };
                            if let Err(response) = Self::insert_audit_event(
                                &tx,
                                &user,
                                #event_kind,
                                id,
                                before.as_ref(),
                                Some(&after),
                            )
                            .await
                            {
                                let _ = tx.rollback().await;
                                return response;
                            }
                            if let Err(error) = tx.commit().await {
                                return #runtime_crate::core::errors::internal_error(error.to_string());
                            }
                            HttpResponse::Ok().finish()
                        }
                        Err(error) => {
                            let _ = tx.rollback().await;
                            #runtime_crate::core::errors::internal_error(error.to_string())
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
                    resource.db.placeholder(update_plan.where_index)
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
                                let tx = match db.get_ref().begin().await {
                                    Ok(tx) => tx,
                                    Err(error) => {
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                };
                                let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                    Ok(item) => item,
                                    Err(error) => {
                                        let _ = tx.rollback().await;
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                };
                                let sql = #admin_sql;
                                let mut q = #runtime_crate::db::query(sql);
                                #(#bind_fields_update)*
                                q = q.bind(id);
                                match q.execute(&tx).await {
                                    Ok(result) if result.rows_affected() == 0 => {
                                        let _ = tx.rollback().await;
                                        #runtime_crate::core::errors::not_found("Not found")
                                    }
                                    Ok(_) => {
                                        let after = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                            Ok(Some(item)) => item,
                                            Ok(None) => {
                                                let _ = tx.rollback().await;
                                                return #runtime_crate::core::errors::internal_error(
                                                    "updated row could not be reloaded for audit",
                                                );
                                            }
                                            Err(error) => {
                                                let _ = tx.rollback().await;
                                                return #runtime_crate::core::errors::internal_error(error.to_string());
                                            }
                                        };
                                        if let Err(response) = Self::insert_audit_event(
                                            &tx,
                                            &user,
                                            #event_kind,
                                            id,
                                            before.as_ref(),
                                            Some(&after),
                                        )
                                        .await
                                        {
                                            let _ = tx.rollback().await;
                                            return response;
                                        }
                                        if let Err(error) = tx.commit().await {
                                            return #runtime_crate::core::errors::internal_error(error.to_string());
                                        }
                                        HttpResponse::Ok().finish()
                                    }
                                    Err(error) => {
                                        let _ = tx.rollback().await;
                                        #runtime_crate::core::errors::internal_error(error.to_string())
                                    }
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
                            let tx = match db.get_ref().begin().await {
                                Ok(tx) => tx,
                                Err(error) => {
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                            };
                            let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                Ok(item) => item,
                                Err(error) => {
                                    let _ = tx.rollback().await;
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                            };
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
                            match q.execute(&tx).await {
                                Ok(result) if result.rows_affected() == 0 => {
                                    let _ = tx.rollback().await;
                                    #hybrid_update_fallback
                                }
                                Ok(_) => {
                                    let after = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                        Ok(Some(item)) => item,
                                        Ok(None) => {
                                            let _ = tx.rollback().await;
                                            return #runtime_crate::core::errors::internal_error(
                                                "updated row could not be reloaded for audit",
                                            );
                                        }
                                        Err(error) => {
                                            let _ = tx.rollback().await;
                                            return #runtime_crate::core::errors::internal_error(error.to_string());
                                        }
                                    };
                                    if let Err(response) = Self::insert_audit_event(
                                        &tx,
                                        &user,
                                        #event_kind,
                                        id,
                                        before.as_ref(),
                                        Some(&after),
                                    )
                                    .await
                                    {
                                        let _ = tx.rollback().await;
                                        return response;
                                    }
                                    if let Err(error) = tx.commit().await {
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                    HttpResponse::Ok().finish()
                                }
                                Err(error) => {
                                    let _ = tx.rollback().await;
                                    #runtime_crate::core::errors::internal_error(error.to_string())
                                }
                            }
                        }
                        #plan_ident::Indeterminate => #hybrid_update_fallback,
                    }
                };
                if admin_bypass {
                    quote! {
                        let id = path.into_inner();
                        if #is_admin {
                            let tx = match db.get_ref().begin().await {
                                Ok(tx) => tx,
                                Err(error) => {
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                            };
                            let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                Ok(item) => item,
                                Err(error) => {
                                    let _ = tx.rollback().await;
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                            };
                            let sql = #admin_sql;
                            let mut q = #runtime_crate::db::query(sql);
                            #(#bind_fields_update)*
                            q = q.bind(id);
                            match q.execute(&tx).await {
                                Ok(result) if result.rows_affected() == 0 => {
                                    let _ = tx.rollback().await;
                                    #runtime_crate::core::errors::not_found("Not found")
                                }
                                Ok(_) => {
                                    let after = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                        Ok(Some(item)) => item,
                                        Ok(None) => {
                                            let _ = tx.rollback().await;
                                            return #runtime_crate::core::errors::internal_error(
                                                "updated row could not be reloaded for audit",
                                            );
                                        }
                                        Err(error) => {
                                            let _ = tx.rollback().await;
                                            return #runtime_crate::core::errors::internal_error(error.to_string());
                                        }
                                    };
                                    if let Err(response) = Self::insert_audit_event(
                                        &tx,
                                        &user,
                                        #event_kind,
                                        id,
                                        before.as_ref(),
                                        Some(&after),
                                    )
                                    .await
                                    {
                                        let _ = tx.rollback().await;
                                        return response;
                                    }
                                    if let Err(error) = tx.commit().await {
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                    HttpResponse::Ok().finish()
                                }
                                Err(error) => {
                                    let _ = tx.rollback().await;
                                    #runtime_crate::core::errors::internal_error(error.to_string())
                                }
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
        }
    };

    let delete_body = if let Some(event_kind) = delete_audit_event_kind {
        if !resource.policies.has_delete_filters() {
            let id_placeholder = resource.db.placeholder(1);
            quote! {
                let id = path.into_inner();
                let tx = match db.get_ref().begin().await {
                    Ok(tx) => tx,
                    Err(error) => {
                        return #runtime_crate::core::errors::internal_error(error.to_string());
                    }
                };
                let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                    Ok(Some(item)) => item,
                    Ok(None) => {
                        let _ = tx.rollback().await;
                        return #runtime_crate::core::errors::not_found("Not found");
                    }
                    Err(error) => {
                        let _ = tx.rollback().await;
                        return #runtime_crate::core::errors::internal_error(error.to_string());
                    }
                };
                let sql = format!("DELETE FROM {} WHERE {} = {}", #table_name, #id_field, #id_placeholder);
                match #runtime_crate::db::query(&sql)
                    .bind(id)
                    .execute(&tx)
                    .await
                {
                    Ok(result) if result.rows_affected() == 0 => {
                        let _ = tx.rollback().await;
                        #runtime_crate::core::errors::not_found("Not found")
                    }
                    Ok(_) => {
                        if let Err(response) = Self::insert_audit_event(
                            &tx,
                            &user,
                            #event_kind,
                            id,
                            Some(&before),
                            None,
                        )
                        .await
                        {
                            let _ = tx.rollback().await;
                            return response;
                        }
                        if let Err(error) = tx.commit().await {
                            return #runtime_crate::core::errors::internal_error(error.to_string());
                        }
                        HttpResponse::Ok().finish()
                    }
                    Err(error) => {
                        let _ = tx.rollback().await;
                        #runtime_crate::core::errors::internal_error(error.to_string())
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
                            let tx = match db.get_ref().begin().await {
                                Ok(tx) => tx,
                                Err(error) => {
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                            };
                            let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                Ok(Some(item)) => item,
                                Ok(None) => {
                                    let _ = tx.rollback().await;
                                    return #runtime_crate::core::errors::not_found("Not found");
                                }
                                Err(error) => {
                                    let _ = tx.rollback().await;
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                            };
                            let sql = #admin_sql;
                            match #runtime_crate::db::query(sql)
                                .bind(id)
                                .execute(&tx)
                                .await
                            {
                                Ok(result) if result.rows_affected() == 0 => {
                                    let _ = tx.rollback().await;
                                    #runtime_crate::core::errors::not_found("Not found")
                                }
                                Ok(_) => {
                                    if let Err(response) = Self::insert_audit_event(
                                        &tx,
                                        &user,
                                        #event_kind,
                                        id,
                                        Some(&before),
                                        None,
                                    )
                                    .await
                                    {
                                        let _ = tx.rollback().await;
                                        return response;
                                    }
                                    if let Err(error) = tx.commit().await {
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                    HttpResponse::Ok().finish()
                                }
                                Err(error) => {
                                    let _ = tx.rollback().await;
                                    #runtime_crate::core::errors::internal_error(error.to_string())
                                }
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
                        let tx = match db.get_ref().begin().await {
                            Ok(tx) => tx,
                            Err(error) => {
                                return #runtime_crate::core::errors::internal_error(error.to_string());
                            }
                        };
                        let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                            Ok(item) => item,
                            Err(error) => {
                                let _ = tx.rollback().await;
                                return #runtime_crate::core::errors::internal_error(error.to_string());
                            }
                        };
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
                        match q.execute(&tx).await {
                            Ok(result) if result.rows_affected() == 0 => {
                                let _ = tx.rollback().await;
                                #hybrid_delete_fallback
                            }
                            Ok(_) => {
                                let before = match before {
                                    Some(item) => item,
                                    None => {
                                        let _ = tx.rollback().await;
                                        return #runtime_crate::core::errors::internal_error(
                                            "deleted row could not be reloaded for audit",
                                        );
                                    }
                                };
                                if let Err(response) = Self::insert_audit_event(
                                    &tx,
                                    &user,
                                    #event_kind,
                                    id,
                                    Some(&before),
                                    None,
                                )
                                .await
                                {
                                    let _ = tx.rollback().await;
                                    return response;
                                }
                                if let Err(error) = tx.commit().await {
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                                HttpResponse::Ok().finish()
                            }
                            Err(error) => {
                                let _ = tx.rollback().await;
                                #runtime_crate::core::errors::internal_error(error.to_string())
                            }
                        }
                    }
                    #plan_ident::Indeterminate => #hybrid_delete_fallback,
                }
            };
            if admin_bypass {
                quote! {
                    let id = path.into_inner();
                    if #is_admin {
                        let tx = match db.get_ref().begin().await {
                            Ok(tx) => tx,
                            Err(error) => {
                                return #runtime_crate::core::errors::internal_error(error.to_string());
                            }
                        };
                        let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                            Ok(Some(item)) => item,
                            Ok(None) => {
                                let _ = tx.rollback().await;
                                return #runtime_crate::core::errors::not_found("Not found");
                            }
                            Err(error) => {
                                let _ = tx.rollback().await;
                                return #runtime_crate::core::errors::internal_error(error.to_string());
                            }
                        };
                        let sql = #admin_sql;
                        match #runtime_crate::db::query(sql)
                            .bind(id)
                            .execute(&tx)
                            .await
                        {
                            Ok(result) if result.rows_affected() == 0 => {
                                let _ = tx.rollback().await;
                                #runtime_crate::core::errors::not_found("Not found")
                            }
                            Ok(_) => {
                                if let Err(response) = Self::insert_audit_event(
                                    &tx,
                                    &user,
                                    #event_kind,
                                    id,
                                    Some(&before),
                                    None,
                                )
                                .await
                                {
                                    let _ = tx.rollback().await;
                                    return response;
                                }
                                if let Err(error) = tx.commit().await {
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                                HttpResponse::Ok().finish()
                            }
                            Err(error) => {
                                let _ = tx.rollback().await;
                                #runtime_crate::core::errors::internal_error(error.to_string())
                            }
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
        }
    } else if !resource.policies.has_delete_filters() {
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
    let count_handler = if read_requires_auth {
        if hybrid.map(|config| config.collection_read).unwrap_or(false) {
            quote! {
                async fn count(
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
                    match count_query.fetch_one(db.get_ref()).await {
                        Ok(count) => HttpResponse::Ok().json(#runtime_crate::serde_json::json!({ "count": count })),
                        Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                    }
                }
            }
        } else {
            quote! {
                async fn count(
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
                    match count_query.fetch_one(db.get_ref()).await {
                        Ok(count) => HttpResponse::Ok().json(#runtime_crate::serde_json::json!({ "count": count })),
                        Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                    }
                }
            }
        }
    } else {
        quote! {
            async fn count(
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
                match count_query.fetch_one(db.get_ref()).await {
                    Ok(count) => HttpResponse::Ok().json(#runtime_crate::serde_json::json!({ "count": count })),
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
    let collection_post_route = if is_audit_sink {
        quote!()
    } else {
        quote!(.route(web::post().to(Self::create)))
    };
    let count_route_registration = if resource.list.count_endpoint {
        quote! {
            cfg.service(
                web::resource(format!("/{}/count", #resource_api_name))
                    .route(web::get().to(Self::count))
            );
        }
    } else {
        quote!()
    };
    let item_write_routes = if is_audit_sink {
        quote!()
    } else {
        quote!(
            .route(web::put().to(Self::update))
            .route(web::delete().to(Self::delete))
        )
    };

    quote! {
        use #runtime_crate::actix_web::{web, HttpRequest, HttpResponse, Responder};
        use #runtime_crate::db::{DbExecutor, DbPool};

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
                        #collection_post_route
                );
                #count_route_registration
                cfg.service(
                    web::resource(format!("/{}/{{id}}", #resource_api_name))
                        .route(web::get().to(Self::get_one))
                        #item_write_routes
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

            #audit_helper_methods

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

            fn list_placeholders(start_index: usize, count: usize) -> String {
                (start_index..start_index + count)
                    .map(Self::list_placeholder)
                    .collect::<Vec<_>>()
                    .join(", ")
            }

            fn parse_filter_in_values<'a>(
                value: &'a str,
                max_values: usize,
            ) -> Result<Vec<&'a str>, HttpResponse> {
                let values = value
                    .split(',')
                    .map(str::trim)
                    .collect::<Vec<_>>();
                if values.is_empty() || values.iter().any(|value| value.is_empty()) {
                    return Err(#runtime_crate::core::errors::bad_request(
                        "invalid_query",
                        "Query parameters are invalid",
                    ));
                }
                if values.len() > max_values {
                    return Err(#runtime_crate::core::errors::bad_request(
                        "invalid_query",
                        "Query parameters are invalid",
                    ));
                }
                Ok(values)
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
                        Some(limit.min(max_limit))
                    }
                    (Some(limit), None) => Some(limit),
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
                if cursor_mode && effective_limit == Some(0) {
                    return Err(#runtime_crate::core::errors::bad_request(
                        "invalid_cursor",
                        "`cursor` requires `limit` to be greater than 0",
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
                        Some(0) => false,
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
            #count_handler

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

fn resource_action_garde_validation_error_helper(
    resource: &ResourceSpec,
    action: &super::model::ResourceActionSpec,
) -> syn::Ident {
    format_ident!(
        "garde_validation_error_{}_{}_action_input",
        resource.struct_ident.to_string().to_snake_case(),
        action.name.to_snake_case()
    )
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
    let error_helper = resource_action_garde_validation_error_helper(resource, action);
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
    let field_name_matches = action
        .input_fields
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let field_ident = resource_action_input_field_ident(index).to_string();
            let field_name = Literal::string(input.name.as_str());
            quote! {
                #field_ident => #field_name.to_owned(),
            }
        })
        .collect::<Vec<_>>();

    Some(quote! {
        #[allow(dead_code)]
        fn #error_helper(
            report: #runtime_crate::garde::Report,
        ) -> (Option<String>, String) {
            match report.iter().next() {
                Some((path, error)) => {
                    let field = match path.to_string().as_str() {
                        #(#field_name_matches)*
                        other => other.to_owned(),
                    };
                    let message = error.to_string();
                    if field.is_empty() {
                        (None, message)
                    } else {
                        (
                            Some(field.clone()),
                            format!("Field `{}` {}", field, message),
                        )
                    }
                }
                None => (None, "Validation failed".to_owned()),
            }
        }

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
            let garde_error_helper =
                resource_action_garde_validation_error_helper(resource, action);
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
            let update_audit_event_kind =
                update_audit_event_kind(resource, Some(action.name.as_str()))
                    .as_deref()
                    .map(Literal::string);

            if !resource.policies.has_update_filters() {
                let sql = format!(
                    "UPDATE {} SET {} WHERE {} = {}",
                    resource.table_name,
                    update_sql,
                    resource.id_field,
                    resource.db.placeholder(where_index)
                );
                if let Some(ref event_kind) = update_audit_event_kind {
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
                            let tx = match db.get_ref().begin().await {
                                Ok(tx) => tx,
                                Err(error) => {
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                            };
                            let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                Ok(item) => item,
                                Err(error) => {
                                    let _ = tx.rollback().await;
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                            };
                            let sql = #sql;
                            let mut q = #runtime_crate::db::query(sql);
                            #(#action_bind_statements)*
                            q = q.bind(id);
                            match q.execute(&tx).await {
                                Ok(result) if result.rows_affected() == 0 => {
                                    let _ = tx.rollback().await;
                                    #runtime_crate::core::errors::not_found("Not found")
                                }
                                Ok(_) => {
                                    let after = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                        Ok(Some(item)) => item,
                                        Ok(None) => {
                                            let _ = tx.rollback().await;
                                            return #runtime_crate::core::errors::internal_error(
                                                "updated row could not be reloaded for audit",
                                            );
                                        }
                                        Err(error) => {
                                            let _ = tx.rollback().await;
                                            return #runtime_crate::core::errors::internal_error(error.to_string());
                                        }
                                    };
                                    if let Err(response) = Self::insert_audit_event(
                                        &tx,
                                        &user,
                                        #event_kind,
                                        id,
                                        before.as_ref(),
                                        Some(&after),
                                    )
                                    .await
                                    {
                                        let _ = tx.rollback().await;
                                        return response;
                                    }
                                    if let Err(error) = tx.commit().await {
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                    HttpResponse::Ok().finish()
                                }
                                Err(error) => {
                                    let _ = tx.rollback().await;
                                    #runtime_crate::core::errors::internal_error(error.to_string())
                                }
                            }
                        }
                    }
                } else {
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
                    if let Some(ref event_kind) = update_audit_event_kind {
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
                                    let tx = match db.get_ref().begin().await {
                                        Ok(tx) => tx,
                                        Err(error) => {
                                            return #runtime_crate::core::errors::internal_error(error.to_string());
                                        }
                                    };
                                    let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                        Ok(item) => item,
                                        Err(error) => {
                                            let _ = tx.rollback().await;
                                            return #runtime_crate::core::errors::internal_error(error.to_string());
                                        }
                                    };
                                    let sql = #admin_sql;
                                    let mut q = #runtime_crate::db::query(sql);
                                    #(#action_bind_statements)*
                                    q = q.bind(id);
                                    match q.execute(&tx).await {
                                        Ok(result) if result.rows_affected() == 0 => {
                                            let _ = tx.rollback().await;
                                            #runtime_crate::core::errors::not_found("Not found")
                                        }
                                        Ok(_) => {
                                            let after = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                                Ok(Some(item)) => item,
                                                Ok(None) => {
                                                    let _ = tx.rollback().await;
                                                    return #runtime_crate::core::errors::internal_error(
                                                        "updated row could not be reloaded for audit",
                                                    );
                                                }
                                                Err(error) => {
                                                    let _ = tx.rollback().await;
                                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                                }
                                            };
                                            if let Err(response) = Self::insert_audit_event(
                                                &tx,
                                                &user,
                                                #event_kind,
                                                id,
                                                before.as_ref(),
                                                Some(&after),
                                            )
                                            .await
                                            {
                                                let _ = tx.rollback().await;
                                                return response;
                                            }
                                            if let Err(error) = tx.commit().await {
                                                return #runtime_crate::core::errors::internal_error(error.to_string());
                                            }
                                            HttpResponse::Ok().finish()
                                        }
                                        Err(error) => {
                                            let _ = tx.rollback().await;
                                            #runtime_crate::core::errors::internal_error(error.to_string())
                                        }
                                    }
                                }
                                Ok(None) => #runtime_crate::core::errors::not_found("Not found"),
                                Err(response) => response,
                            }
                        }
                    } else {
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
                    }
                } else {
                    quote!(#runtime_crate::core::errors::not_found("Not found"))
                };
                let filtered_update = if let Some(ref event_kind) = update_audit_event_kind {
                    quote! {
                        match Self::update_policy_plan(&user, #policy_start_index) {
                            #plan_ident::Resolved { condition, binds } => {
                                let tx = match db.get_ref().begin().await {
                                    Ok(tx) => tx,
                                    Err(error) => {
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                };
                                let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                    Ok(item) => item,
                                    Err(error) => {
                                        let _ = tx.rollback().await;
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                };
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
                                match q.execute(&tx).await {
                                    Ok(result) if result.rows_affected() == 0 => {
                                        let _ = tx.rollback().await;
                                        #hybrid_update_fallback
                                    }
                                    Ok(_) => {
                                        let after = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                            Ok(Some(item)) => item,
                                            Ok(None) => {
                                                let _ = tx.rollback().await;
                                                return #runtime_crate::core::errors::internal_error(
                                                    "updated row could not be reloaded for audit",
                                                );
                                            }
                                            Err(error) => {
                                                let _ = tx.rollback().await;
                                                return #runtime_crate::core::errors::internal_error(error.to_string());
                                            }
                                        };
                                        if let Err(response) = Self::insert_audit_event(
                                            &tx,
                                            &user,
                                            #event_kind,
                                            id,
                                            before.as_ref(),
                                            Some(&after),
                                        )
                                        .await
                                        {
                                            let _ = tx.rollback().await;
                                            return response;
                                        }
                                        if let Err(error) = tx.commit().await {
                                            return #runtime_crate::core::errors::internal_error(error.to_string());
                                        }
                                        HttpResponse::Ok().finish()
                                    }
                                    Err(error) => {
                                        let _ = tx.rollback().await;
                                        #runtime_crate::core::errors::internal_error(error.to_string())
                                    }
                                }
                            }
                            #plan_ident::Indeterminate => #hybrid_update_fallback,
                        }
                    }
                } else {
                    quote! {
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
                    }
                };
                let action_body = if admin_bypass {
                    if let Some(ref event_kind) = update_audit_event_kind {
                        quote! {
                            let id = path.into_inner();
                            #action_payload_setup
                            if #is_admin {
                                let tx = match db.get_ref().begin().await {
                                    Ok(tx) => tx,
                                    Err(error) => {
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                };
                                let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                    Ok(item) => item,
                                    Err(error) => {
                                        let _ = tx.rollback().await;
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                };
                                let sql = #admin_sql;
                                let mut q = #runtime_crate::db::query(sql);
                                #(#action_bind_statements)*
                                q = q.bind(id);
                                match q.execute(&tx).await {
                                    Ok(result) if result.rows_affected() == 0 => {
                                        let _ = tx.rollback().await;
                                        #runtime_crate::core::errors::not_found("Not found")
                                    }
                                    Ok(_) => {
                                        let after = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                            Ok(Some(item)) => item,
                                            Ok(None) => {
                                                let _ = tx.rollback().await;
                                                return #runtime_crate::core::errors::internal_error(
                                                    "updated row could not be reloaded for audit",
                                                );
                                            }
                                            Err(error) => {
                                                let _ = tx.rollback().await;
                                                return #runtime_crate::core::errors::internal_error(error.to_string());
                                            }
                                        };
                                        if let Err(response) = Self::insert_audit_event(
                                            &tx,
                                            &user,
                                            #event_kind,
                                            id,
                                            before.as_ref(),
                                            Some(&after),
                                        )
                                        .await
                                        {
                                            let _ = tx.rollback().await;
                                            return response;
                                        }
                                        if let Err(error) = tx.commit().await {
                                            return #runtime_crate::core::errors::internal_error(error.to_string());
                                        }
                                        HttpResponse::Ok().finish()
                                    }
                                    Err(error) => {
                                        let _ = tx.rollback().await;
                                        #runtime_crate::core::errors::internal_error(error.to_string())
                                    }
                                }
                            } else {
                                #filtered_update
                            }
                        }
                    } else {
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
            let delete_audit_event_kind =
                delete_audit_event_kind(resource, Some(action.name.as_str()))
                    .as_deref()
                    .map(Literal::string);

            if !resource.policies.has_delete_filters() {
                let id_placeholder = resource.db.placeholder(1);
                if let Some(ref event_kind) = delete_audit_event_kind {
                    quote! {
                        async fn #handler_ident(
                            path: web::Path<i64>,
                            user: #runtime_crate::core::auth::UserContext,
                            db: web::Data<DbPool>
                            #delete_runtime_arg
                        ) -> impl Responder {
                            let _ = (&path, &user, &db);
                            #delete_check
                            let id = path.into_inner();
                            let tx = match db.get_ref().begin().await {
                                Ok(tx) => tx,
                                Err(error) => {
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                            };
                            let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                Ok(Some(item)) => item,
                                Ok(None) => {
                                    let _ = tx.rollback().await;
                                    return #runtime_crate::core::errors::not_found("Not found");
                                }
                                Err(error) => {
                                    let _ = tx.rollback().await;
                                    return #runtime_crate::core::errors::internal_error(error.to_string());
                                }
                            };
                            let sql = format!(
                                "DELETE FROM {} WHERE {} = {}",
                                #table_name,
                                #id_field,
                                #id_placeholder
                            );
                            match #runtime_crate::db::query(&sql)
                                .bind(id)
                                .execute(&tx)
                                .await
                            {
                                Ok(result) if result.rows_affected() == 0 => {
                                    let _ = tx.rollback().await;
                                    #runtime_crate::core::errors::not_found("Not found")
                                }
                                Ok(_) => {
                                    if let Err(response) = Self::insert_audit_event(
                                        &tx,
                                        &user,
                                        #event_kind,
                                        id,
                                        Some(&before),
                                        None,
                                    )
                                    .await
                                    {
                                        let _ = tx.rollback().await;
                                        return response;
                                    }
                                    if let Err(error) = tx.commit().await {
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                    HttpResponse::Ok().finish()
                                }
                                Err(error) => {
                                    let _ = tx.rollback().await;
                                    #runtime_crate::core::errors::internal_error(error.to_string())
                                }
                            }
                        }
                    }
                } else {
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
                    if let Some(ref event_kind) = delete_audit_event_kind {
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
                                    let tx = match db.get_ref().begin().await {
                                        Ok(tx) => tx,
                                        Err(error) => {
                                            return #runtime_crate::core::errors::internal_error(error.to_string());
                                        }
                                    };
                                    let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                        Ok(Some(item)) => item,
                                        Ok(None) => {
                                            let _ = tx.rollback().await;
                                            return #runtime_crate::core::errors::not_found("Not found");
                                        }
                                        Err(error) => {
                                            let _ = tx.rollback().await;
                                            return #runtime_crate::core::errors::internal_error(error.to_string());
                                        }
                                    };
                                    let sql = #admin_sql;
                                    match #runtime_crate::db::query(sql)
                                        .bind(id)
                                        .execute(&tx)
                                        .await
                                    {
                                        Ok(result) if result.rows_affected() == 0 => {
                                            let _ = tx.rollback().await;
                                            #runtime_crate::core::errors::not_found("Not found")
                                        }
                                        Ok(_) => {
                                            if let Err(response) = Self::insert_audit_event(
                                                &tx,
                                                &user,
                                                #event_kind,
                                                id,
                                                Some(&before),
                                                None,
                                            )
                                            .await
                                            {
                                                let _ = tx.rollback().await;
                                                return response;
                                            }
                                            if let Err(error) = tx.commit().await {
                                                return #runtime_crate::core::errors::internal_error(error.to_string());
                                            }
                                            HttpResponse::Ok().finish()
                                        }
                                        Err(error) => {
                                            let _ = tx.rollback().await;
                                            #runtime_crate::core::errors::internal_error(error.to_string())
                                        }
                                    }
                                }
                                Ok(None) => #runtime_crate::core::errors::not_found("Not found"),
                                Err(response) => response,
                            }
                        }
                    } else {
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
                    }
                } else {
                    quote!(#runtime_crate::core::errors::not_found("Not found"))
                };
                let filtered_delete = if let Some(ref event_kind) = delete_audit_event_kind {
                    quote! {
                        match Self::delete_policy_plan(&user, 2) {
                            #plan_ident::Resolved { condition, binds } => {
                                let tx = match db.get_ref().begin().await {
                                    Ok(tx) => tx,
                                    Err(error) => {
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                };
                                let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                    Ok(item) => item,
                                    Err(error) => {
                                        let _ = tx.rollback().await;
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                };
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
                                match q.execute(&tx).await {
                                    Ok(result) if result.rows_affected() == 0 => {
                                        let _ = tx.rollback().await;
                                        #hybrid_delete_fallback
                                    }
                                    Ok(_) => {
                                        let before = match before {
                                            Some(item) => item,
                                            None => {
                                                let _ = tx.rollback().await;
                                                return #runtime_crate::core::errors::internal_error(
                                                    "deleted row could not be reloaded for audit",
                                                );
                                            }
                                        };
                                        if let Err(response) = Self::insert_audit_event(
                                            &tx,
                                            &user,
                                            #event_kind,
                                            id,
                                            Some(&before),
                                            None,
                                        )
                                        .await
                                        {
                                            let _ = tx.rollback().await;
                                            return response;
                                        }
                                        if let Err(error) = tx.commit().await {
                                            return #runtime_crate::core::errors::internal_error(error.to_string());
                                        }
                                        HttpResponse::Ok().finish()
                                    }
                                    Err(error) => {
                                        let _ = tx.rollback().await;
                                        #runtime_crate::core::errors::internal_error(error.to_string())
                                    }
                                }
                            }
                            #plan_ident::Indeterminate => #hybrid_delete_fallback,
                        }
                    }
                } else {
                    quote! {
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
                    }
                };
                let delete_body = if admin_bypass {
                    if let Some(ref event_kind) = delete_audit_event_kind {
                        quote! {
                            let id = path.into_inner();
                            if #is_admin {
                                let tx = match db.get_ref().begin().await {
                                    Ok(tx) => tx,
                                    Err(error) => {
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                };
                                let before = match Self::fetch_unfiltered_by_id_for_audit(id, &tx).await {
                                    Ok(Some(item)) => item,
                                    Ok(None) => {
                                        let _ = tx.rollback().await;
                                        return #runtime_crate::core::errors::not_found("Not found");
                                    }
                                    Err(error) => {
                                        let _ = tx.rollback().await;
                                        return #runtime_crate::core::errors::internal_error(error.to_string());
                                    }
                                };
                                let sql = #admin_sql;
                                match #runtime_crate::db::query(sql)
                                    .bind(id)
                                    .execute(&tx)
                                    .await
                                {
                                    Ok(result) if result.rows_affected() == 0 => {
                                        let _ = tx.rollback().await;
                                        #runtime_crate::core::errors::not_found("Not found")
                                    }
                                    Ok(_) => {
                                        if let Err(response) = Self::insert_audit_event(
                                            &tx,
                                            &user,
                                            #event_kind,
                                            id,
                                            Some(&before),
                                            None,
                                        )
                                        .await
                                        {
                                            let _ = tx.rollback().await;
                                            return response;
                                        }
                                        if let Err(error) = tx.commit().await {
                                            return #runtime_crate::core::errors::internal_error(error.to_string());
                                        }
                                        HttpResponse::Ok().finish()
                                    }
                                    Err(error) => {
                                        let _ = tx.rollback().await;
                                        #runtime_crate::core::errors::internal_error(error.to_string())
                                    }
                                }
                            } else {
                                #filtered_delete
                            }
                        }
                    } else {
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

fn list_query_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListQuery", resource.struct_ident)
}

fn list_query_type(resource: &ResourceSpec) -> TokenStream {
    let ident = list_query_ident(resource);
    quote!(#ident)
}

fn list_sort_field_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListSortField", resource.struct_ident)
}

fn list_sort_order_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListSortOrder", resource.struct_ident)
}

fn list_bind_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListBindValue", resource.struct_ident)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ListBindKind {
    Integer,
    Real,
    Boolean,
    Text,
}

#[derive(Clone, Copy, Debug, Default)]
struct PolicyHelperUsage {
    needs_all: bool,
    needs_any: bool,
    needs_not: bool,
}

impl PolicyHelperUsage {
    fn merge(self, other: Self) -> Self {
        Self {
            needs_all: self.needs_all || other.needs_all,
            needs_any: self.needs_any || other.needs_any,
            needs_not: self.needs_not || other.needs_not,
        }
    }
}

fn list_bind_kind_for_field(field: &super::model::FieldSpec) -> ListBindKind {
    if super::model::is_structured_scalar_type(&field.ty) {
        return ListBindKind::Text;
    }

    if super::model::is_bool_type(&field.ty) {
        return ListBindKind::Boolean;
    }

    match field.sql_type.as_str() {
        sql_type if super::model::is_integer_sql_type(sql_type) => ListBindKind::Integer,
        "REAL" => ListBindKind::Real,
        _ => ListBindKind::Text,
    }
}

fn collect_exists_condition_bind_kinds(
    resource: &ResourceSpec,
    target_resource: &ResourceSpec,
    condition: &super::model::PolicyExistsCondition,
    kinds: &mut BTreeSet<ListBindKind>,
) {
    match condition {
        super::model::PolicyExistsCondition::Match(filter) => {
            let field = resource_field(target_resource, &filter.field);
            kinds.insert(list_bind_kind_for_field(field));
        }
        super::model::PolicyExistsCondition::CurrentRowField { row_field, .. } => {
            let field = resource_field(resource, row_field);
            kinds.insert(list_bind_kind_for_field(field));
        }
        super::model::PolicyExistsCondition::All(conditions)
        | super::model::PolicyExistsCondition::Any(conditions) => {
            for condition in conditions {
                collect_exists_condition_bind_kinds(resource, target_resource, condition, kinds);
            }
        }
        super::model::PolicyExistsCondition::Not(condition) => {
            collect_exists_condition_bind_kinds(resource, target_resource, condition, kinds);
        }
    }
}

fn policy_exists_condition_helper_usage(
    condition: &super::model::PolicyExistsCondition,
) -> PolicyHelperUsage {
    match condition {
        super::model::PolicyExistsCondition::Match(_)
        | super::model::PolicyExistsCondition::CurrentRowField { .. } => {
            PolicyHelperUsage::default()
        }
        super::model::PolicyExistsCondition::All(conditions) => conditions.iter().fold(
            PolicyHelperUsage {
                needs_all: true,
                ..PolicyHelperUsage::default()
            },
            |usage, condition| usage.merge(policy_exists_condition_helper_usage(condition)),
        ),
        super::model::PolicyExistsCondition::Any(conditions) => conditions.iter().fold(
            PolicyHelperUsage {
                needs_any: true,
                ..PolicyHelperUsage::default()
            },
            |usage, condition| usage.merge(policy_exists_condition_helper_usage(condition)),
        ),
        super::model::PolicyExistsCondition::Not(condition) => PolicyHelperUsage {
            needs_not: true,
            ..policy_exists_condition_helper_usage(condition)
        },
    }
}

fn policy_expression_helper_usage(expression: &PolicyFilterExpression) -> PolicyHelperUsage {
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

fn list_bind_kinds(resource: &ResourceSpec, resources: &[ResourceSpec]) -> Vec<ListBindKind> {
    let mut kinds = BTreeSet::new();
    kinds.insert(ListBindKind::Integer);

    for field in resource.api_fields() {
        if super::model::supports_exact_filters(field) || field_supports_sort(field) {
            kinds.insert(list_bind_kind_for_field(field));
        }
        if super::model::supports_contains_filters(field) {
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

fn list_bind_type(resource: &ResourceSpec) -> TokenStream {
    let ident = list_bind_ident(resource);
    quote!(#ident)
}

fn option_u32_tokens(value: Option<u32>) -> TokenStream {
    match value {
        Some(value) => {
            let value = Literal::u32_unsuffixed(value);
            quote!(Some(#value))
        }
        None => quote!(None),
    }
}

fn list_plan_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListQueryPlan", resource.struct_ident)
}

fn list_plan_type(resource: &ResourceSpec) -> TokenStream {
    let ident = list_plan_ident(resource);
    quote!(#ident)
}

fn list_response_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListResponse", resource.struct_ident)
}

fn list_response_type(resource: &ResourceSpec) -> TokenStream {
    let ident = list_response_ident(resource);
    quote!(#ident)
}

fn list_cursor_value_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}CursorValue", resource.struct_ident)
}

fn list_cursor_payload_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}CursorPayload", resource.struct_ident)
}

fn list_filter_field_ty(field: &super::model::FieldSpec, runtime_crate: &Path) -> TokenStream {
    if let Some(kind) = super::model::structured_scalar_kind(&field.ty) {
        return structured_scalar_type_tokens(kind, runtime_crate);
    }

    if super::model::is_bool_type(&field.ty) {
        return quote!(bool);
    }

    match field.sql_type.as_str() {
        sql_type if super::model::is_integer_sql_type(sql_type) => quote!(i64),
        "REAL" => quote!(f64),
        _ => quote!(String),
    }
}

fn filter_in_bind_tokens(
    field: &super::model::FieldSpec,
    bind_ident: &syn::Ident,
    runtime_crate: &Path,
) -> TokenStream {
    if super::model::is_structured_scalar_type(&field.ty) {
        let ty = list_filter_field_ty(field, runtime_crate);
        let text_value = structured_scalar_to_text_tokens(&field.ty, quote!(parsed), runtime_crate)
            .expect("structured scalar should render as text");
        return quote! {
            let parsed: #ty = match value.parse() {
                Ok(value) => value,
                Err(_) => {
                    return Err(#runtime_crate::core::errors::bad_request(
                        "invalid_query",
                        "Query parameters are invalid",
                    ));
                }
            };
            filter_binds.push(#bind_ident::Text(#text_value));
        };
    }

    if super::model::is_bool_type(&field.ty) {
        return quote! {
            let parsed = match value.parse::<bool>() {
                Ok(value) => value,
                Err(_) => {
                    return Err(#runtime_crate::core::errors::bad_request(
                        "invalid_query",
                        "Query parameters are invalid",
                    ));
                }
            };
            filter_binds.push(#bind_ident::Boolean(parsed));
        };
    }

    match field.sql_type.as_str() {
        sql_type if super::model::is_integer_sql_type(sql_type) => quote! {
            let parsed = match value.parse::<i64>() {
                Ok(value) => value,
                Err(_) => {
                    return Err(#runtime_crate::core::errors::bad_request(
                        "invalid_query",
                        "Query parameters are invalid",
                    ));
                }
            };
            filter_binds.push(#bind_ident::Integer(parsed));
        },
        "REAL" => quote! {
            let parsed = match value.parse::<f64>() {
                Ok(value) => value,
                Err(_) => {
                    return Err(#runtime_crate::core::errors::bad_request(
                        "invalid_query",
                        "Query parameters are invalid",
                    ));
                }
            };
            filter_binds.push(#bind_ident::Real(parsed));
        },
        _ => {
            let enum_check = if let Some(enum_values) = field.enum_values() {
                let enum_values = enum_values
                    .iter()
                    .map(|value| Literal::string(value.as_str()))
                    .collect::<Vec<_>>();
                quote! {
                    if ![#(#enum_values),*].contains(&value) {
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
                #enum_check
                filter_binds.push(#bind_ident::Text(value.to_owned()));
            }
        }
    }
}

fn list_query_condition_tokens(
    resource: &ResourceSpec,
    max_filter_in_values: usize,
    runtime_crate: &Path,
) -> Vec<TokenStream> {
    let bind_ident = list_bind_ident(resource);
    let max_filter_in_values_lit = Literal::usize_unsuffixed(max_filter_in_values);
    resource
        .fields
        .iter()
        .map(|field| {
            if !field.expose_in_api() {
                return quote! {};
            }
            let field_name = Literal::string(&field.name());
            let contains_filter_tokens = if super::model::supports_contains_filters(field) {
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
            let exact_filter_tokens = if !super::model::supports_exact_filters(field) {
                quote! {}
            } else {
                let filter_ident = format_ident!("filter_{}", field.ident);
                if super::model::is_structured_scalar_type(&field.ty) {
                    let exact_value =
                        structured_scalar_to_text_tokens(&field.ty, quote!(value), runtime_crate);
                    let exact_value = exact_value.expect("structured scalar should render as text");
                    if super::model::supports_range_filters(&field.ty) {
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
                } else if super::model::is_bool_type(&field.ty) {
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
                        sql_type if super::model::is_integer_sql_type(sql_type) => quote! {
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
            let filter_in_tokens = if super::model::supports_exact_filters(field)
                && resource
                    .list
                    .filterable_in
                    .iter()
                    .any(|candidate| candidate == &field.name())
            {
                let filter_in_ident = format_ident!("filter_{}__in", field.ident);
                let bind_value_tokens = filter_in_bind_tokens(field, &bind_ident, runtime_crate);
                quote! {
                    if let Some(value) = &query.#filter_in_ident {
                        let values = Self::parse_filter_in_values(value, #max_filter_in_values_lit)?;
                        conditions.push(format!(
                            "{} IN ({})",
                            #field_name,
                            Self::list_placeholders(filter_binds.len() + 1, values.len())
                        ));
                        for value in values {
                            #bind_value_tokens
                        }
                    }
                }
            } else {
                quote! {}
            };
            quote! {
                #exact_filter_tokens
                #filter_in_tokens
                #contains_filter_tokens
            }
        })
        .collect()
}

fn list_bind_match_tokens(
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

fn validation_tokens(
    resource: &ResourceSpec,
    field: &super::model::FieldSpec,
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

fn typed_object_payload_validation_tokens(
    resource: &ResourceSpec,
    field: &super::model::FieldSpec,
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

fn enum_values_as_message(field: &super::model::FieldSpec) -> String {
    field
        .enum_values()
        .expect("enum-backed field should define enum values")
        .join(", ")
}

fn validation_checks(
    field: &super::model::FieldSpec,
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

fn insert_fields(resource: &ResourceSpec) -> Vec<&super::model::FieldSpec> {
    resource
        .fields
        .iter()
        .filter(|field| !field.generated.skip_insert())
        .collect()
}

fn policy_controlled_fields(resource: &ResourceSpec) -> BTreeSet<String> {
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

fn create_assignment_source<'a>(
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

fn resource_field<'a>(resource: &'a ResourceSpec, field_name: &str) -> &'a super::model::FieldSpec {
    resource
        .fields
        .iter()
        .find(|field| field.name() == field_name)
        .unwrap_or_else(|| panic!("validated resource is missing policy field `{field_name}`"))
}

fn claim_access_value_tokens(claim_name: &Literal, field: &super::model::FieldSpec) -> TokenStream {
    match super::model::policy_field_claim_type(&field.ty)
        .unwrap_or_else(|| panic!("unsupported row policy field type for `{}`", field.name()))
    {
        crate::auth::AuthClaimType::I64 => quote!(user.claim_i64(#claim_name)),
        crate::auth::AuthClaimType::Bool => quote!(user.claim_bool(#claim_name)),
        crate::auth::AuthClaimType::String => {
            quote!(user.claim_str(#claim_name).map(|value| value.to_owned()))
        }
    }
}

fn policy_source_value(
    source: &PolicyValueSource,
    field: &super::model::FieldSpec,
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

fn optional_policy_source_value(
    source: &PolicyValueSource,
    field: &super::model::FieldSpec,
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

fn policy_literal_value_tokens(value: &PolicyLiteralValue) -> TokenStream {
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

fn list_bind_value_tokens(
    bind_ident: &syn::Ident,
    field: &super::model::FieldSpec,
    value: TokenStream,
) -> TokenStream {
    match super::model::policy_field_claim_type(&field.ty)
        .unwrap_or_else(|| panic!("unsupported row policy field type for `{}`", field.name()))
    {
        crate::auth::AuthClaimType::I64 => quote!(#bind_ident::Integer(#value)),
        crate::auth::AuthClaimType::Bool => quote!(#bind_ident::Boolean(#value)),
        crate::auth::AuthClaimType::String => quote!(#bind_ident::Text(#value)),
    }
}

fn policy_plan_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}PolicyFilterPlan", resource.struct_ident)
}

fn maybe_policy_comparison_value(
    source: &PolicyComparisonValue,
    field: &super::model::FieldSpec,
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

fn policy_plan_enum_tokens(resource: &ResourceSpec) -> TokenStream {
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

fn policy_plan_method_tokens(
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

fn single_policy_plan_method_tokens(
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

fn create_requirement_method_tokens(
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
fn create_requirement_expression_plan_tokens(
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
                super::model::PolicyFilterOperator::Equals(source) => {
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
                super::model::PolicyFilterOperator::IsNull => {
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
                super::model::PolicyFilterOperator::IsNotNull => {
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
fn create_requirement_exists_condition_tokens(
    resource: &ResourceSpec,
    target_resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
    condition: &super::model::PolicyExistsCondition,
    bind_ident: &syn::Ident,
    next_index_ident: &syn::Ident,
    alias: &Literal,
    runtime_crate: &Path,
    path: &str,
) -> TokenStream {
    match condition {
        super::model::PolicyExistsCondition::Match(filter) => {
            let field = resource_field(target_resource, &filter.field);
            let field_name = Literal::string(&filter.field);
            match &filter.operator {
                super::model::PolicyFilterOperator::Equals(source) => {
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
                super::model::PolicyFilterOperator::IsNull => {
                    quote!((format!("{}.{} IS NULL", #alias, #field_name), Vec::<#bind_ident>::new()))
                }
                super::model::PolicyFilterOperator::IsNotNull => {
                    quote!((format!("{}.{} IS NOT NULL", #alias, #field_name), Vec::<#bind_ident>::new()))
                }
            }
        }
        super::model::PolicyExistsCondition::CurrentRowField { field, row_field } => {
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
        super::model::PolicyExistsCondition::All(conditions) => {
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
        super::model::PolicyExistsCondition::Any(conditions) => {
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
        super::model::PolicyExistsCondition::Not(condition) => {
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

fn create_source_value_tokens(
    resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
    target_field: &super::model::FieldSpec,
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

fn create_comparison_value_tokens(
    resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
    target_field: &super::model::FieldSpec,
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

fn create_claim_source_value_tokens(
    target_field: &super::model::FieldSpec,
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

fn create_effective_field_value_tokens(
    resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
    field: &super::model::FieldSpec,
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

fn create_raw_input_field_value_tokens(
    resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
    field: &super::model::FieldSpec,
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
fn policy_expression_plan_tokens(
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
                super::model::PolicyFilterOperator::Equals(source) => {
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
                super::model::PolicyFilterOperator::IsNull => quote! {
                    #plan_ident::Resolved {
                        condition: format!("{} IS NULL", #field_name),
                        binds: Vec::<#bind_ident>::new(),
                    }
                },
                super::model::PolicyFilterOperator::IsNotNull => quote! {
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
fn exists_condition_plan_tokens(
    target_resource: &ResourceSpec,
    condition: &super::model::PolicyExistsCondition,
    bind_ident: &syn::Ident,
    plan_ident: &syn::Ident,
    next_index_ident: &syn::Ident,
    alias: &Literal,
    current_table_name: &Literal,
    path: &str,
) -> TokenStream {
    match condition {
        super::model::PolicyExistsCondition::Match(filter) => {
            let field = resource_field(target_resource, &filter.field);
            let field_name = Literal::string(&filter.field);
            match &filter.operator {
                super::model::PolicyFilterOperator::Equals(source) => {
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
                super::model::PolicyFilterOperator::IsNull => quote! {
                    #plan_ident::Resolved {
                        condition: format!("{}.{} IS NULL", #alias, #field_name),
                        binds: Vec::<#bind_ident>::new(),
                    }
                },
                super::model::PolicyFilterOperator::IsNotNull => quote! {
                    #plan_ident::Resolved {
                        condition: format!("{}.{} IS NOT NULL", #alias, #field_name),
                        binds: Vec::<#bind_ident>::new(),
                    }
                },
            }
        }
        super::model::PolicyExistsCondition::CurrentRowField { field, row_field } => {
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
        super::model::PolicyExistsCondition::All(conditions) => {
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
        super::model::PolicyExistsCondition::Any(conditions) => {
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
        super::model::PolicyExistsCondition::Not(condition) => {
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

fn role_guard(runtime_crate: &Path, role: Option<&str>) -> TokenStream {
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

struct UpdatePlan {
    clauses: Vec<String>,
    bind_fields: Vec<syn::Ident>,
    where_index: usize,
}

fn build_update_plan(resource: &ResourceSpec) -> UpdatePlan {
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
                            super::model::generated_temporal_kind_for_field(
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
