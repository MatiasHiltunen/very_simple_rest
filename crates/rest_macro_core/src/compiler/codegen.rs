use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::Path;

use super::model::{
    ResourceSpec, ServiceSpec,
    StaticCacheProfile, StaticMode,
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



mod garde_tokens;
use self::garde_tokens::*;

mod resource_struct_tokens;
use self::resource_struct_tokens::*;


mod resource_impl;
use self::resource_impl::*;

mod resource_action_tokens;
use self::resource_action_tokens::*;

mod payload_tokens;
use self::payload_tokens::*;

mod list_tokens;
use self::list_tokens::*;

mod policy_plan_tokens;
use self::policy_plan_tokens::*;
