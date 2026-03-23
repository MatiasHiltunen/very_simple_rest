use std::collections::BTreeSet;

use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::Path;

use super::model::{
    GeneratedValue, PolicyFilterExpression, PolicyValueSource, ResourceSpec, ServiceSpec,
    StaticCacheProfile, StaticMode, WriteModelStyle, default_service_database_url,
};
use crate::{
    authorization::{
        ActionAuthorization, AuthorizationAssignment, AuthorizationCondition,
        AuthorizationExistsCondition, AuthorizationMatch, AuthorizationModel,
        AuthorizationOperator, AuthorizationValueSource, ResourceAuthorization,
    },
    database::DatabaseEngine,
    logging::LogTimestampPrecision,
    security::{FrameOptions, ReferrerPolicy},
};

pub fn expand_resource_impl(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    runtime_crate: &Path,
) -> syn::Result<TokenStream> {
    let impl_module_ident = &resource.impl_module_ident;
    let impl_body = resource_impl_tokens(resource, resources, runtime_crate);

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
    let struct_tokens = resource_struct_tokens(resource, runtime_crate);
    let impl_tokens =
        expand_resource_impl(resource, std::slice::from_ref(resource), runtime_crate)?;

    Ok(quote! {
        #struct_tokens
        #impl_tokens
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
    };
    let include_path_lit = Literal::string(include_path);
    let resources = service
        .resources
        .iter()
        .map(|resource| {
            let struct_tokens = resource_struct_tokens(resource, runtime_crate);
            let impl_tokens = expand_resource_impl(resource, &service.resources, runtime_crate)?;
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
    let configure_static_body = if service.static_mounts.is_empty() {
        quote! {}
    } else {
        quote! {
            let mounts = [
                #(#static_mounts),*
            ];
            let runtime = runtime();
            #runtime_crate::core::static_files::configure_static_mounts_with_runtime(
                cfg,
                &mounts,
                &runtime,
            );
        }
    };
    let database = database_tokens(service, runtime_crate);
    let default_database_url = Literal::string(&default_service_database_url(service));
    let logging = logging_tokens(service, runtime_crate);
    let runtime = runtime_tokens(service, runtime_crate);
    let security = security_tokens(service, runtime_crate);
    let authorization = authorization_tokens(service, runtime_crate);
    let tls = tls_tokens(service, runtime_crate);

    Ok(quote! {
        pub mod #module_ident {
            const _: &str = include_str!(#include_path_lit);

            #type_aliases

            use #runtime_crate::actix_web::{web, HttpResponse, Responder};
            use #runtime_crate::db::DbPool;

            #(#resources)*

            pub fn configure(cfg: &mut web::ServiceConfig, db: impl Into<DbPool>) {
                let db = db.into();
                cfg.app_data(web::Data::new(authorization_runtime(db.clone())));
                #(#configure_calls)*
                configure_security(cfg);
            }

            pub fn configure_static(cfg: &mut web::ServiceConfig) {
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

            pub fn security() -> #runtime_crate::core::security::SecurityConfig {
                #security
            }

            pub fn authorization() -> #runtime_crate::core::authorization::AuthorizationModel {
                #authorization
            }

            pub fn authorization_runtime(
                db: impl Into<DbPool>,
            ) -> #runtime_crate::core::authorization::AuthorizationRuntime {
                #runtime_crate::core::authorization::AuthorizationRuntime::new(
                    authorization(),
                    db,
                )
            }

            pub fn tls() -> #runtime_crate::core::tls::TlsConfig {
                #tls
            }

            pub fn configure_security(cfg: &mut web::ServiceConfig) {
                let security = security();
                #runtime_crate::core::security::configure_scope_security(cfg, &security);
            }

            pub fn configure_authorization_management(
                cfg: &mut web::ServiceConfig,
                db: impl Into<DbPool>,
            ) {
                let db = db.into();
                cfg.app_data(web::Data::new(authorization_runtime(db)));
                #runtime_crate::core::authorization::authorization_management_routes(cfg);
            }
        }
    })
}

fn authorization_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
    let model = super::authorization::compile_service_authorization(service);
    authorization_model_tokens(&model, runtime_crate)
}

fn authorization_model_tokens(model: &AuthorizationModel, runtime_crate: &Path) -> TokenStream {
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
    let source = value_source_tokens(&rule.source, runtime_crate);

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

fn database_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
    match &service.database.engine {
        DatabaseEngine::Sqlx => {
            quote!(#runtime_crate::core::database::DatabaseConfig {
                engine: #runtime_crate::core::database::DatabaseEngine::Sqlx,
            })
        }
        DatabaseEngine::TursoLocal(engine) => {
            let path = Literal::string(&engine.path);
            let encryption_key_env = match engine.encryption_key_env.as_deref() {
                Some(value) => {
                    let value = Literal::string(value);
                    quote!(Some(#value.to_owned()))
                }
                None => quote!(None),
            };
            quote!(#runtime_crate::core::database::DatabaseConfig {
                engine: #runtime_crate::core::database::DatabaseEngine::TursoLocal(
                    #runtime_crate::core::database::TursoLocalConfig {
                        path: #path.to_owned(),
                        encryption_key_env: #encryption_key_env,
                    }
                ),
            })
        }
    }
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

fn security_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
    let security = &service.security;
    let json_max_bytes = option_usize_tokens(security.requests.json_max_bytes);
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
    let auth_claims = auth_claim_mappings_tokens(&security.auth.claims, runtime_crate);
    let session_cookie =
        option_session_cookie_tokens(security.auth.session_cookie.as_ref(), runtime_crate);
    let email = option_auth_email_tokens(security.auth.email.as_ref(), runtime_crate);
    let portal = option_auth_ui_page_tokens(security.auth.portal.as_ref(), runtime_crate);
    let admin_dashboard =
        option_auth_ui_page_tokens(security.auth.admin_dashboard.as_ref(), runtime_crate);
    let content_type_options = security.headers.content_type_options;

    quote! {
        #runtime_crate::core::security::SecurityConfig {
            requests: #runtime_crate::core::security::RequestSecurity {
                json_max_bytes: #json_max_bytes,
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

    quote! {
        {
            let mut claims = ::std::collections::BTreeMap::new();
            #(#entries)*
            claims
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
                    api_key_env,
                    api_base_url,
                } => {
                    let api_key_env = Literal::string(api_key_env);
                    let api_base_url = option_string_tokens(api_base_url.as_deref());
                    quote!(
                        #runtime_crate::core::auth::AuthEmailProvider::Resend {
                            api_key_env: #api_key_env.to_owned(),
                            api_base_url: #api_base_url,
                        }
                    )
                }
                crate::auth::AuthEmailProvider::Smtp { connection_url_env } => {
                    let connection_url_env = Literal::string(connection_url_env);
                    quote!(
                        #runtime_crate::core::auth::AuthEmailProvider::Smtp {
                            connection_url_env: #connection_url_env.to_owned(),
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

fn resource_struct_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> TokenStream {
    let struct_ident = &resource.struct_ident;
    let create_ident = format_ident!("{struct_ident}Create");
    let update_ident = format_ident!("{struct_ident}Update");
    let list_query_tokens = list_query_tokens(resource, runtime_crate);
    let generated_from_row = generated_from_row_tokens(resource, runtime_crate);
    let fields = resource.fields.iter().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        quote! {
            pub #ident: #ty,
        }
    });

    let create_fields = create_payload_fields(resource).into_iter().map(|field| {
        let ident = &field.field.ident;
        let ty = create_payload_field_ty(&field);
        quote! {
            pub #ident: #ty,
        }
    });
    let update_fields = update_payload_fields(resource).into_iter().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        quote! {
            pub #ident: #ty,
        }
    });

    match resource.write_style {
        WriteModelStyle::ExistingStructWithDtos => quote! {
            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize
            )]
            pub struct #create_ident {
                #(#create_fields)*
            }

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize
            )]
            pub struct #update_ident {
                #(#update_fields)*
            }

            #list_query_tokens
        },
        WriteModelStyle::GeneratedStructWithDtos => quote! {
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
                #runtime_crate::serde::Deserialize
            )]
            pub struct #create_ident {
                #(#create_fields)*
            }

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize
            )]
            pub struct #update_ident {
                #(#update_fields)*
            }

            #list_query_tokens
        },
    }
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
    }
}

fn field_supports_sort(field: &super::model::FieldSpec) -> bool {
    super::model::supports_sort(&field.ty)
}

fn generated_from_row_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> TokenStream {
    let struct_ident = &resource.struct_ident;
    let field_extracts = resource.fields.iter().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        let field_name_lit = Literal::string(&field.name());

        if super::model::is_structured_scalar_type(&field.ty) {
            let base_ty = super::model::base_type(&field.ty);
            if super::model::is_optional_type(&field.ty) {
                quote! {
                    let #ident: #ty = match #runtime_crate::sqlx::Row::try_get::<Option<String>, _>(row, #field_name_lit)? {
                        Some(value) => Some(value.parse::<#base_ty>().map_err(|error| #runtime_crate::sqlx::Error::ColumnDecode {
                            index: #field_name_lit.to_owned(),
                            source: Box::new(error),
                        })?),
                        None => None,
                    };
                }
            } else {
                quote! {
                    let #ident: #ty = #runtime_crate::sqlx::Row::try_get::<String, _>(row, #field_name_lit)?
                        .parse::<#ty>()
                        .map_err(|error| #runtime_crate::sqlx::Error::ColumnDecode {
                            index: #field_name_lit.to_owned(),
                            source: Box::new(error),
                        })?;
                }
            }
        } else if field.sql_type == "BOOLEAN" {
            if super::model::is_optional_type(&field.ty) {
                quote! {
                    let #ident: #ty = match #runtime_crate::sqlx::Row::try_get::<Option<bool>, _>(row, #field_name_lit) {
                        Ok(value) => value,
                        Err(#runtime_crate::sqlx::Error::ColumnDecode { .. }) => {
                            #runtime_crate::sqlx::Row::try_get::<Option<i64>, _>(row, #field_name_lit)?
                                .map(|value| value != 0)
                        }
                        Err(error) => return Err(error),
                    };
                }
            } else {
                quote! {
                    let #ident: #ty = match #runtime_crate::sqlx::Row::try_get::<bool, _>(row, #field_name_lit) {
                        Ok(value) => value,
                        Err(#runtime_crate::sqlx::Error::ColumnDecode { .. }) => {
                            #runtime_crate::sqlx::Row::try_get::<i64, _>(row, #field_name_lit)? != 0
                        }
                        Err(error) => return Err(error),
                    };
                }
            }
        } else {
            quote! {
                let #ident: #ty = #runtime_crate::sqlx::Row::try_get(row, #field_name_lit)?;
            }
        }
    });
    let field_names = resource.fields.iter().map(|field| &field.ident);

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

fn list_query_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> TokenStream {
    let list_query_ident = list_query_ident(resource);
    let sort_field_ident = list_sort_field_ident(resource);
    let sort_order_ident = list_sort_order_ident(resource);
    let bind_ident = list_bind_ident(resource);
    let response_ident = list_response_ident(resource);
    let plan_ident = list_plan_ident(resource);
    let cursor_value_ident = list_cursor_value_ident(resource);
    let cursor_payload_ident = list_cursor_payload_ident(resource);
    let struct_ident = &resource.struct_ident;
    let sortable_fields = resource
        .fields
        .iter()
        .filter(|field| field_supports_sort(field))
        .collect::<Vec<_>>();
    let filter_fields = resource.fields.iter().flat_map(|field| {
        let filter_ident = format_ident!("filter_{}", field.ident);
        let base_ty = list_filter_field_ty(field, runtime_crate);
        let mut tokens = vec![quote! {
            pub #filter_ident: Option<#base_ty>,
        }];

        if super::model::supports_contains_filters(field) {
            let contains_ident = format_ident!("filter_{}_contains", field.ident);
            tokens.push(quote! {
                pub #contains_ident: Option<String>,
            });
        }

        if super::model::supports_range_filters(&field.ty) {
            for suffix in ["gt", "gte", "lt", "lte"] {
                let ident = format_ident!("filter_{}_{}", field.ident, suffix);
                let range_ty = base_ty.clone();
                tokens.push(quote! {
                    pub #ident: Option<#range_ty>,
                });
            }
        }

        tokens
    });
    let sort_variants = sortable_fields.iter().map(|field| {
        let variant_ident = super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name = Literal::string(&field.name());
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
        let field_name = Literal::string(&field.name());
        quote! {
            Self::#variant_ident => #field_name,
        }
    });
    let sort_variant_parse = sortable_fields.iter().map(|field| {
        let variant_ident = super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name = Literal::string(&field.name());
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
            Integer(i64),
            Real(f64),
            Boolean(bool),
            Text(String),
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
    runtime_crate: &Path,
) -> TokenStream {
    let struct_ident = &resource.struct_ident;
    let table_name = &resource.table_name;
    let id_field = &resource.id_field;
    let read_requires_auth = super::model::read_requires_auth(resource);
    let create_payload_ty = create_payload_type(resource);
    let update_payload_ty = update_payload_type(resource);
    let list_query_ty = list_query_type(resource);
    let list_bind_ty = list_bind_type(resource);
    let list_plan_ty = list_plan_type(resource);
    let list_response_ty = list_response_type(resource);
    let default_limit_tokens = option_u32_tokens(resource.list.default_limit);
    let max_limit_tokens = option_u32_tokens(resource.list.max_limit);
    let create_check = role_guard(runtime_crate, resource.roles.create.as_deref());
    let read_check = role_guard(runtime_crate, resource.roles.read.as_deref());
    let update_check = role_guard(runtime_crate, resource.roles.update.as_deref());
    let delete_check = role_guard(runtime_crate, resource.roles.delete.as_deref());
    let create_validation = create_validation_tokens(resource, runtime_crate);
    let update_validation = update_validation_tokens(resource, runtime_crate);
    let is_admin = quote! { user.roles.iter().any(|candidate| candidate == "admin") };
    let admin_bypass = resource.policies.admin_bypass;

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
            if let Some(source) = create_assignment_source(resource, &field_name) {
                let value = policy_source_value(source, field, runtime_crate);
                quote! {
                    q = q.bind(#value);
                }
            } else {
                quote! {
                    q = q.bind(&item.#ident);
                }
            }
        })
        .collect::<Vec<_>>();
    let bind_fields_insert_admin = insert_fields
        .iter()
        .map(|field| {
            let ident = &field.ident;
            let field_name = field.name();
            if let Some(source) = create_assignment_source(resource, &field_name) {
                match source {
                    PolicyValueSource::Claim(_) => {
                        let value = optional_policy_source_value(source, field);
                        let field_name_lit = Literal::string(&field_name);
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
                }
            } else {
                quote! {
                    q = q.bind(&item.#ident);
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
            quote! {
                q = q.bind(&item.#ident);
            }
        })
        .collect::<Vec<_>>();
    let list_placeholder_body = match resource.db {
        super::model::DbBackend::Postgres => quote!(format!("${index}")),
        super::model::DbBackend::Sqlite | super::model::DbBackend::Mysql => {
            quote!("?".to_owned())
        }
    };
    let query_filter_conditions = list_query_condition_tokens(resource, runtime_crate);
    let list_bind_matches = list_bind_match_tokens(resource, "q");
    let count_bind_matches = list_bind_match_tokens(resource, "count_query");
    let query_bind_matches = list_bind_match_tokens(resource, "q");
    let policy_plan_enum = policy_plan_enum_tokens(resource);
    let policy_plan_methods = policy_plan_method_tokens(resource, resources, runtime_crate);
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
    let create_admin_override =
        resource.policies.admin_bypass && resource.policies.create.iter().next().is_some();
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
        .fields
        .iter()
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
    let cursor_id_for_item_body = if super::model::is_optional_type(&id_field_spec.ty) {
        quote! {
            match item.#id_field_ident {
                Some(value) => Ok(value as i64),
                None => Err(#runtime_crate::core::errors::internal_error(
                    format!("Cannot build cursor for `{}` without a persisted id", #id_field_name_lit),
                )),
            }
        }
    } else {
        quote! {
            Ok(item.#id_field_ident as i64)
        }
    };
    let default_sort_variant =
        super::model::sanitize_struct_ident(&id_field_spec.name(), id_field_spec.ident.span());
    let sortable_fields = resource
        .fields
        .iter()
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
        let field_name_lit = Literal::string(&field.name());
        if field.name() == resource.id_field {
            if super::model::is_optional_type(&field.ty) {
                quote! {
                    #sort_field_ty::#variant_ident => match item.#ident {
                        Some(value) => Ok(#cursor_value_ty::Integer(value as i64)),
                        None => Err(#runtime_crate::core::errors::internal_error(
                            format!("Cannot build cursor for `{}` without a persisted id", #field_name_lit),
                        )),
                    },
                }
            } else {
                quote! {
                    #sort_field_ty::#variant_ident => Ok(#cursor_value_ty::Integer(item.#ident as i64)),
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
                match field.sql_type.as_str() {
                    "INTEGER" => quote! {
                        #sort_field_ty::#variant_ident => Ok(#cursor_value_ty::Integer(item.#ident as i64)),
                    },
                    "REAL" => quote! {
                        #sort_field_ty::#variant_ident => Ok(#cursor_value_ty::Real(item.#ident as f64)),
                    },
                    "BOOLEAN" => quote! {
                        #sort_field_ty::#variant_ident => Ok(#cursor_value_ty::Boolean(item.#ident)),
                    },
                    _ => quote! {
                        #sort_field_ty::#variant_ident => Ok(#cursor_value_ty::Text(item.#ident.clone())),
                    },
                }
            }
        }
    });
    let cursor_condition_arms = sortable_fields.iter().map(|field| {
        let variant_ident = super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name_lit = Literal::string(&field.name());
        if field.name() == resource.id_field {
            quote! {
                #sort_field_ty::#variant_ident => match &cursor_payload.value {
                    #cursor_value_ty::Integer(_) => {
                        let placeholder = Self::list_placeholder(
                            filter_binds.len() + select_only_binds.len() + 1
                        );
                        select_only_conditions.push(format!(
                            "{} {} {}",
                            #field_name_lit,
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
            let bind_push = match field.sql_type.as_str() {
                "INTEGER" => quote! {
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
                "BOOLEAN" => quote! {
                    #cursor_value_ty::Boolean(value) => {
                        select_only_binds.push(#list_bind_ty::Boolean(*value));
                        select_only_binds.push(#list_bind_ty::Boolean(*value));
                    }
                },
                _ => quote! {
                    #cursor_value_ty::Text(value) => {
                        select_only_binds.push(#list_bind_ty::Text(value.clone()));
                        select_only_binds.push(#list_bind_ty::Text(value.clone()));
                    }
                },
            };
            quote! {
                #sort_field_ty::#variant_ident => {
                    let first_index = filter_binds.len() + select_only_binds.len() + 1;
                    let first = Self::list_placeholder(first_index);
                    let second = Self::list_placeholder(first_index + 1);
                    let third = Self::list_placeholder(first_index + 2);
                    select_only_conditions.push(format!(
                        "(({} {} {}) OR ({} = {} AND {} {} {}))",
                        #field_name_lit,
                        comparator,
                        first,
                        #field_name_lit,
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
        Some(role) => quote! {
            user.roles
                .iter()
                .any(|candidate| candidate == "admin" || candidate == #role)
        },
        None => quote!(true),
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
        quote! {
            if !Self::can_read(user) {
                return Ok(None);
            }

            let sql = format!("SELECT * FROM {} WHERE {} = {}", #table_name, #id_field, #id_placeholder);

            if #admin_bypass && #is_admin {
                #runtime_crate::db::query_as::<#runtime_crate::sqlx::Any, Self>(&sql)
                    .bind(id)
                    .fetch_optional(db)
                    .await
            } else {
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
                    #plan_ident::Indeterminate => return Ok(None),
                }
            }
        }
    };

    let get_one_body = quote! {
        match Self::fetch_readable_by_id(path.into_inner(), &user, db.get_ref()).await {
            Ok(Some(item)) => HttpResponse::Ok().json(item),
            Ok(None) => #runtime_crate::core::errors::not_found("Not found"),
            Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
        }
    };

    let create_body = match (resource.db, insert_fields.is_empty()) {
        (super::model::DbBackend::Postgres | super::model::DbBackend::Sqlite, true) => {
            quote! {
                let sql = format!("INSERT INTO {} DEFAULT VALUES RETURNING {}", #table_name, #id_field);
                match #runtime_crate::db::query_scalar::<#runtime_crate::sqlx::Any, i64>(&sql)
                    .fetch_one(db.get_ref())
                    .await
                {
                    Ok(created_id) => Self::created_response(created_id, &req, &user, db.get_ref()).await,
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
                    Ok(created_id) => Self::created_response(created_id, &req, &user, db.get_ref()).await,
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
                            Self::created_response(created_id, &req, &user, db.get_ref()).await
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
                            Self::created_response(created_id, &req, &user, db.get_ref()).await
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

            quote! {
                if #admin_bypass && #is_admin {
                    let sql = #admin_sql;
                    let mut q = #runtime_crate::db::query(sql);
                    #(#bind_fields_update)*
                    q = q.bind(path.into_inner());
                    match q.execute(db.get_ref()).await {
                        Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                        Ok(_) => HttpResponse::Ok().finish(),
                        Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                    }
                } else {
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
                            q = q.bind(path.into_inner());
                            for bind in binds {
                                q = match bind {
                                    #(#query_bind_matches)*
                                };
                            }
                            match q.execute(db.get_ref()).await {
                                Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                                Ok(_) => HttpResponse::Ok().finish(),
                                Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                            }
                        }
                        #plan_ident::Indeterminate => #runtime_crate::core::errors::forbidden(
                            "missing_claim",
                            "Missing required principal values for row policy",
                        ),
                    }
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
        quote! {
            if #admin_bypass && #is_admin {
                let sql = #admin_sql;
                match #runtime_crate::db::query(sql)
                    .bind(path.into_inner())
                    .execute(db.get_ref())
                    .await
                {
                    Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                    Ok(_) => HttpResponse::Ok().finish(),
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            } else {
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
                        q = q.bind(path.into_inner());
                        for bind in binds {
                            q = match bind {
                                #(#query_bind_matches)*
                            };
                        }
                        match q.execute(db.get_ref()).await {
                            Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                            Ok(_) => HttpResponse::Ok().finish(),
                            Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                        }
                    }
                    #plan_ident::Indeterminate => #runtime_crate::core::errors::forbidden(
                        "missing_claim",
                        "Missing required principal values for row policy",
                    ),
                }
            }
        }
    };

    let relation_routes = resource.fields.iter().filter_map(|field| {
        field
            .relation
            .as_ref()
            .filter(|relation| relation.nested_route)
            .map(|relation| (field.ident.clone(), relation.references_table.clone()))
    });
    let nested_route_registrations = relation_routes.clone().map(|(field_ident, parent_table)| {
        let handler_ident = format_ident!("get_by_{}", field_ident);
        quote! {
            cfg.service(
                web::resource(format!("/{}/{{parent_id}}/{}", #parent_table, #table_name))
                    .route(web::get().to(Self::#handler_ident))
            );
        }
    });
    let nested_handlers = relation_routes.map(|(field_ident, _)| {
        let handler_ident = format_ident!("get_by_{}", field_ident);
        if read_requires_auth {
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
                            Ok(response) => HttpResponse::Ok().json(response),
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
                            Ok(response) => HttpResponse::Ok().json(response),
                            Err(response) => response,
                        },
                        Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                    }
                }
            }
        }
    });
    let get_all_handler = if read_requires_auth {
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
                        Ok(response) => HttpResponse::Ok().json(response),
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
                        Ok(response) => HttpResponse::Ok().json(response),
                        Err(response) => response,
                    },
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }
        }
    };
    let get_one_handler = if read_requires_auth {
        quote! {
            async fn get_one(
                path: web::Path<i64>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<DbPool>,
            ) -> impl Responder {
                #read_check
                #get_one_body
            }
        }
    } else {
        quote! {
            async fn get_one(
                path: web::Path<i64>,
                db: web::Data<DbPool>,
            ) -> impl Responder {
                let user = Self::anonymous_user_context();
                #get_one_body
            }
        }
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

                cfg.service(
                    web::resource(format!("/{}", #table_name))
                        .route(web::get().to(Self::get_all))
                        .route(web::post().to(Self::create))
                )
                .service(
                    web::resource(format!("/{}/{{id}}", #table_name))
                        .route(web::get().to(Self::get_one))
                        .route(web::put().to(Self::update))
                        .route(web::delete().to(Self::delete))
                );

                #(#nested_route_registrations)*
            }

            #anonymous_user_context_fn

            #contains_filter_helper

            fn can_read(user: &#runtime_crate::core::auth::UserContext) -> bool {
                #can_read_body
            }

            async fn fetch_readable_by_id(
                id: i64,
                user: &#runtime_crate::core::auth::UserContext,
                db: &DbPool,
            ) -> Result<Option<Self>, #runtime_crate::sqlx::Error> {
                #fetch_readable_by_id_body
            }

            fn created_location(req: &HttpRequest, id: i64) -> String {
                format!("{}/{}", req.uri().path().trim_end_matches('/'), id)
            }

            async fn created_response(
                id: i64,
                req: &HttpRequest,
                user: &#runtime_crate::core::auth::UserContext,
                db: &DbPool,
            ) -> HttpResponse {
                match Self::fetch_readable_by_id(id, user, db).await {
                    Ok(Some(item)) => HttpResponse::Created()
                        .append_header(("Location", Self::created_location(req, id)))
                        .json(item),
                    Ok(None) => HttpResponse::Created().finish(),
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }

            fn list_placeholder(index: usize) -> String {
                #list_placeholder_body
            }

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

            fn build_list_plan(
                query: &#list_query_ty,
                user: &#runtime_crate::core::auth::UserContext,
                parent_filter: Option<(&'static str, i64)>,
            ) -> Result<#list_plan_ty, HttpResponse> {
                let mut select_sql = format!("SELECT * FROM {}", #table_name);
                let mut count_sql = format!("SELECT COUNT(*) FROM {}", #table_name);
                let mut conditions: Vec<String> = Vec::new();
                let mut filter_binds: Vec<#list_bind_ty> = Vec::new();
                let mut select_only_conditions: Vec<String> = Vec::new();
                let mut select_only_binds: Vec<#list_bind_ty> = Vec::new();
                let is_admin = #is_admin;
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

                if !(#admin_bypass && is_admin) {
                    #read_policy_list_conditions
                }

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
                if sort.as_name() != #id_field_name_lit {
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

                if let Some(offset) = query.offset {
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

            fn finalize_list_response(
                plan: #list_plan_ty,
                total: i64,
                mut items: Vec<Self>,
            ) -> Result<#list_response_ty, HttpResponse> {
                let mut has_more = false;
                if plan.cursor_mode {
                    if let Some(limit) = plan.limit {
                        if items.len() > limit as usize {
                            has_more = true;
                            items.pop();
                        }
                    }
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

            async fn create(
                req: HttpRequest,
                item: web::Json<#create_payload_ty>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<DbPool>,
            ) -> impl Responder {
                #create_check
                #(#create_validation)*
                #create_body
            }

            async fn update(
                path: web::Path<i64>,
                item: web::Json<#update_payload_ty>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<DbPool>,
            ) -> impl Responder {
                #update_check
                #(#update_validation)*
                #update_body
            }

            async fn delete(
                path: web::Path<i64>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<DbPool>,
            ) -> impl Responder {
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

struct CreatePayloadField<'a> {
    field: &'a super::model::FieldSpec,
    allow_admin_override: bool,
}

fn create_payload_fields(resource: &ResourceSpec) -> Vec<CreatePayloadField<'_>> {
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
            if controlled && !allow_admin_override {
                return None;
            }

            Some(CreatePayloadField {
                field,
                allow_admin_override,
            })
        })
        .collect()
}

fn create_payload_field_ty(field: &CreatePayloadField<'_>) -> syn::Type {
    if field.allow_admin_override && !super::model::is_optional_type(&field.field.ty) {
        let ty = &field.field.ty;
        syn::parse_quote!(Option<#ty>)
    } else {
        field.field.ty.clone()
    }
}

fn create_payload_field_is_optional(field: &CreatePayloadField<'_>) -> bool {
    field.allow_admin_override || super::model::is_optional_type(&field.field.ty)
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

    match field.sql_type.as_str() {
        "INTEGER" => quote!(i64),
        "REAL" => quote!(f64),
        "BOOLEAN" => quote!(bool),
        _ => quote!(String),
    }
}

fn list_query_condition_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    let bind_ident = list_bind_ident(resource);
    resource
        .fields
        .iter()
        .map(|field| {
            let field_name = Literal::string(&field.name());
            let filter_ident = format_ident!("filter_{}", field.ident);
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
            } else {
                match field.sql_type.as_str() {
                    "INTEGER" => quote! {
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
                    "BOOLEAN" => quote! {
                        if let Some(value) = query.#filter_ident {
                            conditions.push(format!(
                                "{} = {}",
                                #field_name,
                                Self::list_placeholder(filter_binds.len() + 1)
                            ));
                            filter_binds.push(#bind_ident::Boolean(value));
                        }
                    },
                    _ => quote! {
                        if let Some(value) = &query.#filter_ident {
                            conditions.push(format!(
                                "{} = {}",
                                #field_name,
                                Self::list_placeholder(filter_binds.len() + 1)
                            ));
                            filter_binds.push(#bind_ident::Text(value.clone()));
                        }
                        #contains_filter_tokens
                    },
                }
            }
        })
        .collect()
}

fn list_bind_match_tokens(resource: &ResourceSpec, query_ident: &str) -> Vec<TokenStream> {
    let bind_ident = list_bind_ident(resource);
    let query_ident = syn::Ident::new(query_ident, proc_macro2::Span::call_site());
    vec![
        quote! {
            #bind_ident::Integer(value) => #query_ident.bind(value),
        },
        quote! {
            #bind_ident::Real(value) => #query_ident.bind(value),
        },
        quote! {
            #bind_ident::Boolean(value) => #query_ident.bind(value),
        },
        quote! {
            #bind_ident::Text(value) => #query_ident.bind(value),
        },
    ]
}

fn create_validation_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    create_payload_fields(resource)
        .into_iter()
        .filter_map(|field| {
            validation_tokens(
                field.field,
                &field.field.ident,
                create_payload_field_is_optional(&field),
                runtime_crate,
            )
        })
        .collect()
}

fn update_validation_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    update_payload_fields(resource)
        .into_iter()
        .filter_map(|field| {
            validation_tokens(
                field,
                &field.ident,
                super::model::is_optional_type(&field.ty),
                runtime_crate,
            )
        })
        .collect()
}

fn validation_tokens(
    field: &super::model::FieldSpec,
    ident: &syn::Ident,
    optional: bool,
    runtime_crate: &Path,
) -> Option<TokenStream> {
    if field.validation.is_empty() {
        return None;
    }

    let field_name = Literal::string(&field.name());
    let checks = validation_checks(field, &field_name, runtime_crate);
    if checks.is_empty() {
        return None;
    }

    Some(if optional {
        quote! {
            if let Some(value) = &item.#ident {
                #(#checks)*
            }
        }
    } else {
        quote! {
            let value = &item.#ident;
            #(#checks)*
        }
    })
}

fn validation_checks(
    field: &super::model::FieldSpec,
    field_name: &Literal,
    runtime_crate: &Path,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();

    if let Some(min_length) = field.validation.min_length {
        checks.push(quote! {
            if value.chars().count() < #min_length {
                return #runtime_crate::core::errors::validation_error(
                    #field_name,
                    format!("Field `{}` must have at least {} characters", #field_name, #min_length),
                );
            }
        });
    }

    if let Some(max_length) = field.validation.max_length {
        checks.push(quote! {
            if value.chars().count() > #max_length {
                return #runtime_crate::core::errors::validation_error(
                    #field_name,
                    format!("Field `{}` must have at most {} characters", #field_name, #max_length),
                );
            }
        });
    }

    match field.sql_type.as_str() {
        "INTEGER" => {
            if let Some(super::model::NumericBound::Integer(minimum)) = &field.validation.minimum {
                let minimum = Literal::i64_unsuffixed(*minimum);
                checks.push(quote! {
                    if *value < #minimum {
                        return #runtime_crate::core::errors::validation_error(
                            #field_name,
                            format!("Field `{}` must be at least {}", #field_name, #minimum),
                        );
                    }
                });
            }
            if let Some(super::model::NumericBound::Integer(maximum)) = &field.validation.maximum {
                let maximum = Literal::i64_unsuffixed(*maximum);
                checks.push(quote! {
                    if *value > #maximum {
                        return #runtime_crate::core::errors::validation_error(
                            #field_name,
                            format!("Field `{}` must be at most {}", #field_name, #maximum),
                        );
                    }
                });
            }
        }
        "REAL" => {
            if let Some(minimum) = &field.validation.minimum {
                let minimum = Literal::f64_unsuffixed(minimum.as_f64());
                checks.push(quote! {
                    if (*value as f64) < #minimum {
                        return #runtime_crate::core::errors::validation_error(
                            #field_name,
                            format!("Field `{}` must be at least {}", #field_name, #minimum),
                        );
                    }
                });
            }
            if let Some(maximum) = &field.validation.maximum {
                let maximum = Literal::f64_unsuffixed(maximum.as_f64());
                checks.push(quote! {
                    if (*value as f64) > #maximum {
                        return #runtime_crate::core::errors::validation_error(
                            #field_name,
                            format!("Field `{}` must be at most {}", #field_name, #maximum),
                        );
                    }
                });
            }
        }
        _ => {}
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

fn maybe_policy_source_value(
    source: &PolicyValueSource,
    field: &super::model::FieldSpec,
) -> TokenStream {
    match source {
        PolicyValueSource::UserId => quote!(Some(user.id)),
        PolicyValueSource::Claim(name) => {
            let claim_name = Literal::string(name);
            claim_access_value_tokens(&claim_name, field)
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

        fn negate_policy_plan(plan: #plan_ident) -> #plan_ident {
            match plan {
                #plan_ident::Resolved { condition, binds } => #plan_ident::Resolved {
                    condition: format!("NOT ({condition})"),
                    binds,
                },
                #plan_ident::Indeterminate => #plan_ident::Indeterminate,
            }
        }

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
            let value = maybe_policy_source_value(&filter.source, field);
            let bind_value = list_bind_value_tokens(bind_ident, field, quote!(value));
            quote! {
                {
                    match #value {
                        Some(value) => {
                            let placeholder = Self::list_placeholder(#next_index_ident);
                            #next_index_ident += 1;
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
                    candidate.struct_ident.to_string() == filter.resource
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
                    match #exists_condition {
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
            let value = maybe_policy_source_value(&filter.source, field);
            let bind_value = list_bind_value_tokens(bind_ident, field, quote!(value));
            quote! {
                match #value {
                    Some(value) => {
                        let placeholder = Self::list_placeholder(#next_index_ident);
                        #next_index_ident += 1;
                        #plan_ident::Resolved {
                            condition: format!("{}.{} = {}", #alias, #field_name, placeholder),
                            binds: vec![#bind_value],
                        }
                    }
                    None => #plan_ident::Indeterminate,
                }
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
                        .generated_temporal_expression(super::model::temporal_scalar_kind(
                            &field.ty
                        ))
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
