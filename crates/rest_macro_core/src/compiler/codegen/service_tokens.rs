//! Service-level configuration token generators.
//!
//! This module contains functions that emit `proc_macro2::TokenStream` for
//! service-level setup: database, auth, logging, TLS, runtime, storage,
//! security, and authorization configuration. All functions are called from
//! [`super::expand_service_module`].

use proc_macro2::{Literal, TokenStream};
use quote::quote;
use syn::Path;

use super::super::model::ServiceSpec;
use crate::{
    authorization::{
        ActionAuthorization, AuthorizationAssignment, AuthorizationCondition,
        AuthorizationExistsCondition, AuthorizationLiteralValue, AuthorizationMatch,
        AuthorizationModel, AuthorizationOperator, AuthorizationValueSource,
        ResourceAuthorization,
    },
    database::{
        DatabaseBackupMode, DatabaseBackupTarget, DatabaseEngine, DatabaseReadRoutingMode,
        DatabaseReplicationMode, DatabaseResilienceProfile,
    },
    logging::LogTimestampPrecision,
    security::{DefaultReadAccess, FrameOptions, ReferrerPolicy},
};
pub(super) fn authorization_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
    let model = super::super::authorization::compile_service_authorization(service);
    authorization_model_tokens(&model, runtime_crate)
}

pub(super) fn authorization_management_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
    let enabled = service.authorization.management_api.enabled;
    let mount = Literal::string(&service.authorization.management_api.mount);
    quote!(#runtime_crate::core::authorization::AuthorizationManagementApiConfig {
        enabled: #enabled,
        mount: #mount.to_owned(),
    })
}

pub(super) fn authorization_model_tokens(model: &AuthorizationModel, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn resource_authorization_tokens(
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

pub(super) fn action_authorization_tokens(action: &ActionAuthorization, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn option_condition_tokens(
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

pub(super) fn condition_tokens(condition: &AuthorizationCondition, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn exists_condition_tokens(
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

pub(super) fn match_tokens(rule: &AuthorizationMatch, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn assignment_tokens(assignment: &AuthorizationAssignment, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn authorization_action_tokens(
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

pub(super) fn authorization_operator_tokens(
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

pub(super) fn value_source_tokens(source: &AuthorizationValueSource, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn authorization_literal_value_tokens(
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

pub(super) fn optional_value_source_tokens(
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

pub(super) fn auth_claim_type_tokens(ty: crate::auth::AuthClaimType, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn database_resilience_profile_tokens(
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

pub(super) fn database_backup_mode_tokens(mode: DatabaseBackupMode, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn database_backup_target_tokens(
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

pub(super) fn database_replication_mode_tokens(
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

pub(super) fn database_read_routing_mode_tokens(
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

pub(super) fn database_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn logging_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn tls_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn runtime_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn storage_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn security_tokens(service: &ServiceSpec, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn option_string_tokens(value: Option<&str>) -> TokenStream {
    match value {
        Some(value) => {
            let value = Literal::string(value);
            quote!(Some(#value.to_owned()))
        }
        None => quote!(None),
    }
}

pub(super) fn option_usize_tokens(value: Option<usize>) -> TokenStream {
    match value {
        Some(value) => {
            let value = Literal::usize_unsuffixed(value);
            quote!(Some(#value))
        }
        None => quote!(None),
    }
}

pub(super) fn option_secret_ref_tokens(
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

pub(super) fn secret_ref_tokens(value: &crate::secret::SecretRef, runtime_crate: &Path) -> TokenStream {
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

pub(super) fn option_auth_jwt_tokens(
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

pub(super) fn auth_claim_mappings_tokens(
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

pub(super) fn vec_string_tokens(values: &[String]) -> TokenStream {
    let values = values.iter().map(|value| {
        let value = Literal::string(value);
        quote!(#value.to_owned())
    });
    quote!(vec![#(#values),*])
}

pub(super) fn option_rate_limit_tokens(
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

pub(super) fn option_session_cookie_tokens(
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

pub(super) fn option_auth_email_tokens(
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

pub(super) fn option_auth_ui_page_tokens(
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