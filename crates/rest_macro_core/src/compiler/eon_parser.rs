use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, NaiveDate, NaiveTime, SecondsFormat, Utc};
use heck::ToSnakeCase;
use proc_macro2::Span;
use quote::ToTokens;
use rust_decimal::Decimal;
use serde_json::Value as JsonValue;
use syn::LitStr;
use uuid::Uuid;

use super::model::{
    BuildCacheCleanupStrategy, BuildConfig, BuildLtoMode, ClientsConfig,
    DbBackend, EnumSpec, FieldSpec, FieldTransform, GeneratedValue, IndexSpec, LengthMode,
    NumericBound, PolicyFilterExpression, PolicyValueSource,
    ResourceActionAssignmentSpec, ResourceActionBehaviorSpec,
    ResourceActionInputFieldSpec, ResourceActionMethod, ResourceActionSpec, ResourceActionTarget,
    ResourceActionValueSpec, ResourceReadAccess, ResourceSpec, ResponseContextSpec,
    RoleRequirements, RowPolicies, ServiceSpec, StaticCacheProfile, StaticMode,
    WriteModelStyle,
    apply_service_read_access_defaults, default_resource_module_ident, infer_generated_value,
    infer_sql_type, is_json_array_type, is_json_object_type, is_json_type, is_list_field,
    is_optional_type, is_typed_object_field, sanitize_module_ident, sanitize_struct_ident,
    structured_scalar_kind, supports_declared_index, validate_authorization_contract,
    validate_build_config, validate_clients_config, validate_field_transforms,
    validate_field_validations, validate_list_config, validate_logging_config,
    validate_policy_claim_sources, validate_relations, validate_resource_access,
    validate_row_policies, validate_runtime_config, validate_security_config,
    validate_sql_identifier, validate_tls_config,
};
use crate::{
    auth::{
        AuthClaimMapping, AuthClaimType, AuthEmailProvider, AuthJwtAlgorithm,
        AuthJwtSettings, AuthJwtVerificationKey, SessionCookieSameSite,
    },
    authorization::{
        AuthorizationAction, AuthorizationContract, DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT,
    },
    database::{
        DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV, DatabaseBackupMode,
        DatabaseBackupTarget, DatabaseEngine, DatabaseReadRoutingMode,
        DatabaseReplicationMode, DatabaseResilienceProfile, TursoLocalConfig,
    },
    logging::{LogTimestampPrecision, LoggingConfig},
    runtime::RuntimeConfig,
    secret::SecretRef,
    security::{FrameOptions, Hsts, RateLimitRule, ReferrerPolicy, SecurityConfig},
    storage::{StorageBackendKind, StorageConfig},
    tls::{
        DEFAULT_TLS_CERT_PATH, DEFAULT_TLS_CERT_PATH_ENV, DEFAULT_TLS_KEY_PATH,
        DEFAULT_TLS_KEY_PATH_ENV, TlsConfig,
    },
};


/// The result of loading and parsing a `.eon` service file.
///
/// Returned by [`load_service_from_file`] and [`load_service_from_path`].
pub(super) struct LoadedService {
    /// The parsed service specification.
    pub(super) service: ServiceSpec,
    /// Absolute path to the directory containing the `.eon` file, used to
    /// resolve relative include paths during code generation.
    pub(super) include_path: String,
}

mod documents;
use self::documents::*;

pub fn load_service_from_file(path: LitStr) -> syn::Result<LoadedService> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| syn::Error::new(path.span(), "CARGO_MANIFEST_DIR is not available"))?;
    let manifest_dir = PathBuf::from(manifest_dir);
    let absolute_path = manifest_dir.join(path.value());
    load_service_document(&absolute_path, path.span())
}

pub fn load_service_from_path(path: &Path) -> syn::Result<LoadedService> {
    load_service_document(path, Span::call_site())
}

fn load_service_document(path: &Path, span: Span) -> syn::Result<LoadedService> {
    let absolute_path = path.to_path_buf();
    let include_path = absolute_path
        .canonicalize()
        .unwrap_or_else(|_| absolute_path.clone())
        .display()
        .to_string();

    let source = fs::read_to_string(&absolute_path).map_err(|error| {
        syn::Error::new(
            span,
            format!("failed to read `{}`: {error}", absolute_path.display()),
        )
    })?;
    let document = eon::from_str::<ServiceDocument>(&source).map_err(|error| {
        syn::Error::new(
            span,
            format!(
                "failed to parse `{}` as EON: {error}",
                absolute_path.display()
            ),
        )
    })?;

    let file_stem = absolute_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("generated_api");
    let module_ident = sanitize_module_ident(document.module.as_deref().unwrap_or(file_stem), span);
    let service_root = absolute_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let static_mounts = build_static_mounts(&service_root, document.static_config)?;
    let storage = parse_storage_document(&service_root, document.storage)?;
    validate_distinct_public_mounts(static_mounts.as_slice(), &storage)?;
    let database = parse_database_document(
        document.db,
        document.database,
        &module_ident.to_string(),
        span,
    )?;
    let build = parse_build_document(document.build)?;
    let clients = parse_clients_document(document.clients);
    let logging = parse_logging_document(document.logging)?;
    let runtime = parse_runtime_document(document.runtime);
    let authorization = parse_authorization_document(document.authorization)?;
    let tls = parse_tls_document(document.tls)?;
    let security = parse_security_document(document.security, span)?;
    validate_build_config(&build, span)?;
    validate_clients_config(&clients, span)?;
    validate_logging_config(&logging, span)?;
    validate_runtime_config(&runtime, span)?;
    validate_tls_config(&tls, span)?;
    validate_security_config(&security, span)?;
    let enums = build_enums(document.enums)?;
    let mixins = build_mixins(document.mixins)?;
    let resources = expand_resource_mixins(document.resources, &mixins)?;
    let mut resources = build_resources_with_enums(document.db, resources, enums.as_slice())?;
    if resources.is_empty() {
        return Err(syn::Error::new(
            span,
            "service config must contain at least one resource",
        ));
    }
    apply_service_read_access_defaults(&mut resources, &security);
    validate_storage_upload_routes(&storage, &resources)?;
    validate_policy_claim_sources(&resources, &security, span)?;
    validate_authorization_contract(&authorization, &resources, span)?;

    Ok(LoadedService {
        service: ServiceSpec {
            module_ident,
            enums,
            resources,
            authorization,
            static_mounts,
            storage,
            database,
            build,
            clients,
            logging,
            runtime,
            security,
            tls,
        },
        include_path,
    })
}

#[cfg(test)]
fn build_resources(
    db: DbBackend,
    resources: Vec<ResourceDocument>,
) -> syn::Result<Vec<ResourceSpec>> {
    build_resources_with_enums(db, resources, &[])
}

fn build_enums(documents: Vec<EnumDocument>) -> syn::Result<Vec<EnumSpec>> {
    let mut seen_names = HashSet::new();
    let mut enums = Vec::with_capacity(documents.len());

    for document in documents {
        if !seen_names.insert(document.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate enum `{}`", document.name),
            ));
        }
        syn::parse_str::<syn::Ident>(&document.name).map_err(|_| {
            syn::Error::new(
                Span::call_site(),
                format!(
                    "enum name `{}` is not a valid Rust identifier",
                    document.name
                ),
            )
        })?;
        if document.values.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("enum `{}` must declare at least one value", document.name),
            ));
        }
        let mut seen_values = HashSet::new();
        for value in &document.values {
            if !seen_values.insert(value.clone()) {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "enum `{}` contains duplicate value `{value}`",
                        document.name
                    ),
                ));
            }
        }
        enums.push(EnumSpec {
            name: document.name,
            values: document.values,
        });
    }

    Ok(enums)
}

fn build_mixins(documents: Vec<MixinDocument>) -> syn::Result<HashMap<String, MixinDocument>> {
    let mut seen_names = HashSet::new();
    let mut mixins = HashMap::with_capacity(documents.len());

    for document in documents {
        if !seen_names.insert(document.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate mixin `{}`", document.name),
            ));
        }
        syn::parse_str::<syn::Ident>(document.name.as_str()).map_err(|_| {
            syn::Error::new(
                Span::call_site(),
                format!(
                    "mixin name `{}` is not a valid Rust identifier",
                    document.name
                ),
            )
        })?;
        validate_mixin_document(&document)?;
        mixins.insert(document.name.clone(), document);
    }

    Ok(mixins)
}

fn validate_mixin_document(mixin: &MixinDocument) -> syn::Result<()> {
    let mut seen_fields = HashSet::new();
    let mut seen_api_names = HashSet::new();

    for field in &mixin.fields {
        if !seen_fields.insert(field.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate field `{}` in mixin `{}`", field.name, mixin.name),
            ));
        }

        let field_api_name = field.api_name.as_deref().unwrap_or(field.name.as_str());
        if !seen_api_names.insert(field_api_name.to_owned()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate field api_name `{field_api_name}` in mixin `{}`",
                    mixin.name
                ),
            ));
        }

        if field.id {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "mixin `{}` cannot declare id field `{}`",
                    mixin.name, field.name
                ),
            ));
        }
    }

    let field_names = mixin
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<HashSet<_>>();
    for index in &mixin.indexes {
        if index.fields.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "mixin `{}` index definitions must declare at least one field",
                    mixin.name
                ),
            ));
        }
        for field_name in &index.fields {
            if !field_names.contains(field_name.as_str()) {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "mixin `{}` index references unknown mixin field `{field_name}`",
                        mixin.name
                    ),
                ));
            }
        }
    }

    Ok(())
}

fn expand_resource_mixins(
    resources: Vec<ResourceDocument>,
    mixins: &HashMap<String, MixinDocument>,
) -> syn::Result<Vec<ResourceDocument>> {
    let mut expanded = Vec::with_capacity(resources.len());

    for mut resource in resources {
        let mut seen_mixins = HashSet::new();
        let mut mixin_fields = Vec::new();
        let mut mixin_indexes = Vec::new();

        for mixin_name in &resource.use_mixins {
            if !seen_mixins.insert(mixin_name.clone()) {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "resource `{}` uses mixin `{mixin_name}` more than once",
                        resource.name
                    ),
                ));
            }
            let mixin = mixins.get(mixin_name).ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        "resource `{}` references unknown mixin `{mixin_name}`",
                        resource.name
                    ),
                )
            })?;
            mixin_fields.extend(mixin.fields.clone());
            mixin_indexes.extend(mixin.indexes.clone());
        }

        mixin_fields.extend(resource.fields);
        mixin_indexes.extend(resource.indexes);
        resource.fields = mixin_fields;
        resource.indexes = mixin_indexes;
        expanded.push(resource);
    }

    Ok(expanded)
}

fn build_resources_with_enums(
    db: DbBackend,
    resources: Vec<ResourceDocument>,
    enums: &[EnumSpec],
) -> syn::Result<Vec<ResourceSpec>> {
    let mut seen_names = HashSet::new();
    let mut seen_api_names = HashSet::new();
    let mut pending_many_to_many = Vec::with_capacity(resources.len());
    let mut result = Vec::with_capacity(resources.len());

    for resource in resources {
        let struct_ident = sanitize_struct_ident(&resource.name, Span::call_site());
        let struct_name = struct_ident.to_string();
        if !seen_names.insert(struct_name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate resource `{struct_name}`"),
            ));
        }

        let table_name = resource
            .table
            .unwrap_or_else(|| struct_name.to_snake_case());
        validate_sql_identifier(&table_name, Span::call_site(), "table name")?;
        let api_name = resource.api_name.unwrap_or_else(|| table_name.clone());
        validate_api_name(
            api_name.as_str(),
            format!("resource `{struct_name}` api_name").as_str(),
        )?;
        if !seen_api_names.insert(api_name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate resource api_name `{api_name}`"),
            ));
        }
        let configured_id = resource.id_field.unwrap_or_else(|| "id".to_owned());
        let resource_api = resource.api.unwrap_or_default();
        let resource_many_to_many = resource.many_to_many;
        let resource_actions = resource.actions;
        let has_api_projection_block = !resource_api.fields.is_empty();
        if has_api_projection_block && resource.fields.iter().any(|field| field.api_name.is_some())
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{struct_name}` cannot combine resource `api.fields` with per-field `api_name`"
                ),
            ));
        }

        let mut seen_fields = HashSet::new();
        let mut seen_field_api_names = HashSet::new();
        let mut fields = Vec::with_capacity(resource.fields.len());

        for field in resource.fields {
            if !seen_fields.insert(field.name.clone()) {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "duplicate field `{}` on resource `{struct_name}`",
                        field.name
                    ),
                ));
            }
            let (field_api_name, expose_in_api) = if has_api_projection_block {
                (field.name.clone(), false)
            } else {
                let field_api_name = field.api_name.unwrap_or_else(|| field.name.clone());
                validate_api_name(
                    field_api_name.as_str(),
                    format!(
                        "field `{}` on resource `{struct_name}` api_name",
                        field.name
                    )
                    .as_str(),
                )?;
                if !seen_field_api_names.insert(field_api_name.clone()) {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!(
                            "duplicate field api_name `{}` on resource `{struct_name}`",
                            field_api_name
                        ),
                    ));
                }
                (field_api_name, true)
            };
            reject_legacy_field_validation(
                field.legacy_validate.as_ref(),
                format!("field `{}` on resource `{struct_name}`", field.name).as_str(),
            )?;

            let is_id = field.id || field.name == configured_id;
            let generated = match field.generated {
                GeneratedValue::None => infer_generated_value(&field.name, is_id),
                other => other,
            };

            let parsed_ty = parse_field_type(
                &field.ty,
                field.items.as_ref(),
                field.nullable || generated != GeneratedValue::None,
                enums,
            )?;
            let sql_type = infer_sql_type(&parsed_ty.ty, db);
            let object_fields = match &field.ty {
                FieldTypeDocument::Scalar(ScalarType::Object) => {
                    if field.fields.is_empty() {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "field `{}` on resource `{struct_name}` must set nested `fields` when `type = Object`",
                                field.name
                            ),
                        ));
                    }
                    if is_id {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "field `{}` on resource `{struct_name}` cannot be an object ID field",
                                field.name
                            ),
                        ));
                    }
                    if field.relation.is_some() {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "field `{}` on resource `{struct_name}` cannot combine `type = Object` with `relation`",
                                field.name
                            ),
                        ));
                    }
                    if field.validate.is_some() {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "field `{}` on resource `{struct_name}` only supports nested garde validation through child fields and `dive`/`required`",
                                field.name
                            ),
                        ));
                    }
                    Some(build_object_fields(
                        db,
                        field.fields,
                        format!("resource `{struct_name}` field `{}`", field.name).as_str(),
                        enums,
                    )?)
                }
                _ => {
                    if !field.fields.is_empty() {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "field `{}` on resource `{struct_name}` can only set nested `fields` when `type = Object`",
                                field.name
                            ),
                        ));
                    }
                    None
                }
            };

            if parsed_ty.list_item_ty.is_some() {
                if is_id {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!(
                            "field `{}` on resource `{struct_name}` cannot be a list ID field",
                            field.name
                        ),
                    ));
                }
                if field.relation.is_some() {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!(
                            "field `{}` on resource `{struct_name}` cannot combine `type = List` with `relation`",
                            field.name
                        ),
                    ));
                }
            }

            let relation = match field.relation {
                Some(relation) => Some(parse_relation_document(relation)?),
                None => None,
            };
            let validation = parse_field_validation_document(field.validate)?;
            let transforms = parse_field_transforms_document(field.transforms)?;

            fields.push(FieldSpec {
                ident: syn::parse_str(&field.name).map_err(|_| {
                    syn::Error::new(
                        Span::call_site(),
                        format!("field name `{}` is not a valid Rust identifier", field.name),
                    )
                })?,
                api_name: field_api_name,
                expose_in_api,
                unique: field.unique,
                enum_name: parsed_ty.enum_name,
                enum_values: parsed_ty.enum_values,
                transforms,
                ty: parsed_ty.ty,
                list_item_ty: parsed_ty.list_item_ty,
                object_fields,
                sql_type,
                is_id,
                generated,
                validation,
                relation,
            });
        }

        if !fields.iter().any(|field| field.name() == configured_id) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("configured id field `{configured_id}` does not exist on `{struct_name}`"),
            ));
        }

        let computed_fields = if has_api_projection_block {
            apply_resource_api_projections(
                &mut fields,
                resource_api.fields.clone(),
                struct_name.as_str(),
                configured_id.as_str(),
            )?
        } else {
            Vec::new()
        };

        let policies = parse_row_policies(resource.policies).map_err(|error| {
            syn::Error::new(
                error.span(),
                format!("failed to parse row policies for `{struct_name}`: {error}"),
            )
        })?;
        let access = parse_resource_access_document(resource.access)?;
        let (default_response_context, response_contexts) = build_response_contexts(
            fields.as_slice(),
            computed_fields.as_slice(),
            resource_api.default_context,
            resource_api.contexts,
            struct_name.as_str(),
        )?;
        let indexes = build_index_specs(resource.indexes);
        let actions = build_resource_action_specs(
            struct_name.as_str(),
            fields.as_slice(),
            &policies,
            resource_actions,
        )?;
        pending_many_to_many.push((struct_name.clone(), resource_many_to_many));

        result.push(ResourceSpec {
            struct_ident: struct_ident.clone(),
            impl_module_ident: default_resource_module_ident(&struct_ident),
            table_name,
            api_name,
            default_response_context,
            response_contexts,
            id_field: configured_id,
            db,
            access,
            roles: resource.roles.with_legacy_defaults(),
            policies,
            list: parse_list_config(resource.list),
            indexes,
            many_to_many: Vec::new(),
            actions,
            computed_fields,
            fields,
            write_style: WriteModelStyle::GeneratedStructWithDtos,
        });
    }

    let resolved_many_to_many = result
        .iter()
        .zip(pending_many_to_many.iter())
        .map(|(resource, (resource_name, documents))| {
            resolve_many_to_many_specs(resource, resource_name.as_str(), documents, &result)
        })
        .collect::<syn::Result<Vec<_>>>()?;

    for (resource, many_to_many) in result.iter_mut().zip(resolved_many_to_many) {
        resource.many_to_many = many_to_many;
    }

    for resource in &result {
        validate_resource_access(resource, Span::call_site())?;
        validate_row_policies(resource, &result, &resource.policies, Span::call_site())?;
        validate_relations(&resource.fields, Span::call_site())?;
        validate_field_validations(&resource.fields, Span::call_site())?;
        validate_field_transforms(&resource.fields, Span::call_site())?;
        validate_list_config(&resource.list, Span::call_site())?;
        validate_resource_indexes(resource, Span::call_site())?;
    }

    Ok(result)
}

fn resolve_many_to_many_specs(
    source_resource: &ResourceSpec,
    source_resource_name: &str,
    documents: &[ManyToManyDocument],
    resources: &[ResourceSpec],
) -> syn::Result<Vec<super::model::ManyToManySpec>> {
    let mut seen_names = HashSet::new();
    let mut relations = Vec::with_capacity(documents.len());

    for document in documents {
        validate_api_name(
            document.name.as_str(),
            format!(
                "many_to_many `{}` on resource `{source_resource_name}`",
                document.name
            )
            .as_str(),
        )?;
        if !seen_names.insert(document.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate many_to_many `{}` on resource `{source_resource_name}`",
                    document.name
                ),
            ));
        }
        validate_sql_identifier(
            document.source_field.as_str(),
            Span::call_site(),
            "many_to_many source_field",
        )?;
        validate_sql_identifier(
            document.target_field.as_str(),
            Span::call_site(),
            "many_to_many target_field",
        )?;

        let target_resource = resolve_resource_selector(
            resources,
            document.target.as_str(),
            format!(
                "many_to_many `{}` on resource `{source_resource_name}` target",
                document.name
            )
            .as_str(),
        )?;
        let through_resource = resolve_resource_selector(
            resources,
            document.through.as_str(),
            format!(
                "many_to_many `{}` on resource `{source_resource_name}` through",
                document.name
            )
            .as_str(),
        )?;

        let source_field = through_resource
            .find_field(document.source_field.as_str())
            .ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        "many_to_many `{}` on resource `{source_resource_name}` references unknown through field `{}` on `{}`",
                        document.name, document.source_field, through_resource.table_name
                    ),
                )
            })?;
        let source_relation = source_field.relation.as_ref().ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!(
                    "many_to_many `{}` on resource `{source_resource_name}` requires through field `{}` on `{}` to declare a relation",
                    document.name, document.source_field, through_resource.table_name
                ),
            )
        })?;
        if source_relation.references_table != source_resource.table_name
            || source_relation.references_field != source_resource.id_field
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "many_to_many `{}` on resource `{source_resource_name}` requires through field `{}` on `{}` to reference `{}.{}`",
                    document.name,
                    document.source_field,
                    through_resource.table_name,
                    source_resource.table_name,
                    source_resource.id_field
                ),
            ));
        }

        let target_field = through_resource
            .find_field(document.target_field.as_str())
            .ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        "many_to_many `{}` on resource `{source_resource_name}` references unknown through field `{}` on `{}`",
                        document.name, document.target_field, through_resource.table_name
                    ),
                )
            })?;
        let target_relation = target_field.relation.as_ref().ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!(
                    "many_to_many `{}` on resource `{source_resource_name}` requires through field `{}` on `{}` to declare a relation",
                    document.name, document.target_field, through_resource.table_name
                ),
            )
        })?;
        if target_relation.references_table != target_resource.table_name
            || target_relation.references_field != target_resource.id_field
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "many_to_many `{}` on resource `{source_resource_name}` requires through field `{}` on `{}` to reference `{}.{}`",
                    document.name,
                    document.target_field,
                    through_resource.table_name,
                    target_resource.table_name,
                    target_resource.id_field
                ),
            ));
        }

        relations.push(super::model::ManyToManySpec {
            name: document.name.clone(),
            target_table: target_resource.table_name.clone(),
            through_table: through_resource.table_name.clone(),
            source_field: document.source_field.clone(),
            target_field: document.target_field.clone(),
        });
    }

    Ok(relations)
}

fn resolve_resource_selector<'a>(
    resources: &'a [ResourceSpec],
    selector: &str,
    context: &str,
) -> syn::Result<&'a ResourceSpec> {
    resources
        .iter()
        .find(|resource| {
            resource.struct_ident == sanitize_struct_ident(selector, Span::call_site())
                || resource.table_name == selector
        })
        .ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!("{context} references unknown resource `{selector}`"),
            )
        })
}

fn build_resource_action_specs(
    resource_name: &str,
    fields: &[FieldSpec],
    policies: &RowPolicies,
    documents: Vec<ResourceActionDocument>,
) -> syn::Result<Vec<ResourceActionSpec>> {
    let controlled_fields = policies
        .controlled_filter_fields()
        .into_iter()
        .chain(
            policies
                .iter_assignments()
                .map(|(_, policy)| policy.field.clone()),
        )
        .collect::<HashSet<_>>();
    let mut seen_names = HashSet::new();
    let mut seen_paths = HashSet::new();
    let mut actions = Vec::with_capacity(documents.len());

    for document in documents {
        validate_api_name(
            document.name.as_str(),
            format!("resource `{resource_name}` action `{}`", document.name).as_str(),
        )?;
        if !seen_names.insert(document.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate action `{}` on resource `{resource_name}`",
                    document.name
                ),
            ));
        }
        let path = document.path.unwrap_or_else(|| document.name.clone());
        validate_api_name(
            path.as_str(),
            format!("resource `{resource_name}` action `{}` path", document.name).as_str(),
        )?;
        if !seen_paths.insert(path.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate action path `{path}` on resource `{resource_name}`",),
            ));
        }

        let target = parse_resource_action_target(
            document.target.as_deref(),
            resource_name,
            document.name.as_str(),
        )?;
        let method = parse_resource_action_method(
            document.method.as_deref(),
            resource_name,
            document.name.as_str(),
        )?;
        let behavior = parse_resource_action_behavior(
            resource_name,
            document.name.as_str(),
            fields,
            &controlled_fields,
            document.behavior,
        )?;
        let input_fields = match &behavior {
            ResourceActionBehaviorSpec::UpdateFields { assignments } => assignments
                .iter()
                .filter_map(|assignment| match &assignment.value {
                    ResourceActionValueSpec::InputField(name) => {
                        Some(ResourceActionInputFieldSpec {
                            name: name.clone(),
                            target_field: assignment.field.clone(),
                        })
                    }
                    ResourceActionValueSpec::Literal(_) => None,
                })
                .collect(),
            ResourceActionBehaviorSpec::DeleteResource => Vec::new(),
        };

        actions.push(ResourceActionSpec {
            name: document.name,
            path,
            target,
            method,
            input_fields,
            behavior,
        });
    }

    Ok(actions)
}

fn parse_resource_action_target(
    value: Option<&str>,
    resource_name: &str,
    action_name: &str,
) -> syn::Result<ResourceActionTarget> {
    match value.unwrap_or("Item") {
        "Item" => Ok(ResourceActionTarget::Item),
        other => Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` has unsupported target `{other}`; only `Item` is supported"
            ),
        )),
    }
}

fn parse_resource_action_method(
    value: Option<&str>,
    resource_name: &str,
    action_name: &str,
) -> syn::Result<ResourceActionMethod> {
    match value.unwrap_or("POST") {
        "POST" => Ok(ResourceActionMethod::Post),
        other => Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` has unsupported method `{other}`; only `POST` is supported"
            ),
        )),
    }
}

fn parse_resource_action_behavior(
    resource_name: &str,
    action_name: &str,
    fields: &[FieldSpec],
    controlled_fields: &HashSet<String>,
    document: ResourceActionBehaviorDocument,
) -> syn::Result<ResourceActionBehaviorSpec> {
    match document.kind.as_str() {
        "UpdateFields" => {
            if document.set.is_empty() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "resource `{resource_name}` action `{action_name}` must declare at least one `behavior.set` field"
                    ),
                ));
            }
            let mut seen_input_fields = HashSet::new();
            let assignments = document
                .set
                .into_iter()
                .map(|(field_name, value)| {
                    let Some(field) = fields.iter().find(|field| field.name() == field_name) else {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "resource `{resource_name}` action `{action_name}` references unknown field `{field_name}`"
                            ),
                        ));
                    };
                    validate_resource_action_assignment_field(
                        resource_name,
                        action_name,
                        field,
                        controlled_fields,
                    )?;
                    Ok(ResourceActionAssignmentSpec {
                        field: field_name,
                        value: match value {
                            ResourceActionAssignmentValueDocument::Literal(value) => {
                                ResourceActionValueSpec::Literal(
                                    normalize_resource_action_field_value(
                                        resource_name,
                                        action_name,
                                        field,
                                        &value,
                                    )?,
                                )
                            }
                            ResourceActionAssignmentValueDocument::Input(input) => {
                                validate_api_name(
                                    input.input.as_str(),
                                    format!(
                                        "resource `{resource_name}` action `{action_name}` input"
                                    )
                                    .as_str(),
                                )?;
                                if !seen_input_fields.insert(input.input.clone()) {
                                    return Err(syn::Error::new(
                                        Span::call_site(),
                                        format!(
                                            "resource `{resource_name}` action `{action_name}` reuses input field `{}` across multiple assignments; duplicate action inputs are not supported yet",
                                            input.input
                                        ),
                                    ));
                                }
                                ResourceActionValueSpec::InputField(input.input)
                            }
                        },
                    })
                })
                .collect::<syn::Result<Vec<_>>>()?;
            Ok(ResourceActionBehaviorSpec::UpdateFields { assignments })
        }
        "DeleteResource" => {
            if !document.set.is_empty() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "resource `{resource_name}` action `{action_name}` with `DeleteResource` behavior cannot declare `behavior.set` fields"
                    ),
                ));
            }
            Ok(ResourceActionBehaviorSpec::DeleteResource)
        }
        other => Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` has unsupported behavior kind `{other}`; only `UpdateFields` and `DeleteResource` are supported"
            ),
        )),
    }
}

fn validate_resource_action_assignment_field(
    resource_name: &str,
    action_name: &str,
    field: &FieldSpec,
    controlled_fields: &HashSet<String>,
) -> syn::Result<()> {
    if field.is_id {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` cannot assign id field `{}`",
                field.name()
            ),
        ));
    }
    if field.generated.skip_update_bind() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` cannot assign generated field `{}`",
                field.name()
            ),
        ));
    }
    if controlled_fields.contains(&field.name()) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` cannot assign policy-controlled field `{}`",
                field.name()
            ),
        ));
    }
    if is_typed_object_field(field)
        || is_list_field(field)
        || is_json_type(&field.ty)
        || is_json_object_type(&field.ty)
        || is_json_array_type(&field.ty)
    {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` only supports scalar assignment fields in the first slice; `{}` is not supported",
                field.name()
            ),
        ));
    }
    Ok(())
}

fn normalize_resource_action_field_value(
    resource_name: &str,
    action_name: &str,
    field: &FieldSpec,
    value: &JsonValue,
) -> syn::Result<JsonValue> {
    let label = format!(
        "resource `{resource_name}` action `{action_name}` field `{}`",
        field.name()
    );

    if value.is_null() {
        return if is_optional_type(&field.ty) {
            Ok(JsonValue::Null)
        } else {
            Err(syn::Error::new(
                Span::call_site(),
                format!("{label} cannot be null"),
            ))
        };
    }

    let normalized =
        if let Some(kind) = structured_scalar_kind(&field.ty) {
            let text = value.as_str().ok_or_else(|| {
                syn::Error::new(Span::call_site(), format!("{label} must be a string"))
            })?;
            JsonValue::String(normalize_structured_scalar_action_text(kind, text).map_err(
                |error| syn::Error::new(Span::call_site(), format!("{label} is invalid: {error}")),
            )?)
        } else if super::model::is_bool_type(&field.ty) {
            JsonValue::Bool(value.as_bool().ok_or_else(|| {
                syn::Error::new(Span::call_site(), format!("{label} must be a boolean"))
            })?)
        } else {
            match infer_sql_type(&field.ty, DbBackend::Sqlite).as_str() {
                sql_type if super::model::is_integer_sql_type(sql_type) => {
                    JsonValue::from(value.as_i64().ok_or_else(|| {
                        syn::Error::new(Span::call_site(), format!("{label} must be an integer"))
                    })?)
                }
                "REAL" => JsonValue::Number(
                    serde_json::Number::from_f64(value.as_f64().ok_or_else(|| {
                        syn::Error::new(Span::call_site(), format!("{label} must be a number"))
                    })?)
                    .ok_or_else(|| {
                        syn::Error::new(
                            Span::call_site(),
                            format!("{label} must be a finite number"),
                        )
                    })?,
                ),
                _ => {
                    let text = value.as_str().ok_or_else(|| {
                        syn::Error::new(Span::call_site(), format!("{label} must be a string"))
                    })?;
                    JsonValue::String(apply_action_field_transforms(field.transforms(), text))
                }
            }
        };

    validate_resource_action_scalar_value(field, &normalized, &label)?;
    Ok(normalized)
}

fn normalize_structured_scalar_action_text(
    kind: super::model::StructuredScalarKind,
    value: &str,
) -> Result<String, String> {
    Ok(match kind {
        super::model::StructuredScalarKind::DateTime => DateTime::parse_from_rfc3339(value)
            .map_err(|error| format!("invalid date-time `{value}`: {error}"))?
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Micros, false),
        super::model::StructuredScalarKind::Date => NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .map_err(|error| format!("invalid date `{value}`: {error}"))?
            .format("%Y-%m-%d")
            .to_string(),
        super::model::StructuredScalarKind::Time => value
            .parse::<NaiveTime>()
            .map_err(|error| format!("invalid time `{value}`: {error}"))?
            .format("%H:%M:%S.%6f")
            .to_string(),
        super::model::StructuredScalarKind::Uuid => Uuid::parse_str(value)
            .map_err(|error| format!("invalid uuid `{value}`: {error}"))?
            .as_hyphenated()
            .to_string(),
        super::model::StructuredScalarKind::Decimal => value
            .parse::<Decimal>()
            .map_err(|error| format!("invalid decimal `{value}`: {error}"))?
            .normalize()
            .to_string(),
        super::model::StructuredScalarKind::Json
        | super::model::StructuredScalarKind::JsonObject
        | super::model::StructuredScalarKind::JsonArray => {
            return Err("JSON scalar fields are not supported in action assignments".to_owned());
        }
    })
}

fn apply_action_field_transforms(transforms: &[FieldTransform], value: &str) -> String {
    transforms
        .iter()
        .fold(value.to_owned(), |current, transform| match transform {
            FieldTransform::Trim => current.trim().to_owned(),
            FieldTransform::Lowercase => current.to_lowercase(),
            FieldTransform::CollapseWhitespace => {
                current.split_whitespace().collect::<Vec<_>>().join(" ")
            }
            FieldTransform::Slugify => {
                let mut slug = String::new();
                let mut pending_dash = false;
                for ch in current.chars() {
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
                slug
            }
        })
}

fn validate_resource_action_scalar_value(
    field: &FieldSpec,
    value: &JsonValue,
    label: &str,
) -> syn::Result<()> {
    if let Some(enum_values) = field.enum_values() {
        let text = value.as_str().ok_or_else(|| {
            syn::Error::new(Span::call_site(), format!("{label} must be a string"))
        })?;
        if !enum_values.iter().any(|candidate| candidate == text) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{label} must be one of: {}", enum_values.join(", ")),
            ));
        }
    }

    if let Some(length) = field.validation.length.as_ref() {
        let text = value.as_str().ok_or_else(|| {
            syn::Error::new(Span::call_site(), format!("{label} must be a string"))
        })?;
        let measured = match length.mode {
            Some(LengthMode::Chars) => text.chars().count(),
            _ => text.len(),
        };
        if let Some(min_length) = length.min
            && measured < min_length
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{label} must have at least {min_length} characters"),
            ));
        }
        if let Some(max_length) = length.max
            && measured > max_length
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{label} must have at most {max_length} characters"),
            ));
        }
        if let Some(equal) = length.equal
            && measured != equal
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{label} must have exactly {equal} characters"),
            ));
        }
    }

    if let Some(range) = field.validation.range.as_ref() {
        match infer_sql_type(&field.ty, DbBackend::Sqlite).as_str() {
            sql_type if super::model::is_integer_sql_type(sql_type) => {
                if let Some(NumericBound::Integer(minimum)) = &range.min
                    && value.as_i64().is_some_and(|actual| actual < *minimum)
                {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!("{label} must be at least {minimum}"),
                    ));
                }
                if let Some(NumericBound::Integer(maximum)) = &range.max
                    && value.as_i64().is_some_and(|actual| actual > *maximum)
                {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!("{label} must be at most {maximum}"),
                    ));
                }
                if let Some(NumericBound::Integer(equal)) = &range.equal
                    && value.as_i64().is_some_and(|actual| actual != *equal)
                {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!("{label} must equal {equal}"),
                    ));
                }
            }
            "REAL" => {
                if let Some(minimum) = &range.min
                    && value
                        .as_f64()
                        .is_some_and(|actual| actual < minimum.as_f64())
                {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!("{label} must be at least {}", minimum.as_f64()),
                    ));
                }
                if let Some(maximum) = &range.max
                    && value
                        .as_f64()
                        .is_some_and(|actual| actual > maximum.as_f64())
                {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!("{label} must be at most {}", maximum.as_f64()),
                    ));
                }
                if let Some(equal) = &range.equal
                    && value
                        .as_f64()
                        .is_some_and(|actual| actual != equal.as_f64())
                {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!("{label} must equal {}", equal.as_f64()),
                    ));
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn build_computed_field_spec(
    api_name: &str,
    template: &str,
    available_fields: &[&FieldSpec],
    resource_name: &str,
) -> syn::Result<super::model::ComputedFieldSpec> {
    use super::model::{ComputedFieldPart, ComputedFieldSpec};

    let mut parts = Vec::new();
    let mut optional = false;
    let mut cursor = 0;

    while let Some(start_offset) = template[cursor..].find('{') {
        let start = cursor + start_offset;
        if start > cursor {
            parts.push(ComputedFieldPart::Literal(
                template[cursor..start].to_owned(),
            ));
        }
        let placeholder_start = start + 1;
        let Some(end_offset) = template[placeholder_start..].find('}') else {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` computed api field `{api_name}` has an unterminated template placeholder"
                ),
            ));
        };
        let end = placeholder_start + end_offset;
        let field_name = template[placeholder_start..end].trim();
        if field_name.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` computed api field `{api_name}` has an empty template placeholder"
                ),
            ));
        }
        let Some(field) = available_fields
            .iter()
            .find(|field| field.api_name() == field_name)
        else {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` computed api field `{api_name}` references unknown API field `{field_name}`"
                ),
            ));
        };
        if !supports_computed_template_field(field) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` computed api field `{api_name}` cannot interpolate non-scalar API field `{field_name}`"
                ),
            ));
        }
        optional |= super::model::is_optional_type(&field.ty);
        parts.push(ComputedFieldPart::Field(field_name.to_owned()));
        cursor = end + 1;
    }

    if cursor < template.len() {
        parts.push(ComputedFieldPart::Literal(template[cursor..].to_owned()));
    }

    if parts.is_empty() {
        parts.push(ComputedFieldPart::Literal(String::new()));
    }

    Ok(ComputedFieldSpec {
        api_name: api_name.to_owned(),
        optional,
        parts,
    })
}

fn supports_computed_template_field(field: &FieldSpec) -> bool {
    field.list_item_ty.is_none()
        && field.object_fields.is_none()
        && !super::model::is_json_type(&field.ty)
        && !super::model::is_json_object_type(&field.ty)
        && !super::model::is_json_array_type(&field.ty)
}

fn apply_resource_api_projections(
    fields: &mut [FieldSpec],
    projections: Vec<ApiFieldProjectionDocument>,
    resource_name: &str,
    configured_id: &str,
) -> syn::Result<Vec<super::model::ComputedFieldSpec>> {
    let mut seen_api_names = HashSet::new();
    let mut seen_storage_fields = HashSet::new();

    for projection in &projections {
        match (&projection.from, &projection.template) {
            (Some(_), None) | (None, Some(_)) => {}
            (Some(_), Some(_)) => {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "resource `{resource_name}` api field `{}` cannot set both `from` and `template`",
                        projection.name
                    ),
                ));
            }
            (None, None) => {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "resource `{resource_name}` api field `{}` must set either `from` or `template`",
                        projection.name
                    ),
                ));
            }
        }
    }

    for projection in projections
        .iter()
        .filter(|projection| projection.from.is_some())
    {
        validate_api_name(
            projection.name.as_str(),
            format!(
                "resource `{resource_name}` api.fields `{}`",
                projection.name
            )
            .as_str(),
        )?;
        if !seen_api_names.insert(projection.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate api field projection `{}` on resource `{resource_name}`",
                    projection.name
                ),
            ));
        }
        let storage_field_name = projection
            .from
            .as_ref()
            .expect("projection storage field should exist");
        if !seen_storage_fields.insert(storage_field_name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` maps storage field `{}` more than once in `api.fields`",
                    storage_field_name
                ),
            ));
        }
        let Some(field) = fields
            .iter_mut()
            .find(|field| field.name() == *storage_field_name)
        else {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` api field `{}` references unknown storage field `{}`",
                    projection.name, storage_field_name
                ),
            ));
        };
        field.api_name = projection.name.clone();
        field.expose_in_api = true;
    }

    let mut computed_fields = Vec::new();
    let available_fields = fields
        .iter()
        .filter(|field| field.expose_in_api())
        .collect::<Vec<_>>();
    for projection in projections
        .into_iter()
        .filter(|projection| projection.template.is_some())
    {
        validate_api_name(
            projection.name.as_str(),
            format!(
                "resource `{resource_name}` api.fields `{}`",
                projection.name
            )
            .as_str(),
        )?;
        if !seen_api_names.insert(projection.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate api field projection `{}` on resource `{resource_name}`",
                    projection.name
                ),
            ));
        }
        let template = projection
            .template
            .as_deref()
            .expect("computed template should exist");
        computed_fields.push(build_computed_field_spec(
            projection.name.as_str(),
            template,
            available_fields.as_slice(),
            resource_name,
        )?);
    }

    if !fields
        .iter()
        .any(|field| field.name() == configured_id && field.expose_in_api())
    {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` must expose configured id field `{configured_id}` in `api.fields`"
            ),
        ));
    }

    Ok(computed_fields)
}

fn build_response_contexts(
    fields: &[FieldSpec],
    computed_fields: &[super::model::ComputedFieldSpec],
    default_context: Option<String>,
    contexts: Vec<ResponseContextDocument>,
    resource_name: &str,
) -> syn::Result<(Option<String>, Vec<ResponseContextSpec>)> {
    let mut seen_contexts = HashSet::new();
    let mut parsed_contexts = Vec::with_capacity(contexts.len());

    for context in contexts {
        validate_api_name(
            context.name.as_str(),
            format!("resource `{resource_name}` api.contexts `{}`", context.name).as_str(),
        )?;
        if !seen_contexts.insert(context.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate response context `{}` on resource `{resource_name}`",
                    context.name
                ),
            ));
        }

        let mut seen_fields = HashSet::new();
        let mut parsed_fields = Vec::with_capacity(context.fields.len());
        for field_name in context.fields {
            if !seen_fields.insert(field_name.clone()) {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "response context `{}` on resource `{resource_name}` includes field `{field_name}` more than once",
                        context.name
                    ),
                ));
            }
            if !fields
                .iter()
                .any(|field| field.expose_in_api() && field.api_name() == field_name)
                && !computed_fields
                    .iter()
                    .any(|field| field.api_name == field_name)
            {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "response context `{}` on resource `{resource_name}` references unknown API field `{field_name}`",
                        context.name
                    ),
                ));
            }
            parsed_fields.push(field_name);
        }

        parsed_contexts.push(ResponseContextSpec {
            name: context.name,
            fields: parsed_fields,
        });
    }

    if let Some(default_context_name) = default_context {
        validate_api_name(
            default_context_name.as_str(),
            format!("resource `{resource_name}` api.default_context").as_str(),
        )?;
        if !parsed_contexts
            .iter()
            .any(|context| context.name == default_context_name)
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` api.default_context `{default_context_name}` does not match any configured `api.contexts`"
                ),
            ));
        }
        Ok((Some(default_context_name), parsed_contexts))
    } else {
        Ok((None, parsed_contexts))
    }
}

fn build_index_specs(indexes: Vec<IndexDocument>) -> Vec<IndexSpec> {
    indexes
        .into_iter()
        .map(|index| IndexSpec {
            fields: index.fields,
            unique: index.unique,
        })
        .collect()
}

fn validate_resource_indexes(resource: &ResourceSpec, span: Span) -> syn::Result<()> {
    for field in &resource.fields {
        if !field.unique {
            continue;
        }

        if field.is_id {
            return Err(syn::Error::new(
                span,
                format!(
                    "field `{}` on resource `{}` cannot combine `id` with `unique`",
                    field.name(),
                    resource.struct_ident
                ),
            ));
        }

        if !supports_declared_index(field) {
            return Err(syn::Error::new(
                span,
                format!(
                    "field `{}` on resource `{}` does not support `unique`",
                    field.name(),
                    resource.struct_ident
                ),
            ));
        }
    }

    let mut seen_indexes = HashSet::new();
    for index in &resource.indexes {
        if index.fields.is_empty() {
            return Err(syn::Error::new(
                span,
                format!(
                    "resource `{}` index definitions must declare at least one field",
                    resource.struct_ident
                ),
            ));
        }

        let mut seen_fields = HashSet::new();
        for field_name in &index.fields {
            if !seen_fields.insert(field_name.clone()) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "resource `{}` index `{}` lists field `{field_name}` more than once",
                        resource.struct_ident,
                        index.name_for_table(resource.table_name.as_str())
                    ),
                ));
            }

            let field = resource.find_field(field_name.as_str()).ok_or_else(|| {
                syn::Error::new(
                    span,
                    format!(
                        "resource `{}` index references unknown field `{field_name}`",
                        resource.struct_ident
                    ),
                )
            })?;
            if !supports_declared_index(field) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "resource `{}` index references unsupported field `{field_name}`",
                        resource.struct_ident
                    ),
                ));
            }
        }

        let key = format!("{}:{}", index.unique as u8, index.fields.join("\u{1f}"));
        if !seen_indexes.insert(key) {
            return Err(syn::Error::new(
                span,
                format!(
                    "resource `{}` declares duplicate index `{}`",
                    resource.struct_ident,
                    index.name_for_table(resource.table_name.as_str())
                ),
            ));
        }
    }

    Ok(())
}

fn build_object_fields(
    db: DbBackend,
    fields: Vec<FieldDocument>,
    context: &str,
    enums: &[EnumSpec],
) -> syn::Result<Vec<FieldSpec>> {
    let mut seen_fields = HashSet::new();
    let mut seen_api_names = HashSet::new();
    let mut result = Vec::with_capacity(fields.len());

    for field in fields {
        if !seen_fields.insert(field.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate nested field `{}` in {context}", field.name),
            ));
        }
        let field_api_name = field.api_name.unwrap_or_else(|| field.name.clone());
        validate_api_name(
            field_api_name.as_str(),
            format!("nested field `{}` in {context} api_name", field.name).as_str(),
        )?;
        if !seen_api_names.insert(field_api_name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate nested field api_name `{}` in {context}",
                    field_api_name
                ),
            ));
        }
        reject_legacy_field_validation(
            field.legacy_validate.as_ref(),
            format!("nested field `{}` in {context}", field.name).as_str(),
        )?;

        if field.id {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "nested field `{}` in {context} cannot set `id = true`",
                    field.name
                ),
            ));
        }
        if field.generated != GeneratedValue::None {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "nested field `{}` in {context} cannot set `generated`",
                    field.name
                ),
            ));
        }
        if field.relation.is_some() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "nested field `{}` in {context} cannot set `relation`",
                    field.name
                ),
            ));
        }

        let parsed_ty = parse_field_type(&field.ty, field.items.as_ref(), field.nullable, enums)?;
        let sql_type = infer_sql_type(&parsed_ty.ty, db);
        let nested_context = format!("{context}.{}", field.name);
        if field.unique {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "nested field `{}` in {context} cannot declare `unique`",
                    field.name
                ),
            ));
        }
        let object_fields = match &field.ty {
            FieldTypeDocument::Scalar(ScalarType::Object) => {
                if field.fields.is_empty() {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!(
                            "nested field `{}` in {context} must set nested `fields` when `type = Object`",
                            field.name
                        ),
                    ));
                }
                if field.validate.is_some() {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!(
                            "nested field `{}` in {context} only supports nested garde validation through child fields and `dive`/`required`",
                            field.name
                        ),
                    ));
                }
                Some(build_object_fields(
                    db,
                    field.fields,
                    nested_context.as_str(),
                    enums,
                )?)
            }
            _ => {
                if !field.fields.is_empty() {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!(
                            "nested field `{}` in {context} can only set nested `fields` when `type = Object`",
                            field.name
                        ),
                    ));
                }
                None
            }
        };

        result.push(FieldSpec {
            ident: syn::parse_str(&field.name).map_err(|_| {
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        "nested field name `{}` in {context} is not a valid Rust identifier",
                        field.name
                    ),
                )
            })?,
            api_name: field_api_name,
            expose_in_api: true,
            unique: field.unique,
            enum_name: parsed_ty.enum_name,
            enum_values: parsed_ty.enum_values,
            transforms: parse_field_transforms_document(field.transforms)?,
            ty: parsed_ty.ty,
            list_item_ty: parsed_ty.list_item_ty,
            object_fields,
            sql_type,
            is_id: false,
            generated: GeneratedValue::None,
            validation: parse_field_validation_document(field.validate)?,
            relation: None,
        });
    }

    Ok(result)
}


mod config_parsing;
use self::config_parsing::*;



mod storage_parsing;
use self::storage_parsing::*;



mod field_parsing;
use self::field_parsing::*;

mod policy_parsing;
use self::policy_parsing::*;
#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    fn parse_document(source: &str) -> ServiceDocument {
        eon::from_str::<ServiceDocument>(source).expect("eon should parse")
    }

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}_{stamp}"))
    }

    #[test]
    fn parses_turso_local_database_engine_from_eon() {
        let database = parse_database_document(
            DbBackend::Sqlite,
            Some(DatabaseDocument {
                engine: Some(DatabaseEngineDocument {
                    kind: "TursoLocal".to_owned(),
                    path: Some("var/data/app.db".to_owned()),
                    encryption_key: None,
                    encryption_key_env: None,
                }),
                resilience: None,
            }),
            "app_api",
            Span::call_site(),
        )
        .expect("database config should parse");
        assert_eq!(
            database.engine,
            DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: "var/data/app.db".to_owned(),
                encryption_key: None,
            })
        );
        assert!(database.resilience.is_none());
    }

    #[test]
    fn rejects_turso_local_for_non_sqlite_dialect() {
        let error = parse_database_document(
            DbBackend::Postgres,
            Some(DatabaseDocument {
                engine: Some(DatabaseEngineDocument {
                    kind: "TursoLocal".to_owned(),
                    path: Some("var/data/app.db".to_owned()),
                    encryption_key: None,
                    encryption_key_env: None,
                }),
                resilience: None,
            }),
            "app_api",
            Span::call_site(),
        )
        .expect_err("non-sqlite turso config should fail");
        assert!(
            error
                .to_string()
                .contains("database.engine = TursoLocal requires `db: Sqlite`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn defaults_sqlite_services_to_turso_local_engine() {
        let database =
            parse_database_document(DbBackend::Sqlite, None, "blog_api", Span::call_site())
                .expect("sqlite service should default to turso local");
        assert_eq!(
            database.engine,
            DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: "var/data/blog_api.db".to_owned(),
                encryption_key: Some(SecretRef::env_or_file(
                    DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV,
                )),
            })
        );
        assert!(database.resilience.is_none());
    }

    #[test]
    fn parses_database_resilience_contract_from_eon() {
        let database = parse_database_document(
            DbBackend::Postgres,
            Some(DatabaseDocument {
                engine: Some(DatabaseEngineDocument {
                    kind: "Sqlx".to_owned(),
                    path: None,
                    encryption_key: None,
                    encryption_key_env: None,
                }),
                resilience: Some(DatabaseResilienceDocument {
                    profile: Some("Pitr".to_owned()),
                    backup: Some(DatabaseBackupDocument {
                        required: Some(true),
                        mode: Some("Pitr".to_owned()),
                        target: Some("S3".to_owned()),
                        verify_restore: Some(true),
                        max_age: Some("24h".to_owned()),
                        encryption_key: None,
                        encryption_key_env: Some("BACKUP_ENCRYPTION_KEY".to_owned()),
                        retention: Some(DatabaseBackupRetentionDocument {
                            daily: Some(7),
                            weekly: Some(4),
                            monthly: Some(12),
                        }),
                    }),
                    replication: Some(DatabaseReplicationDocument {
                        mode: Some("ReadReplica".to_owned()),
                        read_routing: Some("Explicit".to_owned()),
                        read_url: None,
                        read_url_env: Some("DATABASE_READ_URL".to_owned()),
                        max_lag: Some("30s".to_owned()),
                        replicas_expected: Some(1),
                    }),
                }),
            }),
            "app_api",
            Span::call_site(),
        )
        .expect("database resilience should parse");

        let resilience = database.resilience.expect("resilience should exist");
        assert_eq!(resilience.profile, DatabaseResilienceProfile::Pitr);
        let backup = resilience.backup.expect("backup should exist");
        assert_eq!(backup.mode, DatabaseBackupMode::Pitr);
        assert_eq!(backup.target, DatabaseBackupTarget::S3);
        assert!(backup.verify_restore);
        assert_eq!(backup.max_age.as_deref(), Some("24h"));
        let replication = resilience.replication.expect("replication should exist");
        assert_eq!(replication.mode, DatabaseReplicationMode::ReadReplica);
        assert_eq!(replication.read_routing, DatabaseReadRoutingMode::Explicit);
        assert_eq!(
            replication.read_url.as_ref(),
            Some(&SecretRef::env_or_file("DATABASE_READ_URL"))
        );
    }

    #[test]
    fn parses_typed_database_secret_refs_from_eon() {
        let database = parse_database_document(
            DbBackend::Sqlite,
            Some(DatabaseDocument {
                engine: Some(DatabaseEngineDocument {
                    kind: "TursoLocal".to_owned(),
                    path: Some("var/data/app.db".to_owned()),
                    encryption_key: Some(SecretRefDocument {
                        env: None,
                        env_or_file: Some("TURSO_ENCRYPTION_KEY".to_owned()),
                        systemd_credential: None,
                        external: None,
                    }),
                    encryption_key_env: None,
                }),
                resilience: Some(DatabaseResilienceDocument {
                    profile: Some("Pitr".to_owned()),
                    backup: Some(DatabaseBackupDocument {
                        required: Some(true),
                        mode: Some("Snapshot".to_owned()),
                        target: Some("Local".to_owned()),
                        verify_restore: Some(true),
                        max_age: None,
                        encryption_key: Some(SecretRefDocument {
                            env: None,
                            env_or_file: None,
                            systemd_credential: Some("backup_encryption_key".to_owned()),
                            external: None,
                        }),
                        encryption_key_env: None,
                        retention: None,
                    }),
                    replication: None,
                }),
            }),
            "app_api",
            Span::call_site(),
        )
        .expect("typed secret refs should parse");

        assert_eq!(
            database.engine,
            DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: "var/data/app.db".to_owned(),
                encryption_key: Some(SecretRef::env_or_file("TURSO_ENCRYPTION_KEY")),
            })
        );
        assert_eq!(
            database
                .resilience
                .as_ref()
                .and_then(|config| config.backup.as_ref())
                .and_then(|backup| backup.encryption_key.as_ref()),
            Some(&SecretRef::SystemdCredential {
                id: "backup_encryption_key".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_replication_read_routing_without_read_url() {
        let error = parse_database_document(
            DbBackend::Postgres,
            Some(DatabaseDocument {
                engine: Some(DatabaseEngineDocument {
                    kind: "Sqlx".to_owned(),
                    path: None,
                    encryption_key: None,
                    encryption_key_env: None,
                }),
                resilience: Some(DatabaseResilienceDocument {
                    profile: None,
                    backup: None,
                    replication: Some(DatabaseReplicationDocument {
                        mode: Some("ReadReplica".to_owned()),
                        read_routing: Some("Explicit".to_owned()),
                        read_url: None,
                        read_url_env: None,
                        max_lag: None,
                        replicas_expected: None,
                    }),
                }),
            }),
            "app_api",
            Span::call_site(),
        )
        .expect_err("missing read url should fail");

        assert!(
            error
                .to_string()
                .contains("database.resilience.replication.read_url or `read_url_env` is required"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_turso_local_replication_contract() {
        let error = parse_database_document(
            DbBackend::Sqlite,
            Some(DatabaseDocument {
                engine: Some(DatabaseEngineDocument {
                    kind: "TursoLocal".to_owned(),
                    path: Some("var/data/app.db".to_owned()),
                    encryption_key: None,
                    encryption_key_env: None,
                }),
                resilience: Some(DatabaseResilienceDocument {
                    profile: Some("Ha".to_owned()),
                    backup: None,
                    replication: Some(DatabaseReplicationDocument {
                        mode: Some("ReadReplica".to_owned()),
                        read_routing: Some("Off".to_owned()),
                        read_url: None,
                        read_url_env: None,
                        max_lag: None,
                        replicas_expected: None,
                    }),
                }),
            }),
            "app_api",
            Span::call_site(),
        )
        .expect_err("turso local replication should fail");

        assert!(
            error
                .to_string()
                .contains("database.resilience.replication is not supported for `database.engine = TursoLocal`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn parses_datetime_scalar_as_typed_datetime_field() {
        let resources = build_resources(
            DbBackend::Sqlite,
            vec![ResourceDocument {
                name: "Event".to_owned(),
                api_name: None,
                table: None,
                id_field: None,
                access: ResourceAccessDocument::default(),
                roles: RoleRequirements::default(),
                policies: RowPoliciesDocument::default(),
                list: ListConfigDocument::default(),
                api: None,
                use_mixins: Vec::new(),
                indexes: Vec::new(),
                many_to_many: Vec::new(),
                actions: Vec::new(),
                fields: vec![
                    FieldDocument {
                        name: "id".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::I64),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: true,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                    FieldDocument {
                        name: "starts_at".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::DateTime),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                ],
            }],
        )
        .expect("resources should build");

        let starts_at = resources[0]
            .find_field("starts_at")
            .expect("starts_at field should exist");
        assert_eq!(starts_at.sql_type, "TEXT");
        assert!(super::super::model::is_datetime_type(&starts_at.ty));
    }

    #[test]
    fn parses_portable_scalar_types_as_typed_fields() {
        let resources = build_resources(
            DbBackend::Sqlite,
            vec![ResourceDocument {
                name: "Schedule".to_owned(),
                api_name: None,
                table: None,
                id_field: None,
                access: ResourceAccessDocument::default(),
                roles: RoleRequirements::default(),
                policies: RowPoliciesDocument::default(),
                list: ListConfigDocument::default(),
                api: None,
                use_mixins: Vec::new(),
                indexes: Vec::new(),
                many_to_many: Vec::new(),
                actions: Vec::new(),
                fields: vec![
                    FieldDocument {
                        name: "id".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::I64),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: true,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                    FieldDocument {
                        name: "run_on".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::Date),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                    FieldDocument {
                        name: "run_at".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::Time),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                    FieldDocument {
                        name: "external_id".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::Uuid),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                    FieldDocument {
                        name: "amount".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::Decimal),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                ],
            }],
        )
        .expect("resources should build");

        let run_on = resources[0]
            .find_field("run_on")
            .expect("run_on field should exist");
        let run_at = resources[0]
            .find_field("run_at")
            .expect("run_at field should exist");
        let external_id = resources[0]
            .find_field("external_id")
            .expect("external_id field should exist");
        let amount = resources[0]
            .find_field("amount")
            .expect("amount field should exist");

        assert_eq!(run_on.sql_type, "TEXT");
        assert_eq!(run_at.sql_type, "TEXT");
        assert_eq!(external_id.sql_type, "TEXT");
        assert_eq!(amount.sql_type, "TEXT");
        assert!(super::super::model::is_date_type(&run_on.ty));
        assert!(super::super::model::is_time_type(&run_at.ty));
        assert!(super::super::model::is_uuid_type(&external_id.ty));
        assert!(super::super::model::is_decimal_type(&amount.ty));
    }

    #[test]
    fn parses_json_scalar_types_as_typed_fields() {
        let resources = build_resources(
            DbBackend::Sqlite,
            vec![ResourceDocument {
                name: "BlockDocument".to_owned(),
                api_name: None,
                table: None,
                id_field: None,
                access: ResourceAccessDocument::default(),
                roles: RoleRequirements::default(),
                policies: RowPoliciesDocument::default(),
                list: ListConfigDocument::default(),
                api: None,
                use_mixins: Vec::new(),
                indexes: Vec::new(),
                many_to_many: Vec::new(),
                actions: Vec::new(),
                fields: vec![
                    FieldDocument {
                        name: "id".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::I64),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: true,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                    FieldDocument {
                        name: "payload".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::Json),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                    FieldDocument {
                        name: "attributes".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::JsonObject),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                    FieldDocument {
                        name: "blocks".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::JsonArray),
                        items: None,
                        fields: vec![],
                        nullable: true,
                        id: false,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                ],
            }],
        )
        .expect("resources should build");

        let payload = resources[0]
            .find_field("payload")
            .expect("payload field should exist");
        let attributes = resources[0]
            .find_field("attributes")
            .expect("attributes field should exist");
        let blocks = resources[0]
            .find_field("blocks")
            .expect("blocks field should exist");

        assert_eq!(payload.sql_type, "TEXT");
        assert_eq!(attributes.sql_type, "TEXT");
        assert_eq!(blocks.sql_type, "TEXT");
        assert!(super::super::model::is_json_type(&payload.ty));
        assert!(super::super::model::is_json_object_type(&attributes.ty));
        assert!(super::super::model::is_json_array_type(&blocks.ty));
    }

    #[test]
    fn parses_list_fields_with_scalar_item_types() {
        let resources = build_resources(
            DbBackend::Sqlite,
            vec![ResourceDocument {
                name: "Entry".to_owned(),
                api_name: None,
                table: None,
                id_field: None,
                access: ResourceAccessDocument::default(),
                roles: RoleRequirements::default(),
                policies: RowPoliciesDocument::default(),
                list: ListConfigDocument::default(),
                api: None,
                use_mixins: Vec::new(),
                indexes: Vec::new(),
                many_to_many: Vec::new(),
                actions: Vec::new(),
                fields: vec![
                    FieldDocument {
                        name: "id".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::I64),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: true,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                    FieldDocument {
                        name: "categories".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::List),
                        items: Some(FieldTypeDocument::Scalar(ScalarType::I64)),
                        fields: vec![],
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                    FieldDocument {
                        name: "blocks".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::List),
                        items: Some(FieldTypeDocument::Scalar(ScalarType::JsonObject)),
                        fields: vec![],
                        nullable: true,
                        id: false,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                ],
            }],
        )
        .expect("resources should build");

        let categories = resources[0]
            .find_field("categories")
            .expect("categories field should exist");
        let blocks = resources[0]
            .find_field("blocks")
            .expect("blocks field should exist");

        assert_eq!(categories.sql_type, "TEXT");
        assert_eq!(blocks.sql_type, "TEXT");
        assert!(super::super::model::is_list_field(categories));
        assert!(super::super::model::is_list_field(blocks));
        assert_eq!(
            super::super::model::list_item_type(categories)
                .expect("list item type should exist")
                .to_token_stream()
                .to_string(),
            "i64"
        );
        assert_eq!(
            super::super::model::list_item_type(blocks)
                .expect("list item type should exist")
                .to_token_stream()
                .to_string(),
            super::super::model::GENERATED_JSON_OBJECT_ALIAS
        );
    }

    #[test]
    fn parses_typed_object_fields_with_nested_shapes() {
        let resources = build_resources(
            DbBackend::Sqlite,
            vec![ResourceDocument {
                name: "Entry".to_owned(),
                api_name: None,
                table: None,
                id_field: None,
                access: ResourceAccessDocument::default(),
                roles: RoleRequirements::default(),
                policies: RowPoliciesDocument::default(),
                list: ListConfigDocument::default(),
                api: None,
                use_mixins: Vec::new(),
                indexes: Vec::new(),
                many_to_many: Vec::new(),
                actions: Vec::new(),
                fields: vec![
                    FieldDocument {
                        name: "id".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::I64),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: true,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                    FieldDocument {
                        name: "title".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::Object),
                        items: None,
                        fields: vec![
                            FieldDocument {
                                name: "raw".to_owned(),
                                api_name: None,
                                ty: FieldTypeDocument::Scalar(ScalarType::String),
                                items: None,
                                fields: vec![],
                                nullable: false,
                                id: false,
                                generated: GeneratedValue::None,
                                unique: false,
                                transforms: Vec::new(),
                                relation: None,
                                validate: Some(FieldValidationDocument {
                                    length: Some(LengthValidationDocument {
                                        min: Some(3),
                                        max: None,
                                        equal: None,
                                        mode: Some("Chars".to_owned()),
                                    }),
                                    ..FieldValidationDocument::default()
                                }),
                                legacy_validate: None,
                            },
                            FieldDocument {
                                name: "rendered".to_owned(),
                                api_name: None,
                                ty: FieldTypeDocument::Scalar(ScalarType::String),
                                items: None,
                                fields: vec![],
                                nullable: true,
                                id: false,
                                generated: GeneratedValue::None,
                                unique: false,
                                transforms: Vec::new(),
                                relation: None,
                                validate: None,
                                legacy_validate: None,
                            },
                        ],
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                    FieldDocument {
                        name: "settings".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::Object),
                        items: None,
                        fields: vec![
                            FieldDocument {
                                name: "featured".to_owned(),
                                api_name: None,
                                ty: FieldTypeDocument::Scalar(ScalarType::Bool),
                                items: None,
                                fields: vec![],
                                nullable: false,
                                id: false,
                                generated: GeneratedValue::None,
                                unique: false,
                                transforms: Vec::new(),
                                relation: None,
                                validate: None,
                                legacy_validate: None,
                            },
                            FieldDocument {
                                name: "categories".to_owned(),
                                api_name: None,
                                ty: FieldTypeDocument::Scalar(ScalarType::List),
                                items: Some(FieldTypeDocument::Scalar(ScalarType::I64)),
                                fields: vec![],
                                nullable: true,
                                id: false,
                                generated: GeneratedValue::None,
                                unique: false,
                                transforms: Vec::new(),
                                relation: None,
                                validate: None,
                                legacy_validate: None,
                            },
                        ],
                        nullable: true,
                        id: false,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                ],
            }],
        )
        .expect("resources should build");

        let title = resources[0]
            .find_field("title")
            .expect("title field should exist");
        let settings = resources[0]
            .find_field("settings")
            .expect("settings field should exist");
        let title_fields =
            super::super::model::object_fields(title).expect("title should define object fields");
        let settings_fields = super::super::model::object_fields(settings)
            .expect("settings should define object fields");

        assert_eq!(title.sql_type, "TEXT");
        assert!(super::super::model::is_typed_object_field(title));
        assert_eq!(title_fields.len(), 2);
        assert_eq!(title_fields[0].name(), "raw");
        assert_eq!(
            title_fields[0]
                .validation
                .length
                .as_ref()
                .and_then(|length| length.min),
            Some(3)
        );
        assert!(super::super::model::is_list_field(&settings_fields[1]));
        assert_eq!(
            super::super::model::list_item_type(&settings_fields[1])
                .expect("list item type should exist")
                .to_token_stream()
                .to_string(),
            "i64"
        );
    }

    #[test]
    fn parses_resource_and_field_api_names_from_eon() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        api_name: "posts"
        fields: [
            { name: "id", type: I64, id: true, api_name: "postId" }
            {
                name: "title_text"
                type: String
                api_name: "title"
            }
            {
                name: "meta"
                type: Object
                api_name: "metadata"
                fields: [
                    { name: "summary_text", type: String, api_name: "summary", nullable: true }
                ]
            }
        ]
    }
]
"#,
        );
        let resources =
            build_resources(DbBackend::Sqlite, document.resources).expect("resources should build");

        let resource = &resources[0];
        let title = resource
            .find_field("title_text")
            .expect("title field should exist");
        let meta = resource
            .find_field("meta")
            .expect("meta field should exist");
        let meta_fields =
            super::super::model::object_fields(meta).expect("meta should define object fields");

        assert_eq!(resource.api_name(), "posts");
        assert_eq!(
            resource
                .find_field("id")
                .expect("id should exist")
                .api_name(),
            "postId"
        );
        assert_eq!(title.api_name(), "title");
        assert_eq!(meta.api_name(), "metadata");
        assert_eq!(meta_fields[0].api_name(), "summary");
    }

    #[test]
    fn parses_declared_enums_and_enum_fields() {
        let document = parse_document(
            r#"
enums: {
    PostStatus: ["draft", "published", "archived"]
}
resources: [
    {
        name: "Post"
        fields: [
            { name: "id", type: I64, id: true }
            { name: "status", type: PostStatus }
            {
                name: "workflow"
                type: Object
                nullable: true
                fields: [
                    { name: "current", type: PostStatus }
                ]
            }
        ]
    }
]
"#,
        );
        let enums = build_enums(document.enums).expect("enums should build");
        let resources = build_resources_with_enums(DbBackend::Sqlite, document.resources, &enums)
            .expect("resources should build");
        let resource = &resources[0];
        let status = resource
            .find_field("status")
            .expect("status field should exist");
        let workflow = resource
            .find_field("workflow")
            .expect("workflow field should exist");
        let workflow_fields = super::super::model::object_fields(workflow)
            .expect("workflow should define object fields");

        assert_eq!(enums[0].name, "PostStatus");
        assert_eq!(enums[0].values, vec!["draft", "published", "archived"]);
        assert_eq!(status.enum_name(), Some("PostStatus"));
        assert_eq!(
            status.enum_values().map(|values| values.to_vec()),
            Some(vec![
                "draft".to_owned(),
                "published".to_owned(),
                "archived".to_owned()
            ])
        );
        assert_eq!(status.sql_type, "TEXT");
        assert_eq!(workflow_fields[0].enum_name(), Some("PostStatus"));
    }

    #[test]
    fn parses_write_time_text_transforms_on_scalar_and_nested_fields() {
        let document = parse_document(
            r#"
enums: {
    PostStatus: ["draft", "published"]
}
resources: [
    {
        name: "Post"
        fields: [
            { name: "id", type: I64, id: true }
            { name: "slug", type: String, transforms: [Slugify] }
            { name: "status", type: PostStatus, transforms: [Trim, Lowercase] }
            {
                name: "title"
                type: Object
                fields: [
                    { name: "raw", type: String, transforms: [CollapseWhitespace] }
                ]
            }
        ]
    }
]
"#,
        );
        let enums = build_enums(document.enums).expect("enums should build");
        let resources = build_resources_with_enums(DbBackend::Sqlite, document.resources, &enums)
            .expect("resources should build");
        let resource = &resources[0];
        let slug = resource
            .find_field("slug")
            .expect("slug field should exist");
        let status = resource
            .find_field("status")
            .expect("status field should exist");
        let title = resource
            .find_field("title")
            .expect("title field should exist");
        let title_fields =
            super::super::model::object_fields(title).expect("title should define object fields");

        assert_eq!(
            slug.transforms(),
            &[super::super::model::FieldTransform::Slugify]
        );
        assert_eq!(
            status.transforms(),
            &[
                super::super::model::FieldTransform::Trim,
                super::super::model::FieldTransform::Lowercase,
            ]
        );
        assert_eq!(
            title_fields[0].transforms(),
            &[super::super::model::FieldTransform::CollapseWhitespace]
        );
    }

    #[test]
    fn rejects_write_time_transforms_on_non_text_fields() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        fields: [
            { name: "id", type: I64, id: true }
            { name: "workspace_id", type: I64, transforms: [Trim] }
        ]
    }
]
"#,
        );
        let error = build_resources(DbBackend::Sqlite, document.resources)
            .expect_err("non-text transforms should fail");

        assert!(
            error
                .to_string()
                .contains("field `workspace_id` does not support write-time transform `Trim`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_slugify_transform_on_enum_fields() {
        let document = parse_document(
            r#"
enums: {
    PostStatus: ["draft", "published"]
}
resources: [
    {
        name: "Post"
        fields: [
            { name: "id", type: I64, id: true }
            { name: "status", type: PostStatus, transforms: [Slugify] }
        ]
    }
]
"#,
        );
        let enums = build_enums(document.enums).expect("enums should build");
        let error = build_resources_with_enums(DbBackend::Sqlite, document.resources, &enums)
            .expect_err("slugify enum fields should fail");

        assert!(
            error
                .to_string()
                .contains("field `status` does not support write-time transform `Slugify`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_validation_constraints_on_enum_fields() {
        let document = parse_document(
            r#"
enums: {
    PostStatus: ["draft", "published", "archived"]
}
resources: [
    {
        name: "Post"
        fields: [
            { name: "id", type: I64, id: true }
            {
                name: "status"
                type: PostStatus
                garde: {
                    length: {
                        min: 3
                        mode: Chars
                    }
                }
            }
        ]
    }
]
"#,
        );
        let enums = build_enums(document.enums).expect("enums should build");
        let error = build_resources_with_enums(DbBackend::Sqlite, document.resources, &enums)
            .expect_err("enum field validation constraints should fail");
        assert!(
            error
                .to_string()
                .contains("enum field `status` does not support validation constraints")
        );
    }

    #[test]
    fn parses_field_unique_and_resource_indexes_from_eon() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        indexes: [
            { fields: ["workspace_id", "slug"], unique: true }
            { fields: ["status", "published_at"] }
        ]
        fields: [
            { name: "id", type: I64, id: true }
            { name: "workspace_id", type: I64 }
            { name: "slug", type: String, unique: true }
            { name: "status", type: String }
            { name: "published_at", type: DateTime, nullable: true }
        ]
    }
]
"#,
        );
        let resources =
            build_resources(DbBackend::Sqlite, document.resources).expect("resources should build");
        let resource = &resources[0];
        let slug = resource
            .find_field("slug")
            .expect("slug field should exist");

        assert!(slug.unique);
        assert_eq!(resource.indexes.len(), 2);
        assert_eq!(
            resource.indexes[0],
            IndexSpec {
                fields: vec!["workspace_id".to_owned(), "slug".to_owned()],
                unique: true,
            }
        );
        assert_eq!(
            resource.indexes[1],
            IndexSpec {
                fields: vec!["status".to_owned(), "published_at".to_owned()],
                unique: false,
            }
        );
    }

    #[test]
    fn rejects_unique_on_object_field() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        fields: [
            { name: "id", type: I64, id: true }
            {
                name: "title"
                type: Object
                unique: true
                fields: [
                    { name: "raw", type: String }
                ]
            }
        ]
    }
]
"#,
        );
        let error = build_resources(DbBackend::Sqlite, document.resources)
            .expect_err("object field unique should fail");
        assert!(
            error
                .to_string()
                .contains("field `title` on resource `Post` does not support `unique`")
        );
    }

    #[test]
    fn parses_resource_many_to_many_definitions() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        many_to_many: [
            {
                name: "tags"
                target: "Tag"
                through: "PostTag"
                source_field: "post_id"
                target_field: "tag_id"
            }
        ]
        fields: [
            { name: "id", type: I64, id: true }
            { name: "title", type: String }
        ]
    }
    {
        name: "Tag"
        fields: [
            { name: "id", type: I64, id: true }
            { name: "name", type: String }
        ]
    }
    {
        name: "PostTag"
        table: "post_tag"
        fields: [
            { name: "id", type: I64, id: true }
            { name: "post_id", type: I64, relation: { references: "post.id" } }
            { name: "tag_id", type: I64, relation: { references: "tag.id" } }
        ]
    }
]
"#,
        );
        let resources =
            build_resources(DbBackend::Sqlite, document.resources).expect("resources should build");
        let post = resources
            .iter()
            .find(|resource| resource.table_name == "post")
            .expect("post resource should exist");

        assert_eq!(post.many_to_many.len(), 1);
        assert_eq!(
            post.many_to_many[0],
            super::super::model::ManyToManySpec {
                name: "tags".to_owned(),
                target_table: "tag".to_owned(),
                through_table: "post_tag".to_owned(),
                source_field: "post_id".to_owned(),
                target_field: "tag_id".to_owned(),
            }
        );
    }

    #[test]
    fn rejects_many_to_many_with_wrong_join_relation() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        many_to_many: [
            {
                name: "tags"
                target: "Tag"
                through: "PostTag"
                source_field: "post_id"
                target_field: "tag_id"
            }
        ]
        fields: [
            { name: "id", type: I64, id: true }
            { name: "title", type: String }
        ]
    }
    {
        name: "Tag"
        fields: [
            { name: "id", type: I64, id: true }
            { name: "name", type: String }
        ]
    }
    {
        name: "PostTag"
        table: "post_tag"
        fields: [
            { name: "id", type: I64, id: true }
            { name: "post_id", type: I64, relation: { references: "tag.id" } }
            { name: "tag_id", type: I64, relation: { references: "tag.id" } }
        ]
    }
]
"#,
        );
        let error = build_resources(DbBackend::Sqlite, document.resources)
            .expect_err("many_to_many with wrong join relation should fail");
        assert!(
            error
                .to_string()
                .contains("requires through field `post_id` on `post_tag` to reference `post.id`")
        );
    }

    #[test]
    fn parses_resource_update_actions_with_normalized_values() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        actions: [
            {
                name: "publish"
                path: "go-live"
                behavior: {
                    kind: "UpdateFields"
                    set: {
                        status: " Published "
                        slug: " Launch   Post! "
                    }
                }
            }
            {
                name: "rename"
                behavior: {
                    kind: "UpdateFields"
                    set: {
                        title: { input: "newTitle" }
                        slug: { input: "newSlug" }
                        status: { input: "newStatus" }
                    }
                }
            }
            {
                name: "purge"
                behavior: {
                    kind: "DeleteResource"
                }
            }
        ]
        fields: [
            { name: "id", type: I64, id: true }
            { name: "title", type: String, garde: { length: { min: 5, mode: Chars } } }
            { name: "slug", type: String, transforms: [Slugify] }
            { name: "status", type: String, transforms: [Trim, Lowercase] }
        ]
    }
]
"#,
        );
        let resources =
            build_resources(DbBackend::Sqlite, document.resources).expect("resources should build");
        let action = resources[0]
            .actions
            .iter()
            .find(|action| action.name == "publish")
            .expect("publish action should exist");

        assert_eq!(action.path, "go-live");
        assert_eq!(action.target, ResourceActionTarget::Item);
        assert_eq!(action.method, ResourceActionMethod::Post);
        let ResourceActionBehaviorSpec::UpdateFields { assignments } = &action.behavior else {
            panic!("publish action should use UpdateFields");
        };
        assert_eq!(assignments.len(), 2);
        assert_eq!(assignments[0].field, "slug");
        assert_eq!(
            assignments[0].value,
            ResourceActionValueSpec::Literal(JsonValue::String("launch-post".to_owned()))
        );
        assert_eq!(assignments[1].field, "status");
        assert_eq!(
            assignments[1].value,
            ResourceActionValueSpec::Literal(JsonValue::String("published".to_owned()))
        );

        let rename = resources[0]
            .actions
            .iter()
            .find(|action| action.name == "rename")
            .expect("rename action should exist");
        assert_eq!(
            rename.input_fields,
            vec![
                ResourceActionInputFieldSpec {
                    name: "newSlug".to_owned(),
                    target_field: "slug".to_owned(),
                },
                ResourceActionInputFieldSpec {
                    name: "newStatus".to_owned(),
                    target_field: "status".to_owned(),
                },
                ResourceActionInputFieldSpec {
                    name: "newTitle".to_owned(),
                    target_field: "title".to_owned(),
                },
            ]
        );
        let ResourceActionBehaviorSpec::UpdateFields { assignments } = &rename.behavior else {
            panic!("rename action should use UpdateFields");
        };
        assert_eq!(assignments.len(), 3);
        assert_eq!(assignments[0].field, "slug");
        assert_eq!(
            assignments[0].value,
            ResourceActionValueSpec::InputField("newSlug".to_owned())
        );
        assert_eq!(assignments[1].field, "status");
        assert_eq!(
            assignments[1].value,
            ResourceActionValueSpec::InputField("newStatus".to_owned())
        );
        assert_eq!(assignments[2].field, "title");
        assert_eq!(
            assignments[2].value,
            ResourceActionValueSpec::InputField("newTitle".to_owned())
        );

        let purge = resources[0]
            .actions
            .iter()
            .find(|action| action.name == "purge")
            .expect("purge action should exist");
        assert!(purge.input_fields.is_empty());
        assert_eq!(purge.behavior, ResourceActionBehaviorSpec::DeleteResource);
    }

    #[test]
    fn rejects_resource_actions_on_generated_or_unknown_fields() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        actions: [
            {
                name: "publish"
                behavior: {
                    kind: "UpdateFields"
                    set: {
                        published_at: "2026-03-27T12:00:00Z"
                    }
                }
            }
        ]
        fields: [
            { name: "id", type: I64, id: true }
            { name: "published_at", type: DateTime, generated: "UpdatedAt" }
        ]
    }
]
"#,
        );
        let error = build_resources(DbBackend::Sqlite, document.resources)
            .expect_err("generated action assignment should fail");
        assert!(
            error
                .to_string()
                .contains("cannot assign generated field `published_at`")
        );
    }

    #[test]
    fn rejects_duplicate_resource_action_input_names() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        actions: [
            {
                name: "rename"
                behavior: {
                    kind: "UpdateFields"
                    set: {
                        title: { input: "value" }
                        slug: { input: "value" }
                    }
                }
            }
        ]
        fields: [
            { name: "id", type: I64, id: true }
            { name: "title", type: String }
            { name: "slug", type: String }
        ]
    }
]
"#,
        );
        let error = build_resources(DbBackend::Sqlite, document.resources)
            .expect_err("duplicate action inputs should fail");
        assert!(
            error
                .to_string()
                .contains("reuses input field `value` across multiple assignments")
        );
    }

    #[test]
    fn rejects_delete_resource_actions_with_assignments() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        actions: [
            {
                name: "purge"
                behavior: {
                    kind: "DeleteResource"
                    set: {
                        status: "deleted"
                    }
                }
            }
        ]
        fields: [
            { name: "id", type: I64, id: true }
            { name: "status", type: String }
        ]
    }
]
"#,
        );
        let error = build_resources(DbBackend::Sqlite, document.resources)
            .expect_err("delete resource action assignments should fail");
        assert!(
            error
                .to_string()
                .contains("with `DeleteResource` behavior cannot declare `behavior.set` fields")
        );
    }

    #[test]
    fn expands_local_mixins_into_resource_fields_and_indexes() {
        let document = parse_document(
            r#"
mixins: {
    Timestamps: {
        fields: {
            created_at: { type: DateTime, generated: CreatedAt }
            updated_at: { type: DateTime, generated: UpdatedAt }
        }
    }
    TenantSlug: {
        indexes: [
            { fields: ["tenant_id", "slug"], unique: true }
        ]
        fields: {
            tenant_id: I64
            slug: { type: String, unique: true }
        }
    }
}
resources: [
    {
        name: "Post"
        use: ["Timestamps", "TenantSlug"]
        fields: [
            { name: "id", type: I64, id: true }
            { name: "title", type: String }
        ]
    }
]
"#,
        );
        let mixins = build_mixins(document.mixins).expect("mixins should build");
        let expanded_resources =
            expand_resource_mixins(document.resources, &mixins).expect("resources should expand");
        let resources = build_resources_with_enums(DbBackend::Sqlite, expanded_resources, &[])
            .expect("resources should build");
        let resource = &resources[0];

        assert!(resource.find_field("tenant_id").is_some());
        assert!(resource.find_field("slug").is_some());
        assert!(resource.find_field("created_at").is_some());
        assert!(resource.find_field("updated_at").is_some());
        assert!(
            resource
                .find_field("slug")
                .expect("slug field should exist")
                .unique
        );
        assert_eq!(
            resource.indexes,
            vec![IndexSpec {
                fields: vec!["tenant_id".to_owned(), "slug".to_owned()],
                unique: true,
            }]
        );
    }

    #[test]
    fn rejects_unknown_mixin_reference() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        use: ["MissingMixin"]
        fields: [
            { name: "id", type: I64, id: true }
        ]
    }
]
"#,
        );
        let mixins = build_mixins(document.mixins).expect("mixins should build");
        let error = match expand_resource_mixins(document.resources, &mixins) {
            Ok(_) => panic!("unknown mixin should fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("references unknown mixin `MissingMixin`")
        );
    }

    #[test]
    fn rejects_mixin_index_referencing_resource_local_field() {
        let document = parse_document(
            r#"
mixins: {
    TenantSlug: {
        indexes: [
            { fields: ["tenant_id", "slug"], unique: true }
        ]
        fields: {
            slug: String
        }
    }
}
resources: [
    {
        name: "Post"
        use: ["TenantSlug"]
        fields: [
            { name: "id", type: I64, id: true }
            { name: "tenant_id", type: I64 }
        ]
    }
]
"#,
        );
        let error = match build_mixins(document.mixins) {
            Ok(_) => panic!("mixin index should be local-only"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("mixin `TenantSlug` index references unknown mixin field `tenant_id`")
        );
    }

    #[test]
    fn rejects_duplicate_field_api_names_on_single_resource() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        fields: [
            { name: "id", type: I64, id: true }
            { name: "title_text", type: String, api_name: "title" }
            { name: "headline_text", type: String, api_name: "title" }
        ]
    }
]
"#,
        );
        let error = build_resources(DbBackend::Sqlite, document.resources)
            .expect_err("duplicate field api_name should fail");
        assert!(
            error
                .to_string()
                .contains("duplicate field api_name `title`")
        );
    }

    #[test]
    fn parses_resource_api_field_projections() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        api: {
            fields: {
                id: { from: "id" }
                title: { from: "title_text" }
                author: { from: "author_id" }
            }
        }
        fields: [
            { name: "id", type: I64, id: true }
            { name: "title_text", type: String }
            { name: "author_id", type: I64 }
            { name: "internal_note", type: String, nullable: true }
        ]
    }
]
"#,
        );
        let resources =
            build_resources(DbBackend::Sqlite, document.resources).expect("resources should build");
        let resource = &resources[0];

        assert_eq!(resource.api_fields().count(), 3);
        assert_eq!(
            resource
                .field_by_api_name("title")
                .expect("title projection should exist")
                .name(),
            "title_text"
        );
        assert!(
            !resource
                .find_field("internal_note")
                .expect("hidden field should exist in storage")
                .expose_in_api()
        );
    }

    #[test]
    fn parses_resource_api_computed_fields() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        api: {
            fields: {
                id: { from: "id" }
                slug: { from: "slug" }
                summary: { from: "summary" }
                permalink: { template: "/posts/{slug}" }
                preview: { template: "{slug}:{summary}" }
            }
        }
        fields: [
            { name: "id", type: I64, id: true }
            { name: "slug", type: String }
            { name: "summary", type: String, nullable: true }
        ]
    }
]
"#,
        );
        let resources =
            build_resources(DbBackend::Sqlite, document.resources).expect("resources should build");
        let resource = &resources[0];

        assert_eq!(resource.computed_fields.len(), 2);
        assert_eq!(resource.computed_fields[0].api_name, "permalink");
        assert!(!resource.computed_fields[0].optional);
        assert_eq!(resource.computed_fields[1].api_name, "preview");
        assert!(resource.computed_fields[1].optional);
    }

    #[test]
    fn rejects_computed_api_fields_referencing_non_scalar_values() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        api: {
            fields: {
                id: { from: "id" }
                title: { from: "title" }
                permalink: { template: "{title}" }
            }
        }
        fields: [
            { name: "id", type: I64, id: true }
            {
                name: "title"
                type: Object
                fields: [
                    { name: "raw", type: String }
                ]
            }
        ]
    }
]
"#,
        );
        let error = build_resources(DbBackend::Sqlite, document.resources)
            .expect_err("computed field over object api field should fail");
        assert!(
            error
                .to_string()
                .contains("cannot interpolate non-scalar API field `title`")
        );
    }

    #[test]
    fn allows_hiding_required_storage_fields_in_api_projection() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        api: {
            fields: {
                id: { from: "id" }
                title: { from: "title_text" }
            }
        }
        fields: [
            { name: "id", type: I64, id: true }
            { name: "title_text", type: String }
            { name: "body_text", type: String }
        ]
    }
]
"#,
        );
        let resources =
            build_resources(DbBackend::Sqlite, document.resources).expect("resources should build");
        let resource = &resources[0];
        let hidden = resource
            .find_field("body_text")
            .expect("hidden storage field should remain present");
        assert!(!hidden.expose_in_api());
    }

    #[test]
    fn parses_resource_api_response_contexts() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        api: {
            fields: {
                id: { from: "id" }
                title: { from: "title_text" }
                secret: { from: "draft_body" }
            }
            default_context: "view"
            contexts: {
                view: ["id", "title"]
                edit: ["id", "title", "secret"]
            }
        }
        fields: [
            { name: "id", type: I64, id: true }
            { name: "title_text", type: String }
            { name: "draft_body", type: String, nullable: true }
        ]
    }
]
"#,
        );
        let resources =
            build_resources(DbBackend::Sqlite, document.resources).expect("resources should build");
        let resource = &resources[0];

        assert_eq!(
            resource
                .default_response_context()
                .expect("default response context should exist")
                .name,
            "view"
        );
        assert_eq!(
            resource
                .response_context("edit")
                .expect("edit context should exist")
                .fields,
            vec!["id".to_owned(), "title".to_owned(), "secret".to_owned()]
        );
    }

    #[test]
    fn applies_authenticated_read_default_and_preserves_explicit_public_access() {
        let document = parse_document(
            r#"
security: {
    access: {
        default_read: "authenticated"
    }
}
resources: [
    {
        name: "Post"
        access: {
            read: "public"
        }
        fields: [
            { name: "id", type: I64, id: true }
            { name: "title", type: String }
        ]
    }
    {
        name: "Draft"
        fields: [
            { name: "id", type: I64, id: true }
            { name: "title", type: String }
        ]
    }
]
"#,
        );
        let security = parse_security_document(document.security, Span::call_site())
            .expect("security should parse");
        let mut resources =
            build_resources(DbBackend::Sqlite, document.resources).expect("resources should build");
        apply_service_read_access_defaults(&mut resources, &security);

        assert_eq!(resources[0].access.read, ResourceReadAccess::Public);
        assert!(!super::super::model::read_requires_auth(&resources[0]));
        assert_eq!(resources[1].access.read, ResourceReadAccess::Authenticated);
        assert!(super::super::model::read_requires_auth(&resources[1]));
    }

    #[test]
    fn rejects_public_read_access_with_principal_dependent_policy() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Comment"
        access: {
            read: "public"
        }
        policies: {
            read: { field: "author_user_id", equals: "user.id" }
        }
        fields: [
            { name: "id", type: I64, id: true }
            { name: "author_user_id", type: I64 }
        ]
    }
]
"#,
        );
        let error = build_resources(DbBackend::Sqlite, document.resources)
            .expect_err("public access with user policy should fail");
        assert!(
            error
                .to_string()
                .contains("cannot use `access.read = public` with read row policies"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_unknown_api_field_in_response_context() {
        let document = parse_document(
            r#"
resources: [
    {
        name: "Post"
        api: {
            contexts: {
                view: ["id", "secret"]
            }
        }
        fields: [
            { name: "id", type: I64, id: true }
            { name: "title", type: String }
        ]
    }
]
"#,
        );
        let error = build_resources(DbBackend::Sqlite, document.resources)
            .expect_err("unknown context field should fail");
        assert!(
            error
                .to_string()
                .contains("references unknown API field `secret`")
        );
    }

    #[test]
    fn rejects_invalid_table_identifier_from_eon() {
        let error = build_resources(
            DbBackend::Sqlite,
            vec![ResourceDocument {
                name: "Post".to_owned(),
                api_name: None,
                table: Some("post; DROP TABLE user;".to_owned()),
                id_field: None,
                access: ResourceAccessDocument::default(),
                roles: RoleRequirements::default(),
                policies: RowPoliciesDocument::default(),
                list: ListConfigDocument::default(),
                api: None,
                use_mixins: Vec::new(),
                indexes: Vec::new(),
                many_to_many: Vec::new(),
                actions: Vec::new(),
                fields: vec![
                    FieldDocument {
                        name: "id".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::I64),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: true,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                    FieldDocument {
                        name: "title".to_owned(),
                        api_name: None,
                        ty: FieldTypeDocument::Scalar(ScalarType::String),
                        items: None,
                        fields: vec![],
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        unique: false,
                        transforms: Vec::new(),
                        relation: None,
                        validate: None,
                        legacy_validate: None,
                    },
                ],
            }],
        )
        .expect_err("invalid table identifier should fail");
        assert!(error.to_string().contains("table name"));
        assert!(error.to_string().contains("valid SQL identifier"));
    }

    #[test]
    fn rejects_invalid_relation_identifier_from_eon() {
        let error = parse_relation_document(RelationDocument {
            references: "post.id); DROP TABLE user;".to_owned(),
            on_delete: None,
            nested_route: false,
        })
        .expect_err("invalid relation identifier should fail");
        assert!(error.to_string().contains("relation field"));
        assert!(error.to_string().contains("valid SQL identifier"));
    }

    #[test]
    fn parses_row_policies_from_eon() {
        let path = syn::LitStr::new("test.eon", Span::call_site());
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { kind: Owner, field: "user_id" }
                        create: { kind: SetOwner, field: "user_id" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let service = LoadedService {
            service: ServiceSpec {
                module_ident: sanitize_module_ident("test", Span::call_site()),
                resources: build_resources(document.db, document.resources)
                    .expect("resources should build"),
                authorization: AuthorizationContract::default(),
                static_mounts: Vec::new(),
                storage: StorageConfig::default(),
                database: parse_database_document(
                    document.db,
                    document.database,
                    "test",
                    Span::call_site(),
                )
                .expect("database config should parse"),
                build: BuildConfig::default(),
                clients: ClientsConfig::default(),
                logging: LoggingConfig::default(),
                runtime: RuntimeConfig::default(),
                security: SecurityConfig::default(),
                tls: TlsConfig::default(),
                enums: Vec::new(),
            },
            include_path: path.value(),
        };

        let resource = &service.service.resources[0];
        let read_filters = resource
            .policies
            .iter_filters()
            .into_iter()
            .filter(|(scope, _)| *scope == "read")
            .map(|(_, filter)| filter)
            .collect::<Vec<_>>();
        assert_eq!(read_filters[0].field, "user_id");
        assert_eq!(
            resource.policies.create[0].source,
            super::super::model::PolicyValueSource::UserId
        );
    }

    #[test]
    fn parses_claim_based_row_policies_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        admin_bypass: false
                        read: [
                            "user_id=user.id"
                            { field: "tenant_id", equals: "claim.tenant_id" }
                        ]
                        create: [
                            "user_id=user.id"
                            { field: "tenant_id", value: "claim.tenant_id" }
                        ]
                        update: { field: "tenant_id", equals: "claim.tenant_id" }
                        delete: { field: "tenant_id", equals: "claim.tenant_id" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "tenant_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let resource = &resources[0];
        assert!(!resource.policies.admin_bypass);
        let read_filters = resource
            .policies
            .iter_filters()
            .into_iter()
            .filter(|(scope, _)| *scope == "read")
            .map(|(_, filter)| filter)
            .collect::<Vec<_>>();
        assert_eq!(read_filters.len(), 2);
        assert_eq!(
            read_filters[1].operator,
            super::super::model::PolicyFilterOperator::Equals(
                super::super::model::PolicyComparisonValue::Source(
                    super::super::model::PolicyValueSource::Claim("tenant_id".to_owned())
                )
            )
        );
        assert_eq!(resource.policies.create.len(), 2);
    }

    #[test]
    fn parses_literal_row_policies_from_eon() {
        let document = parse_document(
            r#"
            enums: [
                { name: "CommentStatus", values: ["Approved", "Rejected"] }
            ]
            resources: [
                {
                    name: "Comment"
                    policies: {
                        read: [
                            { field: "visibility", equals: "public" }
                            { field: "status", equals: "Approved" }
                            { field: "priority", equals: 10 }
                            { field: "featured", equals: true }
                        ]
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "visibility", type: String }
                        { name: "status", type: CommentStatus }
                        { name: "priority", type: I64 }
                        { name: "featured", type: Bool }
                    ]
                }
            ]
            "#,
        );

        let enums = build_enums(document.enums).expect("enums should build");
        let resources = build_resources_with_enums(document.db, document.resources, &enums)
            .expect("resources should build");
        let resource = &resources[0];
        let read_filters = resource
            .policies
            .iter_filters()
            .into_iter()
            .filter(|(scope, _)| *scope == "read")
            .map(|(_, filter)| filter)
            .collect::<Vec<_>>();

        assert_eq!(
            read_filters[0].operator,
            super::super::model::PolicyFilterOperator::Equals(
                super::super::model::PolicyComparisonValue::Literal(
                    super::super::model::PolicyLiteralValue::String("public".to_owned())
                )
            )
        );
        assert_eq!(
            read_filters[1].operator,
            super::super::model::PolicyFilterOperator::Equals(
                super::super::model::PolicyComparisonValue::Literal(
                    super::super::model::PolicyLiteralValue::String("Approved".to_owned())
                )
            )
        );
        assert_eq!(
            read_filters[2].operator,
            super::super::model::PolicyFilterOperator::Equals(
                super::super::model::PolicyComparisonValue::Literal(
                    super::super::model::PolicyLiteralValue::I64(10)
                )
            )
        );
        assert_eq!(
            read_filters[3].operator,
            super::super::model::PolicyFilterOperator::Equals(
                super::super::model::PolicyComparisonValue::Literal(
                    super::super::model::PolicyLiteralValue::Bool(true)
                )
            )
        );
    }

    #[test]
    fn rejects_unknown_enum_literal_in_row_policy_from_eon() {
        let document = parse_document(
            r#"
            enums: [
                { name: "CommentStatus", values: ["Approved", "Rejected"] }
            ]
            resources: [
                {
                    name: "Comment"
                    policies: {
                        read: { field: "status", equals: "Pending" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "status", type: CommentStatus }
                    ]
                }
            ]
            "#,
        );

        let enums = build_enums(document.enums).expect("enums should build");
        let error = build_resources_with_enums(document.db, document.resources, &enums)
            .expect_err("unknown enum literal should fail");
        assert!(
            error
                .to_string()
                .contains("must use one of declared enum values [Approved, Rejected]")
        );
    }

    #[test]
    fn parses_null_check_row_policies_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Note"
                    policies: {
                        read: { field: "archived_at", is_null: true }
                        delete: { field: "archived_at", is_not_null: true }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "title", type: String }
                        { name: "archived_at", type: String, nullable: true }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let resource = &resources[0];
        let read = resource
            .policies
            .read
            .as_ref()
            .expect("read policy should exist");
        let delete = resource
            .policies
            .delete
            .as_ref()
            .expect("delete policy should exist");

        match read {
            PolicyFilterExpression::Match(filter) => assert_eq!(
                filter.operator,
                super::super::model::PolicyFilterOperator::IsNull
            ),
            other => panic!("expected read null-check filter, got {other:?}"),
        }
        match delete {
            PolicyFilterExpression::Match(filter) => assert_eq!(
                filter.operator,
                super::super::model::PolicyFilterOperator::IsNotNull
            ),
            other => panic!("expected delete null-check filter, got {other:?}"),
        }
    }

    #[test]
    fn rejects_null_check_row_policies_for_non_nullable_fields() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Note"
                    policies: {
                        read: { field: "title", is_null: true }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let error = build_resources(document.db, document.resources)
            .expect_err("null checks on non-nullable fields should fail");
        assert!(
            error
                .to_string()
                .contains("null checks require nullable/optional field")
        );
    }

    #[test]
    fn parses_nested_boolean_row_policies_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: {
                            any_of: [
                                "owner_id=user.id"
                                {
                                    all_of: [
                                        "tenant_id=claim.tenant_id"
                                        { not: "blocked_user_id=user.id" }
                                    ]
                                }
                            ]
                        }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "owner_id", type: I64 }
                        { name: "tenant_id", type: I64 }
                        { name: "blocked_user_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let resource = &resources[0];
        let read = resource
            .policies
            .read
            .as_ref()
            .expect("read policy should be present");
        assert!(matches!(read, PolicyFilterExpression::Any(_)));

        let read_filters = resource
            .policies
            .iter_filters()
            .into_iter()
            .filter(|(scope, _)| *scope == "read")
            .map(|(_, filter)| filter)
            .collect::<Vec<_>>();
        assert_eq!(read_filters.len(), 3);
        assert_eq!(read_filters[2].field, "blocked_user_id");
    }

    #[test]
    fn parses_exists_row_policies_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "FamilyMember"
                    fields: [
                        { name: "id", type: I64 }
                        { name: "family_id", type: I64 }
                        { name: "user_id", type: I64 }
                    ]
                }
                {
                    name: "SharedDoc"
                    policies: {
                        read: {
                            exists: {
                                resource: "FamilyMember"
                                where: [
                                    { field: "family_id", equals_field: "family_id" }
                                    "user_id=user.id"
                                ]
                            }
                        }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "family_id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let resource = resources
            .iter()
            .find(|resource| resource.struct_ident == "SharedDoc")
            .expect("shared doc resource should exist");
        let read = resource
            .policies
            .read
            .as_ref()
            .expect("read policy should be present");
        match read {
            PolicyFilterExpression::Exists(filter) => {
                assert_eq!(filter.resource, "FamilyMember");
                match &filter.condition {
                    super::super::model::PolicyExistsCondition::All(conditions) => {
                        assert_eq!(conditions.len(), 2);
                        assert!(matches!(
                            conditions[0],
                            super::super::model::PolicyExistsCondition::CurrentRowField { .. }
                        ));
                        assert!(matches!(
                            conditions[1],
                            super::super::model::PolicyExistsCondition::Match(_)
                        ));
                    }
                    other => panic!("expected implicit exists all_of group, got {other:?}"),
                }
            }
            other => panic!("expected exists filter, got {other:?}"),
        }
    }

    #[test]
    fn parses_create_require_policies_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Family"
                    fields: [
                        { name: "id", type: I64 }
                        { name: "owner_user_id", type: I64 }
                    ]
                }
                {
                    name: "FamilyMember"
                    policies: {
                        create: {
                            assign: [
                                "created_by_user_id=user.id"
                            ]
                            require: {
                                exists: {
                                    resource: "Family"
                                    where: [
                                        { field: "id", equals: "input.family_id" }
                                        "owner_user_id=user.id"
                                    ]
                                }
                            }
                        }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "family_id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "created_by_user_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let resource = resources
            .iter()
            .find(|resource| resource.struct_ident == "FamilyMember")
            .expect("family member resource should exist");

        assert_eq!(resource.policies.create.len(), 1);
        let create_require = resource
            .policies
            .create_require
            .as_ref()
            .expect("create.require should be present");
        match create_require {
            PolicyFilterExpression::Exists(filter) => match &filter.condition {
                super::super::model::PolicyExistsCondition::All(conditions) => {
                    assert_eq!(conditions.len(), 2);
                    match &conditions[0] {
                        super::super::model::PolicyExistsCondition::Match(filter) => {
                            assert_eq!(filter.field, "id");
                            assert_eq!(
                                filter.operator,
                                super::super::model::PolicyFilterOperator::Equals(
                                    super::super::model::PolicyComparisonValue::Source(
                                        PolicyValueSource::InputField("family_id".to_owned())
                                    )
                                )
                            );
                        }
                        other => panic!("expected input match inside exists, got {other:?}"),
                    }
                }
                other => panic!("expected implicit exists all_of group, got {other:?}"),
            },
            other => panic!("expected exists create.require filter, got {other:?}"),
        }
    }

    #[test]
    fn rejects_input_sources_outside_create_require() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { field: "tenant_id", equals: "input.tenant_id" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "tenant_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let error = build_resources(document.db, document.resources)
            .expect_err("input sources outside create.require should fail");
        assert!(
            error
                .to_string()
                .contains("read row policy field `tenant_id` cannot use `input.tenant_id`")
        );
    }

    #[test]
    fn parses_nested_boolean_groups_inside_exists_policies() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "FamilyAccess"
                    fields: [
                        { name: "id", type: I64 }
                        { name: "family_id", type: I64 }
                        { name: "primary_user_id", type: I64 }
                        { name: "delegate_user_id", type: I64 }
                    ]
                }
                {
                    name: "SharedDoc"
                    policies: {
                        read: {
                            exists: {
                                resource: "FamilyAccess"
                                where: [
                                    { field: "family_id", equals_field: "family_id" }
                                    {
                                        any_of: [
                                            "primary_user_id=user.id"
                                            "delegate_user_id=user.id"
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "family_id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let resource = resources
            .iter()
            .find(|resource| resource.struct_ident == "SharedDoc")
            .expect("shared doc resource should exist");
        let read = resource
            .policies
            .read
            .as_ref()
            .expect("read policy should be present");
        match read {
            PolicyFilterExpression::Exists(filter) => match &filter.condition {
                super::super::model::PolicyExistsCondition::All(conditions) => {
                    assert_eq!(conditions.len(), 2);
                    assert!(matches!(
                        conditions[0],
                        super::super::model::PolicyExistsCondition::CurrentRowField { .. }
                    ));
                    match &conditions[1] {
                        super::super::model::PolicyExistsCondition::Any(inner) => {
                            assert_eq!(inner.len(), 2);
                            assert!(matches!(
                                inner[0],
                                super::super::model::PolicyExistsCondition::Match(_)
                            ));
                            assert!(matches!(
                                inner[1],
                                super::super::model::PolicyExistsCondition::Match(_)
                            ));
                        }
                        other => panic!("expected any_of group inside exists, got {other:?}"),
                    }
                }
                other => panic!("expected implicit exists all_of group, got {other:?}"),
            },
            other => panic!("expected exists filter, got {other:?}"),
        }
    }

    #[test]
    fn rejects_exists_row_policies_for_unknown_resource() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "SharedDoc"
                    policies: {
                        read: {
                            exists: {
                                resource: "FamilyMember"
                                where: [
                                    { field: "family_id", equals_field: "family_id" }
                                    "user_id=user.id"
                                ]
                            }
                        }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "family_id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let error = build_resources(document.db, document.resources)
            .expect_err("unknown exists resource should fail");
        assert!(
            error
                .to_string()
                .contains("unknown exists resource `FamilyMember`")
        );
    }

    #[test]
    fn parses_security_config_from_eon() {
        let document = parse_document(
            r#"
            logging: {
                filter_env: "APP_LOG"
                default_filter: "debug,sqlx=warn"
                timestamp: Millis
            }
            security: {
                requests: { json_max_bytes: 128 }
                cors: {
                    origins: ["http://localhost:3000"]
                    origins_env: "CORS_ORIGINS"
                    allow_credentials: true
                    allow_methods: ["GET", "POST", "OPTIONS"]
                        allow_headers: ["authorization", "content-type", "x-csrf-token"]
                    expose_headers: ["x-total-count"]
                    max_age_seconds: 600
                }
                trusted_proxies: {
                    proxies: ["127.0.0.1", "::1"]
                    proxies_env: "TRUSTED_PROXIES"
                }
                rate_limits: {
                    login: { requests: 2, window_seconds: 60 }
                    register: { requests: 3, window_seconds: 120 }
                }
                headers: {
                    frame_options: Deny
                    content_type_options: true
                    referrer_policy: StrictOriginWhenCrossOrigin
                    hsts: {
                        max_age_seconds: 3600
                        include_subdomains: true
                    }
                }
                auth: {
                    issuer: "issuer"
                    audience: "audience"
                    access_token_ttl_seconds: 600
                    claims: {
                        tenant_id: I64
                        workspace_id: "claim_workspace_id"
                        staff: { column: "is_staff", type: Bool }
                        plan: String
                    }
                    session_cookie: {
                        secure: false
                        same_site: Lax
                        csrf_header_name: "x-session-csrf"
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let logging = parse_logging_document(document.logging).expect("logging ok");
        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");

        assert_eq!(logging.filter_env, "APP_LOG");
        assert_eq!(logging.default_filter, "debug,sqlx=warn");
        assert_eq!(logging.timestamp, LogTimestampPrecision::Millis);
        assert_eq!(security.requests.json_max_bytes, Some(128));
        assert_eq!(
            security.cors.origins,
            vec!["http://localhost:3000".to_owned()]
        );
        assert_eq!(security.cors.origins_env.as_deref(), Some("CORS_ORIGINS"));
        assert!(security.cors.allow_credentials);
        assert_eq!(
            security.cors.allow_methods,
            vec!["GET".to_owned(), "POST".to_owned(), "OPTIONS".to_owned()]
        );
        assert_eq!(
            security.cors.allow_headers,
            vec![
                "authorization".to_owned(),
                "content-type".to_owned(),
                "x-csrf-token".to_owned()
            ]
        );
        assert_eq!(
            security.cors.expose_headers,
            vec!["x-total-count".to_owned()]
        );
        assert_eq!(security.cors.max_age_seconds, Some(600));
        assert_eq!(
            security.trusted_proxies.proxies,
            vec!["127.0.0.1".to_owned(), "::1".to_owned()]
        );
        assert_eq!(
            security.trusted_proxies.proxies_env.as_deref(),
            Some("TRUSTED_PROXIES")
        );
        assert_eq!(
            security.rate_limits.login,
            Some(RateLimitRule {
                requests: 2,
                window_seconds: 60,
            })
        );
        assert_eq!(
            security.rate_limits.register,
            Some(RateLimitRule {
                requests: 3,
                window_seconds: 120,
            })
        );
        assert_eq!(security.auth.issuer.as_deref(), Some("issuer"));
        assert_eq!(security.auth.audience.as_deref(), Some("audience"));
        assert_eq!(security.auth.access_token_ttl_seconds, 600);
        assert_eq!(
            security.auth.claims.get("tenant_id"),
            Some(&AuthClaimMapping {
                column: "tenant_id".to_owned(),
                ty: AuthClaimType::I64,
            })
        );
        assert_eq!(
            security.auth.claims.get("workspace_id"),
            Some(&AuthClaimMapping {
                column: "claim_workspace_id".to_owned(),
                ty: AuthClaimType::I64,
            })
        );
        assert_eq!(
            security.auth.claims.get("staff"),
            Some(&AuthClaimMapping {
                column: "is_staff".to_owned(),
                ty: AuthClaimType::Bool,
            })
        );
        assert_eq!(
            security.auth.claims.get("plan"),
            Some(&AuthClaimMapping {
                column: "plan".to_owned(),
                ty: AuthClaimType::String,
            })
        );
        let session_cookie = security
            .auth
            .session_cookie
            .expect("session cookie settings should parse");
        assert!(!session_cookie.secure);
        assert_eq!(session_cookie.same_site, SessionCookieSameSite::Lax);
        assert_eq!(session_cookie.csrf_header_name, "x-session-csrf");
        assert_eq!(security.headers.frame_options, Some(FrameOptions::Deny));
        assert_eq!(
            security.headers.referrer_policy,
            Some(ReferrerPolicy::StrictOriginWhenCrossOrigin)
        );
        assert!(security.headers.content_type_options);
        assert_eq!(
            security.headers.hsts,
            Some(Hsts {
                max_age_seconds: 3600,
                include_subdomains: true,
            })
        );
    }

    #[test]
    fn parses_typed_auth_secret_refs_from_eon() {
        let document = parse_document(
            r#"
            security: {
                auth: {
                    jwt_secret: { systemd_credential: "jwt_signing_key" }
                    email: {
                        from_email: "noreply@example.com"
                        provider: {
                            kind: Resend
                            api_key: {
                                external: {
                                    provider: "infisical"
                                    locator: "prod/resend_api_key"
                                }
                            }
                        }
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");

        assert_eq!(
            security.auth.jwt_secret,
            Some(SecretRef::SystemdCredential {
                id: "jwt_signing_key".to_owned(),
            })
        );
        assert_eq!(
            security.auth.email.map(|email| email.provider),
            Some(AuthEmailProvider::Resend {
                api_key: SecretRef::External {
                    provider: "infisical".to_owned(),
                    locator: "prod/resend_api_key".to_owned(),
                },
                api_base_url: None,
            })
        );
    }

    #[test]
    fn parses_structured_auth_jwt_from_eon() {
        let document = parse_document(
            r#"
            security: {
                auth: {
                    jwt: {
                        algorithm: EdDSA
                        active_kid: "current"
                        signing_key: { systemd_credential: "jwt_signing_key" }
                        verification_keys: [
                            {
                                kid: "current"
                                key: {
                                    external: {
                                        provider: "infisical"
                                        locator: "prod/jwt_public_key"
                                    }
                                }
                            }
                        ]
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");

        assert_eq!(security.auth.jwt_secret, None);
        assert_eq!(
            security.auth.jwt,
            Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: Some("current".to_owned()),
                signing_key: SecretRef::SystemdCredential {
                    id: "jwt_signing_key".to_owned(),
                },
                verification_keys: vec![AuthJwtVerificationKey {
                    kid: "current".to_owned(),
                    key: SecretRef::External {
                        provider: "infisical".to_owned(),
                        locator: "prod/jwt_public_key".to_owned(),
                    },
                }],
            })
        );
    }

    #[test]
    fn parses_runtime_config_from_eon() {
        let document = parse_document(
            r#"
            runtime: {
                compression: {
                    enabled: true
                    static_precompressed: true
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let runtime = parse_runtime_document(document.runtime);
        assert!(runtime.compression.enabled);
        assert!(runtime.compression.static_precompressed);
    }

    #[test]
    fn parses_build_config_from_eon() {
        let document = parse_document(
            r#"
            build: {
                target_cpu_native: true
                artifacts: {
                    binary: {
                        path: "dist/api"
                        env: "CMS_BINARY_PATH"
                    }
                    bundle: {
                        path: "dist/api.bundle"
                        env: "CMS_BUNDLE_PATH"
                    }
                    cache: {
                        root: ".vsr-build"
                        env: "CMS_BUILD_CACHE_DIR"
                        cleanup: RemoveOnSuccess
                    }
                }
                release: {
                    lto: Thin
                    codegen_units: 1
                    strip_debug_symbols: true
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let build = parse_build_document(document.build).expect("build config should parse");
        assert!(build.target_cpu_native);
        assert_eq!(build.release.lto, Some(BuildLtoMode::Thin));
        assert_eq!(build.release.codegen_units, Some(1));
        assert!(build.release.strip_debug_symbols);
        assert_eq!(build.artifacts.binary.path.as_deref(), Some("dist/api"));
        assert_eq!(
            build.artifacts.binary.env.as_deref(),
            Some("CMS_BINARY_PATH")
        );
        assert_eq!(
            build.artifacts.bundle.path.as_deref(),
            Some("dist/api.bundle")
        );
        assert_eq!(
            build.artifacts.bundle.env.as_deref(),
            Some("CMS_BUNDLE_PATH")
        );
        assert_eq!(build.artifacts.cache.root.as_deref(), Some(".vsr-build"));
        assert_eq!(
            build.artifacts.cache.env.as_deref(),
            Some("CMS_BUILD_CACHE_DIR")
        );
        assert_eq!(
            build.artifacts.cache.cleanup,
            BuildCacheCleanupStrategy::RemoveOnSuccess
        );
    }

    #[test]
    fn rejects_zero_codegen_units_in_build_config() {
        let document = parse_document(
            r#"
            build: {
                release: {
                    codegen_units: 0
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );
        let build = parse_build_document(document.build).expect("build config should parse");
        let error = validate_build_config(&build, Span::call_site())
            .expect_err("zero codegen units should be rejected");

        assert!(
            error
                .to_string()
                .contains("`build.release.codegen_units` must be greater than zero")
        );
    }

    #[test]
    fn rejects_empty_build_artifact_env_names() {
        let document = parse_document(
            r#"
            build: {
                artifacts: {
                    binary: {
                        env: ""
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );
        let build = parse_build_document(document.build).expect("build config should parse");
        let error = validate_build_config(&build, Span::call_site())
            .expect_err("empty build artifact env should be rejected");

        assert!(
            error
                .to_string()
                .contains("`build.artifacts.binary.env` cannot be empty")
        );
    }

    #[test]
    fn parses_clients_config_from_eon() {
        let document = parse_document(
            r#"
            clients: {
                ts: {
                    output_dir: {
                        path: "web/src/gen/client"
                        env: "CMS_TS_CLIENT_OUT"
                    }
                    package_name: {
                        value: "@cms/api-client"
                        env: "CMS_TS_CLIENT_PACKAGE"
                    }
                    server_url: "/edge-api"
                    emit_js: true
                    include_builtin_auth: false
                    exclude_tables: ["audit_log", "internal_note"]
                    automation: {
                        on_build: true
                        self_test: true
                        self_test_report: {
                            path: "reports/client-self-test.json"
                            env: "CMS_TS_CLIENT_SELF_TEST_REPORT"
                        }
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let clients = parse_clients_document(document.clients);
        assert_eq!(
            clients.ts.output_dir.path.as_deref(),
            Some("web/src/gen/client")
        );
        assert_eq!(
            clients.ts.output_dir.env.as_deref(),
            Some("CMS_TS_CLIENT_OUT")
        );
        assert_eq!(
            clients.ts.package_name.value.as_deref(),
            Some("@cms/api-client")
        );
        assert_eq!(
            clients.ts.package_name.env.as_deref(),
            Some("CMS_TS_CLIENT_PACKAGE")
        );
        assert_eq!(clients.ts.server_url.as_deref(), Some("/edge-api"));
        assert!(clients.ts.emit_js);
        assert!(!clients.ts.include_builtin_auth);
        assert_eq!(
            clients.ts.exclude_tables,
            vec!["audit_log".to_owned(), "internal_note".to_owned()]
        );
        assert!(clients.ts.automation.on_build);
        assert!(clients.ts.automation.self_test);
        assert_eq!(
            clients.ts.automation.self_test_report.path.as_deref(),
            Some("reports/client-self-test.json")
        );
        assert_eq!(
            clients.ts.automation.self_test_report.env.as_deref(),
            Some("CMS_TS_CLIENT_SELF_TEST_REPORT")
        );
    }

    #[test]
    fn rejects_empty_client_config_values() {
        let document = parse_document(
            r#"
            clients: {
                ts: {
                    package_name: {
                        env: ""
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );
        let clients = parse_clients_document(document.clients);
        let error = validate_clients_config(&clients, Span::call_site())
            .expect_err("empty client env should be rejected");

        assert!(
            error
                .to_string()
                .contains("`clients.ts.package_name.env` cannot be empty")
        );
    }

    #[test]
    fn rejects_empty_client_exclude_table_names() {
        let document = parse_document(
            r#"
            clients: {
                ts: {
                    exclude_tables: ["audit_log", ""]
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );
        let clients = parse_clients_document(document.clients);
        let error = validate_clients_config(&clients, Span::call_site())
            .expect_err("empty exclude table names should be rejected");

        assert!(
            error
                .to_string()
                .contains("`clients.ts.exclude_tables` cannot contain empty table names")
        );
    }

    #[test]
    fn parses_authorization_contract_from_eon() {
        let document = parse_document(
            r#"
            authorization: {
                scopes: {
                    Family: {
                        description: "Family scope"
                    }
                    Household: {
                        parent: "Family"
                    }
                }
                permissions: {
                    FamilyRead: {
                        actions: ["Read"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                }
                templates: {
                    FamilyMember: {
                        permissions: ["FamilyRead"]
                        scopes: ["Family"]
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        validate_authorization_contract(&authorization, &resources, Span::call_site())
            .expect("authorization contract should validate");

        assert!(!authorization.management_api.enabled);
        assert_eq!(
            authorization.management_api.mount,
            DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT
        );
        assert_eq!(authorization.scopes.len(), 2);
        assert_eq!(authorization.scopes[1].name, "Household");
        assert_eq!(authorization.scopes[1].parent.as_deref(), Some("Family"));
        assert_eq!(
            authorization.permissions[0].actions,
            vec![AuthorizationAction::Read]
        );
        assert_eq!(
            authorization.templates[0].permissions,
            vec!["FamilyRead".to_owned()]
        );
    }

    #[test]
    fn rejects_authorization_permission_for_unknown_resource() {
        let document = parse_document(
            r#"
            authorization: {
                permissions: {
                    FamilyRead: {
                        actions: ["Read"]
                        resources: ["MissingResource"]
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let error = validate_authorization_contract(&authorization, &resources, Span::call_site())
            .expect_err("unknown authorization resource should fail");
        assert!(error.to_string().contains("MissingResource"));
        assert!(
            error
                .to_string()
                .contains("authorization.permissions.FamilyRead")
        );
    }

    #[test]
    fn parses_authorization_management_api_from_eon() {
        let document = parse_document(
            r#"
            authorization: {
                management_api: {
                    mount: "/ops/authz/"
                }
                scopes: {
                    Family: {}
                }
                permissions: {
                    FamilyRead: {
                        actions: ["Read"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        assert!(authorization.management_api.enabled);
        assert_eq!(authorization.management_api.mount, "/ops/authz");
    }

    #[test]
    fn parses_authorization_hybrid_enforcement_from_eon() {
        let document = parse_document(
            r#"
            authorization: {
                scopes: {
                    Family: {}
                }
                permissions: {
                    FamilyRead: {
                        actions: ["Read"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                }
                hybrid_enforcement: {
                    resources: {
                        ScopedDoc: {
                            scope: "Family"
                            scope_field: "family_id"
                            actions: ["Read"]
                        }
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    roles: {
                        read: "member"
                    }
                    policies: {
                        read: "user_id=user.id"
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "family_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        validate_authorization_contract(&authorization, &resources, Span::call_site())
            .expect("authorization contract should validate");

        assert_eq!(authorization.hybrid_enforcement.resources.len(), 1);
        assert_eq!(
            authorization.hybrid_enforcement.resources[0].resource,
            "ScopedDoc"
        );
        assert_eq!(
            authorization.hybrid_enforcement.resources[0].scope,
            "Family"
        );
        assert_eq!(
            authorization.hybrid_enforcement.resources[0].scope_field,
            "family_id"
        );
        assert!(
            authorization.hybrid_enforcement.resources[0]
                .scope_sources
                .item
        );
        assert!(
            authorization.hybrid_enforcement.resources[0]
                .scope_sources
                .collection_filter
        );
        assert!(
            authorization.hybrid_enforcement.resources[0]
                .scope_sources
                .nested_parent
        );
        assert!(
            !authorization.hybrid_enforcement.resources[0]
                .scope_sources
                .create_payload
        );
        assert_eq!(
            authorization.hybrid_enforcement.resources[0].actions,
            vec![AuthorizationAction::Read]
        );
    }

    #[test]
    fn parses_explicit_authorization_hybrid_scope_sources_from_eon() {
        let document = parse_document(
            r#"
            authorization: {
                scopes: {
                    Family: {}
                }
                permissions: {
                    FamilyRead: {
                        actions: ["Read"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                    FamilyCreate: {
                        actions: ["Create"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                }
                hybrid_enforcement: {
                    resources: {
                        ScopedDoc: {
                            scope: "Family"
                            scope_field: "family_id"
                            scope_sources: {
                                item: false
                                collection_filter: true
                                nested_parent: false
                                create_payload: true
                            }
                            actions: ["Create", "Read"]
                        }
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    roles: {
                        read: "member"
                        create: "member"
                    }
                    policies: {
                        read: "user_id=user.id"
                        create: [
                            "user_id=user.id"
                            { field: "family_id", value: "claim.family_id" }
                        ]
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "family_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        validate_authorization_contract(&authorization, &resources, Span::call_site())
            .expect("authorization contract should validate");

        let resource = &authorization.hybrid_enforcement.resources[0];
        assert!(!resource.scope_sources.item);
        assert!(resource.scope_sources.collection_filter);
        assert!(!resource.scope_sources.nested_parent);
        assert!(resource.scope_sources.create_payload);
    }

    #[test]
    fn rejects_authorization_hybrid_enforcement_create_without_claim_controlled_scope_field() {
        let document = parse_document(
            r#"
            authorization: {
                scopes: {
                    Family: {}
                }
                permissions: {
                    FamilyCreate: {
                        actions: ["Create"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                }
                hybrid_enforcement: {
                    resources: {
                        ScopedDoc: {
                            scope: "Family"
                            scope_field: "family_id"
                            actions: ["Create"]
                        }
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    policies: {
                        create: "user_id=user.id"
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "family_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let error = validate_authorization_contract(&authorization, &resources, Span::call_site())
            .expect_err("hybrid create without claim-controlled scope field should fail");
        assert!(
            error
                .to_string()
                .contains("requires `family_id` to be assigned by a static create policy")
        );
    }

    #[test]
    fn accepts_authorization_hybrid_enforcement_create_for_claim_controlled_scope_field() {
        let document = parse_document(
            r#"
            authorization: {
                scopes: {
                    Family: {}
                }
                permissions: {
                    FamilyCreate: {
                        actions: ["Create"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                }
                hybrid_enforcement: {
                    resources: {
                        ScopedDoc: {
                            scope: "Family"
                            scope_field: "family_id"
                            actions: ["Create"]
                        }
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    policies: {
                        create: [
                            "user_id=user.id"
                            { field: "family_id", value: "claim.family_id" }
                        ]
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "family_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        validate_authorization_contract(&authorization, &resources, Span::call_site())
            .expect("hybrid create with claim-controlled scope field should validate");
    }

    #[test]
    fn rejects_authorization_management_api_mount_without_leading_slash() {
        let document = parse_document(
            r#"
            authorization: {
                management_api: {
                    mount: "authz/runtime"
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let error = parse_authorization_document(document.authorization)
            .expect_err("invalid management api mount should fail");
        assert!(error.to_string().contains("must start with `/`"));
    }

    #[test]
    fn rejects_undeclared_non_legacy_policy_claim_when_explicit_auth_claims_are_present() {
        let document = parse_document(
            r#"
            security: {
                auth: {
                    claims: {
                        tenant_id: I64
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { field: "tenant_id", equals: "claim.tenant" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "tenant_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let error = validate_policy_claim_sources(&resources, &security, Span::call_site())
            .expect_err("undeclared claim should fail");
        assert!(error.to_string().contains("undeclared `claim.tenant`"));
        assert!(error.to_string().contains("security.auth.claims.tenant"));
    }

    #[test]
    fn accepts_typed_explicit_claims_in_row_policies() {
        let document = parse_document(
            r#"
            security: {
                auth: {
                    claims: {
                        tenant_slug: String
                        staff: Bool
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { field: "tenant_id", equals: "claim.tenant_slug" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "tenant_id", type: String }
                    ]
                }
                {
                    name: "FlaggedPost"
                    policies: {
                        read: { field: "staff_only", equals: "claim.staff" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "staff_only", type: Bool }
                    ]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        validate_policy_claim_sources(&resources, &security, Span::call_site())
            .expect("typed mapped claims should validate");
    }

    #[test]
    fn rejects_mismatched_explicit_claim_type_in_row_policy() {
        let document = parse_document(
            r#"
            security: {
                auth: {
                    claims: {
                        tenant_slug: String
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { field: "tenant_id", equals: "claim.tenant_slug" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "tenant_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let error = validate_policy_claim_sources(&resources, &security, Span::call_site())
            .expect_err("mismatched mapped claim should fail");
        assert!(error.to_string().contains("tenant_slug"));
        assert!(error.to_string().contains("expects `I64`"));
    }

    #[test]
    fn runtime_config_defaults_to_disabled_compression() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let runtime = parse_runtime_document(document.runtime);
        assert!(!runtime.compression.enabled);
        assert!(!runtime.compression.static_precompressed);
    }

    #[test]
    fn parses_tls_config_from_eon() {
        let document = parse_document(
            r#"
            tls: {
                cert_path: "certs/local-cert.pem"
                key_path: "certs/local-key.pem"
                cert_path_env: "APP_TLS_CERT_PATH"
                key_path_env: "APP_TLS_KEY_PATH"
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let tls = parse_tls_document(document.tls).expect("tls config should parse");
        assert_eq!(tls.cert_path.as_deref(), Some("certs/local-cert.pem"));
        assert_eq!(tls.key_path.as_deref(), Some("certs/local-key.pem"));
        assert_eq!(tls.cert_path_env.as_deref(), Some("APP_TLS_CERT_PATH"));
        assert_eq!(tls.key_path_env.as_deref(), Some("APP_TLS_KEY_PATH"));
    }

    #[test]
    fn tls_block_defaults_to_dev_cert_paths_and_env_names() {
        let document = parse_document(
            r#"
            tls: {}
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let tls = parse_tls_document(document.tls).expect("tls config should parse");
        assert_eq!(tls.cert_path.as_deref(), Some(DEFAULT_TLS_CERT_PATH));
        assert_eq!(tls.key_path.as_deref(), Some(DEFAULT_TLS_KEY_PATH));
        assert_eq!(
            tls.cert_path_env.as_deref(),
            Some(DEFAULT_TLS_CERT_PATH_ENV)
        );
        assert_eq!(tls.key_path_env.as_deref(), Some(DEFAULT_TLS_KEY_PATH_ENV));
    }

    #[test]
    fn rejects_unknown_security_header_values() {
        let document = parse_document(
            r#"
            security: {
                headers: { frame_options: "maybe" }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let error = parse_security_document(document.security, Span::call_site())
            .expect_err("unknown frame_options should fail");
        assert!(error.to_string().contains("security.headers.frame_options"));
    }

    #[test]
    fn rejects_invalid_cors_method_values() {
        let document = parse_document(
            r#"
            security: {
                cors: { allow_methods: ["NOT A METHOD"] }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");
        let error = validate_security_config(&security, Span::call_site())
            .expect_err("invalid cors method should fail validation");
        assert!(error.to_string().contains("security.cors.allow_methods"));
    }

    #[test]
    fn rejects_invalid_trusted_proxy_values() {
        let document = parse_document(
            r#"
            security: {
                trusted_proxies: { proxies: ["not-an-ip"] }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");
        let error = validate_security_config(&security, Span::call_site())
            .expect_err("invalid trusted proxy should fail validation");
        assert!(
            error
                .to_string()
                .contains("security.trusted_proxies.proxies")
        );
    }

    #[test]
    fn rejects_zero_rate_limit_values() {
        let document = parse_document(
            r#"
            security: {
                rate_limits: {
                    login: { requests: 0, window_seconds: 60 }
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");
        let error = validate_security_config(&security, Span::call_site())
            .expect_err("zero rate limit should fail validation");
        assert!(
            error
                .to_string()
                .contains("security.rate_limits.login.requests")
        );
    }

    #[test]
    fn parses_relation_on_delete_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Comment"
                    fields: [
                        { name: "id", type: I64 }
                        {
                            name: "post_id"
                            type: I64
                            relation: {
                                references: "post.id"
                                nested_route: true
                                on_delete: Cascade
                            }
                        }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let relation = resources[0]
            .find_field("post_id")
            .and_then(|field| field.relation.as_ref())
            .expect("relation should exist");
        assert_eq!(
            relation.on_delete,
            Some(super::super::model::ReferentialAction::Cascade)
        );
    }

    #[test]
    fn parses_field_validation_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                        {
                            name: "title"
                            type: String
                            garde: {
                                length: {
                                    min: 3
                                    max: 32
                                    mode: Chars
                                }
                            }
                        }
                        {
                            name: "score"
                            type: I64
                            garde: {
                                range: {
                                    min: 1
                                    max: 10
                                }
                            }
                        }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let title = resources[0]
            .find_field("title")
            .expect("title should exist");
        assert_eq!(
            title
                .validation
                .length
                .as_ref()
                .and_then(|length| length.min),
            Some(3)
        );
        assert_eq!(
            title
                .validation
                .length
                .as_ref()
                .and_then(|length| length.max),
            Some(32)
        );

        let score = resources[0]
            .find_field("score")
            .expect("score should exist");
        assert_eq!(
            score
                .validation
                .range
                .as_ref()
                .and_then(|range| range.min.clone()),
            Some(super::super::model::NumericBound::Integer(1))
        );
        assert_eq!(
            score
                .validation
                .range
                .as_ref()
                .and_then(|range| range.max.clone()),
            Some(super::super::model::NumericBound::Integer(10))
        );
    }

    #[test]
    fn parses_list_config_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    list: {
                        default_limit: 25
                        max_limit: 100
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        assert_eq!(resources[0].list.default_limit, Some(25));
        assert_eq!(resources[0].list.max_limit, Some(100));
    }

    #[test]
    fn parses_resource_and_field_maps_from_eon() {
        let document = parse_document(
            r#"
            resources: {
                Post: {
                    list: {
                        default_limit: 25
                        max_limit: 100
                    }
                    fields: {
                        id: I64
                        title: String
                        subtitle: {
                            type: String
                            nullable: true
                        }
                        author_id: {
                            type: I64
                            relation: {
                                references: "user.id"
                                nested_route: true
                            }
                        }
                    }
                }
            }
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].struct_ident.to_string(), "Post");
        assert_eq!(resources[0].list.default_limit, Some(25));
        assert_eq!(resources[0].list.max_limit, Some(100));

        let subtitle = resources[0]
            .find_field("subtitle")
            .expect("subtitle should exist");
        assert!(super::super::model::is_optional_type(&subtitle.ty));

        let author_id = resources[0]
            .find_field("author_id")
            .expect("author_id should exist");
        let relation = author_id
            .relation
            .as_ref()
            .expect("author_id relation should exist");
        assert_eq!(relation.references_table, "user");
        assert_eq!(relation.references_field, "id");
        assert!(relation.nested_route);
    }

    #[test]
    fn rejects_mismatched_resource_name_in_map_entry() {
        let error = match eon::from_str::<ServiceDocument>(
            r#"
            resources: {
                Post: {
                    name: "Comment"
                    fields: {
                        id: I64
                    }
                }
            }
            "#,
        ) {
            Ok(_) => panic!("mismatched resource name should fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("resource map entry `Post` has mismatched `name` value `Comment`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_mismatched_field_name_in_map_entry() {
        let error = match eon::from_str::<ServiceDocument>(
            r#"
            resources: {
                Post: {
                    fields: {
                        title: {
                            name: "headline"
                            type: String
                        }
                    }
                }
            }
            "#,
        ) {
            Ok(_) => panic!("mismatched field name should fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("field map entry `title` has mismatched `name` value `headline`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_invalid_list_config_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    list: {
                        default_limit: 50
                        max_limit: 10
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("invalid list config should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("default_limit"));
        assert!(error.to_string().contains("max_limit"));
    }

    #[test]
    fn rejects_unknown_row_policy_kind_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { kind: Tenant, field: "user_id" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("invalid row policy kind should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("Owner"));
        assert!(error.to_string().contains("SetOwner"));
    }

    #[test]
    fn rejects_invalid_row_policy_source_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { field: "tenant_id", equals: "session.tenant_id" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "tenant_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("invalid row policy source should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(
            "read row policy field `tenant_id` compares incompatible field types `I64` and `String`"
        ));
    }

    #[test]
    fn rejects_set_null_on_non_nullable_relation_field() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Comment"
                    fields: [
                        { name: "id", type: I64 }
                        {
                            name: "post_id"
                            type: I64
                            relation: {
                                references: "post.id"
                                on_delete: SetNull
                            }
                        }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("invalid relation should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("SetNull"));
        assert!(error.to_string().contains("not nullable"));
    }

    #[test]
    fn rejects_invalid_field_validation_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                        {
                            name: "published"
                            type: Bool
                            garde: {
                                range: {
                                    min: 1
                                }
                            }
                        }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("invalid validation should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("published"));
        assert!(error.to_string().contains("range"));
    }

    #[test]
    fn rejects_legacy_validate_key_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                        {
                            name: "title"
                            type: String
                            validate: {
                                min_length: 3
                            }
                        }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("legacy validate should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("legacy `validate`"));
        assert!(error.to_string().contains("rename it to `garde`"));
    }

    #[test]
    fn rejects_missing_row_policy_field_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { kind: Owner, field: "user_id" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("missing row policy field should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("missing field `user_id`"));
    }

    #[test]
    fn rejects_unsupported_row_policy_field_type_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { kind: Owner, field: "created_at" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "created_at", type: DateTime }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("unsupported row policy field should fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("must use type `i64`, `String`, `bool`, or an `Option<...>`")
        );
    }

    #[test]
    fn parses_static_mounts_from_eon() {
        let root = temp_root("eon_static_mounts");
        fs::create_dir_all(root.join("public/assets")).expect("asset dir should exist");
        fs::write(root.join("public/index.html"), "<html>ok</html>").expect("index should exist");
        fs::write(root.join("public/assets/app.js"), "console.log('ok');")
            .expect("asset should exist");

        let document = parse_document(
            r#"
            static: {
                mounts: [
                    {
                        mount: "/assets"
                        dir: "public/assets"
                        mode: Directory
                        cache: Immutable
                    }
                    {
                        mount: "/"
                        dir: "public"
                        mode: Spa
                        cache: NoStore
                    }
                ]
            }
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let mounts =
            build_static_mounts(&root, document.static_config).expect("mounts should parse");
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].mount_path, "/assets");
        assert_eq!(mounts[0].source_dir, "public/assets");
        assert_eq!(mounts[0].cache, StaticCacheProfile::Immutable);
        assert_eq!(mounts[1].mode, StaticMode::Spa);
        assert_eq!(mounts[1].index_file.as_deref(), Some("index.html"));
        assert_eq!(mounts[1].fallback_file.as_deref(), Some("index.html"));
    }

    #[test]
    fn rejects_static_mounts_that_escape_service_root() {
        let root = temp_root("eon_static_escape");
        fs::create_dir_all(&root).expect("root should exist");
        let outside = root
            .parent()
            .expect("temp root should have a parent")
            .join("outside-static");
        fs::create_dir_all(&outside).expect("outside dir should exist");

        let document = parse_document(
            r#"
            static: {
                mounts: [
                    {
                        mount: "/"
                        dir: "../outside-static"
                        mode: Spa
                    }
                ]
            }
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let error = build_static_mounts(&root, document.static_config)
            .expect_err("escaping static mount should fail");
        assert!(
            error
                .to_string()
                .contains("cannot escape the service directory")
        );
    }

    #[test]
    fn rejects_static_mounts_that_conflict_with_reserved_routes() {
        let root = temp_root("eon_static_reserved");
        fs::create_dir_all(root.join("public")).expect("public dir should exist");

        let document = parse_document(
            r#"
            static: {
                mounts: [
                    {
                        mount: "/docs"
                        dir: "public"
                    }
                ]
            }
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let error = build_static_mounts(&root, document.static_config)
            .expect_err("reserved route conflict should fail");
        assert!(
            error
                .to_string()
                .contains("conflicts with a reserved route")
        );
    }

    #[test]
    fn parses_storage_backends_and_public_mounts_from_eon() {
        let root = temp_root("eon_storage_mounts");
        fs::create_dir_all(&root).expect("root should exist");

        let document = parse_document(
            r#"
            storage: {
                backends: [
                    {
                        name: "uploads"
                        kind: Local
                        dir: "var/uploads"
                    }
                ]
                public_mounts: [
                    {
                        mount: "/uploads"
                        backend: "uploads"
                        prefix: "public"
                        cache: Immutable
                    }
                ]
            }
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let storage =
            parse_storage_document(&root, document.storage).expect("storage should parse");
        assert_eq!(storage.backends.len(), 1);
        assert_eq!(storage.backends[0].name, "uploads");
        assert_eq!(storage.backends[0].kind, StorageBackendKind::Local);
        assert_eq!(storage.backends[0].root_dir, "var/uploads");
        assert_eq!(storage.public_mounts.len(), 1);
        assert_eq!(storage.public_mounts[0].mount_path, "/uploads");
        assert_eq!(storage.public_mounts[0].backend, "uploads");
        assert_eq!(storage.public_mounts[0].key_prefix, "public");
        assert_eq!(
            storage.public_mounts[0].cache,
            crate::static_files::StaticCacheProfile::Immutable
        );
    }

    #[test]
    fn rejects_storage_public_mounts_with_unknown_backends() {
        let root = temp_root("eon_storage_unknown_backend");
        fs::create_dir_all(&root).expect("root should exist");

        let document = parse_document(
            r#"
            storage: {
                public_mounts: [
                    {
                        mount: "/uploads"
                        backend: "missing"
                    }
                ]
            }
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let error = parse_storage_document(&root, document.storage)
            .expect_err("unknown storage backend should fail");
        assert!(
            error
                .to_string()
                .contains("references unknown backend `missing`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_storage_mounts_that_conflict_with_static_mounts() {
        let root = temp_root("eon_storage_mount_conflict");
        fs::create_dir_all(root.join("public")).expect("public dir should exist");

        let document = parse_document(
            r#"
            static: {
                mounts: [
                    {
                        mount: "/uploads"
                        dir: "public"
                    }
                ]
            }
            storage: {
                backends: [
                    {
                        name: "uploads"
                        kind: Local
                        dir: "var/uploads"
                    }
                ]
                public_mounts: [
                    {
                        mount: "/uploads"
                        backend: "uploads"
                    }
                ]
            }
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let static_mounts =
            build_static_mounts(&root, document.static_config).expect("static mounts should parse");
        let storage =
            parse_storage_document(&root, document.storage).expect("storage should parse");
        let error = validate_distinct_public_mounts(static_mounts.as_slice(), &storage)
            .expect_err("conflicting mount paths should fail");
        assert!(
            error
                .to_string()
                .contains("already declared by a static mount"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn parses_storage_uploads_from_eon() {
        let root = temp_root("eon_storage_uploads");
        fs::create_dir_all(&root).expect("root should exist");

        let document = parse_document(
            r#"
            storage: {
                backends: [
                    {
                        name: "uploads"
                        kind: Local
                        dir: "var/uploads"
                    }
                ]
                uploads: [
                    {
                        name: "asset_upload"
                        path: "uploads"
                        backend: "uploads"
                        prefix: "assets"
                        max_bytes: 4096
                        require_auth: false
                        roles: ["editor"]
                    }
                ]
            }
            resources: [
                {
                    name: "Post"
                    api_name: "posts"
                    fields: [
                        { name: "id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let storage =
            parse_storage_document(&root, document.storage).expect("storage should parse");
        assert_eq!(storage.uploads.len(), 1);
        assert_eq!(storage.uploads[0].name, "asset_upload");
        assert_eq!(storage.uploads[0].path, "uploads");
        assert_eq!(storage.uploads[0].backend, "uploads");
        assert_eq!(storage.uploads[0].key_prefix, "assets");
        assert_eq!(storage.uploads[0].max_bytes, 4096);
        assert!(!storage.uploads[0].require_auth);
        assert_eq!(storage.uploads[0].roles, vec!["editor"]);
    }

    #[test]
    fn rejects_storage_upload_paths_that_conflict_with_resource_routes() {
        let root = temp_root("eon_storage_upload_conflict");
        fs::create_dir_all(&root).expect("root should exist");

        let document = parse_document(
            r#"
            storage: {
                backends: [
                    {
                        name: "uploads"
                        kind: Local
                        dir: "var/uploads"
                    }
                ]
                uploads: [
                    {
                        name: "asset_upload"
                        path: "posts"
                        backend: "uploads"
                    }
                ]
            }
            resources: [
                {
                    name: "Post"
                    api_name: "posts"
                    fields: [
                        { name: "id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let storage =
            parse_storage_document(&root, document.storage).expect("storage should parse");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let error = validate_storage_upload_routes(&storage, &resources)
            .expect_err("conflicting upload route should fail");
        assert!(
            error
                .to_string()
                .contains("conflicts with an existing API route segment"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn parses_storage_s3_compat_mounts_from_eon() {
        let root = temp_root("eon_storage_s3_compat");
        fs::create_dir_all(&root).expect("root should exist");

        let document = parse_document(
            r#"
            storage: {
                backends: [
                    {
                        name: "uploads"
                        kind: Local
                        dir: "var/uploads"
                    }
                ]
                s3_compat: {
                    mount: "/_s3"
                    buckets: [
                        {
                            name: "media"
                            backend: "uploads"
                            prefix: "assets"
                        }
                    ]
                }
            }
            resources: [
                {
                    name: "Post"
                    api_name: "posts"
                    fields: [
                        { name: "id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let storage =
            parse_storage_document(&root, document.storage).expect("storage should parse");
        let s3_compat = storage
            .s3_compat
            .expect("s3 compat config should be present");
        assert_eq!(s3_compat.mount_path, "/_s3");
        assert_eq!(s3_compat.buckets.len(), 1);
        assert_eq!(s3_compat.buckets[0].name, "media");
        assert_eq!(s3_compat.buckets[0].backend, "uploads");
        assert_eq!(s3_compat.buckets[0].key_prefix, "assets");
    }

    #[test]
    fn rejects_storage_s3_compat_mounts_that_conflict_with_static_mounts() {
        let root = temp_root("eon_storage_s3_compat_conflict");
        fs::create_dir_all(root.join("public")).expect("public dir should exist");

        let document = parse_document(
            r#"
            storage: {
                backends: [
                    {
                        name: "uploads"
                        kind: Local
                        dir: "var/uploads"
                    }
                ]
                s3_compat: {
                    mount: "/studio"
                    buckets: [
                        {
                            name: "media"
                            backend: "uploads"
                        }
                    ]
                }
            }
            static: {
                mounts: [
                    {
                        mount: "/studio"
                        dir: "public"
                        mode: Directory
                    }
                ]
            }
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let static_mounts =
            build_static_mounts(&root, document.static_config).expect("static mounts should parse");
        let storage =
            parse_storage_document(&root, document.storage).expect("storage should parse");
        let error = validate_distinct_public_mounts(static_mounts.as_slice(), &storage)
            .expect_err("conflicting s3 compat mount should fail");
        assert!(
            error
                .to_string()
                .contains("mount path `/studio` is already declared"),
            "unexpected error: {error}"
        );
    }
}