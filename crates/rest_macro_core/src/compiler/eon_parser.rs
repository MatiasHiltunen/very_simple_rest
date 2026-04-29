use std::{
    env, fs,
    path::{Path, PathBuf},
};

use proc_macro2::Span;
use syn::LitStr;

use super::model::{
    // Used in production code (load_service_document):
    ServiceSpec,
    apply_service_read_access_defaults, sanitize_module_ident, validate_authorization_contract,
    validate_build_config, validate_clients_config, validate_logging_config,
    validate_policy_claim_sources, validate_runtime_config, validate_security_config,
    validate_tls_config,
    // Test-only (cargo check reports unused; cargo test needs them):
    BuildCacheCleanupStrategy, BuildConfig, BuildLtoMode, ClientsConfig,
    DbBackend, GeneratedValue, NumericBound, PolicyFilterExpression, PolicyValueSource,
    ResourceReadAccess, RoleRequirements, StaticCacheProfile, StaticMode,
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

// Required for the #[cfg(test)] build_resources helper below.
#[cfg(test)]
use super::model::ResourceSpec;

#[cfg(test)]
fn build_resources(
    db: DbBackend,
    resources: Vec<ResourceDocument>,
) -> syn::Result<Vec<ResourceSpec>> {
    build_resources_with_enums(db, resources, &[])
}


mod resource_builder;
use self::resource_builder::*;

mod config_parsing;
use self::config_parsing::*;

mod storage_parsing;
use self::storage_parsing::*;

mod field_parsing;
use self::field_parsing::*;

mod policy_parsing;
use self::policy_parsing::*;

#[cfg(test)]
mod tests;
