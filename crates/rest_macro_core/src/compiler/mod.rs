mod authorization;
mod codegen;
mod derive_parser;
mod eon_parser;
mod migrations;
mod model;
mod openapi;
mod source_loader;

use proc_macro2::TokenStream;
use std::path::Path as FsPath;
use syn::{DeriveInput, LitStr, Path};

pub use crate::storage::{
    StorageBackendConfig, StorageBackendKind, StorageConfig, StoragePublicMount,
};
pub use authorization::{compile_resource_authorization, compile_service_authorization};
pub use model::{
    BuildArtifactPathConfig, BuildArtifactsConfig, BuildCacheArtifactConfig,
    BuildCacheCleanupStrategy, BuildConfig, BuildLtoMode, ClientValueConfig, ClientsConfig,
    ComputedFieldPart, ComputedFieldSpec, DbBackend, EnumSpec, FieldSpec, FieldTransform,
    FieldValidation, GeneratedTemporalKind, GeneratedValue, IndexSpec, NumericBound,
    PolicyAssignment, PolicyComparisonValue, PolicyExistsCondition, PolicyExistsFilter,
    PolicyFilter, PolicyFilterExpression, PolicyFilterOperator, PolicyLiteralValue,
    PolicyValueSource, ReferentialAction, RelationSpec, ReleaseBuildConfig,
    ResourceActionAssignmentSpec, ResourceActionBehaviorSpec, ResourceActionInputFieldSpec,
    ResourceActionMethod, ResourceActionSpec, ResourceActionTarget, ResourceActionValueSpec,
    ResourceSpec, ResponseContextSpec, RoleRequirements, RowPolicies, ServiceSpec,
    StaticCacheProfile, StaticMode, StaticMountSpec, StructuredScalarKind, TsClientConfig,
    default_service_database_url, infer_sql_type, is_date_type, is_datetime_type,
    is_decimal_type, is_enum_field, is_json_array_type, is_json_object_type, is_json_type,
    is_list_field, is_optional_type, is_structured_scalar_type, is_time_type,
    is_typed_object_field, is_uuid_type, list_item_type, object_fields, structured_scalar_kind,
    supports_declared_index, supports_exact_filters, supports_field_sort,
    supports_field_transforms, supports_range_filters, supports_sort, temporal_scalar_kind,
    validate_field_transforms,
};
pub use openapi::OpenApiSpecOptions;

pub fn expand_derive(input: DeriveInput, runtime_crate: Path) -> syn::Result<TokenStream> {
    let resource = derive_parser::parse_derive_input(input)?;
    codegen::expand_derive_resource(&resource, &runtime_crate)
}

pub fn expand_eon_file(path: LitStr, runtime_crate: Path) -> syn::Result<TokenStream> {
    let loaded = eon_parser::load_service_from_file(path)?;
    codegen::expand_service_module(&loaded.service, &runtime_crate, &loaded.include_path)
}

pub fn expand_service_from_path(path: &FsPath, runtime_crate: Path) -> syn::Result<TokenStream> {
    let loaded = eon_parser::load_service_from_path(path)?;
    codegen::expand_service_module(&loaded.service, &runtime_crate, &loaded.include_path)
}

pub fn expand_service(
    service: &ServiceSpec,
    runtime_crate: Path,
    include_path: &str,
) -> syn::Result<TokenStream> {
    codegen::expand_service_module(service, &runtime_crate, include_path)
}

pub fn load_service_from_path(path: &FsPath) -> syn::Result<ServiceSpec> {
    let loaded = eon_parser::load_service_from_path(path)?;
    Ok(loaded.service)
}

pub fn render_service_migration_sql(service: &ServiceSpec) -> syn::Result<String> {
    migrations::render_service_migration_sql(service)
}

pub fn load_derive_service_from_path(path: &FsPath) -> syn::Result<ServiceSpec> {
    source_loader::load_derive_service_from_path(path)
}

pub fn render_service_diff_migration_sql(
    previous: &ServiceSpec,
    next: &ServiceSpec,
) -> syn::Result<String> {
    migrations::render_service_diff_migration_sql(previous, next)
}

pub fn render_service_openapi_json(
    service: &ServiceSpec,
    options: &OpenApiSpecOptions,
) -> syn::Result<String> {
    openapi::render_service_openapi_json(service, options)
}
