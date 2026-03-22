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

pub use authorization::{compile_resource_authorization, compile_service_authorization};
pub use model::{
    DbBackend, FieldSpec, GeneratedTemporalKind, GeneratedValue, ReferentialAction, RelationSpec,
    ResourceSpec, RoleRequirements, RowPolicies, ServiceSpec, StaticCacheProfile, StaticMode,
    StaticMountSpec, StructuredScalarKind, default_service_database_url, is_date_type,
    is_datetime_type, is_decimal_type, is_optional_type, is_structured_scalar_type, is_time_type,
    is_uuid_type, structured_scalar_kind, supports_range_filters, supports_sort,
    temporal_scalar_kind,
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
