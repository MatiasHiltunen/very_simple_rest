//! Type-classification, access, and identifier helpers.
//!
//! These functions answer "is this type optional / a list / a structured
//! scalar?" or "does this resource require auth to read?". They are pure
//! queries over the spec types defined in `specs.rs` and the scalar enums in
//! `scalars.rs`.

use syn::Type;

use crate::auth::AuthClaimType;
use crate::database::{DatabaseEngine, sqlite_url_for_path};
use crate::security::{DefaultReadAccess, SecurityConfig};

use super::scalars::{
    DbBackend, GENERATED_DATETIME_ALIAS, GENERATED_DATE_ALIAS, GENERATED_DECIMAL_ALIAS,
    GENERATED_JSON_ALIAS, GENERATED_JSON_ARRAY_ALIAS, GENERATED_JSON_OBJECT_ALIAS,
    GENERATED_TIME_ALIAS, GENERATED_UUID_ALIAS, GeneratedTemporalKind, GeneratedValue,
    ResourceReadAccess, StructuredScalarKind,
};
use super::specs::{FieldSpec, ResourceSpec};
use super::validation::FieldTransform;

pub fn default_service_database_url(service: &super::specs::ServiceSpec) -> String {
    match &service.database.engine {
        DatabaseEngine::TursoLocal(engine) => sqlite_url_for_path(&engine.path),
        DatabaseEngine::Sqlx => service
            .resources
            .first()
            .map(|resource| match resource.db {
                DbBackend::Sqlite => "sqlite:app.db?mode=rwc".to_owned(),
                DbBackend::Postgres => "postgres://postgres:postgres@127.0.0.1/app".to_owned(),
                DbBackend::Mysql => "mysql://root:password@127.0.0.1/app".to_owned(),
            })
            .unwrap_or_else(|| "sqlite:app.db?mode=rwc".to_owned()),
    }
}

pub fn infer_sql_type(ty: &Type, db: DbBackend) -> String {
    if let Some(kind) = structured_scalar_kind(ty) {
        return kind.sql_type(db).to_owned();
    }

    match type_leaf_name(ty).as_deref() {
        Some("i64" | "u64" | "isize" | "usize") => match db {
            DbBackend::Sqlite => "INTEGER".to_owned(),
            DbBackend::Postgres | DbBackend::Mysql => "BIGINT".to_owned(),
        },
        Some("i8" | "i16" | "i32") => "INTEGER".to_owned(),
        Some("u8" | "u16" | "u32") => "INTEGER".to_owned(),
        Some("f32" | "f64") => "REAL".to_owned(),
        Some("bool") => match db {
            DbBackend::Sqlite | DbBackend::Mysql => "INTEGER".to_owned(),
            DbBackend::Postgres => "BOOLEAN".to_owned(),
        },
        Some("String") => match db {
            DbBackend::Mysql => "VARCHAR(255)".to_owned(),
            DbBackend::Sqlite | DbBackend::Postgres => "TEXT".to_owned(),
        },
        _ => "TEXT".to_owned(),
    }
}

pub fn is_integer_sql_type(sql_type: &str) -> bool {
    matches!(sql_type, "INTEGER" | "BIGINT")
}

pub fn is_bool_type(ty: &Type) -> bool {
    matches!(type_leaf_name(ty).as_deref(), Some("bool"))
}

pub(super) fn type_leaf_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(type_path) => {
            let segment = type_path.path.segments.last()?;
            if segment.ident == "Option"
                && let syn::PathArguments::AngleBracketed(args) = &segment.arguments
            {
                let inner_ty = args.args.iter().find_map(|arg| match arg {
                    syn::GenericArgument::Type(inner_ty) => Some(inner_ty),
                    _ => None,
                })?;
                return type_leaf_name(inner_ty);
            }
            Some(segment.ident.to_string())
        }
        _ => None,
    }
}

pub fn is_optional_type(ty: &Type) -> bool {
    match ty {
        Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .map(|segment| segment.ident == "Option")
            .unwrap_or(false),
        _ => false,
    }
}

pub fn base_type(ty: &Type) -> Type {
    match ty {
        Type::Path(type_path) => {
            let Some(segment) = type_path.path.segments.last() else {
                return ty.clone();
            };
            if segment.ident != "Option" {
                return ty.clone();
            }
            let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
                return ty.clone();
            };
            args.args
                .iter()
                .find_map(|arg| match arg {
                    syn::GenericArgument::Type(inner_ty) => Some(inner_ty.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| ty.clone())
        }
        _ => ty.clone(),
    }
}

pub fn policy_field_claim_type(ty: &Type) -> Option<AuthClaimType> {
    match type_leaf_name(ty).as_deref() {
        Some("i64") => Some(AuthClaimType::I64),
        Some("String") => Some(AuthClaimType::String),
        Some("bool") => Some(AuthClaimType::Bool),
        _ => None,
    }
}

pub fn structured_scalar_kind(ty: &Type) -> Option<StructuredScalarKind> {
    match type_leaf_name(ty).as_deref() {
        Some("DateTime" | GENERATED_DATETIME_ALIAS) => Some(StructuredScalarKind::DateTime),
        Some("Date" | "NaiveDate" | GENERATED_DATE_ALIAS) => Some(StructuredScalarKind::Date),
        Some("Time" | "NaiveTime" | GENERATED_TIME_ALIAS) => Some(StructuredScalarKind::Time),
        Some("Uuid" | GENERATED_UUID_ALIAS) => Some(StructuredScalarKind::Uuid),
        Some("Decimal" | GENERATED_DECIMAL_ALIAS) => Some(StructuredScalarKind::Decimal),
        Some(GENERATED_JSON_ALIAS) => Some(StructuredScalarKind::Json),
        Some(GENERATED_JSON_OBJECT_ALIAS) => Some(StructuredScalarKind::JsonObject),
        Some(GENERATED_JSON_ARRAY_ALIAS) => Some(StructuredScalarKind::JsonArray),
        _ => None,
    }
}

pub fn temporal_scalar_kind(ty: &Type) -> Option<GeneratedTemporalKind> {
    structured_scalar_kind(ty).and_then(|kind| kind.generated_temporal_kind())
}

pub fn generated_temporal_kind_for_field(
    ty: &Type,
    generated: GeneratedValue,
) -> Option<GeneratedTemporalKind> {
    temporal_scalar_kind(ty).or_else(|| {
        if matches!(
            generated,
            GeneratedValue::CreatedAt | GeneratedValue::UpdatedAt
        ) && matches!(type_leaf_name(ty).as_deref(), Some("String"))
        {
            Some(GeneratedTemporalKind::DateTime)
        } else {
            None
        }
    })
}

pub fn supports_range_filters(ty: &Type) -> bool {
    structured_scalar_kind(ty)
        .map(|kind| kind.supports_range_filters())
        .unwrap_or(false)
}

pub fn supports_exact_filters(field: &FieldSpec) -> bool {
    if field.list_item_ty.is_some() {
        return false;
    }
    structured_scalar_kind(&field.ty)
        .map(|kind| kind.supports_exact_filters())
        .unwrap_or(true)
}

pub fn supports_contains_filters(field: &FieldSpec) -> bool {
    if field.list_item_ty.is_some()
        || is_structured_scalar_type(&field.ty)
        || field.enum_values.is_some()
    {
        return false;
    }

    !is_integer_sql_type(field.sql_type.as_str())
        && !matches!(field.sql_type.as_str(), "REAL")
        && !is_bool_type(&field.ty)
}

pub fn read_requires_auth(resource: &ResourceSpec) -> bool {
    match resource.access.read {
        ResourceReadAccess::Public => false,
        ResourceReadAccess::Authenticated => true,
        ResourceReadAccess::Inferred => {
            resource.roles.read.is_some() || resource.policies.has_read_filters()
        }
    }
}

pub fn apply_service_read_access_defaults(
    resources: &mut [ResourceSpec],
    security: &SecurityConfig,
) {
    if security.access.default_read != DefaultReadAccess::Authenticated {
        return;
    }

    for resource in resources {
        if resource.access.read == ResourceReadAccess::Inferred {
            resource.access.read = ResourceReadAccess::Authenticated;
        }
    }
}

pub fn supports_sort(ty: &Type) -> bool {
    structured_scalar_kind(ty)
        .map(|kind| kind.supports_sort())
        .unwrap_or(true)
}

pub fn supports_field_sort(field: &FieldSpec) -> bool {
    if field.list_item_ty.is_some() {
        return false;
    }
    supports_sort(&field.ty)
}

pub fn is_enum_field(field: &FieldSpec) -> bool {
    field.enum_values.is_some()
}

pub fn supports_declared_index(field: &FieldSpec) -> bool {
    field.object_fields.is_none()
        && field.list_item_ty.is_none()
        && !is_json_type(&field.ty)
        && !is_json_object_type(&field.ty)
        && !is_json_array_type(&field.ty)
}

pub fn supports_field_transforms(field: &FieldSpec) -> bool {
    field.list_item_ty.is_none()
        && field.object_fields.is_none()
        && !is_structured_scalar_type(&field.ty)
        && !is_bool_type(&field.ty)
        && !is_integer_sql_type(field.sql_type.as_str())
        && !matches!(field.sql_type.as_str(), "REAL")
}

pub fn supports_field_transform(field: &FieldSpec, transform: FieldTransform) -> bool {
    if !supports_field_transforms(field) {
        return false;
    }

    match transform {
        FieldTransform::Trim | FieldTransform::Lowercase | FieldTransform::CollapseWhitespace => {
            true
        }
        FieldTransform::Slugify => field.enum_values.is_none(),
    }
}

pub fn is_list_field(field: &FieldSpec) -> bool {
    field.list_item_ty.is_some()
}

pub fn list_item_type(field: &FieldSpec) -> Option<&Type> {
    field.list_item_ty.as_ref()
}

pub fn object_fields(field: &FieldSpec) -> Option<&[FieldSpec]> {
    field.object_fields.as_deref()
}

pub fn is_typed_object_field(field: &FieldSpec) -> bool {
    field.object_fields.is_some()
}

pub fn is_structured_scalar_type(ty: &Type) -> bool {
    structured_scalar_kind(ty).is_some()
}

pub fn is_datetime_type(ty: &Type) -> bool {
    structured_scalar_kind(ty) == Some(StructuredScalarKind::DateTime)
}

pub fn is_date_type(ty: &Type) -> bool {
    structured_scalar_kind(ty) == Some(StructuredScalarKind::Date)
}

pub fn is_time_type(ty: &Type) -> bool {
    structured_scalar_kind(ty) == Some(StructuredScalarKind::Time)
}

pub fn is_uuid_type(ty: &Type) -> bool {
    structured_scalar_kind(ty) == Some(StructuredScalarKind::Uuid)
}

pub fn is_decimal_type(ty: &Type) -> bool {
    structured_scalar_kind(ty) == Some(StructuredScalarKind::Decimal)
}

pub fn is_json_type(ty: &Type) -> bool {
    structured_scalar_kind(ty) == Some(StructuredScalarKind::Json)
}

pub fn is_json_object_type(ty: &Type) -> bool {
    structured_scalar_kind(ty) == Some(StructuredScalarKind::JsonObject)
}

pub fn is_json_array_type(ty: &Type) -> bool {
    structured_scalar_kind(ty) == Some(StructuredScalarKind::JsonArray)
}
