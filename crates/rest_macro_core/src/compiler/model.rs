use std::{collections::HashSet, net::IpAddr, str::FromStr};

use actix_web::http::{Method, Uri, header::HeaderName};
use heck::{ToSnakeCase, ToUpperCamelCase};
use proc_macro2::Span;
use quote::ToTokens;
use syn::{Ident, Type};

use crate::auth::{AuthEmailProvider, SessionCookieSameSite};
use crate::database::{DatabaseConfig, DatabaseEngine, sqlite_url_for_path};
use crate::logging::LoggingConfig;
use crate::security::SecurityConfig;
use url::Url;

pub const GENERATED_DATETIME_ALIAS: &str = "__VsrDateTimeUtc";
pub const GENERATED_DATE_ALIAS: &str = "__VsrNaiveDate";
pub const GENERATED_TIME_ALIAS: &str = "__VsrNaiveTime";
pub const GENERATED_UUID_ALIAS: &str = "__VsrUuid";
pub const GENERATED_DECIMAL_ALIAS: &str = "__VsrDecimal";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructuredScalarKind {
    DateTime,
    Date,
    Time,
    Uuid,
    Decimal,
}

impl StructuredScalarKind {
    pub fn sql_type(self, db: DbBackend) -> &'static str {
        match (self, db) {
            (_, DbBackend::Sqlite | DbBackend::Postgres) => "TEXT",
            (Self::DateTime, DbBackend::Mysql) => "VARCHAR(64)",
            (Self::Date, DbBackend::Mysql) => "VARCHAR(10)",
            (Self::Time, DbBackend::Mysql) => "VARCHAR(15)",
            (Self::Uuid, DbBackend::Mysql) => "CHAR(36)",
            (Self::Decimal, DbBackend::Mysql) => "VARCHAR(80)",
        }
    }

    pub fn openapi_format(self) -> &'static str {
        match self {
            Self::DateTime => "date-time",
            Self::Date => "date",
            Self::Time => "time",
            Self::Uuid => "uuid",
            Self::Decimal => "decimal",
        }
    }

    pub fn supports_range_filters(self) -> bool {
        matches!(self, Self::DateTime | Self::Date | Self::Time)
    }

    pub fn supports_sort(self) -> bool {
        !matches!(self, Self::Decimal)
    }

    pub fn generated_temporal_kind(self) -> Option<GeneratedTemporalKind> {
        match self {
            Self::DateTime => Some(GeneratedTemporalKind::DateTime),
            Self::Date => Some(GeneratedTemporalKind::Date),
            Self::Time => Some(GeneratedTemporalKind::Time),
            Self::Uuid | Self::Decimal => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedTemporalKind {
    DateTime,
    Date,
    Time,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub enum DbBackend {
    #[default]
    Sqlite,
    Postgres,
    Mysql,
}

impl DbBackend {
    pub fn placeholder(self, index: usize) -> String {
        match self {
            Self::Postgres => format!("${index}"),
            Self::Sqlite | Self::Mysql => "?".to_owned(),
        }
    }

    pub fn primary_key_sql(self, field_name: &str) -> String {
        match self {
            Self::Sqlite => format!("{field_name} INTEGER PRIMARY KEY AUTOINCREMENT"),
            Self::Postgres => format!("{field_name} BIGSERIAL PRIMARY KEY"),
            Self::Mysql => format!("{field_name} BIGINT AUTO_INCREMENT PRIMARY KEY"),
        }
    }

    pub fn generated_temporal_expression(
        self,
        kind: Option<GeneratedTemporalKind>,
    ) -> &'static str {
        match kind {
            Some(GeneratedTemporalKind::DateTime) => match self {
                Self::Sqlite => "(STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now'))",
                Self::Postgres => {
                    "(TO_CHAR(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US') || '+00:00')"
                }
                Self::Mysql => "(DATE_FORMAT(UTC_TIMESTAMP(6), '%Y-%m-%dT%H:%i:%s.%f+00:00'))",
            },
            Some(GeneratedTemporalKind::Date) => match self {
                Self::Sqlite => "(DATE('now'))",
                Self::Postgres => "(TO_CHAR(CURRENT_DATE, 'YYYY-MM-DD'))",
                Self::Mysql => "(DATE_FORMAT(UTC_DATE(), '%Y-%m-%d'))",
            },
            Some(GeneratedTemporalKind::Time) => match self {
                Self::Sqlite => "(STRFTIME('%H:%M:%f000', 'now'))",
                Self::Postgres => {
                    "(TO_CHAR(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'HH24:MI:SS.US'))"
                }
                Self::Mysql => "(DATE_FORMAT(UTC_TIMESTAMP(6), '%H:%i:%s.%f'))",
            },
            None => "CURRENT_TIMESTAMP",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub enum GeneratedValue {
    #[default]
    None,
    AutoIncrement,
    CreatedAt,
    UpdatedAt,
}

impl GeneratedValue {
    pub fn skip_insert(self) -> bool {
        matches!(
            self,
            Self::AutoIncrement | Self::CreatedAt | Self::UpdatedAt
        )
    }

    pub fn skip_update_bind(self) -> bool {
        matches!(
            self,
            Self::AutoIncrement | Self::CreatedAt | Self::UpdatedAt
        )
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct RoleRequirements {
    pub read: Option<String>,
    pub create: Option<String>,
    pub update: Option<String>,
    pub delete: Option<String>,
}

impl RoleRequirements {
    pub fn with_legacy_defaults(mut self) -> Self {
        if self.create.is_none() {
            self.create = self.update.clone();
        }
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RowPolicyKind {
    Owner,
    SetOwner,
}

impl RowPolicyKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "owner" => Some(Self::Owner),
            "set_owner" | "setowner" | "set-owner" => Some(Self::SetOwner),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyValueSource {
    UserId,
    Claim(String),
}

impl PolicyValueSource {
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value == "user.id" {
            Some(Self::UserId)
        } else {
            value.strip_prefix("claim.").and_then(|claim| {
                if claim.is_empty() {
                    None
                } else {
                    Some(Self::Claim(claim.to_owned()))
                }
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyFilter {
    pub field: String,
    pub source: PolicyValueSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyAssignment {
    pub field: String,
    pub source: PolicyValueSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowPolicies {
    pub admin_bypass: bool,
    pub read: Vec<PolicyFilter>,
    pub create: Vec<PolicyAssignment>,
    pub update: Vec<PolicyFilter>,
    pub delete: Vec<PolicyFilter>,
}

impl Default for RowPolicies {
    fn default() -> Self {
        Self {
            admin_bypass: true,
            read: Vec::new(),
            create: Vec::new(),
            update: Vec::new(),
            delete: Vec::new(),
        }
    }
}

impl RowPolicies {
    pub fn iter_filters(&self) -> impl Iterator<Item = (&'static str, &PolicyFilter)> {
        self.read
            .iter()
            .map(|policy| ("read", policy))
            .chain(self.update.iter().map(|policy| ("update", policy)))
            .chain(self.delete.iter().map(|policy| ("delete", policy)))
    }

    pub fn iter_assignments(&self) -> impl Iterator<Item = (&'static str, &PolicyAssignment)> {
        self.create.iter().map(|policy| ("create", policy))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
pub struct RelationSpec {
    pub references_table: String,
    pub references_field: String,
    #[serde(default)]
    pub on_delete: Option<ReferentialAction>,
    #[serde(default)]
    pub nested_route: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ReferentialAction {
    Cascade,
    Restrict,
    SetNull,
    NoAction,
}

impl ReferentialAction {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "cascade" => Some(Self::Cascade),
            "restrict" => Some(Self::Restrict),
            "set_null" | "setnull" | "set-null" => Some(Self::SetNull),
            "no_action" | "noaction" | "no-action" => Some(Self::NoAction),
            _ => None,
        }
    }

    pub fn sql(self) -> &'static str {
        match self {
            Self::Cascade => "CASCADE",
            Self::Restrict => "RESTRICT",
            Self::SetNull => "SET NULL",
            Self::NoAction => "NO ACTION",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct FieldValidation {
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub minimum: Option<NumericBound>,
    pub maximum: Option<NumericBound>,
}

impl FieldValidation {
    pub fn is_empty(&self) -> bool {
        self.min_length.is_none()
            && self.max_length.is_none()
            && self.minimum.is_none()
            && self.maximum.is_none()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListConfig {
    pub default_limit: Option<u32>,
    pub max_limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum NumericBound {
    Integer(i64),
    Float(f64),
}

impl NumericBound {
    pub fn as_f64(&self) -> f64 {
        match self {
            Self::Integer(value) => *value as f64,
            Self::Float(value) => *value,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteModelStyle {
    ExistingStructWithDtos,
    GeneratedStructWithDtos,
}

#[derive(Clone)]
pub struct FieldSpec {
    pub ident: Ident,
    pub ty: Type,
    pub sql_type: String,
    pub is_id: bool,
    pub generated: GeneratedValue,
    pub validation: FieldValidation,
    pub relation: Option<RelationSpec>,
}

impl FieldSpec {
    pub fn name(&self) -> String {
        self.ident.to_string()
    }
}

#[derive(Clone)]
pub struct ResourceSpec {
    pub struct_ident: Ident,
    pub impl_module_ident: Ident,
    pub table_name: String,
    pub id_field: String,
    pub db: DbBackend,
    pub roles: RoleRequirements,
    pub policies: RowPolicies,
    pub list: ListConfig,
    pub fields: Vec<FieldSpec>,
    pub write_style: WriteModelStyle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticMode {
    Directory,
    Spa,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticCacheProfile {
    NoStore,
    Revalidate,
    Immutable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticMountSpec {
    pub mount_path: String,
    pub source_dir: String,
    pub resolved_dir: String,
    pub mode: StaticMode,
    pub index_file: Option<String>,
    pub fallback_file: Option<String>,
    pub cache: StaticCacheProfile,
}

#[derive(Clone)]
pub struct ServiceSpec {
    pub module_ident: Ident,
    pub resources: Vec<ResourceSpec>,
    pub static_mounts: Vec<StaticMountSpec>,
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
}

impl ResourceSpec {
    pub fn find_field(&self, field_name: &str) -> Option<&FieldSpec> {
        self.fields.iter().find(|field| field.name() == field_name)
    }
}

impl std::fmt::Debug for FieldSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldSpec")
            .field("ident", &self.ident)
            .field("name", &self.name())
            .field("ty", &self.ty.to_token_stream().to_string())
            .field("sql_type", &self.sql_type)
            .field("is_id", &self.is_id)
            .field("generated", &self.generated)
            .field("relation", &self.relation)
            .field("validation", &self.validation)
            .finish()
    }
}

impl std::fmt::Debug for ResourceSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceSpec")
            .field("struct_ident", &self.struct_ident)
            .field("impl_module_ident", &self.impl_module_ident)
            .field("table_name", &self.table_name)
            .field("id_field", &self.id_field)
            .field("db", &self.db)
            .field("roles", &self.roles)
            .field("policies", &self.policies)
            .field("list", &self.list)
            .field("fields", &self.fields)
            .field("write_style", &self.write_style)
            .finish()
    }
}

impl std::fmt::Debug for ServiceSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSpec")
            .field("module_ident", &self.module_ident)
            .field("resources", &self.resources)
            .field("static_mounts", &self.static_mounts)
            .field("database", &self.database)
            .field("logging", &self.logging)
            .field("security", &self.security)
            .finish()
    }
}

pub fn default_service_database_url(service: &ServiceSpec) -> String {
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
        Some("i8" | "i16" | "i32" | "i64" | "isize") => "INTEGER".to_owned(),
        Some("u8" | "u16" | "u32" | "u64" | "usize") => "INTEGER".to_owned(),
        Some("f32" | "f64") => "REAL".to_owned(),
        Some("bool") => "BOOLEAN".to_owned(),
        _ => "TEXT".to_owned(),
    }
}

fn type_leaf_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(type_path) => {
            let segment = type_path.path.segments.last()?;
            if segment.ident == "Option" {
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    let inner_ty = args.args.iter().find_map(|arg| match arg {
                        syn::GenericArgument::Type(inner_ty) => Some(inner_ty),
                        _ => None,
                    })?;
                    return type_leaf_name(inner_ty);
                }
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

pub fn is_i64_field(ty: &Type) -> bool {
    matches!(type_leaf_name(ty).as_deref(), Some("i64"))
}

pub fn structured_scalar_kind(ty: &Type) -> Option<StructuredScalarKind> {
    match type_leaf_name(ty).as_deref() {
        Some("DateTime" | GENERATED_DATETIME_ALIAS) => Some(StructuredScalarKind::DateTime),
        Some("NaiveDate" | GENERATED_DATE_ALIAS) => Some(StructuredScalarKind::Date),
        Some("NaiveTime" | GENERATED_TIME_ALIAS) => Some(StructuredScalarKind::Time),
        Some("Uuid" | GENERATED_UUID_ALIAS) => Some(StructuredScalarKind::Uuid),
        Some("Decimal" | GENERATED_DECIMAL_ALIAS) => Some(StructuredScalarKind::Decimal),
        _ => None,
    }
}

pub fn temporal_scalar_kind(ty: &Type) -> Option<GeneratedTemporalKind> {
    structured_scalar_kind(ty).and_then(|kind| kind.generated_temporal_kind())
}

pub fn supports_range_filters(ty: &Type) -> bool {
    structured_scalar_kind(ty)
        .map(|kind| kind.supports_range_filters())
        .unwrap_or(false)
}

pub fn supports_sort(ty: &Type) -> bool {
    structured_scalar_kind(ty)
        .map(|kind| kind.supports_sort())
        .unwrap_or(true)
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

pub fn infer_generated_value(field_name: &str, is_id: bool) -> GeneratedValue {
    if is_id {
        GeneratedValue::AutoIncrement
    } else if field_name == "created_at" {
        GeneratedValue::CreatedAt
    } else if field_name == "updated_at" {
        GeneratedValue::UpdatedAt
    } else {
        GeneratedValue::None
    }
}

pub fn sanitize_struct_ident(name: &str, span: Span) -> Ident {
    let candidate = name.to_upper_camel_case();
    syn::parse_str::<Ident>(&candidate).unwrap_or_else(|_| Ident::new("GeneratedResource", span))
}

pub fn sanitize_module_ident(name: &str, span: Span) -> Ident {
    let candidate = name.to_snake_case().replace('-', "_");
    syn::parse_str::<Ident>(&candidate).unwrap_or_else(|_| Ident::new("generated_api", span))
}

pub fn is_valid_sql_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some('a'..='z' | 'A'..='Z' | '_') => {}
        _ => return false,
    }

    chars.all(|ch| matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_'))
}

pub fn validate_sql_identifier(value: &str, span: Span, label: &str) -> syn::Result<()> {
    if is_valid_sql_identifier(value) {
        Ok(())
    } else {
        Err(syn::Error::new(
            span,
            format!(
                "{label} `{value}` is not a valid SQL identifier; use only letters, digits, and underscores, and start with a letter or underscore"
            ),
        ))
    }
}

pub fn default_resource_module_ident(struct_ident: &Ident) -> Ident {
    let lower = struct_ident.to_string().to_snake_case();
    syn::Ident::new(&format!("__rest_api_impl_for_{lower}"), struct_ident.span())
}

pub fn validate_row_policies(
    fields: &[FieldSpec],
    policies: &RowPolicies,
    span: Span,
) -> syn::Result<()> {
    validate_policy_filters(fields, "read", &policies.read, span)?;
    validate_policy_assignments(fields, "create", &policies.create, span)?;
    validate_policy_filters(fields, "update", &policies.update, span)?;
    validate_policy_filters(fields, "delete", &policies.delete, span)
}

pub fn validate_relations(fields: &[FieldSpec], span: Span) -> syn::Result<()> {
    for field in fields {
        let Some(relation) = &field.relation else {
            continue;
        };

        if relation.on_delete == Some(ReferentialAction::SetNull) && !is_optional_type(&field.ty) {
            return Err(syn::Error::new(
                span,
                format!(
                    "relation field `{}` uses `on_delete = SetNull` but is not nullable",
                    field.name()
                ),
            ));
        }
    }

    Ok(())
}

pub fn validate_field_validations(fields: &[FieldSpec], span: Span) -> syn::Result<()> {
    for field in fields {
        let validation = &field.validation;
        if validation.is_empty() {
            continue;
        }

        if is_structured_scalar_type(&field.ty) {
            return Err(syn::Error::new(
                span,
                format!(
                    "field `{}` does not support validation constraints",
                    field.name()
                ),
            ));
        }

        if let (Some(min), Some(max)) = (validation.min_length, validation.max_length) {
            if min > max {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "field `{}` has `min_length` greater than `max_length`",
                        field.name()
                    ),
                ));
            }
        }

        match field.sql_type.as_str() {
            "TEXT" => {
                if validation.minimum.is_some() || validation.maximum.is_some() {
                    return Err(syn::Error::new(
                        span,
                        format!(
                            "field `{}` only supports `min_length` and `max_length` validation",
                            field.name()
                        ),
                    ));
                }
            }
            "INTEGER" => {
                if validation.min_length.is_some() || validation.max_length.is_some() {
                    return Err(syn::Error::new(
                        span,
                        format!(
                            "field `{}` only supports `minimum` and `maximum` validation",
                            field.name()
                        ),
                    ));
                }

                if !matches!(
                    (&validation.minimum, &validation.maximum),
                    (
                        None | Some(NumericBound::Integer(_)),
                        None | Some(NumericBound::Integer(_))
                    )
                ) {
                    return Err(syn::Error::new(
                        span,
                        format!(
                            "integer field `{}` requires integer `minimum` and `maximum` values",
                            field.name()
                        ),
                    ));
                }

                if let (
                    Some(NumericBound::Integer(minimum)),
                    Some(NumericBound::Integer(maximum)),
                ) = (&validation.minimum, &validation.maximum)
                {
                    if minimum > maximum {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "field `{}` has `minimum` greater than `maximum`",
                                field.name()
                            ),
                        ));
                    }
                }
            }
            "REAL" => {
                if validation.min_length.is_some() || validation.max_length.is_some() {
                    return Err(syn::Error::new(
                        span,
                        format!(
                            "field `{}` only supports `minimum` and `maximum` validation",
                            field.name()
                        ),
                    ));
                }

                if let (Some(minimum), Some(maximum)) = (&validation.minimum, &validation.maximum) {
                    if minimum.as_f64() > maximum.as_f64() {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "field `{}` has `minimum` greater than `maximum`",
                                field.name()
                            ),
                        ));
                    }
                }
            }
            _ => {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "field `{}` does not support validation constraints",
                        field.name()
                    ),
                ));
            }
        }
    }

    Ok(())
}

pub fn validate_list_config(list: &ListConfig, span: Span) -> syn::Result<()> {
    if matches!(list.default_limit, Some(0)) {
        return Err(syn::Error::new(
            span,
            "`default_limit` must be greater than 0",
        ));
    }

    if matches!(list.max_limit, Some(0)) {
        return Err(syn::Error::new(span, "`max_limit` must be greater than 0"));
    }

    if let (Some(default_limit), Some(max_limit)) = (list.default_limit, list.max_limit) {
        if default_limit > max_limit {
            return Err(syn::Error::new(
                span,
                "`default_limit` cannot be greater than `max_limit`",
            ));
        }
    }

    Ok(())
}

pub fn validate_security_config(security: &SecurityConfig, span: Span) -> syn::Result<()> {
    if matches!(security.requests.json_max_bytes, Some(0)) {
        return Err(syn::Error::new(
            span,
            "`security.requests.json_max_bytes` must be greater than 0",
        ));
    }

    if let Some(hsts) = &security.headers.hsts {
        if hsts.max_age_seconds == 0 {
            return Err(syn::Error::new(
                span,
                "`security.headers.hsts.max_age_seconds` must be greater than 0",
            ));
        }
    }

    if security.auth.access_token_ttl_seconds <= 0 {
        return Err(syn::Error::new(
            span,
            "`security.auth.access_token_ttl_seconds` must be greater than 0",
        ));
    }

    if security.auth.verification_token_ttl_seconds <= 0 {
        return Err(syn::Error::new(
            span,
            "`security.auth.verification_token_ttl_seconds` must be greater than 0",
        ));
    }

    if security.auth.password_reset_token_ttl_seconds <= 0 {
        return Err(syn::Error::new(
            span,
            "`security.auth.password_reset_token_ttl_seconds` must be greater than 0",
        ));
    }

    if security.auth.require_email_verification && security.auth.email.is_none() {
        return Err(syn::Error::new(
            span,
            "`security.auth.require_email_verification = true` requires `security.auth.email`",
        ));
    }

    if matches!(security.cors.max_age_seconds, Some(0)) {
        return Err(syn::Error::new(
            span,
            "`security.cors.max_age_seconds` must be greater than 0",
        ));
    }

    if matches!(security.cors.origins_env.as_deref(), Some("")) {
        return Err(syn::Error::new(
            span,
            "`security.cors.origins_env` cannot be empty",
        ));
    }

    let wildcard_origin = security.cors.origins.iter().any(|origin| origin == "*");
    if wildcard_origin && security.cors.allow_credentials {
        return Err(syn::Error::new(
            span,
            "`security.cors.allow_credentials` cannot be combined with wildcard `*` origins",
        ));
    }

    for origin in &security.cors.origins {
        if origin == "*" {
            continue;
        }
        Uri::try_from(origin.as_str()).map_err(|_| {
            syn::Error::new(
                span,
                format!("`security.cors.origins` contains invalid origin `{origin}`"),
            )
        })?;
    }

    for method in &security.cors.allow_methods {
        if method == "*" {
            continue;
        }
        Method::from_bytes(method.as_bytes()).map_err(|_| {
            syn::Error::new(
                span,
                format!("`security.cors.allow_methods` contains invalid method `{method}`"),
            )
        })?;
    }

    for header in security
        .cors
        .allow_headers
        .iter()
        .chain(security.cors.expose_headers.iter())
    {
        if header == "*" {
            continue;
        }
        HeaderName::try_from(header.as_str()).map_err(|_| {
            syn::Error::new(
                span,
                format!("`security.cors` contains invalid header name `{header}`"),
            )
        })?;
    }

    if matches!(security.trusted_proxies.proxies_env.as_deref(), Some("")) {
        return Err(syn::Error::new(
            span,
            "`security.trusted_proxies.proxies_env` cannot be empty",
        ));
    }

    for proxy in &security.trusted_proxies.proxies {
        IpAddr::from_str(proxy).map_err(|_| {
            syn::Error::new(
                span,
                format!("`security.trusted_proxies.proxies` contains invalid IP `{proxy}`"),
            )
        })?;
    }

    validate_rate_limit_rule("login", security.rate_limits.login, span)?;
    validate_rate_limit_rule("register", security.rate_limits.register, span)?;

    if let Some(cookie) = &security.auth.session_cookie {
        if cookie.name.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                "`security.auth.session_cookie.name` cannot be empty",
            ));
        }

        if cookie.csrf_cookie_name.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                "`security.auth.session_cookie.csrf_cookie_name` cannot be empty",
            ));
        }

        if cookie.csrf_cookie_name == cookie.name {
            return Err(syn::Error::new(
                span,
                "`security.auth.session_cookie.csrf_cookie_name` must differ from `name`",
            ));
        }

        if cookie.csrf_header_name.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                "`security.auth.session_cookie.csrf_header_name` cannot be empty",
            ));
        }

        HeaderName::try_from(cookie.csrf_header_name.as_str()).map_err(|_| {
            syn::Error::new(
                span,
                format!(
                    "`security.auth.session_cookie.csrf_header_name` contains invalid header name `{}`",
                    cookie.csrf_header_name
                ),
            )
        })?;

        if !cookie.path.starts_with('/') {
            return Err(syn::Error::new(
                span,
                "`security.auth.session_cookie.path` must start with `/`",
            ));
        }

        if matches!(cookie.same_site, SessionCookieSameSite::None) && !cookie.secure {
            return Err(syn::Error::new(
                span,
                "`security.auth.session_cookie.same_site = None` requires `secure = true`",
            ));
        }

        for (label, name) in [
            ("name", cookie.name.as_str()),
            ("csrf_cookie_name", cookie.csrf_cookie_name.as_str()),
        ] {
            if name.starts_with("__Host-") && (!cookie.secure || cookie.path != "/") {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`security.auth.session_cookie.{label}` uses the `__Host-` prefix but requires `secure = true` and `path = \"/\"`",
                    ),
                ));
            }
        }
    }

    if let Some(email) = &security.auth.email {
        if email.from_email.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                "`security.auth.email.from_email` cannot be empty",
            ));
        }
        if !email.from_email.contains('@') {
            return Err(syn::Error::new(
                span,
                "`security.auth.email.from_email` must look like an email address",
            ));
        }
        if matches!(email.reply_to.as_deref(), Some("")) {
            return Err(syn::Error::new(
                span,
                "`security.auth.email.reply_to` cannot be empty",
            ));
        }
        if let Some(public_base_url) = &email.public_base_url {
            Url::parse(public_base_url).map_err(|_| {
                syn::Error::new(
                    span,
                    "`security.auth.email.public_base_url` must be a valid absolute URL",
                )
            })?;
        }

        match &email.provider {
            AuthEmailProvider::Resend {
                api_key_env,
                api_base_url,
            } => {
                if api_key_env.trim().is_empty() {
                    return Err(syn::Error::new(
                        span,
                        "`security.auth.email.provider.api_key_env` cannot be empty",
                    ));
                }
                if let Some(api_base_url) = api_base_url {
                    Url::parse(api_base_url).map_err(|_| {
                        syn::Error::new(
                            span,
                            "`security.auth.email.provider.api_base_url` must be a valid absolute URL",
                        )
                    })?;
                }
            }
            AuthEmailProvider::Smtp { connection_url_env } => {
                if connection_url_env.trim().is_empty() {
                    return Err(syn::Error::new(
                        span,
                        "`security.auth.email.provider.connection_url_env` cannot be empty",
                    ));
                }
            }
        }
    }

    let reserved_auth_paths = [
        "/auth/register",
        "/auth/login",
        "/auth/logout",
        "/auth/me",
        "/auth/account",
        "/auth/account/password",
        "/auth/account/verification",
        "/auth/verify-email",
        "/auth/verification/resend",
        "/auth/password-reset",
        "/auth/password-reset/request",
        "/auth/password-reset/confirm",
        "/auth/admin/users",
    ];
    let mut custom_paths = std::collections::HashSet::<String>::new();
    for (label, page) in [
        ("portal", security.auth.portal.as_ref()),
        ("admin_dashboard", security.auth.admin_dashboard.as_ref()),
    ] {
        let Some(page) = page else {
            continue;
        };
        if page.path.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                format!("`security.auth.{label}.path` cannot be empty"),
            ));
        }
        if !page.path.starts_with('/') {
            return Err(syn::Error::new(
                span,
                format!("`security.auth.{label}.path` must start with `/`"),
            ));
        }
        if page.title.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                format!("`security.auth.{label}.title` cannot be empty"),
            ));
        }
        if reserved_auth_paths.contains(&page.path.as_str()) {
            return Err(syn::Error::new(
                span,
                format!(
                    "`security.auth.{label}.path` conflicts with a built-in auth route: `{}`",
                    page.path
                ),
            ));
        }
        if !custom_paths.insert(page.path.clone()) {
            return Err(syn::Error::new(span, "custom auth UI paths must be unique"));
        }
    }

    Ok(())
}

pub fn validate_logging_config(logging: &LoggingConfig, span: Span) -> syn::Result<()> {
    if logging.filter_env.trim().is_empty() {
        return Err(syn::Error::new(
            span,
            "`logging.filter_env` cannot be empty",
        ));
    }

    if logging.default_filter.trim().is_empty() {
        return Err(syn::Error::new(
            span,
            "`logging.default_filter` cannot be empty",
        ));
    }

    Ok(())
}

fn validate_rate_limit_rule(
    scope: &str,
    rule: Option<crate::security::RateLimitRule>,
    span: Span,
) -> syn::Result<()> {
    let Some(rule) = rule else {
        return Ok(());
    };

    if rule.requests == 0 {
        return Err(syn::Error::new(
            span,
            format!("`security.rate_limits.{scope}.requests` must be greater than 0"),
        ));
    }

    if rule.window_seconds == 0 {
        return Err(syn::Error::new(
            span,
            format!("`security.rate_limits.{scope}.window_seconds` must be greater than 0"),
        ));
    }

    Ok(())
}

fn validate_policy_filters(
    fields: &[FieldSpec],
    scope: &str,
    policies: &[PolicyFilter],
    span: Span,
) -> syn::Result<()> {
    let mut seen_fields = HashSet::new();
    for policy in policies {
        validate_policy_field(fields, scope, &policy.field, span)?;
        if !seen_fields.insert(policy.field.clone()) {
            return Err(syn::Error::new(
                span,
                format!(
                    "duplicate row policy field `{}` for `{scope}`",
                    policy.field
                ),
            ));
        }
    }

    Ok(())
}

fn validate_policy_assignments(
    fields: &[FieldSpec],
    scope: &str,
    policies: &[PolicyAssignment],
    span: Span,
) -> syn::Result<()> {
    let mut seen_fields = HashSet::new();
    for policy in policies {
        validate_policy_field(fields, scope, &policy.field, span)?;
        if !seen_fields.insert(policy.field.clone()) {
            return Err(syn::Error::new(
                span,
                format!(
                    "duplicate row policy field `{}` for `{scope}`",
                    policy.field
                ),
            ));
        }
    }

    Ok(())
}

fn validate_policy_field(
    fields: &[FieldSpec],
    scope: &str,
    field_name: &str,
    span: Span,
) -> syn::Result<()> {
    let field = fields
        .iter()
        .find(|field| field.name() == field_name)
        .ok_or_else(|| {
            syn::Error::new(
                span,
                format!("row policy for `{scope}` references missing field `{field_name}`"),
            )
        })?;

    if !is_i64_field(&field.ty) {
        return Err(syn::Error::new(
            span,
            format!("row policy field `{field_name}` must use type `i64` or `Option<i64>`"),
        ));
    }

    Ok(())
}
