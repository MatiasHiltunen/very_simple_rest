use std::{
    collections::{BTreeSet, HashSet},
    net::IpAddr,
    str::FromStr,
};

use actix_web::http::{Method, Uri, header::HeaderName};
use heck::{ToSnakeCase, ToUpperCamelCase};
use proc_macro2::Span;
use quote::ToTokens;
use syn::{Ident, Type};

use crate::auth::{AuthClaimType, AuthEmailProvider, SessionCookieSameSite};
use crate::authorization::AuthorizationContract;
use crate::database::{DatabaseConfig, DatabaseEngine, sqlite_url_for_path};
use crate::logging::LoggingConfig;
use crate::runtime::RuntimeConfig;
use crate::security::SecurityConfig;
use crate::tls::TlsConfig;
use url::Url;

pub const GENERATED_DATETIME_ALIAS: &str = "__VsrDateTimeUtc";
pub const GENERATED_DATE_ALIAS: &str = "__VsrNaiveDate";
pub const GENERATED_TIME_ALIAS: &str = "__VsrNaiveTime";
pub const GENERATED_UUID_ALIAS: &str = "__VsrUuid";
pub const GENERATED_DECIMAL_ALIAS: &str = "__VsrDecimal";
pub const GENERATED_JSON_ALIAS: &str = "__VsrJson";
pub const GENERATED_JSON_OBJECT_ALIAS: &str = "__VsrJsonObject";
pub const GENERATED_JSON_ARRAY_ALIAS: &str = "__VsrJsonArray";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructuredScalarKind {
    DateTime,
    Date,
    Time,
    Uuid,
    Decimal,
    Json,
    JsonObject,
    JsonArray,
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
            (Self::Json | Self::JsonObject | Self::JsonArray, DbBackend::Mysql) => "TEXT",
        }
    }

    pub fn openapi_format(self) -> Option<&'static str> {
        match self {
            Self::DateTime => Some("date-time"),
            Self::Date => Some("date"),
            Self::Time => Some("time"),
            Self::Uuid => Some("uuid"),
            Self::Decimal => Some("decimal"),
            Self::Json | Self::JsonObject | Self::JsonArray => None,
        }
    }

    pub fn supports_range_filters(self) -> bool {
        matches!(self, Self::DateTime | Self::Date | Self::Time)
    }

    pub fn supports_sort(self) -> bool {
        !matches!(
            self,
            Self::Decimal | Self::Json | Self::JsonObject | Self::JsonArray
        )
    }

    pub fn supports_exact_filters(self) -> bool {
        !matches!(self, Self::Json | Self::JsonObject | Self::JsonArray)
    }

    pub fn generated_temporal_kind(self) -> Option<GeneratedTemporalKind> {
        match self {
            Self::DateTime => Some(GeneratedTemporalKind::DateTime),
            Self::Date => Some(GeneratedTemporalKind::Date),
            Self::Time => Some(GeneratedTemporalKind::Time),
            Self::Uuid
            | Self::Decimal
            | Self::Json
            | Self::JsonObject
            | Self::JsonArray => None,
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
    InputField(String),
}

impl PolicyValueSource {
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value == "user.id" {
            Some(Self::UserId)
        } else {
            value
                .strip_prefix("claim.")
                .and_then(|claim| {
                    if claim.is_empty() {
                        None
                    } else {
                        Some(Self::Claim(claim.to_owned()))
                    }
                })
                .or_else(|| {
                    value.strip_prefix("input.").and_then(|field| {
                        if field.is_empty() {
                            None
                        } else {
                            Some(Self::InputField(field.to_owned()))
                        }
                    })
                })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyFilter {
    pub field: String,
    pub operator: PolicyFilterOperator,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyFilterOperator {
    Equals(PolicyValueSource),
    IsNull,
    IsNotNull,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyExistsCondition {
    Match(PolicyFilter),
    CurrentRowField { field: String, row_field: String },
    All(Vec<PolicyExistsCondition>),
    Any(Vec<PolicyExistsCondition>),
    Not(Box<PolicyExistsCondition>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyExistsFilter {
    pub resource: String,
    pub condition: PolicyExistsCondition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyFilterExpression {
    Match(PolicyFilter),
    All(Vec<PolicyFilterExpression>),
    Any(Vec<PolicyFilterExpression>),
    Not(Box<PolicyFilterExpression>),
    Exists(PolicyExistsFilter),
}

impl PolicyFilterExpression {
    pub fn all(expressions: Vec<Self>) -> Option<Self> {
        match expressions.len() {
            0 => None,
            1 => expressions.into_iter().next(),
            _ => Some(Self::All(expressions)),
        }
    }

    pub fn any(expressions: Vec<Self>) -> Option<Self> {
        match expressions.len() {
            0 => None,
            1 => expressions.into_iter().next(),
            _ => Some(Self::Any(expressions)),
        }
    }

    pub fn collect_filters<'a>(&'a self, filters: &mut Vec<&'a PolicyFilter>) {
        match self {
            Self::Match(filter) => filters.push(filter),
            Self::All(expressions) | Self::Any(expressions) => {
                for expression in expressions {
                    expression.collect_filters(filters);
                }
            }
            Self::Not(expression) => expression.collect_filters(filters),
            Self::Exists(filter) => filter.condition.collect_filters(filters),
        }
    }

    pub fn collect_controlled_fields(&self, fields: &mut BTreeSet<String>) {
        match self {
            Self::Match(filter) => {
                fields.insert(filter.field.clone());
            }
            Self::All(expressions) | Self::Any(expressions) => {
                for expression in expressions {
                    expression.collect_controlled_fields(fields);
                }
            }
            Self::Not(expression) => expression.collect_controlled_fields(fields),
            Self::Exists(filter) => filter.condition.collect_controlled_fields(fields),
        }
    }

    pub fn collect_exists_index_targets(&self, targets: &mut Vec<(String, String)>) {
        match self {
            Self::Match(_) => {}
            Self::All(expressions) | Self::Any(expressions) => {
                for expression in expressions {
                    expression.collect_exists_index_targets(targets);
                }
            }
            Self::Not(expression) => expression.collect_exists_index_targets(targets),
            Self::Exists(filter) => filter
                .condition
                .collect_exists_index_targets(&filter.resource, targets),
        }
    }
}

impl PolicyExistsCondition {
    pub fn all(expressions: Vec<Self>) -> Option<Self> {
        match expressions.len() {
            0 => None,
            1 => expressions.into_iter().next(),
            _ => Some(Self::All(expressions)),
        }
    }

    pub fn any(expressions: Vec<Self>) -> Option<Self> {
        match expressions.len() {
            0 => None,
            1 => expressions.into_iter().next(),
            _ => Some(Self::Any(expressions)),
        }
    }

    pub fn collect_filters<'a>(&'a self, filters: &mut Vec<&'a PolicyFilter>) {
        match self {
            Self::Match(filter) => filters.push(filter),
            Self::CurrentRowField { .. } => {}
            Self::All(expressions) | Self::Any(expressions) => {
                for expression in expressions {
                    expression.collect_filters(filters);
                }
            }
            Self::Not(expression) => expression.collect_filters(filters),
        }
    }

    pub fn collect_controlled_fields(&self, fields: &mut BTreeSet<String>) {
        match self {
            Self::Match(_) => {}
            Self::CurrentRowField { row_field, .. } => {
                fields.insert(row_field.clone());
            }
            Self::All(expressions) | Self::Any(expressions) => {
                for expression in expressions {
                    expression.collect_controlled_fields(fields);
                }
            }
            Self::Not(expression) => expression.collect_controlled_fields(fields),
        }
    }

    pub fn collect_exists_index_targets(
        &self,
        resource: &str,
        targets: &mut Vec<(String, String)>,
    ) {
        match self {
            Self::Match(condition) => {
                targets.push((resource.to_owned(), condition.field.clone()));
            }
            Self::CurrentRowField { field, .. } => {
                targets.push((resource.to_owned(), field.clone()));
            }
            Self::All(expressions) | Self::Any(expressions) => {
                for expression in expressions {
                    expression.collect_exists_index_targets(resource, targets);
                }
            }
            Self::Not(expression) => expression.collect_exists_index_targets(resource, targets),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyAssignment {
    pub field: String,
    pub source: PolicyValueSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowPolicies {
    pub admin_bypass: bool,
    pub read: Option<PolicyFilterExpression>,
    pub create_require: Option<PolicyFilterExpression>,
    pub create: Vec<PolicyAssignment>,
    pub update: Option<PolicyFilterExpression>,
    pub delete: Option<PolicyFilterExpression>,
}

impl Default for RowPolicies {
    fn default() -> Self {
        Self {
            admin_bypass: true,
            read: None,
            create_require: None,
            create: Vec::new(),
            update: None,
            delete: None,
        }
    }
}

impl RowPolicies {
    pub fn has_read_filters(&self) -> bool {
        self.read.is_some()
    }

    pub fn has_create_require_filters(&self) -> bool {
        self.create_require.is_some()
    }

    pub fn has_update_filters(&self) -> bool {
        self.update.is_some()
    }

    pub fn has_delete_filters(&self) -> bool {
        self.delete.is_some()
    }

    pub fn iter_filters(&self) -> Vec<(&'static str, &PolicyFilter)> {
        let mut filters = Vec::new();
        collect_scope_filters("read", self.read.as_ref(), &mut filters);
        collect_scope_filters("create.require", self.create_require.as_ref(), &mut filters);
        collect_scope_filters("update", self.update.as_ref(), &mut filters);
        collect_scope_filters("delete", self.delete.as_ref(), &mut filters);
        filters
    }

    pub fn controlled_filter_fields(&self) -> BTreeSet<String> {
        let mut fields = BTreeSet::new();
        collect_scope_controlled_fields(self.read.as_ref(), &mut fields);
        collect_scope_controlled_fields(self.update.as_ref(), &mut fields);
        collect_scope_controlled_fields(self.delete.as_ref(), &mut fields);
        fields
    }

    pub fn iter_assignments(&self) -> impl Iterator<Item = (&'static str, &PolicyAssignment)> {
        self.create.iter().map(|policy| ("create", policy))
    }

    pub fn exists_index_targets(&self) -> Vec<(String, String)> {
        let mut targets = Vec::new();
        collect_scope_exists_index_targets(self.read.as_ref(), &mut targets);
        collect_scope_exists_index_targets(self.create_require.as_ref(), &mut targets);
        collect_scope_exists_index_targets(self.update.as_ref(), &mut targets);
        collect_scope_exists_index_targets(self.delete.as_ref(), &mut targets);
        targets
    }
}

fn collect_scope_filters<'a>(
    scope: &'static str,
    expression: Option<&'a PolicyFilterExpression>,
    filters: &mut Vec<(&'static str, &'a PolicyFilter)>,
) {
    let Some(expression) = expression else {
        return;
    };
    let mut scoped_filters = Vec::new();
    expression.collect_filters(&mut scoped_filters);
    filters.extend(scoped_filters.into_iter().map(|filter| (scope, filter)));
}

fn collect_scope_controlled_fields(
    expression: Option<&PolicyFilterExpression>,
    fields: &mut BTreeSet<String>,
) {
    let Some(expression) = expression else {
        return;
    };
    expression.collect_controlled_fields(fields);
}

fn collect_scope_exists_index_targets(
    expression: Option<&PolicyFilterExpression>,
    targets: &mut Vec<(String, String)>,
) {
    let Some(expression) = expression else {
        return;
    };
    expression.collect_exists_index_targets(targets);
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
    pub api_name: String,
    pub expose_in_api: bool,
    pub unique: bool,
    pub enum_name: Option<String>,
    pub enum_values: Option<Vec<String>>,
    pub ty: Type,
    pub list_item_ty: Option<Type>,
    pub object_fields: Option<Vec<FieldSpec>>,
    pub sql_type: String,
    pub is_id: bool,
    pub generated: GeneratedValue,
    pub validation: FieldValidation,
    pub relation: Option<RelationSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseContextSpec {
    pub name: String,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumSpec {
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexSpec {
    pub fields: Vec<String>,
    pub unique: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManyToManySpec {
    pub name: String,
    pub target_table: String,
    pub through_table: String,
    pub source_field: String,
    pub target_field: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComputedFieldPart {
    Literal(String),
    Field(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComputedFieldSpec {
    pub api_name: String,
    pub optional: bool,
    pub parts: Vec<ComputedFieldPart>,
}

impl FieldSpec {
    pub fn name(&self) -> String {
        self.ident.to_string()
    }

    pub fn api_name(&self) -> &str {
        self.api_name.as_str()
    }

    pub fn expose_in_api(&self) -> bool {
        self.expose_in_api
    }

    pub fn enum_name(&self) -> Option<&str> {
        self.enum_name.as_deref()
    }

    pub fn enum_values(&self) -> Option<&[String]> {
        self.enum_values.as_deref()
    }
}

#[derive(Clone)]
pub struct ResourceSpec {
    pub struct_ident: Ident,
    pub impl_module_ident: Ident,
    pub table_name: String,
    pub api_name: String,
    pub default_response_context: Option<String>,
    pub response_contexts: Vec<ResponseContextSpec>,
    pub id_field: String,
    pub db: DbBackend,
    pub roles: RoleRequirements,
    pub policies: RowPolicies,
    pub list: ListConfig,
    pub indexes: Vec<IndexSpec>,
    pub many_to_many: Vec<ManyToManySpec>,
    pub computed_fields: Vec<ComputedFieldSpec>,
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
    pub enums: Vec<EnumSpec>,
    pub resources: Vec<ResourceSpec>,
    pub authorization: AuthorizationContract,
    pub static_mounts: Vec<StaticMountSpec>,
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
    pub runtime: RuntimeConfig,
    pub security: SecurityConfig,
    pub tls: TlsConfig,
}

impl ResourceSpec {
    pub fn find_field(&self, field_name: &str) -> Option<&FieldSpec> {
        self.fields.iter().find(|field| field.name() == field_name)
    }

    pub fn field_by_api_name(&self, field_name: &str) -> Option<&FieldSpec> {
        self.fields
            .iter()
            .find(|field| field.expose_in_api() && field.api_name() == field_name)
    }

    pub fn api_name(&self) -> &str {
        self.api_name.as_str()
    }

    pub fn default_response_context(&self) -> Option<&ResponseContextSpec> {
        self.default_response_context
            .as_deref()
            .and_then(|name| self.response_context(name))
    }

    pub fn response_context(&self, name: &str) -> Option<&ResponseContextSpec> {
        self.response_contexts
            .iter()
            .find(|context| context.name == name)
    }

    pub fn response_context_names(&self) -> impl Iterator<Item = &str> {
        self.response_contexts
            .iter()
            .map(|context| context.name.as_str())
    }

    pub fn response_field_names(&self) -> impl Iterator<Item = &str> {
        self.api_fields()
            .map(|field| field.api_name())
            .chain(
                self.computed_fields
                    .iter()
                    .map(|field| field.api_name.as_str()),
            )
    }

    pub fn api_fields(&self) -> impl Iterator<Item = &FieldSpec> {
        self.fields.iter().filter(|field| field.expose_in_api())
    }
}

impl std::fmt::Debug for FieldSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldSpec")
            .field("ident", &self.ident)
            .field("name", &self.name())
            .field("api_name", &self.api_name)
            .field("expose_in_api", &self.expose_in_api)
            .field("unique", &self.unique)
            .field("enum_name", &self.enum_name)
            .field("enum_values", &self.enum_values)
            .field("ty", &self.ty.to_token_stream().to_string())
            .field(
                "list_item_ty",
                &self
                    .list_item_ty
                    .as_ref()
                    .map(|ty| ty.to_token_stream().to_string()),
            )
            .field("object_fields", &self.object_fields)
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
            .field("api_name", &self.api_name)
            .field("default_response_context", &self.default_response_context)
            .field("response_contexts", &self.response_contexts)
            .field("id_field", &self.id_field)
            .field("db", &self.db)
            .field("roles", &self.roles)
            .field("policies", &self.policies)
            .field("list", &self.list)
            .field("indexes", &self.indexes)
            .field("many_to_many", &self.many_to_many)
            .field("computed_fields", &self.computed_fields)
            .field("fields", &self.fields)
            .field("write_style", &self.write_style)
            .finish()
    }
}

impl std::fmt::Debug for ServiceSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSpec")
            .field("module_ident", &self.module_ident)
            .field("enums", &self.enums)
            .field("resources", &self.resources)
            .field("authorization", &self.authorization)
            .field("static_mounts", &self.static_mounts)
            .field("database", &self.database)
            .field("logging", &self.logging)
            .field("runtime", &self.runtime)
            .field("security", &self.security)
            .field("tls", &self.tls)
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
        Some("NaiveDate" | GENERATED_DATE_ALIAS) => Some(StructuredScalarKind::Date),
        Some("NaiveTime" | GENERATED_TIME_ALIAS) => Some(StructuredScalarKind::Time),
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
    resource.roles.read.is_some() || resource.policies.has_read_filters()
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

impl IndexSpec {
    pub fn name_for_table(&self, table_name: &str) -> String {
        let prefix = if self.unique { "uidx" } else { "idx" };
        format!("{prefix}_{table_name}_{}", self.fields.join("_"))
    }
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
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    policies: &RowPolicies,
    span: Span,
) -> syn::Result<()> {
    validate_policy_filters(
        resource,
        resources,
        "read",
        policies.read.as_ref(),
        false,
        span,
    )?;
    validate_policy_filters(
        resource,
        resources,
        "create.require",
        policies.create_require.as_ref(),
        true,
        span,
    )?;
    validate_policy_assignments(&resource.fields, "create", &policies.create, span)?;
    validate_policy_filters(
        resource,
        resources,
        "update",
        policies.update.as_ref(),
        false,
        span,
    )?;
    validate_policy_filters(
        resource,
        resources,
        "delete",
        policies.delete.as_ref(),
        false,
        span,
    )
}

pub fn validate_policy_claim_sources(
    resources: &[ResourceSpec],
    security: &SecurityConfig,
    span: Span,
) -> syn::Result<()> {
    if security.auth.claims.is_empty() {
        return Ok(());
    }

    for resource in resources {
        validate_policy_claim_sources_in_expression(
            resource,
            resources,
            "read",
            resource.policies.read.as_ref(),
            security,
            span,
        )?;
        validate_policy_claim_sources_in_expression(
            resource,
            resources,
            "create.require",
            resource.policies.create_require.as_ref(),
            security,
            span,
        )?;
        validate_policy_claim_sources_in_expression(
            resource,
            resources,
            "update",
            resource.policies.update.as_ref(),
            security,
            span,
        )?;
        validate_policy_claim_sources_in_expression(
            resource,
            resources,
            "delete",
            resource.policies.delete.as_ref(),
            security,
            span,
        )?;
        for (scope, assignment) in resource.policies.iter_assignments() {
            validate_policy_claim_source(
                resource,
                scope,
                &assignment.field,
                &assignment.source,
                security,
                span,
            )?;
        }
    }

    Ok(())
}

fn validate_policy_claim_sources_in_expression(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    scope: &str,
    expression: Option<&PolicyFilterExpression>,
    security: &SecurityConfig,
    span: Span,
) -> syn::Result<()> {
    let Some(expression) = expression else {
        return Ok(());
    };
    match expression {
        PolicyFilterExpression::Match(filter) => {
            validate_policy_filter_claim_source(resource, scope, filter, security, span)
        }
        PolicyFilterExpression::All(expressions) | PolicyFilterExpression::Any(expressions) => {
            for expression in expressions {
                validate_policy_claim_sources_in_expression(
                    resource,
                    resources,
                    scope,
                    Some(expression),
                    security,
                    span,
                )?;
            }
            Ok(())
        }
        PolicyFilterExpression::Not(expression) => validate_policy_claim_sources_in_expression(
            resource,
            resources,
            scope,
            Some(expression),
            security,
            span,
        ),
        PolicyFilterExpression::Exists(filter) => {
            let target_resource = resources.iter().find(|candidate| {
                candidate.struct_ident.to_string() == filter.resource
                    || candidate.table_name == filter.resource
            });
            let Some(target_resource) = target_resource else {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "row policy for `{scope}` references unknown exists resource `{}`",
                        filter.resource
                    ),
                ));
            };
            validate_exists_policy_claim_sources(
                target_resource,
                scope,
                &filter.condition,
                security,
                span,
            )
        }
    }
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
        if let Some(nested_fields) = field.object_fields.as_deref() {
            validate_field_validations(nested_fields, span)?;
        }

        let validation = &field.validation;
        if validation.is_empty() {
            continue;
        }

        if field.enum_values.is_some() {
            return Err(syn::Error::new(
                span,
                format!("enum field `{}` does not support validation constraints", field.name()),
            ));
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
            sql_type if is_integer_sql_type(sql_type) => {
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

pub fn validate_authorization_contract(
    contract: &AuthorizationContract,
    resources: &[ResourceSpec],
    span: Span,
) -> syn::Result<()> {
    validate_authorization_management_api(&contract.management_api, span)?;

    let mut scope_names = HashSet::new();
    for scope in &contract.scopes {
        validate_authorization_identifier(&scope.name, span, "authorization scope name")?;
        if !scope_names.insert(scope.name.as_str()) {
            return Err(syn::Error::new(
                span,
                format!("duplicate authorization scope `{}`", scope.name),
            ));
        }
        if matches!(scope.description.as_deref(), Some(description) if description.trim().is_empty())
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.scopes.{}` description cannot be empty",
                    scope.name
                ),
            ));
        }
    }

    for scope in &contract.scopes {
        if let Some(parent) = &scope.parent {
            if !scope_names.contains(parent.as_str()) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.scopes.{}` references unknown parent scope `{parent}`",
                        scope.name
                    ),
                ));
            }
        }
    }
    for scope in &contract.scopes {
        let mut seen = HashSet::new();
        let mut current = scope.parent.as_deref();
        while let Some(parent) = current {
            if !seen.insert(parent) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.scopes.{}` contains a parent cycle involving `{parent}`",
                        scope.name
                    ),
                ));
            }
            current = contract
                .scopes
                .iter()
                .find(|candidate| candidate.name == parent)
                .and_then(|candidate| candidate.parent.as_deref());
        }
    }

    let resource_names = resources
        .iter()
        .map(|resource| resource.struct_ident.to_string())
        .collect::<HashSet<_>>();

    let mut permission_names = HashSet::new();
    for permission in &contract.permissions {
        validate_authorization_identifier(&permission.name, span, "authorization permission name")?;
        if !permission_names.insert(permission.name.as_str()) {
            return Err(syn::Error::new(
                span,
                format!("duplicate authorization permission `{}`", permission.name),
            ));
        }
        if matches!(permission.description.as_deref(), Some(description) if description.trim().is_empty())
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.permissions.{}` description cannot be empty",
                    permission.name
                ),
            ));
        }
        if permission.actions.is_empty() {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.permissions.{}` must declare at least one action",
                    permission.name
                ),
            ));
        }
        if permission.resources.is_empty() {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.permissions.{}` must declare at least one resource",
                    permission.name
                ),
            ));
        }
        for resource_name in &permission.resources {
            if !resource_names.contains(resource_name) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.permissions.{}` references unknown resource `{resource_name}`",
                        permission.name
                    ),
                ));
            }
        }
        for scope_name in &permission.scopes {
            if !scope_names.contains(scope_name.as_str()) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.permissions.{}` references unknown scope `{scope_name}`",
                        permission.name
                    ),
                ));
            }
        }
    }

    let permission_names = permission_names;
    let mut template_names = HashSet::new();
    for template in &contract.templates {
        validate_authorization_identifier(&template.name, span, "authorization template name")?;
        if !template_names.insert(template.name.as_str()) {
            return Err(syn::Error::new(
                span,
                format!("duplicate authorization template `{}`", template.name),
            ));
        }
        if matches!(template.description.as_deref(), Some(description) if description.trim().is_empty())
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.templates.{}` description cannot be empty",
                    template.name
                ),
            ));
        }
        if template.permissions.is_empty() {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.templates.{}` must declare at least one permission",
                    template.name
                ),
            ));
        }
        for permission_name in &template.permissions {
            if !permission_names.contains(permission_name.as_str()) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.templates.{}` references unknown permission `{permission_name}`",
                        template.name
                    ),
                ));
            }
        }
        for scope_name in &template.scopes {
            if !scope_names.contains(scope_name.as_str()) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.templates.{}` references unknown scope `{scope_name}`",
                        template.name
                    ),
                ));
            }
        }
    }

    validate_authorization_hybrid_enforcement(contract, resources, &scope_names, span)?;

    Ok(())
}

fn validate_authorization_hybrid_enforcement(
    contract: &AuthorizationContract,
    resources: &[ResourceSpec],
    scope_names: &HashSet<&str>,
    span: Span,
) -> syn::Result<()> {
    let mut seen_resources = HashSet::new();
    for config in &contract.hybrid_enforcement.resources {
        if !seen_resources.insert(config.resource.as_str()) {
            return Err(syn::Error::new(
                span,
                format!(
                    "duplicate authorization hybrid enforcement resource `{}`",
                    config.resource
                ),
            ));
        }

        let resource = resources
            .iter()
            .find(|resource| resource.struct_ident.to_string() == config.resource)
            .ok_or_else(|| {
                syn::Error::new(
                    span,
                    format!(
                        "`authorization.hybrid_enforcement.resources.{}` references unknown resource `{}`",
                        config.resource, config.resource
                    ),
                )
            })?;

        if !scope_names.contains(config.scope.as_str()) {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}` references unknown scope `{}`",
                    config.resource, config.scope
                ),
            ));
        }

        let field = resource.find_field(&config.scope_field).ok_or_else(|| {
            syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}.scope_field` references missing field `{}`",
                    config.resource, config.scope_field
                ),
            )
        })?;

        if policy_field_claim_type(&field.ty).is_none() {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}.scope_field` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types",
                    config.resource
                ),
            ));
        }

        if config.scope_sources.collection_filter
            && !config.supports_action(crate::authorization::AuthorizationAction::Read)
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}` `scope_sources.collection_filter` requires `Read`",
                    config.resource
                ),
            ));
        }
        if config.scope_sources.nested_parent
            && !config.supports_action(crate::authorization::AuthorizationAction::Read)
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}` `scope_sources.nested_parent` requires `Read`",
                    config.resource
                ),
            ));
        }
        if config.scope_sources.create_payload
            && !config.supports_action(crate::authorization::AuthorizationAction::Create)
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}` `scope_sources.create_payload` requires `Create`",
                    config.resource
                ),
            ));
        }
        if config.scope_sources.item
            && !config.supports_action(crate::authorization::AuthorizationAction::Read)
            && !config.supports_action(crate::authorization::AuthorizationAction::Update)
            && !config.supports_action(crate::authorization::AuthorizationAction::Delete)
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}` `scope_sources.item` requires `Read`, `Update`, or `Delete`",
                    config.resource
                ),
            ));
        }

        if config.actions.is_empty() {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}` must declare at least one action",
                    config.resource
                ),
            ));
        }

        let mut seen_actions = HashSet::new();
        for action in &config.actions {
            if !seen_actions.insert(*action) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.hybrid_enforcement.resources.{}` contains duplicate action `{:?}`",
                        config.resource, action
                    ),
                ));
            }

            match action {
                crate::authorization::AuthorizationAction::Read => {
                    if !read_requires_auth(resource) {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` cannot enable `Read` for a public resource; add read auth first",
                                config.resource
                            ),
                        ));
                    }
                    if !resource.policies.has_read_filters() {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Read` requires a static read row policy to supplement",
                                config.resource
                            ),
                        ));
                    }
                    if !config.scope_sources.item
                        && !config.scope_sources.collection_filter
                        && !config.scope_sources.nested_parent
                    {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Read` requires at least one of `scope_sources.item`, `scope_sources.collection_filter`, or `scope_sources.nested_parent`",
                                config.resource
                            ),
                        ));
                    }
                }
                crate::authorization::AuthorizationAction::Update => {
                    if !resource.policies.has_update_filters() {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Update` requires a static update row policy to supplement",
                                config.resource
                            ),
                        ));
                    }
                    if !config.scope_sources.item {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Update` requires `scope_sources.item = true`",
                                config.resource
                            ),
                        ));
                    }
                }
                crate::authorization::AuthorizationAction::Delete => {
                    if !resource.policies.has_delete_filters() {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Delete` requires a static delete row policy to supplement",
                                config.resource
                            ),
                        ));
                    }
                    if !config.scope_sources.item {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Delete` requires `scope_sources.item = true`",
                                config.resource
                            ),
                        ));
                    }
                }
                crate::authorization::AuthorizationAction::Create => {
                    if !config.scope_sources.create_payload {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Create` requires `scope_sources.create_payload = true`",
                                config.resource
                            ),
                        ));
                    }
                    let Some(assignment) = resource
                        .policies
                        .create
                        .iter()
                        .find(|assignment| assignment.field == config.scope_field)
                    else {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Create` requires `{}` to be assigned by a static create policy",
                                config.resource, config.scope_field
                            ),
                        ));
                    };
                    if !matches!(assignment.source, PolicyValueSource::Claim(_)) {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Create` requires `{}` to be claim-controlled in `policies.create`",
                                config.resource, config.scope_field
                            ),
                        ));
                    }
                }
            }

            let has_permission = contract.permissions.iter().any(|permission| {
                permission.supports_scope(&config.scope)
                    && permission.matches_resource_action(&config.resource, *action)
            });
            if !has_permission {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.hybrid_enforcement.resources.{}` action `{:?}` has no matching declared permission for resource `{}` and scope `{}`",
                        config.resource, action, config.resource, config.scope
                    ),
                ));
            }
        }
    }

    Ok(())
}

fn validate_authorization_management_api(
    config: &crate::authorization::AuthorizationManagementApiConfig,
    span: Span,
) -> syn::Result<()> {
    if config.mount.trim().is_empty() {
        return Err(syn::Error::new(
            span,
            "`authorization.management_api.mount` cannot be empty",
        ));
    }

    if !config.mount.starts_with('/') {
        return Err(syn::Error::new(
            span,
            "`authorization.management_api.mount` must start with `/`",
        ));
    }

    if config.mount.contains("//") {
        return Err(syn::Error::new(
            span,
            "`authorization.management_api.mount` cannot contain `//`",
        ));
    }

    Ok(())
}

fn validate_authorization_identifier(value: &str, span: Span, label: &str) -> syn::Result<()> {
    if is_valid_sql_identifier(value) {
        Ok(())
    } else {
        Err(syn::Error::new(
            span,
            format!(
                "{label} `{value}` is not valid; use only letters, digits, and underscores, and start with a letter or underscore"
            ),
        ))
    }
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

    for (claim_name, mapping) in &security.auth.claims {
        if !is_valid_sql_identifier(claim_name) {
            return Err(syn::Error::new(
                span,
                format!(
                    "`security.auth.claims.{claim_name}` is not a valid claim identifier; use only letters, digits, and underscores, and start with a letter or underscore"
                ),
            ));
        }

        if is_reserved_auth_claim_name(claim_name) {
            return Err(syn::Error::new(
                span,
                format!("`security.auth.claims.{claim_name}` uses a reserved JWT/auth field name"),
            ));
        }

        validate_sql_identifier(
            &mapping.column,
            span,
            &format!("`security.auth.claims.{claim_name}.column`"),
        )?;
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

fn validate_policy_claim_source(
    resource: &ResourceSpec,
    scope: &str,
    field_name: &str,
    source: &PolicyValueSource,
    security: &SecurityConfig,
    span: Span,
) -> syn::Result<()> {
    let PolicyValueSource::Claim(claim_name) = source else {
        return Ok(());
    };

    let field = resource
        .fields
        .iter()
        .find(|field| field.name() == field_name)
        .ok_or_else(|| {
            syn::Error::new(
                span,
                format!(
                    "resource `{}` {scope} row policy references missing field `{field_name}`",
                    resource.struct_ident,
                ),
            )
        })?;
    let expected_ty = policy_field_claim_type(&field.ty).ok_or_else(|| {
        syn::Error::new(
            span,
            format!(
                "resource `{}` {scope} row policy field `{field_name}` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types",
                resource.struct_ident,
            ),
        )
    })?;

    if let Some(mapping) = security.auth.claims.get(claim_name) {
        if mapping.ty != expected_ty {
            return Err(syn::Error::new(
                span,
                format!(
                    "resource `{}` {scope} row policy for field `{field_name}` uses `claim.{claim_name}`, but `security.auth.claims.{claim_name}` is `{}` while the field expects `{}`",
                    resource.struct_ident,
                    auth_claim_type_label(mapping.ty),
                    auth_claim_type_label(expected_ty),
                ),
            ));
        }
        return Ok(());
    }

    if legacy_auth_claim_name_supported(claim_name) && expected_ty == AuthClaimType::I64 {
        return Ok(());
    }

    Err(syn::Error::new(
        span,
        format!(
            "resource `{}` {scope} row policy for field `{field_name}` references undeclared `claim.{claim_name}`; declare `security.auth.claims.{claim_name}`{}",
            resource.struct_ident,
            if expected_ty == AuthClaimType::I64 {
                " or keep using a legacy numeric `*_id` claim"
            } else {
                ""
            },
        ),
    ))
}

fn validate_policy_filter_claim_source(
    resource: &ResourceSpec,
    scope: &str,
    filter: &PolicyFilter,
    security: &SecurityConfig,
    span: Span,
) -> syn::Result<()> {
    match &filter.operator {
        PolicyFilterOperator::Equals(source) => match source {
            PolicyValueSource::InputField(_) => Ok(()),
            _ => {
                validate_policy_claim_source(resource, scope, &filter.field, source, security, span)
            }
        },
        PolicyFilterOperator::IsNull | PolicyFilterOperator::IsNotNull => Ok(()),
    }
}

fn legacy_auth_claim_name_supported(claim_name: &str) -> bool {
    claim_name.ends_with("_id") && claim_name != "id"
}

fn is_reserved_auth_claim_name(claim_name: &str) -> bool {
    matches!(claim_name, "sub" | "roles" | "iss" | "aud" | "exp" | "id")
}

fn auth_claim_type_label(ty: AuthClaimType) -> &'static str {
    match ty {
        AuthClaimType::I64 => "I64",
        AuthClaimType::String => "String",
        AuthClaimType::Bool => "Bool",
    }
}

pub fn validate_runtime_config(_runtime: &RuntimeConfig, _span: Span) -> syn::Result<()> {
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

pub fn validate_tls_config(tls: &TlsConfig, span: Span) -> syn::Result<()> {
    if !tls.is_enabled() {
        return Ok(());
    }

    if tls
        .cert_path
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(syn::Error::new(span, "`tls.cert_path` cannot be empty"));
    }

    if tls
        .key_path
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(syn::Error::new(span, "`tls.key_path` cannot be empty"));
    }

    if tls
        .cert_path_env
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(syn::Error::new(span, "`tls.cert_path_env` cannot be empty"));
    }

    if tls
        .key_path_env
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(syn::Error::new(span, "`tls.key_path_env` cannot be empty"));
    }

    if tls.cert_path.is_none() && tls.cert_path_env.is_none() {
        return Err(syn::Error::new(
            span,
            "`tls.cert_path` or `tls.cert_path_env` must be configured when TLS is enabled",
        ));
    }

    if tls.key_path.is_none() && tls.key_path_env.is_none() {
        return Err(syn::Error::new(
            span,
            "`tls.key_path` or `tls.key_path_env` must be configured when TLS is enabled",
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
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    scope: &str,
    expression: Option<&PolicyFilterExpression>,
    allow_input_fields: bool,
    span: Span,
) -> syn::Result<()> {
    let Some(expression) = expression else {
        return Ok(());
    };
    validate_policy_filter_expression(
        resource,
        resources,
        scope,
        expression,
        allow_input_fields,
        span,
    )
}

fn validate_policy_filter_expression(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    scope: &str,
    expression: &PolicyFilterExpression,
    allow_input_fields: bool,
    span: Span,
) -> syn::Result<()> {
    match expression {
        PolicyFilterExpression::Match(policy) => {
            let field = validate_policy_field(&resource.fields, scope, &policy.field, span)?;
            validate_policy_filter_operator(
                resource,
                scope,
                &policy.field,
                field,
                &policy.operator,
                allow_input_fields,
                span,
            )
        }
        PolicyFilterExpression::All(expressions) | PolicyFilterExpression::Any(expressions) => {
            for expression in expressions {
                validate_policy_filter_expression(
                    resource,
                    resources,
                    scope,
                    expression,
                    allow_input_fields,
                    span,
                )?;
            }
            Ok(())
        }
        PolicyFilterExpression::Not(expression) => validate_policy_filter_expression(
            resource,
            resources,
            scope,
            expression,
            allow_input_fields,
            span,
        ),
        PolicyFilterExpression::Exists(filter) => validate_exists_policy_filter(
            resource,
            resources,
            scope,
            filter,
            allow_input_fields,
            span,
        ),
    }
}

fn validate_exists_policy_filter(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    scope: &str,
    filter: &PolicyExistsFilter,
    allow_input_fields: bool,
    span: Span,
) -> syn::Result<()> {
    let target_resource = resources.iter().find(|candidate| {
        candidate.struct_ident.to_string() == filter.resource
            || candidate.table_name == filter.resource
    });
    let Some(target_resource) = target_resource else {
        return Err(syn::Error::new(
            span,
            format!(
                "row policy for `{scope}` references unknown exists resource `{}`",
                filter.resource
            ),
        ));
    };

    validate_exists_policy_condition(
        resource,
        target_resource,
        scope,
        &filter.condition,
        allow_input_fields,
        span,
    )
}

fn validate_exists_policy_condition(
    resource: &ResourceSpec,
    target_resource: &ResourceSpec,
    scope: &str,
    condition: &PolicyExistsCondition,
    allow_input_fields: bool,
    span: Span,
) -> syn::Result<()> {
    match condition {
        PolicyExistsCondition::Match(policy) => {
            let field = validate_policy_field(&target_resource.fields, scope, &policy.field, span)?;
            validate_policy_filter_operator(
                resource,
                scope,
                &policy.field,
                field,
                &policy.operator,
                allow_input_fields,
                span,
            )
        }
        PolicyExistsCondition::CurrentRowField { field, row_field } => {
            let target_field = validate_policy_field(&target_resource.fields, scope, field, span)?;
            let row_field_spec = validate_policy_field(&resource.fields, scope, row_field, span)?;
            let target_ty = policy_field_claim_type(&target_field.ty).ok_or_else(|| {
                syn::Error::new(
                    span,
                    format!(
                        "exists row policy field `{field}` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types"
                    ),
                )
            })?;
            let row_ty = policy_field_claim_type(&row_field_spec.ty).ok_or_else(|| {
                syn::Error::new(
                    span,
                    format!(
                        "exists row policy outer field `{row_field}` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types"
                    ),
                )
            })?;
            if target_ty != row_ty {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "exists row policy `{field} = row.{row_field}` compares incompatible field types `{}` and `{}`",
                        auth_claim_type_label(target_ty),
                        auth_claim_type_label(row_ty),
                    ),
                ));
            }
            Ok(())
        }
        PolicyExistsCondition::All(expressions) | PolicyExistsCondition::Any(expressions) => {
            for expression in expressions {
                validate_exists_policy_condition(
                    resource,
                    target_resource,
                    scope,
                    expression,
                    allow_input_fields,
                    span,
                )?;
            }
            Ok(())
        }
        PolicyExistsCondition::Not(expression) => validate_exists_policy_condition(
            resource,
            target_resource,
            scope,
            expression,
            allow_input_fields,
            span,
        ),
    }
}

fn validate_exists_policy_claim_sources(
    target_resource: &ResourceSpec,
    scope: &str,
    condition: &PolicyExistsCondition,
    security: &SecurityConfig,
    span: Span,
) -> syn::Result<()> {
    match condition {
        PolicyExistsCondition::Match(condition) => {
            validate_policy_filter_claim_source(target_resource, scope, condition, security, span)
        }
        PolicyExistsCondition::CurrentRowField { .. } => Ok(()),
        PolicyExistsCondition::All(expressions) | PolicyExistsCondition::Any(expressions) => {
            for expression in expressions {
                validate_exists_policy_claim_sources(
                    target_resource,
                    scope,
                    expression,
                    security,
                    span,
                )?;
            }
            Ok(())
        }
        PolicyExistsCondition::Not(expression) => {
            validate_exists_policy_claim_sources(target_resource, scope, expression, security, span)
        }
    }
}

fn validate_policy_filter_operator(
    source_resource: &ResourceSpec,
    scope: &str,
    field_name: &str,
    field: &FieldSpec,
    operator: &PolicyFilterOperator,
    allow_input_fields: bool,
    span: Span,
) -> syn::Result<()> {
    match operator {
        PolicyFilterOperator::Equals(source) => {
            if let PolicyValueSource::InputField(input_field_name) = source {
                if !allow_input_fields {
                    return Err(syn::Error::new(
                        span,
                        format!(
                            "{scope} row policy field `{field_name}` cannot use `input.{input_field_name}`"
                        ),
                    ));
                }

                let expected_ty = policy_field_claim_type(&field.ty).ok_or_else(|| {
                    syn::Error::new(
                        span,
                        format!(
                            "row policy field `{field_name}` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types"
                        ),
                    )
                })?;
                let input_field =
                    validate_policy_field(&source_resource.fields, scope, input_field_name, span)?;
                let input_ty = policy_field_claim_type(&input_field.ty).ok_or_else(|| {
                    syn::Error::new(
                        span,
                        format!(
                            "input row policy field `{input_field_name}` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types"
                        ),
                    )
                })?;
                if expected_ty != input_ty {
                    return Err(syn::Error::new(
                        span,
                        format!(
                            "{scope} row policy `{field_name} = input.{input_field_name}` compares incompatible field types `{}` and `{}`",
                            auth_claim_type_label(expected_ty),
                            auth_claim_type_label(input_ty),
                        ),
                    ));
                }
            }
            Ok(())
        }
        PolicyFilterOperator::IsNull | PolicyFilterOperator::IsNotNull => {
            if is_optional_type(&field.ty) {
                Ok(())
            } else {
                Err(syn::Error::new(
                    span,
                    format!(
                        "{scope} row policy null checks require nullable/optional field `{field_name}`"
                    ),
                ))
            }
        }
    }
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

fn validate_policy_field<'a>(
    fields: &'a [FieldSpec],
    scope: &str,
    field_name: &str,
    span: Span,
) -> syn::Result<&'a FieldSpec> {
    let field = fields
        .iter()
        .find(|field| field.name() == field_name)
        .ok_or_else(|| {
            syn::Error::new(
                span,
                format!("row policy for `{scope}` references missing field `{field_name}`"),
            )
        })?;

    if policy_field_claim_type(&field.ty).is_none() {
        return Err(syn::Error::new(
            span,
            format!(
                "row policy field `{field_name}` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types"
            ),
        ));
    }

    Ok(field)
}
