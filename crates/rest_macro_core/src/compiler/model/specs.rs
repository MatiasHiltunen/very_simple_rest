//! Resource, field, and service spec types.
//!
//! These are the heaviest data structures in the compiler model — they
//! reference everything from `scalars`, `policies`, and `validation`. They
//! are kept in their own file so the spec graph reads coherently in one place.

use proc_macro2::Span;
use quote::ToTokens;
use serde_json::Value as JsonValue;
use syn::{Ident, Type};

use crate::authorization::AuthorizationContract;
use crate::database::DatabaseConfig;
use crate::logging::LoggingConfig;
use crate::runtime::RuntimeConfig;
use crate::security::SecurityConfig;
use crate::storage::StorageConfig;
use crate::tls::TlsConfig;

use super::policies::RowPolicies;
use super::scalars::{DbBackend, GeneratedValue, ResourceAccess, RoleRequirements};
use super::validation::{
    BuildConfig, ClientsConfig, FieldTransform, FieldValidation, ListConfig, WriteModelStyle,
};

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

#[derive(Clone)]
pub struct FieldSpec {
    pub ident: Ident,
    pub api_name: String,
    pub expose_in_api: bool,
    pub unique: bool,
    pub enum_name: Option<String>,
    pub enum_values: Option<Vec<String>>,
    pub transforms: Vec<FieldTransform>,
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

impl IndexSpec {
    pub fn name_for_table(&self, table_name: &str) -> String {
        let prefix = if self.unique { "uidx" } else { "idx" };
        format!("{prefix}_{table_name}_{}", self.fields.join("_"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManyToManySpec {
    pub name: String,
    pub target_table: String,
    pub through_table: String,
    pub source_field: String,
    pub target_field: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceActionTarget {
    Item,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceActionMethod {
    Post,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ResourceActionValueSpec {
    Literal(JsonValue),
    InputField(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceActionInputFieldSpec {
    pub name: String,
    pub target_field: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResourceActionAssignmentSpec {
    pub field: String,
    pub value: ResourceActionValueSpec,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ResourceActionBehaviorSpec {
    UpdateFields {
        assignments: Vec<ResourceActionAssignmentSpec>,
    },
    DeleteResource,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResourceActionSpec {
    pub name: String,
    pub path: String,
    pub target: ResourceActionTarget,
    pub method: ResourceActionMethod,
    pub input_fields: Vec<ResourceActionInputFieldSpec>,
    pub behavior: ResourceActionBehaviorSpec,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceAuditActionSelection {
    All,
    Named(Vec<String>),
}

impl ResourceAuditActionSelection {
    pub fn audits_action(&self, action_name: &str) -> bool {
        match self {
            Self::All => true,
            Self::Named(actions) => actions.iter().any(|candidate| candidate == action_name),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceAuditConfig {
    pub resource: String,
    pub create: bool,
    pub update: bool,
    pub delete: bool,
    pub actions: Option<ResourceAuditActionSelection>,
}

impl ResourceAuditConfig {
    pub fn audits_create(&self) -> bool {
        self.create
    }

    pub fn audits_update(&self) -> bool {
        self.update
    }

    pub fn audits_delete(&self) -> bool {
        self.delete
    }

    pub fn audits_action(&self, action_name: &str) -> bool {
        self.actions
            .as_ref()
            .is_some_and(|selection| selection.audits_action(action_name))
    }

    pub fn is_enabled(&self) -> bool {
        self.create || self.update || self.delete || self.actions.is_some()
    }
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

    pub fn transforms(&self) -> &[FieldTransform] {
        self.transforms.as_slice()
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
    pub access: ResourceAccess,
    pub roles: RoleRequirements,
    pub policies: RowPolicies,
    pub list: ListConfig,
    pub indexes: Vec<IndexSpec>,
    pub many_to_many: Vec<ManyToManySpec>,
    pub actions: Vec<ResourceActionSpec>,
    pub audit: Option<ResourceAuditConfig>,
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
    pub storage: StorageConfig,
    pub database: DatabaseConfig,
    pub build: BuildConfig,
    pub clients: ClientsConfig,
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
        self.api_fields().map(|field| field.api_name()).chain(
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
            .field("transforms", &self.transforms)
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
            .field("access", &self.access)
            .field("roles", &self.roles)
            .field("policies", &self.policies)
            .field("list", &self.list)
            .field("indexes", &self.indexes)
            .field("many_to_many", &self.many_to_many)
            .field("actions", &self.actions)
            .field("audit", &self.audit)
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
            .field("storage", &self.storage)
            .field("database", &self.database)
            .field("build", &self.build)
            .field("clients", &self.clients)
            .field("logging", &self.logging)
            .field("runtime", &self.runtime)
            .field("security", &self.security)
            .field("tls", &self.tls)
            .finish()
    }
}

pub fn sanitize_struct_ident(name: &str, span: Span) -> Ident {
    use heck::ToUpperCamelCase;
    let candidate = name.to_upper_camel_case();
    syn::parse_str::<Ident>(&candidate).unwrap_or_else(|_| Ident::new("GeneratedResource", span))
}

pub fn sanitize_module_ident(name: &str, span: Span) -> Ident {
    use heck::ToSnakeCase;
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
    use heck::ToSnakeCase;
    let lower = struct_ident.to_string().to_snake_case();
    syn::Ident::new(&format!("__rest_api_impl_for_{lower}"), struct_ident.span())
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
