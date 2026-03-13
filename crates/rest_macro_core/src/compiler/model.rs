use std::collections::HashSet;

use heck::{ToSnakeCase, ToUpperCamelCase};
use proc_macro2::Span;
use syn::{Ident, Type};

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
    pub foreign_key: String,
    pub references_table: String,
    pub references_field: String,
    #[serde(default)]
    pub nested_route: bool,
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
}

impl ResourceSpec {
    pub fn find_field(&self, field_name: &str) -> Option<&FieldSpec> {
        self.fields.iter().find(|field| field.name() == field_name)
    }
}

pub fn infer_sql_type(ty: &Type) -> String {
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

pub fn is_i64_field(ty: &Type) -> bool {
    matches!(type_leaf_name(ty).as_deref(), Some("i64"))
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
