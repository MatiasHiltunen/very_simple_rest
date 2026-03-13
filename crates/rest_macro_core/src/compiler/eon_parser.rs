use std::{
    collections::HashSet,
    env, fs,
    path::{Component, Path, PathBuf},
};

use heck::ToSnakeCase;
use proc_macro2::Span;
use syn::{LitStr, Type};

use super::model::{
    DbBackend, FieldSpec, GeneratedValue, PolicyAssignment, PolicyFilter, PolicyValueSource,
    ReferentialAction, ResourceSpec, RoleRequirements, RowPolicies, RowPolicyKind, ServiceSpec,
    StaticCacheProfile, StaticMode, StaticMountSpec, WriteModelStyle,
    default_resource_module_ident, infer_generated_value, infer_sql_type, sanitize_module_ident,
    sanitize_struct_ident, validate_relations, validate_row_policies,
};

pub struct LoadedService {
    pub service: ServiceSpec,
    pub include_path: String,
}

#[derive(serde::Deserialize)]
struct ServiceDocument {
    #[serde(default)]
    module: Option<String>,
    #[serde(default)]
    db: DbBackend,
    #[serde(default, rename = "static")]
    static_config: Option<StaticConfigDocument>,
    resources: Vec<ResourceDocument>,
}

#[derive(Default, serde::Deserialize)]
struct StaticConfigDocument {
    #[serde(default)]
    mounts: Vec<StaticMountDocument>,
}

#[derive(serde::Deserialize)]
struct StaticMountDocument {
    mount: String,
    dir: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    index_file: Option<String>,
    #[serde(default)]
    fallback_file: Option<String>,
    #[serde(default)]
    cache: Option<String>,
}

#[derive(serde::Deserialize)]
struct ResourceDocument {
    name: String,
    #[serde(default)]
    table: Option<String>,
    #[serde(default)]
    id_field: Option<String>,
    #[serde(default)]
    roles: RoleRequirements,
    #[serde(default)]
    policies: RowPoliciesDocument,
    fields: Vec<FieldDocument>,
}

#[derive(Default, serde::Deserialize)]
struct RowPoliciesDocument {
    #[serde(default = "default_admin_bypass")]
    admin_bypass: bool,
    #[serde(default)]
    read: Option<ScopePoliciesDocument>,
    #[serde(default)]
    create: Option<ScopePoliciesDocument>,
    #[serde(default)]
    update: Option<ScopePoliciesDocument>,
    #[serde(default)]
    delete: Option<ScopePoliciesDocument>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ScopePoliciesDocument {
    Single(PolicyEntryDocument),
    Many(Vec<PolicyEntryDocument>),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum PolicyEntryDocument {
    Legacy(LegacyRowPolicyDocument),
    Rule(PolicyRuleDocument),
    Shorthand(String),
}

#[derive(serde::Deserialize)]
struct LegacyRowPolicyDocument {
    kind: String,
    field: String,
}

#[derive(serde::Deserialize)]
struct PolicyRuleDocument {
    field: String,
    #[serde(default)]
    equals: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(serde::Deserialize)]
struct FieldDocument {
    name: String,
    #[serde(rename = "type")]
    ty: FieldTypeDocument,
    #[serde(default)]
    nullable: bool,
    #[serde(default)]
    id: bool,
    #[serde(default)]
    generated: GeneratedValue,
    #[serde(default)]
    relation: Option<RelationDocument>,
}

#[derive(serde::Deserialize)]
struct RelationDocument {
    references: String,
    #[serde(default)]
    on_delete: Option<String>,
    #[serde(default)]
    nested_route: bool,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum FieldTypeDocument {
    Scalar(ScalarType),
    Rust(String),
}

#[derive(Clone, Copy, serde::Deserialize)]
enum ScalarType {
    String,
    I32,
    I64,
    F32,
    F64,
    Bool,
}

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

    let resources = build_resources(document.db, document.resources)?;
    if resources.is_empty() {
        return Err(syn::Error::new(
            span,
            "service config must contain at least one resource",
        ));
    }

    Ok(LoadedService {
        service: ServiceSpec {
            module_ident,
            resources,
            static_mounts,
        },
        include_path,
    })
}

fn build_resources(
    db: DbBackend,
    resources: Vec<ResourceDocument>,
) -> syn::Result<Vec<ResourceSpec>> {
    let mut seen_names = HashSet::new();
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
        let configured_id = resource.id_field.unwrap_or_else(|| "id".to_owned());

        let mut seen_fields = HashSet::new();
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

            let is_id = field.id || field.name == configured_id;
            let generated = match field.generated {
                GeneratedValue::None => infer_generated_value(&field.name, is_id),
                other => other,
            };

            let ty = parse_field_type(
                &field.ty,
                field.nullable || generated != GeneratedValue::None,
            )?;
            let sql_type = infer_sql_type(&ty);

            let relation = match field.relation {
                Some(relation) => Some(parse_relation_document(&field.name, relation)?),
                None => None,
            };

            fields.push(FieldSpec {
                ident: syn::parse_str(&field.name).map_err(|_| {
                    syn::Error::new(
                        Span::call_site(),
                        format!("field name `{}` is not a valid Rust identifier", field.name),
                    )
                })?,
                ty,
                sql_type,
                is_id,
                generated,
                relation,
            });
        }

        if !fields.iter().any(|field| field.name() == configured_id) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("configured id field `{configured_id}` does not exist on `{struct_name}`"),
            ));
        }

        result.push(ResourceSpec {
            struct_ident: struct_ident.clone(),
            impl_module_ident: default_resource_module_ident(&struct_ident),
            table_name,
            id_field: configured_id,
            db,
            roles: resource.roles.with_legacy_defaults(),
            policies: parse_row_policies(resource.policies)?,
            fields,
            write_style: WriteModelStyle::GeneratedStructWithDtos,
        });

        let last = result.last().expect("just pushed resource");
        validate_row_policies(&last.fields, &last.policies, Span::call_site())?;
        validate_relations(&last.fields, Span::call_site())?;
    }

    Ok(result)
}

fn build_static_mounts(
    service_root: &Path,
    static_config: Option<StaticConfigDocument>,
) -> syn::Result<Vec<StaticMountSpec>> {
    let service_root = service_root
        .canonicalize()
        .unwrap_or_else(|_| service_root.to_path_buf());
    let Some(static_config) = static_config else {
        return Ok(Vec::new());
    };

    let mut mounts = Vec::with_capacity(static_config.mounts.len());
    let mut seen_mounts = HashSet::new();
    for mount in static_config.mounts {
        let mount_path = normalize_mount_path(&mount.mount)?;
        if !seen_mounts.insert(mount_path.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate static mount `{mount_path}`"),
            ));
        }
        validate_mount_path(&mount_path)?;

        let source_dir = validate_relative_path(&mount.dir, "static dir")?;
        let resolved_dir = resolve_directory_under_root(&service_root, &source_dir)?;
        let mode = parse_static_mode(mount.mode.as_deref().unwrap_or("Directory"))?;
        let cache = parse_static_cache_profile(mount.cache.as_deref().unwrap_or("Revalidate"))?;
        let index_file = mount
            .index_file
            .as_deref()
            .map(|value| validate_relative_path(value, "static index_file"))
            .transpose()?;
        let fallback_file = mount
            .fallback_file
            .as_deref()
            .map(|value| validate_relative_path(value, "static fallback_file"))
            .transpose()?;

        let (index_file, fallback_file) = match mode {
            StaticMode::Directory => (index_file, fallback_file),
            StaticMode::Spa => (
                Some(index_file.unwrap_or_else(|| "index.html".to_owned())),
                Some(fallback_file.unwrap_or_else(|| "index.html".to_owned())),
            ),
        };

        if let Some(index_file) = &index_file {
            resolve_file_under_root(&resolved_dir, index_file, "static index_file")?;
        }
        if let Some(fallback_file) = &fallback_file {
            resolve_file_under_root(&resolved_dir, fallback_file, "static fallback_file")?;
        }

        mounts.push(StaticMountSpec {
            mount_path,
            source_dir,
            resolved_dir: resolved_dir.display().to_string(),
            mode,
            index_file,
            fallback_file,
            cache,
        });
    }

    Ok(mounts)
}

fn normalize_mount_path(value: &str) -> syn::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "static mount path cannot be empty",
        ));
    }

    if !trimmed.starts_with('/') {
        return Err(syn::Error::new(
            Span::call_site(),
            "static mount path must start with `/`",
        ));
    }

    if trimmed != "/" && trimmed.ends_with('/') {
        return Ok(trimmed.trim_end_matches('/').to_owned());
    }

    Ok(trimmed.to_owned())
}

fn validate_mount_path(mount_path: &str) -> syn::Result<()> {
    if matches!(mount_path, "/api" | "/auth" | "/docs" | "/openapi.json") {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("static mount `{mount_path}` conflicts with a reserved route"),
        ));
    }

    if mount_path.contains("//") {
        return Err(syn::Error::new(
            Span::call_site(),
            "static mount path cannot contain `//`",
        ));
    }

    Ok(())
}

fn validate_relative_path(value: &str, label: &str) -> syn::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} cannot be empty"),
        ));
    }

    let path = Path::new(trimmed);
    if path.is_absolute() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} must be relative to the `.eon` file"),
        ));
    }

    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} cannot escape the service directory"),
        ));
    }

    Ok(trimmed.to_owned())
}

fn resolve_directory_under_root(service_root: &Path, relative_dir: &str) -> syn::Result<PathBuf> {
    let resolved = service_root.join(relative_dir);
    let canonical = resolved.canonicalize().map_err(|error| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to resolve static dir `{relative_dir}`: {error}"),
        )
    })?;
    if !canonical.starts_with(service_root) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("static dir `{relative_dir}` resolves outside the service directory"),
        ));
    }
    if !canonical.is_dir() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("static dir `{relative_dir}` is not a directory"),
        ));
    }
    Ok(canonical)
}

fn resolve_file_under_root(
    base_dir: &Path,
    relative_file: &str,
    label: &str,
) -> syn::Result<PathBuf> {
    let resolved = base_dir.join(relative_file);
    let canonical = resolved.canonicalize().map_err(|error| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to resolve {label} `{relative_file}`: {error}"),
        )
    })?;
    if !canonical.starts_with(base_dir) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} `{relative_file}` resolves outside the static dir"),
        ));
    }
    if !canonical.is_file() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} `{relative_file}` is not a file"),
        ));
    }
    Ok(canonical)
}

fn parse_static_mode(value: &str) -> syn::Result<StaticMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "directory" => Ok(StaticMode::Directory),
        "spa" => Ok(StaticMode::Spa),
        _ => Err(syn::Error::new(
            Span::call_site(),
            "static mode must be `Directory` or `Spa`",
        )),
    }
}

fn parse_static_cache_profile(value: &str) -> syn::Result<StaticCacheProfile> {
    match value.trim().to_ascii_lowercase().as_str() {
        "nostore" | "no_store" | "no-store" => Ok(StaticCacheProfile::NoStore),
        "revalidate" => Ok(StaticCacheProfile::Revalidate),
        "immutable" => Ok(StaticCacheProfile::Immutable),
        _ => Err(syn::Error::new(
            Span::call_site(),
            "static cache must be `NoStore`, `Revalidate`, or `Immutable`",
        )),
    }
}

fn parse_field_type(field_ty: &FieldTypeDocument, nullable: bool) -> syn::Result<Type> {
    let base = match field_ty {
        FieldTypeDocument::Scalar(scalar) => scalar.rust_type().to_owned(),
        FieldTypeDocument::Rust(raw) => raw.clone(),
    };

    let rust_type = if nullable {
        format!("Option<{base}>")
    } else {
        base
    };

    syn::parse_str::<Type>(&rust_type).map_err(|error| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to parse Rust type `{rust_type}`: {error}"),
        )
    })
}

impl ScalarType {
    fn rust_type(self) -> &'static str {
        match self {
            Self::String => "String",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::Bool => "bool",
        }
    }
}

fn parse_relation_document(
    field_name: &str,
    relation: RelationDocument,
) -> syn::Result<super::model::RelationSpec> {
    let mut parts = relation.references.split('.');
    let references_table = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "relation references must be `table.field`",
            )
        })?;
    let references_field = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "relation references must be `table.field`",
            )
        })?;

    if parts.next().is_some() {
        return Err(syn::Error::new(
            Span::call_site(),
            "relation references must be exactly `table.field`",
        ));
    }

    let on_delete = relation
        .on_delete
        .as_deref()
        .map(parse_referential_action)
        .transpose()?;

    Ok(super::model::RelationSpec {
        foreign_key: field_name.to_owned(),
        references_table: references_table.to_owned(),
        references_field: references_field.to_owned(),
        on_delete,
        nested_route: relation.nested_route,
    })
}

fn parse_referential_action(value: &str) -> syn::Result<ReferentialAction> {
    ReferentialAction::parse(value).ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "relation on_delete must be Cascade, Restrict, SetNull, or NoAction",
        )
    })
}

fn parse_row_policies(policies: RowPoliciesDocument) -> syn::Result<RowPolicies> {
    Ok(RowPolicies {
        admin_bypass: policies.admin_bypass,
        read: parse_filter_policies("read", policies.read)?,
        create: parse_assignment_policies("create", policies.create)?,
        update: parse_filter_policies("update", policies.update)?,
        delete: parse_filter_policies("delete", policies.delete)?,
    })
}

fn default_admin_bypass() -> bool {
    true
}

fn parse_filter_policies(
    scope: &'static str,
    policies: Option<ScopePoliciesDocument>,
) -> syn::Result<Vec<PolicyFilter>> {
    expand_policy_entries(policies)?
        .into_iter()
        .map(|policy| parse_filter_policy(scope, policy))
        .collect()
}

fn parse_assignment_policies(
    scope: &'static str,
    policies: Option<ScopePoliciesDocument>,
) -> syn::Result<Vec<PolicyAssignment>> {
    expand_policy_entries(policies)?
        .into_iter()
        .map(|policy| parse_assignment_policy(scope, policy))
        .collect()
}

fn expand_policy_entries(
    policies: Option<ScopePoliciesDocument>,
) -> syn::Result<Vec<PolicyEntryDocument>> {
    let Some(policies) = policies else {
        return Ok(Vec::new());
    };

    let entries = match policies {
        ScopePoliciesDocument::Single(entry) => vec![entry],
        ScopePoliciesDocument::Many(entries) => entries,
    };

    if entries.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "row policy entries cannot be empty",
        ));
    }

    Ok(entries)
}

fn parse_filter_policy(
    scope: &'static str,
    policy: PolicyEntryDocument,
) -> syn::Result<PolicyFilter> {
    match policy {
        PolicyEntryDocument::Legacy(policy) => {
            let kind = RowPolicyKind::parse(&policy.kind).ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    "row policy kind must be `Owner` or `SetOwner`",
                )
            })?;
            match kind {
                RowPolicyKind::Owner => Ok(PolicyFilter {
                    field: policy.field,
                    source: PolicyValueSource::UserId,
                }),
                RowPolicyKind::SetOwner => Err(syn::Error::new(
                    Span::call_site(),
                    format!("{scope} row policy must use `Owner` semantics"),
                )),
            }
        }
        PolicyEntryDocument::Rule(policy) => {
            let source = policy.equals.ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!("{scope} row policy entries must use `equals`"),
                )
            })?;
            Ok(PolicyFilter {
                field: policy.field,
                source: parse_policy_source(&source)?,
            })
        }
        PolicyEntryDocument::Shorthand(policy) => parse_filter_shorthand(scope, &policy),
    }
}

fn parse_assignment_policy(
    scope: &'static str,
    policy: PolicyEntryDocument,
) -> syn::Result<PolicyAssignment> {
    match policy {
        PolicyEntryDocument::Legacy(policy) => {
            let kind = RowPolicyKind::parse(&policy.kind).ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    "row policy kind must be `Owner` or `SetOwner`",
                )
            })?;
            match kind {
                RowPolicyKind::SetOwner => Ok(PolicyAssignment {
                    field: policy.field,
                    source: PolicyValueSource::UserId,
                }),
                RowPolicyKind::Owner => Err(syn::Error::new(
                    Span::call_site(),
                    "create row policy must use kind `SetOwner`",
                )),
            }
        }
        PolicyEntryDocument::Rule(policy) => {
            let source = policy.value.ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!("{scope} row policy entries must use `value`"),
                )
            })?;
            Ok(PolicyAssignment {
                field: policy.field,
                source: parse_policy_source(&source)?,
            })
        }
        PolicyEntryDocument::Shorthand(policy) => parse_assignment_shorthand(&policy),
    }
}

fn parse_filter_shorthand(scope: &'static str, value: &str) -> syn::Result<PolicyFilter> {
    if let Some(field) = parse_legacy_policy_field(value, RowPolicyKind::Owner) {
        return Ok(PolicyFilter {
            field,
            source: PolicyValueSource::UserId,
        });
    }

    if parse_legacy_policy_field(value, RowPolicyKind::SetOwner).is_some() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{scope} row policy must use `Owner` semantics"),
        ));
    }

    let (field, source) = parse_policy_expression(value)?;
    Ok(PolicyFilter { field, source })
}

fn parse_assignment_shorthand(value: &str) -> syn::Result<PolicyAssignment> {
    if let Some(field) = parse_legacy_policy_field(value, RowPolicyKind::SetOwner) {
        return Ok(PolicyAssignment {
            field,
            source: PolicyValueSource::UserId,
        });
    }

    if parse_legacy_policy_field(value, RowPolicyKind::Owner).is_some() {
        return Err(syn::Error::new(
            Span::call_site(),
            "create row policy must use kind `SetOwner`",
        ));
    }

    let (field, source) = parse_policy_expression(value)?;
    Ok(PolicyAssignment { field, source })
}

fn parse_legacy_policy_field(value: &str, kind: RowPolicyKind) -> Option<String> {
    let (parsed_kind, field) = value.split_once(':')?;
    let parsed_kind = RowPolicyKind::parse(parsed_kind.trim())?;
    if parsed_kind != kind {
        return None;
    }

    let field = field.trim();
    if field.is_empty() {
        None
    } else {
        Some(field.to_owned())
    }
}

fn parse_policy_expression(value: &str) -> syn::Result<(String, PolicyValueSource)> {
    let (field, source) = value.split_once('=').ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "row policy values must use `field=source`",
        )
    })?;
    let field = field.trim();
    if field.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "row policy field name cannot be empty",
        ));
    }

    Ok((field.to_owned(), parse_policy_source(source)?))
}

fn parse_policy_source(value: &str) -> syn::Result<PolicyValueSource> {
    PolicyValueSource::parse(value).ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "row policy source must be `user.id` or `claim.<name>`",
        )
    })
}

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
                static_mounts: Vec::new(),
            },
            include_path: path.value(),
        };

        let resource = &service.service.resources[0];
        assert_eq!(resource.policies.read[0].field, "user_id");
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
        assert_eq!(resource.policies.read.len(), 2);
        assert_eq!(
            resource.policies.read[1].source,
            super::super::model::PolicyValueSource::Claim("tenant_id".to_owned())
        );
        assert_eq!(resource.policies.create.len(), 2);
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
        assert!(error.to_string().contains("user.id"));
        assert!(error.to_string().contains("claim.<name>"));
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
    fn rejects_non_i64_row_policy_field_from_eon() {
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
                        { name: "user_id", type: String }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("non-i64 row policy field should fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("must use type `i64` or `Option<i64>`")
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
}
