//! Compile the existing VSR EON schema into the example's portable contract.
#[path = "src/contract.rs"]
mod contract;
mod profile;

use contract::{Contract, Field, Filter, Kind, Resource, Rule, Source};
use rest_macro_core::compiler::{
    self, PolicyComparisonValue as Value, PolicyFilterExpression as Expr,
    PolicyFilterOperator as Op, PolicyValueSource as From, ResourceReadAccess,
};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

fn source(value: &From) -> Result<Source, Box<dyn Error>> {
    match value {
        From::UserId => Ok(Source::User),
        From::Claim(name) if name == "tenant_id" => Ok(Source::Tenant),
        _ => Err("example supports only user.id and claim.tenant_id policy sources".into()),
    }
}

fn filters(expr: &Expr) -> Result<Vec<Filter>, Box<dyn Error>> {
    match expr {
        Expr::All(items) => items
            .iter()
            .map(filters)
            .collect::<Result<Vec<_>, _>>()
            .map(|v| v.into_iter().flatten().collect()),
        Expr::Match(f) => match &f.operator {
            Op::Equals(Value::Source(s)) => Ok(vec![Filter {
                field: f.field.clone(),
                source: source(s)?,
            }]),
            _ => Err("unsupported example policy operator".into()),
        },
        _ => Err("example requires conjunctive row policies".into()),
    }
}

fn rule(
    role: &Option<String>,
    expr: Option<&Expr>,
    tenant_required: bool,
) -> Result<Rule, Box<dyn Error>> {
    let role = role
        .clone()
        .filter(|s| !s.is_empty())
        .ok_or("every operation requires an explicit role")?;
    let filters = expr.map(filters).transpose()?.unwrap_or_default();
    if filters.iter().any(|f| {
        !matches!(
            (&f.source, f.field.as_str()),
            (Source::Tenant, "tenant_id") | (Source::User, "owner_user_id")
        )
    }) {
        return Err("example row filters only support tenant and owner boundaries".into());
    }
    if tenant_required
        && !filters.contains(&Filter {
            field: "tenant_id".into(),
            source: Source::Tenant,
        })
    {
        return Err("every read/update/delete requires the tenant boundary".into());
    }
    Ok(Rule { role, filters })
}

pub fn compile(path: &Path) -> Result<(Contract, String), Box<dyn Error>> {
    let _: profile::Profile = eon::from_str(&fs::read_to_string(path)?)?;
    let spec = compiler::load_service_from_path(path)?;
    if spec
        .resources
        .iter()
        .any(|r| r.db != compiler::DbBackend::Sqlite)
    {
        return Err(
            "this example requires SQLite; production database adapters are separate work".into(),
        );
    }
    let mut resources = Vec::new();
    for r in &spec.resources {
        if r.policies.admin_bypass || r.access.read != ResourceReadAccess::Authenticated {
            return Err(
                "enterprise resources require authenticated reads and no admin bypass".into(),
            );
        }
        if !r.actions.is_empty()
            || r.audit.is_some()
            || !r.many_to_many.is_empty()
            || !r.computed_fields.is_empty()
        {
            return Err("unsupported example resource extension".into());
        }
        let mut fields = Vec::new();
        for f in &r.fields {
            let name = f.name();
            if !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                || f.api_name != name
                || !f.expose_in_api
                || !f.transforms.is_empty()
            {
                return Err("example requires plain, exposed SQL field names".into());
            }
            let syn::Type::Path(ty) = &f.ty else {
                return Err("unsupported example scalar type".into());
            };
            let segment = ty.path.segments.last().ok_or("missing scalar type")?;
            // The compiler models generated IDs as Option<i64> for insert DTOs;
            // persisted records and this adapter always expose an assigned i64.
            let scalar = if f.is_id && segment.ident == "Option" {
                let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
                    return Err("invalid generated ID type".into());
                };
                let Some(syn::GenericArgument::Type(syn::Type::Path(inner))) = args.args.first()
                else {
                    return Err("invalid generated ID type".into());
                };
                inner
                    .path
                    .segments
                    .last()
                    .ok_or("invalid generated ID type")?
            } else {
                segment
            };
            let type_name = scalar.ident.to_string();
            let kind = match type_name.as_str() {
                "String" => Kind::String,
                "i64" => Kind::I64,
                "bool" => Kind::Bool,
                _ => {
                    return Err(
                        format!("unsupported example scalar type {type_name} on {name}").into(),
                    );
                }
            };
            if f.relation.as_ref().is_some_and(|rel| {
                rel.references_field != "id"
                    || rel.nested_route
                    || rel.on_delete != Some(compiler::ReferentialAction::Restrict)
            }) {
                return Err(
                    "example relations must reference id with Restrict and no nested routes".into(),
                );
            }
            fields.push(Field {
                name,
                kind,
                references: f.relation.as_ref().map(|rel| rel.references_table.clone()),
            });
        }
        for name in ["id", "tenant_id", "owner_user_id"] {
            if !fields.iter().any(|f| f.name == name && f.kind == Kind::I64) {
                return Err("missing required enterprise identity field".into());
            }
        }
        let assignments = r
            .policies
            .create
            .iter()
            .map(|a| {
                Ok(Filter {
                    field: a.field.clone(),
                    source: source(&a.source)?,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        if assignments.len() != 2
            || !assignments.contains(&Filter {
                field: "tenant_id".into(),
                source: Source::Tenant,
            })
            || !assignments.contains(&Filter {
                field: "owner_user_id".into(),
                source: Source::User,
            })
        {
            return Err("tenant and owner must be assigned by the server".into());
        }
        resources.push(Resource {
            name: r.struct_ident.to_string(),
            table: r.table_name.clone(),
            fields,
            read: rule(&r.roles.read, r.policies.read.as_ref(), true)?,
            create: rule(&r.roles.create, r.policies.create_require.as_ref(), false)?,
            update: rule(&r.roles.update, r.policies.update.as_ref(), true)?,
            delete: rule(&r.roles.delete, r.policies.delete.as_ref(), true)?,
            assignments,
        });
    }
    let contract = Contract {
        issuer: spec.security.auth.issuer.clone().ok_or("issuer required")?,
        audience: spec
            .security
            .auth
            .audience
            .clone()
            .ok_or("audience required")?,
        token_ttl: spec.security.auth.access_token_ttl_seconds,
        max_body_bytes: spec
            .security
            .requests
            .json_max_bytes
            .ok_or("explicit body limit required")?,
        resources,
    };
    let schema = compiler::render_service_migration_sql(&spec)?;
    Ok((contract, schema))
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=api.eon");
    println!("cargo:rerun-if-changed=src/contract.rs");
    println!("cargo:rerun-if-changed=profile.rs");
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let (contract, schema) = compile(&root.join("api.eon"))?;
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    fs::write(
        out.join("contract.json"),
        serde_json::to_vec_pretty(&contract)?,
    )?;
    fs::write(out.join("schema.sql"), schema)?;
    Ok(())
}
