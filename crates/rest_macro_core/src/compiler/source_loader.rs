use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use proc_macro2::Span;
use quote::ToTokens;
use syn::{DeriveInput, Item};

use super::model::BuildConfig;
use super::{
    derive_parser,
    model::{ResourceSpec, ServiceSpec, sanitize_module_ident},
};
use crate::database::DatabaseConfig;
use crate::logging::LoggingConfig;
use crate::runtime::RuntimeConfig;
use crate::storage::StorageConfig;
use crate::tls::TlsConfig;

pub fn load_derive_service_from_path(path: &Path) -> syn::Result<ServiceSpec> {
    let mut rust_files = collect_rust_files(path)?;
    rust_files.sort();

    if rust_files.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("no Rust source files found under `{}`", path.display()),
        ));
    }

    let mut resources = Vec::new();
    for file in rust_files {
        let source = fs::read_to_string(&file).map_err(|error| {
            syn::Error::new(
                Span::call_site(),
                format!("failed to read `{}`: {error}", file.display()),
            )
        })?;
        let parsed = syn::parse_file(&source).map_err(|error| {
            syn::Error::new(
                Span::call_site(),
                format!("failed to parse `{}`: {error}", file.display()),
            )
        })?;
        collect_resources_from_items(&parsed.items, &mut resources)?;
    }

    if resources.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "no `#[derive(RestApi)]` resources found under `{}`",
                path.display()
            ),
        ));
    }

    validate_unique_resources(&resources)?;

    let module_name = path
        .file_stem()
        .or_else(|| path.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("generated_api");

    Ok(ServiceSpec {
        module_ident: sanitize_module_ident(module_name, Span::call_site()),
        enums: Vec::new(),
        resources,
        authorization: crate::authorization::AuthorizationContract::default(),
        static_mounts: Vec::new(),
        storage: StorageConfig::default(),
        database: DatabaseConfig::default(),
        build: BuildConfig::default(),
        clients: crate::compiler::ClientsConfig::default(),
        logging: LoggingConfig::default(),
        runtime: RuntimeConfig::default(),
        security: crate::security::SecurityConfig::default(),
        tls: TlsConfig::default(),
    })
}

fn collect_rust_files(path: &Path) -> syn::Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    if !path.is_dir() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("path `{}` does not exist", path.display()),
        ));
    }

    let mut files = Vec::new();
    collect_rust_files_recursive(path, &mut files)?;
    Ok(files)
}

fn collect_rust_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> syn::Result<()> {
    let mut entries = fs::read_dir(dir)
        .map_err(|error| {
            syn::Error::new(
                Span::call_site(),
                format!("failed to read directory `{}`: {error}", dir.display()),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            syn::Error::new(
                Span::call_site(),
                format!("failed to enumerate directory `{}`: {error}", dir.display()),
            )
        })?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files_recursive(&path, files)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            files.push(path);
        }
    }

    Ok(())
}

fn collect_resources_from_items(
    items: &[Item],
    resources: &mut Vec<ResourceSpec>,
) -> syn::Result<()> {
    for item in items {
        match item {
            Item::Struct(item_struct) if has_rest_api_derive(&item_struct.attrs)? => {
                let input = syn::parse2::<DeriveInput>(item_struct.to_token_stream())?;
                resources.push(derive_parser::parse_derive_input(input)?);
            }
            Item::Mod(item_mod) => {
                if let Some((_, nested_items)) = &item_mod.content {
                    collect_resources_from_items(nested_items, resources)?;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn has_rest_api_derive(attrs: &[syn::Attribute]) -> syn::Result<bool> {
    let mut found = false;

    for attr in attrs {
        if !attr.path().is_ident("derive") {
            continue;
        }

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("RestApi") {
                found = true;
            }
            Ok(())
        })?;
    }

    Ok(found)
}

fn validate_unique_resources(resources: &[ResourceSpec]) -> syn::Result<()> {
    let mut struct_names = HashSet::new();
    let mut table_names = HashSet::new();

    for resource in resources {
        let struct_name = resource.struct_ident.to_string();
        if !struct_names.insert(struct_name.clone()) {
            return Err(syn::Error::new(
                resource.struct_ident.span(),
                format!("duplicate derive resource `{struct_name}`"),
            ));
        }

        if !table_names.insert(resource.table_name.clone()) {
            return Err(syn::Error::new(
                resource.struct_ident.span(),
                format!(
                    "duplicate table `{}` in derive resources",
                    resource.table_name
                ),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::load_derive_service_from_path;

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}_{stamp}"))
    }

    #[test]
    fn loads_derive_resources_from_directory_tree() {
        let root = temp_root("derive_loader");
        let models_dir = root.join("models");
        fs::create_dir_all(&models_dir).expect("temp dir should exist");

        fs::write(
            root.join("main.rs"),
            r#"
            use very_simple_rest::prelude::*;

            #[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
            #[rest_api(table = "post", id = "id", db = "sqlite")]
            struct Post {
                id: Option<i64>,
                title: String,
            }
            "#,
        )
        .expect("main file should be written");

        fs::write(
            models_dir.join("comment.rs"),
            r#"
            use very_simple_rest::prelude::*;

            #[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
            #[rest_api(table = "comment", id = "id", db = "sqlite")]
            struct Comment {
                id: Option<i64>,
                #[relation(references = "post.id", nested_route = true)]
                post_id: i64,
                body: String,
            }
            "#,
        )
        .expect("comment file should be written");

        let service = load_derive_service_from_path(&root).expect("derive service should load");
        let tables = service
            .resources
            .iter()
            .map(|resource| resource.table_name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(tables, vec!["post", "comment"]);
    }
}
