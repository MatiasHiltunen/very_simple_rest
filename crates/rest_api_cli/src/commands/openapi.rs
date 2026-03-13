use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use colored::Colorize;
use rest_macro_core::compiler::{self, OpenApiSpecOptions};

use crate::commands::schema::load_schema_service;

const DEFAULT_OPENAPI_VERSION: &str = "1.0.0";

pub fn generate_openapi(
    input: &Path,
    output: &Path,
    force: bool,
    exclude_tables: &[String],
    title: Option<String>,
    version: Option<String>,
    server_url: &str,
    with_auth: bool,
) -> Result<()> {
    if output.exists() && !force {
        bail!(
            "OpenAPI file already exists at {} (use --force to overwrite)",
            output.display()
        );
    }

    let service = load_schema_service(input, exclude_tables)?;
    let options = OpenApiSpecOptions::new(
        title.unwrap_or_else(|| default_title(&service)),
        version.unwrap_or_else(|| DEFAULT_OPENAPI_VERSION.to_owned()),
        server_url.to_owned(),
    )
    .with_builtin_auth(with_auth);
    let document = compiler::render_service_openapi_json(&service, &options)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("failed to render OpenAPI JSON")?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    fs::write(output, document)
        .with_context(|| format!("failed to write OpenAPI JSON to {}", output.display()))?;

    println!(
        "{} {}",
        "Generated OpenAPI spec:".green().bold(),
        output.display()
    );

    Ok(())
}

fn default_title(service: &compiler::ServiceSpec) -> String {
    service
        .module_ident
        .to_string()
        .replace('_', " ")
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use serde_json::Value;
    use uuid::Uuid;

    use super::generate_openapi;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn test_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/openapi_tests")
            .join(Uuid::new_v4().to_string())
    }

    fn read_to_string(path: &Path) -> String {
        fs::read_to_string(path).expect("generated file should be readable")
    }

    #[test]
    fn generate_openapi_writes_json_file_for_eon_service() {
        let root = test_root();
        let output = root.join("openapi.json");
        generate_openapi(
            &fixture_path("blog_api.eon"),
            &output,
            false,
            &[],
            Some("Blog API".to_owned()),
            Some("2026.03".to_owned()),
            "/api",
            false,
        )
        .expect("openapi should generate");

        let document: Value =
            serde_json::from_str(&read_to_string(&output)).expect("document should parse");
        assert_eq!(document["info"]["title"], "Blog API");
        assert_eq!(document["info"]["version"], "2026.03");
        assert_eq!(document["servers"][0]["url"], "/api");
        assert!(document["paths"]["/post"].is_object());
        assert!(document["components"]["schemas"]["PostCreate"].is_object());
        assert!(document["components"]["securitySchemes"]["bearerAuth"].is_object());
    }

    #[test]
    fn generate_openapi_can_include_builtin_auth_routes() {
        let root = test_root();
        let output = root.join("openapi-auth.json");
        generate_openapi(
            &fixture_path("blog_api.eon"),
            &output,
            false,
            &[],
            Some("Blog API".to_owned()),
            Some("2026.03".to_owned()),
            "/api",
            true,
        )
        .expect("openapi should generate");

        let document: Value =
            serde_json::from_str(&read_to_string(&output)).expect("document should parse");
        assert!(document["paths"]["/auth/login"]["post"].is_object());
        assert!(document["paths"]["/auth/me"]["get"].is_object());
        assert_eq!(document["paths"]["/auth/me"]["get"]["tags"][0], "Account");
    }
}
