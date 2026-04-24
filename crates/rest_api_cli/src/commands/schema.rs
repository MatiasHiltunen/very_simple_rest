use std::fs;
use std::io::{self, Read};
use std::path::Path;

use anyhow::{Context, Result, bail};
use rest_macro_core::compiler;
use vsr_schema_doc::{ServiceInputDocument, render_input_document_to_eon};

pub(crate) fn load_schema_service(
    input: &Path,
    exclude_tables: &[String],
) -> Result<compiler::ServiceSpec> {
    let mut service = if input.extension().and_then(|ext| ext.to_str()) == Some("eon") {
        compiler::load_service_from_path(input)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
            .with_context(|| {
                format!("failed to load service definition from {}", input.display())
            })?
    } else {
        compiler::load_derive_service_from_path(input)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
            .with_context(|| format!("failed to load derive resources from {}", input.display()))?
    };

    apply_table_exclusions(&mut service, exclude_tables, input)?;
    Ok(service)
}

pub(crate) fn load_filtered_derive_service(
    input: &Path,
    exclude_tables: &[String],
) -> Result<compiler::ServiceSpec> {
    let mut service = compiler::load_derive_service_from_path(input)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("failed to load derive resources from {}", input.display()))?;
    apply_table_exclusions(&mut service, exclude_tables, input)?;
    Ok(service)
}

pub fn render_schema_document(
    input: Option<&Path>,
    output: Option<&Path>,
) -> Result<()> {
    let json = read_render_input(input)?;
    let document: ServiceInputDocument =
        serde_json::from_str(&json).context("failed to parse schema JSON")?;
    let rendered = render_input_document_to_eon(document)
        .map_err(|error| anyhow::anyhow!(error))
        .context("failed to render canonical .eon")?;

    if let Some(path) = output {
        fs::write(path, rendered)
            .with_context(|| format!("failed to write {}", path.display()))?;
    } else {
        print!("{rendered}");
    }

    Ok(())
}

fn read_render_input(input: Option<&Path>) -> Result<String> {
    match input {
        Some(path) => fs::read_to_string(path)
            .with_context(|| format!("failed to read schema JSON from {}", path.display())),
        None => {
            let mut json = String::new();
            io::stdin()
                .read_to_string(&mut json)
                .context("failed to read schema JSON from stdin")?;
            Ok(json)
        }
    }
}

fn apply_table_exclusions(
    service: &mut compiler::ServiceSpec,
    exclude_tables: &[String],
    input: &Path,
) -> Result<()> {
    if !exclude_tables.is_empty() {
        service.resources.retain(|resource| {
            !exclude_tables
                .iter()
                .any(|excluded| excluded == &resource.table_name)
        });
    }

    if service.resources.is_empty() {
        bail!(
            "no resources remain after exclusions for {}",
            input.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::read_render_input;
    use anyhow::Result;
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;
    use vsr_schema_doc::{
        ServiceInputDocument, normalize_input_document, parse_eon_document,
        render_input_document_to_eon,
    };

    fn temp_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/schema_command_tests")
            .join(Uuid::new_v4().to_string())
    }

    #[test]
    fn render_input_document_produces_parseable_eon() -> Result<()> {
        let json = r#"
        {
            "module": "blog_api",
            "resources": {
                "Post": {
                    "name": "Post",
                    "api_name": "posts",
                    "fields": {
                        "id": { "type": "I64", "id": true },
                        "title": { "type": "String" }
                    }
                }
            }
        }
        "#;
        let document: ServiceInputDocument = serde_json::from_str(json)?;
        let rendered =
            render_input_document_to_eon(document.clone()).map_err(|error| anyhow::anyhow!(error))?;
        let normalized =
            normalize_input_document(document).map_err(|error| anyhow::anyhow!(error))?;
        let reparsed = parse_eon_document(&rendered).map_err(|error| anyhow::anyhow!(error))?;

        assert!(rendered.contains("module: \"blog_api\""));
        assert!(rendered.contains("api_name: \"posts\""));
        assert_eq!(normalized.resources.len(), 1);
        assert_eq!(reparsed.resources.len(), 1);
        assert_eq!(reparsed.resources[0].name, "Post");
        assert_eq!(reparsed.resources[0].fields[0].name, "id");
        Ok(())
    }

    #[test]
    fn read_render_input_reads_json_file() -> Result<()> {
        let root = temp_root();
        fs::create_dir_all(&root)?;
        let input = root.join("service.json");
        fs::write(&input, "{\"module\":\"demo\"}")?;

        let contents = read_render_input(Some(&input))?;
        assert_eq!(contents, "{\"module\":\"demo\"}");

        fs::remove_dir_all(root)?;
        Ok(())
    }
}
