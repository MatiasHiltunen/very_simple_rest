use std::path::Path;

use anyhow::{Context, Result, bail};
use rest_macro_core::compiler;

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
