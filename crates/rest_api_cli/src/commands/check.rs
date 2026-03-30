use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use colored::Colorize;
use rest_macro_core::{
    compiler::{ResourceSpec, ServiceSpec, supports_declared_index},
    database::service_base_dir_from_config_path,
    tls,
};

use crate::commands::schema::load_schema_service;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckSeverity {
    Warning,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CheckFinding {
    pub code: String,
    pub severity: CheckSeverity,
    pub path: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CheckSummary {
    pub warning_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ServiceCheckReport {
    pub kind: String,
    pub source: String,
    pub strict: bool,
    pub summary: CheckSummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CheckFinding>,
}

impl ServiceCheckReport {
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }
}

pub fn run_service_check(
    input: &Path,
    exclude_tables: &[String],
    strict: bool,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let report = build_service_check_report(input, exclude_tables, strict)?;
    let rendered = render_service_check_report(&report, format)?;
    write_output(rendered, output, force, "service check report")?;

    if strict && report.has_findings() {
        bail!(
            "strict check found {} warning(s)",
            report.summary.warning_count
        );
    }

    Ok(())
}

pub fn render_service_check_report(
    report: &ServiceCheckReport,
    format: OutputFormat,
) -> Result<String> {
    match format {
        OutputFormat::Text => Ok(render_text_report(report)),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .context("failed to serialize service check report to JSON"),
    }
}

pub fn build_service_check_report(
    input: &Path,
    exclude_tables: &[String],
    strict: bool,
) -> Result<ServiceCheckReport> {
    let service = load_schema_service(input, exclude_tables)?;
    let findings = collect_findings(input, &service);

    Ok(ServiceCheckReport {
        kind: "service_check".to_owned(),
        source: input.display().to_string(),
        strict,
        summary: CheckSummary {
            warning_count: findings.len(),
        },
        findings,
    })
}

fn collect_findings(input: &Path, service: &ServiceSpec) -> Vec<CheckFinding> {
    let mut findings = Vec::new();
    findings.extend(authorization_surface_findings(service));
    findings.extend(unused_authorization_scope_findings(service));
    findings.extend(explicit_index_findings(service));
    findings.extend(tls_path_findings(input, service));
    findings
}

fn authorization_surface_findings(service: &ServiceSpec) -> Vec<CheckFinding> {
    let mut findings = Vec::new();
    let contract = &service.authorization;
    let has_contract_declarations = !contract.scopes.is_empty()
        || !contract.permissions.is_empty()
        || !contract.templates.is_empty();
    let has_generated_surface =
        contract.management_api.enabled || !contract.hybrid_enforcement.resources.is_empty();

    if has_contract_declarations && !has_generated_surface {
        findings.push(CheckFinding {
            code: "authorization.contract_without_generated_surface".to_owned(),
            severity: CheckSeverity::Warning,
            path: "authorization".to_owned(),
            message: "authorization scopes, permissions, or templates are declared, but no generated runtime surface consumes them directly".to_owned(),
            suggestion: Some(
                "Enable `authorization.management_api`, add `authorization.hybrid_enforcement`, or keep the contract only for custom handlers and `vsr authz` tooling."
                    .to_owned(),
            ),
        });
    }

    if contract.management_api.enabled
        && contract.permissions.is_empty()
        && contract.templates.is_empty()
    {
        findings.push(CheckFinding {
            code: "authorization.management_api_without_targets".to_owned(),
            severity: CheckSeverity::Warning,
            path: "authorization.management_api".to_owned(),
            message: "authorization management API is enabled, but no permissions or templates are declared".to_owned(),
            suggestion: Some(
                "Declare `authorization.permissions` or `authorization.templates`, or disable the management API until runtime assignments are modeled."
                    .to_owned(),
            ),
        });
    }

    findings
}

fn unused_authorization_scope_findings(service: &ServiceSpec) -> Vec<CheckFinding> {
    let contract = &service.authorization;
    let mut referenced_scopes = BTreeSet::<String>::new();

    for scope in &contract.scopes {
        if let Some(parent) = &scope.parent {
            referenced_scopes.insert(parent.clone());
        }
    }
    for permission in &contract.permissions {
        referenced_scopes.extend(permission.scopes.iter().cloned());
    }
    for template in &contract.templates {
        referenced_scopes.extend(template.scopes.iter().cloned());
    }
    for resource in &contract.hybrid_enforcement.resources {
        referenced_scopes.insert(resource.scope.clone());
    }

    contract
        .scopes
        .iter()
        .filter(|scope| !referenced_scopes.contains(&scope.name))
        .map(|scope| CheckFinding {
            code: "authorization.unused_scope".to_owned(),
            severity: CheckSeverity::Warning,
            path: format!("authorization.scopes.{}", scope.name),
            message: format!(
                "scope `{}` is declared but not referenced by any permission, template, parent relationship, or hybrid enforcement rule",
                scope.name
            ),
            suggestion: Some(
                "Reference the scope from a permission, template, or hybrid enforcement rule, or remove it until it becomes part of the contract."
                    .to_owned(),
            ),
        })
        .collect()
}

fn explicit_index_findings(service: &ServiceSpec) -> Vec<CheckFinding> {
    let mut findings = Vec::new();

    for resource in &service.resources {
        for field in resource.fields.iter().filter(|field| {
            field
                .relation
                .as_ref()
                .map(|relation| relation.nested_route)
                .unwrap_or(false)
        }) {
            let field_name = field.name();
            if !supports_declared_index(field)
                || has_explicit_lookup_index(resource, field_name.as_str())
            {
                continue;
            }
            findings.push(CheckFinding {
                code: "indexes.explicit_nested_route_index_missing".to_owned(),
                severity: CheckSeverity::Warning,
                path: format!("resources.{}.indexes", resource.api_name()),
                message: format!(
                    "resource `{}` exposes a nested route through `{}`, but no explicit index starts with that field",
                    resource.api_name(),
                    field_name
                ),
                suggestion: Some(
                    format!(
                        "Declare an explicit index on `{}` so nested-route lookup paths stay visible in the `.eon` contract.",
                        field_name
                    ),
                ),
            });
        }
    }

    for resource in &service.resources {
        let mut policy_field_scopes = BTreeMap::<String, BTreeSet<&'static str>>::new();
        for (scope, filter) in resource.policies.iter_filters() {
            policy_field_scopes
                .entry(filter.field.clone())
                .or_default()
                .insert(scope);
        }

        for (field_name, scopes) in policy_field_scopes {
            let Some(field) = resource.find_field(field_name.as_str()) else {
                continue;
            };
            if !supports_declared_index(field)
                || has_explicit_lookup_index(resource, field_name.as_str())
            {
                continue;
            }
            findings.push(CheckFinding {
                code: "indexes.explicit_policy_index_missing".to_owned(),
                severity: CheckSeverity::Warning,
                path: format!("resources.{}.indexes", resource.api_name()),
                message: format!(
                    "resource `{}` uses `{}` in `{}` policy filters, but no explicit index starts with that field",
                    resource.api_name(),
                    field_name,
                    scopes.into_iter().collect::<Vec<_>>().join(", ")
                ),
                suggestion: Some(
                    format!(
                        "Declare an explicit index on `{}` for schema clarity. Generated migrations can infer one, but the `.eon` contract does not show it today.",
                        field_name
                    ),
                ),
            });
        }
    }

    let mut exists_targets = BTreeMap::<(String, String), BTreeSet<String>>::new();
    for resource in &service.resources {
        for (target_resource, field_name) in resource.policies.exists_index_targets() {
            let Some(target) = resolve_exists_target_resource(&service.resources, &target_resource)
            else {
                continue;
            };
            exists_targets
                .entry((target.api_name().to_owned(), field_name))
                .or_default()
                .insert(resource.api_name().to_owned());
        }
    }

    for ((resource_name, field_name), sources) in exists_targets {
        let Some(resource) = service
            .resources
            .iter()
            .find(|resource| resource.api_name() == resource_name)
        else {
            continue;
        };
        let Some(field) = resource.find_field(field_name.as_str()) else {
            continue;
        };
        if !supports_declared_index(field)
            || has_explicit_lookup_index(resource, field_name.as_str())
        {
            continue;
        }
        findings.push(CheckFinding {
            code: "indexes.explicit_exists_index_missing".to_owned(),
            severity: CheckSeverity::Warning,
            path: format!("resources.{}.indexes", resource.api_name()),
            message: format!(
                "resource `{}` is targeted by `exists` policies on field `{}` from `{}`, but no explicit index starts with that field",
                resource.api_name(),
                field_name,
                sources.into_iter().collect::<Vec<_>>().join(", ")
            ),
            suggestion: Some(
                format!(
                    "Declare an explicit index on `{}` so relation-aware authorization stays visible in the schema contract.",
                    field_name
                ),
            ),
        });
    }

    for config in &service.authorization.hybrid_enforcement.resources {
        let Some(resource) = service
            .resources
            .iter()
            .find(|resource| resource.api_name() == config.resource)
        else {
            continue;
        };
        let Some(field) = resource.find_field(config.scope_field.as_str()) else {
            continue;
        };
        if !supports_declared_index(field)
            || has_explicit_lookup_index(resource, config.scope_field.as_str())
        {
            continue;
        }
        findings.push(CheckFinding {
            code: "indexes.explicit_hybrid_scope_index_missing".to_owned(),
            severity: CheckSeverity::Warning,
            path: format!("authorization.hybrid_enforcement.resources.{}", config.resource),
            message: format!(
                "hybrid enforcement for `{}` derives scope from `{}`, but the resource does not declare an explicit index starting with that field",
                config.resource, config.scope_field
            ),
            suggestion: Some(
                format!(
                    "Declare an explicit index on `{}` to make the hybrid lookup path explicit in `.eon`.",
                    config.scope_field
                ),
            ),
        });
    }

    findings
}

fn tls_path_findings(input: &Path, service: &ServiceSpec) -> Vec<CheckFinding> {
    let mut findings = Vec::new();
    let base_dir = service_base_dir_from_config_path(input);
    let resolved = tls::resolve_tls_config(&service.tls, &base_dir);

    if let Some(cert_path) = resolved.cert_path {
        let path = PathBuf::from(&cert_path);
        if !path.is_file() {
            findings.push(CheckFinding {
                code: "tls.cert_path_missing".to_owned(),
                severity: CheckSeverity::Warning,
                path: "tls.cert_path".to_owned(),
                message: format!(
                    "TLS certificate path resolves to `{}`, but that file does not exist",
                    path.display()
                ),
                suggestion: Some(
                    "Create the certificate file, or switch to `tls.cert_path_env` so deployment-specific credentials stay outside the service config."
                        .to_owned(),
                ),
            });
        }
    }

    if let Some(key_path) = resolved.key_path {
        let path = PathBuf::from(&key_path);
        if !path.is_file() {
            findings.push(CheckFinding {
                code: "tls.key_path_missing".to_owned(),
                severity: CheckSeverity::Warning,
                path: "tls.key_path".to_owned(),
                message: format!(
                    "TLS private key path resolves to `{}`, but that file does not exist",
                    path.display()
                ),
                suggestion: Some(
                    "Create the private key file, or switch to `tls.key_path_env` so deployment-specific credentials stay outside the service config."
                        .to_owned(),
                ),
            });
        }
    }

    findings
}

fn resolve_exists_target_resource<'a>(
    resources: &'a [ResourceSpec],
    target_resource: &str,
) -> Option<&'a ResourceSpec> {
    resources.iter().find(|resource| {
        resource.table_name == target_resource
            || resource.struct_ident.to_string() == target_resource
    })
}

fn has_explicit_lookup_index(resource: &ResourceSpec, field_name: &str) -> bool {
    if resource.id_field == field_name {
        return true;
    }

    if resource
        .find_field(field_name)
        .map(|field| field.unique)
        .unwrap_or(false)
    {
        return true;
    }

    resource
        .indexes
        .iter()
        .any(|index| index.fields.first().map(|field| field.as_str()) == Some(field_name))
}

fn render_text_report(report: &ServiceCheckReport) -> String {
    let mut output = String::new();
    output.push_str("Service Check\n");
    output.push_str(&format!("Source: {}\n", report.source));
    output.push_str(&format!("Strict: {}\n", report.strict));
    output.push_str(&format!("Warnings: {}\n", report.summary.warning_count));

    if report.findings.is_empty() {
        output.push_str("\nNo findings.\n");
        return output;
    }

    output.push_str("\nFindings:\n");
    for finding in &report.findings {
        output.push_str(&format!(
            "- [{:?}] {} at `{}`: {}\n",
            finding.severity, finding.code, finding.path, finding.message
        ));
        if let Some(suggestion) = &finding.suggestion {
            output.push_str(&format!("  Suggestion: {suggestion}\n"));
        }
    }

    output
}

fn write_output(rendered: String, output: Option<&Path>, force: bool, label: &str) -> Result<()> {
    if let Some(output) = output {
        if output.exists() && !force {
            bail!(
                "{label} output already exists at {} (use --force to overwrite)",
                output.display()
            );
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(output, rendered)
            .with_context(|| format!("failed to write {label} to {}", output.display()))?;
        println!("{} {}", "Generated".green().bold(), output.display());
    } else {
        print!("{rendered}");
        if !rendered.ends_with('\n') {
            println!();
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

    use super::{
        OutputFormat, build_service_check_report, render_service_check_report, run_service_check,
    };

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn temp_dir(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("vsr-check-{name}-{stamp}"));
        fs::create_dir_all(&dir).expect("temp dir should create");
        dir
    }

    #[test]
    fn check_report_is_clean_for_simple_auth_management_fixture() {
        let report =
            build_service_check_report(&fixture_path("auth_management_api.eon"), &[], true)
                .expect("fixture should load");
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        let rendered =
            render_service_check_report(&report, OutputFormat::Text).expect("text should render");
        assert!(rendered.contains("No findings."));
    }

    #[test]
    fn check_report_finds_tls_authz_and_index_warnings() {
        let root = temp_dir("strict-fixture");
        let config = root.join("strict_check_api.eon");
        fs::write(
            &config,
            r#"
module: "strict_check_api"
tls: {
    cert_path: "certs/prod-cert.pem"
    key_path: "certs/prod-key.pem"
}
authorization: {
    management_api: {
        mount: "/ops/authz"
    }
    scopes: {
        Family: {
            description: "Family scope"
        }
        Unused: {
            description: "Unused scope"
        }
    }
}
resources: [
    {
        name: "ScopedDoc"
        roles: {
            read: "member"
        }
        policies: {
            read: "user_id=user.id"
        }
        fields: [
            { name: "id", type: I64, id: true }
            { name: "user_id", type: I64 }
            { name: "title", type: String }
        ]
    }
]
"#,
        )
        .expect("fixture should write");

        let report = build_service_check_report(&config, &[], true).expect("fixture should load");
        let codes = report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"authorization.management_api_without_targets"));
        assert!(codes.contains(&"authorization.unused_scope"));
        assert!(codes.contains(&"indexes.explicit_policy_index_missing"));
        assert!(codes.contains(&"tls.cert_path_missing"));
        assert!(codes.contains(&"tls.key_path_missing"));

        let rendered =
            render_service_check_report(&report, OutputFormat::Json).expect("json should render");
        assert!(rendered.contains("\"strict\": true"));
        assert!(rendered.contains("\"warning_count\""));
    }

    #[test]
    fn check_report_warns_for_nested_route_without_explicit_index() {
        let root = temp_dir("nested-route-fixture");
        let config = root.join("nested_route_check_api.eon");
        fs::write(
            &config,
            r#"
module: "nested_route_check_api"
resources: [
    {
        name: "Parent"
        fields: [
            { name: "id", type: I64, id: true }
        ]
    }
    {
        name: "Child"
        fields: [
            { name: "id", type: I64, id: true }
            {
                name: "parent_id"
                type: I64
                relation: {
                    references: "parent.id"
                    nested_route: true
                }
            }
        ]
    }
]
"#,
        )
        .expect("fixture should write");

        let report = build_service_check_report(&config, &[], true).expect("fixture should load");
        let codes = report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"indexes.explicit_nested_route_index_missing"));
    }

    #[test]
    fn run_service_check_writes_json_output() {
        let root = temp_dir("check-output");
        let output = root.join("report.json");
        run_service_check(
            &fixture_path("auth_management_api.eon"),
            &[],
            true,
            Some(&output),
            OutputFormat::Json,
            true,
        )
        .expect("clean fixture should pass");

        let body = fs::read_to_string(&output).expect("report should write");
        assert!(body.contains("\"kind\": \"service_check\""));
        assert!(body.contains("\"warning_count\": 0"));
    }

    #[test]
    fn run_service_check_fails_in_strict_mode_when_warnings_exist() {
        let root = temp_dir("check-strict-fail");
        let config = root.join("strict_check_api.eon");
        fs::write(
            &config,
            r#"
module: "strict_check_api"
authorization: {
    scopes: {
        Unused: {
            description: "Unused scope"
        }
    }
}
resources: [
    {
        name: "Note"
        fields: [
            { name: "id", type: I64, id: true }
        ]
    }
]
"#,
        )
        .expect("fixture should write");

        let error = run_service_check(&config, &[], true, None, OutputFormat::Text, true)
            .expect_err("strict check should fail");
        assert!(error.to_string().contains("strict check found 2 warning"));
    }
}
