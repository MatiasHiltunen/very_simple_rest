use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use colored::Colorize;
use rest_macro_core::{
    auth::AuthJwtAlgorithm,
    compiler::{ResourceSpec, ServiceSpec, supports_declared_index},
    database::service_base_dir_from_config_path,
    secret::SecretRef,
    tls,
};
use url::Url;

use crate::commands::{
    client::{
        resolve_configured_client_output_dir, resolve_configured_client_self_test_report_path,
    },
    schema::load_schema_service,
    server::{
        resolve_binary_output_path, resolve_build_cache_root, resolve_bundle_output_path,
        resolve_generated_package_name,
    },
};

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
    findings.extend(jwt_configuration_findings(service));
    findings.extend(auth_email_findings(service));
    findings.extend(auth_ui_path_findings(service));
    findings.extend(unused_authorization_scope_findings(service));
    findings.extend(explicit_index_findings(service));
    findings.extend(build_artifact_findings(input, service));
    findings.extend(client_generation_findings(input, service));
    findings.extend(storage_path_findings(service));
    findings.extend(tls_path_findings(input, service));
    findings
}

fn auth_email_findings(service: &ServiceSpec) -> Vec<CheckFinding> {
    let Some(email) = service.security.auth.email.as_ref() else {
        return Vec::new();
    };
    let Some(public_base_url) = email.public_base_url.as_deref() else {
        return Vec::new();
    };
    let Ok(parsed) = Url::parse(public_base_url) else {
        return Vec::new();
    };
    let Some(host) = parsed.host_str() else {
        return Vec::new();
    };

    let is_local = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback() || ip.is_unspecified())
            .unwrap_or(false);

    let mut findings = Vec::new();
    if is_local {
        findings.push(CheckFinding {
            code: "security.auth.email.public_base_url_is_local".to_owned(),
            severity: CheckSeverity::Warning,
            path: "security.auth.email.public_base_url".to_owned(),
            message: format!(
                "auth email public base URL `{public_base_url}` points at a local-only host"
            ),
            suggestion: Some(
                "Use a publicly reachable HTTPS origin for email verification and password-reset links. Localhost and loopback URLs are fine for development, but they are not safe production defaults."
                    .to_owned(),
            ),
        });
        return findings;
    }

    if parsed.scheme() != "https" {
        findings.push(CheckFinding {
            code: "security.auth.email.public_base_url_not_https".to_owned(),
            severity: CheckSeverity::Warning,
            path: "security.auth.email.public_base_url".to_owned(),
            message: format!(
                "auth email public base URL `{public_base_url}` does not use HTTPS"
            ),
            suggestion: Some(
                "Use an `https://` public base URL for verification and password-reset links so email-driven auth flows do not downgrade users onto insecure origins."
                    .to_owned(),
            ),
        });
    }

    findings
}

fn jwt_configuration_findings(service: &ServiceSpec) -> Vec<CheckFinding> {
    let mut findings = Vec::new();
    let auth = &service.security.auth;

    if auth
        .jwt_secret
        .as_ref()
        .is_some_and(|secret| secret != &SecretRef::env_or_file("JWT_SECRET"))
    {
        findings.push(CheckFinding {
            code: "security.auth.legacy_jwt_secret_configured".to_owned(),
            severity: CheckSeverity::Warning,
            path: "security.auth.jwt_secret".to_owned(),
            message: "legacy symmetric `security.auth.jwt_secret` is configured".to_owned(),
            suggestion: Some(
                "Prefer `security.auth.jwt` with asymmetric signing keys so key rotation and JWKS publication are first-class."
                    .to_owned(),
            ),
        });
    }

    let Some(jwt) = &auth.jwt else {
        return findings;
    };

    if !jwt.algorithm.is_symmetric() && jwt.verification_keys.len() < 2 {
        findings.push(CheckFinding {
            code: "security.auth.jwt_rotation_overlap_missing".to_owned(),
            severity: CheckSeverity::Warning,
            path: "security.auth.jwt.verification_keys".to_owned(),
            message: format!(
                "asymmetric `{}` JWT configuration exposes only {} verification key, so rotation has no overlap window",
                jwt_algorithm_label(jwt.algorithm),
                jwt.verification_keys.len()
            ),
            suggestion: Some(
                "Keep both the current and previous public verification keys in `security.auth.jwt.verification_keys` during rotations, then remove the old key after issued tokens expire."
                    .to_owned(),
            ),
        });
    }

    if !jwt.algorithm.is_symmetric() {
        for verification_key in &jwt.verification_keys {
            if verification_key.key == jwt.signing_key {
                findings.push(CheckFinding {
                    code: "security.auth.jwt_verification_key_matches_signing_key".to_owned(),
                    severity: CheckSeverity::Warning,
                    path: format!(
                        "security.auth.jwt.verification_keys.{}",
                        verification_key.kid
                    ),
                    message: format!(
                        "verification key `{}` resolves from the same secret reference as `security.auth.jwt.signing_key`",
                        verification_key.kid
                    ),
                    suggestion: Some(
                        "Point verification keys at public key material. Reusing the signing-key secret usually means the runtime will try to verify tokens with a private key source."
                            .to_owned(),
                    ),
                });
            }
        }
    }

    findings
}

fn jwt_algorithm_label(algorithm: AuthJwtAlgorithm) -> &'static str {
    match algorithm {
        AuthJwtAlgorithm::Hs256 => "HS256",
        AuthJwtAlgorithm::Hs384 => "HS384",
        AuthJwtAlgorithm::Hs512 => "HS512",
        AuthJwtAlgorithm::Es256 => "ES256",
        AuthJwtAlgorithm::Es384 => "ES384",
        AuthJwtAlgorithm::EdDsa => "EdDSA",
    }
}

fn auth_ui_path_findings(service: &ServiceSpec) -> Vec<CheckFinding> {
    let mut findings = Vec::new();

    for (label, path) in [
        (
            "portal",
            service
                .security
                .auth
                .portal
                .as_ref()
                .map(|page| page.path.as_str()),
        ),
        (
            "admin_dashboard",
            service
                .security
                .auth
                .admin_dashboard
                .as_ref()
                .map(|page| page.path.as_str()),
        ),
    ] {
        let Some(path) = path else {
            continue;
        };
        let external_path = auth_ui_external_path(path);

        if let Some(resource_name) = auth_ui_resource_namespace_overlap(service, path) {
            findings.push(CheckFinding {
                code: "security.auth.ui_path_overlaps_resource_namespace".to_owned(),
                severity: CheckSeverity::Warning,
                path: format!("security.auth.{label}.path"),
                message: format!(
                    "built-in auth UI path `{path}` shares the `/api/{}` namespace with resource `{}`",
                    resource_name, resource_name
                ),
                suggestion: Some(
                    "Move the auth UI path outside resource namespaces, for example under `/auth/...`, so built-in pages do not shadow generated resource routes."
                        .to_owned(),
                ),
            });
        }

        if let Some(upload_name) = auth_ui_upload_namespace_overlap(service, path) {
            findings.push(CheckFinding {
                code: "security.auth.ui_path_overlaps_upload_namespace".to_owned(),
                severity: CheckSeverity::Warning,
                path: format!("security.auth.{label}.path"),
                message: format!(
                    "built-in auth UI path `{path}` shares the `/api` namespace used by storage upload `{upload_name}`",
                ),
                suggestion: Some(
                    "Move the auth UI path or the upload route so each owns a distinct first path segment inside `/api`."
                        .to_owned(),
                ),
            });
        }

        if service.authorization.management_api.enabled
            && auth_ui_matches_or_overlaps(
                path,
                service.authorization.management_api.mount.as_str(),
            )
        {
            findings.push(CheckFinding {
                code: "security.auth.ui_path_overlaps_authorization_management".to_owned(),
                severity: CheckSeverity::Warning,
                path: format!("security.auth.{label}.path"),
                message: format!(
                    "built-in auth UI path `{path}` overlaps the authorization management mount `{}` inside `/api`",
                    service.authorization.management_api.mount
                ),
                suggestion: Some(
                    "Keep auth UI pages and runtime authorization management under separate `/api` prefixes."
                        .to_owned(),
                ),
            });
        }

        for mount in &service.static_mounts {
            if auth_ui_matches_or_overlaps(external_path.as_str(), mount.mount_path.as_str()) {
                findings.push(CheckFinding {
                    code: "security.auth.ui_path_overlaps_static_mount".to_owned(),
                    severity: CheckSeverity::Warning,
                    path: format!("security.auth.{label}.path"),
                    message: format!(
                        "built-in auth UI path `{external_path}` overlaps static mount `{}`",
                        mount.mount_path
                    ),
                    suggestion: Some(
                        "Move the static mount or auth UI page so a root-level static handler cannot shadow the built-in auth UI route."
                            .to_owned(),
                    ),
                });
            }
        }
    }

    findings
}

fn auth_ui_external_path(path: &str) -> String {
    if path == "/" {
        "/api".to_owned()
    } else {
        format!("/api{path}")
    }
}

fn auth_ui_resource_namespace_overlap(service: &ServiceSpec, path: &str) -> Option<String> {
    let first_segment = first_path_segment(path)?;
    service
        .resources
        .iter()
        .find(|resource| resource.api_name() == first_segment)
        .map(|resource| resource.api_name().to_owned())
}

fn auth_ui_upload_namespace_overlap(service: &ServiceSpec, path: &str) -> Option<String> {
    let first_segment = first_path_segment(path)?;
    service
        .storage
        .uploads
        .iter()
        .find(|upload| {
            upload
                .path
                .split('/')
                .next()
                .map(|segment| segment == first_segment)
                .unwrap_or(false)
        })
        .map(|upload| upload.name.clone())
}

fn first_path_segment(path: &str) -> Option<&str> {
    path.trim_matches('/')
        .split('/')
        .find(|segment| !segment.is_empty())
}

fn auth_ui_matches_or_overlaps(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
        || right
            .strip_prefix(left)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
}

fn build_artifact_findings(input: &Path, service: &ServiceSpec) -> Vec<CheckFinding> {
    let mut findings = build_artifact_env_findings(service);

    let Ok(package_name) = resolve_generated_package_name(input, None) else {
        return findings;
    };
    let Ok(binary_output) = resolve_binary_output_path(input, service, None, Some(&package_name))
    else {
        return findings;
    };
    let Ok(bundle_output) = resolve_bundle_output_path(input, service, &binary_output, false)
    else {
        return findings;
    };
    let Ok(build_root) = resolve_build_cache_root(input, service, &package_name, None) else {
        return findings;
    };

    if paths_equal(&binary_output, &bundle_output) {
        findings.push(CheckFinding {
            code: "build.artifacts.binary_bundle_path_collision".to_owned(),
            severity: CheckSeverity::Warning,
            path: "build.artifacts".to_owned(),
            message: format!(
                "resolved binary output and bundle directory both point to `{}`",
                binary_output.display()
            ),
            suggestion: Some(
                "Move `build.artifacts.binary.path` or `build.artifacts.bundle.path` so the binary and runtime bundle do not share the same path."
                    .to_owned(),
            ),
        });
    }

    if path_is_within(&binary_output, &bundle_output) {
        findings.push(CheckFinding {
            code: "build.artifacts.binary_inside_bundle".to_owned(),
            severity: CheckSeverity::Warning,
            path: "build.artifacts".to_owned(),
            message: format!(
                "resolved binary output `{}` is inside the bundle directory `{}`",
                binary_output.display(),
                bundle_output.display()
            ),
            suggestion: Some(
                "Place the binary outside the bundle directory. `vsr build --force` recreates the bundle directory and can delete files nested inside it."
                    .to_owned(),
            ),
        });
    }

    if paths_overlap(&build_root, &bundle_output) {
        findings.push(CheckFinding {
            code: "build.artifacts.cache_bundle_overlap".to_owned(),
            severity: CheckSeverity::Warning,
            path: "build.artifacts".to_owned(),
            message: format!(
                "resolved build cache `{}` overlaps the bundle directory `{}`",
                build_root.display(),
                bundle_output.display()
            ),
            suggestion: Some(
                "Move `build.artifacts.cache.root` or `build.artifacts.bundle.path` so the reusable build cache stays separate from exported runtime artifacts."
                    .to_owned(),
            ),
        });
    }

    if paths_overlap(&build_root, &binary_output) {
        findings.push(CheckFinding {
            code: "build.artifacts.cache_binary_overlap".to_owned(),
            severity: CheckSeverity::Warning,
            path: "build.artifacts".to_owned(),
            message: format!(
                "resolved build cache `{}` overlaps the binary output path `{}`",
                build_root.display(),
                binary_output.display()
            ),
            suggestion: Some(
                "Move `build.artifacts.cache.root` or `build.artifacts.binary.path` so cleaning the build cache cannot touch the built binary."
                    .to_owned(),
            ),
        });
    }

    findings
}

fn build_artifact_env_findings(service: &ServiceSpec) -> Vec<CheckFinding> {
    let mut findings = Vec::new();

    for (path, env_name, code, label) in [
        (
            "build.artifacts.binary.env",
            service.build.artifacts.binary.env.as_deref(),
            "build.artifacts.binary_env_override_empty",
            "binary output path",
        ),
        (
            "build.artifacts.bundle.env",
            service.build.artifacts.bundle.env.as_deref(),
            "build.artifacts.bundle_env_override_empty",
            "bundle output path",
        ),
        (
            "build.artifacts.cache.env",
            service.build.artifacts.cache.env.as_deref(),
            "build.artifacts.cache_env_override_empty",
            "build cache root",
        ),
    ] {
        let Some(env_name) = env_name else {
            continue;
        };
        let Some(value) = std::env::var_os(env_name) else {
            continue;
        };
        if !value.to_string_lossy().trim().is_empty() {
            continue;
        }
        findings.push(CheckFinding {
            code: code.to_owned(),
            severity: CheckSeverity::Warning,
            path: path.to_owned(),
            message: format!(
                "declared env override `{env_name}` is set, but it resolves to an empty {label}"
            ),
            suggestion: Some(format!(
                "Unset `{env_name}` or give it a non-empty path value. When it is empty, `vsr` falls back to the literal `.eon` path or service-relative default."
            )),
        });
    }

    findings
}

fn client_generation_findings(input: &Path, service: &ServiceSpec) -> Vec<CheckFinding> {
    let mut findings = client_generation_env_findings(service);

    if !service.clients.ts.automation.on_build {
        return findings;
    }

    let Ok(package_name) = resolve_generated_package_name(input, None) else {
        return findings;
    };
    let Ok(binary_output) = resolve_binary_output_path(input, service, None, Some(&package_name))
    else {
        return findings;
    };
    let Ok(bundle_output) = resolve_bundle_output_path(input, service, &binary_output, false)
    else {
        return findings;
    };
    let Ok(build_root) = resolve_build_cache_root(input, service, &package_name, None) else {
        return findings;
    };
    let Ok(client_output) = resolve_configured_client_output_dir(input, service) else {
        return findings;
    };

    if paths_overlap(&client_output, &build_root) {
        findings.push(CheckFinding {
            code: "clients.ts.output_dir_overlaps_build_cache".to_owned(),
            severity: CheckSeverity::Warning,
            path: "clients.ts.output_dir".to_owned(),
            message: format!(
                "automated client output `{}` overlaps the build cache `{}`",
                client_output.display(),
                build_root.display()
            ),
            suggestion: Some(
                "Move `clients.ts.output_dir` outside `.vsr-build`. Build-cache cleanup and regeneration should not share the same path tree."
                    .to_owned(),
            ),
        });
    }

    if paths_overlap(&client_output, &bundle_output) {
        findings.push(CheckFinding {
            code: "clients.ts.output_dir_overlaps_bundle".to_owned(),
            severity: CheckSeverity::Warning,
            path: "clients.ts.output_dir".to_owned(),
            message: format!(
                "automated client output `{}` overlaps the server bundle `{}`",
                client_output.display(),
                bundle_output.display()
            ),
            suggestion: Some(
                "Move `clients.ts.output_dir` outside the bundle directory. `vsr build --force` recreates the bundle and can remove overlapping client artifacts."
                    .to_owned(),
            ),
        });
    }

    if paths_overlap(&client_output, &binary_output) {
        findings.push(CheckFinding {
            code: "clients.ts.output_dir_overlaps_binary".to_owned(),
            severity: CheckSeverity::Warning,
            path: "clients.ts.output_dir".to_owned(),
            message: format!(
                "automated client output `{}` overlaps the built binary path `{}`",
                client_output.display(),
                binary_output.display()
            ),
            suggestion: Some(
                "Place `clients.ts.output_dir` in a separate directory so client generation cannot collide with the server executable."
                    .to_owned(),
            ),
        });
    }

    let Ok(self_test_report_path) =
        resolve_configured_client_self_test_report_path(input, service, &client_output)
    else {
        return findings;
    };
    let Some(self_test_report_path) = self_test_report_path else {
        return findings;
    };

    for generated_name in [
        "index.ts",
        "client.ts",
        "types.ts",
        "operations.ts",
        "package.json",
        "tsconfig.json",
        "self-test-report.json",
    ] {
        let generated_path = client_output.join(generated_name);
        if paths_equal(&self_test_report_path, &generated_path) {
            findings.push(CheckFinding {
                code: "clients.ts.self_test_report_path_collides_with_generated_file".to_owned(),
                severity: CheckSeverity::Warning,
                path: "clients.ts.automation.self_test_report".to_owned(),
                message: format!(
                    "automated client self-test report path `{}` collides with generated client file `{generated_name}`",
                    self_test_report_path.display()
                ),
                suggestion: Some(
                    "Move `clients.ts.automation.self_test_report` to a separate filename such as `reports/client-self-test.json`."
                        .to_owned(),
                ),
            });
            break;
        }
    }

    findings
}

fn client_generation_env_findings(service: &ServiceSpec) -> Vec<CheckFinding> {
    let mut findings = Vec::new();

    for (path, env_name, code, label) in [
        (
            "clients.ts.output_dir.env",
            service.clients.ts.output_dir.env.as_deref(),
            "clients.ts.output_dir_env_override_empty",
            "client output directory",
        ),
        (
            "clients.ts.package_name.env",
            service.clients.ts.package_name.env.as_deref(),
            "clients.ts.package_name_env_override_empty",
            "client package name",
        ),
        (
            "clients.ts.automation.self_test_report.env",
            service
                .clients
                .ts
                .automation
                .self_test_report
                .env
                .as_deref(),
            "clients.ts.self_test_report_env_override_empty",
            "client self-test report path",
        ),
    ] {
        let Some(env_name) = env_name else {
            continue;
        };
        let Some(value) = std::env::var_os(env_name) else {
            continue;
        };
        if !value.to_string_lossy().trim().is_empty() {
            continue;
        }
        findings.push(CheckFinding {
            code: code.to_owned(),
            severity: CheckSeverity::Warning,
            path: path.to_owned(),
            message: format!(
                "declared env override `{env_name}` is set, but it resolves to an empty {label}"
            ),
            suggestion: Some(format!(
                "Unset `{env_name}` or give it a non-empty value. When it is empty, `vsr` falls back to the literal `.eon` value or service-relative default."
            )),
        });
    }

    findings
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    left == right
}

fn path_is_within(path: &Path, ancestor: &Path) -> bool {
    path != ancestor && path.starts_with(ancestor)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
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
        for relation in &resource.many_to_many {
            let Some(through_resource) =
                resolve_resource_reference(&service.resources, &relation.through_table)
            else {
                continue;
            };
            let Some(field) = through_resource.find_field(relation.source_field.as_str()) else {
                continue;
            };
            if !supports_declared_index(field)
                || has_explicit_lookup_index(through_resource, relation.source_field.as_str())
            {
                continue;
            }
            findings.push(CheckFinding {
                code: "indexes.explicit_many_to_many_index_missing".to_owned(),
                severity: CheckSeverity::Warning,
                path: format!("resources.{}.indexes", through_resource.api_name()),
                message: format!(
                    "join resource `{}` backs many-to-many relation `{}`.`{}`, but no explicit index starts with `{}`",
                    through_resource.api_name(),
                    resource.api_name(),
                    relation.name,
                    relation.source_field
                ),
                suggestion: Some(format!(
                    "Declare an explicit index on `{}` or a composite index starting with it, such as `[\"{}\", \"{}\"]`.",
                    relation.source_field, relation.source_field, relation.target_field
                )),
            });
        }
    }

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

fn storage_path_findings(service: &ServiceSpec) -> Vec<CheckFinding> {
    let mut findings = Vec::new();
    let mut used_backends = BTreeSet::<String>::new();

    for mount in &service.storage.public_mounts {
        used_backends.insert(mount.backend.clone());
    }
    for upload in &service.storage.uploads {
        used_backends.insert(upload.backend.clone());
        if !upload.require_auth && !upload.roles.is_empty() {
            findings.push(CheckFinding {
                code: "storage.upload_roles_without_auth".to_owned(),
                severity: CheckSeverity::Warning,
                path: format!("storage.uploads.{}.roles", upload.name),
                message: format!(
                    "storage upload `{}` declares roles, but `require_auth` is false so those roles are never enforced",
                    upload.name
                ),
                suggestion: Some(
                    "Set `require_auth: true` if the upload should use role-based access, or remove `roles` to make the public intent explicit."
                        .to_owned(),
                ),
            });
        }
    }
    if let Some(s3_compat) = &service.storage.s3_compat {
        for bucket in &s3_compat.buckets {
            used_backends.insert(bucket.backend.clone());
        }
    }

    for backend in &service.storage.backends {
        let path = PathBuf::from(&backend.resolved_root_dir);
        if path.exists() && !path.is_dir() {
            findings.push(CheckFinding {
                code: "storage.backend_root_not_directory".to_owned(),
                severity: CheckSeverity::Warning,
                path: format!("storage.backends.{}.dir", backend.name),
                message: format!(
                    "storage backend `{}` resolves to `{}`, but that path is not a directory",
                    backend.name,
                    path.display()
                ),
                suggestion: Some(
                    "Point `storage.backends.*.dir` to a directory path, or remove the blocking file before runtime initializes the backend."
                        .to_owned(),
                ),
            });
        }
        if !used_backends.contains(&backend.name) {
            findings.push(CheckFinding {
                code: "storage.unused_backend".to_owned(),
                severity: CheckSeverity::Warning,
                path: format!("storage.backends.{}", backend.name),
                message: format!(
                    "storage backend `{}` is declared but not referenced by any public mount, upload endpoint, or S3-compatible bucket",
                    backend.name
                ),
                suggestion: Some(
                    "Reference the backend from `storage.public_mounts`, `storage.uploads`, or `storage.s3_compat`, or remove it until it is needed."
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
    resolve_resource_reference(resources, target_resource)
}

fn resolve_resource_reference<'a>(
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
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        OutputFormat, ServiceCheckReport, build_service_check_report, render_service_check_report,
        run_service_check,
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

    fn snapshot_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/snapshots/check")
            .join(name)
    }

    fn assert_text_snapshot(snapshot: &Path, actual: &str) {
        if std::env::var_os("VSR_UPDATE_SNAPSHOTS").is_some() {
            if let Some(parent) = snapshot.parent() {
                fs::create_dir_all(parent).expect("snapshot parent should be creatable");
            }
            fs::write(snapshot, actual).expect("snapshot should be writable");
            return;
        }

        let expected = fs::read_to_string(snapshot).unwrap_or_else(|error| {
            panic!(
                "snapshot {} is missing or unreadable: {error}. Re-run with VSR_UPDATE_SNAPSHOTS=1 to create it.",
                snapshot.display()
            )
        });
        let expected = expected.trim_end_matches('\n');
        let actual = actual.trim_end_matches('\n');
        assert_eq!(
            expected,
            actual,
            "snapshot mismatch at {}",
            snapshot.display()
        );
    }

    fn normalize_report_source(report: &ServiceCheckReport, source: &str) -> ServiceCheckReport {
        let mut normalized = report.clone();
        normalized.source = source.to_owned();
        normalized
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
    fn check_report_warns_for_many_to_many_join_without_explicit_source_index() {
        let root = temp_dir("many-to-many-fixture");
        let config = root.join("many_to_many_check_api.eon");
        fs::write(
            &config,
            r#"
module: "many_to_many_check_api"
resources: [
    {
        name: "Post"
        many_to_many: [
            {
                name: "tags"
                target: "Tag"
                through: "PostTag"
                source_field: "post_id"
                target_field: "tag_id"
            }
        ]
        fields: [
            { name: "id", type: I64, id: true }
        ]
    }
    {
        name: "Tag"
        fields: [
            { name: "id", type: I64, id: true }
        ]
    }
    {
        name: "PostTag"
        fields: [
            { name: "id", type: I64, id: true }
            {
                name: "post_id"
                type: I64
                relation: {
                    references: "post.id"
                }
            }
            {
                name: "tag_id"
                type: I64
                relation: {
                    references: "tag.id"
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
        assert!(codes.contains(&"indexes.explicit_many_to_many_index_missing"));
    }

    #[test]
    fn check_report_warns_for_build_artifact_overlaps() {
        let root = temp_dir("build-artifact-overlap");
        let config = root.join("build_artifact_overlap_api.eon");
        fs::write(
            &config,
            r#"
module: "build_artifact_overlap_api"
build: {
    artifacts: {
        binary: {
            path: "dist/site.bundle/api"
        }
        bundle: {
            path: "dist/site.bundle"
        }
        cache: {
            root: "dist/site.bundle/cache"
        }
    }
}
resources: [
    {
        name: "Asset"
        fields: [
            { name: "id", type: I64, id: true }
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
        assert!(codes.contains(&"build.artifacts.binary_inside_bundle"));
        assert!(codes.contains(&"build.artifacts.cache_bundle_overlap"));
    }

    #[test]
    fn check_report_warns_for_empty_build_artifact_env_override() {
        let root = temp_dir("build-artifact-env-empty");
        let config = root.join("build_artifact_env_check_api.eon");
        let env_name = format!(
            "VSR_TEST_BUILD_ARTIFACT_BINARY_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should advance")
                .as_nanos()
        );
        fs::write(
            &config,
            format!(
                r#"
module: "build_artifact_env_check_api"
build: {{
    artifacts: {{
        binary: {{
            env: "{env_name}"
        }}
    }}
}}
resources: [
    {{
        name: "Asset"
        fields: [
            {{ name: "id", type: I64, id: true }}
            {{ name: "title", type: String }}
        ]
    }}
]
"#
            ),
        )
        .expect("fixture should write");

        unsafe {
            std::env::set_var(&env_name, "   ");
        }
        let report = build_service_check_report(&config, &[], true).expect("fixture should load");
        unsafe {
            std::env::remove_var(&env_name);
        }

        let codes = report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"build.artifacts.binary_env_override_empty"));
    }

    #[test]
    fn check_report_warns_for_binary_bundle_path_collision() {
        let root = temp_dir("build-artifact-collision");
        let config = root.join("build_artifact_collision_api.eon");
        fs::write(
            &config,
            r#"
module: "build_artifact_collision_api"
build: {
    artifacts: {
        binary: {
            path: "dist/api"
        }
        bundle: {
            path: "dist/api"
        }
    }
}
resources: [
    {
        name: "Asset"
        fields: [
            { name: "id", type: I64, id: true }
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
        assert!(codes.contains(&"build.artifacts.binary_bundle_path_collision"));
    }

    #[test]
    fn check_report_warns_for_client_automation_path_overlaps_and_empty_env_overrides() {
        let root = temp_dir("client-automation-overlap");
        let config = root.join("client_overlap_api.eon");
        let output_env = format!(
            "VSR_TEST_CLIENT_OUTPUT_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should advance")
                .as_nanos()
        );
        let package_env = format!(
            "VSR_TEST_CLIENT_PACKAGE_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should advance")
                .as_nanos()
        );
        let report_env = format!(
            "VSR_TEST_CLIENT_REPORT_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should advance")
                .as_nanos()
        );
        fs::write(
            &config,
            format!(
                r#"
module: "client_overlap_api"
clients: {{
    ts: {{
        output_dir: {{
            path: ".vsr-build/client-overlap-api"
            env: "{output_env}"
        }}
        package_name: {{
            value: "@demo/client-overlap-api"
            env: "{package_env}"
        }}
        automation: {{
            on_build: true
            self_test: true
            self_test_report: {{
                path: ".vsr-build/client-overlap-api/package.json"
                env: "{report_env}"
            }}
        }}
    }}
}}
resources: [
    {{
        name: "Asset"
        fields: [
            {{ name: "id", type: I64, id: true }}
            {{ name: "title", type: String }}
        ]
    }}
]
"#
            ),
        )
        .expect("fixture should write");

        unsafe {
            std::env::set_var(&output_env, "   ");
            std::env::set_var(&package_env, "   ");
            std::env::set_var(&report_env, "   ");
        }
        let report = build_service_check_report(&config, &[], true).expect("fixture should load");
        unsafe {
            std::env::remove_var(&output_env);
            std::env::remove_var(&package_env);
            std::env::remove_var(&report_env);
        }

        let codes = report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"clients.ts.output_dir_env_override_empty"));
        assert!(codes.contains(&"clients.ts.package_name_env_override_empty"));
        assert!(codes.contains(&"clients.ts.self_test_report_env_override_empty"));
        assert!(codes.contains(&"clients.ts.output_dir_overlaps_build_cache"));
        assert!(codes.contains(&"clients.ts.self_test_report_path_collides_with_generated_file"));
    }

    #[test]
    fn check_report_warns_for_client_automation_output_overlapping_bundle() {
        let root = temp_dir("client-automation-bundle-overlap");
        let config = root.join("client_bundle_overlap_api.eon");
        fs::write(
            &config,
            r#"
module: "client_bundle_overlap_api"
clients: {
    ts: {
        output_dir: {
            path: "client-bundle-overlap-api.bundle/generated-client"
        }
        automation: {
            on_build: true
        }
    }
}
resources: [
    {
        name: "Asset"
        fields: [
            { name: "id", type: I64, id: true }
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
        assert!(codes.contains(&"clients.ts.output_dir_overlaps_bundle"));
    }

    #[test]
    fn check_report_warns_for_storage_backend_root_that_is_not_directory() {
        let root = temp_dir("storage-backend-root-file");
        let blocking_path = root.join("var/uploads");
        fs::create_dir_all(blocking_path.parent().expect("parent should exist"))
            .expect("parent directory should create");
        fs::write(&blocking_path, "not a directory").expect("blocking file should write");
        let config = root.join("storage_backend_check_api.eon");
        fs::write(
            &config,
            r#"
module: "storage_backend_check_api"
storage: {
    backends: [
        {
            name: "uploads"
            kind: "Local"
            dir: "var/uploads"
        }
    ]
}
resources: [
    {
        name: "Asset"
        fields: [
            { name: "id", type: I64, id: true }
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
        assert!(codes.contains(&"storage.backend_root_not_directory"));
    }

    #[test]
    fn check_report_warns_for_unused_storage_backend() {
        let root = temp_dir("unused-storage-backend");
        let config = root.join("unused_storage_backend_api.eon");
        fs::write(
            &config,
            r#"
module: "unused_storage_backend_api"
storage: {
    backends: [
        {
            name: "orphaned"
            kind: "Local"
            dir: "var/orphaned"
        }
    ]
}
resources: [
    {
        name: "Asset"
        fields: [
            { name: "id", type: I64, id: true }
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
        assert!(codes.contains(&"storage.unused_backend"));
    }

    #[test]
    fn check_report_warns_for_upload_roles_without_auth() {
        let root = temp_dir("upload-roles-without-auth");
        let config = root.join("upload_roles_without_auth_api.eon");
        fs::write(
            &config,
            r#"
module: "upload_roles_without_auth_api"
storage: {
    backends: [
        {
            name: "uploads"
            kind: "Local"
            dir: "var/uploads"
        }
    ]
    uploads: [
        {
            name: "asset_upload"
            path: "uploads"
            backend: "uploads"
            require_auth: false
            roles: ["editor"]
        }
    ]
}
resources: [
    {
        name: "Asset"
        fields: [
            { name: "id", type: I64, id: true }
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
        assert!(codes.contains(&"storage.upload_roles_without_auth"));
    }

    #[test]
    fn check_report_warns_for_legacy_jwt_secret_configuration() {
        let root = temp_dir("legacy-jwt-secret");
        let config = root.join("legacy_jwt_secret_api.eon");
        fs::write(
            &config,
            r#"
module: "legacy_jwt_secret_api"
security: {
    auth: {
        jwt_secret: { systemd_credential: "jwt_secret" }
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

        let report = build_service_check_report(&config, &[], true).expect("fixture should load");
        let codes = report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"security.auth.legacy_jwt_secret_configured"));
    }

    #[test]
    fn check_report_warns_for_asymmetric_jwt_without_rotation_overlap() {
        let root = temp_dir("single-jwt-verification-key");
        let config = root.join("single_jwt_verification_key_api.eon");
        fs::write(
            &config,
            r#"
module: "single_jwt_verification_key_api"
security: {
    auth: {
        jwt: {
            algorithm: EdDSA
            active_kid: "current"
            signing_key: { systemd_credential: "jwt_signing_key" }
            verification_keys: [
                {
                    kid: "current"
                    key: { systemd_credential: "jwt_public_key" }
                }
            ]
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

        let report = build_service_check_report(&config, &[], true).expect("fixture should load");
        let codes = report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"security.auth.jwt_rotation_overlap_missing"));
    }

    #[test]
    fn check_report_warns_for_localhost_auth_email_public_base_url() {
        let root = temp_dir("localhost-auth-email-base");
        let config = root.join("localhost_auth_email_api.eon");
        fs::write(
            &config,
            r#"
module: "localhost_auth_email_api"
security: {
    auth: {
        require_email_verification: true
        email: {
            from_email: "noreply@example.com"
            public_base_url: "http://127.0.0.1:8082"
            provider: {
                kind: Resend
                api_key_env: "RESEND_API_KEY"
            }
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

        let report = build_service_check_report(&config, &[], true).expect("fixture should load");
        let codes = report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"security.auth.email.public_base_url_is_local"));
    }

    #[test]
    fn check_report_warns_for_non_https_auth_email_public_base_url() {
        let root = temp_dir("non-https-auth-email-base");
        let config = root.join("non_https_auth_email_api.eon");
        fs::write(
            &config,
            r#"
module: "non_https_auth_email_api"
security: {
    auth: {
        require_email_verification: true
        email: {
            from_email: "noreply@example.com"
            public_base_url: "http://example.com"
            provider: {
                kind: Resend
                api_key_env: "RESEND_API_KEY"
            }
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

        let report = build_service_check_report(&config, &[], true).expect("fixture should load");
        let codes = report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"security.auth.email.public_base_url_not_https"));
    }

    #[test]
    fn check_report_warns_when_asymmetric_verification_key_reuses_signing_secret_ref() {
        let root = temp_dir("jwt-shared-secret-ref");
        let config = root.join("jwt_shared_secret_ref_api.eon");
        fs::write(
            &config,
            r#"
module: "jwt_shared_secret_ref_api"
security: {
    auth: {
        jwt: {
            algorithm: EdDSA
            active_kid: "current"
            signing_key: { systemd_credential: "jwt_keypair" }
            verification_keys: [
                {
                    kid: "current"
                    key: { systemd_credential: "jwt_keypair" }
                }
                {
                    kid: "previous"
                    key: { systemd_credential: "jwt_previous_public" }
                }
            ]
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

        let report = build_service_check_report(&config, &[], true).expect("fixture should load");
        let codes = report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"security.auth.jwt_verification_key_matches_signing_key"));
    }

    #[test]
    fn check_report_warns_for_auth_ui_path_collisions() {
        let root = temp_dir("auth-ui-path-collisions");
        fs::create_dir_all(root.join("public")).expect("static dir should exist");
        fs::write(root.join("public/index.html"), "<html></html>").expect("index should exist");
        let config = root.join("auth_ui_path_collision_api.eon");
        fs::write(
            &config,
            r#"
module: "auth_ui_path_collision_api"
authorization: {
    management_api: {
        mount: "/ops/authz"
    }
}
static: {
    mounts: [
        {
            mount: "/api/auth/portal"
            dir: "public"
            mode: Spa
            cache: NoStore
        }
    ]
}
storage: {
    backends: [
        {
            name: "uploads"
            kind: Local
            dir: "var/uploads"
        }
    ]
    uploads: [
        {
            name: "asset_upload"
            path: "dashboard"
            backend: "uploads"
        }
    ]
}
security: {
    auth: {
        portal: {
            path: "/note"
            title: "Portal"
        }
        admin_dashboard: {
            path: "/ops/authz"
            title: "Admin Dashboard"
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

        let report = build_service_check_report(&config, &[], true).expect("fixture should load");
        let codes = report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"security.auth.ui_path_overlaps_resource_namespace"));
        assert!(codes.contains(&"security.auth.ui_path_overlaps_authorization_management"));

        let rendered =
            render_service_check_report(&report, OutputFormat::Text).expect("text should render");
        assert!(rendered.contains("security.auth.ui_path_overlaps_resource_namespace"));
        assert!(rendered.contains("security.auth.ui_path_overlaps_authorization_management"));
    }

    #[test]
    fn check_report_auth_ui_path_collisions_match_text_snapshot() {
        let root = temp_dir("auth-ui-path-collision-snapshot");
        fs::create_dir_all(root.join("public")).expect("static dir should exist");
        fs::write(root.join("public/index.html"), "<html></html>").expect("index should exist");
        let config = root.join("auth_ui_path_collision_api.eon");
        fs::write(
            &config,
            r#"
module: "auth_ui_path_collision_api"
authorization: {
    management_api: {
        mount: "/ops/authz"
    }
}
static: {
    mounts: [
        {
            mount: "/api/auth/portal"
            dir: "public"
            mode: Spa
            cache: NoStore
        }
    ]
}
storage: {
    backends: [
        {
            name: "uploads"
            kind: Local
            dir: "var/uploads"
        }
    ]
    uploads: [
        {
            name: "dashboard_upload"
            path: "dashboard/files"
            backend: "uploads"
        }
    ]
}
security: {
    auth: {
        portal: {
            path: "/auth/portal"
            title: "Portal"
        }
        admin_dashboard: {
            path: "/dashboard"
            title: "Admin Dashboard"
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

        let report = build_service_check_report(&config, &[], true).expect("fixture should load");
        let normalized =
            normalize_report_source(&report, "tests/fixtures/auth_ui_path_collision_api.eon");
        let rendered = render_service_check_report(&normalized, OutputFormat::Text)
            .expect("text should render");
        assert_text_snapshot(&snapshot_path("auth_ui_path_collision_api.txt"), &rendered);
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

    #[test]
    fn check_report_authorization_contract_matches_text_snapshot() {
        let report =
            build_service_check_report(&fixture_path("authorization_contract_api.eon"), &[], true)
                .expect("fixture should load");
        let normalized =
            normalize_report_source(&report, "tests/fixtures/authorization_contract_api.eon");
        let rendered = render_service_check_report(&normalized, OutputFormat::Text)
            .expect("text should render");
        assert_text_snapshot(&snapshot_path("authorization_contract_api.txt"), &rendered);
    }

    #[test]
    fn check_report_hybrid_runtime_matches_json_snapshot() {
        let report = build_service_check_report(&fixture_path("hybrid_runtime_api.eon"), &[], true)
            .expect("fixture should load");
        let normalized = normalize_report_source(&report, "tests/fixtures/hybrid_runtime_api.eon");
        let rendered = render_service_check_report(&normalized, OutputFormat::Json)
            .expect("json should render");
        assert_text_snapshot(&snapshot_path("hybrid_runtime_api.json"), &rendered);
    }
}
