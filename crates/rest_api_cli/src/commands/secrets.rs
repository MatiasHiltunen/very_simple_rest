use crate::error::{Error, Result};
use clap::ValueEnum;
use rest_macro_core::{
    auth::{AuthEmailProvider, auth_jwt_signing_secret_ref},
    compiler::{self, ServiceSpec, default_service_database_url},
    database::{DatabaseEngine, DatabaseReplicationMode},
    secret::{describe_secret_source, load_optional_secret_from_env_or_file},
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum InfisicalAuthMethod {
    UniversalAuth,
    Azure,
    AwsIam,
    Kubernetes,
    GcpIdToken,
    GcpIam,
}

impl InfisicalAuthMethod {
    fn auth_type(self) -> &'static str {
        match self {
            Self::UniversalAuth => "universal-auth",
            Self::Azure => "azure",
            Self::AwsIam => "aws-iam",
            Self::Kubernetes => "kubernetes",
            Self::GcpIdToken => "gcp-id-token",
            Self::GcpIam => "gcp-iam",
        }
    }

    fn auth_readme(self) -> &'static str {
        match self {
            Self::UniversalAuth => {
                "Populate `auth/client-id` and `auth/client-secret` with the Infisical Universal Auth client credentials for this workload."
            }
            Self::Azure => {
                "Populate `auth/identity-id` with the Infisical machine identity id used for Azure authentication."
            }
            Self::AwsIam => {
                "Populate `auth/identity-id` with the Infisical machine identity id used for AWS IAM authentication."
            }
            Self::Kubernetes => {
                "Populate `auth/identity-id` with the Infisical machine identity id used for Kubernetes authentication."
            }
            Self::GcpIdToken => {
                "Populate `auth/identity-id` with the Infisical machine identity id used for GCP ID token authentication."
            }
            Self::GcpIam => {
                "Populate `auth/identity-id` and `auth/service-account-key.json` with the Infisical machine identity id and the GCP service account key file."
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InfisicalScaffoldReport {
    pub output_dir: PathBuf,
    pub files: Vec<PathBuf>,
    pub secret_bindings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct SecretBindingSpec {
    var_name: String,
    description: String,
    example_value: String,
    required: bool,
}

#[derive(Clone, Debug, Serialize)]
struct SecretBindingCheck {
    var_name: String,
    description: String,
    required: bool,
    status: DoctorStatus,
    source: Option<String>,
    detail: String,
}

#[derive(Clone, Debug, Serialize)]
struct ScaffoldCheck {
    name: String,
    status: DoctorStatus,
    detail: String,
}

#[derive(Clone, Debug, Serialize)]
struct SecretsDoctorReport {
    kind: String,
    service_module: String,
    scaffold_dir: Option<String>,
    healthy: bool,
    bindings: Vec<SecretBindingCheck>,
    scaffold_checks: Vec<ScaffoldCheck>,
}

pub fn scaffold_infisical(
    config_path: &Path,
    output_dir: Option<&Path>,
    project_slug: &str,
    project_id: Option<&str>,
    environment: &str,
    secret_path: &str,
    render_dir: &str,
    auth_method: InfisicalAuthMethod,
    force: bool,
) -> Result<InfisicalScaffoldReport> {
    if project_slug.trim().is_empty() {
        return Err(Error::Validation(
            "Infisical project slug cannot be empty".to_owned(),
        ));
    }
    if let Some(project_id) = project_id
        && project_id.trim().is_empty()
    {
        return Err(Error::Validation(
            "Infisical project ID cannot be empty when provided".to_owned(),
        ));
    }
    if environment.trim().is_empty() {
        return Err(Error::Validation(
            "Infisical environment cannot be empty".to_owned(),
        ));
    }
    if secret_path.trim().is_empty() {
        return Err(Error::Validation(
            "Infisical secret path cannot be empty".to_owned(),
        ));
    }
    if render_dir.trim().is_empty() {
        return Err(Error::Validation(
            "Infisical render directory cannot be empty".to_owned(),
        ));
    }

    let service = load_service(config_path)?;
    let secret_bindings = collect_secret_bindings(&service);
    let scaffold_dir = resolve_output_dir(config_path, output_dir)?;
    let templates_dir = scaffold_dir.join("templates");
    let auth_dir = scaffold_dir.join("auth");

    let mut files = vec![
        scaffold_dir.join("README.md"),
        scaffold_dir.join("runtime.env"),
        scaffold_dir.join("expected-secrets.env"),
        scaffold_dir.join("infisical-agent.yaml"),
        auth_dir.join("README.md"),
    ];
    files.extend(
        secret_bindings
            .iter()
            .map(|binding| templates_dir.join(format!("{}.tpl", binding.var_name))),
    );

    if !force && let Some(existing) = files.iter().find(|path| path.exists()) {
        return Err(Error::Config(format!(
            "Refusing to overwrite existing scaffold file `{}`. Re-run with --force.",
            existing.display()
        )));
    }

    std::fs::create_dir_all(&scaffold_dir)?;
    std::fs::create_dir_all(&templates_dir)?;
    std::fs::create_dir_all(&auth_dir)?;

    let normalized_secret_path = normalize_secret_path(secret_path);
    let normalized_render_dir = normalize_render_dir(render_dir);
    let project_ref = InfisicalProjectRef {
        slug: project_slug,
        id: project_id,
    };

    std::fs::write(
        scaffold_dir.join("README.md"),
        render_scaffold_readme(
            project_ref,
            environment,
            normalized_secret_path.as_str(),
            normalized_render_dir.as_str(),
            auth_method,
            &secret_bindings,
        ),
    )?;
    std::fs::write(
        auth_dir.join("README.md"),
        render_auth_readme(auth_method, normalized_render_dir.as_str()),
    )?;
    std::fs::write(
        scaffold_dir.join("runtime.env"),
        render_runtime_env(normalized_render_dir.as_str(), &secret_bindings),
    )?;
    std::fs::write(
        scaffold_dir.join("expected-secrets.env"),
        render_expected_secrets_env(&service, &secret_bindings),
    )?;
    std::fs::write(
        scaffold_dir.join("infisical-agent.yaml"),
        render_infisical_agent_config(
            auth_method,
            normalized_render_dir.as_str(),
            &secret_bindings,
        ),
    )?;
    for binding in &secret_bindings {
        std::fs::write(
            templates_dir.join(format!("{}.tpl", binding.var_name)),
            render_template(
                project_ref,
                environment,
                normalized_secret_path.as_str(),
                binding.var_name.as_str(),
            ),
        )?;
    }

    Ok(InfisicalScaffoldReport {
        output_dir: scaffold_dir,
        files,
        secret_bindings: secret_bindings
            .into_iter()
            .map(|binding| binding.var_name)
            .collect(),
    })
}

pub fn doctor_secrets(
    config_path: &Path,
    infisical_dir: Option<&Path>,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let service = load_service(config_path)?;
    let bindings = collect_secret_bindings(&service);
    let binding_checks = bindings
        .iter()
        .map(check_binding_resolution)
        .collect::<Vec<_>>();
    let scaffold_checks = match infisical_dir {
        Some(dir) => collect_infisical_scaffold_checks(dir, &bindings),
        None => Vec::new(),
    };

    let healthy = binding_checks
        .iter()
        .all(|check| check.status != DoctorStatus::Fail)
        && scaffold_checks
            .iter()
            .all(|check| check.status != DoctorStatus::Fail);

    let report = SecretsDoctorReport {
        kind: "secrets_doctor".to_owned(),
        service_module: service.module_ident.to_string(),
        scaffold_dir: infisical_dir.map(|path| path.display().to_string()),
        healthy,
        bindings: binding_checks,
        scaffold_checks,
    };

    let rendered = match format {
        OutputFormat::Text => render_doctor_report_text(&report),
        OutputFormat::Json => serde_json::to_string_pretty(&report).map_err(|error| {
            Error::Unknown(format!(
                "failed to serialize secrets doctor report: {error}"
            ))
        })?,
    };

    write_output(rendered, output, force, "secrets doctor report")
}

fn load_service(config_path: &Path) -> Result<ServiceSpec> {
    compiler::load_service_from_path(config_path).map_err(|error| Error::Config(error.to_string()))
}

fn resolve_output_dir(config_path: &Path, output_dir: Option<&Path>) -> Result<PathBuf> {
    let raw = match output_dir {
        Some(path) => path.to_path_buf(),
        None => config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("deploy/infisical"),
    };
    if raw.is_absolute() {
        Ok(raw)
    } else {
        Ok(std::env::current_dir()?.join(raw))
    }
}

fn normalize_secret_path(secret_path: &str) -> String {
    let trimmed = secret_path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_owned()
    } else if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}

fn normalize_render_dir(render_dir: &str) -> String {
    let trimmed = render_dir.trim();
    if trimmed.ends_with('/') && trimmed.len() > 1 {
        trimmed.trim_end_matches('/').to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn service_owns_user_table(service: &ServiceSpec) -> bool {
    service
        .resources
        .iter()
        .any(|resource| resource.table_name == "user")
}

fn collect_secret_bindings(service: &ServiceSpec) -> Vec<SecretBindingSpec> {
    let mut bindings = BTreeMap::<String, SecretBindingSpec>::new();

    insert_binding(
        &mut bindings,
        SecretBindingSpec {
            var_name: "DATABASE_URL".to_owned(),
            description: "Primary database connection string".to_owned(),
            example_value: default_service_database_url(service),
            required: true,
        },
    );

    if !service_owns_user_table(service) {
        let jwt_var = auth_jwt_signing_secret_ref(&service.security.auth)
            .and_then(|secret| secret.env_binding_name())
            .unwrap_or("JWT_SECRET");
        insert_binding(
            &mut bindings,
            SecretBindingSpec {
                var_name: jwt_var.to_owned(),
                description: "Built-in auth JWT signing key".to_owned(),
                example_value: if service
                    .security
                    .auth
                    .jwt
                    .as_ref()
                    .is_some_and(|jwt| !jwt.algorithm.is_symmetric())
                {
                    "-----BEGIN PRIVATE KEY-----...".to_owned()
                } else {
                    "change-me".to_owned()
                },
                required: true,
            },
        );
        if let Some(jwt) = &service.security.auth.jwt {
            for verification_key in &jwt.verification_keys {
                if let Some(var_name) = verification_key.key.env_binding_name() {
                    insert_binding(
                        &mut bindings,
                        SecretBindingSpec {
                            var_name: var_name.to_owned(),
                            description: format!(
                                "Built-in auth JWT verification key `{}`",
                                verification_key.kid
                            ),
                            example_value: "-----BEGIN PUBLIC KEY-----...".to_owned(),
                            required: true,
                        },
                    );
                }
            }
        }
    }

    if let DatabaseEngine::TursoLocal(engine) = &service.database.engine
        && let Some(var_name) = engine
            .encryption_key
            .as_ref()
            .and_then(|secret| secret.env_binding_name())
    {
        insert_binding(
            &mut bindings,
            SecretBindingSpec {
                var_name: var_name.to_owned(),
                description: "Local Turso encryption key".to_owned(),
                example_value: "change-me-64-hex-characters".to_owned(),
                required: true,
            },
        );
    }

    if let Some(email) = service.security.auth.email.as_ref() {
        match &email.provider {
            AuthEmailProvider::Resend { api_key, .. } => {
                if let Some(var_name) = api_key.env_binding_name() {
                    insert_binding(
                        &mut bindings,
                        SecretBindingSpec {
                            var_name: var_name.to_owned(),
                            description: "Built-in auth Resend API key".to_owned(),
                            example_value: "change-me".to_owned(),
                            required: true,
                        },
                    );
                }
            }
            AuthEmailProvider::Smtp { connection_url } => {
                if let Some(var_name) = connection_url.env_binding_name() {
                    insert_binding(
                        &mut bindings,
                        SecretBindingSpec {
                            var_name: var_name.to_owned(),
                            description: "Built-in auth SMTP connection URL".to_owned(),
                            example_value: "smtp://user:password@smtp.example.com:587".to_owned(),
                            required: true,
                        },
                    );
                }
            }
        }
    }

    if let Some(resilience) = service.database.resilience.as_ref() {
        if let Some(backup) = resilience.backup.as_ref()
            && let Some(var_name) = backup
                .encryption_key
                .as_ref()
                .and_then(|secret| secret.env_binding_name())
        {
            insert_binding(
                &mut bindings,
                SecretBindingSpec {
                    var_name: var_name.to_owned(),
                    description: "Backup encryption key".to_owned(),
                    example_value: "change-me".to_owned(),
                    required: true,
                },
            );
        }
        if let Some(replication) = resilience.replication.as_ref()
            && let Some(var_name) = replication
                .read_url
                .as_ref()
                .and_then(|secret| secret.env_binding_name())
        {
            insert_binding(
                &mut bindings,
                SecretBindingSpec {
                    var_name: var_name.to_owned(),
                    description: "Read-replica database connection string".to_owned(),
                    example_value: "postgres://reader:password@db-replica.example.com/app"
                        .to_owned(),
                    required: replication.mode != DatabaseReplicationMode::None,
                },
            );
        }
    }

    bindings.into_values().collect()
}

fn insert_binding(bindings: &mut BTreeMap<String, SecretBindingSpec>, binding: SecretBindingSpec) {
    bindings.entry(binding.var_name.clone()).or_insert(binding);
}

#[derive(Clone, Copy, Debug)]
struct InfisicalProjectRef<'a> {
    slug: &'a str,
    id: Option<&'a str>,
}

fn render_scaffold_readme(
    project_ref: InfisicalProjectRef<'_>,
    environment: &str,
    secret_path: &str,
    render_dir: &str,
    auth_method: InfisicalAuthMethod,
    bindings: &[SecretBindingSpec],
) -> String {
    let mut output = String::new();
    writeln!(&mut output, "# Infisical Scaffold").unwrap();
    writeln!(&mut output).unwrap();
    writeln!(
        &mut output,
        "This directory was generated by `vsr secrets infisical scaffold`."
    )
    .unwrap();
    writeln!(&mut output).unwrap();
    writeln!(&mut output, "## Generated files").unwrap();
    writeln!(
        &mut output,
        "- `infisical-agent.yaml`: Infisical Agent config"
    )
    .unwrap();
    writeln!(
        &mut output,
        "- `runtime.env`: `*_FILE` pointers for the VSR runtime/CLI"
    )
    .unwrap();
    writeln!(
        &mut output,
        "- `expected-secrets.env`: import-friendly list of expected Infisical secrets"
    )
    .unwrap();
    writeln!(
        &mut output,
        "- `templates/*.tpl`: one Infisical template per secret binding"
    )
    .unwrap();
    writeln!(
        &mut output,
        "- `auth/README.md`: auth-method specific bootstrap notes"
    )
    .unwrap();
    writeln!(&mut output).unwrap();
    writeln!(&mut output, "## Parameters").unwrap();
    writeln!(&mut output, "- Project slug: `{}`", project_ref.slug).unwrap();
    if let Some(project_id) = project_ref.id {
        writeln!(&mut output, "- Project ID: `{project_id}`").unwrap();
    }
    writeln!(&mut output, "- Environment: `{environment}`").unwrap();
    writeln!(&mut output, "- Secret path: `{secret_path}`").unwrap();
    writeln!(&mut output, "- Render directory: `{render_dir}`").unwrap();
    writeln!(&mut output, "- Auth method: `{}`", auth_method.auth_type()).unwrap();
    writeln!(&mut output).unwrap();
    writeln!(&mut output, "## Secret bindings").unwrap();
    for binding in bindings {
        writeln!(
            &mut output,
            "- `{}`: {}{}",
            binding.var_name,
            binding.description,
            if binding.required { "" } else { " (optional)" }
        )
        .unwrap();
    }
    writeln!(&mut output).unwrap();
    writeln!(&mut output, "## Next steps").unwrap();
    writeln!(
        &mut output,
        "1. Create the listed secrets in Infisical, or import `expected-secrets.env` into the target project/environment."
    )
    .unwrap();
    writeln!(
        &mut output,
        "2. Follow `auth/README.md` to provision the Infisical auth files used by the agent."
    )
    .unwrap();
    writeln!(
        &mut output,
        "3. Start the agent from this directory with `infisical agent --config infisical-agent.yaml`."
    )
    .unwrap();
    writeln!(
        &mut output,
        "4. Load `runtime.env` into your service environment or convert it into your systemd / Docker / Kubernetes configuration."
    )
    .unwrap();
    writeln!(
        &mut output,
        "5. For local development, you can still use `infisical run -- vsr serve api.eon` if you prefer direct env injection."
    )
    .unwrap();

    output
}

fn render_auth_readme(auth_method: InfisicalAuthMethod, render_dir: &str) -> String {
    let mut output = String::new();
    writeln!(&mut output, "# Infisical Auth Inputs").unwrap();
    writeln!(&mut output).unwrap();
    writeln!(
        &mut output,
        "Selected auth method: `{}`",
        auth_method.auth_type()
    )
    .unwrap();
    writeln!(&mut output).unwrap();
    writeln!(&mut output, "{}", auth_method.auth_readme()).unwrap();
    writeln!(&mut output).unwrap();
    writeln!(
        &mut output,
        "The generated agent config renders secret files into `{render_dir}`. The VSR runtime then reads those files through the `*_FILE` bindings in `runtime.env`."
    )
    .unwrap();
    output
}

fn render_runtime_env(render_dir: &str, bindings: &[SecretBindingSpec]) -> String {
    let mut output = String::new();
    writeln!(
        &mut output,
        "# Generated by `vsr secrets infisical scaffold`"
    )
    .unwrap();
    writeln!(
        &mut output,
        "# Load this file into the runtime environment so VSR reads secret files rendered by Infisical Agent."
    )
    .unwrap();
    writeln!(&mut output).unwrap();
    for binding in bindings {
        writeln!(
            &mut output,
            "{}_FILE={}/{}",
            binding.var_name, render_dir, binding.var_name
        )
        .unwrap();
    }
    output
}

fn render_expected_secrets_env(service: &ServiceSpec, bindings: &[SecretBindingSpec]) -> String {
    let mut output = String::new();
    writeln!(
        &mut output,
        "# Generated by `vsr secrets infisical scaffold`"
    )
    .unwrap();
    writeln!(
        &mut output,
        "# Import these keys into Infisical and replace the example values before production use."
    )
    .unwrap();
    writeln!(&mut output).unwrap();
    writeln!(&mut output, "# Service module: {}", service.module_ident).unwrap();
    writeln!(&mut output).unwrap();
    for binding in bindings {
        writeln!(&mut output, "# {}", binding.description).unwrap();
        writeln!(
            &mut output,
            "{}={}",
            binding.var_name, binding.example_value
        )
        .unwrap();
        writeln!(&mut output).unwrap();
    }
    output
}

fn render_infisical_agent_config(
    auth_method: InfisicalAuthMethod,
    render_dir: &str,
    bindings: &[SecretBindingSpec],
) -> String {
    let mut output = String::new();
    writeln!(&mut output, "infisical:").unwrap();
    writeln!(&mut output, "  address: \"https://app.infisical.com\"").unwrap();
    writeln!(&mut output, "  exit-after-auth: false").unwrap();
    writeln!(&mut output, "auth:").unwrap();
    writeln!(&mut output, "  type: \"{}\"", auth_method.auth_type()).unwrap();
    writeln!(&mut output, "  config:").unwrap();
    match auth_method {
        InfisicalAuthMethod::UniversalAuth => {
            writeln!(&mut output, "    client-id: \"./auth/client-id\"").unwrap();
            writeln!(&mut output, "    client-secret: \"./auth/client-secret\"").unwrap();
            writeln!(&mut output, "    remove_client_secret_on_read: false").unwrap();
        }
        InfisicalAuthMethod::Azure
        | InfisicalAuthMethod::AwsIam
        | InfisicalAuthMethod::Kubernetes
        | InfisicalAuthMethod::GcpIdToken => {
            writeln!(&mut output, "    identity-id: \"./auth/identity-id\"").unwrap();
        }
        InfisicalAuthMethod::GcpIam => {
            writeln!(&mut output, "    identity-id: \"./auth/identity-id\"").unwrap();
            writeln!(
                &mut output,
                "    service-account-key: \"./auth/service-account-key.json\""
            )
            .unwrap();
        }
    }
    writeln!(&mut output, "templates:").unwrap();
    for binding in bindings {
        writeln!(
            &mut output,
            "  - source-path: \"./templates/{}.tpl\"",
            binding.var_name
        )
        .unwrap();
        writeln!(
            &mut output,
            "    destination-path: \"{}/{}\"",
            render_dir, binding.var_name
        )
        .unwrap();
        writeln!(&mut output, "    config:").unwrap();
        writeln!(&mut output, "      polling-interval: 60s").unwrap();
    }
    output
}

fn render_template(
    project_ref: InfisicalProjectRef<'_>,
    environment: &str,
    secret_path: &str,
    key: &str,
) -> String {
    if let Some(project_id) = project_ref.id {
        return format!(
            "{{{{- with getSecretByName \"{project_id}\" \"{environment}\" \"{secret_path}\" \"{key}\" -}}}}\n\
{{{{- .Value -}}}}\n\
{{{{- end -}}}}\n"
        );
    }

    format!(
        "{{{{- with listSecretsByProjectSlug \"{}\" \"{environment}\" \"{secret_path}\" `{{\"recursive\": false, \"expandSecretReferences\": true}}` -}}}}\n\
{{{{- range . -}}}}\n\
{{{{- if eq .Key \"{key}\" -}}}}\n\
{{{{ .Value }}}}\n\
{{{{- end -}}}}\n\
{{{{- end -}}}}\n\
{{{{- end -}}}}\n",
        project_ref.slug
    )
}

fn check_binding_resolution(binding: &SecretBindingSpec) -> SecretBindingCheck {
    let source = describe_secret_source(binding.var_name.as_str());
    let detail = match load_optional_secret_from_env_or_file(
        binding.var_name.as_str(),
        binding.description.as_str(),
    ) {
        Ok(Some(_)) => {
            let how = source
                .clone()
                .unwrap_or_else(|| "a resolved binding".to_owned());
            return SecretBindingCheck {
                var_name: binding.var_name.clone(),
                description: binding.description.clone(),
                required: binding.required,
                status: DoctorStatus::Pass,
                source,
                detail: format!("Resolved via {how}."),
            };
        }
        Ok(None) if binding.var_name == "DATABASE_URL" => {
            format!(
                "No `DATABASE_URL` override is set. The service can still use its compiled default `{}`.",
                binding.example_value
            )
        }
        Ok(None) if binding.required => {
            format!(
                "Missing required binding `{}` or `{}_FILE`.",
                binding.var_name, binding.var_name
            )
        }
        Ok(None) => {
            format!(
                "Optional binding `{}` is not currently resolved.",
                binding.var_name
            )
        }
        Err(error) => error.to_string(),
    };

    let status = if binding.var_name == "DATABASE_URL" {
        DoctorStatus::Pass
    } else if detail.starts_with("Missing required") || detail.contains("resolved to an empty") {
        DoctorStatus::Fail
    } else if detail.contains("unreadable file") {
        DoctorStatus::Fail
    } else if binding.required {
        DoctorStatus::Fail
    } else {
        DoctorStatus::Warn
    };

    SecretBindingCheck {
        var_name: binding.var_name.clone(),
        description: binding.description.clone(),
        required: binding.required,
        status,
        source,
        detail,
    }
}

fn collect_infisical_scaffold_checks(
    infisical_dir: &Path,
    bindings: &[SecretBindingSpec],
) -> Vec<ScaffoldCheck> {
    let mut checks = Vec::new();

    if !infisical_dir.exists() {
        checks.push(ScaffoldCheck {
            name: "infisical_dir".to_owned(),
            status: DoctorStatus::Fail,
            detail: format!(
                "Infisical scaffold directory `{}` does not exist.",
                infisical_dir.display()
            ),
        });
        return checks;
    }

    let runtime_env_path = infisical_dir.join("runtime.env");
    let expected_secrets_path = infisical_dir.join("expected-secrets.env");
    let agent_path = infisical_dir.join("infisical-agent.yaml");
    let auth_readme_path = infisical_dir.join("auth/README.md");

    checks.push(check_path_exists(
        "infisical_agent",
        &agent_path,
        "Expected generated Infisical Agent config.",
    ));
    checks.push(check_path_exists(
        "runtime_env",
        &runtime_env_path,
        "Expected generated runtime.env file.",
    ));
    checks.push(check_path_exists(
        "expected_secrets_env",
        &expected_secrets_path,
        "Expected generated expected-secrets.env file.",
    ));
    checks.push(check_path_exists(
        "auth_readme",
        &auth_readme_path,
        "Expected generated auth/README.md file.",
    ));

    let runtime_assignments = if runtime_env_path.exists() {
        Some(parse_env_assignments(
            &std::fs::read_to_string(&runtime_env_path).unwrap_or_default(),
        ))
    } else {
        None
    };
    let expected_assignments = if expected_secrets_path.exists() {
        Some(parse_env_assignments(
            &std::fs::read_to_string(&expected_secrets_path).unwrap_or_default(),
        ))
    } else {
        None
    };

    for binding in bindings {
        let template_path = infisical_dir
            .join("templates")
            .join(format!("{}.tpl", binding.var_name));
        checks.push(check_path_exists(
            format!("template_{}", binding.var_name).as_str(),
            &template_path,
            &format!("Expected Infisical template for `{}`.", binding.var_name),
        ));

        if let Some(assignments) = runtime_assignments.as_ref() {
            let runtime_key = format!("{}_FILE", binding.var_name);
            let status = if assignments.contains_key(&runtime_key) {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            };
            checks.push(ScaffoldCheck {
                name: format!("runtime_env_{}", binding.var_name),
                status,
                detail: if status == DoctorStatus::Pass {
                    format!("`runtime.env` exports `{runtime_key}`.")
                } else {
                    format!("`runtime.env` is missing `{runtime_key}`.")
                },
            });
        }

        if let Some(assignments) = expected_assignments.as_ref() {
            let status = if assignments.contains_key(&binding.var_name) {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            };
            checks.push(ScaffoldCheck {
                name: format!("expected_secret_{}", binding.var_name),
                status,
                detail: if status == DoctorStatus::Pass {
                    format!("`expected-secrets.env` includes `{}`.", binding.var_name)
                } else {
                    format!("`expected-secrets.env` is missing `{}`.", binding.var_name)
                },
            });
        }
    }

    checks
}

fn check_path_exists(name: &str, path: &Path, description: &str) -> ScaffoldCheck {
    let exists = path.exists();
    ScaffoldCheck {
        name: name.to_owned(),
        status: if exists {
            DoctorStatus::Pass
        } else {
            DoctorStatus::Fail
        },
        detail: if exists {
            format!("{description} Found `{}`.", path.display())
        } else {
            format!("{description} Missing `{}`.", path.display())
        },
    }
}

fn parse_env_assignments(content: &str) -> BTreeMap<String, String> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let (key, value) = trimmed.split_once('=')?;
            let key = key.trim();
            if key.is_empty() {
                return None;
            }
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn render_doctor_report_text(report: &SecretsDoctorReport) -> String {
    let mut output = String::new();
    writeln!(&mut output, "Secrets doctor for {}", report.service_module).unwrap();
    writeln!(&mut output, "healthy: {}", report.healthy).unwrap();
    writeln!(&mut output).unwrap();
    writeln!(&mut output, "bindings:").unwrap();
    for binding in &report.bindings {
        writeln!(
            &mut output,
            "- {} [{}]: {}",
            binding.var_name,
            status_label(binding.status),
            binding.detail
        )
        .unwrap();
    }
    if !report.scaffold_checks.is_empty() {
        writeln!(&mut output).unwrap();
        writeln!(&mut output, "scaffold:").unwrap();
        for check in &report.scaffold_checks {
            writeln!(
                &mut output,
                "- {} [{}]: {}",
                check.name,
                status_label(check.status),
                check.detail
            )
            .unwrap();
        }
    }
    output
}

fn status_label(status: DoctorStatus) -> &'static str {
    match status {
        DoctorStatus::Pass => "pass",
        DoctorStatus::Warn => "warn",
        DoctorStatus::Fail => "fail",
    }
}

fn write_output(rendered: String, output: Option<&Path>, force: bool, label: &str) -> Result<()> {
    if let Some(path) = output {
        if path.exists() && !force {
            return Err(Error::Config(format!(
                "Refusing to overwrite existing {} at `{}`. Re-run with --force.",
                label,
                path.display()
            )));
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, rendered)?;
        println!("Wrote {label} to {}", path.display());
        Ok(())
    } else {
        print!("{rendered}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{InfisicalAuthMethod, OutputFormat, doctor_secrets, scaffold_infisical};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn temp_root(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir().join(format!("vsr_infisical_{prefix}_{stamp}"))
    }

    #[test]
    fn scaffold_infisical_writes_expected_auth_files() {
        let root = temp_root("auth");
        let report = scaffold_infisical(
            &fixture_path("auth_management_api.eon"),
            Some(&root),
            "demo-project",
            None,
            "prod",
            "/",
            "/run/secrets/vsr",
            InfisicalAuthMethod::UniversalAuth,
            false,
        )
        .expect("scaffold should write");

        let runtime_env = fs::read_to_string(root.join("runtime.env")).expect("runtime env");
        assert!(runtime_env.contains("DATABASE_URL_FILE=/run/secrets/vsr/DATABASE_URL"));
        assert!(runtime_env.contains("JWT_SECRET_FILE=/run/secrets/vsr/JWT_SECRET"));
        assert!(runtime_env.contains("RESEND_API_KEY_FILE=/run/secrets/vsr/RESEND_API_KEY"));

        let agent = fs::read_to_string(root.join("infisical-agent.yaml")).expect("agent config");
        assert!(agent.contains("type: \"universal-auth\""));
        assert!(agent.contains("source-path: \"./templates/JWT_SECRET.tpl\""));
        assert!(agent.contains("destination-path: \"/run/secrets/vsr/RESEND_API_KEY\""));

        let template = fs::read_to_string(root.join("templates/JWT_SECRET.tpl")).expect("template");
        assert!(template.contains("listSecretsByProjectSlug \"demo-project\" \"prod\" \"/\""));
        assert!(template.contains("if eq .Key \"JWT_SECRET\""));

        let expected =
            fs::read_to_string(root.join("expected-secrets.env")).expect("expected secrets env");
        assert!(expected.contains("DATABASE_URL=sqlite:var/data/auth_management_api.db?mode=rwc"));
        assert!(expected.contains("JWT_SECRET=change-me"));
        assert!(expected.contains("RESEND_API_KEY=change-me"));

        assert!(report.secret_bindings.contains(&"JWT_SECRET".to_owned()));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scaffold_infisical_includes_resilience_secret_bindings() {
        let root = temp_root("resilience");
        scaffold_infisical(
            &fixture_path("backup_resilience_api.eon"),
            Some(&root),
            "demo-project",
            None,
            "prod",
            "/ops",
            "/run/secrets/vsr",
            InfisicalAuthMethod::Azure,
            false,
        )
        .expect("scaffold should write");

        let runtime_env = fs::read_to_string(root.join("runtime.env")).expect("runtime env");
        assert!(
            runtime_env
                .contains("BACKUP_ENCRYPTION_KEY_FILE=/run/secrets/vsr/BACKUP_ENCRYPTION_KEY")
        );
        assert!(runtime_env.contains("DATABASE_READ_URL_FILE=/run/secrets/vsr/DATABASE_READ_URL"));

        let agent = fs::read_to_string(root.join("infisical-agent.yaml")).expect("agent config");
        assert!(agent.contains("type: \"azure\""));
        assert!(agent.contains("identity-id: \"./auth/identity-id\""));

        let template =
            fs::read_to_string(root.join("templates/DATABASE_READ_URL.tpl")).expect("template");
        assert!(template.contains("listSecretsByProjectSlug \"demo-project\" \"prod\" \"/ops\""));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn doctor_secrets_reports_runtime_resolution_and_scaffold_checks() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let root = temp_root("doctor");
        scaffold_infisical(
            &fixture_path("auth_management_api.eon"),
            Some(&root),
            "demo-project",
            None,
            "prod",
            "/",
            "/run/secrets/vsr",
            InfisicalAuthMethod::UniversalAuth,
            false,
        )
        .expect("scaffold should write");

        unsafe {
            std::env::set_var("JWT_SECRET", "unit-test-secret");
            std::env::set_var("RESEND_API_KEY", "unit-test-resend");
            std::env::set_var(
                "TURSO_ENCRYPTION_KEY",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            );
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("DATABASE_URL_FILE");
            std::env::remove_var("JWT_SECRET_FILE");
            std::env::remove_var("RESEND_API_KEY_FILE");
            std::env::remove_var("TURSO_ENCRYPTION_KEY_FILE");
        }

        let output_path = root.join("doctor.json");
        doctor_secrets(
            &fixture_path("auth_management_api.eon"),
            Some(&root),
            Some(&output_path),
            OutputFormat::Json,
            true,
        )
        .expect("doctor should succeed");

        let report = fs::read_to_string(&output_path).expect("doctor output should exist");
        assert!(report.contains("\"healthy\": true"));
        assert!(report.contains("\"var_name\": \"JWT_SECRET\""));
        assert!(report.contains("\"var_name\": \"DATABASE_URL\""));
        assert!(report.contains("\"name\": \"runtime_env_JWT_SECRET\""));

        unsafe {
            std::env::remove_var("JWT_SECRET");
            std::env::remove_var("RESEND_API_KEY");
            std::env::remove_var("TURSO_ENCRYPTION_KEY");
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scaffold_infisical_uses_project_id_templates_when_provided() {
        let root = temp_root("project_id");
        scaffold_infisical(
            &fixture_path("auth_management_api.eon"),
            Some(&root),
            "demo-project",
            Some("2435f6d5-14d0-4429-b1e6-172b497f2c17"),
            "prod",
            "/",
            "/run/secrets/vsr",
            InfisicalAuthMethod::UniversalAuth,
            false,
        )
        .expect("scaffold should write");

        let template = fs::read_to_string(root.join("templates/JWT_SECRET.tpl")).expect("template");
        assert!(template.contains(
            "getSecretByName \"2435f6d5-14d0-4429-b1e6-172b497f2c17\" \"prod\" \"/\" \"JWT_SECRET\""
        ));
        assert!(!template.contains("listSecretsByProjectSlug"));

        let readme = fs::read_to_string(root.join("README.md")).expect("readme");
        assert!(readme.contains("Project ID: `2435f6d5-14d0-4429-b1e6-172b497f2c17`"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn doctor_secrets_fails_when_required_secret_binding_is_missing() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let root = temp_root("doctor_missing");
        let output_path = root.join("doctor.txt");
        fs::create_dir_all(&root).expect("root should exist");

        unsafe {
            std::env::remove_var("JWT_SECRET");
            std::env::remove_var("JWT_SECRET_FILE");
            std::env::remove_var("RESEND_API_KEY");
            std::env::remove_var("RESEND_API_KEY_FILE");
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("DATABASE_URL_FILE");
        }

        doctor_secrets(
            &fixture_path("auth_management_api.eon"),
            None,
            Some(&output_path),
            OutputFormat::Text,
            true,
        )
        .expect("doctor should still write report");

        let report = fs::read_to_string(&output_path).expect("doctor output should exist");
        assert!(report.contains("JWT_SECRET [fail]"));
        assert!(report.contains("RESEND_API_KEY [fail]"));
        assert!(report.contains("DATABASE_URL [pass]"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scaffold_infisical_includes_structured_jwt_key_bindings() {
        let root = temp_root("jwt_structured");
        let config_path = root.join("jwt_api.eon");
        fs::create_dir_all(&root).expect("root should exist");
        fs::write(
            &config_path,
            r#"
            module: "jwt_api"
            security: {
                auth: {
                    jwt: {
                        algorithm: EdDSA
                        active_kid: "current"
                        signing_key: { env_or_file: "JWT_SIGNING_KEY" }
                        verification_keys: [
                            { kid: "current", key: { env_or_file: "JWT_VERIFYING_KEY" } }
                            { kid: "previous", key: { env_or_file: "JWT_VERIFYING_KEY_PREVIOUS" } }
                        ]
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64, id: true }]
                }
            ]
            "#,
        )
        .expect("config should write");

        scaffold_infisical(
            &config_path,
            Some(&root),
            "demo-project",
            None,
            "prod",
            "/",
            "/run/secrets/vsr",
            InfisicalAuthMethod::UniversalAuth,
            true,
        )
        .expect("scaffold should write");

        let runtime_env = fs::read_to_string(root.join("runtime.env")).expect("runtime env");
        assert!(runtime_env.contains("JWT_SIGNING_KEY_FILE=/run/secrets/vsr/JWT_SIGNING_KEY"));
        assert!(runtime_env.contains("JWT_VERIFYING_KEY_FILE=/run/secrets/vsr/JWT_VERIFYING_KEY"));
        assert!(runtime_env.contains(
            "JWT_VERIFYING_KEY_PREVIOUS_FILE=/run/secrets/vsr/JWT_VERIFYING_KEY_PREVIOUS"
        ));

        let expected =
            fs::read_to_string(root.join("expected-secrets.env")).expect("expected secrets env");
        assert!(expected.contains("JWT_SIGNING_KEY=-----BEGIN PRIVATE KEY-----..."));
        assert!(expected.contains("JWT_VERIFYING_KEY=-----BEGIN PUBLIC KEY-----..."));
        assert!(expected.contains("JWT_VERIFYING_KEY_PREVIOUS=-----BEGIN PUBLIC KEY-----..."));

        let template =
            fs::read_to_string(root.join("templates/JWT_SIGNING_KEY.tpl")).expect("template");
        assert!(template.contains("listSecretsByProjectSlug \"demo-project\" \"prod\" \"/\""));
        assert!(template.contains("JWT_SIGNING_KEY"));

        let _ = fs::remove_dir_all(root);
    }
}
