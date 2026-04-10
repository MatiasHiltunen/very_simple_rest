use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use colored::Colorize;
use rest_macro_core::compiler::{
    self, BuildArtifactPathConfig, ClientValueConfig, OpenApiSpecOptions,
};
use rest_macro_core::database::service_base_dir_from_config_path;
use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::commands::schema::load_schema_service;

const DEFAULT_OPENAPI_VERSION: &str = "1.0.0";
const DEFAULT_SERVER_URL: &str = "/api";

#[derive(Clone, Debug)]
pub struct TypescriptClientSelfTestOptions {
    pub report_path: Option<PathBuf>,
    pub runtime_base_url: Option<String>,
    pub node_binary: Option<PathBuf>,
    pub tsc_binary: Option<PathBuf>,
    pub insecure_tls: bool,
    pub force: bool,
}

pub fn generate_typescript_client(
    input: &Path,
    output: Option<&Path>,
    force: bool,
    exclude_tables: &[String],
    package_name: Option<&str>,
    server_url: Option<&str>,
    emit_js: Option<bool>,
    include_builtin_auth: Option<bool>,
) -> Result<PathBuf> {
    Ok(generate_typescript_client_artifacts(
        input,
        output,
        force,
        exclude_tables,
        package_name,
        server_url,
        emit_js,
        include_builtin_auth,
    )?
    .output_dir)
}

pub fn generate_typescript_client_with_self_test(
    input: &Path,
    output: Option<&Path>,
    force: bool,
    exclude_tables: &[String],
    package_name: Option<&str>,
    server_url: Option<&str>,
    emit_js: Option<bool>,
    include_builtin_auth: Option<bool>,
    self_test: Option<TypescriptClientSelfTestOptions>,
) -> Result<PathBuf> {
    let generated = generate_typescript_client_artifacts(
        input,
        output,
        force,
        exclude_tables,
        package_name,
        server_url,
        emit_js,
        include_builtin_auth,
    )?;

    if let Some(self_test) = self_test {
        let report = run_typescript_client_self_test(input, &generated, &self_test)?;
        let report_path = resolve_self_test_report_path(&generated.output_dir, &self_test)?;
        write_self_test_report(&report, &report_path, self_test.force)?;
        print_self_test_summary(&report, &report_path);
        if !report.passed {
            bail!(
                "generated TypeScript client self-test failed (see {})",
                report_path.display()
            );
        }
    }

    Ok(generated.output_dir)
}

pub fn generate_automated_typescript_client_for_build(input: &Path) -> Result<Option<PathBuf>> {
    let service = load_client_generation_service(input, &[])?;
    if !service.clients.ts.automation.on_build {
        return Ok(None);
    }

    println!(
        "{}",
        "Generating automated TypeScript client...".cyan().bold()
    );

    let self_test = if service.clients.ts.automation.self_test {
        Some(TypescriptClientSelfTestOptions {
            report_path: resolve_client_path_from_config(
                input,
                &service.clients.ts.automation.self_test_report,
            )?,
            runtime_base_url: None,
            node_binary: None,
            tsc_binary: None,
            insecure_tls: false,
            force: true,
        })
    } else {
        None
    };

    let output_dir = generate_typescript_client_with_self_test(
        input,
        None,
        true,
        &[],
        None,
        None,
        None,
        None,
        self_test,
    )?;

    Ok(Some(output_dir))
}

fn generate_typescript_client_artifacts(
    input: &Path,
    output: Option<&Path>,
    force: bool,
    exclude_tables: &[String],
    package_name: Option<&str>,
    server_url: Option<&str>,
    emit_js: Option<bool>,
    include_builtin_auth: Option<bool>,
) -> Result<GeneratedClientArtifacts> {
    let service = load_client_generation_service(input, exclude_tables)?;
    let output_dir = resolve_client_output_dir(input, &service, output)?;
    prepare_output_dir(&output_dir, force)?;
    let package_name = resolve_client_package_name(input, &service, package_name);
    let server_url = resolve_client_server_url(&service, server_url);
    let emit_js = resolve_client_emit_js(&service, emit_js);
    let include_builtin_auth = resolve_client_include_builtin_auth(&service, include_builtin_auth);

    let options = OpenApiSpecOptions::new(
        default_title(&service),
        DEFAULT_OPENAPI_VERSION.to_owned(),
        server_url,
    )
    .with_builtin_auth(include_builtin_auth);
    let document_json = compiler::render_service_openapi_json(&service, &options)
        .map_err(|error| anyhow!(error.to_string()))
        .context("failed to render OpenAPI JSON for client generation")?;
    let document: Value =
        serde_json::from_str(&document_json).context("generated OpenAPI JSON was invalid")?;
    let ir = ClientDocument::from_openapi(&document)?;

    write_generated_client(&output_dir, &package_name, &ir, emit_js)?;

    println!(
        "{} {}",
        "Generated TypeScript client:".green().bold(),
        output_dir.display()
    );

    Ok(GeneratedClientArtifacts {
        output_dir,
        package_name,
        document: ir,
    })
}

fn resolve_client_output_dir(
    input: &Path,
    service: &compiler::ServiceSpec,
    output: Option<&Path>,
) -> Result<PathBuf> {
    match output {
        Some(path) if path.is_absolute() => Ok(path.to_path_buf()),
        Some(path) => Ok(std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join(path)),
        None => match resolve_client_path_from_config(input, &service.clients.ts.output_dir)? {
            Some(path) => Ok(path),
            None => Ok(
                service_base_dir_from_config_path(&absolute_path(input)?).join(format!(
                    "{}.client",
                    input
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .filter(|value| !value.is_empty())
                        .unwrap_or("service")
                )),
            ),
        },
    }
}

pub(crate) fn resolve_configured_client_output_dir(
    input: &Path,
    service: &compiler::ServiceSpec,
) -> Result<PathBuf> {
    resolve_client_output_dir(input, service, None)
}

fn load_client_generation_service(
    input: &Path,
    cli_exclude_tables: &[String],
) -> Result<compiler::ServiceSpec> {
    let mut service = load_schema_service(input, &[])?;
    let exclude_tables = merged_client_exclude_tables(&service, cli_exclude_tables);
    apply_client_table_exclusions(&mut service, &exclude_tables, input)?;
    Ok(service)
}

fn merged_client_exclude_tables(
    service: &compiler::ServiceSpec,
    cli_exclude_tables: &[String],
) -> Vec<String> {
    let mut merged = BTreeSet::new();
    for table in &service.clients.ts.exclude_tables {
        let trimmed = table.trim();
        if !trimmed.is_empty() {
            merged.insert(trimmed.to_owned());
        }
    }
    for table in cli_exclude_tables {
        let trimmed = table.trim();
        if !trimmed.is_empty() {
            merged.insert(trimmed.to_owned());
        }
    }
    merged.into_iter().collect()
}

fn apply_client_table_exclusions(
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
            "no resources remain after client exclusions for {}",
            input.display()
        );
    }

    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join(path))
    }
}

fn prepare_output_dir(path: &Path, force: bool) -> Result<()> {
    if path.exists() {
        if !force {
            bail!(
                "client output already exists at {} (use --force to overwrite)",
                path.display()
            );
        }
        if path.is_dir() {
            fs::remove_dir_all(path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        } else {
            fs::remove_file(path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
    }

    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
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

fn default_package_name(input: &Path) -> String {
    let stem = input
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("service");
    format!("{stem}-client")
}

fn resolve_client_package_name(
    input: &Path,
    service: &compiler::ServiceSpec,
    package_name: Option<&str>,
) -> String {
    if let Some(package_name) = package_name {
        return package_name.to_owned();
    }
    if let Some(package_name) = resolve_client_value_from_config(&service.clients.ts.package_name) {
        return package_name;
    }
    default_package_name(input)
}

fn resolve_client_server_url(service: &compiler::ServiceSpec, server_url: Option<&str>) -> String {
    server_url
        .map(str::to_owned)
        .or_else(|| service.clients.ts.server_url.clone())
        .unwrap_or_else(|| DEFAULT_SERVER_URL.to_owned())
}

fn resolve_client_emit_js(service: &compiler::ServiceSpec, emit_js: Option<bool>) -> bool {
    emit_js.unwrap_or(service.clients.ts.emit_js)
}

fn resolve_client_include_builtin_auth(
    service: &compiler::ServiceSpec,
    include_builtin_auth: Option<bool>,
) -> bool {
    include_builtin_auth.unwrap_or(service.clients.ts.include_builtin_auth)
}

fn resolve_client_path_from_config(
    input: &Path,
    config: &BuildArtifactPathConfig,
) -> Result<Option<PathBuf>> {
    if let Some(env_name) = config.env.as_deref() {
        if let Ok(value) = std::env::var(env_name) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Ok(Some(resolve_config_relative_path(
                    input,
                    Path::new(trimmed),
                )?));
            }
        }
    }

    config
        .path
        .as_deref()
        .map(|path| resolve_config_relative_path(input, Path::new(path)))
        .transpose()
}

pub(crate) fn resolve_configured_client_self_test_report_path(
    input: &Path,
    service: &compiler::ServiceSpec,
    output_dir: &Path,
) -> Result<Option<PathBuf>> {
    if !service.clients.ts.automation.self_test {
        return Ok(None);
    }

    match resolve_client_path_from_config(input, &service.clients.ts.automation.self_test_report)? {
        Some(path) => Ok(Some(path)),
        None => Ok(Some(output_dir.join("self-test-report.json"))),
    }
}

fn resolve_client_value_from_config(config: &ClientValueConfig) -> Option<String> {
    if let Some(env_name) = config.env.as_deref() {
        if let Ok(value) = std::env::var(env_name) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
    }

    config
        .value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn resolve_config_relative_path(input: &Path, path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(service_base_dir_from_config_path(&absolute_path(input)?).join(path))
    }
}

fn write_generated_client(
    output_dir: &Path,
    package_name: &str,
    document: &ClientDocument,
    emit_js: bool,
) -> Result<()> {
    let input_schema_aliases = compute_input_schema_aliases(&document.schemas);

    write_file(
        &output_dir.join("package.json"),
        &render_package_json(package_name, emit_js),
    )?;
    write_file(&output_dir.join("tsconfig.json"), &render_tsconfig_json())?;
    write_file(&output_dir.join("index.ts"), &render_index_ts())?;
    write_file(
        &output_dir.join("client.ts"),
        &render_client_ts(&document.server_url),
    )?;
    write_file(
        &output_dir.join("types.ts"),
        &render_types_ts(&document.schemas, &input_schema_aliases),
    )?;
    write_file(
        &output_dir.join("operations.ts"),
        &render_operations_ts(document, &input_schema_aliases),
    )?;
    if emit_js {
        write_file(&output_dir.join("index.js"), &render_index_js())?;
        write_file(
            &output_dir.join("client.js"),
            &render_client_js(&document.server_url),
        )?;
        write_file(
            &output_dir.join("operations.js"),
            &render_operations_js(document),
        )?;
    }
    Ok(())
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))
}

#[derive(Clone, Debug)]
struct GeneratedClientArtifacts {
    output_dir: PathBuf,
    package_name: String,
    document: ClientDocument,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ClientSelfTestStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ClientSelfTestKind {
    Static,
    Runtime,
}

#[derive(Clone, Debug, Serialize)]
struct ClientSelfTestCheck {
    name: String,
    kind: ClientSelfTestKind,
    status: ClientSelfTestStatus,
    details: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
struct ClientSelfTestSummary {
    passed: usize,
    failed: usize,
    skipped: usize,
}

#[derive(Clone, Debug, Serialize)]
struct ClientSelfTestReport {
    generated_at: String,
    schema_input: String,
    client_dir: String,
    package_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_base_url: Option<String>,
    passed: bool,
    summary: ClientSelfTestSummary,
    checks: Vec<ClientSelfTestCheck>,
}

#[derive(Clone, Debug)]
struct ClientDocument {
    server_url: String,
    schemas: BTreeMap<String, Value>,
    operations: Vec<ClientOperation>,
}

impl ClientDocument {
    fn from_openapi(document: &Value) -> Result<Self> {
        let server_url = document
            .get("servers")
            .and_then(Value::as_array)
            .and_then(|servers| servers.first())
            .and_then(|server| server.get("url"))
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_SERVER_URL)
            .to_owned();

        let schemas = document
            .get("components")
            .and_then(|components| components.get("schemas"))
            .and_then(Value::as_object)
            .map(|schemas| {
                schemas
                    .iter()
                    .map(|(name, schema)| (name.clone(), schema.clone()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();

        let paths = document
            .get("paths")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("generated OpenAPI document is missing `paths`"))?;

        let mut operations = Vec::new();
        for (path, path_item) in paths {
            let Some(path_item) = path_item.as_object() else {
                continue;
            };
            for method in ["get", "post", "put", "patch", "delete"] {
                let Some(operation) = path_item.get(method).and_then(Value::as_object) else {
                    continue;
                };
                operations.push(ClientOperation::from_openapi(method, path, operation)?);
            }
        }

        Ok(Self {
            server_url,
            schemas,
            operations,
        })
    }
}

#[derive(Clone, Debug)]
struct ClientOperation {
    operation_id: String,
    method: String,
    path: String,
    path_params: Vec<ClientParameter>,
    query_params: Vec<ClientParameter>,
    header_params: Vec<ClientParameter>,
    request_body: Option<ClientRequestBody>,
    response: ClientResponse,
    requires_bearer_auth: bool,
}

impl ClientOperation {
    fn from_openapi(method: &str, path: &str, operation: &Map<String, Value>) -> Result<Self> {
        let operation_id = operation
            .get("operationId")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| fallback_operation_id(method, path));

        let mut path_params = Vec::new();
        let mut query_params = Vec::new();
        let mut header_params = Vec::new();
        if let Some(parameters) = operation.get("parameters").and_then(Value::as_array) {
            for parameter in parameters {
                let Some(parameter) = parameter.as_object() else {
                    continue;
                };
                let client_parameter = ClientParameter::from_openapi(parameter)?;
                match client_parameter.location {
                    ParameterLocation::Path => path_params.push(client_parameter),
                    ParameterLocation::Query => query_params.push(client_parameter),
                    ParameterLocation::Header => header_params.push(client_parameter),
                }
            }
        }

        let request_body = match operation.get("requestBody") {
            Some(request_body) => ClientRequestBody::from_openapi(request_body)?,
            None => None,
        };
        let response = ClientResponse::from_openapi(operation.get("responses"))?;
        let requires_bearer_auth = operation
            .get("security")
            .and_then(Value::as_array)
            .map(|entries| {
                entries.iter().any(|entry| {
                    entry
                        .as_object()
                        .map(|object| object.contains_key("bearerAuth"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);

        Ok(Self {
            operation_id,
            method: method.to_ascii_uppercase(),
            path: path.to_owned(),
            path_params,
            query_params,
            header_params,
            request_body,
            response,
            requires_bearer_auth,
        })
    }
}

fn fallback_operation_id(method: &str, path: &str) -> String {
    let mut value = format!("{method}_{}", path.trim_matches('/').replace('/', "_"));
    value = value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    sanitize_identifier(&value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParameterLocation {
    Path,
    Query,
    Header,
}

#[derive(Clone, Debug)]
struct ClientParameter {
    name: String,
    schema: Value,
    required: bool,
    location: ParameterLocation,
}

impl ClientParameter {
    fn from_openapi(parameter: &Map<String, Value>) -> Result<Self> {
        let location = match parameter.get("in").and_then(Value::as_str) {
            Some("path") => ParameterLocation::Path,
            Some("query") => ParameterLocation::Query,
            Some("header") => ParameterLocation::Header,
            Some(other) => bail!("unsupported OpenAPI parameter location `{other}`"),
            None => bail!("OpenAPI parameter is missing `in`"),
        };
        Ok(Self {
            name: parameter
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("OpenAPI parameter is missing `name`"))?
                .to_owned(),
            schema: parameter
                .get("schema")
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new())),
            required: parameter
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            location,
        })
    }
}

#[derive(Clone, Debug)]
struct ClientRequestBody {
    content_type: RequestContentType,
    schema: Value,
}

impl ClientRequestBody {
    fn from_openapi(value: &Value) -> Result<Option<Self>> {
        let Some(body) = value.as_object() else {
            return Ok(None);
        };
        let Some(content) = body.get("content").and_then(Value::as_object) else {
            return Ok(None);
        };
        let Some((content_type, schema)) = preferred_content_schema(content) else {
            return Ok(None);
        };
        Ok(Some(Self {
            content_type: RequestContentType::from_content_type(content_type),
            schema,
        }))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestContentType {
    Json,
    Multipart,
    Text,
    Binary,
}

impl RequestContentType {
    fn from_content_type(value: &str) -> Self {
        match value {
            "application/json" => Self::Json,
            "multipart/form-data" => Self::Multipart,
            "text/plain" => Self::Text,
            _ => Self::Binary,
        }
    }

    fn as_http_header(self) -> Option<&'static str> {
        match self {
            Self::Json => Some("application/json"),
            Self::Text => Some("text/plain"),
            Self::Multipart => None,
            Self::Binary => Some("application/octet-stream"),
        }
    }
}

fn preferred_content_schema(content: &Map<String, Value>) -> Option<(&str, Value)> {
    for preferred in [
        "application/json",
        "multipart/form-data",
        "text/plain",
        "application/octet-stream",
    ] {
        if let Some(schema) = content
            .get(preferred)
            .and_then(Value::as_object)
            .and_then(|value| value.get("schema"))
            .cloned()
        {
            return Some((preferred, schema));
        }
    }

    content.iter().find_map(|(content_type, value)| {
        value
            .as_object()
            .and_then(|value| value.get("schema"))
            .cloned()
            .map(|schema| (content_type.as_str(), schema))
    })
}

#[derive(Clone, Debug)]
struct ClientResponse {
    kind: ResponseKind,
}

impl ClientResponse {
    fn from_openapi(value: Option<&Value>) -> Result<Self> {
        let Some(responses) = value.and_then(Value::as_object) else {
            return Ok(Self {
                kind: ResponseKind::Void,
            });
        };
        let mut success_codes = responses
            .iter()
            .filter_map(|(status, response)| {
                status
                    .parse::<u16>()
                    .ok()
                    .filter(|status| (200..300).contains(status))
                    .map(|status| (status, response))
            })
            .collect::<Vec<_>>();
        success_codes.sort_by_key(|(status, _)| *status);

        let Some((_, response)) = success_codes.into_iter().next() else {
            return Ok(Self {
                kind: ResponseKind::Void,
            });
        };
        let Some(response) = response.as_object() else {
            return Ok(Self {
                kind: ResponseKind::Void,
            });
        };
        let Some(content) = response.get("content").and_then(Value::as_object) else {
            return Ok(Self {
                kind: ResponseKind::Void,
            });
        };

        if let Some(schema) = content
            .get("application/json")
            .and_then(Value::as_object)
            .and_then(|value| value.get("schema"))
            .cloned()
        {
            return Ok(Self {
                kind: ResponseKind::Json(schema),
            });
        }

        if content.contains_key("text/plain") || content.contains_key("text/html") {
            return Ok(Self {
                kind: ResponseKind::Text,
            });
        }

        Ok(Self {
            kind: ResponseKind::Binary,
        })
    }
}

#[derive(Clone, Debug)]
enum ResponseKind {
    Json(Value),
    Text,
    Binary,
    Void,
}

fn render_package_json(package_name: &str, emit_js: bool) -> String {
    if emit_js {
        return format!(
            "{{\n  \"name\": \"{package_name}\",\n  \"private\": true,\n  \"type\": \"module\",\n  \"sideEffects\": false,\n  \"exports\": {{\n    \".\": {{\n      \"types\": \"./index.ts\",\n      \"default\": \"./index.js\"\n    }}\n  }}\n}}\n"
        );
    }

    format!(
        "{{\n  \"name\": \"{package_name}\",\n  \"private\": true,\n  \"type\": \"module\",\n  \"sideEffects\": false,\n  \"exports\": {{\n    \".\": \"./index.ts\"\n  }}\n}}\n"
    )
}

fn render_tsconfig_json() -> String {
    r#"{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["DOM", "ES2022"],
    "strict": true,
    "noEmit": true,
    "allowImportingTsExtensions": true,
    "skipLibCheck": true
  },
  "include": ["./*.ts"]
}
"#
    .to_owned()
}

fn render_index_ts() -> String {
    [
        "export * from \"./client.ts\";",
        "export * from \"./types.ts\";",
        "export * from \"./operations.ts\";",
        "",
    ]
    .join("\n")
}

fn render_index_js() -> String {
    [
        "export * from \"./client.js\";",
        "export * from \"./operations.js\";",
        "",
    ]
    .join("\n")
}

fn render_client_ts(server_url: &str) -> String {
    format!(
        r#"export type DateTimeInput = string | Date;
export type DateInput = string | VsrDate;
export type TimeInput = string | VsrTime;

type TemporalValue = Date | VsrDate | VsrTime;
type ScalarValue = string | number | boolean | TemporalValue;

export type QueryValue =
  | ScalarValue
  | null
  | undefined
  | Blob
  | Array<ScalarValue | null | undefined>;

export type QueryParams = Record<string, QueryValue>;

export type RequestConfig = {{
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  query?: QueryParams;
  body?: unknown;
  contentType?: string;
  headers?: HeadersInit;
  signal?: AbortSignal;
  requiresBearerAuth?: boolean;
}};

export type ClientConfig = {{
  baseUrl?: string;
  serverUrl?: string;
  fetch?: typeof fetch;
  defaultHeaders?: HeadersInit;
  credentials?: RequestCredentials;
  getAccessToken?: () => string | null | undefined | Promise<string | null | undefined>;
  getCsrfToken?: () => string | null | undefined | Promise<string | null | undefined>;
  csrfHeaderName?: string;
}};

export type ResolvedClientConfig = {{
  baseUrl: string;
  serverUrl: string;
  fetch: typeof fetch;
  defaultHeaders?: HeadersInit;
  credentials: RequestCredentials;
  getAccessToken?: () => string | null | undefined | Promise<string | null | undefined>;
  getCsrfToken?: () => string | null | undefined | Promise<string | null | undefined>;
  csrfHeaderName: string;
}};

export class VsrDate {{
  readonly year: number;
  readonly month: number;
  readonly day: number;

  constructor(year: number, month: number, day: number) {{
    if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) {{
      throw new Error("VsrDate values must be integers.");
    }}
    const normalized = new Date(Date.UTC(year, month - 1, day));
    if (
      normalized.getUTCFullYear() !== year ||
      normalized.getUTCMonth() !== month - 1 ||
      normalized.getUTCDate() !== day
    ) {{
      throw new Error("Invalid VsrDate value.");
    }}
    this.year = year;
    this.month = month;
    this.day = day;
  }}

  toString(): string {{
    return `${{padNumber(this.year, 4)}}-${{padNumber(this.month, 2)}}-${{padNumber(this.day, 2)}}`;
  }}

  toJSON(): string {{
    return this.toString();
  }}
}}

export class VsrTime {{
  readonly hour: number;
  readonly minute: number;
  readonly second: number;
  readonly microsecond: number;

  constructor(hour: number, minute: number, second: number = 0, microsecond: number = 0) {{
    if (
      !Number.isInteger(hour) ||
      !Number.isInteger(minute) ||
      !Number.isInteger(second) ||
      !Number.isInteger(microsecond)
    ) {{
      throw new Error("VsrTime values must be integers.");
    }}
    if (hour < 0 || hour > 23) {{
      throw new Error("VsrTime hour must be between 0 and 23.");
    }}
    if (minute < 0 || minute > 59) {{
      throw new Error("VsrTime minute must be between 0 and 59.");
    }}
    if (second < 0 || second > 59) {{
      throw new Error("VsrTime second must be between 0 and 59.");
    }}
    if (microsecond < 0 || microsecond > 999999) {{
      throw new Error("VsrTime microsecond must be between 0 and 999999.");
    }}
    this.hour = hour;
    this.minute = minute;
    this.second = second;
    this.microsecond = microsecond;
  }}

  toString(): string {{
    return `${{padNumber(this.hour, 2)}}:${{padNumber(this.minute, 2)}}:${{padNumber(this.second, 2)}}.${{padNumber(this.microsecond, 6)}}`;
  }}

  toJSON(): string {{
    return this.toString();
  }}
}}

export class ApiError extends Error {{
  readonly status: number;
  readonly body: unknown;
  readonly headers: Headers;

  constructor(message: string, status: number, body: unknown, headers: Headers) {{
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.headers = headers;
  }}
}}

export interface VsrClient {{
  readonly config: ResolvedClientConfig;
  request<TResponse>(request: RequestConfig): Promise<TResponse>;
}}

const DEFAULT_SERVER_URL = {server_url:?};

function requestNeedsCsrf(method: string): boolean {{
  const normalized = method.toUpperCase();
  return normalized === "POST" || normalized === "PUT" || normalized === "PATCH" || normalized === "DELETE";
}}

export function createClient(config: ClientConfig = {{}}): VsrClient {{
  const resolvedConfig: ResolvedClientConfig = {{
    baseUrl: config.baseUrl ?? "",
    serverUrl: config.serverUrl ?? DEFAULT_SERVER_URL,
    fetch: bindFetch(config.fetch ?? globalThis.fetch),
    defaultHeaders: config.defaultHeaders,
    credentials: config.credentials ?? "include",
    getAccessToken: config.getAccessToken,
    getCsrfToken: config.getCsrfToken,
    csrfHeaderName: config.csrfHeaderName ?? "x-csrf-token",
  }};

  return {{
    config: resolvedConfig,
    async request<TResponse>(request: RequestConfig): Promise<TResponse> {{
      const headers = new Headers(resolvedConfig.defaultHeaders ?? undefined);
      if (request.headers) {{
        new Headers(request.headers).forEach((value, key) => headers.set(key, value));
      }}

      if (request.requiresBearerAuth && resolvedConfig.getAccessToken) {{
        const token = await resolvedConfig.getAccessToken();
        if (token) {{
          headers.set("authorization", `Bearer ${{token}}`);
        }}
      }}

      let body: BodyInit | undefined;
      if (request.body !== undefined) {{
        if (request.contentType === "multipart/form-data") {{
          body = request.body instanceof FormData ? request.body : objectToFormData(request.body);
        }} else if (request.contentType === "application/json") {{
          headers.set("content-type", "application/json");
          body = JSON.stringify(normalizeJsonValue(request.body));
        }} else if (request.contentType === "text/plain") {{
          headers.set("content-type", "text/plain");
          body = stringifyScalarLikeValue(request.body);
        }} else {{
          if (request.contentType) {{
            headers.set("content-type", request.contentType);
          }}
          body = request.body as BodyInit;
        }}
      }}

      if (requestNeedsCsrf(request.method) && resolvedConfig.getCsrfToken) {{
        const csrfToken = await resolvedConfig.getCsrfToken();
        if (csrfToken) {{
          headers.set(resolvedConfig.csrfHeaderName, csrfToken);
        }}
      }}

      const response = await resolvedConfig.fetch(buildUrl(resolvedConfig, request.path, request.query), {{
        method: request.method,
        headers,
        body,
        signal: request.signal,
        credentials: resolvedConfig.credentials,
      }});

      const parsedBody = await parseResponseBody(response);
      if (!response.ok) {{
        const message =
          typeof parsedBody === "object" &&
          parsedBody !== null &&
          "message" in parsedBody &&
          typeof (parsedBody as {{ message?: unknown }}).message === "string"
            ? ((parsedBody as {{ message: string }}).message)
            : `${{response.status}} ${{response.statusText}}`;
        throw new ApiError(message, response.status, parsedBody, response.headers);
      }}

      return parsedBody as TResponse;
    }},
  }};
}}

function bindFetch(fetchImpl: typeof fetch | undefined): typeof fetch {{
  if (typeof fetchImpl !== "function") {{
    throw new Error("No fetch implementation is available for the generated client.");
  }}
  return fetchImpl.bind(globalThis);
}}

function buildUrl(config: ResolvedClientConfig, path: string, query?: QueryParams): string {{
  const base = `${{trimTrailingSlash(config.baseUrl)}}${{ensureLeadingSlash(config.serverUrl)}}${{ensureLeadingSlash(path)}}`;
  const url = new URL(base, base.startsWith("http://") || base.startsWith("https://") ? undefined : "http://localhost");
  if (query) {{
    appendQuery(url.searchParams, query);
  }}

  if (!config.baseUrl) {{
    return `${{url.pathname}}${{url.search}}${{url.hash}}`;
  }}

  return url.toString();
}}

function trimTrailingSlash(value: string): string {{
  return value.endsWith("/") ? value.slice(0, -1) : value;
}}

function ensureLeadingSlash(value: string): string {{
  if (!value) {{
    return "";
  }}
  return value.startsWith("/") ? value : `/${{value}}`;
}}

export function interpolatePath(
  template: string,
  params?: Record<string, ScalarValue | null | undefined>,
): string {{
  return template.replace(/\{{([^}}]+)\}}/g, (_, key: string) => {{
    const value = params?.[key];
    if (value === undefined || value === null) {{
      throw new Error(`Missing required path parameter: ${{key}}`);
    }}
    return encodeURIComponent(stringifyScalarValue(value));
  }});
}}

function appendQuery(searchParams: URLSearchParams, query: QueryParams): void {{
  for (const [key, value] of Object.entries(query)) {{
    if (value === undefined || value === null) {{
      continue;
    }}
    if (Array.isArray(value)) {{
      for (const item of value) {{
        if (item !== undefined && item !== null) {{
          searchParams.append(key, stringifyScalarValue(item));
        }}
      }}
      continue;
    }}
    if (value instanceof Blob) {{
      continue;
    }}
    searchParams.append(key, stringifyScalarValue(value));
  }}
}}

function stringifyScalarValue(value: ScalarValue): string {{
  if (typeof value === "string") {{
    return value;
  }}
  if (typeof value === "number" || typeof value === "boolean") {{
    return String(value);
  }}
  return stringifyTemporalValue(value);
}}

function stringifyScalarLikeValue(value: unknown): string {{
  if (typeof value === "string") {{
    return value;
  }}
  if (typeof value === "number" || typeof value === "boolean") {{
    return String(value);
  }}
  if (isTemporalValue(value)) {{
    return stringifyTemporalValue(value);
  }}
  return String(value);
}}

function objectToFormData(value: unknown): FormData {{
  if (value instanceof FormData) {{
    return value;
  }}
  const formData = new FormData();
  if (!value || typeof value !== "object") {{
    return formData;
  }}
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {{
    appendFormDataValue(formData, key, entry);
  }}
  return formData;
}}

function appendFormDataValue(formData: FormData, key: string, value: unknown): void {{
  if (value === undefined || value === null) {{
    return;
  }}
  if (Array.isArray(value)) {{
    for (const item of value) {{
      appendFormDataValue(formData, key, item);
    }}
    return;
  }}
  if (value instanceof Blob) {{
    formData.append(key, value);
    return;
  }}
  if (isTemporalValue(value)) {{
    formData.append(key, stringifyTemporalValue(value));
    return;
  }}
  if (typeof value === "string") {{
    formData.append(key, value);
    return;
  }}
  if (typeof value === "number" || typeof value === "boolean") {{
    formData.append(key, String(value));
    return;
  }}
  formData.append(key, JSON.stringify(value));
}}

async function parseResponseBody(response: Response): Promise<unknown> {{
  if (response.status === 204 || response.status === 205) {{
    return undefined;
  }}

  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {{
    const text = await response.text();
    return text ? JSON.parse(text) : undefined;
  }}
  if (contentType.startsWith("text/")) {{
    return response.text();
  }}
  const text = await response.text();
  return text ? text : undefined;
}}

function normalizeJsonValue(value: unknown): unknown {{
  if (value === undefined || value === null) {{
    return value;
  }}
  if (isTemporalValue(value)) {{
    return stringifyTemporalValue(value);
  }}
  if (Array.isArray(value)) {{
    return value.map((entry) => normalizeJsonValue(entry));
  }}
  if (value instanceof Blob || value instanceof FormData || value instanceof URLSearchParams) {{
    return value;
  }}
  if (typeof value === "object") {{
    const normalized: Record<string, unknown> = {{}};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {{
      normalized[key] = normalizeJsonValue(entry);
    }}
    return normalized;
  }}
  return value;
}}

function isTemporalValue(value: unknown): value is TemporalValue {{
  return value instanceof Date || value instanceof VsrDate || value instanceof VsrTime;
}}

function stringifyTemporalValue(value: TemporalValue): string {{
  if (value instanceof Date) {{
    if (Number.isNaN(value.getTime())) {{
      throw new Error("Invalid DateTimeInput value.");
    }}
    return `${{padNumber(value.getUTCFullYear(), 4)}}-${{padNumber(value.getUTCMonth() + 1, 2)}}-${{padNumber(value.getUTCDate(), 2)}}T${{padNumber(value.getUTCHours(), 2)}}:${{padNumber(value.getUTCMinutes(), 2)}}:${{padNumber(value.getUTCSeconds(), 2)}}.${{padNumber(value.getUTCMilliseconds() * 1000, 6)}}+00:00`;
  }}
  return value.toString();
}}

function padNumber(value: number, width: number): string {{
  return String(value).padStart(width, "0");
}}
"#
    )
}

fn render_client_js(server_url: &str) -> String {
    format!(
        r#"export class VsrDate {{
  constructor(year, month, day) {{
    if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) {{
      throw new Error("VsrDate values must be integers.");
    }}
    const normalized = new Date(Date.UTC(year, month - 1, day));
    if (
      normalized.getUTCFullYear() !== year ||
      normalized.getUTCMonth() !== month - 1 ||
      normalized.getUTCDate() !== day
    ) {{
      throw new Error("Invalid VsrDate value.");
    }}
    this.year = year;
    this.month = month;
    this.day = day;
  }}

  toString() {{
    return `${{padNumber(this.year, 4)}}-${{padNumber(this.month, 2)}}-${{padNumber(this.day, 2)}}`;
  }}

  toJSON() {{
    return this.toString();
  }}
}}

export class VsrTime {{
  constructor(hour, minute, second = 0, microsecond = 0) {{
    if (
      !Number.isInteger(hour) ||
      !Number.isInteger(minute) ||
      !Number.isInteger(second) ||
      !Number.isInteger(microsecond)
    ) {{
      throw new Error("VsrTime values must be integers.");
    }}
    if (hour < 0 || hour > 23) {{
      throw new Error("VsrTime hour must be between 0 and 23.");
    }}
    if (minute < 0 || minute > 59) {{
      throw new Error("VsrTime minute must be between 0 and 59.");
    }}
    if (second < 0 || second > 59) {{
      throw new Error("VsrTime second must be between 0 and 59.");
    }}
    if (microsecond < 0 || microsecond > 999999) {{
      throw new Error("VsrTime microsecond must be between 0 and 999999.");
    }}
    this.hour = hour;
    this.minute = minute;
    this.second = second;
    this.microsecond = microsecond;
  }}

  toString() {{
    return `${{padNumber(this.hour, 2)}}:${{padNumber(this.minute, 2)}}:${{padNumber(this.second, 2)}}.${{padNumber(this.microsecond, 6)}}`;
  }}

  toJSON() {{
    return this.toString();
  }}
}}

export class ApiError extends Error {{
  constructor(message, status, body, headers) {{
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.headers = headers;
  }}
}}

const DEFAULT_SERVER_URL = {server_url:?};

function requestNeedsCsrf(method) {{
  const normalized = method.toUpperCase();
  return normalized === "POST" || normalized === "PUT" || normalized === "PATCH" || normalized === "DELETE";
}}

export function createClient(config = {{}}) {{
  const resolvedConfig = {{
    baseUrl: config.baseUrl ?? "",
    serverUrl: config.serverUrl ?? DEFAULT_SERVER_URL,
    fetch: bindFetch(config.fetch ?? globalThis.fetch),
    defaultHeaders: config.defaultHeaders,
    credentials: config.credentials ?? "include",
    getAccessToken: config.getAccessToken,
    getCsrfToken: config.getCsrfToken,
    csrfHeaderName: config.csrfHeaderName ?? "x-csrf-token",
  }};

  return {{
    config: resolvedConfig,
    async request(request) {{
      const headers = new Headers(resolvedConfig.defaultHeaders ?? undefined);
      if (request.headers) {{
        new Headers(request.headers).forEach((value, key) => headers.set(key, value));
      }}

      if (request.requiresBearerAuth && resolvedConfig.getAccessToken) {{
        const token = await resolvedConfig.getAccessToken();
        if (token) {{
          headers.set("authorization", `Bearer ${{token}}`);
        }}
      }}

      let body;
      if (request.body !== undefined) {{
        if (request.contentType === "multipart/form-data") {{
          body = request.body instanceof FormData ? request.body : objectToFormData(request.body);
        }} else if (request.contentType === "application/json") {{
          headers.set("content-type", "application/json");
          body = JSON.stringify(normalizeJsonValue(request.body));
        }} else if (request.contentType === "text/plain") {{
          headers.set("content-type", "text/plain");
          body = stringifyScalarLikeValue(request.body);
        }} else {{
          if (request.contentType) {{
            headers.set("content-type", request.contentType);
          }}
          body = request.body;
        }}
      }}

      if (requestNeedsCsrf(request.method) && resolvedConfig.getCsrfToken) {{
        const csrfToken = await resolvedConfig.getCsrfToken();
        if (csrfToken) {{
          headers.set(resolvedConfig.csrfHeaderName, csrfToken);
        }}
      }}

      const response = await resolvedConfig.fetch(buildUrl(resolvedConfig, request.path, request.query), {{
        method: request.method,
        headers,
        body,
        signal: request.signal,
        credentials: resolvedConfig.credentials,
      }});

      const parsedBody = await parseResponseBody(response);
      if (!response.ok) {{
        const message =
          typeof parsedBody === "object" &&
          parsedBody !== null &&
          "message" in parsedBody &&
          typeof parsedBody.message === "string"
            ? parsedBody.message
            : `${{response.status}} ${{response.statusText}}`;
        throw new ApiError(message, response.status, parsedBody, response.headers);
      }}

      return parsedBody;
    }},
  }};
}}

function bindFetch(fetchImpl) {{
  if (typeof fetchImpl !== "function") {{
    throw new Error("No fetch implementation is available for the generated client.");
  }}
  return fetchImpl.bind(globalThis);
}}

function buildUrl(config, path, query) {{
  const base = `${{trimTrailingSlash(config.baseUrl)}}${{ensureLeadingSlash(config.serverUrl)}}${{ensureLeadingSlash(path)}}`;
  const url = new URL(base, base.startsWith("http://") || base.startsWith("https://") ? undefined : "http://localhost");
  if (query) {{
    appendQuery(url.searchParams, query);
  }}

  if (!config.baseUrl) {{
    return `${{url.pathname}}${{url.search}}${{url.hash}}`;
  }}

  return url.toString();
}}

function trimTrailingSlash(value) {{
  return value.endsWith("/") ? value.slice(0, -1) : value;
}}

function ensureLeadingSlash(value) {{
  if (!value) {{
    return "";
  }}
  return value.startsWith("/") ? value : `/${{value}}`;
}}

export function interpolatePath(template, params) {{
  return template.replace(/\{{([^}}]+)\}}/g, (_, key) => {{
    const value = params?.[key];
    if (value === undefined || value === null) {{
      throw new Error(`Missing required path parameter: ${{key}}`);
    }}
    return encodeURIComponent(stringifyScalarValue(value));
  }});
}}

function appendQuery(searchParams, query) {{
  for (const [key, value] of Object.entries(query)) {{
    if (value === undefined || value === null) {{
      continue;
    }}
    if (Array.isArray(value)) {{
      for (const item of value) {{
        if (item !== undefined && item !== null) {{
          searchParams.append(key, stringifyScalarValue(item));
        }}
      }}
      continue;
    }}
    if (value instanceof Blob) {{
      continue;
    }}
    searchParams.append(key, stringifyScalarValue(value));
  }}
}}

function stringifyScalarValue(value) {{
  if (typeof value === "string") {{
    return value;
  }}
  if (typeof value === "number" || typeof value === "boolean") {{
    return String(value);
  }}
  return stringifyTemporalValue(value);
}}

function stringifyScalarLikeValue(value) {{
  if (typeof value === "string") {{
    return value;
  }}
  if (typeof value === "number" || typeof value === "boolean") {{
    return String(value);
  }}
  if (isTemporalValue(value)) {{
    return stringifyTemporalValue(value);
  }}
  return String(value);
}}

function objectToFormData(value) {{
  if (value instanceof FormData) {{
    return value;
  }}
  const formData = new FormData();
  if (!value || typeof value !== "object") {{
    return formData;
  }}
  for (const [key, entry] of Object.entries(value)) {{
    appendFormDataValue(formData, key, entry);
  }}
  return formData;
}}

function appendFormDataValue(formData, key, value) {{
  if (value === undefined || value === null) {{
    return;
  }}
  if (Array.isArray(value)) {{
    for (const item of value) {{
      appendFormDataValue(formData, key, item);
    }}
    return;
  }}
  if (value instanceof Blob) {{
    formData.append(key, value);
    return;
  }}
  if (isTemporalValue(value)) {{
    formData.append(key, stringifyTemporalValue(value));
    return;
  }}
  if (typeof value === "string") {{
    formData.append(key, value);
    return;
  }}
  if (typeof value === "number" || typeof value === "boolean") {{
    formData.append(key, String(value));
    return;
  }}
  formData.append(key, JSON.stringify(value));
}}

async function parseResponseBody(response) {{
  if (response.status === 204 || response.status === 205) {{
    return undefined;
  }}

  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {{
    const text = await response.text();
    return text ? JSON.parse(text) : undefined;
  }}
  if (contentType.startsWith("text/")) {{
    return response.text();
  }}
  const text = await response.text();
  return text ? text : undefined;
}}

function normalizeJsonValue(value) {{
  if (value === undefined || value === null) {{
    return value;
  }}
  if (isTemporalValue(value)) {{
    return stringifyTemporalValue(value);
  }}
  if (Array.isArray(value)) {{
    return value.map((entry) => normalizeJsonValue(entry));
  }}
  if (value instanceof Blob || value instanceof FormData || value instanceof URLSearchParams) {{
    return value;
  }}
  if (typeof value === "object") {{
    const normalized = {{}};
    for (const [key, entry] of Object.entries(value)) {{
      normalized[key] = normalizeJsonValue(entry);
    }}
    return normalized;
  }}
  return value;
}}

function isTemporalValue(value) {{
  return value instanceof Date || value instanceof VsrDate || value instanceof VsrTime;
}}

function stringifyTemporalValue(value) {{
  if (value instanceof Date) {{
    if (Number.isNaN(value.getTime())) {{
      throw new Error("Invalid DateTimeInput value.");
    }}
    return `${{padNumber(value.getUTCFullYear(), 4)}}-${{padNumber(value.getUTCMonth() + 1, 2)}}-${{padNumber(value.getUTCDate(), 2)}}T${{padNumber(value.getUTCHours(), 2)}}:${{padNumber(value.getUTCMinutes(), 2)}}:${{padNumber(value.getUTCSeconds(), 2)}}.${{padNumber(value.getUTCMilliseconds() * 1000, 6)}}+00:00`;
  }}
  return value.toString();
}}

function padNumber(value, width) {{
  return String(value).padStart(width, "0");
}}
"#
    )
}

fn render_types_ts(
    schemas: &BTreeMap<String, Value>,
    input_schema_aliases: &BTreeSet<String>,
) -> String {
    let mut output = String::from("// Generated by `vsr client ts`\n\n");
    if !input_schema_aliases.is_empty() {
        output.push_str(
            "import type { DateInput, DateTimeInput, TimeInput } from \"./client.ts\";\n\n",
        );
    }
    for (name, schema) in schemas {
        let type_name = sanitize_type_name(name);
        output.push_str(&format!(
            "export type {} = {};\n\n",
            type_name,
            render_schema_type_with_refs(
                schema,
                0,
                RefMode::Bare,
                TypeUsage::Output,
                input_schema_aliases
            )
        ));
        if input_schema_aliases.contains(&type_name) {
            output.push_str(&format!(
                "export type {}Input = {};\n\n",
                type_name,
                render_schema_type_with_refs(
                    schema,
                    0,
                    RefMode::Bare,
                    TypeUsage::Input,
                    input_schema_aliases
                )
            ));
        }
    }
    if schemas.is_empty() {
        output.push_str("export {};\n");
    }
    output
}

fn render_operations_ts(
    document: &ClientDocument,
    input_schema_aliases: &BTreeSet<String>,
) -> String {
    let mut output = String::from(
        "// Generated by `vsr client ts`\n\nimport type * as Schemas from \"./types.ts\";\nimport { interpolatePath, type DateInput, type DateTimeInput, type QueryParams, type TimeInput, type VsrClient } from \"./client.ts\";\n\ntype Req = { headers?: HeadersInit; signal?: AbortSignal };\ntype Page<S extends string> = { limit?: number; offset?: number; cursor?: string; sort?: S; order?: \"asc\" | \"desc\" };\ntype Range<K extends string, V> = { [P in K]?: V } & { [P in K as `${P}_gt` | `${P}_gte` | `${P}_lt` | `${P}_lte`]?: V };\ntype DR<K extends string, V = DateTimeInput> = Range<K, V>;\nconst r = (p: Req) => ({ headers: p.headers, signal: p.signal });\n\n",
    );

    for operation in &document.operations {
        let request_type_name = format!("{}Request", sanitize_type_name(&operation.operation_id));
        let query_type_name = (!operation.query_params.is_empty())
            .then(|| format!("{}Query", sanitize_type_name(&operation.operation_id)));
        let response_type =
            render_operation_response_type(&operation.response, input_schema_aliases);
        if let Some(query_type_name) = query_type_name.as_deref() {
            output.push_str(&format!(
                "export type {query_type_name} = {};\n",
                render_operation_query_type(&operation.query_params, input_schema_aliases)
            ));
        }
        if !operation_uses_inline_req(operation) {
            output.push_str(&format!(
                "export type {request_type_name} = {};\n",
                render_operation_request_type(
                    operation,
                    query_type_name.as_deref(),
                    input_schema_aliases
                )
            ));
        }
        if query_type_name.is_some() || !operation_uses_inline_req(operation) {
            output.push('\n');
        }
        let params_default = if operation_has_required_inputs(operation) {
            ""
        } else {
            " = {}"
        };
        let params_type = if operation_uses_inline_req(operation) {
            "Req"
        } else {
            request_type_name.as_str()
        };
        output.push_str(&format!(
            "export async function {}(client: VsrClient, params: {}{}): Promise<{}> {{\n",
            sanitize_identifier(&operation.operation_id),
            params_type,
            params_default,
            response_type
        ));
        output.push_str(&format!(
            "  return client.request<{}>({});\n",
            response_type,
            render_request_config_literal(operation, false)
        ));
        output.push_str("}\n\n");
    }

    if document.operations.is_empty() {
        output.push_str("export {};\n");
    }

    output
}

fn render_operations_js(document: &ClientDocument) -> String {
    let mut output = String::from(
        "// Generated by `vsr client ts`\n\nimport { interpolatePath } from \"./client.js\";\n\nconst r = (p) => ({ headers: p.headers, signal: p.signal });\n\n",
    );

    for operation in &document.operations {
        let params_default = if operation_has_required_inputs(operation) {
            ""
        } else {
            " = {}"
        };
        output.push_str(&format!(
            "export async function {}(client, params{}) {{\n",
            sanitize_identifier(&operation.operation_id),
            params_default
        ));
        output.push_str(&format!(
            "  return client.request({});\n",
            render_request_config_literal(operation, true)
        ));
        output.push_str("}\n\n");
    }

    if document.operations.is_empty() {
        output.push_str("export {};\n");
    }

    output
}

fn render_operation_response_type(
    response: &ClientResponse,
    input_schema_aliases: &BTreeSet<String>,
) -> String {
    match &response.kind {
        ResponseKind::Json(schema) => render_schema_type_with_refs(
            schema,
            0,
            RefMode::Schemas,
            TypeUsage::Output,
            input_schema_aliases,
        ),
        ResponseKind::Text => "string".to_owned(),
        ResponseKind::Binary => "Blob".to_owned(),
        ResponseKind::Void => "void".to_owned(),
    }
}

fn render_operation_request_type(
    operation: &ClientOperation,
    query_type_name: Option<&str>,
    input_schema_aliases: &BTreeSet<String>,
) -> String {
    let mut parts = Vec::new();
    if !operation.path_params.is_empty() {
        parts.push(render_type_literal(
            &[format!(
                "\"path\": {};",
                render_parameter_object_type(
                    &operation.path_params,
                    TypeUsage::Input,
                    input_schema_aliases
                )
            )],
            0,
        ));
    }
    if let Some(query_type_name) = query_type_name {
        let optional = operation.query_params.iter().all(|param| !param.required);
        parts.push(render_type_literal(
            &[format!(
                "\"query\"{}: {query_type_name};",
                if optional { "?" } else { "" }
            )],
            0,
        ));
    }
    if let Some(body) = &operation.request_body {
        parts.push(render_type_literal(
            &[format!(
                "\"body\": {};",
                render_schema_type_with_refs(
                    &body.schema,
                    1,
                    RefMode::Schemas,
                    TypeUsage::Input,
                    input_schema_aliases
                )
            )],
            0,
        ));
    }
    if !operation.header_params.is_empty() {
        let optional = operation.header_params.iter().all(|param| !param.required);
        parts.push(render_type_literal(
            &[
                format!(
                    "\"headers\"{}: {};",
                    if optional { "?" } else { "" },
                    render_parameter_object_type(
                        &operation.header_params,
                        TypeUsage::Input,
                        input_schema_aliases
                    )
                ),
                "\"signal\"?: AbortSignal;".to_owned(),
            ],
            0,
        ));
    } else {
        parts.push("Req".to_owned());
    }
    render_intersection_type(&parts)
}

fn render_operation_query_type(
    parameters: &[ClientParameter],
    input_schema_aliases: &BTreeSet<String>,
) -> String {
    let page_sort_union = render_page_sort_union(parameters, input_schema_aliases);
    let range_groups = collect_range_groups(parameters, input_schema_aliases);
    let mut consumed = BTreeSet::new();
    if page_sort_union.is_some() {
        consumed.extend(["limit", "offset", "cursor", "sort", "order"]);
    }
    for group in &range_groups {
        for name in &group.covered_names {
            consumed.insert(name.as_str());
        }
    }

    let remaining = parameters
        .iter()
        .filter(|parameter| !consumed.contains(parameter.name.as_str()))
        .collect::<Vec<_>>();

    let mut parts = Vec::new();
    if let Some(sort_union) = page_sort_union {
        parts.push(format!("Page<{sort_union}>"));
    }
    for group in range_groups {
        parts.push(group.rendered);
    }
    if !remaining.is_empty() {
        parts.push(render_parameter_object_type_refs(
            &remaining,
            TypeUsage::Input,
            input_schema_aliases,
        ));
    }

    if parts.is_empty() {
        "{}".to_owned()
    } else if parts.len() == 1 {
        parts.remove(0)
    } else {
        parts.join("\n  & ")
    }
}

fn render_parameter_object_type(
    parameters: &[ClientParameter],
    type_usage: TypeUsage,
    input_schema_aliases: &BTreeSet<String>,
) -> String {
    let parameters = parameters.iter().collect::<Vec<_>>();
    render_parameter_object_type_refs(&parameters, type_usage, input_schema_aliases)
}

fn render_parameter_object_type_refs(
    parameters: &[&ClientParameter],
    type_usage: TypeUsage,
    input_schema_aliases: &BTreeSet<String>,
) -> String {
    let fields = parameters
        .iter()
        .map(|parameter| {
            format!(
                "{}{}: {};",
                quoted_property_name(&parameter.name),
                if parameter.required { "" } else { "?" },
                render_schema_type_with_refs(
                    &parameter.schema,
                    1,
                    RefMode::Schemas,
                    type_usage,
                    input_schema_aliases
                )
            )
        })
        .collect::<Vec<_>>();
    render_type_literal(&fields, 0)
}

fn render_request_config_literal(operation: &ClientOperation, javascript: bool) -> String {
    let mut fields = vec![format!("method: {:?}", operation.method)];
    if operation.path_params.is_empty() {
        fields.push(format!("path: {:?}", operation.path));
    } else {
        fields.push(format!(
            "path: interpolatePath({:?}, params.path)",
            operation.path
        ));
    }
    if !operation.query_params.is_empty() {
        fields.push(if javascript {
            "query: params.query".to_owned()
        } else {
            "query: params.query as QueryParams | undefined".to_owned()
        });
    }
    if let Some(body) = &operation.request_body {
        fields.push("body: params.body".to_owned());
        if let Some(content_type) = body.content_type.as_http_header() {
            fields.push(format!("contentType: {:?}", content_type));
        } else if body.content_type == RequestContentType::Multipart {
            fields.push("contentType: \"multipart/form-data\"".to_owned());
        }
    }
    fields.push("...r(params)".to_owned());
    if operation.requires_bearer_auth {
        fields.push("requiresBearerAuth: true".to_owned());
    }
    let mut literal = String::from("{\n");
    for field in &fields {
        literal.push_str("    ");
        literal.push_str(field);
        literal.push_str(",\n");
    }
    literal.push_str("  }");
    literal
}

fn operation_has_required_inputs(operation: &ClientOperation) -> bool {
    operation.path_params.iter().any(|param| param.required)
        || operation.query_params.iter().any(|param| param.required)
        || operation.header_params.iter().any(|param| param.required)
        || operation.request_body.is_some()
}

fn operation_uses_inline_req(operation: &ClientOperation) -> bool {
    operation.path_params.is_empty()
        && operation.query_params.is_empty()
        && operation.header_params.is_empty()
        && operation.request_body.is_none()
}

fn render_page_sort_union(
    parameters: &[ClientParameter],
    input_schema_aliases: &BTreeSet<String>,
) -> Option<String> {
    let mut limit = false;
    let mut offset = false;
    let mut cursor = false;
    let mut order = false;
    let mut sort_union = None;

    for parameter in parameters {
        match parameter.name.as_str() {
            "limit" => limit = true,
            "offset" => offset = true,
            "cursor" => cursor = true,
            "order" => order = true,
            "sort" => {
                sort_union = Some(render_schema_type_with_refs(
                    &parameter.schema,
                    0,
                    RefMode::Schemas,
                    TypeUsage::Input,
                    input_schema_aliases,
                ));
            }
            _ => {}
        }
    }

    (limit && offset && cursor && order)
        .then(|| sort_union)
        .flatten()
}

fn collect_range_groups(
    parameters: &[ClientParameter],
    input_schema_aliases: &BTreeSet<String>,
) -> Vec<RenderedRangeGroup> {
    let mut base_groups = Vec::<RangeGroupSpec>::new();
    let mut base_index = BTreeMap::<String, usize>::new();

    for parameter in parameters {
        let Some(base_name) = range_parameter_base_name(&parameter.name) else {
            continue;
        };
        let value_type = render_schema_type_with_refs(
            &parameter.schema,
            0,
            RefMode::Schemas,
            TypeUsage::Input,
            input_schema_aliases,
        );
        let uses_dr = matches!(
            value_type.as_str(),
            "DateTimeInput" | "DateInput" | "TimeInput"
        );
        let index = match base_index.get(base_name).copied() {
            Some(index) => index,
            None => {
                let index = base_groups.len();
                base_groups.push(RangeGroupSpec {
                    base_name: base_name.to_owned(),
                    covered_names: BTreeSet::new(),
                    value_type,
                    uses_dr,
                });
                base_index.insert(base_name.to_owned(), index);
                index
            }
        };
        let group = &mut base_groups[index];
        group.covered_names.insert(parameter.name.clone());
        group.uses_dr &= uses_dr;
    }

    for parameter in parameters {
        if let Some(index) = base_index.get(&parameter.name).copied() {
            let group = &mut base_groups[index];
            group.covered_names.insert(parameter.name.clone());
            if group.value_type.is_empty() {
                group.value_type = render_schema_type_with_refs(
                    &parameter.schema,
                    0,
                    RefMode::Schemas,
                    TypeUsage::Input,
                    input_schema_aliases,
                );
            }
            group.uses_dr &= matches!(
                group.value_type.as_str(),
                "DateTimeInput" | "DateInput" | "TimeInput"
            );
        }
    }

    let mut rendered_groups = Vec::<RenderedRangeGroup>::new();
    for group in base_groups {
        let key = if group.uses_dr {
            ("dr".to_owned(), group.value_type.clone())
        } else {
            ("range".to_owned(), group.value_type.clone())
        };
        if let Some(existing) = rendered_groups
            .iter_mut()
            .find(|candidate| candidate.key == key)
        {
            existing.base_names.push(group.base_name);
            existing.covered_names.extend(group.covered_names);
        } else {
            rendered_groups.push(RenderedRangeGroup {
                key,
                base_names: vec![group.base_name],
                covered_names: group.covered_names,
                rendered: String::new(),
            });
        }
    }

    for group in &mut rendered_groups {
        let union = render_string_literal_union(&group.base_names);
        group.rendered = if group.key.0 == "dr" {
            if group.key.1 == "DateTimeInput" {
                format!("DR<{union}>")
            } else {
                format!("DR<{union}, {}>", group.key.1)
            }
        } else {
            format!("Range<{union}, {}>", group.key.1)
        };
    }

    rendered_groups
}

fn range_parameter_base_name(value: &str) -> Option<&str> {
    for suffix in ["_gt", "_gte", "_lt", "_lte"] {
        if let Some(base) = value.strip_suffix(suffix) {
            return Some(base);
        }
    }
    None
}

fn render_string_literal_union(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("{value:?}"))
        .collect::<Vec<_>>()
        .join(" | ")
}

fn render_intersection_type(parts: &[String]) -> String {
    if parts.is_empty() {
        "{}".to_owned()
    } else if parts.len() == 1 {
        parts[0].clone()
    } else {
        parts.join(" &\n  ")
    }
}

#[derive(Clone, Debug)]
struct RangeGroupSpec {
    base_name: String,
    covered_names: BTreeSet<String>,
    value_type: String,
    uses_dr: bool,
}

#[derive(Clone, Debug)]
struct RenderedRangeGroup {
    key: (String, String),
    base_names: Vec<String>,
    covered_names: BTreeSet<String>,
    rendered: String,
}

fn render_type_literal(fields: &[String], indent_level: usize) -> String {
    if fields.is_empty() {
        return "{}".to_owned();
    }
    let indent = "  ".repeat(indent_level);
    let field_indent = "  ".repeat(indent_level + 1);
    let mut rendered = String::from("{\n");
    for field in fields {
        rendered.push_str(&field_indent);
        rendered.push_str(field);
        rendered.push('\n');
    }
    rendered.push_str(&indent);
    rendered.push('}');
    rendered
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RefMode {
    Bare,
    Schemas,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TypeUsage {
    Output,
    Input,
}

fn compute_input_schema_aliases(schemas: &BTreeMap<String, Value>) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    loop {
        let mut next_aliases = BTreeSet::new();
        for (name, schema) in schemas {
            let output =
                render_schema_type_with_refs(schema, 0, RefMode::Bare, TypeUsage::Output, &aliases);
            let input =
                render_schema_type_with_refs(schema, 0, RefMode::Bare, TypeUsage::Input, &aliases);
            if output != input {
                next_aliases.insert(sanitize_type_name(name));
            }
        }
        if next_aliases == aliases {
            return aliases;
        }
        aliases = next_aliases;
    }
}

fn render_schema_type_with_refs(
    schema: &Value,
    indent_level: usize,
    ref_mode: RefMode,
    type_usage: TypeUsage,
    input_schema_aliases: &BTreeSet<String>,
) -> String {
    let Some(schema) = schema.as_object() else {
        return "unknown".to_owned();
    };

    let mut rendered = if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let type_name = reference
            .rsplit('/')
            .next()
            .map(sanitize_type_name)
            .unwrap_or_else(|| "unknown".to_owned());
        let reference_type_name =
            if type_usage == TypeUsage::Input && input_schema_aliases.contains(&type_name) {
                format!("{type_name}Input")
            } else {
                type_name
            };
        match ref_mode {
            RefMode::Bare => reference_type_name,
            RefMode::Schemas => format!("Schemas.{reference_type_name}"),
        }
    } else if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        render_enum_union(values)
    } else if let Some(value) = schema.get("const") {
        render_literal_type(value)
    } else if let Some(values) = schema.get("oneOf").and_then(Value::as_array) {
        render_union(
            values,
            indent_level,
            "|",
            ref_mode,
            type_usage,
            input_schema_aliases,
        )
    } else if let Some(values) = schema.get("anyOf").and_then(Value::as_array) {
        render_union(
            values,
            indent_level,
            "|",
            ref_mode,
            type_usage,
            input_schema_aliases,
        )
    } else if let Some(values) = schema.get("allOf").and_then(Value::as_array) {
        render_union(
            values,
            indent_level,
            "&",
            ref_mode,
            type_usage,
            input_schema_aliases,
        )
    } else if schema_type(schema) == Some("array") {
        let item_type = schema
            .get("items")
            .map(|items| {
                render_schema_type_with_refs(
                    items,
                    indent_level,
                    ref_mode,
                    type_usage,
                    input_schema_aliases,
                )
            })
            .unwrap_or_else(|| "unknown".to_owned());
        format!("Array<{item_type}>")
    } else if schema_type(schema) == Some("object")
        || schema.contains_key("properties")
        || schema.contains_key("additionalProperties")
    {
        render_object_schema(
            schema,
            indent_level,
            ref_mode,
            type_usage,
            input_schema_aliases,
        )
    } else {
        match schema_type(schema) {
            Some("string") => {
                if schema.get("format").and_then(Value::as_str) == Some("binary") {
                    "Blob".to_owned()
                } else if type_usage == TypeUsage::Input {
                    render_temporal_input_type(schema).unwrap_or_else(|| "string".to_owned())
                } else {
                    "string".to_owned()
                }
            }
            Some("integer") | Some("number") => "number".to_owned(),
            Some("boolean") => "boolean".to_owned(),
            Some("null") => "null".to_owned(),
            _ => "unknown".to_owned(),
        }
    };

    if schema
        .get("nullable")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && rendered != "null"
    {
        rendered = format!("({rendered}) | null");
    }
    rendered
}

fn render_enum_union(values: &[Value]) -> String {
    values
        .iter()
        .map(render_literal_type)
        .collect::<Vec<_>>()
        .join(" | ")
}

fn render_literal_type(value: &Value) -> String {
    match value {
        Value::String(value) => format!("{value:?}"),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => "null".to_owned(),
        _ => "unknown".to_owned(),
    }
}

fn render_union(
    values: &[Value],
    indent_level: usize,
    separator: &str,
    ref_mode: RefMode,
    type_usage: TypeUsage,
    input_schema_aliases: &BTreeSet<String>,
) -> String {
    values
        .iter()
        .map(|value| {
            parenthesize_complex_type(&render_schema_type_with_refs(
                value,
                indent_level + 1,
                ref_mode,
                type_usage,
                input_schema_aliases,
            ))
        })
        .collect::<Vec<_>>()
        .join(&format!(" {separator} "))
}

fn render_object_schema(
    schema: &Map<String, Value>,
    indent_level: usize,
    ref_mode: RefMode,
    type_usage: TypeUsage,
    input_schema_aliases: &BTreeSet<String>,
) -> String {
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();

    let mut fields = Vec::new();
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, property_schema) in properties {
            fields.push(format!(
                "{}{}: {};",
                quoted_property_name(name),
                if required.contains(name) { "" } else { "?" },
                render_schema_type_with_refs(
                    property_schema,
                    indent_level + 1,
                    ref_mode,
                    type_usage,
                    input_schema_aliases,
                )
            ));
        }
    }

    match schema.get("additionalProperties") {
        Some(Value::Bool(true)) => fields.push("[key: string]: unknown;".to_owned()),
        Some(Value::Object(_)) => fields.push(format!(
            "[key: string]: {};",
            render_schema_type_with_refs(
                &schema["additionalProperties"],
                indent_level + 1,
                ref_mode,
                type_usage,
                input_schema_aliases,
            )
        )),
        _ => {}
    }

    render_type_literal(&fields, indent_level)
}

fn schema_type(schema: &Map<String, Value>) -> Option<&str> {
    schema.get("type").and_then(Value::as_str)
}

fn render_temporal_input_type(schema: &Map<String, Value>) -> Option<String> {
    match schema.get("format").and_then(Value::as_str) {
        Some("date-time") => Some("DateTimeInput".to_owned()),
        Some("date") => Some("DateInput".to_owned()),
        Some("time") => Some("TimeInput".to_owned()),
        _ => None,
    }
}

fn parenthesize_complex_type(value: &str) -> String {
    if value.contains('\n') || value.contains(" | ") || value.contains(" & ") {
        format!("({value})")
    } else {
        value.to_owned()
    }
}

fn sanitize_identifier(value: &str) -> String {
    let mut output = String::new();
    for (index, ch) in value.chars().enumerate() {
        if (index == 0 && (ch.is_ascii_alphabetic() || ch == '_'))
            || (index > 0 && (ch.is_ascii_alphanumeric() || ch == '_'))
        {
            output.push(ch);
        } else {
            output.push('_');
        }
    }

    if output.is_empty() {
        output.push('_');
    }
    output
}

fn sanitize_type_name(value: &str) -> String {
    let identifier = sanitize_identifier(value);
    let mut chars = identifier.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
        None => "Unknown".to_owned(),
    }
}

fn quoted_property_name(value: &str) -> String {
    format!("{value:?}")
}

fn run_typescript_client_self_test(
    input: &Path,
    generated: &GeneratedClientArtifacts,
    options: &TypescriptClientSelfTestOptions,
) -> Result<ClientSelfTestReport> {
    let mut checks = Vec::new();

    checks.push(check_generated_client_manifest(&generated.output_dir)?);
    checks.push(check_generated_client_import_graph(&generated.output_dir)?);
    checks.push(run_node_import_smoke_check(&generated.output_dir, options)?);
    checks.push(run_typescript_compile_check(
        &generated.output_dir,
        options,
    )?);

    if let Some(base_url) = options.runtime_base_url.as_deref() {
        checks.extend(run_runtime_probe_checks(generated, base_url, options)?);
    }

    let summary = summarize_client_self_test_checks(&checks);
    Ok(ClientSelfTestReport {
        generated_at: Utc::now().to_rfc3339(),
        schema_input: input.display().to_string(),
        client_dir: generated.output_dir.display().to_string(),
        package_name: generated.package_name.clone(),
        runtime_base_url: options.runtime_base_url.clone(),
        passed: summary.failed == 0,
        summary,
        checks,
    })
}

fn check_generated_client_manifest(output_dir: &Path) -> Result<ClientSelfTestCheck> {
    let package_json: Value = serde_json::from_str(
        &fs::read_to_string(output_dir.join("package.json"))
            .context("failed to read generated package.json")?,
    )
    .context("generated package.json was invalid JSON")?;

    let mut forbidden = Vec::new();
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if package_json.get(field).is_some() {
            forbidden.push(field);
        }
    }

    Ok(if forbidden.is_empty() {
        ClientSelfTestCheck {
            name: "manifest.dependencies".to_owned(),
            kind: ClientSelfTestKind::Static,
            status: ClientSelfTestStatus::Passed,
            details: "Generated package.json does not declare external package dependencies."
                .to_owned(),
            metadata: None,
        }
    } else {
        ClientSelfTestCheck {
            name: "manifest.dependencies".to_owned(),
            kind: ClientSelfTestKind::Static,
            status: ClientSelfTestStatus::Failed,
            details: format!(
                "Generated package.json declared forbidden dependency sections: {}.",
                forbidden.join(", ")
            ),
            metadata: Some(serde_json::json!({ "forbidden_sections": forbidden })),
        }
    })
}

fn check_generated_client_import_graph(output_dir: &Path) -> Result<ClientSelfTestCheck> {
    let source_files = collect_generated_client_source_files(output_dir)?;
    let mut bare_imports = Vec::new();

    for path in &source_files {
        for specifier in collect_module_specifiers(path)? {
            if !(specifier.starts_with("./") || specifier.starts_with("../")) {
                bare_imports.push(serde_json::json!({
                    "file": path.display().to_string(),
                    "specifier": specifier,
                }));
            }
        }
    }

    Ok(if bare_imports.is_empty() {
        ClientSelfTestCheck {
            name: "module.imports".to_owned(),
            kind: ClientSelfTestKind::Static,
            status: ClientSelfTestStatus::Passed,
            details: "Generated client source files import only relative local modules.".to_owned(),
            metadata: Some(serde_json::json!({
                "files_checked": source_files.len(),
            })),
        }
    } else {
        ClientSelfTestCheck {
            name: "module.imports".to_owned(),
            kind: ClientSelfTestKind::Static,
            status: ClientSelfTestStatus::Failed,
            details: "Generated TypeScript files imported external or bare module specifiers."
                .to_owned(),
            metadata: Some(serde_json::json!({
                "files_checked": source_files.len(),
                "bare_imports": bare_imports,
            })),
        }
    })
}

fn run_node_import_smoke_check(
    output_dir: &Path,
    options: &TypescriptClientSelfTestOptions,
) -> Result<ClientSelfTestCheck> {
    let Some(node_binary) = resolve_executable(options.node_binary.as_deref(), "node") else {
        return Ok(ClientSelfTestCheck {
            name: "runtime.node_import_smoke".to_owned(),
            kind: ClientSelfTestKind::Runtime,
            status: if options.runtime_base_url.is_some() {
                ClientSelfTestStatus::Failed
            } else {
                ClientSelfTestStatus::Skipped
            },
            details: if options.runtime_base_url.is_some() {
                "Node.js was not available, so the generated client runtime smoke test could not run."
                    .to_owned()
            } else {
                "Node.js was not available, so the generated client runtime import smoke test was skipped."
                    .to_owned()
            },
            metadata: None,
        });
    };

    let runtime_module_path = preferred_runtime_module_path(output_dir);
    let requires_typescript_runtime = runtime_module_path
        .extension()
        .and_then(|value| value.to_str())
        == Some("ts");
    if requires_typescript_runtime && !node_supports_typescript_scripts(&node_binary)? {
        return Ok(ClientSelfTestCheck {
            name: "runtime.node_import_smoke".to_owned(),
            kind: ClientSelfTestKind::Runtime,
            status: if options.runtime_base_url.is_some() {
                ClientSelfTestStatus::Failed
            } else {
                ClientSelfTestStatus::Skipped
            },
            details: if options.runtime_base_url.is_some() {
                "Node.js was available, but it could not execute the generated TypeScript client runtime directly."
                    .to_owned()
            } else {
                "Node.js was available, but it could not execute TypeScript modules directly, so the generated client runtime import smoke test was skipped."
                    .to_owned()
            },
            metadata: Some(serde_json::json!({
                "node_binary": node_binary.display().to_string(),
                "module_path": runtime_module_path.display().to_string(),
            })),
        });
    }

    let module_url = file_url_string(&runtime_module_path)?;
    let script_path = temp_self_test_script_path(
        "import-smoke",
        if requires_typescript_runtime {
            "ts"
        } else {
            "mjs"
        },
    )?;
    fs::write(
        &script_path,
        format!(
            "import {{ createClient }} from {module_url:?};\n\
             const client = createClient({{ baseUrl: \"\" }});\n\
             if (!client || typeof client.request !== \"function\") {{\n\
               throw new Error(\"generated client did not expose a request function\");\n\
             }}\n\
             console.log(JSON.stringify({{ ok: true }}));\n"
        ),
    )
    .with_context(|| format!("failed to write {}", script_path.display()))?;

    let output = Command::new(&node_binary)
        .arg(&script_path)
        .output()
        .with_context(|| format!("failed to execute {}", node_binary.display()))?;
    let _ = fs::remove_file(&script_path);

    Ok(if output.status.success() {
        ClientSelfTestCheck {
            name: "runtime.node_import_smoke".to_owned(),
            kind: ClientSelfTestKind::Runtime,
            status: ClientSelfTestStatus::Passed,
            details: "Node.js imported the generated client and created a runtime client instance."
                .to_owned(),
            metadata: Some(serde_json::json!({
                "node_binary": node_binary.display().to_string(),
            })),
        }
    } else {
        ClientSelfTestCheck {
            name: "runtime.node_import_smoke".to_owned(),
            kind: ClientSelfTestKind::Runtime,
            status: ClientSelfTestStatus::Failed,
            details: format!(
                "Node.js failed to import the generated client.\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            metadata: Some(serde_json::json!({
                "node_binary": node_binary.display().to_string(),
            })),
        }
    })
}

fn run_typescript_compile_check(
    output_dir: &Path,
    options: &TypescriptClientSelfTestOptions,
) -> Result<ClientSelfTestCheck> {
    let Some(tsc_binary) = resolve_executable(options.tsc_binary.as_deref(), "tsc") else {
        return Ok(ClientSelfTestCheck {
            name: "typescript.compile".to_owned(),
            kind: ClientSelfTestKind::Static,
            status: ClientSelfTestStatus::Skipped,
            details: "TypeScript compiler was not available, so `tsc -p` was skipped.".to_owned(),
            metadata: None,
        });
    };

    let output = Command::new(&tsc_binary)
        .arg("-p")
        .arg(output_dir)
        .output()
        .with_context(|| format!("failed to execute {}", tsc_binary.display()))?;

    Ok(if output.status.success() {
        ClientSelfTestCheck {
            name: "typescript.compile".to_owned(),
            kind: ClientSelfTestKind::Static,
            status: ClientSelfTestStatus::Passed,
            details: "Generated client compiled cleanly with `tsc -p`.".to_owned(),
            metadata: Some(serde_json::json!({
                "tsc_binary": tsc_binary.display().to_string(),
            })),
        }
    } else {
        ClientSelfTestCheck {
            name: "typescript.compile".to_owned(),
            kind: ClientSelfTestKind::Static,
            status: ClientSelfTestStatus::Failed,
            details: format!(
                "TypeScript compile failed.\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            metadata: Some(serde_json::json!({
                "tsc_binary": tsc_binary.display().to_string(),
            })),
        }
    })
}

fn run_runtime_probe_checks(
    generated: &GeneratedClientArtifacts,
    base_url: &str,
    options: &TypescriptClientSelfTestOptions,
) -> Result<Vec<ClientSelfTestCheck>> {
    let Some(node_binary) = resolve_executable(options.node_binary.as_deref(), "node") else {
        return Ok(vec![ClientSelfTestCheck {
            name: "runtime.public_get_probes".to_owned(),
            kind: ClientSelfTestKind::Runtime,
            status: ClientSelfTestStatus::Failed,
            details:
                "Runtime probe execution requires Node.js, but no usable `node` executable was found."
                    .to_owned(),
            metadata: None,
        }]);
    };

    let runtime_module_path = preferred_runtime_module_path(&generated.output_dir);
    let requires_typescript_runtime = runtime_module_path
        .extension()
        .and_then(|value| value.to_str())
        == Some("ts");
    if requires_typescript_runtime && !node_supports_typescript_scripts(&node_binary)? {
        return Ok(vec![ClientSelfTestCheck {
            name: "runtime.public_get_probes".to_owned(),
            kind: ClientSelfTestKind::Runtime,
            status: ClientSelfTestStatus::Failed,
            details:
                "Runtime probe execution requires a Node.js runtime that can execute TypeScript modules directly, but the available `node` executable could not do so."
                    .to_owned(),
            metadata: Some(serde_json::json!({
                "node_binary": node_binary.display().to_string(),
                "module_path": runtime_module_path.display().to_string(),
            })),
        }]);
    }

    let probes = generated
        .document
        .operations
        .iter()
        .filter(|operation| {
            operation.method == "GET"
                && !operation.requires_bearer_auth
                && operation.request_body.is_none()
                && !operation.path_params.iter().any(|param| param.required)
                && !operation.query_params.iter().any(|param| param.required)
                && !operation.header_params.iter().any(|param| param.required)
        })
        .take(20)
        .cloned()
        .collect::<Vec<_>>();

    let script_path = temp_self_test_script_path(
        "runtime-probes",
        if requires_typescript_runtime {
            "ts"
        } else {
            "mjs"
        },
    )?;
    fs::write(
        &script_path,
        render_runtime_probe_script(&runtime_module_path, &probes)?,
    )
    .with_context(|| format!("failed to write {}", script_path.display()))?;

    let output = Command::new(&node_binary)
        .arg(&script_path)
        .env("BASE_URL", base_url)
        .env(
            "NODE_TLS_REJECT_UNAUTHORIZED",
            if options.insecure_tls { "0" } else { "1" },
        )
        .output()
        .with_context(|| format!("failed to execute {}", node_binary.display()))?;
    let _ = fs::remove_file(&script_path);

    if !output.status.success() {
        return Ok(vec![ClientSelfTestCheck {
            name: "runtime.public_get_probes".to_owned(),
            kind: ClientSelfTestKind::Runtime,
            status: ClientSelfTestStatus::Failed,
            details: format!(
                "Runtime probe script failed.\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            metadata: Some(serde_json::json!({
                "node_binary": node_binary.display().to_string(),
                "probe_count": probes.len(),
                "insecure_tls": options.insecure_tls,
            })),
        }]);
    }

    let runtime_report: Value = serde_json::from_slice(&output.stdout)
        .context("runtime probe script did not emit valid JSON")?;
    let checks = runtime_report
        .get("checks")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("runtime probe script omitted `checks`"))?;

    let mut rendered = Vec::new();
    for check in checks {
        let status = match check
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("failed")
        {
            "passed" => ClientSelfTestStatus::Passed,
            "skipped" => ClientSelfTestStatus::Skipped,
            _ => ClientSelfTestStatus::Failed,
        };
        rendered.push(ClientSelfTestCheck {
            name: check
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("runtime.unknown")
                .to_owned(),
            kind: ClientSelfTestKind::Runtime,
            status,
            details: check
                .get("details")
                .and_then(Value::as_str)
                .unwrap_or("runtime probe did not include details")
                .to_owned(),
            metadata: check.get("metadata").cloned(),
        });
    }
    Ok(rendered)
}

fn summarize_client_self_test_checks(checks: &[ClientSelfTestCheck]) -> ClientSelfTestSummary {
    let mut summary = ClientSelfTestSummary {
        passed: 0,
        failed: 0,
        skipped: 0,
    };
    for check in checks {
        match check.status {
            ClientSelfTestStatus::Passed => summary.passed += 1,
            ClientSelfTestStatus::Failed => summary.failed += 1,
            ClientSelfTestStatus::Skipped => summary.skipped += 1,
        }
    }
    summary
}

fn resolve_self_test_report_path(
    output_dir: &Path,
    options: &TypescriptClientSelfTestOptions,
) -> Result<PathBuf> {
    match options.report_path.as_deref() {
        Some(path) if path.is_absolute() => Ok(path.to_path_buf()),
        Some(path) => Ok(std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join(path)),
        None => Ok(output_dir.join("self-test-report.json")),
    }
}

fn write_self_test_report(report: &ClientSelfTestReport, path: &Path, force: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if path.exists() && !force {
        bail!(
            "self-test report already exists at {} (use --force to overwrite)",
            path.display()
        );
    }
    let rendered = serde_json::to_string_pretty(report)
        .context("failed to serialize generated client self-test report")?;
    fs::write(path, rendered).with_context(|| format!("failed to write {}", path.display()))
}

fn print_self_test_summary(report: &ClientSelfTestReport, report_path: &Path) {
    println!(
        "{} {} passed, {} failed, {} skipped",
        "Generated client self-test:".green().bold(),
        report.summary.passed,
        report.summary.failed,
        report.summary.skipped
    );
    println!(
        "{} {}",
        "Self-test report:".green().bold(),
        report_path.display()
    );
}

fn collect_generated_client_source_files(output_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = fs::read_dir(output_dir)
        .with_context(|| format!("failed to read {}", output_dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("ts" | "js")
            )
        })
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

fn preferred_runtime_module_path(output_dir: &Path) -> PathBuf {
    let js_path = output_dir.join("index.js");
    if js_path.is_file() {
        js_path
    } else {
        output_dir.join("index.ts")
    }
}

fn collect_module_specifiers(path: &Path) -> Result<Vec<String>> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut specifiers = Vec::new();
    for line in contents.lines() {
        if let Some(specifier) = extract_module_specifier(line) {
            specifiers.push(specifier.to_owned());
        }
    }
    Ok(specifiers)
}

fn extract_module_specifier(line: &str) -> Option<&str> {
    for marker in [" from \"", " from '", "import(\"", "import('"] {
        let Some(start_index) = line.find(marker) else {
            continue;
        };
        let start = start_index + marker.len();
        let rest = &line[start..];
        let end = match marker {
            " from \"" | "import(\"" => rest.find('"')?,
            " from '" | "import('" => rest.find('\'')?,
            _ => return None,
        };
        return Some(&rest[..end]);
    }
    None
}

fn resolve_executable(explicit: Option<&Path>, default_name: &str) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(normalize_windows_command_shim(path));
    }

    Command::new(default_name)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|_| PathBuf::from(default_name))
}

fn normalize_windows_command_shim(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        match path.extension().and_then(|value| value.to_str()) {
            Some("cmd" | "exe" | "bat") => return path.to_path_buf(),
            Some("ps1") => {
                let cmd_path = path.with_extension("cmd");
                if cmd_path.is_file() {
                    return cmd_path;
                }
            }
            _ => {
                let cmd_path = path.with_extension("cmd");
                if cmd_path.is_file() {
                    return cmd_path;
                }
            }
        }
    }

    path.to_path_buf()
}

fn node_supports_typescript_scripts(node_binary: &Path) -> Result<bool> {
    let script_path = temp_self_test_script_path("typescript-probe", "ts")?;
    fs::write(
        &script_path,
        "type ProbeValue = { value: number };\nconst probe: ProbeValue = { value: 1 };\nconsole.log(probe.value);\n",
    )
    .with_context(|| format!("failed to write {}", script_path.display()))?;

    let output = Command::new(node_binary)
        .arg(&script_path)
        .output()
        .with_context(|| format!("failed to execute {}", node_binary.display()))?;
    let _ = fs::remove_file(&script_path);
    Ok(output.status.success())
}

fn temp_self_test_script_path(kind: &str, extension: &str) -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "vsr-client-self-test-{kind}-{}.{}",
        Uuid::new_v4(),
        extension
    ));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(path)
}

fn file_url_string(path: &Path) -> Result<String> {
    url::Url::from_file_path(path)
        .map(|url| url.to_string())
        .map_err(|_| anyhow!("failed to convert {} to a file URL", path.display()))
}

fn render_runtime_probe_script(module_path: &Path, probes: &[ClientOperation]) -> Result<String> {
    let module_url = file_url_string(module_path)?;
    let mut import_names = vec!["createClient".to_owned()];
    import_names.extend(
        probes
            .iter()
            .map(|operation| sanitize_identifier(&operation.operation_id))
            .collect::<Vec<_>>(),
    );
    import_names.sort();
    import_names.dedup();

    let import_line = format!(
        "import {{ {} }} from {module_url:?};",
        import_names.join(", ")
    );

    let mut operations = String::new();
    for operation in probes {
        let function_name = sanitize_identifier(&operation.operation_id);
        operations.push_str(&format!(
            "  {{\n    name: {name:?},\n    path: {path:?},\n    run: () => {function_name}(client),\n  }},\n",
            name = format!("runtime.{}", function_name),
            path = operation.path,
        ));
    }

    Ok(format!(
        r#"{import_line}

const baseUrl = process.env.BASE_URL;
if (!baseUrl) {{
  throw new Error("missing BASE_URL for generated client self-test");
}}

function summarize(value) {{
  if (value === undefined) {{
    return {{ kind: "undefined" }};
  }}
  if (value === null) {{
    return {{ kind: "null" }};
  }}
  if (value instanceof Blob) {{
    return {{ kind: "blob", size: value.size, type: value.type }};
  }}
  if (Array.isArray(value)) {{
    return {{ kind: "array", length: value.length }};
  }}
  if (typeof value === "object") {{
    const keys = Object.keys(value);
    const summary = {{ kind: "object", keys: keys.slice(0, 8) }};
    if (typeof value.total === "number") {{
      summary.total = value.total;
    }}
    if (Array.isArray(value.items)) {{
      summary.items = value.items.length;
    }}
    return summary;
  }}
  return {{ kind: typeof value, value }};
}}

const checks = [];
try {{
  const openapi = await fetch(`${{baseUrl}}/openapi.json`);
  checks.push({{
    name: "runtime.openapi_reachable",
    status: openapi.ok ? "passed" : "failed",
    details: openapi.ok
      ? "OpenAPI document was reachable from the supplied base URL."
      : `OpenAPI reachability returned ${{openapi.status}} ${{openapi.statusText}}.`,
    metadata: {{ status: openapi.status }},
  }});
}} catch (error) {{
  checks.push({{
    name: "runtime.openapi_reachable",
    status: "failed",
    details: `OpenAPI reachability failed: ${{String(error)}}`,
  }});
}}

const client = createClient({{ baseUrl }});
const probes = [
{operations}];

if (probes.length === 0) {{
  checks.push({{
    name: "runtime.public_get_probes",
    status: "skipped",
    details: "No anonymous GET operations without required parameters were available for runtime probing.",
  }});
}} else {{
  for (const probe of probes) {{
    try {{
      const value = await probe.run();
      checks.push({{
        name: probe.name,
        status: "passed",
        details: `Probe completed successfully for ${{probe.path}}.`,
        metadata: {{ path: probe.path, summary: summarize(value) }},
      }});
    }} catch (error) {{
      checks.push({{
        name: probe.name,
        status: "failed",
        details: `Probe failed for ${{probe.path}}: ${{String(error)}}`,
        metadata: {{ path: probe.path }},
      }});
    }}
  }}
}}

console.log(JSON.stringify({{ checks }}, null, 2));
"#
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;
    use uuid::Uuid;

    use super::{
        ClientParameter, ClientSelfTestStatus, ParameterLocation, TypescriptClientSelfTestOptions,
        compute_input_schema_aliases, generate_automated_typescript_client_for_build,
        generate_typescript_client, render_operation_query_type, render_types_ts,
        run_node_import_smoke_check,
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn test_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/client_tests")
            .join(Uuid::new_v4().to_string())
    }

    fn read_to_string(path: &Path) -> String {
        fs::read_to_string(path).expect("generated file should be readable")
    }

    fn unique_env_name(prefix: &str) -> String {
        format!(
            "{prefix}_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos()
        )
    }

    #[cfg(unix)]
    fn write_executable_script(path: &Path, contents: &str) {
        fs::write(path, contents).expect("script should write");
        let mut permissions = fs::metadata(path)
            .expect("script metadata should load")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("script permissions should apply");
    }

    #[cfg(unix)]
    fn fake_node_binary(root: &Path) -> PathBuf {
        let node_path = root.join("fake-node");
        write_executable_script(
            &node_path,
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "v20.0.0"
  exit 0
fi

case "$1" in
  *.ts)
    echo 'TypeError [ERR_UNKNOWN_FILE_EXTENSION]: Unknown file extension ".ts"' >&2
    exit 1
    ;;
  *.mjs)
    echo '{"ok":true}'
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
"#,
        );
        node_path
    }

    #[test]
    fn generate_typescript_client_emits_core_files_for_blog_fixture() {
        let root = test_root();
        let output = root.join("blog-client");
        generate_typescript_client(
            &fixture_path("blog_api.eon"),
            Some(&output),
            false,
            &[],
            Some("@demo/blog-client"),
            Some("/api"),
            None,
            Some(true),
        )
        .expect("client should generate");

        let operations = read_to_string(&output.join("operations.ts"));
        let types = read_to_string(&output.join("types.ts"));
        let client = read_to_string(&output.join("client.ts"));
        let package_json = read_to_string(&output.join("package.json"));
        let tsconfig = read_to_string(&output.join("tsconfig.json"));

        assert!(operations.contains("export async function listPost"));
        assert!(operations.contains("export async function loginUser"));
        assert!(operations.contains("createPost(client: VsrClient"));
        assert!(operations.contains("type DR<K extends string, V = DateTimeInput> = Range<K, V>;"));
        assert!(operations.contains("type Req = { headers?: HeadersInit; signal?: AbortSignal };"));
        assert!(operations.contains("type Page<S extends string> = { limit?: number; offset?: number; cursor?: string; sort?: S; order?: \"asc\" | \"desc\" };"));
        assert!(operations.contains("type Range<K extends string, V> = { [P in K]?: V } & { [P in K as `${P}_gt` | `${P}_gte` | `${P}_lt` | `${P}_lte`]?: V };"));
        assert!(
            operations
                .contains("const r = (p: Req) => ({ headers: p.headers, signal: p.signal });")
        );
        assert!(operations.contains("export type ListPostQuery = Page<"));
        assert!(
            operations.contains("getAuthenticatedAccount(client: VsrClient, params: Req = {})")
        );
        assert!(operations.contains("...r(params)"));
        assert!(operations.contains("requiresBearerAuth: true"));
        assert!(!operations.contains("requiresBearerAuth: false"));
        assert!(!operations.contains("export type ListPostResponse ="));
        assert!(!operations.contains("/**"));
        assert!(types.contains("export type Post ="));
        assert!(types.contains("export type PostInput ="));
        assert!(types.contains("\"created_at\"?: (string) | null;"));
        assert!(types.contains("\"created_at\"?: (DateTimeInput) | null;"));
        assert!(types.contains("export type AuthTokenResponse ="));
        assert!(client.contains("export function createClient"));
        assert!(client.contains("export type DateTimeInput = string | Date;"));
        assert!(client.contains("export class VsrDate"));
        assert!(client.contains("export class VsrTime"));
        assert!(client.contains("function requestNeedsCsrf(method: string): boolean"));
        assert!(
            client.contains("if (requestNeedsCsrf(request.method) && resolvedConfig.getCsrfToken)")
        );
        assert!(!client.contains("if (body !== undefined && resolvedConfig.getCsrfToken)"));
        assert!(
            client.contains("if (request.requiresBearerAuth && resolvedConfig.getAccessToken)")
        );
        assert!(!client.contains("const requiresBearerAuth = request.requiresBearerAuth ?? true;"));
        assert!(client.contains("body = JSON.stringify(normalizeJsonValue(request.body));"));
        assert!(package_json.contains("\"name\": \"@demo/blog-client\""));
        assert!(tsconfig.contains("\"allowImportingTsExtensions\": true"));
    }

    #[test]
    fn generate_typescript_client_composes_datetime_and_numeric_range_query_helpers() {
        let root = test_root();

        let mixin_output = root.join("mixin-client");
        generate_typescript_client(
            &fixture_path("mixin_fields_api.eon"),
            Some(&mixin_output),
            false,
            &[],
            None,
            Some("/api"),
            None,
            Some(true),
        )
        .expect("mixin client should generate");
        let mixin_operations = read_to_string(&mixin_output.join("operations.ts"));
        assert!(mixin_operations.contains("export type ListPostQuery = Page<"));
        assert!(mixin_operations.contains("DR<\"filter_created_at\" | \"filter_updated_at\">"));

        let numeric_query = render_operation_query_type(
            &[
                ClientParameter {
                    name: "limit".to_owned(),
                    schema: serde_json::json!({ "type": "integer", "format": "int64" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "offset".to_owned(),
                    schema: serde_json::json!({ "type": "integer", "format": "int64" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "cursor".to_owned(),
                    schema: serde_json::json!({ "type": "string" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "sort".to_owned(),
                    schema: serde_json::json!({
                        "type": "string",
                        "enum": ["id", "publication_year"]
                    }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "order".to_owned(),
                    schema: serde_json::json!({
                        "type": "string",
                        "enum": ["asc", "desc"]
                    }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "filter_publication_year".to_owned(),
                    schema: serde_json::json!({ "type": "integer", "format": "int64" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "filter_publication_year_gt".to_owned(),
                    schema: serde_json::json!({ "type": "integer", "format": "int64" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "filter_publication_year_gte".to_owned(),
                    schema: serde_json::json!({ "type": "integer", "format": "int64" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "filter_publication_year_lt".to_owned(),
                    schema: serde_json::json!({ "type": "integer", "format": "int64" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "filter_publication_year_lte".to_owned(),
                    schema: serde_json::json!({ "type": "integer", "format": "int64" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
            ],
            &BTreeSet::new(),
        );
        assert!(numeric_query.contains("Page<\"id\" | \"publication_year\">"));
        assert!(numeric_query.contains("Range<\"filter_publication_year\", number>"));

        let temporal_query = render_operation_query_type(
            &[
                ClientParameter {
                    name: "filter_run_on".to_owned(),
                    schema: serde_json::json!({ "type": "string", "format": "date" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "filter_run_on_gte".to_owned(),
                    schema: serde_json::json!({ "type": "string", "format": "date" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "filter_run_on_lt".to_owned(),
                    schema: serde_json::json!({ "type": "string", "format": "date" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "filter_run_at".to_owned(),
                    schema: serde_json::json!({ "type": "string", "format": "time" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "filter_run_at_gt".to_owned(),
                    schema: serde_json::json!({ "type": "string", "format": "time" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
                ClientParameter {
                    name: "filter_run_at_lte".to_owned(),
                    schema: serde_json::json!({ "type": "string", "format": "time" }),
                    required: false,
                    location: ParameterLocation::Query,
                },
            ],
            &BTreeSet::new(),
        );
        assert!(temporal_query.contains("DR<\"filter_run_on\", DateInput>"));
        assert!(temporal_query.contains("DR<\"filter_run_at\", TimeInput>"));
    }

    #[test]
    fn generate_typescript_client_emits_temporal_input_aliases_without_widening_outputs() {
        let schemas = BTreeMap::from([
            (
                "Event".to_owned(),
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "starts_at": { "type": "string", "format": "date-time" }
                    },
                    "required": ["starts_at"]
                }),
            ),
            (
                "Envelope".to_owned(),
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "event": { "$ref": "#/components/schemas/Event" }
                    },
                    "required": ["event"]
                }),
            ),
        ]);

        let input_schema_aliases = compute_input_schema_aliases(&schemas);
        assert_eq!(
            input_schema_aliases,
            BTreeSet::from(["Envelope".to_owned(), "Event".to_owned()])
        );

        let types = render_types_ts(&schemas, &input_schema_aliases);
        assert!(
            types.contains(
                "import type { DateInput, DateTimeInput, TimeInput } from \"./client.ts\";"
            )
        );
        assert!(types.contains("export type Event = {"));
        assert!(types.contains("\"starts_at\": string;"));
        assert!(types.contains("export type EventInput = {"));
        assert!(types.contains("\"starts_at\": DateTimeInput;"));
        assert!(types.contains("export type EnvelopeInput = {"));
        assert!(types.contains("\"event\": EventInput;"));
    }

    #[test]
    fn generate_typescript_client_emits_multipart_upload_operations() {
        let root = test_root();
        let output = root.join("upload-client");
        generate_typescript_client(
            &fixture_path("storage_upload_api.eon"),
            Some(&output),
            false,
            &[],
            None,
            Some("/api"),
            None,
            Some(true),
        )
        .expect("client should generate");

        let operations = read_to_string(&output.join("operations.ts"));
        let types = read_to_string(&output.join("types.ts"));

        assert!(operations.contains("uploadAssetUpload"));
        assert!(operations.contains("contentType: \"multipart/form-data\""));
        assert!(operations.contains("\"file\": Blob;"));
        assert!(types.contains("export type StorageUploadResponse ="));
    }

    #[test]
    fn generate_typescript_client_emits_browser_js_when_requested() {
        let root = test_root();
        let output = root.join("blog-client-js");
        generate_typescript_client(
            &fixture_path("blog_api.eon"),
            Some(&output),
            false,
            &[],
            Some("@demo/blog-client"),
            Some("/api"),
            Some(true),
            Some(true),
        )
        .expect("client should generate");

        let package_json = read_to_string(&output.join("package.json"));
        let index_js = read_to_string(&output.join("index.js"));
        let client_js = read_to_string(&output.join("client.js"));
        let operations_js = read_to_string(&output.join("operations.js"));

        assert!(package_json.contains("\"default\": \"./index.js\""));
        assert!(package_json.contains("\"types\": \"./index.ts\""));
        assert!(index_js.contains("export * from \"./client.js\";"));
        assert!(client_js.contains("export function createClient"));
        assert!(client_js.contains("export class VsrDate"));
        assert!(client_js.contains("export class VsrTime"));
        assert!(client_js.contains("function requestNeedsCsrf(method)"));
        assert!(
            client_js
                .contains("if (requestNeedsCsrf(request.method) && resolvedConfig.getCsrfToken)")
        );
        assert!(!client_js.contains("if (body !== undefined && resolvedConfig.getCsrfToken)"));
        assert!(
            client_js.contains("if (request.requiresBearerAuth && resolvedConfig.getAccessToken)")
        );
        assert!(
            !client_js.contains("const requiresBearerAuth = request.requiresBearerAuth ?? true;")
        );
        assert!(client_js.contains("body = JSON.stringify(normalizeJsonValue(request.body));"));
        assert!(client_js.contains("bind(globalThis)"));
        assert!(operations_js.contains("export async function listPost"));
        assert!(
            operations_js.contains("const r = (p) => ({ headers: p.headers, signal: p.signal });")
        );
        assert!(operations_js.contains("...r(params)"));
        assert!(operations_js.contains("requiresBearerAuth: true"));
        assert!(!operations_js.contains("requiresBearerAuth: false"));
        assert!(!operations_js.contains("/**"));
        assert!(!operations_js.contains("import type"));
    }

    #[test]
    fn generate_typescript_client_defaults_output_next_to_service_file() {
        let root = test_root();
        let service_dir = root.join("service");
        fs::create_dir_all(&service_dir).expect("service dir should exist");
        let input = service_dir.join("todo_app.eon");
        fs::copy(fixture_path("blog_api.eon"), &input).expect("fixture should copy");

        let output = generate_typescript_client(&input, None, false, &[], None, None, None, None)
            .expect("client should generate");

        assert_eq!(output, service_dir.join("todo_app.client"));
        assert!(output.join("index.ts").exists());
    }

    #[test]
    fn generate_typescript_client_writes_dependency_free_package_json() {
        let root = test_root();
        let output = root.join("blog-client");
        generate_typescript_client(
            &fixture_path("blog_api.eon"),
            Some(&output),
            false,
            &[],
            Some("@demo/blog-client"),
            Some("/api"),
            None,
            Some(true),
        )
        .expect("client should generate");

        let package_json: Value =
            serde_json::from_str(&read_to_string(&output.join("package.json")))
                .expect("package json should parse");
        assert_eq!(package_json["name"], "@demo/blog-client");
        assert!(package_json.get("dependencies").is_none());
        assert!(package_json.get("devDependencies").is_none());
        assert!(package_json.get("peerDependencies").is_none());
    }

    #[test]
    fn generate_typescript_client_respects_without_auth() {
        let root = test_root();
        let output = root.join("blog-client-no-auth");
        generate_typescript_client(
            &fixture_path("blog_api.eon"),
            Some(&output),
            false,
            &[],
            None,
            Some("/api"),
            None,
            Some(false),
        )
        .expect("client should generate");

        let operations = read_to_string(&output.join("operations.ts"));
        assert!(!operations.contains("loginUser("));
        assert!(!operations.contains("getAuthenticatedAccount("));
        assert!(operations.contains("listPost("));
    }

    #[test]
    fn generate_typescript_client_uses_clients_config_defaults() {
        let root = test_root();
        let service_dir = root.join("service");
        fs::create_dir_all(&service_dir).expect("service dir should exist");
        let input = service_dir.join("client_api.eon");
        fs::write(
            &input,
            r#"
            module: "client_api"
            clients: {
                ts: {
                    output_dir: {
                        path: "web/src/gen/client"
                    }
                    package_name: "@demo/client-api"
                    server_url: "/edge-api"
                    emit_js: true
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        )
        .expect("service should write");

        let output = generate_typescript_client(&input, None, false, &[], None, None, None, None)
            .expect("client should generate");

        assert_eq!(output, service_dir.join("web/src/gen/client"));
        assert!(
            read_to_string(&output.join("package.json")).contains("\"name\": \"@demo/client-api\"")
        );
        assert!(
            read_to_string(&output.join("client.ts"))
                .contains("const DEFAULT_SERVER_URL = \"/edge-api\";")
        );
        assert!(output.join("index.js").exists());
    }

    #[test]
    fn generate_typescript_client_respects_clients_config_auth_and_exclusions() {
        let root = test_root();
        let service_dir = root.join("service");
        fs::create_dir_all(&service_dir).expect("service dir should exist");
        let input = service_dir.join("client_api.eon");
        fs::write(
            &input,
            r#"
            module: "client_api"
            clients: {
                ts: {
                    include_builtin_auth: false
                    exclude_tables: ["audit_log"]
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
                {
                    name: "AuditLog"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        )
        .expect("service should write");

        let output = generate_typescript_client(&input, None, false, &[], None, None, None, None)
            .expect("client should generate");
        let operations = read_to_string(&output.join("operations.ts"));

        assert!(!operations.contains("loginUser("));
        assert!(!operations.contains("listAuditLog("));
        assert!(operations.contains("listPost("));
    }

    #[test]
    fn generate_automated_typescript_client_for_build_uses_automation_config() {
        let root = test_root();
        let service_dir = root.join("service");
        fs::create_dir_all(&service_dir).expect("service dir should exist");
        let input = service_dir.join("client_api.eon");
        fs::write(
            &input,
            r#"
            module: "client_api"
            clients: {
                ts: {
                    output_dir: {
                        path: "web/src/gen/client"
                    }
                    include_builtin_auth: false
                    exclude_tables: ["audit_log"]
                    automation: {
                        on_build: true
                        self_test: true
                        self_test_report: {
                            path: "reports/client-self-test.json"
                        }
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
                {
                    name: "AuditLog"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        )
        .expect("service should write");

        let output = generate_automated_typescript_client_for_build(&input)
            .expect("automated client generation should succeed")
            .expect("automation should be enabled");

        assert_eq!(output, service_dir.join("web/src/gen/client"));
        assert!(service_dir.join("reports/client-self-test.json").exists());

        let operations = read_to_string(&output.join("operations.ts"));
        assert!(!operations.contains("loginUser("));
        assert!(!operations.contains("listAuditLog("));
        assert!(operations.contains("listPost("));
    }

    #[cfg(unix)]
    #[test]
    fn node_import_smoke_skips_for_ts_only_clients_when_node_lacks_ts_support() {
        let root = test_root();
        let output = root.join("ts-client");
        fs::create_dir_all(&output).expect("output dir should exist");
        fs::write(
            output.join("index.ts"),
            "export function createClient() { return { request() {} }; }\n",
        )
        .expect("ts client should write");

        let check = run_node_import_smoke_check(
            &output,
            &TypescriptClientSelfTestOptions {
                report_path: None,
                runtime_base_url: None,
                node_binary: Some(fake_node_binary(&root)),
                tsc_binary: None,
                insecure_tls: false,
                force: false,
            },
        )
        .expect("self-test check should run");

        assert_eq!(check.status, ClientSelfTestStatus::Skipped);
        assert!(
            check
                .details
                .contains("could not execute TypeScript modules directly")
        );
    }

    #[cfg(unix)]
    #[test]
    fn node_import_smoke_uses_mjs_wrapper_for_js_clients() {
        let root = test_root();
        let output = root.join("js-client");
        fs::create_dir_all(&output).expect("output dir should exist");
        fs::write(
            output.join("index.js"),
            "export function createClient() { return { request() {} }; }\n",
        )
        .expect("js client should write");

        let check = run_node_import_smoke_check(
            &output,
            &TypescriptClientSelfTestOptions {
                report_path: None,
                runtime_base_url: None,
                node_binary: Some(fake_node_binary(&root)),
                tsc_binary: None,
                insecure_tls: false,
                force: false,
            },
        )
        .expect("self-test check should run");

        assert_eq!(check.status, ClientSelfTestStatus::Passed);
    }

    #[test]
    fn generate_typescript_client_prefers_declared_env_overrides() {
        let root = test_root();
        let service_dir = root.join("service");
        fs::create_dir_all(&service_dir).expect("service dir should exist");
        let input = service_dir.join("client_api.eon");
        let output_env = unique_env_name("VSR_CLIENT_TS_OUTPUT");
        let package_env = unique_env_name("VSR_CLIENT_TS_PACKAGE");
        fs::write(
            &input,
            format!(
                r#"
            module: "client_api"
            clients: {{
                ts: {{
                    output_dir: {{
                        path: "web/src/gen/client"
                        env: "{output_env}"
                    }}
                    package_name: {{
                        value: "@demo/client-api"
                        env: "{package_env}"
                    }}
                }}
            }}
            resources: [
                {{
                    name: "Post"
                    fields: [{{ name: "id", type: I64 }}]
                }}
            ]
            "#
            ),
        )
        .expect("service should write");

        unsafe {
            std::env::set_var(&output_env, "env-client");
            std::env::set_var(&package_env, "@env/client-api");
        }
        let output = generate_typescript_client(&input, None, false, &[], None, None, None, None)
            .expect("client should generate");
        unsafe {
            std::env::remove_var(&output_env);
            std::env::remove_var(&package_env);
        }

        assert_eq!(output, service_dir.join("env-client"));
        assert!(
            read_to_string(&output.join("package.json")).contains("\"name\": \"@env/client-api\"")
        );
    }
}
