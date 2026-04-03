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

    println!("{}", "Generating automated TypeScript client...".cyan().bold());

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
        &render_types_ts(&document.schemas),
    )?;
    write_file(
        &output_dir.join("operations.ts"),
        &render_operations_ts(document),
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
    summary: Option<String>,
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
            summary: operation
                .get("summary")
                .and_then(Value::as_str)
                .map(str::to_owned),
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
        r#"export type QueryValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | Blob
  | Array<string | number | boolean | null | undefined>;

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
          body = JSON.stringify(request.body);
        }} else if (request.contentType === "text/plain") {{
          headers.set("content-type", "text/plain");
          body = typeof request.body === "string" ? request.body : String(request.body);
        }} else {{
          if (request.contentType) {{
            headers.set("content-type", request.contentType);
          }}
          body = request.body as BodyInit;
        }}
      }}

      if (body !== undefined && resolvedConfig.getCsrfToken) {{
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
  params?: Record<string, string | number | boolean | null | undefined>,
): string {{
  return template.replace(/\{{([^}}]+)\}}/g, (_, key: string) => {{
    const value = params?.[key];
    if (value === undefined || value === null) {{
      throw new Error(`Missing required path parameter: ${{key}}`);
    }}
    return encodeURIComponent(String(value));
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
          searchParams.append(key, stringifyQueryValue(item));
        }}
      }}
      continue;
    }}
    if (value instanceof Blob) {{
      continue;
    }}
    searchParams.append(key, stringifyQueryValue(value));
  }}
}}

function stringifyQueryValue(value: string | number | boolean): string {{
  return typeof value === "string" ? value : String(value);
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
"#
    )
}

fn render_client_js(server_url: &str) -> String {
    format!(
        r#"export class ApiError extends Error {{
  constructor(message, status, body, headers) {{
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.headers = headers;
  }}
}}

const DEFAULT_SERVER_URL = {server_url:?};

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
          body = JSON.stringify(request.body);
        }} else if (request.contentType === "text/plain") {{
          headers.set("content-type", "text/plain");
          body = typeof request.body === "string" ? request.body : String(request.body);
        }} else {{
          if (request.contentType) {{
            headers.set("content-type", request.contentType);
          }}
          body = request.body;
        }}
      }}

      if (body !== undefined && resolvedConfig.getCsrfToken) {{
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
    return encodeURIComponent(String(value));
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
          searchParams.append(key, stringifyQueryValue(item));
        }}
      }}
      continue;
    }}
    if (value instanceof Blob) {{
      continue;
    }}
    searchParams.append(key, stringifyQueryValue(value));
  }}
}}

function stringifyQueryValue(value) {{
  return typeof value === "string" ? value : String(value);
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
"#
    )
}

fn render_types_ts(schemas: &BTreeMap<String, Value>) -> String {
    let mut output = String::from("// Generated by `vsr client ts`\n\n");
    for (name, schema) in schemas {
        output.push_str(&format!(
            "export type {} = {};\n\n",
            sanitize_type_name(name),
            render_schema_type(schema, 0)
        ));
    }
    if schemas.is_empty() {
        output.push_str("export {};\n");
    }
    output
}

fn render_operations_ts(document: &ClientDocument) -> String {
    let mut output = String::from(
        "// Generated by `vsr client ts`\n\nimport type * as Schemas from \"./types.ts\";\nimport { interpolatePath, type QueryParams, type VsrClient } from \"./client.ts\";\n\n",
    );

    for operation in &document.operations {
        let request_type_name = format!("{}Request", sanitize_type_name(&operation.operation_id));
        let response_type_name = format!("{}Response", sanitize_type_name(&operation.operation_id));
        output.push_str(&format!(
            "export type {response_type_name} = {};\n",
            render_operation_response_type(&operation.response)
        ));
        output.push_str(&format!(
            "export type {request_type_name} = {};\n\n",
            render_operation_request_type(operation)
        ));

        if let Some(summary) = operation.summary.as_deref() {
            output.push_str(&format!("/** {} */\n", escape_js_doc(summary)));
        }
        let params_default = if operation_has_required_inputs(operation) {
            ""
        } else {
            " = {}"
        };
        output.push_str(&format!(
            "export async function {}(client: VsrClient, params: {}{}): Promise<{}> {{\n",
            sanitize_identifier(&operation.operation_id),
            request_type_name,
            params_default,
            response_type_name
        ));
        output.push_str(&format!(
            "  return client.request<{}>({});\n",
            response_type_name,
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
        "// Generated by `vsr client ts`\n\nimport { interpolatePath } from \"./client.js\";\n\n",
    );

    for operation in &document.operations {
        if let Some(summary) = operation.summary.as_deref() {
            output.push_str(&format!("/** {} */\n", escape_js_doc(summary)));
        }
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

fn render_operation_response_type(response: &ClientResponse) -> String {
    match &response.kind {
        ResponseKind::Json(schema) => render_schema_type_with_refs(schema, 0, RefMode::Schemas),
        ResponseKind::Text => "string".to_owned(),
        ResponseKind::Binary => "Blob".to_owned(),
        ResponseKind::Void => "void".to_owned(),
    }
}

fn render_operation_request_type(operation: &ClientOperation) -> String {
    let mut fields = Vec::new();
    if !operation.path_params.is_empty() {
        fields.push(format!(
            "\"path\": {};",
            render_parameter_object_type(&operation.path_params)
        ));
    }
    if !operation.query_params.is_empty() {
        let optional = operation.query_params.iter().all(|param| !param.required);
        fields.push(format!(
            "\"query\"{}: {};",
            if optional { "?" } else { "" },
            render_parameter_object_type(&operation.query_params)
        ));
    }
    if !operation.header_params.is_empty() {
        let optional = operation.header_params.iter().all(|param| !param.required);
        fields.push(format!(
            "\"headers\"{}: {};",
            if optional { "?" } else { "" },
            render_parameter_object_type(&operation.header_params)
        ));
    } else {
        fields.push("\"headers\"?: HeadersInit;".to_owned());
    }
    if let Some(body) = &operation.request_body {
        fields.push(format!(
            "\"body\": {};",
            render_schema_type_with_refs(&body.schema, 1, RefMode::Schemas)
        ));
    }
    fields.push("\"signal\"?: AbortSignal;".to_owned());
    render_type_literal(&fields, 0)
}

fn render_parameter_object_type(parameters: &[ClientParameter]) -> String {
    let fields = parameters
        .iter()
        .map(|parameter| {
            format!(
                "{}{}: {};",
                quoted_property_name(&parameter.name),
                if parameter.required { "" } else { "?" },
                render_schema_type_with_refs(&parameter.schema, 1, RefMode::Schemas)
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
    if !operation.header_params.is_empty() {
        fields.push("headers: params.headers".to_owned());
    } else {
        fields.push("headers: params.headers".to_owned());
    }
    if let Some(body) = &operation.request_body {
        fields.push("body: params.body".to_owned());
        if let Some(content_type) = body.content_type.as_http_header() {
            fields.push(format!("contentType: {:?}", content_type));
        } else if body.content_type == RequestContentType::Multipart {
            fields.push("contentType: \"multipart/form-data\"".to_owned());
        }
    }
    fields.push("signal: params.signal".to_owned());
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

fn render_schema_type(schema: &Value, indent_level: usize) -> String {
    render_schema_type_with_refs(schema, indent_level, RefMode::Bare)
}

#[derive(Clone, Copy)]
enum RefMode {
    Bare,
    Schemas,
}

fn render_schema_type_with_refs(schema: &Value, indent_level: usize, ref_mode: RefMode) -> String {
    let Some(schema) = schema.as_object() else {
        return "unknown".to_owned();
    };

    let mut rendered = if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let type_name = reference
            .rsplit('/')
            .next()
            .map(sanitize_type_name)
            .unwrap_or_else(|| "unknown".to_owned());
        match ref_mode {
            RefMode::Bare => type_name,
            RefMode::Schemas => format!("Schemas.{type_name}"),
        }
    } else if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        render_enum_union(values)
    } else if let Some(value) = schema.get("const") {
        render_literal_type(value)
    } else if let Some(values) = schema.get("oneOf").and_then(Value::as_array) {
        render_union(values, indent_level, "|", ref_mode)
    } else if let Some(values) = schema.get("anyOf").and_then(Value::as_array) {
        render_union(values, indent_level, "|", ref_mode)
    } else if let Some(values) = schema.get("allOf").and_then(Value::as_array) {
        render_union(values, indent_level, "&", ref_mode)
    } else if schema_type(schema) == Some("array") {
        let item_type = schema
            .get("items")
            .map(|items| render_schema_type_with_refs(items, indent_level, ref_mode))
            .unwrap_or_else(|| "unknown".to_owned());
        format!("Array<{item_type}>")
    } else if schema_type(schema) == Some("object")
        || schema.contains_key("properties")
        || schema.contains_key("additionalProperties")
    {
        render_object_schema(schema, indent_level, ref_mode)
    } else {
        match schema_type(schema) {
            Some("string") => {
                if schema.get("format").and_then(Value::as_str) == Some("binary") {
                    "Blob".to_owned()
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
) -> String {
    values
        .iter()
        .map(|value| {
            parenthesize_complex_type(&render_schema_type_with_refs(
                value,
                indent_level + 1,
                ref_mode,
            ))
        })
        .collect::<Vec<_>>()
        .join(&format!(" {separator} "))
}

fn render_object_schema(
    schema: &Map<String, Value>,
    indent_level: usize,
    ref_mode: RefMode,
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
                render_schema_type_with_refs(property_schema, indent_level + 1, ref_mode)
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
                ref_mode
            )
        )),
        _ => {}
    }

    render_type_literal(&fields, indent_level)
}

fn schema_type(schema: &Map<String, Value>) -> Option<&str> {
    schema.get("type").and_then(Value::as_str)
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

fn escape_js_doc(value: &str) -> String {
    value.replace("*/", "* /")
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
    checks.push(run_typescript_compile_check(&generated.output_dir, options)?);

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
    for field in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] {
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
            details: "Generated client source files import only relative local modules."
                .to_owned(),
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

    let module_url = file_url_string(&preferred_runtime_module_path(output_dir))?;
    let script_path = temp_self_test_script_path("import-smoke")?;
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
            details: "TypeScript compiler was not available, so `tsc -p` was skipped."
                .to_owned(),
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

    let script_path = temp_self_test_script_path("runtime-probes")?;
    fs::write(
        &script_path,
        render_runtime_probe_script(&generated.output_dir, &probes)?,
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
        let status = match check.get("status").and_then(Value::as_str).unwrap_or("failed") {
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

fn write_self_test_report(
    report: &ClientSelfTestReport,
    path: &Path,
    force: bool,
) -> Result<()> {
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
    println!("{} {}", "Self-test report:".green().bold(), report_path.display());
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
        return path
            .is_file()
            .then(|| path.to_path_buf())
            .or_else(|| Some(path.to_path_buf()));
    }

    Command::new(default_name)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|_| PathBuf::from(default_name))
}

fn temp_self_test_script_path(kind: &str) -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "vsr-client-self-test-{kind}-{}.ts",
        Uuid::new_v4()
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

fn render_runtime_probe_script(output_dir: &Path, probes: &[ClientOperation]) -> Result<String> {
    let module_url = file_url_string(&preferred_runtime_module_path(output_dir))?;
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
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;
    use uuid::Uuid;

    use super::{generate_automated_typescript_client_for_build, generate_typescript_client};

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
        assert!(types.contains("export type Post ="));
        assert!(types.contains("export type AuthTokenResponse ="));
        assert!(client.contains("export function createClient"));
        assert!(package_json.contains("\"name\": \"@demo/blog-client\""));
        assert!(tsconfig.contains("\"allowImportingTsExtensions\": true"));
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
        assert!(client_js.contains("bind(globalThis)"));
        assert!(operations_js.contains("export async function listPost"));
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
        assert!(
            service_dir
                .join("reports/client-self-test.json")
                .exists()
        );

        let operations = read_to_string(&output.join("operations.ts"));
        assert!(!operations.contains("loginUser("));
        assert!(!operations.contains("listAuditLog("));
        assert!(operations.contains("listPost("));
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
