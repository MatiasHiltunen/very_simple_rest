use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use colored::Colorize;
use rest_macro_core::auth::{
    AuthDbBackend, AuthEmailProvider, auth_management_migration_sql, auth_migration_sql,
};
use rest_macro_core::compiler::{self, DbBackend, OpenApiSpecOptions, ServiceSpec};
use rest_macro_core::database::{DatabaseEngine, sqlite_url_for_path};
use uuid::Uuid;

use crate::error::{Error, Result};

const LOCAL_DEP_PATH_ENV: &str = "VSR_LOCAL_DEP_PATH";
const REPO_GIT_URL: &str = "https://github.com/MatiasHiltunen/very_simple_rest.git";
const CARGO_BUILD_RETRY_DELAYS_MS: &[u64] = &[200, 500, 1_000];
const BUILD_ARTIFACT_DIR_SUFFIX: &str = ".bundle";

pub fn emit_server_project(
    input: &Path,
    output_dir: &Path,
    package_name: Option<String>,
    include_builtin_auth: bool,
    force: bool,
) -> Result<()> {
    let emitted =
        emit_server_project_inner(input, output_dir, package_name, include_builtin_auth, force)?;
    println!(
        "{} {}",
        "Generated server project:".green().bold(),
        emitted.project_dir.display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn build_server_binary_with_defaults(
    input: &Path,
    output: Option<&Path>,
    package_name: Option<String>,
    build_dir: Option<PathBuf>,
    include_builtin_auth: bool,
    release: bool,
    target: Option<String>,
    keep_build_dir: bool,
    force: bool,
) -> Result<PathBuf> {
    let resolved_output = resolve_binary_output_path(input, output, package_name.as_deref())?;
    build_server_binary(
        input,
        &resolved_output,
        package_name,
        build_dir,
        include_builtin_auth,
        release,
        target,
        keep_build_dir,
        force,
    )?;
    Ok(resolved_output)
}

#[allow(clippy::too_many_arguments)]
pub fn build_server_binary(
    input: &Path,
    output: &Path,
    package_name: Option<String>,
    build_dir: Option<PathBuf>,
    include_builtin_auth: bool,
    release: bool,
    target: Option<String>,
    keep_build_dir: bool,
    force: bool,
) -> Result<()> {
    if output.exists() && !force {
        return Err(Error::Config(format!(
            "output binary already exists: {} (pass --force to overwrite)",
            output.display()
        )));
    }

    let resolved_package_name = resolve_generated_package_name(input, package_name.as_deref())?;
    let build_root = match build_dir {
        Some(dir) => dir,
        None => std::env::current_dir()
            .map_err(Error::Io)?
            .join(".vsr-build")
            .join(&resolved_package_name)
            .join(Uuid::new_v4().to_string()),
    };

    let emitted =
        emit_server_project_inner(input, &build_root, package_name, include_builtin_auth, true)?;

    let target_dir = emitted.project_dir.join("target");
    let output_result = run_generated_project_build(
        &emitted.project_dir,
        &target_dir,
        release,
        target.as_deref(),
    )?;
    if !output_result.status.success() {
        let stdout = String::from_utf8_lossy(&output_result.stdout);
        let stderr = String::from_utf8_lossy(&output_result.stderr);
        return Err(Error::Unknown(format!(
            "cargo build failed for generated server project\nstdout:\n{stdout}\nstderr:\n{stderr}"
        )));
    }

    let profile_dir = if release { "release" } else { "debug" };
    let mut binary_path = target_dir;
    if let Some(target) = &target {
        binary_path = binary_path.join(target);
    }
    binary_path = binary_path
        .join(profile_dir)
        .join(binary_file_name(&emitted.package_name));

    if !binary_path.exists() {
        return Err(Error::Unknown(format!(
            "cargo build succeeded but the binary was not found at {}",
            binary_path.display()
        )));
    }

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    fs::copy(&binary_path, output).map_err(Error::Io)?;
    let artifact_dir = export_generated_runtime_artifacts(&emitted.project_dir, output, force)?;

    if !keep_build_dir {
        let _ = fs::remove_dir_all(&emitted.project_dir);
    }

    println!(
        "{} {}",
        "Built server binary:".green().bold(),
        output.display()
    );
    println!(
        "{} {}",
        "Exported runtime artifacts:".green().bold(),
        artifact_dir.display()
    );

    Ok(())
}

struct EmittedProject {
    project_dir: PathBuf,
    package_name: String,
}

fn emit_server_project_inner(
    input: &Path,
    output_dir: &Path,
    package_name: Option<String>,
    include_builtin_auth: bool,
    force: bool,
) -> Result<EmittedProject> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| Error::Config(format!("failed to load `{}`: {error}", input.display())))?;
    let backend = detect_backend(&service)?;
    ensure_auth_is_compatible(&service, include_builtin_auth)?;
    ensure_database_engine_is_compatible(&service, backend)?;

    prepare_output_dir(output_dir, force)?;

    let package_name = resolve_generated_package_name(input, package_name.as_deref())?;
    let eon_file_name = input
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("service.eon")
        .to_owned();

    let input_content = fs::read_to_string(input).map_err(Error::Io)?;
    let migration_sql = compiler::render_service_migration_sql(&service)
        .map_err(|error| Error::Config(format!("failed to render migration SQL: {error}")))?;
    let openapi_json = compiler::render_service_openapi_json(
        &service,
        &OpenApiSpecOptions::new(package_name.clone(), "1.0.0", "/api")
            .with_builtin_auth(include_builtin_auth),
    )
    .map_err(|error| Error::Config(format!("failed to render OpenAPI JSON: {error}")))?;
    let module_name = service.module_ident.to_string();

    fs::create_dir_all(output_dir.join("src")).map_err(Error::Io)?;
    fs::create_dir_all(output_dir.join("migrations")).map_err(Error::Io)?;

    write_file(
        &output_dir.join("Cargo.toml"),
        &render_cargo_toml(&package_name, &service, backend)?,
    )?;
    write_file(
        &output_dir.join("src/main.rs"),
        &render_main_rs(&module_name, &eon_file_name, include_builtin_auth),
    )?;
    write_file(&output_dir.join(&eon_file_name), &input_content)?;
    write_file(
        &output_dir.join(".env.example"),
        &render_env_example(&service, backend, include_builtin_auth),
    )?;
    write_file(
        &output_dir.join(".gitignore"),
        "target/\n.env\n*.db\n*.db-shm\n*.db-wal\n",
    )?;
    write_file(
        &output_dir.join("README.md"),
        &render_project_readme(&package_name, &service, backend, include_builtin_auth),
    )?;
    write_file(&output_dir.join("openapi.json"), &openapi_json)?;
    copy_configured_static_dirs(input, output_dir, &service)?;
    if include_builtin_auth {
        write_file(
            &output_dir.join("migrations/0000_auth.sql"),
            &auth_migration_sql(auth_backend(backend)),
        )?;
        write_file(
            &output_dir.join("migrations/0001_auth_management.sql"),
            &auth_management_migration_sql(auth_backend(backend)),
        )?;
    }
    write_file(
        &output_dir.join(if include_builtin_auth {
            "migrations/0002_service.sql"
        } else {
            "migrations/0001_service.sql"
        }),
        &migration_sql,
    )?;

    Ok(EmittedProject {
        project_dir: output_dir.to_path_buf(),
        package_name,
    })
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).map_err(Error::Io)
}

fn export_generated_runtime_artifacts(
    project_dir: &Path,
    output: &Path,
    force: bool,
) -> Result<PathBuf> {
    let artifact_dir = build_artifact_dir(output)?;
    prepare_output_dir(&artifact_dir, force)?;

    for file_name in [".env.example", "README.md", "openapi.json"] {
        let source = project_dir.join(file_name);
        if source.exists() {
            fs::copy(&source, artifact_dir.join(file_name)).map_err(Error::Io)?;
        }
    }

    for entry in fs::read_dir(project_dir).map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("eon") {
            fs::copy(&path, artifact_dir.join(entry.file_name())).map_err(Error::Io)?;
        }
    }

    let migrations = project_dir.join("migrations");
    if migrations.exists() {
        copy_dir_recursive(&migrations, &artifact_dir.join("migrations"))?;
    }

    copy_generated_static_artifacts(project_dir, &artifact_dir)?;

    Ok(artifact_dir)
}

fn copy_generated_static_artifacts(project_dir: &Path, artifact_dir: &Path) -> Result<()> {
    let Some(service) = load_emitted_service_spec(project_dir)? else {
        return Ok(());
    };

    if service.static_mounts.is_empty() {
        return Ok(());
    }

    let mut copied = Vec::<PathBuf>::new();
    let mut mounts = service.static_mounts.iter().collect::<Vec<_>>();
    mounts.sort_by_key(|mount| Path::new(&mount.source_dir).components().count());

    for mount in mounts {
        let relative_dir = PathBuf::from(&mount.source_dir);
        if copied
            .iter()
            .any(|existing| relative_dir.starts_with(existing))
        {
            continue;
        }

        let source = project_dir.join(&relative_dir);
        if !source.exists() {
            return Err(Error::Config(format!(
                "emitted project is missing copied static dir: {}",
                source.display()
            )));
        }

        copy_dir_recursive(&source, &artifact_dir.join(&relative_dir))?;
        copied.push(relative_dir);
    }

    Ok(())
}

fn load_emitted_service_spec(project_dir: &Path) -> Result<Option<ServiceSpec>> {
    let mut eon_files = fs::read_dir(project_dir)
        .map_err(Error::Io)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("eon"))
        .collect::<Vec<_>>();
    eon_files.sort();

    let Some(path) = eon_files.into_iter().next() else {
        return Ok(None);
    };

    compiler::load_service_from_path(&path)
        .map(Some)
        .map_err(|error| {
            Error::Config(format!(
                "failed to reload emitted service from `{}`: {error}",
                path.display()
            ))
        })
}

fn build_artifact_dir(output: &Path) -> Result<PathBuf> {
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            Error::Config(format!(
                "output path must end with a file name: {}",
                output.display()
            ))
        })?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!("{file_name}{BUILD_ARTIFACT_DIR_SUFFIX}")))
}

fn run_generated_project_build(
    project_dir: &Path,
    target_dir: &Path,
    release: bool,
    target: Option<&str>,
) -> Result<std::process::Output> {
    for (attempt, delay_ms) in CARGO_BUILD_RETRY_DELAYS_MS
        .iter()
        .copied()
        .chain(std::iter::once(0))
        .enumerate()
    {
        let mut command = Command::new("cargo");
        command.arg("build");
        if release {
            command.arg("--release");
        }
        if let Some(target) = target {
            command.arg("--target").arg(target);
        }
        command.current_dir(project_dir);
        command.env("CARGO_TARGET_DIR", target_dir);

        let output = command.output().map_err(Error::Io)?;
        if output.status.success() {
            return Ok(output);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if delay_ms == 0 || !is_text_file_busy_failure(&stdout, &stderr) {
            return Ok(output);
        }

        eprintln!(
            "cargo build hit a transient Text file busy error; retrying ({}/{})...",
            attempt + 1,
            CARGO_BUILD_RETRY_DELAYS_MS.len()
        );
        thread::sleep(Duration::from_millis(delay_ms));
    }

    unreachable!("retry loop always returns")
}

fn is_text_file_busy_failure(stdout: &str, stderr: &str) -> bool {
    let combined = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    combined.contains("text file busy")
        || combined.contains("os error 26")
        || combined.contains("etxtbsy")
}

fn copy_configured_static_dirs(
    input: &Path,
    output_dir: &Path,
    service: &ServiceSpec,
) -> Result<()> {
    if service.static_mounts.is_empty() {
        return Ok(());
    }

    let service_root = input.parent().unwrap_or_else(|| Path::new("."));
    let mut copied = Vec::<PathBuf>::new();
    let mut mounts = service.static_mounts.iter().collect::<Vec<_>>();
    mounts.sort_by_key(|mount| Path::new(&mount.source_dir).components().count());

    for mount in mounts {
        let relative_dir = PathBuf::from(&mount.source_dir);
        if copied
            .iter()
            .any(|existing| relative_dir.starts_with(existing))
        {
            continue;
        }

        let source = service_root.join(&relative_dir);
        let destination = output_dir.join(&relative_dir);
        copy_dir_recursive(&source, &destination)?;
        copied.push(relative_dir);
    }

    Ok(())
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination).map_err(Error::Io)?;
    for entry in fs::read_dir(source).map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let file_type = entry.file_type().map_err(Error::Io)?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());

        if file_type.is_symlink() {
            return Err(Error::Config(format!(
                "static asset path contains a symlink and cannot be emitted safely: {}",
                source_path.display()
            )));
        }

        if file_type.is_dir() {
            copy_dir_recursive(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent).map_err(Error::Io)?;
            }
            fs::copy(&source_path, &destination_path).map_err(Error::Io)?;
        }
    }
    Ok(())
}

fn prepare_output_dir(path: &Path, force: bool) -> Result<()> {
    if path.exists() {
        if !path.is_dir() {
            if force {
                fs::remove_file(path).map_err(Error::Io)?;
            } else {
                return Err(Error::Config(format!(
                    "output path exists and is not a directory: {}",
                    path.display()
                )));
            }
        }

        if path.exists() {
            let has_entries = fs::read_dir(path)
                .map_err(Error::Io)?
                .next()
                .transpose()
                .map_err(Error::Io)?
                .is_some();
            if has_entries {
                if !force {
                    return Err(Error::Config(format!(
                        "output directory already exists and is not empty: {} (pass --force to overwrite)",
                        path.display()
                    )));
                }
                fs::remove_dir_all(path).map_err(Error::Io)?;
            }
        }
    }

    fs::create_dir_all(path).map_err(Error::Io)
}

fn detect_backend(service: &ServiceSpec) -> Result<DbBackend> {
    let mut backends = service.resources.iter().map(|resource| resource.db);
    let Some(first) = backends.next() else {
        return Err(Error::Config(
            "service config must contain at least one resource".to_owned(),
        ));
    };

    if backends.any(|backend| backend != first) {
        return Err(Error::Config(
            "mixed database backends in one service are not supported by `vsr server`".to_owned(),
        ));
    }

    Ok(first)
}

fn ensure_auth_is_compatible(service: &ServiceSpec, include_builtin_auth: bool) -> Result<()> {
    if !include_builtin_auth {
        return Ok(());
    }

    if service
        .resources
        .iter()
        .any(|resource| resource.table_name == "user")
    {
        return Err(Error::Config(
            "built-in auth is enabled by default and cannot be used when the service already defines a `user` table; re-run with `--without-auth`"
                .to_owned(),
        ));
    }

    Ok(())
}

fn ensure_database_engine_is_compatible(service: &ServiceSpec, backend: DbBackend) -> Result<()> {
    match &service.database.engine {
        DatabaseEngine::Sqlx => Ok(()),
        DatabaseEngine::TursoLocal(engine) => {
            if backend != DbBackend::Sqlite {
                return Err(Error::Config(
                    "database.engine = TursoLocal requires SQLite resources".to_owned(),
                ));
            }
            let _ = engine;
            Ok(())
        }
    }
}

fn render_cargo_toml(
    package_name: &str,
    service: &ServiceSpec,
    backend: DbBackend,
) -> Result<String> {
    let dependency = render_runtime_dependency(service, backend)?;
    let backend_feature = backend_feature_name(backend);
    Ok(format!(
        r#"[package]
name = "{package_name}"
version = "0.1.0"
edition = "2024"

[workspace]

[dependencies]
actix-web = "4"
dotenv = "0.15"
env_logger = "0.11"
log = "0.4"
serde = {{ version = "1", features = ["derive"] }}
sqlx = {{ version = "0.8.3", features = ["runtime-tokio-native-tls", "any", "macros", "chrono", "{backend_feature}"] }}
{dependency}
"#
    ))
}

fn render_runtime_dependency(service: &ServiceSpec, backend: DbBackend) -> Result<String> {
    let feature_list = runtime_feature_list(service, backend);

    if let Ok(explicit_path) = std::env::var(LOCAL_DEP_PATH_ENV) {
        return Ok(format!(
            "very_simple_rest = {{ path = \"{}\", default-features = false, features = [{}] }}",
            escape_toml_path(&explicit_path),
            feature_list
        ));
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if workspace_root.join("Cargo.toml").exists() {
        let canonical = workspace_root.canonicalize().map_err(Error::Io)?;
        return Ok(format!(
            "very_simple_rest = {{ path = \"{}\", default-features = false, features = [{}] }}",
            escape_toml_path(&canonical.display().to_string()),
            feature_list
        ));
    }

    Ok(format!(
        "very_simple_rest = {{ git = \"{REPO_GIT_URL}\", default-features = false, features = [{}] }}",
        feature_list
    ))
}

fn render_main_rs(module_name: &str, eon_file_name: &str, include_builtin_auth: bool) -> String {
    let auth_config = if include_builtin_auth {
        "                    .configure(|cfg| auth::auth_routes_with_settings(cfg, server_pool.clone(), api_security.auth.clone()))\n"
    } else {
        ""
    };
    let auth_startup_check = if include_builtin_auth {
        "    very_simple_rest::auth::ensure_jwt_secret_configured()\n        .map_err(|error| std::io::Error::other(format!(\"auth configuration error: {error}\")))?;\n"
    } else {
        ""
    };

    format!(
        r##"use std::env;

use very_simple_rest::prelude::*;

rest_api_from_eon!("{eon_file_name}");

const OPENAPI_JSON: &str = include_str!("../openapi.json");

fn swagger_ui_html() -> &'static str {{
    r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>API Docs</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    body {{
      margin: 0;
      background: #101820;
    }}
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {{
      window.ui = SwaggerUIBundle({{
        url: '/openapi.json',
        dom_id: '#swagger-ui'
      }});
    }};
  </script>
</body>
</html>"#
}}

async fn openapi_spec() -> impl Responder {{
    HttpResponse::Ok()
        .content_type("application/json")
        .body(OPENAPI_JSON)
}}

async fn swagger_ui() -> impl Responder {{
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(swagger_ui_html())
}}

#[actix_web::main]
async fn main() -> std::io::Result<()> {{
    let _ = dotenv::dotenv();
    let logging = {module_name}::logging();
    logging.init_env_logger();

{auth_startup_check}    let database_config = {module_name}::database();
    let database_url = match env::var("DATABASE_URL") {{
        Ok(url) => url,
        Err(_) => {{
            very_simple_rest::core::database::prepare_database_engine(&database_config)
                .await
                .map_err(|error| std::io::Error::other(format!("database engine bootstrap failed: {{error}}")))?;
            {module_name}::default_database_url().to_owned()
        }}
    }};
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());

    let pool = very_simple_rest::db::connect_with_config(&database_url, &database_config)
        .await
        .map_err(|error| std::io::Error::other(format!("database connection failed: {{error}}")))?;

    let api_security = {module_name}::security();
    let server_pool = pool.clone();
    let server = HttpServer::new(move || {{
        let api_security = api_security.clone();
        App::new()
            .wrap(Logger::default())
            .wrap(very_simple_rest::core::security::cors_middleware(&api_security))
            .wrap(very_simple_rest::core::security::security_headers_middleware(&api_security))
            .route("/openapi.json", web::get().to(openapi_spec))
            .route("/docs", web::get().to(swagger_ui))
            .service(
                scope("/api")
{auth_config}                    .configure(|cfg| {module_name}::configure(cfg, server_pool.clone()))
            )
            .configure({module_name}::configure_static)
    }})
    .bind(&bind_addr)?;

    info!("Server listening on http://{{}}", bind_addr);
    server.run().await
}}
"##
    )
}

fn render_env_example(
    service: &ServiceSpec,
    backend: DbBackend,
    include_builtin_auth: bool,
) -> String {
    let auth_block = if include_builtin_auth {
        format!(
            "# Required when built-in auth is enabled\nJWT_SECRET=change-me\n# Or mount a secret file and set JWT_SECRET_FILE=/run/secrets/jwt_secret\n{}# Optional built-in auth bootstrap values\n# ADMIN_EMAIL=admin@example.com\n# ADMIN_PASSWORD=change-me\n# ADMIN_TENANT_ID=1\n",
            render_auth_email_env_example(service)
        )
    } else {
        "# JWT_SECRET=change-me-if-you-enable-built-in-auth\n".to_owned()
    };
    let engine_block = match &service.database.engine {
        DatabaseEngine::Sqlx => String::new(),
        DatabaseEngine::TursoLocal(engine) => {
            let encryption_block = engine
                .encryption_key_env
                .as_ref()
                .map(|var| {
                    format!(
                        "{var}=change-me-hex-key\n# Or mount a secret file and set {var}_FILE=/run/secrets/{var}\n"
                    )
                })
                .unwrap_or_default();
            format!(
                "# Local Turso bootstrap will initialize `{}` before the runtime connects.\n{}",
                engine.path, encryption_block
            )
        }
    };
    let security_block = render_security_env_example(service);
    let logging_env_var = &service.logging.filter_env;
    let logging_default_filter = &service.logging.default_filter;

    format!(
        "{}DATABASE_URL={}\nBIND_ADDR=127.0.0.1:8080\n{}{}{}={}\n",
        engine_block,
        default_database_url(service, backend),
        auth_block,
        security_block,
        logging_env_var,
        logging_default_filter
    )
}

fn render_auth_email_env_example(service: &ServiceSpec) -> String {
    let Some(email) = service.security.auth.email.as_ref() else {
        return String::new();
    };

    match &email.provider {
        AuthEmailProvider::Resend { api_key_env, .. } => format!(
            "# Built-in auth email delivery via Resend\n{api_key_env}=change-me\n# Or mount a secret file and set {api_key_env}_FILE=/run/secrets/{api_key_env}\n"
        ),
        AuthEmailProvider::Smtp { connection_url_env } => format!(
            "# Built-in auth email delivery via SMTP/lettre\n{connection_url_env}=smtp://user:password@smtp.example.com:587\n# Or mount a secret file and set {connection_url_env}_FILE=/run/secrets/{connection_url_env}\n"
        ),
    }
}

fn render_project_readme(
    package_name: &str,
    service: &ServiceSpec,
    backend: DbBackend,
    include_builtin_auth: bool,
) -> String {
    let auth_note = if include_builtin_auth {
        "The generated project includes built-in auth/account routes plus `migrations/0000_auth.sql` and `migrations/0001_auth_management.sql`. Set `JWT_SECRET` before starting the server.\n"
    } else {
        "The generated project does not include built-in auth/account routes by default.\n"
    };
    let openapi_note = if include_builtin_auth {
        "The OpenAPI document also includes the built-in auth/account routes, with `/auth/me` grouped under `Account` in Swagger.\n\n"
    } else {
        "\n"
    };
    let database_note = match &service.database.engine {
        DatabaseEngine::Sqlx => "Runtime engine: `Sqlx`.\n\n".to_owned(),
        DatabaseEngine::TursoLocal(engine) => {
            let encryption_note = engine
                .encryption_key_env
                .as_ref()
                .map(|var| {
                    format!(
                        "Local encryption is enabled. Set `{var}` to a 64-character hex key before starting the server.\n"
                    )
                })
                .unwrap_or_default();
            format!(
                "Runtime engine: `TursoLocal` bootstrapping `{}` before the runtime connects to the SQLite-compatible database file.\n{}\
\n",
                engine.path, encryption_note
            )
        }
    };
    let security_note = render_project_security_note(service);
    let logging_note = render_project_logging_note(service);

    format!(
        "# {package_name}\n\nGenerated by `vsr server emit`.\n\n\
Backend: `{}`\n\n\
{}\
{}\
{}\
{}\n\
The generated server serves `openapi.json` at `/openapi.json` and Swagger UI at `/docs`.\n\
{}\
Apply the SQL files in `migrations/` before starting the server, then run:\n\n\
```bash\n\
cp .env.example .env\n\
cargo run\n\
```\n",
        backend_feature_name(backend),
        database_note,
        logging_note,
        security_note,
        auth_note,
        openapi_note
    )
}

fn render_security_env_example(service: &ServiceSpec) -> String {
    let mut block = String::new();

    if let Some(var_name) = &service.security.cors.origins_env {
        block.push_str("# Security overrides\n");
        block.push_str(&format!(
            "# {var_name}=http://localhost:3000,http://127.0.0.1:3000\n"
        ));
    }

    if let Some(var_name) = &service.security.trusted_proxies.proxies_env {
        if block.is_empty() {
            block.push_str("# Security overrides\n");
        }
        block.push_str(&format!("# {var_name}=127.0.0.1,::1\n"));
    }

    if !block.is_empty() {
        block.push('\n');
    }

    block
}

fn render_project_security_note(service: &ServiceSpec) -> String {
    let mut features = Vec::new();

    if service.security.requests.json_max_bytes.is_some() {
        features.push("JSON request body limits");
    }
    if !service.security.cors.origins.is_empty() || service.security.cors.origins_env.is_some() {
        features.push("CORS policy");
    }
    if !service.security.trusted_proxies.proxies.is_empty()
        || service.security.trusted_proxies.proxies_env.is_some()
    {
        features.push("trusted-proxy IP resolution");
    }
    if service.security.rate_limits.login.is_some()
        || service.security.rate_limits.register.is_some()
    {
        features.push("built-in auth rate limits");
    }
    if service.security.headers != Default::default() {
        features.push("security response headers");
    }
    if service.security.auth != Default::default() {
        features.push("built-in auth JWT settings");
    }

    let mut note = String::new();
    if !features.is_empty() {
        note.push_str(&format!(
            "Compiled security defaults: {}.\n",
            features.join(", ")
        ));
    }

    let mut env_vars = Vec::new();
    if let Some(var_name) = &service.security.cors.origins_env {
        env_vars.push(var_name.as_str());
    }
    if let Some(var_name) = &service.security.trusted_proxies.proxies_env {
        env_vars.push(var_name.as_str());
    }

    if !env_vars.is_empty() {
        note.push_str(&format!(
            "Optional security env vars surfaced in `.env.example`: `{}`.\n\n",
            env_vars.join("`, `")
        ));
    } else if !note.is_empty() {
        note.push('\n');
    }

    note
}

fn render_project_logging_note(service: &ServiceSpec) -> String {
    let timestamp = match service.logging.timestamp {
        rest_macro_core::logging::LogTimestampPrecision::None => "no timestamps",
        rest_macro_core::logging::LogTimestampPrecision::Seconds => "second timestamps",
        rest_macro_core::logging::LogTimestampPrecision::Millis => "millisecond timestamps",
        rest_macro_core::logging::LogTimestampPrecision::Micros => "microsecond timestamps",
        rest_macro_core::logging::LogTimestampPrecision::Nanos => "nanosecond timestamps",
    };
    format!(
        "Compiled logging defaults: `{}` falls back to `{}` with {}.\n",
        service.logging.filter_env, service.logging.default_filter, timestamp
    )
}

fn backend_feature_name(backend: DbBackend) -> &'static str {
    match backend {
        DbBackend::Sqlite => "sqlite",
        DbBackend::Postgres => "postgres",
        DbBackend::Mysql => "mysql",
    }
}

fn auth_backend(backend: DbBackend) -> AuthDbBackend {
    match backend {
        DbBackend::Sqlite => AuthDbBackend::Sqlite,
        DbBackend::Postgres => AuthDbBackend::Postgres,
        DbBackend::Mysql => AuthDbBackend::Mysql,
    }
}

fn runtime_feature_list(service: &ServiceSpec, backend: DbBackend) -> String {
    let mut features = vec![format!("\"{}\"", backend_feature_name(backend))];
    if matches!(service.database.engine, DatabaseEngine::TursoLocal(_)) {
        features.push("\"turso-local\"".to_owned());
    }
    features.join(", ")
}

fn resolve_generated_package_name(input: &Path, package_name: Option<&str>) -> Result<String> {
    if let Some(package_name) = package_name {
        return Ok(sanitize_package_name(package_name));
    }

    if let Some(stem) = input
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.trim().is_empty())
    {
        return Ok(sanitize_package_name(stem));
    }

    let service = compiler::load_service_from_path(input)
        .map_err(|error| Error::Config(format!("failed to load `{}`: {error}", input.display())))?;
    Ok(sanitize_package_name(&service.module_ident.to_string()))
}

fn resolve_binary_output_path(
    input: &Path,
    output: Option<&Path>,
    package_name: Option<&str>,
) -> Result<PathBuf> {
    let package_name = resolve_generated_package_name(input, package_name)?;
    let binary_name = binary_file_name(&package_name);

    match output {
        Some(path) if path.exists() && path.is_dir() => Ok(path.join(binary_name)),
        Some(path) => Ok(path.to_path_buf()),
        None => Ok(std::env::current_dir()
            .map_err(Error::Io)?
            .join(binary_name)),
    }
}

fn default_database_url(service: &ServiceSpec, backend: DbBackend) -> String {
    match &service.database.engine {
        DatabaseEngine::TursoLocal(engine) => sqlite_url_for_path(&engine.path),
        DatabaseEngine::Sqlx => match backend {
            DbBackend::Sqlite => "sqlite:app.db?mode=rwc".to_owned(),
            DbBackend::Postgres => "postgres://postgres:postgres@127.0.0.1/app".to_owned(),
            DbBackend::Mysql => "mysql://root:password@127.0.0.1/app".to_owned(),
        },
    }
}

fn sanitize_package_name(value: &str) -> String {
    let mut sanitized = value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' => ch,
            'A'..='Z' => ch.to_ascii_lowercase(),
            '_' | '-' | ' ' => '-',
            _ => '-',
        })
        .collect::<String>();

    while sanitized.contains("--") {
        sanitized = sanitized.replace("--", "-");
    }

    sanitized = sanitized.trim_matches('-').to_owned();

    if sanitized.is_empty() {
        return "vsr-eon-server".to_owned();
    }

    if sanitized
        .chars()
        .next()
        .map(|ch| ch.is_ascii_digit())
        .unwrap_or(false)
    {
        format!("vsr-{sanitized}")
    } else {
        sanitized
    }
}

fn escape_toml_path(path: &str) -> String {
    path.replace('\\', "\\\\")
}

fn binary_file_name(package_name: &str) -> String {
    if cfg!(windows) {
        format!("{package_name}.exe")
    } else {
        package_name.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        binary_file_name, build_artifact_dir, build_server_binary, emit_server_project,
        export_generated_runtime_artifacts, is_text_file_busy_failure, resolve_binary_output_path,
        resolve_generated_package_name, sanitize_package_name,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn example_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
            .join(name)
    }

    fn test_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/server_tests")
            .join(Uuid::new_v4().to_string())
    }

    fn read_to_string(path: &Path) -> String {
        fs::read_to_string(path).expect("generated file should be readable")
    }

    #[test]
    fn sanitize_package_name_normalizes_values() {
        assert_eq!(
            sanitize_package_name("Commerce Bench API"),
            "commerce-bench-api"
        );
        assert_eq!(sanitize_package_name("9service"), "vsr-9service");
        assert_eq!(sanitize_package_name("___"), "vsr-eon-server");
    }

    #[test]
    fn resolve_binary_output_path_defaults_to_current_directory() {
        let resolved = resolve_binary_output_path(&fixture_path("blog_api.eon"), None, None)
            .expect("default output should resolve");
        assert_eq!(
            resolved,
            std::env::current_dir()
                .expect("current dir should resolve")
                .join(binary_file_name("blog-api"))
        );
    }

    #[test]
    fn resolve_binary_output_path_places_binary_inside_existing_directory() {
        let root = test_root();
        fs::create_dir_all(&root).expect("output directory should exist");
        let resolved = resolve_binary_output_path(&fixture_path("blog_api.eon"), Some(&root), None)
            .expect("directory output should resolve");
        assert_eq!(resolved, root.join(binary_file_name("blog-api")));
    }

    #[test]
    fn resolve_generated_package_name_defaults_to_input_file_stem() {
        let resolved = resolve_generated_package_name(&example_path("todo_app/todo_app.eon"), None)
            .expect("default package name should resolve");
        assert_eq!(resolved, "todo-app");
    }

    #[test]
    fn text_file_busy_classifier_matches_cargo_error_output() {
        assert!(is_text_file_busy_failure(
            "",
            "Caused by:\n  Text file busy (os error 26)\n",
        ));
        assert!(is_text_file_busy_failure("", "process failed with ETXTBSY"));
        assert!(!is_text_file_busy_failure(
            "",
            "error: linker `cc` not found"
        ));
    }

    #[test]
    fn emit_server_project_writes_project_files() {
        let root = test_root();
        emit_server_project(
            &fixture_path("blog_api.eon"),
            &root,
            Some("blog-server".to_owned()),
            false,
            false,
        )
        .expect("server project should emit");

        assert!(root.join("Cargo.toml").exists());
        assert!(root.join("src/main.rs").exists());
        assert!(root.join("blog_api.eon").exists());
        assert!(root.join("openapi.json").exists());
        assert!(root.join("migrations/0001_service.sql").exists());

        let main_rs = read_to_string(&root.join("src/main.rs"));
        assert!(main_rs.contains("rest_api_from_eon!(\"blog_api.eon\")"));
        assert!(main_rs.contains("blog_api::security()"));
        assert!(main_rs.contains("let database_config = blog_api::database();"));
        assert!(main_rs.contains("prepare_database_engine(&database_config)"));
        assert!(main_rs.contains("blog_api::configure"));
        assert!(main_rs.contains("cors_middleware"));
        assert!(main_rs.contains("security_headers_middleware"));
        assert!(main_rs.contains(".route(\"/openapi.json\""));
        assert!(main_rs.contains(".route(\"/docs\""));

        let cargo_toml = read_to_string(&root.join("Cargo.toml"));
        assert!(cargo_toml.contains("name = \"blog-server\""));
        assert!(cargo_toml.contains("very_simple_rest"));
        assert!(cargo_toml.contains("\"sqlite\", \"turso-local\""));

        let migration = read_to_string(&root.join("migrations/0001_service.sql"));
        assert!(migration.contains("CREATE TABLE post"));
        assert!(migration.contains("CREATE TABLE comment"));

        let env_example = read_to_string(&root.join(".env.example"));
        assert!(env_example.contains("sqlite:var/data/blog_api.db?mode=rwc"));
        assert!(env_example.contains("Local Turso bootstrap"));
        assert!(env_example.contains("TURSO_ENCRYPTION_KEY=change-me-hex-key"));

        let openapi = read_to_string(&root.join("openapi.json"));
        assert!(openapi.contains("\"openapi\": \"3.0.3\""));
        assert!(openapi.contains("\"/post\""));
        assert!(!openapi.contains("\"/auth/login\""));
    }

    #[test]
    fn emit_server_project_defaults_package_name_to_input_file_stem() {
        let root = test_root();
        emit_server_project(
            &example_path("todo_app/todo_app.eon"),
            &root,
            None,
            true,
            false,
        )
        .expect("server project should emit");

        let cargo_toml = read_to_string(&root.join("Cargo.toml"));
        assert!(cargo_toml.contains("name = \"todo-app\""));

        let main_rs = read_to_string(&root.join("src/main.rs"));
        assert!(main_rs.contains("todo_app_api::database()"));
    }

    #[test]
    fn emit_server_project_includes_auth_migration_when_requested() {
        let root = test_root();
        emit_server_project(
            &fixture_path("blog_api.eon"),
            &root,
            Some("auth-blog-server".to_owned()),
            true,
            false,
        )
        .expect("server project should emit");

        assert!(root.join("migrations/0000_auth.sql").exists());
        assert!(root.join("migrations/0001_auth_management.sql").exists());
        assert!(root.join("migrations/0002_service.sql").exists());
        let main_rs = read_to_string(&root.join("src/main.rs"));
        assert!(main_rs.contains("auth::auth_routes_with_settings"));
        assert!(main_rs.contains("ensure_jwt_secret_configured"));
        let openapi = read_to_string(&root.join("openapi.json"));
        assert!(openapi.contains("\"/auth/login\""));
        assert!(openapi.contains("\"Account\""));
        assert!(openapi.contains("\"/auth/password-reset/request\""));
    }

    #[test]
    fn emit_server_project_surfaces_security_env_overrides() {
        let root = test_root();
        emit_server_project(
            &fixture_path("security_api.eon"),
            &root,
            Some("security-server".to_owned()),
            true,
            false,
        )
        .expect("security server project should emit");

        let env_example = read_to_string(&root.join(".env.example"));
        assert!(env_example.contains("# CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000"));
        assert!(env_example.contains("# TRUSTED_PROXIES=127.0.0.1,::1"));
        assert!(env_example.contains("JWT_SECRET=change-me"));
        assert!(env_example.contains("APP_LOG=debug,sqlx=warn"));

        let readme = read_to_string(&root.join("README.md"));
        assert!(readme.contains("Compiled logging defaults:"));
        assert!(readme.contains("Compiled security defaults:"));
        assert!(readme.contains("Optional security env vars surfaced in `.env.example`"));
        assert!(env_example.contains("TURSO_ENCRYPTION_KEY=change-me-hex-key"));

        let main_rs = read_to_string(&root.join("src/main.rs"));
        assert!(main_rs.contains("let logging = security_api::logging();"));
        assert!(main_rs.contains("logging.init_env_logger();"));
    }

    #[test]
    fn emit_server_project_copies_configured_static_directories() {
        let root = test_root();
        emit_server_project(
            &fixture_path("static_site_api.eon"),
            &root,
            Some("static-site-server".to_owned()),
            false,
            false,
        )
        .expect("server project should emit");

        let main_rs = read_to_string(&root.join("src/main.rs"));
        assert!(main_rs.contains(".configure(static_site_api::configure_static)"));
        assert!(root.join("static_site/index.html").exists());
        assert!(root.join("static_site/assets/app.js").exists());
    }

    #[test]
    fn emit_server_project_wires_turso_local_bootstrap() {
        let root = test_root();
        emit_server_project(
            &fixture_path("turso_local_api.eon"),
            &root,
            Some("turso-local-server".to_owned()),
            false,
            false,
        )
        .expect("server project should emit");

        let main_rs = read_to_string(&root.join("src/main.rs"));
        assert!(main_rs.contains("let database_config = turso_local_api::database();"));
        assert!(main_rs.contains("prepare_database_engine(&database_config)"));
        assert!(main_rs.contains("turso_local_api::default_database_url()"));

        let cargo_toml = read_to_string(&root.join("Cargo.toml"));
        assert!(cargo_toml.contains("\"sqlite\", \"turso-local\""));

        let env_example = read_to_string(&root.join(".env.example"));
        assert!(env_example.contains("sqlite:var/data/turso_local.db?mode=rwc"));
        assert!(env_example.contains("Local Turso bootstrap"));
    }

    #[test]
    fn emit_server_project_wires_encrypted_turso_local_bootstrap() {
        let root = test_root();
        emit_server_project(
            &fixture_path("turso_local_encrypted_api.eon"),
            &root,
            Some("turso-local-encrypted-server".to_owned()),
            false,
            false,
        )
        .expect("encrypted turso local server project should emit");

        let main_rs = read_to_string(&root.join("src/main.rs"));
        assert!(main_rs.contains("let database_config = turso_local_encrypted_api::database();"));
        assert!(main_rs.contains("prepare_database_engine(&database_config)"));

        let cargo_toml = read_to_string(&root.join("Cargo.toml"));
        assert!(cargo_toml.contains("\"sqlite\", \"turso-local\""));

        let env_example = read_to_string(&root.join(".env.example"));
        assert!(env_example.contains("TURSO_ENCRYPTION_KEY=change-me-hex-key"));
        assert!(env_example.contains("Local Turso bootstrap"));

        let readme = read_to_string(&root.join("README.md"));
        assert!(readme.contains("Local encryption is enabled."));
        assert!(readme.contains("TURSO_ENCRYPTION_KEY"));
    }

    #[test]
    fn emit_server_project_rejects_builtin_auth_for_service_owned_user_table() {
        let root = test_root();
        let error = emit_server_project(
            &fixture_path("user_table_api.eon"),
            &root,
            Some("user-table-server".to_owned()),
            true,
            false,
        )
        .expect_err("default built-in auth should reject a service-owned user table");

        assert!(
            error.to_string().contains("re-run with `--without-auth`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn emit_server_project_can_opt_out_of_builtin_auth_for_service_owned_user_table() {
        let root = test_root();
        emit_server_project(
            &fixture_path("user_table_api.eon"),
            &root,
            Some("user-table-server".to_owned()),
            false,
            false,
        )
        .expect("service-owned user table should emit when built-in auth is disabled");

        assert!(root.join("migrations/0001_service.sql").exists());
        assert!(!root.join("migrations/0000_auth.sql").exists());

        let openapi = read_to_string(&root.join("openapi.json"));
        assert!(!openapi.contains("\"/auth/login\""));
    }

    #[test]
    fn emit_server_project_surfaces_auth_email_env_hints() {
        let root = test_root();
        emit_server_project(
            &fixture_path("auth_management_api.eon"),
            &root,
            Some("auth-management-server".to_owned()),
            true,
            false,
        )
        .expect("auth management server project should emit");

        let env_example = read_to_string(&root.join(".env.example"));
        assert!(env_example.contains("RESEND_API_KEY=change-me"));
        assert!(env_example.contains("RESEND_API_KEY_FILE=/run/secrets/RESEND_API_KEY"));

        let openapi = read_to_string(&root.join("openapi.json"));
        assert!(openapi.contains("\"/auth/account/password\""));
        assert!(openapi.contains("\"/auth/admin/users/{id}/verification\""));
    }

    #[test]
    fn export_generated_runtime_artifacts_writes_sidecar_bundle() {
        let root = test_root();
        let project_dir = root.join("project");
        let migrations = project_dir.join("migrations");
        fs::create_dir_all(&migrations).expect("project migrations directory should exist");
        fs::write(project_dir.join(".env.example"), "JWT_SECRET=change-me\n")
            .expect("env example should write");
        fs::write(project_dir.join("README.md"), "# Generated\n").expect("readme should write");
        fs::write(project_dir.join("openapi.json"), "{ }\n").expect("openapi should write");
        fs::write(
            project_dir.join("service.eon"),
            fs::read_to_string(fixture_path("blog_api.eon")).expect("fixture should read"),
        )
        .expect("eon should write");
        fs::write(migrations.join("0000_auth.sql"), "-- auth\n").expect("migration should write");
        fs::write(
            migrations.join("0001_auth_management.sql"),
            "-- auth management\n",
        )
        .expect("management migration should write");

        let output = root.join("dist/api-server");
        let artifact_dir = export_generated_runtime_artifacts(&project_dir, &output, false)
            .expect("runtime artifacts should export");

        assert_eq!(
            artifact_dir,
            build_artifact_dir(&output).expect("artifact dir should resolve")
        );
        assert!(artifact_dir.join(".env.example").exists());
        assert!(artifact_dir.join("README.md").exists());
        assert!(artifact_dir.join("openapi.json").exists());
        assert!(artifact_dir.join("service.eon").exists());
        assert!(artifact_dir.join("migrations/0000_auth.sql").exists());
        assert!(
            artifact_dir
                .join("migrations/0001_auth_management.sql")
                .exists()
        );
    }

    #[test]
    fn export_generated_runtime_artifacts_copies_static_dirs_into_bundle() {
        let root = test_root();
        let project_dir = root.join("project");
        emit_server_project(
            &fixture_path("static_site_api.eon"),
            &project_dir,
            Some("static-site-server".to_owned()),
            false,
            false,
        )
        .expect("server project should emit");

        let output = root.join("dist/static-site-server");
        let artifact_dir = export_generated_runtime_artifacts(&project_dir, &output, false)
            .expect("runtime artifacts should export");

        assert!(artifact_dir.join("static_site/index.html").exists());
        assert!(artifact_dir.join("static_site/assets/app.js").exists());
    }

    #[test]
    #[ignore]
    fn build_server_binary_compiles_generated_project() {
        let root = test_root();
        let output = root.join("dist/blog-server");
        build_server_binary(
            &fixture_path("blog_api.eon"),
            &output,
            Some("blog-server".to_owned()),
            Some(root.join("build")),
            false,
            false,
            None,
            false,
            false,
        )
        .expect("generated server binary should build");

        assert!(
            output.exists(),
            "binary should exist at {}",
            output.display()
        );
        assert!(
            output
                .parent()
                .expect("binary output should have a parent")
                .join("blog-server.bundle/.env.example")
                .exists()
        );
    }

    #[test]
    #[ignore]
    fn build_server_binary_compiles_encrypted_turso_local_generated_project() {
        let root = test_root();
        let output = root.join("dist/turso-encrypted-server");
        build_server_binary(
            &fixture_path("turso_local_encrypted_api.eon"),
            &output,
            Some("turso-encrypted-server".to_owned()),
            Some(root.join("build")),
            false,
            false,
            None,
            false,
            false,
        )
        .expect("generated encrypted turso local server binary should build");

        assert!(
            output.exists(),
            "binary should exist at {}",
            output.display()
        );
        assert!(
            output
                .parent()
                .expect("binary output should have a parent")
                .join("turso-encrypted-server.bundle/.env.example")
                .exists()
        );
    }
}
