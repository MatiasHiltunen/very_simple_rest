use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

use brotli::CompressorWriter;
use colored::Colorize;
use flate2::{Compression, write::GzEncoder};
use rest_macro_core::auth::{
    AuthDbBackend, AuthEmailProvider, auth_management_migration_sql, auth_migration_sql,
};
use rest_macro_core::compiler::{self, BuildLtoMode, DbBackend, OpenApiSpecOptions, ServiceSpec};
use rest_macro_core::database::{DatabaseEngine, sqlite_url_for_path};
use rest_macro_core::tls::{
    DEFAULT_TLS_CERT_PATH, DEFAULT_TLS_CERT_PATH_ENV, DEFAULT_TLS_KEY_PATH,
    DEFAULT_TLS_KEY_PATH_ENV,
};
use syn::{parse_str, parse2};
use uuid::Uuid;

use crate::error::{Error, Result};

const LOCAL_DEP_PATH_ENV: &str = "VSR_LOCAL_DEP_PATH";
const REPO_GIT_URL: &str = "https://github.com/MatiasHiltunen/very_simple_rest.git";
const CARGO_BUILD_RETRY_DELAYS_MS: &[u64] = &[200, 500, 1_000];
const BUILD_ARTIFACT_DIR_SUFFIX: &str = ".bundle";
const DEFAULT_BUILD_CACHE_DIR: &str = ".vsr-build";
const PRECOMPRESSED_BROTLI_SUFFIX: &str = ".br";
const PRECOMPRESSED_GZIP_SUFFIX: &str = ".gz";
const BROTLI_BUFFER_SIZE: usize = 4096;
const BROTLI_QUALITY: u32 = 5;
const BROTLI_LGWIN: u32 = 22;

struct BuildCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

pub fn emit_server_project(
    input: &Path,
    output_dir: &Path,
    package_name: Option<String>,
    include_builtin_auth: bool,
    force: bool,
) -> Result<()> {
    let emitted = emit_server_project_inner(
        input,
        output_dir,
        package_name,
        include_builtin_auth,
        force,
        false,
    )?;
    println!(
        "{} {}",
        "Generated server project:".green().bold(),
        emitted.project_dir.display()
    );
    Ok(())
}

pub fn expand_server_code(input: &Path, output: Option<&Path>, force: bool) -> Result<PathBuf> {
    let resolved_output = resolve_expanded_output_path(input, output);
    let absolute_output = if resolved_output.is_absolute() {
        resolved_output
    } else {
        std::env::current_dir()
            .map_err(Error::Io)?
            .join(resolved_output)
    };

    let absolute_input = if input.is_absolute() {
        input.to_path_buf()
    } else {
        std::env::current_dir().map_err(Error::Io)?.join(input)
    };

    prepare_output_file(&absolute_output, force)?;
    let runtime_crate = parse_str("very_simple_rest")
        .map_err(|error| Error::Unknown(format!("invalid runtime crate path: {error}")))?;
    let tokens =
        compiler::expand_service_from_path(&absolute_input, runtime_crate).map_err(|error| {
            Error::Config(format!(
                "failed to expand `{}` into generated Rust: {error}",
                absolute_input.display()
            ))
        })?;
    let parsed = parse2::<syn::File>(tokens).map_err(|error| {
        Error::Unknown(format!(
            "compiler expansion for `{}` did not parse as a Rust file: {error}",
            absolute_input.display()
        ))
    })?;
    let rendered = prettyplease::unparse(&parsed);
    write_file(&absolute_output, &rendered)?;
    println!(
        "{} {}",
        "Generated expanded server code:".green().bold(),
        absolute_output.display()
    );
    Ok(absolute_output)
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
    let build_root = resolve_build_cache_root(input, &resolved_package_name, build_dir.as_deref())?;
    let project_dir = build_root.join("project");
    let target_dir = build_root.join("target");

    println!(
        "{} {}",
        "Using build cache in".cyan().bold(),
        build_root.display()
    );
    println!(
        "{} {}",
        "Generating temporary server project in".cyan().bold(),
        project_dir.display()
    );
    let emitted = emit_server_project_inner(
        input,
        &project_dir,
        package_name,
        include_builtin_auth,
        true,
        true,
    )?;

    println!(
        "{} {}",
        "Running cargo build in".cyan().bold(),
        emitted.project_dir.display()
    );
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
    println!(
        "{} {}",
        "Copying built binary to".cyan().bold(),
        output.display()
    );
    fs::copy(&binary_path, output).map_err(Error::Io)?;
    println!(
        "{} {}",
        "Exporting runtime artifacts next to".cyan().bold(),
        output.display()
    );
    let artifact_dir = export_generated_runtime_artifacts(&emitted.project_dir, output, force)?;

    if keep_build_dir {
        println!(
            "{} {}",
            "Preserved generated project cache in".cyan().bold(),
            project_dir.display()
        );
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

pub fn clean_build_cache(build_dir: Option<&Path>) -> Result<PathBuf> {
    let cache_root = resolve_clean_build_cache_root(build_dir)?;
    if !cache_root.exists() {
        println!(
            "{} {}",
            "No build cache found at".yellow().bold(),
            cache_root.display()
        );
        return Ok(cache_root);
    }

    fs::remove_dir_all(&cache_root).map_err(Error::Io)?;
    println!(
        "{} {}",
        "Removed build cache:".green().bold(),
        cache_root.display()
    );
    Ok(cache_root)
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
    reuse_existing_project: bool,
) -> Result<EmittedProject> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| Error::Config(format!("failed to load `{}`: {error}", input.display())))?;
    let backend = detect_backend(&service)?;
    ensure_auth_is_compatible(&service, include_builtin_auth)?;
    ensure_database_engine_is_compatible(&service, backend)?;

    let package_name = resolve_generated_package_name(input, package_name.as_deref())?;
    let eon_file_name = input
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("service.eon")
        .to_owned();

    if reuse_existing_project {
        prepare_cached_project_dir(output_dir)?;
        remove_stale_root_eon_files(output_dir, &eon_file_name)?;
        remove_stale_generated_migrations(output_dir, include_builtin_auth)?;
    } else {
        prepare_output_dir(output_dir, force)?;
    }

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

    write_file_if_changed(
        &output_dir.join("Cargo.toml"),
        &render_cargo_toml(&package_name, &service, backend)?,
    )?;
    write_generated_cargo_config(output_dir, &service)?;
    let generated_include_path = format!("../{eon_file_name}");
    write_file_if_changed(
        &output_dir.join("src/generated.rs"),
        &render_generated_module(&service, &generated_include_path)?,
    )?;
    write_file_if_changed(
        &output_dir.join("src/main.rs"),
        &render_main_rs(&service, &module_name, include_builtin_auth),
    )?;
    write_file_if_changed(&output_dir.join(&eon_file_name), &input_content)?;
    write_file_if_changed(
        &output_dir.join(".env.example"),
        &render_env_example(&service, backend, include_builtin_auth),
    )?;
    write_file_if_changed(
        &output_dir.join(".gitignore"),
        "target/\n.env\ncerts/\n*.db\n*.db-shm\n*.db-wal\n",
    )?;
    write_file_if_changed(
        &output_dir.join("README.md"),
        &render_project_readme(&package_name, &service, backend, include_builtin_auth),
    )?;
    write_file_if_changed(&output_dir.join("openapi.json"), &openapi_json)?;
    copy_configured_static_dirs(input, output_dir, &service)?;
    copy_configured_tls_files(input, output_dir, &service)?;
    if include_builtin_auth {
        write_file_if_changed(
            &output_dir.join("migrations/0000_auth.sql"),
            &auth_migration_sql(auth_backend(backend)),
        )?;
        write_file_if_changed(
            &output_dir.join("migrations/0001_auth_management.sql"),
            &auth_management_migration_sql(auth_backend(backend)),
        )?;
    }
    write_file_if_changed(
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

fn write_file_if_changed(path: &Path, contents: &str) -> Result<()> {
    if matches!(fs::read_to_string(path), Ok(existing) if existing == contents) {
        return Ok(());
    }
    write_file(path, contents)
}

fn write_generated_cargo_config(output_dir: &Path, service: &ServiceSpec) -> Result<()> {
    let config_path = output_dir.join(".cargo/config.toml");
    if let Some(config) = render_cargo_config_toml(service) {
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        write_file_if_changed(&config_path, &config)?;
    } else if config_path.exists() {
        fs::remove_file(&config_path).map_err(Error::Io)?;
    }

    let cargo_dir = output_dir.join(".cargo");
    if cargo_dir.exists()
        && fs::read_dir(&cargo_dir)
            .map_err(Error::Io)?
            .next()
            .transpose()
            .map_err(Error::Io)?
            .is_none()
    {
        fs::remove_dir(&cargo_dir).map_err(Error::Io)?;
    }

    Ok(())
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

    let service = load_emitted_service_spec(project_dir)?;

    let migrations = project_dir.join("migrations");
    if migrations.exists() {
        copy_dir_recursive(&migrations, &artifact_dir.join("migrations"))?;
    }

    copy_generated_static_artifacts(project_dir, &artifact_dir, service.as_ref())?;
    generate_precompressed_static_artifacts(&artifact_dir, service.as_ref())?;
    copy_generated_tls_artifacts(project_dir, &artifact_dir, service.as_ref())?;

    Ok(artifact_dir)
}

fn copy_generated_static_artifacts(
    project_dir: &Path,
    artifact_dir: &Path,
    service: Option<&ServiceSpec>,
) -> Result<()> {
    let Some(service) = service else {
        return Ok(());
    };

    for relative_dir in configured_static_relative_dirs(service) {
        let source = project_dir.join(&relative_dir);
        if !source.exists() {
            return Err(Error::Config(format!(
                "emitted project is missing copied static dir: {}",
                source.display()
            )));
        }

        copy_dir_recursive(&source, &artifact_dir.join(&relative_dir))?;
    }

    Ok(())
}

fn generate_precompressed_static_artifacts(
    artifact_dir: &Path,
    service: Option<&ServiceSpec>,
) -> Result<()> {
    let Some(service) = service else {
        return Ok(());
    };
    if !service.runtime.compression.static_precompressed {
        return Ok(());
    }

    for relative_dir in configured_static_relative_dirs(service) {
        let static_dir = artifact_dir.join(&relative_dir);
        if !static_dir.exists() {
            return Err(Error::Config(format!(
                "runtime bundle is missing copied static dir for compression: {}",
                static_dir.display()
            )));
        }
        generate_precompressed_static_dir(&static_dir)?;
    }

    Ok(())
}

fn copy_generated_tls_artifacts(
    project_dir: &Path,
    artifact_dir: &Path,
    service: Option<&ServiceSpec>,
) -> Result<()> {
    let Some(service) = service else {
        return Ok(());
    };

    for relative_path in configured_tls_relative_paths(&service) {
        let source = project_dir.join(&relative_path);
        if !source.exists() {
            continue;
        }
        copy_runtime_file(&source, &artifact_dir.join(&relative_path), "TLS asset")?;
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

fn resolve_build_cache_root(
    input: &Path,
    package_name: &str,
    build_dir: Option<&Path>,
) -> Result<PathBuf> {
    match build_dir {
        Some(dir) => resolve_absolute_path(dir),
        None => Ok(default_build_cache_root()?
            .join(package_name)
            .join(stable_build_cache_key(input, package_name)?)),
    }
}

fn resolve_clean_build_cache_root(build_dir: Option<&Path>) -> Result<PathBuf> {
    match build_dir {
        Some(dir) => resolve_absolute_path(dir),
        None => default_build_cache_root(),
    }
}

fn default_build_cache_root() -> Result<PathBuf> {
    Ok(std::env::current_dir()
        .map_err(Error::Io)?
        .join(DEFAULT_BUILD_CACHE_DIR))
}

fn stable_build_cache_key(input: &Path, package_name: &str) -> Result<String> {
    let absolute_input = resolve_absolute_path(input)?;
    let canonical_input = absolute_input
        .canonicalize()
        .unwrap_or_else(|_| absolute_input.clone());
    Ok(Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "vsr-build-cache:{package_name}:{}",
            canonical_input.display()
        )
        .as_bytes(),
    )
    .simple()
    .to_string())
}

fn resolve_absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir().map_err(Error::Io)?.join(path))
    }
}

fn run_generated_project_build(
    project_dir: &Path,
    target_dir: &Path,
    release: bool,
    target: Option<&str>,
) -> Result<BuildCommandOutput> {
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
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command.spawn().map_err(Error::Io)?;
        let stdout = child.stdout.take().ok_or_else(|| {
            Error::Unknown("cargo build child process did not provide stdout".to_owned())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            Error::Unknown("cargo build child process did not provide stderr".to_owned())
        })?;
        let stdout_handle = thread::spawn(move || stream_build_pipe(stdout, false));
        let stderr_handle = thread::spawn(move || stream_build_pipe(stderr, true));

        let status = child.wait().map_err(Error::Io)?;
        let stdout = stdout_handle
            .join()
            .map_err(|_| Error::Unknown("cargo build stdout reader thread panicked".to_owned()))?
            .map_err(Error::Io)?;
        let stderr = stderr_handle
            .join()
            .map_err(|_| Error::Unknown("cargo build stderr reader thread panicked".to_owned()))?
            .map_err(Error::Io)?;
        let output = BuildCommandOutput {
            status,
            stdout,
            stderr,
        };
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

fn stream_build_pipe<R: std::io::Read>(reader: R, is_stderr: bool) -> std::io::Result<Vec<u8>> {
    let mut reader = BufReader::new(reader);
    let mut captured = Vec::new();

    loop {
        let mut line = Vec::new();
        let bytes_read = reader.read_until(b'\n', &mut line)?;
        if bytes_read == 0 {
            break;
        }

        captured.extend_from_slice(&line);
        if is_stderr {
            let mut stderr = std::io::stderr();
            stderr.write_all(&line)?;
            stderr.flush()?;
        } else {
            let mut stdout = std::io::stdout();
            stdout.write_all(&line)?;
            stdout.flush()?;
        }
    }

    Ok(captured)
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
    let service_root = input.parent().unwrap_or_else(|| Path::new("."));
    for relative_dir in configured_static_relative_dirs(service) {
        let source = service_root.join(&relative_dir);
        let destination = output_dir.join(&relative_dir);
        if destination.exists() {
            fs::remove_dir_all(&destination).map_err(Error::Io)?;
        }
        copy_dir_recursive(&source, &destination)?;
    }

    Ok(())
}

fn configured_static_relative_dirs(service: &ServiceSpec) -> Vec<PathBuf> {
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
        copied.push(relative_dir);
    }

    copied
}

fn copy_configured_tls_files(input: &Path, output_dir: &Path, service: &ServiceSpec) -> Result<()> {
    let service_root = input.parent().unwrap_or_else(|| Path::new("."));

    for relative_path in configured_tls_relative_paths(service) {
        let source = service_root.join(&relative_path);
        if !source.exists() {
            continue;
        }
        copy_runtime_file(&source, &output_dir.join(&relative_path), "TLS asset")?;
    }

    Ok(())
}

fn configured_tls_relative_paths(service: &ServiceSpec) -> Vec<PathBuf> {
    let mut paths = Vec::<PathBuf>::new();

    for path in [
        service.tls.cert_path.as_deref(),
        service.tls.key_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let candidate = Path::new(path);
        if candidate.is_absolute() {
            continue;
        }

        let relative = candidate.to_path_buf();
        if !paths.iter().any(|existing| existing == &relative) {
            paths.push(relative);
        }
    }

    paths
}

fn copy_runtime_file(source: &Path, destination: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(source).map_err(Error::Io)?;
    if metadata.file_type().is_symlink() {
        return Err(Error::Config(format!(
            "{label} path contains a symlink and cannot be emitted safely: {}",
            source.display()
        )));
    }
    if !metadata.is_file() {
        return Err(Error::Config(format!(
            "{label} path must be a regular file: {}",
            source.display()
        )));
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    fs::copy(source, destination).map_err(Error::Io)?;
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

fn generate_precompressed_static_dir(source: &Path) -> Result<()> {
    for entry in fs::read_dir(source).map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let file_type = entry.file_type().map_err(Error::Io)?;
        let path = entry.path();

        if file_type.is_symlink() {
            return Err(Error::Config(format!(
                "static asset path contains a symlink and cannot be emitted safely: {}",
                path.display()
            )));
        }

        if file_type.is_dir() {
            generate_precompressed_static_dir(&path)?;
        } else if file_type.is_file() {
            generate_precompressed_companions(&path)?;
        }
    }

    Ok(())
}

fn generate_precompressed_companions(path: &Path) -> Result<()> {
    if !is_precompressible_static_asset(path) {
        return Ok(());
    }

    let contents = fs::read(path).map_err(Error::Io)?;
    write_precompressed_companion_if_missing(
        path,
        PRECOMPRESSED_GZIP_SUFFIX,
        gzip_bytes(&contents)?,
    )?;
    write_precompressed_companion_if_missing(
        path,
        PRECOMPRESSED_BROTLI_SUFFIX,
        brotli_bytes(&contents)?,
    )?;
    Ok(())
}

fn write_precompressed_companion_if_missing(
    path: &Path,
    suffix: &str,
    compressed: Vec<u8>,
) -> Result<()> {
    let companion = precompressed_path(path, suffix);
    if companion.exists() {
        return Ok(());
    }
    fs::write(companion, compressed).map_err(Error::Io)
}

fn precompressed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut companion = path.as_os_str().to_os_string();
    companion.push(suffix);
    PathBuf::from(companion)
}

fn is_precompressible_static_asset(path: &Path) -> bool {
    let Some(extension) = path.extension().and_then(|ext| ext.to_str()) else {
        return false;
    };

    matches!(
        extension.to_ascii_lowercase().as_str(),
        "html"
            | "htm"
            | "css"
            | "js"
            | "mjs"
            | "cjs"
            | "json"
            | "svg"
            | "txt"
            | "xml"
            | "map"
            | "webmanifest"
            | "wasm"
    )
}

fn gzip_bytes(contents: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(contents).map_err(Error::Io)?;
    encoder.finish().map_err(Error::Io)
}

fn brotli_bytes(contents: &[u8]) -> Result<Vec<u8>> {
    let mut compressed = Vec::new();
    {
        let mut writer = CompressorWriter::new(
            &mut compressed,
            BROTLI_BUFFER_SIZE,
            BROTLI_QUALITY,
            BROTLI_LGWIN,
        );
        writer.write_all(contents).map_err(Error::Io)?;
        writer.flush().map_err(Error::Io)?;
    }
    Ok(compressed)
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

fn prepare_cached_project_dir(path: &Path) -> Result<()> {
    if path.exists() && !path.is_dir() {
        fs::remove_file(path).map_err(Error::Io)?;
    }
    fs::create_dir_all(path.join("src")).map_err(Error::Io)?;
    fs::create_dir_all(path.join("migrations")).map_err(Error::Io)?;
    Ok(())
}

fn remove_stale_root_eon_files(path: &Path, current_name: &str) -> Result<()> {
    for entry in fs::read_dir(path).map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let entry_path = entry.path();
        if entry_path.extension().and_then(|ext| ext.to_str()) != Some("eon") {
            continue;
        }
        let file_name = entry.file_name();
        if file_name.to_string_lossy() == current_name {
            continue;
        }
        fs::remove_file(entry_path).map_err(Error::Io)?;
    }
    Ok(())
}

fn remove_stale_generated_migrations(path: &Path, include_builtin_auth: bool) -> Result<()> {
    let migrations_dir = path.join("migrations");
    if !migrations_dir.exists() {
        return Ok(());
    }

    let managed_paths = [
        "0000_auth.sql",
        "0001_auth_management.sql",
        "0001_service.sql",
        "0002_service.sql",
    ];
    let retained = if include_builtin_auth {
        [
            "0000_auth.sql",
            "0001_auth_management.sql",
            "0002_service.sql",
        ]
        .into_iter()
        .collect::<Vec<_>>()
    } else {
        ["0001_service.sql"].into_iter().collect::<Vec<_>>()
    };

    for file_name in managed_paths {
        if retained.contains(&file_name) {
            continue;
        }
        let file_path = migrations_dir.join(file_name);
        if file_path.exists() {
            fs::remove_file(file_path).map_err(Error::Io)?;
        }
    }

    Ok(())
}

fn prepare_output_file(path: &Path, force: bool) -> Result<()> {
    if path.exists() {
        if path.is_dir() {
            return Err(Error::Config(format!(
                "output path exists and is a directory: {}",
                path.display()
            )));
        }
        if !force {
            return Err(Error::Config(format!(
                "output file already exists: {} (pass --force to overwrite)",
                path.display()
            )));
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(Error::Io)?;
    }

    Ok(())
}

fn resolve_expanded_output_path(input: &Path, output: Option<&Path>) -> PathBuf {
    match output {
        Some(path) => path.to_path_buf(),
        None => {
            let parent = input.parent().unwrap_or_else(|| Path::new("."));
            let stem = input
                .file_stem()
                .and_then(|value| value.to_str())
                .filter(|value| !value.is_empty())
                .unwrap_or("service");
            parent.join(format!("{stem}.expanded.rs"))
        }
    }
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
    let actix_web_dependency = if service.tls.is_enabled() {
        "actix-web = { version = \"4\", features = [\"rustls-0_23\"] }"
    } else {
        "actix-web = \"4\""
    };
    let release_profile = render_release_profile_toml(service);
    Ok(format!(
        r#"[package]
name = "{package_name}"
version = "0.1.0"
edition = "2024"

[workspace]

[dependencies]
{actix_web_dependency}
dotenv = "0.15"
serde = {{ version = "1", features = ["derive"] }}
{dependency}
{release_profile}
"#
    ))
}

fn render_release_profile_toml(service: &ServiceSpec) -> String {
    let release = &service.build.release;
    if release.lto.is_none() && release.codegen_units.is_none() && !release.strip_debug_symbols {
        return String::new();
    }

    let mut profile = String::from("\n[profile.release]\n");
    if let Some(lto) = release.lto {
        let value = match lto {
            BuildLtoMode::Thin => "thin",
            BuildLtoMode::Fat => "fat",
        };
        profile.push_str(&format!("lto = \"{value}\"\n"));
    }
    if let Some(codegen_units) = release.codegen_units {
        profile.push_str(&format!("codegen-units = {codegen_units}\n"));
    }
    if release.strip_debug_symbols {
        profile.push_str("strip = \"debuginfo\"\n");
    }
    profile
}

fn render_cargo_config_toml(service: &ServiceSpec) -> Option<String> {
    if !service.build.target_cpu_native {
        return None;
    }

    Some(
        r#"[build]
rustflags = ["-C", "target-cpu=native"]
"#
        .to_owned(),
    )
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

fn render_main_rs(service: &ServiceSpec, module_name: &str, include_builtin_auth: bool) -> String {
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
    let bind_addr_default = default_bind_addr(service);
    let tls_setup = if service.tls.is_enabled() {
        format!(
            "    let tls_base_dir = bundle_dir\n        .clone()\n        .or_else(|| env::current_dir().ok())\n        .unwrap_or_else(|| PathBuf::from(\".\"));\n    let tls_config = generated::{module_name}::tls();\n    let rustls_config = very_simple_rest::core::tls::load_rustls_server_config(&tls_config, &tls_base_dir)\n        .map_err(|error| std::io::Error::other(format!(\"TLS configuration error: {{error}}\")))?;\n"
        )
    } else {
        String::new()
    };
    let server_bind = if service.tls.is_enabled() {
        "    let server = server.bind_rustls_0_23(&bind_addr, rustls_config)?;\n\n    info!(\"Server listening on https://{}\", bind_addr);\n"
    } else {
        "    let server = server.bind(&bind_addr)?;\n\n    info!(\"Server listening on http://{}\", bind_addr);\n"
    };

    format!(
        r##"use std::env;
use std::path::PathBuf;

use very_simple_rest::prelude::*;

mod generated;

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
    let logging = generated::{module_name}::logging();
    logging.init_env_logger();

{auth_startup_check}    let current_exe = env::current_exe().ok();
    let bundle_dir = current_exe
        .as_ref()
        .map(|path| path.with_extension("bundle"))
        .filter(|dir| dir.is_dir());
    let database_base_dir = bundle_dir
        .as_ref()
        .and_then(|_| current_exe.as_ref().and_then(|path| path.parent().map(|dir| dir.to_path_buf())))
        .or_else(|| env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let database_config = very_simple_rest::core::database::resolve_database_config(
        &generated::{module_name}::database(),
        &database_base_dir,
    );
    let default_database_url = very_simple_rest::core::database::resolve_database_url(
        generated::{module_name}::default_database_url(),
        &database_base_dir,
    );
    let database_url = match env::var("DATABASE_URL") {{
        Ok(url) => url,
        Err(_) => {{
            very_simple_rest::core::database::prepare_database_engine(&database_config)
                .await
                .map_err(|error| std::io::Error::other(format!("database engine bootstrap failed: {{error}}")))?;
            default_database_url
        }}
    }};
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "{bind_addr_default}".to_owned());

    let pool = very_simple_rest::db::connect_with_config(&database_url, &database_config)
        .await
        .map_err(|error| std::io::Error::other(format!("database connection failed: {{error}}")))?;

{tls_setup}    let api_runtime = generated::{module_name}::runtime();
    let api_security = generated::{module_name}::security();
    let server_pool = pool.clone();
    let server = HttpServer::new(move || {{
        let api_runtime = api_runtime.clone();
        let api_security = api_security.clone();
        App::new()
            .wrap(Logger::default())
            .wrap(very_simple_rest::core::runtime::compression_middleware(&api_runtime))
            .wrap(very_simple_rest::core::security::cors_middleware(&api_security))
            .wrap(very_simple_rest::core::security::security_headers_middleware(&api_security))
            .route("/openapi.json", web::get().to(openapi_spec))
            .route("/docs", web::get().to(swagger_ui))
            .service(
                scope("/api")
{auth_config}                    .configure(|cfg| generated::{module_name}::configure(cfg, server_pool.clone()))
            )
            .configure(generated::{module_name}::configure_static)
    }});
{server_bind}    server.run().await
}}
"##
    )
}

fn render_generated_module(service: &ServiceSpec, include_path: &str) -> Result<String> {
    let runtime_crate = parse_str("very_simple_rest")
        .map_err(|error| Error::Unknown(format!("invalid runtime crate path: {error}")))?;
    let tokens = compiler::expand_service(service, runtime_crate, include_path)
        .map_err(|error| Error::Config(format!("failed to expand service module: {error}")))?;
    let parsed = parse2::<syn::File>(tokens).map_err(|error| {
        Error::Unknown(format!(
            "compiler expansion did not parse as a Rust file: {error}"
        ))
    })?;
    Ok(prettyplease::unparse(&parsed))
}

fn default_bind_addr(service: &ServiceSpec) -> &'static str {
    if service.tls.is_enabled() {
        "127.0.0.1:8443"
    } else {
        "127.0.0.1:8080"
    }
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
    let tls_block = render_tls_env_example(service);
    let security_block = render_security_env_example(service);
    let logging_env_var = &service.logging.filter_env;
    let logging_default_filter = &service.logging.default_filter;

    format!(
        "{}DATABASE_URL={}\nBIND_ADDR={}\n{}{}{}{}={}\n",
        engine_block,
        default_database_url(service, backend),
        default_bind_addr(service),
        tls_block,
        auth_block,
        security_block,
        logging_env_var,
        logging_default_filter
    )
}

fn render_tls_env_example(service: &ServiceSpec) -> String {
    if !service.tls.is_enabled() {
        return String::new();
    }

    let cert_path = service
        .tls
        .cert_path
        .as_deref()
        .unwrap_or(DEFAULT_TLS_CERT_PATH);
    let key_path = service
        .tls
        .key_path
        .as_deref()
        .unwrap_or(DEFAULT_TLS_KEY_PATH);
    let cert_path_env = service
        .tls
        .cert_path_env
        .as_deref()
        .unwrap_or(DEFAULT_TLS_CERT_PATH_ENV);
    let key_path_env = service
        .tls
        .key_path_env
        .as_deref()
        .unwrap_or(DEFAULT_TLS_KEY_PATH_ENV);

    format!(
        "# Rustls TLS is enabled for HTTPS + HTTP/2\n# Generate local certs with `vsr tls self-signed`\n# {cert_path_env}={cert_path}\n# {key_path_env}={key_path}\n"
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
    let tls_note = render_project_tls_note(service);
    let build_note = render_project_build_note(service);
    let security_note = render_project_security_note(service);
    let logging_note = render_project_logging_note(service);
    let run_hint = if service.tls.is_enabled() {
        "cargo run\n# Then open https://127.0.0.1:8443\n"
    } else {
        "cargo run\n# Then open http://127.0.0.1:8080\n"
    };

    format!(
        "# {package_name}\n\nGenerated by `vsr server emit`.\n\n\
Backend: `{}`\n\n\
{}\
{}\
{}\
{}\
{}\
{}\n\
The generated server serves `openapi.json` at `/openapi.json` and Swagger UI at `/docs`.\n\
{}\
Apply the SQL files in `migrations/` before starting the server, then run:\n\n\
```bash\n\
cp .env.example .env\n\
{run_hint}```\n",
        backend_feature_name(backend),
        database_note,
        tls_note,
        build_note,
        logging_note,
        security_note,
        auth_note,
        openapi_note
    )
}

fn render_project_tls_note(service: &ServiceSpec) -> String {
    if !service.tls.is_enabled() {
        return String::new();
    }

    let cert_path = service
        .tls
        .cert_path
        .as_deref()
        .unwrap_or(DEFAULT_TLS_CERT_PATH);
    let key_path = service
        .tls
        .key_path
        .as_deref()
        .unwrap_or(DEFAULT_TLS_KEY_PATH);
    let cert_path_env = service
        .tls
        .cert_path_env
        .as_deref()
        .unwrap_or(DEFAULT_TLS_CERT_PATH_ENV);
    let key_path_env = service
        .tls
        .key_path_env
        .as_deref()
        .unwrap_or(DEFAULT_TLS_KEY_PATH_ENV);

    format!(
        "Transport: Rustls TLS is enabled for HTTPS + HTTP/2.\nCompiled certificate defaults: `{cert_path}` and `{key_path}`.\nOverride them with `{cert_path_env}` and `{key_path_env}`, or run `vsr tls self-signed` to generate local certs.\n"
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

fn render_project_build_note(service: &ServiceSpec) -> String {
    let mut features = Vec::new();

    if let Some(lto) = service.build.release.lto {
        let label = match lto {
            BuildLtoMode::Thin => "thin LTO",
            BuildLtoMode::Fat => "fat LTO",
        };
        features.push(label.to_owned());
    }
    if let Some(codegen_units) = service.build.release.codegen_units {
        features.push(format!("codegen-units = {codegen_units}"));
    }
    if service.build.release.strip_debug_symbols {
        features.push("strip debug symbols".to_owned());
    }

    let mut note = String::new();
    if !features.is_empty() {
        note.push_str(&format!(
            "Compiled release build defaults: {}.\n",
            features.join(", ")
        ));
    }
    if service.build.target_cpu_native {
        note.push_str(
            "Compiled build target defaults: local `target-cpu=native` is enabled through `.cargo/config.toml`; use it only when building and running on the same machine class.\n",
        );
    }
    if !note.is_empty() {
        note.push('\n');
    }

    note
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
        binary_file_name, build_artifact_dir, build_server_binary, clean_build_cache,
        emit_server_project, expand_server_code, export_generated_runtime_artifacts,
        is_text_file_busy_failure, resolve_binary_output_path, resolve_build_cache_root,
        resolve_expanded_output_path, resolve_generated_package_name, sanitize_package_name,
    };
    use crate::commands::db::database_url_from_service_config;
    use crate::commands::setup::run_setup;
    use crate::commands::tls::generate_self_signed_certificate;
    use brotli::Decompressor;
    use flate2::read::GzDecoder;
    use reqwest::blocking::Client;
    use serde_json::{Value, json};
    use std::fs;
    use std::io::Read;
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
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

    fn read_gzip_to_string(path: &Path) -> String {
        let bytes = fs::read(path).expect("gzip file should be readable");
        let mut decoder = GzDecoder::new(&bytes[..]);
        let mut decoded = String::new();
        decoder
            .read_to_string(&mut decoded)
            .expect("gzip file should decode");
        decoded
    }

    fn read_brotli_to_string(path: &Path) -> String {
        let bytes = fs::read(path).expect("brotli file should be readable");
        let mut decoder = Decompressor::new(&bytes[..], 4096);
        let mut decoded = String::new();
        decoder
            .read_to_string(&mut decoded)
            .expect("brotli file should decode");
        decoded
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn capture_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = fs::read_dir(dir)
            .expect("capture dir should exist")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .collect::<Vec<_>>();
        files.sort();
        files
    }

    fn extract_token_from_text(text: &str) -> String {
        let start = text
            .find("token=")
            .expect("email should contain a token parameter")
            + "token=".len();
        text[start..]
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
            .collect()
    }

    fn extract_url_from_text(text: &str) -> String {
        let start = text
            .find("http://")
            .or_else(|| text.find("https://"))
            .expect("email should contain an absolute URL");
        text[start..]
            .lines()
            .next()
            .expect("email URL line should exist")
            .trim()
            .to_owned()
    }

    fn path_and_query_from_url(url: &str) -> String {
        let authority_start = url.find("://").map(|index| index + 3).unwrap_or(0);
        let path_start = url[authority_start..]
            .find('/')
            .map(|index| authority_start + index);
        match path_start {
            Some(index) => url[index..].to_owned(),
            None => "/".to_owned(),
        }
    }

    fn token_from_capture(path: &Path) -> String {
        let body = read_to_string(path);
        let payload: Value = serde_json::from_str(&body).expect("capture file should be JSON");
        let text_body = payload
            .get("text_body")
            .and_then(Value::as_str)
            .expect("capture payload should contain text_body");
        extract_token_from_text(text_body)
    }

    fn url_from_capture(path: &Path) -> String {
        let body = read_to_string(path);
        let payload: Value = serde_json::from_str(&body).expect("capture file should be JSON");
        let text_body = payload
            .get("text_body")
            .and_then(Value::as_str)
            .expect("capture payload should contain text_body");
        extract_url_from_text(text_body)
    }

    fn free_bind_addr() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral port should bind");
        let addr = listener
            .local_addr()
            .expect("listener address should resolve");
        drop(listener);
        format!("127.0.0.1:{}", addr.port())
    }

    fn wait_for_http_ready(client: &Client, url: &str, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        let mut last_error = None;

        while Instant::now() < deadline {
            match client.get(url).send() {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response) => {
                    last_error = Some(format!("server responded with {}", response.status()));
                }
                Err(error) => {
                    last_error = Some(error.to_string());
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        Err(last_error.unwrap_or_else(|| "server never became ready".to_owned()))
    }

    fn wait_for_capture_count(dir: &Path, expected: usize, timeout: Duration) -> Vec<PathBuf> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let files = capture_files(dir);
            if files.len() >= expected {
                return files;
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        panic!(
            "expected at least {expected} captured emails in {}, found {}",
            dir.display(),
            capture_files(dir).len()
        );
    }

    struct SpawnedBinary {
        child: Child,
        stdout_log: PathBuf,
        stderr_log: PathBuf,
    }

    impl SpawnedBinary {
        fn new(child: Child, stdout_log: PathBuf, stderr_log: PathBuf) -> Self {
            Self {
                child,
                stdout_log,
                stderr_log,
            }
        }

        fn logs(&self) -> String {
            let stdout = fs::read_to_string(&self.stdout_log).unwrap_or_default();
            let stderr = fs::read_to_string(&self.stderr_log).unwrap_or_default();
            format!(
                "stdout:\n{stdout}\n\nstderr:\n{stderr}\nlog files:\n- {}\n- {}",
                self.stdout_log.display(),
                self.stderr_log.display()
            )
        }
    }

    impl Drop for SpawnedBinary {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
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
    fn resolve_build_cache_root_is_stable_for_same_service_and_package() {
        let input = fixture_path("blog_api.eon");
        let first = resolve_build_cache_root(&input, "blog-api", None)
            .expect("build cache root should resolve");
        let second = resolve_build_cache_root(&input, "blog-api", None)
            .expect("build cache root should resolve");

        assert_eq!(first, second);
        assert!(
            first.starts_with(
                std::env::current_dir()
                    .expect("current dir should resolve")
                    .join(".vsr-build")
                    .join("blog-api")
            )
        );
    }

    #[test]
    fn clean_build_cache_removes_explicit_cache_dir() {
        let root = test_root().join("build-cache");
        fs::create_dir_all(root.join("project")).expect("cache project dir should be created");
        fs::create_dir_all(root.join("target")).expect("cache target dir should be created");
        fs::write(
            root.join("project/Cargo.toml"),
            "[package]\nname = \"demo\"\n",
        )
        .expect("cache project file should be created");

        let removed = clean_build_cache(Some(&root)).expect("build cache should be removed");
        assert_eq!(removed, root);
        assert!(!removed.exists(), "cache root should be removed");
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
        assert!(root.join("src/generated.rs").exists());
        assert!(root.join("blog_api.eon").exists());
        assert!(root.join("openapi.json").exists());
        assert!(root.join("migrations/0001_service.sql").exists());

        let main_rs = read_to_string(&root.join("src/main.rs"));
        assert!(main_rs.contains("mod generated;"));
        assert!(!main_rs.contains("rest_api_from_eon!("));
        assert!(main_rs.contains("generated::blog_api::security()"));
        assert!(main_rs.contains("generated::blog_api::runtime()"));
        assert!(main_rs.contains("resolve_database_config("));
        assert!(main_rs.contains("&generated::blog_api::database()"));
        assert!(main_rs.contains("resolve_database_url("));
        assert!(main_rs.contains("prepare_database_engine(&database_config)"));
        assert!(main_rs.contains("generated::blog_api::configure"));
        assert!(main_rs.contains("compression_middleware"));
        assert!(main_rs.contains("cors_middleware"));
        assert!(main_rs.contains("security_headers_middleware"));
        assert!(main_rs.contains(".route(\"/openapi.json\""));
        assert!(main_rs.contains(".route(\"/docs\""));

        let generated = read_to_string(&root.join("src/generated.rs"));
        assert!(generated.contains("pub mod blog_api"));
        assert!(generated.contains("include_str!(\"../blog_api.eon\")"));

        let cargo_toml = read_to_string(&root.join("Cargo.toml"));
        assert!(cargo_toml.contains("name = \"blog-server\""));
        assert!(cargo_toml.contains("very_simple_rest"));
        assert!(cargo_toml.contains("\"sqlite\", \"turso-local\""));
        assert!(!cargo_toml.contains("\"macros\""));

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
    fn expand_server_code_writes_direct_compiler_output() {
        let output = test_root().join("expanded.rs");
        expand_server_code(&fixture_path("blog_api.eon"), Some(&output), false)
            .expect("server expansion should succeed");

        let expanded = read_to_string(&output);
        assert!(expanded.contains("pub mod blog_api"));
        assert!(expanded.contains("include_str!"));
        assert!(expanded.contains("pub fn configure"));
    }

    #[test]
    fn expand_server_code_rejects_existing_output_without_force() {
        let output = test_root().join("expanded.rs");
        fs::create_dir_all(output.parent().expect("output should have a parent"))
            .expect("output parent should be creatable");
        fs::write(&output, "// existing").expect("existing output file should be writable");

        let error = expand_server_code(&fixture_path("blog_api.eon"), Some(&output), false)
            .expect_err("expansion should reject existing files without --force");
        assert!(
            error.to_string().contains("output file already exists"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn expand_server_code_defaults_output_next_to_input() {
        let root = test_root();
        fs::create_dir_all(&root).expect("test root should be creatable");
        let input = root.join("demo-api.eon");
        fs::copy(fixture_path("blog_api.eon"), &input).expect("fixture should copy");

        let output =
            expand_server_code(&input, None, false).expect("default expansion should work");
        assert_eq!(output, root.join("demo-api.expanded.rs"));
        assert!(output.exists(), "default output file should exist");
    }

    #[test]
    fn resolve_expanded_output_path_defaults_to_stem_expanded_rs() {
        let input = Path::new("configs/api.eon");
        assert_eq!(
            resolve_expanded_output_path(input, None),
            PathBuf::from("configs/api.expanded.rs")
        );
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
        assert!(main_rs.contains("&generated::todo_app_api::database()"));
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
        assert!(main_rs.contains("let logging = generated::security_api::logging();"));
        assert!(main_rs.contains("logging.init_env_logger();"));
    }

    #[test]
    fn emit_server_project_wires_rustls_tls_when_configured() {
        let root = test_root();
        emit_server_project(
            &fixture_path("tls_api.eon"),
            &root,
            Some("tls-server".to_owned()),
            false,
            false,
        )
        .expect("tls-enabled server project should emit");

        let main_rs = read_to_string(&root.join("src/main.rs"));
        assert!(main_rs.contains("let tls_config = generated::tls_api::tls();"));
        assert!(main_rs.contains("load_rustls_server_config(&tls_config, &tls_base_dir)"));
        assert!(main_rs.contains("bind_rustls_0_23"));
        assert!(main_rs.contains("Server listening on https://"));

        let cargo_toml = read_to_string(&root.join("Cargo.toml"));
        assert!(
            cargo_toml.contains("actix-web = { version = \"4\", features = [\"rustls-0_23\"] }")
        );

        let env_example = read_to_string(&root.join(".env.example"));
        assert!(env_example.contains("BIND_ADDR=127.0.0.1:8443"));
        assert!(env_example.contains("# TLS_CERT_PATH=certs/dev-cert.pem"));
        assert!(env_example.contains("# TLS_KEY_PATH=certs/dev-key.pem"));

        let readme = read_to_string(&root.join("README.md"));
        assert!(readme.contains("Rustls TLS is enabled"));
        assert!(readme.contains("vsr tls self-signed"));
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
        assert!(main_rs.contains(".configure(generated::static_site_api::configure_static)"));
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
        assert!(main_rs.contains("&generated::turso_local_api::database()"));
        assert!(main_rs.contains("prepare_database_engine(&database_config)"));
        assert!(main_rs.contains("generated::turso_local_api::default_database_url()"));

        let cargo_toml = read_to_string(&root.join("Cargo.toml"));
        assert!(cargo_toml.contains("\"sqlite\", \"turso-local\""));

        let env_example = read_to_string(&root.join(".env.example"));
        assert!(env_example.contains("sqlite:var/data/turso_local.db?mode=rwc"));
        assert!(env_example.contains("Local Turso bootstrap"));
    }

    #[test]
    fn emit_server_project_wires_build_profile_overrides_from_eon() {
        let root = test_root();
        emit_server_project(
            &fixture_path("build_config_api.eon"),
            &root,
            Some("build-config-server".to_owned()),
            false,
            false,
        )
        .expect("build-config server project should emit");

        let cargo_toml = read_to_string(&root.join("Cargo.toml"));
        assert!(cargo_toml.contains("[profile.release]"));
        assert!(cargo_toml.contains("lto = \"thin\""));
        assert!(cargo_toml.contains("codegen-units = 1"));
        assert!(cargo_toml.contains("strip = \"debuginfo\""));

        let cargo_config = read_to_string(&root.join(".cargo/config.toml"));
        assert!(cargo_config.contains("target-cpu=native"));

        let readme = read_to_string(&root.join("README.md"));
        assert!(readme.contains(
            "Compiled release build defaults: thin LTO, codegen-units = 1, strip debug symbols."
        ));
        assert!(readme.contains("target-cpu=native"));
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
        assert!(main_rs.contains("&generated::turso_local_encrypted_api::database()"));
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
        assert!(!artifact_dir.join("static_site/index.html.gz").exists());
        assert!(!artifact_dir.join("static_site/index.html.br").exists());
        assert!(!artifact_dir.join("static_site/assets/app.js.gz").exists());
        assert!(!artifact_dir.join("static_site/assets/app.js.br").exists());
    }

    #[test]
    fn export_generated_runtime_artifacts_generates_precompressed_static_dirs_into_bundle() {
        let root = test_root();
        let project_dir = root.join("project");
        emit_server_project(
            &fixture_path("static_site_precompressed_api.eon"),
            &project_dir,
            Some("static-site-precompressed-server".to_owned()),
            false,
            false,
        )
        .expect("server project should emit");

        let output = root.join("dist/static-site-precompressed-server");
        let artifact_dir = export_generated_runtime_artifacts(&project_dir, &output, false)
            .expect("runtime artifacts should export");

        let index_html = artifact_dir.join("static_site/index.html");
        let app_js = artifact_dir.join("static_site/assets/app.js");

        assert_eq!(
            read_gzip_to_string(&artifact_dir.join("static_site/index.html.gz")),
            read_to_string(&index_html)
        );
        assert_eq!(
            read_brotli_to_string(&artifact_dir.join("static_site/index.html.br")),
            read_to_string(&index_html)
        );
        assert_eq!(
            read_gzip_to_string(&artifact_dir.join("static_site/assets/app.js.gz")),
            read_to_string(&app_js)
        );
        assert_eq!(
            read_brotli_to_string(&artifact_dir.join("static_site/assets/app.js.br")),
            read_to_string(&app_js)
        );
    }

    #[test]
    fn export_generated_runtime_artifacts_copies_tls_files_into_bundle() {
        let root = test_root();
        let source = root.join("source");
        fs::create_dir_all(&source).expect("source dir should exist");
        let config_path = source.join("service.eon");
        fs::write(
            &config_path,
            r#"
            module: "tls_service"
            tls: {}
            resources: [
                {
                    name: "Note"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        )
        .expect("config should write");

        generate_self_signed_certificate(Some(&config_path), None, None, &[], false)
            .expect("self-signed certs should generate");

        let project_dir = root.join("project");
        emit_server_project(
            &config_path,
            &project_dir,
            Some("tls-service-server".to_owned()),
            false,
            false,
        )
        .expect("tls server project should emit");

        assert!(project_dir.join("certs/dev-cert.pem").exists());
        assert!(project_dir.join("certs/dev-key.pem").exists());

        let output = root.join("dist/tls-service-server");
        let artifact_dir = export_generated_runtime_artifacts(&project_dir, &output, false)
            .expect("runtime artifacts should export");

        assert!(artifact_dir.join("certs/dev-cert.pem").exists());
        assert!(artifact_dir.join("certs/dev-key.pem").exists());
    }

    #[test]
    fn build_server_binary_bridgeboard_supports_clean_room_e2e() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let root = test_root();
        let dist_dir = root.join("dist");
        fs::create_dir_all(&dist_dir).expect("dist dir should exist");

        let output = dist_dir.join(binary_file_name("bridgeboard"));
        build_server_binary(
            &example_path("bridgeboard/bridgeboard.eon"),
            &output,
            None,
            Some(root.join("build")),
            true,
            false,
            None,
            false,
            false,
        )
        .expect("bridgeboard binary should build");

        let artifact_dir = build_artifact_dir(&output).expect("artifact dir should resolve");
        let bundle_eon = artifact_dir.join("bridgeboard.eon");
        let database_url = database_url_from_service_config(&bundle_eon)
            .expect("bundle config should resolve a database url");
        assert_eq!(database_url, "sqlite:var/data/bridgeboard.db?mode=rwc");

        let capture_dir = root.join("capture");
        fs::create_dir_all(&capture_dir).expect("capture dir should exist");
        let jwt_secret = "bridgeboard-e2e-secret";
        let turso_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        unsafe {
            std::env::set_var("JWT_SECRET", jwt_secret);
            std::env::set_var("TURSO_ENCRYPTION_KEY", turso_key);
            std::env::set_var("VSR_AUTH_EMAIL_CAPTURE_DIR", &capture_dir);
            std::env::set_var("ADMIN_EMAIL", "admin@example.com");
            std::env::set_var("ADMIN_PASSWORD", "password123");
        }

        tokio::runtime::Runtime::new()
            .expect("tokio runtime should initialize")
            .block_on(run_setup(&database_url, Some(&bundle_eon), true, false))
            .expect("setup should initialize the bridgeboard database");

        assert!(
            dist_dir.join("var/data/bridgeboard.db").exists(),
            "setup should create the bundle-relative bridgeboard database"
        );
        assert!(
            !dist_dir.join("app.db").exists(),
            "setup should not create a stray app.db alongside the built binary"
        );

        let bind_addr = free_bind_addr();
        let base_url = format!("http://{bind_addr}");
        let stdout_log = root.join("bridgeboard.stdout.log");
        let stderr_log = root.join("bridgeboard.stderr.log");
        let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
        let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
        let child = Command::new(&output)
            .current_dir(&root)
            .env("BIND_ADDR", &bind_addr)
            .env("JWT_SECRET", jwt_secret)
            .env("TURSO_ENCRYPTION_KEY", turso_key)
            .env("VSR_AUTH_EMAIL_CAPTURE_DIR", &capture_dir)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("built binary should start");
        let server = SpawnedBinary::new(child, stdout_log, stderr_log);

        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("http client should build");
        if let Err(error) =
            wait_for_http_ready(&client, &format!("{base_url}/"), Duration::from_secs(30))
        {
            panic!(
                "bridgeboard binary never became ready: {error}\n{}",
                server.logs()
            );
        }

        let root_response = client
            .get(format!("{base_url}/"))
            .send()
            .expect("root page should load");
        assert!(root_response.status().is_success());
        let root_body = root_response.text().expect("root page body should read");
        assert!(root_body.contains("Bridgeboard"));

        let app_js_response = client
            .get(format!("{base_url}/app.js"))
            .send()
            .expect("app.js should load");
        assert!(app_js_response.status().is_success());

        let public_catalog_response = client
            .get(format!("{base_url}/api/organization"))
            .send()
            .expect("organization list should load");
        assert!(public_catalog_response.status().is_success());
        let public_catalog: Value = public_catalog_response
            .json()
            .expect("organization list should decode");
        assert_eq!(public_catalog.get("total").and_then(Value::as_i64), Some(0));

        let admin_login_response = client
            .post(format!("{base_url}/api/auth/login"))
            .json(&json!({
                "email": "admin@example.com",
                "password": "password123",
            }))
            .send()
            .expect("admin login should succeed");
        assert_eq!(admin_login_response.status(), reqwest::StatusCode::OK);
        let admin_login: Value = admin_login_response
            .json()
            .expect("admin login response should decode");
        let admin_token = admin_login
            .get("token")
            .and_then(Value::as_str)
            .expect("admin login should return a token")
            .to_owned();

        let create_org_response = client
            .post(format!("{base_url}/api/organization"))
            .bearer_auth(&admin_token)
            .json(&json!({
                "slug": "nordic-bridge",
                "name": "Nordic Bridge Institute",
                "country": "Finland",
                "city": "Oulu",
                "website_url": "https://bridge.example",
                "contact_email": "hello@bridge.example",
                "collaboration_stage": "Open call",
                "summary": "Coordinates cross-border thesis work between applied research labs and regional industry partners."
            }))
            .send()
            .expect("organization create should succeed");
        assert_eq!(create_org_response.status(), reqwest::StatusCode::CREATED);
        let organization_location = create_org_response
            .headers()
            .get("Location")
            .and_then(|value| value.to_str().ok())
            .expect("organization create should expose a location")
            .to_owned();
        let organization: Value = create_org_response
            .json()
            .expect("organization create response should decode");
        let organization_id = organization
            .get("id")
            .and_then(Value::as_i64)
            .expect("organization create should return an id");
        assert_eq!(
            organization_location,
            format!("/api/organization/{organization_id}")
        );

        let register_response = client
            .post(format!("{base_url}/api/auth/register"))
            .json(&json!({
                "email": "alice@example.com",
                "password": "password123",
            }))
            .send()
            .expect("user registration should succeed");
        assert_eq!(register_response.status(), reqwest::StatusCode::CREATED);

        let captured = wait_for_capture_count(&capture_dir, 1, Duration::from_secs(10));
        let verification_token = token_from_capture(&captured[0]);

        let verify_response = client
            .post(format!("{base_url}/api/auth/verify-email"))
            .json(&json!({ "token": verification_token }))
            .send()
            .expect("email verification should succeed");
        assert_eq!(verify_response.status(), reqwest::StatusCode::NO_CONTENT);

        let user_login_response = client
            .post(format!("{base_url}/api/auth/login"))
            .json(&json!({
                "email": "alice@example.com",
                "password": "password123",
            }))
            .send()
            .expect("verified user login should succeed");
        assert_eq!(user_login_response.status(), reqwest::StatusCode::OK);

        let password_reset_response = client
            .post(format!("{base_url}/api/auth/password-reset/request"))
            .json(&json!({
                "email": "alice@example.com",
            }))
            .send()
            .expect("password reset request should succeed");
        assert_eq!(
            password_reset_response.status(),
            reqwest::StatusCode::ACCEPTED
        );

        let captured = wait_for_capture_count(&capture_dir, 2, Duration::from_secs(10));
        let reset_capture = captured
            .iter()
            .find(|path| url_from_capture(path).contains("/password-reset?token="))
            .expect("reset email should be captured");
        let reset_token = token_from_capture(reset_capture);
        let reset_url = url_from_capture(reset_capture);
        let reset_path_and_query = path_and_query_from_url(&reset_url);
        assert!(
            reset_path_and_query.starts_with("/api/auth/password-reset?token="),
            "unexpected reset link path: {reset_path_and_query}"
        );

        let reset_page_response = client
            .get(format!("{base_url}{reset_path_and_query}"))
            .send()
            .expect("password reset page should load");
        assert_eq!(reset_page_response.status(), reqwest::StatusCode::OK);
        let reset_page_body = reset_page_response
            .text()
            .expect("password reset page body should read");
        assert!(reset_page_body.contains("Choose A New Password"));

        let confirm_reset_response = client
            .post(format!("{base_url}/api/auth/password-reset/confirm"))
            .json(&json!({
                "token": reset_token,
                "new_password": "password456",
            }))
            .send()
            .expect("password reset confirmation should succeed");
        assert_eq!(
            confirm_reset_response.status(),
            reqwest::StatusCode::NO_CONTENT
        );

        let old_password_login_response = client
            .post(format!("{base_url}/api/auth/login"))
            .json(&json!({
                "email": "alice@example.com",
                "password": "password123",
            }))
            .send()
            .expect("old password login response should return");
        assert_eq!(
            old_password_login_response.status(),
            reqwest::StatusCode::UNAUTHORIZED
        );

        let user_login_response = client
            .post(format!("{base_url}/api/auth/login"))
            .json(&json!({
                "email": "alice@example.com",
                "password": "password456",
            }))
            .send()
            .expect("login with reset password should succeed");
        assert_eq!(user_login_response.status(), reqwest::StatusCode::OK);
        let user_login: Value = user_login_response
            .json()
            .expect("user login response should decode");
        let user_token = user_login
            .get("token")
            .and_then(Value::as_str)
            .expect("reset-password login should return a token")
            .to_owned();

        let create_request_response = client
            .post(format!("{base_url}/api/collaboration_request"))
            .bearer_auth(&user_token)
            .json(&json!({
                "organization_id": organization_id,
                "title": "Applied AI thesis partnership",
                "message": "We want to connect a student team with the organization to shape a shared supervision track around applied AI validation.",
                "status": "submitted",
                "preferred_start_on": "2026-09-15"
            }))
            .send()
            .expect("collaboration request create should succeed");
        assert_eq!(
            create_request_response.status(),
            reqwest::StatusCode::CREATED
        );
        let request_location = create_request_response
            .headers()
            .get("Location")
            .and_then(|value| value.to_str().ok())
            .expect("collaboration request create should expose a location")
            .to_owned();
        let collaboration_request: Value = create_request_response
            .json()
            .expect("collaboration request response should decode");
        let request_id = collaboration_request
            .get("id")
            .and_then(Value::as_i64)
            .expect("collaboration request should include an id");
        assert_eq!(
            collaboration_request
                .get("requester_user_id")
                .and_then(Value::as_i64),
            Some(2)
        );
        assert_eq!(
            request_location,
            format!("/api/collaboration_request/{request_id}")
        );

        let admin_requests_response = client
            .get(format!("{base_url}/api/collaboration_request"))
            .bearer_auth(&admin_token)
            .send()
            .expect("admin should be able to list collaboration requests");
        assert_eq!(admin_requests_response.status(), reqwest::StatusCode::OK);
        let admin_requests: Value = admin_requests_response
            .json()
            .expect("admin collaboration list should decode");
        assert_eq!(admin_requests.get("total").and_then(Value::as_i64), Some(1));

        let portal_response = client
            .get(format!("{base_url}/api/auth/portal"))
            .send()
            .expect("account portal should load");
        assert_eq!(portal_response.status(), reqwest::StatusCode::OK);
        let portal_body = portal_response.text().expect("portal body should read");
        assert!(portal_body.contains("Bridgeboard Account"));

        let dashboard_response = client
            .get(format!("{base_url}/api/auth/admin"))
            .bearer_auth(&admin_token)
            .send()
            .expect("admin dashboard should load");
        assert_eq!(dashboard_response.status(), reqwest::StatusCode::OK);

        unsafe {
            std::env::remove_var("JWT_SECRET");
            std::env::remove_var("TURSO_ENCRYPTION_KEY");
            std::env::remove_var("VSR_AUTH_EMAIL_CAPTURE_DIR");
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
        }
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
