use std::{
    env, fs,
    io::Read,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

use anyhow::{Context, Result, bail};
use aws_config::{BehaviorVersion, meta::region::RegionProviderChain};
use aws_sdk_s3::{
    Client as S3Client,
    config::{Builder as S3ConfigBuilder, Region},
    primitives::ByteStream,
};
use chrono::Utc;
use colored::Colorize;
use reqwest::Url;
use rest_macro_core::{
    compiler::{self, DbBackend},
    database::{
        DatabaseBackupMode, DatabaseBackupTarget, DatabaseConfig, DatabaseEngine,
        DatabaseReadRoutingMode, DatabaseReplicationMode, DatabaseResilienceConfig,
        DatabaseResilienceProfile, sqlite_url_for_path,
    },
    db::{DbPool, query, query_scalar},
};
use sha2::{Digest, Sha256};
use sqlx::Row as _;

use super::db::{connect_database, database_config_from_service_config};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Clone, Debug, serde::Serialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    detail: String,
}

#[derive(Clone, Debug, serde::Serialize)]
struct DoctorReport {
    kind: String,
    service_module: String,
    sql_dialect: String,
    runtime_engine: String,
    primary_database_url: String,
    read_database_url: Option<String>,
    healthy: bool,
    checks: Vec<DoctorCheck>,
}

#[derive(Clone, Debug, serde::Serialize)]
struct BackupPlan {
    service_module: String,
    sql_dialect: String,
    runtime_engine: String,
    default_database_url: String,
    resilience: Option<DatabaseResilienceConfig>,
    summary: Vec<String>,
    backup_guidance: Vec<String>,
    replication_guidance: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct SnapshotManifest {
    format_version: u32,
    #[serde(default = "default_backup_artifact_kind")]
    artifact_kind: BackupArtifactKind,
    service_module: String,
    sql_dialect: String,
    runtime_engine: String,
    created_at: String,
    database: DatabaseConfig,
    backup_mode: Option<DatabaseBackupMode>,
    #[serde(default)]
    source_database_name: Option<String>,
    artifact_file: String,
    artifact_sha256: String,
    artifact_size_bytes: u64,
    schema_object_count: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum BackupArtifactKind {
    Snapshot,
    LogicalDump,
}

fn default_backup_artifact_kind() -> BackupArtifactKind {
    BackupArtifactKind::Snapshot
}

#[derive(Clone, Debug, serde::Serialize)]
struct SnapshotResult {
    artifact_dir: String,
    manifest_path: String,
    snapshot_path: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
struct VerifyRestoreResult {
    artifact_dir: String,
    manifest_path: String,
    artifact_kind: BackupArtifactKind,
    artifact_path: String,
    checksum_verified: bool,
    integrity_check: String,
    schema_object_count_expected: i64,
    schema_object_count_actual: i64,
    restore_target: Option<String>,
    healthy: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
struct RemoteArtifactTransferResult {
    remote_uri: String,
    artifact_dir: String,
    file_count: usize,
    total_bytes: u64,
    files: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct S3RemoteLocation {
    bucket: String,
    prefix: String,
}

#[derive(Clone, Debug, Default)]
struct S3RemoteOptions<'a> {
    endpoint_url: Option<&'a str>,
    region: Option<&'a str>,
    path_style: bool,
}

struct DisposableRestoreTarget {
    backend: DbBackend,
    container_name: String,
    database_url: String,
}

pub fn generate_backup_plan(
    input: &Path,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("failed to load service definition from {}", input.display()))?;
    let rendered = render_backup_plan(&service, format)?;

    if let Some(output) = output {
        if output.exists() && !force {
            bail!(
                "backup plan already exists at {} (use --force to overwrite)",
                output.display()
            );
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(output, rendered)
            .with_context(|| format!("failed to write backup plan to {}", output.display()))?;
        println!(
            "{} {}",
            "Generated backup plan:".green().bold(),
            output.display()
        );
    } else {
        print!("{rendered}");
        if !rendered.ends_with('\n') {
            println!();
        }
    }

    Ok(())
}

pub fn render_backup_plan(service: &compiler::ServiceSpec, format: OutputFormat) -> Result<String> {
    let plan = build_backup_plan(service);
    match format {
        OutputFormat::Text => Ok(render_text_plan(&plan)),
        OutputFormat::Json => {
            serde_json::to_string_pretty(&plan).context("failed to serialize backup plan to JSON")
        }
    }
}

pub async fn run_backup_snapshot(
    input: &Path,
    database_url: &str,
    config_path: Option<&Path>,
    output: &Path,
    force: bool,
) -> Result<()> {
    let result = create_snapshot_artifact(input, database_url, config_path, output, force).await?;
    println!(
        "{} {}\n{} {}\n{} {}",
        "Created backup artifact:".green().bold(),
        result.artifact_dir,
        "Manifest:".green().bold(),
        result.manifest_path,
        "Snapshot:".green().bold(),
        result.snapshot_path,
    );
    Ok(())
}

pub async fn run_backup_export(
    input: &Path,
    database_url: &str,
    output: &Path,
    force: bool,
) -> Result<()> {
    let result = create_logical_export_artifact(input, database_url, output, force).await?;
    println!(
        "{} {}\n{} {}\n{} {}",
        "Created backup artifact:".green().bold(),
        result.artifact_dir,
        "Manifest:".green().bold(),
        result.manifest_path,
        "Export:".green().bold(),
        result.snapshot_path,
    );
    Ok(())
}

pub async fn run_backup_verify_restore(
    artifact: &Path,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let result = verify_backup_artifact(artifact).await?;
    let rendered = match format {
        OutputFormat::Text => render_text_verify_restore(&result),
        OutputFormat::Json => serde_json::to_string_pretty(&result)
            .context("failed to serialize verify-restore result to JSON")?,
    };
    write_rendered_output(rendered, output, force, "verify-restore report")
}

pub async fn run_backup_push(
    artifact: &Path,
    remote: &str,
    endpoint_url: Option<&str>,
    region: Option<&str>,
    path_style: bool,
    format: OutputFormat,
) -> Result<()> {
    let result = push_snapshot_artifact(
        artifact,
        remote,
        S3RemoteOptions {
            endpoint_url,
            region,
            path_style,
        },
    )
    .await?;
    print_rendered_transfer_result(&result, format);
    Ok(())
}

pub async fn run_backup_pull(
    remote: &str,
    output: &Path,
    endpoint_url: Option<&str>,
    region: Option<&str>,
    path_style: bool,
    force: bool,
    format: OutputFormat,
) -> Result<()> {
    let result = pull_snapshot_artifact(
        remote,
        output,
        force,
        S3RemoteOptions {
            endpoint_url,
            region,
            path_style,
        },
    )
    .await?;
    print_rendered_transfer_result(&result, format);
    Ok(())
}

pub async fn run_backup_doctor(
    input: &Path,
    database_url: &str,
    config_path: Option<&Path>,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("failed to load service definition from {}", input.display()))?;
    let report = build_backup_doctor_report(&service, database_url, config_path).await;
    write_rendered_output(
        render_doctor_report(&report, format)?,
        output,
        force,
        "backup doctor report",
    )
}

pub async fn run_replication_doctor(
    input: &Path,
    database_url: &str,
    read_database_url: Option<&str>,
    config_path: Option<&Path>,
    output: Option<&Path>,
    format: OutputFormat,
    force: bool,
) -> Result<()> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("failed to load service definition from {}", input.display()))?;
    let report =
        build_replication_doctor_report(&service, database_url, read_database_url, config_path)
            .await;
    write_rendered_output(
        render_doctor_report(&report, format)?,
        output,
        force,
        "replication doctor report",
    )
}

async fn create_snapshot_artifact(
    input: &Path,
    database_url: &str,
    config_path: Option<&Path>,
    output: &Path,
    force: bool,
) -> Result<SnapshotResult> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("failed to load service definition from {}", input.display()))?;
    ensure_sqlite_snapshot_supported(&service)?;

    prepare_artifact_directory(output, force)?;
    let snapshot_path = output.join("snapshot.db");
    let manifest_path = output.join("manifest.json");
    let pool = connect_database(database_url, config_path.or(Some(input)))
        .await
        .context("failed to connect database for snapshot")?;
    snapshot_sqlite_database(&pool, &snapshot_path).await?;
    let schema_object_count = count_schema_objects(&pool).await?;
    let sha256 = compute_file_sha256(&snapshot_path)?;
    let size_bytes = fs::metadata(&snapshot_path)
        .with_context(|| format!("failed to read metadata for {}", snapshot_path.display()))?
        .len();
    let database = database_config_from_service_config(input)
        .context("failed to resolve service database config for manifest")?;
    let backup_mode = service
        .database
        .resilience
        .as_ref()
        .and_then(|config| config.backup.as_ref())
        .map(|backup| backup.mode);
    let manifest = SnapshotManifest {
        format_version: 1,
        artifact_kind: BackupArtifactKind::Snapshot,
        service_module: service.module_ident.to_string(),
        sql_dialect: sql_dialect_name(
            service
                .resources
                .first()
                .map(|resource| resource.db)
                .unwrap_or(DbBackend::Sqlite),
        )
        .to_owned(),
        runtime_engine: runtime_engine_name(&database),
        created_at: Utc::now().to_rfc3339(),
        database,
        backup_mode,
        source_database_name: None,
        artifact_file: "snapshot.db".to_owned(),
        artifact_sha256: sha256.clone(),
        artifact_size_bytes: size_bytes,
        schema_object_count,
    };
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("failed to write manifest to {}", manifest_path.display()))?;

    Ok(SnapshotResult {
        artifact_dir: output.display().to_string(),
        manifest_path: manifest_path.display().to_string(),
        snapshot_path: snapshot_path.display().to_string(),
        sha256,
        size_bytes,
    })
}

async fn create_logical_export_artifact(
    input: &Path,
    database_url: &str,
    output: &Path,
    force: bool,
) -> Result<SnapshotResult> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("failed to load service definition from {}", input.display()))?;
    let backend = ensure_logical_export_supported(&service)?;

    prepare_artifact_directory(output, force)?;
    let dump_path = output.join("dump.sql");
    let manifest_path = output.join("manifest.json");
    export_logical_backup(database_url, backend, &dump_path).await?;

    let pool = connect_database(database_url, Some(input))
        .await
        .context("failed to connect database for export metadata")?;
    let schema_object_count = count_schema_objects_for_backend(&pool, backend).await?;
    let sha256 = compute_file_sha256(&dump_path)?;
    let size_bytes = fs::metadata(&dump_path)
        .with_context(|| format!("failed to read metadata for {}", dump_path.display()))?
        .len();
    let database = database_config_from_service_config(input)
        .context("failed to resolve service database config for manifest")?;
    let backup_mode = service
        .database
        .resilience
        .as_ref()
        .and_then(|config| config.backup.as_ref())
        .map(|backup| backup.mode)
        .or(Some(DatabaseBackupMode::Logical));
    let manifest = SnapshotManifest {
        format_version: 1,
        artifact_kind: BackupArtifactKind::LogicalDump,
        service_module: service.module_ident.to_string(),
        sql_dialect: sql_dialect_name(backend).to_owned(),
        runtime_engine: runtime_engine_name(&database),
        created_at: Utc::now().to_rfc3339(),
        database,
        backup_mode,
        source_database_name: Some(parse_database_url(database_url)?.database),
        artifact_file: "dump.sql".to_owned(),
        artifact_sha256: sha256.clone(),
        artifact_size_bytes: size_bytes,
        schema_object_count,
    };
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("failed to write manifest to {}", manifest_path.display()))?;

    Ok(SnapshotResult {
        artifact_dir: output.display().to_string(),
        manifest_path: manifest_path.display().to_string(),
        snapshot_path: dump_path.display().to_string(),
        sha256,
        size_bytes,
    })
}

async fn verify_backup_artifact(artifact: &Path) -> Result<VerifyRestoreResult> {
    let (artifact_dir, manifest_path, manifest) = load_snapshot_manifest(artifact)?;
    match manifest.artifact_kind {
        BackupArtifactKind::Snapshot => {
            verify_snapshot_artifact_from_manifest(artifact_dir, manifest_path, manifest).await
        }
        BackupArtifactKind::LogicalDump => {
            verify_logical_dump_artifact_from_manifest(artifact_dir, manifest_path, manifest).await
        }
    }
}

async fn verify_snapshot_artifact_from_manifest(
    artifact_dir: PathBuf,
    manifest_path: PathBuf,
    manifest: SnapshotManifest,
) -> Result<VerifyRestoreResult> {
    let snapshot_path = artifact_dir.join(&manifest.artifact_file);
    if !snapshot_path.is_file() {
        bail!("snapshot artifact is missing {}", snapshot_path.display());
    }

    let checksum_verified = compute_file_sha256(&snapshot_path)? == manifest.artifact_sha256;
    if !checksum_verified {
        bail!("snapshot checksum mismatch for {}", snapshot_path.display());
    }

    let restore_dir = std::env::temp_dir().join(format!(
        "vsr_verify_restore_{}_{}",
        manifest.service_module,
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    fs::create_dir_all(&restore_dir)
        .with_context(|| format!("failed to create {}", restore_dir.display()))?;
    let restore_path = restore_dir.join("restored.db");
    fs::copy(&snapshot_path, &restore_path).with_context(|| {
        format!(
            "failed to copy snapshot {} to {}",
            snapshot_path.display(),
            restore_path.display()
        )
    })?;

    let restore_config = database_config_for_restore(&manifest.database, &restore_path);
    let restore_database_url = sqlite_url_for_path(&restore_path.display().to_string());
    let pool = DbPool::connect_with_config(&restore_database_url, &restore_config)
        .await
        .context("failed to open restored snapshot")?;
    let integrity_check: String = query_scalar::<sqlx::Any, String>("PRAGMA integrity_check")
        .fetch_one(&pool)
        .await
        .context("failed to run PRAGMA integrity_check on restored snapshot")?;
    let schema_object_count_actual = count_schema_objects(&pool).await?;
    let healthy = integrity_check.eq_ignore_ascii_case("ok")
        && schema_object_count_actual == manifest.schema_object_count;

    let result = VerifyRestoreResult {
        artifact_dir: artifact_dir.display().to_string(),
        manifest_path: manifest_path.display().to_string(),
        artifact_kind: manifest.artifact_kind,
        artifact_path: snapshot_path.display().to_string(),
        checksum_verified,
        integrity_check,
        schema_object_count_expected: manifest.schema_object_count,
        schema_object_count_actual,
        restore_target: Some(restore_database_url),
        healthy,
    };

    let _ = fs::remove_dir_all(&restore_dir);

    Ok(result)
}

async fn verify_logical_dump_artifact_from_manifest(
    artifact_dir: PathBuf,
    manifest_path: PathBuf,
    manifest: SnapshotManifest,
) -> Result<VerifyRestoreResult> {
    let backend = backend_from_sql_dialect(&manifest.sql_dialect)?;
    if backend == DbBackend::Sqlite {
        bail!("logical dump verification is not supported for SQLite artifacts");
    }

    let dump_path = artifact_dir.join(&manifest.artifact_file);
    if !dump_path.is_file() {
        bail!("logical dump artifact is missing {}", dump_path.display());
    }

    let checksum_verified = compute_file_sha256(&dump_path)? == manifest.artifact_sha256;
    if !checksum_verified {
        bail!("logical dump checksum mismatch for {}", dump_path.display());
    }

    let source_database_name = logical_dump_restore_database_name(&manifest, &dump_path, backend)
        .with_context(|| {
        format!(
            "failed to determine restore database name for {}",
            dump_path.display()
        )
    })?;
    let target = start_disposable_restore_target(backend, &source_database_name)?;
    let restore_target_url = target.database_url.clone();

    let outcome = async {
        restore_logical_dump_into_target(&target, &dump_path)?;
        let pool = DbPool::connect(&target.database_url)
            .await
            .with_context(|| format!("failed to connect restored {}", sql_dialect_name(backend)))?;
        let connectivity_check: i64 = query_scalar::<sqlx::Any, i64>("SELECT 1")
            .fetch_one(&pool)
            .await
            .context("failed to confirm restored database connectivity")?;
        let schema_object_count_actual = count_schema_objects_for_backend(&pool, backend).await?;
        let healthy = connectivity_check == 1
            && schema_object_count_actual == manifest.schema_object_count
            && checksum_verified;

        Ok(VerifyRestoreResult {
            artifact_dir: artifact_dir.display().to_string(),
            manifest_path: manifest_path.display().to_string(),
            artifact_kind: manifest.artifact_kind,
            artifact_path: dump_path.display().to_string(),
            checksum_verified,
            integrity_check: "restore_ok".to_owned(),
            schema_object_count_expected: manifest.schema_object_count,
            schema_object_count_actual,
            restore_target: Some(restore_target_url.clone()),
            healthy,
        })
    }
    .await;

    let cleanup_result = cleanup_disposable_restore_target(&target);
    match (outcome, cleanup_result) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

async fn push_snapshot_artifact(
    artifact: &Path,
    remote: &str,
    options: S3RemoteOptions<'_>,
) -> Result<RemoteArtifactTransferResult> {
    let (artifact_dir, _, _) = load_snapshot_manifest(artifact)?;
    let location = parse_s3_remote_location(remote)?;
    let files = collect_artifact_files(&artifact_dir)?;
    let client = build_s3_client(options).await?;
    let mut total_bytes = 0u64;
    let mut uploaded_files = Vec::with_capacity(files.len());

    for (absolute_path, relative_path) in files {
        let key = join_s3_key(&location.prefix, &relative_path);
        let body = ByteStream::from_path(&absolute_path)
            .await
            .with_context(|| format!("failed to stream {}", absolute_path.display()))?;
        let size = fs::metadata(&absolute_path)
            .with_context(|| format!("failed to read metadata for {}", absolute_path.display()))?
            .len();
        client
            .put_object()
            .bucket(&location.bucket)
            .key(&key)
            .body(body)
            .send()
            .await
            .with_context(|| format!("failed to upload s3://{}/{}", location.bucket, key))?;
        total_bytes += size;
        uploaded_files.push(relative_path);
    }

    Ok(RemoteArtifactTransferResult {
        remote_uri: remote.to_owned(),
        artifact_dir: artifact_dir.display().to_string(),
        file_count: uploaded_files.len(),
        total_bytes,
        files: uploaded_files,
    })
}

async fn pull_snapshot_artifact(
    remote: &str,
    output: &Path,
    force: bool,
    options: S3RemoteOptions<'_>,
) -> Result<RemoteArtifactTransferResult> {
    let location = parse_s3_remote_location(remote)?;
    prepare_artifact_directory(output, force)?;
    let client = build_s3_client(options).await?;
    let object_keys = list_s3_object_keys(&client, &location).await?;
    if object_keys.is_empty() {
        bail!("no backup artifact files found at {remote}");
    }

    let mut total_bytes = 0u64;
    let mut downloaded_files = Vec::with_capacity(object_keys.len());

    for key in object_keys {
        let relative_path = relative_path_from_s3_key(&location.prefix, &key)?;
        let local_path = output.join(&relative_path);
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let response = client
            .get_object()
            .bucket(&location.bucket)
            .key(&key)
            .send()
            .await
            .with_context(|| format!("failed to download s3://{}/{}", location.bucket, key))?;
        let bytes = response
            .body
            .collect()
            .await
            .with_context(|| format!("failed to read body for s3://{}/{}", location.bucket, key))?
            .into_bytes();
        fs::write(&local_path, &bytes)
            .with_context(|| format!("failed to write {}", local_path.display()))?;
        total_bytes += bytes.len() as u64;
        downloaded_files.push(relative_path);
    }

    let (artifact_dir, _, manifest) = load_snapshot_manifest(output)?;
    let snapshot_path = artifact_dir.join(&manifest.artifact_file);
    if !snapshot_path.is_file() {
        bail!(
            "pulled artifact is missing the manifest-declared snapshot file {}",
            snapshot_path.display()
        );
    }

    Ok(RemoteArtifactTransferResult {
        remote_uri: remote.to_owned(),
        artifact_dir: artifact_dir.display().to_string(),
        file_count: downloaded_files.len(),
        total_bytes,
        files: downloaded_files,
    })
}

async fn build_s3_client(options: S3RemoteOptions<'_>) -> Result<S3Client> {
    let region_provider = match options.region {
        Some(region) => RegionProviderChain::first_try(Some(Region::new(region.to_owned())))
            .or_default_provider()
            .or_else(Region::new("us-east-1")),
        None => RegionProviderChain::default_provider().or_else(Region::new("us-east-1")),
    };
    let shared_config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    let mut builder = S3ConfigBuilder::from(&shared_config);
    if let Some(endpoint_url) = options.endpoint_url {
        builder = builder.endpoint_url(endpoint_url);
    }
    if options.path_style {
        builder = builder.force_path_style(true);
    }
    Ok(S3Client::from_conf(builder.build()))
}

async fn list_s3_object_keys(
    client: &S3Client,
    location: &S3RemoteLocation,
) -> Result<Vec<String>> {
    let mut continuation_token = None;
    let mut keys = Vec::new();

    loop {
        let mut request = client.list_objects_v2().bucket(&location.bucket);
        if !location.prefix.is_empty() {
            request = request.prefix(location.prefix.clone());
        }
        if let Some(token) = continuation_token.as_deref() {
            request = request.continuation_token(token);
        }

        let response = request.send().await.with_context(|| {
            format!(
                "failed to list objects under s3://{}/{}",
                location.bucket, location.prefix
            )
        })?;

        for object in response.contents() {
            let Some(key) = object.key() else {
                continue;
            };
            if key.ends_with('/') {
                continue;
            }
            keys.push(key.to_owned());
        }

        if !response.is_truncated().unwrap_or(false) {
            break;
        }
        continuation_token = response.next_continuation_token().map(str::to_owned);
    }

    keys.sort();
    Ok(keys)
}

fn parse_s3_remote_location(remote: &str) -> Result<S3RemoteLocation> {
    let trimmed = remote.trim();
    let without_scheme = trimmed
        .strip_prefix("s3://")
        .ok_or_else(|| anyhow::anyhow!("remote must use the form s3://bucket/prefix"))?;
    if without_scheme.is_empty() {
        bail!("remote must include a bucket name");
    }

    let mut parts = without_scheme.splitn(2, '/');
    let bucket = parts.next().unwrap_or_default().trim();
    if bucket.is_empty() {
        bail!("remote must include a bucket name");
    }
    let prefix = parts
        .next()
        .unwrap_or_default()
        .trim_matches('/')
        .to_owned();

    Ok(S3RemoteLocation {
        bucket: bucket.to_owned(),
        prefix,
    })
}

fn collect_artifact_files(artifact_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut files = Vec::new();
    collect_artifact_files_recursive(artifact_dir, artifact_dir, &mut files)?;
    files.sort_by(|left, right| left.1.cmp(&right.1));
    Ok(files)
}

fn collect_artifact_files_recursive(
    root: &Path,
    current: &Path,
    files: &mut Vec<(PathBuf, String)>,
) -> Result<()> {
    for entry in
        fs::read_dir(current).with_context(|| format!("failed to read {}", current.display()))?
    {
        let entry = entry.with_context(|| format!("failed to inspect {}", current.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_artifact_files_recursive(root, &path, files)?;
        } else if path.is_file() {
            let relative_path = path
                .strip_prefix(root)
                .map_err(|_| anyhow::anyhow!("failed to build relative artifact path"))?
                .to_string_lossy()
                .replace('\\', "/");
            files.push((path, relative_path));
        }
    }
    Ok(())
}

fn join_s3_key(prefix: &str, relative_path: &str) -> String {
    if prefix.is_empty() {
        relative_path.to_owned()
    } else {
        format!("{prefix}/{relative_path}")
    }
}

fn relative_path_from_s3_key(prefix: &str, key: &str) -> Result<String> {
    if prefix.is_empty() {
        if key.is_empty() {
            bail!("encountered an empty object key while pulling artifact");
        }
        return Ok(key.to_owned());
    }

    let expected_prefix = format!("{prefix}/");
    key.strip_prefix(&expected_prefix)
        .filter(|relative| !relative.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "encountered object key `{key}` outside requested remote prefix `{prefix}`"
            )
        })
}

async fn export_logical_backup(
    database_url: &str,
    backend: DbBackend,
    dump_path: &Path,
) -> Result<()> {
    match backend {
        DbBackend::Postgres => export_postgres_logical_backup(database_url, dump_path),
        DbBackend::Mysql => export_mysql_logical_backup(database_url, dump_path),
        DbBackend::Sqlite => bail!("logical export is not supported for SQLite"),
    }
}

fn export_postgres_logical_backup(database_url: &str, dump_path: &Path) -> Result<()> {
    let tool_args = vec![
        "--no-owner".to_owned(),
        "--no-privileges".to_owned(),
        "--format=plain".to_owned(),
        format!("--file={}", dump_path.display()),
        format!("--dbname={database_url}"),
    ];

    run_native_or_docker_tool(
        "pg_dump",
        &tool_args,
        Some(("postgres:16", vec!["pg_dump".to_owned()])),
        dump_path.parent().unwrap_or_else(|| Path::new(".")),
        "dump.sql",
        database_url,
        None,
    )
}

fn export_mysql_logical_backup(database_url: &str, dump_path: &Path) -> Result<()> {
    let info = parse_database_url(database_url)?;
    let host = info.host;
    let port = info.port;
    let user = info.username;
    let password = info.password;
    let database = info.database;

    let tool_args = vec![
        "--protocol=tcp".to_owned(),
        format!("--host={host}"),
        format!("--port={port}"),
        format!("--user={user}"),
        "--single-transaction".to_owned(),
        "--skip-comments".to_owned(),
        "--routines".to_owned(),
        "--triggers".to_owned(),
        format!("--result-file={}", dump_path.display()),
        "--databases".to_owned(),
        database.clone(),
    ];

    run_native_or_docker_tool(
        "mysqldump",
        &tool_args,
        Some(("mysql:8.4", vec!["mysqldump".to_owned()])),
        dump_path.parent().unwrap_or_else(|| Path::new(".")),
        "dump.sql",
        database_url,
        password.as_deref(),
    )
}

fn run_native_or_docker_tool(
    tool_name: &str,
    tool_args: &[String],
    docker_fallback: Option<(&str, Vec<String>)>,
    output_dir: &Path,
    output_file_name: &str,
    database_url: &str,
    mysql_password: Option<&str>,
) -> Result<()> {
    if let Some(executable) = find_executable(tool_name) {
        let mut command = Command::new(executable);
        command.args(tool_args);
        if let Some(password) = mysql_password {
            command.env("MYSQL_PWD", password);
        }
        run_command(command, tool_name)
    } else if let Some((image, docker_cmd)) = docker_fallback {
        if find_executable("docker").is_none() {
            bail!(
                "{} is not installed and Docker is not available for fallback execution",
                tool_name
            );
        }
        let docker_database_url = rewrite_database_url_for_docker(database_url)?;
        let mut args = docker_cmd;
        let mounted_output = format!("/backup/{output_file_name}");
        match tool_name {
            "pg_dump" => {
                args.extend([
                    "--no-owner".to_owned(),
                    "--no-privileges".to_owned(),
                    "--format=plain".to_owned(),
                    format!("--file={mounted_output}"),
                    format!("--dbname={docker_database_url}"),
                ]);
            }
            "mysqldump" => {
                let info = parse_database_url(&docker_database_url)?;
                args.extend([
                    "--protocol=tcp".to_owned(),
                    format!("--host={}", info.host),
                    format!("--port={}", info.port),
                    format!("--user={}", info.username),
                    "--single-transaction".to_owned(),
                    "--skip-comments".to_owned(),
                    "--routines".to_owned(),
                    "--triggers".to_owned(),
                    format!("--result-file={mounted_output}"),
                    "--databases".to_owned(),
                    info.database,
                ]);
            }
            _ => bail!("unsupported docker fallback tool {tool_name}"),
        }

        let mut command = Command::new("docker");
        command.arg("run").arg("--rm");
        if cfg!(target_os = "linux") {
            command.args(["--network", "host"]);
        }
        command
            .arg("-v")
            .arg(format!("{}:/backup", output_dir.display()));
        if tool_name == "mysqldump" {
            let info = parse_database_url(&docker_database_url)?;
            if let Some(password) = info.password {
                command.arg("-e").arg(format!("MYSQL_PWD={password}"));
            }
        }
        command.arg(image);
        command.args(args);
        run_command(command, &format!("{tool_name} (docker fallback)"))
    } else {
        bail!("{tool_name} is not installed");
    }
}

fn run_command(mut command: Command, label: &str) -> Result<()> {
    let output = command
        .output()
        .with_context(|| format!("failed to run {label}"))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if !stderr.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    bail!("{label} failed: {detail}");
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn rewrite_database_url_for_docker(database_url: &str) -> Result<String> {
    let mut url = Url::parse(database_url)
        .with_context(|| format!("failed to parse database URL `{database_url}`"))?;
    if cfg!(target_os = "linux") {
        return Ok(url.to_string());
    }

    match url.host_str() {
        Some("127.0.0.1") | Some("localhost") | Some("::1") => {
            url.set_host(Some("host.docker.internal"))
                .map_err(|_| anyhow::anyhow!("failed to rewrite database URL host for docker"))?;
        }
        _ => {}
    }
    Ok(url.to_string())
}

struct ParsedDatabaseUrl {
    host: String,
    port: u16,
    username: String,
    password: Option<String>,
    database: String,
}

fn parse_database_url(database_url: &str) -> Result<ParsedDatabaseUrl> {
    let url = Url::parse(database_url)
        .with_context(|| format!("failed to parse database URL `{database_url}`"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("database URL is missing a host"))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("database URL is missing a port"))?;
    let username = if url.username().is_empty() {
        bail!("database URL is missing a username");
    } else {
        url.username().to_owned()
    };
    let database = url
        .path()
        .trim_start_matches('/')
        .split('/')
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("database URL is missing a database name"))?
        .to_owned();

    Ok(ParsedDatabaseUrl {
        host,
        port,
        username,
        password: url.password().map(str::to_owned),
        database,
    })
}

fn backend_from_sql_dialect(sql_dialect: &str) -> Result<DbBackend> {
    match sql_dialect.trim().to_ascii_lowercase().as_str() {
        "sqlite" => Ok(DbBackend::Sqlite),
        "postgres" => Ok(DbBackend::Postgres),
        "mysql" => Ok(DbBackend::Mysql),
        other => bail!("unsupported SQL dialect `{other}` in backup artifact manifest"),
    }
}

fn logical_dump_restore_database_name(
    manifest: &SnapshotManifest,
    dump_path: &Path,
    backend: DbBackend,
) -> Result<String> {
    if let Some(name) = manifest.source_database_name.as_ref()
        && !name.trim().is_empty()
    {
        return Ok(name.trim().to_owned());
    }

    match backend {
        DbBackend::Postgres => Ok("restore_verify".to_owned()),
        DbBackend::Mysql => parse_mysql_dump_database_name(dump_path),
        DbBackend::Sqlite => bail!("SQLite logical dump restore is unsupported"),
    }
}

fn parse_mysql_dump_database_name(dump_path: &Path) -> Result<String> {
    let contents = fs::read_to_string(dump_path)
        .with_context(|| format!("failed to read {}", dump_path.display()))?;
    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(name) = mysql_dump_identifier(trimmed, "CREATE DATABASE") {
            return Ok(name);
        }
        if let Some(name) = mysql_dump_identifier(trimmed, "USE") {
            return Ok(name);
        }
    }

    bail!(
        "could not determine MySQL database name from dump {}; regenerate the artifact with a newer `vsr backup export`",
        dump_path.display()
    )
}

fn mysql_dump_identifier(line: &str, prefix: &str) -> Option<String> {
    if !line.to_ascii_uppercase().starts_with(prefix) {
        return None;
    }

    let tick_start = line.find('`')?;
    let rest = &line[tick_start + 1..];
    let tick_end = rest.find('`')?;
    let ident = &rest[..tick_end];
    if ident.is_empty() {
        None
    } else {
        Some(ident.to_owned())
    }
}

fn start_disposable_restore_target(
    backend: DbBackend,
    database_name: &str,
) -> Result<DisposableRestoreTarget> {
    if find_executable("docker").is_none() {
        bail!("docker is required for logical dump restore verification");
    }

    let port = reserve_local_port()?;
    let unique = Utc::now().timestamp_nanos_opt().unwrap_or_default();
    let container_name = match backend {
        DbBackend::Postgres => format!("vsr-verify-pg-{unique}"),
        DbBackend::Mysql => format!("vsr-verify-mysql-{unique}"),
        DbBackend::Sqlite => bail!("SQLite restore targets are not docker-backed"),
    };

    let mut command = Command::new("docker");
    command.arg("run").arg("-d").arg("--rm");
    command.arg("--name").arg(&container_name);
    match backend {
        DbBackend::Postgres => {
            command
                .arg("-e")
                .arg("POSTGRES_PASSWORD=postgres")
                .arg("-e")
                .arg(format!("POSTGRES_DB={database_name}"))
                .arg("-p")
                .arg(format!("127.0.0.1:{port}:5432"))
                .arg("postgres:16");
        }
        DbBackend::Mysql => {
            command
                .arg("-e")
                .arg("MYSQL_ROOT_PASSWORD=password")
                .arg("-e")
                .arg(format!("MYSQL_DATABASE={database_name}"))
                .arg("-p")
                .arg(format!("127.0.0.1:{port}:3306"))
                .arg("mysql:8.4");
        }
        DbBackend::Sqlite => unreachable!(),
    }
    run_command(command, "docker run restore target")?;
    wait_for_restore_target_ready(backend, &container_name, database_name)?;

    let database_url = match backend {
        DbBackend::Postgres => {
            format!("postgres://postgres:postgres@127.0.0.1:{port}/{database_name}")
        }
        DbBackend::Mysql => format!("mysql://root:password@127.0.0.1:{port}/{database_name}"),
        DbBackend::Sqlite => unreachable!(),
    };

    Ok(DisposableRestoreTarget {
        backend,
        container_name,
        database_url,
    })
}

fn wait_for_restore_target_ready(
    backend: DbBackend,
    container_name: &str,
    database_name: &str,
) -> Result<()> {
    for _ in 0..60 {
        let mut command = Command::new("docker");
        command.arg("exec").arg(container_name);
        match backend {
            DbBackend::Postgres => {
                command.args(["pg_isready", "-U", "postgres", "-d", database_name]);
            }
            DbBackend::Mysql => {
                command.args(["mysqladmin", "ping", "-h127.0.0.1", "-uroot", "-ppassword"]);
            }
            DbBackend::Sqlite => unreachable!(),
        }

        if let Ok(output) = command.output()
            && output.status.success()
        {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    bail!(
        "timed out waiting for disposable {} restore target `{}`",
        sql_dialect_name(backend),
        container_name
    )
}

fn restore_logical_dump_into_target(
    target: &DisposableRestoreTarget,
    dump_path: &Path,
) -> Result<()> {
    let dump_file = fs::File::open(dump_path)
        .with_context(|| format!("failed to open {}", dump_path.display()))?;
    let mut command = Command::new("docker");
    command.arg("exec").arg("-i").arg(&target.container_name);
    match target.backend {
        DbBackend::Postgres => {
            let database_name =
                target.database_url.rsplit('/').next().ok_or_else(|| {
                    anyhow::anyhow!("restore target URL is missing a database name")
                })?;
            command.args([
                "psql",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "postgres",
                "-d",
                database_name,
            ]);
        }
        DbBackend::Mysql => {
            command.args(["mysql", "-uroot", "-ppassword"]);
        }
        DbBackend::Sqlite => unreachable!(),
    }
    command.stdin(Stdio::from(dump_file));
    run_command(command, "logical dump restore")?;
    Ok(())
}

fn cleanup_disposable_restore_target(target: &DisposableRestoreTarget) -> Result<()> {
    let mut command = Command::new("docker");
    command.arg("rm").arg("-f").arg(&target.container_name);
    run_command(command, "docker rm restore target")
}

fn reserve_local_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .context("failed to reserve a local port for restore verification")?;
    let port = listener
        .local_addr()
        .context("failed to read reserved local port")?
        .port();
    drop(listener);
    Ok(port)
}

fn build_backup_plan(service: &compiler::ServiceSpec) -> BackupPlan {
    let backend = service
        .resources
        .first()
        .map(|resource| resource.db)
        .unwrap_or(DbBackend::Sqlite);
    let resilience = service.database.resilience.clone();
    let mut summary = Vec::new();
    let mut warnings = Vec::new();

    let runtime_engine = runtime_engine_name(&service.database);
    let sql_dialect = sql_dialect_name(backend).to_owned();

    match &resilience {
        Some(config) => {
            summary.push(format!(
                "Resilience profile: {}",
                resilience_profile_name(config.profile)
            ));
            if let Some(backup) = &config.backup {
                summary.push(format!(
                    "Backup: {} to {}",
                    backup_mode_name(backup.mode),
                    backup_target_name(backup.target)
                ));
                if backup.verify_restore {
                    summary.push("Restore verification is required".to_owned());
                }
            } else {
                warnings.push(
                    "A resilience profile is declared, but `database.resilience.backup` is missing"
                        .to_owned(),
                );
            }
            if let Some(replication) = &config.replication {
                summary.push(format!(
                    "Replication: {} with {} read routing",
                    replication_mode_name(replication.mode),
                    read_routing_name(replication.read_routing)
                ));
            }
        }
        None => warnings.push(
            "No `database.resilience` contract is declared. This plan is advisory only.".to_owned(),
        ),
    }

    if backend == DbBackend::Postgres
        && resilience
            .as_ref()
            .and_then(|c| c.replication.as_ref())
            .is_none()
    {
        warnings.push(
            "Postgres deployments intended for HA should declare replica topology explicitly"
                .to_owned(),
        );
    }
    if backend == DbBackend::Mysql
        && resilience
            .as_ref()
            .and_then(|c| c.replication.as_ref())
            .is_none()
    {
        warnings.push(
            "MySQL deployments intended for HA should declare replica topology explicitly"
                .to_owned(),
        );
    }

    BackupPlan {
        service_module: service.module_ident.to_string(),
        sql_dialect,
        runtime_engine,
        default_database_url: compiler::default_service_database_url(service),
        resilience,
        summary,
        backup_guidance: build_backup_guidance(backend, &service.database),
        replication_guidance: build_replication_guidance(backend, &service.database),
        warnings,
    }
}

fn ensure_sqlite_snapshot_supported(service: &compiler::ServiceSpec) -> Result<()> {
    let backend = service
        .resources
        .first()
        .map(|resource| resource.db)
        .unwrap_or(DbBackend::Sqlite);
    if backend != DbBackend::Sqlite {
        bail!("backup snapshot currently supports only SQLite-based services");
    }
    Ok(())
}

fn ensure_logical_export_supported(service: &compiler::ServiceSpec) -> Result<DbBackend> {
    let backend = service
        .resources
        .first()
        .map(|resource| resource.db)
        .unwrap_or(DbBackend::Sqlite);
    match backend {
        DbBackend::Postgres | DbBackend::Mysql => Ok(backend),
        DbBackend::Sqlite => bail!(
            "backup export currently supports only Postgres/MySQL services; use `backup snapshot` for SQLite/TursoLocal"
        ),
    }
}

fn prepare_artifact_directory(output: &Path, force: bool) -> Result<()> {
    if output.exists() {
        if !force {
            bail!(
                "backup artifact directory already exists at {} (use --force to overwrite)",
                output.display()
            );
        }
        if output.is_dir() {
            fs::remove_dir_all(output)
                .with_context(|| format!("failed to remove {}", output.display()))?;
        } else {
            fs::remove_file(output)
                .with_context(|| format!("failed to remove {}", output.display()))?;
        }
    }
    fs::create_dir_all(output).with_context(|| format!("failed to create {}", output.display()))
}

async fn snapshot_sqlite_database(pool: &DbPool, snapshot_path: &Path) -> Result<()> {
    let escaped = snapshot_path.display().to_string().replace('\'', "''");
    let sql = format!("VACUUM INTO '{escaped}';");
    pool.execute_batch(&sql)
        .await
        .with_context(|| format!("failed to create snapshot at {}", snapshot_path.display()))?;
    Ok(())
}

async fn count_schema_objects(pool: &DbPool) -> Result<i64> {
    count_schema_objects_for_backend(pool, DbBackend::Sqlite).await
}

async fn count_schema_objects_for_backend(pool: &DbPool, backend: DbBackend) -> Result<i64> {
    match backend {
        DbBackend::Sqlite => {
    query_scalar::<sqlx::Any, i64>(
        "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table', 'view', 'index', 'trigger') AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_one(pool)
    .await
    .context("failed to count SQLite schema objects")
        }
        DbBackend::Postgres => query_scalar::<sqlx::Any, i64>(
            "SELECT COUNT(*) FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') \
             AND c.relkind IN ('r', 'v', 'm', 'S', 'f')",
        )
        .fetch_one(pool)
        .await
        .context("failed to count Postgres schema objects"),
        DbBackend::Mysql => query_scalar::<sqlx::Any, i64>(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()",
        )
        .fetch_one(pool)
        .await
        .context("failed to count MySQL schema objects"),
    }
}

fn compute_file_sha256(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn load_snapshot_manifest(artifact: &Path) -> Result<(PathBuf, PathBuf, SnapshotManifest)> {
    let manifest_path = if artifact.is_dir() {
        artifact.join("manifest.json")
    } else {
        artifact.to_path_buf()
    };
    let manifest_dir = manifest_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("manifest path has no parent directory"))?;
    let bytes = fs::read(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    let manifest: SnapshotManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", manifest_path.display()))?;
    Ok((manifest_dir, manifest_path, manifest))
}

fn database_config_for_restore(base: &DatabaseConfig, restore_path: &Path) -> DatabaseConfig {
    match &base.engine {
        DatabaseEngine::Sqlx => DatabaseConfig {
            engine: DatabaseEngine::Sqlx,
            resilience: base.resilience.clone(),
        },
        DatabaseEngine::TursoLocal(engine) => DatabaseConfig {
            engine: DatabaseEngine::TursoLocal(rest_macro_core::database::TursoLocalConfig {
                path: restore_path.display().to_string(),
                encryption_key_env: engine.encryption_key_env.clone(),
            }),
            resilience: base.resilience.clone(),
        },
    }
}

async fn build_backup_doctor_report(
    service: &compiler::ServiceSpec,
    database_url: &str,
    config_path: Option<&Path>,
) -> DoctorReport {
    let backend = service
        .resources
        .first()
        .map(|resource| resource.db)
        .unwrap_or(DbBackend::Sqlite);
    let mut checks = Vec::new();

    match &service.database.resilience {
        Some(resilience) => {
            if resilience.backup.is_some() {
                checks.push(DoctorCheck {
                    name: "backup_contract".to_owned(),
                    status: DoctorStatus::Pass,
                    detail: format!(
                        "Backup contract declared under `database.resilience` with profile {}.",
                        resilience_profile_name(resilience.profile)
                    ),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "backup_contract".to_owned(),
                    status: DoctorStatus::Warn,
                    detail: "No `database.resilience.backup` block is declared.".to_owned(),
                });
            }
        }
        None => checks.push(DoctorCheck {
            name: "backup_contract".to_owned(),
            status: DoctorStatus::Warn,
            detail: "No `database.resilience` contract is declared.".to_owned(),
        }),
    }

    checks.push(check_primary_connection(database_url, config_path).await);

    if let Some(backup) = service
        .database
        .resilience
        .as_ref()
        .and_then(|config| config.backup.as_ref())
    {
        if let Some(var_name) = backup.encryption_key_env.as_deref() {
            checks.push(check_env_or_file_present(
                "backup_encryption_env",
                var_name,
                "Backup encryption",
            ));
        } else {
            checks.push(DoctorCheck {
                name: "backup_encryption_env".to_owned(),
                status: DoctorStatus::Warn,
                detail: "No backup encryption env var is declared.".to_owned(),
            });
        }

        checks.push(check_restore_verification_requirement(
            backup.verify_restore,
        ));
        checks.push(check_backup_mode_backend_fit(backend, backup.mode));
    }

    build_doctor_report("backup", service, database_url, None, checks)
}

async fn build_replication_doctor_report(
    service: &compiler::ServiceSpec,
    database_url: &str,
    read_database_url: Option<&str>,
    config_path: Option<&Path>,
) -> DoctorReport {
    let backend = service
        .resources
        .first()
        .map(|resource| resource.db)
        .unwrap_or(DbBackend::Sqlite);
    let mut checks = Vec::new();
    let replication = service
        .database
        .resilience
        .as_ref()
        .and_then(|config| config.replication.as_ref());

    match replication {
        Some(replication) => checks.push(DoctorCheck {
            name: "replication_contract".to_owned(),
            status: DoctorStatus::Pass,
            detail: format!(
                "Replication contract declared with mode {} and {} read routing.",
                replication_mode_name(replication.mode),
                read_routing_name(replication.read_routing)
            ),
        }),
        None => checks.push(DoctorCheck {
            name: "replication_contract".to_owned(),
            status: DoctorStatus::Warn,
            detail: "No `database.resilience.replication` block is declared.".to_owned(),
        }),
    }

    checks.push(check_primary_connection(database_url, config_path).await);

    let resolved_read_database_url =
        resolve_replication_read_database_url(replication, read_database_url);
    match &resolved_read_database_url {
        Some(url) => {
            checks.push(DoctorCheck {
                name: "read_database_url".to_owned(),
                status: DoctorStatus::Pass,
                detail: "Resolved the read-replica database URL.".to_owned(),
            });
            if url == database_url {
                checks.push(DoctorCheck {
                    name: "read_topology_separation".to_owned(),
                    status: DoctorStatus::Warn,
                    detail:
                        "Primary and read database URLs are identical. This does not look like a separated topology."
                            .to_owned(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "read_topology_separation".to_owned(),
                    status: DoctorStatus::Pass,
                    detail: "Primary and read database URLs are distinct.".to_owned(),
                });
            }
            checks.push(check_read_connection(url, config_path).await);
            checks.extend(
                check_live_replication_role_state(backend, database_url, url, config_path).await,
            );
        }
        None => {
            let status = if replication.is_some_and(|config| {
                config.mode != DatabaseReplicationMode::None
                    && config.read_routing == DatabaseReadRoutingMode::Explicit
            }) {
                DoctorStatus::Fail
            } else {
                DoctorStatus::Warn
            };
            checks.push(DoctorCheck {
                name: "read_database_url".to_owned(),
                status,
                detail: "No read database URL could be resolved from arguments or the configured env var."
                    .to_owned(),
            });
        }
    }

    build_doctor_report(
        "replication",
        service,
        database_url,
        resolved_read_database_url,
        checks,
    )
}

async fn check_live_replication_role_state(
    backend: DbBackend,
    primary_database_url: &str,
    read_database_url: &str,
    config_path: Option<&Path>,
) -> Vec<DoctorCheck> {
    match backend {
        DbBackend::Sqlite => vec![DoctorCheck {
            name: "live_replication_role_state".to_owned(),
            status: DoctorStatus::Warn,
            detail:
                "SQLite does not expose a built-in replica-role signal here; validate any external replication story separately."
                    .to_owned(),
        }],
        DbBackend::Postgres => vec![
            check_postgres_primary_role(primary_database_url, config_path).await,
            check_postgres_read_role(read_database_url, config_path).await,
        ],
        DbBackend::Mysql => vec![
            check_mysql_primary_role(primary_database_url, config_path).await,
            check_mysql_read_role(read_database_url, config_path).await,
        ],
    }
}

async fn check_postgres_primary_role(
    database_url: &str,
    config_path: Option<&Path>,
) -> DoctorCheck {
    match query_postgres_in_recovery(database_url, config_path).await {
        Ok(false) => DoctorCheck {
            name: "primary_role_state".to_owned(),
            status: DoctorStatus::Pass,
            detail: "Primary Postgres URL reports pg_is_in_recovery() = false.".to_owned(),
        },
        Ok(true) => DoctorCheck {
            name: "primary_role_state".to_owned(),
            status: DoctorStatus::Fail,
            detail:
                "Primary Postgres URL reports pg_is_in_recovery() = true, which looks like a replica target."
                    .to_owned(),
        },
        Err(error) => DoctorCheck {
            name: "primary_role_state".to_owned(),
            status: DoctorStatus::Fail,
            detail: format!("Failed to inspect Postgres primary role state: {error}"),
        },
    }
}

async fn check_postgres_read_role(database_url: &str, config_path: Option<&Path>) -> DoctorCheck {
    match query_postgres_in_recovery(database_url, config_path).await {
        Ok(true) => DoctorCheck {
            name: "read_role_state".to_owned(),
            status: DoctorStatus::Pass,
            detail: "Read Postgres URL reports pg_is_in_recovery() = true.".to_owned(),
        },
        Ok(false) => DoctorCheck {
            name: "read_role_state".to_owned(),
            status: DoctorStatus::Fail,
            detail:
                "Read Postgres URL reports pg_is_in_recovery() = false, so it does not look like a replica."
                    .to_owned(),
        },
        Err(error) => DoctorCheck {
            name: "read_role_state".to_owned(),
            status: DoctorStatus::Fail,
            detail: format!("Failed to inspect Postgres read role state: {error}"),
        },
    }
}

async fn check_mysql_primary_role(database_url: &str, config_path: Option<&Path>) -> DoctorCheck {
    match query_mysql_read_only_state(database_url, config_path).await {
        Ok(false) => DoctorCheck {
            name: "primary_role_state".to_owned(),
            status: DoctorStatus::Pass,
            detail:
                "Primary MySQL URL reports read_only = off and super_read_only = off.".to_owned(),
        },
        Ok(true) => DoctorCheck {
            name: "primary_role_state".to_owned(),
            status: DoctorStatus::Fail,
            detail:
                "Primary MySQL URL reports read_only/super_read_only enabled, so it does not look writable."
                    .to_owned(),
        },
        Err(error) => DoctorCheck {
            name: "primary_role_state".to_owned(),
            status: DoctorStatus::Fail,
            detail: format!("Failed to inspect MySQL primary role state: {error}"),
        },
    }
}

async fn check_mysql_read_role(database_url: &str, config_path: Option<&Path>) -> DoctorCheck {
    match query_mysql_read_only_state(database_url, config_path).await {
        Ok(true) => DoctorCheck {
            name: "read_role_state".to_owned(),
            status: DoctorStatus::Pass,
            detail:
                "Read MySQL URL reports read_only or super_read_only enabled.".to_owned(),
        },
        Ok(false) => DoctorCheck {
            name: "read_role_state".to_owned(),
            status: DoctorStatus::Fail,
            detail:
                "Read MySQL URL reports read_only = off and super_read_only = off, so it does not look like a replica/read-only target."
                    .to_owned(),
        },
        Err(error) => DoctorCheck {
            name: "read_role_state".to_owned(),
            status: DoctorStatus::Fail,
            detail: format!("Failed to inspect MySQL read role state: {error}"),
        },
    }
}

async fn query_postgres_in_recovery(
    database_url: &str,
    config_path: Option<&Path>,
) -> Result<bool> {
    let pool = connect_database(database_url, config_path)
        .await
        .with_context(|| format!("failed to connect to {database_url}"))?;
    let value = query_scalar::<sqlx::Any, bool>("SELECT pg_is_in_recovery()")
        .fetch_one(&pool)
        .await
        .context("failed to query pg_is_in_recovery()")?;
    Ok(value)
}

async fn query_mysql_read_only_state(
    database_url: &str,
    config_path: Option<&Path>,
) -> Result<bool> {
    let pool = connect_database(database_url, config_path)
        .await
        .with_context(|| format!("failed to connect to {database_url}"))?;
    let read_only = query_scalar::<sqlx::Any, i64>("SELECT @@global.read_only")
        .fetch_one(&pool)
        .await
        .context("failed to query @@global.read_only")?;

    let super_read_only = match query("SELECT @@global.super_read_only")
        .fetch_one(&pool)
        .await
    {
        Ok(row) => row.try_get::<i64, _>(0).unwrap_or_default(),
        Err(_) => 0,
    };

    Ok(read_only != 0 || super_read_only != 0)
}

fn build_backup_guidance(backend: DbBackend, database: &DatabaseConfig) -> Vec<String> {
    let mut guidance = Vec::new();
    match &database.resilience {
        Some(config) => {
            if let Some(backup) = &config.backup {
                guidance.push(format!(
                    "Use a {} backup flow with {} storage.",
                    backup_mode_name(backup.mode),
                    backup_target_name(backup.target)
                ));
                if backup.required {
                    guidance.push("Treat backup success as a deployment requirement.".to_owned());
                }
                if let Some(max_age) = backup.max_age.as_deref() {
                    guidance.push(format!(
                        "Monitor backup freshness and alert when artifacts exceed {}.",
                        max_age
                    ));
                }
                if backup.verify_restore {
                    guidance.push(
                        "Run restore verification regularly against disposable environments."
                            .to_owned(),
                    );
                }
                if let Some(var_name) = backup.encryption_key_env.as_deref() {
                    guidance.push(format!(
                        "Provision `{}` for backup artifact encryption or envelope-key access.",
                        var_name
                    ));
                }
                if let Some(retention) = &backup.retention {
                    let mut periods = Vec::new();
                    if let Some(days) = retention.daily {
                        periods.push(format!("daily={days}"));
                    }
                    if let Some(weeks) = retention.weekly {
                        periods.push(format!("weekly={weeks}"));
                    }
                    if let Some(months) = retention.monthly {
                        periods.push(format!("monthly={months}"));
                    }
                    if !periods.is_empty() {
                        guidance.push(format!("Retention targets: {}.", periods.join(", ")));
                    }
                }
            } else {
                guidance.push(
                    "Add `database.resilience.backup` to declare the intended backup posture."
                        .to_owned(),
                );
            }
        }
        None => guidance.push(
            "Add `database.resilience` to turn this advisory plan into a checked contract."
                .to_owned(),
        ),
    }

    match (backend, &database.engine) {
        (DbBackend::Sqlite, DatabaseEngine::TursoLocal(_)) => {
            guidance.push(
                "Prefer a consistent database-native snapshot/export flow instead of ad-hoc file copies while writes are active."
                    .to_owned(),
            );
            guidance.push(
                "Keep at least one off-host copy of each verified backup artifact.".to_owned(),
            );
        }
        (DbBackend::Sqlite, DatabaseEngine::Sqlx) => {
            guidance.push(
                "Use a SQLite-safe snapshot/export flow and document file-locking expectations."
                    .to_owned(),
            );
        }
        (DbBackend::Postgres, _) => {
            guidance.push(
                "Use native Postgres tooling. PITR requires base backups plus WAL archiving; logical dumps alone are not enough."
                    .to_owned(),
            );
        }
        (DbBackend::Mysql, _) => {
            guidance.push(
                "Use native MySQL tooling. PITR requires physical or full backups plus binlog retention."
                    .to_owned(),
            );
        }
    }

    guidance
}

fn build_replication_guidance(backend: DbBackend, database: &DatabaseConfig) -> Vec<String> {
    let mut guidance = Vec::new();
    match &database.resilience {
        Some(config) => match &config.replication {
            Some(replication) => {
                guidance.push(format!(
                    "Replication mode: {}.",
                    replication_mode_name(replication.mode)
                ));
                if let Some(var_name) = replication.read_url_env.as_deref() {
                    guidance.push(format!(
                        "Use `{}` for the explicit read connection.",
                        var_name
                    ));
                }
                if let Some(max_lag) = replication.max_lag.as_deref() {
                    guidance.push(format!(
                        "Alert when replica lag exceeds {}.",
                        max_lag
                    ));
                }
                if let Some(count) = replication.replicas_expected {
                    guidance.push(format!(
                        "Validate that at least {} replica endpoint(s) are provisioned.",
                        count
                    ));
                }
                if replication.read_routing == DatabaseReadRoutingMode::Explicit {
                    guidance.push(
                        "Keep read routing opt-in and never route writes to the replica pool."
                            .to_owned(),
                    );
                }
            }
            None => guidance.push(
                "No replication contract is declared. Generated servers should treat all connections as primary-only."
                    .to_owned(),
            ),
        },
        None => guidance.push(
            "No replication contract is declared. Add `database.resilience.replication` before introducing replica-aware runtime behavior."
                .to_owned(),
        ),
    }

    match backend {
        DbBackend::Sqlite => guidance.push(
            "SQLite deployments should assume primary-only operation unless an external replication story is documented separately."
                .to_owned(),
        ),
        DbBackend::Postgres => guidance.push(
            "For Postgres, validate primary/read URL separation and document promotion or failover ownership clearly."
                .to_owned(),
        ),
        DbBackend::Mysql => guidance.push(
            "For MySQL, validate primary/read URL separation and monitor replication lag alongside backup freshness."
                .to_owned(),
        ),
    }

    guidance
}

fn build_doctor_report(
    kind: &str,
    service: &compiler::ServiceSpec,
    primary_database_url: &str,
    read_database_url: Option<String>,
    checks: Vec<DoctorCheck>,
) -> DoctorReport {
    let backend = service
        .resources
        .first()
        .map(|resource| resource.db)
        .unwrap_or(DbBackend::Sqlite);
    let healthy = checks
        .iter()
        .all(|check| check.status != DoctorStatus::Fail);
    DoctorReport {
        kind: kind.to_owned(),
        service_module: service.module_ident.to_string(),
        sql_dialect: sql_dialect_name(backend).to_owned(),
        runtime_engine: runtime_engine_name(&service.database),
        primary_database_url: primary_database_url.to_owned(),
        read_database_url,
        healthy,
        checks,
    }
}

async fn check_primary_connection(database_url: &str, config_path: Option<&Path>) -> DoctorCheck {
    check_database_connection("primary_connection", "Primary", database_url, config_path).await
}

async fn check_read_connection(database_url: &str, config_path: Option<&Path>) -> DoctorCheck {
    check_database_connection("read_connection", "Read", database_url, config_path).await
}

async fn check_database_connection(
    name: &str,
    label: &str,
    database_url: &str,
    config_path: Option<&Path>,
) -> DoctorCheck {
    let start = Instant::now();
    match connect_database(database_url, config_path).await {
        Ok(pool) => match query_scalar::<sqlx::Any, i64>("SELECT 1")
            .fetch_one(&pool)
            .await
        {
            Ok(_) => DoctorCheck {
                name: name.to_owned(),
                status: DoctorStatus::Pass,
                detail: format!(
                    "{} database connection succeeded in {:?}.",
                    label,
                    start.elapsed()
                ),
            },
            Err(error) => DoctorCheck {
                name: name.to_owned(),
                status: DoctorStatus::Fail,
                detail: format!("{label} database probe failed: {error}"),
            },
        },
        Err(error) => DoctorCheck {
            name: name.to_owned(),
            status: DoctorStatus::Fail,
            detail: format!("{label} database connection failed: {error}"),
        },
    }
}

fn check_env_or_file_present(name: &str, var_name: &str, label: &str) -> DoctorCheck {
    if let Some(source) = resolve_env_or_file_source(var_name) {
        DoctorCheck {
            name: name.to_owned(),
            status: DoctorStatus::Pass,
            detail: format!("{label} secret/source is available via {source}."),
        }
    } else {
        DoctorCheck {
            name: name.to_owned(),
            status: DoctorStatus::Fail,
            detail: format!(
                "{label} source is missing. Set `{}` or `{}_FILE`.",
                var_name, var_name
            ),
        }
    }
}

fn check_restore_verification_requirement(required: bool) -> DoctorCheck {
    if required {
        DoctorCheck {
            name: "restore_verification".to_owned(),
            status: DoctorStatus::Warn,
            detail:
                "Restore verification is required by contract. Automate and document restore drills before relying on this service in production."
                    .to_owned(),
        }
    } else {
        DoctorCheck {
            name: "restore_verification".to_owned(),
            status: DoctorStatus::Warn,
            detail: "Restore verification is not required by contract. Consider enabling it for production workloads."
                .to_owned(),
        }
    }
}

fn check_backup_mode_backend_fit(backend: DbBackend, mode: DatabaseBackupMode) -> DoctorCheck {
    let (status, detail) = match (backend, mode) {
        (DbBackend::Sqlite, DatabaseBackupMode::Snapshot) => (
            DoctorStatus::Pass,
            "SQLite snapshot backups are a sensible starting point for single-node deployments."
                .to_owned(),
        ),
        (DbBackend::Sqlite, DatabaseBackupMode::Pitr) => (
            DoctorStatus::Warn,
            "SQLite does not have a native PITR story comparable to WAL/binlog-backed databases."
                .to_owned(),
        ),
        (DbBackend::Postgres | DbBackend::Mysql, DatabaseBackupMode::Snapshot) => (
            DoctorStatus::Warn,
            "Snapshot-only backups may not be sufficient for serious Postgres/MySQL recovery targets."
                .to_owned(),
        ),
        (DbBackend::Postgres, DatabaseBackupMode::Pitr) => (
            DoctorStatus::Pass,
            "Postgres PITR aligns with base-backup plus WAL retention workflows.".to_owned(),
        ),
        (DbBackend::Mysql, DatabaseBackupMode::Pitr) => (
            DoctorStatus::Pass,
            "MySQL PITR aligns with full/physical backup plus binlog retention workflows."
                .to_owned(),
        ),
        _ => (
            DoctorStatus::Pass,
            format!(
                "Configured backup mode {} is accepted for {}.",
                backup_mode_name(mode),
                sql_dialect_name(backend)
            ),
        ),
    };

    DoctorCheck {
        name: "backup_mode_backend_fit".to_owned(),
        status,
        detail,
    }
}

fn resolve_replication_read_database_url(
    replication: Option<&rest_macro_core::database::DatabaseReplicationConfig>,
    read_database_url: Option<&str>,
) -> Option<String> {
    read_database_url.map(str::to_owned).or_else(|| {
        replication
            .and_then(|config| config.read_url_env.as_deref())
            .and_then(resolve_env_or_file_value)
    })
}

fn resolve_env_or_file_source(var_name: &str) -> Option<String> {
    if std::env::var_os(var_name).is_some() {
        Some(format!("`{var_name}`"))
    } else {
        let file_var = format!("{var_name}_FILE");
        std::env::var_os(&file_var).map(|_| format!("`{file_var}`"))
    }
}

fn resolve_env_or_file_value(var_name: &str) -> Option<String> {
    if let Ok(value) = std::env::var(var_name)
        && !value.trim().is_empty()
    {
        return Some(value);
    }

    let file_var = format!("{var_name}_FILE");
    let file_path = std::env::var(&file_var).ok()?;
    let value = fs::read_to_string(&file_path).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn render_doctor_report(report: &DoctorReport, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Text => Ok(render_text_doctor_report(report)),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .context("failed to serialize doctor report to JSON"),
    }
}

fn render_text_doctor_report(report: &DoctorReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("Kind: {}\n", report.kind));
    output.push_str(&format!("Service: {}\n", report.service_module));
    output.push_str(&format!("SQL dialect: {}\n", report.sql_dialect));
    output.push_str(&format!("Runtime engine: {}\n", report.runtime_engine));
    output.push_str(&format!(
        "Primary database URL: {}\n",
        report.primary_database_url
    ));
    if let Some(read_database_url) = &report.read_database_url {
        output.push_str(&format!("Read database URL: {}\n", read_database_url));
    }
    output.push_str(&format!(
        "Healthy: {}\n\n",
        if report.healthy { "yes" } else { "no" }
    ));

    output.push_str("Checks:\n");
    for check in &report.checks {
        output.push_str(&format!(
            "- [{}] {}: {}\n",
            match check.status {
                DoctorStatus::Pass => "pass",
                DoctorStatus::Warn => "warn",
                DoctorStatus::Fail => "fail",
            },
            check.name,
            check.detail
        ));
    }
    output
}

fn write_rendered_output(
    rendered: String,
    output: Option<&Path>,
    force: bool,
    label: &str,
) -> Result<()> {
    if let Some(output) = output {
        if output.exists() && !force {
            bail!(
                "{} already exists at {} (use --force to overwrite)",
                label,
                output.display()
            );
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(output, rendered)
            .with_context(|| format!("failed to write {} to {}", label, output.display()))?;
        println!(
            "{} {}",
            format!("Generated {label}:").green().bold(),
            output.display()
        );
    } else {
        print!("{rendered}");
        if !rendered.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

fn render_text_plan(plan: &BackupPlan) -> String {
    let mut output = String::new();
    output.push_str(&format!("Service: {}\n", plan.service_module));
    output.push_str(&format!("SQL dialect: {}\n", plan.sql_dialect));
    output.push_str(&format!("Runtime engine: {}\n", plan.runtime_engine));
    output.push_str(&format!(
        "Default database URL: {}\n",
        plan.default_database_url
    ));
    output.push('\n');

    output.push_str("Summary:\n");
    if plan.summary.is_empty() {
        output.push_str("- No resilience contract declared.\n");
    } else {
        for line in &plan.summary {
            output.push_str(&format!("- {line}\n"));
        }
    }
    output.push('\n');

    output.push_str("Backup guidance:\n");
    for line in &plan.backup_guidance {
        output.push_str(&format!("- {line}\n"));
    }
    output.push('\n');

    output.push_str("Replication guidance:\n");
    for line in &plan.replication_guidance {
        output.push_str(&format!("- {line}\n"));
    }

    if !plan.warnings.is_empty() {
        output.push('\n');
        output.push_str("Warnings:\n");
        for line in &plan.warnings {
            output.push_str(&format!("- {line}\n"));
        }
    }

    output
}

fn render_text_verify_restore(result: &VerifyRestoreResult) -> String {
    let mut output = String::new();
    output.push_str(&format!("Artifact directory: {}\n", result.artifact_dir));
    output.push_str(&format!("Manifest: {}\n", result.manifest_path));
    output.push_str(&format!(
        "Artifact kind: {}\n",
        backup_artifact_kind_name(result.artifact_kind)
    ));
    output.push_str(&format!("Artifact file: {}\n", result.artifact_path));
    if let Some(restore_target) = result.restore_target.as_deref() {
        output.push_str(&format!("Restore target: {}\n", restore_target));
    }
    output.push_str(&format!(
        "Checksum verified: {}\n",
        if result.checksum_verified {
            "yes"
        } else {
            "no"
        }
    ));
    output.push_str(&format!("Integrity check: {}\n", result.integrity_check));
    output.push_str(&format!(
        "Schema objects: expected {}, restored {}\n",
        result.schema_object_count_expected, result.schema_object_count_actual
    ));
    output.push_str(&format!(
        "Healthy: {}\n",
        if result.healthy { "yes" } else { "no" }
    ));
    output
}

fn print_rendered_transfer_result(result: &RemoteArtifactTransferResult, format: OutputFormat) {
    let rendered = match format {
        OutputFormat::Text => render_text_transfer_result(result),
        OutputFormat::Json => serde_json::to_string_pretty(result)
            .unwrap_or_else(|_| "{\"error\":\"failed to serialize transfer result\"}".to_owned()),
    };
    print!("{rendered}");
    if !rendered.ends_with('\n') {
        println!();
    }
}

fn render_text_transfer_result(result: &RemoteArtifactTransferResult) -> String {
    let mut output = String::new();
    output.push_str(&format!("Remote URI: {}\n", result.remote_uri));
    output.push_str(&format!("Artifact directory: {}\n", result.artifact_dir));
    output.push_str(&format!("Files transferred: {}\n", result.file_count));
    output.push_str(&format!("Total bytes: {}\n", result.total_bytes));
    output.push_str("Files:\n");
    for file in &result.files {
        output.push_str(&format!("- {file}\n"));
    }
    output
}

fn sql_dialect_name(db: DbBackend) -> &'static str {
    match db {
        DbBackend::Sqlite => "Sqlite",
        DbBackend::Postgres => "Postgres",
        DbBackend::Mysql => "Mysql",
    }
}

fn runtime_engine_name(database: &DatabaseConfig) -> String {
    match &database.engine {
        DatabaseEngine::Sqlx => "Sqlx".to_owned(),
        DatabaseEngine::TursoLocal(engine) => format!("TursoLocal({})", engine.path),
    }
}

fn resilience_profile_name(profile: DatabaseResilienceProfile) -> &'static str {
    match profile {
        DatabaseResilienceProfile::SingleNode => "SingleNode",
        DatabaseResilienceProfile::Pitr => "Pitr",
        DatabaseResilienceProfile::Ha => "Ha",
    }
}

fn backup_mode_name(mode: DatabaseBackupMode) -> &'static str {
    match mode {
        DatabaseBackupMode::Snapshot => "Snapshot",
        DatabaseBackupMode::Logical => "Logical",
        DatabaseBackupMode::Physical => "Physical",
        DatabaseBackupMode::Pitr => "Pitr",
    }
}

fn backup_artifact_kind_name(kind: BackupArtifactKind) -> &'static str {
    match kind {
        BackupArtifactKind::Snapshot => "snapshot",
        BackupArtifactKind::LogicalDump => "logical_dump",
    }
}

fn backup_target_name(target: DatabaseBackupTarget) -> &'static str {
    match target {
        DatabaseBackupTarget::Local => "Local",
        DatabaseBackupTarget::S3 => "S3",
        DatabaseBackupTarget::Gcs => "Gcs",
        DatabaseBackupTarget::AzureBlob => "AzureBlob",
        DatabaseBackupTarget::Custom => "Custom",
    }
}

fn replication_mode_name(mode: DatabaseReplicationMode) -> &'static str {
    match mode {
        DatabaseReplicationMode::None => "None",
        DatabaseReplicationMode::ReadReplica => "ReadReplica",
        DatabaseReplicationMode::HotStandby => "HotStandby",
        DatabaseReplicationMode::ManagedExternal => "ManagedExternal",
    }
}

fn read_routing_name(mode: DatabaseReadRoutingMode) -> &'static str {
    match mode {
        DatabaseReadRoutingMode::Off => "Off",
        DatabaseReadRoutingMode::Explicit => "Explicit",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        OutputFormat, build_backup_doctor_report, build_replication_doctor_report,
        collect_artifact_files, create_snapshot_artifact, parse_database_url,
        parse_mysql_dump_database_name, parse_s3_remote_location, relative_path_from_s3_key,
        render_backup_plan, rewrite_database_url_for_docker, verify_backup_artifact,
    };
    use rest_macro_core::{compiler, db::query};

    use crate::commands::db::connect_database;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn load_service(name: &str) -> compiler::ServiceSpec {
        compiler::load_service_from_path(&fixture_path(name)).expect("fixture should load")
    }

    #[test]
    fn render_backup_plan_includes_resilience_contract_details() {
        let rendered = render_backup_plan(
            &load_service("backup_resilience_api.eon"),
            OutputFormat::Text,
        )
        .expect("backup plan should render");

        assert!(rendered.contains("Service: backup_resilience_api"));
        assert!(rendered.contains("Resilience profile: Pitr"));
        assert!(rendered.contains("Backup: Pitr to S3"));
        assert!(rendered.contains("Replication: ReadReplica with Explicit read routing"));
        assert!(rendered.contains("DATABASE_READ_URL"));
    }

    #[test]
    fn render_backup_plan_json_serializes_resilience_config() {
        let rendered = render_backup_plan(
            &load_service("backup_resilience_api.eon"),
            OutputFormat::Json,
        )
        .expect("backup plan json should render");

        assert!(rendered.contains("\"profile\": \"Pitr\""));
        assert!(rendered.contains("\"mode\": \"ReadReplica\""));
        assert!(rendered.contains("\"read_url_env\": \"DATABASE_READ_URL\""));
    }

    #[test]
    fn parse_s3_remote_location_supports_bucket_and_prefix() {
        let location =
            parse_s3_remote_location("s3://backup-bucket/path/to/run1").expect("s3 uri parses");
        assert_eq!(location.bucket, "backup-bucket");
        assert_eq!(location.prefix, "path/to/run1");

        let bucket_only = parse_s3_remote_location("s3://backup-bucket").expect("bucket parses");
        assert_eq!(bucket_only.bucket, "backup-bucket");
        assert!(bucket_only.prefix.is_empty());
    }

    #[test]
    fn relative_path_from_s3_key_rejects_out_of_prefix_objects() {
        assert_eq!(
            relative_path_from_s3_key("backups/run1", "backups/run1/manifest.json")
                .expect("relative path should resolve"),
            "manifest.json"
        );
        assert!(relative_path_from_s3_key("backups/run1", "backups/other/manifest.json").is_err());
    }

    #[test]
    fn collect_artifact_files_recurses_and_normalizes_relative_paths() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_collect_artifact_{stamp}"));
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("artifact dir should exist");
        fs::write(root.join("manifest.json"), "{}").expect("manifest should write");
        fs::write(nested.join("snapshot.db"), "db").expect("snapshot should write");

        let files = collect_artifact_files(&root).expect("artifact files should collect");
        let relative_paths: Vec<_> = files.into_iter().map(|(_, path)| path).collect();
        assert_eq!(relative_paths, vec!["manifest.json", "nested/snapshot.db"]);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn parse_database_url_extracts_connection_parts() {
        let parsed = parse_database_url("mysql://root:password@127.0.0.1:3306/app_db")
            .expect("database url should parse");
        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, 3306);
        assert_eq!(parsed.username, "root");
        assert_eq!(parsed.password.as_deref(), Some("password"));
        assert_eq!(parsed.database, "app_db");
    }

    #[test]
    fn rewrite_database_url_for_docker_rewrites_localhost_outside_linux() {
        let rewritten =
            rewrite_database_url_for_docker("postgres://postgres:secret@127.0.0.1:5432/app")
                .expect("database url should rewrite");
        if cfg!(target_os = "linux") {
            assert_eq!(rewritten, "postgres://postgres:secret@127.0.0.1:5432/app");
        } else {
            assert_eq!(
                rewritten,
                "postgres://postgres:secret@host.docker.internal:5432/app"
            );
        }
    }

    #[test]
    fn parse_mysql_dump_database_name_reads_create_database_or_use_statements() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_mysql_dump_name_{stamp}.sql"));
        fs::write(
            &root,
            "CREATE DATABASE /*!32312 IF NOT EXISTS*/ `family_app`;\nUSE `family_app`;\n",
        )
        .expect("dump should write");

        let database_name =
            parse_mysql_dump_database_name(&root).expect("database name should parse");
        assert_eq!(database_name, "family_app");

        let _ = fs::remove_file(root);
    }

    #[tokio::test]
    async fn backup_doctor_reports_primary_connectivity_and_backup_env() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_backup_doctor_{stamp}"));
        fs::create_dir_all(&root).expect("temp root should exist");
        let config = root.join("backup_doctor_sqlite_api.eon");
        fs::copy(fixture_path("backup_doctor_sqlite_api.eon"), &config)
            .expect("fixture should copy");
        let service = compiler::load_service_from_path(&config).expect("service should load");
        let database_url = format!("sqlite:{}?mode=rwc", root.join("doctor.db").display());

        unsafe {
            std::env::set_var("BACKUP_ENCRYPTION_KEY", "example-secret");
        }

        let report = build_backup_doctor_report(&service, &database_url, Some(&config)).await;
        assert!(report.healthy);
        assert!(report.checks.iter().any(|check| {
            check.name == "primary_connection" && matches!(check.status, super::DoctorStatus::Pass)
        }));
        assert!(report.checks.iter().any(|check| {
            check.name == "backup_encryption_env"
                && matches!(check.status, super::DoctorStatus::Pass)
        }));

        unsafe {
            std::env::remove_var("BACKUP_ENCRYPTION_KEY");
        }
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn replication_doctor_fails_when_read_database_url_cannot_be_resolved() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_replication_doctor_{stamp}"));
        fs::create_dir_all(&root).expect("temp root should exist");
        let config = root.join("backup_doctor_sqlite_api.eon");
        fs::copy(fixture_path("backup_doctor_sqlite_api.eon"), &config)
            .expect("fixture should copy");
        let service = compiler::load_service_from_path(&config).expect("service should load");
        let database_url = format!("sqlite:{}?mode=rwc", root.join("doctor.db").display());

        unsafe {
            std::env::remove_var("DATABASE_READ_URL");
            std::env::remove_var("DATABASE_READ_URL_FILE");
        }

        let report =
            build_replication_doctor_report(&service, &database_url, None, Some(&config)).await;
        assert!(!report.healthy);
        assert!(report.checks.iter().any(|check| {
            check.name == "read_database_url" && matches!(check.status, super::DoctorStatus::Fail)
        }));

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn snapshot_and_verify_restore_work_for_sqlite_service() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_snapshot_verify_{stamp}"));
        fs::create_dir_all(&root).expect("temp root should exist");
        let config = root.join("backup_doctor_sqlite_api.eon");
        fs::copy(fixture_path("backup_doctor_sqlite_api.eon"), &config)
            .expect("fixture should copy");
        let service = compiler::load_service_from_path(&config).expect("service should load");
        let database_url = format!("sqlite:{}?mode=rwc", root.join("app.db").display());
        let pool = connect_database(&database_url, Some(&config))
            .await
            .expect("database should connect");
        let migration_sql =
            compiler::render_service_migration_sql(&service).expect("migration should render");
        pool.execute_batch(&migration_sql)
            .await
            .expect("migration should apply");
        query("INSERT INTO note (title) VALUES (?)")
            .bind("hello")
            .execute(&pool)
            .await
            .expect("seed insert should work");

        let artifact_dir = root.join("artifact");
        let result =
            create_snapshot_artifact(&config, &database_url, Some(&config), &artifact_dir, false)
                .await
                .expect("snapshot should succeed");
        assert!(PathBuf::from(&result.manifest_path).is_file());
        assert!(PathBuf::from(&result.snapshot_path).is_file());

        let verify = verify_backup_artifact(&artifact_dir)
            .await
            .expect("verify-restore should succeed");
        assert!(verify.checksum_verified);
        assert_eq!(verify.integrity_check.to_ascii_lowercase(), "ok");
        assert!(verify.healthy);
        assert!(verify.schema_object_count_actual >= 1);
        assert!(matches!(
            verify.artifact_kind,
            super::BackupArtifactKind::Snapshot
        ));
        assert!(PathBuf::from(&verify.artifact_path).is_file());

        let _ = fs::remove_dir_all(root);
    }
}
