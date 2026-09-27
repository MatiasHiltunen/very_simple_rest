//! Driver-independent database configuration, path resolution, and engine startup.

use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config_secret::SecretRef;
#[cfg(feature = "turso-local")]
use crate::config_secret::load_secret;

/// Database engine and declared resilience settings.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database engine selection.
    #[serde(default)]
    pub engine: DatabaseEngine,
    /// Optional resilience contract.
    #[serde(default)]
    pub resilience: Option<DatabaseResilienceConfig>,
}

/// Engine selected for service database connections.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum DatabaseEngine {
    /// Use SQLx with the service database URL.
    #[default]
    Sqlx,
    /// Use an embedded local Turso database.
    TursoLocal(TursoLocalConfig),
}

/// Local Turso database path and optional encryption secret.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TursoLocalConfig {
    /// Database file path, or `:memory:`.
    pub path: String,
    /// Secret reference for encryption key material.
    #[serde(default)]
    pub encryption_key: Option<SecretRef>,
}

/// Declared backup and replication requirements.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DatabaseResilienceConfig {
    /// Selected resilience profile.
    #[serde(default)]
    pub profile: DatabaseResilienceProfile,
    /// Optional backup requirements.
    #[serde(default)]
    pub backup: Option<DatabaseBackupConfig>,
    /// Optional replication requirements.
    #[serde(default)]
    pub replication: Option<DatabaseReplicationConfig>,
}

/// Resilience profile preserved in compiled service configuration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DatabaseResilienceProfile {
    /// One database node.
    #[default]
    SingleNode,
    /// Point-in-time recovery.
    Pitr,
    /// High availability.
    Ha,
}

/// Backup policy and storage requirements.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DatabaseBackupConfig {
    /// Whether backup readiness is required.
    #[serde(default = "default_true")]
    pub required: bool,
    /// Selected mechanism.
    pub mode: DatabaseBackupMode,
    /// Backup storage destination.
    #[serde(default)]
    pub target: DatabaseBackupTarget,
    /// Whether restoring backup artifacts must be verified.
    #[serde(default)]
    pub verify_restore: bool,
    /// Maximum acceptable backup age.
    #[serde(default)]
    pub max_age: Option<String>,
    /// Secret reference for encryption key material.
    #[serde(default)]
    pub encryption_key: Option<SecretRef>,
    /// Optional backup retention policy.
    #[serde(default)]
    pub retention: Option<DatabaseBackupRetention>,
}

/// Configured backup mechanism.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DatabaseBackupMode {
    /// Database snapshots.
    #[default]
    Snapshot,
    /// Logical database dumps.
    Logical,
    /// Physical database backups.
    Physical,
    /// Point-in-time recovery.
    Pitr,
}

/// Storage destination for backup artifacts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DatabaseBackupTarget {
    /// Local filesystem.
    #[default]
    Local,
    /// S3-compatible object storage.
    S3,
    /// Google Cloud Storage.
    Gcs,
    /// Azure Blob Storage.
    AzureBlob,
    /// User-configured storage provider.
    Custom,
}

/// Numbers of daily, weekly, and monthly backups to retain.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DatabaseBackupRetention {
    /// Daily backups retained.
    #[serde(default)]
    pub daily: Option<u32>,
    /// Weekly backups retained.
    #[serde(default)]
    pub weekly: Option<u32>,
    /// Monthly backups retained.
    #[serde(default)]
    pub monthly: Option<u32>,
}

/// Replication mode and optional read routing settings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DatabaseReplicationConfig {
    /// Selected mechanism.
    pub mode: DatabaseReplicationMode,
    /// Read routing mode.
    #[serde(default)]
    pub read_routing: DatabaseReadRoutingMode,
    /// Optional secret reference for the replica URL.
    #[serde(default)]
    pub read_url: Option<SecretRef>,
    /// Maximum acceptable replication lag.
    #[serde(default)]
    pub max_lag: Option<String>,
    /// Expected number of replicas.
    #[serde(default)]
    pub replicas_expected: Option<u32>,
}

/// Configured database replication mechanism.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DatabaseReplicationMode {
    /// No replication.
    #[default]
    None,
    /// Read replica connections.
    ReadReplica,
    /// Hot standby nodes.
    HotStandby,
    /// Externally managed replication.
    ManagedExternal,
}

/// How reads select a replica connection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DatabaseReadRoutingMode {
    /// Use the primary database for reads.
    #[default]
    Off,
    /// Use explicitly configured read routing.
    Explicit,
}

/// Default environment binding used for local Turso encryption keys.
pub const DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV: &str = "TURSO_ENCRYPTION_KEY";

const fn default_true() -> bool {
    true
}

/// Build a SQLite connection URL for a file or in-memory database.
pub fn sqlite_url_for_path(path: &str) -> String {
    if path == ":memory:" {
        "sqlite::memory:".to_owned()
    } else {
        format!("sqlite:{path}?mode=rwc")
    }
}

/// Resolve the base directory, including bundled service configurations.
pub fn service_base_dir_from_config_path(config_path: &Path) -> PathBuf {
    let config_dir = config_path
        .parent()
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));

    if config_dir.extension().and_then(|ext| ext.to_str()) == Some("bundle") {
        config_dir
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or(config_dir)
    } else {
        config_dir
    }
}

/// Rebase a database file path while preserving absolute and memory paths.
pub fn resolve_relative_database_path(base_dir: &Path, path: &str) -> String {
    if path.is_empty() || path == ":memory:" {
        return path.to_owned();
    }

    let candidate = Path::new(path);
    if candidate.is_absolute() {
        candidate.to_string_lossy().into_owned()
    } else {
        base_dir.join(candidate).to_string_lossy().into_owned()
    }
}

/// Rebase SQLite file URLs while preserving query parameters and other drivers.
pub fn resolve_database_url(database_url: &str, base_dir: &Path) -> String {
    let Some(sqlite_path) = database_url.strip_prefix("sqlite:") else {
        return database_url.to_owned();
    };
    if sqlite_path == ":memory:" {
        return database_url.to_owned();
    }

    let (path, suffix) = if let Some((path, query)) = sqlite_path.split_once('?') {
        (path, format!("?{query}"))
    } else {
        (sqlite_path, String::new())
    };

    let resolved = resolve_relative_database_path(base_dir, path);
    format!("sqlite:{resolved}{suffix}")
}

/// Rebase configured engine paths and retain resilience settings.
pub fn resolve_database_config(config: &DatabaseConfig, base_dir: &Path) -> DatabaseConfig {
    match &config.engine {
        DatabaseEngine::Sqlx => config.clone(),
        DatabaseEngine::TursoLocal(engine) => DatabaseConfig {
            engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: resolve_relative_database_path(base_dir, &engine.path),
                encryption_key: engine.encryption_key.clone(),
            }),
            resilience: config.resilience.clone(),
        },
    }
}

/// Initialize the configured engine or report an unsupported feature.
pub async fn prepare_database_engine(config: &DatabaseConfig) -> Result<()> {
    match &config.engine {
        DatabaseEngine::Sqlx => Ok(()),
        DatabaseEngine::TursoLocal(engine) => {
            prepare_turso_local(engine).await?;
            Ok(())
        }
    }
}

#[cfg(feature = "turso-local")]
async fn prepare_turso_local(engine: &TursoLocalConfig) -> Result<()> {
    open_turso_local_database(engine).await.map(|_| ())
}

/// Open a local Turso database with its configured encryption, when enabled.
#[cfg(feature = "turso-local")]
pub async fn open_turso_local_database(engine: &TursoLocalConfig) -> Result<turso::Database> {
    if engine.path.trim().is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "database.engine.path cannot be empty",
        ));
    }

    if engine.path != ":memory:"
        && let Some(parent) = Path::new(&engine.path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let mut builder = turso::Builder::new_local(&engine.path);
    if let Some(encryption) = resolve_turso_encryption(engine)? {
        builder = builder
            .experimental_encryption(true)
            .with_encryption(encryption);
    }

    builder.build().await.map_err(|error| {
        Error::other(format!(
            "failed to initialize local Turso database: {error}"
        ))
    })
}

#[cfg(feature = "turso-local")]
fn resolve_turso_encryption(engine: &TursoLocalConfig) -> Result<Option<turso::EncryptionOpts>> {
    let Some(secret_ref) = engine.encryption_key.as_ref() else {
        return Ok(None);
    };

    let hexkey = load_secret(secret_ref, "database.engine.encryption_key")?;

    Ok(Some(turso::EncryptionOpts {
        cipher: "aegis256".to_owned(),
        hexkey,
    }))
}

#[cfg(not(feature = "turso-local"))]
async fn prepare_turso_local(_engine: &TursoLocalConfig) -> Result<()> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "database.engine = TursoLocal requires the `turso-local` crate feature",
    ))
}

/// Open a local Turso database with its configured encryption, when enabled.
#[cfg(not(feature = "turso-local"))]
pub async fn open_turso_local_database(_engine: &TursoLocalConfig) -> Result<()> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "database.engine = TursoLocal requires the `turso-local` crate feature",
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        DatabaseBackupConfig, DatabaseBackupMode, DatabaseBackupTarget, DatabaseConfig,
        DatabaseEngine, DatabaseReadRoutingMode, DatabaseReplicationConfig,
        DatabaseReplicationMode, DatabaseResilienceConfig, DatabaseResilienceProfile,
        TursoLocalConfig, resolve_database_config, resolve_database_url,
        service_base_dir_from_config_path, sqlite_url_for_path,
    };
    use crate::config_secret::SecretRef;

    #[test]
    fn sqlite_url_for_path_handles_memory_and_file_paths() {
        assert_eq!(sqlite_url_for_path(":memory:"), "sqlite::memory:");
        assert_eq!(sqlite_url_for_path("app.db"), "sqlite:app.db?mode=rwc");
        assert_eq!(
            sqlite_url_for_path("var/data/app.db"),
            "sqlite:var/data/app.db?mode=rwc"
        );
    }

    #[test]
    fn database_config_defaults_to_sqlx_engine() {
        assert_eq!(DatabaseConfig::default().engine, DatabaseEngine::Sqlx,);
        assert_eq!(
            DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: "app.db".to_owned(),
                encryption_key: None,
            }),
            DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: "app.db".to_owned(),
                encryption_key: None,
            })
        );
    }

    #[test]
    fn service_base_dir_uses_bundle_parent_for_bundled_configs() {
        let root = std::env::temp_dir().join("vsr_database_base_dir");
        let config = root.join("app.bundle").join("service.eon");

        assert_eq!(service_base_dir_from_config_path(&config), root);
    }

    #[test]
    fn resolve_database_url_rebases_relative_sqlite_paths() {
        let base_dir = std::env::temp_dir().join("vsr-database-url");
        let expected = format!(
            "sqlite:{}?mode=rwc",
            base_dir.join("var/data/app.db").display()
        );
        assert_eq!(
            resolve_database_url("sqlite:var/data/app.db?mode=rwc", &base_dir),
            expected
        );
        assert_eq!(
            resolve_database_url("sqlite::memory:", &base_dir),
            "sqlite::memory:"
        );
    }

    #[test]
    fn resolve_database_config_rebases_relative_turso_paths() {
        let base_dir = std::env::temp_dir().join("vsr-database-config");
        let resolved = resolve_database_config(
            &DatabaseConfig {
                engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                    path: "var/data/app.db".to_owned(),
                    encryption_key: Some(SecretRef::env_or_file("TURSO_KEY")),
                }),
                resilience: None,
            },
            &base_dir,
        );

        assert_eq!(
            resolved,
            DatabaseConfig {
                engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                    path: base_dir.join("var/data/app.db").display().to_string(),
                    encryption_key: Some(SecretRef::env_or_file("TURSO_KEY")),
                }),
                resilience: None,
            }
        );
    }

    #[test]
    fn resolve_database_config_preserves_resilience_contract() {
        let base_dir = std::env::temp_dir().join("vsr-database-resilience");
        let resolved = resolve_database_config(
            &DatabaseConfig {
                engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                    path: "var/data/app.db".to_owned(),
                    encryption_key: None,
                }),
                resilience: Some(DatabaseResilienceConfig {
                    profile: DatabaseResilienceProfile::Pitr,
                    backup: Some(DatabaseBackupConfig {
                        required: true,
                        mode: DatabaseBackupMode::Pitr,
                        target: DatabaseBackupTarget::S3,
                        verify_restore: true,
                        max_age: Some("24h".to_owned()),
                        encryption_key: Some(SecretRef::env_or_file("BACKUP_ENCRYPTION_KEY")),
                        retention: None,
                    }),
                    replication: Some(DatabaseReplicationConfig {
                        mode: DatabaseReplicationMode::ReadReplica,
                        read_routing: DatabaseReadRoutingMode::Explicit,
                        read_url: Some(SecretRef::env_or_file("DATABASE_READ_URL")),
                        max_lag: Some("30s".to_owned()),
                        replicas_expected: Some(1),
                    }),
                }),
            },
            &base_dir,
        );

        assert_eq!(
            resolved.resilience.as_ref().map(|config| config.profile),
            Some(DatabaseResilienceProfile::Pitr)
        );
        assert_eq!(
            resolved
                .resilience
                .as_ref()
                .and_then(|config| config.replication.as_ref())
                .and_then(|config| config.read_url.as_ref())
                .and_then(|secret| secret.env_binding_name()),
            Some("DATABASE_READ_URL")
        );
    }

    #[cfg(feature = "turso-local")]
    #[test]
    fn resolve_turso_encryption_requires_present_env_var() {
        let error = super::resolve_turso_encryption(&TursoLocalConfig {
            path: "app.db".to_owned(),
            encryption_key: Some(SecretRef::env_or_file("VSR_TEST_MISSING_TURSO_KEY")),
        })
        .expect_err("missing env var should fail");
        assert!(
            error
                .to_string()
                .contains("references missing environment variable"),
            "unexpected error: {error}"
        );
    }

    #[cfg(feature = "turso-local")]
    #[test]
    fn resolve_turso_encryption_uses_file_hex_key() {
        let key = "b1bbfda4f589dc9daaf004fe21111e00dc00c98237102f5c7002a5669fc76327";
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), format!("{key}\n")).unwrap();
        let encryption = super::resolve_turso_encryption(&TursoLocalConfig {
            path: "app.db".into(),
            encryption_key: Some(SecretRef::File {
                path: file.path().to_path_buf(),
            }),
        })
        .unwrap()
        .unwrap();
        assert_eq!(encryption.cipher, "aegis256");
        assert_eq!(encryption.hexkey, key);
    }

    #[cfg(feature = "turso-local")]
    #[test]
    fn resolve_turso_encryption_requires_existing_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let error = super::resolve_turso_encryption(&TursoLocalConfig {
            path: "app.db".into(),
            encryption_key: Some(SecretRef::File {
                path: dir.path().join("missing"),
            }),
        })
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("database.engine.encryption_key references missing file"),
            "unexpected error: {error}"
        );
    }
}
