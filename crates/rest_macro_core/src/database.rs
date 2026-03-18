use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[cfg(feature = "turso-local")]
use crate::secret::load_secret_from_env_or_file;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default)]
    pub engine: DatabaseEngine,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum DatabaseEngine {
    #[default]
    Sqlx,
    TursoLocal(TursoLocalConfig),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TursoLocalConfig {
    pub path: String,
    #[serde(default)]
    pub encryption_key_env: Option<String>,
}

pub const DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV: &str = "TURSO_ENCRYPTION_KEY";

pub fn sqlite_url_for_path(path: &str) -> String {
    if path == ":memory:" {
        "sqlite::memory:".to_owned()
    } else {
        format!("sqlite:{path}?mode=rwc")
    }
}

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

pub fn resolve_database_config(config: &DatabaseConfig, base_dir: &Path) -> DatabaseConfig {
    match &config.engine {
        DatabaseEngine::Sqlx => config.clone(),
        DatabaseEngine::TursoLocal(engine) => DatabaseConfig {
            engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: resolve_relative_database_path(base_dir, &engine.path),
                encryption_key_env: engine.encryption_key_env.clone(),
            }),
        },
    }
}

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
    let Some(var_name) = engine.encryption_key_env.as_deref() else {
        return Ok(None);
    };

    let hexkey = load_secret_from_env_or_file(
        var_name,
        &format!("database.engine.encryption_key_env `{var_name}`"),
    )?;

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
        DatabaseConfig, DatabaseEngine, TursoLocalConfig, resolve_database_config,
        resolve_database_url, service_base_dir_from_config_path, sqlite_url_for_path,
    };

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
                encryption_key_env: None,
            }),
            DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: "app.db".to_owned(),
                encryption_key_env: None,
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
                    encryption_key_env: Some("TURSO_KEY".to_owned()),
                }),
            },
            &base_dir,
        );

        assert_eq!(
            resolved,
            DatabaseConfig {
                engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                    path: base_dir.join("var/data/app.db").display().to_string(),
                    encryption_key_env: Some("TURSO_KEY".to_owned()),
                }),
            }
        );
    }

    #[cfg(feature = "turso-local")]
    #[test]
    fn resolve_turso_encryption_requires_present_env_var() {
        let error = super::resolve_turso_encryption(&TursoLocalConfig {
            path: "app.db".to_owned(),
            encryption_key_env: Some("VSR_TEST_MISSING_TURSO_KEY".to_owned()),
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
    fn resolve_turso_encryption_uses_env_hex_key() {
        let key = "b1bbfda4f589dc9daaf004fe21111e00dc00c98237102f5c7002a5669fc76327";
        let var_name = format!("VSR_TURSO_KEY_{}", std::process::id());
        unsafe {
            std::env::set_var(&var_name, key);
        }

        let encryption = super::resolve_turso_encryption(&TursoLocalConfig {
            path: "app.db".to_owned(),
            encryption_key_env: Some(var_name.clone()),
        })
        .expect("env var should resolve")
        .expect("encryption opts should exist");

        assert_eq!(encryption.cipher, "aegis256");
        assert_eq!(encryption.hexkey, key);

        unsafe {
            std::env::remove_var(var_name);
        }
    }

    #[cfg(feature = "turso-local")]
    #[test]
    fn resolve_turso_encryption_uses_file_backed_hex_key() {
        let key = "c2bbfda4f589dc9daaf004fe21111e00dc00c98237102f5c7002a5669fc76327";
        let var_name = format!("VSR_TURSO_KEY_FILE_{}", std::process::id());
        let path = std::env::temp_dir().join(format!("{var_name}.txt"));
        std::fs::write(&path, key).expect("hex key file should write");
        unsafe {
            std::env::remove_var(&var_name);
            std::env::set_var(format!("{var_name}_FILE"), path.as_os_str());
        }

        let encryption = super::resolve_turso_encryption(&TursoLocalConfig {
            path: "app.db".to_owned(),
            encryption_key_env: Some(var_name.clone()),
        })
        .expect("file-backed env should resolve")
        .expect("encryption opts should exist");

        assert_eq!(encryption.cipher, "aegis256");
        assert_eq!(encryption.hexkey, key);

        unsafe {
            std::env::remove_var(format!("{var_name}_FILE"));
        }
        let _ = std::fs::remove_file(path);
    }
}
