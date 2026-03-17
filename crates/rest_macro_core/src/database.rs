use std::io::{Error, ErrorKind, Result};

use serde::{Deserialize, Serialize};

#[cfg(feature = "turso-local")]
use std::env;
#[cfg(feature = "turso-local")]
use std::path::Path;

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

    let hexkey = env::var(var_name).map_err(|_| {
        Error::new(
            ErrorKind::InvalidInput,
            format!(
                "database.engine.encryption_key_env references missing environment variable `{var_name}`"
            ),
        )
    })?;

    if hexkey.trim().is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("database.engine.encryption_key_env `{var_name}` resolved to an empty value"),
        ));
    }

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
    use super::{DatabaseConfig, DatabaseEngine, TursoLocalConfig, sqlite_url_for_path};

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
}
