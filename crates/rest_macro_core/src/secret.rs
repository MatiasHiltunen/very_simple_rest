use std::{
    env, fs,
    io::{Error, ErrorKind, Result},
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretRef {
    Env { var_name: String },
    EnvOrFile { var_name: String },
    File { path: PathBuf },
    SystemdCredential { id: String },
    External { provider: String, locator: String },
}

impl SecretRef {
    pub fn env(var_name: impl Into<String>) -> Self {
        Self::Env {
            var_name: var_name.into(),
        }
    }

    pub fn env_or_file(var_name: impl Into<String>) -> Self {
        Self::EnvOrFile {
            var_name: var_name.into(),
        }
    }
}

pub fn describe_secret_source(var_name: &str) -> Option<String> {
    if env::var_os(var_name).is_some() {
        Some(format!("`{var_name}`"))
    } else {
        let file_var = format!("{var_name}_FILE");
        env::var_os(&file_var).map(|_| format!("`{file_var}`"))
    }
}

pub fn has_secret_from_env_or_file(var_name: &str) -> bool {
    load_optional_secret_from_env_or_file(var_name, "secret")
        .ok()
        .flatten()
        .is_some()
}

pub fn load_optional_secret_from_env_or_file(
    var_name: &str,
    label: &str,
) -> Result<Option<String>> {
    if let Ok(value) = env::var(var_name) {
        if value.trim().is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("{label} `{var_name}` resolved to an empty value"),
            ));
        }
        return Ok(Some(value));
    }

    let file_var = format!("{var_name}_FILE");
    let path = match env::var(&file_var) {
        Ok(path) => path,
        Err(env::VarError::NotPresent) => return Ok(None),
        Err(error) => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("failed to read `{file_var}` for {label}: {error}"),
            ));
        }
    };

    if path.trim().is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("{label} `{file_var}` resolved to an empty value"),
        ));
    }

    let secret = fs::read_to_string(&path).map_err(|error| {
        Error::new(
            error.kind(),
            format!("{label} `{file_var}` points to unreadable file `{path}`: {error}"),
        )
    })?;
    let secret = secret.trim().to_owned();

    if secret.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("{label} file `{path}` resolved to an empty value"),
        ));
    }

    Ok(Some(secret))
}

pub fn load_secret_from_env_or_file(var_name: &str, label: &str) -> Result<String> {
    load_optional_secret_from_env_or_file(var_name, label)?.ok_or_else(|| {
        let file_var = format!("{var_name}_FILE");
        Error::new(
            ErrorKind::InvalidInput,
            format!("{label} references missing environment variable `{var_name}` or `{file_var}`"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{
        SecretRef, describe_secret_source, has_secret_from_env_or_file,
        load_optional_secret_from_env_or_file, load_secret_from_env_or_file,
    };
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_secret_path(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        std::env::temp_dir().join(format!("vsr_secret_{prefix}_{nanos}.txt"))
    }

    #[test]
    fn prefers_inline_secret_env_var() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var("VSR_TEST_SECRET", "inline-secret");
            std::env::remove_var("VSR_TEST_SECRET_FILE");
        }

        let secret = load_secret_from_env_or_file("VSR_TEST_SECRET", "test secret")
            .expect("env secret should load");
        assert_eq!(secret, "inline-secret");

        unsafe {
            std::env::remove_var("VSR_TEST_SECRET");
        }
    }

    #[test]
    fn loads_secret_from_mounted_file_path() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let path = unique_secret_path("file");
        std::fs::write(&path, "file-secret\n").expect("secret file should write");

        unsafe {
            std::env::remove_var("VSR_TEST_SECRET");
            std::env::set_var("VSR_TEST_SECRET_FILE", path.as_os_str());
        }

        let secret = load_secret_from_env_or_file("VSR_TEST_SECRET", "test secret")
            .expect("file-backed secret should load");
        assert_eq!(secret, "file-secret");

        unsafe {
            std::env::remove_var("VSR_TEST_SECRET_FILE");
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn optional_loader_returns_none_when_binding_is_absent() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::remove_var("VSR_TEST_SECRET");
            std::env::remove_var("VSR_TEST_SECRET_FILE");
        }

        let secret = load_optional_secret_from_env_or_file("VSR_TEST_SECRET", "test secret")
            .expect("missing binding should not error");
        assert_eq!(secret, None);
        assert!(!has_secret_from_env_or_file("VSR_TEST_SECRET"));
    }

    #[test]
    fn describe_source_prefers_inline_env_then_file_binding() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var("VSR_TEST_SECRET", "inline-secret");
            std::env::remove_var("VSR_TEST_SECRET_FILE");
        }
        assert_eq!(
            describe_secret_source("VSR_TEST_SECRET").as_deref(),
            Some("`VSR_TEST_SECRET`")
        );

        unsafe {
            std::env::remove_var("VSR_TEST_SECRET");
            std::env::set_var("VSR_TEST_SECRET_FILE", "/run/secrets/test");
        }
        assert_eq!(
            describe_secret_source("VSR_TEST_SECRET").as_deref(),
            Some("`VSR_TEST_SECRET_FILE`")
        );

        unsafe {
            std::env::remove_var("VSR_TEST_SECRET_FILE");
        }
    }

    #[test]
    fn secret_ref_helpers_build_expected_variants() {
        assert_eq!(
            SecretRef::env("JWT_SECRET"),
            SecretRef::Env {
                var_name: "JWT_SECRET".to_owned()
            }
        );
        assert_eq!(
            SecretRef::env_or_file("JWT_SECRET"),
            SecretRef::EnvOrFile {
                var_name: "JWT_SECRET".to_owned()
            }
        );
    }
}
