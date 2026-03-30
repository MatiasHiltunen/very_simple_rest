use std::{
    env, fs,
    io::{Error, ErrorKind, Result},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
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

    pub fn env_binding_name(&self) -> Option<&str> {
        match self {
            Self::Env { var_name } | Self::EnvOrFile { var_name } => Some(var_name.as_str()),
            Self::File { .. } | Self::SystemdCredential { .. } | Self::External { .. } => None,
        }
    }

    pub fn systemd_credential_path(&self) -> Option<PathBuf> {
        match self {
            Self::SystemdCredential { id } => Some(Path::new("/run/credentials").join(id)),
            Self::Env { .. }
            | Self::EnvOrFile { .. }
            | Self::File { .. }
            | Self::External { .. } => None,
        }
    }
}

pub fn describe_secret_ref(secret: &SecretRef) -> Option<String> {
    match secret {
        SecretRef::Env { var_name } | SecretRef::EnvOrFile { var_name } => {
            describe_secret_source(var_name)
        }
        SecretRef::File { path } => {
            if path.is_file() {
                Some(format!("file `{}`", path.display()))
            } else {
                None
            }
        }
        SecretRef::SystemdCredential { id } => {
            let path = Path::new("/run/credentials").join(id);
            if path.is_file() {
                Some(format!("systemd credential `{}`", id))
            } else {
                None
            }
        }
        SecretRef::External { provider, locator } => {
            Some(format!("external `{provider}` secret `{locator}`"))
        }
    }
}

pub fn has_secret(secret: &SecretRef) -> bool {
    load_optional_secret(secret, "secret")
        .ok()
        .flatten()
        .is_some()
}

pub fn load_optional_secret(secret: &SecretRef, label: &str) -> Result<Option<String>> {
    match secret {
        SecretRef::Env { var_name } => match env::var(var_name) {
            Ok(value) => {
                if value.trim().is_empty() {
                    Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!("{label} `{var_name}` resolved to an empty value"),
                    ))
                } else {
                    Ok(Some(value))
                }
            }
            Err(env::VarError::NotPresent) => Ok(None),
            Err(error) => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("failed to read `{var_name}` for {label}: {error}"),
            )),
        },
        SecretRef::EnvOrFile { var_name } => load_optional_secret_from_env_or_file(var_name, label),
        SecretRef::File { path } => load_optional_secret_from_path(path, label),
        SecretRef::SystemdCredential { id } => {
            load_optional_secret_from_path(&Path::new("/run/credentials").join(id), label)
        }
        SecretRef::External { provider, locator } => Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "{label} uses external secret provider `{provider}` locator `{locator}`, but direct runtime resolution is not implemented"
            ),
        )),
    }
}

pub fn load_secret(secret: &SecretRef, label: &str) -> Result<String> {
    load_optional_secret(secret, label)?.ok_or_else(|| match secret {
        SecretRef::Env { var_name } => Error::new(
            ErrorKind::InvalidInput,
            format!("{label} references missing environment variable `{var_name}`"),
        ),
        SecretRef::EnvOrFile { var_name } => {
            let file_var = format!("{var_name}_FILE");
            Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "{label} references missing environment variable `{var_name}` or `{file_var}`"
                ),
            )
        }
        SecretRef::File { path } => Error::new(
            ErrorKind::InvalidInput,
            format!("{label} references missing file `{}`", path.display()),
        ),
        SecretRef::SystemdCredential { id } => Error::new(
            ErrorKind::InvalidInput,
            format!(
                "{label} references missing systemd credential `{id}` at `/run/credentials/{id}`"
            ),
        ),
        SecretRef::External { provider, locator } => Error::new(
            ErrorKind::Unsupported,
            format!(
                "{label} uses external secret provider `{provider}` locator `{locator}`, but direct runtime resolution is not implemented"
            ),
        ),
    })
}

fn load_optional_secret_from_path(path: &Path, label: &str) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    if !path.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("{label} path `{}` is not a file", path.display()),
        ));
    }

    let secret = fs::read_to_string(path).map_err(|error| {
        Error::new(
            error.kind(),
            format!("{label} file `{}` is unreadable: {error}", path.display()),
        )
    })?;
    let secret = secret.trim().to_owned();
    if secret.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "{label} file `{}` resolved to an empty value",
                path.display()
            ),
        ));
    }
    Ok(Some(secret))
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
