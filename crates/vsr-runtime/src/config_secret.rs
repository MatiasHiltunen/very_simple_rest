//! Serializable secret references and resolution used by service configuration.
//!
//! This preserves the `.eon` secret variants. The provider-oriented
//! `vsr_core::secret::SecretRef` is a separate contract.

use std::{
    env, fs,
    io::{Error, ErrorKind, Result},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// A configured source for a secret value.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretRef {
    /// Read an environment variable.
    Env {
        /// Environment variable name.
        var_name: String,
    },
    /// Read an environment variable or its `_FILE` companion.
    EnvOrFile {
        /// Environment variable name.
        var_name: String,
    },
    /// Read a file.
    File {
        /// File path.
        path: PathBuf,
    },
    /// Read a systemd credential.
    SystemdCredential {
        /// Credential identifier.
        id: String,
    },
    /// Refer to a provider whose direct resolution is unsupported here.
    External {
        /// Provider name.
        provider: String,
        /// Provider-specific locator.
        locator: String,
    },
}

impl SecretRef {
    /// Reference an environment variable.
    pub fn env(var_name: impl Into<String>) -> Self {
        Self::Env {
            var_name: var_name.into(),
        }
    }

    /// Reference an environment variable or its `_FILE` companion.
    pub fn env_or_file(var_name: impl Into<String>) -> Self {
        Self::EnvOrFile {
            var_name: var_name.into(),
        }
    }

    /// Return the environment variable name, when this variant has one.
    pub fn env_binding_name(&self) -> Option<&str> {
        match self {
            Self::Env { var_name } | Self::EnvOrFile { var_name } => Some(var_name.as_str()),
            Self::File { .. } | Self::SystemdCredential { .. } | Self::External { .. } => None,
        }
    }

    /// Return the systemd credential file path, when applicable.
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

/// Describe the configured source without exposing its value.
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

/// Whether the configured secret can currently be resolved.
pub fn has_secret(secret: &SecretRef) -> bool {
    load_optional_secret(secret, "secret")
        .ok()
        .flatten()
        .is_some()
}

/// Resolve a configured secret if it is present.
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

/// Resolve a required configured secret.
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

/// Describe which environment binding supplies a secret, if any.
pub fn describe_secret_source(var_name: &str) -> Option<String> {
    if env::var_os(var_name).is_some() {
        Some(format!("`{var_name}`"))
    } else {
        let file_var = format!("{var_name}_FILE");
        env::var_os(&file_var).map(|_| format!("`{file_var}`"))
    }
}

/// Whether an inline or `_FILE` environment binding supplies a secret.
pub fn has_secret_from_env_or_file(var_name: &str) -> bool {
    load_optional_secret_from_env_or_file(var_name, "secret")
        .ok()
        .flatten()
        .is_some()
}

/// Resolve an inline or `_FILE` environment binding if present.
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

/// Resolve a required inline or `_FILE` environment binding.
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
    use super::{SecretRef, load_secret};

    #[test]
    fn file_secret_resolution_is_available_without_the_compiler() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key");
        std::fs::write(&path, "  test-key\n").unwrap();
        let source = SecretRef::File { path: path.clone() };
        assert_eq!(load_secret(&source, "signing key").unwrap(), "test-key");

        std::fs::remove_file(path).unwrap();
        assert!(load_secret(&source, "signing key").is_err());
    }
}
