use std::env;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};

pub const DEFAULT_TLS_CERT_PATH: &str = "certs/dev-cert.pem";
pub const DEFAULT_TLS_KEY_PATH: &str = "certs/dev-key.pem";
pub const DEFAULT_TLS_CERT_PATH_ENV: &str = "TLS_CERT_PATH";
pub const DEFAULT_TLS_KEY_PATH_ENV: &str = "TLS_KEY_PATH";

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub cert_path_env: Option<String>,
    #[serde(default)]
    pub key_path_env: Option<String>,
}

impl TlsConfig {
    pub fn is_enabled(&self) -> bool {
        self.cert_path.is_some()
            || self.key_path.is_some()
            || self.cert_path_env.is_some()
            || self.key_path_env.is_some()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTlsPaths {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

pub fn resolve_tls_config(config: &TlsConfig, base_dir: &Path) -> TlsConfig {
    TlsConfig {
        cert_path: config
            .cert_path
            .as_deref()
            .map(|path| resolve_relative_path(base_dir, path)),
        key_path: config
            .key_path
            .as_deref()
            .map(|path| resolve_relative_path(base_dir, path)),
        cert_path_env: config.cert_path_env.clone(),
        key_path_env: config.key_path_env.clone(),
    }
}

pub fn load_rustls_server_config(
    config: &TlsConfig,
    base_dir: &Path,
) -> Result<rustls::ServerConfig> {
    let resolved = resolve_tls_paths(config, base_dir)?;
    let certs = load_certificates(&resolved.cert_path)?;
    let key = load_private_key(&resolved.key_path)?;

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| {
            Error::new(
                ErrorKind::InvalidData,
                format!("invalid TLS certificate or key: {error}"),
            )
        })
}

pub fn resolve_tls_paths(config: &TlsConfig, base_dir: &Path) -> Result<ResolvedTlsPaths> {
    if !config.is_enabled() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "TLS is not configured for this service",
        ));
    }

    let cert_path = resolve_path_field(
        config.cert_path.as_deref(),
        config.cert_path_env.as_deref(),
        "tls.cert_path",
        "tls.cert_path_env",
        base_dir,
    )?;
    let key_path = resolve_path_field(
        config.key_path.as_deref(),
        config.key_path_env.as_deref(),
        "tls.key_path",
        "tls.key_path_env",
        base_dir,
    )?;

    Ok(ResolvedTlsPaths {
        cert_path,
        key_path,
    })
}

fn resolve_path_field(
    configured_path: Option<&str>,
    env_var: Option<&str>,
    path_label: &str,
    env_label: &str,
    base_dir: &Path,
) -> Result<PathBuf> {
    if let Some(env_var) = env_var {
        match env::var(env_var) {
            Ok(value) => {
                let value = value.trim();
                if value.is_empty() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!("{env_label} `{env_var}` resolved to an empty path"),
                    ));
                }
                return Ok(PathBuf::from(resolve_relative_path(base_dir, value)));
            }
            Err(env::VarError::NotPresent) => {}
            Err(error) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("failed to read {env_label} `{env_var}`: {error}"),
                ));
            }
        }
    }

    let Some(path) = configured_path
        .map(str::trim)
        .filter(|path| !path.is_empty())
    else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("{path_label} must be configured when TLS is enabled"),
        ));
    };

    Ok(PathBuf::from(resolve_relative_path(base_dir, path)))
}

fn resolve_relative_path(base_dir: &Path, path: &str) -> String {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        candidate.to_string_lossy().into_owned()
    } else {
        base_dir.join(candidate).to_string_lossy().into_owned()
    }
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|error| tls_pem_error(path, "certificate", error))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| tls_pem_error(path, "certificate", error))?;

    if certs.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "TLS certificate PEM `{}` did not contain any certificates",
                path.display()
            ),
        ));
    }

    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).map_err(|error| tls_pem_error(path, "private key", error))
}

fn tls_pem_error(path: &Path, label: &str, error: PemError) -> Error {
    match error {
        PemError::Io(error) => Error::new(
            error.kind(),
            format!("failed to open TLS {label} `{}`: {error}", path.display()),
        ),
        PemError::NoItemsFound => Error::new(
            ErrorKind::InvalidData,
            format!(
                "TLS {label} PEM `{}` did not contain any supported PEM sections",
                path.display()
            ),
        ),
        other => Error::new(
            ErrorKind::InvalidData,
            format!(
                "failed to parse TLS {label} PEM `{}`: {other}",
                path.display()
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_TLS_CERT_PATH_ENV, DEFAULT_TLS_KEY_PATH_ENV, TlsConfig, resolve_tls_config,
    };

    #[test]
    fn tls_config_defaults_to_disabled() {
        assert!(!TlsConfig::default().is_enabled());
    }

    #[test]
    fn resolve_tls_config_rebases_relative_paths() {
        let base_dir = std::env::temp_dir().join("vsr_tls_base_dir");
        let resolved = resolve_tls_config(
            &TlsConfig {
                cert_path: Some("certs/dev-cert.pem".to_owned()),
                key_path: Some("certs/dev-key.pem".to_owned()),
                cert_path_env: Some(DEFAULT_TLS_CERT_PATH_ENV.to_owned()),
                key_path_env: Some(DEFAULT_TLS_KEY_PATH_ENV.to_owned()),
            },
            &base_dir,
        );

        assert_eq!(
            resolved.cert_path.as_deref(),
            Some(
                base_dir
                    .join("certs/dev-cert.pem")
                    .to_string_lossy()
                    .as_ref()
            )
        );
        assert_eq!(
            resolved.key_path.as_deref(),
            Some(
                base_dir
                    .join("certs/dev-key.pem")
                    .to_string_lossy()
                    .as_ref()
            )
        );
    }
}
