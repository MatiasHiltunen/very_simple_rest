//! TLS configuration, path resolution and Rustls loading shared by native
//! services and both HTTP adapters.

use std::env;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};
#[cfg(feature = "tls")]
use std::sync::Arc;

#[cfg(feature = "tls")]
use rustls::pki_types::pem::{Error as PemError, PemObject};
#[cfg(feature = "tls")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};

/// Development certificate path used when TLS is enabled without a custom path.
pub const DEFAULT_TLS_CERT_PATH: &str = "certs/dev-cert.pem";
/// Development private key path used when TLS is enabled without a custom path.
pub const DEFAULT_TLS_KEY_PATH: &str = "certs/dev-key.pem";
/// Environment variable that can override the certificate path.
pub const DEFAULT_TLS_CERT_PATH_ENV: &str = "TLS_CERT_PATH";
/// Environment variable that can override the private key path.
pub const DEFAULT_TLS_KEY_PATH_ENV: &str = "TLS_KEY_PATH";

/// TLS paths supplied by a service configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Certificate path, relative to the service directory unless absolute.
    #[serde(default)]
    pub cert_path: Option<String>,
    /// Private key path, relative to the service directory unless absolute.
    #[serde(default)]
    pub key_path: Option<String>,
    /// Optional environment variable containing the certificate path.
    #[serde(default)]
    pub cert_path_env: Option<String>,
    /// Optional environment variable containing the private key path.
    #[serde(default)]
    pub key_path_env: Option<String>,
}

impl TlsConfig {
    /// Whether any TLS path or path environment variable was configured.
    pub fn is_enabled(&self) -> bool {
        self.cert_path.is_some()
            || self.key_path.is_some()
            || self.cert_path_env.is_some()
            || self.key_path_env.is_some()
    }
}

/// Certificate and private key paths resolved for a running service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTlsPaths {
    /// Certificate PEM path.
    pub cert_path: PathBuf,
    /// Private key PEM path.
    pub key_path: PathBuf,
}

/// Rebase configured relative paths against a service directory.
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

/// Load a Rustls server configuration from resolved service TLS settings.
#[cfg(feature = "tls")]
pub fn load_rustls_server_config(
    config: &TlsConfig,
    base_dir: &Path,
) -> Result<rustls::ServerConfig> {
    let resolved = resolve_tls_paths(config, base_dir)?;
    load_rustls_from_paths(&resolved)
}

/// Load the certificate and private key with the same validation for every
/// HTTP adapter. The adapter may set its own ALPN protocols afterward.
#[cfg(feature = "tls")]
pub(crate) fn load_rustls_from_paths(paths: &ResolvedTlsPaths) -> Result<rustls::ServerConfig> {
    let certs = load_certificates(&paths.cert_path)?;
    let key = load_private_key(&paths.key_path)?;

    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| {
        Error::new(
            ErrorKind::InvalidData,
            format!("failed to configure TLS protocol versions: {error}"),
        )
    })?;

    builder
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| {
            Error::new(
                ErrorKind::InvalidData,
                format!("invalid TLS certificate or key: {error}"),
            )
        })
}

/// Resolve configured paths and environment overrides against a service directory.
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

#[cfg(feature = "tls")]
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

#[cfg(feature = "tls")]
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).map_err(|error| tls_pem_error(path, "private key", error))
}

#[cfg(feature = "tls")]
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

    #[cfg(feature = "tls")]
    #[test]
    fn rustls_loader_accepts_matching_pem_and_rejects_missing_key() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
        let config = TlsConfig {
            cert_path: Some(cert_path.display().to_string()),
            key_path: Some(key_path.display().to_string()),
            ..TlsConfig::default()
        };
        let loaded = super::load_rustls_server_config(&config, dir.path()).unwrap();
        assert!(loaded.alpn_protocols.is_empty(), "the adapter chooses ALPN");

        std::fs::remove_file(&key_path).unwrap();
        let error = super::load_rustls_server_config(&config, dir.path()).unwrap_err();
        assert!(error.to_string().contains("private key"));
    }
}
