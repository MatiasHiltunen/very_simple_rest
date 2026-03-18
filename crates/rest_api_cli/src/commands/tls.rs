use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use colored::Colorize;
use rcgen::generate_simple_self_signed;
use rest_macro_core::compiler;
use rest_macro_core::tls::{DEFAULT_TLS_CERT_PATH, DEFAULT_TLS_KEY_PATH};

use crate::error::{Error, Result};

pub fn generate_self_signed_certificate(
    config_path: Option<&Path>,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    hosts: &[String],
    force: bool,
) -> Result<(PathBuf, PathBuf)> {
    let (cert_path, key_path) = resolve_output_paths(config_path, cert_path, key_path)?;
    ensure_output_available(&cert_path, force)?;
    ensure_output_available(&key_path, force)?;

    let hostnames = if hosts.is_empty() {
        vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "::1".to_owned(),
        ]
    } else {
        hosts.to_vec()
    };

    let certified = generate_simple_self_signed(hostnames.clone()).map_err(|error| {
        Error::Config(format!(
            "failed to generate self-signed certificate: {error}"
        ))
    })?;

    write_pem_file(&cert_path, certified.cert.pem().as_bytes())?;
    write_pem_file(&key_path, certified.signing_key.serialize_pem().as_bytes())?;
    set_private_key_permissions(&key_path)?;

    println!(
        "{} {}",
        "Generated TLS certificate:".green().bold(),
        cert_path.display()
    );
    println!(
        "{} {}",
        "Generated TLS private key:".green().bold(),
        key_path.display()
    );
    println!(
        "{} {}",
        "Certificate SANs:".green().bold(),
        hostnames.join(", ")
    );

    Ok((cert_path, key_path))
}

fn resolve_output_paths(
    config_path: Option<&Path>,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
) -> Result<(PathBuf, PathBuf)> {
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => Ok((cert_path, key_path)),
        (Some(_), None) | (None, Some(_)) => Err(Error::Config(
            "`vsr tls self-signed` requires both --cert-path and --key-path together".to_owned(),
        )),
        (None, None) => resolve_config_default_paths(config_path),
    }
}

fn resolve_config_default_paths(config_path: Option<&Path>) -> Result<(PathBuf, PathBuf)> {
    let Some(config_path) = config_path else {
        let cwd = std::env::current_dir().map_err(Error::Io)?;
        return Ok((
            cwd.join(DEFAULT_TLS_CERT_PATH),
            cwd.join(DEFAULT_TLS_KEY_PATH),
        ));
    };

    let service = compiler::load_service_from_path(config_path).map_err(|error| {
        Error::Config(format!(
            "failed to load `{}`: {error}",
            config_path.display()
        ))
    })?;
    if !service.tls.is_enabled() {
        return Err(Error::Config(
            "service config does not define `tls`; add `tls: {}` or pass --cert-path and --key-path"
                .to_owned(),
        ));
    }

    let base_dir = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let cert_path = service
        .tls
        .cert_path
        .as_deref()
        .map(|path| resolve_relative_path(&base_dir, path))
        .ok_or_else(|| Error::Config("service TLS config is missing tls.cert_path".to_owned()))?;
    let key_path = service
        .tls
        .key_path
        .as_deref()
        .map(|path| resolve_relative_path(&base_dir, path))
        .ok_or_else(|| Error::Config("service TLS config is missing tls.key_path".to_owned()))?;

    Ok((cert_path, key_path))
}

fn resolve_relative_path(base_dir: &Path, path: &str) -> PathBuf {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base_dir.join(candidate)
    }
}

fn ensure_output_available(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(Error::Config(format!(
            "refusing to overwrite existing file: {} (pass --force to overwrite)",
            path.display()
        )));
    }
    Ok(())
}

fn write_pem_file(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    fs::write(path, contents).map_err(Error::Io)
}

fn set_private_key_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(Error::Io)?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::generate_self_signed_certificate;
    use rest_macro_core::compiler;

    fn test_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}_{stamp}"))
    }

    #[test]
    fn self_signed_certificate_generation_uses_service_tls_defaults() {
        let root = test_root("vsr_tls_command");
        fs::create_dir_all(&root).expect("test root should exist");
        let config_path = root.join("service.eon");
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

        let (cert_path, key_path) = generate_self_signed_certificate(
            Some(&config_path),
            None,
            None,
            &["localhost".to_owned()],
            false,
        )
        .expect("cert generation should succeed");

        assert!(cert_path.exists());
        assert!(key_path.exists());
        assert!(
            fs::read_to_string(&cert_path)
                .expect("cert should read")
                .contains("BEGIN CERTIFICATE")
        );
        assert!(
            fs::read_to_string(&key_path)
                .expect("key should read")
                .contains("BEGIN PRIVATE KEY")
        );

        let service =
            compiler::load_service_from_path(&config_path).expect("service config should reload");
        rest_macro_core::tls::load_rustls_server_config(&service.tls, &root)
            .expect("generated PEM files should load into rustls");
    }

    #[test]
    fn self_signed_certificate_generation_rejects_missing_tls_config_defaults() {
        let root = test_root("vsr_tls_missing_config");
        fs::create_dir_all(&root).expect("test root should exist");
        let config_path = root.join("service.eon");
        fs::write(
            &config_path,
            r#"
            module: "plain_service"
            resources: [
                {
                    name: "Note"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        )
        .expect("config should write");

        let error = generate_self_signed_certificate(Some(&config_path), None, None, &[], false)
            .expect_err("missing tls config should fail");
        assert!(error.to_string().contains("does not define `tls`"));
    }
}
