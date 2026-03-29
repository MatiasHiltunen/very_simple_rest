use crate::error::{Error, Result};
use rand::distr::{Alphanumeric, SampleString};
use rand::{RngExt, rng};
use rest_macro_core::auth::{AuthClaimType, AuthEmailProvider};
use rest_macro_core::compiler::{self, default_service_database_url};
use rest_macro_core::database::{DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV, DatabaseEngine};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Generate a secure random string for JWT secret
fn generate_random_secret(length: usize) -> String {
    let mut random = rng();
    Alphanumeric.sample_string(&mut random, length)
}

fn generate_random_hex(bytes_len: usize) -> String {
    let mut random = rng();
    let mut output = String::with_capacity(bytes_len * 2);
    for _ in 0..(bytes_len * 2) {
        let value = random.random_range(0_u8..16_u8);
        write!(&mut output, "{value:x}").expect("hex write should succeed");
    }
    output
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvTemplateMode {
    Development,
    Production,
}

impl EnvTemplateMode {
    pub fn writes_live_secrets(self) -> bool {
        matches!(self, Self::Development)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvFileReport {
    pub path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub generated_turso_encryption_var: Option<String>,
    pub preserved_turso_encryption_var: Option<String>,
    pub generated_jwt_secret: bool,
    pub preserved_jwt_secret: bool,
    pub mode: EnvTemplateMode,
}

struct EnvTemplateConfig {
    database_url: String,
    turso_encryption_var: Option<String>,
    auth_email_env_var: Option<String>,
    auth_email_env_comment: Option<String>,
    admin_claim_examples: Vec<AdminClaimEnvExample>,
    cors_origins_var: Option<String>,
    trusted_proxies_var: Option<String>,
    log_filter_env: String,
    log_default_filter: String,
    bind_addr: String,
    tls_cert_path_env: Option<String>,
    tls_key_path_env: Option<String>,
    tls_cert_path: Option<String>,
    tls_key_path: Option<String>,
}

struct AdminClaimEnvExample {
    env_var: String,
    example_value: String,
    comment: String,
}

fn env_template_config(config_path: Option<&Path>) -> Result<EnvTemplateConfig> {
    let Some(path) = config_path else {
        return Ok(EnvTemplateConfig {
            database_url: "sqlite:var/data/app.db?mode=rwc".to_owned(),
            turso_encryption_var: None,
            auth_email_env_var: None,
            auth_email_env_comment: None,
            admin_claim_examples: Vec::new(),
            cors_origins_var: None,
            trusted_proxies_var: None,
            log_filter_env: "RUST_LOG".to_owned(),
            log_default_filter: "info".to_owned(),
            bind_addr: "127.0.0.1:8080".to_owned(),
            tls_cert_path_env: None,
            tls_key_path_env: None,
            tls_cert_path: None,
            tls_key_path: None,
        });
    };

    let service = compiler::load_service_from_path(path)
        .map_err(|error| crate::error::Error::Config(error.to_string()))?;
    let turso_encryption_var = match &service.database.engine {
        DatabaseEngine::TursoLocal(engine) => engine.encryption_key_env.clone(),
        DatabaseEngine::Sqlx => None,
    };
    let (auth_email_env_var, auth_email_env_comment) = match service.security.auth.email.as_ref() {
        Some(email) => match &email.provider {
            AuthEmailProvider::Resend { api_key_env, .. } => (
                Some(api_key_env.clone()),
                Some("Built-in auth email delivery via Resend".to_owned()),
            ),
            AuthEmailProvider::Smtp { connection_url_env } => (
                Some(connection_url_env.clone()),
                Some("Built-in auth email delivery via SMTP/lettre".to_owned()),
            ),
        },
        None => (None, None),
    };
    let admin_claim_examples = configured_admin_claim_env_examples(&service.security.auth.claims);

    Ok(EnvTemplateConfig {
        database_url: default_service_database_url(&service),
        turso_encryption_var,
        auth_email_env_var,
        auth_email_env_comment,
        admin_claim_examples,
        cors_origins_var: service.security.cors.origins_env.clone(),
        trusted_proxies_var: service.security.trusted_proxies.proxies_env.clone(),
        log_filter_env: service.logging.filter_env.clone(),
        log_default_filter: service.logging.default_filter.clone(),
        bind_addr: if service.tls.is_enabled() {
            "127.0.0.1:8443".to_owned()
        } else {
            "127.0.0.1:8080".to_owned()
        },
        tls_cert_path_env: service.tls.cert_path_env.clone(),
        tls_key_path_env: service.tls.key_path_env.clone(),
        tls_cert_path: service.tls.cert_path.clone(),
        tls_key_path: service.tls.key_path.clone(),
    })
}

fn render_secret_binding_comment(output: &mut String, var_name: &str, example: &str) {
    writeln!(output, "# {var_name}={example}").unwrap();
    writeln!(
        output,
        "# Or mount a secret file and set {var_name}_FILE=/run/secrets/{var_name}"
    )
    .unwrap();
}

fn render_env_template_with_config(config: &EnvTemplateConfig, mode: EnvTemplateMode) -> String {
    let jwt_secret = generate_random_secret(32);
    let mut output = String::new();

    writeln!(&mut output, "# very_simple_rest API Configuration").unwrap();
    if mode == EnvTemplateMode::Production {
        writeln!(
            &mut output,
            "# Production mode: this template does not write live secret values."
        )
        .unwrap();
        writeln!(
            &mut output,
            "# Prefer workload identity or a secret manager. Mounted secret files are the next-best option."
        )
        .unwrap();
    }
    writeln!(&mut output).unwrap();
    writeln!(&mut output, "# Database Configuration").unwrap();
    writeln!(
        &mut output,
        "# Override DATABASE_URL only if you need a runtime target different from the service defaults."
    )
    .unwrap();
    writeln!(&mut output, "DATABASE_URL={}", config.database_url).unwrap();
    writeln!(
        &mut output,
        "# If the runtime database URL contains credentials, prefer DATABASE_URL_FILE=/run/secrets/DATABASE_URL"
    )
    .unwrap();
    writeln!(&mut output).unwrap();

    if let Some(var_name) = &config.turso_encryption_var {
        let heading = if var_name == DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV {
            "# Local Turso encryption used by the compiled database engine"
        } else {
            "# Local Turso encryption"
        };
        writeln!(&mut output, "{heading}").unwrap();
        if mode.writes_live_secrets() {
            let turso_key = generate_random_hex(32);
            writeln!(&mut output, "{var_name}={turso_key}").unwrap();
            writeln!(
                &mut output,
                "# Or mount a secret file and set {var_name}_FILE=/run/secrets/{var_name}"
            )
            .unwrap();
        } else {
            render_secret_binding_comment(&mut output, var_name, "change-me-64-hex-characters");
        }
        writeln!(&mut output).unwrap();
    }

    if let (Some(cert_env), Some(key_env), Some(cert_path), Some(key_path)) = (
        config.tls_cert_path_env.as_deref(),
        config.tls_key_path_env.as_deref(),
        config.tls_cert_path.as_deref(),
        config.tls_key_path.as_deref(),
    ) {
        writeln!(&mut output, "# TLS (Rustls)").unwrap();
        writeln!(
            &mut output,
            "# This service defaults to HTTPS + HTTP/2. Generate local certs with `vsr tls self-signed`."
        )
        .unwrap();
        writeln!(&mut output, "# {cert_env}={cert_path}").unwrap();
        writeln!(&mut output, "# {key_env}={key_path}").unwrap();
        writeln!(&mut output).unwrap();
    }

    writeln!(&mut output, "# Authentication").unwrap();
    writeln!(
        &mut output,
        "# Required secret key used for JWT token generation and verification"
    )
    .unwrap();
    writeln!(
        &mut output,
        "# IMPORTANT: Changing this will invalidate all existing user tokens"
    )
    .unwrap();
    if mode.writes_live_secrets() {
        writeln!(&mut output, "JWT_SECRET={jwt_secret}").unwrap();
        writeln!(
            &mut output,
            "# Or mount a secret file and set JWT_SECRET_FILE=/run/secrets/JWT_SECRET"
        )
        .unwrap();
    } else {
        render_secret_binding_comment(&mut output, "JWT_SECRET", "change-me");
    }
    writeln!(&mut output).unwrap();
    if let Some(var_name) = &config.auth_email_env_var {
        writeln!(
            &mut output,
            "# {}",
            config
                .auth_email_env_comment
                .as_deref()
                .unwrap_or("Built-in auth email delivery")
        )
        .unwrap();
        if config
            .auth_email_env_comment
            .as_deref()
            .unwrap_or_default()
            .contains("SMTP")
        {
            render_secret_binding_comment(
                &mut output,
                var_name,
                "smtp://user:password@smtp.example.com:587",
            );
        } else {
            render_secret_binding_comment(&mut output, var_name, "change-me");
        }
        writeln!(&mut output).unwrap();
    }
    writeln!(&mut output, "# Admin User (optional)").unwrap();
    if mode == EnvTemplateMode::Production {
        writeln!(
            &mut output,
            "# Avoid storing bootstrap credentials in persisted env files for production."
        )
        .unwrap();
        writeln!(
            &mut output,
            "# Prefer interactive bootstrap or one-shot CI / secret-manager injection during setup."
        )
        .unwrap();
    } else {
        writeln!(
            &mut output,
            "# If set, these will be used when creating the admin user"
        )
        .unwrap();
    }
    writeln!(&mut output, "# ADMIN_EMAIL=admin@example.com").unwrap();
    writeln!(&mut output, "# ADMIN_PASSWORD=securepassword").unwrap();
    if config.admin_claim_examples.is_empty() {
        writeln!(
            &mut output,
            "# Optional auth claim columns use ADMIN_<COLUMN_NAME>, for example:"
        )
        .unwrap();
        writeln!(&mut output, "# ADMIN_TENANT_ID=1").unwrap();
    } else {
        writeln!(
            &mut output,
            "# Explicit security.auth.claims values are supplied with ADMIN_<COLUMN_NAME>:"
        )
        .unwrap();
        for example in &config.admin_claim_examples {
            writeln!(
                &mut output,
                "# {}={} ({})",
                example.env_var, example.example_value, example.comment
            )
            .unwrap();
        }
    }
    writeln!(&mut output).unwrap();
    writeln!(&mut output, "# Server Configuration").unwrap();
    writeln!(&mut output, "BIND_ADDR={}", config.bind_addr).unwrap();
    writeln!(&mut output).unwrap();

    if let Some(var_name) = &config.cors_origins_var {
        writeln!(&mut output, "# Security Overrides").unwrap();
        writeln!(
            &mut output,
            "# {var_name}=http://localhost:3000,http://127.0.0.1:3000"
        )
        .unwrap();
        if let Some(proxy_var) = &config.trusted_proxies_var {
            writeln!(&mut output, "# {proxy_var}=127.0.0.1,::1").unwrap();
        }
        writeln!(&mut output).unwrap();
    } else if let Some(proxy_var) = &config.trusted_proxies_var {
        writeln!(&mut output, "# Security Overrides").unwrap();
        writeln!(&mut output, "# {proxy_var}=127.0.0.1,::1").unwrap();
        writeln!(&mut output).unwrap();
    }

    writeln!(&mut output, "# Logging").unwrap();
    writeln!(
        &mut output,
        "# Possible values: error, warn, info, debug, trace"
    )
    .unwrap();
    writeln!(
        &mut output,
        "{}={}",
        config.log_filter_env, config.log_default_filter
    )
    .unwrap();

    output
}

pub fn render_env_template_for_mode(
    config_path: Option<&Path>,
    mode: EnvTemplateMode,
) -> Result<String> {
    let config = env_template_config(config_path)?;
    Ok(render_env_template_with_config(&config, mode))
}

pub fn render_env_template(config_path: Option<&Path>) -> Result<String> {
    render_env_template_for_mode(config_path, EnvTemplateMode::Development)
}

fn configured_admin_claim_env_examples(
    claims: &std::collections::BTreeMap<String, rest_macro_core::auth::AuthClaimMapping>,
) -> Vec<AdminClaimEnvExample> {
    let mut seen_columns = BTreeSet::new();
    let mut examples = Vec::new();

    for (claim_name, mapping) in claims {
        if !seen_columns.insert(mapping.column.clone()) {
            continue;
        }

        let example_value = match mapping.ty {
            AuthClaimType::I64 => "1",
            AuthClaimType::String => "pro",
            AuthClaimType::Bool => "true",
        };
        let comment = if claim_name == &mapping.column {
            format!(
                "claim.{claim_name} ({})",
                admin_claim_type_label(mapping.ty)
            )
        } else {
            format!(
                "claim.{claim_name} from user.{} ({})",
                mapping.column,
                admin_claim_type_label(mapping.ty)
            )
        };
        examples.push(AdminClaimEnvExample {
            env_var: admin_claim_env_var(&mapping.column),
            example_value: example_value.to_owned(),
            comment,
        });
    }

    examples
}

fn admin_claim_env_var(column_name: &str) -> String {
    let mut env_var = String::from("ADMIN_");
    for ch in column_name.chars() {
        if ch.is_ascii_alphanumeric() {
            env_var.push(ch.to_ascii_uppercase());
        } else {
            env_var.push('_');
        }
    }
    env_var
}

fn admin_claim_type_label(ty: AuthClaimType) -> &'static str {
    match ty {
        AuthClaimType::I64 => "I64",
        AuthClaimType::String => "String",
        AuthClaimType::Bool => "Bool",
    }
}

fn absolutize_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

pub fn default_env_path(config_path: Option<&Path>) -> Result<PathBuf> {
    let relative = match config_path {
        Some(config_path) => config_path
            .parent()
            .map(|parent| parent.join(".env"))
            .unwrap_or_else(|| PathBuf::from(".env")),
        None => PathBuf::from(".env"),
    };
    absolutize_path(&relative)
}

pub fn load_env_file(path: &Path) -> Result<()> {
    dotenv::from_path(path).map_err(|error| {
        Error::Config(format!(
            "failed to load environment file `{}`: {error}",
            path.display()
        ))
    })
}

pub fn write_env_file(
    output_path: Option<&Path>,
    config_path: Option<&Path>,
    backup_existing: bool,
    refuse_existing: bool,
    mode: EnvTemplateMode,
) -> Result<EnvFileReport> {
    let env_path = match output_path {
        Some(path) => absolutize_path(path)?,
        None => default_env_path(config_path)?,
    };

    if let Some(parent) = env_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let existing_assignments = if env_path.exists() {
        parse_env_assignments(&std::fs::read_to_string(&env_path)?)
    } else {
        BTreeMap::new()
    };

    let backup_path = if env_path.exists() {
        if refuse_existing {
            return Err(Error::Config(format!(
                "Environment file already exists at {}. Use --force to overwrite.",
                env_path.display()
            )));
        }

        if backup_existing {
            let backup_name = format!(
                "{}.backup",
                env_path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or(".env")
            );
            let backup_path = env_path
                .parent()
                .map(|parent| parent.join(&backup_name))
                .unwrap_or_else(|| PathBuf::from(backup_name));
            std::fs::copy(&env_path, &backup_path)?;
            Some(backup_path)
        } else {
            None
        }
    } else {
        None
    };

    let config = env_template_config(config_path)?;
    let preserved_jwt_secret = existing_env_value(&existing_assignments, "JWT_SECRET").is_some();
    let preserved_turso_encryption_var = config
        .turso_encryption_var
        .as_ref()
        .filter(|var_name| existing_env_value(&existing_assignments, var_name.as_str()).is_some())
        .cloned();
    let content = merge_env_template_with_existing(
        &render_env_template_with_config(&config, mode),
        &existing_assignments,
    );
    std::fs::write(&env_path, content)?;

    Ok(EnvFileReport {
        path: env_path,
        backup_path,
        generated_turso_encryption_var: if mode.writes_live_secrets()
            && config.turso_encryption_var.is_some()
            && preserved_turso_encryption_var.is_none()
        {
            config.turso_encryption_var
        } else {
            None
        },
        preserved_turso_encryption_var,
        generated_jwt_secret: mode.writes_live_secrets() && !preserved_jwt_secret,
        preserved_jwt_secret,
        mode,
    })
}

/// Generate .env template file
pub fn generate_env_template(
    config_path: Option<&Path>,
    mode: EnvTemplateMode,
) -> Result<EnvFileReport> {
    write_env_file(None, config_path, true, false, mode)
}

fn parse_env_assignments(content: &str) -> BTreeMap<String, String> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let (key, value) = trimmed.split_once('=')?;
            let key = key.trim();
            if key.is_empty() {
                return None;
            }
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn existing_env_value<'a>(
    existing_assignments: &'a BTreeMap<String, String>,
    key: &str,
) -> Option<&'a String> {
    existing_assignments
        .get(key)
        .filter(|value| !value.trim().is_empty())
}

fn merge_env_template_with_existing(
    rendered: &str,
    existing_assignments: &BTreeMap<String, String>,
) -> String {
    if existing_assignments.is_empty() {
        return rendered.to_owned();
    }

    let mut merged = Vec::new();
    let mut seen = BTreeSet::new();

    for line in rendered.lines() {
        if let Some((key, _)) = line.split_once('=')
            && let Some(existing_value) = existing_env_value(existing_assignments, key.trim())
        {
            merged.push(format!("{}={}", key.trim(), existing_value));
            seen.insert(key.trim().to_owned());
            continue;
        }
        merged.push(line.to_owned());
    }

    let extra_assignments = existing_assignments
        .iter()
        .filter(|(key, value)| !seen.contains(key.as_str()) && !value.trim().is_empty())
        .collect::<Vec<_>>();
    if !extra_assignments.is_empty() {
        merged.push(String::new());
        merged.push("# Preserved existing variables".to_owned());
        for (key, value) in extra_assignments {
            merged.push(format!("{key}={value}"));
        }
    }

    format!("{}\n", merged.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::{
        EnvTemplateMode, default_env_path, render_env_template, render_env_template_for_mode,
        write_env_file,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn temp_root(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir().join(format!("vsr_env_{prefix}_{stamp}"))
    }

    fn env_line_value<'a>(content: &'a str, key: &str) -> Option<&'a str> {
        content
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
    }

    #[test]
    fn rendered_env_template_reflects_service_security_and_turso_vars() {
        let content = render_env_template(Some(&fixture_path("security_api.eon")))
            .expect("security fixture should render");
        assert!(content.contains("DATABASE_URL=sqlite:var/data/security_api.db?mode=rwc"));
        let turso_key =
            env_line_value(&content, "TURSO_ENCRYPTION_KEY").expect("turso key should exist");
        assert_eq!(turso_key.len(), 64);
        assert!(turso_key.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert!(content.contains("# CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000"));
        assert!(content.contains("# TRUSTED_PROXIES=127.0.0.1,::1"));
        assert!(content.contains("APP_LOG=debug,sqlx=warn"));
    }

    #[test]
    fn rendered_env_template_reflects_turso_encryption_var() {
        let content = render_env_template(Some(&fixture_path("turso_local_encrypted_api.eon")))
            .expect("encrypted fixture should render");
        assert!(content.contains("DATABASE_URL=sqlite:var/data/turso_encrypted.db?mode=rwc"));
        let turso_key =
            env_line_value(&content, "TURSO_ENCRYPTION_KEY").expect("turso key should exist");
        assert_eq!(turso_key.len(), 64);
        assert!(turso_key.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn rendered_env_template_includes_auth_email_provider_env_hints() {
        let content = render_env_template(Some(&fixture_path("auth_management_api.eon")))
            .expect("auth management fixture should render");
        assert!(content.contains("RESEND_API_KEY=change-me"));
        assert!(content.contains(
            "# Or mount a secret file and set RESEND_API_KEY_FILE=/run/secrets/RESEND_API_KEY"
        ));
    }

    #[test]
    fn rendered_env_template_includes_explicit_auth_claim_examples() {
        let content = render_env_template(Some(&fixture_path("auth_claims_api.eon")))
            .expect("auth claims fixture should render");
        assert!(content.contains("# ADMIN_TENANT_SCOPE=1"));
        assert!(content.contains("# ADMIN_CLAIM_WORKSPACE_ID=1"));
        assert!(content.contains("# ADMIN_IS_STAFF=true"));
        assert!(content.contains("# ADMIN_PLAN=pro"));
    }

    #[test]
    fn production_env_template_does_not_write_live_secret_values() {
        let content = render_env_template_for_mode(
            Some(&fixture_path("auth_management_api.eon")),
            EnvTemplateMode::Production,
        )
        .expect("production template should render");
        assert!(
            content.contains("# Production mode: this template does not write live secret values.")
        );
        assert!(content.contains("DATABASE_URL=sqlite:var/data/auth_management_api.db?mode=rwc"));
        assert!(content.contains("# JWT_SECRET=change-me"));
        assert!(!content.contains("\nJWT_SECRET="));
        assert!(content.contains("# RESEND_API_KEY=change-me"));
        assert!(!content.contains("\nRESEND_API_KEY="));
    }

    #[test]
    fn default_env_path_uses_service_directory_when_config_is_present() {
        let config = PathBuf::from("/tmp/example/service/api.eon");
        assert_eq!(
            default_env_path(Some(&config)).expect("env path should resolve"),
            PathBuf::from("/tmp/example/service/.env")
        );
    }

    #[test]
    fn write_env_file_can_backup_existing_env_in_service_directory() {
        let root = temp_root("write_env");
        fs::create_dir_all(&root).expect("root should exist");
        let config = root.join("api.eon");
        fs::copy(fixture_path("security_api.eon"), &config).expect("fixture should copy");
        let env_path = root.join(".env");
        fs::write(&env_path, "DATABASE_URL=sqlite:old.db\n").expect("existing env should write");

        let report = write_env_file(
            None,
            Some(&config),
            true,
            false,
            EnvTemplateMode::Development,
        )
        .expect("env file should write with backup");
        assert_eq!(report.path, env_path);
        assert_eq!(report.backup_path, Some(root.join(".env.backup")));
        assert!(
            fs::read_to_string(root.join(".env.backup"))
                .expect("backup should read")
                .contains("DATABASE_URL=sqlite:old.db")
        );
        assert!(
            fs::read_to_string(&report.path)
                .expect("env should read")
                .contains("JWT_SECRET=")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn write_env_file_preserves_existing_secret_values_and_custom_vars() {
        let root = temp_root("preserve_env");
        fs::create_dir_all(&root).expect("root should exist");
        let config = root.join("api.eon");
        fs::copy(fixture_path("turso_local_encrypted_api.eon"), &config)
            .expect("fixture should copy");
        let env_path = root.join(".env");
        fs::write(
            &env_path,
            "DATABASE_URL=sqlite:custom.db?mode=rwc\nJWT_SECRET=preserve-jwt\nTURSO_ENCRYPTION_KEY=preserve-key\nEXTRA_TOKEN=keep-me\n",
        )
        .expect("existing env should write");

        let report = write_env_file(
            None,
            Some(&config),
            true,
            false,
            EnvTemplateMode::Development,
        )
        .expect("env file should preserve existing values");
        let content = fs::read_to_string(&report.path).expect("env should read");

        assert!(report.preserved_jwt_secret);
        assert!(!report.generated_jwt_secret);
        assert_eq!(
            report.preserved_turso_encryption_var.as_deref(),
            Some("TURSO_ENCRYPTION_KEY")
        );
        assert_eq!(report.generated_turso_encryption_var, None);
        assert!(content.contains("DATABASE_URL=sqlite:custom.db?mode=rwc"));
        assert!(content.contains("JWT_SECRET=preserve-jwt"));
        assert!(content.contains("TURSO_ENCRYPTION_KEY=preserve-key"));
        assert!(content.contains("EXTRA_TOKEN=keep-me"));

        let _ = fs::remove_dir_all(root);
    }
}
