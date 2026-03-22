use crate::error::Result;
use colored::Colorize;
use rand::distr::{Alphanumeric, SampleString};
use rand::rng;
use rest_macro_core::auth::{AuthClaimType, AuthEmailProvider};
use rest_macro_core::compiler::{self, default_service_database_url};
use rest_macro_core::database::{DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV, DatabaseEngine};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// Generate a secure random string for JWT secret
fn generate_random_secret(length: usize) -> String {
    let mut random = rng();
    Alphanumeric.sample_string(&mut random, length)
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

pub fn render_env_template(config_path: Option<&Path>) -> Result<String> {
    let jwt_secret = generate_random_secret(32);
    let config = env_template_config(config_path)?;
    let mut output = String::new();

    writeln!(&mut output, "# very_simple_rest API Configuration").unwrap();
    writeln!(&mut output).unwrap();
    writeln!(&mut output, "# Database Configuration").unwrap();
    writeln!(
        &mut output,
        "# Override DATABASE_URL only if you need a runtime target different from the service defaults."
    )
    .unwrap();
    writeln!(&mut output, "DATABASE_URL={}", config.database_url).unwrap();
    writeln!(&mut output).unwrap();

    if let Some(var_name) = &config.turso_encryption_var {
        let heading = if var_name == DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV {
            "# Local Turso encryption used by the compiled database engine"
        } else {
            "# Local Turso encryption"
        };
        writeln!(&mut output, "{heading}").unwrap();
        writeln!(&mut output, "{var_name}=64_hex_characters_here").unwrap();
        writeln!(
            &mut output,
            "# Or mount a secret file and set {var_name}_FILE=/run/secrets/{var_name}"
        )
        .unwrap();
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
    writeln!(&mut output, "JWT_SECRET={jwt_secret}").unwrap();
    writeln!(
        &mut output,
        "# Or mount a secret file and set JWT_SECRET_FILE=/run/secrets/jwt_secret"
    )
    .unwrap();
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
            writeln!(
                &mut output,
                "{var_name}=smtp://user:password@smtp.example.com:587"
            )
            .unwrap();
        } else {
            writeln!(&mut output, "{var_name}=change-me").unwrap();
        }
        writeln!(
            &mut output,
            "# Or mount a secret file and set {var_name}_FILE=/run/secrets/{var_name}"
        )
        .unwrap();
        writeln!(&mut output).unwrap();
    }
    writeln!(&mut output, "# Admin User (optional)").unwrap();
    writeln!(
        &mut output,
        "# If set, these will be used when creating the admin user"
    )
    .unwrap();
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

    Ok(output)
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

/// Generate .env template file
pub fn generate_env_template(config_path: Option<&Path>) -> Result<()> {
    let env_path = Path::new(".env");

    // Check if .env already exists
    if env_path.exists() {
        println!("{}", "Warning: .env file already exists".yellow());
        println!("A backup will be created before generating a new one.");

        // Create backup
        let backup_path = Path::new(".env.backup");
        std::fs::copy(env_path, backup_path)?;
        println!("Backup created at .env.backup");
    }

    let content = render_env_template(config_path)?;
    std::fs::write(env_path, content)?;

    println!("{}", "✓ .env template generated successfully".green());
    println!("Edit the .env file to customize your configuration.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::render_env_template;
    use std::path::PathBuf;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    #[test]
    fn rendered_env_template_reflects_service_security_and_turso_vars() {
        let content = render_env_template(Some(&fixture_path("security_api.eon")))
            .expect("security fixture should render");
        assert!(content.contains("DATABASE_URL=sqlite:var/data/security_api.db?mode=rwc"));
        assert!(content.contains("TURSO_ENCRYPTION_KEY=64_hex_characters_here"));
        assert!(content.contains("# CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000"));
        assert!(content.contains("# TRUSTED_PROXIES=127.0.0.1,::1"));
        assert!(content.contains("APP_LOG=debug,sqlx=warn"));
    }

    #[test]
    fn rendered_env_template_reflects_turso_encryption_var() {
        let content = render_env_template(Some(&fixture_path("turso_local_encrypted_api.eon")))
            .expect("encrypted fixture should render");
        assert!(content.contains("DATABASE_URL=sqlite:var/data/turso_encrypted.db?mode=rwc"));
        assert!(content.contains("TURSO_ENCRYPTION_KEY=64_hex_characters_here"));
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
}
