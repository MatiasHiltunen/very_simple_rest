use crate::error::Result;
use colored::Colorize;
use rand::distr::{Alphanumeric, SampleString};
use rand::rng;
use rest_macro_core::compiler::{self, default_service_database_url};
use rest_macro_core::database::{DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV, DatabaseEngine};
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
    cors_origins_var: Option<String>,
    trusted_proxies_var: Option<String>,
    log_filter_env: String,
    log_default_filter: String,
}

fn env_template_config(config_path: Option<&Path>) -> Result<EnvTemplateConfig> {
    let Some(path) = config_path else {
        return Ok(EnvTemplateConfig {
            database_url: "sqlite:var/data/app.db?mode=rwc".to_owned(),
            turso_encryption_var: None,
            cors_origins_var: None,
            trusted_proxies_var: None,
            log_filter_env: "RUST_LOG".to_owned(),
            log_default_filter: "info".to_owned(),
        });
    };

    let service = compiler::load_service_from_path(path)
        .map_err(|error| crate::error::Error::Config(error.to_string()))?;
    let turso_encryption_var = match &service.database.engine {
        DatabaseEngine::TursoLocal(engine) => engine.encryption_key_env.clone(),
        DatabaseEngine::Sqlx => None,
    };

    Ok(EnvTemplateConfig {
        database_url: default_service_database_url(&service),
        turso_encryption_var,
        cors_origins_var: service.security.cors.origins_env.clone(),
        trusted_proxies_var: service.security.trusted_proxies.proxies_env.clone(),
        log_filter_env: service.logging.filter_env.clone(),
        log_default_filter: service.logging.default_filter.clone(),
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
    writeln!(&mut output, "# Admin User (optional)").unwrap();
    writeln!(
        &mut output,
        "# If set, these will be used when creating the admin user"
    )
    .unwrap();
    writeln!(&mut output, "# ADMIN_EMAIL=admin@example.com").unwrap();
    writeln!(&mut output, "# ADMIN_PASSWORD=securepassword").unwrap();
    writeln!(
        &mut output,
        "# Optional auth claim columns use ADMIN_<COLUMN_NAME>, for example:"
    )
    .unwrap();
    writeln!(&mut output, "# ADMIN_TENANT_ID=1").unwrap();
    writeln!(&mut output).unwrap();
    writeln!(&mut output, "# Server Configuration").unwrap();
    writeln!(&mut output, "BIND_ADDR=127.0.0.1:8080").unwrap();
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
}
