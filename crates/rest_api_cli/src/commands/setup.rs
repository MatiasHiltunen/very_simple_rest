use crate::commands::admin::{create_admin, create_admin_with_options, prompt_admin_credentials};
use crate::commands::db::connect_database;
use crate::commands::env::{
    EnvFileReport, EnvTemplateMode, default_env_path, generate_env_template, load_env_file,
};
use crate::commands::migrate::apply_setup_migrations;
use crate::commands::tls::generate_self_signed_certificate;
use crate::error::{Error, Result};
use colored::Colorize;
use dialoguer::Confirm;
use rest_macro_core::auth::{AuthDbBackend, auth_jwt_signing_secret_ref, auth_user_table_ident};
use rest_macro_core::compiler::{self, ServiceSpec};
use rest_macro_core::database::DatabaseEngine;
use rest_macro_core::db::query_scalar;
use rest_macro_core::secret::{
    SecretRef, describe_secret_ref, has_secret, load_optional_secret_from_env_or_file,
};
use rest_macro_core::tls::{
    DEFAULT_TLS_CERT_PATH, DEFAULT_TLS_KEY_PATH, ResolvedTlsPaths, resolve_tls_paths,
};
use std::path::{Path, PathBuf};

#[derive(Default)]
struct SetupBootstrapReport {
    env_generated: Option<EnvFileReport>,
    env_loaded_from: Option<PathBuf>,
    tls: Option<TlsBootstrapReport>,
}

enum TlsBootstrapReport {
    Generated {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    Existing {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    SkippedMissing {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
}

struct RequiredSecretBinding {
    secret: SecretRef,
    label: String,
}

/// Run setup wizard to initialize the API
pub async fn run_setup(
    database_url: &str,
    config_path: Option<&Path>,
    non_interactive: bool,
    database_url_is_explicit: bool,
    production: bool,
) -> Result<()> {
    println!(
        "{}",
        "=== very_simple_rest API Setup Wizard ===".cyan().bold()
    );

    println!("\n{}", "Step 1: Preparing local environment".cyan().bold());
    let bootstrap = bootstrap_setup_environment(config_path, non_interactive, production)?;
    let effective_database_url = if database_url_is_explicit {
        database_url.to_owned()
    } else {
        load_optional_secret_from_env_or_file("DATABASE_URL", "DATABASE_URL")
            .map_err(|error| Error::Config(error.to_string()))?
            .unwrap_or_else(|| database_url.to_owned())
    };

    println!("\n{}", "Step 2: Checking database connection".cyan().bold());
    let pool = connect_database(&effective_database_url, config_path).await?;
    println!("{}", "✓ Database connection successful".green());

    println!("\n{}", "Step 3: Setting up database schema".cyan().bold());
    apply_setup_migrations(&effective_database_url, config_path)
        .await
        .map_err(|error| Error::Config(format!("{error:#}")))?;
    println!("{}", "✓ Schema migrated/verified".green());

    ensure_admin_user(
        &effective_database_url,
        config_path,
        &pool,
        non_interactive,
        true,
    )
    .await?;

    println!("\n{}", "Setup completed successfully!".green().bold());
    print_setup_summary(&bootstrap);
    println!("You can now start your API server.");

    Ok(())
}

pub async fn run_setup_for_serve(
    database_url: &str,
    config_path: &Path,
    database_url_is_explicit: bool,
    include_builtin_auth: bool,
) -> Result<()> {
    println!(
        "{}",
        "=== very_simple_rest API Setup Wizard ===".cyan().bold()
    );

    println!("\n{}", "Step 1: Preparing local environment".cyan().bold());
    let bootstrap = bootstrap_setup_environment(Some(config_path), true, false)?;
    let effective_database_url = if database_url_is_explicit {
        database_url.to_owned()
    } else {
        load_optional_secret_from_env_or_file("DATABASE_URL", "DATABASE_URL")
            .map_err(|error| Error::Config(error.to_string()))?
            .unwrap_or_else(|| database_url.to_owned())
    };

    println!("\n{}", "Step 2: Checking database connection".cyan().bold());
    let pool = connect_database(&effective_database_url, Some(config_path)).await?;
    println!("{}", "✓ Database connection successful".green());

    println!("\n{}", "Step 3: Setting up database schema".cyan().bold());
    apply_setup_migrations(&effective_database_url, Some(config_path))
        .await
        .map_err(|error| Error::Config(format!("{error:#}")))?;
    println!("{}", "✓ Schema migrated/verified".green());

    ensure_admin_user(
        &effective_database_url,
        Some(config_path),
        &pool,
        false,
        include_builtin_auth,
    )
    .await?;

    println!(
        "\n{}",
        "Serve bootstrap completed successfully!".green().bold()
    );
    print_setup_summary(&bootstrap);
    println!("Continuing to `vsr serve` with the prepared environment.");

    Ok(())
}

async fn ensure_admin_user(
    database_url: &str,
    config_path: Option<&Path>,
    pool: &rest_macro_core::db::DbPool,
    non_interactive: bool,
    include_builtin_auth: bool,
) -> Result<()> {
    if !include_builtin_auth {
        return Ok(());
    }

    println!("\n{}", "Step 4: Verifying admin user".cyan().bold());
    let auth_backend =
        AuthDbBackend::from_database_url(database_url).unwrap_or(AuthDbBackend::Sqlite);
    let admin_exists = query_scalar::<sqlx::Any, i64>(&format!(
        "SELECT COUNT(*) FROM {} WHERE role = 'admin'",
        auth_user_table_ident(auth_backend)
    ))
    .fetch_one(pool)
    .await?;

    if admin_exists > 0 {
        println!("{}", "✓ Admin user already exists".green());

        if !non_interactive {
            let create_another = Confirm::new()
                .with_prompt("Do you want to create another admin user?")
                .default(false)
                .interact()
                .unwrap_or(false);

            if create_another {
                let (email, password) = prompt_admin_credentials().await?;
                create_admin(database_url, config_path, email, password).await?;
            }
        }

        return Ok(());
    }

    println!(
        "{}",
        "No admin user found. You need to create an admin user.".yellow()
    );

    let env_email = std::env::var("ADMIN_EMAIL").ok();
    let env_password = std::env::var("ADMIN_PASSWORD").ok();

    if non_interactive {
        if let (Some(email), Some(password)) = (env_email, env_password) {
            println!("Using admin credentials from environment variables");
            create_admin_with_options(database_url, config_path, email, password, false).await?;
        } else {
            println!(
                "{}",
                "Warning: Cannot create admin user in non-interactive mode without ADMIN_EMAIL and ADMIN_PASSWORD environment variables.".yellow()
            );
        }
    } else {
        let (email, password) = prompt_admin_credentials().await?;
        create_admin_with_options(database_url, config_path, email, password, true).await?;
    }

    Ok(())
}

fn bootstrap_setup_environment(
    config_path: Option<&Path>,
    non_interactive: bool,
    production: bool,
) -> Result<SetupBootstrapReport> {
    let mut report = SetupBootstrapReport::default();
    let env_path = default_env_path(config_path)?;
    let required_turso_var = match config_path {
        Some(path) => required_turso_encryption_var(path)?,
        None => None,
    };
    let turso_key_missing = required_turso_var
        .as_deref()
        .map(required_env_var_is_missing)
        .unwrap_or(false);

    let generate_env = if non_interactive {
        config_path.is_some() && (!env_path.exists() || turso_key_missing)
    } else {
        let prompt = if env_path.exists() {
            if production {
                format!(
                    "Generate or refresh production-safe {} template before setup?",
                    env_path.display()
                )
            } else {
                format!("Generate or refresh {} before setup?", env_path.display())
            }
        } else {
            if production {
                format!(
                    "Generate production-safe {} template before setup?",
                    env_path.display()
                )
            } else {
                format!("Generate {} before setup?", env_path.display())
            }
        };
        Confirm::new()
            .with_prompt(prompt)
            .default(!env_path.exists() || turso_key_missing)
            .interact()
            .unwrap_or(false)
    };

    if generate_env {
        let mode = if production {
            EnvTemplateMode::Production
        } else {
            EnvTemplateMode::Development
        };
        let env_report = generate_env_template(config_path, mode)?;
        println!(
            "{} {}",
            if production {
                "Generated production environment template:".green().bold()
            } else {
                "Generated environment file:".green().bold()
            },
            env_report.path.display()
        );
        if let Some(backup_path) = &env_report.backup_path {
            println!(
                "{} {}",
                "Backed up previous environment file to:".green().bold(),
                backup_path.display()
            );
        }
        if env_report.generated_jwt_secret {
            println!("{} JWT_SECRET", "Generated secret in .env:".green().bold());
        } else if env_report.preserved_jwt_secret {
            println!(
                "{} JWT_SECRET in {}",
                "Preserved existing secret in .env:".green().bold(),
                env_report.path.display()
            );
        }
        if let Some(var_name) = &env_report.generated_turso_encryption_var {
            println!(
                "{} {} in {}",
                "Generated local Turso encryption key:".green().bold(),
                var_name,
                env_report.path.display()
            );
        } else if let Some(var_name) = &env_report.preserved_turso_encryption_var {
            println!(
                "{} {} in {}",
                "Preserved existing local Turso encryption key:"
                    .green()
                    .bold(),
                var_name,
                env_report.path.display()
            );
        }
        if production {
            println!(
                "{}",
                "Production mode did not write live secret values into the environment file."
                    .yellow()
            );
        }
        load_env_file(&env_report.path)?;
        println!(
            "{} {}",
            "Loaded environment file for this setup run:".green().bold(),
            env_report.path.display()
        );
        report.env_loaded_from = Some(env_report.path.clone());
        report.env_generated = Some(env_report);
    } else if env_path.exists() {
        load_env_file(&env_path)?;
        println!(
            "{} {}",
            "Loaded environment file for this setup run:".green().bold(),
            env_path.display()
        );
        report.env_loaded_from = Some(env_path);
    }

    if let Some(var_name) = required_turso_var
        && required_env_var_is_missing(var_name.as_str())
    {
        println!(
            "{} {}",
            "Warning: missing local Turso encryption key in the environment:"
                .yellow()
                .bold(),
            var_name
        );
        println!(
            "{}",
            "Database setup may fail until the key is resolved from the environment or a mounted *_FILE secret."
                .yellow()
        );
    }

    if let Some(config_path) = config_path {
        if production {
            validate_required_production_secrets(config_path)?;
        }
        report.tls = maybe_prepare_tls_assets(config_path, non_interactive, production)?;
    }

    Ok(report)
}

fn required_turso_encryption_var(config_path: &Path) -> Result<Option<String>> {
    let service = load_service(config_path)?;
    Ok(match &service.database.engine {
        DatabaseEngine::TursoLocal(engine) => engine
            .encryption_key
            .as_ref()
            .and_then(SecretRef::env_binding_name)
            .map(str::to_owned),
        DatabaseEngine::Sqlx => None,
    })
}

fn maybe_prepare_tls_assets(
    config_path: &Path,
    non_interactive: bool,
    production: bool,
) -> Result<Option<TlsBootstrapReport>> {
    let service = load_service(config_path)?;
    if !service.tls.is_enabled() {
        return Ok(None);
    }

    let resolved = resolve_service_tls_paths(config_path, &service)?;
    let cert_exists = resolved.cert_path.exists();
    let key_exists = resolved.key_path.exists();

    if cert_exists && key_exists {
        println!(
            "{} {}",
            "Using existing TLS certificate:".green().bold(),
            resolved.cert_path.display()
        );
        println!(
            "{} {}",
            "Using existing TLS private key:".green().bold(),
            resolved.key_path.display()
        );
        return Ok(Some(TlsBootstrapReport::Existing {
            cert_path: resolved.cert_path,
            key_path: resolved.key_path,
        }));
    }

    if cert_exists || key_exists {
        println!(
            "{}",
            "TLS is configured but only one of the certificate/key files exists.".yellow()
        );
        println!(
            "Certificate path: {}\nKey path: {}",
            resolved.cert_path.display(),
            resolved.key_path.display()
        );
        println!(
            "{}",
            "Run `vsr tls self-signed --force` or fix the configured TLS paths before serving HTTPS."
                .yellow()
        );
        return Ok(Some(TlsBootstrapReport::SkippedMissing {
            cert_path: resolved.cert_path,
            key_path: resolved.key_path,
        }));
    }

    if production {
        return Err(Error::Config(format!(
            "production setup refuses to generate self-signed TLS assets. Configure real certificate/key files for `{}` and `{}`, or terminate TLS upstream and remove the `tls` block.",
            resolved.cert_path.display(),
            resolved.key_path.display()
        )));
    }

    let generate_certs = if non_interactive {
        uses_default_dev_tls_paths(&service)
    } else {
        Confirm::new()
            .with_prompt(format!(
                "Generate self-signed TLS certs at {} and {}?",
                resolved.cert_path.display(),
                resolved.key_path.display()
            ))
            .default(true)
            .interact()
            .unwrap_or(false)
    };

    if !generate_certs {
        println!(
            "{}",
            "Skipping TLS certificate generation. HTTPS serving will fail until certs exist."
                .yellow()
        );
        return Ok(Some(TlsBootstrapReport::SkippedMissing {
            cert_path: resolved.cert_path,
            key_path: resolved.key_path,
        }));
    }

    let (cert_path, key_path) =
        generate_self_signed_certificate(Some(config_path), None, None, &[], false)?;
    Ok(Some(TlsBootstrapReport::Generated {
        cert_path,
        key_path,
    }))
}

fn validate_required_production_secrets(config_path: &Path) -> Result<()> {
    let service = load_service(config_path)?;
    let missing = required_production_secret_bindings(&service)
        .into_iter()
        .filter(|binding| !has_secret(&binding.secret))
        .collect::<Vec<_>>();

    if missing.is_empty() {
        return Ok(());
    }

    let details = missing
        .iter()
        .map(|binding| {
            let source = describe_required_secret_binding(&binding.secret);
            format!("- {} via {source}", binding.label)
        })
        .collect::<Vec<_>>()
        .join("\n");

    Err(Error::Config(format!(
        "production setup refuses to assume or generate live secrets.\nResolve the required secret bindings before setup continues:\n{details}"
    )))
}

fn required_production_secret_bindings(service: &ServiceSpec) -> Vec<RequiredSecretBinding> {
    let mut bindings = Vec::new();

    if !service
        .resources
        .iter()
        .any(|resource| resource.table_name == "user")
    {
        bindings.push(RequiredSecretBinding {
            secret: auth_jwt_signing_secret_ref(&service.security.auth)
                .cloned()
                .unwrap_or_else(|| SecretRef::env_or_file("JWT_SECRET")),
            label: "built-in auth JWT signing key".to_owned(),
        });
        if let Some(jwt) = &service.security.auth.jwt {
            for verification_key in &jwt.verification_keys {
                bindings.push(RequiredSecretBinding {
                    secret: verification_key.key.clone(),
                    label: format!(
                        "built-in auth JWT verification key `{}`",
                        verification_key.kid
                    ),
                });
            }
        }
    }

    if let DatabaseEngine::TursoLocal(engine) = &service.database.engine
        && let Some(secret) = engine.encryption_key.as_ref()
    {
        bindings.push(RequiredSecretBinding {
            secret: secret.clone(),
            label: "local Turso encryption key".to_owned(),
        });
    }

    if let Some(email) = &service.security.auth.email {
        match &email.provider {
            rest_macro_core::auth::AuthEmailProvider::Resend { api_key, .. } => {
                bindings.push(RequiredSecretBinding {
                    secret: api_key.clone(),
                    label: "Resend API key".to_owned(),
                });
            }
            rest_macro_core::auth::AuthEmailProvider::Smtp { connection_url } => {
                bindings.push(RequiredSecretBinding {
                    secret: connection_url.clone(),
                    label: "SMTP connection URL".to_owned(),
                });
            }
        }
    }

    bindings
}

fn describe_required_secret_binding(secret: &SecretRef) -> String {
    if let Some(var_name) = secret.env_binding_name() {
        format!("`{var_name}` or `{var_name}_FILE`")
    } else if let Some(source) = describe_secret_ref(secret) {
        source
    } else {
        "an unavailable secret binding".to_owned()
    }
}

fn load_service(config_path: &Path) -> Result<ServiceSpec> {
    compiler::load_service_from_path(config_path).map_err(|error| Error::Config(error.to_string()))
}

fn resolve_service_tls_paths(
    config_path: &Path,
    service: &ServiceSpec,
) -> Result<ResolvedTlsPaths> {
    let base_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    resolve_tls_paths(&service.tls, base_dir).map_err(|error| {
        Error::Config(format!(
            "failed to resolve TLS paths for `{}`: {error}",
            config_path.display()
        ))
    })
}

fn uses_default_dev_tls_paths(service: &ServiceSpec) -> bool {
    service.tls.cert_path.as_deref() == Some(DEFAULT_TLS_CERT_PATH)
        && service.tls.key_path.as_deref() == Some(DEFAULT_TLS_KEY_PATH)
}

fn required_env_var_is_missing(var_name: &str) -> bool {
    !has_secret(&SecretRef::env_or_file(var_name))
}

fn print_setup_summary(report: &SetupBootstrapReport) {
    println!("\n{}", "Setup summary".cyan().bold());

    if let Some(env_report) = &report.env_generated {
        if env_report.mode == EnvTemplateMode::Production {
            println!(
                "Generated production-safe .env template: {}",
                env_report.path.display()
            );
        } else {
            println!("Generated .env: {}", env_report.path.display());
        }
        if let Some(backup_path) = &env_report.backup_path {
            println!("Previous .env backup: {}", backup_path.display());
        }
        if env_report.generated_jwt_secret {
            println!("Generated JWT_SECRET in: {}", env_report.path.display());
        } else if env_report.preserved_jwt_secret {
            println!("Preserved JWT_SECRET in: {}", env_report.path.display());
        } else if env_report.mode == EnvTemplateMode::Production {
            println!(
                "Did not write a live JWT secret into: {}",
                env_report.path.display()
            );
        }
        if let Some(var_name) = &env_report.generated_turso_encryption_var {
            println!("Generated {var_name} in: {}", env_report.path.display());
        } else if let Some(var_name) = &env_report.preserved_turso_encryption_var {
            println!("Preserved {var_name} in: {}", env_report.path.display());
        } else if env_report.mode == EnvTemplateMode::Production {
            println!(
                "Did not write live database encryption secrets into: {}",
                env_report.path.display()
            );
        }
    } else if let Some(env_path) = &report.env_loaded_from {
        println!("Loaded .env from: {}", env_path.display());
    }

    match &report.tls {
        Some(TlsBootstrapReport::Generated {
            cert_path,
            key_path,
        }) => {
            println!("Generated TLS certificate: {}", cert_path.display());
            println!("Generated TLS private key: {}", key_path.display());
        }
        Some(TlsBootstrapReport::Existing {
            cert_path,
            key_path,
        }) => {
            println!("Using TLS certificate: {}", cert_path.display());
            println!("Using TLS private key: {}", key_path.display());
        }
        Some(TlsBootstrapReport::SkippedMissing {
            cert_path,
            key_path,
        }) => {
            println!(
                "TLS files still missing: {} and {}",
                cert_path.display(),
                key_path.display()
            );
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::run_setup;
    use crate::commands::db::database_url_from_service_config;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn temp_root(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir().join(format!("vsr_setup_{prefix}_{stamp}"))
    }

    #[tokio::test]
    async fn setup_generates_env_and_dev_tls_before_database_bootstrap() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("DATABASE_URL_FILE");
            std::env::remove_var("TURSO_ENCRYPTION_KEY");
            std::env::remove_var("JWT_SECRET");
            std::env::remove_var("TLS_CERT_PATH");
            std::env::remove_var("TLS_KEY_PATH");
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
        }

        let root = temp_root("bootstrap");
        fs::create_dir_all(&root).expect("root should exist");
        let config_path = root.join("setup_api.eon");
        fs::write(
            &config_path,
            r#"
            module: "setup_api"
            database: {
                engine: {
                    kind: TursoLocal
                    path: "var/data/setup_api.db"
                    encryption_key_env: "TURSO_ENCRYPTION_KEY"
                }
            }
            tls: {}
            resources: [
                {
                    name: "Note"
                    fields: [
                        { name: "id", type: I64, id: true }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        )
        .expect("config should write");

        let database_url =
            database_url_from_service_config(&config_path).expect("database url should resolve");
        run_setup(&database_url, Some(&config_path), true, false, false)
            .await
            .expect("setup should complete");

        let env_path = root.join(".env");
        let env_contents = fs::read_to_string(&env_path).expect(".env should exist");
        assert!(env_contents.contains("JWT_SECRET="));
        let turso_line = env_contents
            .lines()
            .find(|line| line.starts_with("TURSO_ENCRYPTION_KEY="))
            .expect("turso key should be written");
        let turso_key = turso_line
            .split_once('=')
            .map(|(_, value)| value)
            .expect("turso key line should split");
        assert_eq!(turso_key.len(), 64);
        assert!(turso_key.chars().all(|ch| ch.is_ascii_hexdigit()));

        assert!(root.join("var/data/setup_api.db").exists());
        assert!(root.join("certs/dev-cert.pem").exists());
        assert!(root.join("certs/dev-key.pem").exists());

        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("DATABASE_URL_FILE");
            std::env::remove_var("TURSO_ENCRYPTION_KEY");
            std::env::remove_var("JWT_SECRET");
            std::env::remove_var("TLS_CERT_PATH");
            std::env::remove_var("TLS_KEY_PATH");
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
        }
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn production_setup_refuses_to_generate_live_secrets_or_dev_tls() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("DATABASE_URL_FILE");
            std::env::remove_var("TURSO_ENCRYPTION_KEY");
            std::env::remove_var("TURSO_ENCRYPTION_KEY_FILE");
            std::env::remove_var("JWT_SECRET");
            std::env::remove_var("JWT_SECRET_FILE");
            std::env::remove_var("TLS_CERT_PATH");
            std::env::remove_var("TLS_KEY_PATH");
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
        }

        let root = temp_root("production_guard");
        fs::create_dir_all(&root).expect("root should exist");
        let config_path = root.join("setup_api.eon");
        fs::write(
            &config_path,
            r#"
            module: "setup_api"
            database: {
                engine: {
                    kind: TursoLocal
                    path: "var/data/setup_api.db"
                    encryption_key_env: "TURSO_ENCRYPTION_KEY"
                }
            }
            tls: {}
            resources: [
                {
                    name: "Note"
                    fields: [
                        { name: "id", type: I64, id: true }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        )
        .expect("config should write");

        let database_url =
            database_url_from_service_config(&config_path).expect("database url should resolve");
        let error = run_setup(&database_url, Some(&config_path), true, false, true)
            .await
            .expect_err("production setup should fail without resolved secrets");

        let message = error.to_string();
        assert!(message.contains("production setup refuses"));
        assert!(message.contains("JWT_SECRET"));
        assert!(message.contains("TURSO_ENCRYPTION_KEY"));

        let env_contents = fs::read_to_string(root.join(".env")).expect(".env should exist");
        assert!(env_contents.contains("# JWT_SECRET=change-me"));
        assert!(!env_contents.contains("\nJWT_SECRET="));

        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("DATABASE_URL_FILE");
            std::env::remove_var("TURSO_ENCRYPTION_KEY");
            std::env::remove_var("TURSO_ENCRYPTION_KEY_FILE");
            std::env::remove_var("JWT_SECRET");
            std::env::remove_var("JWT_SECRET_FILE");
            std::env::remove_var("TLS_CERT_PATH");
            std::env::remove_var("TLS_KEY_PATH");
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
        }
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn setup_honors_database_url_file_from_loaded_env() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("DATABASE_URL_FILE");
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
        }

        let root = temp_root("database_url_file");
        fs::create_dir_all(&root).expect("root should exist");
        let config_path = root.join("setup_api.eon");
        fs::write(
            &config_path,
            r#"
            module: "setup_api"
            database: {
                engine: {
                    kind: Sqlx
                }
            }
            resources: [
                {
                    name: "Note"
                    fields: [
                        { name: "id", type: I64, id: true }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        )
        .expect("config should write");

        let database_url_file = root.join("database-url.txt");
        let effective_database_url = format!(
            "sqlite:{}?mode=rwc",
            root.join("var/data/from_file.db").display()
        );
        fs::create_dir_all(root.join("var/data")).expect("db dir should exist");
        fs::write(&database_url_file, &effective_database_url).expect("db url file should write");
        fs::write(
            root.join(".env"),
            format!("DATABASE_URL_FILE={}\n", database_url_file.display()),
        )
        .expect(".env should write");

        run_setup(
            "sqlite:var/data/ignored.db?mode=rwc",
            Some(&config_path),
            true,
            false,
            false,
        )
        .await
        .expect("setup should honor DATABASE_URL_FILE");

        assert!(root.join("var/data/from_file.db").exists());
        assert!(!root.join("var/data/ignored.db").exists());

        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("DATABASE_URL_FILE");
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
        }
        let _ = fs::remove_dir_all(root);
    }
}
