use crate::commands::admin::{create_admin, create_admin_with_options, prompt_admin_credentials};
use crate::commands::db::connect_database;
use crate::commands::env::generate_env_template;
use crate::commands::migrate::apply_setup_migrations;
use crate::error::Result;
use colored::Colorize;
use dialoguer::Confirm;
use rest_macro_core::auth::{AuthDbBackend, auth_user_table_ident};
use rest_macro_core::db::query_scalar;
use std::path::Path;

/// Run setup wizard to initialize the API
pub async fn run_setup(
    database_url: &str,
    config_path: Option<&Path>,
    non_interactive: bool,
) -> Result<()> {
    println!(
        "{}",
        "=== very_simple_rest API Setup Wizard ===".cyan().bold()
    );

    // Step 1: Check database connection
    println!("\n{}", "Step 1: Checking database connection".cyan().bold());
    let pool = connect_database(database_url, config_path).await?;
    println!("{}", "✓ Database connection successful".green());

    // Step 2: Apply auth and service migrations if needed
    println!("\n{}", "Step 2: Setting up database schema".cyan().bold());
    apply_setup_migrations(database_url, config_path)
        .await
        .map_err(|error| crate::error::Error::Config(error.to_string()))?;
    println!("{}", "✓ Schema migrated/verified".green());

    // Step 3: Check if admin user already exists
    println!("\n{}", "Step 3: Verifying admin user".cyan().bold());
    let auth_backend =
        AuthDbBackend::from_database_url(database_url).unwrap_or(AuthDbBackend::Sqlite);
    let admin_exists = query_scalar::<sqlx::Any, i64>(&format!(
        "SELECT COUNT(*) FROM {} WHERE role = 'admin'",
        auth_user_table_ident(auth_backend)
    ))
    .fetch_one(&pool)
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
    } else {
        println!(
            "{}",
            "No admin user found. You need to create an admin user.".yellow()
        );

        // Try to get credentials from environment variables
        let env_email = std::env::var("ADMIN_EMAIL").ok();
        let env_password = std::env::var("ADMIN_PASSWORD").ok();

        if non_interactive {
            if let (Some(email), Some(password)) = (env_email, env_password) {
                println!("Using admin credentials from environment variables");
                create_admin_with_options(database_url, config_path, email, password, false)
                    .await?;
            } else {
                println!("{}", "Warning: Cannot create admin user in non-interactive mode without ADMIN_EMAIL and ADMIN_PASSWORD environment variables.".yellow());
            }
        } else {
            // In interactive mode, always prompt for credentials
            let (email, password) = prompt_admin_credentials().await?;
            create_admin_with_options(database_url, config_path, email, password, true).await?;
        }
    }

    // Step 4: Generate .env template if needed
    println!("\n{}", "Step 4: Environment configuration".cyan().bold());
    if !non_interactive {
        let create_env = Confirm::new()
            .with_prompt("Do you want to generate a .env template file?")
            .default(true)
            .interact()
            .unwrap_or(false);

        if create_env {
            generate_env_template(config_path)?;
        }
    }

    println!("\n{}", "Setup completed successfully!".green().bold());
    println!("You can now start your API server.");

    Ok(())
}
