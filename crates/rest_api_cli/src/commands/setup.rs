use crate::error::Result;
use crate::commands::admin::create_admin;
use crate::commands::env::generate_env_template;
use colored::Colorize;
use dialoguer::Confirm;
use sqlx::AnyPool;

/// Run setup wizard to initialize the API
pub async fn run_setup(database_url: &str, non_interactive: bool) -> Result<()> {
    println!("{}", "=== very_simple_rest API Setup Wizard ===".cyan().bold());
    
    // Step 1: Check database connection
    println!("\n{}", "Step 1: Checking database connection".cyan().bold());
    let pool = AnyPool::connect(database_url).await?;
    println!("{}", "✓ Database connection successful".green());
    
    // Step 2: Create user table if it doesn't exist
    println!("\n{}", "Step 2: Setting up database schema".cyan().bold());
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )"
    )
    .execute(&pool)
    .await?;
    println!("{}", "✓ User table created/verified".green());
    
    // Step 3: Check if admin user already exists
    println!("\n{}", "Step 3: Verifying admin user".cyan().bold());
    let admin_exists = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM user WHERE role = 'admin')")
        .fetch_one(&pool)
        .await?;
    
    if admin_exists {
        println!("{}", "✓ Admin user already exists".green());
        
        if !non_interactive {
            let create_another = Confirm::new()
                .with_prompt("Do you want to create another admin user?")
                .default(false)
                .interact()
                .unwrap_or(false);
                
            if create_another {
                let (email, password) = crate::commands::admin::prompt_admin_credentials().await?;
                create_admin(database_url, email, password).await?;
            }
        }
    } else {
        println!("No admin user found. Creating admin user...");
        let (email, password) = crate::commands::admin::prompt_admin_credentials().await?;
        create_admin(database_url, email, password).await?;
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
            generate_env_template()?;
        }
    }
    
    println!("\n{}", "Setup completed successfully!".green().bold());
    println!("You can now start your API server.");
    
    Ok(())
} 