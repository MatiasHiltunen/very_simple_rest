use crate::error::Result;
use colored::Colorize;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use rand::{rng, Rng};
use rand::distr::Alphanumeric;

/// Generate a secure random string for JWT secret
fn generate_random_secret(length: usize) -> String {
    rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Generate .env template file
pub fn generate_env_template() -> Result<()> {
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
    
    // Generate JWT secret
    let jwt_secret = generate_random_secret(32);
    
    // Create .env file
    let mut file = File::create(env_path)?;
    
    // Write template content
    writeln!(file, "# very_simple_rest API Configuration")?;
    writeln!(file)?;
    writeln!(file, "# Database Configuration")?;
    writeln!(file, "# Supported formats: sqlite, postgres, mysql")?;
    writeln!(file, "# Examples:")?;
    writeln!(file, "# DATABASE_URL=sqlite:app.db?mode=rwc")?;
    writeln!(file, "# DATABASE_URL=postgres://user:password@localhost:5432/dbname")?;
    writeln!(file, "# DATABASE_URL=mysql://user:password@localhost:3306/dbname")?;
    writeln!(file, "DATABASE_URL=sqlite:app.db?mode=rwc")?;
    writeln!(file)?;
    writeln!(file, "# Authentication")?;
    writeln!(file, "# Secret key used for JWT token generation and verification")?;
    writeln!(file, "# This is auto-generated, but you can change it if needed")?;
    writeln!(file, "# IMPORTANT: Changing this will invalidate all existing user tokens")?;
    writeln!(file, "JWT_SECRET={}", jwt_secret)?;
    writeln!(file)?;
    writeln!(file, "# Admin User (optional)")?;
    writeln!(file, "# If set, these will be used when creating the admin user")?;
    writeln!(file, "# ADMIN_EMAIL=admin@example.com")?;
    writeln!(file, "# ADMIN_PASSWORD=securepassword")?;
    writeln!(file)?;
    writeln!(file, "# Server Configuration")?;
    writeln!(file, "# HOST=127.0.0.1")?;
    writeln!(file, "# PORT=8080")?;
    writeln!(file)?;
    writeln!(file, "# Logging")?;
    writeln!(file, "# Possible values: error, warn, info, debug, trace")?;
    writeln!(file, "LOG_LEVEL=info")?;
    
    println!("{}", "✓ .env template generated successfully".green());
    println!("Edit the .env file to customize your configuration.");
    
    Ok(())
} 