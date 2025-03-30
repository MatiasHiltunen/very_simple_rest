use crate::error::Result;
use colored::Colorize;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use rand::Rng;
use rand::distr::{Alphanumeric, SampleString};

/// Generate a .env file with default configuration
pub fn generate_env_file(path: Option<String>) -> Result<()> {
    let env_path = match path {
        Some(p) => p,
        None => ".env".to_string(),
    };

    // Check if file already exists
    if Path::new(&env_path).exists() {
        return Err(crate::error::Error::Config(format!(
            "Environment file already exists at {}. Use --force to overwrite.",
            env_path
        )));
    }

    // Generate a random JWT secret
    let jwt_secret = generate_random_string(32);

    // Create the .env content
    let env_content = format!(
        r#"# Database Configuration
DATABASE_URL=sqlite:app.db?mode=rwc

# Authentication
# Secret key used for JWT token generation and verification
JWT_SECRET={}

# Server Configuration
HOST=127.0.0.1
PORT=8080

# Logging
# Possible values: error, warn, info, debug, trace
LOG_LEVEL=info
"#,
        jwt_secret
    );

    // Write to file
    let mut file = File::create(&env_path)?;
    file.write_all(env_content.as_bytes())?;

    println!("{} {}", "Environment file created at:".green(), env_path);
    println!("\n{}", "Remember to update the settings if needed.".yellow());

    Ok(())
}

/// Generate a random string of specified length
fn generate_random_string(length: usize) -> String {
    // Using the newer SampleString trait for rand 0.9
    let mut rng = rand::rng();
    // Generate alphanumeric part with special characters mixed in
    let alphanumeric = Alphanumeric.sample_string(&mut rng, length);
    let special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    
    // Mix in some special characters
    let mut result = alphanumeric.chars().collect::<Vec<_>>();
    for _ in 0..length/4 {
        let pos = rng.random_range(0..length);
        let special_idx = rng.random_range(0..special_chars.len());
        if let Some(special) = special_chars.chars().nth(special_idx) {
            if let Some(c) = result.get_mut(pos) {
                *c = special;
            }
        }
    }
    
    result.into_iter().collect()
} 