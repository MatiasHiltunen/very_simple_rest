use crate::error::Result;
use colored::Colorize;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Generate a .env file with default configuration
pub fn generate_env_file(path: Option<String>, config_path: Option<&Path>) -> Result<()> {
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

    let env_content = crate::commands::env::render_env_template(config_path)?;

    // Write to file
    let mut file = File::create(&env_path)?;
    file.write_all(env_content.as_bytes())?;

    println!("{} {}", "Environment file created at:".green(), env_path);
    println!(
        "\n{}",
        "Remember to update the settings if needed.".yellow()
    );

    Ok(())
}
