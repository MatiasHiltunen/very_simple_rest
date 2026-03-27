use crate::error::Result;
use colored::Colorize;
use std::path::Path;

/// Generate a .env file with default configuration
pub fn generate_env_file(path: Option<String>, config_path: Option<&Path>) -> Result<()> {
    let report = crate::commands::env::write_env_file(
        path.as_deref().map(Path::new),
        config_path,
        false,
        true,
    )?;

    println!(
        "{} {}",
        "Environment file created at:".green(),
        report.path.display()
    );
    if report.generated_jwt_secret {
        println!("{} JWT_SECRET", "Generated secret:".green());
    }
    if let Some(var_name) = &report.generated_turso_encryption_var {
        println!(
            "{} {} in {}",
            "Generated local Turso encryption key:".green(),
            var_name,
            report.path.display()
        );
    }
    println!(
        "\n{}",
        "Review the generated values before sharing the file.".yellow()
    );

    Ok(())
}
