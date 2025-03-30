use crate::error::Result;
use colored::Colorize;
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::Path;
use reqwest;

// Base URL for raw content (not the HTML view)
const TEMPLATE_DIR_URL: &str = "https://raw.githubusercontent.com/MatiasHiltunen/very_simple_rest/demo/examples/template";
const TEMPLATE_MAIN_RS: &str = "src/main.rs";
const TEMPLATE_CARGO_TOML: &str = "Cargo.toml";
const TEMPLATE_ENV_EXAMPLE: &str = ".env.example";
const TEMPLATE_README_MD: &str = "README.md";
const TEMPLATE_PUBLIC_INDEX: &str = "public/index.html";
const TEMPLATE_PUBLIC_APP_JS: &str = "public/app.js";

/// Create a new project from the template
pub fn create_project(
    name: &str,
    description: String,
    author: String,
    license: &str,
    output_dir: String,
    repository: Option<String>,
) -> Result<()> {
    // Create project directory
    let project_dir = Path::new(&output_dir).join(name);
    if project_dir.exists() {
        return Err(crate::error::Error::Config(format!(
            "Directory already exists: {}",
            project_dir.display()
        )));
    }
    
    create_dir_all(&project_dir)?;
    println!("{} {}", "Created project directory:".green(), project_dir.display());
    
    // Create src directory
    create_dir_all(project_dir.join("src"))?;
    
    // Create public directory
    create_dir_all(project_dir.join("public"))?;
    
    // Download and process template files
    let client = reqwest::blocking::Client::new();
    
    println!("Downloading template files from GitHub...");
    
    // Main source file
    fetch_and_process_file(
        &client,
        &format!("{}/{}", TEMPLATE_DIR_URL, TEMPLATE_MAIN_RS),
        &project_dir.join(TEMPLATE_MAIN_RS),
        &[
            ("{{project_name}}", name),
            ("{{description}}", &description),
            ("{{author}}", &author),
        ],
    )?;
    
    // Cargo.toml
    fetch_and_process_file(
        &client,
        &format!("{}/{}", TEMPLATE_DIR_URL, TEMPLATE_CARGO_TOML),
        &project_dir.join(TEMPLATE_CARGO_TOML),
        &[
            ("{{project_name}}", name),
            ("{{description}}", &description),
            ("{{author}}", &author),
            ("{{license}}", license),
            ("{{repository_url}}", repository.as_deref().unwrap_or("")),
        ],
    )?;
    
    // .env.example
    fetch_and_process_file(
        &client,
        &format!("{}/{}", TEMPLATE_DIR_URL, TEMPLATE_ENV_EXAMPLE),
        &project_dir.join(TEMPLATE_ENV_EXAMPLE),
        &[],
    )?;
    
    // README.md
    fetch_and_process_file(
        &client,
        &format!("{}/{}", TEMPLATE_DIR_URL, TEMPLATE_README_MD),
        &project_dir.join(TEMPLATE_README_MD),
        &[
            ("{{project_name}}", name),
            ("{{description}}", &description),
            ("{{author}}", &author),
            ("{{license}}", license),
        ],
    )?;
    
    // public/index.html
    fetch_and_process_file(
        &client,
        &format!("{}/{}", TEMPLATE_DIR_URL, TEMPLATE_PUBLIC_INDEX),
        &project_dir.join(TEMPLATE_PUBLIC_INDEX),
        &[
            ("{{project_name}}", name),
        ],
    )?;
    
    // public/app.js
    fetch_and_process_file(
        &client,
        &format!("{}/{}", TEMPLATE_DIR_URL, TEMPLATE_PUBLIC_APP_JS),
        &project_dir.join(TEMPLATE_PUBLIC_APP_JS),
        &[],
    )?;
    
    println!("\n{} {}", "Project created successfully at:".green().bold(), project_dir.display());
    println!("\nTo get started:");
    println!("  cd {}", name);
    println!("  cp .env.example .env  # Configure your environment");
    println!("  cargo run             # Start the server");
    
    Ok(())
}

/// Fetch a file from URL and process its content
fn fetch_and_process_file(
    client: &reqwest::blocking::Client,
    url: &str,
    destination: &Path,
    replacements: &[(&str, &str)],
) -> Result<()> {
    println!("Fetching: {}", url);
    
    // Fetch file content from URL
    let response = client.get(url)
        .send()
        .map_err(|e| crate::error::Error::Config(format!("Failed to fetch template file: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(crate::error::Error::Config(format!(
            "Failed to fetch template file: HTTP status {}", 
            response.status()
        )));
    }
    
    let content = response.text()
        .map_err(|e| crate::error::Error::Config(format!("Failed to read template content: {}", e)))?;
    
    // Create parent directories if needed
    if let Some(parent) = destination.parent() {
        create_dir_all(parent)?;
    }
    
    // Process content with replacements
    let mut processed_content = content;
    for (placeholder, value) in replacements {
        processed_content = processed_content.replace(placeholder, value);
    }
    
    // Write to destination file
    let mut file = File::create(destination)?;
    file.write_all(processed_content.as_bytes())?;
    
    println!("{} {}", "Created:".green(), destination.display());
    
    Ok(())
} 