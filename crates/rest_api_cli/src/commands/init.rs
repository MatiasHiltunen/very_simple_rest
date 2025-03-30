use crate::error::Result;
use colored::Colorize;
use std::fs::{self, File, create_dir_all};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const TEMPLATE_DIR: &str = "examples/template";

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
    
    // Clone repository if provided, otherwise copy template
    let template_dir = PathBuf::from(TEMPLATE_DIR);
    if !template_dir.exists() {
        return Err(crate::error::Error::Config(format!(
            "Template directory not found: {}",
            template_dir.display()
        )));
    }
    
    // Create src directory
    create_dir_all(project_dir.join("src"))?;
    
    // Create public directory
    create_dir_all(project_dir.join("public"))?;
    
    // Copy and process template files
    copy_and_process_dir(
        &template_dir,
        &project_dir,
        &[
            ("{{project_name}}", name),
            ("{{description}}", &description),
            ("{{author}}", &author),
            ("{{license}}", license),
            ("{{repository_url}}", repository.as_deref().unwrap_or("")),
        ],
    )?;
    
    println!("\n{} {}", "Project created successfully at:".green().bold(), project_dir.display());
    println!("\nTo get started:");
    println!("  cd {}", name);
    println!("  cp .env.example .env  # Configure your environment");
    println!("  cargo run             # Start the server");
    
    Ok(())
}

/// Copy directory recursively and process template files
fn copy_and_process_dir(
    source: &Path,
    destination: &Path,
    replacements: &[(&str, &str)],
) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let file_name = source_path.file_name().unwrap().to_string_lossy().to_string();
        
        // Skip .git directory and any hidden files
        if file_name.starts_with('.') {
            continue;
        }
        
        let destination_path = destination.join(&file_name);
        
        if source_path.is_dir() {
            if !destination_path.exists() {
                create_dir_all(&destination_path)?;
            }
            copy_and_process_dir(&source_path, &destination_path, replacements)?;
        } else {
            process_and_copy_file(&source_path, &destination_path, replacements)?;
            println!("{} {}", "Created:".green(), destination_path.display());
        }
    }
    
    Ok(())
}

/// Process and copy a file, replacing template placeholders
fn process_and_copy_file(
    source: &Path,
    destination: &Path,
    replacements: &[(&str, &str)],
) -> Result<()> {
    let mut source_file = File::open(source)?;
    let mut content = String::new();
    source_file.read_to_string(&mut content)?;
    
    // Replace placeholders
    for (placeholder, value) in replacements {
        content = content.replace(placeholder, value);
    }
    
    let mut destination_file = File::create(destination)?;
    destination_file.write_all(content.as_bytes())?;
    
    Ok(())
} 