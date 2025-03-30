use crate::error::{Error, Result};
use console::style;
use dialoguer::{Input, Password};
use sqlx::AnyPool;
use colored::Colorize;
use uuid::Uuid;
use chrono::Utc;
use serde_json::json;
use regex::Regex;
use std::sync::OnceLock;

/// Get a compiled regex for email validation
fn email_regex() -> &'static Regex {
    static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
    EMAIL_REGEX.get_or_init(|| {
        Regex::new(r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})").unwrap()
    })
}

/// Validates an email address with better format checks
fn validate_email(email: &str) -> bool {
    // Use regex for more comprehensive validation
    email_regex().is_match(&email.to_lowercase())
}

/// Validates password strength
fn validate_password(password: &str) -> bool {
    password.len() >= 8
}

/// Checks if a user with the given email already exists
async fn user_exists(pool: &AnyPool, email: &str) -> Result<bool> {
    let exists = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM user WHERE email = $1)")
        .bind(email)
        .fetch_one(pool)
        .await?;
    
    Ok(exists)
}

/// Asks for admin credentials interactively
pub async fn prompt_admin_credentials() -> Result<(String, String)> {
    println!("{}", style("Creating a new admin user").cyan().bold());
    
    // Prompt for email
    let email: String = Input::new()
        .with_prompt("Admin email")
        .validate_with(|input: &String| -> std::result::Result<(), &str> {
            if validate_email(input) {
                Ok(())
            } else {
                Err("Please enter a valid email address")
            }
        })
        .interact()
        .map_err(|_| Error::Cancelled)?;
    
    // Prompt for password
    let password: String = Password::new()
        .with_prompt("Admin password")
        .with_confirmation("Confirm password", "Passwords don't match")
        .validate_with(|input: &String| -> std::result::Result<(), &str> {
            if validate_password(input) {
                Ok(())
            } else {
                Err("Password must be at least 8 characters long")
            }
        })
        .interact()
        .map_err(|_| Error::Cancelled)?;
    
    Ok((email, password))
}

/// Create an admin user in the database
pub async fn create_admin(database_url: &str, email: String, password: String) -> Result<()> {
    println!("Connecting to database...");
    let pool = AnyPool::connect(database_url).await?;
    
    // Generate a UUID for the new admin user
    let id = Uuid::new_v4();
    
    // Hash the password
    let hashed_password = bcrypt::hash(&password, bcrypt::DEFAULT_COST)?;
    
    // Check if the user already exists
    if user_exists(&pool, &email).await? {
        println!("{} {}", "User already exists:".yellow().bold(), email);
        return Ok(());
    }
    
    // Current timestamp
    let now = Utc::now();
    
    // Insert the admin user
    sqlx::query(
        r#"
        INSERT INTO user (id, email, password, roles, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(id.to_string())
    .bind(&email)
    .bind(&hashed_password)
    .bind(json!(["admin", "user"]).to_string())
    .bind(now.to_string())
    .bind(now.to_string())
    .execute(&pool)
    .await?;
    
    println!("{} {}", "Admin user created successfully:".green().bold(), email);
    
    Ok(())
} 