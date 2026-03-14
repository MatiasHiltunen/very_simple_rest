use crate::error::{Error, Result};
use colored::Colorize;
use console::style;
use dialoguer::{Input, Password};
use regex::Regex;
use rest_macro_core::db::{DbPool, query, query_scalar};
use sqlx::Row;
use std::io::{IsTerminal, stdin, stdout};
use std::path::Path;
use std::sync::OnceLock;

use crate::commands::db::connect_database;

/// Get a compiled regex for email validation
fn email_regex() -> &'static Regex {
    static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
    EMAIL_REGEX.get_or_init(|| {
        Regex::new(
            r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})",
        )
        .unwrap()
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
async fn user_exists(pool: &DbPool, database_url: &str, email: &str) -> Result<bool> {
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM user WHERE email = {})",
        placeholder_for_url(database_url, 1)
    );
    let exists = query_scalar::<sqlx::Any, i64>(&sql)
        .bind(email)
        .fetch_one(pool)
        .await?;

    Ok(exists != 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AdminClaimColumn {
    column_name: String,
    env_var: String,
    required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AdminClaimValue {
    column_name: String,
    value: i64,
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
pub async fn create_admin(
    database_url: &str,
    config_path: Option<&Path>,
    email: String,
    password: String,
) -> Result<()> {
    let interactive_claims = stdin().is_terminal() && stdout().is_terminal();
    create_admin_with_options(
        database_url,
        config_path,
        email,
        password,
        interactive_claims,
    )
    .await
}

/// Create an admin user in the database with explicit claim prompting behavior
pub async fn create_admin_with_options(
    database_url: &str,
    config_path: Option<&Path>,
    email: String,
    password: String,
    interactive_claims: bool,
) -> Result<()> {
    println!("Connecting to database...");
    let pool = connect_database(database_url, config_path).await?;
    create_admin_in_pool(&pool, database_url, email, password, interactive_claims).await
}

async fn create_admin_in_pool(
    pool: &DbPool,
    database_url: &str,
    email: String,
    password: String,
    interactive_claims: bool,
) -> Result<()> {
    // Hash the password
    let hashed_password = bcrypt::hash(&password, bcrypt::DEFAULT_COST)?;

    // Check if the user already exists
    if user_exists(pool, database_url, &email).await? {
        println!("{} {}", "User already exists:".yellow().bold(), email);
        return Ok(());
    }

    let claim_columns = discover_admin_claim_columns(pool, database_url).await?;
    let claim_values = resolve_admin_claim_values(&claim_columns, interactive_claims)?;

    // Insert the admin user
    let mut columns = vec![
        "email".to_owned(),
        "password_hash".to_owned(),
        "role".to_owned(),
    ];
    columns.extend(claim_values.iter().map(|claim| claim.column_name.clone()));
    let placeholders = (1..=columns.len())
        .map(|index| placeholder_for_url(database_url, index))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO user ({}) VALUES ({})",
        columns.join(", "),
        placeholders
    );
    let mut query = query(&sql)
        .bind(&email)
        .bind(&hashed_password)
        .bind("admin");
    for claim in &claim_values {
        query = query.bind(claim.value);
    }
    query.execute(pool).await?;

    println!(
        "{} {}",
        "Admin user created successfully:".green().bold(),
        email
    );
    if !claim_values.is_empty() {
        let rendered_claims = claim_values
            .iter()
            .map(|claim| format!("{}={}", claim.column_name, claim.value))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{} {}",
            "Admin claim values:".green().bold(),
            rendered_claims
        );
    }

    Ok(())
}

async fn discover_admin_claim_columns(
    pool: &DbPool,
    database_url: &str,
) -> Result<Vec<AdminClaimColumn>> {
    let backend = detect_backend(database_url)?;
    let rows = match backend {
        DbBackend::Sqlite => query("PRAGMA table_info('user')").fetch_all(pool).await?,
        DbBackend::Postgres => {
            query(
                "SELECT column_name, data_type, is_nullable, column_default \
             FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'user' \
             ORDER BY ordinal_position",
            )
            .fetch_all(pool)
            .await?
        }
        DbBackend::Mysql => {
            query(
                "SELECT column_name, data_type, is_nullable, column_default \
             FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = 'user' \
             ORDER BY ordinal_position",
            )
            .fetch_all(pool)
            .await?
        }
    };

    let mut columns = Vec::new();
    for row in rows {
        let Some(metadata) = admin_claim_column_from_row(&row, backend)? else {
            continue;
        };
        columns.push(metadata);
    }

    Ok(columns)
}

fn admin_claim_column_from_row(
    row: &sqlx::any::AnyRow,
    backend: DbBackend,
) -> Result<Option<AdminClaimColumn>> {
    let (column_name, data_type, required) = match backend {
        DbBackend::Sqlite => {
            let column_name: String = row.try_get("name")?;
            let data_type: String = row
                .try_get::<Option<String>, _>("type")?
                .unwrap_or_default()
                .to_ascii_lowercase();
            let notnull = row.try_get::<i64, _>("notnull")? != 0;
            let default_value = row.try_get::<Option<String>, _>("dflt_value")?;
            (column_name, data_type, notnull && default_value.is_none())
        }
        DbBackend::Postgres | DbBackend::Mysql => {
            let column_name: String = row.try_get("column_name")?;
            let data_type: String = row.try_get::<String, _>("data_type")?.to_ascii_lowercase();
            let is_nullable = row.try_get::<String, _>("is_nullable")?;
            let default_value = row.try_get::<Option<String>, _>("column_default")?;
            (
                column_name,
                data_type,
                is_nullable.eq_ignore_ascii_case("NO") && default_value.is_none(),
            )
        }
    };

    if !is_claim_column_name(&column_name) || !is_integer_claim_type(&data_type) {
        return Ok(None);
    }

    Ok(Some(AdminClaimColumn {
        env_var: admin_claim_env_var(&column_name),
        column_name,
        required,
    }))
}

fn resolve_admin_claim_values(
    claim_columns: &[AdminClaimColumn],
    interactive_claims: bool,
) -> Result<Vec<AdminClaimValue>> {
    let mut values = Vec::new();

    for column in claim_columns {
        if let Some(value) = claim_value_from_env(column)? {
            values.push(AdminClaimValue {
                column_name: column.column_name.clone(),
                value,
            });
            continue;
        }

        if interactive_claims {
            if let Some(value) = prompt_admin_claim_value(column)? {
                values.push(AdminClaimValue {
                    column_name: column.column_name.clone(),
                    value,
                });
            }
            continue;
        }

        if column.required {
            return Err(Error::Config(format!(
                "Missing required admin claim column `{}`. Set {} or use interactive admin creation.",
                column.column_name, column.env_var
            )));
        }
    }

    Ok(values)
}

fn claim_value_from_env(column: &AdminClaimColumn) -> Result<Option<i64>> {
    match std::env::var(&column.env_var) {
        Ok(raw) if raw.trim().is_empty() => Ok(None),
        Ok(raw) => raw.trim().parse::<i64>().map(Some).map_err(|_| {
            Error::Validation(format!(
                "Environment variable {} must be a valid integer",
                column.env_var
            ))
        }),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn prompt_admin_claim_value(column: &AdminClaimColumn) -> Result<Option<i64>> {
    let prompt = if column.required {
        format!("{} (required admin claim column)", column.column_name)
    } else {
        format!(
            "{} (optional admin claim column, press Enter to skip)",
            column.column_name
        )
    };

    let raw: String = Input::new()
        .with_prompt(prompt)
        .allow_empty(!column.required)
        .validate_with(|input: &String| -> std::result::Result<(), &str> {
            let trimmed = input.trim();
            if trimmed.is_empty() {
                if column.required {
                    Err("This value is required")
                } else {
                    Ok(())
                }
            } else if trimmed.parse::<i64>().is_ok() {
                Ok(())
            } else {
                Err("Please enter a valid integer")
            }
        })
        .interact_text()
        .map_err(|_| Error::Cancelled)?;

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        trimmed
            .parse::<i64>()
            .map(Some)
            .map_err(|_| Error::Validation(format!("{} must be an integer", column.column_name)))
    }
}

fn admin_claim_env_var(column_name: &str) -> String {
    let mut env_var = String::from("ADMIN_");
    for ch in column_name.chars() {
        if ch.is_ascii_alphanumeric() {
            env_var.push(ch.to_ascii_uppercase());
        } else {
            env_var.push('_');
        }
    }
    env_var
}

fn is_claim_column_name(column_name: &str) -> bool {
    if matches!(column_name, "id" | "email" | "password_hash" | "role") {
        return false;
    }
    if let Some(rest) = column_name.strip_prefix("claim_") {
        return !rest.is_empty();
    }

    column_name.ends_with("_id") && column_name != "id"
}

fn is_integer_claim_type(data_type: &str) -> bool {
    let data_type = data_type.trim().to_ascii_lowercase();
    data_type.contains("int")
}

#[derive(Clone, Copy)]
enum DbBackend {
    Sqlite,
    Postgres,
    Mysql,
}

fn detect_backend(database_url: &str) -> Result<DbBackend> {
    if database_url.starts_with("postgres:") || database_url.starts_with("postgresql:") {
        Ok(DbBackend::Postgres)
    } else if database_url.starts_with("mysql:") || database_url.starts_with("mariadb:") {
        Ok(DbBackend::Mysql)
    } else if database_url.starts_with("sqlite:") {
        Ok(DbBackend::Sqlite)
    } else {
        Err(Error::Config(format!(
            "Unsupported database URL for admin setup: {database_url}"
        )))
    }
}

fn placeholder_for_url(database_url: &str, index: usize) -> String {
    if database_url.starts_with("postgres:") || database_url.starts_with("postgresql:") {
        format!("${index}")
    } else {
        "?".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::create_admin_with_options;
    use rest_macro_core::db::{DbPool, query};
    use sqlx::Row;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_sqlite_url(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("vsr_admin_{prefix}_{nanos}.db"));
        format!("sqlite:{}?mode=rwc", path.display())
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[tokio::test]
    async fn create_admin_inserts_detected_claim_columns_from_environment() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let database_url = unique_sqlite_url("claims");
        let pool = DbPool::connect(&database_url)
            .await
            .expect("database should connect");

        query(
            "CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_id INTEGER,
                claim_workspace_id INTEGER
            )",
        )
        .execute(&pool)
        .await
        .expect("user table should exist");

        unsafe {
            std::env::set_var("ADMIN_TENANT_ID", "7");
            std::env::set_var("ADMIN_CLAIM_WORKSPACE_ID", "42");
        }

        create_admin_with_options(
            &database_url,
            None,
            "admin@example.com".to_owned(),
            "password123".to_owned(),
            false,
        )
        .await
        .expect("admin should be created");

        let row = query("SELECT tenant_id, claim_workspace_id FROM user WHERE email = ?")
            .bind("admin@example.com")
            .fetch_one(&pool)
            .await
            .expect("admin row should exist");
        let tenant_id: Option<i64> = row.try_get("tenant_id").expect("tenant_id should decode");
        let workspace_id: Option<i64> = row
            .try_get("claim_workspace_id")
            .expect("workspace claim should decode");
        assert_eq!(tenant_id, Some(7));
        assert_eq!(workspace_id, Some(42));

        unsafe {
            std::env::remove_var("ADMIN_TENANT_ID");
            std::env::remove_var("ADMIN_CLAIM_WORKSPACE_ID");
        }
    }

    #[tokio::test]
    async fn create_admin_requires_missing_non_nullable_claim_columns_in_non_interactive_mode() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::remove_var("ADMIN_TENANT_ID");
        }
        let database_url = unique_sqlite_url("required_claim");
        let pool = DbPool::connect(&database_url)
            .await
            .expect("database should connect");

        query(
            "CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_id INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("user table should exist");

        let error = create_admin_with_options(
            &database_url,
            None,
            "admin@example.com".to_owned(),
            "password123".to_owned(),
            false,
        )
        .await
        .expect_err("missing required claim should fail");

        assert!(
            error.to_string().contains("ADMIN_TENANT_ID"),
            "unexpected error: {error}"
        );
    }
}
