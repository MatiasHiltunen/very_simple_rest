use crate::error::{Error, Result};
use chrono::{SecondsFormat, Utc};
use colored::Colorize;
use console::style;
use dialoguer::{Input, Password};
use regex::Regex;
use rest_macro_core::{
    auth::{AuthClaimMapping, AuthClaimType},
    compiler,
    db::{DbPool, query, query_scalar},
};
use sqlx::Row;
use std::collections::{BTreeMap, HashMap, HashSet};
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
async fn user_exists(pool: &DbPool, backend: DbBackend, email: &str) -> Result<bool> {
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE {} = {})",
        quote_ident(backend, "user"),
        quote_ident(backend, "email"),
        placeholder_for_backend(backend, 1)
    );
    let exists = query_scalar::<sqlx::Any, i64>(&sql)
        .bind(email)
        .fetch_one(pool)
        .await?;

    Ok(exists != 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AdminClaimColumn {
    claim_name: Option<String>,
    column_name: String,
    env_var: String,
    required: bool,
    ty: AuthClaimType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AdminClaimValue {
    I64 { column_name: String, value: i64 },
    String { column_name: String, value: String },
    Bool { column_name: String, value: bool },
}

impl AdminClaimValue {
    fn column_name(&self) -> &str {
        match self {
            Self::I64 { column_name, .. }
            | Self::String { column_name, .. }
            | Self::Bool { column_name, .. } => column_name,
        }
    }

    fn render(&self) -> String {
        match self {
            Self::I64 { column_name, value } => format!("{column_name}={value}"),
            Self::String { column_name, value } => format!("{column_name}={value}"),
            Self::Bool { column_name, value } => format!("{column_name}={value}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UserColumnMetadata {
    column_name: String,
    data_type: String,
    required: bool,
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
    let configured_claims = configured_auth_claims(config_path)?;
    create_admin_in_pool(
        &pool,
        email,
        password,
        interactive_claims,
        &configured_claims,
    )
    .await
}

async fn create_admin_in_pool(
    pool: &DbPool,
    email: String,
    password: String,
    interactive_claims: bool,
    configured_claims: &BTreeMap<String, AuthClaimMapping>,
) -> Result<()> {
    let backend = detect_backend(pool).await?;

    // Hash the password
    let hashed_password = bcrypt::hash(&password, bcrypt::DEFAULT_COST)?;

    // Check if the user already exists
    if user_exists(pool, backend, &email).await? {
        println!("{} {}", "User already exists:".yellow().bold(), email);
        return Ok(());
    }

    let claim_columns = discover_admin_claim_columns(pool, backend, configured_claims).await?;
    let claim_values = resolve_admin_claim_values(&claim_columns, interactive_claims)?;

    // Insert the admin user
    let mut columns = vec![
        "email".to_owned(),
        "password_hash".to_owned(),
        "role".to_owned(),
    ];
    columns.extend(
        claim_values
            .iter()
            .map(|claim| claim.column_name().to_owned()),
    );
    let placeholders = (1..=columns.len())
        .map(|index| placeholder_for_backend(backend, index))
        .collect::<Vec<_>>()
        .join(", ");
    let quoted_columns = columns
        .iter()
        .map(|column| quote_ident(backend, column))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO {} ({}) VALUES ({})",
        quote_ident(backend, "user"),
        quoted_columns,
        placeholders
    );
    let mut query = query(&sql)
        .bind(&email)
        .bind(&hashed_password)
        .bind("admin");
    for claim in &claim_values {
        query = match claim {
            AdminClaimValue::I64 { value, .. } => query.bind(*value),
            AdminClaimValue::String { value, .. } => query.bind(value),
            AdminClaimValue::Bool { value, .. } => query.bind(*value),
        };
    }
    query.execute(pool).await?;
    initialize_admin_management_fields(pool, &email).await?;

    println!(
        "{} {}",
        "Admin user created successfully:".green().bold(),
        email
    );
    if !claim_values.is_empty() {
        let rendered_claims = claim_values
            .iter()
            .map(AdminClaimValue::render)
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

async fn initialize_admin_management_fields(pool: &DbPool, email: &str) -> Result<()> {
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false);
    match query(
        "UPDATE user \
         SET created_at = COALESCE(created_at, ?), \
             email_verified_at = COALESCE(email_verified_at, ?), \
             updated_at = COALESCE(updated_at, ?) \
         WHERE email = ?",
    )
    .bind(&timestamp)
    .bind(&timestamp)
    .bind(&timestamp)
    .bind(email)
    .execute(pool)
    .await
    {
        Ok(_) => Ok(()),
        Err(error) if is_missing_auth_management_schema(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn is_missing_auth_management_schema(error: &sqlx::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("no such table: auth_user_token")
        || message.contains("relation \"auth_user_token\" does not exist")
        || message.contains("unknown table 'auth_user_token'")
        || message.contains("no such column: email_verified_at")
        || message.contains("column \"email_verified_at\" does not exist")
        || message.contains("unknown column 'email_verified_at'")
        || message.contains("no such column: created_at")
        || message.contains("column \"created_at\" does not exist")
        || message.contains("unknown column 'created_at'")
        || message.contains("no such column: updated_at")
        || message.contains("column \"updated_at\" does not exist")
        || message.contains("unknown column 'updated_at'")
}

async fn discover_admin_claim_columns(
    pool: &DbPool,
    backend: DbBackend,
    configured_claims: &BTreeMap<String, AuthClaimMapping>,
) -> Result<Vec<AdminClaimColumn>> {
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

    let mut user_columns = Vec::new();
    for row in rows {
        user_columns.push(user_column_from_row(&row, backend)?);
    }

    if configured_claims.is_empty() {
        return Ok(user_columns
            .into_iter()
            .filter_map(legacy_admin_claim_column_from_metadata)
            .collect());
    }

    configured_admin_claim_columns(&user_columns, configured_claims)
}

fn user_column_from_row(row: &sqlx::any::AnyRow, backend: DbBackend) -> Result<UserColumnMetadata> {
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

    Ok(UserColumnMetadata {
        column_name,
        data_type,
        required,
    })
}

fn legacy_admin_claim_column_from_metadata(
    metadata: UserColumnMetadata,
) -> Option<AdminClaimColumn> {
    if !is_claim_column_name(&metadata.column_name) || !is_integer_claim_type(&metadata.data_type) {
        return None;
    }

    Some(AdminClaimColumn {
        claim_name: None,
        env_var: admin_claim_env_var(&metadata.column_name),
        column_name: metadata.column_name,
        required: metadata.required,
        ty: AuthClaimType::I64,
    })
}

fn configured_admin_claim_columns(
    user_columns: &[UserColumnMetadata],
    configured_claims: &BTreeMap<String, AuthClaimMapping>,
) -> Result<Vec<AdminClaimColumn>> {
    let columns_by_name = user_columns
        .iter()
        .map(|column| (column.column_name.as_str(), column))
        .collect::<HashMap<_, _>>();
    let mut columns = Vec::new();
    let mut seen_columns = HashSet::new();

    for (claim_name, mapping) in configured_claims {
        let Some(metadata) = columns_by_name.get(mapping.column.as_str()) else {
            return Err(Error::Config(format!(
                "Configured auth claim `security.auth.claims.{claim_name}` maps to missing `user.{}` column",
                mapping.column
            )));
        };

        if !claim_type_matches_column(mapping.ty, &metadata.data_type) {
            return Err(Error::Config(format!(
                "Configured auth claim `security.auth.claims.{claim_name}` expects `{}` values, but `user.{}` is declared as `{}`",
                admin_claim_type_label(mapping.ty),
                mapping.column,
                metadata.data_type
            )));
        }

        if !seen_columns.insert(mapping.column.clone()) {
            continue;
        }

        columns.push(AdminClaimColumn {
            claim_name: Some(claim_name.clone()),
            column_name: mapping.column.clone(),
            env_var: admin_claim_env_var(&mapping.column),
            required: metadata.required,
            ty: mapping.ty,
        });
    }

    Ok(columns)
}

fn resolve_admin_claim_values(
    claim_columns: &[AdminClaimColumn],
    interactive_claims: bool,
) -> Result<Vec<AdminClaimValue>> {
    let mut values = Vec::new();

    for column in claim_columns {
        if let Some(value) = claim_value_from_env(column)? {
            values.push(value);
            continue;
        }

        if interactive_claims {
            if let Some(value) = prompt_admin_claim_value(column)? {
                values.push(value);
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

fn claim_value_from_env(column: &AdminClaimColumn) -> Result<Option<AdminClaimValue>> {
    match std::env::var(&column.env_var) {
        Ok(raw) if raw.trim().is_empty() => Ok(None),
        Ok(raw) => parse_admin_claim_value(column, raw.trim()),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn prompt_admin_claim_value(column: &AdminClaimColumn) -> Result<Option<AdminClaimValue>> {
    let prompt = if column.required {
        format!(
            "{} (required {} admin claim column)",
            admin_claim_display_name(column),
            admin_claim_type_label(column.ty).to_ascii_lowercase()
        )
    } else {
        format!(
            "{} (optional {} admin claim column, press Enter to skip)",
            admin_claim_display_name(column),
            admin_claim_type_label(column.ty).to_ascii_lowercase()
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
            } else {
                validate_admin_claim_input(column.ty, trimmed)
            }
        })
        .interact_text()
        .map_err(|_| Error::Cancelled)?;

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        parse_admin_claim_value(column, trimmed)
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

fn is_string_claim_type(data_type: &str) -> bool {
    let data_type = data_type.trim().to_ascii_lowercase();
    data_type.is_empty()
        || data_type.contains("char")
        || data_type.contains("text")
        || data_type.contains("clob")
        || data_type.contains("string")
}

fn is_bool_claim_type(data_type: &str) -> bool {
    let data_type = data_type.trim().to_ascii_lowercase();
    data_type.is_empty()
        || data_type.contains("bool")
        || data_type.contains("tinyint")
        || data_type.contains("int")
}

fn claim_type_matches_column(ty: AuthClaimType, data_type: &str) -> bool {
    match ty {
        AuthClaimType::I64 => is_integer_claim_type(data_type),
        AuthClaimType::String => is_string_claim_type(data_type),
        AuthClaimType::Bool => is_bool_claim_type(data_type),
    }
}

fn admin_claim_display_name(column: &AdminClaimColumn) -> String {
    match column.claim_name.as_deref() {
        Some(claim_name) if claim_name != column.column_name => {
            format!("{claim_name} (column {})", column.column_name)
        }
        Some(claim_name) => claim_name.to_owned(),
        None => column.column_name.clone(),
    }
}

fn admin_claim_type_label(ty: AuthClaimType) -> &'static str {
    match ty {
        AuthClaimType::I64 => "I64",
        AuthClaimType::String => "String",
        AuthClaimType::Bool => "Bool",
    }
}

fn validate_admin_claim_input(
    ty: AuthClaimType,
    raw: &str,
) -> std::result::Result<(), &'static str> {
    match ty {
        AuthClaimType::I64 => {
            if raw.parse::<i64>().is_ok() {
                Ok(())
            } else {
                Err("Please enter a valid integer")
            }
        }
        AuthClaimType::String => Ok(()),
        AuthClaimType::Bool => {
            if parse_bool_claim(raw).is_some() {
                Ok(())
            } else {
                Err("Please enter true/false, yes/no, on/off, or 1/0")
            }
        }
    }
}

fn parse_admin_claim_value(
    column: &AdminClaimColumn,
    raw: &str,
) -> Result<Option<AdminClaimValue>> {
    let value = match column.ty {
        AuthClaimType::I64 => {
            let value = raw.parse::<i64>().map_err(|_| {
                Error::Validation(format!(
                    "Environment variable {} must be a valid integer",
                    column.env_var
                ))
            })?;
            AdminClaimValue::I64 {
                column_name: column.column_name.clone(),
                value,
            }
        }
        AuthClaimType::String => AdminClaimValue::String {
            column_name: column.column_name.clone(),
            value: raw.to_owned(),
        },
        AuthClaimType::Bool => {
            let value = parse_bool_claim(raw).ok_or_else(|| {
                Error::Validation(format!(
                    "Environment variable {} must be true/false, yes/no, on/off, or 1/0",
                    column.env_var
                ))
            })?;
            AdminClaimValue::Bool {
                column_name: column.column_name.clone(),
                value,
            }
        }
    };
    Ok(Some(value))
}

fn parse_bool_claim(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn configured_auth_claims(
    config_path: Option<&Path>,
) -> Result<BTreeMap<String, AuthClaimMapping>> {
    let Some(path) = config_path else {
        return Ok(BTreeMap::new());
    };

    let service =
        compiler::load_service_from_path(path).map_err(|error| Error::Config(error.to_string()))?;
    Ok(service.security.auth.claims)
}

#[derive(Clone, Copy)]
enum DbBackend {
    Sqlite,
    Postgres,
    Mysql,
}

async fn detect_backend(pool: &DbPool) -> Result<DbBackend> {
    match pool {
        DbPool::Sqlx(pool) => {
            let connection = pool.acquire().await?;
            let backend_name = connection.backend_name().to_ascii_lowercase();
            if backend_name.contains("postgres") {
                Ok(DbBackend::Postgres)
            } else if backend_name.contains("mysql") {
                Ok(DbBackend::Mysql)
            } else if backend_name.contains("sqlite") {
                Ok(DbBackend::Sqlite)
            } else {
                Err(Error::Config(format!(
                    "Unsupported database backend for admin setup: {backend_name}"
                )))
            }
        }
        DbPool::TursoLocal(_) => Ok(DbBackend::Sqlite),
    }
}

fn placeholder_for_backend(backend: DbBackend, index: usize) -> String {
    if matches!(backend, DbBackend::Postgres) {
        format!("${index}")
    } else {
        "?".to_owned()
    }
}

fn quote_ident(backend: DbBackend, ident: &str) -> String {
    match backend {
        DbBackend::Sqlite | DbBackend::Postgres => {
            format!("\"{}\"", ident.replace('"', "\"\""))
        }
        DbBackend::Mysql => format!("`{}`", ident.replace('`', "``")),
    }
}

#[cfg(test)]
mod tests {
    use super::{configured_auth_claims, create_admin_in_pool, create_admin_with_options};
    use rest_macro_core::db::{DbPool, query};
    use sqlx::Row;
    use std::path::PathBuf;
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

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
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

    #[tokio::test]
    async fn create_admin_initializes_auth_management_fields_when_present() {
        let database_url = unique_sqlite_url("management_fields");
        let pool = DbPool::connect(&database_url)
            .await
            .expect("database should connect");

        query(
            "CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                email_verified_at TEXT,
                created_at TEXT,
                updated_at TEXT
            )",
        )
        .execute(&pool)
        .await
        .expect("user table should exist");

        create_admin_with_options(
            &database_url,
            None,
            "admin@example.com".to_owned(),
            "password123".to_owned(),
            false,
        )
        .await
        .expect("admin should be created");

        let row =
            query("SELECT email_verified_at, created_at, updated_at FROM user WHERE email = ?")
                .bind("admin@example.com")
                .fetch_one(&pool)
                .await
                .expect("admin row should exist");
        let email_verified_at: Option<String> = row
            .try_get("email_verified_at")
            .expect("email_verified_at should decode");
        let created_at: Option<String> =
            row.try_get("created_at").expect("created_at should decode");
        let updated_at: Option<String> =
            row.try_get("updated_at").expect("updated_at should decode");

        assert!(email_verified_at.is_some());
        assert!(created_at.is_some());
        assert!(updated_at.is_some());
    }

    #[tokio::test]
    async fn create_admin_uses_explicit_auth_claim_mappings_from_config() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let database_url = unique_sqlite_url("mapped_claims");
        let pool = DbPool::connect(&database_url)
            .await
            .expect("database should connect");

        query(
            "CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_scope INTEGER NOT NULL,
                claim_workspace_id INTEGER,
                is_staff BOOLEAN NOT NULL,
                plan TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("user table should exist");

        let configured_claims = configured_auth_claims(Some(&fixture_path("auth_claims_api.eon")))
            .expect("auth claims fixture should load");

        unsafe {
            std::env::set_var("ADMIN_TENANT_SCOPE", "7");
            std::env::set_var("ADMIN_CLAIM_WORKSPACE_ID", "42");
            std::env::set_var("ADMIN_IS_STAFF", "true");
            std::env::set_var("ADMIN_PLAN", "pro");
        }

        create_admin_in_pool(
            &pool,
            "admin@example.com".to_owned(),
            "password123".to_owned(),
            false,
            &configured_claims,
        )
        .await
        .expect("admin should be created");

        let row = query(
            "SELECT tenant_scope, claim_workspace_id, CAST(is_staff AS INTEGER) AS is_staff_value, plan \
             FROM user WHERE email = ?",
        )
        .bind("admin@example.com")
        .fetch_one(&pool)
        .await
        .expect("admin row should exist");
        let tenant_scope: i64 = row
            .try_get("tenant_scope")
            .expect("tenant scope should decode");
        let workspace_id: Option<i64> = row
            .try_get("claim_workspace_id")
            .expect("workspace claim should decode");
        let is_staff: i64 = row
            .try_get("is_staff_value")
            .expect("is_staff should decode");
        let plan: String = row.try_get("plan").expect("plan should decode");
        assert_eq!(tenant_scope, 7);
        assert_eq!(workspace_id, Some(42));
        assert_eq!(is_staff, 1);
        assert_eq!(plan, "pro");

        unsafe {
            std::env::remove_var("ADMIN_TENANT_SCOPE");
            std::env::remove_var("ADMIN_CLAIM_WORKSPACE_ID");
            std::env::remove_var("ADMIN_IS_STAFF");
            std::env::remove_var("ADMIN_PLAN");
        }
    }
}
