use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{IsTerminal, Write, stdin, stdout};

use actix_web::HttpResponse;
use bcrypt::hash;
use serde_json::Value;

use crate::db::{DbPool, query_scalar};
use crate::errors;

use super::db_ops::{
    UserColumnMetadata, detect_auth_backend, user_table_columns,
};
use super::helpers::{
    is_missing_auth_management_schema, now_timestamp_string,
};
use super::migrations::{AuthDbBackend, auth_user_table_ident};
use super::settings::{AuthClaimMapping, AuthClaimType, AuthSettings};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdminClaimColumn {
    pub claim_name: Option<String>,
    pub column_name: String,
    pub env_var: String,
    pub required: bool,
    pub ty: AuthClaimType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AdminClaimValue {
    I64 { column_name: String, value: i64 },
    String { column_name: String, value: String },
    Bool { column_name: String, value: bool },
}

impl AdminClaimValue {
    pub fn column_name(&self) -> &str {
        match self {
            Self::I64 { column_name, .. }
            | Self::String { column_name, .. }
            | Self::Bool { column_name, .. } => column_name,
        }
    }

    pub fn render(&self) -> String {
        match self {
            Self::I64 { column_name, value } => format!("{column_name}={value}"),
            Self::String { column_name, value } => format!("{column_name}={value}"),
            Self::Bool { column_name, value } => format!("{column_name}={value}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ManagedClaimUpdateValue {
    I64 {
        claim_name: String,
        column_name: String,
        value: Option<i64>,
    },
    String {
        claim_name: String,
        column_name: String,
        value: Option<String>,
    },
    Bool {
        claim_name: String,
        column_name: String,
        value: Option<bool>,
    },
}

impl ManagedClaimUpdateValue {
    pub fn column_name(&self) -> &str {
        match self {
            Self::I64 { column_name, .. }
            | Self::String { column_name, .. }
            | Self::Bool { column_name, .. } => column_name,
        }
    }
}

pub(crate) fn legacy_admin_claim_column_from_metadata(
    metadata: UserColumnMetadata,
) -> Option<AdminClaimColumn> {
    if !is_admin_claim_column_name(&metadata.column_name)
        || !is_integer_claim_type(&metadata.data_type)
    {
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

pub(crate) fn configured_admin_claim_columns(
    user_columns: &[UserColumnMetadata],
    configured_claims: &BTreeMap<String, AuthClaimMapping>,
) -> Result<Vec<AdminClaimColumn>, String> {
    let columns_by_name = user_columns
        .iter()
        .map(|column| (column.column_name.as_str(), column))
        .collect::<HashMap<_, _>>();
    let mut columns = Vec::new();
    let mut seen_columns = HashSet::new();

    for (claim_name, mapping) in configured_claims {
        let Some(metadata) = columns_by_name.get(mapping.column.as_str()) else {
            return Err(format!(
                "Configured auth claim `security.auth.claims.{claim_name}` maps to missing `user.{}` column",
                mapping.column
            ));
        };

        if !claim_type_matches_column(mapping.ty, &metadata.data_type) {
            return Err(format!(
                "Configured auth claim `security.auth.claims.{claim_name}` expects `{}` values, but `user.{}` is declared as `{}`",
                admin_claim_type_label(mapping.ty),
                mapping.column,
                metadata.data_type
            ));
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

pub(crate) fn is_admin_claim_column_name(column_name: &str) -> bool {
    if matches!(column_name, "id" | "email" | "password_hash" | "role") {
        return false;
    }
    if let Some(rest) = column_name.strip_prefix("claim_") {
        return !rest.is_empty();
    }

    column_name.ends_with("_id") && column_name != "id"
}

pub(crate) fn is_integer_claim_type(data_type: &str) -> bool {
    data_type.trim().to_ascii_lowercase().contains("int")
}

pub(crate) fn is_string_claim_type(data_type: &str) -> bool {
    let data_type = data_type.trim().to_ascii_lowercase();
    data_type.is_empty()
        || data_type.contains("char")
        || data_type.contains("text")
        || data_type.contains("clob")
        || data_type.contains("string")
}

pub(crate) fn is_bool_claim_type(data_type: &str) -> bool {
    let data_type = data_type.trim().to_ascii_lowercase();
    data_type.is_empty()
        || data_type.contains("bool")
        || data_type.contains("tinyint")
        || data_type.contains("int")
}

pub(crate) fn claim_type_matches_column(ty: AuthClaimType, data_type: &str) -> bool {
    match ty {
        AuthClaimType::I64 => is_integer_claim_type(data_type),
        AuthClaimType::String => is_string_claim_type(data_type),
        AuthClaimType::Bool => is_bool_claim_type(data_type),
    }
}

pub(crate) fn admin_claim_env_var(column_name: &str) -> String {
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

pub(crate) fn resolve_admin_claim_values(
    claim_columns: &[AdminClaimColumn],
    interactive: bool,
) -> Result<Vec<AdminClaimValue>, String> {
    let mut values = Vec::new();

    for column in claim_columns {
        if let Some(value) = claim_value_from_env(column)? {
            values.push(value);
            continue;
        }

        if interactive {
            if let Some(value) = prompt_admin_claim_value(column)? {
                values.push(value);
            }
            continue;
        }

        if column.required {
            return Err(format!(
                "Missing required admin claim column `{}`. Set {} before starting the server.",
                column.column_name, column.env_var
            ));
        }
    }

    Ok(values)
}

pub(crate) fn claim_value_from_env(
    column: &AdminClaimColumn,
) -> Result<Option<AdminClaimValue>, String> {
    match std::env::var(&column.env_var) {
        Ok(raw) if raw.trim().is_empty() => Ok(None),
        Ok(raw) => parse_admin_claim_value(column, raw.trim()),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(format!(
            "Failed to read environment variable {}: {}",
            column.env_var, error
        )),
    }
}

pub(crate) fn prompt_admin_claim_value(
    column: &AdminClaimColumn,
) -> Result<Option<AdminClaimValue>, String> {
    let prompt = if column.required {
        format!(
            "{} (required {} admin claim column): ",
            admin_claim_display_name(column),
            admin_claim_type_label(column.ty).to_ascii_lowercase()
        )
    } else {
        format!(
            "{} (optional {} admin claim column, press Enter to skip): ",
            admin_claim_display_name(column),
            admin_claim_type_label(column.ty).to_ascii_lowercase()
        )
    };

    print!("{prompt}");
    stdout()
        .flush()
        .map_err(|error| format!("Failed to flush stdout: {error}"))?;

    let mut value = String::new();
    stdin()
        .read_line(&mut value)
        .map_err(|error| format!("Failed to read {}: {error}", column.column_name))?;

    let value = value.trim();
    if value.is_empty() {
        if column.required {
            return Err(format!("{} is required", column.column_name));
        }
        return Ok(None);
    }

    parse_admin_claim_value(column, value)
}

pub(crate) fn admin_claim_display_name(column: &AdminClaimColumn) -> String {
    match column.claim_name.as_deref() {
        Some(claim_name) if claim_name != column.column_name => {
            format!("{claim_name} (column {})", column.column_name)
        }
        Some(claim_name) => claim_name.to_owned(),
        None => column.column_name.clone(),
    }
}

pub(crate) fn admin_claim_type_label(ty: AuthClaimType) -> &'static str {
    match ty {
        AuthClaimType::I64 => "I64",
        AuthClaimType::String => "String",
        AuthClaimType::Bool => "Bool",
    }
}

pub(crate) fn parse_admin_claim_value(
    column: &AdminClaimColumn,
    raw: &str,
) -> Result<Option<AdminClaimValue>, String> {
    let value = match column.ty {
        AuthClaimType::I64 => {
            let value = raw.parse::<i64>().map_err(|_| {
                format!(
                    "Environment variable {} must be a valid integer",
                    column.env_var
                )
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
                format!(
                    "Environment variable {} must be true/false, yes/no, on/off, or 1/0",
                    column.env_var
                )
            })?;
            AdminClaimValue::Bool {
                column_name: column.column_name.clone(),
                value,
            }
        }
    };

    Ok(Some(value))
}

pub(crate) fn parse_bool_claim(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

pub(crate) fn resolve_managed_claim_updates(
    user_columns: &[UserColumnMetadata],
    configured_claims: &BTreeMap<String, AuthClaimMapping>,
    provided_claims: &BTreeMap<String, Value>,
) -> Result<Vec<ManagedClaimUpdateValue>, HttpResponse> {
    if provided_claims.is_empty() {
        return Ok(Vec::new());
    }
    if configured_claims.is_empty() {
        return Err(errors::bad_request(
            "claims_not_configured",
            "This service does not declare `security.auth.claims`, so managed claim updates are unavailable",
        ));
    }

    let configured_columns = configured_admin_claim_columns(user_columns, configured_claims)
        .map_err(|error| errors::validation_error("claims", error))?;
    let columns_by_claim = configured_columns
        .into_iter()
        .filter_map(|column| column.claim_name.clone().map(|name| (name, column)))
        .collect::<HashMap<_, _>>();

    let mut updates = Vec::new();
    for (claim_name, raw_value) in provided_claims {
        let field = format!("claims.{claim_name}");
        let Some(column) = columns_by_claim.get(claim_name.as_str()) else {
            return Err(errors::validation_error(
                field,
                format!(
                    "Unknown managed auth claim `{claim_name}`. Declare it under `security.auth.claims` first"
                ),
            ));
        };

        let update = match (column.ty, raw_value) {
            (AuthClaimType::I64, Value::Null) => {
                if column.required {
                    return Err(errors::validation_error(
                        field,
                        format!("Managed auth claim `{claim_name}` cannot be null"),
                    ));
                }
                ManagedClaimUpdateValue::I64 {
                    claim_name: claim_name.clone(),
                    column_name: column.column_name.clone(),
                    value: None,
                }
            }
            (AuthClaimType::I64, Value::Number(number)) => {
                let Some(value) = number.as_i64() else {
                    return Err(errors::validation_error(
                        field,
                        format!("Managed auth claim `{claim_name}` must be an integer"),
                    ));
                };
                ManagedClaimUpdateValue::I64 {
                    claim_name: claim_name.clone(),
                    column_name: column.column_name.clone(),
                    value: Some(value),
                }
            }
            (AuthClaimType::String, Value::Null) => {
                if column.required {
                    return Err(errors::validation_error(
                        field,
                        format!("Managed auth claim `{claim_name}` cannot be null"),
                    ));
                }
                ManagedClaimUpdateValue::String {
                    claim_name: claim_name.clone(),
                    column_name: column.column_name.clone(),
                    value: None,
                }
            }
            (AuthClaimType::String, Value::String(value)) => ManagedClaimUpdateValue::String {
                claim_name: claim_name.clone(),
                column_name: column.column_name.clone(),
                value: Some(value.clone()),
            },
            (AuthClaimType::Bool, Value::Null) => {
                if column.required {
                    return Err(errors::validation_error(
                        field,
                        format!("Managed auth claim `{claim_name}` cannot be null"),
                    ));
                }
                ManagedClaimUpdateValue::Bool {
                    claim_name: claim_name.clone(),
                    column_name: column.column_name.clone(),
                    value: None,
                }
            }
            (AuthClaimType::Bool, Value::Bool(value)) => ManagedClaimUpdateValue::Bool {
                claim_name: claim_name.clone(),
                column_name: column.column_name.clone(),
                value: Some(*value),
            },
            (AuthClaimType::I64, _) => {
                return Err(errors::validation_error(
                    field,
                    format!("Managed auth claim `{claim_name}` must be an integer"),
                ));
            }
            (AuthClaimType::String, _) => {
                return Err(errors::validation_error(
                    field,
                    format!("Managed auth claim `{claim_name}` must be a string"),
                ));
            }
            (AuthClaimType::Bool, _) => {
                return Err(errors::validation_error(
                    field,
                    format!("Managed auth claim `{claim_name}` must be a boolean"),
                ));
            }
        };
        updates.push(update);
    }

    Ok(updates)
}

pub(crate) async fn insert_admin_user(
    pool: &DbPool,
    backend: AuthDbBackend,
    email: &str,
    password_hash: &str,
    claim_values: &[AdminClaimValue],
) -> Result<(), sqlx::Error> {
    use crate::db::query;

    let mut columns = vec![
        "email".to_owned(),
        "password_hash".to_owned(),
        "role".to_owned(),
    ];
    columns.extend(
        claim_values
            .iter()
            .map(|claim| claim.column_name().to_owned())
            .collect::<Vec<_>>(),
    );

    let placeholders = (1..=columns.len())
        .map(|index| super::db_ops::placeholder_for_backend(backend, index))
        .collect::<Vec<_>>()
        .join(", ");
    let quoted_columns = columns
        .iter()
        .map(|column| backend.quote_ident(column))
        .collect::<Vec<_>>()
        .join(", ");

    let sql = format!(
        "INSERT INTO {} ({}) VALUES ({})",
        backend.quote_ident("user"),
        quoted_columns,
        placeholders
    );
    let mut insert_query = query(&sql).bind(email).bind(password_hash).bind("admin");
    for claim in claim_values {
        insert_query = match claim {
            AdminClaimValue::I64 { value, .. } => insert_query.bind(*value),
            AdminClaimValue::String { value, .. } => insert_query.bind(value),
            AdminClaimValue::Bool { value, .. } => insert_query.bind(*value),
        };
    }
    insert_query.execute(pool).await?;
    let verified_at = now_timestamp_string();
    if let Err(error) = query(&format!(
        "UPDATE {} SET created_at = COALESCE(created_at, ?), email_verified_at = ?, updated_at = ? WHERE email = ?",
        auth_user_table_ident(backend)
    ))
        .bind(&verified_at)
        .bind(&verified_at)
        .bind(&verified_at)
        .bind(email)
        .execute(pool)
        .await
        && !is_missing_auth_management_schema(&error)
    {
        return Err(error);
    }
    Ok(())
}

/// Check if an admin user exists, and create one automatically if not
///
/// This function will:
/// 1. Check if an admin user already exists
/// 2. If not, prompt the user to enter admin credentials via stdin
///
/// Returns true if an admin exists (either previously or newly created),
/// false only if there was an error creating the admin user.
pub async fn ensure_admin_exists(pool: &DbPool) -> Result<bool, sqlx::Error> {
    ensure_admin_exists_with_settings_and_claim_prompt_mode(
        pool,
        &AuthSettings::default(),
        stdin().is_terminal() && stdout().is_terminal(),
    )
    .await
}

pub async fn ensure_admin_exists_with_settings(
    pool: &DbPool,
    settings: &AuthSettings,
) -> Result<bool, sqlx::Error> {
    ensure_admin_exists_with_settings_and_claim_prompt_mode(
        pool,
        settings,
        stdin().is_terminal() && stdout().is_terminal(),
    )
    .await
}

pub async fn validate_auth_claim_mappings(
    pool: &DbPool,
    settings: &AuthSettings,
) -> Result<(), String> {
    if settings.claims.is_empty() {
        return Ok(());
    }

    let backend = detect_auth_backend(pool)
        .await
        .map_err(|error| format!("Failed to detect auth backend: {error}"))?;
    let user_columns = user_table_columns(pool, backend)
        .await
        .map_err(|error| format!("Failed to inspect auth schema: {error}"))?;
    configured_admin_claim_columns(&user_columns, &settings.claims).map(|_| ())
}

pub(crate) async fn ensure_admin_exists_with_settings_and_claim_prompt_mode(
    pool: &DbPool,
    settings: &AuthSettings,
    interactive_claims: bool,
) -> Result<bool, sqlx::Error> {
    let backend = detect_auth_backend(pool).await?;
    // Check if any admin exists
    let count = match query_scalar::<sqlx::Any, i64>(&format!(
        "SELECT COUNT(*) FROM {} WHERE role = 'admin'",
        auth_user_table_ident(backend)
    ))
    .fetch_one(pool)
    .await
    {
        Ok(count) => count,
        Err(error) => {
            eprintln!(
                "[ERROR] Missing built-in auth schema. Apply the auth migration before starting the server."
            );
            return Err(error);
        }
    };

    let admin_exists = count > 0;

    if admin_exists {
        println!("[INFO] Admin user is set up and ready");
        return Ok(true);
    }

    println!("[INFO] No admin user found. Creating an admin user...");

    // Try to get admin credentials from environment variables first
    let (email, password) = if let (Ok(email), Ok(password)) = (
        std::env::var("ADMIN_EMAIL"),
        std::env::var("ADMIN_PASSWORD"),
    ) {
        if !email.is_empty() && !password.is_empty() {
            println!("[INFO] Using environment variables for admin credentials");
            (email, password)
        } else {
            prompt_admin_credentials()
        }
    } else {
        prompt_admin_credentials()
    };

    // Create the admin user
    let password_hash = match hash(&password, 12) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("[ERROR] Failed to hash password: {}", e);
            return Ok(false);
        }
    };
    let backend = match detect_auth_backend(pool).await {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("[ERROR] Failed to detect auth backend: {}", error);
            return Err(error);
        }
    };
    let user_columns = match user_table_columns(pool, backend).await {
        Ok(columns) => columns,
        Err(error) => {
            eprintln!("[ERROR] Failed to inspect auth schema: {}", error);
            return Err(error);
        }
    };
    let claim_columns = if settings.claims.is_empty() {
        user_columns
            .into_iter()
            .filter_map(legacy_admin_claim_column_from_metadata)
            .collect::<Vec<_>>()
    } else {
        match configured_admin_claim_columns(&user_columns, &settings.claims) {
            Ok(columns) => columns,
            Err(error) => {
                eprintln!("[ERROR] {}", error);
                return Ok(false);
            }
        }
    };
    let claim_values = match resolve_admin_claim_values(&claim_columns, interactive_claims) {
        Ok(values) => values,
        Err(error) => {
            eprintln!("[ERROR] {}", error);
            return Ok(false);
        }
    };

    let result = insert_admin_user(pool, backend, &email, &password_hash, &claim_values).await;

    match result {
        Ok(_) => {
            println!("[SUCCESS] Admin user created successfully!");
            println!("--------------------------------------------");
            println!("🔐 Admin User Created 🔐");
            println!("Email: {}", email);
            if !claim_values.is_empty() {
                let rendered_claims = claim_values
                    .iter()
                    .map(AdminClaimValue::render)
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("Claims: {}", rendered_claims);
            }
            println!("--------------------------------------------");
            Ok(true)
        }
        Err(e) => {
            eprintln!("[ERROR] Failed to create admin user: {}", e);
            Ok(false)
        }
    }
}

/// Prompt for admin credentials via stdin
pub(crate) fn prompt_admin_credentials() -> (String, String) {
    println!("[INFO] Please enter admin credentials:");

    // Prompt for email
    let mut email = String::new();
    print!("Admin email: ");
    if let Err(error) = stdout().flush() {
        eprintln!("[ERROR] Failed to flush stdout while prompting for admin email: {error}");
        println!("[WARN] Using default admin credentials as fallback.");
        return create_default_admin();
    }
    if let Err(error) = stdin().read_line(&mut email) {
        eprintln!("[ERROR] Failed to read admin email from stdin: {error}");
        println!("[WARN] Using default admin credentials as fallback.");
        return create_default_admin();
    }
    let email = email.trim().to_string();

    // Prompt for password securely (no echo)
    let password = match rpassword::prompt_password("Admin password: ") {
        Ok(password) => password,
        Err(e) => {
            eprintln!("[ERROR] Failed to read password: {}", e);
            println!("[WARN] Using default admin credentials as fallback.");
            return create_default_admin();
        }
    };

    // Simple validation
    if email.is_empty() || password.is_empty() {
        println!(
            "[WARN] Email or password cannot be empty. Using default email and a random password."
        );
        return create_default_admin();
    }

    (email, password)
}

/// Create default admin credentials as a fallback
pub(crate) fn create_default_admin() -> (String, String) {
    use rand::RngExt;

    // Characters to use for password generation
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    // Generate a secure random password
    let mut rng = rand::rng();
    let password: String = (0..12)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    // Use a default admin email
    let email = "admin@example.com".to_string();

    println!("[INFO] Creating default admin user");

    (email, password)
}
