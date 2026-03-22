use crate::error::{Error, Result};
use colored::Colorize;
use rest_macro_core::auth::validate_auth_claim_mappings;
use rest_macro_core::compiler::{self, default_service_database_url};
use rest_macro_core::database::{
    DatabaseConfig, resolve_database_config, service_base_dir_from_config_path,
};
use rest_macro_core::db::{DbPool, query_scalar};
use std::path::Path;
use std::time::Instant;

pub fn database_url_from_service_config(path: &Path) -> Result<String> {
    let service = compiler::load_service_from_path(path)
        .map_err(|error| crate::error::Error::Config(error.to_string()))?;
    Ok(default_service_database_url(&service))
}

pub fn database_config_from_service_config(path: &Path) -> Result<DatabaseConfig> {
    let service = compiler::load_service_from_path(path)
        .map_err(|error| crate::error::Error::Config(error.to_string()))?;
    let base_dir = service_base_dir_from_config_path(path);
    Ok(resolve_database_config(&service.database, &base_dir))
}

pub async fn connect_database(database_url: &str, config_path: Option<&Path>) -> Result<DbPool> {
    match config_path {
        Some(path) => {
            let config = database_config_from_service_config(path)?;
            Ok(DbPool::connect_with_config(database_url, &config).await?)
        }
        None => Ok(DbPool::connect(database_url).await?),
    }
}

/// Check database connection and schema
pub async fn check_connection(database_url: &str, config_path: Option<&Path>) -> Result<()> {
    println!("Connecting to database: {}", database_url);
    let service = match config_path {
        Some(path) => Some(
            compiler::load_service_from_path(path)
                .map_err(|error| Error::Config(error.to_string()))?,
        ),
        None => None,
    };

    let start = Instant::now();
    let pool = connect_database(database_url, config_path).await?;
    let connection_time = start.elapsed();

    println!(
        "{} in {:?}",
        "Connection successful".green().bold(),
        connection_time
    );

    let start = Instant::now();
    let user_count = match query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM user")
        .fetch_one(&pool)
        .await
    {
        Ok(count) => count,
        Err(sqlx::Error::Database(error)) if is_missing_user_table(&*error) => {
            println!(
                "{}: User table does not exist. Run the auth migration first",
                "WARNING".yellow().bold()
            );
            println!("Database check completed in {:?}", start.elapsed());
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    println!("{}", "User table exists".green());
    println!("Found {} users in the database", user_count);

    // Count admins
    let admin_count: i64 =
        query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM user WHERE role = 'admin'")
            .fetch_one(&pool)
            .await?;

    if admin_count > 0 {
        println!("{}: {} admin users found", "OK".green().bold(), admin_count);
    } else {
        println!(
            "{}: No admin users found. Run the 'create-admin' command to create one",
            "WARNING".yellow().bold()
        );
    }

    if let Some(service) = &service
        && !service.security.auth.claims.is_empty()
    {
        validate_auth_claim_mappings(&pool, &service.security.auth)
            .await
            .map_err(Error::Config)?;
        println!(
            "{}: Configured auth claim mappings match the user schema",
            "OK".green().bold()
        );
    }

    println!("Database check completed in {:?}", start.elapsed());

    Ok(())
}

fn is_missing_user_table(error: &dyn sqlx::error::DatabaseError) -> bool {
    let message = error.message().to_ascii_lowercase();
    message.contains("no such table") || message.contains("does not exist")
}

#[cfg(test)]
mod tests {
    use super::{check_connection, connect_database, database_url_from_service_config};
    use rest_macro_core::db::query;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn derives_sqlite_url_from_turso_local_service_config() {
        let url = database_url_from_service_config(&fixture_path("turso_local_api.eon"))
            .expect("service config should resolve");
        assert_eq!(url, "sqlite:var/data/turso_local.db?mode=rwc");
    }

    #[test]
    fn derives_default_sqlite_url_from_plain_service_config() {
        let url = database_url_from_service_config(&fixture_path("blog_api.eon"))
            .expect("service config should resolve");
        assert_eq!(url, "sqlite:var/data/blog_api.db?mode=rwc");
    }

    #[tokio::test]
    async fn check_connection_accepts_missing_auth_table_for_turso_local_service() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var(
                "TURSO_ENCRYPTION_KEY",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            );
        }

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_check_connection_{stamp}"));
        std::fs::create_dir_all(&root).expect("temp root should be created");
        let config = root.join("blog_api.eon");
        std::fs::copy(fixture_path("blog_api.eon"), &config).expect("fixture should copy");
        let database_url =
            database_url_from_service_config(&config).expect("service config should resolve");

        check_connection(&database_url, Some(&config))
            .await
            .expect("missing auth table should only warn");

        unsafe {
            std::env::remove_var("TURSO_ENCRYPTION_KEY");
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn check_connection_rejects_mismatched_explicit_auth_claim_mappings() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var(
                "TURSO_ENCRYPTION_KEY",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            );
        }

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_check_claims_{stamp}"));
        std::fs::create_dir_all(&root).expect("temp root should be created");
        let config = root.join("auth_claims_api.eon");
        std::fs::copy(fixture_path("auth_claims_api.eon"), &config).expect("fixture should copy");
        let database_url =
            database_url_from_service_config(&config).expect("service config should resolve");
        let pool = connect_database(&database_url, Some(&config))
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
                is_staff TEXT NOT NULL,
                plan TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("user table should exist");

        let error = check_connection(&database_url, Some(&config))
            .await
            .expect_err("mismatched auth claim mappings should fail");
        assert!(error.to_string().contains("security.auth.claims.staff"));

        unsafe {
            std::env::remove_var("TURSO_ENCRYPTION_KEY");
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
