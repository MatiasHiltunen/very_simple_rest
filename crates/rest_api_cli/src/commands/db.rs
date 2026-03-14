use crate::error::Result;
use colored::Colorize;
use rest_macro_core::compiler::{self, default_service_database_url};
use rest_macro_core::database::DatabaseConfig;
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
    Ok(service.database)
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

    println!("Database check completed in {:?}", start.elapsed());

    Ok(())
}

fn is_missing_user_table(error: &dyn sqlx::error::DatabaseError) -> bool {
    let message = error.message().to_ascii_lowercase();
    message.contains("no such table") || message.contains("does not exist")
}

#[cfg(test)]
mod tests {
    use super::database_url_from_service_config;
    use std::path::PathBuf;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
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
        assert_eq!(url, "sqlite:app.db?mode=rwc");
    }
}
