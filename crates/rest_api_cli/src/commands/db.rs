use crate::error::Result;
use colored::Colorize;
use sqlx::AnyPool;
use std::time::Instant;

/// Check database connection and schema
pub async fn check_connection(database_url: &str) -> Result<()> {
    println!("Connecting to database: {}", database_url);

    let start = Instant::now();
    let pool = AnyPool::connect(database_url).await?;
    let connection_time = start.elapsed();

    println!(
        "{} in {:?}",
        "Connection successful".green().bold(),
        connection_time
    );

    let start = Instant::now();
    let user_count = match sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user")
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
    let admin_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user WHERE role = 'admin'")
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
