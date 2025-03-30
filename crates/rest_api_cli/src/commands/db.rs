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
    
    println!("{} in {:?}", "Connection successful".green().bold(), connection_time);
    
    // Check if user table exists
    let start = Instant::now();
    let user_table_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (
            SELECT 1 FROM sqlite_master WHERE type='table' AND name='user'
        )"
    )
    .fetch_one(&pool)
    .await?;
    
    if user_table_exists {
        println!("{}", "User table exists".green());
        
        // Count users
        let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user")
            .fetch_one(&pool)
            .await?;
            
        println!("Found {} users in the database", user_count);
        
        // Count admins
        let admin_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user WHERE role = 'admin'")
            .fetch_one(&pool)
            .await?;
            
        if admin_count > 0 {
            println!("{}: {} admin users found", "OK".green().bold(), admin_count);
        } else {
            println!("{}: No admin users found. Run the 'create-admin' command to create one", "WARNING".yellow().bold());
        }
    } else {
        println!("{}: User table does not exist. Run the 'setup' command to initialize the database", "WARNING".yellow().bold());
    }
    
    println!("Database check completed in {:?}", start.elapsed());
    
    Ok(())
} 