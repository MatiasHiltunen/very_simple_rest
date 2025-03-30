use thiserror::Error;

/// Custom error type for the CLI tool
#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Password hashing error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    
    #[error("Environment variable error: {0}")]
    Env(#[from] std::env::VarError),
    
    #[error("Input validation error: {0}")]
    Validation(String),
    
    #[error("User already exists: {0}")]
    UserExists(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("User interaction cancelled")]
    Cancelled,
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Alias for Result with our custom error type
pub type Result<T> = std::result::Result<T, Error>; 