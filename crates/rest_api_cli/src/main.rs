use clap::{Parser, Subcommand};
use anyhow::Result;
use colored::Colorize;
use rest_api_cli::commands;

#[derive(Parser)]
#[command(name = "vsr")]
#[command(about = "CLI tool for very_simple_rest API management", long_about = None)]
#[command(version)]
struct Cli {
    /// Optional configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<String>,
    
    /// Database connection string
    #[arg(short, long, value_name = "URL")]
    database_url: Option<String>,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new project
    Init {
        /// Project name
        #[arg(value_name = "NAME")]
        name: String,
        
        /// Project description
        #[arg(short, long)]
        description: Option<String>,
        
        /// Author name
        #[arg(short, long)]
        author: Option<String>,
        
        /// License
        #[arg(short, long, default_value = "MIT")]
        license: String,
        
        /// Output directory
        #[arg(short, long)]
        output_dir: Option<String>,
        
        /// Git repository URL
        #[arg(short, long)]
        repository: Option<String>,
    },
    
    /// Initialize the API with admin user
    Setup {
        /// Skip interactive prompts and use environment variables
        #[arg(short, long)]
        non_interactive: bool,
    },
    
    /// Create a new admin user
    CreateAdmin {
        /// Admin email address
        #[arg(short, long)]
        email: Option<String>,
        
        /// Admin password
        #[arg(short, long)]
        password: Option<String>,
    },
    
    /// Check database connection
    CheckDb,
    
    /// Generate .env file template
    GenEnv {
        /// Path to the environment file
        #[arg(short, long)]
        path: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if present
    let _ = dotenv::dotenv();
    
    let cli = Cli::parse();
    
    // Determine database URL from CLI args or environment
    let database_url = cli.database_url
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .unwrap_or_else(|| "sqlite:app.db?mode=rwc".to_string());
    
    // Process commands
    match &cli.command {
        Commands::Init {
            name,
            description,
            author,
            license,
            output_dir,
            repository,
        } => {
            println!("{}", "Initializing new project...".green().bold());
            commands::init::create_project(
                name,
                description.clone().unwrap_or_else(|| format!("A REST API built with very_simple_rest")),
                author.clone().unwrap_or_else(|| "Anonymous".to_string()),
                license,
                output_dir.clone().unwrap_or_else(|| ".".to_string()),
                repository.clone(),
            )?;
        },
        
        Commands::Setup { non_interactive } => {
            println!("{}", "Running setup wizard...".green().bold());
            commands::setup::run_setup(&database_url, *non_interactive).await?;
        },
        
        Commands::CreateAdmin { email, password } => {
            println!("{}", "Creating admin user...".green().bold());
            match (email.clone(), password.clone()) {
                (Some(email), Some(password)) => {
                    commands::admin::create_admin(&database_url, email, password).await?;
                },
                _ => {
                    // Check environment variables if command line args not provided
                    let env_email = std::env::var("ADMIN_EMAIL").ok();
                    let env_password = std::env::var("ADMIN_PASSWORD").ok();
                    
                    match (env_email, env_password) {
                        (Some(email), Some(password)) => {
                            println!("{}", "Using admin credentials from environment variables".yellow());
                            commands::admin::create_admin(&database_url, email, password).await?;
                        },
                        _ => {
                            println!("{}", "No credentials provided via arguments or environment variables".yellow());
                            println!("{}", "Please enter admin credentials:".cyan());
                            let (email, password) = commands::admin::prompt_admin_credentials().await?;
                            commands::admin::create_admin(&database_url, email, password).await?;
                        }
                    }
                }
            }
        },
        
        Commands::CheckDb => {
            println!("{}", "Checking database connection...".green().bold());
            commands::db::check_connection(&database_url).await?;
        },
        
        Commands::GenEnv { path } => {
            println!("{}", "Generating environment file...".green().bold());
            commands::gen_env::generate_env_file(path.clone())?;
        },
    }
    
    Ok(())
} 