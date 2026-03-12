use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use rest_api_cli::commands;
use std::path::PathBuf;

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

    /// Manage SQL migrations generated from a `.eon` service file
    Migrate {
        #[command(subcommand)]
        command: MigrationCommand,
    },

    /// Generate .env file template
    GenEnv {
        /// Path to the environment file
        #[arg(short, long)]
        path: Option<String>,
    },
}

#[derive(Subcommand)]
enum MigrationCommand {
    /// Generate a migration SQL file for the built-in auth schema
    Auth {
        /// Output SQL migration file
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Generate a migration SQL file from Rust sources using `#[derive(RestApi)]`
    Derive {
        /// Rust source file or directory to scan
        #[arg(short, long, value_name = "PATH")]
        input: PathBuf,

        /// Output SQL migration file
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Exclude a table from the generated migration
        #[arg(long = "exclude-table", value_name = "TABLE")]
        exclude_tables: Vec<String>,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Generate a migration SQL file from a `.eon` service definition
    Generate {
        /// Path to the `.eon` service file
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Output SQL migration file
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Check that an existing migration file matches the current `.eon` schema
    Check {
        /// Path to the `.eon` service file
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Existing SQL migration file to compare against
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },

    /// Check that a derive-based migration file matches the current Rust sources
    CheckDerive {
        /// Rust source file or directory to scan
        #[arg(short, long, value_name = "PATH")]
        input: PathBuf,

        /// Existing SQL migration file to compare against
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Exclude a table from the generated migration
        #[arg(long = "exclude-table", value_name = "TABLE")]
        exclude_tables: Vec<String>,
    },

    /// Generate an additive migration by diffing two schema sources
    Diff {
        /// Previous schema source (`.eon`, `.rs`, or a Rust source directory)
        #[arg(long, value_name = "PATH")]
        from: PathBuf,

        /// Next schema source (`.eon`, `.rs`, or a Rust source directory)
        #[arg(long, value_name = "PATH")]
        to: PathBuf,

        /// Output SQL migration file
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Exclude a table from both sides of the diff
        #[arg(long = "exclude-table", value_name = "TABLE")]
        exclude_tables: Vec<String>,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Inspect the live database for drift against a schema source
    Inspect {
        /// Schema source (`.eon`, `.rs`, or a Rust source directory)
        #[arg(short, long, value_name = "PATH")]
        input: PathBuf,

        /// Exclude a table from the inspection
        #[arg(long = "exclude-table", value_name = "TABLE")]
        exclude_tables: Vec<String>,
    },

    /// Apply SQL migration files from a directory
    Apply {
        /// Directory containing `.sql` migration files
        #[arg(short, long, value_name = "DIR", default_value = "migrations")]
        dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    sqlx::any::install_default_drivers();

    // Load .env file if present
    let _ = dotenv::dotenv();

    let cli = Cli::parse();

    // Determine database URL from CLI args or environment
    let database_url = cli
        .database_url
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
                description
                    .clone()
                    .unwrap_or_else(|| format!("A REST API built with very_simple_rest")),
                author.clone().unwrap_or_else(|| "Anonymous".to_string()),
                license,
                output_dir.clone().unwrap_or_else(|| ".".to_string()),
                repository.clone(),
            )?;
        }

        Commands::Setup { non_interactive } => {
            println!("{}", "Running setup wizard...".green().bold());
            commands::setup::run_setup(&database_url, *non_interactive).await?;
        }

        Commands::CreateAdmin { email, password } => {
            println!("{}", "Creating admin user...".green().bold());
            match (email.clone(), password.clone()) {
                (Some(email), Some(password)) => {
                    commands::admin::create_admin(&database_url, email, password).await?;
                }
                _ => {
                    // Check environment variables if command line args not provided
                    let env_email = std::env::var("ADMIN_EMAIL").ok();
                    let env_password = std::env::var("ADMIN_PASSWORD").ok();

                    match (env_email, env_password) {
                        (Some(email), Some(password)) => {
                            println!(
                                "{}",
                                "Using admin credentials from environment variables".yellow()
                            );
                            commands::admin::create_admin(&database_url, email, password).await?;
                        }
                        _ => {
                            println!(
                                "{}",
                                "No credentials provided via arguments or environment variables"
                                    .yellow()
                            );
                            println!("{}", "Please enter admin credentials:".cyan());
                            let (email, password) =
                                commands::admin::prompt_admin_credentials().await?;
                            commands::admin::create_admin(&database_url, email, password).await?;
                        }
                    }
                }
            }
        }

        Commands::CheckDb => {
            println!("{}", "Checking database connection...".green().bold());
            commands::db::check_connection(&database_url).await?;
        }

        Commands::Migrate { command } => match command {
            MigrationCommand::Auth { output, force } => {
                println!("{}", "Generating auth migration SQL...".green().bold());
                commands::migrate::generate_auth_migration(&database_url, output, *force)?;
            }
            MigrationCommand::Derive {
                input,
                output,
                exclude_tables,
                force,
            } => {
                println!("{}", "Generating derive migration SQL...".green().bold());
                commands::migrate::generate_derive_migration(
                    input,
                    output,
                    *force,
                    exclude_tables,
                )?;
            }
            MigrationCommand::Generate {
                input,
                output,
                force,
            } => {
                println!("{}", "Generating migration SQL...".green().bold());
                commands::migrate::generate_migration(input, output, *force)?;
            }
            MigrationCommand::Check { input, output } => {
                println!("{}", "Checking migration drift...".green().bold());
                commands::migrate::check_migration(input, output)?;
            }
            MigrationCommand::CheckDerive {
                input,
                output,
                exclude_tables,
            } => {
                println!("{}", "Checking derive migration drift...".green().bold());
                commands::migrate::check_derive_migration(input, output, exclude_tables)?;
            }
            MigrationCommand::Diff {
                from,
                to,
                output,
                exclude_tables,
                force,
            } => {
                println!("{}", "Generating additive diff migration...".green().bold());
                commands::migrate::generate_diff_migration(
                    from,
                    to,
                    output,
                    *force,
                    exclude_tables,
                )?;
            }
            MigrationCommand::Inspect {
                input,
                exclude_tables,
            } => {
                println!("{}", "Inspecting live schema drift...".green().bold());
                commands::migrate::inspect_live_schema(&database_url, input, exclude_tables)
                    .await?;
            }
            MigrationCommand::Apply { dir } => {
                println!("{}", "Applying migrations...".green().bold());
                commands::migrate::apply_migrations(&database_url, dir).await?;
            }
        },

        Commands::GenEnv { path } => {
            println!("{}", "Generating environment file...".green().bold());
            commands::gen_env::generate_env_file(path.clone())?;
        }
    }

    Ok(())
}
