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
    /// Optional `.eon` service config path used to derive defaults such as `DATABASE_URL`
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

    /// Generate or build a runnable server from a bare `.eon` service file
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },

    /// Generate an OpenAPI document from a `.eon` service or derive-based Rust sources
    OpenApi {
        /// Schema source (`.eon`, `.rs`, or a Rust source directory)
        #[arg(short, long, value_name = "PATH")]
        input: PathBuf,

        /// Output OpenAPI JSON file
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Override the document title
        #[arg(long, value_name = "TITLE")]
        title: Option<String>,

        /// Override the OpenAPI version string
        #[arg(long, value_name = "VERSION")]
        version: Option<String>,

        /// Server URL mounted in the generated document
        #[arg(long, value_name = "URL", default_value = "/api")]
        server_url: String,

        /// Include built-in auth routes in the generated document
        #[arg(long)]
        with_auth: bool,

        /// Exclude a table from the generated document
        #[arg(long = "exclude-table", value_name = "TABLE")]
        exclude_tables: Vec<String>,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
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

#[derive(Subcommand)]
enum ServerCommand {
    /// Emit a standalone Rust server project for a `.eon` service
    Emit {
        /// Path to the `.eon` service file
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Output directory for the generated server project
        #[arg(short, long, value_name = "DIR")]
        output_dir: PathBuf,

        /// Override the generated Cargo package name
        #[arg(long, value_name = "NAME")]
        package_name: Option<String>,

        /// Include built-in auth routes and auth migration SQL
        #[arg(long)]
        with_auth: bool,

        /// Overwrite the output directory if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Build a server binary from a `.eon` service
    Build {
        /// Path to the `.eon` service file
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Output binary path
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Override the generated Cargo package name
        #[arg(long, value_name = "NAME")]
        package_name: Option<String>,

        /// Temporary build directory for the generated Cargo project
        #[arg(long, value_name = "DIR")]
        build_dir: Option<PathBuf>,

        /// Include built-in auth routes and auth migration SQL
        #[arg(long)]
        with_auth: bool,

        /// Build an optimized release binary
        #[arg(long)]
        release: bool,

        /// Cargo target triple to build for
        #[arg(long, value_name = "TARGET")]
        target: Option<String>,

        /// Keep the generated build project after compiling
        #[arg(long)]
        keep_build_dir: bool,

        /// Overwrite the output binary if it already exists
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if present
    let _ = dotenv::dotenv();

    let cli = Cli::parse();
    let config_path = cli.config.as_deref().map(PathBuf::from);

    // Determine database URL from CLI args, environment, or an `.eon` service config.
    let database_url = if let Some(url) = cli.database_url {
        url
    } else if let Ok(url) = std::env::var("DATABASE_URL") {
        url
    } else if let Some(config) = config_path.as_deref() {
        commands::db::database_url_from_service_config(config)?
    } else {
        "sqlite:app.db?mode=rwc".to_string()
    };

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
            commands::setup::run_setup(&database_url, config_path.as_deref(), *non_interactive)
                .await?;
        }

        Commands::CreateAdmin { email, password } => {
            println!("{}", "Creating admin user...".green().bold());
            match (email.clone(), password.clone()) {
                (Some(email), Some(password)) => {
                    commands::admin::create_admin(
                        &database_url,
                        config_path.as_deref(),
                        email,
                        password,
                    )
                    .await?;
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
                            commands::admin::create_admin(
                                &database_url,
                                config_path.as_deref(),
                                email,
                                password,
                            )
                            .await?;
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
                            commands::admin::create_admin(
                                &database_url,
                                config_path.as_deref(),
                                email,
                                password,
                            )
                            .await?;
                        }
                    }
                }
            }
        }

        Commands::CheckDb => {
            println!("{}", "Checking database connection...".green().bold());
            commands::db::check_connection(&database_url, config_path.as_deref()).await?;
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
                commands::migrate::inspect_live_schema(
                    &database_url,
                    config_path.as_deref(),
                    input,
                    exclude_tables,
                )
                .await?;
            }
            MigrationCommand::Apply { dir } => {
                println!("{}", "Applying migrations...".green().bold());
                commands::migrate::apply_migrations(&database_url, config_path.as_deref(), dir)
                    .await?;
            }
        },

        Commands::Server { command } => match command {
            ServerCommand::Emit {
                input,
                output_dir,
                package_name,
                with_auth,
                force,
            } => {
                println!("{}", "Generating server project...".green().bold());
                commands::server::emit_server_project(
                    input,
                    output_dir,
                    package_name.clone(),
                    *with_auth,
                    *force,
                )?;
            }
            ServerCommand::Build {
                input,
                output,
                package_name,
                build_dir,
                with_auth,
                release,
                target,
                keep_build_dir,
                force,
            } => {
                println!("{}", "Building server binary...".green().bold());
                commands::server::build_server_binary(
                    input,
                    output,
                    package_name.clone(),
                    build_dir.clone(),
                    *with_auth,
                    *release,
                    target.clone(),
                    *keep_build_dir,
                    *force,
                )?;
            }
        },

        Commands::OpenApi {
            input,
            output,
            title,
            version,
            server_url,
            with_auth,
            exclude_tables,
            force,
        } => {
            println!("{}", "Generating OpenAPI spec...".green().bold());
            commands::openapi::generate_openapi(
                input,
                output,
                *force,
                exclude_tables,
                title.clone(),
                version.clone(),
                server_url,
                *with_auth,
            )?;
        }

        Commands::GenEnv { path } => {
            println!("{}", "Generating environment file...".green().bold());
            commands::gen_env::generate_env_file(path.clone())?;
        }
    }

    Ok(())
}
