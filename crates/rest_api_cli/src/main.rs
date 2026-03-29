#[cfg(not(test))]
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
#[cfg(not(test))]
use colored::Colorize;
use std::path::PathBuf;
use vsra::commands;

#[derive(Parser)]
#[command(name = "vsr")]
#[command(about = "CLI tool for very_simple_rest API management", long_about = None)]
#[command(version)]
struct Cli {
    /// Optional `.eon` service config path used to derive defaults such as `DATABASE_URL`, Turso envs, and security env hints
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
    /// Initialize a new starter project with a generated `.eon` starter and local defaults
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

        /// Starter style; omit this to get an interactive prompt in a terminal
        #[arg(long, value_enum)]
        starter: Option<commands::init::StarterKind>,
    },

    /// Initialize the API with admin user
    Setup {
        /// Skip interactive prompts and use environment variables
        #[arg(short, long)]
        non_interactive: bool,

        /// Use production-safe setup behavior: do not generate live secrets into `.env` or self-signed dev TLS certs
        #[arg(long)]
        production: bool,
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

    /// Build a server binary directly from a `.eon` service
    Build {
        /// Path to the `.eon` service file
        #[arg(value_name = "FILE")]
        input: PathBuf,

        /// Output binary path or directory
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,

        /// Override the generated Cargo package name
        #[arg(long, value_name = "NAME")]
        package_name: Option<String>,

        /// Build cache directory for the generated Cargo project and Cargo target artifacts
        #[arg(long, value_name = "DIR")]
        build_dir: Option<PathBuf>,

        /// Deprecated compatibility flag; built-in auth is now included by default
        #[arg(long, hide = true, conflicts_with = "without_auth")]
        with_auth: bool,

        /// Exclude built-in auth routes and auth migration SQL
        #[arg(long, alias = "no-auth")]
        without_auth: bool,

        /// Build an optimized release binary
        #[arg(long)]
        release: bool,

        /// Cargo target triple to build for
        #[arg(long, value_name = "TARGET")]
        target: Option<String>,

        /// Deprecated compatibility flag; the reusable build cache is preserved automatically
        #[arg(long, hide = true)]
        keep_build_dir: bool,

        /// Overwrite the output binary if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Remove cached generated build projects and Cargo build artifacts
    Clean {
        /// Build cache directory to remove; defaults to `./.vsr-build`
        #[arg(long, value_name = "DIR")]
        build_dir: Option<PathBuf>,
    },

    /// Serve a `.eon` service directly without generating or compiling a Rust project
    Serve {
        /// Path to the `.eon` service file; falls back to `--config` when omitted
        #[arg(value_name = "FILE")]
        input: Option<PathBuf>,

        /// Override the bind address; otherwise `BIND_ADDR` or the service default is used
        #[arg(long, value_name = "ADDR")]
        bind_addr: Option<String>,

        /// Deprecated compatibility flag; built-in auth is now included by default
        #[arg(long, hide = true, conflicts_with = "without_auth")]
        with_auth: bool,

        /// Exclude built-in auth routes
        #[arg(long, alias = "no-auth")]
        without_auth: bool,
    },

    /// Generate an OpenAPI document from a `.eon` service or derive-based Rust sources
    #[command(name = "openapi")]
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

        /// Deprecated compatibility flag; built-in auth is now included by default
        #[arg(long, hide = true, conflicts_with = "without_auth")]
        with_auth: bool,

        /// Exclude built-in auth routes from the generated document
        #[arg(long, alias = "no-auth")]
        without_auth: bool,

        /// Exclude a table from the generated document
        #[arg(long = "exclude-table", value_name = "TABLE")]
        exclude_tables: Vec<String>,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Generate a .env file template, optionally derived from `--config`
    GenEnv {
        /// Path to the environment file
        #[arg(short, long)]
        path: Option<String>,

        /// Generate a production-safe template without writing live secret values
        #[arg(long)]
        production: bool,
    },

    /// Generate Markdown reference documentation for the `.eon` format
    Docs {
        /// Output Markdown file
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Generate secret-manager scaffolding from a `.eon` service
    Secrets {
        #[command(subcommand)]
        command: SecretsCommand,
    },

    /// Run operational diagnostics against a `.eon` service
    Doctor {
        #[command(subcommand)]
        command: DoctorCommand,
    },

    /// Plan backup and replication posture from a `.eon` service
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },

    /// Validate live replication topology against a `.eon` resilience contract
    Replication {
        #[command(subcommand)]
        command: ReplicationCommand,
    },

    /// Explain the compiled authorization model for a `.eon` service
    Authz {
        #[command(subcommand)]
        command: AuthzCommand,
    },

    /// Manage local TLS certificates for generated servers
    Tls {
        #[command(subcommand)]
        command: TlsCommand,
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

    /// Generate a migration SQL file for runtime authorization assignments
    Authz {
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
enum SecretsCommand {
    /// Generate Infisical scaffolding from a `.eon` service
    Infisical {
        #[command(subcommand)]
        command: InfisicalCommand,
    },
}

#[derive(Subcommand)]
enum InfisicalCommand {
    /// Generate Infisical Agent templates and runtime file bindings
    Scaffold {
        /// Path to the `.eon` service file; falls back to `--config` when omitted
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Output directory for generated Infisical files
        #[arg(short, long, value_name = "DIR")]
        output_dir: Option<PathBuf>,

        /// Infisical project slug used by the generated templates
        #[arg(long, value_name = "SLUG")]
        project: String,

        /// Optional Infisical project ID used by generated templates instead of the project slug
        #[arg(long, value_name = "UUID")]
        project_id: Option<String>,

        /// Infisical environment slug used by the generated templates
        #[arg(long, value_name = "ENV", default_value = "prod")]
        environment: String,

        /// Infisical secret path used by the generated templates
        #[arg(long, value_name = "PATH", default_value = "/")]
        secret_path: String,

        /// Destination directory where Infisical Agent renders secret files
        #[arg(long, value_name = "DIR", default_value = "/run/secrets/vsr")]
        render_dir: String,

        /// Auth method skeleton to use in the generated Infisical Agent config
        #[arg(long, value_enum, default_value = "universal-auth")]
        auth_method: commands::secrets::InfisicalAuthMethod,

        /// Overwrite existing generated files
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum DoctorCommand {
    /// Validate resolved secret bindings for a `.eon` service
    Secrets {
        /// Path to the `.eon` service file; falls back to `--config` when omitted
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Optional Infisical scaffold directory to validate alongside the runtime bindings
        #[arg(long, value_name = "DIR")]
        infisical_dir: Option<PathBuf>,

        /// Write the report to a file instead of stdout
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: BackupPlanFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum BackupCommand {
    /// Render a backend-aware backup and replication plan from a `.eon` service
    Plan {
        /// Path to the `.eon` service file
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Optional output file
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value_t = BackupPlanFormatArg::Text)]
        format: BackupPlanFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Validate backup posture and obvious environment/connectivity gaps
    Doctor {
        /// Path to the `.eon` service file
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Optional output file
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value_t = BackupPlanFormatArg::Text)]
        format: BackupPlanFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Create a SQLite/TursoLocal snapshot artifact with a manifest
    Snapshot {
        /// Path to the `.eon` service file
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Output artifact directory
        #[arg(short, long, value_name = "DIR")]
        output: PathBuf,

        /// Overwrite the output directory if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Create a Postgres/MySQL logical dump artifact with a manifest
    Export {
        /// Path to the `.eon` service file
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Output artifact directory
        #[arg(short, long, value_name = "DIR")]
        output: PathBuf,

        /// Overwrite the output directory if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Restore a snapshot artifact into a disposable target and verify it
    VerifyRestore {
        /// Backup artifact directory or manifest.json path
        #[arg(short, long, value_name = "PATH")]
        artifact: PathBuf,

        /// Optional output file
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value_t = BackupPlanFormatArg::Text)]
        format: BackupPlanFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Upload a local backup artifact directory to an S3-compatible remote prefix
    Push {
        /// Backup artifact directory or manifest.json path
        #[arg(short, long, value_name = "PATH")]
        artifact: PathBuf,

        /// Remote artifact prefix in the form s3://bucket/prefix
        #[arg(long, value_name = "S3_URI")]
        remote: String,

        /// Optional S3-compatible endpoint override, for example http://127.0.0.1:9000 for MinIO
        #[arg(long, value_name = "URL")]
        endpoint_url: Option<String>,

        /// Optional S3 region override
        #[arg(long, value_name = "REGION")]
        region: Option<String>,

        /// Force path-style S3 requests for compatible providers such as MinIO
        #[arg(long)]
        path_style: bool,

        /// Output format
        #[arg(long, value_enum, default_value_t = BackupPlanFormatArg::Text)]
        format: BackupPlanFormatArg,
    },

    /// Download a backup artifact directory from an S3-compatible remote prefix
    Pull {
        /// Remote artifact prefix in the form s3://bucket/prefix
        #[arg(long, value_name = "S3_URI")]
        remote: String,

        /// Local output artifact directory
        #[arg(short, long, value_name = "DIR")]
        output: PathBuf,

        /// Optional S3-compatible endpoint override, for example http://127.0.0.1:9000 for MinIO
        #[arg(long, value_name = "URL")]
        endpoint_url: Option<String>,

        /// Optional S3 region override
        #[arg(long, value_name = "REGION")]
        region: Option<String>,

        /// Force path-style S3 requests for compatible providers such as MinIO
        #[arg(long)]
        path_style: bool,

        /// Overwrite the output directory if it already exists
        #[arg(long)]
        force: bool,

        /// Output format
        #[arg(long, value_enum, default_value_t = BackupPlanFormatArg::Text)]
        format: BackupPlanFormatArg,
    },
}

#[derive(Subcommand)]
enum ReplicationCommand {
    /// Validate primary/read topology and obvious replication config gaps
    Doctor {
        /// Path to the `.eon` service file
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Explicit read database URL override
        #[arg(long, value_name = "URL")]
        read_database_url: Option<String>,

        /// Optional output file
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value_t = BackupPlanFormatArg::Text)]
        format: BackupPlanFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
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

        /// Deprecated compatibility flag; built-in auth is now included by default
        #[arg(long, hide = true, conflicts_with = "without_auth")]
        with_auth: bool,

        /// Exclude built-in auth routes and auth migration SQL
        #[arg(long, alias = "no-auth")]
        without_auth: bool,

        /// Overwrite the output directory if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Expand a `.eon` service into the full generated Rust module source
    Expand {
        /// Path to the `.eon` service file
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Output Rust source path; defaults to `<input-stem>.expanded.rs`
        #[arg(short, long, value_name = "FILE", conflicts_with = "output_dir")]
        output: Option<PathBuf>,

        /// Deprecated compatibility flag to place the expanded file inside a directory
        #[arg(long, value_name = "DIR", conflicts_with = "output")]
        output_dir: Option<PathBuf>,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Build a server binary from a `.eon` service
    Build {
        /// Path to the `.eon` service file
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Output binary path or directory
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Override the generated Cargo package name
        #[arg(long, value_name = "NAME")]
        package_name: Option<String>,

        /// Build cache directory for the generated Cargo project and Cargo target artifacts
        #[arg(long, value_name = "DIR")]
        build_dir: Option<PathBuf>,

        /// Deprecated compatibility flag; built-in auth is now included by default
        #[arg(long, hide = true, conflicts_with = "without_auth")]
        with_auth: bool,

        /// Exclude built-in auth routes and auth migration SQL
        #[arg(long, alias = "no-auth")]
        without_auth: bool,

        /// Build an optimized release binary
        #[arg(long)]
        release: bool,

        /// Cargo target triple to build for
        #[arg(long, value_name = "TARGET")]
        target: Option<String>,

        /// Deprecated compatibility flag; the reusable build cache is preserved automatically
        #[arg(long, hide = true)]
        keep_build_dir: bool,

        /// Overwrite the output binary if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Serve a `.eon` service directly without generating or compiling a Rust project
    Serve {
        /// Path to the `.eon` service file
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Override the bind address; otherwise `BIND_ADDR` or the service default is used
        #[arg(long, value_name = "ADDR")]
        bind_addr: Option<String>,

        /// Deprecated compatibility flag; built-in auth is now included by default
        #[arg(long, hide = true, conflicts_with = "without_auth")]
        with_auth: bool,

        /// Exclude built-in auth routes
        #[arg(long, alias = "no-auth")]
        without_auth: bool,
    },
}

#[derive(Subcommand)]
enum TlsCommand {
    /// Generate a self-signed certificate and private key for local development
    SelfSigned {
        /// Output certificate PEM path
        #[arg(long, value_name = "FILE")]
        cert_path: Option<PathBuf>,

        /// Output private key PEM path
        #[arg(long, value_name = "FILE")]
        key_path: Option<PathBuf>,

        /// Subject alternative name to include; may be repeated
        #[arg(long = "host", value_name = "NAME")]
        hosts: Vec<String>,

        /// Overwrite existing certificate and key files
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum AuthzCommand {
    /// Render the compiled authorization model from a `.eon` service
    Explain {
        /// Path to the `.eon` service file; falls back to `--config` when omitted
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Optional output file; defaults to stdout
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: AuthzExplainFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Simulate one authorization decision against the compiled model
    Simulate {
        /// Path to the `.eon` service file; falls back to `--config` when omitted
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Resource name; when omitted, a single-resource service is auto-selected
        #[arg(long, value_name = "NAME")]
        resource: Option<String>,

        /// Action to simulate
        #[arg(long, value_enum)]
        action: AuthzActionArg,

        /// Simulated authenticated user id
        #[arg(long, value_name = "ID")]
        user_id: Option<i64>,

        /// Simulated roles; may be repeated
        #[arg(long = "role", value_name = "ROLE")]
        roles: Vec<String>,

        /// Simulated claims in key=value form; may be repeated
        #[arg(long = "claim", value_name = "KEY=VALUE")]
        claims: Vec<String>,

        /// Simulated row fields in key=value form; may be repeated
        #[arg(long = "row", value_name = "KEY=VALUE")]
        row: Vec<String>,

        /// Related rows for EXISTS predicates in `Resource:key=value,other=value` form; may be repeated
        #[arg(long = "related-row", value_name = "ROW")]
        related_rows: Vec<String>,

        /// Proposed create payload fields in key=value form; may be repeated
        #[arg(long = "proposed", value_name = "KEY=VALUE")]
        proposed: Vec<String>,

        /// Simulated scope in ScopeName=value form
        #[arg(long, value_name = "SCOPE=VALUE")]
        scope: Option<String>,

        /// Optional hybrid request shape to simulate against generated handler behavior
        #[arg(long = "hybrid-source", value_enum)]
        hybrid_source: Option<AuthzHybridSourceArg>,

        /// Runtime scoped assignments in `permission:Name@Scope=value` or `template:Name@Scope=value` form; may be repeated
        #[arg(
            long = "scoped-assignment",
            alias = "assignment",
            value_name = "ASSIGNMENT"
        )]
        scoped_assignments: Vec<String>,

        /// Load runtime scoped assignments for `--user-id` from the configured database
        #[arg(long)]
        load_runtime_assignments: bool,

        /// Optional output file; defaults to stdout
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: AuthzExplainFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Manage persisted runtime authorization assignments and evaluate runtime grants
    Runtime {
        #[command(subcommand)]
        command: AuthzRuntimeCommand,
    },
}

#[derive(Subcommand)]
enum AuthzRuntimeCommand {
    /// List persisted runtime authorization assignments for a user
    List {
        /// User id to inspect
        #[arg(long, value_name = "ID")]
        user_id: i64,

        /// Optional output file; defaults to stdout
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: AuthzExplainFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Create one persisted runtime authorization assignment
    Create {
        /// Path to the `.eon` service file; falls back to `--config` when omitted
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// User id that will receive the assignment
        #[arg(long, value_name = "ID")]
        user_id: i64,

        /// Assignment in `permission:Name@Scope=value` or `template:Name@Scope=value` form
        #[arg(long = "assignment", value_name = "ASSIGNMENT")]
        assignment: String,

        /// Optional actor user id recorded as the creator
        #[arg(long, value_name = "ID")]
        created_by_user_id: Option<i64>,

        /// Optional RFC3339 expiration timestamp
        #[arg(long, value_name = "RFC3339")]
        expires_at: Option<String>,

        /// Optional output file; defaults to stdout
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: AuthzExplainFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Delete one persisted runtime authorization assignment by id
    Delete {
        /// Assignment id to delete
        #[arg(long, value_name = "ID")]
        id: String,

        /// Optional actor user id recorded in the delete event
        #[arg(long, value_name = "ID")]
        actor_user_id: Option<i64>,

        /// Optional delete reason stored in assignment history
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,

        /// Optional output file; defaults to stdout
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: AuthzExplainFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Revoke one persisted runtime authorization assignment without deleting its history
    Revoke {
        /// Assignment id to revoke
        #[arg(long, value_name = "ID")]
        id: String,

        /// Optional actor user id recorded in the revoke event
        #[arg(long, value_name = "ID")]
        actor_user_id: Option<i64>,

        /// Optional revoke reason stored in assignment history
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,

        /// Optional output file; defaults to stdout
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: AuthzExplainFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Renew one persisted runtime authorization assignment by setting a new future expiration
    Renew {
        /// Assignment id to renew
        #[arg(long, value_name = "ID")]
        id: String,

        /// New RFC3339 expiration timestamp
        #[arg(long, value_name = "RFC3339")]
        expires_at: String,

        /// Optional actor user id recorded in the renew event
        #[arg(long, value_name = "ID")]
        actor_user_id: Option<i64>,

        /// Optional renewal reason stored in assignment history
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,

        /// Optional output file; defaults to stdout
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: AuthzExplainFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// List persisted runtime authorization assignment history for a user
    History {
        /// User id to inspect
        #[arg(long, value_name = "ID")]
        user_id: i64,

        /// Optional output file; defaults to stdout
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: AuthzExplainFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Evaluate persisted runtime grants for one user/resource/action/scope tuple
    Evaluate {
        /// Path to the `.eon` service file; falls back to `--config` when omitted
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Resource name
        #[arg(long, value_name = "NAME")]
        resource: String,

        /// Action to evaluate
        #[arg(long, value_enum)]
        action: AuthzActionArg,

        /// User id to evaluate
        #[arg(long, value_name = "ID")]
        user_id: i64,

        /// Scope in ScopeName=value form
        #[arg(long, value_name = "SCOPE=VALUE")]
        scope: String,

        /// Optional output file; defaults to stdout
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: AuthzExplainFormatArg,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum AuthzExplainFormatArg {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum AuthzActionArg {
    Read,
    Create,
    Update,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, Default)]
enum BackupPlanFormatArg {
    #[default]
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum AuthzHybridSourceArg {
    Item,
    CollectionFilter,
    NestedParent,
    CreatePayload,
}

#[cfg(not(test))]
async fn run_cli() -> Result<()> {
    // Load .env file if present
    let _ = dotenv::dotenv();

    let cli = Cli::parse();
    let config_path = resolve_config_path(cli.config.as_deref())?;
    let cli_database_url = cli.database_url.clone();
    let env_database_url = rest_macro_core::secret::load_optional_secret_from_env_or_file(
        "DATABASE_URL",
        "DATABASE_URL",
    )
    .map_err(|error| anyhow!(error))?;

    // Determine database URL from CLI args, environment, or an `.eon` service config.
    let database_url = if let Some(url) = cli_database_url.clone() {
        url
    } else if let Some(url) = env_database_url.clone() {
        url
    } else if let Some(config) = config_path.as_deref() {
        commands::db::database_url_from_service_config(config)?
    } else {
        "sqlite:var/data/app.db?mode=rwc".to_string()
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
            starter,
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
                *starter,
            )?;
        }

        Commands::Setup {
            non_interactive,
            production,
        } => {
            println!("{}", "Running setup wizard...".green().bold());
            commands::setup::run_setup(
                &database_url,
                config_path.as_deref(),
                *non_interactive,
                cli_database_url.is_some(),
                *production,
            )
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
                commands::migrate::generate_auth_migration(
                    &database_url,
                    config_path.as_deref(),
                    output,
                    *force,
                )?;
            }
            MigrationCommand::Authz { output, force } => {
                println!(
                    "{}",
                    "Generating runtime authorization migration SQL..."
                        .green()
                        .bold()
                );
                commands::migrate::generate_authz_migration(&database_url, output, *force)?;
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
                without_auth,
                force,
            } => {
                println!("{}", "Generating server project...".green().bold());
                let include_builtin_auth = include_builtin_auth(*with_auth, *without_auth);
                commands::server::emit_server_project(
                    input,
                    output_dir,
                    package_name.clone(),
                    include_builtin_auth,
                    *force,
                )?;
            }
            ServerCommand::Expand {
                input,
                output,
                output_dir,
                force,
            } => {
                println!("{}", "Expanding generated server code...".green().bold());
                let resolved_output = output.clone().or_else(|| {
                    output_dir.as_ref().map(|dir| {
                        let stem = input
                            .file_stem()
                            .and_then(|value| value.to_str())
                            .filter(|value| !value.is_empty())
                            .unwrap_or("service");
                        dir.join(format!("{stem}.expanded.rs"))
                    })
                });
                commands::server::expand_server_code(input, resolved_output.as_deref(), *force)?;
            }
            ServerCommand::Build {
                input,
                output,
                package_name,
                build_dir,
                with_auth,
                without_auth,
                release,
                target,
                keep_build_dir,
                force,
            } => {
                println!("{}", "Building server binary...".green().bold());
                let include_builtin_auth = include_builtin_auth(*with_auth, *without_auth);
                commands::server::build_server_binary_with_defaults(
                    input,
                    Some(output),
                    package_name.clone(),
                    build_dir.clone(),
                    include_builtin_auth,
                    *release,
                    target.clone(),
                    *keep_build_dir,
                    *force,
                )?;
            }
            ServerCommand::Serve {
                input,
                bind_addr,
                with_auth,
                without_auth,
            } => {
                println!("{}", "Starting native runtime server...".green().bold());
                let include_builtin_auth = include_builtin_auth(*with_auth, *without_auth);
                let serve_database_url = database_url_for_service_input(
                    cli_database_url.as_ref(),
                    env_database_url.as_ref(),
                    config_path.as_deref(),
                    Some(input),
                    &database_url,
                )?;
                commands::serve::serve_service(
                    input,
                    &serve_database_url,
                    bind_addr.as_deref(),
                    include_builtin_auth,
                )
                .await?;
            }
        },

        Commands::Build {
            input,
            output,
            package_name,
            build_dir,
            with_auth,
            without_auth,
            release,
            target,
            keep_build_dir,
            force,
        } => {
            println!("{}", "Building server binary...".green().bold());
            let include_builtin_auth = include_builtin_auth(*with_auth, *without_auth);
            commands::server::build_server_binary_with_defaults(
                input,
                output.as_deref(),
                package_name.clone(),
                build_dir.clone(),
                include_builtin_auth,
                *release,
                target.clone(),
                *keep_build_dir,
                *force,
            )?;
        }

        Commands::Clean { build_dir } => {
            println!("{}", "Cleaning build cache...".green().bold());
            commands::server::clean_build_cache(build_dir.as_deref())?;
        }

        Commands::Serve {
            input,
            bind_addr,
            with_auth,
            without_auth,
        } => {
            println!("{}", "Starting native runtime server...".green().bold());
            let input = input
                .clone()
                .or_else(|| config_path.clone())
                .ok_or_else(|| anyhow!("serve requires a `.eon` input path or --config"))?;
            let include_builtin_auth = include_builtin_auth(*with_auth, *without_auth);
            let serve_database_url = database_url_for_service_input(
                cli_database_url.as_ref(),
                env_database_url.as_ref(),
                config_path.as_deref(),
                Some(&input),
                &database_url,
            )?;
            commands::serve::serve_service(
                &input,
                &serve_database_url,
                bind_addr.as_deref(),
                include_builtin_auth,
            )
            .await?;
        }

        Commands::OpenApi {
            input,
            output,
            title,
            version,
            server_url,
            with_auth,
            without_auth,
            exclude_tables,
            force,
        } => {
            println!("{}", "Generating OpenAPI spec...".green().bold());
            let include_builtin_auth = include_builtin_auth(*with_auth, *without_auth);
            commands::openapi::generate_openapi(
                input,
                output,
                *force,
                exclude_tables,
                title.clone(),
                version.clone(),
                server_url,
                include_builtin_auth,
            )?;
        }

        Commands::GenEnv { path, production } => {
            println!("{}", "Generating environment file...".green().bold());
            commands::gen_env::generate_env_file(
                path.clone(),
                config_path.as_deref(),
                *production,
            )?;
        }

        Commands::Docs { output, force } => {
            println!("{}", "Generating `.eon` reference docs...".green().bold());
            commands::docs::generate_eon_reference(output, *force)?;
        }

        Commands::Secrets { command } => match command {
            SecretsCommand::Infisical { command } => match command {
                InfisicalCommand::Scaffold {
                    input,
                    output_dir,
                    project,
                    project_id,
                    environment,
                    secret_path,
                    render_dir,
                    auth_method,
                    force,
                } => {
                    println!(
                        "{}",
                        "Generating Infisical secret scaffolding...".green().bold()
                    );
                    let input = input
                        .clone()
                        .or_else(|| config_path.clone())
                        .ok_or_else(|| {
                            anyhow!("secrets infisical scaffold requires --input or --config")
                        })?;
                    let report = commands::secrets::scaffold_infisical(
                        &input,
                        output_dir.as_deref(),
                        project,
                        project_id.as_deref(),
                        environment,
                        secret_path,
                        render_dir,
                        *auth_method,
                        *force,
                    )?;
                    println!("Scaffold directory: {}", report.output_dir.display());
                    println!("Secret bindings: {}", report.secret_bindings.join(", "));
                }
            },
        },

        Commands::Doctor { command } => match command {
            DoctorCommand::Secrets {
                input,
                infisical_dir,
                output,
                format,
                force,
            } => {
                println!("{}", "Running secrets doctor...".green().bold());
                let input = input
                    .clone()
                    .or_else(|| config_path.clone())
                    .ok_or_else(|| anyhow!("doctor secrets requires --input or --config"))?;
                commands::secrets::doctor_secrets(
                    &input,
                    infisical_dir.as_deref(),
                    output.as_deref(),
                    match format {
                        BackupPlanFormatArg::Text => commands::secrets::OutputFormat::Text,
                        BackupPlanFormatArg::Json => commands::secrets::OutputFormat::Json,
                    },
                    *force,
                )?;
            }
        },

        Commands::Backup { command } => match command {
            BackupCommand::Plan {
                input,
                output,
                format,
                force,
            } => {
                println!("{}", "Generating backup plan...".green().bold());
                let input = input
                    .clone()
                    .or_else(|| config_path.clone())
                    .ok_or_else(|| anyhow!("backup plan requires --input or --config"))?;
                commands::backup::generate_backup_plan(
                    &input,
                    output.as_deref(),
                    match format {
                        BackupPlanFormatArg::Text => commands::backup::OutputFormat::Text,
                        BackupPlanFormatArg::Json => commands::backup::OutputFormat::Json,
                    },
                    *force,
                )?;
            }
            BackupCommand::Doctor {
                input,
                output,
                format,
                force,
            } => {
                println!("{}", "Running backup doctor...".green().bold());
                let input = input
                    .clone()
                    .or_else(|| config_path.clone())
                    .ok_or_else(|| anyhow!("backup doctor requires --input or --config"))?;
                let command_database_url = database_url_for_service_input(
                    cli_database_url.as_ref(),
                    env_database_url.as_ref(),
                    config_path.as_deref(),
                    Some(&input),
                    &database_url,
                )?;
                commands::backup::run_backup_doctor(
                    &input,
                    &command_database_url,
                    config_path.as_deref(),
                    output.as_deref(),
                    match format {
                        BackupPlanFormatArg::Text => commands::backup::OutputFormat::Text,
                        BackupPlanFormatArg::Json => commands::backup::OutputFormat::Json,
                    },
                    *force,
                )
                .await?;
            }
            BackupCommand::Snapshot {
                input,
                output,
                force,
            } => {
                println!("{}", "Creating backup snapshot...".green().bold());
                let input = input
                    .clone()
                    .or_else(|| config_path.clone())
                    .ok_or_else(|| anyhow!("backup snapshot requires --input or --config"))?;
                let command_database_url = database_url_for_service_input(
                    cli_database_url.as_ref(),
                    env_database_url.as_ref(),
                    config_path.as_deref(),
                    Some(&input),
                    &database_url,
                )?;
                commands::backup::run_backup_snapshot(
                    &input,
                    &command_database_url,
                    config_path.as_deref(),
                    output,
                    *force,
                )
                .await?;
            }
            BackupCommand::Export {
                input,
                output,
                force,
            } => {
                println!("{}", "Creating logical backup export...".green().bold());
                let input = input
                    .clone()
                    .or_else(|| config_path.clone())
                    .ok_or_else(|| anyhow!("backup export requires --input or --config"))?;
                let command_database_url = database_url_for_service_input(
                    cli_database_url.as_ref(),
                    env_database_url.as_ref(),
                    config_path.as_deref(),
                    Some(&input),
                    &database_url,
                )?;
                commands::backup::run_backup_export(&input, &command_database_url, output, *force)
                    .await?;
            }
            BackupCommand::VerifyRestore {
                artifact,
                output,
                format,
                force,
            } => {
                println!("{}", "Verifying backup restore...".green().bold());
                commands::backup::run_backup_verify_restore(
                    artifact,
                    output.as_deref(),
                    match format {
                        BackupPlanFormatArg::Text => commands::backup::OutputFormat::Text,
                        BackupPlanFormatArg::Json => commands::backup::OutputFormat::Json,
                    },
                    *force,
                )
                .await?;
            }
            BackupCommand::Push {
                artifact,
                remote,
                endpoint_url,
                region,
                path_style,
                format,
            } => {
                println!("{}", "Uploading backup artifact...".green().bold());
                commands::backup::run_backup_push(
                    artifact,
                    remote,
                    endpoint_url.as_deref(),
                    region.as_deref(),
                    *path_style,
                    match format {
                        BackupPlanFormatArg::Text => commands::backup::OutputFormat::Text,
                        BackupPlanFormatArg::Json => commands::backup::OutputFormat::Json,
                    },
                )
                .await?;
            }
            BackupCommand::Pull {
                remote,
                output,
                endpoint_url,
                region,
                path_style,
                force,
                format,
            } => {
                println!("{}", "Downloading backup artifact...".green().bold());
                commands::backup::run_backup_pull(
                    remote,
                    output,
                    endpoint_url.as_deref(),
                    region.as_deref(),
                    *path_style,
                    *force,
                    match format {
                        BackupPlanFormatArg::Text => commands::backup::OutputFormat::Text,
                        BackupPlanFormatArg::Json => commands::backup::OutputFormat::Json,
                    },
                )
                .await?;
            }
        },

        Commands::Replication { command } => match command {
            ReplicationCommand::Doctor {
                input,
                read_database_url,
                output,
                format,
                force,
            } => {
                println!("{}", "Running replication doctor...".green().bold());
                let input = input
                    .clone()
                    .or_else(|| config_path.clone())
                    .ok_or_else(|| anyhow!("replication doctor requires --input or --config"))?;
                let command_database_url = database_url_for_service_input(
                    cli_database_url.as_ref(),
                    env_database_url.as_ref(),
                    config_path.as_deref(),
                    Some(&input),
                    &database_url,
                )?;
                commands::backup::run_replication_doctor(
                    &input,
                    &command_database_url,
                    read_database_url.as_deref(),
                    config_path.as_deref(),
                    output.as_deref(),
                    match format {
                        BackupPlanFormatArg::Text => commands::backup::OutputFormat::Text,
                        BackupPlanFormatArg::Json => commands::backup::OutputFormat::Json,
                    },
                    *force,
                )
                .await?;
            }
        },

        Commands::Authz { command } => match command {
            AuthzCommand::Explain {
                input,
                output,
                format,
                force,
            } => {
                println!("{}", "Explaining authorization...".green().bold());
                let input = input
                    .clone()
                    .or_else(|| config_path.clone())
                    .ok_or_else(|| anyhow!("authz explain requires --input or --config"))?;
                commands::authz::explain_authorization(
                    &input,
                    output.as_deref(),
                    match format {
                        AuthzExplainFormatArg::Text => commands::authz::OutputFormat::Text,
                        AuthzExplainFormatArg::Json => commands::authz::OutputFormat::Json,
                    },
                    *force,
                )?;
            }
            AuthzCommand::Simulate {
                input,
                resource,
                action,
                user_id,
                roles,
                claims,
                row,
                related_rows,
                proposed,
                scope,
                hybrid_source,
                scoped_assignments,
                load_runtime_assignments,
                output,
                format,
                force,
            } => {
                println!("{}", "Simulating authorization...".green().bold());
                let input = input
                    .clone()
                    .or_else(|| config_path.clone())
                    .ok_or_else(|| anyhow!("authz simulate requires --input or --config"))?;
                commands::authz::simulate_authorization(
                    &input,
                    resource.as_deref(),
                    authz_action(*action),
                    *user_id,
                    roles,
                    claims,
                    row,
                    related_rows,
                    proposed,
                    scope.as_deref(),
                    hybrid_source.map(authz_hybrid_source),
                    scoped_assignments,
                    *load_runtime_assignments,
                    Some(&database_url),
                    config_path.as_deref(),
                    output.as_deref(),
                    match format {
                        AuthzExplainFormatArg::Text => commands::authz::OutputFormat::Text,
                        AuthzExplainFormatArg::Json => commands::authz::OutputFormat::Json,
                    },
                    *force,
                )
                .await?;
            }
            AuthzCommand::Runtime { command } => match command {
                AuthzRuntimeCommand::List {
                    user_id,
                    output,
                    format,
                    force,
                } => {
                    println!(
                        "{}",
                        "Listing runtime authorization assignments..."
                            .green()
                            .bold()
                    );
                    commands::authz::list_runtime_assignments(
                        *user_id,
                        &database_url,
                        config_path.as_deref(),
                        output.as_deref(),
                        match format {
                            AuthzExplainFormatArg::Text => commands::authz::OutputFormat::Text,
                            AuthzExplainFormatArg::Json => commands::authz::OutputFormat::Json,
                        },
                        *force,
                    )
                    .await?;
                }
                AuthzRuntimeCommand::Create {
                    input,
                    user_id,
                    assignment,
                    created_by_user_id,
                    expires_at,
                    output,
                    format,
                    force,
                } => {
                    println!(
                        "{}",
                        "Creating runtime authorization assignment..."
                            .green()
                            .bold()
                    );
                    let input = input
                        .clone()
                        .or_else(|| config_path.clone())
                        .ok_or_else(|| {
                            anyhow!("authz runtime create requires --input or --config")
                        })?;
                    commands::authz::create_runtime_assignment(
                        &input,
                        *user_id,
                        assignment,
                        expires_at.as_deref(),
                        *created_by_user_id,
                        &database_url,
                        config_path.as_deref(),
                        output.as_deref(),
                        match format {
                            AuthzExplainFormatArg::Text => commands::authz::OutputFormat::Text,
                            AuthzExplainFormatArg::Json => commands::authz::OutputFormat::Json,
                        },
                        *force,
                    )
                    .await?;
                }
                AuthzRuntimeCommand::Delete {
                    id,
                    actor_user_id,
                    reason,
                    output,
                    format,
                    force,
                } => {
                    println!(
                        "{}",
                        "Deleting runtime authorization assignment..."
                            .green()
                            .bold()
                    );
                    commands::authz::delete_runtime_assignment(
                        id,
                        *actor_user_id,
                        reason.as_deref(),
                        &database_url,
                        config_path.as_deref(),
                        output.as_deref(),
                        match format {
                            AuthzExplainFormatArg::Text => commands::authz::OutputFormat::Text,
                            AuthzExplainFormatArg::Json => commands::authz::OutputFormat::Json,
                        },
                        *force,
                    )
                    .await?;
                }
                AuthzRuntimeCommand::Revoke {
                    id,
                    actor_user_id,
                    reason,
                    output,
                    format,
                    force,
                } => {
                    println!(
                        "{}",
                        "Revoking runtime authorization assignment..."
                            .green()
                            .bold()
                    );
                    commands::authz::revoke_runtime_assignment(
                        id,
                        *actor_user_id,
                        reason.as_deref(),
                        &database_url,
                        config_path.as_deref(),
                        output.as_deref(),
                        match format {
                            AuthzExplainFormatArg::Text => commands::authz::OutputFormat::Text,
                            AuthzExplainFormatArg::Json => commands::authz::OutputFormat::Json,
                        },
                        *force,
                    )
                    .await?;
                }
                AuthzRuntimeCommand::Renew {
                    id,
                    expires_at,
                    actor_user_id,
                    reason,
                    output,
                    format,
                    force,
                } => {
                    println!(
                        "{}",
                        "Renewing runtime authorization assignment..."
                            .green()
                            .bold()
                    );
                    commands::authz::renew_runtime_assignment(
                        id,
                        expires_at,
                        *actor_user_id,
                        reason.as_deref(),
                        &database_url,
                        config_path.as_deref(),
                        output.as_deref(),
                        match format {
                            AuthzExplainFormatArg::Text => commands::authz::OutputFormat::Text,
                            AuthzExplainFormatArg::Json => commands::authz::OutputFormat::Json,
                        },
                        *force,
                    )
                    .await?;
                }
                AuthzRuntimeCommand::History {
                    user_id,
                    output,
                    format,
                    force,
                } => {
                    println!(
                        "{}",
                        "Listing runtime authorization assignment history..."
                            .green()
                            .bold()
                    );
                    commands::authz::list_runtime_assignment_history(
                        *user_id,
                        &database_url,
                        config_path.as_deref(),
                        output.as_deref(),
                        match format {
                            AuthzExplainFormatArg::Text => commands::authz::OutputFormat::Text,
                            AuthzExplainFormatArg::Json => commands::authz::OutputFormat::Json,
                        },
                        *force,
                    )
                    .await?;
                }
                AuthzRuntimeCommand::Evaluate {
                    input,
                    resource,
                    action,
                    user_id,
                    scope,
                    output,
                    format,
                    force,
                } => {
                    println!(
                        "{}",
                        "Evaluating runtime authorization access...".green().bold()
                    );
                    let input = input
                        .clone()
                        .or_else(|| config_path.clone())
                        .ok_or_else(|| {
                            anyhow!("authz runtime evaluate requires --input or --config")
                        })?;
                    commands::authz::evaluate_runtime_access(
                        &input,
                        resource,
                        authz_action(*action),
                        *user_id,
                        scope,
                        &database_url,
                        config_path.as_deref(),
                        output.as_deref(),
                        match format {
                            AuthzExplainFormatArg::Text => commands::authz::OutputFormat::Text,
                            AuthzExplainFormatArg::Json => commands::authz::OutputFormat::Json,
                        },
                        *force,
                    )
                    .await?;
                }
            },
        },

        Commands::Tls { command } => match command {
            TlsCommand::SelfSigned {
                cert_path,
                key_path,
                hosts,
                force,
            } => {
                println!(
                    "{}",
                    "Generating self-signed TLS certificate...".green().bold()
                );
                commands::tls::generate_self_signed_certificate(
                    config_path.as_deref(),
                    cert_path.clone(),
                    key_path.clone(),
                    hosts,
                    *force,
                )?;
            }
        },
    }

    Ok(())
}

#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<()> {
    run_cli().await
}

#[cfg(not(test))]
fn authz_action(action: AuthzActionArg) -> rest_macro_core::authorization::AuthorizationAction {
    match action {
        AuthzActionArg::Read => rest_macro_core::authorization::AuthorizationAction::Read,
        AuthzActionArg::Create => rest_macro_core::authorization::AuthorizationAction::Create,
        AuthzActionArg::Update => rest_macro_core::authorization::AuthorizationAction::Update,
        AuthzActionArg::Delete => rest_macro_core::authorization::AuthorizationAction::Delete,
    }
}

#[cfg(not(test))]
fn authz_hybrid_source(
    source: AuthzHybridSourceArg,
) -> rest_macro_core::authorization::AuthorizationHybridSource {
    match source {
        AuthzHybridSourceArg::Item => {
            rest_macro_core::authorization::AuthorizationHybridSource::Item
        }
        AuthzHybridSourceArg::CollectionFilter => {
            rest_macro_core::authorization::AuthorizationHybridSource::CollectionFilter
        }
        AuthzHybridSourceArg::NestedParent => {
            rest_macro_core::authorization::AuthorizationHybridSource::NestedParent
        }
        AuthzHybridSourceArg::CreatePayload => {
            rest_macro_core::authorization::AuthorizationHybridSource::CreatePayload
        }
    }
}

fn include_builtin_auth(with_auth: bool, without_auth: bool) -> bool {
    if without_auth {
        return false;
    }

    if with_auth {
        return true;
    }

    true
}

#[cfg(not(test))]
fn database_url_for_service_input(
    cli_database_url: Option<&String>,
    env_database_url: Option<&String>,
    config_path: Option<&std::path::Path>,
    input: Option<&PathBuf>,
    fallback_database_url: &str,
) -> Result<String> {
    if let Some(url) = cli_database_url {
        return Ok(url.clone());
    }
    if let Some(url) = env_database_url {
        return Ok(url.clone());
    }
    if let Some(path) = config_path.or(input.map(PathBuf::as_path)) {
        return commands::db::database_url_from_service_config(path).map_err(Into::into);
    }
    Ok(fallback_database_url.to_owned())
}

#[cfg(not(test))]
fn resolve_config_path(explicit: Option<&str>) -> Result<Option<PathBuf>> {
    if let Some(path) = explicit {
        return Ok(Some(PathBuf::from(path)));
    }

    let cwd = std::env::current_dir()?;
    Ok(autodiscover_config_path(&cwd))
}

fn autodiscover_config_path(dir: &std::path::Path) -> Option<PathBuf> {
    let mut matches = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("eon"))
        .collect::<Vec<_>>();
    matches.sort();
    if matches.len() == 1 {
        matches.into_iter().next()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, autodiscover_config_path, include_builtin_auth};
    use clap::Parser;
    use std::{fs, path::PathBuf};
    use uuid::Uuid;

    #[test]
    fn include_builtin_auth_defaults_on() {
        assert!(include_builtin_auth(false, false));
        assert!(include_builtin_auth(true, false));
        assert!(!include_builtin_auth(false, true));
    }

    #[test]
    fn openapi_subcommand_uses_documented_name() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "openapi",
                "--input",
                "api.eon",
                "--output",
                "openapi.json",
            ])
            .is_ok()
        );
    }

    #[test]
    fn build_command_accepts_positional_service_input() {
        assert!(Cli::try_parse_from(["vsr", "build", "todo_app.eon"]).is_ok());
    }

    #[test]
    fn clean_command_accepts_optional_build_dir() {
        assert!(Cli::try_parse_from(["vsr", "clean"]).is_ok());
        assert!(Cli::try_parse_from(["vsr", "clean", "--build-dir", ".vsr-build"]).is_ok());
    }

    #[test]
    fn serve_command_accepts_positional_service_input() {
        assert!(Cli::try_parse_from(["vsr", "serve", "todo_app.eon"]).is_ok());
    }

    #[test]
    fn serve_command_accepts_without_auth_alias() {
        assert!(Cli::try_parse_from(["vsr", "serve", "todo_app.eon", "--no-auth",]).is_ok());
    }

    #[test]
    fn init_command_accepts_starter_flag() {
        assert!(Cli::try_parse_from(["vsr", "init", "demo", "--starter", "minimal"]).is_ok());
    }

    #[test]
    fn server_serve_subcommand_accepts_input() {
        assert!(Cli::try_parse_from(["vsr", "server", "serve", "--input", "todo_app.eon"]).is_ok());
    }

    #[test]
    fn server_serve_subcommand_accepts_without_auth_alias() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "server",
                "serve",
                "--input",
                "todo_app.eon",
                "--no-auth",
            ])
            .is_ok()
        );
    }

    #[test]
    fn server_expand_subcommand_accepts_input_and_output() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "server",
                "expand",
                "--input",
                "todo_app.eon",
                "--output",
                "expanded.rs",
            ])
            .is_ok()
        );
    }

    #[test]
    fn server_expand_subcommand_accepts_output_dir_alias() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "server",
                "expand",
                "--input",
                "todo_app.eon",
                "--output-dir",
                "generated-api",
            ])
            .is_ok()
        );
    }

    #[test]
    fn server_expand_subcommand_accepts_default_output() {
        assert!(
            Cli::try_parse_from(["vsr", "server", "expand", "--input", "todo_app.eon"]).is_ok()
        );
    }

    #[test]
    fn docs_command_accepts_output_file() {
        assert!(Cli::try_parse_from(["vsr", "docs", "--output", "docs/eon-reference.md"]).is_ok());
    }

    #[test]
    fn secrets_infisical_scaffold_accepts_input_and_project() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "secrets",
                "infisical",
                "scaffold",
                "--input",
                "api.eon",
                "--project",
                "demo-project",
                "--project-id",
                "2435f6d5-14d0-4429-b1e6-172b497f2c17",
                "--environment",
                "prod",
                "--auth-method",
                "azure",
            ])
            .is_ok()
        );
    }

    #[test]
    fn doctor_secrets_accepts_infisical_dir_and_json_format() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "doctor",
                "secrets",
                "--input",
                "api.eon",
                "--infisical-dir",
                "deploy/infisical",
                "--format",
                "json",
            ])
            .is_ok()
        );
    }

    #[test]
    fn backup_plan_accepts_input_and_json_format() {
        assert!(
            Cli::try_parse_from([
                "vsr", "backup", "plan", "--input", "api.eon", "--format", "json",
            ])
            .is_ok()
        );
    }

    #[test]
    fn backup_doctor_accepts_input() {
        assert!(Cli::try_parse_from(["vsr", "backup", "doctor", "--input", "api.eon"]).is_ok());
    }

    #[test]
    fn backup_snapshot_accepts_output_directory() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "backup",
                "snapshot",
                "--input",
                "api.eon",
                "--output",
                "backups/run1",
            ])
            .is_ok()
        );
    }

    #[test]
    fn backup_export_accepts_output_directory() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "backup",
                "export",
                "--input",
                "api.eon",
                "--output",
                "backups/run1",
            ])
            .is_ok()
        );
    }

    #[test]
    fn backup_verify_restore_accepts_artifact_path() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "backup",
                "verify-restore",
                "--artifact",
                "backups/run1",
                "--format",
                "json",
            ])
            .is_ok()
        );
    }

    #[test]
    fn backup_push_accepts_remote_s3_options() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "backup",
                "push",
                "--artifact",
                "backups/run1",
                "--remote",
                "s3://bucket/prefix",
                "--endpoint-url",
                "http://127.0.0.1:9000",
                "--path-style",
                "--format",
                "json",
            ])
            .is_ok()
        );
    }

    #[test]
    fn backup_pull_accepts_remote_s3_options() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "backup",
                "pull",
                "--remote",
                "s3://bucket/prefix",
                "--output",
                "backups/run1",
                "--force",
            ])
            .is_ok()
        );
    }

    #[test]
    fn replication_doctor_accepts_read_database_url() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "replication",
                "doctor",
                "--input",
                "api.eon",
                "--read-database-url",
                "postgres://reader@127.0.0.1/app",
            ])
            .is_ok()
        );
    }

    #[test]
    fn authz_explain_accepts_input_and_json_format() {
        assert!(
            Cli::try_parse_from([
                "vsr", "authz", "explain", "--input", "api.eon", "--format", "json",
            ])
            .is_ok()
        );
    }

    #[test]
    fn authz_simulate_accepts_resource_action_and_claims() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "authz",
                "simulate",
                "--input",
                "api.eon",
                "--resource",
                "ScopedDoc",
                "--action",
                "create",
                "--user-id",
                "1",
                "--role",
                "admin",
                "--claim",
                "tenant_id=7",
                "--proposed",
                "tenant_id=42",
                "--scope",
                "Family=42",
                "--hybrid-source",
                "create-payload",
                "--scoped-assignment",
                "template:FamilyMember@Family=42",
                "--load-runtime-assignments",
                "--format",
                "json",
            ])
            .is_ok()
        );
    }

    #[test]
    fn migrate_authz_accepts_output_file() {
        assert!(
            Cli::try_parse_from([
                "vsr",
                "migrate",
                "authz",
                "--output",
                "migrations/0002_authz.sql",
            ])
            .is_ok()
        );
    }

    #[test]
    fn tls_command_accepts_self_signed_subcommand() {
        assert!(Cli::try_parse_from(["vsr", "tls", "self-signed"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "vsr",
                "tls",
                "self-signed",
                "--cert-path",
                "certs/dev-cert.pem",
                "--key-path",
                "certs/dev-key.pem",
                "--host",
                "localhost",
            ])
            .is_ok()
        );
    }

    #[test]
    fn autodiscover_config_path_picks_single_local_eon() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/main_tests")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&root).expect("test directory should exist");
        fs::write(root.join("todo_app.eon"), "module: \"todo_app\"\n")
            .expect("config should write");

        assert_eq!(
            autodiscover_config_path(&root),
            Some(root.join("todo_app.eon"))
        );
    }

    #[test]
    fn autodiscover_config_path_skips_ambiguous_directories() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/main_tests")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&root).expect("test directory should exist");
        fs::write(root.join("todo_app.eon"), "module: \"todo_app\"\n")
            .expect("first config should write");
        fs::write(root.join("blog_api.eon"), "module: \"blog_api\"\n")
            .expect("second config should write");

        assert_eq!(autodiscover_config_path(&root), None);
    }
}
