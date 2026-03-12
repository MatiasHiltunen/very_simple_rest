use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use colored::Colorize;
use rest_macro_core::auth::{AuthDbBackend, auth_migration_sql};
use rest_macro_core::compiler::{self, DbBackend, ServiceSpec};
use uuid::Uuid;

use crate::error::{Error, Result};

const LOCAL_DEP_PATH_ENV: &str = "VSR_LOCAL_DEP_PATH";
const REPO_GIT_URL: &str = "https://github.com/MatiasHiltunen/very_simple_rest.git";

pub fn emit_server_project(
    input: &Path,
    output_dir: &Path,
    package_name: Option<String>,
    with_auth: bool,
    force: bool,
) -> Result<()> {
    let emitted = emit_server_project_inner(input, output_dir, package_name, with_auth, force)?;
    println!(
        "{} {}",
        "Generated server project:".green().bold(),
        emitted.project_dir.display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn build_server_binary(
    input: &Path,
    output: &Path,
    package_name: Option<String>,
    build_dir: Option<PathBuf>,
    with_auth: bool,
    release: bool,
    target: Option<String>,
    keep_build_dir: bool,
    force: bool,
) -> Result<()> {
    if output.exists() && !force {
        return Err(Error::Config(format!(
            "output binary already exists: {} (pass --force to overwrite)",
            output.display()
        )));
    }

    let build_root = match build_dir {
        Some(dir) => dir,
        None => std::env::current_dir()
            .map_err(Error::Io)?
            .join(".vsr-build")
            .join(
                package_name
                    .clone()
                    .unwrap_or_else(|| "vsr-eon-server".to_owned()),
            )
            .join(Uuid::new_v4().to_string()),
    };

    let emitted = emit_server_project_inner(input, &build_root, package_name, with_auth, true)?;

    let target_dir = emitted.project_dir.join("target");
    let mut command = Command::new("cargo");
    command.arg("build");
    if release {
        command.arg("--release");
    }
    if let Some(target) = &target {
        command.arg("--target").arg(target);
    }
    command.current_dir(&emitted.project_dir);
    command.env("CARGO_TARGET_DIR", &target_dir);

    let output_result = command.output().map_err(Error::Io)?;
    if !output_result.status.success() {
        let stdout = String::from_utf8_lossy(&output_result.stdout);
        let stderr = String::from_utf8_lossy(&output_result.stderr);
        return Err(Error::Unknown(format!(
            "cargo build failed for generated server project\nstdout:\n{stdout}\nstderr:\n{stderr}"
        )));
    }

    let profile_dir = if release { "release" } else { "debug" };
    let mut binary_path = target_dir;
    if let Some(target) = &target {
        binary_path = binary_path.join(target);
    }
    binary_path = binary_path
        .join(profile_dir)
        .join(binary_file_name(&emitted.package_name));

    if !binary_path.exists() {
        return Err(Error::Unknown(format!(
            "cargo build succeeded but the binary was not found at {}",
            binary_path.display()
        )));
    }

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    fs::copy(&binary_path, output).map_err(Error::Io)?;

    if !keep_build_dir {
        let _ = fs::remove_dir_all(&emitted.project_dir);
    }

    println!(
        "{} {}",
        "Built server binary:".green().bold(),
        output.display()
    );

    Ok(())
}

struct EmittedProject {
    project_dir: PathBuf,
    package_name: String,
}

fn emit_server_project_inner(
    input: &Path,
    output_dir: &Path,
    package_name: Option<String>,
    with_auth: bool,
    force: bool,
) -> Result<EmittedProject> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| Error::Config(format!("failed to load `{}`: {error}", input.display())))?;
    let backend = detect_backend(&service)?;
    ensure_auth_is_compatible(&service, with_auth)?;

    prepare_output_dir(output_dir, force)?;

    let package_name = package_name
        .map(|name| sanitize_package_name(&name))
        .unwrap_or_else(|| sanitize_package_name(&service.module_ident.to_string()));
    let eon_file_name = input
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("service.eon")
        .to_owned();

    let input_content = fs::read_to_string(input).map_err(Error::Io)?;
    let migration_sql = compiler::render_service_migration_sql(&service)
        .map_err(|error| Error::Config(format!("failed to render migration SQL: {error}")))?;
    let module_name = service.module_ident.to_string();

    fs::create_dir_all(output_dir.join("src")).map_err(Error::Io)?;
    fs::create_dir_all(output_dir.join("migrations")).map_err(Error::Io)?;

    write_file(
        &output_dir.join("Cargo.toml"),
        &render_cargo_toml(&package_name, backend)?,
    )?;
    write_file(
        &output_dir.join("src/main.rs"),
        &render_main_rs(&module_name, &eon_file_name, backend, with_auth),
    )?;
    write_file(&output_dir.join(&eon_file_name), &input_content)?;
    write_file(
        &output_dir.join(".env.example"),
        &render_env_example(backend, with_auth),
    )?;
    write_file(
        &output_dir.join(".gitignore"),
        "target/\n.env\n*.db\n*.db-shm\n*.db-wal\n",
    )?;
    write_file(
        &output_dir.join("README.md"),
        &render_project_readme(&package_name, backend, with_auth),
    )?;
    write_file(
        &output_dir.join("migrations/0001_service.sql"),
        &migration_sql,
    )?;

    if with_auth {
        write_file(
            &output_dir.join("migrations/0000_auth.sql"),
            &auth_migration_sql(auth_backend(backend)),
        )?;
    }

    Ok(EmittedProject {
        project_dir: output_dir.to_path_buf(),
        package_name,
    })
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).map_err(Error::Io)
}

fn prepare_output_dir(path: &Path, force: bool) -> Result<()> {
    if path.exists() {
        if !path.is_dir() {
            if force {
                fs::remove_file(path).map_err(Error::Io)?;
            } else {
                return Err(Error::Config(format!(
                    "output path exists and is not a directory: {}",
                    path.display()
                )));
            }
        }

        if path.exists() {
            let has_entries = fs::read_dir(path)
                .map_err(Error::Io)?
                .next()
                .transpose()
                .map_err(Error::Io)?
                .is_some();
            if has_entries {
                if !force {
                    return Err(Error::Config(format!(
                        "output directory already exists and is not empty: {} (pass --force to overwrite)",
                        path.display()
                    )));
                }
                fs::remove_dir_all(path).map_err(Error::Io)?;
            }
        }
    }

    fs::create_dir_all(path).map_err(Error::Io)
}

fn detect_backend(service: &ServiceSpec) -> Result<DbBackend> {
    let mut backends = service.resources.iter().map(|resource| resource.db);
    let Some(first) = backends.next() else {
        return Err(Error::Config(
            "service config must contain at least one resource".to_owned(),
        ));
    };

    if backends.any(|backend| backend != first) {
        return Err(Error::Config(
            "mixed database backends in one service are not supported by `vsr server`".to_owned(),
        ));
    }

    Ok(first)
}

fn ensure_auth_is_compatible(service: &ServiceSpec, with_auth: bool) -> Result<()> {
    if !with_auth {
        return Ok(());
    }

    if service
        .resources
        .iter()
        .any(|resource| resource.table_name == "user")
    {
        return Err(Error::Config(
            "`--with-auth` cannot be used when the service already defines a `user` table"
                .to_owned(),
        ));
    }

    Ok(())
}

fn render_cargo_toml(package_name: &str, backend: DbBackend) -> Result<String> {
    let dependency = render_runtime_dependency(backend)?;
    let backend_feature = backend_feature_name(backend);
    Ok(format!(
        r#"[package]
name = "{package_name}"
version = "0.1.0"
edition = "2024"

[workspace]

[dependencies]
actix-web = "4"
dotenv = "0.15"
env_logger = "0.11"
log = "0.4"
serde = {{ version = "1", features = ["derive"] }}
sqlx = {{ version = "0.8.3", features = ["runtime-tokio-native-tls", "any", "macros", "chrono", "{backend_feature}"] }}
{dependency}
"#
    ))
}

fn render_runtime_dependency(backend: DbBackend) -> Result<String> {
    let backend_feature = backend_feature_name(backend);

    if let Ok(explicit_path) = std::env::var(LOCAL_DEP_PATH_ENV) {
        return Ok(format!(
            "very_simple_rest = {{ path = \"{}\", default-features = false, features = [\"{backend_feature}\"] }}",
            escape_toml_path(&explicit_path)
        ));
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if workspace_root.join("Cargo.toml").exists() {
        let canonical = workspace_root.canonicalize().map_err(Error::Io)?;
        return Ok(format!(
            "very_simple_rest = {{ path = \"{}\", default-features = false, features = [\"{backend_feature}\"] }}",
            escape_toml_path(&canonical.display().to_string())
        ));
    }

    Ok(format!(
        "very_simple_rest = {{ git = \"{REPO_GIT_URL}\", default-features = false, features = [\"{backend_feature}\"] }}"
    ))
}

fn render_main_rs(
    module_name: &str,
    eon_file_name: &str,
    backend: DbBackend,
    with_auth: bool,
) -> String {
    let default_database_url = default_database_url(backend);
    let auth_config = if with_auth {
        "                    .configure(|cfg| auth::auth_routes(cfg, server_pool.clone()))\n"
    } else {
        ""
    };

    format!(
        r#"use std::env;

use very_simple_rest::prelude::*;

rest_api_from_eon!("{eon_file_name}");

#[actix_web::main]
async fn main() -> std::io::Result<()> {{
    let _ = dotenv::dotenv();
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    very_simple_rest::sqlx::any::install_default_drivers();

    let database_url =
        env::var("DATABASE_URL").unwrap_or_else(|_| "{default_database_url}".to_owned());
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());

    let pool = AnyPool::connect(&database_url)
        .await
        .map_err(|error| std::io::Error::other(format!("database connection failed: {{error}}")))?;

    let server_pool = pool.clone();
    let server = HttpServer::new(move || {{
        App::new()
            .wrap(Logger::default())
            .service(
                scope("/api")
{auth_config}                    .configure(|cfg| {module_name}::configure(cfg, server_pool.clone()))
            )
    }})
    .bind(&bind_addr)?;

    info!("Server listening on http://{{}}", bind_addr);
    server.run().await
}}
"#
    )
}

fn render_env_example(backend: DbBackend, with_auth: bool) -> String {
    let auth_block = if with_auth {
        "JWT_SECRET=change-me\n# Optional built-in auth bootstrap values\n# ADMIN_EMAIL=admin@example.com\n# ADMIN_PASSWORD=change-me\n"
    } else {
        "# JWT_SECRET=change-me-if-you-enable-built-in-auth\n"
    };

    format!(
        "DATABASE_URL={}\nBIND_ADDR=127.0.0.1:8080\nRUST_LOG=info\n{}",
        default_database_url(backend),
        auth_block
    )
}

fn render_project_readme(package_name: &str, backend: DbBackend, with_auth: bool) -> String {
    let auth_note = if with_auth {
        "The generated project includes built-in auth routes and `migrations/0000_auth.sql`.\n"
    } else {
        "The generated project does not include built-in auth routes by default.\n"
    };

    format!(
        "# {package_name}\n\nGenerated by `vsr server emit`.\n\n\
Backend: `{}`\n\n\
{}\n\
Apply the SQL files in `migrations/` before starting the server, then run:\n\n\
```bash\n\
cp .env.example .env\n\
cargo run\n\
```\n",
        backend_feature_name(backend),
        auth_note
    )
}

fn backend_feature_name(backend: DbBackend) -> &'static str {
    match backend {
        DbBackend::Sqlite => "sqlite",
        DbBackend::Postgres => "postgres",
        DbBackend::Mysql => "mysql",
    }
}

fn auth_backend(backend: DbBackend) -> AuthDbBackend {
    match backend {
        DbBackend::Sqlite => AuthDbBackend::Sqlite,
        DbBackend::Postgres => AuthDbBackend::Postgres,
        DbBackend::Mysql => AuthDbBackend::Mysql,
    }
}

fn default_database_url(backend: DbBackend) -> &'static str {
    match backend {
        DbBackend::Sqlite => "sqlite:app.db?mode=rwc",
        DbBackend::Postgres => "postgres://postgres:postgres@127.0.0.1/app",
        DbBackend::Mysql => "mysql://root:password@127.0.0.1/app",
    }
}

fn sanitize_package_name(value: &str) -> String {
    let mut sanitized = value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' => ch,
            'A'..='Z' => ch.to_ascii_lowercase(),
            '_' | '-' | ' ' => '-',
            _ => '-',
        })
        .collect::<String>();

    while sanitized.contains("--") {
        sanitized = sanitized.replace("--", "-");
    }

    sanitized = sanitized.trim_matches('-').to_owned();

    if sanitized.is_empty() {
        return "vsr-eon-server".to_owned();
    }

    if sanitized
        .chars()
        .next()
        .map(|ch| ch.is_ascii_digit())
        .unwrap_or(false)
    {
        format!("vsr-{sanitized}")
    } else {
        sanitized
    }
}

fn escape_toml_path(path: &str) -> String {
    path.replace('\\', "\\\\")
}

fn binary_file_name(package_name: &str) -> String {
    if cfg!(windows) {
        format!("{package_name}.exe")
    } else {
        package_name.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{build_server_binary, emit_server_project, sanitize_package_name};
    use std::fs;
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn test_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/server_tests")
            .join(Uuid::new_v4().to_string())
    }

    fn read_to_string(path: &Path) -> String {
        fs::read_to_string(path).expect("generated file should be readable")
    }

    #[test]
    fn sanitize_package_name_normalizes_values() {
        assert_eq!(
            sanitize_package_name("Commerce Bench API"),
            "commerce-bench-api"
        );
        assert_eq!(sanitize_package_name("9service"), "vsr-9service");
        assert_eq!(sanitize_package_name("___"), "vsr-eon-server");
    }

    #[test]
    fn emit_server_project_writes_project_files() {
        let root = test_root();
        emit_server_project(
            &fixture_path("blog_api.eon"),
            &root,
            Some("blog-server".to_owned()),
            false,
            false,
        )
        .expect("server project should emit");

        assert!(root.join("Cargo.toml").exists());
        assert!(root.join("src/main.rs").exists());
        assert!(root.join("blog_api.eon").exists());
        assert!(root.join("migrations/0001_service.sql").exists());

        let main_rs = read_to_string(&root.join("src/main.rs"));
        assert!(main_rs.contains("rest_api_from_eon!(\"blog_api.eon\")"));
        assert!(main_rs.contains("blog_api::configure"));

        let cargo_toml = read_to_string(&root.join("Cargo.toml"));
        assert!(cargo_toml.contains("name = \"blog-server\""));
        assert!(cargo_toml.contains("very_simple_rest"));

        let migration = read_to_string(&root.join("migrations/0001_service.sql"));
        assert!(migration.contains("CREATE TABLE post"));
        assert!(migration.contains("CREATE TABLE comment"));
    }

    #[test]
    fn emit_server_project_includes_auth_migration_when_requested() {
        let root = test_root();
        emit_server_project(
            &fixture_path("blog_api.eon"),
            &root,
            Some("auth-blog-server".to_owned()),
            true,
            false,
        )
        .expect("server project should emit");

        assert!(root.join("migrations/0000_auth.sql").exists());
        let main_rs = read_to_string(&root.join("src/main.rs"));
        assert!(main_rs.contains("auth::auth_routes"));
    }

    #[test]
    #[ignore]
    fn build_server_binary_compiles_generated_project() {
        let root = test_root();
        let output = root.join("dist/blog-server");
        build_server_binary(
            &fixture_path("blog_api.eon"),
            &output,
            Some("blog-server".to_owned()),
            Some(root.join("build")),
            false,
            false,
            None,
            false,
            false,
        )
        .expect("generated server binary should build");

        assert!(
            output.exists(),
            "binary should exist at {}",
            output.display()
        );
    }
}
