use anyhow::{Context, Result, bail};
use colored::Colorize;
use rest_macro_core::auth::{AuthDbBackend, auth_migration_sql};
use rest_macro_core::compiler;
use sqlx::{AnyPool, Row};
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
};

use crate::commands::schema::{load_filtered_derive_service, load_schema_service};

const MIGRATIONS_TABLE: &str = "_vsr_migrations";
const BUILTIN_AUTH_MIGRATION: &str = "0000_builtin_auth.sql";

pub fn generate_migration(input: &Path, output: &Path, force: bool) -> Result<()> {
    if output.exists() && !force {
        bail!(
            "migration file already exists at {} (use --force to overwrite)",
            output.display()
        );
    }

    let service = compiler::load_service_from_path(input)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("failed to load service definition from {}", input.display()))?;
    let sql = compiler::render_service_migration_sql(&service)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("failed to render migration SQL")?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    fs::write(output, sql)
        .with_context(|| format!("failed to write migration to {}", output.display()))?;

    println!(
        "{} {}",
        "Generated migration:".green().bold(),
        output.display()
    );

    Ok(())
}

pub fn generate_derive_migration(
    input: &Path,
    output: &Path,
    force: bool,
    exclude_tables: &[String],
) -> Result<()> {
    if output.exists() && !force {
        bail!(
            "migration file already exists at {} (use --force to overwrite)",
            output.display()
        );
    }

    let service = load_filtered_derive_service(input, exclude_tables)?;
    let sql = compiler::render_service_migration_sql(&service)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("failed to render derive migration SQL")?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    fs::write(output, sql)
        .with_context(|| format!("failed to write migration to {}", output.display()))?;

    println!(
        "{} {}",
        "Generated derive migration:".green().bold(),
        output.display()
    );

    Ok(())
}

pub fn generate_auth_migration(database_url: &str, output: &Path, force: bool) -> Result<()> {
    if output.exists() && !force {
        bail!(
            "migration file already exists at {} (use --force to overwrite)",
            output.display()
        );
    }

    let backend = AuthDbBackend::from_database_url(database_url)
        .ok_or_else(|| anyhow::anyhow!("unsupported database url: {database_url}"))?;
    let sql = auth_migration_sql(backend);

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    fs::write(output, sql)
        .with_context(|| format!("failed to write migration to {}", output.display()))?;

    println!(
        "{} {}",
        "Generated auth migration:".green().bold(),
        output.display()
    );

    Ok(())
}

pub fn check_migration(input: &Path, existing: &Path) -> Result<()> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("failed to load service definition from {}", input.display()))?;
    let generated = compiler::render_service_migration_sql(&service)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("failed to render migration SQL")?;
    let existing_sql = fs::read_to_string(existing)
        .with_context(|| format!("failed to read {}", existing.display()))?;

    if normalize_sql(&generated) != normalize_sql(&existing_sql) {
        bail!(
            "migration drift detected between {} and {}",
            input.display(),
            existing.display()
        );
    }

    println!(
        "{} {}",
        "Migration is up to date:".green().bold(),
        existing.display()
    );

    Ok(())
}

pub fn check_derive_migration(
    input: &Path,
    existing: &Path,
    exclude_tables: &[String],
) -> Result<()> {
    let service = load_filtered_derive_service(input, exclude_tables)?;
    let generated = compiler::render_service_migration_sql(&service)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("failed to render derive migration SQL")?;
    let existing_sql = fs::read_to_string(existing)
        .with_context(|| format!("failed to read {}", existing.display()))?;

    if normalize_sql(&generated) != normalize_sql(&existing_sql) {
        bail!(
            "derive migration drift detected between {} and {}",
            input.display(),
            existing.display()
        );
    }

    println!(
        "{} {}",
        "Derive migration is up to date:".green().bold(),
        existing.display()
    );

    Ok(())
}

pub fn generate_diff_migration(
    previous: &Path,
    next: &Path,
    output: &Path,
    force: bool,
    exclude_tables: &[String],
) -> Result<()> {
    if output.exists() && !force {
        bail!(
            "migration file already exists at {} (use --force to overwrite)",
            output.display()
        );
    }

    let previous_service = load_schema_service(previous, exclude_tables)?;
    let next_service = load_schema_service(next, exclude_tables)?;
    let sql = compiler::render_service_diff_migration_sql(&previous_service, &next_service)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("failed to render additive diff migration SQL")?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    fs::write(output, sql)
        .with_context(|| format!("failed to write migration to {}", output.display()))?;

    println!(
        "{} {}",
        "Generated diff migration:".green().bold(),
        output.display()
    );

    Ok(())
}

pub async fn inspect_live_schema(
    database_url: &str,
    input: &Path,
    exclude_tables: &[String],
) -> Result<()> {
    let service = load_schema_service(input, exclude_tables)?;
    let backend = AuthDbBackend::from_database_url(database_url)
        .ok_or_else(|| anyhow::anyhow!("unsupported database url: {database_url}"))?;
    let pool = AnyPool::connect(database_url)
        .await
        .with_context(|| format!("failed to connect to database at {database_url}"))?;

    let mut issues = Vec::new();
    for resource in &service.resources {
        let live = inspect_table_schema(&pool, backend, &resource.table_name).await?;
        let Some(live) = live else {
            issues.push(format!("missing table `{}`", resource.table_name));
            continue;
        };

        for field in &resource.fields {
            let field_name = field.name();
            let Some(column) = live.columns.get(&field_name) else {
                issues.push(format!(
                    "missing column `{}` on `{}`",
                    field_name, resource.table_name
                ));
                continue;
            };

            let expected_type = if field.is_id {
                "INTEGER".to_owned()
            } else {
                field.sql_type.clone()
            };
            if normalize_sql_type(&column.sql_type) != expected_type {
                issues.push(format!(
                    "column `{}` on `{}` has type `{}` but `{}` was expected",
                    field_name, resource.table_name, column.sql_type, expected_type
                ));
            }

            if field.is_id && !column.primary_key {
                issues.push(format!(
                    "column `{}` on `{}` is not a primary key",
                    field_name, resource.table_name
                ));
            }

            let expected_nullable = if field.is_id {
                false
            } else if matches!(
                field.generated,
                compiler::GeneratedValue::CreatedAt | compiler::GeneratedValue::UpdatedAt
            ) {
                false
            } else {
                compiler::is_optional_type(&field.ty)
            };
            if column.nullable != expected_nullable {
                let expected = if expected_nullable {
                    "nullable"
                } else {
                    "not nullable"
                };
                issues.push(format!(
                    "column `{}` on `{}` has wrong nullability; expected {}",
                    field_name, resource.table_name, expected
                ));
            }

            if matches!(
                field.generated,
                compiler::GeneratedValue::CreatedAt | compiler::GeneratedValue::UpdatedAt
            ) && !column.default_current_timestamp
            {
                issues.push(format!(
                    "column `{}` on `{}` is missing a CURRENT_TIMESTAMP default",
                    field_name, resource.table_name
                ));
            }
        }

        for index in required_index_names(resource) {
            if !live.indexes.contains(&index) {
                issues.push(format!(
                    "missing index `{}` on `{}`",
                    index, resource.table_name
                ));
            }
        }
    }

    if issues.is_empty() {
        println!(
            "{} {}",
            "Live database schema matches".green().bold(),
            input.display()
        );
        return Ok(());
    }

    let message = issues
        .into_iter()
        .map(|issue| format!("- {issue}"))
        .collect::<Vec<_>>()
        .join("\n");
    bail!("live schema drift detected:\n{message}");
}

pub async fn apply_migrations(database_url: &str, dir: &Path) -> Result<()> {
    let files = migration_files(dir)?;
    if files.is_empty() {
        println!(
            "{} {}",
            "No migration files found in".yellow().bold(),
            dir.display()
        );
        return Ok(());
    }

    let pool = connect_pool(database_url).await?;

    for file in files {
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("invalid migration file name: {}", file.display()))?
            .to_owned();

        let sql = fs::read_to_string(&file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        match apply_named_migration(&pool, database_url, &name, &sql).await? {
            ApplyResult::Skipped => println!("{} {}", "Skipping applied migration".yellow(), name),
            ApplyResult::Applied => println!("{} {}", "Applied migration".green().bold(), name),
        }
    }

    Ok(())
}

pub async fn apply_auth_migration(database_url: &str) -> Result<()> {
    let pool = connect_pool(database_url).await?;
    let backend = AuthDbBackend::from_database_url(database_url)
        .ok_or_else(|| anyhow::anyhow!("unsupported database url: {database_url}"))?;
    let sql = auth_migration_sql(backend);

    match apply_named_migration(&pool, database_url, BUILTIN_AUTH_MIGRATION, &sql).await? {
        ApplyResult::Skipped => println!(
            "{} {}",
            "Auth migration already applied".yellow().bold(),
            BUILTIN_AUTH_MIGRATION
        ),
        ApplyResult::Applied => println!(
            "{} {}",
            "Applied auth migration".green().bold(),
            BUILTIN_AUTH_MIGRATION
        ),
    }

    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.replace("\r\n", "\n").trim().to_owned()
}

fn normalize_sql_type(raw: &str) -> String {
    let value = raw.trim().to_ascii_lowercase();
    if value.contains("int") {
        "INTEGER".to_owned()
    } else if value.contains("char")
        || value.contains("text")
        || value.contains("clob")
        || value.is_empty()
    {
        "TEXT".to_owned()
    } else if value.contains("bool") || value == "tinyint" {
        "BOOLEAN".to_owned()
    } else if value.contains("real")
        || value.contains("floa")
        || value.contains("doub")
        || value.contains("dec")
        || value.contains("num")
    {
        "REAL".to_owned()
    } else {
        raw.trim().to_ascii_uppercase()
    }
}

async fn inspect_table_schema(
    pool: &AnyPool,
    backend: AuthDbBackend,
    table: &str,
) -> Result<Option<LiveTableSchema>> {
    match backend {
        AuthDbBackend::Sqlite => inspect_sqlite_table(pool, table).await,
        AuthDbBackend::Postgres => inspect_postgres_table(pool, table).await,
        AuthDbBackend::Mysql => inspect_mysql_table(pool, table).await,
    }
}

async fn inspect_sqlite_table(pool: &AnyPool, table: &str) -> Result<Option<LiveTableSchema>> {
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .context("failed to inspect sqlite tables")?;
    if exists == 0 {
        return Ok(None);
    }

    let mut schema = LiveTableSchema::default();
    let columns = sqlx::query(&format!("PRAGMA table_info({})", quote_sqlite_ident(table)))
        .fetch_all(pool)
        .await
        .context("failed to inspect sqlite columns")?;
    for row in columns {
        let name: String = row.try_get("name")?;
        let sql_type: String = row.try_get("type")?;
        let notnull: i64 = row.try_get("notnull")?;
        let pk: i64 = row.try_get("pk")?;
        let default_value: Option<String> = row.try_get("dflt_value")?;
        schema.columns.insert(
            name,
            LiveColumnSchema {
                sql_type,
                nullable: notnull == 0 && pk == 0,
                primary_key: pk != 0,
                default_current_timestamp: default_is_current_timestamp(default_value.as_deref()),
            },
        );
    }

    let indexes = sqlx::query(&format!("PRAGMA index_list({})", quote_sqlite_ident(table)))
        .fetch_all(pool)
        .await
        .context("failed to inspect sqlite indexes")?;
    for row in indexes {
        let name: String = row.try_get("name")?;
        if !name.starts_with("sqlite_autoindex") {
            schema.indexes.insert(name);
        }
    }

    Ok(Some(schema))
}

async fn inspect_postgres_table(pool: &AnyPool, table: &str) -> Result<Option<LiveTableSchema>> {
    let columns = sqlx::query(
        "SELECT column_name, data_type, is_nullable, column_default
         FROM information_schema.columns
         WHERE table_schema = current_schema() AND table_name = $1
         ORDER BY ordinal_position",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .context("failed to inspect postgres columns")?;
    if columns.is_empty() {
        return Ok(None);
    }

    let primary_keys = sqlx::query(
        "SELECT kcu.column_name
         FROM information_schema.table_constraints tc
         JOIN information_schema.key_column_usage kcu
           ON tc.constraint_name = kcu.constraint_name
          AND tc.table_schema = kcu.table_schema
         WHERE tc.constraint_type = 'PRIMARY KEY'
           AND tc.table_schema = current_schema()
           AND tc.table_name = $1",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .context("failed to inspect postgres primary keys")?;
    let primary_keys = primary_keys
        .into_iter()
        .map(|row| row.get::<String, _>("column_name"))
        .collect::<BTreeSet<_>>();

    let mut schema = LiveTableSchema::default();
    for row in columns {
        let name: String = row.try_get("column_name")?;
        let sql_type: String = row.try_get("data_type")?;
        let nullable: String = row.try_get("is_nullable")?;
        let default_value: Option<String> = row.try_get("column_default")?;
        schema.columns.insert(
            name.clone(),
            LiveColumnSchema {
                sql_type,
                nullable: nullable.eq_ignore_ascii_case("YES"),
                primary_key: primary_keys.contains(&name),
                default_current_timestamp: default_is_current_timestamp(default_value.as_deref()),
            },
        );
    }

    let indexes = sqlx::query(
        "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() AND tablename = $1",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .context("failed to inspect postgres indexes")?;
    for row in indexes {
        schema.indexes.insert(row.get::<String, _>("indexname"));
    }

    Ok(Some(schema))
}

async fn inspect_mysql_table(pool: &AnyPool, table: &str) -> Result<Option<LiveTableSchema>> {
    let columns = sqlx::query(
        "SELECT column_name, data_type, is_nullable, column_default, column_key, extra
         FROM information_schema.columns
         WHERE table_schema = DATABASE() AND table_name = ?
         ORDER BY ordinal_position",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .context("failed to inspect mysql columns")?;
    if columns.is_empty() {
        return Ok(None);
    }

    let mut schema = LiveTableSchema::default();
    for row in columns {
        let name: String = row.try_get("column_name")?;
        let sql_type: String = row.try_get("data_type")?;
        let nullable: String = row.try_get("is_nullable")?;
        let default_value: Option<String> = row.try_get("column_default")?;
        let column_key: Option<String> = row.try_get("column_key")?;
        let extra: Option<String> = row.try_get("extra")?;
        let default_current = default_is_current_timestamp(default_value.as_deref())
            || default_is_current_timestamp(extra.as_deref());

        schema.columns.insert(
            name,
            LiveColumnSchema {
                sql_type,
                nullable: nullable.eq_ignore_ascii_case("YES"),
                primary_key: column_key.as_deref() == Some("PRI"),
                default_current_timestamp: default_current,
            },
        );
    }

    let indexes = sqlx::query(
        "SELECT DISTINCT index_name
         FROM information_schema.statistics
         WHERE table_schema = DATABASE() AND table_name = ?",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .context("failed to inspect mysql indexes")?;
    for row in indexes {
        schema.indexes.insert(row.get::<String, _>("index_name"));
    }

    Ok(Some(schema))
}

fn required_index_names(resource: &compiler::ResourceSpec) -> BTreeSet<String> {
    let mut indexes = BTreeSet::new();

    for field in &resource.fields {
        if field.relation.is_some() {
            indexes.insert(format!("idx_{}_{}", resource.table_name, field.name()));
        }
    }

    indexes.extend(
        resource
            .policies
            .iter_filters()
            .map(|(_, policy)| format!("idx_{}_{}", resource.table_name, policy.field)),
    );
    indexes.extend(
        resource
            .policies
            .iter_assignments()
            .map(|(_, policy)| format!("idx_{}_{}", resource.table_name, policy.field)),
    );
    indexes
}

fn default_is_current_timestamp(value: Option<&str>) -> bool {
    value
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized.contains("current_timestamp") || normalized.contains("now()")
        })
        .unwrap_or(false)
}

fn quote_sqlite_ident(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

#[derive(Default)]
struct LiveTableSchema {
    columns: HashMap<String, LiveColumnSchema>,
    indexes: BTreeSet<String>,
}

struct LiveColumnSchema {
    sql_type: String,
    nullable: bool,
    primary_key: bool,
    default_current_timestamp: bool,
}

fn migration_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = fs::read_dir(dir)
        .with_context(|| format!("failed to read migration directory {}", dir.display()))?
        .filter_map(|entry| match entry {
            Ok(entry) => Some(entry.path()),
            Err(_) => None,
        })
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("sql"))
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

async fn ensure_migrations_table(pool: &AnyPool) -> Result<()> {
    let sql = format!(
        "CREATE TABLE IF NOT EXISTS {} (
            name TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        MIGRATIONS_TABLE
    );
    sqlx::query(&sql)
        .execute(pool)
        .await
        .context("failed to ensure migration metadata table exists")?;
    Ok(())
}

async fn migration_applied(pool: &AnyPool, database_url: &str, name: &str) -> Result<bool> {
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE name = {})",
        MIGRATIONS_TABLE,
        placeholder_for_url(database_url, 1)
    );
    let exists = sqlx::query_scalar::<_, i64>(&sql)
        .bind(name)
        .fetch_one(pool)
        .await
        .context("failed to check migration status")?;
    Ok(exists != 0)
}

async fn connect_pool(database_url: &str) -> Result<AnyPool> {
    let pool = AnyPool::connect(database_url)
        .await
        .with_context(|| format!("failed to connect to database at {database_url}"))?;
    ensure_migrations_table(&pool).await?;
    Ok(pool)
}

async fn apply_named_migration(
    pool: &AnyPool,
    database_url: &str,
    name: &str,
    sql: &str,
) -> Result<ApplyResult> {
    if migration_applied(pool, database_url, name).await? {
        return Ok(ApplyResult::Skipped);
    }

    let mut tx = pool
        .begin()
        .await
        .context("failed to start migration transaction")?;

    sqlx::raw_sql(sql)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("failed to apply migration {name}"))?;

    let insert_sql = format!(
        "INSERT INTO {} (name) VALUES ({})",
        MIGRATIONS_TABLE,
        placeholder_for_url(database_url, 1)
    );
    sqlx::query(&insert_sql)
        .bind(name)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("failed to record migration {name}"))?;

    tx.commit()
        .await
        .context("failed to commit migration transaction")?;

    Ok(ApplyResult::Applied)
}

fn placeholder_for_url(database_url: &str, index: usize) -> String {
    if database_url.starts_with("postgres:") || database_url.starts_with("postgresql:") {
        format!("${index}")
    } else {
        "?".to_owned()
    }
}

enum ApplyResult {
    Applied,
    Skipped,
}

#[cfg(test)]
mod tests {
    use sqlx::Row;

    use super::{
        BUILTIN_AUTH_MIGRATION, apply_auth_migration, apply_migrations, check_derive_migration,
        generate_derive_migration, generate_diff_migration, inspect_live_schema, migration_files,
    };

    #[test]
    fn migration_files_only_returns_sorted_sql_files() {
        let root = std::env::temp_dir().join("migration_files_only_sql");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp dir should exist");
        std::fs::write(root.join("002_second.sql"), "").expect("sql file should be written");
        std::fs::write(root.join("001_first.sql"), "").expect("sql file should be written");
        std::fs::write(root.join("notes.txt"), "").expect("non-sql file should be written");

        let files = migration_files(&root).expect("migration files should load");
        let names = files
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["001_first.sql", "002_second.sql"]);
    }

    #[tokio::test]
    async fn apply_migrations_executes_sql_and_records_state() {
        sqlx::any::install_default_drivers();

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_apply_migrations_{stamp}"));
        let database_path = root.join("app.db");
        let database_url = format!("sqlite:{}?mode=rwc", database_path.display());

        std::fs::create_dir_all(&root).expect("temp dir should exist");
        std::fs::write(
            root.join("001_init.sql"),
            "CREATE TABLE widget (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL);\n\
             CREATE INDEX idx_widget_name ON widget (name);\n",
        )
        .expect("migration should be written");

        apply_migrations(&database_url, &root)
            .await
            .expect("migrations should apply");
        apply_migrations(&database_url, &root)
            .await
            .expect("reapplying should skip existing migrations");

        let pool = sqlx::AnyPool::connect(&database_url)
            .await
            .expect("database should connect");
        let table_exists = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'widget')",
        )
        .fetch_one(&pool)
        .await
        .expect("table lookup should succeed");
        assert_ne!(table_exists, 0);

        let applied = sqlx::query("SELECT name FROM _vsr_migrations ORDER BY name")
            .fetch_all(&pool)
            .await
            .expect("migration rows should exist");
        let names = applied
            .into_iter()
            .map(|row| row.get::<String, _>("name"))
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["001_init.sql"]);
    }

    #[tokio::test]
    async fn apply_auth_migration_creates_user_table_once() {
        sqlx::any::install_default_drivers();

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_apply_auth_migration_{stamp}"));
        let database_path = root.join("app.db");
        let database_url = format!("sqlite:{}?mode=rwc", database_path.display());

        std::fs::create_dir_all(&root).expect("temp dir should exist");

        apply_auth_migration(&database_url)
            .await
            .expect("auth migration should apply");
        apply_auth_migration(&database_url)
            .await
            .expect("reapplying should skip existing auth migration");

        let pool = sqlx::AnyPool::connect(&database_url)
            .await
            .expect("database should connect");
        let user_table_exists = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'user')",
        )
        .fetch_one(&pool)
        .await
        .expect("table lookup should succeed");
        assert_ne!(user_table_exists, 0);

        let applied = sqlx::query("SELECT name FROM _vsr_migrations ORDER BY name")
            .fetch_all(&pool)
            .await
            .expect("migration rows should exist");
        let names = applied
            .into_iter()
            .map(|row| row.get::<String, _>("name"))
            .collect::<Vec<_>>();
        assert_eq!(names, vec![BUILTIN_AUTH_MIGRATION]);
    }

    #[test]
    fn generate_and_check_derive_migration_support_excluded_tables() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_generate_derive_{stamp}"));
        let src_dir = root.join("src");
        let output = root.join("0001_resources.sql");

        std::fs::create_dir_all(&src_dir).expect("temp dir should exist");
        std::fs::write(
            src_dir.join("models.rs"),
            r#"
            use very_simple_rest::prelude::*;

            #[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
            #[rest_api(table = "user", id = "id", db = "sqlite")]
            struct User {
                id: Option<i64>,
                email: String,
                password_hash: String,
                role: String,
            }

            #[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
            #[rest_api(table = "post", id = "id", db = "sqlite")]
            struct Post {
                id: Option<i64>,
                title: String,
            }
            "#,
        )
        .expect("source file should be written");

        generate_derive_migration(&src_dir, &output, false, &["user".to_owned()])
            .expect("derive migration should generate");

        let sql = std::fs::read_to_string(&output).expect("migration file should exist");
        assert!(sql.contains("CREATE TABLE post"));
        assert!(!sql.contains("CREATE TABLE user"));

        check_derive_migration(&src_dir, &output, &["user".to_owned()])
            .expect("derive migration should match");
    }

    #[test]
    fn generate_diff_migration_emits_additive_changes_only() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_generate_diff_{stamp}"));
        let previous = root.join("owned_api.eon");
        let next = root.join("owned_api_v2.eon");
        let output = root.join("0002_additive.sql");
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");

        std::fs::create_dir_all(&root).expect("temp dir should exist");
        std::fs::copy(fixtures.join("owned_api.eon"), &previous).expect("previous schema copied");
        std::fs::copy(fixtures.join("owned_api_v2.eon"), &next).expect("next schema copied");

        generate_diff_migration(&previous, &next, &output, false, &[])
            .expect("diff migration should generate");

        let sql = std::fs::read_to_string(&output).expect("diff migration should exist");
        assert!(sql.contains("ALTER TABLE owned_post ADD COLUMN subtitle TEXT;"));
        assert!(sql.contains("CREATE TABLE audit_log"));
    }

    #[tokio::test]
    async fn inspect_live_schema_accepts_matching_sqlite_schema() {
        sqlx::any::install_default_drivers();

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_inspect_live_match_{stamp}"));
        let schema = root.join("owned_api.eon");
        let migrations = root.join("migrations");
        let output = migrations.join("0001_owned.sql");
        let database_path = root.join("app.db");
        let database_url = format!("sqlite:{}?mode=rwc", database_path.display());
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");

        std::fs::create_dir_all(&migrations).expect("temp dir should exist");
        std::fs::copy(fixtures.join("owned_api.eon"), &schema).expect("schema should copy");

        super::generate_migration(&schema, &output, false).expect("migration should generate");
        apply_migrations(&database_url, &migrations)
            .await
            .expect("migration should apply");

        inspect_live_schema(&database_url, &schema, &[])
            .await
            .expect("live schema should match");
    }

    #[tokio::test]
    async fn inspect_live_schema_reports_missing_live_objects() {
        sqlx::any::install_default_drivers();

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_inspect_live_drift_{stamp}"));
        let previous = root.join("owned_api.eon");
        let next = root.join("owned_api_v2.eon");
        let migrations = root.join("migrations");
        let output = migrations.join("0001_owned.sql");
        let database_path = root.join("app.db");
        let database_url = format!("sqlite:{}?mode=rwc", database_path.display());
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");

        std::fs::create_dir_all(&migrations).expect("temp dir should exist");
        std::fs::copy(fixtures.join("owned_api.eon"), &previous).expect("schema should copy");
        std::fs::copy(fixtures.join("owned_api_v2.eon"), &next).expect("schema should copy");

        super::generate_migration(&previous, &output, false).expect("migration should generate");
        apply_migrations(&database_url, &migrations)
            .await
            .expect("migration should apply");

        let error = inspect_live_schema(&database_url, &next, &[])
            .await
            .expect_err("live schema drift should be reported");
        let message = error.to_string();
        assert!(message.contains("missing column `subtitle`"));
        assert!(message.contains("missing table `audit_log`"));
    }
}
