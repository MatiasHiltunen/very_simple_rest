use anyhow::{Context, Result, bail};
use colored::Colorize;
use rest_macro_core::auth::{AuthDbBackend, auth_management_migration_sql, auth_migration_sql};
use rest_macro_core::compiler;
use rest_macro_core::db::{DbPool, query, query_scalar};
use sqlx::Row;
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
};

use crate::commands::db::connect_database;
use crate::commands::schema::{load_filtered_derive_service, load_schema_service};

const MIGRATIONS_TABLE: &str = "_vsr_migrations";
const BUILTIN_AUTH_MIGRATION: &str = "0000_builtin_auth.sql";
const BUILTIN_AUTH_MANAGEMENT_MIGRATION: &str = "0001_builtin_auth_management.sql";

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
    let sql = format!(
        "{}\n{}",
        auth_migration_sql(backend),
        auth_management_migration_sql(backend)
    );

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
    config_path: Option<&Path>,
    input: &Path,
    exclude_tables: &[String],
) -> Result<()> {
    let service = load_schema_service(input, exclude_tables)?;
    let pool = connect_pool(database_url, config_path).await?;
    let backend = detect_runtime_backend(&pool).await?;

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
            ) && !generated_default_matches_field(field, column.default_expression.as_deref())
            {
                issues.push(format!(
                    "column `{}` on `{}` is missing the expected generated temporal default",
                    field_name, resource.table_name
                ));
            }

            if let Some(relation) = &field.relation {
                let Some(live_relation) = live.relations.get(&field_name) else {
                    issues.push(format!(
                        "missing foreign key for column `{}` on `{}`",
                        field_name, resource.table_name
                    ));
                    continue;
                };

                if live_relation.references_table != relation.references_table
                    || live_relation.references_field != relation.references_field
                {
                    issues.push(format!(
                        "foreign key `{}` on `{}` points to `{}.{}` but `{}.{}` was expected",
                        field_name,
                        resource.table_name,
                        live_relation.references_table,
                        live_relation.references_field,
                        relation.references_table,
                        relation.references_field
                    ));
                }

                if !relation_delete_action_matches(
                    relation.on_delete,
                    live_relation.on_delete.as_deref(),
                ) {
                    let actual = live_relation.on_delete.as_deref().unwrap_or("DEFAULT");
                    let expected = relation
                        .on_delete
                        .map(|action| action.sql())
                        .unwrap_or("DEFAULT");
                    issues.push(format!(
                        "foreign key `{}` on `{}` has ON DELETE `{}` but `{}` was expected",
                        field_name, resource.table_name, actual, expected
                    ));
                }
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

pub async fn apply_migrations(
    database_url: &str,
    config_path: Option<&Path>,
    dir: &Path,
) -> Result<()> {
    let files = migration_files(dir)?;
    if files.is_empty() {
        println!(
            "{} {}",
            "No migration files found in".yellow().bold(),
            dir.display()
        );
        return Ok(());
    }

    let pool = connect_pool(database_url, config_path).await?;
    let backend = detect_runtime_backend(&pool).await?;

    for file in files {
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("invalid migration file name: {}", file.display()))?
            .to_owned();

        let sql = fs::read_to_string(&file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        match apply_named_migration(&pool, backend, &name, &sql).await? {
            ApplyResult::Skipped => println!("{} {}", "Skipping applied migration".yellow(), name),
            ApplyResult::Applied => println!("{} {}", "Applied migration".green().bold(), name),
        }
    }

    Ok(())
}

pub async fn apply_auth_migration(database_url: &str, config_path: Option<&Path>) -> Result<()> {
    let pool = connect_pool(database_url, config_path).await?;
    let backend = detect_runtime_backend(&pool).await?;
    for (name, sql) in [
        (BUILTIN_AUTH_MIGRATION, auth_migration_sql(backend)),
        (
            BUILTIN_AUTH_MANAGEMENT_MIGRATION,
            auth_management_migration_sql(backend),
        ),
    ] {
        match apply_named_migration(&pool, backend, name, &sql).await? {
            ApplyResult::Skipped => println!(
                "{} {}",
                "Auth migration already applied".yellow().bold(),
                name
            ),
            ApplyResult::Applied => {
                println!("{} {}", "Applied auth migration".green().bold(), name)
            }
        }
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
    pool: &DbPool,
    backend: AuthDbBackend,
    table: &str,
) -> Result<Option<LiveTableSchema>> {
    match backend {
        AuthDbBackend::Sqlite => inspect_sqlite_table(pool, table).await,
        AuthDbBackend::Postgres => inspect_postgres_table(pool, table).await,
        AuthDbBackend::Mysql => inspect_mysql_table(pool, table).await,
    }
}

async fn inspect_sqlite_table(pool: &DbPool, table: &str) -> Result<Option<LiveTableSchema>> {
    let exists = query_scalar::<sqlx::Any, i64>(
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
    let columns = query(&format!("PRAGMA table_info({})", quote_sqlite_ident(table)))
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
                default_expression: default_value,
            },
        );
    }

    let indexes = query(&format!("PRAGMA index_list({})", quote_sqlite_ident(table)))
        .fetch_all(pool)
        .await
        .context("failed to inspect sqlite indexes")?;
    for row in indexes {
        let name: String = row.try_get("name")?;
        if !name.starts_with("sqlite_autoindex") {
            schema.indexes.insert(name);
        }
    }

    let foreign_keys = query(&format!(
        "PRAGMA foreign_key_list({})",
        quote_sqlite_ident(table)
    ))
    .fetch_all(pool)
    .await
    .context("failed to inspect sqlite foreign keys")?;
    for row in foreign_keys {
        let seq: i64 = row.try_get("seq")?;
        if seq != 0 {
            continue;
        }

        let column: String = row.try_get("from")?;
        schema.relations.insert(
            column,
            LiveRelationSchema {
                references_table: row.try_get("table")?,
                references_field: row.try_get("to")?,
                on_delete: normalize_live_delete_rule(Some(
                    &row.try_get::<String, _>("on_delete")?,
                )),
            },
        );
    }

    Ok(Some(schema))
}

async fn inspect_postgres_table(pool: &DbPool, table: &str) -> Result<Option<LiveTableSchema>> {
    let columns = query(
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

    let primary_keys = query(
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
                default_expression: default_value,
            },
        );
    }

    let indexes = query(
        "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() AND tablename = $1",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .context("failed to inspect postgres indexes")?;
    for row in indexes {
        schema.indexes.insert(row.get::<String, _>("indexname"));
    }

    let relations = query(
        "SELECT
             child_attr.attname AS column_name,
             parent_table.relname AS referenced_table,
             parent_attr.attname AS referenced_column,
             CASE constraint.confdeltype
                 WHEN 'a' THEN 'NO ACTION'
                 WHEN 'r' THEN 'RESTRICT'
                 WHEN 'c' THEN 'CASCADE'
                 WHEN 'n' THEN 'SET NULL'
                 WHEN 'd' THEN 'SET DEFAULT'
             END AS delete_rule
         FROM pg_constraint constraint
         JOIN pg_class child_table
           ON child_table.oid = constraint.conrelid
         JOIN pg_namespace child_namespace
           ON child_namespace.oid = child_table.relnamespace
         JOIN pg_class parent_table
           ON parent_table.oid = constraint.confrelid
         JOIN LATERAL unnest(constraint.conkey) WITH ORDINALITY AS child_cols(attnum, ord)
           ON true
         JOIN LATERAL unnest(constraint.confkey) WITH ORDINALITY AS parent_cols(attnum, ord)
           ON parent_cols.ord = child_cols.ord
         JOIN pg_attribute child_attr
           ON child_attr.attrelid = child_table.oid AND child_attr.attnum = child_cols.attnum
         JOIN pg_attribute parent_attr
           ON parent_attr.attrelid = parent_table.oid AND parent_attr.attnum = parent_cols.attnum
         WHERE constraint.contype = 'f'
           AND child_namespace.nspname = current_schema()
           AND child_table.relname = $1",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .context("failed to inspect postgres foreign keys")?;
    for row in relations {
        let column: String = row.try_get("column_name")?;
        schema.relations.insert(
            column,
            LiveRelationSchema {
                references_table: row.try_get("referenced_table")?,
                references_field: row.try_get("referenced_column")?,
                on_delete: normalize_live_delete_rule(
                    row.try_get::<Option<String>, _>("delete_rule")?.as_deref(),
                ),
            },
        );
    }

    Ok(Some(schema))
}

async fn inspect_mysql_table(pool: &DbPool, table: &str) -> Result<Option<LiveTableSchema>> {
    let columns = query(
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
        let default_expression = match (default_value, extra) {
            (Some(default_value), Some(extra)) => Some(format!("{default_value} {extra}")),
            (Some(default_value), None) => Some(default_value),
            (None, Some(extra)) => Some(extra),
            (None, None) => None,
        };

        schema.columns.insert(
            name,
            LiveColumnSchema {
                sql_type,
                nullable: nullable.eq_ignore_ascii_case("YES"),
                primary_key: column_key.as_deref() == Some("PRI"),
                default_expression,
            },
        );
    }

    let indexes = query(
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

    let relations = query(
        "SELECT
             kcu.column_name,
             kcu.referenced_table_name,
             kcu.referenced_column_name,
             rc.delete_rule
         FROM information_schema.key_column_usage kcu
         JOIN information_schema.referential_constraints rc
           ON rc.constraint_schema = kcu.constraint_schema
          AND rc.constraint_name = kcu.constraint_name
         WHERE kcu.table_schema = DATABASE()
           AND kcu.table_name = ?
           AND kcu.referenced_table_name IS NOT NULL",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .context("failed to inspect mysql foreign keys")?;
    for row in relations {
        let column: String = row.try_get("column_name")?;
        schema.relations.insert(
            column,
            LiveRelationSchema {
                references_table: row.try_get("referenced_table_name")?,
                references_field: row.try_get("referenced_column_name")?,
                on_delete: normalize_live_delete_rule(
                    row.try_get::<Option<String>, _>("delete_rule")?.as_deref(),
                ),
            },
        );
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
            normalized.contains("current_timestamp")
                || normalized.contains("now()")
                || normalized.contains("utc_timestamp")
                || (normalized.contains("strftime(") && normalized.contains("'now'"))
        })
        .unwrap_or(false)
}

fn default_is_current_date(value: Option<&str>) -> bool {
    value
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized.contains("current_date")
                || normalized.contains("utc_date")
                || normalized.contains("curdate()")
                || normalized.contains("date('now')")
        })
        .unwrap_or(false)
}

fn default_is_current_time(value: Option<&str>) -> bool {
    value
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized.contains("current_time")
                || normalized.contains("curtime()")
                || normalized.contains("utc_timestamp")
                || (normalized.contains("strftime(") && normalized.contains("%h:%m:%f"))
                || normalized.contains("to_char(")
        })
        .unwrap_or(false)
}

fn generated_default_matches_field(field: &compiler::FieldSpec, value: Option<&str>) -> bool {
    match compiler::temporal_scalar_kind(&field.ty) {
        Some(compiler::GeneratedTemporalKind::DateTime) => default_is_current_timestamp(value),
        Some(compiler::GeneratedTemporalKind::Date) => default_is_current_date(value),
        Some(compiler::GeneratedTemporalKind::Time) => default_is_current_time(value),
        None => default_is_current_timestamp(value),
    }
}

fn normalize_live_delete_rule(value: Option<&str>) -> Option<String> {
    value.and_then(|value| {
        let normalized = value.trim().replace('_', " ").to_ascii_uppercase();
        if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        }
    })
}

fn relation_delete_action_matches(
    expected: Option<compiler::ReferentialAction>,
    actual: Option<&str>,
) -> bool {
    match expected {
        Some(expected) => actual == Some(expected.sql()),
        None => matches!(actual, None | Some("NO ACTION") | Some("RESTRICT")),
    }
}

fn quote_sqlite_ident(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

#[derive(Default)]
struct LiveTableSchema {
    columns: HashMap<String, LiveColumnSchema>,
    indexes: BTreeSet<String>,
    relations: HashMap<String, LiveRelationSchema>,
}

struct LiveColumnSchema {
    sql_type: String,
    nullable: bool,
    primary_key: bool,
    default_expression: Option<String>,
}

struct LiveRelationSchema {
    references_table: String,
    references_field: String,
    on_delete: Option<String>,
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

async fn ensure_migrations_table(pool: &DbPool) -> Result<()> {
    let sql = format!(
        "CREATE TABLE IF NOT EXISTS {} (
            name TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        MIGRATIONS_TABLE
    );
    query(&sql)
        .execute(pool)
        .await
        .context("failed to ensure migration metadata table exists")?;
    Ok(())
}

async fn migration_applied(pool: &DbPool, backend: AuthDbBackend, name: &str) -> Result<bool> {
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE name = {})",
        MIGRATIONS_TABLE,
        placeholder_for_backend(backend, 1)
    );
    let exists = query_scalar::<sqlx::Any, i64>(&sql)
        .bind(name)
        .fetch_one(pool)
        .await
        .context("failed to check migration status")?;
    Ok(exists != 0)
}

async fn connect_pool(database_url: &str, config_path: Option<&Path>) -> Result<DbPool> {
    let pool = connect_database(database_url, config_path)
        .await
        .with_context(|| format!("failed to connect to database at {database_url}"))?;
    ensure_migrations_table(&pool).await?;
    Ok(pool)
}

async fn detect_runtime_backend(pool: &DbPool) -> Result<AuthDbBackend> {
    match pool {
        DbPool::Sqlx(pool) => {
            let connection = pool.acquire().await?;
            let backend_name = connection.backend_name().to_ascii_lowercase();
            if backend_name.contains("postgres") {
                Ok(AuthDbBackend::Postgres)
            } else if backend_name.contains("mysql") {
                Ok(AuthDbBackend::Mysql)
            } else if backend_name.contains("sqlite") {
                Ok(AuthDbBackend::Sqlite)
            } else {
                bail!("unsupported live database backend `{backend_name}`")
            }
        }
        DbPool::TursoLocal(_) => Ok(AuthDbBackend::Sqlite),
    }
}

async fn apply_named_migration(
    pool: &DbPool,
    backend: AuthDbBackend,
    name: &str,
    sql: &str,
) -> Result<ApplyResult> {
    if migration_applied(pool, backend, name).await? {
        return Ok(ApplyResult::Skipped);
    }

    let tx = pool
        .begin()
        .await
        .context("failed to start migration transaction")?;

    tx.execute_batch(sql)
        .await
        .with_context(|| format!("failed to apply migration {name}"))?;

    let insert_sql = format!(
        "INSERT INTO {} (name) VALUES ({})",
        MIGRATIONS_TABLE,
        placeholder_for_backend(backend, 1)
    );
    query(&insert_sql)
        .bind(name)
        .execute(&tx)
        .await
        .with_context(|| format!("failed to record migration {name}"))?;

    tx.commit()
        .await
        .context("failed to commit migration transaction")?;

    Ok(ApplyResult::Applied)
}

fn placeholder_for_backend(backend: AuthDbBackend, index: usize) -> String {
    match backend {
        AuthDbBackend::Postgres => format!("${index}"),
        AuthDbBackend::Sqlite | AuthDbBackend::Mysql => "?".to_owned(),
    }
}

enum ApplyResult {
    Applied,
    Skipped,
}

#[cfg(test)]
mod tests {
    use crate::commands::db::{connect_database, database_url_from_service_config};
    use rest_macro_core::db::query_scalar;
    use sqlx::Row;
    use std::sync::{Mutex, OnceLock};

    use super::{
        BUILTIN_AUTH_MANAGEMENT_MIGRATION, BUILTIN_AUTH_MIGRATION, apply_auth_migration,
        apply_migrations, check_derive_migration, generate_derive_migration,
        generate_diff_migration, inspect_live_schema, migration_files,
    };

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

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

        apply_migrations(&database_url, None, &root)
            .await
            .expect("migrations should apply");
        apply_migrations(&database_url, None, &root)
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

        apply_auth_migration(&database_url, None)
            .await
            .expect("auth migration should apply");
        apply_auth_migration(&database_url, None)
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
        assert_eq!(
            names,
            vec![BUILTIN_AUTH_MIGRATION, BUILTIN_AUTH_MANAGEMENT_MIGRATION]
        );
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
        apply_migrations(&database_url, None, &migrations)
            .await
            .expect("migration should apply");

        inspect_live_schema(&database_url, None, &schema, &[])
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
        apply_migrations(&database_url, None, &migrations)
            .await
            .expect("migration should apply");

        let error = inspect_live_schema(&database_url, None, &next, &[])
            .await
            .expect_err("live schema drift should be reported");
        let message = error.to_string();
        assert!(message.contains("missing column `subtitle`"));
        assert!(message.contains("missing table `audit_log`"));
    }

    #[tokio::test]
    async fn inspect_live_schema_accepts_matching_sqlite_relation_actions() {
        sqlx::any::install_default_drivers();

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_inspect_live_rel_match_{stamp}"));
        let schema = root.join("cascade_api.eon");
        let migrations = root.join("migrations");
        let output = migrations.join("0001_cascade.sql");
        let database_path = root.join("app.db");
        let database_url = format!("sqlite:{}?mode=rwc", database_path.display());
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");

        std::fs::create_dir_all(&migrations).expect("temp dir should exist");
        std::fs::copy(fixtures.join("cascade_api.eon"), &schema).expect("schema should copy");

        super::generate_migration(&schema, &output, false).expect("migration should generate");
        apply_migrations(&database_url, None, &migrations)
            .await
            .expect("migration should apply");

        inspect_live_schema(&database_url, None, &schema, &[])
            .await
            .expect("live schema should match");
    }

    #[tokio::test]
    async fn inspect_live_schema_reports_relation_delete_drift() {
        sqlx::any::install_default_drivers();

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_inspect_live_rel_drift_{stamp}"));
        let schema = root.join("cascade_api.eon");
        let database_path = root.join("app.db");
        let database_url = format!("sqlite:{}?mode=rwc", database_path.display());
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");

        std::fs::create_dir_all(&root).expect("temp dir should exist");
        std::fs::copy(fixtures.join("cascade_api.eon"), &schema).expect("schema should copy");

        let pool = sqlx::AnyPool::connect(&database_url)
            .await
            .expect("database should connect");
        sqlx::raw_sql(
            r#"
            CREATE TABLE parent (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL
            );

            CREATE TABLE child (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parent_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                FOREIGN KEY (parent_id) REFERENCES parent(id)
            );
            "#,
        )
        .execute(&pool)
        .await
        .expect("schema should apply");

        let error = inspect_live_schema(&database_url, None, &schema, &[])
            .await
            .expect_err("live relation drift should be reported");
        let message = error.to_string();
        assert!(message.contains("foreign key `parent_id` on `child` has ON DELETE `NO ACTION`"));
        assert!(message.contains("`CASCADE` was expected"));
    }

    #[tokio::test]
    async fn apply_migrations_uses_turso_local_config_path() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_apply_turso_local_{stamp}"));
        let schema = root.join("turso_local_api.eon");
        let migrations = root.join("migrations");
        let output = migrations.join("0001_turso_local.sql");
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");

        std::fs::create_dir_all(&migrations).expect("temp dir should exist");
        std::fs::copy(fixtures.join("turso_local_api.eon"), &schema).expect("schema should copy");

        super::generate_migration(&schema, &output, false).expect("migration should generate");
        let database_url =
            database_url_from_service_config(&schema).expect("service database url should resolve");

        apply_migrations(&database_url, Some(&schema), &migrations)
            .await
            .expect("migration should apply through the Turso local adapter");

        let pool = connect_database(&database_url, Some(&schema))
            .await
            .expect("database should connect through the Turso local adapter");
        let table_exists = query_scalar::<sqlx::Any, i64>(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'note')",
        )
        .fetch_one(&pool)
        .await
        .expect("table lookup should succeed");
        assert_ne!(table_exists, 0);
    }

    #[tokio::test]
    async fn apply_migrations_uses_encrypted_turso_local_config_path() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vsr_apply_turso_local_encrypted_{stamp}"));
        let schema = root.join("turso_local_encrypted_api.eon");
        let migrations = root.join("migrations");
        let output = migrations.join("0001_turso_local_encrypted.sql");
        let database_path = root.join("var/data/turso_local_encrypted.db");
        let env_var = format!("VSR_TURSO_ENCRYPTED_KEY_{stamp}");
        let key = "d1bbfda4f589dc9daaf004fe21111e00dc00c98237102f5c7002a5669fc76327";

        std::fs::create_dir_all(&migrations).expect("temp dir should exist");
        if let Some(parent) = database_path.parent() {
            std::fs::create_dir_all(parent).expect("database dir should exist");
        }
        unsafe {
            std::env::set_var(&env_var, key);
        }
        std::fs::write(
            &schema,
            format!(
                r#"module: "turso_local_encrypted_runtime"
database: {{
    engine: {{
        kind: TursoLocal
        path: "{}"
        encryption_key_env: "{}"
    }}
}}
resources: [
    {{
        name: "SecretNote"
        fields: [
            {{ name: "id", type: I64, id: true }}
            {{ name: "title", type: String }}
        ]
    }}
]
"#,
                database_path.display(),
                env_var,
            ),
        )
        .expect("schema should be written");

        super::generate_migration(&schema, &output, false).expect("migration should generate");
        let database_url =
            database_url_from_service_config(&schema).expect("service database url should resolve");

        apply_auth_migration(&database_url, Some(&schema))
            .await
            .expect("auth migration should apply through the encrypted Turso local adapter");
        apply_migrations(&database_url, Some(&schema), &migrations)
            .await
            .expect("migration should apply through the encrypted Turso local adapter");

        let pool = connect_database(&database_url, Some(&schema))
            .await
            .expect("database should connect through the encrypted Turso local adapter");
        let user_table_exists = query_scalar::<sqlx::Any, i64>(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'user')",
        )
        .fetch_one(&pool)
        .await
        .expect("user table lookup should succeed");
        let secret_note_exists = query_scalar::<sqlx::Any, i64>(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'secret_note')",
        )
        .fetch_one(&pool)
        .await
        .expect("resource table lookup should succeed");
        assert_ne!(user_table_exists, 0);
        assert_ne!(secret_note_exists, 0);

        unsafe {
            std::env::remove_var(&env_var);
        }
    }
}
