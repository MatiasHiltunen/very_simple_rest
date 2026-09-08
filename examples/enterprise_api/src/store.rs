//! SQLite transaction boundary: current grants, row policies, mutation and audit.
use crate::{
    Error,
    auth::{Claims, now},
    contract::{Field, Filter, Kind, Resource, Rule, Source},
};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::{
    QueryBuilder, Row, Sqlite, SqlitePool, Transaction,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow},
};
use std::{collections::BTreeMap, path::Path, time::Duration};

const INTERNAL_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS _example_schema (id INTEGER PRIMARY KEY CHECK(id=1), checksum TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS _principals (id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL CHECK(enabled IN(0,1)), version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS _grants (user_id INTEGER NOT NULL REFERENCES _principals(id), tenant_id INTEGER NOT NULL, role TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(user_id, tenant_id, role));
CREATE TABLE IF NOT EXISTS _revoked_tokens (jti TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS _versions (resource TEXT NOT NULL, record_id INTEGER NOT NULL, version INTEGER NOT NULL, PRIMARY KEY(resource,record_id));
CREATE TABLE IF NOT EXISTS _record_ids (id INTEGER PRIMARY KEY AUTOINCREMENT, resource TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS _audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, tenant_id INTEGER, user_id INTEGER, resource TEXT NOT NULL, action TEXT NOT NULL, record_id INTEGER, status INTEGER NOT NULL, request_id TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS _audit_tenant_page ON _audit(tenant_id,id);
CREATE TRIGGER IF NOT EXISTS _audit_no_update BEFORE UPDATE ON _audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS _audit_no_delete BEFORE DELETE ON _audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
";

pub async fn connect(path: &Path) -> std::result::Result<SqlitePool, Error> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(3));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(3))
        .connect_with(options)
        .await?;
    let schema = include_str!(concat!(env!("OUT_DIR"), "/schema.sql"));
    let checksum = hex::encode(Sha256::digest(
        format!("{schema}\n{INTERNAL_SCHEMA}").as_bytes(),
    ));
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::raw_sql(INTERNAL_SCHEMA).execute(&mut *tx).await?;
    let existing: Option<String> =
        sqlx::query_scalar("SELECT checksum FROM _example_schema WHERE id=1")
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(existing) = existing {
        if existing != checksum {
            return Err(
                "schema changed: explicit migration required; refusing to modify the database"
                    .into(),
            );
        }
    } else {
        sqlx::raw_sql(schema).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO _example_schema VALUES(1,?)")
            .bind(checksum)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(pool)
}

#[derive(Debug)]
pub struct Failure(pub u16, pub &'static str);
impl From<sqlx::Error> for Failure {
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db) = &error {
            if db.is_unique_violation() || db.is_foreign_key_violation() {
                return Self(409, "Resource conflict");
            }
        }
        Self(503, "Service unavailable")
    }
}
pub type Result<T> = std::result::Result<T, Failure>;

pub async fn authorize(
    tx: &mut Transaction<'_, Sqlite>,
    claims: &Claims,
    role: &str,
) -> Result<()> {
    let user = claims.user_id().ok_or(Failure(401, "Unauthorized"))?;
    let active: i64 = sqlx::query_scalar("SELECT count(*) FROM _principals WHERE id=? AND enabled=1 AND version=? AND NOT EXISTS(SELECT 1 FROM _revoked_tokens WHERE jti=?)")
        .bind(user).bind(claims.ver).bind(&claims.jti).fetch_one(&mut **tx).await?;
    if active != 1 || claims.exp <= now() {
        return Err(Failure(401, "Unauthorized"));
    }
    let granted: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM _grants WHERE user_id=? AND tenant_id=? AND role=? AND expires_at>?",
    )
    .bind(user)
    .bind(claims.tenant_id)
    .bind(role)
    .bind(now())
    .fetch_one(&mut **tx)
    .await?;
    if granted != 1 {
        return Err(Failure(403, "Forbidden"));
    }
    Ok(())
}

pub fn value(filter: &Filter, claims: &Claims) -> i64 {
    match filter.source {
        Source::Tenant => claims.tenant_id,
        Source::User => claims.user_id().unwrap_or(0),
    }
}

fn predicates(query: &mut QueryBuilder<Sqlite>, filters: &[Filter], claims: &Claims) {
    for filter in filters {
        query
            .push(" AND r.\"")
            .push(&filter.field)
            .push("\"=")
            .push_bind(value(filter, claims));
    }
}

fn select(resource: &Resource) -> QueryBuilder<Sqlite> {
    let mut query = QueryBuilder::new("SELECT r.*, v.version AS _version FROM \"");
    query
        .push(&resource.table)
        .push("\" r JOIN _versions v ON v.record_id=r.id AND v.resource=")
        .push_bind(resource.table.clone())
        .push(" WHERE 1=1");
    query
}

pub fn document(row: &SqliteRow, fields: &[Field]) -> Result<Value> {
    let mut map = Map::new();
    for f in fields {
        let value = match f.kind {
            Kind::String => json!(row.try_get::<String, _>(f.name.as_str())?),
            Kind::I64 => json!(row.try_get::<i64, _>(f.name.as_str())?),
            Kind::Bool => json!(row.try_get::<bool, _>(f.name.as_str())?),
        };
        map.insert(f.name.clone(), value);
    }
    Ok(Value::Object(map))
}

pub async fn get(
    tx: &mut Transaction<'_, Sqlite>,
    resource: &Resource,
    rule: &Rule,
    claims: &Claims,
    id: i64,
) -> Result<(Value, i64)> {
    let mut query = select(resource);
    predicates(&mut query, &rule.filters, claims);
    query.push(" AND r.id=").push_bind(id);
    let row = query
        .build()
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Failure(404, "Not found"))?;
    Ok((document(&row, &resource.fields)?, row.try_get("_version")?))
}

pub async fn list(
    tx: &mut Transaction<'_, Sqlite>,
    resource: &Resource,
    claims: &Claims,
    after: i64,
    limit: u32,
) -> Result<Value> {
    let mut query = select(resource);
    predicates(&mut query, &resource.read.filters, claims);
    query
        .push(" AND r.id>")
        .push_bind(after)
        .push(" ORDER BY r.id LIMIT ")
        .push_bind(i64::from(limit) + 1);
    let rows = query.build().fetch_all(&mut **tx).await?;
    let more = rows.len() > limit as usize;
    let mut data = Vec::new();
    for row in rows.iter().take(limit as usize) {
        data.push(document(row, &resource.fields)?);
    }
    let next = if more {
        data.last().and_then(|row| row["id"].as_i64())
    } else {
        None
    };
    Ok(json!({"data": data, "next_after": next}))
}

struct UniqueObject(BTreeMap<String, Value>);
impl<'de> Deserialize<'de> for UniqueObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = UniqueObject;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object with unique fields")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                let mut fields = BTreeMap::new();
                while let Some((name, value)) = map.next_entry::<String, Value>()? {
                    if fields.insert(name, value).is_some() {
                        return Err(de::Error::custom("duplicate field"));
                    }
                }
                Ok(UniqueObject(fields))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}

pub fn payload(
    resource: &Resource,
    body: Option<&[u8]>,
    max_chars: usize,
    creating: bool,
) -> Result<BTreeMap<String, Value>> {
    let UniqueObject(values) =
        serde_json::from_slice(body.ok_or(Failure(400, "JSON object required"))?)
            .map_err(|_| Failure(400, "JSON object required"))?;
    if values.is_empty() {
        return Err(Failure(400, "Empty mutation"));
    }
    for (name, value) in &values {
        let f = resource
            .fields
            .iter()
            .find(|f| &f.name == name)
            .ok_or(Failure(400, "Unknown field"))?;
        if resource.controlled(name) {
            return Err(Failure(400, "Server-controlled field"));
        }
        let valid = match f.kind {
            Kind::String => value.as_str().is_some_and(|s| {
                !s.trim().is_empty() && s.chars().count() <= max_chars && !s.contains('\0')
            }),
            Kind::I64 => value
                .as_i64()
                .is_some_and(|v| f.references.is_none() || v > 0),
            Kind::Bool => value.is_boolean(),
        };
        if !valid {
            return Err(Failure(400, "Invalid field value"));
        }
    }
    if creating
        && resource
            .fields
            .iter()
            .any(|f| !resource.controlled(&f.name) && !values.contains_key(&f.name))
    {
        return Err(Failure(400, "Missing field"));
    }
    Ok(values)
}

pub async fn references(
    tx: &mut Transaction<'_, Sqlite>,
    resource: &Resource,
    resources: &[Resource],
    values: &BTreeMap<String, Value>,
    claims: &Claims,
) -> Result<()> {
    for f in &resource.fields {
        if let (Some(table), Some(id)) = (&f.references, values.get(&f.name)) {
            let target = resources
                .iter()
                .find(|r| &r.table == table)
                .ok_or(Failure(503, "Invalid relation contract"))?;
            authorize(tx, claims, &target.read.role).await?;
            get(
                tx,
                target,
                &target.read,
                claims,
                id.as_i64().ok_or(Failure(400, "Invalid reference"))?,
            )
            .await?;
        }
    }
    Ok(())
}

fn bind(query: &mut QueryBuilder<Sqlite>, value: &Value) {
    match value {
        Value::String(s) => {
            query.push_bind(s.clone());
        }
        Value::Bool(b) => {
            query.push_bind(*b);
        }
        _ => {
            query.push_bind(value.as_i64().unwrap_or(0));
        }
    }
}

pub async fn create(
    tx: &mut Transaction<'_, Sqlite>,
    resource: &Resource,
    mut values: BTreeMap<String, Value>,
    claims: &Claims,
) -> Result<i64> {
    for assignment in &resource.assignments {
        values.insert(assignment.field.clone(), json!(value(assignment, claims)));
    }
    if resource
        .create
        .filters
        .iter()
        .any(|f| values.get(&f.field) != Some(&json!(value(f, claims))))
    {
        return Err(Failure(403, "Forbidden"));
    }
    // Keep allocated IDs after deletion so an old ETag can never target a new row.
    let id = sqlx::query("INSERT INTO _record_ids(resource) VALUES(?)")
        .bind(&resource.table)
        .execute(&mut **tx)
        .await?
        .last_insert_rowid();
    values.insert("id".into(), json!(id));
    let mut query = QueryBuilder::new("INSERT INTO \"");
    query.push(&resource.table).push("\" (");
    for (i, name) in values.keys().enumerate() {
        if i > 0 {
            query.push(",");
        }
        query.push("\"").push(name).push("\"");
    }
    query.push(") VALUES (");
    for (i, value) in values.values().enumerate() {
        if i > 0 {
            query.push(",");
        }
        bind(&mut query, value);
    }
    query.push(")");
    query.build().execute(&mut **tx).await?;
    sqlx::query("INSERT INTO _versions VALUES(?,?,1)")
        .bind(&resource.table)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(id)
}

pub async fn update(
    tx: &mut Transaction<'_, Sqlite>,
    resource: &Resource,
    id: i64,
    values: &BTreeMap<String, Value>,
) -> Result<()> {
    let mut query = QueryBuilder::new("UPDATE \"");
    query.push(&resource.table).push("\" SET ");
    for (i, (name, value)) in values.iter().enumerate() {
        if i > 0 {
            query.push(",");
        }
        query.push("\"").push(name).push("\"=");
        bind(&mut query, value);
    }
    query.push(" WHERE id=").push_bind(id);
    query.build().execute(&mut **tx).await?;
    sqlx::query("UPDATE _versions SET version=version+1 WHERE resource=? AND record_id=?")
        .bind(&resource.table)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn delete(
    tx: &mut Transaction<'_, Sqlite>,
    resource: &Resource,
    resources: &[Resource],
    id: i64,
) -> Result<()> {
    // Check declared RESTRICT relations under the same write lock. SQLx maps
    // SQLite's RESTRICT trigger error differently from its deferred FK error.
    for child in resources {
        for field in &child.fields {
            if field.references.as_deref() == Some(resource.table.as_str()) {
                let mut check = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM \"");
                check
                    .push(&child.table)
                    .push("\" WHERE \"")
                    .push(&field.name)
                    .push("\"=")
                    .push_bind(id)
                    .push(")");
                if check
                    .build_query_scalar::<bool>()
                    .fetch_one(&mut **tx)
                    .await?
                {
                    return Err(Failure(409, "Resource conflict"));
                }
            }
        }
    }
    let mut query = QueryBuilder::new("DELETE FROM \"");
    query
        .push(&resource.table)
        .push("\" WHERE id=")
        .push_bind(id);
    query.build().execute(&mut **tx).await?;
    sqlx::query("DELETE FROM _versions WHERE resource=? AND record_id=?")
        .bind(&resource.table)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn audit(
    tx: &mut Transaction<'_, Sqlite>,
    claims: Option<&Claims>,
    resource: &str,
    action: &str,
    id: Option<i64>,
    status: u16,
    request: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO _audit(at,tenant_id,user_id,resource,action,record_id,status,request_id) VALUES(?,?,?,?,?,?,?,?)")
        .bind(now()).bind(claims.map(|c| c.tenant_id)).bind(claims.and_then(Claims::user_id)).bind(resource).bind(action).bind(id).bind(i64::from(status)).bind(request)
        .execute(&mut **tx).await?;
    Ok(())
}
