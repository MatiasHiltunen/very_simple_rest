use std::future::Future;
use std::pin::Pin;

use chrono::{DateTime, NaiveDate, NaiveTime, SecondsFormat, Utc};
use rust_decimal::Decimal;
use sqlx::AnyPool;
use sqlx::any::{Any, AnyPoolOptions, AnyRow};
use sqlx::{FromRow, Row as _};
#[cfg(feature = "turso-local")]
use sqlx_core::HashMap;
#[cfg(feature = "turso-local")]
use sqlx_core::any::{AnyColumn, AnyTypeInfo, AnyTypeInfoKind, AnyValue, AnyValueKind};
#[cfg(feature = "turso-local")]
use sqlx_core::error::{DatabaseError as SqlxDatabaseError, ErrorKind as SqlxErrorKind};
#[cfg(feature = "turso-local")]
use sqlx_core::ext::ustr::UStr;
#[cfg(feature = "turso-local")]
use std::borrow::Cow;
#[cfg(feature = "turso-local")]
use std::fmt;
#[cfg(feature = "turso-local")]
use std::sync::Arc;
#[cfg(feature = "turso-local")]
use std::sync::Mutex as StdMutex;
#[cfg(feature = "turso-local")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "turso-local")]
use std::time::Duration;
#[cfg(feature = "turso-local")]
use tokio::sync::Notify;
use uuid::Uuid;

#[cfg(feature = "turso-local")]
use crate::database::open_turso_local_database;
use crate::database::{DatabaseConfig, DatabaseEngine};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone)]
pub enum DbPool {
    Sqlx {
        pool: AnyPool,
        backend: SqlxBackend,
    },
    #[cfg(feature = "turso-local")]
    TursoLocal(TursoLocalPool),
}

impl From<AnyPool> for DbPool {
    fn from(value: AnyPool) -> Self {
        Self::Sqlx {
            pool: value,
            backend: SqlxBackend::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlxBackend {
    Unknown,
    Sqlite,
    Postgres,
    Mysql,
}

#[cfg(feature = "turso-local")]
#[derive(Clone)]
pub struct TursoLocalPool {
    state: Arc<TursoLocalPoolState>,
}

#[cfg(feature = "turso-local")]
struct TursoLocalPoolState {
    database: turso::Database,
    idle_connections: StdMutex<Vec<turso::Connection>>,
    total_connections: AtomicUsize,
    max_connections: usize,
    waiters: Notify,
}

#[cfg(feature = "turso-local")]
struct TursoConnectionLease {
    state: Arc<TursoLocalPoolState>,
    connection: Option<turso::Connection>,
    reusable: bool,
}

#[cfg(feature = "turso-local")]
const DEFAULT_TURSO_LOCAL_MAX_CONNECTIONS: usize = 16;

#[cfg(feature = "turso-local")]
fn default_turso_local_max_connections() -> usize {
    let suggested = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get().saturating_mul(2))
        .unwrap_or(DEFAULT_TURSO_LOCAL_MAX_CONNECTIONS);
    suggested.clamp(4, DEFAULT_TURSO_LOCAL_MAX_CONNECTIONS)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DbQueryResult {
    rows_affected: u64,
    last_insert_rowid: Option<i64>,
}

impl DbQueryResult {
    pub fn rows_affected(&self) -> u64 {
        self.rows_affected
    }

    pub fn last_insert_rowid(&self) -> Option<i64> {
        self.last_insert_rowid
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum DbValue {
    Null,
    Bool(bool),
    Integer(i64),
    Double(f64),
    Text(String),
    Blob(Vec<u8>),
}

pub trait IntoDbValue {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error>;
}

macro_rules! impl_integer_value {
    ($($ty:ty),* $(,)?) => {
        $(
            impl IntoDbValue for $ty {
                fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
                    Ok(DbValue::Integer(self as i64))
                }
            }
        )*
    };
}

impl_integer_value!(i8, i16, i32, i64, u8, u16, u32);

impl IntoDbValue for u64 {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        let value = i64::try_from(self)
            .map_err(|_| sqlx::Error::Encode("u64 is too large to fit in i64".into()))?;
        Ok(DbValue::Integer(value))
    }
}

impl IntoDbValue for bool {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        Ok(DbValue::Bool(self))
    }
}

impl IntoDbValue for f32 {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        Ok(DbValue::Double(self as f64))
    }
}

impl IntoDbValue for f64 {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        Ok(DbValue::Double(self))
    }
}

impl IntoDbValue for String {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        Ok(DbValue::Text(self))
    }
}

impl IntoDbValue for &str {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        Ok(DbValue::Text(self.to_owned()))
    }
}

impl IntoDbValue for Vec<u8> {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        Ok(DbValue::Blob(self))
    }
}

impl IntoDbValue for &[u8] {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        Ok(DbValue::Blob(self.to_vec()))
    }
}

impl IntoDbValue for DateTime<Utc> {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        Ok(DbValue::Text(
            self.to_rfc3339_opts(SecondsFormat::Micros, false),
        ))
    }
}

impl IntoDbValue for NaiveDate {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        Ok(DbValue::Text(self.format("%Y-%m-%d").to_string()))
    }
}

impl IntoDbValue for NaiveTime {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        Ok(DbValue::Text(self.format("%H:%M:%S.%6f").to_string()))
    }
}

impl IntoDbValue for Uuid {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        Ok(DbValue::Text(self.as_hyphenated().to_string()))
    }
}

impl IntoDbValue for Decimal {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        Ok(DbValue::Text(self.normalize().to_string()))
    }
}

impl<T> IntoDbValue for Option<T>
where
    T: IntoDbValue,
{
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        match self {
            Some(value) => value.into_db_value(),
            None => Ok(DbValue::Null),
        }
    }
}

impl<T> IntoDbValue for &T
where
    T: IntoDbValue + Clone,
{
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        self.clone().into_db_value()
    }
}

pub async fn connect(database_url: &str) -> Result<DbPool, sqlx::Error> {
    match parse_turso_local_url(database_url)? {
        #[cfg(feature = "turso-local")]
        Some(config) => connect_turso_local(&config).await,
        #[cfg(not(feature = "turso-local"))]
        Some(_) => Err(sqlx::Error::Configuration(
            "turso-local URLs require the `turso-local` crate feature".into(),
        )),
        None => {
            sqlx::any::install_default_drivers();
            let backend = sqlx_backend_from_database_url(database_url)?;
            AnyPoolOptions::new()
                .connect(database_url)
                .await
                .map(|pool| DbPool::Sqlx { pool, backend })
        }
    }
}

pub async fn connect_with_config(
    database_url: &str,
    config: &DatabaseConfig,
) -> Result<DbPool, sqlx::Error> {
    match &config.engine {
        DatabaseEngine::Sqlx => connect(database_url).await,
        DatabaseEngine::TursoLocal(engine) => {
            #[cfg(feature = "turso-local")]
            {
                connect_turso_local(engine).await
            }
            #[cfg(not(feature = "turso-local"))]
            {
                let _ = engine;
                Err(sqlx::Error::Configuration(
                    "database.engine = TursoLocal requires the `turso-local` crate feature".into(),
                ))
            }
        }
    }
}

impl DbPool {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        connect(database_url).await
    }

    pub async fn connect_with_config(
        database_url: &str,
        config: &DatabaseConfig,
    ) -> Result<Self, sqlx::Error> {
        connect_with_config(database_url, config).await
    }

    pub async fn begin(&self) -> Result<DbTransaction, sqlx::Error> {
        match self {
            Self::Sqlx { pool, backend } => {
                let tx = pool.begin().await?;
                Ok(DbTransaction {
                    inner: DbTransactionInner::Sqlx {
                        tx: tokio::sync::Mutex::new(Some(tx)),
                        backend: *backend,
                    },
                })
            }
            #[cfg(feature = "turso-local")]
            Self::TursoLocal(pool) => {
                let mut conn = pool.acquire().await?;
                if let Err(error) = conn.connection().execute("BEGIN", ()).await {
                    conn.discard();
                    return Err(map_turso_error(error));
                }
                Ok(DbTransaction {
                    inner: DbTransactionInner::TursoLocal(tokio::sync::Mutex::new(
                        TursoTransactionState {
                            connection: Some(conn),
                            finished: false,
                        },
                    )),
                })
            }
        }
    }

    pub async fn execute_batch(&self, sql: &str) -> Result<(), sqlx::Error> {
        match self {
            Self::Sqlx { pool, .. } => {
                sqlx::raw_sql(sql).execute(pool).await?;
                Ok(())
            }
            #[cfg(feature = "turso-local")]
            Self::TursoLocal(pool) => pool.execute_batch(sql).await,
        }
    }
}

pub struct DbTransaction {
    inner: DbTransactionInner,
}

enum DbTransactionInner {
    Sqlx {
        tx: tokio::sync::Mutex<Option<sqlx::Transaction<'static, Any>>>,
        backend: SqlxBackend,
    },
    #[cfg(feature = "turso-local")]
    TursoLocal(tokio::sync::Mutex<TursoTransactionState>),
}

#[cfg(feature = "turso-local")]
struct TursoTransactionState {
    connection: Option<TursoConnectionLease>,
    finished: bool,
}

#[cfg(feature = "turso-local")]
impl TursoTransactionState {
    fn connection(&self) -> Result<&turso::Connection, sqlx::Error> {
        self.connection
            .as_ref()
            .map(TursoConnectionLease::connection)
            .ok_or_else(|| sqlx::Error::Protocol("transaction already finished".to_owned()))
    }
}

#[cfg(feature = "turso-local")]
impl Drop for TursoTransactionState {
    fn drop(&mut self) {
        if !self.finished
            && let Some(connection) = self.connection.as_mut()
        {
            connection.discard();
        }
    }
}

impl DbTransaction {
    pub async fn commit(&self) -> Result<(), sqlx::Error> {
        match &self.inner {
            DbTransactionInner::Sqlx { tx, .. } => {
                let mut guard = tx.lock().await;
                let tx = guard.take().ok_or_else(|| {
                    sqlx::Error::Protocol("transaction already finished".to_owned())
                })?;
                tx.commit().await
            }
            #[cfg(feature = "turso-local")]
            DbTransactionInner::TursoLocal(tx) => {
                let mut guard = tx.lock().await;
                if guard.finished {
                    return Err(sqlx::Error::Protocol(
                        "transaction already finished".to_owned(),
                    ));
                }
                let mut connection = guard.connection.take().ok_or_else(|| {
                    sqlx::Error::Protocol("transaction already finished".to_owned())
                })?;
                if let Err(error) = connection.connection().execute("COMMIT", ()).await {
                    connection.discard();
                    return Err(map_turso_error(error));
                }
                guard.finished = true;
                drop(guard);
                drop(connection);
                Ok(())
            }
        }
    }

    pub async fn rollback(&self) -> Result<(), sqlx::Error> {
        match &self.inner {
            DbTransactionInner::Sqlx { tx, .. } => {
                let mut guard = tx.lock().await;
                let tx = guard.take().ok_or_else(|| {
                    sqlx::Error::Protocol("transaction already finished".to_owned())
                })?;
                tx.rollback().await
            }
            #[cfg(feature = "turso-local")]
            DbTransactionInner::TursoLocal(tx) => {
                let mut guard = tx.lock().await;
                if guard.finished {
                    return Err(sqlx::Error::Protocol(
                        "transaction already finished".to_owned(),
                    ));
                }
                let mut connection = guard.connection.take().ok_or_else(|| {
                    sqlx::Error::Protocol("transaction already finished".to_owned())
                })?;
                if let Err(error) = connection.connection().execute("ROLLBACK", ()).await {
                    connection.discard();
                    return Err(map_turso_error(error));
                }
                guard.finished = true;
                drop(guard);
                drop(connection);
                Ok(())
            }
        }
    }

    pub async fn execute_batch(&self, sql: &str) -> Result<(), sqlx::Error> {
        match &self.inner {
            DbTransactionInner::Sqlx { tx, .. } => {
                let mut guard = tx.lock().await;
                let tx = guard.as_mut().ok_or_else(|| {
                    sqlx::Error::Protocol("transaction already finished".to_owned())
                })?;
                let conn: &mut sqlx::AnyConnection = tx.as_mut();
                sqlx::raw_sql(sql).execute(conn).await?;
                Ok(())
            }
            #[cfg(feature = "turso-local")]
            DbTransactionInner::TursoLocal(tx) => {
                let guard = tx.lock().await;
                if guard.finished {
                    return Err(sqlx::Error::Protocol(
                        "transaction already finished".to_owned(),
                    ));
                }
                guard
                    .connection()?
                    .execute_batch(sql)
                    .await
                    .map_err(map_turso_error)
            }
        }
    }
}

pub fn query(sql: &str) -> Query<'_> {
    Query {
        sql,
        binds: Vec::new(),
        bind_error: None,
    }
}

pub fn query_as<DB, T>(sql: &str) -> QueryAs<'_, T> {
    let _ = std::marker::PhantomData::<DB>;
    QueryAs {
        inner: query(sql),
        _marker: std::marker::PhantomData,
    }
}

pub fn query_scalar<DB, T>(sql: &str) -> QueryScalar<'_, T> {
    let _ = std::marker::PhantomData::<DB>;
    QueryScalar {
        inner: query(sql),
        _marker: std::marker::PhantomData,
    }
}

pub struct Query<'q> {
    sql: &'q str,
    binds: Vec<DbValue>,
    bind_error: Option<sqlx::Error>,
}

impl<'q> Query<'q> {
    pub fn bind<T>(mut self, value: T) -> Self
    where
        T: IntoDbValue,
    {
        if self.bind_error.is_none() {
            match value.into_db_value() {
                Ok(value) => self.binds.push(value),
                Err(error) => self.bind_error = Some(error),
            }
        }
        self
    }

    pub async fn execute<E>(self, executor: &E) -> Result<DbQueryResult, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
    {
        self.into_bound()?.execute(executor).await
    }

    pub async fn fetch_optional<E>(self, executor: &E) -> Result<Option<AnyRow>, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
    {
        self.into_bound()?.fetch_optional(executor).await
    }

    pub async fn fetch_one<E>(self, executor: &E) -> Result<AnyRow, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
    {
        self.into_bound()?.fetch_one(executor).await
    }

    pub async fn fetch_all<E>(self, executor: &E) -> Result<Vec<AnyRow>, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
    {
        self.into_bound()?.fetch_all(executor).await
    }

    fn into_bound(self) -> Result<BoundQuery<'q>, sqlx::Error> {
        if let Some(error) = self.bind_error {
            Err(error)
        } else {
            Ok(BoundQuery {
                sql: self.sql,
                binds: self.binds,
            })
        }
    }
}

pub struct QueryAs<'q, T> {
    inner: Query<'q>,
    _marker: std::marker::PhantomData<T>,
}

impl<'q, T> QueryAs<'q, T> {
    pub fn bind<U>(mut self, value: U) -> Self
    where
        U: IntoDbValue,
    {
        self.inner = self.inner.bind(value);
        self
    }

    pub async fn fetch_optional<E>(self, executor: &E) -> Result<Option<T>, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
        for<'r> T: FromRow<'r, AnyRow>,
    {
        match self.inner.fetch_optional(executor).await? {
            Some(row) => T::from_row(&row).map(Some),
            None => Ok(None),
        }
    }

    pub async fn fetch_one<E>(self, executor: &E) -> Result<T, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
        for<'r> T: FromRow<'r, AnyRow>,
    {
        let row = self.inner.fetch_one(executor).await?;
        T::from_row(&row)
    }

    pub async fn fetch_all<E>(self, executor: &E) -> Result<Vec<T>, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
        for<'r> T: FromRow<'r, AnyRow>,
    {
        let rows = self.inner.fetch_all(executor).await?;
        rows.into_iter().map(|row| T::from_row(&row)).collect()
    }
}

pub struct QueryScalar<'q, T> {
    inner: Query<'q>,
    _marker: std::marker::PhantomData<T>,
}

impl<'q, T> QueryScalar<'q, T> {
    pub fn bind<U>(mut self, value: U) -> Self
    where
        U: IntoDbValue,
    {
        self.inner = self.inner.bind(value);
        self
    }

    pub async fn fetch_optional<E>(self, executor: &E) -> Result<Option<T>, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
        for<'r> T: sqlx::Decode<'r, Any> + sqlx::Type<Any>,
    {
        match self.inner.fetch_optional(executor).await? {
            Some(row) => row.try_get(0).map(Some),
            None => Ok(None),
        }
    }

    pub async fn fetch_one<E>(self, executor: &E) -> Result<T, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
        for<'r> T: sqlx::Decode<'r, Any> + sqlx::Type<Any>,
    {
        let row = self.inner.fetch_one(executor).await?;
        row.try_get(0)
    }

    pub async fn fetch_all<E>(self, executor: &E) -> Result<Vec<T>, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
        for<'r> T: sqlx::Decode<'r, Any> + sqlx::Type<Any>,
    {
        let rows = self.inner.fetch_all(executor).await?;
        rows.into_iter().map(|row| row.try_get(0)).collect()
    }
}

pub struct BoundQuery<'q> {
    sql: &'q str,
    binds: Vec<DbValue>,
}

impl<'q> BoundQuery<'q> {
    async fn execute<E>(self, executor: &E) -> Result<DbQueryResult, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
    {
        executor.execute_bound(self).await
    }

    async fn fetch_optional<E>(self, executor: &E) -> Result<Option<AnyRow>, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
    {
        let mut rows = executor.fetch_all_bound(self).await?;
        Ok(rows.drain(..).next())
    }

    async fn fetch_one<E>(self, executor: &E) -> Result<AnyRow, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
    {
        self.fetch_optional(executor)
            .await?
            .ok_or(sqlx::Error::RowNotFound)
    }

    async fn fetch_all<E>(self, executor: &E) -> Result<Vec<AnyRow>, sqlx::Error>
    where
        E: DbExecutor + ?Sized,
    {
        executor.fetch_all_bound(self).await
    }
}

pub trait DbExecutor {
    fn execute_bound<'a>(
        &'a self,
        query: BoundQuery<'a>,
    ) -> BoxFuture<'a, Result<DbQueryResult, sqlx::Error>>;
    fn fetch_all_bound<'a>(
        &'a self,
        query: BoundQuery<'a>,
    ) -> BoxFuture<'a, Result<Vec<AnyRow>, sqlx::Error>>;
}

impl DbExecutor for DbPool {
    fn execute_bound<'a>(
        &'a self,
        query: BoundQuery<'a>,
    ) -> BoxFuture<'a, Result<DbQueryResult, sqlx::Error>> {
        Box::pin(async move {
            match self {
                Self::Sqlx { pool, backend } => execute_sqlx(pool, *backend, query).await,
                #[cfg(feature = "turso-local")]
                Self::TursoLocal(pool) => pool.execute(query).await,
            }
        })
    }

    fn fetch_all_bound<'a>(
        &'a self,
        query: BoundQuery<'a>,
    ) -> BoxFuture<'a, Result<Vec<AnyRow>, sqlx::Error>> {
        Box::pin(async move {
            match self {
                Self::Sqlx { pool, backend } => fetch_all_sqlx(pool, *backend, query).await,
                #[cfg(feature = "turso-local")]
                Self::TursoLocal(pool) => pool.fetch_all(query).await,
            }
        })
    }
}

impl DbExecutor for DbTransaction {
    fn execute_bound<'a>(
        &'a self,
        query: BoundQuery<'a>,
    ) -> BoxFuture<'a, Result<DbQueryResult, sqlx::Error>> {
        Box::pin(async move {
            match &self.inner {
                DbTransactionInner::Sqlx { tx, backend } => {
                    let mut guard = tx.lock().await;
                    let tx = guard.as_mut().ok_or_else(|| {
                        sqlx::Error::Protocol("transaction already finished".to_owned())
                    })?;
                    execute_sqlx_tx(tx, *backend, query).await
                }
                #[cfg(feature = "turso-local")]
                DbTransactionInner::TursoLocal(tx) => {
                    let guard = tx.lock().await;
                    if guard.finished {
                        return Err(sqlx::Error::Protocol(
                            "transaction already finished".to_owned(),
                        ));
                    }
                    execute_turso_connection(guard.connection()?, query).await
                }
            }
        })
    }

    fn fetch_all_bound<'a>(
        &'a self,
        query: BoundQuery<'a>,
    ) -> BoxFuture<'a, Result<Vec<AnyRow>, sqlx::Error>> {
        Box::pin(async move {
            match &self.inner {
                DbTransactionInner::Sqlx { tx, backend } => {
                    let mut guard = tx.lock().await;
                    let tx = guard.as_mut().ok_or_else(|| {
                        sqlx::Error::Protocol("transaction already finished".to_owned())
                    })?;
                    fetch_all_sqlx_tx(tx, *backend, query).await
                }
                #[cfg(feature = "turso-local")]
                DbTransactionInner::TursoLocal(tx) => {
                    let guard = tx.lock().await;
                    if guard.finished {
                        return Err(sqlx::Error::Protocol(
                            "transaction already finished".to_owned(),
                        ));
                    }
                    fetch_all_turso_connection(guard.connection()?, query).await
                }
            }
        })
    }
}

async fn execute_sqlx<E>(
    executor: E,
    backend: SqlxBackend,
    query: BoundQuery<'_>,
) -> Result<DbQueryResult, sqlx::Error>
where
    E: sqlx::Executor<'static, Database = Any>,
{
    let sql = rewrite_sql_placeholders(query.sql, backend);
    let result = apply_sqlx_binds(sqlx::query(&sql), query.binds)
        .execute(executor)
        .await?;
    Ok(DbQueryResult {
        rows_affected: result.rows_affected(),
        last_insert_rowid: result.last_insert_id(),
    })
}

async fn fetch_all_sqlx<E>(
    executor: E,
    backend: SqlxBackend,
    query: BoundQuery<'_>,
) -> Result<Vec<AnyRow>, sqlx::Error>
where
    E: sqlx::Executor<'static, Database = Any>,
{
    let sql = rewrite_sql_placeholders(query.sql, backend);
    apply_sqlx_binds(sqlx::query(&sql), query.binds)
        .fetch_all(executor)
        .await
}

async fn execute_sqlx_tx(
    tx: &mut sqlx::Transaction<'static, Any>,
    backend: SqlxBackend,
    query: BoundQuery<'_>,
) -> Result<DbQueryResult, sqlx::Error> {
    let sql = rewrite_sql_placeholders(query.sql, backend);
    let result = apply_sqlx_binds(sqlx::query(&sql), query.binds)
        .execute(tx.as_mut())
        .await?;
    Ok(DbQueryResult {
        rows_affected: result.rows_affected(),
        last_insert_rowid: result.last_insert_id(),
    })
}

async fn fetch_all_sqlx_tx(
    tx: &mut sqlx::Transaction<'static, Any>,
    backend: SqlxBackend,
    query: BoundQuery<'_>,
) -> Result<Vec<AnyRow>, sqlx::Error> {
    let sql = rewrite_sql_placeholders(query.sql, backend);
    apply_sqlx_binds(sqlx::query(&sql), query.binds)
        .fetch_all(tx.as_mut())
        .await
}

fn sqlx_backend_from_database_url(database_url: &str) -> Result<SqlxBackend, sqlx::Error> {
    if database_url.starts_with("postgres:") || database_url.starts_with("postgresql:") {
        Ok(SqlxBackend::Postgres)
    } else if database_url.starts_with("mysql:") || database_url.starts_with("mariadb:") {
        Ok(SqlxBackend::Mysql)
    } else if database_url.starts_with("sqlite:") {
        Ok(SqlxBackend::Sqlite)
    } else {
        Err(sqlx::Error::Configuration(
            format!("unsupported database URL scheme in `{database_url}`").into(),
        ))
    }
}

fn rewrite_sql_placeholders(sql: &str, backend: SqlxBackend) -> String {
    if backend != SqlxBackend::Postgres || !sql.contains('?') {
        return sql.to_owned();
    }

    let mut rewritten = String::with_capacity(sql.len() + 8);
    let mut placeholder_index = 1usize;
    let mut chars = sql.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double_quote => {
                rewritten.push(ch);
                if in_single_quote && chars.peek() == Some(&'\'') {
                    rewritten.push(chars.next().expect("peeked quote should exist"));
                } else {
                    in_single_quote = !in_single_quote;
                }
            }
            '"' if !in_single_quote => {
                rewritten.push(ch);
                if in_double_quote && chars.peek() == Some(&'"') {
                    rewritten.push(chars.next().expect("peeked quote should exist"));
                } else {
                    in_double_quote = !in_double_quote;
                }
            }
            '?' if !in_single_quote && !in_double_quote => {
                rewritten.push('$');
                rewritten.push_str(&placeholder_index.to_string());
                placeholder_index += 1;
            }
            _ => rewritten.push(ch),
        }
    }

    rewritten
}

fn apply_sqlx_binds<'q>(
    mut query: sqlx::query::Query<'q, Any, sqlx::any::AnyArguments<'q>>,
    binds: Vec<DbValue>,
) -> sqlx::query::Query<'q, Any, sqlx::any::AnyArguments<'q>> {
    for bind in binds {
        query = match bind {
            DbValue::Null => query.bind::<Option<String>>(None),
            DbValue::Bool(value) => query.bind(value),
            DbValue::Integer(value) => query.bind(value),
            DbValue::Double(value) => query.bind(value),
            DbValue::Text(value) => query.bind(value),
            DbValue::Blob(value) => query.bind(value),
        };
    }
    query
}

#[cfg(feature = "turso-local")]
async fn connect_turso_local(
    engine: &crate::database::TursoLocalConfig,
) -> Result<DbPool, sqlx::Error> {
    let database = open_turso_local_database(engine)
        .await
        .map_err(sqlx::Error::Io)?;
    Ok(DbPool::TursoLocal(TursoLocalPool {
        state: Arc::new(TursoLocalPoolState {
            database,
            idle_connections: StdMutex::new(Vec::new()),
            total_connections: AtomicUsize::new(0),
            max_connections: default_turso_local_max_connections(),
            waiters: Notify::new(),
        }),
    }))
}

#[cfg(feature = "turso-local")]
impl TursoLocalPool {
    async fn acquire(&self) -> Result<TursoConnectionLease, sqlx::Error> {
        self.state.acquire().await
    }

    async fn execute(&self, query: BoundQuery<'_>) -> Result<DbQueryResult, sqlx::Error> {
        let conn = self.acquire().await?;
        execute_turso_connection(conn.connection(), query).await
    }

    async fn fetch_all(&self, query: BoundQuery<'_>) -> Result<Vec<AnyRow>, sqlx::Error> {
        let conn = self.acquire().await?;
        fetch_all_turso_connection(conn.connection(), query).await
    }

    async fn execute_batch(&self, sql: &str) -> Result<(), sqlx::Error> {
        let conn = self.acquire().await?;
        conn.connection()
            .execute_batch(sql)
            .await
            .map_err(map_turso_error)
    }

    #[cfg(test)]
    fn stats(&self) -> TursoLocalPoolStats {
        self.state.stats()
    }
}

#[cfg(feature = "turso-local")]
impl TursoLocalPoolState {
    async fn acquire(self: &Arc<Self>) -> Result<TursoConnectionLease, sqlx::Error> {
        loop {
            let notified = self.waiters.notified();

            if let Some(connection) = self.take_idle_connection() {
                return Ok(TursoConnectionLease::new(self.clone(), connection));
            }

            if self.try_reserve_connection_slot() {
                match self.open_connection().await {
                    Ok(connection) => {
                        return Ok(TursoConnectionLease::new(self.clone(), connection));
                    }
                    Err(error) => {
                        self.release_connection_slot();
                        return Err(error);
                    }
                }
            }

            notified.await;
        }
    }

    async fn open_connection(&self) -> Result<turso::Connection, sqlx::Error> {
        let conn = self.database.connect().map_err(map_turso_error)?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(map_turso_error)?;
        conn.execute("PRAGMA foreign_keys = ON", ())
            .await
            .map_err(map_turso_error)?;
        Ok(conn)
    }

    fn take_idle_connection(&self) -> Option<turso::Connection> {
        self.idle_connections
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop()
    }

    fn recycle_connection(&self, connection: turso::Connection) {
        self.idle_connections
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(connection);
        self.waiters.notify_one();
    }

    fn try_reserve_connection_slot(&self) -> bool {
        loop {
            let current = self.total_connections.load(Ordering::Acquire);
            if current >= self.max_connections {
                return false;
            }
            if self
                .total_connections
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn release_connection_slot(&self) {
        self.total_connections.fetch_sub(1, Ordering::AcqRel);
        self.waiters.notify_one();
    }

    #[cfg(test)]
    fn stats(&self) -> TursoLocalPoolStats {
        let idle_connections = self
            .idle_connections
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len();
        TursoLocalPoolStats {
            idle_connections,
            total_connections: self.total_connections.load(Ordering::Acquire),
            max_connections: self.max_connections,
        }
    }
}

#[cfg(feature = "turso-local")]
impl TursoConnectionLease {
    fn new(state: Arc<TursoLocalPoolState>, connection: turso::Connection) -> Self {
        Self {
            state,
            connection: Some(connection),
            reusable: true,
        }
    }

    fn connection(&self) -> &turso::Connection {
        self.connection
            .as_ref()
            .expect("lease should hold an active connection")
    }

    fn discard(&mut self) {
        self.reusable = false;
    }
}

#[cfg(feature = "turso-local")]
impl Drop for TursoConnectionLease {
    fn drop(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };

        if self.reusable {
            self.state.recycle_connection(connection);
        } else {
            drop(connection);
            self.state.release_connection_slot();
        }
    }
}

#[cfg(all(feature = "turso-local", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TursoLocalPoolStats {
    idle_connections: usize,
    total_connections: usize,
    max_connections: usize,
}

#[cfg(feature = "turso-local")]
async fn execute_turso_connection(
    conn: &turso::Connection,
    query: BoundQuery<'_>,
) -> Result<DbQueryResult, sqlx::Error> {
    let params = turso::params_from_iter(query.binds.into_iter().map(db_value_to_turso_value));
    let rows_affected = conn
        .execute(query.sql, params)
        .await
        .map_err(map_turso_error)?;
    Ok(DbQueryResult {
        rows_affected,
        last_insert_rowid: Some(conn.last_insert_rowid()),
    })
}

#[cfg(feature = "turso-local")]
async fn fetch_all_turso_connection(
    conn: &turso::Connection,
    query: BoundQuery<'_>,
) -> Result<Vec<AnyRow>, sqlx::Error> {
    let mut stmt = conn.prepare(query.sql).await.map_err(map_turso_error)?;
    let columns = stmt.columns();
    let column_names = Arc::new(
        columns
            .iter()
            .enumerate()
            .map(|(index, column)| (UStr::new(column.name()), index))
            .collect::<HashMap<UStr, usize>>(),
    );
    let params = turso::params_from_iter(query.binds.into_iter().map(db_value_to_turso_value));
    let mut rows = stmt.query(params).await.map_err(map_turso_error)?;
    let mut out = Vec::new();

    while let Some(row) = rows.next().await.map_err(map_turso_error)? {
        out.push(any_row_from_turso_row(&columns, row, column_names.clone()));
    }

    Ok(out)
}

#[cfg(feature = "turso-local")]
fn db_value_to_turso_value(value: DbValue) -> turso::Value {
    match value {
        DbValue::Null => turso::Value::Null,
        DbValue::Bool(value) => turso::Value::Integer(i64::from(value)),
        DbValue::Integer(value) => turso::Value::Integer(value),
        DbValue::Double(value) => turso::Value::Real(value),
        DbValue::Text(value) => turso::Value::Text(value),
        DbValue::Blob(value) => turso::Value::Blob(value),
    }
}

#[cfg(feature = "turso-local")]
fn any_row_from_turso_row(
    columns: &[turso::Column],
    row: turso::Row,
    column_names: Arc<HashMap<UStr, usize>>,
) -> AnyRow {
    let mut any_columns = Vec::with_capacity(columns.len());
    let mut values = Vec::with_capacity(columns.len());

    for (index, column) in columns.iter().enumerate() {
        let decl_kind = decl_type_kind(column.decl_type());
        let value = row.get_value(index).unwrap_or(turso::Value::Null);
        let value_kind = any_value_kind_from_turso_value(value, decl_kind);
        any_columns.push(AnyColumn {
            ordinal: index,
            name: UStr::new(column.name()),
            type_info: AnyTypeInfo {
                kind: type_info_kind_for_value_kind(&value_kind),
            },
        });
        values.push(AnyValue {
            kind: value_kind.to_owned(),
        });
    }

    AnyRow {
        column_names,
        columns: any_columns,
        values,
    }
}

#[cfg(feature = "turso-local")]
fn decl_type_kind(decl_type: Option<&str>) -> Option<AnyTypeInfoKind> {
    let decl_type = decl_type?.to_ascii_uppercase();
    if decl_type.contains("BOOL") {
        Some(AnyTypeInfoKind::Bool)
    } else if decl_type.contains("INT") {
        Some(AnyTypeInfoKind::BigInt)
    } else if decl_type.contains("REAL") || decl_type.contains("FLOA") || decl_type.contains("DOUB")
    {
        Some(AnyTypeInfoKind::Double)
    } else if decl_type.contains("BLOB") {
        Some(AnyTypeInfoKind::Blob)
    } else if decl_type.contains("CHAR") || decl_type.contains("CLOB") || decl_type.contains("TEXT")
    {
        Some(AnyTypeInfoKind::Text)
    } else {
        None
    }
}

#[cfg(feature = "turso-local")]
fn any_value_kind_from_turso_value(
    value: turso::Value,
    decl_kind: Option<AnyTypeInfoKind>,
) -> AnyValueKind<'static> {
    match value {
        turso::Value::Null => AnyValueKind::Null(decl_kind.unwrap_or(AnyTypeInfoKind::Null)),
        turso::Value::Integer(value) => match decl_kind {
            Some(AnyTypeInfoKind::Bool) => AnyValueKind::Bool(value != 0),
            _ => AnyValueKind::BigInt(value),
        },
        turso::Value::Real(value) => AnyValueKind::Double(value),
        turso::Value::Text(value) => AnyValueKind::Text(value.into()),
        turso::Value::Blob(value) => AnyValueKind::Blob(value.into()),
    }
}

#[cfg(feature = "turso-local")]
fn type_info_kind_for_value_kind(value: &AnyValueKind<'_>) -> AnyTypeInfoKind {
    match value {
        AnyValueKind::Null(kind) => *kind,
        AnyValueKind::Bool(_) => AnyTypeInfoKind::Bool,
        AnyValueKind::SmallInt(_) => AnyTypeInfoKind::SmallInt,
        AnyValueKind::Integer(_) => AnyTypeInfoKind::Integer,
        AnyValueKind::BigInt(_) => AnyTypeInfoKind::BigInt,
        AnyValueKind::Real(_) => AnyTypeInfoKind::Real,
        AnyValueKind::Double(_) => AnyTypeInfoKind::Double,
        AnyValueKind::Text(_) => AnyTypeInfoKind::Text,
        AnyValueKind::Blob(_) => AnyTypeInfoKind::Blob,
        _ => AnyTypeInfoKind::Null,
    }
}

#[cfg(feature = "turso-local")]
#[derive(Debug)]
struct TursoDatabaseError {
    message: String,
    kind: SqlxErrorKind,
    transient_in_connect_phase: bool,
}

#[cfg(feature = "turso-local")]
impl TursoDatabaseError {
    fn new(message: String, kind: SqlxErrorKind) -> Self {
        Self {
            message,
            kind,
            transient_in_connect_phase: false,
        }
    }

    fn transient(mut self) -> Self {
        self.transient_in_connect_phase = true;
        self
    }
}

#[cfg(feature = "turso-local")]
impl fmt::Display for TursoDatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

#[cfg(feature = "turso-local")]
impl std::error::Error for TursoDatabaseError {}

#[cfg(feature = "turso-local")]
impl SqlxDatabaseError for TursoDatabaseError {
    fn message(&self) -> &str {
        &self.message
    }

    fn code(&self) -> Option<Cow<'_, str>> {
        None
    }

    fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self
    }

    fn is_transient_in_connect_phase(&self) -> bool {
        self.transient_in_connect_phase
    }

    fn kind(&self) -> SqlxErrorKind {
        match self.kind {
            SqlxErrorKind::UniqueViolation => SqlxErrorKind::UniqueViolation,
            SqlxErrorKind::ForeignKeyViolation => SqlxErrorKind::ForeignKeyViolation,
            SqlxErrorKind::NotNullViolation => SqlxErrorKind::NotNullViolation,
            SqlxErrorKind::CheckViolation => SqlxErrorKind::CheckViolation,
            SqlxErrorKind::Other => SqlxErrorKind::Other,
            _ => SqlxErrorKind::Other,
        }
    }
}

#[cfg(feature = "turso-local")]
fn sqlite_error_kind_from_message(message: &str) -> SqlxErrorKind {
    let normalized = message.to_ascii_lowercase();
    if normalized.contains("unique constraint failed")
        || normalized.contains("is not unique")
        || normalized.contains("duplicate")
        || normalized.contains("primary key")
    {
        SqlxErrorKind::UniqueViolation
    } else if normalized.contains("foreign key constraint failed")
        || normalized.contains("foreign key mismatch")
    {
        SqlxErrorKind::ForeignKeyViolation
    } else if normalized.contains("not null constraint failed")
        || normalized.contains("cannot be null")
    {
        SqlxErrorKind::NotNullViolation
    } else if normalized.contains("check constraint failed") {
        SqlxErrorKind::CheckViolation
    } else {
        SqlxErrorKind::Other
    }
}

#[cfg(feature = "turso-local")]
fn map_turso_error(error: turso::Error) -> sqlx::Error {
    match error {
        turso::Error::ToSqlConversionFailure(error) => sqlx::Error::Encode(error),
        turso::Error::QueryReturnedNoRows => sqlx::Error::RowNotFound,
        turso::Error::ConversionFailure(message) => sqlx::Error::Protocol(message),
        turso::Error::Busy(message) => sqlx::Error::database(
            TursoDatabaseError::new(message, SqlxErrorKind::Other).transient(),
        ),
        turso::Error::BusySnapshot(message) => sqlx::Error::database(
            TursoDatabaseError::new(message, SqlxErrorKind::Other).transient(),
        ),
        turso::Error::Interrupt(message) => {
            sqlx::Error::database(TursoDatabaseError::new(message, SqlxErrorKind::Other))
        }
        turso::Error::Error(message) => sqlx::Error::database(TursoDatabaseError::new(
            message.clone(),
            sqlite_error_kind_from_message(&message),
        )),
        turso::Error::Misuse(message) => sqlx::Error::Protocol(message),
        turso::Error::Constraint(message) => sqlx::Error::database(TursoDatabaseError::new(
            message.clone(),
            sqlite_error_kind_from_message(&message),
        )),
        turso::Error::Readonly(message)
        | turso::Error::DatabaseFull(message)
        | turso::Error::NotAdb(message)
        | turso::Error::Corrupt(message) => {
            sqlx::Error::database(TursoDatabaseError::new(message, SqlxErrorKind::Other))
        }
        turso::Error::IoError(kind, operation) => {
            sqlx::Error::Io(std::io::Error::new(kind, operation))
        }
    }
}

#[cfg(feature = "turso-local")]
fn parse_turso_local_url(
    url: &str,
) -> Result<Option<crate::database::TursoLocalConfig>, sqlx::Error> {
    if url.starts_with("turso://") || url.starts_with("turso-local://") {
        let parsed = url.parse::<url::Url>().map_err(sqlx::Error::config)?;
        let path = if parsed.path() == "/:memory:" || parsed.path() == ":memory:" {
            ":memory:".to_owned()
        } else {
            let host = parsed.host_str().unwrap_or_default();
            let path = parsed.path();
            match (host.is_empty(), path.is_empty() || path == "/") {
                (false, true) => host.to_owned(),
                (false, false) => format!("{host}{path}"),
                (true, false) => path.to_owned(),
                (true, true) => {
                    return Err(sqlx::Error::Configuration(
                        format!("turso-local URL must include a database path: {url}").into(),
                    ));
                }
            }
        };
        let encryption_key_env = parsed
            .query_pairs()
            .find_map(|(key, value)| (key == "encryption_key_env").then(|| value.into_owned()));
        return Ok(Some(crate::database::TursoLocalConfig {
            path,
            encryption_key_env,
        }));
    }

    if let Some(path) = url.strip_prefix("turso-local:") {
        return Ok(Some(crate::database::TursoLocalConfig {
            path: path.to_owned(),
            encryption_key_env: None,
        }));
    }

    if let Some(path) = url.strip_prefix("turso:") {
        return Ok(Some(crate::database::TursoLocalConfig {
            path: path.to_owned(),
            encryption_key_env: None,
        }));
    }

    Ok(None)
}

#[cfg(not(feature = "turso-local"))]
fn parse_turso_local_url(
    _url: &str,
) -> Result<Option<crate::database::TursoLocalConfig>, sqlx::Error> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "turso-local")]
    use super::{DbPool, connect_with_config, query, query_scalar};
    use super::{SqlxBackend, rewrite_sql_placeholders};
    #[cfg(feature = "turso-local")]
    use crate::database::{DatabaseConfig, DatabaseEngine, TursoLocalConfig};
    #[cfg(feature = "turso-local")]
    use std::sync::{Mutex, OnceLock};

    #[cfg(feature = "turso-local")]
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn rewrite_sql_placeholders_translates_question_marks_for_postgres_only() {
        let sql = "SELECT * FROM \"user\" WHERE email = ? AND note = '?' AND id = ?";
        assert_eq!(
            rewrite_sql_placeholders(sql, SqlxBackend::Postgres),
            "SELECT * FROM \"user\" WHERE email = $1 AND note = '?' AND id = $2"
        );
        assert_eq!(rewrite_sql_placeholders(sql, SqlxBackend::Mysql), sql);
        assert_eq!(rewrite_sql_placeholders(sql, SqlxBackend::Sqlite), sql);
    }

    #[cfg(feature = "turso-local")]
    #[test]
    fn parse_turso_local_url_preserves_relative_and_absolute_paths() {
        let relative = super::parse_turso_local_url(
            "turso-local://var/data/app.db?encryption_key_env=TURSO_KEY",
        )
        .expect("relative url should parse")
        .expect("relative url should resolve to config");
        assert_eq!(relative.path, "var/data/app.db");
        assert_eq!(relative.encryption_key_env.as_deref(), Some("TURSO_KEY"));

        let absolute = super::parse_turso_local_url("turso-local:///tmp/app.db")
            .expect("absolute url should parse")
            .expect("absolute url should resolve to config");
        assert_eq!(absolute.path, "/tmp/app.db");
    }

    #[cfg(feature = "turso-local")]
    #[test]
    fn map_turso_error_preserves_database_error_kind() {
        let error = super::map_turso_error(turso::Error::Constraint(
            "UNIQUE constraint failed: user.email".to_owned(),
        ));
        let database_error = error
            .as_database_error()
            .expect("constraint should map to database error");
        assert!(database_error.is_unique_violation());
        assert_eq!(
            database_error.message(),
            "UNIQUE constraint failed: user.email"
        );
    }

    #[cfg(feature = "turso-local")]
    #[test]
    fn map_turso_error_surfaces_missing_table_as_database_error() {
        let error = super::map_turso_error(turso::Error::Error("no such table: user".to_owned()));
        let database_error = error
            .as_database_error()
            .expect("sqlite runtime error should map to database error");
        assert!(database_error.message().contains("no such table: user"));
    }

    #[cfg(feature = "turso-local")]
    #[actix_web::test]
    async fn turso_local_pool_executes_queries_and_transactions() {
        let path = std::env::temp_dir().join(format!(
            "vsr_turso_local_{}_{}.db",
            std::process::id(),
            std::thread::current().name().unwrap_or("main")
        ));
        let config = DatabaseConfig {
            engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: path.to_string_lossy().into_owned(),
                encryption_key_env: None,
            }),
            resilience: None,
        };

        let pool = connect_with_config("sqlite:ignored.db?mode=rwc", &config)
            .await
            .expect("turso local pool should connect");
        assert!(matches!(pool, DbPool::TursoLocal(_)));

        query("CREATE TABLE note (id INTEGER PRIMARY KEY, title TEXT NOT NULL)")
            .execute(&pool)
            .await
            .expect("create table should succeed");

        let tx = pool.begin().await.expect("transaction should start");
        query("INSERT INTO note (title) VALUES (?)")
            .bind("hello")
            .execute(&tx)
            .await
            .expect("insert should succeed");
        tx.commit().await.expect("commit should succeed");

        let count: i64 = query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM note")
            .fetch_one(&pool)
            .await
            .expect("count query should succeed");
        assert_eq!(count, 1);
        let pooled = match &pool {
            DbPool::TursoLocal(pool) => pool,
            _ => unreachable!("expected turso local pool"),
        };
        let stats = pooled.stats();
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.idle_connections, 1);

        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "turso-local")]
    #[actix_web::test]
    async fn turso_local_pool_reuses_single_connection_for_sequential_queries() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("vsr_turso_local_reuse_{stamp}.db"));
        let config = DatabaseConfig {
            engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: path.to_string_lossy().into_owned(),
                encryption_key_env: None,
            }),
            resilience: None,
        };

        let pool = connect_with_config("sqlite:ignored.db?mode=rwc", &config)
            .await
            .expect("turso local pool should connect");
        let pooled = match &pool {
            DbPool::TursoLocal(pool) => pool,
            _ => unreachable!("expected turso local pool"),
        };

        query("CREATE TABLE note (id INTEGER PRIMARY KEY, title TEXT NOT NULL)")
            .execute(&pool)
            .await
            .expect("create table should succeed");
        query("INSERT INTO note (title) VALUES (?)")
            .bind("one")
            .execute(&pool)
            .await
            .expect("first insert should succeed");
        query("INSERT INTO note (title) VALUES (?)")
            .bind("two")
            .execute(&pool)
            .await
            .expect("second insert should succeed");

        let count: i64 = query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM note")
            .fetch_one(&pool)
            .await
            .expect("count query should succeed");
        assert_eq!(count, 2);

        let stats = pooled.stats();
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.idle_connections, 1);

        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "turso-local")]
    #[actix_web::test]
    async fn turso_local_pool_discards_dropped_transaction_connections() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("vsr_turso_local_dropped_tx_{stamp}.db"));
        let config = DatabaseConfig {
            engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: path.to_string_lossy().into_owned(),
                encryption_key_env: None,
            }),
            resilience: None,
        };

        let pool = connect_with_config("sqlite:ignored.db?mode=rwc", &config)
            .await
            .expect("turso local pool should connect");
        let pooled = match &pool {
            DbPool::TursoLocal(pool) => pool,
            _ => unreachable!("expected turso local pool"),
        };

        query("CREATE TABLE note (id INTEGER PRIMARY KEY, title TEXT NOT NULL)")
            .execute(&pool)
            .await
            .expect("create table should succeed");
        assert_eq!(pooled.stats().total_connections, 1);

        let tx = pool.begin().await.expect("transaction should start");
        query("INSERT INTO note (title) VALUES (?)")
            .bind("discarded")
            .execute(&tx)
            .await
            .expect("transaction insert should succeed");
        drop(tx);

        let stats = pooled.stats();
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.idle_connections, 0);

        query("INSERT INTO note (title) VALUES (?)")
            .bind("committed")
            .execute(&pool)
            .await
            .expect("standalone insert should succeed");

        let count: i64 = query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM note")
            .fetch_one(&pool)
            .await
            .expect("count query should succeed");
        assert_eq!(count, 1);

        let stats = pooled.stats();
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.idle_connections, 1);

        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "turso-local")]
    #[actix_web::test]
    async fn turso_local_encrypted_pool_executes_queries_and_reopens() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("vsr_turso_local_encrypted_{stamp}.db"));
        let env_var = format!("VSR_TURSO_LOCAL_KEY_{stamp}");
        let key = "b1bbfda4f589dc9daaf004fe21111e00dc00c98237102f5c7002a5669fc76327";

        unsafe {
            std::env::set_var(&env_var, key);
        }

        let config = DatabaseConfig {
            engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: path.to_string_lossy().into_owned(),
                encryption_key_env: Some(env_var.clone()),
            }),
            resilience: None,
        };

        let pool = connect_with_config("sqlite:ignored.db?mode=rwc", &config)
            .await
            .expect("encrypted turso local pool should connect");
        assert!(matches!(pool, DbPool::TursoLocal(_)));

        query("CREATE TABLE secret_note (id INTEGER PRIMARY KEY, title TEXT NOT NULL)")
            .execute(&pool)
            .await
            .expect("create table should succeed");
        query("INSERT INTO secret_note (title) VALUES (?)")
            .bind("classified")
            .execute(&pool)
            .await
            .expect("insert should succeed");

        let reopened = connect_with_config("sqlite:ignored.db?mode=rwc", &config)
            .await
            .expect("encrypted turso local pool should reconnect");
        let count: i64 = query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM secret_note")
            .fetch_one(&reopened)
            .await
            .expect("count query should succeed");
        assert_eq!(count, 1);

        unsafe {
            std::env::remove_var(&env_var);
        }
        let _ = std::fs::remove_file(path);
    }
}
