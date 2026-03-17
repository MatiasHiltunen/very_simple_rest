use std::future::Future;
use std::pin::Pin;

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
use std::time::Duration;

#[cfg(feature = "turso-local")]
use crate::database::open_turso_local_database;
use crate::database::{DatabaseConfig, DatabaseEngine};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone)]
pub enum DbPool {
    Sqlx(AnyPool),
    #[cfg(feature = "turso-local")]
    TursoLocal(TursoLocalPool),
}

impl From<AnyPool> for DbPool {
    fn from(value: AnyPool) -> Self {
        Self::Sqlx(value)
    }
}

#[cfg(feature = "turso-local")]
#[derive(Clone)]
pub struct TursoLocalPool {
    database: turso::Database,
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
            AnyPoolOptions::new()
                .connect(database_url)
                .await
                .map(DbPool::Sqlx)
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
            Self::Sqlx(pool) => {
                let tx = pool.begin().await?;
                Ok(DbTransaction {
                    inner: DbTransactionInner::Sqlx(tokio::sync::Mutex::new(Some(tx))),
                })
            }
            #[cfg(feature = "turso-local")]
            Self::TursoLocal(pool) => {
                let conn = pool.connect().await?;
                conn.execute("BEGIN", ()).await.map_err(map_turso_error)?;
                Ok(DbTransaction {
                    inner: DbTransactionInner::TursoLocal(tokio::sync::Mutex::new(
                        TursoTransactionState {
                            connection: conn,
                            finished: false,
                        },
                    )),
                })
            }
        }
    }

    pub async fn execute_batch(&self, sql: &str) -> Result<(), sqlx::Error> {
        match self {
            Self::Sqlx(pool) => {
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
    Sqlx(tokio::sync::Mutex<Option<sqlx::Transaction<'static, Any>>>),
    #[cfg(feature = "turso-local")]
    TursoLocal(tokio::sync::Mutex<TursoTransactionState>),
}

#[cfg(feature = "turso-local")]
struct TursoTransactionState {
    connection: turso::Connection,
    finished: bool,
}

impl DbTransaction {
    pub async fn commit(&self) -> Result<(), sqlx::Error> {
        match &self.inner {
            DbTransactionInner::Sqlx(tx) => {
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
                guard
                    .connection
                    .execute("COMMIT", ())
                    .await
                    .map_err(map_turso_error)?;
                guard.finished = true;
                Ok(())
            }
        }
    }

    pub async fn rollback(&self) -> Result<(), sqlx::Error> {
        match &self.inner {
            DbTransactionInner::Sqlx(tx) => {
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
                guard
                    .connection
                    .execute("ROLLBACK", ())
                    .await
                    .map_err(map_turso_error)?;
                guard.finished = true;
                Ok(())
            }
        }
    }

    pub async fn execute_batch(&self, sql: &str) -> Result<(), sqlx::Error> {
        match &self.inner {
            DbTransactionInner::Sqlx(tx) => {
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
                    .connection
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
                Self::Sqlx(pool) => execute_sqlx(pool, query).await,
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
                Self::Sqlx(pool) => fetch_all_sqlx(pool, query).await,
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
                DbTransactionInner::Sqlx(tx) => {
                    let mut guard = tx.lock().await;
                    let tx = guard.as_mut().ok_or_else(|| {
                        sqlx::Error::Protocol("transaction already finished".to_owned())
                    })?;
                    execute_sqlx_tx(tx, query).await
                }
                #[cfg(feature = "turso-local")]
                DbTransactionInner::TursoLocal(tx) => {
                    let guard = tx.lock().await;
                    if guard.finished {
                        return Err(sqlx::Error::Protocol(
                            "transaction already finished".to_owned(),
                        ));
                    }
                    execute_turso_connection(&guard.connection, query).await
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
                DbTransactionInner::Sqlx(tx) => {
                    let mut guard = tx.lock().await;
                    let tx = guard.as_mut().ok_or_else(|| {
                        sqlx::Error::Protocol("transaction already finished".to_owned())
                    })?;
                    fetch_all_sqlx_tx(tx, query).await
                }
                #[cfg(feature = "turso-local")]
                DbTransactionInner::TursoLocal(tx) => {
                    let guard = tx.lock().await;
                    if guard.finished {
                        return Err(sqlx::Error::Protocol(
                            "transaction already finished".to_owned(),
                        ));
                    }
                    fetch_all_turso_connection(&guard.connection, query).await
                }
            }
        })
    }
}

async fn execute_sqlx<E>(executor: E, query: BoundQuery<'_>) -> Result<DbQueryResult, sqlx::Error>
where
    E: sqlx::Executor<'static, Database = Any>,
{
    let result = apply_sqlx_binds(sqlx::query(query.sql), query.binds)
        .execute(executor)
        .await?;
    Ok(DbQueryResult {
        rows_affected: result.rows_affected(),
        last_insert_rowid: None,
    })
}

async fn fetch_all_sqlx<E>(executor: E, query: BoundQuery<'_>) -> Result<Vec<AnyRow>, sqlx::Error>
where
    E: sqlx::Executor<'static, Database = Any>,
{
    apply_sqlx_binds(sqlx::query(query.sql), query.binds)
        .fetch_all(executor)
        .await
}

async fn execute_sqlx_tx(
    tx: &mut sqlx::Transaction<'static, Any>,
    query: BoundQuery<'_>,
) -> Result<DbQueryResult, sqlx::Error> {
    let result = apply_sqlx_binds(sqlx::query(query.sql), query.binds)
        .execute(tx.as_mut())
        .await?;
    Ok(DbQueryResult {
        rows_affected: result.rows_affected(),
        last_insert_rowid: None,
    })
}

async fn fetch_all_sqlx_tx(
    tx: &mut sqlx::Transaction<'static, Any>,
    query: BoundQuery<'_>,
) -> Result<Vec<AnyRow>, sqlx::Error> {
    apply_sqlx_binds(sqlx::query(query.sql), query.binds)
        .fetch_all(tx.as_mut())
        .await
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
    Ok(DbPool::TursoLocal(TursoLocalPool { database }))
}

#[cfg(feature = "turso-local")]
impl TursoLocalPool {
    async fn connect(&self) -> Result<turso::Connection, sqlx::Error> {
        let conn = self.database.connect().map_err(map_turso_error)?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(map_turso_error)?;
        conn.execute("PRAGMA foreign_keys = ON", ())
            .await
            .map_err(map_turso_error)?;
        Ok(conn)
    }

    async fn execute(&self, query: BoundQuery<'_>) -> Result<DbQueryResult, sqlx::Error> {
        let conn = self.connect().await?;
        execute_turso_connection(&conn, query).await
    }

    async fn fetch_all(&self, query: BoundQuery<'_>) -> Result<Vec<AnyRow>, sqlx::Error> {
        let conn = self.connect().await?;
        fetch_all_turso_connection(&conn, query).await
    }

    async fn execute_batch(&self, sql: &str) -> Result<(), sqlx::Error> {
        let conn = self.connect().await?;
        conn.execute_batch(sql).await.map_err(map_turso_error)
    }
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
    #[cfg(feature = "turso-local")]
    use crate::database::{DatabaseConfig, DatabaseEngine, TursoLocalConfig};
    #[cfg(feature = "turso-local")]
    use sqlx::error::DatabaseError as _;
    #[cfg(feature = "turso-local")]
    use std::sync::{Mutex, OnceLock};

    #[cfg(feature = "turso-local")]
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
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
