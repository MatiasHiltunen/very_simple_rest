//! Driver-independent statement values, binding, and write execution.

use std::future::Future;

/// Owned scalar or binary value in placeholder order.
#[derive(Clone, Debug, PartialEq)]
pub enum StatementValue {
    /// SQL NULL.
    Null,
    /// Boolean value.
    Bool(bool),
    /// Signed 64-bit integer.
    Integer(i64),
    /// 64-bit floating point value.
    Double(f64),
    /// UTF-8 text.
    Text(String),
    /// Binary value.
    Blob(Vec<u8>),
}

/// Convert an application value without exposing driver errors.
pub trait IntoStatementValue {
    /// Convert this value or return a binding error.
    fn into_statement_value(self) -> Result<StatementValue, String>;
}

impl IntoStatementValue for StatementValue {
    fn into_statement_value(self) -> Result<StatementValue, String> {
        Ok(self)
    }
}

/// Affected rows and a generated ID reported by a database adapter.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StatementResult {
    pub(crate) rows_affected: u64,
    pub(crate) last_insert_rowid: Option<i64>,
}

impl StatementResult {
    /// Construct an adapter result.
    pub fn new(rows_affected: u64, last_insert_rowid: Option<i64>) -> Self {
        Self {
            rows_affected,
            last_insert_rowid,
        }
    }

    /// Number of rows affected by the statement.
    pub fn rows_affected(&self) -> u64 {
        self.rows_affected
    }

    /// Generated insert ID when reported by the driver.
    pub fn last_insert_rowid(&self) -> Option<i64> {
        self.last_insert_rowid
    }
}

/// Borrowed SQL with validated, owned bindings.
pub struct StatementQuery<'a> {
    /// SQL supplied by the application planner.
    pub sql: &'a str,
    /// Values in placeholder order.
    pub binds: Vec<StatementValue>,
}

/// Execute a write in a pool or an existing transaction.
pub trait StatementExecutor: Send + Sync {
    /// Execute without changing the caller's transaction boundary.
    fn execute(
        &self,
        query: StatementQuery<'_>,
    ) -> impl Future<Output = Result<StatementResult, String>> + Send;
}

/// Execute an insert whose RETURNING row supplies the new integer ID.
pub trait ReturningIdExecutor: Send + Sync {
    /// Fetch the returned ID or report a database/decoding failure.
    fn returning_id(
        &self,
        query: StatementQuery<'_>,
    ) -> impl Future<Output = Result<i64, String>> + Send;
}

/// A statement builder that defers the first binding failure until execution.
pub struct Statement<'a> {
    query: StatementQuery<'a>,
    bind_error: Option<String>,
}

impl<'a> Statement<'a> {
    /// Start a statement using planner-owned SQL.
    pub fn new(sql: &'a str) -> Self {
        Self {
            query: StatementQuery {
                sql,
                binds: Vec::new(),
            },
            bind_error: None,
        }
    }

    /// Append a value, preserving the first conversion failure.
    pub fn bind<T: IntoStatementValue>(mut self, value: T) -> Self {
        if self.bind_error.is_none() {
            match value.into_statement_value() {
                Ok(value) => self.query.binds.push(value),
                Err(error) => self.bind_error = Some(error),
            }
        }
        self
    }

    fn into_query(self) -> Result<StatementQuery<'a>, String> {
        match self.bind_error {
            Some(error) => Err(error),
            None => Ok(self.query),
        }
    }

    /// Execute only after all binding conversions succeed.
    pub async fn execute<E: StatementExecutor + ?Sized>(
        self,
        executor: &E,
    ) -> Result<StatementResult, String> {
        executor.execute(self.into_query()?).await
    }

    /// Fetch an insert ID only after all binding conversions succeed.
    pub async fn returning_id<E: ReturningIdExecutor + ?Sized>(
        self,
        executor: &E,
    ) -> Result<i64, String> {
        executor.returning_id(self.into_query()?).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct Executor(Mutex<Vec<(String, Vec<StatementValue>)>>);

    impl StatementExecutor for Executor {
        async fn execute(&self, query: StatementQuery<'_>) -> Result<StatementResult, String> {
            self.0.lock().unwrap().push((query.sql.into(), query.binds));
            Ok(StatementResult::new(2, Some(42)))
        }
    }

    impl ReturningIdExecutor for Executor {
        async fn returning_id(&self, query: StatementQuery<'_>) -> Result<i64, String> {
            self.0.lock().unwrap().push((query.sql.into(), query.binds));
            Ok(42)
        }
    }

    struct InvalidValue(Arc<AtomicUsize>);
    impl IntoStatementValue for InvalidValue {
        fn into_statement_value(self) -> Result<StatementValue, String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err("invalid first bind".into())
        }
    }

    #[tokio::test]
    async fn statement_transfers_owned_bindings_and_write_results_without_a_driver() {
        let executor = Executor::default();
        let values = vec![
            StatementValue::Null,
            StatementValue::Bool(true),
            StatementValue::Integer(7),
            StatementValue::Double(2.5),
            StatementValue::Text("owned".into()),
            StatementValue::Blob(vec![0, 255]),
        ];
        let mut statement = Statement::new("write");
        for value in values.clone() {
            statement = statement.bind(value);
        }
        let result = statement.execute(&executor).await.unwrap();
        assert_eq!(result.rows_affected(), 2);
        assert_eq!(result.last_insert_rowid(), Some(42));
        assert_eq!(
            executor.0.lock().unwrap().as_slice(),
            &[("write".into(), values)]
        );
        let id = Statement::new("returning")
            .bind(StatementValue::Integer(8))
            .returning_id(&executor)
            .await
            .unwrap();
        assert_eq!(id, 42);
        assert_eq!(
            executor.0.lock().unwrap()[1],
            ("returning".into(), vec![StatementValue::Integer(8)])
        );
    }

    #[tokio::test]
    async fn failed_bind_prevents_execution_and_later_conversions() {
        let executor = Executor::default();
        for returning in [false, true] {
            let conversions = Arc::new(AtomicUsize::new(0));
            let statement = Statement::new("never execute")
                .bind(InvalidValue(conversions.clone()))
                .bind(InvalidValue(conversions.clone()));
            let error = if returning {
                statement.returning_id(&executor).await.err().unwrap()
            } else {
                statement.execute(&executor).await.err().unwrap()
            };
            assert_eq!(error, "invalid first bind");
            assert_eq!(conversions.load(Ordering::SeqCst), 1);
            assert!(executor.0.lock().unwrap().is_empty());
        }
    }
}
