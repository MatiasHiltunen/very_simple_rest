//! Typed collection reads shared by generated handlers and database adapters.

use std::future::Future;

use crate::native_resource::RuntimeBoundValue;

/// Borrowed SQL with owned values in placeholder order.
pub struct TypedReadQuery<'a> {
    /// SQL supplied by the resource's query planner.
    pub sql: &'a str,
    /// Ordered scalar bindings supplied by that planner.
    pub binds: Vec<RuntimeBoundValue>,
}

/// Database operations for a collection of application-owned row types.
///
/// Implementations own row decoding; this contract requires no database driver
/// or HTTP framework types.
pub trait TypedReadExecutor<T>: Send + Sync {
    /// Count the matching rows without pagination bindings.
    fn count(&self, query: TypedReadQuery<'_>) -> impl Future<Output = Result<i64, String>> + Send;

    /// Fetch and decode the selected page.
    fn fetch_all(
        &self,
        query: TypedReadQuery<'_>,
    ) -> impl Future<Output = Result<Vec<T>, String>> + Send;
}

/// A decoded page and its total before pagination.
pub struct TypedReadPage<T> {
    /// Number of matching rows before page limits or cursor constraints.
    pub total: i64,
    /// Rows selected for this page.
    pub items: Vec<T>,
}

/// Count first, then fetch a typed page; stop immediately on either failure.
pub async fn read_collection<T, E: TypedReadExecutor<T> + ?Sized>(
    executor: &E,
    count: TypedReadQuery<'_>,
    select: TypedReadQuery<'_>,
) -> Result<TypedReadPage<T>, String> {
    let total = executor.count(count).await?;
    let items = executor.fetch_all(select).await?;
    Ok(TypedReadPage { total, items })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Executor {
        calls: Mutex<Vec<(String, Vec<RuntimeBoundValue>)>>,
        fail_count: bool,
        fail_select: bool,
    }

    impl TypedReadExecutor<i64> for Executor {
        async fn count(&self, query: TypedReadQuery<'_>) -> Result<i64, String> {
            self.calls
                .lock()
                .unwrap()
                .push((query.sql.into(), query.binds));
            if self.fail_count {
                Err("count failed".into())
            } else {
                Ok(3)
            }
        }

        async fn fetch_all(&self, query: TypedReadQuery<'_>) -> Result<Vec<i64>, String> {
            self.calls
                .lock()
                .unwrap()
                .push((query.sql.into(), query.binds));
            if self.fail_select {
                Err("select failed".into())
            } else {
                Ok(vec![7])
            }
        }
    }

    #[tokio::test]
    async fn typed_collection_keeps_query_order_and_distinct_bindings() {
        let executor = Executor {
            calls: Mutex::default(),
            fail_count: false,
            fail_select: false,
        };
        let filter = vec![RuntimeBoundValue::Integer(7)];
        let page = vec![RuntimeBoundValue::Integer(7), RuntimeBoundValue::Integer(1)];
        let result = read_collection(
            &executor,
            TypedReadQuery {
                sql: "count",
                binds: filter,
            },
            TypedReadQuery {
                sql: "select",
                binds: page,
            },
        )
        .await
        .unwrap();
        assert_eq!(result.total, 3);
        assert_eq!(result.items, vec![7]);
        let calls = executor.calls.lock().unwrap();
        assert_eq!(
            calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
            ["count", "select"]
        );
        assert!(matches!(
            calls[0].1.as_slice(),
            [RuntimeBoundValue::Integer(7)]
        ));
        assert!(matches!(
            calls[1].1.as_slice(),
            [RuntimeBoundValue::Integer(7), RuntimeBoundValue::Integer(1)]
        ));
    }

    #[tokio::test]
    async fn typed_collection_stops_on_count_failure_and_preserves_select_failure() {
        for fail_count in [true, false] {
            let executor = Executor {
                calls: Mutex::default(),
                fail_count,
                fail_select: true,
            };
            let error = read_collection(
                &executor,
                TypedReadQuery {
                    sql: "count",
                    binds: vec![],
                },
                TypedReadQuery {
                    sql: "select",
                    binds: vec![],
                },
            )
            .await
            .err()
            .unwrap();
            assert_eq!(
                error,
                if fail_count {
                    "count failed"
                } else {
                    "select failed"
                }
            );
            assert_eq!(
                executor.calls.lock().unwrap().len(),
                if fail_count { 1 } else { 2 }
            );
        }
    }
}
