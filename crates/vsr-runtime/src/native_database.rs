//! SQLx and local Turso adapters for native CRUD and audited transactions.

use serde_json::Value;

use crate::{
    db::{
        DbExecutor, DbPool, DbTransaction, DbValue, IntoDbValue, Query, QueryScalar, query,
        query_as, query_scalar,
    },
    native_audit::{AuditDatabase, AuditTransaction},
    native_insert::{InsertExecutor, InsertPlan},
    native_mutation::MutationStatement,
    native_read::{ReadExecutor, ReadStatement, unfiltered_item_statement},
    native_resource::{RuntimeBoundValue, RuntimeResource},
    native_sqlx::row_to_json,
    typed_read::{TypedItemReadExecutor, TypedReadExecutor, TypedReadQuery},
};

impl IntoDbValue for RuntimeBoundValue {
    fn into_db_value(self) -> Result<DbValue, sqlx::Error> {
        Ok(match self {
            Self::Null => DbValue::Null,
            Self::Bool(value) => DbValue::Bool(value),
            Self::Integer(value) => DbValue::Integer(value),
            Self::Real(value) => DbValue::Double(value),
            Self::Text(value) => DbValue::Text(value),
        })
    }
}

/// Append a native value to a portable database query.
pub fn bind_query<'q>(query: Query<'q>, value: &RuntimeBoundValue) -> Query<'q> {
    match value {
        RuntimeBoundValue::Null => query.bind::<Option<String>>(None),
        RuntimeBoundValue::Bool(value) => query.bind(*value),
        RuntimeBoundValue::Integer(value) => query.bind(*value),
        RuntimeBoundValue::Real(value) => query.bind(*value),
        RuntimeBoundValue::Text(value) => query.bind(value.clone()),
    }
}

/// Append a native value to a portable scalar query.
pub fn bind_scalar_query<'q, T>(
    query: QueryScalar<'q, T>,
    value: &RuntimeBoundValue,
) -> QueryScalar<'q, T> {
    match value {
        RuntimeBoundValue::Null => query.bind::<Option<String>>(None),
        RuntimeBoundValue::Bool(value) => query.bind(*value),
        RuntimeBoundValue::Integer(value) => query.bind(*value),
        RuntimeBoundValue::Real(value) => query.bind(*value),
        RuntimeBoundValue::Text(value) => query.bind(value.clone()),
    }
}

async fn fetch_optional<E: DbExecutor + Sync + ?Sized>(
    resource: &RuntimeResource,
    executor: &E,
    statement: &ReadStatement,
) -> Result<Option<Value>, String> {
    let mut request = query(&statement.sql);
    for bind in &statement.binds {
        request = bind_query(request, bind);
    }
    let row = request
        .fetch_optional(executor)
        .await
        .map_err(|error| error.to_string())?;
    row.map(|row| row_to_json(resource, &row))
        .transpose()
        .map_err(|error| error.to_string())
}

/// Fetch an unfiltered row snapshot using a pool or an existing transaction.
pub async fn fetch_native_row<E: DbExecutor + Sync + ?Sized>(
    resource: &RuntimeResource,
    executor: &E,
    id: i64,
) -> Result<Option<Value>, String> {
    fetch_optional(resource, executor, &unfiltered_item_statement(resource, id)).await
}

/// Execute a mutation or audit statement and return its affected rows.
pub async fn execute_native_statement<E: DbExecutor + Sync + ?Sized>(
    executor: &E,
    statement: &MutationStatement,
) -> Result<u64, String> {
    let mut request = query(&statement.sql);
    for bind in &statement.binds {
        request = bind_query(request, bind);
    }
    request
        .execute(executor)
        .await
        .map(|result| result.rows_affected())
        .map_err(|error| error.to_string())
}

async fn insert<E: DbExecutor + Sync + ?Sized>(
    executor: &E,
    plan: &InsertPlan,
) -> Result<Option<i64>, String> {
    if plan.returning_id {
        let mut request = query_scalar::<sqlx::Any, i64>(&plan.sql);
        for value in &plan.binds {
            request = bind_scalar_query(request, value);
        }
        request
            .fetch_one(executor)
            .await
            .map(Some)
            .map_err(|error| error.to_string())
    } else {
        let mut request = query(&plan.sql);
        for value in &plan.binds {
            request = bind_query(request, value);
        }
        request
            .execute(executor)
            .await
            .map(|result| result.last_insert_rowid())
            .map_err(|error| error.to_string())
    }
}

macro_rules! impl_native_executor {
    ($executor:ty) => {
        impl<T> TypedItemReadExecutor<T> for $executor
        where
            T: for<'row> sqlx::FromRow<'row, sqlx::any::AnyRow> + Send + Unpin,
        {
            async fn fetch_optional(
                &self,
                statement: TypedReadQuery<'_>,
            ) -> Result<Option<T>, String> {
                let mut request = query_as::<sqlx::Any, T>(statement.sql);
                for bind in statement.binds {
                    request = request.bind(bind);
                }
                request
                    .fetch_optional(self)
                    .await
                    .map_err(|error| error.to_string())
            }
        }

        impl<T> TypedReadExecutor<T> for $executor
        where
            T: for<'row> sqlx::FromRow<'row, sqlx::any::AnyRow> + Send + Unpin,
        {
            async fn count(&self, statement: TypedReadQuery<'_>) -> Result<i64, String> {
                let mut request = query_scalar::<sqlx::Any, i64>(statement.sql);
                for bind in statement.binds {
                    request = request.bind(bind);
                }
                request
                    .fetch_one(self)
                    .await
                    .map_err(|error| error.to_string())
            }

            async fn fetch_all(&self, statement: TypedReadQuery<'_>) -> Result<Vec<T>, String> {
                let mut request = query_as::<sqlx::Any, T>(statement.sql);
                for bind in statement.binds {
                    request = request.bind(bind);
                }
                request
                    .fetch_all(self)
                    .await
                    .map_err(|error| error.to_string())
            }
        }

        impl InsertExecutor for $executor {
            async fn insert(&self, plan: &InsertPlan) -> Result<Option<i64>, String> {
                insert(self, plan).await
            }
        }

        impl ReadExecutor for $executor {
            async fn fetch_optional(
                &self,
                resource: &RuntimeResource,
                statement: &ReadStatement,
            ) -> Result<Option<Value>, String> {
                fetch_optional(resource, self, statement).await
            }

            async fn fetch_all(
                &self,
                resource: &RuntimeResource,
                statement: &ReadStatement,
            ) -> Result<Vec<Value>, String> {
                let mut request = query(&statement.sql);
                for bind in &statement.binds {
                    request = bind_query(request, bind);
                }
                let rows = request
                    .fetch_all(self)
                    .await
                    .map_err(|error| error.to_string())?;
                rows.iter()
                    .map(|row| row_to_json(resource, row))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())
            }

            async fn count(&self, statement: &ReadStatement) -> Result<i64, String> {
                let mut request = query_scalar::<sqlx::Any, i64>(&statement.sql);
                for bind in &statement.binds {
                    request = bind_scalar_query(request, bind);
                }
                request
                    .fetch_one(self)
                    .await
                    .map_err(|error| error.to_string())
            }
        }
    };
}

impl_native_executor!(DbPool);
impl_native_executor!(DbTransaction);

impl AuditDatabase for DbPool {
    type Transaction = DbTransaction;

    async fn begin(&self) -> Result<Self::Transaction, String> {
        DbPool::begin(self).await.map_err(|error| error.to_string())
    }
}

impl AuditTransaction for DbTransaction {
    async fn snapshot(
        &self,
        resource: &RuntimeResource,
        record_id: i64,
    ) -> Result<Option<Value>, String> {
        fetch_native_row(resource, self, record_id).await
    }

    async fn execute(&self, statement: &MutationStatement) -> Result<u64, String> {
        execute_native_statement(self, statement).await
    }

    async fn commit(self) -> Result<(), String> {
        DbTransaction::commit(&self)
            .await
            .map_err(|error| error.to_string())
    }

    async fn rollback(self) -> Result<(), String> {
        DbTransaction::rollback(&self)
            .await
            .map_err(|error| error.to_string())
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use crate::{
        authz::{RoleRequirements, policy::RowPolicies},
        database::{DatabaseConfig, DatabaseEngine, TursoLocalConfig},
        field::{FieldKind, FieldValidation, GeneratedValue, RuntimeField},
        model::DbBackend,
        native_audit::{
            AuditActor, AuditedMutation, execute_audited_insert, execute_audited_mutation,
        },
        native_mutation::MutationAction,
        native_resource::RuntimeAuditConfig,
        native_write::{PreparedCreate, WriteAssignment},
    };
    use serde_json::json;
    use std::collections::{BTreeSet, HashMap};

    #[tokio::test]
    async fn typed_read_adapters_preserve_filters_pagination_nulls_and_transactions() {
        use crate::typed_read::read_collection;
        type Row = (i64, String, Option<String>, f64);

        for local_turso in [false, true] {
            if local_turso && !cfg!(feature = "turso-local") {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("typed.db");
            let config = DatabaseConfig {
                engine: if local_turso {
                    DatabaseEngine::TursoLocal(TursoLocalConfig {
                        path: path.display().to_string(),
                        encryption_key: None,
                    })
                } else {
                    DatabaseEngine::Sqlx
                },
                resilience: None,
            };
            let pool = DbPool::connect_with_config(
                &format!("sqlite:{}?mode=rwc", path.display()),
                &config,
            )
            .await
            .unwrap();
            pool.execute_batch("CREATE TABLE typed_note (id INTEGER PRIMARY KEY, title TEXT NOT NULL, note TEXT, score REAL NOT NULL, enabled INTEGER NOT NULL)").await.unwrap();
            for (id, title, enabled, score) in [
                (1, "alpha", true, 1.5),
                (2, "bravo", true, 2.5),
                (3, "hidden", false, 3.5),
            ] {
                query("INSERT INTO typed_note (id, title, note, score, enabled) VALUES (?, ?, ?, ?, ?)")
                    .bind(RuntimeBoundValue::Integer(id))
                    .bind(RuntimeBoundValue::Text(title.into()))
                    .bind(RuntimeBoundValue::Null)
                    .bind(RuntimeBoundValue::Real(score))
                    .bind(RuntimeBoundValue::Bool(enabled))
                    .execute(&pool).await.unwrap();
            }
            let count = || TypedReadQuery {
                sql: "SELECT COUNT(*) FROM typed_note WHERE enabled = ? AND score >= ?",
                binds: vec![RuntimeBoundValue::Bool(true), RuntimeBoundValue::Real(1.5)],
            };
            let select = || TypedReadQuery {
                sql: "SELECT id, title, note, score FROM typed_note WHERE enabled = ? AND score >= ? AND id > ? ORDER BY id LIMIT ? OFFSET ?",
                binds: vec![
                    RuntimeBoundValue::Bool(true),
                    RuntimeBoundValue::Real(1.5),
                    RuntimeBoundValue::Integer(1),
                    RuntimeBoundValue::Integer(1),
                    RuntimeBoundValue::Integer(0),
                ],
            };
            let page = read_collection::<Row, _>(&pool, count(), select())
                .await
                .unwrap();
            assert_eq!(page.total, 2);
            assert_eq!(page.items, vec![(2, "bravo".into(), None, 2.5)]);
            let empty = TypedReadExecutor::<Row>::fetch_all(
                &pool,
                TypedReadQuery {
                    sql: "SELECT id, title, note, score FROM typed_note WHERE id = ?",
                    binds: vec![RuntimeBoundValue::Integer(99)],
                },
            )
            .await
            .unwrap();
            assert!(empty.is_empty());
            let item_query = |id| TypedReadQuery {
                sql: "SELECT id, title, note, score FROM typed_note WHERE id = ? AND enabled = ? AND title = ? AND score >= ?",
                binds: vec![
                    RuntimeBoundValue::Integer(id),
                    RuntimeBoundValue::Bool(true),
                    RuntimeBoundValue::Text("bravo".into()),
                    RuntimeBoundValue::Real(2.5),
                ],
            };
            let item = TypedItemReadExecutor::<Row>::fetch_optional(&pool, item_query(2))
                .await
                .unwrap();
            assert_eq!(item, Some((2, "bravo".into(), None, 2.5)));
            for id in [3, 99] {
                assert!(
                    TypedItemReadExecutor::<Row>::fetch_optional(&pool, item_query(id))
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            assert!(
                TypedItemReadExecutor::<Row>::fetch_optional(
                    &pool,
                    TypedReadQuery {
                        sql: "SELECT * FROM missing_typed_table",
                        binds: vec![],
                    },
                )
                .await
                .is_err()
            );
            let tx = DbPool::begin(&pool).await.unwrap();
            query("INSERT INTO typed_note VALUES (4, 'transaction', 'visible in transaction', 4.5, 1)").execute(&tx).await.unwrap();
            let page = read_collection::<Row, _>(
                &tx,
                count(),
                TypedReadQuery {
                    sql: "SELECT id, title, note, score FROM typed_note WHERE id = ?",
                    binds: vec![RuntimeBoundValue::Integer(4)],
                },
            )
            .await
            .unwrap();
            assert_eq!(page.total, 3);
            let transaction_item = || TypedReadQuery {
                sql: "SELECT id, title, note, score FROM typed_note WHERE id = ?",
                binds: vec![RuntimeBoundValue::Integer(4)],
            };
            let item = TypedItemReadExecutor::<Row>::fetch_optional(&tx, transaction_item())
                .await
                .unwrap();
            assert_eq!(item.as_ref(), page.items.first());
            assert_eq!(
                page.items,
                vec![(
                    4,
                    "transaction".into(),
                    Some("visible in transaction".into()),
                    4.5
                )]
            );
            DbTransaction::rollback(&tx).await.unwrap();
            assert!(
                TypedItemReadExecutor::<Row>::fetch_optional(&pool, transaction_item())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                TypedReadExecutor::<Row>::count(&pool, count())
                    .await
                    .unwrap(),
                2
            );
            if let Some(sqlx_pool) = pool.sqlx_pool() {
                sqlx_pool.close().await;
            }
            drop(pool);
        }
    }

    fn resource() -> RuntimeResource {
        let fields = [
            ("id", "id", FieldKind::Integer),
            ("title_text", "title", FieldKind::Text),
            ("active", "active", FieldKind::Boolean),
        ]
        .map(|(name, api_name, kind)| RuntimeField {
            name: name.into(),
            api_name: api_name.into(),
            expose_in_api: true,
            enum_values: None,
            transforms: Vec::new(),
            kind,
            list_item_kind: None,
            object_fields: None,
            optional: false,
            generated: GeneratedValue::None,
            validation: FieldValidation::default(),
            supports_exact_filters: true,
            supports_sort: true,
            supports_range_filters: false,
        })
        .to_vec();
        RuntimeResource {
            resource_name: "Document".into(),
            table_name: "document".into(),
            api_name: "documents".into(),
            default_response_context: None,
            id_field: "id".into(),
            id_api_name: "id".into(),
            db: DbBackend::Sqlite,
            roles: RoleRequirements::default(),
            policies: RowPolicies::default(),
            default_limit: None,
            max_limit: None,
            filterable_in: BTreeSet::new(),
            count_endpoint: true,
            create_assignment_sources: HashMap::new(),
            field_index: fields
                .iter()
                .enumerate()
                .map(|(i, field)| (field.name.clone(), i))
                .collect(),
            api_field_index: fields
                .iter()
                .enumerate()
                .map(|(i, field)| (field.api_name.clone(), i))
                .collect(),
            fields,
            response_contexts: HashMap::new(),
            computed_fields: Vec::new(),
            create_fields: Vec::new(),
            update_field_names: Vec::new(),
            actions: Vec::new(),
            audit: Some(RuntimeAuditConfig {
                sink_table_name: "audit_event".into(),
                create: true,
                update: true,
                delete: true,
                actions: None,
            }),
            is_audit_sink: false,
            read_requires_auth: false,
            hybrid: None,
            nested_relations: Vec::new(),
            many_to_many_routes: Vec::new(),
        }
    }

    #[tokio::test]
    async fn standalone_native_adapters_commit_and_roll_back_on_sqlite_and_turso() {
        for local_turso in [false, true] {
            if local_turso && !cfg!(feature = "turso-local") {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("native.db");
            let config = DatabaseConfig {
                engine: if local_turso {
                    DatabaseEngine::TursoLocal(TursoLocalConfig {
                        path: path.display().to_string(),
                        encryption_key: None,
                    })
                } else {
                    DatabaseEngine::Sqlx
                },
                resilience: None,
            };
            let pool = DbPool::connect_with_config(
                &format!("sqlite:{}?mode=rwc", path.display()),
                &config,
            )
            .await
            .unwrap();
            pool.execute_batch("CREATE TABLE document (id INTEGER PRIMARY KEY, title_text TEXT NOT NULL, active INTEGER NOT NULL); CREATE TABLE audit_event (id INTEGER PRIMARY KEY, event_kind TEXT, resource_name TEXT, record_id INTEGER, actor_user_id INTEGER, actor_roles_json TEXT, payload_json TEXT);").await.unwrap();
            let resource = resource();
            let roles = vec!["member".into()];
            let actor = AuditActor {
                user_id: 7,
                roles: &roles,
            };
            let prepared = PreparedCreate {
                assignments: vec![
                    WriteAssignment {
                        field_name: "title_text".into(),
                        value: RuntimeBoundValue::Text("old".into()),
                    },
                    WriteAssignment {
                        field_name: "active".into(),
                        value: RuntimeBoundValue::Bool(false),
                    },
                ],
            };
            let id = execute_audited_insert(&resource, &prepared, &actor, "created", &pool)
                .await
                .unwrap();
            assert_eq!(
                fetch_native_row(&resource, &pool, id).await.unwrap(),
                Some(json!({"id": id, "title": "old", "active": false}))
            );
            let statement = ReadStatement {
                sql: "SELECT COUNT(*) FROM document WHERE active = ?".into(),
                binds: vec![RuntimeBoundValue::Bool(false)],
            };
            assert_eq!(ReadExecutor::count(&pool, &statement).await.unwrap(), 1);
            let page = ReadStatement {
                sql: "SELECT * FROM document ORDER BY id LIMIT ?".into(),
                binds: vec![RuntimeBoundValue::Integer(1)],
            };
            assert_eq!(
                ReadExecutor::fetch_all(&pool, &resource, &page)
                    .await
                    .unwrap()
                    .len(),
                1
            );
            let tx = AuditDatabase::begin(&pool).await.unwrap();
            InsertExecutor::insert(
                &tx,
                &crate::native_insert::build_insert_plan(&resource, &prepared),
            )
            .await
            .unwrap();
            assert_eq!(ReadExecutor::count(&tx, &statement).await.unwrap(), 2);
            AuditTransaction::rollback(tx).await.unwrap();
            assert_eq!(ReadExecutor::count(&pool, &statement).await.unwrap(), 1);
            let update = MutationStatement {
                sql: "UPDATE document SET title_text = ?, active = ? WHERE id = ?".into(),
                binds: vec![
                    RuntimeBoundValue::Text("new".into()),
                    RuntimeBoundValue::Bool(true),
                    RuntimeBoundValue::Integer(id),
                ],
            };
            let request = AuditedMutation {
                resource: &resource,
                actor,
                event_kind: "updated",
                record_id: id,
                action: MutationAction::Update,
                statement: &update,
            };
            assert_eq!(execute_audited_mutation(&request, &pool).await.unwrap(), 1);
            let snapshot = fetch_native_row(&resource, &pool, id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(snapshot["title"], "new");
            assert_eq!(snapshot["active"], true);
            let payload: String = query_scalar::<sqlx::Any, String>(
                "SELECT payload_json FROM audit_event WHERE event_kind = 'updated'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            let payload: Value = serde_json::from_str(&payload).unwrap();
            assert_eq!(payload["before"]["title"], "old");
            assert_eq!(payload["after"]["active"], true);
            let missed = MutationStatement {
                sql: "DELETE FROM document WHERE id = ?".into(),
                binds: vec![RuntimeBoundValue::Integer(id + 99)],
            };
            assert_eq!(
                execute_audited_mutation(
                    &AuditedMutation {
                        action: MutationAction::Delete,
                        statement: &missed,
                        ..request
                    },
                    &pool
                )
                .await
                .unwrap(),
                0
            );
            assert_eq!(
                query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM audit_event")
                    .fetch_one(&pool)
                    .await
                    .unwrap(),
                2
            );
            pool.execute_batch("DROP TABLE audit_event").await.unwrap();
            let failed = MutationStatement {
                sql: "UPDATE document SET title_text = ? WHERE id = ?".into(),
                binds: vec![
                    RuntimeBoundValue::Text("must roll back".into()),
                    RuntimeBoundValue::Integer(id),
                ],
            };
            assert!(
                execute_audited_mutation(
                    &AuditedMutation {
                        statement: &failed,
                        ..request
                    },
                    &pool
                )
                .await
                .is_err()
            );
            assert_eq!(
                fetch_native_row(&resource, &pool, id)
                    .await
                    .unwrap()
                    .unwrap(),
                snapshot
            );
            let tx = DbPool::begin(&pool).await.unwrap();
            execute_native_statement(&tx, &failed).await.unwrap();
            drop(tx);
            assert_eq!(
                fetch_native_row(&resource, &pool, id)
                    .await
                    .unwrap()
                    .unwrap(),
                snapshot
            );
            if let DbPool::Sqlx { pool, .. } = &pool {
                pool.close().await;
            }
            drop(pool);
        }
    }
}
