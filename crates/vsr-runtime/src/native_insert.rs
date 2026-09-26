//! Native insert planning and the database execution boundary.

use std::future::Future;

use crate::{
    model::DbBackend,
    native_resource::{RuntimeBoundValue, RuntimeResource},
    native_write::PreparedCreate,
};

/// An insert statement using the resource's database dialect.
#[derive(Clone, Debug, PartialEq)]
pub struct InsertPlan {
    /// SQL built from trusted, lowered resource identifiers.
    pub sql: String,
    /// Bound values in descriptor field order.
    pub binds: Vec<RuntimeBoundValue>,
    /// Read the new ID from a RETURNING row rather than a driver insert result.
    pub returning_id: bool,
}

/// Runs an insert using a pool or the caller's existing audit transaction.
pub trait InsertExecutor: Send + Sync {
    /// Bind and execute the plan, returning its generated integer ID when available.
    fn insert(&self, plan: &InsertPlan)
    -> impl Future<Output = Result<Option<i64>, String>> + Send;
}

/// Plan an insert from the same validated values used for create requirements.
pub fn build_insert_plan(resource: &RuntimeResource, prepared: &PreparedCreate) -> InsertPlan {
    let returning_id = matches!(resource.db, DbBackend::Postgres | DbBackend::Sqlite);
    let mut sql = if prepared.assignments.is_empty() {
        if resource.db == DbBackend::Mysql {
            format!("INSERT INTO {} () VALUES ()", resource.table_name)
        } else {
            format!("INSERT INTO {} DEFAULT VALUES", resource.table_name)
        }
    } else {
        let fields = prepared
            .assignments
            .iter()
            .map(|assignment| assignment.field_name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let placeholders = (1..=prepared.assignments.len())
            .map(|index| resource.db.placeholder(index))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "INSERT INTO {} ({fields}) VALUES ({placeholders})",
            resource.table_name
        )
    };
    if returning_id {
        sql.push_str(" RETURNING ");
        sql.push_str(&resource.id_field);
    }
    InsertPlan {
        sql,
        binds: prepared
            .assignments
            .iter()
            .map(|assignment| assignment.value.clone())
            .collect(),
        returning_id,
    }
}

/// Plan and execute a native create without selecting the transport or database driver.
///
/// Audit transaction creation, rollback, and commit remain the caller's responsibility.
pub async fn execute_insert(
    resource: &RuntimeResource,
    prepared: &PreparedCreate,
    executor: &impl InsertExecutor,
) -> Result<Option<i64>, String> {
    executor
        .insert(&build_insert_plan(resource, prepared))
        .await
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, HashMap},
        sync::Mutex,
    };

    use super::*;
    use crate::{
        authz::{RoleRequirements, policy::RowPolicies},
        native_write::WriteAssignment,
    };

    fn resource(db: DbBackend) -> RuntimeResource {
        RuntimeResource {
            resource_name: "Document".into(),
            table_name: "document".into(),
            api_name: "documents".into(),
            default_response_context: None,
            id_field: "document_id".into(),
            id_api_name: "id".into(),
            db,
            roles: RoleRequirements::default(),
            policies: RowPolicies::default(),
            default_limit: None,
            max_limit: None,
            filterable_in: BTreeSet::new(),
            count_endpoint: false,
            create_assignment_sources: HashMap::new(),
            fields: Vec::new(),
            field_index: HashMap::new(),
            api_field_index: HashMap::new(),
            response_contexts: HashMap::new(),
            computed_fields: Vec::new(),
            create_fields: Vec::new(),
            update_field_names: Vec::new(),
            actions: Vec::new(),
            audit: None,
            is_audit_sink: false,
            read_requires_auth: false,
            hybrid: None,
            nested_relations: Vec::new(),
            many_to_many_routes: Vec::new(),
        }
    }

    #[test]
    fn insert_uses_internal_names_and_keeps_values_out_of_sql() {
        let values = vec![
            RuntimeBoundValue::Text("'); DELETE FROM document; --".into()),
            RuntimeBoundValue::Integer(7),
        ];
        let prepared = PreparedCreate {
            assignments: vec![
                WriteAssignment {
                    field_name: "title_text".into(),
                    value: values[0].clone(),
                },
                WriteAssignment {
                    field_name: "owner_id".into(),
                    value: values[1].clone(),
                },
            ],
        };
        for (db, expected, returning_id) in [
            (
                DbBackend::Sqlite,
                "INSERT INTO document (title_text, owner_id) VALUES (?, ?) RETURNING document_id",
                true,
            ),
            (
                DbBackend::Postgres,
                "INSERT INTO document (title_text, owner_id) VALUES ($1, $2) RETURNING document_id",
                true,
            ),
            (
                DbBackend::Mysql,
                "INSERT INTO document (title_text, owner_id) VALUES (?, ?)",
                false,
            ),
        ] {
            let plan = build_insert_plan(&resource(db), &prepared);
            assert_eq!(plan.sql, expected);
            assert_eq!(plan.binds, values);
            assert_eq!(plan.returning_id, returning_id);
        }
    }

    #[test]
    fn insert_with_only_database_defaults_uses_each_dialect() {
        let prepared = PreparedCreate {
            assignments: Vec::new(),
        };
        for (db, expected) in [
            (
                DbBackend::Sqlite,
                "INSERT INTO document DEFAULT VALUES RETURNING document_id",
            ),
            (
                DbBackend::Postgres,
                "INSERT INTO document DEFAULT VALUES RETURNING document_id",
            ),
            (DbBackend::Mysql, "INSERT INTO document () VALUES ()"),
        ] {
            let plan = build_insert_plan(&resource(db), &prepared);
            assert_eq!(plan.sql, expected);
            assert!(plan.binds.is_empty());
        }
    }

    struct Executor {
        result: Result<Option<i64>, String>,
        plans: Mutex<Vec<InsertPlan>>,
    }

    impl InsertExecutor for Executor {
        async fn insert(&self, plan: &InsertPlan) -> Result<Option<i64>, String> {
            self.plans.lock().unwrap().push(plan.clone());
            self.result.clone()
        }
    }

    #[tokio::test]
    async fn execution_preserves_generated_ids_missing_ids_and_driver_errors() {
        let prepared = PreparedCreate {
            assignments: Vec::new(),
        };
        for result in [Ok(Some(17)), Ok(None), Err("transaction aborted".into())] {
            let executor = Executor {
                result: result.clone(),
                plans: Mutex::new(Vec::new()),
            };
            assert_eq!(
                execute_insert(&resource(DbBackend::Sqlite), &prepared, &executor).await,
                result
            );
            let plans = executor.plans.lock().unwrap();
            assert_eq!(plans.len(), 1);
            assert!(plans[0].returning_id);
        }
    }
}
