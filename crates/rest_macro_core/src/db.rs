//! Compatibility facade for the database drivers in `vsr-runtime`.

#[cfg(feature = "turso-local")]
pub use vsr_runtime::db::TursoLocalPool;
pub use vsr_runtime::db::{
    BoundQuery, DbExecutor, DbPool, DbQueryResult, DbTransaction, DbValue, IntoDbValue, Query,
    QueryAs, QueryScalar, SqlxBackend, connect, connect_with_config, query, query_as, query_scalar,
};

#[cfg(all(test, feature = "turso-local"))]
// Legacy environment compatibility fixture; production and runtime deny unsafe.
#[allow(unsafe_code)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::{DbPool, connect_with_config, query, query_scalar};
    use crate::database::{DatabaseConfig, DatabaseEngine, TursoLocalConfig};
    use crate::secret::SecretRef;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
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
                encryption_key: Some(SecretRef::env_or_file(env_var.clone())),
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
