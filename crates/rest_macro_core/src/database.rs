//! Compatibility facade for database configuration in `vsr-runtime`.

pub use vsr_runtime::database::{
    DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV, DatabaseBackupConfig, DatabaseBackupMode,
    DatabaseBackupRetention, DatabaseBackupTarget, DatabaseConfig, DatabaseEngine,
    DatabaseReadRoutingMode, DatabaseReplicationConfig, DatabaseReplicationMode,
    DatabaseResilienceConfig, DatabaseResilienceProfile, TursoLocalConfig,
    open_turso_local_database, prepare_database_engine, resolve_database_config,
    resolve_database_url, resolve_relative_database_path, service_base_dir_from_config_path,
    sqlite_url_for_path,
};
