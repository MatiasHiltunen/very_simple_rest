//! Database pool and SQL dialect abstractions.
//!
//! Everything in VSR that touches a database goes through these traits.
//! No concrete sqlx, Turso, or other driver types cross a public VSR seam.
//! Adapter modules (behind feature flags) translate between VSR types and
//! driver types at the edge.
//!
//! # The seam
//!
//! ```text
//! vsr-runtime / emitted server
//!     │
//!     ▼  depends on trait
//! DbPool  ◄────── concrete impl behind feature flag
//!     │               (e.g. SqlxPool<Sqlite>)
//!     ▼
//! actual DB driver (sqlx, turso, …)
//! ```
//!
//! Swapping from SQLite to Postgres is a `Cargo.toml` feature change and a
//! connection-URL change — no handler code changes.
//!
//! # Dialect
//!
//! [`Dialect`] captures the SQL capability set of a connected backend. The
//! compiler (`vsr-codegen`) uses it to emit correct SQL at code-generation
//! time; the runtime uses it to choose query branches at startup.

use crate::error::VsrResult;

// ─── Dialect ──────────────────────────────────────────────────────────────────

/// Identifies the SQL dialect and capability set of a connected database.
///
/// The value is determined at pool-creation time and exposed via
/// [`DbPool::dialect`]. It is `#[non_exhaustive]` so we can add future
/// backends without breaking existing match arms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Dialect {
    /// SQLite — file-based or in-memory.
    Sqlite,
    /// Turso's libsql local mode — SQLite wire protocol with Turso extensions.
    TursoLocal,
    /// PostgreSQL (any version ≥ 14 recommended).
    Postgres,
    /// MySQL / MariaDB.
    Mysql,
}

impl Dialect {
    /// Returns `true` if this dialect supports `RETURNING` on `INSERT`/`UPDATE`.
    ///
    /// If `false`, codegen emits a separate fetch-after-mutation.
    pub fn supports_returning(&self) -> bool {
        matches!(self, Dialect::Sqlite | Dialect::TursoLocal | Dialect::Postgres)
    }

    /// Returns `true` if upsert uses `ON CONFLICT … DO UPDATE`.
    ///
    /// MySQL uses `ON DUPLICATE KEY UPDATE` instead.
    pub fn uses_on_conflict_upsert(&self) -> bool {
        matches!(self, Dialect::Sqlite | Dialect::TursoLocal | Dialect::Postgres)
    }

    /// Returns `true` if JSON access uses the `jsonb` operator family.
    ///
    /// SQLite/Turso use `json_extract`; MySQL uses `JSON_EXTRACT`.
    pub fn uses_jsonb(&self) -> bool {
        matches!(self, Dialect::Postgres)
    }

    /// Returns `true` if the dialect uses `TIMESTAMPTZ` for timestamp storage.
    ///
    /// SQLite stores timestamps as `TEXT` (ISO-8601) or `INTEGER` (epoch).
    /// MySQL uses plain `TIMESTAMP`/`DATETIME`.
    pub fn has_timestamptz(&self) -> bool {
        matches!(self, Dialect::Postgres)
    }

    /// Human-readable name used in error messages and docs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Dialect::Sqlite => "SQLite",
            Dialect::TursoLocal => "TursoLocal",
            Dialect::Postgres => "Postgres",
            Dialect::Mysql => "MySQL",
        }
    }
}

impl std::fmt::Display for Dialect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── DbPool ──────────────────────────────────────────────────────────────────

/// A low-level database connection pool.
///
/// VSR does not expose driver-specific types (sqlx `Pool<DB>`, Turso
/// `Database`, etc.) in its public API. All database access goes through
/// this trait. Concrete implementations live behind feature flags.
///
/// # Implementor notes
///
/// - Cloning a `DbPool` shares the underlying connection pool. Clones are
///   cheap (usually just an `Arc` increment).
/// - The `execute_raw` method is **for DDL and internal lifecycle SQL only**
///   (e.g. `PRAGMA journal_mode=WAL`). Application query code lives in typed
///   repository functions that accept a concrete `sqlx::Pool<DB>` or
///   equivalent, behind the feature flag that enables that backend.
pub trait DbPool: Clone + Send + Sync + 'static {
    /// The SQL dialect of this pool.
    fn dialect(&self) -> Dialect;

    /// Execute a raw SQL statement. Intended for DDL and internal lifecycle
    /// SQL (PRAGMAs, session-level settings). Not for application data.
    ///
    /// # Errors
    /// Returns `Err(VsrError::Database(_))` on failure. The error message
    /// never includes the full SQL statement or any parameter values.
    fn execute_raw(
        &self,
        sql: &str,
    ) -> impl Future<Output = VsrResult<()>> + Send;

    /// Returns `true` if the pool can reach the database right now.
    ///
    /// Used by `/readyz` health checks and `vsr doctor db`.
    fn is_healthy(&self) -> impl Future<Output = bool> + Send;
}

use std::future::Future;

// ─── DbCapabilities ──────────────────────────────────────────────────────────

/// Runtime capability flags — information discovered by querying the live
/// database that cannot be inferred from the dialect alone.
///
/// Populated by `vsr doctor db` and stored for the lifetime of the process.
#[derive(Debug, Clone, Default)]
pub struct DbCapabilities {
    /// Server version string (e.g. `"PostgreSQL 16.1"`, `"3.45.0"`).
    pub version: Option<String>,
    /// Whether SQLite WAL mode is active.
    pub wal_mode: Option<bool>,
    /// Maximum connections allowed for the pool.
    pub max_connections: Option<u32>,
    /// Whether the database is running with the minimum required isolation
    /// level (checked at startup, refused below).
    pub isolation_ok: bool,
}
