//! Compiler-free service descriptor for native request handling.

use std::sync::Arc;

use crate::{
    native_resource::RuntimeResource,
    runtime::RuntimeConfig,
    security::SecurityConfig,
    static_config::StaticMount,
    storage::{StoragePublicMount, StorageS3CompatConfig, StorageUploadEndpoint},
    tls::TlsConfig,
};

/// Lowered service settings shared by native HTTP handlers and adapters.
#[derive(Clone)]
pub struct RuntimeService {
    /// Module name used in diagnostics.
    pub module_name: String,
    /// Listener, compression, and request limits.
    pub runtime: RuntimeConfig,
    /// Request and browser security settings.
    pub security: SecurityConfig,
    /// TLS listener configuration.
    pub tls: TlsConfig,
    /// Whether authorization management routes are exposed.
    pub authorization_management_enabled: bool,
    /// Public mount for authorization management routes.
    pub authorization_management_mount: String,
    /// Lowered resources served by the native application.
    pub resources: Vec<Arc<RuntimeResource>>,
    /// Resource selected for the experimental neutral CRUD route.
    pub neutral_crud_resource: Option<String>,
    /// Generated `OpenAPI` document.
    pub openapi_json: Arc<String>,
    /// Documentation page HTML.
    pub docs_html: Arc<String>,
    /// Whether built-in authentication routes are mounted.
    pub include_builtin_auth: bool,
    /// Static directory mounts.
    pub static_mounts: Arc<Vec<StaticMount>>,
    /// Public storage mounts.
    pub storage_public_mounts: Arc<Vec<StoragePublicMount>>,
    /// Upload endpoints.
    pub storage_uploads: Arc<Vec<StorageUploadEndpoint>>,
    /// Optional S3-compatible API configuration.
    pub storage_s3_compat: Arc<Option<StorageS3CompatConfig>>,
}
