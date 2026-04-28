//! Deserialization document types for the `.eon` config format.
//!
//! `*Document` structs are intermediate serde-deserialisable types that map 1:1
//! to the raw YAML/JSON structure of `.eon` files. They are converted into the
//! canonical model types in [`super`] (the `eon_parser` module).
//!
//! The custom `Visitor` / `Deserializer` impls at the bottom of this file
//! handle maps-written-as-arrays, where the field name is embedded as a `name`
//! key inside a sequence of objects.

use std::collections::{BTreeMap, HashSet};

use serde::de::{self, Deserializer, Error as _, MapAccess, Visitor};
use serde_json::Value as JsonValue;

use super::super::model::{DbBackend, GeneratedValue, RoleRequirements};
use super::{default_admin_bypass, deserialize_create_policies_document};

#[derive(serde::Deserialize)]
pub(super) struct ServiceDocument {
    #[serde(default)]
    pub(super) module: Option<String>,
    #[serde(default, deserialize_with = "deserialize_enum_documents")]
    pub(super) enums: Vec<EnumDocument>,
    #[serde(default, deserialize_with = "deserialize_mixin_documents")]
    pub(super) mixins: Vec<MixinDocument>,
    #[serde(default)]
    pub(super) db: DbBackend,
    #[serde(default)]
    pub(super) database: Option<DatabaseDocument>,
    #[serde(default)]
    pub(super) build: Option<BuildDocument>,
    #[serde(default)]
    pub(super) clients: Option<ClientsDocument>,
    #[serde(default)]
    pub(super) logging: Option<LoggingDocument>,
    #[serde(default)]
    pub(super) runtime: Option<RuntimeDocument>,
    #[serde(default)]
    pub(super) storage: Option<StorageDocument>,
    #[serde(default)]
    pub(super) authorization: Option<AuthorizationDocument>,
    #[serde(default)]
    pub(super) tls: Option<TlsDocument>,
    #[serde(default, rename = "static")]
    pub(super) static_config: Option<StaticConfigDocument>,
    #[serde(default)]
    pub(super) security: SecurityDocument,
    #[serde(deserialize_with = "deserialize_resource_documents")]
    pub(super) resources: Vec<ResourceDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct DatabaseDocument {
    #[serde(default)]
    pub(super) engine: Option<DatabaseEngineDocument>,
    #[serde(default)]
    pub(super) resilience: Option<DatabaseResilienceDocument>,
}

#[derive(serde::Deserialize)]
pub(super) struct DatabaseEngineDocument {
    pub(super) kind: String,
    #[serde(default)]
    pub(super) path: Option<String>,
    #[serde(default)]
    pub(super) encryption_key_env: Option<String>,
    #[serde(default)]
    pub(super) encryption_key: Option<SecretRefDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct DatabaseResilienceDocument {
    #[serde(default)]
    pub(super) profile: Option<String>,
    #[serde(default)]
    pub(super) backup: Option<DatabaseBackupDocument>,
    #[serde(default)]
    pub(super) replication: Option<DatabaseReplicationDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct DatabaseBackupDocument {
    #[serde(default)]
    pub(super) required: Option<bool>,
    #[serde(default)]
    pub(super) mode: Option<String>,
    #[serde(default)]
    pub(super) target: Option<String>,
    #[serde(default)]
    pub(super) verify_restore: Option<bool>,
    #[serde(default)]
    pub(super) max_age: Option<String>,
    #[serde(default)]
    pub(super) encryption_key_env: Option<String>,
    #[serde(default)]
    pub(super) encryption_key: Option<SecretRefDocument>,
    #[serde(default)]
    pub(super) retention: Option<DatabaseBackupRetentionDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct DatabaseBackupRetentionDocument {
    #[serde(default)]
    pub(super) daily: Option<u32>,
    #[serde(default)]
    pub(super) weekly: Option<u32>,
    #[serde(default)]
    pub(super) monthly: Option<u32>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct DatabaseReplicationDocument {
    #[serde(default)]
    pub(super) mode: Option<String>,
    #[serde(default)]
    pub(super) read_routing: Option<String>,
    #[serde(default)]
    pub(super) read_url_env: Option<String>,
    #[serde(default)]
    pub(super) read_url: Option<SecretRefDocument>,
    #[serde(default)]
    pub(super) max_lag: Option<String>,
    #[serde(default)]
    pub(super) replicas_expected: Option<u32>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct SecurityDocument {
    #[serde(default)]
    pub(super) requests: Option<RequestSecurityDocument>,
    #[serde(default)]
    pub(super) cors: Option<CorsSecurityDocument>,
    #[serde(default)]
    pub(super) trusted_proxies: Option<TrustedProxiesDocument>,
    #[serde(default)]
    pub(super) rate_limits: Option<RateLimitsDocument>,
    #[serde(default)]
    pub(super) access: Option<SecurityAccessDocument>,
    #[serde(default)]
    pub(super) headers: Option<HeaderSecurityDocument>,
    #[serde(default)]
    pub(super) auth: Option<AuthSecurityDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct SecurityAccessDocument {
    #[serde(default)]
    pub(super) default_read: Option<String>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct RequestSecurityDocument {
    #[serde(default)]
    pub(super) json_max_bytes: Option<usize>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct CorsSecurityDocument {
    #[serde(default)]
    pub(super) origins: Vec<String>,
    #[serde(default)]
    pub(super) origins_env: Option<String>,
    #[serde(default)]
    pub(super) allow_credentials: Option<bool>,
    #[serde(default)]
    pub(super) allow_methods: Vec<String>,
    #[serde(default)]
    pub(super) allow_headers: Vec<String>,
    #[serde(default)]
    pub(super) expose_headers: Vec<String>,
    #[serde(default)]
    pub(super) max_age_seconds: Option<usize>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct TrustedProxiesDocument {
    #[serde(default)]
    pub(super) proxies: Vec<String>,
    #[serde(default)]
    pub(super) proxies_env: Option<String>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct RateLimitsDocument {
    #[serde(default)]
    pub(super) login: Option<RateLimitRuleDocument>,
    #[serde(default)]
    pub(super) register: Option<RateLimitRuleDocument>,
}

#[derive(serde::Deserialize)]
pub(super) struct RateLimitRuleDocument {
    pub(super) requests: u32,
    pub(super) window_seconds: u64,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct HeaderSecurityDocument {
    #[serde(default)]
    pub(super) frame_options: Option<String>,
    #[serde(default)]
    pub(super) content_type_options: Option<bool>,
    #[serde(default)]
    pub(super) referrer_policy: Option<String>,
    #[serde(default)]
    pub(super) hsts: Option<HstsDocument>,
}

#[derive(serde::Deserialize)]
pub(super) struct HstsDocument {
    pub(super) max_age_seconds: u64,
    #[serde(default)]
    pub(super) include_subdomains: bool,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AuthSecurityDocument {
    #[serde(default)]
    pub(super) issuer: Option<String>,
    #[serde(default)]
    pub(super) audience: Option<String>,
    #[serde(default)]
    pub(super) access_token_ttl_seconds: Option<i64>,
    #[serde(default)]
    pub(super) require_email_verification: Option<bool>,
    #[serde(default)]
    pub(super) verification_token_ttl_seconds: Option<i64>,
    #[serde(default)]
    pub(super) password_reset_token_ttl_seconds: Option<i64>,
    #[serde(default)]
    pub(super) jwt: Option<AuthJwtDocument>,
    #[serde(default)]
    pub(super) jwt_secret: Option<SecretRefDocument>,
    #[serde(default)]
    pub(super) claims: BTreeMap<String, AuthClaimMapValueDocument>,
    #[serde(default)]
    pub(super) session_cookie: Option<SessionCookieDocument>,
    #[serde(default)]
    pub(super) email: Option<AuthEmailDocument>,
    #[serde(default)]
    pub(super) portal: Option<AuthUiPageDocument>,
    #[serde(default)]
    pub(super) admin_dashboard: Option<AuthUiPageDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AuthJwtDocument {
    #[serde(default)]
    pub(super) algorithm: Option<String>,
    #[serde(default)]
    pub(super) active_kid: Option<String>,
    #[serde(default)]
    pub(super) signing_key: Option<SecretRefDocument>,
    #[serde(default)]
    pub(super) verification_keys: Vec<AuthJwtVerificationKeyDocument>,
}

#[derive(serde::Deserialize)]
pub(super) struct AuthJwtVerificationKeyDocument {
    pub(super) kid: String,
    pub(super) key: SecretRefDocument,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct SessionCookieDocument {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) csrf_cookie_name: Option<String>,
    #[serde(default)]
    pub(super) csrf_header_name: Option<String>,
    #[serde(default)]
    pub(super) path: Option<String>,
    #[serde(default)]
    pub(super) secure: Option<bool>,
    #[serde(default)]
    pub(super) same_site: Option<String>,
}

#[derive(serde::Deserialize)]
pub(super) struct AuthEmailDocument {
    pub(super) from_email: String,
    #[serde(default)]
    pub(super) from_name: Option<String>,
    #[serde(default)]
    pub(super) reply_to: Option<String>,
    #[serde(default)]
    pub(super) public_base_url: Option<String>,
    pub(super) provider: AuthEmailProviderDocument,
}

#[derive(serde::Deserialize)]
pub(super) struct AuthEmailProviderDocument {
    pub(super) kind: String,
    #[serde(default)]
    pub(super) api_key_env: Option<String>,
    #[serde(default)]
    pub(super) api_key: Option<SecretRefDocument>,
    #[serde(default)]
    pub(super) api_base_url: Option<String>,
    #[serde(default)]
    pub(super) connection_url_env: Option<String>,
    #[serde(default)]
    pub(super) connection_url: Option<SecretRefDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct SecretRefDocument {
    #[serde(default)]
    pub(super) env: Option<String>,
    #[serde(default)]
    pub(super) env_or_file: Option<String>,
    #[serde(default)]
    pub(super) systemd_credential: Option<String>,
    #[serde(default)]
    pub(super) external: Option<ExternalSecretRefDocument>,
}

#[derive(serde::Deserialize)]
pub(super) struct ExternalSecretRefDocument {
    pub(super) provider: String,
    pub(super) locator: String,
}

#[derive(serde::Deserialize)]
pub(super) struct AuthUiPageDocument {
    pub(super) path: String,
    #[serde(default)]
    pub(super) title: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum AuthClaimMapValueDocument {
    Type(AuthClaimTypeDocument),
    Column(String),
    Config(AuthClaimConfigDocument),
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AuthClaimConfigDocument {
    #[serde(default)]
    pub(super) column: Option<String>,
    #[serde(default, rename = "type")]
    pub(super) ty: Option<AuthClaimTypeDocument>,
}

#[derive(Clone, Copy, serde::Deserialize)]
pub(super) enum AuthClaimTypeDocument {
    String,
    I64,
    Bool,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct LoggingDocument {
    #[serde(default)]
    pub(super) filter_env: Option<String>,
    #[serde(default)]
    pub(super) default_filter: Option<String>,
    #[serde(default)]
    pub(super) timestamp: Option<String>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct BuildDocument {
    #[serde(default)]
    pub(super) target_cpu_native: Option<bool>,
    #[serde(default)]
    pub(super) release: Option<ReleaseBuildDocument>,
    #[serde(default)]
    pub(super) artifacts: Option<BuildArtifactsDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct ReleaseBuildDocument {
    #[serde(default)]
    pub(super) lto: Option<BuildLtoDocument>,
    #[serde(default)]
    pub(super) codegen_units: Option<u32>,
    #[serde(default)]
    pub(super) strip_debug_symbols: Option<bool>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct BuildArtifactsDocument {
    #[serde(default)]
    pub(super) binary: Option<BuildArtifactPathDocument>,
    #[serde(default)]
    pub(super) bundle: Option<BuildArtifactPathDocument>,
    #[serde(default)]
    pub(super) cache: Option<BuildCacheArtifactDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct BuildArtifactPathDocument {
    #[serde(default)]
    pub(super) path: Option<String>,
    #[serde(default)]
    pub(super) env: Option<String>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct ClientsDocument {
    #[serde(default)]
    pub(super) ts: Option<TsClientDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct TsClientDocument {
    #[serde(default)]
    pub(super) output_dir: Option<BuildArtifactPathDocument>,
    #[serde(default)]
    pub(super) package_name: Option<ClientValueDocument>,
    #[serde(default)]
    pub(super) server_url: Option<String>,
    #[serde(default)]
    pub(super) emit_js: Option<bool>,
    #[serde(default)]
    pub(super) include_builtin_auth: Option<bool>,
    #[serde(default)]
    pub(super) exclude_tables: Option<Vec<String>>,
    #[serde(default)]
    pub(super) automation: Option<TsClientAutomationDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct TsClientAutomationDocument {
    #[serde(default)]
    pub(super) on_build: Option<bool>,
    #[serde(default)]
    pub(super) self_test: Option<bool>,
    #[serde(default)]
    pub(super) self_test_report: Option<BuildArtifactPathDocument>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum ClientValueDocument {
    Value(String),
    Config(ClientValueConfigDocument),
}

#[derive(Default, serde::Deserialize)]
pub(super) struct ClientValueConfigDocument {
    #[serde(default)]
    pub(super) value: Option<String>,
    #[serde(default)]
    pub(super) env: Option<String>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct BuildCacheArtifactDocument {
    #[serde(default)]
    pub(super) root: Option<String>,
    #[serde(default)]
    pub(super) env: Option<String>,
    #[serde(default)]
    pub(super) cleanup: Option<String>,
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(untagged)]
pub(super) enum BuildLtoDocument {
    Bool(bool),
    Mode(BuildLtoModeDocument),
}

#[derive(Clone, Copy, serde::Deserialize)]
pub(super) enum BuildLtoModeDocument {
    Thin,
    Fat,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct RuntimeDocument {
    #[serde(default)]
    pub(super) compression: Option<CompressionDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AuthorizationDocument {
    #[serde(default)]
    pub(super) scopes: BTreeMap<String, AuthorizationScopeDocument>,
    #[serde(default)]
    pub(super) permissions: BTreeMap<String, AuthorizationPermissionDocument>,
    #[serde(default)]
    pub(super) templates: BTreeMap<String, AuthorizationTemplateDocument>,
    #[serde(default)]
    pub(super) hybrid_enforcement: Option<AuthorizationHybridEnforcementDocument>,
    #[serde(default)]
    pub(super) management_api: Option<AuthorizationManagementApiDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AuthorizationHybridEnforcementDocument {
    #[serde(default)]
    pub(super) resources: BTreeMap<String, AuthorizationHybridResourceDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AuthorizationHybridResourceDocument {
    #[serde(default)]
    pub(super) scope: Option<String>,
    #[serde(default)]
    pub(super) scope_field: Option<String>,
    #[serde(default)]
    pub(super) scope_sources: Option<AuthorizationHybridScopeSourcesDocument>,
    #[serde(default)]
    pub(super) actions: Vec<AuthorizationActionDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AuthorizationHybridScopeSourcesDocument {
    #[serde(default)]
    pub(super) item: Option<bool>,
    #[serde(default)]
    pub(super) collection_filter: Option<bool>,
    #[serde(default)]
    pub(super) nested_parent: Option<bool>,
    #[serde(default)]
    pub(super) create_payload: Option<bool>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AuthorizationManagementApiDocument {
    #[serde(default)]
    pub(super) enabled: Option<bool>,
    #[serde(default)]
    pub(super) mount: Option<String>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AuthorizationScopeDocument {
    #[serde(default)]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) parent: Option<String>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AuthorizationPermissionDocument {
    #[serde(default)]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) actions: Vec<AuthorizationActionDocument>,
    #[serde(default)]
    pub(super) resources: Vec<String>,
    #[serde(default)]
    pub(super) scopes: Vec<String>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct AuthorizationTemplateDocument {
    #[serde(default)]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) permissions: Vec<String>,
    #[serde(default)]
    pub(super) scopes: Vec<String>,
}

#[derive(Clone, Copy, serde::Deserialize)]
pub(super) enum AuthorizationActionDocument {
    Read,
    Create,
    Update,
    Delete,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct CompressionDocument {
    #[serde(default)]
    pub(super) enabled: Option<bool>,
    #[serde(default)]
    pub(super) static_precompressed: Option<bool>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct StorageDocument {
    #[serde(default)]
    pub(super) backends: Vec<StorageBackendDocument>,
    #[serde(default)]
    pub(super) public_mounts: Vec<StoragePublicMountDocument>,
    #[serde(default)]
    pub(super) uploads: Vec<StorageUploadDocument>,
    #[serde(default)]
    pub(super) s3_compat: Option<StorageS3CompatDocument>,
}

#[derive(serde::Deserialize)]
pub(super) struct StorageBackendDocument {
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) dir: String,
}

#[derive(serde::Deserialize)]
pub(super) struct StoragePublicMountDocument {
    pub(super) mount: String,
    pub(super) backend: String,
    #[serde(default)]
    pub(super) prefix: Option<String>,
    #[serde(default)]
    pub(super) cache: Option<String>,
}

#[derive(serde::Deserialize)]
pub(super) struct StorageUploadDocument {
    pub(super) name: String,
    pub(super) path: String,
    pub(super) backend: String,
    #[serde(default)]
    pub(super) prefix: Option<String>,
    #[serde(default)]
    pub(super) max_bytes: Option<usize>,
    #[serde(default)]
    pub(super) require_auth: Option<bool>,
    #[serde(default)]
    pub(super) roles: Vec<String>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct StorageS3CompatDocument {
    #[serde(default)]
    pub(super) mount: Option<String>,
    #[serde(default)]
    pub(super) buckets: Vec<StorageS3CompatBucketDocument>,
}

#[derive(serde::Deserialize)]
pub(super) struct StorageS3CompatBucketDocument {
    pub(super) name: String,
    pub(super) backend: String,
    #[serde(default)]
    pub(super) prefix: Option<String>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct TlsDocument {
    #[serde(default)]
    pub(super) cert_path: Option<String>,
    #[serde(default)]
    pub(super) key_path: Option<String>,
    #[serde(default)]
    pub(super) cert_path_env: Option<String>,
    #[serde(default)]
    pub(super) key_path_env: Option<String>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct StaticConfigDocument {
    #[serde(default)]
    pub(super) mounts: Vec<StaticMountDocument>,
}

#[derive(serde::Deserialize)]
pub(super) struct StaticMountDocument {
    pub(super) mount: String,
    pub(super) dir: String,
    #[serde(default)]
    pub(super) mode: Option<String>,
    #[serde(default)]
    pub(super) index_file: Option<String>,
    #[serde(default)]
    pub(super) fallback_file: Option<String>,
    #[serde(default)]
    pub(super) cache: Option<String>,
}

#[derive(serde::Deserialize)]
pub(super) struct ResourceDocument {
    pub(super) name: String,
    #[serde(default)]
    pub(super) table: Option<String>,
    #[serde(default)]
    pub(super) api_name: Option<String>,
    #[serde(default)]
    pub(super) id_field: Option<String>,
    #[serde(default)]
    pub(super) access: ResourceAccessDocument,
    #[serde(default)]
    pub(super) roles: RoleRequirements,
    #[serde(default)]
    pub(super) policies: RowPoliciesDocument,
    #[serde(default)]
    pub(super) list: ListConfigDocument,
    #[serde(default)]
    pub(super) api: Option<ResourceApiDocument>,
    #[serde(default, rename = "use")]
    pub(super) use_mixins: Vec<String>,
    #[serde(default)]
    pub(super) indexes: Vec<IndexDocument>,
    #[serde(default)]
    pub(super) many_to_many: Vec<ManyToManyDocument>,
    #[serde(default)]
    pub(super) actions: Vec<ResourceActionDocument>,
    #[serde(deserialize_with = "deserialize_field_documents")]
    pub(super) fields: Vec<FieldDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct ResourceAccessDocument {
    #[serde(default)]
    pub(super) read: Option<String>,
}

#[derive(Clone, serde::Deserialize)]
pub(super) struct MixinDocument {
    pub(super) name: String,
    #[serde(default)]
    pub(super) indexes: Vec<IndexDocument>,
    #[serde(default, deserialize_with = "deserialize_field_documents")]
    pub(super) fields: Vec<FieldDocument>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct ResourceApiDocument {
    #[serde(
        default,
        deserialize_with = "deserialize_api_field_projection_documents"
    )]
    pub(super) fields: Vec<ApiFieldProjectionDocument>,
    #[serde(default)]
    pub(super) default_context: Option<String>,
    #[serde(default, deserialize_with = "deserialize_response_context_documents")]
    pub(super) contexts: Vec<ResponseContextDocument>,
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResourceActionDocument {
    pub(super) name: String,
    #[serde(default)]
    pub(super) path: Option<String>,
    #[serde(default)]
    pub(super) target: Option<String>,
    #[serde(default)]
    pub(super) method: Option<String>,
    pub(super) behavior: ResourceActionBehaviorDocument,
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResourceActionBehaviorDocument {
    pub(super) kind: String,
    #[serde(default)]
    pub(super) set: BTreeMap<String, ResourceActionAssignmentValueDocument>,
}

#[derive(Clone, serde::Deserialize)]
#[serde(untagged)]
pub(super) enum ResourceActionAssignmentValueDocument {
    Input(ResourceActionInputValueDocument),
    Literal(JsonValue),
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResourceActionInputValueDocument {
    pub(super) input: String,
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManyToManyDocument {
    pub(super) name: String,
    pub(super) target: String,
    pub(super) through: String,
    pub(super) source_field: String,
    pub(super) target_field: String,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct ListConfigDocument {
    #[serde(default)]
    pub(super) default_limit: Option<u32>,
    #[serde(default)]
    pub(super) max_limit: Option<u32>,
}

#[derive(Default, serde::Deserialize)]
pub(super) struct RowPoliciesDocument {
    #[serde(default = "default_admin_bypass")]
    pub(super) admin_bypass: bool,
    #[serde(default)]
    pub(super) read: Option<FilterPoliciesDocument>,
    #[serde(default, deserialize_with = "deserialize_create_policies_document")]
    pub(super) create: Option<CreatePoliciesDocument>,
    #[serde(default)]
    pub(super) update: Option<FilterPoliciesDocument>,
    #[serde(default)]
    pub(super) delete: Option<FilterPoliciesDocument>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum CreatePoliciesDocument {
    Structured(CreatePoliciesGroupDocument),
    Assignments(ScopePoliciesDocument),
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreatePoliciesGroupDocument {
    #[serde(default)]
    pub(super) assign: Option<ScopePoliciesDocument>,
    #[serde(default)]
    pub(super) require: Option<FilterPoliciesDocument>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum FilterPoliciesDocument {
    Group(FilterPolicyGroupDocument),
    Many(Vec<FilterPoliciesDocument>),
    Single(PolicyEntryDocument),
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FilterPolicyGroupDocument {
    #[serde(default)]
    pub(super) all_of: Option<Vec<FilterPoliciesDocument>>,
    #[serde(default)]
    pub(super) any_of: Option<Vec<FilterPoliciesDocument>>,
    #[serde(default)]
    pub(super) not: Option<Box<FilterPoliciesDocument>>,
    #[serde(default)]
    pub(super) exists: Option<ExistsPolicyDocument>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum ScopePoliciesDocument {
    Many(Vec<PolicyEntryDocument>),
    Single(PolicyEntryDocument),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum PolicyEntryDocument {
    Shorthand(String),
    Rule(PolicyRuleDocument),
    Legacy(LegacyRowPolicyDocument),
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExistsPolicyDocument {
    pub(super) resource: String,
    #[serde(default, rename = "where")]
    pub(super) condition: Option<ExistsPolicyEntriesDocument>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum ExistsPolicyEntriesDocument {
    Group(ExistsPolicyGroupDocument),
    Many(Vec<ExistsPolicyEntriesDocument>),
    Single(ExistsPolicyEntryDocument),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum ExistsPolicyEntryDocument {
    Shorthand(String),
    Rule(ExistsPolicyRuleDocument),
    Legacy(LegacyRowPolicyDocument),
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExistsPolicyGroupDocument {
    #[serde(default)]
    pub(super) all_of: Option<Vec<ExistsPolicyEntriesDocument>>,
    #[serde(default)]
    pub(super) any_of: Option<Vec<ExistsPolicyEntriesDocument>>,
    #[serde(default)]
    pub(super) not: Option<Box<ExistsPolicyEntriesDocument>>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyRowPolicyDocument {
    pub(super) kind: String,
    pub(super) field: String,
}

#[derive(Clone, serde::Deserialize)]
#[serde(untagged)]
pub(super) enum PolicyComparisonValueDocument {
    String(String),
    Integer(i64),
    Bool(bool),
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyRuleDocument {
    pub(super) field: String,
    #[serde(default)]
    pub(super) equals: Option<PolicyComparisonValueDocument>,
    #[serde(default)]
    pub(super) is_null: bool,
    #[serde(default)]
    pub(super) is_not_null: bool,
    #[serde(default)]
    pub(super) value: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExistsPolicyRuleDocument {
    pub(super) field: String,
    #[serde(default)]
    pub(super) equals: Option<PolicyComparisonValueDocument>,
    #[serde(default)]
    pub(super) is_null: bool,
    #[serde(default)]
    pub(super) is_not_null: bool,
    #[serde(default)]
    pub(super) equals_field: Option<String>,
}

#[derive(Clone, serde::Deserialize)]
pub(super) struct FieldDocument {
    pub(super) name: String,
    #[serde(default)]
    pub(super) api_name: Option<String>,
    #[serde(rename = "type")]
    pub(super) ty: FieldTypeDocument,
    #[serde(default)]
    pub(super) items: Option<FieldTypeDocument>,
    #[serde(default, deserialize_with = "deserialize_field_documents")]
    pub(super) fields: Vec<FieldDocument>,
    #[serde(default)]
    pub(super) nullable: bool,
    #[serde(default)]
    pub(super) id: bool,
    #[serde(default)]
    pub(super) generated: GeneratedValue,
    #[serde(default)]
    pub(super) unique: bool,
    #[serde(default)]
    pub(super) transforms: Vec<String>,
    #[serde(default)]
    pub(super) relation: Option<RelationDocument>,
    #[serde(default, rename = "garde")]
    pub(super) validate: Option<FieldValidationDocument>,
    #[serde(default, rename = "validate")]
    pub(super) legacy_validate: Option<JsonValue>,
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IndexDocument {
    pub(super) fields: Vec<String>,
    #[serde(default)]
    pub(super) unique: bool,
}

#[derive(Clone, serde::Deserialize)]
pub(super) struct EnumDocument {
    pub(super) name: String,
    pub(super) values: Vec<String>,
}

#[derive(Clone, serde::Deserialize)]
pub(super) struct RelationDocument {
    pub(super) references: String,
    #[serde(default)]
    pub(super) on_delete: Option<String>,
    #[serde(default)]
    pub(super) nested_route: bool,
}

#[derive(Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FieldValidationDocument {
    #[serde(default)]
    pub(super) ascii: bool,
    #[serde(default)]
    pub(super) alphanumeric: bool,
    #[serde(default)]
    pub(super) email: bool,
    #[serde(default)]
    pub(super) url: bool,
    #[serde(default)]
    pub(super) ip: bool,
    #[serde(default)]
    pub(super) ipv4: bool,
    #[serde(default)]
    pub(super) ipv6: bool,
    #[serde(default)]
    pub(super) phone_number: bool,
    #[serde(default)]
    pub(super) credit_card: bool,
    #[serde(default)]
    pub(super) required: bool,
    #[serde(default)]
    pub(super) dive: bool,
    #[serde(default)]
    pub(super) contains: Option<String>,
    #[serde(default)]
    pub(super) prefix: Option<String>,
    #[serde(default)]
    pub(super) suffix: Option<String>,
    #[serde(default)]
    pub(super) pattern: Option<String>,
    #[serde(default)]
    pub(super) length: Option<LengthValidationDocument>,
    #[serde(default)]
    pub(super) range: Option<RangeValidationDocument>,
    #[serde(default)]
    pub(super) inner: Option<Box<FieldValidationDocument>>,
}

#[derive(Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LengthValidationDocument {
    #[serde(default)]
    pub(super) min: Option<usize>,
    #[serde(default)]
    pub(super) max: Option<usize>,
    #[serde(default)]
    pub(super) equal: Option<usize>,
    #[serde(default)]
    pub(super) mode: Option<String>,
}

#[derive(Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RangeValidationDocument {
    #[serde(default)]
    pub(super) min: Option<NumericBoundDocument>,
    #[serde(default)]
    pub(super) max: Option<NumericBoundDocument>,
    #[serde(default)]
    pub(super) equal: Option<NumericBoundDocument>,
}

#[derive(Clone, serde::Deserialize)]
#[serde(untagged)]
pub(super) enum NumericBoundDocument {
    Integer(i64),
    Float(f64),
}

#[derive(Clone, serde::Deserialize)]
#[serde(untagged)]
pub(super) enum FieldTypeDocument {
    Scalar(ScalarType),
    Rust(String),
}

#[derive(Clone, Copy, serde::Deserialize)]
pub(super) enum ScalarType {
    String,
    I32,
    I64,
    F32,
    F64,
    Bool,
    DateTime,
    Date,
    Time,
    Uuid,
    Decimal,
    Json,
    JsonObject,
    JsonArray,
    List,
    Object,
}

#[derive(serde::Deserialize)]
pub(super) struct ResourceMapValueDocument {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) table: Option<String>,
    #[serde(default)]
    pub(super) api_name: Option<String>,
    #[serde(default)]
    pub(super) id_field: Option<String>,
    #[serde(default)]
    pub(super) access: ResourceAccessDocument,
    #[serde(default)]
    pub(super) roles: RoleRequirements,
    #[serde(default)]
    pub(super) policies: RowPoliciesDocument,
    #[serde(default)]
    pub(super) list: ListConfigDocument,
    #[serde(default)]
    pub(super) api: Option<ResourceApiDocument>,
    #[serde(default, rename = "use")]
    pub(super) use_mixins: Vec<String>,
    #[serde(default)]
    pub(super) indexes: Vec<IndexDocument>,
    #[serde(default)]
    pub(super) many_to_many: Vec<ManyToManyDocument>,
    #[serde(default)]
    pub(super) actions: Vec<ResourceActionDocument>,
    #[serde(deserialize_with = "deserialize_field_documents")]
    pub(super) fields: Vec<FieldDocument>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum MixinMapValueDocument {
    Fields(Vec<FieldDocument>),
    Config(MixinConfigDocument),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub(super) enum FieldMapValueDocument {
    Type(FieldTypeDocument),
    Config(FieldMapConfigDocument),
}

#[derive(serde::Deserialize)]
pub(super) struct FieldMapConfigDocument {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) api_name: Option<String>,
    #[serde(rename = "type")]
    pub(super) ty: FieldTypeDocument,
    #[serde(default)]
    pub(super) items: Option<FieldTypeDocument>,
    #[serde(default, deserialize_with = "deserialize_field_documents")]
    pub(super) fields: Vec<FieldDocument>,
    #[serde(default)]
    pub(super) nullable: bool,
    #[serde(default)]
    pub(super) id: bool,
    #[serde(default)]
    pub(super) generated: GeneratedValue,
    #[serde(default)]
    pub(super) unique: bool,
    #[serde(default)]
    pub(super) transforms: Vec<String>,
    #[serde(default)]
    pub(super) relation: Option<RelationDocument>,
    #[serde(default, rename = "garde")]
    pub(super) validate: Option<FieldValidationDocument>,
    #[serde(default, rename = "validate")]
    pub(super) legacy_validate: Option<JsonValue>,
}

#[derive(Clone, serde::Deserialize)]
pub(super) struct ApiFieldProjectionDocument {
    pub(super) name: String,
    #[serde(default)]
    pub(super) from: Option<String>,
    #[serde(default)]
    pub(super) template: Option<String>,
}

#[derive(Clone, serde::Deserialize)]
pub(super) struct ResponseContextDocument {
    pub(super) name: String,
    #[serde(default)]
    pub(super) fields: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum EnumMapValueDocument {
    Values(Vec<String>),
    Config(EnumConfigDocument),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum ApiFieldProjectionMapValueDocument {
    From(String),
    Config(ApiFieldProjectionConfigDocument),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum ResponseContextMapValueDocument {
    Fields(Vec<String>),
    Config(ResponseContextConfigDocument),
}

#[derive(serde::Deserialize)]
pub(super) struct ApiFieldProjectionConfigDocument {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) from: Option<String>,
    #[serde(default)]
    pub(super) template: Option<String>,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MixinConfigDocument {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) indexes: Vec<IndexDocument>,
    #[serde(default, deserialize_with = "deserialize_field_documents")]
    pub(super) fields: Vec<FieldDocument>,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResponseContextConfigDocument {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) fields: Vec<String>,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnumConfigDocument {
    #[serde(default)]
    pub(super) name: Option<String>,
    pub(super) values: Vec<String>,
}

pub(super) fn deserialize_enum_documents<'de, D>(deserializer: D) -> Result<Vec<EnumDocument>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(EnumDocumentsVisitor)
}

pub(super) fn deserialize_mixin_documents<'de, D>(deserializer: D) -> Result<Vec<MixinDocument>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(MixinDocumentsVisitor)
}

pub(super) fn deserialize_resource_documents<'de, D>(
    deserializer: D,
) -> Result<Vec<ResourceDocument>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(ResourceDocumentsVisitor)
}

pub(super) fn deserialize_field_documents<'de, D>(deserializer: D) -> Result<Vec<FieldDocument>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(FieldDocumentsVisitor)
}

pub(super) fn deserialize_api_field_projection_documents<'de, D>(
    deserializer: D,
) -> Result<Vec<ApiFieldProjectionDocument>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(ApiFieldProjectionDocumentsVisitor)
}

pub(super) fn deserialize_response_context_documents<'de, D>(
    deserializer: D,
) -> Result<Vec<ResponseContextDocument>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(ResponseContextDocumentsVisitor)
}

impl ResourceMapValueDocument {
    fn into_document<E>(self, key: String) -> Result<ResourceDocument, E>
    where
        E: de::Error,
    {
        if let Some(name) = self.name.as_deref()
            && name != key
        {
            return Err(E::custom(format!(
                "resource map entry `{key}` has mismatched `name` value `{name}`"
            )));
        }

        Ok(ResourceDocument {
            name: key,
            table: self.table,
            api_name: self.api_name,
            id_field: self.id_field,
            access: self.access,
            roles: self.roles,
            policies: self.policies,
            list: self.list,
            api: self.api,
            use_mixins: self.use_mixins,
            indexes: self.indexes,
            many_to_many: self.many_to_many,
            actions: self.actions,
            fields: self.fields,
        })
    }
}

impl MixinMapValueDocument {
    fn into_document<E>(self, key: String) -> Result<MixinDocument, E>
    where
        E: de::Error,
    {
        match self {
            Self::Fields(fields) => Ok(MixinDocument {
                name: key,
                indexes: Vec::new(),
                fields,
            }),
            Self::Config(mixin) => mixin.into_document::<E>(key),
        }
    }
}

impl FieldMapValueDocument {
    fn into_document<E>(self, key: String) -> Result<FieldDocument, E>
    where
        E: de::Error,
    {
        match self {
            Self::Type(ty) => Ok(FieldDocument {
                name: key,
                api_name: None,
                ty,
                items: None,
                fields: Vec::new(),
                nullable: false,
                id: false,
                generated: GeneratedValue::None,
                unique: false,
                transforms: Vec::new(),
                relation: None,
                validate: None,
                legacy_validate: None,
            }),
            Self::Config(field) => field.into_document::<E>(key),
        }
    }
}

impl FieldMapConfigDocument {
    fn into_document<E>(self, key: String) -> Result<FieldDocument, E>
    where
        E: de::Error,
    {
        if let Some(name) = self.name.as_deref()
            && name != key
        {
            return Err(E::custom(format!(
                "field map entry `{key}` has mismatched `name` value `{name}`"
            )));
        }

        Ok(FieldDocument {
            name: key,
            api_name: self.api_name,
            ty: self.ty,
            items: self.items,
            fields: self.fields,
            nullable: self.nullable,
            id: self.id,
            generated: self.generated,
            unique: self.unique,
            transforms: self.transforms,
            relation: self.relation,
            validate: self.validate,
            legacy_validate: self.legacy_validate,
        })
    }
}

impl MixinConfigDocument {
    fn into_document<E>(self, key: String) -> Result<MixinDocument, E>
    where
        E: de::Error,
    {
        if let Some(name) = self.name.as_deref()
            && name != key
        {
            return Err(E::custom(format!(
                "mixin map entry `{key}` has mismatched `name` value `{name}`"
            )));
        }

        Ok(MixinDocument {
            name: key,
            indexes: self.indexes,
            fields: self.fields,
        })
    }
}

impl ApiFieldProjectionMapValueDocument {
    fn into_document<E>(self, key: String) -> Result<ApiFieldProjectionDocument, E>
    where
        E: de::Error,
    {
        match self {
            Self::From(from) => Ok(ApiFieldProjectionDocument {
                name: key,
                from: Some(from),
                template: None,
            }),
            Self::Config(config) => config.into_document::<E>(key),
        }
    }
}

impl ApiFieldProjectionConfigDocument {
    fn into_document<E>(self, key: String) -> Result<ApiFieldProjectionDocument, E>
    where
        E: de::Error,
    {
        if let Some(name) = self.name.as_deref()
            && name != key
        {
            return Err(E::custom(format!(
                "api.fields map entry `{key}` has mismatched `name` value `{name}`"
            )));
        }

        Ok(ApiFieldProjectionDocument {
            name: key,
            from: self.from,
            template: self.template,
        })
    }
}

impl ResponseContextMapValueDocument {
    fn into_document<E>(self, key: String) -> Result<ResponseContextDocument, E>
    where
        E: de::Error,
    {
        match self {
            Self::Fields(fields) => Ok(ResponseContextDocument { name: key, fields }),
            Self::Config(config) => config.into_document::<E>(key),
        }
    }
}

impl ResponseContextConfigDocument {
    fn into_document<E>(self, key: String) -> Result<ResponseContextDocument, E>
    where
        E: de::Error,
    {
        if let Some(name) = self.name.as_deref()
            && name != key
        {
            return Err(E::custom(format!(
                "api.contexts map entry `{key}` has mismatched `name` value `{name}`"
            )));
        }

        Ok(ResponseContextDocument {
            name: key,
            fields: self.fields,
        })
    }
}

impl EnumMapValueDocument {
    fn into_document<E>(self, key: String) -> Result<EnumDocument, E>
    where
        E: de::Error,
    {
        match self {
            Self::Values(values) => Ok(EnumDocument { name: key, values }),
            Self::Config(config) => config.into_document::<E>(key),
        }
    }
}

impl EnumConfigDocument {
    fn into_document<E>(self, key: String) -> Result<EnumDocument, E>
    where
        E: de::Error,
    {
        if let Some(name) = self.name.as_deref()
            && name != key
        {
            return Err(E::custom(format!(
                "enums map entry `{key}` has mismatched `name` value `{name}`"
            )));
        }

        Ok(EnumDocument {
            name: key,
            values: self.values,
        })
    }
}

pub(super) struct ResourceDocumentsVisitor;

pub(super) struct EnumDocumentsVisitor;

pub(super) struct MixinDocumentsVisitor;

impl<'de> Visitor<'de> for EnumDocumentsVisitor {
    type Value = Vec<EnumDocument>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a list or map of enum definitions")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut enums = Vec::new();
        while let Some(document) = seq.next_element::<EnumDocument>()? {
            enums.push(document);
        }
        Ok(enums)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut enums = Vec::new();

        while let Some((key, value)) = map.next_entry::<String, EnumMapValueDocument>()? {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom(format!("duplicate enum `{key}`")));
            }
            enums.push(value.into_document::<A::Error>(key)?);
        }

        Ok(enums)
    }
}

impl<'de> Visitor<'de> for MixinDocumentsVisitor {
    type Value = Vec<MixinDocument>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a list or map of mixin definitions")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut mixins = Vec::new();
        while let Some(document) = seq.next_element::<MixinDocument>()? {
            mixins.push(document);
        }
        Ok(mixins)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut mixins = Vec::new();

        while let Some((key, value)) = map.next_entry::<String, MixinMapValueDocument>()? {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom(format!("duplicate mixin `{key}`")));
            }
            mixins.push(value.into_document::<A::Error>(key)?);
        }

        Ok(mixins)
    }
}

impl<'de> Visitor<'de> for ResourceDocumentsVisitor {
    type Value = Vec<ResourceDocument>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a list or map of resource definitions")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut resources = Vec::new();
        while let Some(resource) = seq.next_element::<ResourceDocument>()? {
            resources.push(resource);
        }
        Ok(resources)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut resources = Vec::new();

        while let Some((key, value)) = map.next_entry::<String, ResourceMapValueDocument>()? {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom(format!("duplicate resource `{key}`")));
            }
            resources.push(value.into_document::<A::Error>(key)?);
        }

        Ok(resources)
    }
}

pub(super) struct FieldDocumentsVisitor;

impl<'de> Visitor<'de> for FieldDocumentsVisitor {
    type Value = Vec<FieldDocument>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a list or map of field definitions")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut fields = Vec::new();
        while let Some(field) = seq.next_element::<FieldDocument>()? {
            fields.push(field);
        }
        Ok(fields)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut fields = Vec::new();

        while let Some((key, value)) = map.next_entry::<String, FieldMapValueDocument>()? {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom(format!("duplicate field `{key}`")));
            }
            fields.push(value.into_document::<A::Error>(key)?);
        }

        Ok(fields)
    }
}

pub(super) struct ApiFieldProjectionDocumentsVisitor;

impl<'de> Visitor<'de> for ApiFieldProjectionDocumentsVisitor {
    type Value = Vec<ApiFieldProjectionDocument>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a list or map of api field projection definitions")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut fields = Vec::new();
        while let Some(field) = seq.next_element::<ApiFieldProjectionDocument>()? {
            fields.push(field);
        }
        Ok(fields)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut fields = Vec::new();

        while let Some((key, value)) =
            map.next_entry::<String, ApiFieldProjectionMapValueDocument>()?
        {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom(format!(
                    "duplicate api field projection `{key}`"
                )));
            }
            fields.push(value.into_document::<A::Error>(key)?);
        }

        Ok(fields)
    }
}

pub(super) struct ResponseContextDocumentsVisitor;

impl<'de> Visitor<'de> for ResponseContextDocumentsVisitor {
    type Value = Vec<ResponseContextDocument>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a list or map of response context definitions")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut contexts = Vec::new();
        while let Some(context) = seq.next_element::<ResponseContextDocument>()? {
            contexts.push(context);
        }
        Ok(contexts)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut contexts = Vec::new();

        while let Some((key, value)) =
            map.next_entry::<String, ResponseContextMapValueDocument>()?
        {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom(format!(
                    "duplicate response context `{key}`"
                )));
            }
            contexts.push(value.into_document::<A::Error>(key)?);
        }

        Ok(contexts)
    }
}
