use std::collections::{BTreeMap, HashSet};

use serde::de::{self, Deserializer, Error as _, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use ts_rs::TS;

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub enum DbBackendDocument {
    #[default]
    Sqlite,
    Postgres,
    Mysql,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub enum GeneratedValueDocument {
    #[default]
    None,
    AutoIncrement,
    CreatedAt,
    UpdatedAt,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct RoleRequirementsDocument {
    #[serde(default)]
    pub read: Option<String>,
    #[serde(default)]
    pub create: Option<String>,
    #[serde(default)]
    pub update: Option<String>,
    #[serde(default)]
    pub delete: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct ServiceDocument {
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default, deserialize_with = "deserialize_enum_documents")]
    pub enums: Vec<EnumDocument>,
    #[serde(default, deserialize_with = "deserialize_mixin_documents")]
    pub mixins: Vec<MixinDocument>,
    #[serde(default)]
    pub db: DbBackendDocument,
    #[serde(default)]
    pub database: Option<DatabaseDocument>,
    #[serde(default)]
    pub build: Option<BuildDocument>,
    #[serde(default)]
    pub clients: Option<ClientsDocument>,
    #[serde(default)]
    pub logging: Option<LoggingDocument>,
    #[serde(default)]
    pub runtime: Option<RuntimeDocument>,
    #[serde(default)]
    pub storage: Option<StorageDocument>,
    #[serde(default)]
    pub authorization: Option<AuthorizationDocument>,
    #[serde(default)]
    pub tls: Option<TlsDocument>,
    #[serde(default, rename = "static")]
    pub static_config: Option<StaticConfigDocument>,
    #[serde(default)]
    pub security: SecurityDocument,
    #[serde(default, deserialize_with = "deserialize_resource_documents")]
    pub resources: Vec<ResourceDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct DatabaseDocument {
    #[serde(default)]
    pub engine: Option<DatabaseEngineDocument>,
    #[serde(default)]
    pub resilience: Option<DatabaseResilienceDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct DatabaseEngineDocument {
    pub kind: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub encryption_key_env: Option<String>,
    #[serde(default)]
    pub encryption_key: Option<SecretRefDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct DatabaseResilienceDocument {
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub backup: Option<DatabaseBackupDocument>,
    #[serde(default)]
    pub replication: Option<DatabaseReplicationDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct DatabaseBackupDocument {
    #[serde(default)]
    pub required: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub verify_restore: Option<bool>,
    #[serde(default)]
    pub max_age: Option<String>,
    #[serde(default)]
    pub encryption_key_env: Option<String>,
    #[serde(default)]
    pub encryption_key: Option<SecretRefDocument>,
    #[serde(default)]
    pub retention: Option<DatabaseBackupRetentionDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct DatabaseBackupRetentionDocument {
    #[serde(default)]
    pub daily: Option<u32>,
    #[serde(default)]
    pub weekly: Option<u32>,
    #[serde(default)]
    pub monthly: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct DatabaseReplicationDocument {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub read_routing: Option<String>,
    #[serde(default)]
    pub read_url_env: Option<String>,
    #[serde(default)]
    pub read_url: Option<SecretRefDocument>,
    #[serde(default)]
    pub max_lag: Option<String>,
    #[serde(default)]
    pub replicas_expected: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct SecurityDocument {
    #[serde(default)]
    pub requests: Option<RequestSecurityDocument>,
    #[serde(default)]
    pub cors: Option<CorsSecurityDocument>,
    #[serde(default)]
    pub trusted_proxies: Option<TrustedProxiesDocument>,
    #[serde(default)]
    pub rate_limits: Option<RateLimitsDocument>,
    #[serde(default)]
    pub access: Option<SecurityAccessDocument>,
    #[serde(default)]
    pub headers: Option<HeaderSecurityDocument>,
    #[serde(default)]
    pub auth: Option<AuthSecurityDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct SecurityAccessDocument {
    #[serde(default)]
    pub default_read: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct RequestSecurityDocument {
    #[serde(default)]
    pub json_max_bytes: Option<usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct CorsSecurityDocument {
    #[serde(default)]
    pub origins: Vec<String>,
    #[serde(default)]
    pub origins_env: Option<String>,
    #[serde(default)]
    pub allow_credentials: Option<bool>,
    #[serde(default)]
    pub allow_methods: Vec<String>,
    #[serde(default)]
    pub allow_headers: Vec<String>,
    #[serde(default)]
    pub expose_headers: Vec<String>,
    #[serde(default)]
    pub max_age_seconds: Option<usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct TrustedProxiesDocument {
    #[serde(default)]
    pub proxies: Vec<String>,
    #[serde(default)]
    pub proxies_env: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct RateLimitsDocument {
    #[serde(default)]
    pub login: Option<RateLimitRuleDocument>,
    #[serde(default)]
    pub register: Option<RateLimitRuleDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct RateLimitRuleDocument {
    pub requests: u32,
    pub window_seconds: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct HeaderSecurityDocument {
    #[serde(default)]
    pub frame_options: Option<String>,
    #[serde(default)]
    pub content_type_options: Option<bool>,
    #[serde(default)]
    pub referrer_policy: Option<String>,
    #[serde(default)]
    pub hsts: Option<HstsDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct HstsDocument {
    pub max_age_seconds: u64,
    #[serde(default)]
    pub include_subdomains: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthSecurityDocument {
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub access_token_ttl_seconds: Option<i64>,
    #[serde(default)]
    pub require_email_verification: Option<bool>,
    #[serde(default)]
    pub verification_token_ttl_seconds: Option<i64>,
    #[serde(default)]
    pub password_reset_token_ttl_seconds: Option<i64>,
    #[serde(default)]
    pub jwt: Option<AuthJwtDocument>,
    #[serde(default)]
    pub jwt_secret: Option<SecretRefDocument>,
    #[serde(default)]
    pub claims: BTreeMap<String, AuthClaimMapValueDocument>,
    #[serde(default)]
    pub session_cookie: Option<SessionCookieDocument>,
    #[serde(default)]
    pub email: Option<AuthEmailDocument>,
    #[serde(default)]
    pub portal: Option<AuthUiPageDocument>,
    #[serde(default)]
    pub admin_dashboard: Option<AuthUiPageDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthJwtDocument {
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub active_kid: Option<String>,
    #[serde(default)]
    pub signing_key: Option<SecretRefDocument>,
    #[serde(default)]
    pub verification_keys: Vec<AuthJwtVerificationKeyDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthJwtVerificationKeyDocument {
    pub kid: String,
    pub key: SecretRefDocument,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct SessionCookieDocument {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub csrf_cookie_name: Option<String>,
    #[serde(default)]
    pub csrf_header_name: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub secure: Option<bool>,
    #[serde(default)]
    pub same_site: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthEmailDocument {
    pub from_email: String,
    #[serde(default)]
    pub from_name: Option<String>,
    #[serde(default)]
    pub reply_to: Option<String>,
    #[serde(default)]
    pub public_base_url: Option<String>,
    pub provider: AuthEmailProviderDocument,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthEmailProviderDocument {
    pub kind: String,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default)]
    pub api_key: Option<SecretRefDocument>,
    #[serde(default)]
    pub api_base_url: Option<String>,
    #[serde(default)]
    pub connection_url_env: Option<String>,
    #[serde(default)]
    pub connection_url: Option<SecretRefDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct SecretRefDocument {
    #[serde(default)]
    pub env: Option<String>,
    #[serde(default)]
    pub env_or_file: Option<String>,
    #[serde(default)]
    pub systemd_credential: Option<String>,
    #[serde(default)]
    pub external: Option<ExternalSecretRefDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct ExternalSecretRefDocument {
    pub provider: String,
    pub locator: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthUiPageDocument {
    pub path: String,
    #[serde(default)]
    pub title: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum AuthClaimMapValueDocument {
    Type(AuthClaimTypeDocument),
    Column(String),
    Config(AuthClaimConfigDocument),
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthClaimConfigDocument {
    #[serde(default)]
    pub column: Option<String>,
    #[serde(default, rename = "type")]
    pub ty: Option<AuthClaimTypeDocument>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, TS)]
pub enum AuthClaimTypeDocument {
    String,
    I64,
    Bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct LoggingDocument {
    #[serde(default)]
    pub filter_env: Option<String>,
    #[serde(default)]
    pub default_filter: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct BuildDocument {
    #[serde(default)]
    pub target_cpu_native: Option<bool>,
    #[serde(default)]
    pub release: Option<ReleaseBuildDocument>,
    #[serde(default)]
    pub artifacts: Option<BuildArtifactsDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct ReleaseBuildDocument {
    #[serde(default)]
    pub lto: Option<BuildLtoDocument>,
    #[serde(default)]
    pub codegen_units: Option<u32>,
    #[serde(default)]
    pub strip_debug_symbols: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct BuildArtifactsDocument {
    #[serde(default)]
    pub binary: Option<BuildArtifactPathDocument>,
    #[serde(default)]
    pub bundle: Option<BuildArtifactPathDocument>,
    #[serde(default)]
    pub cache: Option<BuildCacheArtifactDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct BuildArtifactPathDocument {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub env: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct ClientsDocument {
    #[serde(default)]
    pub ts: Option<TsClientDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct TsClientDocument {
    #[serde(default)]
    pub output_dir: Option<BuildArtifactPathDocument>,
    #[serde(default)]
    pub package_name: Option<ClientValueDocument>,
    #[serde(default)]
    pub server_url: Option<String>,
    #[serde(default)]
    pub emit_js: Option<bool>,
    #[serde(default)]
    pub include_builtin_auth: Option<bool>,
    #[serde(default)]
    pub exclude_tables: Option<Vec<String>>,
    #[serde(default)]
    pub automation: Option<TsClientAutomationDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct TsClientAutomationDocument {
    #[serde(default)]
    pub on_build: Option<bool>,
    #[serde(default)]
    pub self_test: Option<bool>,
    #[serde(default)]
    pub self_test_report: Option<BuildArtifactPathDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum ClientValueDocument {
    Value(String),
    Config(ClientValueConfigDocument),
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct ClientValueConfigDocument {
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub env: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct BuildCacheArtifactDocument {
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub env: Option<String>,
    #[serde(default)]
    pub cleanup: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum BuildLtoDocument {
    Bool(bool),
    Mode(BuildLtoModeDocument),
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, TS)]
pub enum BuildLtoModeDocument {
    Thin,
    Fat,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct RuntimeDocument {
    #[serde(default)]
    pub compression: Option<CompressionDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthorizationDocument {
    #[serde(default)]
    pub scopes: BTreeMap<String, AuthorizationScopeDocument>,
    #[serde(default)]
    pub permissions: BTreeMap<String, AuthorizationPermissionDocument>,
    #[serde(default)]
    pub templates: BTreeMap<String, AuthorizationTemplateDocument>,
    #[serde(default)]
    pub hybrid_enforcement: Option<AuthorizationHybridEnforcementDocument>,
    #[serde(default)]
    pub management_api: Option<AuthorizationManagementApiDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthorizationHybridEnforcementDocument {
    #[serde(default)]
    pub resources: BTreeMap<String, AuthorizationHybridResourceDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthorizationHybridResourceDocument {
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub scope_field: Option<String>,
    #[serde(default)]
    pub scope_sources: Option<AuthorizationHybridScopeSourcesDocument>,
    #[serde(default)]
    pub actions: Vec<AuthorizationActionDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthorizationHybridScopeSourcesDocument {
    #[serde(default)]
    pub item: Option<bool>,
    #[serde(default)]
    pub collection_filter: Option<bool>,
    #[serde(default)]
    pub nested_parent: Option<bool>,
    #[serde(default)]
    pub create_payload: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthorizationManagementApiDocument {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub mount: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthorizationScopeDocument {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub parent: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthorizationPermissionDocument {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub actions: Vec<AuthorizationActionDocument>,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct AuthorizationTemplateDocument {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, TS)]
pub enum AuthorizationActionDocument {
    Read,
    Create,
    Update,
    Delete,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct CompressionDocument {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub static_precompressed: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct StorageDocument {
    #[serde(default)]
    pub backends: Vec<StorageBackendDocument>,
    #[serde(default)]
    pub public_mounts: Vec<StoragePublicMountDocument>,
    #[serde(default)]
    pub uploads: Vec<StorageUploadDocument>,
    #[serde(default)]
    pub s3_compat: Option<StorageS3CompatDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct StorageBackendDocument {
    pub name: String,
    pub kind: String,
    pub dir: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct StoragePublicMountDocument {
    pub mount: String,
    pub backend: String,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub cache: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct StorageUploadDocument {
    pub name: String,
    pub path: String,
    pub backend: String,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
    #[serde(default)]
    pub require_auth: Option<bool>,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct StorageS3CompatDocument {
    #[serde(default)]
    pub mount: Option<String>,
    #[serde(default)]
    pub buckets: Vec<StorageS3CompatBucketDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct StorageS3CompatBucketDocument {
    pub name: String,
    pub backend: String,
    #[serde(default)]
    pub prefix: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct TlsDocument {
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub cert_path_env: Option<String>,
    #[serde(default)]
    pub key_path_env: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct StaticConfigDocument {
    #[serde(default)]
    pub mounts: Vec<StaticMountDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct StaticMountDocument {
    pub mount: String,
    pub dir: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub index_file: Option<String>,
    #[serde(default)]
    pub fallback_file: Option<String>,
    #[serde(default)]
    pub cache: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct ResourceDocument {
    pub name: String,
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub api_name: Option<String>,
    #[serde(default)]
    pub id_field: Option<String>,
    #[serde(default)]
    pub access: ResourceAccessDocument,
    #[serde(default)]
    pub roles: RoleRequirementsDocument,
    #[serde(default)]
    pub policies: RowPoliciesDocument,
    #[serde(default)]
    pub list: ListConfigDocument,
    #[serde(default)]
    pub api: Option<ResourceApiDocument>,
    #[serde(default, rename = "use")]
    pub use_mixins: Vec<String>,
    #[serde(default)]
    pub indexes: Vec<IndexDocument>,
    #[serde(default)]
    pub many_to_many: Vec<ManyToManyDocument>,
    #[serde(default)]
    pub actions: Vec<ResourceActionDocument>,
    #[serde(default, deserialize_with = "deserialize_field_documents")]
    pub fields: Vec<FieldDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct ResourceAccessDocument {
    #[serde(default)]
    pub read: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct MixinDocument {
    pub name: String,
    #[serde(default)]
    pub indexes: Vec<IndexDocument>,
    #[serde(default, deserialize_with = "deserialize_field_documents")]
    pub fields: Vec<FieldDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct ResourceApiDocument {
    #[serde(
        default,
        deserialize_with = "deserialize_api_field_projection_documents"
    )]
    pub fields: Vec<ApiFieldProjectionDocument>,
    #[serde(default)]
    pub default_context: Option<String>,
    #[serde(default, deserialize_with = "deserialize_response_context_documents")]
    pub contexts: Vec<ResponseContextDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ResourceActionDocument {
    pub name: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    pub behavior: ResourceActionBehaviorDocument,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ResourceActionBehaviorDocument {
    pub kind: String,
    #[serde(default)]
    pub set: BTreeMap<String, ResourceActionAssignmentValueDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum ResourceActionAssignmentValueDocument {
    Input(ResourceActionInputValueDocument),
    Literal(JsonValue),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ResourceActionInputValueDocument {
    pub input: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ManyToManyDocument {
    pub name: String,
    pub target: String,
    pub through: String,
    pub source_field: String,
    pub target_field: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct ListConfigDocument {
    #[serde(default)]
    pub default_limit: Option<u32>,
    #[serde(default)]
    pub max_limit: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct RowPoliciesDocument {
    #[serde(default = "default_admin_bypass")]
    pub admin_bypass: bool,
    #[serde(default)]
    pub read: Option<FilterPoliciesDocument>,
    #[serde(default, deserialize_with = "deserialize_create_policies_document")]
    pub create: Option<CreatePoliciesDocument>,
    #[serde(default)]
    pub update: Option<FilterPoliciesDocument>,
    #[serde(default)]
    pub delete: Option<FilterPoliciesDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum CreatePoliciesDocument {
    Structured(CreatePoliciesGroupDocument),
    Assignments(ScopePoliciesDocument),
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CreatePoliciesGroupDocument {
    #[serde(default)]
    pub assign: Option<ScopePoliciesDocument>,
    #[serde(default)]
    pub require: Option<FilterPoliciesDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum FilterPoliciesDocument {
    Group(FilterPolicyGroupDocument),
    Many(Vec<FilterPoliciesDocument>),
    Single(PolicyEntryDocument),
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct FilterPolicyGroupDocument {
    #[serde(default)]
    pub all_of: Option<Vec<FilterPoliciesDocument>>,
    #[serde(default)]
    pub any_of: Option<Vec<FilterPoliciesDocument>>,
    #[serde(default)]
    pub not: Option<Box<FilterPoliciesDocument>>,
    #[serde(default)]
    pub exists: Option<ExistsPolicyDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum ScopePoliciesDocument {
    Many(Vec<PolicyEntryDocument>),
    Single(PolicyEntryDocument),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum PolicyEntryDocument {
    Shorthand(String),
    Rule(PolicyRuleDocument),
    Legacy(LegacyRowPolicyDocument),
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ExistsPolicyDocument {
    pub resource: String,
    #[serde(default, rename = "where")]
    pub condition: Option<ExistsPolicyEntriesDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum ExistsPolicyEntriesDocument {
    Group(ExistsPolicyGroupDocument),
    Many(Vec<ExistsPolicyEntriesDocument>),
    Single(ExistsPolicyEntryDocument),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum ExistsPolicyEntryDocument {
    Shorthand(String),
    Rule(ExistsPolicyRuleDocument),
    Legacy(LegacyRowPolicyDocument),
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ExistsPolicyGroupDocument {
    #[serde(default)]
    pub all_of: Option<Vec<ExistsPolicyEntriesDocument>>,
    #[serde(default)]
    pub any_of: Option<Vec<ExistsPolicyEntriesDocument>>,
    #[serde(default)]
    pub not: Option<Box<ExistsPolicyEntriesDocument>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct LegacyRowPolicyDocument {
    pub kind: String,
    pub field: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum PolicyComparisonValueDocument {
    String(String),
    Integer(i64),
    Bool(bool),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuleDocument {
    pub field: String,
    #[serde(default)]
    pub equals: Option<PolicyComparisonValueDocument>,
    #[serde(default)]
    pub is_null: bool,
    #[serde(default)]
    pub is_not_null: bool,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ExistsPolicyRuleDocument {
    pub field: String,
    #[serde(default)]
    pub equals: Option<PolicyComparisonValueDocument>,
    #[serde(default)]
    pub is_null: bool,
    #[serde(default)]
    pub is_not_null: bool,
    #[serde(default)]
    pub equals_field: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct FieldDocument {
    pub name: String,
    #[serde(default)]
    pub api_name: Option<String>,
    #[serde(rename = "type")]
    pub ty: FieldTypeDocument,
    #[serde(default)]
    pub items: Option<FieldTypeDocument>,
    #[serde(default, deserialize_with = "deserialize_field_documents")]
    pub fields: Vec<FieldDocument>,
    #[serde(default)]
    pub nullable: bool,
    #[serde(default)]
    pub id: bool,
    #[serde(default)]
    pub generated: GeneratedValueDocument,
    #[serde(default)]
    pub unique: bool,
    #[serde(default)]
    pub transforms: Vec<String>,
    #[serde(default)]
    pub relation: Option<RelationDocument>,
    #[serde(default)]
    pub validate: Option<FieldValidationDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct IndexDocument {
    pub fields: Vec<String>,
    #[serde(default)]
    pub unique: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct EnumDocument {
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct RelationDocument {
    pub references: String,
    #[serde(default)]
    pub on_delete: Option<String>,
    #[serde(default)]
    pub nested_route: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct FieldValidationDocument {
    #[serde(default)]
    pub min_length: Option<usize>,
    #[serde(default)]
    pub max_length: Option<usize>,
    #[serde(default)]
    pub minimum: Option<NumericBoundDocument>,
    #[serde(default)]
    pub maximum: Option<NumericBoundDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum NumericBoundDocument {
    Integer(i64),
    Float(f64),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum FieldTypeDocument {
    Scalar(ScalarTypeDocument),
    Rust(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, TS)]
pub enum ScalarTypeDocument {
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct ResourceMapValueDocument {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub api_name: Option<String>,
    #[serde(default)]
    pub id_field: Option<String>,
    #[serde(default)]
    pub access: ResourceAccessDocument,
    #[serde(default)]
    pub roles: RoleRequirementsDocument,
    #[serde(default)]
    pub policies: RowPoliciesDocument,
    #[serde(default)]
    pub list: ListConfigDocument,
    #[serde(default)]
    pub api: Option<ResourceApiDocument>,
    #[serde(default, rename = "use")]
    pub use_mixins: Vec<String>,
    #[serde(default)]
    pub indexes: Vec<IndexDocument>,
    #[serde(default)]
    pub many_to_many: Vec<ManyToManyDocument>,
    #[serde(default)]
    pub actions: Vec<ResourceActionDocument>,
    #[serde(default, deserialize_with = "deserialize_field_documents")]
    pub fields: Vec<FieldDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum MixinMapValueDocument {
    Fields(Vec<FieldDocument>),
    Config(MixinConfigDocument),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum FieldMapValueDocument {
    Type(FieldTypeDocument),
    Config(FieldMapConfigDocument),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct FieldMapConfigDocument {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub api_name: Option<String>,
    #[serde(rename = "type")]
    pub ty: FieldTypeDocument,
    #[serde(default)]
    pub items: Option<FieldTypeDocument>,
    #[serde(default, deserialize_with = "deserialize_field_documents")]
    pub fields: Vec<FieldDocument>,
    #[serde(default)]
    pub nullable: bool,
    #[serde(default)]
    pub id: bool,
    #[serde(default)]
    pub generated: GeneratedValueDocument,
    #[serde(default)]
    pub unique: bool,
    #[serde(default)]
    pub transforms: Vec<String>,
    #[serde(default)]
    pub relation: Option<RelationDocument>,
    #[serde(default)]
    pub validate: Option<FieldValidationDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct ApiFieldProjectionDocument {
    pub name: String,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub template: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct ResponseContextDocument {
    pub name: String,
    #[serde(default)]
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum EnumMapValueDocument {
    Values(Vec<String>),
    Config(EnumConfigDocument),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum ApiFieldProjectionMapValueDocument {
    From(String),
    Config(ApiFieldProjectionConfigDocument),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum ResponseContextMapValueDocument {
    Fields(Vec<String>),
    Config(ResponseContextConfigDocument),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct ApiFieldProjectionConfigDocument {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub template: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct MixinConfigDocument {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub indexes: Vec<IndexDocument>,
    #[serde(default, deserialize_with = "deserialize_field_documents")]
    pub fields: Vec<FieldDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ResponseContextConfigDocument {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct EnumConfigDocument {
    #[serde(default)]
    pub name: Option<String>,
    pub values: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct ServiceInputDocument {
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub enums: Option<EnumDocumentsInput>,
    #[serde(default)]
    pub mixins: Option<MixinDocumentsInput>,
    #[serde(default)]
    pub db: DbBackendDocument,
    #[serde(default)]
    pub database: Option<DatabaseDocument>,
    #[serde(default)]
    pub build: Option<BuildDocument>,
    #[serde(default)]
    pub clients: Option<ClientsDocument>,
    #[serde(default)]
    pub logging: Option<LoggingDocument>,
    #[serde(default)]
    pub runtime: Option<RuntimeDocument>,
    #[serde(default)]
    pub storage: Option<StorageDocument>,
    #[serde(default)]
    pub authorization: Option<AuthorizationDocument>,
    #[serde(default)]
    pub tls: Option<TlsDocument>,
    #[serde(default, rename = "static")]
    pub static_config: Option<StaticConfigDocument>,
    #[serde(default)]
    pub security: SecurityDocument,
    pub resources: ResourceDocumentsInput,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum EnumDocumentsInput {
    List(Vec<EnumDocument>),
    Map(BTreeMap<String, EnumMapValueDocument>),
}

impl Default for EnumDocumentsInput {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum MixinDocumentsInput {
    List(Vec<MixinInputDocument>),
    Map(BTreeMap<String, MixinMapValueInputDocument>),
}

impl Default for MixinDocumentsInput {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct MixinInputDocument {
    pub name: String,
    #[serde(default)]
    pub indexes: Vec<IndexDocument>,
    #[serde(default)]
    pub fields: FieldDocumentsInput,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum MixinMapValueInputDocument {
    Fields(Vec<FieldInputDocument>),
    Config(MixinConfigInputDocument),
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct MixinConfigInputDocument {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub indexes: Vec<IndexDocument>,
    #[serde(default)]
    pub fields: FieldDocumentsInput,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum ResourceDocumentsInput {
    List(Vec<ResourceInputDocument>),
    Map(BTreeMap<String, ResourceMapValueInputDocument>),
}

impl Default for ResourceDocumentsInput {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct ResourceInputDocument {
    pub name: String,
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub api_name: Option<String>,
    #[serde(default)]
    pub id_field: Option<String>,
    #[serde(default)]
    pub access: ResourceAccessDocument,
    #[serde(default)]
    pub roles: RoleRequirementsDocument,
    #[serde(default)]
    pub policies: RowPoliciesDocument,
    #[serde(default)]
    pub list: ListConfigDocument,
    #[serde(default)]
    pub api: Option<ResourceApiInputDocument>,
    #[serde(default, rename = "use")]
    pub use_mixins: Vec<String>,
    #[serde(default)]
    pub indexes: Vec<IndexDocument>,
    #[serde(default)]
    pub many_to_many: Vec<ManyToManyDocument>,
    #[serde(default)]
    pub actions: Vec<ResourceActionDocument>,
    pub fields: FieldDocumentsInput,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct ResourceMapValueInputDocument {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub api_name: Option<String>,
    #[serde(default)]
    pub id_field: Option<String>,
    #[serde(default)]
    pub access: ResourceAccessDocument,
    #[serde(default)]
    pub roles: RoleRequirementsDocument,
    #[serde(default)]
    pub policies: RowPoliciesDocument,
    #[serde(default)]
    pub list: ListConfigDocument,
    #[serde(default)]
    pub api: Option<ResourceApiInputDocument>,
    #[serde(default, rename = "use")]
    pub use_mixins: Vec<String>,
    #[serde(default)]
    pub indexes: Vec<IndexDocument>,
    #[serde(default)]
    pub many_to_many: Vec<ManyToManyDocument>,
    #[serde(default)]
    pub actions: Vec<ResourceActionDocument>,
    pub fields: FieldDocumentsInput,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct ResourceApiInputDocument {
    #[serde(default)]
    pub fields: ApiFieldProjectionDocumentsInput,
    #[serde(default)]
    pub default_context: Option<String>,
    #[serde(default)]
    pub contexts: ResponseContextDocumentsInput,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum FieldDocumentsInput {
    List(Vec<FieldInputDocument>),
    Map(BTreeMap<String, FieldMapValueInputDocument>),
}

impl Default for FieldDocumentsInput {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct FieldInputDocument {
    pub name: String,
    #[serde(default)]
    pub api_name: Option<String>,
    #[serde(rename = "type")]
    pub ty: FieldTypeDocument,
    #[serde(default)]
    pub items: Option<FieldTypeDocument>,
    #[serde(default)]
    pub fields: FieldDocumentsInput,
    #[serde(default)]
    pub nullable: bool,
    #[serde(default)]
    pub id: bool,
    #[serde(default)]
    pub generated: GeneratedValueDocument,
    #[serde(default)]
    pub unique: bool,
    #[serde(default)]
    pub transforms: Vec<String>,
    #[serde(default)]
    pub relation: Option<RelationDocument>,
    #[serde(default)]
    pub validate: Option<FieldValidationDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum FieldMapValueInputDocument {
    Type(FieldTypeDocument),
    Config(FieldMapConfigInputDocument),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
pub struct FieldMapConfigInputDocument {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub api_name: Option<String>,
    #[serde(rename = "type")]
    pub ty: FieldTypeDocument,
    #[serde(default)]
    pub items: Option<FieldTypeDocument>,
    #[serde(default)]
    pub fields: FieldDocumentsInput,
    #[serde(default)]
    pub nullable: bool,
    #[serde(default)]
    pub id: bool,
    #[serde(default)]
    pub generated: GeneratedValueDocument,
    #[serde(default)]
    pub unique: bool,
    #[serde(default)]
    pub transforms: Vec<String>,
    #[serde(default)]
    pub relation: Option<RelationDocument>,
    #[serde(default)]
    pub validate: Option<FieldValidationDocument>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum ApiFieldProjectionDocumentsInput {
    List(Vec<ApiFieldProjectionDocument>),
    Map(BTreeMap<String, ApiFieldProjectionMapValueDocument>),
}

impl Default for ApiFieldProjectionDocumentsInput {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(untagged)]
pub enum ResponseContextDocumentsInput {
    List(Vec<ResponseContextDocument>),
    Map(BTreeMap<String, ResponseContextMapValueDocument>),
}

impl Default for ResponseContextDocumentsInput {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

pub fn normalize_input_document(input: ServiceInputDocument) -> Result<ServiceDocument, String> {
    Ok(ServiceDocument {
        module: input.module,
        enums: normalize_enum_documents(input.enums.unwrap_or_default())?,
        mixins: normalize_mixin_documents(input.mixins.unwrap_or_default())?,
        db: input.db,
        database: input.database,
        build: input.build,
        clients: input.clients,
        logging: input.logging,
        runtime: input.runtime,
        storage: input.storage,
        authorization: input.authorization,
        tls: input.tls,
        static_config: input.static_config,
        security: input.security,
        resources: normalize_resource_documents(input.resources)?,
    })
}

pub fn render_input_document_to_eon(input: ServiceInputDocument) -> Result<String, String> {
    let document = normalize_input_document(input)?;
    render_canonical_eon(&document)
}

fn normalize_enum_documents(input: EnumDocumentsInput) -> Result<Vec<EnumDocument>, String> {
    match input {
        EnumDocumentsInput::List(values) => Ok(values),
        EnumDocumentsInput::Map(values) => values
            .into_iter()
            .map(|(key, value)| {
                value
                    .into_document::<serde::de::value::Error>(key)
                    .map_err(|error| error.to_string())
            })
            .collect(),
    }
}

fn normalize_mixin_documents(input: MixinDocumentsInput) -> Result<Vec<MixinDocument>, String> {
    match input {
        MixinDocumentsInput::List(values) => values
            .into_iter()
            .map(normalize_mixin_input_document)
            .collect(),
        MixinDocumentsInput::Map(values) => values
            .into_iter()
            .map(|(key, value)| {
                let mixin = value
                    .into_input_document::<serde::de::value::Error>(key)
                    .map_err(|error| error.to_string())?;
                normalize_mixin_input_document(mixin)
            })
            .collect(),
    }
}

fn normalize_mixin_input_document(input: MixinInputDocument) -> Result<MixinDocument, String> {
    Ok(MixinDocument {
        name: input.name,
        indexes: input.indexes,
        fields: normalize_field_documents(input.fields)?,
    })
}

fn normalize_resource_documents(
    input: ResourceDocumentsInput,
) -> Result<Vec<ResourceDocument>, String> {
    match input {
        ResourceDocumentsInput::List(values) => values
            .into_iter()
            .map(normalize_resource_input_document)
            .collect(),
        ResourceDocumentsInput::Map(values) => values
            .into_iter()
            .map(|(key, value)| {
                let resource = value
                    .into_input_document::<serde::de::value::Error>(key)
                    .map_err(|error| error.to_string())?;
                normalize_resource_input_document(resource)
            })
            .collect(),
    }
}

fn normalize_resource_input_document(
    input: ResourceInputDocument,
) -> Result<ResourceDocument, String> {
    Ok(ResourceDocument {
        name: input.name,
        table: input.table,
        api_name: input.api_name,
        id_field: input.id_field,
        access: input.access,
        roles: input.roles,
        policies: input.policies,
        list: input.list,
        api: input
            .api
            .map(normalize_resource_api_input_document)
            .transpose()?,
        use_mixins: input.use_mixins,
        indexes: input.indexes,
        many_to_many: input.many_to_many,
        actions: input.actions,
        fields: normalize_field_documents(input.fields)?,
    })
}

fn normalize_resource_api_input_document(
    input: ResourceApiInputDocument,
) -> Result<ResourceApiDocument, String> {
    Ok(ResourceApiDocument {
        fields: normalize_api_field_projection_documents(input.fields)?,
        default_context: input.default_context,
        contexts: normalize_response_context_documents(input.contexts)?,
    })
}

fn normalize_field_documents(input: FieldDocumentsInput) -> Result<Vec<FieldDocument>, String> {
    match input {
        FieldDocumentsInput::List(values) => values
            .into_iter()
            .map(normalize_field_input_document)
            .collect(),
        FieldDocumentsInput::Map(values) => values
            .into_iter()
            .map(|(key, value)| {
                let field = value
                    .into_input_document::<serde::de::value::Error>(key)
                    .map_err(|error| error.to_string())?;
                normalize_field_input_document(field)
            })
            .collect(),
    }
}

fn normalize_field_input_document(input: FieldInputDocument) -> Result<FieldDocument, String> {
    Ok(FieldDocument {
        name: input.name,
        api_name: input.api_name,
        ty: input.ty,
        items: input.items,
        fields: normalize_field_documents(input.fields)?,
        nullable: input.nullable,
        id: input.id,
        generated: input.generated,
        unique: input.unique,
        transforms: input.transforms,
        relation: input.relation,
        validate: input.validate,
    })
}

fn normalize_api_field_projection_documents(
    input: ApiFieldProjectionDocumentsInput,
) -> Result<Vec<ApiFieldProjectionDocument>, String> {
    match input {
        ApiFieldProjectionDocumentsInput::List(values) => Ok(values),
        ApiFieldProjectionDocumentsInput::Map(values) => values
            .into_iter()
            .map(|(key, value)| {
                value
                    .into_document::<serde::de::value::Error>(key)
                    .map_err(|error| error.to_string())
            })
            .collect(),
    }
}

fn normalize_response_context_documents(
    input: ResponseContextDocumentsInput,
) -> Result<Vec<ResponseContextDocument>, String> {
    match input {
        ResponseContextDocumentsInput::List(values) => Ok(values),
        ResponseContextDocumentsInput::Map(values) => values
            .into_iter()
            .map(|(key, value)| {
                value
                    .into_document::<serde::de::value::Error>(key)
                    .map_err(|error| error.to_string())
            })
            .collect(),
    }
}

pub fn parse_eon_document(source: &str) -> Result<ServiceDocument, String> {
    eon::from_str::<ServiceDocument>(source).map_err(|error| error.to_string())
}

pub fn render_canonical_eon(document: &ServiceDocument) -> Result<String, String> {
    let mut value = serde_json::to_value(document).map_err(|error| error.to_string())?;
    prune_serialized_value(&mut value);
    eon::to_string(&value, &eon::FormatOptions::default()).map_err(|error| error.to_string())
}

fn prune_serialized_value(value: &mut serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => true,
        serde_json::Value::Array(values) => {
            values.retain_mut(|entry| !prune_serialized_value(entry));
            values.is_empty()
        }
        serde_json::Value::Object(map) => {
            map.retain(|_, entry| !prune_serialized_value(entry));
            map.is_empty()
        }
        _ => false,
    }
}

fn default_admin_bypass() -> bool {
    true
}

fn deserialize_create_policies_document<'de, D>(
    deserializer: D,
) -> Result<Option<CreatePoliciesDocument>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <Option<serde_json::Value> as serde::Deserialize>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        serde_json::Value::Object(map)
            if map.contains_key("assign") || map.contains_key("require") =>
        {
            serde_json::from_value::<CreatePoliciesGroupDocument>(serde_json::Value::Object(map))
                .map(CreatePoliciesDocument::Structured)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
        other => serde_json::from_value::<ScopePoliciesDocument>(other)
            .map(CreatePoliciesDocument::Assignments)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

fn deserialize_enum_documents<'de, D>(deserializer: D) -> Result<Vec<EnumDocument>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(EnumDocumentsVisitor)
}

fn deserialize_mixin_documents<'de, D>(deserializer: D) -> Result<Vec<MixinDocument>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(MixinDocumentsVisitor)
}

fn deserialize_resource_documents<'de, D>(
    deserializer: D,
) -> Result<Vec<ResourceDocument>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(ResourceDocumentsVisitor)
}

fn deserialize_field_documents<'de, D>(deserializer: D) -> Result<Vec<FieldDocument>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(FieldDocumentsVisitor)
}

fn deserialize_api_field_projection_documents<'de, D>(
    deserializer: D,
) -> Result<Vec<ApiFieldProjectionDocument>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(ApiFieldProjectionDocumentsVisitor)
}

fn deserialize_response_context_documents<'de, D>(
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
        if let Some(name) = self.name.as_deref() {
            if name != key {
                return Err(E::custom(format!(
                    "resource map entry `{key}` has mismatched `name` value `{name}`"
                )));
            }
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

impl MixinMapValueInputDocument {
    fn into_input_document<E>(self, key: String) -> Result<MixinInputDocument, E>
    where
        E: de::Error,
    {
        match self {
            Self::Fields(fields) => Ok(MixinInputDocument {
                name: key,
                indexes: Vec::new(),
                fields: FieldDocumentsInput::List(fields),
            }),
            Self::Config(mixin) => mixin.into_input_document::<E>(key),
        }
    }
}

impl MixinConfigInputDocument {
    fn into_input_document<E>(self, key: String) -> Result<MixinInputDocument, E>
    where
        E: de::Error,
    {
        if let Some(name) = self.name.as_deref() {
            if name != key {
                return Err(E::custom(format!(
                    "mixin map entry `{key}` has mismatched `name` value `{name}`"
                )));
            }
        }

        Ok(MixinInputDocument {
            name: key,
            indexes: self.indexes,
            fields: self.fields,
        })
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
                generated: GeneratedValueDocument::None,
                unique: false,
                transforms: Vec::new(),
                relation: None,
                validate: None,
            }),
            Self::Config(field) => field.into_document::<E>(key),
        }
    }
}

impl FieldMapValueInputDocument {
    fn into_input_document<E>(self, key: String) -> Result<FieldInputDocument, E>
    where
        E: de::Error,
    {
        match self {
            Self::Type(ty) => Ok(FieldInputDocument {
                name: key,
                api_name: None,
                ty,
                items: None,
                fields: FieldDocumentsInput::default(),
                nullable: false,
                id: false,
                generated: GeneratedValueDocument::None,
                unique: false,
                transforms: Vec::new(),
                relation: None,
                validate: None,
            }),
            Self::Config(field) => field.into_input_document::<E>(key),
        }
    }
}

impl FieldMapConfigDocument {
    fn into_document<E>(self, key: String) -> Result<FieldDocument, E>
    where
        E: de::Error,
    {
        if let Some(name) = self.name.as_deref() {
            if name != key {
                return Err(E::custom(format!(
                    "field map entry `{key}` has mismatched `name` value `{name}`"
                )));
            }
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
        })
    }
}

impl FieldMapConfigInputDocument {
    fn into_input_document<E>(self, key: String) -> Result<FieldInputDocument, E>
    where
        E: de::Error,
    {
        if let Some(name) = self.name.as_deref() {
            if name != key {
                return Err(E::custom(format!(
                    "field map entry `{key}` has mismatched `name` value `{name}`"
                )));
            }
        }

        Ok(FieldInputDocument {
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
        })
    }
}

impl ResourceMapValueInputDocument {
    fn into_input_document<E>(self, key: String) -> Result<ResourceInputDocument, E>
    where
        E: de::Error,
    {
        if let Some(name) = self.name.as_deref() {
            if name != key {
                return Err(E::custom(format!(
                    "resource map entry `{key}` has mismatched `name` value `{name}`"
                )));
            }
        }

        Ok(ResourceInputDocument {
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

impl MixinConfigDocument {
    fn into_document<E>(self, key: String) -> Result<MixinDocument, E>
    where
        E: de::Error,
    {
        if let Some(name) = self.name.as_deref() {
            if name != key {
                return Err(E::custom(format!(
                    "mixin map entry `{key}` has mismatched `name` value `{name}`"
                )));
            }
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
        if let Some(name) = self.name.as_deref() {
            if name != key {
                return Err(E::custom(format!(
                    "api.fields map entry `{key}` has mismatched `name` value `{name}`"
                )));
            }
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
        if let Some(name) = self.name.as_deref() {
            if name != key {
                return Err(E::custom(format!(
                    "api.contexts map entry `{key}` has mismatched `name` value `{name}`"
                )));
            }
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
        if let Some(name) = self.name.as_deref() {
            if name != key {
                return Err(E::custom(format!(
                    "enums map entry `{key}` has mismatched `name` value `{name}`"
                )));
            }
        }

        Ok(EnumDocument {
            name: key,
            values: self.values,
        })
    }
}

struct ResourceDocumentsVisitor;
struct EnumDocumentsVisitor;
struct MixinDocumentsVisitor;
struct FieldDocumentsVisitor;
struct ApiFieldProjectionDocumentsVisitor;
struct ResponseContextDocumentsVisitor;

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
