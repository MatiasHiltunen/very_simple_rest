use std::{
    collections::{BTreeMap, HashSet},
    env, fs,
    path::{Component, Path, PathBuf},
};

use heck::ToSnakeCase;
use proc_macro2::Span;
use serde::de::{self, Deserializer, Error as _, MapAccess, Visitor};
use syn::{LitStr, Type};

use super::model::{
    DbBackend, FieldSpec, FieldValidation, GENERATED_DATE_ALIAS, GENERATED_DATETIME_ALIAS,
    GENERATED_DECIMAL_ALIAS, GENERATED_TIME_ALIAS, GENERATED_UUID_ALIAS, GeneratedValue,
    ListConfig, NumericBound, PolicyAssignment, PolicyExistsCondition, PolicyExistsFilter,
    PolicyFilter, PolicyFilterExpression, PolicyFilterOperator, PolicyValueSource,
    ReferentialAction, ResourceSpec, RoleRequirements, RowPolicies, RowPolicyKind, ServiceSpec,
    StaticCacheProfile, StaticMode, StaticMountSpec, WriteModelStyle,
    default_resource_module_ident, infer_generated_value, infer_sql_type, sanitize_module_ident,
    sanitize_struct_ident, validate_authorization_contract, validate_field_validations,
    validate_list_config, validate_logging_config, validate_policy_claim_sources,
    validate_relations, validate_row_policies, validate_runtime_config, validate_security_config,
    validate_sql_identifier, validate_tls_config,
};
use crate::{
    auth::{
        AuthClaimMapping, AuthClaimType, AuthEmailProvider, AuthEmailSettings, AuthSettings,
        AuthUiPageSettings, SessionCookieSameSite, SessionCookieSettings,
    },
    authorization::{
        AuthorizationAction, AuthorizationContract, AuthorizationHybridEnforcementConfig,
        AuthorizationHybridResource, AuthorizationHybridScopeSources,
        AuthorizationManagementApiConfig, AuthorizationPermission, AuthorizationScope,
        AuthorizationTemplate, DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT,
    },
    database::{
        DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV, DatabaseBackupConfig, DatabaseBackupMode,
        DatabaseBackupRetention, DatabaseBackupTarget, DatabaseConfig, DatabaseEngine,
        DatabaseReadRoutingMode, DatabaseReplicationConfig, DatabaseReplicationMode,
        DatabaseResilienceConfig, DatabaseResilienceProfile, TursoLocalConfig,
    },
    logging::{LogTimestampPrecision, LoggingConfig},
    runtime::{CompressionConfig, RuntimeConfig},
    security::{
        CorsSecurity, FrameOptions, HeaderSecurity, Hsts, RateLimitRule, RateLimitSecurity,
        ReferrerPolicy, RequestSecurity, SecurityConfig, TrustedProxySecurity,
    },
    tls::{
        DEFAULT_TLS_CERT_PATH, DEFAULT_TLS_CERT_PATH_ENV, DEFAULT_TLS_KEY_PATH,
        DEFAULT_TLS_KEY_PATH_ENV, TlsConfig,
    },
};

pub struct LoadedService {
    pub service: ServiceSpec,
    pub include_path: String,
}

#[derive(serde::Deserialize)]
struct ServiceDocument {
    #[serde(default)]
    module: Option<String>,
    #[serde(default)]
    db: DbBackend,
    #[serde(default)]
    database: Option<DatabaseDocument>,
    #[serde(default)]
    logging: Option<LoggingDocument>,
    #[serde(default)]
    runtime: Option<RuntimeDocument>,
    #[serde(default)]
    authorization: Option<AuthorizationDocument>,
    #[serde(default)]
    tls: Option<TlsDocument>,
    #[serde(default, rename = "static")]
    static_config: Option<StaticConfigDocument>,
    #[serde(default)]
    security: SecurityDocument,
    #[serde(deserialize_with = "deserialize_resource_documents")]
    resources: Vec<ResourceDocument>,
}

#[derive(Default, serde::Deserialize)]
struct DatabaseDocument {
    #[serde(default)]
    engine: Option<DatabaseEngineDocument>,
    #[serde(default)]
    resilience: Option<DatabaseResilienceDocument>,
}

#[derive(serde::Deserialize)]
struct DatabaseEngineDocument {
    kind: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    encryption_key_env: Option<String>,
}

#[derive(Default, serde::Deserialize)]
struct DatabaseResilienceDocument {
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    backup: Option<DatabaseBackupDocument>,
    #[serde(default)]
    replication: Option<DatabaseReplicationDocument>,
}

#[derive(Default, serde::Deserialize)]
struct DatabaseBackupDocument {
    #[serde(default)]
    required: Option<bool>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    verify_restore: Option<bool>,
    #[serde(default)]
    max_age: Option<String>,
    #[serde(default)]
    encryption_key_env: Option<String>,
    #[serde(default)]
    retention: Option<DatabaseBackupRetentionDocument>,
}

#[derive(Default, serde::Deserialize)]
struct DatabaseBackupRetentionDocument {
    #[serde(default)]
    daily: Option<u32>,
    #[serde(default)]
    weekly: Option<u32>,
    #[serde(default)]
    monthly: Option<u32>,
}

#[derive(Default, serde::Deserialize)]
struct DatabaseReplicationDocument {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    read_routing: Option<String>,
    #[serde(default)]
    read_url_env: Option<String>,
    #[serde(default)]
    max_lag: Option<String>,
    #[serde(default)]
    replicas_expected: Option<u32>,
}

#[derive(Default, serde::Deserialize)]
struct SecurityDocument {
    #[serde(default)]
    requests: Option<RequestSecurityDocument>,
    #[serde(default)]
    cors: Option<CorsSecurityDocument>,
    #[serde(default)]
    trusted_proxies: Option<TrustedProxiesDocument>,
    #[serde(default)]
    rate_limits: Option<RateLimitsDocument>,
    #[serde(default)]
    headers: Option<HeaderSecurityDocument>,
    #[serde(default)]
    auth: Option<AuthSecurityDocument>,
}

#[derive(Default, serde::Deserialize)]
struct RequestSecurityDocument {
    #[serde(default)]
    json_max_bytes: Option<usize>,
}

#[derive(Default, serde::Deserialize)]
struct CorsSecurityDocument {
    #[serde(default)]
    origins: Vec<String>,
    #[serde(default)]
    origins_env: Option<String>,
    #[serde(default)]
    allow_credentials: Option<bool>,
    #[serde(default)]
    allow_methods: Vec<String>,
    #[serde(default)]
    allow_headers: Vec<String>,
    #[serde(default)]
    expose_headers: Vec<String>,
    #[serde(default)]
    max_age_seconds: Option<usize>,
}

#[derive(Default, serde::Deserialize)]
struct TrustedProxiesDocument {
    #[serde(default)]
    proxies: Vec<String>,
    #[serde(default)]
    proxies_env: Option<String>,
}

#[derive(Default, serde::Deserialize)]
struct RateLimitsDocument {
    #[serde(default)]
    login: Option<RateLimitRuleDocument>,
    #[serde(default)]
    register: Option<RateLimitRuleDocument>,
}

#[derive(serde::Deserialize)]
struct RateLimitRuleDocument {
    requests: u32,
    window_seconds: u64,
}

#[derive(Default, serde::Deserialize)]
struct HeaderSecurityDocument {
    #[serde(default)]
    frame_options: Option<String>,
    #[serde(default)]
    content_type_options: Option<bool>,
    #[serde(default)]
    referrer_policy: Option<String>,
    #[serde(default)]
    hsts: Option<HstsDocument>,
}

#[derive(serde::Deserialize)]
struct HstsDocument {
    max_age_seconds: u64,
    #[serde(default)]
    include_subdomains: bool,
}

#[derive(Default, serde::Deserialize)]
struct AuthSecurityDocument {
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    access_token_ttl_seconds: Option<i64>,
    #[serde(default)]
    require_email_verification: Option<bool>,
    #[serde(default)]
    verification_token_ttl_seconds: Option<i64>,
    #[serde(default)]
    password_reset_token_ttl_seconds: Option<i64>,
    #[serde(default)]
    claims: BTreeMap<String, AuthClaimMapValueDocument>,
    #[serde(default)]
    session_cookie: Option<SessionCookieDocument>,
    #[serde(default)]
    email: Option<AuthEmailDocument>,
    #[serde(default)]
    portal: Option<AuthUiPageDocument>,
    #[serde(default)]
    admin_dashboard: Option<AuthUiPageDocument>,
}

#[derive(Default, serde::Deserialize)]
struct SessionCookieDocument {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    csrf_cookie_name: Option<String>,
    #[serde(default)]
    csrf_header_name: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    secure: Option<bool>,
    #[serde(default)]
    same_site: Option<String>,
}

#[derive(serde::Deserialize)]
struct AuthEmailDocument {
    from_email: String,
    #[serde(default)]
    from_name: Option<String>,
    #[serde(default)]
    reply_to: Option<String>,
    #[serde(default)]
    public_base_url: Option<String>,
    provider: AuthEmailProviderDocument,
}

#[derive(serde::Deserialize)]
struct AuthEmailProviderDocument {
    kind: String,
    #[serde(default)]
    api_key_env: Option<String>,
    #[serde(default)]
    api_base_url: Option<String>,
    #[serde(default)]
    connection_url_env: Option<String>,
}

#[derive(serde::Deserialize)]
struct AuthUiPageDocument {
    path: String,
    #[serde(default)]
    title: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum AuthClaimMapValueDocument {
    Type(AuthClaimTypeDocument),
    Column(String),
    Config(AuthClaimConfigDocument),
}

#[derive(Default, serde::Deserialize)]
struct AuthClaimConfigDocument {
    #[serde(default)]
    column: Option<String>,
    #[serde(default, rename = "type")]
    ty: Option<AuthClaimTypeDocument>,
}

#[derive(Clone, Copy, serde::Deserialize)]
enum AuthClaimTypeDocument {
    String,
    I64,
    Bool,
}

#[derive(Default, serde::Deserialize)]
struct LoggingDocument {
    #[serde(default)]
    filter_env: Option<String>,
    #[serde(default)]
    default_filter: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
}

#[derive(Default, serde::Deserialize)]
struct RuntimeDocument {
    #[serde(default)]
    compression: Option<CompressionDocument>,
}

#[derive(Default, serde::Deserialize)]
struct AuthorizationDocument {
    #[serde(default)]
    scopes: BTreeMap<String, AuthorizationScopeDocument>,
    #[serde(default)]
    permissions: BTreeMap<String, AuthorizationPermissionDocument>,
    #[serde(default)]
    templates: BTreeMap<String, AuthorizationTemplateDocument>,
    #[serde(default)]
    hybrid_enforcement: Option<AuthorizationHybridEnforcementDocument>,
    #[serde(default)]
    management_api: Option<AuthorizationManagementApiDocument>,
}

#[derive(Default, serde::Deserialize)]
struct AuthorizationHybridEnforcementDocument {
    #[serde(default)]
    resources: BTreeMap<String, AuthorizationHybridResourceDocument>,
}

#[derive(Default, serde::Deserialize)]
struct AuthorizationHybridResourceDocument {
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scope_field: Option<String>,
    #[serde(default)]
    scope_sources: Option<AuthorizationHybridScopeSourcesDocument>,
    #[serde(default)]
    actions: Vec<AuthorizationActionDocument>,
}

#[derive(Default, serde::Deserialize)]
struct AuthorizationHybridScopeSourcesDocument {
    #[serde(default)]
    item: Option<bool>,
    #[serde(default)]
    collection_filter: Option<bool>,
    #[serde(default)]
    nested_parent: Option<bool>,
    #[serde(default)]
    create_payload: Option<bool>,
}

#[derive(Default, serde::Deserialize)]
struct AuthorizationManagementApiDocument {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    mount: Option<String>,
}

#[derive(Default, serde::Deserialize)]
struct AuthorizationScopeDocument {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    parent: Option<String>,
}

#[derive(Default, serde::Deserialize)]
struct AuthorizationPermissionDocument {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    actions: Vec<AuthorizationActionDocument>,
    #[serde(default)]
    resources: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Default, serde::Deserialize)]
struct AuthorizationTemplateDocument {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Clone, Copy, serde::Deserialize)]
enum AuthorizationActionDocument {
    Read,
    Create,
    Update,
    Delete,
}

#[derive(Default, serde::Deserialize)]
struct CompressionDocument {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    static_precompressed: Option<bool>,
}

#[derive(Default, serde::Deserialize)]
struct TlsDocument {
    #[serde(default)]
    cert_path: Option<String>,
    #[serde(default)]
    key_path: Option<String>,
    #[serde(default)]
    cert_path_env: Option<String>,
    #[serde(default)]
    key_path_env: Option<String>,
}

#[derive(Default, serde::Deserialize)]
struct StaticConfigDocument {
    #[serde(default)]
    mounts: Vec<StaticMountDocument>,
}

#[derive(serde::Deserialize)]
struct StaticMountDocument {
    mount: String,
    dir: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    index_file: Option<String>,
    #[serde(default)]
    fallback_file: Option<String>,
    #[serde(default)]
    cache: Option<String>,
}

#[derive(serde::Deserialize)]
struct ResourceDocument {
    name: String,
    #[serde(default)]
    table: Option<String>,
    #[serde(default)]
    id_field: Option<String>,
    #[serde(default)]
    roles: RoleRequirements,
    #[serde(default)]
    policies: RowPoliciesDocument,
    #[serde(default)]
    list: ListConfigDocument,
    #[serde(deserialize_with = "deserialize_field_documents")]
    fields: Vec<FieldDocument>,
}

#[derive(Default, serde::Deserialize)]
struct ListConfigDocument {
    #[serde(default)]
    default_limit: Option<u32>,
    #[serde(default)]
    max_limit: Option<u32>,
}

#[derive(Default, serde::Deserialize)]
struct RowPoliciesDocument {
    #[serde(default = "default_admin_bypass")]
    admin_bypass: bool,
    #[serde(default)]
    read: Option<FilterPoliciesDocument>,
    #[serde(default, deserialize_with = "deserialize_create_policies_document")]
    create: Option<CreatePoliciesDocument>,
    #[serde(default)]
    update: Option<FilterPoliciesDocument>,
    #[serde(default)]
    delete: Option<FilterPoliciesDocument>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum CreatePoliciesDocument {
    Structured(CreatePoliciesGroupDocument),
    Assignments(ScopePoliciesDocument),
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePoliciesGroupDocument {
    #[serde(default)]
    assign: Option<ScopePoliciesDocument>,
    #[serde(default)]
    require: Option<FilterPoliciesDocument>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum FilterPoliciesDocument {
    Group(FilterPolicyGroupDocument),
    Many(Vec<FilterPoliciesDocument>),
    Single(PolicyEntryDocument),
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FilterPolicyGroupDocument {
    #[serde(default)]
    all_of: Option<Vec<FilterPoliciesDocument>>,
    #[serde(default)]
    any_of: Option<Vec<FilterPoliciesDocument>>,
    #[serde(default)]
    not: Option<Box<FilterPoliciesDocument>>,
    #[serde(default)]
    exists: Option<ExistsPolicyDocument>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ScopePoliciesDocument {
    Many(Vec<PolicyEntryDocument>),
    Single(PolicyEntryDocument),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum PolicyEntryDocument {
    Shorthand(String),
    Rule(PolicyRuleDocument),
    Legacy(LegacyRowPolicyDocument),
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExistsPolicyDocument {
    resource: String,
    #[serde(default, rename = "where")]
    condition: Option<ExistsPolicyEntriesDocument>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ExistsPolicyEntriesDocument {
    Group(ExistsPolicyGroupDocument),
    Many(Vec<ExistsPolicyEntriesDocument>),
    Single(ExistsPolicyEntryDocument),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ExistsPolicyEntryDocument {
    Shorthand(String),
    Rule(ExistsPolicyRuleDocument),
    Legacy(LegacyRowPolicyDocument),
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExistsPolicyGroupDocument {
    #[serde(default)]
    all_of: Option<Vec<ExistsPolicyEntriesDocument>>,
    #[serde(default)]
    any_of: Option<Vec<ExistsPolicyEntriesDocument>>,
    #[serde(default)]
    not: Option<Box<ExistsPolicyEntriesDocument>>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRowPolicyDocument {
    kind: String,
    field: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRuleDocument {
    field: String,
    #[serde(default)]
    equals: Option<String>,
    #[serde(default)]
    is_null: bool,
    #[serde(default)]
    is_not_null: bool,
    #[serde(default)]
    value: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExistsPolicyRuleDocument {
    field: String,
    #[serde(default)]
    equals: Option<String>,
    #[serde(default)]
    is_null: bool,
    #[serde(default)]
    is_not_null: bool,
    #[serde(default)]
    equals_field: Option<String>,
}

#[derive(serde::Deserialize)]
struct FieldDocument {
    name: String,
    #[serde(rename = "type")]
    ty: FieldTypeDocument,
    #[serde(default)]
    nullable: bool,
    #[serde(default)]
    id: bool,
    #[serde(default)]
    generated: GeneratedValue,
    #[serde(default)]
    relation: Option<RelationDocument>,
    #[serde(default)]
    validate: Option<FieldValidationDocument>,
}

#[derive(serde::Deserialize)]
struct RelationDocument {
    references: String,
    #[serde(default)]
    on_delete: Option<String>,
    #[serde(default)]
    nested_route: bool,
}

#[derive(Default, serde::Deserialize)]
struct FieldValidationDocument {
    #[serde(default)]
    min_length: Option<usize>,
    #[serde(default)]
    max_length: Option<usize>,
    #[serde(default)]
    minimum: Option<NumericBoundDocument>,
    #[serde(default)]
    maximum: Option<NumericBoundDocument>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum NumericBoundDocument {
    Integer(i64),
    Float(f64),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum FieldTypeDocument {
    Scalar(ScalarType),
    Rust(String),
}

#[derive(Clone, Copy, serde::Deserialize)]
enum ScalarType {
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
}

#[derive(serde::Deserialize)]
struct ResourceMapValueDocument {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    table: Option<String>,
    #[serde(default)]
    id_field: Option<String>,
    #[serde(default)]
    roles: RoleRequirements,
    #[serde(default)]
    policies: RowPoliciesDocument,
    #[serde(default)]
    list: ListConfigDocument,
    #[serde(deserialize_with = "deserialize_field_documents")]
    fields: Vec<FieldDocument>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum FieldMapValueDocument {
    Type(FieldTypeDocument),
    Config(FieldMapConfigDocument),
}

#[derive(serde::Deserialize)]
struct FieldMapConfigDocument {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "type")]
    ty: FieldTypeDocument,
    #[serde(default)]
    nullable: bool,
    #[serde(default)]
    id: bool,
    #[serde(default)]
    generated: GeneratedValue,
    #[serde(default)]
    relation: Option<RelationDocument>,
    #[serde(default)]
    validate: Option<FieldValidationDocument>,
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
            id_field: self.id_field,
            roles: self.roles,
            policies: self.policies,
            list: self.list,
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
                ty,
                nullable: false,
                id: false,
                generated: GeneratedValue::None,
                relation: None,
                validate: None,
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
        if let Some(name) = self.name.as_deref() {
            if name != key {
                return Err(E::custom(format!(
                    "field map entry `{key}` has mismatched `name` value `{name}`"
                )));
            }
        }

        Ok(FieldDocument {
            name: key,
            ty: self.ty,
            nullable: self.nullable,
            id: self.id,
            generated: self.generated,
            relation: self.relation,
            validate: self.validate,
        })
    }
}

struct ResourceDocumentsVisitor;

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

struct FieldDocumentsVisitor;

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

pub fn load_service_from_file(path: LitStr) -> syn::Result<LoadedService> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| syn::Error::new(path.span(), "CARGO_MANIFEST_DIR is not available"))?;
    let manifest_dir = PathBuf::from(manifest_dir);
    let absolute_path = manifest_dir.join(path.value());
    load_service_document(&absolute_path, path.span())
}

pub fn load_service_from_path(path: &Path) -> syn::Result<LoadedService> {
    load_service_document(path, Span::call_site())
}

fn load_service_document(path: &Path, span: Span) -> syn::Result<LoadedService> {
    let absolute_path = path.to_path_buf();
    let include_path = absolute_path
        .canonicalize()
        .unwrap_or_else(|_| absolute_path.clone())
        .display()
        .to_string();

    let source = fs::read_to_string(&absolute_path).map_err(|error| {
        syn::Error::new(
            span,
            format!("failed to read `{}`: {error}", absolute_path.display()),
        )
    })?;
    let document = eon::from_str::<ServiceDocument>(&source).map_err(|error| {
        syn::Error::new(
            span,
            format!(
                "failed to parse `{}` as EON: {error}",
                absolute_path.display()
            ),
        )
    })?;

    let file_stem = absolute_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("generated_api");
    let module_ident = sanitize_module_ident(document.module.as_deref().unwrap_or(file_stem), span);
    let service_root = absolute_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let static_mounts = build_static_mounts(&service_root, document.static_config)?;
    let database = parse_database_document(
        document.db,
        document.database,
        &module_ident.to_string(),
        span,
    )?;
    let logging = parse_logging_document(document.logging)?;
    let runtime = parse_runtime_document(document.runtime);
    let authorization = parse_authorization_document(document.authorization)?;
    let tls = parse_tls_document(document.tls)?;
    let security = parse_security_document(document.security, span)?;
    validate_logging_config(&logging, span)?;
    validate_runtime_config(&runtime, span)?;
    validate_tls_config(&tls, span)?;
    validate_security_config(&security, span)?;

    let resources = build_resources(document.db, document.resources)?;
    if resources.is_empty() {
        return Err(syn::Error::new(
            span,
            "service config must contain at least one resource",
        ));
    }
    validate_policy_claim_sources(&resources, &security, span)?;
    validate_authorization_contract(&authorization, &resources, span)?;

    Ok(LoadedService {
        service: ServiceSpec {
            module_ident,
            resources,
            authorization,
            static_mounts,
            database,
            logging,
            runtime,
            security,
            tls,
        },
        include_path,
    })
}

fn build_resources(
    db: DbBackend,
    resources: Vec<ResourceDocument>,
) -> syn::Result<Vec<ResourceSpec>> {
    let mut seen_names = HashSet::new();
    let mut result = Vec::with_capacity(resources.len());

    for resource in resources {
        let struct_ident = sanitize_struct_ident(&resource.name, Span::call_site());
        let struct_name = struct_ident.to_string();
        if !seen_names.insert(struct_name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate resource `{struct_name}`"),
            ));
        }

        let table_name = resource
            .table
            .unwrap_or_else(|| struct_name.to_snake_case());
        validate_sql_identifier(&table_name, Span::call_site(), "table name")?;
        let configured_id = resource.id_field.unwrap_or_else(|| "id".to_owned());

        let mut seen_fields = HashSet::new();
        let mut fields = Vec::with_capacity(resource.fields.len());

        for field in resource.fields {
            if !seen_fields.insert(field.name.clone()) {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "duplicate field `{}` on resource `{struct_name}`",
                        field.name
                    ),
                ));
            }

            let is_id = field.id || field.name == configured_id;
            let generated = match field.generated {
                GeneratedValue::None => infer_generated_value(&field.name, is_id),
                other => other,
            };

            let ty = parse_field_type(
                &field.ty,
                field.nullable || generated != GeneratedValue::None,
            )?;
            let sql_type = infer_sql_type(&ty, db);

            let relation = match field.relation {
                Some(relation) => Some(parse_relation_document(relation)?),
                None => None,
            };
            let validation = parse_field_validation_document(field.validate);

            fields.push(FieldSpec {
                ident: syn::parse_str(&field.name).map_err(|_| {
                    syn::Error::new(
                        Span::call_site(),
                        format!("field name `{}` is not a valid Rust identifier", field.name),
                    )
                })?,
                ty,
                sql_type,
                is_id,
                generated,
                validation,
                relation,
            });
        }

        if !fields.iter().any(|field| field.name() == configured_id) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("configured id field `{configured_id}` does not exist on `{struct_name}`"),
            ));
        }

        let policies = parse_row_policies(resource.policies).map_err(|error| {
            syn::Error::new(
                error.span(),
                format!("failed to parse row policies for `{struct_name}`: {error}"),
            )
        })?;

        result.push(ResourceSpec {
            struct_ident: struct_ident.clone(),
            impl_module_ident: default_resource_module_ident(&struct_ident),
            table_name,
            id_field: configured_id,
            db,
            roles: resource.roles.with_legacy_defaults(),
            policies,
            list: parse_list_config(resource.list),
            fields,
            write_style: WriteModelStyle::GeneratedStructWithDtos,
        });
    }

    for resource in &result {
        validate_row_policies(resource, &result, &resource.policies, Span::call_site())?;
        validate_relations(&resource.fields, Span::call_site())?;
        validate_field_validations(&resource.fields, Span::call_site())?;
        validate_list_config(&resource.list, Span::call_site())?;
    }

    Ok(result)
}

fn parse_list_config(document: ListConfigDocument) -> ListConfig {
    ListConfig {
        default_limit: document.default_limit,
        max_limit: document.max_limit,
    }
}

fn parse_security_document(document: SecurityDocument, span: Span) -> syn::Result<SecurityConfig> {
    let requests = document
        .requests
        .map(|requests| RequestSecurity {
            json_max_bytes: requests.json_max_bytes,
        })
        .unwrap_or_default();

    let headers = if let Some(headers) = document.headers {
        HeaderSecurity {
            frame_options: match headers.frame_options.as_deref() {
                Some(value) => Some(parse_frame_options(value).ok_or_else(|| {
                    syn::Error::new(
                        span,
                        format!("unsupported `security.headers.frame_options` value `{value}`"),
                    )
                })?),
                None => None,
            },
            content_type_options: headers.content_type_options.unwrap_or(false),
            referrer_policy: match headers.referrer_policy.as_deref() {
                Some(value) => Some(parse_referrer_policy(value).ok_or_else(|| {
                    syn::Error::new(
                        span,
                        format!("unsupported `security.headers.referrer_policy` value `{value}`"),
                    )
                })?),
                None => None,
            },
            hsts: headers.hsts.map(|hsts| Hsts {
                max_age_seconds: hsts.max_age_seconds,
                include_subdomains: hsts.include_subdomains,
            }),
        }
    } else {
        HeaderSecurity::default()
    };

    let cors = document
        .cors
        .map(|cors| CorsSecurity {
            origins: cors.origins,
            origins_env: cors.origins_env,
            allow_credentials: cors.allow_credentials.unwrap_or(false),
            allow_methods: cors.allow_methods,
            allow_headers: cors.allow_headers,
            expose_headers: cors.expose_headers,
            max_age_seconds: cors.max_age_seconds,
        })
        .unwrap_or_default();

    let trusted_proxies = document
        .trusted_proxies
        .map(|trusted_proxies| TrustedProxySecurity {
            proxies: trusted_proxies.proxies,
            proxies_env: trusted_proxies.proxies_env,
        })
        .unwrap_or_default();

    let rate_limits = document
        .rate_limits
        .map(|rate_limits| RateLimitSecurity {
            login: rate_limits.login.map(parse_rate_limit_rule_document),
            register: rate_limits.register.map(parse_rate_limit_rule_document),
        })
        .unwrap_or_default();

    let auth = match document.auth {
        Some(auth) => {
            let defaults = AuthSettings::default();
            AuthSettings {
                issuer: auth.issuer,
                audience: auth.audience,
                access_token_ttl_seconds: auth
                    .access_token_ttl_seconds
                    .unwrap_or(defaults.access_token_ttl_seconds),
                require_email_verification: auth
                    .require_email_verification
                    .unwrap_or(defaults.require_email_verification),
                verification_token_ttl_seconds: auth
                    .verification_token_ttl_seconds
                    .unwrap_or(defaults.verification_token_ttl_seconds),
                password_reset_token_ttl_seconds: auth
                    .password_reset_token_ttl_seconds
                    .unwrap_or(defaults.password_reset_token_ttl_seconds),
                claims: parse_auth_claims_document(auth.claims),
                session_cookie: auth
                    .session_cookie
                    .map(parse_session_cookie_document)
                    .transpose()?,
                email: auth.email.map(parse_auth_email_document).transpose()?,
                portal: auth
                    .portal
                    .map(|page| parse_auth_ui_page_document(page, "Account Portal"))
                    .transpose()?,
                admin_dashboard: auth
                    .admin_dashboard
                    .map(|page| parse_auth_ui_page_document(page, "Admin Dashboard"))
                    .transpose()?,
            }
        }
        None => AuthSettings::default(),
    };

    Ok(SecurityConfig {
        requests,
        cors,
        trusted_proxies,
        rate_limits,
        headers,
        auth,
    })
}

fn parse_logging_document(document: Option<LoggingDocument>) -> syn::Result<LoggingConfig> {
    let defaults = LoggingConfig::default();
    let Some(document) = document else {
        return Ok(defaults);
    };

    let timestamp = match document.timestamp.as_deref() {
        None => defaults.timestamp,
        Some(value) => parse_log_timestamp_precision(value).ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!("unsupported `logging.timestamp` value `{value}`"),
            )
        })?,
    };

    Ok(LoggingConfig {
        filter_env: document.filter_env.unwrap_or(defaults.filter_env),
        default_filter: document.default_filter.unwrap_or(defaults.default_filter),
        timestamp,
    })
}

fn parse_runtime_document(document: Option<RuntimeDocument>) -> RuntimeConfig {
    let Some(document) = document else {
        return RuntimeConfig::default();
    };

    let compression = document
        .compression
        .map(|compression| CompressionConfig {
            enabled: compression.enabled.unwrap_or(false),
            static_precompressed: compression.static_precompressed.unwrap_or(false),
        })
        .unwrap_or_default();

    RuntimeConfig { compression }
}

fn parse_authorization_document(
    document: Option<AuthorizationDocument>,
) -> syn::Result<AuthorizationContract> {
    let Some(document) = document else {
        return Ok(AuthorizationContract::default());
    };

    Ok(AuthorizationContract {
        scopes: document
            .scopes
            .into_iter()
            .map(|(name, scope)| AuthorizationScope {
                name,
                description: scope.description,
                parent: scope.parent,
            })
            .collect(),
        permissions: document
            .permissions
            .into_iter()
            .map(|(name, permission)| AuthorizationPermission {
                name,
                description: permission.description,
                actions: permission
                    .actions
                    .into_iter()
                    .map(parse_authorization_action_document)
                    .collect(),
                resources: permission.resources,
                scopes: permission.scopes,
            })
            .collect(),
        templates: document
            .templates
            .into_iter()
            .map(|(name, template)| AuthorizationTemplate {
                name,
                description: template.description,
                permissions: template.permissions,
                scopes: template.scopes,
            })
            .collect(),
        hybrid_enforcement: parse_authorization_hybrid_enforcement_document(
            document.hybrid_enforcement,
        )?,
        management_api: parse_authorization_management_api_document(document.management_api)?,
    })
}

fn parse_authorization_hybrid_enforcement_document(
    document: Option<AuthorizationHybridEnforcementDocument>,
) -> syn::Result<AuthorizationHybridEnforcementConfig> {
    let Some(document) = document else {
        return Ok(AuthorizationHybridEnforcementConfig::default());
    };

    Ok(AuthorizationHybridEnforcementConfig {
        resources: document
            .resources
            .into_iter()
            .map(|(resource, config)| {
                let actions = config
                    .actions
                    .into_iter()
                    .map(parse_authorization_action_document)
                    .collect::<Vec<_>>();
                let scope = config.scope.ok_or_else(|| {
                    syn::Error::new(
                        Span::call_site(),
                        format!(
                            "`authorization.hybrid_enforcement.resources.{resource}.scope` is required"
                        ),
                    )
                })?;
                let scope_field = config.scope_field.ok_or_else(|| {
                    syn::Error::new(
                        Span::call_site(),
                        format!(
                            "`authorization.hybrid_enforcement.resources.{resource}.scope_field` is required"
                        ),
                    )
                })?;
                Ok(AuthorizationHybridResource {
                    resource,
                    scope,
                    scope_field,
                    scope_sources: parse_authorization_hybrid_scope_sources_document(
                        config.scope_sources,
                        &actions,
                    ),
                    actions,
                })
            })
            .collect::<syn::Result<Vec<_>>>()?,
    })
}

fn parse_authorization_hybrid_scope_sources_document(
    document: Option<AuthorizationHybridScopeSourcesDocument>,
    actions: &[AuthorizationAction],
) -> AuthorizationHybridScopeSources {
    let supports_read = actions.contains(&AuthorizationAction::Read);
    let supports_update = actions.contains(&AuthorizationAction::Update);
    let supports_delete = actions.contains(&AuthorizationAction::Delete);
    let supports_create = actions.contains(&AuthorizationAction::Create);
    let item_default = supports_read || supports_update || supports_delete;

    let document = document.unwrap_or_default();
    AuthorizationHybridScopeSources {
        item: document.item.unwrap_or(item_default),
        collection_filter: document.collection_filter.unwrap_or(supports_read),
        nested_parent: document.nested_parent.unwrap_or(supports_read),
        create_payload: document.create_payload.unwrap_or(supports_create),
    }
}

fn parse_authorization_management_api_document(
    document: Option<AuthorizationManagementApiDocument>,
) -> syn::Result<AuthorizationManagementApiConfig> {
    let Some(document) = document else {
        return Ok(AuthorizationManagementApiConfig::default());
    };

    let enabled = document.enabled.unwrap_or(true);
    let mount = normalize_authorization_management_mount(
        document
            .mount
            .as_deref()
            .unwrap_or(DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT),
    )?;

    Ok(AuthorizationManagementApiConfig { enabled, mount })
}

fn parse_authorization_action_document(value: AuthorizationActionDocument) -> AuthorizationAction {
    match value {
        AuthorizationActionDocument::Read => AuthorizationAction::Read,
        AuthorizationActionDocument::Create => AuthorizationAction::Create,
        AuthorizationActionDocument::Update => AuthorizationAction::Update,
        AuthorizationActionDocument::Delete => AuthorizationAction::Delete,
    }
}

fn normalize_authorization_management_mount(value: &str) -> syn::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "authorization management API mount cannot be empty",
        ));
    }

    if !trimmed.starts_with('/') {
        return Err(syn::Error::new(
            Span::call_site(),
            "authorization management API mount must start with `/`",
        ));
    }

    let normalized = if trimmed != "/" && trimmed.ends_with('/') {
        trimmed.trim_end_matches('/').to_owned()
    } else {
        trimmed.to_owned()
    };

    if normalized.contains("//") {
        return Err(syn::Error::new(
            Span::call_site(),
            "authorization management API mount cannot contain `//`",
        ));
    }

    Ok(normalized)
}

fn parse_tls_document(document: Option<TlsDocument>) -> syn::Result<TlsConfig> {
    let Some(document) = document else {
        return Ok(TlsConfig::default());
    };

    let cert_path = validate_tls_path(
        document
            .cert_path
            .as_deref()
            .unwrap_or(DEFAULT_TLS_CERT_PATH),
        "tls.cert_path",
    )?;
    let key_path = validate_tls_path(
        document.key_path.as_deref().unwrap_or(DEFAULT_TLS_KEY_PATH),
        "tls.key_path",
    )?;

    Ok(TlsConfig {
        cert_path: Some(cert_path),
        key_path: Some(key_path),
        cert_path_env: Some(
            document
                .cert_path_env
                .unwrap_or_else(|| DEFAULT_TLS_CERT_PATH_ENV.to_owned()),
        ),
        key_path_env: Some(
            document
                .key_path_env
                .unwrap_or_else(|| DEFAULT_TLS_KEY_PATH_ENV.to_owned()),
        ),
    })
}

fn parse_log_timestamp_precision(value: &str) -> Option<LogTimestampPrecision> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none" | "off" => Some(LogTimestampPrecision::None),
        "seconds" | "second" | "secs" | "sec" => Some(LogTimestampPrecision::Seconds),
        "millis" | "milliseconds" | "millisecond" | "ms" => Some(LogTimestampPrecision::Millis),
        "micros" | "microseconds" | "microsecond" | "us" => Some(LogTimestampPrecision::Micros),
        "nanos" | "nanoseconds" | "nanosecond" | "ns" => Some(LogTimestampPrecision::Nanos),
        _ => None,
    }
}

fn validate_tls_path(value: &str, label: &str) -> syn::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("`{label}` cannot be empty"),
        ));
    }

    if Path::new(trimmed).is_absolute() {
        Ok(trimmed.to_owned())
    } else {
        validate_relative_path(trimmed, label)
    }
}

fn parse_session_cookie_document(
    document: SessionCookieDocument,
) -> syn::Result<SessionCookieSettings> {
    let defaults = SessionCookieSettings::default();
    let same_site = match document.same_site.as_deref() {
        None => defaults.same_site,
        Some(value) => parse_session_cookie_same_site(value).ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!("unsupported `security.auth.session_cookie.same_site` value `{value}`"),
            )
        })?,
    };

    Ok(SessionCookieSettings {
        name: document.name.unwrap_or(defaults.name),
        csrf_cookie_name: document
            .csrf_cookie_name
            .unwrap_or(defaults.csrf_cookie_name),
        csrf_header_name: document
            .csrf_header_name
            .unwrap_or(defaults.csrf_header_name),
        path: document.path.unwrap_or(defaults.path),
        secure: document.secure.unwrap_or(defaults.secure),
        same_site,
    })
}

fn parse_auth_email_document(document: AuthEmailDocument) -> syn::Result<AuthEmailSettings> {
    Ok(AuthEmailSettings {
        from_email: document.from_email,
        from_name: document.from_name,
        reply_to: document.reply_to,
        public_base_url: document.public_base_url,
        provider: parse_auth_email_provider_document(document.provider)?,
    })
}

fn parse_auth_email_provider_document(
    document: AuthEmailProviderDocument,
) -> syn::Result<AuthEmailProvider> {
    match document.kind.trim().to_ascii_lowercase().as_str() {
        "resend" => Ok(AuthEmailProvider::Resend {
            api_key_env: document.api_key_env.ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    "`security.auth.email.provider.api_key_env` is required for `kind = Resend`",
                )
            })?,
            api_base_url: document.api_base_url,
        }),
        "smtp" => Ok(AuthEmailProvider::Smtp {
            connection_url_env: document.connection_url_env.ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    "`security.auth.email.provider.connection_url_env` is required for `kind = Smtp`",
                )
            })?,
        }),
        other => Err(syn::Error::new(
            Span::call_site(),
            format!("unsupported `security.auth.email.provider.kind` value `{other}`"),
        )),
    }
}

fn parse_auth_ui_page_document(
    document: AuthUiPageDocument,
    default_title: &str,
) -> syn::Result<AuthUiPageSettings> {
    Ok(AuthUiPageSettings {
        path: document.path,
        title: document.title.unwrap_or_else(|| default_title.to_owned()),
    })
}

fn parse_auth_claims_document(
    document: BTreeMap<String, AuthClaimMapValueDocument>,
) -> BTreeMap<String, AuthClaimMapping> {
    document
        .into_iter()
        .map(|(claim_name, value)| {
            let (column, ty) = match value {
                AuthClaimMapValueDocument::Type(ty) => {
                    (claim_name.clone(), parse_auth_claim_type_document(ty))
                }
                AuthClaimMapValueDocument::Column(column) => (column, AuthClaimType::I64),
                AuthClaimMapValueDocument::Config(config) => (
                    config.column.unwrap_or_else(|| claim_name.clone()),
                    config
                        .ty
                        .map(parse_auth_claim_type_document)
                        .unwrap_or(AuthClaimType::I64),
                ),
            };
            (claim_name, AuthClaimMapping { column, ty })
        })
        .collect()
}

fn parse_auth_claim_type_document(document: AuthClaimTypeDocument) -> AuthClaimType {
    match document {
        AuthClaimTypeDocument::String => AuthClaimType::String,
        AuthClaimTypeDocument::I64 => AuthClaimType::I64,
        AuthClaimTypeDocument::Bool => AuthClaimType::Bool,
    }
}

fn parse_session_cookie_same_site(value: &str) -> Option<SessionCookieSameSite> {
    match value.trim().to_ascii_lowercase().as_str() {
        "strict" => Some(SessionCookieSameSite::Strict),
        "lax" => Some(SessionCookieSameSite::Lax),
        "none" => Some(SessionCookieSameSite::None),
        _ => None,
    }
}

fn parse_database_document(
    db: DbBackend,
    document: Option<DatabaseDocument>,
    module_name: &str,
    span: Span,
) -> syn::Result<DatabaseConfig> {
    let (engine_document, resilience_document) = match document {
        Some(document) => (document.engine, document.resilience),
        None => (None, None),
    };
    let engine = match engine_document {
        None => match db {
            DbBackend::Sqlite => DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: format!("var/data/{module_name}.db"),
                encryption_key_env: Some(DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV.to_owned()),
            }),
            DbBackend::Postgres | DbBackend::Mysql => DatabaseEngine::Sqlx,
        },
        Some(engine) => parse_database_engine_document(db, engine, span)?,
    };
    let resilience = resilience_document
        .map(|document| parse_database_resilience_document(db, &engine, document, span))
        .transpose()?;

    Ok(DatabaseConfig { engine, resilience })
}

fn parse_database_engine_document(
    db: DbBackend,
    document: DatabaseEngineDocument,
    span: Span,
) -> syn::Result<DatabaseEngine> {
    match document.kind.trim().to_ascii_lowercase().as_str() {
        "sqlx" => Ok(DatabaseEngine::Sqlx),
        "tursolocal" | "turso_local" | "turso-local" => {
            if db != DbBackend::Sqlite {
                return Err(syn::Error::new(
                    span,
                    "database.engine = TursoLocal requires `db: Sqlite`",
                ));
            }

            let path = document.path.ok_or_else(|| {
                syn::Error::new(
                    span,
                    "database.engine.path is required when `kind = TursoLocal`",
                )
            })?;
            if path.trim().is_empty() {
                return Err(syn::Error::new(
                    span,
                    "database.engine.path cannot be empty",
                ));
            }

            Ok(DatabaseEngine::TursoLocal(TursoLocalConfig {
                path,
                encryption_key_env: document.encryption_key_env,
            }))
        }
        other => Err(syn::Error::new(
            span,
            format!("unsupported `database.engine.kind` value `{other}`"),
        )),
    }
}

fn parse_database_resilience_document(
    db: DbBackend,
    engine: &DatabaseEngine,
    document: DatabaseResilienceDocument,
    span: Span,
) -> syn::Result<DatabaseResilienceConfig> {
    let profile = match document.profile.as_deref() {
        None => DatabaseResilienceProfile::SingleNode,
        Some(value) => parse_database_resilience_profile(value, span)?,
    };
    let backup = document
        .backup
        .map(|document| parse_database_backup_document(db, engine, profile, document, span))
        .transpose()?;
    let replication = document
        .replication
        .map(|document| parse_database_replication_document(document, span))
        .transpose()?;

    if let Some(replication) = &replication {
        if replication.read_routing == DatabaseReadRoutingMode::Explicit
            && replication.read_url_env.is_none()
        {
            return Err(syn::Error::new(
                span,
                "database.resilience.replication.read_url_env is required when `read_routing = Explicit`",
            ));
        }
        if replication.mode == DatabaseReplicationMode::None
            && (replication.read_url_env.is_some()
                || replication.max_lag.is_some()
                || replication.replicas_expected.is_some()
                || replication.read_routing != DatabaseReadRoutingMode::Off)
        {
            return Err(syn::Error::new(
                span,
                "database.resilience.replication.mode = None cannot be combined with replica settings",
            ));
        }
    }

    if db == DbBackend::Sqlite
        && matches!(engine, DatabaseEngine::TursoLocal(_))
        && matches!(replication.as_ref().map(|config| config.mode), Some(mode) if mode != DatabaseReplicationMode::None)
    {
        return Err(syn::Error::new(
            span,
            "database.resilience.replication is not supported for `database.engine = TursoLocal`",
        ));
    }

    Ok(DatabaseResilienceConfig {
        profile,
        backup,
        replication,
    })
}

fn parse_database_resilience_profile(
    value: &str,
    span: Span,
) -> syn::Result<DatabaseResilienceProfile> {
    match value.trim().to_ascii_lowercase().as_str() {
        "singlenode" | "single_node" | "single-node" => Ok(DatabaseResilienceProfile::SingleNode),
        "pitr" => Ok(DatabaseResilienceProfile::Pitr),
        "ha" => Ok(DatabaseResilienceProfile::Ha),
        other => Err(syn::Error::new(
            span,
            format!("unsupported `database.resilience.profile` value `{other}`"),
        )),
    }
}

fn parse_database_backup_document(
    db: DbBackend,
    _engine: &DatabaseEngine,
    profile: DatabaseResilienceProfile,
    document: DatabaseBackupDocument,
    span: Span,
) -> syn::Result<DatabaseBackupConfig> {
    let mode = match document.mode.as_deref() {
        Some(value) => parse_database_backup_mode(value, span)?,
        None => default_database_backup_mode(db, profile),
    };
    let target = match document.target.as_deref() {
        Some(value) => parse_database_backup_target(value, span)?,
        None => DatabaseBackupTarget::Local,
    };
    validate_non_empty_optional(
        "database.resilience.backup.max_age",
        document.max_age.as_deref(),
        span,
    )?;
    validate_non_empty_optional(
        "database.resilience.backup.encryption_key_env",
        document.encryption_key_env.as_deref(),
        span,
    )?;
    let retention = document.retention.map(|retention| DatabaseBackupRetention {
        daily: retention.daily,
        weekly: retention.weekly,
        monthly: retention.monthly,
    });

    Ok(DatabaseBackupConfig {
        required: document.required.unwrap_or(true),
        mode,
        target,
        verify_restore: document.verify_restore.unwrap_or(false),
        max_age: document.max_age,
        encryption_key_env: document.encryption_key_env,
        retention,
    })
}

fn default_database_backup_mode(
    db: DbBackend,
    profile: DatabaseResilienceProfile,
) -> DatabaseBackupMode {
    match profile {
        DatabaseResilienceProfile::Pitr => DatabaseBackupMode::Pitr,
        DatabaseResilienceProfile::SingleNode | DatabaseResilienceProfile::Ha => match db {
            DbBackend::Sqlite => DatabaseBackupMode::Snapshot,
            DbBackend::Postgres | DbBackend::Mysql => DatabaseBackupMode::Logical,
        },
    }
}

fn parse_database_backup_mode(value: &str, span: Span) -> syn::Result<DatabaseBackupMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "snapshot" => Ok(DatabaseBackupMode::Snapshot),
        "logical" => Ok(DatabaseBackupMode::Logical),
        "physical" => Ok(DatabaseBackupMode::Physical),
        "pitr" => Ok(DatabaseBackupMode::Pitr),
        other => Err(syn::Error::new(
            span,
            format!("unsupported `database.resilience.backup.mode` value `{other}`"),
        )),
    }
}

fn parse_database_backup_target(value: &str, span: Span) -> syn::Result<DatabaseBackupTarget> {
    match value.trim().to_ascii_lowercase().as_str() {
        "local" => Ok(DatabaseBackupTarget::Local),
        "s3" => Ok(DatabaseBackupTarget::S3),
        "gcs" => Ok(DatabaseBackupTarget::Gcs),
        "azureblob" | "azure_blob" | "azure-blob" => Ok(DatabaseBackupTarget::AzureBlob),
        "custom" => Ok(DatabaseBackupTarget::Custom),
        other => Err(syn::Error::new(
            span,
            format!("unsupported `database.resilience.backup.target` value `{other}`"),
        )),
    }
}

fn parse_database_replication_document(
    document: DatabaseReplicationDocument,
    span: Span,
) -> syn::Result<DatabaseReplicationConfig> {
    let mode = document.mode.as_deref().ok_or_else(|| {
        syn::Error::new(
            span,
            "database.resilience.replication.mode is required when the replication block exists",
        )
    })?;
    let mode = parse_database_replication_mode(mode, span)?;
    let read_routing = match document.read_routing.as_deref() {
        Some(value) => parse_database_read_routing_mode(value, span)?,
        None => DatabaseReadRoutingMode::Off,
    };
    validate_non_empty_optional(
        "database.resilience.replication.read_url_env",
        document.read_url_env.as_deref(),
        span,
    )?;
    validate_non_empty_optional(
        "database.resilience.replication.max_lag",
        document.max_lag.as_deref(),
        span,
    )?;

    Ok(DatabaseReplicationConfig {
        mode,
        read_routing,
        read_url_env: document.read_url_env,
        max_lag: document.max_lag,
        replicas_expected: document.replicas_expected,
    })
}

fn parse_database_replication_mode(
    value: &str,
    span: Span,
) -> syn::Result<DatabaseReplicationMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none" => Ok(DatabaseReplicationMode::None),
        "readreplica" | "read_replica" | "read-replica" => Ok(DatabaseReplicationMode::ReadReplica),
        "hotstandby" | "hot_standby" | "hot-standby" => Ok(DatabaseReplicationMode::HotStandby),
        "managedexternal" | "managed_external" | "managed-external" => {
            Ok(DatabaseReplicationMode::ManagedExternal)
        }
        other => Err(syn::Error::new(
            span,
            format!("unsupported `database.resilience.replication.mode` value `{other}`"),
        )),
    }
}

fn parse_database_read_routing_mode(
    value: &str,
    span: Span,
) -> syn::Result<DatabaseReadRoutingMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(DatabaseReadRoutingMode::Off),
        "explicit" => Ok(DatabaseReadRoutingMode::Explicit),
        other => Err(syn::Error::new(
            span,
            format!("unsupported `database.resilience.replication.read_routing` value `{other}`"),
        )),
    }
}

fn validate_non_empty_optional(path: &str, value: Option<&str>, span: Span) -> syn::Result<()> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        return Err(syn::Error::new(span, format!("{path} cannot be empty")));
    }
    Ok(())
}

fn parse_rate_limit_rule_document(document: RateLimitRuleDocument) -> RateLimitRule {
    RateLimitRule {
        requests: document.requests,
        window_seconds: document.window_seconds,
    }
}

fn parse_frame_options(value: &str) -> Option<FrameOptions> {
    match value.trim().to_ascii_lowercase().as_str() {
        "deny" => Some(FrameOptions::Deny),
        "same_origin" | "same-origin" | "sameorigin" => Some(FrameOptions::SameOrigin),
        _ => None,
    }
}

fn parse_referrer_policy(value: &str) -> Option<ReferrerPolicy> {
    match value.trim().to_ascii_lowercase().as_str() {
        "no_referrer" | "no-referrer" => Some(ReferrerPolicy::NoReferrer),
        "same_origin" | "same-origin" => Some(ReferrerPolicy::SameOrigin),
        "strict_origin_when_cross_origin"
        | "strict-origin-when-cross-origin"
        | "strictoriginwhencrossorigin" => Some(ReferrerPolicy::StrictOriginWhenCrossOrigin),
        "no_referrer_when_downgrade" | "no-referrer-when-downgrade" | "noreferrerwhendowngrade" => {
            Some(ReferrerPolicy::NoReferrerWhenDowngrade)
        }
        "origin" => Some(ReferrerPolicy::Origin),
        "origin_when_cross_origin" | "origin-when-cross-origin" | "originwhencrossorigin" => {
            Some(ReferrerPolicy::OriginWhenCrossOrigin)
        }
        "unsafe_url" | "unsafe-url" | "unsafeurl" => Some(ReferrerPolicy::UnsafeUrl),
        _ => None,
    }
}

fn build_static_mounts(
    service_root: &Path,
    static_config: Option<StaticConfigDocument>,
) -> syn::Result<Vec<StaticMountSpec>> {
    let service_root = service_root
        .canonicalize()
        .unwrap_or_else(|_| service_root.to_path_buf());
    let Some(static_config) = static_config else {
        return Ok(Vec::new());
    };

    let mut mounts = Vec::with_capacity(static_config.mounts.len());
    let mut seen_mounts = HashSet::new();
    for mount in static_config.mounts {
        let mount_path = normalize_mount_path(&mount.mount)?;
        if !seen_mounts.insert(mount_path.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate static mount `{mount_path}`"),
            ));
        }
        validate_mount_path(&mount_path)?;

        let source_dir = validate_relative_path(&mount.dir, "static dir")?;
        let resolved_dir = resolve_directory_under_root(&service_root, &source_dir)?;
        let mode = parse_static_mode(mount.mode.as_deref().unwrap_or("Directory"))?;
        let cache = parse_static_cache_profile(mount.cache.as_deref().unwrap_or("Revalidate"))?;
        let index_file = mount
            .index_file
            .as_deref()
            .map(|value| validate_relative_path(value, "static index_file"))
            .transpose()?;
        let fallback_file = mount
            .fallback_file
            .as_deref()
            .map(|value| validate_relative_path(value, "static fallback_file"))
            .transpose()?;

        let (index_file, fallback_file) = match mode {
            StaticMode::Directory => (index_file, fallback_file),
            StaticMode::Spa => (
                Some(index_file.unwrap_or_else(|| "index.html".to_owned())),
                Some(fallback_file.unwrap_or_else(|| "index.html".to_owned())),
            ),
        };

        if let Some(index_file) = &index_file {
            resolve_file_under_root(&resolved_dir, index_file, "static index_file")?;
        }
        if let Some(fallback_file) = &fallback_file {
            resolve_file_under_root(&resolved_dir, fallback_file, "static fallback_file")?;
        }

        mounts.push(StaticMountSpec {
            mount_path,
            source_dir,
            resolved_dir: resolved_dir.display().to_string(),
            mode,
            index_file,
            fallback_file,
            cache,
        });
    }

    Ok(mounts)
}

fn normalize_mount_path(value: &str) -> syn::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "static mount path cannot be empty",
        ));
    }

    if !trimmed.starts_with('/') {
        return Err(syn::Error::new(
            Span::call_site(),
            "static mount path must start with `/`",
        ));
    }

    if trimmed != "/" && trimmed.ends_with('/') {
        return Ok(trimmed.trim_end_matches('/').to_owned());
    }

    Ok(trimmed.to_owned())
}

fn validate_mount_path(mount_path: &str) -> syn::Result<()> {
    if matches!(mount_path, "/api" | "/auth" | "/docs" | "/openapi.json") {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("static mount `{mount_path}` conflicts with a reserved route"),
        ));
    }

    if mount_path.contains("//") {
        return Err(syn::Error::new(
            Span::call_site(),
            "static mount path cannot contain `//`",
        ));
    }

    Ok(())
}

fn validate_relative_path(value: &str, label: &str) -> syn::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} cannot be empty"),
        ));
    }

    let path = Path::new(trimmed);
    if path.is_absolute() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} must be relative to the `.eon` file"),
        ));
    }

    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} cannot escape the service directory"),
        ));
    }

    Ok(trimmed.to_owned())
}

fn resolve_directory_under_root(service_root: &Path, relative_dir: &str) -> syn::Result<PathBuf> {
    let resolved = service_root.join(relative_dir);
    let canonical = resolved.canonicalize().map_err(|error| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to resolve static dir `{relative_dir}`: {error}"),
        )
    })?;
    if !canonical.starts_with(service_root) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("static dir `{relative_dir}` resolves outside the service directory"),
        ));
    }
    if !canonical.is_dir() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("static dir `{relative_dir}` is not a directory"),
        ));
    }
    Ok(canonical)
}

fn resolve_file_under_root(
    base_dir: &Path,
    relative_file: &str,
    label: &str,
) -> syn::Result<PathBuf> {
    let resolved = base_dir.join(relative_file);
    let canonical = resolved.canonicalize().map_err(|error| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to resolve {label} `{relative_file}`: {error}"),
        )
    })?;
    if !canonical.starts_with(base_dir) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} `{relative_file}` resolves outside the static dir"),
        ));
    }
    if !canonical.is_file() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} `{relative_file}` is not a file"),
        ));
    }
    Ok(canonical)
}

fn parse_static_mode(value: &str) -> syn::Result<StaticMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "directory" => Ok(StaticMode::Directory),
        "spa" => Ok(StaticMode::Spa),
        _ => Err(syn::Error::new(
            Span::call_site(),
            "static mode must be `Directory` or `Spa`",
        )),
    }
}

fn parse_static_cache_profile(value: &str) -> syn::Result<StaticCacheProfile> {
    match value.trim().to_ascii_lowercase().as_str() {
        "nostore" | "no_store" | "no-store" => Ok(StaticCacheProfile::NoStore),
        "revalidate" => Ok(StaticCacheProfile::Revalidate),
        "immutable" => Ok(StaticCacheProfile::Immutable),
        _ => Err(syn::Error::new(
            Span::call_site(),
            "static cache must be `NoStore`, `Revalidate`, or `Immutable`",
        )),
    }
}

fn parse_field_type(field_ty: &FieldTypeDocument, nullable: bool) -> syn::Result<Type> {
    let base = match field_ty {
        FieldTypeDocument::Scalar(scalar) => scalar.rust_type().to_owned(),
        FieldTypeDocument::Rust(raw) => raw.clone(),
    };

    let rust_type = if nullable {
        format!("Option<{base}>")
    } else {
        base
    };

    syn::parse_str::<Type>(&rust_type).map_err(|error| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to parse Rust type `{rust_type}`: {error}"),
        )
    })
}

impl ScalarType {
    fn rust_type(self) -> &'static str {
        match self {
            Self::String => "String",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::Bool => "bool",
            Self::DateTime => GENERATED_DATETIME_ALIAS,
            Self::Date => GENERATED_DATE_ALIAS,
            Self::Time => GENERATED_TIME_ALIAS,
            Self::Uuid => GENERATED_UUID_ALIAS,
            Self::Decimal => GENERATED_DECIMAL_ALIAS,
        }
    }
}

fn parse_relation_document(relation: RelationDocument) -> syn::Result<super::model::RelationSpec> {
    let mut parts = relation.references.split('.');
    let references_table = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "relation references must be `table.field`",
            )
        })?;
    let references_field = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "relation references must be `table.field`",
            )
        })?;

    if parts.next().is_some() {
        return Err(syn::Error::new(
            Span::call_site(),
            "relation references must be exactly `table.field`",
        ));
    }

    validate_sql_identifier(references_table, Span::call_site(), "relation table")?;
    validate_sql_identifier(references_field, Span::call_site(), "relation field")?;

    let on_delete = relation
        .on_delete
        .as_deref()
        .map(parse_referential_action)
        .transpose()?;

    Ok(super::model::RelationSpec {
        references_table: references_table.to_owned(),
        references_field: references_field.to_owned(),
        on_delete,
        nested_route: relation.nested_route,
    })
}

fn parse_referential_action(value: &str) -> syn::Result<ReferentialAction> {
    ReferentialAction::parse(value).ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "relation on_delete must be Cascade, Restrict, SetNull, or NoAction",
        )
    })
}

fn parse_field_validation_document(document: Option<FieldValidationDocument>) -> FieldValidation {
    let Some(document) = document else {
        return FieldValidation::default();
    };

    FieldValidation {
        min_length: document.min_length,
        max_length: document.max_length,
        minimum: document.minimum.map(parse_numeric_bound_document),
        maximum: document.maximum.map(parse_numeric_bound_document),
    }
}

fn parse_numeric_bound_document(bound: NumericBoundDocument) -> NumericBound {
    match bound {
        NumericBoundDocument::Integer(value) => NumericBound::Integer(value),
        NumericBoundDocument::Float(value) => NumericBound::Float(value),
    }
}

fn parse_row_policies(policies: RowPoliciesDocument) -> syn::Result<RowPolicies> {
    let (create_require, create_assignments) = parse_create_policies(policies.create)?;
    Ok(RowPolicies {
        admin_bypass: policies.admin_bypass,
        read: parse_filter_policies("read", policies.read)?,
        create_require,
        create: create_assignments,
        update: parse_filter_policies("update", policies.update)?,
        delete: parse_filter_policies("delete", policies.delete)?,
    })
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

fn parse_filter_policies(
    scope: &'static str,
    policies: Option<FilterPoliciesDocument>,
) -> syn::Result<Option<PolicyFilterExpression>> {
    policies
        .map(|policy| parse_filter_policy_expression(scope, policy))
        .transpose()
}

fn parse_assignment_policies(
    scope: &'static str,
    policies: Option<ScopePoliciesDocument>,
) -> syn::Result<Vec<PolicyAssignment>> {
    expand_policy_entries(policies)?
        .into_iter()
        .map(|policy| parse_assignment_policy(scope, policy))
        .collect()
}

fn parse_create_policies(
    policies: Option<CreatePoliciesDocument>,
) -> syn::Result<(Option<PolicyFilterExpression>, Vec<PolicyAssignment>)> {
    match policies {
        None => Ok((None, Vec::new())),
        Some(CreatePoliciesDocument::Assignments(assignments)) => Ok((
            None,
            parse_assignment_policies("create", Some(assignments))?,
        )),
        Some(CreatePoliciesDocument::Structured(group)) => {
            if group.assign.is_none() && group.require.is_none() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "create row policy groups must set at least one of `assign` or `require`",
                ));
            }
            Ok((
                parse_filter_policies("create.require", group.require)?,
                parse_assignment_policies("create", group.assign)?,
            ))
        }
    }
}

fn expand_policy_entries(
    policies: Option<ScopePoliciesDocument>,
) -> syn::Result<Vec<PolicyEntryDocument>> {
    let Some(policies) = policies else {
        return Ok(Vec::new());
    };

    let entries = match policies {
        ScopePoliciesDocument::Single(entry) => vec![entry],
        ScopePoliciesDocument::Many(entries) => entries,
    };

    if entries.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "row policy entries cannot be empty",
        ));
    }

    Ok(entries)
}

fn parse_filter_policy_expression(
    scope: &'static str,
    policy: FilterPoliciesDocument,
) -> syn::Result<PolicyFilterExpression> {
    match policy {
        FilterPoliciesDocument::Group(group) => parse_filter_policy_group(scope, group),
        FilterPoliciesDocument::Many(entries) => {
            if entries.is_empty() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "row policy entries cannot be empty",
                ));
            }
            let expressions = entries
                .into_iter()
                .map(|entry| parse_filter_policy_expression(scope, entry))
                .collect::<syn::Result<Vec<_>>>()?;
            PolicyFilterExpression::all(expressions).ok_or_else(|| {
                syn::Error::new(Span::call_site(), "row policy entries cannot be empty")
            })
        }
        FilterPoliciesDocument::Single(policy) => {
            parse_filter_policy(scope, policy).map(PolicyFilterExpression::Match)
        }
    }
}

fn parse_filter_policy_group(
    scope: &'static str,
    group: FilterPolicyGroupDocument,
) -> syn::Result<PolicyFilterExpression> {
    let present = usize::from(group.all_of.is_some())
        + usize::from(group.any_of.is_some())
        + usize::from(group.not.is_some())
        + usize::from(group.exists.is_some());
    if present != 1 {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "{scope} row policy groups must set exactly one of `all_of`, `any_of`, `not`, or `exists`"
            ),
        ));
    }

    if let Some(entries) = group.all_of {
        if entries.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy `all_of` entries cannot be empty"),
            ));
        }
        let expressions = entries
            .into_iter()
            .map(|entry| parse_filter_policy_expression(scope, entry))
            .collect::<syn::Result<Vec<_>>>()?;
        return PolicyFilterExpression::all(expressions).ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy `all_of` entries cannot be empty"),
            )
        });
    }

    if let Some(entries) = group.any_of {
        if entries.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy `any_of` entries cannot be empty"),
            ));
        }
        let expressions = entries
            .into_iter()
            .map(|entry| parse_filter_policy_expression(scope, entry))
            .collect::<syn::Result<Vec<_>>>()?;
        return PolicyFilterExpression::any(expressions).ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy `any_of` entries cannot be empty"),
            )
        });
    }

    let Some(policy) = group.not else {
        if let Some(filter) = group.exists {
            return parse_exists_policy(scope, filter);
        }
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "{scope} row policy groups must set exactly one of `all_of`, `any_of`, `not`, or `exists`"
            ),
        ));
    };
    Ok(PolicyFilterExpression::Not(Box::new(
        parse_filter_policy_expression(scope, *policy)?,
    )))
}

fn parse_exists_policy(
    scope: &'static str,
    policy: ExistsPolicyDocument,
) -> syn::Result<PolicyFilterExpression> {
    if policy.resource.trim().is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{scope} row policy exists resource cannot be empty"),
        ));
    }
    Ok(PolicyFilterExpression::Exists(PolicyExistsFilter {
        resource: policy.resource,
        condition: parse_exists_policy_expression(scope, policy.condition)?,
    }))
}

fn parse_exists_policy_expression(
    scope: &'static str,
    policy: Option<ExistsPolicyEntriesDocument>,
) -> syn::Result<PolicyExistsCondition> {
    let Some(policy) = policy else {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{scope} row policy exists conditions cannot be empty"),
        ));
    };
    parse_exists_policy_node(scope, policy)
}

fn parse_exists_policy_node(
    scope: &'static str,
    policy: ExistsPolicyEntriesDocument,
) -> syn::Result<PolicyExistsCondition> {
    match policy {
        ExistsPolicyEntriesDocument::Group(group) => parse_exists_policy_group(scope, group),
        ExistsPolicyEntriesDocument::Many(entries) => {
            if entries.is_empty() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!("{scope} row policy exists conditions cannot be empty"),
                ));
            }
            let expressions = entries
                .into_iter()
                .map(|entry| parse_exists_policy_node(scope, entry))
                .collect::<syn::Result<Vec<_>>>()?;
            PolicyExistsCondition::all(expressions).ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!("{scope} row policy exists conditions cannot be empty"),
                )
            })
        }
        ExistsPolicyEntriesDocument::Single(entry) => parse_exists_policy_entry(scope, entry),
    }
}

fn parse_exists_policy_group(
    scope: &'static str,
    group: ExistsPolicyGroupDocument,
) -> syn::Result<PolicyExistsCondition> {
    let present = usize::from(group.all_of.is_some())
        + usize::from(group.any_of.is_some())
        + usize::from(group.not.is_some());
    if present != 1 {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "{scope} row policy exists groups must set exactly one of `all_of`, `any_of`, or `not`"
            ),
        ));
    }

    if let Some(entries) = group.all_of {
        if entries.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy exists `all_of` entries cannot be empty"),
            ));
        }
        let expressions = entries
            .into_iter()
            .map(|entry| parse_exists_policy_node(scope, entry))
            .collect::<syn::Result<Vec<_>>>()?;
        return PolicyExistsCondition::all(expressions).ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy exists `all_of` entries cannot be empty"),
            )
        });
    }

    if let Some(entries) = group.any_of {
        if entries.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy exists `any_of` entries cannot be empty"),
            ));
        }
        let expressions = entries
            .into_iter()
            .map(|entry| parse_exists_policy_node(scope, entry))
            .collect::<syn::Result<Vec<_>>>()?;
        return PolicyExistsCondition::any(expressions).ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!("{scope} row policy exists `any_of` entries cannot be empty"),
            )
        });
    }

    let Some(policy) = group.not else {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "{scope} row policy exists groups must set exactly one of `all_of`, `any_of`, or `not`"
            ),
        ));
    };
    Ok(PolicyExistsCondition::Not(Box::new(
        parse_exists_policy_node(scope, *policy)?,
    )))
}

fn parse_exists_policy_entry(
    scope: &'static str,
    policy: ExistsPolicyEntryDocument,
) -> syn::Result<PolicyExistsCondition> {
    match policy {
        ExistsPolicyEntryDocument::Legacy(policy) => {
            let filter = parse_filter_policy(scope, PolicyEntryDocument::Legacy(policy))?;
            Ok(PolicyExistsCondition::Match(filter))
        }
        ExistsPolicyEntryDocument::Shorthand(policy) => {
            let filter = parse_filter_shorthand(scope, &policy)?;
            Ok(PolicyExistsCondition::Match(filter))
        }
        ExistsPolicyEntryDocument::Rule(policy) => {
            let present = usize::from(policy.equals.is_some())
                + usize::from(policy.equals_field.is_some())
                + usize::from(policy.is_null)
                + usize::from(policy.is_not_null);
            if present != 1 {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "{scope} row policy exists entries must set exactly one of `equals`, `equals_field`, `is_null`, or `is_not_null`"
                    ),
                ));
            }
            if let Some(source) = policy.equals {
                return Ok(PolicyExistsCondition::Match(PolicyFilter {
                    field: policy.field,
                    operator: PolicyFilterOperator::Equals(parse_policy_source(&source)?),
                }));
            }
            if policy.is_null {
                return Ok(PolicyExistsCondition::Match(PolicyFilter {
                    field: policy.field,
                    operator: PolicyFilterOperator::IsNull,
                }));
            }
            if policy.is_not_null {
                return Ok(PolicyExistsCondition::Match(PolicyFilter {
                    field: policy.field,
                    operator: PolicyFilterOperator::IsNotNull,
                }));
            }
            Ok(PolicyExistsCondition::CurrentRowField {
                field: policy.field,
                row_field: policy.equals_field.expect("validated above"),
            })
        }
    }
}

fn parse_filter_policy(
    scope: &'static str,
    policy: PolicyEntryDocument,
) -> syn::Result<PolicyFilter> {
    match policy {
        PolicyEntryDocument::Legacy(policy) => {
            let kind = RowPolicyKind::parse(&policy.kind).ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        "row policy kind must be `Owner` or `SetOwner` (got `{}`)",
                        policy.kind
                    ),
                )
            })?;
            match kind {
                RowPolicyKind::Owner => Ok(PolicyFilter {
                    field: policy.field,
                    operator: PolicyFilterOperator::Equals(PolicyValueSource::UserId),
                }),
                RowPolicyKind::SetOwner => Err(syn::Error::new(
                    Span::call_site(),
                    format!("{scope} row policy must use `Owner` semantics"),
                )),
            }
        }
        PolicyEntryDocument::Rule(policy) => {
            let present = usize::from(policy.equals.is_some())
                + usize::from(policy.is_null)
                + usize::from(policy.is_not_null);
            if present != 1 {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "{scope} row policy entries must set exactly one of `equals`, `is_null`, or `is_not_null`"
                    ),
                ));
            }
            if let Some(source) = policy.equals {
                return Ok(PolicyFilter {
                    field: policy.field,
                    operator: PolicyFilterOperator::Equals(parse_policy_source(&source)?),
                });
            }
            if policy.is_null {
                return Ok(PolicyFilter {
                    field: policy.field,
                    operator: PolicyFilterOperator::IsNull,
                });
            }
            Ok(PolicyFilter {
                field: policy.field,
                operator: PolicyFilterOperator::IsNotNull,
            })
        }
        PolicyEntryDocument::Shorthand(policy) => parse_filter_shorthand(scope, &policy),
    }
}

fn parse_assignment_policy(
    scope: &'static str,
    policy: PolicyEntryDocument,
) -> syn::Result<PolicyAssignment> {
    match policy {
        PolicyEntryDocument::Legacy(policy) => {
            let kind = RowPolicyKind::parse(&policy.kind).ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        "row policy kind must be `Owner` or `SetOwner` (got `{}`)",
                        policy.kind
                    ),
                )
            })?;
            match kind {
                RowPolicyKind::SetOwner => Ok(PolicyAssignment {
                    field: policy.field,
                    source: PolicyValueSource::UserId,
                }),
                RowPolicyKind::Owner => Err(syn::Error::new(
                    Span::call_site(),
                    "create row policy must use kind `SetOwner`",
                )),
            }
        }
        PolicyEntryDocument::Rule(policy) => {
            if policy.value.is_none()
                && policy.equals.is_none()
                && !policy.is_null
                && !policy.is_not_null
                && (policy.field.contains('=') || policy.field.contains(':'))
            {
                return parse_assignment_shorthand(&policy.field);
            }
            let source = policy.value.ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!("{scope} row policy entries must use `value`"),
                )
            })?;
            Ok(PolicyAssignment {
                field: policy.field,
                source: parse_policy_source(&source)?,
            })
        }
        PolicyEntryDocument::Shorthand(policy) => parse_assignment_shorthand(&policy),
    }
}

fn parse_filter_shorthand(scope: &'static str, value: &str) -> syn::Result<PolicyFilter> {
    if let Some(field) = parse_legacy_policy_field(value, RowPolicyKind::Owner) {
        return Ok(PolicyFilter {
            field,
            operator: PolicyFilterOperator::Equals(PolicyValueSource::UserId),
        });
    }

    if parse_legacy_policy_field(value, RowPolicyKind::SetOwner).is_some() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{scope} row policy must use `Owner` semantics"),
        ));
    }

    let (field, source) = parse_policy_expression(value)?;
    Ok(PolicyFilter {
        field,
        operator: PolicyFilterOperator::Equals(source),
    })
}

fn parse_assignment_shorthand(value: &str) -> syn::Result<PolicyAssignment> {
    if let Some(field) = parse_legacy_policy_field(value, RowPolicyKind::SetOwner) {
        return Ok(PolicyAssignment {
            field,
            source: PolicyValueSource::UserId,
        });
    }

    if parse_legacy_policy_field(value, RowPolicyKind::Owner).is_some() {
        return Err(syn::Error::new(
            Span::call_site(),
            "create row policy must use kind `SetOwner`",
        ));
    }

    let (field, source) = parse_policy_expression(value)?;
    Ok(PolicyAssignment { field, source })
}

fn parse_legacy_policy_field(value: &str, kind: RowPolicyKind) -> Option<String> {
    let (parsed_kind, field) = value.split_once(':')?;
    let parsed_kind = RowPolicyKind::parse(parsed_kind.trim())?;
    if parsed_kind != kind {
        return None;
    }

    let field = field.trim();
    if field.is_empty() {
        None
    } else {
        Some(field.to_owned())
    }
}

fn parse_policy_expression(value: &str) -> syn::Result<(String, PolicyValueSource)> {
    let (field, source) = value.split_once('=').ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "row policy values must use `field=source`",
        )
    })?;
    let field = field.trim();
    if field.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "row policy field name cannot be empty",
        ));
    }

    Ok((field.to_owned(), parse_policy_source(source)?))
}

fn parse_policy_source(value: &str) -> syn::Result<PolicyValueSource> {
    PolicyValueSource::parse(value).ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "row policy source must be `user.id`, `claim.<name>`, or `input.<field>`",
        )
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    fn parse_document(source: &str) -> ServiceDocument {
        eon::from_str::<ServiceDocument>(source).expect("eon should parse")
    }

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}_{stamp}"))
    }

    #[test]
    fn parses_turso_local_database_engine_from_eon() {
        let database = parse_database_document(
            DbBackend::Sqlite,
            Some(DatabaseDocument {
                engine: Some(DatabaseEngineDocument {
                    kind: "TursoLocal".to_owned(),
                    path: Some("var/data/app.db".to_owned()),
                    encryption_key_env: None,
                }),
                resilience: None,
            }),
            "app_api",
            Span::call_site(),
        )
        .expect("database config should parse");
        assert_eq!(
            database.engine,
            DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: "var/data/app.db".to_owned(),
                encryption_key_env: None,
            })
        );
        assert!(database.resilience.is_none());
    }

    #[test]
    fn rejects_turso_local_for_non_sqlite_dialect() {
        let error = parse_database_document(
            DbBackend::Postgres,
            Some(DatabaseDocument {
                engine: Some(DatabaseEngineDocument {
                    kind: "TursoLocal".to_owned(),
                    path: Some("var/data/app.db".to_owned()),
                    encryption_key_env: None,
                }),
                resilience: None,
            }),
            "app_api",
            Span::call_site(),
        )
        .expect_err("non-sqlite turso config should fail");
        assert!(
            error
                .to_string()
                .contains("database.engine = TursoLocal requires `db: Sqlite`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn defaults_sqlite_services_to_turso_local_engine() {
        let database =
            parse_database_document(DbBackend::Sqlite, None, "blog_api", Span::call_site())
                .expect("sqlite service should default to turso local");
        assert_eq!(
            database.engine,
            DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: "var/data/blog_api.db".to_owned(),
                encryption_key_env: Some(DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV.to_owned()),
            })
        );
        assert!(database.resilience.is_none());
    }

    #[test]
    fn parses_database_resilience_contract_from_eon() {
        let database = parse_database_document(
            DbBackend::Postgres,
            Some(DatabaseDocument {
                engine: Some(DatabaseEngineDocument {
                    kind: "Sqlx".to_owned(),
                    path: None,
                    encryption_key_env: None,
                }),
                resilience: Some(DatabaseResilienceDocument {
                    profile: Some("Pitr".to_owned()),
                    backup: Some(DatabaseBackupDocument {
                        required: Some(true),
                        mode: Some("Pitr".to_owned()),
                        target: Some("S3".to_owned()),
                        verify_restore: Some(true),
                        max_age: Some("24h".to_owned()),
                        encryption_key_env: Some("BACKUP_ENCRYPTION_KEY".to_owned()),
                        retention: Some(DatabaseBackupRetentionDocument {
                            daily: Some(7),
                            weekly: Some(4),
                            monthly: Some(12),
                        }),
                    }),
                    replication: Some(DatabaseReplicationDocument {
                        mode: Some("ReadReplica".to_owned()),
                        read_routing: Some("Explicit".to_owned()),
                        read_url_env: Some("DATABASE_READ_URL".to_owned()),
                        max_lag: Some("30s".to_owned()),
                        replicas_expected: Some(1),
                    }),
                }),
            }),
            "app_api",
            Span::call_site(),
        )
        .expect("database resilience should parse");

        let resilience = database.resilience.expect("resilience should exist");
        assert_eq!(resilience.profile, DatabaseResilienceProfile::Pitr);
        let backup = resilience.backup.expect("backup should exist");
        assert_eq!(backup.mode, DatabaseBackupMode::Pitr);
        assert_eq!(backup.target, DatabaseBackupTarget::S3);
        assert!(backup.verify_restore);
        assert_eq!(backup.max_age.as_deref(), Some("24h"));
        let replication = resilience.replication.expect("replication should exist");
        assert_eq!(replication.mode, DatabaseReplicationMode::ReadReplica);
        assert_eq!(replication.read_routing, DatabaseReadRoutingMode::Explicit);
        assert_eq!(
            replication.read_url_env.as_deref(),
            Some("DATABASE_READ_URL")
        );
    }

    #[test]
    fn rejects_replication_read_routing_without_read_url_env() {
        let error = parse_database_document(
            DbBackend::Postgres,
            Some(DatabaseDocument {
                engine: Some(DatabaseEngineDocument {
                    kind: "Sqlx".to_owned(),
                    path: None,
                    encryption_key_env: None,
                }),
                resilience: Some(DatabaseResilienceDocument {
                    profile: None,
                    backup: None,
                    replication: Some(DatabaseReplicationDocument {
                        mode: Some("ReadReplica".to_owned()),
                        read_routing: Some("Explicit".to_owned()),
                        read_url_env: None,
                        max_lag: None,
                        replicas_expected: None,
                    }),
                }),
            }),
            "app_api",
            Span::call_site(),
        )
        .expect_err("missing read url should fail");

        assert!(
            error
                .to_string()
                .contains("database.resilience.replication.read_url_env is required"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_turso_local_replication_contract() {
        let error = parse_database_document(
            DbBackend::Sqlite,
            Some(DatabaseDocument {
                engine: Some(DatabaseEngineDocument {
                    kind: "TursoLocal".to_owned(),
                    path: Some("var/data/app.db".to_owned()),
                    encryption_key_env: None,
                }),
                resilience: Some(DatabaseResilienceDocument {
                    profile: Some("Ha".to_owned()),
                    backup: None,
                    replication: Some(DatabaseReplicationDocument {
                        mode: Some("ReadReplica".to_owned()),
                        read_routing: Some("Off".to_owned()),
                        read_url_env: None,
                        max_lag: None,
                        replicas_expected: None,
                    }),
                }),
            }),
            "app_api",
            Span::call_site(),
        )
        .expect_err("turso local replication should fail");

        assert!(
            error
                .to_string()
                .contains("database.resilience.replication is not supported for `database.engine = TursoLocal`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn parses_datetime_scalar_as_typed_datetime_field() {
        let resources = build_resources(
            DbBackend::Sqlite,
            vec![ResourceDocument {
                name: "Event".to_owned(),
                table: None,
                id_field: None,
                roles: RoleRequirements::default(),
                policies: RowPoliciesDocument::default(),
                list: ListConfigDocument::default(),
                fields: vec![
                    FieldDocument {
                        name: "id".to_owned(),
                        ty: FieldTypeDocument::Scalar(ScalarType::I64),
                        nullable: false,
                        id: true,
                        generated: GeneratedValue::None,
                        relation: None,
                        validate: None,
                    },
                    FieldDocument {
                        name: "starts_at".to_owned(),
                        ty: FieldTypeDocument::Scalar(ScalarType::DateTime),
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        relation: None,
                        validate: None,
                    },
                ],
            }],
        )
        .expect("resources should build");

        let starts_at = resources[0]
            .find_field("starts_at")
            .expect("starts_at field should exist");
        assert_eq!(starts_at.sql_type, "TEXT");
        assert!(super::super::model::is_datetime_type(&starts_at.ty));
    }

    #[test]
    fn parses_portable_scalar_types_as_typed_fields() {
        let resources = build_resources(
            DbBackend::Sqlite,
            vec![ResourceDocument {
                name: "Schedule".to_owned(),
                table: None,
                id_field: None,
                roles: RoleRequirements::default(),
                policies: RowPoliciesDocument::default(),
                list: ListConfigDocument::default(),
                fields: vec![
                    FieldDocument {
                        name: "id".to_owned(),
                        ty: FieldTypeDocument::Scalar(ScalarType::I64),
                        nullable: false,
                        id: true,
                        generated: GeneratedValue::None,
                        relation: None,
                        validate: None,
                    },
                    FieldDocument {
                        name: "run_on".to_owned(),
                        ty: FieldTypeDocument::Scalar(ScalarType::Date),
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        relation: None,
                        validate: None,
                    },
                    FieldDocument {
                        name: "run_at".to_owned(),
                        ty: FieldTypeDocument::Scalar(ScalarType::Time),
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        relation: None,
                        validate: None,
                    },
                    FieldDocument {
                        name: "external_id".to_owned(),
                        ty: FieldTypeDocument::Scalar(ScalarType::Uuid),
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        relation: None,
                        validate: None,
                    },
                    FieldDocument {
                        name: "amount".to_owned(),
                        ty: FieldTypeDocument::Scalar(ScalarType::Decimal),
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        relation: None,
                        validate: None,
                    },
                ],
            }],
        )
        .expect("resources should build");

        let run_on = resources[0]
            .find_field("run_on")
            .expect("run_on field should exist");
        let run_at = resources[0]
            .find_field("run_at")
            .expect("run_at field should exist");
        let external_id = resources[0]
            .find_field("external_id")
            .expect("external_id field should exist");
        let amount = resources[0]
            .find_field("amount")
            .expect("amount field should exist");

        assert_eq!(run_on.sql_type, "TEXT");
        assert_eq!(run_at.sql_type, "TEXT");
        assert_eq!(external_id.sql_type, "TEXT");
        assert_eq!(amount.sql_type, "TEXT");
        assert!(super::super::model::is_date_type(&run_on.ty));
        assert!(super::super::model::is_time_type(&run_at.ty));
        assert!(super::super::model::is_uuid_type(&external_id.ty));
        assert!(super::super::model::is_decimal_type(&amount.ty));
    }

    #[test]
    fn rejects_invalid_table_identifier_from_eon() {
        let error = build_resources(
            DbBackend::Sqlite,
            vec![ResourceDocument {
                name: "Post".to_owned(),
                table: Some("post; DROP TABLE user;".to_owned()),
                id_field: None,
                roles: RoleRequirements::default(),
                policies: RowPoliciesDocument::default(),
                list: ListConfigDocument::default(),
                fields: vec![
                    FieldDocument {
                        name: "id".to_owned(),
                        ty: FieldTypeDocument::Scalar(ScalarType::I64),
                        nullable: false,
                        id: true,
                        generated: GeneratedValue::None,
                        relation: None,
                        validate: None,
                    },
                    FieldDocument {
                        name: "title".to_owned(),
                        ty: FieldTypeDocument::Scalar(ScalarType::String),
                        nullable: false,
                        id: false,
                        generated: GeneratedValue::None,
                        relation: None,
                        validate: None,
                    },
                ],
            }],
        )
        .expect_err("invalid table identifier should fail");
        assert!(error.to_string().contains("table name"));
        assert!(error.to_string().contains("valid SQL identifier"));
    }

    #[test]
    fn rejects_invalid_relation_identifier_from_eon() {
        let error = parse_relation_document(RelationDocument {
            references: "post.id); DROP TABLE user;".to_owned(),
            on_delete: None,
            nested_route: false,
        })
        .expect_err("invalid relation identifier should fail");
        assert!(error.to_string().contains("relation field"));
        assert!(error.to_string().contains("valid SQL identifier"));
    }

    #[test]
    fn parses_row_policies_from_eon() {
        let path = syn::LitStr::new("test.eon", Span::call_site());
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { kind: Owner, field: "user_id" }
                        create: { kind: SetOwner, field: "user_id" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let service = LoadedService {
            service: ServiceSpec {
                module_ident: sanitize_module_ident("test", Span::call_site()),
                resources: build_resources(document.db, document.resources)
                    .expect("resources should build"),
                authorization: AuthorizationContract::default(),
                static_mounts: Vec::new(),
                database: parse_database_document(
                    document.db,
                    document.database,
                    "test",
                    Span::call_site(),
                )
                .expect("database config should parse"),
                logging: LoggingConfig::default(),
                runtime: RuntimeConfig::default(),
                security: SecurityConfig::default(),
                tls: TlsConfig::default(),
            },
            include_path: path.value(),
        };

        let resource = &service.service.resources[0];
        let read_filters = resource
            .policies
            .iter_filters()
            .into_iter()
            .filter(|(scope, _)| *scope == "read")
            .map(|(_, filter)| filter)
            .collect::<Vec<_>>();
        assert_eq!(read_filters[0].field, "user_id");
        assert_eq!(
            resource.policies.create[0].source,
            super::super::model::PolicyValueSource::UserId
        );
    }

    #[test]
    fn parses_claim_based_row_policies_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        admin_bypass: false
                        read: [
                            "user_id=user.id"
                            { field: "tenant_id", equals: "claim.tenant_id" }
                        ]
                        create: [
                            "user_id=user.id"
                            { field: "tenant_id", value: "claim.tenant_id" }
                        ]
                        update: { field: "tenant_id", equals: "claim.tenant_id" }
                        delete: { field: "tenant_id", equals: "claim.tenant_id" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "tenant_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let resource = &resources[0];
        assert!(!resource.policies.admin_bypass);
        let read_filters = resource
            .policies
            .iter_filters()
            .into_iter()
            .filter(|(scope, _)| *scope == "read")
            .map(|(_, filter)| filter)
            .collect::<Vec<_>>();
        assert_eq!(read_filters.len(), 2);
        assert_eq!(
            read_filters[1].operator,
            super::super::model::PolicyFilterOperator::Equals(
                super::super::model::PolicyValueSource::Claim("tenant_id".to_owned())
            )
        );
        assert_eq!(resource.policies.create.len(), 2);
    }

    #[test]
    fn parses_null_check_row_policies_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Note"
                    policies: {
                        read: { field: "archived_at", is_null: true }
                        delete: { field: "archived_at", is_not_null: true }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "title", type: String }
                        { name: "archived_at", type: String, nullable: true }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let resource = &resources[0];
        let read = resource
            .policies
            .read
            .as_ref()
            .expect("read policy should exist");
        let delete = resource
            .policies
            .delete
            .as_ref()
            .expect("delete policy should exist");

        match read {
            PolicyFilterExpression::Match(filter) => assert_eq!(
                filter.operator,
                super::super::model::PolicyFilterOperator::IsNull
            ),
            other => panic!("expected read null-check filter, got {other:?}"),
        }
        match delete {
            PolicyFilterExpression::Match(filter) => assert_eq!(
                filter.operator,
                super::super::model::PolicyFilterOperator::IsNotNull
            ),
            other => panic!("expected delete null-check filter, got {other:?}"),
        }
    }

    #[test]
    fn rejects_null_check_row_policies_for_non_nullable_fields() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Note"
                    policies: {
                        read: { field: "title", is_null: true }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let error = build_resources(document.db, document.resources)
            .expect_err("null checks on non-nullable fields should fail");
        assert!(
            error
                .to_string()
                .contains("null checks require nullable/optional field")
        );
    }

    #[test]
    fn parses_nested_boolean_row_policies_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: {
                            any_of: [
                                "owner_id=user.id"
                                {
                                    all_of: [
                                        "tenant_id=claim.tenant_id"
                                        { not: "blocked_user_id=user.id" }
                                    ]
                                }
                            ]
                        }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "owner_id", type: I64 }
                        { name: "tenant_id", type: I64 }
                        { name: "blocked_user_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let resource = &resources[0];
        let read = resource
            .policies
            .read
            .as_ref()
            .expect("read policy should be present");
        assert!(matches!(read, PolicyFilterExpression::Any(_)));

        let read_filters = resource
            .policies
            .iter_filters()
            .into_iter()
            .filter(|(scope, _)| *scope == "read")
            .map(|(_, filter)| filter)
            .collect::<Vec<_>>();
        assert_eq!(read_filters.len(), 3);
        assert_eq!(read_filters[2].field, "blocked_user_id");
    }

    #[test]
    fn parses_exists_row_policies_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "FamilyMember"
                    fields: [
                        { name: "id", type: I64 }
                        { name: "family_id", type: I64 }
                        { name: "user_id", type: I64 }
                    ]
                }
                {
                    name: "SharedDoc"
                    policies: {
                        read: {
                            exists: {
                                resource: "FamilyMember"
                                where: [
                                    { field: "family_id", equals_field: "family_id" }
                                    "user_id=user.id"
                                ]
                            }
                        }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "family_id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let resource = resources
            .iter()
            .find(|resource| resource.struct_ident.to_string() == "SharedDoc")
            .expect("shared doc resource should exist");
        let read = resource
            .policies
            .read
            .as_ref()
            .expect("read policy should be present");
        match read {
            PolicyFilterExpression::Exists(filter) => {
                assert_eq!(filter.resource, "FamilyMember");
                match &filter.condition {
                    super::super::model::PolicyExistsCondition::All(conditions) => {
                        assert_eq!(conditions.len(), 2);
                        assert!(matches!(
                            conditions[0],
                            super::super::model::PolicyExistsCondition::CurrentRowField { .. }
                        ));
                        assert!(matches!(
                            conditions[1],
                            super::super::model::PolicyExistsCondition::Match(_)
                        ));
                    }
                    other => panic!("expected implicit exists all_of group, got {other:?}"),
                }
            }
            other => panic!("expected exists filter, got {other:?}"),
        }
    }

    #[test]
    fn parses_create_require_policies_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Family"
                    fields: [
                        { name: "id", type: I64 }
                        { name: "owner_user_id", type: I64 }
                    ]
                }
                {
                    name: "FamilyMember"
                    policies: {
                        create: {
                            assign: [
                                "created_by_user_id=user.id"
                            ]
                            require: {
                                exists: {
                                    resource: "Family"
                                    where: [
                                        { field: "id", equals: "input.family_id" }
                                        "owner_user_id=user.id"
                                    ]
                                }
                            }
                        }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "family_id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "created_by_user_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let resource = resources
            .iter()
            .find(|resource| resource.struct_ident.to_string() == "FamilyMember")
            .expect("family member resource should exist");

        assert_eq!(resource.policies.create.len(), 1);
        let create_require = resource
            .policies
            .create_require
            .as_ref()
            .expect("create.require should be present");
        match create_require {
            PolicyFilterExpression::Exists(filter) => match &filter.condition {
                super::super::model::PolicyExistsCondition::All(conditions) => {
                    assert_eq!(conditions.len(), 2);
                    match &conditions[0] {
                        super::super::model::PolicyExistsCondition::Match(filter) => {
                            assert_eq!(filter.field, "id");
                            assert_eq!(
                                filter.operator,
                                super::super::model::PolicyFilterOperator::Equals(
                                    PolicyValueSource::InputField("family_id".to_owned())
                                )
                            );
                        }
                        other => panic!("expected input match inside exists, got {other:?}"),
                    }
                }
                other => panic!("expected implicit exists all_of group, got {other:?}"),
            },
            other => panic!("expected exists create.require filter, got {other:?}"),
        }
    }

    #[test]
    fn rejects_input_sources_outside_create_require() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { field: "tenant_id", equals: "input.tenant_id" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "tenant_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let error = build_resources(document.db, document.resources)
            .expect_err("input sources outside create.require should fail");
        assert!(
            error
                .to_string()
                .contains("read row policy field `tenant_id` cannot use `input.tenant_id`")
        );
    }

    #[test]
    fn parses_nested_boolean_groups_inside_exists_policies() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "FamilyAccess"
                    fields: [
                        { name: "id", type: I64 }
                        { name: "family_id", type: I64 }
                        { name: "primary_user_id", type: I64 }
                        { name: "delegate_user_id", type: I64 }
                    ]
                }
                {
                    name: "SharedDoc"
                    policies: {
                        read: {
                            exists: {
                                resource: "FamilyAccess"
                                where: [
                                    { field: "family_id", equals_field: "family_id" }
                                    {
                                        any_of: [
                                            "primary_user_id=user.id"
                                            "delegate_user_id=user.id"
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "family_id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let resource = resources
            .iter()
            .find(|resource| resource.struct_ident.to_string() == "SharedDoc")
            .expect("shared doc resource should exist");
        let read = resource
            .policies
            .read
            .as_ref()
            .expect("read policy should be present");
        match read {
            PolicyFilterExpression::Exists(filter) => match &filter.condition {
                super::super::model::PolicyExistsCondition::All(conditions) => {
                    assert_eq!(conditions.len(), 2);
                    assert!(matches!(
                        conditions[0],
                        super::super::model::PolicyExistsCondition::CurrentRowField { .. }
                    ));
                    match &conditions[1] {
                        super::super::model::PolicyExistsCondition::Any(inner) => {
                            assert_eq!(inner.len(), 2);
                            assert!(matches!(
                                inner[0],
                                super::super::model::PolicyExistsCondition::Match(_)
                            ));
                            assert!(matches!(
                                inner[1],
                                super::super::model::PolicyExistsCondition::Match(_)
                            ));
                        }
                        other => panic!("expected any_of group inside exists, got {other:?}"),
                    }
                }
                other => panic!("expected implicit exists all_of group, got {other:?}"),
            },
            other => panic!("expected exists filter, got {other:?}"),
        }
    }

    #[test]
    fn rejects_exists_row_policies_for_unknown_resource() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "SharedDoc"
                    policies: {
                        read: {
                            exists: {
                                resource: "FamilyMember"
                                where: [
                                    { field: "family_id", equals_field: "family_id" }
                                    "user_id=user.id"
                                ]
                            }
                        }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "family_id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let error = build_resources(document.db, document.resources)
            .expect_err("unknown exists resource should fail");
        assert!(
            error
                .to_string()
                .contains("unknown exists resource `FamilyMember`")
        );
    }

    #[test]
    fn parses_security_config_from_eon() {
        let document = parse_document(
            r#"
            logging: {
                filter_env: "APP_LOG"
                default_filter: "debug,sqlx=warn"
                timestamp: Millis
            }
            security: {
                requests: { json_max_bytes: 128 }
                cors: {
                    origins: ["http://localhost:3000"]
                    origins_env: "CORS_ORIGINS"
                    allow_credentials: true
                    allow_methods: ["GET", "POST", "OPTIONS"]
                        allow_headers: ["authorization", "content-type", "x-csrf-token"]
                    expose_headers: ["x-total-count"]
                    max_age_seconds: 600
                }
                trusted_proxies: {
                    proxies: ["127.0.0.1", "::1"]
                    proxies_env: "TRUSTED_PROXIES"
                }
                rate_limits: {
                    login: { requests: 2, window_seconds: 60 }
                    register: { requests: 3, window_seconds: 120 }
                }
                headers: {
                    frame_options: Deny
                    content_type_options: true
                    referrer_policy: StrictOriginWhenCrossOrigin
                    hsts: {
                        max_age_seconds: 3600
                        include_subdomains: true
                    }
                }
                auth: {
                    issuer: "issuer"
                    audience: "audience"
                    access_token_ttl_seconds: 600
                    claims: {
                        tenant_id: I64
                        workspace_id: "claim_workspace_id"
                        staff: { column: "is_staff", type: Bool }
                        plan: String
                    }
                    session_cookie: {
                        secure: false
                        same_site: Lax
                        csrf_header_name: "x-session-csrf"
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let logging = parse_logging_document(document.logging).expect("logging ok");
        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");

        assert_eq!(logging.filter_env, "APP_LOG");
        assert_eq!(logging.default_filter, "debug,sqlx=warn");
        assert_eq!(logging.timestamp, LogTimestampPrecision::Millis);
        assert_eq!(security.requests.json_max_bytes, Some(128));
        assert_eq!(
            security.cors.origins,
            vec!["http://localhost:3000".to_owned()]
        );
        assert_eq!(security.cors.origins_env.as_deref(), Some("CORS_ORIGINS"));
        assert!(security.cors.allow_credentials);
        assert_eq!(
            security.cors.allow_methods,
            vec!["GET".to_owned(), "POST".to_owned(), "OPTIONS".to_owned()]
        );
        assert_eq!(
            security.cors.allow_headers,
            vec![
                "authorization".to_owned(),
                "content-type".to_owned(),
                "x-csrf-token".to_owned()
            ]
        );
        assert_eq!(
            security.cors.expose_headers,
            vec!["x-total-count".to_owned()]
        );
        assert_eq!(security.cors.max_age_seconds, Some(600));
        assert_eq!(
            security.trusted_proxies.proxies,
            vec!["127.0.0.1".to_owned(), "::1".to_owned()]
        );
        assert_eq!(
            security.trusted_proxies.proxies_env.as_deref(),
            Some("TRUSTED_PROXIES")
        );
        assert_eq!(
            security.rate_limits.login,
            Some(RateLimitRule {
                requests: 2,
                window_seconds: 60,
            })
        );
        assert_eq!(
            security.rate_limits.register,
            Some(RateLimitRule {
                requests: 3,
                window_seconds: 120,
            })
        );
        assert_eq!(security.auth.issuer.as_deref(), Some("issuer"));
        assert_eq!(security.auth.audience.as_deref(), Some("audience"));
        assert_eq!(security.auth.access_token_ttl_seconds, 600);
        assert_eq!(
            security.auth.claims.get("tenant_id"),
            Some(&AuthClaimMapping {
                column: "tenant_id".to_owned(),
                ty: AuthClaimType::I64,
            })
        );
        assert_eq!(
            security.auth.claims.get("workspace_id"),
            Some(&AuthClaimMapping {
                column: "claim_workspace_id".to_owned(),
                ty: AuthClaimType::I64,
            })
        );
        assert_eq!(
            security.auth.claims.get("staff"),
            Some(&AuthClaimMapping {
                column: "is_staff".to_owned(),
                ty: AuthClaimType::Bool,
            })
        );
        assert_eq!(
            security.auth.claims.get("plan"),
            Some(&AuthClaimMapping {
                column: "plan".to_owned(),
                ty: AuthClaimType::String,
            })
        );
        let session_cookie = security
            .auth
            .session_cookie
            .expect("session cookie settings should parse");
        assert!(!session_cookie.secure);
        assert_eq!(session_cookie.same_site, SessionCookieSameSite::Lax);
        assert_eq!(session_cookie.csrf_header_name, "x-session-csrf");
        assert_eq!(security.headers.frame_options, Some(FrameOptions::Deny));
        assert_eq!(
            security.headers.referrer_policy,
            Some(ReferrerPolicy::StrictOriginWhenCrossOrigin)
        );
        assert!(security.headers.content_type_options);
        assert_eq!(
            security.headers.hsts,
            Some(Hsts {
                max_age_seconds: 3600,
                include_subdomains: true,
            })
        );
    }

    #[test]
    fn parses_runtime_config_from_eon() {
        let document = parse_document(
            r#"
            runtime: {
                compression: {
                    enabled: true
                    static_precompressed: true
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let runtime = parse_runtime_document(document.runtime);
        assert!(runtime.compression.enabled);
        assert!(runtime.compression.static_precompressed);
    }

    #[test]
    fn parses_authorization_contract_from_eon() {
        let document = parse_document(
            r#"
            authorization: {
                scopes: {
                    Family: {
                        description: "Family scope"
                    }
                    Household: {
                        parent: "Family"
                    }
                }
                permissions: {
                    FamilyRead: {
                        actions: ["Read"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                }
                templates: {
                    FamilyMember: {
                        permissions: ["FamilyRead"]
                        scopes: ["Family"]
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        validate_authorization_contract(&authorization, &resources, Span::call_site())
            .expect("authorization contract should validate");

        assert!(!authorization.management_api.enabled);
        assert_eq!(
            authorization.management_api.mount,
            DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT
        );
        assert_eq!(authorization.scopes.len(), 2);
        assert_eq!(authorization.scopes[1].name, "Household");
        assert_eq!(authorization.scopes[1].parent.as_deref(), Some("Family"));
        assert_eq!(
            authorization.permissions[0].actions,
            vec![AuthorizationAction::Read]
        );
        assert_eq!(
            authorization.templates[0].permissions,
            vec!["FamilyRead".to_owned()]
        );
    }

    #[test]
    fn rejects_authorization_permission_for_unknown_resource() {
        let document = parse_document(
            r#"
            authorization: {
                permissions: {
                    FamilyRead: {
                        actions: ["Read"]
                        resources: ["MissingResource"]
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let error = validate_authorization_contract(&authorization, &resources, Span::call_site())
            .expect_err("unknown authorization resource should fail");
        assert!(error.to_string().contains("MissingResource"));
        assert!(
            error
                .to_string()
                .contains("authorization.permissions.FamilyRead")
        );
    }

    #[test]
    fn parses_authorization_management_api_from_eon() {
        let document = parse_document(
            r#"
            authorization: {
                management_api: {
                    mount: "/ops/authz/"
                }
                scopes: {
                    Family: {}
                }
                permissions: {
                    FamilyRead: {
                        actions: ["Read"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        assert!(authorization.management_api.enabled);
        assert_eq!(authorization.management_api.mount, "/ops/authz");
    }

    #[test]
    fn parses_authorization_hybrid_enforcement_from_eon() {
        let document = parse_document(
            r#"
            authorization: {
                scopes: {
                    Family: {}
                }
                permissions: {
                    FamilyRead: {
                        actions: ["Read"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                }
                hybrid_enforcement: {
                    resources: {
                        ScopedDoc: {
                            scope: "Family"
                            scope_field: "family_id"
                            actions: ["Read"]
                        }
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    roles: {
                        read: "member"
                    }
                    policies: {
                        read: "user_id=user.id"
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "family_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        validate_authorization_contract(&authorization, &resources, Span::call_site())
            .expect("authorization contract should validate");

        assert_eq!(authorization.hybrid_enforcement.resources.len(), 1);
        assert_eq!(
            authorization.hybrid_enforcement.resources[0].resource,
            "ScopedDoc"
        );
        assert_eq!(
            authorization.hybrid_enforcement.resources[0].scope,
            "Family"
        );
        assert_eq!(
            authorization.hybrid_enforcement.resources[0].scope_field,
            "family_id"
        );
        assert!(
            authorization.hybrid_enforcement.resources[0]
                .scope_sources
                .item
        );
        assert!(
            authorization.hybrid_enforcement.resources[0]
                .scope_sources
                .collection_filter
        );
        assert!(
            authorization.hybrid_enforcement.resources[0]
                .scope_sources
                .nested_parent
        );
        assert!(
            !authorization.hybrid_enforcement.resources[0]
                .scope_sources
                .create_payload
        );
        assert_eq!(
            authorization.hybrid_enforcement.resources[0].actions,
            vec![AuthorizationAction::Read]
        );
    }

    #[test]
    fn parses_explicit_authorization_hybrid_scope_sources_from_eon() {
        let document = parse_document(
            r#"
            authorization: {
                scopes: {
                    Family: {}
                }
                permissions: {
                    FamilyRead: {
                        actions: ["Read"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                    FamilyCreate: {
                        actions: ["Create"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                }
                hybrid_enforcement: {
                    resources: {
                        ScopedDoc: {
                            scope: "Family"
                            scope_field: "family_id"
                            scope_sources: {
                                item: false
                                collection_filter: true
                                nested_parent: false
                                create_payload: true
                            }
                            actions: ["Create", "Read"]
                        }
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    roles: {
                        read: "member"
                        create: "member"
                    }
                    policies: {
                        read: "user_id=user.id"
                        create: [
                            "user_id=user.id"
                            { field: "family_id", value: "claim.family_id" }
                        ]
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "family_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        validate_authorization_contract(&authorization, &resources, Span::call_site())
            .expect("authorization contract should validate");

        let resource = &authorization.hybrid_enforcement.resources[0];
        assert!(!resource.scope_sources.item);
        assert!(resource.scope_sources.collection_filter);
        assert!(!resource.scope_sources.nested_parent);
        assert!(resource.scope_sources.create_payload);
    }

    #[test]
    fn rejects_authorization_hybrid_enforcement_create_without_claim_controlled_scope_field() {
        let document = parse_document(
            r#"
            authorization: {
                scopes: {
                    Family: {}
                }
                permissions: {
                    FamilyCreate: {
                        actions: ["Create"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                }
                hybrid_enforcement: {
                    resources: {
                        ScopedDoc: {
                            scope: "Family"
                            scope_field: "family_id"
                            actions: ["Create"]
                        }
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    policies: {
                        create: "user_id=user.id"
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "family_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let error = validate_authorization_contract(&authorization, &resources, Span::call_site())
            .expect_err("hybrid create without claim-controlled scope field should fail");
        assert!(
            error
                .to_string()
                .contains("requires `family_id` to be assigned by a static create policy")
        );
    }

    #[test]
    fn accepts_authorization_hybrid_enforcement_create_for_claim_controlled_scope_field() {
        let document = parse_document(
            r#"
            authorization: {
                scopes: {
                    Family: {}
                }
                permissions: {
                    FamilyCreate: {
                        actions: ["Create"]
                        resources: ["ScopedDoc"]
                        scopes: ["Family"]
                    }
                }
                hybrid_enforcement: {
                    resources: {
                        ScopedDoc: {
                            scope: "Family"
                            scope_field: "family_id"
                            actions: ["Create"]
                        }
                    }
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    policies: {
                        create: [
                            "user_id=user.id"
                            { field: "family_id", value: "claim.family_id" }
                        ]
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                        { name: "family_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let authorization = parse_authorization_document(document.authorization)
            .expect("authorization should parse");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        validate_authorization_contract(&authorization, &resources, Span::call_site())
            .expect("hybrid create with claim-controlled scope field should validate");
    }

    #[test]
    fn rejects_authorization_management_api_mount_without_leading_slash() {
        let document = parse_document(
            r#"
            authorization: {
                management_api: {
                    mount: "authz/runtime"
                }
            }
            resources: [
                {
                    name: "ScopedDoc"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let error = parse_authorization_document(document.authorization)
            .expect_err("invalid management api mount should fail");
        assert!(error.to_string().contains("must start with `/`"));
    }

    #[test]
    fn rejects_undeclared_non_legacy_policy_claim_when_explicit_auth_claims_are_present() {
        let document = parse_document(
            r#"
            security: {
                auth: {
                    claims: {
                        tenant_id: I64
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { field: "tenant_id", equals: "claim.tenant" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "tenant_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let error = validate_policy_claim_sources(&resources, &security, Span::call_site())
            .expect_err("undeclared claim should fail");
        assert!(error.to_string().contains("undeclared `claim.tenant`"));
        assert!(error.to_string().contains("security.auth.claims.tenant"));
    }

    #[test]
    fn accepts_typed_explicit_claims_in_row_policies() {
        let document = parse_document(
            r#"
            security: {
                auth: {
                    claims: {
                        tenant_slug: String
                        staff: Bool
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { field: "tenant_id", equals: "claim.tenant_slug" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "tenant_id", type: String }
                    ]
                }
                {
                    name: "FlaggedPost"
                    policies: {
                        read: { field: "staff_only", equals: "claim.staff" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "staff_only", type: Bool }
                    ]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        validate_policy_claim_sources(&resources, &security, Span::call_site())
            .expect("typed mapped claims should validate");
    }

    #[test]
    fn rejects_mismatched_explicit_claim_type_in_row_policy() {
        let document = parse_document(
            r#"
            security: {
                auth: {
                    claims: {
                        tenant_slug: String
                    }
                }
            }
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { field: "tenant_id", equals: "claim.tenant_slug" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "tenant_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");
        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let error = validate_policy_claim_sources(&resources, &security, Span::call_site())
            .expect_err("mismatched mapped claim should fail");
        assert!(error.to_string().contains("tenant_slug"));
        assert!(error.to_string().contains("expects `I64`"));
    }

    #[test]
    fn runtime_config_defaults_to_disabled_compression() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let runtime = parse_runtime_document(document.runtime);
        assert!(!runtime.compression.enabled);
        assert!(!runtime.compression.static_precompressed);
    }

    #[test]
    fn parses_tls_config_from_eon() {
        let document = parse_document(
            r#"
            tls: {
                cert_path: "certs/local-cert.pem"
                key_path: "certs/local-key.pem"
                cert_path_env: "APP_TLS_CERT_PATH"
                key_path_env: "APP_TLS_KEY_PATH"
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let tls = parse_tls_document(document.tls).expect("tls config should parse");
        assert_eq!(tls.cert_path.as_deref(), Some("certs/local-cert.pem"));
        assert_eq!(tls.key_path.as_deref(), Some("certs/local-key.pem"));
        assert_eq!(tls.cert_path_env.as_deref(), Some("APP_TLS_CERT_PATH"));
        assert_eq!(tls.key_path_env.as_deref(), Some("APP_TLS_KEY_PATH"));
    }

    #[test]
    fn tls_block_defaults_to_dev_cert_paths_and_env_names() {
        let document = parse_document(
            r#"
            tls: {}
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let tls = parse_tls_document(document.tls).expect("tls config should parse");
        assert_eq!(tls.cert_path.as_deref(), Some(DEFAULT_TLS_CERT_PATH));
        assert_eq!(tls.key_path.as_deref(), Some(DEFAULT_TLS_KEY_PATH));
        assert_eq!(
            tls.cert_path_env.as_deref(),
            Some(DEFAULT_TLS_CERT_PATH_ENV)
        );
        assert_eq!(tls.key_path_env.as_deref(), Some(DEFAULT_TLS_KEY_PATH_ENV));
    }

    #[test]
    fn rejects_unknown_security_header_values() {
        let document = parse_document(
            r#"
            security: {
                headers: { frame_options: "maybe" }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let error = parse_security_document(document.security, Span::call_site())
            .expect_err("unknown frame_options should fail");
        assert!(error.to_string().contains("security.headers.frame_options"));
    }

    #[test]
    fn rejects_invalid_cors_method_values() {
        let document = parse_document(
            r#"
            security: {
                cors: { allow_methods: ["NOT A METHOD"] }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");
        let error = validate_security_config(&security, Span::call_site())
            .expect_err("invalid cors method should fail validation");
        assert!(error.to_string().contains("security.cors.allow_methods"));
    }

    #[test]
    fn rejects_invalid_trusted_proxy_values() {
        let document = parse_document(
            r#"
            security: {
                trusted_proxies: { proxies: ["not-an-ip"] }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");
        let error = validate_security_config(&security, Span::call_site())
            .expect_err("invalid trusted proxy should fail validation");
        assert!(
            error
                .to_string()
                .contains("security.trusted_proxies.proxies")
        );
    }

    #[test]
    fn rejects_zero_rate_limit_values() {
        let document = parse_document(
            r#"
            security: {
                rate_limits: {
                    login: { requests: 0, window_seconds: 60 }
                }
            }
            resources: [
                {
                    name: "Post"
                    fields: [{ name: "id", type: I64 }]
                }
            ]
            "#,
        );

        let security =
            parse_security_document(document.security, Span::call_site()).expect("security ok");
        let error = validate_security_config(&security, Span::call_site())
            .expect_err("zero rate limit should fail validation");
        assert!(
            error
                .to_string()
                .contains("security.rate_limits.login.requests")
        );
    }

    #[test]
    fn parses_relation_on_delete_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Comment"
                    fields: [
                        { name: "id", type: I64 }
                        {
                            name: "post_id"
                            type: I64
                            relation: {
                                references: "post.id"
                                nested_route: true
                                on_delete: Cascade
                            }
                        }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let relation = resources[0]
            .find_field("post_id")
            .and_then(|field| field.relation.as_ref())
            .expect("relation should exist");
        assert_eq!(
            relation.on_delete,
            Some(super::super::model::ReferentialAction::Cascade)
        );
    }

    #[test]
    fn parses_field_validation_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                        {
                            name: "title"
                            type: String
                            validate: {
                                min_length: 3
                                max_length: 32
                            }
                        }
                        {
                            name: "score"
                            type: I64
                            validate: {
                                minimum: 1
                                maximum: 10
                            }
                        }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        let title = resources[0]
            .find_field("title")
            .expect("title should exist");
        assert_eq!(title.validation.min_length, Some(3));
        assert_eq!(title.validation.max_length, Some(32));

        let score = resources[0]
            .find_field("score")
            .expect("score should exist");
        assert_eq!(
            score.validation.minimum,
            Some(super::super::model::NumericBound::Integer(1))
        );
        assert_eq!(
            score.validation.maximum,
            Some(super::super::model::NumericBound::Integer(10))
        );
    }

    #[test]
    fn parses_list_config_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    list: {
                        default_limit: 25
                        max_limit: 100
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        assert_eq!(resources[0].list.default_limit, Some(25));
        assert_eq!(resources[0].list.max_limit, Some(100));
    }

    #[test]
    fn parses_resource_and_field_maps_from_eon() {
        let document = parse_document(
            r#"
            resources: {
                Post: {
                    list: {
                        default_limit: 25
                        max_limit: 100
                    }
                    fields: {
                        id: I64
                        title: String
                        subtitle: {
                            type: String
                            nullable: true
                        }
                        author_id: {
                            type: I64
                            relation: {
                                references: "user.id"
                                nested_route: true
                            }
                        }
                    }
                }
            }
            "#,
        );

        let resources =
            build_resources(document.db, document.resources).expect("resources should build");
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].struct_ident.to_string(), "Post");
        assert_eq!(resources[0].list.default_limit, Some(25));
        assert_eq!(resources[0].list.max_limit, Some(100));

        let subtitle = resources[0]
            .find_field("subtitle")
            .expect("subtitle should exist");
        assert!(super::super::model::is_optional_type(&subtitle.ty));

        let author_id = resources[0]
            .find_field("author_id")
            .expect("author_id should exist");
        let relation = author_id
            .relation
            .as_ref()
            .expect("author_id relation should exist");
        assert_eq!(relation.references_table, "user");
        assert_eq!(relation.references_field, "id");
        assert!(relation.nested_route);
    }

    #[test]
    fn rejects_mismatched_resource_name_in_map_entry() {
        let error = match eon::from_str::<ServiceDocument>(
            r#"
            resources: {
                Post: {
                    name: "Comment"
                    fields: {
                        id: I64
                    }
                }
            }
            "#,
        ) {
            Ok(_) => panic!("mismatched resource name should fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("resource map entry `Post` has mismatched `name` value `Comment`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_mismatched_field_name_in_map_entry() {
        let error = match eon::from_str::<ServiceDocument>(
            r#"
            resources: {
                Post: {
                    fields: {
                        title: {
                            name: "headline"
                            type: String
                        }
                    }
                }
            }
            "#,
        ) {
            Ok(_) => panic!("mismatched field name should fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("field map entry `title` has mismatched `name` value `headline`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_invalid_list_config_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    list: {
                        default_limit: 50
                        max_limit: 10
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("invalid list config should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("default_limit"));
        assert!(error.to_string().contains("max_limit"));
    }

    #[test]
    fn rejects_unknown_row_policy_kind_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { kind: Tenant, field: "user_id" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "user_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("invalid row policy kind should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("Owner"));
        assert!(error.to_string().contains("SetOwner"));
    }

    #[test]
    fn rejects_invalid_row_policy_source_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { field: "tenant_id", equals: "session.tenant_id" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "tenant_id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("invalid row policy source should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("user.id"));
        assert!(error.to_string().contains("claim.<name>"));
    }

    #[test]
    fn rejects_set_null_on_non_nullable_relation_field() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Comment"
                    fields: [
                        { name: "id", type: I64 }
                        {
                            name: "post_id"
                            type: I64
                            relation: {
                                references: "post.id"
                                on_delete: SetNull
                            }
                        }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("invalid relation should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("SetNull"));
        assert!(error.to_string().contains("not nullable"));
    }

    #[test]
    fn rejects_invalid_field_validation_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                        {
                            name: "published"
                            type: Bool
                            validate: {
                                minimum: 1
                            }
                        }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("invalid validation should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("published"));
        assert!(error.to_string().contains("does not support validation"));
    }

    #[test]
    fn rejects_missing_row_policy_field_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { kind: Owner, field: "user_id" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("missing row policy field should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("missing field `user_id`"));
    }

    #[test]
    fn rejects_unsupported_row_policy_field_type_from_eon() {
        let document = parse_document(
            r#"
            resources: [
                {
                    name: "Post"
                    policies: {
                        read: { kind: Owner, field: "created_at" }
                    }
                    fields: [
                        { name: "id", type: I64 }
                        { name: "created_at", type: DateTime }
                    ]
                }
            ]
            "#,
        );

        let error = match build_resources(document.db, document.resources) {
            Ok(_) => panic!("unsupported row policy field should fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("must use type `i64`, `String`, `bool`, or an `Option<...>`")
        );
    }

    #[test]
    fn parses_static_mounts_from_eon() {
        let root = temp_root("eon_static_mounts");
        fs::create_dir_all(root.join("public/assets")).expect("asset dir should exist");
        fs::write(root.join("public/index.html"), "<html>ok</html>").expect("index should exist");
        fs::write(root.join("public/assets/app.js"), "console.log('ok');")
            .expect("asset should exist");

        let document = parse_document(
            r#"
            static: {
                mounts: [
                    {
                        mount: "/assets"
                        dir: "public/assets"
                        mode: Directory
                        cache: Immutable
                    }
                    {
                        mount: "/"
                        dir: "public"
                        mode: Spa
                        cache: NoStore
                    }
                ]
            }
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                        { name: "title", type: String }
                    ]
                }
            ]
            "#,
        );

        let mounts =
            build_static_mounts(&root, document.static_config).expect("mounts should parse");
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].mount_path, "/assets");
        assert_eq!(mounts[0].source_dir, "public/assets");
        assert_eq!(mounts[0].cache, StaticCacheProfile::Immutable);
        assert_eq!(mounts[1].mode, StaticMode::Spa);
        assert_eq!(mounts[1].index_file.as_deref(), Some("index.html"));
        assert_eq!(mounts[1].fallback_file.as_deref(), Some("index.html"));
    }

    #[test]
    fn rejects_static_mounts_that_escape_service_root() {
        let root = temp_root("eon_static_escape");
        fs::create_dir_all(&root).expect("root should exist");
        let outside = root
            .parent()
            .expect("temp root should have a parent")
            .join("outside-static");
        fs::create_dir_all(&outside).expect("outside dir should exist");

        let document = parse_document(
            r#"
            static: {
                mounts: [
                    {
                        mount: "/"
                        dir: "../outside-static"
                        mode: Spa
                    }
                ]
            }
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let error = build_static_mounts(&root, document.static_config)
            .expect_err("escaping static mount should fail");
        assert!(
            error
                .to_string()
                .contains("cannot escape the service directory")
        );
    }

    #[test]
    fn rejects_static_mounts_that_conflict_with_reserved_routes() {
        let root = temp_root("eon_static_reserved");
        fs::create_dir_all(root.join("public")).expect("public dir should exist");

        let document = parse_document(
            r#"
            static: {
                mounts: [
                    {
                        mount: "/docs"
                        dir: "public"
                    }
                ]
            }
            resources: [
                {
                    name: "Post"
                    fields: [
                        { name: "id", type: I64 }
                    ]
                }
            ]
            "#,
        );

        let error = build_static_mounts(&root, document.static_config)
            .expect_err("reserved route conflict should fail");
        assert!(
            error
                .to_string()
                .contains("conflicts with a reserved route")
        );
    }
}
