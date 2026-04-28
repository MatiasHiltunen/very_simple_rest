//! Service-level configuration parsing: auth, database, security, TLS,
//! logging, build, runtime, authorization, and related document → model
//! type conversions.
//!
//! Called from `super::load_service_document` and the resource-building path.

use std::{collections::BTreeMap, path::Path};

use proc_macro2::Span;

use super::super::model::{
    BuildArtifactPathConfig, BuildArtifactsConfig, BuildCacheArtifactConfig,
    BuildCacheCleanupStrategy, BuildConfig, BuildLtoMode, ClientValueConfig, ClientsConfig,
    DbBackend, ListConfig, ReleaseBuildConfig,
    ResourceAccess, ResourceReadAccess, TsClientAutomationConfig, TsClientConfig,
};
use super::documents::{
    AuthClaimMapValueDocument, AuthClaimTypeDocument, AuthEmailDocument,
    AuthEmailProviderDocument, AuthJwtDocument, AuthJwtVerificationKeyDocument,
    AuthUiPageDocument, AuthorizationActionDocument, AuthorizationDocument,
    AuthorizationHybridEnforcementDocument, AuthorizationHybridScopeSourcesDocument,
    AuthorizationManagementApiDocument, BuildArtifactPathDocument, BuildDocument,
    BuildLtoDocument, BuildLtoModeDocument, ClientValueDocument, ClientsDocument,
    DatabaseBackupDocument, DatabaseDocument, DatabaseEngineDocument,
    DatabaseReplicationDocument, DatabaseResilienceDocument, ListConfigDocument,
    LoggingDocument, RateLimitRuleDocument, ResourceAccessDocument, RuntimeDocument,
    SecretRefDocument, SecurityAccessDocument, SecurityDocument, SessionCookieDocument,
    TlsDocument, TsClientAutomationDocument,
};
use crate::{
    auth::{
        AuthClaimMapping, AuthClaimType, AuthEmailProvider, AuthEmailSettings, AuthJwtAlgorithm,
        AuthJwtSettings, AuthJwtVerificationKey, AuthSettings, AuthUiPageSettings,
        SessionCookieSameSite, SessionCookieSettings,
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
    secret::SecretRef,
    security::{
        AccessSecurity, CorsSecurity, DefaultReadAccess, FrameOptions, HeaderSecurity, Hsts,
        RateLimitRule, RateLimitSecurity, ReferrerPolicy, RequestSecurity, SecurityConfig,
        TrustedProxySecurity,
    },
    tls::{
        DEFAULT_TLS_CERT_PATH, DEFAULT_TLS_CERT_PATH_ENV, DEFAULT_TLS_KEY_PATH,
        DEFAULT_TLS_KEY_PATH_ENV, TlsConfig,
    },
};
use super::storage_parsing::validate_relative_path;

pub(super) fn parse_list_config(document: ListConfigDocument) -> ListConfig {
    ListConfig {
        default_limit: document.default_limit,
        max_limit: document.max_limit,
    }
}

pub(super) fn parse_resource_access_document(document: ResourceAccessDocument) -> syn::Result<ResourceAccess> {
    let read = match document.read.as_deref() {
        None => ResourceReadAccess::Inferred,
        Some(value) => match value.trim().to_ascii_lowercase().as_str() {
            "public" => ResourceReadAccess::Public,
            "authenticated" => ResourceReadAccess::Authenticated,
            _ => {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!("unsupported `resources[].access.read` value `{value}`"),
                ));
            }
        },
    };

    Ok(ResourceAccess { read })
}

pub(super) fn parse_security_access_document(
    document: Option<SecurityAccessDocument>,
) -> syn::Result<AccessSecurity> {
    let Some(document) = document else {
        return Ok(AccessSecurity::default());
    };

    let default_read = match document.default_read.as_deref() {
        None => DefaultReadAccess::Inferred,
        Some(value) => match value.trim().to_ascii_lowercase().as_str() {
            "inferred" => DefaultReadAccess::Inferred,
            "authenticated" => DefaultReadAccess::Authenticated,
            _ => {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!("unsupported `security.access.default_read` value `{value}`"),
                ));
            }
        },
    };

    Ok(AccessSecurity { default_read })
}

pub(super) fn parse_security_document(document: SecurityDocument, span: Span) -> syn::Result<SecurityConfig> {
    let requests = document
        .requests
        .map(|requests| RequestSecurity {
            json_max_bytes: requests.json_max_bytes,
        })
        .unwrap_or_default();
    let access = parse_security_access_document(document.access)?;

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
            let explicit_jwt_secret = parse_secret_ref_with_legacy_env(
                auth.jwt_secret,
                None,
                "security.auth.jwt_secret",
            )?;
            let jwt = auth.jwt.map(parse_auth_jwt_document).transpose()?;
            if jwt.is_some() && explicit_jwt_secret.is_some() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "`security.auth.jwt` cannot be combined with `security.auth.jwt_secret`",
                ));
            }
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
                jwt: jwt.clone(),
                jwt_secret: if jwt.is_some() {
                    explicit_jwt_secret
                } else {
                    explicit_jwt_secret.or(defaults.jwt_secret)
                },
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
        access,
        headers,
        auth,
    })
}

pub(super) fn parse_logging_document(document: Option<LoggingDocument>) -> syn::Result<LoggingConfig> {
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

pub(super) fn parse_build_document(document: Option<BuildDocument>) -> syn::Result<BuildConfig> {
    let Some(document) = document else {
        return Ok(BuildConfig::default());
    };

    let release = document.release.unwrap_or_default();
    let artifacts = document.artifacts.unwrap_or_default();
    let cache = artifacts.cache.unwrap_or_default();
    let lto = match release.lto {
        None => None,
        Some(BuildLtoDocument::Bool(false)) => None,
        Some(BuildLtoDocument::Bool(true)) => Some(BuildLtoMode::Thin),
        Some(BuildLtoDocument::Mode(BuildLtoModeDocument::Thin)) => Some(BuildLtoMode::Thin),
        Some(BuildLtoDocument::Mode(BuildLtoModeDocument::Fat)) => Some(BuildLtoMode::Fat),
    };

    Ok(BuildConfig {
        target_cpu_native: document.target_cpu_native.unwrap_or(false),
        release: ReleaseBuildConfig {
            lto,
            codegen_units: release.codegen_units,
            strip_debug_symbols: release.strip_debug_symbols.unwrap_or(false),
        },
        artifacts: BuildArtifactsConfig {
            binary: parse_build_artifact_path_document(artifacts.binary),
            bundle: parse_build_artifact_path_document(artifacts.bundle),
            cache: BuildCacheArtifactConfig {
                root: cache.root,
                env: cache.env,
                cleanup: parse_build_cache_cleanup(cache.cleanup)?,
            },
        },
    })
}

pub(super) fn parse_build_artifact_path_document(
    document: Option<BuildArtifactPathDocument>,
) -> BuildArtifactPathConfig {
    let document = document.unwrap_or_default();
    BuildArtifactPathConfig {
        path: document.path,
        env: document.env,
    }
}

pub(super) fn parse_clients_document(document: Option<ClientsDocument>) -> ClientsConfig {
    let Some(document) = document else {
        return ClientsConfig::default();
    };

    let ts = document.ts.unwrap_or_default();

    ClientsConfig {
        ts: TsClientConfig {
            output_dir: parse_build_artifact_path_document(ts.output_dir),
            package_name: parse_client_value_document(ts.package_name),
            server_url: ts.server_url,
            emit_js: ts.emit_js.unwrap_or(false),
            include_builtin_auth: ts.include_builtin_auth.unwrap_or(true),
            exclude_tables: ts.exclude_tables.unwrap_or_default(),
            automation: parse_ts_client_automation_document(ts.automation),
        },
    }
}

pub(super) fn parse_client_value_document(document: Option<ClientValueDocument>) -> ClientValueConfig {
    match document {
        None => ClientValueConfig::default(),
        Some(ClientValueDocument::Value(value)) => ClientValueConfig {
            value: Some(value),
            env: None,
        },
        Some(ClientValueDocument::Config(document)) => ClientValueConfig {
            value: document.value,
            env: document.env,
        },
    }
}

pub(super) fn parse_ts_client_automation_document(
    document: Option<TsClientAutomationDocument>,
) -> TsClientAutomationConfig {
    let document = document.unwrap_or_default();
    TsClientAutomationConfig {
        on_build: document.on_build.unwrap_or(false),
        self_test: document.self_test.unwrap_or(false),
        self_test_report: parse_build_artifact_path_document(document.self_test_report),
    }
}

pub(super) fn parse_build_cache_cleanup(value: Option<String>) -> syn::Result<BuildCacheCleanupStrategy> {
    let Some(value) = value else {
        return Ok(BuildCacheCleanupStrategy::Reuse);
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "reuse" => Ok(BuildCacheCleanupStrategy::Reuse),
        "cleanbeforebuild" | "clean_before_build" | "clean-before-build" => {
            Ok(BuildCacheCleanupStrategy::CleanBeforeBuild)
        }
        "removeonsuccess" | "remove_on_success" | "remove-on-success" => {
            Ok(BuildCacheCleanupStrategy::RemoveOnSuccess)
        }
        other => Err(syn::Error::new(
            Span::call_site(),
            format!(
                "unsupported `build.artifacts.cache.cleanup` value `{other}`; expected `Reuse`, `CleanBeforeBuild`, or `RemoveOnSuccess`"
            ),
        )),
    }
}

pub(super) fn parse_runtime_document(document: Option<RuntimeDocument>) -> RuntimeConfig {
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

pub(super) fn parse_authorization_document(
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

pub(super) fn parse_authorization_hybrid_enforcement_document(
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

pub(super) fn parse_authorization_hybrid_scope_sources_document(
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

pub(super) fn parse_authorization_management_api_document(
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

pub(super) fn parse_authorization_action_document(value: AuthorizationActionDocument) -> AuthorizationAction {
    match value {
        AuthorizationActionDocument::Read => AuthorizationAction::Read,
        AuthorizationActionDocument::Create => AuthorizationAction::Create,
        AuthorizationActionDocument::Update => AuthorizationAction::Update,
        AuthorizationActionDocument::Delete => AuthorizationAction::Delete,
    }
}

pub(super) fn normalize_authorization_management_mount(value: &str) -> syn::Result<String> {
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

pub(super) fn parse_tls_document(document: Option<TlsDocument>) -> syn::Result<TlsConfig> {
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

pub(super) fn parse_log_timestamp_precision(value: &str) -> Option<LogTimestampPrecision> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none" | "off" => Some(LogTimestampPrecision::None),
        "seconds" | "second" | "secs" | "sec" => Some(LogTimestampPrecision::Seconds),
        "millis" | "milliseconds" | "millisecond" | "ms" => Some(LogTimestampPrecision::Millis),
        "micros" | "microseconds" | "microsecond" | "us" => Some(LogTimestampPrecision::Micros),
        "nanos" | "nanoseconds" | "nanosecond" | "ns" => Some(LogTimestampPrecision::Nanos),
        _ => None,
    }
}

pub(super) fn validate_tls_path(value: &str, label: &str) -> syn::Result<String> {
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

pub(super) fn parse_session_cookie_document(
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

pub(super) fn parse_auth_jwt_document(document: AuthJwtDocument) -> syn::Result<AuthJwtSettings> {
    Ok(AuthJwtSettings {
        algorithm: document
            .algorithm
            .as_deref()
            .map(parse_auth_jwt_algorithm)
            .transpose()?
            .unwrap_or_default(),
        active_kid: document.active_kid,
        signing_key: document.signing_key.map_or_else(
            || {
                Err(syn::Error::new(
                    Span::call_site(),
                    "`security.auth.jwt.signing_key` is required",
                ))
            },
            |secret| parse_secret_ref_document(secret, "security.auth.jwt.signing_key"),
        )?,
        verification_keys: document
            .verification_keys
            .into_iter()
            .map(parse_auth_jwt_verification_key_document)
            .collect::<syn::Result<Vec<_>>>()?,
    })
}

pub(super) fn parse_auth_jwt_verification_key_document(
    document: AuthJwtVerificationKeyDocument,
) -> syn::Result<AuthJwtVerificationKey> {
    if document.kid.trim().is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "`security.auth.jwt.verification_keys[].kid` cannot be empty",
        ));
    }

    Ok(AuthJwtVerificationKey {
        kid: document.kid,
        key: parse_secret_ref_document(document.key, "security.auth.jwt.verification_keys[].key")?,
    })
}

pub(super) fn parse_auth_jwt_algorithm(value: &str) -> syn::Result<AuthJwtAlgorithm> {
    match value.trim().to_ascii_lowercase().as_str() {
        "hs256" => Ok(AuthJwtAlgorithm::Hs256),
        "hs384" => Ok(AuthJwtAlgorithm::Hs384),
        "hs512" => Ok(AuthJwtAlgorithm::Hs512),
        "es256" => Ok(AuthJwtAlgorithm::Es256),
        "es384" => Ok(AuthJwtAlgorithm::Es384),
        "eddsa" | "ed_dsa" | "ed-dsa" => Ok(AuthJwtAlgorithm::EdDsa),
        other => Err(syn::Error::new(
            Span::call_site(),
            format!(
                "unsupported `security.auth.jwt.algorithm` value `{other}`; expected HS256, HS384, HS512, ES256, ES384, or EdDSA"
            ),
        )),
    }
}

pub(super) fn parse_auth_email_document(document: AuthEmailDocument) -> syn::Result<AuthEmailSettings> {
    Ok(AuthEmailSettings {
        from_email: document.from_email,
        from_name: document.from_name,
        reply_to: document.reply_to,
        public_base_url: document.public_base_url,
        provider: parse_auth_email_provider_document(document.provider)?,
    })
}

pub(super) fn parse_auth_email_provider_document(
    document: AuthEmailProviderDocument,
) -> syn::Result<AuthEmailProvider> {
    match document.kind.trim().to_ascii_lowercase().as_str() {
        "resend" => Ok(AuthEmailProvider::Resend {
            api_key: parse_required_secret_ref_with_legacy_env(
                document.api_key,
                document.api_key_env,
                "security.auth.email.provider.api_key",
                "security.auth.email.provider.api_key_env",
                "kind = Resend",
            )?,
            api_base_url: document.api_base_url,
        }),
        "smtp" => Ok(AuthEmailProvider::Smtp {
            connection_url: parse_required_secret_ref_with_legacy_env(
                document.connection_url,
                document.connection_url_env,
                "security.auth.email.provider.connection_url",
                "security.auth.email.provider.connection_url_env",
                "kind = Smtp",
            )?,
        }),
        other => Err(syn::Error::new(
            Span::call_site(),
            format!("unsupported `security.auth.email.provider.kind` value `{other}`"),
        )),
    }
}

pub(super) fn parse_secret_ref_with_legacy_env(
    document: Option<SecretRefDocument>,
    legacy_env: Option<String>,
    label: &str,
) -> syn::Result<Option<SecretRef>> {
    if document.is_some() && legacy_env.is_some() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("`{label}` cannot be combined with its legacy `*_env` form"),
        ));
    }

    if let Some(document) = document {
        return Ok(Some(parse_secret_ref_document(document, label)?));
    }

    match legacy_env {
        Some(value) => {
            if value.trim().is_empty() {
                Err(syn::Error::new(
                    Span::call_site(),
                    format!("legacy env binding for `{label}` cannot be empty"),
                ))
            } else {
                Ok(Some(SecretRef::env_or_file(value)))
            }
        }
        None => Ok(None),
    }
}

pub(super) fn parse_required_secret_ref_with_legacy_env(
    document: Option<SecretRefDocument>,
    legacy_env: Option<String>,
    label: &str,
    legacy_label: &str,
    kind_label: &str,
) -> syn::Result<SecretRef> {
    parse_secret_ref_with_legacy_env(document, legacy_env, label)?.ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            format!("`{label}` or `{legacy_label}` is required for `{kind_label}`"),
        )
    })
}

pub(super) fn parse_secret_ref_document(document: SecretRefDocument, label: &str) -> syn::Result<SecretRef> {
    let mut variants = Vec::new();
    if let Some(env) = document.env {
        variants.push(("env", env));
    }
    if let Some(env_or_file) = document.env_or_file {
        variants.push(("env_or_file", env_or_file));
    }
    if let Some(systemd_credential) = document.systemd_credential {
        variants.push(("systemd_credential", systemd_credential));
    }

    if variants.len() + usize::from(document.external.is_some()) != 1 {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "`{label}` must set exactly one of `env`, `env_or_file`, `systemd_credential`, or `external`"
            ),
        ));
    }

    if let Some((kind, value)) = variants.into_iter().next() {
        if value.trim().is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("`{label}.{kind}` cannot be empty"),
            ));
        }
        return Ok(match kind {
            "env" => SecretRef::env(value),
            "env_or_file" => SecretRef::env_or_file(value),
            "systemd_credential" => SecretRef::SystemdCredential { id: value },
            _ => unreachable!("validated secret ref kind"),
        });
    }

    let external = document.external.expect("validated external secret ref");
    if external.provider.trim().is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("`{label}.external.provider` cannot be empty"),
        ));
    }
    if external.locator.trim().is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("`{label}.external.locator` cannot be empty"),
        ));
    }
    Ok(SecretRef::External {
        provider: external.provider,
        locator: external.locator,
    })
}

pub(super) fn parse_auth_ui_page_document(
    document: AuthUiPageDocument,
    default_title: &str,
) -> syn::Result<AuthUiPageSettings> {
    Ok(AuthUiPageSettings {
        path: document.path,
        title: document.title.unwrap_or_else(|| default_title.to_owned()),
    })
}

pub(super) fn parse_auth_claims_document(
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

pub(super) fn parse_auth_claim_type_document(document: AuthClaimTypeDocument) -> AuthClaimType {
    match document {
        AuthClaimTypeDocument::String => AuthClaimType::String,
        AuthClaimTypeDocument::I64 => AuthClaimType::I64,
        AuthClaimTypeDocument::Bool => AuthClaimType::Bool,
    }
}

pub(super) fn parse_session_cookie_same_site(value: &str) -> Option<SessionCookieSameSite> {
    match value.trim().to_ascii_lowercase().as_str() {
        "strict" => Some(SessionCookieSameSite::Strict),
        "lax" => Some(SessionCookieSameSite::Lax),
        "none" => Some(SessionCookieSameSite::None),
        _ => None,
    }
}

pub(super) fn parse_database_document(
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
                encryption_key: Some(SecretRef::env_or_file(
                    DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV,
                )),
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

pub(super) fn parse_database_engine_document(
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
                encryption_key: parse_secret_ref_with_legacy_env(
                    document.encryption_key,
                    document.encryption_key_env,
                    "database.engine.encryption_key",
                )?,
            }))
        }
        other => Err(syn::Error::new(
            span,
            format!("unsupported `database.engine.kind` value `{other}`"),
        )),
    }
}

pub(super) fn parse_database_resilience_document(
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
            && replication.read_url.is_none()
        {
            return Err(syn::Error::new(
                span,
                "database.resilience.replication.read_url or `read_url_env` is required when `read_routing = Explicit`",
            ));
        }
        if replication.mode == DatabaseReplicationMode::None
            && (replication.read_url.is_some()
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

pub(super) fn parse_database_resilience_profile(
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

pub(super) fn parse_database_backup_document(
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
        encryption_key: parse_secret_ref_with_legacy_env(
            document.encryption_key,
            document.encryption_key_env,
            "database.resilience.backup.encryption_key",
        )?,
        retention,
    })
}

pub(super) fn default_database_backup_mode(
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

pub(super) fn parse_database_backup_mode(value: &str, span: Span) -> syn::Result<DatabaseBackupMode> {
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

pub(super) fn parse_database_backup_target(value: &str, span: Span) -> syn::Result<DatabaseBackupTarget> {
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

pub(super) fn parse_database_replication_document(
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
        "database.resilience.replication.max_lag",
        document.max_lag.as_deref(),
        span,
    )?;

    Ok(DatabaseReplicationConfig {
        mode,
        read_routing,
        read_url: parse_secret_ref_with_legacy_env(
            document.read_url,
            document.read_url_env,
            "database.resilience.replication.read_url",
        )?,
        max_lag: document.max_lag,
        replicas_expected: document.replicas_expected,
    })
}

pub(super) fn parse_database_replication_mode(
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

pub(super) fn parse_database_read_routing_mode(
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

pub(super) fn validate_non_empty_optional(path: &str, value: Option<&str>, span: Span) -> syn::Result<()> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        return Err(syn::Error::new(span, format!("{path} cannot be empty")));
    }
    Ok(())
}

pub(super) fn parse_rate_limit_rule_document(document: RateLimitRuleDocument) -> RateLimitRule {
    RateLimitRule {
        requests: document.requests,
        window_seconds: document.window_seconds,
    }
}

pub(super) fn parse_frame_options(value: &str) -> Option<FrameOptions> {
    match value.trim().to_ascii_lowercase().as_str() {
        "deny" => Some(FrameOptions::Deny),
        "same_origin" | "same-origin" | "sameorigin" => Some(FrameOptions::SameOrigin),
        _ => None,
    }
}

pub(super) fn parse_referrer_policy(value: &str) -> Option<ReferrerPolicy> {
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