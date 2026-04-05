use actix_web::dev::Payload;
use actix_web::{
    FromRequest, HttpRequest,
    cookie::{Cookie, SameSite, time::Duration as CookieDuration},
    http::Method,
};
use actix_web::{HttpResponse, Responder, web};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bcrypt::{hash, verify};
use chrono::{Duration, SecondsFormat, Utc};
use dotenv::dotenv;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
    EllipticCurveKeyType, Jwk, JwkSet, KeyAlgorithm, OctetKeyPairParameters, OctetKeyPairType,
    PublicKeyUse,
};
use jsonwebtoken::{
    Algorithm as JsonWebTokenAlgorithm, DecodingKey, EncodingKey, Header, Validation, decode,
    decode_header, encode,
};
use rand::distr::{Alphanumeric, SampleString};
use rand::rng;
use rpassword;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Column, FromRow, Row, any::AnyRow};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::{Ready, ready};
use std::io::{IsTerminal, Write, stdin, stdout};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use crate::{
    db::{DbPool, query, query_scalar},
    email::{AuthEmailMessage, send_auth_email},
    errors,
    secret::{SecretRef, load_secret},
    security::{RateLimitRule, SecurityConfig, request_client_ip},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default = "default_access_token_ttl_seconds")]
    pub access_token_ttl_seconds: i64,
    #[serde(default)]
    pub require_email_verification: bool,
    #[serde(default = "default_verification_token_ttl_seconds")]
    pub verification_token_ttl_seconds: i64,
    #[serde(default = "default_password_reset_token_ttl_seconds")]
    pub password_reset_token_ttl_seconds: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<AuthJwtSettings>,
    #[serde(
        default = "default_jwt_secret_ref",
        skip_serializing_if = "Option::is_none"
    )]
    pub jwt_secret: Option<SecretRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, AuthClaimMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_cookie: Option<SessionCookieSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<AuthEmailSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portal: Option<AuthUiPageSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_dashboard: Option<AuthUiPageSettings>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthClaimType {
    #[default]
    I64,
    String,
    Bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthClaimMapping {
    pub column: String,
    #[serde(default)]
    pub ty: AuthClaimType,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthEmailSettings {
    pub from_email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
    pub provider: AuthEmailProvider,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthEmailProvider {
    Resend {
        api_key: SecretRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_base_url: Option<String>,
    },
    Smtp {
        connection_url: SecretRef,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum AuthJwtAlgorithm {
    #[serde(rename = "HS256")]
    Hs256,
    #[serde(rename = "HS384")]
    Hs384,
    #[serde(rename = "HS512")]
    Hs512,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ES384")]
    Es384,
    #[default]
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl AuthJwtAlgorithm {
    pub fn is_symmetric(self) -> bool {
        matches!(self, Self::Hs256 | Self::Hs384 | Self::Hs512)
    }

    fn jsonwebtoken(self) -> JsonWebTokenAlgorithm {
        match self {
            Self::Hs256 => JsonWebTokenAlgorithm::HS256,
            Self::Hs384 => JsonWebTokenAlgorithm::HS384,
            Self::Hs512 => JsonWebTokenAlgorithm::HS512,
            Self::Es256 => JsonWebTokenAlgorithm::ES256,
            Self::Es384 => JsonWebTokenAlgorithm::ES384,
            Self::EdDsa => JsonWebTokenAlgorithm::EdDSA,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthJwtVerificationKey {
    pub kid: String,
    pub key: SecretRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthJwtSettings {
    #[serde(default)]
    pub algorithm: AuthJwtAlgorithm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_kid: Option<String>,
    pub signing_key: SecretRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_keys: Vec<AuthJwtVerificationKey>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthUiPageSettings {
    pub path: String,
    pub title: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCookieSameSite {
    Lax,
    None,
    #[default]
    Strict,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionCookieSettings {
    #[serde(default = "default_session_cookie_name")]
    pub name: String,
    #[serde(default = "default_session_csrf_cookie_name")]
    pub csrf_cookie_name: String,
    #[serde(default = "default_session_csrf_header_name")]
    pub csrf_header_name: String,
    #[serde(default = "default_session_cookie_path")]
    pub path: String,
    #[serde(default = "default_session_cookie_secure")]
    pub secure: bool,
    #[serde(default)]
    pub same_site: SessionCookieSameSite,
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            issuer: None,
            audience: None,
            access_token_ttl_seconds: default_access_token_ttl_seconds(),
            require_email_verification: false,
            verification_token_ttl_seconds: default_verification_token_ttl_seconds(),
            password_reset_token_ttl_seconds: default_password_reset_token_ttl_seconds(),
            jwt: None,
            jwt_secret: default_jwt_secret_ref(),
            claims: BTreeMap::new(),
            session_cookie: None,
            email: None,
            portal: None,
            admin_dashboard: None,
        }
    }
}

impl Default for SessionCookieSettings {
    fn default() -> Self {
        Self {
            name: default_session_cookie_name(),
            csrf_cookie_name: default_session_csrf_cookie_name(),
            csrf_header_name: default_session_csrf_header_name(),
            path: default_session_cookie_path(),
            secure: default_session_cookie_secure(),
            same_site: SessionCookieSameSite::default(),
        }
    }
}

const fn default_access_token_ttl_seconds() -> i64 {
    24 * 60 * 60
}

const fn default_verification_token_ttl_seconds() -> i64 {
    24 * 60 * 60
}

const fn default_password_reset_token_ttl_seconds() -> i64 {
    60 * 60
}

fn default_jwt_secret_ref() -> Option<SecretRef> {
    Some(SecretRef::env_or_file("JWT_SECRET"))
}

pub fn auth_jwt_signing_secret_ref(settings: &AuthSettings) -> Option<&SecretRef> {
    settings
        .jwt
        .as_ref()
        .map(|jwt| &jwt.signing_key)
        .or(settings.jwt_secret.as_ref())
}

fn default_session_cookie_name() -> String {
    "vsr_session".to_owned()
}

fn default_session_csrf_cookie_name() -> String {
    "vsr_csrf".to_owned()
}

fn default_session_csrf_header_name() -> String {
    "x-csrf-token".to_owned()
}

fn default_session_cookie_path() -> String {
    "/".to_owned()
}

const fn default_session_cookie_secure() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthDbBackend {
    Sqlite,
    Postgres,
    Mysql,
}

impl AuthDbBackend {
    pub fn from_database_url(database_url: &str) -> Option<Self> {
        if database_url.starts_with("postgres:") || database_url.starts_with("postgresql:") {
            Some(Self::Postgres)
        } else if database_url.starts_with("mysql:") || database_url.starts_with("mariadb:") {
            Some(Self::Mysql)
        } else if database_url.starts_with("sqlite:")
            || database_url.starts_with("turso:")
            || database_url.starts_with("turso-local:")
        {
            Some(Self::Sqlite)
        } else {
            None
        }
    }

    fn id_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite => "id INTEGER PRIMARY KEY AUTOINCREMENT",
            Self::Postgres => "id BIGSERIAL PRIMARY KEY",
            Self::Mysql => "id BIGINT AUTO_INCREMENT PRIMARY KEY",
        }
    }

    fn email_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite | Self::Postgres => "email TEXT NOT NULL UNIQUE",
            Self::Mysql => "email VARCHAR(255) NOT NULL UNIQUE",
        }
    }

    fn password_hash_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite | Self::Postgres => "password_hash TEXT NOT NULL",
            Self::Mysql => "password_hash VARCHAR(255) NOT NULL",
        }
    }

    fn role_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite | Self::Postgres => "role TEXT NOT NULL",
            Self::Mysql => "role VARCHAR(64) NOT NULL",
        }
    }

    fn auth_claim_column_sql(self, column_name: &str, ty: AuthClaimType) -> String {
        let quoted = self.quote_ident(column_name);
        let sql = match ty {
            AuthClaimType::I64 => match self {
                Self::Sqlite => "INTEGER".to_owned(),
                Self::Postgres | Self::Mysql => "BIGINT".to_owned(),
            },
            AuthClaimType::String => match self {
                Self::Sqlite | Self::Postgres => "TEXT".to_owned(),
                Self::Mysql => "VARCHAR(255)".to_owned(),
            },
            AuthClaimType::Bool => match self {
                Self::Sqlite | Self::Mysql => "INTEGER NOT NULL DEFAULT 0".to_owned(),
                Self::Postgres => "BOOLEAN NOT NULL DEFAULT FALSE".to_owned(),
            },
        };
        format!("{quoted} {sql}")
    }

    fn optional_datetime_column_sql(self, column_name: &str) -> String {
        match self {
            Self::Sqlite | Self::Postgres => format!("{column_name} TEXT"),
            Self::Mysql => format!("{column_name} VARCHAR(64)"),
        }
    }

    fn required_datetime_column_sql(self, column_name: &str) -> String {
        format!(
            "{} NOT NULL DEFAULT {}",
            self.optional_datetime_column_sql(column_name),
            self.current_timestamp_expression()
        )
    }

    fn token_hash_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite | Self::Postgres => "token_hash TEXT NOT NULL",
            Self::Mysql => "token_hash VARCHAR(64) NOT NULL",
        }
    }

    fn token_purpose_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite | Self::Postgres => "purpose TEXT NOT NULL",
            Self::Mysql => "purpose VARCHAR(64) NOT NULL",
        }
    }

    fn requested_email_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite | Self::Postgres => "requested_email TEXT",
            Self::Mysql => "requested_email VARCHAR(255)",
        }
    }

    fn foreign_key_id_column_sql(self, column_name: &str) -> &'static str {
        let _ = column_name;
        match self {
            Self::Sqlite => "user_id INTEGER NOT NULL",
            Self::Postgres | Self::Mysql => "user_id BIGINT NOT NULL",
        }
    }

    fn current_timestamp_expression(self) -> &'static str {
        match self {
            Self::Sqlite => "(STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now'))",
            Self::Postgres => {
                "(TO_CHAR(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US') || '+00:00')"
            }
            Self::Mysql => "(DATE_FORMAT(UTC_TIMESTAMP(6), '%Y-%m-%dT%H:%i:%s.%f+00:00'))",
        }
    }

    fn quote_ident(self, ident: &str) -> String {
        match self {
            Self::Sqlite | Self::Postgres => format!("\"{}\"", ident.replace('"', "\"\"")),
            Self::Mysql => format!("`{}`", ident.replace('`', "``")),
        }
    }
}

pub fn auth_user_table_ident(backend: AuthDbBackend) -> String {
    backend.quote_ident("user")
}

pub fn auth_migration_sql(backend: AuthDbBackend) -> String {
    let quoted_user = auth_user_table_ident(backend);
    format!(
        "-- Generated by very_simple_rest for built-in auth.\n\n\
         CREATE TABLE {quoted_user} (\n\
             {},\n\
             {},\n\
             {},\n\
             {}\n\
         );\n\n\
         CREATE INDEX idx_user_role ON {quoted_user} (role);\n",
        backend.id_column_sql(),
        backend.email_column_sql(),
        backend.password_hash_column_sql(),
        backend.role_column_sql(),
        quoted_user = quoted_user,
    )
}

pub fn auth_management_migration_sql(backend: AuthDbBackend) -> String {
    let email_verified_at = backend.optional_datetime_column_sql("email_verified_at");
    let created_at = backend.optional_datetime_column_sql("created_at");
    let updated_at = backend.optional_datetime_column_sql("updated_at");
    let token_created_at = backend.required_datetime_column_sql("created_at");
    let token_expires_at = backend.optional_datetime_column_sql("expires_at");
    let token_used_at = backend.optional_datetime_column_sql("used_at");
    let now = backend.current_timestamp_expression();
    let quoted_user = auth_user_table_ident(backend);

    format!(
        "-- Generated by very_simple_rest for built-in auth management.\n\n\
         ALTER TABLE {quoted_user} ADD COLUMN {email_verified_at};\n\
         ALTER TABLE {quoted_user} ADD COLUMN {created_at};\n\
         ALTER TABLE {quoted_user} ADD COLUMN {updated_at};\n\
         UPDATE {quoted_user} SET created_at = {now} WHERE created_at IS NULL;\n\
         UPDATE {quoted_user} SET updated_at = COALESCE(updated_at, created_at, {now}) WHERE updated_at IS NULL;\n\n\
         CREATE TABLE auth_user_token (\n\
             {id_column},\n\
             {user_id_column},\n\
             {purpose_column},\n\
             {token_hash_column},\n\
             {requested_email_column},\n\
             {expires_at_column},\n\
             {used_at_column},\n\
             {created_at_column},\n\
             CONSTRAINT {fk_name} FOREIGN KEY ({quoted_user_id}) REFERENCES {quoted_user} ({quoted_user_pk}) ON DELETE CASCADE\n\
         );\n\n\
         CREATE UNIQUE INDEX idx_auth_user_token_hash ON auth_user_token (token_hash);\n\
         CREATE INDEX idx_auth_user_token_user_purpose ON auth_user_token (user_id, purpose);\n",
        id_column = backend.id_column_sql(),
        user_id_column = backend.foreign_key_id_column_sql("user_id"),
        purpose_column = backend.token_purpose_column_sql(),
        token_hash_column = backend.token_hash_column_sql(),
        requested_email_column = backend.requested_email_column_sql(),
        expires_at_column = token_expires_at,
        used_at_column = token_used_at,
        created_at_column = token_created_at,
        now = now,
        quoted_user = quoted_user,
        fk_name = backend.quote_ident("fk_auth_user_token_user"),
        quoted_user_id = backend.quote_ident("user_id"),
        quoted_user_pk = backend.quote_ident("id"),
    )
}

pub fn auth_claim_migration_sql(backend: AuthDbBackend, settings: &AuthSettings) -> String {
    let mut seen_columns = HashSet::new();
    let statements = settings
        .claims
        .values()
        .filter_map(|mapping| {
            if is_builtin_auth_user_column(&mapping.column)
                || !seen_columns.insert(mapping.column.clone())
            {
                return None;
            }

            Some(format!(
                "ALTER TABLE {} ADD COLUMN {};",
                auth_user_table_ident(backend),
                backend.auth_claim_column_sql(&mapping.column, mapping.ty)
            ))
        })
        .collect::<Vec<_>>();

    if statements.is_empty() {
        String::new()
    } else {
        format!(
            "-- Generated by very_simple_rest for built-in auth claim columns.\n\n{}\n",
            statements.join("\n")
        )
    }
}

fn is_builtin_auth_user_column(column_name: &str) -> bool {
    matches!(
        column_name,
        "id" | "email"
            | "password_hash"
            | "role"
            | "email_verified_at"
            | "created_at"
            | "updated_at"
    )
}

fn load_jwt_key_material(secret: &SecretRef, label: &str) -> Result<Arc<[u8]>, String> {
    let _ = dotenv();

    load_secret(secret, label)
        .map(|value| Arc::<[u8]>::from(value.into_bytes()))
        .map_err(|error| error.to_string())
}

fn load_jwt_secret(secret: &SecretRef) -> Result<Arc<[u8]>, String> {
    load_jwt_key_material(secret, "JWT secret")
}

fn configured_legacy_jwt_secret(settings: &AuthSettings) -> Result<Arc<[u8]>, String> {
    let secret_ref = auth_jwt_signing_secret_ref(settings)
        .cloned()
        .unwrap_or_else(|| SecretRef::env_or_file("JWT_SECRET"));
    load_jwt_secret(&secret_ref)
}

fn load_jwt_encoding_key(
    algorithm: AuthJwtAlgorithm,
    secret: &SecretRef,
    label: &str,
) -> Result<Arc<EncodingKey>, String> {
    let material = load_jwt_key_material(secret, label)?;
    let key = match algorithm {
        AuthJwtAlgorithm::Hs256 | AuthJwtAlgorithm::Hs384 | AuthJwtAlgorithm::Hs512 => {
            Ok(EncodingKey::from_secret(material.as_ref()))
        }
        AuthJwtAlgorithm::Es256 | AuthJwtAlgorithm::Es384 => {
            EncodingKey::from_ec_pem(material.as_ref()).map_err(|error| {
                format!(
                    "{label} must be a valid EC private PEM for {}: {error}",
                    algorithm_name(algorithm)
                )
            })
        }
        AuthJwtAlgorithm::EdDsa => EncodingKey::from_ed_pem(material.as_ref()).map_err(|error| {
            format!("{label} must be a valid Ed25519 private PEM for EdDSA: {error}")
        }),
    }?;
    Ok(Arc::new(key))
}

fn load_jwt_decoding_key(
    algorithm: AuthJwtAlgorithm,
    secret: &SecretRef,
    label: &str,
) -> Result<Arc<DecodingKey>, String> {
    let material = load_jwt_key_material(secret, label)?;
    let key = match algorithm {
        AuthJwtAlgorithm::Hs256 | AuthJwtAlgorithm::Hs384 | AuthJwtAlgorithm::Hs512 => {
            Ok(DecodingKey::from_secret(material.as_ref()))
        }
        AuthJwtAlgorithm::Es256 | AuthJwtAlgorithm::Es384 => {
            DecodingKey::from_ec_pem(material.as_ref()).map_err(|error| {
                format!(
                    "{label} must be a valid EC public PEM for {}: {error}",
                    algorithm_name(algorithm)
                )
            })
        }
        AuthJwtAlgorithm::EdDsa => DecodingKey::from_ed_pem(material.as_ref()).map_err(|error| {
            format!("{label} must be a valid Ed25519 public PEM for EdDSA: {error}")
        }),
    }?;
    Ok(Arc::new(key))
}

fn configured_jwt_signer(settings: &AuthSettings) -> Result<(Header, Arc<EncodingKey>), String> {
    if let Some(jwt) = &settings.jwt {
        let mut header = Header::new(jwt.algorithm.jsonwebtoken());
        header.kid = jwt.active_kid.clone();
        let key = load_jwt_encoding_key(jwt.algorithm, &jwt.signing_key, "JWT signing key")?;
        Ok((header, key))
    } else {
        let secret = configured_legacy_jwt_secret(settings)?;
        Ok((
            Header::default(),
            Arc::new(EncodingKey::from_secret(secret.as_ref())),
        ))
    }
}

fn configured_jwt_decoding_key(
    token: &str,
    settings: &AuthSettings,
) -> Result<(Arc<DecodingKey>, Validation), String> {
    if let Some(jwt) = &settings.jwt {
        let header =
            decode_header(token).map_err(|error| format!("invalid JWT header: {error}"))?;
        if header.alg != jwt.algorithm.jsonwebtoken() {
            return Err(format!(
                "token header algorithm `{:?}` does not match configured `{}`",
                header.alg,
                algorithm_name(jwt.algorithm)
            ));
        }

        let decoding_key = if jwt.verification_keys.is_empty() {
            if let (Some(active_kid), Some(header_kid)) =
                (jwt.active_kid.as_deref(), header.kid.as_deref())
                && active_kid != header_kid
            {
                return Err(format!(
                    "token kid `{header_kid}` does not match configured active kid `{active_kid}`"
                ));
            }
            load_jwt_decoding_key(jwt.algorithm, &jwt.signing_key, "JWT signing key")?
        } else if let Some(header_kid) = header.kid.as_deref() {
            let key = jwt
                .verification_keys
                .iter()
                .find(|key| key.kid == header_kid)
                .ok_or_else(|| format!("unknown JWT key id `{header_kid}`"))?;
            load_jwt_decoding_key(jwt.algorithm, &key.key, "JWT verification key")?
        } else if jwt.verification_keys.len() == 1 {
            let key = &jwt.verification_keys[0];
            load_jwt_decoding_key(jwt.algorithm, &key.key, "JWT verification key")?
        } else {
            return Err("JWT token is missing a `kid` header".to_owned());
        };

        Ok((
            decoding_key,
            validation_for_settings(settings, jwt.algorithm),
        ))
    } else {
        let secret = configured_legacy_jwt_secret(settings)?;
        Ok((
            Arc::new(DecodingKey::from_secret(secret.as_ref())),
            validation_for_settings(settings, AuthJwtAlgorithm::Hs256),
        ))
    }
}

fn algorithm_name(algorithm: AuthJwtAlgorithm) -> &'static str {
    match algorithm {
        AuthJwtAlgorithm::Hs256 => "HS256",
        AuthJwtAlgorithm::Hs384 => "HS384",
        AuthJwtAlgorithm::Hs512 => "HS512",
        AuthJwtAlgorithm::Es256 => "ES256",
        AuthJwtAlgorithm::Es384 => "ES384",
        AuthJwtAlgorithm::EdDsa => "EdDSA",
    }
}

pub fn ensure_jwt_secret_configured() -> Result<(), String> {
    ensure_jwt_secret_configured_with_settings(&AuthSettings::default())
}

pub fn ensure_jwt_secret_configured_with_settings(settings: &AuthSettings) -> Result<(), String> {
    let _ = configured_jwt_signer(settings)?;
    if let Some(jwt) = &settings.jwt {
        for verification_key in &jwt.verification_keys {
            let _ = load_jwt_decoding_key(
                jwt.algorithm,
                &verification_key.key,
                "JWT verification key",
            )?;
        }
    }
    Ok(())
}

fn configured_public_jwks(settings: &AuthSettings) -> Result<Option<JwkSet>, String> {
    let Some(jwt) = &settings.jwt else {
        return Ok(None);
    };
    if jwt.algorithm.is_symmetric() || jwt.verification_keys.is_empty() {
        return Ok(None);
    }

    let mut keys = Vec::with_capacity(jwt.verification_keys.len());
    for verification_key in &jwt.verification_keys {
        keys.push(configured_public_jwk(jwt.algorithm, verification_key)?);
    }
    Ok(Some(JwkSet { keys }))
}

fn configured_public_jwk(
    algorithm: AuthJwtAlgorithm,
    verification_key: &AuthJwtVerificationKey,
) -> Result<Jwk, String> {
    let decoding_key =
        load_jwt_decoding_key(algorithm, &verification_key.key, "JWT verification key")?;
    let common = CommonParameters {
        public_key_use: Some(PublicKeyUse::Signature),
        key_algorithm: Some(jwk_key_algorithm(algorithm)),
        key_id: Some(verification_key.kid.clone()),
        ..Default::default()
    };

    let algorithm = match algorithm {
        AuthJwtAlgorithm::Es256 => {
            let (x, y) = extract_ec_public_coordinates(decoding_key.as_bytes(), 32, "ES256")?;
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P256,
                x,
                y,
            })
        }
        AuthJwtAlgorithm::Es384 => {
            let (x, y) = extract_ec_public_coordinates(decoding_key.as_bytes(), 48, "ES384")?;
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P384,
                x,
                y,
            })
        }
        AuthJwtAlgorithm::EdDsa => AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EllipticCurve::Ed25519,
            x: URL_SAFE_NO_PAD.encode(decoding_key.as_bytes()),
        }),
        AuthJwtAlgorithm::Hs256 | AuthJwtAlgorithm::Hs384 | AuthJwtAlgorithm::Hs512 => {
            return Err(format!(
                "public JWKS is not available for symmetric `{}` JWT configuration",
                algorithm_name(algorithm)
            ));
        }
    };

    Ok(Jwk { common, algorithm })
}

fn jwk_key_algorithm(algorithm: AuthJwtAlgorithm) -> KeyAlgorithm {
    match algorithm {
        AuthJwtAlgorithm::Hs256 => KeyAlgorithm::HS256,
        AuthJwtAlgorithm::Hs384 => KeyAlgorithm::HS384,
        AuthJwtAlgorithm::Hs512 => KeyAlgorithm::HS512,
        AuthJwtAlgorithm::Es256 => KeyAlgorithm::ES256,
        AuthJwtAlgorithm::Es384 => KeyAlgorithm::ES384,
        AuthJwtAlgorithm::EdDsa => KeyAlgorithm::EdDSA,
    }
}

fn extract_ec_public_coordinates(
    public_key: &[u8],
    coordinate_len: usize,
    label: &str,
) -> Result<(String, String), String> {
    let expected_len = 1 + coordinate_len * 2;
    if public_key.len() != expected_len || public_key.first().copied() != Some(0x04) {
        return Err(format!(
            "JWT verification key must be an uncompressed {label} public key"
        ));
    }
    let x = &public_key[1..1 + coordinate_len];
    let y = &public_key[1 + coordinate_len..];
    Ok((URL_SAFE_NO_PAD.encode(x), URL_SAFE_NO_PAD.encode(y)))
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i64,
    roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    exp: usize,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UserContext {
    pub id: i64,
    pub roles: Vec<String>,
    #[serde(flatten)]
    pub claims: BTreeMap<String, Value>,
}

impl UserContext {
    pub fn claim_i64(&self, claim: &str) -> Option<i64> {
        self.claims.get(claim).and_then(Value::as_i64)
    }

    pub fn claim_bool(&self, claim: &str) -> Option<bool> {
        self.claims.get(claim).and_then(Value::as_bool)
    }

    pub fn claim_str(&self, claim: &str) -> Option<&str> {
        self.claims.get(claim).and_then(Value::as_str)
    }

    pub fn claim_value(&self, claim: &str) -> Option<&Value> {
        self.claims.get(claim)
    }
}

impl FromRequest for UserContext {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        use actix_web::http::header;

        let settings = auth_settings_from_request(req);
        let bearer_token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_string());

        if let Some(token) = bearer_token {
            return ready(decode_user_context_token(&token, &settings));
        }

        if let Some(cookie_settings) = &settings.session_cookie
            && let Some(cookie) = req.cookie(&cookie_settings.name)
        {
            if request_needs_csrf(req.method())
                && let Err(response) = validate_cookie_csrf(req, cookie_settings)
            {
                return ready(Err(errors::into_actix_error(response)));
            }

            return ready(decode_user_context_token(cookie.value(), &settings));
        }

        ready(Err(errors::into_actix_error(errors::unauthorized(
            "missing_token",
            "Missing token",
        ))))
    }
}

fn decode_user_context_token(
    token: &str,
    settings: &AuthSettings,
) -> Result<UserContext, actix_web::Error> {
    let (decoding_key, validation) =
        configured_jwt_decoding_key(token, settings).map_err(|_| {
            errors::into_actix_error(errors::unauthorized("invalid_token", "Invalid token"))
        })?;
    let data = decode::<Claims>(token, decoding_key.as_ref(), &validation).map_err(|_| {
        errors::into_actix_error(errors::unauthorized("invalid_token", "Invalid token"))
    })?;
    let claims = data.claims;

    Ok(UserContext {
        id: claims.sub,
        roles: claims.roles,
        claims: claims.extra,
    })
}

fn request_needs_csrf(method: &Method) -> bool {
    !matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

fn validate_cookie_csrf(
    req: &HttpRequest,
    settings: &SessionCookieSettings,
) -> Result<(), HttpResponse> {
    let csrf_cookie = req
        .cookie(&settings.csrf_cookie_name)
        .ok_or_else(|| errors::forbidden("invalid_csrf", "Missing or invalid CSRF token"))?;
    let csrf_header = req
        .headers()
        .get(settings.csrf_header_name.as_str())
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| errors::forbidden("invalid_csrf", "Missing or invalid CSRF token"))?;

    if csrf_header == csrf_cookie.value() {
        Ok(())
    } else {
        Err(errors::forbidden(
            "invalid_csrf",
            "Missing or invalid CSRF token",
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Option<i64>,
    pub email: String,
    pub password_hash: String,
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterInput {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginInput {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyEmailInput {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationResendInput {
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordResetRequestInput {
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordResetConfirmInput {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordInput {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateManagedUserInput {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub send_verification_email: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateManagedUserInput {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub id: i64,
    pub email: String,
    pub role: String,
    pub roles: Vec<String>,
    pub email_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(flatten)]
    pub claims: BTreeMap<String, Value>,
}

struct AuthenticatedUser {
    id: i64,
    email: String,
    password_hash: String,
    role: String,
    email_verified_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    has_email_verified_at_column: bool,
    has_created_at_column: bool,
    has_updated_at_column: bool,
    claims: BTreeMap<String, Value>,
}

impl AuthenticatedUser {
    fn has_auth_management_schema(&self) -> bool {
        self.has_email_verified_at_column
            && self.has_created_at_column
            && self.has_updated_at_column
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthTokenPurpose {
    EmailVerification,
    PasswordReset,
}

impl AuthTokenPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::EmailVerification => "email_verification",
            Self::PasswordReset => "password_reset",
        }
    }

    fn subject(self) -> &'static str {
        match self {
            Self::EmailVerification => "Verify your email address",
            Self::PasswordReset => "Reset your password",
        }
    }
}

#[derive(Debug)]
struct StoredAuthToken {
    id: i64,
    user_id: i64,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthTokenQuery {
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdminListQuery {
    limit: Option<u32>,
    offset: Option<u32>,
    email: Option<String>,
}

#[derive(Default)]
struct AuthRateLimiter {
    entries: Mutex<HashMap<String, VecDeque<Instant>>>,
}

#[derive(Clone, Copy)]
enum AuthRateLimitScope {
    Login,
    Register,
}

impl AuthRateLimitScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Register => "register",
        }
    }
}

fn now_timestamp_string() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false)
}

fn service_unavailable(code: &'static str, message: impl Into<String>) -> HttpResponse {
    errors::error_response(
        actix_web::http::StatusCode::SERVICE_UNAVAILABLE,
        code,
        message,
    )
}

fn normalize_auth_email(raw: &str) -> Result<String, HttpResponse> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(errors::validation_error(
            "email",
            "Email address cannot be empty",
        ));
    }
    if normalized.contains(char::is_whitespace) {
        return Err(errors::validation_error(
            "email",
            "Email address cannot contain whitespace",
        ));
    }
    let mut parts = normalized.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if local.is_empty() || domain.is_empty() || parts.next().is_some() || !domain.contains('.') {
        return Err(errors::validation_error(
            "email",
            "Email address is not valid",
        ));
    }
    Ok(normalized)
}

fn validate_auth_password(password: &str) -> Result<(), HttpResponse> {
    let len = password.chars().count();
    if len < 8 {
        return Err(errors::validation_error(
            "password",
            "Password must be at least 8 characters long",
        ));
    }
    if password.len() > 72 {
        return Err(errors::validation_error(
            "password",
            "Password must be at most 72 bytes long",
        ));
    }
    Ok(())
}

fn normalize_auth_role(raw: Option<&str>, default_role: &str) -> Result<String, HttpResponse> {
    let role = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_role)
        .to_owned();
    if role.chars().any(char::is_whitespace) {
        return Err(errors::validation_error(
            "role",
            "Role cannot contain whitespace",
        ));
    }
    Ok(role)
}

fn hash_auth_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn is_missing_auth_management_schema(error: &sqlx::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("no such table: auth_user_token")
        || message.contains("relation \"auth_user_token\" does not exist")
        || message.contains("unknown table 'auth_user_token'")
        || message.contains("no such column: email_verified_at")
        || message.contains("column \"email_verified_at\" does not exist")
        || message.contains("unknown column 'email_verified_at'")
        || message.contains("no such column: created_at")
        || message.contains("column \"created_at\" does not exist")
        || message.contains("unknown column 'created_at'")
        || message.contains("no such column: updated_at")
        || message.contains("column \"updated_at\" does not exist")
        || message.contains("unknown column 'updated_at'")
}

fn missing_auth_management_schema_response() -> HttpResponse {
    errors::internal_error(
        "Built-in auth management schema is missing. Apply the built-in auth migration again to add email verification and password reset tables.",
    )
}

fn scope_prefix_from_request(req: &HttpRequest, current_route_path: Option<&str>) -> String {
    if let Some(route) = current_route_path
        && req.path().ends_with(route)
    {
        let prefix = req.path().trim_end_matches(route);
        return prefix.to_owned();
    }

    if let Some(index) = req.path().find("/auth/") {
        return req.path()[..index].to_owned();
    }

    String::new()
}

fn build_public_auth_url(
    req: Option<&HttpRequest>,
    settings: &AuthSettings,
    auth_path: &str,
    current_route_path: Option<&str>,
    query_pairs: &[(&str, &str)],
) -> Result<String, String> {
    let scope_prefix = req
        .map(|req| scope_prefix_from_request(req, current_route_path))
        .unwrap_or_default();
    let mut base_url = if let Some(public_base_url) = settings
        .email
        .as_ref()
        .and_then(|email| email.public_base_url.clone())
    {
        let mut url = url::Url::parse(&public_base_url)
            .map_err(|error| format!("invalid security.auth.email.public_base_url: {error}"))?;
        url.set_query(None);
        url.set_fragment(None);

        let base_path = url.path().trim_end_matches('/');
        let scope_prefix = scope_prefix.trim_end_matches('/');
        let scoped_path = if scope_prefix.is_empty() {
            base_path.to_owned()
        } else if base_path.is_empty() || base_path == "/" {
            scope_prefix.to_owned()
        } else if base_path.ends_with(scope_prefix) {
            base_path.to_owned()
        } else {
            format!("{base_path}{scope_prefix}")
        };
        if scoped_path.is_empty() {
            url.set_path("/");
        } else {
            url.set_path(&scoped_path);
        }
        url
    } else if let Some(req) = req {
        let info = req.connection_info();
        url::Url::parse(&format!(
            "{}://{}{}",
            info.scheme(),
            info.host(),
            scope_prefix.trim_end_matches('/')
        ))
        .map_err(|error| format!("failed to build auth base URL from request: {error}"))?
    } else {
        return Err(
            "security.auth.email.public_base_url is required when auth emails are sent outside an HTTP request context"
                .to_owned(),
        );
    };

    let base_path = base_url.path().trim_end_matches('/');
    let next_path = format!("{base_path}/{}", auth_path.trim_start_matches('/'));
    base_url.set_path(&next_path);

    if !query_pairs.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in query_pairs {
            serializer.append_pair(key, value);
        }
        base_url.set_query(Some(&serializer.finish()));
    } else {
        base_url.set_query(None);
    }

    Ok(base_url.to_string())
}

fn user_roles(role: &str) -> Vec<String> {
    vec![role.to_owned()]
}

fn user_is_admin(user: &UserContext) -> bool {
    user.roles.iter().any(|role| role == "admin")
}

fn optional_text_column(row: &AnyRow, column: &str) -> Result<Option<String>, sqlx::Error> {
    match row.try_get::<Option<String>, _>(column) {
        Ok(value) => Ok(value),
        Err(sqlx::Error::ColumnNotFound(_)) => Ok(None),
        Err(sqlx::Error::ColumnDecode { .. }) => Ok(None),
        Err(error) => Err(error),
    }
}

fn row_has_column(row: &AnyRow, column: &str) -> bool {
    row.columns()
        .iter()
        .any(|candidate| candidate.name().eq_ignore_ascii_case(column))
}

fn authenticated_user_from_row_with_settings(
    row: &AnyRow,
    settings: &AuthSettings,
) -> Result<AuthenticatedUser, sqlx::Error> {
    Ok(AuthenticatedUser {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        password_hash: row.try_get("password_hash")?,
        role: row.try_get("role")?,
        email_verified_at: optional_text_column(row, "email_verified_at")?,
        created_at: optional_text_column(row, "created_at")?,
        updated_at: optional_text_column(row, "updated_at")?,
        has_email_verified_at_column: row_has_column(row, "email_verified_at"),
        has_created_at_column: row_has_column(row, "created_at"),
        has_updated_at_column: row_has_column(row, "updated_at"),
        claims: collect_user_claims_with_settings(row, settings)?,
    })
}

fn account_info_from_user(user: AuthenticatedUser) -> AccountInfo {
    AccountInfo {
        id: user.id,
        email: user.email,
        role: user.role.clone(),
        roles: user_roles(&user.role),
        email_verified: user.email_verified_at.is_some(),
        email_verified_at: user.email_verified_at,
        created_at: user.created_at,
        updated_at: user.updated_at,
        claims: user.claims,
    }
}

pub async fn register(input: web::Json<RegisterInput>, db: web::Data<DbPool>) -> impl Responder {
    register_with_settings(None, input, db, AuthSettings::default()).await
}

async fn register_with_settings(
    request: Option<&HttpRequest>,
    input: web::Json<RegisterInput>,
    db: web::Data<DbPool>,
    settings: AuthSettings,
) -> HttpResponse {
    let backend = match detect_auth_backend(db.get_ref()).await {
        Ok(backend) => backend,
        Err(_) => return errors::internal_error("Database error"),
    };
    let email = match normalize_auth_email(&input.email) {
        Ok(email) => email,
        Err(response) => return response,
    };
    if let Err(response) = validate_auth_password(&input.password) {
        return response;
    }
    let password_hash = match hash(&input.password, 12) {
        Ok(h) => h,
        Err(_) => return errors::internal_error("Hashing error"),
    };

    let tx = match db.begin().await {
        Ok(tx) => tx,
        Err(_) => return errors::internal_error("Database error"),
    };
    let result = query(&format!(
        "INSERT INTO {} (email, password_hash, role) VALUES (?, ?, ?)",
        auth_user_table_ident(backend)
    ))
    .bind(&email)
    .bind(&password_hash)
    .bind("user")
    .execute(&tx)
    .await;

    match result {
        Ok(_) => {}
        Err(error) if is_unique_violation(&error) => {
            let _ = tx.rollback().await;
            return errors::conflict("duplicate_email", "A user with that email already exists");
        }
        Err(error) => {
            let _ = tx.rollback().await;
            if is_missing_auth_management_schema(&error) {
                return missing_auth_management_schema_response();
            }
            return errors::internal_error("Database error");
        }
    };

    let user = match load_authenticated_user_by_email_with_settings_for_backend(
        &tx, backend, &email, &settings,
    )
    .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            let _ = tx.rollback().await;
            return errors::internal_error("Failed to load registered account");
        }
        Err(error) => {
            let _ = tx.rollback().await;
            if is_missing_auth_management_schema(&error) {
                return missing_auth_management_schema_response();
            }
            return errors::internal_error("Database error");
        }
    };
    let now = now_timestamp_string();
    if let Err(error) = initialize_user_management_timestamps(&tx, backend, user.id, &now).await {
        if settings.email.is_some() || settings.require_email_verification {
            let _ = tx.rollback().await;
            if is_missing_auth_management_schema(&error) {
                return missing_auth_management_schema_response();
            }
            return errors::internal_error("Database error");
        }
    }

    if settings.email.is_some() {
        if let Err(response) =
            send_verification_email_for_user(&tx, request, &settings, &user, "/auth/register").await
        {
            let _ = tx.rollback().await;
            return response;
        }
    } else if let Err(error) = mark_user_email_verified(&tx, backend, user.id, &now).await
        && !is_missing_auth_management_schema(&error)
    {
        let _ = tx.rollback().await;
        return errors::internal_error("Database error");
    }

    if tx.commit().await.is_err() {
        return errors::internal_error("Database error");
    }

    HttpResponse::Created().finish()
}

pub async fn register_with_request(
    req: HttpRequest,
    input: web::Json<RegisterInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if let Some(response) = enforce_auth_rate_limit(&req, AuthRateLimitScope::Register) {
        return response;
    }
    let settings = auth_settings_from_request(&req);
    register_with_settings(Some(&req), input, db, settings).await
}

pub async fn login(input: web::Json<LoginInput>, db: web::Data<DbPool>) -> impl Responder {
    login_with_settings(input, db, AuthSettings::default()).await
}

async fn login_with_settings(
    input: web::Json<LoginInput>,
    db: web::Data<DbPool>,
    settings: AuthSettings,
) -> HttpResponse {
    let email = match normalize_auth_email(&input.email) {
        Ok(email) => email,
        Err(response) => return response,
    };
    let user = match load_authenticated_user_by_email_with_settings(db.get_ref(), &email, &settings)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return errors::unauthorized("invalid_credentials", "Invalid credentials"),
        Err(error) => {
            if is_missing_auth_management_schema(&error) {
                return missing_auth_management_schema_response();
            }
            return errors::internal_error("Database error");
        }
    };

    if verify(&input.password, &user.password_hash).unwrap_or(false) {
        if settings.require_email_verification && user.email_verified_at.is_none() {
            if !user.has_auth_management_schema() {
                return missing_auth_management_schema_response();
            }
            return errors::forbidden(
                "email_not_verified",
                "Email address must be verified before logging in",
            );
        }
        let claims = Claims {
            sub: user.id,
            roles: user_roles(&user.role),
            iss: settings.issuer.clone(),
            aud: settings.audience.clone(),
            exp: (Utc::now() + Duration::seconds(settings.access_token_ttl_seconds)).timestamp()
                as usize,
            extra: user.claims,
        };
        let (header, encoding_key) = match configured_jwt_signer(&settings) {
            Ok(signer) => signer,
            Err(message) => return errors::internal_error(message),
        };

        match encode(&header, &claims, encoding_key.as_ref()) {
            Ok(token) => {
                if let Some(cookie_settings) = &settings.session_cookie {
                    issue_cookie_login_response(
                        &token,
                        cookie_settings,
                        settings.access_token_ttl_seconds,
                    )
                } else {
                    HttpResponse::Ok().json(serde_json::json!({ "token": token }))
                }
            }
            Err(_) => errors::internal_error("Token generation failed"),
        }
    } else {
        errors::unauthorized("invalid_credentials", "Invalid credentials")
    }
}

pub async fn login_with_request(
    req: HttpRequest,
    input: web::Json<LoginInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if let Some(response) = enforce_auth_rate_limit(&req, AuthRateLimitScope::Login) {
        return response;
    }
    let settings = auth_settings_from_request(&req);
    login_with_settings(input, db, settings).await
}

fn issue_cookie_login_response(
    token: &str,
    settings: &SessionCookieSettings,
    ttl_seconds: i64,
) -> HttpResponse {
    let csrf_token = generate_ephemeral_secret(32);
    let same_site = same_site_from_settings(settings.same_site);
    let max_age = CookieDuration::seconds(ttl_seconds.max(1));

    let session_cookie = Cookie::build(settings.name.clone(), token.to_owned())
        .path(settings.path.clone())
        .http_only(true)
        .secure(settings.secure)
        .same_site(same_site)
        .max_age(max_age)
        .finish();
    let csrf_cookie = Cookie::build(settings.csrf_cookie_name.clone(), csrf_token.clone())
        .path(settings.path.clone())
        .http_only(false)
        .secure(settings.secure)
        .same_site(same_site)
        .max_age(max_age)
        .finish();

    HttpResponse::Ok()
        .cookie(session_cookie)
        .cookie(csrf_cookie)
        .json(serde_json::json!({
            "token": token,
            "csrf_token": csrf_token,
        }))
}

fn generate_ephemeral_secret(length: usize) -> String {
    let mut random = rng();
    Alphanumeric.sample_string(&mut random, length)
}

fn same_site_from_settings(value: SessionCookieSameSite) -> SameSite {
    match value {
        SessionCookieSameSite::Lax => SameSite::Lax,
        SessionCookieSameSite::None => SameSite::None,
        SessionCookieSameSite::Strict => SameSite::Strict,
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .map(sqlx::error::DatabaseError::is_unique_violation)
        .unwrap_or(false)
}

async fn load_authenticated_user_by_email_with_settings_for_backend<E>(
    db: &E,
    backend: AuthDbBackend,
    email: &str,
    settings: &AuthSettings,
) -> Result<Option<AuthenticatedUser>, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let row = query(&format!(
        "SELECT * FROM {} WHERE email = ?",
        auth_user_table_ident(backend)
    ))
    .bind(email)
    .fetch_optional(db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    authenticated_user_from_row_with_settings(&row, settings).map(Some)
}

async fn load_authenticated_user_by_email_with_settings(
    db: &DbPool,
    email: &str,
    settings: &AuthSettings,
) -> Result<Option<AuthenticatedUser>, sqlx::Error> {
    let backend = detect_auth_backend(db).await?;
    load_authenticated_user_by_email_with_settings_for_backend(db, backend, email, settings).await
}

fn collect_user_claims_with_settings(
    row: &AnyRow,
    settings: &AuthSettings,
) -> Result<BTreeMap<String, Value>, sqlx::Error> {
    let mut claims = BTreeMap::new();

    for (claim_name, mapping) in &settings.claims {
        if let Some(value) = optional_claim_column(row, &mapping.column, mapping.ty)? {
            claims.insert(claim_name.clone(), value);
        }
    }

    for column in row.columns() {
        let column_name = column.name();
        let Some(claim_name) = explicit_claim_name(column_name) else {
            continue;
        };
        if let Some(value) = optional_i64_claim_column(row, column_name)? {
            claims.insert(claim_name, Value::from(value));
        }
    }

    for column in row.columns() {
        let column_name = column.name();
        let Some(claim_name) = implicit_claim_name(column_name) else {
            continue;
        };
        if claims.contains_key(&claim_name) {
            continue;
        }
        if let Some(value) = optional_i64_claim_column(row, column_name)? {
            claims.insert(claim_name, Value::from(value));
        }
    }

    Ok(claims)
}
fn explicit_claim_name(column: &str) -> Option<String> {
    column
        .strip_prefix("claim_")
        .filter(|claim| !claim.is_empty())
        .map(ToOwned::to_owned)
}

fn implicit_claim_name(column: &str) -> Option<String> {
    if matches!(column, "id" | "email" | "password_hash" | "role") {
        return None;
    }
    if column.starts_with("claim_") {
        return None;
    }

    column
        .ends_with("_id")
        .then(|| column.to_owned())
        .filter(|claim| claim != "id")
}

fn optional_i64_claim_column(row: &AnyRow, column: &str) -> Result<Option<i64>, sqlx::Error> {
    match row.try_get::<Option<i64>, _>(column) {
        Ok(value) => Ok(value),
        Err(sqlx::Error::ColumnNotFound(_)) => Ok(None),
        Err(sqlx::Error::ColumnDecode { .. }) => Ok(None),
        Err(error) => Err(error),
    }
}

fn optional_string_claim_column(row: &AnyRow, column: &str) -> Result<Option<String>, sqlx::Error> {
    match row.try_get::<Option<String>, _>(column) {
        Ok(value) => Ok(value),
        Err(sqlx::Error::ColumnNotFound(_)) => Ok(None),
        Err(sqlx::Error::ColumnDecode { .. }) => Ok(None),
        Err(error) => Err(error),
    }
}

fn optional_bool_claim_column(row: &AnyRow, column: &str) -> Result<Option<bool>, sqlx::Error> {
    match row.try_get::<Option<bool>, _>(column) {
        Ok(value) => Ok(value),
        Err(sqlx::Error::ColumnDecode { .. }) => match row.try_get::<Option<i64>, _>(column) {
            Ok(value) => Ok(value.map(|value| value != 0)),
            Err(sqlx::Error::ColumnNotFound(_)) => Ok(None),
            Err(sqlx::Error::ColumnDecode { .. }) => Ok(None),
            Err(error) => Err(error),
        },
        Err(sqlx::Error::ColumnNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn optional_claim_column(
    row: &AnyRow,
    column: &str,
    ty: AuthClaimType,
) -> Result<Option<Value>, sqlx::Error> {
    match ty {
        AuthClaimType::I64 => {
            optional_i64_claim_column(row, column).map(|value| value.map(Value::from))
        }
        AuthClaimType::String => {
            optional_string_claim_column(row, column).map(|value| value.map(Value::from))
        }
        AuthClaimType::Bool => {
            optional_bool_claim_column(row, column).map(|value| value.map(Value::from))
        }
    }
}

async fn load_authenticated_user_by_id_with_settings_for_backend<E>(
    db: &E,
    backend: AuthDbBackend,
    user_id: i64,
    settings: &AuthSettings,
) -> Result<Option<AuthenticatedUser>, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let row = query(&format!(
        "SELECT * FROM {} WHERE id = ?",
        auth_user_table_ident(backend)
    ))
    .bind(user_id)
    .fetch_optional(db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    authenticated_user_from_row_with_settings(&row, settings).map(Some)
}

async fn load_authenticated_user_by_id_with_settings(
    db: &DbPool,
    user_id: i64,
    settings: &AuthSettings,
) -> Result<Option<AuthenticatedUser>, sqlx::Error> {
    let backend = detect_auth_backend(db).await?;
    load_authenticated_user_by_id_with_settings_for_backend(db, backend, user_id, settings).await
}

async fn load_authenticated_user_by_id(
    db: &DbPool,
    user_id: i64,
) -> Result<Option<AuthenticatedUser>, sqlx::Error> {
    let backend = detect_auth_backend(db).await?;
    load_authenticated_user_by_id_with_settings_for_backend(
        db,
        backend,
        user_id,
        &AuthSettings::default(),
    )
    .await
}

async fn list_authenticated_users_with_settings(
    db: &DbPool,
    backend: AuthDbBackend,
    limit: u32,
    offset: u32,
    email_filter: Option<&str>,
    settings: &AuthSettings,
) -> Result<Vec<AccountInfo>, sqlx::Error> {
    let rows = if let Some(email_filter) = email_filter {
        query(&format!(
            "SELECT * FROM {} WHERE email LIKE ? ORDER BY id LIMIT ? OFFSET ?",
            auth_user_table_ident(backend)
        ))
        .bind(format!("%{email_filter}%"))
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(db)
        .await?
    } else {
        query(&format!(
            "SELECT * FROM {} ORDER BY id LIMIT ? OFFSET ?",
            auth_user_table_ident(backend)
        ))
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(db)
        .await?
    };

    rows.into_iter()
        .map(|row| {
            authenticated_user_from_row_with_settings(&row, settings).map(account_info_from_user)
        })
        .collect()
}

async fn create_auth_token<E>(
    db: &E,
    user_id: i64,
    purpose: AuthTokenPurpose,
    requested_email: Option<&str>,
    ttl_seconds: i64,
) -> Result<String, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let token = generate_ephemeral_secret(48);
    let token_hash = hash_auth_token(&token);
    let expires_at = (Utc::now() + Duration::seconds(ttl_seconds.max(1)))
        .to_rfc3339_opts(SecondsFormat::Micros, false);
    query("DELETE FROM auth_user_token WHERE user_id = ? AND purpose = ?")
        .bind(user_id)
        .bind(purpose.as_str())
        .execute(db)
        .await?;
    query(
        "INSERT INTO auth_user_token (user_id, purpose, token_hash, requested_email, expires_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(purpose.as_str())
    .bind(token_hash)
    .bind(requested_email)
    .bind(expires_at)
    .execute(db)
    .await?;
    Ok(token)
}

async fn load_pending_auth_token<E>(
    db: &E,
    raw_token: &str,
    purpose: AuthTokenPurpose,
) -> Result<Option<StoredAuthToken>, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let token_hash = hash_auth_token(raw_token);
    let row = query(
        "SELECT id, user_id, purpose, requested_email, expires_at FROM auth_user_token WHERE token_hash = ? AND purpose = ? AND used_at IS NULL",
    )
    .bind(token_hash)
    .bind(purpose.as_str())
    .fetch_optional(db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    Ok(Some(StoredAuthToken {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        expires_at: row.try_get("expires_at")?,
    }))
}

fn auth_token_is_expired(token: &StoredAuthToken) -> bool {
    chrono::DateTime::parse_from_rfc3339(&token.expires_at)
        .map(|expires_at| expires_at.with_timezone(&Utc) < Utc::now())
        .unwrap_or(true)
}

async fn mark_auth_token_used<E>(db: &E, token_id: i64, used_at: &str) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query("UPDATE auth_user_token SET used_at = ? WHERE id = ?")
        .bind(used_at)
        .bind(token_id)
        .execute(db)
        .await?;
    Ok(())
}

async fn delete_auth_tokens_for_user_purpose<E>(
    db: &E,
    user_id: i64,
    purpose: AuthTokenPurpose,
) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query("DELETE FROM auth_user_token WHERE user_id = ? AND purpose = ?")
        .bind(user_id)
        .bind(purpose.as_str())
        .execute(db)
        .await?;
    Ok(())
}

async fn delete_auth_token_by_id<E>(db: &E, token_id: i64) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query("DELETE FROM auth_user_token WHERE id = ?")
        .bind(token_id)
        .execute(db)
        .await?;
    Ok(())
}

async fn mark_user_email_verified<E>(
    db: &E,
    backend: AuthDbBackend,
    user_id: i64,
    verified_at: &str,
) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query(&format!(
        "UPDATE {} SET email_verified_at = ?, updated_at = ? WHERE id = ?",
        auth_user_table_ident(backend)
    ))
    .bind(verified_at)
    .bind(verified_at)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

async fn initialize_user_management_timestamps<E>(
    db: &E,
    backend: AuthDbBackend,
    user_id: i64,
    timestamp: &str,
) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query(&format!(
        "UPDATE {} SET created_at = COALESCE(created_at, ?), updated_at = COALESCE(updated_at, ?) WHERE id = ?",
        auth_user_table_ident(backend)
    ))
        .bind(timestamp)
        .bind(timestamp)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

async fn update_user_password<E>(
    db: &E,
    backend: AuthDbBackend,
    user_id: i64,
    password_hash: &str,
    updated_at: &str,
) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query(&format!(
        "UPDATE {} SET password_hash = ?, updated_at = ? WHERE id = ?",
        auth_user_table_ident(backend)
    ))
    .bind(password_hash)
    .bind(updated_at)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

async fn delete_user_row<E>(
    db: &E,
    backend: AuthDbBackend,
    user_id: i64,
) -> Result<bool, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let result = query(&format!(
        "DELETE FROM {} WHERE id = ?",
        auth_user_table_ident(backend)
    ))
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(result.rows_affected() != 0)
}

async fn update_managed_user_row(
    db: &DbPool,
    backend: AuthDbBackend,
    user_id: i64,
    input: &UpdateManagedUserInput,
    claim_updates: &[ManagedClaimUpdateValue],
    updated_at: &str,
) -> Result<bool, sqlx::Error> {
    let tx = db.begin().await?;
    let exists = query_scalar::<sqlx::Any, i64>(&format!(
        "SELECT COUNT(*) FROM {} WHERE id = ?",
        auth_user_table_ident(backend)
    ))
    .bind(user_id)
    .fetch_one(&tx)
    .await?;
    if exists == 0 {
        tx.rollback().await?;
        return Ok(false);
    }

    let role = input
        .role
        .as_ref()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let set_verified = input.email_verified == Some(true);
    let clear_verified = input.email_verified == Some(false);
    let should_update =
        role.is_some() || input.email_verified.is_some() || !claim_updates.is_empty();

    if role.is_some() || input.email_verified.is_some() {
        query(
            &format!(
                "UPDATE {} \
             SET role = CASE WHEN ? THEN ? ELSE role END, \
                 email_verified_at = CASE WHEN ? THEN ? WHEN ? THEN NULL ELSE email_verified_at END, \
                 updated_at = CASE WHEN ? THEN ? ELSE updated_at END \
             WHERE id = ?",
                auth_user_table_ident(backend)
            ),
        )
        .bind(role.is_some())
        .bind(role.unwrap_or_default())
        .bind(set_verified)
        .bind(updated_at)
        .bind(clear_verified)
        .bind(should_update)
        .bind(updated_at)
        .bind(user_id)
        .execute(&tx)
        .await?;
    }

    if !claim_updates.is_empty() {
        let backend = detect_auth_backend(db).await?;
        let user_columns = user_table_columns(db, backend).await?;
        let has_updated_at = user_columns
            .iter()
            .any(|column| column.column_name == "updated_at");

        for update in claim_updates {
            let sql = if has_updated_at {
                format!(
                    "UPDATE {} SET {} = {}, {} = {} WHERE {} = {}",
                    backend.quote_ident("user"),
                    backend.quote_ident(update.column_name()),
                    placeholder_for_backend(backend, 1),
                    backend.quote_ident("updated_at"),
                    placeholder_for_backend(backend, 2),
                    backend.quote_ident("id"),
                    placeholder_for_backend(backend, 3),
                )
            } else {
                format!(
                    "UPDATE {} SET {} = {} WHERE {} = {}",
                    backend.quote_ident("user"),
                    backend.quote_ident(update.column_name()),
                    placeholder_for_backend(backend, 1),
                    backend.quote_ident("id"),
                    placeholder_for_backend(backend, 2),
                )
            };
            let mut update_query = query(&sql);
            update_query = match update {
                ManagedClaimUpdateValue::I64 { value, .. } => update_query.bind(*value),
                ManagedClaimUpdateValue::String { value, .. } => update_query.bind(value),
                ManagedClaimUpdateValue::Bool { value, .. } => update_query.bind(*value),
            };
            if has_updated_at {
                update_query = update_query.bind(updated_at);
            }
            update_query.bind(user_id).execute(&tx).await?;
        }
    }

    tx.commit().await?;
    Ok(should_update)
}

fn configured_auth_email(settings: &AuthSettings) -> Result<&AuthEmailSettings, HttpResponse> {
    settings.email.as_ref().ok_or_else(|| {
        service_unavailable(
            "auth_email_unavailable",
            "Built-in auth email delivery is not configured",
        )
    })
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn verification_email_message(email: &str, url: &str) -> AuthEmailMessage {
    AuthEmailMessage {
        to_email: email.to_owned(),
        to_name: None,
        subject: AuthTokenPurpose::EmailVerification.subject().to_owned(),
        text_body: format!(
            "Verify your email address by opening this link:\n\n{url}\n\nIf you did not create this account, you can ignore this message."
        ),
        html_body: format!(
            "<!doctype html><html><body><h1>Verify your email</h1><p>Open the link below to verify your email address.</p><p><a href=\"{url}\">{label}</a></p><p>If you did not create this account, you can ignore this message.</p></body></html>",
            url = escape_html(url),
            label = escape_html(url),
        ),
    }
}

fn password_reset_email_message(email: &str, url: &str) -> AuthEmailMessage {
    AuthEmailMessage {
        to_email: email.to_owned(),
        to_name: None,
        subject: AuthTokenPurpose::PasswordReset.subject().to_owned(),
        text_body: format!(
            "Reset your password by opening this link:\n\n{url}\n\nIf you did not request a password reset, you can ignore this message."
        ),
        html_body: format!(
            "<!doctype html><html><body><h1>Reset your password</h1><p>Open the link below to choose a new password.</p><p><a href=\"{url}\">{label}</a></p><p>If you did not request a password reset, you can ignore this message.</p></body></html>",
            url = escape_html(url),
            label = escape_html(url),
        ),
    }
}

async fn send_verification_email_for_user<E>(
    db: &E,
    request: Option<&HttpRequest>,
    settings: &AuthSettings,
    user: &AuthenticatedUser,
    current_route_path: &str,
) -> Result<(), HttpResponse>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let email_settings = configured_auth_email(settings)?;
    let token = create_auth_token(
        db,
        user.id,
        AuthTokenPurpose::EmailVerification,
        Some(&user.email),
        settings.verification_token_ttl_seconds,
    )
    .await
    .map_err(|error| {
        if is_missing_auth_management_schema(&error) {
            missing_auth_management_schema_response()
        } else {
            errors::internal_error("Database error")
        }
    })?;
    let url = build_public_auth_url(
        request,
        settings,
        "/auth/verify-email",
        Some(current_route_path),
        &[("token", token.as_str())],
    )
    .map_err(errors::internal_error)?;
    let message = verification_email_message(&user.email, &url);
    send_auth_email(email_settings, &message)
        .await
        .map_err(|error| {
            errors::internal_error(format!("Failed to send verification email: {error}"))
        })
}

async fn send_password_reset_email_for_user<E>(
    db: &E,
    request: Option<&HttpRequest>,
    settings: &AuthSettings,
    user: &AuthenticatedUser,
) -> Result<(), HttpResponse>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let email_settings = configured_auth_email(settings)?;
    let token = create_auth_token(
        db,
        user.id,
        AuthTokenPurpose::PasswordReset,
        Some(&user.email),
        settings.password_reset_token_ttl_seconds,
    )
    .await
    .map_err(|error| {
        if is_missing_auth_management_schema(&error) {
            missing_auth_management_schema_response()
        } else {
            errors::internal_error("Database error")
        }
    })?;
    let url = build_public_auth_url(
        request,
        settings,
        "/auth/password-reset",
        None,
        &[("token", token.as_str())],
    )
    .map_err(errors::internal_error)?;
    let message = password_reset_email_message(&user.email, &url);
    send_auth_email(email_settings, &message)
        .await
        .map_err(|error| {
            errors::internal_error(format!("Failed to send password reset email: {error}"))
        })
}

enum TokenActionOutcome {
    Applied,
    Invalid,
    Expired,
}

async fn apply_email_verification_token(
    db: &DbPool,
    raw_token: &str,
) -> Result<TokenActionOutcome, sqlx::Error> {
    let backend = detect_auth_backend(db).await?;
    let tx = db.begin().await?;
    let Some(token) =
        load_pending_auth_token(&tx, raw_token, AuthTokenPurpose::EmailVerification).await?
    else {
        tx.rollback().await?;
        return Ok(TokenActionOutcome::Invalid);
    };
    if auth_token_is_expired(&token) {
        delete_auth_token_by_id(&tx, token.id).await?;
        tx.commit().await?;
        return Ok(TokenActionOutcome::Expired);
    }

    let now = now_timestamp_string();
    mark_user_email_verified(&tx, backend, token.user_id, &now).await?;
    mark_auth_token_used(&tx, token.id, &now).await?;
    delete_auth_tokens_for_user_purpose(&tx, token.user_id, AuthTokenPurpose::EmailVerification)
        .await?;
    tx.commit().await?;
    Ok(TokenActionOutcome::Applied)
}

async fn apply_password_reset_token(
    db: &DbPool,
    raw_token: &str,
    password_hash: &str,
) -> Result<TokenActionOutcome, sqlx::Error> {
    let backend = detect_auth_backend(db).await?;
    let tx = db.begin().await?;
    let Some(token) =
        load_pending_auth_token(&tx, raw_token, AuthTokenPurpose::PasswordReset).await?
    else {
        tx.rollback().await?;
        return Ok(TokenActionOutcome::Invalid);
    };
    if auth_token_is_expired(&token) {
        delete_auth_token_by_id(&tx, token.id).await?;
        tx.commit().await?;
        return Ok(TokenActionOutcome::Expired);
    }

    let now = now_timestamp_string();
    update_user_password(&tx, backend, token.user_id, password_hash, &now).await?;
    mark_auth_token_used(&tx, token.id, &now).await?;
    delete_auth_tokens_for_user_purpose(&tx, token.user_id, AuthTokenPurpose::PasswordReset)
        .await?;
    tx.commit().await?;
    Ok(TokenActionOutcome::Applied)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AdminClaimColumn {
    claim_name: Option<String>,
    column_name: String,
    env_var: String,
    required: bool,
    ty: AuthClaimType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AdminClaimValue {
    I64 { column_name: String, value: i64 },
    String { column_name: String, value: String },
    Bool { column_name: String, value: bool },
}

impl AdminClaimValue {
    fn column_name(&self) -> &str {
        match self {
            Self::I64 { column_name, .. }
            | Self::String { column_name, .. }
            | Self::Bool { column_name, .. } => column_name,
        }
    }

    fn render(&self) -> String {
        match self {
            Self::I64 { column_name, value } => format!("{column_name}={value}"),
            Self::String { column_name, value } => format!("{column_name}={value}"),
            Self::Bool { column_name, value } => format!("{column_name}={value}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ManagedClaimUpdateValue {
    I64 {
        claim_name: String,
        column_name: String,
        value: Option<i64>,
    },
    String {
        claim_name: String,
        column_name: String,
        value: Option<String>,
    },
    Bool {
        claim_name: String,
        column_name: String,
        value: Option<bool>,
    },
}

impl ManagedClaimUpdateValue {
    fn column_name(&self) -> &str {
        match self {
            Self::I64 { column_name, .. }
            | Self::String { column_name, .. }
            | Self::Bool { column_name, .. } => column_name,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UserColumnMetadata {
    column_name: String,
    data_type: String,
    required: bool,
}

async fn detect_auth_backend(pool: &DbPool) -> Result<AuthDbBackend, sqlx::Error> {
    match pool {
        DbPool::Sqlx { pool, .. } => {
            let connection = pool.acquire().await?;
            let backend_name = connection.backend_name().to_ascii_lowercase();
            if backend_name.contains("postgres") {
                Ok(AuthDbBackend::Postgres)
            } else if backend_name.contains("mysql") {
                Ok(AuthDbBackend::Mysql)
            } else if backend_name.contains("sqlite") {
                Ok(AuthDbBackend::Sqlite)
            } else {
                Err(sqlx::Error::Protocol(format!(
                    "unsupported built-in auth backend `{backend_name}`"
                )))
            }
        }
        #[cfg(feature = "turso-local")]
        DbPool::TursoLocal(_) => Ok(AuthDbBackend::Sqlite),
    }
}

async fn user_table_columns(
    pool: &DbPool,
    backend: AuthDbBackend,
) -> Result<Vec<UserColumnMetadata>, sqlx::Error> {
    let rows = match backend {
        AuthDbBackend::Sqlite => query("PRAGMA table_info('user')").fetch_all(pool).await?,
        AuthDbBackend::Postgres => {
            query(
                "SELECT column_name::text AS column_name, \
                        data_type::text AS data_type, \
                        is_nullable::text AS is_nullable, \
                        column_default::text AS column_default \
             FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'user' \
             ORDER BY ordinal_position",
            )
            .fetch_all(pool)
            .await?
        }
        AuthDbBackend::Mysql => {
            query(
                "SELECT CAST(column_name AS CHAR(255)) AS column_name, \
                        CAST(data_type AS CHAR(255)) AS data_type, \
                        CAST(is_nullable AS CHAR(3)) AS is_nullable, \
                        CAST(column_default AS CHAR(255)) AS column_default \
             FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = 'user' \
             ORDER BY ordinal_position",
            )
            .fetch_all(pool)
            .await?
        }
    };

    let mut columns = Vec::new();
    for row in rows {
        columns.push(user_column_from_row(&row, backend)?);
    }

    Ok(columns)
}

fn user_column_from_row(
    row: &AnyRow,
    backend: AuthDbBackend,
) -> Result<UserColumnMetadata, sqlx::Error> {
    let (column_name, data_type, required) = match backend {
        AuthDbBackend::Sqlite => {
            let column_name: String = row.try_get("name")?;
            let data_type: String = row
                .try_get::<Option<String>, _>("type")?
                .unwrap_or_default()
                .to_ascii_lowercase();
            let notnull = row.try_get::<i64, _>("notnull")? != 0;
            let default_value = row.try_get::<Option<String>, _>("dflt_value")?;
            (column_name, data_type, notnull && default_value.is_none())
        }
        AuthDbBackend::Postgres | AuthDbBackend::Mysql => {
            let column_name: String = row.try_get("column_name")?;
            let data_type: String = row.try_get::<String, _>("data_type")?.to_ascii_lowercase();
            let is_nullable = row.try_get::<String, _>("is_nullable")?;
            let default_value = row.try_get::<Option<String>, _>("column_default")?;
            (
                column_name,
                data_type,
                is_nullable.eq_ignore_ascii_case("NO") && default_value.is_none(),
            )
        }
    };

    Ok(UserColumnMetadata {
        column_name,
        data_type,
        required,
    })
}

fn legacy_admin_claim_column_from_metadata(
    metadata: UserColumnMetadata,
) -> Option<AdminClaimColumn> {
    if !is_admin_claim_column_name(&metadata.column_name)
        || !is_integer_claim_type(&metadata.data_type)
    {
        return None;
    }

    Some(AdminClaimColumn {
        claim_name: None,
        env_var: admin_claim_env_var(&metadata.column_name),
        column_name: metadata.column_name,
        required: metadata.required,
        ty: AuthClaimType::I64,
    })
}

fn configured_admin_claim_columns(
    user_columns: &[UserColumnMetadata],
    configured_claims: &BTreeMap<String, AuthClaimMapping>,
) -> Result<Vec<AdminClaimColumn>, String> {
    let columns_by_name = user_columns
        .iter()
        .map(|column| (column.column_name.as_str(), column))
        .collect::<HashMap<_, _>>();
    let mut columns = Vec::new();
    let mut seen_columns = HashSet::new();

    for (claim_name, mapping) in configured_claims {
        let Some(metadata) = columns_by_name.get(mapping.column.as_str()) else {
            return Err(format!(
                "Configured auth claim `security.auth.claims.{claim_name}` maps to missing `user.{}` column",
                mapping.column
            ));
        };

        if !claim_type_matches_column(mapping.ty, &metadata.data_type) {
            return Err(format!(
                "Configured auth claim `security.auth.claims.{claim_name}` expects `{}` values, but `user.{}` is declared as `{}`",
                admin_claim_type_label(mapping.ty),
                mapping.column,
                metadata.data_type
            ));
        }

        if !seen_columns.insert(mapping.column.clone()) {
            continue;
        }

        columns.push(AdminClaimColumn {
            claim_name: Some(claim_name.clone()),
            column_name: mapping.column.clone(),
            env_var: admin_claim_env_var(&mapping.column),
            required: metadata.required,
            ty: mapping.ty,
        });
    }

    Ok(columns)
}

fn is_admin_claim_column_name(column_name: &str) -> bool {
    if matches!(column_name, "id" | "email" | "password_hash" | "role") {
        return false;
    }
    if let Some(rest) = column_name.strip_prefix("claim_") {
        return !rest.is_empty();
    }

    column_name.ends_with("_id") && column_name != "id"
}

fn is_integer_claim_type(data_type: &str) -> bool {
    data_type.trim().to_ascii_lowercase().contains("int")
}

fn is_string_claim_type(data_type: &str) -> bool {
    let data_type = data_type.trim().to_ascii_lowercase();
    data_type.is_empty()
        || data_type.contains("char")
        || data_type.contains("text")
        || data_type.contains("clob")
        || data_type.contains("string")
}

fn is_bool_claim_type(data_type: &str) -> bool {
    let data_type = data_type.trim().to_ascii_lowercase();
    data_type.is_empty()
        || data_type.contains("bool")
        || data_type.contains("tinyint")
        || data_type.contains("int")
}

fn claim_type_matches_column(ty: AuthClaimType, data_type: &str) -> bool {
    match ty {
        AuthClaimType::I64 => is_integer_claim_type(data_type),
        AuthClaimType::String => is_string_claim_type(data_type),
        AuthClaimType::Bool => is_bool_claim_type(data_type),
    }
}

fn admin_claim_env_var(column_name: &str) -> String {
    let mut env_var = String::from("ADMIN_");
    for ch in column_name.chars() {
        if ch.is_ascii_alphanumeric() {
            env_var.push(ch.to_ascii_uppercase());
        } else {
            env_var.push('_');
        }
    }
    env_var
}

fn resolve_admin_claim_values(
    claim_columns: &[AdminClaimColumn],
    interactive: bool,
) -> Result<Vec<AdminClaimValue>, String> {
    let mut values = Vec::new();

    for column in claim_columns {
        if let Some(value) = claim_value_from_env(column)? {
            values.push(value);
            continue;
        }

        if interactive {
            if let Some(value) = prompt_admin_claim_value(column)? {
                values.push(value);
            }
            continue;
        }

        if column.required {
            return Err(format!(
                "Missing required admin claim column `{}`. Set {} before starting the server.",
                column.column_name, column.env_var
            ));
        }
    }

    Ok(values)
}

fn claim_value_from_env(column: &AdminClaimColumn) -> Result<Option<AdminClaimValue>, String> {
    match std::env::var(&column.env_var) {
        Ok(raw) if raw.trim().is_empty() => Ok(None),
        Ok(raw) => parse_admin_claim_value(column, raw.trim()),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(format!(
            "Failed to read environment variable {}: {}",
            column.env_var, error
        )),
    }
}

fn prompt_admin_claim_value(column: &AdminClaimColumn) -> Result<Option<AdminClaimValue>, String> {
    let prompt = if column.required {
        format!(
            "{} (required {} admin claim column): ",
            admin_claim_display_name(column),
            admin_claim_type_label(column.ty).to_ascii_lowercase()
        )
    } else {
        format!(
            "{} (optional {} admin claim column, press Enter to skip): ",
            admin_claim_display_name(column),
            admin_claim_type_label(column.ty).to_ascii_lowercase()
        )
    };

    print!("{prompt}");
    stdout()
        .flush()
        .map_err(|error| format!("Failed to flush stdout: {error}"))?;

    let mut value = String::new();
    stdin()
        .read_line(&mut value)
        .map_err(|error| format!("Failed to read {}: {error}", column.column_name))?;

    let value = value.trim();
    if value.is_empty() {
        if column.required {
            return Err(format!("{} is required", column.column_name));
        }
        return Ok(None);
    }

    parse_admin_claim_value(column, value)
}

fn admin_claim_display_name(column: &AdminClaimColumn) -> String {
    match column.claim_name.as_deref() {
        Some(claim_name) if claim_name != column.column_name => {
            format!("{claim_name} (column {})", column.column_name)
        }
        Some(claim_name) => claim_name.to_owned(),
        None => column.column_name.clone(),
    }
}

fn admin_claim_type_label(ty: AuthClaimType) -> &'static str {
    match ty {
        AuthClaimType::I64 => "I64",
        AuthClaimType::String => "String",
        AuthClaimType::Bool => "Bool",
    }
}

fn parse_admin_claim_value(
    column: &AdminClaimColumn,
    raw: &str,
) -> Result<Option<AdminClaimValue>, String> {
    let value = match column.ty {
        AuthClaimType::I64 => {
            let value = raw.parse::<i64>().map_err(|_| {
                format!(
                    "Environment variable {} must be a valid integer",
                    column.env_var
                )
            })?;
            AdminClaimValue::I64 {
                column_name: column.column_name.clone(),
                value,
            }
        }
        AuthClaimType::String => AdminClaimValue::String {
            column_name: column.column_name.clone(),
            value: raw.to_owned(),
        },
        AuthClaimType::Bool => {
            let value = parse_bool_claim(raw).ok_or_else(|| {
                format!(
                    "Environment variable {} must be true/false, yes/no, on/off, or 1/0",
                    column.env_var
                )
            })?;
            AdminClaimValue::Bool {
                column_name: column.column_name.clone(),
                value,
            }
        }
    };

    Ok(Some(value))
}

fn parse_bool_claim(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn resolve_managed_claim_updates(
    user_columns: &[UserColumnMetadata],
    configured_claims: &BTreeMap<String, AuthClaimMapping>,
    provided_claims: &BTreeMap<String, Value>,
) -> Result<Vec<ManagedClaimUpdateValue>, HttpResponse> {
    if provided_claims.is_empty() {
        return Ok(Vec::new());
    }
    if configured_claims.is_empty() {
        return Err(errors::bad_request(
            "claims_not_configured",
            "This service does not declare `security.auth.claims`, so managed claim updates are unavailable",
        ));
    }

    let configured_columns = configured_admin_claim_columns(user_columns, configured_claims)
        .map_err(|error| errors::validation_error("claims", error))?;
    let columns_by_claim = configured_columns
        .into_iter()
        .filter_map(|column| column.claim_name.clone().map(|name| (name, column)))
        .collect::<HashMap<_, _>>();

    let mut updates = Vec::new();
    for (claim_name, raw_value) in provided_claims {
        let field = format!("claims.{claim_name}");
        let Some(column) = columns_by_claim.get(claim_name.as_str()) else {
            return Err(errors::validation_error(
                field,
                format!(
                    "Unknown managed auth claim `{claim_name}`. Declare it under `security.auth.claims` first"
                ),
            ));
        };

        let update = match (column.ty, raw_value) {
            (AuthClaimType::I64, Value::Null) => {
                if column.required {
                    return Err(errors::validation_error(
                        field,
                        format!("Managed auth claim `{claim_name}` cannot be null"),
                    ));
                }
                ManagedClaimUpdateValue::I64 {
                    claim_name: claim_name.clone(),
                    column_name: column.column_name.clone(),
                    value: None,
                }
            }
            (AuthClaimType::I64, Value::Number(number)) => {
                let Some(value) = number.as_i64() else {
                    return Err(errors::validation_error(
                        field,
                        format!("Managed auth claim `{claim_name}` must be an integer"),
                    ));
                };
                ManagedClaimUpdateValue::I64 {
                    claim_name: claim_name.clone(),
                    column_name: column.column_name.clone(),
                    value: Some(value),
                }
            }
            (AuthClaimType::String, Value::Null) => {
                if column.required {
                    return Err(errors::validation_error(
                        field,
                        format!("Managed auth claim `{claim_name}` cannot be null"),
                    ));
                }
                ManagedClaimUpdateValue::String {
                    claim_name: claim_name.clone(),
                    column_name: column.column_name.clone(),
                    value: None,
                }
            }
            (AuthClaimType::String, Value::String(value)) => ManagedClaimUpdateValue::String {
                claim_name: claim_name.clone(),
                column_name: column.column_name.clone(),
                value: Some(value.clone()),
            },
            (AuthClaimType::Bool, Value::Null) => {
                if column.required {
                    return Err(errors::validation_error(
                        field,
                        format!("Managed auth claim `{claim_name}` cannot be null"),
                    ));
                }
                ManagedClaimUpdateValue::Bool {
                    claim_name: claim_name.clone(),
                    column_name: column.column_name.clone(),
                    value: None,
                }
            }
            (AuthClaimType::Bool, Value::Bool(value)) => ManagedClaimUpdateValue::Bool {
                claim_name: claim_name.clone(),
                column_name: column.column_name.clone(),
                value: Some(*value),
            },
            (AuthClaimType::I64, _) => {
                return Err(errors::validation_error(
                    field,
                    format!("Managed auth claim `{claim_name}` must be an integer"),
                ));
            }
            (AuthClaimType::String, _) => {
                return Err(errors::validation_error(
                    field,
                    format!("Managed auth claim `{claim_name}` must be a string"),
                ));
            }
            (AuthClaimType::Bool, _) => {
                return Err(errors::validation_error(
                    field,
                    format!("Managed auth claim `{claim_name}` must be a boolean"),
                ));
            }
        };
        updates.push(update);
    }

    Ok(updates)
}

fn placeholder_for_backend(backend: AuthDbBackend, index: usize) -> String {
    match backend {
        AuthDbBackend::Postgres => format!("${index}"),
        AuthDbBackend::Sqlite | AuthDbBackend::Mysql => "?".to_owned(),
    }
}

async fn insert_admin_user(
    pool: &DbPool,
    backend: AuthDbBackend,
    email: &str,
    password_hash: &str,
    claim_values: &[AdminClaimValue],
) -> Result<(), sqlx::Error> {
    let mut columns = vec![
        "email".to_owned(),
        "password_hash".to_owned(),
        "role".to_owned(),
    ];
    columns.extend(
        claim_values
            .iter()
            .map(|claim| claim.column_name().to_owned())
            .collect::<Vec<_>>(),
    );

    let placeholders = (1..=columns.len())
        .map(|index| placeholder_for_backend(backend, index))
        .collect::<Vec<_>>()
        .join(", ");
    let quoted_columns = columns
        .iter()
        .map(|column| backend.quote_ident(column))
        .collect::<Vec<_>>()
        .join(", ");

    let sql = format!(
        "INSERT INTO {} ({}) VALUES ({})",
        backend.quote_ident("user"),
        quoted_columns,
        placeholders
    );
    let mut insert_query = query(&sql).bind(email).bind(password_hash).bind("admin");
    for claim in claim_values {
        insert_query = match claim {
            AdminClaimValue::I64 { value, .. } => insert_query.bind(*value),
            AdminClaimValue::String { value, .. } => insert_query.bind(value),
            AdminClaimValue::Bool { value, .. } => insert_query.bind(*value),
        };
    }
    insert_query.execute(pool).await?;
    let verified_at = now_timestamp_string();
    if let Err(error) = query(&format!(
        "UPDATE {} SET created_at = COALESCE(created_at, ?), email_verified_at = ?, updated_at = ? WHERE email = ?",
        auth_user_table_ident(backend)
    ))
        .bind(&verified_at)
        .bind(&verified_at)
        .bind(&verified_at)
        .bind(email)
        .execute(pool)
        .await
        && !is_missing_auth_management_schema(&error)
    {
        return Err(error);
    }
    Ok(())
}

pub async fn me(user: UserContext) -> impl Responder {
    HttpResponse::Ok().json(user)
}

pub async fn logout(req: HttpRequest) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    let Some(cookie_settings) = settings.session_cookie.as_ref() else {
        return HttpResponse::NoContent().finish();
    };

    if req.cookie(&cookie_settings.name).is_some()
        && let Err(response) = validate_cookie_csrf(&req, cookie_settings)
    {
        return response;
    }

    clear_session_cookie_response(cookie_settings)
}

fn clear_session_cookie_response(settings: &SessionCookieSettings) -> HttpResponse {
    let same_site = same_site_from_settings(settings.same_site);
    let expired_session = Cookie::build(settings.name.clone(), "")
        .path(settings.path.clone())
        .http_only(true)
        .secure(settings.secure)
        .same_site(same_site)
        .max_age(CookieDuration::seconds(0))
        .finish();
    let expired_csrf = Cookie::build(settings.csrf_cookie_name.clone(), "")
        .path(settings.path.clone())
        .http_only(false)
        .secure(settings.secure)
        .same_site(same_site)
        .max_age(CookieDuration::seconds(0))
        .finish();

    HttpResponse::NoContent()
        .cookie(expired_session)
        .cookie(expired_csrf)
        .finish()
}

pub async fn account(req: HttpRequest, user: UserContext, db: web::Data<DbPool>) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    match load_authenticated_user_by_id_with_settings(db.get_ref(), user.id, &settings).await {
        Ok(Some(user)) => HttpResponse::Ok().json(account_info_from_user(user)),
        Ok(None) => errors::unauthorized("invalid_token", "Authenticated user not found"),
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn change_password(
    user: UserContext,
    input: web::Json<ChangePasswordInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let backend = match detect_auth_backend(db.get_ref()).await {
        Ok(backend) => backend,
        Err(_) => return errors::internal_error("Database error"),
    };
    if let Err(response) = validate_auth_password(&input.new_password) {
        return response;
    }

    let account = match load_authenticated_user_by_id(db.get_ref(), user.id).await {
        Ok(Some(account)) => account,
        Ok(None) => return errors::unauthorized("invalid_token", "Authenticated user not found"),
        Err(_) => return errors::internal_error("Database error"),
    };

    if !verify(&input.current_password, &account.password_hash).unwrap_or(false) {
        return errors::unauthorized("invalid_credentials", "Current password is incorrect");
    }

    let password_hash = match hash(&input.new_password, 12) {
        Ok(hash) => hash,
        Err(_) => return errors::internal_error("Hashing error"),
    };
    let now = now_timestamp_string();

    match update_user_password(db.get_ref(), backend, user.id, &password_hash, &now).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(error) if is_missing_auth_management_schema(&error) => {
            match query(&format!(
                "UPDATE {} SET password_hash = ? WHERE id = ?",
                auth_user_table_ident(backend)
            ))
            .bind(password_hash)
            .bind(user.id)
            .execute(db.get_ref())
            .await
            {
                Ok(_) => HttpResponse::NoContent().finish(),
                Err(_) => errors::internal_error("Database error"),
            }
        }
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn verify_email_token(
    input: web::Json<VerifyEmailInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let token = input.token.trim();
    if token.is_empty() {
        return errors::validation_error("token", "Verification token cannot be empty");
    }

    match apply_email_verification_token(db.get_ref(), token).await {
        Ok(TokenActionOutcome::Applied) => HttpResponse::NoContent().finish(),
        Ok(TokenActionOutcome::Invalid) => {
            errors::bad_request("invalid_token", "Verification token is invalid")
        }
        Ok(TokenActionOutcome::Expired) => {
            errors::bad_request("expired_token", "Verification token has expired")
        }
        Err(error) if is_missing_auth_management_schema(&error) => {
            missing_auth_management_schema_response()
        }
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn verify_email_page(
    query: web::Query<AuthTokenQuery>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let Some(token) = query
        .token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
    else {
        return render_message_page(
            "Verify Email",
            "Verification link is missing a token.",
            "Ask the application to resend the verification email and open the new link.",
        );
    };

    match apply_email_verification_token(db.get_ref(), token).await {
        Ok(TokenActionOutcome::Applied) => render_message_page(
            "Email Verified",
            "Your email address has been verified.",
            "You can return to the app and continue signing in.",
        ),
        Ok(TokenActionOutcome::Invalid) => render_message_page(
            "Invalid Link",
            "This verification link is invalid.",
            "Request a new verification email from the account portal or sign-up flow.",
        ),
        Ok(TokenActionOutcome::Expired) => render_message_page(
            "Expired Link",
            "This verification link has expired.",
            "Request a new verification email from the account portal or sign-up flow.",
        ),
        Err(error) if is_missing_auth_management_schema(&error) => render_message_page(
            "Migration Required",
            "The built-in auth management schema is missing.",
            "Apply the built-in auth migration again to add email verification support.",
        ),
        Err(_) => render_message_page(
            "Unexpected Error",
            "Email verification failed because of a server error.",
            "Try again later or contact the application administrator.",
        ),
    }
}

pub async fn resend_verification(
    req: HttpRequest,
    input: web::Json<VerificationResendInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    if let Err(response) = configured_auth_email(&settings) {
        return response;
    }

    let email = match normalize_auth_email(&input.email) {
        Ok(email) => email,
        Err(response) => return response,
    };
    let user = match load_authenticated_user_by_email_with_settings(db.get_ref(), &email, &settings)
        .await
    {
        Ok(user) => user,
        Err(_) => return errors::internal_error("Database error"),
    };
    let Some(user) = user else {
        return HttpResponse::Accepted().finish();
    };
    if user.email_verified_at.is_some() {
        return HttpResponse::Accepted().finish();
    }

    let tx = match db.begin().await {
        Ok(tx) => tx,
        Err(_) => return errors::internal_error("Database error"),
    };
    if let Err(response) = send_verification_email_for_user(
        &tx,
        Some(&req),
        &settings,
        &user,
        "/auth/verification/resend",
    )
    .await
    {
        let _ = tx.rollback().await;
        return response;
    }
    if tx.commit().await.is_err() {
        return errors::internal_error("Database error");
    }

    HttpResponse::Accepted().finish()
}

pub async fn resend_account_verification(
    req: HttpRequest,
    user: UserContext,
    db: web::Data<DbPool>,
) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    if let Err(response) = configured_auth_email(&settings) {
        return response;
    }

    let account =
        match load_authenticated_user_by_id_with_settings(db.get_ref(), user.id, &settings).await {
            Ok(Some(account)) => account,
            Ok(None) => {
                return errors::unauthorized("invalid_token", "Authenticated user not found");
            }
            Err(_) => return errors::internal_error("Database error"),
        };
    if account.email_verified_at.is_some() {
        return HttpResponse::NoContent().finish();
    }

    let tx = match db.begin().await {
        Ok(tx) => tx,
        Err(_) => return errors::internal_error("Database error"),
    };
    if let Err(response) = send_verification_email_for_user(
        &tx,
        Some(&req),
        &settings,
        &account,
        "/auth/account/verification",
    )
    .await
    {
        let _ = tx.rollback().await;
        return response;
    }
    if tx.commit().await.is_err() {
        return errors::internal_error("Database error");
    }

    HttpResponse::Accepted().finish()
}

pub async fn request_password_reset(
    req: HttpRequest,
    input: web::Json<PasswordResetRequestInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    if let Err(response) = configured_auth_email(&settings) {
        return response;
    }

    let email = match normalize_auth_email(&input.email) {
        Ok(email) => email,
        Err(response) => return response,
    };
    let user = match load_authenticated_user_by_email_with_settings(db.get_ref(), &email, &settings)
        .await
    {
        Ok(user) => user,
        Err(_) => return errors::internal_error("Database error"),
    };
    let Some(user) = user else {
        return HttpResponse::Accepted().finish();
    };

    let tx = match db.begin().await {
        Ok(tx) => tx,
        Err(_) => return errors::internal_error("Database error"),
    };
    if let Err(response) =
        send_password_reset_email_for_user(&tx, Some(&req), &settings, &user).await
    {
        let _ = tx.rollback().await;
        return response;
    }
    if tx.commit().await.is_err() {
        return errors::internal_error("Database error");
    }

    HttpResponse::Accepted().finish()
}

pub async fn confirm_password_reset(
    input: web::Json<PasswordResetConfirmInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let token = input.token.trim();
    if token.is_empty() {
        return errors::validation_error("token", "Reset token cannot be empty");
    }
    if let Err(response) = validate_auth_password(&input.new_password) {
        return response;
    }

    let password_hash = match hash(&input.new_password, 12) {
        Ok(hash) => hash,
        Err(_) => return errors::internal_error("Hashing error"),
    };

    match apply_password_reset_token(db.get_ref(), token, &password_hash).await {
        Ok(TokenActionOutcome::Applied) => HttpResponse::NoContent().finish(),
        Ok(TokenActionOutcome::Invalid) => {
            errors::bad_request("invalid_token", "Password reset token is invalid")
        }
        Ok(TokenActionOutcome::Expired) => {
            errors::bad_request("expired_token", "Password reset token has expired")
        }
        Err(error) if is_missing_auth_management_schema(&error) => {
            missing_auth_management_schema_response()
        }
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn password_reset_page(
    req: HttpRequest,
    query: web::Query<AuthTokenQuery>,
) -> impl Responder {
    let auth_base = auth_api_base_path_for_page(&req, None);
    let page = render_password_reset_page(&auth_base, query.token.as_deref());
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(page)
}

pub async fn create_managed_user(
    req: HttpRequest,
    user: UserContext,
    input: web::Json<CreateManagedUserInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let settings = auth_settings_from_request(&req);
    let backend = match detect_auth_backend(db.get_ref()).await {
        Ok(backend) => backend,
        Err(_) => return errors::internal_error("Database error"),
    };
    let email = match normalize_auth_email(&input.email) {
        Ok(email) => email,
        Err(response) => return response,
    };
    if let Err(response) = validate_auth_password(&input.password) {
        return response;
    }
    let role = match normalize_auth_role(input.role.as_deref(), "user") {
        Ok(role) => role,
        Err(response) => return response,
    };
    if input.email_verified == Some(true) && input.send_verification_email == Some(true) {
        return errors::bad_request(
            "invalid_invite_state",
            "A verified user does not need a verification email",
        );
    }
    if input.send_verification_email == Some(true)
        && let Err(response) = configured_auth_email(&settings)
    {
        return response;
    }

    let password_hash = match hash(&input.password, 12) {
        Ok(hash) => hash,
        Err(_) => return errors::internal_error("Hashing error"),
    };

    let tx = match db.begin().await {
        Ok(tx) => tx,
        Err(_) => return errors::internal_error("Database error"),
    };
    let insert_result = query(&format!(
        "INSERT INTO {} (email, password_hash, role) VALUES (?, ?, ?)",
        auth_user_table_ident(backend)
    ))
    .bind(&email)
    .bind(&password_hash)
    .bind(&role)
    .execute(&tx)
    .await;

    match insert_result {
        Ok(_) => {}
        Err(error) if is_unique_violation(&error) => {
            let _ = tx.rollback().await;
            return errors::conflict("duplicate_email", "A user with that email already exists");
        }
        Err(error) => {
            let _ = tx.rollback().await;
            if is_missing_auth_management_schema(&error) {
                return missing_auth_management_schema_response();
            }
            return errors::internal_error("Database error");
        }
    }

    let Some(created_user) = (match load_authenticated_user_by_email_with_settings_for_backend(
        &tx, backend, &email, &settings,
    )
    .await
    {
        Ok(user) => user,
        Err(error) => {
            let _ = tx.rollback().await;
            if is_missing_auth_management_schema(&error) {
                return missing_auth_management_schema_response();
            }
            return errors::internal_error("Database error");
        }
    }) else {
        let _ = tx.rollback().await;
        return errors::internal_error("Failed to load created user");
    };

    let now = now_timestamp_string();
    if let Err(error) =
        initialize_user_management_timestamps(&tx, backend, created_user.id, &now).await
    {
        let _ = tx.rollback().await;
        if is_missing_auth_management_schema(&error) {
            return missing_auth_management_schema_response();
        }
        return errors::internal_error("Database error");
    }

    if input.email_verified.unwrap_or(false) {
        if let Err(error) = mark_user_email_verified(&tx, backend, created_user.id, &now).await {
            let _ = tx.rollback().await;
            if is_missing_auth_management_schema(&error) {
                return missing_auth_management_schema_response();
            }
            return errors::internal_error("Database error");
        }
    } else if input.send_verification_email.unwrap_or(false)
        && let Err(response) = send_verification_email_for_user(
            &tx,
            Some(&req),
            &settings,
            &created_user,
            "/auth/admin/users",
        )
        .await
    {
        let _ = tx.rollback().await;
        return response;
    }

    if tx.commit().await.is_err() {
        return errors::internal_error("Database error");
    }

    match load_authenticated_user_by_email_with_settings(db.get_ref(), &email, &settings).await {
        Ok(Some(account)) => {
            let scope_prefix = scope_prefix_from_request(&req, Some("/auth/admin/users"));
            let location = if scope_prefix.is_empty() {
                format!("/auth/admin/users/{}", account.id)
            } else {
                format!(
                    "{}/auth/admin/users/{}",
                    scope_prefix.trim_end_matches('/'),
                    account.id
                )
            };
            HttpResponse::Created()
                .append_header(("Location", location))
                .json(account_info_from_user(account))
        }
        Ok(None) => errors::internal_error("Failed to load created user"),
        Err(error) if is_missing_auth_management_schema(&error) => {
            missing_auth_management_schema_response()
        }
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn list_managed_users(
    req: HttpRequest,
    user: UserContext,
    query_params: web::Query<AdminListQuery>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let limit = query_params.limit.unwrap_or(50).clamp(1, 100);
    let offset = query_params.offset.unwrap_or(0);
    let email_filter = query_params
        .email
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let settings = auth_settings_from_request(&req);
    let backend = match detect_auth_backend(db.get_ref()).await {
        Ok(backend) => backend,
        Err(_) => return errors::internal_error("Database error"),
    };
    match list_authenticated_users_with_settings(
        db.get_ref(),
        backend,
        limit,
        offset,
        email_filter,
        &settings,
    )
    .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({
            "items": items,
            "limit": limit,
            "offset": offset,
        })),
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn managed_user(
    req: HttpRequest,
    user: UserContext,
    path: web::Path<i64>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let settings = auth_settings_from_request(&req);
    match load_authenticated_user_by_id_with_settings(db.get_ref(), path.into_inner(), &settings)
        .await
    {
        Ok(Some(user)) => HttpResponse::Ok().json(account_info_from_user(user)),
        Ok(None) => errors::not_found("User not found"),
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn update_managed_user(
    req: HttpRequest,
    user: UserContext,
    path: web::Path<i64>,
    input: web::Json<UpdateManagedUserInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }
    if input
        .role
        .as_deref()
        .is_some_and(|role| role.trim().is_empty())
    {
        return errors::validation_error("role", "Role cannot be empty");
    }

    let user_id = path.into_inner();
    let now = now_timestamp_string();
    let settings = auth_settings_from_request(&req);
    let backend = match detect_auth_backend(db.get_ref()).await {
        Ok(backend) => backend,
        Err(_) => return errors::internal_error("Database error"),
    };
    let claim_updates = if input.claims.is_empty() {
        Vec::new()
    } else {
        let user_columns = match user_table_columns(db.get_ref(), backend).await {
            Ok(columns) => columns,
            Err(_) => return errors::internal_error("Database error"),
        };
        match resolve_managed_claim_updates(&user_columns, &settings.claims, &input.claims) {
            Ok(updates) => updates,
            Err(response) => return response,
        }
    };
    if input.role.is_none() && input.email_verified.is_none() && claim_updates.is_empty() {
        return errors::bad_request(
            "missing_changes",
            "Provide `role`, `email_verified`, and/or `claims` to update the user",
        );
    }
    match update_managed_user_row(db.get_ref(), backend, user_id, &input, &claim_updates, &now)
        .await
    {
        Ok(true) => {
            match load_authenticated_user_by_id_with_settings(db.get_ref(), user_id, &settings)
                .await
            {
                Ok(Some(user)) => HttpResponse::Ok().json(account_info_from_user(user)),
                Ok(None) => errors::not_found("User not found"),
                Err(_) => errors::internal_error("Database error"),
            }
        }
        Ok(false) => errors::not_found("User not found"),
        Err(error) if is_missing_auth_management_schema(&error) => {
            missing_auth_management_schema_response()
        }
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn delete_managed_user(
    user: UserContext,
    path: web::Path<i64>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let user_id = path.into_inner();
    if user.id == user_id {
        return errors::bad_request(
            "cannot_delete_self",
            "Admins cannot delete their own account from the admin dashboard",
        );
    }

    let backend = match detect_auth_backend(db.get_ref()).await {
        Ok(backend) => backend,
        Err(_) => return errors::internal_error("Database error"),
    };
    match delete_user_row(db.get_ref(), backend, user_id).await {
        Ok(true) => HttpResponse::NoContent().finish(),
        Ok(false) => errors::not_found("User not found"),
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn resend_managed_user_verification(
    req: HttpRequest,
    user: UserContext,
    path: web::Path<i64>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }
    let settings = auth_settings_from_request(&req);
    if let Err(response) = configured_auth_email(&settings) {
        return response;
    }

    let Some(account) = (match load_authenticated_user_by_id_with_settings(
        db.get_ref(),
        path.into_inner(),
        &settings,
    )
    .await
    {
        Ok(account) => account,
        Err(_) => return errors::internal_error("Database error"),
    }) else {
        return errors::not_found("User not found");
    };
    if account.email_verified_at.is_some() {
        return HttpResponse::NoContent().finish();
    }

    let tx = match db.begin().await {
        Ok(tx) => tx,
        Err(_) => return errors::internal_error("Database error"),
    };
    if let Err(response) = send_verification_email_for_user(
        &tx,
        Some(&req),
        &settings,
        &account,
        "/auth/admin/users/verification",
    )
    .await
    {
        let _ = tx.rollback().await;
        return response;
    }
    if tx.commit().await.is_err() {
        return errors::internal_error("Database error");
    }

    HttpResponse::Accepted().finish()
}

pub async fn account_portal_page(req: HttpRequest) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    let Some(portal) = settings.portal.as_ref() else {
        return errors::not_found("Account portal is not enabled");
    };
    let auth_base = auth_api_base_path_for_page(&req, Some(portal.path.as_str()));
    let csrf_cookie_name = settings
        .session_cookie
        .as_ref()
        .map(|cookie| cookie.csrf_cookie_name.as_str())
        .unwrap_or("vsr_csrf");
    let csrf_header_name = settings
        .session_cookie
        .as_ref()
        .map(|cookie| cookie.csrf_header_name.as_str())
        .unwrap_or("x-csrf-token");

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(render_account_portal_page(
            &portal.title,
            &auth_base,
            csrf_cookie_name,
            csrf_header_name,
        ))
}

pub async fn admin_dashboard_page(req: HttpRequest, user: UserContext) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let settings = auth_settings_from_request(&req);
    let Some(dashboard) = settings.admin_dashboard.as_ref() else {
        return errors::not_found("Admin dashboard is not enabled");
    };
    let auth_base = auth_api_base_path_for_page(&req, Some(dashboard.path.as_str()));
    let csrf_cookie_name = settings
        .session_cookie
        .as_ref()
        .map(|cookie| cookie.csrf_cookie_name.as_str())
        .unwrap_or("vsr_csrf");
    let csrf_header_name = settings
        .session_cookie
        .as_ref()
        .map(|cookie| cookie.csrf_header_name.as_str())
        .unwrap_or("x-csrf-token");

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(render_admin_dashboard_page(
            &dashboard.title,
            &auth_base,
            csrf_cookie_name,
            csrf_header_name,
        ))
}

fn auth_api_base_path_for_page(req: &HttpRequest, page_path: Option<&str>) -> String {
    let scope_prefix = scope_prefix_from_request(req, page_path);
    if scope_prefix.is_empty() {
        "/auth".to_owned()
    } else {
        format!("{}/auth", scope_prefix.trim_end_matches('/'))
    }
}

fn render_message_page(title: &str, headline: &str, detail: &str) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(render_shell(
            title,
            "",
            &format!(
                "<section class=\"panel single\"><h2>{}</h2><p>{}</p></section>",
                escape_html(headline),
                escape_html(detail),
            ),
            "",
        ))
}

fn render_password_reset_page(auth_base: &str, token: Option<&str>) -> String {
    let body = if let Some(token) = token.filter(|token| !token.trim().is_empty()) {
        format!(
            "<section class=\"panel\"><h2>Choose A New Password</h2><form id=\"reset-form\"><input type=\"hidden\" id=\"reset-token\" value=\"{}\"><label>New password</label><input id=\"new-password\" type=\"password\" autocomplete=\"new-password\" required><button type=\"submit\">Reset password</button></form><p id=\"reset-result\" class=\"muted\"></p></section>",
            escape_html(token),
        )
    } else {
        "<section class=\"panel\"><h2>Request Password Reset</h2><form id=\"reset-request-form\"><label>Email address</label><input id=\"reset-email\" type=\"email\" autocomplete=\"email\" required><button type=\"submit\">Send reset link</button></form><p id=\"reset-result\" class=\"muted\"></p></section>".to_owned()
    };
    let script = format!(
        "const authBase = {auth_base:?};\n\
         const token = document.getElementById('reset-token');\n\
         async function submitJson(path, payload) {{\n\
             const response = await fetch(`${{authBase}}/${{path}}`, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify(payload), credentials: 'include' }});\n\
             if (response.ok) return {{ ok: true }};\n\
             let detail = 'Request failed';\n\
             try {{ const body = await response.json(); detail = body.message || detail; }} catch {{}}\n\
             return {{ ok: false, detail }};\n\
         }}\n\
         const result = document.getElementById('reset-result');\n\
         document.getElementById('reset-request-form')?.addEventListener('submit', async (event) => {{\n\
             event.preventDefault();\n\
             const email = document.getElementById('reset-email').value.trim();\n\
             const outcome = await submitJson('password-reset/request', {{ email }});\n\
             result.textContent = outcome.ok ? 'If that account exists, a reset link has been sent.' : outcome.detail;\n\
         }});\n\
         document.getElementById('reset-form')?.addEventListener('submit', async (event) => {{\n\
             event.preventDefault();\n\
             const newPassword = document.getElementById('new-password').value;\n\
             const outcome = await submitJson('password-reset/confirm', {{ token: token.value, new_password: newPassword }});\n\
             result.textContent = outcome.ok ? 'Password updated. Return to the app and sign in.' : outcome.detail;\n\
         }});"
    );
    render_shell(
        "Password Reset",
        "Built-in account recovery",
        &body,
        &script,
    )
}

fn render_account_portal_page(
    title: &str,
    auth_base: &str,
    csrf_cookie_name: &str,
    csrf_header_name: &str,
) -> String {
    let body = r#"
        <section class="panel wide">
            <p class="kicker">Account Portal</p>
            <h2>Account Portal</h2>
            <p class="muted">Review your live account record, password, and verification state without leaving the app.</p>
            <div id="account-status" class="status-note info">Loading account…</div>
            <div id="account-summary" class="summary-grid">
                <article class="stat"><span class="stat-label">Email</span><strong>-</strong></article>
                <article class="stat"><span class="stat-label">Role</span><strong>-</strong></article>
                <article class="stat"><span class="stat-label">Verification</span><strong>-</strong></article>
            </div>
            <div class="toolbar">
                <label class="wide-field">
                    <span>Optional bearer token</span>
                    <input id="bearer-token" type="text" placeholder="Paste a bearer token if you are not using cookies">
                </label>
                <div class="actions">
                    <button id="refresh-account" type="button">Refresh account</button>
                    <button id="logout-button" type="button" class="secondary">Log out</button>
                </div>
            </div>
            <pre id="account-state">Loading account…</pre>
        </section>
        <section class="panel">
            <h2>Change password</h2>
            <form id="change-password-form">
                <label>
                    <span>Current password</span>
                    <input id="current-password" type="password" autocomplete="current-password" required>
                </label>
                <label>
                    <span>New password</span>
                    <input id="next-password" type="password" autocomplete="new-password" required>
                </label>
                <button type="submit">Update password</button>
            </form>
            <p id="password-result" class="muted"></p>
        </section>
        <section class="panel">
            <h2>Email verification</h2>
            <p class="muted">If the account is still pending verification, request a fresh verification link.</p>
            <div class="actions">
                <button id="resend-verification" type="button">Send verification email</button>
                <a class="text-link" id="password-reset-link" href="/auth/password-reset">Open password reset page</a>
            </div>
            <p id="verification-result" class="muted"></p>
        </section>
    "#;
    let script_template = r#"
const authBase = __AUTH_BASE__;
const csrfCookieName = __CSRF_COOKIE_NAME__;
const csrfHeaderName = __CSRF_HEADER_NAME__;
const accountStateEl = document.getElementById('account-state');
const accountSummaryEl = document.getElementById('account-summary');
const accountStatusEl = document.getElementById('account-status');
document.getElementById('password-reset-link').href = `${authBase}/password-reset`;

function bearerToken() {
  return document.getElementById('bearer-token').value.trim();
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function csrfToken() {
  const escaped = csrfCookieName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = document.cookie.match(new RegExp(`(?:^|; )${escaped}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : '';
}

async function responseMessage(response, fallback = 'Request failed') {
  const text = await response.text();
  if (!text) return fallback;
  try {
    const payload = JSON.parse(text);
    return payload.message || payload.code || fallback;
  } catch {
    return text;
  }
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const token = bearerToken();
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  const method = (options.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = csrfToken();
    if (csrf) {
      headers.set(csrfHeaderName, csrf);
    }
  }
  return fetch(`${authBase}/${path}`, { ...options, headers, credentials: 'include' });
}

function setAccountStatus(message, kind = 'info') {
  accountStatusEl.textContent = message;
  accountStatusEl.className = `status-note ${kind}`;
}

function renderAccountSummary(account) {
  const verified = account?.email_verified ? 'Verified' : 'Pending verification';
  accountSummaryEl.innerHTML = `
    <article class="stat"><span class="stat-label">Email</span><strong>${escapeHtml(account?.email || '-')}</strong></article>
    <article class="stat"><span class="stat-label">Role</span><strong>${escapeHtml(account?.role || '-')}</strong></article>
    <article class="stat"><span class="stat-label">Verification</span><strong>${escapeHtml(verified)}</strong></article>
  `;
}

async function refreshAccount(showSuccess = false) {
  const response = await api('account');
  if (!response.ok) {
    accountStateEl.textContent = await responseMessage(response);
    renderAccountSummary(null);
    setAccountStatus('Could not load account details.', 'error');
    return;
  }
  const payload = await response.json();
  accountStateEl.textContent = JSON.stringify(payload, null, 2);
  renderAccountSummary(payload);
  if (showSuccess) {
    setAccountStatus('Account details refreshed.', 'success');
  } else {
    setAccountStatus('Account details loaded.', 'success');
  }
}

document.getElementById('refresh-account').addEventListener('click', () => {
  refreshAccount(true).catch((error) => {
    setAccountStatus(error.message || 'Could not refresh account.', 'error');
  });
});

document.getElementById('change-password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = {
    current_password: document.getElementById('current-password').value,
    new_password: document.getElementById('next-password').value,
  };
  const response = await api('account/password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  document.getElementById('password-result').textContent = response.ok
    ? 'Password updated successfully.'
    : await responseMessage(response);
});

document.getElementById('resend-verification').addEventListener('click', async () => {
  const response = await api('account/verification', { method: 'POST' });
  document.getElementById('verification-result').textContent = response.ok
    ? 'Verification email sent.'
    : await responseMessage(response);
});

document.getElementById('logout-button').addEventListener('click', async () => {
  const response = await api('logout', { method: 'POST' });
  if (response.ok) {
    accountStateEl.textContent = 'Logged out.';
    renderAccountSummary(null);
    setAccountStatus('Session cleared.', 'success');
    document.getElementById('verification-result').textContent = 'Logged out.';
    return;
  }
  document.getElementById('verification-result').textContent = await responseMessage(response);
});

refreshAccount(false).catch((error) => {
  setAccountStatus(error.message || 'Could not load account.', 'error');
});
"#;
    let script = script_template
        .replace("__AUTH_BASE__", &format!("{auth_base:?}"))
        .replace("__CSRF_COOKIE_NAME__", &format!("{csrf_cookie_name:?}"))
        .replace("__CSRF_HEADER_NAME__", &format!("{csrf_header_name:?}"));
    render_shell(title, "Built-in account management", body, &script)
}

fn render_admin_dashboard_page(
    title: &str,
    auth_base: &str,
    csrf_cookie_name: &str,
    csrf_header_name: &str,
) -> String {
    let body = r#"
        <section class="panel wide">
            <p class="kicker">Admin Dashboard</p>
            <h2>Admin Dashboard</h2>
            <p class="muted">Create accounts, update roles, resend verification, trigger recovery, and remove access from one place.</p>
            <div id="admin-status" class="status-note info">Loading user directory…</div>
            <form id="admin-search-form" class="toolbar">
                <label class="wide-field">
                    <span>Optional bearer token</span>
                    <input id="bearer-token" type="text" placeholder="Paste a bearer token if you are not using cookies">
                </label>
                <label class="wide-field">
                    <span>Search by email</span>
                    <input id="user-search" type="search" placeholder="jane@example.com">
                </label>
                <div class="actions">
                    <button id="load-users" type="submit">Refresh users</button>
                </div>
            </form>
        </section>
        <section class="panel">
            <h2>Create user</h2>
            <form id="create-user-form">
                <label>
                    <span>Email</span>
                    <input id="create-user-email" type="email" autocomplete="email" required>
                </label>
                <label>
                    <span>Initial password</span>
                    <input id="create-user-password" type="password" autocomplete="new-password" required>
                </label>
                <label>
                    <span>Role</span>
                    <input id="create-user-role" type="text" value="user" required>
                </label>
                <label>
                    <span>Verification state</span>
                    <select id="create-user-verified">
                        <option value="false">Pending verification</option>
                        <option value="true">Verified immediately</option>
                    </select>
                </label>
                <label>
                    <span>Verification email</span>
                    <select id="create-user-send-verification">
                        <option value="true">Send verification email</option>
                        <option value="false">Do not send</option>
                    </select>
                </label>
                <button type="submit">Create user</button>
            </form>
            <p id="create-user-result" class="muted"></p>
        </section>
        <section class="panel wide">
            <div class="section-head">
                <div>
                    <h2>User directory</h2>
                    <p id="admin-summary" class="muted">Loading users…</p>
                </div>
            </div>
            <div id="user-list" class="user-list"></div>
        </section>
    "#;
    let script_template = r#"
const authBase = __AUTH_BASE__;
const csrfCookieName = __CSRF_COOKIE_NAME__;
const csrfHeaderName = __CSRF_HEADER_NAME__;
const userListEl = document.getElementById('user-list');
const adminSummaryEl = document.getElementById('admin-summary');
const adminStatusEl = document.getElementById('admin-status');
let currentAccount = null;
let users = [];

function bearerToken() {
  return document.getElementById('bearer-token').value.trim();
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll('`', '&#96;');
}

function csrfToken() {
  const escaped = csrfCookieName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = document.cookie.match(new RegExp(`(?:^|; )${escaped}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : '';
}

async function responseMessage(response, fallback = 'Request failed') {
  const text = await response.text();
  if (!text) return fallback;
  try {
    const payload = JSON.parse(text);
    return payload.message || payload.code || fallback;
  } catch {
    return text;
  }
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const token = bearerToken();
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  const method = (options.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = csrfToken();
    if (csrf) {
      headers.set(csrfHeaderName, csrf);
    }
  }
  return fetch(`${authBase}/${path}`, { ...options, headers, credentials: 'include' });
}

function setAdminStatus(message, kind = 'info') {
  adminStatusEl.textContent = message;
  adminStatusEl.className = `status-note ${kind}`;
}

async function loadCurrentAccount() {
  const response = await api('account');
  if (!response.ok) {
    throw new Error(await responseMessage(response, 'Could not load admin account'));
  }
  currentAccount = await response.json();
}

function renderUsers() {
  if (users.length === 0) {
    userListEl.innerHTML = '<article class="user-card"><p class="muted">No users match the current filter.</p></article>';
    adminSummaryEl.textContent = 'No matching users.';
    return;
  }

  adminSummaryEl.textContent = `${users.length} user${users.length === 1 ? '' : 's'} loaded.`;
  userListEl.innerHTML = users.map((item) => {
    const verified = item.email_verified ? 'true' : 'false';
    const verifiedLabel = item.email_verified ? 'Verified' : 'Pending verification';
    const disableDelete = currentAccount && currentAccount.id === item.id;
    const claims = item.claims && Object.keys(item.claims).length > 0
      ? `<details><summary>Claims</summary><pre>${escapeHtml(JSON.stringify(item.claims, null, 2))}</pre></details>`
      : '';
    return `
      <article class="user-card">
        <header class="card-head">
          <div>
            <strong>${escapeHtml(item.email)}</strong>
            <p class="muted">User #${escapeHtml(item.id)} · ${escapeHtml(item.created_at || 'created timestamp unavailable')}</p>
          </div>
          <span class="badge ${item.email_verified ? 'success' : 'warning'}">${escapeHtml(verifiedLabel)}</span>
        </header>
        <div class="summary-grid compact">
          <article class="stat"><span class="stat-label">Role</span><strong>${escapeHtml(item.role)}</strong></article>
          <article class="stat"><span class="stat-label">Updated</span><strong>${escapeHtml(item.updated_at || '-')}</strong></article>
          <article class="stat"><span class="stat-label">Verification</span><strong>${escapeHtml(item.email_verified_at || 'Not verified')}</strong></article>
        </div>
        <form class="inline-form" data-user-id="${escapeAttribute(item.id)}">
          <label>
            <span>Role</span>
            <input id="user-role-${escapeAttribute(item.id)}" type="text" value="${escapeAttribute(item.role)}">
          </label>
          <label>
            <span>Verification state</span>
            <select id="user-verified-${escapeAttribute(item.id)}">
              <option value="false"${verified === 'false' ? ' selected' : ''}>Pending verification</option>
              <option value="true"${verified === 'true' ? ' selected' : ''}>Verified</option>
            </select>
          </label>
        </form>
        <div class="actions">
          <button data-action="save" data-id="${escapeAttribute(item.id)}" type="button">Save changes</button>
          <button data-action="verify" data-id="${escapeAttribute(item.id)}" type="button" class="secondary">Resend verification</button>
          <button data-action="reset" data-id="${escapeAttribute(item.id)}" data-email="${escapeAttribute(item.email)}" type="button" class="secondary">Send reset email</button>
          <button data-action="delete" data-id="${escapeAttribute(item.id)}" type="button" class="danger"${disableDelete ? ' disabled' : ''}>Delete user</button>
        </div>
        ${claims}
      </article>
    `;
  }).join('');
}

async function loadUsers() {
  const email = document.getElementById('user-search').value.trim();
  const params = new URLSearchParams();
  if (email) {
    params.set('email', email);
  }
  const suffix = params.toString() ? `?${params.toString()}` : '';
  const response = await api(`admin/users${suffix}`);
  if (!response.ok) {
    throw new Error(await responseMessage(response, 'Could not load users'));
  }
  const payload = await response.json();
  users = payload.items || [];
  renderUsers();
  setAdminStatus('User directory refreshed.', 'success');
}

document.getElementById('admin-search-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await loadUsers();
  } catch (error) {
    setAdminStatus(error.message || 'Could not load users.', 'error');
  }
});

document.getElementById('create-user-verified').addEventListener('change', (event) => {
  if (event.target.value === 'true') {
    document.getElementById('create-user-send-verification').value = 'false';
  }
});

document.getElementById('create-user-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const emailVerified = document.getElementById('create-user-verified').value === 'true';
  const payload = {
    email: document.getElementById('create-user-email').value.trim(),
    password: document.getElementById('create-user-password').value,
    role: document.getElementById('create-user-role').value.trim(),
    email_verified: emailVerified,
    send_verification_email: !emailVerified && document.getElementById('create-user-send-verification').value === 'true',
  };
  const response = await api('admin/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const resultEl = document.getElementById('create-user-result');
  if (!response.ok) {
    resultEl.textContent = await responseMessage(response, 'Could not create user');
    return;
  }
  const payloadBody = await response.json();
  resultEl.textContent = `Created ${payloadBody.email}.`;
  document.getElementById('create-user-form').reset();
  document.getElementById('create-user-role').value = 'user';
  document.getElementById('create-user-verified').value = 'false';
  document.getElementById('create-user-send-verification').value = 'true';
  await loadUsers();
});

userListEl.addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action]');
  if (!button) {
    return;
  }
  const id = button.dataset.id;
  try {
    if (button.dataset.action === 'save') {
      const role = document.getElementById(`user-role-${id}`).value.trim();
      const emailVerified = document.getElementById(`user-verified-${id}`).value === 'true';
      const response = await api(`admin/users/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role, email_verified: emailVerified }),
      });
      if (!response.ok) {
        throw new Error(await responseMessage(response, 'Could not update user'));
      }
      await loadUsers();
      return;
    }

    if (button.dataset.action === 'verify') {
      const response = await api(`admin/users/${id}/verification`, { method: 'POST' });
      if (!response.ok) {
        throw new Error(await responseMessage(response, 'Could not send verification email'));
      }
      setAdminStatus('Verification email queued.', 'success');
      return;
    }

    if (button.dataset.action === 'reset') {
      const response = await api('password-reset/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: button.dataset.email }),
      });
      if (!response.ok) {
        throw new Error(await responseMessage(response, 'Could not send password reset email'));
      }
      setAdminStatus('Password reset email queued.', 'success');
      return;
    }

    if (button.dataset.action === 'delete') {
      if (!window.confirm('Delete this user and revoke built-in auth access?')) {
        return;
      }
      const response = await api(`admin/users/${id}`, { method: 'DELETE' });
      if (!response.ok) {
        throw new Error(await responseMessage(response, 'Could not delete user'));
      }
      await loadUsers();
      setAdminStatus('User deleted.', 'success');
    }
  } catch (error) {
    setAdminStatus(error.message || 'Admin action failed.', 'error');
  }
});

Promise.all([loadCurrentAccount(), loadUsers()]).catch((error) => {
  setAdminStatus(error.message || 'Could not load admin dashboard.', 'error');
});
"#;
    let script = script_template
        .replace("__AUTH_BASE__", &format!("{auth_base:?}"))
        .replace("__CSRF_COOKIE_NAME__", &format!("{csrf_cookie_name:?}"))
        .replace("__CSRF_HEADER_NAME__", &format!("{csrf_header_name:?}"));
    render_shell(title, "Built-in admin account management", body, &script)
}

fn render_shell(title: &str, subtitle: &str, body: &str, script: &str) -> String {
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{}</title><style>:root{{--bg:#f3f5f8;--surface:#ffffff;--surface-soft:#f7f9fc;--ink:#15202b;--muted:#5b6774;--border:#d9e1ea;--accent:#1d4ed8;--accent-strong:#163fbc;--accent-soft:rgba(29,78,216,.1);--danger:#b42318;--danger-soft:rgba(180,35,24,.08);--success-soft:rgba(22,163,74,.1);--warning-soft:rgba(217,119,6,.12);--shadow:0 28px 80px rgba(15,23,42,.08);}}*{{box-sizing:border-box}}body{{margin:0;font-family:"SF Pro Text","Segoe UI",ui-sans-serif,system-ui,sans-serif;color:var(--ink);background:linear-gradient(180deg,#f9fbfd 0%,var(--bg) 100%);min-height:100vh}}body::before{{content:"";position:fixed;inset:0;pointer-events:none;background:radial-gradient(circle at top left,rgba(29,78,216,.08),transparent 34%),radial-gradient(circle at top right,rgba(15,23,42,.06),transparent 28%)}}main{{position:relative;max-width:1180px;margin:0 auto;padding:40px 20px 64px}}header.hero{{display:grid;gap:10px;margin-bottom:24px}}header.hero h1{{margin:0;font-size:clamp(2.25rem,5vw,3.8rem);letter-spacing:-0.05em;font-family:"Iowan Old Style","Palatino Linotype","Book Antiqua",ui-serif,serif}}header.hero p{{margin:0;color:var(--muted);max-width:62ch;line-height:1.65}}.kicker{{margin:0;color:var(--accent);font-size:.82rem;font-weight:700;letter-spacing:.18em;text-transform:uppercase}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px}}.wide{{grid-column:1 / -1}}section.panel{{background:linear-gradient(180deg,var(--surface),var(--surface-soft));border:1px solid var(--border);border-radius:28px;padding:24px;box-shadow:var(--shadow)}}section.panel h2{{margin:0 0 8px;font-size:1.45rem;letter-spacing:-.03em}}.section-head{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}}label{{display:grid;gap:6px;font-size:.92rem;font-weight:600}}input,select,textarea,button{{font:inherit}}input,select,textarea{{width:100%;padding:12px 14px;border-radius:16px;border:1px solid var(--border);background:#fff;color:var(--ink)}}textarea{{min-height:132px;resize:vertical}}button{{padding:12px 16px;border:none;border-radius:999px;background:linear-gradient(135deg,var(--accent),var(--accent-strong));color:#fff;font-weight:700;cursor:pointer;box-shadow:0 12px 28px rgba(29,78,216,.22)}}button.secondary{{background:#e8eefc;color:var(--accent-strong);box-shadow:none}}button.danger{{background:linear-gradient(135deg,#d13a2e,var(--danger));box-shadow:0 12px 28px rgba(180,35,24,.18)}}button:disabled{{opacity:.55;cursor:not-allowed;box-shadow:none}}button:hover:not(:disabled){{transform:translateY(-1px)}}form{{display:grid;gap:14px}}pre{{margin:0;padding:14px 16px;border-radius:18px;background:#0f172a;color:#e2e8f0;overflow:auto;min-height:120px}}.muted{{color:var(--muted)}}.toolbar{{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr) auto;gap:14px;align-items:end}}.wide-field{{grid-column:auto}}.actions{{display:flex;gap:10px;flex-wrap:wrap;align-items:center}}.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0}}.summary-grid.compact{{margin:12px 0 0}}.stat{{padding:16px;border:1px solid var(--border);border-radius:20px;background:#fff}}.stat-label{{display:block;margin-bottom:8px;color:var(--muted);font-size:.88rem}}.badge{{display:inline-flex;align-items:center;justify-content:center;padding:8px 12px;border-radius:999px;background:var(--accent-soft);color:var(--accent-strong);font-size:.82rem;font-weight:700}}.badge.success{{background:var(--success-soft);color:#166534}}.badge.warning{{background:var(--warning-soft);color:#9a5b00}}.status-note{{margin:0;padding:14px 16px;border-radius:18px;border:1px solid var(--border);background:#fff}}.status-note.info{{background:#eef4ff;border-color:#d3e1ff;color:#173f8a}}.status-note.success{{background:#ecfdf3;border-color:#b7ebca;color:#166534}}.status-note.error{{background:#fff1f2;border-color:#fecdd3;color:#9f1239}}.user-list{{display:grid;gap:14px}}.user-card{{border:1px solid var(--border);border-radius:22px;padding:18px;background:#fff}}.card-head{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:8px}}.inline-form{{grid-template-columns:repeat(auto-fit,minmax(220px,1fr));align-items:end;margin-top:12px}}.text-link{{color:var(--accent-strong);font-weight:600;text-decoration:none}}summary{{cursor:pointer;color:var(--muted);font-weight:600}}details pre{{margin-top:10px;min-height:0}}@media (max-width:800px){{main{{padding:28px 16px 48px}}.toolbar{{grid-template-columns:1fr}}.section-head{{flex-direction:column}}.card-head{{flex-direction:column;align-items:flex-start}}}}</style></head><body><main><header class="hero"><p class="kicker">Built-in Auth</p><h1>{}</h1><p>{}</p></header><div class="grid">{}</div></main><script>{}</script></body></html>"#,
        escape_html(title),
        escape_html(title),
        escape_html(subtitle),
        body,
        script,
    )
}

/// Check if an admin user exists, and create one automatically if not
///
/// This function will:
/// 1. Check if an admin user already exists
/// 2. If not, prompt the user to enter admin credentials via stdin
///
/// Returns true if an admin exists (either previously or newly created),
/// false only if there was an error creating the admin user.
pub async fn ensure_admin_exists(pool: &DbPool) -> Result<bool, sqlx::Error> {
    ensure_admin_exists_with_settings_and_claim_prompt_mode(
        pool,
        &AuthSettings::default(),
        stdin().is_terminal() && stdout().is_terminal(),
    )
    .await
}

pub async fn ensure_admin_exists_with_settings(
    pool: &DbPool,
    settings: &AuthSettings,
) -> Result<bool, sqlx::Error> {
    ensure_admin_exists_with_settings_and_claim_prompt_mode(
        pool,
        settings,
        stdin().is_terminal() && stdout().is_terminal(),
    )
    .await
}

pub async fn validate_auth_claim_mappings(
    pool: &DbPool,
    settings: &AuthSettings,
) -> Result<(), String> {
    if settings.claims.is_empty() {
        return Ok(());
    }

    let backend = detect_auth_backend(pool)
        .await
        .map_err(|error| format!("Failed to detect auth backend: {error}"))?;
    let user_columns = user_table_columns(pool, backend)
        .await
        .map_err(|error| format!("Failed to inspect auth schema: {error}"))?;
    configured_admin_claim_columns(&user_columns, &settings.claims).map(|_| ())
}

async fn ensure_admin_exists_with_settings_and_claim_prompt_mode(
    pool: &DbPool,
    settings: &AuthSettings,
    interactive_claims: bool,
) -> Result<bool, sqlx::Error> {
    let backend = detect_auth_backend(pool).await?;
    // Check if any admin exists
    let count = match query_scalar::<sqlx::Any, i64>(&format!(
        "SELECT COUNT(*) FROM {} WHERE role = 'admin'",
        auth_user_table_ident(backend)
    ))
    .fetch_one(pool)
    .await
    {
        Ok(count) => count,
        Err(error) => {
            eprintln!(
                "[ERROR] Missing built-in auth schema. Apply the auth migration before starting the server."
            );
            return Err(error);
        }
    };

    let admin_exists = count > 0;

    if admin_exists {
        println!("[INFO] Admin user is set up and ready");
        return Ok(true);
    }

    println!("[INFO] No admin user found. Creating an admin user...");

    // Try to get admin credentials from environment variables first
    let (email, password) = if let (Ok(email), Ok(password)) = (
        std::env::var("ADMIN_EMAIL"),
        std::env::var("ADMIN_PASSWORD"),
    ) {
        if !email.is_empty() && !password.is_empty() {
            println!("[INFO] Using environment variables for admin credentials");
            (email, password)
        } else {
            prompt_admin_credentials()
        }
    } else {
        prompt_admin_credentials()
    };

    // Create the admin user
    let password_hash = match hash(&password, 12) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("[ERROR] Failed to hash password: {}", e);
            return Ok(false);
        }
    };
    let backend = match detect_auth_backend(pool).await {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("[ERROR] Failed to detect auth backend: {}", error);
            return Err(error);
        }
    };
    let user_columns = match user_table_columns(pool, backend).await {
        Ok(columns) => columns,
        Err(error) => {
            eprintln!("[ERROR] Failed to inspect auth schema: {}", error);
            return Err(error);
        }
    };
    let claim_columns = if settings.claims.is_empty() {
        user_columns
            .into_iter()
            .filter_map(legacy_admin_claim_column_from_metadata)
            .collect::<Vec<_>>()
    } else {
        match configured_admin_claim_columns(&user_columns, &settings.claims) {
            Ok(columns) => columns,
            Err(error) => {
                eprintln!("[ERROR] {}", error);
                return Ok(false);
            }
        }
    };
    let claim_values = match resolve_admin_claim_values(&claim_columns, interactive_claims) {
        Ok(values) => values,
        Err(error) => {
            eprintln!("[ERROR] {}", error);
            return Ok(false);
        }
    };

    let result = insert_admin_user(pool, backend, &email, &password_hash, &claim_values).await;

    match result {
        Ok(_) => {
            println!("[SUCCESS] Admin user created successfully!");
            println!("--------------------------------------------");
            println!("🔐 Admin User Created 🔐");
            println!("Email: {}", email);
            if !claim_values.is_empty() {
                let rendered_claims = claim_values
                    .iter()
                    .map(AdminClaimValue::render)
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("Claims: {}", rendered_claims);
            }
            println!("--------------------------------------------");
            Ok(true)
        }
        Err(e) => {
            eprintln!("[ERROR] Failed to create admin user: {}", e);
            Ok(false)
        }
    }
}

/// Prompt for admin credentials via stdin
fn prompt_admin_credentials() -> (String, String) {
    println!("[INFO] Please enter admin credentials:");

    // Prompt for email
    let mut email = String::new();
    print!("Admin email: ");
    stdout().flush().unwrap();
    stdin().read_line(&mut email).unwrap();
    let email = email.trim().to_string();

    // Prompt for password securely (no echo)
    let password = match rpassword::prompt_password("Admin password: ") {
        Ok(password) => password,
        Err(e) => {
            eprintln!("[ERROR] Failed to read password: {}", e);
            println!("[WARN] Using default admin credentials as fallback.");
            return create_default_admin();
        }
    };

    // Simple validation
    if email.is_empty() || password.is_empty() {
        println!(
            "[WARN] Email or password cannot be empty. Using default email and a random password."
        );
        return create_default_admin();
    }

    (email, password)
}

/// Create default admin credentials as a fallback
fn create_default_admin() -> (String, String) {
    use rand::RngExt;

    // Characters to use for password generation
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    // Generate a secure random password
    let mut rng = rand::rng();
    let password: String = (0..12)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    // Use a default admin email
    let email = "admin@example.com".to_string();

    println!("[INFO] Creating default admin user");

    (email, password)
}

pub fn auth_routes(cfg: &mut web::ServiceConfig, db: impl Into<DbPool>) {
    auth_routes_with_settings(cfg, db, AuthSettings::default());
}

pub fn public_auth_discovery_routes(cfg: &mut web::ServiceConfig) {
    public_auth_discovery_routes_with_settings(cfg, AuthSettings::default());
}

pub fn public_auth_discovery_routes_with_settings(
    cfg: &mut web::ServiceConfig,
    settings: AuthSettings,
) {
    let settings = web::Data::new(settings);
    cfg.app_data(settings.clone());
    if settings
        .get_ref()
        .jwt
        .as_ref()
        .is_some_and(|jwt| !jwt.algorithm.is_symmetric() && !jwt.verification_keys.is_empty())
    {
        cfg.route("/.well-known/jwks.json", web::get().to(jwks));
    }
}

pub fn auth_routes_with_settings(
    cfg: &mut web::ServiceConfig,
    db: impl Into<DbPool>,
    settings: AuthSettings,
) {
    public_auth_discovery_routes_with_settings(cfg, settings.clone());
    auth_api_routes_with_settings(cfg, db, settings);
}

pub fn auth_api_routes_with_settings(
    cfg: &mut web::ServiceConfig,
    db: impl Into<DbPool>,
    settings: AuthSettings,
) {
    let db = web::Data::new(db.into());
    let enable_portal = settings.portal.clone();
    let enable_admin_dashboard = settings.admin_dashboard.clone();
    let settings = web::Data::new(settings);
    let limiter = web::Data::new(AuthRateLimiter::default());
    errors::configure_extractor_errors(cfg);
    cfg.app_data(db.clone());
    cfg.app_data(settings.clone());
    cfg.app_data(limiter);

    cfg.route("/auth/register", web::post().to(register_with_request));
    cfg.route("/auth/login", web::post().to(login_with_request));
    cfg.route("/auth/logout", web::post().to(logout));
    cfg.route("/auth/me", web::get().to(me));
    cfg.route("/auth/account", web::get().to(account));
    cfg.route("/auth/account/password", web::post().to(change_password));
    cfg.route(
        "/auth/account/verification",
        web::post().to(resend_account_verification),
    );
    cfg.route("/auth/verify-email", web::get().to(verify_email_page));
    cfg.route("/auth/verify-email", web::post().to(verify_email_token));
    cfg.route(
        "/auth/verification/resend",
        web::post().to(resend_verification),
    );
    cfg.route("/auth/password-reset", web::get().to(password_reset_page));
    cfg.route(
        "/auth/password-reset/request",
        web::post().to(request_password_reset),
    );
    cfg.route(
        "/auth/password-reset/confirm",
        web::post().to(confirm_password_reset),
    );
    cfg.route("/auth/admin/users", web::get().to(list_managed_users));
    cfg.route("/auth/admin/users", web::post().to(create_managed_user));
    cfg.route("/auth/admin/users/{id}", web::get().to(managed_user));
    cfg.route(
        "/auth/admin/users/{id}",
        web::patch().to(update_managed_user),
    );
    cfg.route(
        "/auth/admin/users/{id}",
        web::delete().to(delete_managed_user),
    );
    cfg.route(
        "/auth/admin/users/{id}/verification",
        web::post().to(resend_managed_user_verification),
    );

    if let Some(portal) = enable_portal {
        cfg.route(portal.path.as_str(), web::get().to(account_portal_page));
    }
    if let Some(dashboard) = enable_admin_dashboard {
        cfg.route(dashboard.path.as_str(), web::get().to(admin_dashboard_page));
    }
}

fn auth_settings_from_request(req: &HttpRequest) -> AuthSettings {
    req.app_data::<web::Data<AuthSettings>>()
        .map(|settings| settings.get_ref().clone())
        .unwrap_or_default()
}

fn security_from_request(req: &HttpRequest) -> SecurityConfig {
    req.app_data::<web::Data<SecurityConfig>>()
        .map(|security| security.get_ref().clone())
        .unwrap_or_else(|| {
            let mut security = SecurityConfig::default();
            security.auth = auth_settings_from_request(req);
            security
        })
}

async fn jwks(req: HttpRequest) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    match configured_public_jwks(&settings) {
        Ok(Some(jwks)) => HttpResponse::Ok().json(jwks),
        Ok(None) => errors::not_found("JWKS is not configured for this service"),
        Err(message) => errors::internal_error(message),
    }
}

fn enforce_auth_rate_limit(req: &HttpRequest, scope: AuthRateLimitScope) -> Option<HttpResponse> {
    let security = security_from_request(req);
    let rule = match scope {
        AuthRateLimitScope::Login => security.rate_limits.login,
        AuthRateLimitScope::Register => security.rate_limits.register,
    }?;

    let limiter = req.app_data::<web::Data<AuthRateLimiter>>()?;
    let client_ip = request_client_ip(req, &security)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    let key = format!("{}:{client_ip}", scope.as_str());
    let retry_after = limiter.check(&key, rule)?;

    let mut response = errors::too_many_requests(
        "rate_limited",
        format!("Too many {} attempts. Try again later.", scope.as_str()),
    );
    if let Ok(value) = actix_web::http::header::HeaderValue::from_str(&retry_after.to_string()) {
        response
            .headers_mut()
            .insert(actix_web::http::header::RETRY_AFTER, value);
    }
    Some(response)
}

fn validation_for_settings(settings: &AuthSettings, algorithm: AuthJwtAlgorithm) -> Validation {
    let mut validation = Validation::new(algorithm.jsonwebtoken());
    let mut required = vec!["exp"];

    if let Some(audience) = &settings.audience {
        validation.set_audience(&[audience.as_str()]);
        required.push("aud");
    } else {
        validation.validate_aud = false;
    }

    if let Some(issuer) = &settings.issuer {
        validation.set_issuer(&[issuer.as_str()]);
        required.push("iss");
    }

    validation.set_required_spec_claims(&required);
    validation
}

impl AuthRateLimiter {
    fn check(&self, key: &str, rule: RateLimitRule) -> Option<u64> {
        let now = Instant::now();
        let window = StdDuration::from_secs(rule.window_seconds);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let entry = entries.entry(key.to_owned()).or_default();

        while entry
            .front()
            .is_some_and(|instant| now.duration_since(*instant) >= window)
        {
            entry.pop_front();
        }

        if entry.len() >= rule.requests as usize {
            let retry_after = entry
                .front()
                .map(|oldest| {
                    window
                        .saturating_sub(now.duration_since(*oldest))
                        .as_secs()
                        .max(1)
                })
                .unwrap_or(rule.window_seconds);
            return Some(retry_after);
        }

        entry.push_back(now);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthClaimMapping, AuthClaimType, AuthDbBackend, AuthEmailProvider, AuthEmailSettings,
        AuthJwtAlgorithm, AuthJwtSettings, AuthJwtVerificationKey, AuthSettings, Claims,
        auth_claim_migration_sql, auth_migration_sql, build_public_auth_url,
        configured_public_jwks, load_jwt_secret,
    };
    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    use super::{
        LoginInput, auth_management_migration_sql,
        ensure_admin_exists_with_settings_and_claim_prompt_mode, login_with_settings,
        validate_auth_claim_mappings,
    };
    #[cfg(feature = "turso-local")]
    use crate::database::{DatabaseConfig, DatabaseEngine, TursoLocalConfig};
    #[cfg(all(not(feature = "turso-local"), feature = "sqlite"))]
    use crate::db::connect;
    #[cfg(feature = "turso-local")]
    use crate::db::connect_with_config;
    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    use crate::db::{DbPool, query, query_scalar};
    use crate::secret::SecretRef;
    use actix_web::App;
    use actix_web::test::{TestRequest, call_service, init_service, read_body_json};
    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    use actix_web::body::to_bytes;
    use actix_web::{http::StatusCode, web};
    use chrono::{Duration, Utc};
    use jsonwebtoken::{
        DecodingKey, encode,
        jwk::{AlgorithmParameters, EllipticCurve, KeyAlgorithm},
    };
    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    use sqlx::Row;
    use std::collections::BTreeMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[cfg(all(not(feature = "turso-local"), feature = "sqlite"))]
    fn unique_sqlite_url(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("vsr_auth_{prefix}_{nanos}.db"));
        format!("sqlite:{}?mode=rwc", path.display())
    }

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    async fn connect_test_pool(prefix: &str) -> DbPool {
        #[cfg(feature = "turso-local")]
        {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should be monotonic enough")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("vsr_auth_{prefix}_{nanos}.db"));
            let config = DatabaseConfig {
                engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                    path: path.to_string_lossy().into_owned(),
                    encryption_key: None,
                }),
                resilience: None,
            };
            return connect_with_config("sqlite:ignored.db?mode=rwc", &config)
                .await
                .expect("database should connect");
        }
        #[cfg(all(not(feature = "turso-local"), feature = "sqlite"))]
        {
            let database_url = unique_sqlite_url(prefix);
            return connect(&database_url)
                .await
                .expect("database should connect");
        }
    }

    fn write_temp_secret_file(prefix: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "vsr_auth_{prefix}_{}.pem",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should be monotonic enough")
                .as_nanos()
        ));
        std::fs::write(&path, contents).expect("temporary secret file should write");
        path
    }

    const TEST_ED25519_PRIVATE_KEY_CURRENT: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICan3gTz94CxAFR90FubWnI1S7Hu81HAawRP0JnhgJd1\n-----END PRIVATE KEY-----\n";
    const TEST_ED25519_PUBLIC_KEY_CURRENT: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA6SXZeouSZ6gAAGu0fq5MlKZt7T0z0mf3pK1NmaIWqi4=\n-----END PUBLIC KEY-----\n";
    const TEST_ED25519_PRIVATE_KEY_PREVIOUS: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHP+7KrmLqsh9YuYdKt7lixHaso9B9XfoxDhheTT93xC\n-----END PRIVATE KEY-----\n";
    const TEST_ED25519_PUBLIC_KEY_PREVIOUS: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAMtHpnFKVCrgrEn+eT5L9XptGRw7nq2RZy5ZsM6TdS1Q=\n-----END PUBLIC KEY-----\n";

    #[test]
    fn sqlite_auth_migration_uses_expected_schema() {
        let sql = auth_migration_sql(AuthDbBackend::Sqlite);
        assert!(sql.contains("CREATE TABLE \"user\""));
        assert!(sql.contains("id INTEGER PRIMARY KEY AUTOINCREMENT"));
        assert!(sql.contains("email TEXT NOT NULL UNIQUE"));
        assert!(sql.contains("password_hash TEXT NOT NULL"));
        assert!(sql.contains("role TEXT NOT NULL"));
        assert!(sql.contains("CREATE INDEX idx_user_role ON \"user\" (role);"));
    }

    #[test]
    fn postgres_auth_migration_quotes_reserved_user_table() {
        let sql = auth_migration_sql(AuthDbBackend::Postgres);
        assert!(sql.contains("CREATE TABLE \"user\""));
        assert!(sql.contains("CREATE INDEX idx_user_role ON \"user\" (role);"));
    }

    #[test]
    fn auth_claim_migration_sql_generates_columns_from_explicit_claims() {
        let sql = auth_claim_migration_sql(
            AuthDbBackend::Sqlite,
            &AuthSettings {
                claims: BTreeMap::from([
                    (
                        "tenant_id".to_owned(),
                        AuthClaimMapping {
                            column: "active_family_id".to_owned(),
                            ty: AuthClaimType::I64,
                        },
                    ),
                    (
                        "preferred_household".to_owned(),
                        AuthClaimMapping {
                            column: "preferred_household".to_owned(),
                            ty: AuthClaimType::String,
                        },
                    ),
                    (
                        "support_agent".to_owned(),
                        AuthClaimMapping {
                            column: "is_support_agent".to_owned(),
                            ty: AuthClaimType::Bool,
                        },
                    ),
                ]),
                ..AuthSettings::default()
            },
        );

        assert!(sql.contains("ALTER TABLE \"user\" ADD COLUMN \"active_family_id\" INTEGER;"));
        assert!(sql.contains("ALTER TABLE \"user\" ADD COLUMN \"preferred_household\" TEXT;"));
        assert!(sql.contains(
            "ALTER TABLE \"user\" ADD COLUMN \"is_support_agent\" INTEGER NOT NULL DEFAULT 0;"
        ));
    }

    #[test]
    fn load_jwt_secret_requires_non_empty_secret() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::remove_var("JWT_SECRET");
            std::env::remove_var("JWT_SECRET_FILE");
        }

        let error = load_jwt_secret(&SecretRef::env_or_file("JWT_SECRET"))
            .expect_err("missing JWT secret should fail");
        assert!(error.contains("JWT_SECRET"));

        unsafe {
            std::env::set_var("JWT_SECRET", "");
        }

        let error = load_jwt_secret(&SecretRef::env_or_file("JWT_SECRET"))
            .expect_err("empty JWT secret should fail");
        assert!(error.contains("JWT_SECRET"));

        unsafe {
            std::env::remove_var("JWT_SECRET");
        }
    }

    #[test]
    fn load_jwt_secret_accepts_non_empty_secret() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var("JWT_SECRET", "unit-test-secret");
        }

        let secret = load_jwt_secret(&SecretRef::env_or_file("JWT_SECRET"))
            .expect("non-empty JWT secret should load");
        assert_eq!(&*secret, b"unit-test-secret");

        unsafe {
            std::env::remove_var("JWT_SECRET");
        }
    }

    #[test]
    fn load_jwt_secret_from_file_path_env() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let path = std::env::temp_dir().join(format!(
            "vsr_jwt_secret_{}.txt",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should be monotonic enough")
                .as_nanos()
        ));
        std::fs::write(&path, "file-secret\n").expect("jwt secret file should write");

        unsafe {
            std::env::remove_var("JWT_SECRET");
            std::env::set_var("JWT_SECRET_FILE", path.as_os_str());
        }

        let secret = load_jwt_secret(&SecretRef::env_or_file("JWT_SECRET"))
            .expect("file-backed JWT secret should load");
        assert_eq!(&*secret, b"file-secret");

        unsafe {
            std::env::remove_var("JWT_SECRET_FILE");
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn eddsa_jwt_signing_and_verification_supports_configured_key_ids() {
        let private_key =
            write_temp_secret_file("jwt_current_private", TEST_ED25519_PRIVATE_KEY_CURRENT);
        let public_key =
            write_temp_secret_file("jwt_current_public", TEST_ED25519_PUBLIC_KEY_CURRENT);

        let settings = AuthSettings {
            jwt: Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: Some("current".to_owned()),
                signing_key: SecretRef::File {
                    path: private_key.clone(),
                },
                verification_keys: vec![AuthJwtVerificationKey {
                    kid: "current".to_owned(),
                    key: SecretRef::File {
                        path: public_key.clone(),
                    },
                }],
            }),
            jwt_secret: None,
            ..AuthSettings::default()
        };

        let claims = Claims {
            sub: 42,
            roles: vec!["user".to_owned()],
            iss: None,
            aud: None,
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            extra: BTreeMap::new(),
        };

        let (header, encoding_key) =
            super::configured_jwt_signer(&settings).expect("jwt signer should resolve");
        assert_eq!(header.kid.as_deref(), Some("current"));
        let token = encode(&header, &claims, encoding_key.as_ref()).expect("jwt should encode");

        let context =
            super::decode_user_context_token(&token, &settings).expect("jwt should decode");
        assert_eq!(context.id, 42);
        assert_eq!(context.roles, vec!["user".to_owned()]);

        let _ = std::fs::remove_file(private_key);
        let _ = std::fs::remove_file(public_key);
    }

    #[test]
    fn eddsa_jwt_rotation_accepts_previous_verification_key() {
        let current_private = write_temp_secret_file(
            "jwt_rotate_current_private",
            TEST_ED25519_PRIVATE_KEY_CURRENT,
        );
        let current_public =
            write_temp_secret_file("jwt_rotate_current_public", TEST_ED25519_PUBLIC_KEY_CURRENT);
        let previous_private = write_temp_secret_file(
            "jwt_rotate_previous_private",
            TEST_ED25519_PRIVATE_KEY_PREVIOUS,
        );
        let previous_public = write_temp_secret_file(
            "jwt_rotate_previous_public",
            TEST_ED25519_PUBLIC_KEY_PREVIOUS,
        );

        let previous_settings = AuthSettings {
            jwt: Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: Some("previous".to_owned()),
                signing_key: SecretRef::File {
                    path: previous_private.clone(),
                },
                verification_keys: vec![AuthJwtVerificationKey {
                    kid: "previous".to_owned(),
                    key: SecretRef::File {
                        path: previous_public.clone(),
                    },
                }],
            }),
            jwt_secret: None,
            ..AuthSettings::default()
        };
        let rotated_settings = AuthSettings {
            jwt: Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: Some("current".to_owned()),
                signing_key: SecretRef::File {
                    path: current_private.clone(),
                },
                verification_keys: vec![
                    AuthJwtVerificationKey {
                        kid: "current".to_owned(),
                        key: SecretRef::File {
                            path: current_public.clone(),
                        },
                    },
                    AuthJwtVerificationKey {
                        kid: "previous".to_owned(),
                        key: SecretRef::File {
                            path: previous_public.clone(),
                        },
                    },
                ],
            }),
            jwt_secret: None,
            ..AuthSettings::default()
        };

        let claims = Claims {
            sub: 7,
            roles: vec!["admin".to_owned()],
            iss: None,
            aud: None,
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            extra: BTreeMap::new(),
        };

        let (header, encoding_key) = super::configured_jwt_signer(&previous_settings)
            .expect("previous jwt signer should resolve");
        let token =
            encode(&header, &claims, encoding_key.as_ref()).expect("rotated jwt should encode");

        let context = super::decode_user_context_token(&token, &rotated_settings)
            .expect("old token should decode after rotation");
        assert_eq!(context.id, 7);
        assert_eq!(context.roles, vec!["admin".to_owned()]);

        for path in [
            current_private,
            current_public,
            previous_private,
            previous_public,
        ] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn configured_public_jwks_returns_eddsa_verification_keys() {
        let public_key =
            write_temp_secret_file("jwt_jwks_current_public", TEST_ED25519_PUBLIC_KEY_CURRENT);
        let settings = AuthSettings {
            jwt: Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: Some("current".to_owned()),
                signing_key: SecretRef::env_or_file("JWT_SIGNING_KEY"),
                verification_keys: vec![AuthJwtVerificationKey {
                    kid: "current".to_owned(),
                    key: SecretRef::File {
                        path: public_key.clone(),
                    },
                }],
            }),
            jwt_secret: None,
            ..AuthSettings::default()
        };

        let jwks = configured_public_jwks(&settings)
            .expect("jwks should resolve")
            .expect("jwks should be present");
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].common.key_id.as_deref(), Some("current"));
        assert_eq!(jwks.keys[0].common.key_algorithm, Some(KeyAlgorithm::EdDSA));
        match &jwks.keys[0].algorithm {
            AlgorithmParameters::OctetKeyPair(params) => {
                assert_eq!(params.curve, EllipticCurve::Ed25519);
                assert!(!params.x.is_empty());
                let decoding_key =
                    DecodingKey::from_jwk(&jwks.keys[0]).expect("returned jwk should decode");
                assert_eq!(decoding_key.as_bytes().len(), 32);
            }
            other => panic!("expected Ed25519 octet key pair, got {other:?}"),
        }

        let _ = std::fs::remove_file(public_key);
    }

    #[actix_web::test]
    async fn auth_routes_expose_public_jwks_for_asymmetric_jwt() {
        let public_key =
            write_temp_secret_file("jwt_jwks_route_public", TEST_ED25519_PUBLIC_KEY_CURRENT);
        let settings = AuthSettings {
            jwt: Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: Some("current".to_owned()),
                signing_key: SecretRef::env_or_file("JWT_SIGNING_KEY"),
                verification_keys: vec![AuthJwtVerificationKey {
                    kid: "current".to_owned(),
                    key: SecretRef::File {
                        path: public_key.clone(),
                    },
                }],
            }),
            jwt_secret: None,
            ..AuthSettings::default()
        };

        let app = init_service(
            App::new()
                .app_data(web::Data::new(settings))
                .route("/.well-known/jwks.json", web::get().to(super::jwks)),
        )
        .await;

        let response = call_service(
            &app,
            TestRequest::get()
                .uri("/.well-known/jwks.json")
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = read_body_json(response).await;
        assert_eq!(body["keys"][0]["kid"], "current");
        assert_eq!(body["keys"][0]["alg"], "EdDSA");
        assert_eq!(body["keys"][0]["kty"], "OKP");
        assert_eq!(body["keys"][0]["crv"], "Ed25519");
        assert!(body["keys"][0]["x"].is_string());

        let _ = std::fs::remove_file(public_key);
    }

    #[test]
    fn public_auth_url_uses_request_scope_with_public_base_url() {
        let settings = AuthSettings {
            email: Some(AuthEmailSettings {
                from_email: "noreply@example.com".to_owned(),
                from_name: Some("VSR".to_owned()),
                reply_to: None,
                public_base_url: Some("https://app.example".to_owned()),
                provider: AuthEmailProvider::Resend {
                    api_key: SecretRef::env_or_file("RESEND_API_KEY"),
                    api_base_url: None,
                },
            }),
            ..AuthSettings::default()
        };
        let request = TestRequest::with_uri("/api/auth/password-reset/request").to_http_request();

        let url = build_public_auth_url(
            Some(&request),
            &settings,
            "/auth/password-reset",
            Some("/auth/password-reset/request"),
            &[("token", "abc123")],
        )
        .expect("password reset url should build");

        assert_eq!(
            url,
            "https://app.example/api/auth/password-reset?token=abc123"
        );
    }

    #[test]
    fn public_auth_url_does_not_duplicate_existing_scope_prefix() {
        let settings = AuthSettings {
            email: Some(AuthEmailSettings {
                from_email: "noreply@example.com".to_owned(),
                from_name: Some("VSR".to_owned()),
                reply_to: None,
                public_base_url: Some("https://app.example/app/api".to_owned()),
                provider: AuthEmailProvider::Resend {
                    api_key: SecretRef::env_or_file("RESEND_API_KEY"),
                    api_base_url: None,
                },
            }),
            ..AuthSettings::default()
        };
        let request = TestRequest::with_uri("/api/auth/verify-email").to_http_request();

        let url = build_public_auth_url(
            Some(&request),
            &settings,
            "/auth/verify-email",
            Some("/auth/verify-email"),
            &[("token", "xyz")],
        )
        .expect("verification url should build");

        assert_eq!(
            url,
            "https://app.example/app/api/auth/verify-email?token=xyz"
        );
    }

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    #[actix_web::test]
    async fn ensure_admin_exists_inserts_detected_claim_columns_from_environment() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());

        unsafe {
            std::env::set_var("ADMIN_EMAIL", "admin@example.com");
            std::env::set_var("ADMIN_PASSWORD", "password123");
            std::env::set_var("ADMIN_TENANT_ID", "7");
            std::env::set_var("ADMIN_CLAIM_WORKSPACE_ID", "42");
        }

        let pool = connect_test_pool("ensure_admin_claims").await;

        query(
            "CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_id INTEGER,
                claim_workspace_id INTEGER
            )",
        )
        .execute(&pool)
        .await
        .expect("user table should be created");

        let created = ensure_admin_exists_with_settings_and_claim_prompt_mode(
            &pool,
            &AuthSettings::default(),
            false,
        )
        .await
        .expect("ensure_admin_exists should not error");
        assert!(created);

        let row = query("SELECT tenant_id, claim_workspace_id FROM user WHERE role = 'admin'")
            .fetch_one(&pool)
            .await
            .expect("admin row should exist");
        let tenant_id: Option<i64> = row.try_get("tenant_id").expect("tenant_id should decode");
        let workspace_id: Option<i64> = row
            .try_get("claim_workspace_id")
            .expect("workspace claim should decode");
        assert_eq!(tenant_id, Some(7));
        assert_eq!(workspace_id, Some(42));

        unsafe {
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
            std::env::remove_var("ADMIN_TENANT_ID");
            std::env::remove_var("ADMIN_CLAIM_WORKSPACE_ID");
        }
    }

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    #[actix_web::test]
    async fn ensure_admin_exists_returns_false_when_required_claim_is_missing() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());

        unsafe {
            std::env::set_var("ADMIN_EMAIL", "admin@example.com");
            std::env::set_var("ADMIN_PASSWORD", "password123");
            std::env::remove_var("ADMIN_TENANT_ID");
        }

        let pool = connect_test_pool("ensure_admin_required_claim").await;

        query(
            "CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_id INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("user table should be created");

        let created = ensure_admin_exists_with_settings_and_claim_prompt_mode(
            &pool,
            &AuthSettings::default(),
            false,
        )
        .await
        .expect("ensure_admin_exists should not error");
        assert!(!created);

        let count: i64 = query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM user")
            .fetch_one(&pool)
            .await
            .expect("row count should be queryable");
        assert_eq!(count, 0);

        unsafe {
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
        }
    }

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    #[actix_web::test]
    async fn login_treats_null_management_fields_as_unverified_when_schema_exists() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var("JWT_SECRET", "auth-management-test-secret");
        }

        let pool = connect_test_pool("management_nulls").await;

        for statement in auth_migration_sql(AuthDbBackend::Sqlite)
            .split(';')
            .map(str::trim)
            .filter(|statement| !statement.is_empty())
        {
            query(statement)
                .execute(&pool)
                .await
                .expect("auth schema should apply");
        }
        for statement in auth_management_migration_sql(AuthDbBackend::Sqlite)
            .split(';')
            .map(str::trim)
            .filter(|statement| !statement.is_empty())
        {
            query(statement)
                .execute(&pool)
                .await
                .expect("auth management schema should apply");
        }

        let password_hash =
            super::hash("password123", 12).expect("password hash should be created");
        query("INSERT INTO user (email, password_hash, role) VALUES (?, ?, ?)")
            .bind("nulls@example.com")
            .bind(password_hash)
            .bind("user")
            .execute(&pool)
            .await
            .expect("user row should insert");

        let response = login_with_settings(
            web::Json(LoginInput {
                email: "nulls@example.com".to_owned(),
                password: "password123".to_owned(),
            }),
            web::Data::new(pool),
            AuthSettings {
                require_email_verification: true,
                ..AuthSettings::default()
            },
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body())
            .await
            .expect("response body should be readable");
        let body = String::from_utf8(body.to_vec()).expect("response should be valid utf-8");
        assert!(
            body.contains("\"email_not_verified\""),
            "unexpected body: {body}"
        );
    }

    #[cfg(feature = "turso-local")]
    #[actix_web::test]
    async fn ensure_admin_exists_works_with_encrypted_turso_local() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("vsr_auth_encrypted_{stamp}.db"));
        let env_var = format!("VSR_AUTH_TURSO_KEY_{stamp}");
        let key = "c1bbfda4f589dc9daaf004fe21111e00dc00c98237102f5c7002a5669fc76327";

        unsafe {
            std::env::set_var("ADMIN_EMAIL", "encrypted-admin@example.com");
            std::env::set_var("ADMIN_PASSWORD", "password123");
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
            .expect("database should connect");

        for statement in auth_migration_sql(AuthDbBackend::Sqlite)
            .split(';')
            .map(str::trim)
            .filter(|statement| !statement.is_empty())
        {
            query(statement)
                .execute(&pool)
                .await
                .expect("auth schema should apply");
        }

        let created = ensure_admin_exists_with_settings_and_claim_prompt_mode(
            &pool,
            &AuthSettings::default(),
            false,
        )
        .await
        .expect("ensure_admin_exists should not error");
        assert!(created);

        let count: i64 =
            query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM user WHERE role = 'admin'")
                .fetch_one(&pool)
                .await
                .expect("admin row should be queryable");
        assert_eq!(count, 1);

        unsafe {
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
            std::env::remove_var(&env_var);
        }
        let _ = std::fs::remove_file(path);
    }

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    #[actix_web::test]
    async fn ensure_admin_exists_uses_explicit_auth_claim_mappings() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());

        unsafe {
            std::env::set_var("ADMIN_EMAIL", "admin@example.com");
            std::env::set_var("ADMIN_PASSWORD", "password123");
            std::env::set_var("ADMIN_TENANT_SCOPE", "7");
            std::env::set_var("ADMIN_CLAIM_WORKSPACE_ID", "42");
            std::env::set_var("ADMIN_IS_STAFF", "true");
            std::env::set_var("ADMIN_PLAN", "pro");
        }

        let pool = connect_test_pool("ensure_admin_explicit_claims").await;

        query(
            "CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_scope INTEGER NOT NULL,
                claim_workspace_id INTEGER,
                is_staff BOOLEAN NOT NULL,
                plan TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("user table should be created");

        let settings = AuthSettings {
            claims: BTreeMap::from([
                (
                    "tenant_id".to_owned(),
                    AuthClaimMapping {
                        column: "tenant_scope".to_owned(),
                        ty: AuthClaimType::I64,
                    },
                ),
                (
                    "workspace_id".to_owned(),
                    AuthClaimMapping {
                        column: "claim_workspace_id".to_owned(),
                        ty: AuthClaimType::I64,
                    },
                ),
                (
                    "staff".to_owned(),
                    AuthClaimMapping {
                        column: "is_staff".to_owned(),
                        ty: AuthClaimType::Bool,
                    },
                ),
                (
                    "plan".to_owned(),
                    AuthClaimMapping {
                        column: "plan".to_owned(),
                        ty: AuthClaimType::String,
                    },
                ),
            ]),
            ..AuthSettings::default()
        };

        let created =
            ensure_admin_exists_with_settings_and_claim_prompt_mode(&pool, &settings, false)
                .await
                .expect("ensure_admin_exists should not error");
        assert!(created);

        let row = query(
            "SELECT tenant_scope, claim_workspace_id, CAST(is_staff AS INTEGER) AS is_staff_value, plan \
             FROM user WHERE role = 'admin'",
        )
        .fetch_one(&pool)
        .await
        .expect("admin row should exist");
        let tenant_scope: i64 = row
            .try_get("tenant_scope")
            .expect("tenant scope should decode");
        let workspace_id: Option<i64> = row
            .try_get("claim_workspace_id")
            .expect("workspace claim should decode");
        let is_staff: i64 = row
            .try_get("is_staff_value")
            .expect("is_staff should decode");
        let plan: String = row.try_get("plan").expect("plan should decode");
        assert_eq!(tenant_scope, 7);
        assert_eq!(workspace_id, Some(42));
        assert_eq!(is_staff, 1);
        assert_eq!(plan, "pro");

        unsafe {
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
            std::env::remove_var("ADMIN_TENANT_SCOPE");
            std::env::remove_var("ADMIN_CLAIM_WORKSPACE_ID");
            std::env::remove_var("ADMIN_IS_STAFF");
            std::env::remove_var("ADMIN_PLAN");
        }
    }

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    #[actix_web::test]
    async fn validate_auth_claim_mappings_rejects_mismatched_column_types() {
        let pool = connect_test_pool("validate_auth_claims").await;

        query(
            "CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_scope INTEGER NOT NULL,
                is_staff TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("user table should be created");

        let settings = AuthSettings {
            claims: BTreeMap::from([
                (
                    "tenant_id".to_owned(),
                    AuthClaimMapping {
                        column: "tenant_scope".to_owned(),
                        ty: AuthClaimType::I64,
                    },
                ),
                (
                    "staff".to_owned(),
                    AuthClaimMapping {
                        column: "is_staff".to_owned(),
                        ty: AuthClaimType::Bool,
                    },
                ),
            ]),
            ..AuthSettings::default()
        };

        let error = validate_auth_claim_mappings(&pool, &settings)
            .await
            .expect_err("mismatched claim type should fail");
        assert!(error.contains("security.auth.claims.staff"));
        assert!(error.contains("is_staff"));
    }
}
