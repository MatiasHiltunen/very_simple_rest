use actix_web::dev::Payload;
use actix_web::{
    FromRequest, HttpRequest,
    cookie::{Cookie, SameSite, time::Duration as CookieDuration},
    http::Method,
};
use actix_web::{HttpResponse, Responder, web};
use bcrypt::{hash, verify};
use chrono::{Duration, SecondsFormat, Utc};
use dotenv::dotenv;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::distr::{Alphanumeric, SampleString};
use rand::rng;
use rpassword;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Column, FromRow, Row, any::AnyRow};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::{Ready, ready};
use std::io::{IsTerminal, Write, stdin, stdout};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration as StdDuration, Instant};

use crate::{
    db::{DbPool, query, query_scalar},
    email::{AuthEmailMessage, send_auth_email},
    errors,
    secret::load_secret_from_env_or_file,
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
    pub session_cookie: Option<SessionCookieSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<AuthEmailSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portal: Option<AuthUiPageSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_dashboard: Option<AuthUiPageSettings>,
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
        api_key_env: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_base_url: Option<String>,
    },
    Smtp {
        connection_url_env: String,
    },
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

pub fn auth_migration_sql(backend: AuthDbBackend) -> String {
    format!(
        "-- Generated by very_simple_rest for built-in auth.\n\n\
         CREATE TABLE user (\n\
             {},\n\
             {},\n\
             {},\n\
             {}\n\
         );\n\n\
         CREATE INDEX idx_user_role ON user (role);\n",
        backend.id_column_sql(),
        backend.email_column_sql(),
        backend.password_hash_column_sql(),
        backend.role_column_sql()
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

    format!(
        "-- Generated by very_simple_rest for built-in auth management.\n\n\
         ALTER TABLE user ADD COLUMN {email_verified_at};\n\
         ALTER TABLE user ADD COLUMN {created_at};\n\
         ALTER TABLE user ADD COLUMN {updated_at};\n\
         UPDATE user SET created_at = {now} WHERE created_at IS NULL;\n\
         UPDATE user SET updated_at = COALESCE(updated_at, created_at, {now}) WHERE updated_at IS NULL;\n\n\
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
        fk_name = backend.quote_ident("fk_auth_user_token_user"),
        quoted_user_id = backend.quote_ident("user_id"),
        quoted_user = backend.quote_ident("user"),
        quoted_user_pk = backend.quote_ident("id"),
    )
}

fn load_jwt_secret_from_env() -> Result<Vec<u8>, String> {
    let _ = dotenv();

    load_secret_from_env_or_file("JWT_SECRET", "JWT secret")
        .map(String::into_bytes)
        .map_err(|_| {
            "JWT_SECRET or JWT_SECRET_FILE must be set when built-in auth is enabled".to_owned()
        })
}

fn configured_jwt_secret() -> Result<&'static [u8], &'static str> {
    static JWT_SECRET: OnceLock<Result<Vec<u8>, String>> = OnceLock::new();

    match JWT_SECRET.get_or_init(load_jwt_secret_from_env) {
        Ok(secret) => Ok(secret.as_slice()),
        Err(message) => Err(message.as_str()),
    }
}

pub fn ensure_jwt_secret_configured() -> Result<(), String> {
    configured_jwt_secret()
        .map(|_| ())
        .map_err(ToOwned::to_owned)
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
    let jwt_secret = configured_jwt_secret().map_err(actix_web::error::ErrorInternalServerError)?;
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret),
        &validation_for_settings(settings),
    )
    .map_err(|_| {
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
pub struct UpdateManagedUserInput {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
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
    let mut base = if let Some(public_base_url) = settings
        .email
        .as_ref()
        .and_then(|email| email.public_base_url.clone())
    {
        public_base_url.trim_end_matches('/').to_owned()
    } else if let Some(req) = req {
        let info = req.connection_info();
        let scope_prefix = scope_prefix_from_request(req, current_route_path);
        format!(
            "{}://{}{}",
            info.scheme(),
            info.host(),
            scope_prefix.trim_end_matches('/')
        )
    } else {
        return Err(
            "security.auth.email.public_base_url is required when auth emails are sent outside an HTTP request context"
                .to_owned(),
        );
    };

    if !base.ends_with('/') {
        base.push('/');
    }
    base.push_str(auth_path.trim_start_matches('/'));

    if !query_pairs.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in query_pairs {
            serializer.append_pair(key, value);
        }
        base.push('?');
        base.push_str(&serializer.finish());
    }

    Ok(base)
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

fn authenticated_user_from_row(row: &AnyRow) -> Result<AuthenticatedUser, sqlx::Error> {
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
        claims: collect_user_claims(row)?,
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
    let result = query("INSERT INTO user (email, password_hash, role) VALUES (?, ?, ?)")
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

    let user = match load_authenticated_user_by_email(&tx, &email).await {
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
    if let Err(error) = initialize_user_management_timestamps(&tx, user.id, &now).await {
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
    } else if let Err(error) = mark_user_email_verified(&tx, user.id, &now).await
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
    let user = match load_authenticated_user_by_email(db.get_ref(), &email).await {
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
        let jwt_secret = match configured_jwt_secret() {
            Ok(secret) => secret,
            Err(message) => return errors::internal_error(message),
        };

        match encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret),
        ) {
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

async fn load_authenticated_user_by_email<E>(
    db: &E,
    email: &str,
) -> Result<Option<AuthenticatedUser>, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let row = query("SELECT * FROM user WHERE email = ?")
        .bind(email)
        .fetch_optional(db)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    authenticated_user_from_row(&row).map(Some)
}

fn collect_user_claims(row: &AnyRow) -> Result<BTreeMap<String, Value>, sqlx::Error> {
    let mut claims = BTreeMap::new();

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

async fn load_authenticated_user_by_id<E>(
    db: &E,
    user_id: i64,
) -> Result<Option<AuthenticatedUser>, sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    let row = query("SELECT * FROM user WHERE id = ?")
        .bind(user_id)
        .fetch_optional(db)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    authenticated_user_from_row(&row).map(Some)
}

async fn list_authenticated_users(
    db: &DbPool,
    limit: u32,
    offset: u32,
    email_filter: Option<&str>,
) -> Result<Vec<AccountInfo>, sqlx::Error> {
    let rows = if let Some(email_filter) = email_filter {
        query("SELECT * FROM user WHERE email LIKE ? ORDER BY id LIMIT ? OFFSET ?")
            .bind(format!("%{email_filter}%"))
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(db)
            .await?
    } else {
        query("SELECT * FROM user ORDER BY id LIMIT ? OFFSET ?")
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(db)
            .await?
    };

    rows.into_iter()
        .map(|row| authenticated_user_from_row(&row).map(account_info_from_user))
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
    user_id: i64,
    verified_at: &str,
) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query("UPDATE user SET email_verified_at = ?, updated_at = ? WHERE id = ?")
        .bind(verified_at)
        .bind(verified_at)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

async fn initialize_user_management_timestamps<E>(
    db: &E,
    user_id: i64,
    timestamp: &str,
) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query("UPDATE user SET created_at = COALESCE(created_at, ?), updated_at = COALESCE(updated_at, ?) WHERE id = ?")
        .bind(timestamp)
        .bind(timestamp)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

async fn update_user_password<E>(
    db: &E,
    user_id: i64,
    password_hash: &str,
    updated_at: &str,
) -> Result<(), sqlx::Error>
where
    E: crate::db::DbExecutor + ?Sized,
{
    query("UPDATE user SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(password_hash)
        .bind(updated_at)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

async fn update_managed_user_row(
    db: &DbPool,
    user_id: i64,
    input: &UpdateManagedUserInput,
    updated_at: &str,
) -> Result<bool, sqlx::Error> {
    let role = input
        .role
        .as_ref()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let set_verified = input.email_verified == Some(true);
    let clear_verified = input.email_verified == Some(false);
    let should_update = role.is_some() || input.email_verified.is_some();

    let result = query(
        "UPDATE user \
         SET role = CASE WHEN ? THEN ? ELSE role END, \
             email_verified_at = CASE WHEN ? THEN ? WHEN ? THEN NULL ELSE email_verified_at END, \
             updated_at = CASE WHEN ? THEN ? ELSE updated_at END \
         WHERE id = ?",
    )
    .bind(role.is_some())
    .bind(role.unwrap_or_default())
    .bind(set_verified)
    .bind(updated_at)
    .bind(clear_verified)
    .bind(should_update)
    .bind(updated_at)
    .bind(user_id)
    .execute(db)
    .await?;

    Ok(result.rows_affected() != 0)
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
    mark_user_email_verified(&tx, token.user_id, &now).await?;
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
    update_user_password(&tx, token.user_id, password_hash, &now).await?;
    mark_auth_token_used(&tx, token.id, &now).await?;
    delete_auth_tokens_for_user_purpose(&tx, token.user_id, AuthTokenPurpose::PasswordReset)
        .await?;
    tx.commit().await?;
    Ok(TokenActionOutcome::Applied)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AdminClaimColumn {
    column_name: String,
    env_var: String,
    required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AdminClaimValue {
    column_name: String,
    value: i64,
}

async fn detect_auth_backend(pool: &DbPool) -> Result<AuthDbBackend, sqlx::Error> {
    match pool {
        DbPool::Sqlx(pool) => {
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

async fn discover_admin_claim_columns(
    pool: &DbPool,
    backend: AuthDbBackend,
) -> Result<Vec<AdminClaimColumn>, sqlx::Error> {
    let rows = match backend {
        AuthDbBackend::Sqlite => query("PRAGMA table_info('user')").fetch_all(pool).await?,
        AuthDbBackend::Postgres => {
            query(
                "SELECT column_name, data_type, is_nullable, column_default \
             FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'user' \
             ORDER BY ordinal_position",
            )
            .fetch_all(pool)
            .await?
        }
        AuthDbBackend::Mysql => {
            query(
                "SELECT column_name, data_type, is_nullable, column_default \
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
        let Some(metadata) = admin_claim_column_from_row(&row, backend)? else {
            continue;
        };
        columns.push(metadata);
    }

    Ok(columns)
}

fn admin_claim_column_from_row(
    row: &AnyRow,
    backend: AuthDbBackend,
) -> Result<Option<AdminClaimColumn>, sqlx::Error> {
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

    if !is_admin_claim_column_name(&column_name) || !is_integer_claim_type(&data_type) {
        return Ok(None);
    }

    Ok(Some(AdminClaimColumn {
        env_var: admin_claim_env_var(&column_name),
        column_name,
        required,
    }))
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
            values.push(AdminClaimValue {
                column_name: column.column_name.clone(),
                value,
            });
            continue;
        }

        if interactive {
            if let Some(value) = prompt_admin_claim_value(column)? {
                values.push(AdminClaimValue {
                    column_name: column.column_name.clone(),
                    value,
                });
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

fn claim_value_from_env(column: &AdminClaimColumn) -> Result<Option<i64>, String> {
    match std::env::var(&column.env_var) {
        Ok(raw) if raw.trim().is_empty() => Ok(None),
        Ok(raw) => raw.trim().parse::<i64>().map(Some).map_err(|_| {
            format!(
                "Environment variable {} must be a valid integer",
                column.env_var
            )
        }),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(format!(
            "Failed to read environment variable {}: {}",
            column.env_var, error
        )),
    }
}

fn prompt_admin_claim_value(column: &AdminClaimColumn) -> Result<Option<i64>, String> {
    let prompt = if column.required {
        format!("{} (required admin claim column): ", column.column_name)
    } else {
        format!(
            "{} (optional admin claim column, press Enter to skip): ",
            column.column_name
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

    value
        .parse::<i64>()
        .map(Some)
        .map_err(|_| format!("{} must be a valid integer", column.column_name))
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
            .map(|claim| claim.column_name.clone())
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
        insert_query = insert_query.bind(claim.value);
    }
    insert_query.execute(pool).await?;
    let verified_at = now_timestamp_string();
    if let Err(error) = query("UPDATE user SET created_at = COALESCE(created_at, ?), email_verified_at = ?, updated_at = ? WHERE email = ?")
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

pub async fn account(user: UserContext, db: web::Data<DbPool>) -> impl Responder {
    match load_authenticated_user_by_id(db.get_ref(), user.id).await {
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

    match update_user_password(db.get_ref(), user.id, &password_hash, &now).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(error) if is_missing_auth_management_schema(&error) => {
            match query("UPDATE user SET password_hash = ? WHERE id = ?")
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
    let user = match load_authenticated_user_by_email(db.get_ref(), &email).await {
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

    let account = match load_authenticated_user_by_id(db.get_ref(), user.id).await {
        Ok(Some(account)) => account,
        Ok(None) => return errors::unauthorized("invalid_token", "Authenticated user not found"),
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
    let user = match load_authenticated_user_by_email(db.get_ref(), &email).await {
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

pub async fn list_managed_users(
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

    match list_authenticated_users(db.get_ref(), limit, offset, email_filter).await {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({
            "items": items,
            "limit": limit,
            "offset": offset,
        })),
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn managed_user(
    user: UserContext,
    path: web::Path<i64>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    match load_authenticated_user_by_id(db.get_ref(), path.into_inner()).await {
        Ok(Some(user)) => HttpResponse::Ok().json(account_info_from_user(user)),
        Ok(None) => errors::not_found("User not found"),
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn update_managed_user(
    user: UserContext,
    path: web::Path<i64>,
    input: web::Json<UpdateManagedUserInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }
    if input.role.is_none() && input.email_verified.is_none() {
        return errors::bad_request(
            "missing_changes",
            "Provide `role` and/or `email_verified` to update the user",
        );
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
    match update_managed_user_row(db.get_ref(), user_id, &input, &now).await {
        Ok(true) => match load_authenticated_user_by_id(db.get_ref(), user_id).await {
            Ok(Some(user)) => HttpResponse::Ok().json(account_info_from_user(user)),
            Ok(None) => errors::not_found("User not found"),
            Err(_) => errors::internal_error("Database error"),
        },
        Ok(false) => errors::not_found("User not found"),
        Err(error) if is_missing_auth_management_schema(&error) => {
            missing_auth_management_schema_response()
        }
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

    let Some(account) = (match load_authenticated_user_by_id(db.get_ref(), path.into_inner()).await
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
    let body = "<section class=\"panel\"><h2>Session</h2><label>Optional bearer token</label><input id=\"bearer-token\" type=\"text\" placeholder=\"Paste a bearer token if you are not using cookies\"><button id=\"refresh-account\" type=\"button\">Refresh account</button><pre id=\"account-state\">Loading account…</pre></section><section class=\"panel\"><h2>Change Password</h2><form id=\"change-password-form\"><label>Current password</label><input id=\"current-password\" type=\"password\" autocomplete=\"current-password\" required><label>New password</label><input id=\"next-password\" type=\"password\" autocomplete=\"new-password\" required><button type=\"submit\">Update password</button></form><p id=\"password-result\" class=\"muted\"></p></section><section class=\"panel\"><h2>Verification</h2><p class=\"muted\">If your email is still unverified, send another verification link.</p><button id=\"resend-verification\" type=\"button\">Send verification email</button><button id=\"logout-button\" type=\"button\">Log out</button><p id=\"verification-result\" class=\"muted\"></p></section>";
    let script = format!(
        "const authBase = {auth_base:?};\n\
         const csrfCookieName = {csrf_cookie_name:?};\n\
         const csrfHeaderName = {csrf_header_name:?};\n\
         function bearerToken() {{ return document.getElementById('bearer-token').value.trim(); }}\n\
         function csrfToken() {{ const match = document.cookie.match(new RegExp(`(?:^|; )${{csrfCookieName.replace(/[.*+?^${{}}()|[\\]\\\\]/g, '\\\\$&')}}=([^;]*)`)); return match ? decodeURIComponent(match[1]) : ''; }}\n\
         async function api(path, options = {{}}) {{\n\
             const headers = new Headers(options.headers || {{}});\n\
             const token = bearerToken();\n\
             if (token) headers.set('Authorization', `Bearer ${{token}}`);\n\
             const method = (options.method || 'GET').toUpperCase();\n\
             if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {{\n\
                 const csrf = csrfToken();\n\
                 if (csrf) headers.set(csrfHeaderName, csrf);\n\
             }}\n\
             const response = await fetch(`${{authBase}}/${{path}}`, {{ ...options, headers, credentials: 'include' }});\n\
             return response;\n\
         }}\n\
         async function refreshAccount() {{\n\
             const target = document.getElementById('account-state');\n\
             const response = await api('account');\n\
             const text = await response.text();\n\
             try {{ target.textContent = JSON.stringify(JSON.parse(text), null, 2); }} catch {{ target.textContent = text; }}\n\
         }}\n\
         document.getElementById('refresh-account').addEventListener('click', refreshAccount);\n\
         document.getElementById('change-password-form').addEventListener('submit', async (event) => {{\n\
             event.preventDefault();\n\
             const payload = {{ current_password: document.getElementById('current-password').value, new_password: document.getElementById('next-password').value }};\n\
             const response = await api('account/password', {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify(payload) }});\n\
             document.getElementById('password-result').textContent = response.ok ? 'Password updated.' : (await response.text());\n\
         }});\n\
         document.getElementById('resend-verification').addEventListener('click', async () => {{\n\
             const response = await api('account/verification', {{ method: 'POST' }});\n\
             document.getElementById('verification-result').textContent = response.ok ? 'Verification email sent.' : (await response.text());\n\
         }});\n\
         document.getElementById('logout-button').addEventListener('click', async () => {{\n\
             const response = await api('logout', {{ method: 'POST' }});\n\
             document.getElementById('verification-result').textContent = response.ok ? 'Logged out.' : (await response.text());\n\
         }});\n\
         refreshAccount();"
    );
    render_shell(title, "Built-in account management", body, &script)
}

fn render_admin_dashboard_page(
    title: &str,
    auth_base: &str,
    csrf_cookie_name: &str,
    csrf_header_name: &str,
) -> String {
    let body = "<section class=\"panel\"><h2>Admin Session</h2><label>Optional bearer token</label><input id=\"bearer-token\" type=\"text\" placeholder=\"Paste a bearer token if you are not using cookies\"><button id=\"load-users\" type=\"button\">Load users</button><p class=\"muted\">Use role updates and resend verification directly from the list.</p></section><section class=\"panel wide\"><h2>User Directory</h2><div id=\"user-list\" class=\"user-list\"></div></section>";
    let script = format!(
        "const authBase = {auth_base:?};\n\
         const csrfCookieName = {csrf_cookie_name:?};\n\
         const csrfHeaderName = {csrf_header_name:?};\n\
         function bearerToken() {{ return document.getElementById('bearer-token').value.trim(); }}\n\
         function csrfToken() {{ const match = document.cookie.match(new RegExp(`(?:^|; )${{csrfCookieName.replace(/[.*+?^${{}}()|[\\]\\\\]/g, '\\\\$&')}}=([^;]*)`)); return match ? decodeURIComponent(match[1]) : ''; }}\n\
         async function api(path, options = {{}}) {{\n\
             const headers = new Headers(options.headers || {{}});\n\
             const token = bearerToken();\n\
             if (token) headers.set('Authorization', `Bearer ${{token}}`);\n\
             const method = (options.method || 'GET').toUpperCase();\n\
             if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {{ const csrf = csrfToken(); if (csrf) headers.set(csrfHeaderName, csrf); }}\n\
             return fetch(`${{authBase}}/${{path}}`, {{ ...options, headers, credentials: 'include' }});\n\
         }}\n\
         async function loadUsers() {{\n\
             const response = await api('admin/users');\n\
             const container = document.getElementById('user-list');\n\
             if (!response.ok) {{ container.textContent = await response.text(); return; }}\n\
             const payload = await response.json();\n\
             const items = payload.items || [];\n\
             container.innerHTML = items.map((item) => `<article class=\"user-card\"><header><strong>${{item.email}}</strong><span>${{item.role}}</span></header><pre>${{JSON.stringify(item, null, 2)}}</pre><div class=\"actions\"><button data-action=\"verify\" data-id=\"${{item.id}}\">Resend verification</button><button data-action=\"role\" data-id=\"${{item.id}}\">Change role</button></div></article>`).join('');\n\
         }}\n\
         document.getElementById('load-users').addEventListener('click', loadUsers);\n\
         document.getElementById('user-list').addEventListener('click', async (event) => {{\n\
             const button = event.target.closest('button');\n\
             if (!button) return;\n\
             const id = button.dataset.id;\n\
             if (button.dataset.action === 'verify') {{\n\
                 const response = await api(`admin/users/${{id}}/verification`, {{ method: 'POST' }});\n\
                 button.textContent = response.ok ? 'Verification sent' : 'Failed';\n\
                 return;\n\
             }}\n\
             if (button.dataset.action === 'role') {{\n\
                 const role = prompt('New role for user #' + id);\n\
                 if (!role) return;\n\
                 await api(`admin/users/${{id}}`, {{ method: 'PATCH', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ role }}) }});\n\
                 loadUsers();\n\
             }}\n\
         }});\n\
         loadUsers();"
    );
    render_shell(title, "Built-in admin account management", body, &script)
}

fn render_shell(title: &str, subtitle: &str, body: &str, script: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title><style>:root{{--bg:#f6f1e8;--bg2:#efe4cf;--card:#fffaf2;--ink:#1f1a14;--muted:#6b6257;--accent:#b85c38;--accent2:#244c43;--border:#d6c7b1;}}*{{box-sizing:border-box}}body{{margin:0;font-family:ui-sans-serif,system-ui,sans-serif;color:var(--ink);background:radial-gradient(circle at top left,var(--bg2),var(--bg));min-height:100vh}}main{{max-width:1100px;margin:0 auto;padding:40px 20px 56px}}header.hero{{display:grid;gap:8px;margin-bottom:24px}}header.hero h1{{margin:0;font-size:clamp(2.2rem,5vw,4rem);letter-spacing:-0.04em}}header.hero p{{margin:0;color:var(--muted);max-width:60ch}}section.panel{{background:linear-gradient(180deg,rgba(255,255,255,.82),rgba(255,250,242,.95));border:1px solid var(--border);border-radius:24px;padding:20px;box-shadow:0 24px 60px rgba(31,26,20,.08)}}section.panel.single{{max-width:680px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}}.wide{{grid-column:1 / -1}}label{{display:block;font-size:.92rem;font-weight:700;margin:0 0 6px}}input,button,textarea{{font:inherit}}input{{width:100%;padding:12px 14px;border-radius:14px;border:1px solid var(--border);background:#fff}}button{{padding:12px 16px;border:none;border-radius:999px;background:var(--accent);color:white;font-weight:700;cursor:pointer}}button + button{{margin-left:8px;background:var(--accent2)}}form{{display:grid;gap:12px}}pre{{margin:0;padding:14px;border-radius:16px;background:#201a16;color:#f4efe6;overflow:auto;min-height:120px}}.muted{{color:var(--muted)}}.user-list{{display:grid;gap:12px}}.user-card{{border:1px solid var(--border);border-radius:18px;padding:14px;background:rgba(255,255,255,.72)}}.user-card header{{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:8px}}.actions{{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}}</style></head><body><main><header class=\"hero\"><h1>{}</h1><p>{}</p></header><div class=\"grid\">{}</div></main><script>{}</script></body></html>",
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
    ensure_admin_exists_with_claim_prompt_mode(
        pool,
        stdin().is_terminal() && stdout().is_terminal(),
    )
    .await
}

async fn ensure_admin_exists_with_claim_prompt_mode(
    pool: &DbPool,
    interactive_claims: bool,
) -> Result<bool, sqlx::Error> {
    // Check if any admin exists
    let count = match query_scalar::<sqlx::Any, i64>(
        "SELECT COUNT(*) FROM user WHERE role = 'admin'",
    )
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
    let claim_columns = match discover_admin_claim_columns(pool, backend).await {
        Ok(columns) => columns,
        Err(error) => {
            eprintln!("[ERROR] Failed to inspect auth schema: {}", error);
            return Err(error);
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
                    .map(|claim| format!("{}={}", claim.column_name, claim.value))
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

pub fn auth_routes_with_settings(
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
    cfg.route("/auth/admin/users/{id}", web::get().to(managed_user));
    cfg.route(
        "/auth/admin/users/{id}",
        web::patch().to(update_managed_user),
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

fn validation_for_settings(settings: &AuthSettings) -> Validation {
    let mut validation = Validation::default();
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
        AuthDbBackend, AuthSettings, LoginInput, auth_management_migration_sql, auth_migration_sql,
        ensure_admin_exists_with_claim_prompt_mode, load_jwt_secret_from_env, login_with_settings,
    };
    #[cfg(feature = "turso-local")]
    use crate::database::{DatabaseConfig, DatabaseEngine, TursoLocalConfig};
    #[cfg(feature = "turso-local")]
    use crate::db::connect_with_config;
    use crate::db::{connect, query, query_scalar};
    use actix_web::{body::to_bytes, http::StatusCode, web};
    use sqlx::Row;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_sqlite_url(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("vsr_auth_{prefix}_{nanos}.db"));
        format!("sqlite:{}?mode=rwc", path.display())
    }

    #[test]
    fn sqlite_auth_migration_uses_expected_schema() {
        let sql = auth_migration_sql(AuthDbBackend::Sqlite);
        assert!(sql.contains("CREATE TABLE user"));
        assert!(sql.contains("id INTEGER PRIMARY KEY AUTOINCREMENT"));
        assert!(sql.contains("email TEXT NOT NULL UNIQUE"));
        assert!(sql.contains("password_hash TEXT NOT NULL"));
        assert!(sql.contains("role TEXT NOT NULL"));
        assert!(sql.contains("CREATE INDEX idx_user_role ON user (role);"));
    }

    #[test]
    fn load_jwt_secret_from_env_requires_non_empty_secret() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::remove_var("JWT_SECRET");
            std::env::remove_var("JWT_SECRET_FILE");
        }

        let error = load_jwt_secret_from_env().expect_err("missing JWT secret should fail");
        assert!(error.contains("JWT_SECRET"));

        unsafe {
            std::env::set_var("JWT_SECRET", "");
        }

        let error = load_jwt_secret_from_env().expect_err("empty JWT secret should fail");
        assert!(error.contains("JWT_SECRET"));

        unsafe {
            std::env::remove_var("JWT_SECRET");
        }
    }

    #[test]
    fn load_jwt_secret_from_env_accepts_non_empty_secret() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var("JWT_SECRET", "unit-test-secret");
        }

        let secret = load_jwt_secret_from_env().expect("non-empty JWT secret should load");
        assert_eq!(secret, b"unit-test-secret");

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

        let secret = load_jwt_secret_from_env().expect("file-backed JWT secret should load");
        assert_eq!(secret, b"file-secret");

        unsafe {
            std::env::remove_var("JWT_SECRET_FILE");
        }
        let _ = std::fs::remove_file(path);
    }

    #[actix_web::test]
    async fn ensure_admin_exists_inserts_detected_claim_columns_from_environment() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());

        unsafe {
            std::env::set_var("ADMIN_EMAIL", "admin@example.com");
            std::env::set_var("ADMIN_PASSWORD", "password123");
            std::env::set_var("ADMIN_TENANT_ID", "7");
            std::env::set_var("ADMIN_CLAIM_WORKSPACE_ID", "42");
        }

        let database_url = unique_sqlite_url("ensure_admin_claims");
        let pool = connect(&database_url)
            .await
            .expect("database should connect");

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

        let created = ensure_admin_exists_with_claim_prompt_mode(&pool, false)
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

    #[actix_web::test]
    async fn ensure_admin_exists_returns_false_when_required_claim_is_missing() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());

        unsafe {
            std::env::set_var("ADMIN_EMAIL", "admin@example.com");
            std::env::set_var("ADMIN_PASSWORD", "password123");
            std::env::remove_var("ADMIN_TENANT_ID");
        }

        let database_url = unique_sqlite_url("ensure_admin_required_claim");
        let pool = connect(&database_url)
            .await
            .expect("database should connect");

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

        let created = ensure_admin_exists_with_claim_prompt_mode(&pool, false)
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

    #[actix_web::test]
    async fn login_treats_null_management_fields_as_unverified_when_schema_exists() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var("JWT_SECRET", "auth-management-test-secret");
        }

        let database_url = unique_sqlite_url("management_nulls");
        let pool = connect(&database_url)
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
                encryption_key_env: Some(env_var.clone()),
            }),
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

        let created = ensure_admin_exists_with_claim_prompt_mode(&pool, false)
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
}
