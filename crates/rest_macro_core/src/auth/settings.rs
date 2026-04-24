use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::secret::SecretRef;

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

    pub(crate) fn jsonwebtoken(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::Hs256 => jsonwebtoken::Algorithm::HS256,
            Self::Hs384 => jsonwebtoken::Algorithm::HS384,
            Self::Hs512 => jsonwebtoken::Algorithm::HS512,
            Self::Es256 => jsonwebtoken::Algorithm::ES256,
            Self::Es384 => jsonwebtoken::Algorithm::ES384,
            Self::EdDsa => jsonwebtoken::Algorithm::EdDSA,
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
