//! Serializable authentication configuration shared by native and emitted services.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config_secret::SecretRef;

/// Built-in authentication settings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthSettings {
    /// Expected JWT issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Expected JWT audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Access token lifetime in seconds.
    #[serde(default = "default_access_token_ttl_seconds")]
    pub access_token_ttl_seconds: i64,
    /// Whether accounts require verified email before login.
    #[serde(default)]
    pub require_email_verification: bool,
    /// Email verification token lifetime in seconds.
    #[serde(default = "default_verification_token_ttl_seconds")]
    pub verification_token_ttl_seconds: i64,
    /// Password reset token lifetime in seconds.
    #[serde(default = "default_password_reset_token_ttl_seconds")]
    pub password_reset_token_ttl_seconds: i64,
    /// Explicit JWT key configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<AuthJwtSettings>,
    /// Legacy JWT secret source.
    #[serde(
        default = "default_jwt_secret_ref",
        skip_serializing_if = "Option::is_none"
    )]
    pub jwt_secret: Option<SecretRef>,
    /// JWT claims mapped from account columns.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, AuthClaimMapping>,
    /// Optional session cookie settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_cookie: Option<SessionCookieSettings>,
    /// Optional transactional email settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<AuthEmailSettings>,
    /// Optional account portal page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portal: Option<AuthUiPageSettings>,
    /// Optional administrator dashboard page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_dashboard: Option<AuthUiPageSettings>,
}

/// Scalar type used when reading an account column into a JWT claim.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthClaimType {
    /// Signed 64-bit integer.
    #[default]
    I64,
    /// UTF-8 string.
    String,
    /// Boolean.
    Bool,
}

/// Mapping from an account column to a JWT claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthClaimMapping {
    /// Account column name.
    pub column: String,
    /// Expected claim scalar type.
    #[serde(default)]
    pub ty: AuthClaimType,
}

/// Transactional authentication email settings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthEmailSettings {
    /// Sender email address.
    pub from_email: String,
    /// Optional sender display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_name: Option<String>,
    /// Optional reply-to address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// Public origin used in email links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
    /// Delivery provider.
    pub provider: AuthEmailProvider,
}

/// Delivery provider for transactional authentication email.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthEmailProvider {
    /// Resend API delivery.
    Resend {
        /// API key source.
        api_key: SecretRef,
        /// Optional API base URL.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_base_url: Option<String>,
    },
    /// SMTP delivery.
    Smtp {
        /// SMTP connection URL source.
        connection_url: SecretRef,
    },
}

/// JWT signing algorithm supported by the legacy built-in auth service.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum AuthJwtAlgorithm {
    /// HMAC SHA-256.
    #[serde(rename = "HS256")]
    Hs256,
    /// HMAC SHA-384.
    #[serde(rename = "HS384")]
    Hs384,
    /// HMAC SHA-512.
    #[serde(rename = "HS512")]
    Hs512,
    /// ECDSA P-256 SHA-256.
    #[serde(rename = "ES256")]
    Es256,
    /// ECDSA P-384 SHA-384.
    #[serde(rename = "ES384")]
    Es384,
    /// Ed25519.
    #[default]
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl AuthJwtAlgorithm {
    /// Whether signing and verification use the same secret.
    pub fn is_symmetric(self) -> bool {
        matches!(self, Self::Hs256 | Self::Hs384 | Self::Hs512)
    }
}

/// Verification key used during JWT key rotation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthJwtVerificationKey {
    /// Key identifier from the token header.
    pub kid: String,
    /// Verification key source.
    pub key: SecretRef,
}

/// JWT signing and verification settings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthJwtSettings {
    /// Signing algorithm.
    #[serde(default)]
    pub algorithm: AuthJwtAlgorithm,
    /// Identifier of the active signing key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_kid: Option<String>,
    /// Current signing key source.
    pub signing_key: SecretRef,
    /// Additional keys accepted for verification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_keys: Vec<AuthJwtVerificationKey>,
}

/// Built-in authentication UI page settings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthUiPageSettings {
    /// URL path for the page.
    pub path: String,
    /// Browser page title.
    pub title: String,
}

/// SameSite policy for the session cookie.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCookieSameSite {
    /// Same-site and top-level navigation requests.
    Lax,
    /// Include cross-site requests.
    None,
    /// Same-site requests only.
    #[default]
    Strict,
}

/// Authentication session cookie and CSRF settings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionCookieSettings {
    /// Session cookie name.
    #[serde(default = "default_session_cookie_name")]
    pub name: String,
    /// CSRF cookie name.
    #[serde(default = "default_session_csrf_cookie_name")]
    pub csrf_cookie_name: String,
    /// CSRF request header name.
    #[serde(default = "default_session_csrf_header_name")]
    pub csrf_header_name: String,
    /// Cookie path.
    #[serde(default = "default_session_cookie_path")]
    pub path: String,
    /// Whether cookies require HTTPS.
    #[serde(default = "default_session_cookie_secure")]
    pub secure: bool,
    /// SameSite cookie policy.
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

/// Select the configured current signing secret.
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

#[cfg(test)]
mod tests {
    use super::{AuthSettings, SessionCookieSettings};

    #[test]
    fn default_settings_keep_the_legacy_secret_shape() {
        let settings = AuthSettings::default();
        let encoded = serde_json::to_value(&settings).unwrap();
        assert_eq!(
            encoded["jwt_secret"],
            serde_json::json!({"kind": "env_or_file", "var_name": "JWT_SECRET"})
        );
        assert_eq!(
            serde_json::from_value::<AuthSettings>(encoded).unwrap(),
            settings
        );
        assert_eq!(SessionCookieSettings::default().name, "vsr_session");
    }
}
