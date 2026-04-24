//! Authentication trait seams.
//!
//! The default implementation (`vsr-runtime::auth::builtin`) lives in
//! `rest_macro_core` today and migrates here during Phase 3. The traits
//! defined here are the stable public contract.
//!
//! # Key traits
//!
//! | Trait | Purpose |
//! |---|---|
//! | [`AuthProvider`] | Top-level: authenticate, issue, verify, revoke tokens |
//! | [`KeyProvider`] | JWT signing key rotation (KMS, file, Infisical) |
//! | [`PasswordPolicy`] | Pluggable password strength rules |
//! | [`Mailer`] | Send transactional email (OTP, verify, reset) |

use std::future::Future;
use vsr_core::error::VsrResult;

// ─── Identity model ───────────────────────────────────────────────────────────

/// The authenticated identity of a request principal.
///
/// This is the VSR-owned type that flows through every auth and authz seam.
/// No JWT library type appears at the boundary.
#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity {
    /// Stable user identifier (opaque string; typically a UUID).
    pub user_id: String,
    /// Email address, if known.
    pub email: Option<String>,
    /// Roles carried in the token at issue time.
    pub roles: Vec<String>,
    /// Custom claim values keyed by claim name.
    pub claims: std::collections::HashMap<String, serde_json::Value>,
    /// Whether this identity has platform-admin privileges.
    pub is_admin: bool,
    /// When this identity's token expires (Unix timestamp).
    pub expires_at: Option<i64>,
}

// ─── Credential types ─────────────────────────────────────────────────────────

/// Credentials presented by a client for authentication.
#[derive(Debug)]
#[non_exhaustive]
pub enum Credentials {
    /// Email + plaintext password (login flow).
    EmailPassword {
        /// User's email address.
        email: String,
        /// Plaintext password (never logged or stored).
        password: String,
    },
    /// A short-lived OTP sent via email.
    EmailOtp {
        /// User's email address.
        email: String,
        /// One-time password delivered by email.
        otp: String,
    },
    /// An opaque token from a previous session (refresh flow).
    RefreshToken(String),
}

/// The purpose a token was issued for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenPurpose {
    /// Regular session access token.
    Access,
    /// Long-lived refresh token.
    Refresh,
    /// Email verification link token.
    EmailVerification,
    /// Password reset link token.
    PasswordReset,
}

// ─── AuthProvider trait ───────────────────────────────────────────────────────

/// Top-level authentication contract.
///
/// The default implementation (`BuiltinAuthProvider`) lives in the VSR runtime
/// and uses JWT + bcrypt + SQLx. Operators can replace it with an OIDC bridge,
/// SSO adapter, or any other implementation.
///
/// # Contract
///
/// - Implementations MUST be `Send + Sync + 'static` so they can be held in
///   `Arc<dyn AuthProvider>` and shared across tokio tasks.
/// - All operations MUST NOT panic. Errors are always returned as
///   `Err(VsrError::*)`.
/// - Implementations MUST NOT log credential values (passwords, raw tokens).
pub trait AuthProvider: Send + Sync + 'static {
    /// Verify `credentials` and return the authenticated identity.
    ///
    /// Returns `Err(VsrError::Config)` if the provider is not configured,
    /// `Err(VsrError::Other)` for invalid credentials (do not leak *why*
    /// to the caller; log the reason internally with `tracing::debug!`).
    fn authenticate(
        &self,
        credentials: &Credentials,
    ) -> impl Future<Output = VsrResult<AuthenticatedIdentity>> + Send;

    /// Verify an opaque token string and return the identity it encodes.
    fn verify_token(
        &self,
        token: &str,
    ) -> impl Future<Output = VsrResult<AuthenticatedIdentity>> + Send;

    /// Issue a signed token for `identity` with the given `purpose`.
    fn issue_token(
        &self,
        identity: &AuthenticatedIdentity,
        purpose: TokenPurpose,
    ) -> impl Future<Output = VsrResult<String>> + Send;

    /// Revoke `token` (best-effort; some implementations use short-lived
    /// tokens and cannot revoke before expiry).
    fn revoke_token(&self, token: &str) -> impl Future<Output = VsrResult<()>> + Send;

    /// Initiate a password-reset flow for `email`. If the email is not
    /// registered, silently succeeds (do not leak account existence).
    fn request_password_reset(
        &self,
        email: &str,
    ) -> impl Future<Output = VsrResult<()>> + Send;

    /// Complete a password reset using a token issued by
    /// [`request_password_reset`](Self::request_password_reset).
    fn confirm_password_reset(
        &self,
        token: &str,
        new_password: &str,
    ) -> impl Future<Output = VsrResult<()>> + Send;
}

// ─── KeyProvider trait ────────────────────────────────────────────────────────

/// Provides JWT signing and verification keys.
///
/// Decoupled from [`AuthProvider`] so that key rotation (KMS, Infisical,
/// file rotation) can be swapped independently.
///
/// # Rotation model
///
/// `signing_key` returns the *current* key used to sign new tokens.
/// `verification_keys` returns *all currently valid* keys (current + recently
/// rotated). This allows old tokens to verify during a rotation window.
pub trait KeyProvider: Send + Sync + 'static {
    /// The algorithm used by this provider.
    fn algorithm(&self) -> JwtAlgorithm;

    /// Current signing key. Called once per token issue.
    fn signing_key(&self) -> impl Future<Output = VsrResult<SigningKey>> + Send;

    /// All valid verification keys. Called once per token verification.
    fn verification_keys(&self) -> impl Future<Output = VsrResult<Vec<VerificationKey>>> + Send;
}

/// JWT signing algorithm. Kept as a VSR type so the algorithm is part of the
/// seam contract, not a `jsonwebtoken` type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwtAlgorithm {
    /// HMAC-SHA256 (symmetric; secret from `SecretRef`).
    HS256,
    /// HMAC-SHA384.
    HS384,
    /// HMAC-SHA512.
    HS512,
    /// RSA-PKCS1-SHA256 (asymmetric; PEM key pair).
    RS256,
    /// ECDSA P-256.
    ES256,
}

/// An opaque signing key handle. The concrete bytes are hidden from callers.
#[derive(Debug)]
pub struct SigningKey {
    /// Key ID (included in the JWT `kid` header for rotation matching).
    pub kid: String,
    /// The algorithm this key uses.
    pub algorithm: JwtAlgorithm,
    /// Raw key material (secret or private key PEM). Not `Clone` intentionally.
    pub(crate) material: KeyMaterial,
}

/// A verification key (public or symmetric).
#[derive(Debug, Clone)]
pub struct VerificationKey {
    /// Key ID matching the JWT `kid` header.
    pub kid: String,
    /// Algorithm.
    pub algorithm: JwtAlgorithm,
    /// Public or symmetric verification material.
    pub(crate) material: KeyMaterial,
}

/// Raw key material — opaque to code outside this module.
#[derive(Debug, Clone)]
pub(crate) enum KeyMaterial {
    /// HMAC symmetric secret bytes.
    Symmetric(Vec<u8>),
    /// PEM-encoded public key (RSA, EC).
    Pem(String),
}

// ─── PasswordPolicy trait ─────────────────────────────────────────────────────

/// Pluggable password strength policy.
///
/// The default implementation enforces minimum length and basic complexity.
/// Operators can replace it with a zxcvbn strength estimator, a custom
/// blocked-password list, or any other policy.
pub trait PasswordPolicy: Send + Sync + 'static {
    /// Validate a candidate plaintext password.
    ///
    /// Returns `Ok(())` if the password meets the policy, or `Err` with a
    /// human-readable reason if it does not.
    fn validate(&self, password: &str) -> Result<(), PasswordPolicyViolation>;

    /// Minimum required length. Checked before [`validate`](Self::validate).
    fn min_length(&self) -> usize;
}

/// A password that failed a [`PasswordPolicy`] check.
#[derive(Debug, Clone)]
pub struct PasswordPolicyViolation {
    /// Human-readable description of the failure.
    pub reason: String,
}

impl std::fmt::Display for PasswordPolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "password policy violation: {}", self.reason)
    }
}

impl std::error::Error for PasswordPolicyViolation {}

// ─── Mailer trait ─────────────────────────────────────────────────────────────

/// Sends transactional email.
///
/// Used by OTP login, email verification, password reset. The default
/// implementation uses `lettre` behind the `auth-email` feature.
///
/// Implementations MUST NOT log the email body (it may contain one-time
/// tokens).
pub trait Mailer: Send + Sync + 'static {
    /// Send a transactional email message.
    fn send(&self, message: MailMessage) -> impl Future<Output = VsrResult<()>> + Send;
}

/// A transactional email message.
#[derive(Debug, Clone)]
pub struct MailMessage {
    /// Sender address (e.g. `"VSR Service <noreply@example.com>"`).
    pub from: String,
    /// Recipient address.
    pub to: String,
    /// Email subject.
    pub subject: String,
    /// Plain-text body (always required; used as fallback when HTML is set).
    pub text_body: String,
    /// Optional HTML body.
    pub html_body: Option<String>,
}
