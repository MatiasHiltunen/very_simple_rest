//! Secret management abstractions.
//!
//! VSR code never passes raw secret strings across module or crate boundaries.
//! Instead, it passes a [`SecretRef`] — a lightweight name + provider hint —
//! and calls [`SecretProvider::resolve`] only at the point of actual use.
//!
//! This discipline means secrets cannot accidentally leak through logs,
//! error messages, or serialization. The [`SecretRef`]'s `Display` impl
//! always prints `<secret:NAME>`, never the value.
//!
//! # Example
//!
//! ```rust
//! use vsr_core::secret::{SecretRef, SecretProvider};
//!
//! async fn connect(secrets: &impl SecretProvider) {
//!     let db_ref = SecretRef::new("DATABASE_URL");
//!     let url = secrets.resolve(&db_ref).await.expect("DATABASE_URL must be set");
//!     // use url to open a connection — it never appears in any log
//! }
//! ```

use std::fmt;
use crate::error::VsrResult;

// ─── SecretRef ────────────────────────────────────────────────────────────────

/// A reference to a named secret. Cheap to clone; **contains no secret data**.
///
/// The `Display` impl intentionally prints `<secret:NAME>` so that structs
/// containing `SecretRef` can be `Debug`-printed and logged safely.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretRef {
    /// Logical name (e.g. `"DATABASE_URL"`, `"JWT_SECRET"`).
    pub name: String,
    /// Optional hint directing resolution to a specific provider.
    pub provider: Option<String>,
}

impl SecretRef {
    /// Create a `SecretRef` with no provider hint.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            provider: None,
        }
    }

    /// Create a `SecretRef` with a provider hint directing resolution to a
    /// specific named provider (e.g. `"infisical"`, `"vault"`).
    pub fn with_provider(name: impl Into<String>, provider: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            provider: Some(provider.into()),
        }
    }
}

/// Prints `<secret:NAME>` — never the value.
impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<secret:{}>", self.name)
    }
}

// ─── SecretProvider trait ─────────────────────────────────────────────────────

/// Resolves a [`SecretRef`] to its plaintext value at the point of use.
///
/// Implementors live behind feature flags:
/// - `EnvSecretProvider` — reads from environment variables (always available).
/// - `InfisicalProvider` — Infisical API (behind `secrets-infisical`).
/// - `VaultProvider` — HashiCorp Vault (behind `secrets-vault`).
/// - `AwsSecretsProvider` — AWS Secrets Manager (behind `secrets-aws`).
///
/// Multiple providers can be composed with [`ChainedProvider`].
///
/// # Contract
///
/// - The returned `String` is sensitive. Callers **must not** log it or
///   include it in any `Display` or `Debug` output.
/// - Implementations must be `Send + Sync + 'static` so they can be held in
///   `Arc<dyn ...>` and passed across task boundaries.
pub trait SecretProvider: Send + Sync + 'static {
    /// Resolve the secret to its plaintext value.
    ///
    /// Returns `Err(VsrError::Secret { .. })` if the secret cannot be found
    /// or the provider encounters an error.
    fn resolve(&self, secret: &SecretRef) -> impl Future<Output = VsrResult<String>> + Send;

    /// Returns `true` if this provider claims ownership of the given name.
    ///
    /// Used by [`ChainedProvider`] to skip unnecessary network calls.
    /// Returning `true` does not guarantee `resolve` will succeed.
    fn owns(&self, name: &str) -> bool;
}

use std::future::Future;

// ─── Env provider (always available) ─────────────────────────────────────────

/// Resolves secrets from environment variables.
///
/// This is the baseline provider — always compiled in, zero network
/// dependencies. All other providers should be chained on top of this one
/// as a fallback.
#[derive(Clone, Debug, Default)]
pub struct EnvSecretProvider;

impl SecretProvider for EnvSecretProvider {
    async fn resolve(&self, secret: &SecretRef) -> VsrResult<String> {
        std::env::var(&secret.name).map_err(|_| crate::error::VsrError::Secret {
            name: secret.name.clone(),
            reason: "not found in environment".into(),
        })
    }

    fn owns(&self, name: &str) -> bool {
        std::env::var(name).is_ok()
    }
}

// ─── ChainedProvider ──────────────────────────────────────────────────────────

/// Composes two providers: tries `primary` first, falls back to `fallback`.
///
/// ```rust
/// use vsr_core::secret::{ChainedProvider, EnvSecretProvider};
///
/// // Env as the only provider (trivial chain with itself — real usage chains
/// // Infisical → Env):
/// let provider = ChainedProvider::new(EnvSecretProvider, EnvSecretProvider);
/// ```
pub struct ChainedProvider<A, B> {
    primary: A,
    fallback: B,
}

impl<A: SecretProvider, B: SecretProvider> ChainedProvider<A, B> {
    /// Create a chain that tries `primary` first, then `fallback`.
    pub fn new(primary: A, fallback: B) -> Self {
        Self { primary, fallback }
    }
}

impl<A: SecretProvider, B: SecretProvider> SecretProvider for ChainedProvider<A, B> {
    async fn resolve(&self, secret: &SecretRef) -> VsrResult<String> {
        if self.primary.owns(&secret.name) {
            self.primary.resolve(secret).await
        } else {
            self.fallback.resolve(secret).await
        }
    }

    fn owns(&self, name: &str) -> bool {
        self.primary.owns(name) || self.fallback.owns(name)
    }
}
