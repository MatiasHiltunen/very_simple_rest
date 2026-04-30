//! In-process fakes for every `vsr-core` trait.
//!
//! Import this module in unit tests to get zero-dependency, zero-network
//! implementations of [`SecretProvider`], [`Clock`], and [`IdGenerator`].
//!
//! These fakes are compiled into the crate unconditionally (no `#[cfg(test)]`
//! gate) so that downstream crates can use them in their own tests without
//! needing dev-dependency workarounds.
//!
//! # Quick reference
//!
//! | Trait | Fake | Notes |
//! |---|---|---|
//! | `SecretProvider` | `StaticSecretProvider` | Pre-seeded key→value map |
//! | `Clock` | `MockClock` | Fixed timestamp, manually advanced |
//! | `IdGenerator` | `SequentialIdGenerator` | `"id-1"`, `"id-2"`, … |
//!
//! # Example
//!
//! ```rust
//! use vsr_core::testing::{StaticSecretProvider, MockClock, SequentialIdGenerator};
//! use vsr_core::secret::SecretProvider;
//! use vsr_core::clock::Clock;
//!
//! let secrets = StaticSecretProvider::new()
//!     .with("DATABASE_URL", "sqlite::memory:")
//!     .with("JWT_SECRET", "test-secret");
//!
//! let clock = MockClock::at(1_700_000_000);
//! clock.advance(3600);
//! assert_eq!(clock.now_unix(), 1_700_003_600);
//!
//! let ids = SequentialIdGenerator::default();
//! ```

use crate::{
    clock::{Clock, IdGenerator, UnixTimestamp},
    error::{VsrError, VsrResult},
    secret::{SecretProvider, SecretRef},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

// ─── StaticSecretProvider ─────────────────────────────────────────────────────

/// A [`SecretProvider`] backed by a pre-loaded key→value map.
///
/// Useful for unit tests that need a fixed set of secrets without touching
/// environment variables.
#[derive(Clone, Default)]
pub struct StaticSecretProvider {
    secrets: Arc<HashMap<String, String>>,
}

impl StaticSecretProvider {
    /// Create an empty provider. Add secrets with [`with`](Self::with).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a secret and return `self` for builder-style chaining.
    pub fn with(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        Arc::make_mut(&mut self.secrets).insert(name.into(), value.into());
        self
    }
}

impl std::fmt::Debug for StaticSecretProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the values — only the names.
        let keys: Vec<&str> = self.secrets.keys().map(String::as_str).collect();
        f.debug_struct("StaticSecretProvider")
            .field("keys", &keys)
            .finish()
    }
}

impl SecretProvider for StaticSecretProvider {
    async fn resolve(&self, secret: &SecretRef) -> VsrResult<String> {
        self.secrets
            .get(&secret.name)
            .cloned()
            .ok_or_else(|| VsrError::Secret {
                name: secret.name.clone(),
                reason: "not found in StaticSecretProvider".into(),
            })
    }

    fn owns(&self, name: &str) -> bool {
        self.secrets.contains_key(name)
    }
}

// ─── MockClock ────────────────────────────────────────────────────────────────

/// A [`Clock`] that always returns a fixed timestamp.
///
/// The timestamp can be advanced with [`MockClock::advance`] or set directly
/// with [`MockClock::set`]. Cheap to clone — all clones share the same
/// internal counter.
#[derive(Clone, Debug)]
pub struct MockClock {
    ts: Arc<Mutex<UnixTimestamp>>,
}

impl MockClock {
    /// Create a clock fixed at `ts` seconds since the Unix epoch.
    pub fn at(ts: UnixTimestamp) -> Self {
        Self {
            ts: Arc::new(Mutex::new(ts)),
        }
    }

    /// Set the current timestamp.
    pub fn set(&self, ts: UnixTimestamp) {
        *self.ts.lock().unwrap() = ts;
    }

    /// Advance the clock by `secs` seconds.
    pub fn advance(&self, secs: i64) {
        *self.ts.lock().unwrap() += secs;
    }
}

impl Clock for MockClock {
    fn now_unix(&self) -> UnixTimestamp {
        *self.ts.lock().unwrap()
    }
}

// ─── SequentialIdGenerator ────────────────────────────────────────────────────

/// An [`IdGenerator`] that produces `"id-1"`, `"id-2"`, … in sequence.
///
/// All clones share the same counter so IDs remain globally unique within
/// a test process, even when the generator is passed across tasks.
#[derive(Clone, Debug, Default)]
pub struct SequentialIdGenerator {
    counter: Arc<Mutex<u64>>,
}

impl IdGenerator for SequentialIdGenerator {
    async fn generate(&self) -> String {
        let mut n = self.counter.lock().unwrap();
        *n += 1;
        format!("id-{n}")
    }
}
