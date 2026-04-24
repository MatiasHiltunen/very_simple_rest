//! Rate limiting trait seam.
//!
//! The default implementation is an in-process token-bucket store backed by
//! `DashMap`. It is suitable for single-instance deployments. Multi-instance
//! deployments need a shared store (Redis); that adapter lives behind
//! `rate-limit-redis`.

use std::{future::Future, time::Duration};
use vsr_core::error::VsrResult;

// ─── RateLimitKey ─────────────────────────────────────────────────────────────

/// The dimension over which a rate limit is applied.
///
/// Multiple keys compose naturally: check `PerIp` first (coarse), then
/// `PerUser` (fine) as two separate calls.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RateLimitKey {
    /// One bucket per client IP address.
    PerIp(std::net::IpAddr),
    /// One bucket per authenticated user ID.
    PerUser(String),
    /// One bucket per resource + action pair (e.g. brute-force on one route).
    PerRoute {
        /// Resource name (e.g. `"Post"`).
        resource: String,
        /// Action name (e.g. `"create"`).
        action: String,
    },
    /// One bucket per user + resource (fine-grained per-resource limits).
    PerUserRoute {
        /// Authenticated user ID.
        user_id: String,
        /// Resource name.
        resource: String,
        /// Action name.
        action: String,
    },
    /// Custom composite key.
    Custom(String),
}

// ─── RateLimitDecision ────────────────────────────────────────────────────────

/// The outcome of a rate-limit check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// The request is within the limit.
    Allowed {
        /// How many more requests are allowed in the current window.
        remaining: u32,
        /// When the current window resets (Unix timestamp).
        reset_at: i64,
    },
    /// The request exceeds the limit.
    Denied {
        /// Seconds until the client may retry.
        retry_after_secs: u64,
    },
}

impl RateLimitDecision {
    /// Returns `true` if the request is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitDecision::Allowed { .. })
    }
}

// ─── RateLimitStore trait ─────────────────────────────────────────────────────

/// Stores and checks rate-limit counters.
///
/// # Contract
///
/// - `check_and_increment` atomically checks *and* increments the counter.
///   A single call serves as both the check and the consumption.
/// - `reset` clears a counter (useful for tests and admin overrides).
/// - Implementations MUST be `Send + Sync + 'static`.
/// - Implementations MUST handle counter TTL internally — a counter that
///   has not been incremented past its `window` MUST be cleaned up or
///   treated as zero on the next call.
pub trait RateLimitStore: Send + Sync + 'static {
    /// Check the counter for `key` and, if allowed, increment it.
    ///
    /// - `limit` — maximum requests allowed per `window`.
    /// - `window` — sliding window duration.
    fn check_and_increment(
        &self,
        key: &RateLimitKey,
        limit: u32,
        window: Duration,
    ) -> impl Future<Output = VsrResult<RateLimitDecision>> + Send;

    /// Reset the counter for `key` to zero.
    fn reset(&self, key: &RateLimitKey) -> impl Future<Output = VsrResult<()>> + Send;
}
