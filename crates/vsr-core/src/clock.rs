//! Time and ID generation abstractions.
//!
//! Using these traits instead of calling `SystemTime::now()` or
//! `Uuid::new_v4()` directly makes deterministic testing straightforward:
//! inject a [`MockClock`] and a [`SequentialIdGenerator`] in tests and all
//! timestamps and IDs become predictable — no flaky time comparisons, no
//! random UUIDs in snapshot assertions.
//!
//! # Usage in production code
//!
//! ```rust
//! use vsr_core::clock::{Clock, SystemClock};
//!
//! fn record_created_at(clock: &impl Clock) -> i64 {
//!     clock.now_unix()
//! }
//! ```
//!
//! # Usage in tests
//!
//! ```rust
//! use vsr_core::clock::Clock;
//! use vsr_core::testing::MockClock;
//!
//! let clock = MockClock::at(1_700_000_000);
//! assert_eq!(clock.now_unix(), 1_700_000_000);
//! clock.advance(3600);
//! assert_eq!(clock.now_unix(), 1_700_003_600);
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch (UTC).
pub type UnixTimestamp = i64;

// ─── Clock ────────────────────────────────────────────────────────────────────

/// Provides the current wall-clock time.
///
/// Inject this into any code that records or compares timestamps so that
/// tests can control time precisely.
pub trait Clock: Send + Sync + 'static {
    /// Current time as seconds since the Unix epoch (UTC).
    fn now_unix(&self) -> UnixTimestamp;

    /// Microseconds since the Unix epoch for subsecond token expiry/revisions.
    /// Clocks with only second precision inherit a whole-second default.
    fn now_unix_micros(&self) -> i64 {
        self.now_unix().saturating_mul(1_000_000)
    }

    /// Current time as an ISO-8601 UTC string (e.g. `"2024-01-15T12:34:56Z"`).
    ///
    /// The default implementation emits a minimal numeric string. Enable the
    /// `chrono` feature for a properly formatted ISO-8601 string.
    fn now_iso8601(&self) -> String {
        // Minimal implementation that avoids pulling in chrono.
        // The `chrono` feature provides a proper override.
        format!("{}Z", self.now_unix())
    }
}

/// The real wall clock — delegates to `SystemTime::now()`.
#[derive(Clone, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> UnixTimestamp {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn now_unix_micros(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| i64::try_from(duration.as_micros()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}

// ─── IdGenerator ─────────────────────────────────────────────────────────────

/// Generates unique IDs for records, events, and request traces.
///
/// The default production implementation produces UUID v4 strings (behind
/// the `uuid` feature of `vsr-core`). Tests use [`SequentialIdGenerator`] for
/// deterministic, human-readable IDs.
pub trait IdGenerator: Send + Sync + 'static {
    /// Produce a new unique ID string.
    ///
    /// The returned string is treated as opaque by VSR's runtime — callers
    /// must not parse its format. The format is implementation-defined
    /// (UUID v4, ULID, sequential, etc.).
    fn generate(&self) -> impl Future<Output = String> + Send;
}

use std::future::Future;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_precision_clocks_have_a_microsecond_default() {
        let clock = crate::testing::MockClock::at(123);
        assert_eq!(clock.now_unix_micros(), 123_000_000);
        clock.advance(1);
        assert_eq!(clock.now_unix_micros(), 124_000_000);
    }

    #[test]
    fn system_microseconds_are_within_the_observed_epoch_seconds() {
        let clock = SystemClock;
        let before = clock.now_unix();
        let micros = clock.now_unix_micros();
        let after = clock.now_unix();
        assert!(micros >= before * 1_000_000);
        assert!(micros < (after + 1) * 1_000_000);
    }
}
