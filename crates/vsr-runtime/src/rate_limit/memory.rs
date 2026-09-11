//! Bounded single-process sliding-window counters with monotonic expiration.

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use super::{RateLimitDecision, RateLimitKey, RateLimitStore};
use vsr_core::error::{VsrError, VsrResult};

/// Hard ceilings for resident keys and accepted events. Live entries are never
/// evicted to admit a new client; capacity exhaustion fails closed.
#[derive(Clone, Copy, Debug)]
pub struct MemoryRateLimitCapacity {
    /// Maximum simultaneously resident keys.
    pub max_keys: usize,
    /// Maximum accepted events retained across all keys.
    pub max_events: usize,
    /// Maximum combined string length within a key.
    pub max_key_bytes: usize,
}

impl Default for MemoryRateLimitCapacity {
    fn default() -> Self {
        Self {
            max_keys: 10_000,
            max_events: 100_000,
            max_key_bytes: 1024,
        }
    }
}

struct Bucket {
    limit: u32,
    window: Duration,
    events: VecDeque<Instant>,
}

impl Bucket {
    fn prune(&mut self, now: Instant) {
        while self
            .events
            .front()
            .is_some_and(|time| now.saturating_duration_since(*time) >= self.window)
        {
            self.events.pop_front();
        }
        // Do not retain every bucket's historical peak allocation after bursts.
        if self.events.capacity() > self.events.len().saturating_mul(2).max(8) {
            self.events.shrink_to_fit();
        }
    }
}

#[derive(Default)]
struct State {
    buckets: HashMap<RateLimitKey, Bucket>,
    events: usize,
    next_prune: Option<Instant>,
    last_seen: Option<Instant>,
}

/// Atomic in-process store. Share one instance across server workers. This is
/// not a distributed quota: multiple processes require a shared store adapter.
#[derive(Default)]
pub struct MemoryRateLimitStore {
    capacity: MemoryRateLimitCapacity,
    state: Mutex<State>,
}

impl MemoryRateLimitStore {
    /// Set explicit capacity ceilings; zero capacity is invalid.
    pub fn new(capacity: MemoryRateLimitCapacity) -> VsrResult<Self> {
        if capacity.max_keys == 0 || capacity.max_events == 0 || capacity.max_key_bytes == 0 {
            return Err(error("invalid rate-limit capacity"));
        }
        Ok(Self {
            capacity,
            state: Mutex::default(),
        })
    }

    fn check_at(
        &self,
        key: &RateLimitKey,
        limit: u32,
        window: Duration,
        now: Instant,
        unix: i64,
    ) -> VsrResult<RateLimitDecision> {
        let limit_size = usize::try_from(limit).map_err(|_| error("rate-limit rule too large"))?;
        if limit == 0
            || window.is_zero()
            || limit_size > self.capacity.max_events
            || key_bytes(key) > self.capacity.max_key_bytes
        {
            return Err(error("invalid rate-limit rule or key"));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| error("rate-limit state unavailable"))?;
        // Concurrent callers can observe time before acquiring the mutex in a
        // different order. Never append an older timestamp behind a newer one.
        let now = state.last_seen.map_or(now, |last| last.max(now));
        if now.checked_add(window).is_none() {
            return Err(error("rate-limit window too large"));
        }
        state.last_seen = Some(now);
        // At most one full sweep per second bounds maintenance under key flooding.
        // Capacity can conservatively remain unavailable until the next sweep.
        if state.next_prune.is_none_or(|next| now >= next) {
            let mut events = 0;
            state.buckets.retain(|_, bucket| {
                bucket.prune(now);
                events += bucket.events.len();
                !bucket.events.is_empty()
            });
            state.events = events;
            state.next_prune = now.checked_add(Duration::from_secs(1));
        }
        if let Some(bucket) = state.buckets.get_mut(key) {
            let before = bucket.events.len();
            bucket.prune(now);
            let removed = before - bucket.events.len();
            if !bucket.events.is_empty() && (bucket.limit != limit || bucket.window != window) {
                state.events -= removed;
                return Err(error("rate-limit rule changed while its window is active"));
            }
            bucket.limit = limit;
            bucket.window = window;
            if bucket.events.len() >= limit_size {
                let wait = window.saturating_sub(now.saturating_duration_since(bucket.events[0]));
                state.events -= removed;
                return Ok(RateLimitDecision::Denied {
                    retry_after_secs: ceil_seconds(wait),
                });
            }
            state.events -= removed;
        } else if state.buckets.len() >= self.capacity.max_keys {
            return Err(error("rate-limit key capacity exhausted"));
        }
        if state.events >= self.capacity.max_events {
            return Err(error("rate-limit event capacity exhausted"));
        }
        let bucket = state.buckets.entry(key.clone()).or_insert_with(|| Bucket {
            limit,
            window,
            events: VecDeque::new(),
        });
        let remaining = u32::try_from(limit_size - bucket.events.len() - 1)
            .map_err(|_| error("invalid rate-limit event count"))?;
        bucket.events.push_back(now);
        let wait = window.saturating_sub(now.saturating_duration_since(bucket.events[0]));
        let reset_at = unix.saturating_add(i64::try_from(ceil_seconds(wait)).unwrap_or(i64::MAX));
        state.events += 1;
        Ok(RateLimitDecision::Allowed {
            remaining,
            reset_at,
        })
    }
}

// Keep mutations lazy: constructing and dropping an unpolled future must do nothing.
#[allow(clippy::unused_async_trait_impl)]
impl RateLimitStore for MemoryRateLimitStore {
    async fn check_and_increment(
        &self,
        key: &RateLimitKey,
        limit: u32,
        window: Duration,
    ) -> VsrResult<RateLimitDecision> {
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| i64::try_from(time.as_secs()).ok())
            .ok_or_else(|| error("rate-limit clock unavailable"))?;
        self.check_at(key, limit, window, Instant::now(), unix)
    }

    async fn reset(&self, key: &RateLimitKey) -> VsrResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| error("rate-limit state unavailable"))?;
        if let Some(bucket) = state.buckets.remove(key) {
            state.events -= bucket.events.len();
        }
        Ok(())
    }
}

fn ceil_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0))
        .max(1)
}

fn key_bytes(key: &RateLimitKey) -> usize {
    match key {
        RateLimitKey::PerIp(_) => 0,
        RateLimitKey::PerUser(value) | RateLimitKey::Custom(value) => value.len(),
        RateLimitKey::PerRoute { resource, action } => resource.len().saturating_add(action.len()),
        RateLimitKey::PerUserRoute {
            user_id,
            resource,
            action,
        } => user_id
            .len()
            .saturating_add(resource.len())
            .saturating_add(action.len()),
    }
}

fn error(message: &'static str) -> VsrError {
    VsrError::Other(message.into())
}

#[cfg(test)]
#[path = "memory_tests.rs"]
mod tests;
