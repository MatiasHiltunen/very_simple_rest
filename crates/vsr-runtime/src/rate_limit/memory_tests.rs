use super::*;
use std::sync::{Arc, Barrier};

fn key(value: &str) -> RateLimitKey {
    RateLimitKey::Custom(value.into())
}
fn store(keys: usize, events: usize) -> MemoryRateLimitStore {
    MemoryRateLimitStore::new(MemoryRateLimitCapacity {
        max_keys: keys,
        max_events: events,
        max_key_bytes: 32,
    })
    .unwrap()
}

#[test]
fn sliding_windows_expire_exactly_and_retry_after_rounds_up() {
    let store = store(2, 4);
    let now = Instant::now();
    let window = Duration::from_secs(2);
    assert_eq!(
        store.check_at(&key("a"), 2, window, now, 100).unwrap(),
        RateLimitDecision::Allowed {
            remaining: 1,
            reset_at: 102
        }
    );
    assert!(
        store
            .check_at(&key("a"), 2, window, now + Duration::from_millis(500), 100)
            .unwrap()
            .is_allowed()
    );
    for (elapsed, retry) in [(900, 2), (1999, 1)] {
        assert_eq!(
            store
                .check_at(
                    &key("a"),
                    2,
                    window,
                    now + Duration::from_millis(elapsed),
                    999
                )
                .unwrap(),
            RateLimitDecision::Denied {
                retry_after_secs: retry
            }
        );
    }
    assert!(
        store
            .check_at(&key("a"), 2, window, now + window, 1)
            .unwrap()
            .is_allowed()
    );
    assert_eq!(store.state.lock().unwrap().events, 2);
}

#[test]
fn capacity_never_evicts_live_counters_and_reclaims_expired_keys() {
    let store = store(1, 2);
    let now = Instant::now();
    let window = Duration::from_secs(2);
    assert!(
        store
            .check_at(&key("a"), 1, window, now, 100)
            .unwrap()
            .is_allowed()
    );
    for i in 0..100 {
        assert!(
            store
                .check_at(&key(&format!("flood-{i}")), 1, window, now, 100)
                .is_err()
        );
    }
    assert!(matches!(
        store.check_at(&key("a"), 1, window, now, 100).unwrap(),
        RateLimitDecision::Denied { .. }
    ));
    assert!(
        store
            .check_at(&key("b"), 1, window, now + window, 102)
            .unwrap()
            .is_allowed()
    );
    let state = store.state.lock().unwrap();
    assert_eq!(state.buckets.len(), 1);
    assert_eq!(state.events, 1);
    assert!(!state.buckets.contains_key(&key("a")));
}

#[tokio::test]
async fn global_event_capacity_and_reset_are_atomic() {
    let store = store(2, 2);
    let window = Duration::from_secs(60);
    for name in ["a", "b"] {
        assert!(
            store
                .check_and_increment(&key(name), 2, window)
                .await
                .unwrap()
                .is_allowed()
        );
    }
    assert!(
        store
            .check_and_increment(&key("a"), 2, window)
            .await
            .is_err()
    );
    store.reset(&key("b")).await.unwrap();
    store.reset(&key("b")).await.unwrap();
    assert!(
        store
            .check_and_increment(&key("a"), 2, window)
            .await
            .unwrap()
            .is_allowed()
    );
    assert!(matches!(
        store
            .check_and_increment(&key("a"), 2, window)
            .await
            .unwrap(),
        RateLimitDecision::Denied { .. }
    ));
    assert_eq!(store.state.lock().unwrap().events, 2);
}

#[test]
fn rules_cannot_reset_live_budgets_and_out_of_order_observations_are_clamped() {
    let store = store(1, 4);
    let now = Instant::now();
    let window = Duration::from_secs(2);
    store.check_at(&key("a"), 2, window, now, 100).unwrap();
    assert!(store.check_at(&key("a"), 3, window, now, 100).is_err());
    assert!(
        store
            .check_at(&key("a"), 2, Duration::from_secs(1), now, 100)
            .is_err()
    );
    store
        .check_at(&key("a"), 2, window, now - Duration::from_secs(10), 1)
        .unwrap();
    assert!(matches!(
        store.check_at(&key("a"), 2, window, now, 100).unwrap(),
        RateLimitDecision::Denied { .. }
    ));
    assert!(
        store
            .check_at(&key("a"), 3, window, now + window, 102)
            .unwrap()
            .is_allowed()
    );
}

#[test]
fn concurrent_attempts_cannot_exceed_the_budget() {
    let store = Arc::new(store(1, 32));
    let barrier = Arc::new(Barrier::new(32));
    let now = Instant::now();
    let workers: Vec<_> = (0..32)
        .map(|_| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .check_at(&key("a"), 7, Duration::from_secs(60), now, 100)
                    .unwrap()
                    .is_allowed()
            })
        })
        .collect();
    let accepted = workers
        .into_iter()
        .map(|worker| usize::from(worker.join().unwrap()))
        .sum::<usize>();
    assert_eq!(accepted, 7);
    assert_eq!(store.state.lock().unwrap().events, 7);
}

#[test]
fn invalid_capacity_rules_keys_and_poisoned_state_fail_closed() {
    assert!(
        MemoryRateLimitStore::new(MemoryRateLimitCapacity {
            max_keys: 0,
            ..Default::default()
        })
        .is_err()
    );
    let store = store(1, 2);
    let now = Instant::now();
    for (limit, window) in [
        (0, Duration::from_secs(1)),
        (1, Duration::ZERO),
        (3, Duration::from_secs(1)),
        (1, Duration::MAX),
    ] {
        assert!(store.check_at(&key("a"), limit, window, now, 100).is_err());
    }
    assert!(
        store
            .check_at(&key(&"x".repeat(33)), 1, Duration::from_secs(1), now, 100)
            .is_err()
    );
    assert_eq!(store.state.lock().unwrap().events, 0);
    for key in [
        RateLimitKey::PerUser("x".repeat(33)),
        RateLimitKey::PerRoute {
            resource: "r".repeat(16),
            action: "a".repeat(17),
        },
        RateLimitKey::PerUserRoute {
            user_id: "u".repeat(10),
            resource: "r".repeat(10),
            action: "a".repeat(13),
        },
    ] {
        assert!(
            store
                .check_at(&key, 1, Duration::from_secs(1), now, 100)
                .is_err()
        );
    }
    let _ = std::panic::catch_unwind(|| {
        let _guard = store.state.lock().unwrap();
        panic!("injected poison");
    });
    assert!(
        store
            .check_at(&key("a"), 1, Duration::from_secs(1), now, 100)
            .is_err()
    );
}

#[test]
fn expired_bursts_release_historical_queue_capacity() {
    let store = store(2, 100);
    let now = Instant::now();
    let window = Duration::from_secs(2);
    for _ in 0..99 {
        store.check_at(&key("a"), 100, window, now, 100).unwrap();
    }
    store
        .check_at(&key("a"), 100, window, now + Duration::from_secs(1), 101)
        .unwrap();
    store
        .check_at(&key("a"), 100, window, now + window, 102)
        .unwrap();
    let state = store.state.lock().unwrap();
    assert_eq!(state.events, 2);
    assert!(state.buckets[&key("a")].events.capacity() <= 8);
}

#[tokio::test]
async fn unpolled_checks_and_resets_do_not_mutate_counters() {
    let store = store(1, 1);
    let key = key("a");
    let window = Duration::from_secs(60);
    drop(store.check_and_increment(&key, 1, window));
    assert_eq!(store.state.lock().unwrap().events, 0);
    assert!(
        store
            .check_and_increment(&key, 1, window)
            .await
            .unwrap()
            .is_allowed()
    );
    drop(store.reset(&key));
    assert!(matches!(
        store.check_and_increment(&key, 1, window).await.unwrap(),
        RateLimitDecision::Denied { .. }
    ));
}
