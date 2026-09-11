use super::*;
use crate::{
    http::{HeaderFields, HttpMethod, RequestContext, ResponseBody},
    rate_limit::MemoryRateLimitStore,
};
use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Unavailable;
impl RateLimitStore for Unavailable {
    async fn check_and_increment(
        &self,
        _: &RateLimitKey,
        _: u32,
        _: Duration,
    ) -> vsr_core::error::VsrResult<RateLimitDecision> {
        Err(vsr_core::error::VsrError::Other(
            "private backend credentials".into(),
        ))
    }
    async fn reset(&self, _: &RateLimitKey) -> vsr_core::error::VsrResult<()> {
        Ok(())
    }
}
fn rule(requests: u32) -> AuthRateLimitRule {
    AuthRateLimitRule {
        requests,
        window_seconds: 60,
    }
}
fn request(peer: Option<&str>) -> RequestContext {
    RequestContext {
        method: HttpMethod::Post,
        path: "/auth/login".into(),
        raw_query: String::new(),
        matched_route: None,
        peer_addr: peer.map(|peer| peer.parse().unwrap()),
        path_params: HashMap::new(),
        query_params: HashMap::new(),
        headers: HeaderFields::default(),
        body: None,
        identity: None,
        request_id: "test".into(),
    }
}

#[tokio::test]
async fn wrapper_uses_only_direct_peer_and_stops_before_the_handler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let handler = rate_limit_authentication(
        Arc::new(MemoryRateLimitStore::default()),
        AuthRateLimitScope::Login,
        rule(1),
        make_handler(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            async { ResponseEnvelope::status(200) }
        }),
    )
    .unwrap();
    assert_eq!(handler(request(Some("127.0.0.1:1000"))).await.status, 200);
    let mut spoof = request(Some("127.0.0.1:2000"));
    spoof
        .headers
        .append("x-forwarded-for", "192.0.2.99")
        .unwrap();
    spoof.headers.append("forwarded", "for=192.0.2.99").unwrap();
    spoof.identity = Some(crate::auth::AuthenticatedIdentity {
        user_id: "spoof".into(),
        email: None,
        roles: vec!["admin".into()],
        claims: HashMap::new(),
        is_admin: true,
        expires_at: None,
    });
    let response = handler(spoof).await;
    assert_eq!(response.status, 429);
    assert_eq!(response.headers.get("retry-after"), Some(b"60".as_slice()));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(handler(request(Some("192.0.2.1:1000"))).await.status, 200);
}

#[tokio::test]
async fn scopes_are_separate_but_missing_peers_share_a_bucket() {
    let store = MemoryRateLimitStore::default();
    for scope in [AuthRateLimitScope::Login, AuthRateLimitScope::Register] {
        check_auth_rate_limit(&store, scope, None, rule(1))
            .await
            .unwrap();
        assert!(matches!(
            check_auth_rate_limit(&store, scope, None, rule(1)).await,
            Err(AuthAdmissionError::Limited { .. })
        ));
    }
    check_auth_rate_limit(
        &store,
        AuthRateLimitScope::Login,
        Some("127.0.0.1".parse().unwrap()),
        rule(1),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn store_errors_are_redacted_and_configuration_never_disables_enforcement() {
    let error = check_auth_rate_limit(&Unavailable, AuthRateLimitScope::Login, None, rule(1))
        .await
        .unwrap_err();
    assert_eq!(error, AuthAdmissionError::Unavailable);
    let response = error.response();
    assert_eq!(response.status, 503);
    assert_eq!(response.headers.get("retry-after"), Some(b"1".as_slice()));
    let ResponseBody::Bytes(body) = response.body else {
        panic!("serialized JSON")
    };
    assert!(!std::str::from_utf8(&body).unwrap().contains("private"));
    for invalid in [
        rule(0),
        AuthRateLimitRule {
            requests: 1,
            window_seconds: 0,
        },
    ] {
        assert_eq!(
            check_auth_rate_limit(&Unavailable, AuthRateLimitScope::Login, None, invalid).await,
            Err(AuthAdmissionError::Configuration)
        );
        assert!(
            rate_limit_authentication(
                Arc::new(Unavailable),
                AuthRateLimitScope::Login,
                invalid,
                make_handler(|_| async { ResponseEnvelope::status(200) })
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn wrapper_passes_canonical_key_to_injected_store() {
    #[derive(Default)]
    struct Spy(Mutex<Vec<RateLimitKey>>);
    impl RateLimitStore for Spy {
        async fn check_and_increment(
            &self,
            key: &RateLimitKey,
            limit: u32,
            window: Duration,
        ) -> vsr_core::error::VsrResult<RateLimitDecision> {
            self.0.lock().unwrap().push(key.clone());
            assert_eq!((limit, window), (3, Duration::from_secs(60)));
            Ok(RateLimitDecision::Denied {
                retry_after_secs: 0,
            })
        }
        async fn reset(&self, _: &RateLimitKey) -> vsr_core::error::VsrResult<()> {
            Ok(())
        }
    }
    let store = Spy::default();
    let error = check_auth_rate_limit(
        &store,
        AuthRateLimitScope::Register,
        Some("::1".parse().unwrap()),
        rule(3),
    )
    .await
    .unwrap_err();
    assert_eq!(
        store.0.lock().unwrap()[0],
        RateLimitKey::Custom("auth:register:::1".into())
    );
    assert_eq!(
        error.response().headers.get("retry-after"),
        Some(b"1".as_slice())
    );
}
