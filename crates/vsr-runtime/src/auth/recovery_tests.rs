use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI64, Ordering},
};

#[derive(Clone)]
struct TestClock(Arc<AtomicI64>);
impl Clock for TestClock {
    fn now_unix(&self) -> i64 {
        self.now_unix_micros() / 1_000_000
    }
    fn now_unix_micros(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn timestamp(micros: i64) -> String {
    DateTime::<Utc>::from_timestamp_micros(micros)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Micros, false)
}

struct State {
    events: Vec<&'static str>,
    failure: Option<&'static str>,
    expires: String,
    email: Option<String>,
    found: bool,
    claim: bool,
    account: bool,
    advance_on_claim: bool,
    hash: Option<String>,
    committed: bool,
    block_apply: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            events: vec![],
            failure: None,
            expires: timestamp(20_000_001),
            email: Some("owner@example.test".into()),
            found: true,
            claim: true,
            account: true,
            advance_on_claim: false,
            hash: None,
            committed: false,
            block_apply: false,
        }
    }
}

#[derive(Clone)]
struct Repository {
    state: Arc<Mutex<State>>,
    clock: TestClock,
    started: Arc<tokio::sync::Notify>,
}
struct Transaction {
    repository: Repository,
    finished: bool,
}

impl Repository {
    fn step(&self, name: &'static str) -> Result<(), AccountError> {
        let mut state = self.state.lock().unwrap();
        state.events.push(name);
        if state.failure == Some(name) {
            Err(AccountError::Database)
        } else {
            Ok(())
        }
    }
}

impl RecoveryRepository for Repository {
    type Transaction = Transaction;
    async fn begin(&self) -> Result<Transaction, AccountError> {
        self.step("begin")?;
        Ok(Transaction {
            repository: self.clone(),
            finished: false,
        })
    }
}

impl RecoveryTransaction for Transaction {
    async fn pending(
        &self,
        digest: &str,
        _purpose: TokenPurpose,
    ) -> Result<Option<PendingToken>, AccountError> {
        self.repository.step("pending")?;
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let state = self.repository.state.lock().unwrap();
        Ok(state.found.then(|| PendingToken {
            id: 1,
            user_id: 7,
            requested_email: state.email.clone(),
            expires_at: state.expires.clone(),
        }))
    }
    async fn claim(&self, id: i64, used_at: &str) -> Result<bool, AccountError> {
        self.repository.step("claim")?;
        assert_eq!(id, 1);
        assert_eq!(used_at, timestamp(10_000_001));
        let state = self.repository.state.lock().unwrap();
        if state.advance_on_claim {
            self.repository.clock.0.store(20_000_001, Ordering::SeqCst);
        }
        Ok(state.claim)
    }
    async fn apply(
        &self,
        token: &PendingToken,
        purpose: TokenPurpose,
        hash: Option<&str>,
        _changed_at: &str,
    ) -> Result<bool, AccountError> {
        self.repository.step("apply")?;
        assert_eq!(token.user_id, 7);
        assert_eq!(hash.is_some(), purpose == TokenPurpose::PasswordReset);
        let block = self.repository.state.lock().unwrap().block_apply;
        if block {
            self.repository.started.notify_one();
            std::future::pending::<()>().await;
        }
        let mut state = self.repository.state.lock().unwrap();
        state.hash = hash.map(str::to_owned);
        Ok(state.account)
    }
    async fn delete(&self, id: i64) -> Result<(), AccountError> {
        assert_eq!(id, 1);
        self.repository.step("delete")
    }
    async fn delete_siblings(&self, id: i64, _purpose: TokenPurpose) -> Result<(), AccountError> {
        assert_eq!(id, 7);
        self.repository.step("siblings")
    }
    async fn commit(mut self) -> Result<(), AccountError> {
        self.repository.step("commit")?;
        self.repository.state.lock().unwrap().committed = true;
        self.finished = true;
        Ok(())
    }
    async fn rollback(mut self) -> Result<(), AccountError> {
        self.repository.step("rollback")?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.finished {
            self.repository
                .state
                .lock()
                .unwrap()
                .events
                .push("drop_rollback");
        }
    }
}

fn fixture(state: State) -> (Repository, RecoveryService<Repository, TestClock>) {
    let repository = Repository {
        state: Arc::new(Mutex::new(state)),
        clock: TestClock(Arc::new(AtomicI64::new(10_000_001))),
        started: Arc::default(),
    };
    let service = RecoveryService::with_clock(repository.clone(), repository.clock.clone());
    (repository, service)
}

#[tokio::test]
async fn verify_commits_claim_mutation_and_sibling_removal_in_order() {
    let (repository, service) = fixture(State::default());
    assert_eq!(
        service.verify_email(" abc ").await.unwrap(),
        TokenActionOutcome::Applied
    );
    let state = repository.state.lock().unwrap();
    assert_eq!(
        state.events,
        ["begin", "pending", "claim", "apply", "siblings", "commit"]
    );
    assert!(state.committed);
}

#[tokio::test]
async fn expiry_is_subsecond_inclusive_and_rechecked_after_claim() {
    for expires in [
        timestamp(10_000_000),
        timestamp(10_000_001),
        "malformed".into(),
    ] {
        let (repository, service) = fixture(State {
            expires,
            ..Default::default()
        });
        assert_eq!(
            service.verify_email("abc").await.unwrap(),
            TokenActionOutcome::Expired
        );
        assert_eq!(
            repository.state.lock().unwrap().events,
            ["begin", "pending", "delete", "commit"]
        );
    }
    let (_, service) = fixture(State {
        expires: timestamp(10_000_002),
        ..Default::default()
    });
    assert_eq!(
        service.verify_email("abc").await.unwrap(),
        TokenActionOutcome::Applied
    );
    let (repository, service) = fixture(State {
        advance_on_claim: true,
        ..Default::default()
    });
    assert_eq!(
        service.verify_email("abc").await.unwrap(),
        TokenActionOutcome::Expired
    );
    assert_eq!(
        repository.state.lock().unwrap().events,
        ["begin", "pending", "claim", "delete", "commit"]
    );
}

#[tokio::test]
async fn missing_reused_unbound_and_deleted_accounts_do_not_apply() {
    for state in [
        State {
            found: false,
            ..Default::default()
        },
        State {
            claim: false,
            ..Default::default()
        },
        State {
            email: None,
            ..Default::default()
        },
        State {
            email: Some(String::new()),
            ..Default::default()
        },
        State {
            account: false,
            ..Default::default()
        },
    ] {
        let (repository, service) = fixture(state);
        assert_eq!(
            service.verify_email("abc").await.unwrap(),
            TokenActionOutcome::Invalid
        );
        assert!(
            !repository
                .state
                .lock()
                .unwrap()
                .events
                .contains(&"siblings")
        );
    }
}

#[tokio::test]
async fn every_storage_failure_is_an_error_and_rolls_back_before_commit() {
    for step in ["begin", "pending", "claim", "apply", "siblings", "commit"] {
        let (repository, service) = fixture(State {
            failure: Some(step),
            ..Default::default()
        });
        assert_eq!(
            service.verify_email("abc").await,
            Err(AccountError::Database)
        );
        let state = repository.state.lock().unwrap();
        assert!(!state.committed);
        assert_eq!(
            state.events.last().copied(),
            Some(match step {
                "begin" => "begin",
                "commit" => "drop_rollback",
                _ => "rollback",
            })
        );
    }
    let (repository, service) = fixture(State {
        failure: Some("delete"),
        expires: "bad".into(),
        ..Default::default()
    });
    assert_eq!(
        service.verify_email("abc").await,
        Err(AccountError::Database)
    );
    assert_eq!(
        repository.state.lock().unwrap().events.last(),
        Some(&"rollback")
    );
}

#[tokio::test]
async fn cancelling_after_claim_drops_the_uncommitted_transaction() {
    let (repository, service) = fixture(State {
        block_apply: true,
        ..Default::default()
    });
    let task = tokio::spawn(async move { service.verify_email("abc").await });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        repository.started.notified(),
    )
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let state = repository.state.lock().unwrap();
    assert_eq!(state.events.last(), Some(&"drop_rollback"));
    assert!(!state.committed);
}

#[tokio::test]
async fn password_policy_runs_before_opening_a_transaction() {
    let _guard = password::TEST_LOCK.lock().await;
    let (repository, service) = fixture(State::default());
    assert!(matches!(
        service.reset_password("abc", "short").await,
        Err(AccountError::Validation("password", _))
    ));
    assert!(matches!(
        service.reset_password(" ", "valid-password").await,
        Err(AccountError::Validation("token", _))
    ));
    assert!(matches!(
        service.verify_email(" ").await,
        Err(AccountError::Validation("token", _))
    ));
    assert!(repository.state.lock().unwrap().events.is_empty());
    assert_eq!(
        service
            .reset_password("abc", "valid-password")
            .await
            .unwrap(),
        TokenActionOutcome::Applied
    );
    let state = repository.state.lock().unwrap();
    let hash = state.hash.as_deref().unwrap();
    assert!(hash.starts_with("$2b$12$"));
    assert!(bcrypt::verify("valid-password", hash).unwrap());
}

#[tokio::test]
async fn invalid_clock_fails_closed_and_rollback_failure_uses_drop_cleanup() {
    for failure in [None, Some("rollback")] {
        let (repository, service) = fixture(State {
            failure,
            ..Default::default()
        });
        repository.clock.0.store(-1, Ordering::SeqCst);
        assert_eq!(
            service.verify_email("abc").await,
            Err(if failure.is_some() {
                AccountError::Database
            } else {
                AccountError::Configuration
            })
        );
        let state = repository.state.lock().unwrap();
        assert!(!state.committed);
        assert!(!state.events.contains(&"claim"));
        if failure.is_some() {
            assert_eq!(state.events.last(), Some(&"drop_rollback"));
        }
    }
}

#[test]
fn public_outcomes_preserve_codes_and_do_not_contain_credentials() {
    for purpose in [TokenPurpose::EmailVerification, TokenPurpose::PasswordReset] {
        assert_eq!(TokenActionOutcome::Applied.response(purpose).status, 204);
        for (outcome, code) in [
            (TokenActionOutcome::Invalid, "invalid_token"),
            (TokenActionOutcome::Expired, "expired_token"),
        ] {
            let response = outcome.response(purpose);
            assert_eq!(response.status, 400);
            let crate::http::ResponseBody::Bytes(body) = response.body else {
                panic!("expected JSON");
            };
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["code"], code);
            assert_eq!(body.as_object().unwrap().len(), 2);
        }
    }
}
