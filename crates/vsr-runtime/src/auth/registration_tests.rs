use super::super::{
    MailMessage,
    recovery_email::{RecoveryEmailPolicy, RecoveryToken},
};
use super::*;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone)]
struct FixedClock(i64);
impl Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.0 / 1_000_000
    }
    fn now_unix_micros(&self) -> i64 {
        self.0
    }
}

struct State {
    events: Vec<&'static str>,
    fail: &'static str,
    schema: u8,
    role: &'static str,
    input: Option<(String, String, String)>,
    timestamp: Option<String>,
    token: Option<(String, String, TokenPurpose)>,
    messages: Vec<MailMessage>,
}

#[derive(Clone)]
struct Fixture(Arc<Mutex<State>>);
impl Fixture {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            events: vec![],
            fail: "",
            schema: 7,
            role: "user",
            input: None,
            timestamp: None,
            token: None,
            messages: vec![],
        })))
    }
    fn step(&self, event: &'static str) -> Result<(), AccountError> {
        let mut state = self.0.lock().unwrap();
        state.events.push(event);
        if state.fail == event {
            Err(AccountError::Database)
        } else {
            Ok(())
        }
    }
}

struct Transaction {
    fixture: Fixture,
    finished: bool,
}
impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.finished {
            self.fixture.0.lock().unwrap().events.push("drop_rollback");
        }
    }
}
impl RegistrationRepository for Fixture {
    type Transaction = Transaction;
    async fn begin(&self) -> Result<Transaction, AccountError> {
        self.step("begin")?;
        Ok(Transaction {
            fixture: self.clone(),
            finished: false,
        })
    }
}
impl RegistrationTransaction for Transaction {
    async fn create(&self, email: &str, hash: &str, role: &str) -> Result<Account, AccountError> {
        self.fixture.step("create")?;
        let mut state = self.fixture.0.lock().unwrap();
        if state.fail == "duplicate" {
            return Err(AccountError::DuplicateEmail);
        }
        state.input = Some((email.into(), hash.into(), role.into()));
        Ok(Account {
            id: 7,
            email: email.into(),
            password_hash: hash.into(),
            role: state.role.into(),
            email_verified_at: None,
            created_at: None,
            updated_at: None,
            has_email_verified_at_column: state.schema & 1 != 0,
            has_created_at_column: state.schema & 2 != 0,
            has_updated_at_column: state.schema & 4 != 0,
            claims: BTreeMap::new(),
        })
    }
    async fn initialize(&self, id: i64, timestamp: &str) -> Result<(), AccountError> {
        assert_eq!(id, 7);
        self.fixture.step("initialize")?;
        self.fixture.0.lock().unwrap().timestamp = Some(timestamp.into());
        Ok(())
    }
    async fn mark_verified(&self, id: i64, timestamp: &str) -> Result<(), AccountError> {
        assert_eq!(id, 7);
        self.fixture.step("verify")?;
        assert_eq!(
            self.fixture.0.lock().unwrap().timestamp.as_deref(),
            Some(timestamp)
        );
        Ok(())
    }
    async fn commit(mut self) -> Result<(), AccountError> {
        self.fixture.step("commit")?;
        self.finished = true;
        Ok(())
    }
    async fn rollback(mut self) -> Result<(), AccountError> {
        self.fixture.step("rollback")?;
        self.finished = true;
        Ok(())
    }
}
impl RecoveryTokenStore for Transaction {
    async fn replace(
        &self,
        id: i64,
        email: &str,
        purpose: TokenPurpose,
        token: &RecoveryToken,
    ) -> Result<(), AccountError> {
        assert_eq!(id, 7);
        self.fixture.step("replace")?;
        self.fixture.0.lock().unwrap().token = Some((email.into(), token.digest().into(), purpose));
        Ok(())
    }
}
impl Mailer for Fixture {
    async fn send(&self, message: MailMessage) -> vsr_core::error::VsrResult<()> {
        let fail = {
            let mut state = self.0.lock().unwrap();
            state.events.push("send");
            state.messages.push(message);
            state.fail
        };
        if fail == "pending" {
            std::future::pending::<()>().await;
        }
        if fail == "send" {
            return Err(vsr_core::error::VsrError::Other(
                "private provider error".into(),
            ));
        }
        Ok(())
    }
}

fn sender(
    fixture: &Fixture,
    purpose: TokenPurpose,
    timeout: Duration,
) -> RecoveryEmailSender<Fixture, FixedClock> {
    RecoveryEmailSender::with_clock(
        fixture.clone(),
        RecoveryEmailPolicy {
            from: "noreply@example.test".into(),
            action_url: "https://app.example.test/auth/verify-email".into(),
            purpose,
            ttl_seconds: 300,
            delivery_timeout: timeout,
        },
        FixedClock(1_700_000_000_123_456),
    )
    .unwrap()
}
fn service(fixture: &Fixture, email: bool) -> RegistrationService<Fixture, Fixture, FixedClock> {
    RegistrationService::with_clock(
        fixture.clone(),
        email.then(|| {
            sender(
                fixture,
                TokenPurpose::EmailVerification,
                Duration::from_secs(30),
            )
        }),
        email,
        FixedClock(1_700_000_000_123_456),
    )
    .unwrap()
}

#[tokio::test]
async fn public_registration_normalizes_hashes_and_creates_only_a_normal_user() {
    let _guard = super::super::password::TEST_LOCK.lock().await;
    let fixture = Fixture::new();
    service(&fixture, false)
        .register(" Alice@EXAMPLE.TEST ", "secure-password")
        .await
        .unwrap();
    let (email, hash, role) = fixture.0.lock().unwrap().input.clone().unwrap();
    assert_eq!(
        (email.as_str(), role.as_str()),
        ("alice@example.test", "user")
    );
    assert!(hash.starts_with("$2b$12$"));
    assert!(password::verify("secure-password", &hash).await.unwrap());
    let state = fixture.0.lock().unwrap();
    assert_eq!(
        state.events,
        ["begin", "create", "initialize", "verify", "commit"]
    );
    assert_eq!(
        DateTime::parse_from_rfc3339(state.timestamp.as_deref().unwrap())
            .unwrap()
            .timestamp_micros(),
        1_700_000_000_123_456
    );
    assert!(state.token.is_none());
}

#[tokio::test]
async fn invalid_input_configuration_and_clock_never_open_a_transaction() {
    let fixture = Fixture::new();
    for (email, password) in [
        ("bad", "secure-password"),
        ("user@example.test", "short"),
        ("user@example.test", &"x".repeat(73)),
    ] {
        assert!(matches!(
            service(&fixture, false).register(email, password).await,
            Err(AccountError::Validation(_, _))
        ));
    }
    for now in [-1, i64::MAX] {
        let service = RegistrationService::<_, Fixture, _>::with_clock(
            fixture.clone(),
            None,
            false,
            FixedClock(now),
        )
        .unwrap();
        assert_eq!(
            service
                .register("user@example.test", "secure-password")
                .await,
            Err(AccountError::Configuration)
        );
    }
    assert!(matches!(
        RegistrationService::<_, Fixture, _>::with_clock(
            fixture.clone(),
            None,
            true,
            FixedClock(1)
        ),
        Err(AccountError::Configuration)
    ));
    assert!(matches!(
        RegistrationService::with_clock(
            fixture.clone(),
            Some(sender(
                &fixture,
                TokenPurpose::PasswordReset,
                Duration::from_secs(1)
            )),
            false,
            FixedClock(1)
        ),
        Err(AccountError::Configuration)
    ));
    assert!(fixture.0.lock().unwrap().events.is_empty());
}

#[tokio::test]
async fn legacy_schema_is_explicit_and_partial_schema_fails_closed() {
    for schema in 0..8 {
        let fixture = Fixture::new();
        fixture.0.lock().unwrap().schema = schema;
        let result = service(&fixture, false)
            .register_hashed("user@example.test", "hash", "now")
            .await;
        if schema == 0 || schema == 7 {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(AccountError::MissingSchema));
        }
        assert_eq!(
            fixture.0.lock().unwrap().events.contains(&"commit"),
            schema == 0 || schema == 7
        );
        if schema != 7 {
            let fixture = Fixture::new();
            fixture.0.lock().unwrap().schema = schema;
            assert_eq!(
                service(&fixture, true)
                    .register_hashed("user@example.test", "hash", "now")
                    .await,
                Err(AccountError::MissingSchema)
            );
            assert!(fixture.0.lock().unwrap().messages.is_empty());
        }
    }
}

#[tokio::test]
async fn verification_issues_only_a_digest_before_delivery_and_commit() {
    let fixture = Fixture::new();
    service(&fixture, true)
        .register_hashed("user@example.test", "hash", "now")
        .await
        .unwrap();
    let state = fixture.0.lock().unwrap();
    assert_eq!(
        state.events,
        ["begin", "create", "initialize", "replace", "send", "commit"]
    );
    let (email, digest, purpose) = state.token.as_ref().unwrap();
    assert_eq!(email, "user@example.test");
    assert_eq!(*purpose, TokenPurpose::EmailVerification);
    let url = url::Url::parse(state.messages[0].text_body.split("\n\n").nth(1).unwrap()).unwrap();
    let raw = url
        .query_pairs()
        .find(|(name, _)| name == "token")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(digest, &super::super::recovery::token_digest(&raw));
    assert_ne!(&raw, digest);
}

#[tokio::test]
async fn failures_never_commit_and_duplicate_errors_keep_the_public_contract() {
    for fail in [
        "begin",
        "create",
        "duplicate",
        "initialize",
        "verify",
        "replace",
        "send",
        "commit",
    ] {
        let fixture = Fixture::new();
        fixture.0.lock().unwrap().fail = fail;
        let result = service(&fixture, fail != "verify")
            .register_hashed("user@example.test", "hash", "now")
            .await;
        let expected = match fail {
            "duplicate" => AccountError::DuplicateEmail,
            "send" => AccountError::EmailDelivery,
            _ => AccountError::Database,
        };
        assert_eq!(result, Err(expected));
        let state = fixture.0.lock().unwrap();
        if fail == "commit" {
            assert_eq!(state.events.last(), Some(&"drop_rollback"));
        } else if fail != "begin" {
            assert_eq!(state.events.last(), Some(&"rollback"));
        }
        if fail != "commit" {
            assert!(!state.events.contains(&"commit"));
        }
    }
    let response = AccountError::DuplicateEmail.response();
    assert_eq!(response.status, 409);
    let body: serde_json::Value = match response.body {
        crate::http::ResponseBody::Json(body) => body,
        crate::http::ResponseBody::Bytes(bytes) => serde_json::from_slice(&bytes).unwrap(),
        _ => panic!("expected JSON error"),
    };
    assert_eq!(body["code"], "duplicate_email");
}

#[tokio::test]
async fn wrong_account_and_failed_rollback_cannot_be_reported_as_success() {
    let fixture = Fixture::new();
    fixture.0.lock().unwrap().role = "admin";
    assert_eq!(
        service(&fixture, false)
            .register_hashed("user@example.test", "hash", "now")
            .await,
        Err(AccountError::Database)
    );
    assert_eq!(
        fixture.0.lock().unwrap().events,
        ["begin", "create", "rollback"]
    );
    let fixture = Fixture::new();
    {
        let mut state = fixture.0.lock().unwrap();
        state.schema = 1;
        state.fail = "rollback";
    }
    assert_eq!(
        service(&fixture, false)
            .register_hashed("user@example.test", "hash", "now")
            .await,
        Err(AccountError::Database)
    );
    assert_eq!(
        fixture.0.lock().unwrap().events.last(),
        Some(&"drop_rollback")
    );
}

#[tokio::test]
async fn cancellation_and_delivery_timeout_roll_back_the_entire_registration() {
    let fixture = Fixture::new();
    fixture.0.lock().unwrap().fail = "pending";
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            service(&fixture, true).register_hashed("user@example.test", "hash", "now")
        )
        .await
        .is_err()
    );
    assert_eq!(
        fixture.0.lock().unwrap().events.last(),
        Some(&"drop_rollback")
    );
    assert!(!fixture.0.lock().unwrap().events.contains(&"commit"));
    let fixture = Fixture::new();
    fixture.0.lock().unwrap().fail = "pending";
    let service = RegistrationService::with_clock(
        fixture.clone(),
        Some(sender(
            &fixture,
            TokenPurpose::EmailVerification,
            Duration::from_millis(20),
        )),
        true,
        FixedClock(1),
    )
    .unwrap();
    assert_eq!(
        service
            .register_hashed("user@example.test", "hash", "now")
            .await,
        Err(AccountError::EmailDelivery)
    );
    assert_eq!(fixture.0.lock().unwrap().events.last(), Some(&"rollback"));
}
