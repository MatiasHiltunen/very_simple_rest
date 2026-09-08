use super::*;
use std::sync::{Arc, Mutex};
use vsr_core::error::{VsrError, VsrResult};

struct FixedClock(i64);
impl Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.0 / 1_000_000
    }
    fn now_unix_micros(&self) -> i64 {
        self.0
    }
}

#[test]
fn token_entropy_expiry_and_failure_are_checked() {
    let clock = FixedClock(1_700_000_000_123_456);
    let token = RecoveryToken::generate_with(60, &clock, |bytes| {
        bytes.fill(0xab);
        Ok(())
    })
    .unwrap();
    assert_eq!(token.raw(), "ab".repeat(32));
    assert_eq!(token.digest(), token_digest(token.raw()));
    assert_eq!(
        DateTime::parse_from_rfc3339(token.expires_at())
            .unwrap()
            .timestamp_micros(),
        clock.0 + 60_000_000
    );
    for (ttl, now) in [
        (0, clock.0),
        (-1, clock.0),
        (i64::MAX, clock.0),
        (1, -1),
        (1, i64::MAX),
    ] {
        assert!(matches!(
            RecoveryToken::generate_with(ttl, &FixedClock(now), |_| panic!(
                "entropy must not be requested"
            )),
            Err(AccountError::Configuration)
        ));
    }
    assert!(matches!(
        RecoveryToken::generate_with(60, &clock, |_| Err(AccountError::TokenGeneration)),
        Err(AccountError::TokenGeneration)
    ));
    let a = RecoveryToken::generate(60, &clock).unwrap();
    let b = RecoveryToken::generate(60, &clock).unwrap();
    assert_eq!(a.raw().len(), 64);
    assert_ne!(a.raw(), b.raw());
}

fn policy(purpose: TokenPurpose) -> RecoveryEmailPolicy {
    RecoveryEmailPolicy {
        from: "App <noreply@example.test>".into(),
        action_url: "https://app.example.test/api/auth/action".into(),
        purpose,
        ttl_seconds: 300,
        delivery_timeout: Duration::from_millis(20),
    }
}

#[derive(Default)]
struct State {
    absent: bool,
    verified: bool,
    lookup_error: bool,
    store_error: bool,
    mail_error: bool,
    mail_pending: bool,
    commit_error: bool,
    rollback_error: bool,
    begins: usize,
    commits: usize,
    rollbacks: usize,
    lookup: String,
    stored: Vec<(i64, String, TokenPurpose, String, String)>,
    messages: Vec<MailMessage>,
}

#[derive(Clone, Default)]
struct Fixture(Arc<Mutex<State>>);
struct Transaction {
    fixture: Fixture,
    finished: bool,
}
impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.finished {
            self.fixture.0.lock().unwrap().rollbacks += 1;
        }
    }
}
impl RecoveryEmailRepository for Fixture {
    type Transaction = Transaction;
    async fn begin(&self) -> Result<Transaction, AccountError> {
        self.0.lock().unwrap().begins += 1;
        Ok(Transaction {
            fixture: self.clone(),
            finished: false,
        })
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
        let mut state = self.fixture.0.lock().unwrap();
        if state.store_error {
            return Err(AccountError::Database);
        }
        state.stored.push((
            id,
            email.to_owned(),
            purpose,
            token.digest().to_owned(),
            token.expires_at().to_owned(),
        ));
        Ok(())
    }
}
impl RecoveryEmailTransaction for Transaction {
    async fn recipient(&self, email: &str) -> Result<Option<RecoveryRecipient>, AccountError> {
        let mut state = self.fixture.0.lock().unwrap();
        state.lookup = email.to_owned();
        if state.lookup_error {
            return Err(AccountError::Database);
        }
        Ok((!state.absent).then(|| RecoveryRecipient {
            id: 7,
            email: email.into(),
            verified: state.verified,
        }))
    }
    async fn commit(mut self) -> Result<(), AccountError> {
        if self.fixture.0.lock().unwrap().commit_error {
            return Err(AccountError::Database);
        }
        self.finished = true;
        self.fixture.0.lock().unwrap().commits += 1;
        Ok(())
    }
    async fn rollback(mut self) -> Result<(), AccountError> {
        if self.fixture.0.lock().unwrap().rollback_error {
            return Err(AccountError::Database);
        }
        self.finished = true;
        self.fixture.0.lock().unwrap().rollbacks += 1;
        Ok(())
    }
}
impl Mailer for Fixture {
    async fn send(&self, message: MailMessage) -> VsrResult<()> {
        let pending = {
            let mut state = self.0.lock().unwrap();
            state.messages.push(message);
            if state.mail_error {
                return Err(VsrError::Other(
                    "secret provider credentials and token".into(),
                ));
            }
            state.mail_pending
        };
        if pending {
            std::future::pending::<()>().await;
        }
        Ok(())
    }
}
impl Fixture {
    fn service(&self, purpose: TokenPurpose) -> RecoveryEmailService<Self, Self, FixedClock> {
        RecoveryEmailService::new(
            self.clone(),
            RecoveryEmailSender::with_clock(
                self.clone(),
                policy(purpose),
                FixedClock(1_700_000_000_123_456),
            )
            .unwrap(),
        )
    }
}

#[test]
fn action_urls_reject_untrusted_or_insecure_forms() {
    for url in [
        "https://app.example.test/reset",
        "http://localhost:8000/reset",
        "http://127.0.0.1/reset",
        "http://[::1]/reset",
    ] {
        let mut p = policy(TokenPurpose::PasswordReset);
        p.action_url = url.into();
        assert!(RecoveryEmailSender::new(Fixture::default(), p).is_ok());
    }
    for url in [
        "/reset",
        "javascript:alert(1)",
        "file:///reset",
        "http://app.example.test/reset",
        "https://user:pass@app.example.test/reset",
        "https://app.example.test/reset?token=bad",
        "https://app.example.test/reset#bad",
        "http://localhost.evil.test/reset",
    ] {
        let mut p = policy(TokenPurpose::PasswordReset);
        p.action_url = url.into();
        assert!(
            matches!(
                RecoveryEmailSender::new(Fixture::default(), p),
                Err(AccountError::Configuration)
            ),
            "{url}"
        );
    }
    for i in 0..4 {
        let mut p = policy(TokenPurpose::PasswordReset);
        match i {
            0 => p.ttl_seconds = 0,
            1 => p.ttl_seconds = i64::MAX,
            2 => p.delivery_timeout = Duration::ZERO,
            _ => p.from = "mail\r\nBcc: other@example.test".into(),
        }
        assert!(RecoveryEmailSender::new(Fixture::default(), p).is_err());
    }
}

#[tokio::test]
async fn requests_normalize_bind_digest_and_send_both_templates() {
    for purpose in [TokenPurpose::EmailVerification, TokenPurpose::PasswordReset] {
        let fixture = Fixture::default();
        fixture
            .service(purpose)
            .request(" Owner@EXAMPLE.TEST ")
            .await
            .unwrap();
        let state = fixture.0.lock().unwrap();
        assert_eq!(state.lookup, "owner@example.test");
        assert_eq!((state.commits, state.rollbacks), (1, 0));
        let message = &state.messages[0];
        assert_eq!(message.subject, purpose.subject());
        assert_eq!(message.to, "owner@example.test");
        let url = Url::parse(message.text_body.split("\n\n").nth(1).unwrap()).unwrap();
        let raw = url
            .query_pairs()
            .find(|(k, _)| k == "token")
            .unwrap()
            .1
            .into_owned();
        assert_eq!(state.stored[0].0, 7);
        assert_eq!(state.stored[0].1, message.to);
        assert_eq!(state.stored[0].2, purpose);
        assert_eq!(state.stored[0].3, token_digest(&raw));
        assert!(!format!("{message:?}").contains(&raw));
        assert!(message.html_body.as_ref().unwrap().contains(url.as_str()));
    }
}

#[test]
fn email_html_is_escaped_and_debug_is_redacted() {
    let message = recovery_message(
        "sender",
        "recipient",
        TokenPurpose::PasswordReset,
        "https://app.example/reset?x=\"<'&",
    );
    let html = message.html_body.as_ref().unwrap();
    assert!(html.contains("&quot;&lt;&#39;&amp;"));
    assert_eq!(format!("{message:?}"), "MailMessage { .. }");
}

#[tokio::test]
async fn absent_verified_and_invalid_requests_do_not_issue() {
    for absent in [true, false] {
        let fixture = Fixture::default();
        {
            let mut state = fixture.0.lock().unwrap();
            state.absent = absent;
            state.verified = !absent;
        }
        fixture
            .service(TokenPurpose::EmailVerification)
            .request("owner@example.test")
            .await
            .unwrap();
        let state = fixture.0.lock().unwrap();
        assert_eq!((state.commits, state.rollbacks), (0, 1));
        assert!(state.stored.is_empty() && state.messages.is_empty());
    }
    let fixture = Fixture::default();
    assert!(matches!(
        fixture
            .service(TokenPurpose::PasswordReset)
            .request("bad")
            .await,
        Err(AccountError::Validation(..))
    ));
    assert_eq!(fixture.0.lock().unwrap().begins, 0);
    fixture.0.lock().unwrap().verified = true;
    fixture
        .service(TokenPurpose::PasswordReset)
        .request("owner@example.test")
        .await
        .unwrap();
    assert_eq!(fixture.0.lock().unwrap().commits, 1);
}

#[tokio::test]
async fn repository_mail_timeout_and_commit_errors_roll_back() {
    for failure in 0..6 {
        let fixture = Fixture::default();
        {
            let mut s = fixture.0.lock().unwrap();
            match failure {
                0 => s.lookup_error = true,
                1 => s.store_error = true,
                2 => s.mail_error = true,
                3 => s.mail_pending = true,
                4 => s.commit_error = true,
                _ => {
                    s.mail_error = true;
                    s.rollback_error = true;
                }
            }
        }
        let error = fixture
            .service(TokenPurpose::PasswordReset)
            .request("owner@example.test")
            .await
            .unwrap_err();
        assert_eq!(
            error,
            if (2..=3).contains(&failure) {
                AccountError::EmailDelivery
            } else {
                AccountError::Database
            }
        );
        let s = fixture.0.lock().unwrap();
        assert_eq!((s.commits, s.rollbacks), (0, 1));
        assert_eq!(s.messages.len(), usize::from(failure >= 2));
        assert!(!format!("{:?}", error.response()).contains("secret provider"));
    }
}

#[tokio::test]
async fn cancellation_during_delivery_drops_the_transaction() {
    let fixture = Fixture::default();
    fixture.0.lock().unwrap().mail_pending = true;
    let service = fixture.service(TokenPurpose::PasswordReset);
    let task = tokio::spawn(async move { service.request("owner@example.test").await });
    while fixture.0.lock().unwrap().messages.is_empty() {
        tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(fixture.0.lock().unwrap().rollbacks, 1);
}
