use super::super::{
    MailMessage,
    management::{ManagedClaim, UpdateManagedUserInput},
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
#[derive(Default)]
struct State {
    events: Vec<&'static str>,
    fail: &'static str,
    demoted: bool,
    missing_actor: bool,
    missing_target: bool,
    verified: bool,
    missing_schema: bool,
    wrong_created_role: bool,
    locks: Vec<i64>,
    created_hash: Option<String>,
    token: Option<(i64, String, String, TokenPurpose)>,
    messages: Vec<MailMessage>,
}
#[derive(Clone, Default)]
struct Repository(Arc<Mutex<State>>);
impl Repository {
    fn step(&self, event: &'static str) -> Result<(), ManagementError> {
        let mut state = self.0.lock().unwrap();
        state.events.push(event);
        if state.fail == event {
            Err(AccountError::Database.into())
        } else {
            Ok(())
        }
    }
    fn service(&self, email: bool) -> ProvisioningService<Self, Self, FixedClock> {
        ProvisioningService::with_clock(
            self.clone(),
            email.then(|| sender(self)),
            FixedClock(1_000_000),
        )
        .unwrap()
    }
}
fn sender(repository: &Repository) -> RecoveryEmailSender<Repository, FixedClock> {
    sender_for(repository, TokenPurpose::EmailVerification)
}
fn sender_for(
    repository: &Repository,
    purpose: TokenPurpose,
) -> RecoveryEmailSender<Repository, FixedClock> {
    RecoveryEmailSender::with_clock(
        repository.clone(),
        RecoveryEmailPolicy {
            from: "noreply@example.test".into(),
            action_url: "https://app.example.test/auth/verify-email".into(),
            purpose,
            ttl_seconds: 60,
            delivery_timeout: Duration::from_millis(50),
        },
        FixedClock(1_000_000),
    )
    .unwrap()
}
fn input(invite: bool) -> CreateManagedUserInput {
    CreateManagedUserInput {
        email: " NEW@EXAMPLE.TEST ".into(),
        password: "provisioned-password".into(),
        role: Some(" operator ".into()),
        email_verified: None,
        send_verification_email: Some(invite),
    }
}
fn actor(id: i64, admin: bool) -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        user_id: id.to_string(),
        roles: vec![if admin { "admin" } else { "user" }.into()],
        is_admin: true,
        email: None,
        claims: Default::default(),
        expires_at: None,
    }
}
fn account(id: i64) -> Account {
    Account {
        id,
        email: if id == 1 {
            "admin@example.test"
        } else {
            "current@example.test"
        }
        .into(),
        password_hash: "private-hash".into(),
        role: if id == 1 { "admin" } else { "user" }.into(),
        email_verified_at: None,
        created_at: Some("initial".into()),
        updated_at: Some("initial".into()),
        has_email_verified_at_column: true,
        has_created_at_column: true,
        has_updated_at_column: true,
        claims: BTreeMap::new(),
    }
}
struct Transaction {
    repository: Repository,
    finished: bool,
}
impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.finished {
            self.repository
                .0
                .lock()
                .unwrap()
                .events
                .push("drop_rollback");
        }
    }
}
impl ManagementRepository for Repository {
    type Transaction = Transaction;
    async fn begin(&self) -> Result<Transaction, ManagementError> {
        self.step("begin")?;
        Ok(Transaction {
            repository: self.clone(),
            finished: false,
        })
    }
}
impl ManagementTransaction for Transaction {
    async fn lock_accounts(&self, ids: &[i64]) -> Result<Vec<Account>, ManagementError> {
        self.repository.step("lock")?;
        let mut state = self.repository.0.lock().unwrap();
        state.locks = ids.to_vec();
        Ok(ids
            .iter()
            .filter_map(|&id| {
                if (id == 1 && state.missing_actor) || (id == 2 && state.missing_target) {
                    return None;
                }
                let mut account = account(id);
                if id == 1 && state.demoted {
                    account.role = "user".into();
                }
                if id == 2 && state.verified {
                    account.email_verified_at = Some("verified".into());
                }
                if state.missing_schema {
                    account.has_created_at_column = false;
                }
                Some(account)
            })
            .collect())
    }
    async fn list(
        &self,
        _: u32,
        _: u32,
        _: Option<&str>,
    ) -> Result<Vec<AccountInfo>, ManagementError> {
        unreachable!()
    }
    async fn claim_schema(&self) -> Result<BTreeMap<String, ManagedClaim>, ManagementError> {
        unreachable!()
    }
    async fn update(
        &self,
        _: i64,
        _: &UpdateManagedUserInput,
        _: &str,
    ) -> Result<Account, ManagementError> {
        unreachable!()
    }
    async fn delete(&self, _: i64) -> Result<(), ManagementError> {
        unreachable!()
    }
    async fn commit(mut self) -> Result<(), ManagementError> {
        self.repository.step("commit")?;
        self.finished = true;
        Ok(())
    }
    async fn rollback(mut self) -> Result<(), ManagementError> {
        self.repository.step("rollback")?;
        self.finished = true;
        Ok(())
    }
}
impl ProvisioningTransaction for Transaction {
    async fn create(
        &self,
        email: &str,
        hash: &str,
        role: &str,
        timestamp: &str,
        verified: bool,
    ) -> Result<Account, ManagementError> {
        self.repository.step("create")?;
        let mut state = self.repository.0.lock().unwrap();
        if state.fail == "duplicate" {
            return Err(AccountError::DuplicateEmail.into());
        }
        state.created_hash = Some(hash.into());
        let mut account = account(3);
        account.email = email.into();
        account.password_hash = hash.into();
        account.role = if state.wrong_created_role {
            "wrong"
        } else {
            role
        }
        .into();
        account.created_at = Some(timestamp.into());
        account.updated_at = Some(timestamp.into());
        account.email_verified_at = verified.then(|| timestamp.into());
        account.has_created_at_column = !state.missing_schema;
        Ok(account)
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
        self.repository
            .step("replace")
            .map_err(|_| AccountError::Database)?;
        self.repository.0.lock().unwrap().token =
            Some((id, email.into(), token.digest().into(), purpose));
        Ok(())
    }
}
impl Mailer for Repository {
    async fn send(&self, message: MailMessage) -> vsr_core::error::VsrResult<()> {
        self.0.lock().unwrap().events.push("send");
        let fail = self.0.lock().unwrap().fail;
        if fail == "pending" {
            std::future::pending::<()>().await;
        }
        if fail == "send" {
            return Err(vsr_core::error::VsrError::Other(
                "private provider details".into(),
            ));
        }
        self.0.lock().unwrap().messages.push(message);
        Ok(())
    }
}

#[tokio::test]
async fn public_creation_normalizes_hashes_and_redacts_passwords() {
    let _guard = super::super::password::TEST_LOCK.lock().await;
    let repository = Repository::default();
    let mut input = input(false);
    input.email_verified = Some(true);
    let result = repository
        .service(false)
        .create(&actor(1, true), &input)
        .await
        .unwrap();
    assert_eq!(result.email, "new@example.test");
    assert_eq!(result.role, "operator");
    assert_eq!(
        result.created_at.as_deref(),
        Some("1970-01-01T00:00:01.000000+00:00")
    );
    assert!(result.email_verified);
    let hash = repository.0.lock().unwrap().created_hash.clone().unwrap();
    assert!(password::verify(&input.password, &hash).await.unwrap());
    assert!(!format!("{input:?}").contains(&input.password));
    assert!(!serde_json::to_string(&result).unwrap().contains(&hash));
    assert_eq!(
        repository.0.lock().unwrap().events,
        ["begin", "lock", "create", "commit"]
    );
    input.role = Some(" ".into());
    assert_eq!(
        repository
            .service(false)
            .create(&actor(1, true), &input)
            .await
            .unwrap()
            .role,
        "user"
    );
}

#[tokio::test]
async fn input_and_identity_validation_precede_transactions() {
    let repository = Repository::default();
    let service = repository.service(false);
    assert_eq!(
        service
            .create(&actor(2, false), &input(false))
            .await
            .unwrap_err(),
        ManagementError::Forbidden
    );
    assert_eq!(
        service.resend_managed(&actor(2, false), 1).await,
        Err(ManagementError::Forbidden)
    );
    assert!(matches!(
        service.resend_account(&actor(0, false)).await,
        Err(ManagementError::Account(AccountError::Auth(_)))
    ));
    for (field, value) in [
        ("email", "invalid"),
        ("password", "short"),
        ("role", "two roles"),
    ] {
        let mut input = input(false);
        match field {
            "email" => input.email = value.into(),
            "password" => input.password = value.into(),
            _ => input.role = Some(value.into()),
        }
        assert!(matches!(
            service.create(&actor(1, true), &input).await,
            Err(ManagementError::Account(AccountError::Validation(_, _)))
        ));
    }
    assert_eq!(
        service
            .create(&actor(1, true), &input(true))
            .await
            .unwrap_err(),
        AccountError::EmailUnavailable.into()
    );
    let mut invalid = input(true);
    invalid.email_verified = Some(true);
    assert_eq!(
        service.create(&actor(1, true), &invalid).await.unwrap_err(),
        ManagementError::InvalidInviteState
    );
    assert_eq!(
        service.resend_account(&actor(2, false)).await,
        Err(AccountError::EmailUnavailable.into())
    );
    assert!(repository.0.lock().unwrap().events.is_empty());
    for now in [-1, i64::MAX] {
        let service = ProvisioningService::with_clock(
            repository.clone(),
            None::<RecoveryEmailSender<Repository, FixedClock>>,
            FixedClock(now),
        )
        .unwrap();
        assert_eq!(
            service
                .create(&actor(1, true), &input(false))
                .await
                .unwrap_err(),
            AccountError::Configuration.into()
        );
    }
    let wrong = sender_for(&repository, TokenPurpose::PasswordReset);
    assert!(matches!(
        ProvisioningService::with_clock(repository.clone(), Some(wrong), FixedClock(0)),
        Err(ManagementError::Account(AccountError::Configuration))
    ));
}

#[tokio::test]
async fn creation_rechecks_live_admin_and_requires_complete_initialized_snapshot() {
    for (demoted, missing, schema, wrong_role, error) in [
        (true, false, false, false, ManagementError::Forbidden),
        (
            false,
            true,
            false,
            false,
            AccountError::MissingAccount.into(),
        ),
        (
            false,
            false,
            true,
            false,
            AccountError::MissingSchema.into(),
        ),
        (false, false, false, true, AccountError::Database.into()),
    ] {
        let repository = Repository::default();
        {
            let mut state = repository.0.lock().unwrap();
            state.demoted = demoted;
            state.missing_actor = missing;
            state.missing_schema = schema;
            state.wrong_created_role = wrong_role;
        }
        assert_eq!(
            repository
                .service(false)
                .create_hashed(1, &input(false), "new@example.test", "hash", "user", "now")
                .await
                .unwrap_err(),
            error
        );
        assert_eq!(
            repository.0.lock().unwrap().events.last(),
            Some(&"rollback")
        );
        assert!(repository.0.lock().unwrap().messages.is_empty());
    }
}

#[tokio::test]
async fn invitations_use_email_bound_digest_and_send_before_commit() {
    let repository = Repository::default();
    repository
        .service(true)
        .create_hashed(
            1,
            &input(true),
            "new@example.test",
            "hash",
            "operator",
            "now",
        )
        .await
        .unwrap();
    let state = repository.0.lock().unwrap();
    assert_eq!(
        state.events,
        ["begin", "lock", "create", "replace", "send", "commit"]
    );
    let (id, email, digest, purpose) = state.token.as_ref().unwrap();
    assert_eq!(*id, 3);
    assert_eq!(email, "new@example.test");
    assert_eq!(*purpose, TokenPurpose::EmailVerification);
    let message = &state.messages[0];
    assert_eq!(message.to, *email);
    let url = url::Url::parse(message.text_body.split("\n\n").nth(1).unwrap()).unwrap();
    let raw = url
        .query_pairs()
        .find(|(key, _)| key == "token")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(*digest, super::super::recovery::token_digest(&raw));
    assert_ne!(*digest, raw);
}

#[tokio::test]
async fn resend_uses_locked_current_recipient_and_preserves_noop_and_error_contracts() {
    let repository = Repository::default();
    let service = repository.service(true);
    let mut own = actor(2, false);
    own.email = Some("stale@example.test".into());
    assert_eq!(
        service.resend_account(&own).await.unwrap(),
        VerificationDelivery::Sent
    );
    assert_eq!(repository.0.lock().unwrap().locks, [2]);
    assert_eq!(
        repository.0.lock().unwrap().messages[0].to,
        "current@example.test"
    );
    assert_eq!(
        service.resend_managed(&actor(1, true), 2).await.unwrap(),
        VerificationDelivery::Sent
    );
    assert_eq!(repository.0.lock().unwrap().locks, [1, 2]);
    repository.0.lock().unwrap().verified = true;
    let count = repository.0.lock().unwrap().messages.len();
    assert_eq!(
        service.resend_account(&own).await.unwrap(),
        VerificationDelivery::AlreadyVerified
    );
    assert_eq!(
        service.resend_managed(&actor(1, true), 2).await.unwrap(),
        VerificationDelivery::AlreadyVerified
    );
    assert_eq!(repository.0.lock().unwrap().messages.len(), count);
    repository.0.lock().unwrap().missing_target = true;
    assert_eq!(
        service.resend_account(&own).await,
        Err(AccountError::MissingAccount.into())
    );
    assert_eq!(
        service.resend_managed(&actor(1, true), 2).await,
        Err(ManagementError::NotFound)
    );
    repository.0.lock().unwrap().demoted = true;
    assert_eq!(
        service.resend_managed(&actor(1, true), 2).await,
        Err(ManagementError::Forbidden)
    );
    assert_eq!(VerificationDelivery::Sent.response().status, 202);
    assert_eq!(VerificationDelivery::AlreadyVerified.response().status, 204);
}

#[tokio::test]
async fn create_failures_duplicate_commit_and_rollback_errors_never_report_success() {
    for fail in [
        "begin",
        "lock",
        "create",
        "duplicate",
        "replace",
        "send",
        "commit",
    ] {
        let repository = Repository::default();
        repository.0.lock().unwrap().fail = fail;
        let result = repository
            .service(true)
            .create_hashed(1, &input(true), "new@example.test", "hash", "user", "now")
            .await;
        assert_eq!(
            result.unwrap_err(),
            match fail {
                "duplicate" => AccountError::DuplicateEmail.into(),
                "send" => AccountError::EmailDelivery.into(),
                _ => AccountError::Database.into(),
            }
        );
        let state = repository.0.lock().unwrap();
        assert_eq!(
            state.events.last(),
            Some(&match fail {
                "begin" => "begin",
                "commit" => "drop_rollback",
                _ => "rollback",
            })
        );
    }
    let repository = Repository::default();
    repository.0.lock().unwrap().fail = "rollback";
    repository.0.lock().unwrap().demoted = true;
    assert_eq!(
        repository
            .service(true)
            .resend_managed(&actor(1, true), 2)
            .await,
        Err(AccountError::Database.into())
    );
    assert_eq!(
        repository.0.lock().unwrap().events.last(),
        Some(&"drop_rollback")
    );
}

#[tokio::test]
async fn delivery_timeout_and_cancellation_roll_back_unfinished_resend() {
    let repository = Repository::default();
    repository.0.lock().unwrap().fail = "pending";
    assert_eq!(
        repository
            .service(true)
            .resend_account(&actor(2, false))
            .await,
        Err(AccountError::EmailDelivery.into())
    );
    assert_eq!(
        repository.0.lock().unwrap().events.last(),
        Some(&"rollback")
    );
    let result = tokio::time::timeout(
        Duration::from_millis(5),
        repository.service(true).resend_account(&actor(2, false)),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(
        repository.0.lock().unwrap().events.last(),
        Some(&"drop_rollback")
    );
}
