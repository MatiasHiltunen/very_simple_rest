use super::*;
use std::sync::{Arc, LazyLock, Mutex};
use vsr_core::testing::MockClock;

fn record() -> Account {
    static HASH: LazyLock<String> = LazyLock::new(|| bcrypt::hash("original-password", 4).unwrap());
    Account {
        id: 7,
        email: "owner@example.test".into(),
        password_hash: HASH.clone(),
        role: "admin".into(),
        email_verified_at: Some("verified".into()),
        created_at: Some("created".into()),
        updated_at: Some("revision".into()),
        has_email_verified_at_column: true,
        has_created_at_column: true,
        has_updated_at_column: true,
        claims: BTreeMap::from([("tenant_id".into(), Value::from(42))]),
    }
}

#[derive(Clone)]
struct Repository {
    record: fn() -> Option<Account>,
    failure: Option<AccountError>,
    cas: Result<bool, AccountError>,
    writes: Arc<Mutex<Vec<String>>>,
}

impl Default for Repository {
    fn default() -> Self {
        Self {
            record: || Some(record()),
            failure: None,
            cas: Ok(true),
            writes: Arc::default(),
        }
    }
}

impl AccountRepository for Repository {
    async fn by_email(&self, email: &str) -> Result<Option<Account>, AccountError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        Ok((self.record)().filter(|account| account.email == email))
    }

    async fn by_id(&self, id: i64) -> Result<Option<Account>, AccountError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        Ok((self.record)().filter(|account| account.id == id))
    }

    async fn compare_and_set_password(
        &self,
        expected: &Account,
        hash: &str,
    ) -> Result<bool, AccountError> {
        assert_eq!(expected.id, 7);
        assert_eq!(expected.password_hash, record().password_hash);
        assert_eq!(expected.updated_at.as_deref(), Some("revision"));
        if self.cas == Ok(true) {
            self.writes.lock().unwrap().push(hash.into());
        }
        self.cas
    }
}

#[derive(Clone, Default)]
struct Issuer {
    claims: Arc<Mutex<Vec<AccessClaims>>>,
    failure: bool,
}

impl AccessTokenIssuer for Issuer {
    fn issue(&self, claims: &AccessClaims) -> Result<String, AccountError> {
        if self.failure {
            return Err(AccountError::TokenGeneration);
        }
        self.claims.lock().unwrap().push(claims.clone());
        Ok("signed-token".into())
    }
}

fn policy() -> AccountPolicy {
    AccountPolicy {
        issuer: Some("issuer".into()),
        audience: Some("audience".into()),
        access_token_ttl_seconds: 3600,
        require_email_verification: true,
    }
}

fn service(
    repository: Repository,
    issuer: Issuer,
) -> AccountService<Repository, Issuer, MockClock> {
    AccountService::with_clock(repository, issuer, policy(), MockClock::at(1000)).unwrap()
}

#[tokio::test]
async fn login_normalizes_email_and_issues_exact_state_bound_claims() {
    let _guard = password::TEST_LOCK.lock().await;
    let issuer = Issuer::default();
    let service = service(Repository::default(), issuer.clone());
    assert_eq!(
        service
            .login(" OWNER@EXAMPLE.TEST ", "original-password")
            .await
            .unwrap(),
        "signed-token"
    );
    let claims = issuer.claims.lock().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(
        serde_json::to_value(&claims[0]).unwrap(),
        serde_json::json!({
            "sub": 7, "roles": ["admin"], "iss": "issuer", "aud": "audience", "exp": 4600,
            "tenant_id": 42, "_vsr_auth_state": record().auth_state(),
        })
    );
}

#[tokio::test]
async fn credential_failures_never_issue_tokens() {
    let _guard = password::TEST_LOCK.lock().await;
    let issuer = Issuer::default();
    let service = service(Repository::default(), issuer.clone());
    for (email, password) in [
        ("owner@example.test", "wrong"),
        ("absent@example.test", "original-password"),
        ("owner@example.test", ""),
        ("owner@example.test", &"x".repeat(73)),
    ] {
        assert_eq!(
            service.login(email, password).await,
            Err(AccountError::InvalidCredentials)
        );
    }
    assert!(issuer.claims.lock().unwrap().is_empty());
}

#[tokio::test]
async fn login_distinguishes_missing_schema_from_unverified_email() {
    let _guard = password::TEST_LOCK.lock().await;
    let mut repository = Repository::default();
    repository.record = || {
        let mut account = record();
        account.email_verified_at = None;
        Some(account)
    };
    assert_eq!(
        service(repository.clone(), Issuer::default())
            .login("owner@example.test", "original-password")
            .await,
        Err(AccountError::UnverifiedEmail)
    );
    repository.record = || {
        let mut account = record();
        account.email_verified_at = None;
        account.has_created_at_column = false;
        Some(account)
    };
    assert_eq!(
        service(repository.clone(), Issuer::default())
            .login("owner@example.test", "original-password")
            .await,
        Err(AccountError::MissingSchema)
    );
    let mut policy = policy();
    policy.require_email_verification = false;
    let service =
        AccountService::with_clock(repository, Issuer::default(), policy, MockClock::at(1000))
            .unwrap();
    assert!(
        service
            .login("owner@example.test", "original-password")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn invalid_clock_ttl_subject_and_signer_fail_closed() {
    let _guard = password::TEST_LOCK.lock().await;
    for ttl in [0, -1] {
        let mut policy = policy();
        policy.access_token_ttl_seconds = ttl;
        assert!(matches!(
            AccountService::new(Repository::default(), Issuer::default(), policy),
            Err(AccountError::Configuration)
        ));
    }
    for now in [-1, i64::MAX] {
        let service = AccountService::with_clock(
            Repository::default(),
            Issuer::default(),
            policy(),
            MockClock::at(now),
        )
        .unwrap();
        assert_eq!(
            service
                .login("owner@example.test", "original-password")
                .await,
            Err(AccountError::Configuration)
        );
    }
    let repository = Repository {
        record: || {
            let mut account = record();
            account.id = 0;
            Some(account)
        },
        ..Default::default()
    };
    assert_eq!(
        service(repository, Issuer::default())
            .login("owner@example.test", "original-password")
            .await,
        Err(AccountError::Configuration)
    );
    let issuer = Issuer {
        failure: true,
        ..Default::default()
    };
    assert_eq!(
        service(Repository::default(), issuer)
            .login("owner@example.test", "original-password")
            .await,
        Err(AccountError::TokenGeneration)
    );
}

#[tokio::test]
async fn account_response_contains_only_public_live_fields() {
    let _guard = password::TEST_LOCK.lock().await;
    let service = service(Repository::default(), Issuer::default());
    let info = serde_json::to_value(service.account(7).await.unwrap()).unwrap();
    assert_eq!(
        info,
        serde_json::json!({"id":7, "email":"owner@example.test", "role":"admin", "roles":["admin"],
        "email_verified":true, "email_verified_at":"verified", "created_at":"created", "updated_at":"revision", "tenant_id":42})
    );
    for id in [0, -1, 8] {
        assert_eq!(
            service.account(id).await.unwrap_err(),
            AccountError::MissingAccount
        );
    }
}

#[tokio::test]
async fn repository_failure_and_deleted_accounts_fail_closed() {
    let _guard = password::TEST_LOCK.lock().await;
    let repository = Repository {
        failure: Some(AccountError::Database),
        ..Default::default()
    };
    let service = service(repository, Issuer::default());
    assert_eq!(
        service
            .login("owner@example.test", "original-password")
            .await,
        Err(AccountError::Database)
    );
    assert_eq!(
        service.account(7).await.unwrap_err(),
        AccountError::Database
    );
    assert_eq!(
        service
            .change_password(7, "original-password", "changed-password")
            .await,
        Err(AccountError::Database)
    );
    let repository = Repository {
        record: || None,
        ..Default::default()
    };
    let service = super::tests::service(repository, Issuer::default());
    assert_eq!(
        service.account(7).await.unwrap_err(),
        AccountError::MissingAccount
    );
    assert_eq!(
        service
            .change_password(7, "original-password", "changed-password")
            .await,
        Err(AccountError::MissingAccount)
    );
}

#[tokio::test]
async fn password_change_requires_current_proof_and_valid_new_password() {
    let _guard = password::TEST_LOCK.lock().await;
    let repository = Repository::default();
    let service = service(repository.clone(), Issuer::default());
    for current in ["", "wrong", &"x".repeat(73)] {
        assert_eq!(
            service
                .change_password(7, current, "changed-password")
                .await,
            Err(AccountError::InvalidCurrentPassword)
        );
    }
    assert!(matches!(
        service
            .change_password(7, "original-password", "short")
            .await,
        Err(AccountError::Validation("password", _))
    ));
    assert_eq!(
        service
            .change_password(0, "original-password", "changed-password")
            .await,
        Err(AccountError::MissingAccount)
    );
    assert!(repository.writes.lock().unwrap().is_empty());
    service
        .change_password(7, "original-password", "changed-password")
        .await
        .unwrap();
    let writes = repository.writes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    assert!(bcrypt::verify("changed-password", &writes[0]).unwrap());
    assert!(!bcrypt::verify("original-password", &writes[0]).unwrap());
    assert!(writes[0].starts_with("$2b$12$"));
}

#[tokio::test]
async fn failed_password_cas_does_not_retry_or_report_success() {
    let _guard = password::TEST_LOCK.lock().await;
    for (cas, expected) in [
        (Ok(false), AccountError::ConcurrentChange),
        (Err(AccountError::Database), AccountError::Database),
    ] {
        let repository = Repository {
            cas,
            ..Default::default()
        };
        let service = service(repository.clone(), Issuer::default());
        assert_eq!(
            service
                .change_password(7, "original-password", "changed-password")
                .await,
            Err(expected)
        );
        assert!(repository.writes.lock().unwrap().is_empty());
    }
}

#[test]
fn validation_keeps_character_minimum_and_bcrypt_byte_maximum() {
    for email in ["", "a b@example.test", "a@b", "a@b@c.test"] {
        assert!(normalize_email(email).is_err());
    }
    assert!(validate_password(&"\u{e9}".repeat(7)).is_err());
    assert!(validate_password(&"\u{e9}".repeat(36)).is_ok());
    assert!(validate_password(&"\u{e9}".repeat(37)).is_err());
    assert!(validate_password(&"x".repeat(72)).is_ok());
}

#[test]
fn errors_have_stable_public_codes_without_internal_details() {
    for (error, status, code) in [
        (AccountError::InvalidCredentials, 401, "invalid_credentials"),
        (
            AccountError::InvalidCurrentPassword,
            401,
            "invalid_credentials",
        ),
        (AccountError::MissingAccount, 401, "invalid_token"),
        (AccountError::UnverifiedEmail, 403, "email_not_verified"),
        (AccountError::Database, 500, "internal_error"),
        (AccountError::TokenGeneration, 500, "internal_error"),
        (AccountError::Configuration, 500, "internal_error"),
        (AccountError::ConcurrentChange, 409, "account_changed"),
        (
            AccountError::Validation("password", "invalid"),
            400,
            "validation_error",
        ),
        (
            AccountError::Auth(AuthFailure::InvalidToken),
            401,
            "invalid_token",
        ),
    ] {
        let response = error.response();
        assert_eq!(response.status, status);
        let crate::http::ResponseBody::Bytes(body) = response.body else {
            panic!("expected serialized JSON");
        };
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], code);
        assert!(!body.to_string().contains("password_hash"));
    }
}
