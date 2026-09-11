use super::*;
use std::sync::{Arc, Mutex};

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
    deleted: bool,
    missing_target: bool,
    missing_schema: bool,
    locked: Vec<i64>,
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
    fn service(&self) -> ManagementService<Self, FixedClock> {
        ManagementService::with_clock(self.clone(), FixedClock(1_000_000))
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
fn record(id: i64) -> Account {
    Account {
        id,
        email: format!("{id}@example.test"),
        password_hash: "private-hash".into(),
        role: if id == 7 { "admin" } else { "user" }.into(),
        email_verified_at: None,
        created_at: Some("created".into()),
        updated_at: Some("1970-01-01T00:00:02.000000+00:00".into()),
        has_email_verified_at_column: true,
        has_created_at_column: true,
        has_updated_at_column: true,
        claims: BTreeMap::new(),
    }
}
fn actor() -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        user_id: "7".into(),
        email: None,
        roles: vec!["admin".into()],
        claims: Default::default(),
        is_admin: true,
        expires_at: None,
    }
}
fn input() -> UpdateManagedUserInput {
    UpdateManagedUserInput {
        role: Some(" operator ".into()),
        ..Default::default()
    }
}
fn schema() -> BTreeMap<String, ManagedClaim> {
    BTreeMap::from([
        (
            "tenant".into(),
            ManagedClaim {
                kind: ManagedClaimType::I64,
                nullable: false,
            },
        ),
        (
            "plan".into(),
            ManagedClaim {
                kind: ManagedClaimType::String,
                nullable: true,
            },
        ),
        (
            "staff".into(),
            ManagedClaim {
                kind: ManagedClaimType::Bool,
                nullable: true,
            },
        ),
    ])
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
        state.locked = ids.to_vec();
        Ok(ids
            .iter()
            .filter_map(|&id| {
                if (id == 7 && state.deleted) || (id != 7 && state.missing_target) {
                    return None;
                }
                let mut account = record(id);
                if id == 7 && state.demoted {
                    account.role = "user".into();
                }
                if state.missing_schema {
                    account.has_updated_at_column = false;
                }
                Some(account)
            })
            .collect())
    }
    async fn list(
        &self,
        limit: u32,
        offset: u32,
        email: Option<&str>,
    ) -> Result<Vec<AccountInfo>, ManagementError> {
        self.repository.step("list")?;
        assert_eq!((limit, offset, email), (100, 4, Some("example")));
        Ok(vec![record(1).into()])
    }
    async fn claim_schema(&self) -> Result<BTreeMap<String, ManagedClaim>, ManagementError> {
        self.repository.step("schema")?;
        Ok(schema())
    }
    async fn update(
        &self,
        id: i64,
        input: &UpdateManagedUserInput,
        timestamp: &str,
    ) -> Result<Account, ManagementError> {
        self.repository.step("update")?;
        if self.repository.0.lock().unwrap().fail == "pending" {
            std::future::pending::<()>().await;
        }
        assert_eq!(input.role.as_deref(), Some("operator"));
        assert_eq!(timestamp, "1970-01-01T00:00:02.000001+00:00");
        let mut account = record(id);
        account.role = input.role.clone().unwrap();
        account.updated_at = Some(timestamp.into());
        Ok(account)
    }
    async fn delete(&self, _id: i64) -> Result<(), ManagementError> {
        self.repository.step("delete")
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

#[tokio::test]
async fn authorization_precedes_storage_and_distrusts_admin_flag() {
    let repository = Repository::default();
    let service = repository.service();
    let mut actor = actor();
    actor.roles.clear();
    assert_eq!(
        service.get(&actor, 1).await.unwrap_err(),
        ManagementError::Forbidden
    );
    assert_eq!(
        service
            .list(&actor, &AdminListQuery::default())
            .await
            .unwrap_err(),
        ManagementError::Forbidden
    );
    assert_eq!(
        service.update(&actor, 1, input()).await.unwrap_err(),
        ManagementError::Forbidden
    );
    assert_eq!(
        service.delete(&actor, 1).await.unwrap_err(),
        ManagementError::Forbidden
    );
    assert!(repository.0.lock().unwrap().events.is_empty());
    actor.roles.push("admin".into());
    for id in ["0", "-1", "invalid"] {
        actor.user_id = id.into();
        assert!(matches!(
            service.get(&actor, 1).await,
            Err(ManagementError::Account(AccountError::Auth(
                AuthFailure::InvalidToken
            )))
        ));
    }
    assert!(repository.0.lock().unwrap().events.is_empty());
}

#[tokio::test]
async fn locked_current_actor_is_required_for_every_operation() {
    for deleted in [false, true] {
        for operation in 0..4 {
            let repository = Repository::default();
            repository.0.lock().unwrap().demoted = !deleted;
            repository.0.lock().unwrap().deleted = deleted;
            let service = repository.service();
            let result = match operation {
                0 => service.get(&actor(), 1).await.map(|_| ()),
                1 => service
                    .list(&actor(), &AdminListQuery::default())
                    .await
                    .map(|_| ()),
                2 => service.update(&actor(), 1, input()).await.map(|_| ()),
                _ => service.delete(&actor(), 1).await,
            };
            assert_eq!(
                result,
                Err(if deleted {
                    AccountError::MissingAccount.into()
                } else {
                    ManagementError::Forbidden
                })
            );
            assert_eq!(
                repository.0.lock().unwrap().events,
                ["begin", "lock", "rollback"]
            );
        }
    }
}

#[tokio::test]
async fn bounded_reads_and_atomic_updates_hide_password_material() {
    let repository = Repository::default();
    let service = repository.service();
    let page = service
        .list(
            &actor(),
            &AdminListQuery {
                limit: Some(900),
                offset: Some(4),
                email: Some(" example ".into()),
            },
        )
        .await
        .unwrap();
    assert_eq!(page.limit, 100);
    let updated = service.update(&actor(), 1, input()).await.unwrap();
    assert_eq!(updated.role, "operator");
    assert_eq!(repository.0.lock().unwrap().locked, [1, 7]);
    let public = serde_json::to_string(&updated).unwrap();
    assert!(!public.contains("private-hash"));
    assert!(!public.contains("password_hash"));
    assert!(!public.contains("auth_state"));
    service.get(&actor(), 7).await.unwrap();
    assert_eq!(repository.0.lock().unwrap().locked, [7]);
    service.delete(&actor(), 1).await.unwrap();
}

#[test]
fn claims_are_typed_nullable_and_allowlisted() {
    for (name, value, phrase) in [
        ("tenant", serde_json::json!(null), "cannot be null"),
        ("tenant", serde_json::json!(1.5), "must be an integer"),
        ("tenant", serde_json::json!(u64::MAX), "must be an integer"),
        ("tenant", serde_json::json!("1"), "must be an integer"),
        ("staff", serde_json::json!(1), "must be a boolean"),
        ("plan", serde_json::json!(true), "must be a string"),
        (
            "password_hash",
            serde_json::json!("injected"),
            "Unknown managed auth claim",
        ),
    ] {
        let error =
            validate_claims(&schema(), &BTreeMap::from([(name.into(), value)])).unwrap_err();
        let ManagementError::Validation(field, message) = error else {
            panic!("wrong error")
        };
        assert_eq!(field, format!("claims.{name}"));
        assert!(message.contains(phrase));
    }
    validate_claims(
        &schema(),
        &BTreeMap::from([
            ("tenant".into(), (-1).into()),
            ("staff".into(), true.into()),
            ("plan".into(), Value::Null),
        ]),
    )
    .unwrap();
    assert_eq!(
        validate_claims(
            &BTreeMap::new(),
            &BTreeMap::from([("tenant".into(), 1.into())])
        ),
        Err(ManagementError::ClaimsNotConfigured)
    );
}

#[tokio::test]
async fn invalid_changes_self_deletion_and_missing_schema_fail_closed() {
    let repository = Repository::default();
    let service = repository.service();
    assert_eq!(
        service.delete(&actor(), 7).await,
        Err(ManagementError::CannotDeleteSelf)
    );
    assert_eq!(
        service
            .update(&actor(), 1, UpdateManagedUserInput::default())
            .await
            .unwrap_err(),
        ManagementError::MissingChanges
    );
    assert!(matches!(
        service
            .update(
                &actor(),
                1,
                UpdateManagedUserInput {
                    role: Some(" ".into()),
                    ..Default::default()
                }
            )
            .await,
        Err(ManagementError::Validation(_, _))
    ));
    assert!(repository.0.lock().unwrap().events.is_empty());
    repository.0.lock().unwrap().missing_schema = true;
    assert_eq!(
        service.update(&actor(), 1, input()).await.unwrap_err(),
        AccountError::MissingSchema.into()
    );
    repository.0.lock().unwrap().missing_target = true;
    assert_eq!(
        service.get(&actor(), 1).await.unwrap_err(),
        ManagementError::NotFound
    );
    assert_eq!(
        service.delete(&actor(), 1).await,
        Err(ManagementError::NotFound)
    );
}

#[tokio::test]
async fn failed_storage_commit_and_cancellation_never_succeed() {
    for fail in ["begin", "lock", "schema", "update", "commit"] {
        let repository = Repository::default();
        repository.0.lock().unwrap().fail = fail;
        let mut input = input();
        input.claims.insert("tenant".into(), 4.into());
        assert_eq!(
            repository
                .service()
                .update(&actor(), 1, input)
                .await
                .unwrap_err(),
            AccountError::Database.into()
        );
        let events = &repository.0.lock().unwrap().events;
        assert_eq!(
            events.last(),
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
        repository.service().get(&actor(), 1).await.unwrap_err(),
        AccountError::Database.into()
    );
    assert_eq!(
        repository.0.lock().unwrap().events.last(),
        Some(&"drop_rollback")
    );
    let repository = Repository::default();
    repository.0.lock().unwrap().fail = "pending";
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            repository.service().update(&actor(), 1, input())
        )
        .await
        .is_err()
    );
    assert_eq!(
        repository.0.lock().unwrap().events.last(),
        Some(&"drop_rollback")
    );
}

#[test]
fn revisions_increase_despite_repeated_or_backward_clocks() {
    let mut previous = next_revision(1_000_000, None).unwrap();
    for now in [1_000_000, 500_000, 0] {
        let next = next_revision(now, Some(&previous)).unwrap();
        assert!(
            DateTime::parse_from_rfc3339(&next).unwrap()
                > DateTime::parse_from_rfc3339(&previous).unwrap()
        );
        previous = next;
    }
    assert_eq!(next_revision(-1, None), Err(AccountError::Configuration));
    assert_eq!(
        next_revision(i64::MAX, None),
        Err(AccountError::Configuration)
    );
}
