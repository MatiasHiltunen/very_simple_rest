use super::tests::{actor, close, database, drivers};
use super::*;
use sqlx::Row;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use vsr_runtime::auth::{
    MailMessage,
    provisioning::{CreateManagedUserInput, VerificationDelivery},
    recovery_email::{RecoveryEmailPolicy, RecoveryEmailSender},
};

#[derive(Clone, Default)]
struct Mailbox {
    messages: Arc<Mutex<Vec<MailMessage>>>,
    fail: Arc<AtomicBool>,
    pending: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
}
impl Mailer for Mailbox {
    async fn send(&self, message: MailMessage) -> vsr_core::error::VsrResult<()> {
        self.entered.notify_one();
        if self.pending.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(vsr_core::error::VsrError::Other(
                "private provider error".into(),
            ));
        }
        self.messages.lock().unwrap().push(message);
        Ok(())
    }
}
fn service(
    db: &DbPool,
    settings: &AuthSettings,
    mail: Option<&Mailbox>,
) -> ProvisioningService<Repository, Mailbox> {
    ProvisioningService::new(
        Repository {
            db: db.clone(),
            settings: settings.clone(),
        },
        mail.map(|mail| {
            RecoveryEmailSender::new(
                mail.clone(),
                RecoveryEmailPolicy {
                    from: "noreply@example.test".into(),
                    action_url: "https://app.example.test/auth/verify-email".into(),
                    purpose: TokenPurpose::EmailVerification,
                    ttl_seconds: 300,
                    delivery_timeout: Duration::from_secs(2),
                },
            )
            .unwrap()
        }),
    )
    .unwrap()
}
fn input(email: &str, invite: bool) -> CreateManagedUserInput {
    CreateManagedUserInput {
        email: email.into(),
        password: "provisioned-password".into(),
        role: Some(" operator ".into()),
        email_verified: None,
        send_verification_email: Some(invite),
    }
}
async fn count(db: &DbPool, table: &str) -> i64 {
    query(&format!("SELECT COUNT(*) AS count FROM {table}"))
        .fetch_one(db)
        .await
        .unwrap()
        .try_get("count")
        .unwrap()
}
fn raw_token(mail: &Mailbox, index: usize) -> String {
    let messages = mail.messages.lock().unwrap();
    let url = url::Url::parse(messages[index].text_body.split("\n\n").nth(1).unwrap()).unwrap();
    url.query_pairs()
        .find(|(key, _)| key == "token")
        .unwrap()
        .1
        .into_owned()
}

#[cfg(all(feature = "postgres", feature = "mysql"))]
pub(super) async fn verify_server_flows(db: &DbPool) {
    let backend = db_ops::detect_auth_backend(db).await.unwrap();
    query(&format!(
        "UPDATE {} SET role = 'admin' WHERE id = 1",
        super::super::auth_user_table_ident(backend)
    ))
    .execute(db)
    .await
    .unwrap();
    let mailbox = Mailbox::default();
    let service = service(db, &AuthSettings::default(), Some(&mailbox));
    let admin = actor();
    let a = input("SERVER-PROVISIONED@example.test", true);
    let b = input("server-provisioned@example.test", true);
    let (a, b) = tokio::join!(service.create(&admin, &a), service.create(&admin, &b));
    let created = match (a, b) {
        (Ok(account), Err(ManagementError::Account(AccountError::DuplicateEmail)))
        | (Err(ManagementError::Account(AccountError::DuplicateEmail)), Ok(account)) => account,
        _ => panic!("expected one provisioned account and one duplicate conflict"),
    };
    assert!(!created.email_verified);
    assert!(created.created_at.is_some());
    assert!(created.updated_at.is_some());
    assert_eq!(mailbox.messages.lock().unwrap().len(), 1);
    let first = raw_token(&mailbox, 0);
    assert_eq!(
        service.resend_managed(&admin, created.id).await.unwrap(),
        VerificationDelivery::Sent
    );
    let latest = raw_token(&mailbox, 1);
    mailbox.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        service.resend_managed(&admin, created.id).await,
        Err(AccountError::EmailDelivery.into())
    );
    mailbox.fail.store(false, Ordering::SeqCst);
    let recovery = super::super::builtin_recovery_service(db.clone());
    assert_eq!(
        recovery.verify_email(&first).await.unwrap(),
        vsr_runtime::auth::recovery::TokenActionOutcome::Invalid
    );
    assert_eq!(
        recovery.verify_email(&latest).await.unwrap(),
        vsr_runtime::auth::recovery::TokenActionOutcome::Applied
    );
    assert_eq!(
        service.resend_managed(&admin, created.id).await.unwrap(),
        VerificationDelivery::AlreadyVerified
    );
    assert_eq!(mailbox.messages.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn provisioning_local_drivers_create_initialized_accounts_and_serialize_duplicates() {
    let _guard = super::super::PASSWORD_TEST_LOCK.lock().await;
    for driver in drivers() {
        let (db, directory, settings) = database(driver, true).await;
        let mailbox = Mailbox::default();
        let service = service(&db, &settings, Some(&mailbox));
        let mut direct = input(" DIRECT@EXAMPLE.TEST ", false);
        direct.email_verified = Some(true);
        let created = service.create(&actor(), &direct).await.unwrap();
        assert_eq!(created.email, "direct@example.test");
        assert_eq!(created.role, "operator");
        assert!(created.email_verified);
        assert!(created.created_at.is_some());
        assert!(created.updated_at.is_some());
        assert_eq!(created.claims["tenant_id"], 7);
        let account =
            db_ops::load_authenticated_user_by_id_with_settings(&db, created.id, &settings)
                .await
                .unwrap()
                .unwrap();
        assert!(
            vsr_runtime::auth::password::verify(&direct.password, &account.password_hash)
                .await
                .unwrap()
        );
        assert!(mailbox.messages.lock().unwrap().is_empty());
        let admin = actor();
        let a = input(" INVITED@example.test ", true);
        let b = input("invited@example.test", true);
        let (a, b) = tokio::join!(service.create(&admin, &a), service.create(&admin, &b));
        assert!(matches!(
            (a, b),
            (
                Ok(_),
                Err(ManagementError::Account(AccountError::DuplicateEmail))
            ) | (
                Err(ManagementError::Account(AccountError::DuplicateEmail)),
                Ok(_)
            )
        ));
        assert_eq!(count(&db, "user").await, 4);
        assert_eq!(count(&db, "auth_user_token").await, 1);
        assert_eq!(mailbox.messages.lock().unwrap().len(), 1);
        let raw = raw_token(&mailbox, 0);
        let stored = query("SELECT token_hash, requested_email FROM auth_user_token")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(
            stored.try_get::<String, _>("token_hash").unwrap(),
            super::super::helpers::hash_auth_token(&raw)
        );
        assert_eq!(
            stored.try_get::<String, _>("requested_email").unwrap(),
            "invited@example.test"
        );
        let recovery = super::super::builtin_recovery_service(db.clone());
        assert_eq!(
            recovery.verify_email(&raw).await.unwrap(),
            vsr_runtime::auth::recovery::TokenActionOutcome::Applied
        );
        assert_eq!(
            recovery.verify_email(&raw).await.unwrap(),
            vsr_runtime::auth::recovery::TokenActionOutcome::Invalid
        );
        drop(recovery);
        drop(service);
        close(db, directory).await;
    }
}

#[tokio::test]
async fn provisioning_local_drivers_roll_back_failed_invites_and_cancelled_creation() {
    let _guard = super::super::PASSWORD_TEST_LOCK.lock().await;
    for driver in drivers() {
        let (db, directory, settings) = database(driver, true).await;
        let mailbox = Mailbox::default();
        mailbox.fail.store(true, Ordering::SeqCst);
        let service = Arc::new(service(&db, &settings, Some(&mailbox)));
        assert_eq!(
            service
                .create(&actor(), &input("new@example.test", true))
                .await
                .unwrap_err(),
            AccountError::EmailDelivery.into()
        );
        assert_eq!(count(&db, "user").await, 2);
        assert_eq!(count(&db, "auth_user_token").await, 0);
        mailbox.fail.store(false, Ordering::SeqCst);
        db.execute_batch("CREATE TRIGGER reject_provisioned_token BEFORE INSERT ON auth_user_token BEGIN SELECT RAISE(ABORT, 'private write failure'); END;").await.unwrap();
        assert_eq!(
            service
                .create(&actor(), &input("new@example.test", true))
                .await
                .unwrap_err(),
            AccountError::Database.into()
        );
        assert!(mailbox.messages.lock().unwrap().is_empty());
        assert_eq!(count(&db, "user").await, 2);
        db.execute_batch("DROP TRIGGER reject_provisioned_token;")
            .await
            .unwrap();
        // Clear the notification from the earlier failed provider attempt.
        mailbox.entered.notified().await;
        mailbox.pending.store(true, Ordering::SeqCst);
        let task_service = service.clone();
        let task = tokio::spawn(async move {
            task_service
                .create(&actor(), &input("cancelled@example.test", true))
                .await
        });
        mailbox.entered.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(count(&db, "user").await, 2);
        assert_eq!(count(&db, "auth_user_token").await, 0);
        mailbox.pending.store(false, Ordering::SeqCst);
        service
            .create(&actor(), &input("new@example.test", true))
            .await
            .unwrap();
        assert_eq!(count(&db, "user").await, 3);
        drop(service);
        close(db, directory).await;
    }
}

#[tokio::test]
async fn provisioning_local_drivers_resend_from_locked_state_and_preserve_old_token_on_failure() {
    let _guard = super::super::PASSWORD_TEST_LOCK.lock().await;
    for driver in drivers() {
        let (db, directory, settings) = database(driver, true).await;
        let mailbox = Mailbox::default();
        let service = service(&db, &settings, Some(&mailbox));
        let mut own = actor();
        own.user_id = "2".into();
        own.roles = vec!["user".into()];
        own.email = Some("stale@example.test".into());
        assert_eq!(
            service.resend_account(&own).await.unwrap(),
            VerificationDelivery::Sent
        );
        let raw = raw_token(&mailbox, 0);
        mailbox.fail.store(true, Ordering::SeqCst);
        assert_eq!(
            service.resend_managed(&actor(), 2).await,
            Err(AccountError::EmailDelivery.into())
        );
        let stored = query("SELECT token_hash FROM auth_user_token")
            .fetch_one(&db)
            .await
            .unwrap()
            .try_get::<String, _>("token_hash")
            .unwrap();
        assert_eq!(stored, super::super::helpers::hash_auth_token(&raw));
        mailbox.fail.store(false, Ordering::SeqCst);
        db.execute_batch("UPDATE user SET email = 'current@example.test' WHERE id = 2;")
            .await
            .unwrap();
        assert_eq!(
            service.resend_managed(&actor(), 2).await.unwrap(),
            VerificationDelivery::Sent
        );
        assert_eq!(
            mailbox.messages.lock().unwrap()[1].to,
            "current@example.test"
        );
        let recovery = super::super::builtin_recovery_service(db.clone());
        assert_eq!(
            recovery.verify_email(&raw).await.unwrap(),
            vsr_runtime::auth::recovery::TokenActionOutcome::Invalid
        );
        assert_eq!(
            recovery
                .verify_email(&raw_token(&mailbox, 1))
                .await
                .unwrap(),
            vsr_runtime::auth::recovery::TokenActionOutcome::Applied
        );
        let before = mailbox.messages.lock().unwrap().len();
        assert_eq!(
            service.resend_account(&own).await.unwrap(),
            VerificationDelivery::AlreadyVerified
        );
        assert_eq!(
            service.resend_managed(&actor(), 2).await.unwrap(),
            VerificationDelivery::AlreadyVerified
        );
        assert_eq!(mailbox.messages.lock().unwrap().len(), before);
        db.execute_batch("UPDATE user SET role = 'user' WHERE id = 1;")
            .await
            .unwrap();
        assert_eq!(
            service.resend_managed(&actor(), 2).await,
            Err(ManagementError::Forbidden)
        );
        assert_eq!(
            service
                .create(&actor(), &input("blocked@example.test", false))
                .await
                .unwrap_err(),
            ManagementError::Forbidden
        );
        assert_eq!(
            service.resend_managed(&own, 1).await,
            Err(ManagementError::Forbidden)
        );
        db.execute_batch("DELETE FROM user WHERE id = 2;")
            .await
            .unwrap();
        assert_eq!(
            service.resend_account(&own).await,
            Err(AccountError::MissingAccount.into())
        );
        drop(recovery);
        drop(service);
        close(db, directory).await;
    }
}

#[tokio::test]
async fn provisioning_local_drivers_require_management_schema() {
    let _guard = super::super::PASSWORD_TEST_LOCK.lock().await;
    for driver in drivers() {
        let (db, directory, settings) = database(driver, false).await;
        let mailbox = Mailbox::default();
        let service = service(&db, &settings, Some(&mailbox));
        assert_eq!(
            service
                .create(&actor(), &input("new@example.test", false))
                .await
                .unwrap_err(),
            AccountError::MissingSchema.into()
        );
        assert_eq!(
            service.resend_managed(&actor(), 2).await,
            Err(AccountError::MissingSchema.into())
        );
        assert_eq!(count(&db, "user").await, 2);
        assert!(mailbox.messages.lock().unwrap().is_empty());
        drop(service);
        close(db, directory).await;
    }
}
