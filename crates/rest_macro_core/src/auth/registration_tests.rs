use super::*;
use sqlx::Row;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use vsr_runtime::auth::{
    MailMessage,
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
                "private provider failure".into(),
            ));
        }
        self.messages.lock().unwrap().push(message);
        Ok(())
    }
}

async fn database(driver: &str, schema: &str) -> (DbPool, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("registration.db");
    let url = if driver == "sqlite" {
        crate::sqlite_test_support::database_url(&path)
    } else {
        format!("turso-local:{}", path.display())
    };
    let db = crate::db::connect(&url).await.unwrap();
    db.execute_batch(&super::super::auth_migration_sql(AuthDbBackend::Sqlite))
        .await
        .unwrap();
    if schema == "full" {
        db.execute_batch(&super::super::auth_management_migration_sql(
            AuthDbBackend::Sqlite,
        ))
        .await
        .unwrap();
    } else if schema == "partial" {
        db.execute_batch("ALTER TABLE user ADD COLUMN email_verified_at TEXT")
            .await
            .unwrap();
    }
    (db, directory)
}
fn drivers() -> &'static [&'static str] {
    &[
        "sqlite",
        #[cfg(feature = "turso-local")]
        "turso",
    ]
}
async fn close(db: DbPool, directory: tempfile::TempDir) {
    match &db {
        DbPool::Sqlx { pool, .. } => pool.close().await,
        #[cfg(feature = "turso-local")]
        DbPool::TursoLocal(_) => {}
    }
    drop(db);
    directory.close().unwrap();
}
fn service(db: &DbPool, mailbox: Option<&Mailbox>) -> RegistrationService<Repository, Mailbox> {
    RegistrationService::new(
        Repository {
            db: db.clone(),
            settings: AuthSettings::default(),
        },
        mailbox.map(|mailbox| {
            RecoveryEmailSender::new(
                mailbox.clone(),
                RecoveryEmailPolicy {
                    from: "noreply@example.test".into(),
                    action_url: "https://app.example.test/auth/verify-email".into(),
                    purpose: TokenPurpose::EmailVerification,
                    ttl_seconds: 300,
                    delivery_timeout: Duration::from_secs(30),
                },
            )
            .unwrap()
        }),
        mailbox.is_some(),
    )
    .unwrap()
}
async fn users(db: &DbPool) -> i64 {
    query("SELECT COUNT(*) AS count FROM user")
        .fetch_one(db)
        .await
        .unwrap()
        .try_get("count")
        .unwrap()
}

#[tokio::test]
async fn registration_schema_compatibility_and_write_failures_on_local_drivers() {
    let _guard = super::super::PASSWORD_TEST_LOCK.lock().await;
    for driver in drivers() {
        for schema in ["base", "partial", "full"] {
            let (db, directory) = database(driver, schema).await;
            let result = service(&db, None)
                .register(" New@EXAMPLE.TEST ", "registration-password")
                .await;
            if schema == "partial" {
                assert_eq!(result, Err(AccountError::MissingSchema));
                assert_eq!(users(&db).await, 0);
            } else {
                result.unwrap();
                let user = super::super::db_ops::load_authenticated_user_by_email_with_settings(
                    &db,
                    "new@example.test",
                    &AuthSettings::default(),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(user.role, "user");
                assert!(
                    vsr_runtime::auth::password::verify(
                        "registration-password",
                        &user.password_hash
                    )
                    .await
                    .unwrap()
                );
                assert_eq!(user.email_verified_at.is_some(), schema == "full");
                assert_eq!(user.created_at.is_some(), schema == "full");
                assert_eq!(user.updated_at.is_some(), schema == "full");
                query("DELETE FROM user").execute(&db).await.unwrap();
            }
            if schema != "full" {
                assert_eq!(
                    service(&db, Some(&Mailbox::default()))
                        .register("email@example.test", "registration-password")
                        .await,
                    Err(AccountError::MissingSchema)
                );
                assert_eq!(users(&db).await, 0);
            } else {
                for column in ["created_at", "email_verified_at"] {
                    let trigger = format!("reject_{column}");
                    db.execute_batch(&format!("CREATE TRIGGER {trigger} BEFORE UPDATE OF {column} ON user BEGIN SELECT RAISE(ABORT, 'injected initialization failure'); END;"))
                        .await.unwrap_or_else(|error| panic!("{driver}/{column}: {error}"));
                    assert_eq!(
                        service(&db, None)
                            .register("failure@example.test", "registration-password")
                            .await,
                        Err(AccountError::Database)
                    );
                    assert_eq!(users(&db).await, 0);
                    db.execute_batch(&format!("DROP TRIGGER {trigger}"))
                        .await
                        .unwrap();
                    let remaining: i64 =
                        query("SELECT COUNT(*) AS count FROM sqlite_master WHERE name = ?")
                            .bind(&trigger)
                            .fetch_one(&db)
                            .await
                            .unwrap()
                            .try_get("count")
                            .unwrap();
                    assert_eq!(remaining, 0, "{driver}: trigger cleanup after {column}");
                }
            }
            close(db, directory).await;
        }
    }
}

#[tokio::test]
async fn registration_email_failure_cancellation_and_duplicate_race_are_atomic() {
    let _guard = super::super::PASSWORD_TEST_LOCK.lock().await;
    for driver in drivers() {
        let (db, directory) = database(driver, "full").await;
        let mailbox = Mailbox::default();
        let service = Arc::new(service(&db, Some(&mailbox)));
        mailbox.fail.store(true, Ordering::SeqCst);
        assert_eq!(
            service
                .register("new@example.test", "registration-password")
                .await,
            Err(AccountError::EmailDelivery)
        );
        assert_eq!(users(&db).await, 0);
        mailbox.fail.store(false, Ordering::SeqCst);
        db.execute_batch("CREATE TRIGGER reject_token BEFORE INSERT ON auth_user_token BEGIN SELECT RAISE(ABORT, 'injected token failure'); END;").await.unwrap();
        assert_eq!(
            service
                .register("new@example.test", "registration-password")
                .await,
            Err(AccountError::Database)
        );
        assert_eq!(users(&db).await, 0);
        assert!(mailbox.messages.lock().unwrap().is_empty());
        db.execute_batch("DROP TRIGGER reject_token").await.unwrap();

        // Consume the previous provider signal so cancellation waits for this send.
        mailbox.entered.notified().await;
        mailbox.pending.store(true, Ordering::SeqCst);
        let pending_service = service.clone();
        let pending = tokio::spawn(async move {
            pending_service
                .register("cancel@example.test", "registration-password")
                .await
        });
        tokio::time::timeout(Duration::from_secs(10), mailbox.entered.notified())
            .await
            .unwrap();
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        mailbox.pending.store(false, Ordering::SeqCst);
        assert_eq!(users(&db).await, 0);

        let (a, b) = tokio::join!(
            service.register(" New@EXAMPLE.TEST ", "registration-password"),
            service.register("new@example.test", "registration-password"),
        );
        assert!(matches!(
            (a, b),
            (Ok(()), Err(AccountError::DuplicateEmail))
                | (Err(AccountError::DuplicateEmail), Ok(()))
        ));
        assert_eq!(users(&db).await, 1);
        assert_eq!(mailbox.messages.lock().unwrap().len(), 1);
        let message = mailbox.messages.lock().unwrap()[0].clone();
        let url = url::Url::parse(message.text_body.split("\n\n").nth(1).unwrap()).unwrap();
        let raw = url
            .query_pairs()
            .find(|(name, _)| name == "token")
            .unwrap()
            .1
            .into_owned();
        let token = query("SELECT token_hash, requested_email FROM auth_user_token")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(
            token.try_get::<String, _>("token_hash").unwrap(),
            vsr_runtime::auth::recovery::token_digest(&raw)
        );
        assert_eq!(
            token.try_get::<String, _>("requested_email").unwrap(),
            "new@example.test"
        );
        let account = query("SELECT email_verified_at FROM user")
            .fetch_one(&db)
            .await
            .unwrap();
        assert!(
            account
                .try_get::<Option<String>, _>("email_verified_at")
                .unwrap()
                .is_none()
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
        drop(service);
        close(db, directory).await;
    }
}
