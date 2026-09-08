use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Default)]
struct Mailbox {
    messages: Arc<Mutex<Vec<MailMessage>>>,
    fail: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
}
impl Mailer for Mailbox {
    async fn send(&self, message: MailMessage) -> vsr_core::error::VsrResult<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(vsr_core::error::VsrError::Other(
                "sensitive provider response".into(),
            ));
        }
        if self.pause.load(Ordering::SeqCst) {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        self.messages.lock().unwrap().push(message);
        Ok(())
    }
}

fn raw(message: &MailMessage) -> String {
    url::Url::parse(message.text_body.split("\n\n").nth(1).unwrap())
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "token")
        .unwrap()
        .1
        .into_owned()
}

fn service(
    db: &DbPool,
    mailer: &Mailbox,
    purpose: TokenPurpose,
) -> RecoveryEmailService<Repository, Mailbox> {
    RecoveryEmailService::new(
        Repository(db.clone()),
        RecoveryEmailSender::new(
            mailer.clone(),
            RecoveryEmailPolicy {
                from: "noreply@example.test".into(),
                action_url: "https://app.example.test/auth/action".into(),
                purpose,
                ttl_seconds: 300,
                delivery_timeout: Duration::from_secs(1),
            },
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn issuance_replacement_rollback_and_consumption_on_local_drivers() {
    for driver in [
        "sqlite",
        #[cfg(feature = "turso-local")]
        "turso",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("email.db");
        let url = if driver == "sqlite" {
            format!("sqlite://{}?mode=rwc", path.display())
        } else {
            format!("turso-local:{}", path.display())
        };
        let db = crate::db::connect(&url).await.unwrap();
        db.execute_batch(&super::super::auth_migration_sql(AuthDbBackend::Sqlite))
            .await
            .unwrap();
        db.execute_batch(&super::super::auth_management_migration_sql(
            AuthDbBackend::Sqlite,
        ))
        .await
        .unwrap();
        query("INSERT INTO user (email, password_hash, role) VALUES ('owner@example.test', 'old-hash', 'user')").execute(&db).await.unwrap();
        let mailbox = Mailbox::default();
        for purpose in [TokenPurpose::EmailVerification, TokenPurpose::PasswordReset] {
            let service = Arc::new(service(&db, &mailbox, purpose));
            service.request("missing@example.test").await.unwrap();
            assert!(mailbox.messages.lock().unwrap().is_empty());
            service.request(" OWNER@example.test ").await.unwrap();
            let first = raw(&mailbox.messages.lock().unwrap()[0]);
            mailbox.fail.store(true, Ordering::SeqCst);
            assert_eq!(
                service.request("owner@example.test").await,
                Err(AccountError::EmailDelivery)
            );
            assert!(
                super::super::db_ops::load_pending_auth_token(&db, &first, purpose)
                    .await
                    .unwrap()
                    .is_some()
            );
            mailbox.fail.store(false, Ordering::SeqCst);
            db.execute_batch("CREATE TRIGGER reject_token BEFORE INSERT ON auth_user_token BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END;").await.unwrap();
            assert_eq!(
                service.request("owner@example.test").await,
                Err(AccountError::Database)
            );
            db.execute_batch("DROP TRIGGER reject_token;")
                .await
                .unwrap();
            assert!(
                super::super::db_ops::load_pending_auth_token(&db, &first, purpose)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(mailbox.messages.lock().unwrap().len(), 1);
            mailbox.pause.store(true, Ordering::SeqCst);
            let in_flight = service.clone();
            let task = tokio::spawn(async move { in_flight.request("owner@example.test").await });
            tokio::time::timeout(Duration::from_secs(2), mailbox.entered.notified())
                .await
                .unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            mailbox.pause.store(false, Ordering::SeqCst);
            assert!(
                super::super::db_ops::load_pending_auth_token(&db, &first, purpose)
                    .await
                    .unwrap()
                    .is_some()
            );
            let (a, b) = tokio::join!(
                service.request("owner@example.test"),
                service.request("owner@example.test")
            );
            a.unwrap();
            b.unwrap();
            let tokens: Vec<_> = mailbox.messages.lock().unwrap().iter().map(raw).collect();
            assert_eq!(tokens.len(), 3);
            let rows =
                query("SELECT token_hash, requested_email FROM auth_user_token WHERE purpose = ?")
                    .bind(purpose.as_str())
                    .fetch_all(&db)
                    .await
                    .unwrap();
            assert_eq!(rows.len(), 1, "{driver}");
            assert_eq!(
                rows[0].try_get::<String, _>("requested_email").unwrap(),
                "owner@example.test"
            );
            assert_eq!(
                rows[0].try_get::<String, _>("token_hash").unwrap(),
                vsr_runtime::auth::recovery::token_digest(&tokens[2])
            );
            let recovery = super::super::builtin_recovery_service(db.clone());
            for (index, token) in tokens.iter().enumerate() {
                let result = match purpose {
                    TokenPurpose::EmailVerification => recovery.verify_email(token).await,
                    TokenPurpose::PasswordReset => {
                        recovery.apply_password_reset_hash(token, "new-hash").await
                    }
                }
                .unwrap();
                assert_eq!(
                    result,
                    if index == 2 {
                        vsr_runtime::auth::recovery::TokenActionOutcome::Applied
                    } else {
                        vsr_runtime::auth::recovery::TokenActionOutcome::Invalid
                    }
                );
            }
            if purpose == TokenPurpose::EmailVerification {
                service.request("owner@example.test").await.unwrap();
                assert_eq!(mailbox.messages.lock().unwrap().len(), 3);
            }
            mailbox.messages.lock().unwrap().clear();
        }
        match &db {
            DbPool::Sqlx { pool, .. } => pool.close().await,
            #[cfg(feature = "turso-local")]
            DbPool::TursoLocal(_) => {}
        }
        drop(db);
        directory.close().unwrap();
    }
}

#[actix_web::test]
async fn email_links_never_fall_back_to_host_or_forwarded_headers() {
    let mut settings = AuthSettings {
        email: Some(AuthEmailSettings {
            from_email: "noreply@example.test".into(),
            from_name: None,
            reply_to: None,
            public_base_url: None,
            provider: super::super::AuthEmailProvider::Smtp {
                connection_url: crate::secret::SecretRef::Env {
                    var_name: "UNUSED".into(),
                },
            },
        }),
        ..Default::default()
    };
    let request = actix_web::test::TestRequest::post()
        .uri("/api/auth/verification/resend")
        .insert_header(("host", "attacker.example"))
        .insert_header(("forwarded", "host=attacker.example;proto=https"))
        .to_http_request();
    let purpose = TokenPurpose::EmailVerification;
    assert_eq!(
        super::super::email::action_url(
            Some(&request),
            &settings,
            purpose,
            Some("/auth/verification/resend")
        ),
        Err(AccountError::Configuration)
    );
    settings.email.as_mut().unwrap().public_base_url = Some("https://trusted.example/app".into());
    let url = super::super::email::action_url(
        Some(&request),
        &settings,
        purpose,
        Some("/auth/verification/resend"),
    )
    .unwrap();
    assert_eq!(url, "https://trusted.example/app/api/auth/verify-email");
}
