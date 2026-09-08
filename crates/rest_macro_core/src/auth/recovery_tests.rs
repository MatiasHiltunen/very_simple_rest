use super::super::db_ops::{create_auth_token, load_pending_auth_token};
use super::*;
use sqlx::Row;

struct Fixture {
    db: DbPool,
    directory: tempfile::TempDir,
}
impl Fixture {
    async fn new(driver: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("recovery.db");
        let url = if driver == "sqlite" {
            crate::sqlite_test_support::database_url(&path)
        } else {
            format!("turso-local:{}", path.display())
        };
        let db = crate::db::connect(&url).await.unwrap();
        db.execute_batch(&crate::auth::auth_migration_sql(AuthDbBackend::Sqlite))
            .await
            .unwrap();
        db.execute_batch(&crate::auth::auth_management_migration_sql(
            AuthDbBackend::Sqlite,
        ))
        .await
        .unwrap();
        query("INSERT INTO user (email, password_hash, role) VALUES ('owner@example.test', 'old-hash', 'user')").execute(&db).await.unwrap();
        Self { db, directory }
    }
    async fn token(&self, purpose: TokenPurpose, email: Option<&str>) -> String {
        create_auth_token(&self.db, 1, purpose, email, 300)
            .await
            .unwrap()
    }
    async fn close(self) {
        match &self.db {
            DbPool::Sqlx { pool, .. } => pool.close().await,
            #[cfg(feature = "turso-local")]
            DbPool::TursoLocal(_) => {}
        }
        drop(self.db);
        self.directory.close().unwrap();
    }
}

fn drivers() -> &'static [&'static str] {
    &[
        "sqlite",
        #[cfg(feature = "turso-local")]
        "turso",
    ]
}

async fn consume(
    db: &DbPool,
    raw: &str,
    purpose: TokenPurpose,
) -> Result<TokenActionOutcome, AccountError> {
    let service = builtin_recovery_service(db.clone());
    match purpose {
        TokenPurpose::EmailVerification => service.verify_email(raw).await,
        TokenPurpose::PasswordReset => service.apply_password_reset_hash(raw, "new-hash").await,
    }
}

#[tokio::test]
async fn recovery_rejects_stale_or_missing_email_binding_and_never_revives_it() {
    for driver in drivers() {
        for purpose in [TokenPurpose::EmailVerification, TokenPurpose::PasswordReset] {
            let fixture = Fixture::new(driver).await;
            let raw = fixture.token(purpose, Some("owner@example.test")).await;
            query("UPDATE user SET email = 'renamed@example.test' WHERE id = 1")
                .execute(&fixture.db)
                .await
                .unwrap();
            assert_eq!(
                consume(&fixture.db, &raw, purpose).await.unwrap(),
                TokenActionOutcome::Invalid
            );
            let row = query("SELECT password_hash, email_verified_at FROM user WHERE id = 1")
                .fetch_one(&fixture.db)
                .await
                .unwrap();
            assert_eq!(
                row.try_get::<String, _>("password_hash").unwrap(),
                "old-hash"
            );
            assert!(
                row.try_get::<Option<String>, _>("email_verified_at")
                    .unwrap()
                    .is_none()
            );
            query("UPDATE user SET email = 'owner@example.test' WHERE id = 1")
                .execute(&fixture.db)
                .await
                .unwrap();
            assert_eq!(
                consume(&fixture.db, &raw, purpose).await.unwrap(),
                TokenActionOutcome::Invalid
            );
            let unbound = fixture.token(purpose, None).await;
            assert_eq!(
                consume(&fixture.db, &unbound, purpose).await.unwrap(),
                TokenActionOutcome::Invalid
            );
            fixture.close().await;
        }
    }
}

#[tokio::test]
async fn recovery_expiry_and_wrong_purpose_cannot_mutate_an_account() {
    for driver in drivers() {
        let fixture = Fixture::new(driver).await;
        let raw = fixture
            .token(TokenPurpose::EmailVerification, Some("owner@example.test"))
            .await;
        assert_eq!(
            consume(&fixture.db, &raw, TokenPurpose::PasswordReset)
                .await
                .unwrap(),
            TokenActionOutcome::Invalid
        );
        assert!(
            load_pending_auth_token(&fixture.db, &raw, TokenPurpose::EmailVerification)
                .await
                .unwrap()
                .is_some()
        );
        for expiry in ["2000-01-01T00:00:00Z", "invalid-date"] {
            let raw = fixture
                .token(TokenPurpose::EmailVerification, Some("owner@example.test"))
                .await;
            query("UPDATE auth_user_token SET expires_at = ?")
                .bind(expiry)
                .execute(&fixture.db)
                .await
                .unwrap();
            assert_eq!(
                consume(&fixture.db, &raw, TokenPurpose::EmailVerification)
                    .await
                    .unwrap(),
                TokenActionOutcome::Expired
            );
            assert_eq!(
                consume(&fixture.db, &raw, TokenPurpose::EmailVerification)
                    .await
                    .unwrap(),
                TokenActionOutcome::Invalid
            );
        }
        fixture.close().await;
    }
}

#[tokio::test]
async fn recovery_rolls_back_claim_on_account_write_failure_and_transaction_drop() {
    let fixture = Fixture::new("sqlite").await;
    let raw = fixture
        .token(TokenPurpose::PasswordReset, Some("owner@example.test"))
        .await;
    fixture.db.execute_batch("CREATE TRIGGER reject_password BEFORE UPDATE OF password_hash ON user BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").await.unwrap();
    assert_eq!(
        consume(&fixture.db, &raw, TokenPurpose::PasswordReset).await,
        Err(AccountError::Database)
    );
    assert!(
        load_pending_auth_token(&fixture.db, &raw, TokenPurpose::PasswordReset)
            .await
            .unwrap()
            .is_some()
    );
    fixture
        .db
        .execute_batch("DROP TRIGGER reject_password")
        .await
        .unwrap();
    let repository = Repository(fixture.db.clone());
    let transaction = repository.begin().await.unwrap();
    let token = transaction
        .pending(
            &vsr_runtime::auth::recovery::token_digest(&raw),
            TokenPurpose::PasswordReset,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(transaction.claim(token.id, "in-flight").await.unwrap());
    drop(transaction);
    assert_eq!(
        consume(&fixture.db, &raw, TokenPurpose::PasswordReset)
            .await
            .unwrap(),
        TokenActionOutcome::Applied
    );
    drop(repository);
    fixture.close().await;
}

#[tokio::test]
async fn recovery_does_not_report_success_for_a_deleted_account() {
    for driver in drivers() {
        let fixture = Fixture::new(driver).await;
        let raw = fixture
            .token(TokenPurpose::PasswordReset, Some("owner@example.test"))
            .await;
        query("DELETE FROM user WHERE id = 1")
            .execute(&fixture.db)
            .await
            .unwrap();
        assert_eq!(
            consume(&fixture.db, &raw, TokenPurpose::PasswordReset)
                .await
                .unwrap(),
            TokenActionOutcome::Invalid
        );
        fixture.close().await;
    }
}

#[tokio::test]
async fn recovery_race_applies_once_and_rejects_every_other_attempt() {
    for driver in drivers() {
        let fixture = Fixture::new(driver).await;
        let raw = fixture
            .token(TokenPurpose::PasswordReset, Some("owner@example.test"))
            .await;
        let results = futures_util::future::join_all(
            (0..8).map(|_| consume(&fixture.db, &raw, TokenPurpose::PasswordReset)),
        )
        .await;
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Ok(TokenActionOutcome::Applied)))
                .count(),
            1,
            "{driver}: {results:?}"
        );
        assert!(
            results.iter().all(|r| matches!(
                r,
                Ok(TokenActionOutcome::Applied | TokenActionOutcome::Invalid)
            )),
            "{driver}: {results:?}"
        );
        fixture.close().await;
    }
}

#[tokio::test]
async fn recovery_cancelled_lock_wait_and_dropped_claim_leave_the_pool_usable() {
    for driver in drivers() {
        let fixture = Fixture::new(driver).await;
        let raw = fixture
            .token(TokenPurpose::PasswordReset, Some("owner@example.test"))
            .await;
        let repository = Repository(fixture.db.clone());
        let transaction = repository.begin().await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), repository.begin())
                .await
                .is_err()
        );
        let token = transaction
            .pending(
                &vsr_runtime::auth::recovery::token_digest(&raw),
                TokenPurpose::PasswordReset,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(transaction.claim(token.id, "in-flight").await.unwrap());
        drop(transaction);
        assert_eq!(
            consume(&fixture.db, &raw, TokenPurpose::PasswordReset)
                .await
                .unwrap(),
            TokenActionOutcome::Applied
        );
        drop(repository);
        fixture.close().await;
    }
}
