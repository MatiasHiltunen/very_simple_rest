//! Infrastructure bridge for runtime-owned account operations.

use super::AuthSettings;
use actix_web::{HttpResponse, http::StatusCode};
use vsr_runtime::auth::{
    accounts::{
        AccessTokenIssuer, Account, AccountError, AccountPolicy, AccountRepository, AccountService,
    },
    builtin::AccessClaims,
};
use vsr_runtime::http::ResponseBody;

struct Repository {
    db: crate::db::DbPool,
    settings: AuthSettings,
}

impl AccountRepository for Repository {
    async fn by_email(&self, email: &str) -> Result<Option<Account>, AccountError> {
        super::db_ops::load_authenticated_user_by_email_with_settings(
            &self.db,
            email,
            &self.settings,
        )
        .await
        .map_err(|error| {
            if super::helpers::is_missing_auth_management_schema(&error) {
                AccountError::MissingSchema
            } else {
                AccountError::Database
            }
        })
    }

    async fn by_id(&self, id: i64) -> Result<Option<Account>, AccountError> {
        super::db_ops::load_authenticated_user_by_id_with_settings(&self.db, id, &self.settings)
            .await
            .map_err(|_| AccountError::Database)
    }

    async fn compare_and_set_password(
        &self,
        expected: &Account,
        hash: &str,
    ) -> Result<bool, AccountError> {
        let backend = super::db_ops::detect_auth_backend(&self.db)
            .await
            .map_err(|_| AccountError::Database)?;
        super::db_ops::compare_and_set_user_password(
            &self.db,
            backend,
            expected,
            hash,
            &super::helpers::now_timestamp_string(),
        )
        .await
        .map_err(|_| AccountError::Database)
    }
}

struct Issuer(AuthSettings);

impl AccessTokenIssuer for Issuer {
    fn issue(&self, claims: &AccessClaims) -> Result<String, AccountError> {
        let (header, key) = super::jwt::configured_jwt_signer(&self.0)
            .map_err(|_| AccountError::TokenGeneration)?;
        jsonwebtoken::encode(&header, claims, key.as_ref())
            .map_err(|_| AccountError::TokenGeneration)
    }
}

/// Use the shared account service with existing configured keys and SQL drivers.
/// Transport adapters remain responsible for request authentication, rate limits,
/// JSON extraction and composing shared session responses. This facade still links Actix.
pub fn builtin_account_service(
    db: crate::db::DbPool,
    settings: AuthSettings,
) -> Result<AccountService<impl AccountRepository, impl AccessTokenIssuer>, AccountError> {
    let policy = AccountPolicy {
        issuer: settings.issuer.clone(),
        audience: settings.audience.clone(),
        access_token_ttl_seconds: settings.access_token_ttl_seconds,
        require_email_verification: settings.require_email_verification,
    };
    AccountService::new(
        Repository {
            db,
            settings: settings.clone(),
        },
        Issuer(settings),
        policy,
    )
}

pub(super) fn error_response(error: AccountError) -> HttpResponse {
    response(error.response())
}

pub(super) fn response(response: vsr_runtime::http::ResponseEnvelope) -> HttpResponse {
    let mut builder =
        HttpResponse::build(StatusCode::from_u16(response.status).expect("valid account status"));
    for (name, value) in response.headers.iter() {
        builder.append_header((name, value));
    }
    match response.body {
        ResponseBody::Empty => builder.finish(),
        ResponseBody::Bytes(body) => builder.body(body),
        ResponseBody::Json(body) => builder.json(body),
        _ => crate::errors::internal_error("Unsupported account response"),
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use crate::{auth::AuthDbBackend, db::query};

    async fn close(db: &crate::db::DbPool) {
        match db {
            crate::db::DbPool::Sqlx { pool, .. } => pool.close().await,
            #[cfg(feature = "turso-local")]
            crate::db::DbPool::TursoLocal(_) => unreachable!("SQLite fixture"),
        }
    }

    async fn database(management: bool) -> (tempfile::TempDir, crate::db::DbPool) {
        let directory = tempfile::tempdir().unwrap();
        let db = crate::db::connect(&crate::sqlite_test_support::database_url(
            &directory.path().join("accounts.sqlite"),
        ))
        .await
        .unwrap();
        db.execute_batch(&crate::auth::auth_migration_sql(AuthDbBackend::Sqlite))
            .await
            .unwrap();
        if management {
            db.execute_batch(&crate::auth::auth_management_migration_sql(
                AuthDbBackend::Sqlite,
            ))
            .await
            .unwrap();
        }
        query("INSERT INTO user (email, password_hash, role) VALUES (?, ?, ?)")
            .bind("owner@example.test")
            .bind("old-hash")
            .bind("admin")
            .execute(&db)
            .await
            .unwrap();
        (directory, db)
    }

    #[tokio::test]
    async fn sqlite_password_cas_handles_base_null_revision_and_stale_rows() {
        for management in [false, true] {
            let (_directory, db) = database(management).await;
            let repository = Repository {
                db: db.clone(),
                settings: AuthSettings::default(),
            };
            let initial = repository.by_id(1).await.unwrap().unwrap();
            assert_eq!(initial.has_updated_at_column, management);
            assert_eq!(initial.updated_at, None);
            assert!(
                repository
                    .compare_and_set_password(&initial, "new-hash")
                    .await
                    .unwrap()
            );
            assert!(
                !repository
                    .compare_and_set_password(&initial, "stale-hash")
                    .await
                    .unwrap()
            );
            let updated = repository.by_id(1).await.unwrap().unwrap();
            assert_eq!(updated.password_hash, "new-hash");
            assert_ne!(updated.auth_state(), initial.auth_state());
            assert_eq!(updated.updated_at.is_some(), management);
            if management {
                query("UPDATE user SET updated_at = 'admin-revision' WHERE id = 1")
                    .execute(&db)
                    .await
                    .unwrap();
                assert!(
                    !repository
                        .compare_and_set_password(&updated, "stale-revision-hash")
                        .await
                        .unwrap()
                );
            }
            let current = repository.by_id(1).await.unwrap().unwrap();
            let (first, second) = tokio::join!(
                repository.compare_and_set_password(&current, "winner-one"),
                repository.compare_and_set_password(&current, "winner-two"),
            );
            assert_eq!(
                usize::from(first.unwrap()) + usize::from(second.unwrap()),
                1
            );
            let current = repository.by_id(1).await.unwrap().unwrap();
            assert!(matches!(
                current.password_hash.as_str(),
                "winner-one" | "winner-two"
            ));
            query("DELETE FROM user WHERE id = 1")
                .execute(&db)
                .await
                .unwrap();
            assert!(
                !repository
                    .compare_and_set_password(&current, "resurrected")
                    .await
                    .unwrap()
            );
            query("DROP TABLE user").execute(&db).await.unwrap();
            assert_eq!(
                repository
                    .compare_and_set_password(&current, "database-failure")
                    .await,
                Err(AccountError::Database)
            );
            close(&db).await;
        }
    }

    struct GatedRepository {
        inner: Repository,
        loaded: tokio::sync::Barrier,
    }

    impl AccountRepository for GatedRepository {
        async fn by_email(&self, email: &str) -> Result<Option<Account>, AccountError> {
            self.inner.by_email(email).await
        }
        async fn by_id(&self, id: i64) -> Result<Option<Account>, AccountError> {
            self.inner.by_id(id).await
        }
        async fn compare_and_set_password(
            &self,
            expected: &Account,
            hash: &str,
        ) -> Result<bool, AccountError> {
            // Neither snapshot can change until both password proofs complete.
            self.loaded.wait().await;
            self.inner.compare_and_set_password(expected, hash).await
        }
    }

    async fn change_under_load(
        service: &AccountService<GatedRepository, Issuer>,
        new: &str,
    ) -> Result<(), AccountError> {
        loop {
            match service.change_password(1, "original-password", new).await {
                // A single-core runner may admit only one bcrypt job. Retry
                // admission failures; neither request has reached CAS yet.
                Err(AccountError::Auth(vsr_runtime::auth::request::AuthFailure::Busy)) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                result => return result,
            }
        }
    }

    #[tokio::test]
    async fn concurrent_password_changes_have_one_winner_and_revoke_the_snapshot() {
        let _guard = super::super::PASSWORD_TEST_LOCK.lock().await;
        let (_directory, db) = database(true).await;
        let hash = vsr_runtime::auth::password::hash("original-password", 4)
            .await
            .unwrap();
        query("UPDATE user SET password_hash = ? WHERE id = 1")
            .bind(hash)
            .execute(&db)
            .await
            .unwrap();
        let repository = Repository {
            db: db.clone(),
            settings: AuthSettings::default(),
        };
        let initial = repository.by_id(1).await.unwrap().unwrap();
        let service = AccountService::new(
            GatedRepository {
                inner: repository,
                loaded: tokio::sync::Barrier::new(2),
            },
            Issuer(AuthSettings::default()),
            AccountPolicy {
                issuer: None,
                audience: None,
                access_token_ttl_seconds: 3600,
                require_email_verification: false,
            },
        )
        .unwrap();
        let (first, second) = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            tokio::join!(
                change_under_load(&service, "password-one"),
                change_under_load(&service, "password-two")
            )
        })
        .await
        .unwrap();
        let winner = match (first, second) {
            (Ok(()), Err(AccountError::ConcurrentChange)) => "password-one",
            (Err(AccountError::ConcurrentChange), Ok(())) => "password-two",
            results => panic!("expected one winner: {results:?}"),
        };
        let repository = Repository {
            db: db.clone(),
            settings: AuthSettings::default(),
        };
        let current = repository.by_id(1).await.unwrap().unwrap();
        assert!(
            vsr_runtime::auth::password::verify(winner, &current.password_hash)
                .await
                .unwrap()
        );
        assert!(
            !vsr_runtime::auth::password::verify("original-password", &current.password_hash)
                .await
                .unwrap()
        );
        assert_ne!(initial.auth_state(), current.auth_state());
        close(&db).await;
    }
}
