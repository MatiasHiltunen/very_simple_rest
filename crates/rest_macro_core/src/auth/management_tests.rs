use super::super::AuthClaimMapping;
use super::*;
use vsr_runtime::auth::{AuthenticatedIdentity, management::AdminListQuery};

pub(super) async fn database(
    driver: &str,
    managed: bool,
) -> (DbPool, tempfile::TempDir, AuthSettings) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("management.db");
    let url = if driver == "sqlite" {
        crate::sqlite_test_support::database_url(&path)
    } else {
        format!("turso-local:{}", path.display())
    };
    let db = crate::db::connect(&url).await.unwrap();
    db.execute_batch(&super::super::auth_migration_sql(AuthDbBackend::Sqlite))
        .await
        .unwrap();
    if managed {
        db.execute_batch(&super::super::auth_management_migration_sql(
            AuthDbBackend::Sqlite,
        ))
        .await
        .unwrap();
    }
    db.execute_batch("ALTER TABLE user ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 7; ALTER TABLE user ADD COLUMN plan TEXT; ALTER TABLE user ADD COLUMN staff INTEGER;").await.unwrap();
    db.execute_batch("INSERT INTO user (id, email, password_hash, role) VALUES (1, 'owner@example.test', 'private-hash', 'admin'), (2, 'target@example.test', 'private-hash', 'user');").await.unwrap();
    let settings = AuthSettings {
        claims: BTreeMap::from([
            (
                "tenant_id".into(),
                AuthClaimMapping {
                    column: "tenant_id".into(),
                    ty: AuthClaimType::I64,
                },
            ),
            (
                "plan".into(),
                AuthClaimMapping {
                    column: "plan".into(),
                    ty: AuthClaimType::String,
                },
            ),
            (
                "staff".into(),
                AuthClaimMapping {
                    column: "staff".into(),
                    ty: AuthClaimType::Bool,
                },
            ),
        ]),
        ..Default::default()
    };
    (db, directory, settings)
}
pub(super) fn drivers() -> &'static [&'static str] {
    &[
        "sqlite",
        #[cfg(feature = "turso-local")]
        "turso",
    ]
}

// Called by the existing isolated PostgreSQL/MySQL CI fixture after registration.
#[cfg(all(feature = "postgres", feature = "mysql"))]
pub(crate) async fn verify_server_concurrency(db: &DbPool, target: i64) {
    let backend = db_ops::detect_auth_backend(db).await.unwrap();
    query(&format!(
        "UPDATE {} SET role = 'admin' WHERE id = 1",
        super::super::auth_user_table_ident(backend)
    ))
    .execute(db)
    .await
    .unwrap();
    let service = builtin_management_service(db.clone(), &AuthSettings::default());
    let admin = actor();
    let (a, b) = tokio::join!(
        service.update(
            &admin,
            target,
            update(serde_json::json!({"role":"user","email_verified":true}))
        ),
        service.update(
            &admin,
            target,
            update(serde_json::json!({"role":"user","email_verified":true}))
        ),
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_ne!(a.updated_at, b.updated_at);
    assert!(a.email_verified && b.email_verified);
    let page = service
        .list(&admin, &AdminListQuery::default())
        .await
        .unwrap();
    assert!(page.items.iter().any(|item| item.id == target));
    assert_eq!(
        service.delete(&admin, 1).await,
        Err(ManagementError::CannotDeleteSelf)
    );
    service.delete(&admin, target).await.unwrap();
    assert_eq!(
        service.get(&admin, target).await.unwrap_err(),
        ManagementError::NotFound
    );
    service
        .update(&admin, 1, update(serde_json::json!({"role":"user"})))
        .await
        .unwrap();
    assert_eq!(
        service.get(&admin, target).await.unwrap_err(),
        ManagementError::Forbidden
    );
    super::provisioning_tests::verify_server_flows(db).await;
}
pub(super) async fn close(db: DbPool, directory: tempfile::TempDir) {
    match &db {
        DbPool::Sqlx { pool, .. } => pool.close().await,
        #[cfg(feature = "turso-local")]
        DbPool::TursoLocal(_) => {}
    }
    drop(db);
    directory.close().unwrap();
}
pub(super) fn actor() -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        user_id: "1".into(),
        roles: vec!["admin".into()],
        email: None,
        claims: Default::default(),
        is_admin: true,
        expires_at: None,
    }
}
fn update(value: serde_json::Value) -> UpdateManagedUserInput {
    serde_json::from_value(value).unwrap()
}
async fn account(db: &DbPool, settings: &AuthSettings, id: i64) -> Account {
    db_ops::load_authenticated_user_by_id_with_settings(db, id, settings)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn management_local_drivers_validate_claims_and_roll_back_partial_writes() {
    for driver in drivers() {
        let (db, directory, settings) = database(driver, true).await;
        let service = builtin_management_service(db.clone(), &settings);
        let before = account(&db, &settings, 2).await.auth_state();
        let result = service.update(&actor(), 2, update(serde_json::json!({"role":" operator ","email_verified":true,"claims":{"tenant_id":42,"plan":"enterprise","staff":true}}))).await.unwrap();
        assert_eq!(result.role, "operator");
        assert!(result.email_verified);
        assert_eq!(result.claims["tenant_id"], 42);
        assert_eq!(result.claims["plan"], "enterprise");
        assert_eq!(result.claims["staff"], true);
        assert_ne!(before, account(&db, &settings, 2).await.auth_state());
        let before = account(&db, &settings, 2).await.auth_state();
        for claims in [
            serde_json::json!({"tenant_id":null}),
            serde_json::json!({"tenant_id":"42"}),
            serde_json::json!({"unknown":1}),
        ] {
            assert!(matches!(
                service
                    .update(
                        &actor(),
                        2,
                        update(serde_json::json!({"role":"admin","claims":claims}))
                    )
                    .await,
                Err(ManagementError::Validation(_, _))
            ));
            assert_eq!(before, account(&db, &settings, 2).await.auth_state());
        }
        db.execute_batch("CREATE TRIGGER reject_plan BEFORE UPDATE OF plan ON user BEGIN SELECT RAISE(ABORT, 'private failure'); END;").await.unwrap();
        assert_eq!(service.update(&actor(), 2, update(serde_json::json!({"role":"admin","email_verified":false,"claims":{"plan":"new","tenant_id":9}}))).await.unwrap_err(), AccountError::Database.into());
        assert_eq!(before, account(&db, &settings, 2).await.auth_state());
        db.execute_batch("DROP TRIGGER reject_plan;").await.unwrap();
        let result = service
            .update(
                &actor(),
                2,
                update(
                    serde_json::json!({"email_verified":false,"claims":{"plan":null,"staff":null}}),
                ),
            )
            .await
            .unwrap();
        assert!(!result.email_verified);
        assert!(!result.claims.contains_key("plan"));
        assert!(!result.claims.contains_key("staff"));
        let page = service
            .list(
                &actor(),
                &AdminListQuery {
                    limit: Some(0),
                    offset: None,
                    email: Some(" target ".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(page.limit, 1);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].id, 2);
        assert!(
            service
                .list(
                    &actor(),
                    &AdminListQuery {
                        email: Some("' OR 1=1 --".into()),
                        ..Default::default()
                    }
                )
                .await
                .unwrap()
                .items
                .is_empty()
        );
        drop(service);
        close(db, directory).await;
    }
}

#[tokio::test]
async fn management_local_drivers_recheck_roles_and_serialize_revisions() {
    for driver in drivers() {
        let (db, directory, settings) = database(driver, true).await;
        let service = builtin_management_service(db.clone(), &settings);
        db.execute_batch(
            "UPDATE user SET updated_at = '2999-01-01T00:00:00.000000+00:00' WHERE id = 2;",
        )
        .await
        .unwrap();
        let before = account(&db, &settings, 2).await.auth_state();
        let admin = actor();
        let (a, b) = tokio::join!(
            service.update(&admin, 2, update(serde_json::json!({"role":"user"}))),
            service.update(&admin, 2, update(serde_json::json!({"role":"user"}))),
        );
        let a = a.unwrap().updated_at.unwrap();
        let b = b.unwrap().updated_at.unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with("2999-01-01T00:00:00.00000"));
        assert!(b.starts_with("2999-01-01T00:00:00.00000"));
        assert_ne!(before, account(&db, &settings, 2).await.auth_state());
        service
            .update(&actor(), 1, update(serde_json::json!({"role":"user"})))
            .await
            .unwrap();
        // This previously authenticated identity still claims admin, but live state wins.
        assert_eq!(
            service.get(&actor(), 2).await.unwrap_err(),
            ManagementError::Forbidden
        );
        assert_eq!(
            service
                .update(&actor(), 2, update(serde_json::json!({"role":"admin"})))
                .await
                .unwrap_err(),
            ManagementError::Forbidden
        );
        assert_eq!(
            service.delete(&actor(), 2).await,
            Err(ManagementError::Forbidden)
        );
        db.execute_batch("UPDATE user SET role = 'admin' WHERE id = 1;")
            .await
            .unwrap();
        assert_eq!(
            service.delete(&actor(), 1).await,
            Err(ManagementError::CannotDeleteSelf)
        );
        service.delete(&actor(), 2).await.unwrap();
        assert_eq!(
            service.get(&actor(), 2).await.unwrap_err(),
            ManagementError::NotFound
        );
        assert_eq!(
            service.delete(&actor(), 2).await,
            Err(ManagementError::NotFound)
        );
        db.execute_batch("DELETE FROM user WHERE id = 1;")
            .await
            .unwrap();
        assert_eq!(
            service.get(&actor(), 2).await.unwrap_err(),
            AccountError::MissingAccount.into()
        );
        drop(service);
        close(db, directory).await;
    }
}

#[tokio::test]
async fn management_local_drivers_fail_closed_on_legacy_schema_and_unsafe_mappings() {
    for driver in drivers() {
        let (db, directory, settings) = database(driver, false).await;
        let service = builtin_management_service(db.clone(), &settings);
        service.get(&actor(), 2).await.unwrap();
        assert_eq!(
            service
                .update(
                    &actor(),
                    2,
                    update(serde_json::json!({"claims":{"tenant_id":9}}))
                )
                .await
                .unwrap_err(),
            AccountError::MissingSchema.into()
        );
        drop(service);
        close(db, directory).await;
        let (db, directory, settings) = database(driver, true).await;
        for mapping in ["role", "password_hash", "updated_at", "tenant_id"] {
            let mut settings = settings.clone();
            settings.claims.insert(
                "override".into(),
                AuthClaimMapping {
                    column: mapping.into(),
                    ty: if mapping == "tenant_id" {
                        AuthClaimType::I64
                    } else {
                        AuthClaimType::String
                    },
                },
            );
            let service = builtin_management_service(db.clone(), &settings);
            assert_eq!(
                service
                    .update(
                        &actor(),
                        2,
                        update(serde_json::json!({"claims":{"override":"injected"}}))
                    )
                    .await
                    .unwrap_err(),
                AccountError::Configuration.into()
            );
        }
        assert_eq!(account(&db, &settings, 2).await.role, "user");
        for name in ["id", "roles", "email", "_vsr_auth_state", "email_verified"] {
            let mut settings = settings.clone();
            settings.claims = BTreeMap::from([(
                name.into(),
                AuthClaimMapping {
                    column: "tenant_id".into(),
                    ty: AuthClaimType::I64,
                },
            )]);
            let service = builtin_management_service(db.clone(), &settings);
            assert_eq!(
                service.get(&actor(), 2).await.unwrap_err(),
                AccountError::Configuration.into()
            );
        }
        close(db, directory).await;
    }
}

#[tokio::test]
async fn management_local_driver_cancellation_and_dependent_row_failure_roll_back() {
    for driver in drivers() {
        let (db, directory, settings) = database(driver, true).await;
        let before = account(&db, &settings, 2).await.auth_state();
        let repository = Repository {
            db: db.clone(),
            settings: settings.clone(),
        };
        let (entered, receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let tx = repository.begin().await.unwrap();
            tx.lock_accounts(&[1, 2]).await.unwrap();
            tx.update(
                2,
                &update(serde_json::json!({"role":"operator","claims":{"tenant_id":42}})),
                "2026-09-11T00:00:00.000001+00:00",
            )
            .await
            .unwrap();
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
            tx.commit().await.unwrap();
        });
        receiver.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(before, account(&db, &settings, 2).await.auth_state());
        db.execute_batch("CREATE TABLE protected_record (user_id INTEGER NOT NULL REFERENCES user(id) ON DELETE RESTRICT); INSERT INTO protected_record (user_id) VALUES (2);").await.unwrap();
        let service = builtin_management_service(db.clone(), &settings);
        assert_eq!(
            service.delete(&actor(), 2).await,
            Err(AccountError::Database.into())
        );
        assert_eq!(before, account(&db, &settings, 2).await.auth_state());
        db.execute_batch("DELETE FROM protected_record;")
            .await
            .unwrap();
        service.delete(&actor(), 2).await.unwrap();
        drop(service);
        close(db, directory).await;
    }
}
