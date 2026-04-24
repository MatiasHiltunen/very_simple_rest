mod settings;
mod migrations;
mod jwt;
mod user;
mod helpers;
mod db_ops;
mod email;
mod tokens;
mod admin;
mod pages;
pub mod handlers;
mod routing;

// Re-exports — settings
pub use settings::{
    AuthClaimMapping, AuthClaimType, AuthEmailProvider, AuthEmailSettings, AuthJwtAlgorithm,
    AuthJwtSettings, AuthJwtVerificationKey, AuthSettings, AuthUiPageSettings,
    SessionCookieSameSite, SessionCookieSettings, auth_jwt_signing_secret_ref,
};

// Re-exports — migrations
pub use migrations::{
    AuthDbBackend, auth_claim_migration_sql, auth_management_migration_sql, auth_migration_sql,
    auth_user_table_ident,
};

// Re-exports — jwt
pub use jwt::{ensure_jwt_secret_configured, ensure_jwt_secret_configured_with_settings};

// Re-exports — user types
pub use user::{
    AccountInfo, AdminListQuery, AuthTokenQuery, ChangePasswordInput, CreateManagedUserInput,
    LoginInput, PasswordResetConfirmInput, PasswordResetRequestInput, RegisterInput,
    UpdateManagedUserInput, User, UserContext, VerificationResendInput, VerifyEmailInput,
};

// Re-exports — admin
pub use admin::{
    ensure_admin_exists, ensure_admin_exists_with_settings, validate_auth_claim_mappings,
};

// Re-exports — handlers (public HTTP endpoints)
pub use handlers::{
    account, account_portal_page, admin_dashboard_page, change_password, confirm_password_reset,
    create_managed_user, delete_managed_user, list_managed_users, login, login_with_request,
    logout, managed_user, me, password_reset_page, register, register_with_request,
    resend_account_verification, resend_managed_user_verification, resend_verification,
    request_password_reset, update_managed_user, verify_email_page, verify_email_token,
};

// Re-exports — routing
pub use routing::{
    auth_api_routes_with_settings, auth_routes, auth_routes_with_settings,
    public_auth_discovery_routes, public_auth_discovery_routes_with_settings,
    public_jwks_enabled, register_builtin_auth_html_pages,
};

// Re-export jwks handler
pub use jwt::jwks;

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::{
        AuthClaimMapping, AuthClaimType, AuthDbBackend, AuthEmailProvider, AuthEmailSettings,
        AuthJwtAlgorithm, AuthJwtSettings, AuthJwtVerificationKey, AuthSettings,
        auth_claim_migration_sql, auth_migration_sql,
    };
    use super::helpers::build_public_auth_url;
    use super::jwt::{Claims, configured_public_jwks, load_jwt_secret};
    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    use super::{
        LoginInput, auth_management_migration_sql,
        validate_auth_claim_mappings,
    };
    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    use super::admin::ensure_admin_exists_with_settings_and_claim_prompt_mode;
    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    use super::handlers::login_with_settings;
    #[cfg(feature = "turso-local")]
    use crate::database::{DatabaseConfig, DatabaseEngine, TursoLocalConfig};
    #[cfg(all(not(feature = "turso-local"), feature = "sqlite"))]
    use crate::db::connect;
    #[cfg(feature = "turso-local")]
    use crate::db::connect_with_config;
    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    use crate::db::{DbPool, query, query_scalar};
    use crate::secret::SecretRef;
    use actix_web::App;
    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    use actix_web::body::to_bytes;
    use actix_web::http::StatusCode;
    use actix_web::test::{TestRequest, call_service, init_service, read_body_json};
    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    use actix_web::web;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{
        DecodingKey, encode,
        jwk::{AlgorithmParameters, EllipticCurve, KeyAlgorithm},
    };
    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    use sqlx::Row;
    use std::collections::BTreeMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[cfg(all(not(feature = "turso-local"), feature = "sqlite"))]
    fn unique_sqlite_url(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("vsr_auth_{prefix}_{nanos}.db"));
        format!("sqlite:{}?mode=rwc", path.display())
    }

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    async fn connect_test_pool(prefix: &str) -> DbPool {
        #[cfg(feature = "turso-local")]
        {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should be monotonic enough")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("vsr_auth_{prefix}_{nanos}.db"));
            let config = DatabaseConfig {
                engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                    path: path.to_string_lossy().into_owned(),
                    encryption_key: None,
                }),
                resilience: None,
            };
            return connect_with_config("sqlite:ignored.db?mode=rwc", &config)
                .await
                .expect("database should connect");
        }
        #[cfg(all(not(feature = "turso-local"), feature = "sqlite"))]
        {
            let database_url = unique_sqlite_url(prefix);
            return connect(&database_url)
                .await
                .expect("database should connect");
        }
    }

    fn write_temp_secret_file(prefix: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "vsr_auth_{prefix}_{}.pem",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should be monotonic enough")
                .as_nanos()
        ));
        std::fs::write(&path, contents).expect("temporary secret file should write");
        path
    }

    const TEST_ED25519_PRIVATE_KEY_CURRENT: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICan3gTz94CxAFR90FubWnI1S7Hu81HAawRP0JnhgJd1\n-----END PRIVATE KEY-----\n";
    const TEST_ED25519_PUBLIC_KEY_CURRENT: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA6SXZeouSZ6gAAGu0fq5MlKZt7T0z0mf3pK1NmaIWqi4=\n-----END PUBLIC KEY-----\n";
    const TEST_ED25519_PRIVATE_KEY_PREVIOUS: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHP+7KrmLqsh9YuYdKt7lixHaso9B9XfoxDhheTT93xC\n-----END PRIVATE KEY-----\n";
    const TEST_ED25519_PUBLIC_KEY_PREVIOUS: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAMtHpnFKVCrgrEn+eT5L9XptGRw7nq2RZy5ZsM6TdS1Q=\n-----END PUBLIC KEY-----\n";

    #[test]
    fn sqlite_auth_migration_uses_expected_schema() {
        let sql = auth_migration_sql(AuthDbBackend::Sqlite);
        assert!(sql.contains("CREATE TABLE \"user\""));
        assert!(sql.contains("id INTEGER PRIMARY KEY AUTOINCREMENT"));
        assert!(sql.contains("email TEXT NOT NULL UNIQUE"));
        assert!(sql.contains("password_hash TEXT NOT NULL"));
        assert!(sql.contains("role TEXT NOT NULL"));
        assert!(sql.contains("CREATE INDEX idx_user_role ON \"user\" (role);"));
    }

    #[test]
    fn postgres_auth_migration_quotes_reserved_user_table() {
        let sql = auth_migration_sql(AuthDbBackend::Postgres);
        assert!(sql.contains("CREATE TABLE \"user\""));
        assert!(sql.contains("CREATE INDEX idx_user_role ON \"user\" (role);"));
    }

    #[test]
    fn auth_claim_migration_sql_generates_columns_from_explicit_claims() {
        let sql = auth_claim_migration_sql(
            AuthDbBackend::Sqlite,
            &AuthSettings {
                claims: BTreeMap::from([
                    (
                        "tenant_id".to_owned(),
                        AuthClaimMapping {
                            column: "active_family_id".to_owned(),
                            ty: AuthClaimType::I64,
                        },
                    ),
                    (
                        "preferred_household".to_owned(),
                        AuthClaimMapping {
                            column: "preferred_household".to_owned(),
                            ty: AuthClaimType::String,
                        },
                    ),
                    (
                        "support_agent".to_owned(),
                        AuthClaimMapping {
                            column: "is_support_agent".to_owned(),
                            ty: AuthClaimType::Bool,
                        },
                    ),
                ]),
                ..AuthSettings::default()
            },
        );

        assert!(sql.contains("ALTER TABLE \"user\" ADD COLUMN \"active_family_id\" INTEGER;"));
        assert!(sql.contains("ALTER TABLE \"user\" ADD COLUMN \"preferred_household\" TEXT;"));
        assert!(sql.contains(
            "ALTER TABLE \"user\" ADD COLUMN \"is_support_agent\" INTEGER NOT NULL DEFAULT 0;"
        ));
    }

    #[test]
    fn load_jwt_secret_requires_non_empty_secret() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::remove_var("JWT_SECRET");
            std::env::remove_var("JWT_SECRET_FILE");
        }

        let error = load_jwt_secret(&SecretRef::env_or_file("JWT_SECRET"))
            .expect_err("missing JWT secret should fail");
        assert!(error.contains("JWT_SECRET"));

        unsafe {
            std::env::set_var("JWT_SECRET", "");
        }

        let error = load_jwt_secret(&SecretRef::env_or_file("JWT_SECRET"))
            .expect_err("empty JWT secret should fail");
        assert!(error.contains("JWT_SECRET"));

        unsafe {
            std::env::remove_var("JWT_SECRET");
        }
    }

    #[test]
    fn load_jwt_secret_accepts_non_empty_secret() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var("JWT_SECRET", "unit-test-secret");
        }

        let secret = load_jwt_secret(&SecretRef::env_or_file("JWT_SECRET"))
            .expect("non-empty JWT secret should load");
        assert_eq!(&*secret, b"unit-test-secret");

        unsafe {
            std::env::remove_var("JWT_SECRET");
        }
    }

    #[test]
    fn load_jwt_secret_from_file_path_env() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let path = std::env::temp_dir().join(format!(
            "vsr_jwt_secret_{}.txt",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should be monotonic enough")
                .as_nanos()
        ));
        std::fs::write(&path, "file-secret\n").expect("jwt secret file should write");

        unsafe {
            std::env::remove_var("JWT_SECRET");
            std::env::set_var("JWT_SECRET_FILE", path.as_os_str());
        }

        let secret = load_jwt_secret(&SecretRef::env_or_file("JWT_SECRET"))
            .expect("file-backed JWT secret should load");
        assert_eq!(&*secret, b"file-secret");

        unsafe {
            std::env::remove_var("JWT_SECRET_FILE");
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn eddsa_jwt_signing_and_verification_supports_configured_key_ids() {
        let private_key =
            write_temp_secret_file("jwt_current_private", TEST_ED25519_PRIVATE_KEY_CURRENT);
        let public_key =
            write_temp_secret_file("jwt_current_public", TEST_ED25519_PUBLIC_KEY_CURRENT);

        let settings = AuthSettings {
            jwt: Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: Some("current".to_owned()),
                signing_key: SecretRef::File {
                    path: private_key.clone(),
                },
                verification_keys: vec![AuthJwtVerificationKey {
                    kid: "current".to_owned(),
                    key: SecretRef::File {
                        path: public_key.clone(),
                    },
                }],
            }),
            jwt_secret: None,
            ..AuthSettings::default()
        };

        let claims = Claims {
            sub: 42,
            roles: vec!["user".to_owned()],
            iss: None,
            aud: None,
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            extra: BTreeMap::new(),
        };

        let (header, encoding_key) =
            super::jwt::configured_jwt_signer(&settings).expect("jwt signer should resolve");
        assert_eq!(header.kid.as_deref(), Some("current"));
        let token = encode(&header, &claims, encoding_key.as_ref()).expect("jwt should encode");

        let context =
            super::user::decode_user_context_token(&token, &settings).expect("jwt should decode");
        assert_eq!(context.id, 42);
        assert_eq!(context.roles, vec!["user".to_owned()]);

        let _ = std::fs::remove_file(private_key);
        let _ = std::fs::remove_file(public_key);
    }

    #[test]
    fn eddsa_jwt_rotation_accepts_previous_verification_key() {
        let current_private = write_temp_secret_file(
            "jwt_rotate_current_private",
            TEST_ED25519_PRIVATE_KEY_CURRENT,
        );
        let current_public =
            write_temp_secret_file("jwt_rotate_current_public", TEST_ED25519_PUBLIC_KEY_CURRENT);
        let previous_private = write_temp_secret_file(
            "jwt_rotate_previous_private",
            TEST_ED25519_PRIVATE_KEY_PREVIOUS,
        );
        let previous_public = write_temp_secret_file(
            "jwt_rotate_previous_public",
            TEST_ED25519_PUBLIC_KEY_PREVIOUS,
        );

        let previous_settings = AuthSettings {
            jwt: Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: Some("previous".to_owned()),
                signing_key: SecretRef::File {
                    path: previous_private.clone(),
                },
                verification_keys: vec![AuthJwtVerificationKey {
                    kid: "previous".to_owned(),
                    key: SecretRef::File {
                        path: previous_public.clone(),
                    },
                }],
            }),
            jwt_secret: None,
            ..AuthSettings::default()
        };
        let rotated_settings = AuthSettings {
            jwt: Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: Some("current".to_owned()),
                signing_key: SecretRef::File {
                    path: current_private.clone(),
                },
                verification_keys: vec![
                    AuthJwtVerificationKey {
                        kid: "current".to_owned(),
                        key: SecretRef::File {
                            path: current_public.clone(),
                        },
                    },
                    AuthJwtVerificationKey {
                        kid: "previous".to_owned(),
                        key: SecretRef::File {
                            path: previous_public.clone(),
                        },
                    },
                ],
            }),
            jwt_secret: None,
            ..AuthSettings::default()
        };

        let claims = Claims {
            sub: 7,
            roles: vec!["admin".to_owned()],
            iss: None,
            aud: None,
            exp: (Utc::now() + Duration::minutes(5)).timestamp() as usize,
            extra: BTreeMap::new(),
        };

        let (header, encoding_key) = super::jwt::configured_jwt_signer(&previous_settings)
            .expect("previous jwt signer should resolve");
        let token =
            encode(&header, &claims, encoding_key.as_ref()).expect("rotated jwt should encode");

        let context = super::user::decode_user_context_token(&token, &rotated_settings)
            .expect("old token should decode after rotation");
        assert_eq!(context.id, 7);
        assert_eq!(context.roles, vec!["admin".to_owned()]);

        for path in [
            current_private,
            current_public,
            previous_private,
            previous_public,
        ] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn configured_public_jwks_returns_eddsa_verification_keys() {
        let public_key =
            write_temp_secret_file("jwt_jwks_current_public", TEST_ED25519_PUBLIC_KEY_CURRENT);
        let settings = AuthSettings {
            jwt: Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: Some("current".to_owned()),
                signing_key: SecretRef::env_or_file("JWT_SIGNING_KEY"),
                verification_keys: vec![AuthJwtVerificationKey {
                    kid: "current".to_owned(),
                    key: SecretRef::File {
                        path: public_key.clone(),
                    },
                }],
            }),
            jwt_secret: None,
            ..AuthSettings::default()
        };

        let jwks = configured_public_jwks(&settings)
            .expect("jwks should resolve")
            .expect("jwks should be present");
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].common.key_id.as_deref(), Some("current"));
        assert_eq!(jwks.keys[0].common.key_algorithm, Some(KeyAlgorithm::EdDSA));
        match &jwks.keys[0].algorithm {
            AlgorithmParameters::OctetKeyPair(params) => {
                assert_eq!(params.curve, EllipticCurve::Ed25519);
                assert!(!params.x.is_empty());
                let decoding_key =
                    DecodingKey::from_jwk(&jwks.keys[0]).expect("returned jwk should decode");
                assert_eq!(decoding_key.as_bytes().len(), 32);
            }
            other => panic!("expected Ed25519 octet key pair, got {other:?}"),
        }

        let _ = std::fs::remove_file(public_key);
    }

    #[actix_web::test]
    async fn auth_routes_expose_public_jwks_for_asymmetric_jwt() {
        let public_key =
            write_temp_secret_file("jwt_jwks_route_public", TEST_ED25519_PUBLIC_KEY_CURRENT);
        let settings = AuthSettings {
            jwt: Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: Some("current".to_owned()),
                signing_key: SecretRef::env_or_file("JWT_SIGNING_KEY"),
                verification_keys: vec![AuthJwtVerificationKey {
                    kid: "current".to_owned(),
                    key: SecretRef::File {
                        path: public_key.clone(),
                    },
                }],
            }),
            jwt_secret: None,
            ..AuthSettings::default()
        };

        let app = init_service(App::new().configure(|cfg| {
            super::public_auth_discovery_routes_with_settings(cfg, settings.clone())
        }))
        .await;

        let response = call_service(
            &app,
            TestRequest::get()
                .uri("/.well-known/jwks.json")
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = read_body_json(response).await;
        assert_eq!(body["keys"][0]["kid"], "current");
        assert_eq!(body["keys"][0]["alg"], "EdDSA");
        assert_eq!(body["keys"][0]["kty"], "OKP");
        assert_eq!(body["keys"][0]["crv"], "Ed25519");
        assert!(body["keys"][0]["x"].is_string());

        let _ = std::fs::remove_file(public_key);
    }

    #[test]
    fn public_auth_url_uses_request_scope_with_public_base_url() {
        let settings = AuthSettings {
            email: Some(AuthEmailSettings {
                from_email: "noreply@example.com".to_owned(),
                from_name: Some("VSR".to_owned()),
                reply_to: None,
                public_base_url: Some("https://app.example".to_owned()),
                provider: AuthEmailProvider::Resend {
                    api_key: SecretRef::env_or_file("RESEND_API_KEY"),
                    api_base_url: None,
                },
            }),
            ..AuthSettings::default()
        };
        let request = TestRequest::with_uri("/api/auth/password-reset/request").to_http_request();

        let url = build_public_auth_url(
            Some(&request),
            &settings,
            "/auth/password-reset",
            Some("/auth/password-reset/request"),
            &[("token", "abc123")],
        )
        .expect("password reset url should build");

        assert_eq!(
            url,
            "https://app.example/api/auth/password-reset?token=abc123"
        );
    }

    #[test]
    fn public_auth_url_does_not_duplicate_existing_scope_prefix() {
        let settings = AuthSettings {
            email: Some(AuthEmailSettings {
                from_email: "noreply@example.com".to_owned(),
                from_name: Some("VSR".to_owned()),
                reply_to: None,
                public_base_url: Some("https://app.example/app/api".to_owned()),
                provider: AuthEmailProvider::Resend {
                    api_key: SecretRef::env_or_file("RESEND_API_KEY"),
                    api_base_url: None,
                },
            }),
            ..AuthSettings::default()
        };
        let request = TestRequest::with_uri("/api/auth/verify-email").to_http_request();

        let url = build_public_auth_url(
            Some(&request),
            &settings,
            "/auth/verify-email",
            Some("/auth/verify-email"),
            &[("token", "xyz")],
        )
        .expect("verification url should build");

        assert_eq!(
            url,
            "https://app.example/app/api/auth/verify-email?token=xyz"
        );
    }

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    #[actix_web::test]
    async fn ensure_admin_exists_inserts_detected_claim_columns_from_environment() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());

        unsafe {
            std::env::set_var("ADMIN_EMAIL", "admin@example.com");
            std::env::set_var("ADMIN_PASSWORD", "password123");
            std::env::set_var("ADMIN_TENANT_ID", "7");
            std::env::set_var("ADMIN_CLAIM_WORKSPACE_ID", "42");
        }

        let pool = connect_test_pool("ensure_admin_claims").await;

        query(
            "CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_id INTEGER,
                claim_workspace_id INTEGER
            )",
        )
        .execute(&pool)
        .await
        .expect("user table should be created");

        let created = ensure_admin_exists_with_settings_and_claim_prompt_mode(
            &pool,
            &AuthSettings::default(),
            false,
        )
        .await
        .expect("ensure_admin_exists should not error");
        assert!(created);

        let row = query("SELECT tenant_id, claim_workspace_id FROM user WHERE role = 'admin'")
            .fetch_one(&pool)
            .await
            .expect("admin row should exist");
        let tenant_id: Option<i64> = row.try_get("tenant_id").expect("tenant_id should decode");
        let workspace_id: Option<i64> = row
            .try_get("claim_workspace_id")
            .expect("workspace claim should decode");
        assert_eq!(tenant_id, Some(7));
        assert_eq!(workspace_id, Some(42));

        unsafe {
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
            std::env::remove_var("ADMIN_TENANT_ID");
            std::env::remove_var("ADMIN_CLAIM_WORKSPACE_ID");
        }
    }

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    #[actix_web::test]
    async fn ensure_admin_exists_returns_false_when_required_claim_is_missing() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());

        unsafe {
            std::env::set_var("ADMIN_EMAIL", "admin@example.com");
            std::env::set_var("ADMIN_PASSWORD", "password123");
            std::env::remove_var("ADMIN_TENANT_ID");
        }

        let pool = connect_test_pool("ensure_admin_required_claim").await;

        query(
            "CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_id INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("user table should be created");

        let created = ensure_admin_exists_with_settings_and_claim_prompt_mode(
            &pool,
            &AuthSettings::default(),
            false,
        )
        .await
        .expect("ensure_admin_exists should not error");
        assert!(!created);

        let count: i64 = query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM user")
            .fetch_one(&pool)
            .await
            .expect("row count should be queryable");
        assert_eq!(count, 0);

        unsafe {
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
        }
    }

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    #[actix_web::test]
    async fn login_treats_null_management_fields_as_unverified_when_schema_exists() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var("JWT_SECRET", "auth-management-test-secret");
        }

        let pool = connect_test_pool("management_nulls").await;

        for statement in auth_migration_sql(AuthDbBackend::Sqlite)
            .split(';')
            .map(str::trim)
            .filter(|statement| !statement.is_empty())
        {
            query(statement)
                .execute(&pool)
                .await
                .expect("auth schema should apply");
        }
        for statement in auth_management_migration_sql(AuthDbBackend::Sqlite)
            .split(';')
            .map(str::trim)
            .filter(|statement| !statement.is_empty())
        {
            query(statement)
                .execute(&pool)
                .await
                .expect("auth management schema should apply");
        }

        let password_hash =
            bcrypt::hash("password123", 12).expect("password hash should be created");
        query("INSERT INTO user (email, password_hash, role) VALUES (?, ?, ?)")
            .bind("nulls@example.com")
            .bind(password_hash)
            .bind("user")
            .execute(&pool)
            .await
            .expect("user row should insert");

        let response = login_with_settings(
            web::Json(LoginInput {
                email: "nulls@example.com".to_owned(),
                password: "password123".to_owned(),
            }),
            web::Data::new(pool),
            AuthSettings {
                require_email_verification: true,
                ..AuthSettings::default()
            },
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body())
            .await
            .expect("response body should be readable");
        let body = String::from_utf8(body.to_vec()).expect("response should be valid utf-8");
        assert!(
            body.contains("\"email_not_verified\""),
            "unexpected body: {body}"
        );
    }

    #[cfg(feature = "turso-local")]
    #[actix_web::test]
    async fn ensure_admin_exists_works_with_encrypted_turso_local() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("vsr_auth_encrypted_{stamp}.db"));
        let env_var = format!("VSR_AUTH_TURSO_KEY_{stamp}");
        let key = "c1bbfda4f589dc9daaf004fe21111e00dc00c98237102f5c7002a5669fc76327";

        unsafe {
            std::env::set_var("ADMIN_EMAIL", "encrypted-admin@example.com");
            std::env::set_var("ADMIN_PASSWORD", "password123");
            std::env::set_var(&env_var, key);
        }

        let config = DatabaseConfig {
            engine: DatabaseEngine::TursoLocal(TursoLocalConfig {
                path: path.to_string_lossy().into_owned(),
                encryption_key: Some(SecretRef::env_or_file(env_var.clone())),
            }),
            resilience: None,
        };
        let pool = connect_with_config("sqlite:ignored.db?mode=rwc", &config)
            .await
            .expect("database should connect");

        for statement in auth_migration_sql(AuthDbBackend::Sqlite)
            .split(';')
            .map(str::trim)
            .filter(|statement| !statement.is_empty())
        {
            query(statement)
                .execute(&pool)
                .await
                .expect("auth schema should apply");
        }

        let created = ensure_admin_exists_with_settings_and_claim_prompt_mode(
            &pool,
            &AuthSettings::default(),
            false,
        )
        .await
        .expect("ensure_admin_exists should not error");
        assert!(created);

        let count: i64 =
            query_scalar::<sqlx::Any, i64>("SELECT COUNT(*) FROM user WHERE role = 'admin'")
                .fetch_one(&pool)
                .await
                .expect("admin row should be queryable");
        assert_eq!(count, 1);

        unsafe {
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
            std::env::remove_var(&env_var);
        }
        let _ = std::fs::remove_file(path);
    }

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    #[actix_web::test]
    async fn ensure_admin_exists_uses_explicit_auth_claim_mappings() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());

        unsafe {
            std::env::set_var("ADMIN_EMAIL", "admin@example.com");
            std::env::set_var("ADMIN_PASSWORD", "password123");
            std::env::set_var("ADMIN_TENANT_SCOPE", "7");
            std::env::set_var("ADMIN_CLAIM_WORKSPACE_ID", "42");
            std::env::set_var("ADMIN_IS_STAFF", "true");
            std::env::set_var("ADMIN_PLAN", "pro");
        }

        let pool = connect_test_pool("ensure_admin_explicit_claims").await;

        query(
            "CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_scope INTEGER NOT NULL,
                claim_workspace_id INTEGER,
                is_staff INTEGER NOT NULL,
                plan TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("user table should be created");

        let settings = AuthSettings {
            claims: BTreeMap::from([
                (
                    "tenant_id".to_owned(),
                    AuthClaimMapping {
                        column: "tenant_scope".to_owned(),
                        ty: AuthClaimType::I64,
                    },
                ),
                (
                    "workspace_id".to_owned(),
                    AuthClaimMapping {
                        column: "claim_workspace_id".to_owned(),
                        ty: AuthClaimType::I64,
                    },
                ),
                (
                    "staff".to_owned(),
                    AuthClaimMapping {
                        column: "is_staff".to_owned(),
                        ty: AuthClaimType::Bool,
                    },
                ),
                (
                    "plan".to_owned(),
                    AuthClaimMapping {
                        column: "plan".to_owned(),
                        ty: AuthClaimType::String,
                    },
                ),
            ]),
            ..AuthSettings::default()
        };

        let created =
            ensure_admin_exists_with_settings_and_claim_prompt_mode(&pool, &settings, false)
                .await
                .expect("ensure_admin_exists should not error");
        assert!(created);

        let row = query(
            "SELECT tenant_scope, claim_workspace_id, CAST(is_staff AS INTEGER) AS is_staff_value, plan \
             FROM user WHERE role = 'admin'",
        )
        .fetch_one(&pool)
        .await
        .expect("admin row should exist");
        let tenant_scope: i64 = row
            .try_get("tenant_scope")
            .expect("tenant scope should decode");
        let workspace_id: Option<i64> = row
            .try_get("claim_workspace_id")
            .expect("workspace claim should decode");
        let is_staff: i64 = row
            .try_get("is_staff_value")
            .expect("is_staff should decode");
        let plan: String = row.try_get("plan").expect("plan should decode");
        assert_eq!(tenant_scope, 7);
        assert_eq!(workspace_id, Some(42));
        assert_eq!(is_staff, 1);
        assert_eq!(plan, "pro");

        unsafe {
            std::env::remove_var("ADMIN_EMAIL");
            std::env::remove_var("ADMIN_PASSWORD");
            std::env::remove_var("ADMIN_TENANT_SCOPE");
            std::env::remove_var("ADMIN_CLAIM_WORKSPACE_ID");
            std::env::remove_var("ADMIN_IS_STAFF");
            std::env::remove_var("ADMIN_PLAN");
        }
    }

    #[cfg(any(feature = "sqlite", feature = "turso-local"))]
    #[actix_web::test]
    async fn validate_auth_claim_mappings_rejects_mismatched_column_types() {
        let pool = connect_test_pool("validate_auth_claims").await;

        query(
            "CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_scope INTEGER NOT NULL,
                is_staff TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("user table should be created");

        let settings = AuthSettings {
            claims: BTreeMap::from([
                (
                    "tenant_id".to_owned(),
                    AuthClaimMapping {
                        column: "tenant_scope".to_owned(),
                        ty: AuthClaimType::I64,
                    },
                ),
                (
                    "staff".to_owned(),
                    AuthClaimMapping {
                        column: "is_staff".to_owned(),
                        ty: AuthClaimType::Bool,
                    },
                ),
            ]),
            ..AuthSettings::default()
        };

        let error = validate_auth_claim_mappings(&pool, &settings)
            .await
            .expect_err("mismatched claim type should fail");
        assert!(error.contains("security.auth.claims.staff"));
        assert!(error.contains("is_staff"));
    }
}
