//! Real built-in login and SQL account state across native Actix and both adapters.
#![cfg(feature = "sqlite")]

#[path = "support/sqlite.rs"]
mod sqlite_test_support;

use actix_web::{App, HttpServer as NativeServer, web};
use rest_macro_core::{
    auth::{
        self, AuthClaimMapping, AuthClaimType, AuthDbBackend, AuthSettings, SessionCookieSettings,
    },
    db::{DbPool, query},
    secret::SecretRef,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use vsr_runtime::{
    auth::request::require_authentication,
    http::{
        ActixHttpServer, AxumHttpServer, HttpMethod, HttpServer, MiddlewareConfig,
        ResponseEnvelope, ServerConfig, make_handler,
    },
};

struct Fixture {
    _directory: tempfile::TempDir,
    db: DbPool,
    settings: AuthSettings,
    key: Vec<u8>,
}

static PASSWORD_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(feature = "auth-email")]
mod builtin_auth_email_flow;

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let key = format!("test-only-{}", uuid::Uuid::new_v4()).into_bytes();
        let key_path = directory.path().join("signing-key");
        std::fs::write(&key_path, &key).unwrap();
        let settings = AuthSettings {
            jwt_secret: Some(SecretRef::File { path: key_path }),
            issuer: Some("builtin-runtime-test".into()),
            audience: Some("builtin-runtime-client".into()),
            session_cookie: Some(SessionCookieSettings {
                secure: false,
                ..Default::default()
            }),
            claims: BTreeMap::from([(
                "tenant_id".into(),
                AuthClaimMapping {
                    column: "tenant_id".into(),
                    ty: AuthClaimType::I64,
                },
            )]),
            ..Default::default()
        };
        let db = rest_macro_core::db::connect(&sqlite_test_support::database_url(
            &directory.path().join("accounts.sqlite"),
        ))
        .await
        .unwrap();
        db.execute_batch(&auth::auth_migration_sql(AuthDbBackend::Sqlite))
            .await
            .unwrap();
        db.execute_batch(&auth::auth_management_migration_sql(AuthDbBackend::Sqlite))
            .await
            .unwrap();
        query("ALTER TABLE user ADD COLUMN tenant_id INTEGER DEFAULT 7")
            .execute(&db)
            .await
            .unwrap();
        let hash = vsr_runtime::auth::password::hash("original-password", 4)
            .await
            .unwrap();
        query("INSERT INTO user (email, password_hash, role, created_at, updated_at) VALUES ('owner@example.test', ?, 'admin', 'created', 'initial')")
            .bind(hash).execute(&db).await.unwrap();
        Self {
            _directory: directory,
            db,
            settings,
            key,
        }
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

async fn start_neutral<B: HttpServer>(fixture: &Fixture) -> B::Handle {
    let authenticator = Arc::new(auth::builtin_request_authenticator(
        fixture.db.clone(),
        fixture.settings.clone(),
    ));
    let protected = require_authentication(
        authenticator,
        make_handler(|request| async move {
            let identity = request
                .identity
                .expect("wrapper must authenticate before dispatch");
            let mut body = serde_json::Map::from_iter(identity.claims);
            body.insert(
                "id".into(),
                Value::from(identity.user_id.parse::<i64>().unwrap()),
            );
            body.insert("roles".into(), json!(identity.roles));
            ResponseEnvelope::json(body)
        }),
    );
    B::serve(
        ServerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            shutdown_timeout: Duration::from_secs(2),
            ..Default::default()
        },
        MiddlewareConfig::default(),
        vec![
            (HttpMethod::Get, "/protected".into(), protected.clone()),
            (HttpMethod::Post, "/protected".into(), protected),
        ],
    )
    .await
    .unwrap()
}

// Deliberately test-only bearer route adapters. Production cookie presentation,
// extraction and login rate limiting still live in the legacy HTTP facade.
async fn start_account_service<B: HttpServer>(fixture: &Fixture) -> B::Handle {
    let service = Arc::new(
        auth::builtin_account_service(fixture.db.clone(), fixture.settings.clone()).unwrap(),
    );
    let authenticator = Arc::new(auth::builtin_request_authenticator(
        fixture.db.clone(),
        fixture.settings.clone(),
    ));
    let login_service = service.clone();
    let login = make_handler(move |request| {
        let service = login_service.clone();
        async move {
            let input: auth::LoginInput =
                match serde_json::from_slice(request.body.as_deref().unwrap_or_default()) {
                    Ok(input) => input,
                    Err(_) => return ResponseEnvelope::error(400, "Invalid JSON"),
                };
            match service.login(&input.email, &input.password).await {
                Ok(token) => ResponseEnvelope::json(json!({"token": token})),
                Err(error) => error.response(),
            }
        }
    });
    let account_service = service.clone();
    let account = require_authentication(
        authenticator.clone(),
        make_handler(move |request| {
            let service = account_service.clone();
            async move {
                let id = request.identity.unwrap().user_id.parse().unwrap();
                match service.account(id).await {
                    Ok(account) => ResponseEnvelope::json(account),
                    Err(error) => error.response(),
                }
            }
        }),
    );
    let password = require_authentication(
        authenticator,
        make_handler(move |request| {
            let service = service.clone();
            async move {
                let id = request.identity.unwrap().user_id.parse().unwrap();
                let input: auth::ChangePasswordInput =
                    match serde_json::from_slice(request.body.as_deref().unwrap_or_default()) {
                        Ok(input) => input,
                        Err(_) => return ResponseEnvelope::error(400, "Invalid JSON"),
                    };
                match service
                    .change_password(id, &input.current_password, &input.new_password)
                    .await
                {
                    Ok(()) => ResponseEnvelope::status(204),
                    Err(error) => error.response(),
                }
            }
        }),
    );
    B::serve(
        ServerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            shutdown_timeout: Duration::from_secs(2),
            ..Default::default()
        },
        MiddlewareConfig::default(),
        vec![
            (HttpMethod::Post, "/auth/login".into(), login),
            (HttpMethod::Get, "/auth/account".into(), account),
            (HttpMethod::Post, "/auth/account/password".into(), password),
        ]
        .into_iter()
        .chain(recovery_routes(fixture))
        .chain(recovery_email_routes(fixture))
        .collect(),
    )
    .await
    .unwrap()
}

async fn account_response(request: reqwest::RequestBuilder, status: u16) -> Value {
    let response = request.send().await.unwrap();
    assert_eq!(response.status().as_u16(), status);
    assert_eq!(response.headers().get_all("set-cookie").iter().count(), 0);
    if status == 204 || status == 202 {
        assert!(response.bytes().await.unwrap().is_empty());
        Value::Null
    } else {
        response.json().await.unwrap()
    }
}

fn recovery_email_routes(
    fixture: &Fixture,
) -> Vec<(HttpMethod, String, vsr_runtime::http::Handler)> {
    use vsr_runtime::auth::recovery::TokenPurpose;
    let Some(email) = &fixture.settings.email else {
        return Vec::new();
    };
    let base = email.public_base_url.as_deref().unwrap();
    [
        (
            "/auth/verification/resend",
            "/auth/verify-email",
            TokenPurpose::EmailVerification,
        ),
        (
            "/auth/password-reset/request",
            "/auth/password-reset",
            TokenPurpose::PasswordReset,
        ),
    ]
    .into_iter()
    .map(|(path, action, purpose)| {
        let service = Arc::new(
            auth::builtin_recovery_email_service(
                fixture.db.clone(),
                &fixture.settings,
                &format!("{base}{action}"),
                purpose,
            )
            .unwrap(),
        );
        let handler = make_handler(move |request| {
            let service = service.clone();
            async move {
                let input: auth::PasswordResetRequestInput =
                    match serde_json::from_slice(request.body.as_deref().unwrap_or_default()) {
                        Ok(input) => input,
                        Err(_) => return ResponseEnvelope::error(400, "Invalid JSON"),
                    };
                match service.request(&input.email).await {
                    Ok(()) => ResponseEnvelope::status(202),
                    Err(error) => error.response(),
                }
            }
        });
        (HttpMethod::Post, path.to_owned(), handler)
    })
    .collect()
}

fn recovery_routes(fixture: &Fixture) -> Vec<(HttpMethod, String, vsr_runtime::http::Handler)> {
    use vsr_runtime::auth::recovery::TokenPurpose;
    let service = Arc::new(auth::builtin_recovery_service(fixture.db.clone()));
    [
        ("/auth/verify-email", TokenPurpose::EmailVerification),
        ("/auth/password-reset/confirm", TokenPurpose::PasswordReset),
    ]
    .into_iter()
    .map(|(path, purpose)| {
        let service = service.clone();
        let handler = make_handler(move |request| {
            let service = service.clone();
            async move {
                let result = match purpose {
                    TokenPurpose::EmailVerification => {
                        let input: auth::VerifyEmailInput = match serde_json::from_slice(
                            request.body.as_deref().unwrap_or_default(),
                        ) {
                            Ok(input) => input,
                            Err(_) => return ResponseEnvelope::error(400, "Invalid JSON"),
                        };
                        service.verify_email(&input.token).await
                    }
                    TokenPurpose::PasswordReset => {
                        let input: auth::PasswordResetConfirmInput = match serde_json::from_slice(
                            request.body.as_deref().unwrap_or_default(),
                        ) {
                            Ok(input) => input,
                            Err(_) => return ResponseEnvelope::error(400, "Invalid JSON"),
                        };
                        service
                            .reset_password(&input.token, &input.new_password)
                            .await
                    }
                };
                match result {
                    Ok(outcome) => outcome.response(purpose),
                    Err(error) => error.response(),
                }
            }
        });
        (HttpMethod::Post, path.into(), handler)
    })
    .collect()
}

async fn recovery_token(
    fixture: &Fixture,
    purpose: vsr_runtime::auth::recovery::TokenPurpose,
    expiry: &str,
) -> String {
    // Controlled database fixture, using the real issuance hash/schema format.
    // Email delivery is covered separately by the native lifecycle suite.
    let raw = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    query("INSERT INTO auth_user_token (user_id, purpose, token_hash, requested_email, expires_at) VALUES (1, ?, ?, 'owner@example.test', ?)")
        .bind(purpose.as_str()).bind(vsr_runtime::auth::recovery::token_digest(&raw)).bind(expiry).execute(&fixture.db).await.unwrap();
    raw
}

#[actix_web::test]
async fn recovery_tokens_are_single_use_and_revoke_sessions_across_all_three_paths() {
    use vsr_runtime::auth::recovery::TokenPurpose::{EmailVerification, PasswordReset};
    let _guard = PASSWORD_TEST_LOCK.lock().await;
    let mut fixture = Fixture::new().await;
    fixture.settings.session_cookie = None;
    let db = fixture.db.clone();
    let settings = fixture.settings.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let native_base = format!("http://{}", listener.local_addr().unwrap());
    let server = NativeServer::new(move || {
        let db = db.clone();
        let settings = settings.clone();
        App::new().configure(move |cfg| {
            auth::auth_routes_with_settings(cfg, db.clone(), settings.clone())
        })
    })
    .workers(1)
    .disable_signals()
    .listen(listener)
    .unwrap()
    .run();
    let native_handle = server.handle();
    let native_task = actix_web::rt::spawn(server);
    let actix = start_account_service::<ActixHttpServer>(&fixture).await;
    let axum = start_account_service::<AxumHttpServer>(&fixture).await;
    let bases = [
        native_base,
        format!("http://{}", actix.addresses()[0]),
        format!("http://{}", axum.addresses()[0]),
    ];
    let client = client();
    let expires = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
    let mut password = "original-password".to_owned();
    for (index, writer) in bases.iter().enumerate() {
        let before = account_response(
            client
                .post(format!("{writer}/auth/login"))
                .json(&json!({"email":"owner@example.test", "password":password})),
            200,
        )
        .await;
        let before = before["token"].as_str().unwrap();
        let verification = recovery_token(&fixture, EmailVerification, &expires).await;
        let sibling = recovery_token(&fixture, EmailVerification, &expires).await;
        let reset = recovery_token(&fixture, PasswordReset, &expires).await;
        account_response(
            client
                .post(format!("{writer}/auth/verify-email"))
                .json(&json!({"token":verification})),
            204,
        )
        .await;
        for base in &bases {
            let body = account_response(
                client
                    .get(format!("{base}/auth/account"))
                    .bearer_auth(before),
                401,
            )
            .await;
            assert_eq!(body["code"], "revoked_token");
            for raw in [&verification, &sibling, &reset] {
                let body = account_response(
                    client
                        .post(format!("{base}/auth/verify-email"))
                        .json(&json!({"token":raw})),
                    400,
                )
                .await;
                assert_eq!(body["code"], "invalid_token");
            }
        }
        let active = account_response(
            client
                .post(format!("{writer}/auth/login"))
                .json(&json!({"email":"owner@example.test", "password":password})),
            200,
        )
        .await;
        let active = active["token"].as_str().unwrap();
        let reset_sibling = recovery_token(&fixture, PasswordReset, &expires).await;
        let next_password = format!("recovered-password-{index}");
        // The reset credential survived wrong-purpose verification attempts.
        account_response(
            client
                .post(format!("{writer}/auth/password-reset/confirm"))
                .json(&json!({"token":reset, "new_password":next_password})),
            204,
        )
        .await;
        for base in &bases {
            assert_eq!(
                account_response(
                    client
                        .get(format!("{base}/auth/account"))
                        .bearer_auth(active),
                    401
                )
                .await["code"],
                "revoked_token"
            );
            for raw in [&reset, &reset_sibling] {
                assert_eq!(
                    account_response(
                        client
                            .post(format!("{base}/auth/password-reset/confirm"))
                            .json(&json!({"token":raw, "new_password":"replayed-password"})),
                        400
                    )
                    .await["code"],
                    "invalid_token"
                );
            }
            let login = account_response(
                client
                    .post(format!("{base}/auth/login"))
                    .json(&json!({"email":"owner@example.test", "password":next_password})),
                200,
            )
            .await;
            let account = account_response(
                client
                    .get(format!("{base}/auth/account"))
                    .bearer_auth(login["token"].as_str().unwrap()),
                200,
            )
            .await;
            assert_eq!(account["email_verified"], true);
            assert_eq!(account["tenant_id"], 7);
        }
        password = next_password;
    }
    for base in &bases {
        for expiry in ["2000-01-01T00:00:00Z", "invalid-date"] {
            let raw = recovery_token(&fixture, EmailVerification, expiry).await;
            assert_eq!(
                account_response(
                    client
                        .post(format!("{base}/auth/verify-email"))
                        .json(&json!({"token":raw})),
                    400
                )
                .await["code"],
                "expired_token"
            );
        }
        let body = account_response(
            client
                .post(format!("{base}/auth/password-reset/confirm"))
                .json(&json!({"token":" ", "new_password":"valid-password"})),
            400,
        )
        .await;
        assert_eq!(body["field"], "token");
        let body = account_response(
            client
                .post(format!("{base}/auth/password-reset/confirm"))
                .json(&json!({"token":"nonempty", "new_password":"short"})),
            400,
        )
        .await;
        assert_eq!(body["field"], "password");
    }
    // A link sent to the previous address must not verify the new address.
    for base in &bases {
        let raw = recovery_token(&fixture, EmailVerification, &expires).await;
        query("UPDATE user SET email = 'renamed@example.test' WHERE id = 1")
            .execute(&fixture.db)
            .await
            .unwrap();
        assert_eq!(
            account_response(
                client
                    .post(format!("{base}/auth/verify-email"))
                    .json(&json!({"token":raw})),
                400
            )
            .await["code"],
            "invalid_token"
        );
        query("UPDATE user SET email = 'owner@example.test' WHERE id = 1")
            .execute(&fixture.db)
            .await
            .unwrap();
        assert_eq!(
            account_response(
                client
                    .post(format!("{base}/auth/verify-email"))
                    .json(&json!({"token":raw})),
                400
            )
            .await["code"],
            "invalid_token"
        );
    }
    AxumHttpServer::shutdown(axum).await.unwrap();
    ActixHttpServer::shutdown(actix).await.unwrap();
    native_handle.stop(true).await;
    native_task.await.unwrap().unwrap();
    match &fixture.db {
        DbPool::Sqlx { pool, .. } => pool.close().await,
        #[cfg(feature = "turso-local")]
        DbPool::TursoLocal(_) => unreachable!("SQLite fixture"),
    }
}

#[actix_web::test]
async fn account_operations_and_password_revocation_work_across_all_three_paths() {
    let _guard = PASSWORD_TEST_LOCK.lock().await;
    let mut fixture = Fixture::new().await;
    fixture.settings.session_cookie = None;
    let db = fixture.db.clone();
    let settings = fixture.settings.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let native_base = format!("http://{}", listener.local_addr().unwrap());
    let server = NativeServer::new(move || {
        let db = db.clone();
        let settings = settings.clone();
        App::new().configure(move |cfg| {
            auth::auth_routes_with_settings(cfg, db.clone(), settings.clone())
        })
    })
    .workers(1)
    .disable_signals()
    .listen(listener)
    .unwrap()
    .run();
    let native_handle = server.handle();
    let native_task = actix_web::rt::spawn(server);
    let actix = start_account_service::<ActixHttpServer>(&fixture).await;
    let axum = start_account_service::<AxumHttpServer>(&fixture).await;
    let bases = [
        native_base,
        format!("http://{}", actix.addresses()[0]),
        format!("http://{}", axum.addresses()[0]),
    ];
    let client = client();
    let mut password = "original-password".to_owned();
    for (index, writer) in bases.iter().enumerate() {
        let mut tokens = Vec::new();
        for base in &bases {
            let body = account_response(
                client
                    .post(format!("{base}/auth/login"))
                    .json(&json!({"email":" OWNER@EXAMPLE.TEST ", "password":password})),
                200,
            )
            .await;
            tokens.push(body["token"].as_str().unwrap().to_owned());
        }
        // Tokens issued by every path must authenticate on every other path.
        let mut expected_account = None;
        for base in &bases {
            assert_eq!(
                account_response(client.get(format!("{base}/auth/account")), 401).await["code"],
                "missing_token"
            );
            for token in &tokens {
                let body = account_response(
                    client
                        .get(format!("{base}/auth/account"))
                        .bearer_auth(token),
                    200,
                )
                .await;
                assert_eq!(body["id"], 1);
                assert_eq!(body["tenant_id"], 7);
                assert_eq!(body["roles"], json!(["admin"]));
                assert!(body.get("password_hash").is_none());
                assert!(body.get("_vsr_auth_state").is_none());
                if let Some(expected) = &expected_account {
                    assert_eq!(&body, expected);
                } else {
                    expected_account = Some(body);
                }
            }
            let wrong = account_response(
                client
                    .post(format!("{base}/auth/login"))
                    .json(&json!({"email":"owner@example.test", "password":"incorrect"})),
                401,
            )
            .await;
            assert_eq!(
                wrong,
                json!({"code":"invalid_credentials", "message":"Invalid credentials"})
            );
            let wrong = account_response(client.post(format!("{base}/auth/account/password")).bearer_auth(&tokens[0])
                .json(&json!({"current_password":"incorrect", "new_password":"valid-new-password"})), 401).await;
            assert_eq!(
                wrong,
                json!({"code":"invalid_credentials", "message":"Current password is incorrect"})
            );
            let invalid = account_response(
                client
                    .post(format!("{base}/auth/account/password"))
                    .bearer_auth(&tokens[0])
                    .json(&json!({"current_password":password, "new_password":"short"})),
                400,
            )
            .await;
            assert_eq!(invalid["code"], "validation_error");
            assert_eq!(invalid["field"], "password");
            let anonymous = account_response(
                client.post(format!("{base}/auth/account/password")).json(
                    &json!({"current_password":password, "new_password":"valid-new-password"}),
                ),
                401,
            )
            .await;
            assert_eq!(anonymous["code"], "missing_token");
        }
        let next_password = format!("changed-password-{index}");
        account_response(client.post(format!("{writer}/auth/account/password")).bearer_auth(&tokens[index])
            .json(&json!({"current_password":password, "new_password":next_password, "user_id":999})), 204).await;
        for base in &bases {
            for token in &tokens {
                assert_eq!(
                    account_response(
                        client
                            .get(format!("{base}/auth/account"))
                            .bearer_auth(token),
                        401
                    )
                    .await["code"],
                    "revoked_token"
                );
            }
            assert_eq!(
                account_response(
                    client
                        .post(format!("{base}/auth/login"))
                        .json(&json!({"email":"owner@example.test", "password":password})),
                    401
                )
                .await["code"],
                "invalid_credentials"
            );
        }
        password = next_password;
    }
    let body = account_response(
        client
            .post(format!("{}/auth/login", bases[2]))
            .json(&json!({"email":"owner@example.test", "password":password})),
        200,
    )
    .await;
    let token = body["token"].as_str().unwrap();
    query("DELETE FROM user WHERE id = 1")
        .execute(&fixture.db)
        .await
        .unwrap();
    for base in &bases {
        assert_eq!(
            account_response(
                client
                    .get(format!("{base}/auth/account"))
                    .bearer_auth(token),
                401
            )
            .await["code"],
            "revoked_token"
        );
    }
    query("DROP TABLE user").execute(&fixture.db).await.unwrap();
    for base in &bases {
        assert_eq!(
            account_response(
                client
                    .get(format!("{base}/auth/account"))
                    .bearer_auth(token),
                500
            )
            .await["code"],
            "internal_error"
        );
        assert_eq!(
            account_response(
                client
                    .post(format!("{base}/auth/login"))
                    .json(&json!({"email":"owner@example.test", "password":password})),
                500
            )
            .await["code"],
            "internal_error"
        );
    }
    AxumHttpServer::shutdown(axum).await.unwrap();
    ActixHttpServer::shutdown(actix).await.unwrap();
    native_handle.stop(true).await;
    native_task.await.unwrap().unwrap();
    match &fixture.db {
        DbPool::Sqlx { pool, .. } => pool.close().await,
        #[cfg(feature = "turso-local")]
        DbPool::TursoLocal(_) => unreachable!("SQLite fixture"),
    }
}

async fn expect(request: reqwest::RequestBuilder, status: u16, code: Option<&str>) -> Value {
    let response = request.send().await.unwrap();
    assert_eq!(response.status().as_u16(), status);
    if status == 401 {
        assert_eq!(response.headers()["www-authenticate"], "Bearer");
    }
    let body: Value = response.json().await.unwrap();
    if let Some(code) = code {
        assert_eq!(body["code"], code);
    }
    body
}

async fn login(base: &str, password: &str) -> Value {
    let response = client()
        .post(format!("{base}/auth/login"))
        .json(&json!({"email": "owner@example.test", "password": password}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get_all("set-cookie").iter().count(), 2);
    response.json().await.unwrap()
}

#[actix_web::test]
async fn native_and_neutral_builtin_authentication_have_identical_live_policy() {
    let _guard = PASSWORD_TEST_LOCK.lock().await;
    let fixture = Fixture::new().await;
    let db = fixture.db.clone();
    let settings = fixture.settings.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let native_base = format!("http://{}", listener.local_addr().unwrap());
    let server = NativeServer::new(move || {
        let db = db.clone();
        let settings = settings.clone();
        App::new()
            .configure(move |cfg| {
                auth::auth_routes_with_settings(cfg, db.clone(), settings.clone())
            })
            .route("/protected", web::get().to(auth::me))
            .route("/protected", web::post().to(auth::me))
    })
    .workers(1)
    .disable_signals()
    .listen(listener)
    .unwrap()
    .run();
    let native_handle = server.handle();
    let native_task = actix_web::rt::spawn(server);
    let actix = start_neutral::<ActixHttpServer>(&fixture).await;
    let axum = start_neutral::<AxumHttpServer>(&fixture).await;
    let urls = [
        format!("{native_base}/protected"),
        format!("http://{}/protected", actix.addresses()[0]),
        format!("http://{}/protected", axum.addresses()[0]),
    ];
    let client = client();
    let login_body = login(&native_base, "original-password").await;
    let token = login_body["token"].as_str().unwrap();
    let csrf = login_body["csrf_token"].as_str().unwrap();
    let cookie_settings = fixture.settings.session_cookie.as_ref().unwrap();
    let session = format!("{}={token}", cookie_settings.name);
    let cookies = format!("{session}; {}={csrf}", cookie_settings.csrf_cookie_name);
    let expected = json!({"id": 1, "roles": ["admin"], "tenant_id": 7});

    for url in &urls {
        expect(client.get(url), 401, Some("missing_token")).await;
        assert_eq!(
            expect(client.get(url).bearer_auth(token), 200, None).await,
            expected
        );
        assert_eq!(
            expect(
                client
                    .get(url)
                    .header("authorization", format!("bEaReR {token}")),
                200,
                None
            )
            .await,
            expected
        );
        assert_eq!(
            expect(client.get(url).header("cookie", &session), 200, None).await,
            expected
        );
        expect(
            client.post(url).header("cookie", &session),
            403,
            Some("invalid_csrf"),
        )
        .await;
        assert_eq!(
            expect(
                client
                    .post(url)
                    .header("cookie", &cookies)
                    .header(&cookie_settings.csrf_header_name, csrf),
                200,
                None
            )
            .await,
            expected
        );
        expect(
            client
                .post(url)
                .header("cookie", &cookies)
                .header(&cookie_settings.csrf_header_name, "wrong"),
            403,
            Some("invalid_csrf"),
        )
        .await;
        expect(
            client
                .post(url)
                .header("cookie", &cookies)
                .header(&cookie_settings.csrf_header_name, csrf)
                .header(&cookie_settings.csrf_header_name, csrf),
            403,
            Some("invalid_csrf"),
        )
        .await;
        expect(
            client
                .get(url)
                .header("cookie", format!("{session}; {session}")),
            401,
            Some("invalid_token"),
        )
        .await;
        expect(
            client
                .get(url)
                .bearer_auth(token)
                .header("authorization", format!("Bearer {token}")),
            401,
            Some("invalid_token"),
        )
        .await;
        expect(
            client
                .get(url)
                .header("authorization", "Basic invalid")
                .header("cookie", &cookies),
            401,
            Some("invalid_token"),
        )
        .await;
        expect(
            client
                .get(url)
                .header("authorization", "Bearer invalid")
                .header("cookie", &cookies),
            401,
            Some("invalid_token"),
        )
        .await;
        expect(
            client.get(url).header(
                "authorization",
                reqwest::header::HeaderValue::from_bytes(&[0x80]).unwrap(),
            ),
            401,
            Some("invalid_token"),
        )
        .await;
    }

    // Valid signatures do not bypass required account state or configured claims.
    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    let mut validation = validation;
    validation.validate_aud = false;
    let valid_claims = jsonwebtoken::decode::<Value>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(&fixture.key),
        &validation,
    )
    .unwrap()
    .claims;
    for field in ["_vsr_auth_state", "iss", "aud", "exp", "sub"] {
        let mut claims = valid_claims.clone();
        let expected_code = if field == "_vsr_auth_state" {
            claims.as_object_mut().unwrap().remove(field);
            "revoked_token"
        } else {
            claims[field] = match field {
                "exp" | "sub" => json!(0),
                _ => json!("wrong"),
            };
            "invalid_token"
        };
        let altered = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(&fixture.key),
        )
        .unwrap();
        for url in &urls {
            expect(
                client.get(url).bearer_auth(&altered),
                401,
                Some(expected_code),
            )
            .await;
        }
    }
    let wrong_signature = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &valid_claims,
        &jsonwebtoken::EncodingKey::from_secret(b"different-test-key"),
    )
    .unwrap();
    for url in &urls {
        expect(
            client.get(url).bearer_auth(&wrong_signature),
            401,
            Some("invalid_token"),
        )
        .await;
    }

    let mut current = token.to_owned();
    for change in [
        "UPDATE user SET role = 'editor', updated_at = 'demoted' WHERE id = 1",
        "UPDATE user SET role = 'admin', updated_at = 'restored' WHERE id = 1",
        "UPDATE user SET tenant_id = 8, updated_at = 'claim-changed' WHERE id = 1",
    ] {
        query(change).execute(&fixture.db).await.unwrap();
        for url in &urls {
            expect(
                client.get(url).bearer_auth(&current),
                401,
                Some("revoked_token"),
            )
            .await;
            expect(
                client.get(url).bearer_auth(token),
                401,
                Some("revoked_token"),
            )
            .await;
        }
        current = login(&native_base, "original-password").await["token"]
            .as_str()
            .unwrap()
            .to_owned();
        let reference = expect(client.get(&urls[0]).bearer_auth(&current), 200, None).await;
        for url in &urls[1..] {
            assert_eq!(
                expect(client.get(url).bearer_auth(&current), 200, None).await,
                reference
            );
        }
    }

    let response = client.post(format!("{native_base}/auth/account/password")).bearer_auth(&current)
        .json(&json!({"current_password": "original-password", "new_password": "replacement-password"})).send().await.unwrap();
    assert_eq!(response.status(), 204);
    for url in &urls {
        expect(
            client.get(url).bearer_auth(&current),
            401,
            Some("revoked_token"),
        )
        .await;
    }
    current = login(&native_base, "replacement-password").await["token"]
        .as_str()
        .unwrap()
        .to_owned();
    for url in &urls {
        expect(client.get(url).bearer_auth(&current), 200, None).await;
    }
    query("DELETE FROM user WHERE id = 1")
        .execute(&fixture.db)
        .await
        .unwrap();
    for url in &urls {
        expect(
            client.get(url).bearer_auth(&current),
            401,
            Some("revoked_token"),
        )
        .await;
    }
    query("DROP TABLE user").execute(&fixture.db).await.unwrap();
    for url in &urls {
        expect(
            client.get(url).bearer_auth(&current),
            500,
            Some("internal_error"),
        )
        .await;
    }

    AxumHttpServer::shutdown(axum).await.unwrap();
    ActixHttpServer::shutdown(actix).await.unwrap();
    native_handle.stop(true).await;
    native_task.await.unwrap().unwrap();
    // Close SQLite handles before TempDir cleanup, including on Windows.
    match &fixture.db {
        DbPool::Sqlx { pool, .. } => pool.close().await,
        #[cfg(feature = "turso-local")]
        DbPool::TursoLocal(_) => unreachable!("fixture explicitly uses SQLite"),
    }
}
