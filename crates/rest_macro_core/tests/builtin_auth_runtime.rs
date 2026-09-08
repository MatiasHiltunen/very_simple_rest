//! Real built-in login and SQL account state across native Actix and both adapters.
#![cfg(feature = "sqlite")]

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
        ResponseEnvelope, ServerConfig, ServerHandle, make_handler,
    },
};

struct Fixture {
    _directory: tempfile::TempDir,
    db: DbPool,
    settings: AuthSettings,
    key: Vec<u8>,
}

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
        let db = rest_macro_core::db::connect(&format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("accounts.sqlite").display()
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
