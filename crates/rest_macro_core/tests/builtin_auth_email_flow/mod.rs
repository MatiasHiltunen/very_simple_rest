use super::*;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[actix_web::test]
async fn issued_email_links_work_across_native_actix_and_axum() {
    let _guard = PASSWORD_TEST_LOCK.lock().await;
    assert!(
        std::env::var_os("VSR_AUTH_EMAIL_CAPTURE_DIR").is_none(),
        "provider proof requires capture mode to be disabled"
    );
    let messages = Arc::new(Mutex::new(Vec::<Value>::new()));
    let fail = Arc::new(AtomicBool::new(false));
    let capture = messages.clone();
    let reject = fail.clone();
    let provider = AxumHttpServer::serve(
        ServerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        },
        MiddlewareConfig::default(),
        vec![(
            HttpMethod::Post,
            "/emails".into(),
            make_handler(move |request| {
                let capture = capture.clone();
                let reject = reject.clone();
                async move {
                    if reject.load(Ordering::SeqCst) {
                        return ResponseEnvelope::error(502, "sensitive-provider-error-token");
                    }
                    capture
                        .lock()
                        .unwrap()
                        .push(serde_json::from_slice(request.body.as_deref().unwrap()).unwrap());
                    ResponseEnvelope::json(json!({"id":"test-message"}))
                }
            }),
        )],
    )
    .await
    .unwrap();

    let mut fixture = Fixture::new().await;
    fixture.settings.session_cookie = None;
    fixture.settings.require_email_verification = true;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let native_base = format!("http://{}", listener.local_addr().unwrap());
    let provider_key = fixture._directory.path().join("provider-key");
    std::fs::write(&provider_key, "test-only-provider-key").unwrap();
    fixture.settings.email = Some(auth::AuthEmailSettings {
        from_email: "noreply@example.test".into(),
        from_name: Some("VSR App".into()),
        reply_to: Some("support@example.test".into()),
        public_base_url: Some(native_base.clone()),
        provider: auth::AuthEmailProvider::Resend {
            api_key: SecretRef::File { path: provider_key },
            api_base_url: Some(format!("http://{}", provider.addresses()[0])),
        },
    });
    let db = fixture.db.clone();
    let settings = fixture.settings.clone();
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
        native_base.clone(),
        format!("http://{}", actix.addresses()[0]),
        format!("http://{}", axum.addresses()[0]),
    ];
    let client = client();
    let mut password = "original-password".to_owned();
    for (index, writer) in bases.iter().enumerate() {
        query("UPDATE user SET email_verified_at = NULL WHERE id = 1")
            .execute(&fixture.db)
            .await
            .unwrap();
        account_response(
            client
                .post(format!("{writer}/auth/login"))
                .json(&json!({"email":"owner@example.test","password":password})),
            403,
        )
        .await;
        for (path, action, confirm) in [
            (
                "/auth/verification/resend",
                "/auth/verify-email",
                "/auth/verify-email",
            ),
            (
                "/auth/password-reset/request",
                "/auth/password-reset",
                "/auth/password-reset/confirm",
            ),
        ] {
            let count = messages.lock().unwrap().len();
            account_response(
                client
                    .post(format!("{writer}{path}"))
                    .json(&json!({"email":"absent@example.test"})),
                202,
            )
            .await;
            assert_eq!(messages.lock().unwrap().len(), count);
            account_response(
                client
                    .post(format!("{writer}{path}"))
                    .header("host", "attacker.example")
                    .header("forwarded", "host=attacker.example;proto=https")
                    .json(&json!({"email":" Owner@EXAMPLE.TEST "})),
                202,
            )
            .await;
            assert_eq!(messages.lock().unwrap().len(), count + 1);
            let message = messages.lock().unwrap()[count].clone();
            assert_eq!(message["to"], json!(["owner@example.test"]));
            assert_eq!(message["from"], "VSR App <noreply@example.test>");
            assert_eq!(message["reply_to"], "support@example.test");
            let url = url::Url::parse(
                message["text"]
                    .as_str()
                    .unwrap()
                    .split("\n\n")
                    .nth(1)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(url.path(), action);
            assert!(url.as_str().starts_with(&native_base));
            assert!(!url.as_str().contains("attacker"));
            let raw = url
                .query_pairs()
                .find(|(key, _)| key == "token")
                .unwrap()
                .1
                .into_owned();
            assert_eq!(raw.len(), 64);
            assert!(message["html"].as_str().unwrap().contains(url.as_str()));
            fail.store(true, Ordering::SeqCst);
            let error = account_response(
                client
                    .post(format!("{writer}{path}"))
                    .json(&json!({"email":"owner@example.test"})),
                500,
            )
            .await;
            assert_eq!(error["message"], "Failed to send authentication email");
            assert!(!error.to_string().contains("sensitive-provider"));
            fail.store(false, Ordering::SeqCst);

            let session = if confirm.ends_with("confirm") {
                Some(
                    account_response(
                        client
                            .post(format!("{writer}/auth/login"))
                            .json(&json!({"email":"owner@example.test","password":password})),
                        200,
                    )
                    .await["token"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                )
            } else {
                None
            };
            let new_password = format!("email-recovered-password-{index}");
            let body = json!({"token":raw,"new_password":new_password});
            let consumer = &bases[(index + 1) % bases.len()];
            account_response(client.post(format!("{consumer}{confirm}")).json(&body), 204).await;
            account_response(client.post(format!("{writer}{confirm}")).json(&body), 400).await;
            if let Some(session) = session {
                for base in &bases {
                    account_response(
                        client
                            .get(format!("{base}/auth/account"))
                            .bearer_auth(&session),
                        401,
                    )
                    .await;
                    account_response(
                        client
                            .post(format!("{base}/auth/login"))
                            .json(&json!({"email":"owner@example.test","password":password})),
                        401,
                    )
                    .await;
                    account_response(
                        client
                            .post(format!("{base}/auth/login"))
                            .json(&json!({"email":"owner@example.test","password":new_password})),
                        200,
                    )
                    .await;
                }
                password = new_password;
            } else {
                account_response(
                    client
                        .post(format!("{writer}{path}"))
                        .json(&json!({"email":"owner@example.test"})),
                    202,
                )
                .await;
                assert_eq!(messages.lock().unwrap().len(), count + 1);
            }
        }
    }
    // Registration also uses the shared issuer within its existing transaction.
    let response = client
        .post(format!("{native_base}/auth/register"))
        .json(&json!({"email":"new@example.test","password":"registration-password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    assert_eq!(
        messages.lock().unwrap().last().unwrap()["to"],
        json!(["new@example.test"])
    );
    AxumHttpServer::shutdown(axum).await.unwrap();
    ActixHttpServer::shutdown(actix).await.unwrap();
    native_handle.stop(true).await;
    native_task.await.unwrap().unwrap();
    AxumHttpServer::shutdown(provider).await.unwrap();
    match &fixture.db {
        DbPool::Sqlx { pool, .. } => pool.close().await,
        #[cfg(feature = "turso-local")]
        DbPool::TursoLocal(_) => unreachable!("SQLite fixture"),
    }
}
