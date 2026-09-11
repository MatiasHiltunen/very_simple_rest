use super::*;

pub(super) fn routes(fixture: &Fixture) -> Vec<(HttpMethod, String, vsr_runtime::http::Handler)> {
    let url = fixture.settings.email.as_ref().map(|email| {
        format!(
            "{}/auth/verify-email",
            email.public_base_url.as_deref().unwrap()
        )
    });
    let service = Arc::new(
        auth::builtin_provisioning_service(fixture.db.clone(), &fixture.settings, url.as_deref())
            .unwrap(),
    );
    let authenticator = Arc::new(auth::builtin_request_authenticator(
        fixture.db.clone(),
        fixture.settings.clone(),
    ));
    [
        "/auth/admin/users",
        "/auth/admin/users/{id}/verification",
        "/auth/account/verification",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, path)| {
        let service = service.clone();
        (
            HttpMethod::Post,
            path.into(),
            require_authentication(
                authenticator.clone(),
                make_handler(move |request| {
                    let service = service.clone();
                    async move {
                        let actor = request.identity.unwrap();
                        if index == 0 {
                            let input = match serde_json::from_slice(
                                request.body.as_deref().unwrap_or_default(),
                            ) {
                                Ok(input) => input,
                                Err(_) => return ResponseEnvelope::error(400, "Invalid JSON"),
                            };
                            return match service.create(&actor, &input).await {
                                Ok(account) => {
                                    let location = format!("/auth/admin/users/{}", account.id);
                                    let mut response = ResponseEnvelope::json(account);
                                    response.status = 201;
                                    response.headers.append("location", location).unwrap();
                                    response
                                }
                                Err(error) => error.response(),
                            };
                        }
                        let result = if index == 1 {
                            let Some(id) = request
                                .path_params
                                .get("id")
                                .and_then(|value| value.parse().ok())
                            else {
                                return ResponseEnvelope::error(400, "Invalid path");
                            };
                            service.resend_managed(&actor, id).await
                        } else {
                            service.resend_account(&actor).await
                        };
                        match result {
                            Ok(outcome) => outcome.response(),
                            Err(error) => error.response(),
                        }
                    }
                }),
            ),
        )
    })
    .collect()
}

#[cfg(feature = "auth-email")]
async fn login_for(base: &str, email: &str, password: &str) -> String {
    account_response(
        client()
            .post(format!("{base}/auth/login"))
            .json(&json!({"email":email,"password":password})),
        200,
    )
    .await["token"]
        .as_str()
        .unwrap()
        .into()
}

#[cfg(feature = "auth-email")]
fn email_token(message: &Value, base: &str, email: &str) -> String {
    assert_eq!(message["to"], json!([email]));
    let url = url::Url::parse(
        message["text"]
            .as_str()
            .unwrap()
            .split("\n\n")
            .nth(1)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(url.path(), "/auth/verify-email");
    assert!(url.as_str().starts_with(base));
    assert!(!url.as_str().contains("attacker"));
    url.query_pairs()
        .find(|(key, _)| key == "token")
        .unwrap()
        .1
        .into_owned()
}

#[cfg(feature = "auth-email")]
#[actix_web::test]
async fn admin_creation_and_authenticated_resend_work_across_all_three_paths() {
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };
    let _guard = PASSWORD_TEST_LOCK.lock().await;
    assert!(std::env::var_os("VSR_AUTH_EMAIL_CAPTURE_DIR").is_none());
    for email_enabled in [false, true] {
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
                            return ResponseEnvelope::error(502, "private-provider-details");
                        }
                        capture.lock().unwrap().push(
                            serde_json::from_slice(request.body.as_deref().unwrap()).unwrap(),
                        );
                        ResponseEnvelope::json(json!({"id":"test-email"}))
                    }
                }),
            )],
        )
        .await
        .unwrap();
        let mut fixture = Fixture::new().await;
        fixture.settings.session_cookie = None;
        // Optional verification permits real login before self-service resend.
        fixture.settings.require_email_verification = false;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let native_base = format!("http://{}", listener.local_addr().unwrap());
        if email_enabled {
            let key = fixture._directory.path().join("provider-key");
            std::fs::write(&key, "test-only-key").unwrap();
            fixture.settings.email = Some(auth::AuthEmailSettings {
                from_email: "noreply@example.test".into(),
                from_name: None,
                reply_to: None,
                public_base_url: Some(native_base.clone()),
                provider: auth::AuthEmailProvider::Resend {
                    api_key: SecretRef::File { path: key },
                    api_base_url: Some(format!("http://{}", provider.addresses()[0])),
                },
            });
        }
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
        let admin = login_for(&bases[0], "owner@example.test", "original-password").await;
        for (index, writer) in bases.iter().enumerate() {
            let email = format!("provisioned-{index}@example.test");
            let input = json!({"email":format!(" {} ", email.to_ascii_uppercase()), "password":"provisioned-password", "role":" user ", "email_verified": !email_enabled && index == 1, "send_verification_email":email_enabled, "claims":{"tenant_id":99}, "tenant_id":99, "id":1, "password_hash":"injected"});
            account_response(
                client
                    .post(format!("{writer}/auth/admin/users"))
                    .json(&input),
                401,
            )
            .await;
            assert_eq!(account_response(client.post(format!("{writer}/auth/admin/users")).bearer_auth(&admin).json(&json!({"email":email,"password":"provisioned-password","email_verified":true,"send_verification_email":true})), 400).await["code"], "invalid_invite_state");
            let count = messages.lock().unwrap().len();
            if email_enabled {
                fail.store(true, Ordering::SeqCst);
                let error = account_response(
                    client
                        .post(format!("{writer}/auth/admin/users"))
                        .bearer_auth(&admin)
                        .json(&input),
                    500,
                )
                .await;
                assert_eq!(error["message"], "Failed to send authentication email");
                account_response(
                    client
                        .post(format!("{writer}/auth/login"))
                        .json(&json!({"email":email,"password":"provisioned-password"})),
                    401,
                )
                .await;
                fail.store(false, Ordering::SeqCst);
            }
            let response = client
                .post(format!("{writer}/auth/admin/users"))
                .header("host", "attacker.example")
                .bearer_auth(&admin)
                .json(&input)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 201);
            assert_eq!(response.headers().get_all("set-cookie").iter().count(), 0);
            let location = response.headers()["location"].to_str().unwrap().to_owned();
            let created: Value = response.json().await.unwrap();
            let id = created["id"].as_i64().unwrap();
            assert_ne!(id, 1);
            assert_eq!(location, format!("/auth/admin/users/{id}"));
            assert_eq!(created["email"], email);
            assert_eq!(created["role"], "user");
            assert_eq!(created["tenant_id"], 7);
            assert_eq!(created["email_verified"], !email_enabled && index == 1);
            assert!(created.get("password_hash").is_none());
            assert!(created["created_at"].is_string());
            assert!(created["updated_at"].is_string());
            account_response(
                client
                    .post(format!("{writer}/auth/admin/users"))
                    .bearer_auth(&admin)
                    .json(&input),
                409,
            )
            .await;
            let target = login_for(writer, &email, "provisioned-password").await;
            for reader in &bases {
                assert_eq!(
                    account_response(
                        client
                            .get(format!("{reader}/auth/admin/users/{id}"))
                            .bearer_auth(&admin),
                        200
                    )
                    .await,
                    created
                );
                account_response(
                    client
                        .post(format!("{reader}/auth/admin/users"))
                        .bearer_auth(&target)
                        .json(&input),
                    403,
                )
                .await;
                account_response(
                    client
                        .post(format!("{reader}/auth/admin/users/1/verification"))
                        .bearer_auth(&target),
                    403,
                )
                .await;
            }
            if email_enabled {
                assert_eq!(messages.lock().unwrap().len(), count + 1);
                let initial = email_token(&messages.lock().unwrap()[count], &native_base, &email);
                account_response(
                    client
                        .post(format!("{writer}/auth/account/verification"))
                        .header("host", "attacker.example")
                        .bearer_auth(&target)
                        .json(&json!({"id":1,"email":"attacker@example.test"})),
                    202,
                )
                .await;
                let own = email_token(&messages.lock().unwrap()[count + 1], &native_base, &email);
                let other = &bases[(index + 1) % 3];
                account_response(
                    client
                        .post(format!("{other}/auth/admin/users/{id}/verification"))
                        .bearer_auth(&admin),
                    202,
                )
                .await;
                let latest =
                    email_token(&messages.lock().unwrap()[count + 2], &native_base, &email);
                fail.store(true, Ordering::SeqCst);
                account_response(
                    client
                        .post(format!("{writer}/auth/account/verification"))
                        .bearer_auth(&target),
                    500,
                )
                .await;
                fail.store(false, Ordering::SeqCst);
                for raw in [initial, own] {
                    account_response(
                        client
                            .post(format!("{other}/auth/verify-email"))
                            .json(&json!({"token":raw})),
                        400,
                    )
                    .await;
                }
                account_response(
                    client
                        .post(format!("{other}/auth/verify-email"))
                        .json(&json!({"token":latest})),
                    204,
                )
                .await;
                account_response(
                    client
                        .post(format!("{writer}/auth/verify-email"))
                        .json(&json!({"token":latest})),
                    400,
                )
                .await;
                for reader in &bases {
                    account_response(
                        client
                            .get(format!("{reader}/auth/account"))
                            .bearer_auth(&target),
                        401,
                    )
                    .await;
                    let fresh = login_for(reader, &email, "provisioned-password").await;
                    account_response(
                        client
                            .post(format!("{reader}/auth/account/verification"))
                            .bearer_auth(fresh),
                        204,
                    )
                    .await;
                    account_response(
                        client
                            .post(format!("{reader}/auth/admin/users/{id}/verification"))
                            .bearer_auth(&admin),
                        204,
                    )
                    .await;
                }
                assert_eq!(messages.lock().unwrap().len(), count + 3);
            } else {
                for reader in &bases {
                    account_response(
                        client
                            .post(format!("{reader}/auth/account/verification"))
                            .bearer_auth(&target),
                        503,
                    )
                    .await;
                    account_response(
                        client
                            .post(format!("{reader}/auth/admin/users/{id}/verification"))
                            .bearer_auth(&admin),
                        503,
                    )
                    .await;
                }
                assert!(messages.lock().unwrap().is_empty());
            }
        }
        account_response(
            client
                .patch(format!("{}/auth/admin/users/1", bases[0]))
                .bearer_auth(&admin)
                .json(&json!({"role":"user"})),
            200,
        )
        .await;
        for reader in &bases {
            account_response(
                client
                    .post(format!("{reader}/auth/admin/users"))
                    .bearer_auth(&admin)
                    .json(
                        &json!({"email":"blocked@example.test","password":"provisioned-password"}),
                    ),
                401,
            )
            .await;
            account_response(
                client
                    .post(format!("{reader}/auth/admin/users/1/verification"))
                    .bearer_auth(&admin),
                401,
            )
            .await;
        }
        ActixHttpServer::shutdown(actix).await.unwrap();
        AxumHttpServer::shutdown(axum).await.unwrap();
        native_handle.stop(true).await;
        native_task.await.unwrap().unwrap();
        AxumHttpServer::shutdown(provider).await.unwrap();
    }
}
