use super::*;
use vsr_runtime::auth::management::AdminListQuery;

pub(super) fn routes(fixture: &Fixture) -> Vec<(HttpMethod, String, vsr_runtime::http::Handler)> {
    let service = Arc::new(auth::builtin_management_service(
        fixture.db.clone(),
        &fixture.settings,
    ));
    let authenticator = Arc::new(auth::builtin_request_authenticator(
        fixture.db.clone(),
        fixture.settings.clone(),
    ));
    [
        HttpMethod::Get,
        HttpMethod::Get,
        HttpMethod::Patch,
        HttpMethod::Delete,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, method)| {
        let service = service.clone();
        let route = if index == 0 {
            "/auth/admin/users"
        } else {
            "/auth/admin/users/{id}"
        };
        (
            method,
            route.into(),
            require_authentication(
                authenticator.clone(),
                make_handler(move |request| {
                    let service = service.clone();
                    async move {
                        let actor = request.identity.unwrap();
                        if index == 0 {
                            let value = |name: &str| {
                                request
                                    .query_params
                                    .get(name)
                                    .and_then(|values| values.first())
                            };
                            let parse = |name: &str| {
                                value(name).map(|value| value.parse::<u32>()).transpose()
                            };
                            let (Ok(limit), Ok(offset)) = (parse("limit"), parse("offset")) else {
                                return ResponseEnvelope::error(400, "Invalid query");
                            };
                            return match service
                                .list(
                                    &actor,
                                    &AdminListQuery {
                                        limit,
                                        offset,
                                        email: value("email").cloned(),
                                    },
                                )
                                .await
                            {
                                Ok(page) => ResponseEnvelope::json(page),
                                Err(error) => error.response(),
                            };
                        }
                        let Some(id) = request
                            .path_params
                            .get("id")
                            .and_then(|value| value.parse::<i64>().ok())
                        else {
                            return ResponseEnvelope::error(400, "Invalid path");
                        };
                        if index == 3 {
                            return match service.delete(&actor, id).await {
                                Ok(()) => ResponseEnvelope::status(204),
                                Err(error) => error.response(),
                            };
                        }
                        let result = if index == 1 {
                            service.get(&actor, id).await
                        } else {
                            let input = match serde_json::from_slice(
                                request.body.as_deref().unwrap_or_default(),
                            ) {
                                Ok(input) => input,
                                Err(_) => return ResponseEnvelope::error(400, "Invalid JSON"),
                            };
                            service.update(&actor, id, input).await
                        };
                        match result {
                            Ok(account) => ResponseEnvelope::json(account),
                            Err(error) => error.response(),
                        }
                    }
                }),
            ),
        )
    })
    .collect()
}

async fn token(base: &str, email: &str, password: &str) -> String {
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

#[actix_web::test]
async fn admin_reads_updates_and_deletion_have_identical_policy_on_all_three_paths() {
    let _guard = PASSWORD_TEST_LOCK.lock().await;
    let mut fixture = Fixture::new().await;
    fixture.settings.session_cookie = None;
    // Reuse an existing hash to keep this test focused on admin state transitions.
    query("INSERT INTO user (id,email,password_hash,role,created_at,updated_at) SELECT 2,'target@example.test',password_hash,'user','created','initial' FROM user WHERE id=1").execute(&fixture.db).await.unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let native_base = format!("http://{}", listener.local_addr().unwrap());
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
        native_base,
        format!("http://{}", actix.addresses()[0]),
        format!("http://{}", axum.addresses()[0]),
    ];
    let client = client();
    let admin = token(&bases[0], "owner@example.test", "original-password").await;
    let ordinary = token(&bases[0], "target@example.test", "original-password").await;
    for base in &bases {
        account_response(client.get(format!("{base}/auth/admin/users")), 401).await;
        for (method, suffix) in [
            (reqwest::Method::GET, ""),
            (reqwest::Method::GET, "/1"),
            (reqwest::Method::PATCH, "/2"),
            (reqwest::Method::DELETE, "/1"),
        ] {
            let body = account_response(
                client
                    .request(method, format!("{base}/auth/admin/users{suffix}"))
                    .bearer_auth(&ordinary)
                    .json(&json!({"role":"admin","id":1})),
                403,
            )
            .await;
            assert_eq!(body["code"], "forbidden");
        }
        let page = account_response(
            client
                .get(format!(
                    "{base}/auth/admin/users?limit=500&offset=1&email=%20example.test%20"
                ))
                .bearer_auth(&admin),
            200,
        )
        .await;
        assert_eq!(page["limit"], 100);
        assert_eq!(page["offset"], 1);
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        assert_eq!(page["items"][0]["id"], 2);
        assert!(page["items"][0].get("password_hash").is_none());
        for (input, code) in [
            (json!({}), "missing_changes"),
            (json!({"role":" "}), "validation_error"),
            (json!({"claims":{"role":"admin"}}), "validation_error"),
            (json!({"claims":{"tenant_id":"42"}}), "validation_error"),
        ] {
            assert_eq!(
                account_response(
                    client
                        .patch(format!("{base}/auth/admin/users/2"))
                        .bearer_auth(&admin)
                        .json(&input),
                    400
                )
                .await["code"],
                code
            );
        }
        assert_eq!(
            account_response(
                client
                    .delete(format!("{base}/auth/admin/users/1"))
                    .bearer_auth(&admin),
                400
            )
            .await["code"],
            "cannot_delete_self"
        );
        assert_eq!(
            account_response(
                client
                    .get(format!("{base}/auth/admin/users/9999"))
                    .bearer_auth(&admin),
                404
            )
            .await["code"],
            "not_found"
        );
    }
    for (index, writer) in bases.iter().enumerate() {
        let before = token(writer, "target@example.test", "original-password").await;
        let body = account_response(client.patch(format!("{writer}/auth/admin/users/2")).bearer_auth(&admin).json(&json!({"role":" operator ","email_verified":true,"claims":{"tenant_id":42 + index},"id":1,"password_hash":"injected"})), 200).await;
        assert_eq!(body["role"], "operator");
        assert_eq!(body["id"], 2);
        assert_eq!(body["tenant_id"], 42 + index);
        assert_eq!(body["email_verified"], true);
        assert!(body.get("password_hash").is_none());
        for reader in &bases {
            assert_eq!(
                account_response(
                    client
                        .get(format!("{reader}/auth/account"))
                        .bearer_auth(&before),
                    401
                )
                .await["code"],
                "revoked_token"
            );
            assert_eq!(
                account_response(
                    client
                        .get(format!("{reader}/auth/admin/users/2"))
                        .bearer_auth(&admin),
                    200
                )
                .await,
                body
            );
        }
        // Restoring the original role/claim does not revive the old session.
        account_response(
            client
                .patch(format!("{writer}/auth/admin/users/2"))
                .bearer_auth(&admin)
                .json(&json!({"role":"user","email_verified":false,"claims":{"tenant_id":7}})),
            200,
        )
        .await;
        for reader in &bases {
            account_response(
                client
                    .get(format!("{reader}/auth/account"))
                    .bearer_auth(&before),
                401,
            )
            .await;
        }
    }
    // Native and Axum writes share the same serialization boundary.
    let first = client
        .patch(format!("{}/auth/admin/users/2", bases[0]))
        .bearer_auth(&admin)
        .json(&json!({"claims":{"tenant_id":80}}));
    let second = client
        .patch(format!("{}/auth/admin/users/2", bases[2]))
        .bearer_auth(&admin)
        .json(&json!({"claims":{"tenant_id":81}}));
    let (first, second) = tokio::join!(account_response(first, 200), account_response(second, 200));
    assert_eq!(first["tenant_id"], 80);
    assert_eq!(second["tenant_id"], 81);
    assert_ne!(first["updated_at"], second["updated_at"]);
    let target = token(&bases[0], "target@example.test", "original-password").await;
    account_response(
        client
            .delete(format!("{}/auth/admin/users/2", bases[2]))
            .bearer_auth(&admin),
        204,
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
        account_response(
            client
                .get(format!("{reader}/auth/admin/users/2"))
                .bearer_auth(&admin),
            404,
        )
        .await;
    }
    account_response(
        client
            .patch(format!("{}/auth/admin/users/1", bases[1]))
            .bearer_auth(&admin)
            .json(&json!({"role":"user"})),
        200,
    )
    .await;
    for reader in &bases {
        assert_eq!(
            account_response(
                client
                    .get(format!("{reader}/auth/admin/users"))
                    .bearer_auth(&admin),
                401
            )
            .await["code"],
            "revoked_token"
        );
    }
    let demoted = token(&bases[2], "owner@example.test", "original-password").await;
    for reader in &bases {
        account_response(
            client
                .get(format!("{reader}/auth/admin/users"))
                .bearer_auth(&demoted),
            403,
        )
        .await;
    }
    ActixHttpServer::shutdown(actix).await.unwrap();
    AxumHttpServer::shutdown(axum).await.unwrap();
    native_handle.stop(true).await;
    native_task.await.unwrap().unwrap();
}
