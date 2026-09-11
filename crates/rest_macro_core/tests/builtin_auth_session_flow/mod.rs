use super::*;
use actix_web::cookie::{Cookie, SameSite, time::Duration as CookieDuration};

fn response_cookies(response: &reqwest::Response) -> Vec<Cookie<'static>> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| Cookie::parse(value.to_str().unwrap().to_owned()).unwrap())
        .collect()
}

async fn cleared(response: reqwest::Response, settings: Option<&SessionCookieSettings>) {
    assert_eq!(response.status(), 204);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let cookies = response_cookies(&response);
    assert_eq!(cookies.len(), if settings.is_some() { 2 } else { 0 });
    if let Some(settings) = settings {
        for (cookie, name, http_only) in [
            (&cookies[0], &settings.name, true),
            (&cookies[1], &settings.csrf_cookie_name, false),
        ] {
            assert_eq!(cookie.name(), name);
            assert_eq!(cookie.value(), "");
            assert_eq!(cookie.path(), Some(settings.path.as_str()));
            assert_eq!(cookie.secure().unwrap_or(false), settings.secure);
            assert_eq!(cookie.http_only().unwrap_or(false), http_only);
            assert_eq!(cookie.same_site(), Some(SameSite::Strict));
            assert_eq!(cookie.max_age(), Some(CookieDuration::ZERO));
            assert_eq!(cookie.domain(), None);
        }
    }
    assert!(response.bytes().await.unwrap().is_empty());
}

#[actix_web::test]
async fn login_and_logout_cookie_contract_matches_across_native_actix_and_axum() {
    let _guard = PASSWORD_TEST_LOCK.lock().await;
    for cookie_mode in [false, true] {
        let mut fixture = Fixture::new().await;
        fixture.settings.access_token_ttl_seconds = 600;
        if cookie_mode {
            let cookies = fixture.settings.session_cookie.as_mut().unwrap();
            cookies.name = "custom_session".into();
            cookies.csrf_cookie_name = "custom_csrf".into();
            cookies.csrf_header_name = "x-custom-csrf".into();
        } else {
            fixture.settings.session_cookie = None;
        }
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
        let cookie_settings = fixture.settings.session_cookie.as_ref();
        let mut tokens = Vec::new();
        let mut csrf_tokens = Vec::new();
        for base in &bases {
            let invalid = account_response(
                client.post(format!("{base}/auth/login")).json(&json!({
                    "email":"owner@example.test", "password":"wrong-password"
                })),
                401,
            )
            .await;
            assert_eq!(invalid["code"], "invalid_credentials");
            let response = client
                .post(format!("{base}/auth/login"))
                .json(&json!({
                    "email":"owner@example.test", "password":"original-password"
                }))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.headers()["cache-control"], "no-store");
            let issued = response_cookies(&response);
            let body: Value = response.json().await.unwrap();
            let token = body["token"].as_str().unwrap();
            tokens.push(token.to_owned());
            if let Some(settings) = cookie_settings {
                let csrf = body["csrf_token"].as_str().unwrap();
                assert_eq!(csrf.len(), 64);
                assert!(csrf.bytes().all(|byte| byte.is_ascii_hexdigit()));
                assert!(!csrf_tokens.iter().any(|previous| previous == csrf));
                csrf_tokens.push(csrf.to_owned());
                assert_eq!(issued.len(), 2);
                for (cookie, name, value, http_only) in [
                    (&issued[0], &settings.name, token, true),
                    (&issued[1], &settings.csrf_cookie_name, csrf, false),
                ] {
                    assert_eq!(cookie.name(), name);
                    assert_eq!(cookie.value(), value);
                    assert_eq!(cookie.path(), Some("/"));
                    assert_eq!(cookie.secure().unwrap_or(false), settings.secure);
                    assert_eq!(cookie.http_only().unwrap_or(false), http_only);
                    assert_eq!(cookie.same_site(), Some(SameSite::Strict));
                    assert_eq!(cookie.max_age(), Some(CookieDuration::seconds(600)));
                    assert_eq!(cookie.domain(), None);
                }
                let session = format!("{}={token}", settings.name);
                let pair = format!("{session}; {}={csrf}", settings.csrf_cookie_name);
                for consumer in &bases {
                    let account = account_response(
                        client
                            .get(format!("{consumer}/auth/account"))
                            .header("cookie", &session),
                        200,
                    )
                    .await;
                    assert_eq!(account["id"], 1);
                    let url = format!("{consumer}/auth/logout");
                    for request in [
                        client.post(&url).header("cookie", &session),
                        client.post(&url).header("cookie", &pair).bearer_auth(token),
                        client
                            .post(&url)
                            .header("cookie", &pair)
                            .header(&settings.csrf_header_name, "wrong"),
                        client
                            .post(&url)
                            .header("cookie", &pair)
                            .header(&settings.csrf_header_name, csrf)
                            .header(&settings.csrf_header_name, csrf),
                        client
                            .post(&url)
                            .header("cookie", format!("{pair}; {session}"))
                            .header(&settings.csrf_header_name, csrf),
                        client
                            .post(&url)
                            .header("cookie", &pair)
                            .header("cookie", &session)
                            .header(&settings.csrf_header_name, csrf),
                        client
                            .post(&url)
                            .header("cookie", "malformed")
                            .header(&settings.csrf_header_name, csrf),
                    ] {
                        let error = account_response(request, 403).await;
                        assert_eq!(error["code"], "invalid_csrf");
                    }
                    cleared(
                        client
                            .post(&url)
                            .header("cookie", &pair)
                            .header(&settings.csrf_header_name, csrf)
                            .send()
                            .await
                            .unwrap(),
                        cookie_settings,
                    )
                    .await;
                    // Clearing cookies deliberately does not revoke a bearer JWT.
                    account_response(
                        client
                            .get(format!("{consumer}/auth/account"))
                            .bearer_auth(token),
                        200,
                    )
                    .await;
                    let expired_pair = format!(
                        "{}=expired.token; {}={csrf}",
                        settings.name, settings.csrf_cookie_name
                    );
                    cleared(
                        client
                            .post(&url)
                            .header("cookie", expired_pair)
                            .header(&settings.csrf_header_name, csrf)
                            .send()
                            .await
                            .unwrap(),
                        cookie_settings,
                    )
                    .await;
                }
            } else {
                assert!(issued.is_empty());
                assert!(body.get("csrf_token").is_none());
                cleared(
                    client
                        .post(format!("{base}/auth/logout"))
                        .header("cookie", "malformed")
                        .send()
                        .await
                        .unwrap(),
                    None,
                )
                .await;
            }
            cleared(
                client
                    .post(format!("{base}/auth/logout"))
                    .send()
                    .await
                    .unwrap(),
                cookie_settings,
            )
            .await;
        }
        // Account state revocation remains active with the new presentation layer.
        account_response(
            client
                .post(format!("{}/auth/account/password", bases[0]))
                .bearer_auth(&tokens[0])
                .json(&json!({
                    "current_password":"original-password", "new_password":"replacement-password"
                })),
            204,
        )
        .await;
        for base in &bases {
            let error = account_response(
                client
                    .get(format!("{base}/auth/account"))
                    .bearer_auth(&tokens[0]),
                401,
            )
            .await;
            assert_eq!(error["code"], "revoked_token");
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
}

#[actix_web::test]
async fn invalid_programmatic_session_configuration_cannot_issue_native_credentials() {
    let _guard = PASSWORD_TEST_LOCK.lock().await;
    let fixture = Fixture::new().await;
    let mut settings = fixture.settings.clone();
    settings.session_cookie.as_mut().unwrap().path = "/; Domain=evil.test".into();
    assert!(auth::builtin_session_presentation(&settings).is_err());
    let db = fixture.db.clone();
    let app =
        actix_web::test::init_service(App::new().configure(move |cfg| {
            auth::auth_routes_with_settings(cfg, db.clone(), settings.clone())
        }))
        .await;
    for route in ["login", "logout"] {
        let request = actix_web::test::TestRequest::post()
            .uri(&format!("/auth/{route}"))
            .set_json(json!({
                "email":"owner@example.test", "password":"original-password"
            }))
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(response.status(), 500);
        assert!(response.headers().get("set-cookie").is_none());
        let body: Value = actix_web::test::read_body_json(response).await;
        assert_eq!(body["code"], "internal_error");
        assert!(body.get("token").is_none());
        assert!(!body.to_string().contains("evil.test"));
    }
    match &fixture.db {
        DbPool::Sqlx { pool, .. } => pool.close().await,
        #[cfg(feature = "turso-local")]
        DbPool::TursoLocal(_) => unreachable!("SQLite fixture"),
    }
}
