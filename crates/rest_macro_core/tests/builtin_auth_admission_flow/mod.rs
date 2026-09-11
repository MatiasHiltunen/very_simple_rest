use super::*;
use rest_macro_core::security::{self, RateLimitRule, RateLimitSecurity, SecurityConfig};
use vsr_runtime::rate_limit::{MemoryRateLimitCapacity, MemoryRateLimitStore};

fn rules(login: u32, register: u32) -> RateLimitSecurity {
    RateLimitSecurity {
        login: Some(RateLimitRule {
            requests: login,
            window_seconds: 300,
        }),
        register: Some(RateLimitRule {
            requests: register,
            window_seconds: 300,
        }),
    }
}

async fn rejected(request: reqwest::RequestBuilder, status: u16, code: &str) {
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), status);
    assert!(!response.headers().contains_key("set-cookie"));
    let retry: u64 = response.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=300).contains(&retry));
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], code);
    assert!(body.get("token").is_none());
}

#[actix_web::test]
async fn shared_budgets_span_native_workers_and_both_transports() {
    let _guard = PASSWORD_TEST_LOCK.lock().await;
    // Exercise normal quotas and capacity exhaustion against the same real handlers.
    for capacity_exhaustion in [false, true] {
        let mut fixture = Fixture::new().await;
        fixture.settings.session_cookie = None;
        let rules = if capacity_exhaustion {
            rules(1, 1)
        } else {
            rules(3, 2)
        };
        let capacity = if capacity_exhaustion {
            MemoryRateLimitCapacity {
                max_keys: 1,
                max_events: 1,
                max_key_bytes: 128,
            }
        } else {
            MemoryRateLimitCapacity::default()
        };
        let store = Arc::new(MemoryRateLimitStore::new(capacity).unwrap());
        let data = web::Data::from(store.clone());
        let security = SecurityConfig {
            rate_limits: rules.clone(),
            auth: fixture.settings.clone(),
            ..Default::default()
        };
        let db = fixture.db.clone();
        let settings = fixture.settings.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let native_base = format!("http://{}", listener.local_addr().unwrap());
        let server = NativeServer::new(move || {
            let db = db.clone();
            let settings = settings.clone();
            let data = data.clone();
            let security = security.clone();
            App::new().configure(move |cfg| {
                security::configure_scope_security(cfg, &security);
                auth::auth_api_routes_with_settings_and_limiter(cfg, db, settings, data);
            })
        })
        .workers(4)
        .disable_signals()
        .listen(listener)
        .unwrap()
        .run();
        let native_handle = server.handle();
        let native_task = actix_web::rt::spawn(server);
        let actix = start_account_service_with_admission::<ActixHttpServer>(
            &fixture,
            Some((store.clone(), rules.clone())),
        )
        .await;
        let axum =
            start_account_service_with_admission::<AxumHttpServer>(&fixture, Some((store, rules)))
                .await;
        let bases = [
            native_base,
            format!("http://{}", actix.addresses()[0]),
            format!("http://{}", axum.addresses()[0]),
        ];
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(0)
            .build()
            .unwrap();
        let login = |base: &str| {
            client
                .post(format!("{base}/auth/login"))
                .json(&json!({"email":"owner@example.test", "password":"wrong-password"}))
        };
        if capacity_exhaustion {
            // A successful login also consumes its budget.
            account_response(
                client
                    .post(format!("{}/auth/login", bases[0]))
                    .json(&json!({"email":"owner@example.test", "password":"original-password"})),
                200,
            )
            .await;
        } else {
            for base in &bases {
                assert_eq!(
                    account_response(login(base), 401).await["code"],
                    "invalid_credentials"
                );
            }
        }
        // Fresh TCP connections distribute native requests across its four workers.
        for index in 0..12 {
            for base in &bases {
                rejected(
                    login(base)
                        .header("x-forwarded-for", format!("192.0.2.{}", index + 1))
                        .header("forwarded", format!("for=198.51.100.{}", index + 1)),
                    429,
                    "rate_limited",
                )
                .await;
            }
        }
        if !capacity_exhaustion {
            for (index, base) in bases.iter().take(2).enumerate() {
                account_response(client.post(format!("{base}/auth/register"))
                    .json(&json!({"email":format!("admitted-{index}@example.test"), "password":"registration-password"})), 201).await;
            }
        }
        for base in &bases {
            rejected(
                client.post(format!("{base}/auth/register")).json(
                    &json!({"email":"refused@example.test", "password":"registration-password"}),
                ),
                if capacity_exhaustion { 503 } else { 429 },
                if capacity_exhaustion {
                    "auth_rate_limit_unavailable"
                } else {
                    "rate_limited"
                },
            )
            .await;
            // Capacity failure must not evict the original client's active counter.
            rejected(login(base), 429, "rate_limited").await;
        }
        assert!(
            query("SELECT id FROM user WHERE email = 'refused@example.test'")
                .fetch_optional(&fixture.db)
                .await
                .unwrap()
                .is_none()
        );
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
async fn configured_native_limit_without_store_fails_closed() {
    let _guard = PASSWORD_TEST_LOCK.lock().await;
    let fixture = Fixture::new().await;
    let security = SecurityConfig {
        rate_limits: rules(1, 1),
        auth: fixture.settings.clone(),
        ..Default::default()
    };
    let app = actix_web::test::init_service(
        App::new()
            .app_data(web::Data::new(fixture.db.clone()))
            .configure(|cfg| security::configure_scope_security(cfg, &security))
            .route("/auth/login", web::post().to(auth::login_with_request)),
    )
    .await;
    let request = actix_web::test::TestRequest::post()
        .uri("/auth/login")
        .set_json(json!({"email":"owner@example.test", "password":"original-password"}))
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), 503);
    assert_eq!(response.headers().get("retry-after").unwrap(), "1");
    assert!(!response.headers().contains_key("set-cookie"));
    let body: Value = actix_web::test::read_body_json(response).await;
    assert_eq!(body["code"], "auth_rate_limit_unavailable");
    match &fixture.db {
        DbPool::Sqlx { pool, .. } => pool.close().await,
        #[cfg(feature = "turso-local")]
        DbPool::TursoLocal(_) => unreachable!("SQLite fixture"),
    }
}
