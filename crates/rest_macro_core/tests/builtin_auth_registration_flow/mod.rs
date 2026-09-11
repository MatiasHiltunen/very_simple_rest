use super::*;

#[actix_web::test]
async fn registration_without_email_has_identical_policy_on_all_three_paths() {
    let _guard = PASSWORD_TEST_LOCK.lock().await;
    let mut fixture = Fixture::new().await;
    fixture.settings.session_cookie = None;
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
        native_base.clone(),
        format!("http://{}", actix.addresses()[0]),
        format!("http://{}", axum.addresses()[0]),
    ];
    let client = client();
    for (index, base) in bases.iter().enumerate() {
        for body in [
            json!({"email":"bad", "password":"registration-password"}),
            json!({"email":"new@example.test", "password":"short"}),
        ] {
            let error = account_response(
                client.post(format!("{base}/auth/register")).json(&body),
                400,
            )
            .await;
            assert_eq!(error["code"], "validation_error");
        }
        let email = format!("registered-{index}@example.test");
        account_response(client.post(format!("{base}/auth/register")).json(&json!({
            "email": format!(" {} ", email.to_ascii_uppercase()), "password":"registration-password",
            "role":"admin", "roles":["admin"], "id":1, "tenant_id":999,
            "email_verified_at":"forged", "password_hash":"forged",
        })), 201).await;
        let duplicate = account_response(
            client
                .post(format!("{base}/auth/register"))
                .json(&json!({"email":email,"password":"registration-password"})),
            409,
        )
        .await;
        assert_eq!(duplicate["code"], "duplicate_email");
        for consumer in &bases {
            let login = account_response(
                client
                    .post(format!("{consumer}/auth/login"))
                    .json(&json!({"email":email,"password":"registration-password"})),
                200,
            )
            .await;
            let token = login["token"].as_str().unwrap();
            let account = account_response(
                client
                    .get(format!("{consumer}/auth/account"))
                    .bearer_auth(token),
                200,
            )
            .await;
            assert_eq!(account["email"], email);
            assert_eq!(account["role"], "user");
            assert_eq!(account["tenant_id"], 7);
            assert_eq!(account["email_verified"], true);
            assert!(account.get("password_hash").is_none());
            account_response(
                client
                    .get(format!("{native_base}/auth/admin/users"))
                    .bearer_auth(token),
                403,
            )
            .await;
        }
    }
    let request = |base: &str, email: &str| {
        client
            .post(format!("{base}/auth/register"))
            .json(&json!({"email":email,"password":"registration-password"}))
            .send()
    };
    let (a, b) = tokio::join!(
        request(&bases[1], "race@example.test"),
        request(&bases[2], " RACE@EXAMPLE.TEST ")
    );
    let mut statuses = [a.unwrap().status().as_u16(), b.unwrap().status().as_u16()];
    statuses.sort_unstable();
    assert_eq!(statuses, [201, 409]);
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
