use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/blog_api.eon");
rest_api_from_eon!("tests/fixtures/owned_api.eon");
rest_api_from_eon!("tests/fixtures/tenant_api.eon");
rest_api_from_eon!("tests/fixtures/paged_api.eon");
rest_api_from_eon!("tests/fixtures/datetime_api.eon");
rest_api_from_eon!("tests/fixtures/scalar_types_api.eon");
rest_api_from_eon!("tests/fixtures/security_api.eon");
rest_api_from_eon!("tests/fixtures/static_site_api.eon");
rest_api_from_eon!("tests/fixtures/turso_local_api.eon");
rest_api_from_eon!("tests/fixtures/turso_local_encrypted_api.eon");

#[test]
fn eon_macro_generates_models_dtos_and_configure_functions() {
    let post = blog_api::Post {
        id: Some(1),
        title: "Post".to_owned(),
        content: "Body".to_owned(),
        created_at: Some("2026-03-12T00:00:00Z".to_owned()),
        updated_at: Some("2026-03-12T00:00:00Z".to_owned()),
    };
    let create = blog_api::PostCreate {
        title: "Post".to_owned(),
        content: "Body".to_owned(),
    };
    let update = blog_api::PostUpdate {
        title: "Post".to_owned(),
        content: "Body".to_owned(),
    };
    let comment = blog_api::CommentCreate {
        title: "Comment".to_owned(),
        content: "Body".to_owned(),
        post_id: 1,
    };

    let _configure_service_with_db_pool =
        |cfg: &mut very_simple_rest::actix_web::web::ServiceConfig,
         db: very_simple_rest::db::DbPool| blog_api::configure(cfg, db);
    let _configure_post_with_db_pool =
        |cfg: &mut very_simple_rest::actix_web::web::ServiceConfig,
         db: very_simple_rest::db::DbPool| blog_api::Post::configure(cfg, db);

    let _ = (post, create, update, comment);
}

#[test]
fn eon_macro_defaults_sqlite_services_to_turso_local_database_engine() {
    let database = blog_api::database();
    assert_eq!(
        database.engine,
        very_simple_rest::core::database::DatabaseEngine::TursoLocal(
            very_simple_rest::core::database::TursoLocalConfig {
                path: "var/data/blog_api.db".to_owned(),
                encryption_key_env: Some(
                    very_simple_rest::core::database::DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV
                        .to_owned()
                ),
            }
        )
    );
    assert_eq!(
        blog_api::default_database_url(),
        "sqlite:var/data/blog_api.db?mode=rwc"
    );
}

#[test]
fn eon_macro_owner_policies_trim_generated_dtos() {
    let post = owned_api::OwnedPost {
        id: Some(1),
        title: "Owned".to_owned(),
        user_id: 7,
        created_at: Some("2026-03-12T00:00:00Z".to_owned()),
        updated_at: Some("2026-03-12T00:00:00Z".to_owned()),
    };
    let create = owned_api::OwnedPostCreate {
        title: "Owned".to_owned(),
    };
    let update = owned_api::OwnedPostUpdate {
        title: "Updated".to_owned(),
    };

    let _configure_service_with_db_pool =
        |cfg: &mut very_simple_rest::actix_web::web::ServiceConfig,
         db: very_simple_rest::db::DbPool| owned_api::configure(cfg, db);
    let _configure_post_with_db_pool =
        |cfg: &mut very_simple_rest::actix_web::web::ServiceConfig,
         db: very_simple_rest::db::DbPool| owned_api::OwnedPost::configure(cfg, db);

    let _ = (post, create, update);
}

#[test]
fn eon_macro_claim_policies_trim_generated_dtos() {
    let post = tenant_api::TenantPost {
        id: Some(1),
        title: "Tenant".to_owned(),
        user_id: 3,
        tenant_id: 9,
        created_at: Some("2026-03-12T00:00:00Z".to_owned()),
        updated_at: Some("2026-03-12T00:00:00Z".to_owned()),
    };
    let create = tenant_api::TenantPostCreate {
        title: "Tenant".to_owned(),
    };
    let update = tenant_api::TenantPostUpdate {
        title: "Updated".to_owned(),
    };

    let _configure_service_with_db_pool =
        |cfg: &mut very_simple_rest::actix_web::web::ServiceConfig,
         db: very_simple_rest::db::DbPool| tenant_api::configure(cfg, db);
    let _configure_post_with_db_pool =
        |cfg: &mut very_simple_rest::actix_web::web::ServiceConfig,
         db: very_simple_rest::db::DbPool| tenant_api::TenantPost::configure(cfg, db);

    let _ = (post, create, update);
}

#[test]
fn eon_macro_generates_static_configure_function() {
    let _configure_static: fn(&mut very_simple_rest::actix_web::web::ServiceConfig) =
        static_site_api::configure_static;
}

#[test]
fn eon_macro_generates_security_config_function() {
    let _configure_security: fn(&mut very_simple_rest::actix_web::web::ServiceConfig) =
        security_api::configure_security;
    let security = security_api::security();
    assert_eq!(security.requests.json_max_bytes, Some(128));
    assert_eq!(
        security.cors.origins,
        vec!["http://localhost:3000".to_owned()]
    );
    assert_eq!(security.cors.origins_env.as_deref(), Some("CORS_ORIGINS"));
    assert!(security.cors.allow_credentials);
    assert_eq!(
        security.cors.allow_methods,
        vec!["GET".to_owned(), "POST".to_owned(), "OPTIONS".to_owned()]
    );
    assert_eq!(
        security.trusted_proxies.proxies,
        vec!["127.0.0.1".to_owned(), "::1".to_owned()]
    );
    assert_eq!(
        security.trusted_proxies.proxies_env.as_deref(),
        Some("TRUSTED_PROXIES")
    );
    assert_eq!(
        security.rate_limits.login,
        Some(very_simple_rest::core::security::RateLimitRule {
            requests: 2,
            window_seconds: 60,
        })
    );
    assert_eq!(
        security.rate_limits.register,
        Some(very_simple_rest::core::security::RateLimitRule {
            requests: 2,
            window_seconds: 60,
        })
    );
    assert_eq!(
        security.auth.issuer.as_deref(),
        Some("very_simple_rest_tests")
    );
    assert_eq!(security.auth.audience.as_deref(), Some("api_clients"));
    assert_eq!(security.auth.access_token_ttl_seconds, 900);
}

#[test]
fn eon_macro_generates_logging_config_function() {
    let logging = security_api::logging();
    assert_eq!(logging.filter_env, "APP_LOG");
    assert_eq!(logging.default_filter, "debug,sqlx=warn");
    assert_eq!(
        logging.timestamp,
        very_simple_rest::core::logging::LogTimestampPrecision::Millis
    );
}

#[test]
fn eon_macro_generates_database_config_function() {
    let database = turso_local_api::database();
    assert_eq!(
        database.engine,
        very_simple_rest::core::database::DatabaseEngine::TursoLocal(
            very_simple_rest::core::database::TursoLocalConfig {
                path: "var/data/turso_local.db".to_owned(),
                encryption_key_env: None,
            }
        )
    );
    assert_eq!(
        turso_local_api::default_database_url(),
        "sqlite:var/data/turso_local.db?mode=rwc"
    );
}

#[test]
fn eon_macro_preserves_turso_encryption_env_name() {
    let database = turso_local_encrypted_api::database();
    assert_eq!(
        database.engine,
        very_simple_rest::core::database::DatabaseEngine::TursoLocal(
            very_simple_rest::core::database::TursoLocalConfig {
                path: "var/data/turso_encrypted.db".to_owned(),
                encryption_key_env: Some("TURSO_ENCRYPTION_KEY".to_owned()),
            }
        )
    );
}

#[test]
fn eon_macro_generates_list_query_and_response_types() {
    let _query = paged_api::ItemListQuery {
        limit: Some(10),
        offset: Some(0),
        sort: None,
        order: None,
        cursor: None,
        filter_id: None,
        filter_title: None,
        filter_score: None,
    };
    let _response = paged_api::ItemListResponse {
        items: Vec::new(),
        total: 0,
        count: 0,
        limit: Some(2),
        offset: 0,
        next_offset: None,
        next_cursor: None,
    };
}

#[test]
fn eon_macro_generates_datetime_types_and_range_filters() {
    let starts_at = "2026-03-17T10:00:00Z"
        .parse::<very_simple_rest::chrono::DateTime<very_simple_rest::chrono::Utc>>()
        .expect("datetime should parse");
    let ends_at = "2026-03-17T11:00:00Z"
        .parse::<very_simple_rest::chrono::DateTime<very_simple_rest::chrono::Utc>>()
        .expect("datetime should parse");
    let created_at = "2026-03-17T09:00:00Z"
        .parse::<very_simple_rest::chrono::DateTime<very_simple_rest::chrono::Utc>>()
        .expect("datetime should parse");

    let _event = datetime_api::Event {
        id: Some(1),
        title: "Launch".to_owned(),
        starts_at: starts_at.clone(),
        ends_at: Some(ends_at.clone()),
        created_at: Some(created_at),
        updated_at: Some(
            "2026-03-17T09:30:00Z"
                .parse::<very_simple_rest::chrono::DateTime<very_simple_rest::chrono::Utc>>()
                .expect("datetime should parse"),
        ),
    };
    let _create = datetime_api::EventCreate {
        title: "Launch".to_owned(),
        starts_at: starts_at.clone(),
        ends_at: Some(ends_at.clone()),
    };
    let _update = datetime_api::EventUpdate {
        title: "Retimed".to_owned(),
        starts_at: starts_at.clone(),
        ends_at: None,
    };
    let _query = datetime_api::EventListQuery {
        filter_starts_at_gte: Some(starts_at),
        filter_starts_at_lt: Some(ends_at),
        ..Default::default()
    };
}

#[test]
fn eon_macro_generates_portable_scalar_types() {
    let run_on = "2026-03-17"
        .parse::<very_simple_rest::chrono::NaiveDate>()
        .expect("date should parse");
    let run_at = "08:00:00"
        .parse::<very_simple_rest::chrono::NaiveTime>()
        .expect("time should parse");
    let external_id = "33333333-3333-4333-8333-333333333333"
        .parse::<very_simple_rest::uuid::Uuid>()
        .expect("uuid should parse");
    let amount = "12.34"
        .parse::<very_simple_rest::rust_decimal::Decimal>()
        .expect("decimal should parse");

    let _schedule = scalar_types_api::Schedule {
        id: Some(1),
        run_on,
        run_at,
        external_id,
        amount: amount.clone(),
    };
    let _create = scalar_types_api::ScheduleCreate {
        run_on,
        run_at,
        external_id,
        amount: amount.clone(),
    };
    let _update = scalar_types_api::ScheduleUpdate {
        run_on,
        run_at,
        external_id,
        amount: amount.clone(),
    };
    let _query = scalar_types_api::ScheduleListQuery {
        filter_run_on_gte: Some(run_on),
        filter_run_at_lt: Some(run_at),
        filter_external_id: Some(external_id),
        filter_amount: Some(amount),
        ..Default::default()
    };
}
