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
rest_api_from_eon!("tests/fixtures/tls_api.eon");
rest_api_from_eon!("tests/fixtures/mapped_api.eon");
rest_api_from_eon!("tests/fixtures/runtime_api.eon");
rest_api_from_eon!("tests/fixtures/auth_claims_api.eon");
rest_api_from_eon!("tests/fixtures/authorization_contract_api.eon");
rest_api_from_eon!("tests/fixtures/hybrid_runtime_api.eon");
rest_api_from_eon!("tests/fixtures/mixin_fields_api.eon");
rest_api_from_eon!("tests/fixtures/api_computed_fields_api.eon");
rest_api_from_eon!("tests/fixtures/audit_events_api.eon");

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
                encryption_key: Some(very_simple_rest::core::secret::SecretRef::env_or_file(
                    very_simple_rest::core::database::DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV,
                )),
            }
        )
    );
    assert_eq!(
        blog_api::default_database_url(),
        "sqlite:var/data/blog_api.db?mode=rwc"
    );
}

#[test]
fn eon_macro_exposes_runtime_defaults() {
    let runtime = runtime_api::runtime();
    assert!(runtime.compression.enabled);
    assert!(runtime.compression.static_precompressed);
}

#[test]
fn eon_macro_exposes_auth_claim_mappings() {
    let security = auth_claims_api::security();
    assert_eq!(
        security.auth.claims.get("tenant_id"),
        Some(&very_simple_rest::core::auth::AuthClaimMapping {
            column: "tenant_scope".to_owned(),
            ty: very_simple_rest::core::auth::AuthClaimType::I64,
        })
    );
    assert_eq!(
        security.auth.claims.get("staff"),
        Some(&very_simple_rest::core::auth::AuthClaimMapping {
            column: "is_staff".to_owned(),
            ty: very_simple_rest::core::auth::AuthClaimType::Bool,
        })
    );
}

#[test]
fn eon_macro_exposes_authorization_model() {
    let authorization = authorization_contract_api::authorization();
    assert_eq!(authorization.contract.scopes.len(), 2);
    assert_eq!(authorization.contract.permissions.len(), 2);
    assert_eq!(authorization.contract.templates.len(), 2);
    assert_eq!(authorization.resources.len(), 1);
    assert_eq!(authorization.resources[0].id, "resource.scoped_doc");
    assert_eq!(authorization.resources[0].resource, "ScopedDoc");
    assert_eq!(
        authorization.resources[0].actions[0].id,
        "resource.scoped_doc.action.read"
    );
    assert_eq!(
        authorization.resources[0].actions[0].action,
        very_simple_rest::authorization::AuthorizationAction::Read
    );

    let _authorization_runtime_with_db_pool =
        |db: very_simple_rest::db::DbPool| authorization_contract_api::authorization_runtime(db);
}

#[test]
fn eon_macro_exposes_hybrid_create_scope_field_in_generated_dto() {
    let create = hybrid_runtime_api::ScopedDocCreate {
        family_id: Some(42),
        title: "Runtime-created household note".to_owned(),
    };

    let authorization = hybrid_runtime_api::authorization();
    let scoped_doc_hybrid = authorization
        .contract
        .hybrid_enforcement
        .resources
        .iter()
        .find(|resource| resource.resource == "ScopedDoc")
        .expect("scoped doc hybrid resource should exist");
    assert!(scoped_doc_hybrid.scope_sources.item);
    assert!(scoped_doc_hybrid.scope_sources.collection_filter);
    assert!(scoped_doc_hybrid.scope_sources.nested_parent);
    assert!(scoped_doc_hybrid.scope_sources.create_payload);
    assert_eq!(
        scoped_doc_hybrid.actions,
        vec![
            very_simple_rest::authorization::AuthorizationAction::Create,
            very_simple_rest::authorization::AuthorizationAction::Read,
            very_simple_rest::authorization::AuthorizationAction::Update,
            very_simple_rest::authorization::AuthorizationAction::Delete,
        ]
    );

    let _ = create;
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
                encryption_key: None,
            }
        )
    );
    assert_eq!(
        turso_local_api::default_database_url(),
        "sqlite:var/data/turso_local.db?mode=rwc"
    );
}

#[test]
fn eon_macro_generates_tls_config_function() {
    let tls = tls_api::tls();
    assert_eq!(tls.cert_path.as_deref(), Some("certs/dev-cert.pem"));
    assert_eq!(tls.key_path.as_deref(), Some("certs/dev-key.pem"));
    assert_eq!(
        tls.cert_path_env.as_deref(),
        Some(very_simple_rest::core::tls::DEFAULT_TLS_CERT_PATH_ENV)
    );
    assert_eq!(
        tls.key_path_env.as_deref(),
        Some(very_simple_rest::core::tls::DEFAULT_TLS_KEY_PATH_ENV)
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
                encryption_key: Some(very_simple_rest::core::secret::SecretRef::env_or_file(
                    "TURSO_ENCRYPTION_KEY",
                ),),
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
        context: None,
        filter_id: None,
        filter_title: None,
        filter_title_contains: None,
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
fn eon_macro_supports_resource_and_field_map_definitions() {
    let post = mapped_api::Post {
        id: Some(1),
        title: "Mapped".to_owned(),
        published: false,
    };
    let create = mapped_api::PostCreate {
        title: "Mapped".to_owned(),
        published: false,
    };
    let query = mapped_api::PostListQuery {
        limit: Some(10),
        offset: Some(0),
        sort: None,
        order: None,
        cursor: None,
        context: None,
        filter_id: None,
        filter_title: None,
        filter_title_contains: None,
        filter_published: None,
    };
    let response = mapped_api::PostListResponse {
        items: Vec::new(),
        total: 0,
        count: 0,
        limit: Some(10),
        offset: 0,
        next_offset: None,
        next_cursor: None,
    };

    let _ = (post, create, query, response);
}

#[test]
fn eon_macro_expands_local_mixins_into_generated_types() {
    let post = mixin_fields_api::Post {
        id: Some(1),
        title: "Mixed".to_owned(),
        tenant_id: 42,
        slug: "mixed".to_owned(),
        created_at: Some(
            "2026-03-27T10:00:00Z"
                .parse::<very_simple_rest::chrono::DateTime<very_simple_rest::chrono::Utc>>()
                .expect("datetime should parse"),
        ),
        updated_at: Some(
            "2026-03-27T10:30:00Z"
                .parse::<very_simple_rest::chrono::DateTime<very_simple_rest::chrono::Utc>>()
                .expect("datetime should parse"),
        ),
    };
    let create = mixin_fields_api::PostCreate {
        title: "Mixed".to_owned(),
        tenant_id: 42,
        slug: "mixed".to_owned(),
    };
    let update = mixin_fields_api::PostUpdate {
        title: "Updated".to_owned(),
        tenant_id: 42,
        slug: "updated".to_owned(),
    };

    let _ = (post, create, update);
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
        starts_at,
        ends_at: Some(ends_at),
        created_at: Some(created_at),
        updated_at: Some(
            "2026-03-17T09:30:00Z"
                .parse::<very_simple_rest::chrono::DateTime<very_simple_rest::chrono::Utc>>()
                .expect("datetime should parse"),
        ),
    };
    let _create = datetime_api::EventCreate {
        title: "Launch".to_owned(),
        starts_at,
        ends_at: Some(ends_at),
    };
    let _update = datetime_api::EventUpdate {
        title: "Retimed".to_owned(),
        starts_at,
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
        amount,
    };
    let _create = scalar_types_api::ScheduleCreate {
        run_on,
        run_at,
        external_id,
        amount,
    };
    let _update = scalar_types_api::ScheduleUpdate {
        run_on,
        run_at,
        external_id,
        amount,
    };
    let _query = scalar_types_api::ScheduleListQuery {
        filter_run_on_gte: Some(run_on),
        filter_run_at_lt: Some(run_at),
        filter_external_id: Some(external_id),
        filter_amount: Some(amount),
        ..Default::default()
    };
}
