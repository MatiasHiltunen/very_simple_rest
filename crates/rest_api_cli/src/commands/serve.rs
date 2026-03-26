use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;

use actix_web::middleware::Logger;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Scope, web};
use anyhow::{Context, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, NaiveDate, NaiveTime, SecondsFormat, Utc};
use rest_macro_core::auth::{self, UserContext};
use rest_macro_core::authorization::{
    AuthorizationAction, AuthorizationRuntime, AuthorizationScopeBinding,
};
use rest_macro_core::compiler::{
    self, DbBackend, FieldSpec, GeneratedValue, NumericBound, OpenApiSpecOptions,
    PolicyExistsCondition, PolicyExistsFilter, PolicyFilterExpression, PolicyFilterOperator,
    PolicyValueSource, ResourceSpec, RoleRequirements, RowPolicies, ServiceSpec,
    StructuredScalarKind, default_service_database_url, supports_range_filters, supports_sort,
};
use rest_macro_core::database::{
    prepare_database_engine, resolve_database_config, resolve_database_url,
    service_base_dir_from_config_path,
};
use rest_macro_core::db::{DbPool, Query, query, query_scalar};
use rest_macro_core::errors;
use rest_macro_core::static_files::{StaticMount, configure_static_mounts_with_runtime};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::Row;
use syn::{GenericArgument, PathArguments, Type};
use url::form_urlencoded;
use uuid::Uuid;

const BIND_MARKER: &str = "__vsr_bind__";
const DEFAULT_OPENAPI_VERSION: &str = "1.0.0";

pub async fn serve_service(
    input: &Path,
    database_url: &str,
    bind_addr_override: Option<&str>,
    include_builtin_auth: bool,
) -> anyhow::Result<()> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| anyhow!(error.to_string()))
        .with_context(|| format!("failed to load service config {}", input.display()))?;
    let backend = detect_backend(&service)?;
    ensure_auth_is_compatible(&service, include_builtin_auth)?;
    ensure_database_engine_is_compatible(&service, backend)?;

    let base_dir = service_base_dir_from_config_path(input);
    let database_config = resolve_database_config(&service.database, &base_dir);
    let resolved_database_url = if database_url == default_service_database_url(&service) {
        resolve_database_url(database_url, &base_dir)
    } else {
        database_url.to_owned()
    };

    let mut logger = service.logging.build_env_logger();
    let _ = logger.try_init();

    if include_builtin_auth {
        auth::ensure_jwt_secret_configured()
            .map_err(|error| anyhow!("auth configuration error: {error}"))?;
    }

    prepare_database_engine(&database_config)
        .await
        .map_err(|error| anyhow!("database engine bootstrap failed: {error}"))?;

    let pool = DbPool::connect_with_config(&resolved_database_url, &database_config)
        .await
        .map_err(|error| anyhow!("database connection failed: {error}"))?;

    if include_builtin_auth {
        auth::validate_auth_claim_mappings(&pool, &service.security.auth)
            .await
            .map_err(|error| anyhow!("auth claim mapping validation failed: {error}"))?;
    }

    let openapi_json = build_openapi_json(&service, include_builtin_auth)?;
    let authorization_model = compiler::compile_service_authorization(&service);
    let dynamic_service = Arc::new(DynamicService::from_spec(
        service,
        openapi_json,
        include_builtin_auth,
    )?);

    let bind_addr = bind_addr_override
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("BIND_ADDR").ok())
        .unwrap_or_else(|| default_bind_addr_from_tls(dynamic_service.tls.is_enabled()).to_owned());

    let state = NativeServeState {
        pool: pool.clone(),
        authorization_runtime: AuthorizationRuntime::new(authorization_model, pool),
        dynamic_service: dynamic_service.clone(),
    };

    let tls_base_dir = base_dir.clone();
    let tls_config = dynamic_service.tls.clone();
    let rustls_config = if tls_config.is_enabled() {
        Some(
            rest_macro_core::tls::load_rustls_server_config(&tls_config, &tls_base_dir)
                .map_err(|error| anyhow!("TLS configuration error: {error}"))?,
        )
    } else {
        None
    };

    let server = HttpServer::new({
        let dynamic_service = dynamic_service.clone();
        let state = state.clone();
        move || {
            let api_runtime = dynamic_service.runtime.clone();
            let api_security = dynamic_service.security.clone();
            let static_mounts = dynamic_service.static_mounts.clone();
            let docs_html = dynamic_service.docs_html.clone();
            let openapi_json = dynamic_service.openapi_json.clone();

            App::new()
                .app_data(web::Data::new(dynamic_service.clone()))
                .app_data(web::Data::new(state.clone()))
                .wrap(Logger::default())
                .wrap(rest_macro_core::runtime::compression_middleware(
                    &api_runtime,
                ))
                .wrap(rest_macro_core::security::cors_middleware(&api_security))
                .wrap(rest_macro_core::security::security_headers_middleware(
                    &api_security,
                ))
                .route(
                    "/openapi.json",
                    web::get().to(move || {
                        let openapi_json = openapi_json.clone();
                        async move {
                            HttpResponse::Ok()
                                .content_type("application/json")
                                .body(openapi_json.as_ref().clone())
                        }
                    }),
                )
                .route(
                    "/docs",
                    web::get().to(move || {
                        let docs_html = docs_html.clone();
                        async move {
                            HttpResponse::Ok()
                                .content_type("text/html; charset=utf-8")
                                .body(docs_html.as_ref().clone())
                        }
                    }),
                )
                .service(build_api_scope(dynamic_service.clone(), state.clone()))
                .configure(move |cfg| {
                    configure_static_mounts_with_runtime(
                        cfg,
                        static_mounts.as_slice(),
                        &api_runtime,
                    );
                })
        }
    });

    if let Some(rustls_config) = rustls_config {
        log::info!("Server listening on https://{}", bind_addr);
        server
            .bind_rustls_0_23(&bind_addr, rustls_config)?
            .run()
            .await?;
    } else {
        log::info!("Server listening on http://{}", bind_addr);
        server.bind(&bind_addr)?.run().await?;
    }

    Ok(())
}

#[derive(Clone)]
struct NativeServeState {
    pool: DbPool,
    authorization_runtime: AuthorizationRuntime,
    dynamic_service: Arc<DynamicService>,
}

#[derive(Clone)]
struct DynamicService {
    runtime: rest_macro_core::runtime::RuntimeConfig,
    security: rest_macro_core::security::SecurityConfig,
    tls: rest_macro_core::tls::TlsConfig,
    authorization_management_enabled: bool,
    authorization_management_mount: String,
    resources: Vec<Arc<DynamicResource>>,
    openapi_json: Arc<String>,
    docs_html: Arc<String>,
    include_builtin_auth: bool,
    static_mounts: Arc<Vec<StaticMount>>,
}

impl DynamicService {
    fn from_spec(
        service: ServiceSpec,
        openapi_json: String,
        include_builtin_auth: bool,
    ) -> anyhow::Result<Self> {
        let resources = service
            .resources
            .iter()
            .cloned()
            .map(|resource| DynamicResource::from_spec(resource, &service))
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .map(Arc::new)
            .collect();
        let static_mounts = Arc::new(convert_static_mounts(service.static_mounts.as_slice()));

        Ok(Self {
            runtime: service.runtime.clone(),
            security: service.security.clone(),
            tls: service.tls.clone(),
            authorization_management_enabled: service.authorization.management_api.enabled,
            authorization_management_mount: service.authorization.management_api.mount.clone(),
            resources,
            openapi_json: Arc::new(openapi_json),
            docs_html: Arc::new(swagger_ui_html().to_owned()),
            include_builtin_auth,
            static_mounts,
        })
    }
}

#[derive(Clone)]
struct DynamicResource {
    resource_name: String,
    table_name: String,
    id_field: String,
    db: DbBackend,
    roles: RoleRequirements,
    policies: RowPolicies,
    default_limit: Option<u32>,
    max_limit: Option<u32>,
    create_assignment_sources: HashMap<String, PolicyValueSource>,
    fields: Vec<DynamicField>,
    field_index: HashMap<String, usize>,
    create_fields: Vec<CreateFieldRule>,
    update_field_names: Vec<String>,
    read_requires_auth: bool,
    hybrid: Option<HybridResourceConfig>,
    nested_relations: Vec<NestedRoute>,
}

impl DynamicResource {
    fn from_spec(spec: ResourceSpec, service: &ServiceSpec) -> anyhow::Result<Self> {
        let fields = spec
            .fields
            .iter()
            .cloned()
            .map(DynamicField::from_spec)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let field_index = fields
            .iter()
            .enumerate()
            .map(|(index, field)| (field.name.clone(), index))
            .collect::<HashMap<_, _>>();
        let controlled_fields = policy_controlled_fields(&spec);
        let create_fields = build_create_field_rules(&spec, service)?;
        let create_assignment_sources = spec
            .policies
            .create
            .iter()
            .map(|assignment| (assignment.field.clone(), assignment.source.clone()))
            .collect();
        let update_field_names = spec
            .fields
            .iter()
            .filter(|field| {
                !field.is_id
                    && !field.generated.skip_update_bind()
                    && !controlled_fields.contains(&field.name())
            })
            .map(FieldSpec::name)
            .collect();
        let hybrid = build_hybrid_resource_config(&spec, service);
        let nested_relations = spec
            .fields
            .iter()
            .filter_map(|field| {
                field
                    .relation
                    .as_ref()
                    .filter(|relation| relation.nested_route)
                    .map(|relation| NestedRoute {
                        field_name: field.name(),
                        parent_table: relation.references_table.clone(),
                    })
            })
            .collect();

        Ok(Self {
            read_requires_auth: spec.roles.read.is_some() || spec.policies.has_read_filters(),
            resource_name: spec.struct_ident.to_string(),
            table_name: spec.table_name.clone(),
            id_field: spec.id_field.clone(),
            db: spec.db,
            roles: spec.roles.clone(),
            policies: spec.policies.clone(),
            default_limit: spec.list.default_limit,
            max_limit: spec.list.max_limit,
            create_assignment_sources,
            fields,
            field_index,
            create_fields,
            update_field_names,
            hybrid,
            nested_relations,
        })
    }

    fn field(&self, field_name: &str) -> anyhow::Result<&DynamicField> {
        let index =
            self.field_index.get(field_name).copied().ok_or_else(|| {
                anyhow!("field `{field_name}` not found in `{}`", self.table_name)
            })?;
        Ok(&self.fields[index])
    }

    fn supports_hybrid_action(&self, action: AuthorizationAction) -> bool {
        match (&self.hybrid, action) {
            (Some(hybrid), AuthorizationAction::Read) => hybrid.item_read,
            (Some(hybrid), AuthorizationAction::Create) => hybrid.create_payload,
            (Some(hybrid), AuthorizationAction::Update) => hybrid.update,
            (Some(hybrid), AuthorizationAction::Delete) => hybrid.delete,
            (None, _) => false,
        }
    }

    fn can_read(&self, user: &UserContext) -> bool {
        match self.roles.read.as_deref() {
            Some(role) => user
                .roles
                .iter()
                .any(|candidate| candidate == "admin" || candidate == role),
            None => true,
        }
    }

    fn requires_role(&self, action: AuthorizationAction) -> Option<&str> {
        match action {
            AuthorizationAction::Read => self.roles.read.as_deref(),
            AuthorizationAction::Create => self.roles.create.as_deref(),
            AuthorizationAction::Update => self.roles.update.as_deref(),
            AuthorizationAction::Delete => self.roles.delete.as_deref(),
        }
    }
}

#[derive(Clone)]
struct DynamicField {
    name: String,
    kind: FieldKind,
    optional: bool,
    generated: GeneratedValue,
    validation: compiler::FieldValidation,
    supports_sort: bool,
    supports_range_filters: bool,
}

impl DynamicField {
    fn from_spec(spec: FieldSpec) -> anyhow::Result<Self> {
        let name = spec.name();
        let kind = FieldKind::from_field(&spec)
            .ok_or_else(|| anyhow!("unsupported field type for dynamic serve: `{name}`"))?;
        let optional = compiler::is_optional_type(&spec.ty);
        Ok(Self {
            name,
            kind,
            optional,
            generated: spec.generated,
            validation: spec.validation.clone(),
            supports_sort: supports_sort(&spec.ty),
            supports_range_filters: supports_range_filters(&spec.ty),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FieldKind {
    Integer,
    Real,
    Boolean,
    Text,
    DateTime,
    Date,
    Time,
    Uuid,
    Decimal,
}

impl FieldKind {
    fn from_field(field: &FieldSpec) -> Option<Self> {
        match compiler::structured_scalar_kind(&field.ty) {
            Some(StructuredScalarKind::DateTime) => Some(Self::DateTime),
            Some(StructuredScalarKind::Date) => Some(Self::Date),
            Some(StructuredScalarKind::Time) => Some(Self::Time),
            Some(StructuredScalarKind::Uuid) => Some(Self::Uuid),
            Some(StructuredScalarKind::Decimal) => Some(Self::Decimal),
            None => {
                if is_bool_type(&field.ty) {
                    Some(Self::Boolean)
                } else if is_integer_sql_type(field.sql_type.as_str()) {
                    Some(Self::Integer)
                } else if field.sql_type == "REAL" {
                    Some(Self::Real)
                } else {
                    Some(Self::Text)
                }
            }
        }
    }
}

#[derive(Clone)]
struct CreateFieldRule {
    name: String,
    allow_admin_override: bool,
    allow_hybrid_runtime: bool,
    payload_optional: bool,
}

#[derive(Clone)]
struct HybridResourceConfig {
    scope: String,
    scope_field: String,
    item_read: bool,
    collection_read: bool,
    nested_read: bool,
    create_payload: bool,
    update: bool,
    delete: bool,
}

#[derive(Clone)]
struct NestedRoute {
    field_name: String,
    parent_table: String,
}

#[derive(Clone, Debug)]
struct SqlPlan {
    condition: String,
    binds: Vec<BoundValue>,
}

#[derive(Clone, Debug)]
enum PlanOutcome {
    Resolved(SqlPlan),
    Indeterminate,
}

#[derive(Clone, Debug, PartialEq)]
enum BoundValue {
    Null,
    Bool(bool),
    Integer(i64),
    Real(f64),
    Text(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SortOrder {
    Asc,
    Desc,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum CursorValue {
    Integer(i64),
    Real(f64),
    Boolean(bool),
    Text(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CursorPayload {
    sort: String,
    order: String,
    last_id: i64,
    value: CursorValue,
}

#[derive(Clone, Debug)]
struct ListQueryPlan {
    count_sql: String,
    select_sql: String,
    filter_binds: Vec<BoundValue>,
    select_binds: Vec<BoundValue>,
    limit: Option<u32>,
    offset: u32,
    sort: String,
    order: SortOrder,
    cursor_mode: bool,
}

#[derive(Clone, Debug, Serialize)]
struct ListResponse {
    items: Vec<Value>,
    total: i64,
    count: usize,
    limit: Option<u32>,
    offset: u32,
    next_offset: Option<u32>,
    next_cursor: Option<String>,
}

fn build_api_scope(dynamic_service: Arc<DynamicService>, state: NativeServeState) -> Scope {
    let mut scope = web::scope("/api");
    let security = dynamic_service.security.clone();
    let pool = state.pool.clone();
    let authorization_runtime = state.authorization_runtime.clone();
    scope = scope.configure(move |cfg| {
        rest_macro_core::security::configure_scope_security(cfg, &security);
        cfg.app_data(web::Data::new(state.clone()));
        cfg.app_data(web::Data::new(authorization_runtime.clone()));
        if dynamic_service.include_builtin_auth {
            auth::auth_routes_with_settings(
                cfg,
                pool.clone(),
                dynamic_service.security.auth.clone(),
            );
        }
        if dynamic_service.authorization_management_enabled {
            rest_macro_core::authorization::authorization_management_routes_at(
                cfg,
                dynamic_service.authorization_management_mount.as_str(),
            );
        }
        for resource in &dynamic_service.resources {
            register_resource(cfg, resource.clone());
        }
    });
    scope
}

fn register_resource(cfg: &mut web::ServiceConfig, resource: Arc<DynamicResource>) {
    let collection_path = format!("/{}", resource.table_name);
    let item_path = format!("/{}/{{id}}", resource.table_name);

    let list_resource = resource.clone();
    let create_resource = resource.clone();
    let collection = web::resource(collection_path)
        .route(if resource.read_requires_auth {
            web::get().to(
                move |req: HttpRequest, user: UserContext, state: web::Data<NativeServeState>| {
                    let resource = list_resource.clone();
                    async move { list_handler(req, Some(user), state, resource, None).await }
                },
            )
        } else {
            web::get().to(
                move |req: HttpRequest, state: web::Data<NativeServeState>| {
                    let resource = list_resource.clone();
                    async move { list_handler(req, None, state, resource, None).await }
                },
            )
        })
        .route(web::post().to(
            move |req: HttpRequest,
                  item: web::Json<Map<String, Value>>,
                  user: UserContext,
                  state: web::Data<NativeServeState>| {
                let resource = create_resource.clone();
                async move { create_handler(req, item.into_inner(), user, state, resource).await }
            },
        ));
    cfg.service(collection);

    let get_resource = resource.clone();
    let update_resource = resource.clone();
    let delete_resource = resource.clone();
    let item = web::resource(item_path)
        .route(if resource.read_requires_auth {
            web::get().to(
                move |path: web::Path<i64>,
                      req: HttpRequest,
                      user: UserContext,
                      state: web::Data<NativeServeState>| {
                    let resource = get_resource.clone();
                    async move {
                        get_handler(path.into_inner(), req, Some(user), state, resource).await
                    }
                },
            )
        } else {
            web::get().to(
                move |path: web::Path<i64>,
                      req: HttpRequest,
                      state: web::Data<NativeServeState>| {
                    let resource = get_resource.clone();
                    async move { get_handler(path.into_inner(), req, None, state, resource).await }
                },
            )
        })
        .route(web::put().to(
            move |path: web::Path<i64>,
                  item: web::Json<Map<String, Value>>,
                  user: UserContext,
                  state: web::Data<NativeServeState>| {
                let resource = update_resource.clone();
                async move {
                    update_handler(path.into_inner(), item.into_inner(), user, state, resource)
                        .await
                }
            },
        ))
        .route(web::delete().to(
            move |path: web::Path<i64>, user: UserContext, state: web::Data<NativeServeState>| {
                let resource = delete_resource.clone();
                async move { delete_handler(path.into_inner(), user, state, resource).await }
            },
        ));
    cfg.service(item);

    for relation in &resource.nested_relations {
        let nested_path = format!(
            "/{}/{{parent_id}}/{}",
            relation.parent_table, resource.table_name
        );
        let nested_resource = resource.clone();
        let relation_field = relation.field_name.clone();
        let nested = web::resource(nested_path).route(if resource.read_requires_auth {
            web::get().to(
                move |path: web::Path<i64>,
                      req: HttpRequest,
                      user: UserContext,
                      state: web::Data<NativeServeState>| {
                    let resource = nested_resource.clone();
                    let relation_field = relation_field.clone();
                    async move {
                        list_handler(
                            req,
                            Some(user),
                            state,
                            resource,
                            Some((relation_field, path.into_inner())),
                        )
                        .await
                    }
                },
            )
        } else {
            web::get().to(
                move |path: web::Path<i64>,
                      req: HttpRequest,
                      state: web::Data<NativeServeState>| {
                    let resource = nested_resource.clone();
                    let relation_field = relation_field.clone();
                    async move {
                        list_handler(
                            req,
                            None,
                            state,
                            resource,
                            Some((relation_field, path.into_inner())),
                        )
                        .await
                    }
                },
            )
        });
        cfg.service(nested);
    }
}

fn build_openapi_json(service: &ServiceSpec, include_builtin_auth: bool) -> anyhow::Result<String> {
    let options = OpenApiSpecOptions::new(
        default_title(service),
        DEFAULT_OPENAPI_VERSION.to_owned(),
        "/api".to_owned(),
    )
    .with_builtin_auth(include_builtin_auth);
    compiler::render_service_openapi_json(service, &options)
        .map_err(|error| anyhow!(error.to_string()))
}

fn default_title(service: &ServiceSpec) -> String {
    service
        .module_ident
        .to_string()
        .replace('_', " ")
        .trim()
        .to_owned()
}

fn default_bind_addr_from_tls(tls_enabled: bool) -> &'static str {
    if tls_enabled {
        "127.0.0.1:8443"
    } else {
        "127.0.0.1:8080"
    }
}

fn convert_static_mounts(mounts: &[compiler::StaticMountSpec]) -> Vec<StaticMount> {
    mounts
        .iter()
        .map(|mount| StaticMount {
            mount_path: Box::leak(mount.mount_path.clone().into_boxed_str()),
            source_dir: Box::leak(mount.source_dir.clone().into_boxed_str()),
            resolved_dir: Box::leak(mount.resolved_dir.clone().into_boxed_str()),
            mode: match mount.mode {
                compiler::StaticMode::Directory => {
                    rest_macro_core::static_files::StaticMode::Directory
                }
                compiler::StaticMode::Spa => rest_macro_core::static_files::StaticMode::Spa,
            },
            index_file: mount
                .index_file
                .as_ref()
                .map(|value| Box::leak(value.clone().into_boxed_str()) as &'static str),
            fallback_file: mount
                .fallback_file
                .as_ref()
                .map(|value| Box::leak(value.clone().into_boxed_str()) as &'static str),
            cache: match mount.cache {
                compiler::StaticCacheProfile::NoStore => {
                    rest_macro_core::static_files::StaticCacheProfile::NoStore
                }
                compiler::StaticCacheProfile::Revalidate => {
                    rest_macro_core::static_files::StaticCacheProfile::Revalidate
                }
                compiler::StaticCacheProfile::Immutable => {
                    rest_macro_core::static_files::StaticCacheProfile::Immutable
                }
            },
        })
        .collect()
}

fn swagger_ui_html() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>API Docs</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    body {
      margin: 0;
      background: #101820;
    }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {
      window.ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui'
      });
    };
  </script>
</body>
</html>"#
}

fn detect_backend(service: &ServiceSpec) -> anyhow::Result<DbBackend> {
    let mut backends = service.resources.iter().map(|resource| resource.db);
    let Some(first) = backends.next() else {
        bail!("service config must contain at least one resource");
    };
    if backends.any(|backend| backend != first) {
        bail!("mixed database backends in one service are not supported by `vsr serve`");
    }
    Ok(first)
}

fn ensure_auth_is_compatible(
    service: &ServiceSpec,
    include_builtin_auth: bool,
) -> anyhow::Result<()> {
    if !include_builtin_auth {
        return Ok(());
    }
    if service
        .resources
        .iter()
        .any(|resource| resource.table_name == "user")
    {
        bail!(
            "built-in auth is enabled by default and cannot be used when the service already defines a `user` table; re-run with `--without-auth`"
        );
    }
    Ok(())
}

fn ensure_database_engine_is_compatible(
    service: &ServiceSpec,
    backend: DbBackend,
) -> anyhow::Result<()> {
    match &service.database.engine {
        rest_macro_core::database::DatabaseEngine::Sqlx => Ok(()),
        rest_macro_core::database::DatabaseEngine::TursoLocal(_) => {
            if backend != DbBackend::Sqlite {
                bail!("database.engine = TursoLocal requires SQLite resources");
            }
            Ok(())
        }
    }
}

fn build_create_field_rules(
    resource: &ResourceSpec,
    service: &ServiceSpec,
) -> anyhow::Result<Vec<CreateFieldRule>> {
    let hybrid_scope_field = build_hybrid_resource_config(resource, service)
        .filter(|config| config.create_payload)
        .map(|config| config.scope_field);
    let mut fields = Vec::new();

    for field in &resource.fields {
        if field.generated.skip_insert() {
            continue;
        }
        let controlled = create_assignment_source(resource, field.name().as_str()).is_some();
        let allow_admin_override = controlled
            && resource.policies.admin_bypass
            && matches!(
                create_assignment_source(resource, field.name().as_str()),
                Some(PolicyValueSource::Claim(_))
            );
        let allow_hybrid_runtime =
            controlled && hybrid_scope_field.as_deref() == Some(field.name().as_str());
        if controlled && !allow_admin_override && !allow_hybrid_runtime {
            continue;
        }
        fields.push(CreateFieldRule {
            name: field.name(),
            allow_admin_override,
            allow_hybrid_runtime,
            payload_optional: compiler::is_optional_type(&field.ty)
                || allow_admin_override
                || allow_hybrid_runtime,
        });
    }

    Ok(fields)
}

fn build_hybrid_resource_config(
    resource: &ResourceSpec,
    service: &ServiceSpec,
) -> Option<HybridResourceConfig> {
    let hybrid = service
        .authorization
        .hybrid_enforcement
        .resource(resource.struct_ident.to_string().as_str())?;
    Some(HybridResourceConfig {
        scope: hybrid.scope.clone(),
        scope_field: hybrid.scope_field.clone(),
        item_read: hybrid.supports_item_action(AuthorizationAction::Read),
        collection_read: hybrid.supports_collection_read(),
        nested_read: hybrid.supports_nested_read(),
        create_payload: hybrid.supports_item_action(AuthorizationAction::Create),
        update: hybrid.supports_item_action(AuthorizationAction::Update),
        delete: hybrid.supports_item_action(AuthorizationAction::Delete),
    })
}

fn policy_controlled_fields(resource: &ResourceSpec) -> BTreeSet<String> {
    resource
        .policies
        .controlled_filter_fields()
        .into_iter()
        .chain(
            resource
                .policies
                .iter_assignments()
                .map(|(_, policy)| policy.field.clone()),
        )
        .collect()
}

fn create_assignment_source<'a>(
    resource: &'a ResourceSpec,
    field_name: &str,
) -> Option<&'a PolicyValueSource> {
    resource
        .policies
        .create
        .iter()
        .find(|policy| policy.field == field_name)
        .map(|policy| &policy.source)
}

fn placeholder(backend: DbBackend, index: usize) -> String {
    backend.placeholder(index)
}

fn render_condition_with_placeholders(
    condition: &str,
    backend: DbBackend,
    start_index: usize,
) -> String {
    let mut rendered = String::new();
    let mut remaining = condition;
    let mut index = start_index;
    while let Some(position) = remaining.find(BIND_MARKER) {
        rendered.push_str(&remaining[..position]);
        rendered.push_str(&placeholder(backend, index));
        remaining = &remaining[position + BIND_MARKER.len()..];
        index += 1;
    }
    rendered.push_str(remaining);
    rendered
}

fn bind_query<'q>(mut query: Query<'q>, value: &BoundValue) -> Query<'q> {
    query = match value {
        BoundValue::Null => query.bind::<Option<String>>(None),
        BoundValue::Bool(value) => query.bind(*value),
        BoundValue::Integer(value) => query.bind(*value),
        BoundValue::Real(value) => query.bind(*value),
        BoundValue::Text(value) => query.bind(value.clone()),
    };
    query
}

fn bind_scalar_query<'q, T>(
    mut query: rest_macro_core::db::QueryScalar<'q, T>,
    value: &BoundValue,
) -> rest_macro_core::db::QueryScalar<'q, T> {
    query = match value {
        BoundValue::Null => query.bind::<Option<String>>(None),
        BoundValue::Bool(value) => query.bind(*value),
        BoundValue::Integer(value) => query.bind(*value),
        BoundValue::Real(value) => query.bind(*value),
        BoundValue::Text(value) => query.bind(value.clone()),
    };
    query
}

fn anonymous_user_context() -> UserContext {
    UserContext {
        id: 0,
        roles: Vec::new(),
        claims: BTreeMap::new(),
    }
}

fn is_admin(user: &UserContext) -> bool {
    user.roles.iter().any(|candidate| candidate == "admin")
}

fn is_integer_sql_type(sql_type: &str) -> bool {
    matches!(sql_type, "INTEGER" | "BIGINT")
}

fn generated_temporal_expression(db: DbBackend, field: &DynamicField) -> &'static str {
    let kind = match field.kind {
        FieldKind::DateTime => Some(compiler::GeneratedTemporalKind::DateTime),
        FieldKind::Date => Some(compiler::GeneratedTemporalKind::Date),
        FieldKind::Time => Some(compiler::GeneratedTemporalKind::Time),
        _ => None,
    };
    db.generated_temporal_expression(kind)
}

fn type_leaf_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(type_path) => {
            let segment = type_path.path.segments.last()?;
            if segment.ident == "Option" {
                let PathArguments::AngleBracketed(args) = &segment.arguments else {
                    return None;
                };
                let inner = args.args.iter().find_map(|arg| match arg {
                    GenericArgument::Type(ty) => Some(ty),
                    _ => None,
                })?;
                return type_leaf_name(inner);
            }
            Some(segment.ident.to_string())
        }
        _ => None,
    }
}

fn is_bool_type(ty: &Type) -> bool {
    matches!(type_leaf_name(ty).as_deref(), Some("bool"))
}

fn supports_contains_filters(field: &DynamicField) -> bool {
    !matches!(
        field.kind,
        FieldKind::Integer
            | FieldKind::Real
            | FieldKind::Boolean
            | FieldKind::DateTime
            | FieldKind::Date
            | FieldKind::Time
            | FieldKind::Uuid
            | FieldKind::Decimal
    )
}

fn list_contains_pattern(value: &str) -> String {
    let lowered = value.to_lowercase();
    let mut pattern = String::with_capacity(lowered.len() + 2);
    pattern.push('%');
    for ch in lowered.chars() {
        match ch {
            '%' | '_' | '\\' => {
                pattern.push('\\');
                pattern.push(ch);
            }
            _ => pattern.push(ch),
        }
    }
    pattern.push('%');
    pattern
}

fn normalize_text_field_value(kind: FieldKind, value: &str) -> anyhow::Result<String> {
    Ok(match kind {
        FieldKind::DateTime => DateTime::parse_from_rfc3339(value)
            .with_context(|| format!("invalid date-time `{value}`"))?
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Micros, false),
        FieldKind::Date => NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .with_context(|| format!("invalid date `{value}`"))?
            .format("%Y-%m-%d")
            .to_string(),
        FieldKind::Time => value
            .parse::<NaiveTime>()
            .with_context(|| format!("invalid time `{value}`"))?
            .format("%H:%M:%S.%6f")
            .to_string(),
        FieldKind::Uuid => Uuid::parse_str(value)
            .with_context(|| format!("invalid uuid `{value}`"))?
            .as_hyphenated()
            .to_string(),
        FieldKind::Decimal => value
            .parse::<Decimal>()
            .with_context(|| format!("invalid decimal `{value}`"))?
            .normalize()
            .to_string(),
        _ => value.to_owned(),
    })
}

fn bound_value_to_json(value: &BoundValue) -> Value {
    match value {
        BoundValue::Null => Value::Null,
        BoundValue::Bool(value) => Value::Bool(*value),
        BoundValue::Integer(value) => Value::from(*value),
        BoundValue::Real(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        BoundValue::Text(value) => Value::String(value.clone()),
    }
}

fn parse_body_value(
    field: &DynamicField,
    value: Option<&Value>,
    allow_missing: bool,
) -> Result<BoundValue, HttpResponse> {
    match value {
        None => {
            if allow_missing {
                Ok(BoundValue::Null)
            } else {
                Err(errors::bad_request(
                    "invalid_json",
                    "Request body is not valid JSON",
                ))
            }
        }
        Some(Value::Null) => {
            if field.optional || allow_missing {
                Ok(BoundValue::Null)
            } else {
                Err(errors::bad_request(
                    "invalid_json",
                    "Request body is not valid JSON",
                ))
            }
        }
        Some(value) => parse_json_value(field, value)
            .map_err(|_| errors::bad_request("invalid_json", "Request body is not valid JSON")),
    }
}

fn parse_query_value(field: &DynamicField, value: &str) -> anyhow::Result<BoundValue> {
    match field.kind {
        FieldKind::Integer => value
            .parse::<i64>()
            .map(BoundValue::Integer)
            .with_context(|| format!("invalid integer `{value}`")),
        FieldKind::Real => value
            .parse::<f64>()
            .map(BoundValue::Real)
            .with_context(|| format!("invalid real `{value}`")),
        FieldKind::Boolean => value
            .parse::<bool>()
            .map(BoundValue::Bool)
            .with_context(|| format!("invalid boolean `{value}`")),
        FieldKind::Text => Ok(BoundValue::Text(value.to_owned())),
        FieldKind::DateTime
        | FieldKind::Date
        | FieldKind::Time
        | FieldKind::Uuid
        | FieldKind::Decimal => Ok(BoundValue::Text(normalize_text_field_value(
            field.kind, value,
        )?)),
    }
}

fn parse_json_value(field: &DynamicField, value: &Value) -> anyhow::Result<BoundValue> {
    match field.kind {
        FieldKind::Integer => value
            .as_i64()
            .map(BoundValue::Integer)
            .ok_or_else(|| anyhow!("expected integer")),
        FieldKind::Real => value
            .as_f64()
            .map(BoundValue::Real)
            .ok_or_else(|| anyhow!("expected number")),
        FieldKind::Boolean => value
            .as_bool()
            .map(BoundValue::Bool)
            .ok_or_else(|| anyhow!("expected boolean")),
        FieldKind::Text => value
            .as_str()
            .map(|value| BoundValue::Text(value.to_owned()))
            .ok_or_else(|| anyhow!("expected string")),
        FieldKind::DateTime
        | FieldKind::Date
        | FieldKind::Time
        | FieldKind::Uuid
        | FieldKind::Decimal => {
            let value = value.as_str().ok_or_else(|| anyhow!("expected string"))?;
            Ok(BoundValue::Text(normalize_text_field_value(
                field.kind, value,
            )?))
        }
    }
}

fn apply_validation(field: &DynamicField, value: &BoundValue) -> Result<(), HttpResponse> {
    if field.validation.is_empty() || matches!(value, BoundValue::Null) {
        return Ok(());
    }

    if let Some(min_length) = field.validation.min_length {
        if let BoundValue::Text(text) = value {
            if text.chars().count() < min_length {
                return Err(errors::validation_error(
                    field.name.clone(),
                    format!(
                        "Field `{}` must have at least {} characters",
                        field.name, min_length
                    ),
                ));
            }
        }
    }

    if let Some(max_length) = field.validation.max_length {
        if let BoundValue::Text(text) = value {
            if text.chars().count() > max_length {
                return Err(errors::validation_error(
                    field.name.clone(),
                    format!(
                        "Field `{}` must have at most {} characters",
                        field.name, max_length
                    ),
                ));
            }
        }
    }

    match value {
        BoundValue::Integer(actual) => {
            if let Some(NumericBound::Integer(minimum)) = field.validation.minimum {
                if *actual < minimum {
                    return Err(errors::validation_error(
                        field.name.clone(),
                        format!("Field `{}` must be at least {}", field.name, minimum),
                    ));
                }
            }
            if let Some(NumericBound::Integer(maximum)) = field.validation.maximum {
                if *actual > maximum {
                    return Err(errors::validation_error(
                        field.name.clone(),
                        format!("Field `{}` must be at most {}", field.name, maximum),
                    ));
                }
            }
        }
        BoundValue::Real(actual) => {
            if let Some(minimum) = &field.validation.minimum {
                if *actual < minimum.as_f64() {
                    return Err(errors::validation_error(
                        field.name.clone(),
                        format!(
                            "Field `{}` must be at least {}",
                            field.name,
                            minimum.as_f64()
                        ),
                    ));
                }
            }
            if let Some(maximum) = &field.validation.maximum {
                if *actual > maximum.as_f64() {
                    return Err(errors::validation_error(
                        field.name.clone(),
                        format!(
                            "Field `{}` must be at most {}",
                            field.name,
                            maximum.as_f64()
                        ),
                    ));
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn row_to_json(resource: &DynamicResource, row: &sqlx::any::AnyRow) -> Result<Value, sqlx::Error> {
    let mut map = Map::new();
    for field in &resource.fields {
        let value = match field.kind {
            FieldKind::Integer => {
                if field.optional {
                    row.try_get::<Option<i64>, _>(field.name.as_str())?
                        .map(Value::from)
                        .unwrap_or(Value::Null)
                } else {
                    Value::from(row.try_get::<i64, _>(field.name.as_str())?)
                }
            }
            FieldKind::Real => {
                let number = if field.optional {
                    row.try_get::<Option<f64>, _>(field.name.as_str())?
                } else {
                    Some(row.try_get::<f64, _>(field.name.as_str())?)
                };
                number
                    .and_then(serde_json::Number::from_f64)
                    .map(Value::Number)
                    .unwrap_or(Value::Null)
            }
            FieldKind::Boolean => {
                if field.optional {
                    row.try_get::<Option<bool>, _>(field.name.as_str())?
                        .map(Value::Bool)
                        .unwrap_or(Value::Null)
                } else {
                    Value::Bool(row.try_get::<bool, _>(field.name.as_str())?)
                }
            }
            FieldKind::Text
            | FieldKind::DateTime
            | FieldKind::Date
            | FieldKind::Time
            | FieldKind::Uuid
            | FieldKind::Decimal => {
                if field.optional {
                    row.try_get::<Option<String>, _>(field.name.as_str())?
                        .map(Value::String)
                        .unwrap_or(Value::Null)
                } else {
                    Value::String(row.try_get::<String, _>(field.name.as_str())?)
                }
            }
        };
        map.insert(field.name.clone(), value);
    }
    Ok(Value::Object(map))
}

fn json_field_to_scope_value(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn require_role(user: &UserContext, role: Option<&str>) -> Result<(), HttpResponse> {
    if let Some(role) = role {
        if !user
            .roles
            .iter()
            .any(|candidate| candidate == "admin" || candidate == role)
        {
            return Err(errors::forbidden("forbidden", "Insufficient privileges"));
        }
    }
    Ok(())
}

fn current_row_scope_binding(
    resource: &DynamicResource,
    item: &Value,
) -> Option<AuthorizationScopeBinding> {
    let hybrid = resource.hybrid.as_ref()?;
    let value = item.get(hybrid.scope_field.as_str())?;
    Some(AuthorizationScopeBinding {
        scope: hybrid.scope.clone(),
        value: json_field_to_scope_value(value)?,
    })
}

fn list_scope_binding(
    resource: &DynamicResource,
    query: &HashMap<String, String>,
    parent_filter: Option<&(String, i64)>,
) -> Option<AuthorizationScopeBinding> {
    let hybrid = resource.hybrid.as_ref()?;
    if let Some((field_name, value)) = parent_filter
        && field_name == hybrid.scope_field.as_str()
    {
        return Some(AuthorizationScopeBinding {
            scope: hybrid.scope.clone(),
            value: value.to_string(),
        });
    }
    let filter_name = format!("filter_{}", hybrid.scope_field);
    query
        .get(filter_name.as_str())
        .map(|value| AuthorizationScopeBinding {
            scope: hybrid.scope.clone(),
            value: value.clone(),
        })
}

async fn hybrid_runtime_allows(
    resource: &DynamicResource,
    user: &UserContext,
    state: &NativeServeState,
    action: AuthorizationAction,
    scope: AuthorizationScopeBinding,
) -> Result<bool, HttpResponse> {
    match state
        .authorization_runtime
        .evaluate_runtime_access_for_user(user.id, resource.resource_name.as_str(), action, scope)
        .await
    {
        Ok(result) => Ok(result.allowed),
        Err(message) => Err(errors::internal_error(message)),
    }
}

fn resolve_policy_source_value(
    source: &PolicyValueSource,
    target_field: &DynamicField,
    user: &UserContext,
) -> anyhow::Result<Option<BoundValue>> {
    match source {
        PolicyValueSource::UserId => Ok(Some(BoundValue::Integer(user.id))),
        PolicyValueSource::Claim(name) => match target_field.kind {
            FieldKind::Integer => Ok(user.claim_i64(name).map(BoundValue::Integer)),
            FieldKind::Boolean => Ok(user.claim_bool(name).map(BoundValue::Bool)),
            _ => Ok(user
                .claim_str(name)
                .map(|value| BoundValue::Text(value.to_owned()))),
        },
        PolicyValueSource::InputField(_) => {
            bail!("input fields are not supported in row policy sources")
        }
    }
}

fn resolve_create_source_value(
    resource: &DynamicResource,
    source: &PolicyValueSource,
    target_field: &DynamicField,
    payload: &Map<String, Value>,
    user: &UserContext,
) -> Result<Option<BoundValue>, HttpResponse> {
    match source {
        PolicyValueSource::UserId => Ok(Some(BoundValue::Integer(user.id))),
        PolicyValueSource::Claim(name) => match target_field.kind {
            FieldKind::Integer => Ok(user.claim_i64(name).map(BoundValue::Integer)),
            FieldKind::Boolean => Ok(user.claim_bool(name).map(BoundValue::Bool)),
            _ => Ok(user
                .claim_str(name)
                .map(|value| BoundValue::Text(value.to_owned()))),
        },
        PolicyValueSource::InputField(name) => {
            let field = resource
                .field(name)
                .map_err(|error| errors::internal_error(error.to_string()))?;
            parse_body_value(field, payload.get(name.as_str()), field.optional).map(Some)
        }
    }
}

async fn effective_create_field_value(
    resource: &DynamicResource,
    field: &DynamicField,
    payload: &Map<String, Value>,
    user: &UserContext,
    state: &NativeServeState,
) -> Result<BoundValue, HttpResponse> {
    if let Some(source) = resource.create_assignment_sources.get(field.name.as_str()) {
        match source {
            PolicyValueSource::UserId => return Ok(BoundValue::Integer(user.id)),
            PolicyValueSource::Claim(_) => {
                let claim_value =
                    resolve_create_source_value(resource, source, field, payload, user)?;
                let allow_admin_override = resource
                    .create_fields
                    .iter()
                    .find(|rule| rule.name == field.name)
                    .map(|rule| rule.allow_admin_override)
                    .unwrap_or(false);
                let allow_hybrid_runtime = resource
                    .create_fields
                    .iter()
                    .find(|rule| rule.name == field.name)
                    .map(|rule| rule.allow_hybrid_runtime)
                    .unwrap_or(false);
                if allow_hybrid_runtime {
                    if is_admin(user) && allow_admin_override {
                        if let Some(value) = payload.get(field.name.as_str()) {
                            return parse_body_value(field, Some(value), true);
                        }
                        if let Some(value) = claim_value {
                            return Ok(value);
                        }
                        return Err(errors::validation_error(
                            field.name.clone(),
                            format!("Missing required create field `{}`", field.name),
                        ));
                    }
                    if let Some(value) = claim_value {
                        return Ok(value);
                    }
                    let Some(raw_scope) = payload.get(field.name.as_str()) else {
                        return Err(errors::validation_error(
                            field.name.clone(),
                            format!("Missing required create field `{}`", field.name),
                        ));
                    };
                    let scope_value = parse_body_value(field, Some(raw_scope), true)?;
                    let scope = AuthorizationScopeBinding {
                        scope: resource
                            .hybrid
                            .as_ref()
                            .map(|hybrid| hybrid.scope.clone())
                            .unwrap_or_default(),
                        value: json_field_to_scope_value(&bound_value_to_json(&scope_value))
                            .unwrap_or_default(),
                    };
                    if hybrid_runtime_allows(
                        resource,
                        user,
                        state,
                        AuthorizationAction::Create,
                        scope,
                    )
                    .await?
                    {
                        return Ok(scope_value);
                    }
                    return Err(errors::forbidden(
                        "forbidden",
                        format!(
                            "Insufficient privileges for create scope field `{}`",
                            field.name
                        ),
                    ));
                }
                if allow_admin_override {
                    if is_admin(user) {
                        if let Some(value) = payload.get(field.name.as_str()) {
                            return parse_body_value(field, Some(value), true);
                        }
                        if let Some(value) = claim_value {
                            return Ok(value);
                        }
                        return Err(errors::validation_error(
                            field.name.clone(),
                            format!("Missing required create field `{}`", field.name),
                        ));
                    }
                    return claim_value.ok_or_else(|| {
                        errors::forbidden(
                            "missing_claim",
                            format!("Missing required claim for create field `{}`", field.name),
                        )
                    });
                }
                return claim_value.ok_or_else(|| {
                    errors::forbidden(
                        "missing_claim",
                        format!("Missing required claim for create field `{}`", field.name),
                    )
                });
            }
            PolicyValueSource::InputField(_) => {
                return Err(errors::internal_error(
                    "create assignments do not support input-field sources".to_owned(),
                ));
            }
        }
    }

    let rule = resource
        .create_fields
        .iter()
        .find(|rule| rule.name == field.name)
        .ok_or_else(|| {
            errors::internal_error(format!("missing create field rule `{}`", field.name))
        })?;
    parse_body_value(
        field,
        payload.get(field.name.as_str()),
        rule.payload_optional,
    )
}

fn combine_all_plans(plans: Vec<PlanOutcome>) -> PlanOutcome {
    let mut conditions = Vec::new();
    let mut binds = Vec::new();
    for plan in plans {
        match plan {
            PlanOutcome::Resolved(plan) => {
                conditions.push(plan.condition);
                binds.extend(plan.binds);
            }
            PlanOutcome::Indeterminate => return PlanOutcome::Indeterminate,
        }
    }
    PlanOutcome::Resolved(SqlPlan {
        condition: format!("({})", conditions.join(" AND ")),
        binds,
    })
}

fn combine_any_plans(plans: Vec<PlanOutcome>) -> PlanOutcome {
    let mut conditions = Vec::new();
    let mut binds = Vec::new();
    for plan in plans {
        match plan {
            PlanOutcome::Resolved(plan) => {
                conditions.push(plan.condition);
                binds.extend(plan.binds);
            }
            PlanOutcome::Indeterminate => {}
        }
    }
    if conditions.is_empty() {
        PlanOutcome::Indeterminate
    } else {
        PlanOutcome::Resolved(SqlPlan {
            condition: format!("({})", conditions.join(" OR ")),
            binds,
        })
    }
}

fn negate_plan(plan: PlanOutcome) -> PlanOutcome {
    match plan {
        PlanOutcome::Resolved(plan) => PlanOutcome::Resolved(SqlPlan {
            condition: format!("NOT ({})", plan.condition),
            binds: plan.binds,
        }),
        PlanOutcome::Indeterminate => PlanOutcome::Indeterminate,
    }
}

fn build_row_policy_plan(
    current: &DynamicResource,
    service: &DynamicService,
    expression: &PolicyFilterExpression,
    user: &UserContext,
) -> anyhow::Result<PlanOutcome> {
    match expression {
        PolicyFilterExpression::Match(filter) => {
            let field = current.field(filter.field.as_str())?;
            match &filter.operator {
                PolicyFilterOperator::Equals(source) => {
                    let Some(value) = resolve_policy_source_value(source, field, user)? else {
                        return Ok(PlanOutcome::Indeterminate);
                    };
                    Ok(PlanOutcome::Resolved(SqlPlan {
                        condition: format!("{} = {}", field.name, BIND_MARKER),
                        binds: vec![value],
                    }))
                }
                PolicyFilterOperator::IsNull => Ok(PlanOutcome::Resolved(SqlPlan {
                    condition: format!("{} IS NULL", field.name),
                    binds: Vec::new(),
                })),
                PolicyFilterOperator::IsNotNull => Ok(PlanOutcome::Resolved(SqlPlan {
                    condition: format!("{} IS NOT NULL", field.name),
                    binds: Vec::new(),
                })),
            }
        }
        PolicyFilterExpression::All(expressions) => {
            let plans = expressions
                .iter()
                .map(|expression| build_row_policy_plan(current, service, expression, user))
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(combine_all_plans(plans))
        }
        PolicyFilterExpression::Any(expressions) => {
            let plans = expressions
                .iter()
                .map(|expression| build_row_policy_plan(current, service, expression, user))
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(combine_any_plans(plans))
        }
        PolicyFilterExpression::Not(expression) => Ok(negate_plan(build_row_policy_plan(
            current, service, expression, user,
        )?)),
        PolicyFilterExpression::Exists(filter) => {
            build_row_exists_plan(current, service, filter, user)
        }
    }
}

fn build_row_exists_plan(
    current: &DynamicResource,
    service: &DynamicService,
    filter: &PolicyExistsFilter,
    user: &UserContext,
) -> anyhow::Result<PlanOutcome> {
    let target = service
        .resources
        .iter()
        .find(|resource| {
            resource.resource_name == filter.resource || resource.table_name == filter.resource
        })
        .ok_or_else(|| anyhow!("resource `{}` not found", filter.resource))?;
    let alias = format!("{}_exists", target.table_name);
    let plan =
        build_row_exists_condition_plan(current, target.as_ref(), &filter.condition, user, &alias)?;
    match plan {
        PlanOutcome::Resolved(plan) => Ok(PlanOutcome::Resolved(SqlPlan {
            condition: format!(
                "EXISTS (SELECT 1 FROM {} AS {} WHERE {})",
                target.table_name, alias, plan.condition
            ),
            binds: plan.binds,
        })),
        PlanOutcome::Indeterminate => Ok(PlanOutcome::Indeterminate),
    }
}

fn build_row_exists_condition_plan(
    current: &DynamicResource,
    target: &DynamicResource,
    condition: &PolicyExistsCondition,
    user: &UserContext,
    alias: &str,
) -> anyhow::Result<PlanOutcome> {
    match condition {
        PolicyExistsCondition::Match(filter) => {
            let field = target.field(filter.field.as_str())?;
            match &filter.operator {
                PolicyFilterOperator::Equals(source) => {
                    let Some(value) = resolve_policy_source_value(source, field, user)? else {
                        return Ok(PlanOutcome::Indeterminate);
                    };
                    Ok(PlanOutcome::Resolved(SqlPlan {
                        condition: format!("{alias}.{} = {}", field.name, BIND_MARKER),
                        binds: vec![value],
                    }))
                }
                PolicyFilterOperator::IsNull => Ok(PlanOutcome::Resolved(SqlPlan {
                    condition: format!("{alias}.{} IS NULL", field.name),
                    binds: Vec::new(),
                })),
                PolicyFilterOperator::IsNotNull => Ok(PlanOutcome::Resolved(SqlPlan {
                    condition: format!("{alias}.{} IS NOT NULL", field.name),
                    binds: Vec::new(),
                })),
            }
        }
        PolicyExistsCondition::CurrentRowField { field, row_field } => {
            Ok(PlanOutcome::Resolved(SqlPlan {
                condition: format!("{alias}.{field} = {row_field}"),
                binds: Vec::new(),
            }))
        }
        PolicyExistsCondition::All(conditions) => {
            let plans = conditions
                .iter()
                .map(|condition| {
                    build_row_exists_condition_plan(current, target, condition, user, alias)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(combine_all_plans(plans))
        }
        PolicyExistsCondition::Any(conditions) => {
            let plans = conditions
                .iter()
                .map(|condition| {
                    build_row_exists_condition_plan(current, target, condition, user, alias)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(combine_any_plans(plans))
        }
        PolicyExistsCondition::Not(condition) => Ok(negate_plan(build_row_exists_condition_plan(
            current, target, condition, user, alias,
        )?)),
    }
}

async fn evaluate_create_require(
    resource: &DynamicResource,
    service: &DynamicService,
    payload: &Map<String, Value>,
    user: &UserContext,
    state: &NativeServeState,
) -> Result<bool, HttpResponse> {
    let Some(expression) = resource.policies.create_require.as_ref() else {
        return Ok(true);
    };
    let mut effective = HashMap::new();
    for field in &resource.fields {
        if field.generated.skip_insert() {
            continue;
        }
        let value = effective_create_field_value(resource, field, payload, user, state).await?;
        effective.insert(field.name.clone(), value);
    }
    let plan =
        build_create_requirement_plan(resource, service, expression, payload, &effective, user)?;
    let PlanOutcome::Resolved(plan) = plan else {
        return Ok(false);
    };
    let sql = format!(
        "SELECT 1 WHERE {}",
        render_condition_with_placeholders(plan.condition.as_str(), resource.db, 1)
    );
    let mut query = query_scalar::<sqlx::Any, i64>(&sql);
    for bind in &plan.binds {
        query = bind_scalar_query(query, bind);
    }
    match query.fetch_optional(&state.pool).await {
        Ok(result) => Ok(result.is_some()),
        Err(error) => Err(errors::internal_error(error.to_string())),
    }
}

fn build_create_requirement_plan(
    resource: &DynamicResource,
    service: &DynamicService,
    expression: &PolicyFilterExpression,
    payload: &Map<String, Value>,
    effective: &HashMap<String, BoundValue>,
    user: &UserContext,
) -> Result<PlanOutcome, HttpResponse> {
    match expression {
        PolicyFilterExpression::Match(filter) => {
            let field = resource
                .field(filter.field.as_str())
                .map_err(|error| errors::internal_error(error.to_string()))?;
            match &filter.operator {
                PolicyFilterOperator::Equals(source) => {
                    let left = effective
                        .get(filter.field.as_str())
                        .cloned()
                        .unwrap_or(BoundValue::Null);
                    let right = resolve_create_requirement_source_value(
                        resource, source, field, payload, effective, user,
                    )?;
                    Ok(PlanOutcome::Resolved(SqlPlan {
                        condition: format!("{BIND_MARKER} = {BIND_MARKER}"),
                        binds: vec![left, right],
                    }))
                }
                PolicyFilterOperator::IsNull => {
                    let value = effective
                        .get(filter.field.as_str())
                        .cloned()
                        .unwrap_or(BoundValue::Null);
                    Ok(PlanOutcome::Resolved(SqlPlan {
                        condition: if matches!(value, BoundValue::Null) {
                            "1 = 1".to_owned()
                        } else {
                            "1 = 0".to_owned()
                        },
                        binds: Vec::new(),
                    }))
                }
                PolicyFilterOperator::IsNotNull => {
                    let value = effective
                        .get(filter.field.as_str())
                        .cloned()
                        .unwrap_or(BoundValue::Null);
                    Ok(PlanOutcome::Resolved(SqlPlan {
                        condition: if matches!(value, BoundValue::Null) {
                            "1 = 0".to_owned()
                        } else {
                            "1 = 1".to_owned()
                        },
                        binds: Vec::new(),
                    }))
                }
            }
        }
        PolicyFilterExpression::All(expressions) => {
            let plans = expressions
                .iter()
                .map(|expression| {
                    build_create_requirement_plan(
                        resource, service, expression, payload, effective, user,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(combine_all_plans(plans))
        }
        PolicyFilterExpression::Any(expressions) => {
            let plans = expressions
                .iter()
                .map(|expression| {
                    build_create_requirement_plan(
                        resource, service, expression, payload, effective, user,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(combine_any_plans(plans))
        }
        PolicyFilterExpression::Not(expression) => Ok(negate_plan(build_create_requirement_plan(
            resource, service, expression, payload, effective, user,
        )?)),
        PolicyFilterExpression::Exists(filter) => {
            let target = service
                .resources
                .iter()
                .find(|candidate| {
                    candidate.resource_name == filter.resource
                        || candidate.table_name == filter.resource
                })
                .ok_or_else(|| {
                    errors::internal_error(format!("resource `{}` not found", filter.resource))
                })?;
            let alias = format!("{}_create_require", target.table_name);
            let plan = build_create_requirement_exists_condition_plan(
                resource,
                target.as_ref(),
                &filter.condition,
                payload,
                effective,
                user,
                &alias,
            )?;
            Ok(match plan {
                PlanOutcome::Resolved(plan) => PlanOutcome::Resolved(SqlPlan {
                    condition: format!(
                        "EXISTS (SELECT 1 FROM {} AS {} WHERE {})",
                        target.table_name, alias, plan.condition
                    ),
                    binds: plan.binds,
                }),
                PlanOutcome::Indeterminate => PlanOutcome::Indeterminate,
            })
        }
    }
}

fn build_create_requirement_exists_condition_plan(
    current: &DynamicResource,
    target: &DynamicResource,
    condition: &PolicyExistsCondition,
    payload: &Map<String, Value>,
    effective: &HashMap<String, BoundValue>,
    user: &UserContext,
    alias: &str,
) -> Result<PlanOutcome, HttpResponse> {
    match condition {
        PolicyExistsCondition::Match(filter) => {
            let field = target
                .field(filter.field.as_str())
                .map_err(|error| errors::internal_error(error.to_string()))?;
            match &filter.operator {
                PolicyFilterOperator::Equals(source) => {
                    let value = resolve_create_requirement_source_value(
                        current, source, field, payload, effective, user,
                    )?;
                    Ok(PlanOutcome::Resolved(SqlPlan {
                        condition: format!("{alias}.{} = {}", field.name, BIND_MARKER),
                        binds: vec![value],
                    }))
                }
                PolicyFilterOperator::IsNull => Ok(PlanOutcome::Resolved(SqlPlan {
                    condition: format!("{alias}.{} IS NULL", field.name),
                    binds: Vec::new(),
                })),
                PolicyFilterOperator::IsNotNull => Ok(PlanOutcome::Resolved(SqlPlan {
                    condition: format!("{alias}.{} IS NOT NULL", field.name),
                    binds: Vec::new(),
                })),
            }
        }
        PolicyExistsCondition::CurrentRowField { field, row_field } => {
            let value = effective
                .get(row_field.as_str())
                .cloned()
                .unwrap_or(BoundValue::Null);
            Ok(PlanOutcome::Resolved(SqlPlan {
                condition: format!("{alias}.{field} = {BIND_MARKER}"),
                binds: vec![value],
            }))
        }
        PolicyExistsCondition::All(conditions) => {
            let plans = conditions
                .iter()
                .map(|condition| {
                    build_create_requirement_exists_condition_plan(
                        current, target, condition, payload, effective, user, alias,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(combine_all_plans(plans))
        }
        PolicyExistsCondition::Any(conditions) => {
            let plans = conditions
                .iter()
                .map(|condition| {
                    build_create_requirement_exists_condition_plan(
                        current, target, condition, payload, effective, user, alias,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(combine_any_plans(plans))
        }
        PolicyExistsCondition::Not(condition) => {
            Ok(negate_plan(build_create_requirement_exists_condition_plan(
                current, target, condition, payload, effective, user, alias,
            )?))
        }
    }
}

fn resolve_create_requirement_source_value(
    resource: &DynamicResource,
    source: &PolicyValueSource,
    target_field: &DynamicField,
    payload: &Map<String, Value>,
    effective: &HashMap<String, BoundValue>,
    user: &UserContext,
) -> Result<BoundValue, HttpResponse> {
    match source {
        PolicyValueSource::UserId => Ok(BoundValue::Integer(user.id)),
        PolicyValueSource::Claim(name) => {
            match resolve_create_source_value(resource, source, target_field, payload, user)? {
                Some(value) => Ok(value),
                None => Err(errors::forbidden(
                    "missing_claim",
                    format!(
                        "Missing required claim `{}` for create requirement field `{}`",
                        name, target_field.name
                    ),
                )),
            }
        }
        PolicyValueSource::InputField(name) => Ok(effective
            .get(name.as_str())
            .cloned()
            .unwrap_or(BoundValue::Null)),
    }
}

fn decode_cursor(value: &str) -> Result<CursorPayload, HttpResponse> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| errors::bad_request("invalid_cursor", "Cursor is not valid"))?;
    serde_json::from_slice::<CursorPayload>(&bytes)
        .map_err(|_| errors::bad_request("invalid_cursor", "Cursor is not valid"))
}

fn encode_cursor(payload: &CursorPayload) -> Result<String, HttpResponse> {
    let json =
        serde_json::to_vec(payload).map_err(|error| errors::internal_error(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

fn parse_list_query(req: &HttpRequest) -> HashMap<String, String> {
    form_urlencoded::parse(req.query_string().as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn build_list_plan(
    resource: &DynamicResource,
    service: &DynamicService,
    req: &HttpRequest,
    user: &UserContext,
    parent_filter: Option<&(String, i64)>,
    skip_static_read_policy: bool,
) -> Result<ListQueryPlan, HttpResponse> {
    let mut query = parse_list_query(req);
    let requested_limit = query
        .remove("limit")
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| errors::bad_request("invalid_query", "Query parameters are invalid"))?;
    let offset = query
        .remove("offset")
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| errors::bad_request("invalid_query", "Query parameters are invalid"))?;
    let cursor = query.remove("cursor");
    let sort = query.remove("sort");
    let order = query.remove("order");

    if cursor.is_some() && offset.is_some() {
        return Err(errors::bad_request(
            "invalid_cursor",
            "`cursor` cannot be combined with `offset`",
        ));
    }
    if cursor.is_some() && (sort.is_some() || order.is_some()) {
        return Err(errors::bad_request(
            "invalid_cursor",
            "`cursor` cannot be combined with `sort` or `order`",
        ));
    }

    let default_limit = resource.default_limit;
    let max_limit = resource.max_limit;
    let effective_limit = match (requested_limit.or(default_limit), max_limit) {
        (Some(limit), Some(max_limit)) => {
            if limit == 0 {
                return Err(errors::bad_request(
                    "invalid_pagination",
                    "`limit` must be greater than 0",
                ));
            }
            Some(limit.min(max_limit))
        }
        (Some(limit), None) => {
            if limit == 0 {
                return Err(errors::bad_request(
                    "invalid_pagination",
                    "`limit` must be greater than 0",
                ));
            }
            Some(limit)
        }
        (None, _) => None,
    };

    let sort_supplied = sort.is_some();
    let order_supplied = order.is_some();
    let cursor_payload = match cursor.as_deref() {
        Some(value) => Some(decode_cursor(value)?),
        None => None,
    };

    let (sort_field, sort_order, cursor_mode) = if let Some(cursor_payload) = &cursor_payload {
        let sort_field = cursor_payload.sort.clone();
        let sort_order = parse_sort_order(cursor_payload.order.as_str())
            .ok_or_else(|| errors::bad_request("invalid_cursor", "Cursor is not valid"))?;
        (sort_field, sort_order, true)
    } else {
        let sort_field = sort.unwrap_or_else(|| resource.id_field.clone());
        let sort_order = match order {
            Some(order) => parse_sort_order(order.as_str()).ok_or_else(|| {
                errors::bad_request("invalid_query", "Query parameters are invalid")
            })?,
            None => SortOrder::Asc,
        };
        if !sort_supplied && order_supplied {
            return Err(errors::bad_request(
                "invalid_sort",
                "`order` requires `sort`",
            ));
        }
        (sort_field, sort_order, false)
    };

    let sort_field_spec = resource
        .field(sort_field.as_str())
        .map_err(|_| errors::bad_request("invalid_query", "Query parameters are invalid"))?;
    if !sort_field_spec.supports_sort {
        return Err(errors::bad_request(
            "invalid_sort",
            "Unsupported sort field",
        ));
    }
    if cursor_mode && effective_limit.is_none() {
        return Err(errors::bad_request(
            "invalid_cursor",
            "`cursor` requires `limit` or a configured `default_limit`",
        ));
    }
    if cursor_mode
        && sort_field != resource.id_field
        && (!sort_field_spec.supports_sort || sort_field_spec.optional)
    {
        return Err(errors::bad_request(
            "invalid_cursor",
            format!("Cursor pagination does not support nullable sort field `{sort_field}`"),
        ));
    }

    let mut conditions = Vec::new();
    let mut filter_binds = Vec::new();
    let mut select_only_conditions = Vec::new();
    let mut select_only_binds = Vec::new();

    if let Some((field, value)) = parent_filter {
        conditions.push(format!("{field} = {}", BIND_MARKER));
        filter_binds.push(BoundValue::Integer(*value));
    }

    if resource.policies.has_read_filters()
        && !(resource.policies.admin_bypass && is_admin(user))
        && !skip_static_read_policy
    {
        match build_row_policy_plan(
            resource,
            service,
            resource
                .policies
                .read
                .as_ref()
                .expect("read filters checked"),
            user,
        )
        .map_err(|error| errors::internal_error(error.to_string()))?
        {
            PlanOutcome::Resolved(plan) => {
                conditions.push(plan.condition);
                filter_binds.extend(plan.binds);
            }
            PlanOutcome::Indeterminate => {
                return Err(errors::forbidden(
                    "missing_claim",
                    "Missing required principal values for row policy",
                ));
            }
        }
    }

    for field in &resource.fields {
        let exact_name = format!("filter_{}", field.name);
        if let Some(value) = query.remove(exact_name.as_str()) {
            let parsed = parse_query_value(field, value.as_str()).map_err(|_| {
                errors::bad_request("invalid_query", "Query parameters are invalid")
            })?;
            conditions.push(format!("{} = {}", field.name, BIND_MARKER));
            filter_binds.push(parsed);
        }

        if supports_contains_filters(field) {
            let contains_name = format!("filter_{}_contains", field.name);
            if let Some(value) = query.remove(contains_name.as_str()) {
                conditions.push(format!(
                    "LOWER({}) LIKE {} ESCAPE '\\'",
                    field.name, BIND_MARKER
                ));
                filter_binds.push(BoundValue::Text(list_contains_pattern(value.as_str())));
            }
        }

        if field.supports_range_filters {
            for (suffix, operator) in [("_gt", ">"), ("_gte", ">="), ("_lt", "<"), ("_lte", "<=")] {
                let name = format!("filter_{}{}", field.name, suffix);
                if let Some(value) = query.remove(name.as_str()) {
                    let parsed = parse_query_value(field, value.as_str()).map_err(|_| {
                        errors::bad_request("invalid_query", "Query parameters are invalid")
                    })?;
                    conditions.push(format!("{} {} {}", field.name, operator, BIND_MARKER));
                    filter_binds.push(parsed);
                }
            }
        }
    }

    if !query.is_empty() {
        return Err(errors::bad_request(
            "invalid_query",
            "Query parameters are invalid",
        ));
    }

    if let Some(cursor_payload) = &cursor_payload {
        let comparator = if sort_order == SortOrder::Asc {
            ">"
        } else {
            "<"
        };
        if sort_field == resource.id_field {
            if !matches!(cursor_payload.value, CursorValue::Integer(_)) {
                return Err(errors::bad_request(
                    "invalid_cursor",
                    "Cursor does not match the current sort field",
                ));
            }
            select_only_conditions.push(format!("{sort_field} {comparator} {BIND_MARKER}"));
            select_only_binds.push(BoundValue::Integer(cursor_payload.last_id));
        } else {
            let cursor_value = match (&sort_field_spec.kind, &cursor_payload.value) {
                (FieldKind::Integer, CursorValue::Integer(value)) => BoundValue::Integer(*value),
                (FieldKind::Real, CursorValue::Real(value)) => BoundValue::Real(*value),
                (FieldKind::Boolean, CursorValue::Boolean(value)) => BoundValue::Bool(*value),
                (_, CursorValue::Text(value)) => BoundValue::Text(value.clone()),
                _ => {
                    return Err(errors::bad_request(
                        "invalid_cursor",
                        "Cursor does not match the current sort field",
                    ));
                }
            };
            select_only_conditions.push(format!(
                "(({sort_field} {comparator} {BIND_MARKER}) OR ({sort_field} = {BIND_MARKER} AND {} {comparator} {BIND_MARKER}))",
                resource.id_field
            ));
            select_only_binds.push(cursor_value.clone());
            select_only_binds.push(cursor_value);
            select_only_binds.push(BoundValue::Integer(cursor_payload.last_id));
        }
    }

    let count_condition = if conditions.is_empty() {
        None
    } else {
        Some(render_condition_with_placeholders(
            conditions.join(" AND ").as_str(),
            resource.db,
            1,
        ))
    };
    let count_sql = if let Some(condition) = count_condition {
        format!(
            "SELECT COUNT(*) FROM {} WHERE {}",
            resource.table_name, condition
        )
    } else {
        format!("SELECT COUNT(*) FROM {}", resource.table_name)
    };

    let mut select_conditions = conditions.clone();
    select_conditions.extend(select_only_conditions);
    let mut select_binds = filter_binds.clone();
    select_binds.extend(select_only_binds);

    let mut select_sql = format!("SELECT * FROM {}", resource.table_name);
    if !select_conditions.is_empty() {
        select_sql.push_str(" WHERE ");
        select_sql.push_str(
            render_condition_with_placeholders(
                select_conditions.join(" AND ").as_str(),
                resource.db,
                1,
            )
            .as_str(),
        );
    }
    select_sql.push_str(" ORDER BY ");
    select_sql.push_str(sort_field.as_str());
    select_sql.push(' ');
    select_sql.push_str(sort_order.as_sql());
    if sort_field != resource.id_field {
        select_sql.push_str(", ");
        select_sql.push_str(resource.id_field.as_str());
        select_sql.push(' ');
        select_sql.push_str(sort_order.as_sql());
    }

    let query_limit = effective_limit.map(|limit| {
        if cursor_mode {
            limit.saturating_add(1)
        } else {
            limit
        }
    });
    if let Some(query_limit) = query_limit {
        let placeholder_index = select_binds.len() + 1;
        select_sql.push_str(" LIMIT ");
        select_sql.push_str(placeholder(resource.db, placeholder_index).as_str());
        select_binds.push(BoundValue::Integer(query_limit as i64));
    }
    if let Some(offset) = offset {
        if effective_limit.is_none() {
            return Err(errors::bad_request(
                "invalid_pagination",
                "`offset` requires `limit`",
            ));
        }
        let placeholder_index = select_binds.len() + 1;
        select_sql.push_str(" OFFSET ");
        select_sql.push_str(placeholder(resource.db, placeholder_index).as_str());
        select_binds.push(BoundValue::Integer(offset as i64));
    }

    Ok(ListQueryPlan {
        count_sql,
        select_sql,
        filter_binds,
        select_binds,
        limit: effective_limit,
        offset: offset.unwrap_or(0),
        sort: sort_field,
        order: sort_order,
        cursor_mode,
    })
}

fn parse_sort_order(value: &str) -> Option<SortOrder> {
    match value {
        "asc" => Some(SortOrder::Asc),
        "desc" => Some(SortOrder::Desc),
        _ => None,
    }
}

impl SortOrder {
    fn as_sql(self) -> &'static str {
        match self {
            SortOrder::Asc => "ASC",
            SortOrder::Desc => "DESC",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            SortOrder::Asc => "asc",
            SortOrder::Desc => "desc",
        }
    }
}

fn cursor_value_for_item(
    resource: &DynamicResource,
    item: &Value,
    sort: &str,
) -> Result<CursorValue, HttpResponse> {
    let field = resource
        .field(sort)
        .map_err(|error| errors::internal_error(error.to_string()))?;
    let value = item.get(sort).ok_or_else(|| {
        errors::internal_error(format!("missing sort field `{sort}` in response item"))
    })?;
    match (&field.kind, value) {
        (FieldKind::Integer, Value::Number(value)) => value
            .as_i64()
            .map(CursorValue::Integer)
            .ok_or_else(|| errors::internal_error("invalid integer cursor value".to_owned())),
        (FieldKind::Real, Value::Number(value)) => value
            .as_f64()
            .map(CursorValue::Real)
            .ok_or_else(|| errors::internal_error("invalid real cursor value".to_owned())),
        (FieldKind::Boolean, Value::Bool(value)) => Ok(CursorValue::Boolean(*value)),
        (_, Value::String(value)) => Ok(CursorValue::Text(value.clone())),
        (_, Value::Number(value)) if sort == resource.id_field => value
            .as_i64()
            .map(CursorValue::Integer)
            .ok_or_else(|| errors::internal_error("invalid id cursor value".to_owned())),
        _ => Err(errors::internal_error(format!(
            "unsupported cursor value for field `{sort}`"
        ))),
    }
}

fn id_for_item(resource: &DynamicResource, item: &Value) -> Result<i64, HttpResponse> {
    item.get(resource.id_field.as_str())
        .and_then(Value::as_i64)
        .ok_or_else(|| errors::internal_error("missing persisted id in list item".to_owned()))
}

fn finalize_list_response(
    resource: &DynamicResource,
    plan: ListQueryPlan,
    total: i64,
    mut items: Vec<Value>,
) -> Result<ListResponse, HttpResponse> {
    let mut has_more = false;
    if plan.cursor_mode {
        if let Some(limit) = plan.limit {
            if items.len() > limit as usize {
                has_more = true;
                items.pop();
            }
        }
    } else if plan.limit.is_some() {
        has_more = (plan.offset as i64) + (items.len() as i64) < total;
    }

    let next_offset = if !plan.cursor_mode && has_more {
        Some(plan.offset + items.len() as u32)
    } else {
        None
    };

    let next_cursor = if has_more {
        match items.last() {
            Some(item) => Some(encode_cursor(&CursorPayload {
                sort: plan.sort.clone(),
                order: plan.order.as_str().to_owned(),
                last_id: id_for_item(resource, item)?,
                value: cursor_value_for_item(resource, item, plan.sort.as_str())?,
            })?),
            None => None,
        }
    } else {
        None
    };

    Ok(ListResponse {
        count: items.len(),
        items,
        limit: plan.limit,
        next_cursor,
        next_offset,
        offset: plan.offset,
        total,
    })
}

async fn fetch_unfiltered_by_id(
    resource: &DynamicResource,
    state: &NativeServeState,
    id: i64,
) -> Result<Option<Value>, HttpResponse> {
    let sql = format!(
        "SELECT * FROM {} WHERE {} = {}",
        resource.table_name,
        resource.id_field,
        placeholder(resource.db, 1)
    );
    let row = query(&sql)
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|error| errors::internal_error(error.to_string()))?;
    row.map(|row| row_to_json(resource, &row))
        .transpose()
        .map_err(|error| errors::internal_error(error.to_string()))
}

async fn fetch_readable_by_id(
    resource: &DynamicResource,
    service: &DynamicService,
    state: &NativeServeState,
    user: &UserContext,
    id: i64,
) -> Result<Option<Value>, HttpResponse> {
    if !resource.can_read(user) {
        return Ok(None);
    }
    let mut sql = format!(
        "SELECT * FROM {} WHERE {} = {}",
        resource.table_name,
        resource.id_field,
        placeholder(resource.db, 1)
    );
    let mut binds = vec![BoundValue::Integer(id)];
    if resource.policies.has_read_filters() && !(resource.policies.admin_bypass && is_admin(user)) {
        match build_row_policy_plan(
            resource,
            service,
            resource
                .policies
                .read
                .as_ref()
                .expect("read filters checked"),
            user,
        )
        .map_err(|error| errors::internal_error(error.to_string()))?
        {
            PlanOutcome::Resolved(plan) => {
                sql.push_str(" AND ");
                sql.push_str(
                    render_condition_with_placeholders(plan.condition.as_str(), resource.db, 2)
                        .as_str(),
                );
                binds.extend(plan.binds);
            }
            PlanOutcome::Indeterminate => return Ok(None),
        }
    }
    let mut query = query(&sql);
    for bind in &binds {
        query = bind_query(query, bind);
    }
    let row = query
        .fetch_optional(&state.pool)
        .await
        .map_err(|error| errors::internal_error(error.to_string()))?;
    row.map(|row| row_to_json(resource, &row))
        .transpose()
        .map_err(|error| errors::internal_error(error.to_string()))
}

async fn fetch_hybrid_authorized_by_id(
    resource: &DynamicResource,
    state: &NativeServeState,
    user: &UserContext,
    id: i64,
    action: AuthorizationAction,
) -> Result<Option<Value>, HttpResponse> {
    if !resource.supports_hybrid_action(action) {
        return Ok(None);
    }
    let Some(item) = fetch_unfiltered_by_id(resource, state, id).await? else {
        return Ok(None);
    };
    let Some(scope) = current_row_scope_binding(resource, &item) else {
        return Ok(None);
    };
    if hybrid_runtime_allows(resource, user, state, action, scope).await? {
        Ok(Some(item))
    } else {
        Ok(None)
    }
}

async fn list_handler(
    req: HttpRequest,
    user: Option<UserContext>,
    state: web::Data<NativeServeState>,
    resource: Arc<DynamicResource>,
    parent_filter: Option<(String, i64)>,
) -> HttpResponse {
    let dynamic_service = state.dynamic_service.clone();
    let user = user.unwrap_or_else(anonymous_user_context);
    if let Err(response) = require_role(&user, resource.requires_role(AuthorizationAction::Read)) {
        return response;
    }

    let query_map = parse_list_query(&req);
    let skip_static = match (&resource.hybrid, user.id != 0) {
        (Some(hybrid), true) if hybrid.collection_read || hybrid.nested_read => {
            match list_scope_binding(&resource, &query_map, parent_filter.as_ref()) {
                Some(scope) => match hybrid_runtime_allows(
                    &resource,
                    &user,
                    state.get_ref(),
                    AuthorizationAction::Read,
                    scope,
                )
                .await
                {
                    Ok(allowed) => allowed,
                    Err(response) => return response,
                },
                None => false,
            }
        }
        _ => false,
    };

    let plan = match build_list_plan(
        &resource,
        dynamic_service.as_ref(),
        &req,
        &user,
        parent_filter.as_ref(),
        skip_static,
    ) {
        Ok(plan) => plan,
        Err(response) => return response,
    };

    let mut count_query = query_scalar::<sqlx::Any, i64>(&plan.count_sql);
    for bind in &plan.filter_binds {
        count_query = bind_scalar_query(count_query, bind);
    }
    let total = match count_query.fetch_one(&state.pool).await {
        Ok(total) => total,
        Err(error) => return errors::internal_error(error.to_string()),
    };

    let mut select_query = query(&plan.select_sql);
    for bind in &plan.select_binds {
        select_query = bind_query(select_query, bind);
    }
    let rows = match select_query.fetch_all(&state.pool).await {
        Ok(rows) => rows,
        Err(error) => return errors::internal_error(error.to_string()),
    };
    let items = match rows
        .iter()
        .map(|row| row_to_json(&resource, row))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(items) => items,
        Err(error) => return errors::internal_error(error.to_string()),
    };
    match finalize_list_response(&resource, plan, total, items) {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(response) => response,
    }
}

async fn get_handler(
    id: i64,
    _req: HttpRequest,
    user: Option<UserContext>,
    state: web::Data<NativeServeState>,
    resource: Arc<DynamicResource>,
) -> HttpResponse {
    let dynamic_service = state.dynamic_service.clone();
    let user = user.unwrap_or_else(anonymous_user_context);
    if let Err(response) = require_role(&user, resource.requires_role(AuthorizationAction::Read)) {
        return response;
    }
    match fetch_readable_by_id(&resource, dynamic_service.as_ref(), &state, &user, id).await {
        Ok(Some(item)) => HttpResponse::Ok().json(item),
        Ok(None) => match fetch_hybrid_authorized_by_id(
            &resource,
            &state,
            &user,
            id,
            AuthorizationAction::Read,
        )
        .await
        {
            Ok(Some(item)) => HttpResponse::Ok().json(item),
            Ok(None) => errors::not_found("Not found"),
            Err(response) => response,
        },
        Err(response) => response,
    }
}

async fn create_handler(
    req: HttpRequest,
    payload: Map<String, Value>,
    user: UserContext,
    state: web::Data<NativeServeState>,
    resource: Arc<DynamicResource>,
) -> HttpResponse {
    if let Err(response) = require_role(&user, resource.requires_role(AuthorizationAction::Create))
    {
        return response;
    }
    let dynamic_service = state.dynamic_service.clone();

    let mut insert_fields = Vec::new();
    let mut insert_values = Vec::new();
    for field in &resource.fields {
        if field.generated.skip_insert() {
            continue;
        }
        let value =
            match effective_create_field_value(&resource, field, &payload, &user, &state).await {
                Ok(value) => value,
                Err(response) => return response,
            };
        if let Err(response) = apply_validation(field, &value) {
            return response;
        }
        insert_fields.push(field.name.clone());
        insert_values.push(value);
    }

    match evaluate_create_require(&resource, dynamic_service.as_ref(), &payload, &user, &state)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return errors::forbidden("forbidden", "Create requirement conditions did not match");
        }
        Err(response) => return response,
    }

    let created_id = if insert_fields.is_empty() {
        if matches!(resource.db, DbBackend::Postgres | DbBackend::Sqlite) {
            let sql = format!(
                "INSERT INTO {} DEFAULT VALUES RETURNING {}",
                resource.table_name, resource.id_field
            );
            match query_scalar::<sqlx::Any, i64>(&sql)
                .fetch_one(&state.pool)
                .await
            {
                Ok(id) => Some(id),
                Err(error) => return errors::internal_error(error.to_string()),
            }
        } else {
            let sql = format!("INSERT INTO {} DEFAULT VALUES", resource.table_name);
            match query(&sql).execute(&state.pool).await {
                Ok(result) => result.last_insert_rowid(),
                Err(error) => return errors::internal_error(error.to_string()),
            }
        }
    } else {
        let placeholders = (1..=insert_fields.len())
            .map(|index| placeholder(resource.db, index))
            .collect::<Vec<_>>()
            .join(", ");
        let field_sql = insert_fields.join(", ");
        if matches!(resource.db, DbBackend::Postgres | DbBackend::Sqlite) {
            let sql = format!(
                "INSERT INTO {} ({}) VALUES ({}) RETURNING {}",
                resource.table_name, field_sql, placeholders, resource.id_field
            );
            let mut insert_query = query_scalar::<sqlx::Any, i64>(&sql);
            for value in &insert_values {
                insert_query = bind_scalar_query(insert_query, value);
            }
            match insert_query.fetch_one(&state.pool).await {
                Ok(id) => Some(id),
                Err(error) => return errors::internal_error(error.to_string()),
            }
        } else {
            let sql = format!(
                "INSERT INTO {} ({}) VALUES ({})",
                resource.table_name, field_sql, placeholders
            );
            let mut insert_query = query(&sql);
            for value in &insert_values {
                insert_query = bind_query(insert_query, value);
            }
            match insert_query.execute(&state.pool).await {
                Ok(result) => result.last_insert_rowid(),
                Err(error) => return errors::internal_error(error.to_string()),
            }
        }
    };

    let Some(created_id) = created_id else {
        return HttpResponse::Created().finish();
    };
    let location = format!("{}/{}", req.uri().path().trim_end_matches('/'), created_id);
    match fetch_readable_by_id(
        &resource,
        dynamic_service.as_ref(),
        &state,
        &user,
        created_id,
    )
    .await
    {
        Ok(Some(item)) => HttpResponse::Created()
            .append_header(("Location", location))
            .json(item),
        Ok(None) => match fetch_hybrid_authorized_by_id(
            &resource,
            &state,
            &user,
            created_id,
            AuthorizationAction::Read,
        )
        .await
        {
            Ok(Some(item)) => HttpResponse::Created()
                .append_header(("Location", location))
                .json(item),
            Ok(None) => HttpResponse::Created()
                .append_header(("Location", location))
                .finish(),
            Err(response) => response,
        },
        Err(response) => response,
    }
}

async fn update_handler(
    id: i64,
    payload: Map<String, Value>,
    user: UserContext,
    state: web::Data<NativeServeState>,
    resource: Arc<DynamicResource>,
) -> HttpResponse {
    if let Err(response) = require_role(&user, resource.requires_role(AuthorizationAction::Update))
    {
        return response;
    }
    if resource.update_field_names.is_empty() {
        return errors::bad_request("no_updatable_fields", "No updatable fields configured");
    }

    let mut assignments = Vec::new();
    let mut write_binds = Vec::new();
    for field_name in &resource.update_field_names {
        let field = match resource.field(field_name.as_str()) {
            Ok(field) => field,
            Err(error) => return errors::internal_error(error.to_string()),
        };
        let value = match parse_body_value(field, payload.get(field_name.as_str()), field.optional)
        {
            Ok(value) => value,
            Err(response) => return response,
        };
        if let Err(response) = apply_validation(field, &value) {
            return response;
        }
        assignments.push(format!("{} = {}", field.name, BIND_MARKER));
        write_binds.push(value);
    }
    for field in &resource.fields {
        if field.generated == GeneratedValue::UpdatedAt {
            assignments.push(format!(
                "{} = {}",
                field.name,
                generated_temporal_expression(resource.db, field)
            ));
        }
    }

    let policy = resource.policies.update.as_ref();
    let mut sql = format!(
        "UPDATE {} SET {} WHERE {} = {}",
        resource.table_name,
        assignments.join(", "),
        resource.id_field,
        placeholder(resource.db, write_binds.len() + 1),
    );
    let mut binds = write_binds.clone();
    if let Some(policy) = policy
        && !(resource.policies.admin_bypass && is_admin(&user))
    {
        match build_row_policy_plan(&resource, state.dynamic_service.as_ref(), policy, &user)
            .map_err(|error| errors::internal_error(error.to_string()))
        {
            Ok(PlanOutcome::Resolved(plan)) => {
                sql.push_str(" AND ");
                sql.push_str(
                    render_condition_with_placeholders(
                        plan.condition.as_str(),
                        resource.db,
                        write_binds.len() + 2,
                    )
                    .as_str(),
                );
                binds.push(BoundValue::Integer(id));
                binds.extend(plan.binds);
            }
            Ok(PlanOutcome::Indeterminate) => {
                return update_hybrid_fallback(
                    id,
                    &user,
                    &state,
                    &resource,
                    assignments.join(", "),
                    write_binds,
                )
                .await;
            }
            Err(response) => return response,
        }
    } else {
        binds.push(BoundValue::Integer(id));
    }

    let mut update_query = query(&sql);
    for bind in &binds {
        update_query = bind_query(update_query, bind);
    }
    match update_query.execute(&state.pool).await {
        Ok(result) if result.rows_affected() == 0 => {
            update_hybrid_fallback(
                id,
                &user,
                &state,
                &resource,
                assignments.join(", "),
                write_binds,
            )
            .await
        }
        Ok(_) => HttpResponse::Ok().finish(),
        Err(error) => errors::internal_error(error.to_string()),
    }
}

async fn update_hybrid_fallback(
    id: i64,
    user: &UserContext,
    state: &NativeServeState,
    resource: &DynamicResource,
    assignment_sql: String,
    assignment_binds: Vec<BoundValue>,
) -> HttpResponse {
    match fetch_hybrid_authorized_by_id(resource, state, user, id, AuthorizationAction::Update)
        .await
    {
        Ok(Some(_)) => {
            let sql = format!(
                "UPDATE {} SET {} WHERE {} = {}",
                resource.table_name,
                assignment_sql,
                resource.id_field,
                placeholder(resource.db, assignment_binds.len() + 1),
            );
            let mut query = query(&sql);
            for bind in &assignment_binds {
                query = bind_query(query, bind);
            }
            query = query.bind(id);
            match query.execute(&state.pool).await {
                Ok(result) if result.rows_affected() == 0 => errors::not_found("Not found"),
                Ok(_) => HttpResponse::Ok().finish(),
                Err(error) => errors::internal_error(error.to_string()),
            }
        }
        Ok(None) => errors::not_found("Not found"),
        Err(response) => response,
    }
}

async fn delete_handler(
    id: i64,
    user: UserContext,
    state: web::Data<NativeServeState>,
    resource: Arc<DynamicResource>,
) -> HttpResponse {
    if let Err(response) = require_role(&user, resource.requires_role(AuthorizationAction::Delete))
    {
        return response;
    }
    if resource.policies.delete.is_none() || (resource.policies.admin_bypass && is_admin(&user)) {
        let sql = format!(
            "DELETE FROM {} WHERE {} = {}",
            resource.table_name,
            resource.id_field,
            placeholder(resource.db, 1),
        );
        return match query(&sql).bind(id).execute(&state.pool).await {
            Ok(result) if result.rows_affected() == 0 => errors::not_found("Not found"),
            Ok(_) => HttpResponse::Ok().finish(),
            Err(error) => errors::internal_error(error.to_string()),
        };
    }

    match build_row_policy_plan(
        &resource,
        state.dynamic_service.as_ref(),
        resource
            .policies
            .delete
            .as_ref()
            .expect("delete policy checked"),
        &user,
    )
    .map_err(|error| errors::internal_error(error.to_string()))
    {
        Ok(PlanOutcome::Resolved(plan)) => {
            let sql = format!(
                "DELETE FROM {} WHERE {} = {} AND {}",
                resource.table_name,
                resource.id_field,
                placeholder(resource.db, 1),
                render_condition_with_placeholders(plan.condition.as_str(), resource.db, 2),
            );
            let mut delete_query = query(&sql).bind(id);
            for bind in &plan.binds {
                delete_query = bind_query(delete_query, bind);
            }
            match delete_query.execute(&state.pool).await {
                Ok(result) if result.rows_affected() == 0 => {
                    delete_hybrid_fallback(id, &user, &state, &resource).await
                }
                Ok(_) => HttpResponse::Ok().finish(),
                Err(error) => errors::internal_error(error.to_string()),
            }
        }
        Ok(PlanOutcome::Indeterminate) => {
            delete_hybrid_fallback(id, &user, &state, &resource).await
        }
        Err(response) => response,
    }
}

async fn delete_hybrid_fallback(
    id: i64,
    user: &UserContext,
    state: &NativeServeState,
    resource: &DynamicResource,
) -> HttpResponse {
    match fetch_hybrid_authorized_by_id(resource, state, user, id, AuthorizationAction::Delete)
        .await
    {
        Ok(Some(_)) => {
            let sql = format!(
                "DELETE FROM {} WHERE {} = {}",
                resource.table_name,
                resource.id_field,
                placeholder(resource.db, 1)
            );
            match query(&sql).bind(id).execute(&state.pool).await {
                Ok(result) if result.rows_affected() == 0 => errors::not_found("Not found"),
                Ok(_) => HttpResponse::Ok().finish(),
                Err(error) => errors::internal_error(error.to_string()),
            }
        }
        Ok(None) => errors::not_found("Not found"),
        Err(response) => response,
    }
}

#[cfg(test)]
mod tests {
    use super::{DynamicService, NativeServeState, build_api_scope, build_openapi_json};
    use actix_web::{App, HttpResponse, http::StatusCode, test, web};
    use rest_macro_core::authorization::AuthorizationRuntime;
    use rest_macro_core::compiler;
    use rest_macro_core::database::{
        prepare_database_engine, resolve_database_config, service_base_dir_from_config_path,
    };
    use rest_macro_core::db::{DbPool, query};
    use rest_macro_core::static_files::configure_static_mounts_with_runtime;
    use serde_json::{Value, json};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_TURSO_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn unique_sqlite_url(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("vsr_native_{prefix}_{nanos}.db"));
        format!("sqlite:{}?mode=rwc", path.display())
    }

    fn unique_sqlite_path(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        std::env::temp_dir().join(format!("vsr_native_{prefix}_{nanos}.db"))
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    async fn build_test_state(
        fixture_name: &str,
        include_builtin_auth: bool,
    ) -> (Arc<DynamicService>, NativeServeState) {
        let input = fixture_path(fixture_name);
        let mut service =
            compiler::load_service_from_path(&input).expect("fixture service should load");
        let isolated_db_path = unique_sqlite_path(fixture_name.trim_end_matches(".eon"));
        if let rest_macro_core::database::DatabaseEngine::TursoLocal(engine) =
            &mut service.database.engine
        {
            engine.path = isolated_db_path.display().to_string();
        }
        let base_dir = service_base_dir_from_config_path(&input);
        let database_config = resolve_database_config(&service.database, &base_dir);

        prepare_database_engine(&database_config)
            .await
            .expect("database engine should prepare");

        let database_url = if matches!(
            database_config.engine,
            rest_macro_core::database::DatabaseEngine::TursoLocal(_)
        ) {
            format!("sqlite:{}?mode=rwc", isolated_db_path.display())
        } else {
            unique_sqlite_url(fixture_name.trim_end_matches(".eon"))
        };
        let pool = DbPool::connect_with_config(&database_url, &database_config)
            .await
            .expect("fixture database should connect");
        let migration_sql =
            compiler::render_service_migration_sql(&service).expect("migration should render");
        pool.execute_batch(&migration_sql)
            .await
            .expect("migration should apply");

        let openapi_json =
            build_openapi_json(&service, include_builtin_auth).expect("openapi should render");
        let authorization_model = compiler::compile_service_authorization(&service);
        let dynamic_service = Arc::new(
            DynamicService::from_spec(service, openapi_json, include_builtin_auth)
                .expect("dynamic service should build"),
        );
        let state = NativeServeState {
            pool: pool.clone(),
            authorization_runtime: AuthorizationRuntime::new(authorization_model, pool.clone()),
            dynamic_service: dynamic_service.clone(),
        };
        (dynamic_service, state)
    }

    async fn seed_public_catalog(pool: &DbPool) {
        query(
            "INSERT INTO organization (name, country, website_url, summary) VALUES
                ('Nordic Bridge Institute', 'Finland', 'https://nordic.example', 'Cross-border education and industry matching'),
                ('Baltic Industry Lab', 'Estonia', 'https://baltic.example', 'Applied industrial collaboration partner')",
        )
        .execute(pool)
        .await
        .expect("organization seed data should insert");
        query(
            "INSERT INTO interest (title, summary, organization_id) VALUES
                ('AI Thesis Co-Creation', 'Seeking thesis topics on trustworthy AI and shared supervision', 1),
                ('Mobility Pilot Ideas', 'Open to data-sharing pilots across campuses and ports', 1),
                ('Green Manufacturing Topics', 'Looking for thesis work on industrial decarbonization', 2)",
        )
        .execute(pool)
        .await
        .expect("interest seed data should insert");
    }

    #[actix_web::test]
    async fn native_serve_public_catalog_matches_generated_read_surface() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        }
        let (dynamic_service, state) = build_test_state("public_catalog_api.eon", false).await;
        seed_public_catalog(&state.pool).await;

        let app = test::init_service(
            App::new().service(build_api_scope(dynamic_service.clone(), state.clone())),
        )
        .await;

        let list_request = test::TestRequest::get()
            .uri("/api/organization")
            .to_request();
        let list_response = test::call_service(&app, list_request).await;
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body: Value = test::read_body_json(list_response).await;
        assert_eq!(list_body["total"], 2);
        assert_eq!(list_body["items"][0]["name"], "Nordic Bridge Institute");

        let contains_request = test::TestRequest::get()
            .uri("/api/organization?filter_name_contains=BRIDGE")
            .to_request();
        let contains_response = test::call_service(&app, contains_request).await;
        let contains_status = contains_response.status();
        let contains_body_bytes = test::read_body(contains_response).await;
        assert_eq!(
            contains_status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(contains_body_bytes.as_ref())
        );
        let contains_body: Value = serde_json::from_slice(contains_body_bytes.as_ref())
            .expect("contains body should decode");
        assert_eq!(contains_body["total"], 1);
        assert_eq!(contains_body["items"][0]["country"], "Finland");

        let escaped_percent_request = test::TestRequest::get()
            .uri("/api/organization?filter_name_contains=%25")
            .to_request();
        let escaped_percent_response = test::call_service(&app, escaped_percent_request).await;
        assert_eq!(escaped_percent_response.status(), StatusCode::OK);
        let escaped_percent_body: Value = test::read_body_json(escaped_percent_response).await;
        assert_eq!(escaped_percent_body["total"], 0);

        let get_request = test::TestRequest::get()
            .uri("/api/organization/1")
            .to_request();
        let get_response = test::call_service(&app, get_request).await;
        assert_eq!(get_response.status(), StatusCode::OK);
        let get_body: Value = test::read_body_json(get_response).await;
        assert_eq!(get_body["name"], "Nordic Bridge Institute");

        let nested_request = test::TestRequest::get()
            .uri("/api/organization/1/interest?filter_summary_contains=THESIS")
            .to_request();
        let nested_response = test::call_service(&app, nested_request).await;
        assert_eq!(nested_response.status(), StatusCode::OK);
        let nested_body: Value = test::read_body_json(nested_response).await;
        assert_eq!(nested_body["total"], 1);
        assert_eq!(nested_body["items"][0]["title"], "AI Thesis Co-Creation");

        let create_request = test::TestRequest::post()
            .uri("/api/organization")
            .set_json(json!({
                "name": "Unauthorized Org",
                "country": "Sweden",
                "website_url": "https://unauthorized.example",
                "summary": "Should not be created anonymously"
            }))
            .to_request();
        let create_response = test::call_service(&app, create_request).await;
        assert_eq!(create_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn native_serve_auto_mounts_authorization_management_routes() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        }
        let (dynamic_service, state) = build_test_state("authz_management_api.eon", false).await;

        let app = test::init_service(
            App::new().service(build_api_scope(dynamic_service.clone(), state.clone())),
        )
        .await;

        let request = test::TestRequest::get()
            .uri("/api/authz/runtime/assignments?user_id=1")
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn native_serve_preserves_docs_openapi_and_static_mounts() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        }
        let (dynamic_service, state) = build_test_state("static_site_api.eon", false).await;
        query("INSERT INTO page (id, title) VALUES (1, 'Landing page copy')")
            .execute(&state.pool)
            .await
            .expect("page seed should insert");

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(dynamic_service.clone()))
                .app_data(web::Data::new(state.clone()))
                .route(
                    "/openapi.json",
                    web::get().to({
                        let openapi_json = dynamic_service.openapi_json.clone();
                        move || {
                            let openapi_json = openapi_json.clone();
                            async move {
                                HttpResponse::Ok()
                                    .content_type("application/json")
                                    .body(openapi_json.as_ref().clone())
                            }
                        }
                    }),
                )
                .route(
                    "/docs",
                    web::get().to({
                        let docs_html = dynamic_service.docs_html.clone();
                        move || {
                            let docs_html = docs_html.clone();
                            async move {
                                HttpResponse::Ok()
                                    .content_type("text/html; charset=utf-8")
                                    .body(docs_html.as_ref().clone())
                            }
                        }
                    }),
                )
                .service(build_api_scope(dynamic_service.clone(), state.clone()))
                .configure({
                    let static_mounts = dynamic_service.static_mounts.clone();
                    let runtime = dynamic_service.runtime.clone();
                    move |cfg| {
                        configure_static_mounts_with_runtime(
                            cfg,
                            static_mounts.as_slice(),
                            &runtime,
                        );
                    }
                }),
        )
        .await;

        let root_request = test::TestRequest::get().uri("/").to_request();
        let root_response = test::call_service(&app, root_request).await;
        assert_eq!(root_response.status(), StatusCode::OK);
        assert_eq!(
            root_response
                .headers()
                .get("cache-control")
                .expect("cache header should exist"),
            "no-store"
        );
        let root_body = test::read_body(root_response).await;
        assert!(String::from_utf8_lossy(&root_body).contains("Static Fixture"));

        let spa_request = test::TestRequest::get()
            .uri("/dashboard")
            .insert_header(("Accept", "text/html"))
            .to_request();
        let spa_response = test::call_service(&app, spa_request).await;
        assert_eq!(spa_response.status(), StatusCode::OK);
        let spa_body = test::read_body(spa_response).await;
        assert!(String::from_utf8_lossy(&spa_body).contains("Static Fixture"));

        let asset_request = test::TestRequest::get().uri("/assets/app.js").to_request();
        let asset_response = test::call_service(&app, asset_request).await;
        assert_eq!(asset_response.status(), StatusCode::OK);
        assert_eq!(
            asset_response
                .headers()
                .get("cache-control")
                .expect("asset cache header should exist"),
            "public, max-age=31536000, immutable"
        );
        let asset_body = test::read_body(asset_response).await;
        assert!(String::from_utf8_lossy(&asset_body).contains("static fixture"));

        let docs_request = test::TestRequest::get().uri("/docs").to_request();
        let docs_response = test::call_service(&app, docs_request).await;
        assert_eq!(docs_response.status(), StatusCode::OK);
        let docs_body = test::read_body(docs_response).await;
        assert!(String::from_utf8_lossy(&docs_body).contains("SwaggerUIBundle"));

        let openapi_request = test::TestRequest::get().uri("/openapi.json").to_request();
        let openapi_response = test::call_service(&app, openapi_request).await;
        assert_eq!(openapi_response.status(), StatusCode::OK);
        let openapi_body: Value = test::read_body_json(openapi_response).await;
        assert_eq!(openapi_body["openapi"], "3.0.3");
        assert_eq!(openapi_body["servers"][0]["url"], "/api");
        assert!(openapi_body["paths"].get("/page").is_some());

        let api_request = test::TestRequest::get().uri("/api/page").to_request();
        let api_response = test::call_service(&app, api_request).await;
        assert_eq!(api_response.status(), StatusCode::OK);
        let api_body: Value = test::read_body_json(api_response).await;
        assert_eq!(api_body["total"], 1);
        assert_eq!(api_body["items"][0]["title"], "Landing page copy");
    }
}
