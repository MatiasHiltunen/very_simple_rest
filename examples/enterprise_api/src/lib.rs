//! EON-defined enterprise API example on VSR's framework-neutral HTTP contract.
pub mod auth;
pub mod config;
pub mod contract;
pub mod demo;
mod openapi;
pub mod store;

use auth::Claims;
use config::{Backend, Config};
use contract::{Contract, Resource};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};
use std::{sync::Arc, time::Duration};
use store::{Failure, Result as ApiResult};
use tokio::sync::Semaphore;
use vsr_runtime::http::{
    CorsConfig, Handler, HttpMethod, MiddlewareConfig, RequestContext, ResponseEnvelope,
    ServerConfig, TlsConfig, make_handler,
};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct App {
    pub config: Config,
    pub contract: Contract,
    pool: SqlitePool,
    verifier: auth::Verifier,
    permits: Semaphore,
}

#[derive(Clone, Copy)]
enum Action {
    List,
    Get,
    Create,
    Update,
    Delete,
    Audit,
    Session,
}
impl Action {
    fn name(self) -> &'static str {
        match self {
            Self::List | Self::Get => "read",
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Audit => "audit.read",
            Self::Session => "session.read",
        }
    }
    fn mutates(self) -> bool {
        matches!(self, Self::Create | Self::Update | Self::Delete)
    }
}

impl App {
    pub async fn check_database(&self) -> bool {
        let mut names = vec![
            "_example_schema",
            "_principals",
            "_grants",
            "_revoked_tokens",
            "_versions",
            "_record_ids",
            "_audit",
        ];
        names.extend(
            self.contract
                .resources
                .iter()
                .map(|resource| resource.table.as_str()),
        );
        let expected = names.len() as i64;
        let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN (",
        );
        let mut fields = query.separated(",");
        for name in names {
            fields.push_bind(name.to_owned());
        }
        fields.push_unseparated(")");
        query
            .build_query_scalar::<i64>()
            .fetch_one(&self.pool)
            .await
            .is_ok_and(|count| count == expected)
    }

    pub async fn open(config: Config) -> Result<Arc<Self>, Error> {
        config.validate()?;
        let contract: Contract =
            serde_json::from_str(include_str!(concat!(env!("OUT_DIR"), "/contract.json")))?;
        let verifier = auth::Verifier::new(&config, &contract)?;
        let pool = store::connect(&config.database).await?;
        Ok(Arc::new(Self {
            permits: Semaphore::new(config.max_in_flight),
            config,
            contract,
            pool,
            verifier,
        }))
    }

    pub fn server_config(&self) -> ServerConfig {
        ServerConfig {
            addr: self.config.listen,
            workers: if self.config.backend == Backend::Actix {
                Some(2)
            } else {
                None
            },
            max_body_bytes: self.contract.max_body_bytes,
            shutdown_timeout: Duration::from_secs(self.config.shutdown_timeout_seconds),
            tls: self.config.tls.as_ref().map(|tls| TlsConfig {
                cert_path: tls.cert_file.clone(),
                key_path: tls.key_file.clone(),
            }),
            ..ServerConfig::default()
        }
    }

    pub fn middleware(&self) -> MiddlewareConfig {
        MiddlewareConfig {
            cors: Some(CorsConfig {
                allowed_origins: Some(self.config.allowed_origins.clone()),
                allowed_headers: vec![
                    "authorization".into(),
                    "content-type".into(),
                    "if-match".into(),
                ],
                allow_credentials: false,
                ..CorsConfig::default()
            }),
            ..MiddlewareConfig::default()
        }
    }

    pub fn routes(self: &Arc<Self>) -> Vec<(HttpMethod, String, Handler)> {
        let mut routes = Vec::new();
        for resource in &self.contract.resources {
            let collection = format!("/api/v1/{}", resource.table);
            let item = format!("{collection}/{{id}}");
            for (method, path, action) in [
                (HttpMethod::Get, collection.clone(), Action::List),
                (HttpMethod::Post, collection, Action::Create),
                (HttpMethod::Get, item.clone(), Action::Get),
                (HttpMethod::Patch, item.clone(), Action::Update),
                (HttpMethod::Delete, item, Action::Delete),
            ] {
                let app = self.clone();
                let resource = resource.clone();
                routes.push((
                    method,
                    path,
                    make_handler(move |ctx| {
                        let app = app.clone();
                        let resource = resource.clone();
                        async move { app.handle(ctx, Some(&resource), action).await }
                    }),
                ));
            }
        }
        for (path, action) in [
            ("/api/v1/audit", Action::Audit),
            ("/api/v1/session", Action::Session),
        ] {
            let app = self.clone();
            routes.push((
                HttpMethod::Get,
                path.into(),
                make_handler(move |ctx| {
                    let app = app.clone();
                    async move { app.handle(ctx, None, action).await }
                }),
            ));
        }
        let spec = self.openapi();
        routes.push((
            HttpMethod::Get,
            "/openapi.json".into(),
            make_handler(move |_| {
                let spec = spec.clone();
                async move { ResponseEnvelope::json(spec) }
            }),
        ));
        routes
    }

    async fn handle(
        &self,
        ctx: RequestContext,
        resource: Option<&Resource>,
        action: Action,
    ) -> ResponseEnvelope {
        let result = match self.permits.try_acquire() {
            Err(_) => Err(Failure(503, "Request capacity exhausted")),
            Ok(_permit) => tokio::time::timeout(
                Duration::from_secs(self.config.request_timeout_seconds),
                self.protected(&ctx, resource, action),
            )
            .await
            .unwrap_or(Err(Failure(503, "Request deadline exceeded"))),
        };
        let mut response = result
            .unwrap_or_else(|Failure(status, message)| ResponseEnvelope::error(status, message));
        let _ = response.headers.append("cache-control", "no-store");
        let _ = response.headers.append("x-request-id", &ctx.request_id);
        // Explicitly exposed only to configured origins; no ambient-cookie auth.
        let _ = response
            .headers
            .append("access-control-expose-headers", "etag, x-request-id");
        if response.status == 401 {
            let _ = response.headers.append("www-authenticate", "Bearer");
        }
        if response.status == 503 {
            let _ = response.headers.append("retry-after", "1");
        }
        response
    }

    async fn protected(
        &self,
        ctx: &RequestContext,
        resource: Option<&Resource>,
        action: Action,
    ) -> ApiResult<ResponseEnvelope> {
        let claims = self.verifier.verify(ctx);
        let result = match &claims {
            None => Err(Failure(401, "Unauthorized")),
            Some(claims) => self.execute(ctx, resource, action, claims).await,
        };
        if let Err(Failure(status, _)) = &result {
            let mut tx = self.pool.begin().await?;
            store::audit(
                &mut tx,
                claims.as_ref(),
                resource.map_or("system", |r| r.table.as_str()),
                action.name(),
                None,
                *status,
                &ctx.request_id,
            )
            .await?;
            tx.commit().await?;
        }
        result
    }

    async fn execute(
        &self,
        ctx: &RequestContext,
        resource: Option<&Resource>,
        action: Action,
        claims: &Claims,
    ) -> ApiResult<ResponseEnvelope> {
        // Writers lock before checking grants/rows: revocation, ownership checks,
        // optimistic concurrency and audit commit are one serialized transaction.
        let mut tx = if action.mutates() {
            self.pool.begin_with("BEGIN IMMEDIATE").await?
        } else {
            self.pool.begin().await?
        };
        if matches!(action, Action::Session) {
            let roles: Vec<String> = sqlx::query_scalar("SELECT role FROM _grants WHERE user_id=? AND tenant_id=? AND expires_at>? ORDER BY role")
                .bind(claims.user_id()).bind(claims.tenant_id).bind(auth::now()).fetch_all(&mut *tx).await?;
            let role = roles.first().ok_or(Failure(403, "Forbidden"))?;
            store::authorize(&mut tx, claims, role).await?;
            tx.commit().await?;
            return Ok(ResponseEnvelope::json(
                json!({"user_id": claims.user_id(), "tenant_id": claims.tenant_id, "roles": roles}),
            ));
        }
        if matches!(action, Action::Audit) {
            store::authorize(&mut tx, claims, "auditor").await?;
            let (after, limit) = self.page(ctx)?;
            let rows = sqlx::query("SELECT id,at,user_id,resource,action,record_id,status,request_id FROM _audit WHERE tenant_id=? AND id>? ORDER BY id LIMIT ?")
                .bind(claims.tenant_id).bind(after).bind(i64::from(limit)).fetch_all(&mut *tx).await?;
            let data = rows.iter().map(|row| Ok(json!({
                "id": row.try_get::<i64,_>("id")?, "at": row.try_get::<i64,_>("at")?, "user_id": row.try_get::<Option<i64>,_>("user_id")?,
                "resource": row.try_get::<String,_>("resource")?, "action": row.try_get::<String,_>("action")?, "record_id": row.try_get::<Option<i64>,_>("record_id")?,
                "status": row.try_get::<i64,_>("status")?, "request_id": row.try_get::<String,_>("request_id")?
            }))).collect::<Result<Vec<_>, sqlx::Error>>()?;
            tx.commit().await?;
            return Ok(ResponseEnvelope::json(json!({"data": data})));
        }
        let resource = resource.ok_or(Failure(404, "Not found"))?;
        let rule = match action {
            Action::List | Action::Get => &resource.read,
            Action::Create => &resource.create,
            Action::Update => &resource.update,
            Action::Delete => &resource.delete,
            _ => return Err(Failure(404, "Not found")),
        };
        store::authorize(&mut tx, claims, &rule.role).await?;
        if matches!(action, Action::List) {
            let (after, limit) = self.page(ctx)?;
            let data = store::list(&mut tx, resource, claims, after, limit).await?;
            tx.commit().await?;
            return Ok(ResponseEnvelope::json(data));
        }
        if !ctx.query_params.is_empty() {
            return Err(Failure(400, "Unexpected query parameters"));
        }
        let (id, mut version) = if matches!(action, Action::Create) {
            (0, 0)
        } else {
            let id = ctx
                .path_params
                .get("id")
                .and_then(|s| s.parse::<i64>().ok())
                .filter(|id| *id > 0)
                .ok_or(Failure(400, "Invalid resource ID"))?;
            let (_, version) = store::get(&mut tx, resource, rule, claims, id).await?;
            if matches!(action, Action::Update | Action::Delete) {
                let mut headers = ctx.headers.get_all("if-match");
                let expected = headers.next().ok_or(Failure(428, "If-Match required"))?;
                if headers.next().is_some() || expected != etag(resource, id, version).as_bytes() {
                    return Err(Failure(412, "Version precondition failed"));
                }
            }
            (id, version)
        };
        let mut status = 200;
        let id = if matches!(action, Action::Create | Action::Update) {
            let types: Vec<_> = ctx.headers.get_all("content-type").collect();
            if types.len() != 1
                || std::str::from_utf8(types[0])
                    .ok()
                    .and_then(|s| s.split(';').next())
                    .is_none_or(|s| !s.trim().eq_ignore_ascii_case("application/json"))
            {
                return Err(Failure(415, "application/json required"));
            }
            let values = store::payload(
                resource,
                ctx.body.as_deref(),
                self.config.max_string_chars,
                matches!(action, Action::Create),
            )?;
            store::references(&mut tx, resource, &self.contract.resources, &values, claims).await?;
            if matches!(action, Action::Create) {
                status = 201;
                version = 1;
                store::create(&mut tx, resource, values, claims).await?
            } else {
                store::update(&mut tx, resource, id, &values).await?;
                version += 1;
                id
            }
        } else {
            id
        };
        let mut response = if matches!(action, Action::Delete) {
            store::delete(&mut tx, resource, &self.contract.resources, id).await?;
            status = 204;
            ResponseEnvelope::status(status)
        } else {
            // The operation's policy, not a weaker unscoped fetch, controls the response.
            let fetch_rule = if matches!(action, Action::Create) {
                &resource.read
            } else {
                rule
            };
            let (data, _) = store::get(&mut tx, resource, fetch_rule, claims, id).await?;
            let mut response = ResponseEnvelope::json(data);
            response.status = status;
            let _ = response.headers.append("etag", etag(resource, id, version));
            if status == 201 {
                let _ = response
                    .headers
                    .append("location", format!("/api/v1/{}/{id}", resource.table));
            }
            response
        };
        if action.mutates() {
            store::audit(
                &mut tx,
                Some(claims),
                &resource.table,
                action.name(),
                Some(id),
                status,
                &ctx.request_id,
            )
            .await?;
        }
        tx.commit().await?;
        response.status = status;
        Ok(response)
    }

    fn page(&self, ctx: &RequestContext) -> ApiResult<(i64, u32)> {
        if ctx
            .query_params
            .iter()
            .any(|(key, values)| !matches!(key.as_str(), "after" | "limit") || values.len() != 1)
        {
            return Err(Failure(400, "Unsupported or repeated query parameter"));
        }
        let after = ctx
            .query_params
            .get("after")
            .map(|v| v[0].parse::<i64>())
            .transpose()
            .map_err(|_| Failure(400, "Invalid cursor"))?
            .unwrap_or(0);
        let limit = ctx
            .query_params
            .get("limit")
            .map(|v| v[0].parse::<u32>())
            .transpose()
            .map_err(|_| Failure(400, "Invalid limit"))?
            .unwrap_or(self.config.max_page_size.min(25));
        if after < 0 || limit == 0 || limit > self.config.max_page_size {
            return Err(Failure(400, "Invalid page bounds"));
        }
        Ok((after, limit))
    }

    pub fn openapi(&self) -> Value {
        openapi::document(&self.contract, &self.config)
    }
}

fn etag(resource: &Resource, id: i64, version: i64) -> String {
    format!("\"{}:{id}:{version}\"", resource.table)
}
