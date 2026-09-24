//! Temporary native Actix bridge for the first framework-neutral CRUD slice.

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, web};
use rest_macro_core::{
    auth,
    compiler::{DbBackend, GeneratedValue},
    db::{DbPool, query, query_scalar},
};
use sqlx::Row;
use vsr_runtime::{
    http::{ResponseEnvelope, RouteTable, actix_adapter},
    resource::{
        TextCrudConfig, TextCrudRoles, TextCrudService, TextCrudStore, TextPage, TextPageRequest,
        TextRecord, TextStoreError,
    },
};

use super::{DynamicResource, FieldKind};

/// Only a deliberately small, policy-free schema is eligible. Other resources
/// keep the existing native path until their behavior is migrated.
pub(super) fn config_for(resource: &DynamicResource) -> Option<TextCrudConfig> {
    if resource.db != DbBackend::Sqlite
        || !resource.read_requires_auth
        || resource.fields.len() != 2
        || resource.policies.read.is_some()
        || resource.policies.create_require.is_some()
        || !resource.policies.create.is_empty()
        || resource.policies.update.is_some()
        || resource.policies.delete.is_some()
        || resource.audit.is_some()
        || resource.is_audit_sink
        || resource.hybrid.is_some()
        || !resource.actions.is_empty()
        || !resource.nested_relations.is_empty()
        || !resource.many_to_many_routes.is_empty()
        || !resource.computed_fields.is_empty()
        || !resource.response_contexts.is_empty()
        || resource.default_response_context.is_some()
        || resource.default_limit.is_some()
        || resource.max_limit.is_some()
        || !resource.filterable_in.is_empty()
        || !resource.count_endpoint
        || !safe_identifier(&resource.table_name)
        || !safe_identifier(&resource.api_name)
        || !safe_identifier(&resource.id_field)
    {
        return None;
    }
    let id = resource
        .fields
        .iter()
        .find(|field| field.name == resource.id_field)?;
    let value = resource
        .fields
        .iter()
        .find(|field| field.name != resource.id_field)?;
    if id.kind != FieldKind::Integer
        || !id.expose_in_api
        || !safe_identifier(&id.api_name)
        || !value.expose_in_api
        || value.kind != FieldKind::Text
        || value.optional
        || value.generated != GeneratedValue::None
        || !value.validation.is_empty()
        || !value.transforms.is_empty()
        || value.enum_values.is_some()
        || !safe_identifier(&value.name)
        || !safe_identifier(&value.api_name)
        || resource.create_fields.len() != 1
        || resource.create_fields[0].name != value.name
        || resource.update_field_names != [value.name.clone()]
    {
        return None;
    }
    let roles = TextCrudRoles {
        read: resource.roles.read.clone()?,
        create: resource.roles.create.clone()?,
        update: resource.roles.update.clone()?,
        delete: resource.roles.delete.clone()?,
    };
    if [&roles.read, &roles.create, &roles.update, &roles.delete]
        .iter()
        .any(|role| role.is_empty())
    {
        return None;
    }
    Some(TextCrudConfig {
        collection_path: format!("/api/{}", resource.api_name),
        id_field: id.api_name.clone(),
        value_field: value.api_name.clone(),
        roles,
    })
}

pub(super) fn register(
    cfg: &mut web::ServiceConfig,
    resource: &DynamicResource,
    pool: DbPool,
    auth_settings: auth::AuthSettings,
    include_builtin_auth: bool,
    json_max_bytes: Option<usize>,
) {
    let config = config_for(resource).expect("neutral CRUD resource was validated at startup");
    let service = Arc::new(
        TextCrudService::new(
            config,
            Arc::new(SqliteTextStore {
                pool: pool.clone(),
                table: resource.table_name.clone(),
                id_field: resource.id_field.clone(),
                value_field: resource
                    .fields
                    .iter()
                    .find(|field| field.name != resource.id_field)
                    .expect("validated text field")
                    .name
                    .clone(),
            }),
        )
        .expect("neutral CRUD configuration was validated at startup"),
    );
    let authenticator = Arc::new(auth::request_authenticator(
        Some(pool),
        auth_settings,
        include_builtin_auth,
    ));
    let routes = RouteTable::from_routes(service.routes(authenticator))
        .expect("neutral CRUD routes were validated at startup");
    cfg.app_data(web::Data::new(routes));
    let collection_path = format!("/{}", resource.api_name);
    let count_path = format!("{collection_path}/count");
    let item_path = format!("{collection_path}/{{id}}");
    let body_limit = json_max_bytes.unwrap_or(2 * 1024 * 1024);
    cfg.service(
        web::resource(collection_path)
            .app_data(web::PayloadConfig::new(body_limit))
            .route(web::to(dispatch)),
    );
    cfg.service(
        web::resource(count_path)
            .app_data(web::PayloadConfig::new(body_limit))
            .route(web::to(dispatch)),
    );
    cfg.service(
        web::resource(item_path)
            .app_data(web::PayloadConfig::new(body_limit))
            .route(web::to(dispatch)),
    );
}

async fn dispatch(
    request: HttpRequest,
    body: Result<web::Bytes, actix_web::Error>,
    routes: web::Data<RouteTable>,
) -> HttpResponse {
    let body = match body {
        Ok(body) => body,
        Err(error) => {
            return actix_adapter::envelope_to_response(ResponseEnvelope::error(
                error.as_response_error().status_code().as_u16(),
                "Invalid request body",
            ));
        }
    };
    let response = match actix_adapter::request_context_from_actix(&request, body) {
        Ok(context) => routes.dispatch(context).await,
        Err(response) => response,
    };
    actix_adapter::envelope_to_response(response)
}

fn safe_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn db_error(error: sqlx::Error) -> TextStoreError {
    log::error!("neutral CRUD storage operation failed: {error}");
    TextStoreError
}

struct SqliteTextStore {
    pool: DbPool,
    table: String,
    id_field: String,
    value_field: String,
}

impl SqliteTextStore {
    fn row(&self, row: &sqlx::any::AnyRow) -> Result<TextRecord, TextStoreError> {
        Ok(TextRecord {
            id: row.try_get(self.id_field.as_str()).map_err(db_error)?,
            value: row.try_get(self.value_field.as_str()).map_err(db_error)?,
        })
    }
}

impl TextCrudStore for SqliteTextStore {
    async fn list(&self, page: TextPageRequest) -> Result<TextPage, TextStoreError> {
        let total = self.count().await?;
        let sql = format!(
            "SELECT {}, {} FROM {} ORDER BY {} ASC LIMIT ? OFFSET ?",
            self.id_field, self.value_field, self.table, self.id_field
        );
        let rows = query(&sql)
            .bind(page.limit.map_or(-1, i64::from))
            .bind(i64::from(page.offset))
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(TextPage {
            rows: rows
                .iter()
                .map(|row| self.row(row))
                .collect::<Result<Vec<_>, _>>()?,
            total,
        })
    }

    async fn count(&self) -> Result<i64, TextStoreError> {
        let sql = format!("SELECT COUNT(*) FROM {}", self.table);
        query_scalar::<sqlx::Any, i64>(&sql)
            .fetch_one(&self.pool)
            .await
            .map_err(db_error)
    }

    async fn get(&self, id: i64) -> Result<Option<TextRecord>, TextStoreError> {
        let sql = format!(
            "SELECT {}, {} FROM {} WHERE {} = ?",
            self.id_field, self.value_field, self.table, self.id_field
        );
        query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?
            .as_ref()
            .map(|row| self.row(row))
            .transpose()
    }

    async fn create(&self, value: String) -> Result<TextRecord, TextStoreError> {
        let sql = format!(
            "INSERT INTO {} ({}) VALUES (?) RETURNING {}, {}",
            self.table, self.value_field, self.id_field, self.value_field
        );
        let row = query(&sql)
            .bind(value)
            .fetch_one(&self.pool)
            .await
            .map_err(db_error)?;
        self.row(&row)
    }

    async fn update(&self, id: i64, value: String) -> Result<Option<TextRecord>, TextStoreError> {
        let sql = format!(
            "UPDATE {} SET {} = ? WHERE {} = ? RETURNING {}, {}",
            self.table, self.value_field, self.id_field, self.id_field, self.value_field
        );
        query(&sql)
            .bind(value)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?
            .as_ref()
            .map(|row| self.row(row))
            .transpose()
    }

    async fn delete(&self, id: i64) -> Result<bool, TextStoreError> {
        let sql = format!("DELETE FROM {} WHERE {} = ?", self.table, self.id_field);
        query(&sql)
            .bind(id)
            .execute(&self.pool)
            .await
            .map(|result| result.rows_affected() > 0)
            .map_err(db_error)
    }
}
