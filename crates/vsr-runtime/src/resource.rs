//! A small framework-neutral CRUD service used to migrate native resources one
//! shape at a time. This first slice supports an integer ID and one text field.

use std::{future::Future, sync::Arc};

use serde_json::{Map, Value, json};

use crate::{
    auth::{
        AuthenticatedIdentity,
        request::{AuthFailure, RequestAuthenticator, require_authentication},
    },
    http::{Handler, HttpMethod, RequestContext, ResponseEnvelope, make_handler},
};

/// One persisted row in the first native CRUD slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextRecord {
    /// Database primary key.
    pub id: i64,
    /// Value of the configured text field.
    pub value: String,
}

/// Pagination accepted by the text-resource repository.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TextPageRequest {
    /// Maximum number of rows; absent means no limit.
    pub limit: Option<u32>,
    /// Number of rows skipped before the page.
    pub offset: u32,
}

/// Rows and total count for a collection request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextPage {
    /// Rows in the requested page, ordered by ID.
    pub rows: Vec<TextRecord>,
    /// Count before pagination.
    pub total: i64,
}

/// Repository failure. Details are kept out of HTTP responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextStoreError;

/// Persistence boundary for a text resource. Implementations own SQL and
/// transaction details; the service owns request validation and HTTP behavior.
pub trait TextCrudStore: Send + Sync + 'static {
    /// Fetch a page ordered by primary key.
    fn list(
        &self,
        page: TextPageRequest,
    ) -> impl Future<Output = Result<TextPage, TextStoreError>> + Send;
    /// Count all rows.
    fn count(&self) -> impl Future<Output = Result<i64, TextStoreError>> + Send;
    /// Fetch one row.
    fn get(
        &self,
        id: i64,
    ) -> impl Future<Output = Result<Option<TextRecord>, TextStoreError>> + Send;
    /// Insert a row.
    fn create(
        &self,
        value: String,
    ) -> impl Future<Output = Result<TextRecord, TextStoreError>> + Send;
    /// Replace the text value if the row exists.
    fn update(
        &self,
        id: i64,
        value: String,
    ) -> impl Future<Output = Result<Option<TextRecord>, TextStoreError>> + Send;
    /// Delete a row, reporting whether it existed.
    fn delete(&self, id: i64) -> impl Future<Output = Result<bool, TextStoreError>> + Send;
}

/// Required role for each operation. Admin identities can perform every action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextCrudRoles {
    /// Role required for list, count and get.
    pub read: String,
    /// Role required for create.
    pub create: String,
    /// Role required for update.
    pub update: String,
    /// Role required for delete.
    pub delete: String,
}

/// Lowered, framework-free description of a single text resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextCrudConfig {
    /// Collection route, including its API prefix.
    pub collection_path: String,
    /// Public name of the integer ID field.
    pub id_field: String,
    /// Public name of the text field.
    pub value_field: String,
    /// Optional length rule for the text field.
    pub value_length: Option<TextLengthValidation>,
    /// Operation roles.
    pub roles: TextCrudRoles,
}

/// How to measure a text field's length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextLengthMode {
    /// UTF-8 bytes, matching EON's default and Simple modes.
    Bytes,
    /// Unicode scalar values.
    Chars,
    /// Extended grapheme clusters.
    Graphemes,
    /// UTF-16 code units.
    Utf16,
}

/// Compiler-lowered text length limits, shared by both HTTP adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextLengthValidation {
    /// Inclusive minimum length.
    pub min: Option<usize>,
    /// Inclusive maximum length.
    pub max: Option<usize>,
    /// Exact required length.
    pub equal: Option<usize>,
    /// Unit used for all three limits.
    pub mode: TextLengthMode,
}

/// CRUD operation selected by a route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextCrudAction {
    /// List a collection.
    List,
    /// Count a collection.
    Count,
    /// Fetch an item.
    Get,
    /// Create an item.
    Create,
    /// Replace an item's text field.
    Update,
    /// Delete an item.
    Delete,
}

impl TextCrudAction {
    fn required_role(self, roles: &TextCrudRoles) -> &str {
        match self {
            Self::List | Self::Count | Self::Get => &roles.read,
            Self::Create => &roles.create,
            Self::Update => &roles.update,
            Self::Delete => &roles.delete,
        }
    }
}

/// Shared request and response behavior for a single text resource.
pub struct TextCrudService<S: TextCrudStore> {
    config: TextCrudConfig,
    store: Arc<S>,
}

impl<S: TextCrudStore> TextCrudService<S> {
    /// Validate and construct a service from compiler-lowered names.
    pub fn new(config: TextCrudConfig, store: Arc<S>) -> Result<Self, &'static str> {
        if !config.collection_path.starts_with('/')
            || config.collection_path.ends_with('/')
            || !valid_field_name(&config.id_field)
            || !valid_field_name(&config.value_field)
            || config.id_field == config.value_field
            || [
                &config.roles.read,
                &config.roles.create,
                &config.roles.update,
                &config.roles.delete,
            ]
            .iter()
            .any(|role| role.is_empty())
            || config.value_length.as_ref().is_some_and(|length| {
                length
                    .min
                    .zip(length.max)
                    .is_some_and(|(min, max)| min > max)
                    || length.equal.is_some_and(|equal| {
                        length.min.is_some_and(|min| equal < min)
                            || length.max.is_some_and(|max| equal > max)
                    })
            })
        {
            return Err("invalid text CRUD resource configuration");
        }
        Ok(Self { config, store })
    }

    /// Build the same protected routes for either HTTP adapter.
    pub fn routes<A: RequestAuthenticator>(
        self: &Arc<Self>,
        authenticator: Arc<A>,
    ) -> Vec<(HttpMethod, String, Handler)> {
        let collection = self.config.collection_path.clone();
        let item = format!("{collection}/{{id}}");
        let count = format!("{collection}/count");
        [
            (HttpMethod::Get, collection.clone(), TextCrudAction::List),
            (HttpMethod::Get, count, TextCrudAction::Count),
            (HttpMethod::Post, collection, TextCrudAction::Create),
            (HttpMethod::Get, item.clone(), TextCrudAction::Get),
            (HttpMethod::Put, item.clone(), TextCrudAction::Update),
            (HttpMethod::Delete, item, TextCrudAction::Delete),
        ]
        .into_iter()
        .map(|(method, path, action)| {
            let service = self.clone();
            let handler = make_handler(move |context| {
                let service = service.clone();
                async move { service.handle_context(action, context).await }
            });
            (
                method,
                path,
                require_authentication(authenticator.clone(), handler),
            )
        })
        .collect()
    }

    async fn handle_context(
        &self,
        action: TextCrudAction,
        context: RequestContext,
    ) -> ResponseEnvelope {
        if matches!(action, TextCrudAction::Create | TextCrudAction::Update)
            && !is_json_content_type(&context.headers)
        {
            return response_error(
                415,
                "invalid_content_type",
                "Expected Content-Type: application/json",
            );
        }
        let id = match context.path_params.get("id") {
            Some(raw) => match raw.parse::<i64>() {
                Ok(id) => Some(id),
                Err(_) => return response_error(400, "invalid_id", "Invalid resource ID"),
            },
            None => None,
        };
        let body = match context.body {
            Some(bytes) if !bytes.is_empty() => match serde_json::from_slice(&bytes) {
                Ok(value) => Some(value),
                Err(_) => return response_error(400, "invalid_json", "Invalid JSON body"),
            },
            _ => None,
        };
        self.execute(
            action,
            id,
            context.identity.as_ref(),
            body,
            &context.raw_query,
            &context.path,
        )
        .await
    }

    /// Run an operation from a native transport after that transport has
    /// authenticated the request and supplied its canonical identity.
    pub async fn execute(
        &self,
        action: TextCrudAction,
        id: Option<i64>,
        identity: Option<&AuthenticatedIdentity>,
        body: Option<Value>,
        raw_query: &str,
        request_path: &str,
    ) -> ResponseEnvelope {
        let Some(identity) = identity else {
            return AuthFailure::MissingToken.response();
        };
        let required = action.required_role(&self.config.roles);
        if !identity.is_admin && !identity.roles.iter().any(|role| role == required) {
            return response_error(403, "forbidden", "Insufficient privileges");
        }

        match action {
            TextCrudAction::List => {
                let page = match parse_page(raw_query) {
                    Ok(page) => page,
                    Err(error) => return error.response(),
                };
                match self.store.list(page).await {
                    Ok(result) => {
                        let count = result.rows.len();
                        let end = i64::try_from(count)
                            .ok()
                            .and_then(|count| i64::from(page.offset).checked_add(count));
                        let next_offset =
                            if page.limit.is_some() && end.is_some_and(|end| end < result.total) {
                                u32::try_from(count)
                                    .ok()
                                    .and_then(|count| page.offset.checked_add(count))
                            } else {
                                None
                            };
                        ResponseEnvelope::json(json!({
                            "items": result.rows.iter().map(|row| self.record_json(row)).collect::<Vec<_>>(),
                            "total": result.total,
                            "count": count,
                            "limit": page.limit,
                            "offset": page.offset,
                            "next_offset": next_offset,
                            "next_cursor": null
                        }))
                    }
                    Err(_) => store_error(),
                }
            }
            TextCrudAction::Count => {
                if !raw_query.is_empty() {
                    return response_error(400, "invalid_query", "Unsupported query parameter");
                }
                match self.store.count().await {
                    Ok(count) => ResponseEnvelope::json(json!({"count": count})),
                    Err(_) => store_error(),
                }
            }
            TextCrudAction::Get => {
                let Some(id) = id else {
                    return response_error(400, "invalid_id", "Invalid resource ID");
                };
                match self.store.get(id).await {
                    Ok(Some(row)) => ResponseEnvelope::json(self.record_json(&row)),
                    Ok(None) => response_error(404, "not_found", "Not found"),
                    Err(_) => store_error(),
                }
            }
            TextCrudAction::Create => {
                let value = match self.body_value(body) {
                    Ok(value) => value,
                    Err(error) => return error.response(),
                };
                match self.store.create(value).await {
                    Ok(row) => {
                        let can_read = identity.is_admin
                            || identity
                                .roles
                                .iter()
                                .any(|role| role == &self.config.roles.read);
                        let mut response = if can_read {
                            ResponseEnvelope::json(self.record_json(&row))
                        } else {
                            ResponseEnvelope::status(201)
                        };
                        response.status = 201;
                        let location = format!("{}/{}", request_path.trim_end_matches('/'), row.id);
                        let _ = response.headers.append("location", location.as_bytes());
                        response
                    }
                    Err(_) => store_error(),
                }
            }
            TextCrudAction::Update => {
                let Some(id) = id else {
                    return response_error(400, "invalid_id", "Invalid resource ID");
                };
                let value = match self.body_value(body) {
                    Ok(value) => value,
                    Err(error) => return error.response(),
                };
                match self.store.update(id, value).await {
                    Ok(Some(_)) => ResponseEnvelope::status(200),
                    Ok(None) => response_error(404, "not_found", "Not found"),
                    Err(_) => store_error(),
                }
            }
            TextCrudAction::Delete => {
                let Some(id) = id else {
                    return response_error(400, "invalid_id", "Invalid resource ID");
                };
                match self.store.delete(id).await {
                    Ok(true) => ResponseEnvelope::status(200),
                    Ok(false) => response_error(404, "not_found", "Not found"),
                    Err(_) => store_error(),
                }
            }
        }
    }

    fn body_value(&self, body: Option<Value>) -> Result<String, ClientError> {
        let Some(Value::Object(body)) = body else {
            return Err(ClientError::new("invalid_body", "Expected a JSON object"));
        };
        match body.get(&self.config.value_field) {
            Some(Value::String(value)) => {
                self.validate_length(value)?;
                Ok(value.clone())
            }
            _ => Err(ClientError::new("invalid_field", "Expected a text field")),
        }
    }

    fn validate_length(&self, value: &str) -> Result<(), ClientError> {
        let Some(length) = self.config.value_length.as_ref() else {
            return Ok(());
        };
        let measured = match length.mode {
            TextLengthMode::Bytes => value.len(),
            TextLengthMode::Chars => value.chars().count(),
            TextLengthMode::Graphemes => {
                unicode_segmentation::UnicodeSegmentation::graphemes(value, true).count()
            }
            TextLengthMode::Utf16 => value.encode_utf16().count(),
        };
        let field = &self.config.value_field;
        let message = if let Some(min) = length.min.filter(|min| measured < *min) {
            format!("Field `{field}` must have at least {min} characters")
        } else if let Some(max) = length.max.filter(|max| measured > *max) {
            format!("Field `{field}` must have at most {max} characters")
        } else if let Some(equal) = length.equal.filter(|equal| measured != *equal) {
            format!("Field `{field}` must have exactly {equal} characters")
        } else {
            return Ok(());
        };
        Err(ClientError::validation(field.clone(), message))
    }

    fn record_json(&self, row: &TextRecord) -> Value {
        let mut item = Map::new();
        item.insert(self.config.id_field.clone(), json!(row.id));
        item.insert(self.config.value_field.clone(), json!(row.value));
        Value::Object(item)
    }
}

fn is_json_content_type(headers: &crate::http::HeaderFields) -> bool {
    let Some(value) = headers.get("content-type") else {
        return false;
    };
    let Ok(value) = std::str::from_utf8(value) else {
        return false;
    };
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type == "application/json"
        || media_type.starts_with("application/") && media_type.ends_with("+json")
}

fn valid_field_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Clone)]
struct ClientError {
    code: &'static str,
    message: String,
    field: Option<String>,
}

impl ClientError {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            field: None,
        }
    }

    fn validation(field: String, message: String) -> Self {
        Self {
            code: "validation_error",
            message,
            field: Some(field),
        }
    }

    fn response(self) -> ResponseEnvelope {
        let mut response = ResponseEnvelope::json(match self.field {
            Some(field) => json!({"code": self.code, "message": self.message, "field": field}),
            None => json!({"code": self.code, "message": self.message}),
        });
        response.status = 400;
        response
    }
}

fn parse_page(raw_query: &str) -> Result<TextPageRequest, ClientError> {
    let mut page = TextPageRequest::default();
    let mut seen_limit = false;
    let mut seen_offset = false;
    for (key, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match key.as_ref() {
            "limit" if !seen_limit => {
                page.limit = Some(
                    value
                        .parse::<u32>()
                        .ok()
                        .filter(|limit| *limit > 0)
                        .ok_or_else(|| ClientError::new("invalid_query", "Invalid limit"))?,
                );
                seen_limit = true;
            }
            "offset" if !seen_offset => {
                page.offset = value
                    .parse()
                    .map_err(|_| ClientError::new("invalid_query", "Invalid offset"))?;
                seen_offset = true;
            }
            _ => {
                return Err(ClientError::new(
                    "invalid_query",
                    "Unsupported query parameter",
                ));
            }
        }
    }
    Ok(page)
}

fn response_error(status: u16, code: &str, message: &str) -> ResponseEnvelope {
    let mut response = ResponseEnvelope::json(json!({"code": code, "message": message}));
    response.status = status;
    response
}

fn store_error() -> ResponseEnvelope {
    response_error(500, "internal_error", "Internal server error")
}
