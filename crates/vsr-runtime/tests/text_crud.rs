//! The same protected CRUD service runs on both HTTP transports.
#![cfg(any(feature = "http-actix", feature = "http-axum"))]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::{Value, json};
use vsr_runtime::{
    auth::{
        AuthenticatedIdentity,
        request::{AuthFailure, RequestAuthenticator},
    },
    http::{HeaderFields, HttpServer, MiddlewareConfig, ResponseBody, ServerConfig, ServerHandle},
    resource::{
        TextCrudAction, TextCrudConfig, TextCrudRoles, TextCrudService, TextCrudStore, TextFilters,
        TextLengthMode, TextLengthValidation, TextPage, TextPageRequest, TextRecord,
        TextStoreError,
    },
};

trait Backend: HttpServer {
    fn workers() -> Option<usize>;
}

#[cfg(feature = "http-actix")]
impl Backend for vsr_runtime::http::ActixHttpServer {
    fn workers() -> Option<usize> {
        Some(1)
    }
}

#[cfg(feature = "http-axum")]
impl Backend for vsr_runtime::http::AxumHttpServer {
    fn workers() -> Option<usize> {
        None
    }
}

#[derive(Default)]
struct MemoryStore(Mutex<Vec<TextRecord>>);

impl TextCrudStore for MemoryStore {
    async fn list(
        &self,
        page: TextPageRequest,
        filters: &TextFilters,
    ) -> Result<TextPage, TextStoreError> {
        let rows = self.0.lock().unwrap();
        let mut matching = rows
            .iter()
            .filter(|row| matches_filters(row, filters))
            .cloned()
            .collect::<Vec<_>>();
        let total = matching.len() as i64;
        if page.descending {
            matching.reverse();
        }
        let selected = matching
            .into_iter()
            .filter(|row| {
                page.after_id.is_none_or(|id| {
                    if page.descending {
                        row.id < id
                    } else {
                        row.id > id
                    }
                })
            })
            .skip(page.offset as usize)
            .take(
                page.limit
                    .map_or(usize::MAX, |limit| limit.saturating_add(1) as usize),
            )
            .collect();
        Ok(TextPage {
            rows: selected,
            total,
        })
    }

    async fn count(&self, filters: &TextFilters) -> Result<i64, TextStoreError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|row| matches_filters(row, filters))
            .count() as i64)
    }

    async fn get(&self, id: i64) -> Result<Option<TextRecord>, TextStoreError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|row| row.id == id)
            .cloned())
    }

    async fn create(&self, value: String) -> Result<TextRecord, TextStoreError> {
        let mut rows = self.0.lock().unwrap();
        let row = TextRecord {
            id: rows.last().map_or(1, |row| row.id + 1),
            value,
        };
        rows.push(row.clone());
        Ok(row)
    }

    async fn update(&self, id: i64, value: String) -> Result<Option<TextRecord>, TextStoreError> {
        let mut rows = self.0.lock().unwrap();
        let Some(row) = rows.iter_mut().find(|row| row.id == id) else {
            return Ok(None);
        };
        row.value = value;
        Ok(Some(row.clone()))
    }

    async fn delete(&self, id: i64) -> Result<bool, TextStoreError> {
        let mut rows = self.0.lock().unwrap();
        let before = rows.len();
        rows.retain(|row| row.id != id);
        Ok(rows.len() != before)
    }
}

fn matches_filters(row: &TextRecord, filters: &TextFilters) -> bool {
    filters.id.is_none_or(|id| id == row.id)
        && filters
            .value
            .as_ref()
            .is_none_or(|value| value == &row.value)
        && filters
            .value_contains
            .as_ref()
            .is_none_or(|needle| row.value.to_lowercase().contains(&needle.to_lowercase()))
}

struct TestAuth;

impl RequestAuthenticator for TestAuth {
    async fn authenticate(
        &self,
        _method: &str,
        headers: &HeaderFields,
    ) -> Result<AuthenticatedIdentity, AuthFailure> {
        let roles = match headers.get("authorization") {
            Some(b"Bearer user") => vec!["user".to_owned()],
            Some(b"Bearer reader") => vec!["reader".to_owned()],
            _ => return Err(AuthFailure::MissingToken),
        };
        Ok(AuthenticatedIdentity {
            user_id: "1".into(),
            email: None,
            roles,
            claims: Default::default(),
            is_admin: false,
            expires_at: None,
        })
    }
}

async fn protected_crud<B: Backend>() {
    let service = Arc::new(
        TextCrudService::new(
            TextCrudConfig {
                collection_path: "/api/note".into(),
                id_field: "id".into(),
                value_field: "title".into(),
                value_length: Some(TextLengthValidation {
                    min: Some(3),
                    max: Some(7),
                    equal: None,
                    mode: TextLengthMode::Chars,
                }),
                default_limit: None,
                max_limit: None,
                roles: TextCrudRoles {
                    read: "user".into(),
                    create: "user".into(),
                    update: "user".into(),
                    delete: "user".into(),
                },
            },
            Arc::new(MemoryStore::default()),
        )
        .unwrap(),
    );
    let server = B::serve(
        ServerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            workers: B::workers(),
            ..ServerConfig::default()
        },
        MiddlewareConfig::default(),
        service.routes(Arc::new(TestAuth)),
    )
    .await
    .unwrap();
    let base = format!("http://{}/api/note", server.addresses()[0]);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let denied = client.get(&base).send().await.unwrap();
    assert_eq!(denied.status(), 401);
    let forbidden = client
        .post(&base)
        .bearer_auth("reader")
        .json(&json!({"title": "no"}))
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden.status(), 403);

    let invalid_create = client
        .post(&base)
        .bearer_auth("user")
        .json(&json!({"title": "no"}))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_create.status(), 400);
    assert_eq!(
        invalid_create.json::<Value>().await.unwrap(),
        json!({
            "code": "validation_error",
            "message": "Field `title` must have at least 3 characters",
            "field": "title",
        })
    );

    let created = client
        .post(&base)
        .bearer_auth("user")
        .json(&json!({"title": "first"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    assert_eq!(created.headers()["location"], "/api/note/1");
    assert_eq!(
        created.json::<Value>().await.unwrap(),
        json!({"id": 1, "title": "first"})
    );

    let list = client
        .get(format!("{base}?limit=1&offset=0"))
        .bearer_auth("user")
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let list: Value = list.json().await.unwrap();
    assert_eq!(list["items"], json!([{"id": 1, "title": "first"}]));
    assert_eq!(list["total"], 1);

    let filtered: Value = client
        .get(format!("{base}?filter_title_contains=FIR"))
        .bearer_auth("user")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(filtered["items"], json!([{"id": 1, "title": "first"}]));
    let invalid_cursor = client
        .get(format!("{base}?limit=1&cursor=invalid"))
        .bearer_auth("user")
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_cursor.status(), 400);
    assert_eq!(
        invalid_cursor.json::<Value>().await.unwrap()["code"],
        "invalid_cursor"
    );

    let count: Value = client
        .get(format!("{base}/count"))
        .bearer_auth("user")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(count, json!({"count": 1}));
    let filtered_count = client
        .get(format!("{base}/count?filter_title=first"))
        .bearer_auth("user")
        .send()
        .await
        .unwrap();
    assert_eq!(filtered_count.status(), 200);
    assert_eq!(
        filtered_count.json::<Value>().await.unwrap(),
        json!({"count": 1})
    );

    let invalid_update = client
        .put(format!("{base}/1"))
        .bearer_auth("user")
        .json(&json!({"title": "too long"}))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_update.status(), 400);
    assert_eq!(
        invalid_update.json::<Value>().await.unwrap(),
        json!({
            "code": "validation_error",
            "message": "Field `title` must have at most 7 characters",
            "field": "title",
        })
    );

    let updated = client
        .put(format!("{base}/1"))
        .bearer_auth("user")
        .json(&json!({"title": "changed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(updated.status(), 200);
    let fetched: Value = client
        .get(format!("{base}/1"))
        .bearer_auth("user")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetched, json!({"id": 1, "title": "changed"}));

    let deleted = client
        .delete(format!("{base}/1"))
        .bearer_auth("user")
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 200);
    let missing = client
        .get(format!("{base}/1"))
        .bearer_auth("user")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    B::shutdown(server).await.unwrap();
}

#[cfg(feature = "http-actix")]
#[tokio::test]
async fn actix_protected_crud() {
    protected_crud::<vsr_runtime::http::ActixHttpServer>().await;
}

#[cfg(feature = "http-axum")]
#[tokio::test]
async fn axum_protected_crud() {
    protected_crud::<vsr_runtime::http::AxumHttpServer>().await;
}

#[tokio::test]
async fn create_only_role_does_not_receive_an_unreadable_row() {
    let service = TextCrudService::new(
        TextCrudConfig {
            collection_path: "/api/note".into(),
            id_field: "id".into(),
            value_field: "title".into(),
            value_length: None,
            default_limit: None,
            max_limit: None,
            roles: TextCrudRoles {
                read: "reader".into(),
                create: "creator".into(),
                update: "editor".into(),
                delete: "editor".into(),
            },
        },
        Arc::new(MemoryStore::default()),
    )
    .unwrap();
    let identity = AuthenticatedIdentity {
        user_id: "1".into(),
        email: None,
        roles: vec!["creator".into()],
        claims: Default::default(),
        is_admin: false,
        expires_at: None,
    };
    let response = service
        .execute(
            TextCrudAction::Create,
            None,
            Some(&identity),
            Some(json!({"title": "private"})),
            "",
            "/api/note",
        )
        .await;
    assert_eq!(response.status, 201);
    assert!(matches!(response.body, ResponseBody::Empty));
    assert_eq!(response.headers.get("location"), Some(&b"/api/note/1"[..]));
}

#[tokio::test]
async fn text_length_modes_match_eon_units() {
    let identity = AuthenticatedIdentity {
        user_id: "1".into(),
        email: None,
        roles: vec!["user".into()],
        claims: Default::default(),
        is_admin: false,
        expires_at: None,
    };
    for (mode, expected) in [
        (TextLengthMode::Bytes, 3),
        (TextLengthMode::Chars, 2),
        (TextLengthMode::Graphemes, 1),
        (TextLengthMode::Utf16, 2),
    ] {
        let store = Arc::new(MemoryStore::default());
        let config = TextCrudConfig {
            collection_path: "/api/note".into(),
            id_field: "id".into(),
            value_field: "title".into(),
            value_length: Some(TextLengthValidation {
                min: None,
                max: None,
                equal: Some(expected),
                mode,
            }),
            default_limit: None,
            max_limit: None,
            roles: TextCrudRoles {
                read: "user".into(),
                create: "user".into(),
                update: "user".into(),
                delete: "user".into(),
            },
        };
        let service = TextCrudService::new(config.clone(), store.clone()).unwrap();
        let create = service
            .execute(
                TextCrudAction::Create,
                None,
                Some(&identity),
                Some(json!({"title": "e\u{301}"})),
                "",
                "/api/note",
            )
            .await;
        assert_eq!(create.status, 201, "mode {mode:?}");
        assert_eq!(store.count(&TextFilters::default()).await.unwrap(), 1);

        let mut invalid_config = config;
        invalid_config.value_length.as_mut().unwrap().equal = Some(expected + 1);
        let invalid_service = TextCrudService::new(invalid_config, store.clone()).unwrap();
        let update = invalid_service
            .execute(
                TextCrudAction::Update,
                Some(1),
                Some(&identity),
                Some(json!({"title": "e\u{301}"})),
                "",
                "/api/note/1",
            )
            .await;
        assert_eq!(update.status, 400, "mode {mode:?}");
        assert_eq!(store.get(1).await.unwrap().unwrap().value, "e\u{301}");
    }
}
