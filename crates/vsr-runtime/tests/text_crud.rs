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
        TextCrudAction, TextCrudConfig, TextCrudRoles, TextCrudService, TextCrudStore, TextPage,
        TextPageRequest, TextRecord, TextStoreError,
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
    async fn list(&self, page: TextPageRequest) -> Result<TextPage, TextStoreError> {
        let rows = self.0.lock().unwrap();
        let total = rows.len() as i64;
        let selected = rows
            .iter()
            .skip(page.offset as usize)
            .take(page.limit.map_or(usize::MAX, |limit| limit as usize))
            .cloned()
            .collect();
        Ok(TextPage {
            rows: selected,
            total,
        })
    }

    async fn count(&self) -> Result<i64, TextStoreError> {
        Ok(self.0.lock().unwrap().len() as i64)
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
    let unsupported = client
        .get(format!("{base}/count?filter_title=first"))
        .bearer_auth("user")
        .send()
        .await
        .unwrap();
    assert_eq!(unsupported.status(), 400);

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
