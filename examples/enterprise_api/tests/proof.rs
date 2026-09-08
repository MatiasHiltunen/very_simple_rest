//! Real sockets, signed credentials and a persistent isolated database per case.
use enterprise_api::{
    App,
    auth::{Claims, now},
    config::{Backend, Config},
    demo, store,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{Client, Method, Response};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::{path::Path, sync::Arc, time::Duration};
use vsr_runtime::http::{HttpServer, ServerHandle};

trait Transport: HttpServer {
    fn backend() -> Backend;
}
#[cfg(feature = "axum")]
impl Transport for vsr_runtime::http::AxumHttpServer {
    fn backend() -> Backend {
        Backend::Axum
    }
}
#[cfg(feature = "actix")]
impl Transport for vsr_runtime::http::ActixHttpServer {
    fn backend() -> Backend {
        Backend::Actix
    }
}

struct Fixture<B: Transport> {
    server: Option<B::Handle>,
    app: Arc<App>,
    pool: SqlitePool,
    client: Client,
    base: String,
    private: String,
    config: Config,
    _dir: tempfile::TempDir,
}

impl<B: Transport> Fixture<B> {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let pair = rcgen::KeyPair::generate().unwrap();
        let private = pair.serialize_pem();
        let public = dir.path().join("public.pem");
        std::fs::write(&public, pair.public_key_pem()).unwrap();
        let mut config =
            Config::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("server.eon")).unwrap();
        config.backend = B::backend();
        config.listen = "127.0.0.1:0".parse().unwrap();
        config.database = dir.path().join("proof.sqlite");
        config.verification_keys[0].pem_file = public;
        let app = App::open(config.clone()).await.unwrap();
        let pool = store::connect(&config.database).await.unwrap();
        for (user, tenant, roles) in [
            (1, 1, vec!["reader", "editor"]),
            (2, 1, vec!["reader", "editor"]),
            (3, 1, vec!["reader", "manager", "auditor"]),
            (4, 2, vec!["reader", "editor"]),
            (5, 1, vec!["reader"]),
        ] {
            sqlx::query("INSERT INTO _principals VALUES(?,1,1)")
                .bind(user)
                .execute(&pool)
                .await
                .unwrap();
            for role in roles {
                sqlx::query("INSERT INTO _grants VALUES(?,?,?,?)")
                    .bind(user)
                    .bind(tenant)
                    .bind(role)
                    .bind(now() + 3600)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
        }
        let server_config = app.server_config();
        let readiness = server_config.readiness.clone();
        let server = B::serve(server_config, app.middleware(), app.routes())
            .await
            .unwrap();
        readiness.set_ready(true);
        let base = format!("http://{}", server.addresses()[0]);
        Self {
            server: Some(server),
            app,
            pool,
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            base,
            private,
            config,
            _dir: dir,
        }
    }

    fn claims(&self, user: i64, tenant: i64) -> Claims {
        let now = now();
        Claims {
            sub: user.to_string(),
            tenant_id: tenant,
            ver: 1,
            jti: format!("proof-{user}-{tenant}"),
            iss: self.app.contract.issuer.clone(),
            aud: self.app.contract.audience.clone(),
            iat: now,
            nbf: now,
            exp: now + 900,
        }
    }
    fn token(&self, user: i64, tenant: i64) -> String {
        demo::sign(
            &self.claims(user, tenant),
            "demo-es256",
            self.private.as_bytes(),
        )
        .unwrap()
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        user: i64,
        tenant: i64,
        body: Option<Value>,
        etag: Option<&str>,
    ) -> Response {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(self.token(user, tenant));
        if let Some(body) = body {
            request = request.json(&body);
        }
        if let Some(etag) = etag {
            request = request.header("if-match", etag);
        }
        request.send().await.unwrap()
    }

    async fn create(&self, table: &str, user: i64, tenant: i64, body: Value) -> (Value, String) {
        let response = self
            .request(
                Method::POST,
                &format!("/api/v1/{table}"),
                user,
                tenant,
                Some(body),
                None,
            )
            .await;
        assert_eq!(
            response.status(),
            201,
            "{}",
            response.text().await.unwrap_or_default()
        );
        let tag = response.headers()["etag"].to_str().unwrap().to_owned();
        (response.json().await.unwrap(), tag)
    }

    async fn stop(mut self) {
        B::shutdown(self.server.take().unwrap()).await.unwrap();
        self.pool.close().await;
    }
}

async fn crud_isolation<B: Transport>() {
    let f = Fixture::<B>::new().await;
    assert_eq!(f.app.contract.resources.len(), 4);
    let (project, tag) = f
        .create(
            "project",
            1,
            1,
            json!({"name":"Acquisition integration","cost_center":"EU-OPS"}),
        )
        .await;
    let id = project["id"].as_i64().unwrap();
    assert_eq!(project["tenant_id"], 1);
    assert_eq!(project["owner_user_id"], 1);
    let path = format!("/api/v1/project/{id}");
    assert_eq!(
        f.request(Method::GET, &path, 2, 1, None, None)
            .await
            .status(),
        200
    );
    for method in [Method::GET, Method::PATCH, Method::DELETE] {
        let response = f
            .request(
                method,
                &path,
                4,
                2,
                Some(json!({"name":"stolen"})),
                Some(&tag),
            )
            .await;
        assert!(matches!(response.status().as_u16(), 403 | 404));
    }
    assert_eq!(
        f.request(
            Method::PATCH,
            &path,
            2,
            1,
            Some(json!({"name":"not owner"})),
            Some(&tag)
        )
        .await
        .status(),
        404
    );
    assert_eq!(
        f.request(
            Method::POST,
            "/api/v1/project",
            5,
            1,
            Some(json!({"name":"reader write","cost_center":"x"})),
            None
        )
        .await
        .status(),
        403
    );
    for field in [
        "id",
        "tenant_id",
        "owner_user_id",
        "is_admin",
        "role",
        "version",
        "unknown",
    ] {
        let mut body = json!({"name":"mass assignment","cost_center":"x"});
        body[field] = json!(2);
        assert_eq!(
            f.request(Method::POST, "/api/v1/project", 1, 1, Some(body), None)
                .await
                .status(),
            400,
            "{field}"
        );
    }
    let list: Value = f
        .request(Method::GET, "/api/v1/project", 4, 2, None, None)
        .await
        .json()
        .await
        .unwrap();
    assert!(list["data"].as_array().unwrap().is_empty());
    let (other, _) = f
        .create(
            "project",
            4,
            2,
            json!({"name":"Other tenant","cost_center":"US-OPS"}),
        )
        .await;
    assert_eq!(
        f.request(
            Method::POST,
            "/api/v1/change_request",
            1,
            1,
            Some(
                json!({"project_id":other["id"],"summary":"foreign parent","justification":"deny"})
            ),
            None
        )
        .await
        .status(),
        404
    );
    let (change,_) = f.create("change_request",1,1,json!({"project_id":id,"summary":"Move service","justification":"reduce recovery time"})).await;
    assert_eq!(change["project_id"], id);
    let (asset, _) = f
        .create(
            "asset",
            1,
            1,
            json!({"project_id":id,"name":"Settlement service","critical":true}),
        )
        .await;
    assert_eq!(asset["critical"], true);
    let (note, note_tag) = f
        .create(
            "private_note",
            1,
            1,
            json!({"subject":"Assessment","body":"Restricted owner notes"}),
        )
        .await;
    let note_path = format!("/api/v1/private_note/{}", note["id"]);
    assert_eq!(
        f.request(Method::GET, &note_path, 3, 1, None, None)
            .await
            .status(),
        404
    );
    assert_eq!(
        f.request(Method::DELETE, &note_path, 3, 1, None, Some(&note_tag))
            .await
            .status(),
        404
    );
    let notes: Value = f
        .request(Method::GET, "/api/v1/private_note", 2, 1, None, None)
        .await
        .json()
        .await
        .unwrap();
    assert!(notes["data"].as_array().unwrap().is_empty());
    assert_eq!(
        f.request(
            Method::PATCH,
            &path,
            1,
            1,
            Some(json!({"name":"missing version"})),
            None
        )
        .await
        .status(),
        428
    );
    let updated = f
        .request(
            Method::PATCH,
            &path,
            1,
            1,
            Some(json!({"name":"Approved name"})),
            Some(&tag),
        )
        .await;
    assert_eq!(updated.status(), 200);
    let newer_tag = updated.headers()["etag"].to_str().unwrap().to_owned();
    assert_ne!(tag, newer_tag);
    assert_eq!(
        f.request(
            Method::PATCH,
            &path,
            1,
            1,
            Some(json!({"name":"stale"})),
            Some(&tag)
        )
        .await
        .status(),
        412
    );
    // Existing child rows restrict deletion; no silent cascades or audit-only successes.
    assert_eq!(
        f.request(Method::DELETE, &path, 3, 1, None, Some(&newer_tag))
            .await
            .status(),
        409
    );
    f.stop().await;
}

async fn tokens_and_grants<B: Transport>() {
    let f = Fixture::<B>::new().await;
    let url = format!("{}/api/v1/project", f.base);
    assert_eq!(f.client.get(&url).send().await.unwrap().status(), 401);
    assert_eq!(
        f.client
            .get(&url)
            .header("cookie", format!("access_token={}", f.token(1, 1)))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        f.client
            .get(&url)
            .header("authorization", format!("Bearer {}", f.token(1, 1)))
            .header("authorization", format!("Bearer {}", f.token(2, 1)))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    for mutation in 0..10 {
        let mut claims = f.claims(1, 1);
        match mutation {
            0 => claims.aud = "another-service".into(),
            1 => claims.iss = "https://untrusted.example".into(),
            2 => {
                claims.iat -= 1000;
                claims.nbf -= 1000;
                claims.exp = now() - 1;
            }
            3 => claims.nbf += 100,
            4 => claims.iat += 100,
            5 => claims.exp += 1,
            6 => claims.tenant_id = 0,
            7 => claims.sub = "unknown-subject".into(),
            8 => claims.jti = String::new(),
            _ => claims.sub = "01".into(),
        }
        let token = demo::sign(&claims, "demo-es256", f.private.as_bytes()).unwrap();
        assert_eq!(
            f.client
                .get(&url)
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .status(),
            401,
            "mutation {mutation}"
        );
    }
    for (typ, kid) in [
        ("JWT", Some("demo-es256")),
        ("at+jwt", None),
        ("at+jwt", Some("untrusted-key")),
    ] {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(typ.into());
        header.kid = kid.map(str::to_owned);
        let token = jsonwebtoken::encode(
            &header,
            &f.claims(1, 1),
            &EncodingKey::from_ec_pem(f.private.as_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            f.client
                .get(&url)
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
    }
    let other_key = rcgen::KeyPair::generate().unwrap().serialize_pem();
    let token = demo::sign(&f.claims(1, 1), "demo-es256", other_key.as_bytes()).unwrap();
    assert_eq!(
        f.client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let mut escalated = serde_json::to_value(f.claims(5, 1)).unwrap();
    escalated["roles"] = json!(["editor", "manager", "admin"]);
    escalated["is_admin"] = json!(true);
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("at+jwt".into());
    header.kid = Some("demo-es256".into());
    let token = jsonwebtoken::encode(
        &header,
        &escalated,
        &EncodingKey::from_ec_pem(f.private.as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        f.client
            .post(&url)
            .bearer_auth(token)
            .json(&json!({"name":"escalation","cost_center":"x"}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let alice = f.token(1, 1);
    sqlx::query("DELETE FROM _grants WHERE user_id=1 AND role='editor'")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.client
            .post(&url)
            .bearer_auth(&alice)
            .json(&json!({"name":"revoked","cost_center":"x"}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    sqlx::query("UPDATE _grants SET expires_at=? WHERE user_id=1")
        .bind(now() - 1)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.client
            .get(&url)
            .bearer_auth(&alice)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    sqlx::query("UPDATE _principals SET enabled=0 WHERE id=5")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.request(Method::GET, "/api/v1/project", 5, 1, None, None)
            .await
            .status(),
        401
    );
    sqlx::query("UPDATE _principals SET version=2 WHERE id=2")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.request(Method::GET, "/api/v1/project", 2, 1, None, None)
            .await
            .status(),
        401
    );
    sqlx::query("INSERT INTO _revoked_tokens VALUES('proof-3-1',?)")
        .bind(now() + 900)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.request(Method::GET, "/api/v1/project", 3, 1, None, None)
            .await
            .status(),
        401
    );
    // A valid identity cannot select a tenant where it has no current assignment.
    assert_eq!(
        f.request(Method::GET, "/api/v1/project", 4, 1, None, None)
            .await
            .status(),
        403
    );
    f.stop().await;
}

async fn audit_and_persistence<B: Transport>() {
    let mut f = Fixture::<B>::new().await;
    let (project, tag) = f
        .create(
            "project",
            1,
            1,
            json!({"name":"Persisted","cost_center":"OPS"}),
        )
        .await;
    let path = format!("/api/v1/project/{}", project["id"]);
    assert_eq!(
        f.request(Method::GET, "/api/v1/audit", 1, 1, None, None)
            .await
            .status(),
        403
    );
    let audit: Value = f
        .request(Method::GET, "/api/v1/audit", 3, 1, None, None)
        .await
        .json()
        .await
        .unwrap();
    assert!(
        audit["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["action"] == "create" && row["status"] == 201)
    );
    assert!(!audit.to_string().contains("Persisted"));
    assert!(
        sqlx::query("UPDATE _audit SET status=200")
            .execute(&f.pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM _audit")
            .execute(&f.pool)
            .await
            .is_err()
    );
    sqlx::raw_sql("CREATE TRIGGER reject_audit BEFORE INSERT ON _audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;").execute(&f.pool).await.unwrap();
    assert_eq!(
        f.request(
            Method::PATCH,
            &path,
            1,
            1,
            Some(json!({"name":"must roll back"})),
            Some(&tag)
        )
        .await
        .status(),
        503
    );
    sqlx::query("DROP TRIGGER reject_audit")
        .execute(&f.pool)
        .await
        .unwrap();
    let persisted = f.request(Method::GET, &path, 1, 1, None, None).await;
    assert_eq!(persisted.headers()["etag"], tag);
    assert_eq!(
        persisted.json::<Value>().await.unwrap()["name"],
        "Persisted"
    );
    B::shutdown(f.server.take().unwrap()).await.unwrap();
    let reopened = App::open(f.config.clone()).await.unwrap();
    let handle = B::serve(
        reopened.server_config(),
        reopened.middleware(),
        reopened.routes(),
    )
    .await
    .unwrap();
    f.base = format!("http://{}", handle.addresses()[0]);
    f.server = Some(handle);
    f.app = reopened;
    assert_eq!(
        f.request(Method::GET, &path, 1, 1, None, None)
            .await
            .json::<Value>()
            .await
            .unwrap()["name"],
        "Persisted"
    );
    assert_eq!(
        f.request(Method::DELETE, &path, 3, 1, None, Some(&tag))
            .await
            .status(),
        204
    );
    let (replacement, _) = f
        .create(
            "project",
            1,
            1,
            json!({"name":"New record","cost_center":"OPS"}),
        )
        .await;
    assert!(replacement["id"].as_i64().unwrap() > project["id"].as_i64().unwrap());
    sqlx::query("UPDATE _example_schema SET checksum='tampered'")
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(App::open(f.config.clone()).await.is_err());
    f.stop().await;
}

async fn concurrent_writes<B: Transport>() {
    let f = Fixture::<B>::new().await;
    let (p, tag) = f
        .create(
            "project",
            1,
            1,
            json!({"name":"Original","cost_center":"OPS"}),
        )
        .await;
    let path = format!("/api/v1/project/{}", p["id"]);
    let (first, second) = tokio::join!(
        f.request(
            Method::PATCH,
            &path,
            1,
            1,
            Some(json!({"name":"Writer one"})),
            Some(&tag)
        ),
        f.request(
            Method::PATCH,
            &path,
            1,
            1,
            Some(json!({"name":"Writer two"})),
            Some(&tag)
        )
    );
    let mut statuses = vec![first.status().as_u16(), second.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, vec![200, 412]);
    let updates: i64 =
        sqlx::query_scalar("SELECT count(*) FROM _audit WHERE action='update' AND status=200")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(updates, 1);
    f.stop().await;
}

async fn bounds_and_contract<B: Transport>() {
    let f = Fixture::<B>::new().await;
    for query in [
        "limit=0",
        "limit=101",
        "limit=1&limit=2",
        "tenant_id=2",
        "after=-1",
        "unknown=x",
    ] {
        assert_eq!(
            f.request(
                Method::GET,
                &format!("/api/v1/project?{query}"),
                1,
                1,
                None,
                None
            )
            .await
            .status(),
            400,
            "{query}"
        );
    }
    f.create("project", 1, 1, json!({"name":"one","cost_center":"OPS"}))
        .await;
    f.create("project", 1, 1, json!({"name":"two","cost_center":"OPS"}))
        .await;
    let page: Value = f
        .request(Method::GET, "/api/v1/project?limit=1", 1, 1, None, None)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(page["data"].as_array().unwrap().len(), 1);
    let next: Value = f
        .request(
            Method::GET,
            &format!("/api/v1/project?limit=1&after={}", page["next_after"]),
            1,
            1,
            None,
            None,
        )
        .await
        .json()
        .await
        .unwrap();
    assert_ne!(next["data"][0]["id"], page["data"][0]["id"]);
    assert!(next["next_after"].is_null());
    let long = "x".repeat(4097);
    assert_eq!(
        f.request(
            Method::POST,
            "/api/v1/project",
            1,
            1,
            Some(json!({"name":long,"cost_center":"OPS"})),
            None
        )
        .await
        .status(),
        400
    );
    let huge = "x".repeat(65537);
    assert_eq!(
        f.client
            .post(format!("{}/api/v1/project", f.base))
            .bearer_auth(f.token(1, 1))
            .header("content-type", "application/json")
            .body(r#"{"name":"first","name":"second","cost_center":"OPS"}"#)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        f.client
            .post(format!("{}/api/v1/project", f.base))
            .bearer_auth(f.token(1, 1))
            .header("content-type", "application/json")
            .body(huge)
            .send()
            .await
            .unwrap()
            .status(),
        413
    );
    assert_eq!(
        f.client
            .post(format!("{}/api/v1/project", f.base))
            .bearer_auth(f.token(1, 1))
            .body("{}")
            .send()
            .await
            .unwrap()
            .status(),
        415
    );
    assert_eq!(
        f.request(
            Method::GET,
            "/api/v1/project/1%20OR%201=1",
            1,
            1,
            None,
            None
        )
        .await
        .status(),
        400
    );
    let response = f
        .request(Method::GET, "/api/v1/session", 1, 1, None, None)
        .await;
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(response.headers().contains_key("x-request-id"));
    assert_eq!(
        response.json::<Value>().await.unwrap()["roles"],
        json!(["editor", "reader"])
    );
    let openapi: Value = f
        .client
        .get(format!("{}/openapi.json", f.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(openapi["openapi"], "3.1.0");
    assert!(openapi["paths"]["/api/v1/change_request"].is_object());
    let create_schema = &openapi["paths"]["/api/v1/project"]["post"]["requestBody"]["content"]["application/json"]
        ["schema"];
    assert_eq!(create_schema["additionalProperties"], false);
    assert!(create_schema["properties"]["tenant_id"].is_null());
    assert!(create_schema["properties"]["name"].is_object());
    assert_eq!(
        f.client
            .get(format!("{}/readyz", f.base))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let mut invalid = f.config.clone();
    invalid.listen = "0.0.0.0:8080".parse().unwrap();
    assert!(invalid.validate().is_err());
    invalid = f.config.clone();
    invalid
        .verification_keys
        .push(invalid.verification_keys[0].clone());
    assert!(invalid.validate().is_err());
    invalid = f.config.clone();
    invalid.max_in_flight = 0;
    assert!(invalid.validate().is_err());
    let source = include_str!("../server.eon");
    assert!(eon::from_str::<Config>(source).is_ok());
    assert!(eon::from_str::<Config>(&format!("{source}\nunknown_security_option: true")).is_err());
    sqlx::query("DROP TABLE _grants")
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(!f.app.check_database().await);
    assert_eq!(
        f.request(Method::GET, "/api/v1/project", 1, 1, None, None)
            .await
            .status(),
        503
    );
    f.stop().await;
}

macro_rules! suite {
    ($module:ident,$backend:ty) => {
        mod $module {
            use super::*;
            #[tokio::test]
            async fn tenant_owner_roles_and_crud() {
                crud_isolation::<$backend>().await;
            }
            #[tokio::test]
            async fn signature_claims_and_live_revocation() {
                tokens_and_grants::<$backend>().await;
            }
            #[tokio::test]
            async fn transactional_audit_and_restart() {
                audit_and_persistence::<$backend>().await;
            }
            #[tokio::test]
            async fn competing_writes_have_one_winner() {
                concurrent_writes::<$backend>().await;
            }
            #[tokio::test]
            async fn strict_bounds_and_eon_contract() {
                bounds_and_contract::<$backend>().await;
            }
        }
    };
}
#[cfg(feature = "axum")]
suite!(axum, vsr_runtime::http::AxumHttpServer);
#[cfg(feature = "actix")]
suite!(actix, vsr_runtime::http::ActixHttpServer);
