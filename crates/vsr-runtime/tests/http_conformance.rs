//! The same black-box protocol and lifecycle contract against each HTTP backend.
#![cfg(any(feature = "http-actix", feature = "http-axum"))]

use std::{io::Write, sync::Arc, time::Duration};

use serde_json::{Value, json};
use vsr_runtime::http::{
    CorsConfig, Handler, HeaderFields, HttpMethod, HttpServer, MiddlewareConfig, ResponseBody,
    ResponseEnvelope, ServerConfig, ServerHandle, TlsConfig, make_handler,
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

fn config<B: Backend>() -> ServerConfig {
    ServerConfig {
        addr: "127.0.0.1:0".parse().unwrap(),
        workers: B::workers(),
        shutdown_timeout: Duration::from_secs(2),
        ..Default::default()
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

fn echo() -> Handler {
    make_handler(|ctx| async move {
        ResponseEnvelope::json(json!({
            "method": ctx.method.to_string(), "path": ctx.path, "query": ctx.query_params,
            "raw_query": ctx.raw_query, "params": ctx.path_params, "route": ctx.matched_route,
            "peer": ctx.peer_addr.map(|a| a.ip().to_string()), "id": ctx.request_id,
            "opaque": ctx.headers.get("x-opaque").map(|v| v.to_vec()),
            "repeated": ctx.headers.get_all("x-repeated").map(|v| String::from_utf8_lossy(v).into_owned()).collect::<Vec<_>>(),
            "body_len": ctx.body.map_or(0, |b| b.len()),
            "encoding": ctx.headers.get("content-encoding").map(|v| String::from_utf8_lossy(v).into_owned()),
        }))
    })
}

async fn encoding<B: Backend>() {
    let server = B::serve(
        config::<B>(),
        MiddlewareConfig::default(),
        vec![(HttpMethod::Get, "/inspect/{id}".into(), echo())],
    )
    .await
    .unwrap();
    let base = format!("http://{}/inspect/", server.addresses()[0]);
    let response: Value = client()
        .get(format!(
            "{base}a%20b?x=a+b&x=a%2Bb&na%6De=value&=empty&utf=%C3%A4"
        ))
        .header(
            "x-opaque",
            reqwest::header::HeaderValue::from_bytes(&[0x80]).unwrap(),
        )
        .header("x-request-id", "spoofed-id")
        .header("x-repeated", "first")
        .header("x-repeated", "second")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response["path"], "/inspect/a%20b");
    assert_eq!(response["params"]["id"], "a b");
    assert_eq!(
        response["query"],
        json!({"x": ["a b", "a+b"], "name": ["value"], "": ["empty"], "utf": ["\u{e4}"]})
    );
    assert_eq!(response["route"], "/inspect/{id}");
    assert_eq!(response["peer"], "127.0.0.1");
    assert_eq!(response["opaque"], json!([128]));
    assert_eq!(response["repeated"], json!(["first", "second"]));
    assert_ne!(response["id"], "spoofed-id");
    for (path, expected) in [
        ("a%2Fb", "a/b"),
        ("%252F", "%2F"),
        ("%C3%A4", "\u{e4}"),
        ("a+b", "a+b"),
    ] {
        let response: Value = client()
            .get(format!("{base}{path}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(response["params"]["id"], expected, "{path}");
    }
    for suffix in ["%FF", "%2", "abc?x=%FF", "abc?x=%GG"] {
        assert_eq!(
            client()
                .get(format!("{base}{suffix}"))
                .send()
                .await
                .unwrap()
                .status(),
            400,
            "{suffix}"
        );
    }
    B::shutdown(server).await.unwrap();
}

async fn responses<B: Backend>() {
    struct CannotSerialize;
    impl serde::Serialize for CannotSerialize {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("not serializable"))
        }
    }
    assert!(ResponseEnvelope::try_json(CannotSerialize).is_err());
    let server = B::serve(
        config::<B>(),
        MiddlewareConfig::default(),
        vec![
            (
                HttpMethod::Get,
                "/cookies".into(),
                make_handler(|_| async {
                    let mut response = ResponseEnvelope::status(200);
                    response
                        .headers
                        .append("Set-Cookie", "session=abc; HttpOnly; Secure")
                        .unwrap();
                    response
                        .headers
                        .append("set-cookie", "csrf=def; Secure")
                        .unwrap();
                    response.headers.append("x-opaque", [0x80]).unwrap();
                    response
                }),
            ),
            (
                HttpMethod::Get,
                "/error".into(),
                make_handler(|_| async { ResponseEnvelope::json(CannotSerialize) }),
            ),
            (
                HttpMethod::Get,
                "/json".into(),
                make_handler(|_| async {
                    ResponseEnvelope {
                        status: 200,
                        headers: HeaderFields::default(),
                        body: ResponseBody::Json(json!({"ok": true})),
                    }
                }),
            ),
        ],
    )
    .await
    .unwrap();
    let base = format!("http://{}", server.addresses()[0]);
    let response = client()
        .get(format!("{base}/cookies"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["session=abc; HttpOnly; Secure", "csrf=def; Secure"]
    );
    assert_eq!(response.headers()["x-opaque"].as_bytes(), &[0x80]);
    let response = client().get(format!("{base}/error")).send().await.unwrap();
    assert_eq!(response.status(), 500);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"error": "JSON serialization failed"})
    );
    let response = client().get(format!("{base}/json")).send().await.unwrap();
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.json::<Value>().await.unwrap(), json!({"ok": true}));
    B::shutdown(server).await.unwrap();
}

async fn routing<B: Backend>() {
    let server = B::serve(
        config::<B>(),
        MiddlewareConfig::default(),
        vec![
            (HttpMethod::Get, "/items/{id}".into(), echo()),
            (
                HttpMethod::Post,
                "/items/{id}".into(),
                make_handler(|_| async { ResponseEnvelope::status(201) }),
            ),
            (
                HttpMethod::Get,
                "/items/fixed".into(),
                make_handler(|_| async { ResponseEnvelope::json("fixed") }),
            ),
            (HttpMethod::Get, "/files/{*tail}".into(), echo()),
            (
                HttpMethod::Options,
                "/explicit".into(),
                make_handler(|_| async { ResponseEnvelope::status(202) }),
            ),
            (
                HttpMethod::Head,
                "/explicit".into(),
                make_handler(|_| async { ResponseEnvelope::status(203) }),
            ),
        ],
    )
    .await
    .unwrap();
    let base = format!("http://{}", server.addresses()[0]);
    assert_eq!(
        client()
            .post(format!("{base}/items/42"))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    let response = client()
        .head(format!("{base}/items/42"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.bytes().await.unwrap().is_empty());
    assert_eq!(
        client()
            .head(format!("{base}/explicit"))
            .send()
            .await
            .unwrap()
            .status(),
        203
    );
    assert_eq!(
        client()
            .request(reqwest::Method::OPTIONS, format!("{base}/explicit"))
            .send()
            .await
            .unwrap()
            .status(),
        202
    );
    for (method, status) in [
        (reqwest::Method::DELETE, 405),
        (reqwest::Method::OPTIONS, 204),
        (reqwest::Method::TRACE, 405),
    ] {
        let response = client()
            .request(method, format!("{base}/items/42"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["allow"], "GET, HEAD, OPTIONS, POST");
    }
    assert_eq!(
        client()
            .get(format!("{base}/missing"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client()
            .get(format!("{base}/items/fixed"))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap(),
        "fixed"
    );
    let response: Value = client()
        .get(format!("{base}/files/a/b%20c"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response["params"]["tail"], "a/b c");
    assert_eq!(
        client()
            .get(format!("{base}/files/"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    B::shutdown(server).await.unwrap();
}

async fn security<B: Backend>() {
    let mut middleware = MiddlewareConfig::default();
    middleware.cors = Some(CorsConfig {
        allowed_origins: Some(vec!["https://allowed.example".into()]),
        allow_credentials: true,
        ..Default::default()
    });
    let server = B::serve(
        config::<B>(),
        middleware,
        vec![(
            HttpMethod::Get,
            "/data".into(),
            make_handler(|_| async { ResponseEnvelope::json("x".repeat(8192)) }),
        )],
    )
    .await
    .unwrap();
    let base = format!("http://{}/data", server.addresses()[0]);
    let response = client()
        .get(&base)
        .header("origin", "https://allowed.example")
        .header("accept-encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    for (name, value) in [
        ("content-encoding", "gzip"),
        ("x-frame-options", "DENY"),
        ("access-control-allow-origin", "https://allowed.example"),
        ("access-control-allow-credentials", "true"),
        ("content-security-policy", "default-src 'self'"),
        ("x-content-type-options", "nosniff"),
    ] {
        assert_eq!(response.headers()[name], value, "{name}");
    }
    assert!(response.bytes().await.unwrap().len() < 8192);
    assert_eq!(
        client()
            .get(&base)
            .header("origin", "https://denied.example")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let preflight = |method, headers| {
        client()
            .request(reqwest::Method::OPTIONS, &base)
            .header("origin", "https://allowed.example")
            .header("access-control-request-method", method)
            .header("access-control-request-headers", headers)
    };
    let response = preflight("POST", "authorization, content-type")
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "https://allowed.example"
    );
    assert_eq!(
        preflight("TRACE", "authorization")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        preflight("POST", "x-not-allowed")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    B::shutdown(server).await.unwrap();
}

async fn body_limits<B: Backend>() {
    let mut cfg = config::<B>();
    cfg.max_body_bytes = 64;
    let server = B::serve(
        cfg,
        MiddlewareConfig::default(),
        vec![(HttpMethod::Post, "/body".into(), echo())],
    )
    .await
    .unwrap();
    let url = format!("http://{}/body", server.addresses()[0]);
    let response = client()
        .post(&url)
        .body(vec![b'x'; 64])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.json::<Value>().await.unwrap()["body_len"], 64);
    assert_eq!(
        client()
            .post(&url)
            .body(vec![0; 65])
            .send()
            .await
            .unwrap()
            .status(),
        413
    );
    for size in [64, 8192] {
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&vec![b'x'; size]).unwrap();
        let response = client()
            .post(&url)
            .header("content-encoding", "gzip")
            .body(gzip.finish().unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if size == 64 { 200 } else { 413 },
            "decompressed size {size}"
        );
        if size == 64 {
            assert_eq!(response.json::<Value>().await.unwrap()["encoding"], "gzip");
        }
    }
    B::shutdown(server).await.unwrap();
}

async fn lifecycle<B: Backend>() {
    let cfg = config::<B>();
    let readiness = cfg.readiness.clone();
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let handler = make_handler({
        let started = started.clone();
        let release = release.clone();
        move |_| {
            let started = started.clone();
            let release = release.clone();
            async move {
                started.notify_one();
                release.notified().await;
                ResponseEnvelope::status(200)
            }
        }
    });
    let server = B::serve(
        cfg,
        MiddlewareConfig::default(),
        vec![(HttpMethod::Get, "/slow".into(), handler)],
    )
    .await
    .unwrap();
    assert!(!server.is_finished());
    let base = format!("http://{}", server.addresses()[0]);
    assert_eq!(
        client()
            .get(format!("{base}/healthz"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client()
            .get(format!("{base}/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    readiness.set_ready(true);
    assert_eq!(
        client()
            .get(format!("{base}/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let request = tokio::spawn(async move {
        client()
            .get(format!("{base}/slow"))
            .header("connection", "close")
            .send()
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), started.notified())
        .await
        .unwrap();
    let shutdown = tokio::spawn(B::shutdown(server));
    tokio::time::sleep(Duration::from_millis(30)).await;
    let early = shutdown.is_finished();
    assert!(!readiness.is_ready());
    release.notify_one();
    assert_eq!(request.await.unwrap().unwrap().status(), 200);
    tokio::time::timeout(Duration::from_secs(4), shutdown)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!early, "shutdown did not drain the pending handler");
}

async fn drop_stops_server<B: Backend>() {
    let cfg = config::<B>();
    let readiness = cfg.readiness.clone();
    let server = B::serve(cfg, MiddlewareConfig::default(), vec![])
        .await
        .unwrap();
    let url = format!("http://{}/healthz", server.addresses()[0]);
    assert_eq!(client().get(&url).send().await.unwrap().status(), 200);
    readiness.set_ready(true);
    drop(server);
    assert!(!readiness.is_ready());
    tokio::time::timeout(Duration::from_secs(3), async {
        while client().get(&url).send().await.is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

async fn cancellation<B: Backend>(immediate: bool) {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Cancelled(Arc<AtomicBool>);
    impl Drop for Cancelled {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let started = Arc::new(tokio::sync::Notify::new());
    let cancelled = Arc::new(AtomicBool::new(false));
    let handler = make_handler({
        let started = started.clone();
        let cancelled = cancelled.clone();
        move |_| {
            let started = started.clone();
            let cancelled = cancelled.clone();
            async move {
                let _guard = Cancelled(cancelled);
                started.notify_one();
                std::future::pending::<()>().await;
                ResponseEnvelope::status(200)
            }
        }
    });
    let mut cfg = config::<B>();
    cfg.shutdown_timeout = Duration::from_millis(100);
    let server = B::serve(
        cfg,
        MiddlewareConfig::default(),
        vec![(HttpMethod::Get, "/pending".into(), handler)],
    )
    .await
    .unwrap();
    // Cancelling a completion observer must not consume or detach the server.
    assert!(
        tokio::time::timeout(Duration::from_millis(10), server.wait_for_exit())
            .await
            .is_err()
    );
    assert!(!server.is_finished());
    let url = format!("http://{}/pending", server.addresses()[0]);
    let request = tokio::spawn(async move { client().get(url).send().await });
    tokio::time::timeout(Duration::from_secs(3), started.notified())
        .await
        .unwrap();
    if immediate {
        drop(server);
    } else {
        tokio::time::timeout(Duration::from_secs(3), B::shutdown(server))
            .await
            .unwrap()
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while !cancelled.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(request.await.unwrap().is_err());
}

async fn invalid_startup<B: Backend>() {
    for path in [
        "/healthz",
        "/readyz",
        "/{bad:.*}",
        "not-absolute",
        "/{*tail}/end",
    ] {
        assert!(
            B::serve(
                config::<B>(),
                MiddlewareConfig::default(),
                vec![(HttpMethod::Get, path.into(), echo())]
            )
            .await
            .is_err(),
            "{path}"
        );
    }
    assert!(
        B::serve(
            config::<B>(),
            MiddlewareConfig::default(),
            vec![
                (HttpMethod::Get, "/x".into(), echo()),
                (HttpMethod::Get, "/x".into(), echo())
            ]
        )
        .await
        .is_err()
    );
    let bad_cors = MiddlewareConfig {
        cors: Some(CorsConfig {
            allow_credentials: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(B::serve(config::<B>(), bad_cors, vec![]).await.is_err());
    let unsupported = MiddlewareConfig {
        trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
        ..Default::default()
    };
    assert!(B::serve(config::<B>(), unsupported, vec![]).await.is_err());
    let mut bad = config::<B>();
    bad.tls = Some(TlsConfig {
        cert_path: "missing.pem".into(),
        key_path: "missing-key.pem".into(),
    });
    assert!(
        B::serve(bad, MiddlewareConfig::default(), vec![])
            .await
            .is_err()
    );
    let mut bad = config::<B>();
    bad.workers = Some(0);
    assert!(
        B::serve(bad, MiddlewareConfig::default(), vec![])
            .await
            .is_err()
    );
    let mut bad = config::<B>();
    bad.shutdown_timeout = Duration::ZERO;
    assert!(
        B::serve(bad, MiddlewareConfig::default(), vec![])
            .await
            .is_err()
    );
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut bad = config::<B>();
    bad.addr = reserved.local_addr().unwrap();
    assert!(
        B::serve(bad, MiddlewareConfig::default(), vec![])
            .await
            .is_err()
    );
}

async fn tls<B: Backend>() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let mut cfg = config::<B>();
    cfg.tls = Some(TlsConfig {
        cert_path,
        key_path,
    });
    let server = B::serve(
        cfg,
        MiddlewareConfig::default(),
        vec![(HttpMethod::Get, "/tls".into(), echo())],
    )
    .await
    .unwrap();
    let port = server.addresses()[0].port();
    let trusted = reqwest::Certificate::from_pem(cert.cert.pem().as_bytes()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(trusted)
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let response: Value = client
        .get(format!("https://localhost:{port}/tls"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response["peer"], "127.0.0.1");
    assert!(
        client
            .get(format!("http://127.0.0.1:{port}/healthz"))
            .send()
            .await
            .is_err()
    );
    B::shutdown(server).await.unwrap();
}

macro_rules! backend_tests {
    ($module:ident, $backend:ty) => {
        mod $module {
            use super::*;
            #[tokio::test]
            async fn request_encoding() {
                encoding::<$backend>().await;
            }
            #[tokio::test]
            async fn response_contract() {
                responses::<$backend>().await;
            }
            #[tokio::test]
            async fn route_contract() {
                routing::<$backend>().await;
            }
            #[tokio::test]
            async fn security_contract() {
                security::<$backend>().await;
            }
            #[tokio::test]
            async fn bounded_decompressed_body() {
                body_limits::<$backend>().await;
            }
            #[tokio::test]
            async fn readiness_and_graceful_drain() {
                lifecycle::<$backend>().await;
            }
            #[tokio::test]
            async fn dropping_handle_stops_listener() {
                drop_stops_server::<$backend>().await;
            }
            #[tokio::test]
            async fn deadline_cancels_pending_handler() {
                cancellation::<$backend>(false).await;
            }
            #[tokio::test]
            async fn drop_cancels_pending_handler() {
                cancellation::<$backend>(true).await;
            }
            #[tokio::test]
            async fn startup_validation() {
                invalid_startup::<$backend>().await;
            }
            #[tokio::test]
            async fn verified_https() {
                tls::<$backend>().await;
            }
        }
    };
}

#[cfg(feature = "http-actix")]
backend_tests!(actix, vsr_runtime::http::ActixHttpServer);
#[cfg(feature = "http-axum")]
backend_tests!(axum, vsr_runtime::http::AxumHttpServer);
