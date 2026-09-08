//! Review-only contract probes. Four assertions fail on commit 7c27c9bb3.
#![cfg(feature = "http-actix")]

use std::{collections::HashMap, sync::Arc, time::Duration};

use vsr_runtime::http::{
    ActixHttpServer, Handler, HttpMethod, HttpServer, MiddlewareConfig, ResponseBody,
    ResponseEnvelope, ServerConfig, make_handler,
};

async fn start(
    routes: Vec<(HttpMethod, String, Handler)>,
) -> vsr_runtime::http::actix_adapter::ActixServerHandle {
    ActixHttpServer::serve(
        ServerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            workers: Some(1),
            ..Default::default()
        },
        MiddlewareConfig::default(),
        routes,
    )
    .await
    .unwrap()
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
}

#[tokio::test]
async fn query_parameters_should_decode_form_encoding() {
    let handle = start(vec![(
        HttpMethod::Get,
        "/query".into(),
        make_handler(|ctx| async move { ResponseEnvelope::json(ctx.query_params) }),
    )])
    .await;
    let url = format!(
        "http://{}/query?x=a+b&x=a%2Bb&na%6De=value",
        handle.addresses()[0]
    );
    let actual: serde_json::Value = client()
        .get(url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    ActixHttpServer::shutdown(handle).await.unwrap();
    assert_eq!(
        actual,
        serde_json::json!({"x": ["a b", "a+b"], "name": ["value"]})
    );
}

#[tokio::test]
async fn path_should_match_documented_decoded_contract() {
    let handle = start(vec![(
        HttpMethod::Get,
        "/inspect/{id}".into(),
        make_handler(|ctx| async move {
            ResponseEnvelope::json(serde_json::json!({"path": ctx.path, "params": ctx.path_params}))
        }),
    )])
    .await;
    let url = format!("http://{}/inspect/a%20b", handle.addresses()[0]);
    let actual: serde_json::Value = client()
        .get(url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    ActixHttpServer::shutdown(handle).await.unwrap();
    assert_eq!(actual["path"], "/inspect/a b");
}

#[test]
fn json_serialization_error_should_not_be_success() {
    struct CannotSerialize;
    impl serde::Serialize for CannotSerialize {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("review serialization failure"))
        }
    }
    let response = ResponseEnvelope::json(CannotSerialize);
    assert_eq!(
        response.status, 500,
        "serialization failure must not become HTTP 200"
    );
}

#[tokio::test]
async fn response_should_preserve_multiple_set_cookie_headers() {
    let handle = start(vec![(
        HttpMethod::Get,
        "/cookies".into(),
        make_handler(|_| async {
            ResponseEnvelope {
                status: 200,
                headers: HashMap::from([
                    ("set-cookie".into(), "session=abc; HttpOnly; Secure".into()),
                    ("Set-Cookie".into(), "csrf=def; Secure".into()),
                ]),
                body: ResponseBody::Empty,
            }
        }),
    )])
    .await;
    let url = format!("http://{}/cookies", handle.addresses()[0]);
    let response = client().get(url).send().await.unwrap();
    let cookies = response.headers().get_all("set-cookie").iter().count();
    ActixHttpServer::shutdown(handle).await.unwrap();
    assert_eq!(
        cookies, 2,
        "a cookie must not replace a different Set-Cookie field"
    );
}

#[tokio::test]
async fn methods_on_shared_path_dispatch_independently() {
    let handle = start(vec![
        (
            HttpMethod::Get,
            "/resource".into(),
            make_handler(|_| async { ResponseEnvelope::status(200) }),
        ),
        (
            HttpMethod::Post,
            "/resource".into(),
            make_handler(|_| async { ResponseEnvelope::status(201) }),
        ),
    ])
    .await;
    let url = format!("http://{}/resource", handle.addresses()[0]);
    let get = client().get(&url).send().await.unwrap().status();
    let post = client().post(&url).send().await.unwrap().status();
    ActixHttpServer::shutdown(handle).await.unwrap();
    assert_eq!(get, 200);
    assert_eq!(post, 201);
}

#[tokio::test]
async fn shutdown_drains_in_flight_handler() {
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
    let handle = start(vec![(HttpMethod::Get, "/slow".into(), handler)]).await;
    let url = format!("http://{}/slow", handle.addresses()[0]);
    let request =
        tokio::spawn(async move { client().get(url).header("connection", "close").send().await });
    tokio::time::timeout(Duration::from_secs(3), started.notified())
        .await
        .unwrap();
    let shutdown = tokio::spawn(ActixHttpServer::shutdown(handle));
    tokio::time::sleep(Duration::from_millis(30)).await;
    let drained_early = shutdown.is_finished();
    release.notify_one();
    let status = request.await.unwrap().unwrap().status();
    tokio::time::timeout(Duration::from_secs(3), shutdown)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!drained_early);
    assert_eq!(status, 200);
}
