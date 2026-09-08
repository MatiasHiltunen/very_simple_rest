//! The same VSR routes on either transport. This is not the native CLI backend selector.

#[cfg(any(feature = "http-actix", feature = "http-axum"))]
mod demo {
    use vsr_runtime::http::{
        HttpMethod, HttpServer, MiddlewareConfig, ResponseEnvelope, ServerConfig, ServerHandle,
        make_handler,
    };

    pub async fn serve<B: HttpServer>() -> Result<(), Box<dyn std::error::Error>> {
        let config = ServerConfig {
            addr: "127.0.0.1:0".parse()?,
            ..Default::default()
        };
        let readiness = config.readiness.clone();
        let server = B::serve(config, MiddlewareConfig::default(), vec![
            (HttpMethod::Get, "/hello/{name}".into(), make_handler(|ctx| async move {
                ResponseEnvelope::json(serde_json::json!({"hello": ctx.path_params["name"], "request_id": ctx.request_id}))
            })),
        ]).await?;
        readiness.set_ready(true);
        println!("http://{}/hello/world", server.addresses()[0]);
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            () = server.wait_for_exit() => {},
        }
        B::shutdown(server).await?;
        Ok(())
    }
}

#[cfg(any(feature = "http-actix", feature = "http-axum"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = std::env::args().nth(1).unwrap_or_else(|| {
        if cfg!(feature = "http-actix") {
            "actix"
        } else {
            "axum"
        }
        .to_owned()
    });
    match backend.as_str() {
        #[cfg(feature = "http-actix")]
        "actix" => demo::serve::<vsr_runtime::http::ActixHttpServer>().await,
        #[cfg(feature = "http-axum")]
        "axum" => demo::serve::<vsr_runtime::http::AxumHttpServer>().await,
        _ => Err("backend is unknown or not compiled in".into()),
    }
}

#[cfg(not(any(feature = "http-actix", feature = "http-axum")))]
fn main() {
    eprintln!("Enable http-actix or http-axum to run this example.");
    std::process::exit(1);
}
