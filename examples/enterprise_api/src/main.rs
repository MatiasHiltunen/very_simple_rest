//! Run the EON-selected transport without changing application handlers.
use enterprise_api::{
    App, Error,
    config::{Backend, Config},
    demo,
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use vsr_runtime::http::{HttpServer, ServerHandle};

async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result, _ = terminate.recv() => Ok(()) }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

async fn serve<B: HttpServer>(app: Arc<App>) -> Result<(), Error> {
    let config = app.server_config();
    let readiness = config.readiness.clone();
    let server = B::serve(config, app.middleware(), app.routes()).await?;
    readiness.set_ready(true);
    println!(
        "{:?} enterprise API listening on {}",
        app.config.backend,
        server.addresses()[0]
    );
    let mut checks = tokio::time::interval(Duration::from_secs(2));
    let stop = shutdown_signal();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            signal = &mut stop => { signal?; break; }
            () = server.wait_for_exit() => break,
            _ = checks.tick() => {
                // Check required application tables, not merely a reachable socket.
                let healthy = tokio::time::timeout(Duration::from_secs(1), app.check_database()).await.is_ok_and(|v| v);
                readiness.set_ready(healthy);
            }
        }
    }
    B::shutdown(server).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "serve".into());
    let path = args.next().map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("server.eon"),
        PathBuf::from,
    );
    if args.next().is_some() {
        return Err("usage: enterprise-api [serve|demo-init] [server.eon]".into());
    }
    let config = Config::load(&path)?;
    if command == "demo-init" {
        return demo::initialize(&config).await;
    }
    if command != "serve" {
        return Err("usage: enterprise-api [serve|demo-init] [server.eon]".into());
    }
    // Reject unavailable transports before opening or migrating the database.
    match config.backend {
        #[cfg(feature = "axum")]
        Backend::Axum => serve::<vsr_runtime::http::AxumHttpServer>(App::open(config).await?).await,
        #[cfg(feature = "actix")]
        Backend::Actix => {
            serve::<vsr_runtime::http::ActixHttpServer>(App::open(config).await?).await
        }
        #[allow(unreachable_patterns)]
        _ => Err("selected backend was not compiled in".into()),
    }
}
