use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use rest_macro_core::db::query;
use serde_json::Value;
use uuid::Uuid;
use vsra::commands::db::{connect_database, database_url_from_service_config};
use vsra::commands::migrate::apply_setup_migrations;

const TEST_TURSO_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn test_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/serve_cli_tests")
        .join(Uuid::new_v4().to_string())
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("destination directory should exist");
    for entry in fs::read_dir(src).expect("source directory should exist") {
        let entry = entry.expect("directory entry should load");
        let path = entry.path();
        let target = dst.join(entry.file_name());
        if entry.file_type().expect("file type should load").is_dir() {
            copy_dir_all(&path, &target);
        } else {
            fs::copy(&path, &target).expect("fixture file should copy");
        }
    }
}

fn free_bind_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral port should bind");
    let addr = listener
        .local_addr()
        .expect("listener address should resolve");
    drop(listener);
    format!("127.0.0.1:{}", addr.port())
}

fn wait_for_http_ready(client: &Client, url: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut last_error = None;

    while Instant::now() < deadline {
        match client.get(url).send() {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                last_error = Some(format!("server responded with {}", response.status()));
            }
            Err(error) => {
                last_error = Some(error.to_string());
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    Err(last_error.unwrap_or_else(|| "server never became ready".to_owned()))
}

struct SpawnedBinary {
    child: Child,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
}

impl SpawnedBinary {
    fn new(child: Child, stdout_log: PathBuf, stderr_log: PathBuf) -> Self {
        Self {
            child,
            stdout_log,
            stderr_log,
        }
    }

    fn logs(&self) -> String {
        let stdout = fs::read_to_string(&self.stdout_log).unwrap_or_default();
        let stderr = fs::read_to_string(&self.stderr_log).unwrap_or_default();
        format!(
            "stdout:\n{stdout}\n\nstderr:\n{stderr}\nlog files:\n- {}\n- {}",
            self.stdout_log.display(),
            self.stderr_log.display()
        )
    }
}

impl Drop for SpawnedBinary {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn vsr_serve_starts_native_runtime_from_eon() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("static_site_api.eon");
    fs::copy(fixture_path("static_site_api.eon"), &config).expect("fixture should copy");
    copy_dir_all(&fixture_path("static_site"), &root.join("static_site"));

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            apply_setup_migrations(&database_url, Some(&config))
                .await
                .expect("setup migrations should apply");

            let pool = connect_database(&database_url, Some(&config))
                .await
                .expect("database should connect");
            query("INSERT INTO page (title) VALUES ('Landing page copy')")
                .execute(&pool)
                .await
                .expect("page seed should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve.stdout.log");
    let stderr_log = root.join("serve.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .arg("--without-auth")
        .env("BIND_ADDR", &bind_addr)
        .env("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("vsr serve should start");
    let server = SpawnedBinary::new(child, stdout_log, stderr_log);

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client should build");
    if let Err(error) =
        wait_for_http_ready(&client, &format!("{base_url}/"), Duration::from_secs(30))
    {
        panic!("vsr serve never became ready: {error}\n{}", server.logs());
    }

    let root_response = client
        .get(format!("{base_url}/"))
        .send()
        .expect("root page should load");
    assert!(root_response.status().is_success());
    assert_eq!(
        root_response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let root_body = root_response.text().expect("root body should read");
    assert!(root_body.contains("Static Fixture"));

    let docs_response = client
        .get(format!("{base_url}/docs"))
        .send()
        .expect("docs page should load");
    assert!(docs_response.status().is_success());
    let docs_body = docs_response.text().expect("docs body should read");
    assert!(docs_body.contains("SwaggerUIBundle"));

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert_eq!(openapi["servers"][0]["url"], "/api");
    assert!(openapi["paths"].get("/page").is_some());

    let asset_response = client
        .get(format!("{base_url}/assets/app.js"))
        .send()
        .expect("asset should load");
    assert!(asset_response.status().is_success());
    assert_eq!(
        asset_response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("public, max-age=31536000, immutable")
    );
    let asset_body = asset_response.text().expect("asset body should read");
    assert!(asset_body.contains("static fixture"));

    let api_response = client
        .get(format!("{base_url}/api/page"))
        .send()
        .expect("page list should load");
    assert!(api_response.status().is_success());
    let api_body: Value = api_response.json().expect("page list should decode");
    assert_eq!(api_body["total"], 1);
    assert_eq!(api_body["items"][0]["title"], "Landing page copy");
}
