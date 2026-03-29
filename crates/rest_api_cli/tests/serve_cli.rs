use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use reqwest::blocking::Client;
use rest_macro_core::db::query;
use serde_json::{Value, json};
use uuid::Uuid;
use vsra::commands::db::{connect_database, database_url_from_service_config};
use vsra::commands::migrate::{apply_migrations, apply_setup_migrations, generate_migration};
use vsra::commands::setup::run_setup;
use vsra::commands::tls::generate_self_signed_certificate;

const TEST_TURSO_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn example_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
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

fn http_client() -> Client {
    client(false)
}

fn https_client() -> Client {
    client(true)
}

fn client(accept_invalid_certs: bool) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(0);
    if accept_invalid_certs {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().expect("http client should build")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path).expect("capture file should be readable")
}

fn capture_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = fs::read_dir(dir)
        .expect("capture directory should exist")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn extract_token_from_text(text: &str) -> String {
    let start = text
        .find("token=")
        .expect("email should contain a token parameter")
        + "token=".len();
    text[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .collect()
}

fn extract_url_from_text(text: &str) -> String {
    let start = text
        .find("http://")
        .or_else(|| text.find("https://"))
        .expect("email should contain an absolute URL");
    text[start..]
        .lines()
        .next()
        .expect("email URL line should exist")
        .trim()
        .to_owned()
}

fn path_and_query_from_url(url: &str) -> String {
    let authority_start = url.find("://").map(|index| index + 3).unwrap_or(0);
    let path_start = url[authority_start..]
        .find('/')
        .map(|index| authority_start + index);
    match path_start {
        Some(index) => url[index..].to_owned(),
        None => "/".to_owned(),
    }
}

fn token_from_capture(path: &Path) -> String {
    let body = read_to_string(path);
    let payload: Value = serde_json::from_str(&body).expect("capture file should decode");
    let text_body = payload
        .get("text_body")
        .and_then(Value::as_str)
        .expect("capture payload should contain text_body");
    extract_token_from_text(text_body)
}

fn url_from_capture(path: &Path) -> String {
    let body = read_to_string(path);
    let payload: Value = serde_json::from_str(&body).expect("capture file should decode");
    let text_body = payload
        .get("text_body")
        .and_then(Value::as_str)
        .expect("capture payload should contain text_body");
    extract_url_from_text(text_body)
}

fn wait_for_capture_count(dir: &Path, expected: usize, timeout: Duration) -> Vec<PathBuf> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let files = capture_files(dir);
        if files.len() >= expected {
            return files;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    panic!(
        "expected at least {expected} captured emails in {}, found {}",
        dir.display(),
        capture_files(dir).len()
    );
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
    let migrations_dir = root.join("migrations");
    fs::create_dir_all(&migrations_dir).expect("migrations directory should exist");
    generate_migration(&config, &migrations_dir.join("0001_service.sql"), false)
        .expect("service migration should generate");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            apply_migrations(&database_url, Some(&config), &migrations_dir)
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

    let client = http_client();
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

#[test]
fn vsr_serve_supports_builtin_auth_and_authz_management() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "serve-cli-auth-secret");
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("authz_management_api.eon");
    fs::copy(fixture_path("authz_management_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize auth-enabled service");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-auth.stdout.log");
    let stderr_log = root.join("serve-auth.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "serve-cli-auth-secret")
        .env("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("vsr serve should start");
    let server = SpawnedBinary::new(child, stdout_log, stderr_log);

    let client = http_client();
    if let Err(error) = wait_for_http_ready(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(30),
    ) {
        panic!(
            "vsr serve auth flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert!(openapi["paths"].get("/auth/login").is_some());

    let login_response = client
        .post(format!("{base_url}/api/auth/login"))
        .json(&serde_json::json!({
            "email": "admin@example.com",
            "password": "password123"
        }))
        .send()
        .expect("admin login should succeed");
    assert_eq!(login_response.status(), reqwest::StatusCode::OK);
    let login_body: Value = login_response.json().expect("login body should decode");
    let token = login_body["token"]
        .as_str()
        .expect("login should return a token")
        .to_owned();

    let me_response = client
        .get(format!("{base_url}/api/auth/me"))
        .bearer_auth(&token)
        .send()
        .expect("auth me should load");
    assert_eq!(me_response.status(), reqwest::StatusCode::OK);
    let me_body: Value = me_response.json().expect("auth me should decode");
    let user_id = me_body["id"].as_i64().expect("auth me should include id");
    assert!(user_id > 0);
    let roles = me_body["roles"]
        .as_array()
        .expect("auth me should include roles");
    assert!(roles.iter().any(|value| value == "admin"));

    let create_response = client
        .post(format!("{base_url}/api/authz/runtime/assignments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "user_id": user_id,
            "target": { "kind": "template", "name": "FamilyMember" },
            "scope": { "scope": "Family", "value": "42" },
            "expires_at": (Utc::now() + ChronoDuration::days(1))
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
        }))
        .send()
        .expect("runtime assignment create should succeed");
    assert_eq!(create_response.status(), reqwest::StatusCode::CREATED);
    let created: Value = create_response
        .json()
        .expect("created assignment should decode");
    assert_eq!(created["user_id"], user_id);
    assert_eq!(created["target"]["kind"], "template");
    assert_eq!(created["target"]["name"], "FamilyMember");
    assert_eq!(created["scope"]["scope"], "Family");
    assert_eq!(created["scope"]["value"], "42");

    let list_response = client
        .get(format!(
            "{base_url}/api/authz/runtime/assignments?user_id={user_id}"
        ))
        .bearer_auth(&token)
        .send()
        .expect("runtime assignment list should load");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let listed: Value = list_response.json().expect("assignment list should decode");
    let listed_items = listed
        .as_array()
        .expect("assignment list should be an array");
    assert_eq!(listed_items.len(), 1);
    assert_eq!(listed_items[0]["id"], created["id"]);
}

#[test]
fn vsr_serve_applies_field_transforms_in_spawned_process() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "serve-cli-transform-secret");
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("field_transforms_api.eon");
    fs::copy(fixture_path("field_transforms_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize auth-enabled service");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-transform.stdout.log");
    let stderr_log = root.join("serve-transform.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "serve-cli-transform-secret")
        .env("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("vsr serve should start");
    let server = SpawnedBinary::new(child, stdout_log, stderr_log);

    let client = http_client();
    if let Err(error) = wait_for_http_ready(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(30),
    ) {
        panic!(
            "vsr serve transform flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let login_response = client
        .post(format!("{base_url}/api/auth/login"))
        .json(&json!({
            "email": "admin@example.com",
            "password": "password123"
        }))
        .send()
        .expect("admin login should succeed");
    assert_eq!(login_response.status(), reqwest::StatusCode::OK);
    let login_body: Value = login_response.json().expect("login body should decode");
    let token = login_body["token"]
        .as_str()
        .expect("login should return a token")
        .to_owned();

    let create_response = client
        .post(format!("{base_url}/api/posts"))
        .bearer_auth(&token)
        .json(&json!({
            "slug": "  Hello,   World!  ",
            "status": " DRAFT ",
            "title": {
                "raw": "  Hello   world \n again  ",
                "rendered": "  <p>Hello world</p>  "
            }
        }))
        .send()
        .expect("post create should succeed");
    assert_eq!(create_response.status(), reqwest::StatusCode::CREATED);
    let created: Value = create_response.json().expect("created post should decode");
    assert_eq!(created["slug"], "hello-world");
    assert_eq!(created["status"], "draft");
    assert_eq!(created["title"]["raw"], "Hello world again");
    assert_eq!(created["title"]["rendered"], "<p>Hello world</p>");

    let update_response = client
        .put(format!("{base_url}/api/posts/1"))
        .bearer_auth(&token)
        .json(&json!({
            "slug": "  Next__Post!!!  ",
            "status": " PUBLISHED ",
            "title": {
                "raw": "  Updated   title\t\tagain  ",
                "rendered": "  <p>Updated title</p>  "
            }
        }))
        .send()
        .expect("post update should succeed");
    assert_eq!(update_response.status(), reqwest::StatusCode::OK);

    let get_response = client
        .get(format!("{base_url}/api/posts/1"))
        .send()
        .expect("post get should succeed");
    assert_eq!(get_response.status(), reqwest::StatusCode::OK);
    let updated: Value = get_response.json().expect("updated post should decode");
    assert_eq!(updated["slug"], "next-post");
    assert_eq!(updated["status"], "published");
    assert_eq!(updated["title"]["raw"], "Updated title again");
    assert_eq!(updated["title"]["rendered"], "<p>Updated title</p>");
}

#[test]
fn vsr_setup_bootstraps_env_and_tls_in_spawned_process() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("setup_api.eon");
    fs::write(
        &config,
        r#"
        module: "setup_api"
        database: {
            engine: {
                kind: TursoLocal
                path: "var/data/setup_api.db"
                encryption_key_env: "TURSO_ENCRYPTION_KEY"
            }
        }
        tls: {}
        resources: [
            {
                name: "Note"
                fields: [
                    { name: "id", type: I64, id: true }
                    { name: "title", type: String }
                ]
            }
        ]
        "#,
    )
    .expect("setup fixture should write");

    let output = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("--config")
        .arg(&config)
        .arg("setup")
        .arg("--non-interactive")
        .env_remove("DATABASE_URL")
        .env_remove("TURSO_ENCRYPTION_KEY")
        .env_remove("JWT_SECRET")
        .env_remove("TLS_CERT_PATH")
        .env_remove("TLS_KEY_PATH")
        .env_remove("ADMIN_EMAIL")
        .env_remove("ADMIN_PASSWORD")
        .output()
        .expect("vsr setup should run");

    if !output.status.success() {
        panic!(
            "vsr setup should succeed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let env_path = root.join(".env");
    let cert_path = root.join("certs/dev-cert.pem");
    let key_path = root.join("certs/dev-key.pem");
    let database_path = root.join("var/data/setup_api.db");

    let env_contents = fs::read_to_string(&env_path).expect(".env should exist");
    let turso_line = env_contents
        .lines()
        .find(|line| line.starts_with("TURSO_ENCRYPTION_KEY="))
        .expect("turso encryption key should be written");
    let turso_key = turso_line
        .split_once('=')
        .map(|(_, value)| value)
        .expect("turso key line should split");

    assert!(env_contents.contains("JWT_SECRET="));
    assert_eq!(turso_key.len(), 64);
    assert!(turso_key.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert!(cert_path.exists(), "setup should create a TLS certificate");
    assert!(key_path.exists(), "setup should create a TLS private key");
    assert!(
        database_path.exists(),
        "setup should create the config-relative Turso database"
    );

    assert!(
        stdout.contains("Generated environment file:"),
        "setup output should mention env generation: {stdout}"
    );
    assert!(
        stdout.contains("Generated local Turso encryption key:"),
        "setup output should mention Turso key generation: {stdout}"
    );
    assert!(
        stdout.contains("Loaded environment file for this setup run:"),
        "setup output should mention env loading: {stdout}"
    );
    assert!(
        stdout.contains("Setup summary"),
        "setup output should include the summary: {stdout}"
    );
    assert!(
        stdout.contains("Generated TLS certificate:"),
        "setup output should mention TLS certificate generation: {stdout}"
    );
    assert!(
        stdout.contains("Generated TLS private key:"),
        "setup output should mention TLS private key generation: {stdout}"
    );
    assert!(
        stdout.contains(&env_path.display().to_string()),
        "setup output should include the env path: {stdout}"
    );
    assert!(
        stdout.contains(&cert_path.display().to_string()),
        "setup output should include the TLS certificate path: {stdout}"
    );
    assert!(
        stdout.contains(&key_path.display().to_string()),
        "setup output should include the TLS private key path: {stdout}"
    );
}

#[test]
fn vsr_serve_applies_resource_actions_in_spawned_process() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "serve-cli-action-secret");
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("resource_actions_api.eon");
    fs::copy(fixture_path("resource_actions_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize auth-enabled service");

            let pool = connect_database(&database_url, Some(&config))
                .await
                .expect("database should connect");
            query(
                "INSERT INTO post (id, title, slug, status) VALUES (1, 'Draft', 'draft', 'draft')",
            )
            .execute(&pool)
            .await
            .expect("seed row should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-action.stdout.log");
    let stderr_log = root.join("serve-action.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "serve-cli-action-secret")
        .env("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("vsr serve should start");
    let server = SpawnedBinary::new(child, stdout_log, stderr_log);

    let client = http_client();
    if let Err(error) = wait_for_http_ready(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(30),
    ) {
        panic!(
            "vsr serve action flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let login_response = client
        .post(format!("{base_url}/api/auth/login"))
        .json(&json!({
            "email": "admin@example.com",
            "password": "password123"
        }))
        .send()
        .expect("admin login should succeed");
    assert_eq!(login_response.status(), reqwest::StatusCode::OK);
    let login_body: Value = login_response.json().expect("login body should decode");
    let token = login_body["token"]
        .as_str()
        .expect("login should return a token")
        .to_owned();

    let action_response = client
        .post(format!("{base_url}/api/posts/1/go-live"))
        .bearer_auth(&token)
        .send()
        .expect("action request should succeed");
    assert_eq!(action_response.status(), reqwest::StatusCode::OK);
    assert_eq!(action_response.text().expect("action body should read"), "");

    let rename_response = client
        .post(format!("{base_url}/api/posts/1/rename"))
        .bearer_auth(&token)
        .json(&json!({
            "newTitle": "Fresh Launch",
            "newSlug": " Fresh   Launch! ",
            "newStatus": " REVIEW "
        }))
        .send()
        .expect("rename action request should succeed");
    assert_eq!(rename_response.status(), reqwest::StatusCode::OK);
    assert_eq!(rename_response.text().expect("rename body should read"), "");

    let invalid_rename_response = client
        .post(format!("{base_url}/api/posts/1/rename"))
        .bearer_auth(&token)
        .json(&json!({
            "newTitle": "bad",
            "newSlug": "still-valid",
            "newStatus": "draft"
        }))
        .send()
        .expect("invalid rename action request should respond");
    assert_eq!(
        invalid_rename_response.status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let invalid_rename_body: Value = invalid_rename_response
        .json()
        .expect("invalid rename body should decode");
    assert_eq!(invalid_rename_body["code"], "validation_error");
    assert_eq!(invalid_rename_body["field"], "newTitle");

    let get_response = client
        .get(format!("{base_url}/api/posts/1"))
        .send()
        .expect("post fetch should succeed");
    assert_eq!(get_response.status(), reqwest::StatusCode::OK);
    let fetched: Value = get_response.json().expect("fetched post should decode");
    assert_eq!(fetched["title"], "Fresh Launch");
    assert_eq!(fetched["slug"], "fresh-launch");
    assert_eq!(fetched["status"], "review");

    let purge_response = client
        .post(format!("{base_url}/api/posts/1/purge"))
        .bearer_auth(&token)
        .send()
        .expect("purge action request should succeed");
    assert_eq!(purge_response.status(), reqwest::StatusCode::OK);

    let missing_response = client
        .get(format!("{base_url}/api/posts/1"))
        .send()
        .expect("missing get request should respond");
    assert_eq!(missing_response.status(), reqwest::StatusCode::NOT_FOUND);
}

#[test]
fn vsr_server_serve_subcommand_starts_native_runtime() {
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
            query("INSERT INTO page (title) VALUES ('Alias page copy')")
                .execute(&pool)
                .await
                .expect("page seed should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("server-serve.stdout.log");
    let stderr_log = root.join("server-serve.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("server")
        .arg("serve")
        .arg("--input")
        .arg(&config)
        .arg("--without-auth")
        .env("BIND_ADDR", &bind_addr)
        .env("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("vsr server serve should start");
    let server = SpawnedBinary::new(child, stdout_log, stderr_log);

    let client = http_client();
    if let Err(error) =
        wait_for_http_ready(&client, &format!("{base_url}/"), Duration::from_secs(30))
    {
        panic!(
            "vsr server serve never became ready: {error}\n{}",
            server.logs()
        );
    }

    let root_response = client
        .get(format!("{base_url}/"))
        .send()
        .expect("root page should load");
    assert!(root_response.status().is_success());

    let api_response = client
        .get(format!("{base_url}/api/page"))
        .send()
        .expect("page list should load");
    assert!(api_response.status().is_success());
    let api_body: Value = api_response.json().expect("page list should decode");
    assert_eq!(api_body["total"], 1);
    assert_eq!(api_body["items"][0]["title"], "Alias page copy");
}

#[test]
fn vsr_serve_bridgeboard_example_supports_clean_room_e2e() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());

    let root = test_root();
    let capture_dir = root.join("capture");
    fs::create_dir_all(&capture_dir).expect("capture directory should exist");
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "bridgeboard-serve-secret");
        std::env::set_var("VSR_AUTH_EMAIL_CAPTURE_DIR", &capture_dir);
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
    }

    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("bridgeboard.eon");
    fs::copy(example_path("bridgeboard/bridgeboard.eon"), &config).expect("example should copy");
    copy_dir_all(&example_path("bridgeboard/public"), &root.join("public"));
    generate_self_signed_certificate(Some(&config), None, None, &[], false)
        .expect("self-signed bridgeboard certs should generate");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize the bridgeboard database");
        });

    assert!(
        root.join("var/data/bridgeboard.db").exists(),
        "setup should create the config-relative bridgeboard database"
    );
    assert!(
        !root.join("app.db").exists(),
        "setup should not create a stray app.db alongside native serve fixtures"
    );

    let bind_addr = free_bind_addr();
    let base_url = format!("https://{bind_addr}");
    let stdout_log = root.join("bridgeboard-serve.stdout.log");
    let stderr_log = root.join("bridgeboard-serve.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "bridgeboard-serve-secret")
        .env("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY)
        .env("VSR_AUTH_EMAIL_CAPTURE_DIR", &capture_dir)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("vsr serve should start");
    let server = SpawnedBinary::new(child, stdout_log, stderr_log);

    let client = https_client();
    if let Err(error) =
        wait_for_http_ready(&client, &format!("{base_url}/"), Duration::from_secs(30))
    {
        panic!(
            "bridgeboard native serve never became ready: {error}\n{}",
            server.logs()
        );
    }

    let root_response = client
        .get(format!("{base_url}/"))
        .send()
        .expect("root page should load");
    assert!(root_response.status().is_success());
    let root_body = root_response.text().expect("root page body should read");
    assert!(root_body.contains("Bridgeboard"));

    let app_js_response = client
        .get(format!("{base_url}/app.js"))
        .send()
        .expect("app.js should load");
    assert!(app_js_response.status().is_success());

    let public_catalog_response = client
        .get(format!("{base_url}/api/organization"))
        .send()
        .expect("organization list should load");
    assert!(public_catalog_response.status().is_success());
    let public_catalog: Value = public_catalog_response
        .json()
        .expect("organization list should decode");
    assert_eq!(public_catalog.get("total").and_then(Value::as_i64), Some(0));

    let admin_login_response = client
        .post(format!("{base_url}/api/auth/login"))
        .json(&json!({
            "email": "admin@example.com",
            "password": "password123",
        }))
        .send()
        .expect("admin login should succeed");
    assert_eq!(admin_login_response.status(), reqwest::StatusCode::OK);
    let admin_login: Value = admin_login_response
        .json()
        .expect("admin login response should decode");
    let admin_token = admin_login
        .get("token")
        .and_then(Value::as_str)
        .expect("admin login should return a token")
        .to_owned();

    let create_org_response = client
        .post(format!("{base_url}/api/organization"))
        .bearer_auth(&admin_token)
        .json(&json!({
            "slug": "nordic-bridge",
            "name": "Nordic Bridge Institute",
            "country": "Finland",
            "city": "Oulu",
            "website_url": "https://bridge.example",
            "contact_email": "hello@bridge.example",
            "collaboration_stage": "Open call",
            "summary": "Coordinates cross-border thesis work between applied research labs and regional industry partners."
        }))
        .send()
        .expect("organization create should succeed");
    assert_eq!(create_org_response.status(), reqwest::StatusCode::CREATED);
    let organization_location = create_org_response
        .headers()
        .get("Location")
        .and_then(|value| value.to_str().ok())
        .expect("organization create should expose a location")
        .to_owned();
    let organization: Value = create_org_response
        .json()
        .expect("organization create response should decode");
    let organization_id = organization
        .get("id")
        .and_then(Value::as_i64)
        .expect("organization create should return an id");
    assert_eq!(
        organization_location,
        format!("/api/organization/{organization_id}")
    );

    let register_response = client
        .post(format!("{base_url}/api/auth/register"))
        .json(&json!({
            "email": "alice@example.com",
            "password": "password123",
        }))
        .send()
        .expect("user registration should succeed");
    assert_eq!(register_response.status(), reqwest::StatusCode::CREATED);

    let captured = wait_for_capture_count(&capture_dir, 1, Duration::from_secs(10));
    let verification_token = token_from_capture(&captured[0]);

    let verify_response = client
        .post(format!("{base_url}/api/auth/verify-email"))
        .json(&json!({ "token": verification_token }))
        .send()
        .expect("email verification should succeed");
    assert_eq!(verify_response.status(), reqwest::StatusCode::NO_CONTENT);

    let user_login_response = client
        .post(format!("{base_url}/api/auth/login"))
        .json(&json!({
            "email": "alice@example.com",
            "password": "password123",
        }))
        .send()
        .expect("verified user login should succeed");
    assert_eq!(user_login_response.status(), reqwest::StatusCode::OK);

    let password_reset_response = client
        .post(format!("{base_url}/api/auth/password-reset/request"))
        .json(&json!({
            "email": "alice@example.com",
        }))
        .send()
        .expect("password reset request should succeed");
    assert_eq!(
        password_reset_response.status(),
        reqwest::StatusCode::ACCEPTED
    );

    let captured = wait_for_capture_count(&capture_dir, 2, Duration::from_secs(10));
    let reset_capture = captured
        .iter()
        .find(|path| url_from_capture(path).contains("/password-reset?token="))
        .expect("reset email should be captured");
    let reset_token = token_from_capture(reset_capture);
    let reset_url = url_from_capture(reset_capture);
    let reset_path_and_query = path_and_query_from_url(&reset_url);
    assert!(
        reset_path_and_query.starts_with("/api/auth/password-reset?token="),
        "unexpected reset link path: {reset_path_and_query}"
    );

    let reset_page_response = client
        .get(format!("{base_url}{reset_path_and_query}"))
        .send()
        .expect("password reset page should load");
    assert_eq!(reset_page_response.status(), reqwest::StatusCode::OK);
    let reset_page_body = reset_page_response
        .text()
        .expect("password reset page body should read");
    assert!(reset_page_body.contains("Choose A New Password"));

    let confirm_reset_response = client
        .post(format!("{base_url}/api/auth/password-reset/confirm"))
        .json(&json!({
            "token": reset_token,
            "new_password": "password456",
        }))
        .send()
        .expect("password reset confirmation should succeed");
    assert_eq!(
        confirm_reset_response.status(),
        reqwest::StatusCode::NO_CONTENT
    );

    let old_password_login_response = client
        .post(format!("{base_url}/api/auth/login"))
        .json(&json!({
            "email": "alice@example.com",
            "password": "password123",
        }))
        .send()
        .expect("old password login response should return");
    assert_eq!(
        old_password_login_response.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    let user_login_response = client
        .post(format!("{base_url}/api/auth/login"))
        .json(&json!({
            "email": "alice@example.com",
            "password": "password456",
        }))
        .send()
        .expect("login with reset password should succeed");
    assert_eq!(user_login_response.status(), reqwest::StatusCode::OK);
    let user_login: Value = user_login_response
        .json()
        .expect("user login response should decode");
    let user_token = user_login
        .get("token")
        .and_then(Value::as_str)
        .expect("reset-password login should return a token")
        .to_owned();

    let create_request_response = client
        .post(format!("{base_url}/api/collaboration_request"))
        .bearer_auth(&user_token)
        .json(&json!({
            "organization_id": organization_id,
            "title": "Applied AI thesis partnership",
            "message": "We want to connect a student team with the organization to shape a shared supervision track around applied AI validation.",
            "status": "submitted",
            "preferred_start_on": "2026-09-15"
        }))
        .send()
        .expect("collaboration request create should succeed");
    assert_eq!(
        create_request_response.status(),
        reqwest::StatusCode::CREATED
    );
    let request_location = create_request_response
        .headers()
        .get("Location")
        .and_then(|value| value.to_str().ok())
        .expect("collaboration request create should expose a location")
        .to_owned();
    let collaboration_request: Value = create_request_response
        .json()
        .expect("collaboration request response should decode");
    let request_id = collaboration_request
        .get("id")
        .and_then(Value::as_i64)
        .expect("collaboration request should include an id");
    assert_eq!(
        collaboration_request
            .get("requester_user_id")
            .and_then(Value::as_i64),
        Some(2)
    );
    assert_eq!(
        request_location,
        format!("/api/collaboration_request/{request_id}")
    );

    let admin_requests_response = client
        .get(format!("{base_url}/api/collaboration_request"))
        .bearer_auth(&admin_token)
        .send()
        .expect("admin should be able to list collaboration requests");
    assert_eq!(admin_requests_response.status(), reqwest::StatusCode::OK);
    let admin_requests: Value = admin_requests_response
        .json()
        .expect("admin collaboration list should decode");
    assert_eq!(admin_requests.get("total").and_then(Value::as_i64), Some(1));

    let portal_response = client
        .get(format!("{base_url}/api/auth/portal"))
        .send()
        .expect("account portal should load");
    assert_eq!(portal_response.status(), reqwest::StatusCode::OK);
    let portal_body = portal_response.text().expect("portal body should read");
    assert!(portal_body.contains("Bridgeboard Account"));

    let dashboard_response = client
        .get(format!("{base_url}/api/auth/admin"))
        .bearer_auth(&admin_token)
        .send()
        .expect("admin dashboard should load");
    assert_eq!(dashboard_response.status(), reqwest::StatusCode::OK);
}

#[test]
fn vsr_serve_rejects_service_owned_user_table_with_builtin_auth() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");
    let config = root.join("user_table_api.eon");
    fs::copy(fixture_path("user_table_api.eon"), &config).expect("fixture should copy");

    let output = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .output()
        .expect("vsr serve should return an error");

    assert!(
        !output.status.success(),
        "serve should reject built-in auth"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("re-run with `--without-auth`"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn vsr_serve_supports_service_owned_user_table_without_builtin_auth() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");
    let config = root.join("user_table_api.eon");
    fs::copy(fixture_path("user_table_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    let migrations_dir = root.join("migrations");
    fs::create_dir_all(&migrations_dir).expect("migrations directory should exist");
    generate_migration(&config, &migrations_dir.join("0001_service.sql"), false)
        .expect("service migration should generate");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            apply_migrations(&database_url, Some(&config), &migrations_dir)
                .await
                .expect("setup migrations should apply");

            let pool = connect_database(&database_url, Some(&config))
                .await
                .expect("database should connect");
            query("INSERT INTO user (email) VALUES ('owner@example.com')")
                .execute(&pool)
                .await
                .expect("user seed should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("user-table.stdout.log");
    let stderr_log = root.join("user-table.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .arg("--without-auth")
        .env("BIND_ADDR", &bind_addr)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("vsr serve should start");
    let server = SpawnedBinary::new(child, stdout_log, stderr_log);

    let client = http_client();
    if let Err(error) = wait_for_http_ready(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(30),
    ) {
        panic!(
            "user-table native serve never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert!(openapi["paths"].get("/user").is_some());
    assert!(openapi["paths"].get("/auth/login").is_none());

    let user_list_response = client
        .get(format!("{base_url}/api/user"))
        .send()
        .expect("user list should load");
    assert!(user_list_response.status().is_success());
    let users: Value = user_list_response.json().expect("user list should decode");
    assert_eq!(users["total"], 1);
    assert_eq!(users["items"][0]["email"], "owner@example.com");
}
