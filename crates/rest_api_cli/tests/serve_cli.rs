use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use reqwest::blocking::Client;
use rest_macro_core::db::query;
use rest_macro_core::security::{
    DEFAULT_ANON_CLIENT_FALLBACK_KEY, DEFAULT_ANON_CLIENT_HEADER_NAME,
};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;
use vsra::commands::db::{connect_database, database_url_from_service_config};
use vsra::commands::migrate::{apply_migrations, apply_setup_migrations, generate_migration};
use vsra::commands::setup::run_setup;
use vsra::commands::tls::generate_self_signed_certificate;

const TEST_TURSO_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_ED25519_PRIVATE_KEY_CURRENT: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICan3gTz94CxAFR90FubWnI1S7Hu81HAawRP0JnhgJd1\n-----END PRIVATE KEY-----\n";
const TEST_ED25519_PUBLIC_KEY_CURRENT: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA6SXZeouSZ6gAAGu0fq5MlKZt7T0z0mf3pK1NmaIWqi4=\n-----END PUBLIC KEY-----\n";
const TEST_ED25519_PUBLIC_KEY_PREVIOUS: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAMtHpnFKVCrgrEn+eT5L9XptGRw7nq2RZy5ZsM6TdS1Q=\n-----END PUBLIC KEY-----\n";

#[derive(Serialize)]
struct TestBearerClaims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

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

fn wait_for_http_stopped(client: &Client, url: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut last_status = None;

    while Instant::now() < deadline {
        match client.get(url).send() {
            Ok(response) if response.status().is_success() => {
                last_status = Some(format!("server still responded with {}", response.status()));
            }
            Ok(_response) => return Ok(()),
            Err(_) => return Ok(()),
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    Err(last_status.unwrap_or_else(|| "server never stopped".to_owned()))
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
        .pool_max_idle_per_host(0)
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::HeaderName::from_static(DEFAULT_ANON_CLIENT_HEADER_NAME),
                reqwest::header::HeaderValue::from_static(DEFAULT_ANON_CLIENT_FALLBACK_KEY),
            );
            headers
        });
    if accept_invalid_certs {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().expect("http client should build")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path).expect("capture file should be readable")
}

fn write_secret_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, contents).expect("secret file should write");
    path
}

fn issue_hs256_token(secret: &str, user_id: i64, roles: &[&str]) -> String {
    encode(
        &Header::default(),
        &TestBearerClaims {
            sub: user_id,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            exp: 4_102_444_800,
        },
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("test token should encode")
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

fn multipart_upload_payload(file_name: &str, body: &[u8]) -> (String, Vec<u8>) {
    let boundary = "----vsr-storage-upload";
    let mut payload = Vec::new();
    payload.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{file_name}\"\r\nContent-Type: text/plain\r\n\r\n"
        )
        .as_bytes(),
    );
    payload.extend_from_slice(body);
    payload.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), payload)
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

#[cfg(windows)]
struct SpawnedPidGuard {
    pid: u32,
}

#[cfg(windows)]
impl Drop for SpawnedPidGuard {
    fn drop(&mut self) {
        let _ = Command::new("taskkill")
            .args(["/PID", &self.pid.to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn command_output_logs(output: &Output) -> String {
    format!(
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn extract_background_pid(stdout: &str) -> u32 {
    let pid_start = stdout
        .find("(pid ")
        .expect("background serve output should include a pid")
        + "(pid ".len();
    let pid_end = stdout[pid_start..]
        .find(')')
        .map(|index| pid_start + index)
        .expect("background serve output should close the pid marker");
    stdout[pid_start..pid_end]
        .trim()
        .parse()
        .expect("background pid should parse")
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

#[cfg(windows)]
#[test]
fn vsr_serve_stops_when_parent_process_exits() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("public_catalog_api.eon");
    fs::copy(fixture_path("public_catalog_api.eon"), &config).expect("fixture should copy");

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let launcher = root.join("launch_parent.ps1");
    let pid_file = root.join("serve.pid");
    let child_stdout_log = root.join("serve.stdout.log");
    let child_stderr_log = root.join("serve.stderr.log");
    let parent_stdout_log = root.join("parent.stdout.log");
    let parent_stderr_log = root.join("parent.stderr.log");
    let vsr_path = PathBuf::from(env!("CARGO_BIN_EXE_vsr"));

    let launcher_body = format!(
        "\
$env:TURSO_ENCRYPTION_KEY = '{turso_key}'\n\
$child = Start-Process -FilePath '{vsr}' -ArgumentList @('serve','{config}','--without-auth','--bind-addr','{bind_addr}') -WorkingDirectory '{root}' -RedirectStandardOutput '{child_stdout}' -RedirectStandardError '{child_stderr}' -PassThru\n\
Set-Content -Path '{pid_file}' -Value $child.Id\n\
Wait-Process -Id $child.Id\n",
        turso_key = TEST_TURSO_KEY,
        vsr = vsr_path.display().to_string().replace('\'', "''"),
        config = config.display().to_string().replace('\'', "''"),
        bind_addr = bind_addr,
        root = root.display().to_string().replace('\'', "''"),
        child_stdout = child_stdout_log.display().to_string().replace('\'', "''"),
        child_stderr = child_stderr_log.display().to_string().replace('\'', "''"),
        pid_file = pid_file.display().to_string().replace('\'', "''"),
    );
    fs::write(&launcher, launcher_body).expect("launcher should write");

    let parent_stdout =
        fs::File::create(&parent_stdout_log).expect("parent stdout log should open");
    let parent_stderr =
        fs::File::create(&parent_stderr_log).expect("parent stderr log should open");
    let child = Command::new("powershell.exe")
        .current_dir(&root)
        .arg("-NoProfile")
        .arg("-File")
        .arg(&launcher)
        .stdout(Stdio::from(parent_stdout))
        .stderr(Stdio::from(parent_stderr))
        .spawn()
        .expect("launcher parent should start");
    let mut parent =
        SpawnedBinary::new(child, parent_stdout_log.clone(), parent_stderr_log.clone());

    let deadline = Instant::now() + Duration::from_secs(10);
    while !pid_file.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        pid_file.exists(),
        "launcher never wrote child pid\n{}",
        parent.logs()
    );
    let child_pid: u32 = fs::read_to_string(&pid_file)
        .expect("pid file should read")
        .trim()
        .parse()
        .expect("pid should parse");
    let _child_guard = SpawnedPidGuard { pid: child_pid };

    let client = http_client();
    if let Err(error) = wait_for_http_ready(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(30),
    ) {
        panic!(
            "vsr serve never became ready: {error}\nparent logs:\n{}\nchild stdout:\n{}\nchild stderr:\n{}",
            parent.logs(),
            fs::read_to_string(&child_stdout_log).unwrap_or_default(),
            fs::read_to_string(&child_stderr_log).unwrap_or_default(),
        );
    }

    parent
        .child
        .kill()
        .expect("launcher parent should be killable");
    let _ = parent.child.wait();

    if let Err(error) = wait_for_http_stopped(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(15),
    ) {
        panic!(
            "server still responded after parent exit: {error}\nparent logs:\n{}\nchild stdout:\n{}\nchild stderr:\n{}",
            parent.logs(),
            fs::read_to_string(&child_stdout_log).unwrap_or_default(),
            fs::read_to_string(&child_stderr_log).unwrap_or_default(),
        );
    }
}

#[test]
fn vsr_serve_bg_supports_status_kill_and_reset() {
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
            query("INSERT INTO page (title) VALUES ('Background page copy')")
                .execute(&pool)
                .await
                .expect("page seed should insert");
        });
    fs::create_dir_all(root.join("var")).expect("var dir should exist");
    fs::write(root.join("var/marker.txt"), "marker").expect("marker file should write");
    fs::write(root.join("keep.txt"), "keep").expect("keep file should write");

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let start_output = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .arg("--without-auth")
        .arg("--bg")
        .arg("--bind-addr")
        .arg(&bind_addr)
        .env("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY)
        .output()
        .expect("background serve should start");
    assert!(
        start_output.status.success(),
        "{}",
        command_output_logs(&start_output)
    );
    let start_stdout = String::from_utf8_lossy(&start_output.stdout);
    let child_pid = extract_background_pid(&start_stdout);
    #[cfg(windows)]
    let _child_guard = SpawnedPidGuard { pid: child_pid };

    let client = http_client();
    if let Err(error) = wait_for_http_ready(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(30),
    ) {
        panic!(
            "background serve never became ready: {error}\n{}",
            command_output_logs(&start_output)
        );
    }

    let status_output = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("status")
        .arg("--input")
        .arg(&config)
        .output()
        .expect("status should run");
    assert!(
        status_output.status.success(),
        "{}",
        command_output_logs(&status_output)
    );
    let status_stdout = String::from_utf8_lossy(&status_output.stdout);
    assert!(status_stdout.contains("[background]"));
    assert!(status_stdout.contains(&bind_addr));
    assert!(status_stdout.contains("static_site_api"));

    let reset_while_running = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("reset")
        .arg("--input")
        .arg(&config)
        .arg("--accept-permanent-data-loss")
        .output()
        .expect("reset should run");
    assert!(
        !reset_while_running.status.success(),
        "{}",
        command_output_logs(&reset_while_running)
    );
    let reset_stderr = String::from_utf8_lossy(&reset_while_running.stderr);
    assert!(
        reset_stderr.contains("Refusing to reset while tracked serve instances are still running")
    );

    let kill_output = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("kill")
        .arg("--input")
        .arg(&config)
        .arg("--force")
        .output()
        .expect("kill should run");
    assert!(
        kill_output.status.success(),
        "{}",
        command_output_logs(&kill_output)
    );
    let kill_stdout = String::from_utf8_lossy(&kill_output.stdout);
    assert!(kill_stdout.contains("Stopped background instance"));

    if let Err(error) = wait_for_http_stopped(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(15),
    ) {
        panic!(
            "background serve never stopped after kill: {error}\n{}",
            command_output_logs(&kill_output)
        );
    }

    let reset_output = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("reset")
        .arg("--input")
        .arg(&config)
        .arg("--accept-permanent-data-loss")
        .output()
        .expect("reset should run");
    assert!(
        reset_output.status.success(),
        "{}",
        command_output_logs(&reset_output)
    );
    assert!(
        !root.join("var").exists(),
        "reset should remove var directory"
    );
    assert!(
        root.join("keep.txt").is_file(),
        "reset should not touch unrelated files"
    );

    let final_status_output = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("status")
        .arg("--input")
        .arg(&config)
        .output()
        .expect("final status should run");
    assert!(
        final_status_output.status.success(),
        "{}",
        command_output_logs(&final_status_output)
    );
    assert!(
        String::from_utf8_lossy(&final_status_output.stdout)
            .contains("No tracked serve instances.")
    );
}

#[test]
fn vsr_serve_loads_service_local_env_from_config_directory() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("DATABASE_URL_FILE");
        std::env::remove_var("JWT_SECRET");
        std::env::remove_var("JWT_SECRET_FILE");
        std::env::remove_var("ADMIN_EMAIL");
        std::env::remove_var("ADMIN_PASSWORD");
    }

    let root = test_root();
    let service_dir = root.join("service");
    let launch_dir = root.join("launch");
    fs::create_dir_all(&service_dir).expect("service directory should exist");
    fs::create_dir_all(&launch_dir).expect("launch directory should exist");

    let config = service_dir.join("authz_management_api.eon");
    fs::copy(fixture_path("authz_management_api.eon"), &config).expect("fixture should copy");
    fs::write(
        service_dir.join(".env"),
        "JWT_SECRET=service-local-serve-secret\nADMIN_EMAIL=admin@example.com\nADMIN_PASSWORD=password123\n",
    )
    .expect("service env file should write");

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
    let stdout_log = root.join("serve-service-env.stdout.log");
    let stderr_log = root.join("serve-service-env.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&launch_dir)
        .arg("serve")
        .arg(&config)
        .arg("--bind-addr")
        .arg(&bind_addr)
        .env_remove("DATABASE_URL")
        .env_remove("DATABASE_URL_FILE")
        .env_remove("JWT_SECRET")
        .env_remove("JWT_SECRET_FILE")
        .env_remove("ADMIN_EMAIL")
        .env_remove("ADMIN_PASSWORD")
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
            "vsr serve with service-local env never became ready: {error}\n{}",
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
        .expect("login should respond");
    assert!(login_response.status().is_success(), "{}", server.logs());

    unsafe {
        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("DATABASE_URL_FILE");
        std::env::remove_var("JWT_SECRET");
        std::env::remove_var("JWT_SECRET_FILE");
        std::env::remove_var("ADMIN_EMAIL");
        std::env::remove_var("ADMIN_PASSWORD");
    }
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

    let unauthenticated_client = Client::builder()
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(0)
        .build()
        .expect("bare http client should build");
    let docs_response = unauthenticated_client
        .get(format!("{base_url}/docs"))
        .send()
        .expect("docs page should load");
    assert!(docs_response.status().is_success());
    let public_openapi_response = unauthenticated_client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi probe should execute");
    assert!(public_openapi_response.status().is_success());
    let missing_anon_list = unauthenticated_client
        .get(format!("{base_url}/api/organization"))
        .send()
        .expect("anonymous list probe should execute");
    assert_eq!(
        missing_anon_list.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

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
fn vsr_serve_supports_builtin_auth_portal_dashboard_and_admin_users() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "serve-cli-auth-management-secret");
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("auth_management_api.eon");
    fs::copy(fixture_path("auth_management_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize auth management service");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-auth-management.stdout.log");
    let stderr_log = root.join("serve-auth-management.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "serve-cli-auth-management-secret")
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
            "vsr serve auth management flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert!(openapi["paths"].get("/auth/portal").is_some());
    assert!(openapi["paths"].get("/auth/admin").is_some());
    assert!(openapi["paths"].get("/auth/admin/users").is_some());
    assert!(openapi["paths"].get("/auth/admin/users/{id}").is_some());
    assert!(
        openapi["paths"]
            .get("/auth/admin/users/{id}/verification")
            .is_some()
    );

    let portal_response = client
        .get(format!("{base_url}/api/auth/portal"))
        .send()
        .expect("account portal should load");
    assert_eq!(portal_response.status(), reqwest::StatusCode::OK);
    let portal_body = portal_response.text().expect("portal body should read");
    assert!(portal_body.contains("Account Portal"));

    let unauthorized_admin_page = client
        .get(format!("{base_url}/api/auth/admin"))
        .send()
        .expect("admin page should respond");
    assert_eq!(
        unauthorized_admin_page.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

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

    let admin_page_response = client
        .get(format!("{base_url}/api/auth/admin"))
        .bearer_auth(&token)
        .send()
        .expect("admin dashboard should load");
    assert_eq!(admin_page_response.status(), reqwest::StatusCode::OK);
    let admin_page_body = admin_page_response
        .text()
        .expect("admin dashboard body should read");
    assert!(admin_page_body.contains("Admin Dashboard"));
    assert!(admin_page_body.contains("Create user"));

    let create_response = client
        .post(format!("{base_url}/api/auth/admin/users"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "email": "carol@example.com",
            "password": "password789",
            "role": "reviewer",
            "email_verified": false,
            "send_verification_email": false
        }))
        .send()
        .expect("managed user create should succeed");
    assert_eq!(create_response.status(), reqwest::StatusCode::CREATED);
    let location = create_response
        .headers()
        .get("Location")
        .and_then(|value| value.to_str().ok())
        .expect("managed user create should expose Location")
        .to_owned();
    let created_user: Value = create_response
        .json()
        .expect("managed user response should decode");
    let created_id = created_user["id"]
        .as_i64()
        .expect("created managed user should include id");
    assert_eq!(created_user["email"], "carol@example.com");
    assert_eq!(created_user["role"], "reviewer");
    assert_eq!(created_user["email_verified"], false);
    assert_eq!(location, format!("/api/auth/admin/users/{created_id}"));

    let list_response = client
        .get(format!(
            "{base_url}/api/auth/admin/users?email=carol@example.com&limit=10&offset=0"
        ))
        .bearer_auth(&token)
        .send()
        .expect("managed user list should load");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let listed: Value = list_response
        .json()
        .expect("managed user list should decode");
    let listed_items = listed["items"]
        .as_array()
        .expect("managed user list should be an array");
    assert_eq!(listed["limit"], 10);
    assert_eq!(listed["offset"], 0);
    assert_eq!(listed_items.len(), 1);
    assert_eq!(listed_items[0]["id"], created_id);

    let patch_response = client
        .patch(format!("{base_url}/api/auth/admin/users/{created_id}"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "role": "moderator",
            "email_verified": true
        }))
        .send()
        .expect("managed user update should succeed");
    assert_eq!(patch_response.status(), reqwest::StatusCode::OK);
    let patched_user: Value = patch_response
        .json()
        .expect("managed user update should decode");
    assert_eq!(patched_user["id"], created_id);
    assert_eq!(patched_user["role"], "moderator");
    assert_eq!(patched_user["email_verified"], true);

    let get_response = client
        .get(format!("{base_url}/api/auth/admin/users/{created_id}"))
        .bearer_auth(&token)
        .send()
        .expect("managed user should load");
    assert_eq!(get_response.status(), reqwest::StatusCode::OK);
    let loaded_user: Value = get_response.json().expect("managed user should decode");
    assert_eq!(loaded_user["id"], created_id);
    assert_eq!(loaded_user["role"], "moderator");
    assert_eq!(loaded_user["email_verified"], true);

    let delete_response = client
        .delete(format!("{base_url}/api/auth/admin/users/{created_id}"))
        .bearer_auth(&token)
        .send()
        .expect("managed user delete should succeed");
    assert_eq!(delete_response.status(), reqwest::StatusCode::NO_CONTENT);

    let missing_response = client
        .get(format!("{base_url}/api/auth/admin/users/{created_id}"))
        .bearer_auth(&token)
        .send()
        .expect("deleted managed user lookup should respond");
    assert_eq!(missing_response.status(), reqwest::StatusCode::NOT_FOUND);
}

#[test]
fn vsr_serve_supports_admin_verification_resend_and_auth_email_pages() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    let root = test_root();
    let capture_dir = root.join("capture");
    fs::create_dir_all(&capture_dir).expect("capture directory should exist");
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "serve-cli-auth-email-secret");
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
        std::env::set_var("VSR_AUTH_EMAIL_CAPTURE_DIR", &capture_dir);
    }

    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("auth_management_api.eon");
    fs::copy(fixture_path("auth_management_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize auth management service");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-auth-email.stdout.log");
    let stderr_log = root.join("serve-auth-email.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "serve-cli-auth-email-secret")
        .env("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY)
        .env("VSR_AUTH_EMAIL_CAPTURE_DIR", &capture_dir)
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
            "vsr serve auth email flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    for path in [
        "/auth/account/verification",
        "/auth/verify-email",
        "/auth/verification/resend",
        "/auth/password-reset",
        "/auth/password-reset/request",
        "/auth/password-reset/confirm",
    ] {
        assert!(
            openapi["paths"].get(path).is_some(),
            "openapi should document {path}"
        );
    }

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

    let create_response = client
        .post(format!("{base_url}/api/auth/admin/users"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "email": "pending@example.com",
            "password": "password789",
            "role": "reviewer",
            "email_verified": false,
            "send_verification_email": false
        }))
        .send()
        .expect("managed user create should succeed");
    assert_eq!(create_response.status(), reqwest::StatusCode::CREATED);
    let created_user: Value = create_response
        .json()
        .expect("managed user response should decode");
    let created_id = created_user["id"]
        .as_i64()
        .expect("created managed user should include id");

    let resend_response = client
        .post(format!(
            "{base_url}/api/auth/admin/users/{created_id}/verification"
        ))
        .bearer_auth(&token)
        .send()
        .expect("managed user verification resend should succeed");
    assert_eq!(resend_response.status(), reqwest::StatusCode::ACCEPTED);

    let captured = wait_for_capture_count(&capture_dir, 1, Duration::from_secs(10));
    let verification_url = url_from_capture(&captured[0]);
    let verification_path = path_and_query_from_url(&verification_url);
    assert!(
        verification_path.starts_with("/api/auth/verify-email?token="),
        "unexpected verification url: {verification_url}"
    );

    let verify_page_response = client
        .get(format!("{base_url}{verification_path}"))
        .send()
        .expect("verify email page should load");
    assert_eq!(verify_page_response.status(), reqwest::StatusCode::OK);
    let verify_page_body = verify_page_response
        .text()
        .expect("verify email page body should read");
    assert!(verify_page_body.contains("Email Verified"));

    let verified_login_response = client
        .post(format!("{base_url}/api/auth/login"))
        .json(&serde_json::json!({
            "email": "pending@example.com",
            "password": "password789"
        }))
        .send()
        .expect("verified managed user login should succeed");
    assert_eq!(verified_login_response.status(), reqwest::StatusCode::OK);
    let verified_login_body: Value = verified_login_response
        .json()
        .expect("verified managed user login should decode");
    let verified_token = verified_login_body["token"]
        .as_str()
        .expect("verified managed user login should return a token")
        .to_owned();

    let account_resend_response = client
        .post(format!("{base_url}/api/auth/account/verification"))
        .bearer_auth(&verified_token)
        .send()
        .expect("authenticated account resend should respond");
    assert_eq!(
        account_resend_response.status(),
        reqwest::StatusCode::NO_CONTENT
    );

    let password_reset_response = client
        .post(format!("{base_url}/api/auth/password-reset/request"))
        .json(&serde_json::json!({
            "email": "pending@example.com"
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
    let reset_path = path_and_query_from_url(&reset_url);
    assert!(
        reset_path.starts_with("/api/auth/password-reset?token="),
        "unexpected password reset url: {reset_url}"
    );

    let reset_page_response = client
        .get(format!("{base_url}{reset_path}"))
        .send()
        .expect("password reset page should load");
    assert_eq!(reset_page_response.status(), reqwest::StatusCode::OK);
    let reset_page_body = reset_page_response
        .text()
        .expect("password reset page body should read");
    assert!(reset_page_body.contains("Choose A New Password"));

    let confirm_reset_response = client
        .post(format!("{base_url}/api/auth/password-reset/confirm"))
        .json(&serde_json::json!({
            "token": reset_token,
            "new_password": "password456"
        }))
        .send()
        .expect("password reset confirmation should succeed");
    assert_eq!(
        confirm_reset_response.status(),
        reqwest::StatusCode::NO_CONTENT
    );

    let old_password_login_response = client
        .post(format!("{base_url}/api/auth/login"))
        .json(&serde_json::json!({
            "email": "pending@example.com",
            "password": "password789"
        }))
        .send()
        .expect("old password login should respond");
    assert_eq!(
        old_password_login_response.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    let new_password_login_response = client
        .post(format!("{base_url}/api/auth/login"))
        .json(&serde_json::json!({
            "email": "pending@example.com",
            "password": "password456"
        }))
        .send()
        .expect("new password login should succeed");
    assert_eq!(
        new_password_login_response.status(),
        reqwest::StatusCode::OK
    );
}

#[test]
fn vsr_serve_supports_public_verification_resend_for_unverified_users() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    let root = test_root();
    let capture_dir = root.join("capture");
    fs::create_dir_all(&capture_dir).expect("capture directory should exist");
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "serve-cli-public-verification-secret");
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
        std::env::set_var("VSR_AUTH_EMAIL_CAPTURE_DIR", &capture_dir);
    }

    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("auth_management_api.eon");
    fs::copy(fixture_path("auth_management_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize auth management service");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-public-verification.stdout.log");
    let stderr_log = root.join("serve-public-verification.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "serve-cli-public-verification-secret")
        .env("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY)
        .env("VSR_AUTH_EMAIL_CAPTURE_DIR", &capture_dir)
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
            "vsr serve public verification flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let register_response = client
        .post(format!("{base_url}/api/auth/register"))
        .json(&serde_json::json!({
            "email": "alice@example.com",
            "password": "password123"
        }))
        .send()
        .expect("user registration should succeed");
    assert_eq!(register_response.status(), reqwest::StatusCode::CREATED);

    let captured = wait_for_capture_count(&capture_dir, 1, Duration::from_secs(10));
    let first_verification_url = url_from_capture(&captured[0]);
    assert!(
        first_verification_url.contains("/api/auth/verify-email?token="),
        "unexpected initial verification url: {first_verification_url}"
    );

    let login_before_verify_response = client
        .post(format!("{base_url}/api/auth/login"))
        .json(&serde_json::json!({
            "email": "alice@example.com",
            "password": "password123"
        }))
        .send()
        .expect("pre-verification login should respond");
    assert_eq!(
        login_before_verify_response.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let login_before_verify_body: Value = login_before_verify_response
        .json()
        .expect("pre-verification login error should decode");
    assert_eq!(login_before_verify_body["code"], "email_not_verified");

    let resend_response = client
        .post(format!("{base_url}/api/auth/verification/resend"))
        .json(&serde_json::json!({
            "email": "alice@example.com"
        }))
        .send()
        .expect("public verification resend should respond");
    assert_eq!(resend_response.status(), reqwest::StatusCode::ACCEPTED);

    let captured = wait_for_capture_count(&capture_dir, 2, Duration::from_secs(10));
    let resend_capture = captured
        .iter()
        .rev()
        .find(|path| url_from_capture(path).contains("/verify-email?token="))
        .expect("resent verification email should be captured");
    let resent_verification_url = url_from_capture(resend_capture);
    let resent_verification_path = path_and_query_from_url(&resent_verification_url);
    assert!(
        resent_verification_path.starts_with("/api/auth/verify-email?token="),
        "unexpected resent verification url: {resent_verification_url}"
    );

    let verify_page_response = client
        .get(format!("{base_url}{resent_verification_path}"))
        .send()
        .expect("verify email page should load");
    assert_eq!(verify_page_response.status(), reqwest::StatusCode::OK);
    let verify_page_body = verify_page_response
        .text()
        .expect("verify email page body should read");
    assert!(verify_page_body.contains("Email Verified"));

    let login_after_verify_response = client
        .post(format!("{base_url}/api/auth/login"))
        .json(&serde_json::json!({
            "email": "alice@example.com",
            "password": "password123"
        }))
        .send()
        .expect("verified user login should succeed");
    assert_eq!(
        login_after_verify_response.status(),
        reqwest::StatusCode::OK
    );
}

#[test]
fn vsr_serve_exposes_jwks_for_asymmetric_jwt() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let signing_key_path = write_secret_file(
        &root,
        "jwt-signing-key.pem",
        TEST_ED25519_PRIVATE_KEY_CURRENT,
    );
    let current_public_key_path = write_secret_file(
        &root,
        "jwt-current-public.pem",
        TEST_ED25519_PUBLIC_KEY_CURRENT,
    );
    let previous_public_key_path = write_secret_file(
        &root,
        "jwt-previous-public.pem",
        TEST_ED25519_PUBLIC_KEY_PREVIOUS,
    );

    unsafe {
        std::env::set_var("JWT_SIGNING_KEY_FILE", &signing_key_path);
        std::env::set_var("JWT_PUBLIC_KEY_FILE", &current_public_key_path);
        std::env::set_var("JWT_PUBLIC_KEY_PREVIOUS_FILE", &previous_public_key_path);
    }

    let config = root.join("asymmetric_jwt_api.eon");
    fs::write(
        &config,
        r#"module: "asymmetric_jwt_api"
security: {
    auth: {
        issuer: "serve_cli_asymmetric_jwt_tests"
        audience: "serve_cli_clients"
        jwt: {
            algorithm: EdDSA
            active_kid: "current"
            signing_key: { env_or_file: "JWT_SIGNING_KEY" }
            verification_keys: [
                {
                    kid: "current"
                    key: { env_or_file: "JWT_PUBLIC_KEY" }
                }
                {
                    kid: "previous"
                    key: { env_or_file: "JWT_PUBLIC_KEY_PREVIOUS" }
                }
            ]
        }
    }
}
resources: [
    {
        name: "Doc"
        fields: [
            { name: "id", type: I64, id: true }
            { name: "title", type: String }
        ]
    }
]
"#,
    )
    .expect("config should write");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize asymmetric auth service");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-jwks.stdout.log");
    let stderr_log = root.join("serve-jwks.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .env("BIND_ADDR", &bind_addr)
        .env("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY)
        .env("JWT_SIGNING_KEY_FILE", &signing_key_path)
        .env("JWT_PUBLIC_KEY_FILE", &current_public_key_path)
        .env("JWT_PUBLIC_KEY_PREVIOUS_FILE", &previous_public_key_path)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("vsr serve should start");
    let server = SpawnedBinary::new(child, stdout_log, stderr_log);

    let client = http_client();
    if let Err(error) = wait_for_http_ready(
        &client,
        &format!("{base_url}/.well-known/jwks.json"),
        Duration::from_secs(30),
    ) {
        panic!(
            "vsr serve asymmetric auth flow never became ready: {error}\n{}",
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
    assert!(openapi["paths"].get("/.well-known/jwks.json").is_some());

    let unauthenticated_client = Client::builder()
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(0)
        .build()
        .expect("bare http client should build");
    let public_jwks_response = unauthenticated_client
        .get(format!("{base_url}/.well-known/jwks.json"))
        .send()
        .expect("jwks probe should execute");
    assert_eq!(public_jwks_response.status(), reqwest::StatusCode::OK);

    let jwks_response = client
        .get(format!("{base_url}/.well-known/jwks.json"))
        .send()
        .expect("jwks should load");
    assert_eq!(jwks_response.status(), reqwest::StatusCode::OK);
    let jwks_body: Value = jwks_response.json().expect("jwks should decode");
    let keys = jwks_body["keys"]
        .as_array()
        .expect("jwks should contain keys");
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().any(|key| {
        key["kid"] == "current"
            && key["alg"] == "EdDSA"
            && key["kty"] == "OKP"
            && key["crv"] == "Ed25519"
            && key.get("d").is_none()
    }));
    assert!(keys.iter().any(|key| {
        key["kid"] == "previous"
            && key["alg"] == "EdDSA"
            && key["kty"] == "OKP"
            && key["crv"] == "Ed25519"
            && key.get("d").is_none()
    }));

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
    let roles = me_body["roles"]
        .as_array()
        .expect("auth me should include roles");
    assert!(roles.iter().any(|value| value == "admin"));
}

#[test]
fn vsr_serve_supports_storage_uploads_and_public_mounts() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "serve-cli-storage-upload-secret");
    }

    let root = test_root();
    fs::create_dir_all(root.join("var/uploads")).expect("uploads dir should exist");

    let config = root.join("storage_upload_api.eon");
    fs::copy(fixture_path("storage_upload_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize storage upload service");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-storage.stdout.log");
    let stderr_log = root.join("serve-storage.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "serve-cli-storage-upload-secret")
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
            "vsr serve storage upload flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert!(openapi["paths"].get("/uploads").is_some());
    assert_eq!(
        openapi["paths"]["/uploads"]["post"]["responses"]["201"]["content"]["application/json"]["schema"]
            ["$ref"],
        "#/components/schemas/StorageUploadResponse"
    );

    let token = issue_hs256_token("serve-cli-storage-upload-secret", 1, &["user"]);
    let (content_type, payload) = multipart_upload_payload("notes.txt", b"hello upload");
    let upload_response = client
        .post(format!("{base_url}/api/uploads"))
        .bearer_auth(&token)
        .header("Content-Type", content_type)
        .body(payload)
        .send()
        .expect("upload should succeed");
    assert_eq!(upload_response.status(), reqwest::StatusCode::CREATED);
    let uploaded: Value = upload_response
        .json()
        .expect("upload response should decode");
    assert_eq!(uploaded["backend"], "uploads");
    assert_eq!(uploaded["file_name"], "notes.txt");
    assert_eq!(uploaded["size_bytes"], 12);
    let object_key = uploaded["object_key"]
        .as_str()
        .expect("upload should include object key");
    let public_url = uploaded["public_url"]
        .as_str()
        .expect("upload should expose a public url");
    assert_eq!(public_url, format!("/uploads/{object_key}"));

    let public_response = client
        .get(format!("{base_url}{public_url}"))
        .send()
        .expect("uploaded public object should load");
    assert_eq!(public_response.status(), reqwest::StatusCode::OK);
    let public_body = public_response
        .bytes()
        .expect("uploaded public object should read");
    assert_eq!(public_body.as_ref(), b"hello upload");

    let forbidden_token = issue_hs256_token("serve-cli-storage-upload-secret", 2, &["viewer"]);
    let (forbidden_content_type, forbidden_payload) = multipart_upload_payload("notes.txt", b"x");
    let forbidden_response = client
        .post(format!("{base_url}/api/uploads"))
        .bearer_auth(&forbidden_token)
        .header("Content-Type", forbidden_content_type)
        .body(forbidden_payload)
        .send()
        .expect("forbidden upload should respond");
    assert_eq!(forbidden_response.status(), reqwest::StatusCode::FORBIDDEN);
}

#[test]
fn vsr_serve_applies_computed_api_fields_in_spawned_process() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("api_computed_fields_api.eon");
    fs::copy(fixture_path("api_computed_fields_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            let pool = connect_database(&database_url, Some(&config))
                .await
                .expect("database should connect");
            query(
                "CREATE TABLE post (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    slug TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT
                )",
            )
            .execute(&pool)
            .await
            .expect("schema should apply");
            query(
                "INSERT INTO post (id, slug, title, summary) VALUES (1, 'alpha', 'Alpha', 'Intro')",
            )
            .execute(&pool)
            .await
            .expect("seed row should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-computed.stdout.log");
    let stderr_log = root.join("serve-computed.stderr.log");
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
    if let Err(error) = wait_for_http_ready(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(30),
    ) {
        panic!(
            "vsr serve computed-field flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert_eq!(
        openapi["components"]["schemas"]["Post"]["properties"]["permalink"]["type"],
        "string"
    );
    assert_eq!(
        openapi["components"]["schemas"]["Post"]["properties"]["preview"]["nullable"],
        true
    );

    let item_response = client
        .get(format!("{base_url}/api/posts/1"))
        .send()
        .expect("item should load");
    assert_eq!(item_response.status(), reqwest::StatusCode::OK);
    let item_body: Value = item_response.json().expect("item body should decode");
    assert_eq!(item_body["permalink"], "/posts/alpha");
    assert_eq!(item_body["preview"], "alpha:Intro");

    let compact_response = client
        .get(format!("{base_url}/api/posts?context=compact"))
        .send()
        .expect("compact list should load");
    assert_eq!(compact_response.status(), reqwest::StatusCode::OK);
    let compact_body: Value = compact_response.json().expect("compact body should decode");
    assert_eq!(compact_body["items"][0]["id"], 1);
    assert_eq!(compact_body["items"][0]["permalink"], "/posts/alpha");
    assert!(compact_body["items"][0].get("title").is_none());
}

#[test]
fn vsr_serve_applies_response_contexts_in_spawned_process() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("api_contexts_api.eon");
    fs::copy(fixture_path("api_contexts_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            let pool = connect_database(&database_url, Some(&config))
                .await
                .expect("database should connect");
            query(
                "CREATE TABLE blog_post (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title_text TEXT NOT NULL,
                    author_id INTEGER NOT NULL,
                    draft_body TEXT
                )",
            )
            .execute(&pool)
            .await
            .expect("schema should apply");
            query(
                "INSERT INTO blog_post (id, title_text, author_id, draft_body) VALUES (1, 'Alpha', 7, 'secret alpha')",
            )
            .execute(&pool)
            .await
            .expect("seed row should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-contexts.stdout.log");
    let stderr_log = root.join("serve-contexts.stderr.log");
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
    if let Err(error) = wait_for_http_ready(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(30),
    ) {
        panic!(
            "vsr serve response-context flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    let list_parameters = openapi["paths"]["/posts"]["get"]["parameters"]
        .as_array()
        .expect("list parameters should exist");
    let context_parameter = list_parameters
        .iter()
        .find(|parameter| parameter["name"] == "context")
        .expect("context parameter should exist");
    assert_eq!(context_parameter["schema"]["enum"], json!(["view", "edit"]));
    assert_eq!(context_parameter["schema"]["default"], json!("view"));

    let item_response = client
        .get(format!("{base_url}/api/posts/1"))
        .send()
        .expect("item should load");
    assert_eq!(item_response.status(), reqwest::StatusCode::OK);
    let item_body: Value = item_response.json().expect("item body should decode");
    assert_eq!(item_body["title"], "Alpha");
    assert!(item_body.get("secret").is_none());

    let edit_response = client
        .get(format!("{base_url}/api/posts/1?context=edit"))
        .send()
        .expect("edit item should load");
    assert_eq!(edit_response.status(), reqwest::StatusCode::OK);
    let edit_body: Value = edit_response.json().expect("edit body should decode");
    assert_eq!(edit_body["secret"], "secret alpha");

    let invalid_response = client
        .get(format!("{base_url}/api/posts/1?context=unknown"))
        .send()
        .expect("invalid context request should respond");
    assert_eq!(invalid_response.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[test]
fn vsr_serve_lists_many_to_many_routes_in_spawned_process() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("many_to_many_api.eon");
    fs::copy(fixture_path("many_to_many_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            let pool = connect_database(&database_url, Some(&config))
                .await
                .expect("database should connect");
            query(
                "CREATE TABLE post (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL
                )",
            )
            .execute(&pool)
            .await
            .expect("post schema should apply");
            query(
                "CREATE TABLE tag (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL
                )",
            )
            .execute(&pool)
            .await
            .expect("tag schema should apply");
            query(
                "CREATE TABLE post_tag (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    post_id INTEGER NOT NULL,
                    tag_id INTEGER NOT NULL,
                    FOREIGN KEY (post_id) REFERENCES post(id) ON DELETE CASCADE,
                    FOREIGN KEY (tag_id) REFERENCES tag(id) ON DELETE CASCADE
                )",
            )
            .execute(&pool)
            .await
            .expect("join schema should apply");

            query("INSERT INTO post (id, title) VALUES (1, 'First'), (2, 'Second')")
                .execute(&pool)
                .await
                .expect("posts should insert");
            query("INSERT INTO tag (id, name) VALUES (1, 'alpha'), (2, 'beta'), (3, 'gamma')")
                .execute(&pool)
                .await
                .expect("tags should insert");
            query("INSERT INTO post_tag (post_id, tag_id) VALUES (1, 1), (1, 2), (2, 3)")
                .execute(&pool)
                .await
                .expect("join rows should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-many-to-many.stdout.log");
    let stderr_log = root.join("serve-many-to-many.stderr.log");
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
    if let Err(error) = wait_for_http_ready(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(30),
    ) {
        panic!(
            "vsr serve many-to-many flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert!(openapi["paths"].get("/posts/{parent_id}/tags").is_some());
    assert_eq!(
        openapi["paths"]["/posts/{parent_id}/tags"]["get"]["parameters"][0]["name"],
        "parent_id"
    );
    assert_eq!(
        openapi["paths"]["/posts/{parent_id}/tags"]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["$ref"],
        "#/components/schemas/TagListResponse"
    );

    let list_response = client
        .get(format!("{base_url}/api/posts/1/tags?sort=name"))
        .send()
        .expect("many-to-many list should load");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_body: Value = list_response
        .json()
        .expect("many-to-many list should decode");
    assert_eq!(list_body["total"], 2);
    assert_eq!(list_body["items"][0]["name"], "alpha");
    assert_eq!(list_body["items"][1]["name"], "beta");

    let filtered_response = client
        .get(format!("{base_url}/api/posts/1/tags?filter_name=beta"))
        .send()
        .expect("filtered many-to-many list should load");
    assert_eq!(filtered_response.status(), reqwest::StatusCode::OK);
    let filtered_body: Value = filtered_response
        .json()
        .expect("filtered many-to-many body should decode");
    assert_eq!(filtered_body["total"], 1);
    assert_eq!(filtered_body["items"][0]["name"], "beta");

    let second_post_response = client
        .get(format!("{base_url}/api/posts/2/tags"))
        .send()
        .expect("second many-to-many list should load");
    assert_eq!(second_post_response.status(), reqwest::StatusCode::OK);
    let second_post_body: Value = second_post_response
        .json()
        .expect("second many-to-many body should decode");
    assert_eq!(second_post_body["total"], 1);
    assert_eq!(second_post_body["items"][0]["name"], "gamma");
}

#[test]
fn vsr_serve_supports_public_catalog_routes_in_spawned_process() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("public_catalog_api.eon");
    fs::copy(fixture_path("public_catalog_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            let pool = connect_database(&database_url, Some(&config))
                .await
                .expect("database should connect");
            query(
                "CREATE TABLE organization (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    country TEXT NOT NULL,
                    website_url TEXT NOT NULL,
                    summary TEXT NOT NULL
                )",
            )
            .execute(&pool)
            .await
            .expect("organization schema should apply");
            query(
                "CREATE TABLE interest (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    organization_id INTEGER NOT NULL
                )",
            )
            .execute(&pool)
            .await
            .expect("interest schema should apply");

            query(
                "INSERT INTO organization (name, country, website_url, summary) VALUES
                    ('Nordic Bridge Institute', 'Finland', 'https://nordic.example', 'Cross-border education and industry matching'),
                    ('Baltic Industry Lab', 'Estonia', 'https://baltic.example', 'Applied industrial collaboration partner')",
            )
            .execute(&pool)
            .await
            .expect("organization seed data should insert");
            query(
                "INSERT INTO interest (title, summary, organization_id) VALUES
                    ('AI Thesis Co-Creation', 'Seeking thesis topics on trustworthy AI and shared supervision', 1),
                    ('Mobility Pilot Ideas', 'Open to data-sharing pilots across campuses and ports', 1),
                    ('Green Manufacturing Topics', 'Looking for thesis work on industrial decarbonization', 2)",
            )
            .execute(&pool)
            .await
            .expect("interest seed data should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-public-catalog.stdout.log");
    let stderr_log = root.join("serve-public-catalog.stderr.log");
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
    if let Err(error) = wait_for_http_ready(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(30),
    ) {
        panic!(
            "vsr serve public catalog flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert!(openapi["paths"].get("/organization").is_some());
    assert!(openapi["paths"].get("/organization/{id}").is_some());
    assert!(
        openapi["paths"]
            .get("/organization/{parent_id}/interest")
            .is_some()
    );
    assert_eq!(
        openapi["paths"]["/organization"]["get"]["security"][0]["anonKey"],
        json!([])
    );

    let list_response = client
        .get(format!("{base_url}/api/organization"))
        .send()
        .expect("public organization list should load");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_body: Value = list_response
        .json()
        .expect("public organization list should decode");
    assert_eq!(list_body["total"], 2);
    assert_eq!(list_body["items"][0]["name"], "Nordic Bridge Institute");

    let contains_response = client
        .get(format!(
            "{base_url}/api/organization?filter_name_contains=BRIDGE"
        ))
        .send()
        .expect("contains search should load");
    assert_eq!(contains_response.status(), reqwest::StatusCode::OK);
    let contains_body: Value = contains_response
        .json()
        .expect("contains search should decode");
    assert_eq!(contains_body["total"], 1);
    assert_eq!(contains_body["items"][0]["country"], "Finland");

    let nested_response = client
        .get(format!(
            "{base_url}/api/organization/1/interest?filter_summary_contains=THESIS"
        ))
        .send()
        .expect("nested public list should load");
    assert_eq!(nested_response.status(), reqwest::StatusCode::OK);
    let nested_body: Value = nested_response
        .json()
        .expect("nested public list should decode");
    assert_eq!(nested_body["total"], 1);
    assert_eq!(nested_body["items"][0]["title"], "AI Thesis Co-Creation");

    let create_response = client
        .post(format!("{base_url}/api/organization"))
        .json(&json!({
            "name": "Unauthorized Org",
            "country": "Sweden",
            "website_url": "https://unauthorized.example",
            "summary": "Should not be created anonymously"
        }))
        .send()
        .expect("anonymous create should respond");
    assert_eq!(create_response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[test]
fn vsr_serve_supports_object_field_shapes_in_spawned_process() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "serve-cli-object-fields-secret");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("object_fields_api.eon");
    fs::copy(fixture_path("object_fields_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            let pool = connect_database(&database_url, Some(&config))
                .await
                .expect("database should connect");
            query(
                "CREATE TABLE entry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    settings TEXT
                )",
            )
            .execute(&pool)
            .await
            .expect("schema should apply");
            query("INSERT INTO entry (title, settings) VALUES (?, ?)")
                .bind(r#"{"raw":"Hello world","rendered":"<p>Hello world</p>"}"#)
                .bind(r#"{"featured":true,"categories":[1,2],"seo":{"slug":"hello-world"}}"#)
                .execute(&pool)
                .await
                .expect("seed row should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-object-fields.stdout.log");
    let stderr_log = root.join("serve-object-fields.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .arg("--without-auth")
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "serve-cli-object-fields-secret")
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
            "vsr serve object-field flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert_eq!(
        openapi["components"]["schemas"]["Entry"]["properties"]["title"]["type"],
        "object"
    );
    assert_eq!(
        openapi["components"]["schemas"]["Entry"]["properties"]["title"]["additionalProperties"],
        false
    );

    let list_response = client
        .get(format!("{base_url}/api/entry"))
        .send()
        .expect("object-field list should load");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_body: Value = list_response
        .json()
        .expect("object-field list should decode");
    assert_eq!(list_body["total"], 1);
    assert_eq!(
        list_body["items"][0]["title"]["rendered"],
        "<p>Hello world</p>"
    );
    assert_eq!(list_body["items"][0]["settings"]["categories"][1], 2);

    let token = issue_hs256_token("serve-cli-object-fields-secret", 1, &["user"]);
    let create_response = client
        .post(format!("{base_url}/api/entry"))
        .bearer_auth(&token)
        .json(&json!({
            "title": {
                "raw": "Typed object title",
                "rendered": "<p>Typed object title</p>"
            },
            "settings": {
                "featured": false,
                "categories": [5, 8],
                "seo": { "slug": "typed-object-title" }
            }
        }))
        .send()
        .expect("object-field create should succeed");
    assert_eq!(create_response.status(), reqwest::StatusCode::CREATED);
    let created_body: Value = create_response
        .json()
        .expect("object-field create should decode");
    assert_eq!(created_body["title"]["raw"], "Typed object title");
    assert_eq!(
        created_body["settings"]["seo"]["slug"],
        "typed-object-title"
    );
}

#[test]
fn vsr_serve_supports_list_field_shapes_in_spawned_process() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "serve-cli-list-fields-secret");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("list_fields_api.eon");
    fs::copy(fixture_path("list_fields_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            let pool = connect_database(&database_url, Some(&config))
                .await
                .expect("database should connect");
            query(
                "CREATE TABLE entry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    categories TEXT NOT NULL,
                    tags TEXT NOT NULL,
                    blocks TEXT
                )",
            )
            .execute(&pool)
            .await
            .expect("schema should apply");
            query("INSERT INTO entry (categories, tags, blocks) VALUES (?, ?, ?)")
                .bind("[1,2]")
                .bind(r#"["alpha","beta"]"#)
                .bind(r#"[{"name":"core/paragraph"}]"#)
                .execute(&pool)
                .await
                .expect("seed row should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-list-fields.stdout.log");
    let stderr_log = root.join("serve-list-fields.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .arg("--without-auth")
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "serve-cli-list-fields-secret")
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
            "vsr serve list-field flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert_eq!(
        openapi["components"]["schemas"]["Entry"]["properties"]["categories"]["type"],
        "array"
    );
    assert_eq!(
        openapi["components"]["schemas"]["Entry"]["properties"]["blocks"]["items"]["type"],
        "object"
    );

    let list_response = client
        .get(format!("{base_url}/api/entry"))
        .send()
        .expect("list-field list should load");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_body: Value = list_response.json().expect("list-field list should decode");
    assert_eq!(list_body["total"], 1);
    assert_eq!(list_body["items"][0]["categories"][1], 2);
    assert_eq!(list_body["items"][0]["tags"][0], "alpha");

    let token = issue_hs256_token("serve-cli-list-fields-secret", 1, &["user"]);
    let create_response = client
        .post(format!("{base_url}/api/entry"))
        .bearer_auth(&token)
        .json(&json!({
            "categories": [5, 8],
            "tags": ["news", "ai"],
            "blocks": [{ "name": "core/heading", "level": 2 }]
        }))
        .send()
        .expect("list-field create should succeed");
    assert_eq!(create_response.status(), reqwest::StatusCode::CREATED);
    let created_body: Value = create_response
        .json()
        .expect("list-field create should decode");
    assert_eq!(created_body["categories"][0], 5);
    assert_eq!(created_body["tags"][1], "ai");
    assert_eq!(created_body["blocks"][0]["name"], "core/heading");
}

#[test]
fn vsr_serve_supports_enum_field_shapes_in_spawned_process() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "serve-cli-enum-fields-secret");
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("enum_fields_api.eon");
    fs::copy(fixture_path("enum_fields_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize enum field service");
            let pool = connect_database(&database_url, Some(&config))
                .await
                .expect("database should connect");
            query("INSERT INTO blog_post (id, title, status, workflow) VALUES (?, ?, ?, ?)")
                .bind(1_i64)
                .bind("Alpha")
                .bind("published")
                .bind(r#"{"current":"published","previous":"draft"}"#)
                .execute(&pool)
                .await
                .expect("seed row should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-enum-fields.stdout.log");
    let stderr_log = root.join("serve-enum-fields.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "serve-cli-enum-fields-secret")
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
            "vsr serve enum-field flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert_eq!(
        openapi["components"]["schemas"]["Post"]["properties"]["status"]["enum"],
        json!(["draft", "published", "archived"])
    );

    let list_response = client
        .get(format!("{base_url}/api/posts?filter_status=published"))
        .send()
        .expect("enum list should load");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_body: Value = list_response.json().expect("enum list should decode");
    assert_eq!(list_body["items"][0]["status"], "published");
    assert_eq!(list_body["items"][0]["workflow"]["current"], "published");

    let invalid_filter_response = client
        .get(format!("{base_url}/api/posts?filter_status=invalid"))
        .send()
        .expect("invalid enum filter should respond");
    assert_eq!(
        invalid_filter_response.status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    let contains_response = client
        .get(format!("{base_url}/api/posts?filter_status_contains=pub"))
        .send()
        .expect("invalid enum contains should respond");
    assert_eq!(contains_response.status(), reqwest::StatusCode::BAD_REQUEST);

    let token = issue_hs256_token("serve-cli-enum-fields-secret", 1, &["user"]);
    let create_response = client
        .post(format!("{base_url}/api/posts"))
        .bearer_auth(&token)
        .json(&json!({
            "title": "Beta",
            "status": "draft",
            "workflow": { "current": "draft" }
        }))
        .send()
        .expect("enum create should succeed");
    assert_eq!(create_response.status(), reqwest::StatusCode::CREATED);
    let create_body: Value = create_response.json().expect("enum create should decode");
    assert_eq!(create_body["status"], "draft");
}

#[test]
fn vsr_serve_expands_mixin_fields_in_spawned_process() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "serve-cli-mixin-fields-secret");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("mixin_fields_api.eon");
    fs::copy(fixture_path("mixin_fields_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            let pool = connect_database(&database_url, Some(&config))
                .await
                .expect("database should connect");
            query(
                "CREATE TABLE post (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id INTEGER NOT NULL,
                    slug TEXT NOT NULL,
                    title TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now')),
                    updated_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now'))
                )",
            )
            .execute(&pool)
            .await
            .expect("schema should apply");
            query(
                "INSERT INTO post (tenant_id, slug, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(7_i64)
            .bind("alpha")
            .bind("Alpha")
            .bind("2026-03-27T09:00:00Z")
            .bind("2026-03-27T09:15:00Z")
            .execute(&pool)
            .await
            .expect("seed row should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-mixin-fields.stdout.log");
    let stderr_log = root.join("serve-mixin-fields.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "serve-cli-mixin-fields-secret")
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
            "vsr serve mixin-fields flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert!(openapi["paths"].get("/post").is_some());
    assert_eq!(
        openapi["components"]["schemas"]["Post"]["properties"]["tenant_id"]["type"],
        "integer"
    );
    assert_eq!(
        openapi["components"]["schemas"]["Post"]["properties"]["slug"]["type"],
        "string"
    );
    assert_eq!(
        openapi["components"]["schemas"]["Post"]["properties"]["created_at"]["format"],
        "date-time"
    );
    assert_eq!(
        openapi["components"]["schemas"]["Post"]["properties"]["updated_at"]["format"],
        "date-time"
    );

    let token = issue_hs256_token("serve-cli-mixin-fields-secret", 1, &["user"]);
    let create_response = client
        .post(format!("{base_url}/api/post"))
        .bearer_auth(&token)
        .json(&json!({
            "tenant_id": 7,
            "slug": "beta",
            "title": "Beta"
        }))
        .send()
        .expect("mixin create should succeed");
    assert_eq!(create_response.status(), reqwest::StatusCode::CREATED);
    let created: Value = create_response.json().expect("mixin create should decode");
    assert_eq!(created["slug"], "beta");
    assert_eq!(created["tenant_id"], 7);
    assert!(created["created_at"].is_string());
    assert!(created["updated_at"].is_string());

    let list_response = client
        .get(format!("{base_url}/api/post?filter_tenant_id=7&sort=slug"))
        .bearer_auth(&token)
        .send()
        .expect("mixin list should load");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_body: Value = list_response.json().expect("mixin list should decode");
    assert_eq!(list_body["total"], 2);
    assert_eq!(list_body["items"][0]["slug"], "alpha");
    assert_eq!(list_body["items"][1]["slug"], "beta");
}

#[test]
fn vsr_serve_supports_api_name_aliases_in_spawned_process() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "serve-cli-api-alias-secret");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("api_name_alias_api.eon");
    fs::copy(fixture_path("api_name_alias_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            let pool = connect_database(&database_url, Some(&config))
                .await
                .expect("database should connect");
            query(
                "CREATE TABLE blog_post (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title_text TEXT NOT NULL,
                    author_id INTEGER NOT NULL,
                    created_at TEXT
                )",
            )
            .execute(&pool)
            .await
            .expect("post schema should apply");
            query(
                "CREATE TABLE comment_row (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    body_text TEXT NOT NULL,
                    post_id INTEGER NOT NULL
                )",
            )
            .execute(&pool)
            .await
            .expect("comment schema should apply");

            query(
                "INSERT INTO blog_post (id, title_text, author_id, created_at) VALUES (?, ?, ?, ?)",
            )
            .bind(1_i64)
            .bind("Alpha")
            .bind(7_i64)
            .bind("2026-03-26T10:00:00Z")
            .execute(&pool)
            .await
            .expect("first seed row should insert");
            query(
                "INSERT INTO blog_post (id, title_text, author_id, created_at) VALUES (?, ?, ?, ?)",
            )
            .bind(2_i64)
            .bind("Beta")
            .bind(9_i64)
            .bind("2026-03-26T11:00:00Z")
            .execute(&pool)
            .await
            .expect("second seed row should insert");
            query("INSERT INTO comment_row (id, body_text, post_id) VALUES (?, ?, ?)")
                .bind(1_i64)
                .bind("First comment")
                .bind(1_i64)
                .execute(&pool)
                .await
                .expect("comment seed row should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-api-alias.stdout.log");
    let stderr_log = root.join("serve-api-alias.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .arg("--without-auth")
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "serve-cli-api-alias-secret")
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
            "vsr serve api-alias flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert!(openapi["paths"].get("/posts").is_some());
    assert!(
        openapi["paths"]
            .get("/posts/{parent_id}/comments")
            .is_some()
    );
    assert!(openapi["paths"].get("/blog_post").is_none());
    assert_eq!(
        openapi["components"]["schemas"]["Post"]["properties"]["createdAt"]["format"],
        "date-time"
    );

    let token = issue_hs256_token("serve-cli-api-alias-secret", 1, &["user"]);
    let create_response = client
        .post(format!("{base_url}/api/posts"))
        .bearer_auth(&token)
        .json(&json!({
            "title": "Gamma",
            "author": 7,
            "createdAt": "2026-03-26T12:00:00Z"
        }))
        .send()
        .expect("alias create should succeed");
    assert_eq!(create_response.status(), reqwest::StatusCode::CREATED);
    let created: Value = create_response.json().expect("alias create should decode");
    assert_eq!(created["title"], "Gamma");
    assert_eq!(created["author"], 7);
    assert!(created.get("title_text").is_none());
    assert!(created.get("author_id").is_none());

    let list_response = client
        .get(format!(
            "{base_url}/api/posts?filter_author=7&sort=title&limit=1"
        ))
        .send()
        .expect("alias list should load");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_body: Value = list_response.json().expect("alias list should decode");
    assert_eq!(list_body["total"], 2);
    assert_eq!(list_body["items"][0]["title"], "Alpha");
    let next_cursor = list_body["next_cursor"]
        .as_str()
        .expect("next cursor should exist");

    let cursor_response = client
        .get(format!(
            "{base_url}/api/posts?filter_author=7&limit=1&cursor={next_cursor}"
        ))
        .send()
        .expect("alias cursor page should load");
    assert_eq!(cursor_response.status(), reqwest::StatusCode::OK);
    let cursor_body: Value = cursor_response
        .json()
        .expect("alias cursor page should decode");
    assert_eq!(cursor_body["items"][0]["title"], "Gamma");

    let nested_response = client
        .get(format!("{base_url}/api/posts/1/comments"))
        .send()
        .expect("alias nested route should load");
    assert_eq!(nested_response.status(), reqwest::StatusCode::OK);
    let nested_body: Value = nested_response
        .json()
        .expect("alias nested route should decode");
    assert_eq!(nested_body["items"][0]["body"], "First comment");
    assert_eq!(nested_body["items"][0]["post"], 1);
}

#[test]
fn vsr_serve_applies_api_projections_in_spawned_process() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "serve-cli-api-projection-secret");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("api_projection_api.eon");
    fs::copy(fixture_path("api_projection_api.eon"), &config).expect("fixture should copy");

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            let pool = connect_database(&database_url, Some(&config))
                .await
                .expect("database should connect");
            query(
                "CREATE TABLE blog_post (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title_text TEXT NOT NULL,
                    author_id INTEGER NOT NULL,
                    team_id INTEGER NOT NULL,
                    draft_body TEXT,
                    internal_note TEXT
                )",
            )
            .execute(&pool)
            .await
            .expect("schema should apply");
            query(
                "INSERT INTO blog_post (id, title_text, author_id, team_id, draft_body, internal_note) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(1_i64)
            .bind("Alpha")
            .bind(7_i64)
            .bind(3_i64)
            .bind("secret draft")
            .bind("internal only")
            .execute(&pool)
            .await
            .expect("seed row should insert");
        });

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("serve-api-projection.stdout.log");
    let stderr_log = root.join("serve-api-projection.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .arg("--without-auth")
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "serve-cli-api-projection-secret")
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
            "vsr serve api-projection flow never became ready: {error}\n{}",
            server.logs()
        );
    }

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert_eq!(
        openapi["components"]["schemas"]["Post"]["properties"]["title"]["type"],
        "string"
    );
    assert!(
        openapi["components"]["schemas"]["Post"]["properties"]
            .get("draft_body")
            .is_none()
    );

    let token = issue_hs256_token("serve-cli-api-projection-secret", 1, &["user"]);
    let create_response = client
        .post(format!("{base_url}/api/posts"))
        .bearer_auth(&token)
        .json(&json!({
            "title": "Gamma",
            "author": 7,
            "team_id": 3
        }))
        .send()
        .expect("projection create should succeed");
    let create_status = create_response.status();
    let create_body = create_response
        .text()
        .expect("projection create response should read");
    assert_eq!(
        create_status,
        reqwest::StatusCode::CREATED,
        "projection create failed: {create_body}"
    );
    let created: Value =
        serde_json::from_str(&create_body).expect("projection create should decode");
    assert_eq!(created["title"], "Gamma");
    assert_eq!(created["author"], 7);
    assert!(created.get("team_id").is_none());
    assert!(created.get("title_text").is_none());
    assert!(created.get("draft_body").is_none());
    assert!(created.get("internal_note").is_none());
    let created_id = created["id"]
        .as_i64()
        .expect("projection create should return an integer id");

    let update_response = client
        .put(format!("{base_url}/api/posts/{created_id}"))
        .bearer_auth(&token)
        .json(&json!({
            "title": "Gamma Revised",
            "author": 7,
            "team_id": 9
        }))
        .send()
        .expect("projection update should succeed");
    let update_status = update_response.status();
    let update_body = update_response
        .text()
        .expect("projection update response should read");
    assert_eq!(
        update_status,
        reqwest::StatusCode::OK,
        "projection update failed: {update_body}"
    );

    let item_response = client
        .get(format!("{base_url}/api/posts/{created_id}"))
        .send()
        .expect("projection item should load");
    assert_eq!(item_response.status(), reqwest::StatusCode::OK);
    let item_body: Value = item_response.json().expect("projection item should decode");
    assert_eq!(item_body["title"], "Gamma Revised");
    assert_eq!(item_body["author"], 7);
    assert!(item_body.get("team_id").is_none());
    assert!(item_body.get("title_text").is_none());
    assert!(item_body.get("draft_body").is_none());
    assert!(item_body.get("internal_note").is_none());

    let list_response = client
        .get(format!("{base_url}/api/posts?filter_author=7&sort=title"))
        .send()
        .expect("projection list should load");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_body: Value = list_response.json().expect("projection list should decode");
    assert_eq!(list_body["total"], 2);
    assert_eq!(list_body["items"][0]["title"], "Alpha");
    assert_eq!(list_body["items"][1]["title"], "Gamma Revised");
    assert!(list_body["items"][0].get("draft_body").is_none());
    assert!(list_body["items"][0].get("internal_note").is_none());
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

    let openapi_response = client
        .get(format!("{base_url}/openapi.json"))
        .send()
        .expect("openapi spec should load");
    assert!(openapi_response.status().is_success());
    let openapi: Value = openapi_response.json().expect("openapi should decode");
    assert!(openapi["paths"].get("/posts").is_some());
    assert!(openapi["paths"].get("/posts/{id}").is_some());
    assert_eq!(
        openapi["components"]["schemas"]["Post"]["properties"]["status"]["enum"],
        json!(["draft", "published"])
    );
    assert_eq!(
        openapi["components"]["schemas"]["Post"]["properties"]["title"]["type"],
        "object"
    );

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
fn vsr_serve_todo_app_example_supports_clean_room_e2e() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());

    let root = test_root();
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "todo-app-serve-secret");
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
    }

    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("todo_app.eon");
    fs::copy(example_path("todo_app/todo_app.eon"), &config).expect("example should copy");
    copy_dir_all(&example_path("todo_app/public"), &root.join("public"));

    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize the todo app database");
        });

    assert!(
        root.join("var/data/todo_app.db").exists(),
        "setup should create the config-relative todo app database"
    );

    let bind_addr = free_bind_addr();
    let base_url = format!("http://{bind_addr}");
    let stdout_log = root.join("todo-app-serve.stdout.log");
    let stderr_log = root.join("todo-app-serve.stderr.log");
    let stdout = fs::File::create(&stdout_log).expect("stdout log should open");
    let stderr = fs::File::create(&stderr_log).expect("stderr log should open");
    let child = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .current_dir(&root)
        .arg("serve")
        .arg(&config)
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "todo-app-serve-secret")
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
        panic!(
            "todo app native serve never became ready: {error}\n{}",
            server.logs()
        );
    }

    let root_response = client
        .get(format!("{base_url}/"))
        .send()
        .expect("root page should load");
    assert!(root_response.status().is_success());
    let root_body = root_response.text().expect("root page body should read");
    assert!(root_body.contains("Todo App"));

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

    let create_todo_response = client
        .post(format!("{base_url}/api/todo"))
        .bearer_auth(&admin_token)
        .json(&json!({
            "title": "Verify todo example",
            "completed": false,
        }))
        .send()
        .expect("todo create should succeed");
    let create_todo_status = create_todo_response.status();
    let create_todo_body = create_todo_response
        .text()
        .expect("todo create response body should read");
    assert_eq!(
        create_todo_status,
        reqwest::StatusCode::CREATED,
        "todo create should succeed\nbody:\n{create_todo_body}\n{}",
        server.logs()
    );

    let todo_list_response = client
        .get(format!("{base_url}/api/todo"))
        .bearer_auth(&admin_token)
        .send()
        .expect("todo list should load");
    assert!(todo_list_response.status().is_success());
    let todo_list: Value = todo_list_response.json().expect("todo list should decode");
    assert_eq!(todo_list.get("total").and_then(Value::as_i64), Some(1));
    assert_eq!(todo_list["items"][0]["title"], "Verify todo example");
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
