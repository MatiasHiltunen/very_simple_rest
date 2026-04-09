use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use rest_macro_core::db::query;
use serde_json::Value;
use uuid::Uuid;
use vsra::commands::db::{connect_database, database_url_from_service_config};
use vsra::commands::setup::run_setup;

const TEST_TURSO_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn test_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/client_cli_tests")
        .join(Uuid::new_v4().to_string())
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn free_bind_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral port should bind");
    let addr = listener
        .local_addr()
        .expect("listener address should resolve");
    drop(listener);
    format!("127.0.0.1:{}", addr.port())
}

fn http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(0)
        .build()
        .expect("http client should build")
}

fn wait_for_http_ready(client: &Client, url: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut last_error = None;

    while Instant::now() < deadline {
        match client.get(url).send() {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                last_error = Some(format!("server responded with {}", response.status()))
            }
            Err(error) => last_error = Some(error.to_string()),
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    Err(last_error.unwrap_or_else(|| "server never became ready".to_owned()))
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path).expect("file should be readable")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn example_path(name: &str) -> PathBuf {
    repo_root().join("examples").join(name)
}

fn snapshot_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/client_self_test")
        .join(name)
}

fn assert_text_snapshot(snapshot: &Path, actual: &str) {
    if std::env::var_os("VSR_UPDATE_SNAPSHOTS").is_some() {
        if let Some(parent) = snapshot.parent() {
            fs::create_dir_all(parent).expect("snapshot parent should be creatable");
        }
        fs::write(snapshot, actual).expect("snapshot should be writable");
        return;
    }

    let expected = fs::read_to_string(snapshot).unwrap_or_else(|error| {
        panic!(
            "snapshot {} is missing or unreadable: {error}. Re-run with VSR_UPDATE_SNAPSHOTS=1 to create it.",
            snapshot.display()
        )
    });
    assert_eq!(
        expected,
        actual,
        "snapshot mismatch at {}",
        snapshot.display()
    );
}

fn find_tsc_binary() -> Option<PathBuf> {
    let candidate = repo_root().join("examples/cms/web/node_modules/.bin/tsc");
    candidate.is_file().then_some(candidate)
}

fn compile_generated_client(output_dir: &Path) {
    let Some(tsc) = find_tsc_binary() else {
        eprintln!(
            "skipping generated client TypeScript compile check because local tsc is unavailable"
        );
        return;
    };

    let output = Command::new(tsc)
        .arg("-p")
        .arg(output_dir)
        .output()
        .expect("tsc should execute");
    assert!(
        output.status.success(),
        "generated client should type-check\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_dependency_free_client(output_dir: &Path) {
    let package_json: Value =
        serde_json::from_str(&read_to_string(&output_dir.join("package.json")))
            .expect("generated package.json should be valid JSON");
    assert!(
        package_json.get("dependencies").is_none(),
        "generated client must not declare runtime dependencies"
    );
    assert!(
        package_json.get("devDependencies").is_none(),
        "generated client must not declare devDependencies"
    );

    for entry in fs::read_dir(output_dir).expect("client output dir should be readable") {
        let entry = entry.expect("directory entry should read");
        let path = entry.path();
        let extension = path.extension().and_then(|value| value.to_str());
        if !matches!(extension, Some("ts" | "js")) {
            continue;
        }
        for specifier in collect_module_specifiers(&path) {
            assert!(
                specifier.starts_with("./") || specifier.starts_with("../"),
                "generated client must not import external dependencies; found {specifier:?} in {}",
                path.display()
            );
        }
    }
}

fn collect_module_specifiers(path: &Path) -> Vec<String> {
    let contents = read_to_string(path);
    let mut specifiers = Vec::new();
    for line in contents.lines() {
        if let Some(specifier) = extract_module_specifier(line) {
            specifiers.push(specifier.to_owned());
        }
    }
    specifiers
}

fn extract_module_specifier(line: &str) -> Option<&str> {
    for marker in [" from \"", " from '", "import(\"", "import('"] {
        let Some(start_index) = line.find(marker) else {
            continue;
        };
        let start = start_index + marker.len();
        let rest = &line[start..];
        let end = match marker {
            " from \"" | "import(\"" => rest.find('"')?,
            " from '" | "import('" => rest.find('\'')?,
            _ => return None,
        };
        return Some(&rest[..end]);
    }
    None
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

fn generate_client(input: &Path, output_dir: &Path) {
    let status = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .arg("client")
        .arg("ts")
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output_dir)
        .arg("--emit-js")
        .arg("--force")
        .status()
        .expect("vsr client ts should execute");
    assert!(status.success(), "vsr client ts should succeed");
}

fn run_node_script(script_path: &Path, envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new("node");
    command.arg(script_path);
    command.current_dir(
        script_path
            .parent()
            .expect("script should have a parent directory"),
    );
    for (key, value) in envs {
        command.env(key, value);
    }
    command
        .output()
        .expect("node smoke script should execute successfully")
}

fn normalize_self_test_report(mut report: Value) -> Value {
    report["generated_at"] = Value::String("<generated_at>".to_owned());
    report["schema_input"] = Value::String("<schema_input>".to_owned());
    report["client_dir"] = Value::String("<client_dir>".to_owned());

    if let Some(checks) = report.get_mut("checks").and_then(Value::as_array_mut) {
        for check in checks {
            if let Some(metadata) = check.get_mut("metadata").and_then(Value::as_object_mut) {
                if metadata.contains_key("node_binary") {
                    metadata.insert(
                        "node_binary".to_owned(),
                        Value::String("<node_binary>".to_owned()),
                    );
                }
                if metadata.contains_key("tsc_binary") {
                    metadata.insert(
                        "tsc_binary".to_owned(),
                        Value::String("<tsc_binary>".to_owned()),
                    );
                }
            }
        }
    }

    report
}

#[test]
fn generated_typescript_client_supports_auth_and_crud_against_live_server() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "generated-client-blog-secret");
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("blog_api.eon");
    fs::copy(fixture_path("blog_api.eon"), &config).expect("fixture should copy");
    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize auth-enabled blog service");
        });

    let client_dir = root.join("generated-client");
    generate_client(&config, &client_dir);
    assert_dependency_free_client(&client_dir);
    compile_generated_client(&client_dir);

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
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "generated-client-blog-secret")
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
            "generated client server never became ready: {error}\n{}",
            server.logs()
        );
    }

    let script_path = client_dir.join("smoke.mjs");
    fs::write(
        &script_path,
        r#"import {
  createClient,
  loginUser,
  getAuthenticatedAccount,
  createPost,
  listPost,
  getPost,
  updatePost,
} from "./index.js";

const baseUrl = process.env.BASE_URL;
const email = process.env.EMAIL;
const password = process.env.PASSWORD;
if (!baseUrl || !email || !password) {
  throw new Error("missing smoke-test env");
}

const anonClient = createClient({ baseUrl });
const login = await loginUser(anonClient, {
  body: { email, password },
});
if (!login.token) {
  throw new Error("login did not return a token");
}

const authClient = createClient({
  baseUrl,
  getAccessToken: () => login.token,
});
const me = await getAuthenticatedAccount(authClient);
if (!Array.isArray(me.roles) || !me.roles.includes("admin")) {
  throw new Error(`expected admin roles, got ${JSON.stringify(me.roles)}`);
}

await createPost(authClient, {
  body: {
    title: "Generated Client Post",
    content: "Created through generated client",
  },
});

const posts = await listPost(authClient);
const created = posts.items.find((post) => post.title === "Generated Client Post");
if (!created || typeof created.id !== "number") {
  throw new Error(`created post not found in list: ${JSON.stringify(posts)}`);
}

const fetched = await getPost(authClient, { path: { id: created.id } });
if (fetched.content !== "Created through generated client") {
  throw new Error(`unexpected fetched post: ${JSON.stringify(fetched)}`);
}

await updatePost(authClient, {
  path: { id: created.id },
  body: {
    title: "Generated Client Post",
    content: "Updated through generated client",
  },
});

const updated = await getPost(authClient, { path: { id: created.id } });
if (updated.content !== "Updated through generated client") {
  throw new Error(`unexpected updated post: ${JSON.stringify(updated)}`);
}
"#,
    )
    .expect("smoke script should write");

    let output = run_node_script(
        &script_path,
        &[
            ("BASE_URL", &base_url),
            ("EMAIL", "admin@example.com"),
            ("PASSWORD", "password123"),
        ],
    );
    assert!(
        output.status.success(),
        "generated client smoke script failed\nstdout:\n{}\nstderr:\n{}\nserver:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        server.logs()
    );
}

#[test]
fn generated_typescript_client_supports_uploads_against_live_server() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "generated-client-upload-secret");
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");
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

    let client_dir = root.join("generated-client");
    generate_client(&config, &client_dir);
    assert_dependency_free_client(&client_dir);
    compile_generated_client(&client_dir);

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
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "generated-client-upload-secret")
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
            "generated upload client server never became ready: {error}\n{}",
            server.logs()
        );
    }

    let script_path = client_dir.join("upload-smoke.mjs");
    fs::write(
        &script_path,
        r#"import {
  ApiError,
  createClient,
  loginUser,
  registerUser,
  uploadAssetUpload,
} from "./index.js";

const baseUrl = process.env.BASE_URL;
const email = process.env.EMAIL;
const password = process.env.PASSWORD;
if (!baseUrl || !email || !password) {
  throw new Error("missing smoke-test env");
}

const anonClient = createClient({ baseUrl });
try {
  await registerUser(anonClient, {
    body: { email, password },
  });
} catch (error) {
  if (!(error instanceof ApiError) || error.status !== 409) {
    throw error;
  }
}

const login = await loginUser(anonClient, {
  body: { email, password },
});
if (!login.token) {
  throw new Error("login did not return a token");
}

const authClient = createClient({
  baseUrl,
  getAccessToken: () => login.token,
});
const upload = await uploadAssetUpload(authClient, {
  body: {
    file: new Blob(["hello upload"], { type: "text/plain" }),
  },
});
if (upload.backend !== "uploads") {
  throw new Error(`unexpected backend: ${JSON.stringify(upload)}`);
}
if (upload.file_name !== "blob") {
  throw new Error(`unexpected file name: ${JSON.stringify(upload)}`);
}
if (typeof upload.public_url !== "string" || !upload.public_url.startsWith("/uploads/")) {
  throw new Error(`unexpected public url: ${JSON.stringify(upload)}`);
}

const assetResponse = await fetch(`${baseUrl}${upload.public_url}`);
if (!assetResponse.ok) {
  throw new Error(`asset fetch failed: ${assetResponse.status}`);
}
const body = await assetResponse.text();
if (body !== "hello upload") {
  throw new Error(`unexpected uploaded body: ${body}`);
}
"#,
    )
    .expect("upload smoke script should write");

    let output = run_node_script(
        &script_path,
        &[
            ("BASE_URL", &base_url),
            ("EMAIL", "uploader@example.com"),
            ("PASSWORD", "password123"),
        ],
    );
    assert!(
        output.status.success(),
        "generated upload client smoke script failed\nstdout:\n{}\nstderr:\n{}\nserver:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        server.logs()
    );
}

#[test]
fn generated_typescript_client_supports_public_query_and_nested_routes_against_live_server() {
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

    let client_dir = root.join("generated-client");
    generate_client(&config, &client_dir);
    assert_dependency_free_client(&client_dir);
    compile_generated_client(&client_dir);

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
    if let Err(error) = wait_for_http_ready(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(30),
    ) {
        panic!(
            "generated public client server never became ready: {error}\n{}",
            server.logs()
        );
    }

    let script_path = client_dir.join("public-smoke.mjs");
    fs::write(
        &script_path,
        r#"import {
  createClient,
  listInterestByOrganization,
  listOrganization,
} from "./index.js";

const baseUrl = process.env.BASE_URL;
if (!baseUrl) {
  throw new Error("missing smoke-test env");
}

const client = createClient({ baseUrl });
const organizations = await listOrganization(client, {
  query: {
    filter_name_contains: "BRIDGE",
  },
});
if (organizations.total !== 1) {
  throw new Error(`unexpected organization total: ${JSON.stringify(organizations)}`);
}
if (organizations.items[0]?.country !== "Finland") {
  throw new Error(`unexpected organization item: ${JSON.stringify(organizations)}`);
}

const interests = await listInterestByOrganization(client, {
  path: { parent_id: 1 },
  query: {
    filter_summary_contains: "THESIS",
  },
});
if (interests.total !== 1) {
  throw new Error(`unexpected interest total: ${JSON.stringify(interests)}`);
}
if (interests.items[0]?.title !== "AI Thesis Co-Creation") {
  throw new Error(`unexpected interest item: ${JSON.stringify(interests)}`);
}
"#,
    )
    .expect("public smoke script should write");

    let output = run_node_script(&script_path, &[("BASE_URL", &base_url)]);
    assert!(
        output.status.success(),
        "generated public client smoke script failed\nstdout:\n{}\nstderr:\n{}\nserver:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        server.logs()
    );
}

#[test]
fn generated_typescript_client_serializes_datetime_objects_against_live_server() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "generated-client-datetime-secret");
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("datetime_api.eon");
    fs::copy(fixture_path("datetime_api.eon"), &config).expect("fixture should copy");
    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize datetime service");
        });

    let client_dir = root.join("generated-client");
    generate_client(&config, &client_dir);
    assert_dependency_free_client(&client_dir);
    compile_generated_client(&client_dir);

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
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "generated-client-datetime-secret")
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
            "generated datetime client server never became ready: {error}\n{}",
            server.logs()
        );
    }

    let script_path = client_dir.join("datetime-smoke.mjs");
    fs::write(
        &script_path,
        r#"import {
  createClient,
  createEvent,
  loginUser,
  listEvent,
} from "./index.js";

const baseUrl = process.env.BASE_URL;
const email = process.env.EMAIL;
const password = process.env.PASSWORD;
if (!baseUrl || !email || !password) {
  throw new Error("missing smoke-test env");
}

const anonClient = createClient({ baseUrl });
const login = await loginUser(anonClient, {
  body: { email, password },
});
if (!login.token) {
  throw new Error("login did not return a token");
}

const authClient = createClient({
  baseUrl,
  getAccessToken: () => login.token,
});

await createEvent(authClient, {
  body: {
    title: "Temporal Alpha",
    starts_at: new Date("2026-03-17T10:00:00Z"),
    ends_at: new Date("2026-03-17T11:00:00Z"),
  },
});

const exact = await listEvent(authClient, {
  query: {
    filter_starts_at: new Date("2026-03-17T10:00:00Z"),
    sort: "starts_at",
    order: "asc",
  },
});
if (exact.total !== 1 || exact.items[0]?.title !== "Temporal Alpha") {
  throw new Error(`unexpected exact datetime result: ${JSON.stringify(exact)}`);
}

const ranged = await listEvent(authClient, {
  query: {
    filter_starts_at_gte: new Date("2026-03-17T09:59:59Z"),
    filter_starts_at_lt: new Date("2026-03-17T10:00:01Z"),
    sort: "starts_at",
    order: "asc",
  },
});
if (ranged.total !== 1 || ranged.items[0]?.title !== "Temporal Alpha") {
  throw new Error(`unexpected ranged datetime result: ${JSON.stringify(ranged)}`);
}
"#,
    )
    .expect("datetime smoke script should write");

    let output = run_node_script(
        &script_path,
        &[
            ("BASE_URL", &base_url),
            ("EMAIL", "admin@example.com"),
            ("PASSWORD", "password123"),
        ],
    );
    assert!(
        output.status.success(),
        "generated datetime client smoke script failed\nstdout:\n{}\nstderr:\n{}\nserver:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        server.logs()
    );
}

#[test]
fn generated_typescript_client_serializes_date_and_time_objects_against_live_server() {
    let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
    unsafe {
        std::env::set_var("TURSO_ENCRYPTION_KEY", TEST_TURSO_KEY);
        std::env::set_var("JWT_SECRET", "generated-client-scalar-types-secret");
        std::env::set_var("ADMIN_EMAIL", "admin@example.com");
        std::env::set_var("ADMIN_PASSWORD", "password123");
    }

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("scalar_types_api.eon");
    fs::copy(fixture_path("scalar_types_api.eon"), &config).expect("fixture should copy");
    let database_url =
        database_url_from_service_config(&config).expect("database url should resolve");
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should initialize")
        .block_on(async {
            run_setup(&database_url, Some(&config), true, false, false)
                .await
                .expect("setup should initialize scalar types service");
        });

    let client_dir = root.join("generated-client");
    generate_client(&config, &client_dir);
    assert_dependency_free_client(&client_dir);
    compile_generated_client(&client_dir);

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
        .env("BIND_ADDR", &bind_addr)
        .env("JWT_SECRET", "generated-client-scalar-types-secret")
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
            "generated scalar-types client server never became ready: {error}\n{}",
            server.logs()
        );
    }

    let script_path = client_dir.join("scalar-types-smoke.mjs");
    fs::write(
        &script_path,
        r#"import {
  VsrDate,
  VsrTime,
  createClient,
  createSchedule,
  loginUser,
  listSchedule,
} from "./index.js";

const baseUrl = process.env.BASE_URL;
const email = process.env.EMAIL;
const password = process.env.PASSWORD;
if (!baseUrl || !email || !password) {
  throw new Error("missing smoke-test env");
}

const anonClient = createClient({ baseUrl });
const login = await loginUser(anonClient, {
  body: { email, password },
});
if (!login.token) {
  throw new Error("login did not return a token");
}

const authClient = createClient({
  baseUrl,
  getAccessToken: () => login.token,
});

await createSchedule(authClient, {
  body: {
    run_on: new VsrDate(2026, 3, 17),
    run_at: new VsrTime(8, 0, 0),
    external_id: "33333333-3333-4333-8333-333333333333",
    amount: "1.5000",
  },
});

const exact = await listSchedule(authClient, {
  query: {
    filter_run_on: new VsrDate(2026, 3, 17),
    filter_run_at: new VsrTime(8, 0, 0),
    sort: "run_on",
    order: "asc",
  },
});
if (exact.total !== 1 || exact.items[0]?.external_id !== "33333333-3333-4333-8333-333333333333") {
  throw new Error(`unexpected exact date/time result: ${JSON.stringify(exact)}`);
}

const ranged = await listSchedule(authClient, {
  query: {
    filter_run_on_gte: new VsrDate(2026, 3, 17),
    filter_run_on_lt: new VsrDate(2026, 3, 18),
    filter_run_at_gt: new VsrTime(7, 59, 59),
    filter_run_at_lte: new VsrTime(8, 0, 0),
    sort: "run_at",
    order: "asc",
  },
});
if (ranged.total !== 1 || ranged.items[0]?.external_id !== "33333333-3333-4333-8333-333333333333") {
  throw new Error(`unexpected ranged date/time result: ${JSON.stringify(ranged)}`);
}
"#,
    )
    .expect("scalar types smoke script should write");

    let output = run_node_script(
        &script_path,
        &[
            ("BASE_URL", &base_url),
            ("EMAIL", "admin@example.com"),
            ("PASSWORD", "password123"),
        ],
    );
    assert!(
        output.status.success(),
        "generated scalar types client smoke script failed\nstdout:\n{}\nstderr:\n{}\nserver:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        server.logs()
    );
}

#[test]
fn client_ts_self_test_produces_passing_report_against_live_server() {
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
    if let Err(error) = wait_for_http_ready(
        &client,
        &format!("{base_url}/openapi.json"),
        Duration::from_secs(30),
    ) {
        panic!(
            "generated client self-test server never became ready: {error}\n{}",
            server.logs()
        );
    }

    let client_dir = root.join("generated-client");
    let report_path = root.join("client-self-test-report.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_vsr"));
    command
        .arg("client")
        .arg("ts")
        .arg("--input")
        .arg(&config)
        .arg("--output")
        .arg(&client_dir)
        .arg("--emit-js")
        .arg("--force")
        .arg("--without-auth")
        .arg("--self-test")
        .arg("--self-test-base-url")
        .arg(&base_url)
        .arg("--self-test-report")
        .arg(&report_path);
    if let Some(tsc_binary) = find_tsc_binary() {
        command.arg("--self-test-tsc").arg(tsc_binary);
    }
    let output = command
        .output()
        .expect("vsr client ts self-test should execute");
    assert!(
        output.status.success(),
        "generated client self-test command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value =
        serde_json::from_str(&read_to_string(&report_path)).expect("report should parse");
    assert_eq!(report.get("passed").and_then(Value::as_bool), Some(true));
    assert_eq!(report["summary"]["failed"].as_u64(), Some(0));
    let checks = report["checks"]
        .as_array()
        .expect("report checks should be an array");
    assert!(
        checks.iter().any(|check| {
            check["name"] == "manifest.dependencies" && check["status"] == "passed"
        })
    );
    assert!(
        checks
            .iter()
            .any(|check| { check["name"] == "module.imports" && check["status"] == "passed" })
    );
    assert!(checks.iter().any(|check| {
        check["name"] == "runtime.node_import_smoke" && check["status"] == "passed"
    }));
    assert!(checks.iter().any(|check| {
        check["name"] == "runtime.openapi_reachable" && check["status"] == "passed"
    }));
}

#[test]
fn client_ts_self_test_static_report_matches_snapshot() {
    let Some(tsc_binary) = find_tsc_binary() else {
        eprintln!("skipping generated client self-test snapshot because local tsc is unavailable");
        return;
    };

    let root = test_root();
    fs::create_dir_all(&root).expect("test root should exist");

    let config = root.join("public_catalog_api.eon");
    fs::copy(fixture_path("public_catalog_api.eon"), &config).expect("fixture should copy");

    let client_dir = root.join("generated-client");
    let report_path = root.join("client-self-test-report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .arg("client")
        .arg("ts")
        .arg("--input")
        .arg(&config)
        .arg("--output")
        .arg(&client_dir)
        .arg("--force")
        .arg("--without-auth")
        .arg("--self-test")
        .arg("--self-test-report")
        .arg(&report_path)
        .arg("--self-test-tsc")
        .arg(tsc_binary)
        .output()
        .expect("vsr client ts self-test should execute");
    assert!(
        output.status.success(),
        "generated client static self-test command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value =
        serde_json::from_str(&read_to_string(&report_path)).expect("report should parse");
    let normalized = normalize_self_test_report(report);
    let rendered = serde_json::to_string_pretty(&normalized)
        .expect("normalized report should serialize")
        + "\n";
    assert_text_snapshot(
        &snapshot_path("public_catalog_static_report.json"),
        &rendered,
    );
}

#[test]
fn build_uses_clients_ts_automation_for_template_example_copy() {
    let root = test_root();
    let service_dir = root.join("template-example");
    fs::create_dir_all(&service_dir).expect("service dir should exist");

    let template = read_to_string(&example_path("template/api.eon"));
    let automated = format!(
        r#"{template}

clients: {{
    ts: {{
        output_dir: {{
            path: "web/src/gen/client"
        }}
        include_builtin_auth: false
        automation: {{
            on_build: true
            self_test: true
            self_test_report: {{
                path: "reports/client-self-test.json"
            }}
        }}
    }}
}}
"#
    );
    let input = service_dir.join("api.eon");
    fs::write(&input, automated).expect("example copy should write");

    let output = root.join("dist/template-example");
    let build_dir = root.join("build-cache");
    let command_output = Command::new(env!("CARGO_BIN_EXE_vsr"))
        .arg("build")
        .arg(&input)
        .arg("--without-auth")
        .arg("--output")
        .arg(&output)
        .arg("--build-dir")
        .arg(&build_dir)
        .arg("--force")
        .output()
        .expect("vsr build should execute");
    assert!(
        command_output.status.success(),
        "vsr build should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&command_output.stdout),
        String::from_utf8_lossy(&command_output.stderr)
    );

    assert!(output.exists(), "built binary should exist");
    assert!(
        service_dir.join("web/src/gen/client/index.ts").exists(),
        "automated client generation should emit the configured output directory"
    );
    assert!(
        service_dir.join("reports/client-self-test.json").exists(),
        "automated client self-test should write the configured report"
    );
}

#[test]
fn family_app_example_generates_browser_ready_client_modules() {
    let root = test_root();
    let service_dir = root.join("family_app");
    fs::create_dir_all(&service_dir).expect("service dir should exist");

    let source_dir = example_path("family_app");
    fs::copy(
        source_dir.join("family_app.eon"),
        service_dir.join("family_app.eon"),
    )
    .expect("family app config should copy");

    let public_dir = service_dir.join("public");
    fs::create_dir_all(&public_dir).expect("public dir should exist");
    fs::copy(
        source_dir.join("public/index.html"),
        public_dir.join("index.html"),
    )
    .expect("index.html should copy");
    fs::copy(
        source_dir.join("public/styles.css"),
        public_dir.join("styles.css"),
    )
    .expect("styles.css should copy");
    fs::copy(source_dir.join("public/app.js"), public_dir.join("app.js"))
        .expect("app.js should copy");

    generate_client(
        &service_dir.join("family_app.eon"),
        &service_dir.join("public/gen/client"),
    );

    let output_dir = service_dir.join("public/gen/client");
    assert_dependency_free_client(&output_dir);
    compile_generated_client(&output_dir);
    assert!(
        output_dir.join("index.js").exists(),
        "browser JS entry should exist"
    );
    assert!(
        output_dir.join("client.js").exists(),
        "browser JS runtime should exist"
    );
    assert!(
        output_dir.join("operations.js").exists(),
        "browser JS operations should exist"
    );

    let app_js = read_to_string(&service_dir.join("public/app.js"));
    assert!(
        app_js.contains("from \"./gen/client/index.js\""),
        "family app should import the generated browser client"
    );
}
