# Phase 1 Observability And Feature Flags Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase 1 of `docs/src/architecture_roadmap.md`: add the first observability spine, make optional runtime capabilities honest in feature flags, add native `vsr serve` health/readiness endpoints, and expand CI feature coverage across supported platforms.

**Architecture:** Keep the first observability API in `vsr-core` as dependency-light primitives with no-op behavior when features are disabled. Wire native `vsr serve` first, because emitted-server telemetry moves with `vsr-runtime` in Phase 3. Feature flag work should make generated projects request only the runtime features their `.eon` contract uses.

**Tech Stack:** Rust 2024, Actix Web, `tracing`, `metrics`, Cargo features, GitHub Actions.

---

## File Structure

- Modify: `Cargo.toml`
  Workspace feature/dependency forwarding for `tracing`, `metrics`, `auth-email`, and `storage-local`.

- Modify: `crates/vsr-core/Cargo.toml`
  Add optional telemetry dependencies and features.

- Modify: `crates/vsr-core/src/lib.rs`
  Export the new `telemetry` module.

- Create: `crates/vsr-core/src/telemetry.rs`
  Own VSR-level HTTP telemetry event types and no-op/feature-gated recording helpers.

- Modify: `crates/rest_api_cli/Cargo.toml`
  Depend on `vsr-core`, expose CLI feature flags for `storage-local`, and stop enabling heavy runtime features unconditionally.

- Modify: `crates/rest_api_cli/src/commands/serve.rs`
  Add native `vsr serve` `/healthz` and `/readyz` routes and record structured request telemetry.

- Modify: `crates/rest_api_cli/src/commands/server.rs`
  Update generated project dependency feature selection for `auth-email` and `storage-local`.

- Modify: `crates/rest_api_cli/tests/serve_cli.rs`
  Add spawned-process coverage for `/healthz` and `/readyz` in native `vsr serve`.

- Modify: `.github/workflows/generated-code-quality.yml`
  Expand platform and feature matrix so default, no-default, and all-features are checked on Linux, macOS, and Windows.

---

### Task 1: Add `vsr-core::telemetry`

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/vsr-core/Cargo.toml`
- Modify: `crates/vsr-core/src/lib.rs`
- Create: `crates/vsr-core/src/telemetry.rs`

- [ ] **Step 1: Add workspace dependency versions**

Modify root `Cargo.toml` `[workspace.dependencies]`:

```toml
tracing = "0.1"
metrics = "0.24"
```

- [ ] **Step 2: Add optional telemetry dependencies to `vsr-core`**

Modify `crates/vsr-core/Cargo.toml`:

```toml
[features]
default = []
chrono = ["dep:chrono"]
tracing = ["dep:tracing"]
metrics = ["dep:metrics"]
telemetry = ["tracing", "metrics"]

[dependencies.tracing]
workspace = true
optional = true

[dependencies.metrics]
workspace = true
optional = true
```

Keep the existing `chrono`, `sqlite`, `postgres`, `mysql`, and `turso-local` feature entries unchanged.

- [ ] **Step 3: Create the telemetry module**

Create `crates/vsr-core/src/telemetry.rs`:

```rust
//! Telemetry primitives shared by VSR runtime layers.
//!
//! This module is intentionally dependency-light. Without the `tracing` and
//! `metrics` features, recording helpers compile to no-ops.

/// HTTP request telemetry event recorded by runtime adapters.
#[derive(Clone, Debug, PartialEq)]
pub struct HttpRequestTelemetry<'a> {
    /// HTTP method, for example `GET`.
    pub method: &'a str,
    /// Route pattern or request path.
    pub route: &'a str,
    /// HTTP response status code.
    pub status: u16,
    /// Request latency in milliseconds.
    pub latency_ms: f64,
}

impl<'a> HttpRequestTelemetry<'a> {
    /// Create a new HTTP request telemetry event.
    pub const fn new(method: &'a str, route: &'a str, status: u16, latency_ms: f64) -> Self {
        Self {
            method,
            route,
            status,
            latency_ms,
        }
    }
}

/// Record one HTTP request event.
pub fn record_http_request(event: &HttpRequestTelemetry<'_>) {
    record_http_request_trace(event);
    record_http_request_metrics(event);
}

#[cfg(feature = "tracing")]
fn record_http_request_trace(event: &HttpRequestTelemetry<'_>) {
    tracing::info!(
        target: "vsr.http",
        method = event.method,
        route = event.route,
        status = event.status,
        latency_ms = event.latency_ms,
        "request completed",
    );
}

#[cfg(not(feature = "tracing"))]
const fn record_http_request_trace(_event: &HttpRequestTelemetry<'_>) {}

#[cfg(feature = "metrics")]
fn record_http_request_metrics(event: &HttpRequestTelemetry<'_>) {
    let status = event.status.to_string();
    metrics::counter!(
        "vsr_http_requests_total",
        "method" => event.method.to_owned(),
        "route" => event.route.to_owned(),
        "status" => status.clone(),
    )
    .increment(1);
    metrics::histogram!(
        "vsr_http_request_latency_ms",
        "method" => event.method.to_owned(),
        "route" => event.route.to_owned(),
        "status" => status,
    )
    .record(event.latency_ms);
}

#[cfg(not(feature = "metrics"))]
const fn record_http_request_metrics(_event: &HttpRequestTelemetry<'_>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request_telemetry_constructor_preserves_fields() {
        let event = HttpRequestTelemetry::new("GET", "/healthz", 200, 1.25);
        assert_eq!(event.method, "GET");
        assert_eq!(event.route, "/healthz");
        assert_eq!(event.status, 200);
        assert_eq!(event.latency_ms, 1.25);
    }
}
```

- [ ] **Step 4: Export telemetry from `vsr-core`**

Modify `crates/vsr-core/src/lib.rs`:

```rust
pub mod telemetry;

pub use telemetry::{HttpRequestTelemetry, record_http_request};
```

- [ ] **Step 5: Verify the new core module**

Run:

```powershell
cargo test -p vsr-core telemetry --all-features
```

Expected: the constructor test passes.

- [ ] **Step 6: Commit**

```powershell
git add Cargo.toml crates/vsr-core/Cargo.toml crates/vsr-core/src/lib.rs crates/vsr-core/src/telemetry.rs
git commit -m "feat: add core telemetry primitives"
```

---

### Task 2: Add native `vsr serve` health and readiness endpoints

**Files:**
- Modify: `crates/rest_api_cli/Cargo.toml`
- Modify: `crates/rest_api_cli/src/commands/serve.rs`
- Modify: `crates/rest_api_cli/tests/serve_cli.rs`

- [ ] **Step 1: Add `vsr-core` to the CLI**

Modify `crates/rest_api_cli/Cargo.toml` `[dependencies]`:

```toml
vsr-core = { workspace = true, features = ["telemetry"] }
```

- [ ] **Step 2: Add endpoint handlers in native serve**

In `crates/rest_api_cli/src/commands/serve.rs`, near the existing `openapi_spec` and Swagger handlers, add:

```rust
async fn healthz() -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(r#"{"status":"ok"}"#)
}

async fn readyz() -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(r#"{"status":"ready"}"#)
}
```

- [ ] **Step 3: Register routes in the Actix app**

In the `HttpServer::new` app builder in `crates/rest_api_cli/src/commands/serve.rs`, add the routes beside `/openapi.json`:

```rust
.route("/healthz", web::get().to(healthz))
.route("/readyz", web::get().to(readyz))
```

- [ ] **Step 4: Add spawned-process coverage**

Modify `crates/rest_api_cli/tests/serve_cli.rs`, adding assertions to `vsr_serve_starts_native_runtime_from_eon` after the existing readiness wait:

```rust
let health = client
    .get(format!("{base_url}/healthz"))
    .send()
    .expect("health request should complete");
assert_eq!(health.status(), reqwest::StatusCode::OK);
assert_eq!(
    health.text().expect("health response should be readable"),
    r#"{"status":"ok"}"#
);

let ready = client
    .get(format!("{base_url}/readyz"))
    .send()
    .expect("ready request should complete");
assert_eq!(ready.status(), reqwest::StatusCode::OK);
assert_eq!(
    ready.text().expect("ready response should be readable"),
    r#"{"status":"ready"}"#
);
```

- [ ] **Step 5: Verify the native endpoint test**

Run:

```powershell
cargo test -p vsra --test serve_cli vsr_serve_starts_native_runtime_from_eon -- --nocapture
```

Expected: the spawned native runtime test passes and both endpoints return `200`.

- [ ] **Step 6: Commit**

```powershell
git add crates/rest_api_cli/Cargo.toml crates/rest_api_cli/src/commands/serve.rs crates/rest_api_cli/tests/serve_cli.rs
git commit -m "feat: add native serve health endpoints"
```

---

### Task 3: Record native `vsr serve` request telemetry

**Files:**
- Modify: `crates/rest_api_cli/src/commands/serve.rs`
- Modify: `crates/rest_api_cli/tests/serve_cli.rs`

- [ ] **Step 1: Add imports**

At the top of `crates/rest_api_cli/src/commands/serve.rs`, add:

```rust
use std::time::Instant;
use vsr_core::{HttpRequestTelemetry, record_http_request};
```

- [ ] **Step 2: Wrap the Actix app with telemetry middleware**

In the native `HttpServer::new` app builder, add this wrapper after `Logger::default()`:

```rust
.wrap_fn(|req, srv| {
    let method = req.method().as_str().to_owned();
    let route = req.path().to_owned();
    let started_at = Instant::now();
    let fut = srv.call(req);
    async move {
        let response = fut.await?;
        let status = response.status().as_u16();
        let latency_ms = started_at.elapsed().as_secs_f64() * 1000.0;
        record_http_request(&HttpRequestTelemetry::new(
            method.as_str(),
            route.as_str(),
            status,
            latency_ms,
        ));
        Ok(response)
    }
})
```

If `srv.call(req)` requires an import, add:

```rust
use actix_web::dev::Service;
```

- [ ] **Step 3: Add a log smoke assertion**

In `crates/rest_api_cli/tests/serve_cli.rs`, do not parse env logger output. Keep the test focused on behavior: the middleware is covered by the spawned-process endpoint requests from Task 2 and compilation with `vsr-core/telemetry`.

- [ ] **Step 4: Verify the middleware compiles and endpoint test still passes**

Run:

```powershell
cargo test -p vsra --test serve_cli vsr_serve_starts_native_runtime_from_eon -- --nocapture
```

Expected: the test still passes.

- [ ] **Step 5: Commit**

```powershell
git add crates/rest_api_cli/src/commands/serve.rs crates/rest_api_cli/tests/serve_cli.rs
git commit -m "feat: record native serve request telemetry"
```

---

### Task 4: Align runtime feature flags across root, CLI, and generated projects

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/rest_api_cli/Cargo.toml`
- Modify: `crates/rest_api_cli/src/commands/server.rs`
- Modify: `crates/rest_api_cli/tests/server_cli.rs` if this test file exists; otherwise add assertions to existing server command tests in `crates/rest_api_cli/src/commands/server.rs`.

- [ ] **Step 1: Expose root runtime features**

Modify root `Cargo.toml` `[features]`:

```toml
auth-email = ["rest_macro_core/auth-email"]
storage-local = ["rest_macro_core/storage-local"]
```

Keep the existing `storage-local = ["rest_macro_core/storage-local"]` entry if it already exists and only add `auth-email`.

- [ ] **Step 2: Stop enabling storage in `rest_macro_core` unconditionally for the CLI**

Modify `crates/rest_api_cli/Cargo.toml`:

```toml
[features]
default = ["sqlite", "turso-local", "postgres", "auth-email", "storage-local"]
auth-email = ["rest_macro_core/auth-email"]
storage-local = ["rest_macro_core/storage-local", "dep:object_store"]

[dependencies]
rest_macro_core = { workspace = true, features = ["codegen"] }
object_store = { workspace = true, features = ["aws", "fs"], optional = true }
```

Keep `aws-sdk-s3-backup` and `s3-backup` optional as they are today.

- [ ] **Step 3: Gate native storage runtime wiring**

In `crates/rest_api_cli/src/commands/serve.rs`, any imports and calls that require `rest_macro_core::storage::StorageRegistry` or local object-store runtime functions must be under:

```rust
#[cfg(feature = "storage-local")]
```

For services with `!service.storage.is_empty()` when `storage-local` is disabled, return:

```rust
return Err(Error::Config(
    "this service uses `storage`, but the vsr binary was built without the `storage-local` feature"
        .to_owned(),
));
```

- [ ] **Step 4: Add generated dependency feature selection**

In `crates/rest_api_cli/src/commands/server.rs`, update `runtime_feature_list`:

```rust
if service.security.auth.email.is_some() {
    features.push("\"auth-email\"".to_owned());
}
if !service.storage.is_empty() {
    features.push("\"storage-local\"".to_owned());
}
```

Preserve the existing backend and `turso-local` feature behavior.

- [ ] **Step 5: Add generated Cargo.toml assertions**

In existing server command tests in `crates/rest_api_cli/src/commands/server.rs`, add assertions for generated projects:

```rust
assert!(cargo_toml.contains("\"auth-email\""));
assert!(cargo_toml.contains("\"storage-local\""));
```

Use an auth-email fixture for `auth-email` and a storage fixture for `storage-local`; do not assert both features from the same fixture unless that fixture actually uses both capabilities.

- [ ] **Step 6: Verify feature sets**

Run:

```powershell
cargo check -p vsra --no-default-features
cargo check -p vsra --all-features
cargo test -p vsra emit_server_project_storage_upload_generated_code_is_warning_clean -- --ignored --nocapture --test-threads=1
```

Expected: no-default and all-features compile; the storage generated project check still passes.

- [ ] **Step 7: Commit**

```powershell
git add Cargo.toml crates/rest_api_cli/Cargo.toml crates/rest_api_cli/src/commands/serve.rs crates/rest_api_cli/src/commands/server.rs
git commit -m "fix: align optional runtime feature flags"
```

---

### Task 5: Expand CI to platform by feature-set coverage

**Files:**
- Modify: `.github/workflows/generated-code-quality.yml`

- [ ] **Step 1: Replace separate platform and feature jobs with a combined matrix**

In `.github/workflows/generated-code-quality.yml`, replace the current `rust-check` and `feature-check` jobs with one matrix:

```yaml
  rust-feature-check:
    name: Rust Check (${{ matrix.os }}, ${{ matrix.feature_profile }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        include:
          - feature_profile: default
            command: cargo check --workspace
          - feature_profile: no-default-features
            command: cargo check --workspace --no-default-features
          - feature_profile: all-features
            command: cargo check --workspace --all-features
    steps:
      - uses: actions/checkout@v6
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      - name: Cache Cargo
        uses: Swatinem/rust-cache@v2
      - name: Check Workspace Feature Set
        run: ${{ matrix.command }}
```

If GitHub rejects `include` with `os` fan-out semantics, use two dimensions instead:

```yaml
matrix:
  os: [ubuntu-latest, macos-latest, windows-latest]
  feature_profile:
    - default
    - no-default-features
    - all-features
```

and switch the command with a shell-specific step per profile.

- [ ] **Step 2: Keep `generated-warning-clean` on Ubuntu**

Do not move the heavy generated-project tests to every platform in Phase 1. Keep the existing `generated-warning-clean` job on `ubuntu-latest` because the roadmap says platform tests expand in phases and this job already compiles generated projects deeply.

- [ ] **Step 3: Verify workflow syntax through GitHub Actions**

Push the branch and watch:

```powershell
gh run list --branch v1 --limit 3
gh run watch <run-id> --exit-status
```

Expected: all matrix jobs and `generated-warning-clean` pass.

- [ ] **Step 4: Commit**

```powershell
git add .github/workflows/generated-code-quality.yml
git commit -m "ci: check feature sets across platforms"
```

---

## Execution Order

1. Task 1: `vsr-core` telemetry primitives.
2. Task 2: native health/readiness endpoints.
3. Task 3: native request telemetry recording.
4. Task 4: optional runtime feature alignment.
5. Task 5: CI feature/platform matrix expansion.

This order keeps each commit independently reviewable and prevents CI matrix expansion from landing before local feature-set compilation has been repaired.

---

## Verification Summary

Run before final push:

```powershell
cargo test -p vsr-core telemetry --all-features
cargo test -p vsra --test serve_cli vsr_serve_starts_native_runtime_from_eon -- --nocapture
cargo check -p vsra --no-default-features
cargo check -p vsra --all-features
cargo test -p vsra emit_server_project_storage_upload_generated_code_is_warning_clean -- --ignored --nocapture --test-threads=1
```

Run after push:

```powershell
gh run watch <run-id> --exit-status
```

Expected final state: native `vsr serve` has `/healthz` and `/readyz`, request telemetry records through `vsr-core`, generated projects request `auth-email` and `storage-local` only when needed, and CI checks default/no-default/all-features on Linux, macOS, and Windows.
