use std::{
    env,
    path::{Component, Path, PathBuf},
};

use actix_files::NamedFile;
use actix_web::{
    HttpRequest, HttpResponse,
    http::{
        Method,
        header::{self, ContentEncoding},
    },
    web,
};

use crate::runtime::RuntimeConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticMode {
    Directory,
    Spa,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticCacheProfile {
    NoStore,
    Revalidate,
    Immutable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticMount {
    pub mount_path: &'static str,
    pub source_dir: &'static str,
    pub resolved_dir: &'static str,
    pub mode: StaticMode,
    pub index_file: Option<&'static str>,
    pub fallback_file: Option<&'static str>,
    pub cache: StaticCacheProfile,
}

pub fn configure_static_mounts(cfg: &mut web::ServiceConfig, mounts: &[StaticMount]) {
    configure_static_mounts_with_runtime(cfg, mounts, &RuntimeConfig::default());
}

pub fn configure_static_mounts_with_runtime(
    cfg: &mut web::ServiceConfig,
    mounts: &[StaticMount],
    runtime: &RuntimeConfig,
) {
    let mut ordered = mounts.to_vec();
    ordered.sort_by(|left, right| right.mount_path.len().cmp(&left.mount_path.len()));

    for mount in ordered {
        register_mount(cfg, mount, runtime.clone());
    }
}

fn register_mount(cfg: &mut web::ServiceConfig, mount: StaticMount, runtime: RuntimeConfig) {
    let exact_mount = mount;
    let exact_get_runtime = runtime.clone();
    let exact_head_runtime = runtime.clone();
    let exact_path = if mount.mount_path == "/" {
        "/".to_owned()
    } else {
        mount.mount_path.to_owned()
    };
    cfg.service(
        web::resource(exact_path)
            .route(web::get().to(move |req: HttpRequest| {
                serve_static_request(req, exact_mount, None, exact_get_runtime.clone())
            }))
            .route(web::head().to(move |req: HttpRequest| {
                serve_static_request(req, exact_mount, None, exact_head_runtime.clone())
            })),
    );

    let tail_mount = mount;
    let tail_get_runtime = runtime.clone();
    let tail_head_runtime = runtime;
    let tail_path = if mount.mount_path == "/" {
        "/{tail:.*}".to_owned()
    } else {
        format!("{}/{{tail:.*}}", mount.mount_path)
    };
    cfg.service(
        web::resource(tail_path)
            .route(
                web::get().to(move |req: HttpRequest, tail: web::Path<String>| {
                    serve_static_request(
                        req,
                        tail_mount,
                        Some(tail.into_inner()),
                        tail_get_runtime.clone(),
                    )
                }),
            )
            .route(
                web::head().to(move |req: HttpRequest, tail: web::Path<String>| {
                    serve_static_request(
                        req,
                        tail_mount,
                        Some(tail.into_inner()),
                        tail_head_runtime.clone(),
                    )
                }),
            ),
    );
}

async fn serve_static_request(
    req: HttpRequest,
    mount: StaticMount,
    tail: Option<String>,
    runtime: RuntimeConfig,
) -> actix_web::Result<HttpResponse> {
    if reserved_runtime_path(req.path()) {
        return Ok(HttpResponse::NotFound().finish());
    }

    let Some(canonical_base) = resolve_mount_base_dir(mount) else {
        return Ok(HttpResponse::NotFound().finish());
    };
    let relative_path = sanitize_requested_path(tail.as_deref().unwrap_or(""))?;

    if let Some(path) = resolve_existing_path(&canonical_base, &relative_path, mount.index_file) {
        return named_file_response(&req, &path, mount.cache, &runtime).await;
    }

    if mount.mode == StaticMode::Spa && should_serve_spa_fallback(&req, mount.mount_path) {
        let fallback = mount
            .fallback_file
            .expect("spa mounts require a fallback file");
        let fallback_path = canonical_base.join(fallback);
        return named_file_response(&req, &fallback_path, mount.cache, &runtime).await;
    }

    Ok(HttpResponse::NotFound().finish())
}

fn resolve_mount_base_dir(mount: StaticMount) -> Option<PathBuf> {
    resolve_existing_dir(Path::new(mount.resolved_dir))
        .or_else(|| {
            let executable = env::current_exe().ok()?;
            resolve_bundle_mount_dir(&executable, mount)
        })
        .or_else(|| {
            let executable = env::current_exe().ok()?;
            let executable_parent = executable.parent()?;
            resolve_existing_dir(&executable_parent.join(mount.source_dir))
        })
}

fn resolve_existing_dir(path: &Path) -> Option<PathBuf> {
    let canonical = path.canonicalize().ok()?;
    canonical.is_dir().then_some(canonical)
}

fn bundle_dir_for_executable(executable: &Path) -> PathBuf {
    let mut artifact_dir = executable.as_os_str().to_os_string();
    artifact_dir.push(".bundle");
    PathBuf::from(artifact_dir)
}

fn resolve_bundle_mount_dir(executable: &Path, mount: StaticMount) -> Option<PathBuf> {
    resolve_existing_dir(&bundle_dir_for_executable(executable).join(mount.source_dir))
}

fn apply_cache_header(headers: &mut header::HeaderMap, cache: StaticCacheProfile) {
    let value = match cache {
        StaticCacheProfile::NoStore => "no-store",
        StaticCacheProfile::Revalidate => "public, max-age=0, must-revalidate",
        StaticCacheProfile::Immutable => "public, max-age=31536000, immutable",
    };
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static(value),
    );
}

fn sanitize_requested_path(value: &str) -> actix_web::Result<PathBuf> {
    let trimmed = value.trim_matches('/');
    let path = if trimmed.is_empty() {
        PathBuf::new()
    } else {
        PathBuf::from(trimmed)
    };

    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(actix_web::error::ErrorNotFound("invalid path"));
    }

    if path.components().any(|component| match component {
        Component::Normal(segment) => segment.to_string_lossy().starts_with('.'),
        _ => false,
    }) {
        return Err(actix_web::error::ErrorNotFound(
            "hidden files are not served",
        ));
    }

    Ok(path)
}

fn resolve_existing_path(
    base_dir: &Path,
    relative_path: &Path,
    index_file: Option<&str>,
) -> Option<PathBuf> {
    let candidate = base_dir.join(relative_path);
    let metadata = candidate.symlink_metadata().ok()?;
    if metadata.file_type().is_symlink() {
        return None;
    }

    let canonical = candidate.canonicalize().ok()?;
    if !canonical.starts_with(base_dir) {
        return None;
    }

    if canonical.is_dir() {
        let index_file = index_file?;
        let index_path = canonical.join(index_file);
        let index_metadata = index_path.symlink_metadata().ok()?;
        if index_metadata.file_type().is_symlink() {
            return None;
        }
        let canonical_index = index_path.canonicalize().ok()?;
        if canonical_index.starts_with(base_dir) && canonical_index.is_file() {
            return Some(canonical_index);
        }
        return None;
    }

    canonical.is_file().then_some(canonical)
}

async fn named_file_response(
    req: &HttpRequest,
    original_path: &Path,
    cache: StaticCacheProfile,
    runtime: &RuntimeConfig,
) -> actix_web::Result<HttpResponse> {
    let selected = select_static_response_file(req, original_path, runtime);
    let mut file = NamedFile::open_async(&selected.served_path).await?;

    if let Some(encoding) = selected.encoding {
        let original_file = NamedFile::open_async(original_path).await?;
        file = file
            .set_content_type(original_file.content_type().clone())
            .set_content_disposition(original_file.content_disposition().clone())
            .set_content_encoding(encoding.into_content_encoding());
    }

    let mut response = file
        .use_etag(true)
        .use_last_modified(true)
        .prefer_utf8(true)
        .into_response(req);
    apply_cache_header(response.headers_mut(), cache);
    if runtime.compression.static_precompressed {
        append_vary_accept_encoding(response.headers_mut());
    }
    Ok(response)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StaticResponseFile {
    served_path: PathBuf,
    encoding: Option<StaticContentEncoding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StaticContentEncoding {
    Brotli,
    Gzip,
}

impl StaticContentEncoding {
    fn suffix(self) -> &'static str {
        match self {
            Self::Brotli => ".br",
            Self::Gzip => ".gz",
        }
    }

    fn into_content_encoding(self) -> ContentEncoding {
        match self {
            Self::Brotli => ContentEncoding::Brotli,
            Self::Gzip => ContentEncoding::Gzip,
        }
    }
}

fn select_static_response_file(
    req: &HttpRequest,
    original_path: &Path,
    runtime: &RuntimeConfig,
) -> StaticResponseFile {
    if runtime.compression.static_precompressed {
        for encoding in accepted_precompressed_encodings(req) {
            if let Some(served_path) = resolve_precompressed_path(original_path, encoding) {
                return StaticResponseFile {
                    served_path,
                    encoding: Some(encoding),
                };
            }
        }
    }

    StaticResponseFile {
        served_path: original_path.to_path_buf(),
        encoding: None,
    }
}

fn accepted_precompressed_encodings(req: &HttpRequest) -> Vec<StaticContentEncoding> {
    let Some(value) = req.headers().get(header::ACCEPT_ENCODING) else {
        return Vec::new();
    };
    let Ok(value) = value.to_str() else {
        return Vec::new();
    };

    let parsed = parse_accept_encoding(value);
    let brotli_quality = parsed.brotli.or(parsed.wildcard).unwrap_or(0);
    let gzip_quality = parsed.gzip.or(parsed.wildcard).unwrap_or(0);
    let mut accepted = Vec::with_capacity(2);

    if brotli_quality >= gzip_quality {
        if brotli_quality > 0 {
            accepted.push(StaticContentEncoding::Brotli);
        }
        if gzip_quality > 0 {
            accepted.push(StaticContentEncoding::Gzip);
        }
    } else {
        if gzip_quality > 0 {
            accepted.push(StaticContentEncoding::Gzip);
        }
        if brotli_quality > 0 {
            accepted.push(StaticContentEncoding::Brotli);
        }
    }

    accepted
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ParsedAcceptEncoding {
    brotli: Option<u16>,
    gzip: Option<u16>,
    wildcard: Option<u16>,
}

fn parse_accept_encoding(value: &str) -> ParsedAcceptEncoding {
    let mut parsed = ParsedAcceptEncoding::default();

    for token in value.split(',') {
        let mut segments = token.split(';');
        let Some(name) = segments.next().map(str::trim) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }

        let mut quality = 1000;
        for parameter in segments {
            let Some((parameter_name, parameter_value)) = parameter.split_once('=') else {
                continue;
            };
            if parameter_name.trim().eq_ignore_ascii_case("q") {
                quality = parse_quality(parameter_value).unwrap_or(0);
                break;
            }
        }

        match name.to_ascii_lowercase().as_str() {
            "br" => parsed.brotli = Some(parsed.brotli.unwrap_or(0).max(quality)),
            "gzip" => parsed.gzip = Some(parsed.gzip.unwrap_or(0).max(quality)),
            "*" => parsed.wildcard = Some(parsed.wildcard.unwrap_or(0).max(quality)),
            _ => {}
        }
    }

    parsed
}

fn parse_quality(value: &str) -> Option<u16> {
    let quality = value.trim().parse::<f32>().ok()?;
    if !(0.0..=1.0).contains(&quality) {
        return None;
    }
    Some((quality * 1000.0).round() as u16)
}

fn resolve_precompressed_path(
    original_path: &Path,
    encoding: StaticContentEncoding,
) -> Option<PathBuf> {
    let mut candidate = original_path.as_os_str().to_os_string();
    candidate.push(encoding.suffix());
    let candidate = PathBuf::from(candidate);
    let metadata = candidate.symlink_metadata().ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return None;
    }
    Some(candidate)
}

fn append_vary_accept_encoding(headers: &mut header::HeaderMap) {
    let Some(existing) = headers
        .get(header::VARY)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .map(str::to_owned)
    else {
        headers.insert(
            header::VARY,
            header::HeaderValue::from_static("Accept-Encoding"),
        );
        return;
    };

    if existing
        .split(',')
        .any(|value| value.trim().eq_ignore_ascii_case("Accept-Encoding"))
    {
        return;
    }

    let merged = format!("{existing}, Accept-Encoding");
    if let Ok(value) = header::HeaderValue::from_str(&merged) {
        headers.insert(header::VARY, value);
    }
}

fn should_serve_spa_fallback(req: &HttpRequest, mount_path: &str) -> bool {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        return false;
    }

    let path = req.path();
    if reserved_runtime_path(path) {
        return false;
    }

    if !path_belongs_to_mount(path, mount_path) {
        return false;
    }

    if request_path_has_extension(path) {
        return false;
    }

    accepts_html(req)
}

fn reserved_runtime_path(path: &str) -> bool {
    matches!(path, "/docs" | "/openapi.json")
        || path.starts_with("/api/")
        || path == "/api"
        || path.starts_with("/auth/")
        || path == "/auth"
}

fn path_belongs_to_mount(path: &str, mount_path: &str) -> bool {
    if mount_path == "/" {
        return true;
    }
    path == mount_path
        || path
            .strip_prefix(mount_path)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
}

fn request_path_has_extension(path: &str) -> bool {
    let trimmed = path.trim_end_matches('/');
    let Some(last_segment) = trimmed.rsplit('/').next() else {
        return false;
    };
    last_segment.contains('.')
}

fn accepts_html(req: &HttpRequest) -> bool {
    let Some(value) = req.headers().get(header::ACCEPT) else {
        return true;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    value.contains("text/html") || value.contains("*/*")
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use actix_web::{
        App, HttpResponse,
        http::{StatusCode, header},
        test, web,
        web::scope,
    };

    use super::{
        StaticCacheProfile, StaticMode, StaticMount, bundle_dir_for_executable,
        configure_static_mounts, configure_static_mounts_with_runtime, resolve_bundle_mount_dir,
    };
    use crate::runtime::{CompressionConfig, RuntimeConfig};

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}_{stamp}"))
    }

    fn leak_path(path: PathBuf) -> &'static str {
        Box::leak(path.display().to_string().into_boxed_str())
    }

    fn precompressed_runtime() -> RuntimeConfig {
        RuntimeConfig {
            compression: CompressionConfig {
                enabled: false,
                static_precompressed: true,
            },
        }
    }

    #[actix_web::test]
    async fn serves_assets_and_spa_fallback_without_swallowing_reserved_routes() {
        let root = temp_root("static_runtime");
        fs::create_dir_all(root.join("public/assets")).expect("public dir should exist");
        fs::write(root.join("public/index.html"), "<html>index</html>")
            .expect("index should exist");
        fs::write(root.join("public/assets/app.js"), "console.log('ok');")
            .expect("asset should exist");
        let assets_dir = Box::leak(
            root.join("public/assets")
                .display()
                .to_string()
                .into_boxed_str(),
        );
        let public_dir = Box::leak(root.join("public").display().to_string().into_boxed_str());

        let mounts = [
            StaticMount {
                mount_path: "/assets",
                source_dir: "public/assets",
                resolved_dir: assets_dir,
                mode: StaticMode::Directory,
                index_file: None,
                fallback_file: None,
                cache: StaticCacheProfile::Immutable,
            },
            StaticMount {
                mount_path: "/",
                source_dir: "public",
                resolved_dir: public_dir,
                mode: StaticMode::Spa,
                index_file: Some("index.html"),
                fallback_file: Some("index.html"),
                cache: StaticCacheProfile::NoStore,
            },
        ];

        let app = test::init_service(
            App::new()
                .route(
                    "/docs",
                    web::get().to(|| async { HttpResponse::Ok().body("docs") }),
                )
                .service(scope("/api").route(
                    "/health",
                    web::get().to(|| async { HttpResponse::Unauthorized().finish() }),
                ))
                .configure(|cfg| configure_static_mounts(cfg, &mounts)),
        )
        .await;

        let root_req = test::TestRequest::get().uri("/").to_request();
        let root_resp = test::call_service(&app, root_req).await;
        assert_eq!(root_resp.status(), StatusCode::OK);
        assert_eq!(
            root_resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );

        let spa_req = test::TestRequest::get()
            .uri("/dashboard")
            .insert_header((header::ACCEPT, "text/html"))
            .to_request();
        let spa_resp = test::call_service(&app, spa_req).await;
        assert_eq!(spa_resp.status(), StatusCode::OK);

        let asset_req = test::TestRequest::get().uri("/assets/app.js").to_request();
        let asset_resp = test::call_service(&app, asset_req).await;
        assert_eq!(asset_resp.status(), StatusCode::OK);
        assert_eq!(
            asset_resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );

        let missing_asset_req = test::TestRequest::get().uri("/missing.js").to_request();
        let missing_asset_resp = test::call_service(&app, missing_asset_req).await;
        assert_eq!(missing_asset_resp.status(), StatusCode::NOT_FOUND);

        let docs_req = test::TestRequest::get().uri("/docs").to_request();
        let docs_resp = test::call_service(&app, docs_req).await;
        assert_eq!(docs_resp.status(), StatusCode::OK);

        let api_req = test::TestRequest::get().uri("/api/health").to_request();
        let api_resp = test::call_service(&app, api_req).await;
        assert_eq!(api_resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[::core::prelude::v1::test]
    fn prefers_bundle_static_dir_when_compiled_path_is_missing() {
        let root = temp_root("static_runtime_bundle");
        let executable = root.join("dist/todo-app");
        let bundle_public = bundle_dir_for_executable(&executable).join("public");
        fs::create_dir_all(&bundle_public).expect("bundle public dir should exist");

        let mount = StaticMount {
            mount_path: "/",
            source_dir: "public",
            resolved_dir: "/path/that/does/not/exist",
            mode: StaticMode::Spa,
            index_file: Some("index.html"),
            fallback_file: Some("index.html"),
            cache: StaticCacheProfile::NoStore,
        };

        let resolved =
            resolve_bundle_mount_dir(&executable, mount).expect("bundle dir should resolve");
        assert_eq!(
            resolved,
            bundle_public
                .canonicalize()
                .expect("bundle dir should canonicalize")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[actix_web::test]
    async fn serves_brotli_assets_when_available() {
        let root = temp_root("static_runtime_precompressed");
        let asset_dir = root.join("public/assets");
        fs::create_dir_all(&asset_dir).expect("public dir should exist");
        fs::write(asset_dir.join("app.js"), "console.log('identity');")
            .expect("asset should exist");
        let brotli_bytes = b"brotli-payload";
        fs::write(asset_dir.join("app.js.br"), brotli_bytes).expect("brotli asset should exist");
        let assets_dir = leak_path(asset_dir);
        let mounts = [StaticMount {
            mount_path: "/assets",
            source_dir: "public/assets",
            resolved_dir: assets_dir,
            mode: StaticMode::Directory,
            index_file: None,
            fallback_file: None,
            cache: StaticCacheProfile::Immutable,
        }];
        let runtime = precompressed_runtime();

        let app = test::init_service(
            App::new()
                .configure(|cfg| configure_static_mounts_with_runtime(cfg, &mounts, &runtime)),
        )
        .await;

        let request = test::TestRequest::get()
            .uri("/assets/app.js")
            .insert_header((header::ACCEPT_ENCODING, "br"))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_ENCODING).unwrap(),
            "br"
        );
        assert_eq!(
            response.headers().get(header::VARY).unwrap(),
            "Accept-Encoding"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );
        assert!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("javascript"))
        );
        let body = test::read_body(response).await;
        assert_eq!(body.as_ref(), brotli_bytes);

        let _ = fs::remove_dir_all(root);
    }

    #[actix_web::test]
    async fn falls_back_to_next_supported_precompressed_variant() {
        let root = temp_root("static_runtime_precompressed_fallback");
        let asset_dir = root.join("public/assets");
        fs::create_dir_all(&asset_dir).expect("public dir should exist");
        fs::write(asset_dir.join("app.js"), "console.log('identity');")
            .expect("asset should exist");
        let gzip_bytes = [
            0x1f, 0x8b, 0x08, 0x00, 0xf0, 0x75, 0xcc, 0x67, 0x02, 0xff, 0x4b, 0xce, 0xcf, 0x2b,
            0xce, 0xcf, 0x49, 0xd5, 0xcb, 0xc9, 0x4f, 0xd7, 0x50, 0xcf, 0xcc, 0xcb, 0x2c, 0xc9,
            0xcc, 0xcf, 0x53, 0xd7, 0xb4, 0xe6, 0x02, 0x00, 0x45, 0x1e, 0x1d, 0x65, 0x18, 0x00,
            0x00, 0x00,
        ];
        fs::write(asset_dir.join("app.js.gz"), gzip_bytes).expect("gzip asset should exist");
        let assets_dir = leak_path(asset_dir);
        let mounts = [StaticMount {
            mount_path: "/assets",
            source_dir: "public/assets",
            resolved_dir: assets_dir,
            mode: StaticMode::Directory,
            index_file: None,
            fallback_file: None,
            cache: StaticCacheProfile::Immutable,
        }];
        let runtime = precompressed_runtime();

        let app = test::init_service(
            App::new()
                .configure(|cfg| configure_static_mounts_with_runtime(cfg, &mounts, &runtime)),
        )
        .await;

        let request = test::TestRequest::get()
            .uri("/assets/app.js")
            .insert_header((header::ACCEPT_ENCODING, "br, gzip;q=0.5"))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
        let body = test::read_body(response).await;
        assert_eq!(body.as_ref(), &gzip_bytes);

        let _ = fs::remove_dir_all(root);
    }

    #[actix_web::test]
    async fn precompressed_assets_remain_disabled_without_runtime_flag() {
        let root = temp_root("static_runtime_identity");
        let asset_dir = root.join("public/assets");
        fs::create_dir_all(&asset_dir).expect("public dir should exist");
        fs::write(asset_dir.join("app.js"), "console.log('identity');")
            .expect("asset should exist");
        fs::write(asset_dir.join("app.js.gz"), [0x1f, 0x8b, 0x08, 0x00])
            .expect("gzip asset should exist");
        let assets_dir = leak_path(asset_dir);
        let mounts = [StaticMount {
            mount_path: "/assets",
            source_dir: "public/assets",
            resolved_dir: assets_dir,
            mode: StaticMode::Directory,
            index_file: None,
            fallback_file: None,
            cache: StaticCacheProfile::Immutable,
        }];

        let app =
            test::init_service(App::new().configure(|cfg| configure_static_mounts(cfg, &mounts)))
                .await;

        let request = test::TestRequest::get()
            .uri("/assets/app.js")
            .insert_header((header::ACCEPT_ENCODING, "gzip"))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::CONTENT_ENCODING).is_none());
        assert!(response.headers().get(header::VARY).is_none());
        let body = test::read_body(response).await;
        assert_eq!(body.as_ref(), b"console.log('identity');");

        let _ = fs::remove_dir_all(root);
    }
}
