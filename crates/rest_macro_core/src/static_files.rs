use std::{
    env,
    path::{Component, Path, PathBuf},
};

use actix_files::NamedFile;
use actix_web::{
    HttpRequest, HttpResponse,
    http::{Method, header},
    web,
};

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
    let mut ordered = mounts.to_vec();
    ordered.sort_by(|left, right| right.mount_path.len().cmp(&left.mount_path.len()));

    for mount in ordered {
        register_mount(cfg, mount);
    }
}

fn register_mount(cfg: &mut web::ServiceConfig, mount: StaticMount) {
    let exact_mount = mount;
    let exact_path = if mount.mount_path == "/" {
        "/".to_owned()
    } else {
        mount.mount_path.to_owned()
    };
    cfg.service(
        web::resource(exact_path)
            .route(
                web::get().to(move |req: HttpRequest| serve_static_request(req, exact_mount, None)),
            )
            .route(
                web::head()
                    .to(move |req: HttpRequest| serve_static_request(req, exact_mount, None)),
            ),
    );

    let tail_mount = mount;
    let tail_path = if mount.mount_path == "/" {
        "/{tail:.*}".to_owned()
    } else {
        format!("{}/{{tail:.*}}", mount.mount_path)
    };
    cfg.service(
        web::resource(tail_path)
            .route(
                web::get().to(move |req: HttpRequest, tail: web::Path<String>| {
                    serve_static_request(req, tail_mount, Some(tail.into_inner()))
                }),
            )
            .route(
                web::head().to(move |req: HttpRequest, tail: web::Path<String>| {
                    serve_static_request(req, tail_mount, Some(tail.into_inner()))
                }),
            ),
    );
}

async fn serve_static_request(
    req: HttpRequest,
    mount: StaticMount,
    tail: Option<String>,
) -> actix_web::Result<HttpResponse> {
    if reserved_runtime_path(req.path()) {
        return Ok(HttpResponse::NotFound().finish());
    }

    let Some(canonical_base) = resolve_mount_base_dir(mount) else {
        return Ok(HttpResponse::NotFound().finish());
    };
    let relative_path = sanitize_requested_path(tail.as_deref().unwrap_or(""))?;

    if let Some(path) = resolve_existing_path(&canonical_base, &relative_path, mount.index_file) {
        return named_file_response(&req, &path, mount.cache).await;
    }

    if mount.mode == StaticMode::Spa && should_serve_spa_fallback(&req, mount.mount_path) {
        let fallback = mount
            .fallback_file
            .expect("spa mounts require a fallback file");
        let fallback_path = canonical_base.join(fallback);
        return named_file_response(&req, &fallback_path, mount.cache).await;
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
    path: &Path,
    cache: StaticCacheProfile,
) -> actix_web::Result<HttpResponse> {
    let mut response = NamedFile::open_async(path)
        .await?
        .use_etag(true)
        .use_last_modified(true)
        .prefer_utf8(true)
        .into_response(req);
    apply_cache_header(response.headers_mut(), cache);
    Ok(response)
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
        configure_static_mounts, resolve_bundle_mount_dir,
    };

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}_{stamp}"))
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
}
