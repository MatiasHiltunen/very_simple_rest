use std::{
    collections::HashMap,
    fmt,
    fs,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use actix_files::NamedFile;
use actix_web::{
    HttpRequest, HttpResponse,
    http::header,
    web,
};
use object_store::{
    local::LocalFileSystem,
    path::Path as ObjectPath,
    ObjectStoreExt,
};

use crate::{runtime::RuntimeConfig, static_files::StaticCacheProfile};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageBackendKind {
    Local,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageBackendConfig {
    pub name: String,
    pub kind: StorageBackendKind,
    pub root_dir: String,
    pub resolved_root_dir: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoragePublicMount {
    pub mount_path: String,
    pub backend: String,
    pub key_prefix: String,
    pub cache: StaticCacheProfile,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StorageConfig {
    pub backends: Vec<StorageBackendConfig>,
    pub public_mounts: Vec<StoragePublicMount>,
}

impl StorageConfig {
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty() && self.public_mounts.is_empty()
    }
}

#[derive(Debug)]
pub struct StorageError(String);

impl StorageError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StorageError {}

#[derive(Clone, Default)]
pub struct StorageRegistry {
    backends: Arc<HashMap<String, StorageBackendHandle>>,
}

#[derive(Clone)]
enum StorageBackendHandle {
    Local(LocalStorageBackend),
}

#[derive(Clone)]
struct LocalStorageBackend {
    root_dir: PathBuf,
    store: Arc<LocalFileSystem>,
}

impl StorageRegistry {
    pub fn from_config(config: &StorageConfig) -> Result<Self, StorageError> {
        let mut backends = HashMap::with_capacity(config.backends.len());
        for backend in &config.backends {
            let handle = match backend.kind {
                StorageBackendKind::Local => {
                    let root_dir = PathBuf::from(&backend.resolved_root_dir);
                    fs::create_dir_all(&root_dir).map_err(|error| {
                        StorageError::new(format!(
                            "failed to create storage backend `{}` root `{}`: {error}",
                            backend.name,
                            root_dir.display()
                        ))
                    })?;
                    let store = LocalFileSystem::new_with_prefix(&root_dir).map_err(|error| {
                        StorageError::new(format!(
                            "failed to initialize local storage backend `{}` at `{}`: {error}",
                            backend.name,
                            root_dir.display()
                        ))
                    })?;
                    StorageBackendHandle::Local(LocalStorageBackend {
                        root_dir,
                        store: Arc::new(store),
                    })
                }
            };

            backends.insert(backend.name.clone(), handle);
        }

        Ok(Self {
            backends: Arc::new(backends),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    pub async fn put_bytes(
        &self,
        backend_name: &str,
        object_key: &str,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<(), StorageError> {
        let location = parse_object_path(object_key)
            .map_err(|error| StorageError::new(format!("invalid storage object key: {error}")))?;
        let backend = self.backends.get(backend_name).ok_or_else(|| {
            StorageError::new(format!("unknown storage backend `{backend_name}`"))
        })?;
        backend.put_bytes(&location, bytes.into()).await
    }

    fn local_path_for(
        &self,
        backend_name: &str,
        object_path: &ObjectPath,
    ) -> Result<PathBuf, StorageError> {
        let backend = self.backends.get(backend_name).ok_or_else(|| {
            StorageError::new(format!("unknown storage backend `{backend_name}`"))
        })?;
        match backend {
            StorageBackendHandle::Local(backend) => backend
                .store
                .path_to_filesystem(object_path)
                .map_err(|error| {
                    StorageError::new(format!(
                        "failed to resolve object path `{}` for backend `{backend_name}`: {error}",
                        object_path
                    ))
                }),
        }
    }

    pub fn local_root_dir(&self, backend_name: &str) -> Option<&Path> {
        match self.backends.get(backend_name) {
            Some(StorageBackendHandle::Local(backend)) => Some(backend.root_dir.as_path()),
            None => None,
        }
    }
}

impl StorageBackendHandle {
    async fn put_bytes(&self, object_path: &ObjectPath, bytes: Vec<u8>) -> Result<(), StorageError> {
        match self {
            StorageBackendHandle::Local(backend) => backend
                .store
                .put(object_path, bytes.into())
                .await
                .map_err(|error| {
                    StorageError::new(format!(
                        "failed to write object `{object_path}` into local storage backend `{}`: {error}",
                        backend.root_dir.display()
                    ))
                })
                .map(|_| ()),
        }
    }
}

pub fn configure_public_mounts(
    cfg: &mut web::ServiceConfig,
    storage: &StorageRegistry,
    mounts: &[StoragePublicMount],
) {
    configure_public_mounts_with_runtime(cfg, storage, mounts, &RuntimeConfig::default());
}

pub fn configure_public_mounts_with_runtime(
    cfg: &mut web::ServiceConfig,
    storage: &StorageRegistry,
    mounts: &[StoragePublicMount],
    _runtime: &RuntimeConfig,
) {
    let mut ordered = mounts.to_vec();
    ordered.sort_by(|left, right| right.mount_path.len().cmp(&left.mount_path.len()));

    for mount in ordered {
        register_public_mount(cfg, storage.clone(), mount);
    }
}

fn register_public_mount(
    cfg: &mut web::ServiceConfig,
    storage: StorageRegistry,
    mount: StoragePublicMount,
) {
    let exact_mount = mount.clone();
    let exact_storage = storage.clone();
    let exact_head_mount = exact_mount.clone();
    let exact_head_storage = exact_storage.clone();
    cfg.service(
        web::resource(mount.mount_path.clone())
            .route(web::get().to(move |req: HttpRequest| {
                serve_public_request(req, exact_storage.clone(), exact_mount.clone(), None)
            }))
            .route(web::head().to(move |req: HttpRequest| {
                serve_public_request(
                    req,
                    exact_head_storage.clone(),
                    exact_head_mount.clone(),
                    None,
                )
            })),
    );

    let tail_mount = mount.clone();
    let tail_storage = storage;
    let tail_head_mount = tail_mount.clone();
    let tail_head_storage = tail_storage.clone();
    let tail_path = if mount.mount_path == "/" {
        "/{tail:.*}".to_owned()
    } else {
        format!("{}/{{tail:.*}}", mount.mount_path)
    };
    cfg.service(
        web::resource(tail_path)
            .route(
                web::get().to(move |req: HttpRequest, tail: web::Path<String>| {
                    serve_public_request(
                        req,
                        tail_storage.clone(),
                        tail_mount.clone(),
                        Some(tail.into_inner()),
                    )
                }),
            )
            .route(
                web::head().to(move |req: HttpRequest, tail: web::Path<String>| {
                    serve_public_request(
                        req,
                        tail_head_storage.clone(),
                        tail_head_mount.clone(),
                        Some(tail.into_inner()),
                    )
                }),
            ),
    );
}

async fn serve_public_request(
    req: HttpRequest,
    storage: StorageRegistry,
    mount: StoragePublicMount,
    tail: Option<String>,
) -> actix_web::Result<HttpResponse> {
    let Some(requested_path) = tail.as_deref() else {
        return Ok(HttpResponse::NotFound().finish());
    };

    let relative_path = sanitize_requested_path(requested_path)?;
    if relative_path.as_os_str().is_empty() {
        return Ok(HttpResponse::NotFound().finish());
    }

    let object_path = resolve_object_path(&mount.key_prefix, &relative_path)?;
    let filesystem_path = storage
        .local_path_for(&mount.backend, &object_path)
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let metadata = match filesystem_path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(HttpResponse::NotFound().finish());
        }
        Err(error) => {
            return Err(actix_web::error::ErrorInternalServerError(error));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(HttpResponse::NotFound().finish());
    }

    let named_file = NamedFile::open_async(&filesystem_path).await?;
    let mut response = named_file.into_response(&req);
    apply_cache_header(response.headers_mut(), mount.cache);
    Ok(response)
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

fn resolve_object_path(prefix: &str, relative_path: &Path) -> actix_web::Result<ObjectPath> {
    let mut segments = Vec::new();
    if !prefix.is_empty() {
        segments.extend(prefix.split('/').filter(|segment| !segment.is_empty()));
    }
    segments.extend(relative_path.iter().filter_map(|segment| segment.to_str()));
    let joined = segments.join("/");
    parse_object_path(&joined)
        .map_err(|error| actix_web::error::ErrorNotFound(format!("invalid storage path: {error}")))
}

fn parse_object_path(value: &str) -> Result<ObjectPath, object_store::path::Error> {
    ObjectPath::parse(value)
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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use actix_web::{App, http::{StatusCode, header}, test};

    use super::{
        StorageBackendConfig, StorageBackendKind, StorageConfig, StoragePublicMount,
        StorageRegistry, configure_public_mounts,
    };
    use crate::static_files::StaticCacheProfile;

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}_{stamp}"))
    }

    #[actix_web::test]
    async fn serves_local_storage_public_mounts() {
        let root = temp_root("storage_public_mount");
        let storage = StorageConfig {
            backends: vec![StorageBackendConfig {
                name: "uploads".to_owned(),
                kind: StorageBackendKind::Local,
                root_dir: "var/uploads".to_owned(),
                resolved_root_dir: root.join("var/uploads").display().to_string(),
            }],
            public_mounts: vec![StoragePublicMount {
                mount_path: "/uploads".to_owned(),
                backend: "uploads".to_owned(),
                key_prefix: String::new(),
                cache: StaticCacheProfile::Immutable,
            }],
        };
        let registry =
            StorageRegistry::from_config(&storage).expect("storage registry should initialize");
        registry
            .put_bytes("uploads", "images/logo.txt", b"hello storage".to_vec())
            .await
            .expect("object should write");

        let app = test::init_service(App::new().configure(|cfg| {
            configure_public_mounts(cfg, &registry, storage.public_mounts.as_slice());
        }))
        .await;

        let request = test::TestRequest::get()
            .uri("/uploads/images/logo.txt")
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );
        let body = test::read_body(response).await;
        assert_eq!(body.as_ref(), b"hello storage");

        let _ = fs::remove_dir_all(root);
    }

    #[actix_web::test]
    async fn rejects_hidden_and_parent_paths_for_public_mounts() {
        let root = temp_root("storage_public_mount_security");
        let storage = StorageConfig {
            backends: vec![StorageBackendConfig {
                name: "uploads".to_owned(),
                kind: StorageBackendKind::Local,
                root_dir: "var/uploads".to_owned(),
                resolved_root_dir: root.join("var/uploads").display().to_string(),
            }],
            public_mounts: vec![StoragePublicMount {
                mount_path: "/uploads".to_owned(),
                backend: "uploads".to_owned(),
                key_prefix: String::new(),
                cache: StaticCacheProfile::Revalidate,
            }],
        };
        let registry =
            StorageRegistry::from_config(&storage).expect("storage registry should initialize");
        registry
            .put_bytes("uploads", "ok.txt", b"hello".to_vec())
            .await
            .expect("object should write");

        let app = test::init_service(App::new().configure(|cfg| {
            configure_public_mounts(cfg, &registry, storage.public_mounts.as_slice());
        }))
        .await;

        let hidden = test::TestRequest::get()
            .uri("/uploads/.env")
            .to_request();
        let hidden_response = test::call_service(&app, hidden).await;
        assert_eq!(hidden_response.status(), StatusCode::NOT_FOUND);

        let parent = test::TestRequest::get()
            .uri("/uploads/../ok.txt")
            .to_request();
        let parent_response = test::call_service(&app, parent).await;
        assert_eq!(parent_response.status(), StatusCode::NOT_FOUND);

        let _ = fs::remove_dir_all(root);
    }

    #[::core::prelude::v1::test]
    fn registry_creates_missing_local_backend_dirs() {
        let root = temp_root("storage_backend_dir");
        let backend_root = root.join("var/uploads");
        let storage = StorageConfig {
            backends: vec![StorageBackendConfig {
                name: "uploads".to_owned(),
                kind: StorageBackendKind::Local,
                root_dir: "var/uploads".to_owned(),
                resolved_root_dir: backend_root.display().to_string(),
            }],
            public_mounts: Vec::new(),
        };

        let registry =
            StorageRegistry::from_config(&storage).expect("storage registry should initialize");
        assert_eq!(
            registry.local_root_dir("uploads"),
            Some(backend_root.as_path())
        );
        assert!(backend_root.is_dir(), "backend root dir should be created");

        let _ = fs::remove_dir_all(root);
    }
}
