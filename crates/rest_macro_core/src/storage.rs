use std::{
    collections::{BTreeMap, HashMap},
    fmt, fs,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use actix_files::NamedFile;
use actix_multipart::Multipart;
use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web,
};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use object_store::{ObjectStoreExt, local::LocalFileSystem, path::Path as ObjectPath};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{auth::UserContext, errors, runtime::RuntimeConfig, static_files::StaticCacheProfile};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageUploadEndpoint {
    pub name: String,
    pub path: String,
    pub backend: String,
    pub key_prefix: String,
    pub max_bytes: usize,
    pub require_auth: bool,
    pub roles: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageS3CompatBucket {
    pub name: String,
    pub backend: String,
    pub key_prefix: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageS3CompatConfig {
    pub mount_path: String,
    pub buckets: Vec<StorageS3CompatBucket>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StorageConfig {
    pub backends: Vec<StorageBackendConfig>,
    pub public_mounts: Vec<StoragePublicMount>,
    pub uploads: Vec<StorageUploadEndpoint>,
    pub s3_compat: Option<StorageS3CompatConfig>,
}

impl StorageConfig {
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
            && self.public_mounts.is_empty()
            && self.uploads.is_empty()
            && self.s3_compat.is_none()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct StorageUploadResponse {
    pub backend: String,
    pub object_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    pub file_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub size_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct StoredObjectMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    user_metadata: BTreeMap<String, String>,
    size_bytes: usize,
    etag: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageObjectInfo {
    content_type: Option<String>,
    user_metadata: BTreeMap<String, String>,
    size_bytes: usize,
    etag: String,
    last_modified: DateTime<Utc>,
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

    pub(crate) async fn put_bytes_with_metadata(
        &self,
        backend_name: &str,
        object_key: &str,
        bytes: Vec<u8>,
        content_type: Option<String>,
        user_metadata: BTreeMap<String, String>,
    ) -> Result<StorageObjectInfo, StorageError> {
        let location = parse_object_path(object_key)
            .map_err(|error| StorageError::new(format!("invalid storage object key: {error}")))?;
        let backend = self.backends.get(backend_name).ok_or_else(|| {
            StorageError::new(format!("unknown storage backend `{backend_name}`"))
        })?;
        backend
            .put_bytes_with_metadata(&location, bytes, content_type, user_metadata)
            .await
    }

    pub(crate) fn read_bytes(
        &self,
        backend_name: &str,
        object_key: &str,
    ) -> Result<Vec<u8>, StorageError> {
        let location = parse_object_path(object_key)
            .map_err(|error| StorageError::new(format!("invalid storage object key: {error}")))?;
        let backend = self.backends.get(backend_name).ok_or_else(|| {
            StorageError::new(format!("unknown storage backend `{backend_name}`"))
        })?;
        backend.read_bytes(&location)
    }

    pub(crate) fn object_info(
        &self,
        backend_name: &str,
        object_key: &str,
    ) -> Result<StorageObjectInfo, StorageError> {
        let location = parse_object_path(object_key)
            .map_err(|error| StorageError::new(format!("invalid storage object key: {error}")))?;
        let backend = self.backends.get(backend_name).ok_or_else(|| {
            StorageError::new(format!("unknown storage backend `{backend_name}`"))
        })?;
        backend.object_info(&location)
    }

    pub(crate) fn delete_object(
        &self,
        backend_name: &str,
        object_key: &str,
    ) -> Result<bool, StorageError> {
        let location = parse_object_path(object_key)
            .map_err(|error| StorageError::new(format!("invalid storage object key: {error}")))?;
        let backend = self.backends.get(backend_name).ok_or_else(|| {
            StorageError::new(format!("unknown storage backend `{backend_name}`"))
        })?;
        backend.delete_object(&location)
    }

    pub(crate) fn list_objects(
        &self,
        backend_name: &str,
        prefix: &str,
    ) -> Result<Vec<(String, StorageObjectInfo)>, StorageError> {
        let backend = self.backends.get(backend_name).ok_or_else(|| {
            StorageError::new(format!("unknown storage backend `{backend_name}`"))
        })?;
        backend.list_objects(prefix)
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
    async fn put_bytes(
        &self,
        object_path: &ObjectPath,
        bytes: Vec<u8>,
    ) -> Result<(), StorageError> {
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

    async fn put_bytes_with_metadata(
        &self,
        object_path: &ObjectPath,
        bytes: Vec<u8>,
        content_type: Option<String>,
        user_metadata: BTreeMap<String, String>,
    ) -> Result<StorageObjectInfo, StorageError> {
        match self {
            StorageBackendHandle::Local(backend) => {
                backend.put_bytes_with_metadata(object_path, bytes, content_type, user_metadata)
            }
        }
    }

    fn read_bytes(&self, object_path: &ObjectPath) -> Result<Vec<u8>, StorageError> {
        match self {
            StorageBackendHandle::Local(backend) => backend.read_bytes(object_path),
        }
    }

    fn object_info(&self, object_path: &ObjectPath) -> Result<StorageObjectInfo, StorageError> {
        match self {
            StorageBackendHandle::Local(backend) => backend.object_info(object_path),
        }
    }

    fn delete_object(&self, object_path: &ObjectPath) -> Result<bool, StorageError> {
        match self {
            StorageBackendHandle::Local(backend) => backend.delete_object(object_path),
        }
    }

    fn list_objects(&self, prefix: &str) -> Result<Vec<(String, StorageObjectInfo)>, StorageError> {
        match self {
            StorageBackendHandle::Local(backend) => backend.list_objects(prefix),
        }
    }
}

impl LocalStorageBackend {
    fn put_bytes_with_metadata(
        &self,
        object_path: &ObjectPath,
        bytes: Vec<u8>,
        content_type: Option<String>,
        user_metadata: BTreeMap<String, String>,
    ) -> Result<StorageObjectInfo, StorageError> {
        let filesystem_path = self
            .store
            .path_to_filesystem(object_path)
            .map_err(|error| {
                StorageError::new(format!("failed to resolve local object path: {error}"))
            })?;
        if let Some(parent) = filesystem_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                StorageError::new(format!(
                    "failed to create local storage parent `{}`: {error}",
                    parent.display()
                ))
            })?;
        }
        fs::write(&filesystem_path, &bytes).map_err(|error| {
            StorageError::new(format!(
                "failed to write local storage object `{}`: {error}",
                filesystem_path.display()
            ))
        })?;

        let info =
            build_storage_object_info(&filesystem_path, content_type, user_metadata, Some(&bytes))?;
        self.write_metadata(object_path, &info)?;
        Ok(info)
    }

    fn read_bytes(&self, object_path: &ObjectPath) -> Result<Vec<u8>, StorageError> {
        let filesystem_path = self
            .store
            .path_to_filesystem(object_path)
            .map_err(|error| {
                StorageError::new(format!("failed to resolve local object path: {error}"))
            })?;
        fs::read(&filesystem_path).map_err(|error| {
            StorageError::new(format!(
                "failed to read local storage object `{}`: {error}",
                filesystem_path.display()
            ))
        })
    }

    fn object_info(&self, object_path: &ObjectPath) -> Result<StorageObjectInfo, StorageError> {
        let filesystem_path = self
            .store
            .path_to_filesystem(object_path)
            .map_err(|error| {
                StorageError::new(format!("failed to resolve local object path: {error}"))
            })?;
        let metadata = fs::metadata(&filesystem_path).map_err(|error| {
            StorageError::new(format!(
                "failed to stat local storage object `{}`: {error}",
                filesystem_path.display()
            ))
        })?;
        let stored = self.read_metadata(object_path)?;
        let last_modified: DateTime<Utc> = metadata
            .modified()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(|_| Utc::now());
        Ok(StorageObjectInfo {
            content_type: stored.content_type,
            user_metadata: stored.user_metadata,
            size_bytes: stored.size_bytes,
            etag: stored.etag,
            last_modified,
        })
    }

    fn delete_object(&self, object_path: &ObjectPath) -> Result<bool, StorageError> {
        let filesystem_path = self
            .store
            .path_to_filesystem(object_path)
            .map_err(|error| {
                StorageError::new(format!("failed to resolve local object path: {error}"))
            })?;
        let deleted = match fs::remove_file(&filesystem_path) {
            Ok(()) => true,
            Err(error) if error.kind() == ErrorKind::NotFound => false,
            Err(error) => {
                return Err(StorageError::new(format!(
                    "failed to delete local storage object `{}`: {error}",
                    filesystem_path.display()
                )));
            }
        };
        let metadata_path = self.metadata_path(object_path)?;
        match fs::remove_file(&metadata_path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(StorageError::new(format!(
                    "failed to delete local storage metadata `{}`: {error}",
                    metadata_path.display()
                )));
            }
        }
        Ok(deleted)
    }

    fn list_objects(&self, prefix: &str) -> Result<Vec<(String, StorageObjectInfo)>, StorageError> {
        let mut objects = Vec::new();
        self.walk_objects(
            self.root_dir.as_path(),
            PathBuf::new(),
            prefix.trim_matches('/'),
            &mut objects,
        )?;
        objects.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(objects)
    }

    fn walk_objects(
        &self,
        current_dir: &Path,
        relative_dir: PathBuf,
        prefix: &str,
        objects: &mut Vec<(String, StorageObjectInfo)>,
    ) -> Result<(), StorageError> {
        let entries = match fs::read_dir(current_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(StorageError::new(format!(
                    "failed to read local storage directory `{}`: {error}",
                    current_dir.display()
                )));
            }
        };

        for entry in entries {
            let entry = entry.map_err(|error| {
                StorageError::new(format!(
                    "failed to inspect local storage directory `{}`: {error}",
                    current_dir.display()
                ))
            })?;
            let file_name = entry.file_name();
            if file_name.to_string_lossy() == ".vsr-meta" {
                continue;
            }
            let file_type = entry.file_type().map_err(|error| {
                StorageError::new(format!(
                    "failed to inspect local storage path `{}`: {error}",
                    entry.path().display()
                ))
            })?;
            let next_relative = relative_dir.join(&file_name);
            if file_type.is_dir() {
                self.walk_objects(entry.path().as_path(), next_relative, prefix, objects)?;
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let key = next_relative
                .iter()
                .filter_map(|segment| segment.to_str())
                .collect::<Vec<_>>()
                .join("/");
            if !prefix.is_empty() && !key.starts_with(prefix) {
                continue;
            }
            let object_path = parse_object_path(&key).map_err(|error| {
                StorageError::new(format!("invalid local storage key `{key}`: {error}"))
            })?;
            objects.push((key, self.object_info(&object_path)?));
        }

        Ok(())
    }

    fn write_metadata(
        &self,
        object_path: &ObjectPath,
        info: &StorageObjectInfo,
    ) -> Result<(), StorageError> {
        let metadata_path = self.metadata_path(object_path)?;
        if let Some(parent) = metadata_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                StorageError::new(format!(
                    "failed to create local metadata dir `{}`: {error}",
                    parent.display()
                ))
            })?;
        }
        let payload = StoredObjectMetadata {
            content_type: info.content_type.clone(),
            user_metadata: info.user_metadata.clone(),
            size_bytes: info.size_bytes,
            etag: info.etag.clone(),
        };
        let bytes = serde_json::to_vec(&payload).map_err(|error| {
            StorageError::new(format!("failed to serialize object metadata: {error}"))
        })?;
        fs::write(&metadata_path, bytes).map_err(|error| {
            StorageError::new(format!(
                "failed to write local storage metadata `{}`: {error}",
                metadata_path.display()
            ))
        })
    }

    fn read_metadata(
        &self,
        object_path: &ObjectPath,
    ) -> Result<StoredObjectMetadata, StorageError> {
        let metadata_path = self.metadata_path(object_path)?;
        match fs::read(&metadata_path) {
            Ok(bytes) => serde_json::from_slice::<StoredObjectMetadata>(&bytes).map_err(|error| {
                StorageError::new(format!("failed to parse object metadata: {error}"))
            }),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let filesystem_path =
                    self.store
                        .path_to_filesystem(object_path)
                        .map_err(|path_error| {
                            StorageError::new(format!(
                                "failed to resolve local object path: {path_error}"
                            ))
                        })?;
                let bytes = fs::read(&filesystem_path).map_err(|read_error| {
                    StorageError::new(format!(
                        "failed to read local storage object `{}`: {read_error}",
                        filesystem_path.display()
                    ))
                })?;
                let info = build_storage_object_info(
                    &filesystem_path,
                    None,
                    BTreeMap::new(),
                    Some(&bytes),
                )?;
                Ok(StoredObjectMetadata {
                    content_type: info.content_type,
                    user_metadata: info.user_metadata,
                    size_bytes: info.size_bytes,
                    etag: info.etag,
                })
            }
            Err(error) => Err(StorageError::new(format!(
                "failed to read local storage metadata `{}`: {error}",
                metadata_path.display()
            ))),
        }
    }

    fn metadata_path(&self, object_path: &ObjectPath) -> Result<PathBuf, StorageError> {
        let object_key = object_path.to_string();
        let mut metadata_path = self.root_dir.join(".vsr-meta");
        for segment in object_key.split('/') {
            if !segment.is_empty() {
                metadata_path.push(segment);
            }
        }

        let file_name = metadata_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                StorageError::new(format!(
                    "failed to resolve local metadata path for object `{object_key}`"
                ))
            })?;
        metadata_path.set_file_name(format!("{file_name}.json"));
        Ok(metadata_path)
    }
}

fn build_storage_object_info(
    filesystem_path: &Path,
    content_type: Option<String>,
    user_metadata: BTreeMap<String, String>,
    bytes: Option<&[u8]>,
) -> Result<StorageObjectInfo, StorageError> {
    let metadata = fs::metadata(filesystem_path).map_err(|error| {
        StorageError::new(format!(
            "failed to stat local storage object `{}`: {error}",
            filesystem_path.display()
        ))
    })?;
    let size_bytes = metadata.len() as usize;
    let last_modified: DateTime<Utc> = metadata
        .modified()
        .map(DateTime::<Utc>::from)
        .unwrap_or_else(|_| Utc::now());
    let etag = match bytes {
        Some(bytes) => quoted_sha256(bytes),
        None => quoted_sha256(&fs::read(filesystem_path).map_err(|error| {
            StorageError::new(format!(
                "failed to read local storage object `{}`: {error}",
                filesystem_path.display()
            ))
        })?),
    };
    Ok(StorageObjectInfo {
        content_type,
        user_metadata,
        size_bytes,
        etag,
        last_modified,
    })
}

fn quoted_sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("\"{}\"", hex::encode(digest.finalize()))
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
    ordered.sort_by_key(|mount| std::cmp::Reverse(mount.mount_path.len()));

    for mount in ordered {
        register_public_mount(cfg, storage.clone(), mount);
    }
}

pub fn configure_upload_endpoints(
    cfg: &mut web::ServiceConfig,
    storage: &StorageRegistry,
    public_mounts: &[StoragePublicMount],
    uploads: &[StorageUploadEndpoint],
) {
    configure_upload_endpoints_with_runtime(
        cfg,
        storage,
        public_mounts,
        uploads,
        &RuntimeConfig::default(),
    );
}

pub fn configure_upload_endpoints_with_runtime(
    cfg: &mut web::ServiceConfig,
    storage: &StorageRegistry,
    public_mounts: &[StoragePublicMount],
    uploads: &[StorageUploadEndpoint],
    _runtime: &RuntimeConfig,
) {
    for upload in uploads {
        register_upload_endpoint(cfg, storage.clone(), public_mounts.to_vec(), upload.clone());
    }
}

pub fn configure_s3_compat(
    cfg: &mut web::ServiceConfig,
    storage: &StorageRegistry,
    s3_compat: Option<&StorageS3CompatConfig>,
) {
    configure_s3_compat_with_runtime(cfg, storage, s3_compat, &RuntimeConfig::default());
}

pub fn configure_s3_compat_with_runtime(
    cfg: &mut web::ServiceConfig,
    storage: &StorageRegistry,
    s3_compat: Option<&StorageS3CompatConfig>,
    _runtime: &RuntimeConfig,
) {
    let Some(s3_compat) = s3_compat else {
        return;
    };
    let storage_for_bucket = storage.clone();
    let storage_for_bucket_head = storage.clone();
    let storage_for_object_get = storage.clone();
    let storage_for_object_head = storage.clone();
    let storage_for_object_put = storage.clone();
    let storage_for_object_delete = storage.clone();
    let bucket_config = s3_compat.clone();
    let bucket_head_config = s3_compat.clone();
    let object_get_config = s3_compat.clone();
    let object_head_config = s3_compat.clone();
    let object_put_config = s3_compat.clone();
    let object_delete_config = s3_compat.clone();

    let bucket_path = format!("{}/{{bucket}}", s3_compat.mount_path);
    let object_path = format!("{}/{{bucket}}/{{tail:.*}}", s3_compat.mount_path);

    cfg.service(
        web::resource(bucket_path)
            .route(web::get().to(move |req: HttpRequest| {
                handle_s3_bucket_request(req, storage_for_bucket.clone(), bucket_config.clone())
            }))
            .route(web::head().to(move |req: HttpRequest| {
                handle_s3_bucket_head(
                    req,
                    storage_for_bucket_head.clone(),
                    bucket_head_config.clone(),
                )
            })),
    );
    cfg.service(
        web::resource(object_path)
            .route(
                web::get().to(move |req: HttpRequest, tail: web::Path<(String, String)>| {
                    handle_s3_get_object(
                        req,
                        storage_for_object_get.clone(),
                        object_get_config.clone(),
                        tail,
                    )
                }),
            )
            .route(
                web::head().to(move |req: HttpRequest, tail: web::Path<(String, String)>| {
                    handle_s3_head_object(
                        req,
                        storage_for_object_head.clone(),
                        object_head_config.clone(),
                        tail,
                    )
                }),
            )
            .route(web::put().to(
                move |req: HttpRequest, body: web::Bytes, tail: web::Path<(String, String)>| {
                    handle_s3_put_object(
                        req,
                        body,
                        storage_for_object_put.clone(),
                        object_put_config.clone(),
                        tail,
                    )
                },
            ))
            .route(web::delete().to(move |tail: web::Path<(String, String)>| {
                handle_s3_delete_object(
                    storage_for_object_delete.clone(),
                    object_delete_config.clone(),
                    tail,
                )
            })),
    );
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

fn register_upload_endpoint(
    cfg: &mut web::ServiceConfig,
    storage: StorageRegistry,
    public_mounts: Vec<StoragePublicMount>,
    upload: StorageUploadEndpoint,
) {
    let storage_for_post = storage.clone();
    let mounts_for_post = public_mounts.clone();
    let upload_for_post = upload.clone();
    cfg.service(
        web::resource(format!("/{}", upload.path)).route(web::post().to(
            move |user: Option<UserContext>, multipart: Multipart| {
                handle_upload(
                    user,
                    multipart,
                    storage_for_post.clone(),
                    mounts_for_post.clone(),
                    upload_for_post.clone(),
                )
            },
        )),
    );
}

async fn handle_upload(
    user: Option<UserContext>,
    mut multipart: Multipart,
    storage: StorageRegistry,
    public_mounts: Vec<StoragePublicMount>,
    upload: StorageUploadEndpoint,
) -> actix_web::Result<HttpResponse> {
    let user = match authorize_upload(user, &upload) {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };
    let _ = user;

    let mut file_name = None;
    let mut content_type = None;
    let mut bytes = Vec::new();
    let mut file_found = false;

    while let Some(item) = multipart.next().await {
        let mut field = match item {
            Ok(field) => field,
            Err(_) => {
                return Ok(errors::bad_request(
                    "invalid_multipart",
                    "Multipart upload is invalid",
                ));
            }
        };
        let field_name = field
            .content_disposition()
            .and_then(|value| value.get_name())
            .unwrap_or("");
        if field_name != "file" || file_found {
            while let Some(chunk) = field.next().await {
                if chunk.is_err() {
                    return Ok(errors::bad_request(
                        "invalid_multipart",
                        "Multipart upload is invalid",
                    ));
                }
            }
            continue;
        }

        file_found = true;
        file_name = field
            .content_disposition()
            .and_then(|value| value.get_filename())
            .map(sanitize_file_name)
            .filter(|value| !value.is_empty());
        content_type = field.content_type().map(ToOwned::to_owned);

        while let Some(chunk) = field.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => {
                    return Ok(errors::bad_request(
                        "invalid_multipart",
                        "Multipart upload is invalid",
                    ));
                }
            };
            let next_len = bytes.len().saturating_add(chunk.len());
            if next_len > upload.max_bytes {
                return Ok(errors::error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    "Uploaded file exceeds the configured size limit",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
    }

    if !file_found {
        return Ok(errors::validation_error(
            "file",
            "Multipart upload must include a `file` field",
        ));
    }

    let file_name = file_name.unwrap_or_else(|| "upload.bin".to_owned());
    let object_key = build_upload_object_key(&upload, &file_name);
    storage
        .put_bytes(upload.backend.as_str(), &object_key, bytes.clone())
        .await
        .map_err(|error| actix_web::error::ErrorInternalServerError(error.to_string()))?;

    let backend = upload.backend.clone();
    Ok(HttpResponse::Created().json(StorageUploadResponse {
        backend,
        object_key: object_key.clone(),
        public_url: public_url_for_object(
            public_mounts.as_slice(),
            &object_key,
            upload.backend.as_str(),
        ),
        file_name,
        content_type: content_type.map(|value| value.to_string()),
        size_bytes: bytes.len(),
    }))
}

async fn handle_s3_bucket_request(
    req: HttpRequest,
    storage: StorageRegistry,
    s3_compat: StorageS3CompatConfig,
) -> actix_web::Result<HttpResponse> {
    let bucket_name = req.match_info().get("bucket").unwrap_or_default();
    let bucket = match lookup_s3_bucket(&s3_compat, bucket_name) {
        Some(bucket) => bucket,
        None => return Ok(HttpResponse::NotFound().finish()),
    };
    let query = web::Query::<HashMap<String, String>>::from_query(req.query_string())
        .map(|value| value.into_inner())
        .unwrap_or_default();

    let prefix = query.get("prefix").map(String::as_str).unwrap_or("");
    let max_keys = query
        .get("max-keys")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1000)
        .min(1000);
    let continuation_token = query.get("continuation-token").cloned().unwrap_or_default();
    let backend_prefix = bucket_prefixed_key(bucket, prefix);
    let mut objects = storage
        .list_objects(bucket.backend.as_str(), backend_prefix.as_str())
        .map_err(actix_web::error::ErrorInternalServerError)?;
    objects.retain(|(key, _)| key.starts_with(backend_prefix.as_str()));

    let mut normalized = objects
        .into_iter()
        .map(|(key, info)| (strip_bucket_prefix(bucket, key.as_str()), info))
        .filter(|(key, _)| key.starts_with(prefix))
        .collect::<Vec<_>>();
    normalized.sort_by(|left, right| left.0.cmp(&right.0));

    let start_index = if continuation_token.is_empty() {
        0
    } else {
        normalized
            .iter()
            .position(|(key, _)| key > &continuation_token)
            .unwrap_or(normalized.len())
    };
    let slice = normalized
        .iter()
        .skip(start_index)
        .take(max_keys)
        .collect::<Vec<_>>();
    let next_token = normalized
        .get(start_index.saturating_add(slice.len()))
        .map(|(key, _)| key.clone());
    let body = render_list_objects_v2_xml(
        bucket_name,
        prefix,
        continuation_token.as_str(),
        max_keys,
        slice.as_slice(),
        next_token.as_deref(),
    );

    Ok(HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "application/xml"))
        .body(body))
}

async fn handle_s3_bucket_head(
    req: HttpRequest,
    _storage: StorageRegistry,
    s3_compat: StorageS3CompatConfig,
) -> actix_web::Result<HttpResponse> {
    let bucket_name = req.match_info().get("bucket").unwrap_or_default();
    if lookup_s3_bucket(&s3_compat, bucket_name).is_none() {
        return Ok(HttpResponse::NotFound().finish());
    }
    Ok(HttpResponse::Ok().finish())
}

async fn handle_s3_get_object(
    _req: HttpRequest,
    storage: StorageRegistry,
    s3_compat: StorageS3CompatConfig,
    tail: web::Path<(String, String)>,
) -> actix_web::Result<HttpResponse> {
    let (bucket_name, tail) = tail.into_inner();
    let bucket = match lookup_s3_bucket(&s3_compat, bucket_name.as_str()) {
        Some(bucket) => bucket,
        None => return Ok(HttpResponse::NotFound().finish()),
    };
    let object_key = s3_object_key(bucket, tail.as_str())?;
    let bytes = match storage.read_bytes(bucket.backend.as_str(), object_key.as_str()) {
        Ok(bytes) => bytes,
        Err(error) if error.to_string().contains("No such file") => {
            return Ok(HttpResponse::NotFound().finish());
        }
        Err(error) => return Err(actix_web::error::ErrorInternalServerError(error)),
    };
    let info = storage
        .object_info(bucket.backend.as_str(), object_key.as_str())
        .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(s3_object_response(bytes, &info, false))
}

async fn handle_s3_head_object(
    _req: HttpRequest,
    storage: StorageRegistry,
    s3_compat: StorageS3CompatConfig,
    tail: web::Path<(String, String)>,
) -> actix_web::Result<HttpResponse> {
    let (bucket_name, tail) = tail.into_inner();
    let bucket = match lookup_s3_bucket(&s3_compat, bucket_name.as_str()) {
        Some(bucket) => bucket,
        None => return Ok(HttpResponse::NotFound().finish()),
    };
    let object_key = s3_object_key(bucket, tail.as_str())?;
    let info = match storage.object_info(bucket.backend.as_str(), object_key.as_str()) {
        Ok(info) => info,
        Err(error) if error.to_string().contains("No such file") => {
            return Ok(HttpResponse::NotFound().finish());
        }
        Err(error) => return Err(actix_web::error::ErrorInternalServerError(error)),
    };
    Ok(s3_object_response(Vec::new(), &info, true))
}

async fn handle_s3_put_object(
    req: HttpRequest,
    body: web::Bytes,
    storage: StorageRegistry,
    s3_compat: StorageS3CompatConfig,
    tail: web::Path<(String, String)>,
) -> actix_web::Result<HttpResponse> {
    let (bucket_name, tail) = tail.into_inner();
    let bucket = match lookup_s3_bucket(&s3_compat, bucket_name.as_str()) {
        Some(bucket) => bucket,
        None => return Ok(HttpResponse::NotFound().finish()),
    };
    let object_key = s3_object_key(bucket, tail.as_str())?;
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let user_metadata = extract_s3_user_metadata(req.headers());
    let info = storage
        .put_bytes_with_metadata(
            bucket.backend.as_str(),
            object_key.as_str(),
            body.to_vec(),
            content_type,
            user_metadata,
        )
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok()
        .insert_header((header::ETAG, info.etag))
        .finish())
}

async fn handle_s3_delete_object(
    storage: StorageRegistry,
    s3_compat: StorageS3CompatConfig,
    tail: web::Path<(String, String)>,
) -> actix_web::Result<HttpResponse> {
    let (bucket_name, tail) = tail.into_inner();
    let bucket = match lookup_s3_bucket(&s3_compat, bucket_name.as_str()) {
        Some(bucket) => bucket,
        None => return Ok(HttpResponse::NotFound().finish()),
    };
    let object_key = s3_object_key(bucket, tail.as_str())?;
    storage
        .delete_object(bucket.backend.as_str(), object_key.as_str())
        .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::NoContent().finish())
}

fn s3_object_response(bytes: Vec<u8>, info: &StorageObjectInfo, head_only: bool) -> HttpResponse {
    let mut builder = HttpResponse::Ok();
    builder.insert_header((header::ETAG, info.etag.clone()));
    builder.insert_header((header::CONTENT_LENGTH, info.size_bytes.to_string()));
    if let Some(content_type) = &info.content_type {
        builder.insert_header((header::CONTENT_TYPE, content_type.clone()));
    }
    for (key, value) in &info.user_metadata {
        builder.insert_header((format!("x-amz-meta-{key}"), value.clone()));
    }
    if head_only {
        builder.finish()
    } else {
        builder.body(bytes)
    }
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

fn authorize_upload(
    user: Option<UserContext>,
    upload: &StorageUploadEndpoint,
) -> Result<Option<UserContext>, HttpResponse> {
    if !upload.require_auth && upload.roles.is_empty() {
        return Ok(user);
    }
    let Some(user) = user else {
        return Err(errors::unauthorized("missing_token", "Missing token"));
    };
    if upload.roles.is_empty() {
        return Ok(Some(user));
    }
    if upload
        .roles
        .iter()
        .any(|required| user.roles.iter().any(|role| role == required))
    {
        return Ok(Some(user));
    }
    Err(errors::forbidden(
        "forbidden",
        "You do not have permission to upload files",
    ))
}

fn build_upload_object_key(upload: &StorageUploadEndpoint, file_name: &str) -> String {
    let object_name = format!(
        "{}-{}",
        Uuid::new_v4().simple(),
        sanitize_file_name(file_name)
    );
    if upload.key_prefix.is_empty() {
        object_name
    } else {
        format!("{}/{}", upload.key_prefix, object_name)
    }
}

fn sanitize_file_name(value: &str) -> String {
    let raw = Path::new(value)
        .file_name()
        .and_then(|segment| segment.to_str())
        .unwrap_or("upload");
    let mut sanitized = String::with_capacity(raw.len());
    let mut previous_dash = false;

    for ch in raw.chars() {
        let allowed = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-');
        if allowed {
            sanitized.push(ch);
            previous_dash = false;
            continue;
        }
        if !previous_dash {
            sanitized.push('-');
            previous_dash = true;
        }
    }

    let trimmed = sanitized.trim_matches(|ch| matches!(ch, '-' | '_' | '.'));
    if trimmed.is_empty() {
        "upload".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn lookup_s3_bucket<'a>(
    config: &'a StorageS3CompatConfig,
    name: &str,
) -> Option<&'a StorageS3CompatBucket> {
    config.buckets.iter().find(|bucket| bucket.name == name)
}

fn s3_object_key(bucket: &StorageS3CompatBucket, tail: &str) -> actix_web::Result<String> {
    let relative_path = sanitize_requested_path(tail)?;
    if relative_path.as_os_str().is_empty() {
        return Err(actix_web::error::ErrorNotFound("invalid object path"));
    }
    Ok(bucket_prefixed_key(
        bucket,
        &relative_path
            .iter()
            .filter_map(|segment| segment.to_str())
            .collect::<Vec<_>>()
            .join("/"),
    ))
}

fn bucket_prefixed_key(bucket: &StorageS3CompatBucket, key: &str) -> String {
    let key = key.trim_matches('/');
    if bucket.key_prefix.is_empty() {
        key.to_owned()
    } else if key.is_empty() {
        bucket.key_prefix.clone()
    } else {
        format!("{}/{}", bucket.key_prefix, key)
    }
}

fn strip_bucket_prefix(bucket: &StorageS3CompatBucket, key: &str) -> String {
    if bucket.key_prefix.is_empty() {
        key.to_owned()
    } else if key == bucket.key_prefix {
        String::new()
    } else {
        key.strip_prefix(bucket.key_prefix.as_str())
            .and_then(|suffix| suffix.strip_prefix('/'))
            .unwrap_or(key)
            .to_owned()
    }
}

fn extract_s3_user_metadata(headers: &header::HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            name.as_str()
                .strip_prefix("x-amz-meta-")
                .and_then(|suffix| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (suffix.to_owned(), value.to_owned()))
                })
        })
        .collect::<BTreeMap<_, _>>()
}

fn render_list_objects_v2_xml(
    bucket_name: &str,
    prefix: &str,
    continuation_token: &str,
    max_keys: usize,
    objects: &[&(String, StorageObjectInfo)],
    next_token: Option<&str>,
) -> String {
    let mut body = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    body.push_str("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    body.push_str("<Name>");
    body.push_str(xml_escape(bucket_name).as_str());
    body.push_str("</Name><Prefix>");
    body.push_str(xml_escape(prefix).as_str());
    body.push_str("</Prefix><KeyCount>");
    body.push_str(objects.len().to_string().as_str());
    body.push_str("</KeyCount><MaxKeys>");
    body.push_str(max_keys.to_string().as_str());
    body.push_str("</MaxKeys><IsTruncated>");
    body.push_str(if next_token.is_some() {
        "true"
    } else {
        "false"
    });
    body.push_str("</IsTruncated>");
    if !continuation_token.is_empty() {
        body.push_str("<ContinuationToken>");
        body.push_str(xml_escape(continuation_token).as_str());
        body.push_str("</ContinuationToken>");
    }
    if let Some(next_token) = next_token {
        body.push_str("<NextContinuationToken>");
        body.push_str(xml_escape(next_token).as_str());
        body.push_str("</NextContinuationToken>");
    }
    for (key, info) in objects {
        body.push_str("<Contents><Key>");
        body.push_str(xml_escape(key).as_str());
        body.push_str("</Key><LastModified>");
        body.push_str(info.last_modified.to_rfc3339().as_str());
        body.push_str("</LastModified><ETag>");
        body.push_str(xml_escape(info.etag.as_str()).as_str());
        body.push_str("</ETag><Size>");
        body.push_str(info.size_bytes.to_string().as_str());
        body.push_str("</Size><StorageClass>STANDARD</StorageClass></Contents>");
    }
    body.push_str("</ListBucketResult>");
    body
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&apos;")
}

fn public_url_for_object(
    mounts: &[StoragePublicMount],
    object_key: &str,
    backend: &str,
) -> Option<String> {
    mounts
        .iter()
        .filter(|mount| mount.backend == backend)
        .filter_map(|mount| public_url_for_mount(mount, object_key))
        .max_by_key(|candidate| candidate.len())
}

fn public_url_for_mount(mount: &StoragePublicMount, object_key: &str) -> Option<String> {
    let suffix = if mount.key_prefix.is_empty() {
        object_key
    } else if object_key == mount.key_prefix {
        return None;
    } else {
        object_key
            .strip_prefix(mount.key_prefix.as_str())
            .and_then(|suffix| suffix.strip_prefix('/'))?
    };

    Some(if suffix.is_empty() {
        mount.mount_path.clone()
    } else if mount.mount_path == "/" {
        format!("/{}", suffix)
    } else {
        format!("{}/{}", mount.mount_path, suffix)
    })
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

    use actix_web::{
        App,
        http::{StatusCode, header},
        test,
    };

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
            uploads: Vec::new(),
            s3_compat: None,
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
            uploads: Vec::new(),
            s3_compat: None,
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

        let hidden = test::TestRequest::get().uri("/uploads/.env").to_request();
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
            uploads: Vec::new(),
            s3_compat: None,
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
