//! Local filesystem implementation of [`ObjectStorage`].
//!
//! Objects are stored as plain files under a configured root directory.
//! Metadata (content-type, tags) is persisted in JSON sidecar files under
//! a `.vsr-meta/` subdirectory that mirrors the object tree.
//!
//! No extra dependencies are required — this module uses `std::fs` only.

use std::{
    collections::HashMap,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::Duration,
};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use vsr_core::error::{VsrError, VsrResult};

use super::{ObjectStorage, StorageKey, StorageMetadata, StorageObject};

// ── Sidecar metadata ──────────────────────────────────────────────────────────

/// Persisted form of [`StorageMetadata`] written to `.vsr-meta/` sidecars.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    tags: HashMap<String, String>,
}

// ── LocalFsStorage ────────────────────────────────────────────────────────────

/// Local filesystem implementation of [`ObjectStorage`].
///
/// All objects are stored as plain files under `root`. Metadata (content-type
/// and tags) is stored alongside as JSON sidecar files in a `.vsr-meta/`
/// subdirectory. `size_bytes` and `last_modified` are derived from the
/// filesystem at read time.
///
/// # Example
///
/// ```rust,no_run
/// use vsr_runtime::storage::local::LocalFsStorage;
/// use vsr_runtime::storage::{ObjectStorage, StorageKey, StorageMetadata};
/// use bytes::Bytes;
///
/// # async fn example() -> vsr_core::error::VsrResult<()> {
/// let store = LocalFsStorage::new("/var/app/uploads")?;
/// let key = StorageKey::new("avatars/user-42.png");
/// store.put(&key, Bytes::from(b"image bytes".to_vec()), StorageMetadata {
///     content_type: Some("image/png".to_owned()),
///     ..Default::default()
/// }).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct LocalFsStorage {
    root: PathBuf,
}

impl LocalFsStorage {
    /// Create a new storage instance rooted at `root`.
    ///
    /// Creates the directory (and any missing parents) if it does not exist.
    pub fn new(root: impl Into<PathBuf>) -> VsrResult<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| {
            VsrError::Other(format!("failed to create storage root `{}`: {e}", root.display()).into())
        })?;
        Ok(Self { root })
    }

    /// The root directory this storage instance is bound to.
    pub fn root(&self) -> &Path {
        &self.root
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn object_path(&self, key: &StorageKey) -> PathBuf {
        key_to_path(&self.root, key)
    }

    fn meta_path(&self, key: &StorageKey) -> PathBuf {
        let mut meta_dir = self.root.join(".vsr-meta");
        for segment in key.as_str().split('/') {
            if !segment.is_empty() {
                meta_dir.push(segment);
            }
        }
        // Append `.json` to the final segment so the meta file sits next to
        // the object in the mirror tree.
        let file_name = meta_dir
            .file_name()
            .map(|n| format!("{}.json", n.to_string_lossy()))
            .unwrap_or_else(|| "_.json".to_owned());
        meta_dir.set_file_name(file_name);
        meta_dir
    }

    fn read_meta(&self, key: &StorageKey) -> VsrResult<PersistedMeta> {
        let path = self.meta_path(key);
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<PersistedMeta>(&bytes).map_err(|e| {
                VsrError::Other(format!("failed to parse metadata for `{key}`: {e}").into())
            }),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(PersistedMeta::default()),
            Err(e) => Err(VsrError::Other(
                format!("failed to read metadata for `{key}`: {e}").into(),
            )),
        }
    }

    fn write_meta(&self, key: &StorageKey, meta: &PersistedMeta) -> VsrResult<()> {
        let path = self.meta_path(key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                VsrError::Other(format!("failed to create metadata dir: {e}").into())
            })?;
        }
        let bytes = serde_json::to_vec(meta).map_err(|e| {
            VsrError::Other(format!("failed to serialize metadata for `{key}`: {e}").into())
        })?;
        fs::write(&path, bytes).map_err(|e| {
            VsrError::Other(format!("failed to write metadata for `{key}`: {e}").into())
        })
    }

    fn delete_meta(&self, key: &StorageKey) {
        let _ = fs::remove_file(self.meta_path(key));
    }

    fn stat_to_metadata(
        &self,
        key: &StorageKey,
        fs_meta: &fs::Metadata,
        persisted: PersistedMeta,
    ) -> StorageMetadata {
        let last_modified = fs_meta
            .modified()
            .ok()
            .and_then(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs() as i64)
            });
        StorageMetadata {
            content_type: persisted.content_type,
            size_bytes: Some(fs_meta.len()),
            last_modified,
            tags: persisted.tags,
        }
    }
}

impl ObjectStorage for LocalFsStorage {
    async fn get(&self, key: &StorageKey) -> VsrResult<Option<StorageObject>> {
        let path = self.object_path(key);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(VsrError::Other(
                    format!("storage read failed for `{key}`: {e}").into(),
                ));
            }
        };
        let fs_meta = fs::metadata(&path).map_err(|e| {
            VsrError::Other(format!("storage stat failed for `{key}`: {e}").into())
        })?;
        let persisted = self.read_meta(key)?;
        Ok(Some(StorageObject {
            key: key.clone(),
            data: Bytes::from(bytes),
            metadata: self.stat_to_metadata(key, &fs_meta, persisted),
        }))
    }

    async fn put(&self, key: &StorageKey, data: Bytes, metadata: StorageMetadata) -> VsrResult<()> {
        let path = self.object_path(key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                VsrError::Other(format!("failed to create storage parent dir: {e}").into())
            })?;
        }
        fs::write(&path, &data).map_err(|e| {
            VsrError::Other(format!("storage write failed for `{key}`: {e}").into())
        })?;
        self.write_meta(
            key,
            &PersistedMeta {
                content_type: metadata.content_type,
                tags: metadata.tags,
            },
        )
    }

    async fn delete(&self, key: &StorageKey) -> VsrResult<()> {
        let path = self.object_path(key);
        match fs::remove_file(&path) {
            Ok(()) => {
                self.delete_meta(key);
                Ok(())
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(VsrError::Other(
                format!("storage delete failed for `{key}`: {e}").into(),
            )),
        }
    }

    async fn list(&self, prefix: &StorageKey) -> VsrResult<Vec<StorageKey>> {
        let mut keys = Vec::new();
        collect_object_keys(&self.root, &self.root, prefix.as_str(), &mut keys)?;
        keys.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(keys)
    }

    async fn presigned_url(
        &self,
        _key: &StorageKey,
        _expires_in: Duration,
    ) -> VsrResult<Option<String>> {
        // Local filesystem does not support pre-signed URLs.
        Ok(None)
    }
}

// ── Path helpers ──────────────────────────────────────────────────────────────

fn key_to_path(root: &Path, key: &StorageKey) -> PathBuf {
    let mut path = root.to_path_buf();
    for segment in key.as_str().split('/') {
        if !segment.is_empty() {
            path.push(segment);
        }
    }
    path
}

fn collect_object_keys(
    root: &Path,
    dir: &Path,
    prefix: &str,
    out: &mut Vec<StorageKey>,
) -> VsrResult<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(VsrError::Other(
                format!("failed to read storage dir `{}`: {e}", dir.display()).into(),
            ));
        }
    };

    for entry in entries {
        let entry = entry.map_err(|e| {
            VsrError::Other(format!("storage directory entry error: {e}").into())
        })?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        // Skip the metadata mirror directory.
        if name == ".vsr-meta" {
            continue;
        }

        let ft = entry.file_type().map_err(|e| {
            VsrError::Other(format!("failed to stat `{}`: {e}", path.display()).into())
        })?;

        if ft.is_dir() {
            collect_object_keys(root, &path, prefix, out)?;
        } else if ft.is_file() {
            let relative = path.strip_prefix(root).map_err(|e| {
                VsrError::Other(format!("storage path error: {e}").into())
            })?;
            let key_str = relative
                .components()
                .filter_map(|c| c.as_os_str().to_str())
                .collect::<Vec<_>>()
                .join("/");
            if prefix.is_empty() || key_str.starts_with(prefix) {
                out.push(StorageKey::new(&key_str));
            }
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use bytes::Bytes;

    use super::*;
    use crate::storage::StorageMetadata;

    fn temp_root(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("vsr_local_storage_{label}_{stamp}"))
    }

    #[test]
    fn creates_root_dir_on_init() {
        let root = temp_root("init");
        assert!(!root.exists());
        let _store = LocalFsStorage::new(&root).expect("should init");
        assert!(root.is_dir(), "root dir should be created on init");
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn put_and_get_roundtrip() {
        let root = temp_root("roundtrip");
        let store = LocalFsStorage::new(&root).expect("should init");

        let key = StorageKey::new("docs/readme.txt");
        let data = Bytes::from(b"hello from storage".to_vec());

        store
            .put(
                &key,
                data.clone(),
                StorageMetadata {
                    content_type: Some("text/plain".to_owned()),
                    ..Default::default()
                },
            )
            .await
            .expect("put should succeed");

        let obj = store.get(&key).await.expect("get should succeed");
        let obj = obj.expect("object should exist after put");
        assert_eq!(obj.data, data);
        assert_eq!(obj.metadata.content_type.as_deref(), Some("text/plain"));
        assert!(obj.metadata.size_bytes.is_some());

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn get_missing_key_returns_none() {
        let root = temp_root("missing");
        let store = LocalFsStorage::new(&root).expect("should init");
        let result = store
            .get(&StorageKey::new("nonexistent/file.bin"))
            .await
            .expect("get should not error for missing key");
        assert!(result.is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn delete_existing_and_missing_are_both_ok() {
        let root = temp_root("delete");
        let store = LocalFsStorage::new(&root).expect("should init");
        let key = StorageKey::new("to-delete.bin");

        store
            .put(&key, Bytes::from(b"data".to_vec()), StorageMetadata::default())
            .await
            .expect("put should succeed");

        store.delete(&key).await.expect("first delete should succeed");
        store
            .delete(&key)
            .await
            .expect("second delete of missing key should also succeed");

        assert!(store.get(&key).await.expect("get after delete").is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn list_returns_matching_keys_sorted() {
        let root = temp_root("list");
        let store = LocalFsStorage::new(&root).expect("should init");

        for key in ["images/a.png", "images/b.png", "docs/readme.md"] {
            store
                .put(
                    &StorageKey::new(key),
                    Bytes::from(b"x".to_vec()),
                    StorageMetadata::default(),
                )
                .await
                .expect("put should succeed");
        }

        let all = store
            .list(&StorageKey::new(""))
            .await
            .expect("list should succeed");
        let all_strs: Vec<&str> = all.iter().map(StorageKey::as_str).collect();
        assert_eq!(all_strs, vec!["docs/readme.md", "images/a.png", "images/b.png"]);

        let images = store
            .list(&StorageKey::new("images"))
            .await
            .expect("list should succeed");
        assert_eq!(images.len(), 2);
        assert!(images.iter().all(|k| k.as_str().starts_with("images")));

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn presigned_url_returns_none() {
        let root = temp_root("presigned");
        let store = LocalFsStorage::new(&root).expect("should init");
        let url = store
            .presigned_url(&StorageKey::new("any/key"), Duration::from_secs(3600))
            .await
            .expect("presigned_url should not error");
        assert!(url.is_none(), "local FS does not support presigned URLs");
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn metadata_persists_across_get() {
        let root = temp_root("meta");
        let store = LocalFsStorage::new(&root).expect("should init");
        let key = StorageKey::new("files/data.bin");
        let mut tags = HashMap::new();
        tags.insert("user-id".to_owned(), "42".to_owned());

        store
            .put(
                &key,
                Bytes::from(b"bytes".to_vec()),
                StorageMetadata {
                    content_type: Some("application/octet-stream".to_owned()),
                    tags,
                    ..Default::default()
                },
            )
            .await
            .expect("put should succeed");

        let obj = store
            .get(&key)
            .await
            .expect("get should succeed")
            .expect("object should exist");
        assert_eq!(
            obj.metadata.content_type.as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(obj.metadata.tags.get("user-id").map(String::as_str), Some("42"));
        let _ = fs::remove_dir_all(&root);
    }
}
