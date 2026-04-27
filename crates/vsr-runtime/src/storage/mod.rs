//! Object storage trait seam.
//!
//! All file and blob storage in VSR goes through [`ObjectStorage`]. The
//! default implementation uses the local filesystem. S3-compatible object
//! stores (AWS S3, MinIO, Cloudflare R2, etc.) are available behind the
//! `storage-s3` feature via the `object_store` crate.
//!
//! # Key types
//!
//! | Type | Purpose |
//! |---|---|
//! | [`StorageKey`] | Hierarchical path into a storage namespace |
//! | [`StorageObject`] | Retrieved object with metadata |
//! | [`ObjectStorage`] | The trait all adapters implement |

use std::{future::Future, time::Duration};

use bytes::Bytes;
use vsr_core::error::VsrResult;

// ── Concrete implementations ──────────────────────────────────────────────────

#[cfg(feature = "storage-local")]
pub mod local;

// ─── StorageKey ───────────────────────────────────────────────────────────────

/// A hierarchical key (path) into an object store.
///
/// Segments are separated by `/`. Leading and trailing slashes are normalized
/// away. Empty segments are not allowed.
///
/// ```rust
/// use vsr_runtime::storage::StorageKey;
/// let key = StorageKey::new("uploads/avatars/user-42.png");
/// assert_eq!(key.as_str(), "uploads/avatars/user-42.png");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorageKey(String);

impl StorageKey {
    /// Create a `StorageKey` from a path-like string.
    ///
    /// Normalizes leading/trailing slashes.
    pub fn new(path: impl Into<String>) -> Self {
        let s = path.into();
        Self(s.trim_matches('/').to_owned())
    }

    /// The key as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Append a segment and return a new key.
    pub fn join(&self, segment: impl AsRef<str>) -> Self {
        Self(format!("{}/{}", self.0, segment.as_ref().trim_matches('/')))
    }
}

impl std::fmt::Display for StorageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ─── StorageObject ────────────────────────────────────────────────────────────

/// A retrieved storage object with its content and metadata.
#[derive(Debug)]
pub struct StorageObject {
    /// The storage key this object was fetched from.
    pub key: StorageKey,
    /// Object content.
    pub data: Bytes,
    /// Object metadata.
    pub metadata: StorageMetadata,
}

/// Metadata associated with a stored object.
#[derive(Debug, Clone, Default)]
pub struct StorageMetadata {
    /// MIME content type (e.g. `"image/png"`).
    pub content_type: Option<String>,
    /// Size in bytes. `None` if not known at list time.
    pub size_bytes: Option<u64>,
    /// Last-modified time as a Unix timestamp.
    pub last_modified: Option<i64>,
    /// Arbitrary string tags.
    pub tags: std::collections::HashMap<String, String>,
}

// ─── ObjectStorage trait ──────────────────────────────────────────────────────

/// Read/write access to an object store.
///
/// Implementations:
/// - `LocalFsStorage` — stores objects under a directory. No extra deps.
/// - `ObjectStoreAdapter` — wraps `object_store::ObjectStore` for S3,
///   GCS, Azure, etc. Behind `storage-s3`.
///
/// # Contract
///
/// - `get` returns `Ok(None)` for missing keys — never `Err`.
/// - `put` is atomic from the caller's perspective (either fully written
///   or not written). Implementations may use a write-then-rename pattern.
/// - `delete` of a non-existent key is `Ok(())` — idempotent.
/// - `presigned_url` returns `Ok(None)` if the backend does not support
///   presigned URLs (e.g. local FS).
pub trait ObjectStorage: Send + Sync + 'static {
    /// Retrieve an object by key.
    fn get(
        &self,
        key: &StorageKey,
    ) -> impl Future<Output = VsrResult<Option<StorageObject>>> + Send;

    /// Store an object.
    fn put(
        &self,
        key: &StorageKey,
        data: Bytes,
        metadata: StorageMetadata,
    ) -> impl Future<Output = VsrResult<()>> + Send;

    /// Delete an object. Idempotent — does not error if the key is absent.
    fn delete(&self, key: &StorageKey) -> impl Future<Output = VsrResult<()>> + Send;

    /// List keys sharing a common prefix.
    fn list(
        &self,
        prefix: &StorageKey,
    ) -> impl Future<Output = VsrResult<Vec<StorageKey>>> + Send;

    /// Generate a time-limited pre-signed URL for direct client access.
    ///
    /// Returns `Ok(None)` if the backend does not support pre-signed URLs.
    fn presigned_url(
        &self,
        key: &StorageKey,
        expires_in: Duration,
    ) -> impl Future<Output = VsrResult<Option<String>>> + Send;
}
