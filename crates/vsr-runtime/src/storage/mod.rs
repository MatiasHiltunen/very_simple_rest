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
use vsr_core::error::{VsrError, VsrResult};

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
/// let key = StorageKey::new("uploads/avatars/user-42.png").expect("valid storage key");
/// assert_eq!(key.as_str(), "uploads/avatars/user-42.png");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorageKey(String);

/// Error returned when a storage key is not a safe object-store path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageKeyError {
    reason: String,
}

impl StorageKeyError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for StorageKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid storage key: {}", self.reason)
    }
}

impl std::error::Error for StorageKeyError {}

impl From<StorageKeyError> for VsrError {
    fn from(error: StorageKeyError) -> Self {
        Self::Other(Box::new(error))
    }
}

impl StorageKey {
    /// Create a `StorageKey` from a path-like string.
    ///
    /// Normalizes leading/trailing slashes and rejects path traversal,
    /// platform-specific separators, empty components, and the internal
    /// metadata namespace. An empty key is valid as a list-all prefix.
    pub fn new(path: impl Into<String>) -> Result<Self, StorageKeyError> {
        let s = path.into();
        let normalized = s.trim_matches('/');
        validate_storage_key(normalized, true)?;
        Ok(Self(normalized.to_owned()))
    }

    /// The key as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this key is the empty list-all prefix.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Append a segment and return a new key.
    pub fn join(&self, segment: impl AsRef<str>) -> Result<Self, StorageKeyError> {
        let segment = segment.as_ref().trim_matches('/');
        validate_storage_key(segment, false)?;
        if segment.contains('/') {
            return Err(StorageKeyError::new(
                "join accepts exactly one non-empty path segment",
            ));
        }

        if self.0.is_empty() {
            Self::new(segment)
        } else {
            Self::new(format!("{}/{}", self.0, segment))
        }
    }

    #[cfg(feature = "storage-local")]
    pub(crate) fn validate(&self) -> Result<(), StorageKeyError> {
        validate_storage_key(&self.0, true)
    }

    #[cfg(feature = "storage-local")]
    pub(crate) fn require_object(&self) -> Result<(), StorageKeyError> {
        validate_storage_key(&self.0, false)
    }
}

fn validate_storage_key(path: &str, allow_empty: bool) -> Result<(), StorageKeyError> {
    if path.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(StorageKeyError::new("object keys cannot be empty"))
        };
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(StorageKeyError::new(
            "leading and trailing separators must be normalized",
        ));
    }
    if path.contains('\\') {
        return Err(StorageKeyError::new("backslashes are not allowed"));
    }
    if path.chars().any(char::is_control) {
        return Err(StorageKeyError::new("control characters are not allowed"));
    }
    if path
        .chars()
        .any(|character| matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
    {
        return Err(StorageKeyError::new(
            "characters reserved by local filesystems are not allowed",
        ));
    }

    for segment in path.split('/') {
        if segment.ends_with('.') || segment.ends_with(' ') {
            return Err(StorageKeyError::new(
                "path components cannot end with a dot or space",
            ));
        }
        match segment {
            "" => {
                return Err(StorageKeyError::new(
                    "empty path components are not allowed",
                ));
            }
            "." | ".." => {
                return Err(StorageKeyError::new(
                    "`.` and `..` path components are not allowed",
                ));
            }
            segment if segment.eq_ignore_ascii_case(".vsr-meta") => {
                return Err(StorageKeyError::new(
                    "`.vsr-meta` is reserved for internal metadata",
                ));
            }
            _ => {}
        }
    }

    Ok(())
}

impl std::fmt::Display for StorageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod storage_key_tests {
    use super::StorageKey;

    #[test]
    fn storage_key_normalizes_outer_slashes() {
        let key = StorageKey::new("/uploads/avatar.png/").expect("key should be valid");
        assert_eq!(key.as_str(), "uploads/avatar.png");
    }

    #[test]
    fn storage_key_rejects_unsafe_components() {
        for key in [
            "../outside.txt",
            "uploads/../outside.txt",
            "uploads/./avatar.png",
            "uploads//avatar.png",
            "uploads\\avatar.png",
            ".vsr-meta/object.json",
            "uploads/.vsr-meta/object.json",
            "uploads/.VSR-META/object.json",
            "uploads/avatar\0.png",
            "uploads/avatar?.png",
            "C:/outside.txt",
            "uploads/avatar.png.",
        ] {
            assert!(StorageKey::new(key).is_err(), "`{key}` should be rejected");
        }
    }

    #[test]
    fn storage_key_join_validates_one_segment() {
        let root = StorageKey::new("").expect("empty list prefix should be valid");
        let uploads = root.join("uploads").expect("segment should be valid");
        let avatar = uploads.join("avatar.png").expect("segment should be valid");

        assert_eq!(avatar.as_str(), "uploads/avatar.png");
        assert!(uploads.join("../outside.txt").is_err());
        assert!(uploads.join("nested/avatar.png").is_err());
        assert!(uploads.join("").is_err());
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
    fn list(&self, prefix: &StorageKey) -> impl Future<Output = VsrResult<Vec<StorageKey>>> + Send;

    /// Generate a time-limited pre-signed URL for direct client access.
    ///
    /// Returns `Ok(None)` if the backend does not support pre-signed URLs.
    fn presigned_url(
        &self,
        key: &StorageKey,
        expires_in: Duration,
    ) -> impl Future<Output = VsrResult<Option<String>>> + Send;
}
#[cfg(feature = "storage-local")]
#[doc(hidden)]
pub mod transaction;
