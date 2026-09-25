//! Storage backend, mount, upload, and S3 compatibility settings.

use serde::{Deserialize, Serialize};

use crate::static_config::StaticCacheProfile;

/// Supported storage backend kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageBackendKind {
    /// Store objects in the local filesystem.
    Local,
}

/// One named storage backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageBackendConfig {
    /// Name used by mounts and upload endpoints.
    pub name: String,
    /// Backend implementation.
    pub kind: StorageBackendKind,
    /// Configured root directory.
    pub root_dir: String,
    /// Root directory resolved against the service bundle.
    pub resolved_root_dir: String,
}

/// Public HTTP mount for stored objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoragePublicMount {
    /// Public URL prefix.
    pub mount_path: String,
    /// Named backend.
    pub backend: String,
    /// Object key prefix within the backend.
    pub key_prefix: String,
    /// Cache policy for public responses.
    pub cache: StaticCacheProfile,
}

/// Multipart upload endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageUploadEndpoint {
    /// Endpoint name.
    pub name: String,
    /// HTTP path.
    pub path: String,
    /// Named backend.
    pub backend: String,
    /// Prefix for uploaded object keys.
    pub key_prefix: String,
    /// Maximum upload size in bytes.
    pub max_bytes: usize,
    /// Whether uploads require an authenticated caller.
    pub require_auth: bool,
    /// Allowed roles for authenticated uploads.
    pub roles: Vec<String>,
}

/// Bucket exposed by the S3-compatible HTTP API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageS3CompatBucket {
    /// Public bucket name.
    pub name: String,
    /// Named backend.
    pub backend: String,
    /// Object key prefix within the backend.
    pub key_prefix: String,
}

/// S3-compatible HTTP API settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageS3CompatConfig {
    /// URL prefix for the API.
    pub mount_path: String,
    /// Exposed buckets.
    pub buckets: Vec<StorageS3CompatBucket>,
}

/// Complete storage configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StorageConfig {
    /// Named backends.
    pub backends: Vec<StorageBackendConfig>,
    /// Public object mounts.
    pub public_mounts: Vec<StoragePublicMount>,
    /// Upload endpoints.
    pub uploads: Vec<StorageUploadEndpoint>,
    /// Optional S3-compatible API.
    pub s3_compat: Option<StorageS3CompatConfig>,
}

impl StorageConfig {
    /// Whether no storage backends or routes are configured.
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
            && self.public_mounts.is_empty()
            && self.uploads.is_empty()
            && self.s3_compat.is_none()
    }
}

/// Response returned after an upload succeeds.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct StorageUploadResponse {
    /// Named backend that received the object.
    pub backend: String,
    /// Key assigned to the object.
    pub object_key: String,
    /// Optional public URL for the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    /// Original uploaded file name.
    pub file_name: String,
    /// Optional media type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Stored object size in bytes.
    pub size_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::{StorageConfig, StorageUploadResponse};

    #[test]
    fn default_storage_config_is_empty() {
        assert!(StorageConfig::default().is_empty());
    }

    #[test]
    fn upload_response_preserves_json_shape() {
        let response = StorageUploadResponse {
            backend: "local".into(),
            object_key: "avatars/1.png".into(),
            public_url: None,
            file_name: "1.png".into(),
            content_type: None,
            size_bytes: 3,
        };
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({
                "backend": "local",
                "object_key": "avatars/1.png",
                "file_name": "1.png",
                "size_bytes": 3
            })
        );
    }
}
