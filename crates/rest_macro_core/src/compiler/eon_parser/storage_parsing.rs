use std::{
    collections::{HashMap, HashSet},
    path::{Component, Path, PathBuf},
};

use proc_macro2::Span;

use super::super::model::{
    ResourceSpec, StaticCacheProfile, StaticMode, StaticMountSpec,
};
use super::documents::{StaticConfigDocument, StorageDocument};
use crate::storage::{
    StorageBackendConfig, StorageBackendKind, StorageConfig, StoragePublicMount,
    StorageS3CompatBucket, StorageS3CompatConfig, StorageUploadEndpoint,
};
pub(super) fn build_static_mounts(
    service_root: &Path,
    static_config: Option<StaticConfigDocument>,
) -> syn::Result<Vec<StaticMountSpec>> {
    let service_root = service_root
        .canonicalize()
        .unwrap_or_else(|_| service_root.to_path_buf());
    let Some(static_config) = static_config else {
        return Ok(Vec::new());
    };

    let mut mounts = Vec::with_capacity(static_config.mounts.len());
    let mut seen_mounts = HashSet::new();
    for mount in static_config.mounts {
        let mount_path = normalize_mount_path(&mount.mount)?;
        if !seen_mounts.insert(mount_path.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate static mount `{mount_path}`"),
            ));
        }
        validate_mount_path(&mount_path)?;

        let source_dir = validate_relative_path(&mount.dir, "static dir")?;
        let resolved_dir = resolve_directory_under_root(&service_root, &source_dir)?;
        let mode = parse_static_mode(mount.mode.as_deref().unwrap_or("Directory"))?;
        let cache = parse_static_cache_profile(mount.cache.as_deref().unwrap_or("Revalidate"))?;
        let index_file = mount
            .index_file
            .as_deref()
            .map(|value| validate_relative_path(value, "static index_file"))
            .transpose()?;
        let fallback_file = mount
            .fallback_file
            .as_deref()
            .map(|value| validate_relative_path(value, "static fallback_file"))
            .transpose()?;

        let (index_file, fallback_file) = match mode {
            StaticMode::Directory => (index_file, fallback_file),
            StaticMode::Spa => (
                Some(index_file.unwrap_or_else(|| "index.html".to_owned())),
                Some(fallback_file.unwrap_or_else(|| "index.html".to_owned())),
            ),
        };

        if let Some(index_file) = &index_file {
            resolve_file_under_root(&resolved_dir, index_file, "static index_file")?;
        }
        if let Some(fallback_file) = &fallback_file {
            resolve_file_under_root(&resolved_dir, fallback_file, "static fallback_file")?;
        }

        mounts.push(StaticMountSpec {
            mount_path,
            source_dir,
            resolved_dir: resolved_dir.display().to_string(),
            mode,
            index_file,
            fallback_file,
            cache,
        });
    }

    Ok(mounts)
}

pub(super) fn parse_storage_document(
    service_root: &Path,
    storage: Option<StorageDocument>,
) -> syn::Result<StorageConfig> {
    const DEFAULT_STORAGE_UPLOAD_MAX_BYTES: usize = 25 * 1024 * 1024;
    let service_root = service_root
        .canonicalize()
        .unwrap_or_else(|_| service_root.to_path_buf());
    let Some(storage) = storage else {
        return Ok(StorageConfig::default());
    };

    let mut backends = Vec::with_capacity(storage.backends.len());
    let mut seen_backend_names = HashSet::new();
    for backend in storage.backends {
        let backend_name = backend.name.trim();
        if backend_name.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                "storage backend name cannot be empty",
            ));
        }
        if !seen_backend_names.insert(backend_name.to_owned()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate storage backend `{backend_name}`"),
            ));
        }
        let kind = parse_storage_backend_kind(&backend.kind)?;
        let root_dir = validate_relative_path(&backend.dir, "storage backend dir")?;
        let resolved_root_dir =
            resolve_path_under_root_allow_missing(&service_root, &root_dir, "storage backend dir")?;
        backends.push(StorageBackendConfig {
            name: backend_name.to_owned(),
            kind,
            root_dir,
            resolved_root_dir: resolved_root_dir.display().to_string(),
        });
    }

    let mut public_mounts = Vec::with_capacity(storage.public_mounts.len());
    let mut seen_mounts = HashSet::new();
    for mount in storage.public_mounts {
        let mount_path = normalize_mount_path(&mount.mount)?;
        if !seen_mounts.insert(mount_path.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate storage public mount `{mount_path}`"),
            ));
        }
        validate_storage_mount_path(&mount_path)?;

        let backend = mount.backend.trim();
        if backend.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("storage public mount `{mount_path}` must reference a backend"),
            ));
        }
        if !seen_backend_names.contains(backend) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "storage public mount `{mount_path}` references unknown backend `{backend}`"
                ),
            ));
        }

        public_mounts.push(StoragePublicMount {
            mount_path,
            backend: backend.to_owned(),
            key_prefix: validate_storage_key_prefix(mount.prefix.as_deref())?,
            cache: runtime_static_cache_profile(parse_static_cache_profile(
                mount.cache.as_deref().unwrap_or("Revalidate"),
            )?),
        });
    }

    let mut uploads = Vec::with_capacity(storage.uploads.len());
    let mut seen_upload_names = HashSet::new();
    let mut seen_upload_paths = HashSet::new();
    for upload in storage.uploads {
        let upload_name = upload.name.trim();
        if upload_name.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                "storage upload name cannot be empty",
            ));
        }
        if !seen_upload_names.insert(upload_name.to_owned()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate storage upload `{upload_name}`"),
            ));
        }
        let path = normalize_storage_upload_path(&upload.path)?;
        if !seen_upload_paths.insert(path.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate storage upload path `{path}`"),
            ));
        }

        let backend = upload.backend.trim();
        if backend.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("storage upload `{upload_name}` must reference a backend"),
            ));
        }
        if !seen_backend_names.contains(backend) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("storage upload `{upload_name}` references unknown backend `{backend}`"),
            ));
        }
        let max_bytes = upload.max_bytes.unwrap_or(DEFAULT_STORAGE_UPLOAD_MAX_BYTES);
        if max_bytes == 0 {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("storage upload `{upload_name}` must allow at least 1 byte"),
            ));
        }

        uploads.push(StorageUploadEndpoint {
            name: upload_name.to_owned(),
            path,
            backend: backend.to_owned(),
            key_prefix: validate_storage_key_prefix(upload.prefix.as_deref())?,
            max_bytes,
            require_auth: upload.require_auth.unwrap_or(true),
            roles: upload.roles,
        });
    }

    let s3_compat = if let Some(s3_compat) = storage.s3_compat {
        let mount_path = normalize_mount_path(s3_compat.mount.as_deref().unwrap_or("/_s3"))?;
        validate_s3_compat_mount_path(&mount_path)?;
        let mut buckets = Vec::with_capacity(s3_compat.buckets.len());
        let mut seen_bucket_names = HashSet::new();
        for bucket in s3_compat.buckets {
            let bucket_name = bucket.name.trim();
            if bucket_name.is_empty() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "storage s3_compat bucket name cannot be empty",
                ));
            }
            if !seen_bucket_names.insert(bucket_name.to_owned()) {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!("duplicate storage s3_compat bucket `{bucket_name}`"),
                ));
            }
            let backend = bucket.backend.trim();
            if backend.is_empty() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!("storage s3_compat bucket `{bucket_name}` must reference a backend"),
                ));
            }
            if !seen_backend_names.contains(backend) {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "storage s3_compat bucket `{bucket_name}` references unknown backend `{backend}`"
                    ),
                ));
            }
            buckets.push(StorageS3CompatBucket {
                name: bucket_name.to_owned(),
                backend: backend.to_owned(),
                key_prefix: validate_storage_key_prefix(bucket.prefix.as_deref())?,
            });
        }

        Some(StorageS3CompatConfig {
            mount_path,
            buckets,
        })
    } else {
        None
    };

    Ok(StorageConfig {
        backends,
        public_mounts,
        uploads,
        s3_compat,
    })
}

pub(super) fn normalize_mount_path(value: &str) -> syn::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "static mount path cannot be empty",
        ));
    }

    if !trimmed.starts_with('/') {
        return Err(syn::Error::new(
            Span::call_site(),
            "static mount path must start with `/`",
        ));
    }

    if trimmed != "/" && trimmed.ends_with('/') {
        return Ok(trimmed.trim_end_matches('/').to_owned());
    }

    Ok(trimmed.to_owned())
}

pub(super) fn validate_mount_path(mount_path: &str) -> syn::Result<()> {
    if matches!(mount_path, "/api" | "/auth" | "/docs" | "/openapi.json") {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("static mount `{mount_path}` conflicts with a reserved route"),
        ));
    }

    if mount_path.contains("//") {
        return Err(syn::Error::new(
            Span::call_site(),
            "static mount path cannot contain `//`",
        ));
    }

    Ok(())
}

pub(super) fn validate_storage_mount_path(mount_path: &str) -> syn::Result<()> {
    if mount_path == "/api"
        || mount_path.starts_with("/api/")
        || mount_path == "/auth"
        || mount_path.starts_with("/auth/")
        || mount_path == "/docs"
        || mount_path == "/openapi.json"
    {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("storage public mount `{mount_path}` conflicts with a reserved route"),
        ));
    }

    if mount_path.contains("//") {
        return Err(syn::Error::new(
            Span::call_site(),
            "storage public mount path cannot contain `//`",
        ));
    }

    Ok(())
}

pub(super) fn validate_s3_compat_mount_path(mount_path: &str) -> syn::Result<()> {
    if mount_path == "/api"
        || mount_path.starts_with("/api/")
        || mount_path == "/auth"
        || mount_path.starts_with("/auth/")
        || mount_path == "/docs"
        || mount_path == "/openapi.json"
    {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("storage s3_compat mount `{mount_path}` conflicts with a reserved route"),
        ));
    }

    if mount_path.contains("//") {
        return Err(syn::Error::new(
            Span::call_site(),
            "storage s3_compat mount path cannot contain `//`",
        ));
    }

    Ok(())
}

pub(super) fn normalize_storage_upload_path(value: &str) -> syn::Result<String> {
    let trimmed = value.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "storage upload path cannot be empty",
        ));
    }

    let path = Path::new(trimmed);
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(syn::Error::new(
            Span::call_site(),
            "storage upload path must stay within the API scope",
        ));
    }

    if trimmed.contains("//") {
        return Err(syn::Error::new(
            Span::call_site(),
            "storage upload path cannot contain `//`",
        ));
    }

    Ok(trimmed.to_owned())
}

pub(super) fn validate_relative_path(value: &str, label: &str) -> syn::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} cannot be empty"),
        ));
    }

    let path = Path::new(trimmed);
    if path.is_absolute() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} must be relative to the `.eon` file"),
        ));
    }

    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} cannot escape the service directory"),
        ));
    }

    Ok(trimmed.to_owned())
}

pub(super) fn validate_storage_key_prefix(value: Option<&str>) -> syn::Result<String> {
    let Some(value) = value.map(str::trim) else {
        return Ok(String::new());
    };
    if value.is_empty() {
        return Ok(String::new());
    }

    let trimmed = value.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }

    validate_relative_path(trimmed, "storage public mount prefix")
}

pub(super) fn resolve_path_under_root_allow_missing(
    service_root: &Path,
    relative_path: &str,
    label: &str,
) -> syn::Result<PathBuf> {
    let mut resolved = service_root.to_path_buf();
    for component in Path::new(relative_path).components() {
        match component {
            Component::Normal(segment) => {
                resolved.push(segment);
                if resolved.exists() {
                    let canonical = resolved.canonicalize().map_err(|error| {
                        syn::Error::new(
                            Span::call_site(),
                            format!("failed to resolve {label} `{relative_path}`: {error}"),
                        )
                    })?;
                    if !canonical.starts_with(service_root) {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "{label} `{relative_path}` resolves outside the service directory"
                            ),
                        ));
                    }
                    resolved = canonical;
                }
            }
            Component::CurDir => {}
            _ => unreachable!("relative path validation should reject unsupported components"),
        }
    }
    Ok(resolved)
}

pub(super) fn resolve_directory_under_root(service_root: &Path, relative_dir: &str) -> syn::Result<PathBuf> {
    let resolved = service_root.join(relative_dir);
    let canonical = resolved.canonicalize().map_err(|error| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to resolve static dir `{relative_dir}`: {error}"),
        )
    })?;
    if !canonical.starts_with(service_root) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("static dir `{relative_dir}` resolves outside the service directory"),
        ));
    }
    if !canonical.is_dir() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("static dir `{relative_dir}` is not a directory"),
        ));
    }
    Ok(canonical)
}

pub(super) fn parse_storage_backend_kind(value: &str) -> syn::Result<StorageBackendKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "local" => Ok(StorageBackendKind::Local),
        other => Err(syn::Error::new(
            Span::call_site(),
            format!("unsupported `storage.backends.kind` value `{other}`"),
        )),
    }
}

pub(super) fn runtime_static_cache_profile(
    value: StaticCacheProfile,
) -> crate::static_files::StaticCacheProfile {
    match value {
        StaticCacheProfile::NoStore => crate::static_files::StaticCacheProfile::NoStore,
        StaticCacheProfile::Revalidate => crate::static_files::StaticCacheProfile::Revalidate,
        StaticCacheProfile::Immutable => crate::static_files::StaticCacheProfile::Immutable,
    }
}

pub(super) fn validate_distinct_public_mounts(
    static_mounts: &[StaticMountSpec],
    storage: &StorageConfig,
) -> syn::Result<()> {
    let mut mounts = HashMap::new();
    for mount in static_mounts {
        mounts.insert(mount.mount_path.as_str(), "static mount");
    }
    for mount in &storage.public_mounts {
        if let Some(existing) = mounts.insert(mount.mount_path.as_str(), "storage public mount") {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "mount path `{}` is already declared by a {existing}",
                    mount.mount_path
                ),
            ));
        }
    }
    if let Some(s3_compat) = &storage.s3_compat
        && let Some(existing) =
            mounts.insert(s3_compat.mount_path.as_str(), "storage s3_compat mount")
    {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "mount path `{}` is already declared by a {existing}",
                s3_compat.mount_path
            ),
        ));
    }
    Ok(())
}

pub(super) fn validate_storage_upload_routes(
    storage: &StorageConfig,
    resources: &[ResourceSpec],
) -> syn::Result<()> {
    let mut reserved = HashSet::new();
    reserved.insert("auth".to_owned());
    for resource in resources {
        reserved.insert(resource.api_name().to_owned());
        for relation in &resource.many_to_many {
            reserved.insert(relation.name.clone());
        }
    }

    for upload in &storage.uploads {
        let first_segment = upload
            .path
            .split('/')
            .next()
            .unwrap_or(upload.path.as_str());
        if reserved.contains(first_segment) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "storage upload path `{}` conflicts with an existing API route segment",
                    upload.path
                ),
            ));
        }
    }

    Ok(())
}

pub(super) fn resolve_file_under_root(
    base_dir: &Path,
    relative_file: &str,
    label: &str,
) -> syn::Result<PathBuf> {
    let resolved = base_dir.join(relative_file);
    let canonical = resolved.canonicalize().map_err(|error| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to resolve {label} `{relative_file}`: {error}"),
        )
    })?;
    if !canonical.starts_with(base_dir) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} `{relative_file}` resolves outside the static dir"),
        ));
    }
    if !canonical.is_file() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} `{relative_file}` is not a file"),
        ));
    }
    Ok(canonical)
}

pub(super) fn parse_static_mode(value: &str) -> syn::Result<StaticMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "directory" => Ok(StaticMode::Directory),
        "spa" => Ok(StaticMode::Spa),
        _ => Err(syn::Error::new(
            Span::call_site(),
            "static mode must be `Directory` or `Spa`",
        )),
    }
}

pub(super) fn parse_static_cache_profile(value: &str) -> syn::Result<StaticCacheProfile> {
    match value.trim().to_ascii_lowercase().as_str() {
        "nostore" | "no_store" | "no-store" => Ok(StaticCacheProfile::NoStore),
        "revalidate" => Ok(StaticCacheProfile::Revalidate),
        "immutable" => Ok(StaticCacheProfile::Immutable),
        _ => Err(syn::Error::new(
            Span::call_site(),
            "static cache must be `NoStore`, `Revalidate`, or `Immutable`",
        )),
    }
}

pub(super) fn validate_api_name(value: &str, label: &str) -> syn::Result<()> {
    if value.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} cannot be empty"),
        ));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{label} `{value}` must use only ASCII letters, digits, `_`, or `-`"),
        ));
    }
    Ok(())
}
