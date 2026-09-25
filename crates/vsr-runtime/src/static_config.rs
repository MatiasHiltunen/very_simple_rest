//! Framework-neutral static-file mount configuration.

/// How a static mount handles unmatched paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticMode {
    /// Serve only existing files and configured index files.
    Directory,
    /// Serve a fallback document for browser navigation paths.
    Spa,
}

/// Cache-Control policy applied to static responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticCacheProfile {
    /// Prevent response caching.
    NoStore,
    /// Allow caching with revalidation.
    Revalidate,
    /// Cache versioned assets for a year.
    Immutable,
}

/// A static directory mounted at an HTTP path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticMount {
    /// Public URL prefix.
    pub mount_path: &'static str,
    /// Source directory relative to the service bundle.
    pub source_dir: &'static str,
    /// Directory resolved at build or configuration time.
    pub resolved_dir: &'static str,
    /// Directory or SPA serving mode.
    pub mode: StaticMode,
    /// Optional index file for directory requests.
    pub index_file: Option<&'static str>,
    /// Optional SPA fallback file.
    pub fallback_file: Option<&'static str>,
    /// Response caching policy.
    pub cache: StaticCacheProfile,
}
