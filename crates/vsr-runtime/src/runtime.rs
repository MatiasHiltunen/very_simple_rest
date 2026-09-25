//! Framework-neutral runtime settings for service adapters.

#[cfg(feature = "actix-security")]
pub mod actix;

/// HTTP compression settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompressionConfig {
    /// Whether dynamic responses are compressed.
    pub enabled: bool,
    /// Whether static serving may select precompressed `.br` or `.gz` files.
    pub static_precompressed: bool,
}

/// Settings shared by service runtime adapters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeConfig {
    /// HTTP compression settings.
    pub compression: CompressionConfig,
}
