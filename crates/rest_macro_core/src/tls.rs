//! Compatibility facade for TLS configuration and certificate loading.
//! The implementation lives in `vsr-runtime`.

pub use vsr_runtime::tls::{
    DEFAULT_TLS_CERT_PATH, DEFAULT_TLS_CERT_PATH_ENV, DEFAULT_TLS_KEY_PATH,
    DEFAULT_TLS_KEY_PATH_ENV, ResolvedTlsPaths, TlsConfig, load_rustls_server_config,
    resolve_tls_config, resolve_tls_paths,
};
