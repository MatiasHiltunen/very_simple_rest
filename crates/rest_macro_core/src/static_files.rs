//! Compatibility facade for the Actix static-file adapter in `vsr-runtime`.

pub use vsr_runtime::static_files::{
    StaticCacheProfile, StaticMode, StaticMount, configure_static_mounts,
    configure_static_mounts_with_runtime,
};
