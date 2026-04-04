pub mod commands;
pub mod error;

pub use error::{Error, Result};

// Re-export core functionality from rest_macro_core that might be useful
pub use rest_macro_core::auth;

pub mod test_support {
    use std::sync::{Mutex, OnceLock};

    pub fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }
}
