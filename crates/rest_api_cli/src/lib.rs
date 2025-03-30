pub mod commands;
pub mod error;

pub use error::{Error, Result};

// Re-export core functionality from rest_macro_core that might be useful
pub use rest_macro_core::auth;
