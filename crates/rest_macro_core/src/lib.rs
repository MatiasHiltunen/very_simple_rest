// Turso's connection futures require a deeper auto-trait evaluation stack.
#![recursion_limit = "256"]

pub mod auth;
pub mod authorization;
pub mod database;
pub mod db;
mod email;
pub mod errors;
pub mod logging;
pub mod runtime;
pub mod secret;
pub mod security;
pub mod static_files;
pub mod storage;
pub mod tls;

#[cfg(feature = "codegen")]
pub mod compiler;
