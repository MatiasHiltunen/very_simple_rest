// Architecture migration note: `auth` and `authorization` are public
// compatibility facades. Keep these module paths stable while internals move.
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
