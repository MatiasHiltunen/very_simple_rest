//! # vsr-core
//!
//! Foundational traits, error types, and primitive abstractions for the VSR
//! workspace. Every other VSR crate depends on this one; it deliberately
//! depends on nothing external by default.
//!
//! ## What lives here
//!
//! | Module | Purpose |
//! |---|---|
//! | [`error`] | [`VsrError`], [`Diagnostic`], [`Span`], [`ErrorCode`] |
//! | [`secret`] | [`SecretRef`], [`SecretProvider`] trait, [`EnvSecretProvider`] |
//! | [`db`] | [`Dialect`], [`DbPool`] trait, [`DbCapabilities`] |
//! | [`clock`] | [`Clock`] + [`IdGenerator`] traits, [`SystemClock`] |
//! | [`testing`] | Fakes for all traits (`StaticSecretProvider`, `MockClock`, …) |
//!
//! ## What does NOT live here
//!
//! - HTTP, auth, authz, storage — those are in `vsr-runtime`.
//! - The parser, codegen, IR — those are in `vsr-codegen`.
//! - CLI logic — that is in `vsr-cli`.
//! - Backup, secrets ops, TLS cert gen — those are in `vsr-ops`.
//!
//! ## Design rules
//!
//! 1. No new dependency without a feature flag and a rationale comment.
//! 2. Traits use `async fn` (stable since Rust 1.75 / edition 2024). No
//!    `async_trait` macro.
//! 3. Every trait has at least one fake in [`testing`].
//! 4. `#[non_exhaustive]` on all public enums and error structs.

#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::unwrap_in_result)]
#![warn(clippy::pedantic)]
// Allow a few pedantic lints that produce noise without benefit here.
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]

pub mod clock;
pub mod db;
pub mod error;
pub mod secret;
pub mod testing;

// Convenience re-exports of the most commonly imported items.
pub use error::{Diagnostic, ErrorCode, Severity, Span, VsrError, VsrResult};
pub use secret::SecretRef;
