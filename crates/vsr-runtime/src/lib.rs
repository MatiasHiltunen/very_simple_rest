//! # vsr-runtime
//!
//! Framework-neutral runtime trait seams for VSR services.
//!
//! This crate defines the *contracts* that all runtime implementations must
//! satisfy. Default implementations (actix HTTP server, builtin auth, SQLite
//! rate limiter, local-FS storage) live behind feature flags. Alternatives
//! (axum HTTP server, OPA authz engine, Redis rate limiter, S3 storage)
//! plug in by implementing the same traits behind their own features.
//!
//! Framework types (`actix_web::HttpRequest`, `axum::Router`, sqlx
//! `Pool<DB>`, …) stay in feature-gated adapter modules. Only VSR-owned types
//! appear in trait signatures.
//!
//! ## Crate layout
//!
//! | Module | Defines |
//! |---|---|
//! | [`http`] | [`http::HttpServer`], [`http::RouteRegistry`], [`http::RequestContext`], [`http::MiddlewareConfig`] |
//! | [`auth`] | [`auth::AuthProvider`], [`auth::KeyProvider`], [`auth::PasswordPolicy`], [`auth::Mailer`] |
//! | [`authz`] | [`authz::AuthzEngine`], [`authz::PolicyDecision`] |
//! | [`storage`] | [`storage::ObjectStorage`], [`storage::StorageKey`] |
//! | [`rate_limit`] | [`rate_limit::RateLimitStore`], [`rate_limit::RateLimitDecision`] |
//! | [`security`] | Framework-neutral request and browser security settings |
//! | [`config_secret`] | Serializable secret references for service configuration |
//! | [`static_config`] | Framework-neutral static mount settings |
//! | [`runtime`] | Shared compression settings |
//! | `static_files` | Feature-gated Actix static-file adapter |
//! | [`audit`] | [`audit::AuditSink`], [`audit::AuditEvent`] |
//! | [`tls`] | TLS path resolution and optional Rustls certificate loading |
//!
//! ## Design rules
//!
//! 1. Traits use `async fn` (stable, edition 2024). No `async_trait` macro.
//! 2. All trait objects are `Send + Sync + 'static`.
//! 3. Each trait module exposes a `testing` submodule (or points to
//!    `vsr_core::testing`) with zero-dependency fakes for unit tests.
//! 4. Adding a new runtime feature means: define trait → add fake →
//!    add default impl behind a feature flag → add parity test.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

pub mod audit;
pub mod auth;
pub mod authz;
pub mod config_secret;
pub mod field;
pub mod http;
pub mod model;
pub mod native_resource;
pub mod native_service;
pub mod rate_limit;
pub mod resource;
pub mod runtime;
pub mod security;
pub mod static_config;
#[cfg(feature = "static-actix")]
pub mod static_files;
pub mod storage;
pub mod tls;
