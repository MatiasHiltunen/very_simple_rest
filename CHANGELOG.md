# Changelog

All notable changes to the `very_simple_rest` project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned Features

- Full PostgreSQL support
- Full MySQL support
- Swagger/OpenAPI documentation generation
- Advanced validation rules for input data
- Multiple roles per user
- Password reset and account recovery
- Email verification
- Session management improvements
- Async token verification
- Rate limiting and security enhancements

## [0.1.11] - 2026-04-15

### Added

- Typed temporal inputs in the generated TypeScript client surface
- Explicit public read access controls for generated/public catalog surfaces
- Feature-gated S3 backup transfer backend selection for the CLI
- An `mdBook` docs shell that includes the generated `.eon` reference directly

### Changed

- `.eon` validation docs and starter surfaces now consistently use `garde` terminology and examples
- OpenAPI output now documents the create `Location` header
- Bool handling is normalized more consistently across supported database backends
- Maintained examples and docs entry points now align with the current contract-first CLI workflow

### Fixed

- Windows TypeScript client self-test execution and related example-client regressions
- `sqlx-mysql` RSA auth handling for compatible MySQL connections
- The family app shopping-item toggle payload flow
- Dependency vulnerability updates in the published CLI surface

## [0.1.5] - 2026-04-02

### Added

- Typed `SecretRef` support throughout `.eon`, including auth, database, mail, and Infisical-backed secret scaffolding
- Structured JWT configuration under `security.auth.jwt` with algorithm selection, `kid`-based verification, asymmetric signing, and rotation support
- `vsr check --strict` compiler diagnostics for authz/index/build-path/storage issues
- Generated-code quality gates with warning-clean and `clippy -D warnings` checks plus emitted-code snapshots
- CMS local site-preview routes so the example can open local previews without fake published URLs

### Changed

- `vsr build` and `vsr clean` now resolve outputs and cache paths relative to the input `.eon` service by default, with `.eon` artifact-path config and cleanup strategy support
- Production secret tooling now prefers runtime-resolved secret bindings, `*_FILE` inputs, and Infisical Agent scaffolding over inline `.env` secrets
- Generated server code now tracks the actual `.eon` feature surface more tightly, reducing dead helper emission and lint noise
- `examples/cms` now ships with a cleaner local preview workflow, better studio UX, and safer build defaults

### Fixed

- Generated storage setup code no longer shadows `storage()` and break example builds
- Emitted server builds now stay warning-clean across representative `.eon` fixtures
- JWT key material now reloads correctly from env/file sources during rotation instead of sticking to stale cached values
- Service-relative build outputs prevent stray `api`, `api.bundle`, and `.vsr-build` artifacts from landing in the current shell directory by default

## [0.1.4] - 2026-03-28

### Added

- Native `vsr serve` for running `.eon` services directly without generating a Rust project first
- First-class `.eon` schema support for JSON, list, object, enum, mixin, many-to-many, response-context, computed-field, transform, and declarative action features
- Storage backends, upload endpoints, and local S3-compatible mounts for development workflows
- `vsr server expand` to inspect fully expanded generated Rust source from a `.eon` service
- Reusable server build cache plus `vsr clean` to clear cached generated build projects and Cargo artifacts
- `.eon` build profile settings for release LTO, codegen units, debug-symbol stripping, and optional local `target-cpu=native`
- Repository `LICENSE` and `CONTRIBUTING.md` files aligned with MIT publication metadata

### Changed

- `vsr build` now streams cargo progress and reuses a stable generated-project cache between builds
- `vsr init` now creates local `.eon`-first starters instead of relying on fragile template cloning
- `vsr setup` now bootstraps `.env` and local TLS before database setup and preserves existing generated secrets on refresh
- The `examples/cms` example now ships as an in-repo modern CMS backend and studio using local S3-compatible uploads

### Fixed

- TursoLocal now reuses connections instead of reconnecting for every query
- Setup no longer breaks encrypted local Turso databases by rotating secrets during `.env` refresh
- Migration rendering now handles self-references and mutual SQLite/TursoLocal foreign-key cycles during setup
- Static precompressed asset handling, emitted-server expansion on normal runtime paths, and server-build progress reporting were tightened across the CLI

## [0.1.0] - 2025-03-30

### Added

- Initial release of the `very_simple_rest` framework
- Core REST API generation via `RestApi` derive macro
- JWT-based authentication system
- Role-Based Access Control (RBAC) for endpoints
- Automatic database schema generation
- Relationship handling with nested routes
- Support for SQLite database (with PostgreSQL and MySQL planned)
- Admin user management via environment variables
- CLI tool for admin setup and database management
- Example application in `examples/demo`
- Static file serving for frontend integration
- Reusable user authentication endpoints (register, login, me)
- Comprehensive README with usage examples
- Support for singular route paths (`/post` instead of `/posts`)

### Fixed

- SQLite compatibility issues with boolean queries
- Admin user creation and verification 
- Path inconsistencies in static file serving
- Macro expansion issues in demo application
- Module visibility and import organization
- Workspace dependency management
- Compilation errors in CLI tool for rand crate

### Changed

- Restructured to use a workspace with multiple crates
- Reorganized module hierarchy for better maintainability
- Improved error handling and user feedback
- Enhanced documentation with examples
- Expanded environment variable configuration
- Unified re-exports in the prelude module 
