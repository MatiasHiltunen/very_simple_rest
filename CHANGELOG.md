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
