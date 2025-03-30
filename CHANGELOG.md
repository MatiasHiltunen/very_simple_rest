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