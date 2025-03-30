# REST API CLI Tool

A command-line interface for managing `very_simple_rest` API deployments.

## Overview

This CLI tool simplifies the setup and management of `very_simple_rest` API applications, with a focus on secure user management and configuration.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/MatiasHiltunen/very_simple_rest.git
cd very_simple_rest

# Build the CLI tool
cargo build --release -p rest_api_cli

# Run the CLI
./target/release/vsr --help
```

### Cargo Install (Coming Soon)

```bash
cargo install vsr
```

## Commands

### Setup

Initialize a new API deployment with interactive prompts:

```bash
vsr setup
```

This command will:
1. Check your database connection
2. Create necessary tables if they don't exist
3. Help you create an admin user
4. Generate a `.env` template file

For non-interactive setup (e.g., in CI/CD pipelines):

```bash
vsr setup --non-interactive
```

### Create Admin

Create a new admin user:

```bash
# Interactive mode with prompts
vsr create-admin

# Non-interactive mode with parameters
vsr create-admin --email admin@example.com --password secure_password
```

### Check Database

Verify database connection and schema:

```bash
vsr check-db
```

This will:
- Test the database connection
- Check if required tables exist
- Count existing users and admins
- Provide recommendations based on findings

### Generate .env Template

Create a template `.env` file with common configuration options:

```bash
vsr gen-env
```

## Environment Variables

The CLI tool respects the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | `sqlite:app.db?mode=rwc` |
| `ADMIN_EMAIL` | Default admin email address | None |
| `ADMIN_PASSWORD` | Default admin password | None |
| `JWT_SECRET` | Secret key for JWT tokens | Auto-generated |

## Examples

### Complete Setup Example

```bash
# Set database URL
export DATABASE_URL="sqlite:my_app.db?mode=rwc"

# Initialize the application
vsr setup

# Check database status
vsr check-db
```

### Creating Admin in CI/CD Pipeline

```bash
# Set required variables
export DATABASE_URL="sqlite:app.db?mode=rwc"
export ADMIN_EMAIL="admin@example.com"
export ADMIN_PASSWORD="secure_random_password"

# Create admin non-interactively
vsr create-admin --email $ADMIN_EMAIL --password $ADMIN_PASSWORD
```

## Security Best Practices

- Never store admin credentials in version control
- Use environment variables or a secure secret management system
- Change default admin passwords immediately in production
- Use strong, unique passwords
- Consider setting up a dedicated admin user for each team member

## Troubleshooting

### Common Issues

**Database Connection Errors**
- Verify the database URL format
- Ensure the database server is running
- Check file permissions for SQLite databases

**Admin Creation Fails**
- Ensure both email and password are provided
- Verify the database is accessible and writable
- Check if an admin with the same email already exists

## Related Documentation

- [Main Project README](../../README.md)
- [API Documentation](../../docs/api.md)
- [Environment Configuration](../../docs/configuration.md) 