# very_simple_rest Starter Template

This template keeps the derive-based resource flow, but it now uses the current runtime defaults:
local Turso bootstrap through `connect_with_config`, built-in auth with explicit auth settings, and
the shared security middleware for request limits, CORS, trusted proxies, and response headers.

## Included Runtime Defaults

- local Turso database bootstrapped at `var/data/app.db`
- optional encrypted local Turso if `TURSO_ENCRYPTION_KEY` is set before startup
- built-in auth with JWT issuer/audience/TTL settings
- rate-limited `/api/auth/register` and `/api/auth/login`
- CORS origins overridable through `CORS_ORIGINS`
- trusted proxies overridable through `TRUSTED_PROXIES`

## Running The Template

```bash
mkdir -p migrations
mkdir -p var/data

vsr migrate auth --output migrations/0000_auth.sql
vsr migrate derive --input src --exclude-table user --output migrations/0001_resources.sql
vsr --database-url sqlite:var/data/app.db?mode=rwc migrate apply --dir migrations

cp .env.example .env
cargo run
```

The `user` table is excluded from the derive migration because the built-in auth migration owns it.

## Environment Variables

- `JWT_SECRET` is required for stable auth tokens across restarts
- `BIND_ADDR` changes the listen address, defaulting to `127.0.0.1:8080`
- `TURSO_ENCRYPTION_KEY` enables encrypted local Turso bootstrap when present
- `CORS_ORIGINS` appends comma-separated frontend origins to the built-in local default
- `TRUSTED_PROXIES` adds comma-separated proxy IPs for forwarded client IP handling

## Testing The API

Open the frontend at `http://127.0.0.1:8080`, or call the API directly:

```bash
curl -X POST http://127.0.0.1:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

curl -X POST http://127.0.0.1:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'
```
