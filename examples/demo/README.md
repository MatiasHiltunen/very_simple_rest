# REST Macro Demo

This derive-based demo now uses the same modern runtime pieces that the `.eon` server flow uses:
local Turso bootstrap, explicit auth settings, and the shared security middleware instead of a
hand-written permissive CORS setup.

## Features Demonstrated

- derive-based CRUD generation
- built-in auth with JWT issuer/audience/TTL settings
- local Turso runtime via `connect_with_config`
- auth rate limits, request-size limits, CORS, trusted proxies, and security headers
- nested routes and a small frontend client

## Running The Demo

```bash
mkdir -p migrations
mkdir -p var/data

vsr migrate auth --output migrations/0000_auth.sql
vsr migrate derive --input examples/demo/src --exclude-table user --output migrations/0001_resources.sql
vsr --database-url sqlite:var/data/demo.db?mode=rwc migrate apply --dir migrations

export JWT_SECRET=change-me
# Optional:
# export CORS_ORIGINS=http://localhost:3000
# export TRUSTED_PROXIES=127.0.0.1,::1
# export TURSO_ENCRYPTION_KEY=64_hex_characters_here

cargo run -p demo
```

The `user` table is excluded from the derive migration because the built-in auth migration owns it.

## Runtime Notes

- the demo bootstraps `var/data/demo.db` as a local Turso database by default
- if `TURSO_ENCRYPTION_KEY` is set before startup, the same path is opened with local Turso encryption
- `CORS_ORIGINS` and `TRUSTED_PROXIES` augment the compiled defaults in `src/main.rs`
- the frontend is served from the demo package itself, so `cargo run -p demo` works from the repo root

## Testing The API

Open the web client at `http://127.0.0.1:8080`, or call the API directly:

```bash
curl -X POST http://127.0.0.1:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

curl -X POST http://127.0.0.1:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'
```
