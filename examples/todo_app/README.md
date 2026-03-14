# Todo App Example

This example shows the `.eon`-only workflow end to end:

- built-in auth routes for registration and login
- owner-scoped todo data for normal users
- admin access to all todos through `admin_bypass: true`
- a small static client app served by the generated server itself
- local Turso storage through `database.engine = TursoLocal`

The API resource is intentionally small: one `Todo` table with `title`, `completed`, and
`user_id`. Normal users only see and mutate their own rows. Admin users can see and manage
everything.

## Start The Example

```bash
vsr server emit \
  --input examples/todo_app/todo_app.eon \
  --output-dir examples/todo_app/generated-server \
  --with-auth \
  --force

cd examples/todo_app/generated-server
mkdir -p var/data

sqlite3 var/data/todo_app.db < migrations/0000_auth.sql
sqlite3 var/data/todo_app.db < migrations/0001_service.sql

vsr --config todo_app.eon create-admin \
  --email admin@example.com \
  --password change-me

cp .env.example .env
cargo run
```

Then open `http://127.0.0.1:8080`.

## How To Test The Access Rules

1. Log in as the admin account created through `vsr create-admin`.
2. Create a few todos as admin. The admin can list, edit, and delete every todo row.
3. Register a normal user from the browser client and log in.
4. Create todos as that user. The list view now only returns that user’s own rows.
5. Log back in as admin to confirm the admin still sees the full dataset.

## Optional Environment Overrides

- `JWT_SECRET` for stable auth tokens across restarts
- `CORS_ORIGINS` if you want to test the API from another frontend origin
- `TRUSTED_PROXIES` if you run the generated server behind a local proxy

## Files

- `todo_app.eon` defines the API, security defaults, database engine, row policies, and static SPA mount
- `public/index.html` is the browser client
- `public/app.js` contains the minimal client logic for auth and todo CRUD
