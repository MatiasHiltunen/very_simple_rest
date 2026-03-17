# Todo App Example

This example shows the `.eon`-only workflow end to end:

- built-in auth routes for registration and login
- browser-friendly auth through same-origin session cookies plus CSRF protection
- owner-scoped todo data for normal users
- admin access to all todos through `admin_bypass: true`
- a small static client app served by the generated server itself
- local Turso storage through `database.engine = TursoLocal`

The API resource is intentionally small: one `Todo` table with `title`, `completed`, and
`user_id`. Normal users only see and mutate their own rows. Admin users can see and manage
everything.

## Start The Example

```bash
cd examples/todo_app

vsr build todo_app.eon --force
cp todo-app.bundle/.env.example .env

# Set these in `.env` or export them before the next steps.
export JWT_SECRET=replace-me
export TURSO_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

export ADMIN_EMAIL=admin@example.com
export ADMIN_PASSWORD=change-me
vsr setup --non-interactive

./todo-app
```

Then open `http://127.0.0.1:8080`.

`vsr setup` auto-discovers `todo_app.eon` in the current directory, applies the built-in auth
schema, and initializes `var/data/todo_app.db`. `vsr build todo_app.eon` writes the binary to
`./todo-app` and exports the runtime assets to `./todo-app.bundle/`.

The browser client uses cookie-based auth for the session. It no longer stores bearer tokens in
`localStorage`; instead the server issues an `HttpOnly` session cookie and a CSRF cookie for
unsafe requests.

## How To Test The Access Rules

1. Log in as the admin account created through `vsr create-admin`.
2. Create a few todos as admin. The admin can list, edit, and delete every todo row.
3. Register a normal user from the browser client and log in.
4. Create todos as that user. The list view now only returns that user’s own rows.
5. Log back in as admin to confirm the admin still sees the full dataset.

## Optional Environment Overrides

- `JWT_SECRET` is required because built-in auth will not start without it
- `TURSO_ENCRYPTION_KEY` is required because this example uses encrypted local Turso
- `CORS_ORIGINS` if you want to test the API from another frontend origin
- `TRUSTED_PROXIES` if you run the generated server behind a local proxy

## Files

- `todo_app.eon` defines the API, security defaults, database engine, row policies, and static SPA mount
- `public/index.html` is the browser client
- `public/app.js` contains the minimal client logic for auth and todo CRUD
