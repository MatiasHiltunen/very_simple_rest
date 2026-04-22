# Bridgeboard

Bridgeboard is a cross-border collaboration platform example for education and industry. The API
is defined entirely in [bridgeboard.eon](./bridgeboard.eon), and `vsr serve bridgeboard.eon`
serves the browser client from [`public/`](./public/).

It demonstrates:

- Public catalog reads for organizations, interest signals, and thesis topics
- Owner-scoped collaboration requests with admin bypass for review
- Built-in auth with email verification, password reset, account portal, and admin dashboard
- Encrypted local Turso defaults with a static SPA and generated browser client

## Quick Start

Run everything from `examples/bridgeboard/`.

```bash
export JWT_SECRET="$(openssl rand -hex 32)"
export TURSO_ENCRYPTION_KEY="$(openssl rand -hex 32)"
export ADMIN_EMAIL=admin@example.com
export ADMIN_PASSWORD=password123
export VSR_AUTH_EMAIL_CAPTURE_DIR=".emails"
mkdir -p .emails

vsr setup --non-interactive
vsr serve bridgeboard.eon
```

Open `https://127.0.0.1:8443` and accept the local dev certificate warning once.

`vsr setup` prepares `.env`, generates local TLS certs, applies the schema, and creates the admin
account from `ADMIN_EMAIL` / `ADMIN_PASSWORD`. The checked-in SPA imports the generated browser
client from `public/gen/client`, so `vsr serve` is enough to get the example running.

If you change the schema and want to refresh the checked-in browser client manually, run:

```bash
vsr client ts --input bridgeboard.eon --force
```

The example also enables `clients.ts.automation.on_build`, so `vsr build bridgeboard.eon`
refreshes the client automatically and writes a self-test report to `reports/client-self-test.json`.

## Email Delivery

The example is configured for Resend in `.eon`:

```eon
email: {
    from_email: "noreply@example.com"
    from_name: "Bridgeboard"
    provider: {
        kind: Resend
        api_key_env: "RESEND_API_KEY"
    }
}
```

For local development, `VSR_AUTH_EMAIL_CAPTURE_DIR` is the simplest path. Verification and reset
emails are written to JSON files in that directory instead of being sent.

For real delivery:

1. Set `RESEND_API_KEY`.
2. Replace `from_email` with a sender that your provider accepts.
3. If auth emails need a fixed public origin outside request scope, set `public_base_url` to your published HTTPS site.

If you prefer SMTP/`lettre`, swap the provider block in `bridgeboard.eon` to:

```eon
provider: {
    kind: Smtp
    connection_url_env: "SMTP_CONNECTION_URL"
}
```

## Built-In Account Management

Bridgeboard enables the built-in HTML pages as part of the example:

- Account portal: `https://127.0.0.1:8443/api/auth/portal`
- Admin dashboard: `https://127.0.0.1:8443/api/auth/admin`

The browser client also exposes:

- Register, log in, log out
- Resend verification email
- Request password reset email
- Submit collaboration requests
- Review the request pipeline as an admin

## Demo Data

After signing in as an admin, use the **Load demo dataset** button in the admin studio. It seeds
organizations, interest signals, and thesis topics through the generated API itself, without any
additional backend code or seed script.
