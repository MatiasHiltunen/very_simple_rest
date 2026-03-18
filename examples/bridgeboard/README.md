# Bridgeboard

Bridgeboard is a cross-border collaboration platform example for education and industry. The API
is defined entirely in [bridgeboard.eon](./bridgeboard.eon), and the same generated server also
serves the browser client from [`public/`](./public/).

It demonstrates:

- Public catalog reads for organizations, interest signals, and thesis topics
- Owner-scoped collaboration requests with admin bypass for review
- Built-in auth with email verification, password reset, account portal, and admin dashboard
- Encrypted local Turso defaults with a static SPA served by the generated binary

## Quick Start

Run everything from `examples/bridgeboard/`.

```bash
export JWT_SECRET="$(openssl rand -hex 32)"
export TURSO_ENCRYPTION_KEY="$(openssl rand -hex 32)"
export VSR_AUTH_EMAIL_CAPTURE_DIR=".emails"
mkdir -p .emails

vsr setup --non-interactive
vsr create-admin
vsr build bridgeboard.eon --force
./bridgeboard
```

Open `http://127.0.0.1:8080`.

## Email Delivery

The example is configured for Resend in `.eon`:

```eon
email: {
    from_email: "noreply@example.com"
    from_name: "Bridgeboard"
    public_base_url: "http://127.0.0.1:8080"
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
3. Update `public_base_url` if the app is not running on `http://127.0.0.1:8080`.

If you prefer SMTP/`lettre`, swap the provider block in `bridgeboard.eon` to:

```eon
provider: {
    kind: Smtp
    connection_url_env: "SMTP_CONNECTION_URL"
}
```

## Built-In Account Management

Bridgeboard enables the built-in HTML pages as part of the example:

- Account portal: `http://127.0.0.1:8080/api/auth/portal`
- Admin dashboard: `http://127.0.0.1:8080/api/auth/admin`

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
