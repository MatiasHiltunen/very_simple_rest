# Fine-Grained Policy Example

This example is a relation-heavy `.eon` service focused on portable row-policy enforcement rather
than raw CRUD breadth. It models an operations control plane where some resources are tenant-wide
readable but owner-scoped for writes, while others are strictly self-scoped end to end.

It demonstrates:

- tenant-scoped shared reads with `claim.tenant_id`
- create-time assignments such as `owner_user_id=user.id`
- different policy strictness per resource
- `admin_bypass: true` and `admin_bypass: false`
- nested relations across workspaces, projects, incidents, runbooks, and deployment windows

## Resources

- `workspace`, `project`, `runbook`, `escalation_rule`, `incident`, `incident_note`, and
  `deployment_window` are tenant-readable but owner-scoped for updates and deletes.
- `on_call_subscription`, `time_entry`, and `audit_export` are fully self-scoped and disable
  admin bypass.

## Auth Assumption

The policies use `claim.tenant_id`, so the authenticated user must receive a numeric `tenant_id`
claim. Built-in auth can do that after the auth schema is extended:

```bash
vsr migrate auth --output migrations/0000_auth.sql
sqlite3 app.db < migrations/0000_auth.sql
sqlite3 app.db < examples/fine_grained_policies/auth_extension.sql
```

After that, any numeric `tenant_id` value stored on the built-in `user` row will be emitted as a
JWT claim on login.

For resources that keep `admin_bypass: true`, the generated create DTOs also expose optional
claim-backed fields such as `tenant_id`. That means an admin using `/docs` can still create those
resources by supplying `tenant_id` explicitly even if the admin token itself does not carry the
claim. Resources with `admin_bypass: false` still require the claim on the token.

## Generate And Apply

```bash
mkdir -p examples/fine_grained_policies/migrations

vsr migrate generate \
  --input examples/fine_grained_policies/ops_control.eon \
  --output examples/fine_grained_policies/migrations/0001_ops_control.sql

vsr --database-url sqlite:examples/fine_grained_policies/app.db?mode=rwc \
  migrate apply \
  --dir examples/fine_grained_policies/migrations
```

## Seed Data

The included seed script loads deterministic domain data for two tenants. It assumes auth user ids
such as `1`, `2`, `3`, and `4` already exist and that those users are assigned matching
`tenant_id` values in the built-in auth table.

```bash
sqlite3 examples/fine_grained_policies/app.db < examples/fine_grained_policies/seed.sql
```

## Server Generation

This example also works with the new server CLI flow:

```bash
vsr server emit \
  --input examples/fine_grained_policies/ops_control.eon \
  --output-dir generated-ops-control \
  --with-auth
```

That generates a runnable Actix project plus explicit SQL migrations. The only manual follow-up is
adding the auth claim extension from `auth_extension.sql` before relying on tenant-based login
claims.
