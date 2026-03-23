# Family App Example

This example is a policy-heavy `.eon` service that exercises the current authorization surface in
one place.

It demonstrates:

- explicit built-in auth claims with `I64`, `String`, and `Bool`
- relation-aware `exists` policies with nested `any_of` / `all_of`
- static authorization contracts with scopes, permissions, and templates
- runtime authorization management at `/authz/runtime`
- hybrid enforcement on shared resources

## Important Shape

This example uses the built-in auth system's normal coarse role, `user`, for resource access.
Family-specific roles such as guardian, caregiver, and child viewer are modeled through:

- `FamilyMember` rows
- `FamilyDelegate` rows
- runtime authorization templates

That keeps the example aligned with built-in registration, which creates `user` accounts by
default.

## Setup

This example now ships checked-in migrations for:

- the auth claim extension
- runtime authorization assignment tables
- the service schema

That means `vsr setup` works from this directory without manual SQLite bootstrapping.

```bash
cd examples/family_app

export JWT_SECRET=replace-me
export ADMIN_EMAIL=admin@example.com
export ADMIN_PASSWORD=change-me

vsr setup --non-interactive
```

The `migrations/` directory intentionally does not bundle `0000_auth.sql` or
`0001_auth_management.sql`, so `vsr setup` still applies the built-in auth/auth-management
migrations first and then applies the example-specific migrations afterward.

The auth extension adds these `user` columns:

- `active_family_id INTEGER`
- `preferred_household TEXT`
- `is_support_agent INTEGER NOT NULL DEFAULT 0`

Those are mapped by `security.auth.claims` in
[family_app.eon](/Users/mh/Projects/very_simple_rest/examples/family_app/family_app.eon).

## Browser Workspace

This example now ships a same-origin plain HTML, CSS, and JavaScript SPA in
[public/](/Users/mh/Projects/very_simple_rest/examples/family_app/public). The `.eon` config
mounts it at `/`, so once the generated family-app server is running you can open:

```text
http://127.0.0.1:8080/
```

The SPA covers the current real flow:

- register and log in with built-in auth
- create a family and add family members immediately
- inspect visible family, member, and household rows
- patch `active_family_id` and `preferred_household` through the admin API
- manage runtime assignments and inspect their audit trail
- create and use shared shopping and calendar resources

It is intentionally demo-oriented rather than exhaustive: it focuses on the onboarding, claim
activation, and hybrid runtime-grant paths that are hardest to understand from curl examples
alone.

## Verify The Policy Model

```bash
vsr authz explain --input examples/family_app/family_app.eon

vsr authz simulate \
  --input examples/family_app/family_app.eon \
  --resource ChildProfile \
  --action update \
  --user-id 7 \
  --role user \
  --row family_id=42 \
  --row primary_guardian_user_id=11 \
  --row created_by_user_id=11 \
  --related-row FamilyDelegate:family_id=42,primary_user_id=11,delegate_user_id=7

vsr authz simulate \
  --input examples/family_app/family_app.eon \
  --resource ShoppingItem \
  --action read \
  --role user \
  --row created_by_user_id=11 \
  --row family_id=42 \
  --hybrid-source item \
  --scoped-assignment template:Guardian@Family=42
```

## API Bootstrap Flow

The example now supports this real HTTP flow:

1. A normal registered `user` can create a `Family`.
2. The created row is immediately readable by its owner because `Family.read` now includes
   `owner_user_id=user.id`.
3. That guardian can immediately create `FamilyMember` rows for self and other registered users,
   because `FamilyMember.create.require` checks the posted `family_id` against a `Family` row
   owned by `user.id`.
4. An admin can then set that user's `active_family_id` through the built-in auth admin API for
   later family-scoped resources such as `Household`.

The key admin bootstrap call is:

```bash
curl -X PATCH http://127.0.0.1:8080/api/auth/admin/users/<guardian_user_id> \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
        "claims": {
          "active_family_id": 42,
          "preferred_household": "helsinki-household"
        }
      }'
```

`PATCH /api/auth/admin/users/{id}` now accepts configured claim updates from
`security.auth.claims`, so this example can be exercised through HTTP instead of direct SQLite
edits.

## Runtime Assignment Flow

The example also includes a static authorization contract suitable for runtime assignment
management:

```bash
vsr --config examples/family_app/family_app.eon \
  --database-url sqlite:examples/family_app/var/data/family_app.db?mode=rwc \
  authz runtime create \
  --user-id 7 \
  --assignment template:Guardian@Family=42 \
  --created-by-user-id 1
```

That is what widens `ShoppingItem` and `CalendarEvent` through hybrid enforcement while their
static `.eon` policies stay owner-scoped by default.

## Current Limit

The remaining bootstrap limitation is now narrower.

Family membership onboarding works through `.eon` alone, but activating `active_family_id` for
later claim-scoped resources still requires an admin-side claim update. That is because built-in
auth claims are manageable through the admin API, not self-managed by end users.
