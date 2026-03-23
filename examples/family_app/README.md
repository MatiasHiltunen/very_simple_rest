# Family App Example

This example is a policy-heavy `.eon` service that exercises the current authorization surface in
one place.

It demonstrates:

- relation-aware `exists` policies with nested `any_of` / `all_of`
- `create.require` checks against posted input fields
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
default, and it keeps permissions out of the built-in auth `user` row.

## Setup

This example now ships checked-in migrations for:

- runtime authorization assignment tables
- the service schema

That means `vsr setup` works from this directory without manual SQLite bootstrapping or any
hand-written auth SQL.

```bash
cd examples/family_app

export JWT_SECRET=replace-me
export ADMIN_EMAIL=admin@example.com
export ADMIN_PASSWORD=change-me

vsr setup --non-interactive
```

The `migrations/` directory intentionally does not bundle `0000_auth.sql` or
`0001_auth_management.sql`. `vsr setup` applies those built-in auth/auth-management migrations
first, then applies the example-specific runtime-authz and family-schema migrations.

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
- manage runtime assignments and inspect their audit trail
- create and use shared shopping and calendar resources

It is intentionally demo-oriented rather than exhaustive: it focuses on the onboarding,
claim-free relation-policy and hybrid runtime-grant paths that are hardest to understand from curl
examples alone.

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
4. That guardian can create `Household`, `ShoppingItem`, `CalendarEvent`, `CarePlan`, and
   `GuardianNote` rows directly from the selected family/household in the request payload, because
   those resources now use relation-aware `create.require` checks instead of claim-scoped inserts.
5. An admin can then grant runtime templates like `Caregiver@Family=42` to widen access to shared
   resources without changing the built-in auth account shape.

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

That is what widens `ShoppingItem`, `CalendarEvent`, `CarePlan`, and `GuardianNote` through hybrid
enforcement while their static `.eon` policies stay author/creator-scoped by default.

## Current Limit

The remaining limitation is role semantics inside row policies.

This example stores `role_label` and `is_child` on `FamilyMember`, but the current policy language
still cannot compare row fields to literals like `"guardian"` or `"child"` directly. That is why
the example uses:

- relation-aware containment checks for baseline family access
- runtime templates for elevated capabilities

instead of deriving every permission strictly from `FamilyMember.role_label`.
