# Family App Example

This example is a single `.eon` family-management service that demonstrates the newer
authorization surface in one place.

It is intentionally opinionated:

- family membership drives baseline reads through relation-aware `exists` policies
- owner and delegate relationships drive sensitive updates through nested `any_of` / `exists`
- explicit built-in auth claims show typed `I64`, `String`, and `Bool` policy inputs
- runtime authorization scopes and templates are declared up front in `authorization`
- hybrid enforcement widens a few shared resources through runtime grants without weakening the
  static owner-scoped defaults

## What It Demonstrates

- keyed-map `.eon` syntax for both `resources` and `fields`
- explicit auth claim mapping via `security.auth.claims`
- relation-aware policy filters with `exists`
- nested boolean policy groups with `any_of` and `all_of`
- typed claim filters:
  - `claim.active_family_id` on family-scoped rows
  - `claim.preferred_household` on string-matched announcements
  - `claim.support_agent` on bool-matched care-plan visibility
- static authorization contracts with `scopes`, `permissions`, and `templates`
- runtime authorization management API at `/authz/runtime`
- hybrid enforcement on:
  - `ShoppingItem` at `Family` scope
  - `CalendarEvent` at `Household` scope

## Example Domain

- `Family`, `Household`, and `FamilyMember` model the baseline household graph
- `FamilyDelegate` models a parent delegating access to another adult
- `ChildProfile`, `CarePlan`, and `GuardianNote` show more sensitive child-care records
- `HouseholdAnnouncement` shows string-claim-based audience selection
- `ShoppingItem` and `CalendarEvent` start owner-scoped, then can widen through runtime grants

## Auth Claim Setup

The example assumes the built-in auth `user` table has three extra columns:

- `active_family_id INTEGER`
- `preferred_household TEXT`
- `is_support_agent INTEGER NOT NULL DEFAULT 0`

Apply the built-in auth schema first, then extend it:

```bash
mkdir -p examples/family_app/migrations
mkdir -p examples/family_app/var/data

vsr migrate auth --output examples/family_app/migrations/0000_auth.sql
sqlite3 examples/family_app/var/data/family_app.db < examples/family_app/migrations/0000_auth.sql
sqlite3 examples/family_app/var/data/family_app.db < examples/family_app/auth_extension.sql
```

Those columns are then mapped by `security.auth.claims` in
[family_app.eon](/Users/mh/Projects/very_simple_rest/examples/family_app/family_app.eon).

## Generate And Inspect

```bash
vsr authz explain --input examples/family_app/family_app.eon

vsr authz simulate \
  --input examples/family_app/family_app.eon \
  --resource ChildProfile \
  --action update \
  --user-id 7 \
  --role member \
  --row family_id=42 \
  --row primary_guardian_user_id=11 \
  --row created_by_user_id=11 \
  --related-row FamilyDelegate:family_id=42,primary_user_id=11,delegate_user_id=7

vsr authz simulate \
  --input examples/family_app/family_app.eon \
  --resource ShoppingItem \
  --action read \
  --role member \
  --row created_by_user_id=11 \
  --row family_id=42 \
  --hybrid-source item \
  --scoped-assignment template:Guardian@Family=42

vsr authz simulate \
  --input examples/family_app/family_app.eon \
  --resource CalendarEvent \
  --action read \
  --role member \
  --scope Household=12 \
  --hybrid-source collection_filter \
  --scoped-assignment template:HouseholdModerator@Household=12
```

## Runtime Assignment Flow

The example also includes a static authorization contract suitable for the runtime assignment API:

```bash
vsr migrate authz --output examples/family_app/migrations/0001_authz.sql

vsr --config examples/family_app/family_app.eon \
  --database-url sqlite:examples/family_app/var/data/family_app.db?mode=rwc \
  authz runtime create \
  --user-id 7 \
  --assignment template:Guardian@Family=42 \
  --created-by-user-id 1
```

That flow is what lets `ShoppingItem` and `CalendarEvent` widen through hybrid enforcement while
their static `.eon` policies stay owner-scoped by default.

## Current Limits

This example is realistic within the current engine, but it also reflects the current limits:

- family-local role names such as `guardian` or `caregiver` are modeled through runtime templates,
  not directly inside static row-policy predicates
- relation-aware policies are still equality-based
- hybrid collection reads still require one explicit scope per request

That makes the example useful as both a showcase and a map of where the current policy system
still stops.
