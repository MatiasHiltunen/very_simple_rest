# Authorization Roadmap

This document defines the path from today's simple `.eon` row policies to a correct, extensible authorization system that can still keep default app configuration small.

## Goals

- Keep the current `.eon` experience simple for normal CRUD apps.
- Support advanced authorization without forcing every app into an enterprise policy DSL.
- Make correctness the priority through typed validation, deterministic evaluation, explainability, and staged rollout.
- Separate request authorization from governance and access lifecycle concerns.

## Design Direction

The long-term model should have three layers:

1. Static contract in `.eon`
- Resource schema
- Action vocabulary
- Field mutability and sensitivity classes
- Scope types
- Permission templates
- Hard safety invariants
- Which authorization features are allowed to be runtime-managed

2. Runtime policy data
- Memberships
- Scoped role assignments
- Permission bundles
- Exemptions
- Temporary activations
- Approval state
- Policy bundle versions

3. Optional generated policy-management API
- CRUD and workflow endpoints for runtime policy data
- Validation against the static `.eon` contract
- Audit-friendly activation and rollback

The key rule is: runtime policy may decide access within the static contract, but it must not redefine the API contract itself.

## Modes

### Static

This is today's default mode.

- Authorization comes entirely from `.eon`
- Policies are compiled into generated handlers
- Best for small apps and low-ops deployments

### Hybrid

This should become the default path for serious apps.

- `.eon` defines scopes, permissions, templates, and invariants
- Runtime manages memberships, scoped assignments, exemptions, and temporary access
- Request evaluation still uses the same typed authorization engine

### Managed

This is the enterprise mode.

- `.eon` defines the contract and management surface
- Runtime stores versioned policy bundles and activation state
- Generated APIs can manage policy objects safely

## Architecture Principles

- Compile all authorization forms into one typed internal model.
- Keep simple `.eon` `roles` and `policies` as sugar over that model.
- Prefer typed references over free-form string expressions.
- Ship explain/simulate tooling before complex runtime policy editing.
- Keep governance and privileged-access workflows separate from request-time authorization.

## Implementation Phases

### Phase 1: Foundation

- Introduce a typed authorization model in `rest_macro_core`
- Compile current `.eon` resource roles and row policies into that model
- Preserve current runtime behavior exactly
- Add targeted tests that prove the compiled model matches today's semantics

### Phase 2: Diagnostics

- Add `vsr authz explain`
- Add `vsr authz simulate`
- Add stable rule IDs and decision traces
- Add golden tests for authorization decisions

Status: the first diagnostic slice is now in place with `vsr authz explain` and
`vsr authz simulate` for the current `.eon` roles and row policies. The compiled
authorization model now also carries stable resource, action, role-rule, filter,
and assignment IDs so explain/simulate output and future management APIs can refer
to rules deterministically. `vsr authz simulate` can now also validate and resolve
runtime scoped permission/template assignments against the static authorization
contract, including loading persisted assignments for a user from the configured
database once the `vsr migrate authz` schema has been applied, while still
reporting that generated handlers do not enforce those runtime grants yet.
Generated `.eon` modules now also expose an `authorization_runtime(db)` helper and
register that runtime service as Actix app data from `module::configure(...)`, so
custom management or diagnostics endpoints can share the same compiled model and
assignment storage helpers. They also expose an opt-in
`configure_authorization_management(cfg, db)` helper for basic admin-only runtime
assignment CRUD plus a request-time runtime access evaluation endpoint, all without
changing resource enforcement. Custom handlers can now also opt into actual
request-time runtime grant enforcement through
`AuthorizationRuntime::enforce_runtime_access(...)`. Persisted runtime assignments
now also carry `created_at`, `created_by_user_id`, and optional `expires_at`, and
expired assignments are ignored by runtime evaluation.

### Phase 3: Typed Conditions

- Implemented for static `.eon` row filters: `all_of`, `any_of`, and `not`
- Implemented for static `.eon` row filters: typed equality against `I64`, `String`, and `Bool` claims
- Implemented for static `.eon` row filters: nullable `is_null` / `is_not_null` checks on optional fields
- Current shorthand syntax still compiles as sugar
- Remaining: enums, nullable values, richer operators beyond equality, and parity outside static row filters

### Phase 4: Scoped Assignments

- Add scope types and scoped role/permission assignments
- Support runtime-managed memberships and assignments
- Preserve `.eon` as the static contract
- Implemented: opt-in `authorization.management_api` config now lets generated modules and emitted servers auto-mount the runtime authorization management endpoints from `.eon`
- Implemented: persisted runtime assignments now also write append-only create/delete history, exposed through both the generated management API and `vsr authz runtime history`
- Implemented: persisted runtime assignments now support non-destructive revoke/renew lifecycle updates with append-only history, generated management endpoints, and matching `vsr authz runtime revoke|renew` commands
- Implemented: the first hybrid enforcement mode now lets generated item-scoped `Read`/`Update`/`Delete` handlers fall back to persisted runtime grants after static row-policy denial, using explicit `.eon` scope derivation from a configured row field
- Implemented: hybrid `Create` can now use the same runtime grant layer as an additive fallback, but only when the configured `scope_field` is already claim-controlled in `policies.create`

### Phase 5: Relation-Aware Authorization

- Implemented for static `.eon` row filters: a first bounded `exists` predicate against another declared resource
- `exists` conditions currently support equality-only correlation clauses: `related_field = user.id` / `claim.*` and `related_field = row.<field>`
- `exists.where` now also supports nested `all_of`, `any_of`, and `not` groups
- Validation now rejects unknown target resources and incompatible correlation field types at compile time
- Generated migrations and live-schema checks now add required indexes for `exists` target fields
- `vsr authz simulate` can now fully evaluate `exists` predicates when related rows are supplied explicitly
- Remaining: richer relation predicates beyond equality-only correlation

### Phase 6: Field-Level Authorization

- Add per-field read and write controls
- Add masking, hiding, immutable, and write-once semantics
- Distinguish row access from field access

### Phase 7: Governance Plane

- Add policy definitions, assignments, exemptions, and report-only mode
- Track compliance state independently from request authorization

### Phase 8: Privileged Access Lifecycle

- Add eligible versus active assignments
- Add approval, justification, expiry, and audit support

## Groundwork Delivered In This Slice

This slice should establish the reusable base:

- A typed authorization model in `rest_macro_core::authorization`
- A compiler that translates current `.eon` resource roles and row policies into that model
- Tests that lock in current semantics so future work extends the model instead of replacing it

## Near-Term Next Steps

1. Expose explain-oriented views over the compiled authorization model.
2. Extend typed conditions beyond simple equality now that claim-backed `I64`/`String`/`Bool` matches are supported.
3. Add boolean composition (`all_of`, `any_of`, `not`) to the policy AST.
4. Introduce scoped runtime-managed assignments before runtime-managed policy bundles.
