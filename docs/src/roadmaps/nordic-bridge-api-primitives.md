# Nordic Bridge API Primitives Roadmap

This document turns the feature requests in `vsr-feature-request.md` into an implementation
roadmap for `very_simple_rest`.

The source request came from a large prototype that already ships against `vsr serve`. The right
response is not to treat the request as one feature. It is a cluster of related improvements with
very different implementation costs:

- small list-surface and documentation improvements
- medium write/auth improvements
- larger read-planning and projection improvements
- separate authorization-vocabulary work

## Goal

Make VSR better at application-facing API patterns that show up quickly in larger projects:

- batched feed queries
- server-maintained counters
- authenticated viewer hints
- public ingestion resources
- clearer authorization behavior

The constraint is that VSR still needs to preserve:

- native `vsr serve` and emitted-server parity
- OpenAPI and generated client parity
- declarative `.eon` semantics
- predictable performance on list routes

## What Already Exists

Several requested behaviors are close to existing implementation seams:

- list handlers already generate both a row query and a `COUNT(*)` query
- list responses already expose `total`
- the API projection system already supports response-only computed fields, but only `template`
- read access already has explicit `public | authenticated | inferred`
- row-policy create assignments already resolve values from `user.*` and `claim.*`

Relevant implementation seams:

- parser and `.eon` loading: `crates/rest_macro_core/src/compiler/eon_parser.rs`
- shared compiler model: `crates/rest_macro_core/src/compiler/model.rs`
- generated handler/codegen path: `crates/rest_macro_core/src/compiler/codegen.rs`
- native runtime path: `crates/rest_api_cli/src/commands/serve.rs`
- OpenAPI generation: `crates/rest_macro_core/src/compiler/openapi.rs`
- generated docs surface: `crates/rest_api_cli/src/commands/docs.rs`
- public DSL reference: `docs/src/reference/eon-reference.md`

## Design Rules

### Shared IR first

Small syntax additions can go straight through the parser and existing model. Larger read-shape
features should not.

If a feature needs new list-time data loading or response-shape semantics, it should compile into
a shared normalized projection IR used by:

- macro codegen
- native `vsr serve`
- OpenAPI generation
- generated docs

### No N+1 expansion features

Any feature that reads related data for a list route must batch by the visible resource IDs. The
first implementation of aggregates, viewer flags, or embeds must never run one query per row.

### Prefer server-owned derived state over client-owned counters

If the product need is "maintain a vote count correctly", the preferred primitive is server-side
side effects, not granting clients direct authority to patch denormalized counters.

### Keep auth semantics explicit

Public create support and nullable policy assignments are valuable, but they widen the attack
surface. They need static validation and clear documentation, not silent behavior changes.

### Keep built-in admin as a human operator path

The current built-in admin should stay as the bootstrap and human administration mechanism. It is
already deeply tied to the literal `"admin"` super-role, the admin dashboard, and built-in auth
management routes.

That should be documented clearly rather than generalized into the wrong machine-auth primitive.

If VSR gains service keys later, they should be a separate `.eon`-declared machine principal model
with explicit scopes and lifecycle, not a synonym for built-in admin.

## Priority Order

1. `filter_*__in`
2. `/count` plus `limit=0` contract docs
3. document the literal `"admin"` super-role behavior
4. `access.create = public` plus `value_or_null`
5. declarative `on_create` and `on_delete` side effects
6. unified read augmentation IR
7. aggregate fields and viewer flags on top of that IR
8. relation embedding
9. membership-backed JWT role expansion, if still desired after documentation

## Phase 1: Batch Query And Docs Wins

### Scope

- `filter_<field>__in=...`
- `resources[].list.filterable_in`
- `security.requests.max_filter_in_values`
- `/api/<resource>/count`
- documentation for `limit=0`
- documentation for literal `"admin"` super-role behavior

### Why this phase first

This gives the Nordic Bridge use case immediate relief with low architectural risk. The current
list planner already has the core pieces needed for both `__in` and `/count`.

### Syntax direction

```eon
security: {
    requests: {
        max_filter_in_values: 100
    }
}

TopicEngagement: {
    list: {
        filterable_in: ["topic_id"]
        count_endpoint: true
    }
}
```

Example query:

```text
GET /api/topic-engagements?filter_topic_id__in=1,2,3&filter_engagement_type=upvote
GET /api/topic-engagements/count?filter_topic_id=3&filter_engagement_type=upvote
```

### Main code changes

- parser:
  `eon_parser.rs` for new list config and request security fields
- model:
  `model.rs` for list config and request security representation
- codegen:
  `codegen.rs` list query struct generation, plan building, and count route generation
- native runtime:
  `serve.rs` list query parsing and count route parity
- OpenAPI:
  `openapi.rs` query parameter surface and count endpoint
- docs:
  `docs.rs` and `eon-reference.md`

### Acceptance criteria

- exact-match filters keep current behavior
- `__in` is only available on explicitly allowed fields
- invalid value coercion fails the same way as ordinary exact filters
- `__in` is capped by configured maximum size
- `/count` returns `{ "count": N }` with the same auth and row-policy semantics as list
- `limit=0` is documented as supported behavior
- docs state clearly that the literal role string `"admin"` bypasses role gates

### Risk

Low.

## Phase 2: Public Create And Nullable Stamps

### Scope

- `resources[].access.create`
- `access.create = public`
- `value_or_null` for create assignments

### Why this phase second

This removes real workarounds from larger apps, especially anonymous telemetry and onboarding
flows, without requiring the larger read-planner work.

### Syntax direction

```eon
AnalyticsEvent: {
    access: {
        read: "tenant_admin"
        create: "public"
    }
    policies: {
        create: [
            { field: "tenant_id", value_or_null: "claim.tenant_id" }
            { field: "user_id", value_or_null: "user.id" }
        ]
    }
}
```

### Validation rules

- `access.create = public` cannot combine with `roles.create`
- create `require` filters that depend on `user.*` or `claim.*` should be rejected for public
  create, unless a later explicit nullable/optional rule is introduced
- `value_or_null` requires a nullable target field
- existing `value` behavior stays strict and unchanged

### Main code changes

- parser:
  `ResourceAccessDocument` and create-assignment parsing in `eon_parser.rs`
- model:
  add create access enum alongside current read access in `model.rs`
- codegen:
  create auth checks and assignment binding paths in `codegen.rs`
- native runtime:
  parity in `serve.rs`
- docs and OpenAPI:
  docs updates, while OpenAPI mostly stays on request/response shapes

### Acceptance criteria

- public create works without authentication
- existing authenticated/role-gated create behavior does not change
- `value_or_null` writes `NULL` instead of returning "Missing required create field"
- non-nullable target fields fail static validation if used with `value_or_null`

### Risk

Medium. The behavior is simple, but auth and policy semantics must stay explicit.

## Phase 3: Declarative Write-Side Side Effects

### Scope

- `on_create`
- `on_delete`
- narrow action set: `Increment` and `Decrement`

### Why this phase before aggregate fields

The main motivating use case is maintaining counters correctly. That is better served by
transactional write-side side effects than by exposing client-driven counter writes or introducing
general aggregation first.

### Syntax direction

```eon
TopicEngagement: {
    on_create: [
        {
            target: FrontierTopic
            target_id_field: topic_id
            when: { engagement_type: "upvote" }
            action: Increment
            field: upvote_count
        }
    ]
    on_delete: [
        {
            target: FrontierTopic
            target_id_field: topic_id
            when: { engagement_type: "upvote" }
            action: Decrement
            field: upvote_count
        }
    ]
}
```

### Constraints for the first slice

- target exactly one resource row by ID
- action exactly one numeric field
- run in the same transaction as the source create/delete
- no chaining or recursive side effects
- no update-triggered side effects in the first slice

### Main code changes

- parser and model for side-effect specs
- generated create/delete handlers and native runtime create/delete path
- migration/docs examples for counter-maintained resources

### Acceptance criteria

- create and delete keep source and target rows consistent under concurrency
- failure in side effect aborts the whole write
- no client write access is needed for the maintained counter field

### Risk

Medium. Transaction semantics matter, but the feature can stay narrow.

## Phase 4: Unified Read Augmentation IR

### Scope

Introduce a new internal projection model for read-time augmented fields instead of extending
template computed fields ad hoc.

Suggested internal variants:

- `From`
- `Template`
- `AggregateCount`
- `Exists`
- `Embed`

### Why this phase exists

Today `ComputedFieldSpec` only supports string-template interpolation over already-materialized
scalar fields. That model is too small for:

- aggregate counts
- viewer-specific existence flags
- embedded related collections

If these features are added independently, the runtime and codegen will drift and list performance
will degrade.

### Main code changes

- `model.rs` projection structures
- `eon_parser.rs` normalization into shared projection IR
- `codegen.rs` and `serve.rs` serialization pipeline changes
- `openapi.rs` support for new response field kinds

### Acceptance criteria

- native and emitted servers share the same projection behavior
- list routes use batched secondary queries, not per-row queries
- response contexts continue to work over both stored and augmented fields

### Risk

High. This is the enabling architecture for the remaining read-side features.

## Phase 5: Aggregate Fields And Viewer Flags

### Scope

- `aggregate` API fields, first cut `Count` only
- `viewer_relation` built on the same existence-query machinery

### Why group these together

Both features need batched secondary queries keyed by the visible row IDs. `viewer_relation` is
effectively a user-scoped `exists` query and should reuse the same planner instead of inventing a
special path.

### Syntax direction

```eon
FrontierTopic: {
    api: {
        fields: {
            upvote_count: {
                aggregate: {
                    from: TopicEngagement
                    op: Count
                    where: {
                        topic_id: "$id"
                        engagement_type: "upvote"
                    }
                }
            }
            viewer_has_upvoted: {
                viewer_relation: {
                    from: TopicEngagement
                    exists_where: {
                        topic_id: "$id"
                        user_id: "$user.id"
                        engagement_type: "upvote"
                    }
                }
            }
        }
    }
}
```

### First-cut rules

- response-only
- not filterable or sortable
- `Count` only at first
- anonymous viewer relation resolves to `false` or omitted, but this must be one documented choice
- aggregate and exists queries must honor the target resource's normal read visibility rules

### Acceptance criteria

- one feed page can request counts and viewer flags without fan-out
- generated OpenAPI and TypeScript clients expose the fields correctly
- batching remains stable with pagination and response contexts

### Risk

High, but lower once Phase 4 exists.

## Phase 6: Relation Embedding

### Scope

- `embed` read fields for single-level related collections

### Why later

Embedding is useful, but it is more expensive than counts or viewer flags and easier to misuse. It
should land after the read augmentation IR is proven on cheaper field types.

### First-cut rules

- single level only
- fixed `where`, `sort`, and `limit`
- no nested embeds inside embeds
- read-only
- embedded resource policies still apply

### Acceptance criteria

- detail pages can collapse several sequential requests into one
- response size stays bounded by declared embed limits
- contexts can opt into or out of embeds cleanly

### Risk

High. This adds the most response-shape complexity.

## Separate Track: Membership-Backed JWT Role Expansion

This should not be bundled into the API-shape roadmap.

The current `roles.<action>` behavior is global string matching, with literal `"admin"` as the
super-role. Membership-backed expansion raises separate questions:

- should scoped membership roles become global JWT roles
- should role strings encode tenant context
- should this be JWT material or runtime authorization state

Recommended direction:

- document the current behavior first
- keep `exists(TenantMembership ...)` row-policy patterns as the supported tenant-scope mechanism
- revisit this only after deciding whether VSR wants first-class scoped roles

## Cross-Cutting Track: Endpoint Telemetry, Analytics, And Audit

This should be treated as a separate but adjacent workstream.

The important design rule is to not collapse three different needs into one feature:

- analytics: product and usage measurement, often sampled or aggregated
- telemetry: operational request/event traces for debugging and reporting
- audit: append-only accountability records with stronger integrity guarantees

They can share plumbing, but they should not share the same promises.

### Recommendation

Use a shared event-capture framework with different sink modes:

- `analytics`
  - optimized for volume
  - batching is allowed
  - sampling is allowed
  - loss tolerance is acceptable
- `telemetry`
  - structured request/event stream
  - batching is preferred
  - per-endpoint opt-in is useful
  - primarily operational, not compliance-grade
- `audit`
  - append-only
  - no update/delete through generated CRUD
  - write path should be transactional with the protected operation when possible
  - tamper-evident chaining and verification should be first-class if VSR claims audit integrity

### What Should Be Declarative In `.eon`

The developer should declare:

- which resources or actions emit events
- which event class each emission belongs to
- which fields are included in the emitted payload
- who can read the resulting event data through the API
- retention or export intent, when the system grows that far

The developer should not be responsible for inventing the audit envelope itself if VSR wants
provable behavior. A compliance-grade audit trail needs a stable canonical event shape.

### Suggested Shape

One plausible direction is:

```eon
observability: {
    sinks: {
        analytics: {
            mode: Batched
            resource: "AnalyticsEvent"
        }
        audit: {
            mode: Transactional
            resource: "AuditEvent"
            tamper_evident: true
        }
    }
}

FrontierTopic: {
    events: {
        read_list: [
            {
                sink: "analytics"
                event: "frontier_topic.list"
                include: ["tenant_id"]
            }
        ]
        create: [
            {
                sink: "audit"
                event: "frontier_topic.created"
                include: ["id", "tenant_id", "created_by_user_id"]
            }
        ]
        update: [
            {
                sink: "audit"
                event: "frontier_topic.updated"
                include: ["id", "tenant_id"]
                diff: ["title", "status"]
            }
        ]
    }
}

resources: {
    AuditEvent: {
        access: { read: "authenticated" }
        roles: { read: "auditor" }
    }
}
```

The exact syntax can vary, but the model should stay explicit:

- emitters live near the endpoint/resource/action they describe
- sinks declare durability/integrity behavior
- read access to event data is controlled through the normal API contract

### Event Envelope Requirements

Regardless of syntax, emitted records should carry a stable envelope with fields such as:

- event ID
- event class
- timestamp
- request ID / correlation ID
- actor kind and actor ID
- actor roles snapshot
- route template and HTTP method
- target resource and target row ID when applicable
- outcome and status code
- duration
- optional payload and optional field diff

For audit-grade records, add:

- previous event hash
- current event hash over a canonical payload
- optional signing/anchoring metadata later

### Integrity Model

If VSR claims a "tamper-proof" or "provable" audit trail, the first acceptable bar is
tamper-evident append-only audit, not ordinary logging.

That means:

- no update/delete API for audit rows
- hash chaining between audit rows
- a verification command such as `vsr audit verify`
- clear documentation of the trust boundary

If the backing database itself is fully compromised, no in-database mechanism is truly tamper-proof
without an external anchor. So the honest term for the first slice is `tamper_evident`, not
`tamper_proof`.

### Delivery Order

Recommended order inside this track:

1. Document current admin semantics and explicitly keep built-in admin as the human operator path.
2. Add a generic event envelope and sink abstraction.
3. Add batched analytics and telemetry emission.
4. Add append-only transactional audit emission for resource CRUD and actions.
5. Add tamper-evident hash chaining and `vsr audit verify`.
6. Only later consider service keys as a separate machine-principal track.

## Suggested Delivery Sequence

1. Phase 1 in one release.
2. Phase 2 in one release or two small PRs.
3. Phase 3 behind a narrow, explicit DSL.
4. Phase 4 as the enabling refactor.
5. Phase 5 once Phase 4 is stable.
6. Phase 6 last.

## Suggested Test Strategy

Every phase should add coverage in both the macro/codegen path and native `vsr serve` path.

Minimum expectations:

- parser validation tests in `eon_parser.rs`
- OpenAPI snapshot updates in `openapi.rs`
- generated-server behavior coverage where the feature affects emitted code
- native runtime behavior coverage in `crates/rest_api_cli/src/commands/serve.rs` and CLI tests
- one realistic example or fixture for the new syntax if the feature is user-facing

## Recommendation

If implementation time is scarce, the first concrete slice should be:

1. `filter_*__in`
2. `/count`
3. docs for `limit=0` and literal `"admin"`
4. `access.create = public`
5. `value_or_null`

That sequence gives large projects immediate leverage without committing too early to a general
read augmentation engine.
