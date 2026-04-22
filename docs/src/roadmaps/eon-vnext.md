# `.eon` vNext Roadmap

This document defines the next major expansion of the `.eon` schema language beyond today's
resource/table-first CRUD model.

The current surface is already strong for relational CRUD, generated auth, explicit migrations,
and emitted/native runtime parity. The next step is to make `.eon` capable of describing richer
application-facing API contracts without collapsing into an unbounded programming language.

## Priority Order

1. First-class object/list/json field types
2. A separate API-shape layer from storage shape
3. External naming, relation embeds, and response contexts
4. Enum plus unique/index support
5. Reuse/composition
6. Many-to-many
7. Only then computed/hooks/actions

## Current Boundary

The present `.eon` model is intentionally storage-centric:

- fields are either built-in scalar keywords or raw Rust type strings
- resources map directly to tables and generated CRUD handlers
- relations are foreign-key oriented, with `nested_route` as a routing concern
- validation, policies, and list behavior all assume one primary resource shape
- the native `vsr serve` runtime still reduces fields to scalar-ish runtime kinds

Relevant implementation seams today:

- parser and `.eon` syntax loading:
  [crates/rest_macro_core/src/compiler/eon_parser.rs](/data/data/com.termux/files/home/very_simple_rest/crates/rest_macro_core/src/compiler/eon_parser.rs)
- shared compiler model:
  [crates/rest_macro_core/src/compiler/model.rs](/data/data/com.termux/files/home/very_simple_rest/crates/rest_macro_core/src/compiler/model.rs)
- generated handler/codegen path:
  [crates/rest_macro_core/src/compiler/codegen.rs](/data/data/com.termux/files/home/very_simple_rest/crates/rest_macro_core/src/compiler/codegen.rs)
- native runtime path:
  [crates/rest_api_cli/src/commands/serve.rs](/data/data/com.termux/files/home/very_simple_rest/crates/rest_api_cli/src/commands/serve.rs)
- generated reference docs:
  [crates/rest_api_cli/src/commands/docs.rs](/data/data/com.termux/files/home/very_simple_rest/crates/rest_api_cli/src/commands/docs.rs)
- current public DSL reference:
  [docs/eon-reference.md](/data/data/com.termux/files/home/very_simple_rest/docs/eon-reference.md)

The main architectural constraint is that the shared `FieldSpec` model still centers on
`syn::Type + sql_type + relation + validation`. That is enough for scalar CRUD, but it is not
enough for separate storage shape, API projections, typed object fields, contexts, or reusable
schema fragments.

## Goals

1. Keep the default `.eon` path simple for ordinary CRUD services.
2. Preserve `vsr serve`, generated code, and OpenAPI parity as features grow.
3. Add typed API-schema constructs before adding ad hoc escape hatches.
4. Make storage shape and response shape explicit instead of implicit.
5. Prefer declarative, machine-scannable schema features over arbitrary embedded code.
6. Stage rollout so existing `.eon` files keep working unchanged.

## Non-Goals

- turning `.eon` into a general-purpose programming language
- replacing hand-written Rust for every advanced behavior
- supporting arbitrary computed expressions in the first slice
- auto-inventing WordPress semantics by hardcoding WordPress-specific resource types

## Design Principles

### Shared normalized IR first

New `.eon` features must compile into one normalized schema IR used by:

- macro codegen
- native `vsr serve`
- OpenAPI generation
- migration generation
- docs/reference generation
- future UI/tooling

Parser-only additions without a shared IR should be avoided.

### API shape is not storage shape

The current direct resource-to-table mapping remains valid, but vNext must support:

- stored scalar field, exposed object field
- stored foreign key, exposed embedded relation
- stored internal names, exposed external names
- multiple response contexts over the same resource

### Constrained declarative features before hooks

If a common application need can be modeled declaratively, that should come before a hook system.
For example:

- `Enum` before arbitrary validation code
- `JsonObject` before raw Rust types for common JSON shapes
- `api_name` / contexts before custom serializer callbacks
- first-class embeds before hand-written projection code

### Additive migration path

Existing scalar CRUD `.eon` services should remain valid with no required edits. New features
should be opt-in, and defaults should preserve current generated/native behavior.

## Proposed Architecture Shift

## Phase 0: Foundation IR

This is the enabling phase. It should happen before any major surface expansion.

### Introduce a normalized schema model

Add a vNext internal IR in `rest_macro_core` that separates:

- storage resource schema
- API resource schema
- field type model
- response contexts
- embeds/projections
- constraints/index metadata
- reusable fragments/mixins

Suggested high-level shape:

```text
ServiceSchema
  resources: Vec<ResourceSchema>
  enums: Vec<EnumSchema>
  mixins: Vec<MixinSchema>

ResourceSchema
  storage: StorageResourceSchema
  api: ApiResourceSchema

StorageResourceSchema
  table_name
  id_field
  fields
  relations
  constraints
  indexes

ApiResourceSchema
  name
  api_name
  fields
  embeds
  contexts
```

### Keep legacy `ServiceSpec` working during migration

Do not replace the current model in one step. Instead:

1. parse into a richer document model
2. lower into normalized schema IR
3. derive the legacy `ServiceSpec` view from that IR where possible
4. gradually move codegen/runtime/docs/migrations to consume the new IR directly

### Exit criteria

- no public syntax changes required yet
- current `.eon` reference and tests still pass
- `vsr serve` and generated modules can both read from the same normalized schema IR

## Phase 1: First-Class Object/List/Json Field Types

This is the highest-value schema addition.

### Goals

- remove pressure to encode application structure as raw Rust types
- support fields such as `title.raw`, `content.rendered`, `meta`, and attribute
  blobs
- keep generated/native behavior portable and machine-readable

### Proposed syntax

```eon
fields: {
    title: {
        type: Object
        fields: {
            raw: String
            rendered: String
        }
    }
    categories: {
        type: List<I64>
    }
    meta: {
        type: JsonObject
    }
    blocks: {
        type: JsonArray
    }
}
```

### Minimum type set

- `Json`
- `JsonObject`
- `JsonArray`
- `List<T>`
- `Object`

`Object` should allow nested field declarations. `List<T>` should initially support scalar
elements and `Enum` references first; nested objects inside lists can follow once the storage and
OpenAPI paths are stable.

### Storage strategy

Initial implementation should allow these to store as JSON-backed columns while keeping the schema
typed at the `.eon` level.

That means:

- parser understands the new field kinds
- OpenAPI sees structured JSON schemas
- generated/native handlers validate/serialize consistently
- migrations choose backend-appropriate JSON-capable or text-backed columns

### Implementation slices

1. extend parser field type grammar
2. add new normalized field type model
3. add migration SQL mapping for JSON-backed storage
4. teach OpenAPI/docs generation to render object/list/json schemas
5. teach `vsr serve` request decoding and row encoding for these shapes
6. keep raw Rust types as an escape hatch, but mark them as lower-toolability

### Risks

- `vsr serve` currently categorizes fields into scalar runtime kinds only
- list/object validation must not diverge between codegen and native runtime
- backend SQL storage differences need a clear, documented fallback policy

## Phase 2: Separate API Shape From Storage Shape

This is the real platform step.

### Goals

- let a resource expose a different response contract from the underlying table columns
- support renamed fields, nested response objects, and hidden storage columns
- support future compatibility layers such as WordPress-style response contracts

### Proposed direction

Add an optional `api` block per resource:

```eon
resources: {
    Post: {
        table: "wp_post"
        fields: {
            author_id: I64
            title_json: JsonObject
        }
        api: {
            fields: {
                author: { from: "author_id" }
                title: { from: "title_json" }
            }
        }
    }
}
```

### Key rule

Storage fields remain the source of truth for:

- migrations
- persistence
- policies
- indexes

API fields become the source of truth for:

- serialization
- input/output schemas
- response contexts
- external naming

### First slice

Do not implement arbitrary computed projections first. Start with:

- one-to-one aliasing from storage field to API field
- API-level field omission/hiding
- API-level renaming
- API-level type reinterpretation only when structurally safe

### Exit criteria

- one resource can expose storage and API names separately
- OpenAPI reflects API shape, not raw table shape
- `vsr serve` and generated code return the same serialized field set

## Phase 3: External Naming, Relation Embeds, And Response Contexts

This phase builds on the API-shape layer.

### External naming

Add resource and field API aliases:

```eon
resources: {
    Post: {
        api_name: "posts"
        table: "post"
        fields: {
            author_id: {
                type: I64
                api_name: "author"
            }
        }
    }
}
```

This should affect:

- route naming
- OpenAPI naming
- serialized field names
- generated docs

### Relation embeds

Add an explicit API embed layer separate from `nested_route`:

```eon
api: {
    embeds: {
        author: {
            relation_field: "author_id"
            resource: "User"
            mode: Summary
        }
    }
}
```

Key rule:

- `nested_route` controls routing shape
- `embed` controls response shape

Those must stay separate.

### Response contexts

Add named response contexts:

```eon
api: {
    contexts: {
        view: { include: ["id", "title", "excerpt"] }
        edit: { include: ["id", "title", "content", "meta"] }
        embed: { include: ["id", "title"] }
    }
}
```

Contexts should initially affect:

- OpenAPI views if exposed as separate documented shapes
- serializer field sets
- future query parameter / route-mode negotiation

Do not over-design transport negotiation initially. A simple context selection contract is enough.

### Exit criteria

- route/resource names can diverge from storage names
- embedded relations are explicit and documented
- one resource can expose multiple named field subsets

## Phase 4: Enum Plus Unique/Index Support

This is a high-value practical phase and should come before composition.

### Enum support

Add top-level enum declarations:

```eon
enums: {
    PostStatus: ["draft", "publish", "private", "future", "trash"]
}
fields: {
    status: PostStatus
}
```

Enums should feed:

- validation
- OpenAPI enum metadata
- generated docs
- future UI/tooling

Database storage can initially remain string-backed unless backend-native enum support is added
later.

### Uniqueness and indexes

Add explicit schema constraints:

```eon
fields: {
    slug: {
        type: String
        unique: true
    }
}
indexes: [
    { fields: ["workspace_id", "slug"], unique: true }
    { fields: ["status", "published_at"] }
]
```

This should integrate with:

- migration generation
- live-schema drift checks
- docs/OpenAPI hints where relevant

Current policy-derived index hints should remain, but explicit indexes must become first-class.

### Exit criteria

- migrations emit explicit unique/index statements
- live-schema inspection validates declared indexes
- docs reference and OpenAPI expose enum/constraint metadata where useful

## Phase 5: Reuse/Composition

Once the schema can express richer shapes, reuse starts paying off.

### Goals

- avoid repetition in large `.eon` files
- support shared audit fields, ownership patterns, SEO metadata, and common API contexts

### Proposed surface

```eon
mixins: {
    Timestamps: {
        fields: {
            created_at: { type: DateTime, generated: CreatedAt }
            updated_at: { type: DateTime, generated: UpdatedAt }
        }
    }
}
resources: {
    Post: {
        use: ["Timestamps"]
    }
}
```

### Scope of the first slice

Support reuse for:

- fields
- indexes
- maybe API contexts

Do not start with arbitrary override precedence or cross-file imports. Keep first composition local
to one `.eon` file and deterministic.

### Validation rules

- mixin expansion must be deterministic
- duplicate field/index names after expansion are compile errors
- resource-local config wins only where explicitly allowed

## Phase 6: Many-To-Many

This should come after embeds and API shape, because many-to-many is most useful once the API can
describe embedded/expanded relation results cleanly.

### Proposed direction

Start with explicit join-resource metadata rather than implicit table generation:

```eon
relations: {
    tags: {
        kind: ManyToMany
        target: "Tag"
        through: "PostTag"
        source_field: "post_id"
        target_field: "tag_id"
    }
}
```

### Why not earlier

Join modeling is already possible today through explicit resources. It is verbose, but not blocked.
By contrast, API-shape and typed object/json support are structural blockers for editor-oriented
APIs.

### First slice

- documentation and validation of the relationship
- generated list/filter/embed support over an explicit join resource
- no implicit join-table generation at first

## Phase 7: Computed Fields, Hooks, And Actions

These should come last on purpose.

### Reason

These features are powerful, but they are also where schema DSLs often lose discipline and become
hard-to-reason-about embedded programming languages.

### Ordering inside this phase

1. constrained computed read-only fields
2. constrained built-in transforms
3. explicit custom actions
4. only then consider broader hook mechanisms

### Computed fields

Avoid arbitrary expression strings first. Prefer a small built-in vocabulary, for example:

- `SlugFrom("title")`
- `Concat`
- `Lowercase`
- `Trim`

### Hooks/transforms

Prefer built-in transforms on fields over resource-level free-form hook names:

```eon
fields: {
    slug: {
        type: String
        transforms: [Trim, Lowercase]
        derive_on_create: { kind: SlugFrom, field: "title" }
    }
}
```

### Actions

Actions should become a contract surface before they become an execution surface:

```eon
actions: {
    publish: {
        resource: "Post"
        method: POST
        path: "/posts/{id}/publish"
    }
}
```

The first implementation can focus on:

- route and docs contract
- authz integration
- explicit handler plug points

without forcing a full mutation DSL immediately.

## Cross-Cutting Workstreams

These apply across all phases.

### Docs and reference generation

Every new feature must update:

- [docs/eon-reference.md](/data/data/com.termux/files/home/very_simple_rest/docs/eon-reference.md)
- [crates/rest_api_cli/src/commands/docs.rs](/data/data/com.termux/files/home/very_simple_rest/crates/rest_api_cli/src/commands/docs.rs)

The reference generator should stay machine-scannable and explicit about defaults, validation, and
derived behavior.

### OpenAPI

New schema constructs should first-class map into OpenAPI:

- object/list/json field schemas
- enums
- contexts or documented response variants
- embedded relation schemas
- external names instead of storage names

### Native runtime parity

Every major schema expansion must land in both:

- generated handler path
- native `vsr serve` path

No feature should be considered complete if it works only in codegen or only in native runtime.

### Compatibility policy

`.eon` is now large enough to need an explicit compatibility stance:

- existing keys remain valid unless deprecated explicitly
- deprecations should preserve at least one release of overlap
- parser errors should be deterministic and precise
- generated behavior changes should be called out in release notes and docs

This should become part of the public `.eon` reference once the first vNext slice starts landing.

## Suggested Implementation Order

### Milestone A: IR groundwork

- normalized schema IR
- compatibility bridge from current parser/model
- no public syntax expansion yet

### Milestone B: typed non-scalar fields

- `Json`, `JsonObject`, `JsonArray`, `List<T>`, `Object`
- docs/OpenAPI/runtime/codegen parity

### Milestone C: API shape layer

- API field aliasing
- storage/API split
- external resource/field names

### Milestone D: embeds and contexts

- explicit embed model
- response contexts
- route/docs integration

### Milestone E: enums and constraints

- top-level `enums`
- `unique`
- explicit `indexes`

### Milestone F: mixins

- local composition only
- deterministic expansion

### Milestone G: many-to-many

- explicit join relationship metadata

### Milestone H: computed/transforms/actions

- constrained built-ins first

## Immediate Next Steps

1. Define the normalized schema IR before adding public syntax.
2. Draft exact `.eon` syntax for typed object/list/json fields and API-layer aliases.
3. Decide the storage policy for JSON-backed fields per backend.
4. Add parity tests that run the same fixture through generated code and native `vsr serve`.
5. Land enum and explicit-index support only after the shared IR can carry them cleanly.

## Recommendation

If the near-term product goal is WordPress/block-editor compatibility, focus the next design cycle
on:

1. object/list/json field types
2. storage/API shape separation
3. external naming plus contexts/embeds

Those three unlock the largest real compatibility gap. Many-to-many and hook-style features can
wait until after the API contract model is expressive enough to describe the response shapes those
systems actually need.
