# `.eon` Configuration Reference

This document maps the currently supported `.eon` configuration surface in `very_simple_rest` / `vsr`. It is intended to be machine-scannable for AI agents and readable for humans.

Generated with `vsr docs --output <file.md>`.

Current parser guarantees covered here:

- service-level configuration blocks
- resource and field list syntax
- resource and field keyed-map syntax
- shorthand field type syntax in field maps
- current validation rules, defaults, and derived behavior

## Supported Input Shapes

The parser accepts both the original list-based syntax and the newer keyed-map syntax for resources and fields.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| resources | List<Resource> or Map<ResourceName, Resource> | Required | Yes | List entries or keyed map entries | Resource names must be unique. In map form the key is the canonical resource name. If `name` is also present inside the value, it must match the key. |
| resources[].fields | List<Field> or Map<FieldName, Field \| Type> | Required | Yes | List entries, keyed objects, or shorthand type values | Field names must be unique per resource. In map form the value may be a full field object or just a type such as `title: String`. |
| resources.<resource>.fields.<field> | Field object or scalar type | Shorthand defaults to a non-null, non-id, non-generated field | No | `String`, `I64`, `Bool`, or any other supported field type | Map shorthand is only available for field maps, not list entries. |

```eon
resources: {
    Post: {
        fields: {
            id: { type: I64, id: true }
            title: String
            published: { type: Bool }
        }
    }
}
```

## Top-Level Keys

These keys are read from the service root.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| module | String | The `.eon` file stem, sanitized to a Rust module identifier | No | Any non-empty string | Controls the generated Rust module name. |
| db | Enum | Sqlite | No | Sqlite, Postgres, Mysql | Selects the SQL dialect and resource backend used for generated SQL and handlers. |
| database | Map | Backend-dependent runtime engine defaults | No | See Database Engine and Resilience | Overrides the runtime database engine and can declare backup/replication posture without changing the resource SQL dialect. |
| logging | Map | Enabled with built-in defaults | No | See Logging | Controls the emitted server logger configuration. |
| runtime | Map | Compression disabled | No | See Runtime | Controls runtime-only behavior such as HTTP compression. |
| authorization | Map | No static authorization contract | No | See Authorization Contract | Declares optional static scopes, permissions, and templates for the compiled authorization model. |
| tls | Map | Disabled unless the block is present | No | See TLS | Any configured TLS field enables HTTPS/Rustls handling in emitted servers. |
| static | Map | No static mounts | No | See Static Mounts | Declares filesystem-backed static directories and SPA mounts. |
| security | Map | All optional features off / empty | No | See Security | Controls request limits, CORS, trusted proxies, auth settings, headers, and rate limits. |
| enums | List<Enum> or Map<EnumName, Enum \| List<String>> | None | No | Named enum definitions | Declares reusable string-enum vocabularies that fields can reference by name. |
| resources | List or keyed map | None | Yes | Resource definitions | A service must contain at least one resource. |

## Enums

The optional `enums` block declares reusable string-enum vocabularies for field definitions.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| enums.<enum_name>.name | String | Required in list form; implied by the key in map form | Yes in list form | Valid Rust identifier | Enum names must be unique and are referenced from `resources[].fields[].type`. |
| enums.<enum_name>.values | List<String> | Required when the enum exists | Yes | One or more unique string values | Enum values are validated at request time and emitted in OpenAPI schemas and exact-filter parameters. |

## Authorization Contract

The optional `authorization` block declares static scope, permission, template, hybrid-enforcement, and management-surface vocabulary. The scope/permission/template declarations are compiled into the authorization model and available through `vsr authz explain`; request-time behavior changes only when you explicitly enable the generated runtime management API or hybrid enforcement.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| authorization.management_api | Map | Disabled | No | See Authorization Management API | Opt-in generated runtime authorization management routes for modules and emitted servers. |
| authorization.scopes | Map<ScopeName, Scope> | None | No | Keyed scope map | Scope names must be unique valid identifiers. Use this to declare hierarchical authorization scope vocabulary. |
| authorization.permissions | Map<PermissionName, Permission> | None | No | Keyed permission map | Permission names must be unique valid identifiers. Each permission must declare at least one action and one resource. |
| authorization.templates | Map<TemplateName, Template> | None | No | Keyed template map | Template names must be unique valid identifiers. Templates currently reference permissions and scopes only. |
| authorization.hybrid_enforcement | Map | None | No | See Authorization Hybrid Enforcement | Opt-in additive runtime grant checks for generated item-scoped CRUD handlers. |

## Authorization Hybrid Enforcement

Hybrid enforcement lets generated handlers consult runtime scoped grants after static role and row-policy checks fail. `scope_field` still names the canonical scope value source, while `scope_sources` explicitly declares which request shapes may derive scope from it. When `scope_sources` is omitted, current defaults preserve the existing behavior for the configured actions.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| authorization.hybrid_enforcement.resources | Map<ResourceName, HybridResource> | None | No | Keyed resource map | Each entry must reference a declared resource, declared scope, and at least one matching permission action. |
| authorization.hybrid_enforcement.resources.<resource>.scope | String | Required | Yes | Declared scope name such as `Family` | Runtime grants are evaluated against this scope for the configured resource. |
| authorization.hybrid_enforcement.resources.<resource>.scope_field | String | Required | Yes | Declared resource field name such as `family_id` | The generated handler derives the runtime scope value from this row field. |
| authorization.hybrid_enforcement.resources.<resource>.scope_sources | Map | Action-derived defaults | No | See Hybrid Scope Sources | Explicitly declares which request shapes may derive scope from `scope_field`. Omit it to keep the current action-based defaults. |
| authorization.hybrid_enforcement.resources.<resource>.scope_sources.item | Bool | true for `Read`/`Update`/`Delete` | No | true, false | Enables row-derived scope for item routes and created-response fallback. `Update` and `Delete` require this source. |
| authorization.hybrid_enforcement.resources.<resource>.scope_sources.collection_filter | Bool | true for `Read` | No | true, false | Enables top-level collection `Read` when the request includes an exact `filter_<scope_field>` value. |
| authorization.hybrid_enforcement.resources.<resource>.scope_sources.nested_parent | Bool | true for `Read` | No | true, false | Enables nested collection `Read` when the nested parent filter targets `scope_field`. |
| authorization.hybrid_enforcement.resources.<resource>.scope_sources.create_payload | Bool | true for `Create` | No | true, false | Enables the create-payload fallback for claim-controlled `policies.create` scope fields. `Create` requires this source. |
| authorization.hybrid_enforcement.resources.<resource>.actions | [Action] | Required | Yes | Create, Read, Update, Delete | `Read`, `Update`, and `Delete` require matching static row policies to supplement. `Create` is allowed only when `scope_field` is already claim-controlled by `policies.create`. |

## Authorization Management API

When enabled, generated modules and emitted servers automatically mount the runtime authorization management endpoints under the configured path.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| authorization.management_api.enabled | Bool | true when the block exists; otherwise disabled | No | true, false | Controls whether generated `configure(...)` mounts the runtime authorization management routes automatically. |
| authorization.management_api.mount | String | `/authz/runtime` | No | Absolute route path such as `/authz/runtime` or `/ops/authz` | Must start with `/`. Trailing `/` is normalized away. The mounted endpoints are `<mount>/evaluate`, `<mount>/assignment-events`, `<mount>/assignments`, `<mount>/assignments/{id}`, `<mount>/assignments/{id}/revoke`, and `<mount>/assignments/{id}/renew`. |

## Authorization Scopes

Scopes define named authorization boundaries and optional parent relationships.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| authorization.scopes.<scope_name>.description | String | None | No | Any non-empty string | Optional human-readable description for tooling and docs. |
| authorization.scopes.<scope_name>.parent | String | None | No | Another declared scope name | Parent scopes must exist and cannot form cycles. |

## Authorization Permissions

Permissions declare which resource actions belong to a named permission.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| authorization.permissions.<permission_name>.description | String | None | No | Any non-empty string | Optional human-readable description for tooling and docs. |
| authorization.permissions.<permission_name>.actions | [Action] | Required when the permission exists | Yes | Read, Create, Update, Delete | At least one action is required. |
| authorization.permissions.<permission_name>.resources | [String] | Required when the permission exists | Yes | Declared resource names such as `Post` or `ScopedDoc` | At least one resource is required. References must match declared `.eon` resources. |
| authorization.permissions.<permission_name>.scopes | [String] | None | No | Declared scope names | Optional static scope hints for future runtime-managed authorization layers. |

## Authorization Templates

Templates group permissions and optional scopes into reusable named bundles.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| authorization.templates.<template_name>.description | String | None | No | Any non-empty string | Optional human-readable description for tooling and docs. |
| authorization.templates.<template_name>.permissions | [String] | Required when the template exists | Yes | Declared permission names | At least one permission is required. |
| authorization.templates.<template_name>.scopes | [String] | None | No | Declared scope names | Optional static scope hints attached to the template. |

```eon
authorization: {
    management_api: {
        mount: "/ops/authz"
    }
    scopes: {
        Family: {
            description: "Family tenancy scope"
        }
        Household: {
            parent: "Family"
        }
    }
    permissions: {
        FamilyRead: {
            actions: ["Read"]
            resources: ["ScopedDoc"]
            scopes: ["Family"]
        }
    }
    templates: {
        FamilyMember: {
            permissions: ["FamilyRead"]
            scopes: ["Family"]
        }
    }
}
```

## Resource Keys

Each resource describes one generated REST model and its CRUD surface.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| resources[].name | String | Required in list form; implied by the key in map form | Yes in list form | Any name that can sanitize to a Rust struct identifier | The generated Rust struct uses UpperCamelCase. Duplicate names are rejected after sanitization. |
| resources[].table | String | The snake_case form of `name` | No | Valid SQL identifier | Controls the SQL table name and API path segment. |
| resources[].api_name | String | The resolved table name | No | Valid API path segment | Overrides the public collection/item route segment without changing the storage table name. |
| resources[].id_field | String | `id` | No | Field name | The named field must exist on the resource. |
| resources[].roles | Map | No role checks | No | See Resource Roles | Declares coarse role gates for read/create/update/delete. |
| resources[].policies | Map | `admin_bypass = true`; no row policies | No | See Row Policies | Declares row-level filters and assignments using `user.id` or `claim.<name>` sources. |
| resources[].list | Map | No custom limit caps | No | See List Settings | Controls generated list endpoint defaults and hard caps. |
| resources[].api | Map | No API projection or response contexts | No | See Resource API | Separates the public API field surface from storage fields and can define named response contexts. |
| resources[].indexes | List<Index> | No explicit indexes | No | See Indexes | Declares explicit single-field or composite indexes in addition to the automatic relation and policy-derived index hints. |
| resources[].fields | List or keyed map | None | Yes | Field definitions | Each resource must define its fields explicitly. |

## Resource API

The optional `api` block lets a resource expose a different public field surface from its storage fields and declare named response contexts over that public surface.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| resources[].api.fields | List<ApiFieldProjection> or Map<ApiFieldName, String \| ApiFieldProjection> | Expose every field by its storage name | No | Projection definitions | When present, only the projected fields are exposed in generated/native JSON payloads, list filters, sort names, and OpenAPI. Each projection maps one API field name to one storage field via `from`. |
| resources[].api.default_context | String | No default context; responses use the full projected API field set | No | Configured context name | When set, list/get/create responses default to that named context unless a `context` query parameter overrides it. |
| resources[].api.contexts | List<ResponseContext> or Map<ContextName, ResponseContext \| List<String>> | No named response contexts | No | Named context definitions | Each context is a subset of exposed API field names. Generated handlers and native `vsr serve` apply the selected context at response serialization time. |

## Response Contexts

Response contexts are named subsets of already-exposed API fields. They currently affect list/get/create response bodies and can be selected with `?context=<name>`.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| resources[].api.contexts[].name | String | Required in list form; implied by the key in map form | Yes in list form | Valid API identifier | Context names must be unique per resource and are exposed through OpenAPI as the `context` query parameter enum. |
| resources[].api.contexts[].fields | List<String> | [] | No | Exposed API field names | Every listed field must already be exposed on the resource API surface, either directly or through `api.fields` projection. |

## Resource Roles

Role checks are string comparisons against the authenticated user's role list.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| resources[].roles.read | String | None | No | Role name | When set, reads require the named role. |
| resources[].roles.create | String | Falls back to `roles.update` when `create` is omitted and `update` is set | No | Role name | Write-role compatibility with the original shorthand is preserved. |
| resources[].roles.update | String | None | No | Role name | When set, updates require the named role. |
| resources[].roles.delete | String | None | No | Role name | When set, deletes require the named role. |

## List Settings

List settings tune generated list endpoint defaults.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| resources[].list.default_limit | u32 | None | No | Positive integer | Must be greater than 0. If both limits are set, `default_limit <= max_limit`. |
| resources[].list.max_limit | u32 | None | No | Positive integer | Must be greater than 0. |

## Indexes

Resources can declare explicit indexes, while generated migrations and live-schema checks still infer additional non-unique indexes from relations and row-policy fields.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| resources[].indexes[].fields | List<String> | Required when the index exists | Yes | One or more storage field names | Field names reference storage columns, not API projection aliases. Composite indexes preserve the configured field order. |
| resources[].indexes[].unique | Bool | false | No | true, false | When true, generated migrations emit `CREATE UNIQUE INDEX ...` for the configured field list. |

## Row Policies

Row policies support both the newer explicit form and older owner/set-owner shorthands. `read`, `update`, and `delete` accept a single filter, an array that implies `all_of`, or an explicit boolean group with `all_of`, `any_of`, `not`, and `exists`. `create` supports the legacy flat assignment list and an object form with `assign` plus `require`.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| resources[].policies.admin_bypass | Bool | true | No | true, false | When true, admin-role users bypass the configured row-level policies. |
| resources[].policies.read | PolicyFilter, [PolicyFilter], PolicyGroup | None | No | `field=user.id`, `field=claim.<name>`, `{ field, equals }`, `{ field, is_null: true }`, `{ field, is_not_null: true }`, `Owner:field`, `{ all_of: [...] }`, `{ any_of: [...] }`, `{ not: ... }`, `{ exists: { resource, where } }` | Filters read queries. Arrays imply `all_of`. `exists.where` accepts either leaf comparisons or nested `all_of` / `any_of` / `not` groups; list entries still imply `all_of`. `is_null` and `is_not_null` require a nullable field. `SetOwner` syntax is rejected here. |
| resources[].policies.create | PolicyAssignment, [PolicyAssignment], { assign, require } | None | No | `field=user.id`, `field=claim.<name>`, `{ field, value }`, `SetOwner:field`, `{ assign: [...], require: PolicyFilter \| [PolicyFilter] \| PolicyGroup }` | Assigns values during create operations and can also enforce preconditions before insert. `require` uses the same boolean filter tree as `read` / `update` / `delete`, plus `input.<field>` sources for the proposed create payload. `Owner` syntax is rejected here. |
| resources[].policies.update | PolicyFilter, [PolicyFilter], PolicyGroup | None | No | `field=user.id`, `field=claim.<name>`, `{ field, equals }`, `{ field, is_null: true }`, `{ field, is_not_null: true }`, `Owner:field`, `{ all_of: [...] }`, `{ any_of: [...] }`, `{ not: ... }`, `{ exists: { resource, where } }` | Filters update queries. Arrays imply `all_of`. `is_null` and `is_not_null` require a nullable field. |
| resources[].policies.delete | PolicyFilter, [PolicyFilter], PolicyGroup | None | No | `field=user.id`, `field=claim.<name>`, `{ field, equals }`, `{ field, is_null: true }`, `{ field, is_not_null: true }`, `Owner:field`, `{ all_of: [...] }`, `{ any_of: [...] }`, `{ not: ... }`, `{ exists: { resource, where } }` | Filters delete queries. Arrays imply `all_of`. `is_null` and `is_not_null` require a nullable field. |

```eon
policies: {
    admin_bypass: true
    read: {
        any_of: [
            "owner_id=user.id"
            { field: "archived_at", is_null: true }
            {
                all_of: [
                    "tenant_id=claim.tenant_id"
                    { not: "blocked_user_id=user.id" }
                ]
            }
        ]
    }
    create: [
        "owner_id=user.id"
        { field: "tenant_id", value: "claim.tenant_id" }
    ]
    update: {
        any_of: [
            "owner_id=user.id"
            { field: "archived_at", is_not_null: true }
        ]
    }
    delete: "Owner:owner_id"
}
```

```eon
create: {
    assign: [
        "created_by_user_id=user.id"
    ]
    require: {
        exists: {
            resource: "Family"
            where: [
                { field: "id", equals: "input.family_id" }
                "owner_user_id=user.id"
            ]
        }
    }
}
```

The first relation-aware filter form is `exists`, which targets another declared resource and correlates it with the current row. Leaf `where` entries can be equality checks, current-row field correlations, `input.<field>` comparisons for `create.require`, or nullable `is_null` / `is_not_null` checks:

```eon
read: {
    exists: {
        resource: "FamilyMember"
        where: [
            { field: "family_id", equals_field: "family_id" }
            {
                any_of: [
                    "user_id=user.id"
                    "delegate_user_id=user.id"
                ]
            }
        ]
    }
}
```

Generated migrations and live-schema checks also treat row-policy fields as index hints. That includes direct policy-controlled fields on the current resource and target-resource fields referenced by `exists` conditions.

## Field Keys

Field configuration controls generated Rust types, SQL columns, validations, and relations.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| resources[].fields[].name | String | Required in list form; implied by the key in map form | Yes in list form | Valid Rust identifier | Duplicate field names are rejected per resource. |
| resources[].fields[].type | Enum or raw Rust type string | None | Yes | See Field Types | Supported built-in field type keywords and declared enum names are listed below. Other raw Rust types are parsed with `syn` and inferred to SQL best-effort. |
| resources[].fields[].items | Built-in field type keyword | None | Yes when `type = List` | See Field Types | Required for `List` fields. The current first version accepts built-in item types only and stores the resulting list as JSON text. |
| resources[].fields[].fields | List<Field> or Map<FieldName, Field \| Type> | None | Yes when `type = Object` | Nested field definitions | Required for `Object` fields. Nested fields currently support scalar, JSON, nested `Object`, and `List` child shapes and are stored together as a JSON object encoded in text. |
| resources[].fields[].nullable | Bool | false | No | true, false | Wraps the generated Rust field type in `Option<T>`. `generated` fields are also emitted as optional even when `nullable` is false. |
| resources[].fields[].id | Bool | false, but the field matching `id_field` is treated as the ID | No | true, false | Primary key semantics are inferred when the field name matches the resource `id_field`. |
| resources[].fields[].unique | Bool | false | No | true, false | Declares a unique single-column index for supported scalar storage fields. Typed `Object`, `List`, and JSON fields do not support `unique`. |
| resources[].fields[].generated | Enum | Auto-inferred from the field name and ID role when omitted | No | None, AutoIncrement, CreatedAt, UpdatedAt | If omitted, IDs become `AutoIncrement`, `created_at` becomes `CreatedAt`, and `updated_at` becomes `UpdatedAt`. |
| resources[].fields[].relation | Map | None | No | See Relations | Declares a foreign-key style relationship and optional nested route generation. |
| resources[].fields[].validate | Map | None | No | See Field Validation | Validation is supported for text, integer, and real fields only. |

## Relations

Relations annotate fields that reference another table.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| resources[].fields[].relation.references | String | None | Yes | `table.field` | Must be exactly one table name and one field name, both valid SQL identifiers. |
| resources[].fields[].relation.on_delete | Enum | None | No | Cascade, Restrict, SetNull, NoAction | Accepted case-insensitive aliases include `set_null`, `set-null`, `no_action`, and `no-action`. `SetNull` requires the field to be nullable. |
| resources[].fields[].relation.nested_route | Bool | false | No | true, false | Enables the generated nested-route behavior for this relation. |

## Field Validation

Validation is checked at compile time and only certain combinations are allowed.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| resources[].fields[].validate.min_length | usize | None | No | Non-negative integer | Only valid for text-like fields. Must be `<= max_length` when both are set. |
| resources[].fields[].validate.max_length | usize | None | No | Non-negative integer | Only valid for text-like fields. Must be `>= min_length` when both are set. |
| resources[].fields[].validate.minimum | i64 or f64 | None | No | Integer or float literal | Only valid for integer and real fields. Integer SQL fields require integer bounds. |
| resources[].fields[].validate.maximum | i64 or f64 | None | No | Integer or float literal | Only valid for integer and real fields. Must be `>= minimum` when both are set. |

## Static Mounts

Static mounts are resolved relative to the `.eon` file and must stay inside the service directory.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| static.mounts | List<Mount> | No static mounts | No | Mount objects | Duplicate mount paths are rejected. |
| static.mounts[].mount | String | None | Yes | Absolute URL path beginning with `/` | Cannot conflict with `/api`, `/auth`, `/docs`, or `/openapi.json`. Trailing slashes are normalized except for `/`. |
| static.mounts[].dir | String | None | Yes | Relative directory path | Must resolve under the service root and point to an existing directory. |
| static.mounts[].mode | Enum | Directory | No | Directory, Spa | Case-insensitive parsing is supported. `Spa` auto-defaults `index_file` and `fallback_file` to `index.html`. |
| static.mounts[].index_file | String | None for `Directory`; `index.html` for `Spa` | No | Relative file path | Resolved under the mount directory and must point to an existing file. |
| static.mounts[].fallback_file | String | None for `Directory`; `index.html` for `Spa` | No | Relative file path | Only used for SPA fallback behavior. |
| static.mounts[].cache | Enum | Revalidate | No | NoStore, Revalidate, Immutable | Accepted aliases include `no_store` and `no-store`. |

## Database Engine

The top-level `db` controls SQL generation. `database.engine` controls the runtime connection strategy.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| database.engine.kind | Enum | If omitted: `TursoLocal` for `db: Sqlite`; `Sqlx` for `db: Postgres\|Mysql` | No | Sqlx, TursoLocal | Accepted aliases include `turso_local` and `turso-local`. `TursoLocal` requires `db: Sqlite`. |
| database.engine.path | String | For the implicit SQLite runtime engine: `var/data/<module>.db` | Required for explicit `kind = TursoLocal` | Relative path, absolute path, or `:memory:` | The `vsr` runtime resolves relative paths against the service or bundle base directory. |
| database.engine.encryption_key_env | String | For the implicit SQLite runtime engine: `TURSO_ENCRYPTION_KEY` | No | Environment variable name | Used only by `TursoLocal`. When set, the runtime loads the key from `<VAR>` or `<VAR>_FILE`. |

## Database Resilience

The optional `database.resilience` block declares backup, restore-verification, and replication intent. `vsr` can already render plans, run doctor checks, and move local backup artifacts to S3-compatible storage from this contract, but generated servers do not yet enforce replica-aware runtime behavior automatically.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| database.resilience.profile | Enum | SingleNode when the block exists and `profile` is omitted | No | SingleNode, Pitr, Ha | Use this to describe the intended recovery posture without embedding deployment-specific schedules. |
| database.resilience.backup | Map | None | No | See Database Backup | Declares the intended backup mode, target, restore-verification, and retention posture. |
| database.resilience.replication | Map | None | No | See Database Replication | Declares the intended replica topology and explicit read-routing posture. |

## Database Backup

Backup settings describe the intended durability posture. They do not schedule jobs directly.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| database.resilience.backup.required | Bool | true when the backup block exists | No | true, false | Use `false` only when you are documenting a non-critical or externally-managed case explicitly. |
| database.resilience.backup.mode | Enum | By profile/backend: `Pitr` for `profile = Pitr`; otherwise `Snapshot` for SQLite and `Logical` for Postgres/MySQL | No | Snapshot, Logical, Physical, Pitr | SQLite/TursoLocal services can already create local snapshot artifacts from this contract. Postgres/MySQL execution is still planning-oriented. |
| database.resilience.backup.target | Enum | Local | No | Local, S3, Gcs, AzureBlob, Custom | Describes the expected backup destination family. Credentials remain environment-specific. |
| database.resilience.backup.verify_restore | Bool | false | No | true, false | Marks restore verification as part of the required operational posture. |
| database.resilience.backup.max_age | String | None | No | Any non-empty duration-like string such as `24h` | Currently stored as text for planning/doctor output; strict duration parsing is follow-up work. |
| database.resilience.backup.encryption_key_env | String | None | No | Environment variable name | Documents the expected backup encryption or key-unwrapping env var. |
| database.resilience.backup.retention.daily | u32 | None | No | Positive integer | Optional daily retention target. |
| database.resilience.backup.retention.weekly | u32 | None | No | Positive integer | Optional weekly retention target. |
| database.resilience.backup.retention.monthly | u32 | None | No | Positive integer | Optional monthly retention target. |

## Database Replication

Replication settings declare explicit primary/read topology intent. Generated servers do not yet auto-route reads based on this block.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| database.resilience.replication.mode | Enum | Required when the replication block exists | Yes when the block exists | None, ReadReplica, HotStandby, ManagedExternal | TursoLocal currently rejects replication contracts. `ManagedExternal` is meant for provider-managed replica setups. |
| database.resilience.replication.read_routing | Enum | Off | No | Off, Explicit | Only `Explicit` is planned for the first runtime read-routing phase. |
| database.resilience.replication.read_url_env | String | None | Required when `read_routing = Explicit` | Environment variable name | Documents the expected read-replica connection string env var. |
| database.resilience.replication.max_lag | String | None | No | Any non-empty duration-like string such as `30s` | Currently stored as text for planning/doctor output. |
| database.resilience.replication.replicas_expected | u32 | None | No | Positive integer | Documents the expected minimum replica count for validation tooling. |

## Logging

Logging settings are carried into emitted servers and generated projects.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| logging.filter_env | String | RUST_LOG | No | Environment variable name | Used with `env_logger::Env::filter_or`. |
| logging.default_filter | String | info | No | Any env_logger filter string | Fallback when the filter env var is absent. |
| logging.timestamp | Enum | Seconds | No | None, Seconds, Millis, Micros, Nanos | Aliases such as `off`, `sec`, `ms`, `us`, and `ns` are also accepted case-insensitively. |

## Runtime

Runtime settings affect server behavior without changing the data model.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| runtime.compression.enabled | Bool | false | No | true, false | Enables dynamic HTTP response compression middleware in emitted servers. |
| runtime.compression.static_precompressed | Bool | false | No | true, false | Enables `.br` / `.gz` companion lookup for generated static mounts and causes `vsr build` to generate those companion files into `<binary>.bundle/`. |

## TLS

Any configured TLS field enables HTTPS/Rustls support in emitted servers.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| tls.cert_path | String | certs/dev-cert.pem | Required when TLS is enabled unless `tls.cert_path_env` resolves | Relative or absolute PEM path | Relative paths are resolved against the service or bundle base directory. |
| tls.key_path | String | certs/dev-key.pem | Required when TLS is enabled unless `tls.key_path_env` resolves | Relative or absolute PEM path | Relative paths are resolved against the service or bundle base directory. |
| tls.cert_path_env | String | TLS_CERT_PATH | No | Environment variable name | Overrides `tls.cert_path` at runtime when the env var is present. |
| tls.key_path_env | String | TLS_KEY_PATH | No | Environment variable name | Overrides `tls.key_path` at runtime when the env var is present. |

## Security Overview

Every key inside `security` is optional. Unset blocks keep the default open behavior.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| security.requests | Map | No custom extractor limits | No | See Request Security | Currently used for JSON body size limits. |
| security.cors | Map | No custom CORS policy | No | See CORS | Empty methods/headers lists fall back to runtime defaults. |
| security.trusted_proxies | Map | No trusted proxies | No | See Trusted Proxies | Used when extracting the client IP from forwarded headers. |
| security.rate_limits | Map | No auth rate limits | No | See Rate Limits | Currently applies to built-in auth login and register flows. |
| security.headers | Map | No additional security headers | No | See Security Headers | Controls X-Frame-Options, nosniff, Referrer-Policy, and HSTS. |
| security.auth | Map | Built-in auth defaults | No | See Auth Settings | Controls JWT claims, TTLs, email flows, session cookies, and custom UI pages. |

## Request Security

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| security.requests.json_max_bytes | usize | None | No | Positive integer | Sets the generated JSON extractor limit. Must be greater than 0 when provided. |

## CORS

Runtime behavior when lists are empty: methods default to `GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD`; allowed headers default to `authorization, content-type, accept`.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| security.cors.origins | List<String> | [] | No | Absolute origins or `*` | Origins are validated as URIs. `*` cannot be combined with `allow_credentials = true`. |
| security.cors.origins_env | String | None | No | Environment variable name | The runtime splits the env value on commas and appends it to `origins`. |
| security.cors.allow_credentials | Bool | false | No | true, false | Cannot be combined with wildcard `*` origins. |
| security.cors.allow_methods | List<String> | [] | No | HTTP methods or `*` | Methods are validated using Actix/Web HTTP method parsing. |
| security.cors.allow_headers | List<String> | [] | No | Header names or `*` | Header names are validated using HTTP header parsing. |
| security.cors.expose_headers | List<String> | [] | No | Header names or `*` | Header names are validated using HTTP header parsing. |
| security.cors.max_age_seconds | usize | None | No | Positive integer | Must be greater than 0 when provided. |

## Trusted Proxies

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| security.trusted_proxies.proxies | List<String> | [] | No | IP addresses | Every entry must parse as an IP address. |
| security.trusted_proxies.proxies_env | String | None | No | Environment variable name | The runtime splits the env value on commas and appends valid IPs to `proxies`. |

## Rate Limits

Rate-limit rules are currently applied only to built-in auth endpoints.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| security.rate_limits.login.requests | u32 | None | Required when `security.rate_limits.login` is set | Positive integer | Maximum requests allowed per window. |
| security.rate_limits.login.window_seconds | u64 | None | Required when `security.rate_limits.login` is set | Positive integer | Sliding window length in seconds. |
| security.rate_limits.register.requests | u32 | None | Required when `security.rate_limits.register` is set | Positive integer | Maximum requests allowed per window. |
| security.rate_limits.register.window_seconds | u64 | None | Required when `security.rate_limits.register` is set | Positive integer | Sliding window length in seconds. |

## Security Headers

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| security.headers.frame_options | Enum | None | No | Deny, SameOrigin | Accepted aliases include `same-origin` and `same_origin`. |
| security.headers.content_type_options | Bool | false | No | true, false | When true, adds `X-Content-Type-Options: nosniff`. |
| security.headers.referrer_policy | Enum | None | No | NoReferrer, SameOrigin, StrictOriginWhenCrossOrigin, NoReferrerWhenDowngrade, Origin, OriginWhenCrossOrigin, UnsafeUrl | Snake_case and hyphenated aliases are also accepted. |
| security.headers.hsts.max_age_seconds | u64 | None | Required when `security.headers.hsts` is set | Positive integer | Must be greater than 0. |
| security.headers.hsts.include_subdomains | Bool | false | No | true, false | Appends `includeSubDomains` to the HSTS header. |

## Auth Settings

These settings configure the built-in auth/account routes. They do not affect custom resources unless you explicitly use auth-derived claims in row policies.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| security.auth.issuer | String | None | No | JWT issuer string | Included in generated JWTs and enforced during token validation when set. |
| security.auth.audience | String | None | No | JWT audience string | Included in generated JWTs and enforced during token validation when set. |
| security.auth.access_token_ttl_seconds | i64 | 86400 | No | Positive integer | Access-token lifetime in seconds. |
| security.auth.require_email_verification | Bool | false | No | true, false | When true, registration/login flows require email verification and `security.auth.email` must also be configured. |
| security.auth.verification_token_ttl_seconds | i64 | 86400 | No | Positive integer | Verification-token lifetime in seconds. |
| security.auth.password_reset_token_ttl_seconds | i64 | 3600 | No | Positive integer | Password-reset token lifetime in seconds. |
| security.auth.claims | Map<ClaimName, ClaimMapping> | None | No | Keyed map of claim names to claim mappings | Makes built-in auth claims explicit. Claim names must be unique and cannot use reserved fields such as `sub`, `roles`, `iss`, `aud`, `exp`, or `id`. |
| security.auth.session_cookie | Map | None | No | See Session Cookie | Enables cookie-based session auth in addition to bearer tokens. |
| security.auth.email | Map | None | No | See Auth Email | Configures transactional email for verification and password reset flows. |
| security.auth.portal | Map | None | No | See Auth UI Pages | Configures a custom account portal page path and title. |
| security.auth.admin_dashboard | Map | None | No | See Auth UI Pages | Configures a custom admin dashboard page path and title. |

```eon
security: {
    auth: {
        claims: {
            tenant_id: I64
            workspace_id: "claim_workspace_id"
            staff: { column: "is_staff", type: Bool }
            plan: String
        }
    }
}
```

## Auth Claims

Explicit auth claim mappings let built-in auth expose predictable claim names without relying entirely on implicit `_id` / `claim_<name>` discovery. The keyed map name is the emitted JWT claim name. For `.eon` services, `vsr setup` also extends the built-in `user` table with those mapped columns automatically before admin creation. Use this for stable user/session attributes; use the `authorization` contract and runtime authz tables for permissions or scoped grants.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| security.auth.claims.<claim_name> | I64 \| String \| Bool \| String column name \| Map | If shorthand type is used, the column defaults to `<claim_name>` and the type defaults to the shorthand | No | `tenant_id: I64`, `workspace_id: "claim_workspace_id"`, or a full object | String shorthand means `column = <string>` with the default type `I64`. Use the object form when you need a non-`I64` type on a different column. |
| security.auth.claims.<claim_name>.column | String | The claim key name | No | SQL identifier in the built-in `user` table | When omitted in the object form, the claim key is also used as the column name. |
| security.auth.claims.<claim_name>.type | Enum | I64 | No | I64, String, Bool | Controls how built-in auth decodes the `user` column and exposes it in JWTs and `/api/auth/me`. |

Current runtime boundary:

- Row policies can consume explicit `I64`, `String`, and `Bool` claims when the target field uses the matching type.
- When `security.auth.claims` is configured, non-legacy `claim.<name>` references in row policies must be declared there.
- Legacy undeclared `claim.<name>` usage still only works for numeric `*_id` claims.

## Session Cookie

Cookie-session auth is opt-in. Once the block exists, defaults are filled for any omitted keys.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| security.auth.session_cookie.name | String | vsr_session | No | Cookie name | Cannot be empty. `__Host-` prefixed names require `secure = true` and `path = "/"`. |
| security.auth.session_cookie.csrf_cookie_name | String | vsr_csrf | No | Cookie name | Must differ from `name`. `__Host-` prefix has the same constraints as the main cookie. |
| security.auth.session_cookie.csrf_header_name | String | x-csrf-token | No | HTTP header name | Used for CSRF validation on non-safe HTTP methods. |
| security.auth.session_cookie.path | String | / | No | Cookie path beginning with `/` | Must start with `/`. |
| security.auth.session_cookie.secure | Bool | true | No | true, false | Must be true when `same_site = None`. |
| security.auth.session_cookie.same_site | Enum | Strict | No | Strict, Lax, None | Parsed case-insensitively using lowercase/string aliases. |

## Auth Email

This block is required when email verification is mandatory.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| security.auth.email.from_email | String | None | Yes when the block is present | Email-like string | Must contain `@`. |
| security.auth.email.from_name | String | None | No | Display name | Optional sender display name. |
| security.auth.email.reply_to | String | None | No | Email-like string | Cannot be empty when provided. |
| security.auth.email.public_base_url | String | None | No | Absolute URL | Used when generating absolute links in auth emails. |
| security.auth.email.provider | Map | None | Yes when the block is present | See Auth Email Provider | Selects the outbound email provider implementation. |

## Auth Email Provider

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| security.auth.email.provider.kind | Enum | None | Yes | Resend, Smtp | Parsed case-insensitively. |
| security.auth.email.provider.api_key_env | String | None | Required for `kind = Resend` | Environment variable name | Loaded from `<VAR>` or `<VAR>_FILE` by the runtime. |
| security.auth.email.provider.api_base_url | String | None | No | Absolute URL | Optional override for the Resend API base URL. |
| security.auth.email.provider.connection_url_env | String | None | Required for `kind = Smtp` | Environment variable name | Expected to resolve to an SMTP connection URL for lettre. |

## Auth UI Pages

Custom auth UI pages must not collide with built-in auth routes and each path must be unique.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| security.auth.portal.path | String | None | Yes when the block is present | Absolute path beginning with `/` | Cannot be empty or conflict with built-in auth paths such as `/auth/login`. |
| security.auth.portal.title | String | Account Portal | No | Display title | Defaults to `Account Portal` when omitted. |
| security.auth.admin_dashboard.path | String | None | Yes when the block is present | Absolute path beginning with `/` | Cannot be empty or conflict with built-in auth paths such as `/auth/login`. |
| security.auth.admin_dashboard.title | String | Admin Dashboard | No | Display title | Defaults to `Admin Dashboard` when omitted. |

## Field Types

These are the canonical built-in field type keywords accepted by `.eon`. Raw Rust type strings are also allowed.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| String | Rust field type | n/a | n/a | String | Stored as `TEXT`. Supports equality filters, `contains`, and sort. |
| I32 | Rust field type | n/a | n/a | i32 | Stored as `INTEGER`. Supports equality filters and sort. |
| I64 | Rust field type | n/a | n/a | i64 | Stored as `INTEGER`. Supports equality filters and sort. |
| F32 | Rust field type | n/a | n/a | f32 | Stored as `REAL`. Supports equality filters and sort. |
| F64 | Rust field type | n/a | n/a | f64 | Stored as `REAL`. Supports equality filters and sort. |
| Bool | Rust field type | n/a | n/a | bool | Stored as `INTEGER` on SQLite/MySQL and `BOOLEAN` on Postgres. Supports equality filters and sort. |
| DateTime | Rust field type | n/a | n/a | chrono::DateTime<Utc> | Stored as text-compatible values. Supports equality filters, range filters, and sort. |
| Date | Rust field type | n/a | n/a | chrono::NaiveDate | Stored as text-compatible values. Supports equality filters, range filters, and sort. |
| Time | Rust field type | n/a | n/a | chrono::NaiveTime | Stored as text-compatible values. Supports equality filters, range filters, and sort. |
| Uuid | Rust field type | n/a | n/a | uuid::Uuid | Stored as text/char values depending on backend. Supports equality filters and sort. |
| Decimal | Rust field type | n/a | n/a | rust_decimal::Decimal | Stored as text/varchar values. Supports equality filters but not generated sort helpers. |
| <DeclaredEnumName> | Named enum field type | n/a | n/a | Any name declared under `enums` | Stored as text and validated against the declared string values. Supports exact filters and the normal string sort helpers, but not contains filters. |
| Json | Rust field type | n/a | n/a | serde_json::Value | Stored as JSON text. Round-trips through the API as native JSON, but current generated/native list helpers do not expose equality, range, or contains filters for it. |
| JsonObject | Rust field type | n/a | n/a | serde_json::Value | Stored as JSON text and validated to be a JSON object. OpenAPI emits it as an object schema. Current list helpers do not expose equality, range, or contains filters for it. |
| JsonArray | Rust field type | n/a | n/a | serde_json::Value | Stored as JSON text and validated to be a JSON array. OpenAPI emits it as an array schema. Current list helpers do not expose equality, range, or contains filters for it. |
| List | Built-in collection field type | n/a | n/a | Use with `items`, for example `{ type: List, items: I64 }` | Stored as a JSON array encoded in text. OpenAPI emits an array schema based on `items`. Current generated/native list helpers do not expose equality, range, or contains filters for `List` fields. |
| Object | Built-in structured field type | n/a | n/a | Use with `fields`, for example `{ type: Object, fields: [{ name: "raw", type: String }] }` | Stored as a JSON object encoded in text. Nested fields are validated recursively in generated handlers and native `vsr serve`, and OpenAPI emits a closed object schema with nested properties. |
| "<raw Rust type>" | Rust field type | n/a | n/a | Any type parsable by `syn` | SQL type inference is best-effort. Structured-scalar-specific validation and filter helpers only apply to the built-in scalar keywords above. |

## Derived Behavior

These behaviors are not separate config keys, but they are part of the current `.eon` contract.

| Path | Type / Shape | Default | Required | Accepted Values | Notes |
| --- | --- | --- | --- | --- | --- |
| Resource naming | Derived rule | n/a | n/a | n/a | Resource names sanitize to Rust struct identifiers; table names default to the snake_case resource name. |
| ID handling | Derived rule | n/a | n/a | n/a | The field matching `id_field` is treated as the resource ID even if `id: true` is omitted. |
| Generated fields | Derived rule | n/a | n/a | n/a | Generated fields (`AutoIncrement`, `CreatedAt`, `UpdatedAt`) become optional in generated Rust types and are skipped from normal write payloads. |
| Field map shorthand | Derived rule | n/a | n/a | n/a | A field map entry like `title: String` is equivalent to `{ name: "title", type: String, nullable: false, id: false, generated: None }`. |
| Static SPA defaults | Derived rule | n/a | n/a | n/a | SPA mounts default both `index_file` and `fallback_file` to `index.html`. |
| SQLite runtime defaults | Derived rule | n/a | n/a | n/a | When `db: Sqlite` and `database.engine` is omitted, the runtime defaults to `TursoLocal(var/data/<module>.db)` with encrypted-local support via `TURSO_ENCRYPTION_KEY`. |
| Static precompression | Derived rule | n/a | n/a | n/a | When `runtime.compression.static_precompressed = true`, generated static mounts serve `.br`/`.gz` companion assets and `vsr build` generates those companions into the sidecar bundle. |

## Examples

### Minimal service

```eon
module: "blog_api"
resources: [
    {
        name: "Post"
        fields: [
            { name: "id", type: I64 }
            { name: "title", type: String }
            { name: "published", type: Bool }
        ]
    }
]
```

### Map-based resource and field syntax

```eon
resources: {
    Post: {
        list: { default_limit: 20, max_limit: 100 }
        fields: {
            id: { type: I64, id: true }
            title: { type: String, validate: { min_length: 3, max_length: 120 } }
            created_at: { type: DateTime, generated: CreatedAt }
        }
    }
}
```

### Service-level runtime, static, and security config

```eon
runtime: {
    compression: {
        enabled: true
        static_precompressed: true
    }
}
static: {
    mounts: [
        {
            mount: "/"
            dir: "web/dist"
            mode: Spa
            cache: NoStore
        }
        {
            mount: "/assets"
            dir: "web/dist/assets"
            mode: Directory
            cache: Immutable
        }
    ]
}
security: {
    requests: { json_max_bytes: 1048576 }
    cors: {
        origins: ["https://app.example.com"]
        allow_credentials: true
    }
    auth: {
        issuer: "vsr"
        session_cookie: { same_site: Strict }
    }
}
```

