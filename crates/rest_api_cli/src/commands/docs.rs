use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use colored::Colorize;
use rest_macro_core::{
    auth::{AuthSettings, SessionCookieSettings},
    database::DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV,
    logging::LoggingConfig,
    tls::{
        DEFAULT_TLS_CERT_PATH, DEFAULT_TLS_CERT_PATH_ENV, DEFAULT_TLS_KEY_PATH,
        DEFAULT_TLS_KEY_PATH_ENV,
    },
};

pub fn generate_eon_reference(output: &Path, force: bool) -> Result<()> {
    if output.exists() && !force {
        bail!(
            "Markdown file already exists at {} (use --force to overwrite)",
            output.display()
        );
    }

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    fs::write(output, render_eon_reference_markdown())
        .with_context(|| format!("failed to write Markdown to {}", output.display()))?;

    println!(
        "{} {}",
        "Generated `.eon` reference docs:".green().bold(),
        output.display()
    );

    Ok(())
}

pub fn render_eon_reference_markdown() -> String {
    let logging_defaults = LoggingConfig::default();
    let auth_defaults = AuthSettings::default();
    let session_cookie_defaults = SessionCookieSettings::default();

    let mut markdown = String::new();
    markdown.push_str("# `.eon` Configuration Reference\n\n");
    markdown.push_str(
        "This document maps the currently supported `.eon` configuration surface in \
`very_simple_rest` / `vsr`. It is intended to be machine-scannable for AI agents and readable \
for humans.\n\n",
    );
    markdown.push_str(
        "Generated with `vsr docs --output <file.md>`.\n\n\
Current parser guarantees covered here:\n\n\
- service-level configuration blocks\n\
- resource and field list syntax\n\
- resource and field keyed-map syntax\n\
- shorthand field type syntax in field maps\n\
- current validation rules, defaults, and derived behavior\n\n",
    );

    push_section(
        &mut markdown,
        "Supported Input Shapes",
        "The parser accepts both the original list-based syntax and the newer keyed-map syntax \
for resources and fields.",
        &[
            row(
                "resources",
                "List<Resource> or Map<ResourceName, Resource>",
                "Required",
                "Yes",
                "List entries or keyed map entries",
                "Resource names must be unique. In map form the key is the canonical resource name. \
If `name` is also present inside the value, it must match the key.",
            ),
            row(
                "resources[].fields",
                "List<Field> or Map<FieldName, Field | Type>",
                "Required",
                "Yes",
                "List entries, keyed objects, or shorthand type values",
                "Field names must be unique per resource. In map form the value may be a full field \
object or just a type such as `title: String`.",
            ),
            row(
                "resources.<resource>.fields.<field>",
                "Field object or scalar type",
                "Shorthand defaults to a non-null, non-id, non-generated field",
                "No",
                "`String`, `I64`, `Bool`, or any other supported field type",
                "Map shorthand is only available for field maps, not list entries.",
            ),
        ],
    );

    push_code_block(
        &mut markdown,
        "eon",
        r#"resources: {
    Post: {
        fields: {
            id: { type: I64, id: true }
            title: String
            published: { type: Bool }
        }
    }
}"#,
    );

    push_section(
        &mut markdown,
        "Top-Level Keys",
        "These keys are read from the service root.",
        &[
            row(
                "module",
                "String",
                "The `.eon` file stem, sanitized to a Rust module identifier",
                "No",
                "Any non-empty string",
                "Controls the generated Rust module name.",
            ),
            row(
                "db",
                "Enum",
                "Sqlite",
                "No",
                "Sqlite, Postgres, Mysql",
                "Selects the SQL dialect and resource backend used for generated SQL and handlers.",
            ),
            row(
                "database",
                "Map",
                "Backend-dependent runtime engine defaults",
                "No",
                "See Database Engine and Resilience",
                "Overrides the runtime database engine and can declare backup/replication posture without changing the resource SQL dialect.",
            ),
            row(
                "logging",
                "Map",
                "Enabled with built-in defaults",
                "No",
                "See Logging",
                "Controls the emitted server logger configuration.",
            ),
            row(
                "build",
                "Map",
                "No emitted build-profile overrides",
                "No",
                "See Build",
                "Controls generated release build profile settings and optional local-machine CPU tuning for emitted server projects.",
            ),
            row(
                "runtime",
                "Map",
                "Compression disabled",
                "No",
                "See Runtime",
                "Controls runtime-only behavior such as HTTP compression.",
            ),
            row(
                "authorization",
                "Map",
                "No static authorization contract",
                "No",
                "See Authorization Contract",
                "Declares optional static scopes, permissions, and templates for the compiled authorization model.",
            ),
            row(
                "tls",
                "Map",
                "Disabled unless the block is present",
                "No",
                "See TLS",
                "Any configured TLS field enables HTTPS/Rustls handling in emitted servers.",
            ),
            row(
                "static",
                "Map",
                "No static mounts",
                "No",
                "See Static Mounts",
                "Declares filesystem-backed static directories and SPA mounts.",
            ),
            row(
                "security",
                "Map",
                "All optional features off / empty",
                "No",
                "See Security",
                "Controls request limits, CORS, trusted proxies, auth settings, headers, and rate limits.",
            ),
            row(
                "enums",
                "List<Enum> or Map<EnumName, Enum | List<String>>",
                "None",
                "No",
                "Named enum definitions",
                "Declares reusable string-enum vocabularies that fields can reference by name.",
            ),
            row(
                "mixins",
                "List<Mixin> or Map<MixinName, Mixin>",
                "None",
                "No",
                "Named local mixin definitions",
                "Declares reusable local field/index bundles that resources can expand with `use`.",
            ),
            row(
                "resources",
                "List or keyed map",
                "None",
                "Yes",
                "Resource definitions",
                "A service must contain at least one resource.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Enums",
        "The optional `enums` block declares reusable string-enum vocabularies for field definitions.",
        &[
            row(
                "enums.<enum_name>.name",
                "String",
                "Required in list form; implied by the key in map form",
                "Yes in list form",
                "Valid Rust identifier",
                "Enum names must be unique and are referenced from `resources[].fields[].type`.",
            ),
            row(
                "enums.<enum_name>.values",
                "List<String>",
                "Required when the enum exists",
                "Yes",
                "One or more unique string values",
                "Enum values are validated at request time and emitted in OpenAPI schemas and exact-filter parameters.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Mixins",
        "The optional `mixins` block declares reusable local field/index bundles. The first slice is intentionally local-only and deterministic: resources expand mixins with `use`, and duplicate fields or indexes after expansion are rejected.",
        &[
            row(
                "mixins.<mixin_name>.name",
                "String",
                "Required in list form; implied by the key in map form",
                "Yes in list form",
                "Valid Rust identifier",
                "Mixin names must be unique within the `.eon` file and are referenced from `resources[].use`.",
            ),
            row(
                "mixins.<mixin_name>.fields",
                "List<Field> or Map<FieldName, Field | Type>",
                "[]",
                "No",
                "Field definitions",
                "Expanded into each resource that references the mixin. Resource-local fields are appended after mixin fields.",
            ),
            row(
                "mixins.<mixin_name>.indexes",
                "List<Index>",
                "[]",
                "No",
                "See Indexes",
                "Expanded into each resource that references the mixin after the mixin fields are added. In the first slice, mixin indexes must reference fields declared by the same mixin.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Authorization Contract",
        "The optional `authorization` block declares static scope, permission, template, hybrid-enforcement, and management-surface vocabulary. The scope/permission/template declarations are compiled into the authorization model and available through `vsr authz explain`; request-time behavior changes only when you explicitly enable the generated runtime management API or hybrid enforcement.",
        &[
            row(
                "authorization.management_api",
                "Map",
                "Disabled",
                "No",
                "See Authorization Management API",
                "Opt-in generated runtime authorization management routes for modules and emitted servers.",
            ),
            row(
                "authorization.scopes",
                "Map<ScopeName, Scope>",
                "None",
                "No",
                "Keyed scope map",
                "Scope names must be unique valid identifiers. Use this to declare hierarchical authorization scope vocabulary.",
            ),
            row(
                "authorization.permissions",
                "Map<PermissionName, Permission>",
                "None",
                "No",
                "Keyed permission map",
                "Permission names must be unique valid identifiers. Each permission must declare at least one action and one resource.",
            ),
            row(
                "authorization.templates",
                "Map<TemplateName, Template>",
                "None",
                "No",
                "Keyed template map",
                "Template names must be unique valid identifiers. Templates currently reference permissions and scopes only.",
            ),
            row(
                "authorization.hybrid_enforcement",
                "Map",
                "None",
                "No",
                "See Authorization Hybrid Enforcement",
                "Opt-in additive runtime grant checks for generated item-scoped CRUD handlers.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Authorization Hybrid Enforcement",
        "Hybrid enforcement lets generated handlers consult runtime scoped grants after static role and row-policy checks fail. `scope_field` still names the canonical scope value source, while `scope_sources` explicitly declares which request shapes may derive scope from it. When `scope_sources` is omitted, current defaults preserve the existing behavior for the configured actions.",
        &[
            row(
                "authorization.hybrid_enforcement.resources",
                "Map<ResourceName, HybridResource>",
                "None",
                "No",
                "Keyed resource map",
                "Each entry must reference a declared resource, declared scope, and at least one matching permission action.",
            ),
            row(
                "authorization.hybrid_enforcement.resources.<resource>.scope",
                "String",
                "Required",
                "Yes",
                "Declared scope name such as `Family`",
                "Runtime grants are evaluated against this scope for the configured resource.",
            ),
            row(
                "authorization.hybrid_enforcement.resources.<resource>.scope_field",
                "String",
                "Required",
                "Yes",
                "Declared resource field name such as `family_id`",
                "The generated handler derives the runtime scope value from this row field.",
            ),
            row(
                "authorization.hybrid_enforcement.resources.<resource>.scope_sources",
                "Map",
                "Action-derived defaults",
                "No",
                "See Hybrid Scope Sources",
                "Explicitly declares which request shapes may derive scope from `scope_field`. Omit it to keep the current action-based defaults.",
            ),
            row(
                "authorization.hybrid_enforcement.resources.<resource>.scope_sources.item",
                "Bool",
                "true for `Read`/`Update`/`Delete`",
                "No",
                "true, false",
                "Enables row-derived scope for item routes and created-response fallback. `Update` and `Delete` require this source.",
            ),
            row(
                "authorization.hybrid_enforcement.resources.<resource>.scope_sources.collection_filter",
                "Bool",
                "true for `Read`",
                "No",
                "true, false",
                "Enables top-level collection `Read` when the request includes an exact `filter_<scope_field>` value.",
            ),
            row(
                "authorization.hybrid_enforcement.resources.<resource>.scope_sources.nested_parent",
                "Bool",
                "true for `Read`",
                "No",
                "true, false",
                "Enables nested collection `Read` when the nested parent filter targets `scope_field`.",
            ),
            row(
                "authorization.hybrid_enforcement.resources.<resource>.scope_sources.create_payload",
                "Bool",
                "true for `Create`",
                "No",
                "true, false",
                "Enables the create-payload fallback for claim-controlled `policies.create` scope fields. `Create` requires this source.",
            ),
            row(
                "authorization.hybrid_enforcement.resources.<resource>.actions",
                "[Action]",
                "Required",
                "Yes",
                "Create, Read, Update, Delete",
                "`Read`, `Update`, and `Delete` require matching static row policies to supplement. `Create` is allowed only when `scope_field` is already claim-controlled by `policies.create`.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Authorization Management API",
        "When enabled, generated modules and emitted servers automatically mount the runtime authorization management endpoints under the configured path.",
        &[
            row(
                "authorization.management_api.enabled",
                "Bool",
                "true when the block exists; otherwise disabled",
                "No",
                "true, false",
                "Controls whether generated `configure(...)` mounts the runtime authorization management routes automatically.",
            ),
            row(
                "authorization.management_api.mount",
                "String",
                "`/authz/runtime`",
                "No",
                "Absolute route path such as `/authz/runtime` or `/ops/authz`",
                "Must start with `/`. Trailing `/` is normalized away. The mounted endpoints are `<mount>/evaluate`, `<mount>/assignment-events`, `<mount>/assignments`, `<mount>/assignments/{id}`, `<mount>/assignments/{id}/revoke`, and `<mount>/assignments/{id}/renew`.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Authorization Scopes",
        "Scopes define named authorization boundaries and optional parent relationships.",
        &[
            row(
                "authorization.scopes.<scope_name>.description",
                "String",
                "None",
                "No",
                "Any non-empty string",
                "Optional human-readable description for tooling and docs.",
            ),
            row(
                "authorization.scopes.<scope_name>.parent",
                "String",
                "None",
                "No",
                "Another declared scope name",
                "Parent scopes must exist and cannot form cycles.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Authorization Permissions",
        "Permissions declare which resource actions belong to a named permission.",
        &[
            row(
                "authorization.permissions.<permission_name>.description",
                "String",
                "None",
                "No",
                "Any non-empty string",
                "Optional human-readable description for tooling and docs.",
            ),
            row(
                "authorization.permissions.<permission_name>.actions",
                "[Action]",
                "Required when the permission exists",
                "Yes",
                "Read, Create, Update, Delete",
                "At least one action is required.",
            ),
            row(
                "authorization.permissions.<permission_name>.resources",
                "[String]",
                "Required when the permission exists",
                "Yes",
                "Declared resource names such as `Post` or `ScopedDoc`",
                "At least one resource is required. References must match declared `.eon` resources.",
            ),
            row(
                "authorization.permissions.<permission_name>.scopes",
                "[String]",
                "None",
                "No",
                "Declared scope names",
                "Optional static scope hints for future runtime-managed authorization layers.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Authorization Templates",
        "Templates group permissions and optional scopes into reusable named bundles.",
        &[
            row(
                "authorization.templates.<template_name>.description",
                "String",
                "None",
                "No",
                "Any non-empty string",
                "Optional human-readable description for tooling and docs.",
            ),
            row(
                "authorization.templates.<template_name>.permissions",
                "[String]",
                "Required when the template exists",
                "Yes",
                "Declared permission names",
                "At least one permission is required.",
            ),
            row(
                "authorization.templates.<template_name>.scopes",
                "[String]",
                "None",
                "No",
                "Declared scope names",
                "Optional static scope hints attached to the template.",
            ),
        ],
    );

    push_code_block(
        &mut markdown,
        "eon",
        r#"authorization: {
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
}"#,
    );

    push_section(
        &mut markdown,
        "Resource Keys",
        "Each resource describes one generated REST model and its CRUD surface.",
        &[
            row(
                "resources[].name",
                "String",
                "Required in list form; implied by the key in map form",
                "Yes in list form",
                "Any name that can sanitize to a Rust struct identifier",
                "The generated Rust struct uses UpperCamelCase. Duplicate names are rejected after sanitization.",
            ),
            row(
                "resources[].table",
                "String",
                "The snake_case form of `name`",
                "No",
                "Valid SQL identifier",
                "Controls the SQL table name and API path segment.",
            ),
            row(
                "resources[].api_name",
                "String",
                "The resolved table name",
                "No",
                "Valid API path segment",
                "Overrides the public collection/item route segment without changing the storage table name.",
            ),
            row(
                "resources[].id_field",
                "String",
                "`id`",
                "No",
                "Field name",
                "The named field must exist on the resource.",
            ),
            row(
                "resources[].roles",
                "Map",
                "No role checks",
                "No",
                "See Resource Roles",
                "Declares coarse role gates for read/create/update/delete.",
            ),
            row(
                "resources[].policies",
                "Map",
                "`admin_bypass = true`; no row policies",
                "No",
                "See Row Policies",
                "Declares row-level filters and assignments using `user.id` or `claim.<name>` sources.",
            ),
            row(
                "resources[].list",
                "Map",
                "No custom limit caps",
                "No",
                "See List Settings",
                "Controls generated list endpoint defaults and hard caps.",
            ),
            row(
                "resources[].api",
                "Map",
                "No API projection or response contexts",
                "No",
                "See Resource API",
                "Separates the public API field surface from storage fields and can define named response contexts.",
            ),
            row(
                "resources[].use",
                "List<String>",
                "[]",
                "No",
                "Declared mixin names",
                "Expands the listed local mixins into the resource before normal field/index validation. Using the same mixin more than once is rejected.",
            ),
            row(
                "resources[].indexes",
                "List<Index>",
                "No explicit indexes",
                "No",
                "See Indexes",
                "Declares explicit single-field or composite indexes in addition to the automatic relation and policy-derived index hints.",
            ),
            row(
                "resources[].many_to_many",
                "List<ManyToMany>",
                "No declared many-to-many routes",
                "No",
                "See Many-to-Many",
                "Declares read-side collection routes over an explicit join resource without changing the underlying storage schema.",
            ),
            row(
                "resources[].actions",
                "List<Action>",
                "No declared custom actions",
                "No",
                "See Resource Actions",
                "Declares additional resource-scoped routes. The current slice supports item-scoped `POST` actions with declarative `UpdateFields` or `DeleteResource` behaviors.",
            ),
            row(
                "resources[].fields",
                "List or keyed map",
                "None",
                "Yes",
                "Field definitions",
                "Each resource must define its fields explicitly.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Resource API",
        "The optional `api` block lets a resource expose a different public field surface from its storage fields, add response-only computed fields, and declare named response contexts over that public surface.",
        &[
            row(
                "resources[].api.fields",
                "List<ApiFieldProjection> or Map<ApiFieldName, String | ApiFieldProjection>",
                "Expose every field by its storage name",
                "No",
                "Projection definitions",
                "When present, only the declared API fields are exposed. Storage-backed entries map one API field name to one storage field via `from`, while computed entries use `template` to interpolate already-exposed scalar API fields at response time.",
            ),
            row(
                "resources[].api.default_context",
                "String",
                "No default context; responses use the full projected API field set",
                "No",
                "Configured context name",
                "When set, list/get/create responses default to that named context unless a `context` query parameter overrides it.",
            ),
            row(
                "resources[].api.contexts",
                "List<ResponseContext> or Map<ContextName, ResponseContext | List<String>>",
                "No named response contexts",
                "No",
                "Named context definitions",
                "Each context is a subset of exposed API field names. Generated handlers and native `vsr serve` apply the selected context at response serialization time.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Computed API Fields",
        "Computed API fields are response-only fields declared inside `resources[].api.fields`. They are not writable, sortable, or filterable, and they do not affect migrations.",
        &[
            row(
                "resources[].api.fields[].from",
                "String",
                "None",
                "No",
                "Storage field name",
                "Maps one public API field name to one storage field. Exactly one of `from` or `template` must be set.",
            ),
            row(
                "resources[].api.fields[].template",
                "String",
                "None",
                "No",
                "Template string like `/posts/{slug}`",
                "Interpolates already-exposed scalar API fields by name. If any referenced field is nullable and resolves to `null`, the computed field becomes `null`.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Response Contexts",
        "Response contexts are named subsets of already-exposed API fields. They currently affect list/get/create response bodies and can be selected with `?context=<name>`.",
        &[
            row(
                "resources[].api.contexts[].name",
                "String",
                "Required in list form; implied by the key in map form",
                "Yes in list form",
                "Valid API identifier",
                "Context names must be unique per resource and are exposed through OpenAPI as the `context` query parameter enum.",
            ),
            row(
                "resources[].api.contexts[].fields",
                "List<String>",
                "[]",
                "No",
                "Exposed API field names",
                "Every listed field must already be exposed on the resource API surface, either directly or through `api.fields` projection.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Resource Access",
        "Resource access controls whether reads stay legacy/inferred, become explicitly public, or require any authenticated user even without a role.",
        &[row(
            "resources[].access.read",
            "String",
            "`inferred`",
            "No",
            "`inferred`, `public`, or `authenticated`",
            "Use `public` for anonymous reads and `authenticated` to require a valid user token/session without a specific role. `public` cannot be combined with `roles.read` or `user.*` / `claim.*` read row policies.",
        )],
    );

    push_section(
        &mut markdown,
        "Resource Roles",
        "Role checks are string comparisons against the authenticated user's role list.",
        &[
            row(
                "resources[].roles.read",
                "String",
                "None",
                "No",
                "Role name",
                "When set, reads require the named role.",
            ),
            row(
                "resources[].roles.create",
                "String",
                "Falls back to `roles.update` when `create` is omitted and `update` is set",
                "No",
                "Role name",
                "Write-role compatibility with the original shorthand is preserved.",
            ),
            row(
                "resources[].roles.update",
                "String",
                "None",
                "No",
                "Role name",
                "When set, updates require the named role.",
            ),
            row(
                "resources[].roles.delete",
                "String",
                "None",
                "No",
                "Role name",
                "When set, deletes require the named role.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "List Settings",
        "List settings tune generated list endpoint defaults.",
        &[
            row(
                "resources[].list.default_limit",
                "u32",
                "None",
                "No",
                "Positive integer",
                "Must be greater than 0. If both limits are set, `default_limit <= max_limit`.",
            ),
            row(
                "resources[].list.max_limit",
                "u32",
                "None",
                "No",
                "Positive integer",
                "Must be greater than 0.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Indexes",
        "Resources can declare explicit indexes, while generated migrations and live-schema checks still infer additional non-unique indexes from relations and row-policy fields.",
        &[
            row(
                "resources[].indexes[].fields",
                "List<String>",
                "Required when the index exists",
                "Yes",
                "One or more storage field names",
                "Field names reference storage columns, not API projection aliases. Composite indexes preserve the configured field order.",
            ),
            row(
                "resources[].indexes[].unique",
                "Bool",
                "false",
                "No",
                "true, false",
                "When true, generated migrations emit `CREATE UNIQUE INDEX ...` for the configured field list.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Many-to-Many",
        "Many-to-many definitions currently describe read-side nested collection routes over an explicit join resource. The join table is still modeled as a normal resource with two FK fields; `many_to_many` adds the higher-level route metadata.",
        &[
            row(
                "resources[].many_to_many[].name",
                "String",
                "Required",
                "Yes",
                "Valid API path segment",
                "Becomes the trailing nested route segment, for example `/{parent}/{id}/{name}`.",
            ),
            row(
                "resources[].many_to_many[].target",
                "String",
                "Required",
                "Yes",
                "Existing resource name or table name",
                "Names the target resource returned by the nested collection route.",
            ),
            row(
                "resources[].many_to_many[].through",
                "String",
                "Required",
                "Yes",
                "Existing join resource name or table name",
                "Names the explicit join resource that connects the source and target resources.",
            ),
            row(
                "resources[].many_to_many[].source_field",
                "String",
                "Required",
                "Yes",
                "Join resource field name",
                "The named join field must declare a relation back to the source resource ID field.",
            ),
            row(
                "resources[].many_to_many[].target_field",
                "String",
                "Required",
                "Yes",
                "Join resource field name",
                "The named join field must declare a relation to the target resource ID field.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Resource Actions",
        "Resource actions declare extra resource-scoped routes beyond CRUD. The current executable slice is intentionally narrow: item-scoped `POST` routes with declarative `UpdateFields` or `DeleteResource` behaviors that reuse the normal CRUD auth and row-policy semantics.",
        &[
            row(
                "resources[].actions[].name",
                "String",
                "Required",
                "Yes",
                "Valid API identifier",
                "Must be unique per resource. The name is used as the default path segment when `path` is omitted.",
            ),
            row(
                "resources[].actions[].path",
                "String",
                "Defaults to `name`",
                "No",
                "Valid API path segment",
                "Becomes the trailing route segment for item actions, for example `/{resource}/{id}/{path}`.",
            ),
            row(
                "resources[].actions[].target",
                "Enum",
                "Item",
                "No",
                "Item",
                "Only item-scoped actions are supported in the first slice.",
            ),
            row(
                "resources[].actions[].method",
                "Enum",
                "POST",
                "No",
                "POST",
                "Only `POST` is supported in the first slice.",
            ),
            row(
                "resources[].actions[].behavior.kind",
                "Enum",
                "Required",
                "Yes",
                "UpdateFields, DeleteResource",
                "Selects the built-in declarative action behavior.",
            ),
            row(
                "resources[].actions[].behavior.set",
                "Map<String, Scalar | { input: String }>",
                "None",
                "Yes for `UpdateFields`",
                "Storage field names mapped to fixed scalar values or named request-body inputs",
                "Field names reference storage fields, not API projection aliases. The current slice only supports scalar assignment targets, rejects IDs, generated fields, and policy-controlled fields, and applies the normal field transforms and validation rules to fixed values and input-backed assignments alike. Input names become JSON request-body properties for the action route. `DeleteResource` does not accept `behavior.set`.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Row Policies",
        "Row policies support both the newer explicit form and older owner/set-owner shorthands. \
`read`, `update`, and `delete` accept a single filter, an array that implies `all_of`, or an \
explicit boolean group with `all_of`, `any_of`, `not`, and `exists`. `create` supports the \
legacy flat assignment list and an object form with `assign` plus `require`.",
        &[
            row(
                "resources[].policies.admin_bypass",
                "Bool",
                "true",
                "No",
                "true, false",
                "When true, admin-role users bypass the configured row-level policies.",
            ),
            row(
                "resources[].policies.read",
                "PolicyFilter, [PolicyFilter], PolicyGroup",
                "None",
                "No",
                "`field=user.id`, `field=claim.<name>`, `{ field, equals }`, `{ field, is_null: true }`, `{ field, is_not_null: true }`, `Owner:field`, `{ all_of: [...] }`, `{ any_of: [...] }`, `{ not: ... }`, `{ exists: { resource, where } }`",
                "Filters read queries. Arrays imply `all_of`. `exists.where` accepts either leaf comparisons or nested `all_of` / `any_of` / `not` groups; list entries still imply `all_of`. `is_null` and `is_not_null` require a nullable field. `SetOwner` syntax is rejected here.",
            ),
            row(
                "resources[].policies.create",
                "PolicyAssignment, [PolicyAssignment], { assign, require }",
                "None",
                "No",
                "`field=user.id`, `field=claim.<name>`, `{ field, value }`, `SetOwner:field`, `{ assign: [...], require: PolicyFilter | [PolicyFilter] | PolicyGroup }`",
                "Assigns values during create operations and can also enforce preconditions before insert. `require` uses the same boolean filter tree as `read` / `update` / `delete`, plus `input.<field>` sources for the proposed create payload. `Owner` syntax is rejected here.",
            ),
            row(
                "resources[].policies.update",
                "PolicyFilter, [PolicyFilter], PolicyGroup",
                "None",
                "No",
                "`field=user.id`, `field=claim.<name>`, `{ field, equals }`, `{ field, is_null: true }`, `{ field, is_not_null: true }`, `Owner:field`, `{ all_of: [...] }`, `{ any_of: [...] }`, `{ not: ... }`, `{ exists: { resource, where } }`",
                "Filters update queries. Arrays imply `all_of`. `is_null` and `is_not_null` require a nullable field.",
            ),
            row(
                "resources[].policies.delete",
                "PolicyFilter, [PolicyFilter], PolicyGroup",
                "None",
                "No",
                "`field=user.id`, `field=claim.<name>`, `{ field, equals }`, `{ field, is_null: true }`, `{ field, is_not_null: true }`, `Owner:field`, `{ all_of: [...] }`, `{ any_of: [...] }`, `{ not: ... }`, `{ exists: { resource, where } }`",
                "Filters delete queries. Arrays imply `all_of`. `is_null` and `is_not_null` require a nullable field.",
            ),
        ],
    );

    push_code_block(
        &mut markdown,
        "eon",
        r#"policies: {
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
}"#,
    );

    push_code_block(
        &mut markdown,
        "eon",
        r#"create: {
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
}"#,
    );

    markdown.push_str(
        "The first relation-aware filter form is `exists`, which targets another declared \
resource and correlates it with the current row. Leaf `where` entries can be equality checks, \
current-row field correlations, `input.<field>` comparisons for `create.require`, or nullable \
`is_null` / `is_not_null` checks:\n\n",
    );

    push_code_block(
        &mut markdown,
        "eon",
        r#"read: {
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
}"#,
    );

    markdown.push_str(
        "Generated migrations and live-schema checks also treat row-policy fields as index hints. \
That includes direct policy-controlled fields on the current resource and target-resource fields \
referenced by `exists` conditions.\n\n",
    );

    push_section(
        &mut markdown,
        "Field Keys",
        "Field configuration controls generated Rust types, SQL columns, validations, and relations.",
        &[
            row(
                "resources[].fields[].name",
                "String",
                "Required in list form; implied by the key in map form",
                "Yes in list form",
                "Valid Rust identifier",
                "Duplicate field names are rejected per resource.",
            ),
            row(
                "resources[].fields[].type",
                "Enum or raw Rust type string",
                "None",
                "Yes",
                "See Field Types",
                "Supported built-in field type keywords and declared enum names are listed below. Other raw Rust types are parsed with `syn` and inferred to SQL best-effort.",
            ),
            row(
                "resources[].fields[].items",
                "Built-in field type keyword",
                "None",
                "Yes when `type = List`",
                "See Field Types",
                "Required for `List` fields. The current first version accepts built-in item types only and stores the resulting list as JSON text.",
            ),
            row(
                "resources[].fields[].fields",
                "List<Field> or Map<FieldName, Field | Type>",
                "None",
                "Yes when `type = Object`",
                "Nested field definitions",
                "Required for `Object` fields. Nested fields currently support scalar, JSON, nested `Object`, and `List` child shapes and are stored together as a JSON object encoded in text.",
            ),
            row(
                "resources[].fields[].nullable",
                "Bool",
                "false",
                "No",
                "true, false",
                "Wraps the generated Rust field type in `Option<T>`. `generated` fields are also emitted as optional even when `nullable` is false.",
            ),
            row(
                "resources[].fields[].id",
                "Bool",
                "false, but the field matching `id_field` is treated as the ID",
                "No",
                "true, false",
                "Primary key semantics are inferred when the field name matches the resource `id_field`.",
            ),
            row(
                "resources[].fields[].unique",
                "Bool",
                "false",
                "No",
                "true, false",
                "Declares a unique single-column index for supported scalar storage fields. Typed `Object`, `List`, and JSON fields do not support `unique`.",
            ),
            row(
                "resources[].fields[].transforms",
                "List<Enum>",
                "[]",
                "No",
                "Trim, Lowercase, CollapseWhitespace, Slugify",
                "Applies built-in write-time normalization on create and update before validation and persistence. This currently supports text and enum-backed text fields only, including nested text fields inside typed `Object` values. `Slugify` is limited to non-enum text fields.",
            ),
            row(
                "resources[].fields[].generated",
                "Enum",
                "Auto-inferred from the field name and ID role when omitted",
                "No",
                "None, AutoIncrement, CreatedAt, UpdatedAt",
                "If omitted, IDs become `AutoIncrement`, `created_at` becomes `CreatedAt`, and `updated_at` becomes `UpdatedAt`.",
            ),
            row(
                "resources[].fields[].relation",
                "Map",
                "None",
                "No",
                "See Relations",
                "Declares a foreign-key style relationship and optional nested route generation.",
            ),
            row(
                "resources[].fields[].garde",
                "Map",
                "None",
                "No",
                "See Field Validation",
                "Validation is supported for text, integer, real, optional, and list fields where the selected garde rules apply.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Relations",
        "Relations annotate fields that reference another table.",
        &[
            row(
                "resources[].fields[].relation.references",
                "String",
                "None",
                "Yes",
                "`table.field`",
                "Must be exactly one table name and one field name, both valid SQL identifiers.",
            ),
            row(
                "resources[].fields[].relation.on_delete",
                "Enum",
                "None",
                "No",
                "Cascade, Restrict, SetNull, NoAction",
                "Accepted case-insensitive aliases include `set_null`, `set-null`, `no_action`, and `no-action`. `SetNull` requires the field to be nullable.",
            ),
            row(
                "resources[].fields[].relation.nested_route",
                "Bool",
                "false",
                "No",
                "true, false",
                "Enables the generated nested-route behavior for this relation.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Field Validation",
        "Validation is checked at compile time and only certain combinations are allowed.",
        &[
            row(
                "resources[].fields[].garde.length.min",
                "usize",
                "None",
                "No",
                "Non-negative integer",
                "Minimum length for string or list fields. Use `mode: Chars` for character-count string semantics.",
            ),
            row(
                "resources[].fields[].garde.length.max",
                "usize",
                "None",
                "No",
                "Non-negative integer",
                "Maximum length for string or list fields.",
            ),
            row(
                "resources[].fields[].garde.length.equal",
                "usize",
                "None",
                "No",
                "Non-negative integer",
                "Exact length for string or list fields. Cannot be combined with `min`/`max`.",
            ),
            row(
                "resources[].fields[].garde.length.mode",
                "string",
                "None",
                "No",
                "`Simple`, `Bytes`, `Chars`, `Graphemes`, `Utf16`",
                "Length measurement mode. List fields only support `Simple`.",
            ),
            row(
                "resources[].fields[].garde.range.min",
                "i64 or f64",
                "None",
                "No",
                "Integer or float literal",
                "Minimum numeric value for integer and real fields.",
            ),
            row(
                "resources[].fields[].garde.range.max",
                "i64 or f64",
                "None",
                "No",
                "Integer or float literal",
                "Maximum numeric value for integer and real fields.",
            ),
            row(
                "resources[].fields[].garde.range.equal",
                "i64 or f64",
                "None",
                "No",
                "Integer or float literal",
                "Exact numeric value. Cannot be combined with `min`/`max`.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Write-Time Transforms",
        "Write-time transforms normalize request payload values on create and update before validation, policy-driven create requirements, and persistence. They do not change query filter semantics directly; they change the stored value.",
        &[row(
            "resources[].fields[].transforms[]",
            "Enum",
            "None",
            "No",
            "Trim, Lowercase, CollapseWhitespace, Slugify",
            "`Trim` removes leading and trailing Unicode whitespace. `Lowercase` applies Rust string lowercasing. `CollapseWhitespace` collapses all whitespace runs to a single ASCII space. `Slugify` converts non-alphanumeric separators into `-`, lowercases letters, and trims separators from the ends. `Slugify` currently supports non-enum text fields only.",
        )],
    );

    push_section(
        &mut markdown,
        "Static Mounts",
        "Static mounts are resolved relative to the `.eon` file and must stay inside the service directory.",
        &[
            row(
                "static.mounts",
                "List<Mount>",
                "No static mounts",
                "No",
                "Mount objects",
                "Duplicate mount paths are rejected.",
            ),
            row(
                "static.mounts[].mount",
                "String",
                "None",
                "Yes",
                "Absolute URL path beginning with `/`",
                "Cannot conflict with `/api`, `/auth`, `/docs`, or `/openapi.json`. Trailing slashes are normalized except for `/`.",
            ),
            row(
                "static.mounts[].dir",
                "String",
                "None",
                "Yes",
                "Relative directory path",
                "Must resolve under the service root and point to an existing directory.",
            ),
            row(
                "static.mounts[].mode",
                "Enum",
                "Directory",
                "No",
                "Directory, Spa",
                "Case-insensitive parsing is supported. `Spa` auto-defaults `index_file` and `fallback_file` to `index.html`.",
            ),
            row(
                "static.mounts[].index_file",
                "String",
                "None for `Directory`; `index.html` for `Spa`",
                "No",
                "Relative file path",
                "Resolved under the mount directory and must point to an existing file.",
            ),
            row(
                "static.mounts[].fallback_file",
                "String",
                "None for `Directory`; `index.html` for `Spa`",
                "No",
                "Relative file path",
                "Only used for SPA fallback behavior.",
            ),
            row(
                "static.mounts[].cache",
                "Enum",
                "Revalidate",
                "No",
                "NoStore, Revalidate, Immutable",
                "Accepted aliases include `no_store` and `no-store`.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Storage",
        "The optional `storage` block declares named object-storage backends, public read-only mounts, upload endpoints, and a local S3-compatible dev surface. The current runtime supports a local filesystem backend, backed internally by the shared storage runtime, can expose those objects under explicit public URL prefixes, can accept multipart uploads into declared backends, and can mount a narrow path-style S3-compatible API for local workflows without external software.",
        &[
            row(
                "storage.backends",
                "List<Backend>",
                "No storage backends",
                "No",
                "Backend objects",
                "Backend names must be unique.",
            ),
            row(
                "storage.backends[].name",
                "String",
                "None",
                "Yes",
                "Backend name",
                "Referenced by `storage.public_mounts[].backend`.",
            ),
            row(
                "storage.backends[].kind",
                "Enum",
                "None",
                "Yes",
                "Local",
                "The current implementation supports `Local` only.",
            ),
            row(
                "storage.backends[].dir",
                "String",
                "None",
                "Yes",
                "Relative directory path",
                "Resolved relative to the `.eon` file. Unlike static mounts, the directory does not need to exist yet; the runtime creates it when the backend initializes.",
            ),
            row(
                "storage.public_mounts",
                "List<PublicMount>",
                "No public storage mounts",
                "No",
                "Public mount objects",
                "Duplicate mount paths are rejected, and exact collisions with static mounts are rejected too.",
            ),
            row(
                "storage.public_mounts[].mount",
                "String",
                "None",
                "Yes",
                "Absolute URL path beginning with `/`",
                "Cannot conflict with `/api`, `/auth`, `/docs`, or `/openapi.json`.",
            ),
            row(
                "storage.public_mounts[].backend",
                "String",
                "None",
                "Yes",
                "Declared backend name",
                "Must reference one of `storage.backends[].name`.",
            ),
            row(
                "storage.public_mounts[].prefix",
                "String",
                "Empty prefix",
                "No",
                "Relative object key prefix",
                "Prepends a logical key prefix inside the selected backend before mapping requests to objects.",
            ),
            row(
                "storage.public_mounts[].cache",
                "Enum",
                "Revalidate",
                "No",
                "NoStore, Revalidate, Immutable",
                "Uses the same cache semantics as static mounts.",
            ),
            row(
                "storage.uploads",
                "List<Upload>",
                "No upload endpoints",
                "No",
                "Upload endpoint objects",
                "Upload paths live under `/api` and cannot collide with resource route segments or the built-in `/api/auth` namespace.",
            ),
            row(
                "storage.uploads[].name",
                "String",
                "None",
                "Yes",
                "Upload endpoint name",
                "Used for docs/OpenAPI metadata and must be unique.",
            ),
            row(
                "storage.uploads[].path",
                "String",
                "None",
                "Yes",
                "Relative API path segment",
                "Mounted as `POST /api/<path>` and must stay within the API scope.",
            ),
            row(
                "storage.uploads[].backend",
                "String",
                "None",
                "Yes",
                "Declared backend name",
                "Must reference one of `storage.backends[].name`.",
            ),
            row(
                "storage.uploads[].prefix",
                "String",
                "Empty prefix",
                "No",
                "Relative object key prefix",
                "Prepends a logical key prefix before writing uploaded objects into the backend.",
            ),
            row(
                "storage.uploads[].max_bytes",
                "Integer",
                "26214400",
                "No",
                "Positive integer",
                "Maximum accepted multipart file size in bytes.",
            ),
            row(
                "storage.uploads[].require_auth",
                "Bool",
                "true",
                "No",
                "true, false",
                "When `true`, the upload route requires a valid bearer token even if no roles are listed.",
            ),
            row(
                "storage.uploads[].roles",
                "List<String>",
                "No role restriction",
                "No",
                "Role names",
                "If present, the authenticated user must have at least one matching role.",
            ),
            row(
                "storage.s3_compat",
                "Object",
                "Disabled",
                "No",
                "S3-compatible local mount config",
                "Mounts a narrow path-style S3-compatible surface for local development only. The current slice does not validate AWS signatures; clients should use a custom endpoint URL and path-style access.",
            ),
            row(
                "storage.s3_compat.mount",
                "String",
                "\"/_s3\"",
                "No",
                "Absolute URL path beginning with `/`",
                "Mounted outside `/api` so S3-style bucket paths stay clean. Cannot conflict with static mounts, storage public mounts, `/api`, `/auth`, `/docs`, or `/openapi.json`.",
            ),
            row(
                "storage.s3_compat.buckets",
                "List<S3Bucket>",
                "No S3-compatible buckets",
                "No",
                "Bucket objects",
                "Bucket names must be unique within the local S3-compatible surface.",
            ),
            row(
                "storage.s3_compat.buckets[].name",
                "String",
                "None",
                "Yes",
                "Bucket name",
                "Used in path-style URLs like `/_s3/<bucket>/<key>`.",
            ),
            row(
                "storage.s3_compat.buckets[].backend",
                "String",
                "None",
                "Yes",
                "Declared backend name",
                "Must reference one of `storage.backends[].name`.",
            ),
            row(
                "storage.s3_compat.buckets[].prefix",
                "String",
                "Empty prefix",
                "No",
                "Relative object key prefix",
                "Prepends a logical key prefix inside the selected backend before bucket paths are resolved.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Secret References",
        "Typed secret refs let `.eon` declare where a secret should come from without hard-wiring the runtime to plain environment variables. Prefer the typed form for new configs; legacy `*_env` fields still parse for compatibility.",
        &[
            row(
                "<secret>.env",
                "String",
                "None",
                "Exactly one variant is required",
                "Environment variable name",
                "Reads the secret from that exact environment variable only.",
            ),
            row(
                "<secret>.env_or_file",
                "String",
                "None",
                "Exactly one variant is required",
                "Environment variable name",
                "Reads from `<VAR>` or `<VAR>_FILE`. This is the preferred general-purpose runtime form.",
            ),
            row(
                "<secret>.systemd_credential",
                "String",
                "None",
                "Exactly one variant is required",
                "Credential id",
                "Reads from `/run/credentials/<id>` for systemd-style secret delivery.",
            ),
            row(
                "<secret>.external.provider",
                "String",
                "None",
                "Required when using `external`",
                "Provider slug",
                "Declares an external secret-manager contract. Direct runtime resolution is not implemented yet.",
            ),
            row(
                "<secret>.external.locator",
                "String",
                "None",
                "Required when using `external`",
                "Provider-specific secret locator",
                "Stores the provider-specific secret path, name, or locator.",
            ),
        ],
    );

    push_code_block(
        &mut markdown,
        "eon",
        r#"security: {
    auth: {
        jwt_secret: { env_or_file: "JWT_SECRET" }
        email: {
            from_email: "noreply@example.com"
            provider: {
                kind: Resend
                api_key: { systemd_credential: "resend_api_key" }
            }
        }
    }
}

database: {
    engine: {
        kind: TursoLocal
        path: "var/data/app.db"
        encryption_key: { env_or_file: "TURSO_ENCRYPTION_KEY" }
    }
}"#,
    );

    push_section(
        &mut markdown,
        "Database Engine",
        "The top-level `db` controls SQL generation. `database.engine` controls the runtime connection strategy.",
        &[
            row(
                "database.engine.kind",
                "Enum",
                "If omitted: `TursoLocal` for `db: Sqlite`; `Sqlx` for `db: Postgres|Mysql`",
                "No",
                "Sqlx, TursoLocal",
                "Accepted aliases include `turso_local` and `turso-local`. `TursoLocal` requires `db: Sqlite`.",
            ),
            row(
                "database.engine.path",
                "String",
                "For the implicit SQLite runtime engine: `var/data/<module>.db`",
                "Required for explicit `kind = TursoLocal`",
                "Relative path, absolute path, or `:memory:`",
                "The `vsr` runtime resolves relative paths against the service or bundle base directory.",
            ),
            row(
                "database.engine.encryption_key",
                "SecretRef",
                format!(
                    "For the implicit SQLite runtime engine: `{{ env_or_file: \"{}\" }}`",
                    DEFAULT_TURSO_LOCAL_ENCRYPTION_KEY_ENV
                ),
                "No",
                "See Secret References",
                "Used only by `TursoLocal`. Prefer `{ env_or_file: \"...\" }` for runtime-managed file/env secret delivery.",
            ),
            row(
                "database.engine.encryption_key_env",
                "String (legacy)",
                "None",
                "No",
                "Environment variable name",
                "Backward-compatible shorthand for `database.engine.encryption_key: { env_or_file: \"...\" }`.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Database Resilience",
        "The optional `database.resilience` block declares backup, restore-verification, and replication intent. `vsr` can already render plans, run doctor checks, and move local backup artifacts to S3-compatible storage from this contract, but generated servers do not yet enforce replica-aware runtime behavior automatically.",
        &[
            row(
                "database.resilience.profile",
                "Enum",
                "SingleNode when the block exists and `profile` is omitted",
                "No",
                "SingleNode, Pitr, Ha",
                "Use this to describe the intended recovery posture without embedding deployment-specific schedules.",
            ),
            row(
                "database.resilience.backup",
                "Map",
                "None",
                "No",
                "See Database Backup",
                "Declares the intended backup mode, target, restore-verification, and retention posture.",
            ),
            row(
                "database.resilience.replication",
                "Map",
                "None",
                "No",
                "See Database Replication",
                "Declares the intended replica topology and explicit read-routing posture.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Database Backup",
        "Backup settings describe the intended durability posture. They do not schedule jobs directly.",
        &[
            row(
                "database.resilience.backup.required",
                "Bool",
                "true when the backup block exists",
                "No",
                "true, false",
                "Use `false` only when you are documenting a non-critical or externally-managed case explicitly.",
            ),
            row(
                "database.resilience.backup.mode",
                "Enum",
                "By profile/backend: `Pitr` for `profile = Pitr`; otherwise `Snapshot` for SQLite and `Logical` for Postgres/MySQL",
                "No",
                "Snapshot, Logical, Physical, Pitr",
                "SQLite/TursoLocal services can already create local snapshot artifacts from this contract. Postgres/MySQL execution is still planning-oriented.",
            ),
            row(
                "database.resilience.backup.target",
                "Enum",
                "Local",
                "No",
                "Local, S3, Gcs, AzureBlob, Custom",
                "Describes the expected backup destination family. Credentials remain environment-specific.",
            ),
            row(
                "database.resilience.backup.verify_restore",
                "Bool",
                "false",
                "No",
                "true, false",
                "Marks restore verification as part of the required operational posture.",
            ),
            row(
                "database.resilience.backup.max_age",
                "String",
                "None",
                "No",
                "Any non-empty duration-like string such as `24h`",
                "Currently stored as text for planning/doctor output; strict duration parsing is follow-up work.",
            ),
            row(
                "database.resilience.backup.encryption_key",
                "SecretRef",
                "None",
                "No",
                "See Secret References",
                "Documents the expected backup encryption or key-unwrapping secret binding.",
            ),
            row(
                "database.resilience.backup.encryption_key_env",
                "String (legacy)",
                "None",
                "No",
                "Environment variable name",
                "Backward-compatible shorthand for `database.resilience.backup.encryption_key: { env_or_file: \"...\" }`.",
            ),
            row(
                "database.resilience.backup.retention.daily",
                "u32",
                "None",
                "No",
                "Positive integer",
                "Optional daily retention target.",
            ),
            row(
                "database.resilience.backup.retention.weekly",
                "u32",
                "None",
                "No",
                "Positive integer",
                "Optional weekly retention target.",
            ),
            row(
                "database.resilience.backup.retention.monthly",
                "u32",
                "None",
                "No",
                "Positive integer",
                "Optional monthly retention target.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Database Replication",
        "Replication settings declare explicit primary/read topology intent. Generated servers do not yet auto-route reads based on this block.",
        &[
            row(
                "database.resilience.replication.mode",
                "Enum",
                "Required when the replication block exists",
                "Yes when the block exists",
                "None, ReadReplica, HotStandby, ManagedExternal",
                "TursoLocal currently rejects replication contracts. `ManagedExternal` is meant for provider-managed replica setups.",
            ),
            row(
                "database.resilience.replication.read_routing",
                "Enum",
                "Off",
                "No",
                "Off, Explicit",
                "Only `Explicit` is planned for the first runtime read-routing phase.",
            ),
            row(
                "database.resilience.replication.read_url",
                "SecretRef",
                "None",
                "Required when `read_routing = Explicit`",
                "See Secret References",
                "Documents the expected explicit read-replica connection string binding.",
            ),
            row(
                "database.resilience.replication.read_url_env",
                "String (legacy)",
                "None",
                "No",
                "Environment variable name",
                "Backward-compatible shorthand for `database.resilience.replication.read_url: { env_or_file: \"...\" }`.",
            ),
            row(
                "database.resilience.replication.max_lag",
                "String",
                "None",
                "No",
                "Any non-empty duration-like string such as `30s`",
                "Currently stored as text for planning/doctor output.",
            ),
            row(
                "database.resilience.replication.replicas_expected",
                "u32",
                "None",
                "No",
                "Positive integer",
                "Documents the expected minimum replica count for validation tooling.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Logging",
        "Logging settings are carried into emitted servers and generated projects.",
        &[
            row(
                "logging.filter_env",
                "String",
                logging_defaults.filter_env.clone(),
                "No",
                "Environment variable name",
                "Used with `env_logger::Env::filter_or`.",
            ),
            row(
                "logging.default_filter",
                "String",
                logging_defaults.default_filter.clone(),
                "No",
                "Any env_logger filter string",
                "Fallback when the filter env var is absent.",
            ),
            row(
                "logging.timestamp",
                "Enum",
                format!("{:?}", logging_defaults.timestamp),
                "No",
                "None, Seconds, Millis, Micros, Nanos",
                "Aliases such as `off`, `sec`, `ms`, `us`, and `ns` are also accepted case-insensitively.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Build",
        "Build settings affect generated server projects and `vsr build` output without changing the API contract.",
        &[
            row(
                "build.target_cpu_native",
                "Bool",
                "false",
                "No",
                "true, false",
                "When true, emitted projects include `.cargo/config.toml` with `target-cpu=native`. Use only when building and running on the same machine class.",
            ),
            row(
                "build.release.lto",
                "Bool or Enum",
                "None",
                "No",
                "true, false, Thin, Fat",
                "`true` maps to thin LTO. `false` disables emitted release-profile LTO overrides.",
            ),
            row(
                "build.release.codegen_units",
                "u32",
                "None",
                "No",
                "Positive integer",
                "Emits `codegen-units` in `[profile.release]`. Values must be greater than zero.",
            ),
            row(
                "build.release.strip_debug_symbols",
                "Bool",
                "false",
                "No",
                "true, false",
                "Emits `strip = \"debuginfo\"` in `[profile.release]` for generated server projects.",
            ),
            row(
                "build.artifacts.binary.path",
                "String",
                "Service-relative `<input-stem>`",
                "No",
                "Relative or absolute path",
                "Controls the default binary output path for `vsr build`. Relative paths resolve from the `.eon` file directory.",
            ),
            row(
                "build.artifacts.binary.env",
                "String",
                "None",
                "No",
                "Environment variable name",
                "Optional env var override for the binary output path. `vsr` reads it only when this field is declared.",
            ),
            row(
                "build.artifacts.bundle.path",
                "String",
                "Adjacent `<binary>.bundle`",
                "No",
                "Relative or absolute directory path",
                "Controls the exported runtime bundle directory when the binary output is not overridden explicitly on the CLI.",
            ),
            row(
                "build.artifacts.bundle.env",
                "String",
                "None",
                "No",
                "Environment variable name",
                "Optional env var override for the bundle directory. `vsr` reads it only when this field is declared.",
            ),
            row(
                "build.artifacts.cache.root",
                "String",
                "Service-relative `.vsr-build`",
                "No",
                "Relative or absolute directory path",
                "Base directory for reusable generated-project caches. `vsr build` appends the package name and stable service hash under this root.",
            ),
            row(
                "build.artifacts.cache.env",
                "String",
                "None",
                "No",
                "Environment variable name",
                "Optional env var override for the build cache root. `vsr` reads it only when this field is declared.",
            ),
            row(
                "build.artifacts.cache.cleanup",
                "Enum",
                "Reuse",
                "No",
                "Reuse, CleanBeforeBuild, RemoveOnSuccess",
                "Controls reusable build-cache lifecycle for `vsr build`. `CleanBeforeBuild` clears the resolved cache root first; `RemoveOnSuccess` deletes it after a successful build unless `--keep-build-dir` is used.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Clients",
        "Client generation settings control `vsr client ts` defaults and optional build-time automation without changing the API contract.",
        &[
            row(
                "clients.ts.output_dir.path",
                "String",
                "Service-relative `<input-stem>.client`",
                "No",
                "Relative or absolute directory path",
                "Controls the default output directory for `vsr client ts`. Relative paths resolve from the `.eon` file directory.",
            ),
            row(
                "clients.ts.output_dir.env",
                "String",
                "None",
                "No",
                "Environment variable name",
                "Optional env var override for the TypeScript client output directory. `vsr` reads it only when this field is declared.",
            ),
            row(
                "clients.ts.package_name.value",
                "String",
                "<input-stem>-client",
                "No",
                "npm package name string",
                "Default package name written to the generated `package.json` for `vsr client ts`.",
            ),
            row(
                "clients.ts.package_name.env",
                "String",
                "None",
                "No",
                "Environment variable name",
                "Optional env var override for the generated client package name. `vsr` reads it only when this field is declared.",
            ),
            row(
                "clients.ts.server_url",
                "String",
                "/api",
                "No",
                "Relative API base path",
                "Default server URL embedded in the generated TypeScript client when `--server-url` is not passed.",
            ),
            row(
                "clients.ts.emit_js",
                "Bool",
                "false",
                "No",
                "true, false",
                "When true, emits dependency-free browser-ready `.js` modules alongside the generated TypeScript sources.",
            ),
            row(
                "clients.ts.include_builtin_auth",
                "Bool",
                "true",
                "No",
                "true, false",
                "Controls whether built-in auth routes are included in the generated TypeScript client when the CLI does not explicitly pass `--without-auth`.",
            ),
            row(
                "clients.ts.exclude_tables",
                "Array<String>",
                "[]",
                "No",
                "Resource table names",
                "Default resource tables excluded from generated TypeScript client operations. CLI `--exclude-table` values are added on top of this list.",
            ),
            row(
                "clients.ts.automation.on_build",
                "Bool",
                "false",
                "No",
                "true, false",
                "When true, `vsr build` and `vsr server build` automatically regenerate the TypeScript client after a successful server build.",
            ),
            row(
                "clients.ts.automation.self_test",
                "Bool",
                "false",
                "No",
                "true, false",
                "When `automation.on_build` is enabled, runs the generated client static self-test after regeneration and writes a JSON report.",
            ),
            row(
                "clients.ts.automation.self_test_report.path",
                "String",
                "<client-dir>/self-test-report.json",
                "No",
                "Relative or absolute file path",
                "Overrides the automated client self-test report location. Relative paths resolve from the `.eon` file directory.",
            ),
            row(
                "clients.ts.automation.self_test_report.env",
                "String",
                "None",
                "No",
                "Environment variable name",
                "Optional env var override for the automated client self-test report path. `vsr` reads it only when this field is declared.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Runtime",
        "Runtime settings affect server behavior without changing the data model.",
        &[
            row(
                "runtime.compression.enabled",
                "Bool",
                "false",
                "No",
                "true, false",
                "Enables dynamic HTTP response compression middleware in emitted servers.",
            ),
            row(
                "runtime.compression.static_precompressed",
                "Bool",
                "false",
                "No",
                "true, false",
                "Enables `.br` / `.gz` companion lookup for generated static mounts and causes `vsr build` to generate those companion files into `<binary>.bundle/`.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "TLS",
        "Any configured TLS field enables HTTPS/Rustls support in emitted servers.",
        &[
            row(
                "tls.cert_path",
                "String",
                DEFAULT_TLS_CERT_PATH,
                "Required when TLS is enabled unless `tls.cert_path_env` resolves",
                "Relative or absolute PEM path",
                "Relative paths are resolved against the service or bundle base directory.",
            ),
            row(
                "tls.key_path",
                "String",
                DEFAULT_TLS_KEY_PATH,
                "Required when TLS is enabled unless `tls.key_path_env` resolves",
                "Relative or absolute PEM path",
                "Relative paths are resolved against the service or bundle base directory.",
            ),
            row(
                "tls.cert_path_env",
                "String",
                DEFAULT_TLS_CERT_PATH_ENV,
                "No",
                "Environment variable name",
                "Overrides `tls.cert_path` at runtime when the env var is present.",
            ),
            row(
                "tls.key_path_env",
                "String",
                DEFAULT_TLS_KEY_PATH_ENV,
                "No",
                "Environment variable name",
                "Overrides `tls.key_path` at runtime when the env var is present.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Security Overview",
        "Every key inside `security` is optional. Unset blocks keep the default open behavior.",
        &[
            row(
                "security.requests",
                "Map",
                "No custom extractor limits",
                "No",
                "See Request Security",
                "Currently used for JSON body size limits.",
            ),
            row(
                "security.cors",
                "Map",
                "No custom CORS policy",
                "No",
                "See CORS",
                "Empty methods/headers lists fall back to runtime defaults.",
            ),
            row(
                "security.trusted_proxies",
                "Map",
                "No trusted proxies",
                "No",
                "See Trusted Proxies",
                "Used when extracting the client IP from forwarded headers.",
            ),
            row(
                "security.rate_limits",
                "Map",
                "No auth rate limits",
                "No",
                "See Rate Limits",
                "Currently applies to built-in auth login and register flows.",
            ),
            row(
                "security.access",
                "Map",
                "Legacy inferred read access",
                "No",
                "See Access Defaults",
                "Controls the service-wide default for resource read access when `resources[].access.read` is omitted.",
            ),
            row(
                "security.headers",
                "Map",
                "No additional security headers",
                "No",
                "See Security Headers",
                "Controls X-Frame-Options, nosniff, Referrer-Policy, and HSTS.",
            ),
            row(
                "security.auth",
                "Map",
                "Built-in auth defaults",
                "No",
                "See Auth Settings",
                "Controls JWT claims, TTLs, email flows, session cookies, and custom UI pages.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Access Defaults",
        "Use this when you want authenticated reads by default and explicit opt-in for public resources.",
        &[row(
            "security.access.default_read",
            "String",
            "`inferred`",
            "No",
            "`inferred` or `authenticated`",
            "When set to `authenticated`, resources must explicitly opt into anonymous reads with `resources[].access.read = public`.",
        )],
    );

    push_section(
        &mut markdown,
        "Request Security",
        "",
        &[row(
            "security.requests.json_max_bytes",
            "usize",
            "None",
            "No",
            "Positive integer",
            "Sets the generated JSON extractor limit. Must be greater than 0 when provided.",
        )],
    );

    push_section(
        &mut markdown,
        "CORS",
        "Runtime behavior when lists are empty: methods default to `GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD`; allowed headers default to `authorization, content-type, accept`.",
        &[
            row(
                "security.cors.origins",
                "List<String>",
                "[]",
                "No",
                "Absolute origins or `*`",
                "Origins are validated as URIs. `*` cannot be combined with `allow_credentials = true`.",
            ),
            row(
                "security.cors.origins_env",
                "String",
                "None",
                "No",
                "Environment variable name",
                "The runtime splits the env value on commas and appends it to `origins`.",
            ),
            row(
                "security.cors.allow_credentials",
                "Bool",
                "false",
                "No",
                "true, false",
                "Cannot be combined with wildcard `*` origins.",
            ),
            row(
                "security.cors.allow_methods",
                "List<String>",
                "[]",
                "No",
                "HTTP methods or `*`",
                "Methods are validated using Actix/Web HTTP method parsing.",
            ),
            row(
                "security.cors.allow_headers",
                "List<String>",
                "[]",
                "No",
                "Header names or `*`",
                "Header names are validated using HTTP header parsing.",
            ),
            row(
                "security.cors.expose_headers",
                "List<String>",
                "[]",
                "No",
                "Header names or `*`",
                "Header names are validated using HTTP header parsing.",
            ),
            row(
                "security.cors.max_age_seconds",
                "usize",
                "None",
                "No",
                "Positive integer",
                "Must be greater than 0 when provided.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Trusted Proxies",
        "",
        &[
            row(
                "security.trusted_proxies.proxies",
                "List<String>",
                "[]",
                "No",
                "IP addresses",
                "Every entry must parse as an IP address.",
            ),
            row(
                "security.trusted_proxies.proxies_env",
                "String",
                "None",
                "No",
                "Environment variable name",
                "The runtime splits the env value on commas and appends valid IPs to `proxies`.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Rate Limits",
        "Rate-limit rules are currently applied only to built-in auth endpoints.",
        &[
            row(
                "security.rate_limits.login.requests",
                "u32",
                "None",
                "Required when `security.rate_limits.login` is set",
                "Positive integer",
                "Maximum requests allowed per window.",
            ),
            row(
                "security.rate_limits.login.window_seconds",
                "u64",
                "None",
                "Required when `security.rate_limits.login` is set",
                "Positive integer",
                "Sliding window length in seconds.",
            ),
            row(
                "security.rate_limits.register.requests",
                "u32",
                "None",
                "Required when `security.rate_limits.register` is set",
                "Positive integer",
                "Maximum requests allowed per window.",
            ),
            row(
                "security.rate_limits.register.window_seconds",
                "u64",
                "None",
                "Required when `security.rate_limits.register` is set",
                "Positive integer",
                "Sliding window length in seconds.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Security Headers",
        "",
        &[
            row(
                "security.headers.frame_options",
                "Enum",
                "None",
                "No",
                "Deny, SameOrigin",
                "Accepted aliases include `same-origin` and `same_origin`.",
            ),
            row(
                "security.headers.content_type_options",
                "Bool",
                "false",
                "No",
                "true, false",
                "When true, adds `X-Content-Type-Options: nosniff`.",
            ),
            row(
                "security.headers.referrer_policy",
                "Enum",
                "None",
                "No",
                "NoReferrer, SameOrigin, StrictOriginWhenCrossOrigin, NoReferrerWhenDowngrade, Origin, OriginWhenCrossOrigin, UnsafeUrl",
                "Snake_case and hyphenated aliases are also accepted.",
            ),
            row(
                "security.headers.hsts.max_age_seconds",
                "u64",
                "None",
                "Required when `security.headers.hsts` is set",
                "Positive integer",
                "Must be greater than 0.",
            ),
            row(
                "security.headers.hsts.include_subdomains",
                "Bool",
                "false",
                "No",
                "true, false",
                "Appends `includeSubDomains` to the HSTS header.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Auth Settings",
        "These settings configure the built-in auth/account routes. They do not affect custom resources unless you explicitly use auth-derived claims in row policies.",
        &[
            row(
                "security.auth.issuer",
                "String",
                format_option(auth_defaults.issuer.as_deref()),
                "No",
                "JWT issuer string",
                "Included in generated JWTs and enforced during token validation when set.",
            ),
            row(
                "security.auth.audience",
                "String",
                format_option(auth_defaults.audience.as_deref()),
                "No",
                "JWT audience string",
                "Included in generated JWTs and enforced during token validation when set.",
            ),
            row(
                "security.auth.access_token_ttl_seconds",
                "i64",
                auth_defaults.access_token_ttl_seconds.to_string(),
                "No",
                "Positive integer",
                "Access-token lifetime in seconds.",
            ),
            row(
                "security.auth.require_email_verification",
                "Bool",
                auth_defaults.require_email_verification.to_string(),
                "No",
                "true, false",
                "When true, registration/login flows require email verification and `security.auth.email` must also be configured.",
            ),
            row(
                "security.auth.verification_token_ttl_seconds",
                "i64",
                auth_defaults.verification_token_ttl_seconds.to_string(),
                "No",
                "Positive integer",
                "Verification-token lifetime in seconds.",
            ),
            row(
                "security.auth.password_reset_token_ttl_seconds",
                "i64",
                auth_defaults.password_reset_token_ttl_seconds.to_string(),
                "No",
                "Positive integer",
                "Password-reset token lifetime in seconds.",
            ),
            row(
                "security.auth.jwt",
                "Map",
                "None",
                "No",
                "See Auth JWT",
                "Structured JWT signing/verification config with algorithm selection, key ids, and rotation support.",
            ),
            row(
                "security.auth.jwt_secret",
                "SecretRef",
                format_option(
                    auth_defaults
                        .jwt_secret
                        .as_ref()
                        .map(|_| "{ env_or_file: \"JWT_SECRET\" }"),
                ),
                "No",
                "See Secret References",
                "Controls how built-in auth resolves the legacy shared-secret signing key. Prefer `security.auth.jwt` for new configs that need explicit algorithms or rotation.",
            ),
            row(
                "security.auth.claims",
                "Map<ClaimName, ClaimMapping>",
                "None",
                "No",
                "Keyed map of claim names to claim mappings",
                "Makes built-in auth claims explicit. Claim names must be unique and cannot use reserved fields such as `sub`, `roles`, `iss`, `aud`, `exp`, or `id`.",
            ),
            row(
                "security.auth.session_cookie",
                "Map",
                "None",
                "No",
                "See Session Cookie",
                "Enables cookie-based session auth in addition to bearer tokens.",
            ),
            row(
                "security.auth.email",
                "Map",
                "None",
                "No",
                "See Auth Email",
                "Configures transactional email for verification and password reset flows.",
            ),
            row(
                "security.auth.portal",
                "Map",
                "None",
                "No",
                "See Auth UI Pages",
                "Configures a custom account portal page path and title.",
            ),
            row(
                "security.auth.admin_dashboard",
                "Map",
                "None",
                "No",
                "See Auth UI Pages",
                "Configures a custom admin dashboard page path and title.",
            ),
        ],
    );

    push_code_block(
        &mut markdown,
        "eon",
        r#"security: {
    auth: {
        claims: {
            tenant_id: I64
            workspace_id: "claim_workspace_id"
            staff: { column: "is_staff", type: Bool }
            plan: String
        }
    }
}"#,
    );

    push_section(
        &mut markdown,
        "Auth JWT",
        "Use `security.auth.jwt` for asymmetric keys or explicit rotation. Keep `security.auth.jwt_secret` only for the legacy shared-secret path.",
        &[
            row(
                "security.auth.jwt.algorithm",
                "Enum",
                "EdDSA when the `jwt` block exists and `algorithm` is omitted",
                "No",
                "HS256, HS384, HS512, ES256, ES384, EdDSA",
                "Selects the signing and verification algorithm for built-in auth tokens.",
            ),
            row(
                "security.auth.jwt.active_kid",
                "String",
                "None",
                "Required when `verification_keys` are configured",
                "Non-empty string",
                "Emitted in the JWT header as `kid` for newly-issued tokens.",
            ),
            row(
                "security.auth.jwt.signing_key",
                "SecretRef",
                "None",
                "Yes",
                "See Secret References",
                "Signing key for JWT issuance. Asymmetric algorithms expect a private PEM.",
            ),
            row(
                "security.auth.jwt.verification_keys[].kid",
                "String",
                "None",
                "Required for each verification key",
                "Non-empty string",
                "Key id matched against the incoming JWT header `kid`.",
            ),
            row(
                "security.auth.jwt.verification_keys[].key",
                "SecretRef",
                "None",
                "Required for each verification key",
                "See Secret References",
                "Verification key material. Asymmetric algorithms expect a public PEM.",
            ),
        ],
    );

    push_code_block(
        &mut markdown,
        "eon",
        r#"security: {
    auth: {
        jwt: {
            algorithm: EdDSA
            active_kid: "2026-04"
            signing_key: { env_or_file: "JWT_SIGNING_KEY" }
            verification_keys: [
                { kid: "2026-04", key: { env_or_file: "JWT_VERIFYING_KEY" } }
                { kid: "2026-03", key: { env_or_file: "JWT_VERIFYING_KEY_PREVIOUS" } }
            ]
        }
    }
}"#,
    );

    push_section(
        &mut markdown,
        "Auth Claims",
        "Explicit auth claim mappings let built-in auth expose predictable claim names without relying entirely on implicit `_id` / `claim_<name>` discovery. The keyed map name is the emitted JWT claim name. For `.eon` services, `vsr setup` also extends the built-in `user` table with those mapped columns automatically before admin creation. Use this for stable user/session attributes; use the `authorization` contract and runtime authz tables for permissions or scoped grants.",
        &[
            row(
                "security.auth.claims.<claim_name>",
                "I64 | String | Bool | String column name | Map",
                "If shorthand type is used, the column defaults to `<claim_name>` and the type defaults to the shorthand",
                "No",
                "`tenant_id: I64`, `workspace_id: \"claim_workspace_id\"`, or a full object",
                "String shorthand means `column = <string>` with the default type `I64`. Use the object form when you need a non-`I64` type on a different column.",
            ),
            row(
                "security.auth.claims.<claim_name>.column",
                "String",
                "The claim key name",
                "No",
                "SQL identifier in the built-in `user` table",
                "When omitted in the object form, the claim key is also used as the column name.",
            ),
            row(
                "security.auth.claims.<claim_name>.type",
                "Enum",
                "I64",
                "No",
                "I64, String, Bool",
                "Controls how built-in auth decodes the `user` column and exposes it in JWTs and `/api/auth/me`.",
            ),
        ],
    );
    markdown.push_str(
        "Current runtime boundary:\n\n\
- Row policies can consume explicit `I64`, `String`, and `Bool` claims when the target field uses the matching type.\n\
- When `security.auth.claims` is configured, non-legacy `claim.<name>` references in row policies must be declared there.\n\
- Legacy undeclared `claim.<name>` usage still only works for numeric `*_id` claims.\n\n",
    );

    push_section(
        &mut markdown,
        "Session Cookie",
        "Cookie-session auth is opt-in. Once the block exists, defaults are filled for any omitted keys.",
        &[
            row(
                "security.auth.session_cookie.name",
                "String",
                session_cookie_defaults.name.clone(),
                "No",
                "Cookie name",
                "Cannot be empty. `__Host-` prefixed names require `secure = true` and `path = \"/\"`.",
            ),
            row(
                "security.auth.session_cookie.csrf_cookie_name",
                "String",
                session_cookie_defaults.csrf_cookie_name.clone(),
                "No",
                "Cookie name",
                "Must differ from `name`. `__Host-` prefix has the same constraints as the main cookie.",
            ),
            row(
                "security.auth.session_cookie.csrf_header_name",
                "String",
                session_cookie_defaults.csrf_header_name.clone(),
                "No",
                "HTTP header name",
                "Used for CSRF validation on non-safe HTTP methods.",
            ),
            row(
                "security.auth.session_cookie.path",
                "String",
                session_cookie_defaults.path.clone(),
                "No",
                "Cookie path beginning with `/`",
                "Must start with `/`.",
            ),
            row(
                "security.auth.session_cookie.secure",
                "Bool",
                session_cookie_defaults.secure.to_string(),
                "No",
                "true, false",
                "Must be true when `same_site = None`.",
            ),
            row(
                "security.auth.session_cookie.same_site",
                "Enum",
                format!("{:?}", session_cookie_defaults.same_site),
                "No",
                "Strict, Lax, None",
                "Parsed case-insensitively using lowercase/string aliases.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Auth Email",
        "This block is required when email verification is mandatory.",
        &[
            row(
                "security.auth.email.from_email",
                "String",
                "None",
                "Yes when the block is present",
                "Email-like string",
                "Must contain `@`.",
            ),
            row(
                "security.auth.email.from_name",
                "String",
                "None",
                "No",
                "Display name",
                "Optional sender display name.",
            ),
            row(
                "security.auth.email.reply_to",
                "String",
                "None",
                "No",
                "Email-like string",
                "Cannot be empty when provided.",
            ),
            row(
                "security.auth.email.public_base_url",
                "String",
                "None",
                "No",
                "Absolute URL",
                "Used when generating absolute links in auth emails.",
            ),
            row(
                "security.auth.email.provider",
                "Map",
                "None",
                "Yes when the block is present",
                "See Auth Email Provider",
                "Selects the outbound email provider implementation.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Auth Email Provider",
        "",
        &[
            row(
                "security.auth.email.provider.kind",
                "Enum",
                "None",
                "Yes",
                "Resend, Smtp",
                "Parsed case-insensitively.",
            ),
            row(
                "security.auth.email.provider.api_key",
                "SecretRef",
                "None",
                "Required for `kind = Resend`",
                "See Secret References",
                "Preferred Resend API key binding for new configs.",
            ),
            row(
                "security.auth.email.provider.api_key_env",
                "String (legacy)",
                "None",
                "No",
                "Environment variable name",
                "Backward-compatible shorthand for `security.auth.email.provider.api_key: { env_or_file: \"...\" }`.",
            ),
            row(
                "security.auth.email.provider.api_base_url",
                "String",
                "None",
                "No",
                "Absolute URL",
                "Optional override for the Resend API base URL.",
            ),
            row(
                "security.auth.email.provider.connection_url",
                "SecretRef",
                "None",
                "Required for `kind = Smtp`",
                "See Secret References",
                "Preferred SMTP connection binding for new configs.",
            ),
            row(
                "security.auth.email.provider.connection_url_env",
                "String (legacy)",
                "None",
                "No",
                "Environment variable name",
                "Backward-compatible shorthand for `security.auth.email.provider.connection_url: { env_or_file: \"...\" }`.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Auth UI Pages",
        "Custom auth UI pages must not collide with built-in auth routes and each path must be unique.",
        &[
            row(
                "security.auth.portal.path",
                "String",
                "None",
                "Yes when the block is present",
                "Absolute path beginning with `/`",
                "Cannot be empty or conflict with built-in auth paths such as `/auth/login`.",
            ),
            row(
                "security.auth.portal.title",
                "String",
                "Account Portal",
                "No",
                "Display title",
                "Defaults to `Account Portal` when omitted.",
            ),
            row(
                "security.auth.admin_dashboard.path",
                "String",
                "None",
                "Yes when the block is present",
                "Absolute path beginning with `/`",
                "Cannot be empty or conflict with built-in auth paths such as `/auth/login`.",
            ),
            row(
                "security.auth.admin_dashboard.title",
                "String",
                "Admin Dashboard",
                "No",
                "Display title",
                "Defaults to `Admin Dashboard` when omitted.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Field Types",
        "These are the canonical built-in field type keywords accepted by `.eon`. Raw Rust type strings are also allowed.",
        &[
            row(
                "String",
                "Rust field type",
                "n/a",
                "n/a",
                "String",
                "Stored as `TEXT`. Supports equality filters, `contains`, and sort.",
            ),
            row(
                "I32",
                "Rust field type",
                "n/a",
                "n/a",
                "i32",
                "Stored as `INTEGER`. Supports equality filters and sort.",
            ),
            row(
                "I64",
                "Rust field type",
                "n/a",
                "n/a",
                "i64",
                "Stored as `INTEGER`. Supports equality filters and sort.",
            ),
            row(
                "F32",
                "Rust field type",
                "n/a",
                "n/a",
                "f32",
                "Stored as `REAL`. Supports equality filters and sort.",
            ),
            row(
                "F64",
                "Rust field type",
                "n/a",
                "n/a",
                "f64",
                "Stored as `REAL`. Supports equality filters and sort.",
            ),
            row(
                "Bool",
                "Rust field type",
                "n/a",
                "n/a",
                "bool",
                "Stored as `INTEGER` on SQLite/MySQL and `BOOLEAN` on Postgres. Supports equality filters and sort.",
            ),
            row(
                "DateTime",
                "Rust field type",
                "n/a",
                "n/a",
                "chrono::DateTime<Utc>",
                "Stored as text-compatible values. Supports equality filters, range filters, and sort.",
            ),
            row(
                "Date",
                "Rust field type",
                "n/a",
                "n/a",
                "chrono::NaiveDate",
                "Stored as text-compatible values. Supports equality filters, range filters, and sort.",
            ),
            row(
                "Time",
                "Rust field type",
                "n/a",
                "n/a",
                "chrono::NaiveTime",
                "Stored as text-compatible values. Supports equality filters, range filters, and sort.",
            ),
            row(
                "Uuid",
                "Rust field type",
                "n/a",
                "n/a",
                "uuid::Uuid",
                "Stored as text/char values depending on backend. Supports equality filters and sort.",
            ),
            row(
                "Decimal",
                "Rust field type",
                "n/a",
                "n/a",
                "rust_decimal::Decimal",
                "Stored as text/varchar values. Supports equality filters but not generated sort helpers.",
            ),
            row(
                "<DeclaredEnumName>",
                "Named enum field type",
                "n/a",
                "n/a",
                "Any name declared under `enums`",
                "Stored as text and validated against the declared string values. Supports exact filters and the normal string sort helpers, but not contains filters.",
            ),
            row(
                "Json",
                "Rust field type",
                "n/a",
                "n/a",
                "serde_json::Value",
                "Stored as JSON text. Round-trips through the API as native JSON, but current generated/native list helpers do not expose equality, range, or contains filters for it.",
            ),
            row(
                "JsonObject",
                "Rust field type",
                "n/a",
                "n/a",
                "serde_json::Value",
                "Stored as JSON text and validated to be a JSON object. OpenAPI emits it as an object schema. Current list helpers do not expose equality, range, or contains filters for it.",
            ),
            row(
                "JsonArray",
                "Rust field type",
                "n/a",
                "n/a",
                "serde_json::Value",
                "Stored as JSON text and validated to be a JSON array. OpenAPI emits it as an array schema. Current list helpers do not expose equality, range, or contains filters for it.",
            ),
            row(
                "List",
                "Built-in collection field type",
                "n/a",
                "n/a",
                "Use with `items`, for example `{ type: List, items: I64 }`",
                "Stored as a JSON array encoded in text. OpenAPI emits an array schema based on `items`. Current generated/native list helpers do not expose equality, range, or contains filters for `List` fields.",
            ),
            row(
                "Object",
                "Built-in structured field type",
                "n/a",
                "n/a",
                "Use with `fields`, for example `{ type: Object, fields: [{ name: \"raw\", type: String }] }`",
                "Stored as a JSON object encoded in text. Nested fields are validated recursively in generated handlers and native `vsr serve`, and OpenAPI emits a closed object schema with nested properties.",
            ),
            row(
                "\"<raw Rust type>\"",
                "Rust field type",
                "n/a",
                "n/a",
                "Any type parsable by `syn`",
                "SQL type inference is best-effort. Structured-scalar-specific validation and filter helpers only apply to the built-in scalar keywords above.",
            ),
        ],
    );

    push_section(
        &mut markdown,
        "Derived Behavior",
        "These behaviors are not separate config keys, but they are part of the current `.eon` contract.",
        &[
            row(
                "Resource naming",
                "Derived rule",
                "n/a",
                "n/a",
                "n/a",
                "Resource names sanitize to Rust struct identifiers; table names default to the snake_case resource name.",
            ),
            row(
                "ID handling",
                "Derived rule",
                "n/a",
                "n/a",
                "n/a",
                "The field matching `id_field` is treated as the resource ID even if `id: true` is omitted.",
            ),
            row(
                "Generated fields",
                "Derived rule",
                "n/a",
                "n/a",
                "n/a",
                "Generated fields (`AutoIncrement`, `CreatedAt`, `UpdatedAt`) become optional in generated Rust types and are skipped from normal write payloads.",
            ),
            row(
                "Field map shorthand",
                "Derived rule",
                "n/a",
                "n/a",
                "n/a",
                "A field map entry like `title: String` is equivalent to `{ name: \"title\", type: String, nullable: false, id: false, generated: None }`.",
            ),
            row(
                "Static SPA defaults",
                "Derived rule",
                "n/a",
                "n/a",
                "n/a",
                "SPA mounts default both `index_file` and `fallback_file` to `index.html`.",
            ),
            row(
                "SQLite runtime defaults",
                "Derived rule",
                "n/a",
                "n/a",
                "n/a",
                "When `db: Sqlite` and `database.engine` is omitted, the runtime defaults to `TursoLocal(var/data/<module>.db)` with encrypted-local support via `TURSO_ENCRYPTION_KEY`.",
            ),
            row(
                "Static precompression",
                "Derived rule",
                "n/a",
                "n/a",
                "n/a",
                "When `runtime.compression.static_precompressed = true`, generated static mounts serve `.br`/`.gz` companion assets and `vsr build` generates those companions into the sidecar bundle.",
            ),
        ],
    );

    markdown.push_str("## Examples\n\n");
    markdown.push_str("### Minimal service\n\n");
    push_code_block(
        &mut markdown,
        "eon",
        r#"module: "blog_api"
resources: [
    {
        name: "Post"
        fields: [
            { name: "id", type: I64 }
            { name: "title", type: String }
            { name: "published", type: Bool }
        ]
    }
]"#,
    );

    markdown.push_str("### Map-based resource and field syntax\n\n");
    push_code_block(
        &mut markdown,
        "eon",
        r#"resources: {
    Post: {
        list: { default_limit: 20, max_limit: 100 }
        fields: {
            id: { type: I64, id: true }
            title: { type: String, garde: { length: { min: 3, max: 120, mode: Chars } } }
            created_at: { type: DateTime, generated: CreatedAt }
        }
    }
}"#,
    );

    markdown.push_str("### Service-level runtime, static, and security config\n\n");
    push_code_block(
        &mut markdown,
        "eon",
        r#"runtime: {
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
}"#,
    );

    markdown
}

#[derive(Clone, Debug)]
struct TableRow {
    path: String,
    value_type: String,
    default: String,
    required: String,
    values: String,
    notes: String,
}

fn row(
    path: impl Into<String>,
    value_type: impl Into<String>,
    default: impl Into<String>,
    required: impl Into<String>,
    values: impl Into<String>,
    notes: impl Into<String>,
) -> TableRow {
    TableRow {
        path: path.into(),
        value_type: value_type.into(),
        default: default.into(),
        required: required.into(),
        values: values.into(),
        notes: notes.into(),
    }
}

fn push_section(markdown: &mut String, title: &str, intro: &str, rows: &[TableRow]) {
    markdown.push_str(&format!("## {title}\n\n"));
    if !intro.trim().is_empty() {
        markdown.push_str(intro);
        markdown.push_str("\n\n");
    }
    markdown.push_str("| Path | Type / Shape | Default | Required | Accepted Values | Notes |\n");
    markdown.push_str("| --- | --- | --- | --- | --- | --- |\n");
    for row in rows {
        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            markdown_cell(&row.path),
            markdown_cell(&row.value_type),
            markdown_cell(&row.default),
            markdown_cell(&row.required),
            markdown_cell(&row.values),
            markdown_cell(&row.notes),
        ));
    }
    markdown.push('\n');
}

fn push_code_block(markdown: &mut String, language: &str, code: &str) {
    markdown.push_str(&format!("```{language}\n{code}\n```\n\n"));
}

fn markdown_cell(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "\\|")
        .replace('\n', "<br>")
}

fn format_option(value: Option<&str>) -> String {
    value.unwrap_or("None").to_owned()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use uuid::Uuid;

    use super::{generate_eon_reference, render_eon_reference_markdown};

    fn test_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/docs_tests")
            .join(Uuid::new_v4().to_string())
    }

    fn repo_reference_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs")
            .join("eon-reference.md")
    }

    fn read_to_string(path: &Path) -> String {
        fs::read_to_string(path).expect("file should be readable")
    }

    #[test]
    fn render_eon_reference_mentions_core_sections() {
        let markdown = render_eon_reference_markdown();

        assert!(markdown.contains("# `.eon` Configuration Reference"));
        assert!(markdown.contains("## Top-Level Keys"));
        assert!(markdown.contains("## Database Resilience"));
        assert!(markdown.contains("## Authorization Contract"));
        assert!(markdown.contains("## Resource Keys"));
        assert!(markdown.contains("## Security Overview"));
        assert!(markdown.contains("## Auth Claims"));
        assert!(markdown.contains("authorization.permissions."));
        assert!(markdown.contains("database.resilience.backup.mode"));
        assert!(markdown.contains("build.release.lto"));
        assert!(markdown.contains("build.target_cpu_native"));
        assert!(markdown.contains("build.artifacts.binary.path"));
        assert!(markdown.contains("clients.ts.output_dir.path"));
        assert!(markdown.contains("runtime.compression.static_precompressed"));
        assert!(markdown.contains("security.auth.claims."));
        assert!(markdown.contains("resources[].fields[].garde.length.min"));
        assert!(!markdown.contains("resources[].fields[].validate"));
        assert!(markdown.contains("authorization.permissions."));
        assert!(markdown.contains("fields: {"));
    }

    #[test]
    fn generate_eon_reference_writes_markdown_file() {
        let root = test_root();
        let output = root.join("eon-reference.md");

        generate_eon_reference(&output, false).expect("docs should generate");

        let markdown = read_to_string(&output);
        assert!(markdown.contains("## Build"));
        assert!(markdown.contains("## Runtime"));
        assert!(markdown.contains("## Auth Email Provider"));
    }

    #[test]
    fn checked_in_reference_matches_generator() {
        assert_eq!(
            normalize_text(&read_to_string(&repo_reference_path())),
            normalize_text(&render_eon_reference_markdown())
        );
    }

    fn normalize_text(value: &str) -> String {
        value.replace("\r\n", "\n")
    }
}
