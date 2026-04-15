# CLI Workflow

The `vsr` CLI is the main entry point for contract-first VSR projects.

## Core Local Loop

```bash
vsr init my-api
vsr serve api.eon
vsr docs --output docs/eon-reference.md
vsr openapi --input api.eon --output openapi.json
vsr client ts --input api.eon --output web/src/gen/client
```

## Generated Output And Build Flow

```bash
vsr server expand --input api.eon --output api.expanded.rs
vsr server emit --input api.eon --output-dir generated-api
vsr build api.eon --release
```

## Schema And Runtime Checks

```bash
vsr migrate generate --input api.eon --output migrations/0001_init.sql
vsr migrate check --input api.eon --output migrations/0001_init.sql
vsr check --input api.eon --strict
```

## Contract-Derived Ops Tooling

```bash
vsr authz explain --input api.eon
vsr backup plan --input api.eon
vsr doctor secrets --input api.eon
```

The detailed command reference still lives in `crates/rest_api_cli/README.md`.
This chapter is intentionally short; the exact `.eon` config surface belongs in the generated
reference, not in duplicated prose.
