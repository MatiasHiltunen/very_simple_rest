# Quickstart

The fastest working path is to let `vsr` generate a starter project for you.
That keeps the example aligned with the current parser and runtime surface.

## Install The CLI

```bash
cargo install vsra --locked
```

## Create A Starter

```bash
vsr init my-api --starter minimal
cd my-api
cp .env.example .env
vsr migrate generate --input api.eon --output migrations/0001_init.sql
vsr serve api.eon
```

That gives you a local service with:

- a checked-in `.eon` contract
- a generated initial migration
- local Turso/SQLite defaults
- Swagger UI at `/docs`
- OpenAPI JSON at `/openapi.json`

## Generate Local Reference Docs

```bash
vsr docs --output docs/eon-reference.md
```

That command is meant to stay AI-friendly: it writes one precise Markdown file for the currently
supported `.eon` surface, defaults, and derived behavior.

## Maintained Example

If you want a fuller example that tracks the `vsr init` commented starter shape, use
`examples/template/` in this repository.
