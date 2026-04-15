# VSR Contract Starter Example

This example replaces the old Rust app template. It is now a checked-in `.eon`-first starter that
matches the current `vsr init` direction: edit the contract directly, generate migrations from it,
and run it with `vsr serve`.

Files:

- `api.eon`: comment-rich starter contract showing current schema/runtime features
- `.env.example`: local environment defaults
- `migrations/`: placeholder for generated SQL
- `var/data/`: local SQLite/TursoLocal data path

## Run It

```bash
cd examples/template
cp .env.example .env
vsr migrate generate --input api.eon --output migrations/0001_init.sql
vsr serve api.eon
vsr docs --output docs/eon-reference.md
```

## What It Shows

- local `TursoLocal` / SQLite defaults
- typed `Object`, `List`, and `JsonObject` fields
- API projection and response-context examples
- enums, indexes, and transforms
- declarative resource actions
- explicit join-resource many-to-many example

## Notes

- This is a reference contract, not a generated app skeleton.
- `vsr init my-api` now creates the same style of local starter directly, without copying code from
  `examples/` or fetching from GitHub.
- The generated `.eon` reference from `vsr docs` is the canonical single-file docs surface for
  local AI/tooling use.
