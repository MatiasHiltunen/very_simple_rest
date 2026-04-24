# VSR

VSR is a contract-first Rust toolkit for building REST APIs from one source of truth.
Define a service in `.eon`, then use the same contract to serve the API, generate migrations,
emit a Rust server project, build a binary, generate a TypeScript client, publish OpenAPI,
and render machine-scannable docs.

The current center of gravity is the `vsr` CLI and `.eon` services. The derive-based library
surface still exists, but the maintained docs and examples now prioritize the contract-first flow.
Typed `vsr.config.ts/js` files are also supported through the npm wrapper, which materializes a
canonical `api.eon` before delegating to the native CLI.

## Install

Install the CLI from crates.io:

```bash
cargo install vsra --locked
```

Build it from a local checkout:

```bash
git clone https://github.com/MatiasHiltunen/very_simple_rest.git
cd very_simple_rest
cargo build --release
./target/release/vsr --help
```

### npm Package

Install the TypeScript-first wrapper from npm:

```bash
npm install --save-dev @matiashiltunen/vsr typescript
```

The npm package exports generated schema types and a `defineService(...)` helper, loads
`vsr.config.ts/js`, renders a managed `api.eon`, and then delegates to the native `vsr` binary.

## Quickstart

Use the generated starter:

- **Note that `vsr serve` creates .env and runs migrations by default if not present, so you would only need the .eon file and vsr to get defined REST API up and running.**

```bash
vsr init my-api --starter minimal
cd my-api
cp .env.example .env
vsr migrate generate --input api.eon --output migrations/0001_init.sql
vsr serve api.eon
```

TypeScript-first starter:

```bash
npx vsr init my-api
cd my-api
npm install
cp .env.example .env
npx vsr migrate generate --output migrations/0001_init.sql
npx vsr serve
```

That gives you:

- a working `.eon` contract
- a generated initial migration
- Swagger UI at `/docs`
- OpenAPI JSON at `/openapi.json`

For a fuller maintained example, see [examples/template](examples/template/README.md).

## Docs

Docs now live in the book source under [docs/src](docs/src/SUMMARY.md) until domain is set for the project.

The AI-friendly single-file `.eon` reference can be generated with:

```bash
vsr docs --output docs/eon-reference.md
```

Start here:

- [Book overview](docs/src/overview.md)
- [Quickstart](docs/src/quickstart.md)
- [CLI workflow](docs/src/cli.md)
- [`.eon` reference](docs/eon-reference.md)
- [CLI crate README](crates/rest_api_cli/README.md)

## Couple Examples

- [examples/cms](examples/cms/README.md): fuller contract-first CMS example
- [examples/family_app](examples/family_app/README.md): authorization-heavy example
