# VSR

VSR is a contract-first Rust toolkit for building REST APIs from one source of truth.
Define a service in `.eon`, then use the same contract to serve the API, generate migrations,
emit a Rust server project, build a binary, generate a TypeScript client, publish OpenAPI,
and render machine-scannable docs.

The current center of gravity is the `vsr` CLI and `.eon` services. The derive-based library
surface still exists, but the maintained docs and examples now prioritize the contract-first flow.

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

## Quickstart

Use the generated starter instead of copying an old README snippet:

```bash
vsr init my-api --starter minimal
cd my-api
cp .env.example .env
vsr migrate generate --input api.eon --output migrations/0001_init.sql
vsr serve api.eon
```

That gives you:

- a working `.eon` contract
- a generated initial migration
- Swagger UI at `/docs`
- OpenAPI JSON at `/openapi.json`

For a fuller maintained example, see [examples/template](examples/template/README.md).

## Docs

Human-oriented docs now live in the book source under [docs/src](docs/src/SUMMARY.md).
Serve it locally with:

```bash
mdbook serve docs
```

The AI-friendly single-file `.eon` reference is still generated with:

```bash
vsr docs --output docs/eon-reference.md
```

Start here:

- [Book overview](docs/src/overview.md)
- [Quickstart](docs/src/quickstart.md)
- [CLI workflow](docs/src/cli.md)
- [`.eon` reference](docs/eon-reference.md)
- [CLI crate README](crates/rest_api_cli/README.md)

## Examples

- [examples/template](examples/template/README.md): maintained starter-shaped `.eon` service
- [examples/cms](examples/cms/README.md): fuller contract-first CMS example
- [examples/family_app](examples/family_app/README.md): authorization-heavy example
