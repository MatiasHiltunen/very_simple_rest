# SQLite Benchmark Schema

This example is a larger `.eon` service intended for SQLite benchmarking. It models a multi-tenant
commerce workload with accounts, users, categories, suppliers, warehouses, products, customers,
addresses, orders, payments, shipments, returns, inventory lots, and audit events.

The schema is relation-heavy on purpose:

- 16 tables
- foreign keys across account, customer, order, fulfillment, and inventory flows
- nested-route-capable relations on the hot paths
- generated indexes for all relation fields

## Generate And Load

```bash
mkdir -p examples/sqlite_bench/migrations
mkdir -p examples/sqlite_bench/var/data

vsr migrate generate \
  --input examples/sqlite_bench/commerce.eon \
  --output examples/sqlite_bench/migrations/0001_commerce.sql

vsr --config examples/sqlite_bench/commerce.eon \
  migrate apply \
  --dir examples/sqlite_bench/migrations

sqlite3 examples/sqlite_bench/var/data/commerce_bench.db < examples/sqlite_bench/seed.sql
```

The service now declares an explicit local Turso runtime:

```eon
database: {
    engine: {
        kind: TursoLocal
        path: "var/data/commerce_bench.db"
    }
}
```

That keeps the SQL dialect SQLite-compatible while letting the generated runtime bootstrap the
local database file consistently through the same `database.engine` config used by emitted servers.

## Check Drift

```bash
vsr --config examples/sqlite_bench/commerce.eon \
  migrate inspect \
  --input examples/sqlite_bench/commerce.eon
```

## Generated Server Flow

This benchmark service also demonstrates the newer server CLI path and compiled service security
settings:

```bash
vsr server emit \
  --input examples/sqlite_bench/commerce.eon \
  --output-dir examples/sqlite_bench/generated-server

vsr build \
  examples/sqlite_bench/commerce.eon \
  --output examples/sqlite_bench/dist \
  --release
```

The service-level `security` block is intentionally lightweight here: JSON body limits, CORS env
override support through `CORS_ORIGINS`, trusted proxy overrides through `TRUSTED_PROXIES`, and
default security response headers.

## Seed Shape

The included seed script loads a deterministic dataset sized to be non-trivial for local SQLite
benchmarks:

- 25 accounts
- 500 users
- 250 categories
- 500 suppliers
- 250 warehouses
- 5,000 products
- 5,000 customers
- 10,000 addresses
- 10,000 orders
- 50,000 order items
- 10,000 payments
- 10,000 shipments
- 50,000 shipment items
- 25,000 inventory lots
- 1,000 return requests
- 2,000 return items
- 10,000 audit events

The seed script also enables WAL mode and runs `ANALYZE` after loading data so benchmark runs start
from a reasonable SQLite baseline.
