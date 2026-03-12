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

vsr migrate generate \
  --input examples/sqlite_bench/commerce.eon \
  --output examples/sqlite_bench/migrations/0001_commerce.sql

vsr --database-url sqlite:examples/sqlite_bench/commerce.db?mode=rwc \
  migrate apply \
  --dir examples/sqlite_bench/migrations

sqlite3 examples/sqlite_bench/commerce.db < examples/sqlite_bench/seed.sql
```

## Check Drift

```bash
vsr --database-url sqlite:examples/sqlite_bench/commerce.db?mode=rwc \
  migrate inspect \
  --input examples/sqlite_bench/commerce.eon
```

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
