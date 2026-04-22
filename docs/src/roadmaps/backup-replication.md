# Backup And Replication Roadmap

This document defines how `vsr` / `very_simple_rest` should grow backup, restore, and replication
support without pretending to be a full database cluster manager.

Current state: the project can already declare a first-class backup/replication contract in `.eon`,
render backend-aware plans, run doctor checks, create/verify local SQLite/TursoLocal snapshot
artifacts, and push/pull those artifacts through S3-compatible object storage. It does not yet
provide Postgres/MySQL backup execution, replica-aware runtime behavior, or emitted operations
scaffolding for disaster recovery.

## Goals

1. Keep the default path simple for single-node SQLite / TursoLocal services.
2. Support serious Postgres and MySQL production deployments without inventing custom database
   semantics.
3. Make recovery correctness more important than backup feature count.
4. Let `.eon` describe the intended resilience posture while keeping environment-specific
   scheduling and credentials outside the schema.

## Design Principles

### Database-native first

Use backend-native primitives for consistency and recovery:

- SQLite / TursoLocal: consistent local snapshot/export flows
- Postgres: logical dumps, base backups, WAL archiving, streaming replicas
- MySQL: logical dumps, physical backups, binlog-based recovery, replicas

`vsr` should integrate with those models, validate them, and help generate operational artifacts.
It should not invent a cross-database pseudo-replication protocol.

### Recovery before automation

A backup feature is not complete unless restore is also supported and verifiable. The plan should
prioritize:

- backup artifact creation
- restore verification
- backup freshness checks
- recovery runbooks

before adding more automation knobs.

### Explicit topology

Generated servers must not guess whether a connection is primary, replica, or managed externally.
That needs explicit configuration so writes never go to replicas by accident and read-routing stays
opt-in.

### Static contract, runtime diagnostics

The `.eon` file should declare the intended resilience posture and allowed topology. Runtime and CLI
tools should validate the live environment against that contract.

### Environment-specific scheduling stays out of core schema

Cron schedules, cloud bucket credentials, cluster-manager wiring, and failover automation are
deployment concerns. `.eon` should define requirements and hints, not embed every production
automation detail.

## What `vsr` Should And Should Not Do

### In scope

- declare intended backup and replication posture in `.eon`
- generate docs, env templates, and emitted ops scaffolding
- validate configuration and live topology
- support restore verification flows
- support SQLite / TursoLocal local snapshot/export commands directly
- expose runtime status hooks for backup freshness and replica lag later
- support replica-aware read routing only when explicitly configured

### Out of scope

- running a distributed consensus system
- automatic cross-region failover orchestration
- replacing PostgreSQL/MySQL-native backup tools
- hiding backend-specific recovery tradeoffs behind one fake universal button

## Current Capability Snapshot

| Capability | Current state |
| --- | --- |
| Backup config in `.eon` | Implemented |
| Backup CLI | Implemented for plan/doctor, SQLite/TursoLocal snapshot/verify, Postgres/MySQL logical export, and S3-compatible artifact transport |
| Restore verification | Implemented for SQLite/TursoLocal snapshot artifacts and Postgres/MySQL logical dump artifacts |
| Replica-aware runtime pools | Not implemented |
| Replica lag checks | Not implemented |
| Live primary/read role validation | Implemented for Postgres/MySQL doctor checks |
| Emitted backup/restore ops scaffolding | Not implemented |
| Backend-specific recovery docs | Partially implemented |

## Backend Strategy Matrix

| Backend | Backup posture | Replication posture | `vsr` role |
| --- | --- | --- | --- |
| `db: Sqlite` + `database.engine = TursoLocal` | First-class local snapshot/export and restore verification | No built-in replication story by default | Direct CLI support plus generated docs |
| `db: Sqlite` + `database.engine = Sqlx` | Safe SQLite snapshot/export path with clear file-locking guidance | No built-in replication story by default | Direct CLI support plus generated docs |
| `db: Postgres` | Native logical dump plus PITR-oriented guidance | Streaming/read-replica topology validation | Validation, emitted ops scaffolding, optional runtime read routing |
| `db: Mysql` | Native logical/physical backup plus binlog-oriented guidance | Replica topology validation | Validation, emitted ops scaffolding, optional runtime read routing |

## Proposed `.eon` Shape

The best long-term home is under `database`, because backup and replication are runtime database
concerns, not API resource concerns.

Recommended shape:

```eon
database: {
    engine: {
        kind: Sqlx
    }
    resilience: {
        profile: Pitr
        backup: {
            required: true
            mode: Snapshot
            target: S3
            verify_restore: true
            max_age: "24h"
            encryption_key_env: "BACKUP_ENCRYPTION_KEY"
            retention: {
                daily: 7
                weekly: 4
                monthly: 12
            }
        }
        replication: {
            mode: ReadReplica
            read_routing: Explicit
            read_url_env: "DATABASE_READ_URL"
            max_lag: "30s"
            replicas_expected: 1
        }
    }
}
```

### Why `database.resilience`

- It groups durability and recovery settings together.
- It stays separate from SQL dialect selection.
- It leaves room for backup and replication to evolve independently.

### Why schedule is not in the first config shape

The exact execution schedule belongs to deployment tooling. For example:

- local cron/systemd timers
- GitHub Actions
- Kubernetes CronJobs
- managed cloud backup services

`.eon` should describe recovery requirements such as retention, max backup age, and restore
verification, while emitted tooling can turn those requirements into deployment-specific examples.

## Proposed Concepts

### Resilience profiles

Profiles keep the simple path simple:

- `SingleNode`
  Meant for local SQLite / TursoLocal and non-HA deployments.
- `Pitr`
  Backup plus point-in-time recovery expectations.
- `Ha`
  Backup plus replica topology expectations and optional read routing.

Profiles should expand into sensible defaults instead of forcing every service to define every
detail.

### Backup modes

- `Snapshot`
  Consistent full snapshots, best for local SQLite/TursoLocal and some physical-backup flows.
- `Logical`
  Portable schema/data dumps.
- `Physical`
  Physical data directory or engine-native physical backup flows.
- `Pitr`
  Base backup plus WAL/binlog retention expectations.

### Replication modes

- `None`
- `ReadReplica`
- `HotStandby`
- `ManagedExternal`

`ManagedExternal` is important because many production deployments will use provider-managed
replication where `vsr` can only validate and document, not orchestrate.

### Read routing modes

- `Off`
- `Explicit`

Do not start with automatic heuristics. The generated server should only route generated `Read`
operations to replicas when the service explicitly opts into that behavior and the runtime has a
declared read connection.

## CLI Roadmap

### Phase 1: planning and validation

Add:

- `vsr backup plan --input api.eon`
- `vsr backup doctor --config api.eon --database-url ...`
- `vsr replication doctor --config api.eon --database-url ...`

These commands should:

- explain the expected resilience posture
- validate required env vars and runtime URLs
- emit backend-specific next steps
- detect obvious topology mismatches
- inspect backend-native primary/read role signals where possible
- warn when restore verification is required but not configured

### Phase 2: direct SQLite / TursoLocal support

Add:

- `vsr backup snapshot`
- `vsr backup verify-restore`
- `vsr backup push`
- `vsr backup pull`

This is the one place where `vsr` should own the full flow directly, because the database is local
and the runtime already owns that bootstrap path.

Expected outputs:

- backup artifact
- manifest with timestamp, backend, checksum, and schema/module metadata
- temp restore verification result
- optional remote transport to S3-compatible object storage without changing artifact format

### Phase 3: Postgres / MySQL operator integration

Add backend-aware plan and verification support without pretending to replace native tooling.

This phase has now started:

- `vsr backup export` creates logical dump artifacts for Postgres/MySQL
- it uses native `pg_dump` / `mysqldump` when available
- it falls back to official Docker client images when those tools are missing locally
- `vsr backup verify-restore` now restores those logical artifacts into disposable local Docker databases and validates the restored schema

Examples:

- validate `DATABASE_URL` and `DATABASE_READ_URL`
- emit `pg_dump` / `pg_basebackup` or `mysqldump` / physical-backup guidance
- verify restore artifacts in disposable local environments
- validate replica lag thresholds and primary/read URL separation

### Phase 4: emitted operations scaffolding

Extend emitted server projects with optional:

- backup README
- env variable template additions
- cron/systemd/Kubernetes examples
- restore drill examples

This should be generated from the resilience contract, not handwritten per example.

## Runtime Roadmap

### Replica-aware pools

Add an explicit runtime pool model:

- primary/write pool
- optional read pool

Generated handlers should only use the read pool for eligible generated `Read` operations when:

- replication is configured
- read routing is enabled
- a read URL is configured

### Health and observability

Later runtime support should expose:

- replica connectivity
- lag threshold status
- last-known backup freshness metadata

This belongs in readiness/metrics support, not as silent runtime magic.

## Restore Verification Strategy

Restore verification should become a first-class success criterion.

Every supported backup path should aim to support:

1. create or reference a backup artifact
2. restore into a disposable target
3. run schema verification and optional smoke checks
4. produce a machine-readable result

Recommended follow-up command shape:

```bash
vsr backup verify-restore --config api.eon --artifact backup.tar.zst
```

For Postgres and MySQL this may initially operate as a wrapper around local disposable containers
or explicitly provided restore environments rather than attempting in-place restores.

## Acceptance Criteria

### Phase 1 acceptance

- `.eon` can declare intended resilience posture
- `vsr backup plan` explains the expected strategy per backend
- `vsr backup doctor` validates obvious config gaps
- `vsr replication doctor` validates explicit primary/read topology inputs

### Phase 2 acceptance

- SQLite / TursoLocal services can produce a consistent backup artifact
- restore verification works on a disposable local target
- backup freshness requirements can be checked against generated metadata

### Phase 3 acceptance

- Postgres and MySQL services have backend-specific plan/doctor flows
- emitted docs explain logical vs PITR paths clearly
- replica/read URL separation is validated

### Phase 4 acceptance

- generated servers can optionally use a read pool for generated `Read` handlers
- writes never use the read pool
- readiness/diagnostics surface replica state clearly

## Recommended Order

1. Add `database.resilience` to the compiler model and docs only.
2. Add `vsr backup plan` and `vsr backup doctor`.
3. Add first-class SQLite / TursoLocal snapshot plus restore verification.
4. Add Postgres/MySQL plan + doctor + restore-verification support.
5. Add replica-aware runtime pool model.
6. Add emitted ops scaffolding and recovery drill templates.

## Notes For The Existing Roadmap

This work sits alongside the current production backlog:

- it depends on the ongoing Postgres/MySQL parity work
- it complements readiness/metrics/tracing support
- it should land before calling the project production-grade for serious deployments

The most important implementation boundary is this: `vsr` should help users build reliable backup
and replication strategies, but it should not masquerade as a full database operator.
