# Shared Authentication Admission Migration Proof

Date: 2026-09-11. Session presentation was committed and pushed to `origin/v1`
as `d1f4a35809ededfc286ddcaf4e36a40a6f7fca3b`, together with the preceding
registration (`723f711cf`) and admin/provisioning (`499e61857`) milestones.
Local and fetched upstream SHAs matched after publication. This admission
continuation remains uncommitted; main and its unrelated reports are preserved.

## Implementation

- `rate_limit::MemoryRateLimitStore` implements the existing store contract with
  atomic, mutex-protected sliding windows and monotonic expiration.
- Explicit capacity limits cover keys, accepted timestamps and string bytes per
  key. Default limits are 10,000, 100,000 and 1,024 respectively. Queue allocation
  shrinks after expired bursts rather than retaining each key's historical peak.
- No active counter is evicted to accommodate another key. Capacity failure,
  poisoned state, invalid keys/rules and live rule changes return errors.
- `auth::admission` supplies shared login/register rules, key construction,
  redacted HTTP failures and an injectable-store handler wrapper. The runtime
  implementation has no Actix or Axum dependency requirement.
- Native Actix replaces its unbounded map with the shared store and delegates
  admission without changing public endpoint signatures. Missing configured
  app data now fails closed instead of disabling the limit.
- `auth_api_routes_with_settings_and_limiter` accepts shared Actix application
  data. Native CLI state owns it once; emitted servers allocate it outside
  `HttpServer::new`, so worker count no longer multiplies their quotas.

## Compatibility And Boundaries

Login and registration have independent per-client windows. Admitted successes
and failures consume quota. Denied attempts do not extend the window. Existing
429 JSON codes/messages remain, with Retry-After rounded up instead of down.
Store/capacity failures return redacted `503 auth_rate_limit_unavailable` and
`Retry-After: 1`, never credentials or cookies. Zero rules are invalid; absent
EON rules retain disabled enforcement. Requests exceeding a store's total event
capacity cannot be admitted. No EON capacity override was added.

The default wrapper trusts only the direct socket IP. Forwarding headers and
supplied identities cannot change its bucket; absent peers share `unknown`.
Native Actix retains the existing trusted-suffix proxy resolver. Explicit
proxy-aware callers may resolve trust before invoking the shared check; neutral
transport `trusted_proxies` settings remain unsupported and rejected.

Native JSON extraction still occurs before the admission check. Neutral wrappers
placed around extraction charge malformed JSON first. Tests use extracted valid
JSON bodies to compare endpoint admission; they do not claim extraction-order
parity. The old native routing helpers remain source-compatible and allocate
per registration. Hand-written multi-worker servers must opt into the explicit
shared helper, and existing emitted projects must be regenerated.

These are single-process counters, lost on restart. No Redis implementation,
cluster-wide quota, durable recovery delivery or complete abuse/enumeration
defense is claimed. Cold-key pruning happens at most once per second; capacity
recovery may conservatively lag expiry by that interval. Bounds are counts, not
a byte-exact allocation budget. Rule changes cannot clear a live budget without
explicit reset or expiry.

## Local Verification

Commands use stable Rust, locked dependencies, no incremental compilation and
disabled dev/test debug information.

| Check | Result |
| --- | --- |
| Auth-only runtime library, without HTTP features | 77 passed, including 12 admission/store regressions |
| Focused real HTTP admission tests | 2 passed across native/shared Actix/Axum |
| Full workspace, all features | 793 passed, 0 failed, 16 ignored across 71 suites |
| Built-in auth HTTP suite within that run | All 13 passed |
| CLI worker-scope test and generated reference parity | Passed |
| Emitted Bridgeboard build and clean-room end-to-end test | Passed |
| Workspace Clippy, all features and targets | Passed with workspace/test warnings; none in the new production admission/store modules |
| Contract-only build and auth-only dependency isolation | Passed; no normal Actix/Axum dependencies with only `auth-builtin` |
| Scoped rustfmt, mdBook and whitespace checks | Passed |

The first full run caught a reference mismatch while the documentation generator
was being updated. The CLI regenerated the checked-in reference, including its
exact trailing whitespace. The final complete run above used the corrected
generator/reference and final runtime code. Existing ignored tests remain
excluded; local success is not remote CI or production readiness evidence.

The store retains lazy async mutations under one narrowly documented Clippy
exception: constructing and dropping an unpolled check/reset future must not
consume or reset quota. A regression proves this behavior. No lock is held
across an await.

Runtime regressions cover exact expiry, fractional Retry-After rounding, wall
clock rollback, out-of-order concurrent clock observations, live rule changes,
key flooding, global event limits, reset, unpolled-future cancellation, queue allocation reclamation, all
composite-key byte bounds, invalid capacity/rules, poison and 32 concurrent
attempts competing for seven slots. Admission tests cover separate scopes,
unknown peers, forwarded/identity spoofing, canonical IP keys, injected store
failure redaction and invalid rules.

Real SQLite HTTP tests share one store across native Actix with four workers,
shared Actix and Axum. Fresh connections cannot multiply the quota; successful
login and failed credentials both consume it. Registration has an independent
budget. Rejected registration creates no row. Capacity exhaustion produces 503
on all paths without discarding the original exhausted login counter. A direct
native handler missing configured limiter data cannot issue credentials.

The CLI scope-builder test rebuilds four application scopes over one dynamic
service and verifies that its two-attempt budget survives. Emission tests assert
that limiter allocation precedes the worker factory and is absent without
built-in auth. The workspace suite also builds and exercises the emitted
Bridgeboard server. Existing CI auth/HTTP jobs discover the new tests without
workflow changes; their configuration is not remote execution evidence.

Logs use `/private/tmp/vsr-admission-` with `runtime.log`, `http.log`,
`workspace-final.log`, `clippy.log`, `contract.log`, `tree.log` and `book.log`.

## Remaining Migration

Production JSON/path/query extraction and route installation, row authorization,
streaming and complete native/generated backend selection remain. SQLx/Turso
and configured key/email bridges still live in the legacy facade. External
PostgreSQL/MySQL, other operating systems and production workload tests remain
separate gates. This milestone does not complete Phase 3 or add a CLI backend
switch.
