# Enterprise Operations API

An executable, EON-defined Axum backend example for a multi-tenant enterprise
application. It contains projects, change requests, assets and owner-private
notes. This is an authenticated database-backed migration slice, not a claim
that the whole VSR CLI has been ported or that SQLite is an enterprise HA tier.

## Run

Run these commands from the repository worktree:

```sh
cargo +stable run -p enterprise-api -- demo-init
cargo +stable run -p enterprise-api -- serve
```

The first command explicitly creates an isolated demonstration database and
ES256 key pair under `examples/enterprise_api/var/`. It refuses to overwrite
existing data or keys. The second reads `server.eon` and starts **Axum** at
`http://127.0.0.1:8091`. Use another loopback port in that file if it is occupied.
Health probes, `/openapi.json` and HTTP OPTIONS/CORS preflights are anonymous;
business endpoints require authentication.

Demo tokens expire after 15 minutes. The private key is never loaded by `serve`.
Do not deploy the demonstration key, identities or grants. Local token files
use owner-only permissions on Unix; protect their directory with equivalent
ACLs on Windows. No tokens are printed to logs or embedded in source control.

| Token file in `var/` | User | Tenant | Current database roles |
| --- | --- | --- | --- |
| `alice.token` | 1 | 1 | reader, editor |
| `bob.token` | 2 | 1 | reader, editor |
| `carol.token` | 3 | 1 | reader, manager, auditor |
| `dana.token` | 4 | 2 | reader, editor |

For example, create a project using the generated token file:

```sh
curl -i http://127.0.0.1:8091/api/v1/project \
  -H "Authorization: Bearer $(<examples/enterprise_api/var/alice.token)" \
  -H 'Content-Type: application/json' \
  --data '{"name":"Acquisition integration","cost_center":"EU-OPS"}'
```

The server assigns `id`, `tenant_id` and `owner_user_id`, returning 201, Location
and ETag. PATCH and DELETE require the exact ETag in `If-Match`; omitted and
stale versions return 428 and 412. List endpoints use `?after=<id>&limit=<n>`.
They never accept tenant overrides or arbitrary SQL-style filters.

## EON Contract

- `api.eon` is a standard VSR service document. The existing compiler validates
  it and generates the actual SQLite tables. Its resources, scalar types, roles,
  row filters, assignments, relations, token issuer/audience/TTL and body limit
  become the embedded application contract. Rebuild after changing this file.
- `server.eon` is this example runner's strict launcher document. It selects
  `"Axum"` or `"Actix"`, the listener, database file, public verification keys,
  allowed browser origins and capacity limits. Paths resolve relative to it.
- `profile.rs` rejects unknown or unsupported service options before compilation.
  The example supports required String/I64/Bool fields, explicit role gates,
  conjunctive tenant/owner filters, and restrictive same-tenant relations. It
  does not silently ignore richer VSR policies, validators or middleware.
- The legacy compiler is a **build dependency only**. The default binary's
  normal dependency graph contains no Actix. This is not a new generic EON CLI
  backend selector and does not use generated Actix handlers behind Axum.

To use the same application through Actix, change `backend` in `server.eon` to
`"Actix"` and run:

```sh
cargo +stable run -p enterprise-api --no-default-features --features actix -- serve
```

Unavailable backends, missing/invalid public keys, zero/unbounded settings,
non-loopback plaintext listeners, and schema checksum mismatches fail startup.
Schema changes require an explicit migration; the example never auto-drops data.
For a non-loopback listener configure `tls: { cert_file: "...", key_file: "..." }`.

## Authorization Boundaries

Every application request requires one bearer token. Verification pins ES256,
the configured key ID, `at+jwt` token type, issuer, audience, subject, expiry,
not-before time and a bounded token lifetime. The API does not fetch keys from
token-supplied URLs. Multiple configured public keys provide a rotation window;
restarting with a removed key makes its tokens invalid.

The database must also contain an enabled principal at the token's current
version and a nonexpired tenant-specific grant for the operation's EON role.
Revoked token IDs are rejected. Token `roles`, `is_admin`, cookies, forwarding
headers and client-supplied tenant/owner fields never grant access. There is no
HTTP endpoint that provisions users, mints tokens or modifies grants.

All collections and item lookups apply the compiled tenant/owner predicates in
SQL. Updates are owner-bound; managers cannot bypass private-note ownership.
Referenced parents must pass their own current read grant and row policy. A
foreign or invisible record returns 404 without disclosing its contents.

Writers acquire a SQLite write transaction before reading grants and rows.
Authorization, ETag checking, mutation, version increment and audit insertion
commit together. Failed audit insertion rolls back the mutation. Deleted IDs
are not reused, preventing a stale ETag from targeting a replacement record.
Audit rows omit tokens and business payloads; API access is tenant-scoped and
requires the reserved `auditor` role. Triggers reject audit UPDATE/DELETE, but
this is not tamper-proof against a privileged database administrator.

These choices follow [OWASP's deny-by-default and per-request authorization
guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
and [JWT best-current-practice validation boundaries](https://www.rfc-editor.org/rfc/rfc8725.html).

## Proof

```sh
bash examples/enterprise_api/prove.sh
```

The proof uses real Axum and Actix sockets, fresh ES256 signatures and isolated
SQLite files. It checks successful CRUD, role denial, tenant/owner isolation,
mass-assignment rejection, parent authorization, invalid tokens, current grant
revocation/expiry, disabled/version-changed accounts, revoked token IDs, bounded
pagination and input, audit rollback, durable restart and competing writes.
It also checks that the Axum-only normal dependency tree excludes Actix.
No external identity-provider, PostgreSQL, load or HA result is implied.
The [recorded local proof](../../docs/reviews/2026-09-08-enterprise-axum-proof.md)
includes exact test totals and launcher smoke-test results.

## Production Work Still Required

This example is deliberately smaller than a large enterprise deployment:

- Integrate the organization's IdP, subject mapping, MFA/SSO and audited grant
  provisioning; demonstrate rotation and revocation with that real IdP.
- Add a production database adapter, reviewed migrations, backups/restore,
  multi-instance concurrency tests and measured capacity targets. SQLite's
  single-writer transaction strategy is for reproducible local proof.
- Add idempotency keys for retryable create commands. A client timeout can leave
  a committed mutation with an unobserved response; reconcile before retrying POST.
- Apply gateway header/body timeouts, per-principal quotas and tenant budgets.
  The runner bounds buffered body size, handler time and concurrent handlers;
  its deadline starts after transport body extraction, not before it.
- Add durable external audit export, retention, alerting, distributed tracing
  and operations procedures. Rejected transport requests and exhausted/deadline
  requests are not guaranteed to produce database audit entries.
- Add domain workflow authorization such as independent change approval,
  fine-grained data classification and field-level response redaction before
  using this example for those workflows. ChangeRequest is CRUD, not an approval
  engine. There is no browser UI, cookie session or OAuth redirect implementation.

The API is a foundation for an enterprise application, not a finished enterprise
platform or a security certification.
