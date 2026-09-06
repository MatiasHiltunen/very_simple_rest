# Dependencies

Last verified: 2026-09-06. Version availability was checked against crates.io
and npm, not inferred from the previous lockfiles.

## Supported Upgrade Set

All 60 direct external Rust crates resolve to their latest stable release in
`Cargo.lock`. Broad compatible manifest requirements are retained where a
major-version migration is unnecessary. Use `--locked` for reproducible builds.

Notable upgrades are SQLx 0.9.0, Turso 0.7.2, jsonwebtoken 11.0.0, Syn 3.0.5,
prettyplease 0.3.0, garde 0.23.0, object_store 0.14.1, actix-files 0.7.0,
actix-multipart 0.8.1, SHA-2 0.11.0, base64 0.23.1, and Brotli 9.0.0.
The vendored SQLx 0.8.6 MySQL driver is removed. The `mysql` feature enables
upstream `sqlx/mysql-rsa`, retaining non-TLS RSA authentication support.

SQLx 0.9 requires Rust 1.94.0 and the current AWS crates require 1.94.1.
The full workspace was tested on stable Rust 1.98.1; the dependency minimum
has not been established as a tested workspace MSRV. See the
[SQLx changelog](https://github.com/launchbadge/sqlx/blob/main/CHANGELOG.md).
Dynamic SQL remains inside the existing database wrapper, with values bound
separately. `AssertSqlSafe` marks this trust boundary; it does not sanitize SQL.

The CMS uses MUI 9.4.0, Vite 8.2.2, React 19.2.8, React Router 7.18.3,
ESLint 10.10.0, and Playwright 1.63.0. Deprecated MUI system props and slots
were migrated using the [official migration tools](https://mui.com/material-ui/migration/upgrade-to-v9/).
The npm workspace uses TypeScript 7.0.2.

## Compatibility Exceptions

| Package | Selected | Latest checked | Reason and removal condition |
| --- | --- | --- | --- |
| CMS TypeScript | `~6.0.3` | 7.0.2 | typescript-eslint 8.69.0 declares support for TypeScript `>=4.8.4 <6.1.0`. Remove the pin after its peer range supports 7 and build/lint pass. |
| npm wrapper tsx | `4.21.0` | 4.23.13 | Every release from 4.21.1 through 4.23.13 failed the existing file-URL config-import tests. 4.21.0 passed on Node 22.23.2 and 25.9.0. Remove the pin when both runtimes pass `packages/vsr/test/config.test.mjs` with the candidate release. |
| tsx transitive esbuild | root override `^0.28.1`, locked 0.28.2 | 0.28.2 | tsx 4.21.0 otherwise selects the vulnerable 0.27 line. Both config-loader test runs pass with the override. Remove it when the selected tsx release accepts patched esbuild itself. |

The esbuild override is a **workspace installation policy**, not a property of
the published npm package: npm consumers must apply an equivalent root override
until tsx can be upgraded. Do not describe a separately installed package as
audit-clean based on this workspace audit. The advisory concerns esbuild's
Windows development server; VSR uses its transformation API, not that server.
[esbuild advisory](https://github.com/advisories/GHSA-g7r4-m6w7-qqqr).

## Outstanding Rust Advisories

Both npm lockfiles pass `npm audit --include=dev` with zero vulnerabilities.
`cargo audit` still exits nonzero. These findings are not suppressed or waived.

| Dependency path | Advisory | Status |
| --- | --- | --- |
| actix-web / actix-http 3.13.5 -> h2 0.3.27 | [RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html) | HTTP/2 empty DATA frames can cause unbounded memory use. The fix is in h2 >=0.4.16, outside Actix's current compatible dependency range. A newer h2 0.4 elsewhere in the lockfile does not fix this copy. |
| jsonwebtoken 11.0.0 (`rust_crypto`) -> rsa 0.9.10 | [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) | No patched release. The advisory concerns private-key timing leakage; VSR's configured JWT algorithms are HMAC, ECDSA, and EdDSA, not RSA. This is a reachability observation, not a formal waiver. |
| sqlx-mysql 0.9.0 (`mysql-rsa`) -> rsa 0.10.0-rc.18 | [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) | SQLx uses server public-key encryption for authentication. Private-key operations are not part of that path. The upstream dependency is a release candidate even though the direct SQLx release is stable. |
| Turso 0.7.2 -> tantivy 0.26.1 -> lru 0.16.4 | [RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253.html) | Unsoundness warning, fixed in lru >=0.18.2. Exploitation requires particular panicking-key/drop and unwind behavior; reachability through Tantivy has not been demonstrated. |
| garde -> phonenumber -> postcard -> heapless -> atomic-polyfill 1.0.3 | [RUSTSEC-2023-0089](https://rustsec.org/advisories/RUSTSEC-2023-0089.html) | Unmaintained dependency warning in the all-target lockfile; not active in the tested macOS dependency tree. |

Before deployment, either update the owning upstream dependency, deliberately
disable an affected capability with compatibility tests, or record an approved,
time-limited risk exception. Do not force incompatible h2/lru versions into
their parents or silently disable transport/database features.

## Verification

```sh
cargo +stable test --workspace --all-features --no-fail-fast
cargo +stable check --workspace
cargo +stable check --workspace --no-default-features
npm ci
npm run check:vsr-package
npm run check:vsr-schema
npm ci --prefix examples/cms/web
npm run lint --prefix examples/cms/web
cd examples/cms/web
npx playwright install chromium
npm run test:smoke
```

Browser smoke tests use mocked API responses, temporary preview servers, and
screenshots in the system temporary directory. They validate UI compatibility,
not backend authorization or real content persistence. Rebuild the CMS before
serving `web/dist`; generated build output is not part of this source upgrade.
