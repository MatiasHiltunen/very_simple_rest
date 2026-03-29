# Modern CMS Example

This project is a contract-first CMS example built on `very_simple_rest`.

## Structure

- `api.eon`: the backend contract
- `web/`: the Material-based CMS studio client
- `var/`: generated OpenAPI, SQL, and local database files

## Backend

From this directory:

```sh
vsr setup
vsr serve api.eon
```

`vsr setup` will prepare `.env`, generate local TLS certs when needed, and apply the schema. By default the API serves on the configured backend port, and the built studio is mounted at `/studio`.

## Local Site Preview

The CMS studio now has a first-class local site preview route. Editors no longer need to seed a fake
`public_base_url` just to open a workspace in another tab.

- workspace preview root: `/studio/preview/<workspace-slug>`
- entry preview path: `/studio/preview/<workspace-slug>/<entry-slug>`
- the editor's **Open local preview** button carries unsaved draft state into that route for local inspection
- if `public_base_url` is configured, it remains the published origin and is shown separately in the studio

Because the same SPA is also mounted at `/`, the equivalent root-mounted preview path is
`/preview/<workspace-slug>`.

## Seed A First Studio

To create a usable local admin plus starter workspace/content:

```sh
./seed-studio.sh
```

Defaults:

- email: `editor@example.com`
- password: `ChangeMe123!`
- workspace claim: `1`

The seed script uses the supported CLI path:

1. `vsr setup --non-interactive`
2. `vsr create-admin`
3. temporary `vsr serve api.eon`
4. real login, workspace creation or lookup, auth-claim sync, token refresh, and API writes for the workspace, profile, asset, topic, entry, menu, and menu item

Override any of these when needed:

```sh
ADMIN_EMAIL=lead@example.com ADMIN_PASSWORD='StrongerPass123!' ./seed-studio.sh
```

Optional overrides:

```sh
WORKSPACE_PUBLIC_BASE_URL=https://news.example.com \
ENTRY_CANONICAL_URL=https://news.example.com/welcome-to-northstar \
./seed-studio.sh
```

If you do not provide those overrides, the seed flow leaves `public_base_url` and the entry canonical URL
unset so the local preview route stays authoritative during development.

## Local Asset Storage For Development

This example does not rely on S3 or another object-storage service in local development. Instead it uses a local file-backed asset path:

- files are served from `/uploads`
- the backend declares a local `storage` backend rooted at `var/uploads`
- `/uploads` is exposed through a storage public mount, not a plain static directory
- `/_s3/media/...` exposes the same backend through a narrow path-style S3-compatible local mount
- the studio and helper script upload files through that S3-compatible endpoint, then create asset rows through `/api/assets`
- asset rows point `delivery_url` at that local path
- the studio also deletes the backing local object when an uploaded asset row is removed

Import a local file into development storage and create the matching asset row:

```sh
./import-asset.sh ~/Downloads/hero.jpg "Homepage hero image"
```

That command:

1. uploads the file through `PUT /_s3/media/<key>`
2. ensures the local admin exists
3. starts the API temporarily if needed
4. creates the asset row through `/api/assets`

This is intentionally a development/storage bootstrap path, not a production object storage system.

### Local S3-Compatible Endpoint

The same local storage backend is also mounted as a narrow S3-compatible endpoint for development:

- endpoint URL: `https://127.0.0.1:8443/_s3`
- bucket: `media`
- path style: required
- TLS: self-signed dev certificate, so local clients usually need to disable certificate verification
- credentials: any dummy access key / secret work today; the local mount does not validate AWS signatures yet
- the CMS studio uses same-origin `PUT` requests to this endpoint instead of the custom `/api/uploads` helper

Example with AWS CLI-compatible tooling:

```sh
AWS_ACCESS_KEY_ID=local \
AWS_SECRET_ACCESS_KEY=local \
aws s3api put-object \
  --endpoint-url https://127.0.0.1:8443/_s3 \
  --no-verify-ssl \
  --bucket media \
  --key manual/example.txt \
  --body README.md
```

That writes into the same `var/uploads/assets/...` tree that powers `/uploads` and the studio asset flow.

## Studio Development

For live frontend development:

```sh
cd web
npm install
npm run dev
```

The Vite dev server runs on `http://127.0.0.1:5173/studio/` and proxies API traffic to `https://127.0.0.1:8443` by default. Override that target with `VITE_API_PROXY_TARGET` if your backend uses a different address.
The dev proxy also forwards `/_s3` and `/uploads`, so local object uploads and asset previews keep working from the studio during frontend development.
The same dev server also serves the local site preview route under `http://127.0.0.1:5173/studio/preview/<workspace-slug>`.

## Production Build

To rebuild the studio that the backend serves:

```sh
cd web
npm run build
```

That writes the SPA bundle into `web/dist`, and `api.eon` mounts it under `/studio`.
