# Modern CMS Studio

This is the Material-based client application for the example CMS in the parent directory.

## Development

```sh
npm install
npm run dev
```

The dev server runs on `http://127.0.0.1:5173/studio/` and proxies `/api` plus `/openapi.json` to `https://127.0.0.1:8443` by default.

To use a different backend target:

```sh
VITE_API_PROXY_TARGET=https://127.0.0.1:9443 npm run dev
```

## Production Build

```sh
npm run build
```

The built files land in `dist/`. The parent `api.eon` mounts that bundle under `/studio` and mounts `dist/assets` under `/studio/assets`.
