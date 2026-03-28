#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"

if [ $# -lt 1 ]; then
  echo "Usage: ./import-asset.sh /path/to/file [alt text]" >&2
  exit 1
fi

SOURCE_FILE=$1
ALT_TEXT=${2:-}
if [ ! -f "$SOURCE_FILE" ]; then
  echo "File not found: $SOURCE_FILE" >&2
  exit 1
fi

VSR_BIN=${VSR_BIN:-vsr}
BASE_URL=${BASE_URL:-https://127.0.0.1:8443}
ADMIN_EMAIL=${ADMIN_EMAIL:-editor@example.com}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-ChangeMe123!}
ADMIN_WORKSPACE_ID=${ADMIN_WORKSPACE_ID:-1}
ADMIN_IS_STAFF=${ADMIN_IS_STAFF:-true}
SERVER_LOG=${SERVER_LOG:-"$ROOT_DIR/var/import-asset-server.log"}

export ADMIN_WORKSPACE_ID
export ADMIN_IS_STAFF

json_get() {
  node -e '
    const fs = require("node:fs");
    const source = fs.readFileSync(0, "utf8");
    const input = source.trim() ? JSON.parse(source) : {};
    const path = process.argv[1].split(".");
    let value = input;
    for (const part of path) {
      value = value?.[part];
    }
    if (value == null) {
      process.exit(1);
    }
    process.stdout.write(typeof value === "object" ? JSON.stringify(value) : String(value));
  ' "$1"
}

list_find_id() {
  node -e '
    const fs = require("node:fs");
    const data = JSON.parse(fs.readFileSync(0, "utf8"));
    const key = process.argv[1];
    const needle = process.argv[2];
    const items = Array.isArray(data.items) ? data.items : [];
    const hit = items.find((item) => String(item?.[key] ?? "") === needle);
    if (hit?.id != null) {
      process.stdout.write(String(hit.id));
    }
  ' "$1" "$2"
}

guess_kind() {
  mime=$1
  case "$mime" in
    image/*) echo "image" ;;
    video/*) echo "video" ;;
    audio/*) echo "audio" ;;
    *) echo "document" ;;
  esac
}

escape_json() {
  node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$1"
}

wait_for_server() {
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if curl -ksSf "$BASE_URL/openapi.json" >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done

  echo "Server did not become ready at $BASE_URL" >&2
  echo "See $SERVER_LOG for startup logs." >&2
  exit 1
}

ORIGINAL_NAME=$(basename -- "$SOURCE_FILE")
MIME_TYPE=$(file -b --mime-type "$SOURCE_FILE" 2>/dev/null || printf 'application/octet-stream')
BYTE_SIZE=$(wc -c < "$SOURCE_FILE" | tr -d ' ')
KIND=$(guess_kind "$MIME_TYPE")

printf 'Preparing API and admin access...\n'
"$VSR_BIN" setup --non-interactive >/dev/null
"$VSR_BIN" create-admin --email "$ADMIN_EMAIL" --password "$ADMIN_PASSWORD" >/dev/null

printf 'Starting API temporarily for asset import...\n'
"$VSR_BIN" serve api.eon >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
cleanup() {
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

wait_for_server

SAFE_NAME=$(printf '%s' "$ORIGINAL_NAME" | tr ' ' '-' | tr -cd '[:alnum:]._-')
if [ -z "$SAFE_NAME" ]; then
  SAFE_NAME="asset"
fi
OBJECT_KEY="manual/$(date +%s)-$SAFE_NAME"
SOURCE_URL="/uploads/assets/$OBJECT_KEY"

curl -ksS \
  -X PUT \
  -H "Content-Type: $MIME_TYPE" \
  -H "x-amz-meta-original-name: $ORIGINAL_NAME" \
  -H 'x-amz-meta-uploaded-via: import-script' \
  --data-binary "@$SOURCE_FILE" \
  "$BASE_URL/_s3/media/$OBJECT_KEY" >/dev/null

LOGIN_RESPONSE=$(curl -ksS \
  -X POST \
  -H 'Content-Type: application/json' \
  "$BASE_URL/api/auth/login" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")
TOKEN=$(printf '%s' "$LOGIN_RESPONSE" | json_get token)
AUTH_HEADER="Authorization: Bearer $TOKEN"

WORKSPACES_RESPONSE=$(curl -ksS -H "$AUTH_HEADER" "$BASE_URL/api/workspaces?limit=50&context=admin")
WORKSPACE_ID=$(printf '%s' "$WORKSPACES_RESPONSE" | list_find_id slug northstar || true)
if [ -z "${WORKSPACE_ID:-}" ]; then
  WORKSPACE_CREATE_RESPONSE=$(curl -ksS \
    -X POST \
    -H "$AUTH_HEADER" \
    -H 'Content-Type: application/json' \
    "$BASE_URL/api/workspaces" \
    -d '{"name":"Northstar Studio","slug":"northstar","default_locale":"en","public_base_url":"https://northstar.example","theme_settings":{"palette":"editorial","accent":"teal"},"editorial_settings":{"review_required":true,"homepage_entry_slug":"welcome-to-northstar"}}')
  WORKSPACE_ID=$(printf '%s' "$WORKSPACE_CREATE_RESPONSE" | json_get id)
fi

ALT_TEXT_JSON=$(escape_json "$ALT_TEXT")
FILE_NAME_JSON=$(escape_json "$SAFE_NAME")
MIME_JSON=$(escape_json "$MIME_TYPE")
SOURCE_URL_JSON=$(escape_json "$SOURCE_URL")

CREATE_RESPONSE=$(curl -ksS \
  -X POST \
  -H "$AUTH_HEADER" \
  -H 'Content-Type: application/json' \
  "$BASE_URL/api/assets" \
  -d "{\"kind\":\"$KIND\",\"file_name\":$FILE_NAME_JSON,\"mime_type\":$MIME_JSON,\"byte_size\":$BYTE_SIZE,\"width\":null,\"height\":null,\"alt_text\":$ALT_TEXT_JSON,\"source_url\":$SOURCE_URL_JSON,\"focal_point\":null,\"metadata\":{\"storage\":\"local-s3-dev\",\"bucket\":\"media\",\"object_key\":\"$OBJECT_KEY\",\"original_name\":\"$ORIGINAL_NAME\"}}")

ASSET_ID=$(printf '%s' "$CREATE_RESPONSE" | json_get id)
DELIVERY_URL=$(printf '%s' "$CREATE_RESPONSE" | json_get delivery_url)

printf '\nImported local development asset.\n'
printf 'Asset id: %s\n' "$ASSET_ID"
printf 'Uploaded object: %s\n' "$OBJECT_KEY"
printf 'Delivery URL: %s%s\n' "$BASE_URL" "$DELIVERY_URL"
