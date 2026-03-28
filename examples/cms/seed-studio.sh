#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"

VSR_BIN=${VSR_BIN:-vsr}
BASE_URL=${BASE_URL:-https://127.0.0.1:8443}
ADMIN_EMAIL=${ADMIN_EMAIL:-editor@example.com}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-ChangeMe123!}
ADMIN_WORKSPACE_ID=${ADMIN_WORKSPACE_ID:-1}
ADMIN_IS_STAFF=${ADMIN_IS_STAFF:-true}
SERVER_LOG=${SERVER_LOG:-"$ROOT_DIR/var/seed-server.log"}

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
      if (value == null) {
        process.exit(1);
      }
      value = value[part];
    }
    if (value == null) {
      process.exit(1);
    }
    if (typeof value === "object") {
      process.stdout.write(JSON.stringify(value));
    } else {
      process.stdout.write(String(value));
    }
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

list_find_pair_id() {
  node -e '
    const fs = require("node:fs");
    const data = JSON.parse(fs.readFileSync(0, "utf8"));
    const firstKey = process.argv[1];
    const firstValue = process.argv[2];
    const secondKey = process.argv[3];
    const secondValue = process.argv[4];
    const items = Array.isArray(data.items) ? data.items : [];
    const hit = items.find((item) =>
      String(item?.[firstKey] ?? "") === firstValue &&
      String(item?.[secondKey] ?? "") === secondValue
    );
    if (hit?.id != null) {
      process.stdout.write(String(hit.id));
    }
  ' "$1" "$2" "$3" "$4"
}

api_get() {
  curl -ksS -H "$AUTH_HEADER" "$BASE_URL/api/$1"
}

api_post() {
  curl -ksS \
    -X POST \
    -H "$AUTH_HEADER" \
    -H 'Content-Type: application/json' \
    "$BASE_URL/api/$1" \
    -d "$2"
}

api_action() {
  curl -ksS \
    -X POST \
    -H "$AUTH_HEADER" \
    -H 'Content-Type: application/json' \
    "$BASE_URL/api/$1/$2/$3" \
    -d '{}'
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

ensure_resource() {
  list_path=$1
  context=$2
  key=$3
  value=$4
  create_path=$5
  create_body=$6

  existing_json=$(api_get "$list_path?limit=100&context=$context")
  existing_id=$(printf '%s' "$existing_json" | list_find_id "$key" "$value" || true)
  if [ -n "${existing_id:-}" ]; then
    printf '%s' "$existing_id"
    return 0
  fi

  created_json=$(api_post "$create_path" "$create_body")
  printf '%s' "$created_json" | json_get id
}

ensure_pair_resource() {
  list_path=$1
  context=$2
  first_key=$3
  first_value=$4
  second_key=$5
  second_value=$6
  create_path=$7
  create_body=$8

  existing_json=$(api_get "$list_path?limit=100&context=$context")
  existing_id=$(printf '%s' "$existing_json" | list_find_pair_id "$first_key" "$first_value" "$second_key" "$second_value" || true)
  if [ -n "${existing_id:-}" ]; then
    printf '%s' "$existing_id"
    return 0
  fi

  created_json=$(api_post "$create_path" "$create_body")
  printf '%s' "$created_json" | json_get id
}

printf 'Preparing schema and local runtime inputs...\n'
"$VSR_BIN" setup --non-interactive

printf 'Ensuring admin user %s exists...\n' "$ADMIN_EMAIL"
"$VSR_BIN" create-admin --email "$ADMIN_EMAIL" --password "$ADMIN_PASSWORD"

printf 'Starting API temporarily for seed requests...\n'
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

printf 'Authenticating seed user...\n'
LOGIN_RESPONSE=$(curl -ksS \
  -X POST \
  -H 'Content-Type: application/json' \
  "$BASE_URL/api/auth/login" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")
TOKEN=$(printf '%s' "$LOGIN_RESPONSE" | json_get token)
AUTH_HEADER="Authorization: Bearer $TOKEN"
ACCOUNT_RESPONSE=$(curl -ksS -H "$AUTH_HEADER" "$BASE_URL/api/auth/account")
SELF_USER_ID=$(printf '%s' "$ACCOUNT_RESPONSE" | json_get id)

printf 'Seeding workspace-aware studio data...\n'
WORKSPACE_ID=$(ensure_resource \
  'workspaces' \
  'admin' \
  'slug' \
  'northstar' \
  'workspaces' \
  '{"name":"Northstar Studio","slug":"northstar","default_locale":"en","public_base_url":"https://northstar.example","theme_settings":{"palette":"editorial","accent":"teal"},"editorial_settings":{"review_required":true,"homepage_entry_slug":"welcome-to-northstar"}}')

curl -ksS \
  -X PATCH \
  -H "$AUTH_HEADER" \
  -H 'Content-Type: application/json' \
  "$BASE_URL/api/auth/admin/users/$SELF_USER_ID" \
  -d "{\"claims\":{\"workspace_id\":$WORKSPACE_ID}}" >/dev/null

LOGIN_RESPONSE=$(curl -ksS \
  -X POST \
  -H 'Content-Type: application/json' \
  "$BASE_URL/api/auth/login" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")
TOKEN=$(printf '%s' "$LOGIN_RESPONSE" | json_get token)
AUTH_HEADER="Authorization: Bearer $TOKEN"

PROFILE_ID=$(ensure_resource \
  'profiles' \
  'self' \
  'handle' \
  'editorial-lead' \
  'profiles' \
  '{"handle":"editorial-lead","display_name":"Editorial Lead","headline":"Managing editor","bio":"Leads story planning, reviews, and publishing cadence for the example workspace.","avatar_asset":null,"preferences":{"density":"comfortable","dashboard":"publishing"}}')

TOPIC_ID=$(ensure_resource \
  'topics' \
  'edit' \
  'slug' \
  'product-updates' \
  'topics' \
  '{"name":"Product Updates","slug":"product-updates","description":"Announcements and release communication.","color":"teal","meta":{"audience":"customers","priority":"high"}}')

ASSET_ID=$(ensure_resource \
  'assets' \
  'edit' \
  'file_name' \
  'hero-grid.jpg' \
  'assets' \
  '{"kind":"image","file_name":"hero-grid.jpg","mime_type":"image/jpeg","byte_size":248320,"width":1600,"height":900,"alt_text":"Editorial dashboard on a teal interface","source_url":"https://images.example/hero-grid.jpg","focal_point":{"x":0.42,"y":0.38},"metadata":{"origin":"seed","license":"example"}}')

ENTRY_ID=$(ensure_resource \
  'entries' \
  'edit' \
  'slug' \
  'welcome-to-northstar' \
  'entries' \
  "{\"type\":\"article\",\"status\":\"draft\",\"visibility\":\"workspace\",\"slug\":\"welcome-to-northstar\",\"title\":\"Welcome to Northstar\",\"summary\":\"A seeded launch article for the modern CMS studio example.\",\"hero_asset\":$ASSET_ID,\"reviewer\":null,\"published_at\":\"2026-03-28T09:00:00.000Z\",\"scheduled_for\":null,\"body_blocks\":[{\"type\":\"hero\",\"content\":\"Northstar launches with a structured editorial workflow.\"},{\"type\":\"paragraph\",\"content\":\"This seeded entry shows how the studio handles blocks, SEO, and workflow actions.\"}],\"seo\":{\"meta_title\":\"Welcome to Northstar\",\"meta_description\":\"Seeded article for the example CMS studio.\",\"canonical_url\":\"https://northstar.example/welcome-to-northstar\",\"index_mode\":\"index\"},\"settings\":{\"featured\":true,\"seeded\":true}}")

ENTRY_TOPIC_ID=$(ensure_pair_resource \
  'entry-topics' \
  'edit' \
  'entry' \
  "$ENTRY_ID" \
  'topic' \
  "$TOPIC_ID" \
  'entry-topics' \
  "{\"entry\":$ENTRY_ID,\"topic\":$TOPIC_ID}")

MENU_ID=$(ensure_resource \
  'menus' \
  'edit' \
  'handle' \
  'main-navigation' \
  'menus' \
  '{"name":"Main Navigation","handle":"main-navigation","description":"Primary site navigation for the example workspace.","settings":{"placement":"header","seeded":true}}')

MENU_ITEM_ID=$(ensure_pair_resource \
  'menu-items' \
  'edit' \
  'menu' \
  "$MENU_ID" \
  'entry' \
  "$ENTRY_ID" \
  'menu-items' \
  "{\"menu\":$MENU_ID,\"parent_item\":null,\"label\":\"Welcome\",\"item_kind\":\"entry\",\"entry\":$ENTRY_ID,\"external_url\":null,\"target\":\"self\",\"sort_order\":0,\"meta\":{\"seeded\":true}}")

printf 'Publishing the seeded entry...\n'
api_action 'entries' "$ENTRY_ID" 'submit_review' >/dev/null
api_action 'entries' "$ENTRY_ID" 'publish' >/dev/null

printf '\nSeed complete.\n'
printf 'Admin email: %s\n' "$ADMIN_EMAIL"
printf 'Admin password: %s\n' "$ADMIN_PASSWORD"
printf 'Workspace id claim: %s\n' "$WORKSPACE_ID"
printf 'Workspace row id: %s\n' "$WORKSPACE_ID"
printf 'Profile id: %s\n' "$PROFILE_ID"
printf 'Topic id: %s\n' "$TOPIC_ID"
printf 'Asset id: %s\n' "$ASSET_ID"
printf 'Entry id: %s\n' "$ENTRY_ID"
printf 'EntryTopic id: %s\n' "$ENTRY_TOPIC_ID"
printf 'Menu id: %s\n' "$MENU_ID"
printf 'Menu item id: %s\n' "$MENU_ITEM_ID"
printf '\nOpen the studio at %s/studio/\n' "$BASE_URL"
