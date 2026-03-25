#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SQLITE_SERVER_PORT="18079"
POSTGRES_CONTAINER="vsr-postgres-parity"
MYSQL_CONTAINER="vsr-mysql-parity"
POSTGRES_PORT="15432"
MYSQL_PORT="13306"
POSTGRES_DB="vsr_parity"
MYSQL_DB="vsr_parity"
ADMIN_EMAIL="admin@example.com"
ADMIN_PASSWORD="password123"
JWT_SECRET_VALUE="parity-secret"
PG_SERVER_PORT="18080"
MYSQL_SERVER_PORT="18081"
GUARDIAN_EMAIL="guardian@example.com"
SPOUSE_EMAIL="spouse@example.com"
FAMILY_SLUG="parity-family"
FAMILY_NAME="Parity Family"
HOUSEHOLD_SLUG="helsinki-flat"
HOUSEHOLD_LABEL="Helsinki Flat"
SHOPPING_TITLE="Buy oat milk"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

free_bind_addr() {
  local bind_addr="$1"
  local port
  port="${bind_addr##*:}"

  if command -v lsof >/dev/null 2>&1; then
    local pids
    pids="$(lsof -ti "tcp:${port}" 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
      kill $pids >/dev/null 2>&1 || true
      sleep 1
    fi
  fi
}

ensure_container() {
  local name="$1"
  local run_cmd="$2"
  if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
    docker start "$name" >/dev/null
  else
    eval "$run_cmd" >/dev/null
  fi
}

reset_postgres() {
  docker exec "$POSTGRES_CONTAINER" psql -U postgres -d "$POSTGRES_DB" \
    -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;' >/dev/null
}

reset_mysql() {
  docker exec "$MYSQL_CONTAINER" mysql -uroot -ppassword \
    -e "DROP DATABASE IF EXISTS ${MYSQL_DB}; CREATE DATABASE ${MYSQL_DB};" >/dev/null
}

compare_summaries() {
  local baseline_label="$1"
  local baseline_path="$2"
  local other_label="$3"
  local other_path="$4"

  if ! diff -u "$baseline_path" "$other_path"; then
    echo "API parity mismatch between ${baseline_label} and ${other_label}" >&2
    exit 1
  fi
}

make_temp_service_root() {
  local backend="$1"
  local backend_lower
  local tmpdir
  local replacement
  backend_lower="$(printf '%s' "$backend" | tr '[:upper:]' '[:lower:]')"
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/family_app_${backend_lower}_XXXXXX")"
  mkdir -p "$tmpdir/public"
  cp -R "$ROOT_DIR/examples/family_app/public/." "$tmpdir/public/"
  if [[ "$backend" == "Sqlite" ]]; then
    replacement=$'db: "Sqlite"\ndatabase: {\n    engine: {\n        kind: "Sqlx"\n    }\n}\n'
  else
    replacement="db: \"${backend}\"\n"
  fi
  perl -0pe "s/database:\\s*\\{\\s*engine:\\s*\\{\\s*kind:\\s*TursoLocal\\s*path:\\s*\\\"var\\/data\\/family_app\\.db\\\"\\s*\\}\\s*\\}\\n/${replacement}/s" \
    "$ROOT_DIR/examples/family_app/family_app.eon" > "$tmpdir/family_app.eon"
  printf '%s\n' "$tmpdir"
}

wait_for_http() {
  local url="$1"
  for _ in $(seq 1 60); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for $url" >&2
  return 1
}

http_json_expect() {
  local method="$1"
  local url="$2"
  local token="$3"
  local payload="$4"
  local expected_status="$5"
  local response body status
  local -a curl_args

  curl_args=(-sS -w '\n%{http_code}' -X "$method" "$url")
  if [[ -n "$payload" ]]; then
    curl_args+=(-H 'content-type: application/json' -d "$payload")
  fi
  if [[ -n "$token" ]]; then
    curl_args+=(-H "authorization: Bearer ${token}")
  fi

  response="$(curl "${curl_args[@]}")"
  status="${response##*$'\n'}"
  body="${response%$'\n'*}"
  if [[ "$status" != "$expected_status" ]]; then
    echo "Request ${method} ${url} failed: expected ${expected_status}, got ${status}" >&2
    echo "$body" >&2
    return 1
  fi
  printf '%s' "$body"
}

api_post_expect() {
  http_json_expect "POST" "$1" "$2" "$3" "$4"
}

api_get_expect() {
  http_json_expect "GET" "$1" "$2" "" "$3"
}

run_setup() {
  local config="$1"
  local database_url="$2"
  JWT_SECRET="$JWT_SECRET_VALUE" \
  ADMIN_EMAIL="$ADMIN_EMAIL" \
  ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    cargo run -p vsra -- --config "$config" --database-url "$database_url" setup --non-interactive >/dev/null
}

build_server() {
  local config="$1"
  local output="$2"
  cargo run -p vsra -- build "$config" --output "$output" --force >/dev/null
}

smoke_api() {
  local base_url="$1"
  local summary_path="$2"

  api_post_expect "${base_url}/api/auth/register" "" \
    "{\"email\":\"${GUARDIAN_EMAIL}\",\"password\":\"Password123!\"}" 201 >/dev/null
  api_post_expect "${base_url}/api/auth/register" "" \
    "{\"email\":\"${SPOUSE_EMAIL}\",\"password\":\"Password123!\"}" 201 >/dev/null

  local admin_token
  admin_token="$(api_post_expect "${base_url}/api/auth/login" "" \
    "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" 200 | jq -r '.token')"
  local guardian_token
  guardian_token="$(api_post_expect "${base_url}/api/auth/login" "" \
    "{\"email\":\"${GUARDIAN_EMAIL}\",\"password\":\"Password123!\"}" 200 | jq -r '.token')"
  local spouse_token
  spouse_token="$(api_post_expect "${base_url}/api/auth/login" "" \
    "{\"email\":\"${SPOUSE_EMAIL}\",\"password\":\"Password123!\"}" 200 | jq -r '.token')"

  if [[ -z "$admin_token" || "$admin_token" == "null" || -z "$guardian_token" || "$guardian_token" == "null" || -z "$spouse_token" || "$spouse_token" == "null" ]]; then
    echo "One of the login flows did not return a token" >&2
    return 1
  fi

  local guardian_id spouse_id
  guardian_id="$(api_get_expect "${base_url}/api/auth/me" "$guardian_token" 200 | jq -r '.id')"
  spouse_id="$(api_get_expect "${base_url}/api/auth/me" "$spouse_token" 200 | jq -r '.id')"

  local family_json family_id family_get_json
  family_json="$(api_post_expect "${base_url}/api/family" "$guardian_token" \
    "{\"slug\":\"${FAMILY_SLUG}\",\"name\":\"${FAMILY_NAME}\",\"timezone\":\"Europe/Helsinki\"}" 201)"
  family_id="$(printf '%s' "$family_json" | jq -r '.id')"
  family_get_json="$(api_get_expect "${base_url}/api/family/${family_id}" "$guardian_token" 200)"

  local self_membership_json spouse_membership_json family_members_json
  self_membership_json="$(api_post_expect "${base_url}/api/family_member" "$guardian_token" \
    "{\"family_id\":${family_id},\"user_id\":${guardian_id},\"role_label\":\"guardian\",\"display_name\":\"Guardian\",\"is_child\":false}" 201)"
  spouse_membership_json="$(api_post_expect "${base_url}/api/family_member" "$guardian_token" \
    "{\"family_id\":${family_id},\"user_id\":${spouse_id},\"role_label\":\"caregiver\",\"display_name\":\"Spouse\",\"is_child\":false}" 201)"
  family_members_json="$(api_get_expect "${base_url}/api/family_member?filter_family_id=${family_id}&sort=id&order=asc" "$guardian_token" 200)"

  local household_json household_id spouse_households_json
  household_json="$(api_post_expect "${base_url}/api/household" "$guardian_token" \
    "{\"family_id\":${family_id},\"slug\":\"${HOUSEHOLD_SLUG}\",\"label\":\"${HOUSEHOLD_LABEL}\",\"timezone\":\"Europe/Helsinki\"}" 201)"
  household_id="$(printf '%s' "$household_json" | jq -r '.id')"
  spouse_households_json="$(api_get_expect "${base_url}/api/family/${family_id}/household?sort=id&order=asc" "$spouse_token" 200)"

  local shopping_item_json shopping_item_id spouse_shopping_before_json spouse_shopping_after_json spouse_shopping_item_json spouse_family_list_json
  shopping_item_json="$(api_post_expect "${base_url}/api/shopping_item" "$guardian_token" \
    "{\"family_id\":${family_id},\"household_id\":${household_id},\"title\":\"${SHOPPING_TITLE}\",\"completed\":false}" 201)"
  shopping_item_id="$(printf '%s' "$shopping_item_json" | jq -r '.id')"
  spouse_family_list_json="$(api_get_expect "${base_url}/api/family?sort=id&order=asc" "$spouse_token" 200)"
  spouse_shopping_before_json="$(api_get_expect "${base_url}/api/family/${family_id}/shopping_item?sort=id&order=asc" "$spouse_token" 200)"

  api_post_expect "${base_url}/api/authz/runtime/assignments" "$admin_token" \
    "{\"user_id\":${spouse_id},\"target\":{\"kind\":\"template\",\"name\":\"Caregiver\"},\"scope\":{\"scope\":\"Family\",\"value\":\"${family_id}\"}}" 201 >/dev/null

  spouse_shopping_after_json="$(api_get_expect "${base_url}/api/family/${family_id}/shopping_item?sort=id&order=asc" "$spouse_token" 200)"
  spouse_shopping_item_json="$(api_get_expect "${base_url}/api/shopping_item/${shopping_item_id}" "$spouse_token" 200)"

  jq -n \
    --argjson family_created "$family_json" \
    --argjson family_read "$family_get_json" \
    --argjson self_membership "$self_membership_json" \
    --argjson spouse_membership "$spouse_membership_json" \
    --argjson family_members "$family_members_json" \
    --argjson household_created "$household_json" \
    --argjson spouse_households "$spouse_households_json" \
    --argjson shopping_item_created "$shopping_item_json" \
    --argjson spouse_family_list "$spouse_family_list_json" \
    --argjson spouse_shopping_before "$spouse_shopping_before_json" \
    --argjson spouse_shopping_after "$spouse_shopping_after_json" \
    --argjson spouse_shopping_item "$spouse_shopping_item_json" \
    '{
      family_created: $family_created,
      family_read: $family_read,
      self_membership: $self_membership,
      spouse_membership: $spouse_membership,
      family_members: $family_members,
      household_created: $household_created,
      spouse_households: $spouse_households,
      shopping_item_created: $shopping_item_created,
      spouse_family_list: $spouse_family_list,
      spouse_shopping_before: $spouse_shopping_before,
      spouse_shopping_after: $spouse_shopping_after,
      spouse_shopping_item: $spouse_shopping_item
    }' | jq -S . > "$summary_path"
}

run_backend_smoke() {
  local backend="$1"
  local database_url="$2"
  local bind_addr="$3"
  local output="$4"
  local summary_path="$5"
  local service_root
  local server_pid=""

  service_root="$(make_temp_service_root "$backend")"
  trap '[[ -n "$server_pid" ]] && kill "$server_pid" >/dev/null 2>&1 || true; rm -rf "$service_root"' RETURN

  free_bind_addr "$bind_addr"
  run_setup "$service_root/family_app.eon" "$database_url"
  build_server "$service_root/family_app.eon" "$output"

  BIND_ADDR="$bind_addr" \
  DATABASE_URL="$database_url" \
  JWT_SECRET="$JWT_SECRET_VALUE" \
    "$output" >/tmp/"$(basename "$output")".log 2>&1 &
  server_pid=$!

  wait_for_http "http://${bind_addr}/openapi.json"
  smoke_api "http://${bind_addr}" "$summary_path"

  kill "$server_pid" >/dev/null 2>&1 || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=""
  rm -rf "$service_root"
  trap - RETURN
}

main() {
  local sqlite_summary postgres_summary mysql_summary sqlite_db_path
  local sqlite_output postgres_output mysql_output
  require_cmd docker
  require_cmd curl
  require_cmd jq
  require_cmd cargo
  require_cmd perl
  require_cmd lsof

  docker info >/dev/null

  ensure_container \
    "$POSTGRES_CONTAINER" \
    "docker run -d --name ${POSTGRES_CONTAINER} -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=${POSTGRES_DB} -p ${POSTGRES_PORT}:5432 postgres:16"
  ensure_container \
    "$MYSQL_CONTAINER" \
    "docker run -d --name ${MYSQL_CONTAINER} -e MYSQL_ROOT_PASSWORD=password -e MYSQL_DATABASE=${MYSQL_DB} -p ${MYSQL_PORT}:3306 mysql:8.4"

  reset_postgres
  reset_mysql

  sqlite_summary="$(mktemp -t family_app_sqlite_summary).json"
  postgres_summary="$(mktemp -t family_app_postgres_summary).json"
  mysql_summary="$(mktemp -t family_app_mysql_summary).json"
  sqlite_db_path="$(mktemp -t family_app_sqlite_parity).db"
  sqlite_output="$(mktemp -t family_app_sqlite_server)"
  postgres_output="$(mktemp -t family_app_pg_server)"
  mysql_output="$(mktemp -t family_app_mysql_server)"
  rm -f "$sqlite_db_path"
  rm -f "$sqlite_output" "$postgres_output" "$mysql_output"
  trap "rm -f '$sqlite_summary' '$postgres_summary' '$mysql_summary' '$sqlite_db_path' '$sqlite_output' '$postgres_output' '$mysql_output'" EXIT

  run_backend_smoke \
    "Sqlite" \
    "sqlite:${sqlite_db_path}?mode=rwc" \
    "127.0.0.1:${SQLITE_SERVER_PORT}" \
    "$sqlite_output" \
    "$sqlite_summary"

  run_backend_smoke \
    "Postgres" \
    "postgres://postgres:postgres@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}" \
    "127.0.0.1:${PG_SERVER_PORT}" \
    "$postgres_output" \
    "$postgres_summary"

  run_backend_smoke \
    "Mysql" \
    "mysql://root:password@127.0.0.1:${MYSQL_PORT}/${MYSQL_DB}" \
    "127.0.0.1:${MYSQL_SERVER_PORT}" \
    "$mysql_output" \
    "$mysql_summary"

  compare_summaries "Sqlite" "$sqlite_summary" "Postgres" "$postgres_summary"
  compare_summaries "Sqlite" "$sqlite_summary" "Mysql" "$mysql_summary"

  echo "SQLite, Postgres, and MySQL family_app API parity smoke passed."
}

main "$@"
