#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/vsr-replication-smoke-XXXXXX")"
POSTGRES_CONTAINER="vsr-postgres-replication-smoke"
MYSQL_CONTAINER="vsr-mysql-replication-smoke"
POSTGRES_PORT="25432"
MYSQL_PORT="23306"
POSTGRES_DB="vsr_replication_smoke"
MYSQL_DB="vsr_replication_smoke"
POSTGRES_URL="postgres://postgres:postgres@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}"
MYSQL_URL="mysql://root:password@127.0.0.1:${MYSQL_PORT}/${MYSQL_DB}"

cleanup() {
  docker rm -f "$POSTGRES_CONTAINER" >/dev/null 2>&1 || true
  docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

wait_for_postgres() {
  for _ in $(seq 1 60); do
    if docker exec "$POSTGRES_CONTAINER" pg_isready -U postgres -d "$POSTGRES_DB" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for Postgres" >&2
  exit 1
}

wait_for_mysql() {
  for _ in $(seq 1 60); do
    if docker exec "$MYSQL_CONTAINER" mysqladmin ping -h127.0.0.1 -uroot -ppassword >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for MySQL" >&2
  exit 1
}

cd "$ROOT_DIR"
require_cmd docker
require_cmd cargo
require_cmd jq
require_cmd perl

docker rm -f "$POSTGRES_CONTAINER" >/dev/null 2>&1 || true
docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true

docker run -d \
  --name "$POSTGRES_CONTAINER" \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB="$POSTGRES_DB" \
  -p "${POSTGRES_PORT}:5432" \
  postgres:16 >/dev/null

docker run -d \
  --name "$MYSQL_CONTAINER" \
  -e MYSQL_ROOT_PASSWORD=password \
  -e MYSQL_DATABASE="$MYSQL_DB" \
  -p "${MYSQL_PORT}:3306" \
  mysql:8.4 >/dev/null

wait_for_postgres
wait_for_mysql

cp tests/fixtures/backup_resilience_api.eon "$TMP_ROOT/postgres.eon"
perl -0pe 's/module: "backup_resilience_api"/module: "backup_resilience_mysql_api"/; s/db: "Postgres"/db: "Mysql"/' \
  tests/fixtures/backup_resilience_api.eon > "$TMP_ROOT/mysql.eon"

cargo run -p vsra -- \
  --database-url "$POSTGRES_URL" \
  replication doctor \
  --input "$TMP_ROOT/postgres.eon" \
  --read-database-url "$POSTGRES_URL" \
  --format json | sed -n '/^{/,$p' > "$TMP_ROOT/postgres.json"

jq -e '.healthy == false' "$TMP_ROOT/postgres.json" >/dev/null
jq -e '.checks[] | select(.name == "primary_role_state" and .status == "pass")' "$TMP_ROOT/postgres.json" >/dev/null
jq -e '.checks[] | select(.name == "read_role_state" and .status == "fail")' "$TMP_ROOT/postgres.json" >/dev/null

cargo run -p vsra -- \
  --database-url "$MYSQL_URL" \
  replication doctor \
  --input "$TMP_ROOT/mysql.eon" \
  --read-database-url "$MYSQL_URL" \
  --format json | sed -n '/^{/,$p' > "$TMP_ROOT/mysql.json"

jq -e '.healthy == false' "$TMP_ROOT/mysql.json" >/dev/null
jq -e '.checks[] | select(.name == "primary_role_state" and .status == "pass")' "$TMP_ROOT/mysql.json" >/dev/null
jq -e '.checks[] | select(.name == "read_role_state" and .status == "fail")' "$TMP_ROOT/mysql.json" >/dev/null

echo "Postgres and MySQL replication doctor smoke passed."
