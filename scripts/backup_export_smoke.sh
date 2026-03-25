#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/vsr-export-smoke-XXXXXX")"
POSTGRES_CONTAINER="vsr-postgres-export-smoke"
MYSQL_CONTAINER="vsr-mysql-export-smoke"
POSTGRES_PORT="35432"
MYSQL_PORT="33306"
POSTGRES_DB="vsr_export_smoke"
MYSQL_DB="vsr_export_smoke"
POSTGRES_URL="postgres://postgres:postgres@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}"
MYSQL_URL="mysql://root:password@127.0.0.1:${MYSQL_PORT}/${MYSQL_DB}"

cleanup() {
  docker rm -f "$POSTGRES_CONTAINER" >/dev/null 2>&1 || true
  docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

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

docker exec "$POSTGRES_CONTAINER" psql -U postgres -d "$POSTGRES_DB" -c 'CREATE TABLE archive_job (id BIGINT PRIMARY KEY, title TEXT NOT NULL); INSERT INTO archive_job (id, title) VALUES (1, '\''hello'\'');' >/dev/null
docker exec "$MYSQL_CONTAINER" mysql -uroot -ppassword "$MYSQL_DB" -e "CREATE TABLE archive_job (id BIGINT PRIMARY KEY, title VARCHAR(255) NOT NULL); INSERT INTO archive_job (id, title) VALUES (1, 'hello');" >/dev/null

cargo run -p vsra -- \
  --database-url "$POSTGRES_URL" \
  backup export \
  --input "$TMP_ROOT/postgres.eon" \
  --output "$TMP_ROOT/postgres-artifact" >/dev/null

cargo run -p vsra -- \
  --database-url "$MYSQL_URL" \
  backup export \
  --input "$TMP_ROOT/mysql.eon" \
  --output "$TMP_ROOT/mysql-artifact" >/dev/null

cargo run -p vsra -- \
  backup verify-restore \
  --artifact "$TMP_ROOT/postgres-artifact" \
  --format json > "$TMP_ROOT/postgres-verify.json"

cargo run -p vsra -- \
  backup verify-restore \
  --artifact "$TMP_ROOT/mysql-artifact" \
  --format json > "$TMP_ROOT/mysql-verify.json"

grep -q '"artifact_kind": "logical_dump"' "$TMP_ROOT/postgres-artifact/manifest.json"
grep -q '"artifact_kind": "logical_dump"' "$TMP_ROOT/mysql-artifact/manifest.json"
test -s "$TMP_ROOT/postgres-artifact/dump.sql"
test -s "$TMP_ROOT/mysql-artifact/dump.sql"
grep -q '"artifact_kind": "logical_dump"' "$TMP_ROOT/postgres-verify.json"
grep -q '"healthy": true' "$TMP_ROOT/postgres-verify.json"
grep -q '"artifact_kind": "logical_dump"' "$TMP_ROOT/mysql-verify.json"
grep -q '"healthy": true' "$TMP_ROOT/mysql-verify.json"

echo "Postgres and MySQL logical export and restore-verification smoke passed."
