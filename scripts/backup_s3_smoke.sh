#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/vsr-s3-smoke-XXXXXX")"
CONFIG_PATH="$TMP_ROOT/service.eon"
MIGRATIONS_DIR="$TMP_ROOT/migrations"
ARTIFACT_DIR="$TMP_ROOT/artifact"
PULLED_DIR="$TMP_ROOT/pulled-artifact"
DATABASE_URL="sqlite:$TMP_ROOT/app.db?mode=rwc"
MINIO_CONTAINER="vsr-minio-backup-smoke"
MINIO_ENDPOINT="http://127.0.0.1:19000"
REMOTE_URI="s3://backup-artifacts/sqlite-run1"

cleanup() {
  docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

cd "$ROOT_DIR"
cp tests/fixtures/backup_doctor_sqlite_api.eon "$CONFIG_PATH"

docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1 || true
docker run -d \
  --name "$MINIO_CONTAINER" \
  -p 19000:9000 \
  -p 19001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data --console-address ":9001" >/dev/null

for _ in $(seq 1 30); do
  if curl -fsS "$MINIO_ENDPOINT/minio/health/live" >/dev/null; then
    break
  fi
  sleep 1
done

docker exec "$MINIO_CONTAINER" mkdir -p /data/backup-artifacts

cargo run -p vsra -- \
  --config "$CONFIG_PATH" \
  --database-url "$DATABASE_URL" \
  migrate generate \
  --input "$CONFIG_PATH" \
  --output "$MIGRATIONS_DIR/0001_service.sql" \
  --force >/dev/null

cargo run -p vsra -- \
  --config "$CONFIG_PATH" \
  --database-url "$DATABASE_URL" \
  migrate apply \
  --dir "$MIGRATIONS_DIR" >/dev/null

cargo run -p vsra -- \
  --config "$CONFIG_PATH" \
  --database-url "$DATABASE_URL" \
  backup snapshot \
  --input "$CONFIG_PATH" \
  --output "$ARTIFACT_DIR" >/dev/null

AWS_ACCESS_KEY_ID=minioadmin \
AWS_SECRET_ACCESS_KEY=minioadmin \
AWS_REGION=us-east-1 \
cargo run -p vsra -- \
  backup push \
  --artifact "$ARTIFACT_DIR" \
  --remote "$REMOTE_URI" \
  --endpoint-url "$MINIO_ENDPOINT" \
  --path-style \
  --format json >/dev/null

AWS_ACCESS_KEY_ID=minioadmin \
AWS_SECRET_ACCESS_KEY=minioadmin \
AWS_REGION=us-east-1 \
cargo run -p vsra -- \
  backup pull \
  --remote "$REMOTE_URI" \
  --output "$PULLED_DIR" \
  --endpoint-url "$MINIO_ENDPOINT" \
  --path-style \
  --format json >/dev/null

cargo run -p vsra -- \
  backup verify-restore \
  --artifact "$PULLED_DIR" \
  --format json
