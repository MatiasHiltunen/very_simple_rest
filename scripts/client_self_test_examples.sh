#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/client_self_test_examples.sh --mode <static|live> [--example <name>]...

Examples:
  scripts/client_self_test_examples.sh --mode static
  scripts/client_self_test_examples.sh --mode live --example bridgeboard --example cms
EOF
}

mode=""
examples=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      mode="${2:-}"
      shift 2
      ;;
    --example)
      examples+=("${2:-}")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$mode" ]]; then
  echo "--mode is required" >&2
  usage >&2
  exit 1
fi

case "$mode" in
  static|live) ;;
  *)
    echo "Unsupported mode: $mode" >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VSR_BIN="$REPO_ROOT/target/debug/vsr"
TSC_BIN="$REPO_ROOT/examples/cms/web/node_modules/.bin/tsc"
REPORT_ROOT="$REPO_ROOT/target/example_client_self_tests/$mode"
TEST_TURSO_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

if [[ ! -x "$VSR_BIN" ]]; then
  cargo build -p vsra >/dev/null
fi

TSC_ARGS=()
if [[ -x "$TSC_BIN" ]]; then
  TSC_ARGS=(--self-test-tsc "$TSC_BIN")
fi

if [[ ${#examples[@]} -eq 0 ]]; then
  examples=(bridgeboard cms family_app ops_control commerce template todo_app)
fi

example_dir() {
  case "$1" in
    bridgeboard) echo "examples/bridgeboard" ;;
    cms) echo "examples/cms" ;;
    family_app) echo "examples/family_app" ;;
    ops_control) echo "examples/fine_grained_policies" ;;
    commerce) echo "examples/sqlite_bench" ;;
    template) echo "examples/template" ;;
    todo_app) echo "examples/todo_app" ;;
    *)
      echo "Unknown example: $1" >&2
      exit 1
      ;;
  esac
}

example_eon() {
  case "$1" in
    bridgeboard) echo "bridgeboard.eon" ;;
    cms) echo "api.eon" ;;
    family_app) echo "family_app.eon" ;;
    ops_control) echo "ops_control.eon" ;;
    commerce) echo "commerce.eon" ;;
    template) echo "api.eon" ;;
    todo_app) echo "todo_app.eon" ;;
    *)
      echo "Unknown example: $1" >&2
      exit 1
      ;;
  esac
}

free_port() {
  node -e 'const net=require("node:net");const s=net.createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close();});'
}

run_static_example() {
  local name="$1"
  local source_dir="$REPO_ROOT/$(example_dir "$name")"
  local eon_name
  eon_name="$(example_eon "$name")"
  local root="$REPORT_ROOT/$name"
  local output_dir="$root/client"
  local report_path="$root/report.json"

  rm -rf "$root"
  mkdir -p "$root"

  echo "=== STATIC SELF-TEST $name ==="
  local cmd=(
    "$VSR_BIN" client ts
    --input "$source_dir/$eon_name"
    --output "$output_dir"
    --force
    --self-test
    --self-test-report "$report_path"
  )
  if ((${#TSC_ARGS[@]} > 0)); then
    cmd+=("${TSC_ARGS[@]}")
  fi
  "${cmd[@]}"
}

run_live_example() {
  local name="$1"
  local source_dir="$REPO_ROOT/$(example_dir "$name")"
  local eon_name
  eon_name="$(example_eon "$name")"
  local work="$REPORT_ROOT/$name"
  local input="$work/$eon_name"
  local output_dir="$work/generated-client"
  local report_path="$work/self-test-report.json"
  local stdout_log="$work/serve.stdout.log"
  local stderr_log="$work/serve.stderr.log"

  rm -rf "$work"
  mkdir -p "$work"
  rsync -a --exclude node_modules "$source_dir/" "$work/"
  rm -f "$work/.env" "$work/.env.backup"
  rm -rf "$work/var/data"

  local scheme="http"
  local curl_args=(-fsS)
  local extra_args=()
  if rg -q '^tls:' "$input"; then
    scheme="https"
    curl_args=(-k -fsS)
    extra_args+=(--self-test-insecure-tls)
  fi

  local port
  port="$(free_port)"
  local base_url="$scheme://127.0.0.1:$port"

  echo "=== LIVE SELF-TEST $name ==="
  (
    cd "$work"
    export TURSO_ENCRYPTION_KEY="$TEST_TURSO_KEY"
    export JWT_SECRET="${name}-client-self-test-secret"
    export ADMIN_EMAIL="admin@example.com"
    export ADMIN_PASSWORD="password123"

    "$VSR_BIN" --config "$input" setup --non-interactive >/dev/null

    BIND_ADDR="127.0.0.1:$port" "$VSR_BIN" serve "$input" >"$stdout_log" 2>"$stderr_log" &
    local server_pid=$!
    trap 'kill "$server_pid" >/dev/null 2>&1 || true; wait "$server_pid" >/dev/null 2>&1 || true' EXIT

    for _ in $(seq 1 120); do
      if curl "${curl_args[@]}" "$base_url/openapi.json" >/dev/null 2>&1; then
        break
      fi
      sleep 0.25
    done
    curl "${curl_args[@]}" "$base_url/openapi.json" >/dev/null

    local cmd=(
      "$VSR_BIN" client ts
      --input "$input"
      --output "$output_dir"
      --force
      --self-test
      --self-test-base-url "$base_url"
      --self-test-report "$report_path"
    )
    if ((${#TSC_ARGS[@]} > 0)); then
      cmd+=("${TSC_ARGS[@]}")
    fi
    if ((${#extra_args[@]} > 0)); then
      cmd+=("${extra_args[@]}")
    fi
    "${cmd[@]}"
  )
}

mkdir -p "$REPORT_ROOT"

for name in "${examples[@]}"; do
  case "$mode" in
    static) run_static_example "$name" ;;
    live) run_live_example "$name" ;;
  esac
  echo
done

echo "Example client self-tests completed for mode: $mode"
