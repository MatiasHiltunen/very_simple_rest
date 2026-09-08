#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
cargo +stable test -p enterprise-api --no-default-features --features axum --locked
cargo +stable test -p enterprise-api --no-default-features --features actix --locked
tree_file=$(mktemp)
trap 'rm -f "$tree_file"' EXIT
cargo +stable tree -p enterprise-api --no-default-features --features axum -e normal --prefix none --locked > "$tree_file"
if grep -E '^actix[-_ ]' "$tree_file"; then
    printf '%s\n' 'FAIL: Actix is in the Axum runtime dependency graph'
    exit 1
fi
printf '%s\n' 'PASS: authorization proof on both transports; Axum runtime has no Actix dependency'
