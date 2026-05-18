#!/usr/bin/env bash
# Launch carrick run-elf or run under lldb with our standard breakpoints
# pre-loaded. Usage:
#
#   scripts/lldb-tier-b.sh hello              # debug Tier A hello fixture
#   scripts/lldb-tier-b.sh busybox            # debug Tier B alpine busybox
#   scripts/lldb-tier-b.sh -- <full args>     # arbitrary carrick args
#
# When you hit the breakpoint, you can use the carrick.lldb script's
# convenience commands (loaded automatically): `carrick-regs`, `carrick-bt`,
# `carrick-mappings`, `carrick-hvf-state`.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

binary="./target/release/carrick"
entitlements="./scripts/entitlements.plist"
lldb_init="./scripts/carrick.lldb"

cargo build --release --bin carrick --message-format short >&2
codesign --force --sign - --entitlements "$entitlements" "$binary" >&2

case "${1:-}" in
  hello)
    args=(run-elf
      fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello
      --max-traps 8)
    ;;
  busybox)
    args=(run docker.io/library/alpine:latest --max-traps 30 /bin/busybox echo hello)
    ;;
  --)
    shift
    args=("$@")
    ;;
  *)
    echo "usage: $0 {hello|busybox|-- <carrick args...>}" >&2
    exit 2
    ;;
esac

CARRICK_TRACE_REGS=1 CARRICK_TRACE_MAPS=1 \
  exec lldb -s "$lldb_init" -- "$binary" "${args[@]}"
