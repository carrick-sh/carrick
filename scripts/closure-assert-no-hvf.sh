#!/usr/bin/env bash
# L1 closure assertion: a platform-linux build must link NO macOS hypervisor.
# Proves the C4 decouple (carrick-runtime -> carrick-hvf made optional) and the
# carrick-hvf/build.rs host-cfg fix. Used by `just check-linux` and CI.
set -euo pipefail

target="aarch64-unknown-linux-gnu"
features="platform-linux"

echo "cargo tree --no-default-features --features $features --target $target ..."
tree="$(cargo tree -p carrick-cli \
  --no-default-features --features "$features" \
  --target "$target" --edges normal 2>&1)"

if echo "$tree" | grep -E -i 'carrick-hvf|applevisor'; then
  echo >&2
  echo "FAIL: platform-linux closure still contains carrick-hvf / applevisor." >&2
  echo "      The runtime->hvf dependency is not feature-gated correctly." >&2
  exit 1
fi

echo "OK: platform-linux closure is free of carrick-hvf / applevisor."
