#!/usr/bin/env bash
# Build the carrick CLI for platform-linux INSIDE the lima nested-KVM guest and
# print the in-guest binary path on stdout (last line). Reused by the KVM
# conformance lane (carrick-conformance --lane kvm). Idempotent; cargo caches.
#
# ALL build output goes to stderr so the ONLY stdout is the path (callers do
# `… | tail -1` to capture it as --carrick_bin).
set -euo pipefail
vm="${LIMA_INSTANCE:-carrick}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
limactl shell "$vm" -- env REPO="$repo" bash -lc '
  set -euo pipefail
  source "$HOME/.cargo/env"
  cd "$REPO"
  # The carrick CLI is carrick-cli built for platform-linux (== the real
  # `carrick run <image>` path: carrick-engine -> run_oci -> KVM). `--no-default-
  # features` is REQUIRED: the default feature is platform-macos, which pulls in
  # carrick-vmm-hvf/applevisor and fails to build on Linux (E0433). The platform-linux
  # closure is HVF-free (scripts/closure-assert-no-hvf.sh), matching kvm-smoke-lima.sh.
  cargo build --release -p carrick-cli --no-default-features --features platform-linux \
    --target-dir "$HOME/ct" --locked >&2
  echo "$HOME/ct/release/carrick"
'
