#!/usr/bin/env bash
# L2 success gate on the lima nested-KVM lane (run from the macOS host):
# build carrick-linux natively inside the guest and run the freestanding
# hello-aarch64 fixture against real /dev/kvm, diffing stdout + exit code
# against the oracle. Requires `just lima-up` once. Override $LIMA_INSTANCE.
set -euo pipefail

vm="${LIMA_INSTANCE:-carrick}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v limactl >/dev/null || {
  echo "lima is not installed (brew install lima); see scripts/lima-up.sh" >&2
  exit 2
}
if ! limactl list -q 2>/dev/null | grep -qx "$vm"; then
  echo "lima VM '$vm' not found — run 'just lima-up' first." >&2
  exit 2
fi

# `sg kvm -c` runs with the kvm group active (the guest user is added to it by
# lima-up). The committed fixture binary is used as-is (no clang needed in-guest).
# REPO is passed via env to avoid host/guest path-quoting issues.
limactl shell "$vm" -- env REPO="$repo" bash -lc '
  set -euo pipefail
  source "$HOME/.cargo/env"
  cd "$REPO"
  cargo build --release -p carrick-linux --target-dir "$HOME/ct" --locked
  fix="$REPO/crates/carrick-linux/fixtures/hello-aarch64"
  bin="$HOME/ct/release/carrick-linux"
  got="$(sg kvm -c "$bin run-elf $fix/hello-aarch64")"
  code=$?
  oracle="$(cat "$fix/oracle.expected")"
  if [ "$got" = "$oracle" ] && [ "$code" -eq 0 ]; then
    echo "OK: hello-aarch64 printed ok and exited 0 under nested KVM."
  else
    printf "FAIL: stdout=[%s] exit=%s oracle=[%s]\n" "$got" "$code" "$oracle" >&2
    exit 1
  fi
'
