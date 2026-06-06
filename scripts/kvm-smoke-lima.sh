#!/usr/bin/env bash
# L2 success gate on the lima nested-KVM lane (run from the macOS host).
#
# Builds two KVM drivers natively inside the guest and runs the freestanding
# hello-aarch64 fixture against real /dev/kvm, diffing stdout + exit vs oracle:
#
#   1. carrick-linux (thin shim) — services write/exit directly, no dispatcher.
#      Kept for A/B comparison and as the closure-assert subject.
#   2. carrick-kvm (REAL dispatch, Phase B) — drives KvmTrapEngine through the
#      full carrick-runtime SyscallDispatcher. THIS is the Phase B gate.
#
# Requires `just lima-up` once. Override $LIMA_INSTANCE.
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
  fix="$REPO/crates/carrick-linux/fixtures/hello-aarch64"
  oracle="$(cat "$fix/oracle.expected")"

  run_case() {
    # $1 = label, $2 = binary path
    local label="$1" bin="$2" got code
    got="$(sg kvm -c "$bin run-elf $fix/hello-aarch64")" && code=0 || code=$?
    if [ "$got" = "$oracle" ] && [ "$code" -eq 0 ]; then
      echo "OK [$label]: hello-aarch64 printed '\''$got'\'' and exited 0 under nested KVM."
    else
      printf "FAIL [%s]: stdout=[%s] exit=%s oracle=[%s]\n" "$label" "$got" "$code" "$oracle" >&2
      return 1
    fi
  }

  # 1. Thin shim (existing MVP path).
  cargo build --release -p carrick-linux --target-dir "$HOME/ct" --locked
  run_case "thin-shim" "$HOME/ct/release/carrick-linux"

  # 2. Real dispatch (Phase B): the full dispatcher, no HVF in the closure.
  cargo build --release -p carrick-runtime --no-default-features \
    --features platform-linux --bin carrick-kvm --target-dir "$HOME/ct" --locked
  run_case "real-dispatch" "$HOME/ct/release/carrick-kvm"

  # Evidence the REAL dispatch path actually ran (write=64, exit_group=94 traps).
  echo "--- trap trace (proves real dispatch, not the thin shim) ---" >&2
  sg kvm -c "CARRICK_TRACE_TRAPS=1 $HOME/ct/release/carrick-kvm run-elf $fix/hello-aarch64" \
    >/dev/null 2>/tmp/carrick-kvm-trace || true
  grep -E "x8=64|x8=94" /tmp/carrick-kvm-trace >&2 || {
    echo "FAIL: expected write(64)+exit_group(94) traps in the real-dispatch trace" >&2
    exit 1
  }
  echo "OK: Phase B — hello-aarch64 passes via the REAL carrick-runtime dispatcher."
'
