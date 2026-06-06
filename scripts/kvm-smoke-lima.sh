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
  fixdir="$REPO/crates/carrick-linux/fixtures"

  run_case() {
    # $1 = label, $2 = binary path, $3 = fixture name (dir == elf name)
    local label="$1" bin="$2" fixture="$3" got code oracle
    oracle="$(cat "$fixdir/$fixture/oracle.expected")"
    got="$(sg kvm -c "$bin run-elf $fixdir/$fixture/$fixture")" && code=0 || code=$?
    if [ "$got" = "$oracle" ] && [ "$code" -eq 0 ]; then
      echo "OK [$label]: $fixture printed '\''$got'\'' and exited 0 under nested KVM."
    else
      printf "FAIL [%s/%s]: stdout=[%s] exit=%s oracle=[%s]\n" "$label" "$fixture" "$got" "$code" "$oracle" >&2
      return 1
    fi
  }

  # 1. Thin shim (existing MVP path): freestanding hello, no dispatcher.
  cargo build --release -p carrick-linux --target-dir "$HOME/ct" --locked
  run_case "thin-shim" "$HOME/ct/release/carrick-linux" "hello-aarch64"

  # 2. Real dispatch (Phase B): the full dispatcher, no HVF in the closure.
  cargo build --release -p carrick-runtime --no-default-features \
    --features platform-linux --bin carrick-kvm --target-dir "$HOME/ct" --locked
  kvm="$HOME/ct/release/carrick-kvm"
  run_case "real-dispatch" "$kvm" "hello-aarch64"

  # 3. Phase C / C1: a fixture that READS argc from [sp] and push/pops the
  #    stack — only succeeds if the initial stack is set up AND the high stack
  #    region (~1 TiB) is backed by its own KVM slot (the multi-region map).
  run_case "real-dispatch+stack" "$kvm" "hello-stack-aarch64"

  # 4. Phase C: a REAL static glibc binary. Exercises the full libc CRT startup
  #    through the real dispatcher (brk, set_tid_address, set_robust_list, rseq,
  #    prlimit64, readlinkat, getrandom, mprotect, the vdso) before write+exit.
  #    Proves C1 (memory map + initial stack + vdso) runs an actual libc binary.
  if command -v gcc >/dev/null; then
    printf "%s" "static-ok" > /tmp/static-oracle
    cat > /tmp/cstatic.c <<CEOF
#include <unistd.h>
int main(void){ return write(1,"static-ok",9) == 9 ? 0 : 1; }
CEOF
    gcc -static -O2 -o /tmp/cstatic /tmp/cstatic.c
    got="$(sg kvm -c "$kvm run-elf /tmp/cstatic")" && code=0 || code=$?
    if [ "$got" = "static-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+glibc-static]: a static glibc binary ran to completion under nested KVM."
    else
      printf "FAIL [glibc-static]: stdout=[%s] exit=%s\n" "$got" "$code" >&2
      exit 1
    fi
  else
    echo "SKIP [glibc-static]: no gcc in guest" >&2
  fi

  # Evidence the REAL dispatch path actually ran (write=64, exit_group=94 traps).
  echo "--- trap trace (proves real dispatch, not the thin shim) ---" >&2
  sg kvm -c "CARRICK_TRACE_TRAPS=1 $kvm run-elf $fixdir/hello-aarch64/hello-aarch64" \
    >/dev/null 2>/tmp/carrick-kvm-trace || true
  grep -E "x8=64|x8=94" /tmp/carrick-kvm-trace >&2 || {
    echo "FAIL: expected write(64)+exit_group(94) traps in the real-dispatch trace" >&2
    exit 1
  }
  echo "OK: Phase B+C1 — hello, hello-stack, and a static glibc binary pass on KVM."
'
