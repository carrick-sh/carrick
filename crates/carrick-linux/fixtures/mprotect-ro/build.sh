#!/usr/bin/env bash
# Build the mprotect-ro fixture: a STATIC glibc aarch64 Linux binary that
# mmaps a PROT_READ|PROT_WRITE page, TOUCHES it (establishing a writable
# stage-1 TLB entry), mprotect()s it PROT_READ, installs an SA_SIGINFO SIGSEGV
# handler, then stores to the now-read-only page. On a correct system the store
# faults -> the handler prints "segv-ok" + _exit(0). If the store SILENTLY
# succeeds (the KVM stale-stage-1-TLB bug, Task 8), it prints "no-segv" + exit 3.
#
# This locks the KVM stage-1 TLBI path (Task 8): pt_edit writes the descriptor
# but, without a stage-1 TLB flush, a re-protect of an ALREADY-WALKED page does
# not take effect. KvmTrapEngine::run_el1_maintenance (mirroring HVF) runs the
# EL1 maintenance trampoline (dsb sy; tlbi vmalle1is; dsb sy; isb) on the vCPU
# after a changed pt_edit so the store correctly faults. It needs glibc
# (mmap/mprotect/sigaction) and therefore the REAL dispatcher, so it is
# gcc-compiled where an aarch64-linux gcc + glibc exist — i.e. INSIDE the
# nested-KVM Lima guest by scripts/kvm-smoke-lima.sh:
#
#   gcc -static -O2 -o mprotect-ro mprotect-ro.c
#
# On macOS there is no glibc aarch64 gcc, so the binary is built+run in-guest by
# the smoke script rather than committed.
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/mprotect-ro"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -o "$out" "$fixture_dir/mprotect-ro.c"
file "$out"
