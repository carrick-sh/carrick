#!/usr/bin/env bash
# Build the xproc-sigqueue fixture: a STATIC glibc aarch64 Linux binary that
# installs an SA_SIGINFO SIGRTMIN handler, forks a child that
# sigqueue(getppid(), SIGRTMIN, {.sival_int = 0x1234})s the parent, and whose
# parent (blocked in pause()) must run the handler, observe the matching
# si_value, and print "val-ok".
#
# This locks the KVM cross-process queued-signal fidelity path (Task 8): a
# real-time signal queued to a SIBLING carrick guest process is delivered into
# that sibling's guest WITH the sender's si_value, via the shared MAP_SHARED
# xsignal ring (NOT a native rt_sigqueueinfo). It needs glibc (sigaction/fork/
# sigqueue) and therefore the REAL dispatcher, so it is gcc-compiled where an
# aarch64-linux gcc + glibc exist — i.e. INSIDE the nested-KVM Lima guest by
# scripts/kvm-smoke-lima.sh:
#
#   gcc -static -O2 -o xproc-sigqueue xproc-sigqueue.c
#
# On macOS there is no glibc aarch64 gcc, so the binary is built+run in-guest by
# the smoke script rather than committed.
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/xproc-sigqueue"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -o "$out" "$fixture_dir/xproc-sigqueue.c"
file "$out"
