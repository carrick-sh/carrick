#!/usr/bin/env bash
# Build the proc-directed-nonmain fixture: a STATIC glibc aarch64 Linux binary
# whose MAIN thread blocks SIGUSR1, spawns a worker that does NOT block it, then
# kill(getpid(),SIGUSR1)s itself (process-directed). The worker's handler must
# run -> print "worker-got-it". Locks the PROC_PENDING fan-out (Linux thread-
# group semantics) on the carrick KVM backend (timer/signal refactor, Task 7).
#
# Needs glibc (pthreads/sigaction) + the REAL dispatcher, so it is gcc-compiled
# where an aarch64-linux gcc + glibc exist — i.e. INSIDE the nested-KVM Lima
# guest by scripts/kvm-smoke-lima.sh:
#
#   gcc -static -O2 -pthread -o proc-directed-nonmain proc-directed-nonmain.c
#
# On macOS there is no glibc aarch64 gcc, so the binary is built+run in-guest.
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/proc-directed-nonmain"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -pthread -o "$out" "$fixture_dir/proc-directed-nonmain.c"
file "$out"
