#!/usr/bin/env bash
# Build the host-term fixture: a STATIC glibc aarch64 Linux binary that installs
# a SIGTERM handler, forks a child that kill(getppid(),SIGTERM)s the parent, and
# whose parent (blocked in pause()) must run the handler -> print "got-term".
#
# This locks the KVM async host-signal pump + PROC_PENDING fan-out (timer/signal
# refactor, Task 7). It needs glibc (sigaction/fork) and therefore the REAL
# dispatcher, so it is gcc-compiled where an aarch64-linux gcc + glibc exist —
# i.e. INSIDE the nested-KVM Lima guest by scripts/kvm-smoke-lima.sh:
#
#   gcc -static -O2 -o host-term host-term.c
#
# On macOS there is no glibc aarch64 gcc, so the binary is built+run in-guest by
# the smoke script rather than committed.
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/host-term"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -o "$out" "$fixture_dir/host-term.c"
file "$out"
