#!/usr/bin/env bash
# Build the itimer-virtual fixture: a STATIC glibc aarch64 Linux binary that
# proves ITIMER_VIRTUAL (a guest-CPU itimer) fires off REAL guest CPU time on
# KVM (busy phase -> fired) and NOT while idle (sleep phase -> not fired). Like
# the other glibc signal/timer fixtures it needs the REAL dispatcher, so it is
# gcc-compiled INSIDE the nested-KVM Lima guest by scripts/kvm-smoke-lima.sh.
# Run there:
#
#   gcc -static -O2 -o itimer-virtual itimer-virtual.c
#
# On macOS there is no glibc aarch64 gcc, so the binary is built+run in-guest by
# the smoke script rather than committed.
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/itimer-virtual"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -o "$out" "$fixture_dir/itimer-virtual.c"
file "$out"
