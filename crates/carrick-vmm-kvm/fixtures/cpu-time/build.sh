#!/usr/bin/env bash
# Build the cpu-time fixture: a STATIC glibc aarch64 Linux binary that
# busy-spins for ~100ms of CPU then calls times(2) to prove guest CPU time
# is being charged by carrick_host::guest_cpu. Intended to be compiled
# inside the nested-KVM Lima guest by scripts/kvm-smoke-lima.sh (case 27).
#
# Run there:
#   gcc -static -O2 -o cpu-time cpu-time.c
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/cpu-time"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -o "$out" "$fixture_dir/cpu-time.c"
file "$out"
