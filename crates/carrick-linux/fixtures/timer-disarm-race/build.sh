#!/usr/bin/env bash
# Build the timer-disarm-race fixture: a STATIC glibc aarch64 Linux binary that
# arms a 1ms repeating ITIMER_REAL then disarms it IMMEDIATELY, sleeps past
# several intervals, and prints "no-late-alarm" iff no SIGALRM was delivered.
#
# This locks the disarm-during-fire / retire-on-generation-bump invariant of the
# interval-timer fallback (timer/signal shared-core effort): a fallback launched
# for the arm generation must retire when the disarm bumps the slot generation,
# delivering no late signal. It needs glibc (sigaction/setitimer/nanosleep) and
# therefore the REAL dispatcher, so it is gcc-compiled where an aarch64-linux
# gcc + glibc exist — i.e. INSIDE the nested-KVM Lima guest by
# scripts/kvm-smoke-lima.sh:
#
#   gcc -static -O2 -o timer-disarm-race timer-disarm-race.c
#
# On macOS there is no glibc aarch64 gcc, so the binary is built+run in-guest by
# the smoke script rather than committed.
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/timer-disarm-race"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -o "$out" "$fixture_dir/timer-disarm-race.c"
file "$out"
