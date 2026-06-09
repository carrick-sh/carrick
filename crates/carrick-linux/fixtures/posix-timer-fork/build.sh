#!/usr/bin/env bash
# Build the posix-timer-fork fixture: a STATIC glibc aarch64 Linux binary that
# timer_create()s a POSIX timer, forks, and whose CHILD must see EINVAL when it
# calls timer_getoverrun() on the inherited id (POSIX: a fork child inherits NO
# timers) -> the child prints "child-clean"; the parent's own timer stays live.
#
# This locks the KVM fork-clear path: host_signal::reinit_after_fork clears the
# process-global carrick-timer-core POSIX registry in the child so it does not
# reuse the parent's timer ids. It needs glibc (timer_create/fork) and therefore
# the REAL dispatcher, so it is gcc-compiled where an aarch64-linux gcc + glibc
# exist — i.e. INSIDE the nested-KVM Lima guest by scripts/kvm-smoke-lima.sh:
#
#   gcc -static -O2 -o posix-timer-fork posix-timer-fork.c
#
# On macOS there is no glibc aarch64 gcc, so the binary is built+run in-guest by
# the smoke script rather than committed.
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/posix-timer-fork"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -o "$out" "$fixture_dir/posix-timer-fork.c"
file "$out"
