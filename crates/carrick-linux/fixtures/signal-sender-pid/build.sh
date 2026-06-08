#!/usr/bin/env bash
# Build the signal-sender-pid fixture: a STATIC glibc aarch64 Linux binary that
# installs an SA_SIGINFO SIGUSR1 handler, kill(getpid(),SIGUSR1)s itself, and
# asserts siginfo->si_pid == getpid() (the dispatcher siginfo-queue si_pid path).
#
# Unlike the freestanding .S fixtures (clang + rust-lld, serviced by the thin
# shim), this needs glibc (sigaction/printf) and therefore the REAL dispatcher,
# so it is gcc-compiled where an aarch64-linux gcc + glibc exist — i.e. INSIDE
# the nested-KVM Lima guest by scripts/kvm-smoke-lima.sh (case 26). Run there:
#
#   gcc -static -O2 -o sender-pid sender-pid.c
#
# This script performs that build with whatever `gcc` is on PATH (native aarch64
# Linux, or a cross gcc named via $CC). On macOS there is no glibc aarch64 gcc,
# so the binary is built+run in-guest by the smoke script rather than committed.
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/sender-pid"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -o "$out" "$fixture_dir/sender-pid.c"
file "$out"
