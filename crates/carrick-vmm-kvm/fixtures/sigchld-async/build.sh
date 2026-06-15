#!/usr/bin/env bash
# Build the sigchld-async fixture: a STATIC glibc aarch64 Linux binary that
# installs an SA_SIGINFO|SA_RESTART SIGCHLD handler which reaps the child with
# waitpid(WNOHANG) and sets a flag, forks a child that exits after 50ms, and
# whose parent — which NEVER calls a blocking wait4 in main — spins
# `while(!got) pause()` and prints "sigchld-ok" once the async SIGCHLD fires.
#
# This locks the KVM async child-exit path (Task 5): a guest that reaps a child
# FROM its SIGCHLD handler (event-loop style, no synchronous wait4) must receive
# SIGCHLD asynchronously the instant the child exits. On KVM a fork = separate
# host processes, so the pump-thread reaper observes the child's exit (waitid
# WNOWAIT|WNOHANG, peeking the zombie without reaping it) and publishes the
# recorded exit-signal to the recorded parent tid. On HVF this runs off an
# EVFILT_PROC/NOTE_EXIT kqueue watch. It needs glibc (sigaction/fork/waitpid)
# and therefore the REAL dispatcher, so it is gcc-compiled where an
# aarch64-linux gcc + glibc exist — i.e. INSIDE the nested-KVM Lima guest by
# scripts/kvm-smoke-lima.sh:
#
#   gcc -static -O2 -o sigchld-async sigchld-async.c
#
# On macOS there is no glibc aarch64 gcc, so the binary is built+run in-guest by
# the smoke script rather than committed.
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/sigchld-async"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -o "$out" "$fixture_dir/sigchld-async.c"
file "$out"
