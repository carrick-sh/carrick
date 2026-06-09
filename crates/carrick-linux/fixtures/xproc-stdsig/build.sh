#!/usr/bin/env bash
# Build the xproc-stdsig fixture: a STATIC glibc aarch64 Linux binary that
# installs a real SIGUSR1 handler + ignores SIGUSR2, forks a child that
# kill(getppid(), SIGUSR2) [must be DROPPED] then kill(getppid(), SIGUSR1)
# [must RUN the handler], and whose parent (blocked in pause()) must run the
# handler and print "usr1-ok" — having SURVIVED the prior SIGUSR2.
#
# This locks the KVM cross-process STANDARD-signal disposition-mirroring path
# (Task 6): a plain catchable signal kill()ed to a SIBLING carrick guest process
# (NON-namespaced run-elf, so the host-kill path — libc::kill of the host signum,
# NOT the xsignal ring) must run the receiver's installed guest handler (or honor
# its SIG_IGN) instead of host-default-terminating the receiver. KVM mirrors the
# guest disposition onto a REAL host routed handler (HVF-parallel). It needs glibc
# (sigaction/signal/fork/kill) and therefore the REAL dispatcher, so it is
# gcc-compiled where an aarch64-linux gcc + glibc exist — i.e. INSIDE the
# nested-KVM Lima guest by scripts/kvm-smoke-lima.sh:
#
#   gcc -static -O2 -o xproc-stdsig xproc-stdsig.c
#
# On macOS there is no glibc aarch64 gcc, so the binary is built+run in-guest by
# the smoke script rather than committed.
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/xproc-stdsig"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -o "$out" "$fixture_dir/xproc-stdsig.c"
file "$out"
