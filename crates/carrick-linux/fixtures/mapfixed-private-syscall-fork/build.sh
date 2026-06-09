#!/usr/bin/env bash
# Build the mapfixed-private-syscall-fork fixture: a STATIC glibc aarch64 Linux
# binary that proves carrick's SYSCALL buffer path STAGE-1-TRANSLATES a repointed
# overlay VA EVEN IN A FORKED CHILD (the KVM fork-manager regression the non-fork
# mapfixed-private-syscall fixture missed).
#
# The guest mmaps a SHARED-aperture page (576 GiB), memsets it 0xAA, repoints it
# to a per-process PRIVATE overlay (608 GiB) with mmap(MAP_FIXED|MAP_PRIVATE|
# MAP_ANON), memsets it 0xBB, then FORKS. The CHILD — WITHOUT any prior mmap/
# mprotect/munmap — uses the repointed VA as a syscall read buffer (write down a
# pipe). KVM fork RESET the page-table manager to None, and syscall_buffer_ipa is
# &self so it cannot rebuild — so the child's syscall copy resolved to the STALE
# SHARED backing (0xAA) instead of the child's COW overlay (0xBB). The fix clones
# the parent's manager into the child at fork (mirroring HVF), so the child can
# translate the overlay VA immediately. The fixture asserts the child saw 0xBB and
# the parent prints "fork-syscall-priv-ok"; a stale-shared copy exits 3.
#
# It needs glibc (mmap/fork/pipe/read/write) and therefore the REAL dispatcher, so
# it is gcc-compiled where an aarch64-linux gcc + glibc exist — i.e. INSIDE the
# nested-KVM Lima guest by scripts/kvm-smoke-lima.sh, or built there and copied to
# the macOS host to run under HVF (`carrick run-elf`):
#
#   gcc -static -O2 -o mapfixed-private-syscall-fork mapfixed-private-syscall-fork.c
#
# On macOS there is no glibc aarch64 gcc, so the binary is built in-guest rather
# than committed.
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/mapfixed-private-syscall-fork"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -o "$out" "$fixture_dir/mapfixed-private-syscall-fork.c"
file "$out"
