#!/usr/bin/env bash
# Build the mapfixed-private-syscall fixture: a STATIC glibc aarch64 Linux binary
# that proves carrick's SYSCALL buffer path STAGE-1-TRANSLATES a guest VA that a
# mmap(MAP_FIXED|MAP_PRIVATE|MAP_ANON) repointed from the shared aperture (576
# GiB) to a per-process PRIVATE overlay (608 GiB).
#
# The guest's OWN EL0 loads/stores already hit the overlay (the stage-1 leaf was
# repointed by repoint_private). The bug this locks is that carrick's syscall
# read_bytes/write_bytes treated the guest pointer as a GPA directly (identity
# VA==GPA), and the shared aperture sits BELOW the 1-TiB high-VA translate
# threshold, so neither backend translated it — the syscall copy resolved to the
# STALE shared backing, not the overlay. The fixture writes the repointed page
# down a pipe (read_bytes path) and reads back into it (write_bytes path), and
# asserts the syscall saw the PRIVATE 0xBB/0xCC, never the shared 0xAA.
#
# It needs glibc (mmap/pipe/read/write) and therefore the REAL dispatcher, so it
# is gcc-compiled where an aarch64-linux gcc + glibc exist — i.e. INSIDE the
# nested-KVM Lima guest by scripts/kvm-smoke-lima.sh, or built there and copied
# to the macOS host to run under HVF (`carrick run-elf`):
#
#   gcc -static -O2 -o mapfixed-private-syscall mapfixed-private-syscall.c
#
# On macOS there is no glibc aarch64 gcc, so the binary is built in-guest rather
# than committed.
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/mapfixed-private-syscall"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -o "$out" "$fixture_dir/mapfixed-private-syscall.c"
file "$out"
