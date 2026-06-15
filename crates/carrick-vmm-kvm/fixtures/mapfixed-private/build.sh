#!/usr/bin/env bash
# Build the mapfixed-private fixture: a STATIC glibc aarch64 Linux binary that
# proves a guest mmap(MAP_FIXED|MAP_PRIVATE|MAP_ANON) over a shared-aperture VA
# is REPOINTED to a per-process PRIVATE overlay, so a forked child's "private"
# stores stay COW-isolated and do NOT leak through the shared backing.
#
# It maps two contiguous shared-aperture pages; page 0 is repointed PRIVATE via
# MAP_FIXED|MAP_PRIVATE, page 1 stays SHARED as the cross-process signal. The
# parent writes 0x42 to page 0, forks, the child writes 0x99 to page 0 then sets
# the SHARED page 1 to signal the parent. After reaping, the parent re-reads page
# 0: on a correct (PRIVATE) repoint it still sees its own 0x42 -> "private-ok"; if
# the repoint LEAKED to the shared backing it sees the child's 0x99 -> exit 3.
#
# This locks the KVM repoint_private path (Task 9): repoint_private fell through
# to the trait DEFAULT no-op on KVM, so the stage-1 leaf was never redirected and
# the "private" page still aliased the shared backing. KvmTrapEngine's override
# (mirroring HVF) seeds the boot-mapped overlay slot then pt_edit_and_flush(
# map_aliased) repoints the VA's stage-1 leaf to the overlay IPA. It needs glibc
# (mmap/fork/waitpid) and therefore the REAL dispatcher, so it is gcc-compiled
# where an aarch64-linux gcc + glibc exist — i.e. INSIDE the nested-KVM Lima guest
# by scripts/kvm-smoke-lima.sh:
#
#   gcc -static -O2 -o mapfixed-private mapfixed-private.c
#
# On macOS there is no glibc aarch64 gcc, so the binary is built+run in-guest by
# the smoke script rather than committed.
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/mapfixed-private"
cc="${CC:-gcc}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "no '$cc' on PATH — build this fixture inside the aarch64 Linux guest" >&2
  exit 2
fi

"$cc" -static -O2 -o "$out" "$fixture_dir/mapfixed-private.c"
file "$out"
