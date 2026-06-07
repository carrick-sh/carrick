#!/usr/bin/env bash
# Build the freestanding exec-target-exit0 aarch64 ELF (same toolchain as the fork-wait4 /
# pipe-fork fixtures): clang integrated assembler (.S -> aarch64 ELF .o) + the
# bundled rust-lld. Output is a static aarch64 Linux ELF the carrick-linux KVM
# MVP loads as its guest to exercise execve_into target (exit_group 0) (Phase 2, Task 4).
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/exec-target-exit0"
obj="$(mktemp -t exec-target-exit0.XXXXXX.o)"
trap 'rm -f "$obj"' EXIT

sysroot="$(rustc --print sysroot)"
host="$(rustc -vV | awk '/^host:/ { print $2 }')"
lld="$sysroot/lib/rustlib/$host/bin/rust-lld"
if [[ ! -x "$lld" ]]; then
  echo "missing rust-lld at $lld" >&2
  exit 2
fi

clang --target=aarch64-unknown-linux-gnu -nostdlib \
  -c -o "$obj" "$fixture_dir/exit0.S"
"$lld" -flavor gnu -static --entry=_start --gc-sections -o "$out" "$obj"

file "$out"
