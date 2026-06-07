#!/usr/bin/env bash
# Build the freestanding fork-wait4 aarch64 ELF (same toolchain as the
# hello-aarch64 fixture): clang integrated assembler (.S -> aarch64 ELF .o) +
# the bundled rust-lld. Output is a static aarch64 Linux ELF the carrick-linux
# KVM MVP loads as its guest to exercise the fork(2) primitive (Task 2).
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/fork-wait4"
obj="$(mktemp -t fork-wait4.XXXXXX.o)"
trap 'rm -f "$obj"' EXIT

sysroot="$(rustc --print sysroot)"
host="$(rustc -vV | awk '/^host:/ { print $2 }')"
lld="$sysroot/lib/rustlib/$host/bin/rust-lld"
if [[ ! -x "$lld" ]]; then
  echo "missing rust-lld at $lld" >&2
  exit 2
fi

clang --target=aarch64-unknown-linux-gnu -nostdlib \
  -c -o "$obj" "$fixture_dir/fork.S"
"$lld" -flavor gnu -static --entry=_start --gc-sections -o "$out" "$obj"

file "$out"
