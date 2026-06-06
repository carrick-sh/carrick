#!/usr/bin/env bash
# Build the freestanding hello-stack-aarch64 ELF on a Mac with no extra
# toolchain: clang integrated assembler (.S -> aarch64 ELF .o) + the bundled
# rust-lld. Output is a static aarch64 Linux ELF the carrick-linux KVM backend
# loads as its guest to exercise the initial stack (Phase C / C1).
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$fixture_dir/hello-stack-aarch64"
obj="$(mktemp -t hello-stack-aarch64.XXXXXX.o)"
trap 'rm -f "$obj"' EXIT

sysroot="$(rustc --print sysroot)"
host="$(rustc -vV | awk '/^host:/ { print $2 }')"
lld="$sysroot/lib/rustlib/$host/bin/rust-lld"
if [[ ! -x "$lld" ]]; then
  echo "missing rust-lld at $lld" >&2
  exit 2
fi

clang --target=aarch64-unknown-linux-gnu -nostdlib \
  -c -o "$obj" "$fixture_dir/hello-stack.S"
"$lld" -flavor gnu -static --entry=_start --gc-sections -o "$out" "$obj"

file "$out"
