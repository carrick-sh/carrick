#!/usr/bin/env bash
# Build the aarch64 first-call probe with clang and the bundled rust-lld
# (no cross toolchain; the recipe of crates/carrick-vmm-kvm/fixtures/hello-aarch64/build.sh).
# usage: build-firstcall-a64.sh <output-dir>
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:?output directory}"
mkdir -p "$out"
sysroot="$(rustc --print sysroot)"
host="$(rustc -vV | awk '/^host:/ { print $2 }')"
lld="$sysroot/lib/rustlib/$host/bin/rust-lld"
[[ -x "$lld" ]] || { echo "missing rust-lld at $lld" >&2; exit 2; }
clang --target=aarch64-unknown-linux-gnu -nostdlib -ffreestanding -fno-stack-protector \
  -fno-builtin -O1 -c -o "$out/firstcall-a64.o" "$here/firstcall_a64.c"
"$lld" -flavor gnu -static --entry=_start --gc-sections -o "$out/firstcall-a64" "$out/firstcall-a64.o"
file "$out/firstcall-a64"
