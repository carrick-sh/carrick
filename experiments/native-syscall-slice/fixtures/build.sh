#!/bin/sh
set -eu
cd "$(dirname "$0")"
out=../../../target/lease-cost/native-slice/fixtures
mkdir -p "$out"
sysroot=$(rustc --print sysroot)
linker="$sysroot/lib/rustlib/aarch64-apple-darwin/bin/rust-lld"
for phase in 0 1 2 3 4; do
  for n in 1 8 32 128 65536; do
    /opt/homebrew/opt/llvm/bin/clang --target=aarch64-linux-gnu -c -DPHASE="$phase" -DN="$n" watch.S -o "$out/watch-$phase-$n.o"
    "$linker" -flavor gnu -m aarch64elf -static -T guest.ld "$out/watch-$phase-$n.o" -o "$out/watch-$phase-$n"
  done
done
