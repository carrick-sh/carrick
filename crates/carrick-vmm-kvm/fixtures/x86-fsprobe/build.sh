#!/usr/bin/env bash
# Build the M1 x86_64 differential fixture on a Mac with NO C toolchain and NO
# Docker (mirrors fixtures/hello-x86_64/build.sh). rust-lld links the static
# musl ELF directly. The probe calls uname(2), which the standalone run loop
# ENOSYSs but the dispatcher services — the M1 proof.
set -euo pipefail
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
(
  cd "$dir"
  RUSTFLAGS="-C linker=rust-lld -C linker-flavor=ld.lld -C relocation-model=static -C link-arg=--no-pie" \
    cargo build --release --target x86_64-unknown-linux-musl
)
bin="$dir/target/x86_64-unknown-linux-musl/release/carrick-x86-fsprobe"
cp "$bin" "$dir/x86-fsprobe"
file "$dir/x86-fsprobe"   # must say: ELF 64-bit LSB executable, x86-64, statically linked
