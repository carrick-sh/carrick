#!/usr/bin/env bash
# Build the M2 static x86_64 musl hello fixture on a Mac with NO C toolchain and
# NO Docker (per the trap-driven, no-Rosetta oracle policy). rust-lld links the
# ELF directly (Apple's cc/ld cannot link GNU/ELF musl output).
#   - x86_64-unknown-linux-musl: self-contained musl crt + libc rlib.
#   - linker-flavor=ld.lld: pass ld-style args straight to rust-lld.
#   - relocation-model=static + --no-pie: a fixed-base ET_EXEC (no dynamic
#     relocations) — the simplest shape for carrick's M2 ELF loader.
set -euo pipefail
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
(
  cd "$dir"
  RUSTFLAGS="-C linker=rust-lld -C linker-flavor=ld.lld -C relocation-model=static -C link-arg=--no-pie" \
    cargo build --release --target x86_64-unknown-linux-musl
)
bin="$dir/target/x86_64-unknown-linux-musl/release/carrick-hello-x86_64"
cp "$bin" "$dir/hello-x86_64"
file "$dir/hello-x86_64"   # must say: ELF 64-bit LSB executable, x86-64, statically linked
