#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_dir="$repo_root/fixtures/linux-aarch64-hello"
target="aarch64-unknown-linux-musl"
sysroot="$(rustc --print sysroot)"
host="$(rustc -vV | awk '/^host:/ { print $2 }')"
lld="$sysroot/lib/rustlib/$host/bin/rust-lld"

if ! rustup target list --installed | grep -qx "$target"; then
  echo "missing Rust target: $target" >&2
  echo "install it with: rustup target add $target" >&2
  exit 2
fi

if [[ ! -x "$lld" ]]; then
  echo "missing rust-lld at $lld" >&2
  exit 2
fi

out_dir="$fixture_dir/target/$target/release"
mkdir -p "$out_dir"
object="$out_dir/carrick-linux-aarch64-hello.o"
artifact="$out_dir/carrick-linux-aarch64-hello"

rustc "$fixture_dir/src/main.rs" \
  --target "$target" \
  --edition 2024 \
  -C panic=abort \
  -C opt-level=z \
  --emit=obj \
  -o "$object"

"$lld" -flavor gnu \
  -static \
  --entry=_start \
  --gc-sections \
  -o "$artifact" \
  "$object"

cargo metadata \
  --manifest-path "$fixture_dir/Cargo.toml" \
  --format-version 1 \
  >/dev/null

file "$artifact"
