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
tmp_dir="$(mktemp -d "$out_dir/carrick-linux-aarch64-fixtures.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

build_fixture() {
  local source="$1"
  local name="$2"
  local object="$tmp_dir/$name.o"
  local artifact_tmp="$tmp_dir/$name"
  local artifact="$out_dir/$name"

  rustc "$fixture_dir/src/$source" \
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
    -o "$artifact_tmp" \
    "$object"

  mv -f "$artifact_tmp" "$artifact"
  file "$artifact"
}

build_fixture "main.rs" "carrick-linux-aarch64-hello"
build_fixture "cat_motd.rs" "carrick-linux-aarch64-cat-motd"

cargo metadata \
  --manifest-path "$fixture_dir/Cargo.toml" \
  --format-version 1 \
  >/dev/null
