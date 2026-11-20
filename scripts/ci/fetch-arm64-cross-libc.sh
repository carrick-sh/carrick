#!/usr/bin/env bash
set -euo pipefail

root=${1:?usage: fetch-arm64-cross-libc.sh FIXTURE_ROOT}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT

deb=libc6-arm64-cross_2.41-11cross1_all.deb
deb_sha256=82cd3a0c6754d36cb5a7acbd9fa64c38080a681608c41165736dc88438acfc71
curl --fail --silent --show-error --location \
    "https://deb.debian.org/debian/pool/main/c/cross-toolchain-base/$deb" \
    --output "$scratch/$deb"
printf '%s  %s\n' "$deb_sha256" "$scratch/$deb" | sha256sum --check --strict
dpkg-deb --extract "$scratch/$deb" "$scratch/sysroot"

lib="$scratch/sysroot/usr/aarch64-linux-gnu/lib"
install -D -m 644 "$lib/ld-linux-aarch64.so.1" "$root/lib/ld-linux-aarch64.so.1"
install -D -m 644 "$lib/libc.so.6" "$root/lib/libc.so.6"

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
"${CC:-gcc}" -march=armv8-a -O1 -fno-builtin -Wl,-rpath,/lib \
    -Wl,--dynamic-linker=/lib/ld-linux-aarch64.so.1 \
    "$repo/crates/carrick-softcpu-aarch64-host/tests/fixtures/glibc_hello.c" \
    -o "$root/hello"
