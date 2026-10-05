#!/bin/sh
# Build the static copyout fixture used by carrick-embed's signed
# `kernel.el1.anonymous-reservations.host-copyout` contract: host copyout
# into and out of never-touched anonymous memory (read, pread, recv, write,
# and a copyout racing an EL0 first touch of the same page).
#
# Same rules as build-embed-interceptor-probe.sh: no Docker (a std-only
# program cross-compiles locally for aarch64-unknown-linux-musl), and the
# result must be a STATIC aarch64 ELF, because it is mounted into the guest
# through carrick's VFS seam and must not depend on the image's libc.
set -eu
cd "$(dirname "$0")/.."

target="aarch64-unknown-linux-musl"
crate_dir="$PWD/fixtures/embed-copyout"
output_dir="$PWD/target/embed-fixtures"
output_path="$output_dir/copyout-aarch64"
mkdir -p "$output_dir"

if ! rustup target list --installed 2>/dev/null | grep -qx "$target"; then
    echo "build-embed-copyout: rust target $target is not installed" >&2
    echo "  install it with: rustup target add $target" >&2
    exit 1
fi

(cd "$crate_dir" && cargo build --locked --release --target "$target")
cp -f "$crate_dir/target/$target/release/copyout" "$output_path"
chmod 0755 "$output_path"

if ! file "$output_path" | grep -Eq 'ELF 64-bit.*ARM aarch64.*statically linked'; then
    echo "build-embed-copyout: $output_path is not a static aarch64 ELF" >&2
    file "$output_path" >&2
    exit 1
fi
echo "build-embed-copyout: wrote $output_path"
