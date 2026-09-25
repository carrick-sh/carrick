#!/bin/sh
# Build the static el1-sched fixture used by carrick-embed's signed EL1
# scheduler tests (EL1 plan 1b): futex ping-pong with host-exit counting, and
# signal / exit_group / execve against threads parked in futex waits.
#
# Same rules as build-embed-zone-readers.sh: no Docker (a std program with the
# libc crate cross-compiles locally for aarch64-unknown-linux-musl), and the
# result must be a STATIC aarch64 ELF, because it is mounted into the guest
# through carrick's VFS seam and must not depend on the image's libc.
set -eu
cd "$(dirname "$0")/.."

target="aarch64-unknown-linux-musl"
crate_dir="$PWD/fixtures/embed-el1-sched"
output_dir="$PWD/target/embed-fixtures"
output_path="$output_dir/el1-sched-aarch64"
mkdir -p "$output_dir"

if ! rustup target list --installed 2>/dev/null | grep -qx "$target"; then
    echo "build-embed-el1-sched: rust target $target is not installed" >&2
    echo "  install it with: rustup target add $target" >&2
    exit 1
fi

(cd "$crate_dir" && cargo build --release --target "$target")
cp -f "$crate_dir/target/$target/release/el1-sched" "$output_path"
chmod 0755 "$output_path"

if ! file "$output_path" | grep -Eq 'ELF 64-bit.*ARM aarch64.*statically linked'; then
    echo "build-embed-el1-sched: $output_path is not a static aarch64 ELF" >&2
    file "$output_path" >&2
    exit 1
fi
echo "build-embed-el1-sched: wrote $output_path"
