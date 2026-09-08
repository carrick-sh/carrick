#!/bin/sh
# Build the one deterministic raw-syscall fixture used by carrick-embed's
# signed interceptor tests.
#
# NO DOCKER. This used to compile fixtures/embed-interceptor-probe/probe.c
# inside an `alpine:3.20` container, which put a Docker daemon on the critical
# path of `just test-embed`: with Docker not running the whole signed lane died
# here, at step 0, with "failed to connect to the docker API at
# ~/.docker/run/docker.sock" -- before a single test ran and with every image
# the tests need already in the local store. AGENTS.md's rule for probes covers
# exactly this case: a libc-only probe cross-compiles locally
# (`cargo build --target aarch64-unknown-linux-musl`), so the container bought
# nothing but a dependency.
#
# The result must be a STATIC aarch64 ELF with no interpreter: it is mounted
# into the guest through carrick's VFS seam and executed there, so a dynamic
# loader would make the fixture depend on the guest image's libc.
set -eu
cd "$(dirname "$0")/.."

target="aarch64-unknown-linux-musl"
crate_dir="$PWD/fixtures/embed-interceptor-probe"
output_dir="$PWD/target/embed-fixtures"
output_path="$output_dir/interceptor-probe-aarch64"
mkdir -p "$output_dir"

if ! command -v cargo >/dev/null 2>&1; then
    echo "build-embed-interceptor-probe: cargo is required" >&2
    exit 1
fi
if ! rustup target list --installed 2>/dev/null | grep -qx "$target"; then
    echo "build-embed-interceptor-probe: rust target $target is not installed" >&2
    echo "  install it with: rustup target add $target" >&2
    exit 1
fi

(cd "$crate_dir" && cargo build --release --target "$target")
cp -f "$crate_dir/target/$target/release/interceptor-probe" "$output_path"
chmod 0755 "$output_path"

# Prove the two properties the guest depends on, so a toolchain change cannot
# ship a fixture the guest silently cannot run.
if ! file "$output_path" | grep -Eq 'ELF 64-bit.*ARM aarch64.*statically linked'; then
    echo "build-embed-interceptor-probe: $output_path is not a static aarch64 ELF" >&2
    file "$output_path" >&2
    exit 1
fi
if command -v llvm-readelf >/dev/null 2>&1; then
    if llvm-readelf -l "$output_path" | grep -q INTERP; then
        echo "build-embed-interceptor-probe: interceptor probe unexpectedly has a dynamic interpreter" >&2
        exit 1
    fi
fi
echo "build-embed-interceptor-probe: wrote $output_path"
