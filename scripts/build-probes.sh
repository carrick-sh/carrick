#!/bin/sh
# Build the conformance probe binaries as static aarch64-linux-musl ELFs
# inside an arm64 rust:alpine container (no host cross-linker needed). Output
# lands in conformance-probes/target/aarch64-unknown-linux-musl/release/.
set -e
cd "$(dirname "$0")/.."
docker run --rm --platform linux/arm64 \
  -v "$PWD/conformance-probes:/p" -w /p \
  rust:alpine sh -c '
    rustup target add aarch64-unknown-linux-musl >/dev/null 2>&1 || true
    cargo build --release --target aarch64-unknown-linux-musl
  '
echo "probes built: conformance-probes/target/aarch64-unknown-linux-musl/release/"
ls conformance-probes/target/aarch64-unknown-linux-musl/release/ 2>/dev/null | grep -v '\.' || true
