#!/bin/sh
# Build the conformance probe binaries as static Linux/musl ELFs inside a
# native arm64 rust:alpine container (no host cross-linker needed). We build
# a portable x86_64 smoke subset from the arm64 container too: Docker's amd64
# rustc runs under QEMU on this host and has been unreliable, while Rust's musl
# target can cross-link Rust-only probes directly. Most existing probes are
# aarch64-specific (raw syscall numbers/register asm), so do not build all bins
# for x86_64 until they are made arch-neutral.
set -e
cd "$(dirname "$0")/.."
docker run --rm --platform linux/arm64 \
  -v "$PWD/conformance-probes:/p" -w /p \
  rust:alpine sh -c '
    rustup target add aarch64-unknown-linux-musl >/dev/null 2>&1 || true
    rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
    cargo build --release --target aarch64-unknown-linux-musl
    rm -rf target/x86_64-unknown-linux-musl/release
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
      cargo build --release --target x86_64-unknown-linux-musl --bin futexpilock
  '
echo "probes built: conformance-probes/target/aarch64-unknown-linux-musl/release/"
find conformance-probes/target/aarch64-unknown-linux-musl/release \
  -maxdepth 1 -type f ! -name '*.*' -exec basename {} \; 2>/dev/null | sort || true
echo "probes built: conformance-probes/target/x86_64-unknown-linux-musl/release/"
find conformance-probes/target/x86_64-unknown-linux-musl/release \
  -maxdepth 1 -type f ! -name '*.*' -exec basename {} \; 2>/dev/null | sort || true
