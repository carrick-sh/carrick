#!/bin/sh
# Build the conformance probe binaries for BOTH libc flavours, so the
# conformance matrix exercises glibc-specific ABI paths (e.g. glibc tcgetattr/
# isatty going through TCGETS2, which musl never issues) as well as musl:
#
#   * aarch64-unknown-linux-musl  — STATIC ELFs, built in a native arm64
#     rust:alpine container (no host cross-linker needed). The historical set.
#   * aarch64-unknown-linux-gnu   — DYNAMIC glibc ELFs, built in a native arm64
#     rust:bookworm (Debian/glibc) container. Run inside the glibc lane image
#     (ubuntu:24.04) where the dynamic loader + libc are present.
#
# A musl-only suite silently misses any divergence that only manifests under
# glibc — that is exactly how the TCGETS2 isatty gap shipped. Building both and
# diffing each against real Linux closes that blind spot.
#
# We also build a portable x86_64-musl smoke subset from the arm64 container:
# Docker's amd64 rustc runs under QEMU and is unreliable, while Rust's musl
# target cross-links Rust-only probes directly. Most probes are aarch64-specific
# (raw syscall numbers/register asm), so do not build all bins for x86_64.
#
# `--keep-going` on the gnu build is intentional: a probe that does not yet
# compile for glibc is skipped (best-effort), so a single musl-ism in one probe
# does not block the whole matrix. The harness only runs probes whose binary
# exists for a given libc, so a skipped gnu probe is simply not part of the gnu
# lane until it is made portable.
set -e
cd "$(dirname "$0")/.."

# ── musl (static) ───────────────────────────────────────────────────────────
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

# ── gnu (dynamic glibc) ─────────────────────────────────────────────────────
docker run --rm --platform linux/arm64 \
  -v "$PWD/conformance-probes:/p" -w /p \
  rust:bookworm sh -c '
    rustup target add aarch64-unknown-linux-gnu >/dev/null 2>&1 || true
    cargo build --release --target aarch64-unknown-linux-gnu --keep-going || true
  '

for triple in aarch64-unknown-linux-musl aarch64-unknown-linux-gnu x86_64-unknown-linux-musl; do
  dir="conformance-probes/target/$triple/release"
  count=$(find "$dir" -maxdepth 1 -type f ! -name '*.*' 2>/dev/null | wc -l | tr -d ' ')
  echo "probes built: $dir ($count binaries)"
done
