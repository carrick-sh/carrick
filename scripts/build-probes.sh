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
#   * x86_64-unknown-linux-musl   — STATIC ELFs for the AMD64 lane (Linux/KVM,
#     FreeBSD/bhyve, NetBSD/NVMM fleet; macOS Rosetta path).
#   * x86_64-unknown-linux-gnu    — DYNAMIC glibc ELFs for the AMD64 lane.
#
# A musl-only suite silently misses any divergence that only manifests under
# glibc — that is exactly how the TCGETS2 isatty gap shipped. Building both and
# diffing each against real Linux closes that blind spot.
#
# `--keep-going` is intentional everywhere: a probe that does not yet compile
# for a given target (the handful of aarch64-only raw-asm/raw-syscall probes
# fail to build for x86_64) is skipped (best-effort), so one arch-specific probe
# does not block the whole matrix. The harness only runs probes whose binary
# exists for a given libc/target, so a skipped probe is simply not part of that
# lane.
#
# HOST-ARCH AWARE: the x86_64 probe sets are built NATIVELY when this script
# runs on an x86_64 host (the fleet — no Docker/QEMU needed, just rustup
# targets); on macOS/arm64 they are cross-built via Rust's musl target inside
# the arm64 container (gnu x86_64 needs a cross C toolchain we don't have on the
# Mac, so the x86_64-gnu set is only produced natively on the fleet — that lane
# is non-gating anyway). Likewise the aarch64 sets are built natively on an
# aarch64 host's container; on the x86_64 fleet they are simply not produced
# (and `lane_runnable_here` SKIPs the ARM64 lane there).
set -e
cd "$(dirname "$0")/.."

HOST_ARCH="$(uname -m)"
MODE="${1:-default}"

if [ "$MODE" = "--native-pie" ]; then
  if [ "$HOST_ARCH" != "arm64" ] && [ "$HOST_ARCH" != "aarch64" ]; then
    echo "--native-pie requires an arm64 host" >&2
    exit 2
  fi

  docker run --rm --platform linux/arm64 \
    -v "$PWD/conformance-probes:/p" -w /p \
    rust:alpine sh -ec '
      rustup target add aarch64-unknown-linux-musl >/dev/null 2>&1 || true
      rm -rf target/native-pie/release
      rm -rf target/native-pie/aarch64-unknown-linux-musl/release
      sysroot="$(rustc --print sysroot)"
      CARGO_TARGET_DIR=target/native-pie \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=cc \
        RUSTFLAGS="-C link-self-contained=no -C relocation-model=pic -C link-arg=-static-pie -C link-arg=-L${sysroot}/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained" \
        cargo build --release --target aarch64-unknown-linux-musl

      probe=target/native-pie/aarch64-unknown-linux-musl/release/devnullseek
      readelf -h "$probe" | awk '\''$1 == "Type:" { found = 1; if ($2 != "DYN") exit 1 } END { if (!found) exit 1 }'\''
      "$probe" >/dev/null
    '

  docker run --rm --platform linux/arm64 \
    -v "$PWD/conformance-probes:/p" -w /p \
    rust:bookworm sh -ec '
      rustup target add aarch64-unknown-linux-gnu >/dev/null 2>&1 || true
      # Host build artifacts are libc-specific even though target artifacts
      # live in separate triple directories.
      rm -rf target/native-pie/release
      rm -rf target/native-pie/aarch64-unknown-linux-gnu/release
      CARGO_TARGET_DIR=target/native-pie \
        RUSTFLAGS="-C relocation-model=pie -C link-arg=-pie" \
        cargo build --release --target aarch64-unknown-linux-gnu

      probe=target/native-pie/aarch64-unknown-linux-gnu/release/devnullseek
      readelf -h "$probe" | awk '\''$1 == "Type:" { found = 1; if ($2 != "DYN") exit 1 } END { if (!found) exit 1 }'\''
      "$probe" >/dev/null
    '

  for triple in aarch64-unknown-linux-musl aarch64-unknown-linux-gnu; do
    dir="conformance-probes/target/native-pie/$triple/release"
    count=$(find "$dir" -maxdepth 1 -type f ! -name '*.*' 2>/dev/null | wc -l | tr -d ' ')
    echo "native PIE probes built: $dir ($count binaries)"
  done
  exit 0
fi

if [ "$MODE" != "default" ]; then
  echo "usage: $0 [--native-pie]" >&2
  exit 2
fi

build_native() {
  # build_native <target-triple> <linker-env-or-empty>
  # Native build via the host rustc (no container). Adds the rustup target,
  # wipes the prior release dir so stale binaries don't leak into the gate, and
  # keeps going past arch-specific probes that can't compile for this target.
  triple="$1"
  linker_env="$2"
  rustup target add "$triple" >/dev/null 2>&1 || true
  rm -rf "conformance-probes/target/$triple/release"
  (
    cd conformance-probes
    # shellcheck disable=SC2086 # linker_env is a deliberate "VAR=val" prefix
    env $linker_env cargo build --release --target "$triple" --keep-going || true
  )
}

if [ "$HOST_ARCH" = "x86_64" ] || [ "$HOST_ARCH" = "amd64" ]; then
  # ── Native x86_64 fleet (Linux/KVM, FreeBSD/bhyve, NetBSD/NVMM) ────────────
  # No Docker/QEMU: the host rustc targets x86_64 directly. musl is the gating
  # set; gnu is report-only. The aarch64 sets are NOT built here — the ARM64
  # lane is skipped on an x86_64 host (no cross-ISA guest execution).
  build_native x86_64-unknown-linux-musl ""
  build_native x86_64-unknown-linux-gnu ""

  for triple in x86_64-unknown-linux-musl x86_64-unknown-linux-gnu; do
    dir="conformance-probes/target/$triple/release"
    count=$(find "$dir" -maxdepth 1 -type f ! -name '*.*' 2>/dev/null | wc -l | tr -d ' ')
    echo "probes built: $dir ($count binaries)"
  done
  exit 0
fi

# ── macOS / aarch64 host: build via arm64 rust containers (cross-compile) ─────

# ── aarch64-musl (static) + x86_64-musl (static, Rust-only cross-link) ───────
docker run --rm --platform linux/arm64 \
  -v "$PWD/conformance-probes:/p" -w /p \
  rust:alpine sh -c '
    rustup target add aarch64-unknown-linux-musl >/dev/null 2>&1 || true
    rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
    cargo build --release --target aarch64-unknown-linux-musl
    rm -rf target/x86_64-unknown-linux-musl/release
    # The full x86_64-musl set: rust-lld cross-links the Rust-only probes
    # without an x86 C toolchain; --keep-going skips the ~handful of
    # aarch64-only raw-asm probes. This is what feeds the macOS Rosetta amd64
    # lane (the gating x86_64-musl set).
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
      cargo build --release --target x86_64-unknown-linux-musl --keep-going || true
  '

# ── aarch64-gnu (dynamic glibc) ─────────────────────────────────────────────
docker run --rm --platform linux/arm64 \
  -v "$PWD/conformance-probes:/p" -w /p \
  rust:bookworm sh -c '
    rustup target add aarch64-unknown-linux-gnu >/dev/null 2>&1 || true
    cargo build --release --target aarch64-unknown-linux-gnu --keep-going || true
  '

# Note: x86_64-unknown-linux-gnu is intentionally NOT built on macOS (no x86 C
# cross-toolchain for the glibc link); that report-only set is produced natively
# on the x86_64 fleet, where it links against the host glibc cross target.
for triple in aarch64-unknown-linux-musl aarch64-unknown-linux-gnu x86_64-unknown-linux-musl; do
  dir="conformance-probes/target/$triple/release"
  count=$(find "$dir" -maxdepth 1 -type f ! -name '*.*' 2>/dev/null | wc -l | tr -d ' ')
  echo "probes built: $dir ($count binaries)"
done
