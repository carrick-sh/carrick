#!/bin/sh
# Build the release binary, stamp Carrick's qualified Darwin ABI contract, and
# re-sign it with the hypervisor entitlement.
# `cargo build --release` strips the codesignature on macOS; an unsigned binary
# fails every guest run with HV_DENIED (0xfae94007). Always build via this so
# the binary is never left unsigned.
#
# Per-worktree isolation: the signed binary is ALWAYS materialized at this
# worktree's ./target/release/carrick — even when CARGO_TARGET_DIR points at a
# SHARED build cache. Copying the artifact out of the shared dir gives each
# worktree its own immutable signed binary, so concurrent worktrees don't
# clobber each other's signature or race on in-place signing. The shared cache
# still saves recompilation; cargo's own build lock serialises the build step
# (a legitimately-serial prefix), while the per-worktree signed binary lets the
# RUN/test phase fan out (see parallel_conformance_gate).
set -e
cd "$(dirname "$0")/.."

# Entitlements selection.
#
# Default: scripts/entitlements.plist — hypervisor only. Production HVF binary;
# NOT debuggable (no get-task-allow), so hardened-runtime protections hold.
#
# Debug: scripts/entitlements-debug.plist — hypervisor + get-task-allow. Lets a
# debugger attach (task_for_pid). REQUIRED for the carrick-lldb event-ring
# workflow (`lldb -p <pid> -o "process save-core ..."`): on macOS with SIP
# "Debugging Restrictions: enabled", attaching to a self-signed process WITHOUT
# get-task-allow is denied — on macOS 27 / lldb-1703 that denial shows up as an
# immediate SIGILL (exit 132) before any lldb command runs. Opt in with either:
#     CARRICK_DEBUG_SIGN=1 ./scripts/build-signed.sh
#     ./scripts/build-signed.sh --debug
# The hypervisor entitlement is present in BOTH plists, so a --debug build still
# runs guests; it is just additionally debuggable. Never use --debug for a
# binary you ship or leave on an untrusted machine.
entitlements="scripts/entitlements.plist"
debug_sign="${CARRICK_DEBUG_SIGN:-0}"

# Strip a leading --debug from the cargo passthrough args (it is OURS, not
# cargo's). Everything else flows through to `cargo build` unchanged.
cargo_args=""
for arg in "$@"; do
    case "$arg" in
        --debug) debug_sign=1 ;;
        *) cargo_args="$cargo_args $arg" ;;
    esac
done

if [ "$debug_sign" != "0" ]; then
    entitlements="scripts/entitlements-debug.plist"
    echo "build-signed: DEBUG signing (hypervisor + get-task-allow) — debuggable; do not ship" >&2
fi

# shellcheck disable=SC2086
cargo build --release $cargo_args

built="${CARGO_TARGET_DIR:-target}/release/carrick"
signed="target/release/carrick"
if [ ! -x "$built" ]; then
    echo "build-signed: expected binary not found at $built" >&2
    exit 1
fi
# XNU's arm64 exception-return policy preserves physical x18 for binaries
# linked against the pre-macOS-13 ABI. Tier D proves that behavior again at
# runtime before using x18; if Apple changes it, Carrick refuses dynamic code
# rather than trusting this metadata. The private custom-x18 entitlement is
# intentionally NOT used: ad-hoc signed binaries carrying it are killed by
# AMFI on current macOS.
#
# Always materialise ATOMICALLY — vtool requires distinct input/output paths,
# and rename(2) means a concurrent exec sees the complete old or new binary.
mkdir -p target/release
raw="$signed.raw.$$"
tmp="$signed.tmp.$$"
trap 'rm -f "$raw" "$tmp"' EXIT
cp -f "$built" "$raw"
/usr/bin/vtool -set-build-version macos 11.0 12.0 -replace -output "$tmp" "$raw"
codesign --force --sign - --entitlements "$entitlements" "$tmp"
mv -f "$tmp" "$signed"
echo "built + signed: $signed (from $built, entitlements=$entitlements)"
