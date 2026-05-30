#!/bin/sh
# Build the release binary AND re-sign it with the hypervisor entitlement.
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

cargo build --release "$@"

built="${CARGO_TARGET_DIR:-target}/release/carrick"
signed="target/release/carrick"
if [ ! -x "$built" ]; then
    echo "build-signed: expected binary not found at $built" >&2
    exit 1
fi
if [ "$built" != "$signed" ]; then
    # Shared CARGO_TARGET_DIR: materialise ATOMICALLY — sign a temp copy, then
    # rename(2) it into place. `cp -f` rewrites the dest inode in place, so a
    # concurrent guest exec() of ./target/release/carrick during the copy would
    # otherwise open a truncated Mach-O (ETXTBSY/SIGBUS). rename is atomic on the
    # same fs, so an exec sees the whole old or whole new binary, never a torn one.
    mkdir -p target/release
    tmp="$signed.tmp.$$"
    trap 'rm -f "$tmp"' EXIT
    cp -f "$built" "$tmp"
    codesign --force --sign - --entitlements scripts/entitlements.plist "$tmp"
    mv -f "$tmp" "$signed"
else
    # Unset CARGO_TARGET_DIR (common case): sign in place. codesign itself writes
    # via a temp + rename, so the in-place case is already atomic.
    codesign --force --sign - --entitlements scripts/entitlements.plist "$signed"
fi
echo "built + signed: $signed (from $built)"
