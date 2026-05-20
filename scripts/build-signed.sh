#!/bin/sh
# Build the release binary AND re-sign it with the hypervisor entitlement.
# `cargo build --release` strips the codesignature on macOS; an unsigned
# binary fails every guest run with HV_DENIED (0xfae94007). Always build via
# this so the binary is never left unsigned.
set -e
cd "$(dirname "$0")/.."
cargo build --release "$@"
codesign --force --sign - --entitlements scripts/entitlements.plist target/release/carrick
echo "built + signed: target/release/carrick"
