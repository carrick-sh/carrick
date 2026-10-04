#!/usr/bin/env bash
# Mechanical release-closure assertion for the VM-free test coordinator.
set -euo pipefail
cd "$(dirname "$0")/.."
if cargo tree -p carrick-cli --edges normal --prefix none | rg -q '^carrick-kernel-example v'; then
    echo 'vmfree schedule leaked into the product dependency closure' >&2
    exit 1
fi
# The only source hook is guarded at macro expansion, so optimized builds
# contain neither the call nor its point expression.
if ! rg -Uq '#\[cfg\(debug_assertions\)\]\s+if let Some\(schedule\)' \
    crates/carrick-kernel-example/src/schedule.rs; then
    echo 'vmfree schedule hook lost its release compile-out guard' >&2
    exit 1
fi
echo 'vmfree schedule excluded from product closure and release hook expansion'
