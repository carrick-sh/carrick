#!/bin/bash
set -eo pipefail

# Run cargo tree with platform-linux feature, checking that neither carrick-hvf,
# applevisor, nor applevisor-sys are in the build dependency closure of carrick-runtime.

TREE_OUTPUT=$(cargo tree --no-default-features --features platform-linux --target aarch64-unknown-linux-gnu -p carrick-runtime -e no-dev)

if echo "$TREE_OUTPUT" | grep -qE "carrick-hvf|applevisor|applevisor-sys"; then
    echo "ERROR: platform-linux dependency closure contains forbidden macOS/HVF dependencies:"
    echo "$TREE_OUTPUT" | grep -E "carrick-hvf|applevisor|applevisor-sys"
    exit 1
fi

echo "OK: platform-linux dependency closure contains no macOS/HVF dependencies."
exit 0
