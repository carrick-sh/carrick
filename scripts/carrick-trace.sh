#!/usr/bin/env bash
# Run a carrick command under DTrace, using the bundled syscalls.d script.
#
# Usage:
#   scripts/carrick-trace.sh <carrick-args...>
#
# Example:
#   scripts/carrick-trace.sh run docker.io/library/alpine:latest \
#       --max-traps 200 /bin/busybox sh -c 'echo hi; ls /etc'
#
# Notes:
#   * Requires sudo to invoke dtrace. SIP must permit DTrace
#     (`csrutil status` should show "DTrace Restrictions: disabled").
#   * The carrick binary must be signed with `get-task-allow` for DTrace
#     to attach. The repo's `scripts/entitlements.plist` adds it.
#   * Stdout is the live trace + carrick's stdout; the END action prints
#     frequency-sorted aggregations after the command exits.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
carrick="$repo_root/target/release/carrick"
script="$repo_root/scripts/syscalls.d"

if [ ! -x "$carrick" ]; then
    echo "carrick-trace: $carrick not found; run 'cargo build --release' first" >&2
    exit 1
fi
if [ ! -f "$script" ]; then
    echo "carrick-trace: $script missing" >&2
    exit 1
fi

# Quote the carrick command for dtrace -c.
cmd="$carrick"
for arg in "$@"; do
    cmd+=" $(printf '%q' "$arg")"
done

exec sudo dtrace -s "$script" -c "$cmd"
