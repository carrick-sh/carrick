#!/usr/bin/env bash
# Build carrick in release with HVF entitlement signing, then run Tier B
# (Alpine busybox) with full HVF + register tracing turned on. Trace output
# goes to docs/last-tier-b.trace so you can diff runs.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

binary="./target/release/carrick"
entitlements="./scripts/entitlements.plist"
trace_log="docs/last-tier-b.trace"
max_traps="${CARRICK_TIER_B_MAX_TRAPS:-30}"

cargo build --release --bin carrick --message-format short >&2
codesign --force --sign - --entitlements "$entitlements" "$binary" >&2

mkdir -p "$(dirname "$trace_log")"

# Make sure the alpine image is pulled.
if [[ ! -f "$HOME/.carrick/images/docker.io/library/alpine/latest/summary.json" ]]; then
  "$binary" pull docker.io/library/alpine:latest >&2
fi

CARRICK_TRACE_REGS=1 CARRICK_TRACE_MAPS=1 \
  "$binary" run docker.io/library/alpine:latest \
    --max-traps "$max_traps" \
    /bin/busybox echo hello \
    2>"$trace_log" || true

echo "trace written to $trace_log"
echo
echo "--- MAP lines ---"
grep "^MAP " "$trace_log" || true
echo
echo "--- TRAP lines ---"
grep "^TRAP " "$trace_log" || true
echo
echo "--- COMPLETE lines ---"
grep "^COMPLETE " "$trace_log" || true
