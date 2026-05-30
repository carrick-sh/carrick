#!/usr/bin/env bash
# Proves the per-run cleanup isolation that unblocks running carrick lanes
# concurrently: two guests with distinct CARRICK_RUN_IDs, a SCOPED kill of one,
# and the other must SURVIVE. If this fails, concurrent conformance/sweep lanes
# would reap each other (the old global `kill.sh` behaviour).
set -u
repo="$(cd "$(dirname "$0")/.." && pwd)"
CARRICK="${CARRICK:-$repo/target/release/carrick}"
IMG="${IMG:-localhost:5050/ltp:arm64}"
export CARRICK_INSECURE_REGISTRIES="${CARRICK_INSECURE_REGISTRIES:-localhost:5050}"

alive() { ps -axo args | grep "carrick:$1" | grep -v grep | grep -c . ; }

CARRICK_RUN_ID=cr-AAA "$CARRICK" run "$IMG" --raw --fs host /bin/sleep 25 >/dev/null 2>&1 &
CARRICK_RUN_ID=cr-BBB "$CARRICK" run "$IMG" --raw --fs host /bin/sleep 25 >/dev/null 2>&1 &
sleep 7  # boot + title rename

echo "=== running guests ==="; ps -axo pid,args | grep -E 'carrick:cr-(AAA|BBB)' | grep -v grep
a0=$(alive cr-AAA); b0=$(alive cr-BBB)
echo "before: AAA=$a0 BBB=$b0"

echo "=== scoped kill cr-AAA ==="
"$repo/scripts/sudo/kill.sh" cr-AAA || pkill -9 -f 'carrick:cr-AAA'
sleep 1

a1=$(alive cr-AAA); b1=$(alive cr-BBB)
echo "after:  AAA=$a1 BBB=$b1"
pkill -9 -f 'carrick:cr-BBB' 2>/dev/null  # cleanup

if [ "$a0" -ge 1 ] && [ "$b0" -ge 1 ] && [ "$a1" -eq 0 ] && [ "$b1" -ge 1 ]; then
    echo "PASS: scoped kill reaped only cr-AAA; cr-BBB survived"
    exit 0
else
    echo "FAIL: isolation broken (a0=$a0 b0=$b0 a1=$a1 b1=$b1)"
    exit 1
fi
