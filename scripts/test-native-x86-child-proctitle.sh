#!/bin/sh
# End-to-end FreeBSD native fork/exec process-title regression.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
carrick=${1:-"$repo/target/release/carrick"}
image=${2:-carrick-ltp-deps:20260529}
run_id="native-x86-proctitle-$$"
log="/tmp/$run_id.log"
driver_pid=""

cleanup() {
    "$repo/scripts/sudo/kill.sh" "$run_id" >/dev/null 2>&1 || true
    if [ -n "$driver_pid" ]; then
        kill "$driver_pid" >/dev/null 2>&1 || true
        wait "$driver_pid" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

CARRICK_RUN_ID="$run_id" \
CARRICK_MMAP_ARENA_GIB=1 \
    "$carrick" run --pull never --platform linux/amd64 --exec-backend hvpatch \
    "$image" /bin/sh -c '/bin/sleep 30 & wait' >"$log" 2>&1 &
driver_pid=$!

needle="carrick:$run_id: /bin/sleep 30"
deadline=$(( $(date +%s) + 20 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    match=$(ps -axww -o pid= -o command= | awk -v n="$needle" \
        '!/awk/ && index($0, n) { print; exit }')
    if [ -n "$match" ]; then
        printf '%s\n' "$match"
        exit 0
    fi
    if ! kill -0 "$driver_pid" 2>/dev/null; then
        echo "proctitle test driver exited before child title appeared" >&2
        cat "$log" >&2
        exit 1
    fi
    sleep 0.1
done

echo "timed out waiting for exact child title: $needle" >&2
ps -axww -o pid= -o ppid= -o command= | awk -v n="carrick:$run_id:" \
    '!/awk/ && index($0, n) { print }' >&2
cat "$log" >&2
exit 1
