#!/bin/bash
# Isolate thread CREATION (the "Can't start N threads" / thread-stack mmap
# failure) from any contention in the thread bodies.
set -u
# Default to the main checkout's signed binary. Override with BIN=... to
# compare against another build (e.g. a rebuilt base revision for attribution).
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${BIN:-$REPO/target/release/carrick}"
TAG="${1:-spawn}"
N="${2:-20}"
SCRATCH="${SCRATCH:-${TMPDIR:-/tmp}}"
export CARRICK_RUN_ID="spawn-$TAG-$$"
export RUST_LOG="${RUST_LOG:-warn,carrick::mmap=debug,carrick::cow=debug}"
CODE="
import sys, threading, time
N = $N
started = 0
ts = []
def run():
    time.sleep(0.05)
for i in range(N):
    t = threading.Thread(target=run)
    try:
        t.start()
    except RuntimeError as e:
        print('SPAWN: start failed at', i, e); break
    ts.append(t); started += 1
for t in ts:
    t.join(20)
print('SPAWN started:', started, 'of', N, 'alive:', sum(t.is_alive() for t in ts))
sys.stdout.flush()
"
echo "RUN_ID=$CARRICK_RUN_ID BIN=$BIN"
"$BIN" run --name "spawn-$TAG" --max-traps 18446744073709551615 \
  --raw --fs host localhost:5050/cpython-test:3.12.13 \
  /usr/local/bin/python3 -c "$CODE" > "$SCRATCH/$TAG.sout" 2> "$SCRATCH/$TAG.serr"
echo "exit=$?"
grep -a "SPAWN" "$SCRATCH/$TAG.sout" || echo "NO SPAWN LINE"
echo -n "mmap refusals: "; grep -ac "mmap refused" "$SCRATCH/$TAG.serr"
echo -n "superseded receipts: "; grep -ac "superseding deferred COW receipt" "$SCRATCH/$TAG.serr"
bash "$REPO/scripts/sudo/kill.sh" "$CARRICK_RUN_ID" 2>&1 | tail -1
