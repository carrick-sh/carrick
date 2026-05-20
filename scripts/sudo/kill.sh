#!/bin/sh
# Kill all leftover carrick guest processes (argv0 rewritten to
# "carrick: <name>", so `pkill -f "carrick run"` misses them). Wedged HVF
# vCPUs can need a couple of SIGKILL passes.
for pass in 1 2 3; do
    pids=$(ps -axo pid,comm | awk '/carrick:/ {print $1}')
    [ -z "$pids" ] && break
    echo "pass $pass: killing $(echo "$pids" | wc -l | tr -d ' ') procs"
    for p in $pids; do kill -9 "$p" 2>/dev/null; done
    sleep 1
done
remaining=$(ps -axo pid,comm | grep -c "carrick:")
echo "remaining carrick: procs = $remaining"
