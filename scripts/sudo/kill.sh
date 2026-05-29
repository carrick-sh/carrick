#!/bin/sh
# Kill all leftover carrick guest processes (argv0 rewritten to
# "carrick: <name>", so `pkill -f "carrick run"` misses them). Wedged HVF
# vCPUs can need a couple of SIGKILL passes.
# Match BOTH the renamed guest processes (comm "carrick: <name>") AND wedged
# `carrick trace` front-ends (comm stays "carrick"; they can hang in libdtrace/
# HVF with no guest child to reap, so the "carrick:" pattern alone misses them).
# `!/awk/` keeps this pipeline from matching itself; the carrick-binary path in
# the script's own argv lacks the ":"/"trace" tokens, so it is not matched.
for pass in 1 2 3; do
    pids=$(ps -axo pid,args | awk '!/awk/ && (/carrick:/ || /release\/carrick trace/) {print $1}')
    [ -z "$pids" ] && break
    echo "pass $pass: killing $(echo "$pids" | wc -l | tr -d ' ') procs"
    for p in $pids; do kill -9 "$p" 2>/dev/null; done
    sleep 1
done
remaining=$(ps -axo pid,args | awk '!/awk/ && (/carrick:/ || /release\/carrick trace/)' | grep -c .)
echo "remaining carrick procs = $remaining"
