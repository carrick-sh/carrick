#!/bin/sh
# Kill leftover carrick guest processes. carrick rewrites argv0 to
# "carrick:[<run-id>] <name>" (proctitle.rs), so `pkill -f "carrick run"` misses
# them and wedged HVF vCPUs can need a couple of SIGKILL passes.
#
# SCOPED reap (preferred): pass a run id as $1 and ONLY processes whose title
# contains "carrick:<run-id>" are killed. This lets concurrent carrick lanes /
# worktrees clean up without reaping each other (the hazard that forced the
# conformance gate and the LTP sweeps to run serially). carrick stamps the run
# id into the title from $CARRICK_RUN_ID, inherited across guest forks.
#
# GLOBAL reap (no arg): the legacy sledgehammer — every renamed guest
# ("carrick:") AND wedged `carrick trace` front-ends (comm stays "carrick").
# Reserve this for manual recovery, NOT for per-run cleanup.
#
# `!/awk/` keeps the pipeline from matching its own argv (which embeds the
# pattern); the carrick-binary path in this script's argv lacks the ":" token.

run_id="${1:-}"
if [ -n "$run_id" ]; then
    pat="carrick:$run_id"
else
    pat="carrick:|release/carrick trace"
fi

for pass in 1 2 3; do
    pids=$(ps -axo pid,args | awk -v p="$pat" '!/awk/ && $0 ~ p {print $1}')
    [ -z "$pids" ] && break
    echo "pass $pass: killing $(echo "$pids" | wc -w | tr -d ' ') procs (pat=$pat)"
    for p in $pids; do kill -9 "$p" 2>/dev/null; done
    sleep 1
done

remaining=$(ps -axo pid,args | awk -v p="$pat" '!/awk/ && $0 ~ p' | grep -c .)
echo "remaining carrick procs (pat=$pat) = $remaining"
