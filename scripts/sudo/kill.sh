#!/bin/sh
# Kill leftover carrick guest processes. carrick rewrites argv0 to
# "carrick:[<run-id>] <name>" (proctitle.rs), so `pkill -f "carrick run"` misses
# them and wedged HVF vCPUs can need a couple of SIGKILL passes.
#
# A RUN-ID IS REQUIRED ($1). Only processes whose title contains
# "carrick:<run-id>" are killed, so concurrent carrick lanes / worktrees /
# workflow sub-agents clean up WITHOUT reaping each other (the hazard that
# forced the conformance gate and the LTP sweeps to run serially, and that
# silently breaks parallel runs — an unscoped reap mid-run looks like an
# unrelated flake). carrick stamps the run id into the title from
# $CARRICK_RUN_ID, inherited across guest forks. ALWAYS pass a run id.
#
#   kill.sh <run-id>   scoped reap (the ONLY per-run cleanup form)
#   kill.sh --all      explicit GLOBAL sledgehammer (every renamed guest +
#                      wedged `carrick trace` front-ends). MANUAL RECOVERY ONLY
#                      — never in per-run cleanup or while sibling lanes run.
#
# `!/awk/` keeps the pipeline from matching its own argv (which embeds the
# pattern); the carrick-binary path in this script's argv lacks the ":" token.

run_id="${1:-}"
if [ -z "$run_id" ]; then
    echo "kill.sh: a run-id is REQUIRED (kills must not spread across concurrent" >&2
    echo "  lanes/worktrees/agents). Usage: kill.sh <run-id>   |   kill.sh --all (manual only)." >&2
    echo "  The run-id is \$CARRICK_RUN_ID, stamped into the 'carrick:<run-id>' guest title." >&2
    exit 2
fi
if [ "$run_id" = "--all" ]; then
    pat="carrick:|release/carrick trace"
else
    pat="carrick:$run_id"
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
