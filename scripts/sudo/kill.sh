#!/bin/sh
# Kill leftover carrick guest processes. carrick rewrites argv0 to
# "carrick:<run-id>: <name>" (proctitle.rs), so `pkill -f "carrick run"` misses
# them and wedged HVF vCPUs can need a couple of SIGKILL passes.
#
# A RUN-ID IS REQUIRED ($1). The scoped reap matches the EXACT delimited token
# "carrick:<run-id>:" as a LITERAL substring (awk index(), not a regex): the
# trailing ":" is the proctitle's id/name delimiter, so
#   - concurrent carrick lanes / worktrees / agents clean up WITHOUT reaping each
#     other (an unscoped reap mid-run looks like an unrelated flake), AND
#   - a run-id that is a PREFIX of another (e.g. "<...>-c1" vs "<...>-c10") does
#     NOT over-match. A bare "carrick:<id>" regex DID over-match every longer id
#     sharing that prefix — the bug this anchoring fixes — and a run-id with
#     regex metacharacters could misfire; index() of the ":"-anchored token cures
#     both.
# carrick stamps the run id into the title from $CARRICK_RUN_ID, inherited across
# guest forks. ALWAYS pass a run id.
#
#   kill.sh <run-id>   scoped reap (the ONLY per-run cleanup form)
#   kill.sh --all      explicit GLOBAL sledgehammer (every renamed guest +
#                      wedged `carrick trace` front-ends). MANUAL RECOVERY ONLY
#                      — never in per-run cleanup or while sibling lanes run.
#
# The `!/awk/` guard keeps the matcher from killing its own awk pipeline (whose
# argv embeds the pattern).

run_id="${1:-}"
if [ -z "$run_id" ]; then
    echo "kill.sh: a run-id is REQUIRED (kills must not spread across concurrent" >&2
    echo "  lanes/worktrees/agents). Usage: kill.sh <run-id>   |   kill.sh --all (manual only)." >&2
    echo "  The run-id is \$CARRICK_RUN_ID, stamped into the 'carrick:<run-id>:' guest title." >&2
    exit 2
fi

if [ "$run_id" = "--all" ]; then
    # Global sledgehammer (manual recovery only): every renamed guest + trace fronts.
    scan() { ps -axo pid,args | awk '!/awk/ && ($0 ~ /carrick:/ || $0 ~ /release\/carrick trace/) {print $1}'; }
    desc="ALL carrick guests"
else
    # Scoped: LITERAL, anchored match of the delimited token "carrick:<id>:".
    needle="carrick:$run_id:"
    scan() { ps -axo pid,args | awk -v n="$needle" '!/awk/ && index($0, n) {print $1}'; }
    desc="run-id $run_id"
fi

for pass in 1 2 3; do
    pids=$(scan)
    [ -z "$pids" ] && break
    echo "pass $pass: killing $(echo "$pids" | wc -w | tr -d ' ') procs ($desc)"
    for p in $pids; do kill -9 "$p" 2>/dev/null; done
    sleep 1
done

echo "remaining carrick procs ($desc) = $(scan | grep -c .)"
