#!/bin/sh
# Privileged escalation for stress-capture's LLDB/DTrace tools only.
# Match the literal canonical run directory in argv, never a global tool name
# or a supplied PID. A suffix boundary prevents sibling-prefix collisions.
# The caller first TERM-signals sudo (which relays TERM), waits, then invokes
# this helper only if scoped argv remain. Three passes bound the reap.
set -eu
run_dir=${1:?usage: kill-capture.sh /absolute/run-directory}
case "$run_dir" in
    /*) ;;
    *) echo 'kill-capture.sh: absolute run directory required' >&2; exit 2 ;;
esac
case "$run_dir" in
    *'
'*) echo 'kill-capture.sh: control characters refused' >&2; exit 2 ;;
esac
if printf '%s' "$run_dir" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    echo 'kill-capture.sh: control characters refused' >&2
    exit 2
fi
[ -d "$run_dir" ] && [ "$run_dir" != / ] && [ "${run_dir%/}" = "$run_dir" ] || exit 2
# Refuse a broad parent/output directory: the runner creates this marker in
# each private iteration directory before it launches any privileged tool.
[ -f "$run_dir/.stress-capture-run" ] || exit 2
scan() {
    snapshot=$(ps -axww -o pid= -o ppid= -o command=) || return
    printf '%s\n' "$snapshot" | CARRICK_CAPTURE_SCOPE="$run_dir" awk -v self="$$" '
        BEGIN { scope = ENVIRON["CARRICK_CAPTURE_SCOPE"] }
        { rows[NR] = $0; ids[NR] = $1; parents[$1] = $2 }
        END {
            # Exclude only this helper tree and its sudo/caller ancestors.
            # Another orphaned helper bearing the scope must still be reaped.
            cursor = self
            for (hop = 0; cursor && hop < 64; hop++) {
                ancestors[cursor] = 1
                cursor = parents[cursor]
            }
            for (i = 1; i <= NR; i++) {
                if (ancestors[ids[i]]) continue
                cursor = parents[ids[i]]
                own_child = 0
                for (hop = 0; cursor && hop < 64; hop++) {
                    if (cursor == self) { own_child = 1; break }
                    cursor = parents[cursor]
                }
                if (own_child) continue
                rest = rows[i]
                while ((pos = index(rest, scope))) {
                    nextchar = substr(rest, pos + length(scope), 1)
                    if (nextchar == "" || nextchar == "/" || nextchar == " " ||
                        nextchar == "\t" || nextchar == "\"" || nextchar == "\047") {
                        print ids[i]
                        break
                    }
                    rest = substr(rest, pos + length(scope))
                }
            }
        }
    '

}
for pass in 1 2 3; do
    pids=$(scan)
    [ -n "$pids" ] || break
    for pid in $pids; do kill -KILL "$pid" 2>/dev/null || :; done
    sleep 1
done
remaining=$(scan)
if [ -n "$remaining" ]; then
    printf 'kill-capture.sh: scoped processes remain: %s\n' "$remaining" >&2
    exit 1
fi
