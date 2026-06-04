#!/bin/sh
# go-deadlock-capture.sh — launch the N-concurrent `go build` deadlock reproducer
# under carrick + the deadlock watchdog WITHOUT starving the host.
#
# Why this exists: a naive launch saturated all 10 cores. A hung concurrent
# `go build` leaves N builds x GOMAXPROCS vCPU host-threads spinning (the
# Layer-2 fork+exec stall is busy, not blocked), and the watchdog CORES but does
# NOT kill — so the spin outlives the capture until a human notices. That is a
# self-inflicted fork bomb. This harness bounds it:
#
#   1. THROTTLE: `taskpolicy -b` (darwin-background QoS, inherited by every vCPU
#      thread + forked guest child -> E-cores, deprioritized) + `nice -n 20`. The
#      macOS UI/Terminal keep winning the scheduler while the guest spins. (As a
#      bonus the extra scheduling jitter makes the contention-sensitive deadlock
#      MORE likely to reproduce, and we don't care about wall-clock speed.)
#   2. AUTO-KILL ON CAPTURE: the supervisor waits for the watchdog's core to be
#      FULLY written (lldb "corefile created"/"detached"), then SIGKILLs the whole
#      run tree. Spin lasts ~one watchdog window, not "until noticed".
#   3. NEVER ORPHAN: an EXIT/TERM/INT trap kills the tree on ANY harness exit
#      (incl. TaskStop); a hard wall-clock DEADLINE kills regardless; cleanup is
#      scoped by the unique run-id proctitle (`pkill -f <run-id>`), so it never
#      touches another carrick run/worktree.
#
# Usage: scripts/go-deadlock-capture.sh [N] [WATCHDOG_MS] [DEADLINE_S] [CPUS]
#   N           concurrent go builds            (default 4)
#   WATCHDOG_MS tree-wide stall -> self-core    (default 8000)
#   DEADLINE_S  hard kill regardless            (default 90)
#   CPUS        CARRICK_EXPOSED_CPUS cap, ""=host (default "", i.e. host count)
set -u

N="${1:-4}"
WD_MS="${2:-8000}"
DEADLINE_S="${3:-90}"
CPUS="${4:-}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CARRICK="$REPO/target/release/carrick"
IMG="localhost:5005/carrick-go-conformance:1.24"
RUN="go-dl-n${N}-$$"
OUT="/tmp/${RUN}.out"
ERR="/tmp/${RUN}.err"
CORE_GLOB="/tmp/deadlock-*.core"

[ -x "$CARRICK" ] || { echo "FATAL: no signed carrick at $CARRICK (run scripts/build-signed.sh)"; exit 2; }
command -v taskpolicy >/dev/null 2>&1 || { echo "FATAL: taskpolicy missing"; exit 2; }

# Fresh slate for THIS run's stdout/err.
rm -f "$OUT" "$ERR" 2>/dev/null
# A prior run's core is owned by ROOT (the watchdog cores via `sudo lldb`), so a
# plain `rm` as this user can NOT delete it — and keying capture-detection on
# "any deadlock-*.core exists" then mistakes the stale core for a fresh capture
# and kills the run at t~0 (observed). Instead: best-effort remove our own, then
# SNAPSHOT what remains and only ever react to a core THIS run newly creates.
rm -f /tmp/deadlock-*.core 2>/dev/null   # removes only cores this user owns
PRE_CORES="/tmp/.go-dl-precores.$$"
ls /tmp/deadlock-*.core 2>/dev/null | sort > "$PRE_CORES" 2>/dev/null || : > "$PRE_CORES"
# Cores that appeared AFTER our snapshot (whole-line fixed match; an empty
# snapshot file => every current core is "new", which is what we want).
new_cores() { ls /tmp/deadlock-*.core 2>/dev/null | sort | grep -vxF -f "$PRE_CORES" 2>/dev/null; }

# Guest workload: N concurrent `go build`, each with its OWN GOCACHE so all N
# genuinely fork compile+link at once (a shared cache short-circuits builds 2..N
# to a cache hit and they never fork -> no repro).
GUEST=$(cat <<EOF
set -x
cd /tmp
printf 'package main\nfunc main(){println("ok")}\n' > h.go
i=1; while [ "\$i" -le $N ]; do mkdir -p "b\$i" && cp h.go "b\$i/"; i=\$((i+1)); done
i=1; while [ "\$i" -le $N ]; do
  ( cd "/tmp/b\$i" && GOCACHE="/tmp/gc\$i" /usr/local/go/bin/go build -o "/tmp/out\$i" ./h.go && echo "BUILT \$i" ) &
  i=\$((i+1))
done
wait
echo ALL_DONE
EOF
)
B64=$(printf '%s' "$GUEST" | base64 | tr -d '\n')

RUNPID=""
cleanup() {
  # Scoped + reliable: by unique run-id proctitle AND by pid, SIGKILL.
  pkill -9 -f "$RUN" 2>/dev/null
  [ -n "$RUNPID" ] && kill -9 "$RUNPID" 2>/dev/null
  rm -f "$PRE_CORES" 2>/dev/null
  return 0
}
# Kill the tree on ANY exit (normal, deadline, or harness TERM/INT/TaskStop).
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT TERM

echo "run=$RUN  N=$N  watchdog=${WD_MS}ms  deadline=${DEADLINE_S}s  cpus=${CPUS:-host}"
echo "  out=$OUT  err=$ERR"

# Optional guest-CPU cap (fewer GOMAXPROCS -> fewer spinning host vCPU threads).
CPU_ENV=""
[ -n "$CPUS" ] && CPU_ENV="CARRICK_EXPOSED_CPUS=$CPUS"

# Launch THROTTLED + niced, as a child of this harness (same process group), so a
# group kill / the EXIT trap reliably reaps it. Output to files (no terminal tie-up).
# shellcheck disable=SC2086
nice -n 20 taskpolicy -b \
  env CARRICK_INSECURE_REGISTRIES=localhost:5005 CARRICK_DEADLOCK_WATCHDOG_MS="$WD_MS" $CPU_ENV \
  "$CARRICK" run --name "$RUN" --raw --fs host -w /tmp \
  "$IMG" /bin/sh -c "echo $B64 | base64 -d | sh" \
  >"$OUT" 2>"$ERR" &
RUNPID=$!
echo "  carrick pid=$RUNPID (taskpolicy -b, nice 20, detached to files)"

# Supervisor: poll until a captured core is FULLY written, the workload finishes,
# carrick exits, or the deadline hits.
outcome="DEADLINE"
steps=$(( DEADLINE_S * 2 ))   # 0.5s cadence
n=0
while [ "$n" -lt "$steps" ]; do
  # A capture has started: lldb creates the core file, THEN streams memory into
  # it. So a core path existing means >=1 `sudo lldb process save-core` is running
  # right now. Killing carrick mid-dump truncates the core, so wait for ALL
  # save-core processes to drain (MAX_CORES>1 runs several concurrently) before
  # we reap the tree. Bounded to ~60s.
  if [ -n "$(new_cores)" ]; then
    w=0
    while [ "$w" -lt 120 ]; do
      pgrep -f "process save-core" >/dev/null 2>&1 || break
      sleep 0.5; w=$((w + 1))
    done
    outcome="DEADLOCK_CORE"; break
  fi
  if grep -q ALL_DONE "$OUT" 2>/dev/null; then outcome="ALL_DONE"; break; fi
  if ! kill -0 "$RUNPID" 2>/dev/null; then outcome="EXITED"; break; fi
  sleep 0.5
  n=$((n + 1))
done

# Kill the tree NOW (the EXIT trap also would, but be explicit + immediate).
cleanup

echo "OUTCOME=$outcome  (after ~$(( n / 2 ))s)"
echo "=== captured core(s) (new this run) ==="
nc="$(new_cores)"
if [ -n "$nc" ]; then echo "$nc" | while read -r c; do ls -lh "$c"; done; else echo "  none"; fi
echo "=== guest stdout ($OUT) ==="
cat "$OUT" 2>/dev/null
built=$(grep -c '^BUILT' "$OUT" 2>/dev/null || echo 0)
echo "=== ${built}/${N} builds finished; the rest hung in fork+exec ==="
echo "=== watchdog lines (err) ==="
grep -iE "DEADLOCK WATCHDOG|corefile created|detached" "$ERR" 2>/dev/null | head -8
