#!/bin/sh
# External-capture variant of go-deadlock-capture.sh.
#
# Why: under `taskpolicy -b`, a hung guest's spinning vCPU threads starve its OWN
# in-process deadlock watchdog thread, so it never self-cores — observed: only
# the IDLE ns-supervisor's watchdog fired (and, post-fix, correctly DEFERRED),
# leaving the stuck go-build guest un-cored. So don't rely on the in-process
# self-core under throttle. Capture from the HARNESS instead: it runs at NORMAL
# priority OUTSIDE the throttled guest tree, so its `sudo lldb` attaches are never
# starved. On hang-detect it cores EVERY carrick process in the run (a bounded
# handful: supervisor + ns-init + the stuck go driver + its pre-exec child) and
# dumps each one's `thread backtrace all`, so the stuck guest (a vCPU thread mid
# guest-syscall, non-empty event ring) is guaranteed to be among them.
#
# The in-process watchdog is intentionally NOT armed here (no
# CARRICK_DEADLOCK_WATCHDOG_MS) — this harness is the sole capture mechanism.
#
# Usage: scripts/go-deadlock-capture-ext.sh [N] [STALL_S] [DEADLINE_S] [CPUS]
#   N          concurrent go builds                         (default 4)
#   STALL_S    builds remaining + no new BUILT this long => hang (default 15)
#   DEADLINE_S hard kill regardless                          (default 120)
#   CPUS       CARRICK_EXPOSED_CPUS cap, ""=host             (default "")
set -u

N="${1:-4}"
STALL_S="${2:-15}"
DEADLINE_S="${3:-120}"
CPUS="${4:-}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CARRICK="$REPO/target/release/carrick"
IMG="localhost:5005/carrick-go-conformance:1.24"
RUN="go-dlx-n${N}-$$"
OUT="/tmp/${RUN}.out"
ERR="/tmp/${RUN}.err"
OUTDIR="/tmp/${RUN}.cores"

[ -x "$CARRICK" ] || { echo "FATAL: no signed carrick at $CARRICK"; exit 2; }
command -v taskpolicy >/dev/null 2>&1 || { echo "FATAL: taskpolicy missing"; exit 2; }
sudo -n lldb --version >/dev/null 2>&1 || { echo "FATAL: passwordless 'sudo lldb' required"; exit 2; }

rm -f "$OUT" "$ERR" 2>/dev/null
mkdir -p "$OUTDIR"; rm -f "$OUTDIR"/* 2>/dev/null

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
  pkill -9 -f "$RUN" 2>/dev/null
  [ -n "$RUNPID" ] && kill -9 "$RUNPID" 2>/dev/null
  return 0
}
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT TERM

CPU_ENV=""
[ -n "$CPUS" ] && CPU_ENV="CARRICK_EXPOSED_CPUS=$CPUS"

echo "run=$RUN  N=$N  stall=${STALL_S}s  deadline=${DEADLINE_S}s  cpus=${CPUS:-host}"
echo "  cores+bt -> $OUTDIR"

# Throttle the GUEST (host protection). The harness stays at normal priority so
# its lldb attaches are never starved.
# shellcheck disable=SC2086
nice -n 20 taskpolicy -b \
  env CARRICK_INSECURE_REGISTRIES=localhost:5005 $CPU_ENV \
  "$CARRICK" run --name "$RUN" --raw --fs host -w /tmp \
  "$IMG" /bin/sh -c "echo $B64 | base64 -d | sh" \
  >"$OUT" 2>"$ERR" &
RUNPID=$!
echo "  carrick pid=$RUNPID (taskpolicy -b, nice 20); harness un-throttled"

# Hang detection: builds remain AND no new BUILT for STALL_S AND carrick alive.
last_built=0
stall_ticks=0
need_ticks=$(( STALL_S * 2 ))
n=0; steps=$(( DEADLINE_S * 2 )); outcome="DEADLINE"
while [ "$n" -lt "$steps" ]; do
  if grep -q ALL_DONE "$OUT" 2>/dev/null; then outcome="ALL_DONE"; break; fi
  if ! kill -0 "$RUNPID" 2>/dev/null; then outcome="EXITED"; break; fi
  # NOTE: `grep -c` already prints the count AND exits 1 on zero matches, so a
  # `|| echo 0` would append a SECOND "0" ("0\n0") and break the integer tests.
  b=$(grep -c '^BUILT' "$OUT" 2>/dev/null); [ -n "$b" ] || b=0
  if [ "$b" -ne "$last_built" ]; then last_built="$b"; stall_ticks=0; else stall_ticks=$((stall_ticks + 1)); fi
  if [ "$b" -lt "$N" ] && [ "$stall_ticks" -ge "$need_ticks" ]; then outcome="HANG"; break; fi
  sleep 0.5
  n=$((n + 1))
done

echo "DETECT=$outcome  built=${last_built}/${N}  (after ~$(( n / 2 ))s)"

if [ "$outcome" = "HANG" ]; then
  pids=$(pgrep -f "$RUN" 2>/dev/null | tr '\n' ' ')
  echo "run carrick pids: $pids"
  for p in $pids; do
    [ "$p" = "$RUNPID" ] && continue
    # %cpu helps later tell the SPINNING stuck guest from the idle supervisor.
    pcpu=$(ps -o %cpu= -p "$p" 2>/dev/null | tr -d ' ')
    echo "  -> coring pid=$p (%cpu=${pcpu:-?})"
    sudo -n lldb --batch -p "$p" \
      -o "process save-core --style modified-memory $OUTDIR/core-$p.core" \
      -o "thread backtrace all" \
      -o "detach" -o "quit" \
      > "$OUTDIR/bt-$p.txt" 2>&1
  done
fi

cleanup

echo "=== captured cores + backtraces ($OUTDIR) ==="
ls -lh "$OUTDIR"/ 2>/dev/null || echo "  none"
echo "=== guest stdout ==="
cat "$OUT" 2>/dev/null
