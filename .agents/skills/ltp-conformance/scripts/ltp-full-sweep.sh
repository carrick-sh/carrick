#!/bin/bash
# FULL LTP syscall-suite sweep: every unique binary referenced by
# runtest/syscalls (~1427), run BARE (no args) under both the Docker oracle and
# carrick, verdicts diffed. Companion to ltp-sweep.sh (the curated 4-area
# subset, ~192). Use this to get the FULL gap denominator for goal-setting.
#
# Bare-binary caveat: some arg-driven tests TCONF/print-usage without their
# runtest args — call those "not exercised", not "passing" (see the skill's
# "Reading results honestly").
#
# Hardening (same rationale as ltp-sweep.sh): carrick stdout -> FILE per test,
# force-kill `carrick:` guests before+after each run (a wedged vCPU holding the
# stdout pipe would otherwise hang the whole sweep), host-side timeout. The
# Docker oracle runs as ONE in-container loop (no vCPU-wedge risk) for speed and
# in parallel with the carrick pass.
#
# Output dir $OUT (default /tmp/ltp-full-<date>); resumable — re-running skips
# tests already in carrick.tsv:
#   tests.txt   — the test list
#   docker.tsv  — "<test>\t<verdict>"
#   carrick.tsv — "<test>\t<verdict>"  (appended live)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
CARRICK="${CARRICK:-$REPO/target/release/carrick}"
IMAGE="${IMAGE:-localhost:5050/ltp:arm64}"
DOCKER_IMAGE="${DOCKER_IMAGE:-ltp:arm64}"
KILL="${KILL:-$REPO/scripts/sudo/kill.sh}"
export CARRICK_INSECURE_REGISTRIES="${CARRICK_INSECURE_REGISTRIES:-localhost:5050}"
TC="${TC:-15}"   # carrick per-test timeout (s)
TD="${TD:-15}"   # docker per-test timeout (s)
OUT="${OUT:-/tmp/ltp-full-$(date +%Y%m%d)}"; mkdir -p "$OUT"

verdict() {  # $1 = file
  local f="$1" s p fa b c
  s=$(grep -oE "passed +[0-9]+|failed +[0-9]+|broken +[0-9]+" "$f" 2>/dev/null | tr '\n' ' ' | tr -s ' ')
  if [ -n "$s" ]; then echo "$s"; return; fi
  p=$(grep -c "TPASS" "$f" 2>/dev/null); fa=$(grep -c "TFAIL" "$f" 2>/dev/null)
  b=$(grep -c "TBROK" "$f" 2>/dev/null); c=$(grep -c "TCONF" "$f" 2>/dev/null)
  [ "$p$fa$b$c" = "0000" ] && { echo ""; return; }
  echo "P$p F$fa B$b C$c"
}

# 1. test list — unique real syscall-test binaries from runtest/syscalls.
if [ ! -s "$OUT/tests.txt" ]; then
  docker run --rm --platform linux/arm64 "$DOCKER_IMAGE" sh -c \
    "grep -vE '^#|^[[:space:]]*\$' /opt/ltp/runtest/syscalls | awk '{print \$2}' | sort -u" \
    > "$OUT/tests.txt"
fi
ntests=$(wc -l < "$OUT/tests.txt" | tr -d ' ')
echo "[full-sweep] $ntests tests -> $OUT (TC=${TC}s TD=${TD}s)"

# 2. Docker oracle pass — one container, in-loop timeout, runs in background.
if [ ! -s "$OUT/docker.tsv" ]; then
  docker run --rm --platform linux/arm64 -v "$OUT/tests.txt:/tests.txt:ro" "$DOCKER_IMAGE" sh -c '
    while read t; do
      b="/opt/ltp/testcases/bin/$t"
      [ -x "$b" ] || { printf "%s\t%s\n" "$t" "MISSING"; continue; }
      o=$(timeout '"$TD"' "$b" 2>&1); rc=$?
      v=$(printf "%s" "$o" | grep -oE "passed +[0-9]+|failed +[0-9]+|broken +[0-9]+" | tr "\n" " " | tr -s " ")
      [ -z "$v" ] && v="P$(printf "%s" "$o"|grep -c TPASS) F$(printf "%s" "$o"|grep -c TFAIL) B$(printf "%s" "$o"|grep -c TBROK) C$(printf "%s" "$o"|grep -c TCONF)"
      [ $rc -eq 124 ] || [ $rc -eq 137 ] && v="TIMEOUT/$v"
      printf "%s\t%s\n" "$t" "$v"
    done < /tests.txt' > "$OUT/docker.tsv" 2>"$OUT/docker.err" &
  DOCKER_PID=$!
  echo "[full-sweep] docker oracle pass started (pid $DOCKER_PID)"
fi

# 3. carrick pass — serial, one guest per test, resumable.
touch "$OUT/carrick.tsv"
i=0
while read t; do
  i=$((i+1))
  cut -f1 "$OUT/carrick.tsv" | grep -qx "$t" && continue   # resume
  sudo -n "$KILL" >/dev/null 2>&1
  : > "$OUT/c.out"
  timeout -s KILL "$TC" "$CARRICK" run "$IMAGE" --raw --fs host /bin/sh -c "/opt/ltp/testcases/bin/$t" > "$OUT/c.out" 2>&1
  rc=$?
  sudo -n "$KILL" >/dev/null 2>&1
  grep -vE "case-insensitive|Pass .--fs" "$OUT/c.out" > "$OUT/c.clean"
  v=$(verdict "$OUT/c.clean")
  { [ $rc -eq 124 ] || [ $rc -eq 137 ]; } && v="TIMEOUT/$v"
  [ -z "$v" ] && v="(none)"
  printf "%s\t%s\n" "$t" "$v" >> "$OUT/carrick.tsv"
  [ $((i % 50)) -eq 0 ] && echo "[full-sweep] carrick $i/$ntests"
done < "$OUT/tests.txt"

wait
echo "[full-sweep] DONE. docker=$(wc -l <"$OUT/docker.tsv"|tr -d ' ') carrick=$(wc -l <"$OUT/carrick.tsv"|tr -d ' ')"
