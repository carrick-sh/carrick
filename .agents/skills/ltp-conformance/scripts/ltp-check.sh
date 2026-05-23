#!/bin/bash
# Differential LTP check: run each named test under Docker (the real-Linux
# oracle) AND under carrick, and diff the verdicts. Usage:
#   ltp-check.sh pause01 futex_wake03 setitimer01 ...
#
# Verdict (the subtle part — see SKILL.md "Reading results honestly"):
# prefer the new-API "Summary: passed/failed/broken" block; fall back to
# counting old-API per-line TPASS/TFAIL/TBROK/TCONF (those tests print NO
# Summary, so summary-only would false-MATCH them as both-empty). A 124 exit
# from `timeout` is surfaced as TIMEOUT (a hang — the worst class).
#
# NOTE: this is a count-based verdict, good for DISCOVERY. It does NOT prove the
# SAME assertions passed — for a canonical/critical test, also eyeball the
# per-line TPASS/TFAIL or (better) reduce it to a deterministic conformance
# probe (line-exact). Flaky/timing tests: run a few times before believing it.
set -u
CARRICK="${CARRICK:-/Volumes/CaseSensitive/carrick/target/release/carrick}"
KILL="${KILL:-/Volumes/CaseSensitive/carrick/scripts/sudo/kill.sh}"
IMAGE="${IMAGE:-localhost:5050/ltp:arm64}"
export CARRICK_INSECURE_REGISTRIES="${CARRICK_INSECURE_REGISTRIES:-localhost:5050}"

verdict() {
  local f="$1"
  local s
  s=$(grep -oE "passed +[0-9]+|failed +[0-9]+|broken +[0-9]+" "$f" 2>/dev/null | tr '\n' ' ' | tr -s ' ')
  if [ -n "$s" ]; then echo "$s"; return; fi
  local p fa b c
  p=$(grep -c "TPASS" "$f" 2>/dev/null); fa=$(grep -c "TFAIL" "$f" 2>/dev/null)
  b=$(grep -c "TBROK" "$f" 2>/dev/null); c=$(grep -c "TCONF" "$f" 2>/dev/null)
  [ "$p$fa$b$c" = "0000" ] && { echo ""; return; }
  echo "P$p F$fa B$b C$c"
}

m=0; d=0
for t in "$@"; do
  docker run --rm --platform linux/arm64 ltp:arm64 \
    sh -c "/opt/ltp/testcases/bin/$t 2>&1" 2>/dev/null > /tmp/ltpck_d.out
  D=$(verdict /tmp/ltpck_d.out)
  sudo -n "$KILL" >/dev/null 2>&1
  : > /tmp/ltpck_c.out
  timeout 40 "$CARRICK" run "$IMAGE" --raw --fs host /bin/sh -c "/opt/ltp/testcases/bin/$t" > /tmp/ltpck_c.out 2>&1
  rc=$?
  sudo -n "$KILL" >/dev/null 2>&1
  grep -vE "case-insensitive|Pass .--fs" /tmp/ltpck_c.out > /tmp/ltpck_c.clean
  C=$(verdict /tmp/ltpck_c.clean)
  [ $rc -eq 124 ] && C="TIMEOUT/$C"
  if [ "$D" = "$C" ]; then m=$((m+1)); tag="MATCH"; else d=$((d+1)); tag="DIFF "; fi
  printf "%s %-22s docker[%s] carrick[%s]\n" "$tag" "$t" "$D" "$C"
done
echo "---- MATCH=$m DIFF=$d ----"
