#!/usr/bin/env bash
# Attribution round for the live-arena policy-ON overhead.
#
# Produces the receipts behind
# `docs/perf-results/2026-08-06-live-arena-36x-attribution.md`. Kept because
# a capture driver is the reproducible half of an attribution: the doc's
# tables cannot be re-derived without re-running these exact three phases in
# this exact order on a quiet host.
#
#   scripts/perf/live-arena-attribution-capture.sh {anchor|counters|wall}
#
# Read the evidence doc's appendix for the analysis side (it reuses
# scripts/perf/native_wall_attribution.py; there is no second parser).
#
# MEASURE-ONLY. Three phases, each with a settled quiet-host preflight receipt:
#   A  untraced anchor pair (ON, OFF)              -- the ratio on THIS binary
#   C  counter pair (CARRICK_DSR_PROFILE=1)        -- per-op denominators
#   W  native-wall captures (ON bounded, OFF)      -- the wall/CPU/lock split
#
# Traced runs are perturbed: shares are the claim, walls are not.
set -uo pipefail
cd "$(dirname "$0")/../../.."
BIN=target/release/carrick
OUT=${CARRICK_ATTR_OUT:-target/perf/attr36}
LOG="$OUT/capture.log"
IMAGE=localhost:5005/carrick-go-conformance:1.24
say() { echo "$@" | tee -a "$LOG"; }

GUEST='set -eu; cd /tmp; rm -rf gc-w; printf "package main\nfunc main(){println(\"ok\")}\n" > h.go; w0=$(date +%s%N); GOCACHE=/tmp/gc-w /usr/local/go/bin/go build -o h ./h.go; ./h; w1=$(date +%s%N); echo "WORKLOAD_NS=$((w1-w0))"; echo BUILD_OK'

say "=========================================================="
say "binary: $(shasum -a 256 $BIN | cut -d' ' -f1)"
say "source: $(git rev-parse HEAD) tree-clean=$([ -z "$(git status --porcelain)" ] && echo yes || echo no)"
say "host:   $(sw_vers -productVersion) $(sysctl -n machdep.cpu.brand_string) hw.logicalcpu=$(sysctl -n hw.logicalcpu)"
say "=========================================================="

preflight() {
  local tag="$1"
  local ycount ccount
  for _ in $(seq 1 180); do
    l=$(sysctl -n vm.loadavg | awk '{print int($2)}')
    [ "$l" -lt 4 ] && break
    sleep 5
  done
  ycount=$(pgrep -x yes | wc -l | tr -d ' ')
  ccount=$(ps -eo command | grep -ac '^carrick:' 2>/dev/null || true)
  say "$tag PREFLIGHT (settled): yes=$ycount carrick=$ccount loadavg=$(sysctl -n vm.loadavg)"
  if [ "$ycount" != 0 ] || [ "$ccount" != 0 ]; then
    say "$tag PREFLIGHT DIRTY -- aborting"
    exit 3
  fi
}

# $1 tag  $2 policy(off|compiler)  $3 mode(plain|counters|wall)  $4 bound_s
run_one() {
  local tag="$1" policy="$2" mode="$3" bound="${4:-}"
  export CARRICK_RUN_ID="attr36${tag}$$"
  preflight "$tag"
  say "===== $tag policy=$policy mode=$mode bound=${bound:-n/a} run_id=$CARRICK_RUN_ID ====="
  local t0 t1 rc
  t0=$(date +%s)
  (
    if [ "$policy" = off ]; then unset CARRICK_DSR_LIVE_ARENA
    else export CARRICK_DSR_LIVE_ARENA="$policy"; fi
    case "$mode" in
      counters) export CARRICK_DSR_PROFILE=1
                exec "$BIN" run --exec-backend native "$IMAGE" /bin/sh -c "$GUEST" ;;
      wall)     exec "$BIN" trace --profile native-wall --profile-bound-seconds "$bound" \
                  -o "$OUT/$tag.raw" --summary-jsonl "$OUT/$tag.jsonl" \
                  -- run --exec-backend native "$IMAGE" /bin/sh -c "$GUEST" ;;
      *)        exec "$BIN" run --exec-backend native "$IMAGE" /bin/sh -c "$GUEST" ;;
    esac
  ) > "$OUT/$tag.out" 2> "$OUT/$tag.err" &
  local W=$! done_flag=0
  for _ in $(seq 1 3000); do
    kill -0 "$W" 2>/dev/null || { done_flag=1; break; }
    sleep 1
  done
  t1=$(date +%s)
  if [ "$done_flag" = 1 ]; then
    wait "$W"; rc=$?
    say "$tag RESULT: exit=$rc wall_s=$((t1-t0)) out=[$(tr '\n' ' ' < "$OUT/$tag.out")]"
  else
    say "$tag RESULT: WEDGED after $((t1-t0))s"
    ps -eo pid,stat,etime,time,command | grep -a "carrick:$CARRICK_RUN_ID" | grep -v grep \
      | awk '{print "   ", $1, $2, "etime="$3, "cpu="$4}' | tee -a "$LOG"
  fi
  bash scripts/sudo/kill.sh "$CARRICK_RUN_ID" 2>&1 | tail -1 | tee -a "$LOG"
}

case "${1:-all}" in
  anchor)   run_one A1ON compiler plain; run_one A1OFF off plain
            run_one A2ON compiler plain; run_one A2OFF off plain ;;
  counters) run_one C1ON compiler counters; run_one C1OFF off counters ;;
  wall)     run_one W1OFF off wall 900; run_one W1ON compiler wall 3600 ;;
  *)        say "usage: capture.sh {anchor|counters|wall}"; exit 2 ;;
esac
say "PHASE DONE: ${1:-all}"
