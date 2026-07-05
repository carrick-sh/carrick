#!/usr/bin/env bash
# vcpu-admission-gate.sh — gate the HVF vcpu-admission machinery (physical-core
# cap, host-wide 4-VM file-lock permit, whole-VM park/reclaim) against the
# many-thread/fork workloads the maintainer's notes call fragile.
#
# Why this exists: the vcpu-admission retune (physical-core cap ~60 -> ~10, a
# host-wide 4-VM permit, whole-VM park/reclaim) was validated only against LTP.
# LTP is mostly single/few-threaded per test; it never exercised a 100-thread
# CPython test, a Node worker_threads pool, or Go's concurrent fork+exec path —
# exactly the workloads documented elsewhere in this repo as fragile around
# HVF vCPU lifecycle. This script is a MEASUREMENT gate: it runs those four
# fixtures once, serialized (--workers 1, so the admission budget under test
# isn't perturbed by concurrent lanes), and reports MATCH/DIFF/TIMEOUT/CRASH
# per suite. It does not change any runtime/admission code, and it does not
# attempt to fix a red result — see docs/superpowers/plans/
# 2026-07-05-conformance-direction-remediation.md Phase 3 Task 3.1.
#
# Suites (verified present in scripts/conformance/suites.toml):
#   cpython-queue    - python3 -m test -v --randseed 0 test_queue
#                      (includes test_many_threads: 100 threads)
#   node-v8-smoke    - worker_threads (v8-smoke)
#   node-app-smoke   - worker_threads (app-smoke)
#   go-os_exec       - TestConcurrentExec (heavy concurrent fork+exec;
#                      historically a HV_BUSY trigger)
# These are heavy suites (cpython-queue timeout_s ~300, go-os_exec ~180) —
# a full run is 10-25 minutes; let it finish.
#
# apt has no conformance fixture. This script only ECHOES the manual repro
# command — it does not run apt (a real network package install doesn't
# belong in an automated, unattended gate).
#
# Usage:
#   scripts/conformance/vcpu-admission-gate.sh [OUT.jsonl]
#     OUT.jsonl defaults to /tmp/carrick-vcpu-gate.jsonl
#
# Exit status: 0 iff all 4 suites verdict == match. Non-zero otherwise (a
# suite that failed to run/report is treated as a failure, not skipped).

set -euo pipefail
cd "$(dirname "$0")/../.."

OUT="${1:-/tmp/carrick-vcpu-gate.jsonl}"
SUITES=(cpython-queue node-v8-smoke node-app-smoke go-os_exec)

log() { printf '[vcpu-admission-gate] %s\n' "$*" >&2; }

log "building signed carrick binary (unsigned -> HV_DENIED on every run)"
just build >&2

log "running conformance gate over: ${SUITES[*]} (--workers 1 --flake-retries 0)"
SUITE_ARGS=()
for s in "${SUITES[@]}"; do
    SUITE_ARGS+=(--suite "$s")
done

# The harness's own exit code already reflects gating verdicts, but we derive
# our pass/fail independently below (scoped to exactly these 4 suites) so this
# gate's exit status is unambiguous regardless of unrelated harness exit-code
# semantics (e.g. --max-gating early-abort).
set +e
cargo run -p carrick-conformance -- \
    --tier full --workers 1 --flake-retries 0 \
    "${SUITE_ARGS[@]}" \
    --jsonl "$OUT"
harness_status=$?
set -e
log "carrick-conformance exited $harness_status (informational; see table below for the gate verdict)"

if [ ! -s "$OUT" ]; then
    log "ERROR: $OUT is missing or empty — the harness did not produce results"
    exit 1
fi

log "verdicts:"
printf '%-16s %-12s %10s  %s\n' "suite" "verdict" "ratio" "carrick_ms"
gate_fail=0
for s in "${SUITES[@]}"; do
    row=$(python3 - "$OUT" "$s" <<'PY'
import json, sys
out, name = sys.argv[1], sys.argv[2]
rep = None
with open(out) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("name") == name:
            rep = r  # last occurrence wins (flake-retry re-adopts)
if rep is None:
    print("MISSING\t-\t-")
else:
    verdict = rep.get("verdict", "MISSING")
    perf = rep.get("perf") or {}
    ratio = perf.get("carrick_to_oracle_ratio")
    ms = perf.get("carrick_ms")
    print(f"{verdict}\t{ratio if ratio is not None else '-'}\t{ms if ms is not None else '-'}")
PY
)
    IFS=$'\t' read -r verdict ratio ms <<<"$row"
    printf '%-16s %-12s %10s  %s\n' "$s" "$verdict" "$ratio" "$ms"
    if [ "$verdict" != "match" ]; then
        gate_fail=1
    fi
done

log "NOTE: apt has no conformance fixture — manual repro (best-effort, not gated):"
log "  just run run --raw --fs host ubuntu:24.04 apt-get install -y hello   # expect exit 0"

if [ "$gate_fail" -ne 0 ]; then
    log "GATE FAILED: at least one of the 4 workloads did not verdict=match — see $OUT"
    exit 1
fi

log "GATE PASSED: all 4 workloads verdict=match"
