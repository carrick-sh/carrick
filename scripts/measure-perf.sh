#!/usr/bin/env bash
# Differential perf benchmark: carrick vs Docker. Builds the signed binary and
# the probe set, then runs the perf_gate (serial, carrick-then-docker, never
# concurrent) and prints the resulting rows. Profiles tune rep count + cooldown
# via env so a quick smoke and a full baseline share one code path.
#
# Usage: scripts/measure-perf.sh [quick|full]   (default: quick)
set -euo pipefail
cd "$(dirname "$0")/.."
profile="${1:-quick}"

case "$profile" in
  quick) export CARRICK_PERF_REPS="${CARRICK_PERF_REPS:-5}"
         export CARRICK_PERF_WARMUP="${CARRICK_PERF_WARMUP:-1}"
         export CARRICK_PERF_COOLDOWN_SECS="${CARRICK_PERF_COOLDOWN_SECS:-15}" ;;
  full)  export CARRICK_PERF_REPS="${CARRICK_PERF_REPS:-10}"
         export CARRICK_PERF_WARMUP="${CARRICK_PERF_WARMUP:-2}"
         export CARRICK_PERF_COOLDOWN_SECS="${CARRICK_PERF_COOLDOWN_SECS:-15}" ;;
  *) echo "unknown profile: $profile (use quick|full)"; exit 2 ;;
esac

echo "==> building signed carrick"
./scripts/build-signed.sh
echo "==> building probes"
./scripts/build-probes.sh >/dev/null
echo "==> building native (macos) probes"
( cd bench-native && cargo build --release ) >/dev/null
echo "==> running perf_gate (profile=$profile reps=$CARRICK_PERF_REPS)"
cargo test -p carrick-cli --test perf_runner perf_gate -- --nocapture --include-ignored

echo "==> latest result rows:"
latest="$(ls -t docs/perf-results/*.jsonl 2>/dev/null | head -1 || true)"
[ -n "$latest" ] && tail -n 4 "$latest" || echo "(no rows written)"
