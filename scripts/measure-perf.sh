#!/usr/bin/env bash
# Differential perf benchmark: carrick vs Docker. Builds the signed binary and
# the probe set, then runs the perf_gate (serial, carrick-then-docker, never
# concurrent) and prints the resulting rows. Profiles tune rep count + cooldown
# via env so a quick smoke and a full baseline share one code path.
#
# Usage: scripts/measure-perf.sh [quick|full]          (default: quick)
#        scripts/measure-perf.sh backends [quick|full]
#        scripts/measure-perf.sh hvf-mailbox [quick|full]
set -euo pipefail
cd "$(dirname "$0")/.."
mode="perf"
if [[ "${1:-}" == "backends" ]]; then
  mode="backends"
  shift
elif [[ "${1:-}" == "hvf-mailbox" ]]; then
  mode="hvf-mailbox"
  shift
fi
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

if [[ "$mode" == "hvf-mailbox" ]]; then
  case "$profile" in
    quick) export CARRICK_HVF_MAILBOX_WARMUP_BLOCKS="${CARRICK_HVF_MAILBOX_WARMUP_BLOCKS:-1}"
           export CARRICK_HVF_MAILBOX_SAMPLE_BLOCKS="${CARRICK_HVF_MAILBOX_SAMPLE_BLOCKS:-2}" ;;
    full)  export CARRICK_HVF_MAILBOX_WARMUP_BLOCKS="${CARRICK_HVF_MAILBOX_WARMUP_BLOCKS:-10}"
           export CARRICK_HVF_MAILBOX_SAMPLE_BLOCKS="${CARRICK_HVF_MAILBOX_SAMPLE_BLOCKS:-30}" ;;
  esac
  export CARRICK_HVF_MAILBOX_COOLDOWN_SECS="${CARRICK_HVF_MAILBOX_COOLDOWN_SECS:-1}"
fi

echo "==> building signed carrick"
./scripts/build-signed.sh
echo "==> building probes"
if [[ "$mode" == "backends" ]]; then
  ./scripts/build-probes.sh --native-pie >/dev/null
elif [[ "$mode" == "hvf-mailbox" ]]; then
  ./scripts/build-probes.sh --native-pie-musl >/dev/null
fi
if [[ "$mode" == "backends" ]]; then
  export CARRICK_BACKEND_REPORT="${CARRICK_BACKEND_REPORT:-docs/perf-results/$(date +%F)-native16k-hvf.jsonl}"
  echo "==> running backend_pair_report (profile=$profile cycles=$CARRICK_PERF_REPS)"
  cargo test -p carrick-cli --test perf_runner backend_pair_report -- --nocapture --ignored
  echo "==> backend report: $CARRICK_BACKEND_REPORT"
  tail -n 4 "$CARRICK_BACKEND_REPORT"
  exit 0
fi
if [[ "$mode" == "hvf-mailbox" ]]; then
  if ps -axo command= | grep -E 'carrick:[^:]+:' | grep -v grep >/dev/null; then
    echo "active carrick guest detected; refusing to contaminate mailbox campaign" >&2
    exit 1
  fi
  if command -v docker >/dev/null 2>&1; then
    active_docker=$(docker ps --format '{{.Image}}' 2>/dev/null | grep -v '^registry:' || true)
    if [ -n "$active_docker" ]; then
      echo "active non-registry Docker container detected; refusing to co-run the HVF campaign" >&2
      printf '%s\n' "$active_docker" >&2
      exit 1
    fi
  fi
  run_id="mailbox-perf-$$"
  export CARRICK_HVF_MAILBOX_RUN_ID="$run_id"
  export CARRICK_HVF_MAILBOX_REPORT="${CARRICK_HVF_MAILBOX_REPORT:-docs/perf-results/$(date +%F)-hvf-syscall-mailbox.jsonl}"
  cleanup() { sudo -n "$PWD/scripts/sudo/kill.sh" "$run_id"; }
  trap cleanup EXIT INT TERM
  echo "==> power state"
  pmset -g batt
  echo "==> signed identity"
  codesign -dv --verbose=2 target/release/carrick 2>&1 | grep -E '^(Identifier|TeamIdentifier|Signature)='
  echo "==> running hvf_mailbox_report (profile=$profile warmup_blocks=$CARRICK_HVF_MAILBOX_WARMUP_BLOCKS sample_blocks=$CARRICK_HVF_MAILBOX_SAMPLE_BLOCKS)"
  cargo test -p carrick-cli --test perf_runner hvf_mailbox_report -- --nocapture --ignored
  echo "==> mailbox report: $CARRICK_HVF_MAILBOX_REPORT"
  tail -n 4 "$CARRICK_HVF_MAILBOX_REPORT"
  exit 0
fi
./scripts/build-probes.sh >/dev/null
echo "==> building native (macos) probes"
( cd bench-native && cargo build --release ) >/dev/null
echo "==> running perf_gate (profile=$profile reps=$CARRICK_PERF_REPS)"
cargo test -p carrick-cli --test perf_runner perf_gate -- --nocapture --include-ignored

echo "==> latest result rows:"
latest="$(ls -t docs/perf-results/*.jsonl 2>/dev/null | head -1 || true)"
[ -n "$latest" ] && tail -n 4 "$latest" || echo "(no rows written)"
