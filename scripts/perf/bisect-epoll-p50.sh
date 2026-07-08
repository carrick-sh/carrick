#!/bin/bash
# `git bisect run` predicate for the perf_epoll_pipe_loop p50 regression
# window 0572d32f..9baacd44 (good ≈33µs, bad ≈51µs; threshold 42µs on the
# median of 3 one-shot runs). Quiet host required; no concurrent lanes.
# EPOLL_PROBE must point at a probe binary built ONCE at HEAD (the guest
# binary is independent of the carrick commit under test).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
./scripts/build-signed.sh >/dev/null 2>&1 || exit 125   # unbuildable commit: skip
: "${EPOLL_PROBE:?set EPOLL_PROBE=/abs/path/to/perf_epoll_pipe_loop}"
runs=()
for i in 1 2 3; do
  p50=$(base64 -i "$EPOLL_PROBE" | CARRICK_RUN_ID="bisect-$$-$i" timeout 120 \
    target/release/carrick run ubuntu:24.04 --raw --fs host \
    /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p' 2>/dev/null \
    | awk -F= '/^epoll_pipe_loop_p50_us=/{print $2}')
  [ -n "$p50" ] || exit 125                             # run failed here: skip
  runs+=("$p50")
done
median=$(printf '%s\n' "${runs[@]}" | sort -n | sed -n 2p)
echo "bisect $(git rev-parse --short HEAD): p50 median ${median}us" >&2
awk -v m="$median" 'BEGIN { exit (m < 42.0) ? 0 : 1 }'
