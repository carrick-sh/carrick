#!/usr/bin/env bash
# Two-process signed smoke for the crate-extraction plan. A single-process
# guest cannot see a scope bug; this runs fork + pipe + kill + wait + procfs
# under the signed binary and fails on any deviation. Not an oracle gate.
set -euo pipefail
cd "$(dirname "$0")/../.."
bin=target/release/carrick
[ -x "$bin" ] || { echo "build with just build first"; exit 2; }
export CARRICK_RUN_ID="${CARRICK_RUN_ID:-smoke2p-$$}"
out="$("$bin" run --rm ubuntu:24.04 sh -c '
  set -e
  ( sleep 5 ) & child=$!
  kill -TERM $child; wait $child && rc=0 || rc=$?
  echo child_rc=$rc
  echo hello | ( read -r x; echo pipe=$x )
  head -1 /proc/self/status | cut -f1
  ls /proc | grep -c "^[0-9]" | sed "s/^/procs=/"
  mkdir -p /tmp/x && echo data > /tmp/x/f && cat /tmp/x/f
' 2>&1)"
echo "$out"
grep -q '^child_rc=143$' <<<"$out"
grep -q '^pipe=hello$' <<<"$out"
grep -q '^Name:' <<<"$out"
grep -Eq '^procs=[1-9]' <<<"$out"
grep -q '^data$' <<<"$out"
echo "smoke-two-process: ok"
