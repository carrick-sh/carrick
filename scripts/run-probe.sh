#!/usr/bin/env bash
# Run ONE conformance probe the EXACT way tests/conformance.rs does, under BOTH
# carrick and Docker linux/arm64, and diff — for fast, FAITHFUL single-probe
# iteration.
#
# Faithful = the same path the gate uses: the probe is base64'd onto the guest's
# stdin and decoded + exec'd via `/bin/sh -c` under `carrick run <image>` (the
# THREADED run-loop, shell-launched). `carrick run-elf <probe>` is a DIFFERENT,
# lighter path (bare rootfs, single-threaded) and can PASS a probe the gate
# FAILS (signal/timing/threading differences). Always verify a probe here, not
# just via run-elf.
#
# Usage: scripts/run-probe.sh <probe-name> [image]
#   image defaults to ubuntu:24.04 (what the conformance harness uses).
set -u
name="${1:?usage: run-probe.sh <probe-name> [image]}"
image="${2:-ubuntu:24.04}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
bin="$repo/conformance-probes/target/aarch64-unknown-linux-musl/release/$name"
carrick="$repo/target/release/carrick"
snippet='base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'
[ -x "$bin" ] || { echo "probe not built: $bin — run scripts/build-probes.sh"; exit 2; }
export CARRICK_INSECURE_REGISTRIES="${CARRICK_INSECURE_REGISTRIES:-localhost:5050}"

kill_guests() { sudo -n "$repo/scripts/sudo/kill.sh" >/dev/null 2>&1 || pkill -9 -f 'carrick:' 2>/dev/null; }

kill_guests; sleep 0.3
c=$(base64 -i "$bin" | timeout 60 "$carrick" run "$image" --raw --fs host /bin/sh -c "$snippet" 2>/dev/null \
    | grep -vE 'case-insensitive|Pass .--fs')
kill_guests
d=$(base64 -i "$bin" | docker run --rm -i --platform linux/arm64 "$image" /bin/sh -c "$snippet" 2>/dev/null)

if [ "$c" = "$d" ]; then
  echo "MATCH $name"
  printf '%s\n' "$c" | sed 's/^/  /'
else
  echo "DIFF $name (- linux  + carrick)"
  diff <(printf '%s\n' "$d") <(printf '%s\n' "$c") | sed 's/^/  /'
  exit 1
fi
