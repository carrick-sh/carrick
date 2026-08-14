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
[ -x "$carrick" ] || { echo "carrick not built/signed: $carrick — run ./scripts/build-signed.sh"; exit 2; }
snippet='base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'
# Identity probes that assert namespace-init semantics need the probe itself,
# not the decoding shell, to remain PID 1 on both Carrick and Docker. Keep the
# default byte-for-byte faithful to the conformance harness; opt in explicitly.
if [ "${CARRICK_PROBE_EXEC_AS_INIT:-0}" = "1" ]; then
    snippet='base64 -d > /tmp/p && chmod +x /tmp/p && exec /tmp/p'
fi
[ -x "$bin" ] || { echo "probe not built: $bin — run scripts/build-probes.sh"; exit 2; }
export CARRICK_INSECURE_REGISTRIES="${CARRICK_INSECURE_REGISTRIES:-localhost:5050}"

# Per-run id stamped into every carrick guest's title (inherited across forks),
# so cleanup reaps ONLY this invocation's guests — run-probe is now safe to run
# concurrently (parallel probe iteration) without lanes killing each other.
RUN_ID="cr-$$-${RANDOM}"
export CARRICK_RUN_ID="$RUN_ID"
echo "CARRICK_PROBE_RUN_ID=$RUN_ID" >&2
kill_guests() {
    sudo -n "$repo/scripts/sudo/kill.sh" "$RUN_ID" >/dev/null 2>&1 \
        || pkill -9 -f "carrick:$RUN_ID:" 2>/dev/null  # trailing ':' anchors the id
}

cleanup_with_receipt() {
    cleanup_output=$(sudo -n "$repo/scripts/sudo/kill.sh" "$RUN_ID" 2>&1)
    cleanup_status=$?
    if [ "$cleanup_status" -ne 0 ]; then
        pkill -9 -f "carrick:$RUN_ID:" 2>/dev/null || true
        cleanup_output="$cleanup_output
fallback scoped pkill issued"
    fi
    printf 'CARRICK_PROBE_CLEANUP_RUN_ID=%s\n%s\n' "$RUN_ID" "$cleanup_output" >&2
    if [ -n "${CARRICK_PROBE_RECEIPT:-}" ]; then
        printf 'CARRICK_PROBE_RUN_ID=%s\nCARRICK_PROBE_CLEANUP_RUN_ID=%s\n%s\n' \
            "$RUN_ID" "$RUN_ID" "$cleanup_output" >"$CARRICK_PROBE_RECEIPT"
    fi
    return "$cleanup_status"
}

kill_guests; sleep 0.3
c=$(base64 -i "$bin" | timeout 60 "$carrick" run "$image" --raw --fs host /bin/sh -c "$snippet" 2>/dev/null \
    | grep -vE 'case-insensitive|Pass .--fs')
cleanup_with_receipt || exit 3
d=$(base64 -i "$bin" | docker run --rm -i --platform linux/arm64 "$image" /bin/sh -c "$snippet" 2>/dev/null)

if [ "$c" = "$d" ]; then
  echo "MATCH $name"
  printf '%s\n' "$c" | sed 's/^/  /'
else
  echo "DIFF $name (- linux  + carrick)"
  diff <(printf '%s\n' "$d") <(printf '%s\n' "$c") | sed 's/^/  /'
  exit 1
fi
