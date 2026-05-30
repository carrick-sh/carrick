#!/usr/bin/env bash
# Docker-native Go std-library conformance for carrick.
#
# Runs each package's prebuilt std-test binary through the drop-in `carrick run`
# CLI against the self-contained conformance image (built by
# docker/go-conformance/Dockerfile), which carries GOROOT + source + tzdata in
# its rootfs. Because the Go assets are served by the normal fs backend (not
# bind mounts), source-relative reads and timezone loading resolve correctly and
# the verdicts are TRUE carrick verdicts — no run-elf, no scratch loader tar, no
# bind-relative-resolution artifacts.
#
# Usage: scripts/go-conformance-image.sh [pkg ...]   (default: go-conformance-packages.txt)
#   RUN_TIMEOUT=120   per-package carrick timeout (seconds)
#   EXPOSED_CPUS=8    CARRICK_EXPOSED_CPUS for the guest
#   IMG=...           override the conformance image reference
set -uo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
carrick="$repo/target/release/carrick"
[ -x "$carrick" ] || { echo "carrick not built/signed: $carrick — run ./scripts/build-signed.sh" >&2; exit 2; }
IMG="${IMG:-localhost:5005/carrick-go-conformance:1.24}"
RUN_TIMEOUT="${RUN_TIMEOUT:-120}"
EXPOSED_CPUS="${EXPOSED_CPUS:-8}"
export CARRICK_INSECURE_REGISTRIES="${CARRICK_INSECURE_REGISTRIES:-localhost:5005}"

pkgs=("$@")
if [ ${#pkgs[@]} -eq 0 ]; then
  # bash 3.2 (macOS default) has no `mapfile`; read the package list portably.
  pkgs=()
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] && pkgs+=("$line")
  done < "$repo/scripts/go-conformance-packages.txt"
fi

logs="/tmp/go-img-conformance"; mkdir -p "$logs"
printf '%-14s %-8s %s\n' "PACKAGE" "RESULT" "DETAIL"
for p in "${pkgs[@]}"; do
  n=$(echo "$p" | tr / _); log="$logs/$n.log"
  # Per-package exclusions for ENVIRONMENTAL failures — ones that fail
  # identically under a plain Docker linux/arm64 run of the same binary, so they
  # are not carrick gaps. Each must be justified inline (differential oracle).
  skip=""
  case "$p" in
    os/signal)
      # TestTerminalSignal requires a controlling TTY and its own session; the
      # non-interactive harness (no `carrick run -t`) provides none. The same
      # binary fails under plain Docker linux/arm64 with
      # "fork/exec ...: operation not permitted", so this is environmental.
      skip="-test.skip=TestTerminalSignal" ;;
  esac
  # cwd = the package source dir so the test's relative file reads resolve;
  # cap output hard (some failures dump megabytes).
  CARRICK_EXPOSED_CPUS="$EXPOSED_CPUS" timeout -s KILL "$RUN_TIMEOUT" \
    "$carrick" run --raw -w "/usr/local/go/src/$p" "$IMG" \
    "/conformance/$n.test" -test.run Test -test.short $skip 2>&1 | head -c 200000 > "$log"
  # PIPESTATUS[0] is `timeout` (137 on SIGKILL); [1] is head. We want the former.
  rc=${PIPESTATUS[0]}
  if grep -aqE '^ok\b|^PASS$' "$log" && ! grep -aqE '^--- FAIL|^FAIL$|panic:|fatal error:' "$log"; then
    printf '%-14s %-8s\n' "$n" "PASS"
  elif grep -aqE 'panic:|fatal error:' "$log"; then
    sig=$(grep -aoE 'panic:.*|fatal error:.*' "$log" | head -1 | cut -c1-80)
    printf '%-14s %-8s %s\n' "$n" "CRASH" "$sig"
  elif [ "$rc" = "137" ]; then
    printf '%-14s %-8s %s\n' "$n" "TIMEOUT" "(>${RUN_TIMEOUT}s; see $log)"
  else
    fails=$(grep -aoE '^--- FAIL: [A-Za-z0-9_/]+' "$log" | sed 's/^--- FAIL: //' | tr '\n' ' ')
    printf '%-14s %-8s %s\n' "$n" "FAIL" "${fails:-see $log}"
  fi
done
