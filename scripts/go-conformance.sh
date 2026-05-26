#!/usr/bin/env bash
# Differential Go std-test conformance: carrick vs Docker linux/arm64.
#
# Builds Go std-library test binaries with the carrick-compatible recipe
# (external-static-pie), runs each under carrick AND under a Docker arm64
# container with identical args, and reports tests that PASS under Docker but
# FAIL (or are absent) under carrick — the actionable correctness gap.
# Environmental failures appear in both and cancel.
#
# Usage: scripts/go-conformance.sh [pkg ...]   (default: scripts/go-conformance-packages.txt)
#   RUN_TIMEOUT=120  per-binary carrick timeout (seconds)
set -uo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache="/tmp/go-conformance"; mkdir -p "$cache/bin" "$cache/logs"
carrick="$repo/target/release/carrick"
RUN_TIMEOUT="${RUN_TIMEOUT:-120}"
# Tests that need host infra neither carrick nor the Docker oracle can provide:
# a separate ptrace tracer process (gdb/lldb), a C toolchain (cgo), or the test's
# own Go source tree (tracebacksystem). They HANG or panic-abort the test binary
# rather than FAIL cleanly, so the binary would burn the full RUN_TIMEOUT and
# every downstream test would look "absent" (the bogus runtime "277"). Skipped on
# BOTH sides so the carrick-vs-Docker diff stays fair. Override via SKIP=.
# NOTE: TestDebugCall is NOT here — despite the name it uses no ptrace (in-process
# tgkill(SIGTRAP) + an in-guest BRK #0); carrick delivers guest BRK as SIGTRAP
# (see docs/ptrace-darwin-design.md Phase 1), so it runs and passes on both sides.
# TestGoLookupIPCNAMEOrderHostsAliasesFilesDNSMode hangs IDENTICALLY on carrick AND
# the Docker linux/arm64 oracle (same goroutine stack: goLookupIPCNAMEOrder blocked
# on a result chan, dnsclient_unix.go:683) — it needs reachable real DNS that
# neither sandbox provides. A test-timeout panic kills the whole net.test binary,
# so leaving it in falsely marks every later test "absent" on BOTH sides. Skipping
# it un-truncates net (Docker 52→149 PASS) and keeps the diff fair.
SKIP="${SKIP:-TestGdb|TestLldb|TestCgo|TestTracebackSystem|TestGoLookupIPCNAMEOrderHostsAliasesFilesDNSMode}"
# Per-binary Go test timeout: a hung/slow test (e.g. net's DNS lookups) aborts
# itself with a goroutine dump well before the carrick hard-kill, so a stuck
# binary no longer burns the whole RUN_TIMEOUT. Kept comfortably under it.
TEST_TIMEOUT=$(( RUN_TIMEOUT > 60 ? RUN_TIMEOUT - 30 : RUN_TIMEOUT ))

# Portable package-list load: macOS ships bash 3.2 which has no `mapfile`, and
# `set -u` errors on an empty `${arr[@]}`, so seed the array with a sentinel and
# strip it after reading (works on bash 3.2 and 4+).
pkgs=("$@")
if [ ${#pkgs[@]} -eq 0 ]; then
  pkgs=("")
  while IFS= read -r _line || [ -n "$_line" ]; do
    [ -n "$_line" ] && pkgs+=("$_line")
  done < "$repo/scripts/go-conformance-packages.txt"
  pkgs=("${pkgs[@]:1}") # drop the seed
fi

build() {
  local need=()
  for p in "${pkgs[@]}"; do
    local n; n=$(echo "$p" | tr / _)
    [ -x "$cache/bin/$n.test" ] || need+=("$p")
  done
  [ ${#need[@]} -eq 0 ] && return 0
  echo "building: ${need[*]}"
  docker run --rm --platform linux/arm64 -v "$cache/bin":/out golang:1.24-bookworm sh -c '
    for p in '"${need[*]}"'; do
      n=$(echo "$p" | tr / _)
      CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go test -c -buildmode=pie \
        -ldflags "-linkmode external -extldflags -static-pie" -o /out/$n.test "$p" \
        && echo "  built $n.test" || echo "  BUILD FAIL $p"
    done
    chmod -R a+rwx /out'
}

# Extract "PASS <Test>" / "FAIL <Test>" verdict lines.
verdicts() { grep -oE '^--- (PASS|FAIL): [A-Za-z0-9_/]+' "$1" \
  | sed -E 's/^--- (PASS|FAIL): /\1 /' | sort -u; }

build

total_gap=0
for p in "${pkgs[@]}"; do
  n=$(echo "$p" | tr / _); bin="$cache/bin/$n.test"
  if [ ! -x "$bin" ]; then
    echo "[$p] NO BINARY (build failed) — gap"; total_gap=$((total_gap+1)); continue
  fi

  docker run --rm --platform linux/arm64 -v "$cache/bin":/b -w /b debian:stable-slim \
    "./$n.test" -test.run 'Test' -test.skip "$SKIP" -test.short -test.v \
    -test.timeout "${TEST_TIMEOUT}s" > "$cache/logs/$n.docker" 2>&1

  pkill -9 -f "carrick run-elf" 2>/dev/null
  CARRICK_EXPOSED_CPUS=10 timeout -s KILL "$RUN_TIMEOUT" "$carrick" run-elf --raw --fs host \
    "$bin" -- -test.run 'Test' -test.skip "$SKIP" -test.short -test.v \
    -test.timeout "${TEST_TIMEOUT}s" > "$cache/logs/$n.carrick" 2>&1
  pkill -9 -f "carrick run-elf" 2>/dev/null

  gap=$(comm -23 <(verdicts "$cache/logs/$n.docker"  | grep '^PASS ' | awk '{print $2}' | sort -u) \
                 <(verdicts "$cache/logs/$n.carrick" | grep '^PASS ' | awk '{print $2}' | sort -u))
  dpass=$(verdicts "$cache/logs/$n.docker"  | grep -c '^PASS ')
  cpass=$(verdicts "$cache/logs/$n.carrick" | grep -c '^PASS ')
  # Did carrick itself abort mid-run (guest died, not a Go test FAIL)? Then the
  # remaining tests are absent (false gaps) — report the crash + the test it
  # died on (the one after the last PASS), which is the real single root cause.
  crash=$(grep -m1 -oE 'failed to run static ELF|fault not handled by trap path|UnexpectedException|trap engine failed' "$cache/logs/$n.carrick")
  if [ -n "$crash" ]; then
    diedon=$(grep -E '^(=== RUN|--- PASS)' "$cache/logs/$n.carrick" | tail -1 | grep -oE '[A-Za-z0-9_/]+$')
    esr=$(grep -m1 -oE 'esr=0x[0-9a-f]+' "$cache/logs/$n.carrick")
    echo "[$p] docker=$dpass carrick=$cpass  CARRICK CRASH after '$diedon' ($crash $esr) — 1 root cause (+$([ -n "$gap" ] && echo "$gap" | grep -c . || echo 0) absent)"
    total_gap=$((total_gap+1))
    continue
  fi
  if [ -n "$gap" ]; then
    ngap=$(echo "$gap" | grep -c .)
    echo "[$p] docker=$dpass carrick=$cpass  CARRICK-ONLY FAILURES ($ngap):"
    echo "$gap" | sed 's/^/    /'
    total_gap=$((total_gap+ngap))
  else
    echo "[$p] docker=$dpass carrick=$cpass  OK (no carrick-only failures)"
  fi
done
echo "=== TOTAL carrick-only failures: $total_gap ==="
exit $([ "$total_gap" -eq 0 ] && echo 0 || echo 1)
