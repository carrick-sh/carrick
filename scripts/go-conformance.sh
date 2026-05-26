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
cache="/tmp/go-conformance"; mkdir -p "$cache/bin" "$cache/logs" "$cache/run" "$cache/etc"
carrick="$repo/target/release/carrick"
RUN_TIMEOUT="${RUN_TIMEOUT:-120}"
# Packages that must run inside a COHERENT debian rootfs (via `carrick run
# <image>`) rather than the bare `--fs host` scratch, because they exercise the
# process/exec surface — PATH lookup of real binaries (echo, nohup), relative-
# name exec, and the test binary's own argv[0] needing real ancestor dirs —
# which only behaves like the Docker oracle when the binary, its cwd, and /bin
# all live in one filesystem. Fixes os/signal's TestDetectNohup (nohup
# resolves) and os/exec's TestString (echo on PATH) + TestCommandRelativeName
# (binary at /b with real ancestor dirs + the execve relative-path fix). The
# other packages stay on the faster bare-ELF path where they're conformant.
#
# os/exec was previously excluded: TestConcurrentExec's heavy concurrent
# fork+exec triggered the HV_BUSY multithreaded-fork race under the rootfs's
# heavier memory. The per-fork mincore fix (perf(fork): bound the snapshot scan
# to the arena high-water) cut fork cost ~10x and closed that race window;
# os/exec now runs 36/37 stably under the rootfs (3/3 runs, no crash). The lone
# remaining gap, TestExplicitPWD, is a cross-mount symlink/$PWD resolution gap.
ROOTFS_PKGS="${ROOTFS_PKGS:-os/signal os/exec}"
ROOTFS_IMAGE="${ROOTFS_IMAGE:-debian:stable-slim}"
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
    [ "$p" = "cgo-smoke" ] && continue # local fixture, built below
    local n; n=$(echo "$p" | tr / _)
    [ -x "$cache/bin/$n.test" ] || need+=("$p")
  done
  if [ ${#need[@]} -gt 0 ]; then
    echo "building: ${need[*]}"
    docker run --rm --platform linux/arm64 -v "$cache/bin":/out golang:1.24-bookworm sh -c '
      for p in '"${need[*]}"'; do
        n=$(echo "$p" | tr / _)
        CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go test -c -buildmode=pie \
          -ldflags "-linkmode external -extldflags -static-pie" -o /out/$n.test "$p" \
          && echo "  built $n.test" || echo "  BUILD FAIL $p"
      done
      chmod -R a+rwx /out'
  fi
  # cgo conformance smoke fixture (local source, not a std package): exercises
  # Go->C, C->Go callback, and C-pthread->Go callback — the cgo runtime paths.
  if printf '%s\n' "${pkgs[@]}" | grep -qx cgo-smoke && [ ! -x "$cache/bin/cgo-smoke.test" ]; then
    echo "building: cgo-smoke (fixture)"
    docker run --rm --platform linux/arm64 -v "$repo/scripts/cgo-smoke":/src -v "$cache/bin":/out \
      -w /src golang:1.24-bookworm sh -c \
      'CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go test -c -buildmode=pie \
         -ldflags "-linkmode external -extldflags -static-pie" -o /out/cgo-smoke.test . \
         && chmod a+rwx /out/cgo-smoke.test && echo "  built cgo-smoke.test"'
  fi
}

# Provision the test ENVIRONMENT both sides need so environmental failures don't
# pollute the differential: the std-lib `testdata/` trees (e.g. net needs
# `testdata/hosts`, `testdata/resolv.conf`, and `../testdata/Isaac.Newton-Opticks.txt`)
# and `/etc/services` (cgo/getservbyname). We mirror the Go `src/` layout under
# $cache/run so each test's relative `testdata/…` and `../testdata/…` resolve, and
# run every binary with CWD = that package's mirrored src dir. Both the Docker
# oracle (bind-mount + -w) and carrick (`cd` then --fs host) use the same tree, so
# the comparison stays fair while real (non-environmental) gaps still show.
provision() {
  echo "provisioning testdata + /etc/services from golang image"
  # Candidate testdata dirs: the shared src/testdata, each package's own, and its
  # parent's (the `../testdata` a nested package like os/exec references).
  local cand="src/testdata"
  local p parent
  for p in "${pkgs[@]}"; do
    cand="$cand src/$p/testdata"
    parent=$(dirname "$p")
    [ "$parent" != "." ] && cand="$cand src/$parent/testdata"
  done
  docker run --rm --platform linux/arm64 golang:1.24-bookworm sh -c '
    cd /usr/local/go
    avail=""
    for d in '"$cand"'; do [ -d "$d" ] && avail="$avail $d"; done
    [ -n "$avail" ] && tar cf - $avail || true' > "$cache/run/testdata.tar" 2>/dev/null
  tar xf "$cache/run/testdata.tar" -C "$cache/run" 2>/dev/null || true
  rm -f "$cache/run/testdata.tar"
  docker run --rm --platform linux/arm64 golang:1.24-bookworm cat /etc/services \
    > "$cache/etc/services" 2>/dev/null || true
  # IANA tz database for the `time` package. The test needs it in TWO places:
  #
  #  1. lib/time/zoneinfo.zip in the mirrored GOROOT tree. `time`'s init() calls
  #     ForceUSPacificForTesting() -> initTestingZone(), which "for hermeticity"
  #     deliberately ignores the system zoneinfo AND $ZONEINFO and loads only
  #     `../../lib/time/zoneinfo.zip` relative to its CWD (GOROOT/src/time). With
  #     CWD=/run/src/time that resolves to /run/lib/time/zoneinfo.zip. Absent it,
  #     init() panics and the WHOLE binary aborts before any test runs (0/0).
  #  2. /usr/share/zoneinfo (bind-mounted at run time). The non-hermetic tests
  #     call time.LoadLocation("Asia/Jerusalem", ...) which uses the platform
  #     zoneinfo sources; without it those tests fail. Mounting it lets them pass
  #     on both sides (richer coverage) AND exercises carrick's zoneinfo reads.
  #
  # debian:stable-slim (oracle) and carrick's --fs host scratch ship neither, so
  # we mirror both from the golang build image.
  if [ ! -f "$cache/run/lib/time/zoneinfo.zip" ]; then
    echo "provisioning lib/time/zoneinfo.zip into the GOROOT tree"
    mkdir -p "$cache/run/lib/time"
    docker run --rm --platform linux/arm64 golang:1.24-bookworm \
      cat /usr/local/go/lib/time/zoneinfo.zip > "$cache/run/lib/time/zoneinfo.zip" 2>/dev/null || true
  fi
  if [ ! -d "$cache/zoneinfo/America" ]; then
    echo "provisioning /usr/share/zoneinfo from golang image"
    mkdir -p "$cache/zoneinfo"
    docker run --rm --platform linux/arm64 golang:1.24-bookworm \
      tar cf - -C /usr/share/zoneinfo . 2>/dev/null > "$cache/zoneinfo.tar"
    tar xf "$cache/zoneinfo.tar" -C "$cache/zoneinfo" 2>/dev/null || true
    rm -f "$cache/zoneinfo.tar"
  fi
  # A CWD must exist for every package even when it ships no testdata.
  for p in "${pkgs[@]}"; do mkdir -p "$cache/run/src/$p"; done
}

# Extract "PASS <Test>" / "FAIL <Test>" verdict lines.
verdicts() { grep -oE '^--- (PASS|FAIL): [A-Za-z0-9_/]+' "$1" \
  | sed -E 's/^--- (PASS|FAIL): /\1 /' | sort -u; }

build
provision

total_gap=0
for p in "${pkgs[@]}"; do
  n=$(echo "$p" | tr / _); bin="$cache/bin/$n.test"
  if [ ! -x "$bin" ]; then
    echo "[$p] NO BINARY (build failed) — gap"; total_gap=$((total_gap+1)); continue
  fi

  # Run both sides with CWD = the package's mirrored src dir so each test's
  # relative testdata/ and ../testdata/ resolve; provide /etc/services. Docker
  # bind-mounts the run tree + -w; carrick does the same via run-elf -v/-w —
  # `--fs host` is a sandboxed scratch (NOT the real host FS), so the testdata
  # must be bind-mounted in. See provision().
  docker run --rm --platform linux/arm64 -v "$cache/bin":/b -v "$cache/run":/run \
    -v "$cache/etc/services":/etc/services:ro -v "$cache/zoneinfo":/usr/share/zoneinfo:ro \
    -w "/run/src/$p" debian:stable-slim \
    "/b/$n.test" -test.run 'Test' -test.skip "$SKIP" -test.short -test.v \
    -test.timeout "${TEST_TIMEOUT}s" > "$cache/logs/$n.docker" 2>&1

  pkill -9 -f "carrick run" 2>/dev/null
  # Build the carrick subcommand. ROOTFS_PKGS run inside a coherent debian
  # rootfs (same image + bind mounts as the Docker oracle), with the test binary
  # referenced by its in-rootfs mount path (/b/$n.test) so argv[0] has real
  # ancestor dirs; everything else runs the static ELF directly under --fs host.
  # Test args are shared. `--forward-env` carries the CPU count across sudo's
  # env_reset (a CLI arg survives where the NOPASSWD rule's lack of SETENV would
  # reject `sudo VAR=val carrick`).
  test_args=(-test.run Test -test.skip "$SKIP" -test.short -test.v -test.timeout "${TEST_TIMEOUT}s")
  case " $ROOTFS_PKGS " in
    *" $p "*)
      carrick_args=(run --raw --forward-env CARRICK_EXPOSED_CPUS=10
        -v "$cache/bin:/b" -v "$cache/run:/run" -v "$cache/zoneinfo:/usr/share/zoneinfo:ro"
        -w "/run/src/$p" "$ROOTFS_IMAGE" "/b/$n.test" "${test_args[@]}") ;;
    *)
      carrick_args=(run-elf --raw --fs host --forward-env CARRICK_EXPOSED_CPUS=10
        -v "$cache/run:/run" -v "$cache/zoneinfo:/usr/share/zoneinfo:ro"
        -w "/run/src/$p" "$bin" -- "${test_args[@]}") ;;
  esac
  # CARRICK_SUDO=1 runs the guest as root so raw-socket tests (ip:tcp, ip4:icmp)
  # work — macOS has no CAP_NET_RAW equivalent, so raw sockets need root (the same
  # privilege Docker grants by default). Off by default: running guest code as
  # root is a heavier posture and `sudo -n` needs a tty. Under sudo we skip the
  # outer `timeout` (sudo'ing `timeout` wouldn't match the carrick NOPASSWD rule)
  # and rely on -test.timeout + the pkill.
  if [ -n "${CARRICK_SUDO:-}" ]; then
    sudo -n "$carrick" "${carrick_args[@]}" > "$cache/logs/$n.carrick" 2>&1
  else
    timeout -s KILL "$RUN_TIMEOUT" "$carrick" "${carrick_args[@]}" > "$cache/logs/$n.carrick" 2>&1
  fi
  pkill -9 -f "carrick run" 2>/dev/null

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
