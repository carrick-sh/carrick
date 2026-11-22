#!/usr/bin/env bash
# Record the native Docker oracle's syscall and argument-shape profile of the
# parity workload rows (go-hello, go-real, pip, npm, shell), split by root and
# native child, for `carrick debug venue-gaps` (#1906).
#
#   scripts/conformance/oracle-venue-profile.sh <out-dir> [row ...]
#
# Docker-only phase: never run carrick on this machine meanwhile (AGENTS.md).
# The oracle must be native for the ISA it profiles: x86_64 on an amd64 Linux
# host, arm64 on a native arm64 Docker host (never an emulated platform).
# The rows and digests are agy-director's director/parity-rows.sh, so the
# oracle and the carrick scoreboard run the same images and commands.
#
# Each row runs in its own container behind docker-init and stops itself
# before the workload starts. A privileged observer (--pid=host) runs the
# host's bpftrace with scripts/bpftrace/oracle-venue-profile.bt on the
# stopped root, then resumes it. Per row, <out-dir>/<row>/ holds profile.txt
# (the map dump), workload.out, workload.err, rc and receipt.txt.
set -euo pipefail

out=${1:?usage: oracle-venue-profile.sh <out-dir> [row ...]}
shift
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
bt="$repo/scripts/bpftrace/oracle-venue-profile.bt"
bound=${VENUE_PROFILE_BOUND:-900}
bpftrace_bin=${VENUE_PROFILE_BPFTRACE:-/usr/bin/bpftrace}

case "$(uname -m)" in
  x86_64)
    isa=x86_64 isa_code=0
    GO=docker.io/library/golang:1.23@sha256:e87b2a5f6df2dff71ea330d55d54f4979eb380ae58a7e3aabc9d53121243e689
    PY=docker.io/library/python:3.12-slim@sha256:05a994d2344eb364cc186910f4fc8786a38215f39f00d0acc25bff33a08f4177
    ND=docker.io/library/node:22-slim@sha256:47725aca53d3295ec2d3be8f62726599b3033cc262edc2c7e429909b3ac599fc
    UB=docker.io/library/ubuntu:24.04@sha256:77eb101c607d6e3d4f5ad0c8a02c2136c689b98aba1f359e6502ba517e5c57ec ;;
  aarch64|arm64)
    isa=arm64 isa_code=1
    GO=docker.io/library/golang:1.23@sha256:60deed95d3888cc5e4d9ff8a10c54e5edc008c6ae3fba6187be6fb592e19e8c0
    PY=docker.io/library/python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
    ND=docker.io/library/node:22-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
    UB=docker.io/library/ubuntu:24.04@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5 ;;
  *) echo "oracle-venue-profile: unsupported host ISA $(uname -m)" >&2; exit 2 ;;
esac

# name, image, command: the parity rows, verbatim.
declare -A IMG CMD
IMG[go-hello]=$GO
CMD[go-hello]='cd /tmp && printf "package main\nfunc main(){println(\"ok\")}\n" > h.go && GOCACHE=/tmp/gc go build -o h ./h.go && ./h && echo BUILD_OK'
IMG[go-real]=$GO
CMD[go-real]='cd /tmp && GOFLAGS=-mod=mod GOCACHE=/tmp/gc go install golang.org/x/example/hello@v0.0.0-20240925201127-4ac1d1bdc3e3 && /go/bin/hello && echo GOREAL_OK'
IMG[pip]=$PY
CMD[pip]='pip install --no-cache-dir requests==2.32.3 && python -c "import requests;print(requests.__version__)" && echo PIP_OK'
IMG[npm]=$ND
CMD[npm]='mkdir -p /tmp/a && cd /tmp/a && npm init -y >/dev/null && npm install --no-audit --no-fund lodash@4.17.21 && node -e "console.log(require(\"lodash\").VERSION)" && echo NPM_OK'
IMG[shell]=$UB
CMD[shell]='apt-get update && apt-get install -y git gcc && cd /tmp && printf "int main(){return 0;}" > t.c && gcc t.c -o t && ./t && git --version && echo SHELL_OK'
# The known-answer row (not a parity row). The root makes one unknown
# syscall (511) and one socket(AF_INET, SOCK_DGRAM); its forked child makes
# two unknown syscalls (510) and one socket(AF_UNIX, SOCK_STREAM). Docker's
# seccomp profile answers 510 and 511 with ENOSYS before the entry
# tracepoint, so they land in @unentered. The profile must read exactly
# `@unentered[0, 511, -38]: 1`, `@unentered[1, 510, -38]: 2`,
# `@calls[0, 41, 2, 2]: 1` and `@calls[1, 41, 1, 1]: 1` (x86_64 numbers).
IMG[known-answer]=$PY
CMD[known-answer]='exec python3 -c "import os,ctypes; l=ctypes.CDLL(None); l.syscall(511); l.socket(2, 2, 0); p=os.fork(); (l.syscall(510), l.syscall(510), l.socket(1, 1, 0), os._exit(0)) if p == 0 else os.waitpid(p, 0)"'
ALL=(go-hello go-real pip npm shell)
[ $# -gt 0 ] || set -- "${ALL[@]}"

mkdir -p "$out"
status=0
for row in "$@"; do
  [ -n "${IMG[$row]:-}" ] || { echo "unknown row $row (rows: ${ALL[*]})" >&2; exit 2; }
  d="$out/$row"
  rm -rf "$d"
  mkdir -p "$d"
  name="venue-profile-$row-$$"
  docker pull -q "${IMG[$row]}" > /dev/null
  # The workload stops itself before the row command, so bpftrace attaches
  # first; docker-init is pid 1, so the row's shell (pid 2) can stop.
  docker run -d --init --name "$name" -e ROWCMD="${CMD[$row]}" "${IMG[$row]}" \
    sh -c 'kill -STOP $$; exec sh -c "$ROWCMD"' > /dev/null
  # The observer: the host's bpftrace, as root in the host's pid namespace.
  init_pid=$(docker inspect -f '{{.State.Pid}}' "$name")
  docker run --rm --privileged --pid=host -v /:/host \
    -e INIT_PID="$init_pid" -e BOUND="$bound" -e ISA_CODE="$isa_code" -e BPFTRACE="$bpftrace_bin" \
    -e BT="$bt" -e PROFILE="$(cd "$d" && pwd -P)/profile.txt" \
    "${IMG[$row]}" chroot /host /bin/sh -c '
      set -eu
      root=""
      for _ in $(seq 1 100); do
        root=$(cut -d" " -f1 /proc/$INIT_PID/task/$INIT_PID/children 2>/dev/null || true)
        [ -n "$root" ] && grep -q "^State:.*T" /proc/$root/status 2>/dev/null && break
        root=""; sleep 0.1
      done
      [ -n "$root" ] || { echo "VENUEPROFILE1|error=no-stopped-root" >&2; exit 3; }
      mountpoint -q /sys/kernel/tracing || mount -t tracefs tracefs /sys/kernel/tracing
      BPFTRACE_MAX_MAP_KEYS=262144 "$BPFTRACE" -B line "$BT" "$root" "$BOUND" "$ISA_CODE" > "$PROFILE" 2>&1 &
      bt=$!
      for _ in $(seq 1 600); do
        grep -q "VENUEPROFILE1|ready" "$PROFILE" 2>/dev/null && break
        sleep 0.1
      done
      grep -q "VENUEPROFILE1|ready" "$PROFILE" || { kill "$bt"; echo "VENUEPROFILE1|error=not-ready" >&2; exit 3; }
      kill -CONT "$root"
      wait "$bt"
    ' || { status=1; echo "row $row: observer failed" >&2; docker kill "$name" > /dev/null 2>&1 || true; }
  rc=$(docker wait "$name")
  docker logs "$name" > "$d/workload.out" 2> "$d/workload.err" || true
  docker rm -f "$name" > /dev/null
  echo "$rc" > "$d/rc"
  {
    echo "row=$row isa=$isa image=${IMG[$row]}"
    echo "kernel=$(uname -r) docker=$(docker version -f '{{.Server.Version}}') bpftrace=$($bpftrace_bin -V)"
    echo "script_sha256=$(sha256sum "$bt" | cut -c1-64) head=$(git -C "$repo" rev-parse HEAD)"
  } > "$d/receipt.txt"
  grep -q 'VENUEPROFILE1|complete' "$d/profile.txt" || { echo "row $row: profile incomplete" >&2; status=1; }
  echo "ROW $row isa=$isa rc=$rc profile=$d/profile.txt"
done
exit "$status"
