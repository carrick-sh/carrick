#!/usr/bin/env bash
# Record the native Docker oracle's syscall and argument-shape profile of the
# parity workload rows, split by root and native child, for
# `carrick debug venue-gaps` (#1906).
#
#   scripts/conformance/oracle-venue-profile.sh <out-dir> [row ...]
#
# The rows are docs/parity/parity-rows.json (VENUE_PROFILE_ROWS overrides the
# path): a row's image for this ISA and the argv of its `row` stage are read
# from that file, never restated here, so the oracle profiles the command the
# carrick scoreboard runs. With no row named, every row of the file is
# recorded.
#
# Docker-only phase: never run carrick on this machine meanwhile (AGENTS.md).
# The oracle must be native for the ISA it profiles: x86_64 on an amd64 Linux
# host, arm64 on a native arm64 Docker host (never an emulated platform).
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
rows=${VENUE_PROFILE_ROWS:-$repo/docs/parity/parity-rows.json}
bound=${VENUE_PROFILE_BOUND:-900}
bpftrace_bin=${VENUE_PROFILE_BPFTRACE:-/usr/bin/bpftrace}

case "$(uname -m)" in
  x86_64) isa=x86_64 isa_code=0 ;;
  aarch64|arm64) isa=arm64 isa_code=1 ;;
  *) echo "oracle-venue-profile: unsupported host ISA $(uname -m)" >&2; exit 2 ;;
esac
[ -r "$rows" ] || { echo "oracle-venue-profile: no rows file $rows" >&2; exit 2; }

# The image of a rows-file row for this ISA; fails when the file has no such
# row or the row pins no image for the ISA.
row_image() {
  jq -er --arg row "$1" --arg isa "$isa" \
    '[.rows[] | select(.name == $row)] | if length == 1 then .[0].image[$isa] else null end' "$rows"
}

# Set `image` and `argv` for a row. A parity row is its rows-file `row` stage,
# verbatim. The two known-answer rows are not parity rows and live here.
load_row() {
  argv=()
  case "$1" in
    # The root makes one unknown syscall (511) and one
    # socket(AF_INET, SOCK_DGRAM); its forked child makes two unknown
    # syscalls (510) and one socket(AF_UNIX, SOCK_STREAM). Docker's seccomp
    # profile answers 510 and 511 with ENOSYS before the entry tracepoint,
    # so they land in @unentered. The profile must read exactly
    # `@unentered[0, 511, -38]: 1`, `@unentered[1, 510, -38]: 2`,
    # `@calls[0, 41, 2, 2]: 1` and `@calls[1, 41, 1, 1]: 1` (x86_64 numbers).
    known-answer)
      image=$(row_image pip) || return 1
      argv=(python3 -c 'import os,ctypes; l=ctypes.CDLL(None); l.syscall(511); l.socket(2, 2, 0); p=os.fork(); (l.syscall(510), l.syscall(510), l.socket(1, 1, 0), os._exit(0)) if p == 0 else os.waitpid(p, 0)') ;;
    # A workload that outlives VENUE_PROFILE_BOUND. Run with a short bound,
    # the script must exit non-zero within about the bound and leave no
    # container behind.
    bound-hang)
      image=$(row_image pip) || return 1
      argv=(sleep 1000000) ;;
    *)
      image=$(row_image "$1") || return 1
      # jq ends each argument with a NUL, so an argument keeps its newlines.
      mapfile -d '' -t argv < <(jq -j --arg row "$1" \
        '.rows[] | select(.name == $row) | .stages[] | select(.name == "row") | .command[] | . + "\u0000"' "$rows")
      [ "${#argv[@]}" -gt 0 ] ;;
  esac
}

if [ $# -eq 0 ]; then
  mapfile -t all < <(jq -r '.rows[].name' "$rows")
  [ "${#all[@]}" -gt 0 ] || { echo "oracle-venue-profile: $rows names no row" >&2; exit 2; }
  set -- "${all[@]}"
fi
# Refuse an unknown row before the first container starts.
for row in "$@"; do
  load_row "$row" || {
    echo "oracle-venue-profile: $rows has no row $row with a $isa image and a row stage" >&2
    exit 2
  }
done

mkdir -p "$out"
status=0
# The live workload container: removed on any exit, so a Ctrl-C, a `set -e`
# stop or a hung row never leaves Docker running into a carrick phase.
live=""
trap '[ -z "$live" ] || docker rm -f "$live" "$live-observer" > /dev/null 2>&1 || true' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for row in "$@"; do
  load_row "$row"
  d="$out/$row"
  rm -rf "$d"
  mkdir -p "$d"
  name="venue-profile-$row-$$"
  docker pull -q "$image" > /dev/null
  live=$name
  # The workload stops itself before the row command, so bpftrace attaches
  # first; docker-init is pid 1, so the stopping shell (pid 2) can stop. It
  # then execs the row's argv, so the row's root is the profiled root.
  docker run -d --init --name "$name" "$image" \
    sh -c 'kill -STOP $$; exec "$@"' sh "${argv[@]}" > /dev/null
  # The observer: the host's bpftrace, as root in the host's pid namespace.
  init_pid=$(docker inspect -f '{{.State.Pid}}' "$name")
  docker run --rm --name "$name-observer" --privileged --pid=host -v /:/host \
    -e INIT_PID="$init_pid" -e BOUND="$bound" -e ISA_CODE="$isa_code" -e BPFTRACE="$bpftrace_bin" \
    -e BT="$bt" -e PROFILE="$(cd "$d" && pwd -P)/profile.txt" \
    "$image" chroot /host /bin/sh -c '
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
    ' &
  # In the background, so a signal to this script runs its trap now rather
  # than after the observer returns.
  wait "$!" || { status=1; echo "row $row: observer failed" >&2; docker kill "$name" > /dev/null 2>&1 || true; }
  # bpftrace exits 0 at its bound (`error=bound`), so the observer's status
  # alone never says the row finished: without the complete marker, the
  # workload is killed rather than waited on.
  if ! grep -q 'VENUEPROFILE1|complete' "$d/profile.txt" 2> /dev/null; then
    echo "row $row: profile incomplete, killing the workload" >&2
    status=1
    docker kill "$name" > /dev/null 2>&1 || true
  fi
  # The workload has finished (complete) or been killed; the wait is bounded
  # anyway, so no path waits on a live row.
  if ! rc=$(timeout 60 docker wait "$name"); then
    echo "row $row: docker wait did not return, removing the workload" >&2
    status=1
    rc=timeout
  fi
  docker logs "$name" > "$d/workload.out" 2> "$d/workload.err" || true
  docker rm -f "$name" > /dev/null 2>&1 || true
  live=""
  echo "$rc" > "$d/rc"
  {
    echo "row=$row isa=$isa image=$image"
    printf 'argv='; printf '%q ' "${argv[@]}"; echo
    echo "rows_sha256=$(sha256sum "$rows" | cut -c1-64)"
    echo "kernel=$(uname -r) docker=$(docker version -f '{{.Server.Version}}') bpftrace=$($bpftrace_bin -V)"
    echo "script_sha256=$(sha256sum "$bt" | cut -c1-64) head=$(git -C "$repo" rev-parse HEAD)"
  } > "$d/receipt.txt"
  echo "ROW $row isa=$isa rc=$rc profile=$d/profile.txt"
done
exit "$status"
