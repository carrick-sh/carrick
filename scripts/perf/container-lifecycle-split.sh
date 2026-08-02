#!/bin/bash
# Split a workload's cost into CONTAINER LIFECYCLE vs IN-GUEST WORK, for both
# engines, so a ratio is never quoted against the wrong denominator.
#
# Three numbers per engine:
#   lifecycle  = total wall of a no-op container (`true`): image seed, guest
#                boot, exit, and teardown, with ~no guest work
#   in-guest   = the workload's own window, bracketed by clock reads INSIDE
#                the guest (what workload-spread.sh reports)
#   total      = wall of the whole workload run, measured from the host
#
# `total - in-guest` is the lifecycle share a real run actually pays, and it
# is the ONLY term deferred-teardown work can move: an in-guest window
# excludes teardown by construction, because the guest prints its second
# timestamp before carrick starts reclaiming the scratch.
#
# Measured 2026-08-02 (go-conformance image, find over /usr/local/go):
#   carrick lifecycle 1,710 ms | in-guest 225 ms | total 2,000 ms
#   docker  lifecycle   160 ms | in-guest  12 ms | total   150 ms
# i.e. lifecycle is 7.6x the workload window it wraps.
#
# Strictly serial phases (AGENTS.md): all carrick, then all docker. Both are
# heavy VMs and starve each other, producing slow AND wrong verdicts.
set -u
cd "$(dirname "$0")/../.." || exit 1
IMAGE=${IMAGE:-localhost:5005/carrick-go-conformance:1.24}
WORKLOAD=${WORKLOAD:-'find /usr/local/go -type f | wc -l'}
N=${1:-3}

now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }
median() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }

guest_script="w0=\$(date +%s%N); ${WORKLOAD} >/dev/null; w1=\$(date +%s%N); echo WORKLOAD_NS=\$((w1-w0))"

run_engine() { # $1=engine $2=script -> guest stdout
  if [ "$1" = carrick ]; then
    target/release/carrick run --exec-backend native \
      -e "CARRICK_RUN_ID=lifecycle-$$-$RANDOM" -w /tmp "$IMAGE" /bin/sh -c "$2" 2>/dev/null
  else
    docker run --rm --platform linux/arm64 -w /tmp "$IMAGE" /bin/sh -c "$2" 2>/dev/null
  fi
}

measure() { # $1=engine -> "engine lifecycle in_guest total"
  eng=$1
  life=(); total=(); inguest=()
  for _ in $(seq 1 "$N"); do
    t0=$(now_ms); run_engine "$eng" 'true' >/dev/null; t1=$(now_ms)
    life+=($((t1 - t0)))
  done
  for _ in $(seq 1 "$N"); do
    t0=$(now_ms); out=$(run_engine "$eng" "$guest_script"); t1=$(now_ms)
    total+=($((t1 - t0)))
    ns=${out##*WORKLOAD_NS=}
    inguest+=($((ns / 1000000)))
  done
  echo "$eng $(median "${life[@]}") $(median "${inguest[@]}") $(median "${total[@]}")"
}

echo "=== phase: carrick ===" >&2
carrick_row=$(measure carrick)
echo "=== phase: docker ===" >&2
docker_row=$(measure docker)

printf '\n%-8s %10s %10s %10s %14s\n' engine lifecycle in_guest total total_minus_ig
for row in "$carrick_row" "$docker_row"; do
  # shellcheck disable=SC2086
  set -- $row
  printf '%-8s %10s %10s %10s %14s\n' "$1" "$2" "$3" "$4" "$(($4 - $3))"
done
printf '\n(all ms, median of %s)\n' "$N"
