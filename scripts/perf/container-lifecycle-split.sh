#!/bin/zsh
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
# `total - in-guest` is the lifecycle share actually paid by a real run, and
# it is the ONLY term deferred-teardown work can move: an in-guest window
# excludes teardown by construction, because the guest has already printed
# its second timestamp before carrick starts reclaiming the scratch.
#
# Strictly serial phases (AGENTS.md): all carrick, then all docker. Both are
# heavy VMs and starve each other, producing slow AND wrong verdicts.
set -eu
cd /Volumes/CaseSensitive/carrick
IMAGE=${IMAGE:-localhost:5005/carrick-go-conformance:1.24}
WORKLOAD=${WORKLOAD:-'find /usr/local/go -type f | wc -l'}
N=${1:-5}

now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }
median() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }

# In-guest bracket around the workload; the guest prints its own window.
guest_script="w0=\$(date +%s%N); ${WORKLOAD} >/dev/null; w1=\$(date +%s%N); echo WORKLOAD_NS=\$((w1-w0))"

run_carrick() { # $1 = script
  target/release/carrick run --exec-backend native \
    -e "CARRICK_RUN_ID=lifecycle-$$-$RANDOM" -w /tmp "$IMAGE" /bin/sh -c "$1" 2>/dev/null
}
run_docker() { # $1 = script
  docker run --rm --platform linux/arm64 -w /tmp "$IMAGE" /bin/sh -c "$1" 2>/dev/null
}

measure() { # $1 = engine
  local eng=$1 runner="run_${1}"
  local -a life total inguest
  # Phase A: no-op container -> pure lifecycle.
  for i in $(seq 1 $N); do
    local t0=$(now_ms); $runner 'true' >/dev/null; local t1=$(now_ms)
    life+=($((t1 - t0)))
  done
  # Phase B: the workload -> total wall AND the in-guest window from one run.
  for i in $(seq 1 $N); do
    local t0=$(now_ms) out; out=$($runner "$guest_script"); local t1=$(now_ms)
    total+=($((t1 - t0)))
    inguest+=($(( ${out##*WORKLOAD_NS=} / 1000000 )))
  done
  print -r -- "$eng $(median $life) $(median $inguest) $(median $total)"
}

print -u2 "=== phase: carrick ==="
carrick_row=$(measure carrick)
print -u2 "=== phase: docker ==="
docker_row=$(measure docker)

printf '\n%-8s %10s %10s %10s %12s\n' engine lifecycle in_guest total total_minus_ig
for row in "$carrick_row" "$docker_row"; do
  set -- ${=row}
  printf '%-8s %10s %10s %10s %12s\n' "$1" "$2" "$3" "$4" "$(($4 - $3))"
done
printf '\n(all ms, median of %s)\n' "$N"
