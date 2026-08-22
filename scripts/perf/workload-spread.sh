#!/bin/zsh
# Where does carrick actually stand? One workload is not a benchmark.
# Strictly serial phases: ALL carrick, then ALL docker (AGENTS.md -- both are
# heavy VMs and starve each other, producing slow AND wrong verdicts).
set -eu
SCRIPT_DIR=${0:A:h}
REPO_ROOT=${SCRIPT_DIR:h:h}
cd "$REPO_ROOT"

IMAGE=${CARRICK_PERF_IMAGE:-localhost:5005/carrick-go-conformance:1.24}
CARRICK_BIN=${CARRICK_PERF_BINARY:-target/release/carrick}
CARRICK_BIN=${CARRICK_BIN:A}
N=${1:-3}

[[ -x "$CARRICK_BIN" ]] || {
  print -u2 "error: Carrick binary is not executable: $CARRICK_BIN"
  exit 2
}
[[ -z $(git status --porcelain) ]] || {
  print -u2 "error: workload-spread requires a clean source checkout"
  exit 2
}
(( ! ${+CARRICK_DSR_PERSISTENT_STORE} )) || {
  print -u2 "error: unset CARRICK_DSR_PERSISTENT_STORE to measure shipped defaults"
  exit 2
}

print -u2 "repo=$REPO_ROOT"
print -u2 "git_commit=$(git rev-parse HEAD)"
print -u2 "binary=$CARRICK_BIN"
print -u2 "binary_sha256=$(shasum -a 256 "$CARRICK_BIN" | awk '{print $1}')"
print -u2 "image=$IMAGE"
print -u2 "image_id=$(docker image inspect "$IMAGE" --format '{{.Id}}')"
print -u2 "persistent_store_env=unset"
pmset -g batt >&2 || true
pmset -g therm >&2 || true

# Each workload brackets its own guest window with in-guest clock reads, so
# engine-side container setup stays out of the number on both engines.
w() { print -r -- "w0=\$(date +%s%N); $1; w1=\$(date +%s%N); echo \"WORKLOAD_NS=\$((w1-w0))\""; }

typeset -A WL
WL[startup]=$(w 'true')
WL[compute]=$(w "awk 'BEGIN{for(i=0;i<8000000;i++)s+=i;print s}' >/dev/null")
WL[fs-walk]=$(w 'find /usr/local/go -type f | wc -l >/dev/null')
WL[exec-20]=$(w 'i=0; while [ $i -lt 20 ]; do /usr/local/go/pkg/tool/linux_arm64/compile -V >/dev/null; i=$((i+1)); done')
WL[build-cold]=$(w 'cd /tmp; rm -rf gcx bx; printf "package main\nfunc main(){println(\"ok\")}\n" > b.go; GOCACHE=/tmp/gcx /usr/local/go/bin/go build -o bx ./b.go')
WL[build-warm]=$(w 'cd /tmp; printf "package main\nfunc main(){println(\"ok\")}\n" > b2.go; GOCACHE=/tmp/gcw /usr/local/go/bin/go build -o bx2 ./b2.go')

ORDER=(startup compute fs-walk exec-20 build-cold build-warm)

run() { # engine workload-name sample
  local eng=$1 name=$2 i=$3 rid="spread-$1-$2-$$-$3" out
  local script="set -eu; ${WL[$name]}"
  if [[ $eng == carrick ]]; then
    out=$("$CARRICK_BIN" run --exec-backend hvpatch -e "CARRICK_RUN_ID=$rid" -w /tmp "$IMAGE" /bin/sh -c "$script" 2>/dev/null) || return 1
  else
    out=$(docker run --rm --name "$rid" --platform linux/arm64 -e "CARRICK_RUN_ID=$rid" -w /tmp "$IMAGE" /bin/sh -c "$script" 2>/dev/null) || return 1
  fi
  print -r -- "${out##*WORKLOAD_NS=}"
}

# build-warm needs its cache primed once per engine, outside the measurement.
prime() {
  local eng=$1 rid="prime-$1-$$"
  local s="set -eu; cd /tmp; printf 'package main\nfunc main(){println(\"ok\")}\n' > b2.go; GOCACHE=/tmp/gcw /usr/local/go/bin/go build -o bx2 ./b2.go"
  if [[ $eng == carrick ]]; then
    "$CARRICK_BIN" run --exec-backend hvpatch -e "CARRICK_RUN_ID=$rid" -w /tmp "$IMAGE" /bin/sh -c "$s" >/dev/null 2>&1 || true
  else
    docker run --rm --name "$rid" --platform linux/arm64 -e "CARRICK_RUN_ID=$rid" -w /tmp "$IMAGE" /bin/sh -c "$s" >/dev/null 2>&1 || true
  fi
}

typeset -A RES
for eng in carrick docker; do
  print -u2 "=== phase: $eng ==="
  for name in $ORDER; do
    # NOTE: build-warm shares no state across container runs here -- each run is
    # a fresh container, so GOCACHE starts empty every time. Reported as
    # build-cold-equivalent and labelled honestly rather than faked.
    local vals=()
    for i in $(seq 1 $N); do
      v=$(run $eng $name $i) || { vals+=(FAIL); continue; }
      vals+=($((v/1000000)))
    done
    RES[$eng,$name]="${vals[*]}"
    print -u2 "  $name: ${vals[*]} ms"
  done
done

print ""
printf "%-12s %12s %12s %8s\n" workload carrick_ms docker_ms ratio
for name in $ORDER; do
  c=(${=RES[carrick,$name]}); d=(${=RES[docker,$name]})
  cm=$(printf '%s\n' $c | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
  dm=$(printf '%s\n' $d | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
  r=$(python3 -c "print(f'{$cm/max($dm,1):.1f}x')" 2>/dev/null || echo "?")
  printf "%-12s %12s %12s %8s\n" $name $cm $dm $r
done
