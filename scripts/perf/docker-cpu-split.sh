#!/bin/zsh
# Docker-side in-container CPU split for the workload-spread fixtures.
# Move 0 of docs/superpowers/specs/2026-08-05-category-collapse-strategy-design.md:
# the category budgets need Docker's user/sys denominators, which the spread
# harness deliberately does not capture (its Docker rusage is the host
# wrapper). DOCKER-ONLY BY DESIGN -- never run while any carrick workload is
# active (AGENTS.md two-phase rule).
set -eu
SCRIPT_DIR=${0:A:h}
REPO_ROOT=${SCRIPT_DIR:h:h}
cd "$REPO_ROOT"

IMAGE=${CARRICK_PERF_IMAGE:-localhost:5005/carrick-go-conformance:1.24}
N=${1:-5}
OUT_DIR=target/perf/docker-cpu-split
OUT_JSONL=$OUT_DIR/docker-cpu-split.jsonl
mkdir -p "$OUT_DIR"
: > "$OUT_JSONL"

# Fixtures MUST stay byte-identical to workload-spread.sh so this split can
# be joined to the spread scoreboard. Assert, don't trust.
typeset -A WL
WL[compute]="awk 'BEGIN{for(i=0;i<8000000;i++)s+=i;print s}' >/dev/null"
WL[fs-walk]='find /usr/local/go -type f | wc -l >/dev/null'
WL[exec-20]='i=0; while [ $i -lt 20 ]; do /usr/local/go/pkg/tool/linux_arm64/compile -V >/dev/null; i=$((i+1)); done'
WL[build-cold]='cd /tmp; rm -rf gcx bx; printf "package main\nfunc main(){println(\"ok\")}\n" > b.go; GOCACHE=/tmp/gcx /usr/local/go/bin/go build -o bx ./b.go'
ORDER=(compute fs-walk exec-20 build-cold)

for name in $ORDER; do
  grep -qF -- "${WL[$name]}" scripts/perf/workload-spread.sh || {
    print -u2 "error: fixture '$name' drifted from workload-spread.sh"
    exit 2
  }
done

! pgrep -f 'carrick run' >/dev/null || { print -u2 "error: carrick guest live during docker-only measurement"; exit 3; }

print -r -- "$(python3 -c "
import json
print(json.dumps({
  'schema': 'carrick.docker-cpu-split.meta.v1',
  'git_commit': '$(git rev-parse HEAD)',
  'image': '$IMAGE',
  'image_id': '$(docker image inspect "$IMAGE" --format '{{.Id}}')',
  'samples_per_workload': $N,
  'method': 'in-container sh -c window: date +%s%N brackets + POSIX times builtin; shell-self and children lines summed',
}))")" >> "$OUT_JSONL"

run_one() { # workload-name sample -> one JSONL line on stdout
  local name=$1 i=$2 rid="cpusplit-docker-$name-$$-$i" out
  local script="set -eu; w0=\$(date +%s%N); ${WL[$name]}; w1=\$(date +%s%N); echo \"WORKLOAD_NS=\$((w1-w0))\"; times"
  out=$(docker run --rm --name "$rid" --platform linux/arm64 -w /tmp "$IMAGE" /bin/sh -c "$script")
  print -r -- "$out" > "$OUT_DIR/raw-$name-$i.txt"
  print -r -- "$out" | python3 -c "
import re, sys, json
raw = sys.stdin.read()
ns = int(re.search(r'WORKLOAD_NS=(\d+)', raw).group(1))
# times prints two lines after the marker: shell self, then children --
# each 'USERmUSERs SYSmSYSs'. Accept any fractional precision.
pairs = re.findall(r'(\d+)m([0-9.]+)s\s+(\d+)m([0-9.]+)s', raw)
assert len(pairs) >= 2, f'times output not recognized: {raw!r}'
sec = lambda m, s: int(m) * 60 + float(s)
user = sum(sec(p[0], p[1]) for p in pairs[-2:])
syst = sum(sec(p[2], p[3]) for p in pairs[-2:])
print(json.dumps({'schema': 'carrick.docker-cpu-split.v1',
                  'workload': '$name', 'sample': $i,
                  'wall_ms': ns // 1000000,
                  'user_s': round(user, 4), 'sys_s': round(syst, 4)}))
"
}

for name in $ORDER; do
  print -u2 "=== $name ==="
  for i in $(seq 1 $N); do
    line=$(run_one $name $i)
    print -r -- "$line" >> "$OUT_JSONL"
    print -u2 "  $line"
  done
done

print ""
printf "%-12s %10s %10s %10s %12s\n" workload wall_ms user_s sys_s cpu_total_s
python3 - "$OUT_JSONL" <<'PY'
import json, statistics, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if '"carrick.docker-cpu-split.v1"' in l]
for name in ['compute', 'fs-walk', 'exec-20', 'build-cold']:
    rs = [r for r in rows if r['workload'] == name]
    if not rs:
        continue
    med = lambda k: statistics.median(r[k] for r in rs)
    print(f"{name:<12} {med('wall_ms'):>10.0f} {med('user_s'):>10.3f} "
          f"{med('sys_s'):>10.3f} {med('user_s') + med('sys_s'):>12.3f}")
PY
