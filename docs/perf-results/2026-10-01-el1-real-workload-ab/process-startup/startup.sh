#!/bin/bash
# Per-process startup latency: N serial runs, then P parallel lanes of N.
# usage: startup.sh <N>
N=${1:-20}
NODE=/opt/nodejs-conformance/bin/node24
ms() { python3 -c "import sys;print('%.1f' % ((float(sys.argv[2])-float(sys.argv[1]))*1000/float(sys.argv[3])))" "$@"; }
run() { # label, lanes, cmd...
  local label=$1 lanes=$2; shift 2
  local t0=$EPOCHREALTIME
  for ((l=0; l<lanes; l++)); do ( for ((i=0; i<N; i++)); do "$@" >/dev/null 2>&1; done ) & done
  wait
  local t1=$EPOCHREALTIME
  echo "$label lanes=$lanes per_process_ms=$(ms $t0 $t1 $N)"
}
echo "nproc=$(nproc)"
for lanes in 1 4 10; do
  run true $lanes /bin/true
  run python_pass $lanes python3 -c pass
  run node_e0 $lanes $NODE -e 0
done
cd /opt/node-src/v24
run testpy_import 1 python3 tools/test.py --help
