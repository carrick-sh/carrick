#!/bin/bash
# usage: loop.sh <lanes> <N> <cmd...>
lanes=$1; N=$2; shift 2
t0=$EPOCHREALTIME
for ((l=0; l<lanes; l++)); do ( for ((i=0; i<N; i++)); do "$@" >/dev/null 2>&1; done ) & done
wait
t1=$EPOCHREALTIME
python3 -c "import sys;print('LOOP lanes=%s N=%s per_process_ms=%.1f' % (sys.argv[3], sys.argv[4], (float(sys.argv[2])-float(sys.argv[1]))*1000/float(sys.argv[4])))" $t0 $t1 $lanes $N
