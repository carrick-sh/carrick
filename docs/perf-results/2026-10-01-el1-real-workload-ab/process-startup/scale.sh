#!/bin/bash
NODE=/opt/nodejs-conformance/bin/node24
for lanes in 1 2 3 4 5 6 8 10; do
  N=6
  t0=$EPOCHREALTIME
  for ((l=0; l<lanes; l++)); do ( for ((i=0; i<N; i++)); do $NODE -e 0 >/dev/null 2>&1; done ) & done
  wait
  t1=$EPOCHREALTIME
  python3 -c "import sys;w=float(sys.argv[2])-float(sys.argv[1]);n=int(sys.argv[3])*int(sys.argv[4]);print('SCALE lanes=%s per_proc_latency_ms=%.0f throughput_per_s=%.1f' % (sys.argv[3], w*1000/int(sys.argv[4]), n/w))" $t0 $t1 $lanes $N
done
