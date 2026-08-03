# Native performance tools

## Darwin/AArch64 `go-build`

`native_go_build.py` measures the reference cold-`GOCACHE` Go build used by the
native-lane performance handoff:

```sh
just build
python3 scripts/perf/native_go_build.py \
  --samples 5 \
  --output scripts/perf/evidence/native-go-build-post-change.json
```

The runner refuses an active compiler, Carrick process, orphaned `while :` spin
loop, or a one-minute load average above the host logical CPU count. Use
`--allow-busy` only for harness debugging; such a result is not performance
evidence.

Each sample has a unique `CARRICK_RUN_ID`, a cold guest `GOCACHE`, a bounded
deadline, and cleanup through `scripts/sudo/kill.sh`. The JSON records every
sample, the median, binary hash, git state, host provenance, and preflight
state. Run the Docker oracle in a separate phase.

## Receipt-bound ABBA authority

`native_go_build_abba.py` is the retention authority for this workload. It
prepares signed immutable arm receipts, then revalidates the receipt binary,
image, host, environment, and idle-state preflight before every execution. An
official run excludes one warm-up per arm and measures at least eight
A1/B1/B2/A2 quads; its primary metric is total child CPU from
`RUSAGE_CHILDREN`, which is a floor rather than a wall-time or throughput
claim. AC power is required by default. When the operator explicitly authorizes
battery operation, `run --allow-battery` records both that authorization and
the real `pmset` power output while retaining every thermal, load, compiler,
foreign-workload, and Docker-oracle rejection. The approved loopback registry
is plain HTTP `localhost:5005`, forwarded
only through the evidence-visible
`CARRICK_INSECURE_REGISTRIES=localhost:5005` contract; an ambient host setting
fails preflight. The accepted M1 control/control receipt is
[`evidence/native-go-build-abba-control-control-v1.json`](evidence/native-go-build-abba-control-control-v1.json).
Accepting a same-binary control/control run validates the instrument and its
measured resolution only: it cannot establish or retain an optimization.
