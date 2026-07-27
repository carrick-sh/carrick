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
