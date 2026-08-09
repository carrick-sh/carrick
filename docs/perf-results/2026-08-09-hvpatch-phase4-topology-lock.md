# HvPatch Phase 4 topology-lock holder attribution

Date: 2026-08-09

Status: **ATTRIBUTED; Phase 4 remains RED.** Two repeated typed captures reject
the hypothesis that in-process fork alone explains exec's topology-lock wait.
Concurrent exec and fork are the two dominant holder classes. This is traced
attribution, not an untraced performance result.

## Question

The closed exec ledger measured topology-lock acquisition at 1.075 ms per exec,
already beyond Phase 4's `<1 ms` complete-exec target. Was exec principally
waiting for the in-process fork snapshot, or did other shared-VM topology
operations materially contend for the same lock?

## Change under test

Every runtime acquisition of `fork_quiesce::topology_lock()` now uses one typed
RAII guard. It preserves the same process-wide mutex and the same critical
section scopes while emitting request, acquired, release, and try-miss events.
The guard's `Drop` implementation emits release on every Rust exit path.

`hvpatch-topology-lock` carries five scalar CTF fields:

- append-only operation and phase ordinals;
- Linux guest PID and TID (PID is zero only where the caller has no process
  context);
- wait nanoseconds on acquisition or hold nanoseconds on release.

The operation roster covers in-process fork, exec replacement, exec's sibling
gate, sibling materialization, vCPU rebind, VM release, and legacy fork. The
durable consumer is `scripts/dtrace/hvpatch-phase4-topology-lock.d`.

## Provenance

- Host: macOS 27.0 build `26A5388g`, arm64.
- Branch: `codex/hvpatch`, parent `a9b6ebe4`, with only the typed topology
  instrumentation and D script described here uncommitted at capture time.
- Signed binary SHA-256:
  `338897d3901b9c48328b0d7dcccd274389a74e300d87af8d2224c749ee496ff3`.
- Backend: `--exec-backend hvpatch`; filesystem: `--fs host`.
- Workload: `scripts/perf/fixtures/hvpatch-cold-go-build.sh` in
  `localhost:5005/carrick-go-conformance:1.24`, `--pull never`.
- Both retained runs printed exact `ok` and `BUILD_OK` markers. Docker was not
  run concurrently.

Command shape:

```sh
CARRICK_RUN_ID=<scoped-id> target/release/carrick trace \
  --script scripts/dtrace/hvpatch-phase4-topology-lock.d \
  --trace-out target/perf/hvpatch-phase4/<capture>.raw \
  -- run --name <scoped-id> --rm --raw --fs host \
  --exec-backend hvpatch --pull never \
  -v "$PWD/scripts/perf/fixtures:/fixture:ro" \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh /fixture/hvpatch-cold-go-build.sh
```

## Capture validity

| Capture | Request | Acquire | Release | Pair/ordinal/DTrace errors | Result |
|---|---:|---:|---:|---:|---|
| `topology-lock-holder-2.raw` | 3,366 | 3,366 | 3,366 | 0 | `ok`, `BUILD_OK` |
| `topology-lock-holder-3.raw` | 3,011 | 3,011 | 3,011 | 0 | `ok`, `BUILD_OK` |

The first exploratory `topology-lock-holder-1.raw` is rejected: the raw stream
was paired, but its initial coverage summary used contended global scalar
increments and under-counted six requests. The retained script makes DTrace
aggregations the phase-count authority and also prints per-thread pairing
errors. This prevents a plausible-looking racy summary from becoming evidence.

No retained capture was empty or bounded, and neither reported a DTrace error.
There were no try misses in this workload.

## Holder present when exec requested the lock

The script defines a material exec wait as at least 50 us, snapshots the active
holder at the exec request event, and reports an unknown rather than assigning
an untracked holder. The snapshot names the holder present when waiting began;
it does not claim that one holder occupied the entire queued interval.

| Holder at request | Waits | Combined wait | Share |
|---|---:|---:|---:|
| Concurrent exec replacement | 19 | 59.069 ms | 45.67% |
| In-process fork | 17 | 53.775 ms | 41.57% |
| vCPU rebind | 14 | 13.541 ms | 10.47% |
| Untracked at request | 5 | 2.512 ms | 1.94% |
| Sibling materialization | 4 | 0.455 ms | 0.35% |
| **Total** | **59** | **129.352 ms** | **100%** |

The dominant result repeats: exec plus fork account for 84.2% of material wait
in the first retained run and 98.0% in the second. The vCPU-rebind share is
schedule-sensitive, but it is secondary in the combined ledger.

## Lock-hold population

Across both captures:

| Holder operation | Holds | Total hold | Mean hold | Maximum |
|---|---:|---:|---:|---:|
| In-process fork | 137 | 556.815 ms | 4.064 ms | 11.432 ms |
| Exec replacement | 135 | 211.919 ms | 1.570 ms | 4.521 ms |
| vCPU rebind | 5,557 | 99.308 ms | 0.018 ms | 1.200 ms |
| Sibling materialization | 548 | 13.318 ms | 0.024 ms | 0.365 ms |

Fork is the longest individual holder, but serial execs collectively create a
second equally important source of exec wait. Existing fork-snapshot evidence
accounts for only about 1.2 ms of the roughly 4.1 ms mean fork hold, so changing
snapshot construction alone would leave most of both the fork critical section
and the concurrent-exec serialization intact.

## Decision

The single-fork-holder hypothesis is **rejected**. Phase 4 cannot reach its exec
target by optimizing only the fork snapshot or page-table reset. The immediate
next evidence steps are:

1. close an inner stage ledger over the full in-process-fork critical section,
   especially dispatcher cloning, child thread creation, materialization, and
   the ready handshake;
2. qualify whether Hypervisor.framework permits concurrent map/unmap of
   disjoint process-bank IPA ranges before proposing per-bank locking;
3. retain the separate exec engine work: backing-map construction plus bank
   planning is still 1.312 ms per exec even with zero topology wait.

Correct shared-VM isolation remains authoritative. This result does not justify
narrowing or removing the topology lock yet.

## Verification

- Red-first observability ABI test failed because the typed operation, phase,
  and event types did not yet exist, then passed after implementation.
- Red-first `carrick-thread` guard test failed because the typed acquire/try
  APIs did not yet exist, then proved mutual exclusion and RAII release.
- `cargo test -p carrick-observability --lib`: 52 passed.
- `RUST_TEST_THREADS=1 cargo test -p carrick-thread --lib`: 41 passed.
- Focused shared-VM exec identity test: passed.
- Focused clippy for observability, thread, and runtime: passed with warnings
  denied.
- `just ci`: passed after both retained captures.
