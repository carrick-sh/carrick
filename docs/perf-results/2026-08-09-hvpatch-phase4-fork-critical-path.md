# HvPatch Phase 4 in-process-fork critical path

Date: 2026-08-09

Status: **ATTRIBUTED; Phase 4 remains RED.** Two repeated typed captures close
the parent-thread ledger inside the in-process-fork topology-lock hold. Sibling
quiescence and process-spec construction account for 92.9% of the measured
critical section. The quiescence result directly exposes the existing 200-us
sleep-poll cadence as the first behavior lever; this document does not claim a
performance improvement.

## Question

The topology-lock census measured a 4.064-ms mean in-process-fork hold, while
the existing HVF snapshot evidence explained only about 1.2 ms. Which mutually
exclusive parent-thread stages account for the remaining hold, and is the
quiescence wait measuring sibling retirement or a polling artifact?

## Instrument

`hvpatch-fork-runtime-stage` carries five scalar CTF values:

- an append-only stage ordinal;
- Linux parent PID, child PID, and forking TID;
- elapsed nanoseconds.

Stages 0 through 8 partition quiescence, process allocation, pidfd/parent-TID
publication, process-spec construction, dispatcher clone, runtime-state setup,
thread spawn, child-ready handshake, and final publication. Stage 9 is a
cumulative total enclosing stages 0 through 8 and must not be summed with them
as a peer.

`hvpatch-fork-quiesce` separately records Linux parent PID and forking TID,
initial sibling-vCPU population, 200-us poll iterations, and quiescence elapsed
nanoseconds. DTrace `pid` and `tid` remain the distinct Darwin host identities.
The durable consumer is
`scripts/dtrace/hvpatch-phase4-fork-runtime-stages.d`. It fails closed on an
empty or bounded capture, invalid phases, DTrace errors, or unequal per-stage
coverage. Perturbation is eleven low-frequency scalar USDT firings per
successful fork; only same-instrument ratios are citable.

## Provenance

- Host: macOS 27.0 build `26A5388g`, arm64.
- Branch: `codex/hvpatch`, committed parent `15b96887`, with only the fork
  instrumentation, D script, and this evidence document uncommitted at capture
  time.
- Signed binary SHA-256:
  `2fc85de9f8ff713ceff0fd9bc7fa9058c32f951f881ad31c83e995ca3ff847a5`.
- Backend: `--exec-backend hvpatch`; filesystem: `--fs host`.
- Workload: `scripts/perf/fixtures/hvpatch-cold-go-build.sh` in
  `localhost:5005/carrick-go-conformance:1.24`, `--pull never`.
- Both runs printed exact `ok` and `BUILD_OK` markers. Carrick and Docker were
  not run concurrently.

Command shape:

```sh
CARRICK_RUN_ID=<scoped-id> target/release/carrick trace \
  --script scripts/dtrace/hvpatch-phase4-fork-runtime-stages.d \
  --trace-out target/perf/hvpatch-phase4/<capture>.raw \
  -- run --name <scoped-id> --rm --raw --fs host \
  --exec-backend hvpatch --pull never \
  -v "$PWD/scripts/perf/fixtures:/fixture:ro" \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh /fixture/hvpatch-cold-go-build.sh
```

## Capture validity

| Capture | Count for each phase 0..9 | Phase/empty/bounded/DTrace errors | Result |
|---|---:|---:|---|
| `fork-runtime-quiesce-detail-1.raw` | 68 | 0 | `ok`, `BUILD_OK` |
| `fork-runtime-quiesce-detail-2.raw` | 68 | 0 | `ok`, `BUILD_OK` |

The two captures therefore contain 136 complete fork ledgers. Raw capture
files are retained under `target/perf/hvpatch-phase4/`.

## Closed fork-stage ledger

| Parent-thread stage | Combined total | Mean per fork | Share of cumulative total |
|---|---:|---:|---:|
| Sibling quiescence | 292.093 ms | 2.148 ms | 58.1% |
| Process spec | 174.686 ms | 1.284 ms | 34.8% |
| Child ready | 19.098 ms | 0.140 ms | 3.8% |
| Thread spawn | 1.486 ms | 0.011 ms | 0.3% |
| Publication | 1.327 ms | 0.010 ms | 0.3% |
| Dispatcher clone | 0.871 ms | 0.006 ms | 0.2% |
| Pidfd / parent TID | 0.397 ms | 0.003 ms | <0.1% |
| Runtime state | 0.377 ms | 0.003 ms | <0.1% |
| Process allocation | 0.125 ms | 0.001 ms | <0.1% |
| **Cumulative total** | **502.365 ms** | **3.694 ms** | **100%** |

The peer stages sum to 490.461 ms. The 11.904-ms difference from the
cumulative total is inter-stage bookkeeping and probe overhead. Quiescence and
process-spec construction together account for 466.779 ms, or 92.9% of the
cumulative total. Dispatcher cloning, child creation, and publication do not
explain the former accounting gap.

The stage result repeats independently:

| Capture | Quiescence | Process spec | Cumulative total |
|---|---:|---:|---:|
| detail 1 | 145.093 ms | 90.576 ms | 254.039 ms |
| detail 2 | 146.999 ms | 84.110 ms | 248.326 ms |

## Quiescence polling mechanism

Across both captures, 136 forks recorded 926 polling iterations and 292.093 ms
of quiescence time: **315.4 us per recorded poll**. Six forks began with no
sibling vCPU and collectively spent only 250 ns in quiescence. The nonzero
population is schedule-dependent, but every populated group preserves the
same order-of-magnitude relationship between poll count and elapsed time.

| Initial siblings | Forks | Polls | Quiescence time |
|---:|---:|---:|---:|
| 0 | 6 | 0 | 0.000 ms |
| 1 | 34 | 335 | 104.621 ms |
| 2 | 5 | 87 | 27.056 ms |
| 3 | 15 | 109 | 34.034 ms |
| 4 | 40 | 266 | 84.517 ms |
| 5 | 29 | 115 | 37.038 ms |
| 6 | 3 | 10 | 3.257 ms |
| 7 | 3 | 3 | 1.235 ms |
| 8 | 1 | 1 | 0.334 ms |

The current implementation checks `VcpuRegistry::count`, sleeps for 200 us,
and checks again until siblings unregister or a ten-second deadline expires.
The observed 315-us cost includes the requested sleep plus scheduler wakeup.
This is direct mechanism evidence for replacing the common-case sleep poll
with notification on registry-count change. It does not prove that removing
the polling tax alone will close Phase 4's full CPU or exec-latency gaps.

## Decision

Retain the typed probes and durable consumer. The next behavior experiment is
an event-driven, lost-wakeup-safe registry wait:

1. `GenericVcpuRegistry::unregister` notifies waiters while count and the wait
   predicate share the same mutex;
2. the fork path waits until only the forking vCPU remains;
3. the existing ten-second bound remains authoritative, with periodic recovery
   kicks only for a nonresponsive sibling rather than as the common wait path;
4. red-first registry tests cover immediate success, notification wakeup, and
   timeout before the runtime path changes;
5. the same typed capture plus untraced correctness/CPU qualification decides
   retention.

Process-spec construction remains the independent second lever. Correct
single-VM isolation and bounded fork failure remain authoritative; this
evidence does not justify narrowing the global topology lock or changing HVF
map/unmap concurrency.

## Verification before commit

- Red-first typed fork-stage ABI test failed before the event and stage enum
  existed, then passed.
- Red-first cumulative-total test failed before stage 9 existed, then passed.
- Red-first typed quiescence-detail ABI test failed before its event existed,
  then passed.
- `cargo test -p carrick-observability --lib`: 54 passed.
- Focused clippy for `carrick-observability` and `carrick-runtime`: passed with
  warnings denied.
- `cargo fmt --check`: passed.
- Full `just ci`: passed after both retained captures.
