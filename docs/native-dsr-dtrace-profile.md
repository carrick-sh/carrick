# Native DSR DTrace profiles and measured baseline

**Measured:** 2026-07-12

**Scope:** Darwin-native AArch64, `native16k`, opt-in DSR

**Status:** diagnostic baseline for the
[profile-driven optimization plan](superpowers/plans/2026-07-12-dsr-profile-driven-performance.md)

Carrick exposes three supported, machine-readable DSR profiles through
`carrick trace`. They attribute translated execution without putting clocks,
formatting, allocation, or locks in disabled USDT probe closures. DTrace owns
timing and aggregation; the CLI validates the stream and atomically publishes
versioned JSONL.

These profiles identify where to optimize. They are not an untraced latency
benchmark: enabled DTrace changes absolute timing, sometimes substantially.
Counts, phase relationships, and before/after runs under the same profile are
the useful authority.

## Running the profiles

Build and sign first, and retain Apple `ld64` so the DOF section survives:

```bash
just build
otool -l target/release/carrick | grep -A2 __dof_carrick
```

The broad syscall-floor profile is:

```bash
CARRICK_RUN_ID=dsr-profile-smoke target/release/carrick trace \
  --profile dsr \
  --trace-out target/conformance/dsr-profile-smoke.raw \
  --summary-jsonl target/conformance/dsr-profile-smoke.jsonl -- \
  run-elf --raw --exec-backend native --native-page-profile native16k \
  --native-code-mode dsr \
  conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_trap_floor
```

The focused indirect-site profile is:

```bash
CARRICK_RUN_ID=dsr-indirect-v8 target/release/carrick trace \
  --profile dsr-indirect \
  --trace-out target/conformance/dsr-indirect-v8.raw \
  --summary-jsonl target/conformance/dsr-indirect-v8.jsonl -- \
  run --name dsr-indirect-v8 --max-traps 18446744073709551615 \
  --raw --fs host --entrypoint /opt/nodejs-conformance/bin/node24 \
  --exec-backend native --native-page-profile native16k \
  --native-code-mode dsr \
  localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0 \
  /opt/nodejs-conformance/fixtures/v8-smoke.js
```

The process-lifecycle profile is:

```bash
CARRICK_RUN_ID=dsr-fork-profile target/release/carrick trace \
  --profile dsr-fork \
  --trace-out target/conformance/dsr-fork-profile.raw \
  --summary-jsonl target/conformance/dsr-fork-profile.jsonl -- \
  run-elf --raw --exec-backend native --native-page-profile native16k \
  --native-code-mode dsr \
  conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_fork_exec
```

`carrick trace` auto-sudos; do not prefix it with `sudo`. Always stamp a unique
`CARRICK_RUN_ID` and clean only that run with
`scripts/sudo/kill.sh <run-id>`.

## Protocol and completion contract

The D programs emit `DSRPROF1`; summaries use
`carrick.dsr-profile.v1`. Each JSONL row repeats run provenance, scope, metric,
and completion state so a row can be interpreted independently. Exact metrics
carry counts and, when applicable, total/minimum/maximum nanoseconds. Sampled
durations carry p50, p95, minimum, IQR, sample count, and sampling interval.

A successful natural run has all of the following:

- exactly one completion record with `target_exit_reason=1` and `bounded=0`;
- no parser truncation or duplicate completion;
- zero open, overwritten, or missing-begin phase pairs;
- zero principal, aggregation, dynamic, and other DTrace drops;
- no high-cardinality overflow.

Malformed records, an unknown protocol version, missing completion, and a
truncated stream are hard errors. `SIGINT` retains an explicitly requested raw
trace but does not publish a successful summary; the live PTY proof returned
`profile stream is missing its completion record` and left no stamped guest
process. This fail-closed behavior prevents partial profiles from becoming
performance evidence.

The broad profile samples durations every 1,024 events while retaining exact
count/total/minimum/maximum aggregates. `dsr-indirect` keeps one aggregation key
per source and source-target pair, and exposes cardinality and aggregation
drops. `dsr-fork` records every lifecycle interval rather than sampling it.

## Measured optimization targets

The raw live summaries were complete natural runs with zero drops and
incomplete pairs. They are local diagnostic artifacts under
`target/conformance/`; the checked-in overhead files below preserve the
performance guardrail and full host/binary provenance.

### Normal translated loop

The broad `perf_trap_floor` profile at `be441fa2` reconciled 45,427 gateway
slices:

| Phase | Count | Total | Mean | Interpretation |
| --- | ---: | ---: | ---: | --- |
| prepare | 45,427 | 66.79 ms | 1.47 us | repeated entry selection; largest DSR-side aggregate |
| run | 45,427 | 57.95 ms | 1.28 us | translated gateway entry and exit |
| dispatcher | 44,047 | 40.57 ms | 0.92 us | shared syscall layer, not initially a DSR target |
| resolve | 1,352 | 14.46 ms | 10.70 us | miss path, including downstream work |
| translate | 1,372 | 10.52 ms | 7.67 us | nested in prepare and resolve paths |

Prepare is dominated by 45,140 `BlockIndexHit` outcomes consuming 66.08 ms;
only 264 preparations use `ResumeEntryHit`. The first normal-loop experiment
therefore makes the typed last-prepared entry persistent and generation
validated.

#### Accepted prepare result

Commit `23993da4` makes the existing thread-local
`(GuestVa, CodeGeneration, CacheVa)` entry persistent. Every fallback
translation or process-index lookup publishes the tuple; a matching PC reuses
it only while the executable-page generation still matches. Key/generation
mismatches discard it, and fork/exec retain their existing clears.

Against signed baseline `a0b22a2e`, fixed ABBA evidence measured:

| Workload | Baseline p50 | Candidate p50 | Ratio estimate | 95% interval | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| syscall floor, n=30 each | 0.705 us | 0.678 us | 0.9603 | 0.9342–0.9891 | pass |
| direct V8, n=10 each | 7933.22 ms | 7908.30 ms | 0.9967 | 0.9927–1.0022 | pass against 1.01 |

The automatically enabled broad profile recorded 44,250 `ResumeEntryHit`,
1,151 `BlockIndexHit`, and 23 `Translated` outcomes. Relative to the starting
264 resume hits and 45,140 block hits, 43,986 outcomes—97.4% of the former
block-hit volume—moved to the validated thread-local path. The profiled prepare
aggregate fell from 66.79 ms to 38.46 ms, but this enabled-DTrace number is
diagnostic; the untraced 3.97% syscall-floor estimate is the promoted
performance claim.

The evidence, including signed hashes/inodes and power context, is checked in
as
[`native-dsr-prepare-cache-v1.jsonl`](perf-results/native-dsr-prepare-cache-v1.jsonl).
The red/green unit proof and canonical mutation test show that generation
changes cannot reuse the stale prepared entry. A four-entry fallback is not
warranted.

### Indirect-heavy V8

The direct V8 profile at `281417c8` captured 416,997 successful resolver exits,
10,159 source sites, 44,826 source-target pairs, and 41,152 distinct missed
targets. Source, pair, outcome, and total aggregates each sum to 416,997.

The current cache has 1,024 direct-mapped entries indexed by guest-PC bits 2
through 11. Every bucket saw at least 22 distinct missed targets; the largest
saw 71. The two hottest targets both alias bucket 154 and generated 10,393 and
10,377 resolver exits. The top 100 sources account for 161,932 exits (38.8%);
the top 1,000 account for 353,986 (84.9%). This supports a bounded cache-layout
experiment rather than a special case for one source.

The profile observes resolver exits, which are misses. It does not count
fast-path indirect hits, so these data cannot state a miss rate. A cache change
must reduce resolver exits and independently improve untraced V8 wall time.

#### Accepted cache result

Commit `f70ec7f8` expanded the direct map from 1,024 to 8,192 entries (exactly
256 KiB per guest thread) and changed the index from page-offset bits to
`((guest ^ (guest >> 12)) >> 2) & 8191`. Rust publication and emitted AArch64
use the same formula; entry layout, release publication, fork/exec clearing,
and target generation guards are unchanged.

Against signed baseline `905b2c11`, the fixed ABBA V8 gate measured:

| Metric | Baseline | Candidate | Decision |
| --- | ---: | ---: | --- |
| direct V8 p50, n=10 each | 7982.07 ms | 7883.38 ms | ratio 0.9869, 95% interval 0.9674–0.9993; pass |
| successful resolver exits | 416,997 | 132,213 | down 68.3% |
| distinct missed targets | 41,152 | 41,151 | effectively unchanged workload surface |
| monomorphic indirect p50, n=30 each | 7.335 ns | 7.196 ns | ratio 0.9804, interval 0.9434–1.0031, limit 1.02; pass |

The candidate profile completed naturally with `target_exit_reason=1`, zero
drops, zero incomplete pairs, 9,516 source sites, and 43,030 source-target
pairs. The wall-time and hit-path samples, signed binary hashes, inodes,
codesign output, host/power context, and bootstrap policy are checked in as
[`native-dsr-indirect-cache-v1.jsonl`](perf-results/native-dsr-indirect-cache-v1.jsonl)
and
[`native-dsr-indirect-cache-hit-v1.jsonl`](perf-results/native-dsr-indirect-cache-hit-v1.jsonl).
The large miss reduction translating into a smaller end-to-end win is expected:
V8 also spends time in guest computation, translation, syscalls, and startup.

### Fork and exec

The static-PIE fork/exec profile at `87a63918` captured 220 samples in each
lifecycle class:

| Interval | p50 | p95 |
| --- | ---: | ---: |
| child repair | 22.52 us | 26.42 us |
| first prepare after fork | 4.21 us | 5.75 us |
| exec replacement/reset | 1.581 ms | 1.685 ms |
| first prepare after exec | 12.46 us | 15.88 us |

The outer exec interval begins before native image replacement and ends after
translator installation. It includes mapping, protection, relocation, and
handoff work in addition to cache reset. It is a real long pole, but it must be
subdivided before selecting an implementation.

## Instrumentation overhead

The disabled-probe gate compares distinct signed binaries in fixed ABBA order
with 10,000 seeded bootstrap resamples. It ran on a `Mac16,12` with ten logical
CPUs and macOS 27.0. The baseline is commit `fcd17c14`, SHA-256
`68c0e15bbe55e80c4ec6d24c77701fd146b5f14107fddbbb9958476c325e45f3`;
the instrumented candidate is `8fdf8c9d`, SHA-256
`91ded2b3eaab39597a570b15ef29436e6372a1f250d22909264496bfc39a4c3e`.

| Disabled workload | Baseline p50 | Candidate p50 | Ratio estimate | 95% interval | Limit | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| syscall floor, n=30 each | 0.703 us | 0.697 us | 0.9908 | 0.9803–1.0050 | 1.02 | pass |
| direct V8, n=10 each | 8026.50 ms | 8027.66 ms | 1.0015 | 0.9952–1.0059 | 1.01 | pass |

Full samples and codesign provenance are in
[`native-dsr-dtrace-disabled-overhead.jsonl`](perf-results/native-dsr-dtrace-disabled-overhead.jsonl).
These results bound the disabled instrumentation cost; they do not prove that
it is exactly zero.

Enabled profiles are report-only diagnostics. The current artifact was
refreshed on signed commit `5724f9a6`, where `--profile dsr` automatically
enables its const-specialized prepare/run probes before sudo and traced-child
creation:

| Enabled profile/workload | Untraced p50 | Profiled p50 | Ratio estimate | 95% interval |
| --- | ---: | ---: | ---: | ---: |
| broad / syscall floor, n=4 each | 68.63 ms | 1231.99 ms | 17.04 | 16.08–19.89 |
| indirect / direct V8, n=4 each | 7682.31 ms | 8879.72 ms | 1.155 | 1.142–1.173 |
| fork / fork-exec, n=4 each | 1385.16 ms | 2879.93 ms | 2.074 | 2.034–2.128 |

Full samples are in
[`native-dsr-dtrace-enabled-overhead.jsonl`](perf-results/native-dsr-dtrace-enabled-overhead.jsonl).
The refreshed run remained on AC power, but four samples per role are still too
few for a portable overhead claim. The values quantify this recorded
diagnostic run and explain why profile nanoseconds are not substituted for
untraced workload measurements.

## Optimization order and proof rule

After promoting the indirect and prepare caches, the remaining measured queue
is:

1. exec subdivision, followed by the largest reproducible subphase;
2. a low-perturbation scalar/SIMD gateway benchmark;
3. translation/publication, reprofiled after cache misses fall.

Every candidate starts with a deterministic red mechanism test, runs focused
correctness plus a signed workload, and receives a fixed-order ABBA comparison
with a seeded bootstrap interval. A plausible change without a supported wall
time improvement is rejected or revised; it is not promoted on profile counts
alone. Fork, generation, signals/faults, and Go/Rust static and PIE behavior
remain correctness gates. Linux comparisons run separately from Carrick and
remain the semantic oracle.
