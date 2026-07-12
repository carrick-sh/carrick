# Native DSR DTrace profiles and measured baseline

**Measured:** 2026-07-12

**Scope:** Darwin-native AArch64, `native16k` (DSR-only)

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

The added non-overlapping exec subphases then produced two complete 220-exec
runs. Image mapping/protection/vvar was stable at 61.7% and 61.8% of outer
time, with cache reset second at 26.7% and 27.0%; every other named phase was
below 6%. This selected image mapping for the first fixed-gate experiment.

Skipping the two host I-cache publications for DSR source mappings produced a
real but insufficient effect. Across matching complete profiles,
`exec-image-map` p50 moved from 1.0439 ms to 1.0073 ms (ratio 0.9649, 3.5%
gain), while outer `exec-reset` moved from 1.6990 ms to 1.6683 ms (ratio
0.9819, 1.8% gain). Outer p95 was effectively flat/slightly worse at ratio
1.0020. Both missed the precommitted 10% gates, so the cache publications were
restored. This narrows the next mapping profile: `mmap`, byte copy, cache
publication, final protection, and vvar work must be separated before another
structural change. Compact provenance and results are in
[`native-dsr-exec-icache-v1.jsonl`](perf-results/native-dsr-exec-icache-v1.jsonl).

The follow-up nested profile reconciled five mapping details against all 220
outer image-map intervals in each of two runs. Both runs had identical pid/tid
sets, natural completion, zero drops/incomplete pairs, and no negative
residual. Byte copy ranked first at 61.94% and 62.25% of profiled image-map
p50; unaccounted construction was about 19%, Darwin mapping about 9.2%, final
protection about 4.2%, I-cache publication about 3.7%, and vvar work about
1.9%. This rank is stable and selects copy for further proof.

The nested probes raise `perf_fork_exec` p50 from roughly 11.2 ms to roughly
14.0 ms, so the component magnitudes are diagnostic attribution, not untraced
cost claims. The selected copy plan must first replace repeated DTrace
boundaries with low-perturbation aggregate timing before authorizing a backing
representation change. Exact distributions and raw-profile hashes are in
[`native-dsr-exec-map-decomposition-v1.jsonl`](perf-results/native-dsr-exec-map-decomposition-v1.jsonl).

The replacement aggregate profiler removes the repeated probe boundaries and
reads the monotonic clock only in runtime-profile mode. Two further 220-exec
runs assign 89.34% and 88.43% of image-map p50 to copy: 8,904,704 bytes in six
operations per exec. Aggregate profiled guest p50 falls to 12.10 ms and
12.18 ms from the nested profiler's 14.18 ms and 13.97 ms, satisfying the 10%
overhead-reduction gate while strengthening the copy attribution.

The 8.9 MiB payload is much larger than the 517 KiB fixture. Code inspection
confirms `build_linux_initial_stack` materializes the full 8 MiB stack even
though initialized argv/env/auxv data occupies only the suffix beginning at the
initial stack pointer. Fresh Darwin anonymous mappings are already zero-filled,
so the next candidate copies only that initialized suffix. Exact aggregate
durations, byte/operation totals, and hashes are in
[`native-dsr-exec-map-aggregate-v1.jsonl`](perf-results/native-dsr-exec-map-aggregate-v1.jsonl).

#### Accepted initialized-stack copy result

Commit `7e28af59` uses the authoritative initial SP to copy only the initialized
suffix of the exact canonical 8 MiB stack into its already-zero Darwin mapping.
All other regions and ambiguous stack shapes retain the full copy path. Copy
volume falls from 8,904,704 to 516,816 bytes. Across two complete profiles,
image-map p50 falls by 84.8% and 85.0%, and outer exec-reset p50 falls by 52.5%
and 52.3%.

The signed ABBA gate measures a larger end-to-end result than the rejected
I-cache experiment: fork-exec wall p50 falls from 1391.52 ms to 1145.79 ms
(ratio 0.8229, interval 0.8119–0.8354). Direct V8 passes at ratio 1.0023 with
upper 1.0065. A 16-call batched syscall-floor metric fixes the single-call
counter-resolution problem without moving the 1% limit; it passes at ratio
0.9980 with interval 0.9939–1.0031. Signed Rust static/dynamic PIE, Go PIE,
direct V8, vfork, non-leader exec, and stack/SP proofs are green. Compact
evidence and raw hashes are in
[`native-dsr-stack-window-v1.jsonl`](perf-results/native-dsr-stack-window-v1.jsonl).

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

After promoting the indirect cache, prepare cache, stack-copy window, and
gateway closure, the remaining measured queue is:

1. translation/publication, reprofiled after cache misses and fixed gateway
   work have fallen;
2. broader decode/dispatch and native-return attribution if translation is no
   longer a stable long pole.

The gateway experiment deliberately kept DTrace off the hot boundary. Exact
release component benchmarks attributed 0.201 us of the 0.211 us closure to
the paired `pthread_sigmask` calls. The promoted deferred-kick design reduces
the scalar gateway from 0.471 to 0.273 us and the batch-16 syscall floor from
0.486 to 0.281 us; SIMD and direct V8 also improve. The mechanism, fixed-order
ABBA intervals, and correctness proofs are recorded in
`perf-results/native-dsr-gateway-candidate-v1.jsonl`.

Translation follow-up (2026-07-12) used typed decode, plan, emit,
publication/index, and duplicate-wait boundaries across syscall-floor, V8, JIT
rewrite, and concurrent first-publication workloads. Emit reached about 14.4%
of the two short code-churn walls but only about 4% of syscall-floor and V8
wall. Two 30-process release decompositions then bounded guarded emission at
1.666/1.667 us p50: dynasm is about 12%, MAP_JIT publication 7.5%, bad64 decode
5%, and byte reshaping 2%. No isolated candidate reaches the 10% emit gate;
the area stops without production churn. Exact evidence is in
`perf-results/native-dsr-translation-subphases.jsonl` and
`perf-results/native-dsr-emission-components-v1.jsonl`.

## Final campaign and remaining architecture

The campaign promoted four measured changes:

- the indirect resolver cache reduced direct-V8 wall p50 from 7982.07 to
  7883.38 ms (ratio 0.9869, 95% interval 0.9674-0.9993);
- the persistent prepared-entry cache reduced the syscall-floor p50 from 0.705
  to 0.678 us (ratio 0.9603, interval 0.9342-0.9891);
- copying only the initialized initial-stack suffix reduced fork-exec p50 from
  1391.52 to 1145.79 ms (ratio 0.8229, interval 0.8119-0.8354);
- deferred host-window kicks reduced scalar gateway p50 from 0.471 to 0.273 us
  and batch-16 syscall-floor p50 from 0.486 to 0.281 us. The respective ratio
  intervals are 0.5778-0.5860 and 0.5742-0.5798.

Two paths stopped on their declared thresholds. Removing source-mapping I-cache
publication improved image-map p50 by only 3.5% and exec-reset by 1.8%, below
the 10% gate, so it was restored. Emission decomposition found no isolated
candidate projecting to a 10% guarded-emission gain: dynasm preallocation
projects 6.4-6.5%, a 16-block write window 5.9%, and direct bytes below 2%.
`bad64` decode is about 5% of guarded emission and is not a current performance
priority.

The final signed broad profile records a 0.281 us batch-16 syscall floor,
210,667 prepared-entry hits, 1,443 translations, and 7.24 ms total emission.
The V8 indirect profile records 131,953 successful resolver exits. The fork
profile completes 200 iterations at 11.078 ms p50. All three runs ended
naturally with zero DTrace drops and incomplete pairs.

The correctness handoff covers Rust static PIE and dynamic glibc PIE, Go static
PIE and dynamic glibc PIE, direct V8, JIT rewrite and concurrent first
publication, non-leader exec, and vfork/exec. The Go static-PIE proof runs a
goroutine-backed HTTP server/client through graceful shutdown. A fixed-address
Linux ET_EXEC below 4 GiB remains outside the Darwin-native address model
because Mach-O reserves that range with `__PAGEZERO`; this is distinct from
static linking, which is proven with static PIE.

Translation is now bounded rather than presumed to be the broad pole: the
low-perturbation V8 aggregate attributes about 5.6% of wall to all translation
and about 4% to emission. The next plan should attribute translated execution
and native-return time outside translation across V8 and syscall-heavy
workloads. `ProcessTranslator` still serializes translation state, but the
concurrent campaign observed no duplicate publication or wait; changing that
architecture requires a reproducer that first proves contention. Focused fork,
vfork, exec, and 200-iteration lifecycle gates are green, but they are not a
claim of complete fork correctness. The complete machine-readable handoff is
[`native-dsr-profile-driven-final.jsonl`](perf-results/native-dsr-profile-driven-final.jsonl).

Every candidate starts with a deterministic red mechanism test, runs focused
correctness plus a signed workload, and receives a fixed-order ABBA comparison
with a seeded bootstrap interval. A plausible change without a supported wall
time improvement is rejected or revised; it is not promoted on profile counts
alone. Fork, generation, signals/faults, and Go/Rust static and PIE behavior
remain correctness gates. Linux comparisons run separately from Carrick and
remain the semantic oracle.
