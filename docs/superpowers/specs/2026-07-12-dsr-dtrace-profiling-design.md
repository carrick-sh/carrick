# Durable DSR DTrace Profiling Design

**Date:** 2026-07-12

**Status:** Approved design; implementation pending

## Purpose

Carrick's Darwin-native dynamic syscall rewriter (DSR) has enough workload and
counter evidence to show that translation is not its dominant cost, but its
current profile cannot attribute every transition or time the important phases
without opt-in Rust counters. This design adds a durable profiling surface that
uses Carrick USDT probes and DTrace timestamps to attribute DSR preparation,
translated execution slices, exits, resolution, dispatcher work, cache events,
and fork/exec cache lifecycle.

The profiling surface must answer four questions:

1. Which typed exit kinds account for every DSR gateway return?
2. How much time is spent preparing, translating, resolving, dispatching, and
   executing translated slices?
3. Which indirect source and target PCs dominate resolver misses?
4. Which DSR-specific phases account for the native fork+exec gap?

This is diagnostics infrastructure, not a behavior change. When no DTrace
consumer enables the probes, the instrumented binary must have no statistically
detectable syscall-floor or V8 regression.

## Constraints

- Use `carrick trace`; do not introduce standalone one-off `dtrace` drivers.
- Follow the complete process tree with
  `pid == $target || progenyof($target)`.
- Keep probe closures allocation-free and limited to copied scalar arguments.
  They may not format, lock, inspect the environment, read a clock, or traverse
  runtime state.
- DTrace owns timestamps, pairing, aggregation, and sampling. Rust performs no
  hot-path timing when probes are disabled.
- Reuse existing syscall and fork probes instead of duplicating their semantic
  boundaries.
- Preserve stable numeric event kinds and a versioned output schema.
- Bound every built-in profile by both driver timeout and a DTrace tick exit.
- Traced timings describe an instrumented run. They never replace untraced
  workload performance evidence.
- The existing `CARRICK_DSR_PROFILE` counters remain an independent count
  cross-check. They are not the primary timing implementation.

## Considered approaches

### 1. USDT phase boundaries with DTrace aggregation — selected

Small USDT closures fire typed phase and event records. DTrace pairs begin/end
events using thread-local state and uses `timestamp` for elapsed time. This
keeps clock reads and aggregation out of the runtime when probes are disabled,
works across forked Carrick processes, and provides typed attribution that host
stack sampling cannot infer reliably.

### 2. More Rust counters and timers

Rust could produce JSON directly, but clock reads, branches, and aggregation on
hot transitions would perturb the performance being measured. Aggregation
across real forked processes would also require additional durable shared
state. This remains useful only as the existing opt-in count cross-check.

### 3. Existing `pid` and host `syscall` providers only

This requires no runtime changes, but `pid$target` does not follow fork/exec and
host stacks do not expose typed DSR phase or exit semantics. It is useful as a
corroborating source, not as the primary profiler.

## Probe ABI

All probes live in the existing `carrick` provider in
`carrick-observability`. Wrapper functions accept only primitive copied values
and use the generated closure form so arguments are evaluated only when a
consumer enables the probe.

### Stable kind values

DSR exit kinds reuse the runtime's existing status vocabulary:

| Value | Exit kind |
| ---: | --- |
| 1 | syscall |
| 2 | direct resolver |
| 3 | indirect resolver |
| 4 | fault |
| 5 | kick |
| 6 | sensitive instruction |
| 7 | unsupported instruction |

Cache event and lifecycle phase values are ordinal enums in Rust, with tests
pinning every numeric value. Hand-numbered call-site constants are forbidden.

### Phase pairs

Probe arguments stay under the USDT six-argument limit.

`dsr-prepare-begin(tid, guest_pc)`

- Fires before block lookup or translation for a guest entry.

`dsr-prepare-end(tid, guest_pc, cache_pc, generation, outcome)`

- `outcome` distinguishes resume-entry hit, block-index hit, translation, and
  typed failure.
- DTrace pairs this with `dsr-prepare-begin` to measure lookup and preparation.

`dsr-run-begin(tid, guest_pc, cache_pc, generation)`

- Fires immediately before entering the exception-free context gateway.

`dsr-run-end(tid, exit_kind, guest_pc, target_pc, status)`

- Fires immediately after the gateway returns and before Rust resolves or
  dispatches the exit.
- The paired duration includes gateway transport plus the translated slice.
  It is deliberately named a run slice, not pure gateway latency.

`dsr-translate-begin(tid, guest_pc, generation)`

- Fires after a block-index miss and before decode/planning/emission.

`dsr-translate-end(tid, guest_pc, generation, cache_pc, emitted_bytes, outcome)`

- Covers planning, emission, publication, and a typed failure outcome.

`dsr-resolve-begin(tid, kind, source_pc, target_pc)`

- Fires before direct or indirect resolution.

`dsr-resolve-end(tid, kind, source_pc, target_pc, outcome)`

- Covers validation, lookup, translation-on-miss, and cache publication.

### Discrete events

`dsr-cache-event(tid, kind, guest_pc, generation, used_bytes, capacity_bytes)`

- Records block-index hit/miss, target-cache publication, stale invalidation,
  block publication, and cache-capacity failure.
- The broad profiler aggregates low-cardinality `kind` counts. Guest PCs are
  consumed only by the focused indirect-site profile.

`dsr-cache-lifecycle(role, phase, used_bytes, block_count, generation_count)`

- Records child-after-fork repair, exec reset, and completion boundaries.
- `role` distinguishes parent and child when meaningful.
- DTrace correlates the next `dsr-prepare-begin` in that process to measure
  first-entry-after-fork or first-entry-after-exec. The runtime gains no
  permanent first-entry branch.

## Existing probe reuse

The profiler composes the new probes with existing observability:

- `syscall-entry` and `syscall-return` provide guest dispatcher latency and
  syscall identity.
- `fork-pre`, `fork-post`, `fork-quiesce`, `fork-rebuild`, and
  `fork-lifecycle` provide the shared process lifecycle phases.
- Darwin `syscall::fork`, `syscall::mmap`, `syscall::mprotect`, and related
  probes show time entering host kernel mechanisms.
- `profile-997` samples host stacks when a long phase may be blocked or
  spinning.

The DSR fork profile adds only the cache repair/reset and first-entry seams not
already represented by those probes.

## Built-in profiles

The trace CLI gains a typed profile selector:

```text
carrick trace --profile dsr --summary-jsonl PATH -- RUN_ARGS...
carrick trace --profile dsr-indirect --summary-jsonl PATH -- RUN_ARGS...
carrick trace --profile dsr-fork --summary-jsonl PATH -- RUN_ARGS...
```

`--profile` and `--script` are mutually exclusive, and `--summary-jsonl`
requires `--profile`. Profile scripts live under `scripts/dtrace/` for review
and are embedded into the binary with `include_str!` so Homebrew and other
installed binaries do not depend on the source tree. `--trace-out` remains
available for the raw line protocol; when omitted, the profiler uses an
internal temporary stream rather than mixing protocol records with guest
output.

### `dsr`

The broad, low-cardinality profile reports:

- counts for every exit, prepare outcome, cache event, and lifecycle event;
- count, sum, minimum, maximum, and sampled duration distributions for prepare,
  run slices, translation, resolver, and dispatcher phases;
- unmatched begin/end counts;
- cache high-water usage and capacity.

### `dsr-indirect`

The focused profile counts indirect misses by `(source_pc, target_pc)` and
source PC. It is separate because V8 can create high-cardinality target sets.
The script is time-bounded and reports its aggregation cardinality so a result
cannot silently omit a DTrace aggregation overflow.

### `dsr-fork`

The fork profile combines existing fork lifecycle probes, host fork syscalls,
DSR cache lifecycle, and the next prepare event in parent and child. It reports
quiescence, host fork, child repair, parent recovery, exec reset, first
translation, child readiness, and wait/reap timing where the existing probes
make those boundaries observable.

## DTrace aggregation and sampling

Each D script stores begin timestamps in thread-local `self->` variables and
clears them after a matching end event. A begin that overwrites an active pair
and an end without a begin increment explicit incomplete-pair counters.

All events contribute to count, elapsed sum, minimum, and maximum aggregates.
Duration distribution samples use a deterministic per-thread sequence and a
documented sampling interval, defaulting to one sample per 1,024 matching
events after the first warm sample. This bounds output for V8 while preserving
exact total counts.

The scripts emit a stable text protocol with a version prefix. They do not emit
free-form prose on the machine-readable stream. A Rust parser in the trace CLI
converts the records into JSONL and writes human summaries separately.

## JSONL schema

Every row contains:

- schema version;
- profile kind;
- run ID, git SHA, Carrick binary SHA-256, host facts, and command;
- process/thread scope;
- phase or event kind;
- exact count and incomplete-pair count;
- elapsed sum/min/max when applicable;
- sampled p50/p95/min/IQR and sample count when applicable;
- sampling interval;
- traced wall time and whether the trace reached its natural exit or bound;
- cache high-water and capacity where applicable.

Unknown protocol versions, malformed records, incomplete required provenance,
and truncated DTrace output are hard parser errors. Optional missing phase data
is represented explicitly rather than synthesized as zero.

The root trace parent writes the summary atomically and applies the original
caller's uid/gid, matching `--trace-out` ownership handling. A parser or rename
failure leaves no partially valid summary at the requested path.

## Error handling

- D-script compilation failure prevents the guest from launching and produces
  a direct trace error.
- The driver has a longer timeout than the D script so the tick-based DTrace
  exit prints final aggregates.
- The parser refuses output without a final completion record.
- Unmatched phase pairs are published in the result and exclude their duration
  from distributions.
- Forked processes are selected only with `$target` or `progenyof($target)`.
- High-cardinality profiles report aggregation entry counts and an overflow or
  truncation status.
- Profile output never changes the guest's exit status classification.

## Verification

### Static and unit gates

- Compile-time uniqueness and exact-value assertions for exit, cache-event, and
  lifecycle enums.
- Unit tests for protocol parsing, aggregation, percentile calculation,
  incomplete pairs, unknown versions, and truncated output.
- D-script compilation tests on supported macOS hosts.
- `otool -l target/release/carrick | grep dof` verifies probe registration
  survives the signed release build.
- The full local `just ci` gate remains required.

### Live correctness gates

- Signed syscall-floor profile.
- Signed direct Node/V8 generated-code profile.
- Signed Rust static-PIE fork+exec profile following all descendants.
- DTrace exit and resolver counts are reconciled with
  `CARRICK_DSR_PROFILE`; differences must be explained by documented sampling
  or lifecycle boundaries, not silently tolerated.
- A deliberately interrupted trace proves incomplete-pair and truncated-output
  reporting.

### Disabled-probe performance gate

Use pre-change and post-change signed binaries in an interleaved ABBA sequence
on the same host, with no DTrace consumer attached:

- 30 syscall-floor samples per binary;
- 10 direct V8 samples per binary;
- identical images, probe binaries, CPU exposure, and cooldown policy.

The result must show no statistically detectable regression and must publish a
practical non-inferiority interval. A suggested decision threshold is no more
than 2% syscall-floor p50 regression and no more than 1% V8 p50 regression,
with uncertainty reported. A failure triggers inspection of closure argument
construction, wrapper inlining, and probe placement; the offending probes are
reworked or reverted rather than excused.

Enabled tracing overhead is measured and published separately for each built-in
profile. It is never mixed into untraced performance claims.

## Deliverables

- Stable USDT definitions and allocation-free wrappers in
  `carrick-observability`.
- DSR probe calls at the typed runtime seams.
- Bounded built-in DTrace programs for broad DSR, indirect sites, and fork.
- Trace line-protocol parser, JSONL writer, and human summary output.
- Probe ABI and profile usage documentation.
- Parser fixtures, D-script compilation tests, signed live evidence, disabled
  overhead evidence, and enabled-overhead evidence.

## Explicit non-goals

- Optimizing DSR based on the new profile in the same implementation change.
- Replacing the existing counter profile.
- Adding a general tracing query language.
- Treating traced timings as workload benchmarks.
- Adding Linux `bpftrace` support to this macOS DTrace profile; Linux remains
  the semantic oracle and can receive a separate host-profiler design later.
