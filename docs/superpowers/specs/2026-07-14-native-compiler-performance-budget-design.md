# Native Compiler Performance Budget Design

**Date:** 2026-07-14

**Status:** design for review

**Campaign:** native-default conformance, after the approved Task 8 correctness
checkpoint at `145f3f54`

## Problem

Native correctness laddering is blocked by execution cost that is itself a
correctness failure:

- `go-go_internal_srcimporter` was stopped after 1,392.649 seconds, 516.56x
  its 2.696-second Docker oracle, with 42 Carrick processes, 19 runnable, and
  no compiler child complete;
- the exact `TestImplicitsInfo` reducer reaches Carrick's 1,000,000-gateway-exit
  ceiling after 15.90 seconds;
- a direct one-file cgo generation did not complete inside three minutes;
- the content-green Node rows remain 18.96x to 29.33x their Docker oracle.

Raising timeouts or the gateway-exit ceiling would hide the defect. Continuing
the full Go, CPython, or workers=4 ladders would turn a known architectural
problem into hours of noisy evidence.

The retained 45-second DTrace profile establishes useful shape but not an
additive wall budget. Across 14 PIDs it recorded:

- 143,390 native DSR gateway exits;
- 5,096 syscall exits;
- 49,604 direct-resolver exits;
- 22,749 indirect-resolver exits;
- 65,819 sensitive-instruction exits;
- 122 kick exits;
- 67,199 block misses/publications and 117,707 block-index hits;
- 1.678 seconds translating, 1.919 seconds resolving, 0.308 seconds preparing,
  0.317 seconds dispatching syscalls, and only 0.198 seconds inside the measured
  translated-run intervals.

The large unaccounted traced wall is principally DTrace event tax outside the
timed intervals. The counts remain valid proportional evidence; traced wall is
not absolute authority. More importantly, the event mix shows why an AOT cache
cannot yet be selected as the primary solution: it may reduce cold translation
and first resolution, but it does not remove recurring sensitive exits and may
not remove indirect resolution.

## Goal

Build a reproducible, additive native compiler performance budget, identify the
dominant execution term, fix that term without weakening Linux semantics, and
clear a hard real-workload gate before resuming Task 8.

The hard unblock is:

1. the reduced compiler/import workload completes without a gateway-exit
   ceiling;
2. its untraced Carrick/Docker p50 ratio is strictly below 20x;
3. the first target is at most 10x;
4. bounded fan-out completes without hangs, orphans, or superlinear collapse;
5. all signed correctness and code-quality gates remain green.

Near-parity remains the long-term objective. The 20x threshold is an unblock,
not a performance bless.

## Non-goals

- HVF/VMM performance is out of scope.
- Do not raise `max_traps`, scaled deadlines, or workload timeouts as a fix.
- Do not reduce Go's required work or fan-out to make the row green.
- Do not implement a persistent/AOT cache until measured cold work meets the
  decision rule below.
- Do not approximate AArch64 exclusive or signal semantics for speed.
- Do not read Linux kernel or other GPL implementation source.
- Do not mix Carrick and Docker execution phases.

## Approaches considered

### 1. Additive budget, then dominant-term repair — selected

Freeze exact workloads, collect untraced wall/CPU authority, collect low-tax
in-process counters, use DTrace for proportional phase/order evidence, and fix
the largest exclusive category. This distinguishes gateway volume from the
cost of each gateway exit and prevents an attractive but incomplete cache
project from becoming the default answer.

### 2. Persistent/AOT DSR cache now — rejected as the first move

The workload creates many cold per-process caches, so shared immutable
translation may eventually help. Current evidence does not show it dominates:
translation plus resolution was about 3.6 traced seconds out of 45, while
65,819 sensitive exits remain unaffected. Persisted code also embeds native
layout bias, gateway addresses, host pointers, generation assumptions, and
direct-link state. A safe relocatable cache needs its own later design.

### 3. Raise limits and resume conformance — rejected

Allowing tens of millions of gateway exits would make some cases finish while
preserving the 20x–516x defect. It would also make load failures take longer to
classify.

## Workload authority

The performance interlude uses three immutable workload manifests. Each
manifest records source SHA, signed Carrick SHA-256/CDHash, rootfs/image
identity, guest executable and input hashes, argv, environment, page profile,
`max_traps`, host model/OS/CPU count/power state, and Docker command.

### W1: bounded import reducer

Use the existing exact command:

```text
/conformance/go_types.test -test.v -test.run '^TestImplicitsInfo$' -test.short
```

This is the stable one-million-exit control. Before the dominant fix, measure
time and event mix to the ceiling. After the fix, require natural completion.

### W2: single compiler/cgo reducer

Capture the exact direct `linux_arm64/compile` or `cgo` child command, complete
environment, and all input file hashes from W1/c94. Run one compiler child with
no Go test fan-out. Prefer the smallest captured command that exercises the
same exit mix and completes under Docker. A `-h` usage invocation is only a
startup control and cannot be the promotion workload.

Create two variants from the same manifest and inputs:

- unchanged W2 is the performance authority;
- W2-one-thread sets `GOMAXPROCS=1` only as an additive diagnostic control.

Both must produce identical output/status. The one-thread variant does not
replace or weaken the unchanged workload gate.

### W3: compiler fan-out

Run the frozen W2 command at concurrency 1, 2, 4, 8, and 20 through a
deterministic guest-side launcher. Preserve identical work per child. This
separates single-process execution cost from scheduler/cache/process scaling
without changing c94 semantics. Do not run W3 until W2 completes naturally.

After W1–W3 clear their gates, rerun exact c94 as the real-workload authority.

## Three evidence planes

### Plane A: absolute untraced authority

Run the signed binary with neither DTrace nor in-process profiling. Record at
least five repetitions in fixed interleaved baseline/candidate order, one
warm-up discarded per binary. Capture:

- wall, user, and system time;
- exit status and complete work units;
- peak RSS;
- process count and peak concurrent children;
- gateway-limit result;
- scoped descendant cleanup.

Docker runs occur only after all Carrick processes stop. Docker provides the
exact-source ratio, not the Carrick A/B confidence test.

### Plane B: low-tax in-process native budget

Extend the existing profiling-only DSR path rather than timing production hot
paths unconditionally. Emit one versioned, machine-parseable record per native
thread/process with exact counters and exclusive accumulated durations:

- loop iterations/gateway exits by `DsrExitKind`;
- sensitive exits by `SensitiveKind`, especially `Exclusive`;
- prepare split into index hit, translation, and one-entry reuse;
- direct and indirect resolver exits, cache hits, and misses;
- translated-run time;
- finish-exit/recovery time;
- sensitive-emulation time;
- syscall dispatcher time and syscall counts;
- loop/quiesce bookkeeping time;
- process/self-reexec startup count and time;
- blocked/off-CPU time where it can be measured without polling.

Use a monotonic host tick source and profiling-gated counters. Never take a new
subsystem lock solely to record a metric. Profile-off behavior must compile to
the existing path. Measure profiling tax with an off/on ABBA run. Counts remain
authoritative if timing tax is high; in-process duration proportions are used
only when the p50 tax is at most 10%.

The report must reconcile every loop iteration into exactly one exit kind and
must reject missing, duplicate, overflowed, or incomplete records.

### Plane C: proportional DTrace attribution

Reuse `carrick trace --profile dsr` and extend it only where Plane B identifies
an unobservable boundary. Require natural/bounded completion metadata, no
incomplete pairs, no drops, and per-PID reconciliation. DTrace magnitudes may be
inflated; counts, ordering, exit mix, and relative distribution shape are the
accepted evidence.

## Additive budget model

For W2-one-thread, the additive wall budget is:

```text
wall
  = translated guest run
  + prepare/translation/index lookup
  + resolver/finish-exit
  + sensitive emulation
  + syscall dispatch
  + fork/self-reexec/process startup
  + loop/quiesce bookkeeping
  + blocked/off-CPU residual
```

Nested measurements are reported separately and never summed twice. The
analyzer emits both measured exclusive terms and an explicit residual:

```text
residual = wall - sum(exclusive measured terms)
```

A negative residual or a reconciliation difference above 2% invalidates the
run.

For unchanged W1/W2 runs with multiple guest threads, do not sum thread wall
intervals against process wall. Report per-thread exclusive terms, aggregate
thread CPU, and the critical-path process wall separately. Compare the summed
on-CPU budget to measured user+system CPU, with its own explicit residual.

For W3, wall is not additive across parallel children. Report aggregate CPU,
per-child work, throughput, and concurrency efficiency separately. Collect at
least ten one-worker child samples before using its p95 as the load baseline;
higher-concurrency runs may contribute their individual child samples to the
same fixed-order block.

## Decision rules

Choose the first implementation slice from measured evidence:

- If one sensitive kind is at least 30% of gateway exits, reduce that boundary
  first. For `Exclusive`, investigate faithful translated exclusive regions or
  typed atomic lowering; do not replace Linux atomics with a coarse lock.
- If direct/indirect resolution is at least 30% and the same PCs recur after
  warm-up, repair link/cache behavior before adding persistence.
- If cold translation and first resolution together are at least 30% of
  untraced CPU time, design a relocatable shared/AOT artifact. Its cache key
  must include guest content, page profile, translator ABI, host ISA/features,
  and all relocation assumptions.
- If syscall dispatch is at least 30%, rank exact syscall numbers and fix the
  dominant Darwin translation path.
- If blocked/off-CPU residual is at least 30%, diagnose scheduler/parking and
  wake ownership before touching translation.
- If no term reaches 30%, take the smallest two-term slice that explains at
  least 60% and verify them independently.

No implementation may be selected only from DTrace wall time.

## Load gate

W3 must satisfy all of the following before c94 resumes:

- every child completes with identical output/status;
- no Carrick descendants remain after each run;
- aggregate throughput is non-decreasing from 1 to 2 to 4 to 8 workers;
- median per-child latency at 8 workers is no more than 2x the one-worker
  median;
- p95 per-child latency at 20 workers is no more than 3x the one-worker p95;
- CPU work per completed child at 20 workers is no more than 1.5x the
  one-worker value;
- no load-only correctness flip, trap ceiling, deadlock, or timeout occurs.

If host saturation makes a ratio statistically ambiguous, repeat the complete
fixed-order block. Do not weaken the gate from a single noisy run.

## Correctness and promotion gates

Every performance fix is red-first against the selected metric and must retain:

- the exact W1/W2 output and Docker semantics;
- DSR oracle and emitted-code tests for the changed instruction class;
- signed native exec/thread/signal reducers affected by the change;
- `just ci`;
- current prepared-image exact-byte and lifecycle gates;
- zero scoped leftovers.

The performance interlude ends only when:

1. W1 and W2 complete naturally;
2. W1/W2 Carrick-to-Docker p50 is below 20x, with at most 10x as the first
   target;
3. W3 passes the load gate;
4. exact c94 completes and is below 20x Docker;
5. Node's successful rows no longer exceed 20x;
6. no prepared-image fork-only or fork-exec regression is introduced.

Then resume Task 8 at the remaining Go rows, followed by CPython and workers=4.
The original prepared-image ABBA promotion gate remains a later independent
gate; this interlude does not replace it.

## Failure handling

- Every run has a unique `CARRICK_RUN_ID` and scoped cleanup receipt.
- A quiescent or deadline-stopped process gets a real core and `bt all` before
  cleanup; active CPU-bound work is not labeled deadlock.
- Missing counters, DTrace drops, incomplete pairs, dirty provenance, failed
  work units, or Carrick/Docker overlap invalidate the run.
- Measured results and projections remain separate in the campaign ledger.
- A failed optimization is recorded and reverted rather than hidden behind a
  higher limit or baseline exception.

## Expected first measurement

The retained trace suggests the first budget will be dominated by gateway
volume rather than translation milliseconds. Resolver exits plus sensitive
exits account for 138,172 of 143,390 recorded gateway exits. This is a
hypothesis to test with Plane B, not permission to implement exclusive lowering
or cache persistence before the profile reconciles.
