# Darwin native wall-time attribution campaign

**Date:** 2026-07-27  
**Status:** approved by the active goal for planning and execution  
**Scope:** Darwin/AArch64 native DSR; cold-GOCACHE `go-build`

## Purpose

Cut Carrick's wall-clock overhead on the cold-GOCACHE Go-build reference
workload by explaining the dominant costs, proving bounded structural
optimizations, and retaining only repeatable untraced wins.

The first milestone is to halve the freshly measured Carrick/Docker wall-time
ratio. The destination is a ratio at or below 2.0. The checked-in 19,485 ms
Carrick median and 942 ms Docker result imply a historical ratio of 20.68x, but
that ratio is context rather than the campaign baseline: both sides must be
rerun under the fixed protocol before numeric targets become official.

Node V8 smoke and CPython threading/subprocess are correctness and broad
performance guardrails. They do not dilute the Go-build primary metric into a
multi-workload aggregate.

## Fixed decisions

- The primary workload is exactly the hello-world `go build` exercised by
  `scripts/perf/native_go_build.py`, with a new `GOCACHE` for every sample.
- Carrick and native-arm64 Docker run in separate phases and never concurrently.
- Performance claims come only from untraced runs on an accepted idle-host
  preflight. Enabled DTrace timing is diagnostic.
- DTrace follows the launch-owned process tree. An `execname == "carrick"`
  census is not sufficiently scoped because it can admit unrelated work.
- Sampling is the time-attribution mechanism. High-frequency USDT boundaries
  may supply exact counts, but may not bracket time on a path with millions of
  events.
- Each retained optimization removes a measured cost and wins the predeclared
  untraced gate. Plausible code, fewer internal events, or a faster microprobe
  alone is insufficient.
- Guest-visible correctness remains governed by the native-arm64 Docker oracle.
  No Linux kernel or other GPL implementation source is consulted.
- Historical findings are hypotheses until refreshed on the current binary.

## Measurement contract

### Official wall-time baseline

The baseline records five successful Carrick samples followed by five
successful Docker samples. Each sample:

1. starts from the same source, image, command, working directory, and exposed
   CPU policy;
2. uses a unique empty `GOCACHE`;
3. proves the output binary ran and printed the expected marker;
4. records monotonic wall time, exit status, run ID, binary/image provenance,
   commit and dirty state, host/power state, and preflight findings;
5. cleans up only its stamped run ID.

The baseline fields are:

- `C0`: Carrick five-sample median;
- `D0`: Docker five-sample median;
- `R0 = C0 / D0`: official starting ratio;
- initial milestone: `R <= R0 / 2`;
- destination: `R <= 2.0`;
- destination progress:
  `clamp((R0 - R) / (R0 - 2.0), 0, 1)`.

The 19,485/942 historical pair is reported separately until this protocol
produces `C0` and `D0`.

### Whole-tree DTrace attribution

One traced run cannot turn summed thread time into wall time when compiler
processes overlap. The profile therefore has four reconciled planes:

1. **Elapsed wall:** target launch through natural process-tree completion.
2. **Wall-state occupancy:** a single periodic sampler partitions elapsed time
   into:
   - at least one tracked thread on CPU;
   - tracked work runnable but descheduled;
   - every live tracked thread sleeping;
   - transition/unclassified.
3. **On-CPU resource time:** prime-rate samples across tracked threads,
   classified into:
   - translated guest/JIT execution;
   - DSR translate/decode/plan/emit/publication;
   - gateway prepare/resolve/finish/recovery;
   - syscall dispatch and host runtime;
   - process/capsule/exec setup;
   - Darwin kernel;
   - other Carrick host code;
   - unresolved.
4. **Off-CPU resource time:** voluntary-block duration and blocking stacks,
   plus runnable-descheduled duration. These totals explain wait mechanisms and
   scheduling pressure, but are not added as serial wall time.

The traced process set is seeded from `$target`, extended through
`proc:::create`, retained across `exec`, and removed on exit. Image
announcements and samples must be admitted by that set. Raw PCs are keyed by
PID because self-reexec changes ASLR slides.

The first attribution is accepted only when:

- the target completes naturally and the expected build marker is present;
- there are zero DTrace drops and no truncated completion;
- process create/exit and live-set counts reconcile;
- wall-state buckets account for at least 99% of elapsed samples;
- at least 90% of on-CPU samples are assigned to the declared categories;
- the top reported blocking stacks account for at least 80% of voluntary
  off-CPU resource time;
- two complete runs agree on the rank of dominant categories, and every
  category above 10% differs by no more than five percentage points or carries
  an explicit instability finding.

If the existing D programs cannot satisfy these checks, the campaign fixes the
measurement before drawing an optimization conclusion.

### Hypothesis and spike protocol

Every hypothesis enters the ledger with:

- the observation and evidence that created it;
- the measured share or exact event count;
- a calculated upper-bound win if the cost vanished;
- the proposed structural mechanism;
- a bounded spike and stop condition;
- correctness risks and focused proof;
- traced diagnostic result;
- untraced screening and promotion results;
- `PROPOSED`, `SPIKING`, `RETAIN`, `REJECT`, or `DEFER` status.

A quick spike is deliberately disposable:

1. predeclare the expected mechanism, counter movement, wall-time direction,
   and a time/variant bound;
2. add the smallest focused correctness proof necessary to run it safely;
3. screen with two alternating untraced control/candidate samples;
4. reject a spike that does not move its mechanism or produces no credible
   end-to-end signal;
5. promote a credible spike to five control and five candidate samples.

A candidate is retained when the five-sample median ratio is at most 0.97 and
the bootstrap 95% upper bound is below 1.0. A smaller apparent win requires a
second independent five-plus-five campaign; both medians must favor the
candidate and the pooled upper bound must remain below 1.0. Correctness failure
always rejects the candidate regardless of speed.

After a retained wave, `C`, `D`, and `R` are refreshed. Docker may be reused
only when its provenance and host state remain comparable; otherwise both
sides are rerun.

## Progress ledger

The durable controller is
`docs/perf-results/native-wall-time-campaign.md`. It contains:

- milestone state and ratio arithmetic;
- an evidence registry with hashes/paths and validity;
- current wall-state and CPU/off-CPU attribution tables;
- the ordered hypothesis backlog;
- the spike decision log, including rejected experiments;
- correctness and end-to-end verification receipts;
- the next measurement or experiment.

Raw and summarized measurements live under `scripts/perf/evidence/` with
versioned schemas. The ledger links them rather than copying unverifiable
numbers. `handoff.md` points to the ledger and states the current next action.

## Initial hypothesis backlog

These are not yet ranked by current wall attribution:

1. **Residual indirect exits:** the current profile still records 862,580
   indirect resolver exits; a return-target structure may keep call/return flow
   in translated code.
2. **Translation emission:** the current internal profile assigns 5.806 s to
   emission across 1.868 million translations; allocation, relocation,
   publication and I-cache work need separation.
3. **Repeated process setup:** older samples assigned material CPU to serde,
   executable hashing, mountpoints and argument parsing across self-reexec;
   the attempted Clap/bincode shortcut was neutral, so the current cost and
   critical-path relevance must be re-established.
4. **Coarse shared translation:** cross-process reuse is correct but current
   signing/dlopen and late publication regress wall time. Only a coarse,
   early-published unit with a favorable measured production/consumption
   balance may re-enter.
5. **Scheduler and blocking amplification:** large runnable-descheduled or
   all-sleeping occupancy would redirect work from CPU transformations to the
   responsible wait/wakeup or oversubscription mechanism.

No item receives implementation priority until the whole-tree attribution
sizes it on the current binary.

## Correctness and guardrails

Every retained wave must pass:

- focused red/green tests for the changed mechanism;
- a signed native AArch64 runtime demo that compiles and runs the Go marker;
- `just conformance-native smoke --workers 4`;
- explicit review of `go-sync`, `cpython-threading`, and
  `cpython-subprocess` results;
- an untraced Node V8 and CPython guardrail when the change touches translated
  execution, fork/exec, signals, atomics, or shared cache authority;
- `just ci`;
- clean DOF presence and scoped process cleanup.

## Milestones

### M0 — controller

This design, the progress ledger, and the executable plan are checked in.

### M1 — accounted baseline

Fresh `C0`, `D0`, and `R0` are recorded. Two complete whole-tree profiles meet
the reconciliation thresholds and produce a ranked attribution. The first
hypothesis has a calculated ceiling and bounded spike.

### M2 — halve the ratio

Retained, verified waves reduce the fresh ratio to `R0 / 2` or below.

### M3 — approach the destination

The remaining-cost ranking is refreshed after every wave. Work continues while
an evidence-backed route toward 2.0 remains.

### M4 — destination

Two independent five-sample campaigns show `R <= 2.0`; correctness and
guardrail gates are green; the ledger accounts for remaining costs and closes
or scopes every active hypothesis.

## Stop and redesign conditions

- A hypothesis stops after two bounded structural variants fail their
  predeclared mechanism or wall-time gates.
- A trace method stops if it cannot reconcile its populations or drops data;
  it is repaired before optimization continues.
- A correctness obligation requiring a larger architecture change receives a
  separate design rather than a fast-path workaround.
- The campaign is not complete merely because all current hypotheses were
  rejected. It completes only at the measured 2.0 ratio destination with the
  required verification.
