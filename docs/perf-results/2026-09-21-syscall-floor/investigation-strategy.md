# Prioritize attainable workload improvement

Status: research and experiment design; no new performance acceptance. This
supersedes choosing the next optimization from recurring profile frames alone.

## What the evidence does and does not establish

The historical inotify09 reducer measured 3,011 ns per invalid-fd add/remove
pair in Carrick versus 249 ns in native ARM64 Docker. Valid add/remove was
3,481 versus 1,000 ns. These watch-only loops contain no timed write/seek.
These are the frozen initial baseline in assessment.md, not current measurements.
The invalid descriptor path returns before pathname copying or watch mutation,
but still includes descriptor validation, dispatch, and runtime overhead.
It is neither a pure transport measurement nor an irreducible floor.
Subtracting these different operation medians does not establish component cost.

CPU samples nominate hypotheses. Inclusive samples overlap; Vcpu::run combines
several domains; blocked dependencies can dominate completion without appearing
frequently in CPU samples. Event frequency is not elapsed cost. Even exclusive
CPU time need not constrain throughput when work overlaps. The priority metric
is attainable reduction in completed-work latency or increase in throughput,
verified by a controlled intervention. Serial Amdahl bounds apply only where
exclusive serial time has actually been established.

The anonymous-discard candidate produced a measured Node improvement against
its corrected control, but that is not evidence that recurring memory-inventory
frames are now the next best target. Go and Python did not materially improve
in that comparison. Shared syscall overhead remains an independent question.

## First experiment: same request, matched execution paths

1. Freeze current source, signed CLI, image, and freshly verified reducer
   identity. Refresh untraced watch-only measurements, including invalid-fd,
   unchanged-watch, and add/remove operations. Preserve every independent
   process sample; internal loop samples are not independent process runs.
2. Express those operations through the public contract interface using identical
   descriptor state, arguments, memory contents, policy and observer behavior.
   Compare direct kernel dispatch, the runtime request/completion envelope, and
   signed HVF execution. Explicitly inventory differences in memory bridges,
   signal/timer hooks, scheduling and context acquisition. Until those match,
   comparisons are diagnostic and differences cannot be named transport cost.
3. Use carrick trace in a separate bounded run to count requests, completions,
   transitions, context/register acquisition, allocations, copies and relevant
   lock/wake activity. Correlate service and wait intervals by guest task and
   completed iteration. Verify closure, nonzero firing and no dropped events.
   Trace timings do not replace uninstrumented timing; avoid inserting detailed
   probes on every tiny stage until the coarse experiment identifies a need.
4. Make one semantics-preserving intervention at a time against the matched
   control. Measure total loop completion and representative workload latency,
   not just the optimized function. A diagnostic bypass may estimate headroom
   but is not an acceptable candidate or proof of achievable savings. Artificial
   delays measure sensitivity to added cost, not automatically benefit from
   removing it, especially when contention changes.
5. Repeat with independent and shared state at 1/2/4/8 runnable threads. Track
   throughput and latency, including wait chains. Keep structural contract
   scale points 1/8/32/128. Never serialize a regression out of the experiment.

Use warmed, balanced/interleaved control/candidate process runs, with no builds
or other benchmark lanes competing. Carrick and Docker phases remain separate.
Report raw samples, dispersion and paired effect uncertainty; reject a claimed
win that cannot be distinguished from run variation. No arbitrary statistical
significance claim from the 21 samples inside one process.

## Decision gates

| Observation established by intervention | Next investment |
| --- | --- |
| Removing repeated runtime-envelope work materially improves completion | Eliminate that work with a red-first structural contract |
| Transition avoidance dominates after equivalent semantics are retained | Bounded DSR/same-thread gateway experiment with the same operations |
| Shared-state latency scales poorly while independent state does not | Identify the serial dependency; change ownership or locking with concurrency proof |
| Only valid watch mutation is expensive | Investigate descriptor/watch/path implementation using matched state |
| Microbenchmark improves but representative workloads do not | Record local gain; do not promote it as the next parity milestone |

A DSR gateway must retain the unified task model, authority, memory translation,
TLS/register preservation, signals/cancellation, policy and observers. Its
benefit must survive compute/JIT workloads as well as syscall loops. Old native
backend timings and a register-only gateway are feasibility clues, not proof.

Before implementation, name the applicable contract and capture a red semantic
or deterministic-work assertion. Use the cheapest capable proof layer, then
signed binding and Linux differential checks. Set absolute per-operation budgets
from this matched experiment; do not invent them by subtracting unrelated
getpid/fstat/watch measurements. Maintain raw Linux ratios and separate matched
native macOS I/O controls. Near-1x remains the objective; 2x is intermediate.

## Permissively licensed guidance

Pinned source files, original notices, license files and SHA-256 values are in
[permissive-guidance/sources.json](permissive-guidance/sources.json).
The manifest also retains one failed lookup; its corrected path is recorded.
These sources guide experiments; their performance numbers are not Carrick data.

- [Coz](https://github.com/plasma-umass/coz/blob/256e3c389424d6a1691ee5d18b5ecb5a6c1001ec/README.md)
  (BSD-2-Clause): use completed-work progress points and latency boundaries to
  study the effect of hypothetical optimization. Adopt the causal question,
  not an assumption that Coz runs on macOS/HVF. It targets Linux and does not
  support interpreted/JIT languages directly; bundled examples have separate licenses.
- [gVisor performance guide](https://github.com/google/gvisor/blob/164b166ce347fdb6790603318db3e4cbbe76c0b0/g3doc/architecture_guide/performance.md)
  (repository Apache-2.0): separate interception/architecture cost from syscall
  implementation cost and evaluate workload dependence. Its published platform
  numbers are not transferable to Apple HVF. Its inotify design is a semantic
  structure reference, not evidence about Carrick's invalid-fd bottleneck.
- [DynamoRIO architecture](https://github.com/DynamoRIO/dynamorio/blob/d53efb2f19e406e48bbf0c01f9664518ad8c5e3e/api/docs/intro.dox)
  (explicit BSD-3-Clause file header): code-cache linking avoids repeated
  dispatcher returns. This informs a bounded DSR design investigation; it is
  not a ready replacement for Carrick's execution or authority model.
- [Google Benchmark interleaving](https://github.com/google/benchmark/blob/ac13143d96b61cec419b49f76e58d2045aba8536/docs/random_interleaving.md)
  (repository Apache-2.0): interleave repetitions to reduce run-order effects.
  Apply the principle to existing contract tooling rather than introducing a
  new benchmark framework. Retain all license/notice obligations for copied code.


## Node population decision after the DSR prerequisite work

The fresh frozen-candidate census in node-syscall-population/ closes 10,916
requests/arguments/completions across five successful Node runs. Roughly 2,183
host-serviced calls per run makes a uniform 1-us/call saving about 2.18 ms of
aggregate work, not an explanation for the prior 189.5-ms raw Linux gap. This is
sensitivity arithmetic, not a causal wall-time bound. DSR remains relevant to
the common-syscall objective but is not established as Node's longest pole.
Keep its unexecutable planner draft; next prioritize a bounded Node memory-work
intervention with paired end-to-end timing before further broad cache machinery.


## Rejected Node inventory-search intervention

cow-inventory-bound/ records a concrete pinned-owner range lookup replacing the
full inventory candidate scan. Structural red/green and 65 COW tests passed,
but two warmed ABBA blocks measured exactly 245.25 ms mean for BOTH signed arms
(candidate/control 1.0000). The experimental product code and live descriptor
were removed, and the measured discard-retirement CLI restored. This candidate
must not be re-promoted from profile recurrence or reduced predicate counts.
Next locate a larger coarse Node phase (memory-service work, guest execution or
host fault/VM work) and test completed-work sensitivity before another local fix.

## Child/worker reduction decision

node-phases/ records completed untraced balanced runs against the pinned Linux
image. Adding the child costs 95.5 ms without a worker on Carrick versus 13.5 ms
on Linux (differences of medians); the worker costs 36 versus 14.5 ms. Preserve
the high full-variant observation rather than retrying it away. Focus the next
diagnostic on child launch/exec/exit versus standalone child initialization.
This is work removal, not a product win, and does not identify a removable
implementation cost. node-service-budget/ preserves the preceding coarse trace;
its overlapping service intervals must not be presented as critical-path shares.

## Minimal-child and memory-service decision

node-child-control/ adds an echo child control: 66.5 ms incremental Carrick
median versus 2 ms Linux. Coarse traced fork/exec stages are small; summed
madvise service rises from 28.377 to 267.542 ms across five base/echo runs.
This is overlapping perturbed service time, not removable wall time. Next
qualify post-fork discard alignment/sharing and scrub fallback per request,
then test one semantics-preserving intervention against the original fixture.

## Selected unaligned-discard intervention

node-discard-outcomes/ qualifies full-width request addresses and actual scrub
bytes. Five unaligned MADV_DONTNEED ranges per run scrub 41.5744 MB; only 40 KiB
total are partial-host-page edges. Whole-range rejection in HVF discard makes
the aligned interior fall back to authenticated scrub/COW. Next implement the
red-first bounded-edge/interior-retirement experiment, preserving neighboring
bytes, fork peers, authority and publication ordering. No more broad profiling
is needed to choose this experiment; original-fixture paired timing decides it.

## Unaligned discard intervention accepted as a measured candidate

The completed-work test moved: original Node243.5 to184.0ms (24.4% less), with
signed fork/neighbor semantics and no measured Go/Python slowdown in the small
screen. Preserve the candidate; next close production failure-injection and
structural binding before full promotion. Remaining syscall/workload parity
work is still active; do not return to inventory scans based on recurrence.

## Concurrent Node follow-up

Discard-edge candidate retains lower group completion times at1/2/4/8 workloads.
At8, mean779.5ms versus control1155.25ms and Linux82ms (raw9.506x). Throughput
declines from4 to8. Diagnostic lock waits rise substantially but overlap and
perturb scheduling. Carrick exposes4 CPUs versus Docker10, separately verified.
Next control CPU exposure and test a narrowly bounded materialization registry
critical-section intervention; do not call aggregate wait sums removable time.
Evidence: discard-edges/concurrency/. Existing failure-injection obligations
remain open; this screening result does not satisfy concurrent parity.


## Original inotify09 population is now qualified

The seek-header trial in [seek-header/](seek-header/README.md) was rejected:
21.90s before versus21.95s after, all measured runs completing the loop limit.
The full baseline census has3M add-watch services and3M remove-watch services,
but only one host-service seek. Optimizing that handler was a path-selection
error; the candidate is removed and the evidence is retained.

Before implementing another leaf optimization, prove that it participates in
the repeated path of the completed original workload. Neither a serial reducer
nor shell-wrapper counters are sufficient. Keep host-service, engine-fast-path
and guest syscall populations distinct. Frequency is still not an estimate of
removable wall time. The existing mailbox intervention already provides
full-workload sensitivity evidence; further register-read tuning repeats a gain
already present. Any next common-path or native-execution candidate must retain
semantics and improve original uninstrumented completion before expansion.


## Common context-copy reduction does not move inotify09

[context-borrow/](context-borrow/README.md) removes two of three exact context
copies from the real syscall service path, with a measured red/green contract.
Original-workload median21.885 to22.015s fails the predeclared gain criterion;
watch controls are essentially unchanged. The experiment is rejected and
fully removed from product/test registration, with evidence retained.

The completed-call census correctly identifies a repeated path, but its copy
count still does not establish a useful optimization target. Require a
controlled reduction of syscall execution/transition cost that also moves
original completion time before expanding a native/DSR intervention. Do not
reuse this context-copy hypothesis or describe a smaller work count as impact.

## Architectural decision: resident native regions, original workload first

[native-islands](native-islands/README.md) audits 1,344 selected instruction sites
from the exact original inotify09/libc binaries. The small fixture translator
rejects 493; the recovered DSR decoder rejects 0. These are static decoding results,
not dynamic coverage or executable support. The original route includes generic
libc syscall, real calls, TLS, acquire/release memory operations and an LL/SC
alternative. Stop growing the fixture whitelist as if it were this workload.

The selected next integration is a hybrid engine in the current carrier: linked
native regions stay native across synchronous kernel service, with precise HVF
fallback. Reuse DSR instruction machinery; preserve the existing kernel/task/MM
and scheduler. Current-MM memory lowering, backing-wide executable-content
revocation, state/control transfer and the original workload form one vertical
milestone. Do not count each prerequisite as a performance win.

[design.md](native-islands/design.md) defines the boundaries and a >=20% full
original completion-time screen before broadening the architecture. Near 1x
remains the goal and 2x the intermediate milestone. Latest full timings remain
21.885 s versus 5.980 s Linux; there is no new product speedup in this static audit.
