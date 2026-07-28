# Darwin native syscall-to-kernel attribution

**Date:** 2026-07-28
**Status:** approach approved; written design awaiting review
**Scope:** Darwin/AArch64 native DSR; cold-GOCACHE `go-build`

## Decision

The performance campaign will not choose its next optimization from the
Darwin-kernel CPU bucket alone. It will refresh and join three views of the
same launch-owned process tree:

1. complete guest Linux syscall service operations;
2. Darwin host syscall activity, attributed to the guest syscall in flight or
   to Carrick-only work;
3. sampled kernel execution, attributed to the active host syscall or to an
   explicit outside-host-syscall bucket.

Existing wall-state and off-CPU evidence remains part of the same capture. A
syscall context becomes an optimization candidate only when it has direct
on-CPU share or non-overlapping wall-critical blocking evidence. Counts,
amplification, summed syscall duration, and summed blocked thread-time are
diagnostic dimensions, not wall-clock opportunity by themselves.

This design refines the selection step in
`2026-07-27-native-wall-time-attribution-campaign-design.md`. It does not
change the campaign workload, baseline, retention gate, correctness gates, or
destination.

## Why this reframe is necessary

The two accepted current whole-tree profiles attribute 34.5% and 34.3% of
on-CPU samples to Darwin kernel execution. That makes kernel execution a
measurement target, not necessarily the code that should be optimized.
Carrick can drive expensive or amplified Darwin syscalls while the sampled
instruction pointer is in the kernel. The current `native-wall` profile
records kernel PCs and stacks but cannot say which host syscall, guest Linux
syscall, or Carrick-only operation caused them.

There is strong historical evidence that syscall amplification deserves a
fresh measurement:

- an older native Go build made 22,903 guest Linux syscall entries and 394,115
  Darwin host syscall entries, a 17.2x count ratio;
- 278,329 host calls, or 71%, occurred without a guest syscall window;
- the largest host syscall counts were `psynch_cvwait`,
  `psynch_cvsignal`, `mprotect`, `unlinkat`, and `close`;
- a PageGenerationTable read-fast spike did not improve wall time or reduce
  the 17.2x amplification, and increased `psynch` activity;
- separate critical-path work found child lifecycle and futex waits more
  relevant than raw lock-contention totals.

Those numbers came from older code and an `execname == "carrick"` scope, so
they are hypotheses rather than current facts. They also demonstrate the
failure mode this design must prevent: a large count or aggregate blocked
duration can be real without being the next wall-clock lever.

Current-code review also found that the existing
`carrick*:::syscall-entry`/`syscall-return` pair brackets a dispatcher
invocation, not the complete native service operation. Outcome lowering can
perform the actual futex/process wait, host fork, guest exec replacement,
thread creation, mapping installation, or syscall completion after the
dispatcher has emitted `syscall-return`. An internal retry can invoke the
dispatcher more than once for one guest syscall instruction. Reusing that
pair as the causal guest window would both overcount guest syscalls and
misclassify causal host work as Carrick-only. The joined capture therefore
adds a native service boundary and retains the existing probes as a nested
dispatcher-attempt plane. In particular, the historical 71% Carrick-only
share may combine true runtime overhead with guest-caused outcome work that
fell outside the old dispatcher window; the new measurement is designed to
separate them.

The official current baseline remains:

- `C0 = 19,375 ms`;
- `D0 = 1,007 ms`;
- `R0 = 19.2403x`;
- first milestone `R <= 9.6202x`;
- destination `R <= 2.0x`.

No traced elapsed time can replace those untraced wall-clock metrics.

## Goals

The measurement wave must:

1. scope every plane to the process tree created by the traced launch;
2. count guest Linux syscall service operations by canonical number and name;
3. count and time Darwin host syscalls by host name;
4. attribute each host syscall to:
   - a complete guest Linux syscall service operation; or
   - Carrick-only work outside a guest service operation;
5. measure completed per-guest-syscall host-call amplification;
6. classify every sampled kernel PC as:
   - executing within a named active Darwin host syscall; or
   - executing outside a host syscall window;
7. retain the active guest context, if any, on each sampled host-syscall
   context;
8. resolve sampled kernel PCs and stack frames without inventing a kernel
   object identity;
9. preserve elapsed wall, wall-state, user CPU, process lifecycle, image/JIT,
   voluntary off-CPU, and runnable-descheduled planes;
10. measure non-overlapping launch-tree quiescence so blocking candidates can
    be distinguished from summed thread-time;
11. reconcile all populations and reject incomplete or internally
    inconsistent captures;
12. repeat the current exact workload twice and select a candidate only when
    its rank and meaningful shares are stable.

The output must leave enough evidence to choose one bounded hypothesis or to
conclude honestly that the measured cost is diffuse.

## Non-goals

This wave will not:

- optimize Darwin kernel code;
- assume that a Darwin syscall is intrinsically inefficient;
- compare Darwin and Linux syscall names as if they were equivalent ABIs;
- use traced wall time as a performance result;
- infer wall opportunity from syscall counts or summed durations alone;
- admit unrelated Carrick processes through an `execname` predicate;
- reuse the historical amplification report as current evidence;
- serialize an unverified `dts_object` label as kernel object identity;
- reconstruct a complete Darwin kernel object catalog;
- change translation, syscall dispatch, locking, lifecycle, or memory
  behavior while establishing the measurement, except for inert USDT service
  boundaries needed to observe the existing control flow;
- select or benchmark H006 before the joined evidence passes its acceptance
  gates.

## Approaches considered

### Joined syscall and sampled-kernel attribution

This is the approved approach. It answers both causal questions:

- what work caused Carrick to enter the kernel; and
- how much sampled kernel CPU or non-overlapping quiescent wall time belongs
  to that work.

The result can distinguish a Carrick-only synchronization problem, an
amplified guest-emulation path, an ordinary I/O mix, and kernel activity
outside a syscall window.

### Kernel stacks alone

Kernel stacks identify mechanisms such as VM faults, protection changes,
filesystem work, synchronization, or process teardown. They do not identify
the Carrick or guest operation that requested the work. This is insufficient
for selecting an implementation change.

### Syscall counts and durations alone

Counts reveal amplification and durations reveal where threads waited.
Neither is a wall-clock denominator. Parallel waits can produce many summed
thread-seconds without extending elapsed time, and a frequent syscall can be
cheap. This approach repeats the ambiguity in the historical results.

### Reuse the historical syscall-amplification capture

The older capture is useful prior evidence but used a broad `execname` scope
and predates the current binary and performance baseline. It cannot satisfy
the campaign's provenance or stability contract.

## Capture architecture

The existing `native-wall` profile remains the single launch-time capture.
Its D program and parser will be extended rather than running an unjoined
syscall census against a workload already in flight.

### Process ownership

The trace starts with `$target` in `track_pid`. A child is admitted only by a
`proc:::create` event whose creating PID is already tracked. Membership
survives `exec` and ends on the tracked process's exit.

No `execname`, global Carrick census, or time-window-only predicate may admit a
process. Every record carries or derives the launch run ID, target PID,
binary hash, commit, dirty state, host identity, profile schema, and raw-trace
hash.

New children start with empty thread-local guest and host syscall state.
Context is copied only when an explicit guest-service branch creates the child
process or thread, as described below. Image/JIT inheritance alone never
creates a service context.

### Guest syscall service window

The native AArch64 driver adds three inert USDT boundaries:

- `native-syscall-service-entry(nr, name)` fires once when a
  translated guest syscall exit becomes a `SyscallRequest`, before dispatch;
- `native-syscall-service-branch(kind)` fires immediately before an active
  service creates a guest process or thread branch;
- `native-syscall-service-end(nr, name, outcome)` fires when
  that service branch is about to resume guest execution or reaches an
  explicit terminal handoff.

The DTrace program assigns the operation ID as
`(origin_pid, origin_tid, origin_sequence)` at service entry. It copies that
ID to an explicitly announced child branch, so the ID remains stable without
adding runtime bookkeeping. Thread context is separately keyed by `(pid, tid)`
so profile probes can join without reading `self->` storage.

Service entry:

- increments the exact guest syscall-instruction count;
- records the canonical syscall number and bounded ABI name;
- initializes the operation's host-call count and open-branch count to one;
- rejects a nested service entry on the same thread.

The service remains active across:

- dispatcher retries;
- a futex, fd, signal, sleep, or process wait;
- host process or thread creation and child setup;
- `DispatchOutcome` lowering;
- host mapping/protection installation;
- guest register and signal completion.

A normal service end decrements the operation's open-branch count. When the
count reaches zero, the capture adds the operation's complete cross-branch
host-call count to the per-guest amplification distribution and deletes the
operation state.

Successful terminal outcomes are explicit:

- guest `exit`/`exit_group`: `proc:::exit` closes the service branch after
  validating the guest syscall identity;
- a successful fork-child host self-`execve`: `proc:::exec-success` closes the
  inherited guest `execve` service branch;
- guest thread exit: the native driver emits `service-end` before the host
  thread terminates;
- guest exec replaced in-process: the native driver emits `service-end` after
  the replacement image is ready and before it resumes.

Host process or thread creation copies an active service operation into the
new branch only when it consumes a preceding matching `service-branch`
announcement. The operation's open-branch count is incremented before either
branch can complete. The child emits `service-end` when its guest return state
is ready. A missing, duplicate, wrong-kind, or unconsumed branch announcement
rejects the capture. A generic helper process/thread, or a descendant created
outside a service operation, starts without a guest context.

Service populations reconcile exactly as:

`service_entries + created_branches = resumed_branches + terminal_branches + invalid_open`

An accepted run requires `invalid_open = 0`, every operation to reach zero
open branches, and each operation to publish exactly one amplification
observation.

### Nested dispatcher-attempt plane

The existing `carrick*:::syscall-entry` and `syscall-return` probes remain
inside a service window. They count dispatcher attempts, including retries,
and verify which host work occurs before versus after dispatcher return.

Every dispatcher entry must have a matching number/name return before the
service branch ends. Dispatcher events without an active matching service
context, nested dispatcher attempts on one thread, and unpaired attempts
reject the capture.

The report publishes:

- guest service operations;
- dispatcher attempts;
- attempts per service operation;
- host calls inside dispatcher attempts;
- host calls after dispatcher return but before service completion.

Only guest service operations form the host/guest amplification denominator.

### Host syscall window

For tracked `(pid, tid)`, `syscall:::entry` opens one Darwin host syscall
window containing:

- bounded host syscall name;
- entry timestamp;
- guest syscall number/name and operation ID when a service window is active;
- otherwise the explicit `carrick-only` context.

It increments:

- the total host-entry count;
- the count keyed by context and host syscall;
- the current guest operation's host-entry count when applicable.

`syscall:::return` verifies and closes the window, then adds elapsed
nanoseconds to the same context key. Elapsed syscall duration is reported as
resource time. It can include sleep and is never added across threads to
estimate wall time.

The host provider has explicit non-returning and cross-branch cases:

- a successful host `execve` closes on `proc:::exec-success`;
- host `exit` closes on `proc:::exit`;
- a child-side `fork`/`vfork` return without a child-side entry is accepted
  only when `proc:::create` recorded the matching active parent call.

Those events are counted separately as expected transitions. Any other nested
host entry, return without entry, name mismatch, or open host window at
thread/process exit rejects the capture. Host totals reconcile exactly as:

`host_entries = host_returns + expected_exec + expected_exit + invalid_open`

Expected child-side fork returns are not host entries and reconcile against
the matching process-create record. An accepted run requires
`invalid_open = 0`.

### Kernel sampling joined to syscall context

The prime-rate `profile-499` kernel clause remains the time-attribution
mechanism. For each tracked kernel sample it records:

- kernel leaf PC;
- bounded kernel stack;
- active host syscall name, or `outside-host-syscall`;
- active guest service operation ID and syscall number/name, or
  `carrick-only`;
- PID and TID only where needed for raw reconciliation, not as an analysis
  grouping.

DTrace profile probes must not read `self->` state set by syscall probes. A
profile probe runs in probe context where that state is not a reliable join
key. Guest service and host windows are stored in PID/TID-keyed associative
variables, and the sampling clause reads those variables using the sampled
`pid` and `tid`.

Every weighted kernel sample belongs to exactly one of:

1. guest syscall plus active host syscall;
2. Carrick-only plus active host syscall;
3. guest syscall plus outside-host-syscall;
4. Carrick-only plus outside-host-syscall.

The four buckets must sum to the original kernel-sample denominator. Unknown,
dropped, or omitted samples are not renormalized away.

Host syscall counts and kernel samples intentionally remain separate:

- count without kernel samples can identify amplification but not CPU cost;
- kernel samples within a host call size its on-CPU share;
- elapsed host duration can identify waiting but not serial wall cost;
- outside-host-syscall kernel samples expose faults, interrupts, or provider
  boundary gaps rather than silently assigning them to the last syscall.

### Non-overlapping quiescent wall attribution

The existing wall sampler partitions elapsed time into on-CPU,
runnable-descheduled, all-sleeping, and transition states. The implementation
must add the missing `sched:::wakeup` state transition: a woken tracked thread
becomes runnable before it next reaches `sched:::on-cpu`. Without that event,
wakeup latency is incorrectly left in the all-sleeping bucket.

The process/thread state machine is driven by `proc:::create`,
`proc:::lwp-create`, `sched:::on-cpu`, `sched:::off-cpu`,
`sched:::wakeup`, `proc:::lwp-exit`, and `proc:::exit`. Each event removes the
old state contribution before adding the new one. Negative population counts,
duplicate transitions, an unknown live thread after startup, or nonzero live
state at completion reject the capture. The wakeup transition uses the target
LWP from the provider arguments, not the waking thread's ambient `pid`/`tid`.

The extension also records the transition that makes the tracked tree have:

- zero on-CPU tracked threads;
- zero runnable tracked threads;
- at least one sleeping tracked thread.

The last tracked thread to enter sleep owns the beginning of that quiescent
interval. Its PID, user blocking PC, guest context, and active host syscall
context are saved. The first tracked thread to become on-CPU or runnable closes
the interval. A `sched:::wakeup` closes it at wake time rather than delaying
the close until the woken thread is scheduled. Process creation, thread
creation, and completion also update or close an interval according to the
resulting state.

The interval is non-overlapping wall time, not summed thread-time. It is
reported by blocking context and blocking stack. A stack is captured at the
transition in a framed record carrying a monotonic interval ID. The close
record carries the same ID and elapsed nanoseconds, so the parser joins the
exact entry stack; it is not reconstructed from a later thread. Quiescence
records are the only permitted per-interval output and are subject to the same
zero-drop gate.

This does not claim a complete dependency graph for parallel compiler
processes. It supplies the narrower fact needed for selection: which blocking
operation made the entire launch-owned tree unable to advance, and for how
much elapsed time. Voluntary off-CPU resource totals remain available but do
not qualify a candidate without this wall-plane evidence.

### Aggregation and perturbation limits

High-frequency events are aggregated in DTrace. The program does not print
one line per syscall or sample. Keys are bounded by:

- guest syscall number/name;
- Darwin syscall name;
- the four context classes;
- sampled PC or stack;
- a fixed set of reconciliation error kinds.

Presentation may truncate ranked tables only after full totals are recorded.
It may not truncate the authority aggregates or change the denominator.

All counters and nanosecond additions are checked during parsing for unsigned
64-bit overflow. DTrace dynamic-variable drops, principal-buffer drops, or
aggregation truncation reject the capture.

## Sampled kernel symbol overlay

The current live-symbol work established that public libdtrace can resolve
most sampled kernel addresses, but `dts_object` is a CoreSymbolication label
whose identity does not match the object catalog contract. The v6 census
resolved 865 of 878 distinct all-frame addresses and returned public
`(-1, 1015)` ("No symbol corresponds to address") for the other 13. Their
leaf-versus-caller placement must be proven by the implementation.

The capture therefore uses a new identity-free sampled overlay:

`carrick.sampled-kernel-symbols.v1`

It contains:

- kernel identity containing the existing `kern.osversion`, `kern.version`,
  `kern.uuid`, and machine fields plus mandatory
  `kern.bootsessionuuid`, so reuse across a different kernel build or boot is
  rejected;
- the exact requested distinct address set hash and count;
- for each resolved address:
  - address;
  - symbol name;
  - symbol start;
  - symbol size;
  - offset;
- for each unresolved address:
  - address;
  - libdtrace status;
  - public DTrace error number;
- exact resolved and unresolved set hashes and counts.

The overlay does not serialize, compare, group by, or join through
`dts_object`. The label may be copied with bounded lifetime for diagnostics,
but it is opaque and non-authoritative. The analyzer uses
`darwin-kernel-sample` as an analysis namespace only; it is not a claim about
Mach-O or kext object identity.

Acceptance requires:

- requested addresses equal resolved union unresolved;
- resolved and unresolved sets are disjoint and duplicate-free;
- every weighted kernel leaf PC resolves to a non-raw symbol and valid range;
- an unresolved non-leaf frame is allowed only for public
  `(-1, 1015)`;
- any other status, raw-address fallback, zero-size symbol, range mismatch,
  overflow, kernel-identity mismatch, or unresolved leaf rejects the capture.

Raw PCs and stacks remain the authority. The overlay is a checked,
same-capture annotation and never rewrites the raw trace.

## Output and analysis contract

The joined report schema is:

`carrick.native-syscall-kernel-attribution.v1`

Each report contains the following sections.

### Provenance and completion

- run ID and workload declaration;
- commit, dirty-state digest, binary path and SHA-256;
- signed-binary and DOF checks;
- host OS/build, machine, boot/kernel identity, power and idle preflight;
- raw DTrace path, byte count, SHA-256, and overlay SHA-256;
- launch target PID and exact process create/exit/live counts;
- DTrace drop and error counts;
- target exit reason, expected marker, and natural completion status.

### Exact syscall populations

- guest service entries, created branches, resumed branches, terminal
  branches, completed operations, and invalid opens;
- nested dispatcher entries/returns and attempts per service operation;
- host entries, returns, expected exec/exit transitions, expected child-side
  fork returns, invalid opens, and host/guest-operation ratio;
- Carrick-only host count and share;
- guest-context host count and share;
- host calls per completed cross-branch guest operation, including count,
  minimum, median, p90, p99, maximum, and total;
- host calls inside nested dispatcher attempts versus during outcome lowering
  and completion;
- ranked guest syscall, host syscall, and guest-to-host pair tables.

### Time planes

- original wall-state sample denominator and all four occupancy buckets;
- original user and kernel on-CPU sample denominators;
- kernel sample counts and shares for each of the four joined classes;
- ranked joined contexts with kernel samples and shares;
- host elapsed resource nanoseconds by the same context, clearly labeled
  non-wall and non-additive;
- voluntary off-CPU and runnable-descheduled resource time;
- non-overlapping quiescent wall nanoseconds by triggering context and stack.

### Symbols and reconciliation

- requested, resolved, unresolved-leaf, and unresolved-caller counts;
- exact PC, stack, and overlay set hashes;
- kernel samples before and after context grouping;
- kernel samples before and after symbol-family grouping;
- omitted or unknown counts on the original denominator;
- every acceptance threshold and its pass/fail result.

## Candidate identity and selection

A candidate is identified by:

- `cause_class`: `guest-emulation`, `carrick-only`, or
  `kernel-outside-syscall`;
- optional guest syscall number/name;
- optional Darwin host syscall name;
- optional resolved kernel leaf/family;
- optional blocking stack/family.

Two accepted captures of the same binary and exact workload are required.
They run serially, with exact stamped cleanup, and never overlap Docker.

A context is stable enough to rank when:

- it has at least 10% mean share of the relevant original denominator;
- it has at least 5% share in each capture;
- its absolute share differs by no more than five percentage points;
- its rank relative to other contexts above 10% is unchanged.

A lower-share context may be reported but cannot lead the next step-function
spike unless several mechanically identical contexts are grouped by a
predeclared symbol/syscall family and the ungrouped records remain available.

### CPU candidate

A CPU candidate must own stable sampled on-CPU share. Its zero-cost resource
ceiling is its share of kernel samples multiplied by kernel samples' share of
all on-CPU samples. Parallel resource share is not asserted to be serial wall
share. The report states that ceiling, the mechanism that could place it on
the workload's completion path, and the smaller expected spike effect
separately. Only the bounded untraced screen establishes wall direction.

### Blocking candidate

A blocking candidate must own stable non-overlapping quiescent wall time or
another explicitly non-overlapping wall interval. Host elapsed duration and
voluntary off-CPU thread-time can support its mechanism but cannot qualify it.

### Amplification candidate

An amplified guest-emulation pair must additionally show:

- a stable per-instance host-call distribution, not only a global ratio;
- the relevant guest syscall count/mix from the separate Docker oracle;
- a clear reason the Darwin call count exceeds unavoidable host work.

A Carrick-only context does not need a Linux syscall analogue, but still needs
CPU or quiescent-wall share.

If no context satisfies these rules, the report concludes `DIFFUSE` and no
optimization hypothesis is selected from the capture.

## Docker oracle comparison

The Docker phase runs separately on native arm64 and uses `bpftrace` inside
the container, following the repository oracle rules. It records:

- Linux guest syscall count and mix;
- relevant per-process or per-thread distribution when needed;
- process creation count and broad workload shape;
- the expected build/run marker.

Docker evidence is used to ask whether Carrick amplifies the guest workload.
It is not used to equate a Linux syscall with a same-named Darwin syscall, and
Darwin kernel stacks have no Docker-side denominator.

Guest `strace`, Rosetta/amd64 containers, concurrent Carrick/Docker execution,
and GPL implementation source are out of bounds.

## Acceptance and falsification

Both full joined captures must satisfy:

1. the exact signed current binary and cold-GOCACHE workload complete
   naturally with the marker;
2. no DTrace or parser drops, truncation, overflow, or unknown record exists;
3. process-tree create, exit, and live populations reconcile;
4. at least 99% of wall samples are in declared wall-state buckets;
5. the existing on-CPU category classifier assigns at least 85% of samples;
6. the top reported voluntary blocking stacks cover at least 80% of voluntary
   off-CPU resource time;
7. guest service entries, created branches, resumed/terminal branches, open
   branches, completed operations, and amplification observations reconcile;
8. nested dispatcher attempts reconcile inside their matching service
   operations;
9. host entries reconcile to returns plus expected successful exec/exit
   transitions, and expected child-side fork returns reconcile to creates;
10. every host entry has exactly one guest-service or Carrick-only context;
11. every kernel sample has exactly one active-host or outside-host context;
12. joined kernel context totals equal the original kernel denominator;
13. symbol overlay populations reconcile and every weighted leaf resolves;
14. only public `(-1, 1015)` misses occur, and only on non-leaf frames;
15. dominant joined contexts meet the two-run rank/share stability rule;
16. all-sleeping/quiescence intervals are non-overlapping and do not exceed
    elapsed wall time.

The method is falsified and repaired before optimization when:

- profile probes cannot reliably join through PID/TID-keyed context;
- a material outside-host-syscall bucket is caused by provider ordering rather
  than real execution;
- per-syscall probes drop data or destroy category stability between the two
  captures;
- the process set admits unrelated work or loses a descendant;
- quiescent wall ownership cannot be closed and reconciled;
- unresolved kernel leaves prevent a stable family ranking.

Trace perturbation is expected to change absolute elapsed time. It is not an
excuse for unstable proportions, incomplete populations, or dropped events.

## Tests

Implementation follows red-first tests for the parser, analyzer, and symbol
overlay.

### Parser fixtures

- one completed guest service operation with multiple host calls;
- multiple nested dispatcher attempts for one guest operation;
- host work after dispatcher return remains in the guest service context;
- Carrick-only host calls;
- active guest context with outside-host-syscall kernel sample;
- Carrick-only outside-host-syscall kernel sample;
- nested service entry and mismatched service end;
- guest process and thread branch propagation with one operation ID;
- missing, duplicate, wrong-kind, and unconsumed branch announcements;
- terminal guest exit and successful host self-exec;
- unexpected open guest service at exit;
- nested/mismatched dispatcher attempt;
- nested host entry, host return without entry, and unexpected open host
  window;
- expected host exec/exit non-return and expected child-side fork return;
- generic child starts with empty syscall contexts;
- exact four-way kernel sample reconciliation;
- sleep-to-wakeup-to-on-CPU state accounting;
- non-overlapping quiescence start, wake, create, and completion close;
- unsigned counter and nanosecond overflow;
- DTrace drop and truncated completion;
- unknown required record.

### Symbol overlay fixtures

- exact resolved/unresolved partition;
- duplicate and missing requested addresses;
- valid symbol range and offset;
- raw-address, zero-size, range, and overflow rejection;
- public `(-1, 1015)` on a caller frame accepted;
- public `(-1, 1015)` on a weighted leaf rejected;
- any other lookup status rejected;
- opaque object-label changes do not affect grouping;
- kernel identity mismatch rejects reuse.

### Analyzer fixtures

- stable CPU context selected;
- stable quiescent blocker selected;
- high count without CPU/wall share rejected;
- high summed duration without quiescent-wall share rejected;
- unstable rank/share rejected;
- grouped family retains its ungrouped denominator;
- no qualifying context produces `DIFFUSE`;
- report totals remain on original denominators.

### Live proof

1. compile and parser fixture gates;
2. signed `native-wall` smoke that prints `TRACE_OK`;
3. exact process and context reconciliation on the smoke;
4. two complete cold-GOCACHE Go-build joined captures;
5. a separate native-arm64 Docker syscall-shape capture;
6. deterministic report regeneration from immutable raw receipts;
7. exact run-ID cleanup with zero surviving processes.

These are measurement proofs, not performance wins. No source optimization is
retained from this wave.

## Implementation boundaries

The expected implementation surface is:

- `crates/carrick-observability/src/probes.rs` for inert native service
  boundaries;
- `crates/carrick-runtime/src/native_darwin.rs` for boundaries around the
  existing full service/branch control flow;
- `scripts/dtrace/native-wall.d` for launch-owned joined aggregation;
- `crates/carrick-cli/src/trace_profile.rs` for capture framing and profile
  integration;
- `crates/carrick-runtime/src/dtrace_symbols.rs` for the identity-free sampled
  lookup result;
- a versioned parser/analyzer under `scripts/perf/`;
- versioned evidence and receipt schemas under `scripts/perf/evidence/`;
- focused Rust and script tests.

`scripts/dtrace/syscall-amplification.d` remains historical diagnostic
material. Its `execname` scope and standalone timing model are not copied into
the accepted profile.

## Result-driven next hypotheses

The capture chooses, rather than presupposes, the next spike:

- Carrick-only `psynch_*` plus kernel synchronization samples and wall share
  would support a lock/wakeup suppression or coalescing spike;
- guest-context `mprotect` plus VM/protection samples would support protection
  batching or translation publication work;
- `kevent`/process-wait quiescent wall ownership would support a child
  lifecycle spike;
- outside-host-syscall VM-fault samples would support JIT/page-mapping work;
- a Darwin I/O mix proportional to Docker guest I/O and lacking CPU/wall share
  would be deprioritized despite high counts.

Each selected hypothesis still enters the campaign ledger with its measured
share, calculated ceiling, mechanism, bounded spike, stop condition,
correctness proof, and untraced retention gate.

## Rollout

1. approve this written design;
2. write and review the executable implementation plan;
3. implement parser/analyzer and overlay tests red-first;
4. extend the D program and trace framing;
5. pass the signed `TRACE_OK` smoke and reconciliation gates;
6. capture two exact current Go-build runs and the separate Docker syscall
   shape;
7. publish the stable joined ranking or `DIFFUSE` result in the campaign
   ledger;
8. name H006 only if a context passes the selection rules;
9. execute its bounded spike;
10. use the existing untraced five-sample gate and correctness closeout for
    any retained change.

The immediate deliverable after this design is accepted is measurement, not an
optimization patch.
