# Pluggable scheduling and bounded pre-emption

Date: 2026-09-19. Status: research-backed proposal for review; not implementation
authorization or an acceptance receipt.

Carrick source inspected: `e181864aa6c47a9df0681da433c548e46a72e771`.
Research is source inspection, not a live scheduling measurement. Public XNU
source does not establish the configuration of the kernel installed on this Mac.

## Intent and scope

Build on `ContainerBuilder::scheduler(Arc<dyn SchedulingPolicy>)` so runnable
Linux threads make progress even when all execution slots are running guest
code that never makes a syscall. Preserve low overhead without contention,
affinity, exact-generation ownership, host-wait handoff, and policy injection.

The user requested research and a plan. This document and its companion
[implementation plan](../plans/2026-09-19-pluggable-scheduler-preemption.md)
fulfil that request; neither starts implementation.

This extends the [guest-CPU design](2026-09-07-guest-cpu-scheduler-design.md).
It does not replace the active [GMP Phase 3 controller](../plans/2026-09-19-gmp-phase3.md),
its [handoff](../plans/2026-09-19-gmp-phase3-handoff.md), or
[host-wait inventory](../plans/2026-09-19-gmp-phase3-host-waits.md).
Those documents still own host-operation coverage and the default executor-count
change. Pre-emption must work with the current multiple-executors-per-CPU model
and with a future one-executor-per-CPU model.

## Primary-source research

Sources were fetched on 2026-09-19 at the revisions below. All conclusions here
are paraphrases of the named functions and structures; no foreign implementation
is proposed for copying. XNU's relevant files carry APSL notices, FreeBSD ULE
BSD-2-Clause, and illumos files CDDL notices. Keep the Rust implementation
independent; any later source reuse requires its own license review. No Linux
kernel implementation source is needed.

### XNU: Clutch/Edge and pre-emption boundaries

Snapshot: `apple-oss-distributions/xnu`,
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` (public commit dated 2025-10-16).

- [sched_clutch.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/sched_clutch.c):
  root bucket selection uses deadlines derived from runnable time and a
  latency allowance. Limited warp windows let higher buckets advance without
  giving them unlimited precedence. Starvation-avoidance state and thread
  quanta bound that preference. The OSX quantum table ranges from 2 to 10 ms;
  these are XNU parameters, not measured Carrick defaults. Edge implementation
  is in this same file: preferred clusters, migration weights, and permitted
  stealing guide movement between clusters.
- [sched_clutch.h](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/sched_clutch.h):
  the hierarchy distinguishes root QoS buckets, thread groups, and their
  per-QoS buckets. Physical cluster preferences are distinct from thread
  selection inside that hierarchy.
- [sched_prim.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/sched_prim.c):
  `update_pending_nonurgent_preemption` distinguishes urgent work from
  ordinary pre-emption. Kernel-context nonurgent pre-emption can be deferred
  toward a clean userspace boundary, with a timer bounding that deferral;
  an existing pending request is not repeatedly rearmed.

**Apply:** distinguish scheduling preference from mandatory control requests;
keep requests pending until a safe boundary; bound ordinary residency only when
another eligible task needs execution. Preserve locality where it does not
prevent progress.

**Do not transplant:** QoS bands, warp constants, perfcontrol, or P/E-core
placement. Carrick schedules virtual CPUs and the host chooses physical cores.
A guest CPU number does not identify an Apple performance core. XNU can
pre-empt kernel contexts in ways Carrick cannot safely emulate inside an
arbitrary Rust critical section.

### FreeBSD: ULE local queues, slices, and selective notifications

Snapshot: `freebsd/freebsd-src`,
`ed4d2671efbd8fa97c0e027e6945340a02d4725f` (2026-09-19).

- [sched_ule.c](https://github.com/freebsd/freebsd-src/blob/ed4d2671efbd8fa97c0e027e6945340a02d4725f/sys/kern/sched_ule.c):
  `tdq` owns a CPU-local queue, lock, load, current thread, and pending
  pre-emption state. `tdq_slice` reduces timeshare slices as load rises, down
  to a minimum. `sched_shouldpreempt` compares priorities and thresholds;
  `tdq_notify` coalesces remote requests and can wake an idle CPU without
  issuing a pre-emption IPI. `sched_pickcpu` considers affinity and topology.
  `sched_interact_score` distinguishes voluntary sleeping from running time:
  waiting in a run queue is not counted as interactive sleep. Timeshare queue
  advancement provides anti-starvation behavior. These are the inspected main
  branch's structures, not a claim about every FreeBSD release.
- [subr_turnstile.c](https://github.com/freebsd/freebsd-src/blob/ed4d2671efbd8fa97c0e027e6945340a02d4725f/sys/kern/subr_turnstile.c):
  priority propagation follows lock-owner dependencies. Lock contention and
  priority inversion require information beyond CPU queue length.

**Apply:** retain Carrick's local queues, prefer idle capacity before
interrupting useful work, coalesce one request per live residency, and separate
runqueue delay from actual sleep. Start with a fixed bounded quantum; retain
enough policy context to evaluate load-adaptive slices later.

**Do not transplant:** FreeBSD priority-number conventions, clock frequencies,
physical topology, or turnstiles as a substitute for Carrick's continuations.
More pre-emption cannot repair a lost wake or a resource-ownership cycle.

### illumos: dispatcher/class separation, TS aging, and FSS groups

Snapshot: `illumos/illumos-gate`,
`c953d6213189717ed0fdca5ffe06f6d6cf5d4f08` (2026-09-19).

- [class.h](https://github.com/illumos/illumos-gate/blob/c953d6213189717ed0fdca5ffe06f6d6cf5d4f08/usr/src/uts/common/sys/class.h):
  scheduling classes have explicit thread-operation hooks, including
  pre-emption, ticks, sleep/wakeup, and yield. The class controls scheduling
  choices through a dispatcher-owned lifecycle.
- [disp.c](https://github.com/illumos/illumos-gate/blob/c953d6213189717ed0fdca5ffe06f6d6cf5d4f08/usr/src/uts/common/disp/disp.c):
  dispatch queues and CPU state implement the choices. `cpu_surrender` sets
  rescheduling state and requests a trap excursion on the target; user and
  kernel pre-emption have distinct flags. `preempt` passes the outgoing thread
  through its class hook before switching.
- [ts.c](https://github.com/illumos/illumos-gate/blob/c953d6213189717ed0fdca5ffe06f6d6cf5d4f08/usr/src/uts/common/disp/ts.c):
  `ts_tick` decrements the remaining quantum and applies the expiry priority
  transition. Sleep return and excessive dispatch wait have different table
  transitions. `ts_update_list` ages waiting work. A limited no-preempt request
  has a failsafe; it is not permission to monopolize a CPU indefinitely.
- [fss.c](https://github.com/illumos/illumos-gate/blob/c953d6213189717ed0fdca5ffe06f6d6cf5d4f08/usr/src/uts/common/disp/fss.c):
  FSS assigns shares to projects and zones, so fairness can be between groups
  rather than individual threads. Shares influence scheduling under contention;
  they do not prevent use of otherwise idle capacity. Its accounting includes
  group usage and active-share populations.

**Apply:** the existing Carrick policy/mechanism split is the right foundation.
Give policies explicit thread identity, lifecycle reason, and residency context.
Keep process identity separate so later group scheduling need not confuse a
thread with its fairness group.

**Do not transplant:** illumos dispatch tables, zone semantics, or priorities as
Linux ABI behavior. Group shares are a separate product decision. Two carriers
cannot acquire host-wide fairness merely by each installing an in-carrier policy.

### Synthesis

| Concern | Useful precedent | Carrick decision |
|---|---|---|
| Work placement | ULE local queues; XNU locality | Keep existing placement/steal mechanism |
| CPU-bound monopolization | All three have forced scheduling boundaries | Complete exact targeted deadline delivery |
| Wake storms | ULE pending remote requests | One pending fairness request per residency |
| Safe switching | XNU deferred AST; illumos surrender | Record request; settle on owning executor |
| Fairness policy | TS aging, Clutch bounded preference | FIFO bounded rotation first |
| Workload grouping | Clutch groups; illumos FSS | Distinct process/thread IDs now; shares deferred |
| Blocking/lock contention | Turnstiles and class sleep hooks | Continue Phase 3 and owned continuations |

## Current Carrick findings

1. **Policy installation exists.** `carrick-embed/src/builder.rs::scheduler`,
   runtime extensions, and carrier installation pass an `Arc<dyn
   SchedulingPolicy>`. One carrier has one installed policy. Guest CPU exposure
   follows its CPU count. Preserve this entry point.
2. **Placement exists.** `carrick-hal/src/scheduler.rs::GuestCpuPolicy`
   considers allowed CPUs, idle executors, backlog, and last CPU. The kernel
   owns queues, publication, claim validation, stealing, and settlement.
3. **Policy identity currently aliases sibling threads.** `policy_pick`,
   `policy_steal`, placement and notification code construct HAL `TaskKey`
   from `row.thread.task_key().serial`, the owning process serial. Kernel
   `Thread::key().serial` is a separate `ThreadSerial`. A policy cannot reliably
   distinguish two runnable siblings with the present projection.
4. **The advertised callback lock boundary is not implemented everywhere.**
   `pop_local` holds `GuestCpuLocalState` while `policy_pick` calls external
   `pick_next`. The HAL comment says queue views avoid scheduler locks.
   Extend policy callbacks only after fixing this mismatch.
5. **Forced exits exist.** Kernel executor tokens identify executor, epoch,
   thread and execution generation. `WorkerKick::deliver_exact` authenticates
   the token, sets the worker flag and invokes the backend kick. HVF uses
   `hv_vcpus_exit`. The production loop can settle `Preempted`.
6. **Scheduling policy is not a production clock.** At the inspected revision,
   searches find no production caller of `tick_preemption`; `on_tick(cpu)`
   defaults to `Continue` and receives neither running-thread identity nor
   elapsed residency. The broadcast `request_preemption` helper is exercised by
   tests. Ordinary syscall exits consult a carrier-wide `need_resched` flag.
   These findings support a missing-fairness hypothesis, not a measured hang.
7. **A CPU is not a unique executor.** `configured_bound_executors` defaults
   to `available_parallelism()`, not policy CPU count. `GuestCpu::current_task`
   is a single optional thread despite multiple possible bound executors.
   Scheduling deadlines must use exact execution slots, not that field.
8. **Host-wait handoff is partially integrated.** The Phase 3 inventory explicitly
   leaves regular-file I/O, vector/transfer output, faults and other sites open.
   Its VM-free proofs are not signed composition acceptance.
9. **The readiness reactor already does work.** `CarrierWaitService::run_reactor`
   maintains continuation deadlines but also drives retained writes and record
   locks. Do not couple the CPU-bound fairness guarantee to arbitrary readiness
   service duration without an additional proof.
10. **Replay is currently best effort.** `RecordReplay` records placement,
    picking and stealing; `on_tick` simply forwards. Timed decisions and their
    inputs must be captured, and divergence must remain visible.

## Options considered

1. **Wire a periodic timer to `tick_preemption`.** Small patch, but the hook
   cannot identify the running thread, calls once per executor sharing a CPU,
   and encourages full-directory scans or broadcast exits. It also leaves
   syscall-count-driven switching and policy identity defects intact. Reject.
2. **Complete bounded, demand-driven scheduling on the existing trait.** Add
   residency context, exact thread identity, one-shot deadlines and typed
   rescheduling reasons. Preserve placement and default FIFO. Recommended.
3. **Introduce a full QoS/group-share scheduler immediately.** Research supports
   it, but it requires priority authority, reliable accounting and workload-group
   semantics that this request does not establish. Defer until bounded progress
   and its costs are proven.

## Proposed design

### Policy inputs and outputs

Evolve `SchedulingPolicy` in place. Keep the builder method and existing
placement/selection responsibilities. Do not introduce a second scheduler trait,
a legacy adapter, or parallel queue ownership.

- Replace ambiguous HAL `TaskKey` with `SchedThreadId`, projected from the
  non-reused kernel thread serial. Add `SchedProcessId` from the process serial
  to placement and dispatch context. Exec retirement/replacement follows the
  kernel's actual identities; never infer lifetime from a numeric Linux TID.
- Preserve `select_cpu`, `pick_next`, `steal` and `inspects_queues`, using the
  thread identity. Default selection stays FIFO without materializing views.
- Replace `on_tick(cpu)` with `on_dispatch(&DispatchContext) -> RunBudget` and
  `on_contention(&ContentionContext) -> PreemptionAction`. Dispatch context
  identifies thread, process, CPU and current load. Contention context adds
  elapsed residency and eligible backlog. Policies do not see executor handles,
  vCPU IDs, execution generations, locks or guest memory.
- `RunBudget` carries a validated, nonzero duration; default 4 ms. Accept
  durations from 1 ms through 100 ms for custom policies in this proposal;
  invalid configuration returns a typed error at construction. These are
  proposed Carrick configuration bounds, not values derived from Linux ABI.
- `PreemptionAction` is `KeepBudget`, `ShortenTo(Duration)` or `Preempt`.
  Shortening is relative to the original residency start, never the newest
  wake. No event can extend the existing residency deadline. A shortening to
  zero is equivalent to `Preempt`; values beyond the budget are clamped to it.
- Replace reason-free lifecycle notifications with events identifying
  Runnable, Dispatch, Stop and Retire, their thread/process, CPU where relevant,
  and explicit stop reason: pre-empted, yielded, blocked, host-wait, control,
  exec or exited. Retire removes policy state only at actual thread retirement,
  not every generation change. The default policy needs no per-thread map.

The default policy's fairness promise is bounded FIFO rotation among a fixed,
eligible runnable set. Arbitrary custom selection policies can intentionally
starve a thread; the mechanism guarantees ownership safety and bounded resident
quanta under contention, not fairness of every plugin's choices.

### Safe callback boundary

Callbacks are trusted, synchronous and required to be bounded/nonblocking.
Invoke none while holding scheduler queue, lifecycle, executor-directory,
binding or deadline locks. Panic is a carrier failure using existing cleanup;
it must not turn into an apparently successful scheduling answer.

For custom picking, copy the view and its exact internal row identities under
the local lock, release it, call policy, reacquire and validate that the chosen
row still has the same thread and generation. If stale, choose the live FIFO
head once rather than retrying a stale snapshot indefinitely. For stealing,
revalidate affinity and exact row before removal. Default FIFO retains its
single short lock and no snapshot allocation. Lifecycle callbacks carry a
mechanism-assigned event sequence; concurrent delivery order is not assumed.

### Demand-driven pre-emption

Track a residency per exact executor binding. Keep CPU label, thread identity,
start time and policy budget; there can be several residencies on one guest CPU.
An execution slot is conserved through handoff; a host-waiting executor is not
a candidate to interrupt for guest CPU fairness.

On runnable publication, first make idle eligible capacity available through
the existing targeted wake/steal path. If eligible backlog remains behind busy
capacity, select the oldest eligible residency for that demand. Candidate
selection uses per-CPU binding indexes, not a scan of every sleeping task.
Affinity constrains both the queued demand and the execution slot that can
serve it. Publish the row before issuing any interrupt request.

The default deadline is `residency_start + 4 ms`. A task already resident longer
than that is eligible for immediate pre-emption when contention arrives.
Shortening may request an earlier boundary. Repeated arrivals never restart
the clock. When another executor consumes the demand, cancel an unclaimed
deadline. No timers or fairness kicks are needed for an uncontended resident.

Use typed request reasons: `Fairness`, `Signal`, `Control`, `Quiesce` and
`HostWaitReturn`. Maintain reasons independently. Cancelling fairness must not
clear a signal/control request. A syscall boundary checks the exact residency's
request/deadline; it does not reschedule merely because any carrier queue is
nonempty. Guest `sched_yield` retains its explicit yield path.

Each deadline has the exact binding and a monotonically changing demand ticket.
Expiry claims and consumes that ticket once. Settlement, exec, exit, unbind,
handoff or cancellation invalidates it. Deliver outside scheduler locks through
the existing exact hardware-kick boundary. An obsolete token cannot target a
successor; a cancellation that races after expiry has claimed delivery may cause
one harmless extra exit of the same live binding, which is separately counted.
No repeated kick loop is allowed for an executor stuck in host code.

### Deadline driver and clocks

Add one carrier-owned scheduling-deadline driver for each active scheduler,
owned and joined by the executor pool. It waits on a condvar until the earliest
deadline or a state-change notification; no fixed-rate sleep, no scanning tick,
no thread per guest. The kernel owns an indexed deadline set and exposes a
wait/due interface; the runtime owns the host thread and lifetime.

This is separate from continuation readiness because that reactor drives I/O.
It is the sole fairness deadline driver, replacing the unused tick path, not a
second implementation of continuation deadlines. Extract due tokens under the
deadline lock, release it, then authenticate and kick. At most one live deadline
per eligible execution slot; cancel/remove entries eagerly rather than growing
a heap of lazy stale entries. Fail startup if the driver cannot be created.

Use host monotonic time for execution-control deadlines, independently of guest
virtual/frozen/realtime clocks. Inject a manual monotonic source into the
VM-free driver tests. Wall residency includes host descheduling, so it is a
latency-control measure, not exact consumed CPU time or a hard real-time promise.
Do not infer guest compute from `CLOCK_THREAD_CPUTIME_ID`: Carrick's HVF
accounting explicitly warns it undercounts guest execution. CPU-share policy
needs separately qualified accounting and is deferred.

### Safe points and handoff

The driver can request exit from guest computation; it cannot suspend arbitrary
Rust code and transfer half-finished MM, file-table or fork transactions.
Once a backend returns, the owning executor processes mandatory control work,
preserves its existing audits, snapshots only when needed, and settles through
the existing exact-generation protocol.

Host-wait entry suspends/disarms fairness for that residency. The replacement
has its own authenticated residency and deadline. Return requests remain
mandatory control work; reacquire the conserved slot and exact MM authority in
the existing Phase 3 order before resuming guest code. Refresh the residency
budget on resumed execution, not while waiting for the host operation.

Retain existing executor counts for this plan. Do not pre-empt a lock holder
to paper over a critical-section convoy, enlarge the pool, or interpret a
deadline request as proof that a safe boundary was reached.

## Contracts and acceptance

Add three contracts (none is registered at the inspected revision):

| ID | Semantic/structural obligation |
|---|---|
| `kernel.scheduler.runnable-progress` | Eligible syscall-free tasks rotate under a finite execution budget; affinity and thread identity remain exact |
| `kernel.scheduler.preemption-lifecycle` | A stale request never affects a successor; control reasons survive fairness cancellation; handoff preserves slot ownership |
| `kernel.scheduler.preemption-cost` | No idle periodic work or uncontended fairness exits; deadlines and notifications scale with active demand, not parked population |

Linux authority is `sched(7)`, `sched_yield(2)`, `sched_setaffinity(2)`, and
pinned native-arm64 Docker fixtures. Linux does not promise Carrick's exact
4 ms quantum or a deterministic SCHED_OTHER run order; those are Carrick
structural contracts and must not be imposed on the oracle.

Deterministic scale points: 1, 8, 32 and 128 runnable threads; execution slots
1, 2 and 4; guest CPUs 1 and 4; include multiple bound executors on one CPU,
two processes, siblings, and affinity-pinned competitors. In a closed one-slot
FIFO cohort of N tasks with quantum Q, every task is dispatched within N
quanta; new tail arrivals cannot overtake an already queued row. Assert this
in logical/manual time, without inventing a wall-clock guarantee under host
starvation. Fixed multi-slot eligible cohorts must all advance within N
expirations; more exact bounds can be specified by the test's topology.

Structural counters: deadline arms/cancels/claims, live entries, candidates
visited, delivered/coalesced/stale kicks, fairness settlements, request-to-boundary
latency, and queue-to-run latency. Record completeness. Require:

- zero fairness kicks and zero deadline wakeups for 10,000 uncontended ordinary
  syscalls and for an idle scheduler;
- at most one pending fairness request per exact residency/demand ticket;
- deadline storage at most the number of live execution slots;
- one due claim produces at most one delivery, never a broadcast;
- adding 1, 8, 32 or 128 parked noncompetitors does not increase fairness work;
- candidate visits per decision are bounded by configured CPU/slot population,
  never historical tasks; use affine budgets where the registry supports them;
  verify ordered-index comparison bounds in typed deterministic tests;
- zero guest execution without a slot, duplicate settlements, stale successor
  deliveries or loss of mandatory control requests.

Signed tests must use a real no-syscall loop with shared atomic progress/stop
words and an independently scheduled controller. Bound failure cleanup outside
the guest. Pin fixture source, ELF and image identity. A manual call to
`request_preemption` does not prove the production driver. A test that lives
under `carrick-embed/tests` is not necessarily a guest test: existing
`host_wait_policy.rs` explicitly runs VM-free.

Timing uses uninstrumented release Carrick and native-arm64 Docker, sequential
phases, same pinned image, fixed executor/CPU configuration, alternating ABBA
order with at least 20 completed samples per arm. Report completion time,
throughput, CPU cost and p50/p95/p99 wake latency. Require the contract's <=2x
Docker p50 completion ratio and <=5% median uncontended regression against the
same-source disabled-fairness ablation. These are proposed acceptance budgets,
not results. A >=10x completing case returns immediately to correctness triage.
No retries, timeout inflation, reduced concurrency or polling as closure.

After host tests, signed embed and Docker bindings, promote one final signed
artifact through probes, smoke and full conformance; preserve SHA-256, CDHash,
LC_UUID, entitlement, DOF section and run-ID-scoped cleanup. KVM/bhyve/NVMM
receive compile and VM-free coverage here; claiming forced-exit parity requires
their own hardware receipts. Missing required lane evidence stays open.

## Explicitly deferred

Full Linux RT/FIFO/RR/deadline semantics; nice-weight implementation; automatic
interactive boosts; process or tenant shares; host-wide coordination across
carriers; host P/E-core binding; priority inheritance; changes to memory quiesce;
and the Phase 3 executor-count reduction. They are not acceptance shortcuts.
The new context makes later policy work possible without granting it ownership
of execution or inventing guest-visible scheduling classes.
