# Guest-CPU Scheduler — Design (for owner review)

**Date:** 2026-09-07
**Lane:** macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest
**Status:** proposal. Nothing here has landed; the `sched-herd` worker is
fixing the symptoms named in "Problem" while this is reviewed.

---

## Problem

The carrier has executors, a run queue and a reactor, but no *scheduler* in
the kernel sense: no notion of a guest CPU as a domain that owns a queue, a
current task and one host thread, and no notion of a safe point as a
scheduler operation. Every consequence below was measured on 2026-09-07
(`docs/conformance-campaigns/2026-09-04-ecosystem.md`, section "load
coupling measured"):

1. **One run queue, one mutex, `notify_all` everywhere.** `RunQueueInner`
   (`kernel/scheduler.rs`) wakes every parked executor on every claim finish,
   authority release and wake-admission release. Ten executors stampede,
   contend on the mutex (`parking_lot::lock_slow` under
   `GuestExecutorCensus::enter_inner`, `WakeAdmission::drop`,
   `settle_blocked_continuation`), and go back to sleep. `cpython-importlib`
   shows ~44k involuntary context switches per second on an idle host.
2. **Unconditional `sched_yield` per executor boundary**
   (`vcpu_loop/executor.rs`, tail of `run_executor_loop`). Under three
   default-QoS `yes` hogs on a 10-core host a single-threaded row runs 1.3x
   slower with 1.3x the CPU-seconds; background-QoS hogs cost nothing.
   The yield hands the core to any equal-priority competitor on every
   boundary.
3. **Executors are not guest CPUs.** The guest sees `min(P-cores, logical)`
   = 4 CPUs; ten executors (host physical cores) run its tasks; a woken task
   migrates to whichever executor wins the herd (register save/restore, ASID
   switch, cold TLB every time). `sched_getcpu`/affinity are fiction. A
   carrier can burn ten host cores while claiming four, which is exactly the
   over-subscription a four-worker harness turns into load coupling.
4. **Blocking is not a scheduler operation.** Only the continuation outcomes
   in `is_blocking_dispatch_outcome` park a task; synchronous host file
   I/O, fault materialization and the fork transaction run inline holding
   the vCPU, so an executor stuck in a host `read` idles a guest CPU.
5. **Safe points are three global mechanisms outside the scheduler.**
   `PtQuiesce` (one carrier-wide coordinator election for every
   `mmap`/`munmap`/`mprotect`/`brk`), the fork `QuiesceBarrier`
   (`kick_all_except` over every vCPU in the carrier), and
   `fork_quiesce::topology_lock()` (one mutex for fork, COW fault, alias
   map/unmap, retire, exec). Each is "true with one process, wrong with two".

## Reference model

Go's runtime scheduler (BSD-licensed; the sanctioned dual-port oracle):
**G/M/P**. A *P* is a logical processor that owns a local run queue and is
the unit of parallelism (`GOMAXPROCS`); an *M* is a host thread that must
hold a P to run Gs; a *G* is a task. Blocking syscalls hand the P off to
another M (`handoffp`); idle Ps steal from busy ones; wakeups target one
idle P (`wakep`), never all. Linux's per-CPU run queues, wake affinity and
IPI-based TLB shootdown are the same shape at the kernel level.

## Proposal

**GuestCpu (P).** `nproc` of them, where `nproc` is the exposed CPU count
the guest already sees (`host_facts::select_exposed_cpu_count`). Each owns:
a local run queue (its own mutex — no carrier-wide queue lock on the hot
path), the *current* task, an idle condvar, a preemption tick, and the
identity the guest observes (`sched_getcpu`, `/proc/self/status
Cpus_allowed`, `sched_setaffinity` become exact).

**Executor (M).** A host pthread owning one HVF vCPU lease, as today. An M
runs only while bound to a P. The steady state is one M per P; extra Ms
exist only to take over a P whose M entered a blocking host call
(`handoffp`), and park when the call returns. The persistent-executor
audits (TLS/cache, `AuditPassed`) are unchanged; they gate every P
switch.

**Task (G).** `MigratableTaskState` as today, plus `last_cpu` and an
affinity mask. Wake = enqueue on `select_cpu(task)`: `last_cpu` if idle,
else the idlest allowed P; then wake THAT P's condvar with `notify_one`.
`sched_yield` from the guest requeues at the tail of the same P. Idle Ps
steal from the busiest queue before parking (Go's `findrunnable`).

**Blocking as a scheduler operation.** A dispatch that may block on the
host (file read/write slow paths, `connect`, `fsync`, record locks) either
completes as a continuation serviced off-executor (the reactor / a bounded
I/O helper pool — the `HostWrite` continuation already has this shape) or
hands its P to a spare M before entering the call. No inline host wait
ever idles a P.

**Safe point as a primitive.** `quiesce(mm, participants)`: for each P
whose current task is in `participants`, kick its M (`hv_vcpus_exit`) and
have it park the task at the boundary; the requester waits on a per-mm
count, edits, then resumes. This ONE primitive replaces the carrier-global
`PtQuiesce` election (the drain is already per-mm), the fork barrier's
`kick_all_except`, and the parts of the topology lock that exist to
exclude sibling execution rather than to order registry mutations. What
remains carrier-wide is a short frame-registry critical section for
frames genuinely shared across mms.

**No unconditional yield.** An M with nothing runnable on its P (and
nothing to steal) parks on the P's condvar. Fairness between Ps is the
tick, not `sched_yield`.


## Policy interface — an embedder can pass a scheduler

Owner requirement (2026-09-07): `carrick-embed` must accept a scheduler
from the embedding program, the way `ContainerBuilder` already accepts
`time(TimeControl)`, `observer(..)`, `interceptor(..)` and
`network_interposer(..)`.

Split today's `Scheduler` into **mechanism** and **policy**:

- *Mechanism* (stays in `kernel/scheduler.rs`, not pluggable): exact-
  generation claims, `WakeAdmission`, settlement (`settle_*`), executor
  registration and audits, close/drain observation counting, the
  fork/exec/exit transitions. These are correctness invariants; no policy
  may express a wrong one.
- *Policy* (`carrick_hal::SchedulingPolicy`, object-safe, `Send + Sync`):
  `cpu_count()`, `select_cpu(task: &TaskPlacement) -> GuestCpuId` (task id,
  `last_cpu`, affinity mask, per-CPU load snapshot), `pick_next(cpu) ->
  Option<TaskKey>` over that CPU's queue view, `steal(cpu) ->
  Option<(GuestCpuId, TaskKey)>`, `on_tick(cpu) -> Preempt|Continue`,
  and notification hooks (`on_runnable`, `on_block`, `on_exit`) that carry
  typed identities only. The default implementation is the GuestCpu
  policy above (per-CPU queues, last-CPU affinity, stealing).

`ContainerBuilder::scheduler(policy: Arc<dyn SchedulingPolicy>)` installs
it for that container's carrier; `RunRequest` carries it like
`TimeControl`. An embedder can therefore run a deterministic scheduler
(one CPU, FIFO, tick-driven preemption for reproducible tests), a
priority scheduler, or a host-integrated one that consults its own
workload. The policy never sees host threads, vCPUs or generations — it
answers "which guest CPU, which task next", the mechanism does the rest.

## What this buys, measured against today

| symptom | today | with the design |
| --- | --- | --- |
| wake cost | `notify_all` × 10, mutex convoy | one condvar signal |
| task placement | random executor, ASID/TLB cold | `last_cpu` affinity |
| host CPU demand per carrier | up to 10 cores + helpers | ≤ `nproc` Ps + I/O helpers |
| per-boundary `sched_yield` | always | never |
| `mmap` in process A vs `brk` in B | serialized by one election | independent (per-mm quiesce) |
| fork in a threaded parent | kicks every vCPU in the carrier | kicks the thread group's Ps |
| inline host I/O | idles a vCPU | hands the P to a spare M |

## Phasing

1. **Symptoms (worker `sched-herd`, in flight):** remove the boundary
   yield; exact wakes (`notify_one` to a runnable waiter; close waiters on
   their own condvar); shorten the census/admission holds.
2. **Per-CPU queues, affinity, and the policy hook** — whose first consumer
   is an adversarial/record-replay policy in `carrick-embed`'s signed tests
   that pins the load-coupled `lost exact transition` abort
   deterministically (owner, 2026-09-07: races in the scheduler's own
   transitions are reproduced through the scheduler interface, not through
   host load or syscall jitter alone): `GuestCpu` with local queues, executor
   count = `nproc`, `last_cpu` placement, work stealing, `notify_one`.
   Gate: two-process concurrent suites, `cpython-importlib`/`itertools`
   CPU-seconds flat under three default-QoS hogs (the coupling driver's
   L1), no row slower idle.
3. **Blocking handoff:** classify inline host waits; continuation or
   `handoffp` for each; no P idles in a host call.
4. **Safe-point primitive:** per-mm `quiesce`; retire the global
   `PtQuiesce` election and the fork barrier's carrier-wide kick; then
   scope the topology lock per mm (worker `mm-scope` round 1 delivers the
   HVF TLBI-broadcast experiment and the per-mm election that this phase
   builds on).

## Non-goals

Guest-visible CPU count changes (the P-core rule stays); NUMA; real-time
classes; any change to the frame inventory's ownership exactness.

## Open questions for the owner

- Should `nproc` (and so P count) follow performance cores only, as today,
  or all logical cores? The four-worker harness argues for P-cores; a
  single heavy container argues for all ten.
- Spare-M budget: bounded by the HVF vCPU ceiling (60 per VM after
  reserve); propose `2 × nproc` with a `CARRICK_SPARE_EXECUTORS=` hatch.
- Whether the reactor thread should become the I/O helper pool or stay a
  pure readiness service.
- Resolved 2026-09-07 (owner): the design is approved, and the policy must
  be embed-pluggable (section above).
