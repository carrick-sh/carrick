# Pluggable Scheduler Pre-emption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
> if the owner later authorizes implementation. Steps use checkbox syntax for
> tracking. **The current request authorizes planning only. Do not execute these
> steps, change code, run builds/tests, or commit as part of preparing this plan.**

**Goal:** Guarantee bounded scheduling opportunities for competing guest threads,
including syscall-free computation, through Carrick's existing pluggable scheduler.

**Architecture:** Preserve kernel-owned queues, execution claims and settlement,
and the `ContainerBuilder::scheduler` entry point. Extend policy context and use
exact, demand-driven deadlines to interrupt selected live executor residencies.
The default remains affinity-aware placement with FIFO selection, adding a
proposed 4 ms quantum under contention and no periodic work without contention.

**Tech Stack:** Rust 1.96.0; existing HAL, kernel, runtime and embed crates;
existing backend kick interfaces, parking_lot synchronization and conformance
contract infrastructure. No new runtime dependency is proposed.

**Spec:** [Research and design](../specs/2026-09-19-pluggable-scheduler-preemption-design.md).

**Inspected base:** `e181864aa6c47a9df0681da433c548e46a72e771`.
**Status:** Draft for owner review. No implementation or measured performance
claim. Recheck the live tree at execution time; other work is active here.

## Global constraints

- Planning only until explicit implementation authorization.
- Keep `ContainerBuilder::scheduler(Arc<dyn SchedulingPolicy>)`; evolve the
  trait in place, without a V2 trait, legacy adapter or second queue owner.
- Policies choose placement, ordering and budgets; only the mechanism owns
  execution generations, leases, hardware kicks and settlement.
- Preserve Linux-visible results, affinity, signals, continuations, fork/exec/
  exit, and guest CPU exposure. Do not claim RT scheduling support.
- Work with multiple executors per guest CPU. Do not change executor sizing.
- The [GMP Phase 3 plan](2026-09-19-gmp-phase3.md),
  [handoff](2026-09-19-gmp-phase3-handoff.md), and
  [host-wait inventory](2026-09-19-gmp-phase3-host-waits.md) retain their full
  scope and acceptance obligations.
- A host wait releases execution capacity through the existing handoff;
  an in-zone wait uses an owned continuation. A kick cannot replace either.
- Invoke no policy callback under a scheduler queue, lifecycle, directory,
  binding or deadline lock. Callbacks are trusted, bounded and nonblocking.
- Scheduling deadlines use host monotonic time, independently of guest clocks.
- No polling, retry-until-green, wider timeouts, reduced concurrency, increased
  executor counts or weakened budgets as closure.
- Capture red evidence before implementation, then complete VM-free, signed
  embed and pinned Docker proof. Higher layers cannot excuse a lower failure.
- Carrick and Docker phases never overlap. Signed promotion uses one exact
  artifact: probes, smoke, full; preserve provenance and scoped cleanup.
- No push unless requested. Preserve unrelated edits and controller state.

## Research decision

| Source | Adopt | Defer |
|---|---|---|
| XNU Clutch/Edge | Bounded latency preference, safe-boundary requests, locality | QoS hierarchy, warp constants, physical cluster placement |
| FreeBSD ULE | Local queues, targeted/coalesced pre-emption, idle capacity first | Adaptive slice tuning, interactive scoring, priority inheritance |
| illumos dispatcher/TS/FSS | Policy/mechanism separation, explicit lifecycle, separate group identity | Dispatch priority tables, process/tenant shares |

The spec includes revision-pinned primary sources and the inspected functions.
These are design precedents, not Linux semantic oracles. Do not copy their
implementation into Carrick.

## Review focus

1. Sibling threads of one process must be separately selectable; process shares
   must not be accidentally implemented through aliased thread identities.
2. A late deadline crossing exec, unbind or handoff must not affect a successor;
   cancelling fairness must preserve pending signals and mandatory control.
3. Multiple executors on one guest CPU require multiple independent residency
   records; the single `GuestCpu::current_task` field is not scheduling authority.
4. Callback reentrancy, changing queue views and replay divergence must not cause
   deadlock, unbounded retries or silent fallback presented as exact replay.
5. Host descheduling, frozen guest clocks and inline host waits must not be
   mistaken for consumed guest CPU or a successful hardware pre-emption.

## File responsibilities

Paths below are relative to the repository root. Existing files are modified only
where named; proposed new files are explicitly marked.

| Area | Files | Responsibility |
|---|---|---|
| Policy API | `crates/carrick-hal/src/scheduler.rs`, `src/lib.rs` | Typed thread/process identity, budget and context, default policy |
| Queue mechanism | `crates/carrick-kernel/src/kernel/scheduler.rs` | Callback boundaries, publication, claim and settlement integration |
| Pre-emption state (new) | `crates/carrick-kernel/src/kernel/scheduler/preemption.rs` | Per-binding residencies, demand tickets, reason state, indexed deadlines |
| Handoff | `crates/carrick-kernel/src/kernel/scheduler/host_wait.rs` | Suspend/reactivate residency as slot ownership changes |
| Deadline driver (new) | `crates/carrick-runtime/src/vcpu_loop/executor/preemption.rs` | One parked/joinable host helper per scheduler |
| Runtime integration | `crates/carrick-runtime/src/vcpu_loop/executor.rs`, `executor/{pool,binding,settlement}.rs`, `vcpu_loop/binding.rs` | Exact kicks, boundary decisions, startup/shutdown |
| Embed consumers | `crates/carrick-embed/src/{lib,builder,testing}.rs` | Reexports, documentation, adversarial policy and replay |
| Diagnostics | `crates/carrick-kernel/src/kernel/debug/dto.rs`, `event_ring.rs`, `crates/carrick-observability/src/work_meter.rs` | Bounded snapshots, reasons and complete structural observations |
| Public VM-free tests (new) | `crates/carrick-kernel-example/tests/scheduler_preemption.rs` | Progress, identity, lifecycle and cost proofs through public APIs |
| Signed tests (new) | `crates/carrick-embed/tests/scheduler_preemption.rs` | Actual guest compute interrupted by the production driver |
| Guest fixture (new) | `fixtures/linux-aarch64-hello/src/scheduler_preemption.rs` | Shared atomic progress and syscall-free worker loop |
| Fixture registration | `fixtures/linux-aarch64-hello/Cargo.toml`, `scripts/build-linux-fixtures.sh` | Build and identify the exact guest ELF |
| Contracts (new) | `conformance-contracts/contracts/scheduler-{progress,lifecycle,cost}.toml` | Stable IDs, bindings, structural and timing budgets |
| Contract wiring | `conformance-contracts/surfaces.toml`, kernel-example/embed `src/contracts.rs`, existing conformance-next contract runner pattern | Fail-closed layer registration and ordinary gate execution |

Do not restructure the entire scheduler. Extract only the new pre-emption state
and driver so their ownership and shutdown can be reviewed independently.

## Interface decisions to implement

These are proposed signatures, not changes made by this planning task. Definitions
are concentrated here so later tasks use the same vocabulary.

```rust
// carrick-hal; opaque IDs with new/as_u64 accessors.
pub struct SchedThreadId(u64);  // kernel ThreadSerial, never process TaskSerial
pub struct SchedProcessId(u64); // kernel TaskSerial

pub struct RunBudget { quantum: std::time::Duration }
// RunBudget::new(Duration) -> Result<RunBudget, BudgetError>
// Accepted: 1 ms through 100 ms, inclusive. GuestCpuPolicy uses 4 ms.

pub struct DispatchContext {
    pub thread: SchedThreadId,
    pub process: SchedProcessId,
    pub cpu: GuestCpuId,
    pub load: CpuLoad,
}
pub struct ContentionContext {
    pub running: DispatchContext,
    pub residency_elapsed: std::time::Duration,
    pub eligible_queued: usize,
}
pub enum PreemptionAction {
    KeepBudget,
    ShortenTo(std::time::Duration), // measured from residency start
    Preempt,
}
// Replace on_tick with these methods on the existing SchedulingPolicy:
// fn on_dispatch(&self, context: &DispatchContext) -> RunBudget;
// fn on_contention(&self, context: &ContentionContext) -> PreemptionAction;
```

Default trait methods return the validated 4 ms budget and `KeepBudget`.
`TaskPlacement`, `CpuQueueView`, `pick_next` and `steal` use `SchedThreadId`;
placement also carries `SchedProcessId`. Replace the old HAL `TaskKey` spelling
throughout all consumers. Kernel `TaskKey` and `ThreadKey` stay unchanged.

Lifecycle events use `SchedulingEvent { sequence, thread, process, cpu, kind }`.
`sequence` is a typed monotonically increasing scheduler event number, `cpu` is
optional, and `kind` is `Runnable`, `Dispatch`, `Stop(SchedulingStopReason)` or
`Retire`. Stop reasons are `Preempted`, `Yielded`, `Blocked`, `HostWait`, `Control`,
`Exec` and `Exited`. `SchedulingPolicy::on_event(&SchedulingEvent)` replaces the
three reason-free notifications. Exited execution and identity retirement are
distinct: retire policy state only when that thread identity is no longer live.
Concurrent delivery can be out of sequence; consumers must not infer ordering
from callback arrival. The default policy keeps no event-dependent task map.

Kernel-private records pair `ExecutorBinding` with a `DemandTicket`, residency
start, budget, eligible demand and a reason set. `DemandTicket` is a checked
monotonic counter; overflow is a named failure. The driver-facing public kernel
API exposes opaque due requests and the following operations:

```text
Scheduler::wait_preemption_work() -> PreemptionWork
  Wait atomically for deadline expiry, state change or driver shutdown.
  Return Due(Vec<PreemptionRequest>) or Shutdown; no scheduler lock escapes.
Scheduler::deliver_preemption(request: PreemptionRequest) -> DeliveryOutcome
  Authenticate exact binding/ticket and perform at most one hardware delivery.
Scheduler::stop_preemption_driver()
  Close notification/wait state and wake the helper for join.
```

`PreemptionRequest` has private fields; policy code cannot construct it.
`DeliveryOutcome` distinguishes Delivered, Stale, Cancelled and Coalesced.
The kernel engine takes an injected monotonic clock; the production default is
host monotonic time. VM-free tests advance a manual clock and notify the same
wait predicate. This is not guest `TimeControl` and never changes guest clocks.

## Task 1: Make policy identity and callback boundaries correct

**Files:** HAL scheduler/reexports, kernel scheduler, embed reexports/testing;
new public VM-free test file.

**Consumes:** Existing kernel `ThreadKey`, `TaskKey`, `QueueKey`, local queues.
**Produces:** Distinct `SchedThreadId`/`SchedProcessId`; snapshot/callback/
revalidate selection; consistent policy consumers.

- [ ] Add a red regression that clones two siblings, queues both, and uses a
  custom policy to select the second. Assert two distinct policy thread IDs,
  equal process IDs, and the exact second `ThreadKey` is claimed. Repeat with
  a second process to pin both identity domains.
- [ ] Add a callback test that performs a scheduler snapshot/reentrant read
  while selecting. Use bounded channel/barrier coordination, not sleeps, to
  demonstrate that the old lock-held callback cannot finish. Ensure test
  teardown releases the blocked lane rather than leaking a deadlocked thread.
- [ ] Project thread serials for every placement/view/event path. Audit every
  existing `TaskKey::new(...task_key().serial...)` policy projection.
- [ ] For custom selection, snapshot exact rows under lock, unlock for callback,
  then revalidate the selected thread AND execution generation. On stale
  selection take the current FIFO head once. Default FIFO makes no snapshot.
  Revalidate affinity when stealing. Do not loop until a policy answer sticks.
- [ ] Add queue-change-during-callback and stale-affinity tests. Prove default
  FIFO still allocates no queue view and doesn't invoke custom inspection.
- [ ] Update adversarial/replay types and run the focused public suite followed
  by `RUSTC_WRAPPER= just test-kernel` and the HAL/embed compile closure.
- [ ] Produce a narrow reviewed checkpoint. Do not describe this as timed
  pre-emption or signed acceptance.

**Acceptance assertions:** sibling IDs differ; selected sibling matches; stale
choice never claims a different generation; no callback runs with a mechanism
lock held; default FIFO behavior is unchanged.

## Task 2: Introduce explicit residency budgets and reasoned requests

**Files:** HAL scheduler; kernel scheduler and new `scheduler/preemption.rs`;
runtime worker kick/boundary code; embed policy consumers.

**Consumes:** Task 1 identity and lock boundary.
**Produces:** The policy context/budget/event API above, per-binding residency,
independent fairness and mandatory-control request state.

- [ ] Add budget constructor tests with these exact expectations:

  ```rust
  assert!(RunBudget::new(Duration::ZERO).is_err());
  assert!(RunBudget::new(Duration::from_millis(1)).is_ok());
  assert!(RunBudget::new(Duration::from_millis(4)).is_ok());
  assert!(RunBudget::new(Duration::from_millis(100)).is_ok());
  assert!(RunBudget::new(Duration::from_millis(101)).is_err());
  ```

- [ ] Add a red one-CPU/two-executor test: distinct running siblings receive
  independent residency records and policy contexts. Never derive them from
  `GuestCpu::current_task`.
- [ ] Add a pending-signal-plus-fairness test: cancel fairness, consume the
  next boundary, and prove signal/control is still pending and serviced.
- [ ] Replace `on_tick` and all in-tree implementations in one migration.
  Update events on actual claim/stop/retire edges; no callback for duplicate
  coalesced publication. Document no cross-thread callback order guarantee.
- [ ] Register residency after exact binding becomes runnable on the executor;
  finalize it exactly once at stop, including errors. Separate request reasons
  from the worker's old undifferentiated boolean. Preserve urgent paths.
- [ ] Replace carrier-wide queue-nonempty syscall switching with exact
  residency request/deadline checks. Explicit guest yield remains immediate.
- [ ] Verify 10,000 uncontended syscall steps retain residency without a
  fairness snapshot, fairness kick, deadline wake or spurious stop event.
- [ ] Run focused runtime tests in their existing serial lane and
  `RUSTC_WRAPPER= just test-kernel`; review/commit only this task's changes.

## Task 3: Prove demand selection and bounded deadline behavior VM-free

**Files:** Kernel pre-emption submodule and queue publication/claim paths;
public VM-free tests; work metrics and scheduler debug DTO.

**Consumes:** Per-binding residency and budget API.
**Produces:** Indexed exact deadline set, demand tickets, driver-facing API,
structural observations.

- [ ] Add a red manual-clock case: one executor runs A indefinitely, B queues
  on its only allowed CPU, and advancing 4 ms must produce one exact request
  for A. This fixture must exercise publication, not manually call broadcast
  `request_preemption`.
- [ ] Specify event timelines before implementing:

  | Timeline | Required result |
  |---|---|
  | A starts at 0; B queues at 1 ms | One request due at 4 ms |
  | A starts at 0; B queues at 20 ms | A immediately eligible for one request |
  | More wakes at 2 and 3 ms | Original 4 ms deadline is not extended |
  | B is claimed by an idle executor before expiry | Cancel unclaimed deadline |
  | B only allows CPU 0; CPU 1 is busy | Never kick CPU 1 for B |
  | One contender, several busy executors on CPU 0 | Select one oldest eligible residency |
  | Demand disappears after delivery claim | At most one extra exit of the same binding |
  | Deadline fires after exec/unbind | No successor receives that request |

- [ ] Publish runnable state before notification. Try eligible idle capacity
  first; otherwise index demand by allowed local execution slots and select
  the oldest residency. Index bindings per CPU to avoid a global task scan.
- [ ] Recompute demand at publication, claim, affinity change, stop, migration,
  handoff and retirement. A row gated on publication is not eligible demand.
  A finite cohort already queued at driver startup must also arm correctly.
- [ ] Use one removable ordered deadline entry per execution slot, with exact
  binding and ticket. Expiry claims once; deliver after releasing all locks.
  Eager cancellation bounds memory; do not accumulate stale heap entries.
- [ ] Ensure worker registration/hardware publication races preserve a pending
  request, while successor binding creation clears only predecessor state.
- [ ] Add fixed-cohort FIFO rotation at N = 1, 8, 32, 128 and execution slots
  1, 2, 4. One-slot cohorts all dispatch within N logical quanta; fixed
  multi-slot cohorts all progress within N expirations. Include siblings and
  two processes. Check affinity, no duplicate claims and no leaked entries.
- [ ] Add parked-population scaling tests, wake storms, zero-demand idle and
  cancellation-before-expiry. Count operations, not elapsed test time.
- [ ] Run `RUSTC_WRAPPER= just test-kernel`. Review the state machine and its
  lock order before accepting this checkpoint.

**Cost assertions:** live deadline entries <= live execution slots; one claimed
ticket yields <=1 delivery; one demand does not broadcast; parked population
adds zero candidate visits; idle and uncontended execution have zero periodic
fairness work. Instrument candidate visits using a per-decision affine bound
in CPU/slot count and test ordered-index work separately.

## Task 4: Connect the real one-shot driver and safe executor boundaries

**Files:** New runtime `executor/preemption.rs`; executor pool/binding/
settlement and production loop; kernel driver API; existing backend kick seams.

**Consumes:** Task 3 wait/due/deliver interface.
**Produces:** Production demand-driven pre-emption, driver lifetime and shutdown
receipts. Exactly one driver per scheduler, including unusual multiple-pool
construction: duplicate attachment is a typed startup error.

- [ ] Add a real-worker test where the executor engine waits for its hardware
  kick and no test calls a pre-emption helper. Queue a competitor and require
  the production driver to deliver and the executor to settle once.
- [ ] Add startup failure, duplicate driver, close-before-start,
  close-during-expiry, worker failure and shutdown-with-future-deadline tests.
  Require every started helper to join, with no timer retaining the carrier.
- [ ] Start a joinable helper under `ExecutorPool` ownership. Block on the
  kernel wait predicate; state changes wake it, expiry yields due work, and
  shutdown returns `Shutdown`. Never implement a periodic sleep loop.
- [ ] Keep the fairness driver independent of continuation I/O processing.
  It only claims due requests and issues existing exact backend kicks; no
  guest memory, syscall execution, resource retirement or user callback runs
  on this helper.
- [ ] Consume pending reasons at audited safe boundaries. A long Rust handler
  retains a request until it can safely settle; never asynchronously transfer
  its guest memory, locks, TLS, vCPU or execution lease.
- [ ] Remove unused broadcast/tick scheduling paths after updating their tests.
  Keep mandatory signal/control kicks distinct. No compatibility wrapper.
- [ ] Add default-on diagnostic ablation `CARRICK_FAIR_PREEMPTION=0` only for
  controlled before/after experiments; receipts record its value and disabled
  runs cannot qualify fairness acceptance.
- [ ] Run serial runtime coverage, `just test-kernel` and supported compile
  closures. No backend hardware claim follows from compile success alone.

## Task 5: Compose handoff, cancellation, replay and diagnostics

**Files:** Kernel host-wait/pre-emption/settlement; runtime bindings;
embed testing; existing scheduler-handoff, host-wait-policy and new pre-emption
tests; debug DTO/event ring.

**Consumes:** Production driver and exact request state.
**Produces:** Lifecycle composition and replay evidence; Phase 3 remains open.

- [ ] Add handoff while fairness is armed: original A relinquishes its slot,
  replacement B runs, A's deadline cannot kick B, B can be independently
  pre-empted, and A reacquires the slot through existing return control.
- [ ] Cover no spare, nested waits, concurrent returners, exit during host wait,
  exec replacement, signal arrival, job control and close. Use the existing
  production host-I/O injection seam for composition; do not invent a new
  syscall path just for the tests.
- [ ] Suspend/cancel old residency at host-wait entry. Resume only after slot
  and MM readmission; issue a fresh residency ticket. Preserve mandatory
  return/control requests regardless of runnable backlog.
- [ ] Record new policy inputs, elapsed logical residency, budgets, actions,
  lifecycle sequence and stale-answer fallback. Replay validates both input
  and result. VM-free exact replay requires zero divergences; signed replay
  reports divergence honestly and is not claimed to replay physical timing.
- [ ] Add independent policy tests: default, always-preempt-on-contention,
  longer validated quantum, affinity-pinned and adversarial selection. Prove
  injection reaches the production driver without exposing executor authority.
- [ ] Expose per-binding residency, reason, deadline and request-to-boundary
  status in existing debug tables. A contended snapshot returns unavailable,
  not idle. Add bounded event-ring records rather than hot-path logging.
- [ ] Run public kernel tests and serial runtime/embed host tests. Review the
  Phase 3 overlap explicitly; do not mark its unproved host sites complete.

## Task 6: Register contracts and prove real syscall-free guest progress

**Files:** Three contract descriptors/surface registry; VM-free/embed contract
bindings; new guest fixture and registration; signed test and ordinary
conformance-next binding following `futex_contract.rs`; existing metric registry.

**Consumes:** Tasks 1–5; existing signed test/fixture toolchain.
**Produces:** Source-hash-bound, machine-readable observations at every layer.

- [ ] Register the spec's IDs `kernel.scheduler.runnable-progress`,
  `kernel.scheduler.preemption-lifecycle`, and
  `kernel.scheduler.preemption-cost`. All need actual VM-free, signed and
  Docker bindings; names without executable bindings do not count.
- [ ] Create a guest fixture that maps shared atomic progress/stop state before
  worker start, then runs workers without syscalls. A sibling controller must
  itself be scheduled to observe progress and stop them. Include 1/8/32/128
  workers, more workers than bound executors, two-process and affinity cases.
  Publish a normalized success result only after every required worker advanced.
- [ ] Add a separate intermittently waking controller/worker mode to measure
  wake latency. Its waiting primitive is a normal bounded futex/pipe wait;
  the compute workers remain syscall-free. Do not use timed polling to make
  the supposedly blocked controller progress.
- [ ] Use host-side deadline/capture/cleanup facilities for a failing guest.
  Missing entitlement is failure. Verify actual guest instructions and kick
  receipts, not just placement callbacks or mock engine behavior.
- [ ] Capture signed red on the pre-driver implementation (or the explicit
  disabled-driver diagnostic arm) and green with the production driver. Record
  source/binary/fixture hashes and cleanup for both. Tests that already passed
  on the old binary cannot be claimed as evidence of this defect's correction.
- [ ] Run the same fixture on pinned native-arm64 Docker in a separate phase.
  Compare success, affinity and lifecycle results, not exact schedule order or
  Carrick's 4 ms quantum. Register new generic probes via conformance-next,
  never a new legacy CLI subprocess probe.
- [ ] Wire new tests into normal recipes so unfiltered `just test-kernel`,
  `just test-embed` and the applicable public probe gate execute them.

**Future execution commands:**

```sh
RUSTC_WRAPPER= just test-kernel
RUSTC_WRAPPER= just test
RUSTC_WRAPPER= just test-embed scheduler_preemption
RUSTC_WRAPPER= just ci
```

Filters are test-name filters under existing recipes, not evidence of broad
acceptance. Signed tests need names containing `scheduler_preemption` for the
shown focused command. Verify fixture freshness before reading verdicts.

## Task 7: Measure cost and complete signed acceptance

**Files:** Existing Rust conformance/timing harness and contract observations;
new dated evidence report under `docs/conformance-campaigns/`.

**Consumes:** Green lower-layer contracts and exact signed artifacts.
**Produces:** Acceptance receipts, or named failures and a resumable handoff.

- [ ] Freeze workload, image digest, fixture SHA, source HEAD, host conditions,
  policy, guest CPU count, bound/spare counts and concurrency before measuring.
  Include uncontended compute, syscall-heavy execution, saturated compute,
  wake latency and mixed handoff. Do not reduce ordinary executor contention
  to get a better result.
- [ ] First compare driver-on/off using the same release artifact and fixed
  configuration for uncontended overhead. Require <=5% median regression,
  at least 20 completed samples per arm, and zero uncontended fairness work.
  Disabled-driver saturated runs are bounded negative controls, not samples
  to exclude silently from a timing distribution.
- [ ] Separately compare uninstrumented Carrick with pinned same-image native
  arm64 Docker, in serialized ABBA phases with at least 20 completed samples
  per arm. Report p50/p95/p99 wake latency, completion, throughput and CPU cost;
  require contract p50 completion <=2x Docker. Host starvation limits any
  wall-clock latency claim; report it rather than widening the budget.
- [ ] For custom policies, publish their declared budgets and measured results
  separately. Arbitrary custom selection cannot inherit default FIFO fairness.
- [ ] Promote the final artifact without relinking/re-signing between rungs:

  ```sh
  RUSTC_WRAPPER= just conformance-probes
  RUSTC_WRAPPER= just --no-deps conformance smoke
  RUSTC_WRAPPER= just --no-deps conformance
  ```

- [ ] Record SHA-256, CDHash, LC_UUID, hypervisor entitlement, DOF presence and
  run-ID-scoped cleanup after each rung. A red rung blocks promotion. Do not
  convert missing evidence or flaky results into expected gaps.
- [ ] Reconcile documentation around the installed policy, removed tick hook,
  exact multi-executor representation and remaining host-wait work. Claim
  HVF forced-exit behavior only when proven; keep KVM/bhyve/NVMM hardware
  acceptance explicitly open until their own real-lane tests run.
- [ ] Review the whole diff and receipts. Leave incomplete gates named; do not
  modify the Phase 3 completion state or push as a side effect.

## Dependency order and stopping points

```text
1 identity/lock boundary
  -> 2 policy budgets/reasons
  -> 3 deterministic deadline mechanism
  -> 4 production driver
  -> 5 lifecycle/replay composition
  -> 6 signed/Docker contracts
  -> 7 cost and broad acceptance
```

This is one architectural change with sequential ownership dependencies, not
seven independent implementations. Worker execution choices can be decided
after review. No delegation or implementation starts from this plan alone.

Stop and repair the owning layer on stale successor delivery, lost control,
slot duplication, unbounded callback retry, periodic idle work, incomplete
measurement, unsupported required binding or a failed signed rung. Preserve
unrelated ongoing work. A planning document or focused green test does not
close Carrick's full conformance objective.
