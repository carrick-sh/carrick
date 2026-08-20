# HVPatch persistent executor scheduler

**Status:** approved implementation refinement under the standing kernel-security/performance goal.

**Extends:** [`2026-08-13-mn-scheduler-design.md`](2026-08-13-mn-scheduler-design.md). That document remains authoritative on the destination: persistent `(host pthread, HVF vCPU)` executors, migratable Linux threads, blocked threads owning no executor, and deletion of the welded-thread path. This document defines the mechanisms the earlier design intentionally did not spell out.

## Measured reason to do this now

At `b7f7662e01c39e83cac17d6d8ef29715d5467ddb`, the raw 10,000-cycle fork/exit/wait reducer takes a warm median `4.54 s` in Carrick and `0.66 s` in native-arm64 Docker (`6.88x`). One thousand guest forks induce `1,003` Darwin pthread creates, `1,001` pthread terminations, and `80,733` host syscalls. Removing per-child waiter construction cuts the syscall count by roughly 28% but does not improve wall time; the pthread/vCPU lifetime boundary, not kqueue setup, is structural.

## Security and correctness invariants

- Host containment is primary; Linux intra-guest isolation is co-equal.
- A live HVF vCPU is created, run, invalidated, and destroyed by one persistent executor pthread.
- A Linux thread may migrate only as an inert, complete, exact-generation task state.
- A blocked thread owns no executor, vCPU, pthread, private wake pipe, or per-thread kqueue.
- Kernel object generations authenticate every state transition, wake, continuation, MM binding, ASID residency, and executor kick.
- No guest raw pointer survives suspension without the exact MM generation that authorized it.
- No previous task's credentials, signal state, continuation caches, TLS, mappings, or CPU accounting may survive an executor switch.
- HVPatch has one scheduler after migration. A temporary adapter may exist only between explicitly named implementation tasks and is statically forbidden in the final build.

## Two state domains

The current engine mixes state that belongs to a Linux thread with state that belongs to the physical executor. Migration requires a hard split.

### `MigratableTaskState`

Owned by exact Kernel `ThreadKey` and `ExecutionGeneration`:

- EL0 GPRs, PC, PSTATE, SP_EL0;
- user-observable TLS (`TPIDR_EL0`, `TPIDRRO_EL0`) and logical thread id (`CONTEXTIDR_EL1`);
- FP/SIMD registers, FPSR, FPCR;
- task TTBR0/TTBR1, TCR, ACTLR/EnTSO plus exact MM/ASID generation binding;
- pending resume PC, original syscall number/x0, fault ESR/class, last guest-exit class;
- signal/restart bookkeeping that is currently host-thread TLS;
- an optional authenticated `BlockedContinuation`;
- per-thread user/system CPU totals.

The format is a typed, versioned enum owned by `carrick-hal`, not arbitrary bytes:

```rust
enum GuestCpuState {
    Aarch64V1(Arc<Aarch64TaskCpuStateV1>),
    X86_64V1(Arc<X86TaskCpuStateV1>),
}
```

The V1 structs contain every migratable field and validate variable-sized XSAVE/resume payloads at construction. Consumers match the exact architecture/version. Arbitrary same-ABI bytes are never accepted, and adding a field creates a new versioned type rather than silently changing an opaque wire format.

### `ExecutorLocalState`

Never migrates:

- host pthread and Mach thread port;
- `applevisor::Vcpu` and owner-thread destruction obligation;
- SP_EL1 and the executor's syscall-mailbox stack/binding;
- executor mailbox/scratch plus invariant EL1 kernel configuration (`VBAR_EL1`, SCTLR, MAIR, CPACR). Each invariant is validated before task load rather than silently assumed;
- current executor epoch, kick handle, `need_resched`, and timer-preemption state;
- baseline host signal mask and clean-boundary audit state.

Loading a task overlays only migratable registers and rebases mailbox/scratch registers to this executor. A cross-executor test must prove the destination retains its own SP_EL1/mailbox while restoring the task's EL0 state.

## Backend construction split

Existing `ProcessSpec`/`SiblingSpec` materializers create a task-specific engine and a new vCPU. They are replaced for scheduler-enabled HVPatch by two seams:

```rust
trait PersistentExecutorFactory: Send + Sync + 'static {
    type Executor: PersistentExecutor;
    fn create(&self, id: ExecutorId) -> Result<Self::Executor, TrapError>;
}

trait PersistentExecutor: 'static {
    type TaskBinding: Send + Sync + 'static;
    fn load(&mut self, task: &RunnableTask<Self::TaskBinding>) -> Result<(), TrapError>;
    fn run(&mut self) -> Result<ExecutorExit, TrapError>;
    fn save(&mut self, lease: ExecutionLease) -> Result<MigratableTaskState, TrapError>;
    fn invalidate_asid(&mut self, generation: AsidGeneration) -> Result<(), TrapError>;
    fn destroy(self) -> Result<(), TrapError>;
}
```

The factory retains shared VM/mailbox authority. Process-fork materialization commits stage-1 tables, COW metadata, frame inventory, root-slot and MM binding without creating a vCPU. Clone seeds a new `MigratableTaskState` without creating a vCPU. The executor binds either product to its persistent vCPU.

## Kernel execution state and atomic wakes

Each Kernel `Thread` owns one locked record:

```text
Uninitialized
Runnable(generation, queued)
Running(generation, executor, executor_epoch, wake_pending)
SwitchingOut(generation, executor, executor_epoch, wake_pending)
Blocked(generation, continuation)
Exited(generation)
Failed(generation, reason)
```

The scheduler exposes one wake operation under this record's lock:

- `Blocked -> Runnable`: clear the continuation's enrollment token, insert the exact generation in the run queue, notify an executor.
- `Runnable`: coalesce without a duplicate queue row.
- `Running`: publish pending state, set `wake_pending`, capture `(executor, executor_epoch)`, unlock, then kick only if the executor directory still binds that tuple to this thread generation.
- `SwitchingOut`: set `wake_pending`; the saving executor must settle to `Runnable`, never `Blocked`.
- `Exited/Failed`: reject the stale wake.

The executor consumes generation-tagged kicks before loading another task. Signal-before-park, signal-during-save, signal-after-binding-clear, and signal-after-destination-load are distinct red-first tests.

## Run queue and scheduling policy

- Executor count: `max(1, min(physical_cores, hvf_vcpu_ceiling - reserve))`; failure to create any configured executor aborts startup before guest publication.
- A running task stays on its executor across ordinary syscalls. There is no save/queue/load per syscall.
- A switch happens only on block, `sched_yield`, exit, explicit quiesce, `need_resched`, or a competing runnable task after quantum expiry.
- One carrier timer source observes whether the run queue has competitors. Only then does it set `need_resched` and kick running executors. A lone runnable task receives no scheduler tick exits.
- On a preemption exit the executor saves complete state, publishes it Runnable, and takes the next queued generation.
- A one-executor/two-compute-thread test proves progress and prompt signal delivery. A single-task-many-syscalls test proves zero snapshot round trips.

## Blocking continuations

Every blocking `DispatchOutcome` becomes owned `Send` state tied to `(ThreadKey, ExecutionGeneration, MmId/generation)`:

- `FutexWait`, `FutexWaitv`;
- `SharedFutexWait`, `SharedFutexWaitv`, `WaitOnSharedWord`;
- `WaitOnFds`, `WaitOnFdsSelect`, `WaitOnPollFds`;
- `BlockingHostWrite`, `BlockingRecordLock`;
- `WaitOnProcExit`, `WaitOnProcState`, `WaitOnHvpatchChild`;
- `WaitOnSignals`, `WaitOnSleep`;
- vfork-parent suspension;
- exec/exit cancellation for every variant.

Nonblocking `SharedFutexWake`/`SharedFutexRequeue`, clone/fork, sibling signal, and ordinary returns remain inline unless they request rescheduling.

A carrier wait service owns shared host readiness objects. It publishes durable Kernel state, then calls the atomic scheduler wake; it never runs guest code or infers identity from host pid/tid. Enrollment and condition recheck are one protocol, so wake-before-park cannot disappear.

During the continuation migration only, the dedicated-thread adapter repeatedly invokes the new quantum function and services its returned continuation using the old waiter. It is named `TransitionalDedicatedRunner`, HVPatch feature-gated, and a final static gate rejects any reference from the HVPatch product path.

## MM, ASID, and TLB safety

Each ASID allocation has a generation and an executor-residency bitset. Loading a task records residency after the executor performs the required TTBR write plus DSB/ISB ordering. Mapping/COW invalidations target every resident executor generation.

Before ASID reuse:

1. close new loads of the retiring generation;
2. enqueue owner-thread invalidation commands to every executor in its residency set;
3. each executor performs generation-matched TLBI plus DSB/ISB and acknowledges;
4. clear residency only after all acknowledgements;
5. return the ASID to the allocator.

Tests force process B to reuse process A's ASID on every executor and prove B cannot observe A's mapping. Migration after mmap, munmap, mprotect, exec and frame-COW also crosses every executor.

## CPU accounting and `/proc`

Executor host CPU slots are not guest identities. Remove permanent `Thread::cpu_slot` binding.

- Measure guest-run delta around each executor `run` and charge it directly to the claimed Kernel thread's `user_ns`.
- Measure syscall/scheduler service delta and charge `system_ns` to that same exact generation.
- Migration changes neither total.
- `/proc/<pid>/task/<tid>/stat` derives `R/S` from Kernel execution state, not Mach thread state. Runnable and Running are `R`; Blocked is `S`; stopped/job-control remains its existing state.

Tests compare `times`, `getrusage`, and `/proc` before/after migration and ensure two tasks sharing an executor never inherit each other's CPU.

## Executor boundary hygiene

Every production TLS/global previously relying on one-pthread-per-task is classified before executor reuse:

| State | Disposition |
| --- | --- |
| vCPU lease | executor-local; empty outside active run |
| topology/stage-1 depth | executor-local; zero at boundary |
| HVF fork snapshot | prohibited at boundary |
| signal progress/restart state | migrate or reset per task |
| active Kernel resource/context | prohibited at boundary |
| SysV `MSG_QUEUE_FD_CACHE` | carrier-global with exact task authorization, or clear/audit each switch |
| SysV MQ blocked id/wait-word caches | move into `BlockedContinuation` |
| fanotify internal-open depth | zero at boundary |
| lock-order/path-resolution depths | zero at boundary |
| host signal mask | equal executor baseline |
| waiter/kicker/Mach-port task identity | absent before next load |

The boundary audit runs before a worker accepts another task. Any failure marks the executor and carrier failed; a contaminated pthread is never reused.

## Shutdown and descendant ownership

The runtime directory owns executor threads and an in-flight exact-generation count. Closing submissions waits until no active task can publish a descendant, then closes the run queue, drains all generations, destroys each vCPU on its owner pthread, and joins executors. A child that forks a grandchild during root shutdown is covered by the same generation counter; no raw `JoinHandle` identifies a logical guest thread.

## Cross-platform boundary

The new Kernel state, snapshot envelope, and continuation types compile for every platform. Persistent executor enablement is an explicit HVPatch backend capability. KVM/bhyve/NVMM retain their current runtime until they implement that capability, but shared trait changes must pass Linux target checks and real FreeBSD/NetBSD build gates. The final HVPatch static gate forbids the dedicated runner; it does not delete other VMM implementations.

## Evidence and final acceptance

- Pure state-machine, race, fake-executor, snapshot corruption, CPU accounting, TLS hygiene, ASID-reuse, and recursive shutdown tests.
- Codesigned HVF fixtures for real owner-thread vCPU affinity, mailbox rebasing, state migration, preemption, fork/thread/signal/wait/futex/epoll/exec.
- Direct lifecycle and full conformance gates with no skip/retry/TBROK/TCONF/unsupported result accepted.
- DTrace census: executor pthread/vCPU creation bounded by executor count; blocked executor ownership zero; no drops/errors.
- At least 30 measured repetitions per arm after warmup, serial paired A/B/B/A, fixed nearest-rank p95. Carrick median and p95 must each be `<= 1.00x` Docker for fork+wait, pthread create/join, and signal ping-pong.
- Containment tests: stale MM/ASID, stale continuation after TID reuse, previous-task credentials/signal mask/altstack/MQ state, wrong-MM raw pointer, executor panic, and boundary-audit failure all fail closed.
