# HVPatch Kernel M:N Executors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace HVPatch's permanent host-pthread-per-Linux-thread model with Carrick-kernel scheduling onto persistent host-thread/HVF-vCPU executors, so blocked tasks own no executor and fork/thread/signal workloads are no slower than the native-arm64 Docker oracle.

**Architecture:** A fixed executor population owns the only long-lived host pthreads and HVF vCPUs. Complete architectural state and blocking continuations live on exact-generation Kernel `Thread` objects; a generation-checked run queue moves runnable threads between executors only after state is saved. Event sources make blocked threads runnable without a host waiter per guest thread. The transitional per-thread spawn/reclaim scheduler is deleted after every wait family moves.

**Tech Stack:** Rust 2024, Carrick Kernel object graph, `carrick-hal::ThreadedEngine`, Hypervisor.framework, parking_lot synchronization, USDT/DTrace, native-arm64 Docker oracle.

**Spec:** `docs/superpowers/specs/2026-08-20-hvpatch-persistent-executor-scheduler-design.md` (implementation refinement of `docs/superpowers/specs/2026-08-13-mn-scheduler-design.md`)

## Global Constraints

- Host containment is the primary security boundary; intra-guest isolation is a co-equal Linux-conformance obligation.
- A live HVF vCPU never changes host pthread. Executors own vCPUs; guest threads carry saved state.
- Process/thread specs materialize MM/task bindings without a vCPU; one VM-bearing executor factory creates persistent owner-thread vCPUs.
- Migratable task state excludes executor-local SP_EL1/mailbox and EL1 kernel configuration; task load explicitly rebases those fields.
- Guest state authority includes GPRs, PC, PSTATE/RFLAGS, user/kernel stacks, observable sysregs, TLS, FP/SIMD, and backend resume metadata.
- A blocked Linux thread owns no executor, vCPU lease, host waiter pthread, kqueue, or private wake pipe.
- Wake publication is durable and generation-checked before run-queue insertion; no edge is the authority.
- Do not retain a shipped fallback that permanently welds guest threads to host pthreads.
- Process/thread identity, signal masks, altstacks, pending signals, CPU accounting, and wait state remain Kernel-object properties.
- HVPatch execution is fail-closed on snapshot ABI mismatch, stale generation, executor panic, or owner-thread vCPU cleanup failure.
- Snapshots are typed/versioned `carrick-hal` variants; arbitrary same-ABI bytes cannot enter Kernel state.
- A running task stays resident across ordinary syscalls. Save/switch occurs only on block, yield, exit, quiesce, or generation-tagged preemption.
- Signals atomically choose `Blocked -> Runnable` or `Running -> pending + exact-executor kick`, including the switching-out race.
- ASID reuse waits for owner-thread invalidation acknowledgements from every executor in the retired generation's residency set.
- Per-thread user/system CPU and `/proc` state come from Kernel execution records, never persistent executor slots or Mach thread state.
- Every production TLS is classified as executor-local, task-migrated, boundary-reset, or prohibited before executor reuse.
- Run Carrick and Docker serially. Build runnable macOS artifacts only with `just build` so HVF entitlement and `__dof_carrick` remain present.
- Every behavior change is red-first and every task gets a scoped review before the next task.

## Baseline and Final Gates

Baseline at source `b7f7662e01c39e83cac17d6d8ef29715d5467ddb`:

- Carrick binary SHA-256: `bc6eaab3296da296edf1d0f5659d0714a88ccc3b4d63fce7f7df9cb0e0f0ba2f`.
- Reducer SHA-256: `4c85b519295c69509893146deb83b2266dfe8948a621e8a322999630c447998a`.
- Oracle image: `alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce` on Docker `linux/arm64`.
- Warm 10,000-cycle fork+wait: Carrick median `4.54 s`; Docker median `0.66 s`; ratio `6.88x`.
- DTrace per 1,000 forks: `80,733` host syscalls, `1,003` host pthread creates, `1,001` host pthread terminations, `1,000` frame-COW copies, `4,018` stage-2 maps and unmaps.

Final acceptance requires all of the following on one exact signed artifact:

- Fork+wait, pthread create/join, and signal ping-pong median and p95 are each no slower than the serial native-arm64 Docker oracle.
- DTrace shows executor pthread/vCPU creation bounded by executor count, not guest fork/thread count.
- A blocked-thread census proves zero executor ownership for every blocked task.
- A single runnable task performs zero scheduler snapshot round-trips across ordinary syscalls; two CPU-bound tasks make progress on one executor.
- Cross-executor mailbox rebasing and stale-ASID containment fixtures pass on a real codesigned HVF artifact.
- Direct lifecycle probes, full conformance, `just ci`, containment tests, and scoped cleanup are green with no skips, retries, unsupported rows, or stale artifact reuse.

---

### Task 1: Kernel-Owned Architectural State Machine

**Files:**
- Modify: `crates/carrick-hal/src/threaded.rs`
- Modify: `crates/carrick-runtime/src/kernel/objects.rs`
- Test: `crates/carrick-runtime/src/kernel/tests.rs`

**Interfaces:**
- Produces: versioned `GuestCpuState`, `ExecutionGeneration`, `ExecutorId`, `ThreadExecutionState`, and generation-checked `Thread` transition methods.
- Consumes: `carrick_abi::LinuxGuestAbi`, exact `ThreadKey` generations.

- [ ] **Step 1: Write failing state-transition tests**

Add tests that independently assert these literal transitions:

```rust
let state = GuestCpuState::from_aarch64_v1(aarch64_test_task_state());
let generation = thread.publish_initial_cpu_state(state).unwrap();
let lease = thread.claim_runnable(ExecutorId::synthetic_for_tests(7)).unwrap();
assert_eq!(lease.generation(), generation);
assert!(thread.claim_runnable(ExecutorId::synthetic_for_tests(8)).is_err());
thread.park_from_executor(lease, BlockedReason::ChildState).unwrap();
assert!(matches!(thread.execution_state(), ThreadExecutionState::Blocked { .. }));
```

Also assert: invalid XSAVE/resume payload sizes and wrong-version/wrong-ABI restore fail; stale executor/generation cannot yield, park, or exit; exec replacement never transfers old-image CPU state and installs only freshly seeded entry state after replacement commits.

- [ ] **Step 2: Run the focused RED tests**

Run: `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib kernel::tests::thread_execution_`

Expected: compile failure because the execution-state API does not exist.

- [ ] **Step 3: Add the strict snapshot envelope**

In `carrick-hal/src/threaded.rs` add:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestCpuState {
    Aarch64V1(std::sync::Arc<Aarch64TaskCpuStateV1>),
    X86_64V1(std::sync::Arc<X86TaskCpuStateV1>),
}

impl GuestCpuState {
    pub fn from_aarch64_v1(state: Aarch64TaskCpuStateV1) -> Self;
    pub fn from_x86_64_v1(state: X86TaskCpuStateV1) -> Result<Self, TrapError>;
    pub const fn guest_abi(&self) -> carrick_abi::LinuxGuestAbi;
    pub const fn version(&self) -> u16;
}
```

Move the architecture-neutral task snapshot structs into `carrick-hal`. The x86 constructor validates exact XSAVE length; AArch64 has only fixed-size typed fields. No raw byte constructor exists.

- [ ] **Step 4: Add the exact-generation execution state to `Thread`**

Add private storage and typed public observations:

```rust
execution: Mutex<ThreadExecutionState>,

pub enum ThreadExecutionState {
    Uninitialized,
    Runnable { generation: ExecutionGeneration },
    Running { generation: ExecutionGeneration, executor: ExecutorId, executor_epoch: u64, wake_pending: bool },
    SwitchingOut { generation: ExecutionGeneration, executor: ExecutorId, executor_epoch: u64, wake_pending: bool },
    Blocked { generation: ExecutionGeneration, reason: BlockedReason },
    Exited { generation: ExecutionGeneration },
    Failed { generation: ExecutionGeneration, reason: ExecutionFailure },
}
```

Keep the snapshot private inside the locked record. `claim_runnable` returns a non-cloneable `ThreadExecutionLease` carrying the state and exact owner. Settling methods consume the lease. A dropped unsettled lease marks the thread failed and wakes shutdown rather than silently making it runnable.

- [ ] **Step 5: Initialize every thread constructor and preserve exec transfer**

Update `prepare_thread`, `prepare_clone_thread`, `prepare_fork_thread`, and `prepare_exec_thread`. Fork/clone start `Uninitialized`; exec transfers runner ownership/accounting only while its `RunnerGate` is stopped, invalidates the predecessor generation, and publishes newly seeded entry CPU state only after all fallible replacement work commits.

- [ ] **Step 6: Run focused and kernel gates**

Run:

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib kernel::tests::thread_execution_
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib kernel::
cargo clippy -p carrick-runtime --lib -- -D warnings -A clippy::disallowed_methods
```

Expected: all pass; no empty or stale state can enter `Running`.

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-hal/src/threaded.rs crates/carrick-runtime/src/kernel/objects.rs crates/carrick-runtime/src/kernel/tests.rs
git commit -m "kernel: own guest thread execution state"
```

---

### Task 2: Complete Snapshot Authority at the Engine Boundary

**Files:**
- Modify: `crates/carrick-hal/src/threaded.rs`
- Modify: `crates/carrick-aarch64/src/engine.rs`
- Modify: `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs`
- Modify: `crates/carrick-vmm-kvm/src/kvm_aarch64_engine.rs`
- Modify: `crates/carrick-x86/src/engine.rs`
- Modify: `crates/carrick-vmm-bhyve/src/bhyve_x86_engine.rs`
- Modify: `crates/carrick-vmm-nvmm/src/nvmm_x86_engine.rs`
- Modify: `crates/carrick-runtime/src/kernel/objects.rs`
- Modify: `crates/carrick-runtime/src/dispatch/resources.rs`
- Test: corresponding engine unit-test modules.

**Interfaces:**
- Consumes: `GuestCpuState` from Task 1.
- Produces: fallible, ABI-checked `save_guest_state` and `rebind_to_slot` contracts.

- [ ] **Step 1: Write RED round-trip and corruption tests**

For AArch64 use distinct literals in every migratable register, TTBR0/TTBR1, TCR, ACTLR/EnTSO, TLS field, SIMD lane, FPSR, FPCR, pending-resume PC, original syscall/x0, fault/exit class, and exact MM/ASID generation. Save through the real engine helper, restore, and compare every field. Assert invalid XSAVE/resume sizes and wrong-version/wrong-ABI variants return `TrapError`. A cross-executor test restores task state while proving destination SP_EL1/mailbox remains executor-local and VBAR/SCTLR/MAIR/CPACR equal their validated invariant configuration. Add distinct x86 GPR/CR3/FS/GS/full-XSAVE round-trip and corruption tests.

- [ ] **Step 2: Run focused RED tests**

Run:

```bash
cargo test -p carrick-aarch64 snapshot
cargo test -p carrick-x86 snapshot
```

Expected: both fail because `ThreadedEngine` still returns unchecked `Vec<u8>` and the typed AArch64/x86 variants do not exist.

- [ ] **Step 3: Strengthen the trait**

Make complete typed state mandatory:

```rust
pub trait ThreadedEngine {
    fn save_guest_state(&mut self) -> Result<GuestCpuState, TrapError>;
    fn rebind_to_slot(&mut self, slot: SlotId, state: &GuestCpuState)
        -> Result<(), TrapError>;
}
```

The enum has no raw-byte variant. Each backend matches the exact architecture/version before restore. Apply the same type to shared-wait variants. Remove the empty default; a backend must implement complete state or explicitly report unsupported before scheduler enablement.

Define the scheduler-owned shape:

```rust
pub struct MigratableTaskState {
    pub cpu: GuestCpuState,
    pub mm: crate::kernel::MmId,
    pub asid: crate::hvpatch::AsidGeneration,
}
```

The versioned architecture state carries pending resume PC, original syscall/x0, fault/exit class and signal-restart state. Executor-local mailbox/EL1 state is not representable in this struct; it lives only inside `PersistentExecutor`.

- [ ] **Step 4: Convert every backend without weakening its format**

Move existing AArch64/x86 snapshot fields into the versioned HAL variants. Split task-dependent engine fields (resume/syscall/fault state, process ASID/MM/COW/mapping generation) from executor-local vCPU/mailbox/kernel configuration. Preserve owner-thread vCPU teardown rules.

- [ ] **Step 5: Publish saved state into the exact Kernel `Thread`**

At every current reclaim point, save through the engine and settle the exact `ThreadExecutionLease` instead of retaining state only in a stack-local `Vec<u8>`. Restore only after claiming the matching generation. Replace permanent `Thread::cpu_slot` ownership with `user_ns` and `system_ns`; charge per-run and per-service deltas directly to the exact thread generation. Add migration tests for `times`, `getrusage`, and `/proc` CPU totals.

- [ ] **Step 6: Run matrix compile and focused tests**

Run:

```bash
cargo test -p carrick-aarch64 snapshot
cargo test -p carrick-x86 snapshot
just check-linux
cargo check -p carrick-cli --no-default-features --features platform-freebsd --target x86_64-unknown-freebsd
cargo check -p carrick-cli --no-default-features --features platform-netbsd --target x86_64-unknown-netbsd
just bsdvm-gate freebsd-arm64 stage1
just bsdvm-gate netbsd-arm64 stage1
cargo clippy -p carrick-runtime -p carrick-vmm-hvf --lib -- -D warnings -A clippy::disallowed_methods
```

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-hal crates/carrick-aarch64 crates/carrick-x86 crates/carrick-vmm-hvf crates/carrick-vmm-kvm crates/carrick-vmm-bhyve crates/carrick-vmm-nvmm crates/carrick-runtime
git commit -m "kernel: persist complete guest cpu state"
```

---

### Task 3: Generation-Checked Run Queue

**Files:**
- Create: `crates/carrick-runtime/src/kernel/scheduler.rs`
- Modify: `crates/carrick-runtime/src/kernel/mod.rs`
- Modify: `crates/carrick-runtime/src/kernel/operations.rs`
- Test: `crates/carrick-runtime/src/kernel/scheduler.rs` test module.

**Interfaces:**
- Consumes: exact `ThreadKey`, `ExecutionGeneration`, Kernel `Thread` transitions, and generation-tagged executor kicks.
- Produces: `Scheduler::wake`, `RunQueue::take`, `RunnableThread`, `ExecutorBinding`, `RunQueue::close`.

- [ ] **Step 1: Write RED concurrency tests**

Cover: one enqueue per generation; wake-before-block remains runnable; stale PID/TID reuse is rejected; two concurrent wakes coalesce; `Blocked -> Runnable` queues exactly once; `Running -> wake_pending + exact executor/epoch kick`; `SwitchingOut -> wake_pending` settles Runnable; a late kick cannot affect the next task loaded on that executor; close wakes every executor; recursive descendant submission drains; `/proc` reports Runnable/Running=`R`, Blocked=`S`; a blocked thread owns no executor.

- [ ] **Step 2: Run RED tests**

Run: `cargo test -p carrick-runtime --lib kernel::scheduler::tests`

Expected: compile failure because `RunQueue` is absent.

- [ ] **Step 3: Implement the queue around Kernel state, not wake edges**

Use one lock order: thread execution record before run-queue state. `Scheduler::wake` performs the state transition and either queues the exact generation or captures an exact `(ExecutorId, executor_epoch, ThreadKey, ExecutionGeneration)` kick token. It kicks only after unlock and only if the executor directory still matches the token. `take` removes a key and calls `claim_runnable`; stale entries are discarded under the same loop.

- [ ] **Step 4: Route existing task wakes into `make_runnable` behind a feature-local seam**

Add an explicit migration-only scheduler endpoint to `HvpatchRuntimeEndpoint`. Preserve current kicker/waiter wake only through the named `TransitionalDedicatedRunner` introduced in Task 5; Task 7 statically rejects that type from HVPatch.

- [ ] **Step 5: Add demand-driven preemption policy tests**

With one executor, two CPU-bound tasks must both advance and receive signals. With one runnable task crossing thousands of syscalls, `snapshot_count == 0` and `need_resched` remains false. A single carrier timer requests preemption only while a competing generation is runnable.

- [ ] **Step 6: Run scheduler/kernel stress tests and commit**

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib kernel::scheduler::tests
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib kernel::
git add crates/carrick-runtime/src/kernel
git commit -m "kernel: add exact-generation run queue"
```

---

### Task 4: Persistent Executor/VCPU Pool with a Fake Backend

**Files:**
- Create: `crates/carrick-runtime/src/vcpu_loop/executor.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- Modify: `crates/carrick-hal/src/threaded.rs`
- Test: `crates/carrick-runtime/src/vcpu_loop/executor.rs` test module.

**Interfaces:**
- Consumes: `RunQueue`, `RunnableThread`, `MigratableTaskState`, and a VM-bearing executor factory.
- Produces: `ExecutorPool::start`, `ExecutorPool::shutdown`, `PersistentExecutorFactory`, `PersistentExecutor`, `ExecutorBoundaryAudit`.

- [ ] **Step 1: Write RED executor tests**

Tests must prove: executor count follows `max(1, min(physical_cores, hvf_ceiling - reserve))`; one backend vCPU is created and destroyed on the same host pthread; sequential tasks reuse it; a task may migrate only after state save; a lone task crosses many syscalls without snapshotting; one executor preempts two compute tasks; shutdown drains recursive descendant submissions; panic fails closed and retires that executor; blocked tasks do not occupy workers.

- [ ] **Step 2: Run RED tests**

Run: `cargo test -p carrick-runtime --lib vcpu_loop::executor::tests`

- [ ] **Step 3: Add the minimal backend seam**

```rust
trait PersistentExecutorFactory: Send + Sync + 'static {
    type Executor: PersistentExecutor;
    fn create(&self, executor: ExecutorId) -> Result<Self::Executor, TrapError>;
}

trait PersistentExecutor: 'static {
    type TaskBinding: Send + Sync + 'static;
    fn load(&mut self, task: &RunnableTask<Self::TaskBinding>) -> Result<(), TrapError>;
    fn run_until_boundary(&mut self, need_resched: &AtomicBool) -> Result<ExecutorExit, TrapError>;
    fn save(&mut self, lease: ExecutionLease) -> Result<MigratableTaskState, TrapError>;
    fn invalidate_asid(&mut self, generation: AsidGeneration) -> Result<(), TrapError>;
    fn destroy(self) -> Result<(), TrapError>;
}
```

The factory carries shared VM/mailbox authority. The pool creates each executor inside its worker closure and destroys it before that closure returns. Task bindings are materialized independently and never create a vCPU.

- [ ] **Step 4: Add fail-closed boundary hygiene**

Before another task runs, classify and audit every production TLS: vCPU lease; topology/stage-1 depth; legacy fork snapshot; signal progress/restart; active Kernel resources/context; SysV `MSG_QUEUE_FD_CACHE`, blocked IDs and wait-word caches; fanotify internal-open depth; lock-order/path-resolution depths; waiter/kicker/Mach-port task identity; host signal mask. Make the host-fd cache safely carrier-global with exact task authorization or clear it at every switch; move logical MQ/wait state into continuations. A failed audit terminates the run; it never returns the executor to the pool.

- [ ] **Step 5: Add executor-local CPU accounting and shutdown tests**

Charge guest-run and host-service CPU deltas directly to the exact Kernel thread. Prove two tasks sharing/migrating across executors never inherit CPU totals. Track in-flight exact generations so shutdown cannot close submissions while an active child can still publish a grandchild.

- [ ] **Step 6: Run stress/loom-equivalent tests and commit**

```bash
cargo test -p carrick-runtime --lib vcpu_loop::executor::tests
cargo clippy -p carrick-runtime --lib -- -D warnings -A clippy::disallowed_methods
git add crates/carrick-runtime/src/vcpu_loop crates/carrick-hal/src/threaded.rs
git commit -m "runtime: add persistent guest executors"
```

---

### Task 5: Resumable Syscall and Blocking Continuations

**Files:**
- Create: `crates/carrick-runtime/src/vcpu_loop/continuation.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/threads.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Modify: wait-producing dispatch modules under `crates/carrick-runtime/src/dispatch/`.
- Test: runtime unit/integration wait and signal suites.

**Interfaces:**
- Consumes: `DispatchOutcome`, exact Kernel contexts, `MigratableTaskState`, `RunQueue`.
- Produces: `BlockedContinuation`, `QuantumExit::{Runnable, Blocked, Exited}`, `resume_continuation`.

- [ ] **Step 1: Write RED continuation tests for every blocking family**

Use literal tables covering `FutexWait`, `FutexWaitv`, `SharedFutexWait`, `SharedFutexWaitv`, `WaitOnSharedWord`, `WaitOnFds`, `WaitOnFdsSelect`, `WaitOnPollFds`, `BlockingHostWrite`, `BlockingRecordLock`, `WaitOnProcExit`, `WaitOnProcState`, `WaitOnHvpatchChild`, `WaitOnSignals`, `WaitOnSleep`, and vfork-parent suspension. Include exec/exit cancellation and cleanup for every variant. Each test publishes the event before enrollment, during save, after binding clear, and after destination load, proving exactly one runnable transition with the correct return/EINTR/restart result.

- [ ] **Step 2: Run RED tests**

Run: `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib vcpu_loop::continuation::tests`

- [ ] **Step 3: Represent continuations as owned, `Send` state**

Move deadlines, original syscall frame, partial write offsets, exact Kernel context generation, masks, SysV MQ blocked IDs/wait-word cache, and wait-specific tokens out of stack locals/TLS into `BlockedContinuation`. Do not store guest raw pointers without their authenticated MM generation.

- [ ] **Step 4: Make one executor quantum return at every block**

Split `run_vcpu_until_exit` into `run_task_quantum`, but retain the current task across ordinary completed syscalls. Return only on block, yield, exit, quiesce, explicit `need_resched`, or competing runnable task after quantum expiry. On block, transition `Running -> SwitchingOut`, enroll/recheck, save state, and settle to `Blocked` or `Runnable` according to `wake_pending` before returning the executor.

- [ ] **Step 5: Add a carrier wait service that owns host readiness**

Use shared kqueue/event sources and Kernel wait queues. Readiness callbacks only publish durable state and call `RunQueue::make_runnable`; they never execute guest code or infer task identity from a host pid/tid.

- [ ] **Step 6: Add the explicit transitional adapter**

Add `TransitionalDedicatedRunner`, gated only during Tasks 5-6. It repeatedly claims one thread, calls `run_task_quantum`, and services returned continuations through the old waiter so the product remains green before HVPatch executor binding. Add a marker/static test that Task 7 must remove from every HVPatch call graph.

- [ ] **Step 7: Run wait/signal integration gates**

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib vcpu_loop::continuation::tests
cargo test -p carrick-runtime --test integration
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --test wait_proc_exit_recovery
```

- [ ] **Step 8: Commit**

```bash
git add crates/carrick-runtime/src/vcpu_loop crates/carrick-runtime/src/dispatch
git commit -m "kernel: suspend blocked threads without executors"
```

---

### Task 6: Bind HVPatch to Persistent Executors

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs`
- Modify: `crates/carrick-vmm-hvf/src/trap.rs`
- Modify: `crates/carrick-aarch64/src/engine.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/executor.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/threads.rs`
- Modify: `crates/carrick-runtime/src/hvpatch/asid.rs`
- Modify: `crates/carrick-runtime/src/hvpatch/mm_resources.rs`
- Modify: `crates/carrick-runtime/src/hvpatch/stage1_mm.rs`
- Modify: `crates/carrick-runtime/src/hvpatch/mod.rs`
- Test: HVF backend tests and signed raw fixtures.

**Interfaces:**
- Consumes: `PersistentExecutor`, no-vCPU process/thread task bindings, exact MM/ASID generations.
- Produces: one owner-thread HVF vCPU per executor and task load/save without vCPU destruction.

- [ ] **Step 1: Write RED owner-affinity and state-migration tests**

Pure fake tests assert create/run/save/load/destroy owner pthread identity; switch two threads with distinct TTBR0/ASID/TLS/SIMD/task-resume states on one executor; migrate a saved thread to another executor while rebasing destination SP_EL1/mailbox; reject live-vCPU migration. Separate signed-HVF RED fixtures prove the real owner-affinity and mailbox behavior before implementation.

- [ ] **Step 2: Run RED backend tests**

Run pure tests with `RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf executor`. Build a signed pre-change binary with `just build` and run the real migration fixture; expected RED is per-task vCPU creation or missing migration capability, not entitlement failure.

- [ ] **Step 3: Split persistent executor state from task binding**

Split current materializers into: (a) a VM-bearing factory that creates one owner-thread `applevisor::Vcpu` plus executor-local mailbox/EL1 state; and (b) no-vCPU process/thread task bindings that commit root-slot, stage-1, COW, mappings, frame inventory, MM/ASID generation, and seeded migratable state. Loading restores only migratable fields, rebases executor-local fields, publishes exact kick/Mach-port identity, and performs TTBR/ASID DSB/ISB ordering. Saving clears task authority before another task loads. Stage-2 memory remains VM-wide.

- [ ] **Step 4: Add all-executor ASID/TLB residency retirement**

Track an executor bitset per ASID generation. Before reuse, close loads, issue generation-matched owner-thread TLBI commands to every resident executor, require acknowledgements after DSB/ISB, clear residency, then release the ASID. Tests force process B to reuse A's ASID on every executor and prove B cannot observe A's mapping; repeat after mmap, munmap, mprotect, exec, and frame-COW migration.

- [ ] **Step 5: Replace process and clone pthread spawning with run-queue publication**

`handle_in_process_fork` and `spawn_clone_thread` still prepare/publish Kernel objects and backend specs transactionally, but enqueue the new exact thread generation instead of calling `std::thread::Builder::spawn`. Publication rollback and parent copyout ordering remain unchanged.

- [ ] **Step 6: Run signed lifecycle fixtures and DTrace census**

Build with `just build -p carrick-cli`. Run fork, thread, waitid, signal, mq-notify, exec, futex, and epoll fixtures with unique `CARRICK_RUN_ID`s and scoped cleanup. DTrace must show `bsdthread_create` and vCPU creation bounded by executor count across 10,000 guest forks.

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-vmm-hvf crates/carrick-aarch64 crates/carrick-runtime/src/vcpu_loop crates/carrick-runtime/src/hvpatch
git commit -m "runtime: schedule hvpatch tasks on persistent vcpus"
```

---

### Task 7: Delete the Welded-Thread Scheduler

**Files:**
- Modify: `crates/carrick-hal/src/vcpu_sched.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/threads.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`
- Modify: `crates/carrick-runtime/src/threaded_loop.rs`
- Modify: `crates/carrick-runtime/src/kernel/objects.rs`
- Test: static escape/ownership tests and full runtime suites.

**Interfaces:**
- Consumes: completed run queue, continuations, and HVF executor backend.
- Produces: one HVPatch execution path with no per-guest-thread `JoinHandle` ownership.

- [ ] **Step 1: Add RED static and behavioral deletion gates**

Require one non-optional HVPatch persistent-executor capability. Fail if HVPatch reaches `TransitionalDedicatedRunner`, `run_vcpu_until_exit`, any helper that materializes a new task vCPU, `std::thread::spawn`/`Builder::spawn`, per-task `ThreadWaiter`, or blocked executor/vCPU ownership. Keep non-HVPatch platform implementations only where their architecture still requires them.

- [ ] **Step 2: Replace host-thread identity joins with logical generation drains**

Exec/exit drain exact `ThreadKey`/execution generations. Remove `Vec<JoinHandle<()>>`, `std::thread::ThreadId` self-exclusion, per-thread waiter ownership, reclaim/destroy-on-block, and the HVPatch use of `vcpu_sched`. Root shutdown uses in-flight exact-generation accounting and proves a child can publish/drain a grandchild while shutdown begins.

- [ ] **Step 3: Remove the transitional path and dead code**

Delete `should_reclaim_vcpu_for_timed_wait`, HVPatch `save_guest_state` destroy/recreate flow, per-guest thread names, the migration-only scheduler endpoint/adapter, and HVPatch-only wake-pipe machinery made unused. `/proc` run state reads Kernel execution state. No environment hatch may restore the welded model.

- [ ] **Step 4: Run full local correctness gates and commit**

```bash
just ci
just check-linux
cargo check -p carrick-cli --no-default-features --features platform-freebsd --target x86_64-unknown-freebsd
cargo check -p carrick-cli --no-default-features --features platform-netbsd --target x86_64-unknown-netbsd
just bsdvm-gate freebsd-arm64 stage1
just bsdvm-gate netbsd-arm64 stage1
git diff --check
git add crates/carrick-hal crates/carrick-runtime crates/carrick-vmm-hvf
git commit -m "runtime: remove per-guest host thread execution"
```

---

### Task 8: Conformance, Containment, and Performance Closure

**Files:**
- Modify: `docs/perf-results/` with one exact-artifact receipt.
- Modify: conformance inventory only for genuinely new probes.
- Test: signed Carrick, Docker oracle, DTrace, full gates.

**Interfaces:**
- Consumes: final signed artifact and all Task 1-7 gates.
- Produces: durable proof against the original objective.

- [ ] **Step 1: Record exact artifact identity**

Record source HEAD, binary SHA-256, CDHash, LC_UUID, hypervisor entitlement, `__dof_carrick`, fixture hashes, image digests, host/Docker architecture, and scoped cleanup receipts.

- [ ] **Step 2: Run Carrick correctness before Docker**

Run direct fork/wait/thread/signal/mq/waitid/preemption/mailbox/ASID probes, `just conformance-closure-scope`, `just conformance-probes-closure`, and workload ecosystems. Reject skips, retries, TBROK/TCONF, unsupported operations, or missing exercised relationships.

- [ ] **Step 3: Run the Docker oracle serially**

Run `just conformance full --closure --refresh-oracle`; the existing harness executes its Carrick phase first and Docker refresh phase second. Use identical native-arm64 digest-pinned images and verify both phase receipts. Never overlap Carrick and Docker; do not use `--oracle-fill` for closure.

- [ ] **Step 4: Run controlled A/B/B/A performance**

Discard declared warmups, then collect at least 30 measured repetitions per arm for fork+wait, pthread create/join, and signal ping-pong in serial paired A/B/B/A order. Use nearest-rank p95 with the ordered sample retained in the receipt. The final gate is Carrick median and p95 each `<= 1.00x` Docker for every named workload.

- [ ] **Step 5: Prove structural closure with DTrace**

Capture executor creation, vCPU creation/destruction, context switches, zero-snapshot single-task syscall fast path, compute preemptions, blocked-without-executor census, all-executor ASID invalidations, host-syscall amplification, and drops/errors. Counts must close exactly and executor lifecycle must be independent of guest task count.

- [ ] **Step 6: Run exact containment attacks**

Exercise stale MM/ASID reuse, stale continuation after TID reuse, previous-task credentials/signal mask/altstack/SysV-MQ state, wrong-MM raw pointer resumption, executor panic, and every boundary-audit failure. The contaminated executor must never run the next task.

- [ ] **Step 7: Run post-merge-equivalent gates**

Run `RUST_TEST_THREADS=1 just ci`, rebuild/re-sign, rerun the exact final probe/performance set, and prove no scoped Carrick processes remain.

- [ ] **Step 8: Commit the receipt**

```bash
git add docs/perf-results conformance-probes conformance-probes/probe-inventory.json
git commit -m "docs: close kernel mn executor evidence"
```
