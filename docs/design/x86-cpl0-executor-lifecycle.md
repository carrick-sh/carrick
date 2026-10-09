# CPL0 task execution and host I/O continuations

Status: C1 design. This document does not claim a working KVM continuation.

## Contract and current failure

The guest surface is blocking `read` on a host-backed descriptor, followed by
host-backed `poll`/`ppoll`. Linux returns bytes when the source becomes ready,
reports exact readiness and timeout results, and lets another runnable task use
the CPU while one task waits. The structural rule is one wait enrollment and
one winning wake/completion per call; no executor thread or vCPU lease remains
occupied by the blocked task. The applicable existing contracts are
`kernel.scheduler.host-wait-handoff` and the scheduler continuation contracts;
the KVM binding is presently missing and needs red-first coverage.

The production CPL0 launch in `carrick-runtime/src/prepare.rs` calls
`Cpl0Carrier::run_initial_process`. That method in
`carrick-vmm-kvm/src/cpl0_boot.rs` drives two fixed physical actors and gives
a stopped `NativeFrame` to a closure. Its answer can only be Return, Refused or
Exit. A blocking `DispatchOutcome` is rejected in `prepare.rs`. Neither the
physical actor nor `ForwardVenue` has a `ThreadExecutionLease`; holding its
stopped vCPU is not a substitute. The current `run_initial_process` is a
bring-up scaffold and cannot provide task-level blocking semantics.

## Reused ARM and portable lifecycle

`vcpu_loop/executor/{pool,binding,backend,settlement}.rs` already defines the
portable `PersistentExecutorFactory`, `PersistentExecutor`,
`TaskBindingResolver` and worker pool. The scheduler claims a runnable
`ThreadExecutionLease` for a task, passes it to a backend for one quantum, and
settles exactly that lease. `ExecutorExit::BlockedContinuation` enrolls the
owned continuation through `CarrierWaitService`, then
`Scheduler::settle_blocked_continuation` stores it on the task and frees the
worker. A wake makes the task runnable; a later claim carries the continuation
back to its exact generation. The backend saves guest CPU state before
settlement. `ExecutorExit`, `Scheduler`, `CarrierWaitService`, and
`BlockedContinuation` are shared Rust policy, not HVF hardware code.

`vcpu_loop/mod.rs::prepare_hvpatch_continuation` uses
`ContinuationCapture::from_lease(context, lease, request, restart_class)`,
`BlockedContinuation::from_dispatch_outcome`, and temporary signal-mask
custody. `resume_persistent_continuation` captures a fresh task binding,
calls `resume_continuation`, then `fold_continuation_completion` to return,
redispatch or block again. These kernel operations and the executor settlement
route are the single policy to reuse. The method names currently say HVPatch;
extract their architecture-neutral core rather than copying it into KVM.

## KVM integration

1. Give the production CPL0 carrier a `PersistentExecutor` backend and a
   `TaskBindingResolver`. Its binding pairs the shared kernel's exact
   `ThreadKey`/execution generation with the in-guest `CurrentTask`, file-table
   identity, MM/root generation and saved x86 GPR, FS/GS and xstate. Admission
   must prove both views name the same live task; a physical CPU number never
   supplies task identity. Publish the initial root through the scheduler's
   normal root admission. A forked task publishes through the same resolver.
2. Move KVM vCPU ownership from the fixed `run_initial_process` actors into
   the backend factory's worker-owned vCPUs. `load`, `save`, kick, audit and
   `run_until_boundary` are x86/KVM hardware adapters. A stopped forward frame
   is authenticated against its stack, task, MM and generation before the
   runtime dispatches it. The backend retains that saved frame and guest CPU
   state in the task binding, not in a borrowed stack pointer after the worker
   returns. `FORWARD_PORT` remains the already allowed syscall boundary; its
   allowlist does not grow.
3. Route a blocked host `DispatchOutcome` through the shared continuation
   preparation and `ExecutorExit::BlockedContinuation`. The KVM backend saves
   state and returns the lease to common settlement. On readiness, timeout,
   signal or cancellation, the same resume and fold functions decide the next
   outcome. Only the final authenticated result is written into x86 `rax` and
   returned to CPL3. If a source re-blocks, enroll the replacement operation
   with remaining progress/deadline; never replay consumed bytes. A stale task,
   file slot or MM generation fails closed through the existing continuation
   error path.
4. Remove production use of `run_initial_process` once the pool drives the
   carrier. Fixture-only physical actor tests may remain as hardware tests;
   they cannot be a second production scheduler or Linux dispatch route.

The bounded C2 witness is an x86 static ELF reading from an empty, open pipe
whose writer remains live. A peer writes one byte after the reader blocks;
the reader returns exactly that byte, and a scheduler witness shows another
task obtained execution capacity before the write. A second fixture cancels
the waiter during exit/exec and checks zero retained continuation rows. Run
native Linux on the same ELF first. VM-free pool tests assert one enrollment,
one wake and release of the executor at the blocked settlement.

## Exact files and boundaries

| File | Change |
| --- | --- |
| `crates/carrick-runtime/src/vcpu_loop/{mod,executor/{backend,binding,pool,settlement}}.rs` | Extract shared continuation preparation/resume and bind the KVM executor to the existing pool and settlement. No copied wait policy. |
| `crates/carrick-vmm-kvm/src/cpl0_boot.rs`, `cpl0_actors.rs` | Hand worker-owned KVM vCPUs and exact stopped frames to the adapter; retain fixture hardware actors only. |
| `crates/carrick-runtime/src/prepare.rs` | Replace production initial actor dispatch with scheduler root admission/pool startup; classify the already permitted x86 `epoll_pwait` forward where required. |
| `crates/carrick-el1-abi/src/lib.rs`, `crates/carrick-x86-cpl0/src/{entry,native_process}.rs` | Carry exact task/MM/generation and saved-frame binding across the CPL0 boundary; no host descriptor inferred from an inode or bare guest fd. |
| `crates/carrick-cli/tests/x86_kvm_run.rs` and static fixtures | Native/KVM line-exact read and poll witnesses with a retained empty stdin pipe; keep waits bounded. |

C3 builds host-backed poll readiness on the same continuation route. Its
in-zone entries still resolve through the shared file table and IPC owner;
host-bound entries use the typed `HostBoundFd` on `DelegatedOpenFile` and the
existing host epoll wait service. Recheck each entry on completion, writing
independent `revents` for duplicates and unconditional ERR/HUP/NVAL. The
empty-stdin, full-pipe stdout, one-wake and timeout-zero witnesses are red
before that implementation. KVM gates prove this lane; ARM/HVF signed gates
remain a separate artifact-bound acceptance step on macOS.

## C2a: exact driver replacement map

The old physical actors are *not* scheduler participants. In
`cpl0_actors.rs::drive`, each scoped worker owns one borrowed `KvmVcpu`, while
the coordinator owns the stopped CPU and calls `service`. `ActorDecision::Park`
retains that stopped CPU; it never creates a `ThreadExecutionLease` or a task
run-queue row. `run_initial_process` fixes that arrangement to two CPUs. The
production swap replaces this call, rather than adding a fourth decision to
its enum. Keep it for physical fixture tests only.

| Old fixed-actor role | Shared-pool role | KVM adapter |
| --- | --- | --- |
| `cpus[0]` initial runner | Bound executor for guest CPU 0, claiming root's task lease | Move the vCPU into a worker-owned KVM executor; load the root's typed saved x86 state before entry. |
| `cpus[1]` admitted peer | Bound executor for guest CPU 1; host run-queue idle when no task is assigned | Keep the peer's KVM vCPU and private guest-kernel stack, but no synthetic Linux task identity. |
| `run_member` + `VcpuExit` | `PersistentExecutor::run_until_boundary` | Preserve KVM run/kick and physical service ports; translate an authenticated `FORWARD_PORT` to one `ExecutorExit`. |
| `ForwardVenue` stopped-frame borrow | Worker-owned stopped CPU plus task binding | Copy the checked `NativeFrame` into owned task state; never retain its RAM pointer after yielding. |
| `ActorDecision::Resume/Park/Finish` | `ExecutorExit` plus common `save`/settlement | A saved runnable lease requeues; a blocked continuation enrolls once; exit settles terminal. |
| `Cpl0HostCustody` physical grants | VM-wide physical inventory service | Share custody with workers under exact stopped-CPU grants; it does not choose runnable tasks. |

The scheduler is constructed with **two** guest CPUs and an executor ceiling
of two for this carrier. `ExecutorPoolConfig` then starts two bound workers and
zero spares. It must reject a policy with more CPUs; it must not silently
reduce the guest's advertised CPU topology. A blocked task releases its
claimed lease and worker so the other runnable task can be claimed. The
physical peer may be idle, but it cannot stand in for a task lease.

Root publication follows the ARM sequence in
`vcpu_loop/binding.rs::prepare_initial_runner_handoff` (the function
that calls `publish_initial_task_state_gated`): capture the exact root
`KernelContext`, save the x86 runner state, construct
`MigratableTaskState { cpu: GuestCpuState::X86_64V1, mm, asid_generation }`,
publish the gated initial state, take its opened start gate, then prepare and
activate one submission through `TaskBindingResolver` and `Scheduler`. The
ordering is required: a wake after state publication but before submission
must remain unclaimable. `TaskBindingResolver::prepare_submission` with its
`Root` shape calls `Scheduler::admit_process_root` for root authority; no KVM
queue or thread registry is added. Fork and clone use the same
gated publication and submission sequence as
`vcpu_loop/thread_adoption.rs`, with their own exact `ThreadKey`, MM and
generation. The two-live-MM witness checks that the second process has a
distinct saved root and that both can be scheduled before C2c changes waits.

Already portable and reused verbatim: `Scheduler` claim/settlement, the
`ExecutorPool` worker loop, `PersistentExecutorFactory`, `PersistentExecutor`,
`TaskBindingResolver`, `BlockedContinuation`, `CarrierWaitService`, and the
`X86TaskCpuStateV1`/`GuestCpuState::X86_64V1` Kernel state format. Existing
KVM/x86 adapters are `carrick-vmm-kvm/src/carrier_cpu.rs` (`KvmCarrierCpu`
checked load/save/detach) and `carrick-x86/src/arch_context.rs`
(`X86ArchContext` snapshot conversion and exact `GuestArchBinding`). Extend
the former with a running boundary on the production VM instead of making a
second snapshot format or copying ARM settlement. The remaining thin KVM
seams are worker-owned vCPU creation from the retained carrier, task binding
resolution to its exact `X86ArchContext`, KVM kick/guest entry, checked forward
frame capture and physical-port service, and `save_and_detach` into the
lease's migratable state. `PersistentTaskBinding` still exposes ARM-specific
retirement methods; the KVM implementation supplies only its own applicable
methods and keeps those defaults unused until lifecycle operations need them.

C2b changes the production driver at `prepare.rs` and KVM carrier ownership,
then proves the existing x86 fixture suite and the two-live-MM fork witness
without claiming new blocking behavior. C2c makes `WaitOnFds` follow the
common `ExecutorExit::BlockedContinuation` route and resumes through
`resume_persistent_continuation`; the red empty-pipe read becomes green and a
VM-free pool witness proves the worker was free before the writer ran. C3 then
uses this same route for host-backed poll readiness and deadlines. None of
these later milestones is complete at this design commit.

### M-a running-boundary refinement

KVM's `KVM_EXIT_IO` can retain a pending PIO completion until the next
`KVM_RUN`. The carrier CPU's running boundary returns a **snapshot** and a
typed exit while keeping the physical vCPU loaded. It must not reset the vCPU
to its neutral image merely because the host has seen the doorbell. C2b must
complete or transfer this pending physical step using the existing KVM reclaim
semantics in `kvm_x86_engine.rs` before loading a different task on that vCPU;
the typed task snapshot alone is not a license to reassign it. This refines
the earlier table's `save` step: settlement follows an authenticated stopped
snapshot and a safe physical detach, not the IO-exit observation alone.

### M-b physical run ownership refinement

The retained shootdown table is in the carrier RAM aperture, while KVM's VM
handle and physical run flag have separate owners. A worker's production run
context therefore retains `GuestRam`, the exact shared `VmFd`, the two physical
run flags and its physical slot. `run_member` still performs the existing
atomic admission, pending shootdown MSI and stopped-user acknowledgement. The
context does not derive a Linux task from the slot. The bootstrap carrier now
uses this same owned context before the scheduler swap, so its behavior stays
covered by the existing KVM fixtures. Worker CPU ownership must additionally
retain the carrier's backing and frame-inventory lifetime; retaining only the
RAM pointer and VM fd would let registered backing retire underneath a vCPU.

The production bootstrap previously seeded CPL0 with fixture identities 41,
101 and file table 5. Runtime now captures the kernel graph's issued root
`TaskKey`, thread serial, execution generation and file-table ID before
initial MM admission. It projects them through the existing ISA-neutral
`ThreadIdentity` record; KVM validates the root leader and fills its own MM,
lifecycle and physical slot fields. This keeps `carrick-kernel` out of the
VMM dependency closure. The guest root and host graph therefore name the same
thread and file-table incarnation before scheduler publication. The fixed
numbers remain only for hardware fixtures that construct a carrier without a
runtime kernel graph; M-b deletes the production fixed-actor driver.

KVM already flushes a pending `KVM_EXIT_IO` under `immediate_exit` in its vCPU
recycler. The carrier CPU now records whether its last typed exit is an I/O
doorbell and consumes that completion exactly once before its saved image and
neutral reset. This is the detach step the pool will call before giving a
worker another task. A failed completion poisons that physical CPU; it cannot
yield a task-state receipt or be silently reused.
