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
| `crates/carrick-vmm-kvm/src/cpl0_boot.rs`, `carrier_cpu.rs` | Hand worker-owned KVM vCPUs and exact stopped frames to the adapter; use the pool for production fixtures too. |
| `crates/carrick-runtime/src/prepare.rs` | Replace production initial actor dispatch with scheduler root admission/pool startup; leave host readiness to the dedicated typed crossing. |
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

The retired physical actors were *not* scheduler participants. Their scoped
workers owned borrowed `KvmVcpu`s while a coordinator serviced stopped CPUs.
`ActorDecision::Park` retained a stopped CPU without a `ThreadExecutionLease`
or task run-queue row. The shared pool now runs the production fixtures as
well; `run_initial_process`, `run_two_actors`, and `cpl0_actors` are deleted.
Fault-record collection and a deterministic fixture-only mid-forward hook
remain on the worker-owned stopped CPU. A failed running boundary sends a
terminal error before the launcher waits for pool shutdown.

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

The initial boot request doorbell precedes the guest's installation of its
published user address-space root. Capturing the root task there yields a
bootstrap CR3 and cannot satisfy `X86ArchContext`'s binding check. A second
physical doorbell after `install_context`, before the first `iretq`, is the
stopped handoff point. The carrier verifies its request pointer and CR3
against the published root, then completes the pending PIO step before
transferring the vCPU to a worker. This doorbell is a KVM bootstrap protocol,
not a forwarded Linux syscall or a new host crossing.

The retained custody contains a `RetainedMetadataPtr` view of metadata inside
its owned, registered `GuestRam`. The worker handoff needs to move custody
across host threads. Only this non-cloneable pointer owner has an audited
`Send` implementation; the broad custody becomes `Send` automatically. The
RAM stays retained until custody drops; atomic metadata reads and stopped
host service retain their existing access discipline. Compile-time checks
reject `Clone` and `Sync` on both pointer and custody. A hardware
witness transfers the complete parts to a new host thread, loads the issued
root image there, saves and detaches it, then checks both physical CPUs are
idle. The production pool still has to split worker CPU ownership from this
coordinator custody before scheduler submission.

The initial guest MM key must be the kernel graph's issued `MmId`: the
shared scheduler rejects a `MigratableTaskState` whose saved CPU MM generation
differs from its `MmId`. The physical fixtures continue to use their local
initial key, while production binds `InitialTaskBinding.mm` from the root
`KernelContext` before the guest stages its MM. The host inventory, boot
request, zone record and saved x86 image then carry that one identity.

The stopped handoff now offers a worker CPU factory. Each physical vCPU has
one claim, checked against its carrier run-context slot; claiming the same
slot twice fails. A claimed CPU retains an `Arc` to the shared physical
custody so backing and inventory cannot retire while a worker still owns
the vCPU. This factory is the KVM-specific input to the portable executor
pool's `PersistentExecutorFactory::create`; the latter still needs its task
binding and syscall service adapter before production uses it.

The executor submission directory now has an ISA-neutral binding parameter.
Its exact-key record, dormant authority, scheduler rollover observer and
activation transaction are shared unchanged with ARM; the existing
`HvpatchTaskBindingDirectory` and `PreparedHvpatchSubmission` names remain
aliases for ARM callers. A runtime witness publishes and resolves a
`FakeBinding` through this same transaction to prove the directory no longer
requires `HvpatchTaskBinding`. The ARM-specific cancellation and exec
replacement policy remains on the ARM resolver implementation. The KVM
resolver can use the shared record and authority operations without adding
another queue or thread registry.

The KVM resolver now uses that directory directly. Its binding accepts only
an x86 V1 saved CPU whose MM and ASID match the kernel `KernelContext`, whose
task serial is the issued `TaskKey`, and whose execution generation matches
the scheduler submission. The root witness reserves an unclaimable queue
row, prepares the directory authority, opens the start gate, activates the
exact row, then resolves the binding. The generic submission shape and
activation proof carry ISA-neutral names; ARM retains aliases and its
existing policy. This establishes root publication semantics, but the KVM
executor still needs to load and run the physical CPU from this row.

### Baseline and current fixture status

The `origin/main` KVM suite already fails three memory and TLS fixtures:
`mounted_static_x86_adjacent_anonymous_memory_keeps_existing_leaf`,
`mounted_static_x86_arch_prctl_preserves_user_tls_bases`, and
`mounted_static_x86_elf_matches_native_anonymous_memory`. Their execution
report has an extra root exit; this lane does not change those contracts.
`mounted_static_x86_guest_owned_calls_refuse_without_host_effects` also fails
on main after the guest exits 7: its report counts one host forward while
the fixture expected two. On this branch the same guest initially exited 99
because its temporary `poll(fd=3)` ENOSYS expectation predates the accepted
in-zone poll implementation. Native Linux on a closed fd returns one ready
entry with `POLLNVAL` (32), so the fixture now requires that exact result.
The guest still sees ENOSYS for unfinished memory and signal effects, but
these are no longer classified as host-forward refusals in this branch. The
new empty-stdin
read and poll witnesses are red until the continuation and readiness work.

### Stopped forward-frame custody

The CPL0 forward doorbell points at a `NativeFrame` on that physical CPU's
private supervisor stack. A blocked guest must release its executor, so a
later task can reuse the stack before the first task resumes. The KVM adapter
copies the checked frame into an owned `ProductionForwardFrame` token,
recording the exact task generation, MM context, physical slot and stack
address. That frame alone is insufficient: the saved CPL0 RSP can still
point into Rust call frames and xstate below it. On every task save, including
a kick, the KVM adapter copies the live private stack span from stopped RSP
to stack top into task-owned `KernelStackSnapshot`. On load it restores that
span before any guest instruction runs; completion then restores the checked
frame and writes the final return register. The snapshot is authenticated to
its physical slot and stack extent. Until the supervisor stack and GS/CPU
metadata are rebased for
cross-slot migration, a frame-bearing task remains eligible only on the
original guest CPU. This is scheduling affinity, not a vCPU handle owned by
the task: the worker and vCPU still return to the pool while the task waits.
The root is pinned to guest CPU 0 at publication. A future second runnable
task needs the same affinity rule until dedicated per-task mapped stacks
permit cross-slot execution.

### Production pool handoff

The KVM initial-process path now submits its root through the shared binding
directory and scheduler, then starts the shared executor pool with two physical
KVM CPUs. Each worker leases the exact submitted task, restores its stopped
CPU state, and returns that state to the task after a typed carrier exit. The
root remains eligible for guest CPU 0 while its CPL0 stack and per-CPU metadata
are slot-specific; this does not give it permanent ownership of the vCPU.
The peer enters the guest idle path with the pool's publish/recheck/kick
handshake, so queue publication and shutdown can interrupt `KVM_RUN` without
a host polling thread. The production restore reapplies the CPL0 descriptor
tables and syscall MSRs after the portable register image, which otherwise
replaces them with fixture bootstrap values. A terminal root outcome closes
the scheduler and joins the pool. Forwarded blocking outcomes use the
owned-continuation route described below.

### Blocking forwarded calls

A blocking forwarded dispatch now captures a `ContinuationCapture` from the
worker's live `ThreadExecutionLease` and returns the shared pool's
`BlockedContinuation` exit. The task binding retains its owned forward frame
and original syscall request while the pool saves the stopped CPU image,
enrolls the wait, settles the task blocked, and releases execution capacity.
When the existing wait service marks it ready, a worker leases the task again,
reloads its image, and invokes `resume_continuation`. It folds a completed
result through the original stopped guest-memory venue, or redispatches the
same request if the continuation asks for redispatch. A repeated blocking
outcome re-enrolls with the same retained frame; a completed outcome consumes
the frame exactly once and restores the guest return register. The empty-pipe
stdin read witness is green through this path, and the shared pool's
single-worker continuation test confirms that a blocked task releases the
worker for another runnable task.

### Dedicated host-readiness crossing

The first poll implementation incorrectly reused `epoll_pwait` (281) as a
transport marker and forwarded the whole poll into the host dispatcher. That
made one crossing number carry two protocols and moved the poll owner out of
the ring. The corrected boundary uses one named internal crossing, distinct
from every Linux syscall ordinal. The guest poll owner now resolves its fd
map, negative entries, absent entries and duplicates, and sends only typed
`HostReadinessEntry` bindings and interests to the carrier. The KVM adapter
reads that bounded batch from the stopped task's supervisor allocation,
samples host readiness once, and parks the task through the existing owned
continuation when no handle is ready. An absolute deadline survives a
spurious wake and the ready set returns to the same guest poll call, which
writes final `revents` and count. The physical CPU lease is released while
the task waits. Neither a Linux `poll` forward nor an `epoll_pwait` alias
remains.

### Next milestone: in-zone IPC poll

KVM currently calls shared dispatch with `ipc=None` and maps no IPC region or
table map. The KVM host-bound poll milestone is reviewable on that boundary:
there is no in-zone KVM descriptor for it to misclassify. The next milestone
must map an ISA-neutral `IpcVenue` on KVM, publish the task's IPC table binding,
and project pipe, eventfd and epoll readiness from their actual descriptions
in `resolve_poll`. A mixed host and in-zone set needs one ready-set assembly
and one absolute deadline, with a multi-object wait path that subscribes to
each producer before releasing the physical CPU lease. It must reconcile
producer publication racing enrollment, remove subscriptions on completion or
cancellation, and resume through the shared owned-continuation route.

The ARM `PollContinuation` also needs a separate repair in that milestone:
register its IPC producer wake and shared timer before `clear_current`, then
complete from re-sampled `revents` exactly once. Merely clearing the slot
without those registrations returns a false zero and can lose the wake.
