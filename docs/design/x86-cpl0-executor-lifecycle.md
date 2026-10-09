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
