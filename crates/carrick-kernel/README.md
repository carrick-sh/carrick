# carrick-kernel

## What this is

The Carrick kernel: the half of Carrick that answers syscalls. There is **no
guest Linux kernel** anywhere in the picture — a guest's `openat`, `clone`,
`futex` or `epoll_wait` is answered by the Rust code in this crate, against
kernel objects this crate owns. That is the object graph (`kernel/` — task and
process identity, address-space authority, file descriptions, wait sets,
continuations, the scheduler view), the syscall dispatcher and its subsystems
(`dispatch/` — fs, mem, signal, net, futex, creds, sysv, time, …), the
namespaces (`namespace/`), the in-zone network (`network/`), the file authority
(`file_authority/`), the observation/sandbox policy (`observe/`), the
kernel-view filesystems (`vfs/` — `/proc`, `/sys`, `/dev`, `/dev/pts`) over the
`carrick-vfs` filesystem model, and the single-file subsystems the guest reaches
through them (containers, seccomp, inotify/fanotify, the keyring, core dumps,
ptys, the event ring, the syslog, …).

It exists as its own crate so an execution backend **other than**
`carrick-runtime`'s HVPatch carrier can drive the same kernel: it names no
carrier module and no `carrick-vmm-*` crate, and it selects no platform (there
are no `platform-*` features here).

**Status — experimental.** Syscall coverage is partial and several syscalls are
only partially emulated (count the table with
`grep -c 'SupportLevel::BringUp' crates/carrick-abi/src/syscall.rs`; the
per-syscall fidelity map is `docs/syscalls-emulation-map.md`). Guest behaviour
is incomplete, and there has been **no adversarial security review**: a guest
under this kernel is **not a hardened trust boundary**. Do not run untrusted
code under it.

## Stability

Experimental. **No semver.** The API changes without notice — this crate exists
to split Carrick's build graph and to let an execution backend other than the
HVPatch carrier reuse the kernel, not to be a general-purpose library. If you
depend on it, pin a git rev. It is not published to crates.io (no crate in this
workspace is).

## What a backend supplies

A backend brings the execution lane and nothing else. Concretely it implements:

| Seam | Where | What it owns |
|---|---|---|
| `Stage1MmProjection` (3 methods) | `carrick_hal::stage1_mm` | The mm's live stage-1 binding (ASID + root), the identity a foreign-COW invalidation is addressed to, and the publication of each COW invalidation generation. Its companion `ForeignMmInstaller` names the backend-minted `InstallPermit` that a syscall handler holding a type-erased `dyn Stage1MmProjection` cannot mint. |
| `HostSignalBridge` (17 methods) | `carrick_hal::host_signal_bridge` | Host-side signal plumbing: publishing and dequeuing pending signals per thread and per process, self-raise and waiter wakes, host handler install/ignore/default plus the post-`execve` reset, the cross-process xsig ring, and Linux↔host signum translation. `carrick_hal::NullHostSignalBridge` is the no-host-glue implementation. |
| `GuestTimerBridge` (14 methods) | `carrick_hal::guest_timer_bridge` | `setitimer` arming/disarming and its fallback timer, the POSIX per-timer table (create, arm, remaining, overrun, delete) and expiry delivery. `carrick_hal::NullGuestTimerBridge` is the neutral one. |
| `CarrierProcess` (22 methods) | `carrick_kernel::kernel` | The backend's handle on ONE Linux process: its kernel graph, task key and binding, per-Linux-tid contexts, mm access and stage-1 projection, ptrace stops, pidfd watches, thread exit, and the child waits with job control. |
| `MmBackend` (3 methods) | `carrick_kernel::kernel` | The address-space snapshot a `RootBootstrap` boots on: the backend's mapping snapshot at a deadline, its revision, and its VMA revision. |
| `GuestMemory + CurrentMmMemory` | `carrick_guest_mem` | Reads and writes of the current mm's guest address space, plus its mapping/protection metadata. `SyscallDispatcher::dispatch` takes `&mut impl CurrentMmMemory`; `carrick_kernel::dispatch::LinearMemory` is the in-crate witness that the bound is satisfiable from a plain `Vec`. |
| A trap source producing `SyscallRequest` | yours | Whatever observes the guest's syscall entry. The carrier drives `carrick_hal::SyscallTrap::next_syscall` and converts the `RawSyscall` with `SyscallRequest::from_raw`; `SyscallRequest::new` builds one directly. |
| `CarrierBridges` at construction | `carrick_kernel::dispatch` | The two bridges above, handed to `SyscallDispatcher::with_bridges` as public fields (`host_signal`, `timers`) — the constructor a non-carrier backend uses. |

What the kernel needs from the host it takes itself, through the leaf crates
(`carrick-host`, `carrick-mem`, `carrick-thread`, `carrick-host-bsd`/`-linux`);
a backend does not supply those.

## What a backend interprets

`SyscallDispatcher::dispatch` returns one `DispatchOutcome`. Most are "write
this value back"; the rest are work only the execution lane can do. Each
variant's obligation is stated on the variant itself in
`src/dispatch/outcome.rs` as a `Backend:` line — this table is that set,
in declaration order.

| Variant | Backend must |
|---|---|
| `Returned` | Write `value` into the guest's syscall return register, service signals that became pending during the call, resume. |
| `SchedulerYield` | Complete with 0, service pending signals, then **release the guest execution lease** before yielding; yielding only the host thread retains the scarce lease. |
| `Errno` | Complete with `errno.guest_retval()` (the negative errno), service pending signals, resume. |
| `Exit` | Retire the syscall and take this Linux **process** through its terminal with `code`; nothing is written back. |
| `SignalDeath` | Retire the syscall, record the fatal signal for the crash report, and terminate the process with `128 + signum`. |
| `Fork` | Publish the prepared fork through `kernel::operations::PreparedFork::commit`, start the child at the caller's frame with return value 0 (on `child_stack` when nonzero) while the caller completes with the child's visible pid, and honour the `pidfd_out` / `*_tid_addr` / `exit_signal` fields; a `vfork` request instead suspends the caller until the child execs or exits. |
| `Execve` | Tear down the current address space, load the new image (interpreter chain included), rebuild the backend's mappings and vCPU state, and resume at the new entry — there is no return value; sibling threads drain first. |
| `SetMemoryModel` | Apply the vCPU memory-ordering model (`ACTLR_EL1.EnTSO` on Apple silicon) on the active vCPU, then complete with 0. |
| `MapHostAlias` | Claim `transaction` under a host-alias permit, map `backing` at `ipa` for `[va, va+len)` with `payload` written at offset 0, publish the frame inventory, make the range inaccessible when `prot_none`, commit the claimed install, and complete with `success_retval` — on any failure abandon the transaction and lower to a guest errno, never abort the carrier. |
| `SigReturn` | Pop the Carrick sigframe and restore the saved registers and signal mask, then resume at the restored PC **without** completing a syscall return; a bad frame is `force_sigsegv` on this process, never a carrier abort. |
| `CloneThread` | Start a new logical guest thread on this mm at `stack`/`tls` with the requested tid stores, completing the caller with the child's visible tid — or with `EAGAIN` when admission refuses. |
| `ThreadExit` | Perform the `CLONE_CHILD_CLEARTID` zero-store and futex wake, retire this thread from the kernel graph (`CarrierProcess::exit_thread`), stop executing it, and take the process terminal when it was the last live thread. |
| `SignalThread` | Publish `signum` for the target thread and force it out of the guest so it delivers promptly, completing the caller with 0 — or `-ESRCH` if the target raced to exit. |
| `FutexWait`, `FutexWaitv` | Suspend the task (see *blocking outcomes* below); the private futex wake or the timeout completes it. |
| `SharedFutexWait`, `SharedFutexWaitv` | Suspend the task; the wait rides the cross-process `PlatformFutex` seam on the SHARED page, so it pairs with `SharedFutexWake` from another carrick process. |
| `SharedFutexWake` | Wake up to `count` waiters on the shared page through the same `PlatformFutex` seam and complete with the number actually woken. |
| `SharedFutexRequeue` | Wake `wake` and requeue `requeue` waiters from `from` to `to` on that seam, completing with woken + requeued. |
| `WaitOnSharedWord` | Suspend the task until the runtime-owned shared word changes, then **re-dispatch the original syscall** — the word says only "state may have changed", never the result. |
| `WaitOnFds` | Suspend the task on the exact fd descriptions in `fds` under `sig_mask`, and complete per `completion` (fd/poll/select each have their own timeout and EINTR shape). |
| `BlockingWrite` | Suspend the task holding the staged write's exact endpoint and completed byte offset; never restart the write from offset 0. |
| `BlockingTimerFdRead` | Suspend the task holding the timerfd's exact description, so a reused numeric fd cannot retarget completion. |
| `BlockingSemop` | Suspend the task holding the exact semaphore-set generation and operation array, so `IPC_RMID`/id reuse cannot retarget completion. |
| `BlockingMqueue` | Suspend the task holding the exact queue and captured operation across fd close/reuse. |
| `BlockingFdWait` | Suspend the retained poll/select operation; its completion samples the admission snapshot and either writes final output or re-parks. |
| `BlockingRecordLock` | Suspend the retained lock request; the continuation reactor retries acquisition without occupying a guest executor. |
| `WaitOnHvpatchChild` | Suspend on the child selector (`target`, or any child) enrolled against **this** `precheck` generation, then re-dispatch the wait; there is no host child to wait on. |
| `WaitOnSignals` | Suspend until a `wait_set` signal arrives (re-dispatching so the kernel dequeues it and writes `siginfo_t`), or `timeout` elapses, or an unblocked signal outside the set interrupts with EINTR. |
| `WaitOnSleep` | Suspend for `duration` via the task's waiter — never a host `nanosleep` inside the handler — preserving the deadline across re-dispatch so the sleep is not restarted. |

**Blocking outcomes are one contract.** `kernel::continuation::is_blocking_dispatch_outcome`
names them, and a backend must not park its host worker on any of them: hand the
owned outcome to `kernel::continuation::BlockedContinuation::from_dispatch_outcome`
(with a `ContinuationCapture` from the task's execution lease), release the
execution lease, and re-enter the task when the continuation completes or asks
for a re-dispatch. Parking the worker instead is the bug the executor-pool
contract exists to prevent: a bounded pool full of parked workers cannot run the
task that would wake them.

## Bootstrap

```rust,ignore
// 1. The dispatcher, on the two bridges the backend supplies.
let mut dispatcher = SyscallDispatcher::with_bridges(CarrierBridges {
    host_signal: Arc::new(MyHostSignalBridge::new()),
    timers: Arc::new(MyGuestTimerBridge::new()),
});

// 2. The root Linux task, on the backend's own mm backend.
let bootstrap = RootBootstrap::with_mm_backend(pid, tid, mm_backend, name, host_signal)?;
let (kernel, root): (Arc<Kernel>, KernelContext) = Kernel::bootstrap_root(bootstrap)?;

// 3. One syscall.
let outcome = dispatcher.dispatch(&root, request, &mut memory, &reporter)?;
```

`KernelContext` is the exact task+revision the dispatch is attributed to; a
second Linux task comes from the kernel fork operations (`Kernel::reserve_fork`
→ `prepare_with_mm_backend` or `prepare_shared_mm` → `PreparedFork::commit` →
`PublishedFork::start_child` → the child's `KernelContext`), and is reaped with
`Kernel::wait_child`.

## The example

**Start here:** `crates/carrick-kernel-example` — a backend with no VM, no
hypervisor and no guest code, which runs scripted Linux tasks on host threads
against this crate's public surface alone. It is the shortest complete answer to
"what does a backend have to write".

The standing check that the same surface stays reachable from outside is the
out-of-crate probe `tests/integration/public_backend_surface.rs`: it builds
`CarrierBridges` field by field from `carrick-hal`'s null bridges, dispatches a
real syscall through `LinearMemory`, boots a root over a caller-supplied
`MmBackend`, forks and reaps it through the public kernel operations, and uses
`CarrierProcess` through the trait. A `pub` that regresses to `pub(crate)` fails
it at compile time.

## What is deliberately not public

The **execution lane stays in `carrick-runtime`**: the HVPatch VM carrier, the
vCPU executors and their leases, the stage-1 page tables, the threaded loop,
image preparation and the run lifecycle, the supervisors, and the bins. None of
that is reachable from here, and this crate names none of it.

Within the crate, `dispatch`, `kernel` and `observe` are the modules a backend
uses. Everything else is `pub` because dispatch is one crate, not because it is
stable: rustdoc for this crate is built with `--document-private-items` so the
module-level Big Theory Statements can link the internals they describe, and
those internals are not API.
