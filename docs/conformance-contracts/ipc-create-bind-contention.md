# IPC create: readiness-lane lock contention (#1845, `pipe2`, ARM)

`kernel.el1.ipc-two-process` owns this slice.

## What Linux requires

`pipe2(2)` either creates exactly one pipe and installs exactly one pair of
descriptors, or fails with a documented errno (`EFAULT`, `EINVAL`, `EMFILE`,
`ENFILE`). It does not sleep interruptibly and never fails with `EINTR`.
Carrick's internal locks are not Linux-visible: another party holding one is
never an errno, never fatal, and never a reason to restart the call from zero.

## What Carrick must not do

The structural invariant is **zero executor custody across an internal
contention park**. A host executor that spins on another party's lock cannot
run the party that would release it; with a bounded pool, enough spinners
wedge the carrier (AGENTS.md: "Contention is never fatal, never an errno and
never 'no plan'"; "A guest wait releases execution capacity").

## The lock this slice converts

A new pipe pops a recycled object slot and binds its two readiness lanes
(`ZoneTables::bind_object_wait`). The lane's physical queue lock can be held
by a late party of the slot's previous incarnation (a waker, an unlinker, a
timer expiry). Before this slice `HostIpc::bind_waits` waited with the
short-section `HostLockWait`, which spins and never refuses.

Now `HostIpc::begin_pipe` binds with `IpcCreateLockWait`, which refuses at
once. A refused lane returns `PipeCreation::Retained(PendingPipeCreate)`:
the unpublished object plus the lanes already bound. `pipe2` drops its
output permit and returns `DispatchOutcome::IpcLockContended` carrying the
validated arguments, pipe id and pending create.

## Existing mechanisms reused (no new queue, registry or publisher)

- Enrollment: `ReadinessLockCustody::defer` (#1945) posts the waiter's zone
  record on the lane queue's existing admission chain. If the holder already
  released, the post drains immediately, so a release before enrollment is a
  handback, never a lost wakeup.
- Runtime: the owner-memory syscall park's record receipt
  (`OperationToken::metadata_request(serial)`), `settle_into_zone` with
  `ZoneWaitPolicy::KillableOwnerMemory`, and `ResumeOwnerZone`. The new
  `OwnedSyscallResume::IpcLock` arm reruns the operation through
  `SyscallDispatcher::resume_ipc_lock_operation`. No portal cause or wire
  change (`PortalWaitCause` is unchanged).

## Interruption and cancellation

- A caught signal or a job-control stop leaves the create parked; the signal
  is delivered at the syscall boundary after completion (killable gate).
- SIGKILL, group exit, exec and carrier teardown drop the continuation.
  `PendingPipeCreate::drop` unbinds owned lanes newest first, then frees the
  object. That rollback runs only after the guest operation and execution
  lease are gone, so it keeps the short-section wait (a rollback that refused
  would leak the object). The record still on the admission chain is retired
  by the holder's release (`Claim::Transferring { cancelled: true }`).
- An owner refusal of the output copy on resume rolls the create back and
  redispatches `pipe2` afresh, exactly as a first-dispatch refusal does.

## Not in this slice

- The object **data lock** taken by `IpcRegion::lock_fresh` while popping the
  record keeps the short-section wait. Its release tickets
  (`bind_ipc_lock_release`, #1917) are not attached to any production view:
  `IpcRegion::with_lock_release` has test callers only, on the host and in
  EL1, so a ticket park would never be woken by an EL1 holder.
- `eventfd2` and `epoll_create1` still bind through `bind_waits` with the
  short-section wait.
- Pipe `read`/`write` (`dispatch/fs/pipe.rs`) and the host handback route's
  lazy lane bind (`continuation::ipc::lane_snapshots`) are the next slice.
- The in-ring constructor (`carrick-el1-linux` `dispatch.rs`, the `PIPE2`
  arm) is shared by ARM native processes and every x86 task. It still waits
  on the descriptor-table and object data locks with `NativeFdWait`, a spin,
  on both ISAs. On ARM it also binds the new pipe's lanes in EL1 with
  `ShortLockSpin`. Converting those in-ring waits is the data-lock slice.

## x86

x86 `pipe2` never meets the lock this slice converts. On the production CPL0
lane every task is a native process with the ring IPC venue published, so
`pipe2` is served in ring by the shared constructor, never by the host
dispatcher's `pipe2_create`. The x86 native dispatch supplies no scheduler
zone (`carrick-x86-cpl0` `linux_personality.rs`, `zone: None`), so that
constructor binds no readiness lane on x86. The host side has no zone on KVM
either: only the HVF pool start calls `el1_zone::enable`, so a host `pipe2`
there would bind nothing and could not return `IpcLockContended`.

Witness, real KVM through the production CPL0 pool:
`carrick-vmm-kvm::cpl0_initial_mm::native_pipe2_takes_no_readiness_lane_lock_held_by_a_previous_incarnation`.
A live host thread binds and holds both readiness-lane queue locks of the
recycled slot's previous incarnation in the production native zone for the
whole run. The guest's `pipe2` pops that slot (checked by the next host
create landing on the same index two incarnations on) and returns (3, 4)
without waiting for the holder. It goes red, with the holder giving up at
its 20 s bound, when x86 is made to bind the new pipe's lanes with a spin.
When x86 gains in-ring lane binding (with its blocking read and write,
#1756 and #1059), that binding must retain the operation as ARM's does, and
this witness becomes its Busy-once-then-success case.

## Witnesses

Dispatcher layer, VM-free, through the threaded `pipe2` dispatcher entry
(`carrick-kernel::dispatch::ipc_lock_contention_tests`), with a live holder
thread owning the real zone queue lock and every wait bounded:

| Witness | Shows |
| --- | --- |
| `pipe2_held_lane_lock_retains_create_then_succeeds_once` | Writable lane held: returned outcome, readable lane retained, nothing installed; release hands the record back; one pair (3, 4) exactly once |
| `pipe2_held_readable_lane_retains_unbound_create_then_succeeds_once` | Readable lane held: object retained with no lane bound |
| `pipe2_lane_release_before_enrollment_reruns_now` | Release between refusal and enrollment hands back at once |
| `pipe2_cancel_while_parked_leaks_no_object_or_binding` | Dropped continuation frees the object; the release retires the cancelled record; the slot binds again |

Red on the commit before the policy switch: the first three time out with
"the create pinned its executor".

Runtime layer, VM-free (`carrick-runtime::vcpu_loop::ipc_lock_park_tests`):
a real contended `pipe2` from `service_threaded_syscall` goes through
`route_outcome` → `service_outcome` → `ipc_lock_park` → `settle_into_zone`,
the real scheduler's `settle_blocked_continuation`, the zone handback, and
`resume_owner_zone` → `resume_ipc_lock_operation`:

| Witness | Shows |
| --- | --- |
| `serial_host_pipe2_lane_release_after_enrollment_resumes_through_runtime_once` | The parked create returns its executor (the same worker takes the process's other runnable thread); the release wakes it once; one pair (3, 4), one output commit, the retained object itself is published, no second wake |
| `serial_host_pipe2_lane_release_before_enrollment_hands_back_through_runtime` | A release that completed before `ipc_lock_park` enrolled hands the record back before the scheduler settles; the create completes once |
| `serial_host_pipe2_lane_park_keeps_caught_signal_pending_until_completion` | A caught SIGUSR1 leaves the create parked and pending; it is delivered after `pipe2` returns 0 |
| `serial_host_pipe2_lane_park_sigkill_reclaims_the_retained_create` | SIGKILL while parked reaches production termination; the object, its bound lane, the record and the output/descriptor reservations are reclaimed |
| `serial_host_pipe2_lane_resume_output_refusal_rolls_back_and_reruns_once` | The resumed create's `pipefd` is owner-refused: the retained create is rolled back on the resumed dispatcher (no lane left bound or held, no leak, no fatal), the thread parks on the editor, and `pipe2` reruns once after release |
| `pipe2_lane_contention_does_not_exhaust_the_default_executor_pool` | More waiters than the production `ExecutorPoolConfig` default single-CPU pool, with the holder's release queued on the same pool: all complete with distinct pairs |
| `zone::owner_copyout_policy_tests::ipc_lock_wait_is_killable_only_not_ordinary_signal_interruptible` | A real retained create maps to the killable owner gate |

SIGKILL while the holder still holds the lane takes effect at the holder's
release: the parked record sits on that lock's admission chain, and a host
claim of it is deferred until the release drains the chain. The holder is a
host thread in a short section or an EL1 vCPU, which needs no executor of
the parked thread to finish.

The runtime arm's signed (HVF) execution is director-owned and unclaimed
here.
