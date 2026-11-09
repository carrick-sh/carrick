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
- x86/CPL0 have no host zone (`el1_zone::zone()` is `None` off HVF): their
  `pipe2` binds no lanes and never meets this outcome (seam #1059).

## Witnesses

VM-free, through the threaded `pipe2` dispatcher entry
(`carrick-kernel::dispatch::ipc_lock_contention_tests`), with a live holder
thread owning the real zone queue lock and every wait bounded:

| Witness | Shows |
| --- | --- |
| `pipe2_held_lane_lock_retains_create_then_succeeds_once` | Writable lane held: returned outcome, readable lane retained, nothing installed; release hands the record back; one pair (3, 4) exactly once |
| `pipe2_held_readable_lane_retains_unbound_create_then_succeeds_once` | Readable lane held: object retained with no lane bound |
| `pipe2_lane_release_before_enrollment_reruns_now` | Release between refusal and enrollment hands back at once |
| `pipe2_cancel_while_parked_leaks_no_object_or_binding` | Dropped continuation frees the object; the release retires the cancelled record; the slot binds again |
| `pipe2_lane_contention_does_not_exhaust_the_default_executor_pool` | Four waiters on the runtime's default single-CPU pool (three workers) with the holder's release queued on the same pool: all complete with distinct pairs |

Red on the commit before the policy switch: the first three time out with
"the create pinned its executor"; the pool witness reports "pool wedged: 0
of 4 pipe2 waiters returned their worker". The runtime arm compiles on Linux
and `cross-check-macos`; its signed execution is director-owned and
unclaimed here.
