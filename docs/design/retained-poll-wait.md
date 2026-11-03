# Retaining native poll waits

Proposal for [#1051](https://github.com/carrick-sh/carrick/issues/1051),
part of #1035 / #898. This is a design for independent review before code,
as requested in the owner's dispatch brief. It does not enable blocking poll
or claim the issue's runtime acceptance. The publisher can post this proposal
on the issue; this worker has not posted it.

## Decision and first slice

Add a retained `PollWait` operation in the shared Linux ring service. Slice 1
admits initially unready sets only when every waiting entry resolves to the
same in-zone pipe read lane, with an inherited signal mask. Multiple entries
and duplicate descriptors are allowed if their effective interests all map to
that lane. Negative descriptors remain in the snapshot with zero revents.
Unsupported interests, zero effective lanes, host entries and replacement
masks remain refused before output or suspension. Preserve existing immediate
snapshot support. This targets the two-process pipe rendezvous blocking the
first-touch witness in #1478 / #1493 without changing the scheduler's
multi-entry wake protocol at the same time.

For the full multi-object implementation, extend the neutral scheduler's
multi-entry enrollment and wake protocol, shared with `futex_waitv`. Do not
create a private epoll object per poll call. An interest-set implementation
would introduce registration, propagation and teardown authority in addition
to the retained descriptor snapshot, and would still need a proof that every
producer publishes to it. Direct producer keys reuse the scheduler's existing
record identity and claim arbitration. Slice 1 is deliberately incomplete;
#1051 stays open until the remaining venues and acceptance evidence exist.

## Existing production paths

- `carrick-el1-linux/src/dispatch.rs`, `El1PendingFamilies::poll`, copies
  pollfds, samples readiness and calls `complete_poll_copyout`. An unready
  in-zone blocking set currently returns `FamilyCompletion::Forward` before
  output. Native crossing refusal supplies counted ENOSYS (38).
- `ipc/epoll.rs` pins a description, stores `IpcCounterDeadline`, snapshots
  before harvesting, and parks through `ipc.rs::park`. Its resume retires
  the operation and re-reads the call. Reuse its scheduler protocol, but do
  not reuse that array-reload policy for poll.
- `carrick-el1-abi/src/ipc.rs` has a fixed-size, Copy `IpcOperation`, a single
  raw pin and generation-bearing operation tokens. It cannot own a Vec by
  placing a Rust pointer in the cross-boundary record.
- `carrick-sched-core::wake_placed` refuses an EL1 waker that encounters a
  record with several entries (`WakeRefusal::MultiEntry`). Removing that
  check alone would leave other entries linked and permit unsafe reuse.
- `dispatch.rs::ipc_transfer` requires `arm_frame`. Sending poll through it
  unchanged would leave x86 behind. The existing common poll body already
  handles both poll milliseconds and ppoll timespec arguments.

## Ownership and retained data

Introduce a typed, generation-bearing poll payload handle referenced by
`IpcOpKind::PollWait`. The owning ring runtime holds fallibly allocated storage
for the payload until exactly one terminal receipt releases it. Use an
explicit shared ABI handle if a carrier must inspect it, never a guest or host
heap pointer. ABI layout/version checks and all operation-kind matches must
change together. Keep arrays off EL1/CPL0 stacks.

The payload retains:

- exact caller TaskKey, MM generation, operation generation and completion
  authority; original output address, nfds and syscall form;
- the copied fd/events array in original order, including duplicates and
  ignored entries; input revents are discarded;
- pinned open descriptions and incarnation-bearing object/lane keys for all
  admitted endpoints; deduplicated producer keys do not deduplicate output;
- one absolute deadline or infinity, plus original timeout precision and any
  raw-ppoll timeout-copyback obligation;
- signal-mask restoration custody (inherited in slice 1), enrollment/timer
  receipts, and either Waiting or a frozen Completed answer and copyout cursor.

Acquire pins through the FD table's authenticated lookup/pin protocol, with
rollback on partial admission. Resume probes the retained descriptions, not
whatever a reused numeric fd names. A pin keeps the original endpoint alive;
close/reuse of the number must not redirect the operation. Concurrent close
behavior is not completely specified by the Linux manual: record differential
results separately from this explicit Carrick lifetime invariant.

Retain admission progress through an owner or table Busy: release execution
capacity, enroll on that owner's release and probe once. Busy is not ENOSYS,
EAGAIN, a fatal error or grounds to drop the snapshot. An unsupported venue
can be refused only before effects, with every provisional pin released.
Allocation exhaustion is a fallible error, not an abort.

## State and wake protocol

`Admitting -> Waiting -> Completed -> Copying -> Retired` is one owned
operation; owner-memory waits suspend the current state, and cancellation
claims terminal custody rather than starting another operation.

1. Validate the call in existing ABI order and capture inputs once. Compute
   the deadline once from the entry clock, rounding up only to timer
   resolution. Do not turn ppoll nanoseconds into a restarted i32-ms timeout.
2. Pin and classify the whole set before output. For the single lane, observe
   its generation before the readiness probe, using the producer lock/epoch
   protocol. After an empty probe, enroll against that observation. A change
   rejects sleeping and causes a recheck of retained endpoints. Successful
   enrollment precedes the final signal probe. Producer publication must
   update readiness before notifying the same incarnation-bearing key.
3. Commit the retained token, context and timer with the scheduler handoff;
   release the execution lease. No pool worker, vCPU lease or host selector
   remains blocked waiting for this pipe's writer. A runnable second process
   must be able to acquire execution capacity even at pool exhaustion.
4. A wake, timer or signal claims the existing park sequence exactly once.
   A readiness wake only schedules a rescan; it does not promise readiness.
   Repark with the same snapshot, pins and original deadline when readiness
   was consumed by a competing reader. On timeout, perform a final readiness
   scan before authorizing zero. Test both ordered wake/deadline outcomes.
5. When a ready set is selected, freeze its complete revents and return count.
   Detach producer subscriptions and the timer before copyout. An owner-memory
   wait retains these exact bytes even if another process drains the pipe,
   closes the fd, or edits the guest array. Never resample a completed answer.
6. Deliver only output fields required by the ABI, preserving input fd/events
   fields; do not blindly overwrite them from an old whole-record snapshot.
   Prepare owner memory through the existing copyout authority and retain
   any admitted prefix/cursor. Final EFAULT and partial-copy behavior need
   oracle coverage. Completion releases all pins and storage once.

For several producer keys, reserve one scheduler record and N deduplicated
entries. Enrollment must validate every pre-probe epoch before publishing
Parked, with bounded rollback if any epoch changed. Define a global bucket
lock order; never nest arbitrary producer locks. The first claimant owns the
record; after releasing its bucket lock, it unlinks all other entries before
making the record runnable or reusable. Timer, signal and cancellation paths
owe the same cleanup. Placement, sequence authentication and all-or-nothing
EL1 wake semantics must survive races between two producers. Keep MultiEntry
refusal until these invariants have production-entry witnesses.

## Signals, handback and both ISAs

Slice 1 accepts only an inherited mask. A signal ending the wait returns
EINTR (4), with no automatic SA_RESTART replay. Stop/continue preserves the
retained operation and deadline; exec/exit cancellation detaches every waiter,
cancels timer ownership and releases resources without copying into a retired
MM. A late notification must not complete a recycled task or operation.

The later temporary-mask slice extends `kernel.signal.temporary-wait-mask`:
copy and validate the replacement mask once, remove unblockable signals, and
install it atomically with pending-signal observation/enrollment under signal
authority. Transfer a restoration token, never an executor-local guard. Restore
exactly once on success, timeout, EINTR, EFAULT, cancellation and failed park;
for EINTR retain the temporary mask until signal-frame delivery has selected
its handler and arrange restoration on return according to the signal API.
Readiness/signal precedence must be checked against Linux. Memory-copy waits
must not silently restore early or reinstall from guest memory.

Host handback gets an explicit PollWait branch consuming this token and
retained payload. It may resume admission, readiness or output; it must never
re-run the original syscall or reconstruct state from registers. Timer-slot
contention retains the operation and uses existing timer admission/release
notification, or a neutral retained deadline handoff; never restart a timeout
or move a guest producer wait into host poll.

Put normalization and the PollWait state machine in `carrick-el1-linux`, with
neutral producer enrollment in `carrick-sched-core` and typed ABI state in
`carrick-el1-abi`. Introduce or reuse a common task/context parking interface
rather than passing through ARM-only `ipc_transfer`. ARM and x86 adapters
supply only frame decoding, syscall reentry/completion, clock conversion and
interrupt mechanics. Both native runtimes and carrier handback consumers
must handle the operation kind in the same slice. Slice 1 cannot ship as ARM
only; dependency work in #1040 must be integrated rather than copied.

## Host-bound descriptors and refusal boundary

Preserve #894's host-only readiness crossing where supported. A host-only
selector must never wait on behalf of a set containing an unready Carrick
producer. Slice 1 refuses that blocking mixed set before invoking a blocking
host query, including when host readiness infrastructure is available. Test
root and native child venues, since an unrouted family result must become
counted ENOSYS rather than a root-only syscall fallback. Immediate mixed
snapshots may use zero-time host sampling only in already supported venues.

Full mixed support needs a retained host-readiness subscription plus native
producer subscriptions under the same completion owner and deadline. Neither
side can finish and free the payload while the other can still notify it.
That bridge is a separate reviewed slice; until then mixed blocking and
unsupported temporary masks remain counted ENOSYS, with no output or Forward
syscall execution. Existing host-only supported venues need regression tests.

## Contracts and evidence required before implementation can close acceptance

Apply `kernel.copyout.owner-refusal`, `kernel.signal.temporary-wait-mask` and
the scheduler continuation contracts. `kernel.el1.epoll-zone` is a template,
not evidence for poll. Before implementation, register a dedicated proposed
`kernel.poll.retained-wait` surface contract, binding the production common
poll entry and runtime handoff. This documentation-only pass registers no
fictional green binding and changes no executable contract budget.

Linux authority is [poll/ppoll(2)](https://man7.org/linux/man-pages/man2/poll.2.html)
for readiness and interruption, with [select(2)](https://man7.org/linux/man-pages/man2/select.2.html)
for concurrent-close caveats. Use bounded native oracle fixtures to settle
raw ppoll timeout mutation, simultaneous signal/readiness, close/reuse and
partial-copy details. No GPL implementation sources are needed.

The implementation's red-first matrix must drive `El1PendingFamilies::poll`
and the real runtime park/resume path, with two live process graph members:

- producer writes before observation, between probe and enrollment, and after
  parking; reader consumes readiness before rescan; peer closes to publish HUP;
- duplicate descriptors and negative entries, events zero, exact revents/count,
  guest fd/events mutation while parked, close/dup2 reuse and endpoint pin counts;
- finite/infinite waits, spurious wakes without deadline extension, both orders
  of wake/deadline and signal/deadline, plus timer-admission Busy once then success;
- ready answer followed by real sibling MM-editor contention, drained readiness
  during that wait, exact resumed output and no duplicate completion;
- signal, stop/continue, exec/exit, cancellation during admission/park/copyout,
  late notification after reuse, and pool exhaustion with a runnable producer;
- every excluded venue returning counted ENOSYS before output, especially a
  mixed set with an available host crossing; both real ISA frame adapters.

Use deterministic schedules and aligned fixture storage. At scales 1/8/64
entries on the same lane in slice 1, require O(n) input/storage/output work,
one live producer enrollment and at most one live timer, zero host readiness
calls for the native set and zero redispatch while no notification occurs.
Measure producer visits, pin acquire/release balance and copy bytes per
operation, not global deltas. Later distinct-lane scales require O(n)
enrollment/unlink and O(n) rescan per genuine wake, with exactly one winning
completion; no periodic scans or unrelated-task wakeups.

Capture red on the pre-change production entry, then green in focused regular
and serial_host suites. Add signed embed and conformance-next bindings for
both live processes, including `el1_memory_first_touch_stays_in_guest` with
`child_ok=true`, and execute the equivalent x86 KVM witness. Finish the signed
probe/smoke/full sequence and serialized Docker differential on their capable
hosts. Paired uninstrumented same-workload p50 must meet the existing <=2x
policy; structural and semantic passes cannot excuse a failing ratio.

Independent design review is required before slice 1 code. Multi-entry,
temporary masks and mixed-host subscriptions each need their own reviewed
production witnesses; completion of slice 1 alone does not close #1051.
