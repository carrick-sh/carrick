# Retaining native poll waits

Proposal for [#1051](https://github.com/carrick-sh/carrick/issues/1051),
part of #1035 / #898. This is a design for independent review before code,
as requested in the owner's dispatch brief. It does not enable blocking poll
or claim the issue's runtime acceptance. The publisher can post this proposal
on the issue; this worker has not posted it. This draft incorporates the
[round-2 independent review](https://github.com/carrick-sh/carrick/pull/1495#issuecomment-6595929641)
and the owner's ARM-first ruling; implementation remains unapproved here.

## Decision and first slice

Add a retained `PollWait` operation in the shared Linux ring service. Slice 1
admits initially unready sets only when every waiting entry resolves to the
same in-zone pipe read lane and one open description, with an inherited
signal mask. Multiple entries and duplicate descriptors are allowed if their effective interests all map to
that lane. Negative descriptors remain in the snapshot with zero revents.
Write-end entries, distinct descriptions, host entries and replacement masks
remain refused before output or suspension. Read-end interests include
`POLLIN`, `POLLRDNORM` and `POLLRDBAND`; even `POLLOUT` or `events == 0`
subscribe to Readable for unconditional HUP/ERR. Publish last-writer HUP under
the object lock before advancing that same Readable epoch. Preserve the
existing `nfds == 0` and all-negative timed-set host crossing: zero effective
lanes must not newly refuse those calls. Preserve existing immediate
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

Introduce a typed, generation-bearing pool extent `(index, generation)` in
**the shared IPC region**, referenced by `IpcOpKind::PollWait`. Native resume,
host handback, unhome and retirement all access this payload; an EL1 heap
pointer is insufficient. Slice 1 bounds each payload at 64 pollfd entries.
Larger initially unready native sets receive counted ENOSYS (38) before
output/admission; retain the existing RLIMIT_NOFILE EINVAL (22) threshold and
immediate snapshot support. Allocation failure is ENOMEM (12).

Add a protocol fact for the complete `IpcOpKind` discriminant set, including
`PollWait`, to `IPC_LAYOUT_HASH`, plus new field offsets and pool-area facts.
Size/offset facts alone do not detect a new enum discriminant; mismatched
attach must fail before reading one. Update all native substrate, host
continuation and retirement matches together. All arrays and copy buffers
live in the payload, never on EL1/CPL0 stacks. Target entry/resume frames at
most 512 bytes each, with no by-value payload returns; verify actual generated
frames and entry envelopes through `carrick-el1-image/frame_budget.rs` and
extend the same check to CPL0 when #1040 binds it.

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

Acquire the single description pin through authenticated lookup, rolling back
partial admission. Multiple numeric entries may share it, but opening a FIFO
twice produces distinct descriptions and is outside slice 1. The pin keeps
only the original subscription target alive. **Every readiness scan resolves
each numeric fd in the retained copied array through `resolve_poll` against
the current table.** Closed numbers give POLLNVAL and count as ready; `dup2`
replacement reports the new file's readiness. Closing a number alone need not
wake the poll: a later original producer notification triggers that rescan.
Rescans add no subscriptions. Never reread caller fd/events memory.

If reuse now names a host object, use only an authenticated zero-time host
sample in a supported venue; otherwise settle with counted ENOSYS before any
output, never a post-admission Forward or blocking host query. `finish`,
`retire_native_operation`, host interrupt, exec/exit cancellation and every
failed-admission path release the one pin and extent exactly once. A later
multi-description slice needs a payload pin array and updates to all of those
retirement paths together.

Retain admission progress through an owner or table Busy: release execution
capacity, enroll on that owner's release and probe once. Busy is not ENOSYS,
EAGAIN, a fatal error or grounds to drop the snapshot. An unsupported venue
can be refused only before effects, with every provisional pin released.
Allocation exhaustion is a fallible error, not an abort.

## State and wake protocol

`Admitting -> Waiting -> Completed -> Copying -> Retired` is one owned
operation; owner-memory waits suspend the current state, and cancellation
claims terminal custody rather than starting another operation.

1. Validate in existing ABI order: timespec copy/value, sigsetsize, mask
   copy, nfds against RLIMIT_NOFILE, pollfd copy, allocation. Capture inputs
   once. Compute
   the deadline once from the entry clock, rounding up only to timer
   resolution. Do not turn ppoll nanoseconds into a restarted i32-ms timeout.
2. Pin and classify the whole set before output. For the single lane, observe
   its generation before the readiness probe, using the producer lock/epoch
   protocol. After an empty probe, enroll against that observation. A change
   rejects sleeping and causes a rescan by retained fd numbers. Successful
   enrollment precedes the final signal probe. Producer publication must
   update readiness before notifying the same incarnation-bearing key.
3. Commit the retained token, context and timer with the scheduler handoff;
   release the execution lease. No pool worker, vCPU lease or host selector
   remains blocked waiting for this pipe's writer. A runnable second process
   must be able to acquire execution capacity even at pool exhaustion.
4. A wake, timer or signal claims the existing park sequence exactly once.
   A readiness wake only schedules a rescan; it does not promise readiness.
   Repark with the same snapshot, pin and original deadline when readiness
   was consumed by a competing reader. On timeout, perform a final readiness
   scan before authorizing zero. Every resumption orders readiness first, then
   a handled signal, then timeout. Test both ordered wake/deadline outcomes.
5. When a ready set is selected, freeze its complete revents and return count.
   Detach producer subscriptions and the timer before copyout. An owner-memory
   wait retains these exact bytes even if another process drains the pipe,
   closes the fd, or edits the guest array. Never resample a completed answer.
6. Replace the current whole-record `complete_poll_copyout` with strided
   revents-only output: two bytes at offset 6 of each 8-byte pollfd, preserving
   current guest fd/events. Retain entry/byte cursor under one copyout owner
   with page-sized memory preparation, O(n) work and no replayed prefix.
   Write every entry on non-error returns, including zero revents on timeout.
   EINTR revents are fixed by the oracle fixtures below, not guessed.
   Prepare owner memory through the existing copyout authority and retain
   any admitted prefix/cursor. Final EFAULT and partial-copy behavior need
   oracle coverage. Unmapping or protecting output while parked yields EFAULT
   (14) after the wait; retain the admitted prefix. Completion releases the
   pin and storage once. Raw ppoll attempts remaining-timespec write-back on
   every returning outcome (ready, timeout `{0,0}`, EINTR); retain the original
   deadline and write-back cursor through memory waits. The read-only-timespec
   oracle must settle whether its fault overrides the selected result before
   code approval. Libc wrappers hide this mutation; x86 poll milliseconds have
   no timespec write-back.

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
EINTR (4) only for a signal whose handler will run, with no SA_RESTART replay.
Ignored/default-ignore signals do not end it. Job-control or ptrace stop then
SIGCONT continues the same wait with its original deadline, unlike epoll.

Add PollWait-specific handling **before** generic interruption/expiry in both
native resume (`crates/carrick-el1-linux/src/ipc.rs:409-438`) and host
`interrupted()` (`crates/carrick-kernel/src/kernel/continuation/ipc.rs:362-385`).
Both scan first: readiness > handled signal > timeout. Freeze and copy the
answer, including timeout zeros and raw ppoll timespec, before returning; do
not use epoll's bare `frame.x[0] = 0` or `IpcCause::Stop` EINTR arm. Exclude
PollWait from the `frame.esr = 0xfffe` SA_RESTART marker alongside EpollWait.
These locations name the existing arms, not a new line-pinned inventory.

Exec/exit cancellation detaches every waiter,
cancels timer ownership and releases resources without copying into a retired
MM. A late notification must not complete a recycled task or operation.

The later temporary-mask slice extends `kernel.signal.temporary-wait-mask`:
copy and validate the replacement mask once, remove unblockable signals, and
install it atomically with pending-signal observation/enrollment under signal
authority. Transfer a restoration token, never an executor-local guard. Restore
exactly once on success, timeout, EINTR, EFAULT, cancellation and failed park;
for EINTR retain the temporary mask until signal-frame delivery has selected
its handler and arrange restoration on return according to the signal API.
Require the replacement-mask oracle to confirm readiness > signal > timeout.
Memory-copy waits must not silently restore early or reinstall from guest memory.

Host handback gets an explicit PollWait branch consuming this token and
retained payload. It may resume admission, readiness or output; it must never
re-run the original syscall or reconstruct state from registers. Once admitted,
never use `IpcHandback::Restart` or epoll's register-based rerun. Pre-admission
Restart is possible only in an already supported host venue; native children have no such fallback.

Timer admission is per-record and currently always available; do not design
around stale timer-slot contention. Cover **unhome** instead: executor
settlement transfers the record's absolute deadline to the host
(`carrick-el1/src/sched/object_wait.rs`). Host expiry returns
`Handback::Timeout` to the same PollWait scan/freeze/copyout continuation.
A stop or spurious wake cannot reset that deadline.

Put normalization and the PollWait state machine in `carrick-el1-linux`, with
neutral producer enrollment in `carrick-sched-core` and typed ABI state in
`carrick-el1-abi`. Introduce or reuse a common task/context parking interface
rather than passing through ARM-only `ipc_transfer`. ARM and x86 adapters
supply only frame decoding, syscall reentry/completion, clock conversion and
interrupt mechanics. Per owner ruling, **ship ARM first**. All ARM native
and host handback consumers must handle PollWait together. x86 follows through
the explicit #1040 seam with its own production witness; it is not an ARM landing blocker.
The neutral reentry contract retains the token, rewinds ARM ELR by SVC_LEN,
and on x86 rewinds past `syscall` and restores `rax`/`orig_rax`. #1040 supplies
that adapter without copying Linux service logic. Until bound, x86 blocking
venues remain counted ENOSYS; do not claim cross-ISA runtime acceptance.

## Contention prerequisites

Every contention arm retains Busy, releases execution capacity, enrolls on
the responsible authority's release notification and probes once. None may
Forward or become counted ENOSYS just because the authority is busy:

| Arm (including immediate scans) | Required release source |
|---|---|
| `TableContended`, fd-lookup contention in `resolve_poll` | FD table mutation/sequence writer release |
| `PinContended` | Description pin/ref authority release |
| `ObjectBusy`, object-lock contention in `resolve_poll` | Exact object holder release |
| `NoOperationRecord` | Operation-slot retirement/free publication |
| Payload extent admission Busy | Shared pool allocator release |
| Owner-memory copyout Busy | Exact MM editor/owner release |

`resolve_poll` currently collapses lookup/object contention into `None`;
introduce a typed Busy result rather than misclassifying it as an unsupported
shape or POLLNVAL. Operation-slot exhaustion has no suitable notification
today: adding one is a slice-1 prerequisite. Audit the other release sources
and add any missing notifications before routing. Witness each arm Busy once,
then success through production admission/resume with the same owned inputs.

## Host-bound descriptors and refusal boundary

Preserve #894's host-only readiness crossing where supported. A host-only
selector must never wait on behalf of a set containing an unready Carrick
producer. Slice 1 refuses that blocking mixed set before invoking a blocking
host query, including when host readiness infrastructure is available. Test
native child refusal and the root divergence separately; the native result
must be counted ENOSYS without a syscall fallback. Immediate mixed
snapshots may use zero-time host sampling only in already supported venues.

Record the root's existing host blocking poll as a `RootOnly` divergence in
#1393's shrinking list: root and native child currently give different answers.
When root flips to native it adopts this PollWait owner; it cannot retain a
parallel host poll path. This design does not claim that flip has happened.

Full mixed support needs a retained host-readiness subscription plus native
producer subscriptions under the same completion owner and deadline. Neither
side can finish and free the payload while the other can still notify it.
That bridge is a separate reviewed slice; until then mixed blocking and
unsupported temporary masks remain counted ENOSYS, with no output or Forward
syscall execution. Existing host-only supported venues need regression tests.

## Contracts and evidence required before implementation can close acceptance

Apply `kernel.copyout.owner-refusal`, `kernel.signal.temporary-wait-mask` and
the scheduler continuation contracts. `kernel.el1.epoll-zone` is a template,
not evidence for poll. In the first code PR, register red-first a dedicated
`kernel.poll.retained-wait` surface contract, binding the production common
poll entry and runtime handoff. This documentation-only pass registers no
fictional green binding and changes no executable contract budget. The code
PR adds `surfaces.toml` entries for dispatch, IPC and the new service module;
models the descriptor on `el1-epoll-zone.toml` and `temporary-wait-mask.toml`;
and names ppoll/poll, pipe2/read/write/close/dup2/fork, asynchronous signals,
scheduler continuation and both VMM lanes. Bind VM-free production park/resume,
ARM embed structural first-touch, Docker fixtures and the explicitly pending
x86 KVM seam. Preserve the 1/8/64 budgets and <=2x p50 requirement below.

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
  of wake/deadline and signal/deadline, unhome before expiry, and operation-slot
  Busy once then success;
- ready answer followed by real sibling MM-editor contention, drained readiness
  during that wait, exact resumed output and no duplicate completion;
- signal, stop/continue, exec/exit, cancellation during admission/park/copyout,
  late notification after reuse, and pool exhaustion with a runnable producer;
- every excluded venue returning counted ENOSYS before output, especially a
  mixed set with an available host crossing; ARM production frames first,
  x86 production frames through #1040.

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
`child_ok=true`, and require the equivalent x86 KVM witness when #1040 binds
that seam. Finish the signed probe/smoke/full sequence and serialized Docker differential on their capable
hosts. Paired uninstrumented same-workload p50 must meet the existing <=2x
policy; structural and semantic passes cannot excuse a failing ratio.

Independent design review is required before slice 1 code. Multi-entry,
temporary masks and mixed-host subscriptions each need their own reviewed
production witnesses; completion of slice 1 alone does not close #1051.

## Native oracle fixtures and next slice

Before implementation acceptance, commit source-hash-validated fixtures in
conformance-next. Bound every blocking call, run native fixtures under
`timeout 10`, print errno numbers and clean up all children on every exit:

- raw `SYS_ppoll` writable timespec on ready, timeout and EINTR, plus a
  `PROT_READ` timespec to settle fault/result precedence;
- CLONE_FILES close while parked then original-producer write: POLLNVAL,
  count 1; `dup2` to another ready pipe: new POLLIN; old subscription pin
  keeps its reader alive (no writer EPIPE until poll retires);
- `events=0` then last writer close: HUP; data plus close: POLLIN|POLLHUP;
- SIGSTOP/SIGCONT with later data: readiness, not EINTR; without data:
  timeout at original deadline; ignored signal leaves wait active;
- stale `0x7777` revents on timeout and EINTR, duplicates/negative entries,
  exact count and unchanged caller fd/events;
- sibling munmap/mprotect of the poll array during park: post-wait EFAULT
  and exact partial revents prefix; combined bad-argument precedence table;
- simultaneous readiness/signal/timeout in deterministic VM-free schedules;
  pending blocked signal plus ready pipe and unblocking ppoll replacement
  mask in the later mask slice, confirming ready result then handler.

Correct the #1051 diagnosis: shell `$(...)` and pipe `read` use the retained
`PipeRead`, not poll. This slice targets the finite single-pipe first-touch
witness and single-pipe poll loops; it does not claim shell rendezvous coverage.
The publisher should carry that correction to the issue; this worker posts no
comments. Select the next slice by counting refused `ordinal=73` set shapes
under `scripts/dtrace/hvpatch-native-crossing-refused.d` across go/cpython/node
and a build row: distinct in-zone lanes, mixed host stdio, replacement masks.
Publish the counts before naming the winning slice; no ranking is measured
in this docs-only pass. Keep this proposal draft for independent review.
