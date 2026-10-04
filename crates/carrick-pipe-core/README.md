# Pipe and event counter core

Checkpoint 3.2 substrate only. No host/runtime/EL1 integration is included.
The workspace's `crates/*` member declaration includes this crate. Production
uses `core` only: no allocator, locks, syscalls, host dependencies or ABI crate.
Like sched-core, storage is supplied by the venue. `Pipe` borrows a byte reserve
and page metadata; `EventFd` is inline. The borrowed slices are never
persisted: the pipe's whole mutable state is the plain-data `repr(C)`
`PipeRecord`, and `Page`/`EventFd`/`WriteProgress` are `repr(C)` plain data too,
so a venue can keep them in memory shared by host and EL1 (the EL1 IPC records
in `carrick-el1-abi::ipc` do). `Pipe<'_, &mut PipeRecord>` is a view attached
under the object's lock (`Pipe::attach`, O(1) invariant checks, `Corrupt` on a
record that does not describe the storage); `Pipe<'_>` owns its record. Both run
the one algorithm.

## Contract: `kernel.el1.ipc-object-state` (pipe/eventfd part)

Staged copy/commit for venues whose copies can fault (guarded user copies):
`Pipe::read_with` hands queued chunks to a copy callback and consumes only the
bytes it reports delivered; `Pipe::write_with`/`write_progress` reserve ring
space, let a fill callback supply it and publish only filled bytes;
`EventFd::read_with` drains only after a successful delivery. A copy that
delivers nothing is `Error::Fault` with no state change and no wake (EFAULT);
a partial copy returns the delivered prefix. EOF, `WouldBlock`, `BrokenPipe` and
small-write atomicity are decided before any copy runs, so a refused atomic
write stages no byte. `try_read`/`try_write`/`WriteCursor` are these same
functions over a slice. `WriteProgress {len, written}` is the owned
continuation's byte offset: a resumed write never restarts at zero.
An *unbacked* pipe (`PipeRecord::unbacked`, attached over empty storage)
has a capacity but no ring yet, as Linux allocates pipe pages on demand:
reads, readiness, closure and F_SETPIPE_SZ work on it, and its first write
refuses with `Error::Storage` (after the EPIPE check) before any effect, so
the venue provides storage (`Pipe::replace_storage`) and retries.
VM-free bindings: `el1_ipc_*` unit tests in this crate (shared-view/owned
equivalence over a 4000-step model, attach validation, all atomic sizes through
the shared record, read/write faults preserving undelivered bytes, eventfd
fault/semaphore/overflow, copy work exactly 2x transferred bytes at 1/4096/16384).

## Contract: `substrate.pipe-eventfd`

Authorities (no Linux kernel source consulted):

- [pipe(7)](https://man7.org/linux/man-pages/man7/pipe.7.html): atomic writes,
  closure, capacity, FIONREAD.
- [F_GETPIPE_SZ(2const)](https://man7.org/linux/man-pages/man2/F_GETPIPE_SZ.2const.html):
  page rounding, capacity limits and occupied-buffer shrink rejection.
- [eventfd(2)](https://man7.org/linux/man-pages/man2/eventfd.2.html): counter,
  semaphore, invalid all-ones write, overflow prevention and readiness.
- Existing `conformance-probes/src/bin/pipeextra.rs` explicitly expects
  `pipe_fionread_write_end_matches_written`. Linux FIONREAD returns the queued
  byte count on **both** ends. Returning zero on the write end is a host/BSD
  behavior, not the Linux contract. `unread_bytes()` is endpoint-independent.

The VM-free binding is `cargo test -p carrick-pipe-core`. Tests exhaust all
1..=4096 atomic write sizes at four free-space boundaries, exercise larger
split writes, closure/refcounts, page fragmentation, wrapped resize, a 10,000
operation FIFO model, readiness and eventfd counter boundaries. Structural
scales 1/4096/16384 bytes require exactly twice the transferred bytes copied
for write+read and at most twice the touched pages visited. Storage addresses
stay fixed across 100 rounds per scale. No allocator is linked into production;
there is no per-operation allocation. Read/write cost is O(transferred bytes),
readiness/count queries are O(1). Resize may move O(old capacity) bytes and is
explicitly outside the read/write budget.

Signed/embed, native Linux differential and runtime-ratio bindings remain the
integration director's responsibility. These unit tests do not claim guest
execution or checkpoint-3 acceptance.

## Venue obligations

### Landing B preparation: readiness revision and owned progress

Bind `Pipe::with_revision(&mut ReadinessRevision)` to the persistent word for
that exact object incarnation, under the object's lock, on every view that
mutates an object with revision observers. `PipeRecord` keeps its existing
56-byte shared layout; this word is caller-supplied storage. A bound view
advances it on published bytes, consumed bytes, final endpoint close and
capacity change. Peeks, refused operations and zero-byte I/O leave it alone.
`replace_storage` preserves the binding and revision. A revision cannot wrap:
`RevisionExhausted` refuses before effects or copy callbacks. It is a venue
lifetime failure, not a guest errno. `readiness_snapshot` on an unbound view
returns `RevisionUnavailable`, never a fabricated revision.

Observe, enroll, then probe `readiness_snapshot` again under the same object
authority before parking. A changed revision requires rechecking the operation
even if readiness returned to the earlier bits; a snapshot never grants bytes.
The scheduler owns enrollment/park/wake authentication. Revisions do not replace
`WakeSet`, exact object incarnation, OFD pins or the enroll/recheck protocol.
The future shared-layout word and ABI hash/version update belong to landing B
after N1; existing adapters do not automatically bind this API.

`Step::broken_pipe_signal()` returns the signal decision as data; the
personality applies SIGPIPE and returns EPIPE or the already-delivered prefix.
It reuses `Error::BrokenPipe` and raises no signal. Retain the same writer
endpoint and `WriteProgress` across close/reuse and suspension.

VM-free `b_prep_*` bindings extend `kernel.el1.ipc-object-state` and
`kernel.el1.ipc-lifecycle`. The readiness write/drain witness failed on main
`ad3e127a9`: bits alone lose the pre-enrollment edge. At 1/8/64 simultaneously
live blocked writers, reattached views resume precisely at `written`, deliver
each source byte once, and release the final writer only after completion.
The deterministic budget is exactly `2 * delivered_bytes` copied and six page
visits per three-page stream, independent of unrelated pipe population.
These are core proofs, not guest scheduling, executor exhaustion, user-copy
admission or signed integration acceptance.

### Existing venue obligations

- Serialize operations and waiter enrollment under the same object authority.
  On `WouldBlock(Readable/Writable)` (the `WaitFor` enum), either map to EAGAIN
  for O_NONBLOCK/EFD_NONBLOCK, or enroll/recheck and park. Deliver `WakeSet`
  notifications to **all** relevant object waiters and poll/epoll subscribers.
  Notifications are recheck hints, not readiness grants. Never sleep in the core.
- Retain a functional endpoint lease across a suspended syscall. Creation owns
  one reader and one writer reference; the venue releases them when the last
  corresponding open description/in-flight lease closes. Extra retained
  references delay EOF/EPIPE; dead endpoints cannot be resurrected.
- A successful short `try_write` is the nonblocking result. For blocking writes,
  retain `WriteCursor` and its original source until completion, a signal or
  closure. Return prior progress on interruption/closure; on `BrokenPipe`,
  generate SIGPIPE even if previous progress means returning a byte count.
  Zero-length pipe I/O succeeds without checking peer closure.
- Map `BrokenPipe` to EPIPE + SIGPIPE, `Busy` to EBUSY, `Permission` to EPERM,
  `Invalid` to EINVAL. `Storage` means the supplied reserve is insufficient;
  arrange additional venue backing before retrying or map allocation refusal
  to ENOMEM. `Refcount` is a venue lifetime error, not a syscall errno.
- Pass the **guest** page size (power of two, >=4096); the default is 16 pages.
  Supply sufficient storage/metadata for the desired growth range. The current
  API resizes within that reserve; it does not acquire backing. Capacity is
  rounded up to a power of two, at least one page. The authorized growth limit
  includes privilege and per-user accounting; shrinking ignores that ceiling.
  Reject signed-negative F_SETPIPE_SZ arguments in the personality.
- This is an ordinary anonymous byte-stream pipe. Page slots preserve partially
  consumed head pages and unmergeable tail slack; fullness and EBUSY follow
  occupied slots, not just unread bytes. Writable readiness requires a free
  slot, even when a small tail merge is possible. HUP can coexist with readable
  bytes; ERR can coexist with writable capacity. FIFO open-generation rules,
  packet mode and splice/vmsplice gifted pages need separate future contracts.
- Eventfd accepts a u32 initial value, scalar u64 writes and returns scalar u64
  reads. The personality validates flags, validates syscall buffer lengths,
  copies exactly eight native-endian bytes, and owns description lifetime.
  Counter mode drains all; semaphore mode consumes one. All-ones writes are
  invalid, sums exceeding `u64::MAX-1` would block. Kernel KAIO signal-post
  overflow is not represented by this user-write API.
