# Native child IPC constructors (#1506)

`kernel.el1.ipc-fd-authority` covers the constructor ownership work below.
The epoll, pipe and eventfd constructors now serve the VM-free native witnesses;
timerfd remains unimplemented. No signed acceptance is claimed.
The four
`serial_host_native_fork_children_create_*_in_their_own_tables` bindings
fork two children through `NativeProcessRuntime` and call the production
`dispatch_syscall_with_native` entry with a real ARM trap frame. Both
children and their parent remain live. Each binding requires a ring answer,
CLOEXEC on the allocated descriptors, no publication into the parent table,
and distinct backing identities for the two children's newly created objects.
The pipe result is copied from the user buffer separately after each call.
The timerfd bindings remain red until its ring service exists.

The `serial_host_native_root_creates_*_with_live_children` bindings use the
same real-fork fixture and production entry, switch back to the root while
both children remain live, and authenticate its borrowed table identity.
They require creation, FD_CLOEXEC lookup and close to complete in ring.
They require the shared ring path: root success through the host crossing
does not satisfy the one-path contract. These root bindings complement the
child bindings; neither population substitutes for the other.

## Original root cause

`serve_ipc_with_signals` admits read, write and epoll wait, not constructors.
`service_owner` classifies the four constructors as `RingOwed`, through their
Temporary crossing declarations. No constructor family serves that debt.
The production `native_unstaged_exit` asks `unclaimed_native_syscall` before
capturing a crossing: a fork child gets counted ENOSYS (38), while the root
retains the carrier route. This is an absent ring implementation, not a
missing inherited permission. Changing the child to a root or widening the
crossing policy would select the wrong process authority.

The root's carrier dispatcher already implements `pipe2` in `fs/pipe.rs`,
`eventfd2` in `net.rs`, `epoll_create1` in `net/epoll_ops.rs` and
`timerfd_create` in `time.rs`. Pipe, eventfd and zone epoll use shared IPC
objects underneath those host wrappers. Timerfd instead owns host
`TimerFdState`, including the creating container's clock domain. The root
therefore succeeds through a service the native child cannot use; it does
not already have an in-ring constructor.

The borrowed root namespace also has a host `FileTable` and descriptor
projections. `El1PendingFamilies::descriptor` uses the native IPC mutation
owner only for an owned table; the borrowed root takes the host-binding
mutation path instead. A direct `IpcRegion` constructor plus an IPC table
slot is therefore insufficient: it would publish an fd without the root's
functional host metadata. Removing Temporary crossings at that point can
regress root fcntl/close and mixed epoll operations. Constructor publication
must establish one descriptor owner for these consumers rather than leave
the root forwarding beside a child-only implementation.

`HostIpc` also binds the object's Readable and Writable scheduler wait keys
after creating the shared record. A ring constructor must retain that
initialization guarantee before publishing a usable fd. Calling only the
record allocator does not prove scheduler wake delivery.

## Required implementation

Serve constructors before the unclaimed-native boundary, in shared Linux
code used by both ISAs. Resolve the executing task's exact table, including
borrowed root tables, without inheriting a parent table or host task.
Validate flags and clocks before allocating. Preserve current Linux errors,
zone ceilings, elastic storage growth, and bounded work. Capacity misses
are not new fixed limits; contention retains the operation and enrolls on
the authority's release notification.

Pipe construction must prepare owner-aware user output before effects, use
`SlotTableTransaction::install_pair` for atomic publication, and settle both
endpoint descriptions on failed publication or genuine copyout fault.
Allocation/cleanup must account for retained pipe storage. `create_pipe`
now retains a too-small extent on its object; it no longer returns storage
requiring host retirement at construction.
No object/table lock may survive user copy, service, or suspension.

Timerfd needs one shared, pointer-free timer authority, with host users moved
to it rather than a ring-only copy beside `TimerFdState`. Preserve the
creator's clock-domain identity, frozen/deterministic/scaled-clock behavior,
set/get/read, expiry counts, scheduler deadlines, epoll membership and final
release. Any IPC record-layout change must update the ABI identity. Expiry
must respect the existing member-before-epoll lock order, publish after
unlock, and use scheduler notifications without a host readiness pipe or
polling. A dormant create-only timer is not parity with the root service.

The VM-free witnesses do not prove guest instructions, backing supply,
signed ARM execution, x86 execution or Go build. Those higher-layer bindings,
constructor refusal/rollback schedules and deterministic work budgets remain
required before acceptance.

## Functional witness requirements

The constructor bindings now require usable objects before switching away from
one child to the other. Pipe creation must support an eight-byte round trip,
then return EAGAIN (11) on an empty nonblocking read. Eventfd must return its
initial value (7), become empty, then accept and return a new value (23).
Both pipe ends and eventfd must expose O_NONBLOCK through production fcntl.
An empty epoll must complete a zero-timeout wait without changing the event
buffer. A new timerfd must report a zero itimerspec and return EAGAIN (11)
for a nonblocking read while disarmed. All follow-up calls use the same
production native-process dispatch entry as the constructors.

These follow-up assertions are prospective: the current constructor refusal
stops each test before they execute. They therefore add no green backing,
readiness or clock-domain evidence. In particular, the disarmed timer check
does not prove arming, expiry counts, time-namespace identity or wakeups;
the empty epoll check does not prove member add/modify/delete or readiness.
Those functional schedules, constructor rollback and Busy-once resumption
remain necessary. No timeout, retry or wider route is introduced here.

The timer migration changes the shared IPC record layout and clock authority
interface. Under AGENTS.md, those ABI/interface choices require a separate
design review before implementation. The existing host TimerFdState cannot
be placed in shared ring memory: it contains host mutex/condition-variable,
Arc clock-domain and wait-queue references, and change-listener callbacks.
Moving only its counter arithmetic does not establish a ring-owned timer.

## Independent epoll member control

`serial_host_native_fork_epoll_ctl_observes_peer_pipe_write` separates the
missing member service from the constructor refusal. It admits an epoll
through the existing host IPC owner before two real native forks, then closes
the parent descriptor. Child 0 calls production `epoll_ctl(ADD)` for its
inherited pipe reader. A zero-timeout wait must leave the event buffer
unchanged before child 1 writes. Child 0 must then receive EPOLLIN with the
registered data cookie, read the peer's exact bytes, and observe no readiness
after draining the pipe. Every wait has timeout zero; no host timing or
sleep loop supplies the verdict.

The test fails independently at the unserved `epoll_ctl` entry on the current
implementation. Later readiness assertions remain prospective. This control
cannot replace the constructor witnesses: acceptance still requires applying
member operations to the epoll returned by the new constructor in both root
and child. It also does not prove blocking wake delivery, MOD/DEL, or timer
arming/expiry. No crossing policy or production service changes here.

## Earlier epoll implementation checkpoint

The shared descriptor family now serves `epoll_create1`, and zone-member
`epoll_ctl` uses the existing shared epoll core. Construction validates
CLOEXEC, binds scheduler readiness keys and rolls the object back if
numeric publication fails. Root descriptors backed by zone objects select
that same ring descriptor owner for fcntl, close and duplication. The
control input uses the guest ISA's event layout (16 bytes on ARM, packed
12 bytes on x86).

The three existing epoll witnesses pass in the VM-free native suite; the
six pipe, eventfd and timer constructor witnesses still fail. This is an
implementation checkpoint, not completed constructor acceptance. In
particular, the newly constructed object has only the existing empty-wait
witness; the independent pipe-readiness control uses a pre-admitted epoll.
No additional witnesses were added in this continuation.

The checkpoint's independent review requested changes: root epolls created by this path
lack the host description required by forwarded host-member operations;
shared-core HostHalf refusals still forward; and native wait fallback cases
and x86 wait parity remain unresolved. The growth-contention finding from
that review is corrected by the shared publication owner below. These are blockers, not accepted semantics or follow-up-only
coverage. Removing the constructor crossing in this checkpoint does not
establish that the root's full existing epoll surface is preserved. Do not
land it without resolving those findings and obtaining confirming review
and signed proof. No Go-build or guest-execution claim follows from the
VM-free results.

## Earlier pipe storage prerequisite

The shared `IpcRegion::create_pipe` entry can now run in either venue without
returning host allocator work. Reuse keeps a fitting ring. An undersized ring
stays attached to its object while the pipe is unbacked, and the existing host
replacement operation returns that extent exactly once for reclamation.
Stock supply refuses before taking a ring if replacement would need to reclaim
an old extent. The existing host first-write supply owns that replacement.
No second allocator, shared-record layout or lock order is introduced.

The existing storage lifecycle witness was red because creation detached the
old extent. It now checks retained identity, an effect-free write refusal,
replacement custody and an unspent stock ring. The bound remains one retained
extent per object; creation allocates no backing and does no storage copy.
This prerequisite does not serve the pipe2 syscall. Its root and child
constructor witnesses remain red. Pair publication must still retain both
endpoint descriptions across output preparation, owner waits, genuine copy
fault rollback, table/OFD/object growth and scheduler wait-key admission.
A completed-answer copyout alone cannot own those constructor resources.

## Shared constructor storage design (pipe continuation)

Pipe output retains two fd-core numeric claims and two prepared descriptions
until the exact-MM copyout completes. Its owned completion publishes the pair
under one table sequence and transfers the preparation pins under that same
lock, so concurrent close cannot leave an ignored final-release wake.
Cancellation drops both unpublished claims and endpoint pins.
The mapping lifetime is distinct from a single dispatch borrow so a service
wait cannot outlive its IPC authority.

The existing constructor witnesses expose two remaining single-venue allocator
assumptions. Concurrent count publication can report contention as an errno,
and a second native pipe write exhausts the stock and has no ring backing
supplier. The correction uses the existing shared storage owner:

- Each record store has one shared short publication lock. Growth takes the
  observed count, reprobes after another publisher advanced it, and checks the
  ceiling inside the lock. Count and the complete free-list segment publish
  before unlock. A distinct completed-publication count is the admission
  observation; the earlier resolvable count only authenticates new indices.
  No table/object lock, allocation, copy or callback is held.
- Pipe extents use a second `carrick_fd_core::storage::Storage` over the ring
  half of the pool. Delete the host-private buddy allocator. Stock, live and
  retained rings share this authority. A first write takes stock or allocates
  through that same owner, preserving lazy idle pipes.
- Allocation/reclamation is bounded by the buddy tree height. It releases its
  short lock before returning; no allocator holder acquires an object lock.
  Replacement returns the old extent once, authenticated by offset and rounded
  footprint. True pool exhaustion is ENOMEM, never Forward or ENOSYS.

Independent design review accepted these lock and layout changes before code,
with the requirements to preserve observed-count admission at the final segment,
initialize metadata before publication, and exercise two native children without
assuming stock supply. Signed execution and the existing broader epoll review
remain separate acceptance obligations.

## Pipe implementation proof

The existing root/two-child constructor entry witnesses now cover usable pipes,
CLOEXEC and nonblocking flags. Root output fault followed by another creation
requires the same lowest descriptors, proving no leaked numeric claim. The
physical-service owner-wait variants drive that same production TrapFrame entry
with the eight-byte result across a page boundary: only the first four bytes
are delivered before the wait, neither fd is visible while parked, and resumption
publishes both once. Fatal cancellation returns both numeric holes and endpoint
references without delivering the suffix. These are controlled VM-free schedules,
not guest instructions or signed acceptance.

The fd-core publication transfers both preparation pins while its table lock
still excludes close. The shared storage tests require disjoint no-stock rings,
retained undersized replacement with no leaked allocation, and actual pool
exhaustion reported as errno 12. Mid-publication probes require admission to
observe the old completed inventory until the segment is fully linked. The
new locks cover one fixed record segment or one logarithmic buddy operation;
no syscall retries, timeouts or concurrency budgets are widened.

## Eventfd continuation

Eventfd2 now selects the existing shared descriptor constructor owner for
both the borrowed root and native child tables. It shares epoll construction's
object-growth, readiness-key binding, numeric publication and failure cleanup;
it allocates the existing shared eventfd record rather than a second counter.
Flags are checked before allocation; semaphore mode, O_NONBLOCK and FD_CLOEXEC
remain distinct. No user copy or suspension occurs while the constructor owns
an unpublished object, and failed numeric publication releases it once.

The production two-child witness checks independent counters, initial-value
read, empty EAGAIN, write/read and flags. The root witness adds invalid flags,
lowest-hole reuse, two semaphore reads and close. The production fork/exec
successor constructs both an eventfd and an epoll, reads the initial counter,
performs a zero-timeout empty epoll wait, checks CLOEXEC and closes both.
These controls do not prove blocking wake delivery or signed guest execution.
The earlier epoll host-member and native-wait findings remain landing blockers;
this continuation reuses that owner and does not replace the work in #1765.
