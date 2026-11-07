# Native child IPC constructors (#1506)

## Go netpoll continuation audit

The Go surface in this round excludes timerfd. The production native-child
entry already serves the following ARM VM-free witnesses on the preserved
branch. These are dispatch and ownership proofs, not signed guest execution.

| Call | In-ring native-child evidence | Limit |
| --- | --- | --- |
| `epoll_create1(EPOLL_CLOEXEC)` | `serial_host_native_fork_children_create_epoll_in_their_own_tables` | Zone epoll; mixed host members remain open |
| `epoll_ctl` | `serial_host_native_fork_epoll_ctl_observes_peer_pipe_write`; `native_exec_pipe_tests::serial_host_native_fork_exec_pipe_writer_reaches_its_parent` | ADD and post-exec DEL; new MOD composition described below |
| `epoll_pwait` | Both epoll witnesses above and the child constructor witness | Ready/empty timeout-zero calls; new finite park/wake composition described below |
| `eventfd2` | `serial_host_native_fork_children_create_eventfd_in_their_own_tables`; post-exec witness above | Counter round trip, nonblocking status and CLOEXEC |
| `pipe2` | `serial_host_native_fork_children_create_pipe_in_their_own_tables` | Independent child tables, round trip, empty EAGAIN (11), status and descriptor flags |

The focused native-fork harness ran all these bindings successfully. Its
timerfd constructor binding still fails at Forward for ordinal 85; timerfd
is outside this round.

`serial_host_native_fork_netpoll_eventfd_wait` adds the missing composition
witness. Child 0 creates a CLOEXEC epoll and an initially empty CLOEXEC,
NONBLOCK eventfd through production dispatch. It registers EPOLLIN|EPOLLET,
observes an empty timeout-zero wait, writes the counter, receives the exact
cookie, and drains it. MOD installs a second cookie. A real fork from that
child creates the writer with inherited descriptions and a distinct table.
The original parent and both original children remain alive.

The child then enters a finite 500 ms wait on the empty counter. The test
requires Suspended, no current execution record, an owned queued operation
and the exact virtual-counter deadline. The writer's production native
write wakes it. The resumed wait returns one event with the new cookie;
the counter is exactly one and the deadline/operation are retired. DEL
prevents the next write from making the epoll ready. Every syscall completes
in ring and the forwarded counters remain zero. No sleep, retry loop,
timerfd or host readiness object supplies the result.

The first run passed on the preserved implementation after correcting the
test's nested-fork service binding to the active child's CurrentTask. That
fixture correction is not a runtime fix. The new binding closes missing
ARM composition evidence; it does not establish a new behavioral fix or
clear the host-member/x86 findings below.

For a known-answer negative control, temporarily omitting the existing
`EPOLL_CTL` descriptor route makes this binding fail at native child call
21 with `Forward`. The route is restored in the committed tree. This is
witness-sensitivity evidence, not a reproduced regression or a new runtime
fix. Restoring the entire pre-constructor dispatch file did not compile
against the current interfaces and supplies no runtime red evidence.

The Temporary crossings are not proof that every call forwards: dispatch
serves supported zone descriptors before crossing policy. Keep `EpollCtl`
for existing host-backed/mixed-member service until that authority is
connected; `EpollPwait` retains host members and signal-mask fallbacks.
`Dup`, `Dup3`, `Fcntl`, `Close` and `CloseRange` retain host-owned descriptor
effects even though zone operations have ring owners. `InotifyInit1`,
`Signalfd4`, the three timerfd calls and `EpollPwait2` are separate surfaces,
not needed for the requested Go netpoll sequence. Native children cannot
use a Temporary crossing as a substitute for missing ring service.

Constructors and zone-member control share one dispatch implementation
between ARM and x86. The wait adapter still requires an ARM frame and the
x86 carrier supplies no ARM scheduler venue: x86 native waits remain an
explicit gap. Signed ARM/Go checks: **UNRUN (director)**.

The continuation's full `just test-el1-native --jobs 3` run completed both
regular and `serial_host` partitions: 753 passed, two failed, one ignored.
Both failures are the unchanged root/child timerfd constructor witnesses,
which return Forward for ordinal 85. The new netpoll binding passes.
`just build-cpl0`, `just clippy`, `just check-linux`,
`cargo check -p carrick-vmm-kvm`, `just check-contract-change` against the
PR base, the source-only authority census and PR-base authority ratchet,
`just cross-check-macos`, and `just fmt-check` all passed. These are focused
worker checks, not a fresh main-baseline comparison, KVM guest execution,
signed acceptance, or a runtime-ratio claim. Whole-workspace lint-domains
and test-kernel remain with CI. Evidence and the scoped independent reviews
are recorded on PR #1740.

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


## Timerfd arithmetic prerequisite

The continuation rebased onto the admitted main and found that
`carrick-timer-core` had no timerfd implementation: its modules covered only
interval and POSIX signal timers. The existing timerfd expiry calculation now
lives in `carrick_timer_core::timerfd::expirations`, and the host dispatcher
uses it. The host wrapper still samples the creating `ClockDomain`, only for
an armed timer. The moved calculation preserves unavailable/early samples,
one-shot disarming, zero-interval handling, missed-period accumulation and
count/deadline saturation. It does constant arithmetic work, including for a
one-nanosecond period spanning `Duration::MAX`.

This is a behavior-preserving arithmetic extraction from
`crates/carrick-kernel/src/dispatch/format_time.rs` into
`crates/carrick-timer-core/src/timerfd.rs`; it changes neither IPC layout,
clock-domain identity nor lock ordering. The host consumes the extracted
function immediately. The new core unit bindings cover its edge conditions;
they are not a substitute for the two production constructor witnesses.

The remaining migration requires a separately reviewed shared ABI and clock
interface. In particular, IPC currently has no timerfd kind, no creator clock
domain handle and no expiry/rearm enrollment. The timer must retain its
creator's domain across fork/exec and fd transfer, and both host and ring
must mutate the same timer record. Clock samples and deadline translation
must respect deterministic, frozen and scaled domains; a current-task or
raw-counter clock substitution would change Linux-visible behavior. Expiry
publication must retain member-before-epoll locking, post-unlock notification,
and exact-object cancellation at final release. A constructor added before
those consumers exist would create unusable descriptors.

The Temporary timerfd crossings remain, and the native constructor target is
still open. No ARM, x86, signed execution or full #1506 acceptance is claimed
by the arithmetic prerequisite. Earlier epoll review blockers remain open.

## Timerfd finishing-round witness and clock seam

The native two-child timerfd binding now requires `timerfd_settime` to arm
an absolute monotonic one-shot at 1 ns, return its previous disarmed value,
and let the same child read exactly one expiration. A second nonblocking
read must return errno 11, and `timerfd_gettime` must report disarmed state.
The fake counter is fixed at 1,000,000 ticks at 24 MHz; the deadline is
already past. This is immediate-expiry coverage, not clock advancement or
scheduler wakeup coverage. The constructor still refuses before these new
assertions execute; they remain prospective until the implementation exists.

Independent inspection confirmed that there is no existing ring clock-domain
interface to plug into. `ClockDomain` in `kernel/container.rs` owns host
`Instant`, callback subscriptions and deterministic waiter participation.
IPC epoll deadlines use counter ticks, and the dormant transport in
`memory/el1_clock.rs` explicitly excludes frozen/scaled clocks. Reusing
those counters as the timer creator's clock would change observable behavior.

The necessary migration must retain a generation-authenticated clock-domain
handle on the timer object, publish pointer-free clock samples and changes,
and enroll deadlines atomically with both timer and domain generations.
Frozen, scaled and deterministic clocks need the same transformations and
waiter participation as the host authority. Host and ring must consume one
shared timer record, replacing `TimerFdInner`, with an IPC ABI identity
update. Rearm and final release cancel deadlines by exact object generation;
member updates precede epoll updates, and notification follows unlocking.
These are implementation requirements, not a missing owner semantic decision.
No production timerfd service was added in this finishing-round witness.


## Shared timer state continuation

The host timerfd now stores the interval, next deadline and unread count in
`carrick_timer_core::timerfd::State`. Arming (relative, absolute and disarm),
refreshing and count consumption use that one implementation; the old host
expiry wrapper is removed. Only the core mutates those three fields. The
host still selects the captured creator `ClockDomain`, owns its lock and
publishes rearm notifications after unlocking. The refactor does not change
clock selection, copyout admission, expiration consumption on EFAULT, IPC
layout or deadline enrollment. It is a state/transition prerequisite, not an
in-ring timerfd implementation or a new clock authority.

The core scenarios cover periodic missed counts across a read and rearm or
disarm with unread expirations. Existing production dispatcher tests cover
creator-clock isolation, EFAULT consumption and fd reuse; these remain the
host authority witnesses. The native constructor witness remains red until
shared clock-domain publication, the timer IPC object and scheduler expiry
and rearm enrollment exist. No signed or constructor acceptance is claimed.

## Explicit timer-state storage prerequisite

The shared production `carrick_timer_core::timerfd::State` now has a reviewed
48-byte C record layout with eight-byte alignment. Interval and deadline
each use explicit seconds, nanoseconds and a zero reserved word; a presence
bitmap distinguishes absent values from zero durations. The expiration
count, bitmap and final reserved word have asserted offsets. Only the core
transitions construct values. There is no byte-import API, and the full
`Duration` range remains representable without truncation to u64 nanoseconds.

The layout witness was red on the preceding state representation (40 bytes,
containing Rust-native `Option<Duration>` values). Existing arm, refresh,
consume and rearm tests exercise the same state now used by the host. This
does not change the IPC ABI: no IPC object embeds the record yet. The native
timerfd constructor remains unimplemented and its production witness is
still required to turn green.

Independent design review confirmed that completing the migration requires
all of the following as one coherent authority:

- a retained, generation-authenticated creator-clock handle and pointer-free
  clock-mode projection shared by host and ring;
- the timer record in the IPC object store, with a new authenticated IPC ABI
  identity and an arm revision for cancellation;
- migration of host `TimerFdInner` custody to that record;
- deadline enrollment validating clock generation, object generation and arm
  revision, including deterministic waiter participation;
- read, set/get, readiness, rearm and final-release paths using that authority.

The current host lock order is clock-change snapshot before timer state.
Notifications follow unlocking, and member mutation precedes epoll mutation.
Frozen mode freezes realtime only: its monotonic and boottime clocks remain
live. Scaled clocks use elapsed time from their host Instant origin, while
deterministic clocks use explicit virtual progress. A raw architecture
counter cannot substitute for these modes. The Temporary crossings must
remain until the complete service exists; this prerequisite does not justify
retiring them or claiming signed acceptance.

## Shared creator-clock projection prerequisite

`carrick_timer_core::timerfd::clock` now owns clock transformation and timer
wake-deadline selection. Production `ClockDomain` supplies the selected native
source lazily: calibrated realtime, monotonic, boottime, or elapsed time since
that domain's origin. Its existing mode, offset and virtual-progress owners
remain authoritative. Frozen mode fixes realtime only; deterministic mode does
not sample the host; scaled samples and inverse timeouts preserve the existing
u64-nanosecond saturation and zero-numerator policy.

The host timerfd planner builds the view under its existing clock-change
snapshot lock, then uses one sample for both refresh and deadline derivation.
Clock callbacks, deterministic waiter participation and timer-change publication
remain with their existing owners. The core view is ordinary Rust policy, not a
wire record, authenticated domain handle or shared clock publication protocol.
No IPC ABI or crossing policy changes in this step.

The red core binding required the missing projection API; its green scenarios
cover independent live clock sources, signed-offset saturation, frozen realtime
with live monotonic/boottime deadlines, rational scaling, deterministic epoch
conversion, one native sample, and no sample for disarmed or virtual deadlines.
Existing host clock and timerfd tests remain the production integration proof.
This extraction does not serve native timerfd calls. Shared IPC timer storage,
creator-domain publication and generation-authenticated deadline enrollment
remain required before retiring the Temporary crossings or claiming acceptance.

## Native netpoll composition checkpoint

The admitted-main rebase keeps the native descriptor namespace's missing-table
refusal and ports the earlier borrowed-root constructor/zone-object selection
into that namespace. Without the port, the production root epoll witness
returns `Forward` for ordinal 20; with it, root and child epoll, eventfd2 and
pipe2 constructor witnesses pass. All earlier branch commits were retained;
the descriptor-owner changes were ported, and none were intentionally dropped.

The VM-free native suite now reports 752 passed, two failed and one ignored.
The two failures are the existing root and child timerfd constructor witnesses:
ordinal 85 still returns `Forward`. Thus the current ring service inventory is:

- epoll_create1: root and two-child constructor bindings, empty wait and
  child registration of a newly constructed eventfd;
- eventfd2: root and two-child bindings, nonblocking counter read/write and
  root semaphore/invalid-flag schedules;
- pipe2: root and two-child bindings, nonblocking round trip, private table
  publication and root copyout-fault rollback;
- timerfd: no ring constructor; its two production bindings remain red.

The existing fork/exec pipe fixture additionally requires the successor to
register its newly created eventfd in its newly created epoll with
EPOLLIN|EPOLLET, write a wake value, receive the exact 64-bit cookie, drain
the counter, observe an empty zero-timeout wait, and delete the member.
Every call enters production native dispatch with the successor selected;
its parent remains live. This composition passes without another ring service
change. It closes the post-exec registration witness gap, not a newly
reproduced Go runtime defect. The original fatal error cannot be declared
resolved without the director's signed ARM Go workload run.

Remaining implementation and acceptance work includes the shared timer
object/creator-clock/deadline authority described above, mixed host-member
epoll custody, HostHalf/exhaustion and Busy resumption schedules, and x86
runtime parity under #1040. The earlier epoll review findings remain open.
Signed checks are UNRUN (director); these VM-free results do not prove guest
instructions, ARM backing supply or Go build completion.


## Explicit creator projection storage continuation

The creator projection now replaces the Rust enum with one sealed 56-byte,
eight-byte aligned C record. Production `ClockDomain` constructs this record
immediately; the existing timer planner and all host clock methods consume
it through the same projection methods. There is no second transformation
implementation. Mode and duration storage are private, reserved and unused
fields are zero, and constructors preserve the full `Duration` range and
raw rational factors. In particular, zero denominator and zero numerator
retain their previous use-time guards; this is not a clock-policy change.
Size, alignment and every field offset have compile-time assertions.

The layout binding failed on the prior enum (32 bytes rather than 56).
Existing projection tests still cover frozen realtime/live monotonic,
creator-origin scaling, signed offsets, deterministic progress and one-sample
deadline planning. Additional record bindings cover canonical unused fields,
full-range frozen/deterministic values and a retained zero denominator.
The independent design review approved this representation prerequisite,
subject to preserving those properties. No unsafe or raw-byte import exists.

This record is not a published IPC ABI. Embedding it still needs versioned
validation, a retained generation-authenticated creator-domain handle,
calibrated native origins and atomic publication/enrollment. Timer storage,
arm revisions, expiry delivery, deterministic waiter participation and final
release still need migration to one shared authority. The Temporary timerfd
crossings remain; root and child constructor acceptance remains open. No
signed ARM, x86 runtime or Go-workload result follows from this refactor.

## Completing migration: interface review

Independent design inspection of the finishing brief confirms that constructor
routing cannot be separated from timer lifetime and clock publication. The
existing production owners that must move together are:

| Current owner | Required shared owner |
|---|---|
| `kernel/container.rs::ClockDomain` | Retained clock record with an authenticated generation, projection, calibrated native origins and clock-change publication |
| `dispatch/fd_table.rs::TimerFdInner` | IPC timer object holding the creator-clock handle, selected clock, `State` and nonwrapping arm revision |
| `dispatch/format_time.rs::timerfd_plan` | One clock snapshot followed by timer refresh and a generation-bound deadline plan |
| Host timer/clock subscriptions | Enrollment validated against object generation, arm revision and clock generation |
| `ipc.rs::IpcBacking` and object store | One timer backing used by both host and ring, with authenticated ABI identity updated |

The host wrapper must retain the shared timer object rather than keep a second
mutable timer state. A clock handle retains the creator domain across fork,
exec and descriptor transfer; a current-task domain or a raw architecture
counter is not a substitute. Distinct native realtime, monotonic, boottime
and domain-elapsed origins are needed for the existing projection policy.

The lock order is clock snapshot, then timer/member, then epoll where needed.
Enrollment must recheck the captured generations so a clock change in the
snapshot-to-subscribe gap cannot disappear. Rearm and final release cancel
only their exact deadline tickets; a stale callback cannot affect a reused
object. Notifications happen after unlocking. Deterministic clocks retain
their waiter participation, not only their virtual-time sample.

Before removing the three Temporary timerfd crossings, production bindings
must additionally cover clock changes during enrollment, rearm/release/reuse
against stale expiry, two-live-task creator isolation, scaled origins, frozen
realtime with live monotonic time, and deterministic advancement. The existing
constructor bindings cover immediate expiry only. Their passing alone would
not prove future expiry or blocking-reader/epoll wakeup correctness.

This review adds no timer service, ABI record or crossing-policy change. The
two native constructor failures remain acceptance blockers; this branch is
not ready to land as a completed timerfd migration.

## Configured zone ceilings

The root and forked native child use the same immutable region ceilings.
`IpcRegion::initialize` publishes object and description ceilings before the
initialized header; growth callers supply only their observed population.
As before, stores grow in whole segments and always publish the first
segment. The directory clamps configuration to that first segment and the
absolute maximum. Its layout facts include both configuration words, feeding
`IPC_LAYOUT_HASH` and the computed `EL1_ABI_LAYOUT_HASH`.

The production native-child `pipe2` witness exhausts a one-segment object
ceiling through host admission while retaining its objects, then requires
errno 23 (ENFILE), without allowing region growth. Before the fix, the child
returned 0 instead of -23. The corresponding root constructor witness uses
the same configured population and requires the same errno. Shared ABI tests
exercise both object and description growth and a stale observation at the
configured ceiling. These prove bounded admission, not signed execution.
