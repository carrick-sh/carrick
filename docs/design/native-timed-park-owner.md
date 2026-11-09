# Native timed parks across executor departure (#1862)

Status: implemented in PR #1894; VM-free and build evidence is recorded on
that draft PR. Signed acceptance, smoke and the Go workload remain director
work. This note describes the owner and its runtime serving obligation.

## Original ownership gap

`carrick-kernel/src/el1_zone.rs::hand_back_foreign_timer` calls
`ZoneTables::take_foreign_timer` before requesting `Handback::Control`.
The index removes the lease; Control removes the original futex enrollment.
The successful native futex park has already dropped its relative-wait
operation. Native return routing cannot reconstruct that enrollment without
losing wake atomicity. The record's deadline value surviving is insufficient.

`ZoneTables::expire_timer` currently selects a slot heap and queues the
winner on that slot. `reset_slot` requires an empty timer heap. Merely
excluding native records from `take_foreign_timer` fails slot reset and
leaves the hardware timer unserved while its executor is away. Moving all
native timers to a shared heap also needs a server when every vCPU is away;
a timer armed on some other current vCPU is not a lifetime guarantee.

## Neutral owner and state machine

The semantic owner is the exact zone record, not a vCPU or host continuation.
`NativeTimedPark` in `carrick-sched-core` contains authenticated
`RecordRef`, park sequence, original counter deadline and a neutral completion
kind. The completion kind distinguishes scalar result from object timeout;
Linux supplies the scalar timeout value at futex admission, through the
existing neutral scheduler transport. The descriptor is an authenticated view
of the index ticket and record, rather than a second copy of park state.
Index storage remains bounded to one
node per admitted record. Its serving authority is a typed enum:
`SlotTimer(SlotId)` or `CarrierDeadline`, never an unauthenticated slot number.
The parked record keeps the node through serving-authority transfer.

State transitions:

1. Reserve the record-owned node before enrollment. Publish enrollment,
   deadline and Parked claim under the existing wait-queue protocol.
2. On departure, transfer the node from SlotTimer to CarrierDeadline without
   changing the Parked claim, futex linkage, sequence, saved result or PC.
   Publishing the carrier driver's notification is part of this transfer;
   the departing slot cannot become reusable before durable admission.
3. A normal wake and expiry compete on the same Parked sequence. The winner
   removes enrollment and timer exactly once and publishes native runnable
   custody. It never asks for Control or fabricates a host syscall continuation.
4. Expiry publishes the already-decided scalar result, or the existing object
   expired marker for epoll's retained operation. Dispatch is not replayed for
   scalar futex completion. Object operation resumption preserves its token.
5. Cancellation consumes the same node; stale generation/sequence receipts do
   nothing to a reused record. Slot reset and home-record settlement cannot cancel CarrierDeadline nodes.
6. The driver takes the existing non-refusing host short-lock path. After
   the Parked CAS wins, a `HostTransfer` owns cleanup through contention;
   no ticket can be abandoned as Busy and no guest executor lease is held.
   The contended-cleanup test holds the original bucket, observes that exact
   transfer awaiting release, then checks one completion and zero nodes.
   No new fallible refusal arm, deadline retry or guest Busy errno is added.

The implemented detail differs from the proposal at expiry: arbitration
uses the existing Parked-to-HostTransfer CAS before cleanup, rather than
acquiring the wait queue before the CAS. This reuses the scheduler's exclusive
cleanup authority, closes cancellation/reuse during unlink, and avoids a new
Busy retry protocol. Wake uses the same Parked sequence, so its competing CAS
still decides the one winner; native readiness is published only after cleanup.
The index lease is cancelled by the winning transfer, or the final guest wake
unlink, never by mere executor departure.

The carrier driver's work is deadline delivery, not Linux syscall handling.
It must remain armed with zero active guest slots and wake the existing native
executor admission path on completion. Its sleep is bounded by the earliest
original deadline and interrupted by earlier insertion/cancellation/shutdown.
Do not create a thread or host readiness pipe per guest park.

## Files and integration obligations

- `carrick-sched-core/src/timer_index.rs`: serving-owner type, exact-node
  transfer, minimum deadline and cancellation for carrier-owned nodes. Avoid
  allocation or a full record scan per timer event.
- `carrick-sched-core/src/lib.rs`: record-owned timed-park transition; factor
  expiry arbitration from slot placement so a stopped slot is never treated
  as the execution owner. `reset_slot` checks only its actual obligations.
- `carrick-sched-core/src/object_wait.rs`: retain object timeout semantics
  through the same owner; no epoll-specific timer implementation.
- `carrick-kernel/src/el1_zone.rs`: carrier deadline delivery and
  authenticated delivery into native readiness. Adapt the existing
  `HandbackEvent::NativeQueued` notification; do not route through host waits.
- Shared runtime carrier lifecycle: start/stop the driver with zone lifetime,
  retain the mapping through callback completion, and drain cancellation
  before unmapping. Counter-to-host-clock conversion needs a typed calibrated
  source: an ARM counter tick and an x86 counter tick are not nanoseconds.
- ISA code supplies only clock mechanics. Both departure call sites already
  share `hand_back_foreign_timer`; neither backend chooses semantic ownership.

The index lock must never be held across wait-queue acquisition, driver sleep,
executor admission or notification callbacks. Expiry authenticates the exact
incarnation/sequence at the Parked CAS, then cleans up under the original queue
while retaining its exclusive transfer. Transfer and cancellation
must share a linearization point so neither can remove a replacement lease.
This ABI/layout and cross-crate lock protocol needs independent review before
claiming an integrated implementation is safe.

## Required proof

Keep the existing production fork/exec/clone timeout witnesses and add their
wake variants. Both retain two live threads; the sibling executes gettid before
carrier exit/reset. Require original-deadline expiry, no early expiry, one
resolution, zero timer nodes, native result -110 or 0, and a later timeout that
cannot replace a wake winner. All four fail at native custody on the original
implementation and reach those final assertions with this owner. The fixture
settles gettid's completed boundary before rebinding the sibling, matching
carrier return-work settlement rather than skipping pending work.

Add deterministic neutral schedules for Busy then release/success, simultaneous
wake/transfer/expiry, cancellation with record reuse, every slot departing,
expiry with no running vCPU, and driver shutdown while a callback is admitted.
A test that manually calls expiry with the deadline proves arbitration only;
it does not prove a live driver will ever call it.

The same owner covers native epoll object timers. The departure/notification
witness first failed with zero admitted nodes on the original head; the
expiry witness requires the original deadline, one retained operation, the
expired marker, empty enrollment and zero timer nodes before record retirement.
This is neutral object-owner evidence, not a signed epoll workload claim.

## Runtime driver and clocks

The base contains no carrier-lifetime server for abandoned slot timer nodes:
`IpcCounterDeadline` supplies retained operation metadata; the idle/hardware
timer path only serves live slots. Host-owned records instead have a host
continuation which owns the remaining wait. Neither can serve a native park
with every executor away.

`carrick-runtime::deadline_driver` factors a shared Condvar deadline driver
using the lifetime/wait/shutdown discipline inspected in #1836. It sleeps on
the minimum of the same neutral heap and owns no second timer inventory.
Transfer notifies it before returning from the departure boundary. Earlier
insertion interrupts the sleep; cancellation can leave an obsolete earlier
sleep, which is harmless and pruned on wake. Shutdown interrupts sleep and
joins an admitted callback before releasing the target's mapping custody.
The runtime target retains the persistent executor factory authority, whose
Arc owns the carrier mappings. Startup failure drops and joins the driver guard; its published doorbell
retains only inactive notification state, never the mapping target.

The HVF binding samples host monotonic ticks, the same epoch and timebase as
its guest CNTVCT, and validates a nonzero host TickScale before starting the
worker. A missing scale refuses carrier startup through RuntimeError; a failed
worker join also returns through that existing error owner, without new abort
sites. Residual conversions round upwards to avoid a zero-duration poll. No nanosecond
interpretation is applied to a guest TSC. The shared driver accepts a target
which supplies its calibrated remaining time and exact expiry; KVM/CPL0 can
use that same neutral owner without copying a syscall state machine. The
existing KVM persistent-runtime seam and x86 timed-futex routing (#1899)
remain open; this PR does not claim to close those existing gaps. The real
KVM entry gate verifies the current CPL0 image, not an unbound runtime driver.

The live-driver unit witness uses an explicit nanosecond counter calibration,
real neutral futex enrollment and heap transfer with every slot stopped. Only
the worker thread calls expiry; it must deliver one original-deadline result,
clear enrollment and free the node. A separate admitted-callback shutdown
witness checks the join obligation.

## Nanosleep and #1836

Implemented by #1836 on this owner. A native child's sleep is the
`rt_sigtimedwait` member wait with nothing to wait for: it parks with
`PendingSignalKind::Sleep`, leases its record's timer node through
`arm_park_timer`, and therefore uses this note's departure transfer and
carrier deadline driver unchanged. The scalar timeout result is 0; the
resumed owner runs the sleep's own complete decision (`sleep_until`): the
deadline, then a deliverable signal (EINTR, with `rem` written as a retained
`OwnedCopyout`), then a re-park on the same deadline. It never reaches the
`rt_sigtimedwait` result path. The clock-resource sleep
subscription and its host worker were removed, so one owner serves every
native timed park. `crossing.rs` keeps nanosleep/clock_nanosleep as
Permanent crossings for the run root only; children never reach them.
