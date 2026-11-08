# Native timed parks across executor departure (#1862)

Status: proposed, not implemented. PR #1894 still has the confirmed P0.
The departure and slot-reset timeout witnesses remain acceptance blockers.
This note does not claim that preserving a node alone fixes the hang.

## Confirmed ownership gap

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

## Proposed neutral owner and state machine

The semantic owner is the exact zone record, not a vCPU or host continuation.
Add `NativeTimedPark` in `carrick-sched-core`, containing authenticated
`RecordRef`, park sequence, original counter deadline and a neutral completion
kind. The completion kind distinguishes scalar result from object timeout;
Linux supplies the scalar timeout value. Index storage remains bounded to one
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
   nothing to a reused record. Slot reset cannot cancel CarrierDeadline nodes.
6. Busy retains the owned operation and notification obligation. Release of the
   actual contended queue/placement authority wakes the retry. No deadline
   restart, periodic polling, timeout increase or guest-visible Busy errno.

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
- `carrick-kernel/src/el1_zone.rs`: carrier-lifetime deadline driver and
  authenticated delivery into native readiness. Adapt the existing
  `HandbackEvent::NativeQueued` notification; do not route through host waits.
- Shared runtime carrier lifecycle: start/stop the driver with zone lifetime,
  retain the mapping through callback completion, and drain cancellation
  before unmapping. Counter-to-host-clock conversion needs a typed calibrated
  source: an ARM counter tick and an x86 counter tick are not nanoseconds.
- ISA code supplies only clock mechanics. Both departure call sites already
  share `hand_back_foreign_timer`; neither backend chooses semantic ownership.

The index lock must never be held across wait-queue acquisition, driver sleep,
executor admission or notification callbacks. Expiry authenticates its snapshot
under the original wait queue before committing. Transfer and cancellation
must share a linearization point so neither can remove a replacement lease.
This ABI/layout and cross-crate lock protocol needs independent review before
claiming an integrated implementation is safe.

## Required proof

Keep the existing production fork/exec/clone timeout witnesses and add their
wake variants. Both retain two live threads; the sibling executes gettid before
carrier exit/reset. Require original-deadline expiry, no early expiry, one
resolution, zero timer nodes, native result -110 or 0, and a later timeout that
cannot replace a wake winner. The added wake witnesses are red until the owner
exists; their later assertions are not yet execution evidence.

Add deterministic neutral schedules for Busy then release/success, simultaneous
wake/transfer/expiry, cancellation with record reuse, every slot departing,
expiry with no running vCPU, and driver shutdown while a callback is admitted.
A test that manually calls expiry with the deadline proves arbitration only;
it does not prove a live driver will ever call it.

Only after futex is green, add the epoll_pwait timeout-drain witness and retain
its operation token through this owner. Nanosleep has not been implemented in
this round. The director identified PR #1836 / #1808 as the existing lane; read
and reuse that work before any implementation. It is not absorbed here.
Nanosleep needs a native operation carrying selected clock, absolute/relative
mode, original deadline and remaining-time output on interruption. Routing
changes in crossing.rs and the flip table remain director-owned. No proposed
routing diff has yet been validated against #1836.

### Inspection of #1836

Fetched `work/1808-arm-nanosleep` and inspected its clock-service, sleep owner
and zone wake changes. It provides a container-scoped `ClockResourceService`
with a Condvar-driven timer hub and a non-Copy `NativeSleep` that retains its
subscription through arm/cancel ACKs. Reuse that driver infrastructure rather
than introduce another host timer thread mechanism. It is not absorbed in this
round: its wake channel notifies `native_service` and wakes a synthetic futex
address; it does not authenticate or expire the original timed-futex park
sequence, transfer the existing timer-index node, or preserve futex wake XOR
timeout arbitration. Adapting it needs a neutral exact-park deadline target,
not a call to `wake_native_sleep_channel` for the user's original futex address.
Its existing remaining-time and absolute-sleep owner tests are relevant to the
later nanosleep step, after the timed-futex owner is fixed.
