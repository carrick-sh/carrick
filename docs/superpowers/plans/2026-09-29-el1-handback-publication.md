# Batch-3 ownership publication repair

This is implementation detail for task A of the accepted EL1 completion
controller, not a new goal or a reduced definition of completion. Source
inspection starts at `26874b0b2`; the two host reds are retained in
`docs/perf-results/2026-09-29-el1-batch3-resume/host-publication/`.

## Invariant and evidence

A runnable record must have a finished context/result and no remaining old
wait-queue entries. A producer must retain exclusive mutation authority until
that publication. Cancellation may request retirement during a transfer but
must not free/reuse the record under its producer. A delayed notification
keeps the original RecordRef. No new global lock, polling continuation,
capacity increase, serialized workload or timeout extension is allowed.

The host red proves old-producer mutation of a replacement parked waiter.
A further guest-path red observes one old futex entry when the target consumes
a placed waiter. Guest placement and host handback are separate publication
boundaries in the same wake operation; correcting only either one is not
full closure. Neither witness attributes the historical Python/otmp failures.

## Ordered implementation

1. Complete guest wake cleanup before releasing the existing destination
   queue lock. Both `claim_for_el1` (own and remote slot) and `wake_host`'s
   `place_in_guest` path must unlink before target consumption. Preserve
   placement decisions, wake counts, same-lock ordering and bounded guest
   behavior. The guest publication witness runs at 1/8/32 waiters.
2. Add an explicit producer-owned transfer state and a non-copyable transfer
   token, shared by all host-bound producers. Publishing Host is the last
   record operation, after result/context/queue cleanup. Cancellation during
   transfer must atomically delegate retirement to the producer, not return
   AlreadyHost. A pending signal/control wake must remain owed without
   polling and be delivered by the completing producer. Do not clear an
   out-of-band flag after publishing Host: that is another stale write.
3. Convert wake batches and callbacks that cross a bucket-lock release into
   owned pending transfers. Multi-futex cleanup happens only after releasing
   the original bucket (and both requeue buckets), then consumes the token
   to publish readiness or retire. A callback receiving a ready RecordRef
   must have no producer record mutations after it. No token may silently
   become a bare-ID readiness operation.
4. Audit exact retirement and restore admission too: `live()` is a snapshot,
   not a lease. Host/free/reuse must not race a later field read, write or
   raw-index free. Authenticate incarnation together with the ownership
   transition; avoid a check-then-act test followed by an unauthenticated CAS.
   Preserve sequence exhaustion behavior explicitly when relying on a park
   sequence to distinguish allocation reuse.
5. Apply the retained host witnesses as ordinary regression tests, add
   cancellation-before/during/after publication and positive wake controls,
   including multi-entry waits and two live threads. Bind deterministic work
   observations. Run lower layers, fresh signed gates and controller A's
   complete workload/probe gates; keep historical attribution separate.

## Producer and consumer census

| Producer | Outstanding publication work to protect |
| --- | --- |
| `alloc_host_runnable` | Private allocation and initial result/kind publication; verify no observer obtains it early |
| `take_service_head` | Queue removal and kind reads after the Host CAS |
| `take_host_wanted` | Queue removal, host-request clearing and handback kind |
| `sweep_cancelled` | Queue removal and retirement; no intermediate public Host needed |
| `wake_placed` host arm | Result, kind, source entry unlink, remaining waitv entries |
| `drain_slot` | Kind, discard decision, queue links and callback boundary |
| `handback_current` | Context already captured; cancel/kind publication and caller discard ownership |
| `relocate` fallback | Detached source queue record, kind and discard callback |
| `wake_host` fallback | Result/kind, callback before source unlink, then caller's waitv cleanup |
| `claim_for_host` | Park unlinking or queued removal/kind, plus outer host-request clearing |
| Guest wake/placement | Futex unlink before releasing destination queue lock |

Host consumers include `el1_zone::{cancel,is_host_owned,wake,requeue}`, runtime
executor adoption/restore, continuation `zone_event_admitted`, and thread
control wake/blocked settlement. A new pending-transfer result must defer
readiness in all of them. The completing producer must still publish the
owed wake; merely returning a new busy result would introduce lost wakes.

`relocate` currently detaches batches while keeping Queued, so a claimant
retries a missing queue member. Transfer ownership must cover that interval
as well; do not introduce another detached-but-publicly-owned state.

## Acceptance limits

Step 1 alone is a preparatory correction, not repair of the host red.
Green scheduler-core/EL1 host tests do not replace signed proof. Existing
signed receipts at `40a707ba0` belong to that source and cannot certify this
changed implementation. Full controller A and later B-E obligations remain.

## Implementation checkpoint after guest publication preparation

The next branch change introduces producer-owned Transferring claims, with
atomic host-request and cancellation states. A non-copyable HostTransfer
carries cleanup authority through wake callbacks/batches; finish consumes it
only after bucket locks are released. WakeRecord distinguishes complete guest
notifications from pending host cleanup. Readiness/control consumers defer
while a producer owns the transfer. Detached relocation batches retain the
same token and honor a host request before guest placement. Current-record
retirement now happens in the producer, so the runtime does not free it again.
The shared ABI hash includes the new claim encodings.

The original two host reds are now ordinary tests. The cancellation witness
expects the completing producer to report Stale when cancellation won, and
also verifies the record is retired and the slot reusable; this is a changed
ownership result, not removal of the replacement-corruption assertion. The
old branch of the witness still detects removal of a replacement queue entry.
Additional tests cover waitv cleanup with cancellation and a pending host
request, plus transfer-to-guest refusal when a control request wins.

This is not final lifecycle acceptance. Continue step 4 before promotion:
- Audit/rework public raw-index free and context/identity reads after a live
  check, including take_unplaced_service, cancellation after public Host,
  runtime adoption/restore, and discard callbacks that still transfer a
  ready reference plus a separate free decision.
- OnCpu cancellation now records intent before returning El1Held; deferred
  cancellation/host-request words are bound to non-wrapping incarnations.
  The handback-before-follow-up and delayed-write/reuse reds pass. Continue
  auditing owner-side clearing and public Host consumption boundaries.
- Park sequence wrap behavior is unchanged; do not assume it provides an
  unbounded incarnation guarantee for a later ownership CAS.
- Complete exact scheduler handback wake targeting, deterministic signed
  bindings, structural observations, historical attribution and all A gates.
The restored VM-free witnesses establish the named producer-cleanup boundary;
they do not prove those remaining lifetime boundaries.


### Restoration ownership evidence to carry forward

Source inspection: RunnableTask borrows ThreadExecutionLease. Claiming the
thread moves its boxed blocked continuation out of the thread record into
that lease; ZoneWait is non-Clone and its Drop is the cancellation producer.
This protects the normal loader from concurrent destruction of that same
continuation, but does not by itself prove all producer/service paths safe.
Backend load and wait_for_materialized can call materialize_zone, which still
checks live+Host before copying context. Service records are distinct from
ZoneWait records; settle_vacated only re-places Service records. Audit those
ownership classes separately before adding or claiming a universal read lease.


## Re-park request boundary (red at fb265ba9b)

The actual EL1 wait_word path can erase an admitted OnCpu host request:
B parks after the request and is no longer current or queued at host exit.
Two live-thread witnesses fail for cancellation and signal, retained in
`docs/perf-results/2026-09-29-el1-batch3-resume/repark-requests/`.
The next change must atomically arbitrate park admission against the host
request and audit all OnCpu transitions; see that receipt for the proposed
claim-protocol correction and required controls. The existing tagged request
fix remains useful but does not close request lifetime across re-park.
