# Identity-Aware vCPU Lease Drain Design

**Date:** 2026-08-28  
**Status:** Approved in chat; implementation not yet started  
**Controller:** [`../../runtime-abstraction-audit-2026-08-27.md`](../../runtime-abstraction-audit-2026-08-27.md), Part 2 item 3; [`../../identity-and-scope-domains.md`](../../identity-and-scope-domains.md), item 1

## Goal

Delete `VcpuRegistry::count() -> usize` and replace every correctness decision
that means "have all sibling vCPU leases drained?" with a typed, identity-aware
freeze capability. The capability must both witness an empty sibling set and
prevent a lease-less sibling from registering until the protected operation
releases it. Make membership and freeze changes their own subscribable
publications so neither a drain waiter nor a registration waiter can sleep
forever.

This change does not redefine the other runtime populations:

- Durable task membership remains the authority for whether the process-fork
  and crash barriers must be raised.
- `GuestExecutorCensus` remains the authority for page-table-pause observability
  about a peer loop that can return to guest.
- `VcpuRegistry::any_other_in_guest` remains the authority for whether a
  page-table edit has drained all sibling guest execution.
- `CrashQuorum` remains the authority for whether every live crash participant
  has published or withdrawn its register vote.
- Task membership and scheduler state remain logical-lifecycle facts, not vCPU
  lease facts.

## Problem

The process-fork and crash-memory-snapshot drains currently use
`kicker.count() > 1`. That comparison assumes the caller owns one of the
registrations. Both current call sites normally execute while the caller is
registered, so an absent-caller false completion is a structural hazard rather
than a reproduced failure on those exact paths. Carrick nevertheless releases
and reacquires registrations across blocking waits, reclaim, rebind, exec, and
terminal transitions. A correctness API must encode the identity invariant
instead of relying on every present and future caller to preserve it.

The operation asks the wrong shape of question: it needs to exclude one exact
`ThreadId`, identify a remaining sibling, and keep new sibling registrations
closed through the protected operation. A momentary identity poll is
insufficient: after it returns `Complete`, an existing blocked sibling can be
scheduled and reach the sole production `register_vcpu` call before its later
process-quiesce check. Clone admission blocks new clones, not re-registration of
an existing thread.

The existing asynchronous fork retry has a separate wake problem: it subscribes
to `QuiesceBarrier` progress, but terminal and exec paths can unregister without
publishing that progress. Subscribe-before-poll cannot close a wakeup that the
membership owner never publishes.

## Chosen architecture

Add identity diagnostics, an RAII freeze witness, and two registry-owned,
object-safe enrollments to `carrick-hal` (names are normative; private storage
details are not):

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VcpuLeaseDrainPoll {
    Complete,
    Waiting(ThreadId),
}

pub struct VcpuLeaseChangeSubscription {
    // opaque, cancellation-on-drop registration
}

pub enum VcpuLeaseDrainEnrollment {
    Frozen(VcpuLeaseDrainGuard),
    Waiting {
        tid: ThreadId,
        subscription: VcpuLeaseChangeSubscription,
    },
    Busy {
        owner: ThreadId,
        subscription: VcpuLeaseChangeSubscription,
    },
}

pub enum VcpuRegistrationEnrollment {
    Registered,
    Waiting {
        owner: ThreadId,
        subscription: VcpuLeaseChangeSubscription,
    },
}

pub trait VcpuRegistry: Send + Sync {
    fn subscribe_lease_drain(
        &self,
        except: ThreadId,
        callback: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> VcpuLeaseDrainEnrollment;
    fn poll_lease_drain(&self, except: ThreadId) -> VcpuLeaseDrainPoll;
    fn subscribe_register(
        &self,
        tid: ThreadId,
        handle: Box<dyn VcpuKickDyn>,
        in_guest: &InGuestFlag,
        callback: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> VcpuRegistrationEnrollment;
}
```

`GenericVcpuRegistry::poll_lease_drain` locks the registration map once,
excludes `except` by exact identity, and returns the lowest remaining
`ThreadId` for deterministic diagnostics. It re-reads live membership on every
call. It never snapshots a population across a wait and never returns a scalar
that a caller can compare.

`subscribe_lease_drain` locks the same state. If a sibling registration exists,
it returns the deterministic lowest identity and atomically enrolls a one-shot
membership-change callback. If none exists, it installs a freeze owned by
`except` and returns `VcpuLeaseDrainGuard`; observation and registration closure
are one transaction. Only the exact owner may register while the guard lives.
If any freeze already exists, including one with the same owner identity, it
returns `Busy` with a one-shot freeze-release subscription. It never mints two
independent guards: dropping either one would otherwise thaw registration while
the other still witnessed exclusion. The process barrier serializes today's
fork and crash consumers, but the trait encodes contention and accidental
same-owner reentry instead of treating either as impossible.

`subscribe_register` atomically either publishes the registration or, when a
different identity owns the freeze, enrolls a one-shot callback for freeze
release without publishing the entry. It consumes the kick handle in either
case; a resumed attempt mints a fresh handle from its current engine. This makes
the registry, not a later run-loop check, the registration-admission authority.

A successful key-set mutation advances membership generation and claims the
current membership-drain listeners. Dropping the drain guard clears its exact
freeze and atomically claims both `Busy` drain listeners and registration
waiters. Each path releases the lock before invoking callbacks. Replacing an
existing registration under the same `ThreadId`, or unregistering an absent
identity, does not publish a false membership change.
The subscription removes its still-unclaimed listener on drop. A callback
already claimed under the state lock may run after subscription drop; that
exact-thread scheduler wake is permitted and harmless because every wake
re-polls authority. No callback runs under the registry lock.

The private registry state is held behind `Arc`, allowing opaque subscriptions
and the guard to carry `Weak` cancellation/release handles while the public
trait remains object-safe.

The infallible `VcpuRegistry::register` and scalar `count` operations are
deleted from the trait and every implementation.

## Data flow

### Process-fork lease drain

The order is:

1. Win process-fork and clone-admission authority.
2. Raise quiescing when durable task membership contains a sibling.
3. Call `subscribe_lease_drain(this_tid, wake_current_task)`, which polls and
   either enrolls in membership change or freezes sibling registration
   atomically.
4. On `Waiting { tid, subscription }`, kick siblings, notify futex/signal
   waiters, and return the existing retry object carrying that exact registry
   subscription. On `Busy { owner, subscription }`, return the same retry shape
   without inventing membership.
5. On `Frozen(guard)`, carry the guard through the fork's protected memory and
   topology work.
6. Lower the process barrier first, then drop the guard. Guard drop wakes exact
   registration waiters only after guest execution is admissible again.

The enrollment replaces the `count() > 1` decision and its mismatched
quiesce-progress subscription. `ProcessForkCoordinator` owns the guard after
acquisition and its explicit teardown enforces barrier-before-thaw ordering on
success, cancellation, and error. Durable task membership continues to decide
whether the barrier is raised, including for a blocked lease-less sibling.
Quiesce-progress publication remains for its existing barrier-specific users;
it is no longer lease-membership authority.

### Registration admission

The sole production registration path changes from an infallible
`register_vcpu` to an atomic `subscribe_register` enrollment:

1. Enter `GuestExecutorCensus` exactly where production does today, before any
   registry publication. This ordering prevents a page-table mutator from
   observing no peer executor between registry admission and census admission.
2. Call `subscribe_register` with an exact scheduler wake callback. There is no
   new unconditional process-barrier precheck at this point.
3. On `Registered`, publish the thread port and continue through the existing
   production phase and quiesce checks.
4. On `Waiting { owner, subscription }`, retain the subscription in a dedicated
   `registration_wait` sidecar field, not in `HvpatchProductionPhase`, and
   suspend without publishing a registration. The ordinary suspension path
   drops the just-entered census participation.
5. On wake, clear/drop the sidecar and retry census plus registry enrollment;
   the existing production phase is untouched.

The sidecar is required because a registration freeze may meet any existing
phase (`ResumeBlocked`, `RetryCloneThread`, terminal drain, or another state)
and must not overwrite its payload. In particular, a `RetryProcessFork` with
`coordinator: Some` suspended while retaining the raised barrier and then
unregistered. An unconditional barrier precheck would park that exact owner
waiting for a release only it can perform. Registry admission instead permits
the owner to re-register while no freeze exists, resume its host-side drain,
and acquire the freeze once siblings are absent. After a freeze is minted,
`subscribe_register` atomically forbids every non-owner publication; no later
barrier check is relied upon to close that race.

### Crash memory-snapshot lease drain

After the fatal thread raises the barrier and publishes its own register vote,
an extracted drain helper receives a `CrashLeaseDrainBudget` containing the
deadline and polling interval. Production passes the current ten-second and
200-microsecond defaults; tests pass a short deterministic budget.

1. Attempt `subscribe_lease_drain(this_tid, wake_crash_waiter)`.
2. On `Waiting { tid, subscription }`, kick and wake the existing channels,
   sleep for the configured interval, drop the obsolete subscription, and
   re-enroll against live membership.
3. On `Busy { owner, subscription }`, wait through the same bounded helper and
   report the conflicting owner if the impossible-at-present contention times
   out.
4. On timeout, make one final `poll_lease_drain` and report the exact waiting
   `ThreadId` rather than a derived "remaining count".
5. On `Frozen(guard)`, retain both the guard and crash barrier through
   `prepare_core_snapshot`, the full `CrashQuorum`, process-state capture, every
   live `read_core_bytes` region read, and construction of the owned core bytes.
   `prepare_core_snapshot` initializes a live page-table observer; it does not
   copy or freeze guest memory, so releasing after that call is unsound.
6. After the existing result-producing closure has finished all live reads,
   call `authority.stop_collecting()`, lower `end_quiesce`/`end_fork`, and only
   then drop the guard. Guard drop wakes both competing drain subscribers and
   registration waiters.

This freeze does not replace `CrashQuorum`: lease drain authorizes memory
coherence; the quorum authorizes the thread-register inventory.

### Page-table pause observability

`acquire_pt_pause` already drains with `any_other_in_guest(tid)`, which is the
correct predicate and remains unchanged. Its `pt-pause-begin` probe currently
emits `(tid, others_in_guest, leases, executors)` and obtains `leases` through
the raw count API being deleted.

Change the probe ABI to:

```text
(tid, others_in_guest, waiting_vcpu_tid, executors)
```

`waiting_vcpu_tid` comes from a pure mapper over `VcpuLeaseDrainPoll`: `0` for
`Complete`, or the exact `ThreadId::raw()` from `Waiting`. The live probe calls
that mapper. Update the probe declaration, wrapper/stub, source-contract tests,
comments, and `scripts/dtrace/hvpatch-stop-the-world.d`.

The new, deliberately narrower measurement is
`waiting_vcpu_tid == 0 && executors > 1`: a peer executor exists but no sibling
owns a lease. Rename the DTrace counter and output to say exactly that. It is
not equivalent to the historical `leases <= 1` predicate: an absent caller plus
one registered sibling produced `leases == 1`, while the identity poll correctly
returns that sibling. The old metric is retired rather than silently relabeled.

`scripts/dtrace/hvpatch-fork-wait-amplification.d` counts probe firings without
reading these arguments and needs only an ABI-header audit, not a predicate
change.

## Why adjacent populations are not substitutes

### `GuestExecutorCensus`

The census is the transient population of loops currently admitted to an
executor quantum: `suspend()` calls `leave_executor()`, which unregisters the
vCPU and drops census participation, and the next poll re-enters both. It is
useful for page-table-pause observability at an admitted call site, but it does
not include blocked loops and is not durable task membership. It therefore
cannot authorize a process-fork/crash barrier raise or substitute for the exact
registry membership being frozen.

### `QuiesceBarrier` progress and `ThreadExecutionState`

The barrier publishes progress when a sibling suspends specifically for process
quiescence. A loop can instead unregister in `finish`, `leave_executor`, exec,
or terminal handling without that publication. Scheduler state also settles on
a different timeline. Neither channel is the owner of lease membership, so
neither can provide the wake contract for a lease drain. The registry-native
generation advances at the actual key-set mutation.

### Task membership or `ProcessDrain`

Task membership includes published loops that have not started or have been
cancelled. `ProcessDrain` tracks logical-job completion. Neither represents
live vCPU registrations.

## Error handling and invariants

- `VcpuLeaseDrainPoll::Complete` is diagnostic only: no registration differs
  from `except` at that instant. It never authorizes protected work.
- `VcpuLeaseDrainEnrollment::Frozen` is the authorization witness: no sibling
  was registered when it was minted, and no non-owner registration can publish
  until it is dropped.
- A missing caller does not weaken the predicate; any registration is then a
  sibling and yields `Waiting`.
- Callers re-poll after every wake because unregister/re-register may change
  membership between observations.
- A fork retry owns exactly one registry subscription. Dropping or replacing
  the retry cancels an unclaimed listener. A callback already claimed under the
  registry lock may still perform a harmless exact-thread wake.
- A registration waiter owns exactly one freeze-release subscription and
  publishes no registration before retry succeeds.
- Registration wait storage is sidecar state and never replaces, consumes, or
  fabricates the thread's existing `HvpatchProductionPhase`.
- Census participation is entered before registration enrollment and is
  dropped on denied admission, preserving the page-table-pause raise ordering.
- Any extant freeze makes a new drain enrollment `Busy`, even for the same
  owner. Freeze guards are unique and non-refcounted.
- The barrier is lowered before the drain guard is dropped on every path, so a
  thawed registration cannot outrun process quiescence release.
- Every successful membership removal publishes after removal, including
  quiesce, blocking-wait, reclaim, exec, and terminal unregister paths.
- Registry callbacks execute after releasing the registry lock and may safely
  re-enter scheduler code.
- No raw count, subtraction, cached snapshot, wildcard identity, or task-size
  fallback is permitted in a drain decision.
- Poisoned registry mutex recovery remains unchanged.
- Fork cancellation and crash timeout behavior remain bounded and typed as
  today; timeout text gains exact waiting identity.

## Files

- `crates/carrick-hal/src/threaded.rs`: result types, guard, trait operations,
  generic membership/freeze publications and subscriptions, deletion of
  `register`/`count`, and unit tests.
- `crates/carrick-hal/src/lib.rs`: re-export the drain poll, drain enrollment,
  guard, subscription, and registration enrollment types.
- `crates/carrick-hal/src/pump_fork_coord.rs`: test registry implementation.
- `crates/carrick-hal/src/timer_delivery.rs`: migrate the direct test
  registration to the admission API.
- `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`: process-fork enrollment and
  page-table probe ABI call.
- `crates/carrick-runtime/src/vcpu_loop/threads.rs`: replace the sole production
  infallible registration wrapper with the typed admission enrollment.
- `crates/carrick-runtime/src/vcpu_loop/mod.rs`: crash lease-drain poll and
  exact timeout identity, registration-admission retry phase, and the
  `kicker.count()` authority comment.
- `crates/carrick-runtime/src/lib.rs`: update the production blocking-wait
  authority comment that says the kicker count drains to one.
- `crates/carrick-runtime/src/kernel/guest_execution.rs`: replace rustdoc that
  names a scalar lease-count drain with the identity enrollment.
- `crates/carrick-thread/src/fork_quiesce.rs`: update the hermetic fake-kicker
  COUNT contract and stress fixture to the identity-aware drain protocol.
- `crates/carrick-vmm-kvm/src/kvm_kicker.rs`: migrate direct count bookkeeping
  tests to identity polls and membership-change enrollment.
- `crates/carrick-vmm-hvf/src/vcpu_kick.rs`: migrate direct registry tests to
  typed admission.
- `crates/carrick-observability/src/probes.rs`: probe ABI declaration, wrapper,
  and disabled stub.
- `scripts/dtrace/hvpatch-stop-the-world.d`: argument contract and the renamed,
  narrower peer-executor-without-sibling-lease predicate.
- `scripts/dtrace/hvpatch-fork-wait-amplification.d`: ABI comment audit.
- `docs/identity-and-scope-domains.md`: partial implementation receipt after
  gates.

## Testing

Red-first tests must prove:

1. a diagnostic poll with only the caller returns `Complete`, while drain
   enrollment mints a guard;
2. caller plus sibling returns `Waiting(sibling)` from both poll and enrollment;
3. an absent caller plus one sibling still returns `Waiting(sibling)`;
4. unregistering the sibling lets the next enrollment mint a guard;
5. re-registering the sibling before freeze reacquisition reopens the drain;
6. multiple siblings return the deterministic lowest identity, and a second
   drain owner receives typed `Busy` rather than a false empty set;
7. same-owner reentrant drain enrollment also returns `Busy`; dropping the sole
   guard wakes both a competing drain subscriber and a registration waiter;
8. process-fork retry waits for the exact sibling and completes after normal
   quiesce unregister without losing the membership wake;
9. the same retry wakes when the sibling terminally unregisters without any
   `QuiesceBarrier::notify_quiesced_progress` publication;
10. register/unregister between observation and retry construction is closed by
   the atomic enrollment, dropping an unclaimed subscription cancels its
   callback, and a claimed callback after drop is harmless;
11. after a drain guard is minted, a non-owner registration atomically enrolls
    instead of publishing, then succeeds only after barrier release and guard
    drop;
12. a `RetryProcessFork` owner retaining a raised barrier can re-enter host-side
    coordination and does not wait on the release it alone owns;
13. denied registration preserves representative existing production phases
    byte-for-byte in the sidecar design, including `ResumeBlocked`,
    `RetryCloneThread`, and `RetryProcessFork` with its coordinator;
14. census admission happens before registry publication; the exact
    interleaving test proves a peer page-table mutation cannot skip its barrier
    and then admit the new registry member during the edit;
15. a barrier raised while a lease-less non-owner sibling is being scheduled
    cannot publish that sibling after the drain freeze is acquired or before
    the fork/core protected section completes;
16. the crash guard remains owned through quorum collection and every live
    region-byte read, then wakes admissions only after crash barrier release;
17. the injected short crash budget reaches timeout and reports the exact final
    waiting sibling without a ten-second test;
18. a pure `VcpuLeaseDrainPoll -> waiting_vcpu_tid` mapper returns `0` only for
    `Complete`, returns the exact identity for `Waiting`, and the probe wrapper
    source is contract-checked to call it;
19. the DTrace predicate and labels use the new narrower meaning;
20. no production `VcpuRegistry::count`, `.count() > 1`, or remaining-count
    subtraction survives.

Verification uses targeted HAL/runtime tests, `just fmt-check`, `just clippy`,
`just lint-domains`, `just test`, `just doc`, and the repository-standard
`RUST_TEST_THREADS=1 RUSTC_WRAPPER= just ci`. The known host-authority positional
drift is acceptable only when its semantic `changed=[]` field remains empty;
this change must not re-bless that unrelated inventory.

The implementation receipt records this as a **partial** closure of Part 2 item
3 / identity-and-scope item 1: it removes the raw vCPU lease scalar and gives
lease drain an identity set plus its own lifecycle publication. It does not yet
mint every per-purpose participant set from `Task`, and must not claim the whole
population-and-lifecycle item complete.

## Rejected alternatives

### RAII caller-registration token

A token that proves caller registration could make scalar subtraction safe,
but Carrick releases and reacquires registrations across blocking wait,
reclaim, and backend rebind paths. Threading a token through every transition is
larger and still answers less than the identity-aware freeze capability.

### Keep a renamed diagnostic count

Renaming `count` or wrapping its `usize` preserves the attractive nuisance and
leaves future callers able to reconstruct the same bug. Migrating the one probe
ABI removes the scalar completely while preserving stronger observability.

### Reuse quiesce progress for lease membership

That publication belongs to one barrier transition and does not fire for every
registry removal. Teaching every unregister path to reach sideways into the
current barrier would couple a platform-neutral membership owner to one runtime
consumer and would remain vulnerable when another consumer is added.

### Drive drain from scheduler or logical process state

Those populations have different publication and wake protocols. Treating them
as lease authority would exchange a false completion for a lost-wakeup or
permanent-wait bug.
