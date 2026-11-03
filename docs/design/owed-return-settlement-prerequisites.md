# Owed-return settlement: transaction and teardown prerequisites

Implementation inspection for [#1480](https://github.com/carrick-sh/carrick/issues/1480)
found two gaps between the approved settlement sequence and the existing
interfaces. This note proposes how to close them; it does not implement the
settlement routine or amend the approved design.

The governing design is [round 2](https://github.com/carrick-sh/carrick/issues/1369#issuecomment-6592668931),
its [approval](https://github.com/carrick-sh/carrick/issues/1369#issuecomment-6592713783),
the [round-3 slice-2 type changes](https://github.com/carrick-sh/carrick/issues/1369#issuecomment-6592758347),
and the [round-4 correction](https://github.com/carrick-sh/carrick/issues/1369#issuecomment-6592828050).
In particular, the settlement lock is blocking and `ForkLoanPending` is the
only skip reason. COW completion settlement cannot skip lock contention.

## Inventory reservation does not make apply infallible

The approved order authenticates the request, reserves inventory capacity,
clears retired leaves with undo, releases stage-2 backing and waits for its
exact pins, applies inventory infallibly, and acknowledges the journal chunk.

The existing `FrameCowAuthority::reserve` reserves transaction identity,
candidate IDs and event capacity. `FrameCowAuthority::apply` still returns a
`Result`. In `KernelFrameInventory::apply_inner`, authentication, revision
headroom, event validation and the unpublished-mapping check occur when the
commit is applied. Its overlay prevents partial inventory publication, but
does not make an earlier reservation a guarantee that the later apply will
succeed. `apply_retirement_with_receipt` uses that same fallible apply.

Relevant implementations:

- [`FrameCowAuthority`](../../crates/carrick-hal/src/threaded.rs)
- [`FrameInventoryReservation`](../../crates/carrick-hal/src/kernel.rs)
- [`KernelFrameInventory`](../../crates/carrick-kernel/src/kernel/frame_inventory.rs)

Consequently, passing the existing apply through a closure returning `()` or
panicking on its error would conceal a fallible step after physical release.
Quarantining after that error would not establish the approved commit order.

A possible extension is a prepared return transaction that authenticates and
retains the exact mappings, reserves publication headroom, and owns everything
needed for one infallible inventory application. Its design must account for
another MM sharing a frame and changing that frame's reference count while
the first MM settles. The conditional last-reference decision remains the
inventory owner's decision.

Do not retain the global inventory mutex across stage-2 pin waits without a
lock-order and progress proof. A per-MM settlement lock alone does not prevent
another MM from changing shared-frame state. The extension needs a witness in
which one MM has a pinned return while another MM continues making progress,
as well as failure-before-commit, exact-incarnation and shared-frame tests.

## Whole-MM acknowledgement follows root retirement today

[`retire_closed_space`](../../crates/carrick-el1-linux/src/retired_spaces.rs)
closes the space, calls `Reservations::retire_final`, and frees the space
entry. `retire_final` currently clears the deferred slots as it retires the
root. Later, carrier reclamation invokes
[`release_child_mm`](../../crates/carrick-hal/src/fork_stock.rs), which returns
a boolean after inventory and residency retirement. It does not return a
release receipt. The host root also calls `retire_final` from
[`retire_reservation_root`](../../crates/carrick-kernel/src/kernel/mm_occupancy.rs).

Moving physical release before root retirement is not a local reorder:
carrier reclamation requires the old space entry to be absent. Conversely,
minting `ReturnSettlement::whole_mm` at the current slot clear would assert a
physical release that has not happened.

The deferred slots already belong to the reservation table, independently of
the root allocation. A possible transfer is therefore:

1. Retire the root and its tree while retaining its table-level owed slots.
2. Keep the exact old MM and slot epochs available to carrier reclamation.
3. Issue a typed release receipt only after the existing physical release
   succeeds.
4. Consume `ReturnSettlement::whole_mm(receipt)` through table-level
   acknowledgement, without looking up or touching a successor root.

This preserves the physical release ordering, but delays journal capacity
reclamation. Both native and host teardown need the transfer. Tests must
cover a failed release followed by success, reused root and slot indices,
and bounded progress when retired MMs still hold journal slots. The existing
`delegated_final_settlement_drains_owed_returns` test describes the earlier
slot-clear behavior; it cannot simply be relabelled as a physical-release
receipt test.

## Decision needed before the implementation resumes

Review whether these transaction and teardown extensions belong in #1480 or
in prerequisites. The prepared transaction's concurrency contract and the
retired journal's lifetime need to be specified either way. The original
settlement requirements remain: exact `El1MmHandle` authentication, per-MM
`SettlementGuard`, COW before returns, slot epochs, chunk compare-and-swap
acknowledgement, stale requests with no successor quarantine, and per-extent
idempotent retry.

The relevant existing conformance family is
`kernel.el1.anonymous-reservations`. No semantic, structural-budget, signed,
KVM or Docker acceptance is established by this investigation.

## Slice 2a continuation and review limits

The [addendum](https://github.com/carrick-sh/carrick/issues/1369#issuecomment-6593315291)
and its [independent review](https://github.com/carrick-sh/carrick/issues/1369#issuecomment-6593369414)
supersede the proposal above. The checkpoint implements the inventory claim
and receipt prerequisites; it does **not** implement slice 2b settlement.

`PreparedReturn` claims at most 512 pages. Other transactions cannot mutate
its `Retiring` rows, and revision headroom includes outstanding claims.
`Stage1Cleared` has no ordinary abort: an explicit undo runs before abort,
apply is infallible, and drop retains the claim and invokes exact-owner
quarantine. Whole-MM inventory retirement returns `RetryPending` during the
claim. The VM-free witnesses drive those inventory entry points, including
another MM unmapping a shared frame between prepare and apply. They do not
claim to exercise a guest `exit_group` or physical pin retirement.

`RetiredJournal` records the root incarnation and each slot epoch. Local
custody tokens also borrow their originating table: two independently
allocated tables with identical numeric MM/root/slot IDs cannot exchange
return tokens. The borrow keeps that table alive and unmoved. These are local
Rust custody tokens, not transport or shared-memory ABI records; separate
virtual aliases compare unequal. A future carrier transport must authenticate
its own source and reconstruct custody through its admitted mapping.

`RetiredJournalJoin` accepts marking and release in either order and consumes
its proofs once. **Root retirement still eagerly clears slots in 2a.** Its
current `Some(0)` witnesses prove identity and proof consumption, not delayed
physical acknowledgement. Retaining retired-owed slots and the table release
notification belong to 2b. Likewise, `MmReleaseReceipt` proves empty inventory
at a revision; it does not prove backend memslot deletion. The carrier must
finish residency and physical custody work before publishing it to journal
settlement. The join retains the admitted `FrameInventoryOrigin` and rejects a receipt
from another inventory even when every numeric owner field matches. Carrier
integration must supply that admitted source, not derive it from an incoming
receipt.

### Physical gate blocker found in checkpoint review

The checkpoint's new central HVF retirement gate was unsafe and has been
removed in a follow-up change:

- `settle_declined_lease_remainders`, `commit_cow_split`, and
  `retire_stage2_candidate_if_unreferenced` already hold the frame registry
  when they call physical retirement. Acquiring it again deadlocks.
- `retire_task_state_process_grants` stages an inventory commit, retires
  physical candidates, and returns the commit for subsequent apply. A central
  check that rejects every still-live inventory row rejects this existing
  order. It cannot become active as a no-behaviour-change prerequisite.
- Indexing only `stage_mapping_in` misses frames installed by COW splitting.

Do not restore that gate or merely drop the caller's registry lock: that
would reopen the publication/retirement race the existing lock prevents.
The production port must pass existing custody explicitly and reconcile the
old retirement order with the prepared-return transaction. The existing
pending-retirement IPA allocator witness is retained, but is not evidence
for this missing inventory gate. The inherited-frame custody index is also
only a prerequisite; it does not activate chunk settlement.

CPL0's corresponding physical owner is `CarrierMemory`, not HVF's
`NativeFrameBacking`. `retire_child` checks inventory before mutation and
`AlreadyRetiredInventory` checks the last frame population before releasing
private memslots. Its shared-frame witness refuses early custody release,
keeps registrations intact, then completes after the other MM unmaps.
`release_retired_child` currently calls the neutral inventory/residency release
before `CarrierMemory::retire_child`; 2b must retain the intermediate receipt
until that backend step succeeds. Native `cross_child_reclaim` errors are
fatal today. There is no general native release-fails-then-succeeds retry;
that planned witness applies only to the host-root path.

### Inventory lock audit

The new claim lifecycle keeps the inventory lock innermost:

- `prepare_return` allocates its transaction ID and output buffers before
  locking, then validates rows and reserves revision headroom under the lock.
- `ClaimedReturn::apply` and `restore` modify only inventory maps, reference
  arithmetic and counters. Apply's output vector is preallocated.
- The concrete `ClaimedReturn::drop` in its cleared state calls quarantine **before** reacquiring the inventory
  lock to retain and count the abandoned claim.

None of these critical sections acquires `fork_stock`, a reservation root,
physical-owner custody, or a pin wait. This is a scoped audit, not a claim
about every existing generic inventory API: `apply_inner<T>` can drop a
caller's outcome on failure under its lock, and event application emits
tracing. Activation of the wider physical gate still requires review.

The branch remains draft. Slice 2a and its consuming 2b must be reviewed and
gated together; the dormant prerequisite types are not a landing unit.

### Authority-debt blocker

The HAL wrappers now own mandatory boxed claims. The inventory-owned claim
carries its abandonment policy, so consuming a wrapper needs no missing-claim
fatal branch. Prepared drop restores rows; cleared drop quarantines the exact
MM before taking the inventory lock; successful apply or abort disarms drop.

The checkpoint still introduces invariant-fatal sites in the inventory claim
and the admitted-MM conversion. The authority-debt source gate rejects these
unclassified sites. Its ceilings have not been increased. The inventory claim
retains IDs into mutable maps rather than owning stable row/reference tokens;
removing those checks safely requires stronger inventory custody types. This
is an additional draft blocker, not a passing gate or permission to remove
checks from an allegedly infallible commit.
