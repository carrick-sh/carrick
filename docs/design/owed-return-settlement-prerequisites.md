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
