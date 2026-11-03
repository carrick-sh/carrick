# Owed-return prerequisites (#1480, slice 2a)

Contract: `kernel.el1.anonymous-reservations`. Linux munmap/brk retirement
must not release backing still reachable by another MM. The structural
claim in this slice is bounded inventory work per chunk (at most 512 pages),
with no physical wait under the inventory mutex.

The checkpoint's claim tests cover exact rows, revision headroom, shared
frames, teardown refusal and quarantine after stage-1 clear. The continuation
adds undo-before-abort ordering and local table identity. The two-table
`return_tokens_cannot_cross_tables_with_identical_numeric_ids` witness failed
with `b.authenticates_return_slot(&local)` false before the table-borrow fix:
a foreign token freed the receiving table's same-numbered slot.

The root-storage tests now retain the second root's own generation before
mutating the first; they no longer assume independent root incarnations have
the same numeric value. The assertion remains independence of generations.

These are VM-free prerequisite proofs. The journal join still observes eager
clearing, so its tests do not establish physical release or retired-holder
progress. No syscall routing, settlement doorbell, crossing budget or runtime
ratio is claimed. The production HVF inventory gate remains a blocker documented in
[the design note](../design/owed-return-settlement-prerequisites.md).

The release join also retains `FrameInventoryOrigin` at construction. The
foreign-inventory witness first failed to compile because the constructor
accepted no issuing authority; it now refuses a foreign receipt with identical
numeric fields and accepts the intended issuer without losing the journal.


The owned-reference continuation replaces frame re-lookup at claimed apply with
`FrameRef`, paired to its stable counter cell. Overlay commits update that same
cell; they do not copy an owned token. Reference units are counted by
`PrepareMapping` before publication; a failed overlay discards its tentative
unit. Claimed release preserves `Shared`, `Zero`, and requested `Last` semantics.
`FrameRef::split` preserves a pending retirement request across its pieces.
The production fragment event now uses that owned split API on the transaction-local counter; publication updates the stable cell only after the full batch validates.

The new overlay witness invokes production `prepare_return` and inventory
publication: an injected failure after alias prepare leaves one reference,
a successful sibling publication preserves the cell, the claim releases as
shared, and sibling teardown retires the frame. The alias-after-last witness
requires `UnreservedFrame`, with no republished row. These are logical inventory
witnesses; no stage-2 permit or backend release is established by them.

The native first-exec fixture also assumed the recycled root's incarnation was
always 2. Table-wide incarnation allocation invalidates that numeric assumption.
Its isolated red run failed with actual 3 versus expected 2. The fixture now
uses the successor slot's admitted incarnation throughout manifest sealing,
adoption and gate notifications, and asserts it differs from both the retired
root's incarnation and the adoption receipt. The production physical-switch
and gate-revision assertions remain intact.


The production split continuation adds `PrepareMappingFragment`. It validates a
published source in the same MM and frame, and confines the new mapping to its
source extent. It splits an owned reference in the tentative overlay before
unmapping the source, preserving any pending retirement request. Ordinary fork
aliases retain their existing `PrepareMapping` behavior.

The red witness `published_mapping_can_split_into_exact_subranges_of_the_same_frame`
failed with `UnreservedFrame(FrameId(2))`: the old unmap-first sequence retired
the frame before preparing its fragments. The revised witness requires the
last fragment's ordinary unmap to honor the original retirement request.
`split_then_claim_preserves_sibling_and_receipt_and_rolls_back_failed_overlay`
drives production inventory apply and claim entry points, checking two fragment
receipts, failure before publication, and shared-then-last claim release.
Claimed-source rejection is tested with an additional unclaimed alias so that
an available counter unit cannot substitute for source custody.

The shared HVF split producer serves guest, engine, and foreign COW. It now
emits the fragment events before the source unmap; its mapping-ID and receipt
collectors include those events. This is an inventory-level proof, not execution
of the HVF producer on this Linux runner. The physical permit and backend
receipt requirements remain open.
