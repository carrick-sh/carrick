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
Ordinary event-based mapping splits still need conversion to that owned API.

The new overlay witness invokes production `prepare_return` and inventory
publication: an injected failure after alias prepare leaves one reference,
a successful sibling publication preserves the cell, the claim releases as
shared, and sibling teardown retires the frame. The alias-after-last witness
requires `UnreservedFrame`, with no republished row. These are logical inventory
witnesses; no stage-2 permit or backend release is established by them.
