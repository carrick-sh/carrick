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

The physical-identity continuation also binds `kernel.fork.stage1-image`:
`serial_host_shared_file_frames_follow_physical_owner_leases` requires distinct
physical shared-file allocations to have distinct inventory frame IDs, while
an inherited alias retains its source ID. Shared-file index lookup and removal
remain logarithmic in the indexed population; the key adds exact physical
identity without scanning mappings or MMs. The Linux semantic requirement is
unchanged: shared-file coherence is supplied by the host `MAP_SHARED` mapping.
This backend test stubs hardware mapping and supplies kernel reference counts;
it does not prove neutral physical permits, signed execution, or runtime ratios.

The inventory rejection witness
`rejected_inventory_commit_drops_backend_custody_outside_inventory_lock`
drives the public apply, receipt, and retirement-receipt APIs with an empty
transaction carrying backend custody. Its destructor probes the inventory
mutex without blocking. Rejection must release that mutex before destroying
the outcome, just as successful apply returns custody after unlocking. This
closes a generic failure-path lock inversion; it does not exercise physical
retirement permits or establish the backend release receipt. The change adds
no inventory operations or guest crossings. Mapping reservations and return
claims also share the existing fork-aware transaction/provenance draw, before
acquiring the inventory mutex; no authority cohort or ceiling changes.


### Physical identity and claimed-return permits

The claimed-return result now carries linear `FrameRetirementPermit` values,
not frame IDs. A publication can bind the allocator's physical IPA, full
extent and host-owner generation in the same inventory transaction. That
identity is distinct from the per-mapping generation. Rebinding a live frame
or publishing another frame ID for the same physical owner is refused before
any inventory changes commit. Native HVF grant staging, ordinary host mapping
staging and COW replacement staging supply their allocator identities.
Unbound legacy frames cannot enter `prepare_return`; they return
`MissingPhysicalIdentity`, leaving their rows unchanged.

The inventory retains physical admission while a permit is outstanding and
while its request is pending. Abandonment counts and retains that exclusion.
`PendingFrameRetirement::complete` is an unsafe backend boundary: only actual
physical completion (including pins), outside all backend registry locks,
may release it. The cleanup removes the exact frame's admission, so completed
requests do not accumulate an index of historical allocations. It is not an
MM-release receipt and must not delay journal acknowledgement until pin drain.

The VM-free witnesses exercise production inventory preparation/application,
physical identity mismatch rollback, retry custody, and rejection of a new
frame ID while retirement is pending or abandoned. Chunk work remains bounded
by 512 pages; physical identity lookups are logarithmic in live/pending physical
owners, and apply preallocates its permit output before the inventory lock.
The allocator identity shares the existing reference-cell allocation; the
hot `FrameEntry` remains 16 bytes even with 1,024 aliases. The unchanged
structural witness rejected the first 48-byte layout before this correction.
No physical callback runs under that lock. These witnesses do not execute a
backend unmap or prove end-to-end physical retirement.

This continuation remains incomplete: whole-MM retirement still needs permits,
`InventoryReleased`, `BackendCustodyReleased`, and `MmReleaseReceipt::join`;
the backend must consume permits into its actual completion owner. C1's
`NativeFrameBacking::drop` gate, C2's cross-MM legacy checks and monotone counter,
and slice 2b remain open. The new pending token must be wired into S2b, rather
than completed at mere request acceptance. No signed, KVM-runtime, or runtime
ratio acceptance is claimed by these VM-free tests.


### Inventory and backend release halves

`InventoryReleased` now names the result the existing inventory retirement
paths actually produce. It cannot be passed to journal acknowledgement.
`MmReleaseReceipt::join` additionally requires `BackendCustodyReleased`,
authenticating origin, owner/root incarnation, revision and transaction.
A rejected join returns both halves. The backend constructor is an unsafe
implementation boundary requiring actual residency and custody release plus
accepted physical retirement requests; no production caller asserts that
contract in this checkpoint.

The negative compilation witness was executed against the preceding API and
failed because `MmReleaseReceipt::from_retirement` compiled successfully.
The corrected API removes that constructor. Identity witnesses reject each
mismatched component independently and retain custody for the correct join.
The existing root-journal tests use an explicit VM-free backend proof, with
no claim to exercise physical release. The production inventory producers
now return the intermediate type, without changing their release operations.

This is partial B1–B3 work: `InventoryReleased` still needs the whole-MM
permit population and backend consumption before a production join can be
introduced. The pending S2b owner, C1/C2, and slice 2b remain unfinished.
The join performs constant-time identity comparisons and adds no guest work.


### Native backing drop admission (C1)

`NativeFrameBacking` retains the physical inventory that published its grants.
Its final drop no longer treats last-Arc ownership as permission to retire a
physical frame. The kernel atomically checks the allocator incarnation's
absence and excludes publication before returning a linear retirement permit.
Live mappings, claimed returns, and pending or abandoned permits refuse this
request without changing their custody. The lookup is logarithmic in the
physical-identity index; it does not scan mappings or other MMs. Unpublished
allocations and backing left after existing whole-MM inventory removal use
this same absence admission.

The HVF owner retains the accepted permit through its existing S2b pin drain
and backend retry. Only the idle boundary consumes a successful exact-owner
completion, outside backend locks. Abandonment keeps the inventory exclusion
and counts the abandoned permit. Pending-owner removal holds the permit lock
through both index removals, so an installer either prevents removal or
re-enrolls afterward. No new retry loop or physical completion owner is added.

The new kernel admission test failed to compile against the preceding API
and passes with the admission method. The existing physical-republication
witness now covers both claimed returns and unused-backing permits, including
abandonment. The new macOS witnesses drive production `Drop` with a real
kernel inventory and a pinned owner, and pause the production idle cleanup
at its empty check to verify concurrent permit installation. Linux can
cross-check those witnesses but cannot execute them. Their signed/macOS
execution remains required; no runtime-ratio claim follows from this work.

B1–B3 remain partially integrated: `MmReleaseReceipt::join` and claimed-return
permits exist, but whole-MM release still lacks a permit population and a
production backend-half join. C1 now guards final native backing drop; the
separate explicit unused-release path retains its existing behavior. C2's
legacy COW/registry gates and monotone counter are still open, as is slice 2b's
neutral settlement routine, hook generalization and minimal host-root port.
Keep this prerequisite draft; it does not close the original slice-2 brief.
