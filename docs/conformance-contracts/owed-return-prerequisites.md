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

### COW commit inventory recheck (partial C2)

The host, guest-completion and foreign-copy COW paths now pass their kernel
inventory authority to `commit_cow_inventory_split`. Before changing the
backend ledger, the commit queries the old frame under the existing backend
registry lock. A published or claimed kernel row (including a zero-count frame
that has not retired) prevents physical retirement and retains the carrier
lease. The query adds one logarithmic frame lookup per COW commit; it does not
scan other MMs or wait for physical pins. This retains the existing legacy
registry-to-inventory lock order, not the future permit-only settlement order.

`cow_split_preserves_a_claimed_kernel_mapping_missing_from_backend_registry`
uses two actual kernel MM bindings, publishes a sibling alias, claims it, then
stages and applies a local COW transaction. It injects incomplete backend
population information independently of the valid kernel transaction. Commit
must not invoke physical retirement; aborting the sibling claim restores its
original row. A failed inventory query must leave the backend ledger unchanged.
The test is macOS/AArch64-gated: a Linux cross-check proves compilation only,
not its red/green behavioral verdict. Execute both versions on the signed host
before accepting this change.

This does not complete C2: `retire_stage2_candidate_if_unreferenced` and the
`RetirementAuthority::LegacyRegistry` falling counter remain open. B1–B3 also
still need atomic whole-MM permit output and production backend consumption
before `MmReleaseReceipt::join` can be introduced honestly. Slice 2b remains
separate. No signed runtime or performance acceptance is claimed.

### Atomic whole-MM permit output

`FrameInventoryAuthority::retire_mm_with_permits` uses the existing whole-MM
batch and transfers every last physical admission into a linear permit in
the same inventory critical section. Missing allocator identities refuse
before publication. The old event-based callers retain their current release
order until their backend consumes permits; this API is a prerequisite, not
an activated backend path.

The production-entry witnesses cover a claimed row deferring teardown, a
live sibling retaining a shared frame, missing identity leaving the inventory
unchanged, and publication remaining excluded through pending retirement.
A receipt rejects permits from another MM even when its origin and revision
match, by checking the retired mapping population. Joining also refuses
unconsumed permits. Physical completion is simulated in these VM-free tests;
no backend unmap or pin-drain execution is claimed.

The red witness failed compilation with E0599 against the preceding API.
Whole-MM publication performs the existing batch work plus linear permit
construction and logarithmic physical-index operations. Receipt attachment
sorts the frame population once and uses binary searches, avoiding a quadratic
scan for large MMs. Backend consumption and production receipt joining,
C2's remaining candidate check and legacy ratchet, and slice 2b remain open.

### Exact backend completion custody (partial B1)

The existing HVF permit consumer now authenticates the completion owner's
carrier, IPA, extent length and allocator generation before requesting physical
retirement. Backend absence or a changed generation returns the original
unconsumed permit. It cannot attach that permit's publication exclusion to a
foreign physical owner. Accepted pending retirement still uses the existing
pin-drain owner; no lock, retry loop or completion venue is added.

The production-entry witnesses cover a second MM's live backing owner, a foreign
carrier, a stale generation and backend refusal after inventory admission. Refusal keeps
the original permit and excludes new publication. The backing-owner witness then
transfers that same permit to its exact owner. Explicit abandonment remains
counted and keeps publication excluded. The final backing destructor cannot
retry a refused transfer and uses that existing fail-closed abandonment rule.
These tests need macOS execution; cross-compilation alone is not a behavioral
red/green result. Transfer adds constant-time identity checks.

This is a bounded ownership correction in the current production consumer,
not whole-MM release integration. B1–B3 still need retained in-progress MM
release state, backend permit consumption and receipt joining in HVF and CPL0.
C2's candidate admission and ratchet also remain open. In particular, adding a
zero-kernel-reference check to terminal candidate retirement would be wrong:
that path publishes its own inventory unmaps after physical cleanup. Keep the
draft incomplete. The earlier EL1 truncation and runtime failures remain failed
evidence until attributed against admitted main with complete populations.


### CPL0 terminal release joins its backend receipt (partial B2/B3)

`CarrierMemory::release_child_mm` now composes the production terminal release:
exact absence/root authentication, retained whole-MM inventory retirement,
residency removal, permit transfer to the existing slot owner, root/alias/private
slot release, and finally the backend/inventory receipt join. `ChildMmRelease`
retains the joined receipt in the existing quarantine completion owner. A
rejected join restores its original inventory half. Completed retry checks the
receipt's origin and exact MM incarnation without touching a recycled root.
The receipt does not assert physical pin drain; accepted pending permits remain
with their exact memslot until deletion.

The stale-absence witness failed before the correction: low-level
`retire_child` ignored the proof's root incarnation and released its successor.
It now refuses before mutation and leaves a live peer, successor root and
shared slot intact. The real-slot refusal witness now drives the same release
composition the production terminal caller uses, rather than manually assembling
its inventory and backend steps. It checks retained revision, no duplicate
permit transfer, foreign-inventory and stale-incarnation refusal, exact joined
receipt identity, zero abandonment, and an effect-free completed retry after
successor installation. The kernel witness exercises the neutral join owner's
refusal with two inventory MMs. Work adds constant-time identity checks and one
constant-time join; inventory, alias and memslot traversal bounds are unchanged.

This closes neither B1 nor the issue. Unpublished rollback still needs retained
progress in its admitted-loan owner. Final VM-destruction completion remains
open: the outer memory owner can drop while birth-source or wake owners retain
VM references, and outer `Arc<KvmVm>` uniqueness would not prove destruction of
the internally shared VM descriptor or vCPUs. This change does not complete
pending permits at that unproven boundary. HVF production joining, complete
B2/B3 acceptance, C2 candidate admission and its falling counter, and slice 2b
remain open. Independent review covered this bounded production diff and found
no P0/P1 defect; runtime/signed acceptance remains director-owned. Earlier EL1
population truncation and runtime failures remain unattributed failed evidence.


### CPL0 final VM destruction completes accepted permits (partial B1)

`CarrierMemory` now transfers all registered backing and accepted pending
retirements into a node preallocated at creation. Its destructor links that
node into the physical backend's destruction queue without allocating or
completing inventory work. The ISA-neutral `carrick-hal::VmDestructionCustody` seam owns the linked queue
and its final completion contract; the CPL0 node supplies its retained slots.
KVM's shared lifetime owner includes every internal
VM handle, production run context, and live vCPU slot. Parked descriptors do
not retain that owner, avoiding a cycle. At its final drop it takes and closes
parked vCPU descriptors, releases the pool lock, closes the VM descriptor,
then completes pending inventory retirements and releases their backing.
Poisoned pool contents follow the same close order. Queue insertion holds only
the destruction-queue mutex; completion holds neither queue nor pool locks.

The exact registration and permit identity remain the existing authorities;
VM destruction supplies the physical completion already allowed by
`PendingFrameRetirement`. No per-frame polling, new retry owner or guest
crossing is introduced. Terminal handoff is a constant-time tree move and
linked-node insertion. Final cleanup is linear in retained slots and accepted
pending permits, and is outside inventory locks. The lifetime guard in the
shared vCPU slot drops after its descriptor, so a transient reclaim wrapper
cannot outlive destruction authority.

The portable final-wrapper witness and real KVM wrapper/vCPU/sibling witnesses
start at the production release entry, retain accepted retirement across a
backend refusal, and destroy the outer memory owner. They require inventory
publication to stay excluded while an independent owner remains, then require
completion and zero abandonment after its final drop. They do not execute
guest instructions or establish signed/runtime-ratio acceptance.

This resolves the accepted-pending-permit destruction gap described above;
unpublished rollback, unaccepted permits at final carrier destruction, HVF
joining, full B2/B3 acceptance, C2 and slice 2b remain open. No broader B1
completion claim follows from these witnesses.

### Pending-loan abort retains release progress (partial B1)

An admitted, unpublished fork now enters an abort phase in `PendingForkLoan`
before it releases physical backing. That phase owns the original
`ChildMmRelease`; a refused backend transfer leaves its linear permits and
all admitted physical pins in the same loan. `settle` cannot return the
loan's tables, lifecycle or tag before release succeeds. Once physical
release starts, `commit_admitted` refuses the loan permanently, including
after successful release followed by refused lifecycle cleanup. Child and
parent tables must be clean before any physical release begins.

CPL0 invokes this phase before abort settlement instead of dropping admitted
custody and then invoking the receipt-only unpublished release. HVF invokes
the same phase before its abort settlement. Partial admission that fails
before an admitted token exists still uses its older rollback path; this
change does not close that part of B1.

The HAL witness covers refused release, stale execution, unchanged physical
pin lifetime, exact progress identity, commit exclusion, failed lifecycle
cleanup and release-once settlement. The real-inventory witness uses the
existing 1100-cycle production fork-stock fixture in both committed and
unpublished-abort modes. Every abort retains one exact permit through refusal,
rejects a live peer and a recycled incarnation, consumes it once after inventory
unlock and leaves the live parent's shared mapping intact. These are VM-free
ownership witnesses, not a completed guest abort under contention.

Independent review identified an unresolved P1 at the production retry venue:
`abort_loan` has no owned notification-backed continuation. AArch64 denies then
quarantines/fatals the prepared child; CPL0 currently propagates the release
refusal as a trap failure. Retaining the loan prevents early custody disposal,
but does not make either path resume. Closure requires an owned aborted-loan
phase in the existing fork continuation, a release-owner notification, and
idempotent phase advancement after `abort_mm` has freed the child's portal
space. Re-running all of `abort_mm`, polling, returning an errno or claiming
that a host DENIED response supplies a continuation would be incorrect.

Keep this checkpoint draft. Unaccepted-permit final destruction, complete
partial-admission rollback, HVF backend receipt joining, B1–B3/C2 acceptance,
slice 2b and the earlier unattributed EL1/runtime failures remain open.


### Continuation admission: stack-envelope regression

The continuation preserves all 28 prerequisite commits. The two contract
binding conflicts were additive: keep both the new refusal-census binding
and the existing physical-retirement witnesses. No implementation was
removed to resolve them.

The earlier claim that main also failed the stack gate was incorrect. The
matching default and `allocator-test-control` image builds on admitted main
both pass at 10,270 bytes. Before the correction below, both branch builds
fail at 10,302 bytes. The retained 11,311-byte ceiling requires 1,024 bytes
of reserve (effective maximum 10,287); neither limit changes.

Comparing the emitted frames with the production frame-budget parser isolates
the 32-byte increase in this envelope to `Sched::interrupt` (128 → 160 bytes).
In main's image, the SGI bitmap loop calls `send_sgis`; in this branch's image,
LLVM inlines it into `interrupt`, retaining the nested `flat_map` iterator's
front/back state and extra registers across the target lookup. The descriptor,
grant and retained service frames in this envelope are unchanged. This is a
compiled-image regression, not growth of the backing-reply wire record.
An image-build bisection of the inherited commits identifies
`feat(core): carry physical identity in claimed retirement permits` as the
first failing change: its immediate predecessor builds at 10,270 bytes and
that change builds at 10,302 bytes with `allocator-test-control`. The physical
identity and permit custody changes are preserved; the fix reduces the
iterator storage exposed by that change's compiled closure.

`WakeEffects::sgi_slots` now borrows the bitmap with one word cursor and one
remaining-bits word. It still visits only set bits, in slot order, without
consuming or copying the bitmap. The loop remains inlined, so its storage is
charged directly to the IRQ frame rather than hidden in an uncharged helper.
The IRQ frame falls to 144 bytes and both image configurations pass at 10,286
bytes. `wake_effects_iterates_sparse_words_in_slot_order_without_replaying`
covers word boundaries, sparse words, duplicate requests, exhaustion and
preservation of the borrowed bitmap. The existing compiled image gate is the
red-first structural witness; no budget, reserve or timeout changes.

Rebase verification must become green before this continuation adds either
HVF backend receipt joining or the unpublished-abort continuation. Both remain
open. In particular, a boolean backend result is not a joined receipt, and
retaining abort custody is not a notification-backed retry venue. CPL0
receipt joining and VM-destruction custody are retained unchanged. C2 and
slice 2b remain outside this continuation.

### IRQ resume headroom checkpoint

All 31 inherited commits are kept after rebasing onto the admitted main ref;
none needed a conflict port and none were dropped. This round changes only
compiled IRQ resume storage and its structural witness. HVF receipt joining,
unpublished rollback and the slice-2 settlement routine remain later work.

`resume_production` previously retained the unregistered-record branch's
aligned terminal custody while a registered record resumed its native service.
The unregistered branch now owns that scratch in `resume_unregistered` and
returns before any registered owner entry. The checker charges the maximum
of that branch and the registered `resume_selected`/checkpoint descent. It
still charges their common scheduler/IRQ prefix and all existing service tails;
no ceiling or reserve changes. The new parser witness is red against the old
checker because it did not charge the extracted terminal branch, then green
with the alternative descent accounted for.

The existing unregistered cancellation witnesses still drive the production
resume entry: terminal intent precedes record release, adapter operations
requeue without retirement, missing lifecycle retains host custody, and pool
cancellation reaps the exact entry. The registered resume and fault-reply
witnesses remain applicable. This move adds no allocation or wake operation.
Per-build measurements and focused main/candidate populations accompany the
checkpoint evidence; they do not establish signed guest acceptance.

Both rebased pre-change configurations (default and `allocator-test-control`)
measure 10,270 bytes. Both clean candidate configurations measure 9,950 bytes,
a 320-byte reduction and 337 bytes below the unchanged 10,287-byte effective
maximum. The common production-resume frame falls from 639 to 319 bytes;
`interrupt` remains 128 bytes. The extracted terminal frame is 544 bytes,
with its 128-byte handback closure charged too. Their 672-byte alternative
fits below the already charged registered owner descent. The checker still
requires the existing 1,024-byte reserve below its 11,311-byte ceiling.

Comparison checkouts initially shared one Cargo target directory. Cached
workspace metadata and a nested image retained the earlier source checkout;
those candidate attempts are invalid evidence. Cleaning workspace package
outputs and checking nested dependency paths establishes the fresh candidate
builds above. The main combined EL1 Linux process was SIGKILLed after 294 of
655 regular-test completions. The repository's existing process-isolated
harness completes main's full population: 683 passed, one ignored, including
29 serial-host passes, with four concurrent regular test processes. Neither
the incomplete process nor stale-cache attempts are acceptance results.
