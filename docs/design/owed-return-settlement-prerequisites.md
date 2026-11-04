# Owed-return settlement: transaction and teardown prerequisites

Implementation inspection for [#1480](https://github.com/carrick-sh/carrick/issues/1480)
found gaps between the approved settlement sequence and the existing
interfaces. This note records the slice 2a prerequisites and their remaining
integration work. Slice 2b implements the settlement routine and host port.

## Current acceptance status

Slice 2a remains an incomplete draft. Its types and inventory witnesses are
available for collaborator review, but passing their gates does not establish
backend release or make the prerequisite an independent landing unit. The
sections below preserve the design and implementation history; this table
summarizes the current code rather than the earlier checkpoints.

| Requirement | Implemented | Still required |
|---|---|---|
| Owned return claims (A1–A4) | Stable reference custody outside copied overlays, prepare/abort accounting, production fragment splitting, shared/zero/last outcomes, and infallible claimed unmap bookkeeping. | Integration with slice 2b's physical settlement sequence. |
| Physical permits and release receipts (B1–B3) | Exact allocator identity, claimed-return permits, atomic whole-MM permit output, retained quarantine/exec-predecessor release progress, and HVF/CPL0 terminal permit consumption. | Two-half receipt construction/joining is still not a production operation. Unpublished fork rollback keeps its inherited receipt-only release. VM destruction of retained CPL0 memslot completions is not integrated; dropping such a slot still uses fail-closed abandonment. Full physical execution also remains unaccepted. |
| Native backing drop (C1) | `NativeFrameBacking::drop` requests an inventory permit; the existing S2b owner retains it through physical completion. | Execute its macOS witnesses, including pin drain and concurrent idle cleanup. Linux cross-compilation cannot prove those behaviors. |
| Legacy retirement checks (C2) | `commit_cow_inventory_split` consults kernel inventory. | `retire_stage2_candidate_if_unreferenced` still checks only the backend registry. Its kernel-inventory check and the falling `RetirementAuthority::LegacyRegistry` counter are absent. |
| Original six review changes | Typed post-clear custody, claim/headroom handling, journal identity, an inventory-lock destructor witness, and the named CPL0 retirement path. | Physical backend integration and execution remain open; journal identity tests still observe eager clearing and do not prove delayed acknowledgement. |
| Slice 2b | Not implemented in this prerequisite. | Neutral owed-return routine, `SettlementGuard`, slot-epoch chunk acknowledgement, COW-before-return exclusion hook, whole-MM settlement and minimal host reconciler port. |

The terminal production path now obtains `retire_mm_with_permits` through
`ChildMmRelease`, held by the existing fork quarantine or exec-predecessor
owner. Backend refusal retains the original inventory revision and permits.
HVF transfers accepted permits to the existing S2b physical completion owner;
CPL0 transfers them to the existing memslot owner, completing them only after
successful context drain and memslot deletion. A shared slot keeps pending
completions until its final context releases the slot. CPL0 staging supplies
its allocator's typed `PhysicalOwnerGeneration::INITIAL`, independently of
mapping generations.

`PhysicalFrameInventory::retire_mm` and unpublished rollback retain their
inherited receipt-only behavior. They are not a second implementation of the
new settlement routine: slice 2b is still absent. Neither
`MmReleaseReceipt::join` nor `BackendCustodyReleased::from_backend_release`
has a production caller. Accepting the physical request is not a joined
whole-MM receipt and does not authorize journal acknowledgement.

A focused independent source review found no additional P0/P1 in the atomic
whole-MM permit primitive. It confirmed the missing backend integration and
C2 work as acceptance blockers. It was not approval of the entire draft.
The final gate report must preserve these blockers even when the inventory
tests pass. No debt ceiling, timeout, retry policy or concurrency reduction
can substitute for completing them.

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
its `Claimed` rows, and revision headroom includes outstanding claims.
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

### Authority-debt correction

The HAL wrappers now own mandatory boxed claims. The inventory-owned claim
carries its abandonment policy, so consuming a wrapper needs no missing-claim
fatal branch. Prepared drop restores rows; cleared drop quarantines the exact
MM before taking the inventory lock; successful apply or abort disarms drop.

The checkpoint introduced invariant-fatal sites in the inventory claim
and the admitted-MM conversion. Subsequent changes removed them by owning
mapping rows and stable reference units, and by making admitted-MM conversion
fallible. The two counter-related fatal sites were new against admitted main;
neither remains. No authority-debt ceiling was increased. This corrects the
claim's bookkeeping, but does not supply the missing physical retirement gate.

## Continuation audit against the current owner brief

The [superseding brief](https://github.com/carrick-sh/carrick/pull/1485#issuecomment-6594790619)
adopts [addendum 2](https://github.com/carrick-sh/carrick/issues/1369#issuecomment-6594737829)
with its [five review changes](https://github.com/carrick-sh/carrick/issues/1369#issuecomment-6594782213).
The three gaps above are therefore **implementation work**, no longer waiting
for a design ruling. The checkpoint must not be described as awaiting approval
to implement them.

The six items in the original ruling have this status:

| Item | Status and witness |
|---|---|
| Post-clear custody | Implemented: `Stage1Cleared` has no ordinary abort (compile-fail doctest); `stage1_undo_finishes_before_inventory_abort_and_retry` checks undo ordering; `cleared_drop_quarantines_exact_owner_and_retains_claim` checks abandonment. |
| Outstanding claims | Headroom and teardown refusal implemented: `return_claim_reserves_revision_headroom` and `return_claim_blocks_teardown_aborts_and_retries`. The mapping-event refusal witness covers prepare, publish, protect and unmap without modifying the claimed row or frame count. This is an inventory-level reclaim witness, not a guest `exit_group` test. |
| Physical gate and per-frame custody | Remaining: custody is indexed by `(ipa, generation)` and `pending_retirement_excludes_allocator_reuse_at_different_lengths` exists, but the inventory permit gate and the cross-MM retirement protections are absent. |
| Retired journal | Identity and order-independent joining implemented: `retired_journal_release_before_borrowed_root_retirement_joins_once`, `retired_journal_recycled_slots_and_same_raw_mm_do_not_touch_successor`, and `journal_join_rejects_foreign_inventory_with_same_numeric_owner`. The two-half backend release proof required by addendum 2 is remaining. Existing joins still acknowledge zero slots after eager clearing. |
| Inventory lock audit | The claim lifecycle audit above covers the new critical sections; `completion_drops_quarantine_outside_inventory_lock` checks callback destruction on apply and undo. It does not establish a lock-level guarantee for generic transaction outcomes. |
| CPL0 path | Named and witnessed through `CarrierMemory::retire_child` and `custody_release_before_another_mm_unmaps_keeps_physical_registration`. Backend-half receipt integration remains part of the addendum work. |

The continuation moves mapping rows into the claim, leaving constructor-sealed
`Claimed` placeholders; overlays cannot copy a claimed row. The owned-reference
continuation below adds stable reference custody outside the copied overlay,
prepare/abort accounting, and `Shared`/`Zero`/`Last` release semantics with full
unmap bookkeeping. Addendum 2 still requires production split conversion,
linear retirement permits consumed into a backend release half, and gates on
native backing drop and the cross-MM legacy retirement sites. No new debt ceiling or
legacy exemption is introduced by this continuation. Passing prerequisite
tests cannot substitute for these missing production changes or slice 2b.

The continuation's independent review also found a teardown classification race:
`retire_mm_with_receipt` releases the inventory lock after collecting rows.
A claim admitted before the later apply safely refuses that apply, but the
checkpoint returned a generic apply error rather than `RetryPending`.
The continuation translates `ClaimedMapping` from that apply into
`RetryPending`, matching the initial scan's refusal. The existing
pre-admitted-claim witness does not exercise the concurrent interleaving;
the event witness proves the later apply refuses without changing rows.


### Physical identity and backend receipt integration still required

A retirement permit cannot use `ExactReturnMappingRow::generation` as its
host-owner generation. In `StagedPhysicalGrants::stage_with_permissions`,
`owner_generation = NonZeroU64::MIN` initializes the inventory mapping
generation; it is not the generation returned by the physical allocator.
The HVF native allocator already returns the actual IPA and owner generation
before calling that staging API. `stage_mapping_in` also has the stage-2
lease and physical `stage2_owner`, but `PrepareMapping` does not carry that
identity into the inventory frame cell. The implementation must transport
this exact physical identity through publication before it can issue a permit.

Similarly, the current fork-stock reclaim callback releases inventory before
`NativeChildPhysical` drops. Minting a backend half inside that callback would
still claim custody release too early. The retained inventory half must cross
the actual custody drop; CPL0 must retain it through `CarrierMemory::retire_child`.
Neither the existing receipt constructor nor a successful inventory query
proves that step completed.

The owned-reference continuation below resolves the stable-counter gap:
`FrameEntry` owns a stable counter cell, and the overlay copies only its numeric
snapshot. An owned unit stays attached to that cell across overlay commits and
aborts. The split primitive is present, but production mapping splits still use
the event-based path. The physical permit gate remains an implementation
blocker.


The admitted-handle conversion now returns `Option<GuestFrameOwner>` instead
of adding an invariant-fatal branch; the CPL0 cleanup callers refuse a failed
conversion before invoking release. This removes that fatal site, but is not
the proposed admission-time retained `ReturnOwner`. Existing fork-stock
execution contexts already carry the typed owner used at release.


## Owned-reference continuation on admitted main 9bc605a1bd

The two explicit fatal sites in claimed apply were **new against main**, not
carried over. This continuation removes both, without a ceiling change. A
claim now owns a `FrameRef` containing its stable counter cell, outside copied
mapping and frame snapshots. Overlay publication updates the existing cell.
There is no API that accepts a reference token together with a different
counter. Ordinary unmap cannot consume a claimed unit. Restore gives that unit
back; apply consumes it and preserves the existing unmap generation, provenance,
revision, and MM-count bookkeeping.

The neutral counter provides an owned `split` with checked headroom and
preallocated output, plus `Shared`, `Zero`, and `Last` release outcomes. This
is not yet the required conversion of every event-based COW/munmap split.
Integrating a fallible split into a multi-frame commit would be wrong: all
split storage and headroom must be prepared before the first publication.

Remaining implementation work is explicit, not awaiting an owner ruling:

- Connect owned splitting to the production mapping split paths.
- Carry physical IPA and host-owner generation into the inventory frame cell;
  mapping generation cannot substitute for that identity.
- Issue linear retirement permits and consume them into the backend half of
  the two-half MM release receipt after inventory locking ends.
- Gate `NativeFrameBacking::Drop`, `commit_cow_inventory_split`, and
  `retire_stage2_candidate_if_unreferenced` against the kernel inventory.
- Complete slice 2b's neutral settlement routine and minimal host-root port.

The stable cell adds one allocation and a small lock per frame. The reference
operations remain constant-time and the overlay remains proportional to touched
rows; runtime overhead has not been measured. The independent review found and
prompted removal of an earlier unbound public counter token; it did not approve
the unimplemented physical-retirement work. Keep the PR draft.

## Terminal-custody census correction

Comparing the incoming slice with admitted main `53ecfb0c0` identifies nine
additional scanner sites, all in `frame_inventory.rs`. They are calls to
`MappingSlot::live`, the new projection from `Live(MappingEntry)` or
`Claimed(ClaimMark)` to an optional row. The cited dispatcher
`exit_one_task_thread` site is unchanged from main. These additions do not
decide task exit or MM terminal eligibility, so moving them into
`TerminalCustody` would put inventory claim ownership in the wrong owner.

The projection is removed. Each inventory operation now matches the sealed
slot exhaustively: a claimed row is unavailable for copying or authentication,
while its reference and diagnostic snapshot remain owned by the claim.
Whole-MM retirement still returns `RetryPending`; event mutation still returns
`ClaimedMapping`. No scanner rule, exemption, ceiling, or task-exit path changes.
The kernel terminal-custody population returns from 38 to main's 29 sites.

Addendum 2 remains incomplete. The implementation status is:

| Requirement | Status |
|---|---|
| Owned `FrameRef` outside copied entries, prepare/abort reference accounting | Implemented in the preceding continuation; overlay and claim witnesses exist. |
| `FrameRef::split` in every production split | Remaining; the primitive and its unit tests exist, but COW/munmap still use mapping events. |
| `Shared` / `Zero` / requested `Last`, full claimed-unmap bookkeeping | Implemented at the inventory layer; `Last` still yields a frame ID, not a physical permit. |
| Linear permit consumed into `BackendCustodyReleased` | Remaining, including transport of exact physical IPA and host-owner generation at publication. |
| `NativeFrameBacking::Drop` gate | Remaining; last-Arc drop still requests physical retirement directly. |
| Cross-MM legacy reference checks | Remaining in `commit_cow_inventory_split` and `retire_stage2_candidate_if_unreferenced`. |

This census correction is not evidence for those missing production changes,
the two-half release receipt, or slice 2b settlement. The full gate turn and
independent review must retain those as open implementation requirements.

### Gate-turn scope

The source-built census was checked again against admitted main and against
the correction's parent. The parent fails with 38 kernel sites against 29;
the corrected tree's full site list equals main. All nine removed sites are the
inventory projection above, not new dispatcher terminal-policy decisions.
The scanner implementation is unchanged between the compared trees.

Keep the proposal titled **#1369 slice 2a: preserve owned return claims** and
in draft. Successful prerequisite tests do not establish the original slice-2
acceptance: the neutral owed-return routine, `SettlementGuard`, chunk
compare-and-swap acknowledgement, generalized COW-before-return hook and
minimal host reconciler port are still absent. The inventory's infallible
apply boundary proves only its logical commit; it does not prove physical
release preceded that commit. Physical permits and backend receipt integration
remain implementation requirements, not a pending design decision.

On a Linux worker, the macOS cross-check establishes compilation and linting,
not execution of HVF retirement or signed guest behavior. KVM carrier-memory
tests can exercise real memslot custody, but do not supply the missing HVF
drop-gate witness. Retain these distinctions in the gate report and independent
review before promoting this prerequisite together with its consumer.


## Production split continuation (slice 2a)

The admitted-main rebase preserves all thirteen preceding commits. The
source-built `lint-source` passes and `terminal-custody --list` reports 29
`carrick-kernel` sites, equal to the unchanged ceiling.

The production mapping-fragment operation now uses `FrameRef::split`. A
fragment must name a published source in the same MM and frame and lie within
that source's extent. The split operates on the transaction-local reference
snapshot, under the inventory lock; every temporary owned unit is restored
before that snapshot can publish. Failed allocation or later event validation
publishes nothing. The original mapping remains referenced until its surviving
fragments have been prepared, so a pending retirement never observes a
transient zero. Ordinary independent aliases keep their existing semantics.

All current production COW fragment producers converge on
`stage_cow_inventory_split` (guest COW, engine COW and both foreign COW paths).
That producer and the receipt/mapping-ID collectors now understand fragments.
The x86 fork emitter publishes new child aliases, not fragments, and retains
ordinary preparation. The independent A3 review found two missing test-authority
collectors; both were corrected. This review does not approve the remaining
physical-retirement work.

The amended addendum 2 status after this continuation is:

| Requirement | Status |
|---|---|
| A1: owned reference outside copied entries; overlay witness | Implemented by the preceding continuation; unchanged here. |
| A2: reference counted at prepare, returned on abort | Implemented; failed fragment-overlay publication also leaves the original count intact. |
| A3: production split uses the owned primitive; split then claim | Implemented in the shared inventory event and HVF split producer. Pending retirement, sibling survival, receipt population, rollback, and claimed/foreign/out-of-range source witnesses cover the logical transaction. HVF execution still needs its host lane. |
| A4: Zero versus requested Last; claimed-unmap bookkeeping | Implemented at the logical inventory layer. Last still returns a frame ID, not a physical permit. |
| B1–B3: linear physical permits, two-half receipt, in-progress retirement, post-lock consumption | Remaining. Exact physical IPA and host-owner generation must first reach the inventory frame cell. The existing alias-after-last test is only the logical half of B2. |
| C1–C2: native backing-drop gate and cross-MM legacy retirement checks | Remaining. No new legacy authority variant or ceiling was introduced. The director still owns any required policy record. |
| Original slice 2b: settlement routine, guard, slot epochs/chunk acknowledgement, COW-before-return hook and host port | Remaining, as previously recorded. |

Keep the PR draft under **#1369 slice 2a: preserve owned return claims**. The
completed split prerequisite does not establish full slice-2 acceptance or
make the dormant prerequisites a separate landing unit.

## Physical identity continuation: shared-file deduplication

The physical-permit audit found that the existing shared-file index merges
independent physical allocations into one `FrameId`. `HvfTaskState::add_alias`
in `trap/cow_engine.rs` maps each shared-file alias with
`OwnedHostMapping::map_shared_file`, reserves a fresh `GlobalFrameStage2Lease`,
and registers a fresh host owner. It then calls `stage_mapping_in` with
`inherited_frame: None`. That routine reused a frame ID solely by
`SharedFile { device, inode, offset, length }`, while keeping the distinct
physical lease and owner in each `InventoryExtent`.

That behavior prevents the planned frame cell from naming one physical
owner. Storing the first or last allocation's identity in the cell would
strand backing or authorize the wrong release. Keeping every allocation
until the logical frame's last unmap is also insufficient: one long-lived
shared-file alias could retain every subsequently mapped-and-unmapped
physical allocation indefinitely.

The shared-file index now includes the full physical lease and exact owner
identity. Independent physical allocations receive distinct frame IDs;
inherited mappings keep their existing frame ID. Every insertion and removal
uses the same key. File coherence still comes from the existing host
`MAP_SHARED` mappings; it does not require independent physical allocations
to share an inventory frame ID.

`serial_host_shared_file_frames_follow_physical_owner_leases` drives production
allocation, owner registration and mapping staging. It requires distinct
frame IDs for distinct physical leases, preserves the source ID for an
inherited alias, and checks independent retirement and stage-2 cleanup.
Its hardware map/unmap uses the existing test stub and its kernel counts use
the existing test authority; it does not exercise a kernel inventory commit
or a guest. The old shared-file key contradicts the distinct-frame assertion.
An executed red/green witness still requires macOS; cross-compilation on
Linux is not that evidence.

The independent review confirmed the shared-file collision. An initial
review hypothesis about COW creating another frame ID for a reused physical
compound was rejected on inspection: `guest_reservation` requires
`fresh_destination`. This correction does not claim a global frame/physical
bijection. Remaining producers, including structural owner-fork admission,
must be audited, and alias publication must validate physical identity
transactionally before the inventory can issue permits.

Shared-file conditional-retirement eligibility is unchanged. Review also
identified a pre-existing same-owner schedule requiring a dedicated witness:
two retirements stage before either inventory apply, leaving a zero-count
shared frame instead of a retired frame. The remainder settler requires
absence, not zero. This continuation does not prove retirement progress for
that schedule, nor rely on a future independent file mapping to reclaim it.
That proof remains with the physical retirement integration.

Addendum 2 status remains: A1–A3 implemented; A4's logical release and unmap
bookkeeping implemented; B1–B3 physical identity transport, linear permits
and two-half receipts remain; C1–C2 retirement gates remain; slice 2b
settlement remains. The shared-file correction removes one concrete obstacle
to B1, not those remaining requirements. Keep slice 2a draft.

### Whole-MM permit extraction continuation

The new `retire_mm_with_permits` entry composes the existing whole-MM batch
with atomic physical admission transfer. It returns `InventoryReleased`
carrying its last-frame permits after unlocking. It refuses an unbound legacy
frame before changing inventory; it never substitutes a mapping generation
for an allocator generation. A shared frame produces no permit until its
last MM retires. The release half rejects a permit absent from its retired
mapping population, including an unrelated empty-MM receipt at the same
revision, and cannot join while it still contains permits.

This completes the inventory output primitive, not the backend port.
`PhysicalFrameInventory::retire_mm` and current `release_child_mm` callers
still use the existing release order. Activating the new output there would
abandon permits at their current boolean checks. HVF must retain the release
through child custody drop and transfer permits to S2b. CPL0 must bind its
allocator identities at publication, retain the release across memslot
retirement, and consume its permits before constructing the backend half.
Those integrations remain required before this prerequisite may land.

## B1 production continuation

This round is limited to retained whole-MM release progress and its terminal
backend consumers. It changes no settlement doorbell, revival policy, wait
budget, concurrency or C2 retirement authority. The original issue remains
draft and incomplete.

The extended production fork-stock witness performs 1100 child retirements
with a real inventory and a still-live parent. Each first backend request
refuses; the next drain consumes the same permit exactly once. The original
release revision survives; a live peer and a stale root generation cannot
borrow the progress. Physical callbacks can acquire the inventory lock, and
the abandonment counter remains zero. These are VM-free operations, not two
executing guest processes.

The CPL0 physical fixture calls the real permit consumer and `retire_child`.
A live peer root temporarily prevents slot release; retry keeps the accepted
completion with that same slot, does not replay its permit, and deletes the
slot after the peer releases it. The fixture has both a VM-free adapter and a
real KVM memslot binding. The macOS test
`whole_mm_release_retains_permit_when_backend_owner_refuses_once` drives the
HVF terminal release entry, restores the exact temporarily unavailable owner,
and checks physical pin-drain completion. Its execution remains director-owned.

Open work remains explicit:

- B1: carry retained permits through unpublished rollback's admitted-loan
  owner, and integrate terminal VM-destruction completion for CPL0 slots that
  still retain pending retirements. Dropping such a slot currently invokes
  fail-closed abandonment; it is not successful physical release.
- B2: complete and witness production backend receipt construction and joining,
  including every shared-slot and already-pending outcome required by review.
- B3: the portable callback proves post-inventory-lock consumption; backend
  execution and the complete joined release path remain to be accepted.
- C2: the legacy candidate kernel-inventory gate and falling authority counter
  remain unchanged and incomplete.
- Slice 2b: owed-return settlement, guard, slot epochs/chunk acknowledgement,
  COW-before-return exclusion settlement and host reconciler port remain absent.

All 24 inherited commits are kept; the admitted-main rebase was already
satisfied, with no conflicts, ported commits or dropped commits. No earlier
failed or unavailable gate is promoted by these component witnesses.
