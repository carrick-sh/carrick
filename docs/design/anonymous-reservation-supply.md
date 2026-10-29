# Anonymous reservation supply: #898 diagnosis and proposed correction

This is a diagnostic slice, not a runtime fix. The VM-free budget witness is
expected to fail until reusable physical supply exists. No budget is widened.

## Main path

Source inspected: GitHub main `bdfa2b062cde08cd33cf8ae91c94636cdfd8560d`.
The signed report on #898 records 200/589 exits for 64/256 reservations,
flat forwarded mmap/brk and successful guest output. This worker cannot run
HVF or Docker on ctb-w3.

The fixture interleaves mmap and a first write/read for each 1/2/3/4-page
reservation (`fixtures/embed-el1-sched/src/main.rs`, `anonymous_reservations`).
The shared anonymous dispatcher admits the reservation without backing.
First write faults:

1. `crates/carrick-el1/src/fault.rs:1423` probes prepared residency. A new
   reservation has none. The owner-supply branch at `:1487` takes the MM editor
   and root, then calls `select_fault_window` at `:1513`.
2. `crates/carrick-core/src/mm/fault.rs:141` asks the reservation authority for
   a transfer fault plan. In `reservation/root.rs:1712-1719` the aligned bulk
   window is clipped to **one node**. A small mapping cannot borrow the target
   size beyond its own range. Authentication at `:1740-1761` intentionally
   requires the plan to fit that same mapping incarnation.
3. `crates/carrick-core/src/mm/frames.rs:12` clips further around occupied
   descriptors. It cannot enlarge the selected reservation. The fault path
   publishes the selection at `crates/carrick-el1/src/fault.rs:1545` and returns
   Forward. `carrick-el1-linux/src/dispatch.rs:1161-1171` captures that exact
   selection sequence before park, then `:1224-1227` submits the Fault service.
   Native transport consumes it via `ServiceTicket::take_fault_selection`
   (`carrick-core-abi/src/service.rs:1447`).
4. `crates/carrick-vmm-hvf/src/metadata_grant/native_service.rs:679` routes
   Backing to `supply_backing`. At `:854-881`, anonymous publication length is
   the selected range, allocation is rounded to COW compound size, and a new
   extent is allocated. At `:936-947`, Prepare publishes only that selected
   range. Spare rounded bytes do not become guest-spendable stock.
5. `crates/carrick-core/src/mm/frames.rs:215` serves the grant: exact-generation
   authentication, occupancy check, residency publication and descriptor
   execution. It rejects publication beyond the selected range (`:270`).

Thus every new small reservation in this sequential workload needs physical
supply. This is a production backing-service lower bound, independent of
metadata refills or maintenance exits. Source analysis does not attribute the
entire measured ~2.026 exit slope: exit-class capture on the exact signed
artifact is still required. Existing native-fault-supply probes distinguish
Backing/Cow/Unselected and include range length. The VM-free reduction uses
bootstrap metadata and preinstalled descriptor tables to isolate backing
requests from metadata refills and table provisioning.

## VM-free red witness

`anonymous_reservation_first_touch_service_budget` lives in the existing
`carrick-el1-linux::aarch64_process_tests::native_fault_supply_tests` harness.
At 64/256/1024 it interleaves production anonymous dispatch, production fault
selection including the live descriptor scan, and production grant settlement.
It counts actual published physical-supply selections, supplies isolated
synthetic physical extents through Prepare, authenticates against the live
reservation owner, consumes each grant receipt and checks committed, distinct
private leaves retained across subsequent grants.

The backend fixture supplies memory/table storage; it does not emulate guest
instructions or measure host-exit classes. The counter is a lower bound on
service requests: the native intake, park/wake/ACK transport and HVF allocation
are not executed here. A service budget failure is conclusive; passing this
binding alone cannot certify the signed total-exit slope. First-touch readback,
physical zeroing and actual first-write execution remain signed obligations.
The assertion uses the signed contract's unchanged strict <1/8 slope.

The completed main-source run reports:

| Reservations | Backing requests |
|---:|---:|
| 64 | 64 |
| 256 | 256 |
| 1024 | 1024 |

Every reservation and grant completed; the strict budget then failed with
`delta=192/192, required <1/8` (exit 101). The witness is active and intentionally
red in this diagnostic draft. Command:
`cargo test -p carrick-el1-linux --lib anonymous_reservation_first_touch_service_budget -- --nocapture`.

## Revised design: private stock, shared policy

This revision addresses the four publication, lifecycle, permission and capacity
findings on PR #1030. **Shared means shared policy and transaction machinery.**
Stock belongs to one exact MM incarnation, never to the carrier or a peer MM.
The decisions below are proposals, not claims that main implements them.
Slice 1 is the policy extraction described below; it does **not** fix #898.

### Existing foundations and proposed owners

All main citations in this document refer to the main SHA above. Paths below
are relative to `crates/`. These are the existing types relied on by the
proposal; the cited operations identify their limits as well as their uses.

| Existing type or operation | Main location and responsibility |
|---|---|
| `Reservations`, `ReservationFaultPlan` | `carrick-core/src/mm/reservation/root.rs:463`, `:148`; mapping owner and mapping-bound plan; clipping at `:1712`, exact-node authentication at `:1725` |
| `GuestFrameOwner` | `carrick-hal/src/threaded.rs:2583`; native MM generation plus root/context generation; neither VA nor numeric MM alone identifies stock |
| `StagedPhysicalGrants`, `PhysicalGrantCustody` | `carrick-hal/src/physical_grants.rs:44`, `:56`; inventory apply receipt and explicit handoff at `:71` |
| `UnpublishedFrameInventoryApply` | `carrick-hal/src/threaded.rs:2633`; explicit inventory rollback at `:2645`, retained through physical settlement |
| `PhysicalGrantRollback` | `carrick-hal/src/physical_grants.rs:23`; retains failed inventory rollback receipts; this alone does not undo stage-2 or descriptors |
| `NativePhysicalGrants` | `carrick-hal/src/physical_grants.rs:221`; `retain_backing` at `:289` retains physical custody, with no backing-reply settlement operation |
| `NativeFrameBacking` | `carrick-vmm-hvf/src/fork_stock.rs:46`; Drop at `:52` requests retirement using exact IPA, length and host-owner generation; Drop alone is not proof of completed release |
| `MemPerms` | `carrick-hal/src/error.rs:63`; physical permission representation; existing COW capability is `COW_GRANT_PERMISSIONS`, `physical_grants.rs:13` |
| `FrameGrantResidencyIdentity`, `FrameGrantResidencyTable` | `carrick-core-abi/src/mm/residency.rs:22`, `:201`; exact physical identity, bounded publication at `:256`; fragment publication at `:724` is not an atomic capacity reservation |
| `SlotAbsence`, `ExecPredecessorReceipt` | `carrick-hal/src/fork_stock.rs:316`, `:684`; authenticated execution absence and predecessor settlement at `:1458` |
| `DeferredReturn`, `ReturnSlot` | `carrick-core/src/mm/reservation/root.rs:122`, `:133`; owed-return observation at `:2739`, reservation at `:2712` |

The following names are **NEW**, proposed interfaces rather than existing APIs:

- **NEW `PrivateStockPlan`**: exact owner, fault-node incarnation, bounded
  candidate range, root observation version and exclusion observations.
  Revalidation must compare owned node/hole facts and pending/owed state,
  not merely an
  unchanged fault node or a backend-supplied version counter.
- **NEW `StockExclusions`**: bounded input of descriptor/residency occupancy,
  host-only observations and pending/owed exclusions. Backend observations do
  not authorize publication; the root revalidates under its editor.
- **NEW `PrivateSupplyTransaction`**: owned allocation and publication journal,
  indexed by exact owner, root, request sequence and allocation generation.
- **NEW `StockPhysicalCapability` / `StockAdoption`**: physical capability and
  transactional adoption by one mapping incarnation with requested access.
- **NEW `StockCapacityLease` / `StockResidencyRecord`**: concrete reserved
  slots, descriptor-table capacity, chunk custody and retained-page masks.
  Capacity counters alone cannot substitute for successfully claiming slots.

### Selection and authentication

Move the policy in `carrick-kernel/src/dispatch/mem/fault.rs:555`
(`try_root_grant_for_page`) into the neutral reservation owner. It already
collects eligible anonymous nodes and future arena holes, subtracts residency
and owed returns, and selects the contiguous run containing the fault. Keep
host-only occupancy observations in the host adapter. File-backed supply stays
mapping-bound. Exclude heap, pending edits, incompatible nodes, occupied leaves
and unsettled returns. Revalidate the complete selection under the same exact
MM editor immediately before any publication; an observation made before an
asynchronous service request is not permission to publish later.

Keep mapping-bound authentication unchanged. A **NEW `PrivateStockPlan`** must
not be passed as a widened `ReservationFaultPlan`. Its authenticator checks the
fault node and every selected hole/node, including intervening replacements,
and the full owner/root/request identity. A peer with identical VAs cannot
validate or consume it. Only the faulting page permitted by a live node becomes
accessible. Prepared stock in a hole remains invalid; fault admission must
still reject the hole until an authenticated mapping adopts it.

Prepare already installs page leaves. Preserve that behavior and the output
alignment guard in `carrick-mmu-core/src/aarch64.rs:5292` for any subsequent
coalescing. Half-window sizing is a policy bound, not an alignment proof.

### One publication transaction, including physical settlement

Replace early irreversible backing retention in
`carrick-vmm-hvf/src/metadata_grant/native_service.rs:916` with an owned
**NEW `PrivateSupplyTransaction`**. Its neutral owner controls the following
states; ISA/backend adapters perform only the recorded operations.

1. **Reserved:** revalidate the plan; claim actual residency slots, table
   capacity and return/journal capacity before allocation. Record the exact
   preimage of all state that can change. A refusal here changes no live state.
2. **Staged:** allocate zero private chunks, retain their exact host-owner
   leases, install stage-2, and stage inventory receipts. Keep allocation,
   stage-2 pins and inventory receipts in the transaction, including on errors.
3. **Offered:** publish one typed reply referencing that transaction. The ring
   revalidates the selection and applies residency and descriptor edits with
   undo receipts. Reply visibility does not commit physical custody.
4. **Applied:** authenticate the ring's exact apply receipt. Settle backing and
   descriptor-table custody together, then ACK the receipt. Keep a committed
   transaction/tombstone until ACK consumption so duplicate settlement cannot
   release or republish bytes. Afterward transfer ownership to this MM's stock
   and adopted mappings. Subsequent legitimate edits use normal retirement;
   settlement must not mistake them for failed original publication.

The concrete missing physical operation is **NEW
`settle_backing_reply(transaction_id, outcome)`** on the shared physical owner,
paired with **NEW `stage_backing_reply`**, replacing `retain_backing` for this
protocol. It consumes the owned allocation lease and inventory apply receipt,
not just a descriptor receipt. Extend the existing table settlement entry at
`native_service.rs:1369` to invoke the combined owner. Its current
`settle_native_descriptor_tables` call at `:1407` settles tables only.

For clean refusal or cancellation, withdraw the reply and prove the ring can
no longer consume it; reverse descriptor/residency changes under exclusion
and complete translation invalidation; roll inventory back using the retained
apply receipt; remove stage-2 and wait for its exact generation's pins to drain;
then explicitly retire/release the exact allocation lease and return reserved
capacity. Verify each step. Restore the root/journal preimage before reopening
admission. No allocation is released merely because its reply was refused.
A cancellation racing application is resolved by the authenticated receipt,
not by guessing from the current leaf or dropping the host request.

If withdrawal, undo, invalidation, inventory rollback or stage-2 release is
indeterminate, retain the entire remaining journal and physical custody,
quarantine the exact MM and fail closed through the carrier invariant-failure
path. Do not ACK success, reuse capacity, attach to a successor or rely on Drop
to decide terminal policy. The existing failed-receipt retention mechanism is
one component, not a substitute for this settlement protocol. Failure injection
must cover every boundary, including after reply application and before ACK.

### Lifecycle: two live MMs, no transferable unused entitlement

| Event | Required transition |
|---|---|
| Fork | Freeze/revalidate stock under the parent editor. Unused hole stock stays with the parent; the child receives no stock entitlement and no accessible leaf for those holes. Main already omits user leaves outside mappings (`carrick-core/src/mm/fork.rs:692`). Adopted private mappings follow ordinary private inheritance and COW custody (`:1007`); separate unused and adopted page masks before inheriting any compound chunk. A shared chunk may retain physical bytes for inherited adopted pages, but cannot grant the child access to its unused pages. |
| Exec | Successor starts with empty stock and its own exact owner. Pending predecessor replies are withdrawn or settled against the predecessor only. Retain predecessor stock, tables and physical journals until authenticated translation switch, MM retirement and slot absence; extend existing `settle_exec_predecessor` settlement (`carrick-hal/src/fork_stock.rs:1458`), rather than moving stock into the successor. |
| Exit | Close supply admission; settle/withdraw pending replies; retire inventory and residency; prove execution-slot absence before releasing chunks. Use the neutral retirement/quarantine owner (`carrick-hal/src/fork_stock.rs:2115`, `:2149`), retaining any unresolved physical transaction. |
| MAP_FIXED / unmap | Retire adopted pages under their mapping incarnation. Unused stock does not become replacement-owned by sharing its VA. Replacement either authenticates a fresh adoption or removes the old prepared leaf before new publication. Owed returns continue blocking reuse until physical settlement. |
| Stale completion | Authenticate owner generation, root generation, request sequence and physical generation. Reject without mutating the live successor or peer; retain/reconcile custody against the original owner. Numeric MM or VA reuse never suffices. |

`carrick-kernel/src/dispatch/mem/el1_reservations/returns.rs:55` checks host
stock before fork; it does not implement these native transitions. Acceptance
requires two simultaneously live MMs at identical VAs: fork and independently
adopt/write, exec one while the other retains stock, then exit in both orders.
Deliver a stale predecessor reply after successor admission and prove that
neither successor nor peer acquires its bytes or loses its own stock.

### Physical capability and mapping permissions

Main sets inventory permissions from the originating node in
`native_service.rs:908`; adoption in `carrick-el1/src/memory.rs:1035` changes
prepared stage-1 permissions only. That combination is insufficient.

For stock, **NEW `StockPhysicalCapability`** records private zero provenance,
exact allocation identity and physical RWX capability, using the existing COW
physical permission policy. Capability authorizes future inventory operations;
it grants no guest access. Stock inventory is explicitly tagged as unadopted
capability. **NEW `StockAdoption`** authenticates owner, live mapping
incarnation, retained-page mask and capability, then atomically publishes the
mapping's exact inventory access and re-permissions prepared stage-1 leaves.
The adoption overlay and its bounded per-page entries must be ring-owned,
reserved with the refill and updated without a host request or per-adoption
ACK. Export reconciliation in batches at existing service boundaries. Adding
one inventory service per adoption would recreate #898. A per-page adoption
overlay is required where one physical chunk contains mappings with different
protections; changing the whole chunk's permission
field is incorrect. This overlay and its inventory events are **NEW**.

| Adoption | Inventory and descriptor result |
|---|---|
| Read-only origin → RW mapping | Check stock's write capability; publish exact RW adoption; prepared leaves stay invalid until permitted first touch. |
| RW origin → RX mapping | Check execute capability; publish RX adoption, invalidate instruction cache before executable exposure; no writable user alias created by adoption. |
| Any origin → PROT_NONE | Record ownership with no mapping access; keep leaves inaccessible and deny first touch. Later protection changes authenticate the same adoption. |
| Refused adoption | Restore inventory overlay, stock masks, prepared descriptor permissions and root metadata together; stock remains owned by the original MM. Indeterminate undo quarantines and retains custody. |

Test mixed protections within a chunk, both permission directions, PROT_NONE,
and injected failure before/after inventory and descriptor edits. No widening
of the ordinary mapping-bound grant's protection or exact-node check is allowed.

### Bounded capacity and sparse reclamation

The following are **NEW proposed stock limits**, not weakened test budgets.
They require implementation and pressure witnesses before native enablement.
Use a maximum 1 MiB refill, composed of independently releasable 16 KiB chunks
(the existing `COW_GRANT_SIZE`, `carrick-core-abi/src/mm/cow.rs:4`). Batch their
allocation/publication in one service transaction; do not retain a monolithic
1 MiB allocation after all but one page is returned. Multiple chunk identities
in the reply and independently releasable stage-2 leases are **NEW** protocol
work; main's single-data-frame staging does not already provide them.

Per exact MM, allow at most 1 MiB of published unused prepared bytes, one
pending refill of at most 1 MiB, 1024 stock chunk records and 4096 stock-derived page leaves. Charge pending,
committed, retiring and quarantined chunks against the same 16 MiB retained
stock ceiling. Across two MMs these ceilings are 2 MiB published unused
prepared bytes, 2 MiB pending bytes, 2048 records, 8192 leaves and 32 MiB retained. Bytes in
a partly occupied chunk that have been retired are inaccessible padding,
not reusable prepared stock; count them in retained bytes rather than hiding
them from the memory accounting. Descriptor-table pages must be claimed before publication and charged to the existing table ledger;
a refill of 256 pages crosses at most two leaf tables, plus missing ancestors.
Plan actual missing tables rather than assuming that they are preinstalled.

A **NEW `StockResidencyRecord`** retains one chunk identity and a four-page
retained mask separately from its committed/adopted masks. Clear retired pages
in place; do not split a stock record on partial retirement. Thus fragmented
returns require no replacement residency slots. Lookup/overlap authentication
must honor the retained mask, including a new grant in a retired hole. Ordinary
mapping-bound records retain their existing semantics. This is explicit new
work replacing use of main's fragment publication (`residency.rs:724`) for
stock; page-sized descriptors alone cannot establish this property.

The table still has 4096 slots and a 64-probe admission bound (`residency.rs:3`,
`:14`, `:275`). At most 2048 stock records may be charged carrier-wide, leaving
at least 2048 slots outside the stock quota; other consumers may occupy them.
A **NEW `StockCapacityLease`** claims the actual slots in the permitted probe
sets, with exact owner authentication. Global free counts do not imply that a
particular probe set can admit a record. No destructive retire-then-publish
sequence is allowed to discover capacity failure after losing surviving stock.

On moving to a distant window, include retirement of the old window's unused
pages in the next refill transaction. Remove prepared leaves, invalidate,
retire their inventory/residency masks, then release empty chunks only after
stage-2 settlement. Keep adopted or owed pages and their exact chunk custody.
Retired pages are not reusable zero stock without authenticated zeroing. Charge
partially occupied chunks in full, even when only one page survives.

Let L be bytes of adopted or owed stock pages, P pending speculative bytes.
After successful trimming, retained bytes are bounded by `4L + 1 MiB + P`
per MM, also capped at 16 MiB; `P <= 1 MiB`. All unused physical bytes,
including inaccessible padding, are therefore bounded by `3L + 1 MiB + P`,
not just the published stock ceiling. For two MMs the retained bound is
`4(L1 + L2) + 4 MiB`, capped at 32 MiB. Quarantined custody stays charged;
there is no further admission for its MM. Sparse MAP_FIXED touches therefore
retain at most host-chunk rounding per surviving page plus bounded speculative
stock, rather than one retained MiB per touched page. Packed reservations
consume existing stock without host service; refill/trim requests scale with
consumed bytes and window transitions, not each reservation.

If any byte, table, slot/probe or journal reservation fails, shorten the
speculative selection before allocation, down to the existing mapping-bound
selection with its unchanged authenticator. This is a supply-kind choice in
one shared planner/transaction, not a second allocator or host forwarding path.
If even required mapping-bound resources cannot be admitted, preserve the
preimage and report the existing supply refusal; speculative pressure must
never itself become a guest-visible failure for an otherwise serviceable fault.
Do not evict surviving stock, spin, poll, retry until green or raise budgets.

Required pressure witnesses: two live roots with sparse MAP_FIXED pages in
separate MiB windows; alternating-page returns within chunks; adoption mixed
with returns; collision-filled 64-probe sets; slot/table/journal exhaustion;
trim failure and duplicate settlement. Count retained bytes, unused bytes,
records, descriptors and service requests, and assert surviving data and owner
identity after each refusal. Packed 64/256/1024 populations must still meet
the unchanged service slope; sparse populations additionally obey these space
bounds, without claiming the packed slope for arbitrary VA placement.

## Slice 1: landable policy extraction, explicitly intermediate

Name the intermediate witness **NEW
`private_stock_plan_future_holes_are_exact_mm_and_revalidated`**. It exercises
the production shared planner: a small anonymous node selects eligible future
holes, while a simultaneously live peer root at identical VAs remains
independent. Intervening node replacement, pending reservation and owed return
each invalidate the old selection. Include host occupancy exclusions and
bounded fragmented inputs; revalidation must refuse before mutation.

Red-first baseline: assert the selected run extends beyond the small node
using main's `transfer_fault_plan`; it fails because of the clip at
`carrick-core/src/mm/reservation/root.rs:1712`. Then move the existing host
eligibility policy to the production shared planner and route the host caller
through it. This proves reusable policy and authentication, not physical
publication, adoption, lifecycle settlement or service complexity. Keep exact
mapping-bound authentication separately tested and unchanged.

| Files | Scope | Changed lines, including moves/deletions |
|---|---|---:|
| `crates/carrick-core/src/mm/reservation/{root.rs,stock.rs}`; `crates/carrick-core/src/mm/reservation.rs` | NEW bounded stock planner/exclusion inputs and revalidation; existing mapping-bound planner preserved | 650–950 |
| `crates/carrick-kernel/src/dispatch/mem/fault.rs` | Replace policy with shared planner; retain host-specific observations and existing publication behavior | 350–550 |
| Core stock tests; `crates/carrick-kernel/src/dispatch/mem/delegated_tests.rs` | Red/green intermediate witness, pending/owed/occupancy exclusions, two live roots, stale-plan refusal | 700–1000 |
| Design and conformance contract binding | State intermediate guarantee and unchanged native budget obligation | 150–250 |
| **Total** | **No broader native publication** | **1850–2750** |

That is the smallest proposed independently reviewable implementation step,
under ~4k changed lines. It can land only with its intermediate witness green,
existing host stock tests green, and the original native service-budget failure
identified as still open. Open the extraction PR from GitHub main with only
the listed policy changes and intermediate contract binding. Keep this draft's
active failing service witness and its binding unchanged on #1030 until the
native integration makes it green; do not carry an intentionally failing test
into the extraction PR, ignore it, or weaken the signed contract. The extraction
PR must link that outstanding red evidence explicitly. Policy extraction is
not closure of #898.

The complete slope-green vertical change additionally needs the NEW physical
transaction/settlement, chunked reply and capacity leases, masked residency,
adoption inventory overlay and native lifecycle integration specified above.
There is no justified under-4k estimate for that combined change. Plan dependent
slices with their own red-first transaction, capacity, permission and two-MM
lifecycle witnesses; review each file-level estimate before implementation.
Do not enable broader native publication until those owners exist together.

Final closure still requires the existing production-path service witness green
at 64/256/1024, unchanged strict signed exit slope <0.125 with exit-class
attribution, signed readback/zeroing and lifecycle/permission/return gates,
ARM64 Linux differential and exact-artifact smoke/full acceptance. Neither
this documentation revision nor Slice 1 supplies that evidence. No runtime
code changes are part of this revision.
