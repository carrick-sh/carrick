# Anonymous reservation supply: transaction layer

Part of #898, stacked on #1046 (`work/898-supply-s2`). This implements
physical settlement for the existing mapping-bound native backing reply.
It does not enable speculative stock or change the first-touch budget.

## Inventory before implementation

Locations below describe the actual parent tree, for planning this slice;
they are not a permanent source census or a pinned acceptance receipt.

| File / existing owner | Planned change | Estimated changed lines |
|---|---|---:|
| `crates/carrick-hal/src/physical_grants.rs:24` `PhysicalGrantRollback`, `:62` `StagedPhysicalGrants`, `:74` `PhysicalGrantCustody`, `:254` `UnpublishedPhysicalGrant`, `:300` `NativePhysicalGrants`, `:304` `NativeGrant` | NEW `PrivateSupplyTransaction`, `BackingReplySettlement`, `NativeSupplyCustody`, stage/settle/ACK operations; keep uncertain journals in exact-owner custody | 350–550 |
| `crates/carrick-hal/src/fork_stock.rs:867` `ForkStock`, `:822` `NativeDescriptorTableReservation`, `:831` `PendingNativeDescriptorTables`, `:1142` table settlement | Exact-owner failure quarantine, preserving pending tables | 25–50 |
| `crates/carrick-mmu-core/src/aarch64/descriptor_txn.rs:1188` `DescriptorTxnSlot` | Borrow receipt without consuming it before physical/table settlement | 30–65 |
| `crates/carrick-core-abi/src/service.rs:1424` `ServiceTicket`, `:1485` prepared delivery | Report bounded handoff refusal; reserve delivery against cancellation before physical reply visibility | 10–25 |
| `crates/carrick-core-abi/src/mm/grant_slot.rs:13` `PortalGrantSlot` | Expose nonconsuming receipt inspection through shared transport | 10–25 |
| `crates/carrick-vmm-hvf/src/fork_stock.rs:46` `NativeFrameBacking` | Explicit exact-generation stage-2 release, reject nonterminal retirement | 25–55 |
| `crates/carrick-vmm-hvf/src/metadata_grant/native_service.rs:786` supply, `:1382` settlement | Stage before submission; settle physical and tables before receipt consumption; propagate invariant failure | 120–220 |
| `crates/carrick-vmm-hvf/src/metadata_grant.rs:1631` settlement call | Propagate fatal transaction errors to carrier | 2–8 |
| `crates/carrick-kernel/src/kernel/frame_inventory.rs:101` `FrameInventoryAuthority`, `:3508` physical tests | Real inventory two-live-MM refusal/cancellation, applied, stale/duplicate and injected undo/release failure tests | 300–500 |
| `crates/carrick-el1-linux/src/native_process_runtime.rs:315` `NativeProcessService`, `native_process_runtime/service.rs:1400` continuation; `aarch64_process.rs:1525` fault reply | NEW cancellation disposition through the same shared ring settlement path, including terminal checkpoints | 70–130 |
| `crates/carrick-el1-linux/src/aarch64_process_tests/native_fault_supply_tests.rs:228` composed supply; `native_retirement_tests.rs:20` `SupplyBacking` | Wire composed backing path through transaction rather than early retention; explicit test stage-2 release adapter | 100–200 |
| `conformance-contracts/contracts/el1-anonymous-reservations.toml` | Register bounded transaction evidence without changing slope | 1–5 |
| NEW this document | Inventory, implementation decisions and remaining scope | 70–110 |
| **Total** | | **1,213–1,943** |

## Execution and proof

1. Add refusal/cancellation assertions against the real inventory owner and
   capture their failure on the parent behavior (retained backing leaks).
2. Implement exact-owner transaction journal and explicit inventory-then-stage-2
   undo. Unknown undo retains custody and closes admission; no successful ACK.
3. Wire native submit and settlement, preserving the ring's existing descriptor
   and residency undo plus completed translation invalidation. Inspect receipts
   without consuming them until physical and table settlement succeeds.
4. Exercise two live owners, root-incarnation reuse, applied receipt replay,
   cancellation and rollback/release failure. Run focused and required gates.

## Remaining after this layer

Adoption remains: concrete capacity leases before allocation, independently
releasable 16 KiB speculative chunks, stock capability and retained/adopted page
masks, cross-reservation chunk publication, and permission-safe adoption in the
shared ring owners. Those complete the path that can turn the slope green.

Lifecycle remains: unused/adopted stock treatment on fork, predecessor/successor
exec settlement, exit and replacement/unmap, with two simultaneously live
processes and stale predecessor replies. This layer authenticates the current
mapping-bound transaction owner; it does not claim those future stock transitions.

Returns remain outside this layer. Native `CarrierWork` in
`crates/carrick-runtime/src/vcpu_loop/executor/backend.rs:743` does not run
`reconcile_el1_deferred_returns` (#1042). No return capacity or acknowledgement
is inferred from host reconciliation. A future native return settlement must
use the same physical owner before stock can reuse returned pages.

## Implementation decisions

The private physical owner retains each transaction under its authenticated
reply-lane address, exact transaction (including root), owner incarnation and
inventory identity. A completed tombstone stays through synchronous settlement
and is replaced only by a newer authenticated request on that same lane. The
journal population is bounded by the existing residency-slot population and
checked before native allocation; speculative stock capacity leases remain a
later layer. This is not a speculative-capacity admission claim.

The ring's existing `apply_grant` journals descriptors and residency and publishes
its receipt only after invalidation. Inspection leaves the transport non-idle.
Physical undo and explicit exact-generation backend release precede returning
table capacity. Unknown outcomes preserve the remaining physical journal and
pending tables; a permanent supply quarantine prevents ordinary reclaim from
recycling this MM, and the adapter propagates a carrier-fatal error.

Prepared delivery now reserves the service ticket before offering a reply.
Cancellation before delivery settles the unoffered transaction before the
returned ticket is acknowledged. Cancellation after delivery belongs to the
ring continuation, which now withdraws or settles the original reply before
releasing its pending claim, including at an exiting task's checkpoint. Full stock lifecycle settlement remains outside this layer.

Independent review caught the failed-offer ACK ordering and a composed-fixture
table-settlement gap. Refused prepared handoffs now return the pinned ticket;
the real shared HAL coordinator is used by both native and composed paths.
The composed cancellation-after-delivery and missing-table-journal tests exercise
actual ring apply, table ownership and physical settlement with two live MMs.
The failure case preserves the applied receipt and quarantined physical journal
rather than fabricating a successful terminal cleanup.

The obsolete irreversible `retain_backing` API is removed. Its pre-offer owner
refusal tests now use the transaction admission operation. Live inventory rows,
frame counts and publication/table ownership restore their preimage; identity
allocation counters and inventory revisions remain monotone.

The EL1 frame gate initially rejected an extra aggregate buffer. The ring now
retains only a retry verdict across the host settlement crossing; the physical
owner authenticates the full receipt in its retained transport. No frame or
stack ceiling changed.
