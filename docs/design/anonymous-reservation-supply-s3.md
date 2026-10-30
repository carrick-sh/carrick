# Anonymous reservation supply: transaction layer

Part of #898, based on main after #1073 landed. This implements
physical settlement for the live production mapping-bound native first-touch
backing reply.
It does not enable speculative stock or change the first-touch budget.

## Inventory before implementation

Locations below describe the actual parent tree, for planning this slice;
they are not a permanent source census or a pinned acceptance receipt.

| File / existing owner | Planned change | Estimated changed lines |
|---|---|---:|
| `crates/carrick-hal/src/physical_grants.rs` `PhysicalGrantRollback`, `StagedPhysicalGrants`, `PhysicalGrantCustody`, `UnpublishedPhysicalGrant`, `NativePhysicalGrants`, `NativeGrant` | NEW `PrivateSupplyTransaction`, `BackingReplySettlement`, `NativeSupplyCustody`, stage/settle/ACK operations; keep uncertain journals in exact-owner custody | 350–550 |
| `crates/carrick-hal/src/fork_stock.rs` `ForkStock`, `NativeDescriptorTableReservation`, `PendingNativeDescriptorTables`, table settlement | Exact-owner failure quarantine, preserving pending tables | 25–50 |
| `crates/carrick-mmu-core/src/aarch64/descriptor_txn.rs` `DescriptorTxnSlot` | Borrow receipt without consuming it before physical/table settlement | 30–65 |
| `crates/carrick-core-abi/src/service.rs` `ServiceTicket`, prepared delivery | Report bounded handoff refusal; reserve delivery against cancellation before physical reply visibility | 10–25 |
| `crates/carrick-core-abi/src/mm/grant_slot.rs` `PortalGrantSlot` | Expose nonconsuming receipt inspection through shared transport | 10–25 |
| `crates/carrick-vmm-hvf/src/fork_stock.rs` `NativeFrameBacking` | Explicit exact-generation release or transfer to issuing-MM retirement custody | 25–55 |
| `crates/carrick-vmm-hvf/src/metadata_grant/native_service.rs` supply, settlement | Stage before submission; settle physical and tables before receipt consumption; propagate invariant failure | 120–220 |
| `crates/carrick-vmm-hvf/src/metadata_grant.rs` settlement call | Propagate fatal transaction errors to carrier | 2–8 |
| `crates/carrick-kernel/src/kernel/frame_inventory.rs` `FrameInventoryAuthority`, physical tests | Real inventory two-live-MM refusal/cancellation, applied, stale/duplicate and injected undo/release failure tests | 300–500 |
| `crates/carrick-el1-linux/src/native_process_runtime.rs` `NativeProcessService`, `native_process_runtime/service.rs` continuation; `aarch64_process.rs` fault reply | NEW cancellation disposition through the same shared ring settlement path, including terminal checkpoints | 70–130 |
| `crates/carrick-el1-linux/src/aarch64_process_tests/native_fault_supply_tests.rs` composed supply; `native_retirement_tests.rs` `SupplyBacking` | Wire composed backing path through transaction rather than early retention; explicit test stage-2 release adapter | 100–200 |
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
`crates/carrick-runtime/src/vcpu_loop/executor/backend.rs` does not run
`reconcile_el1_deferred_returns` (#1042). No return capacity or acknowledgement
is inferred from host reconciliation. A future native return settlement must
use the same physical owner before stock can reuse returned pages.

## Implementation decisions

The private physical owner retains each transaction under its authenticated
reply-lane address, exact transaction (including root), owner incarnation and
inventory identity. ACK removes the completed journal; historical heap reply
addresses consume no capacity. The outstanding journal population is bounded
by the existing residency-slot population and checked before native allocation; speculative stock capacity leases remain a
later layer. This is not a speculative-capacity admission claim.

The ring's existing `apply_grant` journals descriptors and residency and publishes
its receipt only after invalidation. Inspection leaves the transport non-idle.
Physical undo and settlement of the exact-generation release obligation precede
returning table capacity. Unknown outcomes preserve the remaining physical journal and
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

## Review correction and interim pin custody

This layer changes the live production `supply_backing` first-touch path,
including reply admission, physical/table settlement and cancellation. It requires
the full signed gate; it is not dormant preparation.

ACK removes each completed reply journal, so historical heap addresses cannot
exhaust admission. Stale guest settlement candidates remain refusals; only an
indeterminate undo fails the carrier. Prepared delivery is serialized by the
service cell. The host mutex is acquired before the object-wait queue; the queue
spans only bounded publication and notification. Cancellation drops it before
stage-2 release and backing cleanup, then reacquires it for ticket completion.
Intake retains metadata outside the queue and revalidates the exact member
before claiming its ticket; payload retention also runs after queue release.
No native-service queue holder acquires ForkStock. Early apply errors also settle the reply before
returning their original error.

The director split owned pending settlement into S3b. In this interim layer,
`DeferredActivePins` and `RetryPending` transfer the unused backing to the
issuing MM's existing rollback owner until MM retirement. This is ordinary
retention, distinct from failed undo custody: it neither quarantines the MM nor
closes later fault admission. ACK certifies the transfer of the release
obligation, not a successful physical-retirement receipt. The unchanged fault
retries through the normal selection path. The retained allocation is released
once when its issuing MM retires, with exact-generation authentication protecting
any reused IPA. The retained token owns an Arc of the exact immutable physical
owner: the existing idle turn may finish stage-2 unmap earlier, while the bytes
and owner generation remain owned through MM retirement. That owner has only a
weak carrier reference and no reference to the backing token or MM custody,
so this retention does not introduce a reference cycle.

The physical retirement producer now exposes `Retired` and typed
`Abandoned(reason)` terminal states. Explicit record removal records abandonment
and retains its publication in the same owner until the existing idle boundary,
which publishes outside owner guards. Producer destruction supplies the fallback. A revoked
enrollment drops a callback already captured for deferred publication. Neither
abandonment nor cancellation fabricates a retired receipt.

S3b will add the exact-MM `PhysicalSettlement` cause, owned Pending continuation,
withdrawn window/outcome custody through ACK, pre-offer pending-ticket custody and
ring cancellation/exit integration. Those semantics are not claimed here.
