# Anonymous supply: native integration inventory and first boundary

Inventory against Slice 1 `edebb7cbbe`, before implementation. This document
does not declare #898 fixed. The full native integration exceeds the review
cap and is split as authorized in the brief.

## Complete vertical integration estimate

| File and existing owner at Slice 1 | Work | Estimated changed lines |
|---|---|---:|
| `crates/carrick-core/src/mm/reservation/stock.rs:25` `StockExclusions`, `:57` `PrivateStockPlan`; `root.rs:466` `Reservations`, `:125` `DeferredReturn` | Bind selection, pending refill and adoption to exact root incarnation; return journal | 400–650 |
| `crates/carrick-core-abi/src/mm/residency.rs:22` `FrameGrantResidencyIdentity`, `:68` `FrameGrantResidencyRecord`, `:201` `FrameGrantResidencyTable` | NEW `StockCapacityLease`, NEW `StockResidencyRecord`; actual probe-set claims and retained masks | 800–1100 |
| `crates/carrick-core/src/mm/fault.rs:159` `select_fault_window`, `frames.rs:211` `serve_grant` | Stock selection, revalidation and atomic descriptor/residency adoption | 500–800 |
| `crates/carrick-hal/src/physical_grants.rs:23` `PhysicalGrantRollback`, `:44` `StagedPhysicalGrants`, `:56` `PhysicalGrantCustody`, `:221` `NativePhysicalGrants`; `threaded.rs:2583` `GuestFrameOwner`, `:2633` `UnpublishedFrameInventoryApply` | NEW `PrivateSupplyTransaction`, NEW `StockPhysicalCapability`, NEW `StockAdoption`; chunk journals and stage/settle backing reply | 700–1100 |
| `crates/carrick-hal/src/fork_stock.rs:1036` `reserve_native_descriptor_tables`, `:1142` `settle_native_descriptor_tables`, `:1200` `cancel_submitted_native_descriptor_tables`, `:1458` `settle_exec_predecessor` | Combined physical/table settlement; predecessor, fork and exit custody | 450–750 |
| `crates/carrick-vmm-hvf/src/metadata_grant/native_service.rs:786` `supply_backing`, `:1369` `settle_native_descriptor_reply`; `fork_stock.rs:14` `NativeChildPhysical`, `:46` `NativeFrameBacking` | Chunk allocation and explicit generation-checked stage-2 rollback/release adapter | 450–750 |
| `crates/carrick-runtime/src/vcpu_loop/executor/backend.rs:743` `finish_native_service` | Route native CarrierWork returns through combined owner | 100–200 |
| `crates/carrick-el1/src/fault.rs`, `memory.rs`; `crates/carrick-el1-linux/src/aarch64_process_tests/native_fault_supply_tests.rs:2691` `anonymous_reservation_first_touch_service_budget`; `native_retirement_tests.rs:18` `PhysicalChild`, `:22` `SupplyBacking` | Native adoption, pressure, mixed permissions, fault injection and two-live-MM lifecycle witnesses; exact entry sites to inventory in their implementing slice | 1800–2600 |
| Design, contracts and bindings | Record bounded intermediate guarantees and evidence | 150–250 |
| **Total** | **Full slope-green change; not this PR** | **5350–8200** |

The last implementation row is deliberately a file-level estimate: its future
types and entry points are not yet selected. No native broadening is safe
until capacity, overlay, masked residency and full lifecycle settlement exist.
The shared neutral owners must serve both ISAs; no second x86 service path.

## First landable part: pre-offer inventory and allocation custody

| File and existing owner | Change | Estimate |
|---|---|---:|
| `crates/carrick-hal/src/physical_grants.rs:23` `PhysicalGrantRollback`, `:44` `StagedPhysicalGrants`, `:251` `publish_cow`, `:289` `retain_backing` | NEW `UnpublishedPhysicalGrant<R>` couples an already staged inventory receipt to allocation custody. NEW internal `FailedPhysicalGrant` retains both on failed rollback. Both existing physical admission methods consume the coupled value. | 120–180 |
| `crates/carrick-vmm-hvf/src/metadata_grant/native_service.rs:776` COW admission, `:901` staging and `:916` early retention | Hold coupled unpublished custody through table admission; transfer only immediately before reply submission; use the same coupled custody at COW admission | 20–40 |
| `crates/carrick-kernel/src/kernel/frame_inventory.rs:3508` `physical_projection_tests` | Actual inventory rollback, two simultaneously live owners, retained allocation on indeterminate rollback | 180–280 |
| `crates/carrick-el1-linux/src/aarch64_process_tests/native_fault_supply_tests.rs:763` COW admission, `:1044` backing staging | Adapt the existing production admission bindings | 5–15 |
| `conformance-contracts/contracts/el1-anonymous-reservations.toml:2` `kernel.el1.anonymous-reservations` | Register the intermediate custody witnesses without changing any budget | 1–5 |
| This document | Inventory, limitations and evidence | 100–160 |
| **Total** | **Pre-offer custody only** | **426–680** |

This is not the proposed full `PrivateSupplyTransaction`, nor a substitute for
`stage_backing_reply` / `settle_backing_reply`. It fixes allocation loss when
unpublished inventory rollback fails, and eliminates early irreversible
retention on table-admission refusal. Clean pre-offer refusal rolls inventory
back before dropping allocation custody. Allocation Drop still requests normal
backend retirement; it does not prove stage-2 release or restore the entire
root/descriptor transaction preimage. Initial allocation/staging errors before
the coupled value is constructed remain outside this boundary.

Remaining parts: capacity leases and masked chunk records; ring-owned adoption
overlay with exact protections; chunked reply protocol; combined stage-1,
stage-2, inventory and table settlement with ACK tombstones; native deferred
returns, trim, fork/exec/exit and stale predecessor replies; finally enable
stock and prove the unchanged packed slope. Each needs its own inventory and
red-first witness before implementation.

Returns are outside this part. Native CarrierWork currently calls
`settle_host_work_boundary` without `reconcile_el1_deferred_returns`; no host
return drain is added here. Enabling stock will require returns through the
same transaction owner, not an independent reconciliation path.

## Contract and verification

Applicable contract: `kernel.el1.anonymous-reservations`. Linux authority:
private anonymous backing cannot be released while still
reachable through the owning MM's inventory. Structural invariant: unpublished
receipt rollback precedes allocation release; indeterminate rollback keeps
both exact identities in existing carrier failure custody. The VM-free
inventory owner is the cheapest capable layer for this intermediate guarantee.
The original reservation service-budget contract remains red and unchanged.

HVF, signed frame/readback/lifecycle acceptance and Docker cannot run on ctb-w3.
No signed or slope-green claim is made by this intermediate part.
