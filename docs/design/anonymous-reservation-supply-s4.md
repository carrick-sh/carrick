# Anonymous reservation supply: capacity and masked residency

Part of #898, stacked on #1058 (`work/898-supply-s3`). Inventory written
against the actual S3 tree before implementation. This is a prerequisite,
not native speculative enablement or a claim that the slope is green.

## Remaining design inventory and split

The remaining vertical change cannot honestly fit within 4k changed lines.
These are estimates including tests, not promises that existing APIs already
implement the missing obligations.

| Existing owner (S3 location) | Remaining work | Estimated changed lines |
|---|---|---:|
| `carrick-core-abi/src/mm/residency.rs:22` `FrameGrantResidencyIdentity`, `:55` `FrameGrantResidencyPage`, `:68` `FrameGrantResidencyRecord`, `:167` `FrameGrantResidencyRetirement`, `:201` `FrameGrantResidencyTable` | NEW concrete slot leases and masked chunk records, probe/quota pressure tests | 1,200–1,900 |
| `carrick-core/src/mm/reservation/stock.rs:25` `StockExclusions`, `:57` `PrivateStockPlan`; `carrick-core/src/mm/frames.rs:236` `apply_grant`; `carrick-core-abi/src/mm/grant.rs:6` `PortalGrantWindow` | Chunked stock selection/reply and exact root revalidation; mapping-bound fallback | 800–1,200 |
| `carrick-el1/src/memory.rs:700` anonymous editor/stock span, `:993` adoption; `carrick-x86-cpl0/src/anonymous.rs:168` stock span | Shared per-page inventory adoption overlay and permission-safe publication/undo, ISA adapters | 800–1,200 |
| `carrick-hal/src/physical_grants.rs:338` `NativePhysicalGrants`, `:353` `PrivateSupplyTransaction`; `carrick-vmm-hvf/src/metadata_grant/native_service.rs:786` supply | Independently releasable 16 KiB chunks, physical capability, pre-allocation table/journal leases and batched stock settlement | 800–1,300 |
| `carrick-hal/src/fork_stock.rs:868` `ForkStock`, `:1526` predecessor settlement; `carrick-core/src/mm/fork.rs` existing inheritance owner | Parent-only unused entitlement, adopted masks/COW, successor/exit settlement | 700–1,100 |
| `carrick-core/src/mm/reservation/root.rs:125` `DeferredReturn`, `:136` `ReturnSlot`; `carrick-kernel/src/dispatch/mem/el1_reservations/returns.rs:121` reconciliation; `carrick-runtime/src/vcpu_loop/executor/backend.rs:743` native service completion | Native returns through the SAME physical/table transaction owner; sparse trim and exact terminal custody | 700–1,100 |
| `carrick-el1-linux/src/aarch64_process_tests/native_fault_supply_tests.rs` existing production-path witness and two-MM harness | Permission, fork/exec/exit, stale completion, sparse/return/trim and unchanged slope witnesses | 1,000–1,600 |
| Conformance bindings, inventories, docs | Scope and evidence | 150–250 |
| **Total** | **Dependent layers required** | **6,150–9,650** |

Paths in the table are relative to `crates/` except conformance bindings/docs.

S4 implements the first row, plus mechanical use of a shared retained-span
query by existing ISA stock-span adapters. S5 will add chunk transport and
adoption capability/overlay owners. S6 will complete native integration,
pre-allocation table/journal admission, lifecycle, trimming and deferred returns.
**S6 is the planned slope-green layer:** broader native publication must stay
disabled until all those owners compose. If later inventories exceed the cap,
split further without moving enablement ahead of its prerequisites.

## S4 file inventory

| File / existing owner | Change | Estimated changed lines |
|---|---|---:|
| `crates/carrick-core-abi/src/mm/residency.rs:22,55,68,167,201,256,311,672,689,724` owners above and publication/lookup/retirement | NEW `StockResidencyOwner`, `StockPageMask`, `StockChunkReservation`, `StockResidencyRecord`, `FrameGrantResidencyLease`, `StockCapacityLease`; reserve actual probe slots, ordinary publication consumes the same lease primitive; retained-mask retirement in place | 600–1,000 |
| NEW `crates/carrick-core-abi/src/mm/residency/stock.rs` | Stock owner/mask types and bounded batch lease over the same table | 200–350 |
| NEW `crates/carrick-core-abi/src/mm/residency/stock_tests.rs` | Real shared-table pressure, two live owners/root reuse, cancellation, mixed ordinary/stock holes, alternating returns, pinned preclaim/drop/commit, quotas and wire initialization | 600–900 |
| `crates/carrick-el1/src/memory.rs:761` `HardwareAnonymousEditor::stock_span`; `crates/carrick-x86-cpl0/src/anonymous.rs:168` counterpart | Consume shared contiguous retained-span query, never span a retired hole | 10–25 |
| `crates/carrick-el1-linux/src/aarch64_process_tests/native_fault_supply_tests.rs:2890` existing fixture stock-span adapter | Same shared query, no slope change | 5–15 |
| `crates/carrick-el1-abi/src/lib.rs:928,1067,4245` layout fingerprint and frozen hash | Include new stock-word offsets and updated table size in host/image ABI identity | 5–15 |
| `conformance-contracts/surfaces.toml:2047` existing stock surface mapping | Classify the two new residency files under the same anonymous-reservation contract | 8–12 |
| `conformance-contracts/contracts/el1-anonymous-reservations.toml` existing binding | Add capacity/retirement witness, preserve active slope binding and threshold | 1–5 |
| NEW this document | Inventory, split, limitations and proof | 80–130 |
| **S4 total** | | **1,496–2,425** |

## Obligations of this intermediate layer

Claim concrete residency rows in their actual 64-probe sets before physical
allocation; a global free count cannot authorize a colliding grant. Failed
multi-row admission releases all its claims without losing live rows. Claims
stay invisible to guest residency and block overlapping publication. Dropping
a claim cancels it; unknown *physical* rollback remains S3 custody and must
retain its claim rather than dropping it. No allocation is added by S4.

A stock row represents one independently releasable 16 KiB chunk, with an
exact MM/root generation and four retained-page bits. Partial retirement clears
bits in place, preserving surviving committed pages and the concrete row even
when no spare probe slot exists. Lookup, overlap, commit, transfer pinning and
stock-span queries honor the mask. A new mapping-bound grant can occupy a
retired hole. Old page tokens cannot commit or pin retired pages. Ordinary
mapping-bound records retain their existing fragment semantics.

Reserve at most 64 chunk rows per proposed refill, at most 1024 per exact MM,
and at most 2048 carrier-wide. Claimed/live rows share that quota. Sparse byte,
pending-refill, adopted-leaf, table and physical-journal ceilings are still
native integration obligations, not claims made by this residency-only lease.
Quarantined transactions must keep their leases/rows charged. This layer must
not expose stock to a new MM/root generation or transfer unused entitlement.

The existing Linux zero/private semantics and contract
`kernel.el1.anonymous-reservations` apply. Red-first evidence targets loss of
surviving residency on saturated fragment publication. New capacity interfaces
are tested directly against the real table. Signed readback, zeroing and full
lifecycle gates remain required on a signed host; they cannot run on ctb-w3.

## Implementation notes

The existing 192-byte row keeps its committed and transfer-pin offsets. Two
reserved words now hold root generation and retained mask. One initialized
64-byte table tail holds the atomic carrier stock-row counter and reserved
words; table size increases from 786,944 to 787,008 bytes. Reserved rows have
a distinct non-live state and authenticate the whole batch before any commit.
Rejected publication returns the owned lease for physical rollback custody.
Cancellation leaves a reusable tombstone rather than an EMPTY that could hide
a peer's probe-chain insertion. Identity epochs remain monotone.

Independent review caught cleanup after a row became reusable. Retirement now
keeps the row WRITING through dirty-bit and quota cleanup before releasing it
as RETIRED. The concurrent quota test uses real shared-table claims in two
simultaneously live MM owners. These tests prove residency ownership, not
guest execution, native lifecycle settlement or physical data readback.

Self-review additionally found that retirement scans must honor masks, not
just lookup and publication. A pinned surviving stock page initially blocked
retirement of an independent mapping in its retired hole. That focused witness
failed before the fix; all retirement preclaim/cancel/commit scans now use
retained overlap, so the unrelated pin no longer blocks the hole's owner.
