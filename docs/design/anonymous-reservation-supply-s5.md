# Anonymous reservation supply: adoption storage transaction

Part of #898; follows #1064 on `work/898-supply-s4`. Inventory written
against the actual S4 tree before implementation. Incremental landing and the
explicitly ignored service-budget witness follow the owner decision on #898.
The final native integration layer must remove that ignore and pass its
unchanged workload and budget.

## Inventory and next boundary

The originally proposed S5 combined chunk transport and adoption. Actual
transport must replace a single-extent descriptor reply, reserve all table
and physical journal capacity, and transfer independently releasable chunk
custody through S3 settlement. That plus complete adoption is approximately
4,300–6,500 changed lines including failure witnesses. Split before transport
publication: first give the existing shared residency owner concrete,
preallocated per-page adoption storage and an exact-preimage transaction.
This layer does not enable speculative native grants.

| Existing file/type on S4 | Change | Estimated changed lines |
|---|---|---:|
| `crates/carrick-core-abi/src/mm/residency.rs:100` `FrameGrantResidencyRecord`, `:63` `FrameGrantResidencyPage`, `:264` `FrameGrantResidencyTable`, `:423` `record_commit` | Consume four reserved words for per-page mapping incarnations; pack access into the existing stock word; reject commits during adoption/quarantine; keep record size unchanged | 60–120 |
| `crates/carrick-core-abi/src/mm/residency/stock.rs:141` `StockCapacityLease`, `:211` `reserve_stock`, `:327` `retire_stock_fragment` | Initialize concrete adoption storage with the existing refill claim; retire per-page overlay in place, preserving survivors | 35–80 |
| NEW `crates/carrick-core-abi/src/mm/residency/adoption.rs` | NEW `StockPageAdoption`, `StockAdoptionSnapshot`, `StockAdoptionTransaction`; bounded, allocation-free staging, explicit commit/rollback, fail-closed uncompleted/drop state; no physical or descriptor authority conferred | 300–500 |
| NEW `crates/carrick-core-abi/src/mm/residency/adoption_tests.rs` | Real shared-table two-owner tests, mixed permissions including NONE, complete-preimage rollback, pin conflict, stale/foreign generations, retired-hole reuse, quarantine, batch snapshots | 500–850 |
| `crates/carrick-el1-abi/src/lib.rs:1067` ABI fingerprint | Include adoption word offset/encoding identity; frozen hash update | 5–15 |
| `conformance-contracts/surfaces.toml:2047`; `conformance-contracts/contracts/el1-anonymous-reservations.toml:25` | Classify new shared-owner files and scoped witnesses, preserve slope threshold | 10–25 |
| NEW this document | Inventory, boundary and evidence | 80–120 |
| **S5 estimate** | | **990–1,710** |

## What this participant guarantees

Every stock row reserves four page entries before allocation through S4's
actual probe-slot lease. No allocation, host service or per-adoption ACK is
needed to change the overlay. One record can represent different mapping
incarnations and protections, including PROT_NONE; physical capability does
not imply page access. An already adopted page cannot change mapping
incarnation without retirement. Ordinary mapping-bound rows are unchanged.

The caller must hold the exact-MM editor throughout staging and settlement.
The participant claims the row against transfer pins and retirement, saves
all overlay words, stages the complete validated change, and exposes no stable
adoption snapshot until commit. Explicit rollback restores its exact overlay
preimage before reopening the row. Dropping an unsettled transaction retains
its claim and latches quarantine; it never guesses that descriptor undo
succeeded. Quarantine blocks adoption, commit bits, transfer pinning and
retirement. The enclosing owner must retain physical custody as in S3.

This is one transaction participant, not permission to publish descriptors.
The encompassing adoption owner must authenticate the live reservation node,
physical zero provenance/capability, exact owner and retained mask; perform
permission changes and executable cache maintenance; commit root metadata;
then commit this participant. It must roll back every participant before
calling rollback here, or retain all custody on indeterminate undo.

## Work remaining

A subsequent transport layer must add chunked replies, `StockPhysicalCapability`,
and concrete table/physical-journal leases to the existing
`PrivateSupplyTransaction` owner. The adoption orchestration must consume this
participant while authenticating live nodes and publishing descriptors/root
metadata atomically, and reconcile overlays to inventory in batches at
existing boundaries. No stock is enabled by this prerequisite.

The final native integration layer must compose those owners with bounded
refill/trim, fork/exec/exit and stale reply settlement. Deferred returns must
settle through the same physical/table transaction owner; calling a parallel
host return journal from `CarrierWork` is not a substitute. That final layer,
not this storage-only layer, is responsible for removing the slope ignore and
turning it green. Two live native MMs, physical readback and signed lifecycle
verification remain required. Further inventories may split transport from
orchestration, but must not enable broader publication ahead of its owners.
