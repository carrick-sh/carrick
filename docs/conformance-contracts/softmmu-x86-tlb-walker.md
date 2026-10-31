# Software vCPU linear placement, SoftTlb, and x86-64 walker (`softmmu.x86.tlb-walker`, #580)

Surface: `carrick-softmmu` (`AuthenticatedDescriptorWords`, `AuthenticatedGpa`,
`ExtentTable`, `LinearPlacement`, `MmioHoles`, `SoftTlb`, and `SoftWalker`) and
`carrick_mmu_core::x86::descriptor_txn::translate_leaf_hardware`. Architectural
authority: Intel SDM Vol. 3 §4.5 (4-Level Paging) and §4.10.4 (TLB invalidation).
`LinearPlacement::host` is the single GPA-to-host pointer conversion in the
workspace, accepting only `AuthenticatedGpa` minted by `SoftWalker` through
crate-internal `ExtentTable` authentication via the sealed `PlacementGpa` trait
and refusing MMIO holes (default xAPIC `0xfee0_0000..0xfee0_1000`) and
out-of-span extents. `ExtentTable::remove`, `ExtentTable::replace`,
`ExtentTable::remove_root_generation`, and `ExtentTable::replace_root_generation`
publish a domain-wide invalidation that every seated soft vCPU owes
(`softmmu.x86.physical-retirement`, below), `ExtentTable::set_root_generation`
refuses re-registering an existing root or a root still pending retirement, and
`ExtentTable::expected_generation` refuses unregistered roots (`None`, no
fallback generation). `SoftTlb` provides three 1024-entry direct-mapped planes
(`read`, `write`, `exec`) with 16-byte `SoftTlbEntry { tag, addend }` records
and large-page span tracking so `SoftTlb::evict_va` (`invlpg`) evicts all
sibling 4 KiB slots of a 2 MiB or 1 GiB leaf; `SoftTlb::fill_plane*` are
`pub(crate)` and `Execute` walks fill only `exec` (never `read`, preserving
`CR4.SMAP` on subsequent supervisor data reads). `SoftMmuMemory` does not expose
`LiveDescriptorWords`; `SoftWalker` uses the production
`AuthenticatedDescriptorWords` adapter to perform atomic `AtomicU64` `load` and
`A`/`D` `compare_exchange` directly at `LinearPlacement::host(table_frame) + (pa & 0xfff)`.
It binds `translate_leaf_hardware` in a single pass while enforcing non-present
precedence (`P == 0` ignores bits `63:1`), `MAXPHYADDR` reserved-bit checks on
bits `[51:MAXPHYADDR]`, hardware-ignored bits `11:8` and `62:52`, CR-gated
`EFER.NXE`, `CR4.SMEP`, `CR4.SMAP`, and `CR0.WP` checks, same-word CAS retries
for `A`/`D` bits when `PRESENT`, output address, and permission bits are
unchanged (restarting the walk on a material change and counting every failed
CAS against `MAX_AD_CAS_RETRIES`, with typed `AdCasRetryExhausted` counted in
`SoftWalkerStats`), non-canonical `#GP(0)`/`#SS(0)` and MMIO outcomes, leaf
extent authentication over `[leaf_base, +leaf.size)`, and frame-keyed code-page
write invalidation across explicitly supplied `SoftTlb`s (cross-vCPU code-page
publication is #684, slice 3 of #681).

VM-free bindings in `crates/carrick-softmmu/tests/softmmu_contract.rs` cover
all permission, CR-gating (including `Execute` -> `Read` SMAP isolation), and
fault classes, red-first witnesses against bare `translate_leaf`, 2 MiB / 1 GiB
huge-page authentication and `invlpg` span eviction, hardware `A`/`D` bit CAS
updates (including same-word retry against an ignored-bit-toggling peer,
concurrent `P`-clear walk restart, and bounded `AdCasRetryExhausted` at
`MAX_AD_CAS_RETRIES` against an adversarial concurrent writer flipping
software-available bits `9..=11`), cross-page split accesses, MMIO hole exclusion,
production `AuthenticatedDescriptorWords` `LinearPlacement`-backed atomic access
(rejecting disagreeing raw-PA mappings, retired table frames, and unregistered
roots), `ExtentTable` `remove` / `replace` / `remove_root_generation`
retirements served by both seated CPUs at block entry, frame-keyed code-page
alias invalidation across supplied TLBs, a two-thread
`invlpg` + `mov cr3` shootdown test, a concurrent PTE writer
snapshot-consistency race witness, and structural budget bounds across
`{1, 16, 256}` extents and `{2, 3, 4}` page-table levels.
