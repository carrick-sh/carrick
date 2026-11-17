# AArch64 soft CPU stage-1 walker (A2)

Part of #2480. This is an inventory and proposed design, not an
implemented walker. Inventory taken on GitHub main on 2026-11-17. N1 placement
and TLB policy belongs to the x86 soft-CPU lane; this document does not reserve
its implementation or change its interfaces.

## Authority and scope

Architectural authority is the [Arm ARM, DDI 0487G.a, ID011921](https://documentation-service.arm.com/static/60119835773bb020e3de6fee),
downloaded directly from Arm. Relevant sections: D5.1.4 (address tagging), D5.2 (address translation),
D5.3 (descriptors), D5.4.2–3 (PAN/UAO), D5.4.5–6 (permissions), D5.4.9–15
(blocks, AF/dirty management and contiguous), D5.8.2–3 (fault levels and
priority), D13.2 ESR_EL1 (pages 3145–3153), and FAR_EL1.
For EPAN specifically, G.a already defines FEAT_PAN3 in A2.4.3 (pages
A2-76–77), lists it among Armv8.7 additions to earlier extensions in A2.10.3
(page A2-106), describes PAN in D5.4.2 (page D5-2732), and defines
SCTLR_EL1.EPAN bit 57 in D13.2.116 (page D13-3575). Those pages were read
directly in the linked G.a PDF; no later edition is needed for this claim.
This is section-specific verification, not a claim to have verified the entire
Arm ARM or the unimplemented walker.
No external implementation source was consulted; no Linux, QEMU, Wine or
other copyleft source is admissible. Repo code is implementation evidence,
not architectural authority. In particular, comments describing PAN3 as an
instruction-fetch check must not replace the ARM's EPAN data-access rule.

The parent [backend design](../superpowers/specs/2026-11-04-aarch64-soft-backend-design.md)
requires A2 after N1, with exact aborts and PAN/LDTR behavior. Initial profile:
AArch64 EL1&0 stage 1, 48-bit VA, 40-bit output, 4 KiB granule, software AF
management. Feature exposure must be explicit; host capabilities cannot select
semantics. 16 KiB *host* pages must work with these same guest tables. A future
16 KiB guest granule needs separate geometry and witnesses, not reuse of the
4 KiB shifts. No behavior code is proposed by this design.

## Existing mechanisms

All paths below are repository-relative; symbols identify the source without a
line-pinned inventory.

| Source | What already exists | What it does not establish |
| --- | --- | --- |
| `crates/carrick-mmu-core/src/aarch64.rs`: `PageTableManager`, `TableArena`, `TableLocation`, `HostArenaResolver` | Live/offline descriptor editing, multiple arenas, block splits/coalescing, alias output resolution and ownership/publication transactions | Architectural CPU walk with input registers and fault record |
| Same: `indices`, `walk_descriptors`, `walk_descriptors_host`, `terminal_entry`, `terminal_descriptor` | Four levels, shifts 39/30/21/12, 512 eight-byte entries; diagnostic raw walk stopping at invalid/table/block/page | TCR selection, range checks, reserved formats, permission accumulation, syndrome creation |
| Same: `try_translate`, `translate` | Live arena-backed output resolution for 1 GiB L1 blocks, 2 MiB L2 blocks and 4 KiB L3 pages | Access permission or AF checks; must not use `translate_retained_output` for CPU access |
| Same: `LeafAccess`, `terminal_descriptor_permits_el0`, `Stage1FaultKind` | Read/write/execute; leaf validity/AF/AP/UXN check; decode translation/AF/permission FSC class | EL1/PAN/UAO/WXN, hierarchical table permissions, fault level or ESR/FAR construction |
| `crates/carrick-mmu-core/src/aarch64/descriptor_txn.rs` and `owner_fork.rs` | Production edits, private/COW authority, fixed 4 KiB geometry and nG publication | General 16 KiB guest walker or register-driven translation regime |
| `crates/carrick-mmu-core/src/live_descriptor_words.rs`, `descriptor_refusal.rs` | ISA-neutral live descriptor load/CAS/publication interface and refusal vocabulary, already shared by x86 | Need no duplicate ARM descriptor-memory trait |
| `crates/carrick-mmu-core/src/owner_mmu.rs`: `OwnerMmu`, `Aarch64Mmu::translate_with`, `OwnerTranslation` | Four-level authenticated-load walk; decodes blocks/pages, returns output and executable state, checks `terminal_descriptor_permits_el0` when requested; `translate` supplies `LiveDescriptorWords` | Not a register-driven architectural permission/fault walk |
| `crates/carrick-mmu-core/src/aarch64/owner_fork.rs`: ARM `OwnerForkMmu` impl (`is_table`, `split`, `table_word`, `split_table_word`) | ISA-neutral owner calls ARM format/geometry and COW edit hooks | Owner policy is not CPU translation policy |
| `crates/carrick-mmu-core/src/owner_mmu.rs`: `OwnerGrantMmu: OwnerForkMmu`, `execute_grant` | Grant publication inherits `OwnerForkMmu::is_table`; its ARM implementation is in `aarch64/owner_fork.rs` | No separate grant-specific descriptor classifier |
| `crates/carrick-el1-linux/src/mm_portal/maintenance.rs`: `retired_page` | Loads upper tables and retained invalid page output for scrub | Invalid retained output is never a CPU translation |
| `crates/carrick-mmu-core/src/aarch64.rs`: `existing_l3_descriptor`, `existing_terminal_descriptor`, `split_terminal_descriptor`, `PageTableManager::try_translate` | Live edit walks, block/page output decoding and splitting; manager tree traversal/edit paths use the same format | These need the shared format decoder, not another architectural walk |
| `crates/carrick-mmu-core/src/aarch64/descriptor_txn.rs`: `output_mask`, `plan_descriptor_op`, `execute_descriptor_op`; submodules `guest_cow::classify_guest_cow_write`, `copy_window` | Transaction traversal, terminal geometry, COW table descent and page-only copy-window descent | Retained/prepared owner states remain separate from architectural validity |
| `crates/carrick-el1/src/memory.rs`: `ArmAnonymousDecode::next_table`; `crates/carrick-mem/src/memory.rs`: `stage1_hvpatch_page_tables::scope_table` | ARM table classification for neutral anonymous-backing traversal and recursive nG publication | Neither implements CPU access checking |

The following additional consumers are part of the same slice-2 audit. “Keep
owner view” means keep its authentication/software-state policy, **not** keep
an independent format decoder. Every production format extraction below must
use the shared decoder (including its geometry/output helpers).

| Source / symbol | Verified behavior | Slice 2 disposition and reason |
| --- | --- | --- |
| `crates/carrick-vmm-hvf/src/trap/foreign_mm.rs::foreign_stage1_translate` | Four-level pinned-owner walk with VALID/TABLE_OR_PAGE, ADDRESS_MASK, SHIFTS 39/30/21/12 and its own L3 page check/output | Migrate format decode; keep pinned-owner loads and generation receipts as owner-view authority, not CPU permissions |
| `crates/carrick-vmm-hvf/src/trap/foreign_mm/current_read.rs::translation` | Second four-level walk resolves atomic words through the frame inventory and backing generation; checks EL0 AP and reserved L0/L3 forms; computes block/page output | Migrate format decode; keep live-inventory authentication, read-window guards and EL0 owner-view admission |
| `crates/carrick-vmm-hvf/src/trap/cow_engine.rs::require_published_repoint` | Uses manager debug walk and terminal EL0 predicates, then recomputes span as `1 << (39 - 9*level)` and masks output | Migrate span/output decode; keep completed-publication/expected-access validation as owner-view policy |
| `crates/carrick-vmm-hvf/src/metadata_grant/native_service.rs::native_cow_fault_split` | Four-level stock-backed atomic walk, `descriptor & 3 != 3` terminal detection, then `guest_cow::is_guest_cow_write_leaf` and split-table count | Migrate table/terminal/output format decode; retain COW software-bit policy and stock custody in owner view |
| `crates/carrick-vmm-hvf/src/hvpatch_probe_support/kernel_memory.rs`: `indices`, `PA_MASK`, `table_descriptor`, `leaf_descriptor`, `build_parent_tables`, `copy_child_table_path` | Probe-support geometry and descriptor builders/readback, not a general CPU permission walk | Migrate geometry/output helpers; retain probe fixture construction. Exact raw-byte assertions remain independent expected values |
| `crates/carrick-vmm-hvf/src/trap.rs::next_deferred_cow_authentication_page` | Decodes valid block type and L1/L2 span from an already authenticated walk to skip covered pages | Migrate block/span decode; keep COW-arm boundary clipping and conservative invalid-leaf handling |
| `crates/carrick-core/src/mm/frames.rs::grant_page_available`; `crates/carrick-core/src/mm/fork.rs`: `reconcile_parent_page`, `census_entry`, `copy_entry` and recursive table traversal | Generic four-level owner traversals use `B::is_table`/ADDRESS_MASK, calculate spans and block outputs for census, reconciliation and custody | Keep neutral owner-view traversal; route ARM format/geometry/output through shared decoder via owner hooks, including currently inline mask/span calculations. Fork inheritance/retired-state policy stays separate |
| `crates/carrick-el1/src/memory.rs`: `classify_anonymous_range`, `owed_retired_terminals` and recursive anonymous traversal | Consume `AnonymousDescriptorDecode` (ARM binding is `ArmAnonymousDecode` above) | Keep neutral owner-view consumers; migrate the ARM hook, not a second traversal implementation |
| `crates/carrick-vmm-hvf/src/trap/cow_engine.rs`: `materialize_retired_reuse`, `reuse_sole_owner_cow_in_place`, `perform_frame_cow`, `report_physical_cow_source_refusal`, `winner_pte_writable_private`; `trap/foreign_mm.rs` COW publication receipt checks | Page-output masks plus validity/AP/nG/private-state checks over manager/live terminal words, including retained output and diagnostics | Migrate page-output/format extraction; keep owner publication/retained-state predicates and diagnostic reporting. Invalid retained output must remain distinct from CPU validity |
| `crates/carrick-vmm-hvf/src/trap/process_plan.rs`: `build_setup_process_plan` and child receipt checks; `crates/carrick-aarch64/src/engine.rs`: `commit_prepared_host_write`, `live_el1_grant_pages`, `build_process_spec` | Decode terminal page output for diagnostics, copyout/grant publication and fork-COW receipt authentication | Migrate format/output extraction; keep owner receipt and expected-AP/private/nG policy; shared-MM block receipts must use correct leaf span |
| `crates/carrick-mem/src/memory.rs`: `stage1_identity_page_tables`, `stage1_carrier_maintenance_page_tables`, `el1_stack_page_descriptor` | Build table/page/block bytes and stack descriptors; hvpatch recursive nG traversal is listed above | Share format geometry/encoding helpers without changing image bytes; builders are not permission authorities |
| Test/support raw walks: `crates/carrick-el1-linux/src/mm_portal/tests.rs`; `aarch64_process_tests/native_fault_supply_tests.rs`; `crates/carrick-core/tests/aarch64_fork_geometry.rs`; `crates/carrick-vmm-hvf/tests/el1_descriptor_service.rs`; HVF `trap/foreign_mm.rs::invalidate_live_leaf_without_shadow_for_test`, `trap/guest_alias/tests.rs`, `trap/memory_protection/tests.rs`; `crates/carrick-el1/src/memory/live_peer_tests.rs` | Fixture traversal, descriptor mutation or expected-output readback | Audit in slice 2: reusable fixture walkers use shared format helpers; raw expected bytes/negative mutations remain independent test assertions, never production decoders |

Search method used for this revision (source text, not a host-selected build):

```sh
rg -n '0x0000_ffff_ffff_f000|ADDRESS_MASK|\[39, 30, 21, 12\]|descriptor & 3' --glob '*.rs'
rg -n -i 'terminal|walk' crates --glob '*.rs'
rg -n -i '0x0000_ffff_ffff_f000|ADDRESS_MASK|\[39[^]]*30[^]]*21[^]]*12\]|descriptor & (3|0b11)|terminal|walk' --glob '*.rs'
```

Read candidate function bodies and callers, including cfg-macOS HVF files;
case-insensitive follow-up catches uppercase masks and typed shift literals.
The commands cover all tracked crate source regardless of cfg, including
`carrick-vmm-hvf`, `carrick-el1*`, `carrick-mem`, `carrick-hal`,
`carrick-runtime` and `carrick-engine`. TTBR-only root masks (scheduler context,
HAL root publication, EL1 live-root/service-window bindings and HVF root setup)
are not descriptor walkers; x86 PML4/CPL0 walks share some shifts but are not ARM
decoders. Runtime/engine wrappers delegate to the listed manager/owner APIs.
Archived `docs/perf-results` Rust snapshots are historical, not production.
Diagnostics (`debug_walk`, `walk_descriptors_host`) remain format consumers,
not architectural permission authorities.

Limits: this is a textual candidate audit, not a proof against differently
spelled future decoders, generated source or build behavior. Re-run it at the
implementation head and account for every inventory row. A Linux build does
not compile cfg-macOS bodies: slice 2 must run `just cross-check-macos` and a
signed macOS unit shard on its exact head for the migrated HVF consumers.
Extraction must not copy permissive diagnostic behavior into CPU translation.

Decision **(b)**: `Aarch64Mmu::translate_with` remains the Linux-permission/owner
view. It and the architectural walk share **one descriptor-format decoder**
(level, invalid/table/block/page, output mask/span); migrate the listed ARM
format consumers to it in slice 2. Owner software-state interpretation and CPU
fault priority stay separate. No second block/page decoder is accepted.

Long descriptors currently encoded in `aarch64.rs` and the production
`crates/carrick-mem/src/memory.rs::stage1_identity_page_tables` use validity
bit 0; type 11 for a table at L0–L2 / page at L3, 01 for L1/L2 blocks.
AP[2:1] is bits 7:6, AF bit 10, nG bit 11, contiguous bit 52, PXN bit 53,
UXN bit 54. Output masks are `0x0000_ffff_c000_0000` (1 GiB),
`0x0000_ffff_ffe0_0000` (2 MiB), `0x0000_ffff_ffff_f000` (4 KiB/table).
These masks encode fields, not a 40-bit output-address validation.
Software ownership bits 55–59 must retain their current meanings; an invalid
prepared descriptor with retained output remains architecturally invalid.

AP values 00/01/10/11 mean respectively EL1 RW / both RW / EL1 RO / both RO;
EL0 is denied for 00 and 10. The existing leaf predicate checks bit 6 for EL0,
bit 7 for writes, AF, validity and UXN. It does not decode table APTable,
PXNTable or UXNTable. The new architectural walk belongs in this module tree,
reusing shared descriptor rules rather than putting another walk in softcpu.
Contiguous is not an implementation of larger pages: current geometry and
walk results do not validate or combine a contiguous group. Start with single
leaf translations, preserve the hint, and do not widen TLB validity beyond the
proved leaf. No ASID-tagged software translation cache exists here. nG is
encoded for per-MM mappings; ASID allocation and TLBI are caller concerns.

### Actual hardware profile bytes and registers

`crates/carrick-mem/src/arch_sysregs.rs` is the shared register authority used
by HAL `GuestArch::bootstrap_sysregs` returning `Aarch64BootSysregs` in
`crates/carrick-hal/src/aarch64_arch.rs`, HVF staged CPU and
`carrick-vmm-kvm::guest_setup::program_sysregs`;
the EL1 image consumes that configuration rather than choosing a new TCR.

| Register/field | Programmed value |
| --- | --- |
| TCR_EL1 bootstrap | `0x62_bf10_3f10` |
| T0SZ / T1SZ | 16 / 16: two 48-bit address ranges |
| TG0 / TG1 | 00 / 10: **both 4 KiB**, different encodings |
| IRGN0/1, ORGN0/1, SH0/1 | all 11 |
| IPS | 010: 40-bit output |
| TBI0 / TBI1 | 1 / 1 |
| EPD0/1, A1, AS, HA, HD, HPD0/1, TBID0/1 | zero in bootstrap |
| MAIR_EL1 | `0xff`, slot 0 Normal WB; other slots zero |
| SCTLR_EL1 shared base | `0x0400_d005`: M,C,I,DZE,UCT,UCI; WXN and EPAN clear |
| KVM SCTLR | shared base OR SPAN (bit 23), `0x0480_d005`; preserves PAN=0 on EL1 entry |
| HVF SCTLR | shared base, SPAN clear; forced PAN state documented by the backend |

`crates/carrick-aarch64/src/engine.rs::run_idle_entry_on_vcpu` and task-root
setup enable AS (bit 36), making TCR `0x72_bf10_3f10`. Task setup writes
`ttbr = root | (u64::from(asid) << 48)` to both TTBR0 and TTBR1;
idle uses the carrier root with ASID 0. Bootstrap KVM sets both to
`LINUX_PAGE_TABLES_BASE`; HVF staged CPU likewise starts both at the chosen
stage-1 root. A1=0 selects the TTBR0 ASID, independent of which address range
is walked. Root selection must nevertheless use the input range, T0SZ/T1SZ,
TBI/TBID and EPD; equality of the two programmed roots is no license to ignore
TTBR1. With TBI enabled for the access, bit 55 selects the lower/upper
range; canonicality checks the bits below the ignored top byte against the
selected T0SZ/T1SZ range (D5.1.4). TBID can disable tag ignoring for instruction fetch.
Upper and lower roots must be tested with different bytes.

`aarch64/owner_fork.rs::arm_translation_regime_matches_tcr_bootstrap` already
pins T0SZ/TG0/IPS to `TCR_EL1_BOOTSTRAP`: reuse this register-value witness
pattern. HA/HD (bits 39/40) are clear, so AF=0 must fault.

`memory.rs::stage1_identity_page_tables` supplies eight initial 4 KiB tables
plus the editor pool: L0, two L1s, two L2s, L3 null-guard pages, and two tables
for the Rosetta high-VA alias. Low `0..0x10000` is invalid. Ordinary mappings
use 1 GiB/2 MiB blocks, with L3 where necessary. The kernel hole uses AP=00,
UXN=1, PXN=0, AF=1, SH=11; user blocks AP=01, PXN=1, UXN=0 (mmap arena adds
UXN), AF=1, SH=11. Boot leaves have nG=0 and no contiguous hint; private MM
editor paths add nG=1. Table upper permission restrictions start clear.
16 KiB host backing/identity-page capacity is not TG=16 KiB. Root-switch,
private nG, permissions and cross-page tests must use these builder bytes,
including nonidentity aliases, not only hand-authored descriptors.

## x86 assumptions in softmmu and the boundary to extract

| File / symbol | Assumption to retain in the x86 adapter |
| --- | --- |
| `domains.rs` and `lib.rs` exports | x86 descriptor constants, `Access`, `TranslatedLeaf`, `HardwareWalkConfig`, hardware fault classes reexported from x86; `Cpl`, CR0.WP, CR4.SMEP/SMAP, AC, EFER.NXE and stack-access context |
| `domains.rs::SoftCpuException`, `PageFaultInfo`, `PageFaultErrorCode` | #PF vector 14 with P/W/U/RSVD/I bits; noncanonical #GP(0) or #SS(0); ARM cannot convert these records into ESR |
| `walker.rs::SoftWalker` | MAXPHYADDR clamping, NXE setting and effective NXE conjunction; direct call to x86 `translate_leaf_hardware`; explicit x86 fault mapping and COW classification |
| `walker.rs::AuthenticatedDescriptorWords` | Shared root-generation authentication and atomic descriptor access, currently in 4 KiB frames; reuse authority, do not bypass it for ARM |
| `walk_and_fill` / x86 core hardware walk | `update_ad=true`; CAS sets accessed and dirty, bounded retries/exhaustion. ARM HA=HD=0 must fault on AF=0 and never synthesize an x86 dirty update |
| `tlb.rs::SoftTlb` | 1024 slots in three planes, fixed 4 KiB index/crossing, low VA tag bits encode CPL/AC/WP/SMEP/SMAP/NXE. Root identity is not in the tag; caller invalidation is essential |
| `domains.rs::X86Page4K`, `placement.rs::X86HostPage4K` | 4 KiB masks and signed 48-bit x86 canonicality; ARM tagged lower addresses differ |
| `placement.rs::MmioHoles::default`, `x86_default`, `LinearPlacement` constructors | Default xAPIC hole `0xfee0_0000..0xfee0_1000`; ARM must supply its actual device apertures, never inherit the xAPIC default |
| `walker.rs` crossing/leaf handling | Two 4 KiB pieces, x86 canonical end validation, x86 leaf size and output types; same-page warm fast path and large-leaf eviction bookkeeping |
| `retirement.rs` seat/translation entry points | Accept concrete `SoftWalker` and `CpuAccessMode`; preserve paired TLB/seat, domain admission, acknowledgement and root/extent generations during generalization |

Placement, authenticated extents, code-page publication and retirement remain
one shared mechanism. An ARM walker returns an *unauthenticated* stage-1 output;
only the inventory authenticates it and only `LinearPlacement::host` produces a
host address. MMIO never enters the RAM TLB. Descriptor-memory refusal, owner
contention, generation exhaustion and invalid host backing are not guest
translation faults. A modeled guest physical bus failure can produce a table
external abort; host authentication refusal cannot silently impersonate it.

### Smallest proposed per-ISA contract (requires x86 sign-off)

N1 places neutral vocabulary in a new `carrick-mmu-core::stage1` module:
`Stage1Walker`, `WalkError<F>` (guest fault versus `DescriptorRefusal`),
`LeafSpan` and shared `LeafSize`, and the access-direction type. This crate
already owns `LiveDescriptorWords`/`DescriptorRefusal` and is a dependency of
`carrick-softmmu`. The trait has associated `Context`, `Fault`, and leaf result
and a `walk(words, context, va, access)` operation; leaf results expose typed
output/base/span and effective permissions/attributes, never host pointers.
ISA faults remain associated types, not an enum of x86 protection reasons.

Access direction **is `LeafAccess`**, moved from `aarch64` and re-exported
there. Preserve its existing Read=0, Write=1, Execute=2 probe wire encoding
(`hvpatch__stale__stage1__retry`) through an explicit wire conversion with a
compatibility witness. Replace x86 descriptor `Access` with a re-export of
that same type. The inventory must also account for
`carrick-guest-arch::Access`, the R/W/X direction of `FaultInfo::access`,
alongside LeafAccess, x86 Access and the fault-record vocabulary
`carrick-kernel::event_ring::RingAccess` (which also has Unknown). The alias
proposal does **not** cover guest-arch Access: guest-arch is a lower
dependency, so retain it with an exhaustive explicit conversion at the fault
boundary rather than introduce a reverse dependency on mmu-core. RingAccess
also retains its event-wire encoding; do not alias it to LeafAccess. Witness
all three directions and the distinct wire mappings. TLB planes map explicitly Read→0,
Write→1, Execute→2. `LeafSize` moves from `x86::descriptor_txn` to the neutral
module with the old path re-exporting; x86-specific level interpretation stays
in x86. `LeafSpan` carries base/size for eviction without assuming host geometry.

`carrick-softmmu` becomes generic over `W: Stage1Walker`, using **static
dispatch**, never `dyn`. The x86 production facade keeps the name `SoftWalker`
and wraps `translate_leaf_hardware` through the x86 implementation; it
monomorphizes to today's path. The ARM implementation lives in
`carrick-mmu-core::aarch64`. Public x86 names (`Access`, `TranslatedLeaf`,
`HardwareWalkConfig`, `CpuAccessMode`, `PageFaultInfo`, `PageFaultErrorCode`,
`SoftCpuException` and existing constants) stay compatible re-exports from
`domains`/`lib`, preserving `tests/softmmu_contract.rs` and
`carrick-softcpu-x86` imports. Generic seat/retirement/`SoftMmuMemory` plumbing
must preserve paired TLB/seat authority. **No unused `Stage1Walker` trait lands:
x86 is its first production caller in the extraction PR.**

### Cache representation and invalidation decisions

`SoftTlbEntry` is `#[repr(C, align(16))]`, two u64s (`tag`, `addend`),
`SIZE=16`, `TAG_OFFSET=0`, `ADDEND_OFFSET=8`. Tags are the normalized 4 KiB
VA page OR mode bits. x86 bits 0–5 remain byte-identical
(`TLB_TAG_CPL3_BIT`, `AC_BIT`, `WP_OFF_BIT`, `SMEP_OFF_BIT`, `SMAP_OFF_BIT`,
`NXE_OFF_BIT`, each with the `TLB_TAG_` prefix); bits 6–11 are spare. Do not
permit ARM class tags to set all of bits 0–11 together: for the highest
VA page that would collide with `TLB_TAG_INVALID = u64::MAX`. Prefer typed
per-ISA tag newtypes with checked class construction and an invalid-sentinel
noncollision witness over raw u64 class tags. Do not
attempt to pack root generations, 16-bit ASIDs and epochs into this entry.

1. ARM supplies a collision-free permission-class tag in bits 6–11: encode
   current EL0/EL1, PAN and effective unprivileged class (LDTR/STTR with UAO=0
   versus ordinary/UAO-overridden access). Direction selects the existing
   plane. Original execution EL remains in fault context. Normalize the VA
   before tagging, preserving the original VA for FAR. EL/PAN/UAO/access-class
   changes select tags and **never flush**, including syscall entry/return.
   This follows Arm D5.4.2–3: UAO=1 makes unprivileged instructions use the
   executing EL's permissions, including PAN. Exhaustively witness the class
   matrix on warm hits and misses; no collision may grant access.
2. Initially **no ASID retention**. TTBR0/root or ASID writes flush the per-CPU
   TLB, like x86 CR3. TTBR1 writes also flush all three planes, including
   high-half VAs even though TTBR1 is absent from the tag. TCR and SCTLR
   translation/permission controls (M, WXN, EPAN), and TLBI invalidate; changes
   to the admitted feature profile require fresh admission and invalidation.
   ASID/nG tests are initially flush witnesses, not retained-entry tests.
   Conservatively evicting global entries is permitted; nG encoding/decoding
   remains architectural. Retained ASIDs are a later slice requiring an
   explicit entry layout and measured warm-hit cost before approval.

Thus two roots at one VA cannot alias in one TLB: root/ASID/TCR changes flush
that CPU before reuse; peer CPUs own separate TLBs. Shared table retirement
still uses the existing acknowledged cross-CPU invalidation mechanism from
[closed #607](https://github.com/carrick-sh/carrick/issues/607), as required by
the parent N1 row. Root/extent generations stay in inventory/seat authority,
not truncated into tags. These configuration flushes do not replace retirement,
code-publication write-plane eviction, or explicit TLBI on the affected peers.

### Placement and publication

Remove `impl Default for MmioHoles` (currently returns `x86_default()`) in
slice 1. Repository search finds no `MmioHoles::default()` caller outside
`placement.rs`. ARM must explicitly supply holes. Move/alias
`LAPIC_MMIO_BASE_GPA`, `LAPIC_MMIO_SIZE_BYTES` and `with_x86_defaults` under
x86 naming/ownership; keep compatibility aliases for current x86 imports.
This makes the absent ARM xAPIC default a type/API fact.

The TLB translates by `va + addend`, not a host MMU mapping. The 16 KiB host
constraint is on `LinearPlacement` and host backing/allocation, which must
supply individually authenticated 4 KiB guest fragments. Drop the ambiguous
host-protection sentence: permission enforcement is by the exact 4 KiB VA tag,
access plane and class, with crossing accesses resolving both fragments before
writes. A fill must never widen to a host-page-sized permission range. Retain
large guest leaf span for invalidation. Slice 4 extends production placement
and softmmu contract fixtures with guest 4 KiB × host backing 4/16 KiB,
adjacent fragments of different permissions, nonidentity outputs and boundary
crossings; slice 6 verifies actual 16 KiB host backing on hardware. A future
16 KiB guest granule is separately admitted, not implied by this matrix.

ARM initially models instruction/data caches as always coherent. IC IVAU and
ISB must be decoded/ordered so published code is visible, without simulating a
stale instruction cache. Reuse shared `mark_code_page`/`on_code_page_write`
generation and write-plane invalidation, including publication/rewrite tests.
COW classification in today's x86 hardware walk stays x86-specific: ARM reports
a plain permission fault; Linux COW policy over software bits 55–59 remains
with `OwnerMmu`/the owner, never in the architectural walk.

These are concrete N1 proposals requiring x86/director sign-off. Slices **1
and 4 are shared-kernel changes requiring the director and a published
independent review**, not worker-only PRs. This docs-only revision authorizes
no extraction/code commit.

## Access context, PAN, and exception origin

Use separate typed fields for current execution EL, permission regime, access
direction, and instruction access class (ordinary or unprivileged). The decoder
and execution layer passes the latter; it cannot be inferred from a VA or from
current EL alone. Record PSTATE.PAN/UAO, SCTLR.WXN/EPAN, feature availability,
TCR/TTBRs and translation epoch. SCTLR.SPAN changes PAN on exception entry;
that update belongs to CPU state, before the next walk. UAO is cleared on
exception entry and restored from SPSR on ERET when implemented.

* Ordinary EL0 data uses EL0 AP permissions; fetch uses EL0 execute controls.
* Ordinary EL1 data uses EL1 AP permissions and PAN. PAN=1 denies privileged
  data access to an EL0-data-accessible page; with FEAT_PAN3 and EPAN=1,
  EL0 instruction accessibility also participates. EPAN is not a universal
  extra instruction-fetch prohibition. Follow D5.4 and SCTLR.EPAN, including
  effective table restrictions, PXN/UXN and WXN.
* EL1 fetch uses privileged execute controls (including table restrictions,
  PXN, the AP=01 privileged-execute restriction and WXN), not EL0 UXN alone.
* At EL1, LDTR/LDTRB/LDTRH/signed variants and STTR/STTRB/STTRH with UAO=0
  use EL0 permissions and bypass ordinary privileged PAN restrictions in the
  proposed non-VHE EL1&0 profile. With implemented UAO=1 they behave as ordinary
  privileged accesses, including PAN. Do not expose VHE implicitly.

Actual users: `HardwareUserWord::read_u32` and `read_u64` in
`crates/carrick-el1/src/sched/hw.rs` issue LDTR; `file.rs` user copy uses LDTRB
**and STTRB**. A denied LDTR executed at EL1 is a **current-EL** Data Abort,
EC=0x25, even though its permissions were checked as EL0. No UAO write was
found in these paths; that does not remove the need to decode access class.
Unsupported feature settings must be explicitly refused at profile admission,
not silently treated as ordinary LDR/STR.

## Fault result and delivery

Return a typed ARM fault with original VA, faulting subaccess VA, access class,
origin EL, fault kind and level. The ARM exception builder produces ESR_EL1,
FAR_EL1, ELR_EL1 and saved PSTATE; it dispatches through the real vector path.
Do not return a Linux errno or x86 PageFaultInfo.

| Access / origin | ESR EC |
| --- | --- |
| Instruction fetch at EL0 / EL1 | 0x20 / 0x21 |
| Data read or write at EL0 / EL1 | 0x24 / 0x25 |

For A64, ESR=`(EC << 26) | (1 << 25) | ISS` (IL=1). For ordinary scalar
stage-1 descriptor faults in this profile, instruction ISS=IFSC; data
ISS=DFSC plus bit 6 for a write (WnR). ISV=0 for these EL1-target Data Aborts,
so SAS/SSE/SRT/SF/AR are zero; do not populate them just because decode knows
the destination register. FnV=0, EA=0, S1PTW=0, CM=0 and other inapplicable
fields zero. S1PTW is a stage-2-reporting field, not a flag for every table
read. Atomic RMW WnR depends on whether its read would fault first; cache
maintenance needs its own instruction classification and CM/WnR rules.

| Kind | FSC | Level |
| --- | --- | --- |
| Address size | `0x00 + L` | TTBR/base level 0 or offending table/output level |
| Translation | `0x04 + L` | 0–3 |
| Access flag | `0x08 + L` | terminal L1–L3 |
| Permission (AP, table controls, NX, PAN, WXN) | `0x0c + L` | terminal L1–L3 |
| Synchronous external abort on table walk | `0x14 + L` | failing table read level 0–3, only for modeled bus failure |
| Data alignment | `0x21` | no table level; access layer checks as required |

L0 AF/permission faults need LPA2 and are not valid outputs for this profile;
`Stage1FaultKind::from_fault_status` masks with `0x3c`, classifies only
translation/access-flag/permission and returns `None` for address-size and
external aborts. It neither validates the level nor builds the full fault;
alone it is insufficient validation.
Disabled EPD/range failures are translation faults at the architectural start
level; output-address overflow is address-size, not a truncated successful
translation. Reserved descriptor forms (including L0 block/L3 type 01) must
follow D5.3/D5.8 rather than diagnostic-walk permissiveness. Prioritize faults
per D5.8.3: input checks, each table read/format/output check, AF, permissions;
do not mask a translation fault with a later permission failure.

For valid FAR faults, FAR records the faulting virtual address, not the table
IPA or translated output. Preserve the original tagged address alongside the
TBI-normalized walk address: Data Abort FAR includes the tag when tagging is
enabled. For synchronous external aborts with TBI enabled, the top eight FAR
bits are UNKNOWN and excluded from hardware comparisons. For a cross-page
access with only the second page failing, FAR is the lowest address in that
page touched by the instruction, not its starting VA. If different addresses
produce different faults, Arm does not prioritize between those faults; the
soft implementation may choose a deterministic order but the differential
must accept the architecturally permitted outcomes. Preserve the faulting PC for restart (SVC's next-PC
rule does not apply). Example: EL1 LDTR read permission failure at L3 yields
ESR `0x9600_000f`; EL0 write permission failure at L3 yields `0x9200_004f`;
EL0 instruction L2 translation failure yields `0x8200_0006`.

## Ownership search and overlap disposition

Read #2480 and #1906; searched open issues for `carrick-mmu-core`,
`carrick-softmmu` and softcpu, and inspected files of all open PRs on
2026-11-17. The registry has no A2 walker row. Open PR #2343 touches
`carrick-mmu-core/src/x86/copy_window.rs`; #2468 and #2263 concern shared x86
MMU construction/fault ownership but their current diffs do not touch these
two crates. No open PR directly modifies `carrick-softmmu` in this snapshot.
#2471/#2478 touch the ARM decoder, so execution/access-class binding must reuse
their typed decode rather than fork it; #2472 owns CLI census integration.

Direct/adjacent open ownership issues: #1097 (remaining neutral MMU types),
#2462 (inventory-owned cross-page LOCK RMW), #2397 (code activation/reuse),
#681 (shared invalidation), #601/#684 (code publication/write-plane shootdown),
#602 (eviction/work bounds), #603 (CR3/NXE), #649 (placement/cache identity),
#671 and #578 (x86 provider/soft CPU), #2313/#1187/#153 (COW), #2135 (table
stock), #692 (CPL0 shootdown), #1095 (in-ring permission editing), and parent
#1236. Search results also include architecture umbrellas #2075/#237/#553,
#1486, #1879/#1395 and diagnostic consumers #691/#898/#1369/#1846/#1004/#231;
these do not establish a separate ARM walker owner. This is a search snapshot,
not permission to edit another owner's production function. Recheck before
implementation; coordinate N1 with the x86 lane and stack/reuse its extraction
if unmerged. Do not create a parallel placement or invalidation implementation.

## Ordered implementation slices and red witnesses

Each row is a later scoped PR after design review, not an implementation claim.
Neutral means host/ISA-independent crate ownership; ARM algorithms remain in
its `aarch64` module. Tests must call the production API introduced by the
slice. Keep semantic and deterministic work evidence separate from timing.

| Order | Crates and deliverable | Red-first witness / acceptance |
| --- | --- | --- |
| 1: N1 agreement and extraction | x86-owned `carrick-softmmu`, shared `carrick-mmu-core` vocabulary | Pure x86 extraction: existing production facade/contract tests unchanged; byte-identical tag values across the x86 mode matrix and unchanged `SoftTlbEntry::SIZE`, offsets and tag constants; zero additional warm-hit descriptor reads via `SoftMmuMemory::on_descriptor_load` and fixture `descriptor_loads`/`loads()` deltas, zero inventory scans or coordinator locks (reuse #607 retirement). Pure moves recorded separately; no fabricated red for byte-identical movement |
| 2: ARM hardware walk | `carrick-mmu-core::aarch64`; test fixture uses real `carrick-mem` builder | Production entry rejects missing/reserved descriptors, wrong root, output overflow, misaligned block encoding and AF=0 at correct level; demonstrate failures before correction, then exact output/leaf span, four descriptor reads maximum for 4 KiB/48-bit cold walk; no second block/page decoder: account for every production and support row in Existing mechanisms, with owner `translate_with`, editors, all HVF consumers and architectural walk sharing format/geometry/output decode while preserving owner policy; output/EL0/retained-state regressions; `just cross-check-macos` plus a signed macOS unit shard on the exact head for migrated HVF consumers; no descriptor CAS with HA=HD=0 |
| 3: permission and faults | same mmu core; `carrick-softcpu-aarch64` exception builder | AP four-way matrix, table AP/PXN/UXN restrictions, WXN, PAN off/on, EPAN and UAO profile pairs; exact EC/ISS/FSC/FAR examples and combined-fault priority fail before implementation; no successful unauthorized access |
| 4: ARM softmmu binding | x86-approved shared softmmu adapter plus ARM CPU context | Production `SoftWalker::walk_and_fill` through the ARM `Stage1Walker` binding must fail before implementation for two live roots at the same VA and distinct permission contexts; ASID/nG flush witnesses (no retention), distinct TTBR0/1 writes flush high/low hits, TBI bit-55 selection, TLBI/root generation peer acknowledgement; production placement/softmmu guest-4-KiB × host-4/16-KiB matrix with adjacent permissions and crossings; x86 suite still passes; PAN/UAO/EL class changes select correct hits with zero full-flush delta, config changes invalidate; no MMIO TLB fill |
| 5: execution integration | `carrick-softcpu-aarch64`, shared APIs only as agreed | Execute actual LDTR/LDTRB/STTRB plus ordinary LDR/STR/fetch, check current-EL abort versus lower-EL abort, vector/ELR/FAR and restart; second-page fault with first page valid, no unauthorized partial write; two live CPU invalidation and two live MM alias isolation |
| 6: hardware differential | existing fixture/runtime owners, separately authorized paths | Same production image/table bytes on soft and hardware profiles, PAN/UAO/NX/AF/root/cross-page fault records compared with architectural UNKNOWN bits masked; retain population and artifact identities, then signed embed and ecosystem evidence |

Guest surface: stage-1 translation, permission enforcement and exception
records. Existing contracts include `softmmu.x86.tlb-walker`,
`softmmu.x86.physical-retirement`, `kernel.exec.stage1-image`,
`kernel.fork.stage1-image`, `kernel.mm.image-page-permissions`,
`kernel.el1.stage1-publication` and `kernel.el1.mm-exclusive-owner`.
A later semantic ARM implementation needs an explicit ARM contract and
production binding; x86 contract coverage is regression evidence, not ARM
coverage. Linux-visible permissions derive from mmap/mprotect semantics;
architectural table/abort authority is the Arm ARM. Structural invariant:
bounded table work, no descriptor copying/scanning on warm hits, no authority
bypass, no x86 A/D writes on ARM's software-AF profile. Register the future
contract outside this document's fence through the director; if the contract gate
flags guest-surface files, stop and report instead of adding evidence here.

This revision changes only this document and qualifies for the documentation
exemption in `docs/conformance-contracts.md`: no executable semantic or work
expectation changes. No crate was touched; crate tests, lint-domains,
test-touched and full `just ci` are therefore not required for this checkpoint.
Required checks are fmt-check, doc, check-contract-change against fetched main
and authority-debt source-only. Runtime, signed and hardware differential
verification remain future work; this document cannot claim those results.
