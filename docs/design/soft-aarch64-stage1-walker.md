# AArch64 soft CPU stage-1 walker (A2)

Part of #2480, round 1. This is an inventory and proposed design, not an
implemented walker. Inventory taken on GitHub main on 2026-11-17. N1 placement
and TLB policy belongs to the x86 soft-CPU lane; this document does not reserve
its implementation or change its interfaces.

## Authority and scope

Architectural authority is the [Arm ARM, DDI 0487G.a, ID011921](https://documentation-service.arm.com/static/60119835773bb020e3de6fee),
downloaded directly from Arm. Relevant sections: D5.2 (address translation),
D5.3 (descriptors), D5.4.2–3 (PAN/UAO), D5.4.5–6 (permissions), D5.4.9–15
(blocks, AF/dirty management and contiguous), D5.8.2–3 (fault levels and
priority), D13.2 ESR_EL1 (pages 3145–3153), FAR_EL1 and SCTLR_EL1.EPAN.
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
4 KiB shifts. No behavior code is proposed in this round.

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
by HAL `Aarch64::boot_registers`, HVF staged CPU and KVM `program_sysregs`;
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
TTBR1. Upper and lower roots must be tested with different bytes.

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

An associated-type adapter, conceptually `Stage1Walker`, supplies `Context`,
`Fault`, `walk(words, context, va, access) -> Result<Leaf, WalkError<Fault>>`
and a permission-context key for cache lookup. `WalkError` distinguishes guest
fault from descriptor/authority refusal. `Leaf` carries typed output, leaf base
and span, effective permissions, attributes and global/ASID scope; it does not
carry a host pointer. Access direction is a shared read/write/fetch enum,
without exporting it from the x86 descriptor module. Reuse `LiveDescriptorWords`.
ARM's context contains the root-selection registers and feature profile;
x86's wraps its existing hardware configuration. Keep fault construction in
the ISA implementation; no cross-ISA enum of x86 protection reasons.

The cache key must distinguish selected root and generation, ASID/global scope,
translation configuration epoch and permission context. Either key those or
flush when they change, with witnesses; no hash collision may grant access.
PAN, UAO, current EL and unprivileged access class must affect hits as well as
misses. Initially conservative full invalidation on relevant register changes
is acceptable only with a declared bounded contract, not as a fix for stale
identity. Preserve existing root/extent retirement acknowledgement authority.
A 4 KiB cache fragment may represent part of a larger leaf, but the leaf span
must remain available for invalidation. Guest 4 KiB granules on 16 KiB host
pages must not expose an adjacent fragment with different permissions.

The x86 lane must approve type placement, public compatibility exports,
`SoftMmuMemory`/seat API changes, tag representation, fragment geometry, root
selection/authentication and MMIO defaults. These are N1 decisions. An unused
additive trait would neither prove this seam nor have a production red-first
witness. Therefore **no extraction/code commit is justified in round 1**.

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
`Stage1FaultKind::from_fault_status` alone is insufficient validation.
Disabled EPD/range failures are translation faults at the architectural start
level; output-address overflow is address-size, not a truncated successful
translation. Reserved descriptor forms (including L0 block/L3 type 01) must
follow D5.3/D5.8 rather than diagnostic-walk permissiveness. Prioritize faults
per D5.8.3: input checks, each table read/format/output check, AF, permissions;
do not mask a translation fault with a later permission failure.

For valid FAR faults, FAR records the faulting virtual address, not the table
IPA or translated output. Preserve the original tagged address alongside the
TBI-normalized walk address and apply FAR_EL1's architectural tag rules; any
architecturally UNKNOWN tag bits are excluded from hardware comparisons. For
a cross-page access choose the first failing subaccess address, not always the
instruction's starting VA. Preserve the faulting PC for restart (SVC's next-PC
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
| 1: N1 agreement and extraction | x86-owned `carrick-softmmu`, shared `carrick-mmu-core` vocabulary | Adapter contract fails for two roots at same VA and distinct permission contexts; x86 existing contract tests unchanged; zero additional warm-hit descriptor reads, inventory scans or coordinator locks. Pure moves recorded separately; no fabricated red for byte-identical movement |
| 2: ARM hardware walk | `carrick-mmu-core::aarch64`; test fixture uses real `carrick-mem` builder | Production entry rejects missing/reserved descriptors, wrong root, output overflow, misaligned block encoding and AF=0 at correct level; demonstrate failures before correction, then exact output/leaf span, four descriptor reads maximum for 4 KiB/48-bit cold walk; no descriptor CAS with HA=HD=0 |
| 3: permission and faults | same mmu core; `carrick-softcpu-aarch64` exception builder | AP four-way matrix, table AP/PXN/UXN restrictions, WXN, PAN off/on, EPAN and UAO profile pairs; exact EC/ISS/FSC/FAR examples and combined-fault priority fail before implementation; no successful unauthorized access |
| 4: ARM softmmu binding | x86-approved shared softmmu adapter plus ARM CPU context | Same-VA two live roots, ASID/global distinction, TTBR0/1 selection, TBI tags, TLBI/root generation retirement and 4 KiB guest/4 or 16 KiB host geometry; x86 suite still passes; no stale hits after PAN/UAO/EL/config change, no MMIO TLB fill |
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
contract outside this round's fence through the director; if the contract gate
flags guest-surface files, stop and report instead of adding evidence here.

This round changes only this document and qualifies for the documentation
exemption in `docs/conformance-contracts.md`: no executable semantic or work
expectation changes. No crate was touched; crate tests, lint-domains,
test-touched and full `just ci` are therefore not required for this checkpoint.
Required checks are fmt-check, doc, check-contract-change against fetched main
and authority-debt source-only. Runtime, signed and hardware differential
verification remain future work; this document cannot claim those results.
