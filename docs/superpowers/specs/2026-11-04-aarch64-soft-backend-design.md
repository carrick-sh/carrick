# AArch64 software vCPU and the shared software-machine substrate

Date: 2026-11-04. Status: **proposal for director and independent review**.
Part of [#1236](https://github.com/carrick-sh/carrick/issues/1236).
No implementation is authorized by this document until that review completes.
This extends the [x86 design](2026-10-17-soft-backend-design.md), rather than
replacing its same-ISA x86 plan (#578).

## Decision requested

Build an A64 software CPU that executes the **same `carrick-el1-image` bytes**
as HVF, plus the same generated vectors and maintenance/service trampolines.
Run it on native arm64 Linux and macOS. Move software-machine ownership,
translation-cache lifecycle, physical placement, invalidation and event wake
mechanics into shared crates before either ISA acquires another implementation.
Keep decoding, register semantics, exception entry and interrupt-controller
protocols in the respective ISA crates.

The goal is hosted-runner capacity for real guest execution: `el1_sched`,
`el1_files` and conformance-next, eventually product `--vcpu auto` on hosts
without virtualization. It is not host compilation of the kernel body. A
software result initially supplements the hardware gates; HVF differential
results remain the ARM acceptance authority. Carrick remains experimental and
is not a hardened boundary for untrusted code.

## Evidence and scope

Code citations below are `path:line` at the admitted main
`fc5bf7c2c7003521b10fa2aa1b3188bfe5dae3eb`; they are audit references, not
new line-pinned enforcement inventories. Proposed types and budgets are marked
as proposals. Recheck citations and the actual image disassembly when a slice
starts: Rust source alone does not enumerate compiler-generated instructions.

Read [the x86 assessment #1486](https://github.com/carrick-sh/carrick/issues/1486)
first. Its measurements were a loaded Rosetta experiment, not a native ARM or
Linux throughput forecast. Its crucial distinction still applies: component
fixtures are not a real carrier-image boot. Current code supports that:

| Existing evidence | Consequence for this design |
|---|---|
| `crates/carrick-el1-image/src/lib.rs:4` embeds the built binary; `crates/carrick-el1-image/build.rs:344` extracts it with objcopy | Both providers consume one build output; record its hash, not merely the source revision. |
| `crates/carrick-softcpu-x86/src/cpu.rs:532` plans blocks; `:596` emits; `:599` publishes them | #616 caching is prerequisite to a practical lane. Do not import the old document's performance estimates as measurements. |
| `crates/carrick-kernel/src/page_profile.rs:20` declares hardware backend variants; `crates/carrick-embed/Cargo.toml:90` and `crates/carrick-conformance-next/Cargo.toml:50` register signed-HVF test lanes | Provider selection and portable harness registration are still work, not capabilities this PR delivers. |
| `crates/carrick-aarch64/src/vmm.rs:251` defines `Aarch64Vcpu`, `:620` defines `Aarch64Vmm`; `crates/carrick-aarch64/src/engine.rs:376` owns the shared trap engine | Implement these ARM mechanics without creating another dispatcher or scheduler. These traits alone do not make the production persistent carrier portable. |
| `crates/carrick-vmm-hvf/src/trap/persistent_executor.rs:7` starts an HVF-specific mapping descriptor, `:737` defines `ThreadSpec`; `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs:1074` runs HVF | Extract carrier lifecycle and backing custody by move, leaving HVF resource operations in adapters. Porting only a bring-up engine cannot satisfy #1236. |

Clean-room authorities: the [Arm A-profile ARM, DDI 0487](https://developer.arm.com/documentation/ddi0487/latest/)
(register pseudocode, exceptions, memory model and translation), the
[Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
for existing x86 obligations, and Carrick's own source and differential
fixtures. No QEMU or other copyleft implementation source. Decoder dependency
licensing and generated-table provenance must be reviewed before admission.

## One substrate for both ISAs

The following are **proposed boundaries**, not new copies of current code:

| Owner | Shared responsibility | ISA responsibility outside it |
|---|---|---|
| `carrick-softmmu` (`no_std` + alloc) | Authenticated physical extents, placement, TLB storage/probe/invalidation, code-frame generations, retirement venue | x86 and ARM walker adapters and access-context construction |
| New `carrick-softcpu-core` | Cache key/dependencies, bounded cache admission/eviction, publication pins, safe-point/event protocol, structural counters | A64/x86 decoder, planner, emitter, context layout and exception delivery |
| `carrick-vmm-soft` | Machine lifetime, backing inventory transactions, vCPU membership, wake registration and clock/deadline transport; platform JIT allocator behind one host interface | Typed ARM and x86 CPU adapters, GIC and APIC models |
| Existing neutral runtime/core layers | Provider selection, executor pool, continuation custody, cancellation, neutral retirement authority | Register marshalling and genuine ISA entry/return mechanics |

The shared core must have no dependency on `carrick-softcpu-x86`, HVF or KVM.
`carrick-vmm-soft` is the one backend crate with ISA modules/feature closures,
not separate soft backends per OS or ISA. Avoid an untyped universal register
bag: ARM and x86 snapshots remain typed. ISA carrier code can remain in an
ISA crate only when it handles register frames, vectors, stacks or transport
instructions; process lifecycle and inventory decisions belong to neutral
owners. Existing Linux behavior stays in the shared kernel/personality code.

### Physical memory and TLB

Today `crates/carrick-softmmu/src/placement.rs:113` supplies an x86 hole set,
`:164` makes it the default; `crates/carrick-softmmu/src/domains.rs:4` exports
x86 descriptor types, and `crates/carrick-softmmu/src/walker.rs:7` binds the
walker to x86. `crates/carrick-softmmu/src/tlb.rs:17` encodes CPL/AC and other
x86 mode bits. These are explicit extraction sites.

Preserve authenticated GPA → host placement as the only conversion. Supply a
machine layout explicitly: x86 supplies its xAPIC hole; ARM supplies the GIC
reserved ranges (see `crates/carrick-mem/src/memory.rs:853`) and exact carrier
extents. Guest VA, stage-1 output IPA, inventory frame and host VA remain
separate domains. Admission must first prove that one checked host reservation can cover the
carrier's actual physical address span on each OS, including high control
extents. Report the achieved span and fail before boot if it cannot fit; do
not assume that a 40-bit IPA setting guarantees a 1 TiB host reservation.
Move backing allocation into the machine placement owner so existing host
pointers are not silently treated as linearly placed RAM. Preserve identity
and rollback when adapting the carrier inventory.
Sparse reservations commit only populated physical extents;
never reserve/commit an arena per guest MM or map guest VAs into the host.
Mac host allocation granules can be 16 KiB while guest stage-1 leaves are
4 KiB; align physical backing to the host and authenticate accesses at the
guest leaf and owner-generation boundary. Preserve shared compound backing
and transactional rollback across fork and replacement.

Proposed walker boundary: typed access request + ISA context → authenticated
leaf (output, span, permissions, attributes) or typed architectural fault.
Share extent authentication and TLB storage, not x86 permission rules. ARM
context includes TTBR0/1 roots and owner generations, ASID plus reuse
generation, EL, PAN/UAO, TCR/SCTLR permission regime and access kind. Either
encode all permission-affecting state in an opaque typed context identity or
flush on a context mutation; never pack ARM state into CPL/AC bits. TBI
normalization is ARM policy, not x86 canonical-address checking. Root/ASID
changes must not reuse an entry from another MM with the same numeric ASID.

Start with the image's 4 KiB, 48-bit TTBR0/TTBR1 regime from
`crates/carrick-mem/src/arch_sysregs.rs:23`. Reuse and extend
`carrick-mmu-core::aarch64` for descriptor decoding, terminal blocks and
permission rules (`crates/carrick-mmu-core/src/aarch64.rs:302`, `:567`). Its
`walk_descriptors` at `:1870` is **diagnostic**, not a complete CPU walker.
Add a hardware-access walker there over live authenticated descriptor loads;
include table-level restrictions, AF handling, address-size/translation/access/
permission faults, PXN/UXN, alignment, TTBR selection and exact fault level.
Do not call the x86 walker or treat `permits_el0` alone as an EL1 permission
model. Unsupported translation regimes must fail closed with diagnostics;
they cannot silently fall back to host memory access.

### Translation cache and budgets (#616)

Implement lifecycle once in `carrick-softcpu-core`; both emitters supply code
and typed entry metadata. Proposed key: ISA/feature view, physical code-frame
identity and owner generation, code generation of **every fetched page**,
start offset, guest virtual PC when relocation requires it, and translation/
privilege context. Sharing by GPA alone is wrong after frame reuse; sharing
PC-relative code by physical offset alone is wrong across aliases. Cache
entries retain dependencies on all pages a block spans. Entry guards check
context and generations before executing or following a direct link.

Use bounded capacity and explicit eviction with execution pins. Retire links
and executable storage only after all possible users have acknowledged the
existing neutral retirement authority. Publish once per admitted block version;
never toggle W^X on a cache hit or overwrite storage another CPU can execute.
Concurrent misses deduplicate publication without holding a global lock while
guest code runs. Busy retains the request and enrolls on the owner's release
notification; it is not a guest errno or fatal condition.

Proposed red-first contract `softcpu.translation-reuse` for #616: at 1, 32 and
1024 executions of one warm block with unchanged context and no eviction,
`decode_count == emit_count == publish_count == 1`; warm cache lookup performs
zero decoder/emitter work and no code-allocation permission changes. Count
walks separately: misses plus required entry authentication, not an impossible
zero-walk claim under intentional TLB conflicts. Add adversarial multi-page
blocks, aliases, mixed widths, code-write and root-reuse controls. Measure
capacity scaling and account for evictions explicitly; counters cannot hide
retranslation as a hit. Native paired A/B is separate from these deterministic
budgets. Production executable-cache activation, including the existing x86
consumer, depends on the code-edit and peer-publication protocol below. The
cache core can land first; it cannot expose cached execution before #601/#684
are resolved. This dependency also applies before enabling direct links. The current re-emission path is the required red witness, using the
production `step_block`, not a test-only cache helper.

### Code publication, shootdown and reclamation

Reuse `crates/carrick-core/src/mm/retirement/invalidation.rs:217` member seats,
`:389` staging and `:563` pending invalidations. Soft MMU already consumes that
owner (`crates/carrick-softmmu/src/retirement.rs:1`); #607 is closed. #681's
remaining backend migrations do not license a new ARM epoch coordinator.
Preserve the current `softmmu.x86.physical-retirement` contract and add an ARM
binding before changing its scope. Its no-RMW steady-state and linear peer
visit requirements remain obligations, not implementation suggestions.

#601 and #684 remain distinct open obligations. Current code-page operations
are `crates/carrick-softmmu/src/walker.rs:663` (mark) and `:698` (write).
Route first executable publication through registered peers, including every
writable alias; explicit local TLB slices cannot prove peer coverage. A
synchronized mark is idempotent. Track affected frame/slots or deferred
frame-keyed work so unchanged fetches do not scan every peer write plane.

Proposed code edit protocol: reserve exclusive edit authority for the exact
frame incarnation, prohibit new executable entries, request peer safe points,
retire executable links and stale writable aliases, and await acknowledgements
without occupying guest execution capacity. Then perform the write, publish
new bytes before the completed generation, and release admission. A decoder
must validate a stable generation before and after fetching bytes. Never
announce a new generation before the store. All writes participate: translated
stores, atomics, DC ZVA, DMA-like host copyout and loader/service publication.
ARM IC/DC maintenance and DSB/ISB must order guest instruction visibility; a
conservative stronger invalidation is allowed only if differential tests prove
the supported self-modifying-code contract. Host I-cache synchronization of
emitted code is a separate publication duty.

TLBI VA/ASID/all and inner-shareable broadcast decode in ARM mechanics and
become requests to this same owner; x86 INVLPG/CR3 remain x86 mechanics. A
parked CPU serves debt before its next probe, and a running requester serves
itself rather than waiting on itself. Completion is proof before reuse. Test
two live CPUs: writable alias → executable publication; write → peer branch;
root retirement → GPA reuse; code version replaced while a peer has a direct
link. Require no stale bytes, exact participant acknowledgements and bounded
frame/peer visits. Missing, dropped or overflowed measurement fails closed.

### Backend selection, kicks and timers

#671 must become a shared provider-selection/backend integration stack, rather
than bake `SoftX86Cpl0` into every neutral decision. Model execution identity
as existing guest architecture/carrier plus `VcpuProvider::{Hardware, Soft}`;
resolve once and carry the typed plan through CLI, spec, runtime and embed.
Use `--vcpu hardware|soft|auto`, CLI over `CARRICK_VCPU`, default auto. Keep
`--exec-backend hvpatch` orthogonal. Hardware recipes explicitly require
hardware. Auto chooses soft on known absence of usable virtualization, not
permission errors, entitlement errors or failed VM creation. On macOS,
capability detection must distinguish hosted unavailability from HV_DENIED;
if it cannot, fail with a diagnostic and allow explicit soft. Never turn a
signed test failure into a soft pass. Provide the exact `CARRICK_SOFT_VCPU=0`
opt-out to disable automatic soft selection; explicit conflicting requests
fail validation. The older document's `CARRICK_VCPU=hardware` remains explicit
provider selection, not an exact `=0` hatch.

One event mailbox/wake generation per vCPU handles kicks, retirement debt and
clock deadlines; APIC/GIC decide architectural delivery. Check before entry,
at every bounded translated block/backedge and before parking. Link chaining
cannot bypass checks. Enroll → probe → park closes lost wakeups. A parked CPU
waits on its existing release/event notification with the next deadline;
never busy-poll or hold an executor lease for another guest task. Maintain
separate host cancellation and guest IRQ state. ARM uses existing
`crates/carrick-aarch64/src/owed_kick.rs` custody; do not clear an owed kick
merely because a block or HVC exits. A masked pending IRQ can wake WFI while
delivery still waits for the architectural unmask. Test kick-before-park,
kick-during-enrollment, masked WFI, timer rearm/cancel and peer shutdown.

Use one machine monotonic tick domain for virtual counters and deadlines;
frequency/offset and snapshots must agree with vDSO reads. Host timers only
wake the software loop. They do not implement guest task scheduling. Fake
clocks in tests produce deterministic boundary observations; production uses
host monotonic time, not instruction counts and not slowed/frozen guest time.

## AArch64 mechanics

### Decoder, translator and host execution

New `carrick-softcpu-aarch64` owns a clean-room fixed-width A64 classifier,
block planner, emitter, register file and exception machinery. Native arm64
can copy through approved EL0 arithmetic/SIMD instructions **after relocation
and register handling**; it cannot run an untouched guest EL0 block safely.
Every memory operand needs soft translation/permissions, guest PC-relative
addressing needs relocation, branches target translated entries, and all
system/trap operations need classification. The host is always EL0 even when
the simulated CPU is EL1. The same translator executes kernel arithmetic.

Trap/emulate SVC/HVC/SMC, ERET, MRS/MSR, AT/TLBI, IC/DC, WFI/WFE/SEV,
privileged PSTATE changes, and feature-dependent operations outside the
advertised view. TPIDR_EL0 and counter reads are virtual state, never host TLS
or raw host time. Preserve guest x0–x30, both SPs, NZCV/PSTATE, V0–V31 and
FPCR/FPSR; host ABI scratch conventions cannot leak through a helper. SIMD is
needed for EL0 even though the image build audits its own generated SIMD
(`crates/carrick-el1-image/build.rs:211`). Pin a conservative A64 feature view
and expose only implemented semantics and supported host instructions;
SVE/SME/MTE/PAC/BTI need explicit support or exclusion, not accidental host
execution. Census the actual image, generated stubs, musl/glibc startup and
selected probes; an allowlisted decoder is not a completeness claim.

Loads/stores, pair accesses, unaligned/page-crossing accesses and atomics need
precise effects and fault PCs. Do not reuse x86's split-lock atomicity loss.
LDXR/STXR reservations and LSE operations must operate on exact translated
physical identities; helper calls break host exclusive sequences. Implement
one physical reservation/write protocol for exclusive monitors, aliasing,
ordinary writes and host writes, with bounded contention suspension. CLREX,
exception transitions, faults and CPU teardown invalidate reservations as
required. DMB/DSB/acquire/release must survive lowering: arm64 copy-through
alone does not prove a faithful guest memory model when glue inserts ordering.
Differential litmus tests expose both missing ordering and excessive ordering
that masks a kernel defect; hardware remains necessary for weak-memory bugs.

### Image register and privileged-access inventory

This is the starting implementation surface, grounded in current image code
**and host/generated setup**, not a claim that all registers are directly
accessed by the Rust image body:

| Register/instruction group | Actual access / setup evidence | Software obligation |
|---|---|---|
| SCTLR_EL1, TCR_EL1, MAIR_EL1 | Bootstrap values `crates/carrick-mem/src/arch_sysregs.rs:19`, `:42`, `:72`; HVF marshalling `crates/carrick-vmm-hvf/src/trap/stage2_backend.rs:1205` | Store architectural state; enforce translation, alignment, TBI, cache/permission controls for the supported regime. |
| CPACR_EL1, CNTKCTL_EL1 | Host snapshot/restore `crates/carrick-vmm-hvf/src/trap.rs:7970`, `:8015`; FP bootstrap `crates/carrick-mem/src/arch_sysregs.rs:101` | Enforce FP/SIMD and EL0 counter access controls; preserve them across snapshots. |
| TTBR0_EL1, TTBR1_EL1 | Image root read `crates/carrick-el1/src/isa/aarch64.rs:46`; scheduler writes `crates/carrick-el1/src/sched/hw.rs:141` | Root and ASID switching, permission-context invalidation; never infer MM from a host PID. |
| VBAR_EL1, ESR_EL1, FAR_EL1, ELR_EL1, SPSR_EL1, TPIDR_EL1 | Vector base `crates/carrick-mem/src/memory.rs:234`; generated save/restore `:5294`, `:5435`, `:5574`; shim TPIDR `:551` | Per-CPU banked state, exact exception origin and return; nesting must preserve the vector's own saved values. |
| SP_EL0, TPIDR_EL0, TPIDRRO_EL0, CONTEXTIDR_EL1; FPCR/FPSR | `crates/carrick-el1/src/sched/aarch64_context.rs:39`, `:89`, `:111` | Complete task-switch state; no host TLS leakage; real FP state across fork/signal/exec. |
| CNTVCT_EL0, CNTFRQ_EL0, CNTV_CVAL_EL0, CNTV_CTL_EL0 | Image `crates/carrick-el1/src/sched/hw.rs:177`, `:194`; generated clock `crates/carrick-mem/src/memory/el1_clock.rs:42` | One clock view, compare/enable/mask/status, level-sensitive virtual timer IRQ. |
| MPIDR_EL1; ICC_SGI1R_EL1, ICC_IAR1_EL1, ICC_EOIR1_EL1 | `crates/carrick-el1/src/sched/hw.rs:213`, `:226`, `:235`, `:255` | Affinity, target routing, pending/active/EOI, spurious acknowledgement. |
| ICC_PMR_EL1, ICC_IGRPEN1_EL1 | Host GIC setup `crates/carrick-vmm-hvf/src/gic.rs:374`, `:379` | Match configured group/priority behavior; distinguish host setup from image accesses. |
| DAIF, DAIFSet; AT + PAR_EL1 | `crates/carrick-el1/src/sched/hw.rs:406`, `:425`; `crates/carrick-el1/src/file.rs:239`, `:267` | Interrupt masking and architectural address-translation result, including faults. |
| TLBI, DSB, ISB | Generated maintenance `crates/carrick-mem/src/memory.rs:4132`, ASID trampoline `:5743`; SGI ordering `crates/carrick-el1/src/sched/hw.rs:212` | Decode scope and synchronize through the shared invalidation authority. |

Audit ID/cache registers and EL0 access traps alongside this table via
`crates/carrick-vmm-hvf/src/trap/sysreg.rs:36` and ID emulation
`crates/carrick-vmm-hvf/src/trap/cow_engine.rs:5799`; reconcile auxv HWCAP
publication at `crates/carrick-mem/src/memory.rs:6686` with the software feature
view instead of copying the hardware view wholesale. Advertise no feature without
matching execution and HWCAP/ID-register views. PSTATE PAN is load-bearing:
`crates/carrick-mem/src/memory.rs:3388` documents HVF's bootstrap behavior and
page permissions; `crates/carrick-mem/src/arch_sysregs.rs:13` distinguishes it
from KVM. Emulate the chosen HVF-compatible PAN/SPAN and execute permissions,
including its configured feature view; do not perpetuate the source comment's
broad architecture-version claim as authority for feature detection. UAO is
not established as a directly accessed dependency by these sites. Initially
keep it disabled in the advertised view, reject unsupported writes/operations,
and verify unprivileged LDTR/STTR access behavior; if census requires UAO,
implement it and extend the permission-context tests before boot admission.

### Exceptions, vectors and HVC exits

Model EL0t and EL1t/EL1h, selected SP, PSTATE masks and banked exception state.
SVC saves the next PC; aborts preserve the faulting PC and exact ESR/FAR.
Select VBAR slots for origin EL/SP and sync versus IRQ, execute the original
vector bytes, then emulate ERET with validation. EL0 data/instruction aborts
must reach ring fault handling before host lowering where that is what the
hardware image does. EL1 abort/fixup and stack guards must work too
(`crates/carrick-mem/src/memory.rs:4466`). A software unsupported encoding is
an architectural undefined exception with an explicit coverage diagnostic,
never a successful skip or host signal-based emulation.

HVC terminates translated execution into a typed transport exit; no simulated
EL2 kernel is needed for the Carrick protocol. Move the common HVC protocol
handling out of HVF rather than copying its loop: current decoding is
`crates/carrick-vmm-hvf/src/trap.rs:8464`, `:8625`, `:8645`, `:8887`.
Map to existing `Aarch64Exit`/service custody without losing live versus saved
PC provenance (`crates/carrick-aarch64/src/vmm.rs:54`).

| Immediate | Existing role and evidence | Required treatment |
|---|---|---|
| 0 | SMCCC/legacy, `crates/carrick-mem/src/memory.rs:517` | Implement admitted protocol calls; reject unknown calls explicitly. |
| 1 | Maintenance completion, `crates/carrick-mem/src/memory.rs:520` | Completion after actual invalidation acknowledgements. |
| 2 | EL0 syscall/fault forwarding, `crates/carrick-mem/src/memory.rs:524` | Authenticate mailbox and original ESR; preserve registers and return PC. |
| 3 | Unexpected EL1/fatal, `crates/carrick-el1/src/isa/aarch64.rs:657` | Preserve diagnostics/guard attribution and fail the run. |
| 4 | EL0 IRQ kick boundary, `crates/carrick-mem/src/memory.rs:536` | Settle existing owed-kick custody exactly once. |
| 5 | Idle, `crates/carrick-mem/src/memory.rs:538` | Release execution capacity; park with event enrollment. |
| 6 | Metadata/service grants, `crates/carrick-el1/src/isa/aarch64.rs:63`, `:94`, `:329` | Reuse authenticated host service operations and retained Busy handback; not a syscall bypass. |
| 7 | Host-driven service completion, `crates/carrick-el1/src/isa/aarch64.rs:54` | Complete the same service record, separate from maintenance accounting. |

### Timer and interrupt controller

Implement the minimal configured GICv3 subset, not an invented "IRQ pending"
boolean. Match the CPU interface above and the host-configured distributor/
redistributor state; keep their reserved IPA ranges out of RAM placement.
Model Group 1 enable, priority mask, pending/active state, level timer source,
SGI affinity/target lists and EOI. Match the image constants for kick,
reschedule and virtual timer (`crates/carrick-vmm-hvf/src/gic.rs:39`, `:44`),
and its MPIDR affinity scheme (`:102`). Unknown device accesses fail closed.
No ITS, PCI or full board model is needed for the present carrier. New image
accesses extend the model and differential inventory before admission.

The configured timer source stays pending while its compare is expired and
not disabled/masked; acknowledging/EOI alone cannot erase a still asserted
source. IRQ delivery observes DAIF and priority at safe points; WFI wake and
IRQ delivery are separate decisions. Use two live vCPUs to witness reschedule
SGI and timer wake, including interrupt arrival in an EL1 masked section and
late unmask on ERET. A software GIC pass is not an HVF GIC driver pass.

## Host support and executable memory

Native `ubuntu-24.04-arm` and native macOS arm64 are the initial hosts.
The backend feature closure must not import applevisor on Linux or KVM on
macOS. Linux uses RW allocation → cache synchronization → RX publication;
shared published blocks are immutable. Host page size is queried, never
assumed from guest page geometry.

On macOS use one owned MAP_JIT arena and the appropriate JIT entitlement for
the signed host executable/test process, not the hypervisor entitlement. Use
per-thread write protection with scoped restoration before guest execution;
if the hardened callback allowlist is selected, use the callback API instead
of mixing it with `pthread_jit_write_protect_np`. Synchronize host instruction
caches before publishing entry addresses. Follow Apple's
[JIT porting guidance](https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon).
Do not use the x86 per-block mprotect buffer unchanged
(`crates/carrick-softcpu-x86/src/cpu.rs:72`, `:111`). Test W^X failure cleanup,
concurrent execution/publication and executable-page reuse on real macOS;
Linux tests cannot prove this. Hosted jobs need JIT signing only, while
hardware gates retain their hypervisor signing recipes and artifact checks.

AArch64-on-x86_64 requires an interpreter or cross-ISA code generator plus a
memory-order model. Same-ISA copy-through cannot do it, and the x86 emitter
cannot supply it by changing a decoder. Defer it: native hosted arm64 supplies
the capacity goal with much less machinery. Keep shared cache/memory/event
interfaces host-ISA independent so a future measured need can add a translator;
do not ship a stub cross-ISA backend.

## Differential harness and CI admission

Extend one provider-parametric harness in embed/conformance infrastructure.
Use identical EL1 image, generated vector/trampoline, ELF/rootfs and oracle
identities, CPU feature view, topology and fixture inputs. Run soft and HVF
serially on a native ARM hardware host; hosted ARM consumes the same fixture
bundle and records its own soft receipt. Compare architectural checkpoints,
register/memory effects, typed exit sequence where deterministic, Linux output
and fault provenance. Normalize only specified nondeterminism (timestamps,
addresses declared by the fixture), never drop failing rows. Raw exit counts
can legitimately differ between providers; use semantic boundary observations
and separately declared work budgets. Every started test and finished binary
must be accounted for, not only named failures.

Proposed admission order:

1. Hosted Linux/macOS: MMU/cache/event contracts and native instruction
   differential tests (registers, NZCV, FP state, memory and precise faults).
   Native instruction tests may use controlled function fixtures; privileged
   exception behavior requires the hardware image oracle.
2. Exact-image boot, root exit, successor boot, one SVC, one abort and HVC
   services; then two-CPU timer/SGI/WFI and code-write/shootdown fixtures.
3. Small `el1_sched` cases, then full scheduler suite with pool exhaustion,
   lifecycle and two-live-task witnesses; `el1_files` follows with real host
   file crossings; then source-hash-validated conformance-next probe families.
4. Add explicit `soft-arm64` lane registration and itemized receipts, then
   broaden hosted throughput. Existing signed tests must not acquire an
   auto-fallback or retain a misleading `signed-hvf` label on soft runs.

Do not promise a measured runtime. Planning hypothesis after caching is
5–20x HVF for compute-heavy code and potentially worse for ring-heavy cases;
this is a capacity-planning risk, not an acceptance budget or an excuse for
pathological work. #1486's uncached x86 result invalidates any assumption that
Level 0 will be usable. Record paired, interleaved native ARM HVF/soft times
on the same host and the hosted suite duration before selecting CI shards.
Keep existing bounded waits and concurrency; do not stretch timeouts or slow
the guest clock to make software pass. If a suite cannot finish its contract,
report the failed requirement and fix work amplification before admission.

Initially soft receipts are supplementary. Promote a family to hosted semantic
plus structural gating only after a director-reviewed same-image differential
shows the full population and no new failures, on Linux and macOS soft hosts.
An unresolved mismatch blocks that family's promotion. Soft never supplies a
hardware/Docker runtime-ratio verdict. Continue hardware differentials for
CPU/MMU/cache changes, ARM ordering/TLBI, carrier lifecycle, fork custody,
crossing admission and hardware-specific paths. Keep signed HVF smoke and
applicable KVM merge gates; this design does not remove them or close #1236.
New contract IDs/bindings are added red-first with implementation; this doc
changes no guest surface and claims the documentation exemption only.

## Changes to #668–#671 and sequenced slices

#668, #669 and #670 are already closed; do not pretend they are pending neutral
implementations. Their MSR/IDT/APIC semantics stay x86-specific. Extract only
shared concerns: #668's execution/storage lifecycle and typed safe-point
protocol; #669's pending-event transport and test observation infrastructure,
not a common exception-frame format; #670's clock/deadline/wake plumbing,
not a universal interrupt controller. #671 is open and must change shape now:
one provider resolver, one soft-machine inventory and two typed ISA adapters.
The x86 production-carrier move/generic boot remains prerequisite, as #1486
explains; ARM persistent-carrier portability is an additional required slice.
#616, #601 and #684 are shared substrate work, not x86-only optimizations.

Each row is an issue-sized deliverable, split further before exceeding ~4k
changed lines. Follow-up issue drafts are the rows below; publish them only
after design acceptance and deduplicate against the linked existing issues.
No follow-up issues are filed by this worker under the publication restriction.
Interface/lock-order changes require their own reviewed design before code.

| Order / dependency | Slice and owner boundary | Independently reviewable witness |
|---|---|---|
| S1 first, after this design | ISA-pluggable soft MMU: move x86 domains/walker/mode tags behind adapter; explicit machine holes; keep physical inventory/retirement shared. Add ARM descriptor access walker in `carrick-mmu-core` as a dependent sub-slice if size requires. | Red through production translation entry on two roots with the same VA: ARM RAM at xAPIC GPA works, configured ARM device hole refuses RAM, EL0/EL1/PAN/NX differ correctly; stale root generation refuses. Existing x86 contracts unchanged. No whole guest boot claim. |
| S2 alongside S1 (#616) | Shared bounded cache core/JIT publication without production cached execution; activation is a dependent S2b after S3, adapting x86 production step before ARM emitter. | Production loop red on repeated emits; core lifecycle fixtures first. S2b after S3 makes the production warm budget green, adds multi-page alias/version and capacity controls, and native x86 paired A/B. |
| S3 after S1 and cache-core interface (#601/#684, consume #607/#681) | Shared code-edit and peer-write-plane invalidation, all write venues and direct-link retirement. | Two live CPUs with retained writable alias and running old code, then publication/write/reuse; bounded peer visits, post-store generation, no stale execution. |
| S4 interleave with #671 x86 carrier move | Move portable ARM persistent carrier lifecycle/HVC handling and backing transactions to neutral owners; retain HVF adapters. No Linux routing changes. | Unchanged exact-image signed smoke and scheduler/file failure populations, rollback and Busy-once production witnesses; KVM builds where neutral interfaces change. |
| S5 after S1/S2b | A64 decoder/user translator in separate encoding-family slices; shared cache consumer and native differential harness. | Each family red-first through production step vs native; precise faults, FP/NZCV, cross-page memory, TLS, exclusives and atomics. No fake syscall result presented as conformance. |
| S6 after S3/S5 | A64 EL1 register model, exception vectors/ERET, maintenance/AT; split by register/exception family. | Privileged instruction and generated-vector fixtures under preconfigured architectural state vs HVF; image/stub census and supported HVC/abort return paths. This is not a whole-image boot; that needs S4/S7/S8. |
| S7 after S6 | GIC subset, CNTV, WFI, kicks over shared event transport. | Two-live-vCPU reschedule/timer/masked-wake and kick-enrollment fixtures, identical semantic observations on HVF. |
| S8 after S4/S7, shared #671 resolver | Soft ARM backend over real persistent carrier, CLI/spec/embed provider plumbing shared with x86; platform JIT adaptation is a separately witnessed dependency. | First whole production-image boot on HVF/soft, then static ELF via product `--vcpu soft` on native Linux/macOS ARM with hypervisor unavailable; exact-image smoke, fork/exec/pipe and cancellation, no hardware import in soft-only closure. |
| S9 after S8 | Portable embed/conformance registration, receipts, hosted jobs in small family slices. | Full started/finished population, matching source-hash oracles, signed differential and zero new semantic failures before each family gates. |

S2 core → S3 → S2b activation is a coupled native stack: no intermediate
layer enables executable caching on either ISA without complete write and
peer coverage. Each layer still has its own issue and witness.

S1 is the first independent implementation proposal, not permission to start
it before this design is reviewed. Its ARM permission/hole witnesses must
fail before adapter generalization; it must drive actual `SoftWalker`-level
production access rather than only constructing a new trait in tests. Add an
ARM contract binding with structural counts at three scale points. S1's pure
moves and its new behavior must be distinguished in the PR; preserve the
existing x86 physical-retirement budgets. Run focused crate partitions,
contract-change, authority-debt and applicable Linux/macOS compile checks;
the director owns hardware differential and acceptance at each stack top.

## Risks and review questions

| Risk | Required resolution |
|---|---|
| Persistent ARM carrier extraction is larger than a trait implementation | Identify exact moved ownership and adapter methods in S4's interface review; never clone HVF logic. |
| Software ordering or TLB retention masks a real ARM defect | Differential litmus/retirement fixtures plus continued hardware gates; do not claim universal equivalence from a passing suite. |
| Concurrent code publication exposes stale bytes or frees a running block | S3 before multi-CPU backend admission; exact frame generations, execution pins and neutral completion proof. |
| Atomics or fault fixups lose precise state through helpers | Native and HVF tests with aliases, two live CPUs, guard pages and faulting pair/exclusive accesses. |
| Feature view disagrees with executed instructions or generated image | Census and pin features/HWCAP/ID views together; unknowns remain visible coverage failures. |
| MAP_JIT policy/signing or sparse placement differs on hosted macOS | Native host publication/reclamation and address-span admission tests before scheduling suites; never infer success from Linux. |
| Throughput fails the capacity goal | Cache/structural gates first; measure actual suite closure before CI promotion, not timeout increases. |

Director decisions requested: approve the shared substrate boundaries and S1;
approve the provider-resolution/hatch semantics; approve staged family-level
soft gating with continued hardware truth. Independent review must challenge
these boundaries, the real-image inventory and the first witness. Acceptance
still requires that review and director approval, followed by per-slice issue
publication. This document alone does not establish a functioning ARM soft CPU.
