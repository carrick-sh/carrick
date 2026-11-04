# AArch64 software vCPU for the existing EL1 carrier

Date: 2026-11-04. Status: proposed for director and independent review.
Issue: [#1236](https://github.com/carrick-sh/carrick/issues/1236).
This is a design pass, with no implementation or runtime-equivalence claim.
It extends the [x86 software-backend design](2026-10-17-soft-backend-design.md)
and follows [HAL boundaries](../../hal.md). Implementation and follow-up issue
publication wait for review. The October document's “no code yet” describes
its original snapshot, not today's tree.

## Decision and scope

Build a same-ISA A64 dynamic translator on Linux arm64 first, then macOS
arm64. Execute the unmodified `carrick_el1_image::IMAGE`, including its Rust
kernel body, with the same loader-generated vectors, trampolines, metadata,
page tables and EL0 fixture bytes used by HVF. Calling the ring's Rust body
as host code, replacing SVC with a dispatcher shortcut, or changing its
routing allowlist would invalidate the experiment. Trusted test guests only;
this adds no security-boundary claim.

The architecture has one shared software machine and two ISA engines:

```text
runtime executor / carrier lifecycle / shared kernel
  -> machine provider (hardware or carrick-vmm-soft)
     -> neutral placement, inventory, TLB storage, block cache,
        invalidation authority, event wake and differential receipts
     -> ISA state + decode/lower + exception/MMU permission adapter
        x86: carrick-softcpu-x86       ARM: proposed carrick-softcpu-aarch64
     -> same guest image and loader products as the hardware lane
```

Names below describe proposed ownership, not APIs already present. Keep
Linux services in the existing personality and shared kernel crates. Only
register semantics, instruction lowering, vectors and descriptor formats
belong in ISA-specific modules.

## Ground truth and instruction census

The image build is `crates/carrick-el1-image/build.rs`: it builds the
`carrick-el1` binary owned by `carrick-el1-linux/src/entry.rs`, targeting
`aarch64-unknown-none-softfloat`, then embeds the flat binary. Its linked ELF
and the existing LLVM disassembly/frame-budget pass are the census inputs.
`crates/carrick-mem/src/memory.rs` separately emits executable vector and
maintenance words: scanning only Rust assembly or only the flat image misses
part of the executed machine. EL0 executables, interpreter and vDSO add more.

Before implementing a decoder, slice 0 adds a Rust `carrick debug` census:

1. Decode executable ELF sections using section/symbol boundaries and mapping
   symbols; distinguish literal pools and data from instructions. Decode the
   loader's generated executable spans separately. Record source/build options,
   image and span hashes, compiler and decoder versions, instruction encodings,
   mnemonic/operand classes, system-register encodings and unknown words.
2. Include every ELF in the chosen fixture closure, its interpreter and vDSO.
   Static presence is an upper bound, not proof of reachability. Do not infer
   the minimum subset from inline-assembly mnemonics.
3. Collect dynamic class counts when the translator exists; until then use
   static reachability conservatively. Do not claim a hardware instruction
   trace from HVF exit counters. Record unknown dynamic PCs as a failed census,
   never silently execute them on the host.
4. Publish an artifact report, rather than a new line-pinned source inventory.
   Every compiler/image change reruns it. No instruction counts were measured
   in this design round; the subset below is a source-backed starting bound.

Minimum candidate families: integer arithmetic/logical/bitfield, multiply and
divide, conditional select/compare, ADR/ADRP and literal formation, all direct
and indirect branches/calls/returns, scalar and pair loads/stores (including
pre/post index), acquire/release and exclusive atomics, barriers, SVC/HVC,
MRS/MSR, ERET, TLBI/cache maintenance and WFI/WFE/SEV as encountered. Include
SIMD/FP loads/stores and computation required by the fixture closure; the
kernel's softfloat build does not exclude EL0 NEON or the scheduler's Q-register
save/restore. LSE atomics require explicit lowering or an honestly advertised
feature profile that the unchanged fixture supports. No advertising features
merely because the host has them.

### Actual register and host-exit consumers

These references are to symbols/files, not a fixed line inventory:

| Consumer | Observed accesses / required state |
| --- | --- |
| `carrick-el1/src/sched/hw.rs`, `Aarch64Hardware` | TTBR0/1_EL1, TLBI ASIDE1IS, CNTVCT_EL0, CNTFRQ_EL0, CNTV_CVAL_EL0, CNTV_CTL_EL0, MPIDR_EL1, DAIF; ICC_SGI1R_EL1 (`S3_0_C12_C11_5`), ICC_IAR1_EL1 (`S3_0_C12_C12_0`), ICC_EOIR1_EL1 (`S3_0_C12_C12_1`); DSB/ISB/WFI |
| `carrick-el1/src/sched/aarch64_context.rs` | SP_EL0, TPIDR_EL0, TPIDRRO_EL0, CONTEXTIDR_EL1, FPSR/FPCR and SIMD context |
| `carrick-el1/src/isa/aarch64.rs` | TTBR0_EL1, SP_EL0, HVC 3/6/7 and their register payloads |
| `carrick-mem/src/memory.rs`, vector and maintenance emitters | TPIDR_EL1, ESR_EL1, FAR_EL1, ELR_EL1, SPSR_EL1, DAIF, ERET, TLBI VMALLE1IS and HVC completion/exception boundaries |
| `carrick-vmm-hvf/src/trap.rs`, snapshot/restore, and `carrick-aarch64/src/vmm.rs` | host-configured SCTLR_EL1, TCR_EL1, TTBRx_EL1, MAIR_EL1, VBAR_EL1 and saved register state; these need provider read/write even when absent from image MRS/MSR |

The census must also cover backend initialization of the GIC CPU interface
(SRE, group enable, priority mask and binary point where configured), CPACR,
CNTKCTL and feature-ID/cache registers. Distinguish initialized state from
instructions actually executed. CTR_EL0/DCZID_EL0 and feature-ID reads can
arrive through the non-SVC vector path; use one explicit guest CPU profile.
Unsupported system-register encodings fail with guest architectural semantics,
not a host MRS or a default zero success.

HVC is a typed host boundary, not a guest EL1 exception that overwrites the
saved EL0 syndrome. Preserve the calling register convention, advance past
HVC exactly once and reuse the existing carrier handlers:

| Immediate | Existing purpose |
| --- | --- |
| 1 | stage-1 maintenance completion |
| 2 | mailbox syscall forwarding or non-SVC exception; inspect saved ESR and mailbox, not just HVC EC |
| 3 | current-EL fault / panic, including guard-stack diagnostics |
| 4 | kick boundary |
| 5 | idle with no scheduled thread |
| 6 | metadata/extent grants, stock loans/settlements and lifecycle notifications, distinguished by ABI operation |
| 7 | host-driven EL1 service completion |

These are documented by `carrick-mem/src/memory.rs`,
`carrick-el1-abi/src/lib.rs` and the `is_aarch64_hvc_*` classifiers in HAL.
HVC 0 is not a substitute (SMCCC); unknown calls are diagnosed explicitly.

## Shared layers and changes to the x86 sequence

### Placement and software translations

Refactor `carrick-softmmu`, never fork it. Today `domains.rs`, `walker.rs` and
`tlb.rs` import x86 permission types, 4 KiB geometry and CR-mode tag bits;
`placement.rs` provides xAPIC defaults. Separate neutral extent authentication,
host placement, retirement and TLB storage from ISA page geometry, device-hole
layout, permission context and walker binding. ARM supplies its actual device
layout; it must not inherit a hole at `0xfee00000`. Host page size (often
16 KiB on macOS) is distinct from the image's 4 KiB guest granule. Reserve and
commit host backing at host granularity while preserving guest permissions in
software; never map guest virtual addresses into the host.

Authenticate VA -> stage-1 IPA -> global frame and exact owner generation ->
host address through the existing inventory authority. No GPA masking or raw
addend may bypass owner retirement. TLB tags include or are invalidated on all
changes to root, ASID/incarnation, EL/access type and permission controls.
An initial ARM implementation may flush on root/control changes instead of
retaining ASIDs, but cannot silently alias distinct address spaces. Keep hits
bounded and lock-free; split accesses at guest page boundaries with correct
partial-effect rules.

Use `carrick-mmu-core::aarch64` descriptor decoding/geometry and its shared live
descriptor substrate. `PageTableManager::try_translate` and `walk_descriptors`
are address/debug helpers, not a CPU permission/fault model. Add a hardware
walk entry point there: TCR region selection and address size, TTBR0/1, ASIDs,
table/block/page validity, AP and table restrictions, PXN/UXN, AF and configured
hardware updates, alignment/memory attributes, PAN/UAO and exact fault level.
Unsupported translation regimes are rejected at configuration, never treated
as successful translations. COW remains the ring's abort handling path.

### Concrete reuse and extraction boundaries

| Existing source | Reuse / required change and destination |
| --- | --- |
| `carrick-softmmu/src/placement.rs`: `LinearPlacement::host`, `host_range`, `MmioHoles` | Keep the authenticated placement conversion in softmmu; parameterize host granularity and ISA device layout rather than copying it into ARM. |
| `carrick-softmmu/src/walker.rs`: `ExtentTable`, `AuthenticatedDescriptorWords`, `SoftMmuMemory` | Keep inventory, owner-generation authentication and descriptor reads shared in softmmu; replace only `SoftWalker`'s x86 hardware-walk binding with an ISA adapter. |
| `carrick-softmmu/src/tlb.rs`: `SoftTlb`, `SoftTlbEntry`, `SoftTlbPlane`, `probe`, `flush_all`, `evict_range` | Retain storage/probe/eviction in softmmu, parameterize page geometry and mode tags; x86 permission types stay in its adapter. |
| `carrick-softmmu/src/retirement.rs`: `SoftVcpu`, `SoftVcpuSeat`, `RunningSeat::block_entry`, `PendingRetirement` | Retain seat custody, admission and safe-point service; ARM engine enters through the same owned running seat. |
| `carrick-core/src/mm/retirement/invalidation.rs`: `MemberSeat`, `stage`, `PendingInvalidation`, `DomainCompletion`, `ReclaimQueue` | Keep the neutral authority in core; softmmu remains its venue. Cache/JIT reclamation consumes completion, never invents another served watermark. |
| `carrick-softmmu/src/walker.rs`: `mark_code_page`, `code_generation`, `on_code_page_write` | Reuse frame-keyed tracking, extending publication under #601/#684; current helpers alone do not establish peer write-plane closure. |
| `carrick-softcpu-x86/src/cpu.rs`: block planning/emission/publication in `SoftCpu`, `JitCodeBuffer` | Current path plans/emits again; there is no resident block cache here to claim as already reused. #616 supplies cache storage, deduplication, reverse indexes and budgets once in proposed neutral `carrick-softcpu-core`; both ISA translators consume it. Move host executable allocation from `JitCodeBuffer` behind the neutral host JIT adapter in `carrick-vmm-soft`; x86 `PlannedBlock` and instruction emission remain x86. |

The retired `carrick-dsr/src/cache.rs` is historical design input, not an
additional cache to ship or an audited source import. N2's implementation must
use one neutral cache; #616 must change ownership before ARM and x86 diverge.

### Cache, code writes and retirement

The #616 cache is neutral storage and lifecycle with ISA-specific emitted
blocks. Key by guest PC plus execution mode/profile, root incarnation and
physical code-frame identities/generations for every page a block spans.
Physical identity alone cannot identify PC-relative code or its privilege.
Direct links validate the same epochs and are severed before reclamation.
A bounded cache has explicit byte/block limits and reverse frame indexes;
retirement waits for executing readers before reusing emitted storage.

Reuse `carrick_core::mm::retirement::invalidation` (already consumed by
softmmu) as the sole served-generation/safe-point authority. #681 remains open
for the wider hardware unification; do not add a separate ARM epoch. #607 is
closed and its peer mechanism is present. #684 is still open: execution of
writable aliases on multiple CPUs cannot be admitted before frame-keyed peer
write-plane invalidation is witnessed. Follow #601's code-generation work,
then #684's peer closure: enroll CPUs, revoke cached writes, kick active peers,
acknowledge at safe points and only then publish code. All guest stores,
translated atomics and host copyout/DMA-like providers must participate in code
mutation tracking, including aliases. A write transaction prevents concurrent
translation while bytes change and publishes its new generation after the
store, before any replacement block is admitted (#601); a pre-store generation
bump alone lets a peer cache old bytes under a new identity. ARM IC/DC/DSB/ISB sequences must enforce
instruction visibility; conservative earlier invalidation is acceptable for
coherent test code, never stale execution after architectural synchronization.

The cache contract extends `x86.softcpu.level0` / #616 rather than inventing
an ARM-only budget system. For a resident loop of U distinct blocks executed
N times without mutation or eviction, decode and emit counts are at most U,
independent of N; page marks change state once per frame generation. Assert
bounded page walks per cold page, zero coordinator locks and zero inventory
scans on synchronized hits. Test N at three scales and adversarial aliases,
cross-page blocks and mixed block sizes. Invalidation visits are bounded by
registered affected CPUs plus affected reverse links, not all cached blocks.
Eviction/churn has a separate explicit budget; it cannot weaken the hot-loop
claim. Establish red evidence on the current re-emitting x86 path first.

### Machine seam, kicks and timers

`carrick-vmm-soft` owns machine inventory, CPU seats, event notification and
host JIT allocation. It takes an ISA engine; it must not depend on Linux
personality policy. Runtime retains executor admission, continuation custody,
blocking, fork/exec and completion authority. Move HVF-bound carrier operations
behind a narrow provider seam at their production call sites; do not assume
implementing `Aarch64EngineCore<V>` alone replaces the HVPatch runtime.
Extract ownership/lifecycle code once, leaving true HVF register/VM operations
in HVF. The x86 CPL0 adapter remains distinct ISA mechanics over that seam.

At each bounded block boundary/back-edge checkpoint, check pending kick,
invalidation and deadline. Bound straight-line blocks too. A kick sets a
persistent event generation and wakes the existing waiter; it is not a host
signal. WFI/idle enrolls, probes once and parks until an event or deadline;
never spin for timers or hold an execution lease across another task's wait.
Use the existing `VcpuKick`/registry and timer-core/bridge where applicable;
model architectural CNTV state in the ARM engine, not in Linux timer policy.
A timer expiry wakes the loop and asserts an IRQ; it does not call the guest
scheduler on the host. Guest IRQ masking can delay delivery but cannot lose
the pending event. Witness kick-before-enroll, timer-during-park and a long
compute loop with no syscalls.

`--vcpu hardware|soft|auto` and `CARRICK_VCPU` select mechanism independently of
ISA and `--exec-backend hvpatch`; CLI overrides environment. Explicit soft
never creates a hardware VM. Explicit hardware never falls back. Auto uses a
positive capability result, falling back only on known absence; permission,
entitlement, initialization and run errors stay errors (including HV_DENIED).
Hosted jobs request soft explicitly. Both engines are built into supported
same-ISA hosts; no default-off experimental path. Propose `CARRICK_SOFT_VCPU=0` as the exact opt-out, with explicit soft
conflicting clearly rather than overriding that disable. This replaces the
October design's description of `CARRICK_VCPU=hardware` as an equivalent hatch;
the mechanism selector otherwise keeps its single spelling. Selection and errors share
one implementation and test matrix.

| Existing issue | Required shape now |
| --- | --- |
| #668 (closed, privileged x86 instructions) | Keep MSRs/CRs and x86 exceptions in x86. Extract only common CPU-profile identity and typed host-boundary plumbing when ARM consumes it; no generic register-number soup. |
| #669 (closed, IDT delivery) | IDT/gates/IST stay x86; ARM vectors remain ARM. Move common pending-event ownership, checkpoint and receipt machinery once, with both adapters tested. |
| #670 (closed, APIC/timer) | APIC and TSC registers stay x86. Deadline wake/enrollment, kick generation and loop coordination become neutral; ARM supplies CNTV/GIC state. |
| #671 (open, backend/selection) | Change before landing: neutral machine composition, selection and runtime seam; add ARM capability explicitly, not a second x86-only selector later. ARM integration can follow, but no claim it already works. |

## Decoder and emitter provenance

Choose in-tree generation rather than auditing and adopting another decoder
or assembler. The generator is Carrick-written Rust, emitting mask/value decode
tables, operand extraction/validation and A64 encoding constructors from the
Arm ARM's machine-readable A64 instruction descriptions. Semantic lowering,
exception behavior and helper sequences are authored here from the Arm ARM;
we do not import a third-party implementation or copy ASL implementation code.
The emitter uses generated checked field packers for the bounded instructions
our host glue emits, not a general-purpose assembler dependency.

Slice 0 selects and records an exact upstream Arm package, input hashes and
applicable license notices, and obtains approval for generation and redistribution
of resulting tables before importing data or generated output. Start from
[Arm's corresponding machine-readable collateral](https://support.arm.com/documentation/ddi0487/mc/Preface/About-this-Manual/Corresponding-Collateral).
Availability of a specification does not imply a redistribution license. If its
terms do not permit the intended use, stop this slice for director resolution;
do not substitute an unaudited library. No package has been license-admitted
or downloaded for this design round. No claim of an audited permissive dependency
is made. This explicitly supersedes the October decoder/emitter salvage advice.

Generation must be deterministic (two runs byte-identical), reject overlapping
patterns and reserved operand combinations, and retain source encoding IDs.
Test decode/encode round trips plus independently authored invalid encodings;
round trips alone cannot prove semantics. Differential native microfixtures and
same-image HVF execution supply independent evidence. Generated coverage must
include loader words, the kernel and the selected EL0 closure before admission.

## A64 execution semantics

An arm64 host can copy through register-only EL0 operations, and equivalent
ordinary EL1 arithmetic, inside translated blocks. It cannot copy through an
arbitrary EL0 function: every guest memory operation needs software translation,
every control transfer needs relocation/validation, and privileged state is
virtual. Rewrite ADR/ADRP/literal references; lower SVC, HVC, ERET, BRK,
MRS/MSR, TLBI, AT and cache maintenance; account for branches, atomics and
WFI/WFE/SEV. Never issue guest SVC/HVC against the host. Preserve all guest
GPRs, SP, NZCV, Q registers, FPCR/FPSR and restart PC across helpers. Exclusive
monitors are virtual per CPU with alias-aware write generations; do not depend
on a host exclusive reservation surviving a helper. LSE and exclusive paths
share memory authority. Use our own A64 decoder and emitter generated from Arm's machine-readable
instruction specification, as described below. No third-party decoder/emitter
implementation is admitted; no copyleft source, including file-level copyleft.

Maintain virtual EL0/EL1, PSTATE/DAIF and banked SP/return state. SVC from EL0
saves next PC and syndrome, then enters VBAR's lower-A64 synchronous slot
(+0x400). Instruction/data aborts save the faulting PC, FAR and exact ESR
(EC 0x20/0x24 from lower EL, 0x21/0x25 at current EL, including ISS/FSC).
Current-EL SP0 and SPx select +0x000 and +0x200 synchronous slots; IRQ adds
0x80 to the appropriate group. ERET restores ELR/SPSR and selects the correct
SP/EL with legality checks. HVC returns a provider exit preserving EL1's saved
syndrome. Invalid guest encodings enter guest exception handling; a host JIT
bug fails the lane distinctly.

PAN is required by the loader's kernel-only mappings and user-copy discipline.
Model PSTATE.PAN, SCTLR.SPAN and the configured FEAT_PAN3/EPAN permission
behavior from the Arm specification, rather than relying on the host's PAN.
`memory.rs` documents the AP/PXN/UXN layout workaround; preserve those bytes.
The image already uses EL1 unprivileged loads: `HardwareUserWord::read_u32`
and `read_u64` in `carrick-el1/src/sched/hw.rs` issue LDTR, and the file user-copy
path in `carrick-el1/src/file.rs` issues LDTRB. These require EL0 permission
checks even while executing at EL1; ordinary EL1 LDR semantics are wrong.
No explicit UAO register write was found in those sources. UAO=0 still requires
correct LDTR semantics; do not treat absence of UAO writes as absence of
unprivileged accesses. Census confirms the configured feature/state and all
LDTR/STTR variants; if UAO is exposed, model its override explicitly. Pair
PAN on/off and UAO off/on instruction tests with the hardware profile.
Host ARM capabilities never silently change guest behavior.

Model the minimal GICv3 CPU interface actually used: pending/active Group-1
interrupts, acknowledge/spurious ID, EOI, priority masking, enable state and
SGI target affinity consistent with MPIDR and ABI interrupt IDs. Model CNTFRQ,
CNTVCT, CVAL and CTL enable/mask/status with one monotonic virtual counter
shared with vDSO/vvar time. A level timer remains pending until masked,
disabled or reprogrammed; EOI alone must not erase an expired level. Bootstrap
register setup must agree with the hardware profile; no pretend full GIC
redistributor/distributor when the carrier configures only this subset. Add
MMIO registers only if the census/boot contract actually accesses them.
Deterministic clock injection is for unit tests; integration uses real elapsed
time. Multi-vCPU memory ordering and DMB/DSB semantics are required on ARM,
not inherited from x86's stronger host ordering.

## Hosts, gates and payoff

Linux `ubuntu-24.04-arm` is first: executable-cache allocation transitions
RW -> RX, with host I-cache publication and no writable executable guest RAM.
macOS arm64 uses a shared JIT arena through a host allocation adapter:
`MAP_JIT`, appropriate signing with `com.apple.security.cs.allow-jit` under
hardened runtime, per-thread write protection or Apple's callback allowlist
API, I-cache synchronization, then entry publication. Choose one supported
Apple policy; callback allowlist entitlement disables the older direct toggle.
Never mutate a block executing on another thread or publish a writable entry.
This requires JIT signing of test executables, not hypervisor entitlement;
keep signed-HVF recipes and failures unchanged.

References: [Arm exception model](https://developer.arm.com/documentation/102412/latest),
[Arm architecture manuals](https://developer.arm.com/documentation/ddi0487/latest),
[Apple JIT porting](https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon),
and [Apple allow-jit entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-jit).
Architecture semantics come from Arm ARM / Intel SDM, not another emulator.
Cross-ISA ARM-on-x86 would need an interpreter or a second lowering backend,
FP/atomic validation and much more testing. Leave it outside this bet: plentiful
native ARM hosted runners provide the capacity sought. Shared cache/MMU types
must not preclude it, but no implementation slice is allocated to it.

Stage CI from the first image smoke to EL1 native-process lifecycle, then
`el1_sched`, `el1_files`, `el1_gic` and conformance-next semantic probes.
Extract backend-neutral test setup from currently HVF-gated embed/common code;
reuse assertions/fixtures, not new soft-only tests with weaker output checks.
Keep timing-specific HVF assertions on HVF; soft records semantic and work
results, never supplies native runtime-ratio acceptance. Hardware-specific
entitlement/VM tests also stay on hardware.

Differential receipts identify image bytes, all loader executable spans,
fixtures/oracle, guest profile, topology, source and build. Compare output,
exit/signal, syscall/exception semantics, work invariants and test populations,
not scheduling order or exact clock values. Include started/finished tests and
binary completion; missing results are failures. On one Mac run soft/HVF
serially over exactly the same prepared inputs; Linux ARM soft uses the same
published bundle. Docker remains the semantic oracle, serialized separately.
An HVF failure-set difference stays the signed truth until director-approved
coverage and repeated equivalence across the full population justify any gate
replacement. Soft is initially additive, with its own exact-base failure-set
gate; passing it never waives signed or KVM evidence.

Planning envelope, not measurement: budget 5–20x HVF execution time for the
initial ARM DBT. Retired DSR measurements in the October design are not an ARM
prediction. Measure cold/warm execution separately from builds on a paired
single-Mac run, and hosted throughput separately; no increased correctness
timeouts to make a slow lane green. A completing workload at >=10x Docker
still triggers conformance-contract triage; soft timing is not an exemption
from investigating pathological work.

Mac-hours saved initially: zero signed truth is removed. After approved
migration, let R be daily redundant signed passes, T their eligible elapsed
minutes, and H retained paired hardware minutes: saved Mac-hours/day =
(R*T - H)/60, measured from CI receipts. Example assumptions R=12, T=30,
H=60 yield 5 hours/day; these are capacity scenarios, not observed durations.
Hosted cost is approximately R*T*S/60 ARM runner-hours for slowdown S, before
parallelism/build savings. Parallel hosted jobs reduce queue latency even when
hardware time cannot yet be removed. Slice 0 must obtain actual suite minutes
and queue occupancy before committing to an infrastructure spend.

## Slices, first witness and stopping rule

Every row is a proposed follow-up issue, to be filed after design review.
Each PR stays below ~4k changed lines; split byte-identical moves from semantic
changes and use native stacks where shared hot files demand them. No row is
permission to bypass its dependencies or combine an oversized implementation.

| Slice | Dependency / shared x86 interleave | Bounded deliverable and red-first witness |
| --- | --- | --- |
| 0: census and baseline | design reviewed | Rust census over image plus loader/fixture closure; unknown opcode fixture fails closed; capture actual signed suite minutes. No CPU implementation yet. |
| N1: placement/TLB policy | coordinate #671, reuse #607 | Extract ISA adapters within softmmu, retain x86 behavior; ARM geometry/permission-context tests and two roots at the same VA. |
| N2: cache and code publication | #616, #601, #684, #681 authority | Shared cache storage/reverse indexes and budgets; x86 red hot-loop count, two-live-CPU writable alias invalidation, no stale direct link or reuse. Split cache and peer publication PRs. |
| A1: decode and state | census | Decode coverage/classification, virtual register file and exception entry/ERET; generated instruction microfixtures against Arm semantics, including illegal encodings. |
| A2: ARM hardware walker | N1 | Shared mmu-core walk with permission/fault tests, root switch, PAN, NX, AF, cross-page accesses and block output alignment. |
| A3: translator foundation | A1/A2/N2 | Register/branch and memory lowering in separate PRs; exact restart state and scalar/atomic/FP fixtures. Bound checkpoints and cache work. |
| N3: production provider seam | #671, N1 | Move HVF-specific lifecycle dependencies behind machine operations in separate small slices; hardware behavior retained, x86 consumes the common coordination. |
| A3b: boot clock and interrupt state | A1/N3 | Implement bootstrap-configured CPU-interface state, counter reads and exercised CNTV control/acknowledge operations with unit witnesses; no successful register stubs. |
| 1: first end-to-end ARM bet | A3/A3b/N3 | Execute the exact image through real embed preparation with one CPU; first existing test is `native_root_exec_replaces_pid1_shell` in `el1_fork_exec.rs`, stdout `pid1_exec_ok\n`, exit 0, completed successor and cleanup. Include real bootstrap/SVC/ERET/HVC transcript and image identity. |
| A4: IRQ/timer and concurrency | slice 1, #670 neutral wake extraction | Asynchronous GIC/CNTV delivery and two-live-CPU shootdown; `el1_gic_vtimer_reaches_el1_without_host_exits`, then scheduler compute preemption, timed wait, WFI wake and cross-CPU handoff. |
| H1: hosted integration | A4 | Linux ARM additive gate, then macOS JIT policy and same-byte HVF differential. Add files/native-process/conformance-next populations incrementally, preserving denominators. |

“Slice 1” is the first end-to-end milestone, not a promise to implement a whole
DBT plus runtime extraction in one PR. Its prerequisite slices are independently
witnessable. Before it, use a tiny production-loaded static bootstrap/exit
fixture to expose missing opcodes cheaply; that alone does not pass slice 1 or
claim the native-process suite. The unchanged scheduler programs timers on
entry/switch paths, so A3b must implement the real register/deadline behavior
needed by slice 1; if its census reaches asynchronous IRQ delivery, that part
of A4 moves before the milestone as well. No timer masking or stubbed GIC is
allowed to manufacture a pass. The named existing test exercises a real
exec successor. Its current assertions prove successful exit and exactly
`pid1_exec_ok\n` stdout, repeated by the harness. They do not independently
prove the requested provider was used, same image bytes, instruction coverage,
SVC/ERET/HVC traversal, two live processes/CPUs, timer preemption, shootdown,
safe frame/JIT retirement or scoped cleanup. Slice 1 must add provider/image
identity and boundary/cleanup evidence; A4 and H1 retain their separate witnesses.
Passing this test alone cannot admit the soft lane.

Before funding A1/A2/A3 implementation, checkpoint after slice 0 and N3
call-site sizing: publish opcode-family coverage, proposed move sizes, shared
x86 dependencies, measured suite minutes and an effort estimate per slice.
The director stops or re-scopes the bet there if the prerequisites cannot be
split under the cap or the capacity model does not justify their estimated
cost. This checkpoint precedes paying for the translator and carrier moves.

Timebox the first end-to-end milestone to ten worker-days after prerequisites
land. Stop and return the bet to the director if it cannot run that unchanged
image/test, requires a second kernel service path or broad host-mapped guest VA,
or cannot stay within existing test deadlines. Also stop if warm resident-loop
decode/emission scales with execution count, or if measured representative
slice-1 execution exceeds 20x paired HVF after cache correctness is established.
These are proposed investment thresholds for review, not permission to relax
contracts. One hello timing cannot prove suite throughput: advancing additionally
requires the suite-minute model to predict at least 2 saved Mac-hours/day after
retained hardware checks. No retry-until-green or timeout expansion qualifies.

### Binary stopping checks per slice

The following commands are **proposed interfaces to be implemented by the named
slice**, not commands available today or results of this docs change. Use one
neutral `carrick debug soft-qualify <slice> --receipt <path>` runner for both
ISAs. Each command exits 0 only when every listed metric passes, otherwise 1;
missing counters, empty test populations or omitted receipts fail closed.
Invoke as `carrick debug soft-qualify <ID> --receipt <ID>.json`. Each split PR
must implement its own applicable check before it can land.

| ID | Metric required for exit 0; any violation stops that slice |
| --- | --- |
| 0 | License admission recorded; generated outputs differ by 0 bytes across two runs; census unknown words = 0 over declared executable spans; negative fixture rejected; measured suite minutes and fixture population present. |
| N1 | Existing x86 fixture failures added = 0; two-root same-VA wrong translations = 0; warm-hit inventory scans/coordinator locks = 0; guest granule/host-page matrix fully finished. |
| N2-cache | For resident U blocks and N=1,100,10000 iterations: decode/emit counts <= U at each scale, cache bytes <= configured cap; stale direct-link executions = 0. |
| N2-peer | Two live CPUs, writable aliases and host copyout: stale executions = 0; reuse before counted acknowledgements = 0; visits <= affected CPUs + affected reverse links; exhaustion fixture refuses publication. |
| A1 | Unclassified words in slice-0 closure = 0; native microfixture register/exception diffs = 0; illegal fixtures enter the expected guest exception, not host execution. |
| A2 | Permission/fault-level diffs = 0 for TTBR/root, PAN/UAO/LDTR, NX/AF and crossing/alignment matrix; all declared rows finish. |
| A3-register | Native register/branch/FP diffs = 0; straight-line and back-edge checkpoint distance <= declared maximum block instruction count. |
| A3-memory | Scalar/atomic restart-state and memory diffs = 0; hot-loop N2-cache budget violations = 0; alias tests finish with two live CPUs. |
| N3 | Hardware fixture population lost = 0 and added failures = 0; neutral lifecycle copy count = 1, verified by source review; provider selection/error matrix failures = 0 for both ISAs. |
| A3b | Boot-profile register and CNTV deadline/status diffs = 0; successful unknown-register stubs = 0; every census-required register has a completed witness. |
| 1 | Named exec test stdout/exit diffs = 0, missing provider/image/boundary/cleanup evidence = 0; completed within existing watchdog; elapsed implementation <= ten worker-days after prerequisites and paired soft/HVF ratio <= 20. |
| A4 | GIC timer, preemption, parked wake and two-CPU handoff populations complete; lost/duplicate IRQs and stale shootdown accesses = 0; hardware state/result diffs = 0. |
| H1-linux / H1-macos | Per-host suite population lost = 0, soft-vs-HVF added semantic failures = 0, budget violations = 0; macOS writable published entries = 0; measured model predicts >= 2 saved Mac-hours/day with retained hardware checks. |

The first funding checkpoint fails if slice-0 evidence is incomplete, any
proposed PR exceeds 4k changed lines without a split, or the measured capacity
model predicts less than 2 saved Mac-hours/day. Runtime thresholds assess the
investment; semantic or structural failures always stop admission regardless
of speed. These future checks do not assert design approval or equivalent
execution today.

## Risks and acceptance handoff

| Risk | Rating | Mitigation / evidence before expansion |
| --- | --- | --- |
| ARM carrier still coupled to HVF lifecycle/authority | High | Production-call-site extraction with hardware witnesses; no fake backend or second lifecycle. |
| Census misses generated vectors or compiler/EL0 instructions | High | All executable spans, static unknown coverage and fail-closed dynamic census. |
| Stale code, writable aliases or premature frame/JIT reuse | High | One retirement authority, #684 prerequisite, two live CPUs and generation exhaustion witnesses. |
| Atomics, FP state, PAN and weak ordering differ from hardware | High | Architectural instruction tests, real aborts and paired same-byte HVF runs. |
| Software execution consumes more capacity than it frees | High | Slice-1 kill threshold and measured CI-minute model before migration. |
| macOS JIT policy and 16 KiB host allocation | Medium | Separate host adapter, executable publication tests and signed JIT smoke on hosted arm64. |
| Timer mask/EOI/WFI loses an interrupt | High | Persistent pending level/event, race witnesses, existing preemption and parked-thread tests. |

This document is exempt from guest-semantic contract changes: only this design
path changes; existing `softmmu.x86.tlb-walker`,
`softmmu.x86.physical-retirement`, `x86.softcpu.level0` and
`x86.softcpu.apic-timer` contracts remain unchanged. Implementation begins by
registering ARM bindings and red witnesses for the affected families, then
proves deterministic budgets and applicable signed/oracle layers. No unrun
runtime gate is claimed by the design.

The director reviews the approach and an independent reviewer reviews the
source-backed claims and slice boundaries. Then the publishing workflow files
slice issues (reusing existing issues for their owned work), links dependencies
and records the decision on #1236. This worker does not publish comments,
issues or PRs. Design delivery alone does not satisfy review and follow-up
publication acceptance.
