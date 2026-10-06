# Compile in place, both images

Design pass, **owner decision on PR #72, 2026-10-06**. Make the existing
`carrick-el1` kernel generic over the existing `carrick-guest-arch::KernelArch`
projections and compile **the same modules** into `carrick-el1-image`
(AArch64 EL1) and `carrick-x86-cpl0` (x86 CPL0). The progress metric is
**modules linked into both images**, backed by image closure and call-path
receipts. Moving source between crates earns no progress. Crate re-homing
is optional cleanup after both images execute these modules, and may be
dropped entirely. This supersedes the relocation quotas and family-by-family
extraction mechanism in the earlier commits of this plan and Wave 2.

This revision changes documentation and its citation-generation script only.
The offset manifest, debug subcommand, generic bindings and runtime tests below
are implementation requirements, not delivered tools or acceptance claims.
Carrick remains experimental; linking a module does not establish syscall
coverage, behavioral correctness or acceptable operational cost.

## Authority, integration and investigation disposition

**S = `0f476ce7afb11609c8261cd1954bbe08263548b3`**, the requested study base
called `origin/work/x86-ord5` in the brief. That ref is absent here; the exact
commit exists. Every S-prefixed citation and the census use this immutable
commit, including code absent from the publication base. The docs-only
publication branch started at `github/main`,
`2322d859d463b0d6c9e99ae2ce04f044f66abf53` (P). No study source is copied
into that worktree. Later input commits are cited separately:

| Tag | Immutable input | Authority |
| --- | --- | --- |
| W1 | `a9a39db0cb7cce047519e89a0a3877d1396e6a10` | `docs/superpowers/plans/2026-10-04-x86-parallel-track.md:1` |
| W2 | `289e8d79753cdb4115b35ea16944e91f6c9c25d3` | `docs/superpowers/plans/2026-10-06-x86-wave2-extraction.md:1` |
| X1 | `1bbc39005aa06eee3a4e47023cebf8b4d6363708` | PR #64; `docs/perf-results/2026-10-06-x1-increment2.md:1` |
| O5 | `7245d48af95e147368c7bf214a90e4c063cd794d` | PR #68; `docs/perf-results/2026-10-06-x86-order5-entry-mapping.md:1` |
| O6 | `3fd7862be859e106cdfa27ec183fea9cf66ccf63` | `work/x86-ord6`; `docs/perf-results/2026-10-06-x86-order6-lifecycle-mapping.md:1` |
| R | `0feb7c7b0f7ad99b3c85aac146e65d52c64904da` | `github/work/x1-arm-regress`; `docs/perf-results/2026-10-06-x1-arm-regression.md:1` |

**N1 + Wave 1 land on main first.** Consume their accepted production MM
owner/transport and fixtures; do not reconstruct pre-landing N1 bodies from
S. The N1 ownership controller is
`S:docs/superpowers/plans/2026-10-02-el1-native-ownership.md:697,723,820`.
Then the merge order is **X1 (#64), O5 (#68), O6, inversion**. Rebase each
input on its accepted predecessor and maintain a kept/ported/dropped fix
ledger with exact SHAs, reasons and original authors. In particular, O6's
mapping notes its incomplete incorporation of later O5 fixes
(`O6:docs/perf-results/2026-10-06-x86-order6-lifecycle-mapping.md:261`).
The inversion's actual base is the accepted main after O6, not S or P.
Regenerate citations and module inventory on that base before implementation.

Treat **`origin/work/x1-arm-regress`** as the named ARM regression
investigation. The available remote here is `github/work/x1-arm-regress`,
pinned as R above; do not assume the absent origin spelling resolves.
Its disposition is **diagnostic evidence to retain; no X1 regression fix
or signed acceptance receipt to transplant**. Exact-filter signed runs found
all four nominated COW/vfork/pipe/two-process witnesses red at both
`56bf8c0caefe39fcc2260345d0a54772a74bffad` and `6051e19a2`. The earlier broad
baseline had killed executables before several witnesses ran; missing rows
were not passes (`R:docs/perf-results/2026-10-06-x1-arm-regression.md:5,25,57,103`).
Investigate those baseline defects under their N1/IPC authorities. X1 still
requires a qualified matched comparison for its actual landing head; these
observations cannot prove it adds no failure. Preserve the evidence note
with the X1 review packet and use a genuinely green, exact-filter witness
before attributing or bisecting an X1 regression.

Consume the accepted **X1** anonymous edit/owner-grant and transfer bodies,
including root/pin/invalidation/rollback corrections, as dependencies of the
same EL1 modules. Do not transplant its bounded native fixture as production
MM ownership or claim general remap from its same-size whole-grant witness
(`X1:docs/perf-results/2026-10-06-x1-increment2.md:17`). Consume **O5**'s sole
Linux dispatcher and exact ordinary/born/completion/return-work fixes; its
`PendingFamilies` is temporary routing to existing bodies, to be eliminated
as generic linkage becomes executable
(`O5:docs/perf-results/2026-10-06-x86-order5-entry-mapping.md:3,13`). Consume
**O6**'s core/Linux lifecycle definitions, retained protocol-6 layouts and
native adapters, then genericize their remaining context binding in place.
Do not resurrect deleted EL1 lifecycle policy or repeat its neutral split
(`O6:docs/perf-results/2026-10-06-x86-order6-lifecycle-mapping.md:13,32`).
Use the actual accepted successors of these inspected commits; recheck fix
ledgers, signed receipts and module eligibility after their rebases. Naming
an in-flight source input here does not declare it accepted.

**One owner edits `crates/carrick-x86-cpl0/src/entry.rs` across these inputs
and inversion.** Other workers supply reviewed patches/interfaces to that
owner. Rebase, reconcile and compile the whole entry closure at each
handoff; do not independently replace its allocator, native adapter, suspend
path or vectors. Its current native adapter inclusion is
<!-- cite:cpl0-adapter -->`S:crates/carrick-x86-cpl0/src/entry.rs:26` and allocator is <!-- cite:noallocation -->`S:crates/carrick-x86-cpl0/src/entry.rs:11`.

## Census and progress receipts

Appendix A is generated from immutable git blobs by the committed Rust
script in `docs/superpowers/plans/inversion-census/`. It records individual
ISA-touching lines in nine concern groups, full asm macro spans including
operands/options, complete native files for non-lexical encodings, and
source-selected semantic anchors. It refreshes the marked citations in this
text too. A missing or ambiguous source selector is an error, rather than a
line number that happens to be within the file.

The owner's **49,580** denominator reproduces: tracked Rust under `src/`
in `carrick-el1`, `carrick-el1-abi`, `carrick-aarch64`, excluding blank and
trimmed `//` lines, including unit tests/cfg/asm, excluding build scripts and
integration tests. The owner's narrower **2,922 directly ISA-touching
lines** is not a reproducible adapter-size forecast: the conservative
lexical/syntax counts are reported separately in Appendix A. A host engine
is not a guest kernel body just because it avoids inline asm; host-native
snapshot/backend custody remains in `carrick-aarch64`
(<!-- cite:host-snapshot -->`S:crates/carrick-aarch64/src/vmm.rs:138`). The 46,658 subtraction is a candidate ceiling,
not a measured shared implementation or an instruction-only residue.

Use these **25 operational module units** as the initial linking checklist.
A module unit is its source body, not its crate name or a re-export. Native
leaves are excluded from the shared-body numerator. Regions/types and
existing core/sched/MMU dependencies have a separate closure checklist.
The manifest uses the exact accepted-base module graph, so a module removed
by an accepted predecessor is recorded as consumed by that existing owner,
not recreated to preserve this study's denominator.

| Units | Existing source bodies to instantiate in both images | Binding, with source evidence |
| ---: | --- | --- |
| 2 | `alloc.rs`, `lock.rs` | Same metadata storage and lock algorithm; native masks/regions supplied by A. <!-- cite:allocator -->`S:crates/carrick-el1/src/alloc.rs:25`; <!-- cite:spinlock -->`S:crates/carrick-el1/src/lock.rs:27` |
| 2 | `sched.rs`, `sched/object_wait.rs` | Same scheduling/wait orchestration over `ZoneTables<A::SavedContext>`. <!-- cite:scheduler -->`S:crates/carrick-el1/src/sched.rs:107`; <!-- cite:record-context -->`S:crates/carrick-sched-core/src/lib.rs:573` |
| 4 | `cow.rs`, `fault.rs`, `memory.rs`, `personality/reservations.rs` | Same owner/COW/fault/reservation bodies; native descriptor/copy projection. <!-- cite:fault -->`S:crates/carrick-el1/src/fault.rs:891`; <!-- cite:owner-grant -->`S:crates/carrick-mmu-core/src/owner_mmu.rs:137` |
| 4 | `personality/mm_portal/{production,fork,maintenance,edit_wait}.rs` | Same N1 service/continuation bodies and retained operation records. <!-- cite:portal-slots -->`S:crates/carrick-el1-abi/src/mm_portal.rs:116` |
| 5 | `personality/{common_entry,dispatch,thread_setup,lifecycle,sched}.rs` | Same Linux entry/lifecycle/scheduler bodies; consume O5/O6 updates first. <!-- cite:cfg-personality -->`S:crates/carrick-el1/src/personality/mod.rs:8`; <!-- cite:o6-child -->`O6:crates/carrick-el1/src/personality/lifecycle.rs:137` |
| 3 | `personality/ipc.rs`, `personality/ipc/epoll.rs`, `substrate/ipc.rs` | Same owned IPC continuation and readiness; native frame/ABI encoding. <!-- cite:replay -->`S:crates/carrick-el1/src/personality/ipc.rs:651`; <!-- cite:arm-epoll -->`S:crates/carrick-el1/src/personality/ipc/epoll.rs:57` |
| 2 | `file.rs`, `personality/file.rs` | Same file policy/storage; native validated copy instruction leaves. <!-- cite:guarded-copy -->`S:crates/carrick-el1/src/file.rs:84`; <!-- cite:delegated-file -->`S:crates/carrick-el1-abi/src/lib.rs:1053` |
| 3 | `personality/inotify.rs`, `substrate/{watches,file_notification}.rs` | Same watch/event/cache bodies and lock order; no x86 copy. <!-- cite:delegated-inotify -->`S:crates/carrick-el1-abi/src/lib.rs:2567` |

`common_entry` and `thread_setup` are already enabled for x86 at S; the
other exclusions are explicit (<!-- cite:cfg-exclusions -->`S:crates/carrick-el1/src/lib.rs:13`;
<!-- cite:cfg-personality -->`S:crates/carrick-el1/src/personality/mod.rs:8`). **Enabled is not linked.** For each batch,
record both target triples, rustflags/features, source/blob hashes, full
image hashes, root entry symbols, linker maps and a machine-readable list of
instantiated module symbols reached from the production image entries.
Force real entry call paths, not `#[used]` test anchors or discarded rlibs.
LTO may erase names: keep a same-source diagnostic link with stable module
provenance and pair it with the release build closure and runtime witnesses.
Report `linked/eligible` and `runtime-witnessed/linked` separately. Present
baseline actual linkage as **unmeasured in this design pass**, not 2/25.
Target: **25/25 eligible units in both production images**, with every
behavior family witnessed and no remaining x86 family placeholder path.

### Crate placement and before/after source counts

There is no planned mass re-homing. EL1's package name can remain despite
hosting a kernel for both ISAs. The source-count comparison is an inventory
of retained existing lines, not a prediction of total lines after generic
binding, new tests and native glue. Report those measured deltas at landing.

| Crate | Before S, retained src lines | After retained placement | Disposition |
| --- | ---: | ---: | --- |
| carrick-el1 | 22,907 | 22,907 | Same modules; native leaves move **within** the package into `isa/aarch64.rs`, x86 leaves bind through `isa/x86.rs` |
| carrick-el1-abi | 10,940 | 10,940 | Same definitions compiled by both; consume O6 neutral splits, preserve native ARM records |
| carrick-aarch64 | 15,733 | 15,733 | Host engine/ISA custody stays; update concrete ARM context consumers |
| carrick-core | 10,747 | 10,747 | Reuse existing owners; no new kernel-body relocation |
| carrick-core-abi | 3,884 | 3,884 | Reuse existing neutral records/O6 changes |
| carrick-personality-linux | 1,609 | 1,609 | Reuse decoders and O5/O6 policy; no second family implementation |
| carrick-sched-core | 11,050 | 11,050 | Generic context parameter in place, unchanged ARM instantiation layout |
| carrick-mmu-core | 18,744 | 18,744 | Existing per-ISA descriptor modules/owner interfaces |
| carrick-guest-arch | 368 | 368 | Extend existing backend projections only where needed |
| carrick-x86 | 5,465 | 5,465 | Existing native leaves/host engine; no forced move to CPL0 crate |
| carrick-x86-cpl0 | 371 | 371 | Image entry/packaging and x86 native fixture; invokes shared EL1 modules |
| carrick-el1-image | 16 | 16 | ARM image packaging |

Existing shared-six-crate footprint is **46,402**; including the same EL1
and EL1-ABI sources in both closures yields **80,249 candidate source
lines**, before removing native-only reachability. The twelve-crate inventory
conserves **101,834 existing lines**. These include tests; none are compiled
image-byte estimates. The old relocation target of a 2,000-line production
guest residue is withdrawn. Measure the actual AArch64-only guest leaves
and native record layouts after generic compilation; exclude the 15,733-line
host engine from that guest metric. The goal is zero ARM-only **policy/owner
module bodies**, with ARM instruction/layout leaves explicitly inventoried.
Optional final re-homing of neutral records into core-ABI must have a
concrete owner, reduce coupling and retain one definition. Delete empty
facades; defer cosmetic renames and global typed-address consolidation.

## Small ISA surface: reuse KernelArch

The existing composite is <!-- cite:kernel-trait -->`S:crates/carrick-guest-arch/src/lib.rs:400`, backed by
`EntryArch`, `MmuArch`, `InterruptArch`, `CrossingArch` and their backend
hooks (<!-- cite:entry-trait -->`S:crates/carrick-guest-arch/src/lib.rs:362`; <!-- cite:mmu-trait -->`S:crates/carrick-guest-arch/src/lib.rs:370`;
<!-- cite:irq-trait -->`S:crates/carrick-guest-arch/src/lib.rs:381`; <!-- cite:crossing-trait -->`S:crates/carrick-guest-arch/src/lib.rs:393`).
Instantiate **one backend per ISA**, `Arch<Aarch64Backend>` and
`Arch<X86Backend>`, in `carrick-el1::isa`. Extend these hooks, rather than
introducing a replacement flattened `KernelArch` trait, per-family seam,
new facade crate or duplicate dispatcher. Native snapshots/host tickets
already exist (<!-- cite:snapshot -->`S:crates/carrick-guest-arch/src/lib.rs:131`; <!-- cite:host-ticket -->`S:crates/carrick-guest-arch/src/lib.rs:256`).
Kernel methods become `fn body<A: KernelArch>(...)` in their existing modules.

The following is the **proposed minimal signature delta and binding
inventory**, not code implemented by this document. Put the frame/context
accessors on the existing entry projection (or associated native types), not
on a new Linux-family trait. Each unit below has private integer storage and
checked named constructors; raw wire words appear only inside codecs.
Use `GuestVa`/`Gpa` in new semantic signatures, with explicit checked
conversions from existing leaf `UserVa`/`FrameGpa`; do not make global renames
a prerequisite. Native registers use ARM/X86 enums; register bits, native
ordinal, lengths and flags are distinct types.

```rust
// Associated native types on existing ArchTypes/EntryBackend projections.
trait FrameAccess {
    type Register: NativeRegister; // Aarch64Register or X86Register
    fn read(&self, reg: Self::Register) -> RegisterWord;
    fn write(&mut self, reg: Self::Register, value: RegisterWord);
    fn syscall_nr(&self) -> NativeOrdinal;
    fn args(&self) -> [RegisterWord; 6];
    fn set_result(&mut self, result: NativeReturnWord);
    fn pc(&self) -> GuestVa;
    fn set_pc(&mut self, pc: GuestVa);
    fn sp(&self) -> GuestVa;
    fn set_sp(&mut self, sp: GuestVa);
    fn replay_pc(&self) -> Result<GuestVa, NativeFrameError>;
}
trait ContextAccess: Clone {
    const ZERO: Self; // native storage only, grants no task/root authority
    type Tls;
    fn arg0(&self) -> RegisterWord;
    fn set_result(&mut self, result: NativeReturnWord);
    fn set_stack(&mut self, stack: GuestVa);
    fn set_tls(&mut self, tls: Self::Tls);
}
// Existing EntryBackend: retain decode_entry/snapshot/set_result,
// save_context/load_context/prepare_user_return; add only child native setup.
fn prepare_child_context(
    parent: &Self::SavedContext, stack: GuestVa, tls: Option<Self::Tls>
) -> Result<Self::SavedContext, Self::Error>;
// Existing MmuBackend: typed root/context, live owner translation, leaf edit,
// invalidation tickets, checked copy and executable publication stay existing.
fn install_context(context: AddressContext<Self::Root>) -> Result<(), Self::Error>;
fn copy_user_chunk(transfer: &mut Self::UserTransfer, limit: GuestLen)
    -> Result<CopyProgress, Self::Error>;
// Existing InterruptBackend: preserve current typed CPU/deadline/wake/ack API.
fn mask_interrupts() -> Self::InterruptMask;
fn restore_interrupts(mask: Self::InterruptMask) -> Result<(), Self::Error>;
fn current_cpu() -> CpuId;
fn arm_timer(deadline: Option<Deadline>) -> Result<(), Self::Error>;
fn send_wake(target: CpuTarget, token: WakeToken) -> Result<(), Self::Error>;
// Existing CrossingBackend: transport of owned bounded record payload only.
fn submit_host_request(request: OwnedHostRequest<Self::HostPayload>)
    -> Result<RequestToken<Self::HostTicket>, Self::Error>;
fn consume_completion(token: RequestToken<Self::HostTicket>)
    -> Result<Self::HostCompletion, Self::Error>;
```

| Concern | Native responsibility and minimal shared use |
| --- | --- |
| Trap/entry | Decode ESR/FAR vs vector/error; frame nr/args/result/PC/SP/replay access. Linux codecs choose native table and canonical nr. ARM frame <!-- cite:trap-frame -->`S:crates/carrick-el1-abi/src/lib.rs:645`; x86 <!-- cite:x86-frame -->`S:crates/carrick-x86/src/cpl0_entry.rs:18` |
| Context/TLS | ARM GPR/FP/SIMD/TPIDR vs x86 FS/GS/XSAVE; save/restore and typed child setup only. <!-- cite:threadctx -->`S:crates/carrick-sched-core/src/lib.rs:382`; <!-- cite:native-context -->`S:crates/carrick-x86/src/cpl0_scheduler.rs:34` |
| Descriptor/geometry | Keep encode/decode/table geometry in MMU-core's existing ARM/x86 descriptor modules, with `A::MmOwner`/MMU adapter bound to `OwnerGrantMmu` in the kernel. <!-- cite:owner-mmu -->`S:crates/carrick-mmu-core/src/owner_mmu.rs:21`; <!-- cite:owner-grant -->`S:crates/carrick-mmu-core/src/owner_mmu.rs:137` |
| TLB/barriers | Backend executes exact native publication/invalidation sequence; existing owner drain tickets decide participants/reuse. CR3 reload is local hardware work, not global retirement proof. <!-- cite:cr3-install -->`S:crates/carrick-x86/src/cpl0_scheduler.rs:122` |
| IRQ/kick/timer | Existing typed CPU target, wake token, deadline, interrupt ack and noncopyable saved-mask capability; no Linux task policy in GIC/APIC leaves. <!-- cite:irq-trait -->`S:crates/carrick-guest-arch/src/lib.rs:381`; <!-- cite:irq-token -->`S:crates/carrick-guest-arch/src/lib.rs:230` |
| Host transport | Existing bounded service/forward record plus HVC/doorbell; never a callback that dispatches a Linux family or allocates synchronously for an interrupt. <!-- cite:crossing-trait -->`S:crates/carrick-guest-arch/src/lib.rs:393`; <!-- cite:metadata-mailbox -->`S:crates/carrick-el1-abi/src/lib.rs:819` |
| User copy | Borrow an owner-authenticated transfer/permission lease, then native AT/PAR+guarded access or x86 checked translation/fault recovery. Host mirrors and permissive host-test validators cannot authorize production copy. <!-- cite:validator -->`S:crates/carrick-el1/src/file.rs:165`; <!-- cite:guarded-copy -->`S:crates/carrick-el1/src/file.rs:84` |
| Boot/root | Image-native vectors/control regs/GDT/IDT/TSS; shared entry borrows typed authenticated boot mappings and calls existing root install. Fixed ARM placement stays native. <!-- cite:image-header -->`S:crates/carrick-el1-abi/src/lib.rs:587`; <!-- cite:root-gpa -->`S:crates/carrick-guest-arch/src/lib.rs:71` |

Avoid dependency cycles: `guest-arch` owns units/projections; kernel imposes
MMU-core bounds. Do not move journals, Linux policy, wait admission, fd
selection, root retirement or allocator algorithm into `ArchTypes`
(<!-- cite:arch-types -->`S:crates/carrick-guest-arch/src/lib.rs:287`). Native acknowledgements do not manufacture
core completion receipts (<!-- cite:core-completion -->`S:crates/carrick-core-abi/src/entry.rs:118`). Linux selects
child result zero, clone semantics and visible-tid/vDSO policy; native
context setup handles representation only.

## ABI and the full offset manifest

Keep current ARM bytes exactly while genericizing their users. The
`EL1_ABI_LAYOUT_HASH` begins at <!-- cite:layout-hash -->`S:crates/carrick-el1-abi/src/lib.rs:364` and its expected
value is pinned by a const assert at <!-- cite:hash-assert -->`S:crates/carrick-el1-abi/src/lib.rs:3034`. It lists
selected sizes/offsets, not every field. Passing that hash or existing
TrapFrame assertions is **not** the required layout gate.

Step 0 commits a Rust `offset_of!` **full manifest test** and a golden
machine-readable record. Enumerate every declared field, including private
padding and nested fields, of **TrapFrame, ThreadCtx, ZoneRecord, ZoneTables,
CurrentTask, native syscall mailboxes, metadata/frame/COW grant mailboxes,
portal/descriptor/copy-window slots, ThreadLifecyclePage, PoolEntry and
ThreadControlSlot**. Record size, alignment, offsets, field sizes, array
lengths/element strides and atomic widths; include nested execution/MM/Linux
composites and every vector-asm operand target. Fields must be listed in the
owning crate so private fields are checked without making them public.
Use a syntax-derived field-coverage audit against the manifest registry to
reject omissions, including a newly added private field. Assert every field
with `offset_of!`, not an aggregate hash; a hash may index the complete
manifest but cannot replace it. Capture enums/discriminants used by host
readers and the constants used to address each record. First capture the
accepted base, then require byte-for-byte equality for its ARM instantiation.
Relevant declarations are <!-- cite:trap-frame -->`S:crates/carrick-el1-abi/src/lib.rs:645`; <!-- cite:threadctx -->`S:crates/carrick-sched-core/src/lib.rs:382`;
<!-- cite:zone-record -->`S:crates/carrick-sched-core/src/lib.rs:534`; <!-- cite:zone-tables -->`S:crates/carrick-sched-core/src/lib.rs:1026`;
<!-- cite:current-task -->`S:crates/carrick-el1-abi/src/lib.rs:690`; <!-- cite:native-mailbox -->`S:crates/carrick-aarch64/src/mailbox.rs:5`;
<!-- cite:metadata-mailbox -->`S:crates/carrick-el1-abi/src/lib.rs:819`; <!-- cite:portal-slots -->`S:crates/carrick-el1-abi/src/mm_portal.rs:116`;
<!-- cite:descriptor-slots -->`S:crates/carrick-el1-abi/src/descriptor_txn.rs:32`; <!-- cite:copy-table -->`S:crates/carrick-el1-abi/src/service_copy.rs:65`;
<!-- cite:lifecycle-page -->`S:crates/carrick-el1-abi/src/thread_lifecycle.rs:688`; <!-- cite:pool-entry -->`S:crates/carrick-el1-abi/src/thread_lifecycle.rs:332`;
<!-- cite:control-slot -->`S:crates/carrick-el1-abi/src/thread_lifecycle.rs:459`. Add manifest mutations that change an offset,
array stride, alignment or omit a field and prove the gate rejects them.

| Records | Neutrality and layout decision |
| --- | --- |
| Core entry/completion identities; lifecycle state/ref/generation | Neutral definitions already in core-ABI or supplied by O6 stay there. Later cleanup may move remaining neutral grant/slot headers to core-ABI; do not move operational bodies to obtain linkage. <!-- cite:core-completion -->`S:crates/carrick-core-abi/src/entry.rs:118`; <!-- cite:entry-ref -->`S:crates/carrick-el1-abi/src/thread_lifecycle.rs:195` |
| CurrentTask and Linux control/pool/page payload | Linux composites, not neutral task semantics. Keep the existing exact CurrentTask ARM stride/alignment/offsets and lifecycle protocol **6** on both images. O6's core/Linux split is consumed once; existing storage may remain EL1-ABI during inversion. <!-- cite:current-task -->`S:crates/carrick-el1-abi/src/lib.rs:690`; <!-- cite:lifecycle-version -->`S:crates/carrick-el1-abi/src/thread_lifecycle.rs:53` |
| Metadata/frame/COW/portal/descriptor/mailbox records | Exact common layouts remain shared, including atomic order/state generations. Ownership-neutral headers are eventual core-ABI candidates, Linux requests remain Linux payloads, descriptor words remain typed native encodings. Fixed aperture placement stays per ISA. <!-- cite:metadata-mailbox -->`S:crates/carrick-el1-abi/src/lib.rs:819`; <!-- cite:portal-slots -->`S:crates/carrick-el1-abi/src/mm_portal.rs:116`; <!-- cite:descriptor-slots -->`S:crates/carrick-el1-abi/src/descriptor_txn.rs:32` |
| IPC/file/inotify records and counters | Same retained layouts and algorithms in EL1-ABI, compiled by both. Linux fd/errno/mask/watch payloads stay Linux; no neutral relabeling to justify moving them. <!-- cite:delegated-file -->`S:crates/carrick-el1-abi/src/lib.rs:1053`; <!-- cite:delegated-inotify -->`S:crates/carrick-el1-abi/src/lib.rs:2567` |
| TrapFrame, native syscall mailbox, ThreadCtx/native context, boot header and region constants | Native layout remains per ISA. ARM mailbox version **3** stays exact; x86 frame/FS/GS/XSAVE is a separately tagged layout, never cast as ARM. <!-- cite:mailbox-version -->`S:crates/carrick-aarch64/src/mailbox.rs:2`; <!-- cite:trap-frame -->`S:crates/carrick-el1-abi/src/lib.rs:645`; <!-- cite:native-context -->`S:crates/carrick-x86/src/cpl0_scheduler.rs:34`; <!-- cite:image-header -->`S:crates/carrick-el1-abi/src/lib.rs:587` |
| ZoneRecord/ZoneTables instantiated over Context | ARM specialization must match full manifest exactly. x86 context changes record stride/alignment: host consumes an explicit ISA/layout-version descriptor including context size/align and record/table offsets. Both readers switch atomically; reject wrong tag/version/stride. Never silently widen a host-read common record. <!-- cite:record-context -->`S:crates/carrick-sched-core/src/lib.rs:573`; <!-- cite:zone-tables -->`S:crates/carrick-sched-core/src/lib.rs:1026` |

The shared lifecycle page and common mailboxes keep exact layouts; only
native context-bearing zone tables use versioned per-ISA layouts. Do not
serialize Rust references, generic enums or trait objects. Typed wrappers
preserve the wire representation. Linux **epoll** still needs ISA codecs:
ARM uses 16 bytes (<!-- cite:arm-epoll -->`S:crates/carrick-el1/src/personality/ipc/epoll.rs:57`), x86's packed record is
<!-- cite:linux-epoll -->`S:crates/carrick-abi/src/lib.rs:902`. Shared policy does not imply one Linux wire layout.

## Sequencing and four batched signed comparisons

Keep the owner's order **0 → 1 → 2 → 3 → 4 → 5 → 6 → 7**. Each mechanical
cut has a portable compile/test receipt. Cuts whose type dependencies are
inseparable land together as specified below; no broken intermediate head,
fake hardware implementation or additional x86 cfg escape is pushed.
Every accepted batch adds **no signed ARM failure versus its own base**.

### 0. Native leaves and measurement tools — batch A

Move native instructions/register/ESR/geometry-address binding out of shared
bodies into `carrick-el1/src/isa/aarch64.rs` (internal submodules for large
vector/context blocks are allowed). Preserve asm templates, operands,
constraints, options, clobbers, symbol ABI, fixed placement and ARM call order.
Keep existing MMU-core native descriptor leaves there; bind them through
A rather than duplicate them in `isa`. The full native spans in Appendix A
are the starting fence; host ARM vector emitters remain native host code.
Commit the full offset manifest described above **before** context/layout
adaptation. Compare it before/after every subsequent batch.

Also implement **`carrick debug asm-block-diff`**, a Rust product subcommand,
with a build-manifest emitter. Given two exact builds, compare all
`asm!`/`global_asm!` instruction strings **and operands**: operand kind,
register class/explicit register, ordering/names, type/width, const/sym target,
modifiers, clobber ABI and options. Manifest records target, features,
rustflags, compiler/linker, source hash, image hash, stable block identity
and expansion provenance. Include host-generated vector instruction blocks
and macros emitted into the image; missing/unmatched/unsupported blocks fail
closed. Match moved blocks by explicit stable IDs, allowing path relocation
only, never instruction/operand normalization that hides changes. Provenance
must identify the actually compiled cfg/macro closure, not scan only the
checked-out source. Produce separate string and operand differences and a
receipt linked to both artifacts. Mutate an operand constraint, clobber,
option, const offset and instruction to establish red controls.

This tool proves equality of its captured asm blocks, **not equality of all
compiler-generated instructions**. This design pass makes no disassembly
or binary-equivalence claim; source relocation alone proves neither. If a
future change claims disassembly equivalence, it must extend/use this tool
with a decoded machine-instruction comparison and documented relocation
rules, and attach the result for both exact builds. Do not describe the
still-unimplemented tool as verification performed for this document.

**x86 unlocked:** native frame/IRQ/root/doorbell compile bindings and negative
layout/tag tests; entry-context storage manifests. No new scheduler/MM
coverage claimed yet.

### 1. IRQ mask and lock binding — batch A

Replace DAIF storage/use with `A::InterruptMask`; preserve ARM mask scope,
restore order and lock Acquire/Release. The bare SpinLock at
<!-- cite:spinlock -->`S:crates/carrick-el1/src/lock.rs:27` does not itself mask DAIF: the metadata wrapper
imports IRQ hooks (<!-- cite:allocator-lock -->`S:crates/carrick-el1/src/alloc.rs:11`) and masks before locking
(<!-- cite:allocator-irq -->`S:crates/carrick-el1/src/alloc.rs:51`); native save/restore are
<!-- cite:irq-save -->`S:crates/carrick-el1/src/sched/hw.rs:260` and <!-- cite:irq-restore -->`S:crates/carrick-el1/src/sched/hw.rs:279`.
Bind all callers through the existing InterruptBackend. Save/restore prior
x86 IF state, not unconditional STI, including nesting and interrupts already
masked. Guard release drops the lock before restoring interrupts; masks and
interrupt acknowledgements are consumed once. No allocation/host call under
an interrupt-held lock.

**x86 unlocked:** interrupt-held metadata lock, nested mask restoration,
IRQ-at-entry/return and lost-wake enrollment controls using APIC leaf.

### 2. Generic CPU context and production consumers — batch B

Parameterize `ZoneRecord<Context>`, `ZoneTables<Context>`, context reads and
scheduler CPU binding in place. Rename the concrete machine-state record
to `Aarch64Context` with identical repr and manifest; use the generic spelling
`type ThreadCtx<Context> = Context` for the scheduler projection. This alias
adds no storage or second machine-state definition. Do not wrap it in a new
field that shifts assembly offsets. x86 selects its existing NativeContext.
Shared context capture requires **Clone**, not Copy: ARM ThreadCtx is
`Copy` at <!-- cite:threadctx -->`S:crates/carrick-sched-core/src/lib.rs:382` (derive immediately above); the existing
parked read copies it at <!-- cite:parked-copy -->`S:crates/carrick-sched-core/src/lib.rs:3821`, while x86 NativeContext
and XsaveArea only derive Clone (<!-- cite:native-context -->`S:crates/carrick-x86/src/cpl0_scheduler.rs:34`).
Replace unconditional copies with a native clone under the same exact
claim/quiescence authority, including post-read incarnation validation.
Keep Copy only for concrete ARM record where valid. Never clone claims,
completion tickets, owner permissions or pending operation custody.

Update **production** host consumers in this same cut:
`carrick-runtime/src/vcpu_loop/zone.rs:78–136` builds ARM handback context
(<!-- cite:host-zone -->`S:crates/carrick-runtime/src/vcpu_loop/zone.rs:78`; <!-- cite:host-zone-apply -->`S:crates/carrick-runtime/src/vcpu_loop/zone.rs:136`), its remaining
context writes/readers, `crash.rs` native register projection
(<!-- cite:host-crash -->`S:crates/carrick-runtime/src/vcpu_loop/crash.rs:422`), `carrick-aarch64` snapshot/register/backend
consumers (<!-- cite:host-snapshot -->`S:crates/carrick-aarch64/src/vmm.rs:138`), and HVF table allocations/decoders.
Instantiate explicit ARM context types; bind x86 runtime/KVM readers to the
x86 layout descriptor. Zero-filled storage requires a native-valid zero
representation, not just a `Default` bound. Enforce 64-byte XSAVE alignment
when allocating/mapping tables.

Fixed **832-byte XSAVE** (<!-- cite:xsave -->`S:crates/carrick-x86/src/cpl0_scheduler.rs:23`) depends on the fail-closed
**XCR0=7** qualification in
<!-- cite:xcr0 -->`S:crates/carrick-vmm-kvm/src/carrier_interrupts.rs:300` (`carrier_interrupts.rs:300` at S), plus CPUID leaf 0xD
geometry checks immediately before it. At O6 that same guard is
<!-- cite:o6-xcr0 -->`O6:crates/carrick-vmm-kvm/src/carrier_interrupts.rs:400`. Keep that qualification before publishing any x86
context; a larger enabled component set must be rejected, not truncated.
Two-context SIMD/TLS isolation is mandatory, not GPR-only switching.

Minimal native context projections necessary to make this generic record cut
compile belong here. This is the **only dependency-driven overlap with
step 5**: existing child/scheduler writes use ctx fields
(<!-- cite:child-context -->`S:crates/carrick-el1/src/personality/lifecycle.rs:489`; <!-- cite:sched-result -->`S:crates/carrick-el1/src/sched.rs:317`), so parameterizing
Context without an operation to set/read its state cannot compile. Keep
those operations native and narrow; all frame conversion and shared-body
accessor replacement remains step 5. No behavior move/rewrite accompanies
this cut.

**x86 unlocked:** two-live-record context capture/clone, cross-MM native
root/TLS/FP isolation, exact-record handback and crash decoding; these are
storage/switch witnesses, not a persistent production task pool claim.

### 3. Allocator binding — batch C

Bind existing `MetadataStorage`/capacity owner to A's CPU/regions/transport
and reuse the exact allocator algorithm. Replace x86's **NoAllocation**
(<!-- cite:noallocation -->`S:crates/carrick-x86-cpl0/src/entry.rs:11`) only after bootstrap extents and bounded
expansion/return mailboxes are wired. `alloc` is a freestanding dependency,
not a host std allocator. Preserve ARM bootstrap addresses and HVC sequencing;
do not use x86 heap failure to justify excluding allocating modules.
Refusal must return the same typed capacity error before publication, with
exact-generation cancellation and no synchronous host allocation in IRQ
context. Test empty bootstrap, exhausted extent, stale grant and return.

**x86 unlocked:** metadata-backed IPC/operation objects, lifecycle record
admission and MM reservation/COW metadata capacity; bounded exhaustion and
expansion/return tests. No allocation-capable syscall is counted before
its real allocator is bound.

### 4. Lift cfg exclusions; compile the same modules — batch C

Remove the x86 exclusions at `el1/src/lib.rs:10–27`
(<!-- cite:cfg-exclusions -->`S:crates/carrick-el1/src/lib.rs:13`), personality exclusions
(<!-- cite:cfg-personality -->`S:crates/carrick-el1/src/personality/mod.rs:8`) and nested architecture-only owner-body
branches. Both image Cargo closures use the **same carrick-el1 package and
module graph**, parameterized by A. Leave cfg selection only on native
leaves/image glue. Do not include new shared bodies by path into the CPL0
image, add dummy ARM fields to x86 contexts or provide permissive validators.
Current native x86 leaf path inclusion (<!-- cite:cpl0-adapter -->`S:crates/carrick-x86-cpl0/src/entry.rs:26`) may
remain while the single entry owner connects the real projection; cleaning
up its crate placement is not this step's purpose.

This cut deliberately triggers freestanding x86 type-check diagnostics;
finish step 5 in the **same landable batch** before pushing. Evidence for
the dependency is the direct frame/context accesses below. Do not label an
intentionally noncompiling intermediate edit a completed landable commit.
The order within batch C stays allocator → exclusions → accessor repair.

**x86 unlocked:** all 25 candidate operational units eligible for actual
production linkage, with a compile fence rejecting ARM constructs in generic
bodies and host imports in the guest closure. Record actual link count.

### 5. Frame/context accessors — batch C

Replace frame/context field access in place with EntryBackend/native typed
accessors. The critical mixed path is `sched.rs:317`
(<!-- cite:sched-result -->`S:crates/carrick-el1/src/sched.rs:317`): ctx.x[0] is saved as original arg0 and frame.x[0]
is overwritten with the result immediately after. Child setup at
`personality/lifecycle.rs:489` (<!-- cite:child-context -->`S:crates/carrick-el1/src/personality/lifecycle.rs:489`) writes ctx.x[0]
and sp_el0; O6 has its corresponding native adapter at
<!-- cite:o6-child -->`O6:crates/carrick-el1/src/personality/lifecycle.rs:137`. Preserve original args, exact PC/SP, TLS, return
bits and completion/replay distinction. ARM SVC subtraction at
<!-- cite:replay -->`S:crates/carrick-el1/src/personality/ipc.rs:651` becomes native replay-PC calculation, not a fixed
shared instruction length. Linux epoll/signal/TLS records use ISA codecs;
normalization is not permission to change wire bytes or Linux semantics.

**x86 unlocked:** real shared syscall nr/args/result dispatch, syscall
return-PC/stack tests, failed child publication rollback, clone/TLS native
child setup, epoll packed output and partial-copy faults. Remove x86 family
placeholders only as the SAME body is reachable, never introduce a second
Linux policy path.

### 6. Owned suspend/resume after forward — batch D

Use the guest-side context from step 2 to suspend an exact owned entry and
resume the same record after host completion. Carry context, operation
sequence, task/execution/mm generations, endpoint/pin lifetime, byte offset,
original words and completion authority through the existing owned
continuation. A forwarded call releases execution capacity; it cannot keep
a worker waiting on another task. Resume consumes completion once; stale,
foreign, duplicate, cancelled and exit/exec races refuse without changing
a new record. Do not restart partial I/O at zero, fake a short result or
replay a syscall already committed. Existing RequestToken is owned
(<!-- cite:host-ticket -->`S:crates/carrick-guest-arch/src/lib.rs:256`); hardware completion alone is insufficient
(<!-- cite:core-completion -->`S:crates/carrick-core-abi/src/entry.rs:118`). O5's completion fixes are prerequisites,
not rewritten here.

**x86 unlocked:** CPL0 forward/park/host-completion/resume, partial I/O
continuations, execution-pool exhaustion with another runnable task,
stale generation and duplicate completion controls, exit/exec cancellation.

### 7. Scheduler/MM/IPC/file behavior — batch D

Connect the now-shared bodies to the native x86 adapter and retained host
backing transport. Work in small, mechanically reviewable entry-routing
commits: scheduler/wait, MM/reservation/fault/COW, IPC/readiness, file/inotify.
Reuse X1's accepted owner-transfer/edit machinery and O5/O6 entry/lifecycle;
delete displaced x86 pending-family refusals/temporary fixture routes as
production paths replace them. This is binding and behavioral qualification
of the same modules, not family extraction or an algorithm rewrite.

**x86 unlocked:** persistent runnable/blocked/born/exit pool; two-mm switch,
first-touch/COW/fork rollback and owner-generation refusal; pipe/futex/eventfd/
epoll waits at exhausted execution capacity; file offsets/dirty recall and
inotify ordering/teardown. Test two live tasks, not only single-call fixtures.
Final closure receipt must reach all eligible units from both production
entries and identify any syscall still forwarded/deferred honestly.

### Signed batching and per-cut portable gates

| Batch | Ordered cuts | Comparison base and ARM signed scope | x86 qualification |
| --- | --- | --- | --- |
| A | 0, 1 | Accepted main after O6 → A. Full layout manifest and asm-block tool receipts; signed entry/IRQ/masked-lock probes | Native binding/layout rejection and interrupt boundaries |
| B | 2 | Accepted A → B. Layout/asm receipts; signed two-task TLS/FP switch, host handback, crash/parked-read and lifecycle witnesses | Native context/root/TLS/XSAVE isolation and host readers |
| C | 3, 4, 5 | Accepted B → C. Layout/asm receipts; signed allocation/refusal, dispatch result/replay, clone rollback, fault/copy/IPC/file smoke | Both image closures link same modules; allocator + frame/ABI execution |
| D | 6, 7 | Accepted C → D. Layout/asm receipts; signed persistent scheduler/MM/IPC/file/inotify suites including exhaustion/cancellation and deterministic work budgets | Full persistent CPL0 behavior matrix and final shared-module receipt |

These are **four batched signed comparisons**, not a signed gate per
mechanical commit. All commits in a batch are portable-green; the batch is
accepted only as a whole. The director records each base/head's exact
fixtures, image + executable SHA-256/CDHash/LC_UUID, entitlement and DOF,
matched command/test counts, failures and run-ID-scoped cleanup. **No added
signed failure** is the ARM bar for each batch. A pre-existing red witness
must be qualified on both artifacts; disappearance before execution is not
green. No retries, relaxed budgets, extra workers, timeouts or polling may
hide new failures. If an asm block intentionally changes beyond relocation,
isolate its reason and prove the affected contract; never claim unchanged
assembly from a passing hash.

Per mechanical cut run the cheapest capable red-first contract witnesses,
both freestanding image builds, focused portable crate tests, affected
Clippy, fmt-check and lint-domains. Signature/layout-only cuts can use
mutated manifest/native-frame controls rather than invent Linux probes.
Behavioral cuts use existing conformance contracts and deterministic budgets;
add a red-first contract only for an uncovered case. Reference
`S:docs/conformance-contracts.md:30,131,170` and the conformance-contract
skill. The documentation/census-script revision has no guest-visible
behavior change; its test is deterministic regeneration plus stale-citation
rejection. Workers on carrick-vm run no Docker, signed HVF or full acceptance
gate; the director owns the four signed comparisons and one full stacked
landing gate. Earlier input acceptance is not a fifth inversion batch.

## Minimal host changes and cheap macOS guard

| Host/consumer | Required changes; custody retained |
| --- | --- |
| carrick-runtime | Step 2 updates actual ARM handback constructor (`zone.rs:78–136`), all context writes, parked-read/crash projections and versioned per-ISA table decoding. <!-- cite:host-zone -->`S:crates/carrick-runtime/src/vcpu_loop/zone.rs:78`; <!-- cite:host-zone-apply -->`S:crates/carrick-runtime/src/vcpu_loop/zone.rs:136`; <!-- cite:host-crash -->`S:crates/carrick-runtime/src/vcpu_loop/crash.rs:422` |
| carrick-aarch64 | Explicit `Aarch64Context`/ARM table specialization in native snapshot, service and register consumers; same host backend, pin/backing and vector custody. <!-- cite:host-snapshot -->`S:crates/carrick-aarch64/src/vmm.rs:138`; <!-- cite:native-mailbox -->`S:crates/carrick-aarch64/src/mailbox.rs:5` |
| carrick-vmm-hvf | ARM specialization at table allocation/reads, consume full manifest and exact retained mailbox/page offsets; native vector/HVC/GIC/stage-2 custody remains. Host vectors participate in step-0 asm manifest, not guest-generic code. <!-- cite:native-mailbox -->`S:crates/carrick-aarch64/src/mailbox.rs:5`; <!-- cite:portal-slots -->`S:crates/carrick-el1-abi/src/mm_portal.rs:116` |
| carrick-vmm-kvm | Instantiate x86 table/context descriptor, bind bootstrap metadata backing and existing doorbell/interrupt service; retain physical storage and CPUID/XCR0 qualification. <!-- cite:xcr0 -->`S:crates/carrick-vmm-kvm/src/carrier_interrupts.rs:300`; <!-- cite:o6-xcr0 -->`O6:crates/carrick-vmm-kvm/src/carrier_interrupts.rs:400` |
| Image builders and debug readers | Extend actual shared-package dependency invalidation; emit both module/asm/layout manifests; LLDB/crash decoding checks ISA/version and reads correct native context. ELF image bound remains enforced. <!-- cite:image-bound -->`S:crates/carrick-el1/link.ld:36` |

A cheap **portable compile guard** imports and type-checks the actual
context/layout constructor and reader APIs used by `zone.rs`, `crash.rs`,
HVF and carrick-aarch64. Factor only the constructor/projection functions
needed by these consumers into a host-portable module and have production
callers use it too; a duplicated test constructor is not a guard. Compile
both ARM and x86 instantiations on Linux and exercise full offset manifests.
On macOS also compile-check `carrick-vmm-hvf`, the macOS runtime/CLI closure
and affected all-targets before the batch's signed gate. Linux cannot check
Applevisor APIs or execute HVF, so the portable guard catches ordinary drift
but does not replace the Mac check or signed comparison. Do not transfer
scheduler, Linux policy or MM ownership to host fallback implementations.

## Risks and disproofs

| Risk | Concrete failure control and evidence |
| --- | --- |
| no_std/alloc closure | Current cfg hides allocating EL1 bodies from x86; NoAllocation halts on use. Compile full release image closures, bind real bounded metadata capacity before routing allocating operations, audit no host std/libc in the guest closure. <!-- cite:cfg-exclusions -->`S:crates/carrick-el1/src/lib.rs:13`; <!-- cite:noallocation -->`S:crates/carrick-x86-cpl0/src/entry.rs:11`; <!-- cite:allocator -->`S:crates/carrick-el1/src/alloc.rs:25` |
| Image size/stack | ARM linker permits 1 MiB before adjacent ABI regions (<!-- cite:image-bound -->`S:crates/carrick-el1/link.ld:36`). Report each artifact's text/rodata/data/bss, total image bytes, table/context storage and stack high-water mark. Genericizing must not instantiate both backends in each image. Reject overlap; no silent aperture increase. x86 image budget is measured against its own linker/boot mappings. |
| Atomics/order | Preserve each algorithm's Acquire/Release/CAS and publication order across both ISA implementations. x86 TSO cannot excuse removing ARM barriers; architectural TLB/coherence completion is distinct from Rust atomic publication. Test publication/cancel/claim/drain races with exact generation and two live mms. <!-- cite:identity -->`S:crates/carrick-el1/src/sched.rs:100`; <!-- cite:spinlock -->`S:crates/carrick-el1/src/lock.rs:27`; <!-- cite:irq-save -->`S:crates/carrick-el1/src/sched/hw.rs:260` |
| Interrupt context | No blocking host service/heap expansion under IRQ lock; nested mask restoration and single-consumption ack. Inject interrupts at enrollment/return boundaries; hold lock before a same-subsystem interrupt to expose reentry. <!-- cite:irq-token -->`S:crates/carrick-guest-arch/src/lib.rs:230`; <!-- cite:allocator-irq -->`S:crates/carrick-el1/src/alloc.rs:51` |
| Context ownership/size | Clone only machine state while claim/quiescence is authenticated; retain incarnation revalidation. XSAVE=832 needs qualified XCR0=7/CPUID and align64; reject other component sets. ARM full offsets are immutable. <!-- cite:parked-copy -->`S:crates/carrick-sched-core/src/lib.rs:3821`; <!-- cite:native-context -->`S:crates/carrick-x86/src/cpl0_scheduler.rs:34`; <!-- cite:xcr0 -->`S:crates/carrick-vmm-kvm/src/carrier_interrupts.rs:300` |
| False module progress | Linking enabled declarations/rlibs or fixture-only branches does not count. Track real reachable shared bodies, release hashes and production runtime witnesses; exclude pure re-exports/duplicated implementations. <!-- cite:cfg-personality -->`S:crates/carrick-el1/src/personality/mod.rs:8`; <!-- cite:cpl0-adapter -->`S:crates/carrick-x86-cpl0/src/entry.rs:26` |
| macOS-only consumer drift | Compile the shared production constructors/projections on Linux; Mac closure check and matched signed artifact remain required. Context coupling is in production code, not merely cfg(test). <!-- cite:host-zone -->`S:crates/carrick-runtime/src/vcpu_loop/zone.rs:78`; <!-- cite:host-crash -->`S:crates/carrick-runtime/src/vcpu_loop/crash.rs:422` |
| Input races/regression attribution | Single entry owner, ordered accepted inputs, preserved fix ledger; retain R's already-red investigation disposition and qualify actual landing base/head. `R:docs/perf-results/2026-10-06-x1-arm-regression.md:5,103` |

## Regeneration and document review

Run from a worktree containing the pinned commits:

```sh
cargo run --locked --offline --manifest-path docs/superpowers/plans/inversion-census/Cargo.toml -- --write
cargo run --locked --offline --manifest-path docs/superpowers/plans/inversion-census/Cargo.toml -- --check
cargo fmt --manifest-path docs/superpowers/plans/inversion-census/Cargo.toml -- --check
cargo clippy --locked --offline --manifest-path docs/superpowers/plans/inversion-census/Cargo.toml --all-targets -- -D warnings
```

`--check --document PATH` supports checking a temporary mutated copy: changing
a marked citation or generated site must fail; restoring/regenerating it
must pass. The generator is a documentation audit script, **not** the
planned `carrick debug asm-block-diff` capability. It cannot qualify ISA
instruction equivalence or runtime behavior. Appendix A below replaces the
hand-maintained anchors implicated in the independent review, including IRQ,
linker bound, IPC replay, CR3 install and scheduler identity/type sites.

<!-- BEGIN GENERATED APPENDIX A -->

## Appendix A: regenerated source census and citation anchors

Generated by the committed Rust audit script `docs/superpowers/plans/inversion-census/src/main.rs`. All census sites are at S; semantic anchor rows explicitly select S or O6. The script reads immutable git blobs, resolves each prose anchor from a unique source string, parses asm macro spans with syn (including operands/options), and refuses a missing or ambiguous anchor. This is a conservative lexical inventory plus full native-item spans, not proof of reachability, complete indirect hardware semantics, or machine-code equivalence. Inclusive runs enumerate individual physical source lines. Tests/cfg branches are included. MMU-core's existing ISA modules are audited as whole native items below, without extra relocation credit.

### Source totals

| Crate | Retained src Rust lines | Distinct ISA-site hits |
| --- | ---: | ---: |
| carrick-el1 | 22907 | 1873 |
| carrick-el1-abi | 10940 | 394 |
| carrick-aarch64 | 15733 | 1337 |
| carrick-core | 10747 | not scanned |
| carrick-core-abi | 3884 | not scanned |
| carrick-personality-linux | 1609 | not scanned |
| carrick-sched-core | 11050 | 93 |
| carrick-mmu-core | 18744 | not scanned |
| carrick-guest-arch | 368 | 13 |
| carrick-x86 | 5465 | 405 |
| carrick-x86-cpl0 | 371 | 134 |
| carrick-el1-image | 16 | not scanned |

Three-crate ARM denominator: **49580**. Fully parsed asm macro invocations in the seven scanned packages: **51**. Blank lines and trimmed `//` prefixes are excluded; block-comment prefixes and Rust dereference assignments are retained. Build scripts and integration tests are outside src and excluded.

### Semantic anchors (generated, including prose citations)

| Key | Citation | Matched source line |
| --- | --- | --- |
| arch-types | `S:crates/carrick-guest-arch/src/lib.rs:287` | `pub trait ArchTypes {` |
| entry-trait | `S:crates/carrick-guest-arch/src/lib.rs:362` | `arch_trait!(EntryArch, EntryBackend {` |
| mmu-trait | `S:crates/carrick-guest-arch/src/lib.rs:370` | `arch_trait!(MmuArch, MmuBackend {` |
| irq-trait | `S:crates/carrick-guest-arch/src/lib.rs:381` | `arch_trait!(InterruptArch, InterruptBackend {` |
| crossing-trait | `S:crates/carrick-guest-arch/src/lib.rs:393` | `arch_trait!(CrossingArch, CrossingBackend {` |
| kernel-trait | `S:crates/carrick-guest-arch/src/lib.rs:400` | `pub trait KernelArch: sealed::Sealed + EntryArch + MmuArch + InterruptArch + CrossingArch {}` |
| snapshot | `S:crates/carrick-guest-arch/src/lib.rs:131` | `pub struct NativeEntrySnapshot<'a, F> {` |
| irq-token | `S:crates/carrick-guest-arch/src/lib.rs:230` | `pub struct InterruptAck<I> {` |
| host-ticket | `S:crates/carrick-guest-arch/src/lib.rs:256` | `pub struct RequestToken<T> {` |
| root-gpa | `S:crates/carrick-guest-arch/src/lib.rs:71` | `pub struct RootGpa(FrameGpa);` |
| cfg-exclusions | `S:crates/carrick-el1/src/lib.rs:13` | `pub mod cow;` |
| cfg-personality | `S:crates/carrick-el1/src/personality/mod.rs:8` | `pub mod dispatch;` |
| allocator | `S:crates/carrick-el1/src/alloc.rs:25` | `pub struct MetadataStorage {` |
| allocator-lock | `S:crates/carrick-el1/src/alloc.rs:11` | `pub use crate::substrate::sched::hw::{IrqGuard, disable_irq_save, restore_irq};` |
| allocator-irq | `S:crates/carrick-el1/src/alloc.rs:51` | `pub fn ensure_bootstrap_admitted(&self) {` |
| spinlock | `S:crates/carrick-el1/src/lock.rs:27` | `pub fn lock(&self) -> SpinLockGuard<'_, T> {` |
| irq-save | `S:crates/carrick-el1/src/sched/hw.rs:260` | `pub fn disable_irq_save() -> IrqGuard {` |
| irq-restore | `S:crates/carrick-el1/src/sched/hw.rs:279` | `pub fn restore_irq(guard: IrqGuard) {` |
| fatal-leaf | `S:crates/carrick-el1/src/sched/hw.rs:297` | `pub(crate) fn fatal_entry_binding() -> ! {` |
| identity | `S:crates/carrick-el1/src/sched.rs:100` | `.store(id.generation, Ordering::Release);` |
| scheduler | `S:crates/carrick-el1/src/sched.rs:107` | `pub struct Sched<'a, C: ThreadCpu, U: UserWord> {` |
| sched-result | `S:crates/carrick-el1/src/sched.rs:317` | `self.task.linux.orig_arg0.store(ctx.x[0], Ordering::Relaxed);` |
| child-context | `S:crates/carrick-el1/src/personality/lifecycle.rs:489` | `ctx.x[0] = 0;` |
| o6-child | `O6:crates/carrick-el1/src/personality/lifecycle.rs:137` | `ctx.x[0] = context.result.raw() as u64;` |
| replay | `S:crates/carrick-el1/src/personality/ipc.rs:651` | `OperationResumePc::new(frame.elr.wrapping_sub(linux::SVC_LEN)),` |
| threadctx | `S:crates/carrick-sched-core/src/lib.rs:382` | `pub struct ThreadCtx {` |
| zone-record | `S:crates/carrick-sched-core/src/lib.rs:534` | `pub struct ZoneRecord {` |
| record-context | `S:crates/carrick-sched-core/src/lib.rs:573` | `ctx: UnsafeCell<ThreadCtx>,` |
| zone-tables | `S:crates/carrick-sched-core/src/lib.rs:1026` | `pub struct ZoneTables {` |
| parked-copy | `S:crates/carrick-sched-core/src/lib.rs:3821` | `let ctx = unsafe { *record.ctx_mut() };` |
| trap-frame | `S:crates/carrick-el1-abi/src/lib.rs:645` | `pub struct TrapFrame {` |
| current-task | `S:crates/carrick-el1-abi/src/lib.rs:690` | `pub struct CurrentTask {` |
| layout-hash | `S:crates/carrick-el1-abi/src/lib.rs:364` | `pub const EL1_ABI_LAYOUT_HASH: u64 = {` |
| hash-assert | `S:crates/carrick-el1-abi/src/lib.rs:3034` | `const _: () = assert!(EL1_ABI_LAYOUT_HASH == 0x3ff0_698f_9f1a_67f1);` |
| image-header | `S:crates/carrick-el1-abi/src/lib.rs:587` | `pub struct ImageHeader {` |
| metadata-mailbox | `S:crates/carrick-el1-abi/src/lib.rs:819` | `pub struct MetadataGrantMailbox {` |
| delegated-file | `S:crates/carrick-el1-abi/src/lib.rs:1053` | `pub struct DelegatedFile {` |
| delegated-inotify | `S:crates/carrick-el1-abi/src/lib.rs:2567` | `pub struct DelegatedInotify {` |
| lifecycle-page | `S:crates/carrick-el1-abi/src/thread_lifecycle.rs:688` | `pub struct ThreadLifecyclePage {` |
| lifecycle-version | `S:crates/carrick-el1-abi/src/thread_lifecycle.rs:53` | `pub const THREAD_LIFECYCLE_PROTOCOL_VERSION: u64 = 6;` |
| control-slot | `S:crates/carrick-el1-abi/src/thread_lifecycle.rs:459` | `pub struct ThreadControlSlot {` |
| pool-entry | `S:crates/carrick-el1-abi/src/thread_lifecycle.rs:332` | `pub struct PoolEntry {` |
| entry-ref | `S:crates/carrick-el1-abi/src/thread_lifecycle.rs:195` | `pub struct EntryRef {` |
| portal-slots | `S:crates/carrick-el1-abi/src/mm_portal.rs:116` | `pub struct MmPortalSlots {` |
| descriptor-slots | `S:crates/carrick-el1-abi/src/descriptor_txn.rs:32` | `pub struct DescriptorTxnSlots {` |
| copy-table | `S:crates/carrick-el1-abi/src/service_copy.rs:65` | `pub struct ServiceCopyTable {` |
| native-mailbox | `S:crates/carrick-aarch64/src/mailbox.rs:5` | `pub use carrick_mem::memory::Aarch64SyscallMailbox;` |
| mailbox-version | `S:crates/carrick-aarch64/src/mailbox.rs:2` | `pub const AARCH64_SYSCALL_MAILBOX_VERSION: u32 = 3;` |
| host-zone | `S:crates/carrick-runtime/src/vcpu_loop/zone.rs:78` | `) -> Result<ThreadCtx, RuntimeError> {` |
| host-zone-apply | `S:crates/carrick-runtime/src/vcpu_loop/zone.rs:136` | `ctx: &mut ThreadCtx,` |
| host-crash | `S:crates/carrick-runtime/src/vcpu_loop/crash.rs:422` | `let registers = file.registers;` |
| host-snapshot | `S:crates/carrick-aarch64/src/vmm.rs:138` | `pub struct Aarch64VcpuSnapshot {` |
| native-context | `S:crates/carrick-x86/src/cpl0_scheduler.rs:34` | `pub struct NativeContext {` |
| xsave | `S:crates/carrick-x86/src/cpl0_scheduler.rs:23` | `pub const XSAVE_BYTES: usize = 832;` |
| cr3-install | `S:crates/carrick-x86/src/cpl0_scheduler.rs:122` | `pub unsafe fn install_root(root: RootGpa) {` |
| xcr0 | `S:crates/carrick-vmm-kvm/src/carrier_interrupts.rs:300` | `return Err(fail("CPL0 requires qualified XCR0=7"));` |
| o6-xcr0 | `O6:crates/carrick-vmm-kvm/src/carrier_interrupts.rs:400` | `return Err(fail("CPL0 requires qualified XCR0=7"));` |
| noallocation | `S:crates/carrick-x86-cpl0/src/entry.rs:11` | `struct NoAllocation;` |
| cpl0-adapter | `S:crates/carrick-x86-cpl0/src/entry.rs:26` | `#[path = "../../carrick-x86/src/cpl0_entry.rs"]` |
| x86-frame | `S:crates/carrick-x86/src/cpl0_entry.rs:18` | `pub struct NativeFrame {` |
| image-bound | `S:crates/carrick-el1/link.ld:36` | `ASSERT(_image_end <= _image_start + 0x100000,` |
| guarded-copy | `S:crates/carrick-el1/src/file.rs:84` | `pub(crate) unsafe fn copy_from_user_guarded(` |
| validator | `S:crates/carrick-el1/src/file.rs:165` | `fn writable_bytes(&self, user_va: u64, len: usize) -> usize {` |
| fault | `S:crates/carrick-el1/src/fault.rs:891` | `pub fn dispatch_fault_with_regions<C: CowResolver>(` |
| owner-mmu | `S:crates/carrick-mmu-core/src/owner_mmu.rs:21` | `pub trait OwnerMmu {` |
| owner-grant | `S:crates/carrick-mmu-core/src/owner_mmu.rs:137` | `pub trait OwnerGrantMmu: OwnerForkMmu {` |
| core-completion | `S:crates/carrick-core-abi/src/entry.rs:118` | `pub struct EntryCompletion {` |
| linux-epoll | `S:crates/carrick-abi/src/lib.rs:902` | `pub struct LinuxX8664EpollEvent {` |
| arm-epoll | `S:crates/carrick-el1/src/personality/ipc/epoll.rs:57` | `const EVENT_BYTES: usize = 16;` |

### T — trap/frame

| Pinned source path (S) | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-aarch64/src/descriptor_drain.rs` | 128–129, 230–231, 333, 399–401, 403, 405–406, 435, 440, 447, 468, 471, 489 |
| `crates/carrick-aarch64/src/engine.rs` | 94, 195–196, 198, 222, 225, 232–233, 238, 250, 256, 285, 569, 574–575, 697, 707, 709, 718, 722, 727, 742, 744, 901, 1590, 1645, 1991, 2030, 2099, 2106–2107, 2109, 2120, 2126, 2145–2146, 2167, 2170, 2173, 2176, 2181, 2184, 2189, 2195, 2199, 2203, 2214, 2219, 2224, 2243–2244, 2250, 2268, 2274, 2277, 2282, 2287, 2292, 2321, 2328, 2332–2336, 2344, 2351, 2513, 2543, 2545–2546, 2561–2562, 2571, 2574, 2582–2584, 2587, 2596, 2605, 2609, 2621, 2652, 3204, 3206, 3208–3209, 3213, 3216, 3226, 3228–3235, 3300–3301, 4655–4656, 4658–4659, 4661–4662, 4664–4665, 4744, 4757, 4952, 4955, 4968, 5366, 5435–5437, 5578, 5650, 5876–5877, 5882–5883, 5889, 5892, 5910, 5916, 5919, 5925, 5943, 5999, 6005–6006, 6067, 6069, 6085, 6091, 6098, 6107–6108, 6112, 6117, 6176–6177, 6181–6183, 6491, 6809, 7004, 7008, 7192, 7635, 7645, 8639, 8696, 8700, 8736–8737, 8740–8741, 8743, 8747, 8754, 8757, 8762, 8893, 8895, 8905, 8907, 8922, 8929–8930, 8940, 8943, 8980, 8984–8987, 8990–8992, 8994, 9304, 9316, 9385, 9461, 9464 |
| `crates/carrick-aarch64/src/esr.rs` | 6, 11, 30, 38, 44–45, 51–54, 61–63 |
| `crates/carrick-aarch64/src/fork.rs` | 4, 73, 84–86, 137, 185–187, 192, 359, 383 |
| `crates/carrick-aarch64/src/lib.rs` | 30, 48 |
| `crates/carrick-aarch64/src/mailbox.rs` | 22, 26, 80, 96, 407, 411 |
| `crates/carrick-aarch64/src/owed_kick.rs` | 82, 87, 100, 120, 123, 125, 132–133, 142, 162–163, 224, 234, 245, 249, 307, 323, 325, 330, 345, 348–349, 386–387, 396, 399, 402 |
| `crates/carrick-aarch64/src/user_transfer.rs` | 9, 77–79, 94, 109, 111–112, 117–118, 123, 313–315, 317–318, 320–321, 324–325, 328, 500–502, 569, 573, 601–603, 605, 611, 617, 620, 624, 804–808 |
| `crates/carrick-aarch64/src/user_transfer/prepared.rs` | 36–38 |
| `crates/carrick-aarch64/src/user_transfer/staging.rs` | 122–124, 126–133, 150–151, 156, 164, 172, 178, 180, 188, 191, 198, 200, 204–206, 210, 216, 221, 224, 229, 237, 241, 246–248, 251, 256, 267 |
| `crates/carrick-aarch64/src/vmm.rs` | 22, 54, 60, 78, 80, 93, 101, 267–270, 327, 329, 364, 1453, 1457, 1462, 1466, 1514–1515, 1532 |
| `crates/carrick-el1-abi/src/descriptor_txn.rs` | 225, 266, 311 |
| `crates/carrick-el1-abi/src/lib.rs` | 380–384, 434, 645, 647, 649, 651, 653, 657, 1566–1567, 1569, 1604–1605, 1608–1612, 2218–2219, 2221, 3088–3095, 3939, 3942 |
| `crates/carrick-el1-abi/src/mm_portal.rs` | 10, 107, 109–110 |
| `crates/carrick-el1-abi/src/mm_portal_fork.rs` | 4–5 |
| `crates/carrick-el1-abi/src/mm_portal_grant.rs` | 2 |
| `crates/carrick-el1/src/cow.rs` | 30, 37, 185, 192, 217, 397, 410, 930, 945, 960–962, 964, 1088, 1103, 1128–1130, 1132 |
| `crates/carrick-el1/src/entry.rs` | 37, 42, 46, 50, 54, 58, 62, 66, 70 |
| `crates/carrick-el1/src/fault.rs` | 4, 27–29, 35, 42–44, 50, 57–60, 215–216, 218, 224, 399, 420, 432, 707–708, 721, 729, 762, 767–768, 770, 773, 783, 804, 822, 892, 921, 924, 928, 947–948, 952, 963, 973, 1005, 1011, 1024, 1034, 1055, 1061, 1065, 1075, 1081, 1097, 1102, 1130–1133, 1135, 1139–1142, 1144, 1296–1299, 1323–1324, 1328, 1330, 1352–1355, 1385–1386, 1489, 1508, 1762, 1846–1849, 1854, 2156–2158, 2160, 2373–2374, 2376, 2378–2379, 2386, 2388, 2395 |
| `crates/carrick-el1/src/memory.rs` | 6, 86, 99, 113, 124, 141, 145, 147–149, 155, 164, 187, 199, 201, 203, 211, 217, 221, 223–224, 227, 229, 232, 236, 243, 246, 249–250, 267, 270, 670, 677, 890, 895, 898–899, 949, 954, 957–959, 1045, 1053–1057, 1079, 1094–1095, 1234–1235, 1246, 1253–1254, 1267, 1279, 1441–1443, 1445–1446, 1455 |
| `crates/carrick-el1/src/personality/dispatch.rs` | 8, 34, 54, 61, 77, 113, 124, 149–150, 153, 161, 187, 204, 239, 277, 295, 339, 426, 434, 450, 465–466, 481, 498, 553, 580, 598, 645, 677, 687, 703, 709–711, 726–727, 737, 746, 757–759, 773, 800, 818, 855, 1003–1004, 1030, 1033, 1039, 1046, 1058–1059, 1074–1077, 1082, 1096–1099, 1108–1110, 1121–1124, 1129 |
| `crates/carrick-el1/src/personality/ipc.rs` | 53, 71, 175, 179, 208, 254, 264–265, 280–282, 323, 341, 398, 549, 640, 651, 723, 741, 752–753, 756–757, 1134, 1156, 1164, 1189–1190, 1194–1197, 1199, 1201–1204, 1208–1210, 1283, 1285, 1305, 1308, 1312–1313, 1315, 1334, 1341, 1343, 1346, 1367, 1369, 1371, 1375, 1377, 1404, 1411, 1413, 1446, 1458, 1460, 1483, 1486, 1489, 1491, 1516, 1521, 1533, 1535, 1539, 1542, 1553, 1557, 1561, 1564, 1581, 1623, 1635, 1646, 1648, 1683, 1685, 1741, 1799, 1821, 1825, 1833, 1839, 1844, 1849, 1851–1852, 1860, 1893, 1916, 1924, 1926, 1930, 1934, 1940, 1946, 1948, 1972, 1981, 2003, 2037, 2042, 2084, 2088, 2140, 2168, 2220, 2231, 2256, 2263, 2342, 2344, 2358, 2413–2414 |
| `crates/carrick-el1/src/personality/ipc/epoll.rs` | 41, 84, 102, 113, 118, 121, 126, 144, 162–163, 193, 297–298, 306 |
| `crates/carrick-el1/src/personality/lifecycle.rs` | 34, 124, 131, 138–140, 167, 192, 197, 208, 222, 226, 272, 277, 392, 399, 489, 520, 609, 618 |
| `crates/carrick-el1/src/personality/lifecycle/tests.rs` | 161–163, 165, 186–189, 217, 262, 303, 349–350, 385, 467, 483–485, 498–500, 508, 564, 590, 617, 671, 678–680, 730, 734, 817, 824, 844, 849–851, 863–864, 885–886, 991 |
| `crates/carrick-el1/src/personality/mm_portal/edit_wait.rs` | 9, 16, 19, 29, 39–40, 43, 48–49, 81–82 |
| `crates/carrick-el1/src/personality/mm_portal/fork.rs` | 428, 430, 434, 438, 443, 466, 475–476, 479, 493, 495, 497, 503, 508, 514, 519, 525, 586 |
| `crates/carrick-el1/src/personality/mm_portal/maintenance.rs` | 214–215, 222, 251, 253 |
| `crates/carrick-el1/src/personality/mm_portal/production.rs` | 67, 72, 162, 167, 172, 177, 180–181, 197, 212, 217, 262–265, 267–268, 276–283, 286, 289, 296, 300–302, 310, 313–314, 344–347, 351, 389, 394, 399, 408, 411, 418, 420, 438, 442–443, 449 |
| `crates/carrick-el1/src/personality/mm_portal/tests.rs` | 3020, 3068–3072, 3074, 3076–3077, 3144, 3304, 3354–3359, 3414 |
| `crates/carrick-el1/src/personality/native_ownership_tests.rs` | 11, 194–200, 212 |
| `crates/carrick-el1/src/personality/reservation_decoder_tests.rs` | 35–37, 41, 74, 76–77, 79–80, 111, 143–145, 150, 168–170, 190–192, 230 |
| `crates/carrick-el1/src/personality/sched.rs` | 3, 13–14, 16, 18, 23, 67, 74, 77 |
| `crates/carrick-el1/src/sched.rs` | 4, 22, 24, 142, 180, 187, 207, 264, 307, 317, 319, 389, 472, 529, 547, 563, 712, 725 |
| `crates/carrick-el1/src/sched/aarch64_context.rs` | 3, 5–8, 10–13, 84, 105 |
| `crates/carrick-el1/src/sched/hw.rs` | 15, 111, 114, 248 |
| `crates/carrick-el1/src/sched/object_wait.rs` | 11, 97, 150 |
| `crates/carrick-el1/src/sched/tests.rs` | 10, 76, 99, 139, 142–143, 159, 161–164, 166, 168–170, 186–191, 196, 207, 214–215, 331, 398, 428, 432, 434, 455, 457, 473, 484, 529, 558, 593–594, 596, 614–615, 669, 691–692, 720, 814, 835–838, 840, 933, 936, 959–960, 984, 995, 997, 1004–1005, 1011, 1013, 1047, 1049, 1062, 1167, 1205, 1312, 1392–1393, 1405–1407, 1436–1437, 1470–1471, 1545, 1548, 1560, 1575 |
| `crates/carrick-guest-arch/src/lib.rs` | 177, 289, 329, 363–368 |
| `crates/carrick-sched-core/src/lib.rs` | 384, 411 |
| `crates/carrick-sched-core/src/object_wait.rs` | 2423–2424 |
| `crates/carrick-sched-core/src/tests.rs` | 72, 1674, 2260, 2292 |
| `crates/carrick-x86-cpl0/src/entry.rs` | 41–81, 83–89, 99, 102–103, 108, 113, 115, 147 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 24–68, 210 |
| `crates/carrick-x86/src/arch_context.rs` | 47–49, 72–74 |
| `crates/carrick-x86/src/bringup.rs` | 327–328, 349, 352, 361 |
| `crates/carrick-x86/src/bringup_fns.rs` | 337, 368–369, 442–444, 494–496, 541–543, 576, 582–583, 1006–1008, 1029, 1032–1033, 1040–1042, 1057–1059, 1130–1131, 1136 |
| `crates/carrick-x86/src/bringup_fns/poll_tests.rs` | 27 |
| `crates/carrick-x86/src/cpl0_entry.rs` | 18, 31–34, 36–37, 39, 51–56, 60, 63, 65, 70, 74, 108, 114–115, 126–127, 137–138, 145, 153, 155, 161–164, 170–171, 177–178, 186–187, 193, 196–197 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 11–12, 15, 19, 171–172, 175 |
| `crates/carrick-x86/src/engine.rs` | 786, 793, 800, 814, 1056, 1059, 1679–1683, 1863, 1868, 1872, 1877–1878, 1898, 1906, 1913, 1919–1920, 2093–2097, 2124–2126, 2143–2147, 2238–2241, 2329–2332, 2339, 2348–2351, 2366–2369, 2386, 2393–2396, 2412, 2420, 2443–2446, 2480–2483, 2513–2516, 2530, 2532, 2541–2544, 2564, 2584, 2617–2620, 2628 |
| `crates/carrick-x86/src/fault.rs` | 86, 100, 114, 116–117, 137, 139–140, 164, 180, 182–183, 194, 196–197, 207, 209–210, 217, 219–220, 245, 247–248, 438–439, 457–459, 507, 525, 562, 583, 594, 598, 615, 639, 693, 695–696, 731, 733–734 |

### C — context/TLS

| Pinned source path (S) | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-aarch64/src/engine.rs` | 94, 1062, 1107, 1123, 1127, 1129–1130, 1143–1145, 1147–1148, 1199, 1201, 1234–1235, 1248–1250, 1252–1253, 2236, 2352, 4667–4668, 4670–4671, 4673–4674, 4676–4677, 4679–4680, 4682–4683, 5134, 5148, 5156, 5164, 5209, 5211, 5215, 5218, 5224, 5227, 6027, 6031, 6034, 6036–6037, 6813, 6850, 6852, 6859, 7015, 7017, 7020–7021, 7033–7034, 7036, 7039–7040, 7063, 7085, 7107, 7109–7110, 7119–7120, 7131–7132, 7135–7136, 7500–7501, 7508–7510, 7512–7513, 7516, 7518, 7545, 7572–7573, 7585–7587, 7589–7590, 7634, 7653, 8947, 8950, 8953, 8956, 8959, 8962, 8971, 8974, 9125 |
| `crates/carrick-aarch64/src/lib.rs` | 48 |
| `crates/carrick-aarch64/src/owed_kick.rs` | 120, 124, 142, 144, 162, 176, 205, 219, 227, 237, 253, 257, 261, 265, 269, 273, 285, 289, 333, 337, 340, 376, 396, 425, 449, 505 |
| `crates/carrick-aarch64/src/vmm.rs` | 138, 142, 144, 157, 161, 169, 177, 179, 273–278, 288–289, 298, 1425, 1470, 1474, 1478, 1482, 1486, 1490, 1502, 1506 |
| `crates/carrick-el1-abi/src/lib.rs` | 513, 1865 |
| `crates/carrick-el1/src/personality/ipc.rs` | 775, 1163 |
| `crates/carrick-el1/src/personality/lifecycle.rs` | 34, 209, 211, 490, 492, 495–496 |
| `crates/carrick-el1/src/personality/lifecycle/tests.rs` | 136–137, 139–140, 352, 354–355, 358, 791, 794, 865–866 |
| `crates/carrick-el1/src/sched.rs` | 4, 22, 24, 651–654, 656–657, 712, 714–717, 720–721, 725, 727–730, 733–734 |
| `crates/carrick-el1/src/sched/aarch64_context.rs` | 3, 5, 8, 10, 13, 17–20, 22–70, 74–75, 84, 88–100, 105, 110–121, 123–124 |
| `crates/carrick-el1/src/sched/hw.rs` | 15, 111, 114 |
| `crates/carrick-el1/src/sched/tests.rs` | 3, 123, 137–138, 145–149, 153–154, 164, 173–176, 178–179, 223, 335, 344, 1090, 1106, 1546, 1550–1554, 1556–1557, 1562–1566, 1568–1569 |
| `crates/carrick-sched-core/src/lib.rs` | 382, 389–393, 398–399, 403, 405, 407, 409, 413–417, 420–421, 442, 573, 699 |
| `crates/carrick-sched-core/src/tests.rs` | 1672–1673, 1678–1682, 1688–1689, 1695 |
| `crates/carrick-x86-cpl0/src/entry.rs` | 41–81, 83–89 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 24–68, 104, 112, 114, 120, 138, 158, 201–203, 229 |
| `crates/carrick-x86/src/arch_context.rs` | 54–56, 67, 79–80, 83 |
| `crates/carrick-x86/src/bringup.rs` | 298, 356, 365 |
| `crates/carrick-x86/src/bringup_fns.rs` | 451–452, 458, 501–503, 546–547, 551, 580, 1013–1015, 1031, 1047–1049, 1060 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 23–24, 27–29, 34, 37–39, 45, 47, 73, 85, 88, 101, 167, 169, 183–185, 203, 209 |
| `crates/carrick-x86/src/engine.rs` | 828, 843, 1005, 1017, 1030, 1035, 1634, 1688–1690, 1740, 1841, 1962, 1966, 1971, 1975, 1997, 2001, 2102–2104, 2131–2133, 2152–2154 |
| `crates/carrick-x86/src/vmm.rs` | 533–534, 605 |

### D — descriptors/geometry

| Pinned source path (S) | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-aarch64/src/descriptor_drain.rs` | 4–5, 132–133, 135, 145, 147, 166, 173, 175, 179, 205, 240–241, 243, 266, 268, 291–292, 294, 319, 325, 378–380, 386–387, 399, 406, 419, 427–428, 441, 452, 456, 525–526, 547–549 |
| `crates/carrick-aarch64/src/engine.rs` | 40–41, 67, 86, 117–118, 143, 146–147, 199, 260, 275, 287, 305, 307, 316, 318, 334, 340, 370, 582–583, 585, 599, 601, 622, 647, 676, 678, 732, 862, 864, 901–902, 908, 1133–1137, 1210–1211, 1216, 1218–1221, 1238–1242, 1267, 1286–1287, 1305, 1346, 1585, 1631, 1639, 1727, 1741–1743, 1758, 1763, 1768, 1773, 1776, 1790, 1813, 1830, 1947–1948, 2155, 2158, 2163, 2195, 2237, 2240, 2251–2253, 2257, 2365, 2371, 2421, 2426, 2907, 2912–2913, 2920, 2947, 2966, 2973, 3007, 3028, 3032, 3035, 3037, 3086, 3135–3136, 3146–3147, 3149, 3155, 3160, 3162, 3285, 3298, 3330, 3334, 3513, 3519, 3523, 3530, 3540, 3619, 3636, 3733, 3798, 3848, 3850–3852, 3968, 3983, 4012, 4412, 4628, 4633–4634, 4811–4812, 4899, 4905, 5059, 5074, 5087, 5106, 5325, 5366, 5376, 5443–5444, 5467, 5499, 5506, 5549–5550, 5600, 5650, 5670, 5678, 5731–5733, 5744, 5794–5796, 5800–5801, 5805–5807, 5844, 5917, 5925, 5942–5943, 6069–6070, 6084–6085, 6092–6093, 6101–6102, 6132–6133, 6176, 6178, 6181–6184, 6192, 6194, 6200–6201, 6339–6340, 6535, 6588, 6616, 6626, 6852, 6876, 7025–7029, 7064, 7086, 7123–7124, 7504–7506, 7538–7539, 7549–7550, 7574–7576, 7582–7583, 7673, 7763, 7796, 7809, 7821, 7907–7908, 7920, 7927, 7943, 7983–7985, 8010, 8012, 8016, 8027–8029, 8043, 8053, 8091–8093, 8118, 8120, 8124, 8135–8137, 8148–8150, 8153, 8156, 8162, 8167–8168, 8224, 8229–8230, 8319, 8351, 8356–8357, 8409, 8435, 8440–8441, 8457, 8462–8463, 8478, 8489, 8494–8495, 8507, 8524–8525, 8541, 8549, 8564–8565, 8578, 8586, 8598–8599, 8601–8602, 8610, 8615, 8639, 8659, 8663, 8813, 8821, 8845–8846, 8918, 8941, 8944, 8982, 9006, 9010–9011, 9060, 9138, 9158, 9170, 9218, 9221, 9225, 9402, 9431, 9438, 9443, 9449, 9458 |
| `crates/carrick-aarch64/src/fork.rs` | 34, 53, 103, 124, 194, 205, 221 |
| `crates/carrick-aarch64/src/owed_kick.rs` | 90, 144, 219 |
| `crates/carrick-aarch64/src/resume_invalidation.rs` | 111, 116, 123, 131–132 |
| `crates/carrick-aarch64/src/stage1_authority.rs` | 14, 17, 19, 38, 42, 63, 126, 159, 164, 242, 249, 410, 513, 548, 572, 574, 578, 604, 644, 649, 651, 656, 662, 751, 761, 783, 800, 844, 863, 885, 910, 1074, 1080, 1103, 1149, 1180, 1225, 1227–1228, 1232, 1248, 1264, 1267, 1271, 1275, 1289, 1330–1331, 1344–1345, 1598, 1634, 1639, 1651, 1655, 1675, 1690, 1702, 1714, 1740, 1749, 1758, 1767, 1777, 1786, 1796, 1806, 1817, 1833, 1848, 1858, 1868, 1881, 1889, 1902, 1920, 1934, 1944, 1947, 1949, 1951, 1962, 1982, 1998, 2013, 2018, 2021, 2035, 2218–2219, 2224, 2231–2232, 2239–2240, 2261–2262, 2299, 2302, 2305, 2370, 2384, 2435, 2452, 2457, 2467, 2502, 2582, 2622, 2661, 2769, 2826, 2841, 2861, 2876, 2890, 2920, 2937, 3094, 3109, 3139, 3172, 3206, 3278, 3320, 3367, 3545, 3562, 3598, 3621, 3653, 3657, 3678, 3698, 3705, 3732, 3762, 3776, 3786, 3796, 3798, 3800–3801, 3839, 3844, 3848, 3856, 3893, 3904, 3915, 3917, 3948–3949, 3958, 4004, 4013, 4029, 4072 |
| `crates/carrick-aarch64/src/user_transfer.rs` | 131, 189, 195, 252, 256–257, 262–263, 268, 272, 288, 297, 321, 335, 515, 524, 543, 594–595, 735, 792 |
| `crates/carrick-aarch64/src/user_transfer/prepared.rs` | 78, 98, 104, 125, 132, 138, 189, 204, 210, 220, 236 |
| `crates/carrick-aarch64/src/user_transfer/staging.rs` | 108, 118, 139, 147, 152, 183, 189, 194, 272, 280 |
| `crates/carrick-aarch64/src/vmm.rs` | 29, 37, 148–152, 221, 223, 452, 459–461, 471–472, 477, 489, 568, 722, 730, 950, 1060, 1077, 1090, 1394 |
| `crates/carrick-el1-abi/src/descriptor_txn.rs` | 14, 17, 185, 187, 362, 369–370, 380, 418–419, 427 |
| `crates/carrick-el1-abi/src/internal_read.rs` | 6, 8 |
| `crates/carrick-el1-abi/src/lib.rs` | 126, 131, 150–151 |
| `crates/carrick-el1-abi/src/mm_portal.rs` | 19, 28, 30, 38–39 |
| `crates/carrick-el1-abi/src/mm_portal_executable.rs` | 98 |
| `crates/carrick-el1-abi/src/service_copy.rs` | 30, 54 |
| `crates/carrick-el1/src/cow.rs` | 19, 21, 26, 33–34, 37, 75, 81–82, 89–90, 93, 100, 110–112, 114, 116–117, 132, 138–139, 147–148, 154, 175–176, 179, 189, 206–207, 219–220, 222, 257, 262, 268, 285, 293, 295, 404, 407, 423, 463, 487, 514, 545, 568, 581, 624, 629, 672, 675, 719, 722, 930–931, 936, 941, 1009, 1013, 1026, 1048, 1088–1089, 1094, 1099 |
| `crates/carrick-el1/src/fault.rs` | 6, 9, 42, 49–51, 116, 118, 120, 126, 135, 156, 159, 162, 164, 166, 175, 190, 215–216, 218, 220, 238, 264, 275, 279, 283, 290, 297, 302, 305, 310, 312–313, 316, 318, 320, 328, 333, 349–350, 356–357, 385, 421, 469, 477, 483, 487–488, 491, 495, 526, 533, 557, 574, 586, 591–592, 595, 598, 606, 613, 651, 661, 675, 686, 745, 768, 773, 798, 813, 847, 1005, 1054, 1148, 1150, 1385–1386, 1399, 1402, 1404, 1781, 1786, 1806, 1814, 1819, 1839, 1871, 1873, 1876–1878, 1895, 1902, 1941, 1944, 1957, 1960, 1963, 1980, 2045, 2047, 2113, 2115, 2133, 2144, 2146, 2490–2491, 2501, 2537, 2558, 2566, 2570, 2580, 2585, 2587–2588 |
| `crates/carrick-el1/src/memory.rs` | 7, 312, 321, 328, 331, 334, 337–338, 343, 352, 358, 361, 364, 368–369, 374, 384, 490, 496, 509, 527–528, 532, 535, 538, 541, 563, 585–588, 611, 627, 630, 638, 642, 732, 787, 806, 928, 1001, 1037, 1040, 1047, 1051, 1058, 1063, 1077, 1222, 1226, 1233, 1246, 1328, 1332–1333, 1348, 1390–1391, 1413, 1416, 1423, 1427, 1539, 1649, 1651, 1660–1661, 1865, 1941, 1943, 2023, 2077, 2084, 2118 |
| `crates/carrick-el1/src/personality/dispatch.rs` | 614, 635 |
| `crates/carrick-el1/src/personality/ipc.rs` | 965–966 |
| `crates/carrick-el1/src/personality/mm_portal/fork.rs` | 9, 25, 38, 78, 82, 218, 222, 269, 312–313, 362, 429, 476, 478, 484, 505, 526, 560, 579 |
| `crates/carrick-el1/src/personality/mm_portal/maintenance.rs` | 7–8, 25, 56, 70, 83–84, 96, 100, 119–120, 184, 186, 242 |
| `crates/carrick-el1/src/personality/mm_portal/production.rs` | 14, 41, 76, 121, 123, 129, 171, 208, 210, 238, 311, 355, 357, 359, 364, 367, 377–378, 425 |
| `crates/carrick-el1/src/personality/mm_portal/test_support.rs` | 9, 136–137, 142, 151, 158, 189, 193, 594, 598, 652 |
| `crates/carrick-el1/src/personality/mm_portal/tests.rs` | 8, 157, 161–163, 173, 176, 182, 210, 748, 752, 796, 860, 919, 923, 942, 944, 950, 954, 1028, 1256–1257, 1264, 1270, 1340, 1347, 1352, 1480, 1484, 1495, 1504, 1514, 1524, 1534, 1778, 1781, 1932–1934, 2109, 2113, 2230, 2332, 2351, 2361–2363, 2365, 2411, 2416, 2446, 2450, 2458, 2463, 2472, 2551, 2561–2563, 2565, 2637, 2642, 2903, 2906, 3764, 3980, 3988, 4267–4269, 4271, 4290, 4295, 4315, 4342 |
| `crates/carrick-el1/src/personality/mm_portal/x86_tests.rs` | 5, 20, 114 |
| `crates/carrick-el1/src/personality/native_ownership_tests.rs` | 7, 13, 15, 40, 44–45, 86, 107, 113, 125, 145–146, 148, 157, 232 |
| `crates/carrick-el1/src/sched.rs` | 27, 30, 359, 365, 682, 703, 738–740, 743–744 |
| `crates/carrick-el1/src/sched/hw.rs` | 118, 126–131, 134–135, 139, 145–152 |
| `crates/carrick-el1/src/sched/tests.rs` | 1080, 1082, 1164, 1206, 1310, 1438, 1472 |
| `crates/carrick-sched-core/src/spaces.rs` | 94–95, 157–158, 316–317, 348–349, 379–380, 387–388, 405–406, 549–550, 588–589, 592, 599–600, 614–615, 674, 788–790, 797–798, 897, 918, 933, 1061 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 199 |
| `crates/carrick-x86/src/arch_context.rs` | 51, 76 |
| `crates/carrick-x86/src/bringup_fns.rs` | 447, 498, 521, 1010, 1044 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 109, 124 |
| `crates/carrick-x86/src/engine.rs` | 356, 361, 1578, 1685, 1880, 1922, 2099, 2128, 2149 |

### L — TLB/coherence

| Pinned source path (S) | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-aarch64/src/descriptor_drain.rs` | 171, 195, 208 |
| `crates/carrick-aarch64/src/engine.rs` | 489, 805, 810, 921, 967, 1056, 1399, 1523, 1718, 2406–2407, 2412, 2417, 2420, 2424–2426, 2435, 2437–2438, 2443, 2445, 2448–2449, 2457–2458, 2461, 2467–2468, 2477, 2486–2487, 2675, 2677–2678, 2683–2684, 2687, 2692, 2694, 2696, 4607, 4737, 4746, 4761, 4782, 5288, 7159–7162, 7431, 9272 |
| `crates/carrick-aarch64/src/lib.rs` | 34, 37 |
| `crates/carrick-aarch64/src/stage1_authority.rs` | 322, 601, 624, 1014, 1672, 1676, 2825, 2840, 2875, 3093, 3108, 3595, 3675, 3731, 3755, 3759, 3836 |
| `crates/carrick-aarch64/src/user_transfer.rs` | 212, 650, 655 |
| `crates/carrick-aarch64/src/user_transfer/staging.rs` | 135 |
| `crates/carrick-aarch64/src/vmm.rs` | 424 |
| `crates/carrick-el1/src/cow.rs` | 31, 37, 187, 194, 402, 491, 572, 622, 670, 717, 934, 1092 |
| `crates/carrick-el1/src/fault.rs` | 138, 143, 145, 147, 175, 238, 290, 297, 385, 572 |
| `crates/carrick-el1/src/file.rs` | 174–181, 203–210 |
| `crates/carrick-el1/src/memory.rs` | 352, 384 |
| `crates/carrick-el1/src/personality/mm_portal/fork.rs` | 505, 579 |
| `crates/carrick-el1/src/personality/mm_portal/production.rs` | 384 |
| `crates/carrick-el1/src/personality/mm_portal/tests.rs` | 1354, 2418, 2644, 4297 |
| `crates/carrick-el1/src/sched.rs` | 30, 359, 743 |
| `crates/carrick-el1/src/sched/aarch64_context.rs` | 110–121 |
| `crates/carrick-el1/src/sched/hw.rs` | 126–131, 134–135, 139, 145–152, 175–184, 193–199, 216–221, 227 |
| `crates/carrick-el1/src/sched/tests.rs` | 1572 |
| `crates/carrick-guest-arch/src/lib.rs` | 379 |

### I — interrupt/clock

| Pinned source path (S) | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-el1-abi/src/ipc.rs` | 688–689 |
| `crates/carrick-el1-abi/src/lib.rs` | 301, 304, 306, 310, 510–512 |
| `crates/carrick-el1/src/alloc.rs` | 11, 16, 52, 62, 70, 76, 232, 249, 260, 278, 289, 296, 302, 314, 322, 327, 337, 341 |
| `crates/carrick-el1/src/personality/ipc.rs` | 988, 1122 |
| `crates/carrick-el1/src/personality/mm_portal/maintenance.rs` | 217 |
| `crates/carrick-el1/src/personality/mm_portal/production.rs` | 69, 164, 316, 396 |
| `crates/carrick-el1/src/sched.rs` | 3–4, 38, 41, 43, 46, 50, 63–67, 168, 394, 432, 444–445, 448, 451–452, 456, 461, 464, 497, 628–630, 635, 674, 678, 699, 701, 759–760, 763, 765, 767, 770, 772, 787–788 |
| `crates/carrick-el1/src/sched/hw.rs` | 159, 166, 175–184, 189, 193–199, 203–204, 208, 210, 213, 216–221, 225, 227, 234–235, 237–238, 245, 254, 260–261, 264–269, 273, 275, 279, 282–286 |
| `crates/carrick-el1/src/sched/object_wait.rs` | 35, 38, 40, 187 |
| `crates/carrick-el1/src/sched/tests.rs` | 3, 359, 366, 384, 509, 511, 538–539, 541, 546, 608, 631, 642, 948, 1497, 1524, 1532–1533, 1574, 1580 |
| `crates/carrick-sched-core/src/lib.rs` | 817, 892–893, 898, 918–919, 1126, 1136, 1140–1141, 2394, 2397, 2857, 2860 |
| `crates/carrick-sched-core/src/object_wait.rs` | 3105 |
| `crates/carrick-sched-core/src/tests.rs` | 669, 689, 734, 904, 1226 |
| `crates/carrick-x86-cpl0/src/entry.rs` | 174 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 24–68, 83, 90, 119, 144, 149, 157 |
| `crates/carrick-x86/src/bringup.rs` | 83, 100–102 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 10, 18–19, 35, 170 |
| `crates/carrick-x86/src/interrupts.rs` | 50, 59, 61, 69 |

### H — host transport

| Pinned source path (S) | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-aarch64/src/descriptor_drain.rs` | 234 |
| `crates/carrick-aarch64/src/engine.rs` | 205, 250, 577, 2120, 2243, 2596, 3232, 3303, 5582–5583, 7163, 8994 |
| `crates/carrick-aarch64/src/owed_kick.rs` | 330, 399 |
| `crates/carrick-aarch64/src/vmm.rs` | 108 |
| `crates/carrick-el1-abi/src/lib.rs` | 1558, 1563, 1580–1583, 1590, 1599, 1604, 1606, 1615–1620, 3169, 3171–3175, 3196, 3199, 3206, 3208 |
| `crates/carrick-el1/src/entry.rs` | 109–115 |
| `crates/carrick-el1/src/fault.rs` | 566 |
| `crates/carrick-el1/src/personality/mm_portal/production.rs` | 154 |
| `crates/carrick-el1/src/sched/hw.rs` | 301–304 |
| `crates/carrick-x86-cpl0/src/entry.rs` | 99, 102–103, 110, 114, 129, 133, 150, 154, 163, 167 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 95, 100, 143, 148, 215 |
| `crates/carrick-x86/src/bringup.rs` | 247 |
| `crates/carrick-x86/src/cpl0_entry.rs` | 6–11 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 58–60 |
| `crates/carrick-x86/src/engine.rs` | 2460, 2496 |
| `crates/carrick-x86/src/fault.rs` | 6–7, 126, 620, 679, 717, 721, 741, 743 |
| `crates/carrick-x86/src/lib.rs` | 37 |

### U — user copy/fixup

| Pinned source path (S) | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-aarch64/src/engine.rs` | 5801, 5809, 6102, 7908, 7983–7985, 8010, 8012, 8016, 8027–8029, 8091–8093, 8118, 8120, 8124, 8135–8137 |
| `crates/carrick-aarch64/src/stage1_authority.rs` | 2262, 2300 |
| `crates/carrick-el1-abi/src/lib.rs` | 706, 769, 3228 |
| `crates/carrick-el1/src/fault.rs` | 2144 |
| `crates/carrick-el1/src/file.rs` | 23, 31, 34–58, 84, 92, 95–119, 138, 140, 143, 147, 150–151, 155, 161, 164–165, 174–181, 194, 203–210, 238, 243, 245, 249, 253, 258 |
| `crates/carrick-el1/src/personality/dispatch.rs` | 105, 137, 168, 195, 218, 254, 293, 338, 352, 406, 548, 649, 665, 681, 699, 717, 763, 776, 853, 1015 |
| `crates/carrick-el1/src/personality/file.rs` | 6, 8, 104, 122, 141, 159, 195–196, 212 |
| `crates/carrick-el1/src/personality/inotify.rs` | 14, 39, 52, 59, 177, 202, 229, 254, 280–281, 285, 310–311, 315 |
| `crates/carrick-el1/src/personality/ipc.rs` | 38, 173, 252, 364, 396, 557, 573, 615, 638, 689, 700, 704, 713, 721, 769, 1115, 1141, 2134, 2189 |
| `crates/carrick-el1/src/personality/ipc/epoll.rs` | 37, 82, 100, 111, 304 |
| `crates/carrick-el1/src/personality/lifecycle.rs` | 26, 123, 208, 390, 518 |
| `crates/carrick-el1/src/personality/lifecycle/tests.rs` | 7, 178, 269 |
| `crates/carrick-el1/src/personality/mm_portal/edit_wait.rs` | 5, 14 |
| `crates/carrick-el1/src/personality/mm_portal/tests.rs` | 3019, 3084, 3303, 3365 |
| `crates/carrick-el1/src/personality/sched.rs` | 21, 25, 66 |
| `crates/carrick-el1/src/sched.rs` | 54, 107, 124, 645 |
| `crates/carrick-el1/src/sched/hw.rs` | 8, 19, 21, 24–25, 28, 34–51, 65–66, 69, 75–92 |
| `crates/carrick-el1/src/sched/object_wait.rs` | 9, 61 |
| `crates/carrick-el1/src/sched/tests.rs` | 92, 243, 252, 255, 552, 602, 649, 827, 942, 990, 1057, 1415, 1518, 1600 |
| `crates/carrick-x86/src/bringup_fns.rs` | 96, 157, 359, 533 |

### B — boot/control layout

| Pinned source path (S) | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-aarch64/src/descriptor_drain.rs` | 482, 485, 495–496 |
| `crates/carrick-aarch64/src/engine.rs` | 190, 1202, 1211–1212, 1219, 1221, 1223, 3367, 3537, 3629, 5352, 5657, 7016, 7028–7029, 7031, 8646, 8785, 9053, 9347, 9435, 9438 |
| `crates/carrick-aarch64/src/stage1_authority.rs` | 3357, 3810–3811, 3813, 3975–3976, 3978 |
| `crates/carrick-aarch64/src/user_transfer.rs` | 306 |
| `crates/carrick-aarch64/src/user_transfer/staging.rs` | 103 |
| `crates/carrick-el1-abi/src/cow_grants.rs` | 11–13, 16, 18–19, 26, 45, 54 |
| `crates/carrick-el1-abi/src/delegated_notification.rs` | 2, 25–26, 274, 285, 292 |
| `crates/carrick-el1-abi/src/descriptor_txn.rs` | 22, 175–176, 183–184, 186, 188–190, 194, 197–198, 202, 204–205, 210–212, 243, 259–261, 282, 296, 313–314, 319, 321, 324, 327, 334, 342 |
| `crates/carrick-el1-abi/src/internal_read.rs` | 30, 62 |
| `crates/carrick-el1-abi/src/ipc/tests.rs` | 267 |
| `crates/carrick-el1-abi/src/lib.rs` | 59, 62, 65, 68, 71, 74, 77, 80, 86, 89, 92, 98–99, 115–116, 120–121, 168, 171, 174, 177, 180, 183, 217, 220, 223, 230, 237, 243, 246, 250–251, 253–256, 259, 262, 265, 268, 271, 274, 278, 281, 284, 290, 293, 296, 321, 334–335, 337, 340, 344, 346–347, 352, 366–369, 371–375, 389, 396–401, 403–407, 411–417, 419, 421, 478, 587, 601, 736, 739, 1147, 1149, 1455, 1459, 1462, 1465, 1828, 1845, 1848, 1851, 1854, 1857, 1860, 1871, 1874, 1877, 1879–1880, 1883–1886, 1888, 1890, 1892–1893, 1896, 1900–1901, 1904, 1908–1909, 1912, 1916–1917, 1920, 1922–1928, 2056, 2058, 2072, 2079, 2090, 2104, 2117, 2124, 2133, 2141, 2150, 2163, 2178, 2188, 2201, 2212, 2295, 2311, 2325, 2343, 2359, 2383, 2407, 2430, 2440, 2460, 2486, 2507, 2519, 2530, 3081–3083, 3213–3218, 3252, 3254, 3331–3332, 3338, 3351, 3360, 3382, 3515, 3520, 3524, 3608, 3616, 3746, 3966, 3979, 4012, 4024, 4075, 4082, 4106, 4145, 4188, 4199 |
| `crates/carrick-el1-abi/src/mm_portal.rs` | 111–112, 149–150, 204, 206 |
| `crates/carrick-el1-abi/src/reservations.rs` | 11–12 |
| `crates/carrick-el1-abi/src/service_copy.rs` | 4–9, 14–15, 18, 37, 86, 148–150, 152, 154–155, 171, 185, 189, 191, 195, 207–208, 211, 213, 219, 226, 229 |
| `crates/carrick-el1/src/alloc.rs` | 17–18, 21, 56–57, 94, 237–238 |
| `crates/carrick-el1/src/cow.rs` | 22–23, 216, 262, 267, 280, 420, 472, 479, 511, 554, 581, 753–754, 793–794, 1107 |
| `crates/carrick-el1/src/entry.rs` | 75, 95 |
| `crates/carrick-el1/src/fault.rs` | 355, 506, 513, 527–529, 534–535, 785, 788, 805, 826, 830, 1088, 1120, 1544 |
| `crates/carrick-el1/src/personality/dispatch.rs` | 13–14, 74, 81–82, 84, 86, 89, 91–92, 128–129 |
| `crates/carrick-el1/src/personality/mm_portal/fork.rs` | 432, 457, 529, 545 |
| `crates/carrick-el1/src/personality/mm_portal/maintenance.rs` | 226, 232 |
| `crates/carrick-el1/src/personality/mm_portal/production.rs` | 78, 90, 174, 183, 322, 332, 405, 413, 486, 489, 491, 497, 502 |
| `crates/carrick-el1/src/personality/mm_portal/test_support.rs` | 32, 48, 57, 68 |
| `crates/carrick-el1/src/personality/mm_portal/tests.rs` | 444, 692, 723, 2360, 2560, 4266 |
| `crates/carrick-el1/src/personality/reservations.rs` | 12–16, 31, 33, 48 |
| `crates/carrick-el1/src/personality/thread_setup.rs` | 152, 154–155 |
| `crates/carrick-el1/src/sched.rs` | 27, 365, 382, 738 |
| `crates/carrick-el1/src/sched/hw.rs` | 118 |
| `crates/carrick-el1/src/sched/tests.rs` | 741, 751, 759, 1571 |
| `crates/carrick-guest-arch/src/lib.rs` | 371 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 106, 111 |
| `crates/carrick-x86/src/bringup_fns.rs` | 339, 342, 345–346, 369, 398, 422–423, 556–557 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 122 |

### W — ISA binding/cfg

| Pinned source path (S) | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-aarch64/src/engine.rs` | 36, 94, 185, 195–196, 198, 205, 213, 222–223, 230–234, 340, 379, 492, 516, 522, 535, 537–539, 551, 563, 569, 640, 647, 653, 663, 665, 691–692, 695, 697, 727, 756, 809, 822, 874, 901, 944, 948, 966, 991, 1013–1014, 1162, 1174–1175, 1299, 1590, 1645, 1991, 2030, 2099, 2102–2107, 2109–2111, 2141–2146, 2167, 2170, 2173, 2176, 2181, 2184, 2189, 2195, 2199, 2203, 2214, 2219, 2224, 2251–2253, 2268, 2274, 2277, 2282, 2287, 2292, 2329, 2332–2336, 2351, 2574, 2583–2584, 2621, 3277, 3300–3301, 3309, 3609, 4642, 4654–4655, 4658, 4661, 4664, 4689, 4744, 4757, 4952, 4955, 5009, 5132, 5146, 5154, 5162, 5170, 5182, 5194, 5198, 5231, 5366, 5578, 5650, 5876–5877, 5882–5883, 5889, 5892, 5999, 6005–6006, 6069, 6176–6177, 6181–6183, 6491, 6809, 6908, 7216, 8628, 8639, 8916, 8921–8922, 8929–8930, 8940, 8943, 8984–8987, 8990–8992, 9034, 9132–9133, 9169, 9461–9462 |
| `crates/carrick-aarch64/src/lib.rs` | 30, 43–44, 48 |
| `crates/carrick-aarch64/src/owed_kick.rs` | 41, 43, 71, 87, 107, 116, 120, 123, 141–142, 145, 147, 164, 223–224, 226–229, 234, 236–239, 245, 249, 387, 396 |
| `crates/carrick-aarch64/src/user_transfer.rs` | 6, 25–26, 265–266, 274–275, 294–295, 436, 438, 567, 584–585 |
| `crates/carrick-aarch64/src/user_transfer/prepared.rs` | 26, 29, 52, 54 |
| `crates/carrick-aarch64/src/user_transfer/staging.rs` | 7–8, 60–61, 88 |
| `crates/carrick-aarch64/src/vmm.rs` | 25, 243, 267–270, 327, 329, 555–556, 1448, 1452–1453, 1457, 1462, 1466, 1532 |
| `crates/carrick-el1/src/alloc.rs` | 13 |
| `crates/carrick-el1/src/entry.rs` | 109 |
| `crates/carrick-el1/src/fault.rs` | 118, 138, 143, 145, 147, 174–175, 237–238, 289–290, 296–297, 384–385, 566 |
| `crates/carrick-el1/src/file.rs` | 29, 34, 62, 90, 95, 123, 174, 203 |
| `crates/carrick-el1/src/lib.rs` | 8, 10, 12, 14, 16, 18, 21, 23, 25, 27 |
| `crates/carrick-el1/src/memory.rs` | 351–352, 383–384 |
| `crates/carrick-el1/src/personality/dispatch.rs` | 104, 136, 167, 195, 217, 253, 292, 338, 352, 548, 649, 665, 699, 776 |
| `crates/carrick-el1/src/personality/ipc.rs` | 38, 173, 252, 364, 396, 557, 573, 615, 638, 689, 700, 704, 713, 721 |
| `crates/carrick-el1/src/personality/ipc/epoll.rs` | 37, 82, 100, 111, 304 |
| `crates/carrick-el1/src/personality/lifecycle.rs` | 26, 123, 208, 390, 518 |
| `crates/carrick-el1/src/personality/mm_portal/edit_wait.rs` | 5, 14 |
| `crates/carrick-el1/src/personality/mm_portal/fork.rs` | 505, 579 |
| `crates/carrick-el1/src/personality/mm_portal/production.rs` | 121, 154, 208, 357, 384, 425 |
| `crates/carrick-el1/src/personality/mm_portal/tests.rs` | 3019 |
| `crates/carrick-el1/src/personality/mod.rs` | 7, 9, 11, 13, 15, 17, 19 |
| `crates/carrick-el1/src/personality/sched.rs` | 21, 25, 66 |
| `crates/carrick-el1/src/sched.rs` | 20, 107, 124, 644, 711 |
| `crates/carrick-el1/src/sched/aarch64_context.rs` | 16–17, 72, 83, 88, 104, 110 |
| `crates/carrick-el1/src/sched/hw.rs` | 7, 34, 75, 107, 110, 126, 145, 159, 166, 175, 184, 193, 208, 216, 227, 237, 243, 248, 262, 264, 271, 280, 282, 288, 301 |
| `crates/carrick-el1/src/sched/object_wait.rs` | 9, 28, 61 |
| `crates/carrick-guest-arch/src/lib.rs` | 138, 157 |
| `crates/carrick-x86-cpl0/src/entry.rs` | 41, 102, 174 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 24, 83, 90, 95, 144, 149, 199 |
| `crates/carrick-x86/src/cpl0_entry.rs` | 3, 61, 63–78 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 116, 124 |
| `crates/carrick-x86/src/engine.rs` | 31, 761, 763–780, 786, 793, 800, 802, 806, 814, 816, 820 |
| `crates/carrick-x86/src/interrupts.rs` | 37, 50, 59, 61, 69 |
| `crates/carrick-x86/src/vdso.rs` | 70, 78 |

### Whole native items and substrate projections

These full-file spans also cover constant encodings, arithmetic and failure paths without a lexical ISA spelling. Counts above do not add them a second time.

| Concern | Complete native/source span at S |
| --- | --- |
| Trap | `crates/carrick-aarch64/src/esr.rs:1–65` |
| Context | `crates/carrick-el1/src/sched/aarch64_context.rs:1–126` |
| Context | `crates/carrick-x86/src/arch_context.rs:1–86` |
| Trap | `crates/carrick-x86/src/cpl0_entry.rs:1–203` |
| Context/root | `crates/carrick-x86/src/cpl0_scheduler.rs:1–222` |
| Coherence | `crates/carrick-aarch64/src/icache.rs:1–19` |
| Interrupt | `crates/carrick-x86/src/interrupts.rs:1–113` |
| Boot/transport | `crates/carrick-el1/src/entry.rs:1–120` |
| Boot/transport | `crates/carrick-x86-cpl0/src/entry.rs:1–183` |
| Native fixture | `crates/carrick-x86-cpl0/src/progress.rs:1–230` |
| Boot | `crates/carrick-el1/link.ld:1–44` |
| MMU contracts | `crates/carrick-mmu-core/src/owner_mmu.rs:1–159` |
| Descriptor | `crates/carrick-mmu-core/src/aarch64.rs:1–14090` |
| Descriptor | `crates/carrick-mmu-core/src/aarch64/descriptor_txn.rs:1–5267` |
| Descriptor | `crates/carrick-mmu-core/src/aarch64/descriptor_txn/copy_window.rs:1–318` |
| Descriptor/COW | `crates/carrick-mmu-core/src/aarch64/descriptor_txn/guest_cow.rs:1–421` |
| Descriptor/fork | `crates/carrick-mmu-core/src/aarch64/owner_fork.rs:1–99` |
| Descriptor | `crates/carrick-mmu-core/src/x86/mod.rs:1–3` |
| Descriptor | `crates/carrick-mmu-core/src/x86/descriptor_txn.rs:1–819` |
| Descriptor | `crates/carrick-mmu-core/src/x86/owner_mmu.rs:1–192` |

<!-- END GENERATED APPENDIX A -->
