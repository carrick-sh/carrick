# One guest kernel, two ISA images

Design pass, owner decision **2026-10-06**. Build the same kernel crate set
into `carrick-el1-image` (AArch64 EL1) and `carrick-x86-cpl0` (x86 CPL0).
Move the kernel, then supply its instruction boundary once per ISA. Replace
Wave 2's per-family implementation seams; do not continue growing
`PendingFamilies` into the architecture. Linux policy, IPC, lifecycle, MM
owner/reservations/fault/COW, scheduler/wait and file/inotify each have one
implementation. This document changes no code and claims no guest execution,
ARM acceptance, or performance result. Carrick remains experimental.

## Authority and revision discipline

**S = `0f476ce7afb11609c8261cd1954bbe08263548b3`**, the requested study base.
The brief calls this `origin/work/x86-ord5`; that remote-tracking name is
absent on carrick-vm, but the exact commit exists. All unprefixed `file:line`
citations and the census mean **S**, including references to code absent on
main. Use `git show S:path`, not the publication worktree, to inspect them.
The docs-only publication base is `github/main` at
`2322d859d463b0d6c9e99ae2ce04f044f66abf53` (P). No source from S is copied
into that worktree.

Other immutable authorities, deliberately separate from the code census:

- **W1 = `a9a39db0cb7cce047519e89a0a3877d1396e6a10`**:
  `docs/superpowers/plans/2026-10-04-x86-parallel-track.md:1`.
- **W2 = `289e8d79753cdb4115b35ea16944e91f6c9c25d3`**:
  `docs/superpowers/plans/2026-10-06-x86-wave2-extraction.md:1`.
  Its family seams and N1-paused/single-final-rebase sequencing are superseded
  by this owner's instruction. Its assertions, work budgets and artifact
  discipline survive; see W2's signed packet at `:510` and N1 audit at `:758`.
- **O5 = `7245d48af95e147368c7bf214a90e4c063cd794d`**, inspected
  [PR #68](https://github.com/carrick-sh/carrick/pull/68):
  `docs/perf-results/2026-10-06-x86-order5-entry-mapping.md:3`, `:67`.
- **O6 = `3fd7862be859e106cdfa27ec183fea9cf66ccf63`**, inspected `github/work/x86-ord6`:
  `docs/perf-results/2026-10-06-x86-order6-lifecycle-mapping.md:3`, `:230`,
  `:261`. This branch explicitly has not integrated later order-5 fixes.
- **X1 = `1bbc39005aa06eee3a4e47023cebf8b4d6363708`**, inspected
  [PR #64](https://github.com/carrick-sh/carrick/pull/64):
  `docs/perf-results/2026-10-06-x1-increment2.md:3`, `:17`, `:34`.

The active ownership controller is
`docs/superpowers/plans/2026-10-02-el1-native-ownership.md:697`, `:723`,
`:820`: one production MM owner and one exact-generation production service
transport. Apply the conformance-contract skill and
`docs/conformance-contracts.md:29`, `:133`, `:175`. The exemption for **this
single documentation file** changes no entry, lifecycle, MM, IPC, file,
inotify or scheduler contract/budget. Implementation exemptions must name
exact moved paths and predecessor SHAs; trait adaptation and new x86 binding
are not automatically byte-identical exemptions.

**N1 + Wave 1 land on main first.** The director records that accepted main
SHA, then re-inventories the inversion on it. Do not rebuild the older N1
bodies from S. This replaces both W1's daily N1 synchronization and W2's plan
to postpone N1 landing until X4–X8. The kept/ported/dropped fix ledger remains
mandatory, now at the initial main integration and each subsequent move.

## Census: what is actually architecture dependent

The owner's **49,580** denominator reproduces exactly: tracked `.rs` under
`src/` in `carrick-el1`, `carrick-el1-abi`, `carrick-aarch64`; count nonblank
physical lines whose trimmed text does not begin `//`. Include in-file and
out-of-line unit tests, cfg branches and embedded assembly; exclude `build.rs`
and integration `tests/`. Do not discard lines beginning `*`: they can be
Rust dereference assignments. The earlier W2 metric also discarded these
lines and included integration/build sources; its totals are not comparable.
The complete file counts below and appendix use S.

The supplied **2,922 directly ISA-touching lines** are the owner's narrower
classification, not 2,922 lines of total adapter code. Our conservative site
census has **3,625 distinct line hits** in those three crates: EL1 1,894,
EL1-ABI 394, AArch64 1,337. It includes declarations, cfg wiring, register
fixtures and full asm operands/clobbers, with overlaps between concerns
counted once. It deliberately does not pretend its broader definition
reproduces the owner's 2,922. The subtraction **49,580 − 2,922 = 46,658** is
an ISA-free candidate ceiling, **not** a relocation forecast: much of
`carrick-aarch64` is a host engine with `std`, libc and backend custody
(`crates/carrick-aarch64/Cargo.toml:16`, `:45`, `:51`;
`crates/carrick-aarch64/src/engine.rs:1`).

Appendix A enumerates the individual file/line sites, grouped by concern.
A line range is inclusive and denotes every site in that run; comma-separated
sites share the row's path. It includes ISA calls in tests, because their
fixtures must either become parameterized or remain native. Architectural
routines additionally audited as whole items are listed after the lexical
inventory: bit interpretation inside a routine matters even when that line
contains no register spelling. This is a source inventory, not proof of
compiled reachability or a source-derived runtime budget. The implementation
fence must also inspect macros and disassembly of both image closures.

| Concern | Boundary demonstrated at S | Shared consumer and native responsibility |
| --- | --- | --- |
| Trap/entry frame | `crates/carrick-el1-abi/src/lib.rs:645`; `crates/carrick-el1/src/entry.rs:39`; `crates/carrick-x86/src/cpl0_entry.rs:18` | One core admission and Linux decode/dispatch; native frame exposes raw ordinal, argument words, result bits, PC/SP and classified event. ARM ESR/FAR and x86 vector/error decode never enter policy. |
| Context/TLS | `crates/carrick-el1/src/sched/aarch64_context.rs:5`, `:92`; `crates/carrick-sched-core/src/lib.rs:382`; `crates/carrick-x86/src/cpl0_scheduler.rs:34` | One shared scheduler/record authority; native context owns GPR/FP/SIMD/TPIDR versus FS/GS/XSAVE. Linux chooses child return, clone stack and TLS convention. |
| Descriptors/geometry | `crates/carrick-mmu-core/src/owner_mmu.rs:21`, `:40`, `:137`; `crates/carrick-mmu-core/src/x86/owner_mmu.rs:8` | Reuse MMU-core translation/descriptor adapters and journal. Core owns admission, permission policy, COW/refcounts, rollback and custody. Remove ARM-named neutral type placement without copying algorithms. |
| TLB/barriers/code coherence | `crates/carrick-el1/src/sched/hw.rs:157`; `crates/carrick-el1/src/fault.rs:135`; `crates/carrick-aarch64/src/icache.rs:1`; `crates/carrick-x86/src/cpl0_scheduler.rs:130` | Native backend executes store-publication and invalidation sequences; shared occupancy/drain tickets determine participants and when reuse is authorized. CR3 reload is not a global retirement receipt. |
| Kick/IPI/masks/timers | `crates/carrick-el1/src/sched.rs:20`, `:66`; `crates/carrick-el1/src/sched/hw.rs:196`, `:321`; `crates/carrick-x86/src/interrupts.rs:48`, `:82` | Shared wake effects carry exact slot/generation and absolute deadline. GIC/MPIDR/SGI and APIC routing stay native; interrupt reason and acknowledgement are typed. |
| Hypercall/doorbell | `crates/carrick-el1/src/personality/mm_portal/production.rs:154`; `crates/carrick-el1/src/entry.rs:117`; `crates/carrick-x86-cpl0/src/entry.rs:103` | One existing exact-operation mailbox protocol. Native HVC or port doorbell moves a typed service verb and bounded record address; it does not implement a syscall family or synchronous allocation service. |
| Checked user copy | `crates/carrick-el1/src/file.rs:23`, `:84`, `:164`; `crates/carrick-el1/src/sched/hw.rs:22` | One owner-issued transfer/permission lease; ARM AT/PAR + LDTR/STTR/fixup and x86 checked translation/copy-fault recovery supply the instruction leaf. Neither architecture may substitute host permission mirrors. |
| Boot/root install | `crates/carrick-el1/link.ld:2`, `:6`, `:41`; `crates/carrick-el1-abi/src/lib.rs:58`, `:1878`; `crates/carrick-vmm-kvm/src/cpl0_boot.rs:123` | Per-ISA entry/vector/GDT/IDT/TSS/root registers and layout manifest. A neutral boot record lends already-authenticated mappings to the shared kernel. Host still supplies physical storage. |

### Minimal ISA surface, by subtraction from the existing interface

Use **`carrick-guest-arch`**, not a new facade crate. It already has typed
native snapshots and events (`crates/carrick-guest-arch/src/lib.rs:131`, `:177`), exact identity/counter
units (`:45`, `:57`) and four hardware projections (`:362`, `:370`, `:381`,
`:393`). Keep the existing sealed composite `KernelArch = EntryArch + MmuArch +
InterruptArch + CrossingArch`, with **one concrete backend per ISA** implementing
its existing backend hooks. At S there is only the blanket `KernelArch for
Arch<B>` (`crates/carrick-guest-arch/src/lib.rs:401`), no concrete `impl *Backend for` in the tracked
crates. It is an interface declaration, not a connected production boundary.
Retype and fold the existing de-facto seams into those projections; do not
invent a third hardware interface. Delete displaced hooks in the same move.
MM owner, leaf edit ownership, prepare/settle/cancel,
physical pins and drain membership belong to their existing owners, not to
`ArchTypes`' current catch-all associated capabilities (`:287`).

The following is **proposed Rust signature inventory**, not existing
compiling API. It flattens the existing composite for review; implementation
places entry/context methods in EntryBackend, table/copy/coherence methods
in MmuBackend, IRQ/timer methods in InterruptBackend, and transport/fatal
methods in CrossingBackend. The existing KernelArch blanket composition
remains; the shown `trait KernelArch` is not a second trait to introduce.
All numeric storage is private behind `repr(transparent)` units; wire codecs alone expose
raw integers. `GuestVa` and `Gpa` replace the existing leaf spellings
`UserVa`/`FrameGpa` once across the image closure (`crates/carrick-guest-arch/src/lib.rs:27`), preserving
representation. No aliases with deprecated spellings. Host `GuestVa`/`Gpa`
(`crates/carrick-guest-mem/src/lib.rs:154`, `:280`) convert only at the checked
host-wire boundary; do not pull its host dependencies into the leaf. Remove
core's additional private `GuestVa` (`crates/carrick-core/src/mm/transfer.rs:12`)
in that same mechanical type consolidation.

```rust
// carrick-guest-arch: ISA units, no Linux constants, alloc or host imports.
// RegisterWord, NativeOrdinal, GuestLen, CpuId, CpuGeneration, CounterTick,
// CounterFrequency, NativeReturnWord are private transparent units.
struct NativeSyscallWords {
    ordinal: NativeOrdinal,
    args: [RegisterWord; 6],
}
enum ArgumentIndex { A0, A1, A2, A3, A4, A5 }
enum InterruptReason { Timer, Reschedule, HostKick, External }
enum HostVerb { Service, Forward, CompletedWithWork, Idle, Fatal }
enum CopyDirection { ToUser, FromUser }
struct UserRange { start: GuestVa, len: GuestLen }
struct CpuTarget { slot: CpuId, generation: CpuGeneration }
struct MailboxAddress(Gpa);        // constructor checks alignment and bounds
struct KernelBuffer<'a> { bytes: &'a mut [u8] }

trait NativeFrameAccess {
    type Register: NativeRegister; // Aarch64Register / X86Register enums
    fn read(&self, reg: Self::Register) -> RegisterWord;
    fn write(&mut self, reg: Self::Register, bits: RegisterWord);
    fn syscall_words(&self) -> NativeSyscallWords;
    fn set_result(&mut self, result: NativeReturnWord);
    fn pc(&self) -> GuestVa;
    fn set_pc(&mut self, pc: GuestVa);
    fn replay_site(&self) -> GuestVa; // checked native instruction length
}

trait NativeContextAccess {
    fn result(&self) -> NativeReturnWord;
    fn set_result(&mut self, result: NativeReturnWord);
    fn original_arg0(&self) -> RegisterWord;
}

trait KernelArch {
    type Frame: NativeFrameAccess;
    type Context: NativeContextAccess;                  // native layout, exact-record-owned
    type Mmu;                      // bound to OwnerGrantMmu in core, not here
    type Roots;                    // typed TTBR pair+ASID or CR3+mode/PCID
    type Tls;                      // typed TPIDR values or FS/user-GS bases
    type IrqMask;                  // noncopyable restoration capability
    type IrqAck;                   // consumed exactly once by end_interrupt
    type Invalidation;             // hardware work for owner-issued drain
    type InvalidationAck;          // hardware completion, not reuse authority
    type ExecutableAck;
    type CopyAccess<'owner> where Self: 'owner; // owner-licensed borrow
    type Error;

    fn classify(&self, frame: &Self::Frame) -> Result<EntryEvent, Self::Error>;
    fn user_sp(&self, frame: &Self::Frame) -> GuestVa;
    fn set_user_sp(&mut self, frame: &mut Self::Frame, sp: GuestVa);
    fn save(&mut self, frame: &Self::Frame, into: &mut Self::Context);
    fn restore(&mut self, frame: &mut Self::Frame, from: &Self::Context);
    fn set_tls(context: &mut Self::Context, tls: Self::Tls);
    fn prepare_child_context(&self, parent: &Self::Context,
        stack: GuestVa, tls: Self::Tls, result: NativeReturnWord)
        -> Result<Self::Context, Self::Error>;
    fn install_roots(&mut self, roots: &Self::Roots);
    fn invalidate(&mut self, work: Self::Invalidation)
        -> Result<Self::InvalidationAck, Self::Error>;
    fn publish_executable(&mut self, range: UserRange)
        -> Result<Self::ExecutableAck, Self::Error>;
    fn counter(&self) -> CounterTick;
    fn frequency(&self) -> CounterFrequency;
    fn arm_timer(&mut self, deadline: Option<Deadline>);
    fn mask_interrupts(&mut self) -> Self::IrqMask;
    fn restore_interrupts(&mut self, mask: Self::IrqMask);
    fn ack_interrupt(&mut self) -> Option<(InterruptReason, Self::IrqAck)>;
    fn end_interrupt(&mut self, ack: Self::IrqAck);
    fn send_kick(&mut self, target: CpuTarget) -> Result<(), Self::Error>;
    fn park_until_interrupt(&mut self);
    fn current_cpu(&self) -> CpuId;
    fn validate_user_prefix(&mut self, access: &Self::CopyAccess<'_>,
        range: UserRange, direction: CopyDirection) -> Result<GuestLen, Self::Error>;
    fn copy_user_chunk(&mut self, access: &Self::CopyAccess<'_>, user: UserRange,
        kernel: KernelBuffer<'_>, direction: CopyDirection)
        -> Result<CopyProgress, Self::Error>;
    fn doorbell(&mut self, verb: HostVerb, slot: MailboxAddress);
    fn report_fatal(&mut self, report: FatalReport) -> !;
}
```

`NativeRegister` is a sealed marker implemented only for the two register
enums, with checked register-index constructors for ARM X0–X30. `EntryEvent`
keeps the existing normalized fault address/access/present and adds typed
maintenance service identity rather than synthetic ESR sentinels. Linux
codecs inspect `NativeAbi` and map native ordinals/argument convention after
`syscall_words`; canonical numbers and errno never appear in `KernelArch`.
`Tls` construction belongs to the Linux ABI codec and native qualification;
child result zero and vDSO visible-tid packing remain Linux choices.

`CopyAccess` is lifetime-bound to the existing authenticated owner transfer;
its concrete type cannot be built from `GuestVa` or a boolean permission.
`KernelBuffer` names bytes already mapped in the kernel domain, never a user
VA. Completion authentication remains `carrick-core::entry`, not a trait
method that could invent a receipt (`crates/carrick-core/src/entry.rs:1`;
`crates/carrick-core-abi/src/entry.rs:118`, `:136`). Hardware invalidation ack
feeds the existing exact occupancy/drain authority; it cannot itself release
frames or roots. A frame/context/root operation is legal only under the
caller's exact current-record/service execution lease.

**Descriptor encoding is an existing associated projection, not 20 new
methods on this trait.** In core, bind `A::Mmu: OwnerGrantMmu` and keep live
word loads/stores, before/after descriptor receipts and geometry in
MMU-core. `guest-arch` must not depend on MMU-core: MMU-core already depends
on it (`crates/carrick-mmu-core/Cargo.toml:15`). `A::Mmu` is an unconstrained associated projection in the leaf trait;
the kernel imposes its MMU-core bound. Mechanically type
`OwnerMmu::root(register: u64)` as the native root-register unit and
`OwnerForkMmu`'s descriptor/level/index words as `DescriptorWord`,
`TableLevel`, `TableIndex`; lift shared transaction/receipt declarations
from the ARM namespace to MMU-core root. Keep ARM encode/decode and x86
encode/decode in their current ISA modules (`owner_mmu.rs:21`, `:40`,
`:137`; `src/x86/descriptor_txn.rs:1`). These are rebindings, not another
journal or policy implementation.

**No `boot()` catch-all callback.** Image entry supplies a checked
`BootMappings` view containing code/control VA ranges, root GPA, exact carrier
and context generations. `install_roots` is the only shared root-install
primitive; initial SCTLR/TCR/MAIR/VBAR versus CR0/CR4/EFER/GDT/IDT/TSS setup
stays in image glue. Region lookup becomes borrowed typed views of existing
mapped records, replacing scattered fixed-address casts. Preserve ARM region
addresses exactly (`crates/carrick-el1-abi/src/lib.rs:58`, `:74`, `:1878`).

This surface is minimal by responsibility: raw frame/context, root/coherence,
interrupt clock, checked instruction copy, and host notification. Allocation,
Linux calls, lock acquisition, IPC, ready queues, fork, MM ledger and service
completion are deliberately absent. If a proposed ISA method selects a VMA,
fd, task or Linux result, move that body into the shared owner instead.

## Crate re-homing and line targets

Reuse existing packages. `carrick-core` hosts neutral operational owners,
`carrick-core-abi` neutral records, `carrick-personality-linux` all Linux
policy **including Linux records**, `carrick-sched-core` scheduling/wait,
`carrick-mmu-core` the descriptor substrate, and `carrick-guest-arch` units
and the instruction interface. Keep fd/pipe/inotify/timer/signal cores as
existing dependencies, rather than copying their implementations
(`crates/carrick-el1-abi/src/ipc.rs:95`;
`crates/carrick-el1/src/personality/inotify.rs:8`). Linux fd/pipe semantics do
not become personality-neutral just because their crates say “core”.

| Source module at S | Destination and retained native part |
| --- | --- |
| EL1 `alloc.rs:25`, `lock.rs:1` | Core `metadata/{storage,lock}`: existing allocator ownership, mailbox synchronization and short critical sections. ARM IRQ/current-stack/region binding in EL1; x86 supplies the same bindings, not another heap algorithm. |
| EL1 `sched.rs:128`, `sched/object_wait.rs:1` | Sched-core `guest/{run,wait}` with generic native frame/context and borrowed control records. Linux-facing result/time policy stays Linux. `sched/hw.rs:22`, `sched/aarch64_context.rs:5`, GIC routing codec `sched.rs:66` stay ARM. |
| EL1 `fault.rs:398`, `:431`, `:584`, `:647`, `:720`, `:891`, `:962`; `cow.rs:57` | Core `mm/{fault,cow,capacity,drain}` over existing owners. ESR decode, hardware table resolver, copy window and asm are EL1 native hooks; descriptor adapters remain MMU-core. Portable assertions move with the operational bodies. |
| EL1 `memory.rs:83`, `:186`, `:670` | Linux `mm/{entry,pending}`: decoding, pending syscall lifetime/result and policy. Core takes neutral maintenance/retirement orchestration; native table classification/editing becomes the existing MMU projection (`memory.rs:496`, `:585`). |
| EL1 `personality/mm_portal/{production.rs:67,fork.rs:76,maintenance.rs:21,edit_wait.rs:1}` | Core `mm/{service,fork/pending,maintenance}` owns the whole remaining service orchestration, extending Wave 1. Linux fork inheritance at `fork.rs:48` joins Linux MM. Native `serve_*_hw` transport and checked region resolution stay EL1. |
| EL1 `personality/{common_entry.rs:1,dispatch.rs:1,sched.rs:1,thread_setup.rs:1,lifecycle.rs:1}` | Linux `entry/dispatch/sched/thread/lifecycle`, consuming shared core completion/lifecycle. Consume order-5/6 bodies already there; remove EL1 forwarding wrappers when imports switch. Native entry/ESR/frame and context leaves remain EL1. |
| EL1 `personality/{ipc.rs:173,ipc/epoll.rs:56}` and `substrate/ipc.rs:57` | Linux `ipc/{io,epoll}`, core `io/{transfer,continuation}`. One operation continuation retains byte offset, endpoint pin and completion. Native replay-site calculation replaces `ipc.rs:661`'s ARM SVC subtraction. |
| EL1 `file.rs:268`, `:302`, `:414`; `personality/file.rs:25` | Core `io/file_bytes` for bounded bytes/storage/dirty spans; Linux `file` for fd/access/seek/errno. Guarded load/store and validation at `file.rs:23`, `:84`, `:164` stay ISA. |
| EL1 `personality/inotify.rs:29`, `substrate/watches.rs:5`, `substrate/file_notification.rs:9` | Linux `inotify/{watch,queue,name_cache}`; generic subscription lifetime joins core `object/subscription`. Preserve file-before-instance lock order, exact ready publication and existing fallback/refusal behavior. |
| EL1-ABI `thread_lifecycle.rs:126`, `:195`, `:234`, `:688` | Neutral state/ref/generation in core-ABI; claim/exit/publication implementation in core; Linux identity, clone, robust, mask, altstack and clear-tid in Linux ABI. Consume O6 rather than move it twice. |
| EL1-ABI `ipc.rs:157`, `:398`, `:803`, `:1318`; `ipc_tables.rs:41`; `ipc/epoll.rs:134` | Core-ABI object/operation identities, core pin/subscription/continuation; Linux IPC/fd/eventfd/epoll record and policy implementation in Linux. Physical byte-pool views remain neutral; no native registers in shared operation state. |
| EL1-ABI `lib.rs:690`, `:795`, `:819`, `:1009`, `:1053`, `:1095`, `:1746`, `:2557`, `:2567`, `:2828` and portal modules | Split records as in the ABI table below. Neutral header/state/storage enters core-ABI, Linux payload enters Linux ABI, fixed ARM placement/frame/ESR values stay EL1-ABI. A crate of pure re-exports is deleted; retained EL1-ABI has real native wire/layout ownership. |
| AArch64 `user_transfer/prepared.rs:65`, `:177`, `:228`, `:252` | Core `mm/transfer/prepared_write` for aggregate prepare/settle/cancel/prefix; Linux error interpretation; native `CurrentService`/executor loan at `:26`, `:53` and physical pin/copy binding stay host-side. Reuse X1's completed transport if already moved. |
| AArch64 `engine.rs:1`, `vmm.rs:243`, `stage1_authority.rs:1`, `fork.rs:1`, `descriptor_drain.rs:1`, `mailbox.rs:1`, `owed_kick.rs:1`, `resume_invalidation.rs:1`, `user_transfer.rs:1`, `user_transfer/staging.rs:1` | Keep host engine/bootstrap/service/custody adapters in AArch64, consuming shared protocol. Do not link their std/libc/parking_lot dependency closure into a guest. N1's already-retired host semantic venues stay retired; inversion is not a license to retain/reintroduce them. |
| x86 `cpl0_entry.rs:18`, `cpl0_scheduler.rs:34`, `arch_context.rs:1`, `interrupts.rs:43` | Move native types and instruction leaves into **x86-CPL0's no_std library**; host x86 engine imports that library. Delete `#[path]` inclusion from `crates/carrick-x86-cpl0/src/entry.rs:26`, `:37`. CPL0 library has actual ISA implementation; it is not a facade. |
| x86 `engine.rs:1`, `vmm.rs:1`, `fault.rs:1`, `bringup.rs:1`, `bringup_fns.rs:1`, `vdso.rs:1` | Remain host engine, bootstrap and per-ISA Linux vDSO construction. Shared guest owner/policy must not be implemented here. KVM binds CPL0 library types to its bootstrap/service adapter. |
| EL1 `entry.rs:39`; EL1-image `build.rs:204`, `crates/carrick-guest-arch/src/lib.rs:1`; x86-CPL0 `entry.rs:41`, `progress.rs:24` | Thin image entry/packaging and native vectors remain. Both binaries call the same instantiated core/Linux/scheduler owners; progress fixture remains a fixture, not a production scheduler. |

### Primary production guest denominator and before/after targets

The relocation target uses **guest-resident production source**, excluding
host AArch64 engine source and test-only syntax. Run the existing O6 Rust/syn
census (`docs/perf-results/order6-census/src/main.rs:9`, `:170`, O6), changing
only its line predicate at `:190` to additionally exclude blank and `//`
lines, and its package list to the twelve rows below. Keep every other cfg
branch and embedded asm. This is source classification, not compiled
reachability; the tool's physical-line output is reported independently.
The temporary tool and log live outside tracked source.

At exact S, the original O6 parser reports **10,950 EL1 + 9,311 EL1-ABI =
20,261 physical production guest lines**, plus 13,468 host AArch64 lines.
Applying the brief's non-comment-prefix predicate to those same retained
spans gives **9,287 + 7,054 = 16,341 production guest lines**, plus 10,501
host lines. The independent study's 14,618/9,319 pair does not reproduce
under either published method; without its exclusion rules it cannot be
used as an authoritative denominator. The host-vs-guest correction is valid
regardless of that count discrepancy.

| Crate | Production non-comment-prefix before S | After placement budget | Relocation partition |
| --- | ---: | ---: | --- |
| carrick-el1 | 9,287 | 1,600 | 7,687: core 4,100; Linux 2,700; sched 887 |
| carrick-el1-abi | 7,054 | 400 | 6,654: core-ABI 2,000; core 1,000; Linux 3,654 |
| carrick-aarch64 (host) | 10,501 | 10,301 | 200 aggregate consumer: core 175; Linux 25 |
| carrick-core | 8,218 | 13,493 | +5,275 |
| carrick-core-abi | 3,393 | 5,393 | +2,000 |
| carrick-personality-linux | 1,579 | 7,958 | +6,379 |
| carrick-sched-core | 5,997 | 6,884 | +887 |
| carrick-mmu-core | 8,588 | 8,588 | Existing descriptor substrate, no copy |
| carrick-guest-arch | 355 | 355 | Declaration re-homing/new typed glue measured separately |
| carrick-x86 | 3,524 | 3,274 | 250 existing native production lines to CPL0 library |
| carrick-x86-cpl0 | 371 | 621 | +250; shared owner code stays in dependencies |
| carrick-el1-image | 1 | 1 | Packaging static; unit test source excluded |

**Primary target:** guest-only production residue **16,341 → 2,000**, and
six shared package production footprint **28,130 → 42,671**. Of that gain,
14,341 comes from the guest packages and 200 from the generic host transfer
consumer. Host adapters remain separate at 10,301. The twelve-crate
production ledger conserves **58,868 existing lines**; these are placement
budgets, not measured code edits or image bytes. New glue/tests receive
explicit measured deltas. Native descriptor source within MMU-core is shared
package footprint, not personality-neutral code. Accept no residual owner
body simply because the numeric target passes.

Reproduce with the public O6 census against `git archive S`; retain the
original physical-line run and the modified predicate run side by side.
The exact changed predicate is:

```rust
.filter(|(i, line)| !skipped.contains(&(i + 1))
    && !line.trim().is_empty() && !line.trim_start().starts_with("//"))
```

Receipt: `target/inversion-plan/production-census.log`. O6 mapping
`docs/perf-results/2026-10-06-x86-order6-lifecycle-mapping.md:175`, `:189`
independently publishes the original parser's S counts. Retained/test-only
source is still useful for review workload; report it separately below.

### Supplementary all-source relocation ledger

Counts below use the reproducible `src/` metric above, **including unit tests**.
“After” is a **source-placement budget**, not a measured patch or compiled
image size. Values partition current lines to make the target auditable; the
new typed glue and new witnesses are counted separately at each actual move.
No relocation credit is assigned for merely importing shared code.

| Crate | Before at S | After placement budget | Delta / meaning |
| --- | ---: | ---: | --- |
| carrick-el1 | 22,907 | 3,200 | Move 19,707: core 8,800; Linux 9,097; sched-core 1,810. Retain actual ARM guest adapter and native fixtures. |
| carrick-el1-abi | 10,940 | 600 | Move 10,340: core-ABI 2,800; core 1,450; Linux ABI/policy 6,090. Retain actual ARM layouts/addresses, not forwarding facades. |
| carrick-aarch64 | 15,733 | 15,333 | Aggregate consumer: core 350 + Linux 50. Remaining **host adapter/engine** footprint is not guest kernel residue. |
| carrick-core | 10,747 | 21,347 | +10,600 from the three rows above. |
| carrick-core-abi | 3,884 | 6,684 | +2,800. |
| carrick-personality-linux | 1,609 | 16,846 | +15,237, including Linux ABI and policy tests. |
| carrick-sched-core | 11,050 | 12,860 | +1,810 orchestration; its native record declarations are re-homed within this budget separately. |
| carrick-mmu-core | 18,744 | 18,744 | No algorithm copy; neutral declarations move within the crate. Native descriptor modules are included in this footprint. |
| carrick-guest-arch | 368 | 368 | Budget baseline for replacing, not layering on, its current interface; actual typed surface/context declarations get a measured delta. |
| carrick-x86 | 5,465 | 4,935 | 530 existing native source lines move to CPL0 library. Host loop stays. |
| carrick-x86-cpl0 | 371 | 901 | +530 native source; common kernel linked as dependencies, never copied. Additional boot/copy/allocator hooks are measured separately. |
| carrick-el1-image | 16 | 16 | Packaging library; its 223 non-comment-prefix build-script lines are outside this metric. |

The six existing shared kernel packages total **46,402 → 76,849**, a
**30,447-line** relocation. The narrower core+core-ABI+Linux subtotal is
**16,240 → 44,877**; the remaining 1,810 relocated lines join sched-core.
The three ARM-resident packages total **49,580 → 19,133** before new glue,
partitioned into **3,800 ARM guest image/wire lines** and **15,333 host-engine
lines**. Broad ledger conservation, including x86 and packaging, is
**101,834 before = 101,834 after**. Tests/new declarations can change the real
total; never present these budgeting values as measured achievements.

**Acceptance metric:** no MM, scheduler, wait, lifecycle, IPC or Linux family
body left in either ISA adapter; aim for **≤2,000 current production ARM guest
adapter/wire lines before new typed glue**, separately **≤4,500 all-source ARM guest adapter/wire
lines including native unit fixtures**, with **no unexplained growth beyond the 2,922 direct ISA sites**
under the narrower owner's classification. Recount production-only and
unit-test source separately after every step. The 15k host-engine footprint
must remain separately labeled. A 46,658-line automatic move would be wrong.
Treat the 3,800 planning residue plus 700 lines of glue as an early size
alarm, not permission to hide policy in an adapter. Source totals do not
replace structural budgets, the signed bar, or the ≤2x native-arm64 objective.

The budget needs a refresh on accepted N1+Wave-1 main and the O5/O6/X1 union.
It does **not** add W2's 16,200 extraction forecast on top of this relocation,
or count branch-overlapping anonymous/transfer/lifecycle moves twice.

## ABI decisions: neutral ownership, Linux payload, native layout

“Shared” does not mean “personality neutral”. Shared Rust owners may borrow a
wire projection whose Linux payload lives in `carrick-personality-linux`.
Move methods and records by responsibility without changing ARM bytes.
Preserve repr, atomic widths/orderings, padding, offsets, enum encodings and
layout hashes. Do not serialize Rust generic enums, references or trait objects.

| Existing record / source at S | New owner and layout decision |
| --- | --- |
| ExecutionIdentity/ExecutionMm/EntryCompletion/BornEntryCompletion (`crates/carrick-core-abi/src/entry.rs:27`, `:49`, `:118`, `:136`) | Already neutral; retain core-ABI/core ownership. Owned completion remains noncopyable and exact-generation-bound. |
| CurrentTask (`crates/carrick-el1-abi/src/lib.rs:690`, asserts `:703`) | Shared Linux composite: core execution/MM plus Linux state/metadata. Move to Linux ABI. **Keep 128-byte ARM and currently-used x86 common stride, all offsets and alignment 8 exactly.** Native access views replace fixed region casts. Do not classify visible tid, file table or fixup PC as neutral task semantics. |
| EntryState/EntryRef/claimed/exit/gate; PoolEntry/BornRecord/ThreadControlSlot/ThreadLifecyclePage (`crates/carrick-el1-abi/src/thread_lifecycle.rs:126`, `:195`, `:225`, `:234`, `:332`, `:308`, `:459`, `:688`) | Core-ABI owns neutral transition words/generation, core owns CAS authority; Linux ABI owns the composite pool/page and Linux payload. **Keep lifecycle version 6, 4096-byte page alignment, and every current page/control/pool offset exactly on both ISAs.** O6 implements this split: consume its layout packet, do not redesign it during inversion (O6 mapping `:21`). |
| MetadataGrantRequest/Response/Mailbox (`crates/carrick-el1-abi/src/lib.rs:795`, `:804`, `:819`); existing frame/COW/grant records (`crates/carrick-core-abi/src/lib.rs:1`; `crates/carrick-el1-abi/src/cow_grants.rs:1`) | Core-ABI owns capacity verbs, exact request/storage generations and physical grant/return receipts; core owns capacity protocol. **Exact current mailbox layouts** shared by both, with typed fields of identical storage widths. Fixed ARM aperture placement stays native. |
| Portal transfer/grant/fork/executable slots (`crates/carrick-el1-abi/src/mm_portal.rs:116`, `mm_portal_fork.rs:65`, `mm_portal_executable.rs:31`) | Core-ABI owns operation/custody/completion protocol; Linux request/errno fields use Linux ABI payload codecs. **Keep current retained slot sizes, discriminants and offsets**, split methods without widening the record. Synthetic service ESR/register packing is ARM-only. A future protocol change requires one version bump and simultaneous host/image readers; it is not this move. |
| DescriptorTxnSlots (`crates/carrick-el1-abi/src/descriptor_txn.rs:32`), copy-window records (`service_copy.rs:65`), notification/internal-window records (`delegated_notification.rs:1`, `internal_read.rs:13`) | Neutral slot identities/state to core-ABI; descriptor semantics remain MMU-core. Current neutral slots keep layout. Table alias geometry and stack-derived slot lookup (`service_copy.rs:13`, `:27`) stay ARM. Internal-window privilege remains an owned closed intent. |
| IpcObjectHandle/operation slot/directory/table (`crates/carrick-el1-abi/src/ipc.rs:157`, `:650`, `:1318`; `ipc_tables.rs:41`) | Core-ABI exact object/operation generations plus Linux IPC/fd payload. **Keep current shared-memory directory/table sizes and offsets**. Store normalized deadline and raw saved call words at their existing widths. Original ARM register interpretation becomes Linux native codec; the shared owner never inspects x0. If a new context reference cannot fit, introduce an ISA-tagged versioned operation record with both readers switched together; do not silently repurpose words. |
| DelegatedInodeIdentity/Mark/File/OpenFile/FdMapSlot (`crates/carrick-el1-abi/src/lib.rs:1009`, `:1040`, `:1053`, `:1095`, `:1326`) | Core-ABI owns storage/version/pin/subscription records, Linux ABI owns access/open-offset/fd composite. **Exact current host-read layouts**; operational methods join core or Linux. Host file handle/backing retains host custody. |
| DelegatedWatch/Inotify/NameCache (`crates/carrick-el1-abi/src/lib.rs:2557`, `:2567`, `:2828`, `:2897`) and Counters (`:1746`) | Linux ABI owns watch/mask/wd/name-cache and syscall-indexed counters; generic readiness version/pin may be core fields. **Exact current table/counter layouts**. These records are shared across ISAs, not neutral Linux-free wire. |
| TrapFrame / ImageHeader / region constants (`crates/carrick-el1-abi/src/lib.rs:645`, `:587`, `:58`) | Stay ARM native wire/layout in EL1-ABI. Preserve vector save offsets and image-header version 2. x86 NativeFrame/CpuBinding stay x86-CPL0 wire (`crates/carrick-x86/src/cpl0_entry.rs:18`, `:86`). Do not put a union of register files into a neutral trap frame. |
| AArch64SyscallMailbox (`crates/carrick-aarch64/src/mailbox.rs:1`, `:7`, `:20`) | **Keep ARM mailbox version 3, 256 bytes, alignment 64 and all offsets.** Its SPSR/ESR/X16/X17/FP/LR payload is intrinsically ARM. x86 continues its versioned port/native-frame transport; only service-operation payloads are common. |
| ThreadCtx embedded in ZoneRecord (`crates/carrick-sched-core/src/lib.rs:382`, `:573`, `:699`) | Parameterize the existing record/table by native context, with explicit per-ISA layout identity. Retain ARM Context repr(C, align(16)), every original field offset including V at 304 and FPSR/FPCR, and therefore ARM ZoneRecord/ZoneTables byte layout. x86 gets **versioned per-ISA context/table layout** with 64-byte XSAVE alignment; it never treats ARM context bytes as x86 state. |

For scheduler generics, `ZoneTables<C>`/`ZoneRecord<C>` own the same claim
state machine, queues, incarnation and occupancy. ARM and x86 instantiate
those bodies with their one context type. No `Default` type argument hiding
an ARM layout. Native context storage definitions live in dependency-leaf
`guest-arch::{aarch64,x86}::wire`, with no instructions or host dependencies;
ISA implementation accesses those layouts. This avoids a sched-core →
EL1-ABI dependency cycle. Move the context declaration out of sched-core;
its algorithm depends only on a context-storage contract, not register fields.
The shared guest switch consumes `original_arg0`/result via the native context
accessor, replacing `crates/carrick-el1/src/sched.rs:317`, `:319`; Linux
continues to select timeout/child results. Child context qualification must
finish before output writes or birth publication, replacing native field
writes at `crates/carrick-el1/src/personality/lifecycle.rs:489`, `:490`.
The hook copies only machine state and installs Linux-selected stack/TLS/result;
it allocates no task, reserves no identity and publishes no birth.
The before/after budget must account for this declaration-only internal move.

A common boot **layout descriptor** identifies ISA, scheduler-layout version,
record/table size/alignment/offsets and hash. Host views select the ISA once
at boot, then use the exact matching compiled type. Reject an unknown or
mismatched descriptor before running a vCPU. ARM can keep its existing hash
when physical facts are unchanged; x86 cannot reuse that hash for a different
context layout. Lifecycle, generic service and capacity records retain their
existing versions. No compatibility reader for an old format is introduced.
All host crash/debug readers of parked context must switch simultaneously
(`crates/carrick-sched-core/src/lib.rs:436`, `:699`); an empty ARM `x[]` for x86 is invalid.

Linux ABI codecs remain in Linux: clone argument order, rt-signal frame,
vDSO identity packing and epoll event layout. The current epoll codec is
16 bytes with data at offset 8 (`crates/carrick-el1/src/personality/ipc/epoll.rs:56`, `:228`).
Reuse the existing x86 Linux wire record
(`crates/carrick-abi/src/lib.rs:902`) for its 12-byte packed stride/data
at offset 4; its guest client codec must be independently qualified, with committed oracle bytes and numeric errno
before admission. It is a per-ISA **Linux ABI**, not a core or interrupt
implementation. Preserve current ARM behavior while adding the x86 codec.

## Host changes: imports, typed views, existing transport

No host scheduler/MM policy rewrite is needed to share the guest kernel.
N1's approved removal of admitted host semantic venues is a predecessor,
not extra inversion scope. Physical mapping/backing/pin/quota and runtime
job/terminal authority remain where they already live. An inversion cannot
claim all Linux calls became guest-owned simply because both binaries link.

| Host package | Required minimal changes / preserved boundary |
| --- | --- |
| carrick-vmm-hvf | Rebind neutral/Linux record imports and instantiate ARM scheduler/context layout views. Keep vector/HVC, boot roots, GIC, stage-2 16 KiB physical custody and existing service executor. `hvf_aarch64_engine.rs:2534`, `:2895` take current portal records; callers must compile against the moved definitions. No new host permission/COW/descriptor owner. |
| carrick-aarch64 | Keep register/backend and native mailbox/service glue. Switch aggregate prepared-write consumer to shared core/Linux binding; preserve loan/pin/cancel ordering (`user_transfer/prepared.rs:26`, `:53`, `:199`). Update immutable image/layout validation and parked-context capture type. |
| carrick-runtime | Imports for CurrentTask/lifecycle/IPC/portal; typed carrier region views and native context decode for diagnostics. Preserve terminal-clear/wake completion authority in `vcpu_loop/threads.rs:104`, `:127`; shared Linux constants/policy do not replace graph/job teardown. Runtime must not run guest kernel methods on the host as a shortcut. |
| carrick-vmm-kvm | `cpl0_boot.rs:123`, `:189`, `:313`, `:427`: initialize the common Linux/capacity/IPC/file records at checked supervisor mappings; select x86 layout descriptor; install the existing native roots/vector/APIC and retained backing/service transport. Bind real allocator and scheduler service capacity. These are boot/physical effects, not implementations of fault, clone or IPC syscalls. |
| carrick-x86 | Import no_std CPL0 native records/leaves; retain host backend loop and boot codec. Remove included-by-path duplicate module compilation and any semantic family binding displaced by the shared kernel. |
| Image builders/debug readers | EL1-image nested build remains the signed lane's image source (`build.rs:204`); extend its dependency invalidation list (`:251`) for guest-arch and all actually linked shared crates. x86 linker/checker records its own closure. Update LLDB/crash layout metadata for the typed native context simultaneously, preserving ARM offsets. |

A **cheap Mac compile guard** precedes every push touching moved public
records/traits: a small non-HVF host ABI-consumer compile target, built on
Linux, imports and type-checks the precise constructors/methods/signatures
used by the HVF/runtime callers above. Also run both freestanding image
release checks. This catches ordinary path/type/layout drift without buying
a signed queue. It is a real consumer test, not a text grep or copied host
implementation. On a Mac, CI adds `cargo check --locked -p carrick-vmm-hvf`
and the runtime/CLI macOS closure plus affected all-target Clippy before the
signed comparison. Linux cannot compile all macOS cfg branches or qualify
Applevisor APIs, signing, DOF, GIC and physical custody; the compile target
is an early guard, not a replacement for that Mac gate. O6's host consumer
and capture limitations are explicit (O6 mapping `:205`, `:244`).

## Sequencing: small landable dependency cuts

Each row keeps ARM admission,
results, refusal, ordering and work identical. Most are mechanical moves/type
projections; step 1b explicitly adds the missing x86 resume integration. Split a row further along
module boundaries if its diff is too large; never introduce another family
trait seam to make a large move easy. A single integrator owns shared
manifests, context/layout declarations and inventories. All paths below refer
to the source/target fences in the re-homing table. **New `inversion_*` test
names are proposed**, not current passing tests. X1–X8 names retain the
previous plans' meaning, not a redefinition of acceptance.

| Step and move | Focused proof; x86 CPL0 execution unlocked | ARM signed comparison to its exact predecessor |
| --- | --- | --- |
| **0. Accepted N1 + Wave 1 main, integrate reviewed inputs** | Audit current N1 fixes and O5/O6/X1 ledger. Preserve executing entry/progress/X1 controls and old failures. No new source move is credited. Inventory all fixed casts/native contexts. | N1 main acceptance first. O5, O6, X1 each require no new signed failures against their own integration base before being relied on. |
| **0a. First mechanical implementation: isolate every guest instruction leaf** | Move complete native helper bodies and each asm invocation verbatim under EL1 `isa/aarch64`, including frame save/load, AT/fixup copy, TLBI/GIC/timer/IRQ and HVC. Preserve symbols, inline/asm options, register constraints and call ordering; introduce no owner code there. Wire the existing guest-arch backend projections to these leaves after their typed signatures are ready. The source gate permits asm only in the native subtree; image disassembly must preserve native instruction sequences modulo relocation. KVM's existing native entry/progress tests remain green; this step does not newly admit a Linux family. | EL1_ABI_LAYOUT_HASH unchanged; current signed EL1 packet has no new failure. Preserve the audited FP/SIMD symbol checker. |
| **1. Leaf units and native frame projection** | Rebind guest-arch units and frame accessor once; move ARM native wire declarations without changing offsets. Run existing entry-completion and Linux native-codec tests. KVM X4 plus new `inversion_native_entry_registers` exercises all argument/result/PC/SP/replay conventions, malformed return and kick boundaries. Replace frame.x[N] with inlined accessors for call/return/service arguments/reply, then compile the real shared bodies for x86 to expose remaining leaks; never accept a stub that forwards those bodies. | AE plus fault-context preservation, pending-work return and current admitted syscall families. |
| **1b. Nonterminal host-service handoff/resume** | Replace CPL0's terminal forward branch with an owned suspend→host-effect→exact-operation resume/settle path through the existing service protocol. Preserve result, original arguments, prefix and successor context; do not redispatch a served call. New `inversion_service_resume` injects stale/duplicate completion and kicks while two MMs are live. This is explicit x86 integration work, not an ARM algorithm change or a KVM callback substitute. | AE/AM/AW verify ARM service ordering unchanged; existing HVC transport remains. |
| **2. Layout-preserving neutral/Linux ABI moves** | Move retained records/methods into core-ABI/core/Linux modules as the ABI table specifies; both host/image imports switch. Independent pre/post size/align/offset/hash observations, including lifecycle/version/CurrentTask. Existing X4/X5 plus new `inversion_wire_layout_identity` rejects wrong ISA/version/hash before execution. | ABI refusal negative controls plus AE/AL. No source-only assertion counts as signed proof. |
| **3a. Generic native scheduler context storage** | Move native context declarations to leaf wire modules; parameterize ZoneRecord/ZoneTables and all claim/capture consumers. Preserve ARM layout byte-for-byte; give x86 its tagged layout. Existing KVM context/progress tests, TLS/XSAVE canaries and `inversion_context_incarnation` prove record reuse cannot load predecessor state. | AW + AR, parked-context/core capture, cross-MM scheduling; preserve ARM FP/SIMD disassembly checker. |
| **3b. Shared scheduler/wait orchestration** | Move `Sched` and object wait bodies to sched-core, replacing frame result/TLS/root/IRQ spellings with the one ISA surface. Linux selects futex/timeout results. X5 clone→park→clear/wake and `inversion_pool_exhaustion` at `max(32, actual_executor_count+1)` become executing tests on the real persistent pool when bound. Until then bounded CPL0 progress is only bounded proof. | AW/AL, two-live-process MM occupancy, clone storm and more parked threads than default executor capacity. No larger pool, polling or serialized symptom. |
| **4a. Shared short lock + metadata storage** | Move IRQ-independent lock/allocator protocol with existing mailbox/capacity owner. Bind both image global allocators to it; delete CPL0 NoAllocation. `inversion_allocator_grant_return` executes three-scale growth, refusal, exact return and unrelated progress; assert zero inline allocation host-waits while masked. | Existing allocator sequential/concurrent/delayed-owner/IRQ-boundary packet and fixed work/retention budgets. |
| **4b. Descriptor type projection and region views** | Neutral declarations move within MMU-core; both descriptor modules retain implementations. Borrow boot-provided typed table/control views. Existing X1 descriptor/red controls plus `inversion_nonidentity_roots` use two MMs, same VA, different GPA/generation. | AM/AF/AR: stale translation, copyout, root/ASID return; preserve alias alignment and 16 KiB compound geometry. |
| **5a. Whole MM fault/drain/maintenance orchestration** | Move residual `fault`, COW wrapper, portal pending fork/maintenance/service bodies to existing core owners. Keep only decoded event/checked table/copy/native-doorbell leaves per ISA. Existing X1–X3 and new X6 execute first touch, COW, refusal, brk contraction/regrowth and stale completion through CPL0. | AM/AF/AW/AR, including zero/regrowth, frame return/reuse, cross-vCPU protect/unmap/fork/exec invalidation. |
| **5b. Linux MM client and shared aggregate transfer** | Move residual memory/pending syscall and Linux fork policy to Linux; aggregate prepared-write to core. Reuse X1's already-shared anonymous/transfer pieces. X6 and `inversion_transfer_cancel_before_loan_return` prove actual two-MM bytes, wrong-peer physical pin refusal, short prefix and cancellation before executor loan release. | AM/AF: host copyout, stopped-target service, retained parent write/abort, aggregate cancellation ordering. |
| **6a. Whole object/IPC retained storage** | Move ABI object generation/pin/operation/subscription mechanisms to core; Linux fd/eventfd/epoll payloads/methods to Linux. Existing fd/pipe owners stay. New `inversion_ipc_retained_prefix` executes close/dup/reuse and endpoint lifetime at three scales. | AI/AW: inherited fds, blocked operation lifetime, signal-after-progress, cancellation and default-pool exhaustion. |
| **6b. Whole Linux IPC client** | Move IPC/epoll/substrate transfer bodies and tests into Linux/core. Use native replay-site and the shared copy owner; qualify x86 packed epoll codec before admission. X7 `x7_shared_ipc` executes two-process pipe/eventfd/epoll, large partial write and ready/timeout/close. | AI: two-process blocking, pipe/epoll ping-pong, mixed host/zone and signal/close controls; no changed retry or wait bounds. |
| **7a. Whole file/subscription mechanisms** | Move bounded file bytes/dirty/storage/subscription bodies to core and Linux composites to Linux ABI. Native checked copy stays behind ISA. X8 begins with `inversion_file_shared_inode` (two processes, independent open offsets, same inode, short copy). | AQ/AM: real file bytes, shared inode, host copyout and cross-process readers; preserve current admission/refusal behavior. |
| **7b. Whole Linux file/inotify client** | Move file/inotify/watch/name-cache policy and portable tests to Linux, reuse inotify-core, preserve lock order. X8 `x8_shared_file_inotify` executes watch churn/overflow/close and exact bytes/errno, plus three-scale zero extra host watch/position/queue work. | AQ/AI/AW and **separate exact `inotify_hotpath_contract_budget`** signed receipt, not just `el1_` selection. |
| **8. Close both image closures and delete displaced paths** | Move remaining common entry/lifecycle adapters consumed from O5/O6 into their shared owners, with only native leaf calls; replace temporary `PendingFamilies` with direct shared client calls. Both image builds expose the same entire kernel crate set; only native instructions/codecs differ. No EL1-only kernel-module cfg exclusions or `#[path]` cross-package inclusions. Re-run full executing X1–X8 and production service/pool coverage. | Complete affected signed packet on final integrated source; exact artifact probe→smoke→full promotion is director-owned. |

This is not “each family implements a trait then gets extracted later”. The
kernel modules are moved **whole**, after prerequisite native projections;
only instruction effects remain trait hooks. IPC/file records can move in
multiple import-only commits, but their owner bodies have one implementation
throughout. Every intermediate ARM binary is runnable with identical behavior.
A CPL0 build that links an unbound module is labeled compilation-only until
its executing test is unlocked. Unsupported x86 ordinals remain explicit
existing refusals in the one Linux codec, not default-off hidden product paths.

### Fold in in-flight work, preserving fixes and authors

**Order 5 / PR #68:** retain its one Linux dispatch, exact entry/completion
and pending-work effects as the starting owners. S already contains the
pending-effect move; O5 includes later review corrections. Map each later
O5 commit to accepted N1 main before cherry-picking/rebasing. Preserve the
gettid/setup pending-work exceptions, owned scheduler suspension/switch
receipts and single counter publication (O5 mapping `:29`, `:32`, `:36`,
`:67`). Its temporary family hooks are a migration input, not the inversion
endpoint. Delete them when whole bodies move. Keep actual X4 denominator
honest: at S x86 decode admits only native 273
(`crates/carrick-personality-linux/src/entry.rs:12`;
`crates/carrick-x86-cpl0/src/entry.rs:134`).

**Order 6 / `work/x86-ord6`:** consume neutral lifecycle state/claim bodies,
Linux clone/exit/setup, and reviewed native context leaves. Do not recreate
its already moved records. Bring it forward over the reviewed O5 union once,
using a fix ledger rather than copying complete old EL1 files. Keep version-6
layout equivalence, clear-before-wake, output rollback, exact incarnation,
adopted-job refusal and TLS/XSAVE execution reds (O6 mapping `:21`, `:137`,
`:146`, `:175`, `:261`). Its bounded two-context fixture does not close the
persistent carrier pool or adopted-job semantics (O6 mapping `:214`). Mac
capture discrepancies require real recapture, not fabricated inventory rows
(O6 mapping `:244`).

**X1 / PR #64:** consume shared anonymous edit/translation/service capabilities
and their pin/rollback/invalidation fixes into the existing MMU/core graph.
Preserve its production-path reds and source fence; do not count its Linux
decoder move twice (X1 mapping `:19`, `:34`). The inspected increment qualifies
one executing lane per MM, local non-PCID invalidation and bounded whole-grant
same-size remap; it does not qualify multi-vCPU shootdown, general remap,
physical return/reuse, OCI or persistent-pool production X1 (X1 mapping `:5`,
`:23`; PR #64 review packet). Cross-MM transfer and peer pin rejection must
be executing, not host callback results, before step 5b closes. The director's
reported signed ARM regressions on an earlier X1 packet remain a blocking
comparison obligation, not assumed acceptance. Keep their exact first-bad
attribution and red/green fix packet in step 0's integration ledger.

For every input fix record original SHA/author, responsibility/symbol,
kept/ported/dropped disposition, mapped integrated SHA, retained red/green
witness, scale/budget, and remaining native binding. A dropped fix needs a
superseding fix and equivalent assertion or actual operation retirement.
Re-prove the red on an isolated pre-fix owner or narrowly inverted current
fix; never resurrect a second dispatcher to produce a red. All adopted
changes preserve original authors and N1's newest generation/custody fixes.

### Verification contract for every implementation landing

For each step, **the AArch64 signed bar is no added signed failure versus
that step's exact accepted predecessor**. Also compare the final aggregate
against step 0, so a previous red cannot disappear from the denominator.
A missing binding, unknown counter or incomplete run blocks landing. Existing
baseline failures stay explicitly named; the inversion does not turn them
into success. Assertions, budgets, populations, concurrency and wait bounds
remain unchanged. Newly exposed shared defects require a separate red-first
fix to the one owner, not a “mechanical move” exemption.

Use the cheapest capable layer and preserve these existing contract families:
`kernel.el1.mm-exclusive-owner`, `kernel.el1.stage1-publication`,
`kernel.fork.stage1-image`, `kernel.mm.address-space-occupancy`,
`kernel.el1.thread-lifecycle`, `kernel.futex.contention`,
`kernel.el1.ipc-lifecycle`, `kernel.el1.ipc-two-process`,
`kernel.el1.epoll-zone`, `kernel.el1.files`, `kernel.inotify.mark-race-hotpath`
(descriptors in `conformance-contracts/contracts/el1-mm-exclusive-owner.toml:2`,
`el1-stage1-publication.toml:11`, `fork-stage1-image.toml:2`,
`mm-address-space-occupancy.toml:2`, `el1-thread-lifecycle.toml:2`,
`futex-contention.toml:2`, `el1-ipc-lifecycle.toml:2`,
`el1-ipc-two-process.toml:2`, `el1-epoll-zone.toml:2`, `el1-files.toml:2`,
`inotify-mark-race-hotpath.toml:2`). Reuse O5/O6 `core.entry.completion` and
`core.lifecycle.publication` where integrated; register missing object/file
and native-context bindings red-first, in the existing contract harness.

VM-free focused commands, after moving tests with their owners:

```sh
cargo test --locked -p carrick-core -p carrick-core-abi -p carrick-personality-linux --lib
cargo test --locked -p carrick-mmu-core -p carrick-sched-core --lib
cargo test --locked -p carrick-core --test x86_acceleration
cargo test --locked -p carrick-personality-linux --test x86_wave2
cargo test --locked -p carrick-conformance-contract --lib personality_boundary
cargo build --locked --release -p carrick-x86-cpl0 --target x86_64-unknown-none
cargo build --locked --release -p carrick-el1 --target aarch64-unknown-none-softfloat
```

Some paths/filters move; register the new witnesses and reject zero-test
execution. Run exact CPL0 targets in existing KVM entry, progress, lifecycle,
carrier-memory and proposed IPC/file runners. Require actual CPL0 owner
entry/completion counts, nonzero population, byte checks, exact operation
identities and zero semantic host forwards for admitted operations. A host
callback that applies descriptor edits is preparation, not execution proof.
Record negative controls for missing invalidation, wrong generation/peer,
duplicate completion and retained-prefix replay. Freeze MM work at
16/64/256 touched pages with 16/512 unrelated mappings, pool progress beyond
default capacity, and file/IPC work at at least three sizes.

Linux workers run focused tests, changed-closure all-target Clippy,
`just fmt-check`, `just lint-domains`; no Docker, full `just accept`, or
remote-accept per worker PR. Reconcile inventories only on a clean integrated
snapshot. The director owns one full stacked gate plus each required signed
comparison. On the Mac, rebuild/sign the exact source and record CLI/test/image
SHA-256, CDHash, LC_UUID, entitlement, DOF, ISA/layout hash, run ID and scoped
cleanup. At minimum run the current N1 full affected packet and:

```sh
just build
just --no-deps test-embed el1_ --nocapture
just --no-deps test-embed inotify_hotpath_contract_budget --exact --nocapture
```

The explicit budget test is necessary (`crates/carrick-embed/tests/inotify_hotpath_contract.rs:41`);
its name is not selected by `el1_`. Separate signed test-executable identity
from CLI identity. Preserve unentitled negative control. The final held CLI
artifact is promoted without rebuilding/re-signing through probe → smoke →
full; Docker is a separate director phase. KVM discovery does not qualify
ARM/HVF, oracle coverage, N3 exit ceilings or the ≤2x performance objective.

## Risks and concrete disproofs

| Risk and evidence | Guard / early disproof |
| --- | --- |
| **no_std/alloc and forward/resume closure**: EL1 enables rust_alloc only for ARM and excludes substantial x86 modules (`crates/carrick-el1/src/lib.rs:7`, `:9`, `:12`; `personality/mod.rs:7`). CPL0 halts on allocation (`crates/carrick-x86-cpl0/src/entry.rs:11`) and after Forward (`crates/carrick-x86-cpl0/src/entry.rs:153`). AArch64 host crate pulls libc/parking_lot (`Cargo.toml:51`). | Two bare-metal release builds after every move; cargo dependency-closure check rejects std/libc/parking_lot/backend imports into guest packages. Step 1b proves host-effect handoff/resume before any owner can suspend across that boundary. Shared allocator binds both global allocators before executing an allocating path; exact grant/refusal/return test precedes IPC/file admission. No dummy allocator or host-test feature in product closure. |
| **Image text/control overlap**: ARM linker reserves only 1 MiB before counters (`el1/link.ld:41`), despite a larger kernel region (`crates/carrick-el1-abi/src/lib.rs:58`). EL1-image audits FP/SIMD (`build.rs:36`, `:236`). | Record ELF section sizes, binary end, stack/heap/control bounds and reachable symbols for both images at each step. Keep ARM linker limit unchanged for mechanical moves; investigate excess instantiation/inlining first. A deliberate layout expansion is a separate versioned host/image change with signed proof. x86 map must cover actual PT_LOAD spans, not a fixed bootstrap assumption (`crates/carrick-vmm-kvm/src/cpl0_boot.rs:123`). Common source SLOC is not image size. |
| **Atomic/order differences**: publication uses atomic execution state and release generation (`crates/carrick-el1/src/sched.rs:91`); lifecycle uses retained CAS/gate states (`crates/carrick-el1-abi/src/thread_lifecycle.rs:940`). x86 TSO can conceal a missing ARM acquire/barrier. | Preserve exact orderings and widths on mechanical moves; no relaxed “x86 optimization”. VM-free interposition at close/enroll/publish/rollback plus ARM signed concurrent Dekker/wake tests; hardware table-store ordering remains ISA-specific. Unaligned packed Linux epoll bytes never become unaligned atomic fields. |
| **Interrupt/allocator context**: ARM WFI occurs masked (`crates/carrick-el1/src/sched/hw.rs:274`); x86 park uses STI/HLT/CLI (`crates/carrick-x86/src/interrupts.rs:68`). Saving DAIF/flags is not a semantic permission to block. | Noncopyable mask guard restores once; no allocation/host wait while holding short IRQ/MM/root guards. Owned suspension releases execution capacity and all borrowed editors; allocator demand exits through existing pending-work boundary. Inject kick/timeout during clone, copy, COW and return. No new polling, retries or timeout increases. |
| **Context/layout circularity and code bloat**: scheduler embeds ARM ThreadCtx (`crates/carrick-sched-core/src/lib.rs:573`), while core-ABI depends on sched/MMU/guest-arch (`core-abi/Cargo.toml:9`). | Leaf native wire declarations + generic storage only; avoid sched-core importing either image. Instantiate one ISA per binary. Keep ARM repr/offset packet unchanged and require fail-closed per-ISA host layout tag. Track monomorphized symbol/code size; never link both ISA instruction implementations into one image. |
| **In-zone authority accidentally delegated**: host engine bodies include native service/custody, not shared guest ownership (`crates/carrick-aarch64/src/user_transfer/prepared.rs:26`; `vmm.rs:555`). Current guest forward paths are real scope limits (`crates/carrick-el1/src/personality/ipc.rs:173`). | Kernel dependency/import fence and CPL0 counters/bytes expose an owner routed to host. Preserve existing refused surfaces; never make a test green by falling back to host semantic execution. Per-operation transfer uses exact-MM selection→physical pin→live mapping revalidation. |
| **Mac-only caller breaks invisible on Linux**: HVF portal callers and runtime terminal sequencer are separately compiled (`hvf_aarch64_engine.rs:2534`; `crates/carrick-runtime/src/vcpu_loop/threads.rs:104`). O6 Mac capture remains pending (O6 mapping `:244`). | Linux host ABI-consumer compile target plus exact Mac check before signed queue. Mac authority capture/line-pin updates are real compiler outputs on clean source; no synthesized capture and no gate weakening. |
| **“Everything is shared” becomes an unearned result**: image exclusion/NoAllocation and bounded progress fixture are explicit at S (`crates/carrick-el1/src/lib.rs:4`; `crates/carrick-x86-cpl0/src/entry.rs:11`, `progress.rs:1`). | Report three distinct denominators: linked kernel modules, admitted/executed Linux operations, production service/pool/hardware coverage. Final closure needs all three, both native contexts, and the per-step signed bar. |

## Independent cross-check disposition

1. **Agree on host classification; correct the numeric method.** AArch64
   is a std host engine (`crates/carrick-aarch64/Cargo.toml:16`, `:51`),
   not guest kernel. The primary production guest denominator is now the
   reproduced 16,341 non-comment-prefix lines / 20,261 physical lines;
   49,580 is only the supplied all-source study denominator. The proposed
   14,618/9,319 counts need a reproducible exclusion method before adoption.
2. **Agree: use the existing, currently unimplemented ISA interface.** The
   only existing implementation is blanket composition at
   `crates/carrick-guest-arch/src/lib.rs:401`. Fold ThreadCpu/UserWord
   (`crates/carrick-el1/src/sched.rs:20`, `:54`), MemoryValidator/UserCopy
   (`crates/carrick-el1/src/file.rs:138`, `:229`), anonymous editors
   (`crates/carrick-el1/src/memory.rs:309`), descriptor application and
   COW window (`crates/carrick-el1/src/fault.rs:255`, `:466`) into its
   existing projections with typed roots/targets/access. Keep MMU-core
   TableMaintenance/OwnerMmu implementations; no third trait or journal.
3. **Agree on obstacles.** Native context/layout and descriptor namespace
   mixing are covered above. Direct frame accesses must be replaced through
   inlined native views, not merely moved under a “shared” crate. The syntax-filtered `.x[` line counts
   at S are IPC 14, memory 29, portal production 45, dispatch 30 and fork 16
   (`target/inversion-plan/production-census.log` and Appendix A). The
   independent 76/46/45/35/16 list therefore is not the same source/method;
   its qualitative warning stands, but those numbers are not work budgets.
   AArch64 register service packing is a codec for a shared retained operation, not
   the shared protocol itself. NoAllocation and Forward→halt prevent an
   allocating/suspending production kernel from running on CPL0
   (`crates/carrick-x86-cpl0/src/entry.rs:11`, `:153`). Step 1b explicitly
   closes the latter; cfg exclusion removal alone does not.
4. **First step: verbatim native instruction-leaf relocation (0a).** It
   gives an enforceable asm fence with unchanged ARM wire hash and an
   instruction-sequence comparison before type/body moves. Accessors and
   shared-body x86 compile follow. A compile-only x86 stub may be a temporary
   uncommitted diagnostic, never a landable second kernel implementation or
   acceptance result. **Reuse core-ABI**, as the owner requested, rather
   than introducing a new zone-ABI facade; records with Linux semantics
   enter Linux ABI. Generic native context follows the leaf/record split.

## Document verification and handoff

This design's only tracked change is this file. Verify all pinned citations
against S or their explicitly keyed revisions, reproduce 49,580 and the
per-crate conservation ledger, and review the full ISA appendix rather than
relying on its hit count. Run documentation whitespace/format checks, focused
personality-boundary tests/Clippy and typed-domain lint on publication P.
Record any pre-existing failure without changing source/inventories to make
this document pass. No red-first product test, CPL0 run, Docker or signed
acceptance is performed or claimed for this documentation exemption.

Before implementation, director review must confirm the boundary inventory,
context layout/projection, line targets, accepted N1 main SHA and input-fix
ledger. The document is review-ready design, not authority to skip any signed
comparison or to merge an unqualified input.

Publication checks on P (Linux carrick-vm): the exact embedded census recipe,
all nine appendix groups, citation bounds, both conservation ledgers and
the Rust/syn production census pass;
30 `personality_boundary` tests, focused all-target Clippy, product
`just clippy`, `just fmt-check`, `just lint-domains` and staged
`git diff --check` pass. Lint's live compiler census executes only
`linux-cli`/`linux-runtime` (565 reviewed rows), leaving Mac/FreeBSD/NetBSD
profiles pending; it is not whole-host-matrix acceptance. Receipt directory:
`/home/carrick/dev/wt-inversion-plan/target/inversion-plan/`.
No source, inventory, contract, image or budget changed. Signed/HVF checks
cannot run here; Docker and full acceptance were not run. Proposed steps and
new witnesses remain design work, not tested implementations.

## Appendix A: ISA-touching file/line census at S

The following conservative inventory includes lexical direct uses plus full
asm invocations (instruction lines, register constraints, clobbers and options).
No comment-only or blank lines count as sites. Multiple groups may contain
the same line; the distinct-line totals above remove that overlap. x86 rows
are supplemental, outside the 49,580 denominator. Paths ending in `tests.rs`
or test directories remain explicitly visible rather than falsely counted
as guest production code.

### T — trap/frame

| Pinned source path | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-el1/src/cow.rs` | 30, 37, 185, 192, 217, 397, 410, 930, 945, 960–962, 964, 1088, 1103, 1128–1130, 1132 |
| `crates/carrick-el1/src/entry.rs` | 37, 42, 46, 50, 54, 58, 62, 66, 70 |
| `crates/carrick-el1/src/fault.rs` | 4, 27–29, 35, 42–44, 50, 57–60, 215–216, 218, 224, 399, 420, 432, 707–708, 721, 729, 762, 767–768, 770, 773, 783, 804, 822, 892, 921, 924, 928, 947–948, 952, 963, 973, 1005, 1011, 1024, 1034, 1055, 1061, 1065, 1075, 1081, 1097, 1102, 1130–1133, 1135, 1139–1142, 1144, 1296–1299, 1323–1324, 1328, 1330, 1352–1355, 1385–1386, 1489, 1508, 1762, 1846–1849, 1854, 2156–2158, 2160, 2373–2374, 2376, 2378–2379, 2386, 2388, 2395 |
| `crates/carrick-el1/src/memory.rs` | 6, 86, 99, 113, 124, 141, 145, 147–149, 155, 164, 187, 199, 201, 203, 211, 217, 221, 223–224, 227, 229, 232, 236, 243, 246, 249–250, 267, 270, 670, 677, 890, 895, 898–899, 949, 954, 957–959, 1045, 1053–1057, 1079, 1094–1095, 1234–1235, 1246, 1253–1254, 1267, 1279, 1441–1443, 1445–1446, 1455 |
| `crates/carrick-el1/src/personality/dispatch.rs` | 8, 34, 54, 61, 77, 113, 124, 149–150, 153, 161, 187, 204, 239, 277, 295, 339, 426, 434, 450, 465–466, 481, 498, 553, 580, 598, 645, 677, 687, 703, 709–711, 726–727, 737, 746, 757–759, 773, 800, 818, 855, 1003–1004, 1030, 1033, 1039, 1046, 1058–1059, 1074–1077, 1082, 1096–1099, 1108–1110, 1121–1124, 1129 |
| `crates/carrick-el1/src/personality/ipc/epoll.rs` | 41, 84, 102, 113, 118, 121, 126, 144, 162–163, 193, 297–298, 306 |
| `crates/carrick-el1/src/personality/ipc.rs` | 53, 71, 175, 179, 208, 254, 264–265, 280–282, 323, 341, 398, 549, 640, 651, 723, 741, 752–753, 756–757, 1134, 1156, 1164, 1189–1190, 1194–1197, 1199, 1201–1204, 1208–1210, 1283, 1285, 1305, 1308, 1312–1313, 1315, 1334, 1341, 1343, 1346, 1367, 1369, 1371, 1375, 1377, 1404, 1411, 1413, 1446, 1458, 1460, 1483, 1486, 1489, 1491, 1516, 1521, 1533, 1535, 1539, 1542, 1553, 1557, 1561, 1564, 1581, 1623, 1635, 1646, 1648, 1683, 1685, 1741, 1799, 1821, 1825, 1833, 1839, 1844, 1849, 1851–1852, 1860, 1893, 1916, 1924, 1926, 1930, 1934, 1940, 1946, 1948, 1972, 1981, 2003, 2037, 2042, 2084, 2088, 2140, 2168, 2220, 2231, 2256, 2263, 2342, 2344, 2358, 2413–2414 |
| `crates/carrick-el1/src/personality/lifecycle/tests.rs` | 161–163, 165, 186–189, 217, 262, 303, 349–350, 385, 467, 483–485, 498–500, 508, 564, 590, 617, 671, 678–680, 730, 734, 817, 824, 844, 849–851, 863–864, 885–886, 991 |
| `crates/carrick-el1/src/personality/lifecycle.rs` | 34, 124, 131, 138–140, 167, 192, 197, 208, 222, 226, 272, 277, 392, 399, 489, 520, 609, 618 |
| `crates/carrick-el1/src/personality/mm_portal/edit_wait.rs` | 9, 16, 19, 29, 39–40, 43, 48–49, 81–82 |
| `crates/carrick-el1/src/personality/mm_portal/fork.rs` | 428, 430, 434, 438, 443, 466, 475–476, 479, 493, 495, 497, 503, 508, 514, 519, 525, 586 |
| `crates/carrick-el1/src/personality/mm_portal/maintenance.rs` | 214–215, 222, 251, 253 |
| `crates/carrick-el1/src/personality/mm_portal/production.rs` | 67, 72, 162, 167, 172, 177, 180–181, 197, 212, 217, 262–265, 267–268, 276–283, 286, 289, 296, 300–302, 310, 313–314, 344–347, 351, 389, 394, 399, 408, 411, 418, 420, 438, 442–443, 449 |
| `crates/carrick-el1/src/personality/mm_portal/tests.rs` | 3020, 3068–3072, 3074, 3076–3077, 3144, 3304, 3354–3359, 3414 |
| `crates/carrick-el1/src/personality/native_ownership_tests.rs` | 11, 194–200, 212 |
| `crates/carrick-el1/src/personality/reservation_decoder_tests.rs` | 35–37, 41, 74, 76–77, 79–80, 111, 143–145, 150, 168–170, 190–192, 230 |
| `crates/carrick-el1/src/personality/sched.rs` | 3, 13–14, 16, 18, 23, 67, 74, 77 |
| `crates/carrick-el1/src/sched/aarch64_context.rs` | 3, 5–8, 10–13, 84, 105 |
| `crates/carrick-el1/src/sched/hw.rs` | 15, 111, 114 |
| `crates/carrick-el1/src/sched/object_wait.rs` | 11, 97, 150 |
| `crates/carrick-el1/src/sched/tests.rs` | 10, 76, 99, 139, 142–143, 159, 161–164, 166, 168–170, 186–191, 196, 207, 214–215, 331, 398, 428, 432, 434, 455, 457, 473, 484, 529, 558, 593–594, 596, 614–615, 669, 691–692, 720, 814, 835–838, 840, 933, 936, 959–960, 984, 995, 997, 1004–1005, 1011, 1013, 1047, 1049, 1062, 1167, 1205, 1312, 1392–1393, 1405–1407, 1436–1437, 1470–1471, 1545, 1548, 1560, 1575 |
| `crates/carrick-el1/src/sched.rs` | 4, 22, 24, 142, 180, 187, 207, 264, 307, 317, 319, 389, 472, 529, 547, 563, 712, 725 |
| `crates/carrick-el1-abi/src/descriptor_txn.rs` | 225, 266, 311 |
| `crates/carrick-el1-abi/src/lib.rs` | 380–384, 434, 645, 647, 649, 651, 653, 657, 1566–1567, 1569, 1604–1605, 1608–1612, 2218–2219, 2221, 3088–3095, 3939, 3942 |
| `crates/carrick-el1-abi/src/mm_portal.rs` | 10, 107, 109–110 |
| `crates/carrick-el1-abi/src/mm_portal_fork.rs` | 4–5 |
| `crates/carrick-el1-abi/src/mm_portal_grant.rs` | 2 |
| `crates/carrick-aarch64/src/descriptor_drain.rs` | 128–129, 230–231, 333, 399–401, 403, 405–406, 435, 440, 447, 468, 471, 489 |
| `crates/carrick-aarch64/src/engine.rs` | 94, 195–196, 198, 222, 225, 232–233, 238, 250, 256, 285, 569, 574–575, 697, 707, 709, 718, 722, 727, 742, 744, 901, 1590, 1645, 1991, 2030, 2099, 2106–2107, 2109, 2120, 2126, 2145–2146, 2167, 2170, 2173, 2176, 2181, 2184, 2189, 2195, 2199, 2203, 2214, 2219, 2224, 2243–2244, 2250, 2268, 2274, 2277, 2282, 2287, 2292, 2321, 2328, 2332–2336, 2344, 2351, 2513, 2543, 2545–2546, 2561–2562, 2571, 2574, 2582–2584, 2587, 2596, 2605, 2609, 2621, 2652, 3204, 3206, 3208–3209, 3213, 3216, 3226, 3228–3235, 3300–3301, 4655–4656, 4658–4659, 4661–4662, 4664–4665, 4744, 4757, 4952, 4955, 4968, 5366, 5435–5437, 5578, 5650, 5876–5877, 5882–5883, 5889, 5892, 5910, 5916, 5919, 5925, 5943, 5999, 6005–6006, 6067, 6069, 6085, 6091, 6098, 6107–6108, 6112, 6117, 6176–6177, 6181–6183, 6491, 6809, 7004, 7008, 7192, 7635, 7645, 8639, 8696, 8700, 8736–8737, 8740–8741, 8743, 8747, 8754, 8757, 8762, 8893, 8895, 8905, 8907, 8922, 8929–8930, 8940, 8943, 8980, 8984–8987, 8990–8992, 8994, 9304, 9316, 9385, 9461, 9464 |
| `crates/carrick-aarch64/src/esr.rs` | 6, 11, 30, 38, 44–45, 51–54, 61–63 |
| `crates/carrick-aarch64/src/fork.rs` | 4, 73, 84–86, 137, 185–187, 192, 359, 383 |
| `crates/carrick-aarch64/src/lib.rs` | 30, 48 |
| `crates/carrick-aarch64/src/mailbox.rs` | 22, 26, 80, 96, 407, 411 |
| `crates/carrick-aarch64/src/owed_kick.rs` | 82, 87, 100, 120, 123, 125, 132–133, 142, 162–163, 224, 234, 245, 249, 307, 323, 325, 330, 345, 348–349, 386–387, 396, 399, 402 |
| `crates/carrick-aarch64/src/user_transfer/prepared.rs` | 36–38 |
| `crates/carrick-aarch64/src/user_transfer/staging.rs` | 122–124, 126–133, 150–151, 156, 164, 172, 178, 180, 188, 191, 198, 200, 204–206, 210, 216, 221, 224, 229, 237, 241, 246–248, 251, 256, 267 |
| `crates/carrick-aarch64/src/user_transfer.rs` | 9, 77–79, 94, 109, 111–112, 117–118, 123, 313–315, 317–318, 320–321, 324–325, 328, 500–502, 569, 573, 601–603, 605, 611, 617, 620, 624, 804–808 |
| `crates/carrick-aarch64/src/vmm.rs` | 22, 54, 60, 78, 80, 93, 101, 267–270, 327, 329, 364, 1453, 1457, 1462, 1466, 1514–1515, 1532 |
| `crates/carrick-x86/src/arch_context.rs` | 47–49, 72–74 |
| `crates/carrick-x86/src/bringup.rs` | 327–328, 349, 352, 361 |
| `crates/carrick-x86/src/bringup_fns/poll_tests.rs` | 27 |
| `crates/carrick-x86/src/bringup_fns.rs` | 337, 368–369, 442–444, 494–496, 541–543, 576, 582–583, 1006–1008, 1029, 1032–1033, 1040–1042, 1057–1059, 1130–1131, 1136 |
| `crates/carrick-x86/src/cpl0_entry.rs` | 18, 31–34, 36–37, 39, 51–56, 60, 63, 65, 70, 74, 108, 114–115, 126–127, 137–138, 145, 153, 155, 161–164, 170–171, 177–178, 186–187, 193, 196–197 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 11–12, 15, 19, 171–172, 175 |
| `crates/carrick-x86/src/engine.rs` | 786, 793, 800, 814, 1056, 1059, 1679–1683, 1863, 1868, 1872, 1877–1878, 1898, 1906, 1913, 1919–1920, 2093–2097, 2124–2126, 2143–2147, 2238–2241, 2329–2332, 2339, 2348–2351, 2366–2369, 2386, 2393–2396, 2412, 2420, 2443–2446, 2480–2483, 2513–2516, 2530, 2532, 2541–2544, 2564, 2584, 2617–2620, 2628 |
| `crates/carrick-x86/src/fault.rs` | 86, 100, 114, 116–117, 137, 139–140, 164, 180, 182–183, 194, 196–197, 207, 209–210, 217, 219–220, 245, 247–248, 438–439, 457–459, 507, 525, 562, 583, 594, 598, 615, 639, 693, 695–696, 731, 733–734 |
| `crates/carrick-x86-cpl0/src/entry.rs` | 41–81, 83–89, 99, 102–103, 108, 113, 115, 147 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 24–68, 210 |

### C — context/TLS

| Pinned source path | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-el1/src/personality/ipc.rs` | 775, 1163 |
| `crates/carrick-el1/src/personality/lifecycle/tests.rs` | 136–137, 139–140, 352, 354–355, 358, 791, 794, 865–866 |
| `crates/carrick-el1/src/personality/lifecycle.rs` | 34, 209, 211, 490, 492, 495–496 |
| `crates/carrick-el1/src/sched/aarch64_context.rs` | 3, 5, 8, 10, 13, 17–20, 22–70, 74–75, 84, 88–100, 105, 110–121, 123–124 |
| `crates/carrick-el1/src/sched/hw.rs` | 15, 111, 114 |
| `crates/carrick-el1/src/sched/tests.rs` | 3, 123, 137–138, 145–149, 153–154, 164, 173–176, 178–179, 223, 335, 344, 1090, 1106, 1546, 1550–1554, 1556–1557, 1562–1566, 1568–1569 |
| `crates/carrick-el1/src/sched.rs` | 4, 22, 24, 651–654, 656–657, 712, 714–717, 720–721, 725, 727–730, 733–734 |
| `crates/carrick-el1-abi/src/lib.rs` | 513, 1865 |
| `crates/carrick-aarch64/src/engine.rs` | 94, 1062, 1107, 1123, 1127, 1129–1130, 1143–1145, 1147–1148, 1199, 1201, 1234–1235, 1248–1250, 1252–1253, 2236, 2352, 4667–4668, 4670–4671, 4673–4674, 4676–4677, 4679–4680, 4682–4683, 5134, 5148, 5156, 5164, 5209, 5211, 5215, 5218, 5224, 5227, 6027, 6031, 6034, 6036–6037, 6813, 6850, 6852, 6859, 7015, 7017, 7020–7021, 7033–7034, 7036, 7039–7040, 7063, 7085, 7107, 7109–7110, 7119–7120, 7131–7132, 7135–7136, 7500–7501, 7508–7510, 7512–7513, 7516, 7518, 7545, 7572–7573, 7585–7587, 7589–7590, 7634, 7653, 8947, 8950, 8953, 8956, 8959, 8962, 8971, 8974, 9125 |
| `crates/carrick-aarch64/src/lib.rs` | 48 |
| `crates/carrick-aarch64/src/owed_kick.rs` | 120, 124, 142, 144, 162, 176, 205, 219, 227, 237, 253, 257, 261, 265, 269, 273, 285, 289, 333, 337, 340, 376, 396, 425, 449, 505 |
| `crates/carrick-aarch64/src/vmm.rs` | 138, 142, 144, 157, 161, 169, 177, 179, 273–278, 288–289, 298, 1425, 1470, 1474, 1478, 1482, 1486, 1490, 1502, 1506 |
| `crates/carrick-x86/src/arch_context.rs` | 54–56, 67, 79–80, 83 |
| `crates/carrick-x86/src/bringup.rs` | 298, 356, 365 |
| `crates/carrick-x86/src/bringup_fns.rs` | 451–452, 458, 501–503, 546–547, 551, 580, 1013–1015, 1031, 1047–1049, 1060 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 23–24, 27–29, 34, 37–39, 45, 47, 73, 85, 88, 101, 167, 169, 183–185, 203, 209 |
| `crates/carrick-x86/src/engine.rs` | 828, 843, 1005, 1017, 1030, 1035, 1634, 1688–1690, 1740, 1841, 1962, 1966, 1971, 1975, 1997, 2001, 2102–2104, 2131–2133, 2152–2154 |
| `crates/carrick-x86/src/vmm.rs` | 533–534, 605 |
| `crates/carrick-x86-cpl0/src/entry.rs` | 41–81, 83–89 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 24–68, 104, 112, 114, 120, 138, 149, 151–152, 154–159, 199–203, 229 |

### D — descriptors/geometry

| Pinned source path | Line sites (inclusive runs) |
| --- | --- |
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
| `crates/carrick-el1/src/sched/hw.rs` | 118, 126–131, 134–135, 139, 145–152 |
| `crates/carrick-el1/src/sched/tests.rs` | 1080, 1082, 1164, 1206, 1310, 1438, 1472 |
| `crates/carrick-el1/src/sched.rs` | 27, 30, 359, 365, 682, 703, 738–740, 743–744 |
| `crates/carrick-el1-abi/src/descriptor_txn.rs` | 14, 17, 185, 187, 362, 369–370, 380, 418–419, 427 |
| `crates/carrick-el1-abi/src/internal_read.rs` | 6, 8 |
| `crates/carrick-el1-abi/src/lib.rs` | 126, 131, 150–151 |
| `crates/carrick-el1-abi/src/mm_portal.rs` | 19, 28, 30, 38–39 |
| `crates/carrick-el1-abi/src/mm_portal_executable.rs` | 98 |
| `crates/carrick-el1-abi/src/service_copy.rs` | 30, 54 |
| `crates/carrick-aarch64/src/descriptor_drain.rs` | 4–5, 132–133, 135, 145, 147, 166, 173, 175, 179, 205, 240–241, 243, 266, 268, 291–292, 294, 319, 325, 378–380, 386–387, 399, 406, 419, 427–428, 441, 452, 456, 525–526, 547–549 |
| `crates/carrick-aarch64/src/engine.rs` | 40–41, 67, 86, 117–118, 143, 146–147, 199, 260, 275, 287, 305, 307, 316, 318, 334, 340, 370, 582–583, 585, 599, 601, 622, 647, 676, 678, 732, 862, 864, 901–902, 908, 1133–1137, 1210–1211, 1216, 1218–1221, 1238–1242, 1267, 1286–1287, 1305, 1346, 1585, 1631, 1639, 1727, 1741–1743, 1758, 1763, 1768, 1773, 1776, 1790, 1813, 1830, 1947–1948, 2155, 2158, 2163, 2195, 2237, 2240, 2251–2253, 2257, 2365, 2371, 2421, 2426, 2907, 2912–2913, 2920, 2947, 2966, 2973, 3007, 3028, 3032, 3035, 3037, 3086, 3135–3136, 3146–3147, 3149, 3155, 3160, 3162, 3285, 3298, 3330, 3334, 3513, 3519, 3523, 3530, 3540, 3619, 3636, 3733, 3798, 3848, 3850–3852, 3968, 3983, 4012, 4412, 4628, 4633–4634, 4811–4812, 4899, 4905, 5059, 5074, 5087, 5106, 5325, 5366, 5376, 5443–5444, 5467, 5499, 5506, 5549–5550, 5600, 5650, 5670, 5678, 5731–5733, 5744, 5794–5796, 5800–5801, 5805–5807, 5844, 5917, 5925, 5942–5943, 6069–6070, 6084–6085, 6092–6093, 6101–6102, 6132–6133, 6176, 6178, 6181–6184, 6192, 6194, 6200–6201, 6339–6340, 6535, 6588, 6616, 6626, 6852, 6876, 7025–7029, 7064, 7086, 7123–7124, 7504–7506, 7538–7539, 7549–7550, 7574–7576, 7582–7583, 7673, 7763, 7796, 7809, 7821, 7907–7908, 7920, 7927, 7943, 7983–7985, 8010, 8012, 8016, 8027–8029, 8043, 8053, 8091–8093, 8118, 8120, 8124, 8135–8137, 8148–8150, 8153, 8156, 8162, 8167–8168, 8224, 8229–8230, 8319, 8351, 8356–8357, 8409, 8435, 8440–8441, 8457, 8462–8463, 8478, 8489, 8494–8495, 8507, 8524–8525, 8541, 8549, 8564–8565, 8578, 8586, 8598–8599, 8601–8602, 8610, 8615, 8639, 8659, 8663, 8813, 8821, 8845–8846, 8918, 8941, 8944, 8982, 9006, 9010–9011, 9060, 9138, 9158, 9170, 9218, 9221, 9225, 9402, 9431, 9438, 9443, 9449, 9458 |
| `crates/carrick-aarch64/src/fork.rs` | 34, 53, 103, 124, 194, 205, 221 |
| `crates/carrick-aarch64/src/owed_kick.rs` | 90, 144, 219 |
| `crates/carrick-aarch64/src/resume_invalidation.rs` | 111, 116, 123, 131–132 |
| `crates/carrick-aarch64/src/stage1_authority.rs` | 14, 17, 19, 38, 42, 63, 126, 159, 164, 242, 249, 410, 513, 548, 572, 574, 578, 604, 644, 649, 651, 656, 662, 751, 761, 783, 800, 844, 863, 885, 910, 1074, 1080, 1103, 1149, 1180, 1225, 1227–1228, 1232, 1248, 1264, 1267, 1271, 1275, 1289, 1330–1331, 1344–1345, 1598, 1634, 1639, 1651, 1655, 1675, 1690, 1702, 1714, 1740, 1749, 1758, 1767, 1777, 1786, 1796, 1806, 1817, 1833, 1848, 1858, 1868, 1881, 1889, 1902, 1920, 1934, 1944, 1947, 1949, 1951, 1962, 1982, 1998, 2013, 2018, 2021, 2035, 2218–2219, 2224, 2231–2232, 2239–2240, 2261–2262, 2299, 2302, 2305, 2370, 2384, 2435, 2452, 2457, 2467, 2502, 2582, 2622, 2661, 2769, 2826, 2841, 2861, 2876, 2890, 2920, 2937, 3094, 3109, 3139, 3172, 3206, 3278, 3320, 3367, 3545, 3562, 3598, 3621, 3653, 3657, 3678, 3698, 3705, 3732, 3762, 3776, 3786, 3796, 3798, 3800–3801, 3839, 3844, 3848, 3856, 3893, 3904, 3915, 3917, 3948–3949, 3958, 4004, 4013, 4029, 4072 |
| `crates/carrick-aarch64/src/user_transfer/prepared.rs` | 78, 98, 104, 125, 132, 138, 189, 204, 210, 220, 236 |
| `crates/carrick-aarch64/src/user_transfer/staging.rs` | 108, 118, 139, 147, 152, 183, 189, 194, 272, 280 |
| `crates/carrick-aarch64/src/user_transfer.rs` | 131, 189, 195, 252, 256–257, 262–263, 268, 272, 288, 297, 321, 335, 515, 524, 543, 594–595, 735, 792 |
| `crates/carrick-aarch64/src/vmm.rs` | 29, 37, 148–152, 221, 223, 452, 459–461, 471–472, 477, 489, 568, 722, 730, 950, 1060, 1077, 1090, 1394 |
| `crates/carrick-x86/src/arch_context.rs` | 51, 76 |
| `crates/carrick-x86/src/bringup_fns.rs` | 447, 498, 521, 1010, 1044 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 109, 124 |
| `crates/carrick-x86/src/engine.rs` | 356, 361, 1578, 1685, 1880, 1922, 2099, 2128, 2149 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 199–201 |

### L — TLB/coherence

| Pinned source path | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-el1/src/cow.rs` | 31, 37, 187, 194, 402, 491, 572, 622, 670, 717, 934, 1092 |
| `crates/carrick-el1/src/fault.rs` | 138, 143, 145, 147, 175, 238, 290, 297, 385, 572 |
| `crates/carrick-el1/src/file.rs` | 174–181, 203–210 |
| `crates/carrick-el1/src/memory.rs` | 352, 384 |
| `crates/carrick-el1/src/personality/mm_portal/fork.rs` | 505, 579 |
| `crates/carrick-el1/src/personality/mm_portal/production.rs` | 384 |
| `crates/carrick-el1/src/personality/mm_portal/tests.rs` | 1354, 2418, 2644, 4297 |
| `crates/carrick-el1/src/sched/aarch64_context.rs` | 110–121 |
| `crates/carrick-el1/src/sched/hw.rs` | 126–131, 134–135, 139, 145–152, 159–161, 163–164, 166–168, 170, 173–187, 189, 192–199, 216–221, 227–228, 230–231 |
| `crates/carrick-el1/src/sched/tests.rs` | 1572 |
| `crates/carrick-el1/src/sched.rs` | 30, 359, 743 |
| `crates/carrick-aarch64/src/descriptor_drain.rs` | 171, 195, 208 |
| `crates/carrick-aarch64/src/engine.rs` | 489, 805, 810, 921, 967, 1056, 1399, 1523, 1718, 2406–2407, 2412, 2417, 2420, 2424–2426, 2435, 2437–2438, 2443, 2445, 2448–2449, 2457–2458, 2461, 2467–2468, 2477, 2486–2487, 2675, 2677–2678, 2683–2684, 2687, 2692, 2694, 2696, 4607, 4737, 4746, 4761, 4782, 5288, 7159–7162, 7431, 9272 |
| `crates/carrick-aarch64/src/lib.rs` | 34, 37 |
| `crates/carrick-aarch64/src/stage1_authority.rs` | 322, 601, 624, 1014, 1672, 1676, 2825, 2840, 2875, 3093, 3108, 3595, 3675, 3731, 3755, 3759, 3836 |
| `crates/carrick-aarch64/src/user_transfer/staging.rs` | 135 |
| `crates/carrick-aarch64/src/user_transfer.rs` | 212, 650, 655 |
| `crates/carrick-aarch64/src/vmm.rs` | 424 |

### I — interrupt/clock

| Pinned source path | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-el1/src/alloc.rs` | 11, 16, 52, 62, 70, 76, 232, 249, 260, 278, 289, 296, 302, 314, 322, 327, 337, 341 |
| `crates/carrick-el1/src/personality/ipc.rs` | 988, 1122 |
| `crates/carrick-el1/src/personality/mm_portal/maintenance.rs` | 217 |
| `crates/carrick-el1/src/personality/mm_portal/production.rs` | 69, 164, 316, 396 |
| `crates/carrick-el1/src/sched/hw.rs` | 159–161, 163–164, 166–168, 170, 173–187, 189, 192–199, 203–204, 208, 210, 213, 216–221, 225, 227–228, 230–231, 234–235, 237–240, 243–248, 254, 260–261, 264–269, 273, 275, 279, 282–286 |
| `crates/carrick-el1/src/sched/object_wait.rs` | 35, 38, 40, 187 |
| `crates/carrick-el1/src/sched/tests.rs` | 3, 359, 366, 384, 509, 511, 538–539, 541, 546, 608, 631, 642, 948, 1497, 1524, 1532–1533, 1574, 1580 |
| `crates/carrick-el1/src/sched.rs` | 3–4, 38, 41, 43, 46, 50, 63–67, 168, 394, 432, 444–445, 448, 451–452, 456, 461, 464, 497, 628–630, 635, 674, 678, 699, 701, 759–760, 763, 765, 767, 770, 772, 787–788 |
| `crates/carrick-el1-abi/src/ipc.rs` | 688–689 |
| `crates/carrick-el1-abi/src/lib.rs` | 301, 304, 306, 310, 510–512 |
| `crates/carrick-x86/src/bringup.rs` | 83, 100–102 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 10, 18–19, 35, 170 |
| `crates/carrick-x86/src/interrupts.rs` | 50–54, 57–63, 68–70, 73–75 |
| `crates/carrick-x86-cpl0/src/entry.rs` | 174–177, 179–183 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 24–68, 83–87, 89–93, 95–100, 119, 144–145, 147–149, 151–152, 154–159 |

### H — host transport

| Pinned source path | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-el1/src/entry.rs` | 109–115 |
| `crates/carrick-el1/src/fault.rs` | 566 |
| `crates/carrick-el1/src/personality/mm_portal/production.rs` | 154 |
| `crates/carrick-el1/src/sched/hw.rs` | 301–304 |
| `crates/carrick-el1-abi/src/lib.rs` | 1558, 1563, 1580–1583, 1590, 1599, 1604, 1606, 1615–1620, 3169, 3171–3175, 3196, 3199, 3206, 3208 |
| `crates/carrick-aarch64/src/descriptor_drain.rs` | 234 |
| `crates/carrick-aarch64/src/engine.rs` | 205, 250, 577, 2120, 2243, 2596, 3232, 3303, 5582–5583, 7163, 8994 |
| `crates/carrick-aarch64/src/owed_kick.rs` | 330, 399 |
| `crates/carrick-aarch64/src/vmm.rs` | 108 |
| `crates/carrick-x86/src/bringup.rs` | 247 |
| `crates/carrick-x86/src/cpl0_entry.rs` | 6–11 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 58–60 |
| `crates/carrick-x86/src/engine.rs` | 2460, 2496 |
| `crates/carrick-x86/src/fault.rs` | 6–7, 126, 620, 679, 717, 721, 741, 743 |
| `crates/carrick-x86/src/lib.rs` | 37 |
| `crates/carrick-x86-cpl0/src/entry.rs` | 99, 102–103, 110, 114, 129, 133, 150, 154, 163, 167 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 83–87, 89–93, 95–100, 143–145, 147–148, 215 |

### U — user copy/fixup

| Pinned source path | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-el1/src/fault.rs` | 2144 |
| `crates/carrick-el1/src/file.rs` | 23, 31, 34–58, 84, 92, 95–119, 138, 140, 143, 147, 150–151, 155, 161, 164–165, 174–181, 194, 203–210, 238, 243, 245, 249, 253, 258 |
| `crates/carrick-el1/src/personality/dispatch.rs` | 105, 137, 168, 195, 218, 254, 293, 338, 352, 406, 548, 649, 665, 681, 699, 717, 763, 776, 853, 1015 |
| `crates/carrick-el1/src/personality/file.rs` | 6, 8, 104, 122, 141, 159, 195–196, 212 |
| `crates/carrick-el1/src/personality/inotify.rs` | 14, 39, 52, 59, 177, 202, 229, 254, 280–281, 285, 310–311, 315 |
| `crates/carrick-el1/src/personality/ipc/epoll.rs` | 37, 82, 100, 111, 304 |
| `crates/carrick-el1/src/personality/ipc.rs` | 38, 173, 252, 364, 396, 557, 573, 615, 638, 689, 700, 704, 713, 721, 769, 1115, 1141, 2134, 2189 |
| `crates/carrick-el1/src/personality/lifecycle/tests.rs` | 7, 178, 269 |
| `crates/carrick-el1/src/personality/lifecycle.rs` | 26, 123, 208, 390, 518 |
| `crates/carrick-el1/src/personality/mm_portal/edit_wait.rs` | 5, 14 |
| `crates/carrick-el1/src/personality/mm_portal/tests.rs` | 3019, 3084, 3303, 3365 |
| `crates/carrick-el1/src/personality/sched.rs` | 21, 25, 66 |
| `crates/carrick-el1/src/sched/hw.rs` | 8, 19, 21, 24–25, 28, 34–51, 65–66, 69, 75–92 |
| `crates/carrick-el1/src/sched/object_wait.rs` | 9, 61 |
| `crates/carrick-el1/src/sched/tests.rs` | 92, 243, 252, 255, 552, 602, 649, 827, 942, 990, 1057, 1415, 1518, 1600 |
| `crates/carrick-el1/src/sched.rs` | 54, 107, 124, 645 |
| `crates/carrick-el1-abi/src/lib.rs` | 706, 769, 3228 |
| `crates/carrick-aarch64/src/engine.rs` | 5801, 5809, 6102, 7908, 7983–7985, 8010, 8012, 8016, 8027–8029, 8091–8093, 8118, 8120, 8124, 8135–8137 |
| `crates/carrick-aarch64/src/stage1_authority.rs` | 2262, 2300 |
| `crates/carrick-x86/src/bringup_fns.rs` | 96, 157, 359, 533 |

### B — boot/control layout

| Pinned source path | Line sites (inclusive runs) |
| --- | --- |
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
| `crates/carrick-el1/src/sched/hw.rs` | 118 |
| `crates/carrick-el1/src/sched/tests.rs` | 741, 751, 759, 1571 |
| `crates/carrick-el1/src/sched.rs` | 27, 365, 382, 738 |
| `crates/carrick-el1-abi/src/cow_grants.rs` | 11–13, 16, 18–19, 26, 45, 54 |
| `crates/carrick-el1-abi/src/delegated_notification.rs` | 2, 25–26, 274, 285, 292 |
| `crates/carrick-el1-abi/src/descriptor_txn.rs` | 22, 175–176, 183–184, 186, 188–190, 194, 197–198, 202, 204–205, 210–212, 243, 259–261, 282, 296, 313–314, 319, 321, 324, 327, 334, 342 |
| `crates/carrick-el1-abi/src/internal_read.rs` | 30, 62 |
| `crates/carrick-el1-abi/src/ipc/tests.rs` | 267 |
| `crates/carrick-el1-abi/src/lib.rs` | 59, 62, 65, 68, 71, 74, 77, 80, 86, 89, 92, 98–99, 115–116, 120–121, 168, 171, 174, 177, 180, 183, 217, 220, 223, 230, 237, 243, 246, 250–251, 253–256, 259, 262, 265, 268, 271, 274, 278, 281, 284, 290, 293, 296, 321, 334–335, 337, 340, 344, 346–347, 352, 366–369, 371–375, 389, 396–401, 403–407, 411–417, 419, 421, 478, 587, 601, 736, 739, 1147, 1149, 1455, 1459, 1462, 1465, 1828, 1845, 1848, 1851, 1854, 1857, 1860, 1871, 1874, 1877, 1879–1880, 1883–1886, 1888, 1890, 1892–1893, 1896, 1900–1901, 1904, 1908–1909, 1912, 1916–1917, 1920, 1922–1928, 2056, 2058, 2072, 2079, 2090, 2104, 2117, 2124, 2133, 2141, 2150, 2163, 2178, 2188, 2201, 2212, 2295, 2311, 2325, 2343, 2359, 2383, 2407, 2430, 2440, 2460, 2486, 2507, 2519, 2530, 3081–3083, 3213–3218, 3252, 3254, 3331–3332, 3338, 3351, 3360, 3382, 3515, 3520, 3524, 3608, 3616, 3746, 3966, 3979, 4012, 4024, 4075, 4082, 4106, 4145, 4188, 4199 |
| `crates/carrick-el1-abi/src/mm_portal.rs` | 111–112, 149–150, 204, 206 |
| `crates/carrick-el1-abi/src/reservations.rs` | 11–12 |
| `crates/carrick-el1-abi/src/service_copy.rs` | 4–9, 14–15, 18, 37, 86, 148–150, 152, 154–155, 171, 185, 189, 191, 195, 207–208, 211, 213, 219, 226, 229 |
| `crates/carrick-aarch64/src/descriptor_drain.rs` | 482, 485, 495–496 |
| `crates/carrick-aarch64/src/engine.rs` | 190, 1202, 1211–1212, 1219, 1221, 1223, 3367, 3537, 3629, 5352, 5657, 7016, 7028–7029, 7031, 8646, 8785, 9053, 9347, 9435, 9438 |
| `crates/carrick-aarch64/src/stage1_authority.rs` | 3357, 3810–3811, 3813, 3975–3976, 3978 |
| `crates/carrick-aarch64/src/user_transfer/staging.rs` | 103 |
| `crates/carrick-aarch64/src/user_transfer.rs` | 306 |
| `crates/carrick-x86/src/bringup_fns.rs` | 339, 342, 345–346, 369, 398, 422–423, 556–557 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 122 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 106, 111 |

### W — ISA binding/cfg

| Pinned source path | Line sites (inclusive runs) |
| --- | --- |
| `crates/carrick-el1/src/alloc.rs` | 13 |
| `crates/carrick-el1/src/entry.rs` | 109 |
| `crates/carrick-el1/src/fault.rs` | 118, 138, 143, 145, 147, 174–175, 237–238, 289–290, 296–297, 384–385, 566 |
| `crates/carrick-el1/src/file.rs` | 29, 34, 62, 90, 95, 123, 174, 203 |
| `crates/carrick-el1/src/lib.rs` | 8, 10, 12, 14, 16, 18, 21, 23, 25, 27 |
| `crates/carrick-el1/src/memory.rs` | 351–352, 383–384 |
| `crates/carrick-el1/src/personality/dispatch.rs` | 104, 136, 167, 195, 217, 253, 292, 338, 352, 548, 649, 665, 699, 776 |
| `crates/carrick-el1/src/personality/ipc/epoll.rs` | 37, 82, 100, 111, 304 |
| `crates/carrick-el1/src/personality/ipc.rs` | 38, 173, 252, 364, 396, 557, 573, 615, 638, 689, 700, 704, 713, 721 |
| `crates/carrick-el1/src/personality/lifecycle.rs` | 26, 123, 208, 390, 518 |
| `crates/carrick-el1/src/personality/mm_portal/edit_wait.rs` | 5, 14 |
| `crates/carrick-el1/src/personality/mm_portal/fork.rs` | 505, 579 |
| `crates/carrick-el1/src/personality/mm_portal/production.rs` | 121, 154, 208, 357, 384, 425 |
| `crates/carrick-el1/src/personality/mm_portal/tests.rs` | 3019 |
| `crates/carrick-el1/src/personality/mod.rs` | 7, 9, 11, 13, 15, 17, 19 |
| `crates/carrick-el1/src/personality/sched.rs` | 21, 25, 66 |
| `crates/carrick-el1/src/sched/aarch64_context.rs` | 16–17, 72, 83, 88, 104, 110 |
| `crates/carrick-el1/src/sched/hw.rs` | 7, 34, 75, 107, 110, 126, 145, 159, 166, 175, 184, 193, 208, 216, 227, 237, 243, 248, 262, 264, 271, 280, 282, 288, 301 |
| `crates/carrick-el1/src/sched/object_wait.rs` | 9, 28, 61 |
| `crates/carrick-el1/src/sched.rs` | 20, 107, 124, 644, 711 |
| `crates/carrick-aarch64/src/engine.rs` | 36, 94, 185, 195–196, 198, 205, 213, 222–223, 230–234, 340, 379, 492, 516, 522, 535, 537–539, 551, 563, 569, 640, 647, 653, 663, 665, 691–692, 695, 697, 727, 756, 809, 822, 874, 901, 944, 948, 966, 991, 1013–1014, 1162, 1174–1175, 1299, 1590, 1645, 1991, 2030, 2099, 2102–2107, 2109–2111, 2141–2146, 2167, 2170, 2173, 2176, 2181, 2184, 2189, 2195, 2199, 2203, 2214, 2219, 2224, 2251–2253, 2268, 2274, 2277, 2282, 2287, 2292, 2329, 2332–2336, 2351, 2574, 2583–2584, 2621, 3277, 3300–3301, 3309, 3609, 4642, 4654–4655, 4658, 4661, 4664, 4689, 4744, 4757, 4952, 4955, 5009, 5132, 5146, 5154, 5162, 5170, 5182, 5194, 5198, 5231, 5366, 5578, 5650, 5876–5877, 5882–5883, 5889, 5892, 5999, 6005–6006, 6069, 6176–6177, 6181–6183, 6491, 6809, 6908, 7216, 8628, 8639, 8916, 8921–8922, 8929–8930, 8940, 8943, 8984–8987, 8990–8992, 9034, 9132–9133, 9169, 9461–9462 |
| `crates/carrick-aarch64/src/lib.rs` | 30, 43–44, 48 |
| `crates/carrick-aarch64/src/owed_kick.rs` | 41, 43, 71, 87, 107, 116, 120, 123, 141–142, 145, 147, 164, 223–224, 226–229, 234, 236–239, 245, 249, 387, 396 |
| `crates/carrick-aarch64/src/user_transfer/prepared.rs` | 26, 29, 52, 54 |
| `crates/carrick-aarch64/src/user_transfer/staging.rs` | 7–8, 60–61, 88 |
| `crates/carrick-aarch64/src/user_transfer.rs` | 6, 25–26, 265–266, 274–275, 294–295, 436, 438, 567, 584–585 |
| `crates/carrick-aarch64/src/vmm.rs` | 25, 243, 267–270, 327, 329, 555–556, 1448, 1452–1453, 1457, 1462, 1466, 1532 |
| `crates/carrick-x86/src/cpl0_entry.rs` | 3, 61, 63–78 |
| `crates/carrick-x86/src/cpl0_scheduler.rs` | 116, 124 |
| `crates/carrick-x86/src/engine.rs` | 31, 761, 763–780, 786, 793, 800, 802, 806, 814, 816, 820 |
| `crates/carrick-x86/src/interrupts.rs` | 37, 50, 59, 61, 69 |
| `crates/carrick-x86/src/vdso.rs` | 70, 78 |
| `crates/carrick-x86-cpl0/src/entry.rs` | 41, 102, 174 |
| `crates/carrick-x86-cpl0/src/progress.rs` | 24, 83, 90, 95, 144, 149, 199 |

### Whole native items and existing substrate projections

These item spans supplement the direct line list; they include arithmetic,
constant encodings and failure branches inside the native boundary, even
without an ISA token on each physical line. They are not additional
distinct-line credit in the lexical totals.

| Concern | Entire source span at S |
| --- | --- |
| T/C: complete native frame/context leaves | `crates/carrick-aarch64/src/esr.rs:1–65` |
| T/C: complete native frame/context leaves | `crates/carrick-el1/src/sched/aarch64_context.rs:1–126` |
| T/C: complete native frame/context leaves | `crates/carrick-x86/src/arch_context.rs:1–86` |
| T/C: complete native frame/context leaves | `crates/carrick-x86/src/cpl0_entry.rs:1–203` |
| T/C: complete native frame/context leaves | `crates/carrick-x86/src/cpl0_scheduler.rs:1–222` |
| C/B: complete host-native snapshot/register fields | `crates/carrick-aarch64/src/vmm.rs:138–181` |
| L: complete instruction-coherence leaf | `crates/carrick-aarch64/src/icache.rs:1–19` |
| I/B: complete interrupt gate/APIC leaf | `crates/carrick-x86/src/interrupts.rs:1–113` |
| B/H/T: image entry and native instruction closure | `crates/carrick-el1/src/entry.rs:1–120` |
| B/H/T: image entry and native instruction closure | `crates/carrick-x86-cpl0/src/entry.rs:1–183` |
| B/H/T: image entry and native instruction closure | `crates/carrick-x86-cpl0/src/progress.rs:1–230` |
| U: complete guarded copy/AT permission items | `crates/carrick-el1/src/file.rs:23–132`, `crates/carrick-el1/src/file.rs:164–222`; fixup user-word reads `crates/carrick-el1/src/sched/hw.rs:22–118` |
| D: current complete owner geometry interfaces and implementations | `crates/carrick-mmu-core/src/owner_mmu.rs:1–159`; x86 projection `crates/carrick-mmu-core/src/x86/owner_mmu.rs:1` |
| D: existing ISA descriptor modules | `crates/carrick-mmu-core/src/aarch64.rs:1`, `crates/carrick-mmu-core/src/aarch64/descriptor_txn.rs:1`, `crates/carrick-mmu-core/src/aarch64/descriptor_txn/copy_window.rs:1`, `crates/carrick-mmu-core/src/aarch64/descriptor_txn/guest_cow.rs:1`, `crates/carrick-mmu-core/src/aarch64/owner_fork.rs:1`, `crates/carrick-mmu-core/src/x86/mod.rs:1`, `crates/carrick-mmu-core/src/x86/descriptor_txn.rs:1`, `crates/carrick-mmu-core/src/x86/descriptor_txn/tests.rs:1` |
| C/I: ARM-shaped data outside the three-crate denominator | `crates/carrick-sched-core/src/lib.rs:382–430`, `crates/carrick-sched-core/src/lib.rs:573`, `crates/carrick-sched-core/src/lib.rs:699`, `crates/carrick-sched-core/src/lib.rs:817`, `crates/carrick-sched-core/src/lib.rs:892–899`; root words in `crates/carrick-sched-core/src/spaces.rs:1` |
| B: host-emitted ARM vectors and boot | `crates/carrick-mem/src/memory.rs:1`; ISA frame/vector constants are outside S's three-crate metric, remain a native provider, and participate in mailbox compile assertions (`crates/carrick-aarch64/src/mailbox.rs:37`) |

### Reproduce the counts and site inventory

Run from any worktree containing S. This is a temporary **audit recipe**, not
a shipped Python capability. It reads tracked sources with `git show`, makes
no checkout edits, and prints file/line sets. The regex inventory deliberately
includes type/cfg/fixture binding sites as well as instructions; whole native
item spans above complete the routine-level classification. No lexical
scanner establishes that all indirect hardware semantics have been eliminated;
compile fences and final image disassembly remain mandatory.

```python
import re
import subprocess
from collections import defaultdict

ref = "0f476ce7afb11609c8261cd1954bbe08263548b3"
paths = subprocess.check_output(
    ["git", "ls-tree", "-r", "--name-only", ref, "crates"], text=True
).splitlines()
names = "el1 el1-abi aarch64 core core-abi personality-linux sched-core mmu-core guest-arch x86 x86-cpl0 el1-image".split()
sources = {
    p: subprocess.check_output(["git", "show", ref + ":" + p], text=True).splitlines()
    for p in paths if p.endswith(".rs")
    and any(p.startswith("crates/carrick-" + n + "/src/") for n in names)
}
for name in names:
    prefix = "crates/carrick-" + name + "/src/"
    count = sum(bool(line.strip()) and not line.lstrip().startswith("//")
                for p, lines in sources.items() if p.startswith(prefix)
                for line in lines)
    print(name, count)

patterns = {
    'T — trap/frame': '\\b(?:get|set|read|write)_(?:reg|sys_reg|esr|elr|spsr|far|pc)\\b|\\b(?:TrapFrame|NativeFrame|Aarch64SyscallFrame|Aarch64Exit|EntryEvent|ESR|ELR|SPSR|FAR|SVC_LEN|DESCRIPTOR_DRAIN_ESR|MM_PORTAL_[A-Z_]*ESR)\\b|\\b(?:esr|elr|spsr|far)\\b|\\.(?:x|gpr)\\b|\\b(?:x|gpr):|Reg::(?:X|PC|CPSR)|\\b(?:rip|rflags|rax|rcx|r11|rsp)\\b',
    'C — context/TLS': '\\b(?:get|set)_(?:fpcr|fpsr|vreg|guest_sp)\\b|\\b(?:ThreadCtx|Aarch64VcpuSnapshot|NativeContext|XsaveArea|ContextBinding|FPCR|FPSR|TPIDR[A-Z_]*|SP_EL0|CONTEXTIDR_EL1|Xsave|XSTATE_MASK|XSAVE_BYTES)\\b|\\b(?:sp_el0|tpidr_el0|tpidrro_el0|contextidr_el1|fpsr|fpcr|pstate|fs_base|gs_base)\\b|\\b(?:xsave|xrstor|swapgs|eret|iretq)\\b|carrick_el1_fpsimd',
    'D — descriptors/geometry': 'carrick_mmu_core::aarch64|\\baarch64::|\\b(?:PageTableManager|PageTableError|LeafAccess|El1PrivateLeafState|TTBR_BADDR_MASK|TTBR_BADDR|PTE_[A-Z_]*|SubstrateGpa|PrimaryTableWords|HardwareDescriptorTxnApplier|HardwareAnonymous[A-Za-z]+Editor|Aarch64CowMmu|Aarch64Mmu|X86Mmu)\\b|\\b(?:ttbr\\w*|asid|cr3|pcid)\\b|\\b(?:sctlr|tcr|mair|ttbr)[A-Za-z_0-9]*\\b|\\b(?:indices|table_window|terminal_descriptor|classify_stage1_range|retired_page|descriptor_word|descriptor_bits)\\b',
    'L — TLB/coherence': '\\b(?:tlbi|dsb|dmb|isb|invlpg|mfence|sfence|lfence)\\b|\\b(?:icache|invalidate_asid|invalidate_tlb|broadcast_asid|flush_tlb|invalidate_page|publish_executable|sync_to_host)\\b|Reg::(?:DC|IC)|resume_invalidation',
    'I — interrupt/clock': '\\b(?:daif\\w*|cntv\\w*|cntfrq\\w*|cntp\\w*|mpidr\\w*|sgi\\w*|intid|wfi|cli|sti|hlt|rdtsc|rdmsr|wrmsr)\\b|\\b(?:GIC_[A-Z_]+|ICC_[A-Z0-9_]+|APIC_[A-Z_]+|MPIDR_EL1|CNT[A-Z0-9_]+|DAIF|IrqGuard|InterruptFrame)\\b|s3_0_c12|own_sgi_target|send_sgi|ack_irq|end_irq|wait_for_interrupt|read_current_sp|disable_irq_save|restore_irq',
    'H — host transport': '\\bhvc\\b|\\b(?:HVC_[A-Z_]+|Hvc[A-Za-z_]*|SVC_HVC_[A-Z_]+|[A-Z_]*PORT|[A-Z_]*DOORBELL[A-Z_]*)\\b|\\bdoorbell\\b|\\bout dx|mailbox_capture|run_el1_service_call|EL1_HYPERCALL|MaintenanceDone',
    'U — user copy/fixup': '\\b(?:ldtr\\w*|sttr\\w*|par_el1|HardwareValidator|HardwareUserWord|MemoryValidator|UserWord|fixup_pc|copy_to_user_guarded|copy_from_user_guarded|terminal_descriptor_permits_el0|readable_bytes|writable_bytes)\\b|\\bat s1e|\\bfixup\\b',
    'B — boot/control layout': '\\b(?:EL1_[A-Z_]*(?:BASE|SIZE|OFFSET|ADDR)|KERNEL_[A-Z_]*(?:BASE|SIZE)|ImageHeader|IMAGE_HEADER_[A-Z_]+|ImageAbiError|CARRICK_EL1_ABI_HASH|EL0_TRAMPOLINE[A-Z_]*|TPIDR_EL1|VBAR_EL1|SCTLR_EL1|TCR_EL1|MAIR_EL1)\\b|Reg::(?:VBAR|SCTLR|TCR|MAIR)|\\b(?:boot|install_root|set_translation|install_context)\\b',
    'W — ISA binding/cfg': 'target_arch\\s*=\\s*"(?:aarch64|x86_64)"|\\b(?:Aarch64Vmm|Aarch64Vcpu|Aarch64EngineCore|Aarch64TaskEngineState|Aarch64TaskRuntimeProjection|Aarch64ResidentTaskMetadata|Aarch64Reg|SysReg|Reg|HardwareCpu|ThreadCpu|X86Register)\\b|use carrick_aarch64|crate::esr|pub mod esr|asm!|global_asm!',
}
compiled = {key: re.compile(value) for key, value in patterns.items()}
scopes = "el1 el1-abi aarch64 x86 x86-cpl0 sched-core guest-arch".split()
entries = {key: defaultdict(set) for key in patterns}
unique = defaultdict(set)
for path, lines in sources.items():
    if not any(path.startswith("crates/carrick-" + n + "/src/") for n in scopes):
        continue
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("//"):
            continue
        for key, pattern in compiled.items():
            if pattern.search(line):
                entries[key][path].add(number)
                unique[path].add(number)
    i = 0
    while i < len(lines):
        if not lines[i].lstrip().startswith("//") and re.search(r"(?:global_)?asm!\s*\(", lines[i]):
            end = i
            while end < len(lines) - 1 and not re.search(r"\)\s*;", lines[end]):
                end += 1
            invocation = "\n".join(lines[i:end + 1])
            groups = [k for k, rx in compiled.items()
                      if k != "W — ISA binding/cfg" and rx.search(invocation)]
            if not groups:
                groups = ["T — trap/frame"]
            for number in range(i + 1, end + 2):
                if lines[number - 1].strip() and not lines[number - 1].lstrip().startswith("//"):
                    for key in groups:
                        entries[key][path].add(number)
                    unique[path].add(number)
            i = end
        i += 1
for key, files in entries.items():
    for path, numbers in sorted(files.items()):
        print(key, path, ",".join(map(str, sorted(numbers))))
for name in scopes:
    prefix = "crates/carrick-" + name + "/src/"
    print("distinct-sites", name, sum(len(ns) for p, ns in unique.items() if p.startswith(prefix)))
```
