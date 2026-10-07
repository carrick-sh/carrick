# Personality-neutral core with Linux and NT clients

Status: approved by the owner 2026-10-05 (see Owner decisions). Amended
2026-10-06: the NT personality lives in a separate repository (see
[Repository boundary](#repository-boundary-nt-lives-out-of-tree)).

Design proposal, 2026-10-04. Documentation only; no implementation, runtime
acceptance, or compatibility claim. Inspected Carrick `0250e7f2a834e8bd1b080780bd0f5b8e67bc30ad`.

## Direction and constraints

Continue Carrick by extracting its existing owners into a personality-neutral
in-guest core. Linux is the first client; Windows NT is the second. Support
AArch64 and x86_64 guest architectures on matching hardware, with host adapters
for macOS/HVF, Linux/KVM, Windows/WHP, FreeBSD/bhyve and NetBSD/NVMM. This is
an expansion of the [EL1 design](2026-09-24-el1-kernel.md)'s Linux-only planning
scope, not a restart or a claim that those combinations already work.
“Guest kernel” means EL1 on AArch64 and CPL0 on x86_64.

Preserve the [N0–N4 ownership migration](../plans/2026-10-02-el1-native-ownership.md):
one authoritative incarnation per object, elastic bulk frame grants/returns,
host-scheduled vCPU threads and host-native external I/O. A guest wait yields
execution capacity. No host Linux or NT process per guest process, fixed guest
RAM pool, second semantic implementation, or per-operation fallback after
ownership admission. Carrick remains experimental, with partial Linux
coverage and no adversarial security review; this design is not a hardened
trust-boundary claim.

A **core object** implements identity, lifetime, storage, synchronization or
translation. A **personality object** implements the observable OS contract.
Portability across hosts and `no_std` do not imply personality neutrality.
Likewise, ISA-specific code need not be Linux-specific. Use three independent
choices: `GuestIsa`, `PersonalityKind` and `HostPlatform`; do not infer one from
another or reuse OCI `linux/amd64` as an NT process specification.

The initial product chooses one personality per guest process at creation,
immutable through exec. Separate carriers per personality are the first
supported topology. The core must not use a global current-personality value:
VM-free tests host both clients concurrently to expose scope errors. Mixed
Linux/NT processes in one carrier, cross-personality handle passing and
personality-changing exec are later owner decisions.

## Evidence and corrections to the inputs

Read alongside [the boundary rule](../../personality-boundary.md),
[HAL](../../hal.md), [crate map](../../../crates/README.md) and
[conformance contracts](../../conformance-contracts.md). The fetched censuses
are review inputs, not accepted inventories:

- PR 15: `0a43bf9569e4f8bbc83371d413076758ca3ff22f`,
  `docs/personality-census.md`.
- PR 13: `5d9a7a0a6e9465eda045dc3fd76e33489ad4e462`,
  `docs/x86-syscall-parity.md`.

`origin` here is a local mirror without `pull/*` refs; the requested fetch
failed there and succeeded against `github` (the same upstream project).
Neither branch was merged. The following corrections come from reading the
current implementation, not trusting the census totals.

| Input claim | Checked source and consequence |
| --- | --- |
| The boundary gate covers only scheduler and MMU | `carrick-conformance-contract/src/personality_boundary.rs::DEFAULT_SUBSTRATE_ALLOWLIST` contains **seven** crates: sched, mmu, signal, timer, fd, pipe and el1. `audit_el1_modules` excludes `personality/`, `lib.rs`, `entry.rs`, `fault.rs`, `memory.rs`; the EL1 dependency walk specially permits `carrick-el1-abi`. Passing means the implemented syntactic rule passed, not that this mixed ABI is neutral. |
| `carrick-signal-core` is SUBSTRATE despite 31 Linux items | `src/policy.rs` defines `Signal::KILL = 9`, `CHLD = 17`, uncatchable STOP/KILL, sigaction and exec reset policy. It is Linux personality code. Its manifest currently has no `carrick-abi` dependency: the older spec's dependency claim is stale, and absence of that dependency is insufficient. |
| `carrick-timer-core` has zero Linux items | `src/itimer.rs` has three fixed REAL/VIRTUAL/PROF slots, process-global `SLOTS`, BSD timer-ident/arm flags; `src/posix.rs::PosixTimerSpec` carries `signum` and `si_value`, and `OVERRUN_MAX` encodes POSIX saturation. Mixed timing mechanism, Linux/POSIX policy and host-adapter machinery remain despite the empty dependency section. |
| fd and pipe cores are neutral | `carrick-fd-core/src/lib.rs` contains `Fd`, `dup2`, `dup3`, `fork`, `exec`, mutable Linux status-flag policy and CLOEXEC handling. `carrick-pipe-core/src/lib.rs` contains `EventFd`, `EVENTFD_MAX` and `Step::broken_pipe_signal`. Keep the fd authority as a Linux client; extract only genuinely shared storage and byte-stream mechanics. |
| Scheduler has zero personality items | `carrick-sched-core/src/lib.rs::ThreadIdentity` carries a Linux tid and `file_table`, plus lifecycle/control bindings. Its `ThreadCtx` is AArch64-shaped. Preserve its proven claim/wake algorithm, but move personality context out and parameterize saved ISA context. |
| Existing AArch64 stage-1 assumes 16 KiB | `carrick-mmu-core/src/aarch64.rs::PT_PAGE` is **0x1000**, a 4 KiB stage-1 table page. Host 16 KiB backing custody is a different domain. NT needs reservation policy, not a wholesale replacement of already-4-KiB translations. |
| x86 normalization proves full syscall parity | `carrick-hal/src/x8664_arch.rs::normalize_syscall` really swaps clone TLS/ctid arguments and routes legacy stat/poll/dup2 forms; `carrick-x86/src/engine.rs` consumes it. That proves routing, not runtime semantics or privileged-kernel parity. `dispatch/proc.rs` implements `clone3` and `execveat` despite stale `Planned` metadata. Do not repeat “100% parity,” the census totals, or classify all mapped calls as working. |
| Every NT handle has a particular table encoding; all NT synchronization is an epoll equivalent | Treat guest handles as opaque values, with separately modeled pseudo-handles. No public compatibility promise requires Carrick to copy a Windows internal handle-table layout. Wait-all acquisition, APC delivery and completion ports are distinct protocols. |
| ARM64 TEB lives in `tpidr_el0` | Windows ARM64 reserves **x18** for the user TEB, per [Microsoft's ARM64 ABI](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions). Preserve it across every context switch. Linux TLS conventions cannot be reused as the NT contract. |

Other census assertions are not adopted: “32-bit getdents” does not describe
all fields of the native x86_64 legacy layout; OCI image tooling is not a
kernel substrate merely because it has no Linux syscall names; a named
`HostPid` in diagnostics is not inherently Linux leakage. Modern special
APCs, extended VM APIs and implementation details of `WaitOnAddress` need
version-specific contracts, not the census's universal claims. No Wine or
ReactOS implementation is an authority for this design.

## Target packages and ownership map

Introduce `carrick-core` (`no_std` + `alloc`) for the neutral object graph and
capability interfaces, composing existing `carrick-mmu-core`,
`carrick-sched-core`, cleaned `carrick-timer-core` and cleaned
`carrick-pipe-core`. Do not duplicate their algorithms. `carrick-guest-arch`
remains the sealed hardware seam. `carrick-core-abi` owns only transport and
neutral shared records extracted from the mixed `carrick-el1-abi`.

`carrick-personality-linux` becomes the single home for portable Linux policy
extracted from `carrick-kernel` and `carrick-el1/src/personality`.
`carrick-abi`, `carrick-fd-core`, `carrick-signal-linux` and
`carrick-inotify-core` are explicitly Linux dependencies, regardless of their
suffixes. Move the signal policy into `carrick-signal-linux`; extract a small
bitset only if the second client actually needs it, and retire
`carrick-signal-core` after its callers move. `carrick-personality-nt` and
`carrick-nt-abi` are new, with no dependency on Linux packages. They live in
a separate repository, not in this tree; see
[Repository boundary](#repository-boundary-nt-lives-out-of-tree).

`carrick-kernel` remains transitional Linux integration until its portable
owners and host bindings are relocated, then is retired without a compatibility
facade. Existing std/host-dependent Linux helpers (including signal-linux
`host_glue.rs`, `backend.rs` and signal-pump code) must be moved into host
adapters as the Linux policy crates become `no_std`; merely renaming their
current dependency closure cannot make them link into a guest image.
`carrick-el1` becomes the AArch64 image composition root (core + chosen
personality + ISA adapter); extend the existing `carrick-x86-cpl0` image for
x86_64. A composition root may depend on a personality; a core cannot. In-tree
composition roots compose only the Linux personality and the in-tree test
personality; the NT composition roots live in the NT repository. Existing
host execution venues call the same extracted owners until their privileged
venue passes its gate. They cannot become a second model.

Paths below are relative to `crates/`. Destinations are **proposed**, not
claims of files already present. “Move” means move the listed responsibility,
not blindly copy a mixed source file. Keep source symbols in migration
inventories; line numbers from the moving censuses are not stable IDs.

| Object / responsibility | Current crate and exact source modules | Destination and split |
| --- | --- | --- |
| Tasks, threads, birth/exit gates and execution generations | `carrick-kernel/src/kernel/objects/task.rs`, `objects/thread.rs`, `objects/process.rs`, `thread_ledger.rs`, `thread_adoption.rs`, `thread_retirement.rs`; `carrick-el1-abi/src/thread_lifecycle.rs`; `carrick-el1/src/personality/lifecycle.rs` | `carrick-core/src/task.rs`, `thread.rs`, `lifecycle.rs`: generation keys, runnable/parked/retiring state, accounting, atomic birth/retirement. Linux pid namespaces, tgid, parent/zombie/wait status, credentials, robust list and signal control become `carrick-personality-linux/src/process.rs`, `thread.rs`. NT process/thread handles, client IDs, PEB/TEB and exit statuses become `carrick-personality-nt/src/process.rs`, `thread.rs`. |
| Address spaces, range reservations, commit state, mapping lifetimes | `carrick-kernel/src/kernel/objects/process.rs::Mm`, `kernel/address.rs`, `kernel/mm_transaction.rs`; `carrick-kernel/src/dispatch/mem.rs` and `dispatch/mem/{anonymous,backing,vma,mmap,brk,madvise}.rs`; `carrick-el1/src/personality/reservations.rs`, `reservations/storage.rs`; `carrick-el1-abi/src/reservations.rs` | `carrick-core/src/mm/{mod,reservation,transaction}.rs`: reserve/commit/decommit/release, interval storage, permission transitions, backing references and owner transactions. Linux mmap/brk/growdown/advice/rlimit/clone policies go to Linux `src/mm.rs`; NT reservation/allocation-base, sections/views, commit accounting and PAGE_* policy go to NT `src/mm.rs` and `section.rs`. No `brk` or RLIMIT fields in neutral reservation layout. |
| Page tables, address contexts, ASID/PCID and occupancy | `carrick-mmu-core/src/{aarch64.rs,x86/mod.rs}` and descriptor transaction modules; `carrick-sched-core/src/{occupancy,spaces}.rs`; `carrick-aarch64/src/stage1_authority.rs`; `carrick-kernel/src/kernel/mm_occupancy.rs` | Keep shared MMU algorithms; core `mm` owns admission and retirement, sched-core owns occupancy; ISA adapters perform TLBI or x86 invalidation/shootdown. N1 consumes the host bootstrap authority; no second live editor survives. |
| Frames, COW references, grants and return receipts | `carrick-el1/src/{alloc,memory,cow,fault}.rs`; `carrick-el1-abi/src/{cow_grants,metadata_extent,descriptor_txn}.rs`; `carrick-kernel/src/kernel/frame_inventory.rs`; `carrick-vmm-hvf/src/trap/{frame_inventory,guest_cow,sparse_materialization,memory_protection}.rs` | `carrick-core/src/mm/{frames,cow,fault}.rs`, neutral wire records in core-abi. Host keeps physical extent custody, quota and stage-2 publication. Core owns logical references, zeroing and COW. Fault cause reaches personality only after neutral resolution fails. |
| Wait queues, scheduler, continuations and CPU eligibility | `carrick-sched-core/src/lib.rs`, `object_wait.rs`; `carrick-el1/src/sched.rs`, `sched/{object_wait,hw,aarch64_context}.rs`; `carrick-kernel/src/kernel/{scheduler,continuation}.rs`, `continuation/{wait_service,ipc,readiness}.rs` | Keep sched-core queues and one-winner claims; `carrick-core/src/wait.rs` composes owned wait registrations and continuations. Core/ISA context contains no fd table, signal mask or Linux tid. Linux readiness/futex completion and NT dispatcher-object acquisition remain their clients. |
| Timers and clocks | `carrick-timer-core/src/{lib,itimer,posix}.rs`; `carrick-hal/src/{guest_timer_bridge,posix_timer}.rs`; `carrick-kernel/src/timer_personality.rs`, `dispatch/time.rs`; scheduler timer-owner fields | Clean `carrick-timer-core/src/{deadline,periodic}.rs`: owner-scoped timer generation and expiration, wall/monotonic/CPU domains. Linux `src/timer.rs` owns itimer slots, signal/overrun/timerfd semantics; NT `src/timer.rs` owns waitable timers, NT time units and APC requests. BSD timer-ident transport returns to the host adapter. No global guest timer registry. |
| Generic objects, internal capability tables and pins | `carrick-kernel/src/kernel/{ids,registry,objects}.rs`; `carrick-fd-core/src/lib.rs::{TableId,OfdKey,OfdPin,DescriptorSlot,SlotBacking}`; `carrick-el1-abi/src/{ipc,ipc_tables}.rs` | Extract generation allocation, pin/close lifetime and storage to `carrick-core/src/{object,handle}.rs`. Internal `HandleKey` references an `ObjectKey` with a typed rights grant; not a guest fd, NT HANDLE or host handle. Guest-value encoding and namespace/security policy stay in personalities. |
| Linux fd tables and open file descriptions | `carrick-fd-core/src/lib.rs`; `carrick-kernel/src/dispatch/fd_table.rs`, `dispatch/fs/close_dup.rs`, `kernel/objects.rs::FileDescription`; `carrick-el1/src/personality/{file,ipc}.rs` | Keep one Linux fd authority in fd-core, consuming core pins/storage. Linux `src/fd.rs` owns smallest-free allocation, per-fd CLOEXEC, shared OFD offsets/status, CLONE_FILES and dup semantics across every backing type. Never make NT use it. |
| Linux signals and return frames | `carrick-signal-core/src/{lib,policy}.rs`, `carrick-signal-linux/src/lib.rs`; `carrick-kernel/src/kernel/objects/signal.rs`, `dispatch/signal.rs`; `carrick-hal/src/{sigframe,x8664_arch}.rs`; `carrick-runtime/src/vcpu_loop/signal.rs` | Consolidate policy in signal-linux; Linux `src/signal/{mod,aarch64,x86_64}.rs` owns ABI frames, altstack, restart and sigreturn. Core offers context capture and checked user transfer; NT exceptions/APCs do not enter this machinery. |
| Linux clone, exec and loading | `carrick-kernel/src/kernel/{clone_plan,exec,process_lifecycle}.rs`, `dispatch/proc.rs`; `carrick-mem/src/{elf,memory,vdso}.rs`; `carrick-vmm-hvf/src/trap/{process_plan,execve_rebuild}.rs` | Linux `src/{clone,exec,loader}.rs` selects sharing, ELF/PT_INTERP/auxv/vDSO, sibling cancellation and credential transitions; core commits prepared task/MM/resource bundles atomically. Hardware mappings and context install stay in ISA/VMM. NT PE creation uses the same publication primitive without Linux clone flags. |
| Linux futex ABI | `carrick-thread/src/{thread,platform_futex}.rs`; `carrick-hal/src/futex.rs`; `carrick-el1/src/personality/sched.rs`; `carrick-guest-mem/src/lib.rs::GuestMemory::shared_futex_location` | Linux `src/futex.rs` owns opcodes, robust death, requeue, bitsets and return rules. Core exposes atomic compare/enroll and identity of a pinned memory word; no FUTEX opcode, EINTR or errno in scheduler. NT keyed waits/address waits require their own protocol and oracle. |
| Linux /proc, namespaces and credentials | `carrick-kernel/src/vfs/proc.rs`, `kernel/objects/{credentials,session}.rs`, `kernel/operations/{identity,session,wait}.rs`; `carrick-vfs/src/vfs/mod.rs` synthetic proc records | Linux `src/{procfs,identity,credentials,session}.rs`. Core exports exact-generation observations, not text paths, Linux stat layouts or uid-based access decisions. NT query APIs and token/SID access checks consume its own object state. |
| Pipes, epoll/eventfd, AF_UNIX and notifications | `carrick-pipe-core/src/lib.rs`; `carrick-el1-abi/src/ipc.rs`, `ipc/epoll.rs`; `carrick-kernel/src/kernel/objects/ipc.rs`, `dispatch/net.rs`; `carrick-inotify-core/src/lib.rs` | Clean pipe-core retains byte buffers/cursors/readiness revisions. Linux `src/ipc.rs` owns PIPE_BUF/packet policy, SIGPIPE, eventfd, epoll and AF_UNIX/SCM_RIGHTS. Core retains generic object subscriptions and pins. NT named pipes/events/IOCP are separate semantic clients, not aliases for Linux objects. |
| Host files, namespace admission and caches | `carrick-vfs/src/fs_backend.rs`, `vfs/{dentry,rootfs,errno}.rs`; `carrick-el1/src/file.rs`, `substrate/{ipc,watches}.rs` | Retain contained host capabilities; extract neutral I/O errors, byte cache and storage identity. Linux path/stat/DAC and NT UTF-16 object paths/share modes/security remain personality policy. N4 must not declare current `VfsError = LinuxErrno` a neutral backend interface. |
| NT handle table and Object Manager namespace | **Absent**; nearest storage donors are fd-core and kernel object registry above | New (NT repository) NT `src/{handle,object_manager,security}.rs`: guest HANDLE decoding, pseudo-handles, desired/granted access, duplicate/inherit rules, typed objects, named directories/symlinks and reference lifetime over core capabilities. NT namespace is not the host filesystem. |
| NT multi-object and alertable waits, APC queues | **Absent**; nearest mechanics are sched-core `object_wait.rs` and kernel continuations | New (NT repository) NT `src/{wait,apc,dispatcher}.rs`: WaitAny/WaitAll, manual/auto-reset events, semaphore consumption, mutant ownership/abandonment, APC enrollment and delivery; core owns park/completion arbitration. |
| NT sections and views; 64 KiB reservations | **Absent**; nearest range/backing owners listed above | New (NT repository) NT `src/{section,mm}.rs` owns section object lifetime, independent view lifetime and reservation-versus-commit transitions. Core does not equate an allocation, a view, a page or a host extent. |
| NT SEH and syscall boundary | **Absent**; current Linux entry is `carrick-el1/src/personality/{common_entry,dispatch}.rs`, `carrick-hal/src/{trap,guest_arch,x8664_arch}.rs`, `carrick-x86/src/{engine,fault}.rs` | New (NT repository) NT `src/{dispatch,exception,abi_profile}.rs` plus per-ISA context encoders and a user ntdll implementation/profile. Core reports hardware faults and validates user context; personality selects exception records, user dispatch and NTSTATUS. |

Every “NT `src/…`” destination in this table is a path in the NT repository.
The neutral core capability each row needs (multi-object atomic acquisition,
alertable notification, reserve/commit, independent views, user exception
dispatch) is in-tree core work, specified and tested in neutral vocabulary.

This inventory intentionally does not call the whole existing HAL neutral.
Its Linux syscall normalization, fault-to-signal mapping and sigframe builders
move outward. Hardware register operations remain in HAL/guest-arch. Reuse
`carrick-guest-arch::Arch`, MM owner capabilities and both existing MMU engines;
replace `EntryArch::decode_syscall -> CanonicalCall` with an architectural
entry snapshot plus personality decode. “Canonical” must stop meaning
AArch64 Linux syscall numbering at a hardware boundary.

## Repository boundary: NT lives out of tree

Owner decision, 2026-10-06: the NT personality, its ABI, its clean-room
userland and its Windows-oracle probes live in a **separate repository**
(proposed `carrick-sh/carrick-nt`). This tree holds the personality-neutral
core, the traits and the composition hooks. Dependencies point one way: the
NT repository depends on Carrick crates; no crate, manifest, lockfile, gate,
script or CI job in this tree names the NT repository.

**Why.** If a rights holder objects (trademark, patent or copyright claim),
NT must be removable without touching Linux Carrick. With NT in tree, removal
means deleting directories while the code survives in history, or rewriting
history, which changes every commit identity that receipts, oracle-cache keys,
inventories and PRs depend on. A feature-gated NT in tree would also be a
default-off dark launch, which the opt-out rule forbids, and
`cargo metadata --all-features` would pull it into every gate. Out of tree,
compliance means archiving or privatising one repository and dropping its
build option. Carrick history, receipts and gates are unaffected.

**What stays in this tree.**

- `carrick-core`, `carrick-core-abi`, `carrick-guest-arch` and the
  `Personality`/`CoreServices` seams above, plus every neutral capability NT
  needs, specified in neutral vocabulary: atomic multi-object acquisition,
  alertable notification at a user-return boundary, reserve/commit/decommit,
  independent views over a shared backing, spawn without fork, a
  personality-chosen per-thread TLS base register, a fixed read-only page
  mapped into every MM, and user exception dispatch with a saved context.
- A **non-Linux test personality** in `carrick-kernel-example` that uses each
  of those capabilities with deliberately non-Linux semantics (opaque handles,
  its own status encoding, wait-all, reserve/commit, one-shot guard pages). It
  is the second in-tree client that keeps the core from becoming Linux-shaped.
  Its contracts register under `core.*`, never `nt.*`.
- The composition hooks: the guest-image build is a library/xtask entry point
  that takes a composition crate, replacing the hard-coded `../carrick-el1`
  path in `carrick-el1-image/build.rs`; host-side personality selection is a
  registration API on the engine/CLI (for example `run_with(&[factories])`)
  that the Linux build calls with Linux only. Personality is chosen per
  carrier, so an NT carrier is a separate image and Linux carriers never link
  NT code.
- Windows host support (`carrick-vmm-whp`, `carrick-host-windows`). It uses a
  public, documented hypervisor API like HVF and is independent of the guest
  personality.
- This design document. Its references are to public Microsoft
  documentation.

**What lives in the NT repository.** `carrick-personality-nt`,
`carrick-nt-abi`, the clean-room ntdll subset and later userland, the NT
composition roots (AArch64 and x86_64 images), the NT-enabled CLI build,
Windows container-image layer handling, the `nt.*` contracts, the NT probes,
the Windows-oracle cache and the provenance ledger.

**Keeping the seam honest.** The extended boundary checker (P0) also rejects
Linux types in the core's public API. The NT repository pins an exact Carrick
commit and bumps it deliberately; core changes need no backward compatibility
shims, but a core change that breaks NT is fixed forward in the NT
repository. An optional downstream build job may be added to the NT
repository's CI against Carrick `main`; Carrick's merge queue does not depend
on the NT repository. NT work stays sequenced after the core settles
(N1–N4), so the pin moves against a stable shape rather than daily churn.

**Legal hygiene, enforced in the NT repository.** This is engineering policy,
not legal advice; counsel review is an open owner decision below.

- Names: no “Windows” or Microsoft marks in repository, crate, binary,
  package or product names. Describe compatibility nominatively (“runs
  Windows console programs”).
- Never ship Microsoft binaries, DLLs, Windows SDK headers or container base
  image content. Probes run on the licensed oracle; only our own sources and
  observations are committed.
- Black-box only: probes observe documented API behavior from programs we
  write. Never disassemble, decompile, debug or trace Microsoft binaries.
- Type and signature sources: public Microsoft documentation and Microsoft's
  MIT-licensed `win32metadata` (and generated bindings derived from it).
  Other header sets require a provenance audit before use; mingw-w64 is not
  admitted until audited, because parts of it derive from excluded sources.
- No on-disk Microsoft filesystem formats; NT file semantics map onto host
  files. Patent-sensitive surfaces are recorded in the provenance ledger
  before implementation.
- Every implemented surface has a provenance ledger row naming its public
  documents and its oracle probes.

## Core/personality seams

The following are Rust signature sketches, not compiled APIs. Reuse existing
generation/VA types where their semantics match; perform any consolidation in
one migration, without parallel `GuestVa`/`UserVa` escape routes. Wire integers
are decoded into these types at the boundary; no raw integer grants authority.

```rust
// In carrick-core. Fields/constructors are private to the owning authority.
struct TaskKey { carrier: CarrierGeneration, serial: TaskSerial }
struct ThreadKey { task: TaskKey, incarnation: ThreadGeneration }
struct MmKey { carrier: CarrierGeneration, incarnation: MmGeneration }
struct ObjectKey { domain: ObjectDomain, incarnation: ObjectGeneration }
struct HandleKey { table: HandleTableKey, slot: SlotIndex, generation: HandleGeneration }
struct ReservationKey { mm: MmKey, generation: ReservationGeneration }
struct FrameKey { ipa: FrameGpa, generation: BackingGeneration }

trait Personality<A: EntryArch> {
    type ProcessState;
    type ThreadState;
    type Call;
    type Return;

    fn decode(&self, entry: &A::NativeFrame, abi: GuestAbiProfile)
        -> Result<Self::Call, EntryDecodeError>;
    fn dispatch(&mut self, call: Self::Call, cx: &mut CallContext<'_, A>)
        -> ControlFlow<Self::Return>;
    fn resume(&mut self, continuation: ContinuationKey, cause: WakeCause,
              cx: &mut CallContext<'_, A>) -> ControlFlow<Self::Return>;
    fn fault(&mut self, fault: UserFault<A>, cx: &mut CallContext<'_, A>)
        -> ControlFlow<Self::Return>;
    fn encode_return(&self, value: Self::Return, frame: &mut A::NativeFrame)
        -> Result<(), UserReturnError>;
}

enum ControlFlow<R> {
    Return(R),
    Suspend(OwnedContinuation), // retains pins, progress and one completion right
    Replace(PreparedImage),
    Terminate(TerminationRequest),
}
enum WakeCause {
    Object(ObjectKey), Deadline(TimerKey), Notification(NotificationKey),
    Cancelled(CancellationKey), Backend(CompletionKey),
}

trait CoreServices<A: EntryArch> {
    fn prepare_task(&mut self, parent: &TaskAuthority, plan: ResourcePlan<A>)
        -> Result<UnpublishedTask<A>, CoreError>;
    fn publish_task(&mut self, task: UnpublishedTask<A>, ready: PersonalityReady)
        -> Result<TaskAuthority, CoreError>;
    fn reserve(&mut self, mm: &MmAuthority, request: ReservationRequest)
        -> Result<ReservationLease, MmError>;
    fn commit_pages(&mut self, reservation: &ReservationLease, range: UserRange,
                    backing: BackingRef, access: PageAccess)
        -> Result<CommitReceipt, MmError>;
    fn transfer(&mut self, permit: TransferPermit, range: UserRange)
        -> Result<OwnedTransfer, TransferError>;
    fn pin_object(&mut self, table: &HandleTableAuthority, handle: HandleKey,
                  rights: RequiredRights) -> Result<ObjectPin, HandleError>;
    fn arm_timer(&mut self, owner: TimerOwnerKey, deadline: Deadline,
                 period: Option<Period>) -> Result<TimerLease, TimerError>;
    fn enroll(&mut self, txn: PreparedWait, resume: OwnedContinuation)
        -> Result<WaitLease, WaitError>;
}

// These types belong to the respective personality, never to core error enums.
struct LinuxCall { nr: CanonicalNr, args: LinuxArguments }
struct LinuxReturn(Result<SyscallValue, LinuxErrno>);
struct NtCall { service: NtServiceId, args: NtArguments }
struct NtReturn { status: NtStatus, information: NtInformation }
struct NtAbiProfile { build: NtBuildId, isa: GuestIsa, ntdll: ImageDigest }
```

Architectural entry preserves the full register frame and user stack pointer.
NT decoding must support service-specific stack arguments beyond the six Linux
register arguments in today's `RawSyscall`/`CanonicalCall`; copy them through
the live MM owner with bounded, fault-aware access. The NT ABI profile chooses
calling convention, argument counts and service mapping. Core never guesses
NT arity from the Linux syscall frame.

`CallContext` contains the exact task/thread/MM capabilities and the selected
personality's state. It cannot select a process through host pid or a Linux
namespace integer. State payloads live under the task/thread lifetime, with
one destruction path; no personality side table inferred from recycled IDs.
`ResourcePlan` describes explicit share/copy/new bindings, not clone bits.
`PersonalityReady` is an owned preparation receipt: publication cannot make a
child runnable before its personality identity, MM and resources all commit.
Image replacement drains outstanding leases and commits once; failure before
commit preserves the predecessor. Linux decides which resources reset on exec.

`TransferPermit` distinguishes ordinary read/write, instruction inspection,
snapshot and authorized observer writes. Personality authorization creates an
operation-scoped permit; core still validates the exact live MM, range and
permissions. Ptrace POKE or NT debug access cannot turn into an arbitrary host
pointer. Preserve N1's `BootMmBuilder -> El1MmHandle` consumption and
UserTransfer/Capacity/HostBacking transport. Core returns `MmError`/`IoError`,
not an errno number; Linux and NT independently lower errors with their own
precedence and completed-prefix rules.

`PreparedWait` is a linear transaction over pinned objects and subscriptions.
It acquires object locks in stable key order, checks state and enrolls before
releasing them. The personality supplies acquisition semantics while those
locks are held; no callback may block, issue host I/O or acquire an unlisted
lock. A signaler re-evaluates only subscribed waits. One generation-tagged
claim resolves satisfaction, cancellation, timeout and APC notification;
losers cannot consume state or finish again. Suspension owns partial I/O and
releases the vCPU. A returned `WakeCause` is an internal event, never encoded
`-EINTR`, `-ETIMEDOUT` or `STATUS_USER_APC` stored in a generic register slot.

For NT, WaitAll must atomically check and acquire the whole set: waiting for
one event and then another would consume auto-reset/semaphore state too soon.
WaitAny preserves input-index selection. NT validates access rights and duplicate
handles before enrollment; the core pins identities against reuse. A regular
user APC wakes an alertable wait and dispatches on that exact thread at a safe
user-return boundary. Nonalertable waits retain queued APCs. Special APCs are
a separately versioned feature, not implicitly implemented by a signal mask.
These are the public semantics described in
[WaitForMultipleObjectsEx](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitformultipleobjectsex);
IOCP completion delivery is a different NT object protocol.

The wire ABI remains one versioned, bounded request/completion transport.
Extract `carrick-core-abi` header, lengths, operation generation, custody and
completion records from el1-abi; personality records have separate layout hashes
and explicit tags. Do not send Rust trait objects, pointers or enum layouts.
Host validators check carrier/object generation, physical bounds, quota,
contained host capabilities and duplicate completions. No generic “execute
Linux syscall” or “execute Nt syscall” host service exists. Host `HANDLE`,
`HostFd`, core `HandleKey` and guest `NtHandle` are distinct domains, including
on a Windows host.

## Memory and exceptions under the NT personality

Model three independent granularities: guest translation page (4 KiB for the
initial NT profiles), reservation placement (64 KiB for ordinary NT allocation),
and host backing extent/granule (including 16 KiB macOS backing). The core
accepts a typed alignment and an allocation-base identity. Reserving 64 KiB
creates metadata; committing 4 KiB does not commit all 64 KiB or round its
permissions to the host page size. Decommit discards committed pages while
preserving the reservation; release uses the personality's allocation-base
rules. Frame return waits for all constituent-page and transfer pins, with
bounded retained capacity. Linux mmap placement remains page-granular.

A section object owns backing and maximum protection; each view has its own
MM, offset, range and lifetime. Data versus image sections, copy-on-write,
shared writes and truncation need explicit contracts. Ordinary view placement
uses allocation granularity and commit uses page granularity. Do not apply
64 KiB rounding to every memory operation or every PE section: extended and
large-page APIs require distinct profiles. The relevant public boundaries are
[VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
and [ZwMapViewOfSection](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection).

Architectural faults first enter the core MM owner for lazy commit/COW. A
remaining fault becomes `UserFault` with access kind, address and saved context;
Linux constructs a signal, NT constructs its exception record/context and
invokes its user exception dispatcher. SEH dispatch/unwind, debugger first/
second-chance handling, guard-page behavior and validated continuation belong
to NT plus its user runtime. Core only enforces privilege-safe return and
context ownership. Preserve full ISA extended state and parked-thread snapshots;
never reuse an AArch64 Linux sigframe as an NT CONTEXT. See Microsoft's
[SEH overview](https://learn.microsoft.com/en-us/windows/win32/debug/structured-exception-handling)
and [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
for the clean-room dispatch and image/unwind starting points.

## N1–N4 integration: decisions that cannot wait for NT

Keep N1 moving on its existing branch and acceptance packet. This proposal
adds extraction requirements to the relevant owners; it does not replace its
transactions, restart its migration, or call an inspected plan an implementation.
Numbered rows below refer to section 2 of the native-ownership plan; named
syscalls refer to its section 4 vertical-slice table.

| Milestone / concrete rows at risk | Neutral requirement at landing |
| --- | --- |
| N1 rows 3–9, 24, 27, 30: UserTransfer, observers, signal/native writes | Keep live MM/generation and authorization capabilities in core; Linux ptrace/sigframe policy remains in the Linux client. A future NT observer cannot inherit unrestricted “privileged write.” |
| N1 rows 10–19: Fork/COW, mmap/brk, VMA flags, advice | Range storage, frame references and transactional snapshot/clone are core; DONTFORK/WIPEONFORK, growdown, brk and resource charging are Linux decisions. Reserve/commit/decommit must not collapse into `mmap(flags)`. |
| N1 rows 21, 26, 28–29: exec, snapshots, bootstrap windows | Core image publication/context snapshots are format-neutral. ELF/auxv/vDSO and Linux core-file formatting remain personality clients; x86 and NT snapshots cannot be typed `Aarch64CoreRegisters` universally. |
| N2 `clone`, `exit`/`exit_group`, `wait4`, tid/robust setup rows | Reuse Phase B birth/exit claims, but split `BornRecord.clone_flags`, blocked masks, altstack and robust pointers out of neutral records. Core completion means thread/process retirement, not SIGCHLD, zombie status or `clear_child_tid`. Linux owns all those semantics. |
| N2 `sched_setaffinity` row | Core schedules an eligible CPU set; Linux validates masks and permissions. NT group/affinity encoding is another input, never carrier-thread affinity. |
| N2 memory row and exec loader closure | Linux loader supplies a prepared image to the MM owner. NT PE loading must not require ELF, PT_INTERP, auxv or a Linux stack. Keep byte service and cache shared. |
| N2 `futex`, `ppoll`, `pipe2`/`close`/`write` rows | Scheduler enrolls owned waits over exact object/word identities. Linux owns temporary masks, readiness and EPIPE/SIGPIPE; generic completion cannot assume a single wait object, a negative errno, or a file descriptor. Preserve partial I/O, pair-copyout rollback and default-pool exhaustion tests. |
| N2 `rt_sigaction` and signal-return closure | Move the entire Linux signal owner together. Keep IRQ/preemption and async-notification scheduling separate from signal selection, restart, altstack and sigreturn. |
| N3 fork-COW and creation-workload metrics | Preserve existing ceilings and zero host semantic-forward slope. Label observations by personality, ISA, task/MM and operation generation; “syscall exits” cannot globally mean Linux service numbers. ASID reuse and parked contexts exercise core, without erasing Linux fixture coverage. |
| N4 AF_UNIX/SCM_RIGHTS, eventfd/epoll/select | Core pins/queues are reusable; descriptor passing, credential payloads and readiness masks are Linux. NT handle duplication, named pipes and IOCP must not be implemented through Linux fd objects. |
| N4 credentials/rlimits/job control/timers/observers | Core accounts resources and exports owned observations. Linux defines uid/gid/caps, process groups, signal delivery, rlimits and /proc. NT defines tokens/access checks, jobs, waitable timers and query structures. Move global itimer state before multi-process NT work. |
| N4 names/stat/page cache/shared mapping coherence | Separate byte/storage identities from Linux path/DAC/stat/errno. NT namespace, share/delete access and case rules are personality policy. Preserve host containment, stage2a bounded work and external-writer coherence; NT cannot silently gain a stronger cache promise. |

N3 remains blocked by its existing reds until measured closure: 20×16
fork-COW total exits <=144, syscall exits <=64, scales 16/64/256 and the
existing incremental per-page ceiling. Keep the <=2x native-arm64 Docker
objective and exact-artifact promotion. An NT model passing VM-free does not
close a Linux migration gate. The earlier x86 deferral remains an execution
sequencing constraint for N1–N4; this owner's broader direction adds a later
x86/NT delivery track rather than silently expanding the current branch.

## Host and guest-ISA matrix

Every host must supply: vCPU creation/run/cancel and full context state;
stage-2 extent map/unmap/protect with rollback and custody generations;
interrupt/timer injection and idle park/wake; architectural feature discovery;
clock calibration; contained file/namespace and external socket operations;
asynchronous completion and cancellation; diagnostics and scoped teardown.
The in-guest ISA adapter supplies page-table edits, invalidation, context
switch and architectural entry. GIC versus APIC is an ISA distinction, not a
Linux/NT distinction. A capability not supplied must fail admission explicitly.

| Host / VMM | Current Carrick implementation | Same-ISA target and required backend work |
| --- | --- | --- |
| macOS / HVF | `carrick-vmm-hvf`, `carrick-aarch64`; Apple Silicon AArch64 reference Linux lane | AArch64 Linux now, AArch64 NT after personality gates. Retain GIC/virtual timer, SGI/WFI wake, stage-2 16 KiB custody, executable coherence, signing/entitlement and DOF. No Carrick Intel-HVF lane is claimed. |
| Linux / KVM | `carrick-vmm-kvm/src/{kvm_aarch64_engine,kvm_x86_engine}.rs` | AArch64 on arm64 host; x86_64 on x86_64 host. Supply matching KVM vCPU/register/interrupt-controller APIs, kick/cancel, memory slots and host epoll/file/socket services. Both personalities use the same backend after separate validation. Existing x86 routing is not full guest-kernel acceptance. |
| Windows / WHP | **Absent**: proposed `carrick-vmm-whp`, `carrick-host-windows`, `platform-windows` | x86_64 on x64 Windows; AArch64 on supported ARM64 Windows. WHP partition/vCPU/GPA mapping, cancellation, register/interrupt/timer capabilities; Windows file/socket/completion backend (including IOCP), containment and diagnostics. Remove Unix fd/pthread/fork assumptions from host boundaries; don't route guest NT operations straight to host NT. |
| FreeBSD / bhyve | `carrick-vmm-bhyve/src/bhyve_x86_engine.rs`, shared `carrick-x86` | Existing x86_64 lane targets x86_64 hosts. Qualify CPL0 interrupt/timer delivery, APIC/IPIs, vCPU cancellation, memory custody and BSD kqueue/native I/O. No Carrick AArch64 bhyve implementation or acceptance is claimed; it requires a separate backend qualification. |
| NetBSD / NVMM | `carrick-vmm-nvmm/src/nvmm_x86_engine.rs`, shared `carrick-x86` | x86_64 bring-up on x86_64 hosts; qualify NVMM exit/register/event injection, clock/wake, mapping and kqueue I/O on prepared target hardware. No AArch64 NVMM lane is claimed. Nested-host bring-up results are not native acceptance. |

WHP's public API lists x64 Windows 10 1803 and ARM64 Windows 11 24H2 build
26100.3915 as minimums for
[WHvCreatePartition](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcreatepartition).
This establishes an API possibility, not that Carrick's required interrupt,
timer and memory capabilities have been qualified on either architecture.
Record supported host build and each required capability in the backend gate.

Virtualization does not translate instructions. The existing exception is
**Linux x86_64 on Apple Silicon using in-guest Linux Rosetta**, still inside an
AArch64 VM. It does not run NT PE binaries. There is no NT x86/x86_64-on-arm64
translator in this design, including on Windows ARM64; host Windows emulation
is not automatically available to a Carrick guest. AArch64 NT means native
ARM64 PE. WOW64, 32-bit x86, ARM64EC and mixed-ISA NT modules are outside the
initial scope. Do not multiply five hosts by two ISAs into a fictitious ten-lane
support claim.

## NT userland scope and the decided clean-room boundary

Owner decision, relayed by the director on 2026-10-04: **no Wine at all**,
including no Wine code, design or test reuse. NT userland is clean-room,
verified by black-box differential tests against a real Windows machine.
Wine is LGPL (GPL-family); the previously possible policy exception is now
closed, not an open design option. ReactOS sources are also excluded.

An NT personality is not a Windows desktop or merely a syscall-number table.
The initial goal is a bounded set of native 64-bit PE console/native test
programs using named ntdll services: process/thread lifecycle, basic files,
virtual memory/sections, events/semaphores/mutants, timers, waits/APCs and
exceptions. Kernel drivers, GUI/win32k, services, registry breadth, COM/RPC,
network-stack fidelity and general application compatibility are separately
scoped follow-ons. A future console workload may require several of these;
its missing dependencies block that workload rather than being fake successes.

Use **ntdll's exported service contract as the compatibility boundary**.
Raw NT service ordinals vary by Windows build and architecture. Never make
one numeric table the portable NT contract or normalize NT ordinals through
AArch64 Linux numbers. Microsoft's
[native service entry-point documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/libraries-and-headers)
describes user-mode access through ntdll and warns about undocumented entries.
Even named native exports are not a promise of eternal ABI stability; pin an
explicit ABI profile and DLL/image identities.

| Option | What it requires / decision |
| --- | --- |
| Clean-room Carrick ntdll subset (recommended first) | Implement named exports, loader/runtime subset and per-ISA stubs from public documentation and independently written Windows oracle programs. Stubs enter Carrick using a versioned private NT service ABI; applications keep their named imports. Direct Microsoft numeric syscalls are unsupported unless a separate build profile is selected. Bootstrap tests may use a minimal loader; ordinary PE startup still requires relocation/import/TLS/PEB/TEB and runtime initialization. |
| Broader clean-room Win32 userland | Add independently implemented KernelBase/kernel32/API-set/CRT-facing services as the selected workload requires, above the same ntdll personality boundary. This increases scope substantially; it is a later compatibility milestone, not an alternative kernel. Microsoft DLL reuse is not the initial userland strategy. |

Start with the clean-room native-service subset and grow that one path. A
numeric Microsoft syscall compatibility profile, if required by an application,
is separately pinned by build and ISA and verified against native Windows;
unknown profiles fail explicitly. Do not guess a neighboring build's ordinal.

The NT oracle is a **real Windows machine**, serving the role Docker Linux
serves in Carrick's existing workflow. Independently authored probes invoke
named ntdll/Win32 APIs on Windows and the same APIs under Carrick's NT
personality. Capture source and executable hashes, Windows build/ISA, API
profile, numeric NTSTATUS/Win32 results, output buffers, event ordering and
resource/work observations. Match every required output line and normalize
only declared nondeterministic identities, never failures or missing output.
A probe that also fails on Windows is an oracle/probe issue to attribute,
not automatically a Carrick regression. A Carrick-only mismatch is a red
witness for the owning contract. Retain both raw streams and complete row
populations; crashes, missing DLL exports and unsupported profiles are explicit
failures, never successful empty runs.

Cache source-hash-qualified Windows observations with the same fail-closed
identity discipline as Linux probe oracles; changes to probe source, Windows
build, ISA or API declaration invalidate the key. Refresh on the Windows
machine deliberately and serialize oracle and Carrick timing phases when
sharing hardware. Do not use Wine tests, Wine's behavior or a Linux container
as an NT oracle. Numeric error precedence and undocumented behavior are learned
only from these original black-box probes and public documents.


The clean-room record consists of public Microsoft API/ABI/PE documentation,
a provenance ledger for each implemented surface, and independently authored
black-box tests on a licensed Windows oracle. Unspecified behavior remains an
open contract until characterized. Do not read Wine, ReactOS, leaked Windows
sources or GPL implementations to fill documentation gaps. Windows API names
and public types are compatibility vocabulary, not permission to copy internal
EPROCESS/OBJECT_HEADER implementations.

## Incremental milestones and exact gates

These are proposed implementation units, not commands whose success this spec
claims. Names marked **new** are tests/targets to add in that milestone;
a missing target, zero tests or unregistered binding is a failure. The existing
[contract workflow](../../conformance-contracts.md) applies: red evidence first,
then deterministic semantic/work assertions, then live bindings. Extend the
existing registry with `core.*` and `nt.*` authority namespaces; do not create a
second harness or pretend Docker is an NT oracle.

Milestones P0–P3 run in this tree. P4 and P5 run in the NT repository
against a pinned Carrick commit; their gates are that repository's gates and
never part of `just ci` here.

1. **P0 — extend `check-personality-boundary` before more core moves.**
   Reclassify Linux-only packages honestly; split neutral module roots from
   mixed composition roots. Add an explicit, reviewed inventory of legacy
   policy items in mixed modules keyed by crate/module/item plus normalized
   token hash. Any new or changed Linux-specific item in a core root fails;
   removed debt cannot reappear, stale/missing inventory entries fail, and a
   clean core permits no exceptions. Recognize semantic families beyond
   `LINUX_*`/`SYS_*`: signal numbers/masks/actions, clone flags/robust lists,
   fd exec/dup rules, itimer slots/overrun payloads, Linux syscall normalization
   and proc/stat types. Use AST declaration/import/type checks and compiler
   dependency checks, not only a word search; ban opaque payloads used to
   smuggle those meanings into core. A baseline records existing debt only,
   with destination/owner, never a wildcard waiver. Retain production cfg,
   renamed/transitive/target/build dependency, macro, orphan-source and
   missing-metadata fail-closed behavior. Include negative fixtures for
   `Signal::KILL = 9`, POSIX timer fields and a Linux fd policy added without
   an ABI dependency, plus a legitimate host diagnostic ID control. Also
   reject Linux-typed items (`LinuxErrno`, `CanonicalNr`, `Signal`, `Fd`) in
   the public API of core crates, and any manifest, lockfile or script in
   this tree that references the NT repository.

   Exact gate: `cargo test -p carrick-conformance-contract --lib personality_boundary`,
   then the fresh metadata/checker commands below, then `just lint-domains`.
   Mutant fixtures must be rejected red-first; the original checkout must
   report its existing debt truthfully. The current checker does not expand
   procedural macros or prove absence of arbitrarily encoded semantics;
   retain that limitation and review generated code/expansion inputs.

   ```sh
   cargo metadata --locked --offline --all-features --format-version 1 > target/cargo-metadata.json
   cargo run -p carrick-conformance-contract --bin check-personality-boundary -- --root . --metadata-file target/cargo-metadata.json
   ```

2. **P1 — extract core capabilities through Linux, aligned with N1/N2.**
   Move the actual task/MM/object owners, then replace their callers; no model
   beside production. Introduce neutral raw entry/fault/context and transport
   modules. New `carrick-core/tests/personality_boundary.rs` uses two live
   clients with equal visible IDs/VAs but different generations. Assert stale
   completions cannot mutate successors, absent rights cannot pin objects,
   unpublished births never run, cancellation completes once, reserve-only
   allocations consume no data frames, and drained frames return. The
   non-Linux test personality in `carrick-kernel-example` binds
   `core.wait.multi-object`, `core.mm.reserve-commit-view`,
   `core.entry.alertable-notify` and `core.fault.user-dispatch`, red-first,
   before NT work starts; one fixture runs it beside the Linux client in one
   process to expose global-personality scope errors.

   Exact gate: **new** `cargo test -p carrick-core --test personality_boundary`,
   `cargo test -p carrick-core --doc` (capability compile-fail witnesses),
   `just test-kernel`, P0 and the existing N1/N2 gate packet. Preserve
   `kernel.futex.contention`, `kernel.fork.stage1-image`,
   `kernel.mm.address-space-occupancy`, `kernel.el1.guest-scheduler` and
   `kernel.el1.guest-run-queue`; register missing owner contracts before moves.

3. **P2 — complete Linux client ownership with N2–N4.**
   Linux uses core task/MM/wait/timer/object APIs for every admitted object.
   Delete replaced host semantics and remove the corresponding debt entries.
   New contract `core.wait.transaction` covers timeout/cancel/satisfaction
   races, two live processes, partial I/O and default-pool exhaustion at
   1/8/32/128 waiters; enrollment and wake visits scale with affected
   subscriptions, not historical objects, and parked waits dispatch zero work.

   Exact gate: **new** `cargo test -p carrick-core --test wait_transaction`,
   `just test-kernel`, `just test`, `just ci`, `just accept`, `just el1-gate`,
   then `just --no-deps conformance smoke` and
   `just --no-deps conformance full` on the same final signed CLI artifact.
   Run N3's unchanged creation/fork-COW and impact packet; reconcile every
   row and raw stream. Director owns Docker and signed promotion. Extraction
   is not acceptance while an existing work or runtime-ratio budget is red.

4. **P3 — qualify both ISAs and new hosts using Linux first.**
   Reuse the existing x86 engine/CPL0 work, without assuming it is already a
   full venue. Add a single cross-backend production contract target to
   `carrick-embed`, **new** `core_venue`, proving two-MM same-VA isolation,
   context/TLS/extended-state retention, timer preemption, blocked-vCPU wake,
   invalidation/ASID-or-PCID reuse, stale completion refusal and extent return.
   Its required backend capability denominator comes from the matrix above.
   Remove invalidation as a negative control and require a discriminating red.

   Exact gate on each matching target host: `just build` and
   `just test-embed core_venue` for macOS; otherwise
   `cargo test -p carrick-embed --no-default-features --features platform-<host> --test core_venue`
   with `<host>` exactly `linux`, `freebsd`, `netbsd` or **new** `windows`.
   Each concrete target must run nonzero fixtures and report guest execution,
   not a skip. Pair with that host's CLI build/closure check and Linux probe
   lane; WHP support cannot be claimed until its Windows-native build and
   host-file/completion suite exist. ARM64 and x64 WHP need separate receipts.

5. **P4 — NT semantic core and native-service PE slice (NT repository).**
   Build the clean-room ntdll subset, NT ABI/profile, PE startup and the NT
   objects above. **New** `carrick-personality-nt/tests/native_contracts.rs`
   binds `nt.handle.lifetime`, `nt.wait.multiple-apc`,
   `nt.mm.reserve-commit-section`, `nt.exception.return` and
   `nt.entry.profile`. Exact gate:
   `cargo test -p carrick-personality-nt --test native_contracts`, plus P0/P1.
   Cases include handle reuse/duplicate rights/two processes, WaitAny index,
   atomic WaitAll over consuming objects, timeout/APC races and nonalertable
   retention, abandoned mutex, 64 KiB reserve plus independent 4 KiB commits,
   partial compound reclamation, shared/private section views, fault/SEH
   continuation, TEB retention and unknown-build refusal. Tests compare
   numeric statuses and buffers with committed source-hash-qualified native
   Windows observations. Model success alone does not claim executable support.

6. **P5 — production NT bindings and workload acceptance (NT repository).**
   Add a platform-neutral **new** `nt_native` target in the NT repository,
   reusing `carrick-conformance-next` and `carrick-embed` as pinned
   dependencies, that runs the P4 PE fixtures through `carrick-embed` and
   the clean-room ntdll on both native guest ISAs. Exact host gate:
   `cargo test -p carrick-conformance-next --no-default-features --features platform-<host> --test nt_native`
   run in the NT repository's workspace, using the same explicit platform
   substitutions as P3; macOS signs and executes that test binary with the
   same post-link signing as `scripts/test-signed.sh` (new test function
   names must carry the `nt_native` prefix). Register a Windows-oracle
   capture binding in the same framework and require complete matched
   observations for every P4 contract before claiming NT support. The gate
   must reject missing profiles, oracle rows or runtime bindings.
   Demonstrate PE startup, child/thread creation, section sharing, file I/O,
   alertable multi-wait and SEH on exact artifacts. Require zero host semantic
   dispatch for in-zone work, extent-bounded capacity, no parked-wait polling,
   and controlled <=2x native same-ISA Windows timings for the chosen workloads.
   Preserve Linux P2/P3 regression gates. Owner must select workload and Windows
   oracle availability before this milestone is dispatchable.

For all new scaling contracts, freeze algorithms and budgets at three or more
scale points before implementation. Require one owned completion per operation,
no host process growth per guest task, no MM population scans for range work,
and no fixed-size RAM commitment. Do not weaken budgets, retry flaky verdicts,
increase timeouts or serialize symptoms to close a milestone. Record source,
backend/host build, ISA/personality profile, binary/fixture hashes and cleanup;
HVF adds CDHash, LC_UUID, entitlement and DOF. Rebuild after integration.

## Owner decisions

- Package names and migration map: APPROVED as proposed.
- Separate carriers and IMMUTABLE per-process personality for the first release
  target: APPROVED. Cross-personality sharing stays a later, explicit decision.
- Delivery order: x86_64 FIRST for NT (AArch64 NT later).
- First real workload: a CONSOLE (CUI) program. The black-box oracle runs on
  real Windows under Docker on Windows (Windows containers), mirroring the Linux
  Docker oracle. Use the licensed Windows oracle machine (willow VM 106 is the
  existing Windows host; never touch other protected VMs). No Wine, ever
  (already settled).
- Repository boundary (2026-10-06): NT lives in a SEPARATE REPOSITORY;
  dependencies point only from NT to Carrick; this tree keeps the neutral
  core, the composition hooks, the non-Linux test personality and WHP host
  support. Open, owner's call: whether to run an automated similarity scan of
  NT diffs against excluded corpora (a tool, not a person, reads them), given
  that most code is model-generated; and whether to obtain IP counsel review
  before the first public NT commit.
- Remaining items (ntdll export/workload denominator and direct-syscall support
  boundary; x86/WHP scheduling relative to N1-N4 without diluting Linux
  acceptance; NT namespace/security/filesystem scope; the NT timing denominator
  and <=2x objective): APPROVED AS PROPOSED in this document, to be refined at
  their milestones. Implementation still requires each milestone's stated gates.

## Verification of this design change

Only this file is added (and, on 2026-10-06, amended with the repository
boundary). It changes no guest behavior, artifact or contract
budget; the documentation exemption applies to the task/MM/wait/signal and
file-contract families discussed here. Required document checks are
`test -s docs/superpowers/specs/2026-10-04-personality-core-split.md && just fmt-check`.
The director waived local and remote host acceptance for this documentation-only
handoff; implementation milestones above still require their stated gates.
Signed/HVF and Windows runtime validation are not performed by this design pass.
