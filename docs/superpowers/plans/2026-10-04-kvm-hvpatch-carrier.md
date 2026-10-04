# KVM HVPatch carrier execution plan

Design only; OCI success and production acceptance are not claimed.
Base `00cd94614` (`work/x86-kvm-health`); read the
[lane health hand-off](../../perf-results/2026-10-04-x86-kvm-lane-health.md#production-runtime-blocker-and-hand-off)
first. Willow VM 210: Linux x86_64, 12 vCPU, `/dev/kvm`, **nested KVM inside
Proxmox**, AMD Ryzen 7 7840HS. No Docker was run.

**Goal:** unmodified x86_64 OCI workloads in one HVPatch VM carrier, with
Carrick-owned tasks, identity, address spaces, waits, signals and IPC.

**Decision:** one architecture-neutral in-guest kernel, with thin AArch64
EL1 and x86_64 CPL0 backends. Start by eliminating hot exits. Port each
capability's hardware hooks into that kernel; do not build another personality
or a host-dispatch carrier first. Host semantic dispatch is a temporary,
explicitly counted scaffold removed as each slice lands. Host requests remain
for real crossings and physical capacity/control, as in the ARM design.
The director relayed and confirmed this owner ruling on 2026-10-04.

**Authorities:** [EL1 spec](../specs/2026-09-24-el1-kernel.md) (lines 210–234),
[architecture](../../architecture-overview.md), [HAL](../../hal.md),
[contracts](../../conformance-contracts.md), [AGENTS.md](../../../AGENTS.md),
[N2 creation plan](2026-10-04-el1-n2-creation.md) and
[Phase B rulings](2026-09-30-el1-thread-lifecycle.md) (line 157).
Historical deferred-x86 checkpoints do not override the owner's new request.
Implement the seven landings with `superpowers:executing-plans`; preserve N1
and Phase B authors. This worktree changes docs and a benchmark only.

## 1. Reuse inventory and evidence

Paths in tables are relative to `crates/`. Anchors refer to `00cd94614`
unless marked N1. “Linux compiled” means the Linux feature closure compiled,
not that macOS-gated code executed. “Source-read” is not runtime acceptance.

| Surface | Reuse / hardware boundary | Verification here |
| --- | --- | --- |
| Kernel graph | `carrick-kernel/src/kernel/objects.rs:123` TaskKey; `kernel/operations.rs:549` PreparedFork; `kernel/exec.rs:96` PreparedExec; `kernel/scheduler.rs:3381` Scheduler. Reuse exact identities and publication transactions; never substitute host PIDs. N2 extracts guest-capable mutation into the common core once. | Linux CLI compiled; 25 kernel-example contract tests pass. KVM graph binding is source-read. |
| Dispatch / syscall ABI | `carrick-kernel/src/dispatch/dispatcher.rs:31`; `carrick-hal/src/trap.rs:33` RawSyscall retains canonical/native number and guest ABI. Linux handlers are reusable policy, but the std host dispatcher cannot simply be linked into a no_std guest image. Extract policy once, as N1/N2 prescribe. | Linux compiled; 39 x86 library tests pass. OCI has no KVM binding today. |
| Executor pool / leases | `carrick-runtime/src/vcpu_loop/executor.rs:47`, `executor/pool.rs:786`, `executor/backend.rs:432`, `executor/binding.rs:26`; kernel `scheduler.rs:2034` SubmissionAuthority. Reuse pool/cancellation/settlement; vCPU admission is not guest task identity. | Runtime library compiled. Unit target fails to compile with 129 HVF/native-slice references: pool behavior is source-read here. |
| Owned continuations | `carrick-kernel/src/kernel/continuation.rs:209`, `:912`, `:2437`, `:2536`; runtime `vcpu_loop/continuation/quantum.rs:49`. Keep endpoint lifetime, completed prefix and exact execution generation; never restart consumed I/O. Guest waits release capacity. | Linux compiled; VM-free futex/progress contracts pass. KVM runtime adapter is source-read. |
| Memory / inventory | `carrick-mem/src/pml4.rs:355`, `:633`, `:795` supply a non-identity-capable x86 editor; `elf.rs` supplies image parsing. `carrick-hal/src/kernel.rs:36`, `:107`, `:298`, `:368`, `:464` and kernel `frame_inventory.rs:63`, `:392`, `:449` supply typed apply/rollback/retirement. Editors are not owners. | Linux compiled; x86 image/table unit tests pass. N1 snapshot is source-read only. |
| FD / IPC / signals | `carrick-fd-core/src/lib.rs:119` OFD, `carrick-pipe-core/src/lib.rs:110`, `:685` partial writes; `carrick-sched-core/src/lib.rs:1017` ZoneTables; existing signal/inotify cores. KVM `kvm_futex.rs:15` aliases the shared FutexTable wrapper. | fd 32, pipe 25, sched 89 and EL1 184 native library tests pass. No CPL0 serving proof yet. |
| Host boundaries | `carrick-host-linux/src/epoll_mux.rs` supplies external readiness; contained file authorities supply real bytes. Guest AF_UNIX, pipes, ptys, credentials, timers and child waits remain Carrick objects. | Linux compiled; carrier wiring source-read. Linux host facilities do not confer guest semantics. |
| x86 CPU / KVM ioctls | `carrick-x86/src/engine.rs:172`, `:1035`, `:1500`; KVM `kvm_x86_engine.rs:1002`, `:1250`, `:1395`. Reuse syscall/fault decoding, GPR/FS/GS/XSAVE serialization and VM/vCPU wrappers. | x86 + KVM library tests 58/58; real-KVM benchmark passes. `engine.rs:1522` executor audit explicitly refuses. KvmVmm `:70` owns per-process RAM/tables; host-fork rebuilds `:450`/`:484` are not a carrier implementation. |
| HVF trap / stage-1 / stage-2 | `carrick-vmm-hvf/src/trap.rs:8013`, `:8353`; `carrick-mem/src/memory.rs:4799`, `:5054`; `carrick-mmu-core/src/aarch64/descriptor_txn.rs`. HVC, ESR/ELR/SPSR, TTBR/ASID, ARM descriptors/TLBI and HVF stage-2 calls are hardware adapters. | Source-read; host doubles do not prove ARM hardware behavior. |
| Kick / quiesce / root retirement | Runtime `executor/backend.rs:27`, `:60`, `:633` are HVF-gated; `vcpu_loop/quiesce.rs:82` downcasts to HVF for ARM invalidation; `hvpatch/stage1_mm.rs:42`, `:64` redeems HVF proofs. HVF fork_quiesce wraps shared `carrick-thread/src/fork_quiesce.rs:465`. | Source-read. Reuse admission/drain/cancellation, replace endpoints. KVM `kvm_fork_coord.rs:5` controls the signal pump, not guest fork. `kvm_kicker.rs:71` is an existing KVM_RUN interrupt mechanism. |

OCI refusal is layered: `carrick-kernel/src/page_profile.rs:70`, runtime
`prepare.rs:912`, `lib.rs:478`. Relaxing the profile predicate alone leaves
both pending launch paths. `carrick-x86/src/bringup_fns.rs:651` is a limited
run-elf dispatcher, never the new OCI implementation.

### File-by-file EL1 split

All 26 current `carrick-el1/src/` files were source-read. Native `--lib`
execution covers the host-test branches. The ARM freestanding image also
compile-checks here; no ARM hardware execution was possible. The split
below keeps each semantic implementation in the existing common library.
`substrate/mod.rs` already aliases file/scheduler modules: do not copy them.

| File:line | Common code retained once / architecture work |
| --- | --- |
| `lib.rs:1` | Common no_std library exports; select an ISA adapter explicitly. `target_os=none` alone is insufficient. |
| `entry.rs:38` | ARM image entry, descriptor-drain hook and HVC panic transport. Thin ARM entry calls normalized common entry; x86 gets its own thin image entry. |
| `lock.rs:7` | Atomic SpinLock is common; interrupt masking/admission belongs to the CPU backend. |
| `alloc.rs:121`, `:710`, `:720` | Bounded metadata allocator/extent policy is common; current-slot lookup and mapped-aperture resolution are backend hooks. Preserve extent budgets. |
| `file.rs:138`, `:229`, `:268` | MemoryValidator/UserCopy and file operations are seams; LDTR/STTR/AT fixups and user access machinery move to ARM hooks. N1 cursor supersedes private position authority. |
| `cow.rs:40`, `:57` | COW policy remains common; ARM descriptor/copy-window imports become owner/MMU hooks after N1. |
| `fault.rs:67`, `:85`, `:200`, `:247` | Resolver/transaction policy is common; ESR decode, ARM leaf encoding, table maintenance and physical aliases are backend work. N1 owns the ongoing edits. |
| `memory.rs:37`, `:283`, `:440`, `:534` | Linux reservation/permission/retirement policy is common; hardware editors and ARM-shaped syscall frames are adapters. Rebase onto N1, no second VMA ledger. |
| `sched.rs:20`, `:54`, `:110` | Scheduler/wait policy is common. ThreadCpu currently leaks TTBR, GIC/SGI and ARM TrapFrame; replace those signatures with KernelArch types, not a second scheduler. |
| `sched/hw.rs:18`, `:174` | ARM user-word access, FP/SIMD, TTBR, timer, GIC, WFI/IRQ masking. Extract thin Aarch64Arch; implement X86Arch separately. |
| `sched/object_wait.rs:20`, `:40` | Owned enroll/park/resume common; resume-PC and wake delivery use typed ISA hooks. N1 edits this file. |
| `sched/tests.rs:327`, `:1082`, `:1305` | Common handoff, foreign-MM and prefix-resume tests; parameterize contexts/backends, retain mutation-sensitive state-loss witnesses. |
| `personality/mod.rs:1` | One Linux personality module index; N1 exports its production mm_portal here. |
| `personality/dispatch.rs:63`, `:264` | One common router; normalize `frame.x[8]`, x-register args/results, ESR and slot-address lookup. Host-only entry currently returns Forward; native tests use explicit regions. |
| `personality/file.rs:34` | Shared Linux lseek/read/write result policy. No ISA fork of errno or seek rules. |
| `personality/inotify.rs:29`, `:110`, `:160` | Common watch/read semantics; user-copy and mapped storage use owner/backend hooks. |
| `personality/sched.rs:16`, `:29` | Common futex policy; canonical call/argument decoding replaces ARM register indexing. |
| `personality/ipc.rs:81`, `:86`, `:185` | Common table/operation owner; normalized call and typed mapped-region access replace fixed-address/frame assumptions. |
| `personality/ipc/epoll.rs:111` | Common readiness/deadline/operation policy; syscall and guest-UAPI layout adapters remain explicit. |
| `personality/lifecycle.rs:104`, `:130` | One identity/claim/mask/exit policy from Phase B/N2. Clone argument order, TLS and signal-frame layouts are ISA adapters. |
| `personality/lifecycle/tests.rs:251`, `:397`, `:821` | Reuse birth/exhaustion/exit witnesses with both ABI decoders; host doubles do not prove guest signal frames. |
| `personality/reservations.rs:343`, `:394` | One admitted reservation tree/capacity policy; N1 production root, not a copied private MM model. |
| `personality/reservations/storage.rs:53`, `:149` | Common pinned-node-bank machinery; mapping view resolution is backend work. N1 collision. |
| `substrate/mod.rs:2`, `:5` | Existing aliases to file.rs/sched.rs are the same implementations. |
| `substrate/ipc.rs:54`, `:123` | Common prefix-copy/operation-pin continuation; N1 UserTransfer replaces unsafe or mirror-based access. |
| `substrate/watches.rs:5`, `:66` | Common collection/notification mechanism; no new x86 watch core. |

N1 adds `personality/mm_portal/{mod,production,fork,edit_wait,test_support,tests}.rs`
and native owner tests. Its `production.rs:21` uses real SharedReservations/
AddressSpaces, but imports ARM LiveDescriptorWords/LeafAccess and PA masks;
`fork.rs:412`, `:1062` also walk ARM tables. These need one common owner policy
with two table backends, not wholesale compilation under a new target flag.
The image packer `carrick-el1-image/build.rs:203` and `carrick-el1/link.ld`
are ARM-specific packaging; x86 needs a thin image artifact/ABI receipt.

## 2. Architecture decision and named seam

| Approach | Scope and evidence | Recommendation |
| --- | --- | --- |
| Host dispatch first | Reuses the std dispatcher quickly, but still needs exact MM/CPU custody and leases. A later move changes semantic venue again; nested exit-only cost is ~20 µs even without register completion. | Reject as the carrier architecture. Use only bounded fixtures/scaffolds while bringing up individual hooks; delete each admitted semantic fallback in its landing. |
| Common kernel at CPL0 first | Requires entry/return, user-copy/fault, root/context, interrupt/timer and wake hooks. Reuses the 184-tested EL1 personality plus sched/fd/IPC cores, N1 production owner and N2 task transactions. | Target. First real shared served path is M2; grow hardware slices without a duplicate Linux personality. |

**Package choice:** retain `carrick-el1` as the common kernel library during
N1/N2; its existing ARM image and a new `carrick-x86-cpl0` image are thin entries,
not separate kernels. Put the no_std interface in new `carrick-guest-arch`.
Avoid a broad package rename while N1 changes its imports. Host-facing typed
KVM CPU custody stays in carrick-hal/x86/KVM. **Post-N2:** rename `carrick-el1`
to a neutral common-kernel package in one reviewed move; update both image
dependencies and delete the old package spelling. The single
semantic owner and adapter separation are mandatory.

**KernelArch seam:** refine existing ThreadCpu/UserWord/MemoryValidator/editor
seams. A sealed `KernelArch` binds these smaller traits and associated native
frame/saved-context/root types; the common kernel owns tasks, policy and waits.

| Trait | Required methods / typed inputs and outputs |
| --- | --- |
| `EntryArch` | `decode_entry(NativeFrame) -> EntryEvent`; `decode_syscall -> CanonicalCall` retaining NativeNr/GuestAbi/args; `set_result`; `save_context`/`load_context` including FP/vector/TLS/restart; `prepare_user_return` validates the target and selects a safe return form. No fake ARM x-register frame for x86. |
| `MmuArch` | `install_context(AddressContext)`; `translate_live(owner, GuestVa, Access) -> OwnedTranslation`; `prepare_leaf_edit`/`apply_leaf_edit`/`undo_leaf_edit`; `request_invalidation -> DrainTicket`/`ack_drain`; `copy_user_chunk(owner permit, pins, offset)` and `publish_executable`. All use exact root/frame/backing generations. Geometry is explicit. |
| `InterruptArch` | `counter`/`frequency`; `arm_timer(Option<Deadline>)`; `send_wake(CpuTarget, WakeToken)`; `ack_interrupt -> InterruptReason`; `end_interrupt`; `mask_interrupts`/`restore_interrupts`; `park_until_interrupt`; `current_cpu`. No TTBR/GIC/SGI argument in common policy. |
| `CrossingArch` | `submit_host_request(OwnedHostRequest) -> RequestToken`; `consume_completion(token, generation)`; `leave_idle`/`report_fatal`. Request variants encode bytes/readiness/clock/terminal/backing/control, not a generic run-Linux-syscall opcode. Owned continuation and cancellation survive exits. |

ARM implements ERET, ESR/TTBR/TLBI, GIC/CNTV and HVC; x86 implements SYSCALL,
IRETQ/safe SYSRET, CR2/CR3/page-fault decode, INVLPG/qualified INVPCID,
APIC/timer and an existing OUT doorbell for permitted requests. Interrupt
reason is distinct from a semantic syscall request. ISA syscall tables, clone
argument order, TLS, auxv and signal UAPI remain explicit; common policy uses
canonical calls. ABI hashes cover both common records and each native context.

Size evidence, source-read: x86 engine/bring-up/KVM x86 adapter total 5,291
lines; EL1 sched/fault/memory/dispatch/lifecycle alone total 7,082. These are
scope indicators, not effort estimates. Existing ThreadCtx (`sched-core/lib.rs:381`)
and TrapFrame contain ARM state; freestanding x86 is not a zero-edit build.
Native x86 tests already execute shared algorithms; the KVM lane adds actual
entry, paging, interruption and cross-MM serving validation to that same code.

### Measured transport evidence

Benchmark commits `682a30d6d`, `25e0ea15d`;
[receipt with source/artifact hashes and all samples](../../perf-results/2026-10-04-kvm-syscall-round-trip.md).
Nine interleaved 50k-call batches, one warmup each, inner CPU 2:

| Nested willow path | Median batch mean |
| --- | ---: |
| Native uncached libc getpid | 0.2961 µs |
| KVM exit-only control, no SET_REGS / CPU accounting | 19.9593 µs |
| Existing engine host synthetic identity | 21.4329 µs |
| Benchmark-only CPL0 synthetic identity, no per-call exit | 24.2 ns |

Counts/checksums pass. Neither synthetic identity arm implements Linux
identity, permission, scheduler or signal policy. This experiment suggests
exit elimination matters more than register-copy tuning here; it does not
predict shared-kernel syscall latency. These are **nested**, uncontrolled
outer-host observations, useful conservative planning estimates, not a
bare-metal floor or a guaranteed universal upper bound.

The ≤2x native-Linux Docker target remains per workload. Future receipts must
state nested/bare-metal, outer configuration, same-image x86 digest, artifact
hashes and populations. No cross-host-class ratios. The director must arrange
serial Carrick/native-x86 Docker timing on a quiet declared host class after
correctness; no Docker in this task. First shell success is not cost closure.

## 3. N1 memory and physical ownership

Read-only N1 snapshot: `origin/work/n1` (no local work/n1 ref),
`8d5df2d2e0f235f9ad82ec2cd59dac13efcfb832`, via `git show`, not merged/built.

- `carrick-el1-abi/src/mm_portal.rs:24`, `:81`, `:125`: sealed El1MmHandle
  carrier/MM/incarnation, prepared permit and exact operation sequence.
- `carrick-aarch64/src/user_transfer.rs:12`, `:34`, `:142`, `:202`: a physical
  pin is not semantic authority; retained custody/prefix and maintenance-root
  loan use the current executor, not spare CPU capacity or target execution.
- `carrick-aarch64/src/stage1_authority.rs:197`, `:855`, `:1386`: manager/source/
  share state owned together and exact Fork capacity settlement.
- `carrick-el1/src/personality/mm_portal/production.rs:21` binds the real
  reservation/address-space owners; `reservations/prepared.rs:25` claims
  prepared-copy permits. Fork preparation/publication is in `mm_portal/fork.rs`.

N1's `kernel.el1.mm-exclusive-owner` still has production/signed reds. Its
checkpoint is not acceptance. N2 reports the shared OFD cursor as pending,
not present in this fetched snapshot. Consume its actual landed authority:
staged pread → prepare → commit/cancel under one cursor shared through
fork/dup/SCM_RIGHTS. Do not introduce a per-fd lock, copied f_pos or raw user
copy escape. MM owner, permit and cursor land **once in the common kernel**;
ARM/x86 implement geometry, descriptor maintenance and access hooks only.

1. **Domains:** reuse GuestVa/Gpa/HostVa (`carrick-guest-mem/src/lib.rs:145`,
   `:271`, `:289`), FrameId/MappingId/MappingGeneration/KernelTransactionId.
   Share these domain definitions in the no_std boundary with N1 rather than
   depend on the std-only guest-mem crate from the image. Add issued `X86Root`, `X86AddressContext` (PCID plus allocation generation),
   `BackingOwnerGeneration`, `KvmSlotGeneration`. MM incarnation, frame,
   PCID and slot are not interchangeable. No identity-address fallback.
2. **Per-MM roots:** CR3 selects a private root; CLONE_VM/vfork hold explicit
   shared-owner edges until exec/exit. Supervisor entry/metadata mappings
   are common and inaccessible to CPL3. Every copy authenticates exact live
   owner/root, access/COW and backing generation. Foreign/stopped-target
   transfers progress with every default executor slot occupied.
3. **Second level:** KVM owns Intel EPT or AMD NPT; Carrick owns GPA allocation,
   backing lifetime and memslot projection. `carrick-vmm-kvm/src/kvm.rs:1397`
   burns slot IDs on failure and ignores _perms today; carrier custody must
   fix rollback and type the slot lifetime. Query limits; use bounded extents,
   not a slot/page/MM. Stage-1/NX/COW enforce Linux permissions; memslot RWX
   registration does not grant semantic access.
4. **Publication:** prepare inventory capacity/backing/slots and unlinked
   edits; acquire owner admission, install physical custody, publish leaves
   and exact receipts, then reopen entry. Inject failure at each boundary;
   rollback descriptors/slots/inventory together before re-entry. No MM lock
   spans host I/O. Unprovable physical rollback quarantines/fails the carrier.
5. **Retirement:** revoke admission/permits; unlink; collect exact translation
   drain acknowledgements from every affected CPU, including parked leases;
   settle inventory retirement. Recycle only after references, pins and stale
   translations are gone. A reused address/frame cannot accept old completion.
6. **Maintenance:** x86 invalidation is not broadcast ARM TLBI. An owned
   shootdown reaches affected vCPUs and acknowledges exact context generations.
   Memslot ioctl completion is not stage-1 drain. Start without PCID if needed;
   enabled PCID requires safe reuse/invalidation. Unrelated MMs continue;
   never poll or impose VM-wide quiesce to hide incomplete ownership.
7. **Elasticity:** willow has 4 KiB guest/host pages. Use N1's private first-touch
   backing and hidden reservations, not per-MM 32 GiB arenas/shared-zero COW.
   Make 4 KiB vs ARM 16 KiB compound geometry explicit. Retain N1 work/capacity
   bounds at 16/64/256 pages and 16/512 unrelated mappings; materialized bytes,
   retained extents and touched leaves/tree height are measured. Coalescing
   requires aligned output GPA and equal attributes, not just contiguous leaves.

Clean-room hardware reference: [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
Volumes 2/3. KVM ioctl facts were checked in installed `/usr/include/linux/kvm.h`
(struct kvm_run/userspace_memory_region and ioctl/capability definitions),
existing wrappers, [ioctl(2)](https://man7.org/linux/man-pages/man2/ioctl.2.html)
and [mmap(2)](https://man7.org/linux/man-pages/man2/mmap.2.html).
No GPL implementation or copied api.rst prose.

## 4. Dependencies and sequencing

**Start now:** new files in carrick-hal, carrick-x86, carrick-vmm-kvm and
new no_std arch/image crates. Extract leaf hardware from EL1 `sched/hw.rs`,
`file.rs`, allocator slot/address hooks and lock guards where file-disjoint.
Minimal module/export changes are coordinated separately; do not edit N1's
common router or shared ABI before hand-off merely to wire a leaf.

**Wait for N1:** EL1 lib/entry/Cargo/linker, cow/fault/memory, dispatch/mod,
mm_portal, reservations/prepared/storage, sched/object_wait, substrate/ipc;
sched-core lib/object_wait/spaces; EL1 ABI layout/descriptor/mm_portal records;
runtime memory/reservations/quiesce/binding/lifecycle/signal/zone/backend.
N1 also reserves kernel objects for its cursor. Refresh the actual landed
diff, not just this snapshot. Leaf disjointness is preparation permission,
not proof the owner is accepted. M2 first serving does **not** wait for N1
cursor/MM acceptance. It needs only
the narrow common-entry/export and ISA-selection hand-off below; request those
lines separately from N1, without taking its MM router/ABI ownership. M3 binds
the accepted production owner, never a provisional copy. `sched/hw.rs`,
`file.rs`, `alloc.rs`, `lock.rs` and `sched.rs` are absent from the refreshed
`git diff --name-only ad3e127a9 origin/work/n1` (snapshot unchanged at 8d5df2d2e).
If that changes, defer the touched leaf to M2; no parallel edits.

**M5 first needs a shared runtime file:**
`carrick-runtime/src/vcpu_loop/executor/backend.rs:432`, followed within that
landing by binding, root-resource/retirement adapters and the common loop.
No shared runtime edits in M1–M4. Wait until **N1 and lifecycle Phase B land**,
then consume exact claim/adopt/settle APIs and ABI hashes. Later Phase B
rulings bind credentials/mask/affinity at claim, retain kernel birth custody
and reject reserved_tid maps/prepared runtime backends.

**N2 is one work stream:** its creation, fd, signal/timer, loader and task
transaction extractions serve ARM and x86 through KernelArch. Add x86 to the
existing N2 fixtures/bindings; do not make a parallel N2 plan/graph/dispatcher.
M4 consumes landed common scheduler/IPC slices; M6 consumes N2 birth/exit/wait/
exec and signal ownership. x86 decoder/frame hooks can be prepared earlier.
N2's host-byte loader requests remain real crossings; Linux ELF interpretation,
auxv, permissions and successor transactions remain common policy.

Tests below are **proposed future filenames**, not existing green bindings.
Every landing starts with behavior/work-budget reds at the cheapest capable
layer, then native common-core and executing KVM greens. Missing-symbol
compile errors are not behavioral witnesses. Extend existing contract IDs;
add a KVM binding/descriptor only for an uncovered surface. Never weaken a
budget, add retries, enlarge the default pool or turn absent KVM into a skip.

All milestone commands run from repo root. In addition to listed commands:
`just fmt-check`; Linux feature-closed build; applicable host acceptance
receipt. ARM shared changes require signed gates on Apple hardware. Current
`just accept --phase signed` is macOS-only (`carrick-xtask/src/accept.rs:677`);
register real KVM executing bindings in M5/M7, not false ARM acceptance.
Stamp run IDs, use owned bounded waits/watchdogs and scoped cleanup via
`scripts/sudo/kill.sh RUN_ID`; do not wrap attachable CLI runs with timeout.
Live receipts record HEAD, executable SHA/build ID, ABI, fixture/image hashes,
exact result and released VMs/slots/backing. No Docker overlap or run here.

## 5. Seven reviewable landings

### M1 — architecture seam and ARM-preserving leaf extraction

**Fence:** new `carrick-guest-arch/src/lib.rs`,
`carrick-hal/src/guest_arch_binding.rs`, `carrick-x86/src/arch_context.rs`,
`carrick-vmm-kvm/src/carrier_cpu.rs`; EL1 leaf hardware files identified
above, minimal exports. No runtime, N1 owner/router/ABI or lifecycle edits. New crate manifests are
  independent; defer EL1 dependency/registration (its Cargo.toml/lib.rs are
  N1-owned) to M2. Leaf extraction can use current ARM types meanwhile.

- [ ] Define/test KernelArch context/entry/event contracts and extract ARM
  instruction helpers without changing the shared record layout. Retain one
  policy body; production KernelArch entry wiring lands in M2. KVM custody consumes existing
  `X86TaskCpuStateV1` (`carrick-hal/src/threaded.rs:2349`), not host TLS identity.
- [ ] Red: x86 executor audit currently refuses; saved state must retain
  native/canonical number, syscall resume, CR3, FS/GS, GPR and XSAVE tags
  across two differently identified task contexts. Mutate FP/TLS/root save
  to prove tests fail. ARM fake-backend state trace stays identical.
- [ ] Contracts: task-load-entry, captured-stack and execution-generation
  isolation (`kernel.el1.task-load-entry`, `kernel.syscall.captured-stack`).
- [ ] Accept: `cargo test -p carrick-guest-arch`;
  `cargo test -p carrick-el1 -p carrick-x86 --lib`;
  `cargo test -p carrick-vmm-kvm --lib`. Commit the seam, not an x86 scheduler.

### M2 — CPL0 entry serves the common kernel's first syscall

Candidates were source-read on `00cd94614`, not inferred from syscall names:

| Call | Current common route / dependencies | First-call choice |
| --- | --- | --- |
| set_robust_list (x86 273 → canonical 99) | `personality/dispatch.rs:456` → `lifecycle.rs:162`, `:320`; admitted LifecycleVenue, issued CurrentTask and ThreadControlSlot, open setup gate, length 24. Writes slot metadata, never dereferences head; no UserCopy, scheduler switch, N1 cursor or MM owner. | **Choose:** real mutable kernel-owned state, already served on this base, zero pending-branch policy dependencies. |
| rt_sigprocmask with both pointers NULL | Same dispatch branch; `lifecycle.rs:207`. Issued slot/open gate and sigset size 8; reads owned mask, returns 0 without copy. Non-NULL forms require user-copy hooks. | Available now, but NULL-only success observes less state than robust-list publication. |
| Private FUTEX_WAKE | `dispatch.rs:481` → `personality/sched.rs:37`; admitted zone/MM identity, wait queues and CPU wake hooks. | Already served, but needs scheduler/interrupt work beyond first entry. |
| clock_gettime / sched_yield | No served arm in `dispatch.rs:518` on this base; fall through at :652. Existing timer counter methods do not implement these syscalls. | Do not invent an already-served path. |
| gettid | No lifecycle arm on this base. Phase B adds EL1 serving from exact owned thread identity. | Use once Phase B lands; introduces one pending branch dependency today. |
| lseek | `dispatch.rs:608`, `:831` → `personality/file.rs:34`; admitted OFD/cursor. | Later M2/M3 follow-up after N1 cursor hand-off, never a prerequisite for the first CPL0 call. |

**Fence:** thin `carrick-x86-cpl0` image/linker/entry, x86 `cpl0_entry.rs`,
KVM `cpl0_boot.rs`, `tests/cpl0_entry.rs`; new normalized common entry and
frame-independent robust-list helper in the **existing** kernel. No runtime,
N1 MM policy or ABI layout edits. Phase B/N1 full acceptance is not a first-call
prerequisite.

**Narrow hand-off still required:** EL1 Cargo.toml/lib.rs exports and
ISA-selective module/image wiring are N1-touched. Coordinate only new interface
dependency/entry export and selection of x86-safe common modules; the first
image cannot compile ARM-only hardware bodies unchanged. Extract
`lifecycle.rs:320` to a typed argument/slot helper and have the existing ARM
call invoke that same body. Coordinate this leaf with Phase B. Normalize the
existing robust-list route at `dispatch.rs:456` only if needed for the common
entry, leaving all memory/reservation routes untouched. The new x86 entry must
call the shared helper through the common entry, not build a fake ARM TrapFrame
or copy the syscall algorithm. Existing common ThreadControlSlot/page records
need no layout change for this call; broader native-context ABI wiring stays
with its owner. N1's cursor and production MM changes are outside this hand-off.

- [ ] Use ELF/long-mode bring-up to load the common image, supervisor stacks/
  TSS/IST, IDT, LSTAR/STAR/FMASK and saved user SP. Validate canonical RIP/RSP/
  RFLAGS; use IRETQ where SYSRET is unsafe.
- [ ] Red: current bring-up exits for every call. Two issued live task contexts
  repeatedly set distinct robust-list heads (length 24); verify only their own
  control slot changes via the common kernel's own slot accessor (or shared
  get_robust_list), return 0, and **zero semantic host forwards**. No head
  dereference or user copy occurs. Admit the shared invalid-length error
  route in this landing: len != 24 returns EINVAL (22) without changing either
  head, also with zero semantic host forwards. A return code alone is not a
  witness; inspect both stored heads after success and error.
  Inject kicks at entry/return; exactly one slot publication/completion.
- [ ] Contracts: task-load-entry, captured-stack, kick boundary
  (`kernel.vcpu.kick-el0-boundary`) and existing lifecycle control-slot ownership.
  Remove the successful robust-list host scaffold in this landing; final test
  result/state inspection is declared control transport outside serving.
- [ ] After N1's cursor hand-off, add shared lseek offset/errno/isolation
  witnesses through the same entry; no first-call dependency on that work.
- [ ] Accept: `cargo build --release -p carrick-x86-cpl0 --target x86_64-unknown-none`;
  `cargo test -p carrick-el1 --lib`;
  `CARRICK_RUN_ID=kvm-m2 cargo test -p carrick-vmm-kvm --test cpl0_entry`.

### M3 — N1 owner through x86 MMU/fault/backing hooks

**Fence:** new x86 `owner_mmu.rs`/`user_transfer.rs`, KVM
`carrier_memory.rs`, MMU-core `x86/descriptor_txn.rs`,
`tests/carrier_memory.rs`; N1 common owner/editor seam edits only after its
accepted landing. No shared runtime, task graph or private cursor/permit model.

- [ ] Implement section 3 using production MmPortal, reservation roots,
  prepared permits, owner Fork/Exec/Capacity and exact inventory receipts.
  Common policy is extracted once from ARM code; ARM keeps its backend.
- [ ] Red: two live MMs map identical VAs to different bytes, then share only
  explicit CLONE_VM/frame edges. Exercise first-touch, COW, NX/protection,
  split/coalesce, rollback after each physical/table publication boundary,
  stale transfer/frame/slot reuse and final retirement. Foreign/stopped-MM
  copy must retain prefix and progress with every default lease occupied.
- [ ] Budget: N1 fixed touched-leaf/extent/retained-byte bounds across its
  scale matrix; unrelated 512 mappings add no scan. Host fork projection=0;
  guest semantic MM host dispatch=0 for admitted operations. Remove their
  host scaffolds, not merely decrement a counter.
- [ ] Contracts: `kernel.el1.mm-exclusive-owner` (N1),
  `kernel.el1.stage1-publication`, `kernel.mm.address-space-occupancy`,
  `kernel.mm.pt-pause-drain-acknowledgement`, fork/exec stage1-image.
- [ ] Accept: `cargo test -p carrick-el1 -p carrick-mmu-core --lib`;
  `CARRICK_RUN_ID=kvm-m3 cargo test -p carrick-vmm-kvm --test carrier_memory`.

#### M3 preparation handoff to the accepted N1 owner

N1-independent preparation on `work/x86-m3prep` adds the x86 descriptor backend
and a dedicated carrier memslot owner. It does **not** bind a production
MmPortal, execute Linux memory syscalls in CPL0, admit reservations/permits,
implement the N1 cursor or claim M3 acceptance. No N1-owned file is edited.
The real-KVM fixture has two stopped/run-controlled CPUs and permanent MM
assignments; it is hardware evidence, not the M5 executor binding.

The owner calls the following x86 hooks, with its existing exact-MM editor,
entry exclusion, backing pins and publication/retirement transaction held.
These are the signatures implemented by this preparation (generic bounds are
shown once; paths are relative to `crates/`):

```rust
// carrick-mmu-core/src/x86/descriptor_txn.rs
// W: LiveDescriptorWords + ?Sized; J: DescriptorJournal + ?Sized
fn plan_descriptor_txn<W>(
    words: &W, txn: &DescriptorTxn<'_>, live_root: RootGpa,
) -> Result<DescriptorPlan, DescriptorRefusal>;
fn apply_descriptor_plan<W, J>(
    words: &W, plan: &DescriptorPlan, journal: &mut J,
) -> DescriptorReceipt;
fn rollback_descriptor_plan<W>(
    words: &W, plan: &DescriptorPlan,
) -> DescriptorOutcome;
fn execute_descriptor_txn<W, J>(
    words: &W, txn: &DescriptorTxn<'_>, live_root: RootGpa, journal: &mut J,
) -> DescriptorReceipt;
fn translate<W>(
    words: &W, root: RootGpa, va: UserVa, access: Access, user: bool,
) -> Result<FrameGpa, FaultClass>;
fn DescriptorTxn::verify_receipt(
    &self, receipt: &DescriptorReceipt,
) -> Result<(), DescriptorRefusal>;

// carrick-vmm-kvm/src/carrier_memory.rs
fn CarrierMemory::install(
    &mut self, backings: &[PreparedBacking],
) -> Result<Vec<BackingHandle>, MemoryError>;
fn CarrierMemory::install_root(
    &mut self, mm: NonZeroU64, context: AddressContext<RootGpa>,
) -> Result<(), MemoryError>;
fn CarrierMemory::words(&self) -> DescriptorWords<'_>;
fn CarrierMemory::publish<I: InventoryTransaction>(
    &mut self, txn: &DescriptorTxn<'_>, backings: &[PreparedBacking],
    inventory: &mut I,
) -> Result<(DescriptorReceipt, Vec<BackingHandle>), MemoryError>;
fn CarrierMemory::share(
    &self, handle: BackingHandle,
) -> Result<SharedFrameEdge, MemoryError>;
fn CarrierMemory::attach_shared(
    &mut self, mm: NonZeroU64, edge: &SharedFrameEdge,
) -> Result<(), MemoryError>;
fn CarrierMemory::revoke<D: TranslationDrain, I: InventoryRetirement>(
    &mut self, handle: BackingHandle, drain: &mut D, inventory: &mut I,
) -> Result<(), MemoryError>;
fn CarrierMemory::read(
    &self, pa: FrameGpa, len: usize,
) -> Result<Vec<u8>, MemoryError>;
fn CarrierMemory::write(
    &mut self, pa: FrameGpa, bytes: &[u8],
) -> Result<(), MemoryError>;
```

N1 supplies these implementations; the fixture callbacks are test scaffolding
and cannot substitute for the accepted owner:

```rust
trait InventoryTransaction {
    fn publish(&mut self) -> Result<(), MemoryError>;
    fn commit(&mut self, receipt: &DescriptorReceipt) -> Result<(), MemoryError>;
    fn rollback(&mut self) -> Result<(), MemoryError>;
}
trait InventoryRetirement {
    fn retire(&mut self, identity: BackingIdentity) -> Result<(), MemoryError>;
    fn rollback(&mut self) -> Result<(), MemoryError>;
}
unsafe trait TranslationDrain {
    fn drain(&mut self, plan: ShootdownPlan) -> Result<(), MemoryError>;
}
```

- **Admission / identity:** N1 issues the exact MM key, root, context generation,
  transaction generation, unlinked zeroed table grants and BackingIdentity
  (frame/mapping/owner generation/inventory revision). `RootGpa`, `FrameGpa`,
  `UserVa` and `AddressContext` reuse `carrick-guest-arch`; transaction identity,
  backing identity, PageSpan, descriptor words and journals reuse the existing
  ARM-independent definitions exported by ARM's descriptor module. No ARM
  descriptor encoding or EL1 ABI layout is copied or changed. A future common
  owner interface can associate each ISA's operation/plan/receipt types while
  retaining these same identity and word/journal types.
- **Publication:** the root/table arena is installed before planning; grants remain inside that
  retained primary extent, as in ARM's primary-table window. A published root
  prevents arena revoke. Root arena retirement/reuse remains the accepted
  N1/M5 root-retirement binding; this preparation retains it until carrier
  destruction. New data
  extents may be passed to `publish`. N1's `publish` callback authenticates and
  publishes real inventory readiness after slot installation, before present
  leaves. `commit` settles the exact verified descriptor result, never physical
  old-owner retirement. Failed callbacks, descriptor stores and slot installs
  undo the entire unit. Unprovable undo quarantines and retains registered
  backing until VM destruction. Table grants are returned only after owner
  settlement; coalesced table pages likewise require the owner's drain before
  recycling. The backend never allocates a reservation arena or a shared-zero
  COW source.
- **First touch / COW / user transfer:** normalize x86 PF P/W/U/I and CR2 at the
  architecture seam, then let the accepted reservation/owner policy choose the
  operation. `Map { resident: false }` retains private prepared output;
  `Publish` exposes that exact output. `ArmCow` removes write permission;
  `CowRepoint` validates the old output and restores recorded write intent.
  N1 copies pinned bytes before repoint and supplies the new identity. Its
  UserTransfer permit authenticates the live root and exact backing generation
  around `translate` and bounded `read`/`write`; a hardware walk or physical pin
  alone grants no semantic rights. Foreign-MM/prefix/lease progress is still
  the N1/M5 binding, not this fixture.
- **Drain / retirement:** descriptor-word maintenance in the stopped adapter
  deliberately has no hardware invalidation instruction. N1 must hold entry
  exclusion and perform the trailing CPL0 drain after success **or rollback**
  before re-entry. `revoke` rejects retained physical aliases, collects the
  exact previously unlinked contexts and requests `ReloadCr3`; every live or
  parked CPU that could hold that generation must acknowledge before deletion
  and inventory retirement. A failed inventory retirement reinstalls the exact
  old slot/backing/generation. The unsafe drain trait states that hardware
  obligation explicitly; ioctl completion is insufficient. `Invlpg(PageSpan)`
  is the narrow-range plan form, while this initial fixture uses one actual
  CPL0 CR3 reload per affected context. PCID/global mappings are not admitted.
  The fixture consumes pending KVM IO completion before saving and restoring
  the temporary drain context, preventing replay of the interrupted doorbell.

Preparation witnesses bind `kernel.el1.stage1-publication`,
`kernel.mm.address-space-occupancy` and
`kernel.mm.pt-pause-drain-acknowledgement`. Semantic authority is Linux
`mmap(2)`, `mprotect(2)` and `fork(2)` plus the Intel SDM four-level paging/PF
encoding; this lane uses direct executing hardware fixtures, without Docker.
Deterministic budgets: a fresh n-page map uses n + 3 stores and three tables at
16/64/256 pages; unrelated PML4 branches add no reads. Whole 1 GiB protection
uses one store and no split tables. One extent uses one slot at 16/64/256
pages, with retained bytes equal to its supplied size. Physical alias unlink
visits one touched edge at 16/128/512 unrelated populations.

Red evidence: the MissingTable descriptor stub failed publication/rollback;
no-op physical undo left one slot after second-install failure and two after
inventory failure. The executing revoke fixture initially replayed a previous
byte doorbell across a drain context switch; consuming KVM IO completions made
it detect actual first-touch faults after revoke. All six executing witnesses
cover distinct same-VA bytes, explicit shared edges, first-touch retry, COW
break, NX/RO fault classes, warm translation revoke, generation reuse and
both-root shared retirement. Full verification and receipts are recorded below
when completed; remote host receipt is **director-queued**, and macOS signed,
Docker and accepted N1/M5 integration remain director-owned.

### M4 — shared scheduler, timer/wake and IPC on CPL0

**Fence:** new x86 `cpl0_scheduler.rs`/`interrupts.rs`, KVM
`carrier_interrupts.rs`, `tests/cpl0_progress.rs`; landed common EL1/sched/fd/
pipe-core hook parameterization and existing shared tests. Wait for overlapping
N1/N2 slices. No new scheduler/pipe/futex implementation or shared runtime.

- [ ] Implement context switch, interrupt/timer, address-context install and
  wake delivery hooks. Use the same sched-core records/queues, IPC ownership
  and signal/timer policy. No host pthread waits/futex/pipes for guest tasks.
- [ ] Red: two live processes with same-VA futexes do not cross-wake. Exhaust
  the common scheduler fixture at the **default** executor-capacity bound
  with `max(32, actual_executor_count + 1)` partial pipe writers and a
  runnable reader, overrides unset. Record actual capacity (pool.rs:83):
  requested defaults are P bound + 2P spare (pool.rs:91/:104), so willow may
  have 36 workers, subject to backend ceiling/reserve. Stage the fixture to
  prove every lease claimed before admitting the reader, then drive the
  blocking writes: a wait releases its lease. Prefix survives migration and all bytes appear
  once. Race enqueue/wake/cancel, close/reuse and timed interruption; preempt
  a syscall-free compute loop. No swallowed guest signal or lost kick.
- [ ] Budget: blocked worker occupancy=0, one owned wait/completion episode,
  zero semantic host forwards for admitted IPC/scheduling/timer operations;
  only declared external readiness/clock/control inputs may cross. Remove
  each corresponding fallback. No larger pool or poll-based progress.
- [ ] Contracts: `kernel.el1.ipc-two-process`,
  `kernel.scheduler.host-wait-handoff`, `kernel.scheduler.runnable-progress`,
  `kernel.signal.lease-gap`, `kernel.mm.executor-admission`.
- [ ] Accept: `cargo test -p carrick-el1 -p carrick-sched-core -p carrick-fd-core -p carrick-pipe-core --lib`;
  `CARRICK_RUN_ID=kvm-m4 cargo test -p carrick-vmm-kvm --test cpl0_progress`.

### M5 — persistent KVM carrier binds the shared runtime

**Fence:** KVM `carrier.rs`/`executor.rs`, x86 carrier CPU implementation,
`tests/carrier_runtime.rs`; **first runtime edits** at executor/backend.rs,
executor/binding.rs, continuation/quantum.rs, hvpatch root-resource/retirement
adapters and loop registration. Requires N1 **and lifecycle Phase B landed**.
No proc/IPC/MM policy changes or OCI refusal removal yet.

- [ ] One VM/physical inventory, bounded persistent vCPUs and the existing
  pool/admission/cancellation authority. Split bootstrap VM/CPU from guest
  task/MM ownership; never reuse KvmVmm's host-fork rebuild path. Replace
  ARM-specific root/ASID proof types with typed backend proof adapters.
- [ ] Red: saturate the default pool across two live MMs while transfer,
  host-readiness continuation and cancellation compete. Bind/save/rebind
  exact TaskLoadIdentity once; delayed completion after reuse refuses.
  Parked vCPU/slot/root retirement leaves no live capacity or stale translation.
- [ ] Budget: guest fork/clone cause zero host-process creation; waits consume
  no worker capacity; physical frame/slot growth follows owner receipts only.
  Repeat M4 exhaustion on the actual persistent runtime pool, not only the
  guest scheduler fixture; guest helper progress must not need a spare lease.
  Register KVM contract bindings; compile runtime tests with explicit Linux
  feature closure instead of silently discarding all cross-platform failures.
- [ ] Contracts: task-load-entry, executor-admission, carrier-window-isolation
  (`kernel.mm.carrier-window-isolation`), host-wait-handoff and resource-scope
  (`kernel.dispatch.resource-scope`).
- [ ] Accept: `cargo test -p carrick-runtime --no-default-features --features platform-linux --lib`;
  `CARRICK_RUN_ID=kvm-m5 cargo test -p carrick-vmm-kvm --test carrier_runtime`;
  `cargo build -p carrick-cli --no-default-features --features platform-linux`.

### M6 — N2 x86 lifecycle/exec hooks and first OCI shell

**Fence:** x86 clone/TLS/signal-frame/auxv/successor hooks and new
`tests/carrier_oci.rs`; runtime prepare/lib backend selection and kernel
page_profile capability selection. Consume the **same landed N2** task/fd/
signal/loader transactions. No duplicate kernel graph or host semantic lane.
N2's multi-landing policy work is a dependency, not hidden inside this landing.

- [ ] Bind x86 raw clone/fork/vfork ABI, signal delivery/sigreturn/restart and
  ELF successor state to common policy. CLONE_VM/FILES/SIGHAND relationships,
  Born/adopt/settle and robust/clear-tid follow Phase B/N2 exactly. File reads
  cross for bytes; owner permits/cursor and ELF interpretation stay common.
- [ ] Red: today's OCI attempt exits 125 before execution. Two live same-VA
  processes run fork/pipe/wait and vfork/exec; exhaust creation/pool capacity,
  fail successor preparation, reuse TIDs and deliver signals during wait.
  No host task birth service or replay of an already served operation.
- [ ] **First OCI `/bin/sh -c 'echo ok'` is here**, not M2 or run-elf. Exact
  artifact output must be `ok\n`, exit 0, followed by scoped resource cleanup.
  Add a dynamic-loader/child shell case; an echo builtin alone proves little.
  Remove remaining creation/exec semantic scaffolds for the admitted path.
- [ ] Contracts: N2 `kernel.el1.creation-native-path`, thread-lifecycle,
  signal-delivery-owner, `kernel.fork.{mappings,filetable,stage1-image}`,
  `kernel.exec.stage1-image`, child-rusage/child-exit-notification-lifecycle.
- [ ] Accept: `cargo test -p carrick-kernel-example --test n2_creation`;
  `CARRICK_RUN_ID=kvm-m6 cargo test -p carrick-vmm-kvm --test carrier_oci`;
  `cargo build --release -p carrick-cli --no-default-features --features platform-linux`;
  `CARRICK_RUN_ID=kvm-m6-shell target/release/carrick run --platform linux/amd64 ubuntu:24.04 -- /bin/sh -c 'echo ok'`.
  Pre-fetch/pin image bytes without Docker; record resolved digest.

### M7 — live KVM gate and cost/accounting closure

**Fence:** KVM contract/test bindings, xtask/justfile feature-closed gate,
next/retained probe lane routing and receipts. No new semantic implementation
or performance budget relaxation. Unaccepted workloads remain explicitly open.

- [ ] Red: gate refuses an absent executing binding, wrong/stale artifact,
  missing exit classification or resource leak. Retain per-capability zero
  semantic-forward budgets; any unported syscall is a named remaining gap,
  not allowed hidden dispatch in a supposedly admitted capability.
- [ ] Register a required KVM carrier acceptance command/receipt. Run static
  and dynamic OCI, two-process and exhausted-pool witnesses on one exact
  artifact; rebuild after every merge. Keep real host-work/maintenance counts
  separate from semantic forwards. No current HVF zero-register-I/O budget
  is mechanically claimed for KVM (`kernel.transport.exit-overhead`).
- [ ] Contracts: all M1–M6, deterministic work budgets first; full intended
  supported workload set then ≤2x same-image native-x86 Docker on the declared
  quiet host class. N1/N2 ARM gates still apply to the shared kernel.
- [ ] Accept here: `just fmt-check`; proposed
  `just accept --phase kvm --receipt target/kvm-carrier-accept.json`;
  proposed `just kvm-carrier-smoke`; `just conformance-probes` with executing
  KVM routing. Existing `just kvm-smoke` targets hello-aarch64 (justfile:871)
  and is not an x86 carrier gate; do not count it as one.
  Native-x86 Docker authority/timing is a **separate serial director phase**,
  unavailable in this no-Docker task. A failed ratio is unfinished correctness.

## 6. Risks and open decisions

| Risk / question | Recommendation |
| --- | --- |
| Should CPL0 wait behind a complete host carrier? | No. Owner confirmed coalesced CPL0-first. M1/M2 expose real shared serving early; delete scaffolds per slice. |
| Package naming vs N1 churn | Keep one existing common library during N1/N2, thin ARM/x86 images; defer neutral package rename. Ask owners to confirm KernelArch/new crate names at hand-off. |
| ARM state/layout leaks in ABI and no_std code | Normalize events/context types, separate common/native hashes, explicit ISA guards. Native tests cannot validate freestanding assembly; build both images and live-test both architectures. |
| N1 accepted surface/cursor not yet final | Bind actual production owner/permit/cursor; snapshot is source-read. Wait at collision points, preserve owner budgets and provenance. No invented substitute API or private MM graph. |
| N2/Phase B graph authority during guest serving | One transaction/storage authority and exact generation; claim/commit in common kernel, host observer projects it. No reserved_tid map, host PID identity or mirror reconciliation. |
| PCID, APIC/timer, XSAVE and nested capability differences | Capability-qualified hooks; initial no-PCID path is an explicit hardware mode, not weakened isolation. Preserve full CPU state, bounded interrupt/wake progress and arithmetic clock conversion. Feature gaps fail before task publication. |
| Memslot limits / rollback / shootdown | Extent-based custody with typed generations and fail-closed rollback; async drain of only affected contexts. Qualify limits live before accepting a population. |
| 4 KiB vs ARM 16 KiB capacity geometry | Parameterize physical policy with N1 owner, retain comparable byte/extent bounds and exact receipts. Do not reuse ARM-specific masks or shrink semantic workloads. |
| Nested result cannot close ≤2x gate | Publish nested/bare-metal class for every receipt; arrange same-image native-x86 Docker later. Keep workload gate open; do not extrapolate 24.2 ns synthetic control into service timings. |
| Existing Linux host acceptance reds | Repair feature-closed test/gate routing in a separately fenced landing; preserve actual kernel failures. No platform skips or broad permission-predicate workaround. |

## 7. Verification performed for this plan

All output is under `target/kvm-carrier-plan/`; no production source changed.

- **Pass:** Linux CLI build, x86/KVM libraries 58 tests, kernel-example contracts
  25 tests, native EL1/sched/fd/pipe libraries 330 tests, ARM EL1 freestanding
  compile-check; release KVM benchmark,
  focused example clippy, corrected-source Semgrep/host-authority checks
  (`./scripts/lint-domains.sh`, exit 0) and `just fmt-check`. Commands/receipt below.
- **Not pass:** runtime executor test target compilation (129 errors) and
  full host acceptance. `target/kvm-carrier-plan/accept-host.json` records
  clean HEAD `682a30d6d`, FAIL: kernel 8 failures (same named set as lane
  receipt), cross-platform test/HVF compilation, VFS clippy dead code,
  lint-domains and closure-probe inventory. Its raw-syscall lint finding was
  this benchmark's defect, corrected in `25e0ea15d`; do not classify it as a
  pre-existing failure. A later lint attempt lacked offline
  addr2line; after `cargo fetch --locked` succeeded, `just lint-domains`
  reached the existing runtime-abort fingerprint drift in vcpu-loop.json
  for ProductionHvpatchLoopJob::service_outcome (binding.rs), before Semgrep.
  The focused corrected-source Semgrep/escape gate passes independently;
  the wider inventory gate remains red. None of these receipts accepts a carrier.

```sh
cargo build -p carrick-cli --no-default-features --features platform-linux > target/kvm-carrier-plan/build-linux.log 2>&1
cargo test -p carrick-x86 -p carrick-vmm-kvm --lib > target/kvm-carrier-plan/x86-kvm-tests.log 2>&1
cargo test -p carrick-kernel-example --test contracts > target/kvm-carrier-plan/kernel-contracts.log 2>&1
cargo test -p carrick-el1 -p carrick-sched-core -p carrick-fd-core -p carrick-pipe-core --lib > target/kvm-carrier-plan/neutral-kernel-tests.log 2>&1
cargo build -p carrick-el1 --bin carrick-el1 --target aarch64-unknown-none-softfloat --release > target/kvm-carrier-plan/el1-arm-build.log 2>&1
cargo test -p carrick-runtime --no-default-features --features platform-linux --lib vcpu_loop::executor::tests:: > target/kvm-carrier-plan/executor-tests.log 2>&1
just accept --phase host --receipt target/kvm-carrier-plan/accept-host.json > target/kvm-carrier-plan/accept-host.log 2>&1
cargo fetch --locked > target/kvm-carrier-plan/fetch.log 2>&1
just lint-domains > target/kvm-carrier-plan/lint-domains-corrected.log 2>&1
./scripts/lint-domains.sh > target/kvm-carrier-plan/semgrep-corrected.log 2>&1
just fmt-check > target/kvm-carrier-plan/fmt-final.log 2>&1
```

Benchmark commands/hashes/sample population are in the
[separate receipt](../../perf-results/2026-10-04-kvm-syscall-round-trip.md).
This is an execution plan with checked reuse evidence and declared dependencies,
not production readiness, a hardened boundary or accepted workload coverage.
