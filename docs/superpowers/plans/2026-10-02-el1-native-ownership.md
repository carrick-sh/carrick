# EL1 native ownership: cut over objects, deliver workloads

Design proposal, 2026-10-02; no implementation or runtime acceptance.
Inspected native-design HEAD `8bcd7fd974b6c7028a1c2bb578ac90618ed3aba6`.
Admission branch was read-only at
`cd7d4b335d738d3e995bf15f770b23fe0a68e642`; its two dirty copyout
fixture files are not accepted evidence. Re-inventory the clean integrated
source before implementation: line ranges below belong to this snapshot.

Authorities: [rulebook](../../../AGENTS.md),
[accepted spec](../specs/2026-09-24-el1-kernel.md),
[controller](2026-09-26-el1-completion.md),
[memory completion](2026-10-02-el1-step2-memory-completion.md),
[descriptor/IPC](2026-10-02-el1-step3-fds-ipc.md),
[names/pages](2026-10-02-el1-step4-names-pagecache.md),
[lifecycle](2026-09-30-el1-thread-lifecycle.md), and
[contracts](../../conformance-contracts.md).
This proposes changing the spec's implementation order, not its end state,
Linux semantics, <=2x native-arm64 Docker goal, elasticity, or host scheduling.
The director must adopt the new ordering before dispatching implementation.

## 1. Decision and evidence

**Agree with the ownership thesis; agree with workload ordering as a delivery
strategy, with two qualifications.** The seam is more than two independent
copies: current code sometimes reads live EL1 tables and executes the same
transaction engine on the host under exclusion. That improves coherence but
still leaves two execution venues deciding how one live object changes.
Subsystem extraction remains useful for reusable no_std cores; it should not
be the acceptance unit for a workload spanning those cores.

Evidence in code:

- `Stage1Authority::select_guest_descriptor_owner` makes the host manager
  live on the tables EL1 edits (stage1 source, lines 380–420). This is already
  stronger than a stale shadow. But `prepare_guest_descriptor_txn` lets the
  host plan table capacity/operations, and `execute_guest_descriptor_txn_as_host`
  / `apply_submitted_as_host` let an exclusion holder perform stores
  (438–566). Guest descriptor ownership does not yet imply EL1-only MM policy.
- `build_process_plan` takes `&mut PageTableManager` (process-plan 476–484),
  invalidates omitted mappings (740), maps aliases (1216–1223), restores the
  quiesced table image to host backing (1607–1610), and constructs child
  `MemoryProtections` from the parent's snapshot (1679–1680). The child is
  not born from an exclusively EL1-owned memory-fork transaction.
- `GuestMemory::read_bytes` and `write_bytes` reject through the protection
  mirror before calling raw access (guest-mem 473–507). Engine writes add
  another mirror check before COW and translated copy (engine 3008–3040).
  An EL1-served mapping can be hardware-accessible yet fail this earlier gate.
- `MemState` already distinguishes host setup from delegated anonymous
  authority, but delegated roots have a host proposal venue
  (anonymous 92–117, 379–433). `brk` explicitly plans in either venue
  (brk 44–119, 181–231). Therefore this is not a request to undo the good
  single-root work: remove host Linux decisions against that root.
- `perform_frame_cow`, sole-owner reuse, physical-source authentication and
  host publication remain in cow-engine (3065–3231, 4708–5009,
  6695–7479). Copyout is consequently coupled to host memory ownership,
  not just host custody of physical backing.

The read-only admission branch has **61 commits ahead of current main**:
34 `fix`, 15 `chore`, 4 `test`, 3 `feat`, 3 `diagnostics`, one `refactor`,
one `perf` (classification by subject prefix, not defect count). Concrete
seam repairs include `8f11b44a1` (settle backing before fork snapshots),
`dcf64d022` (hidden backing in proc maps), `12dccba02` (copyout into untouched
reservations), `bd1f11c53` (live-VMA fork projection), `b4dcd0b1a`
(descriptor-granular projection), `39480a8f7` (retired projection builder),
`6550c4f49` (current-MM predecessor alias), and `dcdfb6fda` (overlay storage
across fork). `bd1f11c53` changes six files, 351 insertions/94 deletions;
`6550c4f49` changes four, 111/6. These are concrete maintenance burden;
commit counts alone do not measure elapsed engineering time or prove every
reported bug's cause. The user-reported protection-mirror EFAULT is consistent
with the pre-gate above, but this pass did not reproduce it.

Measured source: the supplied sibling-worktree report
`/Volumes/CaseSensitive/carrick/.worktrees/wt-step2-prep/docs/perf-results/2026-10-02-fork-cow-exit-attribution.md`,
capture g on `0d7d166f6`. It is external evidence, not a receipt for this HEAD.
20 forks at 16 pages yielded 3220 exits = **161/fork**, unchanged ceiling 144.
Its 18 service IDs account for 1748 HVC exits: lifecycle/identity/signals
728 (36.4/fork), memory 563 (28.15), IPC/wait 457 (22.85). Together these
are 87.4/fork, only 54.3% of all exits. ASID invalidation associates with
179 HVC exits (8.95/fork), but overlaps those services. Six host fault-COW
resolutions are 0.3/fork; 102 `perform_frame_cow` events include other phases.
Do not sum overlapping function rows or infer a per-page COW bottleneck.

Remaining: 423/2171 HVC exits without a same-thread service begin;
366 canceled, 393 idle, 50 kick, 240 maintenance. Only 54 idle exits join
resumed services. Mapping arguments/admission identity were not captured.
Thus an exact residual forecast or causal ordering of every pause is unproved.
The plan changes delivery order on the qualified cross-subsystem evidence,
not on an invented exclusive cost partition. Exit removal is not a CPU claim.

The inotify precedent is the **born-in-zone pattern**, not permission to copy
all today's inotify fallback machinery: the accepted spec's Evidence and
end-state sections explicitly reject delegate/recall. Today's
`personality/inotify.rs` still says delegated and forwards spilled/unsupported
cases (19, 110–159, tests 345–390); host notify still recalls watched paths
(notify 408, 501, 698). Reuse its shared core/identity lessons, not those seams.

**Decision:** irreversible cutover of an entire MM incarnation, including
its readers and exceptional writers, followed by one creation-workload slice
across task, memory, fd, wait and signal owners. Do not keep operation-by-
operation host fallback inside an admitted MM. Preserve the rest of the
migration as mandatory follow-on scope, not a reduced definition of done.

## 2. EL1-only address space: host removal inventory

Source key (all paths below relative to `crates/`; link targets are source):

| Key | Source |
| --- | --- |
| stage1 | [stage1_authority.rs](../../../crates/carrick-aarch64/src/stage1_authority.rs) |
| engine | [engine.rs](../../../crates/carrick-aarch64/src/engine.rs) |
| guest-mem | [lib.rs](../../../crates/carrick-guest-mem/src/lib.rs) and [protections.rs](../../../crates/carrick-guest-mem/src/protections.rs) |
| backend | [hvf_aarch64_engine.rs](../../../crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs) |
| process-plan | [process_plan.rs](../../../crates/carrick-vmm-hvf/src/trap/process_plan.rs) |
| cow-engine | [cow_engine.rs](../../../crates/carrick-vmm-hvf/src/trap/cow_engine.rs) |
| guest-copy | [guest_memory.rs](../../../crates/carrick-vmm-hvf/src/trap/guest_memory.rs) |
| host-access | [host_writes.rs](../../../crates/carrick-vmm-hvf/src/trap/host_writes.rs) |
| foreign | [foreign_mm.rs](../../../crates/carrick-vmm-hvf/src/trap/foreign_mm.rs), [current_read.rs](../../../crates/carrick-vmm-hvf/src/trap/foreign_mm/current_read.rs), [instruction_read.rs](../../../crates/carrick-vmm-hvf/src/trap/foreign_mm/instruction_read.rs), [el1_publication.rs](../../../crates/carrick-vmm-hvf/src/trap/foreign_mm/el1_publication.rs) |
| inventory | [frame_inventory.rs](../../../crates/carrick-vmm-hvf/src/trap/frame_inventory.rs), [memory_protection.rs](../../../crates/carrick-vmm-hvf/src/trap/memory_protection.rs), [task_mapping_index.rs](../../../crates/carrick-vmm-hvf/src/trap/task_mapping_index.rs) |
| grants | [guest_cow.rs](../../../crates/carrick-vmm-hvf/src/trap/guest_cow.rs), [sparse_materialization.rs](../../../crates/carrick-vmm-hvf/src/trap/sparse_materialization.rs), [guest_alias.rs](../../../crates/carrick-vmm-hvf/src/trap/guest_alias.rs) |
| exec | [execve_rebuild.rs](../../../crates/carrick-vmm-hvf/src/trap/execve_rebuild.rs) |
| memory policy | [mem.rs](../../../crates/carrick-kernel/src/dispatch/mem.rs), [mmap.rs](../../../crates/carrick-kernel/src/dispatch/mem/mmap.rs), [brk.rs](../../../crates/carrick-kernel/src/dispatch/mem/brk.rs), [anonymous.rs](../../../crates/carrick-kernel/src/dispatch/mem/anonymous.rs), [backing.rs](../../../crates/carrick-kernel/src/dispatch/mem/backing.rs), [vma.rs](../../../crates/carrick-kernel/src/dispatch/mem/vma.rs), [madvise.rs](../../../crates/carrick-kernel/src/dispatch/mem/madvise.rs) |
| runtime | [mod.rs](../../../crates/carrick-runtime/src/vcpu_loop/mod.rs), [binding.rs](../../../crates/carrick-runtime/src/vcpu_loop/binding.rs), [signal.rs](../../../crates/carrick-runtime/src/vcpu_loop/signal.rs), [crash.rs](../../../crates/carrick-runtime/src/vcpu_loop/crash.rs), [lifecycle.rs](../../../crates/carrick-runtime/src/vcpu_loop/lifecycle.rs), [quiesce.rs](../../../crates/carrick-runtime/src/vcpu_loop/quiesce.rs) |
| observers | [proc.rs](../../../crates/carrick-kernel/src/dispatch/proc.rs), [proc VFS](../../../crates/carrick-kernel/src/vfs/proc.rs), [rw.rs](../../../crates/carrick-kernel/src/dispatch/fs/rw.rs), [ioctl.rs](../../../crates/carrick-kernel/src/dispatch/fs/ioctl.rs) |
| pause | [mm_quiesce.rs](../../../crates/carrick-kernel/src/dispatch/mm_quiesce.rs), [mm_mutation.rs](../../../crates/carrick-kernel/src/dispatch/mm_mutation.rs), [fork_quiesce.rs](../../../crates/carrick-thread/src/fork_quiesce.rs), [dispatch/mod.rs](../../../crates/carrick-kernel/src/dispatch/mod.rs) |
| windows | [memory.rs](../../../crates/carrick-mem/src/memory.rs), [vdso.rs](../../../crates/carrick-mem/src/vdso.rs) |

This is an inventory of host **access venues**, including reads and policy,
not just descriptor stores. The 30 rows cover the provider interfaces and
special consumers; ordinary syscall consumers are closed together at their
GuestMemory capability, rather than listing every scalar/struct copy call.
“Delete” means remove the admitted-MM implementation/capability, preserving
other backends only as venues of the same shared core. Named `MmPortal`
operations are proposed, not APIs this pass claims exist.

| # | Current path / functions and line evidence | Admitted-MM disposition |
| --- | --- | --- |
| 1 | stage1 189–258, 380–566, 590–596: manager/resolver binding, owner selection, host planning, host execution under exclusion | Delete live host manager/resolver/edit authority. Consume `BootMmBuilder` once into `El1MmHandle`. EL1 builds plans against its live tables. No `execute_guest_descriptor_txn_as_host` or `apply_submitted_as_host` for this handle. |
| 2 | stage1 685–801, 951–1154: image snapshot/recycling, with_manager, undo/restore, edit, exec predecessor adoption | Delete host live snapshots/undo. EL1 owns image allocation/rollback/recycling. Immutable root identity may be exported; it is not an image or editor. |
| 3 | guest-mem 455–526; engine 2923–3058; backend 2339–2341: protection pre-gates and write-denied mirror | Delete admitted `MemoryProtections` storage and its snapshot/setters. Override the checked entry, not merely raw access. `MmPortal::UserTransfer` checks live VMA permissions and resolves lazy/COW pages in EL1. Returning None for protections alone is unsafe unless every raw escape is also closed. |
| 4 | engine 2617–2757, 2927–3090: syscall_buffer_ipa/chunk, el1_private_range_permits, prepared writes, ensure_frame_cow_write | Replace host walks and COW planning with `UserTransfer`; no VA==IPA fallback. Retain byte segmentation only on authenticated transfer extents. |
| 5 | guest-copy 217–395, 466–593, 831–1028: host_ptr/read_gpa/write_gpa, translated read/write, contiguous pointer/host_read/host_ptr_for_write, validation | Remove guest-VA pointer APIs for admitted MMs. `UserTransfer` or a bounded `TransferLease` names the exact live physical span. Host pointers remain private inside stage-2 custody; cannot be constructed from GuestVa. |
| 6 | guest-copy 593–830: zero_guest_backing/targets and remap scrub; 1165–1239 copy_guest_mapping_in/out | EL1 initializes/zeros private pages and decides provenance. Host copies only granted transfer spans; no scrub of a retired VA's guessed predecessor. |
| 7 | host-access 38–190, 281–431: begin_access, admit_host_read, admit_contiguous, ContentWrite admission | Keep physical pin/content-coherence machinery for actual host transfers and executable publication, but require `TransferLease`. Delete host mapping/permission selection. Lease completion includes required I-cache publication before EL0 executable use. |
| 8 | foreign 343–382, 871–951: MmAccessState protections, manager, bind_cow_runtime; current_read 38–169, 266–339; instruction_read 48–112 | Replace current/foreign live table walks and mirror checks with `UserTransfer` addressed by exact target MM generation. Instruction inspection uses typed ReadInstruction mode; source snapshot is EL1-issued, not host VMA/registry truth. |
| 9 | foreign el1_publication 41–99, 162–219: authenticate/publish/for_target and borrowed drain vCPU | Replace descriptor/COW publication with `UserTransfer`. Preserve a scheduler-owned service context for a stopped target, not a host editor. Ptrace-stop does not require the target to run EL0 to answer. |
| 10 | process-plan 476–484, 740–869, 1216–1239, 1339–1487, 1607–1723: projection/filtering, map_aliased, table restore, child protections | Delete memory portion of build_process_plan. `MmPortal::Fork` creates child from the parent's live EL1 VMAs/leaves and frame references, commits permissions/TLBI, returns child handle. Host task preparation can consume completion until task cutover; cannot supply a host projection. |
| 11 | cow-engine 396–659: fork_cow_ranges, arm_frame_cow_ranges, frame_cow_arm_snapshot/restore; runtime lifecycle arm_parent, quiesce | Delete admitted host arming/snapshots. `Fork` owns parent/child publication and rollback under one EL1 transaction; retain task birth gate while lifecycle still needs it. |
| 12 | cow-engine 2954–3231, 4708–5012: candidate/write route, reuse_sole_owner_cow_in_place, perform_frame_cow, fault resolution/write routing | Delete all admitted host copy/reuse/AP decisions, including non-anonymous private pages. Reuse existing guest `resolve_guest_cow`; `UserTransfer` invokes that same owner for copyout. |
| 13 | cow-engine 6695–7479; inventory frame ownership and alias indexes (memory_protection 840, 1038–1493, 3315–3386) | EL1 owns semantic leaf/refcount/predecessor choice. Keep host extent ledger only for backing generation, host pointer, map/unmap, quota and physical pins. Delete process-visible alias searches and host reference counts as COW authority. |
| 14 | grants guest_cow 56–149, 238–348; sparse_materialization prepare 56, publish 264, publication 650–661, 912–924; cow-engine 1387–1769 | Replace per-page/per-compound guest policy with `Capacity` extent grants/returns. Host stage-2 map and failure rollback remain. Host does not authenticate a predecessor VA or install a leaf; grant has no semantic VA. |
| 15 | guest_alias authenticate/publish/retire/restore_identity/publish_host_alias/rollback 139–410; cow-engine repoint helpers 667–811, 2679 | Delete admitted host descriptor plans/fallback and identity restoration. `HostBacking` completion offers a pinned physical alias; EL1 transaction installs/retires it, with exact generation and rollback. |
| 16 | memory policy mmap_served 149, munmap_served 2275, mremap_served 2471, mprotect_served 3648 | Delete admitted host Linux decode/placement/protection/retirement decisions. EL1 syscall personality drives its one memory core; file mapping asks `HostBacking` for bytes/alias, never a host mmap policy answer. Invalid or unsupported flags use the same personality, not host fallback. |
| 17 | brk 44–119, 181–249; anonymous 324–445; mem semantic_vmas_snapshot 602 | Delete host proposal venue and break/arena/mapping charging decisions after cutover. ELF seed and resource-limit updates are inputs before publication or EL1 task-policy messages; queries use `MmPortal::Observe`. Host quota rejection remains distinct from Linux rlimits. |
| 18 | backing 49–114, 254–611: dynamic maps, private/shared file maps, remap snapshots, proc protection, boot/growdown trimming; vma 184–278 | Move all VMA kinds and merge/split/growdown/DONTFORK/WIPEONFORK to the EL1 view. Delete mutable host semantic maps, including non-anonymous overlays. Physical backing ledger retains no guest VMA shape. |
| 19 | madvise 57–91, 224–294, 438–638; mem 1773, 2275–2610: msync/mlock/mincore/madvise, residency/fault plans, private-file snapshot | EL1 owns discard/lock/residency/advice and rlimit charging. `Observe` returns residency where required; `HostBacking` performs actual sync/lock/native file effects. No host resident map reconciled after guest edits. |
| 20 | engine 1446–1725, 3162–3536, 3710, 4823: manager loading, stage1 rules, protection/unmap/discard/stale-fault repair | Delete admitted stage-1 edit venues, mirror setters and stale-fault repair. Faults resolve or signal at EL1; real stage-2 faults go to Capacity/HostBacking. Other backends call the same core through their adapter. |
| 21 | exec 542–739, 757, 933–1816: global exec plan/table relocation, reapply spans, new protections, trampoline/roots/vDSO | `MmPortal::ExecPrepare/ExecCommit` (one transaction) loads/builds successor at EL1 from backend bytes. No host edits predecessor or admitted successor. Keep bootstrap before EL1 exists, physical stage-2 switching/rollback (444–501), and immutable image supply only. |
| 22 | pause mm_quiesce acquire_mm_stage1_authority 220, other exact-MM mutation acquisitions; mm_mutation 478; dispatch pause_current_mm_for_capture 1294 | Delete admitted edit exclusion/TLS/sole-participant and host drain. EL1 short MM transaction + broadcast TLBI replaces it. Capture uses `Snapshot`; preserve task crash rendezvous until its EL1 replacement exists. |
| 23 | carrick-thread fork_quiesce PtQuiesce/bind_mirror; runtime quiesce prepare_in_process_fork, lifecycle; engine retirement adapters | Remove page-table fencing/kick-drain/mirror. Preserve lifecycle ForkClosing and AddressSpaces closed/retirement/occupancy proofs. They protect runnable/register/root lifetime, not host page-table editing. Task fork pause itself goes in vertical task cutover. |
| 24 | observers proc ptrace 2560, process_vm_readv/writev 3724–3867; foreign memory interfaces | EL1 owns permission and Linux operation semantics; during transition observer adapter submits `UserTransfer` (privileged POKE distinct from user copy). Retain instruction-content coherence, stop ownership, completed-prefix/EFAULT/ESRCH rules. No blanket privileged-write bypass. |
| 25 | observers VFS proc 978–1038; fs/rw 1122–1287; fs/ioctl PROCMAP_QUERY 699; backing proc_maps metadata | `Observe` produces maps/pagemap/residency metadata from exact live MM and semantic VMA tree; /proc/mem transfers use UserTransfer. Delete cached host synthesis as authority. Keep existing foreign-proc access refusal until explicitly extended, not silent new access. |
| 26 | runtime crash capture_core_for_publication 207–715, MM pause 331; engine prepare_core_snapshot/read_core_bytes 4775–4822 | `Snapshot` freezes the exact task/MM generation and captures every thread including parked EL1 registers, sparse VMA/byte manifests. Host only serializes/writes the core to contained storage; cannot re-enumerate a host mapping snapshot. |
| 27 | engine inject_signal/restore 4000–4080; runtime signal delivery/restart; dispatch signal actions; kernel objects signal | Move Linux signal frame construction, permission/fault/restart and sigreturn validation to EL1. Transitional frame write uses UserTransfer with explicit SignalFrame mode, no unrestricted unchecked memory accessor. Vertical cutover deletes host delivery owner. |
| 28 | windows memory kernel-only range 466–500, trampoline/maintenance 210–297; exec roots/trampoline 1731–1761; populate_vdso_data_page 1816 | EL1 installs/seals code/windows in each MM from immutable boot manifest. Kernel windows never accessible by user-copy mode. Host retains clock calibration/vvar physical update on a dedicated carrier control capability, not arbitrary MM write. No host maintenance trampoline to repair an admitted root. |
| 29 | backend task-only projection 1106–1168, 1271–1359, 1410–1488; runtime wrappers runtime.rs 2386–2410; mapping_plan and carrier custody adapters | Replace host Stage1Authority + Arc<MemoryProtections> in runtime projection with El1MmHandle. Keep register save/restore, vCPU ownership, physical custody, bootstrap image mapping and transport. Wrapper cannot recreate raw memory access or pass a host builder through attach/detach/vfork. |


| 30 | foreign 2875–3198, 3489–3644, 3826–4138: perform_foreign_guest_cow, native activation, read/prepare_write/break_cow/borrow_native_data; mirror gate and live terminal walk at 4097–4128 | Native-region/instruction clients use UserTransfer with typed ReadInstruction/NativeData lease and owner-issued activation proof. Delete host COW and live-leaf/mirror authentication. Preserve physical CodeContent admission, exact generation pins, and native direct host byte access only while that proof is valid; mprotect/unmap/exec must revoke/drain activation without a host table editor. Native pointer activation is distinct from privileged ptrace POKE permission. |

Coverage method: traced both provider traits (GuestMemory and AArch64 VMM)
and their HVF implementations, then the exceptional foreign/fork/exec/capture
consumers. A narrower spelling census (`page_tables_authority`, manager
edit/snapshot/restore, protections queries/setters, `perform_frame_cow`) hits
18 source files excluding separately named test files/directories; it also
hits in-file tests and is **not** a reachability proof. Rows 16–28 deliberately
include paths that census misses. The inventory is exhaustive by access venue
at this inspected source; implementation closure additionally requires a
compiler-enforced fence over all callers, not trust in this table's permanence.

The implementation manifest must enumerate direct descriptor stores, table
resolvers, dynamic dispatch and failure/Drop/rollback paths beneath these
providers. No unclassified caller may be accepted. A host capability to a
live table, protection set, VMA tree, COW owner or raw GuestVa pointer is a
failure even if no current workload invokes it. Boot/other-backend exceptions
need types making an admitted handle unrepresentable there, not a boolean.

## 3. One interface and types that eliminate the reported seams

Use **one versioned `MmPortal` ring**, addressed by an opaque
`El1MmHandle { carrier, mm, incarnation }`, with operation incarnation and
bounded completion storage. It is part of the spec's existing hypercall ABI,
not a second transport. “Hypercall” below includes a host-enqueued request
serviced by EL1; the guest need not take an exit for every completion.
Control verbs Fork/Exec/Observe/Snapshot disappear from host Linux dispatch
as those consumers move to EL1; they remain owner operations, not host editors.
Steady physical boundary has three families:

| Family | Request / response authority |
| --- | --- |
| `UserTransfer` | Host requests copy-in/out or an authorized observer operation against the target's live translation. EL1 validates VMA and access intent, materializes zero/file pages, privatizes COW, and copies to/from bounded transfer storage. For direct native I/O, it may export an owned scatter `TransferLease`, never an unpinned pointer. |
| `Capacity` | EL1 requests bulk table/data/metadata extent capacity or returns wholly free extents. Host grants `ExtentGrant { ipa, len, generation, zero_provenance }` after stage-2 publication; no GuestVa or predecessor supplied. Returns consume exact grant generation after TLBI and all copy/table/alias pins retire. |
| `HostBacking` | EL1 requests bytes by pinned host handle/offset or a shared host-file alias. Host returns immutable completion/alias custody token and errors, not Linux mapping policy. EL1 alone installs leaves and owns private COW; live shared bytes remain host mapping owned. |

Proposed type boundary (names specify obligations, not implemented claims):

- `BootMmBuilder::seal(self, ...) -> El1MmHandle` consumes every host
  semantic capability. The handle has no Deref/manager/protection/VMA access;
  cloning it clones identity only. A bootstrap builder cannot take an admitted
  handle. Host roots for other backends have a distinct venue type.
- `El1MmTransaction` alone can access `LiveTables`, `VmaRoot` and
  `PrivateFrameRefs`; construction is private to EL1. Copy/reuse/install/
  retire/fork all run there with one MM lock/order and BBM/TLBI discipline.
  Shared-frame refcounts are one substrate authority, not a host mirror.
- `TransferIntent` is a closed enum (UserRead, UserWrite, authorized
  PtraceRead/Write, ReadInstruction, SignalFrame, coherent SnapshotRead).
  NativeData is a separate guest-store-permission lease, never inferred from
  ptrace COW success. Privileged construction requires the exact target
  operation/stop capability.
  Permission rules remain Linux personality inputs to the neutral substrate.
- `TransferLease` is non-Copy, owns exact physical generation pins and
  operation progress, and cannot become an MM editor. EL1 pins translation
  selection through each bounded transfer or prevents retire/repoint while a
  direct lease exists. Host returns a completion once, explicitly; Drop
  cannot synchronously wait for guest work. Cancellation retains storage/pins
  until settlement. No lock is held across host I/O; exec/fork revoke or drain
  leases through continuations, not parked host workers.
- `ExtentCustody` in host code accepts physical tokens only; it may validate
  stage-2 ownership/quotas and keep CodeContent/I-cache coherence. It has no
  Linux VMA, AP/COW state, predecessor lookup or semantic refcount API.
  A `ReclaimTicket` is consumed exactly once and only after EL1 references
  and physical transfer pins are gone. Wire tokens require validation even
  though local Rust construction is typed: EL1 is guest-reachable code.
- Fork result is `UnpublishedEl1Child` until task and memory commit compose;
  exec result is `PreparedEl1Exec`. Neither exposes tables to the host.
  Failure consumes rollback state on the owner. The child cannot run between
  memory publication and failed identity/fd commit.

Why each reported seam becomes unrepresentable: fork has no host memory plan
from which to project the child; munmap cannot leave a host-unmapped leaf
because host code has no unmap-by-VA operation; copyout resolves and pins lazy
reservations through the same owner as faults; there is no protection mirror
to refuse an EL1 mmap; Capacity has no predecessor VA or ownership decision
for a retired page. This eliminates those *classes of competing-authority
bug*, not all possible errors in EL1 transactions or malicious wire requests.

Bootstrap ELF supply, vCPU management, clock stamping, host stage-2 custody,
contained files/sockets/terminal and core-file writing remain host-native.
They do not justify a host live-MM view. Avoid a monitor VM CPU or a fixed RAM
reservation: stopped-target requests run as EL1 scheduler service work on the
existing carrier maintenance root. Prove service progress when every default
execution slot is otherwise waiting, before deleting the borrowed drain path.

## 4. Vertical slice: fork, exec and thread creation

**Acceptance unit:** existing spawn-loop, thread-spawn, fork-exec, and
20-round fork-COW workloads, including the libc scaffolding, with two live
processes and default execution capacity. Do not invent a smaller fixture
without signals/pipes/waits to declare success. Admit objects at construction;
extract shared cores as necessary, then remove their displaced host semantics.
An unsupported syscall can still request a real host operation through EL1;
it cannot hand the admitted MM/object back to host Linux dispatch.

| Measured syscall(s) | Required EL1 ownership and integration |
| --- | --- |
| clone (9/fork) | Both process fork and CLONE_THREAD use one task graph/identity authority. Reuse Phase B claim/birth/exit protocol, ForkClosing, credentials/uid credits and exact generations; MM Fork builds COW child; fd core copies table or shares CLONE_FILES; CLONE_VM/vfork have explicit shared-root lifetime. Publish tid words from live UserCopy and preserve oracle-qualified fault semantics. |
| exit (8), exit_group (1.05) | Extend Phase B beyond nonleader exits: robust walker, clear-tid/futex wake, accounting, group cancellation, last-thread destruction, zombie/status/SIGCHLD publication, root/frame/fd cleanup at EL1. A host notification of root command termination is a real process boundary, not per-child retirement. |
| wait4 (1) | EL1 child/zombie queues and rusage. Owned sleep/wake, WNOHANG, SIGCHLD, ECHILD, reparenting, autoreap and ptrace stop statuses. No host registry settlement per child wait or condvar placement. |
| set_tid_address (1.05), set_robust_list (1.05), gettid (8) | Extend/reuse Phase A control slot and immutable visible identity; one source for host observers during transition. Correct robust head validation and Linux return tid. Robust/clear-tid operates against current EL1 translation at exit. |
| sched_setaffinity (8) | EL1 validates Linux mask, allowed CPUs and task permission; scheduler applies guest CPU eligibility at placement/steal. Host schedules vCPU threads; guest affinity must not become carrier-thread affinity. Include remote tid and vanished/reused tid cases. |
| mmap (12.55), munmap (10.25), mprotect (5.3), brk (.05) | Reuse admission reservation core, prepared-page/capacity/retirement transactions; remove host proposal venue and protection mirror. Include file/stack/fixed mappings and private COW so unsupported shape cannot restore host memory authority. File misses/aliases use HostBacking. |
| futex (6.65) | Reuse sched-core object waits and EL1 futex handoff, with private/shared key identity, value-check/enroll ordering, robust owner death, clear-tid and lifetime under unmap/reuse. Remaining ops execute same core at EL1 or return oracle-correct result; no host futex model for admitted tasks. |
| ppoll (5.05) | Decode/enroll/readiness/temporary mask and EINTR/timeout restore at EL1. Pipe sets never exit for host readiness proxies; mixed host sets consume completion input in the same wait owner. No periodic scanning, replay or new host wait service for pipes. |
| pipe2 (2), close (8), write (.15) | Reuse fd-core/pipe-core and ABI IPC records, but create pipes in EL1 and own pair copyout/rollback, table allocation, final close, EOF/EPIPE/SIGPIPE, blocked partial writes and fd pins. Standard descriptors and all backing kinds use the same table; terminal/file write is a true backend crossing, pipe write is internal. |
| rt_sigaction (.25) | Move Sighand and signal pending/delivery/restart core, preserving CLONE_SIGHAND, fork/exec reset and SIGCHLD disposition. Port signal frame and sigreturn too; serving sigaction alone leaves a second signal owner. Reuse Phase A blocked mask/altstack storage. |

The rows are 18 IDs, not the entire exec ABI. **Exec is not present in the
attributed 18-ID histogram**. Fork-exec additionally needs execve/execveat,
contained name/image reads, ELF/PT_INTERP/auxv/stack/TLS/vDSO construction,
CLOEXEC/unshare, credential transitions, pending signal/mask rules, sibling
cancellation, robust/clear-tid handling and rollback before irreversible
commit. Reuse the image parser/loader logic as one shared core; host supplies
file bytes, EL1 chooses and installs the image. Dynamic-loader open/read/stat
and file mmap must use the one fd/name/MM owner; no disguised host ELF loader.
Phase B does not by itself implement process fork, wait4, last-thread exit or
exec; those are explicit work here.

Reuse/adaptation decisions:

1. **Admission:** keep exact-MM root/generation checks, shared reservation
   semantics, prepared-page state, retirement and custody failure tests. Its
   host settlement/projection fixes are safe transitional grounding, not the
   target architecture. New MM cutover replaces those protocols together.
2. **Phase B:** reuse identity pool, single ledger, early settlement and
   ForkClosing/exec admission/teardown rules. During task cutover the single
   authoritative graph becomes EL1-resident shared core; host observations
   become immutable views/requests. Do not retain indefinite deferred host
   publication as the owner of EL1-born task existence.
3. **stage2a:** continue bounded contained-parent namespace primitives.
   Fork-COW does not need the full name/page-cache migration first. Exec
   requires contained executable resolution and host byte input, so stage2a
   and the loader-relevant name owner are in its prerequisite closure.
   Wider names/cache work remains mandatory afterward; do not duplicate a
   special exec-only resolver beside the shared namespace core.
4. **Scheduler/MM-switch:** keep landed shared Occupancy/AddressSpaces and
   SGI/preemption. Delete host editing fences, not ASID retirement proofs.
   Work stealing/adoption/idle entry control claims must compose with EL1-born
   processes; the spec's known idle-entry control-claim race is a binding,
   not license to enable arbitrary idle-vCPU task execution.

### Exit expectation and falsifiable budget

Predict **zero host Linux syscall dispatches for the 18 IDs when their
operands are wholly in-zone**, zero host COW resolution, zero host descriptor
edits and host page-table pauses. Do not predict zero physical backend exits
for file write/mmap/exec or capacity exhaustion. Batch capacity requests by
extent/watermark, not fork/page; root status and startup are fixed boundary cost.
Steady warmed in-zone fork/thread/wait/pipe work should need **0 syscall exits
per fork**. Engineering expectation for the existing measured window is
**0–4 total host exits/fork plus fixed startup/termination cost**, not a
measured result or a replacement threshold. It requires cancellation/kick/
maintenance plumbing to disappear with owner cutover; the current report
cannot prove that forecast.

Formal acceptance stays unchanged: 20x16 <=144 exits (=7.2/fork including
fixed cost), <=64 syscall exits/window (=3.2/fork), 16/64/256 scales and
incremental slope <0.125 per added page in
[el1-fork-cow](../../../conformance-contracts/contracts/el1-fork-cow.toml).
For a new owned-slice contract require zero per-operation semantic forward
slope and extent-bounded backend work, with startup recorded separately.
Do not subtract fixture startup from the existing absolute ceilings.
After the first owner cutover, census every residual exit with exact MM,
service/mapping arguments and operation generation; 423 unmatched HVCs are
an explicit attribution debt. A red total ceiling stays red until reconciled.
Even green counts require uninstrumented <=2x native Docker per-operation
ratios; an exit-count win alone is not end-to-end completion.

## 5. Milestones and branch routing

These are proposed dispatch units, not permission to implement in this pass.
Small red-test/core extractions can be preparatory commits; they are not
ownership acceptance. Every behavioral cutover is on by default, exact `=0`
only for pre-admission bisection into the previous coherent venue. Admission
is irreversible: no per-call fallback, resource-pressure demotion, or hatch
that resurrects a host editor. Delete hatch and displaced path at proven
landing; afterward compare preserved prior artifacts. No default-off launch.

| Milestone | Outcome and red-first cheapest proof | Existing milestone disposition |
| --- | --- | --- |
| N0: freeze access/cost contract | Compiler/API fence and VM-free two-MM model for the five reported seams: EL1 mmap then host copy; guest retire/remap then fork; same VA/different MM; fork/exec vs outstanding transfer; failed/duplicate capacity completion. Register proposed `kernel.el1.mm-exclusive-owner` and `kernel.el1.creation-native-path`; retain delegated-residency/reader-cost and fork-COW contracts. Current code must fail runtime semantics/work assertions, not only lack the new API. Freeze extent/granule/watermark/retained-capacity budgets from physical constraints. Add exact exit identity/argument census and stopped-target service-progress binding. | Subsumes step-2 writer audit and L0 extension; no ownership feature moves yet. Gate tooling prerequisite below. |
| N1: complete MM incarnation cutover | Implement rows 1–30 together for admitted roots: seal bootstrap; live EL1 VMA/permissions/fork/COW; UserTransfer/Observe/Snapshot/Exec memory operations; elastic Capacity and HostBacking. Host task/observer adapters may request owner operations temporarily. VM-free MMU/allocator/transaction tests at 16/64/256 and unrelated 16/512 VMAs; fault every commit/rollback boundary; two MMs, partial 16 KiB compound returns, read-only/PROT_NONE, stopped target, exec rollback. Signed negative TLBI control and all special observer/copyout paths bind the production capability. | Combines step-2 M1–M4 into one owner acceptance unit. Deletes host-assisted descriptor execution and mirror/projection completion as end-state milestones. Retains physical custody and shared cores. If task/IPC keeps total fork budget red, checkpoint is ownership-only, not green acceptance or “step 2 done.” |
| N2: creation path born at EL1 | Compose task/fork/exec/thread owner, one fd table across all backing kinds, pipe lifecycle, all-zone/mixed ppoll/futex and signal owner. Register zero semantic forward slope for all 18 IDs and loader boundary; exhaust default pool, robust death, partial I/O, SIGCHLD, ptrace TRACECLONE, seccomp and fork/exec during clone/mapping storms. Cheapest tests are fd/pipe/sched/signal/task shared cores and kernel-semantics; signed fixture confirms trap routing and parked-thread capture. | Reuses lifecycle L1/L2/L3/L4/L5; supersedes host-settle-only Phase B as final task owner. Pulls step-3 M1/M2/M3/M5 and spec step 5 forward; do not defer signals until after AF_UNIX. Pulls step-4 loader/mapping closure needed for exec; full cache is not a prerequisite for cold byte service. |
| N3: close the measured window | Run same-source fork-COW all scales and three impact creation workloads. Reconcile all exits, bytes/grants/returns and cleanup, eliminate residual control-claim/idle/kick/maintenance work rather than widening limits. Red-first existing ceilings plus zero host pause/COW/semantic-dispatch metrics, coherent parked-thread snapshots and ASID reuse. Uninstrumented previous-main/candidate and native Docker <=2x. | Replaces “memory success now, workload benefit after later steps” with one vertical acceptance receipt. Lifecycle L6 is included, not waived; old total-exit and TRACECLONE reds block it. |
| N4: finish remaining EL1 kernel scope | All AF_UNIX/SCM_RIGHTS, eventfd/epoll/select edges, credentials/rlimits/job control/timers/observers not already closed; full names/stat/page cache/external-writer capability and shared mapping coherence. Shared cores, two-process generation/pin tests first; native Linux and signed bindings for each surface. | Preserve step-3 M4 and remaining M1–M5 coverage; preserve stage2a and step-4 M1–M4 cache/coherence work, removing pieces actually subsumed in N1/N2. x86 ring-0 remains explicitly deferred as directed; adapter compile gates remain. |

No unsupported shape or omitted syscall is silently removed from the original
plans. N2 is large because shared fd/signal/task ownership cannot be split
into a fixture-only side implementation. N0/N1's cheap experiment below is
there to reject this commitment before that port. Core extractions can land
on the host first only if they replace the previous implementation, not add
V2 models. Maintain personality/substrate separation and compiler inventories.

### N0 experiment receipt (2026-10-02)

**Verdict: PASS for the bounded VM-free experiment; no section 6 seam
rejection was observed. Production ownership and the workload exit thesis
remain unaccepted.** This supersedes the incomplete preparation verdict below,
which is retained as historical production-red evidence.

`carrick-el1::personality::mm_portal` owns the actual reservation table,
resolved elastic node bank, live `PageTableManager` images and exact physical
frame references. Boot declarations and the production HVPatch initial image
are consumed before `finish_import`; the only admitted identity is
`El1MmHandle { carrier, mm, incarnation }`, with private fields and no Deref.
The three families are UserTransfer (including owner map/protect/unmap/remap
and asynchronous pinned completion), Fork (unpublished task identity), and
Capacity (generation-authenticated grant/return/settlement). Internal reads
have their own closed intent, confined to the boot control page at
`0x2d001e4000`; they do not weaken user authorization.

After admission the managers select `LiveDescriptorOwner::Guest`. Publication,
retirement, protection and fork arming use the existing shared descriptor
planner/executor/receipt settlement; COW uses its real compound classifier
and journaled repoint operation. No manager host publication is enabled to
make tests pass. Fork copies the owner's own live table image and clones the
owner reservation tree; no host VMA/reference snapshot is an input. The fake
backend authenticates only physical extents, generations, pins and byte spans.
It records every callback and checks the real root-holder census at each one.
It contains no protection, predecessor, VMA, COW or projection decision API.

Both MMs have the SAME VA and the full 16/512 unrelated-node population.
`native_owner_matrix` covers lazy copyout/read, RO and PROT_NONE errno **14**,
unmap/remap, moved bytes, child COW with unchanged parent and peer, actual
zeroing/reuse of a dirty physical page in a partial 16 KiB compound with an
unchanged adjacent page, and stale pinned completion refusal. The target's
real scheduler address-space gate stays closed, and all **256** scheduler
slot drivers are away on blocking waits, each with a queued service record,
while the target record itself remains parked. No record is unparked,
no EL0 entry occurs and no host worker is parked by this owner entry. This is
an owner-core progress proof, not a production service transport binding.

| Pages | Unrelated nodes in each MM | Transfer table visits | Transfer VMA visits | Fork VMA visits | Logical pins acquired/released | Physical pins acquired/released at teardown | Grants/returns | Backend callbacks | Dirty-page zero/reuses |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 16 | 16 | 928 | 240 | 260 | 58/58 | 138/138 | 8/1 | 14630 | 1 |
| 16 | 512 | 928 | 480 | 9779 | 58/58 | 138/138 | 8/1 | 25559 | 1 |
| 64 | 16 | 3712 | 960 | 260 | 202/202 | 426/426 | 8/1 | 22310 | 1 |
| 64 | 512 | 3712 | 1920 | 9779 | 202/202 | 426/426 | 8/1 | 33239 | 1 |
| 256 | 16 | 14848 | 3840 | 260 | 778/778 | 1582/1582 | 10/1 | 53034 | 1 |
| 256 | 512 | 14848 | 7680 | 9779 | 778/778 | 1582/1582 | 10/1 | 63963 | 1 |

A table visit counts one live descriptor/range resolution, not every byte of
an extent authenticated by that resolution. Fork also copies **7168/7680**
words at 16/512 nodes. Total VMA work includes bootstrap imports (4239/158005,
4959/159445, 7839/165205 respectively); it is not substituted for the measured
operation windows. Portal physical-dispatch counts and backend callback counts
are different layers: the latter also includes backend-internal validation
pins and raw pinned-span resolutions, and is the complete backend census.
All host semantic/protection/COW/projection decisions, MM-lock crossings,
host worker parks and EL0 entries are **zero** in every row. Retirement visits
are **2**; capacity settlement scans **768/1280** physical frame slots,
proportional to granted extents. After user mapping retirement, references are
exactly **3** explicit boot-control references and **0** user references/pins.
Physical pins all balance on portal destruction.

The transfer budget derives from three passes, four table levels and the
existing bounded table-grant/reclaim widths (8 each), not unrelated VMAs:
`3 * 4 * (8 + 8 + 4) * pages`. Measured visits are exactly `58 * pages`.
VMA queries are bounded by three passes times tree height, with four boundary
visits per level; the unrelated-node increase doubles visits, not 32x.
Fork necessarily clones its own VMAs: its bound includes the cloned node
population and tree height. Capacity is extent-bounded; physical policy is
reused unchanged from `el1-elastic-frame-extents.toml`: 4 KiB Linux pages,
16 KiB compounds, 1 MiB grants, 16 KiB refill threshold, 1 MiB high watermark,
synchronous single outstanding grant and at most one wholly free retained
extent per MM after settlement. No second policy table was introduced.

`extent_generation_and_pin_custody` additionally fills 512 pages, refuses a
forged grant token, refuses returning an extent containing a referenced or
pinned retired page, refuses fork with an outstanding target copy, then rejects
the stale completion and returns the exact generation. Re-grant reuses the
same physical base with a new token; the old return is refused. Four compile-fail
doctests prevent handle access to manager, mutable VMA, protections and raw
host pointer; `just test` now runs them.

Section 6's reject/rethink conditions:

- Stopped transfer needs EL0/host-worker parking: **PASS**, zero entries/parks;
  closed execution gate, parked target and 256 unchanged away drivers/service queues.
- Fork needs a host VMA/reference snapshot: **PASS**, zero host projection
  inputs/decisions; owner clone visits 260/9779, owner table words 7168/7680.
- Lease drain needs host page-table pauses: **PASS**, pending drop performs
  atomic pin release only, and old completion is refused without a pause.
- Capacity needs semantic VA/predecessor custody: **PASS**, exact extent/token
  return checks only; forged, cross-MM, busy and repeated returns are refused.
- MM lock across host I/O: **PASS**, zero actual callback/root-holder crossings.
- Zero 18-ID forwarding but approximately 161 total exits/fork: **UNMEASURED**.
  N0 contains no guest or creation workload and makes no exit-count promise;
  this remains a mandatory N2/N3 workload rejection gate.

Host-only acceptance uses main's official xtask driver (main `b0d8743ee`),
compiled into this worktree's target, with `--root` naming this frozen-admission
worktree. Receipt location: `target/el1-gate/n0-host-receipt.json`; its HEAD,
cleanliness and step results are authoritative. The director owns signed
acceptance. The frozen admission has 64 commits absent from main; rebasing
those dependencies is a separate integration decision, not an N0 code change.

This is a bounded anonymous-MM experiment, not an installed second production
lane. N1 still owns production admission binding, all VMA kinds, cross-core
failure rollback, multi-vCPU publication and signed stale-TLBI/cache negative
controls. No guest run or Docker result is claimed. Shared edits are limited
to the resolved EL1 reservation-lock entry, module registration, dev-only
production image dependency, doctest recipe and contract/inventory binding.

### N0 preparation receipt (partial, 2026-10-02)

Initial reduction ran on admission `690383cc8`, not main. The director froze
admission at `1cf7568e1` without acceptance and requested rebasing onto that
base, which reverts the experimental internal-window read gate. This reduction
does not exercise that gate. Internal bootstrap windows require a distinct
typed intent, not user-transfer permission. The two registrations preserve
N1/N2 red groups from the director's `admission-final/s3t3-narrow-report.md`;
those signed observations are external evidence, with unproved causes and no
GNU coverage, not a receipt for N0's executable.

The production-path known-red witness is
`carrick-el1::native_ownership_tests::red_until_n1_production_admission_retains_host_semantic_venue`.
It publishes two AddressSpaces entries, imports and admits real reservation
roots with `finish_import`, then drives production
`serve_delegated_anonymous` through map/retire/remap at the same VA in each
MM. The descriptor probe reads actual live, resolver-backed
`carrick-mmu-core::PageTableManager` tables using
`classify_stage1_range`; no VMA or table model is substituted. Backing is
zeroed primary-table custody only; physical data extent service is unbound.

| Pages | Primary unrelated nodes | Peer unrelated nodes | Table reads per MM | Primary/peer authentication node reads | Accepted host proposals per MM | Descriptor probes per MM |
| --- | --- | --- | --- | --- | --- | --- |
| 16 | 16 | 16 | 3 | 5 / 5 | 1 | 3 |
| 16 | 512 | 16 | 3 | 10 / 5 | 1 | 3 |
| 64 | 16 | 16 | 3 | 5 / 5 | 1 | 3 |
| 64 | 512 | 16 | 3 | 10 / 5 | 1 | 3 |
| 256 | 16 | 16 | 3 | 5 / 5 | 1 | 3 |
| 256 | 512 | 16 | 3 | 10 / 5 | 1 | 3 |

Table reads cover three lazy-only operations, each skipping an absent root
terminal. Node reads cover new fault-plan creation and cross-MM plan
rejection, not the complete operation transaction. Descriptor probes are
EL1-route callbacks, **not host semantic callbacks**. The accepted
`begin_host_proposal` is separately counted as an actual surviving host
semantic venue. Exclusive-owner assertion returns
`red_until_n1_host_semantic_venue_survives_admission` and is checked with
`expect_err`. Old fault plans fail authentication after retire/remap;
cross-MM plans also fail. Those two semantics are green already and are not
fabricated stale-generation reds.

An initial attempt at **two 512-node roots** failed import with
`MetadataRequired` in the current bootstrap pool. The committed reduction
keeps the peer at 16 unrelated nodes and labels that population explicitly.
This does not prove elastic metadata capacity, and no capacity or node budget
was increased to conceal the failure.

**Experiment verdict: incomplete; current exclusive ownership is red.**
This is production admission evidence, not the replacement architecture or
N0 completion. No sealed handle, UserTransfer, data copyout, protection
mirror/projection witness, fork/child write, partial 16 KiB compound reuse,
delayed transfer completion, physical pin balance, extent capacity crossing,
stopped-target/default-slot progress, or compiler fence is proved here.
Each remains mandatory before the N0 experiment can pass. The two new
contracts register these unresolved bindings explicitly. Physical policy is
reused from step2-prep's
`el1-elastic-frame-extents.toml`; only its absent sibling test bindings are
reclassified as unresolved, rather than claiming they exist or ran here.

Section 6's reject/rethink list: stopped-target EL0/worker requirement,
host snapshot dependency at fork, host page-table pause at lease drain,
semantic VA/predecessor capacity validation, and MM lock across host I/O
are all **unmeasured**, not passed. Total-exit/workload thesis is also
unmeasured. This receipt therefore permits neither owner cutover promotion
nor a claim that the early disproof experiment accepts the design.

`just accept` remains the explicit tooling blocker described below. No
signed guest or Docker execution belongs to this preparation receipt.


Verification/handoff: rebased onto frozen admission `1cf7568e1`.
`RUSTC_WRAPPER= just test-kernel`, `RUSTC_WRAPPER= just test`,
`RUSTC_WRAPPER= just clippy` and `RUSTC_WRAPPER= just lint-domains`
all exited zero in foreground verification. Receipts are
`/tmp/carrick-n0-final-{test-kernel,test,clippy,lint-domains}.log`.
The full kernel/host suites ran at `308e2515b`; subsequent changes were
lint-only metadata on the existing USDT wrapper, a byte-identical test-file
move, and position-only inventory reconciliation. The focused test was
rerun after the move. Clippy passed after the USDT annotation; full
lint-domains passed on clean `b4e7cee9d`. These preparatory exceptions do
not confer signed or ownership acceptance.

Shared-file changes: `carrick-el1/src/lib.rs` registers the test module;
`carrick-observability/src/probes.rs` adds a method-local
`redundant_closure` allowance because the USDT proc macro rejects Clippy's
suggested bare FnOnce value. The executable closure is unchanged.
Clean-source reconciliation rebound 28 existing host-authority positions
and two K1 operation positions, preserving all 601 reviewed rows.
The macOS compiler census passes as a subset; Linux/FreeBSD/NetBSD
profiles remain pending. No admission memory/reservation/trap code was
edited by this N0 slice.

This handoff is **partial N0**, not completion. The sealed API/four compile-fail
witnesses and the full section-6 transfer/fork/physical-capacity/service-progress
experiment must still be implemented. No positive early-disproof verdict,
owner cutover, or `just accept` implementation is claimed.

### In-flight disposition

| Work | Recommendation |
| --- | --- |
| `work/s3-t3b` admission | **Land as-is only as a transitional prerequisite after director review and its existing gates**, preserving all repaired semantics; current dirty fixture changes require separate review. This is not a claim that the inspected branch is gate-green. Do not stop a nearly integrated admission slice to rewrite it. Then rebase N0/N1 onto its accepted clean head. Stop additional feature-by-feature host proposal/recall architecture beyond required landing fixes; N1 deletes those admitted pathways. |
| `work/lifecycle-phase-b` | **Rebase**, retain identity/gate/exit/robust/teardown work and its red witnesses. Land an internally consistent Phase B slice under existing acceptance; stop designs that add another task registry or an indefinitely host-owned birth/exit observer shadow. Extend into process lifecycle owner in N2. Branch source was not inspected here; this recommendation uses the plans/spec, not a claim about its current diff. |
| Step-2 completion implementation briefs | **Stop/rebrief** separate M2 host-projection patches and M3/M4 host exclusion cleanup if dispatched as standalone closure. Reuse code/tests toward N1; extent M1 preparation remains useful. No actual branch is reset/deleted by this doc. |
| stage2a | **Continue/land as-is within its bounded namespace contract**, then rebase loader input on it. Its direct host operation cost survives EL1 migration. No invented branch head/acceptance is asserted. |
| Step-3/step-4 design plans | **Keep as coverage ledgers, reorder implementation briefs** per table. Do not “stop” full AF_UNIX/cache work permanently. One fd/name/page authority must serve both the slice and later callers. |
| Older paused branches | Preserve separately; no blanket merge, stash, reset or cleanup. Use only reviewed red witnesses/core work after rebasing onto accepted source. |

### Acceptance: `just accept` and `just el1-gate`

Each N1–N4 behavioral milestone requires **`just accept` and `just el1-gate`**,
including after hatch deletion and clean integration. Both exist on main
since `38b7578e6`/`062f98959`/`b0d8743ee` (2026-10-02): `just accept` runs the
host phase and the Docker-free signed phase against the committed known-red
list `scripts/conformance/el1-known-red.txt`; `just el1-gate` is the same tool
with the full profile (retained probes, LTP subset, inotify09 comparison),
holding the exclusive Docker lease for steps that may start Docker. The
recipe composes existing checks, fails closed on incomplete observations,
and does not relax budgets or relabel report-only impact output as a pass.

Its required contents are the union of the existing plans' packets:

- Red-first registered VM-free semantic/work contracts in the cheapest
  capable layer, `just test-kernel`, host `just test` serial partition,
  `just ci`, clean-tree inventory reconciliation and `just lint-domains`,
  personality boundary and other-backend compile coverage.
- Fresh/hash-inventoried musl and GNU fixtures/probes; signed embed production
  route for the complete `el1_` suite and each new observer/ownership binding,
  entitlement negative control; unchanged fork-COW ceilings/all scales.
- `just el1-gate`, then keep its CLI artifact for
  `just --no-deps conformance smoke` and
  `just --no-deps conformance full`. No rebuild/re-sign between CLI rungs;
  embed executable is independently identified, not the same artifact.
- Existing impact carrick/base/candidate/docker/report commands with
  spawn-loop/thread-spawn/fork-exec default counts, excluded warmup and ten
  measured samples. Paired go-build/cpython-threading/cpython-subprocess
  on a quiet host with fixed three-round ABBA and wall/carrier CPU separately.
  Native-arm64 Docker phase only after every Carrick guest stops, pinned
  identical declarations/images; direct native macOS I/O control for stage2a.
- Review row completeness, per-operation denominators, raw streams, all
  failed samples, unchanged work ceilings and <=2x native Docker objective.
  A >=10x completing ratio returns to correctness triage. Temporary ecosystem
  regression is disclosed with attribution per spec, not called completion.
  Impact report exit zero alone is not acceptance.
- Exact HEAD, SHA-256, CDHash, LC_UUID, entitlement, DOF, ABI/layout/probe/
  fixture/image identities, operation/MM generations, no dropped/unknown
  measurements and run-ID-scoped zero cleanup. Rebuild after merge with no
  guest alive; restore the inventory only on clean source. Prior receipts do
  not transfer to a new artifact. Record as-built and remaining blockers.

`el1-gate` currently compares `CARRICK_EL1=1/0` inotify arms. When old owner
hatches are deleted, replace that comparison with preserved-artifact evidence
in the gate; never resurrect old semantics to keep the script working.
No acceptance commands above are executed for this design-only task.

## 6. Risks and an early disproof experiment

Largest risk: **a big boundary cutover can be slower to deliver than narrow
repairs**. The new plan concentrates task/MM/fd/signal dependencies; no_std
core extraction, Linux clone/exec edge cases and host-file coherence are real
work, not trivial ports. Accept the approach only if the following small
experiment closes the seam without adding a second model.

**N0 experiment (implemented above; original bounded brief):** two VM-free
EL1 MM instances with the same GuestVa, live reservation core and MMU tables,
plus a fake physical extent backend. Through the proposed sealed handle,
exercise only UserTransfer, Fork and Capacity: map lazy memory, copyout,
protect/unmap/remap, fork and child write, retire/reuse a partial compound,
then delayed copy completion from the old generation. Include a stopped
MM and all default service slots waiting. Run at 16/64/256 pages and unrelated
16/512 VMA nodes; count table/VMA visits, pins, capacity crossings and all
host semantic callbacks. Current behavior should fail the stale-generation,
mirror/projection or host-authority callback witnesses red first.

The experiment passes only with zero host protection/COW/projection decisions,
correct bytes/errno/isolation, balanced references, range/tree-height bounded
work and extent-bounded capacity. Add compile-fail witnesses that an admitted
handle cannot obtain manager, mutable VMA, protections or raw host pointer.
This is not a guest run and does not prove HVF TLBI; one later signed
production binding with stale-TLBI negative control is required before N1
acceptance. Do not build a synthetic fixture that bypasses production
admission and then call it the replacement architecture.

**Reject/rethink early if:** stopped-target transfers require running EL0 or
parking a host worker; fork requires a host VMA/reference snapshot to succeed;
lease drain requires host page-table pauses; capacity needs a semantic VA or
predecessor owner to validate physical custody; or one transaction holds an MM
lock across host I/O. Any of these recreates the seam under a new name.
If 18-ID forwards reach zero but total exits stay near 161/fork, the workload
thesis was insufficient: resolve the unqualified HVC/control/idle population
before committing the remaining port on an exit-count promise.

Other discriminators:

- 4 KiB guest/16 KiB host granules, concurrent COW and executable publication
  may require physical pins for longer than anticipated. Bound retained bytes
  and return latency; no fixed RAM reserve or one mapping per historical fork.
- Faults/interrupts cannot recurse into an MM lock; save ELR/SPSR first,
  bound BBM critical sections and forbid IRQ acquisition of MM transaction
  locks. Signed cross-vCPU/ASID rollover negative controls remain essential.
- Ptrace/core readers must include EL1-parked registers and make progress on
  traced/stopped tasks. An unsupported snapshot blocks pause deletion;
  “debug-only” is not an exemption for a shipped writer/reader.
- File-private/shared mapping, truncate/SIGBUS, external writers and exec
  loader coherence cannot be approximated for performance. Preserve the
  step-4 capability/freshness decision; no mtime-only universal cache promise.
- Rust capability fences protect trusted implementation, not the wire.
  Host validates lengths/generations/quotas/contained handles and completion
  storage; guest-reachable EL1 remains experimental with no adversarial review.
- <=2x can fail after exit removal due to table copy, locks or host I/O.
  Run uninstrumented timing and native I/O controls; optimize qualified work,
  not instrumented wall time. If controlled native ratios do not improve,
  change the cost hypothesis without weakening semantic/structural gates.

## Design-pass verification

Only this plan is written. Source/log/spec inspection is read-only; no build,
guest, Docker, product test or product code change is part of this pass.
Validate Markdown through Pandoc, check all relative document/source targets,
review diff/whitespace, and commit with a Why/What/Verified body and agent
trailer. Documentation verification establishes reviewability, not any proposed
contract, runtime result, branch acceptance or performance forecast.

### N1 execution order

These four checkpoints partition all 30 section-2 venues. Each can land with
its own red-first witnesses and acceptance receipt; none accepts the complete
MM cutover until all four close. Ordering follows the frozen admission report's
observed failure groups, not a claimed causal ranking: buffer authorization
blocks probe output and later shard coverage, policy has four observed DIFFs,
and fork/observer attribution remains mixed with N2. The report did not measure
per-venue failure counts, so an exact frequency ranking is unavailable.

| Checkpoint | Venues | Red-first witnesses and landing boundary |
| --- | --- | --- |
| N1a: live host buffer transfers | 3, 4, 5, 7, 28 | Signed musl `mmapv8align` and separately reached `mmapprivatefiletrack`; inverse EL1 munmap/PROT_NONE then host read must return EFAULT (14), with two live MMs at the same VA. Consume resident/file backing at seal with exact-generation owned pins, retaining transferable frames and HostBacking aliases and copying only CopyOnly input. Bind checked GuestMemory entries and every raw escape to UserTransfer; delete admitted protection-mirror storage, host permission/COW selection and guessed VA-to-IPA copyout. Internal control-window reads use a distinct bounded intent. Physical content pins/coherence remain. Production transport required. |
| N1b: memory policy and physical backing | 6, 12, 13, 14, 15, 16, 17, 18, 19, 20 | Frozen `coredumpbit`, `mmapcluster`, `forkfault`, `roprotect`, `msyncalign`, `rlimitasdata`; signed `el1_anonymous_reservations_stay_in_guest` and `el1_delegated_root_map_fixed_over_cow_pages`. Include all VMA kinds, partial-compound reuse, stale/duplicate grants, failure rollback and live fault classification. Reuse N1a transport for Capacity/HostBacking; no host policy proposals for admitted roots. These tests' causal assignment is provisional. |
| N1c: fork, exec and sealed root lifecycle | 1, 2, 10, 11, 21, 22, 23, 29 | N0 `red_until_n1_production_admission_retains_host_semantic_venue` must become a positive exclusive-owner assertion; compiler fences plus owner matrix fork/child isolation, outstanding-copy refusal, stale completion and exec rollback. Frozen `nxwritableimage`, `forkexecstorm`, `exitgroupthreads`, `futexforkwakegroups` are composition witnesses, with N2 task/wait failures separately retained. Delete projection/snapshot/edit/pause capabilities; preserve task birth and root occupancy proofs. Reuse transport for Fork/Exec. |
| N1d: exceptional readers and writers | 8, 9, 24, 25, 26, 27, 30 | Two-MM stopped-target ptrace/process_vm and /proc/mem permission/prefix witnesses; live maps/residency, parked-thread core snapshot, signal-frame fault and native activation revocation under protect/unmap/exec. Owner matrix stopped-target/default-slot and delayed completion proofs must bind to signed production. Reuse transport for UserTransfer/Observe/Snapshot; ReadInstruction, NativeData and authorized POKE remain distinct intents. |

`killrt`, `splicepipeempty` and deadline failure `epollstopcont` remain explicit
N2 composition reds unless production evidence attributes them to N1. Preserve
all 13 observed musl DIFFs and the deadline row as the frozen denominator;
GNU/private-file cases not reached by that batch must be reported separately.
Do not remove either named `el1_` known red until it actually passes on this
branch's identified signed executable, regardless of checkpoint placement.

#### One production transport, shared by all checkpoints

Extend `carrick-el1-abi`'s existing versioned service/mailbox ABI with a bounded
MmPortal request/completion record. Do not export N0's in-process Rust slices
or host pointers on the wire. Requests name carrier, exact MM/incarnation,
operation generation, closed intent, GuestVa/length and bounded transfer-storage
identity; responses carry completed prefix, errno and the same identities.
Validate lengths, arithmetic, storage custody and generation at both ends.
Release/acquire slot ownership makes storage immutable while EL1 consumes it;
stale, canceled or duplicate completion cannot release a newer operation's pins.

The host enqueues work for the exact owner and schedules the existing EL1
service-call entry on the carrier maintenance root. Reuse the existing
`run_el1_service_call_on` register save/restore and MaintenanceDone return ABI,
with scheduler-owned service capacity, rather than a target-EL0 resume or a
borrowed target descriptor editor. A stopped/parked target stays stopped;
service resolves its root by exact AddressSpaces identity. The shared MM owner
transaction checks live permissions, materializes/COWs and pins selected spans,
then copies through bounded storage. No MM lock spans host file I/O. Capacity
or backing suspension returns an owned continuation; settlement resumes the
same operation, never a host fallback or a restart from byte zero. Default-slot
exhaustion must prove service progress before promotion; register save/restore
alone is not that proof. Checked read APIs currently take `&self`, whereas the
existing service-call entry needs mutable vCPU ownership: production binding
must introduce a scheduler-owned transfer capability, not mutate the vCPU
through an unchecked alias or run the EL1 personality on the host.

N0's 14,630–63,963 backend validation callbacks against 8–10 grants are
**EL1-local work, never host crossings**. Production descriptor resolution,
VMA checks, reference/pin validation and span authentication execute within
the EL1 owner against its live tables and granted extent metadata. Only bulk
Capacity grant/return and actual HostBacking effects cross the physical backend
boundary. A per-validation host RPC would violate N0's cost contract; count
local validations separately from transport requests and bulk grants.
CarrickInternalRead is constructed only by the internal-window capability and
is restricted to the declared immutable boot-control window, including the
previously rejected read at `0x2d001e4004`; it never authorizes user pointers
or arbitrary writes to EL1-owned windows. Dedicated physical clock updates
retain their own carrier control capability.

Each checkpoint uses `kernel.el1.mm-exclusive-owner` and the existing
reservation/reader/fork contracts, preserving all budgets. Run host and signed
`just accept` through main's xtask `--root` if recipes remain absent here;
signed commands take `just lease carrick`, exact CARRICK_RUN_ID and scoped
`scripts/sudo/kill.sh` cleanup. Record signed artifact identities and generic
shard remaining-DIFF delta. No Docker is authorized for this execution task.

N1a resident-import checkpoint: `BootMmBuilder<P>` consumes exact physical
pins before sealing. Owned and shared HostBacking imports retain source bytes;
private HostBacking aliases arm the existing EL1 COW classifier, and CopyOnly
input copies into owner-granted pages. Imported physical frames never enter
the anonymous reuse free set. Pin generation/address authentication precedes
publication; failed sealing rolls back unpublished roots/references and new
non-metadata grants. This is an owner-core checkpoint, not production admission
or hardware TLBI/cache acceptance. The live-byte red is green (`live`), the
two-MM inverse remains green, all four import modes preserve bytes, private
file writes preserve source bytes, stale generation refuses before MM
publication, and a read-only input leaf grants no guest write. Full N0 matrix
scales remain green. Receipts: `/tmp/carrick-n1a-portal.log`,
`/tmp/carrick-n1a-import-clippy.log`, `/tmp/carrick-n1a-import-target.log`.
