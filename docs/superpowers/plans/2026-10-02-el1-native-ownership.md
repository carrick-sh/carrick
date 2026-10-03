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

These four checkpoints partition all 30 section-2 venues. Each is an internal
checkpoint with its own red-first witnesses and acceptance receipt. Per director
review, none lands to main before all N1 venues close; production must have
one MM owner throughout the cutover. N1a includes the fork/attach binding
required by mirror deletion, moved from N1c. Ordering follows the frozen admission report's
observed failure groups, not a claimed causal ranking: buffer authorization
blocks probe output and later shard coverage, policy has four observed DIFFs,
and fork/observer attribution remains mixed with N2. The report did not measure
per-venue failure counts, so an exact frequency ranking is unavailable.

| Checkpoint | Venues | Red-first witnesses and landing boundary |
| --- | --- | --- |
| N1a: live host buffer transfers and required fork/attach binding | 3, 4, 5, 7, 10, 11, 28, 29 | Signed musl `mmapv8align` and separately reached `mmapprivatefiletrack`; inverse EL1 munmap/PROT_NONE then host read must return EFAULT (14), with two live MMs at the same VA. Consume resident/file backing at seal with exact-generation owned pins, retaining transferable frames and HostBacking aliases and copying only CopyOnly input. Bind checked GuestMemory entries and every raw escape to UserTransfer; delete admitted protection-mirror storage, host permission/COW selection and guessed VA-to-IPA copyout. Internal control-window reads use a distinct bounded intent. Physical content pins/coherence remain. Replace TaskOnlyRuntimeAuthorities/clone_authorities and child protection snapshots with owner Fork completion; no mirror remains as a fork input. Production transport required. |
| N1b: memory policy and physical backing | 6, 12, 13, 14, 15, 16, 17, 18, 19, 20 | Frozen `coredumpbit`, `mmapcluster`, `forkfault`, `roprotect`, `msyncalign`, `rlimitasdata`; signed `el1_anonymous_reservations_stay_in_guest` and `el1_delegated_root_map_fixed_over_cow_pages`. Include all VMA kinds, partial-compound reuse, stale/duplicate grants, failure rollback and live fault classification. Reuse N1a transport for Capacity/HostBacking; no host policy proposals for admitted roots. These tests' causal assignment is provisional. |
| N1c: exec and remaining sealed root lifecycle | 1, 2, 21, 22, 23 | N0 `red_until_n1_production_admission_retains_host_semantic_venue` must become a positive exclusive-owner assertion; compiler fences plus owner matrix fork/child isolation, outstanding-copy refusal, stale completion and exec rollback. Frozen `nxwritableimage`, `forkexecstorm`, `exitgroupthreads`, `futexforkwakegroups` are composition witnesses, with N2 task/wait failures separately retained. Delete projection/snapshot/edit/pause capabilities; preserve task birth and root occupancy proofs. Reuse transport for Fork/Exec. |
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

N1a wire/core checkpoint: `carrick-el1-abi::mm_portal` defines bounded,
versioned UserTransfer request/completion slots in the existing region's unused
counters tail. Layout/protocol/bounds participate in the image ABI hash. No
host pointer or unchecked enum discriminant crosses this record. A slot is
single-flight until its exact completion settles; dropping a ticket never
reuses its storage. The runtime custodian must retain pins independently and
settle cancellation before reclaim; that runtime binding is not implemented
by the ABI record alone.

The existing owner core services these records through `serve_user_transfer`:
exact carrier/MM/incarnation and monotonic per-MM operation sequence, separately
registered physical transfer storage, live permission/translation, distinct
internal intent, and existing UserTransfer/COW machinery. Owner tests cover
same-VA isolation, PROT_NONE EFAULT, repeated operation refusal and internal
read confinement. CopyOnly now reads the consumed source pin directly, never
resolving it in the destination's physical namespace; a source whose original
backend has been destroyed remains readable through that pin. Bootstrap
rollback work visits only imported spans and newly granted extents, rather
than snapshotting unrelated frame populations.

Receipts: `/tmp/carrick-n1a-portal-abi.log` (3 tests),
`/tmp/carrick-n1a-portal-service.log` (9 tests including N0 matrix),
`/tmp/carrick-n1a-portal-abi-clippy.log`,
`/tmp/carrick-n1a-service-clippy.log`, and
`/tmp/carrick-n1a-service-target.log`. Main's official xtask is built at
`target/n1-gate-driver/debug/carrick-xtask` for subsequent `--root` acceptance.

**Remaining N1a acceptance work:** production physical adapter and real-root
admission (the core still assigns experiment MM identities), scheduler-owned
transfer capability and maintenance-root service entry, Fork wire/binding and
fork/attach handle replacement, admitted GuestMemory/raw-escape cutover and
mirror deletion, hardware TLBI/cache binding, then host+signed acceptance and
the frozen-baseline generic/case probe delta. These checkpoints do not establish
production ownership, signed runtime behavior or review-ready status. No
known-red entry is removed and no Docker or signed run is claimed here.

#### N1 owner adapter

Director decision: the production EL1 memory owner remains the sole owner.
Delete N0's private MM IDs, `PageTableManager`s, frame/reference ledger and
dangling bank mapping. `El1MmHandle`, closed `TransferIntent` (including
`CarrickInternalRead`) and exact-generation completion remain the public
surface; they identify production authority rather than a portal vector slot.
No GuestMemory venue-3 cutover is included in this adapter slice.

The production functions and structures to reuse are:

- Exact MM/root resolution: `AddressSpaces::find` and `grant`
  (`crates/carrick-sched-core/src/spaces.rs:462`), as used by
  `PreparedView::lock` (`crates/carrick-runtime/src/vcpu_loop/reservations.rs:135`,
  exact-MM lookup at line 145). `CarrierReservations` borrows the table from
  its retained `CarrierMetadataAccess` region (`reservations.rs:63`), never
  from a portal-owned allocation. `AddressSpaces::try_begin_edit`
  (`spaces.rs:495`) supplies the exact-MM descriptor editor.
- UserTransfer permission and mapping policy: the admitted reservation root
  through `delegated_anonymous_root`
  (`crates/carrick-el1/src/memory.rs:855`); policy operations reuse
  `decide_anonymous_syscall` (`memory.rs:184`) and
  `serve_delegated_anonymous` (`memory.rs:662`). These functions preserve
  existing proposals, descriptor completion and deferred-return authority;
  their current forwarding outcomes are not transfer completion.
- UserTransfer prepared-page materialization:
  `HardwarePreparedResolver::commit_prepared`
  (`crates/carrick-el1/src/fault.rs:156`), using the authenticated TTBR0
  and `FrameGrantResidencyTable::lookup`/`record_commit`
  (`crates/carrick-el1-abi/src/lib.rs:1646`, `lib.rs:1678`).
  `HardwareCowResolver::resolve_cow` (`fault.rs:186`) uses
  `PrimaryTableWords` at the live TTBR0 (`fault.rs:194`), the shared
  `cow_grant_pool_guest` (`fault.rs:206`) and `resolve_guest_cow`
  (`crates/carrick-el1/src/cow.rs:57`). Reuse this classifier/pool rather
  than the N0 portal's independent COW frame ledger.
- Carrier reservation-bank lifetime:
  `ResolvedReservationNodes::refresh`
  (`crates/carrick-el1/src/personality/reservations/storage.rs:77`)
  receives the retained carrier region for bootstrap banks and exact extent
  pins for dynamic banks. `SharedReservations::provision_metadata`
  (`storage.rs:159`) publishes banks outside MM locks. EL1's identity bank
  view (`storage.rs:139`) and the host's resolved view name the same storage.
- Fork **open for the next turn**: production admission's `admit_fork`
  (`crates/carrick-kernel/src/dispatch/mem/el1_reservations.rs:190`)
  seeds the child's published root through `DelegatedRoot::seed_from`
  (`el1_reservations/provider.rs:185`). The adapter must bind production
  descriptor/COW publication and child occupancy, not call N0's snapshot fork.
- Capacity **open for the next turn**: existing frame grant requests in
  `dispatch_fault_with_prepared` (`fault.rs:822`, request at line 945),
  shared COW grants, and `CarrierReservations::provision_metadata`
  (`crates/carrick-runtime/src/vcpu_loop/reservations.rs:76`) are the
  existing supply paths. They do not yet constitute a stopped-target
  UserTransfer continuation or a general user-frame pin capability.

Adapter prerequisites authorized by the director: N0's delayed completion
and partial-compound reuse witnesses retain physical data pins independently
of the MM editor. Production `FrameGrantResidencyTable::retire`
(`crates/carrick-el1-abi/src/lib.rs:1766`) revokes a record without a transfer
pin count. `HostApertureState::pin_extent`
(`crates/carrick-vmm-hvf/src/metadata_grant.rs:326`) resolves only the dynamic
metadata aperture, not general user frames. Reusing either as a general data
pin would invent custody. The stopped-target lazy path also needs an owned
transfer continuation: current frame supply ends in `Action::Forward`
(`fault.rs:952`), not a suspended portal operation. The director authorized the
production data-pin and transfer suspension protocol as prerequisites in
this turn, while deferring the public Capacity operation. Do not retain the
N0 ledger, hold an MM editor across suspension, run target EL0, or report an
unbacked lazy page as EFAULT to make these witnesses pass.

This adapter entry is design and source inspection only. UserTransfer has not
been rebound, the private model has not been deleted, and no tests, signed
acceptance or review-ready implementation receipt are claimed by this entry.


N1 adapter prerequisite checkpoint: the production residency record now has
an exact-generation transfer lease count. Retirement closes pin admission
atomically and refuses while a lease is outstanding. Drop releases the lease;
a stale page token cannot pin a successor. Field offset and pin protocol enter
the ABI layout hash. The red witness first failed because `pin_transfer` was
absent, then passed. This is residency retention only: it does not yet protect
physical reclamation, because production callers must honor refusal before
unmapping. No UserTransfer consumer uses the lease yet.

Resolved owner-matrix conflict (director ruling): `mm_portal/tests.rs:299` publishes the supposed
stopped MM with `AddressSpaces::publish_closed` and asserts that the gate
stays closed (`tests.rs:365-366`). This gate is a publication/ASID retirement and
host page-table pause fence (`carrick-sched-core/src/spaces.rs:10`), not a
thread-stop flag. Production `try_begin_edit` refuses it (`spaces.rs:506`).
The N0 portal ignored that scheduler authority because its private MM graph
was separate. Required replacement witness: keep the target thread parked
with its admitted MM gate open, require transfer progress without an EL0
entry, and separately require an owned suspension/refusal for host-excluded
or closing MM gates. Do not give a maintenance service an unrestricted gate
bypass to preserve the synthetic closed-gate success assertion. The original
N0 stopped-target pass was measured on a gate-bypassing private model; it
must be re-proven on production semantics before acceptance.


N1 physical-custody ruling: user-data frame lifetime stays in host
`CarrierVmCustody::pin_stage2_record` (`carrier_custody.rs:1367`), with
pre-unmap `DeferredActivePins` at line 1460. The residency lease guards
**grant windows only**, never general physical custody. COW now revokes
old grant-window tokens before a repoint, refuses while such a lease is held,
and publishes/commits the replacement grant identity on success. Index
saturation declines acceleration; it does not fabricate physical custody.
The red COW witness proved the old token still accepted a commit after
repointing, before the correction.

Director-approved UserTransfer handshake: EL1 selects IPAs under the exact
MM transaction; host resolves those IPAs to exact physical records and
generations in `CarrierVmCustody` and pins them; EL1 then revalidates the
VA-to-IPA mapping under the exact MM before copying. A raced selection must
release the physical pins and return owned retry/suspension. No shared
physical directory is added, and root generations never substitute for
physical generations. This supersedes the earlier physical-custody obstacle.
The shared completion must carry retained-data identities, replacing the
N0 metadata-storage description. UserTransfer and stopped-target lazy grant
continuations remain open until this production handshake is implemented.

### N1 UserTransfer implementation receipt — 2026-10-02

This receipt supersedes the adapter checkpoints above that said UserTransfer
was not rebound, that the private model remained, or that residency leases
provided transfer custody. Those entries describe earlier inspection states.
The N0 private MM/table/frame graph is now deleted. The production adapter
borrows SharedReservations, retained reservation metadata and AddressSpaces;
only CarrierVmCustody owns physical transfer pins. Residency leases protect
unpublished/prepared grant windows, not committed transfer data.

Director-approved scope implemented here:

- Exact admitted carrier/MM/incarnation handle; EL1 selects the current IPA,
  host retains its actual stage-2 record and backing allocation, EL1 revalidates
  under the real SpaceEditor, and completion publishes before that guard drops.
  A 4 KiB copy or cancellation resumes the same suspended EL1 service frame.
- Stopped targets use an OPEN admitted MM gate and borrowed driving vCPU, with
  no target EL0 entry or spare executor. Byte offset and host buffers remain
  owned across preparation/retry. No editor survives a returned continuation.
- Exact-target lazy preparation reuses physical allocation, inventory and
  custody. Its pending owner exists immediately after physical publication,
  pins before alias exposure, and settles only its exact descriptor receipt.
  Concurrent-unmap rollback authenticates inventory mapping/frame and retained
  owner generation; absent alias alone is insufficient. Exact removal leaves
  successor stage-2 custody, inventory and bytes intact.
- Imported private file pages are admitted as EL1-private/COW-armed. Only
  page-granule imports descend to L3: the 2 MiB witness requires exactly one
  additional table; untouched zero arenas and compound-only arming stay coarse.
  Empty COW pools return an exact owner supply receipt, including non-anonymous
  imported-private roots. The host supplies one compound through the existing
  provision_guest_cow_grants allocator; it never reclassifies host table policy.
- A remapped generation may replace only core-typed retired terminals through
  bounded Prepare. It receives fresh zero backing; an adjacent live page in
  the same old compound is untouched. No old physical frame is recycled while
  custody retains it.
- Executable COW uses the authorized bounded physical-publication HVC after
  guest copy and before CowRepoint. The exact claimed grant/epoch/backing and
  physical owner authenticate existing I2 publish_user_executable. No new cache
  mechanism, metadata callback or host policy decision is introduced. Ordinary
  COW has zero publication crossings. Executable UserTransfer writes dirty-mark
  after memcpy and invoke I2 before completion. Non-executable writes also
  dirty completed bytes for executable aliases; per-backing bounded I2
  serialization covers dirty claim through actual invalidation. The guest editor remains held
  for the bounded effect (maximum existing 16 KiB COW run).

Current implementation map (line numbers at this checkpoint):

| Responsibility | Production function |
|---|---|
| Sealed host target and owned request | `crates/carrick-aarch64/src/user_transfer.rs`, `TransferTarget::bind`, `OwnedUserTransfer::advance` |
| Production selection/revalidation | `crates/carrick-el1/src/personality/mm_portal/production.rs:232`, `MmPortal::select` / `revalidate` |
| Guard-retaining copy/completion | `production.rs:513`, `serve_transfer` |
| Exact lazy root/descriptor settlement | `production.rs:762`, `serve_grant` |
| Admitted target bind service | `production.rs:950`, `bind_transfer_hw` |
| Same-frame service runner | `crates/carrick-aarch64/src/engine.rs:232`, `run_el1_service_effect_on`; `:7739`, `run_user_transfer_service` |
| Host physical selection and memcpy | `crates/carrick-vmm-hvf/src/trap/user_transfer.rs`, `retain_exact`, `TransferPin::copy` |
| Claimed executable publication | `user_transfer.rs:261`, `publish_claimed_executable` |
| Exact-target physical adapter | `crates/carrick-vmm-hvf/src/trap/sparse_materialization.rs:889`, `PublicationContext::for_transfer`; `:2315`, `prepare_transfer` |
| Exact-target COW supply | `sparse_materialization.rs:2298`, `refill_transfer_cow` |

Evidence replaces the selection-only draft, not the retained whole-N1 red:
`native_owner_matrix` copies real bytes through the production service for
both live MMs at every 16/64/256-page × 16/512-unrelated-node point, with all
default slots occupied, target parked/open, ≤8 descriptor reads/page and
≤4*ilog2(unrelated+1) reservation visits/page. Every matrix operation checks actual retained physical pins and zero pins
after completion. The physical suite additionally proves, stale pin/refused copy, source allocation lifetime,
Owned/CopyOnly/private/shared file bytes, exact rollback/successor retention,
dirty pool reuse and same-compound partial replacement. These are compositional
VM-free witnesses: the fake inventory authority models kernel unmap receipt
ordering, not execution of a Linux syscall.

Red-first observations: imported private admission initially left its leaf
untagged; partial retired replacement initially returned Refused(Occupied);
kernel-only writes initially returned Suspended; executable COW initially
failed the Resolved assertion without publication capability. Each covering
witness now passes. The executable witness additionally executes a host ARM64
RX view of the retained bytes (7 before write, 9 afterward), after independent
I2-clean assertions; mprotect is test-only W^X capability, not cache authority.

Final commands/results and limits are recorded in the implementation and
controller receipts here and the Why/What/Verified commit bodies. The temporary
review workspace is removed after review closure. No guest or
Docker run occurred in the quiet window. Public bulk Capacity, Fork rebinding,
GuestMemory venue 3, existing production-admission reds, signed guest TLBI and
end-to-end artifact acceptance remain outside this UserTransfer receipt.


#### N1 review fix receipt (supersedes 4f7a6d89a review gaps)

The independent review's four Important findings are addressed in the same
production paths. Pending physical grant cleanup carries the already-held
FrameRegistryGuard, avoiding recursive acquisition on descriptor preparation
refusal. Completed UserWrite copies re-dirty their exact backing bytes even
when selected through a non-executable MM. Existing I2 serializes dirty claim
and actual invalidation under a backing-local lock, with at most 16 KiB cache
work per acquisition and no writer/content drain, metadata or I/O callback.

The restored matrix lives in `crates/carrick-el1/src/personality/mm_portal/test_support.rs:302`
and is driven by real HVF custody in `crates/carrick-vmm-hvf/src/trap/user_transfer.rs:474`.
Every 16/64/256-page × 16/512-unrelated-node point retains both live roots and
writes A, writes B, reads A, reads B through production selection, physical
retention, EL1 revalidation, memcpy and completion. Limits remain ≤8 descriptor
loads/page and ≤4*ilog2(unrelated+1) reservation visits/page per operation.
Actual reservation mprotect to RO/NONE and retirement reject A writes/reads
with errno14 as appropriate while B's bytes remain intact. Restoring writes
first exposed an extra execute-policy table walk; reading executable permission
from the same translated leaf removed it without weakening either budget.

The director additionally licensed retained external CopyOnly input before
admission, with the existing kernel publication owner guarding preparation and
normal admission as one transaction. `PreAdmissionGuard` in
`crates/carrick-kernel/src/kernel/mm_occupancy.rs:835` owns existing SPACES_LOCK;
`with_address_space_admission` in `dispatch/mem/el1_reservations.rs:454` first
acquires exact MM mutation authority, then publication ownership, and releases
the raw publication only after the owner lock drops. Mutable brk/mmap/rlimit
inputs are sampled under mutation admission by `AddressSpacePublicationOwner::publish`
in `dispatch/mm_authority.rs:1539`. Refusal consumes publication using the held
lock; a prepared publication is RAII-owned before any fallible root admission.
This also closes the prior publish-before-mutation concurrent-edit window.

`UserTransferCustody::retain_import_source` (`trap/user_transfer.rs:18`) retains
an exact source stage-2 generation and its mapping allocation. A retained source
may survive directory destruction/retirement; fresh stale acquisition refuses.
`prepare_import` (`trap/sparse_materialization.rs:2801`) uses existing SeededAnon
allocation, frame inventory and CarrierVmCustody under the borrowed kernel
permit. PendingImport owns the existing host-setup descriptor undo journal and
physical receipt immediately, installs/syncs the exact alias, and rolls loader
descriptors back before physical release on refusal. Successful normal root
admission authenticates commit. Executable seeded input uses existing I2 before
descriptor publication. No host protection snapshot, second table graph, new
publication lock or post-admission host editor is introduced.

Covering tests and observed reds:

- `foreign_mm/tests.rs:12884`, pending descriptor-preparation refusal previously
  hung in recursive registry acquisition (exact test process bounded/killed at
  5 seconds); it now returns and preserves exact successor custody/inventory.
- `user_transfer.rs:542` and `:607`, peer publication between write admission
  and memcpy previously left completed executable bytes clean (I2 count1 vs2,
  and non-executable peer publication0 vs1). Both are green.
- `code_content.rs:420`, a peer publication previously returned while the dirty
  claimant's actual invalidation was paused; bounded rendezvous now proves it
  cannot return before the original I2 completes.
- `foreign_mm/tests.rs:13377`, external retained source outlives source owner;
  stale acquisition cannot publish a root. Loader-refusal red retained the new
  IPA665719930880 after physical rollback; green restores the exact original
  descriptor before release, then admits/copies a fresh successor. This fixture
  explicitly models kernel permit issuance, while exercising production physical
  custody/allocation/descriptor undo/reservation admission/copy. The real guard
  is separately covered by kernel `mm_occupancy/tests.rs:827`.
- `dispatch/mem/el1_reservations.rs:965`, executing the old publish-before-
  mutation sequence failed with `old publish-before-mutation order admitted
  concurrent edit`; production ordering denies the same intervening editor.

New fatal inventory rows describe only uncertain descriptor/physical custody,
completion or exact identity invariants; recoverable refusal remains typed.
The seven publish_frame_grant rows retain their classification after factoring
into publish_frame_grant_backing; the borrowed runner rename retains its prior
classification. NEXT_CARRIER is a monotonic physical custody identity allocator,
not guest process state. Existing inventory row order is preserved. These edits
add no cataloged host identity/process operation; clean compiler capture and
line-position reconciliation remain the director's final gate.

Scoped receipts are recorded in the worker report. No guest/Docker execution
was performed. Fork, bulk Capacity and GuestMemory venue3 remain OPEN; this
review fix does not confer whole-N1 or signed-artifact acceptance.

#### N1 review fix2 receipt — full claimed-page I2 coverage

The scoped rereview accepted findings 1/3/4 but found another finding 2 variant:
4 KiB dirty bits could be cleared by a four-byte invalidation, allowing a
second MM's completed write on another cache line of the same page to skip
maintenance. `CodeContent::publish_icache` in
`crates/carrick-vmm-hvf/src/trap/code_content.rs:216` now owns page expansion,
backing-end clamping and bounded chunking as well as dirty claim/completion.
Each lock hold covers at most 16 KiB of whole dirty-page coverage. An unaligned
16 KiB request covering five pages is split into 16 KiB and 4 KiB maintenance,
never one 20 KiB critical section. The raw bit-claim helper is private.
`CarrierVmCustody::publish_user_executable` (`trap/carrier_custody.rs:575`)
passes those exact callback offsets/lengths to existing I2 invalidation.

Deterministic witnesses in `code_content.rs:433` and `:455` record actual
callback ranges. Two completed writes at offsets 0 and 0x200 first failed with
`[(0,4)]` versus required `[(0,4096)]`; the unaligned request first failed with
`[(1,16384)]` versus `[(0,16384),(16384,4096)]`. Both now pass, including final
partial-page clamping and rejection of a range beyond the retained backing.
Existing claimed-invalidation exclusion, peer re-dirty, cache work budget and
host RX executable-COW witnesses remain green. No new cache mechanism or owner
was added; whole-N1/signed acceptance and the director's final gates remain open.

#### N1 assembly boundary review receipt — 2026-10-03

The final lint preflight identified six newly unreviewed assembly sites.
`scripts/lint-domains.sh` runs both Semgrep and the Rust-token escape checker;
these maintain matching exact reviewed-module lists. The compiler operation
catalog covers resolved host calls and contains no inline-assembly operation
rows. The two existing EL1 modules below are now included in those boundary
lists, with no Rust source change, suppression comment, wildcard or new path.

| Site | Reviewed authority and operation |
|---|---|
| `crates/carrick-el1/src/fault.rs:244` | `hvc #1` yields the exact claimed executable-COW grant's physical publication effect after guest copy and before CowRepoint. The slot authenticates the replacement IPA/owner; existing I2 performs bounded cache work while the actual EL1 editor remains on the resumed service stack. No host policy, metadata or I/O callback is authorized. |
| `crates/carrick-el1/src/personality/mm_portal/production.rs:618` | Read `ttbr0_el1` for copy service and compare the complete live root/ASID against the target MM's current AddressSpaces grant before revalidation and retained-editor copy. The value is observed, not changed. |
| `production.rs:648` | `hvc #1` supplies the existing bounded copy/cancel physical effect. The borrowed-vCPU runner resumes this same EL1 stack, retaining the actual SpaceEditor until exact completion is published; it cannot reset the frame or enter target EL0. |
| `production.rs:675` | Read `ttbr0_el1` before selection and refuse a target whose current AddressSpaces grant differs. Carrier/MM/incarnation authentication remains in the production selector. |
| `production.rs:906` | Read `ttbr0_el1` for exact grant preparation, compare with the authorized window's target grant, and use that same root/ASID for descriptor maintenance. This does not write TTBR or choose host policy. |
| `production.rs:966` | Read `ttbr0_el1` before sealing the admitted target binding; complete live root equality with its AddressSpaces grant is required before returning the incarnation. |

The token checker first reproduced exactly these six rejections. After review,
its full-tree check passes. Focused boundary tests retain rejection of nested
suffix lookalikes, including both new EL1 paths, and validate the reviewed exact
paths through both Semgrep and the token checker. Runtime abort/global-state
and carrier-only process checks remain unchanged and pass. Existing inventory
order is preserved; the director owns the final full lint rerun.

The small positive assembly fixture now invokes the real Semgrep assembly rule
and token checker directly. The current full launcher additionally requires the
repository's exact reviewed carrier birth/probe population; manufacturing that
unrelated population in an assembly fixture would obscure its contract. The
launcher-negative and exact-root/nested-path checks remain, and the carrier
checker is separately verified on the actual repository. No product checker is
skipped or relaxed. The focused three-test boundary run passes; full-tree escape,
carrier-only, runtime abort and runtime global-state checks all exit zero.

#### Final whole-branch review fix receipt — fresh import undo ownership

The whole-branch review found that idempotent `begin_undo` allowed two pending
imports, or an import and an existing loader, to share a manager-wide journal.
Dropping one could roll back the other's descriptors. Both required ownership
witnesses reproduced this: `transfer_import_refuses_competing_pending_journal`
failed with `second pending import joined the first journal`, and
`transfer_import_refuses_existing_loader_journal` failed with
`import joined an existing loader journal`.

`PageTableManager::begin_fresh_undo` in
`crates/carrick-mmu-core/src/aarch64.rs:4253` now checks and acquires a fresh
journal atomically under the existing exclusive mutable manager borrow;
already-open journals are left untouched. The existing Stage1Editor forwards
that operation while its authority lock is held (`stage1_authority.rs:1365`).
`ImportDescriptorUndo` in `trap/sparse_materialization.rs:2699` is a non-clone
RAII owner of that fresh journal, the exact retained Stage1Authority and its
resolver. Preparation acquires it before source snapshot or physical effects.
Descriptor sync, commit and rollback all use those same retained owners.
PendingImport rolls back its descriptors before releasing physical publication;
pre-publication failures release the empty fresh journal through RAII. No new
semantic owner, mutex or post-admission editor was introduced.

The physical witnesses in `trap/foreign_mm/tests.rs:13382` and `:13387` now
pass. Under one admission owner, a second pending import refuses before physical
allocation identity counters change; the first translation, `away` bytes, pin
count one and full inventory remain intact. The fixture then covers both first
refusal restoring its original descriptor and first successful admission/commit.
A preexisting loader journal likewise retains its edits, open state, unchanged
physical inventory and ability to roll back after import refusal.

The minor contract finding is also closed: `el1-mm-exclusive-owner.toml` names
`carrick-vmm-hvf::trap::user_transfer::tests::native_owner_matrix_moves_bytes_with_balanced_physical_pins`.
Its evidence now states that the matrix itself uses physical HVF custody and
balanced pins. Cargo exact-name listing found one test; exact execution passed.

Scoped receipts: HVF `transfer_` nine passed; exact matrix one passed; scoped
HVF/AArch64/MMU all-target Clippy passed; `check-contracts` checked 92 contracts,
15 claims and 164 surfaces. The HVF fatal inventory moves the existing rollback
failure classification into ImportDescriptorUndo and retires only the old
missing-resolver abort: resolver absence now refuses before journal acquisition,
and successful preparation retains the resolver through cleanup. Parent owns
clean position reconciliation, final gates and the one scoped fix review.
No guest/Docker run or deferred Fork/Capacity/venue3 acceptance is claimed.

Final-wave verification correction: the serial HVF census rejected the import
wrapper extraction because FOREIGN_MM_TEST_LOCK was acquired only inside the
shared helper. All three `#[test]` wrappers now acquire that existing lock at
entry; the helper no longer acquires it, avoiding recursive locking. This
preserves the original runtime exclusion and restores its mechanical binding.
Focused census and all three import cases pass; no production source changed.


#### N1 controller verification and review receipt — 2026-10-03

The production UserTransfer slice is review-ready. The full branch review
covered `bb98e7aff..8eaa9baf3` and inventory/assembly tails. Its Important import
journal ownership finding and Minor executable contract binding were fixed in
`473c44253`; scoped re-review through `126641bd4` closes both and the observed
test-lock census regression, with no remaining findings or parked minors.
The earlier task review's four Important findings are also closed.

All requested foreground gates exited zero after the final production fix:

| Command | Final result |
|---|---|
| `cargo test -p carrick-el1` | 214 unit tests passed |
| `cargo test -p carrick-el1-abi` | 116 unit tests and two sealing doctests passed |
| `RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib` | 714 passed, three pre-existing ignored |
| `just test-kernel` | Kernel 2391 passed, one pre-existing ignored, 155 serial-host filtered; all selected kernel-semantics suites passed |
| `just clippy` | Workspace/all-targets warnings and no-panic gate passed |
| `just lint-domains` | Full recipe passed on clean committed `f9cf95018` |

Clean-tree inventory reconciliation at source `126641bd4` reports zero position
or identity drift: 601 host-operation rows retain their digest and reviewed
classifications. Only capture provenance was refreshed. The macOS compiler
census is a subset receipt; other-host runtime/profile acceptance is unclaimed.

The final receipt/temporary-workspace cleanup changes no production code or
verification input. The already-tracked scratch worker report is removed; its
implementation evidence remains in these receipts and prior commit history.
All fourteen controller ledger rulings were collected before removing only
this plan's scratch directory. Branch `work/n1` and its worktree are preserved.

No guest or Docker runs occurred. Fork rebinding, public bulk Capacity,
GuestMemory venue 3, prior production-admission reds/WorkObservation, signed
hardware coherence/TLBI and end-to-end N1/N2 acceptance remain OPEN. This
receipt is production-owner UserTransfer groundwork, not whole-N1 closure,
other-host runtime acceptance or adversarial security hardening.

#### N1c fork checkpoint — placement capacity boundary

The director identified frozen `coredumpbit`/`mmapcluster` witnesses whose
64 GiB and 16 TiB `MAP_NORESERVE` reservations exceed the current production
reservation arena. `Reservations::first_fit` refuses placement and the syscall
lowers it to `ENOMEM`. This fork checkpoint inherits the owner's layout; it
does not lift that placement bound. Those capacity witnesses remain OPEN for
N1's bulk Capacity/reservation-model work. No guest run is claimed here.

#### N1c production-owner fork checkpoint — 2026-10-03

Admitted copied MMs now fork through the production portal from live descriptor
words and the owner's reservation tree. Fork authenticates carrier, MM,
incarnation, sequence and generation; retains exact physical custody; and keeps
child execution closed until owner completion. Parent undo and child admission
are settled together. Outstanding UserTransfer refuses admission, stale
completion refuses publication, and two MMs at the same VA remain independent.
Parent deferred physical returns remain parent-owned; retired leaves are omitted
from the child. The director approved this choice, with explicit regression
coverage, rather than introducing host projection or forced settlement.

Private-file reservations retain HostBacking handle token, offset and generation.
Fork inherits that identity from the owner, including untouched MAP_PRIVATE
pages. Host custody serves bytes but supplies no fork VA/protection decisions.
The production fixture proves child file reads and private child writes with
parent and file bytes unchanged. Source lifetime is owner-counted in a bounded
AVL index and retirement queue; split, erase, revival and lookup budgets are
covered. EOF and partial-page handling use the owner's source identity.

The admitted path deletes TaskOnlyRuntimeAuthorities/clone_authorities and
process_plan child protection projection. Its MemState child inherits neither
private_file_maps nor deferred_anonymous.fork_private; the remaining projection
is explicitly confined to pre-admission setup. Runtime task TID/pidfd copy work
uses ordinary or scoped owner capabilities through preparation and settlement.
Executable structural copies retain bounded I2 publication before acknowledgement.
The neutral HAL dependency on carrick-el1-abi is documented in crates/README.md.

Red-first commits 8ed756c52, 23db4cad4, 5e31b831e and 6a8b0292e record host
protection projection, lost file source identity, child host source projection
and independent-custodian identity failures before implementation. The production
matrix now covers live child COW, parent unchanged on rollback, outstanding copy,
stale custody/completion, same-VA MM isolation, untouched private file, owner
DONTFORK/WIPEONFORK, exact retained tables and pending parent COW rollback. The
N0 admission assertion is positive specifically for Fork; the separate non-fork
host-semantic venue witness remains open. No broader exclusive-owner claim is
made from this checkpoint.

Final foreground verification on source 4f305b2f7 (all exit zero):

| Command | Result |
|---|---|
| `cargo test -p carrick-el1` | 231 passed |
| `cargo test -p carrick-el1-abi` | 118 passed and two sealing doctests passed |
| `RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib` | 717 passed, three pre-existing ignored |
| `just test-kernel` | Kernel 2399 passed, one pre-existing ignored, 155 serial-host filtered; selected kernel-semantics suites passed |
| `just clippy` | Workspace/all-targets warnings and no-panic gate passed |
| `just lint-domains` | Full recipe passed on the clean committed tree |

Additional host-only checks passed: check-layering; aarch64 Linux HAL/KVM/host
closure and closure-assert-no-hvf; x86_64 NetBSD NVMM all-targets check. The
pre-existing KVM missing dependency was fixed separately in 43b9b0e7a. The
FreeBSD cross check on macOS remains unavailable because the existing USDT
proc-macro expands host x0/x1 registers; the director approved recording that
limitation without changing unrelated observability code. No FreeBSD runtime
acceptance is claimed.

Inventory review preserves all 601 host-operation classifications and reconciles
five positions. Three macOS compiler profiles are executed receipts; six foreign
profiles remain pending. New abort and K1 operation rows were explicitly reviewed,
without allowances or gate weakening. The final HVC effect call is shared through
the existing reviewed production portal boundary, not a new assembly exemption.

No guest or Docker runs occurred. Hardware coherence/TLBI, signed end-to-end
acceptance, public bulk Capacity (including the frozen 64 GiB/16 TiB witnesses),
GuestMemory venue 3 and remaining non-fork ownership transitions remain OPEN.
This is a review-ready fork implementation checkpoint, not whole-N1 acceptance
or a claim of adversarial security hardening.

#### Venue-3 continuation boundary inspection — 2026-10-03

Inspected clean `e19e1377c` before changing production code. This is a scope
decision receipt, not implementation, red-first evidence or acceptance.
The director confirmed that scheduler-owned transfer capacity and suspendable
GuestMemory/dispatcher outcomes are prerequisites within venue 3. Suspension
must retain its completed offset, release execution capacity, and never lower
to EFAULT or acquire mutable engine ownership through an unchecked alias.

The remaining decision concerns the enclosing syscall's completion authority:

- `carrick-guest-mem/src/lib.rs:473` and `:522` expose synchronous `&self`
  checked reads. `MemoryError` at `:1182` carries no owned continuation.
- `carrick-aarch64/src/user_transfer.rs:202` advances an owned transfer using
  a mutable engine and borrowed-TTBR0 admission. Its `Suspended` result retains
  the transfer buffer and offset, but not the enclosing syscall's Rust stack.
  `engine.rs:8035` likewise needs mutable driving-vCPU ownership.
- `carrick-kernel/src/dispatch/outcome.rs:1183` converts every memory error
  to EFAULT. Merely adding a memory error variant does not preserve suspension.
- `carrick-kernel/src/dispatch/fs/rw.rs:1377` consumes socket bytes before
  the guest copy at `:1380`. The vector case at `:1643` consumes a segment
  before `:1646`, with remaining iovecs and total held on the handler stack.
  Re-dispatch after transfer completion would consume another payload;
  completing only the transfer would lose remaining iovecs and syscall return
  authority. These are concrete stream-corruption boundaries, not permission
  failures, and retaining only the UserTransfer byte offset is insufficient.

The director rejected general consuming-handler continuation migration as too
wide for venue 3. The chosen approach is two-phase UserTransfer: bounded
destination PREPARE resolves lazy/COW backing and takes pins before source
effects. Preparation may suspend and restart cleanly before consuming bytes;
copy into a prepared span must not suspend. Huge vectors prepare bounded
chunks and preserve Linux short-count semantics. Concurrent unmap may produce
a genuine EFAULT and the appropriate partial count. This supersedes the
initial recommendation to migrate enclosing handler continuations.

**Owner-admission seam:** physical pins alone do not establish
that non-suspending copy guarantee. In
`carrick-el1/src/personality/mm_portal/production.rs:470`, `try_begin_edit`
refusal returns `Ok(None)` even when mapping and physical custody are unchanged.
`serve_transfer` at `:630` lowers this to completion errno 11. It would occur
after source consumption in a selection/pin-only PREPARE implementation.
Retaining the current editor across source I/O contradicts the transport's
no-MM-lock-across-host-I/O rule; lowering editor contention to EFAULT contradicts
the director's suspension ruling.

The director chose the bounded EL1-issued prepared-copy permit, resolving this
decision. It retains semantic admission separately from the descriptor editor:

- Admission is range-scoped. Only overlapping edits defer; unrelated edits of
  the same MM proceed.
- Size is limited to the existing transfer chunk and lifetime to consumption
  of already-ready bytes plus memcpy. Never acquire it before a blocking host
  wait; prepare after source readiness or restart without consuming bytes.
- Conflicting munmap/mprotect/remap operations park on EL1-owned continuations
  and resume at commit/cancel, without spinning or parking host workers.
- Every failure cancels; commit checks the exact generation, refusing stale
  permits.
- Required reds: overlapping munmap waits during receive then applies;
  non-overlapping edits proceed; cancel releases waiters.

Post-consumption handler continuations were explicitly not chosen. This ruling
is not an implemented permit or verified non-suspension guarantee. Do not
delete the mirror before the prepared-copy lifetime protocol and scheduler read
service are bound. All implementation and verification below remain open.

The requested production reds remain unimplemented and unrun. `mmapv8align`
must bind to the EL1-map/mirror-unmapped checked-host-read witness;
`mmapprivatefiletrack` must bind to the private-file host-read/write witness
with two live same-VA MMs. Neither assignment is a passing receipt. Inverse
EL1 unmap/PROT_NONE EFAULT 14, raw-escape closure, internal-window confinement,
mirror storage deletion and all requested verification remain open. No signed,
guest or Docker execution occurred during this inspection.

#### Venue-3 atomic-record implementation ruling — 2026-10-03

The director approved an aggregate of page permits for datagram/SEQPACKET
receives. Prepare all pages covering `min(user buffer, record length)` after
readiness and before the nonblocking consume, with all-or-cancel preparation.
The record's socket maximum must be represented by a typed bound and asserted;
an oversized record fails closed. The existing chunk limit still applies to
each stream step. No permit may survive a blocking host wait. Truncation is
determined by the user's buffer, never by an internal permit-page boundary.
The added regression must deliver a record larger than one permit page and
smaller than the user's buffer whole. This ruling is not a test receipt.

Implementation scope includes a narrow `carrick-sched-core::object_wait`
extension: MM edit continuations need a queue identity distinct from IPC,
authenticated by exact address-space incarnation. IPC queue capacity remains
unchanged; any scheduler storage-layout change enters the ABI layout hash.
This out-of-fence support implements the required EL1-owned park/wake boundary,
not a host-worker wait or a polling substitute. Implementation and all venue-3
acceptance gates remain pending.

#### Venue-3 owner permit receipt — 2026-10-03

The owner implementation now separates semantic copy admission from the
descriptor editor. Detached per-page receipts retain exact request identity,
physical-custody authentication and notification admission while the wire slot
prepares another page. COMMIT/CANCEL claim generation and phase atomically,
without a root guard, descriptor words or current target grant. Elastic
reservation nodes hold permits; settled-only intrusive queues and direct
unlinking make preparing and settling an aggregate linear in its page count.
No socket-derived aggregate bound or host consuming handler is bound yet.

The director extended scope to a general scheduler completion primitive:
"owned WakeEffects collected under queue lock and delivered by holder after
unlock (including handback), no polled bitmap, no spin; scope extended to
sched-core and effect-delivery callers." Completion-enabled admission retains
exact queue incarnation until publication. Queue guards own the mandatory
effect callback, including internal cancellation/unlink. Held execution slots
transfer saved continuations through the carrier's existing host handback
authority. Host exit reconciliation drains these handbacks. Publication uses
one exchange and one link store; an interrupted producer retains custody and
the consumer returns immediately. MM queues and later metadata queues can use
the same primitive; IPC remains in its original namespace.

Actual red evidence, before implementation:
`RUSTC_WRAPPER= cargo test -p carrick-el1 prepared_copy_ -- --nocapture`
exited 101, with 0 passed and 2 failed:
`prepared_copy_overlapping_munmap_waits_before_any_mutation` and
`prepared_copy_releases_editor_for_unrelated_edit`. The old editor fence
prevented unrelated edits and did not reject an overlapping owner proposal
before mutation.

Actual green owner bindings in `mm_portal/tests.rs`:

- `prepared_copy_overlapping_munmap_waits_before_any_mutation` and
  `prepared_copy_releases_editor_for_unrelated_edit` close those two reds.
- `prepared_copy_commit_and_cancel_never_acquire_held_root_or_editor`
  covers held root/editor, actual short-copy length, unrelated MM generation
  changes and stale receipt refusal. An additional red-first assertion caught
  direct cancellation accepting an invalid slot; carrier/slot validation now
  precedes the claim, preserving the successor for legitimate cancellation.
- `prepared_copy_el1_edit_parks_then_commit_or_cancel_wakes_exact_saved_syscall`
  covers munmap/mprotect/remap, both commit and cancel, and a queue held across
  settlement. Saved arguments/PC/token resume and the owner edit actually
  applies, without a forwarded host retry.
- `prepared_copy_elastic_aggregate_prepare_and_settlement_have_linear_work`
  checks 16/64/256/320 pages, exactly N preparation visits and N settlement
  visits, and no settled-history rescan.
- `prepared_copy_metadata_capacity_suspends_before_source_and_recovers_after_cancel`
  exhausts elastic metadata before source effects, cancels prior receipts and
  demonstrates recovered preparation capacity.
- `prepared_copy_hardware_settlement_seam_needs_no_live_grant_or_descriptor_words`
  closes the target gate, holds the root and settles through the same helper
  used by hardware COMMIT/CANCEL with no descriptor-word input.

Scheduler witnesses are
`completion_held_queue_publication_advances_epoch_and_holder_delivers`,
`completion_admission_blocks_rebind_and_rejects_stale_incarnation`,
`completion_held_slot_transfers_exact_saved_operation_to_host_boundary`,
`completion_internal_cancel_unlink_delivers_pending_wake_after_unlock`,
`completion_publication_unlock_races_always_deliver` (64 races), and
`paused_producer_link_retains_custody_and_consumer_never_waits`. ABI witness
`detached_page_receipts_reuse_wire_slot_and_preserve_exact_settlement` covers
aggregate receipts independent of the single-flight wire slot.

Validation receipts: `cargo test -p carrick-el1` 239/239;
`cargo test -p carrick-el1-abi` 119/119 plus 2 compile-fail doctests;
`cargo test -p carrick-sched-core` 96/96. All used `RUSTC_WRAPPER=` and exited
0. Targeted kernel/runtime `cargo check` and targeted EL1/ABI/scheduler/
kernel/runtime `cargo clippy --lib -- -D warnings` also exited 0.

The owner layout witness prints Node=120, Root=280, State=256,
SharedReservations=420008, ZoneTables=5416128 and PortalSlot=192 bytes.
Owner layout version is 8, hash `0x9388e3e56ddcda4b`; object-wait protocol is
2, layout hash `0xa23b8b6353e28c37`. Appended transfer fields fit prior slot
padding; `MM_TRANSFER_LAYOUT_HASH` includes their offsets/states even though
slot stride is unchanged. Scheduler queue fields and carrier handback state
are appended; the expanded object-wait array was the last original
ZoneTables field, so earlier scheduler field offsets remain unchanged.
The global EL1 ABI hash incorporates both layout receipts.

Task 2 remains responsible for current-executor host service binding and
owner-authenticated target table access on the maintenance root. PREPARE/
select/one-shot still check target TTBR and use the primary-table alias
(`production.rs:881`, `:888`, `:893`); the maintenance mapping needs the
stage-1 pool window. Removing TTBR equality alone would authenticate the
wrong primary table. Host consuming paths, socket-derived aggregate bounds,
mirror deletion, inverse EFAULT/raw-escape proofs and signed acceptance
remain open. No guest, signed or Docker execution was performed for this
owner receipt. This receipt does not close N1 or venue-3 acceptance.

#### Venue-3 owner review fixes, round 1 — 2026-10-03

Review of `bef8b2a65` found two custody errors under
`kernel.el1.mm-exclusive-owner`: rejected exact claims stored LIVE twice,
allowing the second rollback to overwrite another claimant's COPYING state;
and a schedulerless portal could settle a scheduler-backed permit before
failing to publish its retained notification. Both are fixed without changing
the shared layout or the consuming-path work budget.

Rejection now has exactly one rollback owner. A successful claimed permit
restores exact COPYING-to-LIVE custody on Drop until settlement disarms it.
A private `PreparedDelivery` capability authenticates the required scheduler
venue before copying or releasing; publication afterward cannot refuse.
Rejected wire settlement restores the claim before publishing its completion,
so the rightful portal can cancel and wake an enrolled edit.

Actual new red command:
`RUSTC_WRAPPER= cargo test -p carrick-el1 prepared_copy_ -- --nocapture`
on the reviewed implementation plus tests and a scoped rejection pause.
Exit 101: 8 passed, 3 failed. Exact failing witnesses:

- `prepared_copy_rejected_tuple_cannot_overwrite_concurrent_claim` pauses a
  mismatched tuple on one thread, attempts a legitimate claim on another,
  and observes the legitimate COPYING claim becoming stealable.
- `prepared_copy_schedulerless_cancel_preserves_rightful_wake` observes the
  rightful cancellation returning Stale after the plain portal's error.
- `prepared_copy_schedulerless_commit_refuses_before_copy_and_preserves_rightful_wake`
  observes the copy callback running before delivery rejection.

The same filtered command is green, 11/11. Full EL1 is 242/242; ABI is
119/119 plus 2 doctests; scheduler is 96/96; targeted five-crate clippy
`--lib -- -D warnings` exits 0. EL1 and clippy were repeated after explicit
rollback-before-completion ordering. Cargo commands use `RUSTC_WRAPPER=`.
The existing held-root witness now also submits stale prepared COMMIT,
requires no callback and verifies zero completed bytes before legitimate
successor cancellation. This is current positive coverage, not a historical
red receipt.

Historical red reconciliation: the original overlap exclusion red reaches
its pre-mutation failure before a cancel/wake suffix can execute. The original
`7accff2e1` API has only editor fences and one-shot transfer, with no detached
permit/MM edit continuation seam. Separate pre-implementation behavioral reds
for direct cancel wake and stale prepared COMMIT were not recorded. Neither
new greens nor an absent-API compile failure establishes such a red. The
actual receive overlap/cancel host witness remains a Task 2 obligation.

#### Venue-3 maintenance-root prerequisites — 2026-10-03

Host cutover remains open. The carrier maintenance root now maps the retained
stage-1 table pool EL1-only, non-global and non-executable. Owner transfer
selection, lazy materialization and grant application authenticate target
physical tables independently of the executing root. Maintenance-root COW
uses one exclusive two-page alias pair per scheduler slot, with a retained
L3 page and claims in the unused EL1 counters-area gap at offset `0x1b0000`.
The shared ABI hashes this assignment; linker/boot and compile-time layout
checks protect neighboring image, descriptor, portal and IPC ranges.

`kernel.el1.mm-exclusive-owner` VM-free bindings:

- `carrier_maintenance_root_reaches_table_pool_without_el0_access` failed
  before the mapping because the leaf at `0x9a00000000` was absent; it passes
  alongside the existing kernel-only root test.
- `maintenance_copy_uses_service_root_without_target_aliases` failed before
  separation with `Declined(Refused)`; it now resolves and restores the service
  aliases without target copy aliases.
- `maintenance_copy_two_live_same_va_mms_use_disjoint_slots_and_restore`
  executes two COW operations with both pairs live simultaneously in one
  production-layout maintenance root, preserving different physical bytes.
- `maintenance_copy_failed_alias_install_restores_before_slot_reuse` refuses
  the second alias publication, performs no copy/repoint, restores the first
  alias, and releases the slot and physical grant for reuse.
- `service_copy_slots_are_disjoint_and_refuse_live_reentry` and
  `maintenance_service_authenticates_target_pool_not_current_alias` cover all
  256 slots, exact root identity and pool-boundary refusal.

These are owner service prerequisites, not the required checked GuestMemory,
receiving-handler, raw-escape, internal-control or mirror-deletion witnesses.
The frozen `mmapv8align` and `mmapprivatefiletrack` signed bindings are still
unrun here. No signed/guest/Docker execution belongs to this receipt.

The director's separate file `MAP_FIXED` over a sibling EL1 anonymous mapping
currently returns ENOMEM instead of replacement (work/tlb-budget
`93d2d0568`, `docs/perf-results/2026-10-03-tlb-budget/forced-gap-red.log`).
This remains an open N1b memory-policy/host-backing venue obligation; this
maintenance-root change does not claim to cover that witness.

Venue-3 physical short-count binding:
`prepared_short_commit_copies_only_actual_prefix_with_exact_physical_pin`
prepares 4096 bytes and commits 23, retaining exact physical identity and pin
lifetime while leaving the unconsumed tail unchanged. It failed before the
physical adapter fix because the copy required the prepared full length.
The production owner matrix now checks that COMMIT admits another editor
while its exact prepared range still overlaps; the previous matrix assertion
incorrectly required the old editor-held one-shot behavior. Host checked-memory
consumers and the full cutover remain pending.

Current-CPU review corrections (prerequisite only):
- `nested_shared_service_entry_refuses_without_panicking_or_effects`: actual
  red was RefCell panic at shared Fork entry; now nested entry refuses before
  CPU/transport effects and preserves the outer register image.
- `serial_host_busy_transfer_admission_keeps_carrier_unbound`: actual red
  changed initially unbound slots to carrier17 while refusing a busy CPU. One
  checked loan now precedes binding and all register/slot inspection.
- `serial_host_transfer_restore_failure_is_terminal`: injected restoration
  failure previously returned normally; the child now terminates with SIGABRT
  rather than exposing a reusable, partially restored executor.


Venue-3 owned file-description cursor prerequisite (inactive core):
- One cursor lives in DescriptionCommon, shared by dup/fork/SCM_RIGHTS.
  A short bookkeeping lock elects owned tickets; no borrowed description
  guard or pool worker waits for another guest operation.
- Release transfers custody to one successor, then delivers its notification
  after unlock. Queued cancellation removes its entry immediately; granted
  cancellation transfers once. Per-cursor iterative effect draining covers
  reentrant callbacks and final-Arc cancellation without stack growth.
- `cursor_release_wakes_one_successor_at_any_waiter_population` failed with
  two notifications for one completion at population2 in the initial
  broadcast implementation; the bound is one successor at 2/32/256 waiters.
- `cursor_callback_cancellation_does_not_recurse_through_successors` failed
  with callback depth256 versus1 before iterative draining.
- Release-before-enrollment, cross-thread ownership, canceled queued/granted
  custody and concurrent release during notification have focused witnesses.

This core does not activate dispatcher consumers. Existing read/write/readv/
writev/lseek/sendfile/splice offset callers still use the old description
locking paths until the owned recall/continuation unit replaces them. HostIo
staging, shared-file short-count commit, storage-wait executor release,
O_APPEND symmetry and admitted EL1 delegation removal remain OPEN. The old
ObservedCopy dispatcher source-consumption witness saw f_pos8192 before
copy, even though seek-back returned4096; its separate staged-core green
will not count as production dispatcher closure.

Cursor review round1 correction: callback delivery and final effect destruction
now have an enforced fatal unwind boundary. Runtime catches cannot resume a
description with an abandoned draining flag. The actual child regression
`serial_host_cursor_callback_panic_is_terminal` caught a callback panic then
observed successor wake0 versus1 before the fix (no SIGABRT); after the fix
it requires SIGABRT6. All seven cursor core tests pass. Consumer activation
and the remaining release/recall prerequisites stay open.
