# #1236 R1 machine facade spike

## Verdict

**S3 holds with changes.** A closed machine facade can carry the production
AArch64 EL1 HVC transport through to the original mailbox decoder. The proposed
search-and-replace alone cannot make the carrier portable. It also needs a
mapping geometry, a typed physical-abort contract, an owner-thread vCPU
boundary, and selected host adapters. Leave the hardware-specific entry,
GIC, and kick mechanics in HVF. Keep the mapping and task authority in the
same carrier.

The baseline is GitHub main `2d5cd13dc79094861f3d115600f65db52a170d4b`.
#2380 and #2564 are ancestors. #2579 was still draft at
`54887f5949f671cb6ebef21ab73e419a35f3edb6`. Its 59-file diff adds segmented,
pinned host residency views, grows residency outside the editor, and uses
descriptor-selected spans with prepared/retired descriptor transactions.
On ARM it changes stopped service, grant publication, host user transfer,
and sparse fault materialization. Preserve its single descriptor authority
and pin lifetimes when moving these modules. Its diff did not add a raw
stage-2 protection call or a literal `applevisor::` token. Regenerate the
rename and inventories after it merges. [#2579](https://github.com/carrick-sh/carrick/pull/2579)

## Runtime evidence

| Step | Observed |
| --- | --- |
| Baseline ARM Linux runtime compile | `cargo check --target aarch64-unknown-linux-gnu -p carrick-runtime --no-default-features --features platform-linux` succeeds, via the Linux cfgs. The ARM HVPatch runtime remains unavailable. Compiling `-p carrick-vmm-hvf` directly for that target fails with ten errors, including BSD imports, macOS-gated custody and Applevisor symbols, and `ForkResetBacking::prepare`. |
| Known-answer fixture on main | The existing admitted musl test reached HVC #2 after 10,305 blocks. The first SVC was `set_tid_address(96)` returning `-38`. The next was `ppoll(73)` on three stdio descriptors with no return. |
| Facade | The same ELF reached the same HVC #2 at `0x2d00010b3c` after 10,305 blocks, with post-HVC PC `0x2d00010b40`, ELR `0x4422e8`, and an actual mailbox publication containing ordinal 73 and three descriptors. `StagedCpu::initial_root` supplied the initial register snapshot. The production trampoline, vectors, EL1 image and stage-1 walker ran. GDB stopped in `MailboxBinding::take_request` under `decode_request` and `probe_facade`. The fixture asserts the production mailbox decoder accepted the request. |
| First unresolved boundary | The probe stops before runtime dispatch of `ppoll`. No hello stdout or guest exit. Fixture-created task/fd records are sufficient for mailbox publication, but omit the live native lifecycle references required by `set_tid_address`. The AArch64 frame still needs the host-readiness crossing for admitted stdio. |
| Diagnostic continuation | The existing synthetic `ppoll=0` control runs another 1,226 blocks to HVC #2 for `rt_sigaction(SIGPIPE, ..., 8)`. That fixture lacks the real signal tables. This observation is solely a diagnostic control. |
| Extent witness | The VM refused instruction fetch from a mapped non-executable page and from an unmapped page, then returned HVC #2 after an executable remap. ARM Linux host binary boot-probe suite had 30 ordinary passes and 3 fixture-dependent cases ignored. The static musl case passed its boundary assertions in a separate explicit run. |

This was an x86_64 Debian VM with 4 KiB host pages. Debian QEMU user mode
executed the ARM64 Linux host binary and its emitted AArch64 blocks. Carrick's
dispatcher executed the guest. Native hosted arm64 and signed HVF remain
unverified. Only Carrick and permissively licensed Applevisor source were
consulted. The GNU-linked EL1 and musl inputs had SHA-256
`8f8aeb312532393b6c4e616ac6e0c0df784612fc3d1e07327d3b080cd506cd40` and
`2cc8a37fe08ef2234b9a658c235099107fe543e8ee2f9c55e6d74ff4439fb153`,
respectively.

Main's real Mac launch runs `finalize_hvf_initial_image` and
`run_address_space_with_hvf_and_dispatcher`, prepares the carrier's root
zones and mappings, then restores the staged root on an owning persistent
executor. See `persistent_executor::{from_persistent_executor_spec,
allocate_persistent_mailbox_for_vcpu}`, the lifecycle publication in
`runtime/src/vcpu_loop/thread_lifecycle.rs`, and
`run_to_exit -> decode_hvc_syscall_exit -> MailboxBinding::decode_request` in
the HVF trap and mailbox code. The spike compiles the unchanged mailbox module
into the probe directly, since the whole HVF leaf fails its Linux cross-check.
The persistent executor, native lifecycle authority, production HVC router,
and runtime dispatcher were outside the executed path.

## Geometry audit

Class **A** is guest architectural or carrier guest layout. The Linux page
size stays 4 KiB. Other fixed guest layout sizes are retained independently.
Class **B** is host mapping, machine stage-2 geometry or storage grouping.
Class **C** is fixture, diagnostic, or test-specific. Source files below are
relative to the named crate's `src/`.

| Site | Class and 4 KiB impact |
| --- | --- |
| `guest-mem/lib.rs` `HOST_PAGE_GRANULE` and `vmm-hvf/trap.rs` `HVF_PAGE_SIZE`, root-slot validation | B. The shared constant equates HVF granularity with host granularity. Soft would reject valid 4 KiB-aligned roots. Keep separate host OS page, stage-2 alignment, and guest stage-1 page values. |
| `vmm-hvf/trap/mapping_plan.rs` region alignment and mapped lengths, `stage2_backend.rs` `contains_range`, backing placement and `IPC_WINDOW_GRANULE`, `execve_rebuild.rs` exec plan geometry, `hvf_aarch64_engine.rs` stage-2 size hook | B. Rounded ends may extend outside the logical view and IPC admission may reject legitimate Linux pointers. Map/replay/retire exact physical spans and carry their attributable backing length. The HVF direct-vs-escalated flags remain HVF policy. |
| `vmm-hvf/metadata_grant.rs` `install_backing_using`, `frame_pool.rs` size, allocation, and free/quarantine stride, `trap/global_frame.rs` fixed and allocated stage-2 leases, and `trap/carrier_custody.rs` stage-2 publication/retirement and compound claims | B. Dynamic metadata rejects 4 KiB allocations whose pointers are not 16 KiB-aligned. Pool IDs, leases, keys and invalidation ranges must agree on the physical grouping. Over-alignment is legal but wastes stock and may widen physical retirement or reuse. |
| `vmm-hvf/trap/frame_inventory.rs` `CowArmedRanges::COMPOUND_SIZE`, live-leaf probes, extent split/repoint/retirement, `task_mapping_index.rs` backing index, `process_plan.rs` fork replay/projection and retained invalid aliases, `persistent_executor.rs` fork omission comment | B. Compound owner keys and offsets can silently miss the real backing if only the map call changes. Fork omission and replacement must validate the exact 4 KiB leaves over the owning extent. Retain the guest page bits and separate the ownership grouping. |
| `vmm-hvf/trap/cow_engine.rs` local COW lookup/split/replace, scrub `HOST_PAGE`, high-VA alias rounding and file-offset congruence, `foreign_mm.rs` foreign owner COW, `guest_cow.rs` allocation and grant, `owner_fork.rs` fork stock and claims, `guest_memory.rs` retained-output initialization, `memory_protection.rs` alias inventory physical vs semantic length | B. Mixed 4 KiB ownership inside one old compound can cause wrong copy/zero/repoint or quarantine adjacent storage. Scrub at the host mapping unit only after exclusive ownership, and use the exact owner length for source offsets and retirement. |
| `vmm-hvf/trap/sparse_materialization.rs` anonymous/file-window layouts, offset mask and alignment; `trap/user_transfer.rs` compound-backed copy selection | B. Valid file offsets or small extents can be rejected or overmapped. Keep the stage-1 grant size and backing congruence separate. #2579 reinforces this by selecting the descriptor span before granting it. |
| `runtime/hvpatch/mod.rs` `STAGE2_PAGE_SIZE`, `align_up_stage2`, island allocation and collision checks | B. A 16 KiB minimum on a 4 KiB machine can widen island reservations or miss a valid candidate. The patched branch's reach and original 4 KiB executable intervals stay intact. `mm_resources.rs` numeric occurrences are test GPAs. |
| `mem/memory.rs` `HVF_MAPPING_PAGE_SIZE` in the default loader and fixed stage-2 compatibility alignment for mailbox, maintenance root, fd ceiling, guard assertions | B. Host-rounded ELF `PT_LOAD` regions and padded control mappings can cover a neighbour if used as logical ranges. Existing `load_elf_bytes_with_reader_at_pie_base_without_runtime_regions` already separates explicit mapping shape. Retain the guest control ABI addresses. |
| `mem/shared_aperture.rs` `GRANULE` in allocation, coalescing, carve, grow, shrink and quarantine; `mem/page_geometry.rs` Linux4K-on-16K uniform/composed/guarded policy | B. A valid 4 KiB fragment stays unnecessarily quarantined under the old geometry. The mixed-host-page policy is relevant to HVF and should be selected by mapping profile. |
| `mem/memory.rs` trampoline/vector/maintenance/sigreturn padded sizes, vector offsets and occupant checks, bootstrap L2B `+0x4000` and matching descriptor byte offset; `arch_sysregs.rs` SCTLR bit 14 | A/B edge. Existing control regions were padded for HVF and contain real layout/handler offsets. Retain emitted bytes and guest addresses across a host granule change. The L2B offsets name the fifth **4 KiB** table and SCTLR bit 14 is a register flag. `AT_PAGESZ`, GUEST_VMA_PAGE_SIZE, TCR and stage-1 leaf math remain 4 KiB. |
| `aarch64/engine.rs` focused walk diagnostics `+0x4000` and `aarch64/vmm.rs` `ForkCowRange` documentation | B/C. The diagnostic would sample the fourth adjacent 4 KiB page, but does not choose backing. The range comment assumes an HVF compound. `fork.rs` and `user_transfer.rs` literal uses are test addresses. |
| `vmm-hvf/trap/code_content.rs` and `carrier_custody.rs` 16 KiB cache-publication chunks | C for geometry. These are production work partitioning limits, independent of the minimum mapping granule. Keep their work bounds. |
| `core/mm/reservation/root.rs`, `core/terminal.rs` EL1 stack comments, `core/mm/{capacity,retirement}.rs`, `core/user_copy.rs`, `core/tests/{aarch64_fork_geometry,entry_completion,x86_acceleration}.rs`, `mem/pml4.rs`, `mem/memory/el1_clock.rs` | A/C. Stack capacity and x86 geometry are independent of HVF mapping size. The other numeric hits are test sizes, input addresses or wire offsets. No shared core mapping policy derives from these literals. |
| `vmm-hvf` `bin/*`, `hvpatch_probe_support/*`, `tests/*`, nested `tests.rs`, `*_tests.rs`, plus inline tests | C. Probe compounds describe real HVF on a Mac. Test literals cover offsets, fixture-backed extent sizes, accounting and alignment expectations. Shared geometry witnesses should test both 4 KiB and 16 KiB. |

A 4 KiB host can map 16 KiB ranges. The failures come from treating an
arbitrary 4 KiB mapping as if it had 16 KiB-aligned backing and from
rounding atomic ownership/permissions into adjacent pages. Holding the
16 KiB compound grouping deliberately in some profiles may be valid, if
every allocator, mask, issuer and reclaimer uses the same owned span.

The candidate sweep below produces 862 matches across 70 files at the
baseline, including tests, comments and fixed offsets. The compound and IPC
aliases and the alternate arithmetic spellings in the second sweep matter
more than raw numeric counts.

```sh
rg -n -i 'HOST_PAGE_(GRANULE|SIZE)|HVF_PAGE_(SIZE|MASK|SHIFT)|\b0x0*4000\b|\b16_?384\b|1\s*<<\s*14\b|16\s*ki?b' \
  crates/carrick-vmm-hvf crates/carrick-runtime/src/hvpatch* crates/carrick-{aarch64,mem,core}
rg -n 'COMPOUND_SIZE|HVF_MAPPING_PAGE_SIZE|STAGE2_PAGE_SIZE|IPC_WINDOW_GRANULE|16\s*\*\s*1024|\bGRANULE\b' \
  crates/carrick-vmm-hvf crates/carrick-runtime/src/hvpatch* crates/carrick-{aarch64,mem,core}
```

## Stage-2 reliance and fault shape

| Carrier site | Required behaviour for Soft |
| --- | --- |
| `vmm-hvf/trap.rs::run_to_exit` high-VA registered aliases and `stage2_backend.rs::inventory_hv_vm_map_replay` | Missing stage-2 extent on read, write or fetch exits with original VA, IPA and access. Replay uses registered backing/permissions, in the same VM, then retries at the unchanged faulting PC. HVF uses VA fallback when IPA is unavailable. Preserve authoritative remap result and repeated-fault bounds. |
| `vmm-hvf/hvf_aarch64_engine.rs::handle_memory_exit`, `trap/cow_engine.rs::try_lazy_alias_remap`, and `aarch64/engine.rs::run_to_next_syscall` | The secondary `Aarch64Exit::Memory { gpa, va }` hook can resolve a registered alias and retry. Today's usual HVF path runs replay inside the raw loop. Moving the decision must preserve direct-EL0 fault handling and serialization with alias retirement. |
| `vmm-hvf/trap.rs` direct EL0 abort and unreplayable EL1 image abort | Unhandled EL0 stage-2 abort retains the faulting PC and fault VA for signal synthesis, independent of stale guest ESR/FAR registers. An unreplayable EL1-image abort is a carrier fatal. A refused stage-2 walk must never be reported as normal guest EL1 stage-1 fault delivery. |
| `trap/stage2_backend.rs::hvf_perms`, direct map permissions, and `trap/sparse_materialization.rs` extent flags | Enforce independent R/W/X on the full physical span before side effects. Carry a translation vs permission cause, read/write/fetch class, ESR/ISS including the applicable access and walk bits, valid FAR/IPA or explicit absence, origin EL, and unretired PC. Preserve the existing hardware-only EL0 RW-to-RWX workaround within HVF. |
| `trap/cow_engine.rs::resolve_frame_cow_fault`, `ensure_frame_cow_write`, `trap/guest_cow.rs`, `trap/foreign_mm.rs`, `trap.rs` HVC #3 and #6 | No stage-2 write-protect is required to trigger these COW transitions on this head. No `hv_vm_protect` calls were found. COW arms 4 KiB stage-1 leaves, and the normal path handles the EL1 walker fault and owner grant. Current-EL stage-1 COW can exit HVC #3; owner work uses HVC #6. Host copyout calls `ensure_frame_cow_write` synchronously through retained owner authority. Replacement installs stage-2 backing before publishing the new stage-1 route. |
| `runtime/hvpatch`, sparse materialization, and #2579 descriptor path | Deferred private/anonymous faults usually start with absent or prepared stage-1 descriptors, then use explicit grants. They need stage-2 coverage before the valid descriptor is visible. A stale stage-1 descriptor pointing into a missing or retired physical extent is a distinct translation failure. The facade must never silently zero-fill it. |

Soft already delivers #2540's architectural **stage-1** abort through
`softcpu-aarch64/mmu.rs` and the common walker. Its descriptor reader calls
`GuestMemory::read`; a refused descriptor collapses to `MissingTable`.
Instruction fetch can collapse to `Stop::Fetch`; data stops retain only
the physical address in `MemoryFault`. Neither carries the complete
stage-2 exit record. A production port needs the original VA and access
at both the stage-1 table read and the final byte access, including
cache-hit permission checks and exclusive/pair operations. The spike
adds an opt-in physical fetch-permission hook, uses the softmmu extent
ledger and exact unmap, and reports denied accesses as diagnostic stops.
`LinearPlacement::host` currently requires an `AuthenticatedGpa` with a
crate-private constructor on the softmmu translation path. Expose
resolution for a physical span against an installed owner and retained
placement before replacing this spike's exact-extent host pointer lookup.
Keep backing generations and retirement around any retained translations.

## Darwin dependencies

There are zero `mach_vm_remap` / `vm_remap` symbols in the baseline crate
sources. The description of blanket non-Mac stubs in `carrick-host/lib.rs`
is stale. `host_mapping.rs` already uses libc on Linux for anonymous and
file-backed mappings and fixed file overlays. The counted/requeue ulock
interface really does stub out on Linux. `shared_word.rs` has a Linux futex
implementation. Darwin's kqueue wrapper lives in `carrick-host-bsd`; the
Linux EventMultiplexer implementation already uses epoll and eventfd.

The following inventory follows the actual primitive and selected consumers.
A nominal count of 28 depends on including portable mapping users, module
re-exports, timer and signal bridges, or diagnostic tools.

| Source | Role | Linux route and hello relevance |
| --- | --- | --- |
| `host/host_mapping.rs` | RAII backing, shared/private anonymous or file maps, fixed overlays | Existing mmap/munmap. Use retained memfd + MAP_SHARED and authorized MAP_FIXED if two different host addresses must alias the same anonymous bytes. The kernel mapping alone is insufficient without ownership and rollback. Initial RAM is a boot dependency. |
| `vmm-hvf/trap.rs` | Boot and VM map attachment | Existing portable mapping allocation plus machine stage-2 publication. Initial image, stack, vectors, page tables, mailbox and control blocks are boot dependencies. |
| `vmm-hvf/trap/stage2_backend.rs` | Exact physical attach/detach, replay, IPC windows | Same owned mapping plus Soft install/unmap. IPC window and directory admission are real root setup; the fixture bypasses them. |
| `vmm-hvf/trap/carrier_custody.rs` | Keeps host owners alive for the VM generation and rolls back failed installs | Retain backing with stage-2 record. Boot dependency. |
| `vmm-hvf/trap/persistent_executor.rs` | Binds the mapped carrier ranges to a resident executor | Same retained host backing. Boot dependency. |
| `vmm-hvf/hvf_aarch64_engine.rs` | Attaches carrier state and allocates mappings for memory operations | Existing mmap plus Soft stage 2. Root attachment is a boot dependency. Later backing operations depend on workload. |
| `vmm-hvf/frame_pool.rs` | Pre-mapped, reclaimable compound stock | Anonymous mmap plus extent ledger. Real launch provisions stock. Straight-line fixture supplied its initial pages. |
| `vmm-hvf/metadata_grant.rs` and `metadata_grant/native_service.rs` | Dynamic metadata backing and authenticated stopped-owner service | Anonymous mmap with owner pin. Root must install the service and initial tables; dynamic growth is outside this hello. |
| `runtime/vcpu_loop/reservations.rs` | Publishes retained reservation banks | Existing shared mmap. Root uses boot tables; allocate extension banks on demand. |
| `vmm-hvf/trap/global_frame.rs` | Retains and retires the physical backing owner | Existing mmap plus exact machine retirement. Required when real launch publishes frame stock. |
| `vmm-hvf/trap/cow_engine.rs` | Shared alias creation and replay, private copies and fixed anonymous zero scrub | mmap already supplies allocation and scrub. File-backed aliases reuse an fd; distinct anonymous host views can share a memfd. Ordinary static start does not exercise replay or fork COW. |
| `vmm-hvf/trap/sparse_materialization.rs` | File and anonymous first-touch backing | mmap/file offsets plus exact extent publish. Needed if a startup page is deferred. The fixture eagerly populated its boot pages. |
| `vmm-hvf/trap/foreign_mm.rs` | Retained owner replacement for a foreign MM | Same backing and retirement rules. Multi-MM path. |
| `vmm-hvf/trap/guest_cow.rs` | Supplies private COW extents | Existing mmap or pool. Fork/COW path. |
| `vmm-hvf/trap/owner_fork.rs` and `fork_stock.rs` | Child physical stock, backing retention and grants | Existing mmap; retain a shared object when two owners need it. Fork path. |
| `vmm-hvf/trap/process_plan.rs` and `trap/execve_rebuild.rs` | Rebuild and replay mappings for fork or guest exec | Existing mmap and machine stage 2. Separate from initial static ELF load. |
| `vmm-hvf/trap/user_transfer.rs` | Host copy via owned guest backing, including COW maintenance | Existing host views. A real stdout crossing uses guest reads; replacement and foreign paths are conditional. |
| `mem/shared_aperture.rs` | Logical reservation of shared backing slots | No Mach dependency. Provide machine mapping alignment. Needed by launch policy if the shared aperture is installed. |
| `kernel/kernel/objects/thread_control.rs` | Owns host-mapped kernel state on applicable lanes | Existing shared mmap. Preserve lifetime when the real zone is installed. |
| `host/ulock.rs` | Darwin `os_sync_*_address` and shared counted-wake / requeue ledger | Linux futex wait/wake/requeue. Use a shared key on genuine shared backing. Startup preinit result is ignored. The hello probe hits no futex wait. |
| `host/shared_word.rs` | Portable shared wait/wake adapter | Existing Linux futex arm. |
| `runtime/runtime.rs`, `vcpu_loop/binding.rs`, `vcpu_loop/wait_wake.rs` | Preinit plus Darwin shared futex dispatch, wait, counted wake and requeue | Reuse the Linux host-futex crossing and preserve the kernel wait-queue path for in-zone futexes. |
| `vmm-hvf/threaded_impl.rs` | Threaded carrier routing for wait/kick, bound to HVF engine | Use Linux wait bridges and owning executor. This is launch/runtime glue; shared futex operations are conditional. |
| `host-bsd/kqueue.rs`, `host-bsd/multiplexer.rs`, `vmm-hvf/darwin_kqueue.rs` | Typed kqueue, fd readiness and user wake | Existing `host-linux/epoll_mux.rs` and eventfd. Re-export files themselves require no Linux implementation. |
| `vmm-hvf/io_wait.rs` | Host fd poll/reactor, wake and delivery | `EpollMultiplexer`, eventfd and existing shared readiness service. The real startup `ppoll` needs ARM readiness crossing and immediate stdio sampling even with zero timeout. |
| `vmm-hvf/host_signal.rs` and `signal_arrival.rs` | Host ingress, child-exit notification and signal wake | Linux signal bridge/child watch plus eventfd. Root setup needs bridge ownership. The fixture does not receive an async signal. |
| `vmm-hvf/vcpu_kick.rs`, `timer_delivery.rs`, `itimer.rs`, `posix_timer.rs` | Kick worker, timer deadlines and delivery | Linux timer/deadline bridge plus epoll/eventfd as needed; Soft kicks use an event generation. Bridge initialization may run at launch; this hello has no measured guest timer dependency. |
| `kernel/event_mux.rs` and `dispatch/epoll_shim.rs` | User wake fanout and platform event adapter | Existing Linux eventfd. Startup poll can reuse the common service without constructing a guest epoll object. |
| `kernel/dispatch/net/{lifecycle,support}.rs`, `dispatch/sysv.rs` | BSD socket one-shot readiness and SysV host wait integration | epoll/eventfd and existing shared-word futex. Outside the hello workload. |
| `runtime/lib.rs`, `vmm-hvf/lib.rs`, `kernel/lib.rs`, `host/lib.rs`, `host-bsd/lib.rs` | Imports/re-exports and platform cfgs | Audit feature and target closure. These are not extra syscall sites. |
| `vmm-hvf/bin/hvf_svc_tax_probe.rs`, `observability/probes.rs`, `xtask/lease_supervisor{,/macos_scope}.rs` | HVF ulock tax, observation, and host lease supervision | Out of carrier hello scope. |

For a real launch, the critical host work is initial backing and retained
custody, lifecycle and zone publication, and host stdio readiness/transfer.
There is no evidence that a Mach-style remap, shared futex wait, or guest
timer is required to reach the observed static hello boundary.

## Thread affinity

| Site | Affinity invariant to carry forward |
| --- | --- |
| `vmm-hvf/trap/vcpu_admission.rs` `create_vcpu{,_with_permit}`, `trap/carrier_custody.rs` creation and rollback, `trap.rs` setup and initial sysreg writes | Create, configure and roll back a live vCPU on its executor thread. Global permit and topology owners are independent of the thread-local handle. Topology seals on first run. |
| `trap/persistent_executor.rs` `PersistentExecutorSpec`, mailbox allocation, invariant write/read/restore and destroy, `hvf_aarch64_engine.rs` staged/live variants and snapshot/restore | Pass specs, task data and backing authority across threads. The live hardware vCPU stays thread-local across many task loads. Do not turn a staged register file or transferable task record into a live machine object. |
| `trap.rs` `run_to_exit`, service and register/SIMD/sysreg helpers, `trap/execve_rebuild.rs`, `trap/vcpu_topology.rs::destroy_raw_vcpu` | Live run, state inspection, retire/forget, setup failure and exec replacement remain on the owning thread. Applevisor's vCPU is non-Send. Raw teardown currently exempts no normal post-first-run ownership handoff. |
| `gic.rs` MPIDR, ICC and redistributor setup, pending interrupt, vtimer arm/read and run accounting | Owner thread programs per-vCPU registers, with MPIDR established before redistributor use. Separate driver/GIC backing and cross-thread requests from owner-thread register mutation. |
| `vcpu_kick.rs`, `io_wait.rs`, `host_signal.rs`, `threaded_impl.rs`, runtime `vcpu_loop/{quiesce,signal,thread_adoption}.rs` | Other threads use handle/ID plus generation, request state or signal/watch routing. The cross-thread hardware exception is `hv_vcpus_exit`. Soft should expose a generation-checked kick capability and keep run/state on its persistent owner. |
| Runtime `vcpu_loop/executor/backend.rs`, `lifecycle.rs`, `binding.rs`; `aarch64/engine.rs` | Pool and scheduler own task admission, save and rebinding. Publish lifecycle and current-task identity on the owning executor. Async scheduler state must never infer task identity from a host thread or vCPU ID. |
| HVF raw standalone probes and shutdown tests | Separate fixture implementations create and run locally and kick by ID. Keep them out of the initial carrier rename unless they are being migrated deliberately. |

The single-thread Soft run satisfies the observed ordering without hardware
affinity. It does not verify cross-thread kick, GIC, teardown, or save/load
handoffs. The production facade should retain the non-Send vCPU property and
separate Send/Sync kick capability even when Soft is the only built variant.

## Rename census

The baseline has **433 literal `applevisor::` occurrences across 32 files**,
of which 430 are in the HVF crate. The count includes imports, comments, type
paths and inline tests. Imports make many actual calls unqualified. A separate
pass finds **45 `applevisor_sys::` occurrences** and must also classify aliased
FFI calls in GIC and standalone probes. Include imported register variants,
VM custody and raw-call boundaries in the scripted migration.

```sh
git grep -o -E '\bapplevisor::' HEAD -- crates |
  cut -d: -f2 | sort | uniq -c
```

| File | Occurrences |
| --- | ---: |
| `crates/carrick-aarch64/src/vmm.rs` | 1 |
| `crates/carrick-cli/src/hvpatch_carrier_cpu_attribution_profile.rs` | 2 |
| `crates/carrick-vmm-hvf/src/fork_stock.rs` | 3 |
| `crates/carrick-vmm-hvf/src/frame_pool.rs` | 2 |
| `crates/carrick-vmm-hvf/src/gic.rs` | 9 |
| `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs` | 16 |
| `crates/carrick-vmm-hvf/src/metadata_grant.rs` | 12 |
| `crates/carrick-vmm-hvf/src/trap.rs` | 97 |
| `crates/carrick-vmm-hvf/src/trap/carrier_custody.rs` | 40 |
| `crates/carrick-vmm-hvf/src/trap/cow_engine.rs` | 17 |
| `crates/carrick-vmm-hvf/src/trap/execve_rebuild.rs` | 3 |
| `crates/carrick-vmm-hvf/src/trap/foreign_mm.rs` | 9 |
| `crates/carrick-vmm-hvf/src/trap/foreign_mm/tests.rs` | 50 |
| `crates/carrick-vmm-hvf/src/trap/foreign_mm/tests/syscall_reads.rs` | 1 |
| `crates/carrick-vmm-hvf/src/trap/foreign_mm/tests/syscall_writes.rs` | 1 |
| `crates/carrick-vmm-hvf/src/trap/frame_inventory/tests.rs` | 40 |
| `crates/carrick-vmm-hvf/src/trap/global_frame.rs` | 1 |
| `crates/carrick-vmm-hvf/src/trap/guest_cow.rs` | 3 |
| `crates/carrick-vmm-hvf/src/trap/guest_memory/scrub_tests.rs` | 1 |
| `crates/carrick-vmm-hvf/src/trap/memory_protection/tests.rs` | 24 |
| `crates/carrick-vmm-hvf/src/trap/memory_protection/tests/maintenance_lookup_budget.rs` | 1 |
| `crates/carrick-vmm-hvf/src/trap/owner_fork.rs` | 9 |
| `crates/carrick-vmm-hvf/src/trap/persistent_executor.rs` | 27 |
| `crates/carrick-vmm-hvf/src/trap/process_plan.rs` | 2 |
| `crates/carrick-vmm-hvf/src/trap/sparse_materialization.rs` | 11 |
| `crates/carrick-vmm-hvf/src/trap/stage2_backend.rs` | 19 |
| `crates/carrick-vmm-hvf/src/trap/task_only_carrier_directory_tests.rs` | 2 |
| `crates/carrick-vmm-hvf/src/trap/thread_sibling_tests.rs` | 8 |
| `crates/carrick-vmm-hvf/src/trap/transport_test.rs` | 1 |
| `crates/carrick-vmm-hvf/src/trap/user_transfer.rs` | 3 |
| `crates/carrick-vmm-hvf/src/trap/vcpu_admission.rs` | 11 |
| `crates/carrick-vmm-hvf/src/vcpu_kick.rs` | 7 |

## Landable sequence after the spike

1. **Facade vocabulary and owner-thread handle.** Regenerate a scripted
   rename against the post-#2579 base. Reuse HAL's `MemPerms`, `Reg`,
   `SysReg` and `VcpuExit` as common values with explicit conversions at
   hardware edges. Keep the existing KVM and bhyve HAL trait users intact.
   Classify hardware-only GIC and raw calls before replacing imports.
   Preserve the exact existing register, flag, ownership and teardown paths.
2. **Move boot and transport by family.** Use pure moves for staged-root,
   mailbox, and HVC decode, with the runtime ARM adapter pointing at the
   same carrier. Prove a Linux-arm64 carrier-core compile witness against
   the direct-HVF red. Reuse the in-branch mailbox witness as a transport
   check. It does not count as that carrier-core compile witness.
3. **Move owner service, memory and fork/exec as separate families.** Keep
   descriptor selection and residency from #2579 shared. Introduce mapping
   geometry, keep logical spans vs physical backing lengths explicit, then
   move stage-2 custody/replay, COW/foreign transfer and fork/exec. Land each
   with a fixed-HVF profile and a witness over the same path. Add Soft
   translation and permission exits with VA, IPA, access and replay-state
   coverage. Match read/fetch, write and table-walk refusal cases.
4. **Reuse Linux host adapters and open the real hello path.** Install
   shared root lifecycle and zones, wire Linux fd readiness in the ARM
   ring entry, and enable the machine-backed ARM runtime. Bring up host
   memory, wait and signal crossings at their current authority boundaries.
   Verify static musl stdout and exit without injecting a response, then
   do the scheduled fork/exec, timer, kick and multi-thread witnesses.

Each landing would need its own independent review and appropriate
contract evidence. Whole moves keep signed HVF unit shards, cross-check
and signed queue evidence unchanged, with the same scoreboard population.
The spike is opt-in, does not edit any #2579 file and does not select a
different production execution path. Its raw HVF arm cross-checks only.
The probe maps fixture pages RWX, uses one stopped CPU, refuses aliases,
and supports exact unmap. It does not claim conformance, timing, or
equivalent HVF machine behavior.

ISA witnesses: arm=crates/carrick-softcpu-aarch64-host/tests/boot_probe.rs::facade_remap_changes_execute_permission_before_dispatch; x86=n/a (AArch64 HVC immediate normalization and physical instruction fetch in crates/carrick-hal/src/hypervisor/machine.rs and crates/carrick-softcpu-aarch64/src/dispatch.rs)
