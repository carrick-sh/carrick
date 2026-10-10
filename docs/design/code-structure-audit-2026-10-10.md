# Code-structure audit, 2026-10-10

- **Base:** GitHub `main` at `4e63042fe`, which includes PR 136. The sub-audits read `c9c603b9c`. The only difference between the two touches five files: `carrick-el1-abi/src/lib.rs` (the x86 CPL0 image size went from `0x12_0000` to `0x20_0000`, with a power-of-two assertion), `carrick-vmm-kvm/src/{cpl0_boot,carrier_interrupts}.rs`, `carrick-vmm-kvm/tests/cpl0_entry.rs` and `carrick-x86-cpl0/src/entry.rs`. Line numbers in `cpl0_boot.rs` past line 2000 may be off by up to about 56 lines. Everything else is exact for `4e63042fe`.
- **Method:** read-only. The tree was extracted with `git archive`. Nothing was built or run. Evidence comes from rg, sed, wc, normalized diffs and brace-matching scripts. Line counts are `wc -l` unless the text says "estimated".
- **Confidence labels for dead code:** CERTAIN means no reference outside the definition. LIKELY means only test or self references. SUSPECTED means the code is live but the design plan marks it for deletion, or no script ever compiles it.
- **Scope:** this document is an audit and a plan. It records evidence and proposes work. It does not claim anything has been fixed.

## 0. Executive summary

The shared-kernel direction is real, not aspirational. `carrick-el1` already builds for both `aarch64` and `x86_64` (`target_os = "none"`).
- x86 CPL0 instantiates the same `NativeProcessRuntime` (`carrick-x86-cpl0/src/native_process.rs:69`, with `X86Mmu`).
- The process graph in `carrick-sched-core/src/process/` is shared between the EL1 owner and the host kernel (`carrick-kernel/src/kernel/core.rs:3059`).
- `OwnerMmu`/`OwnerForkMmu`/`OwnerGrantMmu` (`carrick-mmu-core/src/owner_mmu.rs`) has implementations for both ISAs.
- The ISA layer in `carrick-el1` (`isa.rs` plus `isa/`) is 4,959 of 47,528 lines, about 10%. That is close to the owner's 6% estimate.

The duplication sits one ring outside those seams:

| Area | Duplicated or parallel lines (estimated) | Planned deletion (live today) |
|---|---|---|
| Syscall number/routing tables (8 hand-written encodings) | ~1,900 hand-maintained | none |
| Page-table walkers, COW adapters, COW grant supply, `OwnerCowMmu` | ~1,260 | host `perform_frame_cow` ~1,250; `frame_mailbox` 648 |
| Fork: guest service, host servicer, inheritance policy | ~450 | host ARM fork lanes ~6,600; x86 fixture fork lane ~1,650 |
| Kick, timer delivery, futex, fault tables across VMMs | ~700 | KVM fixture driver code in `cpl0_boot.rs` ~1,230 |
| Signal mask/altstack/pending/frame helpers, 4 signal-set types | ~400 | none |
| Total | **~4,700** | **~11,400** |

Dead code:
- CERTAIN: 232 code items, about 1.6k lines, plus 63 unused ABI constants.
- LIKELY: 743 test-only `pub` items, about 8.7k lines; 6.8k of those have production names.
- SUSPECTED: about 11.4k lines of live legacy code (the table above), about 7.9k lines hidden from the lint by 10 module-wide `#![allow(dead_code)]`, about 30 opt-out hatches, and about 13 debug features that no script compiles.

Correctness defects found while auditing. Each needs a red-first witness before it is fixed. Items 1 to 4 were confirmed by reading the code:
1. **rt_sigprocmask aliasing.** In `carrick-kernel/src/dispatch/signal.rs:2133-2167` the host lane writes `old_set` (line 2141) before it reads `new_set` (line 2149). When `set == oldset`, `SIG_BLOCK`/`SIG_UNBLOCK` then read back the old mask. An invalid `how` also writes `old_set` before returning EINVAL. Linux reads the new set first. The ring copy (`carrick-personality-linux/src/lifecycle.rs:458-500`) already documents this and hands aliased calls to the host.
2. **The two x86 COW classifiers disagree.** `X86Mmu::classify_cow` (`carrick-mmu-core/src/x86/owner_mmu.rs:118`) refuses `!leaf.ancestors_writable`. `classify_guest_cow_write` (`carrick-mmu-core/src/x86/descriptor_txn.rs:1062-1097`, used by the fault path at `carrick-el1/src/cow.rs:223`) has no ancestor check.
3. **Two values for `IRQ_HEADER_GPA`.** `carrick-x86/src/interrupts.rs:8` has `0x10_0000`; `carrick-el1/src/isa/x86/interrupts.rs:9` has `0x1d_0000`. Only the host value is read (`carrick-vmm-kvm/src/cpl0_boot.rs:3497`). The guest file also redefines every vector constant.
4. **The KVM continuation skips two steps.** `block_forward` (`carrick-runtime/src/vcpu_loop/executor/kvm.rs:467`) builds a `ContinuationCapture` but never calls `bind_product_futex` or `install_temporary_signal_mask`. HVF does both (`vcpu_loop/mod.rs:1298-1299`). A ppoll/pselect6 sigmask, or a futex binding, is lost on x86.
5. **Fork service divergences** (sub-audit, not independently re-read):
   - x86 `abort_mm` sends no `ForkStockSettlement` (`carrick-x86-cpl0/src/native_process.rs:380-390`), so the KVM `fork_pending[cpu]` loan is never released.
   - x86 `retire_mm` pushes onto `static RETIRED: SpinLock<Vec<Mm>>` (`native_process.rs:34, 513-515`), and nothing ever drains it.
   - ARM does not override `fork_fd_table` (default comment at `native_process_runtime.rs:136-148`), so the fork child shares the parent's fd table.
   - `fork_lifecycle_available` is never reset on commit (`carrick-vmm-hvf/src/fork_stock.rs:323/353/405`, `carrick-vmm-kvm/src/cpl0_anonymous.rs:706/~791`). Each carrier therefore allows one committed native fork for its lifetime.
   - ARM `abort_mm` discards its settlement result with `let _ =` (`carrick-el1/src/personality/aarch64_process.rs:494-499`).

## 1. Duplicate implementations

### 1.1 Fork stock, loans, child retirement

**Guest `NativeProcessService`: two copies of one concept**
- ARM: `carrick-el1/src/personality/aarch64_process.rs` (616 lines). The impl is at 268-600; `prepare_mm` is 275-451.
- x86: `carrick-x86-cpl0/src/native_process.rs` (572 lines, `include!`d at `entry.rs:355`). The impl is at 177-530; `prepare_mm` is 181-352.
- `diff -w` of the two `prepare_mm` bodies gives 61 changed lines out of about 350. The ISA content is only:
  - the MMU type;
  - the crossing: the ARM `ForkStockCrossing` trait vs inline `asm!("out dx, eax", FORK_STOCK_PORT)` on x86 at about line 277. x86 bypasses the trait that already exists at `aarch64_process.rs:68-112`;
  - root encoding: ARM `asid<<48 | base`;
  - the wake IPI.
- `settle` (ARM 507-545 vs x86 532-569), venue/release/deliver_wakes (114-156 vs 87-127), `quarantine_*`, `child_lifecycle` and `commit_mm` match line for line.
- Root exit has the same split: `cross_root_exit` (`aarch64_process.rs:602-611`) vs inline `out dx, al` (`carrick-x86-cpl0/src/native_execution.rs:66-80`).
- About 250 duplicated lines.
- **Shared home:** one generic `impl NativeProcessService for NativeService<B: OwnerForkMmu, X: ForkStockCrossing + IsaWake>` in `carrick-el1/src/personality/`.

**Host fork-stock servicers: two copies**
- HVF: `carrick-vmm-hvf/src/fork_stock.rs` (1,685 lines). KVM: `carrick-vmm-kvm/src/cpl0_anonymous.rs` (2,070 lines).
- `take_fork_table_stock` is a verbatim 39-line copy: HVF 78-116, KVM 138-176.
- `GrantExecution` plus `matches()` (HVF 28-52, KVM 124-136) and `PendingForkLoan` (HVF 56-62, KVM 255-260) are the same.
- Loan admission (`service_loan` HVF 182-365 vs `service_fork_stock` KVM 609-737) and settlement (HVF 367-465 vs KVM 739-970) follow the same step sequence.
- About 150 duplicated lines.
- **Shared home:** `carrick-hal::fork_stock::ForkStockCustody`. Both VMM crates already depend on it, and it owns `AsidAllocator`. Record access and the frame ledger go behind a trait.
- HVF hand-repeats the rollback sequence about 7 times (`fork_stock.rs:225-357`). An RAII `LoanGuard` should replace it.

**Linux fork-inheritance policy, written more than three times**
- Guest side: `carrick-el1/src/personality/mm_portal/fork.rs:58-79`, `carrick-x86-cpl0/src/process.rs:37-53` and `carrick-core/tests/x86_acceleration/fork_cow.rs:136-155`.
- An inline custody filter at `aarch64_process.rs:336-345` and `native_process.rs:238-247`.
- Host side: `carrick-kernel/src/dispatch/mem/vma.rs:570-579`, `carrick-vmm-hvf/src/trap/process_plan.rs:849-860, 1230-1262` and `cow_engine.rs:7626-7810`.
- **Shared home:** `carrick-personality-linux/src/mm.rs:157-163` (`inherits`), as a typed `ForkInheritance` enum.

**Parallel fork lanes**
- ARM production fork is still host-orchestrated: `carrick-kernel` `clone` (`dispatch/proc.rs:3443`) → `mm_authority.rs:1095-1120` → `carrick-runtime/src/vcpu_loop/lifecycle.rs` (2,271 lines) → `carrick-aarch64/src/engine.rs:6237 build_process_spec`. From there:
  - `build_owner_process_spec` (8715) → `carrick-vmm-hvf/src/trap/owner_fork.rs` (904 lines), which runs the synthetic MM_PORTAL ESRs (`carrick-el1/src/entry.rs:46-54`);
  - or `persistent_executor.rs:1221` → `trap/process_plan.rs::build_setup_process_plan` (557; the file is 2,502 lines).
- `carrick-aarch64/src/fork.rs` (395) belongs to the same lane.
- The in-ring ARM fork (`Aarch64NativeProcessService::new`, `HvcForkStockCrossing`, `cross_hvc_fork_stock` at `isa/aarch64.rs:42`) is built only in `aarch64_process_tests.rs`. The HVF `GRANT_OP_FORK_STOCK` handler (`metadata_grant.rs:782-915`) has no production guest caller.
- x86 has a fixture fork lane: `carrick-x86-cpl0/src/process.rs` (515 lines; fixed MMs 77/78, `CHILD_ROOT 0x31_0000`) plus `carrick-x86/src/cpl0_lifecycle.rs` (1,136 lines, `#[path]` in `fixture.rs:24`). It is built into the fixture binary that `cpl0_boot.rs` loads.
- `carrick-vmm-hvf/src/fork_quiesce.rs` is a 7-line re-export shim. It has about 108 `crate::fork_quiesce` call sites. AGENTS.md bans shims.

### 1.2 Page tables, frame inventory, owner grant, COW

**ISA trait families for one MMU concept (4)**
- `OwnerMmu`* (`carrick-mmu-core/src/owner_mmu.rs:21-147`): typed.
- `OwnerCowMmu` (`carrick-core/src/mm/cow.rs:64-100`): raw `u64` throughout. Its adapters are `carrick-el1/src/cow.rs:18-176` (ARM) and `200-~387` (x86), about 360 lines. Its `classify_cow_write` duplicates `OwnerMmu::classify_cow`.
- `MmuBackend`/`MmuEditBackend` (`carrick-guest-arch/src/lib.rs:659-700`).
- Host `PageTableCodec` (`carrick-hal/src/guest_arch.rs:57-78`). Its `Manager` is `PageTableManager` or `Pml4Manager`, and those share no trait.
- **Target:** one typed trait set in `carrick-mmu-core`.

**x86 4-level walk/edit (4 copies, about 350 lines)**
- `carrick-mem/src/pml4.rs` (953 non-test lines; used by KVM's legacy engine, bhyve and the hal).
- `carrick-mmu-core/src/x86/descriptor_txn.rs:946-1040`: the in-ring authority.
- A hand-rolled walk at `carrick-vmm-bhyve/src/bhyve_x86_engine.rs:289-324`.
- A fixture walk at `carrick-vmm-kvm/src/cpl0_boot.rs:2217-2245`.

**AArch64 ad-hoc stage-1 walks (about 300 lines)**
- `carrick-mmu-core/src/aarch64.rs:1661-1700, 4593, 4923`, `owner_mmu.rs:86-114`, `aarch64/descriptor_txn/{guest_cow.rs:96, copy_window.rs:40}`.
- `carrick-vmm-hvf/src/trap/cow_engine.rs:14-51`, `foreign_mm/current_read.rs:38-90`, `foreign_mm.rs:1682, 4781`.
- `carrick-el1/src/memory.rs:516`, `carrick-core/src/mm/fork.rs:14`.
- The clearest pair is `carrick-el1/src/personality/mm_portal/maintenance.rs`: `retired_page` (285-310) and `retired_page_x86` (315-345) are one algorithm. `carrick-core/src/mm/frames.rs:216-235` shows the generic target pattern.

**COW run types (3 near-identical)**
- `aarch64::guest_cow::GuestCowRun` (`guest_cow.rs:36`), x86 `CowRun` (`x86/descriptor_txn.rs:1052`; `va: u64` next to `old_ipa: FrameGpa`) and core `GuestCowRun` (`core/mm/cow.rs:30`).

**Host vs in-ring COW**
- Host: `trap/cow_engine.rs` (8,224 lines). `perform_frame_cow` is 3314-4560, about 1,250 lines.
- In-ring: `core/mm/cow.rs` (304) plus the `el1/cow.rs` adapters.
- The host fallback is live: `resolve_frame_cow_fault` (`cow_engine.rs:4745`) calls `perform_frame_cow` when `refill_guest_cow_pool` returns false (lines 4763, 5031, 4568).

**Host COW grant supply (about 250 lines)**
- HVF `trap/guest_cow.rs` (`provision_guest_cow_grants` 56-127, `refill_guest_cow_pool` 149-200) vs KVM `cpl0_anonymous.rs` (`supply_cow_grant` 995-1141, `settle_cow_grant` 1142-1238).
- **Target:** one host supplier over `carrick_core_abi::CowGrantPool`.

**Frame inventory**
- `carrick-kernel/src/kernel/frame_inventory.rs` (3,193 lines).
- HVF `trap/frame_inventory.rs` (3,627), `global_frame.rs` (4,352) and `carrier_custody.rs` (4,527).
- KVM `carrier_memory.rs` (1,340) defines `InventoryTransaction`/`InventoryRetirement` at :246-257, private to KVM.
- Only the identities in `carrick-core-abi/src/mm/inventory.rs` (294) are shared. AGENTS.md requires stage-1, stage-2 and inventory publication to be one transaction, so the transaction trait belongs in `carrick-hal` or `carrick-core`.

**Wire types in the wrong module**
- The ISA-neutral grant types `DescriptorTxn`, `DescriptorTxnId`, `InlineJournal` and `DescriptorJournal` live under `carrick_mmu_core::aarch64`. x86 re-exports them (`x86/descriptor_txn.rs:2-4`), so `OwnerGrantMmu::execute_grant` takes an aarch64 type.
- `BackingIdentity` (`aarch64/descriptor_txn.rs:124`) duplicates `carrick_guest_arch::EditBacking` (`guest-arch/lib.rs:305`) field for field. `x86/owner_mmu.rs:225-230` copies between them.
- **Target:** a neutral `carrick_mmu_core::grant` module.

### 1.3 Process owner and native process runtime

- Shared: `NativeProcessRuntime` (`carrick-el1/src/personality/native_process_runtime.rs`; 1-2446 production, 2447-5054 tests), `process_owner.rs` (1,085), the sched-core process graph, and `carrick-personality-linux` lifecycle routing.
- Duplicated: the service layer (§1.1) and the in-guest context switch.
  - `carrick_el1::sched::ThreadCpu` (`sched.rs:20`) is ARM-shaped. Its x86 impl (`sched/hw.rs:253-262`) calls `fatal_entry_binding()` for `save`, `load`, `set_translation` and `invalidate_asid`.
  - x86 parks and restores through `carrick-x86/src/cpl0_scheduler.rs:70,90`.
  - `carrick-guest-arch` already defines `KernelArch = EntryArch + InterruptArch + MmuArch` (`lib.rs:697-721`), which nothing uses for this.
  - **Target:** `Sched<A: KernelArch>`, then delete `ThreadCpu` and the cfg-duplicated `IrqGuard` (`hw.rs:382-442`).

### 1.4 Syscall routing tables: 8 hand-written encodings

1. `carrick-abi/src/syscall.rs:280-334`, `define_aarch64_syscall_table!` (338 rows). This is the right source.
2. The same file re-encodes properties as numeric-range matches: `authority_for_aarch64` 106-172, `handler_for_aarch64` 174-251, `compat_note_for_aarch64` 253-276.
3. `carrick-syscall-abi/src/lib.rs:25-71`: 43 hand-typed `CanonicalNr` constants. carrick-abi depends on carrick-syscall-abi, the inverse of what you would expect. The root cause is that carrick-abi is not `no_std`.
4. `carrick-personality-linux/src/crossing.rs:15-160`: 123 more `CanonicalNr` constants, plus the `HOST_CROSSINGS` table at 165-173.
5. `carrick-personality-linux/src/dispatch.rs:526-648`, `route_aarch64`: 22 raw-literal arms (`214 => Brk`, `139 => SignalReturn`) mixed with 46 `nr::X.raw()` guards and a third spelling, `crossing::nr::DUP`, at 831-850. It also serves canonicalized x86 calls, so the name is wrong.
6. `carrick-syscall-abi/src/syscall_x86_64.rs:113-905`: 312 rows, each repeating name and canonical number as literals. The mapping is checked by a test, not derived.
7. `carrick-hal/src/x8664_arch.rs`: 54 raw `X86_NR_*`/`CANONICAL_*` constants (885-1100) and `normalize_syscall` (1111-1582).
8. `carrick-personality-linux/src/entry.rs:11-46`, `decode_x86_64`: a second x86 normalizer (clone arg swap, dup2, fork) without the hal's open/stat/unlink rewrites. **The host and ring x86 lanes canonicalize differently.**

Side tables of raw numbers:
- `carrick-kernel/src/kernel/continuation.rs:2686` `is_restartable_syscall` (18 literals, takes `nr: u64`).
- `carrick-kernel/src/container_policy.rs:136-143`, `carrick-el1/src/memory.rs:18-21`, `carrick-el1/src/personality/dispatch.rs:1606-1660`.
- `carrick-personality-linux/src/{lifecycle.rs:274-279, entry.rs:8, sched.rs:22}`, `carrick-x86/src/bringup_fns.rs:591-598`.

There are three handler classifications: the kernel `SyscallHandler`, the abi `SyscallHandler` and the personality `Family`.

**Target:** one `const`, `no_std` table in `carrick-syscall-abi` (name, canonical nr, x86 native nr or remap, authority, family, host-crossing flag, restartable). Generate everything else from it. About 1,900 hand-maintained lines collapse.

### 1.5 Signal delivery

- Frame build/restore is behind `GuestArch` (`carrick-hal/src/sigframe.rs:93/395`, `x8664_arch.rs:475/696`). The ISA-neutral steps are still copy-pasted:
  - siginfo selection: `sigframe.rs:160-176` vs `x8664_arch.rs:614-629`;
  - uc_stack SS_ONSTACK;
  - altstack SP choice: `sigframe.rs:466` vs `x8664_arch.rs:393/580`.
- `InjectParams` assembly is repeated in `carrick-aarch64/src/engine.rs:~4970` and `carrick-x86/src/engine.rs:~1324`.
- rt_sigprocmask and sigaltstack are implemented twice: kernel `dispatch/signal.rs:2133, 1931` vs `personality-linux/src/lifecycle.rs:458, 508`. The ring copy uses local raw `SIG_BLOCK`, `UNBLOCKABLE` and `SS_*` constants (306-320).
- Type duplication:
  - 4 signal-set types: `carrick_abi::SigSet` (`lib.rs:370`), `carrick_signal_core::SignalSet` (`lib.rs:28`), and two `PendingSignals` in one crate (`personality-linux abi/thread.rs:191`, `signal.rs:31`).
  - 3 block-mask types.
  - 4 signal-number types: `Signal(u8)`, `LinuxSignal(NonZeroI32)`, kernel `abi_args::Signal(pub i32)`, and raw i32.
  - 4 "lowest pending" implementations.
  - 2 default-disposition models: signal-core `policy.rs:262` vs kernel `objects/signal.rs:929/973`. carrick-kernel and carrick-runtime do not depend on carrick-signal-core.
- `carrick-runtime/src/vcpu_loop/signal.rs:92-130` decodes aarch64 ESRs in the generic runtime.
- Open PR #131 adds `carrick-el1/src/personality/arm_signal.rs` (279) next to `x86_signal.rs` (276). That is a new per-ISA pair, which should be a single implementation with an ISA hook.

### 1.6 Zone, executor, doorbell

- **Executor lease: shared, keep it.** `PersistentExecutorFactory`/`PersistentExecutor` (`executor/backend.rs:473,482`) have implementations for HVF (`:697`) and KVM (`executor/kvm.rs:530`). `run_initial_process` is gone.
- **Continuation preparation is copied, not shared.** See defect 4. The design doc (`x86-cpl0-executor-lifecycle.md`) asks for the architecture-neutral core to be extracted. **Target:** `carrick_kernel::continuation::prepare_blocked_continuation(context, lease, request, input)`, called by both backends.
- **Two pool launchers:** KVM `prepare.rs:150-220` vs HVF `wait_wake.rs:735-790` → one `CarrierLauncher`.
- **Three admission authorities:** `threaded_loop` with the global `vcpu_sched` (`threaded_loop.rs:302`, still the HVF entry via `runtime.rs:787`), the kernel `Scheduler` (`scheduler.rs`, 10,147 lines), and the sched-core zone, reconciled by `vcpu_loop/zone.rs` (1,746). The `carrick-hal/src/scheduler.rs` header points to a stale location.
- **Six kick mechanisms:**
  1. `VcpuKick`/`VcpuRegistry` (`threaded.rs:119,364`);
  2. `Aarch64Vcpu::kick`;
  3. `HvVcpu::kick` stubs;
  4. kernel `ExecutorKick` with `ExactHardwareKick`;
  5. the global `el1_zone::SLOT_KICKER`, registered only for HVF (`wait_wake.rs:761`), so KVM has no slot kick;
  6. the KVM MSI `0xfee0_0000|apic<<12` construction, copied at four sites (`carrier_interrupts.rs:72`, `cpl0_boot.rs:691, ~3989, ~4096`, `cpl0_anonymous.rs:365`).
- The kvm/bhyve/nvmm pthread_kill kickers (330/81/79 lines) are the same code with a different signal number.
- **Byte-identical copies:** `TimerDelivery` for KVM (`timer_delivery.rs:25`), bhyve (`bhyve_threaded_glue.rs:23`) and NVMM (`nvmm_threaded_glue.rs:19`) has a 0-line normalized diff. `bhyve_futex.rs` = `nvmm_futex.rs`. The bhyve/nvmm signal backends differ in 4 comment lines.
- **bhyve re-implements the x86 fault tables.** `carrick-vmm-bhyve/src/guest_setup_x86.rs` (4,195) defines its own `IdtGate64`/`Idt64`/`Tss64` and stubs (288-859) beside `carrick-x86/src/fault.rs`. The two have diverged (8 vs 256 slots, stride 64 vs 128), yet bhyve still decodes through `carrick_x86::fault_exit_from_record`.
- **Fixture driver code in the production crate:** `cpl0_boot.rs` has 27 `pub fn fixture_*`, `boot_lifecycle`/`stock_lifecycle` (~5634 to EOF), `fixture_run_until` (~4114, with a watcher thread and a 5 s spin) and `Watchdog` (754). About 1,230 lines, ungated; carrick-vmm-kvm has no `[features]`.

### 1.7 Layout constants

There are three layout authorities:
- `carrick-el1-abi/src/lib.rs`: 80 `*_BASE/_GPA/_VA/_OFFSET/_SIZE` constants as raw `u64`, EL1 and X86_CPL0 mixed, between lines 71 and 2400;
- `carrick-mem/src/memory.rs`: 50 (`LINUX_KERNEL_REGION_BASE` etc.);
- the typed `carrick_guest_arch::KernelLayout`/`KernelVa`, used only in `carrick-el1/src/isa.rs`.

Per-VMM x86 layouts add more: `vmm-bhyve/guest_setup_x86.rs` 16 and `vmm-kvm/guest_setup_x86.rs` 7.

Census of page-aligned hex literals in non-test code: 156 distinct values appear in two or more crates and 78 in three or more. Small values (0x10000, 0x200000) are mostly sizes; the meaningful repeats are below.

| Value | Meaning | Restated at |
|---|---|---|
| `0x2D_0400_0000` | EL1 region base | `el1-abi lib.rs:71`; restated as a literal in `mmu-core aarch64/descriptor_txn/copy_window.rs:17` (`COW_COPY_WINDOW_BASE = 0x2D_0400_0000 + 0x1A_0000`) |
| `0x2D_0000_0000` | kernel control window (L1 index 180) | `carrick-mem/memory.rs:3931,3937`, `mmu-core aarch64/owner_fork.rs:17,46,80`, `vmm-kvm guest_setup_x86.rs:40`, `vmm-bhyve guest_setup_x86.rs:125`, `vmm-kvm guest_setup.rs:1020` (`KERNEL_HOLE_END = 0x2D_0020_0000`) |
| `0x9A_0000_0000` | stage-1 table pool | `el1-abi lib.rs:169`; literal in `hvf_aarch64_engine.rs:3200,3216,3311,3348`, `mmu-core aarch64.rs:10280`, `observability probes.rs:3281,3288`, `hvf staged_cpu.rs:236,252` |
| `0x0000_ffff_ffff_f000` | AArch64 descriptor PA mask | 75 occurrences in 33 files. `TTBR_BADDR_MASK` alone is defined 3 times in `carrick-el1` (`fault.rs`, `memory.rs`) |
| `0x000f_ffff_ffff_f000` | x86 PTE address mask | 13 occurrences in 9 files under 6 names (`PML4_ADDR_MASK`, `ADDRESS`, `TABLE_ADDR` ×2, `ADDRESS_MASK`, `PTE_ADDR`) |
| `0xffff_ffff_8000_0000` | x86 supervisor image VA | `el1-abi lib.rs:206`, `vmm-kvm carrier_interrupts.rs:139`, `x86/engine.rs:2319`, `carrick-mem/pml4.rs:1546,1566,1599`, `el1/isa/x86/user_access.rs:33`, `x86-cpl0/link.ld` |
| `0xffff_ffff_d000_0000` | LAPIC VA | `x86/interrupts.rs:11`, `el1/isa/x86/interrupts.rs:12`, literal in `el1-abi lib.rs:257` |
| `0xffff_ffff_b000_0000` | progress/lifecycle zone | `x86/cpl0_scheduler.rs:131` (`PROGRESS_ZONE`), `x86/cpl0_lifecycle.rs:310` (`LIFECYCLE_ZONE`), literal in `el1-abi lib.rs:255` |
| `0x10_0000` / `0x1d_0000` | IRQ header GPA | conflicting values (defect 3); the true value is `X86_CPL0_SUPERVISOR_IMAGE_GPA` plus `.irq_header` offset 0 |
| `0x10_2000` | `PROGRESS_HEADER` = image + 0x2000 | `cpl0_scheduler.rs:132`; the same address is bhyve `X86_LSTAR_GPA` |
| `0x7fff_0000` | x86 initial user stack | `cpl0_boot.rs:71`, `x86-cpl0 process.rs:25`, `entry.rs:~1277`, `el1/isa/x86/initial_mm.rs:725,862`, `x86/cpl0_scheduler.rs:232`, `x86/bringup.rs:288` |
| `0x1400_0000` | hvpatch probe base | 23 occurrences, mostly `vmm-hvf/src/bin/hvpatch_probe_support` and `runtime/hvpatch/patcher.rs` |

`X86_CPL0_INITIAL_EXTENT_GPA = 0x40_00000` (`el1-abi lib.rs:~219` after PR 136) uses misleading digit grouping; it is 64 MiB.

**Target:** one typed layout module per ISA, `carrick_el1_abi::layout::{arm, x86}`, built from `KernelVa`/`FrameGpa`/`RootGpa`, with named masks in `carrick-mmu-core`. `link.ld` and `carrick-x86` should derive their values from it, and the stale `el1/isa/x86/interrupts.rs` constants should be deleted.

### 1.8 Errno and ABI constants outside carrick-abi

Column-0 ABI-shaped constants in non-test code: kernel 162, mem 74 (mostly layout names), personality-linux 57, syscall-abi 55 (the real no_std leaf), el1 31, x86 25.

Worst offenders:
- `carrick-kernel/src/host_tty.rs` (45);
- `carrick-kernel/src/dispatch/sysv.rs` (32 `LINUX_*` IPC constants at :219+, which breaks the AGENTS.md "no LINUX_* in dispatch" rule);
- `carrick-personality-linux/src/lifecycle.rs:282-294` (CLONE_*, also defined in `carrick-hal/src/x8664_arch.rs`) and `identity.rs` (PR_*, CAPABILITY_VERSION_*).

29 pre-negated `const E*: i64 = -N`, including `carrick-el1/src/personality/file.rs:12-14`, `ipc.rs:62-65`, `personality-linux identity.rs:6-10`, `sysinfo.rs:6-9`, `sched.rs:27-28` and `entry.rs:9`. Inline errno literals: `native_process_runtime.rs:87-90` (-22/-11/-14/-38), :1594, :3003, `el1/inotify.rs:229,274`, `x86-cpl0 entry.rs:~1923`.

Root cause: `carrick-syscall-abi/src/errno.rs` names only 10 errnos. **Target:** move the full errno/SIG*/CLONE_*/PR_*/SS_*/FUTEX_* sets into the no_std leaf and have carrick-abi re-export them.

## 2. Missing abstractions

| Inline branching or prose rule (evidence) | Abstraction that should exist | Home |
|---|---|---|
| `carrick-el1` personality has 81 `cfg(target_arch)`; `mm_portal/production.rs` has 34-36, e.g. inline `asm!("mrs ttbr0_el1")` at :123-158 and a cfg-dispatched `yield_host_effect` at :170 that duplicates `CrossingArch::yield_host_effect` | `MmuArch::live_root`, `CrossingArch` used from the personality | `carrick-guest-arch` traits, implemented in `carrick-el1/src/isa/*` |
| `carrick-runtime`: 328 target_arch cfgs, 266 of them `all(target_os="macos", target_arch="aarch64")`, which conflates host and guest ISA (exec.rs 64, lifecycle.rs 57, binding.rs 45); 166 `carrick_vmm_hvf::` references vs 17 `carrick_vmm_kvm::` | a carrier trait set (`CarrierVcpu`, `CarrierLauncher`, `CarrierMemory`) plus a build.rs cfg alias `carrick_hvf_aarch64` | `carrick-hal` |
| Six kick mechanisms (§1.6) | `CarrierVcpu { kick, arm_idle, wait_in_guest }` keyed by exact executor binding; `PosixSignalKick<const SIG>`; fold the slot kicker into `ExecutorKick` | `carrick-hal` |
| `ThreadCpu` x86 impl is all `fatal_entry_binding()` | `Sched<A: KernelArch>` | `carrick-el1/src/sched` |
| `kernel dispatch/net/support.rs:99-244` (epoll layout) and `dispatch/mem/mmap.rs:201,355` match on `LinuxGuestAbi` | `GuestArch` associated constants or types | `carrick-hal::guest_arch` |
| Raw typed params in `pub fn`: kernel 526 in 485 fns (`fd` 257, `pid` 108, `signum` 72); el1 62 (`process_owner.rs` 23, e.g. `credentials_for(tid: u32)` :246); runtime 11 | existing `Fd`, `NsPid`, `Signal`, `GuestVa` | lint-domains extension |
| Duplicate newtypes undercut typed domains: `Fd` (fd-core vs kernel `abi_args.rs:11`), `HostPid`, `Signal`, `LinuxErrno` (syscall-abi vs inotify-core), `GuestVa` (guest-mem `lib.rs:187` with a `pub u64` field vs `core/mm/transfer.rs:12`), 3 GPA types (`Gpa`, `FrameGpa`/`RootGpa`, `SubstrateGpa(pub u64)`), `TimerTicks`/`ApicId` | one definition each, re-exported | leaf ABI crates |
| About 1,000 `u64` params/fields named va/ipa/gpa/root/far in mmu-core (224), vmm-hvf (309), el1 (134), aarch64 (91); e.g. `OwnerCowMmu`, `Pml4Manager::translate(va: u64) -> Option<u64>`, `translate_va` in kvm/bhyve/nvmm | `UserVa`, `FrameGpa`, `RootGpa` | `carrick-guest-arch` |
| "Caller holds the exact owner editor" with no token: `owner_mmu.rs:19-20`, `el1/cow.rs:3`, `x86/descriptor_txn.rs:1060`, `cow_engine.rs:10,1659,1738,6055` | `ExactMmEditor<'_>` witness parameter | `carrick-mmu-core` |
| `fork_lifecycle_available: bool` doubles as exclusivity token and freshness flag (hvf `fork_stock.rs:126` `pub`, kvm `cpl0_boot.rs:1793`) | `ForkLifecycleLoan` typestate (Available → Loaned → Committed/Aborted → Retired) | `carrick-hal::fork_stock` |
| `quarantine_*` enforced by `mem::forget` plus panic (`aarch64_process.rs:577-593`); "never published after refusal" (`native_process_runtime.rs:1380`) | `#[must_use] ClosedChild` that can only be committed or quarantined | `carrick-el1/src/personality` |
| `read_quiesced_parked_registers(mm: u64)` unsafe with "no vCPU of mm executing" (`el1_zone.rs:547`, sched-core `lib.rs:3943`) | `QuiescedMm<'_>` witness from the crash-quiesce barrier | `carrick-thread` |
| sched-core `enqueue` "guard must be bucket_of(mm,uaddr)" (`lib.rs:1940`); `fd_table.rs:1827 raw() -> i32` "caller must keep HostFdRef alive"; `el1/file.rs:323` "caller must hold the object lock"; `el1/isa/x86/user_access.rs:97` "must not move to another CPU" | `BucketGuard` keyed by `(mm,uaddr)`; `BorrowedFd<'_>`; `&ObjectGuard`; a `!Send` transfer | owning crates |
| Unsafe fns whose safety contract is a prose proof list: `core-abi/mm/reservation.rs:182-189`, `core/mm/transfer.rs:217`, `kvm carrier_memory.rs:957`, `x86/owner_mmu.rs:217`, `guest-arch lib.rs:662-678` | typestate receipts (`DescriptorCommitted`, `BackingCommitted`) | same files |
| 225 tests in 36 files assert on source text via `include_str!("*.rs")`: observability `probes.rs` 28, `hvf_aarch64_engine.rs` 20, runtime `binding.rs` 18, hvf `carrier_custody.rs` 15 (one 2,394-line static-audit fn at :1719), runtime `continuation/tests.rs` 15, `cow_engine/tests.rs` 14 | each rule becomes a type (preferred) or a `.semgrep/typed-domains.yml` rule. Source-grep tests break on any code move and act as merge magnets | `lint-domains` |
| `carrick-el1`/`carrick-el1-abi` names describe one ISA but serve both; `carrick-el1-abi` holds the X86_CPL0 layout | rename to `carrick-guest-kernel` / `carrick-guest-kernel-abi` | last, at a quiet window |

## 3. Dead and legacy code

### CERTAIN
- **232 unreferenced code items, about 1.6k lines,** plus 63 unused ABI constants (kept defensibly). By crate: kernel 80, runtime 21, vmm-hvf 13, vfs 9, el1-abi 8. Notable items:
  - the old HVF entry-point family in `carrick-runtime/src/runtime.rs` (lines 163, 264, 301, 311, 342, 663, 1033; about 135 lines);
  - `carrick-portable/src/lib.rs:459-536` (`semctl*`);
  - `carrick-el1-abi/src/lib.rs:1901 fd_map_lookup_kind`;
  - `carrick-core/src/mm/capacity.rs:180 min_size_for_bin`;
  - `carrick-investigation/src/review.rs:62 render_markdown`;
  - `carrick-vmm-hvf/src/io_wait.rs:567, 299`;
  - `carrick-hal/src/signal_pump.rs:392, 123`;
  - `carrick-vfs/src/apfs.rs:170`;
  - `carrick-kernel/src/kernel/{wait_set.rs:378, container.rs:1132, continuation.rs:2928, operations/signal.rs:564}`;
  - `dispatch/mem/vma.rs:1015,1027`;
  - `carrick-vmm-hvf/src/trap.rs:1490 dump_kick_stats` (its other definition is a no-op stub at `carrick-runtime/src/lib.rs:204`).
- **Stale retired-backend messages:**
  - `carrick-kernel/src/container.rs:679` says "recreate the container with --exec-backend vmm".
  - `carrick-cli/src/amplification_profile.rs:1024` says "Re-run with `--exec-backend native`". AMP1 (`debug_amplification.rs:804`) can therefore never pass its own guest-syscall check.
- **No-op feature:** `carrick-vmm-hvf` `trace-syscalls = []` (`Cargo.toml:20`) has no cfg in that crate; it is only forwarded to. The sub-audit also reported carrick-cli `trace-dtrace` as dead. That is **wrong**: it is used at `carrick-cli/src/runtime_util.rs:278`.
- **Stale documentation:**
  - `crates/README.md:3` says "33-crate workspace"; there are 51. The map is missing core, core-abi, el1, el1-abi, el1-image, fatal, fd-core, guest-arch, personality-linux, pipe-core, signal-linux, syscall-abi, x86-cpl0 and xtask.
  - AGENTS.md says carrick-cli in-file tests never ran. That is stale: `just test` runs `-p carrick-cli --bin carrick` (justfile ~431, ~492).
  - The justfile comment at ~388 calls `--bins` load-bearing for carrick-cli, but that command `--exclude`s carrick-cli.
  - `docs/design/arm-ring-first-flip.md` lists deletion targets that no longer exist (`kernel/src/dispatch/{identity,ipc,sys,sync}.rs`, `runtime/src/task_pool.rs`) and uses `file:///…/.worktrees/arm-flip` links.
  - `scripts/migrate/check-runtime-aborts.py:18-19` lists the deleted crates carrick-dsr and carrick-native-darwin.
  - Scripts reference missing paths: `scripts/dtrace/native-amplification.d`, `debug-tier-b.sh`, `ltp-reduce.py`, `test-nodejs-conformance-dry-run.sh`, `perf/README.md`, and 8 dtrace headers citing old `scripts/X.d` locations.
  - Current docs (outside perf-results/ and superpowers/) contain 122 distinct missing paths, worst in `identity-and-scope-domains-embed-census.md` (39) and `time-consumer-inventory.md` (26). Historical docs have 472 more.
  - `--exec-backend native|vmm` still appears in 6 script files (e.g. `scripts/perf/test_native_go_build.py:992-1058`) and 70 docs, including the current `docs/diagnostics-and-debugging.md:399`.
  - 2 probe names used by scripts are not declared at all: `hvpatch-exec-bank-layout` and `kick-in`.

### LIKELY
- **743 `pub` items referenced only from tests, about 8.7k lines.** 144 (1.9k lines) are deliberate fixtures; 599 (6.8k lines) have production names. By crate: kernel 285, vmm-hvf 67, vmm-kvm 61. Largest:
  - `carrick-kernel/src/kernel/core.rs:2462 validate_invariants` (198) and `:1629 export_boot_launch` (168);
  - `carrick-mmu-core/src/aarch64.rs:960, 4051, 4240`;
  - `carrick-vmm-hvf/src/syscall_mailbox.rs:339-500` (portal arm/cancel/publish);
  - `carrick-el1/src/personality/file_table.rs:303 admit_host_fd`.
- **`carrick-host/src/guest_cpu.rs:83,88`** `set_native_{host,darwin}_provider`: the only caller is a test (`:1507`). The native branch at `host_proc.rs:783` is therefore unreachable in production.
- **56 of 243 USDT probes have no emitter** (dsr-*, fork-pre/post/*, host-translated-*, native-x86-*, supervisor-fork-*, pt-pool and others). Up to 45 `scripts/dtrace/*.d` files arm at least one of them and would see zero events, which AGENTS.md says `carrick trace` must refuse.
- **14 `#[test]`s in vmm-hvf bin targets never run:** `hvf_kernel_memory_probe.rs` (5), `hvf_svc_tax_probe.rs` (2), `hvpatch_probe_support/mod.rs` (7). `just test` runs `-p carrick-vmm-hvf --lib` only, and `test-lanes` (`carrick-xtask/src/test_lanes.rs:169-171`) selects only `kind=="test"` targets, so it cannot catch bin tests.
- **`carrick-kernel/src/dispatch/ioring.rs:721,738`** (`opcode_serviced`, `complete_sqe`) are a test-only second path; the file says the live enter path inlines the match.
- **ARM in-ring fork pieces** (`Aarch64NativeProcessService::new`, `HvcForkStockCrossing`, `cross_hvc_fork_stock`) are built only in tests. They are pending wiring, not dead.
- **Frame-grant mailbox host side:** `frame_grant_mailbox_host_for_slot` (`el1-abi lib.rs:2702`), `claim_request*`, `complete_grant` and `publish_refusal` have no non-test callers. The ARM guest still writes requests (`carrick-el1/src/fault.rs:1070-1110, 1589`) that the host never serves. The protocol is dead, but EL1 still pays for it.

### SUSPECTED: live, but slated for deletion or never compiled
- **Host ARM fork lanes, about 6,600 lines:** `trap/owner_fork.rs` 904, `trap/process_plan.rs` 2,502, `carrick-aarch64/src/fork.rs` 395, the engine owner-fork paths, and runtime `lifecycle.rs` fork handling. Step 6 of `arm-shared-process-owner-adoption.md` deletes them. `prepare_in_process_fork` (`runtime/vcpu_loop/quiesce.rs:466`, 1,585 lines) is the largest function in the tree.
- **Host COW fallback** `perform_frame_cow` (~1,250).
- **`refill_transfer_cow_in`** (`trap/sparse_materialization.rs:2458-2468`) is live, via `refill_transfer_cow` (:2452) ← `trap/user_transfer.rs:304, 344` ← `carrick-aarch64/src/user_transfer.rs:36, 612`.
- **Legacy memory protections:** `UserMemoryAuthority::legacy()` (`carrick-guest-mem/src/prepared.rs:230`) is live through `carrick-aarch64/src/engine.rs:1373, 2988` and the HVF trap planners.
- **`HvfSyscallTransport::Legacy`** (`syscall_mailbox.rs:29`, `CARRICK_HVF_SYSCALL_TRANSPORT=legacy`) is exercised only by perf pair tests.
- **`CARRICK_EL1_DESCRIPTOR_LANE=0`** host-owned MM hatch (`runtime/vcpu_loop/signal.rs:541-632`).
- **`frame_mailbox.rs`** (648) and `FaultSupply::Mailbox`.
- **KVM fixture code** in `cpl0_boot.rs` (~1,230) and the **x86 fixture fork lane** (~1,650).
- **10 module-wide `#![allow(dead_code)]`** hide about 7.9k lines: `kernel/namespace/pid.rs` (2,326), `dispatch/net/unix_pure.rs` (2,541), `dispatch/ioring.rs` (1,879), `dispatch/proctitle.rs` (562), `runtime/hvpatch/asid.rs` (273), and others. `carrick-mem/vdso_getrandom_chacha.rs` is justified. Overall there are 290 `allow(dead_code|unused*)`: kernel 147, vmm-hvf 54, cli 40.
- **About 13 never-compiled debug features** in carrick-cli (alloc-census, fs-memory, trace-*, watchpoint, event-ring-dump, debug-stats) and kernel-example `allocation-metrics`. No recipe enables them, so clippy never sees their code.
- **About 30 default-on `CARRICK_*=0` hatches** whose measurement state is not recorded in source. The `DSR_*` names (20 references) outlived DSR removal.
- **57 `#[ignore]` tests,** 13 without a reason.

**Totals:**
- CERTAIN about 1.6k lines;
- LIKELY about 8.7k lines (6.8k production-named);
- SUSPECTED about 11.4k lines of live legacy code, plus about 7.9k lines under module allows.

## 4. Size hot spots and merge magnets

The workspace is about 1.10M lines of Rust in 51 crates; about 236k are in test files. The biggest crates are carrick-kernel (369k), carrick-vmm-hvf (118.5k), carrick-runtime (100.8k) and carrick-el1 (47.5k).

**Largest files**

| File | Lines |
|---|---|
| `carrick-vmm-hvf/src/trap/foreign_mm/tests.rs` | 14,828 |
| `carrick-mmu-core/src/aarch64.rs` | 14,080 |
| `carrick-kernel/src/dispatch/fs/tests.rs` | 11,541 |
| `carrick-kernel/src/dispatch/tests.rs` | 11,009 |
| `carrick-kernel/src/kernel/scheduler.rs` | 10,147 |
| `carrick-observability/src/probes.rs` | 10,019 |
| `carrick-aarch64/src/engine.rs` | 9,489 |
| `carrick-mem/src/memory.rs` | 9,313 |
| `carrick-vmm-hvf/src/trap.rs` | 9,070 |
| `carrick-runtime/src/vcpu_loop/binding.rs` | 8,874 |
| `carrick-vmm-hvf/src/trap/cow_engine.rs` | 8,224 |
| `carrick-kernel/src/dispatch/proc.rs` | 8,179 |
| `carrick-vmm-kvm/src/cpl0_boot.rs` | ~6,086 |
| `carrick-el1-abi/src/lib.rs` | 5,140 |
| `carrick-el1/src/personality/native_process_runtime.rs` | 5,054 |

**Largest functions:** 98 functions are over 300 lines and 338 over 150.

| Function | Lines |
|---|---|
| `vmm-hvf trap/carrier_custody.rs:1719` (source-text static-audit test) | 2,394 |
| `runtime vcpu_loop/quiesce.rs:466 prepare_in_process_fork` | 1,585 |
| `cli commands.rs:105 run_cli` | 1,445 |
| `vmm-hvf trap/process_plan.rs:557 build_setup_process_plan` | 1,300 |
| `vmm-hvf trap/cow_engine.rs:3314 perform_frame_cow` | 1,246 |
| `kernel dispatch/fs/ioctl.rs:666 ioctl` | 1,236 |
| `runtime binding.rs:3990 poll_with_engine` | 1,206 |
| `runtime executor.rs:262 run_executor_loop` | 1,201 |
| `kernel net/epoll_ops.rs:1358 epoll_pwait_host_core` | 1,014 |
| `runtime exec.rs:1486 drive_execve` | 953 |
| `x86-cpl0 entry.rs:1189 carrick_x86_enter` | 943 |
| `vmm-hvf trap/execve_rebuild.rs:965` | 917 |

**Churn** (commits since 2026-09-20, 2,710 commits on main):

| File | Commits |
|---|---|
| `scripts/migrate/host-authority-*.json` inventories | 250 / 191 / 158 (already retired from main) |
| `carrick-el1-abi/src/lib.rs` | 152 |
| `carrick-aarch64/src/engine.rs` | 114 |
| `carrick-vmm-kvm/src/cpl0_boot.rs` | 87 |
| `carrick-x86-cpl0/src/entry.rs` | 80 |
| `carrick-vmm-hvf/src/trap.rs` | 79 |
| `carrick-mmu-core/src/aarch64.rs` | 79 |
| `carrick-vmm-hvf/src/trap/cow_engine.rs` | 73 |
| `carrick-kernel/src/el1_delegation.rs` | 71 |

**Files touched by the most open PRs** (17 open PRs on 2026-10-10):

| Open PRs | Files |
|---|---|
| 8 | `carrick-el1/src/personality/dispatch.rs`, `carrick-el1-abi/src/lib.rs` |
| 7 | `carrick-el1/src/personality/mod.rs` |
| 6 | `carrick-vmm-hvf/src/trap.rs`; sched-core `lib.rs` and `spaces/notification.rs`; runtime `vcpu_loop/{binding,quiesce,threads,lifecycle,reservations}.rs`; mmu-core `aarch64.rs` and `aarch64/descriptor_txn.rs`; kernel `kernel/mod.rs`, `el1_delegation.rs`, `dispatch/outcome.rs`; hal `trap.rs` and `sigframe.rs`; `carrick-el1/src/{cow,memory}.rs` and `mm_portal/{production,fork}.rs` |

**Split these merge magnets, each in one mechanical commit at a quiet point:**
- `carrick-el1-abi/src/lib.rs` → `layout/{arm,x86}.rs`, `region.rs`, `counters.rs`, `tables.rs`;
- `carrick-aarch64/src/engine.rs` → `engine/{fork,exec,signal,fault}.rs`;
- `cpl0_boot.rs` → production boot plus `fixture.rs`;
- `trap.rs`;
- `mmu-core aarch64.rs`;
- `carrick-el1/src/personality/dispatch.rs` (by syscall family).

## 5. In-flight work that constrains the order

| PR / lane | Touches | Blocks packages |
|---|---|---|
| #131 ring signals | `personality-linux/{dispatch,signal,lifecycle,identity}.rs`, `carrick-abi/src/lib.rs` (−1,011), `syscall-abi`, `el1 personality/{lifecycle,dispatch}.rs`, new `arm_signal.rs`/`x86_signal.rs`, `x86-cpl0 entry.rs`, `kvm cpl0_boot.rs`/`cpl0_anonymous.rs`, `vmm-hvf fork_stock.rs` | P5, P6, P7, P10, P12 |
| #137 ring IPC | `sched-core process/ipc.rs`, `personality-linux/{dispatch,ipc,identity,sysinfo}.rs`, `syscall-abi`, `el1 personality/{lifecycle,dispatch}.rs`, `cpl0_boot.rs`, `x86-cpl0 entry.rs` | P5, P6, P7, P12 |
| #119 x86 fork landing / #86 x86 legacy retire | `cpl0_boot.rs`, `cpl0_anonymous.rs`, `kvm_x86_engine.rs` (deleted), `x86-cpl0/{entry,native_process,process}.rs`, `el1/{fault,cow,memory}.rs`, `mmu-core x86/*`, `carrick-x86/{cpl0_lifecycle,interrupts}.rs`, new `el1-abi/x86_fork_stock.rs`, bhyve/nvmm engines, `hal x8664_arch.rs` | P3 (x86 classifier part), P8, P9, P10, P11, P12 |
| ARM fork COW page supply | `fork_stock`, frame inventory, `el1/cow.rs`, `mm_portal/*`, `trap/guest_cow.rs`, `cow_engine.rs` | P9, P10, P11, P13 |
| N1 PRs #11 #14 #16 #21 #59 | `vmm-hvf trap.rs`, `owner_fork.rs`, `process_plan.rs`, `cow_engine.rs`, `carrier_custody.rs`, `runtime.rs`, `probes.rs`, `el1/fault.rs` | P13 deletes their target; decide whether to close them first |

Note: #131 and #137 both add `personality-linux identity.rs` and `sysinfo.rs` from an older base, and those files are already on main. Expect rebase collisions. Also note PR #119's `x86_fork_stock.rs` (626) beside `fork_stock.rs` (1,205), and #131's per-ISA signal pair. Ask both authors to land those behind the ISA trait (P9, P10), not as parallel files.

## 6. Work packages

Packages are file-disjoint within each wave. Line deltas are estimates. Every package follows AGENTS.md:
- defect fixes are red-first, with a contract from `.agents/skills/carrick-conformance-contract`;
- every package finishes with `just ci`;
- packages that touch macOS/ARM also need the signed gate per the landing policy.

### Wave A: can start now (no conflict with in-flight PRs)

**P1. Stale text and messages**
- **Goal:** correct the README crate map, the AGENTS.md carrick-cli note, the justfile `--bins` comment, the two retired-backend messages, `check-runtime-aborts.py`, the missing script paths, the `arm-ring-first-flip.md` targets and links, and `--exec-backend native|vmm` in current docs.
- **Files:** `crates/README.md`, `AGENTS.md`, `justfile` (comment only), `carrick-kernel/src/container.rs:679`, `carrick-cli/src/amplification_profile.rs:1024`, `scripts/migrate/check-runtime-aborts.py`, the listed `scripts/*`, `docs/diagnostics-and-debugging.md`, `docs/design/arm-ring-first-flip.md`.
- **Delta:** about +60/−80.
- **Risk:** low. The AMP1 message change may need its profile fixed or deleted.
- **Verify:** `just fmt-check`, `just test`, `just lint-domains`.
- **Order:** none.

**P2. Signal mask aliasing defect (defect 1)**
- **Goal:** read `new_set` before writing `old_set`, and validate `how` before any write. Then delete the ring lane's aliasing handback (that part waits for #131).
- **Files:** `carrick-kernel/src/dispatch/signal.rs` (2133-2167), plus one new embed probe in `carrick-conformance-next`.
- **Delta:** about +60/−10.
- **Risk:** low. Guest-visible, so red-first is required.
- **Verify:** `just test-kernel`, `just test`, `just conformance-probes` (signed).
- **Order:** none. Coordinate with the N1 `#21` lane, which also touches this file.

**P3. x86 COW classifier defect (defect 2), merged into one classifier**
- **Goal:** make `classify_guest_cow_write` call `X86Mmu::classify_cow`, or the reverse, so there is one ancestor rule; make `CowRun.va` a `UserVa`.
- **Files:** `carrick-mmu-core/src/x86/{descriptor_txn,owner_mmu}.rs`.
- **Delta:** about +40/−60.
- **Risk:** medium. This is a guest-visible fault path.
- **Verify:** `just test-mm-owner`, `just test`, `just check-linux`, `just test-kvm` (on a KVM host).
- **Order:** #119 touches `x86/descriptor_txn.rs`. Land after #119, or rebase #119 on top of this. The witness can be written now.

**P4. KVM continuation parity (defect 4) and a shared continuation core**
- **Goal:** extract `prepare_blocked_continuation` from `vcpu_loop/mod.rs:1255-1300` into the kernel continuation module and call it from `executor/kvm.rs:467`. Fold the duplicate `restart_class` (`kvm.rs:361`) into it.
- **Files:** `carrick-runtime/src/vcpu_loop/executor/kvm.rs`, `carrick-kernel/src/kernel/continuation.rs`, and the call site in `vcpu_loop/mod.rs`.
- **Delta:** about +80/−120.
- **Risk:** medium.
- **Verify:** `just test-kernel`, `just test`, `just check-linux`, `just test-kvm` with a red-first x86 pselect6-sigmask fixture.
- **Order:** `vcpu_loop/mod.rs` is touched by #59, #90 and #137. Keep the mod.rs edit to a single call site and rebase.

**P5. Host VMM consolidation (BSD and KVM)**
- **Goal:**
  - `carrick_hal::PosixSignalKick<const SIG>` replaces the kvm/bhyve/nvmm kickers;
  - `carrick_hal::FallbackTimerDelivery` replaces three byte-identical `TimerDelivery` impls;
  - one BSD futex module, one BSD signal backend;
  - bhyve fault tables replaced by `carrick-x86/src/fault.rs` (this resolves the slot and stride divergence).
- **Files:** `carrick-hal` (new module), `carrick-vmm-kvm/src/{kvm_kicker,timer_delivery}.rs`, `carrick-vmm-bhyve/src/{bhyve_kicker,bhyve_threaded_glue,bhyve_futex,bhyve_signal_backend,guest_setup_x86}.rs`, the NVMM equivalents.
- **Not included:** the bhyve/nvmm `*_x86_engine.rs` files, which #86 and #119 touch.
- **Delta:** about +250/−900.
- **Risk:** medium. bhyve/NVMM have no hosted CI.
- **Verify:** `just check-linux`, `just check-freebsd`, `just check-netbsd`, `just test`, and the bhyve lane on the FreeBSD test host.
- **Order:** none.

**P6. CERTAIN dead-code removal, part 1 (files no open PR touches)**
- **Goal:** delete the CERTAIN items in files with no open PR:
  - `carrick-portable` `semctl*`;
  - `carrick-host/src/guest_cpu.rs` native-provider setters and the unreachable `host_proc.rs:783` branch;
  - `carrick-investigation` `render_markdown`;
  - `carrick-vfs/src/apfs.rs:170`;
  - `carrick-core/src/mm/capacity.rs:180`;
  - `carrick-hal/src/signal_pump.rs:123,392`;
  - the kernel items in `wait_set.rs`, `container.rs:1132`, `operations/signal.rs:564`, `vma.rs:1015,1027`, `network/interposer.rs:111`;
  - the vmm-hvf `trace-syscalls` no-op feature (plus its forwarders).
- **Files:** as listed.
- **Delta:** about −900.
- **Risk:** low. Watch for macro or string uses; `just ci` will catch them.
- **Verify:** `just ci`, `just check-linux`.
- **Order:** none.

**P7. Test-gate holes**
- **Goal:**
  - make `test-lanes check` fail on bin targets with tests, and run or move the 14 vmm-hvf bin tests;
  - give every `#[ignore]` a reason;
  - add a `just check-debug-features` recipe (`cargo check --features debug-all`, `alloc-census`, `allocation-metrics`) to `just ci` so the never-compiled code is at least compiled;
  - teach `carrick trace` / lint-domains to fail on probe names that are declared but never emitted.
- **Files:** `carrick-xtask/src/test_lanes.rs`, `justfile`, `carrick-vmm-hvf/src/bin/*`, `carrick-observability` (probe-emitter check in xtask, not in `probes.rs`).
- **Delta:** about +200/−50.
- **Risk:** low. It may surface compile errors in the debug features; that is intended.
- **Verify:** `just ci`.
- **Order:** none. P1 also edits the justfile (comment only), so sequence P1 then P7.

### Wave B: after #131 and #137 land

**P8. One no_std syscall table**
- **Goal:** move the table macro to `carrick-syscall-abi` (no_std) with the columns from §1.4, then generate:
  - carrick-abi `nr::*` and its authority/handler/compat functions;
  - `crossing.rs` `nr` and `HOST_CROSSINGS`;
  - `route_aarch64` (renamed `route_canonical`);
  - the `X86_64_SYSCALLS` canonical column;
  - the hal `X86_NR_*`;
  - `is_restartable_syscall(CanonicalNr)`.
- Also merge the two x86 normalizers into one. That removes the host/ring canonicalization split.
- **Files:** `carrick-syscall-abi/src/{lib,syscall_x86_64}.rs`, `carrick-abi/src/syscall.rs`, `carrick-personality-linux/src/{dispatch,crossing,entry,lifecycle,sched}.rs`, `carrick-hal/src/x8664_arch.rs` (normalize only), `carrick-kernel/src/kernel/continuation.rs` (one fn), `carrick-el1/src/memory.rs:18-21`, `carrick-x86/src/bringup_fns.rs:591-598`.
- **Delta:** about +500/−1,900.
- **Risk:** high. Every syscall is routed through this.
- **Verify:** `just test`, `just test-kernel`, `just check-linux`, `just conformance-probes` (signed), and an exhaustive-table test that compares old and new routing for nr 0..512 on both ISAs before the old code is deleted.
- **Order:** after #131, #137 and #86. Before P10.

**P9. No_std ABI leaf constants**
- **Goal:** move the full errno, SIG*, CLONE_*, PR_*, SS_* and FUTEX_* sets into `carrick-syscall-abi` (re-exported by carrick-abi), and replace the 29 pre-negated consts and the inline literals in el1, personality-linux and x86. Move the `dispatch/sysv.rs` `LINUX_*` constants into carrick-abi.
- **Files:** `carrick-syscall-abi/src/errno.rs` (and new modules), `carrick-el1/src/personality/{file,ipc,inotify,native_process_runtime}.rs` (constants only), `carrick-personality-linux/src/{identity,sysinfo,sched,entry,lifecycle}.rs` (constants only), `carrick-kernel/src/dispatch/sysv.rs`, `carrick-x86/src/bringup_fns.rs`, `carrick-vmm-kvm/src/run_elf.rs`.
- **Delta:** about +300/−450.
- **Risk:** low to medium.
- **Verify:** `just ci`, `just check-linux`, `just lint-domains` (extend the semgrep rule to the no_std crates).
- **Order:** after #131 and #137. Shares `personality-linux` files with P8, so run it after P8 or in the same batch with a disjoint hunk list.

**P10. Signal consolidation**
- **Goal:**
  - one signal-set type, one block-mask type and one signal-number type (in the no_std leaf);
  - shared siginfo/uc_stack/altstack helpers behind `GuestArch` in `carrick-hal/src/sigframe.rs`;
  - fold #131's `arm_signal.rs`/`x86_signal.rs` into one implementation with an ISA hook;
  - the kernel uses `carrick-signal-core` dispositions.
- **Files:** `carrick-signal-core`, `carrick-hal/src/{sigframe,x8664_arch}.rs` (signal parts), `carrick-personality-linux/src/{signal,abi/thread}.rs`, `carrick-el1/src/personality/{arm_signal,x86_signal,native_process_signals}.rs`, `carrick-kernel/src/kernel/objects/signal.rs`.
- **Delta:** about +300/−700.
- **Risk:** medium to high.
- **Verify:** `just test-kernel-semantics`, `just test`, `just check-linux`, `just conformance-probes` (signed).
- **Order:** after #131 and P8.

**P11. Layout authority**
- **Goal:**
  - split `carrick-el1-abi/src/lib.rs` into `layout/{arm,x86}.rs` with typed `KernelVa`/`FrameGpa`;
  - derive `COW_COPY_WINDOW_BASE`, the stage-1 pool base, the progress/lifecycle zone, LAPIC and `PROGRESS_HEADER` from it;
  - delete `carrick-el1/src/isa/x86/interrupts.rs` constants (defect 3) in favour of one ABI copy;
  - generate the `link.ld` constants or check them with a `const` assertion;
  - name the AArch64 and x86 descriptor masks once in `carrick-mmu-core`;
  - fix the `0x40_00000` grouping.
- **Files:** `carrick-el1-abi/src/lib.rs` (+ new `layout/`), `carrick-el1/src/isa/x86/interrupts.rs`, `carrick-x86/src/{interrupts,cpl0_scheduler,cpl0_lifecycle}.rs`, `carrick-x86-cpl0/link.ld`, `carrick-mmu-core/src/aarch64/descriptor_txn/copy_window.rs`, and mask call sites in `carrick-el1/src/{fault,memory}.rs`.
- **Delta:** about +400/−350.
- **Risk:** medium. This changes the image ABI hash, which is expected.
- **Verify:** `just test-mm-owner`, `just test`, `just check-linux`, `just check-layering`, `just test-embed` (signed).
- **Order:** after #119, #131 and #137. `el1-abi lib.rs` is touched by 8 open PRs, so this is a quiet-window batch.

### Wave C: after the x86 fork landing (#119/#86) and ARM fork COW page supply

**P12. KVM fixture isolation**
- **Goal:** move the `fixture_*` methods, `boot_lifecycle`/`stock_lifecycle`, `fixture_run_until` and `Watchdog` out of `cpl0_boot.rs` into `#[cfg(feature = "fixture")]` or `tests/support`. Move the x86 fixture fork lane (`x86-cpl0/src/process.rs`, `carrick-x86/src/cpl0_lifecycle.rs`) behind the same gate. Replace the four MSI constructions with `carrier_interrupts::inject_kick`.
- **Files:** `carrick-vmm-kvm/src/{cpl0_boot,cpl0_anonymous,carrier_interrupts}.rs`, `carrick-vmm-kvm/Cargo.toml`, `carrick-x86-cpl0/src/{process,fixture}.rs`, `carrick-x86/src/cpl0_lifecycle.rs`.
- **Delta:** about +150/−400 (most lines move rather than disappear).
- **Risk:** medium.
- **Verify:** `just check-linux`, `just test-kvm`, `just test`.
- **Order:** after #119, #131 and #137.

**P13. Shared fork service and custody**
- **Goal:**
  - one generic `NativeProcessService` over `<B: OwnerForkMmu, X: ForkStockCrossing>`, with x86 using the crossing trait instead of raw `asm!`;
  - `carrick-hal::fork_stock::ForkStockCustody` with a `ForkLifecycleLoan` typestate and RAII rollback;
  - fold `x86_fork_stock.rs` into `fork_stock.rs`;
  - one `ForkInheritance` policy in `personality-linux/src/mm.rs`;
  - fix defect 5 (abort settlement, the RETIRED leak, the ARM fd table, lifecycle reuse), each red-first.
- **Files:** `carrick-el1/src/personality/{aarch64_process,native_process_runtime}.rs`, `carrick-x86-cpl0/src/{native_process,native_execution}.rs`, `carrick-el1-abi/src/{fork_stock,x86_fork_stock}.rs`, `carrick-vmm-hvf/src/fork_stock.rs`, `carrick-vmm-kvm/src/cpl0_anonymous.rs` (fork-stock part), `carrick-hal` (new module), `carrick-personality-linux/src/mm.rs`, `carrick-el1/src/personality/mm_portal/fork.rs` (policy only).
- **Delta:** about +600/−1,100.
- **Risk:** high.
- **Verify:** `just test`, `just test-mm-owner`, `just test-kvm`, `just test-embed` (signed), `just conformance-probes` (signed); the fork14 and forkexecstorm contracts.
- **Order:** after #119 and ARM fork COW supply. Before P15.

**P14. MMU trait unification**
- **Goal:**
  - make `OwnerCowMmu` typed and fold it into `OwnerMmu`;
  - move the grant wire types into `carrick_mmu_core::grant` and merge `BackingIdentity` with `EditBacking` on the typed IDs;
  - one generic walk over `OwnerForkMmu` that replaces the ad-hoc AArch64 walks and `retired_page`/`retired_page_x86`;
  - one COW run type;
  - one host COW-grant supplier for HVF `guest_cow.rs` and KVM `cpl0_anonymous.rs` (COW part).
- **Files:** `carrick-core/src/mm/cow.rs`, `carrick-el1/src/cow.rs`, `carrick-mmu-core/src/{owner_mmu.rs, aarch64/descriptor_txn*.rs, x86/*}`, `carrick-guest-arch/src/lib.rs` (EditBacking), `carrick-el1/src/personality/mm_portal/maintenance.rs`, `carrick-vmm-hvf/src/trap/guest_cow.rs`, a new host supplier in `carrick-hal` or `carrick-core`.
- **Delta:** about +500/−1,300.
- **Risk:** high.
- **Verify:** `just test-mm-owner`, `just test-loom`, `just test`, `just test-kvm`, `just test-embed` (signed).
- **Order:** after ARM fork COW supply and #119. File overlap with P13 is limited to `cpl0_anonymous.rs`: split by function, or run P13 first.

**P15. ARM fault entry on owner supply; delete the frame mailbox**
- **Goal:** switch `carrick-el1/src/fault.rs:1070-1110` to `FaultSupply::Owner`, then delete `FaultSupply::Mailbox`, `GrantMailboxes`, `carrick-core-abi/src/mm/frame_mailbox.rs` and the host accessor `frame_grant_mailbox_host_for_slot`.
- **Files:** `carrick-el1/src/fault.rs`, `carrick-core/src/mm/fault.rs`, `carrick-core-abi/src/mm/frame_mailbox.rs`, `carrick-el1-abi/src/lib.rs` (accessor only).
- **Delta:** about +80/−900.
- **Risk:** medium.
- **Verify:** `just test-mm-owner`, `just test`, `just test-embed` (signed), `just conformance-probes` (signed).
- **Order:** after ARM fork COW supply. Can run in parallel with P13 (disjoint files except `el1-abi lib.rs`, which only needs one-line deletions).

### Wave D: after ARM in-ring fork is production-wired (Step 5/6) and ring-first coverage of COW refusals

**P16. Delete host ARM fork and COW lanes**
- **Goal:** delete:
  - `trap/owner_fork.rs` (904) and `trap/process_plan.rs` (2,502);
  - `carrick-aarch64/src/fork.rs` (395) and `build_owner_process_spec`/`run_owner_fork_service`;
  - the synthetic MM_PORTAL ESR handling in `carrick-el1/src/entry.rs:46-54`;
  - `prepare_in_process_fork`'s host-fork half;
  - `perform_frame_cow` (~1,250) and `refill_transfer_cow{,_in}`;
  - `UserMemoryAuthority::legacy()` and its constructors;
  - the `CARRICK_EL1_DESCRIPTOR_LANE=0` hatch, after the owner confirms it;
  - `vmm-hvf/src/fork_quiesce.rs` (rewrite the about 108 call sites to `carrick_thread::fork_quiesce`).
- Close or rebase the N1 PRs first.
- **Files:** carrick-vmm-hvf `trap/*`, carrick-aarch64 `engine.rs` and `fork.rs`, carrick-runtime `vcpu_loop/{lifecycle,quiesce}.rs`, carrick-kernel `mm_authority.rs` (legacy plans).
- **Delta:** about −8,000.
- **Risk:** high.
- **Verify:** full `just ci`, `just test-embed` (signed), `just conformance-quick` and then `just conformance` on one artifact, and the go/cpython/node ecosystems.
- **Order:** last of the memory work.

**P17. Source-text tests → types or semgrep**
- **Goal:** replace the 225 `include_str!("*.rs")` assertions. Each rule becomes a type (preferred) or a rule in `.semgrep/typed-domains.yml`. Delete the 2,394-line static audit.
- **Files:** the 36 files listed in §2, done per crate.
- **Delta:** about +300/−3,500.
- **Risk:** low to medium. Each rule's intent has to be preserved.
- **Verify:** `just lint-domains`, `just test`.
- **Order:** do it per file after that file's in-flight PRs land. The hvf trap and observability parts go after P16.

**P18. Carrier trait set and kick unification**
- **Goal:** `carrick_hal::CarrierVcpu` keyed by exact executor binding; fold `SLOT_KICKER` into `ExecutorKick` (this gives KVM slot kicks); one `CarrierLauncher` for the HVF and KVM pools; HVF launches through the pool, so `threaded_loop`/`vcpu_sched` can be retired; `Sched<A: KernelArch>` replaces `ThreadCpu`; build.rs cfg alias `carrick_hvf_aarch64` replaces `all(target_os="macos", target_arch="aarch64")` in carrick-runtime.
- **Files:** `carrick-hal/src/{threaded,scheduler}.rs`, `carrick-runtime/src/{threaded_loop.rs, vcpu_loop/wait_wake.rs, prepare.rs}`, `carrick-kernel/src/el1_zone.rs`, `carrick-vmm-hvf/src/vcpu_kick.rs`, `carrick-el1/src/sched*`.
- **Delta:** about +600/−1,500.
- **Risk:** high (lost-wakeup class).
- **Verify:** `just test-loom`, `just test-vmfree-schedule`, `just test`, `just test-kvm`, `just test-embed` (signed), and conformance on one artifact.
- **Order:** after P4 and P12.

**P19. Split merge magnets and rename**
- **Goal:**
  - mechanical splits of `carrick-aarch64/src/engine.rs`, `vmm-hvf trap.rs`, `mmu-core aarch64.rs`, `carrick-el1/src/personality/dispatch.rs` and `carrick-kernel/src/kernel/scheduler.rs`;
  - then rename `carrick-el1` → `carrick-guest-kernel` and `carrick-el1-abi` → `carrick-guest-kernel-abi`.
- **Delta:** about 0 net.
- **Risk:** low per commit, but a very large conflict surface.
- **Verify:** `just ci`, `just check-layering`, `just check-linux`, `just test-embed` (signed).
- **Order:** quiet window, after waves B and C. One rename commit, with no logic changes.

### Ordering graph

```
Wave A (now):   P1 → P7     P2     P5     P6     P3* (after #119 or rebase)     P4
Wave B:         #131,#137,#86 → P8 → P9 → P10      P11 (after #119 too)
Wave C:         #119 + ARM COW supply → P12, P13 → P15, P14
Wave D:         ARM in-ring fork Step 5/6 → P16 → P17(hvf parts) ; P4+P12 → P18 ; all → P19
```

Expected net change across all packages: about −22k lines of production code, plus about −3k lines of source-text tests. Of that, about 11k is the planned legacy deletion (P13-P16), about 4.7k duplicate collapse, about 1.6k CERTAIN dead code, and the rest test conversion.
