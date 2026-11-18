# Soft-AArch64 Carrier Inventory and Design (#1236 M2)

Status: M2 inventory, carrier-seam design, and first hosted-ARM64 guest-visible
exit witness (`work/1236-m2-guest`, stacked on `#2540`).

Goal of M2: boot the unmodified production `carrick-el1-image` on the VM-free
AArch64 soft CPU on Linux `arm64`, drop to `EL0`, and run an unmodified static
`aarch64-linux-musl` `hello` binary (`svc #0` from `EL0` -> `EL1` vector ->
`carrick_el1_syscall` -> stdout `"hello, aarch64 world\n"` -> `exit_group(0)`).

Authority: Arm ARM DDI 0487G.a and in-tree Carrick sources only (clean-room
non-negotiable).

---

## 1. Production HVF Carrier Inventory (What Surrounds the CPU)

On the reference macOS HVF AArch64 lane (`docs/architecture-overview.md:27-99`),
one host carrier owns one VM and projects Carrick's kernel graph into the
in-guest `EL1` image (`carrick-el1-image`). Below is everything the production
carrier provides beyond A64 instruction execution.

### 1.1 Guest Physical / Stage-1 Memory Map and Apertures

HVPatch uses a 40-bit (`1 TiB`, `0..0x100_0000_0000`) guest IPA ceiling with
strictly separated Guest VA, stage-1 IPA, global-frame IPA, host backing, and
owner-generation domains (`docs/architecture-overview.md:128-163, 326-332`;
`crates/carrick-mem/src/memory.rs:14-24, 803`).

| Guest VA / IPA Range | Size | Stage-1 Perm | Purpose & Producer (`file:line`) |
| --- | --- | --- | --- |
| `0x00_0000_0000..0x00_0001_0000` | `64 KiB` | Invalid | Null guard (`LINUX_NULL_GUARD_END`, `crates/carrick-mem/src/memory.rs:226, 3557`). |
| `0x00_0001_0000..0x2D_0000_0000` | ~`180 GiB` | `EL0` RW/RX (`PXN=1`) | Low user segments (`ET_EXEC` at `0x20_0000..`), `brk` heap (`LINUX_HEAP_BASE`), low `mmap` (`crates/carrick-mem/src/memory.rs:612-755, 3473-3480`). |
| `0x2D_0000_0000..0x2D_0020_0000` | `2 MiB` | `EL1` RWX (`AP=00, UXN=1, PXN=0`) | **Kernel control hole** (`LINUX_KERNEL_REGION_BASE`, `crates/carrick-mem/src/memory.rs:217-219, 3460-3471`); persistent carrier control mappings extracted at `crates/carrick-vmm-hvf/src/trap/persistent_executor.rs:314-325`: |
| — `0x2D_0000_0000` | `16 KiB` | `EL1` RX | `LINUX_EL0_TRAMPOLINE_BASE`: `el0_trampoline_bytes()` (`tlbi vmalle1is; dsb sy; ic ialluis; dsb sy; isb; clrex; eret`, `crates/carrick-mem/src/memory.rs:227-231, 4092-4127`). |
| — `0x2D_0001_0000` | `16 KiB` | `EL1` RX | `LINUX_EL1_VECTORS_BASE`: 12 disjoint vector/hook/portal/clock spans (`VECTOR_PAGE_REGIONS`, `crates/carrick-mem/src/memory.rs:236-237, 5063-5116, 5824-6350`). |
| — `0x2D_0002_0000` | `1.75 MiB` | `EL1` RW | `LINUX_PAGE_TABLES_BASE`: 8 initial 4 KiB tables + spare pool (`stage1_identity_page_tables` at `crates/carrick-mem/src/memory.rs:248-262, 3445-3635`; `stage1_hvpatch_page_tables` with `nG=1` and COW copy window at `3912-3980`). |
| — `0x2D_001E_0000` | `16 KiB` | `EL1` RX | `LINUX_EL1_MAINT_BASE`: stage-1 `TLBI` + `hvc #1` / `hvc #7` service trampolines (`el1_maintenance_bytes`, `crates/carrick-mem/src/memory.rs:271-274, 4135-4181`). |
| — `0x2D_001E_4000` | `16 KiB` | `EL1` RW | `LINUX_IDENTITY_PAGE_BASE`: per-container identity fast-path gate and cached PID/UID/GID (`crates/carrick-mem/src/memory.rs:298-300, 448-468`). |
| — `0x2D_001E_8000` | `64 KiB` | `EL1` RW | `LINUX_SYSCALL_MAILBOX_BASE`: 256 slots × 256 B `Aarch64SyscallMailbox` (`crates/carrick-mem/src/memory.rs:92-130, 301-305`). |
| — `0x2D_001F_8000` | `16 KiB` | `EL1` RW | `LINUX_CARRIER_MAINT_ROOT_BASE`: `ASID 0` kernel-only maintenance root (`stage1_carrier_maintenance_page_tables`, `crates/carrick-mem/src/memory.rs:392-393, 3988-4090`). |
| — `0x2D_001F_C000` | `16 KiB` | `EL1` RW | `LINUX_FD_CEILING_CONTROL_BASE`: `fstat`/`close` ceiling gate (`crates/carrick-mem/src/memory.rs:410-421`). |
| `0x2D_0400_0000..` (`EL1_REGION_BASE`) | `EL1_REGION_SIZE` | `EL1` RWX (guards unmapped) | **EL1 kernel image & static ABI tables** (`crates/carrick-el1-abi/src/lib.rs:91-97`; `crates/carrick-mem/src/memory.rs:809-810, 2186-2244`): |
| — `+0x0000_0000` (`EL1_IMAGE_OFFSET`) | `1.5 MiB` | `EL1` RX/RW | Production `carrick-el1` image starting with `ImageHeader` (`b"CEL1"`, v2, `entry_offset` at `+8`, `abi_hash_offset` at `+24`, `crates/carrick-el1-abi/src/lib.rs:995-1046, 1344-1387`; `crates/carrick-el1-linux/link.ld:6-15`). |
| — `EL1_COUNTERS_OFFSET` | `1 MiB` | `EL1` RW | 8 occupants (`EL1_COUNTERS_AREA_OCCUPANTS`, `crates/carrick-el1-abi/src/lib.rs:209-246`): `Counters`, `SharedReservations`, descriptor txns, COW copy window, `EL1_STACK_GUARD_TABLES_OFFSET` (`el1_stack_guard_tables()` at `crates/carrick-mem/src/memory.rs:3823-3834`), `ServiceCopyTable`, `ApertureControl`, `MmPortalSlots`. |
| — `EL1_STACKS_OFFSET` | `8 MiB` | `EL1` RW + L3 guards | 256 slots × `32 KiB` stride (`16 KiB` unmapped L3 guard + `16 KiB` usable stack, `crates/carrick-el1-abi/src/lib.rs:119-153, 288-336`). |
| — `EL1_CURRENT_TASKS_OFFSET` | `1 MiB` | `EL1` RW | 256 × 256 B `CurrentTask` array (`+0x0`), `MetadataGrantMailbox` (`+0x10_000`), `FrameGrantMailboxes` (`+0x20_000`), `FrameGrantResidencyTable` (`+0x30_000`), `SharedSignalIngressQueue` (`crates/carrick-el1-abi/src/lib.rs:367-415, 1570-1620`). |
| — `EL1_BOOTSTRAP_METADATA_OFFSET` | `9 MiB` | `EL1` RW | Bootstrap allocator extent (`crates/carrick-el1-abi/src/lib.rs:469-472, 588`). |
| — `EL1_HEAP_OFFSET..end` | Remainder | `EL1` RW | `ObjectTable`, `FdMap`, `OpenFileTable`, `IpcTableMap`, `32 MiB` delegated file cache (`EL1_CACHE_OFFSET`), inotify/name cache, `ZoneTables` (`EL1_ZONE_OFFSET`, `crates/carrick-el1-abi/src/lib.rs:773-843, 972-978, 1196`). |
| `EL1_DYNAMIC_METADATA_BASE` | `64 MiB` | `EL1` RW (on grant) | Dynamic metadata aperture, granted in `512 KiB` quanta via `hvc #6` (`crates/carrick-el1-abi/src/lib.rs:592, 640-643`; `crates/carrick-vmm-hvf/src/metadata_grant.rs:1-120`). |
| `EL1_IPC_BASE` | `640 MiB` | `EL1` RW | Shared IPC window (`128 MiB` directory + `512 MiB` pool, `crates/carrick-el1-abi/src/lib.rs:786-800`; installed once by `install_registered_ipc_window` at `crates/carrick-vmm-hvf/src/trap/persistent_executor.rs:977`). |
| `0x2E_0000_0000..` | `48 KiB` | `EL0` RO/RX | `LINUX_VVAR_BASE`, `LINUX_VDSO_BASE`, `LINUX_EL0_CLOCK_STUB_BASE` (`crates/carrick-mem/src/memory.rs:820-856`; `crates/carrick-mem/src/vdso.rs:1-150`). |
| `0x2F_0000_0000..0x30_0000_0000` | `256 MiB` | **Unmapped** | `LINUX_GIC_WINDOW_BASE` (distributor `0x2F_0000_0000`, redistributor `0x2F_0100_0000`, `crates/carrick-mem/src/memory.rs:858-865, 3517-3523`; `crates/carrick-vmm-hvf/src/gic.rs:245-254`). |
| `0x30_0000_0000..0xFF_FFFF_0000` | ~`832 GiB` | `EL0` / carrier | `LINUX_SIGRETURN_TRAMPOLINE_BASE` (`0x30_0000_0000`),PIE default (`544 GiB`), dynamic linker (`560 GiB`), shared-file (`0x90_0000_0000`), private-overlay (`0x98_0000_0000`), stage-1 table pool (`0x9A_0000_0000`), global frames (`0x9B_0000_0000..`), and user stack ending at `LINUX_STACK_TOP = 0xFF_FFFF_0000` (`crates/carrick-mem/src/memory.rs:762-808`). |

### 1.2 User ELF and Initial Task Loading

1. **ELF + Linux stack + auxiliary vector**: `AddressSpace::from_elf_bytes`
   parses `PT_LOAD` / `PT_INTERP` / `PT_TLS` and lays out `argc`, `argv`,
   `envp`, and `auxv` (`AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_PAGESZ = 4096`,
   `AT_ENTRY`, `AT_RANDOM`, `AT_SYSINFO_EHDR`, etc.) below `LINUX_STACK_TOP`
   (`crates/carrick-mem/src/memory.rs:1600-1647, 2723-3018`).
2. **HVF / EL1 control decoration**: `finalize_hvf_initial_image` and
   `with_hvf_syscall_mailbox` (`crates/carrick-runtime/src/runtime.rs:813-865`)
   attach `el0_trampoline_bytes`, `with_el1_vectors_mailbox_clock`,
   `EL1_REGION_BASE` (`with_el1_region`), `LINUX_IDENTITY_PAGE_BASE`,
   `LINUX_SYSCALL_MAILBOX_BASE`, `LINUX_FD_CEILING_CONTROL_BASE`,
   `LINUX_CARRIER_MAINT_ROOT_BASE`, `stage1_hvpatch_page_tables`, and optional
   vvar/vDSO pages.
3. **Carrier custody & root binding**: `HvfVmState::map_plan`
   (`crates/carrick-vmm-hvf/src/trap/mapping_plan.rs:640-721`) installs
   stage-2 mappings and captures `StagedCpu::initial_root`. Persistent carrier
   setup (`crates/carrick-vmm-hvf/src/trap/persistent_executor.rs:314-325, 977`)
   retains the 7 immutable carrier control regions, registers `EL1_IPC_BASE`,
   populates the vvar clock page (`populate_vdso_data_page` at
   `crates/carrick-vmm-hvf/src/trap/cow_engine.rs:5900`), and publishes the
   root task's `CurrentTask[slot]` entry (`EL1_CURRENT_TASKS_BASE + slot * 256`,
   `crates/carrick-el1-abi/src/lib.rs:1570-1620`).

### 1.3 Boot / Handoff Registers and Critical `SP_EL1` Invariant

`StagedCpu::initial_root` (`crates/carrick-vmm-hvf/src/staged_cpu.rs:39-78`) and
executor slot binding (`crates/carrick-vmm-hvf/src/trap/persistent_executor.rs:817-846, 1004-1034, 1120-1126`)
establish the exact root vCPU state:

- `PC = LINUX_EL0_TRAMPOLINE_BASE` (`0x2D_0000_0000`)
- `PSTATE = ROOT_BOOT_PSTATE` (`0x3c5`: `EL1h`, `DAIF = 0b1111`)
- `ELR_EL1 = user ELF entry`, `SPSR_EL1 = ROOT_EL0_ENTRY_SPSR` (`0x3c0`: `EL0t`,
  `DAIF = 0b1111`; `GIC` mode clears `PSTATE.I` on served returns at
  `crates/carrick-mem/src/memory.rs:5437-5444`)
- `SP_EL0 = initial_stack_pointer`, `X0..X30 = 0`, `TPIDRRO_EL0 = packed tid`
- `VBAR_EL1 = LINUX_EL1_VECTORS_BASE` (`0x2D_0001_0000`)
- `MAIR_EL1 = MAIR_EL1_BOOTSTRAP` (`0xff`)
- `TCR_EL1 = TCR_EL1_BOOTSTRAP` (`0x62_bf10_3f10`, OR'd with `TCR_AS = 1 << 36`
  -> `0x72_bf10_3f10` when bound to a 16-bit ASID)
- `TTBR0_EL1 = TTBR1_EL1 = root_pa | (asid << 48)`
- `SCTLR_EL1 = SCTLR_EL1_BOOTSTRAP` (`0x0400_d005`: `M | C | I | DZE | UCT | UCI`)
- `CPACR_EL1 = 3 << 20` (`FPEN = 0b11`), `CNTKCTL_EL1 = 0x3` (`EL0VCTEN | EL0PCTEN`)
- **Critical `SP_EL1` invariant**: while `EL0` executes (and across `eret` /
  `hvc #2` / `#4` / `#5`), `SP_EL1` does **not** point into `EL1_STACKS_BASE`;
  it holds the leased `Aarch64SyscallMailbox` VA
  (`LINUX_SYSCALL_MAILBOX_BASE + slot * 256`). On `EL0` entry into
  `write_el1_hook` (`crates/carrick-mem/src/memory.rs:5209-5394`), the vector
  spills `x16`/`x17` at `[sp, #RESUME_X16/X17]`, derives
  `slot = (SP_EL1 - LINUX_SYSCALL_MAILBOX_BASE) >> 8`, switches `sp` to
  `stack_slot_top(slot) - 0x120`, populates `TrapFrame`, reads `entry_offset`
  from `EL1_REGION_BASE + 8`, and `blr`s to `carrick_el1_syscall(frame_ptr)`
  (`crates/carrick-el1-linux/src/entry.rs:1-115`).

### 1.4 Console / UART / Virtio Devices and How the Image Does I/O

**Zero MMIO I/O devices exist on the production HVF carrier.** There is no
PL011/8250 UART, no virtio-mmio transport, and no emulated PCI/framebuffer bus.

- Every guest console, file, pipe, pty, and socket operation enters through
  `svc #0` -> `EL1_VECTOR_HOOK` -> `carrick_el1_syscall`
  (`crates/carrick-el1-linux/src/dispatch.rs:279-355`).
- In-zone pipes/sockets/ptys and delegated cached files complete in-ring
  against shared memory (`EL1_IPC_BASE`, `EL1_CACHE_OFFSET`); host-backed I/O
  returns `Action::Forward` (`x0 = 1`), populates `Aarch64SyscallMailbox` at
  `MAILBOX_CAPTURE_OFFSET` (`crates/carrick-mem/src/memory.rs:5907-6106`), and
  exits via `hvc #2` to host `SyscallDispatcher`.
- Even `LINUX_GIC_WINDOW_BASE` (`0x2F_0000_0000`) is intentionally left
  unmapped in stage-1 (`crates/carrick-mem/src/memory.rs:3517-3523`) and
  stage-2: the guest never performs MMIO to `GICD`/`GICR`. (By contrast, KVM
  AArch64 uses synthetic MMIO sentinel stores only because KVM traps guest `HVC`
  as an `EL1` UNDEF without `KVM_ARM_VCPU_HAS_EL2`, `crates/carrick-aarch64/src/vmm.rs:10-12, 66-67, 113-114`.)

### 1.5 GICv3 and Generic Timer Programmed by the Image

- **Host configuration (`crates/carrick-vmm-hvf/src/gic.rs:38-115, 325-382, 656-658`)**:
  programs unique per-vCPU `MPIDR_EL1` (`(1 << 31) | ((idx / 16) << 8) | (idx % 16)`),
  enables Group 1 private INTIDs on each redistributor (`VTIMER_INTID = 27` PPI
  prio `0x80`, `RESCHED_INTID = 14` SGI prio `0x90`, `KICK_INTID = 15` SGI prio
  `0xa0`), sets `ICC_PMR_EL1 = 0xf0` and `ICC_IGRPEN1_EL1 = 1`, and masks
  `ID_AA64PFR0_EL1.GIC` to `0` for `EL0`. `CARRICK_HVF_GIC=0` selects the legacy
  `El1IrqMode::Masked` fallback.
- **EL1 image accesses (`crates/carrick-el1/src/sched/hw.rs:280-364`)**:
  system registers and `WFI` only:
  - `ICC_IAR1_EL1` (`S3_0_C12_C12_0`, spurious `GIC_SPURIOUS_INTID = 1023`),
    `ICC_EOIR1_EL1` (`S3_0_C12_C12_1`), `ICC_SGI1R_EL1` (`S3_0_C12_C11_5`),
    `MPIDR_EL1` (`S3_0_C0_C0_5`).
  - `CNTFRQ_EL0` (`S3_3_C14_C0_0`), `CNTVCT_EL0` (`S3_3_C14_C0_2`),
    `CNTV_CVAL_EL0` (`S3_3_C14_C3_2`), `CNTV_CTL_EL0` (`S3_3_C14_C3_1`).
  - Idle `WFI` runs in `EL1h` with `PSTATE.I = 1` so wakeups wake from `WFI`
    without vectoring inside `EL1` (`hw.rs:348-364`).

### 1.6 HVC / Hypercall ABI Between Image and Host

`hvc #0` is never used (SMCCC collision hazard). Every `EL1 -> carrier`
boundary uses `hvc #1..#7` (`crates/carrick-hal/src/aarch64.rs:37-121`,
`crates/carrick-vmm-hvf/src/trap.rs:8470-8940`,
`crates/carrick-el1/src/isa/aarch64.rs:51-374`):

| Immediate | Producer | Carrier Meaning |
| --- | --- | --- |
| `hvc #1` | `LINUX_EL1_MAINT_BASE` (`memory.rs:4144, 4176`) | Stage-1 `TLBI` maintenance completion. |
| `hvc #2` | `MAILBOX_CAPTURE` / `not_svc` (`memory.rs:6106`) | Syscall forward (`mailbox.state == 1`) **or** `NotSvc` `EL0` trap (`mailbox.state == 0`: `EC=0x18` `sys64` MRS emulation at `trap.rs:8721-8728` or `EL0Fault`). |
| `hvc #3` | Current-EL sync vector / `entry.rs:116-139` / `isa/aarch64.rs:685-699` | Fail-loud `EL1` fault, stack-guard overflow, `PANIC_SENTINEL` (`0xDEAD_CAFE_DEAD_BEEF`), `NATIVE_RUN_FAILURE_SENTINEL`, or `Stage1CowFault` (`trap.rs:8599-8606`). |
| `hvc #4` | `EL0` IRQ / `SignalCheck` hook (`memory.rs:5600-5640`) | Asynchronous interrupt / `pending_host_work` boundary. |
| `hvc #5` | `EL1_VECTOR_HOOK` idle branch (`memory.rs:5398-5401`) | Scheduler `Action::Idle == 3` (`vacate` onto `CarrierMaintenanceRoot`). |
| `hvc #6` | `crates/carrick-el1/src/isa/aarch64.rs:58-374` | Synchronous stopped-CPU owner/metadata service (`x0 = op 1..=15`, `x1..x3` args/replies; `crates/carrick-el1-abi/src/lib.rs:645-688`; `crates/carrick-vmm-hvf/src/metadata_grant.rs:2352-2537`): `ALLOC=1`, `FREE=2`, `FORK_STOCK=3`, `ROOT_EXIT=4`, `CHILD_RETIRE=5`, `COW_SUPPLY=6`, `WAIT_CHANNEL_WAKE=7`, `DIAGNOSTIC=8`, `RESIDENCY_KICK=9`, `CHILD_RECLAIM=10`, `EXEC_ADOPT=11`, `EXEC_SETTLE=12`, `EXEC_CANCEL=13`, `ROOT_FORK_SEED=14`, `RETURN_SETTLE=15`. |
| `hvc #7` | `LINUX_EL1_MAINT_BASE + 0x14` (`memory.rs:4145`, `isa/aarch64.rs:51-56`) | Host-driven `EL1` service call completion / `yield_host_effect`. |

### 1.7 SMP / Secondary CPUs

All hardware vCPUs are created during `TopologyPhase::Assembling` and sealed
before the first `hv_vcpu_run` (`VcpuTopology`,
`crates/carrick-vmm-hvf/src/trap/vcpu_topology.rs:1-166`). Persistent executor
workers lease vCPU + `MailboxSlotId` (`SP_EL1`) pairs on demand
(`docs/architecture-overview.md:165-194`;
`crates/carrick-vmm-hvf/src/trap/persistent_executor.rs:1036-1061`), enter idle
on `CarrierMaintenanceRoot` (`ASID 0`), and wake peers via `ICC_SGI1R_EL1`
(`RESCHED_INTID = 14`) or host kick (`KICK_INTID = 15`, absorbed across
in-vector windows by `owed_kick` at `crates/carrick-aarch64/src/engine.rs:2634-2673`).

---

## 2. Soft-AArch64 Equivalent and Crate Placement Design

### 2.1 Existing-Mechanism Inventory

| Capability | Existing Crate & Surface | Status for Soft-AArch64 M2 |
| --- | --- | --- |
| A64 decoder, copy-through translator, `CpuState`, `EL0`/`EL1` exceptions, `PAN`/`UAO`, virtual sysreg bank, local exclusive monitor | `crates/carrick-softcpu-aarch64` (`lib.rs`, `translate.rs`, `state.rs`, `exception.rs`, `handler.rs`, `dispatch.rs`) | Ready for `EL1` image + `EL0` scalar/syscall path (with `IC IALLUIS`/`IC IALLU` added in this slice). Needs `EL0` AdvSIMD + `NZCV`/`DC ZVA` for musl CRT (Section 2.3). |
| Linux `arm64` W^X block publisher & `ExecuteBlock` host launch | `crates/carrick-host-jit`, `crates/carrick-softcpu-aarch64-host` | Ready on hosted Linux `arm64`. |
| VMSAv8-64 stage-1 walker (`Stage1Walker`) | `crates/carrick-mmu-core/src/aarch64/stage1_walk.rs` (`Aarch64Walker`, `#2540`) | Ready and wired into `carrick-softcpu-aarch64::mmu`. |
| Generation-authenticated soft TLB & extent resolution | `crates/carrick-softmmu` (`SoftMmuMemory`, `resolve_leaf<W: Stage1Walker>`, `#2540`) | Walker resolution is ISA-neutral; needs an AArch64 `SoftMmuMemory` adapter implementing `carrick_softcpu_aarch64::handler::GuestMemory`. |
| Guest ELF loader, stack/auxv builder, `EL0`/`EL1` trampolines, mailbox vectors, bootstrap stage-1 tables | `crates/carrick-mem` (`AddressSpace`, `el0_trampoline_bytes`, `el1_vectors_bytes_mailbox_clock`, `stage1_hvpatch_page_tables`) | Ready and host-OS-neutral (`std`). |
| Shared AArch64 engine, `owed_kick`, `Aarch64Vmm`/`Aarch64Vcpu` traits | `crates/carrick-aarch64` (`vmm.rs`, `engine.rs`, `owed_kick.rs`) | Exists; `Sys64Read` hook (`engine.rs:2608-2615`) already anticipates shared `emulate_el0_sys64_read`. |
| Neutral fork-stock & native-exec custody | `crates/carrick-hal` (`fork_stock.rs`, `native_exec.rs`, `aarch64.rs`, `aarch64_arch.rs`) | Shared between x86 CPL0 and ARM EL1; HVF's `hvc #6` wire adapter still lives in `carrick-vmm-hvf/src/metadata_grant.rs`. |
| VM-free soft carrier backend (x86 M1 reference) | `crates/carrick-vmm-soft` (`src/lib.rs`, `tests/soft_boot_probe.rs`, `tests/soft_hello.rs`) over `carrick-x86-cpl0-host` (`CarrierCpuBackend`, `CarrierMemoryIo`, `BootstrapCustody`) | Exists, currently `#![cfg(all(target_arch = "x86_64", target_os = "linux"))]`. |

### 2.2 What Must Be Built for M2 (and What Is Not Needed)

1. **No MMIO device bus**: because `carrick-softcpu-aarch64` surfaces `EL1`
   `HVC` directly as `Event::ProviderExit(ProviderExit { immediate })`,
   soft-aarch64 runs the **exact HVF `HVC` vector pages**, not KVM's synthetic
   MMIO sentinel vehicle. Any `Event::MemoryFault` on an unbacked GPA is an
   invariant/stage-2 fault, never a UART or GIC MMIO exit.
2. **Stopped-CPU `HVC #1..#7` carrier loop**:
   - `hvc #1`: flush the per-vCPU `SoftTlb` (`carrick-softmmu`) and resume.
   - `hvc #2`: when `Aarch64SyscallMailbox.state == 1`, normalize registers into
     `SyscallDispatcher` (`carrick-kernel`), write the return/signal action back
     to the mailbox/frame, and resume; when `state == 0` (`NotSvc`), run shared
     `decode_el0_sys64_read` (`CNTFRQ_EL0`, `CNTVCT_EL0`, `CTR_EL0`, `DCZID_EL0`)
     or deliver `EL0Fault`.
   - `hvc #3`: decode fail-loud `EL1` panic/fault sentinels (`PANIC_SENTINEL`,
     `NATIVE_RUN_FAILURE_SENTINEL`, stack-guard overflow) or route
     `Stage1CowFault`.
   - `hvc #4` / `hvc #5`: settle asynchronous host work / scheduler idle return.
   - `hvc #6`: service stopped-CPU owner/metadata operations (`1..=15`),
     starting with `ALLOC (1)`, `FREE (2)`, `FORK_STOCK (3)`, `ROOT_EXIT (4)`,
     `COW_SUPPLY (6)`, `WAIT_CHANNEL_WAKE (7)`, `DIAGNOSTIC (8)`, and
     `RETURN_SETTLE (15)` needed for single-process `hello` admission, write,
     and exit.
   - `hvc #7`: stop the nested host-driven `EL1` service call (`call_el1_service`)
     and return `x0` to the carrier caller.
3. **Minimal GICv3 CPU-interface + virtual generic timer model**:
   - Stateful virtual timer in `carrick-softcpu-aarch64`: `CNTFRQ_EL0 = 10^9` Hz,
     deterministic/monotonic `CNTVCT_EL0` advanced on block retirement (and host
     wait), `CNTV_CVAL_EL0`, and `CNTV_CTL_EL0` (`ENABLE`, `IMASK`, `ISTATUS`
     computed dynamically as `ENABLE && (CNTVCT >= CVAL)`), asserting private
     `VTIMER_INTID = 27` when `ENABLE && !IMASK && ISTATUS`.
   - Per-CPU GICv3 `ICC_*` state (`ICC_IAR1_EL1`, `ICC_EOIR1_EL1`,
     `ICC_SGI1R_EL1`) tracking pending/active bits for INTIDs `14` (`RESCHED`),
     `15` (`KICK`), and `27` (`VTIMER`), returning `1023` (`GIC_SPURIOUS_INTID`)
     when empty. At `dispatch::run` block boundaries, a pending enabled Group 1
     INTID enters `VBAR_EL1 + 0x480` (`EL0` IRQ) when `!pstate.daif.irq_masked()`
     and wakes `Event::Hint(Hint::Wfi)` even when `PSTATE.I = 1` (Arm ARM
     D1.13.4; `crates/carrick-el1/src/sched/hw.rs:348-364`).
4. **SMP / multi-vCPU scope**: just like x86 soft M1
   (`docs/design/soft-x86-cpl0-bringup.md:77-80`), parallel multi-vCPU execution
   over shared `Inventory` is gated on peer code-page revocation (`#2397` /
   `#684`). M2 runs single-vCPU (`slot 0`, `MPIDR_EL1 = 0x8000_0000`).

### 2.3 Measured Static `aarch64-linux-musl` `hello` Gap ("Slice 0b")

Cross-compiling `fn main() { println!("hello, aarch64 world"); }` with
`rustc --target aarch64-unknown-linux-musl -C relocation-model=static -C link-arg=--no-pie`
(the exact AArch64 counterpart of `crates/carrick-vmm-bhyve/fixtures/hello-x86_64`)
produces a static `ET_EXEC` binary (`75,706` instructions across `161` distinct
mnemonics, entry `0x223720`). Tracing its `EL0` startup path reveals two exact
CPU gaps before `main`'s `write`/`writev` syscall:

1. **Mandatory Armv8.0-A user FP/AdvSIMD (`V0..V31`, `FPCR`, `FPSR`)**:
   `_start` (`0x223720`) -> `_start_c` -> `__libc_start_main` -> `__init_libc`
   immediately calls musl `memset(sp + 0x60, 0, 0x130)`, whose very first
   instruction is `dup v0.16b, w1` (`0x4e01_0c20`), followed by `mov x1, v0.d[0]`
   (`0x4e08_3c01`), `str q0` (`0x3d80_0000`), and `stp q0, q0` (`0xad01_0060`).
   - **Design**: add `v: [u128; 32]` to `CpuState` and `BlockFrame`
     (`entry_stub` / `common_exit` `ldp`/`stp q0..q31` + `FPCR`/`FPSR` when
     `CPACR_EL1.FPEN == 0b11`), wire `MemoryRegister::Vector` (already decoded
     in `carrick-softcpu-aarch64/src/lib.rs:1337-1339, 1422-1424`) in
     `handler.rs`, and classify register-only baseline AdvSIMD instructions
     (`DUP`, `MOVI`, `FMOV`, vector `ADD`/`AND`/`ORR`/`EOR`/`BIC`/`MVN`/`EXT`,
     `UXTL`/`SHRN`/`XTN`, `CMEQ`/`CMGT`, `ADDP`/`ADDV`/`UMAXV`) as
     `Copy(CopyKind::Verbatim)` on the arm64 host.
2. **EL0 cache/PSTATE system accesses in musl CRT**:
   - `mrs x5, dczid_el0` (`0xd53b_00e5`) + `dc zva, x3` (`0xd50b_7423`) in
     `memset` (`size >= 0xa0`): decode `DCZID_EL0` (`0x4` = 64 B zeroing block
     when `SCTLR_EL1.DZE == 1`, or trap `EC=0x18` to `emulate_el0_sys64_read`)
     and handle `DC ZVA, <Xt>` as a 64-byte aligned stage-1 zero store.
   - `mrs/msr nzcv, xN` (`S3_3_C4_C2_0`, 2 sites) in `NamedSystemRegister` /
     `CpuState`. (`TPIDR_EL0` used by `__set_thread_area` is already supported;
     `IC IVAU, <Xt>` under `SCTLR_EL1.UCI` completes cache-maintenance parity.)

### 2.4 Where Each Component Belongs (Reuse Over Duplication)

Per `AGENTS.md` ("Fix in shared layers; move code, never copy it"):

- **`crates/carrick-softcpu-aarch64`** (`no_std`, pure ISA):
  `IcOperation` (`Ialluis`, `Iallu`, later `Ivau`), `DcOperation::Zva`,
  `NamedSystemRegister::Nzcv` / `DczidEl0` / `CtrEl0`, `V0..V31` state +
  `BlockFrame` layout + `MemoryRegister::Vector` handler + AdvSIMD `Verbatim`
  classification, and the virtual timer + per-CPU GICv3 `ICC_*` state machine.
- **`crates/carrick-aarch64`** (shared AArch64 VMM/carrier layer):
  1. Move `decode_el0_sys64_read` / `El0SysRegRead` out of
     `crates/carrick-vmm-hvf/src/trap/sysreg.rs:49-71` into `carrick-aarch64` so
     HVF, `Aarch64EngineCore` (`engine.rs:2608-2615`), and soft-aarch64 share one
     decoder.
  2. Extract an AArch64 stopped-CPU carrier seam (`El1CarrierCpu` /
     `El1CarrierMemory` / `El1BootstrapCustody`, mirroring
     `crates/carrick-x86-cpl0-host/src/carrier_cpu.rs` and `carrier_memory.rs`)
     that owns `StagedCpu::initial_root` construction, `call_el1_service`
     (`hvc #7`), and stopped-CPU `hvc #6` dispatch over `carrick-hal::fork_stock`
     and `carrick-hal::native_exec`, instead of duplicating
     `carrick-vmm-hvf/src/metadata_grant.rs`.
- **`crates/carrick-vmm-soft`** (existing VM-free soft carrier crate):
  widen `crates/carrick-vmm-soft/src/lib.rs:11` from `target_arch = "x86_64"` to
  dispatch per host architecture (`#[cfg(target_arch = "x86_64")]` for CPL0 and
  `#[cfg(target_arch = "aarch64")]` for EL1), binding `HostBlockRunner`
  (`carrick-softcpu-aarch64-host`) + `SoftMmuMemory` (`carrick-softmmu` +
  `Aarch64Walker`) to the shared `carrick-aarch64` EL1 carrier seam and hosting
  `tests/soft_aarch64_hello.rs`. Do **not** create a parallel
  `carrick-vmm-soft-aarch64` crate unless `carrick-x86-cpl0-host` vs
  `carrick-aarch64` dependency isolation requires a thin feature split.

### 2.5 Ordered M2 Slice Plan

1. **M2-2a (this branch)**: inventory + design doc, `IC IALLUIS`/`IC IALLU` in
   `carrick-softcpu-aarch64`, and end-to-end hosted-`arm64` boot probe from
   `LINUX_EL0_TRAMPOLINE_BASE` (`0x2D_0000_0000`) -> `eret` -> `EL0` static
   guest ELF (`hello-aarch64`) -> `svc #0` -> `EL1_VECTOR_HOOK` ->
   `carrick_el1_syscall` -> `mailbox_capture` -> `HVC #2`.
2. **M2-2b (EL0 user-ABI closure in `carrick-softcpu-aarch64`)**: `V0..V31`
   in `CpuState` + `BlockFrame` + `handler::execute`, baseline AdvSIMD
   copy-through, `NZCV`/`DCZID_EL0`/`CTR_EL0`, and `DC ZVA` / `IC IVAU`,
   witnessed against the static `aarch64-unknown-linux-musl` `hello` instruction
   census (`0` unknown/undecoded words).
3. **M2-2c (GICv3 `ICC_*` + virtual timer + `SoftMmuMemory` AArch64 binding)**:
   wire `SoftMmuMemory` + `Aarch64Walker` as `GuestMemory` with `hvc #1` TLB
   flush, plus deterministic `CNTV` + `ICC_IAR1`/`EOIR1`/`SGI1R` + `WFI` wake.
4. **M2-2d (Shared EL1 stopped-CPU custody + `carrick-vmm-soft` `aarch64`
   hello)**: extract shared `El1CarrierCpu` / `hvc #6` service in
   `carrick-aarch64`, wire `carrick-vmm-soft` (`aarch64`) + `SyscallDispatcher`,
   and run unmodified static `aarch64-unknown-linux-musl` `hello` end-to-end on
   `soft-aarch64-native` CI (`stdout == "hello, aarch64 world\n"`, `exit == 0`).

---

## 3. First Hosted-ARM64 Guest-Visible Exit Receipt

Driven by `crates/carrick-softcpu-aarch64-host/tests/boot_probe.rs`
(`production_el1_image_boots_past_trampoline_to_first_guest_hvc`) from the
production `StagedCpu::initial_root` entry (`PC = 0x2d00000000` in `EL1h` with
`el0_trampoline_bytes()`, `el1_vectors_bytes_mailbox_clock(true, true, El1IrqMode::Gic)`,
`stage1_hvpatch_page_tables()`, `SP_EL1 = 0x2d001e8000`, and unmodified static
`hello-aarch64` ELF at `ELR_EL1 = 0x210120`):

- Hosted `soft-aarch64-native` receipt: *(populated immediately after hosted CI
  run on `work/1236-m2-guest`)*
