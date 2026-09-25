# EL1 kernel increment 1a: adopt HVF's in-kernel GIC in the production VM

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:executing-plans
> (or superpowers:subagent-driven-development) to run this plan task by task.
> Steps use checkbox (`- [ ]`) syntax. Read `AGENTS.md` first (Rule 0 codesign,
> `just` recipes, red-first, commit style, never `git stash`). The GIC setup
> follows libkrun and `hv_gic.h` (see "Prior art") and is not re-proven. Task 1
> checks only the uses no reference VMM exercises, and Task 2 designs out the
> one use the SDK forbids. Both are DECISION tasks: later tasks are valid only
> under the outcome their gate records, and each gate names its STOP
> condition.

**Goal:** Every production HVF carrier VM is created with Hypervisor.framework's
in-kernel GICv3 (`hv_gic_create`), every vCPU carries a unique MPIDR and a
configured redistributor, every vCPU lives for its VM's life, the interrupt a
kicked vCPU owes at its EL0 boundary travels as a GIC interrupt, and EL1 can take
and complete a GIC interrupt itself, with no guest-visible behaviour change. A
signed embed test proves the guest virtual timer interrupt reaches EL1 in the
production VM with zero host exits between arming and delivery other than host
kicks (which carry no timer).

**Architecture:** One module, `carrick-vmm-hvf/src/gic.rs`, is the only caller of
raw `hv_gic_*`. The single VM-creation funnel (`create_vm_with_admission`) creates
the GIC right after `hv_vm_create`, inside the same custody transaction, so every
VM gets one before its first vCPU. This is the reference order libkrun uses and
`hv_gic.h` requires. The two vCPU-creation wrappers (the only
`vm.vcpu_create()` callers) give each vCPU an MPIDR and configure its
redistributor and CPU interface on the owning thread before it can run. vCPUs
are created before the VM's first run and destroyed only at teardown (Task 2).
Host kicks stay `hv_vcpus_exit`, as in every VMM. The deferred interrupt a
kicked vCPU owes at its next EL0 boundary (`OwedKick`) becomes a
redistributor-pending SGI, because the SDK makes
`hv_vcpu_set_pending_interrupt` return `HV_UNSUPPORTED` once a GIC exists. EL1
takes GIC interrupts in one place: a short IRQ window on the EL1 served-syscall
return path, where a compiled Rust handler (`carrick_el1_irq`, image header v3)
acknowledges, services and completes the interrupt. Guest EL0 keeps running with
DAIF masked exactly as today.

**Tech Stack:** Rust 1.96 (pinned), `applevisor-sys` 1.0.0 (raw `hv_gic_*`,
`macos-15-0` feature), Hypervisor.framework on macOS 27 / Apple M4, `no_std`
`aarch64-unknown-none-softfloat` EL1 image, hand-encoded vector page in
`carrick-mem`, `carrick-conformance-contract`, `carrick trace` / DTrace USDT.

**Spec:** `docs/superpowers/specs/2026-09-24-el1-kernel.md` (ACCEPTED 2026-09-24),
sections "Scheduling" (consequences for the design) and "Open items (entry
criteria for dependent increments)" items 1 and 2.

---

## Prior art: how other VMMs use the in-kernel GIC

Carrick is clean-room with respect to GPL code (AGENTS.md). Every fact below
comes from a permissively licensed source or from Apple's SDK; QEMU (GPL-2.0)
also drives `hv_gic_*`, but nothing from its code or patches is used here.

| Source | License | Link |
|---|---|---|
| Apple Hypervisor.framework SDK headers (`hv_gic.h`, `hv_vcpu.h`), macOS 27 SDK in Xcode-beta | Apple SDK | local: `$(xcrun --show-sdk-path)/System/Library/Frameworks/Hypervisor.framework/Headers/` |
| libkrun at `85bed715434ed644857d963f7df0981ce43eef56` (2026-09-21; `containers/libkrun` redirects here) | Apache-2.0 (`LICENSE`; no GPL text in the tree) | https://github.com/libkrun/libkrun |

libkrun paths below are relative to
`https://github.com/libkrun/libkrun/blob/85bed715434ed644857d963f7df0981ce43eef56/`.

**Creation and placement.**
- The five calls are `hv_gic_get_distributor_size`,
  `hv_gic_get_redistributor_size`, `hv_gic_config_create`,
  `hv_gic_config_set_{distributor,redistributor}_base` and `hv_gic_create`, in
  that order (`src/devices/src/legacy/hvfgicv3.rs` L76-108).
- The ordering is `hv_vm_create` (`src/hvf/src/lib.rs` L301, via
  `src/libkrun/src/vmm/builder.rs` L829 → L2092), then the GIC
  (`builder.rs` L1175), then `hv_vcpu_create` on each vCPU's own thread
  (`lib.rs` L396 from `vstate.rs` L443). This is the order `hv_gic.h` requires.
- Placement comes from libkrun's own board layout: the GIC sits directly below
  its MMIO start `0x0a00_0000`, and the redistributor region is sized for
  exactly `vcpu_count` (`hvfgicv3.rs` L88-90; `src/arch/src/aarch64/layout.rs`
  L89). Each VMM chooses its own window. Carrick's (D6, Task 4) comes from
  Carrick's IPA map, not from any board.
- libkrun does not call the alignment getters, the MSI configuration or
  `hv_gic_get_spi_interrupt_range`. `hv_gic.h` documents the alignment getters,
  and Carrick keeps them (Task 5 `GicGeometry::fits_window`).
- If a symbol or call fails, libkrun falls back to its userspace GIC
  (`builder.rs` L1173-1178). It resolves the symbols with `dlsym` so the binary
  still loads on macOS 14.
- Geometry on the planning host, read once with a stand-alone C query (not
  from libkrun), agrees with Fact 11: distributor 0x10000, one redistributor
  0x20000, region 0x2000000 (256 redistributors), both alignments 0x10000, MSI
  region 0x10000, SPI range base 32, count 988.

**Per-vCPU setup.**
- Right after `hv_vcpu_create`, on the owning thread, libkrun writes
  `MPIDR_EL1` = the CPU index in Aff0 (`lib.rs` L406-411, value from
  `vstate.rs` L291). The code comment there says Aff1; it is stale since
  commit 98520ef.
- libkrun never calls `hv_gic_get_redistributor_base`. The guest finds its
  redistributor by scanning the region.
- The VMM writes no redistributor or ICC register: there is no
  `hv_gic_set_redistributor_reg` or `hv_gic_set_icc_reg`. The guest's Linux
  GICv3 driver programs everything.

**Device interrupts.**
- `set_irq` calls `hv_gic_set_spi(intid, true)` and nothing else
  (`hvfgicv3.rs` L130-150). INTIDs are absolute and allocated from 32
  (`layout.rs` L75-78). The devices are described as edge-rising in the FDT,
  except pl031, which is level.
- `hv_gic.h` says a `true` level also produces an edge, and a `false` level on
  an edge interrupt is ignored.
- The VMM writes no distributor register (no `hv_gic_set_distributor_reg`).
  Group, priority, routing (`GICD_IROUTER`), enables and `GICD_CTLR` are all
  programmed by the guest through the distributor's MMIO frame.
- libkrun does not kick a vCPU after `hv_gic_set_spi`: HVF delivers the
  interrupt to a running vCPU by itself.
- **What the scheduler spike did differently** (`c9897ae4c`,
  `hvf_el1_sched_probe.rs` L1025-1057): it programmed the distributor from the
  host with `hv_gic_set_distributor_reg` right after `hv_gic_create`, before any
  vCPU existed, and never touched the distributor's MMIO frame from the guest.
  libkrun, whose SPIs work, never uses host-side distributor writes. The data
  does not show which difference mattered, so this plan records it as a
  hypothesis, not a finding. 1a needs no SPI (D4). Whoever next needs one
  starts from the reference shape: the guest (Carrick's EL1) programs the
  distributor through MMIO, and the host calls `hv_gic_set_spi(intid, true)`.

**Kicks and exits.**
- libkrun uses `hv_vcpus_exit` to stop a running vCPU (`lib.rs` L181-190). It
  calls it from `Vmm::pause` (`src/libkrun/src/vmm/mod.rs` L266-270) and, on the
  userspace-GIC path only, from IRQ injection (`src/devices/src/legacy/vcpu.rs`
  L45-47).
- `HV_EXIT_REASON_CANCELED` is a no-op exit, after which the loop checks for a
  pause (`vstate.rs` L370-373, L469).
- libkrun has no deferred, per-vCPU interrupt of the kind Carrick's `OwedKick`
  needs (a kick that must surface at the next EL0 boundary, not in the middle of
  an EL1 critical section). That need is Carrick's alone; see D1.

**vCPU lifecycle and scale.**
- Each vCPU has one host thread for the VM's life (`vstate.rs` L338-346,
  L442-443). Nothing calls `hv_vcpu_destroy` or `hv_vm_destroy`. The
  generated `src/hvf/src/bindings.rs` declares both, and nothing else in
  `src` names them.
- libkrun runs one VM per process (HVF allows no more), with `vcpu_count`
  defaulting to 1 (`vmm_config/machine_config.rs` L35, L47).
- `hv_gic.h`: "Once the virtual machine vcpus are running, its topology is
  considered final. Destroy vcpus only when you are tearing down the virtual
  machine." Carrick adopts the same lifecycle (D2, Task 2) instead of testing
  what happens when it is violated.

**Not exercised by libkrun, so Carrick checks it itself (Task 1):**
- the owed-kick vehicle (C2);
- `hv_vcpus_exit` with several vCPUs under a GIC, in Carrick's EL1/EL0 states
  (C1);
- many concurrent processes, each with its own GIC VM (C3).

libkrun has no GIC state save or restore at this commit. `bindings.rs` declares
`hv_gic_state_*` and `hv_gic_set_state` (L4530-4612), but nothing calls them.
1a needs none.

**Headers, directly** (macOS 27 SDK):
- `hv_gic_set_spi`, `hv_gic_{get,set}_distributor_reg` and `hv_gic_send_msi`
  carry no owning-thread requirement.
- Redistributor, ICC, ICH and ICV register accessors "Must be called by the
  owning thread".
- `hv_vcpu_{get,set}_pending_interrupt` return `HV_UNSUPPORTED` once the VM has
  a GIC.
- `hv_vcpus_exit` on a vCPU that is not running makes its next `hv_vcpu_run`
  return at once.
- `hv_vcpu_get_wait_for_interrupt_time` (macOS 27) exists only with a GIC,
  which suggests in-kernel WFI parking. 1c is the increment that relies on
  parking, and qualifies it.

---

## Facts this plan is built on (re-checked in code on 2026-09-24)

Each fact names where it was verified. A worker who finds one false stops and
reports; the plan is not valid under a different fact.

1. **The pause fix has landed.** `director/fault-pause-deadline` was rebased onto
   main as `c245596fe` (kick delivery at the EL0 boundary), `4eaf06af5`, `fdb75f7ac`
   (contracts `kernel.mm.pt-pause-drain-acknowledgement`,
   `kernel.vcpu.kick-el0-boundary`), `854eeff8b`, `08c239bf4`, `3dd2fdcb3`,
   `b91d830ec`. This plan builds on its names: `crate::trap::HVF_VIRTUAL_IRQ`
   (trap.rs:6090), `carrick_aarch64::owed_kick::OwedKick`
   (`absorb`/`rearm`/`settle`), `Aarch64Vcpu::set_pending_irq` and
   `Aarch64Vcpu::injects_kick_irq` (carrick-aarch64/src/vmm.rs:307,315), the three
   set-pending sites (trap.rs:7381 arm in `run_to_exit`, trap.rs:7552 clear on the
   `hvc #4` exit, hvf_aarch64_engine.rs:453 inside `set_pending_irq` at 451), and the test
   `trap::virtual_irq_line_tests::kick_irq_asserts_the_sdk_irq_line`.
2. **The SDK forbids the legacy kick vehicle under a GIC.** Xcode SDK
   `Hypervisor.framework/Headers/hv_vcpu.h`: `hv_vcpu_get_pending_interrupt` and
   `hv_vcpu_set_pending_interrupt` "Returns HV_UNSUPPORTED if the VM was created
   with a GIC device (hv_gic_create)". The same header says pending interrupts
   set this way are cleared on every `hv_vcpu_run` return; GIC redistributor
   pending state is not (Task 1 C2 checks that).
3. **GIC ordering and topology rules** (`hv_gic.h`): `hv_gic_create` only after
   `hv_vm_create` and before any `hv_vcpu_create`; one GIC per VM; affinity
   routing, so each vCPU sets `MPIDR_EL1`; `hv_gic_get_redistributor_base` only
   after MPIDR is set; "Once the virtual machine vcpus are running, its topology
   is considered final. Destroy vcpus only when you are tearing down the virtual
   machine." Redistributor registers and ICC registers are set "by the owning
   thread". There is no host API for `GICR_WAKER` or `GICR_CTLR`
   (`hv_gic_redistributor_reg_t` has TYPER, PIDR2, IGROUPR0, I[SC]ENABLER0,
   I[SC]PENDR0, I[SC]ACTIVER0, IPRIORITYR0-7, ICFGR0-1 only).
4. **Production today:** one VM-creation funnel `create_vm_with_admission`
   (trap.rs:776) returning `VirtualMachineInstance<GicDisabled>` from
   `VirtualMachine::with_config`; two vCPU wrappers `create_vcpu_with_permit` and
   `create_vcpu` (trap/vcpu_admission.rs:892,915) are the only `vm.vcpu_create()`
   callers; nine call sites reach them (trap.rs:6610, mapping_plan.rs:492/494,
   cow_engine.rs:3689, execve_rebuild.rs:1265, persistent_executor.rs:1008, 1058,
   1192, 1450, 1617). No production code sets `MPIDR_EL1`, touches `CNTV_*`, or
   handles `VTIMER_ACTIVATED` (any non-EXCEPTION, non-CANCELED exit is
   `TrapError::UnexpectedExit`, trap.rs:7449).
5. **vCPU destroy sites, and which ones the default HVPatch lane reaches**
   (code map of 2026-09-24; the decision is D2, Task 2).
   - **Reached: the initial-runner park.** It runs on every root boot:
     `launch_persistent_hvpatch_job` (binding.rs:5059) →
     `prepare_initial_runner_handoff` → `save_initial_runner_state`
     (binding.rs:5381-5383) → `initial_runner_park` (persistent_executor.rs:970-996,
     raw `hv_vcpu_destroy` at 982). For the first root this happens before any
     executor vCPU exists, and the boot vCPU never runs. For a later root in a
     reused carrier (carrier.rs:12; boot vCPU created in the live VM at
     mapping_plan.rs:389-497) it destroys a vCPU while pool vCPUs run: a
     mid-life destroy.
   - **Reached: `destroy_vcpu_on_thread_exit`** (persistent_executor.rs:1358),
     called from `HvpatchPersistentExecutor::destroy` (executor/backend.rs:1010-1060)
     when a worker leaves at pool shutdown (teardown) or after a worker fault
     (`retire_failed_worker`, executor.rs:188-214), which is mid-life.
   - **Reached only on error paths:** the boot vCPU's local-RAII rollback
     (`SetupVcpuGuard` `LocalRaii`, carrier_custody.rs:313-329, chosen at
     mapping_plan.rs:489-500), the boot-vCPU error destroy
     (threaded_loop.rs:361), and creation rollback (carrier_custody.rs:110/154;
     whole VM).
   - **No runtime caller** (only HVF engine overrides and trait default
     forwarders):
     - `reclaim_park`/`reclaim_resume` (persistent_executor.rs:944-1070);
     - `release_vm_after_reclaim_park`;
     - `shared_wait_park`/`shared_wait_resume`;
     - `initial_runner_resume`;
     - execve's mature rebuild (execve_rebuild.rs:1243-1256; the lane takes the
       persistent branch at :1072);
     - `HvfVmState::add_vcpu` (cow_engine.rs:3686-3697);
     - `from_process_spec` (trap.rs:6606-6610; HVPatch fork never calls
       `materialize_process`, quantum.rs:1410-1419).

     `CARRICK_HVF_VCPU_RECLAIM` (hvf_aarch64_engine.rs:85-98) now only switches
     the executor budget between the clamp and `usize::MAX`.
   - **Pool workers**, spares included, are all spawned and initialised at pool
     start (pool.rs:1206-1262). No idle shrink exists.
   - **Reporting.** Six of the raw destroys report through
     `trap::vcpu_destroyed(vcpu_id)` (trap.rs:881). The Drop-based ones
     (applevisor-1.0.0 vcpu.rs:157-161: `add_vcpu`'s mailbox failure,
     `from_process_spec`'s error returns, the local-RAII rollback) report
     inconsistently or not at all.
   - HVF vCPU ids are small integers that a later `hv_vcpu_create` can reuse.
6. **Guest EL0 cannot park in HVF.** `SCTLR_EL1_BOOTSTRAP = 0x0400_d005`
   (carrick-mem/src/arch_sysregs.rs:72) leaves `nTWI`(16) and `nTWE`(18) clear, so
   an EL0 `wfi`/`wfe` traps to EL1. `CNTKCTL_EL1` is programmed to
   `EL0VCTEN|EL0PCTEN` only (trap.rs:875), so EL0 cannot program the virtual
   timer. Carrick's EL1 code contains no `wfi`.
7. **Guest memory map** (carrick-mem/src/memory.rs, vdso.rs, carrick-el1-abi):
   Rosetta IPA `0x10_0000_0000`+2 MiB; alias IPA `0x18_0000_0000..0x28_0000_0000`;
   info page `0x2c_ffff_0000`; kernel region `0x2D_0000_0000`+2 MiB; EL1 region
   `0x2D_0400_0000`+64 MiB; **vvar/vDSO/clock stub at `0x2E_0000_0000`**; sigreturn
   trampoline `0x30_0000_0000`; heap `0x40_0000_0000`; mmap `0x60_0000_0000`;
   PIE base `0x88_0000_0000`; interpreter `0x8C_0000_0000`; shared file
   `0x90_0000_0000`; overlay `0x98_0000_0000`; HVPatch root slots and global
   frames `0x9A_0000_0000..0xFE_0000_0000`; stack top `0xff_ffff_0000`. The VM is
   created at the host's maximum IPA size (vcpu_admission.rs:802), at least 40
   bits (memory.rs asserts `LINUX_HVPATCH_RESERVED_END <= 1 << 40`).
8. **EL1 entry shape.** The syscall hook (memory.rs:4378 `write_el1_vector_hook`)
   builds a `TrapFrame` (280 bytes, allocated 0x120) at the slot's EL1 stack top,
   calls the image entry through header offset 8, and on `Served` restores
   `SP_EL1`, `ELR_EL1`, `SPSR_EL1` from the frame and `eret`s. The current-EL SPx
   IRQ slot (0x280) is a bare `eret`; the lower-EL IRQ slot (0x480) is
   `hvc #4; eret`. The vector page is 16 KiB; the syscall hook starts at 0x1000.
9. **A latent kick hole on main (found while planning).** `OwedKick::absorb`
   clears `I` in the live `SPSR_EL1` when the kick lands in the EL1 image or in
   the vector hook, but the hook's served path then reloads `SPSR_EL1` from
   `TrapFrame.spsr` before `eret`, so a kick absorbed while an EL1-served syscall
   is in flight returns to EL0 with `I` still masked and waits for the next
   surfaced exit. A guest looping on EL1-served syscalls may never surface one.
   Task 0B measures it on the frozen base before any 1a code lands (gate D11);
   this plan closes the hole for GIC mode (the served-path IRQ window takes the
   still-pending kick). The `CARRICK_HVF_GIC=0` hatch keeps today's behaviour
   until 1c deletes the hatch.
10. **EL0 ID-register reads return the raw vCPU value.**
   `emulate_el0_sys64_read_inner` (cow_engine.rs:4251-4290) answers an EL0 MRS
   of `ID_AA64PFR0_EL1` and nine other ID registers with
   `vcpu.get_sys_reg(reg)`. Linux hides the GIC system-register field
   (`ID_AA64PFR0_EL1` bits 27:24) from EL0, so if HVF sets it once a GIC
   exists, every guest would see a change (Task 5 Step 8's probe measures it
   against the Docker oracle; D12).
11. **HVF geometry on the planning host** (read-only query, macOS 27.2 / M4):
   distributor 0x10000, redistributor region 0x2000000 of 0x20000 frames (256
   redistributors), alignment 0x10000, `hv_vm_get_max_vcpu_count` 64, maximum
   IPA 40 bits. The per-VM vCPU cap (64) is below the redistributor count, so
   D5's clamp is a no-op here. Task 5's `GicGeometry::query` re-reads the
   geometry at every GIC creation and fails closed if it does not fit the
   window. An independent query during the libkrun reading also reported SPI
   base 32, count 988, and an MSI region of 0x10000 ("Prior art").

---

## Key decisions

| # | Decision | Where decided |
|---|---|---|
| D0 | 1a depends on the landed pause fix and reuses its names; nothing from the branch is re-landed. | Fact 1 |
| D1 | Host kicks stay `hv_vcpus_exit` (the reference pattern). The interrupt a kicked vCPU owes at its next EL0 boundary (`OwedKick`) is SGI 15 made pending on the owning thread with `GICR_ISPENDR0` and withdrawn with `GICR_ICPENDR0`, including production's un-acknowledged `hvc #4` path. The reference device vehicle (`hv_gic_set_spi`) was considered and not adopted: a shared SPI per vCPU would need per-vCPU `GICD_IROUTER` routing and distributor programming that no reference does for this purpose. If C2 fails, STOP and replan from the reference injection path. `HVF_VIRTUAL_IRQ` survives only for the `CARRICK_HVF_GIC=0` hatch. | Task 1 C2 |
| D2 | Every vCPU is created before its VM's first run and destroyed only at VM teardown (`hv_gic.h`; libkrun does the same). The root boots from a snapshot built as data, the dead reclaim/shared-wait paths are deleted, a faulted worker keeps its vCPU until shutdown, and `gic::configure_new_vcpu` fails closed on a create after the generation's first run or first destroy. No mid-life recreate experiment. | Fact 5, Task 2, Task 5 |
| D3 | `hv_vcpus_exit` under a GIC: a smoke check (C1: 8 vCPUs, 1,000 rounds in each of three production states, hang detector). The only spike wedge in a reachable shape came from the ASID spike's deliberately broken no-save control; the scheduler spike's wake runs parked in WFI, which 1a never enters. Any wedge in C1 is a STOP. WFI liveness belongs to 1c. | Task 1 C1 |
| D4 | SPI: 1a uses no SPI and exposes no SPI API. The reference setup (the guest programs the distributor through MMIO; the host raises `hv_gic_set_spi(intid, true)`) and the spike's difference from it (host-side distributor writes before any vCPU existed) are recorded under "Prior art" as a hypothesis for whoever next needs an SPI. | Prior art |
| D5 | Per-carrier vCPU capacity is clamped to the GIC redistributor count read from the SDK at GIC creation. `hv_gic_create`'s `HV_NO_RESOURCES` joins the VM-creation park+retry. `GLOBAL_VCPU_CEILING` follows the C3 ceiling with a GIC (D5b). | Task 1 C3, Task 5 |
| D6 | GIC IPA window `0x2F_0000_0000..0x2F_1000_0000`: distributor at the base, redistributors at base + 16 MiB; refused by both the stage-2 map boundary and stage-1 publication. Carrick-specific: libkrun places its GIC from its own board layout, and Carrick has none. | Task 4 |
| D7 | MPIDR = `1<<31 \| (index/16)<<8 \| index%16`, lowest free index per VM generation (libkrun uses the index in Aff0; Carrick's layout keeps 1c's `ICC_SGI1R_EL1` TargetList able to address every vCPU). Under D2 an index is never reused within a generation; destroys are recorded under the GIC topology lock in the same critical section as `hv_vcpu_destroy`. | Tasks 2, 5 |
| D8 | EL1 takes GIC interrupts only in the served-syscall return window, opened before ELR/SPSR are reloaded from the TrapFrame; EL0 masking is unchanged. | Tasks 7, 9 |
| D9 | Opt-out hatch `CARRICK_HVF_GIC=0` (exact string), read once in `gic.rs`, restores today's VM, vector bytes and kick vehicle for bisection; the vector builder takes the IRQ mode as an argument from that one reader; 1c deletes it. | Tasks 5, 9 |
| D10 | The applevisor-sys IRQ/FIQ swap is corrected once, in a typed `HvfInterruptLine`, and a semgrep rule forbids the binding's variants anywhere else. | Task 3 |
| D11 | Fact 9 is decided on the frozen base before 1a code lands; a confirmed hang on main is reported at once as its own defect. | Task 0B |
| D12 | EL0 ID view: if a GIC changes an ID register EL0 can read, the EL0 view matches Linux (the `ID_AA64PFR0_EL1` GIC field reads 0), proven by a red-first probe against the Docker oracle in the production VM. | Task 5 Step 8 |

## Global constraints

- Red-first. Every behaviour change starts with a failing test run with the
  exact command shown; record the failing output in the commit body.
- No guest-visible change: guest EL0 PSTATE, sigframes, `sched_getcpu`, `MPIDR`
  reads from EL0 (still trapped and unchanged), EL0 ID-register reads (D12),
  every probe and LTP verdict. `just conformance-probes` and the `el1-gate` LTP
  set must be identical in verdicts to the base artifact's (Task 0 Step 4
  records them; Task 13 diffs them row by row).
- Do not widen budgets, add retries, raise timeouts, reduce concurrency or poll.
- One raw-API boundary: only `gic.rs` names `hv_gic_*`; only `interrupt.rs`
  names `InterruptType::{IRQ,FIQ}` or `hv_interrupt_type_t::*` (semgrep-enforced).
- KVM, bhyve and NVMM backends are not modified, and every shared crate this
  plan touches still compiles for them (Task 11 checks).
- Rule 0: guests run only from signed artifacts (`just build`, `just test-hvf`,
  `just test-embed`, `just el1-gate`). Never `just build` while a guest runs.
- Never run carrick and Docker concurrently; stamp `CARRICK_RUN_ID`; reap with
  `scripts/sudo/kill.sh <run-id>`.
- Commit style: `type(scope): subject`, body with Why / What / Verified, trailer
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never
  `--no-verify`, never `git stash`.
- After any rebase onto main: `just reconcile-inventories` on a clean tree, then
  `just lint-domains`.

## File map

| Path | Responsibility | Task |
|---|---|---|
| `fixtures/linux-aarch64-hello/src/el1_served_loop_kick.rs` (new), `crates/carrick-embed/tests/el1_kick_served_loop.rs` (new), `tests/common/mod.rs`, `tests/el1_files.rs` | Fact 9 on the base; shared embed watchdog | 0B |
| `crates/carrick-vmm-hvf/tests/gic_qual/harness.rs`, `tests/gic_qualification.rs` (new) | Signed checks C1 (`hv_vcpus_exit` smoke) and C2 (owed-kick vehicle) on a reference-setup GIC, with their own guest blob | 1 |
| `crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs` | C3: `concurrent-ceiling` with a GIC per VM | 1 |
| `docs/perf-results/2026-09-25-hvf-gic-qualification.md` (new) | Fact 9 on main, the reference setup, C1-C3 results, the vCPU lifecycle evidence and the D1-D12 decisions | 0B, 1, 2, 8, 13 |
| `crates/carrick-vmm-hvf/src/trap/persistent_executor.rs`, `hvf_aarch64_engine.rs`, `trap/mapping_plan.rs`, `crates/carrick-runtime/src/vcpu_loop/{binding.rs, executor.rs, threaded_loop.rs}`, `crates/carrick-vmm-hvf/tests/initial_runner_handoff.rs` (deleted) | vCPUs live for the VM's life: root boot from a snapshot built as data, reclaim/shared-wait paths and the `CARRICK_HVF_VCPU_RECLAIM` hatch deleted, a faulted worker keeps its vCPU until shutdown | 2 |
| `crates/carrick-vmm-hvf/src/trap/cow_engine.rs` | `add_vcpu` error path destroys through `destroy_raw_vcpu` (2); EL0 ID view sanitised (5) | 2, 5 |
| `crates/carrick-vmm-hvf/src/interrupt.rs` (new) | `HvfInterruptLine`: the one correction of the binding's IRQ/FIQ swap | 3 |
| `.semgrep/typed-domains.yml` | Rule `hvf-interrupt-line-outside-boundary` | 3 |
| `crates/carrick-mem/src/memory.rs`, `memory/el1_clock.rs` | `LINUX_GIC_*` window constants, non-overlap asserts, vector bytes (IRQ hook, served-path window, kick tail) with the IRQ mode as an explicit argument | 4, 9 |
| `crates/carrick-mem/src/page_table.rs` | Stage-1 publication refuses outputs in the GIC window | 4 |
| `crates/carrick-vmm-hvf/src/trap/stage2_backend.rs` | Stage-2 map refuses the GIC window | 4 |
| `crates/carrick-runtime/src/runtime.rs` | Passes the carrier's IRQ mode to the vector builder | 9 |
| `conformance-probes/src/bin/idaa64pfr0.rs` (new), probe lists | EL0 view of `ID_AA64PFR0_EL1` against the Docker oracle (D12) | 5 |
| `crates/carrick-vmm-hvf/src/gic.rs` (new) | Geometry, placement, `CarrierGic`, `MpidrAllocator`, vCPU configuration, the D2 lifecycle guard (topology sealed at first run, destroys recorded under the lock), kick vehicle, interrupt model and IRQ mode, vtimer probe | 5, 6, 8 |
| `crates/carrick-vmm-hvf/src/trap.rs`, `trap/vcpu_admission.rs`, `trap/persistent_executor.rs`, `trap/execve_rebuild.rs`, `trap/carrier_custody.rs`, `trap/vcpu_gate.rs` | Teardown-class destroy sites, GIC in VM creation, vCPU creation/destroy, VM release, capacity, first-run seal, kick sites, exit counting | 2, 5, 6, 8 |
| `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs` | `set_pending_irq` through the owed-kick vehicle | 2, 6 |
| `crates/carrick-aarch64/src/owed_kick.rs` | Doc update for the GIC vehicle; GIC-semantics model test | 6 |
| `crates/carrick-el1-abi/src/lib.rs` | Shared INTIDs, `TrapFrame.kick`, `IrqFrame`, header v3, IRQ counters, host-exit counters | 5, 7 |
| `crates/carrick-el1/src/irq.rs` (new), `src/entry.rs`, `link.ld`, `src/lib.rs` | `classify_intid`, `carrick_el1_irq` | 7 |
| `crates/carrick-el1-image/build.rs` | Forbid `wfi`/`wfe` in the EL1 image | 7 |
| `crates/carrick-runtime/src/lib.rs`, `crates/carrick-embed/src/lib.rs` | Re-export the vtimer probe and topology diagnostics | 8 |
| `fixtures/linux-aarch64-hello/src/el1_vtimer_loop.rs` (new), `scripts/build-linux-fixtures.sh` | Guest fixture | 8 |
| `crates/carrick-embed/tests/el1_gic.rs` (new) | Signed embed tests | 8 |
| `conformance-contracts/contracts/{gic-topology,el1-gic-vtimer,kick-el0-boundary}.toml`, `surfaces.toml`, `inventory.json` | Contracts | 5, 6, 10 |
| `scripts/migrate/runtime-global-state.json`, `scripts/migrate/runtime-aborts/hvf.json` | Ledger rows for the new statics; the D2 guard's `carrick_fatal!` site | 5, 8 |
| `justfile` | `el1-gate` runs the fixtures build, each GIC check (C1 states, C2) in its own process and a three-arm inotify09 screen | 12 |
| `docs/superpowers/specs/2026-09-24-el1-kernel.md`, `AGENTS.md`, `docs/hal.md` | Record outcomes, the HVF GIC rules, the backend note | 11 |

---

### Task 0: Preconditions and the base artifact

**Files:** none modified. Produces `target/el1-1a-base/` (untracked).

**Interfaces:**
- Consumes: main at or after `b91d830ec`.
- Produces: `target/el1-1a-base/carrick` (signed base binary for paired runs),
  `target/el1-1a-base/artifact.txt` (source HEAD, SHA-256, CDHash, LC_UUID,
  entitlement, `__dof_carrick`), `target/el1-1a-base/ltp.jsonl` and
  `target/el1-1a-base/probes.log` (the base verdicts Task 13 diffs against).

- [ ] **Step 1: Confirm the pause fix is an ancestor and the tree is clean**

```bash
cd /Volumes/CaseSensitive/carrick/.worktrees/el1-inotify-r5
git merge-base --is-ancestor c245596fe HEAD && echo PAUSE_FIX_PRESENT
git status --short | wc -l
grep -n "pub(crate) const HVF_VIRTUAL_IRQ" crates/carrick-vmm-hvf/src/trap.rs
grep -n "pub struct OwedKick" crates/carrick-aarch64/src/owed_kick.rs
```

Expected: `PAUSE_FIX_PRESENT`, `0`, one line each for the two greps. If the
ancestor check fails, STOP: this plan's kick work is written against those names.

- [ ] **Step 2: Build and freeze the base artifact**

No guest may be running (`just build` replaces the binary under it).

```bash
just build
mkdir -p target/el1-1a-base
cp target/release/carrick target/el1-1a-base/carrick
{
  echo "head $(git rev-parse HEAD)"
  echo "sha256 $(shasum -a 256 target/el1-1a-base/carrick | cut -d' ' -f1)"
  codesign -dvvv target/el1-1a-base/carrick 2>&1 | grep -i 'CDHash='
  otool -l target/el1-1a-base/carrick | grep -A2 LC_UUID | grep uuid
  codesign -d --entitlements - target/el1-1a-base/carrick 2>/dev/null | grep -a -o 'com.apple.security.hypervisor'
  otool -l target/el1-1a-base/carrick | grep -q __dof_carrick && echo "dof present"
} | tee target/el1-1a-base/artifact.txt
```

Expected: six lines ending in `dof present`. Copying preserves the signature;
never re-sign the copy (re-signing changes CDHash).

- [ ] **Step 3: Confirm the toolchain pieces**

```bash
rustup target list --installed | grep -x aarch64-unknown-none-softfloat
rustup target list --installed | grep -x aarch64-unknown-linux-musl
ls conformance-probes/target/aarch64-unknown-linux-musl/release | head -1
ls conformance-probes/target/aarch64-unknown-linux-gnu/release | head -1
```

Expected: both targets listed and both probe directories non-empty (the
`el1-gate` recipe refuses to start otherwise).

- [ ] **Step 4: Record the base verdicts that "no guest-visible change" is measured against**

Carrick only; no Docker VM busy. The probe gate runs in-process from this
(base) tree's signed test executables; the LTP set runs the frozen binary.

```bash
just --no-deps conformance-probes 2>&1 | tee target/el1-1a-base/probes.log | tail -5
suites=$(grep -oE 'name = "ltp-(inotify|fanotify|read|write|lseek|pread|pwrite|fstat|stat|dup|close|open|fsync|ftruncate|truncate|creat)[0-9a-z_]*"' scripts/conformance/suites.toml | sed 's/name = //; s/"//g; s/^/--suite /' | tr '\n' ' ')
cargo run -q -p carrick-conformance -- --tier full $suites \
  --carrick-bin target/el1-1a-base/carrick --jsonl target/el1-1a-base/ltp.jsonl
```

Expected: the probe gate green; `ltp.jsonl` has one row per suite. The suite
selection is the `el1-gate` recipe's, so Task 13 compares like with like.

No commit.

---

### Task 0B: Fact 9 on the base artifact (decides D11)

Fact 9 (a kick absorbed during an EL1-served syscall waits for a surfaced exit
that a served loop may never produce) is a claim about main, independent of the
GIC. It is measured here, on the frozen base, before any 1a code lands. The
answer decides D11: whether main has a live hang to report now, and what the
red-first evidence for Task 9's kick tail is. The kick tail itself is required
in GIC mode either way: once the served path opens an IRQ window, the window
acknowledges the kick SGI, so EL1 must surface it or the kick is lost.

**Files:**
- Create: `fixtures/linux-aarch64-hello/src/el1_served_loop_kick.rs`
- Modify: `scripts/build-linux-fixtures.sh`
- Modify: `crates/carrick-embed/tests/common/mod.rs` (move `Watchdog` here from `el1_files.rs`),
  `crates/carrick-embed/tests/el1_files.rs`
- Create: `crates/carrick-embed/tests/el1_kick_served_loop.rs`
- Create: `docs/perf-results/2026-09-25-hvf-gic-qualification.md` (section "Fact 9 on main")

**Interfaces:**
- Produces: signed test `el1_served_loop_surfaces_kicks`; `common::Watchdog`
  (`pub fn start(Duration) -> Watchdog`, `pub fn disarm(self)`); fixture
  `carrick-linux-aarch64-el1-served-loop-kick`; the D11 verdict.

- [ ] **Step 1: The served-loop kick fixture**

`scripts/build-linux-fixtures.sh` emits one object with `rustc --emit=obj` and
links it with `rust-lld -static` and no `core`/`compiler_builtins`, so the
fixture may use nothing that lowers to a runtime call: no atomic
read-modify-write (outline atomics call `__aarch64_ldadd8_relax`) and no
runtime slice indexing (`panic_bounds_check`). Every counter below has one
writer and uses `load`/`store`; every buffer access is a volatile raw-pointer
access.

Create `fixtures/linux-aarch64-hello/src/el1_served_loop_kick.rs`:

```rust
//! EL1 plan 1a (Fact 9): a sibling looping on EL1-served lseek must not stall
//! a stage-1 page-table drain. The main thread runs 200 mmap/touch/munmap
//! cycles; each pauses the MM, which kicks the sibling once and waits for its
//! acknowledgement with no deadline (carrick-kernel mm_quiesce.rs). A kick
//! absorbed during the sibling's EL1-served syscall must still surface.
//!
//! No runtime dependencies (the fixture build links no core/compiler_builtins):
//! single-writer counters use load/store, never fetch_add, and buffers are
//! written through raw pointers, never indexed.
#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::{exit, syscall1, syscall2, syscall3, syscall4, syscall6};
use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const SYS_OPENAT: u64 = 56;
const SYS_LSEEK: u64 = 62;
const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_EXIT_GROUP: u64 = 94;
const SYS_CLOCK_GETTIME: u64 = 113;
const SYS_MUNMAP: u64 = 215;
const SYS_CLONE: u64 = 220;
const SYS_MMAP: u64 = 222;
const AT_FDCWD: u64 = (-100_i64) as u64;
const O_RDWR_CREAT_TRUNC: u64 = 0o2 | 0o100 | 0o1000;
const PROT_RW: u64 = 0x3;
const MAP_PRIVATE_ANON: u64 = 0x02 | 0x20;
// CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM
const CLONE_THREAD_FLAGS: u64 = 0x50f00;
const CLOCK_MONOTONIC: u64 = 1;
const STACK_SIZE: u64 = 64 * 1024;
const CYCLES: u64 = 200;
const SPIN_LIMIT: u64 = 1 << 34;

const RUNNING: u32 = 1;
const STOP: u32 = 2;
const STOPPED: u32 = 3;

struct Shared {
    fd: AtomicU64,
    state: AtomicU32,
    /// Written only by the worker thread.
    served: AtomicU64,
}

static SHARED: Shared = Shared {
    fd: AtomicU64::new(0),
    state: AtomicU32::new(0),
    served: AtomicU64::new(0),
};
static PATH: [u8; 26] = *b"/tmp/el1_served_loop_kick\0";
static PREFIX: [u8; 24] = *b"served loop kick max_ns=";

extern "C" fn worker() -> ! {
    let fd = SHARED.fd.load(Ordering::Acquire);
    SHARED.state.store(RUNNING, Ordering::Release);
    while SHARED.state.load(Ordering::Acquire) == RUNNING {
        unsafe { syscall3(SYS_LSEEK, fd, 0, 0) };
        let served = SHARED.served.load(Ordering::Relaxed);
        SHARED.served.store(served + 1, Ordering::Release);
    }
    SHARED.state.store(STOPPED, Ordering::Release);
    unsafe { syscall1(SYS_EXIT, 0) };
    loop {
        core::hint::spin_loop();
    }
}

unsafe fn clone_thread(sp: u64) -> i64 {
    let ret: i64;
    let entry = worker as *const () as u64;
    unsafe {
        asm!(
            "mov x0, {flags}",
            "mov x1, {sp}",
            "mov x2, #0",
            "mov x3, #0",
            "mov x4, #0",
            "mov x8, {sys_clone}",
            "svc #0",
            "cmp x0, #0",
            "b.ne 1f",
            "blr {entry}",
            "1:",
            flags = in(reg) CLONE_THREAD_FLAGS,
            sp = in(reg) sp,
            sys_clone = const SYS_CLONE,
            entry = in(reg) entry,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

fn now_ns() -> u64 {
    let mut ts = [0u64; 2];
    unsafe { syscall2(SYS_CLOCK_GETTIME, CLOCK_MONOTONIC, ts.as_mut_ptr() as u64) };
    ts[0] * 1_000_000_000 + ts[1]
}

fn spin_until(done: impl Fn() -> bool, code: u64) {
    let mut spins = 0u64;
    while !done() {
        spins += 1;
        if spins > SPIN_LIMIT {
            exit(code);
        }
        core::hint::spin_loop();
    }
}

fn print_line(value: u64) {
    let mut buf = [0u8; 48];
    let mut digits = [0u8; 20];
    let out = buf.as_mut_ptr();
    let tmp = digits.as_mut_ptr();
    let mut len = 0usize;
    unsafe {
        while len < PREFIX.len() {
            write_volatile(out.add(len), read_volatile(PREFIX.as_ptr().add(len)));
            len += 1;
        }
        let (mut n, mut v) = (0usize, value);
        loop {
            write_volatile(tmp.add(n), b'0' + (v % 10) as u8);
            n += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        while n > 0 {
            n -= 1;
            write_volatile(out.add(len), read_volatile(tmp.add(n)));
            len += 1;
        }
        write_volatile(out.add(len), b'\n');
        len += 1;
        syscall3(SYS_WRITE, 1, out as u64, len as u64);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, O_RDWR_CREAT_TRUNC, 0o600);
        if fd < 0 {
            exit(10);
        }
        if syscall3(SYS_WRITE, fd as u64, PATH.as_ptr() as u64, 1) != 1 {
            exit(11);
        }
        SHARED.fd.store(fd as u64, Ordering::Release);
        let stack = syscall6(SYS_MMAP, 0, STACK_SIZE, PROT_RW, MAP_PRIVATE_ANON, u64::MAX, 0);
        if stack < 0 {
            exit(12);
        }
        if clone_thread((stack as u64 + STACK_SIZE) & !0xf) < 0 {
            exit(13);
        }
        spin_until(|| SHARED.served.load(Ordering::Acquire) >= 10_000, 14);
        let mut slowest = 0u64;
        for _ in 0..CYCLES {
            let start = now_ns();
            let page = syscall6(SYS_MMAP, 0, 0x4000, PROT_RW, MAP_PRIVATE_ANON, u64::MAX, 0);
            if page < 0 {
                exit(15);
            }
            write_volatile(page as *mut u64, 1);
            if syscall2(SYS_MUNMAP, page as u64, 0x4000) != 0 {
                exit(16);
            }
            slowest = slowest.max(now_ns() - start);
        }
        SHARED.state.store(STOP, Ordering::Release);
        spin_until(|| SHARED.state.load(Ordering::Acquire) == STOPPED, 17);
        print_line(slowest);
        syscall1(SYS_EXIT_GROUP, 0);
        exit(0);
    }
}
```

Add to `scripts/build-linux-fixtures.sh` after the `discard_fork_threads` line:

```bash
build_fixture "el1_served_loop_kick.rs" "carrick-linux-aarch64-el1-served-loop-kick"
```

```bash
scripts/build-linux-fixtures.sh
ls -l fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-el1-served-loop-kick
```

Expected: the script links the fixture (a `rust-lld` "undefined symbol" error
means a runtime call slipped in: remove it, never add a runtime library) and
the binary exists.

- [ ] **Step 2: Share the embed watchdog**

Move `struct Watchdog` and its two `impl` blocks verbatim from
`crates/carrick-embed/tests/el1_files.rs` into `crates/carrick-embed/tests/common/mod.rs`,
make the struct and its `start`/`disarm` `pub`, replace `common::run_id()` /
`common::repo_root()` inside it with `run_id()` / `repo_root()`, and change
`el1_files.rs` to use `common::Watchdog`. `common/mod.rs` already carries
`#![allow(dead_code, ...)]`, so other test binaries that include it stay clean.

```bash
cargo check -p carrick-embed --tests
```

- [ ] **Step 3: The signed test**

Create `crates/carrick-embed/tests/el1_kick_served_loop.rs`:

```rust
//! Fact 9 of EL1 plan 1a, measured on main before the GIC lands, and kept as
//! the signed binding of `kernel.vcpu.kick-el0-boundary` for EL1-served loops.
//!
//! Run ONLY through `just test-embed el1_served_loop_surfaces_kicks`
//! (scripts/test-signed.sh) after `scripts/build-linux-fixtures.sh`: HV_DENIED
//! is a failure, never a skip. Runs alone: a watchdog reap kills the test
//! executable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use carrick_embed::{Carrier, EmbedError, PullPolicy, read_el1_counters, reset_el1_counters};

const SYS_LSEEK: usize = 62;

fn carrier_or_fail() -> Carrier {
    for _ in 0..50 {
        match Carrier::new() {
            Ok(carrier) => return carrier,
            Err(EmbedError::Entitlement) => panic!(
                "HV_DENIED (0xfae94007): run through scripts/test-signed.sh; a bare cargo test cannot boot a guest"
            ),
            Err(EmbedError::CarrierAlreadyActive) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("carrier initialization failed: {error}"),
        }
    }
    panic!("carrier initialization timed out waiting for a prior carrier to retire");
}

/// Contract `kernel.vcpu.kick-el0-boundary`: a sibling looping on EL1-served
/// syscalls surfaces every page-table drain kick; the drain (which kicks once
/// and waits with no deadline) completes. The watchdog bounds the red case.
#[test]
fn el1_served_loop_surfaces_kicks() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let path = common::repo_root().join(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-el1-served-loop-kick",
    );
    assert!(path.exists(), "{}: run scripts/build-linux-fixtures.sh first", path.display());
    let dir = path.parent().expect("fixture dir").to_string_lossy().into_owned();
    let carrier = carrier_or_fail();
    let watchdog = common::Watchdog::start(Duration::from_secs(60));
    let result = common::run_or_fail(
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/p/carrick-linux-aarch64-el1-served-loop-kick".to_owned()])
            .mount_readonly(dir, "/p")
            .run_blocking(),
    );
    watchdog.disarm();
    let stdout = result.stdout_utf8();
    println!("el1-served-loop-kick {stdout}");
    assert!(result.success(), "exit {} signal {:?}", result.exit_code, result.signal);
    assert!(stdout.starts_with("served loop kick max_ns="), "{stdout:?}");
    let counters = read_el1_counters().expect("EL1 counters");
    assert!(counters.served[SYS_LSEEK].load(Ordering::Relaxed) >= 10_000);
    drop(carrier);
}
```

- [ ] **Step 4: Run it on the base, three times, and decide D11**

The tree is still the base source (Steps 1-3 add a fixture and a test only), so
the signed binary `just test-embed` builds carries base code; confirm by
comparing `shasum -a 256 target/release/carrick` with
`target/el1-1a-base/artifact.txt` (equal: the tree compiles the same binary;
CDHash may differ after the re-sign, which is expected).

```bash
for round in 1 2 3; do
  just test-embed el1_served_loop_surfaces_kicks --nocapture 2>&1 | tee target/el1-1a-base/fact9-$round.log
done
grep -a 'el1-served-loop-kick\|test el1_served\|WATCHDOG\|panicked' target/el1-1a-base/fact9-*.log
```

**Gate D11** (exactly one row applies; three runs, because a verdict that
differs between runs is itself a finding):

| Result | Decision |
|---|---|
| Watchdog fires in 3/3 | Fact 9 confirmed on main. Report it now as its own defect (outside this plan's fence; the `CARRICK_HVF_GIC=0` hatch keeps it). This test is Task 9's signed red-first evidence. Commit it with `#[ignore = "Fact 9 (EL1 plan 1a D11): red on main until Task 9's served-path IRQ window"]` so the `el1_` filter of Tasks 5-8 and `el1-gate` stay meaningful; run it with `--include-ignored` until Task 9 deletes the attribute. |
| Passes in 3/3 | Fact 9 refuted for this workload. Keep the test, not ignored, as a regression binding. Task 9's red-first evidence for the kick tail is its VM-free machine test (a kick taken in the window must leave through `hvc #4`). |
| Mixed | A load-dependent verdict: record the three outcomes, treat Fact 9 as confirmed (report it, and ignore the test as in the first row), and add a `hvpatch-pt-pause-drain-stall.d` capture of one failing run to the report. |

Create `docs/perf-results/2026-09-25-hvf-gic-qualification.md` with a
"Fact 9 on main" section: base artifact identity (from
`target/el1-1a-base/artifact.txt`), the three outcomes with `max_ns` or the
watchdog line, and the D11 row.

- [ ] **Step 5: Commit**

```bash
just fmt-check
cargo clippy -p carrick-embed --all-targets -- -D warnings
git add fixtures/linux-aarch64-hello/src/el1_served_loop_kick.rs scripts/build-linux-fixtures.sh \
  crates/carrick-embed/tests/common/mod.rs crates/carrick-embed/tests/el1_files.rs \
  crates/carrick-embed/tests/el1_kick_served_loop.rs docs/perf-results/2026-09-25-hvf-gic-qualification.md
git commit -F- <<'MSG'
test(el1): measure kick surfacing while a sibling loops on EL1 syscalls

Why: a stage-1 page-table drain kicks every sibling once and waits
without a deadline. A kick absorbed while a sibling is inside an
EL1-served syscall is re-armed, but the served path reloads SPSR_EL1
from the TrapFrame, so the sibling may return to EL0 with IRQs masked
and never surface the kick (Fact 9 of EL1 plan 1a).

What: fixture el1_served_loop_kick (a lseek sibling beside 200
mmap/touch/munmap drains; no runtime dependencies) and the signed test
el1_served_loop_surfaces_kicks with a 60 s watchdog; the embed
watchdog moves to tests/common.

Verified: three runs on the frozen base artifact: <D11 outcome>.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

Replace `<D11 outcome>` with the row that applied before committing.

---

### Task 1: Reference setup and the Carrick-specific GIC checks (decides D1, D3, D5b)

**Reference setup (adopted, not re-proven).** 1a creates and configures the
GIC the way libkrun does and `hv_gic.h` prescribes (see "Prior art"):
- `hv_gic_config_create`, both bases, then `hv_gic_create` right after
  `hv_vm_create`, before any vCPU;
- one vCPU per host thread for the VM's life;
- `MPIDR_EL1` written on the owning thread before anything touches the vCPU's
  redistributor;
- `hv_vcpus_exit` to stop a running vCPU.

Carrick differs from libkrun in three places, each for a Carrick reason:
- **Placement.** The window comes from Carrick's IPA map (D6), not from a
  board layout.
- **MPIDR layout.** Aff1 = i/16, Aff0 = i%16 (D7), so plan 1c's
  `ICC_SGI1R_EL1` TargetList can address every vCPU.
- **Who configures the GIC.** There is no Linux GIC driver in the guest, so the
  host writes what that driver would: `GICD_CTLR`, and per vCPU the
  redistributor and ICC registers on the owning thread (Task 5). Both spikes
  ran the vtimer PPI with `GICD_CTLR` and the redistributor programmed from
  the host (`c9897ae4c`, `25f6e2f4e`; the ASID spike also wrote the ICC
  registers from the host).

These properties are checked where they live, not in a separate harness:
- ordering and placement, by the VM-free source tests of Task 5;
- vtimer delivery to EL1, by Task 8's red and Task 9's green signed test in the
  production VM;
- the EL0 ID view, by Task 5 Step 8's probe against the Docker oracle.

**What is checked here** is only what no reference VMM exercises and 1a relies
on:

| Check | Why no reference covers it | Decides |
|---|---|---|
| **C1**: `hv_vcpus_exit` smoke under a GIC, 8 vCPUs, production-reachable EL1/EL0 states | libkrun kicks only to pause; Carrick kicks siblings on every page-table drain | D3 |
| **C2**: the owed-kick vehicle, SGI 15 via `GICR_ISPENDR0` on the owning thread, including production's un-acknowledged `hvc #4` exit | No reference VMM defers a kick to the next EL0 boundary | D1 |
| **C3**: many concurrent processes, each with a GIC VM | libkrun runs one small VM; Carrick's gates run many carriers at once | D5b |

Dropped, and why:
- **The vtimer-to-EL1 experiment (old E0).** It is the standard use of the
  device, and 1a's own signed test proves it in production (Tasks 8-9).
- **The SPI matrix (old E4).** 1a uses no SPI; the reference setup is recorded
  under "Prior art".
- **The cost experiment (old E6).** Exit cost is measured where it matters, in
  Task 13's paired runs against the base artifact.
- **The capacity and placement experiment (old E5).** The geometry is read
  from the SDK at every GIC creation and checked against the window, failing
  closed (Task 5). The clamp is arithmetic on those reads.
- **The mid-life recreate experiment (old E3).** It is designed out (D2,
  Task 2): Carrick keeps every vCPU for its VM's life, as libkrun does and
  `hv_gic.h` asks.
- **The WFI liveness states.** 1a never enters in-HVF WFI (Fact 6; Task 7
  Step 5's image ban). Parking and its wake liveness belong to plan 1c, which
  qualifies them.

The only wedge the spikes attributed to `hv_vcpus_exit` under a GIC was the
ASID spike's deliberately broken no-save negative control (`25f6e2f4e`: "A
handler that does not save ELR/SPSR before a nested fault ERETs to EL0 at 0
(3/3) or wedges"). The scheduler spike's failed wake runs parked the target in
in-HVF `wfi` (`c9897ae4c`, `gic-wfi-hvc-*` modes), a state 1a never enters.
C1 is therefore a smoke check with a hang detector, not a hypothesis test.

Verdicts are semantic events, never rates. The only time bounds are hang
detectors (AGENTS.md: bound every wait).

**Files:**
- Create: `crates/carrick-vmm-hvf/tests/gic_qual/harness.rs` (shared harness, `include!`d)
- Create: `crates/carrick-vmm-hvf/tests/gic_qualification.rs` (C1, C2)
- Modify: `crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs` (C3: `concurrent-ceiling` with a GIC)
- Modify: `docs/perf-results/2026-09-25-hvf-gic-qualification.md`

**Interfaces:**
- Consumes: `applevisor_sys` raw `hv_vm_*`, `hv_vcpu_*`, `hv_gic_*`;
  `libc::mmap`; `carrick_host::clock::monotonic_ticks`.
- Produces (recorded decisions, consumed by Tasks 5-6): the C2 verdict for
  SGI 15 (D1), the C1 verdict per state (D3), and the C3 VM ceilings with and
  without a GIC (D5b).

Reference code (read, do not copy blindly): `spike/el1-scheduler` `c9897ae4c`
`crates/carrick-vmm-hvf/src/bin/hvf_el1_sched_probe.rs` lines 975-1080
(`create_gic`) and 1244-1320 (`setup_vcpu`).

HVF allows one VM per process, and a wedge leaks it, so each check runs in its
own process (`just test-hvf gic_qualification_c<N>`, and one `el1-gate` step
per check).

- [ ] **Step 1: Write the harness (guest blob, VM, vCPU helpers)**

Create `crates/carrick-vmm-hvf/tests/gic_qual/harness.rs`. It lives in a
subdirectory without `main.rs`, so cargo does not build it as a test target.

```rust
// Harness of the HVF GIC checks of EL1 plan 1a (C1, C2). The GIC is set up
// the reference way (libkrun, hv_gic.h): created after hv_vm_create and before
// any vCPU, MPIDR written on the owning thread before any redistributor
// access, one host thread per vCPU for the VM's life. Carrick's host-side
// writes of what a guest GIC driver would program (GICD_CTLR, GICR, ICC)
// mirror Task 5. Results are printed as `C<n> {json}` lines and recorded in
// docs/perf-results/2026-09-25-hvf-gic-qualification.md.

use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use applevisor_sys::*;

static SERIAL: Mutex<()> = Mutex::new(());

const HV_UNSUPPORTED: hv_return_t = 0xfae9_400f_u32 as hv_return_t;
/// The SDK's HV_INTERRUPT_TYPE_IRQ (hv_vcpu_types.h: IRQ = 0). applevisor-sys
/// 1.0.0 declares `hv_interrupt_type_t { FIQ, IRQ }`, so the SDK IRQ line is the
/// binding's `FIQ` variant. Task 3 replaces this line with the typed
/// `carrick_vmm_hvf::interrupt::HvfInterruptLine`.
const SDK_IRQ: hv_interrupt_type_t = hv_interrupt_type_t::FIQ;

const RAM_IPA: u64 = 0x4000_0000;
const RAM_SIZE: usize = 4 << 20;
const L1_OFF: u64 = 0x8000;
const L2_OFF: u64 = 0x9000;
const BLOCKS_OFF: u64 = 0x20_0000;
const BLOCK_SIZE: u64 = 0x1000;
const MAX_BLOCKS: usize = 16;
// Per-vCPU data block; the guest asm below uses the same offsets. The guest's
// IRQ handler also stores the last acknowledged INTID at 0x08.
const B_HEARTBEAT: u64 = 0x00;
const B_MODE: u64 = 0x20;
const B_VTIMER_PERIOD: u64 = 0x30;
const B_COUNTS: u64 = 0x40; // [u64; 64] by INTID
const MODE_SPIN_UNMASKED: u64 = 0;
const MODE_SPIN_MASKED: u64 = 1;
const HVC_BAD_VECTOR: u64 = 0x1c;
/// Production's lower-EL IRQ slot exits with `hvc #4` (Fact 8).
const HVC_EL0_KICK: u64 = 0x4;
const EC_HVC64: u64 = 0x16;
const PSTATE_EL1H_MASKED: u64 = 0x3c5;
const PSTATE_EL0T_UNMASKED: u64 = 0x000;
/// Carrick's production EL0 state: EL0t with DAIF masked.
const PSTATE_EL0T_MASKED: u64 = 0x3c0;
const PSTATE_I: u64 = 1 << 7;
/// SCTLR_EL1: RES1 bits | M | C | I (identity map below, Normal WB memory).
const SCTLR: u64 = 0x30D0_1805;
/// TCR_EL1: T0SZ=25, IRGN0/ORGN0 WB, SH0 inner, TG0 4K, EPD1, IPS 40-bit.
const TCR: u64 = 0x2_0080_3519;
const MAIR: u64 = 0xff;
/// Production placement (Task 4 promotes these to carrick-mem).
const GIC_DIST_IPA: u64 = 0x2F_0000_0000;
const GIC_REDIST_IPA: u64 = 0x2F_0100_0000;
const GIC_WINDOW_END: u64 = 0x2F_1000_0000;
/// Affinity routing + group 1 enable, as Task 5 writes it.
const GICD_CTLR_ARE_GRP1: u64 = 0x12;
const VTIMER_INTID: u32 = 27;
const KICK_SGI: u32 = 15;
const ALL_PRIVATE: u64 = 0xffff_ffff;

std::arch::global_asm!(
    ".text",
    ".p2align 11",
    ".globl _gq_start",
    "_gq_start:",
    // 0x000-0x180: current EL with SP0 (never used)
    "hvc #0x1c", "b .", ".p2align 7",
    "hvc #0x1c", "b .", ".p2align 7",
    "hvc #0x1c", "b .", ".p2align 7",
    "hvc #0x1c", "b .", ".p2align 7",
    "hvc #0x1c", "b .", ".p2align 7", // 0x200 current EL SPx sync
    "b Lgq_irq", ".p2align 7",        // 0x280 current EL SPx IRQ
    "hvc #0x1c", "b .", ".p2align 7", // 0x300 FIQ
    "hvc #0x1c", "b .", ".p2align 7", // 0x380 SError
    "hvc #0x1c", "b .", ".p2align 7", // 0x400 lower-EL sync
    "b Lgq_irq", ".p2align 7",        // 0x480 lower-EL IRQ
    "hvc #0x1c", "b .", ".p2align 7", // 0x500
    "hvc #0x1c", "b .", ".p2align 7", // 0x580
    "hvc #0x1c", "b .", ".p2align 7", // 0x600
    "hvc #0x1c", "b .", ".p2align 7", // 0x680
    "hvc #0x1c", "b .", ".p2align 7", // 0x700
    "hvc #0x1c", "b .", ".p2align 7", // 0x780
    // IRQ handler: acknowledge, count by INTID, re-arm a periodic vtimer,
    // complete. TPIDR_EL1 = this vCPU's data block, SP_EL1 = its top.
    "Lgq_irq:",
    "stp x9, x10, [sp, #-16]!",
    "stp x11, x12, [sp, #-16]!",
    "mrs x9, tpidr_el1",
    "mrs x10, S3_0_C12_C12_0", // ICC_IAR1_EL1
    "str x10, [x9, #0x08]",
    "cmp x10, #1023",
    "b.eq Lgq_irq_out",
    "cmp x10, #27",
    "b.ne Lgq_irq_count",
    "msr cntv_ctl_el0, xzr",
    "ldr x11, [x9, #0x30]",
    "cbz x11, Lgq_irq_count",
    "mrs x12, cntvct_el0",
    "add x12, x12, x11",
    "msr cntv_cval_el0, x12",
    "mov x11, #1",
    "msr cntv_ctl_el0, x11",
    "Lgq_irq_count:",
    "cmp x10, #64",
    "b.hs Lgq_irq_eoi",
    "add x11, x9, #0x40",
    "ldr x12, [x11, x10, lsl #3]",
    "add x12, x12, #1",
    "str x12, [x11, x10, lsl #3]",
    "Lgq_irq_eoi:",
    "msr S3_0_C12_C12_1, x10", // ICC_EOIR1_EL1
    "Lgq_irq_out:",
    "ldp x11, x12, [sp], #16",
    "ldp x9, x10, [sp], #16",
    "eret",
    // EL1 entry: x9 = block; the mode word selects masked or unmasked spin.
    ".p2align 7",
    ".globl _gq_main",
    "_gq_main:",
    "mrs x9, tpidr_el1",
    "ldr x10, [x9, #0x20]",
    "cmp x10, #1",
    "b.eq Lgq_masked",
    "msr daifclr, #2",
    "Lgq_spin:",
    "ldr x11, [x9]",
    "add x11, x11, #1",
    "str x11, [x9]",
    "b Lgq_spin",
    "Lgq_masked:",
    "msr daifset, #2",
    "b Lgq_spin",
    // EL0 entry: the host sets x9 = block and the EL0t PSTATE.
    ".globl _gq_el0_spin",
    "_gq_el0_spin:",
    "ldr x11, [x9]",
    "add x11, x11, #1",
    "str x11, [x9]",
    "b _gq_el0_spin",
    // Production-shaped vector table: identical except the lower-EL IRQ slot,
    // which is Carrick's `hvc #4; eret` (no acknowledge; the host withdraws
    // the kick and resumes at ELR_EL1/SPSR_EL1).
    ".p2align 11",
    ".globl _gq_vectors_el0_hvc4",
    "_gq_vectors_el0_hvc4:",
    "hvc #0x1c", "b .", ".p2align 7", // 0x000
    "hvc #0x1c", "b .", ".p2align 7", // 0x080
    "hvc #0x1c", "b .", ".p2align 7", // 0x100
    "hvc #0x1c", "b .", ".p2align 7", // 0x180
    "hvc #0x1c", "b .", ".p2align 7", // 0x200
    "b Lgq_irq", ".p2align 7",        // 0x280
    "hvc #0x1c", "b .", ".p2align 7", // 0x300
    "hvc #0x1c", "b .", ".p2align 7", // 0x380
    "hvc #0x1c", "b .", ".p2align 7", // 0x400
    "hvc #4", "eret", ".p2align 7",   // 0x480 lower-EL IRQ, production shape
    "hvc #0x1c", "b .", ".p2align 7", // 0x500
    "hvc #0x1c", "b .", ".p2align 7", // 0x580
    "hvc #0x1c", "b .", ".p2align 7", // 0x600
    "hvc #0x1c", "b .", ".p2align 7", // 0x680
    "hvc #0x1c", "b .", ".p2align 7", // 0x700
    "hvc #0x1c", "b .", ".p2align 7", // 0x780
    ".globl _gq_end",
    "_gq_end:",
);

unsafe extern "C" {
    static gq_start: u8;
    static gq_main: u8;
    static gq_el0_spin: u8;
    static gq_vectors_el0_hvc4: u8;
    static gq_end: u8;
}

fn guest_ipa(symbol: *const u8) -> u64 {
    RAM_IPA + (symbol as u64 - ptr::addr_of!(gq_start) as u64)
}

fn check(rc: hv_return_t, what: &str) {
    assert_eq!(rc, 0, "{what}: rc={:#x}", rc as u32);
}

/// Reference creation (hv_gic.h; libkrun hvfgicv3.rs L76-108): size queries,
/// config, both bases, `hv_gic_create` after `hv_vm_create` and before any
/// vCPU. Carrick additionally checks the documented alignments and writes the
/// GICD_CTLR a guest driver would (Task 5 does the same).
fn create_gic() {
    let (mut ds, mut da, mut rr, mut ra) = (0usize, 0usize, 0usize, 0usize);
    unsafe {
        check(hv_gic_get_distributor_size(&mut ds), "distributor size");
        check(hv_gic_get_distributor_base_alignment(&mut da), "distributor alignment");
        check(hv_gic_get_redistributor_region_size(&mut rr), "redistributor region");
        check(hv_gic_get_redistributor_base_alignment(&mut ra), "redistributor alignment");
    }
    assert!(GIC_DIST_IPA.is_multiple_of(da as u64), "distributor alignment {da:#x}");
    assert!(GIC_DIST_IPA + ds as u64 <= GIC_REDIST_IPA, "distributor size {ds:#x}");
    assert!(GIC_REDIST_IPA.is_multiple_of(ra as u64), "redistributor alignment {ra:#x}");
    assert!(GIC_REDIST_IPA + rr as u64 <= GIC_WINDOW_END, "redistributor region {rr:#x}");
    let mut vtimer_intid = 0u32;
    unsafe {
        let config = hv_gic_config_create();
        assert!(!config.is_null(), "hv_gic_config_create");
        check(hv_gic_config_set_distributor_base(config, GIC_DIST_IPA), "distributor base");
        check(hv_gic_config_set_redistributor_base(config, GIC_REDIST_IPA), "redistributor base");
        check(hv_gic_create(config), "hv_gic_create");
        os_release(config);
        check(
            hv_gic_get_intid(hv_gic_intid_t::EL1_VIRTUAL_TIMER, &mut vtimer_intid),
            "vtimer intid",
        );
        check(
            hv_gic_set_distributor_reg(hv_gic_distributor_reg_t::CTLR, GICD_CTLR_ARE_GRP1),
            "GICD_CTLR",
        );
    }
    assert_eq!(vtimer_intid, VTIMER_INTID, "HVF EL1 virtual timer INTID");
}

struct Vm {
    host: *mut u8,
}

unsafe impl Send for Vm {}
unsafe impl Sync for Vm {}

impl Vm {
    fn create() -> Vm {
        unsafe {
            let config = hv_vm_config_create();
            let mut max_ipa = 0u32;
            check(hv_vm_config_get_max_ipa_size(&mut max_ipa), "max ipa");
            check(hv_vm_config_set_ipa_size(config, max_ipa), "set ipa");
            check(hv_vm_create(config), "hv_vm_create");
            os_release(config.cast());
        }
        create_gic();
        let host = unsafe {
            libc::mmap(
                ptr::null_mut(),
                RAM_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(host, libc::MAP_FAILED, "guest RAM mmap");
        let vm = Vm { host: host.cast() };
        vm.install_guest();
        unsafe {
            check(
                hv_vm_map(host, RAM_IPA, RAM_SIZE, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC),
                "hv_vm_map",
            );
        }
        vm
    }

    fn install_guest(&self) {
        let start = ptr::addr_of!(gq_start) as usize;
        let end = ptr::addr_of!(gq_end) as usize;
        assert!(end - start <= L1_OFF as usize, "guest blob overlaps the page tables");
        unsafe { ptr::copy_nonoverlapping(start as *const u8, self.host, end - start) };
        // L1[1] (VA 0x4000_0000..0x8000_0000) -> L2. L2[0]: code + tables,
        // read-only at EL1 and EL0, executable. L2[1]: data blocks, RW at both
        // ELs, PXN|UXN. Normal WB (MAIR attr 0), inner shareable, AF set.
        self.write(L1_OFF + 8, (RAM_IPA + L2_OFF) | 0b11);
        self.write(L2_OFF, RAM_IPA | (1 << 10) | (3 << 8) | (0b11 << 6) | 0b01);
        self.write(
            L2_OFF + 8,
            (RAM_IPA + BLOCKS_OFF) | (1 << 54) | (1 << 53) | (1 << 10) | (3 << 8) | (0b01 << 6) | 0b01,
        );
    }

    fn write(&self, offset: u64, value: u64) {
        unsafe { ptr::write_volatile(self.host.add(offset as usize).cast::<u64>(), value) }
    }

    fn read(&self, offset: u64) -> u64 {
        unsafe { ptr::read_volatile(self.host.add(offset as usize).cast::<u64>()) }
    }

    fn block_offset(block: usize) -> u64 {
        assert!(block < MAX_BLOCKS);
        BLOCKS_OFF + block as u64 * BLOCK_SIZE
    }

    fn block_read(&self, block: usize, field: u64) -> u64 {
        self.read(Self::block_offset(block) + field)
    }

    fn block_write(&self, block: usize, field: u64, value: u64) {
        self.write(Self::block_offset(block) + field, value)
    }

    fn count(&self, block: usize, intid: u32) -> u64 {
        self.block_read(block, B_COUNTS + u64::from(intid) * 8)
    }

    /// Destroy the VM. Every vCPU must already be destroyed on its own thread,
    /// at teardown only (hv_gic.h; D2).
    fn destroy(self) {
        unsafe {
            check(hv_vm_unmap(RAM_IPA, RAM_SIZE), "hv_vm_unmap");
            check(hv_vm_destroy(), "hv_vm_destroy");
            libc::munmap(self.host.cast(), RAM_SIZE);
        }
    }
}

/// Task 5's MPIDR layout (D7).
fn mpidr(index: u16) -> u64 {
    (1 << 31) | ((u64::from(index) / 16) << 8) | (u64::from(index) % 16)
}

#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    canceled: u64,
    bad_vector: u64,
    other_exception: u64,
    other_reason: u64,
}

struct Vcpu {
    id: hv_vcpu_t,
    exit: *const hv_vcpu_exit_t,
}

impl Vcpu {
    /// Create on the calling (owning) thread, write MPIDR first, then the
    /// minimal EL1 state and the redistributor/CPU interface for `enable`,
    /// as Task 5's `configure_new_vcpu` does. Zeroes the vCPU's data block.
    fn create(vm: &Vm, block: usize, mpidr_index: u16, enable: &[u32]) -> Vcpu {
        let (mut id, mut exit) = (0, ptr::null());
        unsafe { check(hv_vcpu_create(&mut id, &mut exit, ptr::null_mut()), "hv_vcpu_create") };
        let vcpu = Vcpu { id, exit };
        vcpu.set_sys(hv_sys_reg_t::MPIDR_EL1, mpidr(mpidr_index));
        vcpu.set_sys(hv_sys_reg_t::VBAR_EL1, RAM_IPA);
        vcpu.set_sys(hv_sys_reg_t::MAIR_EL1, MAIR);
        vcpu.set_sys(hv_sys_reg_t::TCR_EL1, TCR);
        vcpu.set_sys(hv_sys_reg_t::TTBR0_EL1, RAM_IPA + L1_OFF);
        vcpu.set_sys(hv_sys_reg_t::SCTLR_EL1, SCTLR);
        vcpu.set_sys(hv_sys_reg_t::SP_EL1, RAM_IPA + Vm::block_offset(block) + BLOCK_SIZE);
        vcpu.set_sys(hv_sys_reg_t::TPIDR_EL1, RAM_IPA + Vm::block_offset(block));
        vcpu.set_sys(hv_sys_reg_t::CNTV_CTL_EL0, 0);
        for field in (0..BLOCK_SIZE / 2).step_by(8) {
            vm.block_write(block, field, 0);
        }
        vcpu.gic_enable(enable);
        vcpu
    }

    fn redistributor_reg(&self, reg: hv_gic_redistributor_reg_t) -> u64 {
        let mut value = 0u64;
        unsafe { check(hv_gic_get_redistributor_reg(self.id, reg, &mut value), "GICR read") };
        value
    }

    fn set_redistributor_reg(&self, reg: hv_gic_redistributor_reg_t, value: u64) {
        unsafe { check(hv_gic_set_redistributor_reg(self.id, reg, value), "GICR write") }
    }

    /// Task 5's `configure_new_vcpu`, minus the affinity allocator.
    fn gic_enable(&self, intids: &[u32]) {
        use hv_gic_redistributor_reg_t as R;
        let mask = intids.iter().fold(0u64, |mask, intid| mask | (1 << intid));
        self.set_redistributor_reg(R::ICENABLER0, ALL_PRIVATE & !mask);
        self.set_redistributor_reg(R::ICPENDR0, ALL_PRIVATE);
        self.set_redistributor_reg(R::ICACTIVER0, ALL_PRIVATE);
        self.set_redistributor_reg(R::IGROUPR0, mask);
        for &intid in intids {
            self.set_priority(intid, 0x80);
        }
        self.set_redistributor_reg(R::ISENABLER0, mask);
        unsafe {
            check(hv_gic_set_icc_reg(self.id, hv_gic_icc_reg_t::PMR_EL1, 0xf0), "ICC_PMR_EL1");
            check(hv_gic_set_icc_reg(self.id, hv_gic_icc_reg_t::IGRPEN1_EL1, 1), "ICC_IGRPEN1_EL1");
        }
    }

    fn set_priority(&self, intid: u32, priority: u8) {
        use hv_gic_redistributor_reg_t as R;
        let reg = match intid / 4 {
            0 => R::IPRIORITYR0,
            1 => R::IPRIORITYR1,
            2 => R::IPRIORITYR2,
            3 => R::IPRIORITYR3,
            4 => R::IPRIORITYR4,
            5 => R::IPRIORITYR5,
            6 => R::IPRIORITYR6,
            7 => R::IPRIORITYR7,
            _ => panic!("private INTID {intid} out of range"),
        };
        let shift = (intid % 4) * 8;
        let value = (self.redistributor_reg(reg) & !(0xff << shift)) | (u64::from(priority) << shift);
        self.set_redistributor_reg(reg, value);
    }

    fn set_sys(&self, reg: hv_sys_reg_t, value: u64) {
        unsafe { check(hv_vcpu_set_sys_reg(self.id, reg, value), "hv_vcpu_set_sys_reg") }
    }

    fn get_sys(&self, reg: hv_sys_reg_t) -> u64 {
        let mut value = 0;
        unsafe { check(hv_vcpu_get_sys_reg(self.id, reg, &mut value), "hv_vcpu_get_sys_reg") };
        value
    }

    fn set(&self, reg: hv_reg_t, value: u64) {
        unsafe { check(hv_vcpu_set_reg(self.id, reg, value), "hv_vcpu_set_reg") }
    }

    fn enter_el1(&self, vm: &Vm, block: usize, mode: u64) {
        vm.block_write(block, B_MODE, mode);
        self.set(hv_reg_t::PC, guest_ipa(ptr::addr_of!(gq_main)));
        self.set(hv_reg_t::CPSR, PSTATE_EL1H_MASKED);
    }

    fn enter_el0(&self, block: usize, masked: bool) {
        self.set(hv_reg_t::X9, RAM_IPA + Vm::block_offset(block));
        self.set(hv_reg_t::PC, guest_ipa(ptr::addr_of!(gq_el0_spin)));
        self.set(hv_reg_t::CPSR, if masked { PSTATE_EL0T_MASKED } else { PSTATE_EL0T_UNMASKED });
    }

    /// Periodic vtimer every `period_ticks`, first expiry one period ahead.
    fn arm_vtimer(&self, vm: &Vm, block: usize, period_ticks: u64) {
        let mut offset = 0;
        unsafe { check(hv_vcpu_get_vtimer_offset(self.id, &mut offset), "vtimer offset") };
        vm.block_write(block, B_VTIMER_PERIOD, period_ticks);
        let now = carrick_host::clock::monotonic_ticks() - offset;
        self.set_sys(hv_sys_reg_t::CNTV_CVAL_EL0, now + period_ticks);
        self.set_sys(hv_sys_reg_t::CNTV_CTL_EL0, 1);
    }

    fn pending(&self, intid: u32) -> bool {
        self.redistributor_reg(hv_gic_redistributor_reg_t::ISPENDR0) & (1 << intid) != 0
    }

    fn set_pending(&self, intid: u32) {
        self.set_redistributor_reg(hv_gic_redistributor_reg_t::ISPENDR0, 1 << intid);
    }

    fn clear_pending(&self, intid: u32) {
        self.set_redistributor_reg(hv_gic_redistributor_reg_t::ICPENDR0, 1 << intid);
    }

    /// Run until a CANCELED exit or any other exit; every exit ends the call.
    fn run_until_canceled(&self) -> Tally {
        let mut tally = Tally::default();
        unsafe { check(hv_vcpu_run(self.id), "hv_vcpu_run") };
        let exit = unsafe { &*self.exit };
        match exit.reason {
            hv_exit_reason_t::CANCELED => tally.canceled += 1,
            hv_exit_reason_t::EXCEPTION
                if exit.exception.syndrome >> 26 == EC_HVC64
                    && exit.exception.syndrome & 0xffff == HVC_BAD_VECTOR =>
            {
                tally.bad_vector += 1
            }
            hv_exit_reason_t::EXCEPTION => tally.other_exception += 1,
            _ => tally.other_reason += 1,
        }
        tally
    }

    /// Only at teardown, on the owning thread (D2).
    fn destroy(self) {
        unsafe { check(hv_vcpu_destroy(self.id), "hv_vcpu_destroy") }
    }
}

/// Production's kick: one `hv_vcpus_exit` call per vCPU (vcpu_kick.rs, per-handle kick).
fn kick(id: hv_vcpu_t) {
    unsafe { check(hv_vcpus_exit(&id, 1), "hv_vcpus_exit") }
}

fn kick_after(id: hv_vcpu_t, after: Duration) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(after);
        kick(id);
    })
}

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
```

Create `crates/carrick-vmm-hvf/tests/gic_qualification.rs`:

```rust
//! Hypervisor.framework in-kernel GIC checks for EL1 plan 1a (Task 1): only
//! what no reference VMM exercises (C1 hv_vcpus_exit under a GIC in Carrick's
//! states, C2 the owed-kick vehicle). The GIC setup itself follows libkrun and
//! hv_gic.h and is not re-proven here.
//!
//! Run ONLY through `just test-hvf gic_qualification_c<N> --nocapture`
//! (scripts/test-signed.sh), one check per process: an unsigned executable
//! gets HV_DENIED, which is a failure here, never a skip, and a wedge leaks
//! the process's one VM.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks
)]

include!("gic_qual/harness.rs");
```

`hv_vcpus_exit`'s first parameter is `*const hv_vcpu_t` in applevisor-sys 1.0.0
(production passes `ids.as_ptr()` in `vcpu_kick.rs`). If the compiler reports
`*mut`, use `ptr::addr_of!(id).cast_mut()`.

- [ ] **Step 2: C2, the owed-kick vehicle (decides D1)**

`OwedKick` needs an interrupt that is pending on one particular vCPU, is taken
at the next EL0 boundary, and can be withdrawn when some other exit surfaces
first. `hv_vcpus_exit` stays the kick itself, as in every VMM. The owed
interrupt cannot use the legacy line once a GIC exists: the SDK refuses it
(Fact 2).

The reference device vehicle, `hv_gic_set_spi`, does not fit here without
adding things no reference exercises. An SPI is a shared interrupt, so each
vCPU would need its own SPI, routed with `GICD_IROUTER` to its MPIDR and
re-routed whenever an index is reused. The distributor would have to be
programmed from the host, the path on which the scheduler spike's SPIs were
never delivered, or through MMIO from EL1, which needs a stage-1 mapping of the
distributor that Task 4 forbids. A private SGI made pending in the vCPU's own
redistributor avoids all of that, and it is written on the thread that already
absorbs the kick. This check proves that one shape and nothing else.

Append to `gic_qualification.rs`:

```rust
#[derive(Debug)]
struct KickOutcome {
    legacy_rc: hv_return_t,
    survives_run_return: bool,
    taken_at_el1: bool,
    el0_boundary_exits: u64,
    el0_boundary_withdrawn: bool,
    tallies: [Tally; 3],
}

/// Run with the production-shaped lower-EL IRQ slot (`hvc #4; eret`, no
/// acknowledge) until a CANCELED exit, servicing each `hvc #4` exactly as
/// trap.rs's kick exit does: withdraw the kick (GICR_ICPENDR0), resume at
/// ELR_EL1 with SPSR_EL1 and I clear (OwedKick::absorb's state). Returns the
/// number of `hvc #4` exits; more than one means the withdrawn, never
/// acknowledged interrupt was re-taken.
fn el0_boundary_kick_round(vcpu: &Vcpu) -> (u64, Tally) {
    let stop = kick_after(vcpu.id, Duration::from_millis(20));
    let mut tally = Tally::default();
    let mut boundary_exits = 0;
    loop {
        unsafe { check(hv_vcpu_run(vcpu.id), "hv_vcpu_run") };
        let exit = unsafe { &*vcpu.exit };
        match exit.reason {
            hv_exit_reason_t::CANCELED => {
                tally.canceled += 1;
                break;
            }
            hv_exit_reason_t::EXCEPTION
                if exit.exception.syndrome >> 26 == EC_HVC64
                    && exit.exception.syndrome & 0xffff == HVC_EL0_KICK =>
            {
                boundary_exits += 1;
                vcpu.clear_pending(KICK_SGI);
                vcpu.set(hv_reg_t::PC, vcpu.get_sys(hv_sys_reg_t::ELR_EL1));
                vcpu.set(hv_reg_t::CPSR, vcpu.get_sys(hv_sys_reg_t::SPSR_EL1) & !PSTATE_I);
                if boundary_exits > 100 {
                    tally.other_exception += 1; // a re-take loop, recorded
                    break;
                }
            }
            hv_exit_reason_t::EXCEPTION => {
                tally.other_exception += 1;
                break;
            }
            _ => {
                tally.other_reason += 1;
                break;
            }
        }
    }
    stop.join().expect("kicker");
    (boundary_exits, tally)
}

fn kick_round(vcpu: &Vcpu) -> Tally {
    let stop = kick_after(vcpu.id, Duration::from_millis(20));
    let tally = vcpu.run_until_canceled();
    stop.join().expect("kicker");
    tally
}

#[test]
fn gic_qualification_c2_owed_kick_vehicle() {
    let _serial = serial();
    let vm = Arc::new(Vm::create());
    let outcome = {
        let vm = Arc::clone(&vm);
        std::thread::spawn(move || {
            let vcpu = Vcpu::create(&vm, 0, 0, &[KICK_SGI]);
            // (a) Negative control: the legacy vehicle is refused under a GIC.
            let legacy_rc = unsafe { hv_vcpu_set_pending_interrupt(vcpu.id, SDK_IRQ, true) };
            // (b) Pending state survives an hv_vcpu_run return while masked
            // (the legacy line is cleared on every return; Fact 2).
            vcpu.enter_el1(&vm, 0, MODE_SPIN_MASKED);
            vcpu.set_pending(KICK_SGI);
            let t_b = kick_round(&vcpu);
            let survives_run_return = vcpu.pending(KICK_SGI) && vm.count(0, KICK_SGI) == 0;
            // (c) Taken and acknowledged at EL1 once unmasked (Task 9's window).
            vcpu.enter_el1(&vm, 0, MODE_SPIN_UNMASKED);
            let t_c = kick_round(&vcpu);
            let taken_at_el1 = vm.count(0, KICK_SGI) == 1 && !vcpu.pending(KICK_SGI);
            // (d) Production's EL0-boundary kick: signalled, never acknowledged,
            // withdrawn by the host, resumed with I clear. Exactly one hvc #4.
            vcpu.set_sys(hv_sys_reg_t::VBAR_EL1, guest_ipa(ptr::addr_of!(gq_vectors_el0_hvc4)));
            vcpu.enter_el0(0, false);
            vcpu.set_pending(KICK_SGI);
            let (el0_boundary_exits, t_d) = el0_boundary_kick_round(&vcpu);
            let el0_boundary_withdrawn = !vcpu.pending(KICK_SGI) && vm.count(0, KICK_SGI) == 1;
            vcpu.destroy(); // teardown
            KickOutcome {
                legacy_rc,
                survives_run_return,
                taken_at_el1,
                el0_boundary_exits,
                el0_boundary_withdrawn,
                tallies: [t_b, t_c, t_d],
            }
        })
        .join()
        .expect("vCPU thread")
    };
    println!("C2 {{\"outcome\":\"{outcome:?}\"}}");
    assert_eq!(outcome.legacy_rc, HV_UNSUPPORTED, "hv_vcpu_set_pending_interrupt under a GIC");
    for tally in &outcome.tallies {
        assert_eq!(
            (tally.canceled, tally.other_exception, tally.other_reason, tally.bad_vector),
            (1, 0, 0, 0),
            "{tally:?}"
        );
    }
    assert!(outcome.survives_run_return, "SGI 15 pending state lost on a run return: STOP at gate D1");
    assert!(outcome.taken_at_el1, "SGI 15 not taken at EL1: STOP at gate D1");
    assert_eq!(outcome.el0_boundary_exits, 1, "hvc #4 path re-took a withdrawn SGI: STOP at gate D1");
    assert!(outcome.el0_boundary_withdrawn, "GICR_ICPENDR0 did not withdraw the kick: STOP at gate D1");
    Arc::into_inner(vm).expect("sole VM handle").destroy();
}
```

Run:

```bash
just test-hvf gic_qualification_c2 --nocapture 2>&1 | tee target/gic-qual-c2.log
grep -a '^C2' target/gic-qual-c2.log
```

Expected: `ok` with one `C2` line, and the script's unentitled negative control
passing. A `HV_DENIED` means the executable was not signed: rerun through the
recipe, never bare `cargo test`. **Gate D1:** green means SGI 15 through
`GICR_ISPENDR0`/`ICPENDR0` is the owed-kick vehicle, and Tasks 5-6 use it. Red
in (b)-(d) means STOP and replan the vehicle from the reference injection path,
before any Task 5 code: a per-vCPU SPI routed by an EL1-programmed distributor
and raised with `hv_gic_set_spi(intid, true)`. Do not fall back to a different
private INTID without a new plan decision.

- [ ] **Step 3: C1, `hv_vcpus_exit` smoke under a GIC (decides D3)**

Eight vCPUs, as a page-table drain kicks every sibling. Each vCPU is kicked
with its own call, as production does. The states are the ones production
reaches: EL1 running with the vtimer firing at 100 us, EL1 masked, and EL0
masked with the kick SGI pending. 1,000 rounds per state. The only time bound
is a 5 s hang detector per round.

Append to `gic_qualification.rs`:

```rust
const SMOKE_VCPUS: usize = 8;
const SMOKE_ROUNDS: u64 = 1_000;
/// Hang detector, not a verdict rate.
const SMOKE_WEDGE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
enum SmokeState {
    El1SpinUnmaskedVtimer,
    El1SpinMasked,
    El0MaskedKickPending,
}

/// Printed through Debug in the `C1` lines.
#[allow(dead_code)]
#[derive(Debug)]
struct SmokeReport {
    state: SmokeState,
    rounds: u64,
    unexpected: u64,
    /// (round, vCPU index, heartbeat still advancing)
    wedge: Option<(u64, usize, bool)>,
}

fn smoke(state: SmokeState) -> SmokeReport {
    let vm = Arc::new(Vm::create());
    let canceled: Arc<Vec<AtomicU64>> = Arc::new((0..SMOKE_VCPUS).map(|_| AtomicU64::new(0)).collect());
    let unexpected = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let ids = Arc::new(Mutex::new(vec![0; SMOKE_VCPUS]));
    let ready = Arc::new(Barrier::new(SMOKE_VCPUS + 1));
    let owners: Vec<_> = (0..SMOKE_VCPUS)
        .map(|index| {
            let (vm, canceled, unexpected, stop, ids, ready) = (
                Arc::clone(&vm),
                Arc::clone(&canceled),
                Arc::clone(&unexpected),
                Arc::clone(&stop),
                Arc::clone(&ids),
                Arc::clone(&ready),
            );
            std::thread::spawn(move || {
                let vcpu = Vcpu::create(&vm, index, index as u16, &[VTIMER_INTID, KICK_SGI]);
                match state {
                    SmokeState::El1SpinUnmaskedVtimer => {
                        vcpu.enter_el1(&vm, index, MODE_SPIN_UNMASKED);
                        vcpu.arm_vtimer(&vm, index, 2_400);
                    }
                    SmokeState::El1SpinMasked => vcpu.enter_el1(&vm, index, MODE_SPIN_MASKED),
                    SmokeState::El0MaskedKickPending => {
                        vcpu.enter_el0(index, true);
                        vcpu.set_pending(KICK_SGI);
                    }
                }
                ids.lock().expect("ids")[index] = vcpu.id;
                ready.wait();
                loop {
                    let tally = vcpu.run_until_canceled();
                    if tally.canceled != 1 {
                        unexpected.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    canceled[index].fetch_add(1, Ordering::Release);
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                }
                vcpu.destroy(); // teardown
            })
        })
        .collect();
    ready.wait();
    let targets: Vec<hv_vcpu_t> = ids.lock().expect("ids").clone();
    let mut wedge = None;
    let mut rounds = 0;
    'rounds: while rounds < SMOKE_ROUNDS && unexpected.load(Ordering::Relaxed) == 0 {
        std::thread::sleep(Duration::from_micros(20));
        let want: Vec<u64> = canceled.iter().map(|c| c.load(Ordering::Acquire) + 1).collect();
        for &id in &targets {
            kick(id);
        }
        let sent = Instant::now();
        loop {
            let behind: Vec<usize> =
                (0..SMOKE_VCPUS).filter(|&i| canceled[i].load(Ordering::Acquire) < want[i]).collect();
            if behind.is_empty() {
                break;
            }
            if sent.elapsed() >= SMOKE_WEDGE {
                let index = behind[0];
                let h0 = vm.block_read(index, B_HEARTBEAT);
                std::thread::sleep(Duration::from_millis(100));
                wedge = Some((rounds, index, vm.block_read(index, B_HEARTBEAT) > h0));
                break 'rounds;
            }
            std::thread::yield_now();
        }
        rounds += 1;
    }
    stop.store(true, Ordering::Release);
    if wedge.is_none() {
        for &id in &targets {
            kick(id);
        }
        for owner in owners {
            owner.join().expect("owner thread");
        }
        Arc::into_inner(vm).expect("sole VM handle").destroy();
    } else {
        // A wedged owner cannot destroy its vCPU; leak the threads and the VM
        // (HVF allows one VM per process; this process creates no other).
        std::mem::forget(owners);
        std::mem::forget(vm);
    }
    SmokeReport { state, rounds, unexpected: unexpected.load(Ordering::Acquire), wedge }
}

#[test]
fn gic_qualification_c1_vcpus_exit_smoke_el1_vtimer() {
    let _serial = serial();
    let report = smoke(SmokeState::El1SpinUnmaskedVtimer);
    println!("C1 {{\"report\":\"{report:?}\"}}");
    assert!(report.wedge.is_none() && report.unexpected == 0 && report.rounds == SMOKE_ROUNDS, "STOP at gate D3: {report:?}");
}

#[test]
fn gic_qualification_c1_vcpus_exit_smoke_el1_masked() {
    let _serial = serial();
    let report = smoke(SmokeState::El1SpinMasked);
    println!("C1 {{\"report\":\"{report:?}\"}}");
    assert!(report.wedge.is_none() && report.unexpected == 0 && report.rounds == SMOKE_ROUNDS, "STOP at gate D3: {report:?}");
}

#[test]
fn gic_qualification_c1_vcpus_exit_smoke_el0_kick_pending() {
    let _serial = serial();
    let report = smoke(SmokeState::El0MaskedKickPending);
    println!("C1 {{\"report\":\"{report:?}\"}}");
    assert!(report.wedge.is_none() && report.unexpected == 0 && report.rounds == SMOKE_ROUNDS, "STOP at gate D3: {report:?}");
}
```

Each state is its own `#[test]`, so each runs in its own process, and a wedge in
one state cannot turn another red through the leaked VM:

```bash
for s in el1_vtimer el1_masked el0_kick_pending; do
  just test-hvf gic_qualification_c1_vcpus_exit_smoke_$s --nocapture 2>&1 | tee target/gic-qual-c1-$s.log
done
grep -a '^C1' target/gic-qual-c1-*.log
```

Expected: three `ok` results, each with one `C1` line and
`rounds: 1000, unexpected: 0, wedge: None`. **Gate D3:** any wedge means
STOP 1a. Keep the log, take a core of the test process
(`sudo lldb -p <pid> -o "process save-core target/gic-c1.core" -o detach`),
and report.

- [ ] **Step 4: C3, many concurrent processes each with a GIC VM (decides D5b)**

Carrick's soft pre-throttle (`GLOBAL_VCPU_CEILING = 120`, vcpu_admission.rs)
rests on 127 concurrent VMs measured without a GIC, and Carrick's gates run
many carriers at once. libkrun runs one small VM, so no reference covers this.
Extend the probe that measured the ceiling.

In `crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs`:
- add `hv_gic_config_create, hv_gic_config_set_distributor_base,
  hv_gic_config_set_redistributor_base, hv_gic_create` to the
  `use applevisor_sys::{...}` list;
- add the helper:

```rust
    /// Hypervisor.framework's in-kernel GIC at Carrick's production placement,
    /// created the reference way (EL1 plan 1a; Task 4 promotes the literals to
    /// carrick-mem constants).
    fn create_probe_gic() -> Result<(), hv_return_t> {
        unsafe {
            let config = hv_gic_config_create();
            if config.is_null() {
                return Err(HV_ERROR);
            }
            let mut rc = hv_gic_config_set_distributor_base(config, 0x2F_0000_0000);
            if rc == HV_SUCCESS {
                rc = hv_gic_config_set_redistributor_base(config, 0x2F_0100_0000);
            }
            if rc == HV_SUCCESS {
                rc = hv_gic_create(config);
            }
            os_release(config);
            if rc == HV_SUCCESS { Ok(()) } else { Err(rc) }
        }
    }
```

- `Vm::create()` becomes `Vm::create_with(with_gic: bool)`, calling
  `create_probe_gic()?` immediately after its `hv_vm_create` succeeds and before
  its `hv_vcpu_create`; `Vm::create()` stays as `Vm::create_with(false)` for
  the other cases;
- `create_vm_with_extras` gains `with_gic: bool` and calls
  `Vm::create_with(with_gic)`;
- the `"concurrent-ceiling"` arm parses `let with_gic = parse_u64_arg(&args, 5, 0) == 1;`
  and passes it through `concurrent_ceiling(max, hold_secs, vcpus_per_vm, map_mib, with_gic)`,
  which prints `with_gic={with_gic}` in its `case=` line; the usage line gains
  `[with_gic 0|1]`.

Run on a quiet host: no guest, no Docker VM, and nothing else using
Hypervisor.framework. This creates about 127 VMs; the July 2026 measurement ran
the same probe.

```bash
cargo build --release -p carrick-vmm-hvf --bin hvf_fork_probe
codesign --force --sign - --entitlements scripts/entitlements.plist target/release/hvf_fork_probe
target/release/hvf_fork_probe concurrent-ceiling 140 30 1 0 0 2>&1 | tee target/gic-qual-c3-plain.log
target/release/hvf_fork_probe concurrent-ceiling 140 30 1 0 1 2>&1 | tee target/gic-qual-c3-gic.log
grep -a 'live_at_failure\|case=' target/gic-qual-c3-*.log
```

Expected: both runs report a `live_at_failure` ceiling (the children
self-destruct after 30 s). **Gate D5b:** if the GIC ceiling is below the plain
ceiling, Task 5 Step 4 sets `GLOBAL_VCPU_CEILING` to the GIC ceiling minus 7
(the same margin as 127 → 120) and rewrites its doc comment with both numbers;
otherwise the constant stays. Either way, Task 5 routes `HV_NO_RESOURCES` from
`hv_gic_create` through the existing park+retry backpressure. The production
form of this check is `page_table_pauses_survive_carrier_load` (four concurrent
carriers, each with its GIC VM after Task 5), which Tasks 6 and 9 run and
Task 12 adds to `el1-gate`.

- [ ] **Step 5: Record the results and decisions**

Append to `docs/perf-results/2026-09-25-hvf-gic-qualification.md`:
- the host (model, and the macOS build from `sw_vers`) and source HEAD;
- the test executable's SHA-256 (the path is in
  `target/test-results/carrick-vmm-hvf-signed-artifacts.jsonl`);
- every `C1`/`C2` line verbatim, and both C3 ceilings;
- a "Reference setup" paragraph that points to the plan's "Prior art" section,
  names the libkrun commit and license, and lists the three differences
  (placement, MPIDR layout, host-side register writes);
- a decisions table:
  - D1: the C2 verdict;
  - D3: the per-state C1 verdict, with the detection bound "zero wedges in
    1,000 rounds x 8 vCPUs per state is a smoke bound, not a probability
    claim";
  - D5b: both ceilings and the `GLOBAL_VCPU_CEILING` decision.

- [ ] **Step 6: Lint and commit**

```bash
cargo clippy -p carrick-vmm-hvf --all-targets -- -D warnings
just fmt-check
git add crates/carrick-vmm-hvf/tests/gic_qual/harness.rs crates/carrick-vmm-hvf/tests/gic_qualification.rs \
  crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs docs/perf-results/2026-09-25-hvf-gic-qualification.md
git commit -F- <<'MSG'
test(hvf): check the carrick-specific uses of the in-kernel GIC

Why: Carrick adopts Hypervisor.framework's in-kernel GIC the way
libkrun (Apache-2.0) uses it and hv_gic.h prescribes. Three uses have
no reference: an owed kick deferred to the next EL0 boundary once
hv_vcpu_set_pending_interrupt is refused; hv_vcpus_exit on eight
vCPUs in Carrick's EL1/EL0 states; and many concurrent processes,
each with a GIC VM.

What: a signed check suite with its own guest blob, set up the
reference way (GIC after hv_vm_create and before any vCPU, MPIDR
first, one thread per vCPU for the VM's life). C2: SGI 15 through
GICR_ISPENDR0, including production's un-acknowledged `hvc #4` slot
(control: the legacy call returns HV_UNSUPPORTED). C1: hv_vcpus_exit
smoke, 8 vCPUs, 1,000 rounds in each of three production states. C3:
the concurrent VM ceiling with a GIC per VM (hvf_fork_probe).

Verified: `just test-hvf gic_qualification_c<N> --nocapture` per
check on <host>; results and decisions in
docs/perf-results/2026-09-25-hvf-gic-qualification.md.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

Replace `<host>` with the `sw_vers`/model line before committing.

---

### Task 2: Every vCPU lives for its VM's life (decides D2)

`hv_gic.h`: "Once the virtual machine vcpus are running, its topology is
considered final. Destroy vcpus only when you are tearing down the virtual
machine." libkrun follows this: one thread per vCPU, and no `hv_vcpu_destroy`
before teardown. The previous plan qualified Carrick's mid-life destroy and
recreate against HVF (old E3) and censused how often production does it. This
task removes the behaviour instead.

**Evidence that it can be designed out.** The code map of 2026-09-24 (Fact 5
states it site by site) shows the following for the default HVPatch lane:
- **Guest waits keep the vCPU.** A blocking wait detaches the task and the
  executor keeps its vCPU (`executor/backend.rs:969-1005`,
  `executor.rs:258-279`). The idle audit requires a live vCPU
  (`persistent_executor.rs:1505-1517`).
- **The M:N reclaim and shared-wait machinery has no runtime caller.** This
  covers `reclaim_park`/`reclaim_resume`, `release_vm_after_reclaim_park` and
  `shared_wait_park`/`shared_wait_resume`. The only references are the HVF
  engine overrides (`hvf_aarch64_engine.rs:1925-2039`) and the trait default
  forwarders in `carrick-hal`/`carrick-aarch64`.
- **Workers live for the carrier.** Every worker, spares included, is spawned
  and initialised at pool start (`pool.rs:1206-1262`). Workers leave only on
  pool shutdown at carrier teardown (`wait_wake.rs:727-750`) or on a worker
  fault (`executor.rs:173-213`, `retire_failed_worker`). There is no idle
  shrink.
- **fork, clone and exec never rebuild the VM.** fork and clone materialise
  tasks without a vCPU (`hvf_aarch64_engine.rs:819,882`), and exec takes the
  persistent branch (`execve_rebuild.rs:1072`).
- **The one live mid-life pattern is the initial-runner hand-off.** Every root
  boot creates a boot vCPU, snapshots it and destroys it
  (`binding.rs:5381-5383` → `persistent_executor.rs:970-996`). For the first
  root this happens before any executor vCPU exists, and the boot vCPU never
  runs. For a later root in a reused carrier (`carrier.rs:12`,
  `mapping_plan.rs:389-497`) it happens while pool vCPUs run. That second case
  is exactly what `hv_gic.h` forbids.
- **No path needs more simultaneous vCPU-owning threads than the per-VM cap,
  and none moves a vCPU between threads.** The pool has about 18 executors on
  the canonical host (10 bound plus 8 spares), against a budget of 60.

**Decision D2:** every vCPU is created before the VM's first `hv_vcpu_run` and
is destroyed only at VM teardown. The root boots without a vCPU, as clone
children already do. The dead reclaim machinery is deleted. A faulted worker
keeps its vCPU until pool shutdown. The executor budget is always clamped.
Task 5 enforces the rule at runtime and fails closed (`gic::configure_new_vcpu`
refuses a create after the generation's first run or first destroy), so a path
this map missed turns a gate red instead of relying on HVF behaviour nobody has
qualified.

If Step 2's reachability check finds a runtime caller the map missed, STOP and
replan. The fallback is not a return to E3. It is to bring that caller under
the same rule.

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/trap.rs` (`VcpuDestroySite`, `destroy_raw_vcpu`,
  `vcpu_destroyed(vcpu_id, site)`)
- Modify: `crates/carrick-vmm-hvf/src/trap/persistent_executor.rs` (delete the park/resume
  paths; `destroy_vcpu_on_thread_exit` through `destroy_raw_vcpu`)
- Modify: `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs` (delete the reclaim,
  shared-wait and initial-runner overrides and the `CARRICK_HVF_VCPU_RECLAIM` hatch;
  root snapshot as data)
- Modify: `crates/carrick-vmm-hvf/src/trap/mapping_plan.rs` (`new_with_plan` creates no boot vCPU)
- Modify: `crates/carrick-vmm-hvf/src/trap/execve_rebuild.rs`, `trap/carrier_custody.rs`,
  `trap/cow_engine.rs`, `trap/vcpu_gate.rs` (remaining destroys name a site; budget always clamped)
- Modify: `crates/carrick-vmm-hvf/src/trap/vcpu_admission.rs` (source test)
- Modify: `crates/carrick-runtime/src/vcpu_loop/binding.rs` (`prepare_initial_runner_handoff`
  takes the root snapshot as data), `crates/carrick-runtime/src/vcpu_loop/executor.rs`
  (a faulted worker keeps its vCPU until Stop), `crates/carrick-runtime/src/vcpu_loop/threaded_loop.rs`
  (the boot-vCPU error destroy at :361 goes away)
- Modify: `crates/carrick-vmm-hvf/tests/initial_runner_handoff.rs` (retire with the hand-off it tests)
- Modify: `docs/perf-results/2026-09-25-hvf-gic-qualification.md` ("vCPU lifecycle" section)

**Interfaces:**
- Produces: `pub(crate) enum VcpuDestroySite { WorkerExit = 1, CreationRollback = 2,
  CreationError = 3, ExecveRebuild = 4 }`;
  `pub(crate) fn destroy_raw_vcpu(vcpu_id: u64, site: VcpuDestroySite) -> applevisor_sys::hv_return_t`
  (the only raw `hv_vcpu_destroy` in the crate's `src/`, outside `src/bin`);
  `pub(crate) fn vcpu_destroyed(vcpu_id: u64, site: VcpuDestroySite)`;
  the root's initial CPU state as data (`initial_root_snapshot`, named in
  Step 4).
- Consumed by: Task 5 (`destroy_raw_vcpu` takes the GIC topology lock; the
  lifecycle guard records the site).

- [ ] **Step 1: Write the failing lifecycle source test**

Append to `crates/carrick-vmm-hvf/src/trap/vcpu_admission.rs`:

```rust
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod vcpu_lifetime_tests {
    fn src(file: &str) -> String {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file))
            .unwrap()
    }

    fn code_lines(text: &str) -> impl Iterator<Item = &str> {
        text.lines().filter(|line| !line.trim_start().starts_with("//"))
    }

    /// EL1 plan 1a D2: a vCPU is destroyed only at VM teardown (hv_gic.h:
    /// "Destroy vcpus only when you are tearing down the virtual machine").
    /// One raw destroy, every destroy names a teardown-class site, and the
    /// destroy-and-recreate paths no longer exist.
    #[test]
    fn vcpus_live_for_the_vm_lifetime() {
        let raw = concat!("hv_vcpu_", "destroy(");
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = vec![src_dir.join("trap.rs"), src_dir.join("hvf_aarch64_engine.rs")];
        for entry in std::fs::read_dir(src_dir.join("trap")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
        let mut raw_sites = Vec::new();
        for path in &files {
            let text = std::fs::read_to_string(path).unwrap();
            let count: usize = code_lines(&text).map(|line| line.matches(raw).count()).sum();
            if count != 0 {
                raw_sites.push((path.file_name().unwrap().to_string_lossy().into_owned(), count));
            }
        }
        assert_eq!(raw_sites, [("trap.rs".to_owned(), 1)], "one raw destroy: destroy_raw_vcpu");

        const TEARDOWN_SITES: [&str; 4] = [
            "VcpuDestroySite::WorkerExit",
            "VcpuDestroySite::CreationRollback",
            "VcpuDestroySite::CreationError",
            "VcpuDestroySite::ExecveRebuild",
        ];
        for path in &files {
            let text = std::fs::read_to_string(path).unwrap();
            for line in code_lines(&text).filter(|line| line.contains(concat!("destroy_raw_", "vcpu(")) && !line.contains("fn destroy_raw_vcpu")) {
                assert!(
                    TEARDOWN_SITES.iter().any(|site| line.contains(site)),
                    "{}: `{}` must name a teardown-class VcpuDestroySite",
                    path.display(),
                    line.trim()
                );
            }
        }

        let executor = src("trap/persistent_executor.rs");
        let engine = src("hvf_aarch64_engine.rs");
        for gone in [
            "fn reclaim_park(",
            "fn reclaim_resume(",
            "fn initial_runner_park(",
            "fn initial_runner_resume(",
            "fn shared_wait_park(",
            "fn shared_wait_resume(",
            "fn release_vm_after_reclaim_park(",
        ] {
            assert!(!executor.contains(gone), "persistent_executor.rs still has {gone}");
        }
        assert!(!engine.contains("CARRICK_HVF_VCPU_RECLAIM"), "reclaim hatch still read");
        assert!(!engine.contains("fn save_initial_runner_state("), "boot vCPU hand-off still present");
    }
}
```

```bash
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib vcpus_live_for_the_vm_lifetime
```

Expected: FAIL with the raw-destroy inventory (seven or more raw
`hv_vcpu_destroy` sites across `persistent_executor.rs`, `execve_rebuild.rs`
and `carrier_custody.rs`). Record the output for the commit body.

- [ ] **Step 2: Confirm the map before deleting anything**

```bash
for sym in save_guest_state rebind_to_slot save_shared_wait_state rebind_shared_wait_state \
           release_vm_after_reclaim_park rebind_initial_runner_state add_vcpu materialize_process; do
  printf '%s: ' "$sym"; grep -rn "\.$sym(" crates/carrick-runtime crates/carrick-embed crates/carrick-engine | grep -v '/tests\?/' | wc -l
done
grep -n 'retire_failed_worker\|WorkerCommand::Stop\|WorkerCommand::Run\|WorkerCommand::Initialize' \
  crates/carrick-runtime/src/vcpu_loop/executor.rs crates/carrick-runtime/src/vcpu_loop/executor/pool.rs \
  crates/carrick-runtime/src/vcpu_loop/executor/settlement.rs
grep -rn 'CARRICK_HVF_VCPU_RECLAIM' --exclude-dir=target . | grep -v '^./docs/superpowers/plans/'
```

Expected:
- `0` for every symbol;
- pool start sends `Run` only after every worker has reported its startup,
  so every executor vCPU exists before any guest instruction runs;
- pool shutdown sends `Stop` to every worker handle, retired ones included;
- the hatch's readers and mentions are listed, so Step 5 can remove every one
  (docs and scripts included).

A non-zero count, a `Run` sent before all startups, or a shutdown that skips
retired workers is a STOP: the map missed something (see D2).

- [ ] **Step 3: One raw destroy, sites for the teardown-class destroys**

In `trap.rs`, next to `vcpu_destroyed` (trap.rs:881):

```rust
/// Where a vCPU was destroyed. Every class is teardown: a worker leaving at
/// pool shutdown, the rollback of a VM being created, a vCPU that failed its
/// own setup before it ran, and execve's whole-VM rebuild (EL1 plan 1a D2;
/// hv_gic.h: destroy vCPUs only when tearing down the VM).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum VcpuDestroySite {
    WorkerExit = 1,
    CreationRollback = 2,
    CreationError = 3,
    ExecveRebuild = 4,
}

/// The only raw `hv_vcpu_destroy` in the crate (test
/// `vcpus_live_for_the_vm_lifetime`). Owning thread; the caller forgets its
/// handle so applevisor's Drop never runs on it.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn destroy_raw_vcpu(vcpu_id: u64, _site: VcpuDestroySite) -> applevisor_sys::hv_return_t {
    // SAFETY: the caller owns the vCPU on this thread and forgets its handle.
    unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) }
}
```

`vcpu_destroyed(vcpu_id)` becomes `vcpu_destroyed(vcpu_id, site: VcpuDestroySite)`.
Route every remaining raw destroy through `destroy_raw_vcpu` with its site:
- `destroy_vcpu_on_thread_exit` → `WorkerExit`;
- the creation rollbacks at `carrier_custody.rs:110/154` → `CreationRollback`;
- execve's mature rebuild (`execve_rebuild.rs:1246`) → `ExecveRebuild`;
- `HvfVmState::add_vcpu`'s mailbox failure (`cow_engine.rs:3695`) and the error
  returns of `from_process_spec` after its `create_vcpu` (`trap.rs:6610`), which
  today destroy through applevisor's `Drop`, → `CreationError`. Wrap the
  handle in `ManuallyDrop` and destroy explicitly.

Task 5 gives `destroy_raw_vcpu` its GIC lock. The unused `_site` becomes the
lifecycle record then.

- [ ] **Step 4: The root boots without a vCPU**

Today `new_with_plan` (`mapping_plan.rs:381-500`) creates the root's boot vCPU,
programs its initial registers, and `prepare_initial_runner_handoff`
(`binding.rs:5320-5395`) snapshots it (`save_initial_runner_state`) and
destroys it before the pool loads the snapshot into an executor vCPU. The boot
vCPU exists only to hold registers (`hvf_aarch64_engine.rs:1937-1947`). Clone
children already start from data (`initial_cpu_state`,
`hvf_aarch64_engine.rs:614/737`, via `sibling_task_cpu_state`).

1. Add `initial_root_snapshot(...) -> Result<Aarch64VcpuSnapshot, TrapError>`
   beside `initial_cpu_state`. It builds the snapshot from the same register
   program `new_with_plan` writes into the boot vCPU (entry PC, SP, PSTATE, and
   the per-task system registers the snapshot carries). Build it from those
   values, not from a vCPU.
2. Transition commit (evidence, not the final shape): in
   `prepare_initial_runner_handoff`, compute both the vCPU snapshot and
   `initial_root_snapshot`, and return a `RuntimeError::Configuration` naming
   the first differing field if they differ. Then run:

   ```bash
   just build
   just test-embed 2>&1 | tail -5
   just --no-deps conformance smoke 2>&1 | tail -10
   ```

   Expected: green. Every root boot in those gates compared equal. Record the
   counts.
3. Final shape: `new_with_plan` creates the VM (first root) or uses the live
   one (later roots), and never a vCPU. `prepare_initial_runner_handoff`
   publishes `initial_root_snapshot` as the `MigratableTaskState`'s `cpu`.
   Delete the following:
   - the comparison;
   - `save_initial_runner_state` and `rebind_initial_runner_state` (HVF
     overrides) and `initial_runner_park`/`initial_runner_resume`;
   - the boot vCPU's `SetupVcpuGuard` lane (`mapping_plan.rs:489-500`,
     `carrier_custody.rs:313-329`);
   - the boot-vCPU error destroy at `threaded_loop.rs:361`;
   - `tests/initial_runner_handoff.rs`, which tests only the deleted mailbox
     hand-off.

   Do not keep them behind a flag (AGENTS.md: no second paths). If the trait
   method `save_initial_runner_state` has no other implementor, delete it from
   the trait. Otherwise leave its default.

If `initial_root_snapshot` cannot reproduce a field without a vCPU (a register
HVF derives at `hv_vcpu_create` that the snapshot carries), STOP and report
the field. That field is then read once from the first executor vCPU instead,
which the replan must name.

- [ ] **Step 5: Delete the reclaim and shared-wait machinery and its hatch**

Delete `reclaim_park`, `reclaim_resume`, `release_vm_after_reclaim_park`,
`shared_wait_park`, `shared_wait_resume`/`shared_wait_resume_inner` and the
`ReclaimParkAuthority` states only they use (`persistent_executor.rs:14-60,
930-1200`). Delete the HVF engine overrides that call them
(`save_guest_state`, `rebind_to_slot`, `save_shared_wait_state`,
`rebind_shared_wait_state*`, `release_vm_after_reclaim_park`;
`hvf_aarch64_engine.rs:1925-2039`), so the trait defaults apply. Delete
`CARRICK_HVF_VCPU_RECLAIM` (`hvf_aarch64_engine.rs:85-98, 1345-1354`): the
executor budget is always `vcpu_gate::budget()`, which closes the hole where
`=0` let a large `CARRICK_BOUND_EXECUTORS` exceed the per-VM cap. Update the
stale doc comments that name these paths (`persistent_executor.rs:930-943`,
`vcpu_gate.rs:1-16, 56-78`). `-D warnings` names anything that becomes unused;
delete it rather than `allow` it.

- [ ] **Step 6: A faulted worker keeps its vCPU until pool shutdown**

In `crates/carrick-runtime/src/vcpu_loop/executor.rs`, after
`retire_failed_worker` and its `terminal_drain` (executor.rs:188-214), a retired
worker whose startup was published waits for `WorkerCommand::Stop` (or a closed
channel) before `destroy_and_unregister`. Its vCPU is idle and no longer
scheduled; it is destroyed at shutdown with the rest. The pool's capacity
shrinks exactly as today. Only the moment of the destroy moves. Keep the
`tracing::error!` that names the death when it happens.

- [ ] **Step 7: Run green and record**

```bash
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib vcpus_live_for_the_vm_lifetime
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib
just test
just build
just test-embed 2>&1 | tail -5
CARRICK_RUN_ID=d2-smoke target/release/carrick run --rm docker.io/library/ubuntu:24.04 /bin/sh -c 'echo hi; nproc' < /dev/null
scripts/sudo/kill.sh d2-smoke
```

Expected: all green. Add a "vCPU lifecycle (D2)" section to
`docs/perf-results/2026-09-25-hvf-gic-qualification.md` with:
- the code-map citations above;
- the Step 1 red inventory;
- the Step 2 zero counts;
- the Step 4 comparison counts.

- [ ] **Step 8: Commit**

Two commits: Step 4.2's comparison lands first, as the evidence commit, then
the rest.

```bash
just fmt-check && cargo clippy -p carrick-vmm-hvf -p carrick-runtime --all-targets -- -D warnings
git add -A crates/carrick-vmm-hvf crates/carrick-runtime docs/perf-results/2026-09-25-hvf-gic-qualification.md
git status --short   # only files this task names
git commit -F- <<'MSG'
refactor(hvf): keep every vcpu for its vm's life

Why: Hypervisor.framework's in-kernel GIC treats a VM's topology as
final once its vCPUs run ("Destroy vcpus only when you are tearing down
the virtual machine", hv_gic.h), and libkrun (Apache-2.0) keeps one
vCPU per thread for the VM's life. Carrick destroyed and recreated a
boot vCPU on every root boot, including inside a live carrier for
later roots, and carried an unreachable M:N reclaim and shared-wait
destroy/recreate machinery from the retired one-thread-per-guest-thread
lane. EL1 plan 1a designs this out instead of qualifying HVF behaviour
the SDK advises against.

What:
- The root boots from an initial CPU snapshot built as data, as clone
  children already do; no boot vCPU, no initial-runner park/resume.
- reclaim_park/resume, shared_wait_park/resume,
  release_vm_after_reclaim_park, their engine overrides and the
  CARRICK_HVF_VCPU_RECLAIM hatch are deleted; the executor budget is
  always clamped to the per-VM cap.
- A faulted executor keeps its idle vCPU until pool shutdown.
- `destroy_raw_vcpu` is the only raw hv_vcpu_destroy and every destroy
  names a teardown-class `VcpuDestroySite`.

Verified: `vcpus_live_for_the_vm_lifetime` red (<N> raw destroys,
park/resume paths present) then green; the transition commit compared
the data-built root snapshot with the boot vCPU's on every root boot of
`just test-embed` and conformance smoke (<counts>, all equal); signed
smoke; `just test`.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

---

### Task 3: One typed correction of the binding's IRQ/FIQ swap (D10)

**Files:**
- Create: `crates/carrick-vmm-hvf/src/interrupt.rs`
- Modify: `crates/carrick-vmm-hvf/src/lib.rs` (module declaration)
- Modify: `crates/carrick-vmm-hvf/src/trap.rs` (`HVF_VIRTUAL_IRQ` derives from the wrapper)
- Modify: `crates/carrick-vmm-hvf/tests/gic_qual/harness.rs` (`SDK_IRQ` via the wrapper)
- Modify: `.semgrep/typed-domains.yml`

**Interfaces:**
- Produces: `pub enum carrick_vmm_hvf::interrupt::HvfInterruptLine { Irq, Fiq }` with
  `pub const fn sdk_value(self) -> u32`, `pub const fn sys(self) -> applevisor_sys::hv_interrupt_type_t`,
  `pub const fn applevisor(self) -> applevisor::prelude::InterruptType`.
- Keeps: `crate::trap::HVF_VIRTUAL_IRQ` (same name and value, now derived) and
  `trap::virtual_irq_line_tests::kick_irq_asserts_the_sdk_irq_line`.
- Consumed by: Task 6 (legacy vehicle for the `CARRICK_HVF_GIC=0` hatch).

- [ ] **Step 1: Add the semgrep rule and run it red**

Append to `.semgrep/typed-domains.yml` `rules:`:

```yaml
  # applevisor-sys 1.0.0 declares `hv_interrupt_type_t { FIQ, IRQ }`, the
  # reverse of the SDK (hv_vcpu_types.h: IRQ = 0, FIQ = 1). Naming a line by
  # the binding's variant asserted the FIQ line, which Carrick masks at every
  # level: kicks were silently lost and page-table drains timed out
  # (c245596fe). Every line is named through HvfInterruptLine.
  - id: carrick-hvf-interrupt-line-outside-boundary
    languages: [rust]
    severity: ERROR
    message: |
      Name a Hypervisor.framework interrupt line through
      carrick_vmm_hvf::interrupt::HvfInterruptLine (Irq/Fiq by SDK number).
      The applevisor/applevisor-sys variants are numbered in reverse of the SDK.
    paths:
      include:
        - "crates/**"
      exclude:
        - "crates/carrick-vmm-hvf/src/interrupt.rs"
    pattern-regex: '\b(InterruptType|hv_interrupt_type_t)::(IRQ|FIQ)\b'
```

```bash
./scripts/lint-domains.sh 2>&1 | grep -a -c 'carrick-hvf-interrupt-line-outside-boundary'
```

Expected: at least `2` (trap.rs `HVF_VIRTUAL_IRQ`, the qualification harness's
`SDK_IRQ`), and `lint-domains.sh` exits non-zero.

- [ ] **Step 2: Write the wrapper**

Create `crates/carrick-vmm-hvf/src/interrupt.rs`:

```rust
//! The one place Carrick names a Hypervisor.framework virtual interrupt line.
//!
//! `applevisor-sys` 1.0.0 (and the `applevisor` wrapper) declare
//! `hv_interrupt_type_t { FIQ, IRQ }`, the reverse of the SDK's
//! `hv_vcpu_types.h` (`HV_INTERRUPT_TYPE_IRQ = 0`, `HV_INTERRUPT_TYPE_FIQ = 1`),
//! so the binding's `IRQ` variant asserts the FIQ line. [`HvfInterruptLine`]
//! names a line by its SDK meaning and maps it to the binding variant carrying
//! the SDK number; const assertions pin both mappings. The semgrep rule
//! `carrick-hvf-interrupt-line-outside-boundary` rejects the binding variants
//! anywhere else.
//!
//! Once a VM has an in-kernel GIC, `hv_vcpu_set_pending_interrupt` returns
//! `HV_UNSUPPORTED` (hv_vcpu.h); these lines then only serve the
//! `CARRICK_HVF_GIC=0` bisection hatch.

/// A Hypervisor.framework virtual interrupt line, by SDK meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HvfInterruptLine {
    Irq,
    Fiq,
}

impl HvfInterruptLine {
    /// The SDK's number for this line (`hv_vcpu_types.h`).
    pub const fn sdk_value(self) -> u32 {
        match self {
            Self::Irq => 0,
            Self::Fiq => 1,
        }
    }

    /// The `applevisor-sys` variant whose discriminant is the SDK number.
    pub const fn sys(self) -> applevisor_sys::hv_interrupt_type_t {
        match self {
            Self::Irq => applevisor_sys::hv_interrupt_type_t::FIQ,
            Self::Fiq => applevisor_sys::hv_interrupt_type_t::IRQ,
        }
    }

    /// The `applevisor` wrapper variant whose discriminant is the SDK number.
    pub const fn applevisor(self) -> applevisor::prelude::InterruptType {
        match self {
            Self::Irq => applevisor::prelude::InterruptType::FIQ,
            Self::Fiq => applevisor::prelude::InterruptType::IRQ,
        }
    }
}

const _: () = assert!(HvfInterruptLine::Irq.sys() as u32 == HvfInterruptLine::Irq.sdk_value());
const _: () = assert!(HvfInterruptLine::Fiq.sys() as u32 == HvfInterruptLine::Fiq.sdk_value());
const _: () =
    assert!(HvfInterruptLine::Irq.applevisor() as u32 == HvfInterruptLine::Irq.sdk_value());
const _: () =
    assert!(HvfInterruptLine::Fiq.applevisor() as u32 == HvfInterruptLine::Fiq.sdk_value());

#[cfg(test)]
mod tests {
    use super::HvfInterruptLine;

    /// The SDK numbers, spelled independently of the const expressions.
    #[test]
    fn lines_carry_the_sdk_numbers() {
        assert_eq!(HvfInterruptLine::Irq.sys() as u32, 0);
        assert_eq!(HvfInterruptLine::Fiq.sys() as u32, 1);
        assert_eq!(HvfInterruptLine::Irq.applevisor() as u32, 0);
        assert_eq!(HvfInterruptLine::Fiq.applevisor() as u32, 1);
    }
}
```

In `crates/carrick-vmm-hvf/src/lib.rs`, next to `pub mod vcpu_kick;`:

```rust
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod interrupt;
```

In `crates/carrick-vmm-hvf/src/trap.rs` replace the `HVF_VIRTUAL_IRQ` definition
(trap.rs:6089-6096, keep its doc comment and the test module below it) with:

```rust
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const HVF_VIRTUAL_IRQ: applevisor::prelude::InterruptType =
    crate::interrupt::HvfInterruptLine::Irq.applevisor();
```

In `crates/carrick-vmm-hvf/tests/gic_qual/harness.rs` replace the `SDK_IRQ`
constant with:

```rust
const SDK_IRQ: hv_interrupt_type_t = carrick_vmm_hvf::interrupt::HvfInterruptLine::Irq.sys();
```

- [ ] **Step 3: Run green**

```bash
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib -- interrupt::tests kick_irq_asserts_the_sdk_irq_line
./scripts/lint-domains.sh
just test-hvf gic_qualification_c2 --nocapture 2>&1 | grep -a '^C2'
```

Expected: both unit tests PASS; `lint-domains.sh` exits 0; C2 unchanged (the
legacy call still reports `HV_UNSUPPORTED` through the wrapper).

- [ ] **Step 4: Commit**

```bash
git add crates/carrick-vmm-hvf/src/interrupt.rs crates/carrick-vmm-hvf/src/lib.rs \
  crates/carrick-vmm-hvf/src/trap.rs crates/carrick-vmm-hvf/tests/gic_qual/harness.rs .semgrep/typed-domains.yml
git commit -F- <<'MSG'
refactor(hvf): name interrupt lines through one typed SDK mapping

Why: applevisor-sys 1.0.0 numbers hv_interrupt_type_t in reverse of the
SDK, and naming a line by the binding's variant already shipped one
silent kick-loss defect (c245596fe). The fix lived in one constant;
nothing stopped the next call site from repeating it, and GIC adoption
adds call sites.

What: `HvfInterruptLine { Irq, Fiq }` maps SDK meaning to the binding
variant carrying the SDK number, pinned by const assertions.
`HVF_VIRTUAL_IRQ` derives from it (same value). Semgrep rule
`carrick-hvf-interrupt-line-outside-boundary` rejects the binding's
variants anywhere else.

Verified: the rule flagged trap.rs and the qualification test before the
change and passes after; `lines_carry_the_sdk_numbers` and
`kick_irq_asserts_the_sdk_irq_line` pass; C2 unchanged.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

---

### Task 4: GIC placement in the guest physical map (D6)

**Files:**
- Modify: `crates/carrick-mem/src/memory.rs` (constants, non-overlap asserts)
- Modify: `crates/carrick-mem/src/page_table.rs` (stage-1 publication guard + tests)
- Modify: `crates/carrick-vmm-hvf/src/trap/stage2_backend.rs` (map guard + test)
- Modify: `crates/carrick-vmm-hvf/tests/gic_qual/harness.rs`,
  `crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs` (use the constants)

**Interfaces:**
- Produces: `carrick_mem::memory::{LINUX_GIC_WINDOW_BASE: u64 = 0x2F_0000_0000,
  LINUX_GIC_WINDOW_SIZE: u64 = 0x1000_0000, LINUX_GIC_DISTRIBUTOR_BASE: u64,
  LINUX_GIC_DISTRIBUTOR_MAX: u64 = 0x100_0000, LINUX_GIC_REDISTRIBUTOR_BASE: u64,
  LINUX_GIC_REDISTRIBUTOR_MAX: u64}`, `pub const fn ipa_overlaps_gic_window(ipa: u64, len: u64) -> bool`,
  `carrick_mem::page_table::PageTableError::GicWindowOutput`.
- Consumed by: Task 5 (`gic.rs` geometry and placement).

The `CARRICK_HVF_GIC=0` hatch is not read here: `carrick-mem` is shared by every
backend, and the hatch has exactly one reader, `gic::interrupt_model()` (Task 5),
which the vector builder receives as an argument (Task 9).

Why this window: the IPA space below the sigreturn trampoline is dense with
kernel-only regions (Fact 7). `0x2E_0000_0000` is taken by vvar/vDSO/clock stub
(vdso.rs:18); `0x2F_0000_0000..0x30_0000_0000` is unused by every constant in
`carrick-mem`, `carrick-el1-abi` and `carrick-vmm-hvf` (grep in Step 1), lies
below 2^40 and below every guest-data arena, and 256 MiB holds a 16 MiB
distributor slot and 240 MiB of redistributors (1,920 vCPUs at 128 KiB each).

- [ ] **Step 1: Confirm the window is unused**

```bash
grep -rn '0x2[fF]_\|0x2[fF][0-9a-fA-F]\{8\}\b' crates --include='*.rs' | grep -v '/tests/\|gic_qual\|hvf_fork_probe.rs'
```

Expected: no output. Any hit: STOP and re-derive the window.

- [ ] **Step 2: Write the failing guard test**

Append to `crates/carrick-vmm-hvf/src/trap/stage2_backend.rs`:

```rust
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
#[test]
fn stage2_map_refuses_the_gic_window() {
    const HV_BAD_ARGUMENT: applevisor_sys::hv_return_t = 0xfae9_4003_u32 as applevisor_sys::hv_return_t;
    let _stub = ScopedStage2MapTestStub::enable();
    let mut page = vec![0u8; 0x4000];
    for ipa in [
        carrick_mem::memory::LINUX_GIC_DISTRIBUTOR_BASE,
        carrick_mem::memory::LINUX_GIC_REDISTRIBUTOR_BASE,
        carrick_mem::memory::LINUX_GIC_WINDOW_BASE + carrick_mem::memory::LINUX_GIC_WINDOW_SIZE - 0x4000,
        carrick_mem::memory::LINUX_GIC_WINDOW_BASE - 0x2000, // straddles the start
    ] {
        let rc = unsafe { inventory_hv_vm_map(page.as_mut_ptr().cast(), ipa, 0x4000, 0b111) };
        assert_eq!(rc, HV_BAD_ARGUMENT, "stage-2 map at {ipa:#x} must be refused");
    }
    let rc = unsafe {
        inventory_hv_vm_map(page.as_mut_ptr().cast(), carrick_mem::memory::LINUX_GIC_WINDOW_BASE - 0x4000, 0x4000, 0b111)
    };
    assert_eq!(rc, 0, "the page below the window is ordinary");
}
```

Add the constants first so the test compiles (Step 3), then:

```bash
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib stage2_map_refuses_the_gic_window
```

Expected (after Step 3, before Step 4): FAIL `stage-2 map at 0x2f00000000 must be refused ... left: 0 right: -...`.

- [ ] **Step 3: Add the window constants and asserts**

In `crates/carrick-mem/src/memory.rs`, after the `LINUX_EL1_*` constants (~line 796):

```rust
/// Hypervisor.framework in-kernel GICv3 (`hv_gic_create`) guest-physical
/// window. Stage-2 only: no stage-1 table maps it, the guest reaches its CPU
/// interface through ICC_* system registers, and the host programs the
/// distributor and redistributors through hv_gic_* calls. It sits between the
/// vvar/vDSO/clock-stub pages (0x2E_0000_0000) and the sigreturn trampoline
/// (0x30_0000_0000). The stage-2 map boundary refuses every mapping into it.
pub const LINUX_GIC_WINDOW_BASE: u64 = 0x2F_0000_0000;
pub const LINUX_GIC_WINDOW_SIZE: u64 = 0x1000_0000; // 256 MiB
pub const LINUX_GIC_DISTRIBUTOR_BASE: u64 = LINUX_GIC_WINDOW_BASE;
pub const LINUX_GIC_DISTRIBUTOR_MAX: u64 = 0x100_0000; // 16 MiB
pub const LINUX_GIC_REDISTRIBUTOR_BASE: u64 = LINUX_GIC_WINDOW_BASE + LINUX_GIC_DISTRIBUTOR_MAX;
pub const LINUX_GIC_REDISTRIBUTOR_MAX: u64 = LINUX_GIC_WINDOW_SIZE - LINUX_GIC_DISTRIBUTOR_MAX;

const fn ranges_disjoint(a: u64, a_len: u64, b: u64, b_len: u64) -> bool {
    a + a_len <= b || b + b_len <= a
}

/// Every reserved guest region the GIC window must not touch.
const GIC_WINDOW_NEIGHBOURS: &[(u64, u64)] = &[
    (LINUX_ROSETTA_IPA_BASE, LINUX_ROSETTA_WINDOW_SIZE),
    (LINUX_ALIAS_IPA_BASE, LINUX_ALIAS_IPA_SIZE),
    (LINUX_INFO_PAGE_BASE, 0x1_0000),
    (LINUX_KERNEL_REGION_BASE, LINUX_KERNEL_REGION_SIZE),
    (LINUX_EL1_KERNEL_BASE, LINUX_EL1_KERNEL_SIZE),
    (
        crate::vdso::LINUX_VVAR_BASE,
        LINUX_EL0_CLOCK_STUB_BASE + LINUX_EL0_CLOCK_STUB_SIZE - crate::vdso::LINUX_VVAR_BASE,
    ),
    (LINUX_SIGRETURN_TRAMPOLINE_BASE, LINUX_SIGRETURN_TRAMPOLINE_SIZE),
    (LINUX_HEAP_BASE, LINUX_HEAP_SIZE),
    (LINUX_MMAP_BASE, LINUX_MMAP_SIZE_MAX),
    (LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_SIZE),
    (LINUX_PRIVATE_OVERLAY_BASE, LINUX_PRIVATE_OVERLAY_SIZE),
    (
        LINUX_HVPATCH_ROOT_SLOT_BASE,
        LINUX_HVPATCH_RESERVED_END - LINUX_HVPATCH_ROOT_SLOT_BASE,
    ),
    (LINUX_STACK_TOP - LINUX_STACK_SIZE, LINUX_STACK_SIZE),
];

const _: () = {
    let mut i = 0;
    while i < GIC_WINDOW_NEIGHBOURS.len() {
        let (base, len) = GIC_WINDOW_NEIGHBOURS[i];
        assert!(
            ranges_disjoint(LINUX_GIC_WINDOW_BASE, LINUX_GIC_WINDOW_SIZE, base, len),
            "GIC window overlaps a reserved guest region"
        );
        i += 1;
    }
};
const _: () = assert!(LINUX_GIC_WINDOW_BASE + LINUX_GIC_WINDOW_SIZE <= 1 << 40);
const _: () = assert!(LINUX_GIC_WINDOW_BASE.is_multiple_of(0x1000_0000));

/// True if `[ipa, ipa + len)` touches the GIC window.
pub const fn ipa_overlaps_gic_window(ipa: u64, len: u64) -> bool {
    !ranges_disjoint(ipa, len, LINUX_GIC_WINDOW_BASE, LINUX_GIC_WINDOW_SIZE)
}
```

Add a VM-free unit test in the `kernel_only_range_tests` module:

```rust
    #[test]
    fn gic_window_is_below_the_trampoline_and_above_the_vdso() {
        assert!(LINUX_GIC_WINDOW_BASE > LINUX_EL0_CLOCK_STUB_BASE + LINUX_EL0_CLOCK_STUB_SIZE);
        assert!(LINUX_GIC_WINDOW_BASE + LINUX_GIC_WINDOW_SIZE <= LINUX_SIGRETURN_TRAMPOLINE_BASE);
        assert!(ipa_overlaps_gic_window(LINUX_GIC_REDISTRIBUTOR_BASE, 0x2_0000));
        assert!(!ipa_overlaps_gic_window(LINUX_SIGRETURN_TRAMPOLINE_BASE, 0x4000));
        assert!(!is_carrick_kernel_only_range(LINUX_GIC_WINDOW_BASE, LINUX_GIC_WINDOW_BASE + 0x4000));
    }
```

(`is_carrick_kernel_only_range` stays false for the window: it is a stage-1
predicate for kernel-only mappings, and nothing may map the GIC at stage 1,
which Step 4b enforces.)

In `crates/carrick-vmm-hvf/tests/gic_qual/harness.rs`, replace the three local
placement constants with:

```rust
const GIC_DIST_IPA: u64 = carrick_mem::memory::LINUX_GIC_DISTRIBUTOR_BASE;
const GIC_REDIST_IPA: u64 = carrick_mem::memory::LINUX_GIC_REDISTRIBUTOR_BASE;
const GIC_WINDOW_END: u64 =
    carrick_mem::memory::LINUX_GIC_WINDOW_BASE + carrick_mem::memory::LINUX_GIC_WINDOW_SIZE;
```

and in `hvf_fork_probe.rs` `create_probe_gic`, replace the two literals with
`carrick_mem::memory::LINUX_GIC_DISTRIBUTOR_BASE` and
`carrick_mem::memory::LINUX_GIC_REDISTRIBUTOR_BASE`.

- [ ] **Step 4: Implement the guard**

At the top of `inventory_hv_vm_map` in `stage2_backend.rs`, before the
`#[cfg(test)]` audit block:

```rust
    // The in-kernel GIC owns this IPA window: a stage-2 mapping there would
    // shadow the distributor or a redistributor.
    if carrick_mem::memory::ipa_overlaps_gic_window(ipa, size as u64) {
        return 0xfae9_4003_u32 as applevisor_sys::hv_return_t; // HV_BAD_ARGUMENT
    }
```

- [ ] **Step 4b: Stage-1 publication refuses outputs in the window**

A stage-1 descriptor whose output lies in the window would give EL1 or EL0
MMIO access to the distributor or a redistributor (a guest could clear the
group enables and silently lose every kick). Stage-1 outputs are written by
three `PageTableManager` paths: `map_aliased_with_flags` (every
`map_aliased`/`map_private_aliased`/`map_kernel_aliased`),
`repoint_preserving_attributes`, and `apply`, whose only `desc_for` call
(page_table.rs:1860) rebuilds an EMPTY descriptor from the identity VA.

Append to the `page_table.rs` test module (it has `fn manager()`):

```rust
    #[test]
    fn stage1_publication_refuses_outputs_in_the_gic_window() {
        use crate::memory::{LINUX_GIC_REDISTRIBUTOR_BASE, LINUX_GIC_WINDOW_BASE};
        let mut pt = manager();
        assert_eq!(
            pt.map_aliased(0x60_0000_0000, LINUX_GIC_REDISTRIBUTOR_BASE, 0x4000, true, None),
            Err(PageTableError::GicWindowOutput)
        );
        assert_eq!(
            pt.repoint_preserving_attributes(0x60_0000_0000, LINUX_GIC_WINDOW_BASE, 0x4000, None),
            Err(PageTableError::GicWindowOutput)
        );
        assert!(matches!(
            pt.apply(LINUX_GIC_WINDOW_BASE, 0x4000, PtOp::ReadWrite { exec: false }, None),
            Err(PageTableError::GicWindowOutput)
        ));
        assert_eq!(pt.translate(LINUX_GIC_WINDOW_BASE), None, "the boot image maps nothing there");
    }
```

```bash
cargo test -p carrick-mem --lib stage1_publication_refuses_outputs_in_the_gic_window
```

Expected: FAIL to compile (`GicWindowOutput` missing). Then:
- `PageTableError` gains `GicWindowOutput` ("an output address in the
  in-kernel GIC's IPA window") with its `Display` arm;
- `map_aliased_with_flags`, after its `len == 0` early return, and
  `repoint_preserving_attributes`, before its loop, add
  `if crate::memory::ipa_overlaps_gic_window(ipa, len) { return Err(PageTableError::GicWindowOutput); }`;
- in `apply`, directly before the `self.desc_for(op, block_start, level)` rebuild
  of an empty descriptor, add
  `if crate::memory::ipa_overlaps_gic_window(block_start, span) { return Err(PageTableError::GicWindowOutput); }`.

If the `apply` assertion instead reports another error (the identity VA range
is refused earlier, for example as `BadAddress`), keep that behaviour and assert
`is_err()` for `apply`: the invariant is that no descriptor with a window
output is written, which the `translate` line checks.

- [ ] **Step 5: Run green**

```bash
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib stage2_map_refuses_the_gic_window
cargo test -p carrick-mem --lib gic_window_is_below_the_trampoline_and_above_the_vdso
cargo test -p carrick-mem --lib stage1_publication_refuses_outputs_in_the_gic_window
cargo test -p carrick-mem --lib page_table
just test-hvf gic_qualification_c2 --nocapture 2>&1 | grep -a '^C2'
```

Expected: PASS for all; C2 unchanged (its GIC is created at the window
constants).

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-mem/src/memory.rs crates/carrick-mem/src/page_table.rs \
  crates/carrick-vmm-hvf/src/trap/stage2_backend.rs \
  crates/carrick-vmm-hvf/tests/gic_qual/harness.rs crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs
git commit -F- <<'MSG'
feat(hvf): reserve the guest-physical window for the in-kernel GIC

Why: hv_gic_create needs a distributor and a redistributor region in
guest-physical space that nothing else maps. The kernel-only IPA range
below the sigreturn trampoline is dense, and 0x2E_0000_0000 already
holds the vvar/vDSO/clock stub.

What: `LINUX_GIC_WINDOW_*` at 0x2F_0000_0000 (256 MiB: 16 MiB
distributor slot, 240 MiB redistributors), const-asserted disjoint from
every reserved region and below 2^40; the stage-2 map boundary refuses
any mapping into it, and stage-1 publication refuses any descriptor
whose output lies in it (`PageTableError::GicWindowOutput`). No VM uses
the window yet.

Verified: `stage2_map_refuses_the_gic_window` and
`stage1_publication_refuses_outputs_in_the_gic_window` red then green;
`gic_window_is_below_the_trampoline_and_above_the_vdso`; check C2
passes at this placement.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

---

### Task 5: Create the GIC in the VM funnel and configure every vCPU (D5, D7, D9)

Valid only if gates D1, D3 and D5b passed and Task 2 (D2) has landed. D12 is
decided inside this task (Step 8).

Task 5 is not committed on its own. It turns the GIC on by default, and until
Task 6 lands the kick vehicle every kick still goes through
`hv_vcpu_set_pending_interrupt`, which HVF refuses (`HV_UNSUPPORTED`) once a VM
has a GIC; the three kick sites propagate that error with `?`, so a commit of
Task 5 alone fails any run that absorbs a kick and breaks bisection. Task 5
ends with that failure recorded as the signed red evidence for Task 6, and
Task 6 commits both.

**Files:**
- Create: `crates/carrick-vmm-hvf/src/gic.rs`
- Modify: `crates/carrick-vmm-hvf/src/lib.rs` (module)
- Modify: `crates/carrick-vmm-hvf/src/trap.rs` (`create_vm_with_admission`, `destroy_raw_vcpu`,
  the first-run seal in `run_to_exit`)
- Modify: `crates/carrick-vmm-hvf/src/trap/vcpu_admission.rs` (both wrappers, `record_vm_released`,
  `GLOBAL_VCPU_CEILING` per D5b, tests)
- Modify: `crates/carrick-vmm-hvf/src/trap/vcpu_gate.rs` (capacity clamp)
- Modify: `crates/carrick-vmm-hvf/src/trap/cow_engine.rs` (EL0 ID view, D12)
- Modify: `crates/carrick-el1-abi/src/lib.rs` (shared INTID constants)
- Create: `conformance-probes/src/bin/idaa64pfr0.rs` and its registrations (D12)
- Create: `conformance-contracts/contracts/gic-topology.toml`
- Modify: `conformance-contracts/surfaces.toml`, `scripts/migrate/runtime-global-state.json`,
  `scripts/migrate/runtime-aborts/hvf.json` (the D2 guard's `carrick_fatal!`)

**Interfaces:**
- Consumes: `carrick_mem::memory::{LINUX_GIC_DISTRIBUTOR_BASE, LINUX_GIC_DISTRIBUTOR_MAX,
  LINUX_GIC_REDISTRIBUTOR_BASE, LINUX_GIC_REDISTRIBUTOR_MAX}`,
  `crate::trap::{VcpuDestroySite, destroy_raw_vcpu}`.
- Produces in `carrick_el1_abi`: `pub const GIC_KICK_INTID: u32 = 15;`,
  `pub const GIC_VTIMER_INTID: u32 = 27;`, `pub const GIC_SPURIOUS_INTID: u32 = 1023;`
  (single source for host and EL1).
- Produces in `crate::gic`: `pub(crate) struct PrivateIntid`, `pub(crate) const KICK_INTID`,
  `pub(crate) const VTIMER_INTID`, `pub(crate) struct Mpidr`, `pub(crate) struct MpidrAllocator`,
  `pub(crate) struct GicGeometry`, `pub(crate) enum InterruptModel { Gic, LegacyPendingLine }`,
  `pub(crate) fn interrupt_model() -> InterruptModel` (the one reader of `CARRICK_HVF_GIC`),
  `pub(crate) enum GicCreateFailure { NoResources, Fatal(TrapError) }`,
  `pub(crate) fn create_carrier_gic(generation: u64) -> Result<(), GicCreateFailure>`,
  `pub(crate) fn carrier_vm_released()`,
  `pub(crate) fn configure_new_vcpu(vcpu: u64) -> Result<(), TrapError>`,
  `pub(crate) fn destroy_releasing_affinity(vcpu: u64, site: VcpuDestroySite, destroy: impl FnOnce() -> applevisor_sys::hv_return_t) -> applevisor_sys::hv_return_t`,
  `pub(crate) fn seal_topology_before_run()`,
  `fn lifecycle_admits_create(sealed: bool, last_release_site: Option<VcpuDestroySite>) -> Result<(), String>` (D2 guard),
  `pub(crate) fn redistributor_capacity() -> Option<usize>`,
  `pub fn gic_topology_snapshot() -> GicTopologySnapshot` (pub, re-exported for embed tests).

- [ ] **Step 1: Add the shared INTID constants to the EL1 ABI**

In `crates/carrick-el1-abi/src/lib.rs`, near `IMAGE_VERSION`:

```rust
/// GIC INTID of the owed host kick: an SGI the host makes pending in the
/// vCPU's redistributor (GICR_ISPENDR0) after an `hv_vcpus_exit` lands inside
/// EL1, and EL1 surfaces as a kick exit (EL1 plan 1a, gate D1).
pub const GIC_KICK_INTID: u32 = 15;
/// GIC INTID of the EL1 virtual timer (Hypervisor.framework
/// `HV_GIC_INT_EL1_VIRTUAL_TIMER`; checked at every GIC creation).
pub const GIC_VTIMER_INTID: u32 = 27;
/// ICC_IAR1_EL1's "no pending interrupt" INTID.
pub const GIC_SPURIOUS_INTID: u32 = 1023;
```

and add `GIC_KICK_INTID as u64, GIC_VTIMER_INTID as u64,` to the `facts` list of
`EL1_ABI_LAYOUT_HASH` (a host/image disagreement about the kick INTID must be
refused like any layout change).

- [ ] **Step 2: Write the failing VM-free tests**

Create `crates/carrick-vmm-hvf/src/gic.rs` with only the test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpidr_carries_res1_and_sgi_addressable_affinity() {
        assert_eq!(Mpidr::for_index(0).raw(), 0x8000_0000);
        assert_eq!(Mpidr::for_index(15).raw(), 0x8000_000f);
        assert_eq!(Mpidr::for_index(16).raw(), 0x8000_0100);
        assert_eq!(Mpidr::for_index(63).raw(), 0x8000_030f);
    }

    #[test]
    fn mpidr_allocator_hands_out_the_lowest_free_index() {
        let mut allocator = MpidrAllocator::with_capacity(4);
        assert_eq!(allocator.allocate(100).unwrap(), 0);
        assert_eq!(allocator.allocate(101).unwrap(), 1);
        assert_eq!(allocator.allocate(102).unwrap(), 2);
        assert_eq!(allocator.release(101), Some(1));
        assert_eq!(allocator.allocate(103).unwrap(), 1);
        assert_eq!(allocator.live(), 3);
    }

    #[test]
    fn mpidr_allocator_refuses_a_second_index_for_one_vcpu_and_a_full_topology() {
        let mut allocator = MpidrAllocator::with_capacity(2);
        allocator.allocate(7).unwrap();
        assert!(allocator.allocate(7).is_err(), "one vCPU, one affinity");
        allocator.allocate(8).unwrap();
        assert!(allocator.allocate(9).is_err(), "no redistributor left");
        assert_eq!(allocator.release(42), None, "unknown vCPU releases nothing");
    }

    #[test]
    fn geometry_must_fit_the_reserved_window() {
        let fits = GicGeometry {
            distributor_size: 0x1_0000,
            distributor_alignment: 0x1_0000,
            redistributor_region_size: 64 * 0x2_0000,
            redistributor_size: 0x2_0000,
            redistributor_alignment: 0x1_0000,
        };
        assert!(fits.fits_window().is_ok());
        assert_eq!(fits.redistributor_capacity(), 64);
        let too_big = GicGeometry { redistributor_region_size: 0x1_0000_0000, ..fits };
        assert!(too_big.fits_window().is_err());
        // LINUX_GIC_REDISTRIBUTOR_BASE (0x2F_0100_0000) is 2^24-aligned only.
        let misaligned = GicGeometry { redistributor_alignment: 0x200_0000, ..fits };
        assert!(misaligned.fits_window().is_err());
    }

    #[test]
    fn a_destroy_releases_its_index_and_the_next_generation_starts_empty() {
        let mut allocator = MpidrAllocator::with_capacity(4);
        assert_eq!(allocator.allocate(5).unwrap(), 0);
        assert_eq!(allocator.allocate(6).unwrap(), 1);
        // Allocator semantics only: HVF reuses vCPU ids, so a released index
        // is handed out again. In production the D2 guard refuses any create
        // after a destroy within one VM generation, and a new generation gets
        // a fresh allocator.
        assert_eq!(allocator.release(5), Some(0));
        assert_eq!(allocator.allocate(5).unwrap(), 0);
        assert_eq!(allocator.live(), 2);
        assert_eq!(MpidrAllocator::with_capacity(4).live(), 0);
    }

    #[test]
    fn capacity_clamps_the_vcpu_budget() {
        assert_eq!(crate::trap::vcpu_gate::hvf_cap_from(64, Some(64)), 60);
        assert_eq!(crate::trap::vcpu_gate::hvf_cap_from(64, Some(32)), 28);
        assert_eq!(crate::trap::vcpu_gate::hvf_cap_from(64, None), 60);
        assert_eq!(crate::trap::vcpu_gate::hvf_cap_from(3, Some(2)), 1);
    }

    /// D2: vCPUs are created before the VM's first run and destroyed only at
    /// teardown (hv_gic.h). A create after the first run or after any destroy
    /// of the generation is refused.
    #[test]
    fn lifecycle_guard_refuses_a_create_after_first_run_or_destroy() {
        assert!(lifecycle_admits_create(false, None).is_ok());
        assert!(lifecycle_admits_create(true, None).is_err(), "topology sealed at first run");
        assert!(
            lifecycle_admits_create(false, Some(VcpuDestroySite::WorkerExit)).is_err(),
            "a create after a destroy is a mid-life recreate"
        );
    }

    /// One raw-API boundary: only this module names `hv_gic_*`.
    #[test]
    fn raw_hv_gic_calls_stay_in_gic_rs() {
        fn visit(dir: &std::path::Path, hits: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    if path.file_name().is_some_and(|name| name == "bin") {
                        continue; // standalone probe binaries own their own VMs
                    }
                    visit(&path, hits);
                } else if path.extension().is_some_and(|ext| ext == "rs")
                    && !path.ends_with("gic.rs")
                    && std::fs::read_to_string(&path).unwrap().contains(concat!("hv_", "gic_"))
                {
                    hits.push(path.display().to_string());
                }
            }
        }
        let mut hits = Vec::new();
        visit(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut hits);
        assert!(hits.is_empty(), "raw hv_gic_* outside gic.rs: {hits:?}");
    }

    /// The GIC exists before any vCPU of the VM: it is created inside the
    /// VM-creation funnel, after hv_vm_create returns and before the funnel
    /// hands the VM to any caller.
    #[test]
    fn gic_is_created_inside_the_vm_creation_funnel() {
        let trap = include_str!("trap.rs");
        let funnel = trap
            .split(concat!("fn create_vm_with_", "admission("))
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("create_vm_with_admission body");
        let create = funnel.find("virtual_machine_with_private_signals_blocked").expect("hv_vm_create");
        let gic = funnel.find("crate::gic::create_carrier_gic(").expect("GIC creation in the funnel");
        let handoff = funnel.rfind("Ok((").expect("hand-off");
        assert!(create < gic && gic < handoff);
    }

    /// Every vCPU is configured before it is counted or handed out, in both
    /// wrappers, and nothing else calls `vcpu_create()`.
    #[test]
    fn every_vcpu_is_configured_by_its_creation_wrapper() {
        let admission = include_str!("trap/vcpu_admission.rs");
        for wrapper in [concat!("fn create_vcpu_with_", "permit("), concat!("fn create_", "vcpu(")] {
            let body = admission
                .split(wrapper)
                .nth(1)
                .and_then(|rest| rest.split("\n}\n").next())
                .expect("wrapper body");
            let configure = body.find("crate::gic::configure_new_vcpu(").expect("configure");
            let counted = body.find("vcpu_created(").expect("counted");
            assert!(configure < counted, "{wrapper}");
        }
        let production: String = ["trap.rs", "hvf_aarch64_engine.rs"]
            .iter()
            .map(|file| std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file)).unwrap())
            .chain(
                std::fs::read_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/trap"))
                    .unwrap()
                    .map(|entry| std::fs::read_to_string(entry.unwrap().path()).unwrap_or_default()),
            )
            .collect();
        assert_eq!(production.matches(concat!(".vcpu_", "create()")).count(), 2);
    }
}
```

Add `#[cfg(all(target_os = "macos", target_arch = "aarch64"))] pub mod gic;` to
`lib.rs` next to `pub mod interrupt;`.

```bash
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib gic::tests
```

Expected: FAIL to compile (`cannot find type Mpidr`, `MpidrAllocator`,
`GicGeometry`, `hvf_cap_from`, `lifecycle_admits_create`). That compile failure is the red for the types;
`gic_is_created_inside_the_vm_creation_funnel` and
`every_vcpu_is_configured_by_its_creation_wrapper` must additionally fail on
their assertions once Step 3 makes the module compile and before Step 4 wires it.

- [ ] **Step 3: Implement the module**

Prepend to `crates/carrick-vmm-hvf/src/gic.rs` (above the test module):

```rust
//! The carrier VM's interrupt controller: Hypervisor.framework's in-kernel
//! GICv3 (`hv_gic_create`). This module is the only caller of raw `hv_gic_*`
//! (test `raw_hv_gic_calls_stay_in_gic_rs`).
//!
//! Setup follows hv_gic.h and libkrun (Apache-2.0; EL1 plan 1a "Prior art"):
//! the GIC is created after `hv_vm_create` and before any `hv_vcpu_create`;
//! each vCPU gets a unique MPIDR on its owning thread before its
//! redistributor is touched; vCPUs live for the VM's life (created before the
//! first run, destroyed only at teardown; D2, enforced here). Carrick has no
//! guest GIC driver, so this module writes what one would (GICD_CTLR, and per
//! vCPU the redistributor and ICC registers, on the owning thread).
//! `hv_vcpu_set_pending_interrupt` returns HV_UNSUPPORTED once a GIC exists;
//! the owed kick is a redistributor-pending SGI that survives `hv_vcpu_run`
//! returns (check C2, docs/perf-results/2026-09-25-hvf-gic-qualification.md).

use applevisor_sys as sys;
use carrick_hal::TrapError;
use carrick_mem::memory::{
    LINUX_GIC_DISTRIBUTOR_BASE, LINUX_GIC_DISTRIBUTOR_MAX, LINUX_GIC_REDISTRIBUTOR_BASE,
    LINUX_GIC_REDISTRIBUTOR_MAX,
};

use crate::trap::VcpuDestroySite;

/// A private (per-vCPU) GIC interrupt: SGI 0-15 or PPI 16-31.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrivateIntid(u32);

impl PrivateIntid {
    pub(crate) const fn sgi(n: u32) -> Self {
        assert!(n < 16, "SGI INTID");
        Self(n)
    }

    pub(crate) const fn ppi(n: u32) -> Self {
        assert!(n >= 16 && n < 32, "PPI INTID");
        Self(n)
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }

    const fn bit(self) -> u64 {
        1 << self.0
    }
}

/// Host kick (gate D1). Change `carrick_el1_abi::GIC_KICK_INTID` and this
/// constructor together.
pub(crate) const KICK_INTID: PrivateIntid = PrivateIntid::sgi(carrick_el1_abi::GIC_KICK_INTID);
pub(crate) const VTIMER_INTID: PrivateIntid = PrivateIntid::ppi(carrick_el1_abi::GIC_VTIMER_INTID);
/// Lower value = higher priority. The vtimer outranks the kick.
const VTIMER_PRIORITY: u8 = 0x80;
const KICK_PRIORITY: u8 = 0xa0;
/// Every Carrick priority passes the CPU-interface mask.
const ICC_PMR: u64 = 0xf0;
/// GICD_CTLR: affinity routing (ARE) + group 1 enable, as a guest GICv3
/// driver sets it; both spikes ran the vtimer PPI after a host-side write of
/// this register.
const GICD_CTLR_ARE_GRP1: u64 = 0x12;
/// Every SGI and PPI bit of the *R0 redistributor registers.
const ALL_PRIVATE: u64 = 0xffff_ffff;
const HV_BAD_ARGUMENT: sys::hv_return_t = 0xfae9_4003_u32 as sys::hv_return_t;
const HV_NO_RESOURCES: sys::hv_return_t = 0xfae9_4005_u32 as sys::hv_return_t;

/// MPIDR_EL1 affinity for GIC index `i`: RES1 bit 31, Aff1 = i / 16,
/// Aff0 = i % 16 (ICC_SGI1R_EL1's TargetList addresses Aff0 0-15 within one
/// Aff1 cluster, which the 1c SGI wake uses).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Mpidr(u64);

impl Mpidr {
    pub(crate) const fn for_index(index: u16) -> Self {
        Self((1 << 31) | ((index as u64 / 16) << 8) | (index as u64 % 16))
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

/// Affinity indices of one VM generation, one per live vCPU, lowest free first.
#[derive(Debug)]
pub(crate) struct MpidrAllocator {
    owners: Vec<Option<u64>>,
}

impl MpidrAllocator {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self { owners: vec![None; capacity] }
    }

    pub(crate) fn allocate(&mut self, vcpu: u64) -> Result<u16, TrapError> {
        if self.owners.contains(&Some(vcpu)) {
            return Err(TrapError::Hypervisor(format!("vCPU {vcpu} already holds a GIC affinity")));
        }
        let index = self.owners.iter().position(Option::is_none).ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "GIC topology full: {} redistributors in use",
                self.owners.len()
            ))
        })?;
        self.owners[index] = Some(vcpu);
        u16::try_from(index).map_err(|_| TrapError::Hypervisor("GIC index overflow".to_owned()))
    }

    pub(crate) fn release(&mut self, vcpu: u64) -> Option<u16> {
        let index = self.owners.iter().position(|owner| *owner == Some(vcpu))?;
        self.owners[index] = None;
        u16::try_from(index).ok()
    }

    pub(crate) fn live(&self) -> usize {
        self.owners.iter().filter(|owner| owner.is_some()).count()
    }
}

/// What Hypervisor.framework reports for its GIC device on this host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GicGeometry {
    pub(crate) distributor_size: u64,
    pub(crate) distributor_alignment: u64,
    pub(crate) redistributor_region_size: u64,
    pub(crate) redistributor_size: u64,
    pub(crate) redistributor_alignment: u64,
}

impl GicGeometry {
    fn query() -> Result<Self, TrapError> {
        let (mut ds, mut da, mut rr, mut rs, mut ra) = (0usize, 0usize, 0usize, 0usize, 0usize);
        // SAFETY: out-pointers to locals; these queries need no VM.
        unsafe {
            gic_check(sys::hv_gic_get_distributor_size(&mut ds), "hv_gic_get_distributor_size")?;
            gic_check(sys::hv_gic_get_distributor_base_alignment(&mut da), "hv_gic_get_distributor_base_alignment")?;
            gic_check(sys::hv_gic_get_redistributor_region_size(&mut rr), "hv_gic_get_redistributor_region_size")?;
            gic_check(sys::hv_gic_get_redistributor_size(&mut rs), "hv_gic_get_redistributor_size")?;
            gic_check(sys::hv_gic_get_redistributor_base_alignment(&mut ra), "hv_gic_get_redistributor_base_alignment")?;
        }
        Ok(Self {
            distributor_size: ds as u64,
            distributor_alignment: da as u64,
            redistributor_region_size: rr as u64,
            redistributor_size: rs as u64,
            redistributor_alignment: ra as u64,
        })
    }

    /// Fail closed when the reserved window cannot hold the device.
    pub(crate) fn fits_window(&self) -> Result<(), TrapError> {
        let ok = self.distributor_alignment != 0
            && self.redistributor_alignment != 0
            && self.redistributor_size != 0
            && LINUX_GIC_DISTRIBUTOR_BASE.is_multiple_of(self.distributor_alignment)
            && self.distributor_size <= LINUX_GIC_DISTRIBUTOR_MAX
            && LINUX_GIC_REDISTRIBUTOR_BASE.is_multiple_of(self.redistributor_alignment)
            && self.redistributor_region_size <= LINUX_GIC_REDISTRIBUTOR_MAX;
        if ok {
            Ok(())
        } else {
            Err(TrapError::Hypervisor(format!("GIC geometry does not fit the reserved window: {self:?}")))
        }
    }

    pub(crate) fn redistributor_capacity(&self) -> usize {
        (self.redistributor_region_size / self.redistributor_size.max(1)) as usize
    }
}

/// The carrier's interrupt model, read once from `CARRICK_HVF_GIC`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterruptModel {
    /// In-kernel GICv3; host kicks are a redistributor-pending SGI.
    Gic,
    /// `CARRICK_HVF_GIC=0` bisection hatch: GIC-less VM, host kicks on the SDK
    /// IRQ line through `hv_vcpu_set_pending_interrupt`.
    LegacyPendingLine,
}

/// The one reader of `CARRICK_HVF_GIC`, latched once per process. The VM, the
/// kick vehicle and (Task 9) the EL1 vector bytes all derive from it, so they
/// cannot disagree within a process. `=0` (exact string) restores the GIC-less
/// VM, the legacy pending-interrupt kick and the pre-GIC vector bytes, for
/// bisection only (EL1 plan 1c deletes the hatch).
pub(crate) fn interrupt_model() -> InterruptModel {
    static MODEL: std::sync::OnceLock<InterruptModel> = std::sync::OnceLock::new();
    *MODEL.get_or_init(|| {
        if std::env::var("CARRICK_HVF_GIC").as_deref() == Ok("0") {
            InterruptModel::LegacyPendingLine
        } else {
            InterruptModel::Gic
        }
    })
}

#[derive(Debug)]
struct CarrierGic {
    /// Custody generation of the VM this GIC belongs to.
    generation: u64,
    mpidrs: MpidrAllocator,
    allocations: u64,
    releases: u64,
    peak_live: usize,
    /// The site of this generation's most recent destroy (gate D2 guard).
    last_release_site: Option<VcpuDestroySite>,
}

/// The GIC of the carrier's one live VM generation. `None` between VM
/// generations and in the legacy model.
static CARRIER_GIC: parking_lot::Mutex<Option<CarrierGic>> = parking_lot::Mutex::new(None);

fn gic_check(rc: sys::hv_return_t, what: &str) -> Result<(), TrapError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(TrapError::Hypervisor(format!("{what}: rc={:#x}", rc as u32)))
    }
}

/// Why `create_carrier_gic` failed. `NoResources` is Hypervisor.framework's
/// `HV_NO_RESOURCES` from `hv_gic_create`, which the VM-creation funnel parks
/// and retries like `hv_vm_create`'s (check C3).
#[derive(Debug)]
pub(crate) enum GicCreateFailure {
    NoResources,
    Fatal(TrapError),
}

impl From<TrapError> for GicCreateFailure {
    fn from(error: TrapError) -> Self {
        Self::Fatal(error)
    }
}

/// Create the in-kernel GIC for the VM `hv_vm_create` just made (custody
/// generation `generation`). Called only by `create_vm_with_admission`, inside
/// the same backpressure attempt and before it hands the VM out, so it
/// precedes every `hv_vcpu_create` of that VM on every creation path.
pub(crate) fn create_carrier_gic(generation: u64) -> Result<(), GicCreateFailure> {
    if interrupt_model() != InterruptModel::Gic {
        return Ok(());
    }
    let geometry = GicGeometry::query()?;
    geometry.fits_window()?;
    // SAFETY: the config object is created, used and released here; the
    // distributor and redistributor bases lie in the reserved window, which
    // the stage-2 map boundary and stage-1 publication refuse to map.
    unsafe {
        let config = sys::hv_gic_config_create();
        if config.is_null() {
            return Err(TrapError::Hypervisor("hv_gic_config_create returned null".to_owned()).into());
        }
        let placed = gic_check(
            sys::hv_gic_config_set_distributor_base(config, LINUX_GIC_DISTRIBUTOR_BASE),
            "hv_gic_config_set_distributor_base",
        )
        .and_then(|()| {
            gic_check(
                sys::hv_gic_config_set_redistributor_base(config, LINUX_GIC_REDISTRIBUTOR_BASE),
                "hv_gic_config_set_redistributor_base",
            )
        });
        let created = match placed {
            Ok(()) => match sys::hv_gic_create(config) {
                HV_NO_RESOURCES => Err(GicCreateFailure::NoResources),
                rc => gic_check(rc, "hv_gic_create").map_err(GicCreateFailure::Fatal),
            },
            Err(error) => Err(GicCreateFailure::Fatal(error)),
        };
        sys::os_release(config);
        created?;
        let mut vtimer = 0u32;
        gic_check(
            sys::hv_gic_get_intid(sys::hv_gic_intid_t::EL1_VIRTUAL_TIMER, &mut vtimer),
            "hv_gic_get_intid(EL1_VIRTUAL_TIMER)",
        )?;
        if vtimer != VTIMER_INTID.raw() {
            return Err(TrapError::Hypervisor(format!(
                "HVF EL1 virtual timer is INTID {vtimer}, EL1 image expects {}",
                VTIMER_INTID.raw()
            )));
        }
        gic_check(
            sys::hv_gic_set_distributor_reg(sys::hv_gic_distributor_reg_t::CTLR, GICD_CTLR_ARE_GRP1),
            "GICD_CTLR",
        )?;
    }
    *CARRIER_GIC.lock() = Some(CarrierGic {
        generation,
        mpidrs: MpidrAllocator::with_capacity(geometry.redistributor_capacity()),
        allocations: 0,
        releases: 0,
        peak_live: 0,
        last_release_site: None,
    });
    Ok(())
}

/// The VM was destroyed through custody; its GIC went with it.
pub(crate) fn carrier_vm_released() {
    *CARRIER_GIC.lock() = None;
}

fn set_priority(vcpu: u64, intid: PrivateIntid, priority: u8) -> Result<(), TrapError> {
    use sys::hv_gic_redistributor_reg_t as R;
    let reg = match intid.raw() / 4 {
        0 => R::IPRIORITYR0,
        1 => R::IPRIORITYR1,
        2 => R::IPRIORITYR2,
        3 => R::IPRIORITYR3,
        4 => R::IPRIORITYR4,
        5 => R::IPRIORITYR5,
        6 => R::IPRIORITYR6,
        _ => R::IPRIORITYR7,
    };
    let shift = (intid.raw() % 4) * 8;
    let mut value = 0u64;
    // SAFETY: owning thread of a live vCPU of this VM.
    unsafe {
        gic_check(sys::hv_gic_get_redistributor_reg(vcpu, reg, &mut value), "GICR_IPRIORITYR read")?;
        value = (value & !(0xff << shift)) | (u64::from(priority) << shift);
        gic_check(sys::hv_gic_set_redistributor_reg(vcpu, reg, value), "GICR_IPRIORITYR write")
    }
}

/// Give a freshly created vCPU its affinity, then configure its
/// redistributor and CPU interface. Owning thread, before the vCPU first runs.
pub(crate) fn configure_new_vcpu(vcpu: u64) -> Result<(), TrapError> {
    if interrupt_model() == InterruptModel::LegacyPendingLine {
        return Ok(());
    }
    let index = {
        let mut guard = CARRIER_GIC.lock();
        let Some(gic) = guard.as_mut() else {
            return Err(TrapError::Hypervisor(
                "vCPU created in a GIC carrier whose VM has no GIC".to_owned(),
            ));
        };
        let index = gic.mpidrs.allocate(vcpu)?;
        gic.allocations += 1;
        gic.peak_live = gic.peak_live.max(gic.mpidrs.live());
        index
    };
    let configured = (|| {
        use sys::hv_gic_redistributor_reg_t as R;
        let enabled = KICK_INTID.bit() | VTIMER_INTID.bit();
        // SAFETY: owning thread of a live vCPU of this VM; MPIDR is set before
        // any redistributor access, as hv_gic.h requires.
        unsafe {
            gic_check(
                sys::hv_vcpu_set_sys_reg(vcpu, sys::hv_sys_reg_t::MPIDR_EL1, Mpidr::for_index(index).raw()),
                "MPIDR_EL1",
            )?;
            // Bring-up reset, as a guest GIC driver does for its CPU:
            // withdraw every private interrupt Carrick does not use, and any
            // pending or active state, before enabling its own.
            gic_check(sys::hv_gic_set_redistributor_reg(vcpu, R::ICENABLER0, ALL_PRIVATE & !enabled), "GICR_ICENABLER0")?;
            gic_check(sys::hv_gic_set_redistributor_reg(vcpu, R::ICPENDR0, ALL_PRIVATE), "GICR_ICPENDR0")?;
            gic_check(sys::hv_gic_set_redistributor_reg(vcpu, R::ICACTIVER0, ALL_PRIVATE), "GICR_ICACTIVER0")?;
            gic_check(sys::hv_gic_set_redistributor_reg(vcpu, R::IGROUPR0, enabled), "GICR_IGROUPR0")?;
        }
        set_priority(vcpu, VTIMER_INTID, VTIMER_PRIORITY)?;
        set_priority(vcpu, KICK_INTID, KICK_PRIORITY)?;
        // SAFETY: as above.
        unsafe {
            gic_check(
                sys::hv_gic_set_redistributor_reg(vcpu, sys::hv_gic_redistributor_reg_t::ISENABLER0, enabled),
                "GICR_ISENABLER0",
            )?;
            gic_check(sys::hv_gic_set_icc_reg(vcpu, sys::hv_gic_icc_reg_t::PMR_EL1, ICC_PMR), "ICC_PMR_EL1")?;
            gic_check(sys::hv_gic_set_icc_reg(vcpu, sys::hv_gic_icc_reg_t::IGRPEN1_EL1, 1), "ICC_IGRPEN1_EL1")
        }
    })();
    if configured.is_err() {
        release_vcpu_index(vcpu);
    }
    configured
}

fn release_vcpu_index(vcpu: u64) {
    if let Some(gic) = CARRIER_GIC.lock().as_mut()
        && gic.mpidrs.release(vcpu).is_some()
    {
        gic.releases += 1;
    }
}

/// Destroy a vCPU (teardown-class only, D2) and record it in one critical
/// section: the topology lock is held across `destroy` (the caller's raw
/// `hv_vcpu_destroy`) and the release, so the D2 guard in
/// `configure_new_vcpu` sees the destroy before any other thread can create
/// a vCPU with the reused HVF id. Releases in a VM generation that no longer
/// has a GIC are no-ops. The topology lock is a leaf: nothing else is locked
/// inside it.
pub(crate) fn destroy_releasing_affinity(
    vcpu: u64,
    site: VcpuDestroySite,
    destroy: impl FnOnce() -> sys::hv_return_t,
) -> sys::hv_return_t {
    let mut guard = CARRIER_GIC.lock();
    let rc = destroy();
    if rc == 0
        && let Some(gic) = guard.as_mut()
        && gic.mpidrs.release(vcpu).is_some()
    {
        gic.releases += 1;
        gic.last_release_site = Some(site);
    }
    rc
}

/// Redistributors Hypervisor.framework provides per VM, in the GIC model.
pub(crate) fn redistributor_capacity() -> Option<usize> {
    static CAPACITY: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *CAPACITY.get_or_init(|| match interrupt_model() {
        InterruptModel::Gic => GicGeometry::query().ok().map(|g| g.redistributor_capacity()),
        InterruptModel::LegacyPendingLine => None,
    })
}

/// Diagnostic view of the carrier GIC topology (signed embed tests).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GicTopologySnapshot {
    pub gic: bool,
    pub generation: u64,
    pub live: usize,
    pub peak_live: usize,
    pub allocations: u64,
    pub releases: u64,
    /// `Debug` of the last destroy site of this generation, if any.
    pub last_release_site: Option<String>,
}

pub fn gic_topology_snapshot() -> GicTopologySnapshot {
    match CARRIER_GIC.lock().as_ref() {
        Some(gic) => GicTopologySnapshot {
            gic: true,
            generation: gic.generation,
            live: gic.mpidrs.live(),
            peak_live: gic.peak_live,
            allocations: gic.allocations,
            releases: gic.releases,
            last_release_site: gic.last_release_site.map(|site| format!("{site:?}")),
        },
        None => GicTopologySnapshot::default(),
    }
}
```

The D2 lifecycle guard. Add `use carrick_fatal::carrick_fatal;` to `gic.rs`,
and above `configure_new_vcpu`:

```rust
/// Set on the generation's first `hv_vcpu_run`; reset with the GIC. hv_gic.h:
/// "Once the virtual machine vcpus are running, its topology is considered
/// final."
static TOPOLOGY_SEALED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Called by `run_to_exit` before every `hv_vcpu_run`: one relaxed load once
/// sealed.
pub(crate) fn seal_topology_before_run() {
    use std::sync::atomic::Ordering;
    if !TOPOLOGY_SEALED.load(Ordering::Relaxed) {
        TOPOLOGY_SEALED.store(true, Ordering::Release);
    }
}

/// D2: a vCPU may be created only before the generation's first run and
/// before any of its destroys (which are all teardown-class, Task 2).
fn lifecycle_admits_create(sealed: bool, last_release_site: Option<VcpuDestroySite>) -> Result<(), String> {
    match (sealed, last_release_site) {
        (false, None) => Ok(()),
        (true, _) => Err("the VM's vCPUs are already running (topology final)".to_owned()),
        (false, Some(site)) => Err(format!("the generation already destroyed a vCPU at {site:?}")),
    }
}
```

In `configure_new_vcpu`, directly before `let index = gic.mpidrs.allocate(vcpu)?;`:

```rust
        // D2: every vCPU lives for its VM's life. A create after the first run
        // or after a teardown-class destroy is a path Task 2 missed; refuse it
        // rather than rely on HVF behaviour hv_gic.h advises against.
        if let Err(reason) = lifecycle_admits_create(
            TOPOLOGY_SEALED.load(std::sync::atomic::Ordering::Acquire),
            gic.last_release_site,
        ) {
            carrick_fatal!(
                "gic::configure_new_vcpu",
                "vCPU {vcpu} created in VM generation {} under the in-kernel GIC: {reason}",
                gic.generation
            );
        }
```

In `create_carrier_gic` and `carrier_vm_released`, reset the seal with
`TOPOLOGY_SEALED.store(false, Ordering::Release)` while holding the
`CARRIER_GIC` lock. Run `python3 scripts/migrate/check-runtime-aborts.py --check`.
It names the new `carrick_fatal!` site and its fingerprint. Add that row to
`scripts/migrate/runtime-aborts/hvf.json` with:
- `"verdict": "carrier_fault"`;
- `"failure_domain": "gic::configure_new_vcpu"`;
- `"sink": "fatal"`;
- `"domain": "gic::configure_new_vcpu"`;
- the rationale "A vCPU was created after the VM's vCPUs started running or
  after one was destroyed while the in-kernel GIC is active. hv_gic.h treats
  the topology as final once vCPUs run; Carrick keeps every vCPU for the VM's
  life (EL1 plan 1a D2)."

Re-run `--check`: exit 0.

`HV_BAD_ARGUMENT` is used by Task 6's kick vehicle; if clippy reports it unused
at this step, add it in Task 6 instead.

- [ ] **Step 4: Wire the funnel, the wrappers, the destroy report and VM release**

In `create_vm_with_admission` (trap.rs), the GIC joins the creation attempt
inside the existing backpressure, and a non-resource GIC failure rolls the new
VM back through custody. Replace the `let create_result = { ... };` block and
the `match create_result {` head with:

```rust
    let create_result = {
        // Config is rebuilt per attempt inside the closure because
        // `with_config` consumes it, so an HV_NO_RESOURCES retry needs a
        // fresh one. The in-kernel GIC belongs to the same attempt: it must
        // exist before any vCPU of this VM, every VM (boot, execve rebuild,
        // shared-wait resume, fork rebuild) is created here, and its
        // HV_NO_RESOURCES parks and retries like hv_vm_create's (check C3).
        crate::probes::vm_lifecycle(0, admission.probe_code());
        create_with_no_resources_backpressure("hv_vm_create+hv_gic_create", || {
            let config = fresh_vm_config()?;
            let vm = virtual_machine_with_private_signals_blocked(config)?;
            match crate::gic::create_carrier_gic(generation.0) {
                Ok(()) => Ok(Ok(vm)),
                Err(crate::gic::GicCreateFailure::NoResources) => {
                    // Unpublished, vCPU-less and unmapped: applevisor's Drop
                    // (hv_vm_destroy) returns the VM slot before the park.
                    drop(vm);
                    Err(applevisor::error::HypervisorError::NoResources)
                }
                Err(crate::gic::GicCreateFailure::Fatal(error)) => Ok(Err((vm, error))),
            }
        })
    };
    match create_result {
        Ok(Err((vm, error))) => {
            // A VM exists: publish it so custody's rollback owns and destroys
            // it (and clears the flag through `record_vm_released`).
            CARRIER_VM_LIVE.store(true, std::sync::atomic::Ordering::Release);
            let pending = PendingCarrierVmCreation {
                custody: std::sync::Arc::clone(custody),
                generation,
                probe_code: admission.probe_code(),
                vcpu_id: None,
                armed: true,
            };
            // Custody destroys the VM; applevisor's Drop must not.
            std::mem::forget(vm);
            drop(permit);
            Err(match pending.rollback(error) {
                Err(error) => error,
                Ok(()) => TrapError::Hypervisor("GIC setup rollback reported success".to_owned()),
            })
        }
        Ok(Ok(vm)) => {
```

and leave the existing `Ok(vm)` arm body (now under `Ok(Ok(vm))`) and the
`Err(error)` arm unchanged. If `rollback` is not reachable with this exact
shape (its signature is `rollback(mut self, setup_error: TrapError) ->
Result<(), TrapError>`, carrier_custody.rs:68), follow it; do not add a second
destroy path.

If gate D5b lowered the ceiling, set `GLOBAL_VCPU_CEILING` (vcpu_admission.rs)
to the C3 GIC ceiling minus 7 and add both measured ceilings to its doc
comment ("127 VMs without a GIC, N with one; EL1 plan 1a check C3").

In `vcpu_admission.rs`, the two wrappers become:

```rust
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn create_vcpu_with_permit(
    vm: &applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    permit: Option<HeldPermitGuard>,
) -> Result<applevisor::vcpu::Vcpu, TrapError> {
    // The permit (this process's admitted soft-budget slot) is held across all
    // retries; only the terminal outcome registers or releases it.
    match create_with_no_resources_backpressure("hv_vcpu_create", || vm.vcpu_create()) {
        Ok(vcpu) => {
            if let Err(error) = crate::gic::configure_new_vcpu(vcpu.id()) {
                discard_unconfigured_vcpu(vcpu);
                drop(permit);
                return Err(error);
            }
            if let Some(permit) = permit {
                register_admission_permit(vcpu.id(), permit.into_inner());
            }
            vcpu_created();
            Ok(vcpu)
        }
        Err(e) => {
            drop(permit);
            Err(e)
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn create_vcpu(
    vm: &applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
) -> Result<applevisor::vcpu::Vcpu, TrapError> {
    // Existing-VM vCPUs (persistent pool executors, all created at pool start;
    // D2) are admitted by the in-process scheduler. Applying the VM-creation
    // permit here would duplicate that scheduler's bounded vCPU accounting.
    match vm.vcpu_create() {
        Ok(vcpu) => {
            if let Err(error) = crate::gic::configure_new_vcpu(vcpu.id()) {
                discard_unconfigured_vcpu(vcpu);
                return Err(error);
            }
            vcpu_created();
            Ok(vcpu)
        }
        Err(e) => Err(TrapError::Hypervisor(format!(
            "hv_vcpu_create (existing carrier VM): {e}"
        ))),
    }
}

/// A vCPU whose GIC configuration failed was never counted or handed out:
/// destroy it on this (owning) thread through the one raw-destroy function,
/// and never let applevisor's Drop run.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn discard_unconfigured_vcpu(vcpu: applevisor::vcpu::Vcpu) {
    let vcpu = std::mem::ManuallyDrop::new(vcpu);
    let id = vcpu.id();
    if crate::trap::destroy_raw_vcpu(id, VcpuDestroySite::CreationError) == 0 {
        vcpu_destroyed(id, VcpuDestroySite::CreationError);
    }
}
```

The VM handle type stays `VirtualMachineInstance<GicDisabled>`: applevisor
documents that a GIC-bearing instance may be held through that type, Carrick
uses none of applevisor's GIC-typed methods (only `gic.rs` touches the device),
and changing the type at 16 sites buys no check the funnel test does not.

`destroy_raw_vcpu` (trap.rs, Task 2) becomes the locked destroy:

```rust
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn destroy_raw_vcpu(vcpu_id: u64, site: VcpuDestroySite) -> applevisor_sys::hv_return_t {
    // SAFETY: the caller owns the vCPU on this thread and forgets its handle.
    crate::gic::destroy_releasing_affinity(vcpu_id, site, || unsafe {
        applevisor_sys::hv_vcpu_destroy(vcpu_id)
    })
}
```

Task 2 removed the boot vCPU's local-RAII lane, so every destroy now passes
through `destroy_raw_vcpu`. Each one is recorded under the topology lock in
the same critical section as `hv_vcpu_destroy`, so the D2 guard sees it
before any other thread can create a vCPU with a reused HVF id.
`vcpu_destroyed` (admission permit, gate wake) runs after the lock is dropped.

In `run_to_exit` (trap.rs:7330), directly before its
`vcpu.run().map_err(hvf_error)?` (trap.rs:7352, the only guest entry of the
lane), call `crate::gic::seal_topology_before_run();`. Add
`gic_seal_precedes_every_run` to `gic::tests`. It asserts that
`include_str!("trap.rs")` contains `vcpu.run()` exactly once, and that
`crate::gic::seal_topology_before_run()` appears before it in the same
function. Run it red before the edit. Task 6 renames the function to
`run_to_exit_inner`, and the test does not depend on the name.

In `record_vm_released` (vcpu_admission.rs:655), after
`CARRIER_VM_LIVE.store(false, ...)`, add `crate::gic::carrier_vm_released();`.

In `vcpu_gate.rs`, split the cap arithmetic into a pure function and clamp:

```rust
pub(crate) fn hvf_cap_budget() -> usize {
    let mut max: u32 = 0;
    let rc = unsafe { applevisor_sys::hv_vm_get_max_vcpu_count(&mut max) };
    let cap = if rc == 0 && max > 0 { i64::from(max) } else { 64 };
    hvf_cap_from(
        cap,
        crate::gic::redistributor_capacity().map(|capacity| capacity as i64),
    )
}

/// The per-VM vCPU cap less `RESERVE`, clamped to the redistributor count when
/// the VM has an in-kernel GIC (each vCPU needs its own redistributor).
pub(crate) fn hvf_cap_from(max_vcpus: i64, redistributors: Option<i64>) -> usize {
    let cap = redistributors.map_or(max_vcpus, |r| max_vcpus.min(r));
    (cap - RESERVE).max(1) as usize
}
```

(Make `vcpu_gate` reachable from `gic::tests` as `crate::trap::vcpu_gate`; if it
is private to `trap`, add `pub(crate)` to its `mod` declaration.)

- [ ] **Step 5: Run the VM-free tests green**

```bash
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib gic::tests
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib
cargo test -p carrick-el1-abi
```

Expected: all PASS, including the existing `carrier_custody.rs` ordering tests
(they slice `execve_rebuild_inner`, untouched here) and
`raw_vm_destroy_is_custody_transaction_gated` (no new raw destroy).

- [ ] **Step 6: Ledger rows**

```bash
python3 scripts/migrate/check-runtime-global-state.py --bootstrap \
  | python3 -c 'import json,sys; print(json.dumps([r for r in json.load(sys.stdin)["rows"] if r["file"].endswith("src/gic.rs")], indent=1))'
```

Add the printed rows (`CARRIER_GIC`, `interrupt_model::MODEL`,
`redistributor_capacity::CAPACITY`) with `"classification": "carrier_infra"` and
rationales: "The in-kernel GIC of the carrier's one live VM generation (MPIDR
allocator and topology counters), reset when custody releases the VM."; "Carrier
interrupt model read once from CARRICK_HVF_GIC (bisection hatch)."; "Per-VM
redistributor count reported by Hypervisor.framework, queried once." Then
`python3 scripts/migrate/check-runtime-global-state.py --check` exits 0.

- [ ] **Step 7: The topology contract (VM-free layer)**

Create `conformance-contracts/contracts/gic-topology.toml`:

```toml
schema_version = 1
id = "kernel.vcpu.gic-topology"
title = "Every carrier vCPU has a unique GIC affinity and a configured redistributor before it runs, and lives for its VM's life"
guest_surfaces = ["vmm:hvf", "scheduler:vcpu-kick", "execution:linux-aarch64"]
semantic_authority = [
  "Hypervisor.framework hv_gic.h: hv_gic_create after hv_vm_create and before any hv_vcpu_create; vCPUs set affinity values in MPIDR_EL1; once the VM's vCPUs are running its topology is final and vCPUs are destroyed only at VM teardown; redistributor registers are written by the owning thread",
  "libkrun (Apache-2.0) 85bed715: the same creation order, MPIDR on the owning thread, one vCPU per host thread for the VM's life",
  "Arm GICv3 architecture specification: affinity routing identifies a PE by MPIDR_EL1 Aff3.Aff2.Aff1.Aff0; ICC_SGI1R_EL1 TargetList addresses Aff0 0-15",
]
fixture = "unit:gic-topology"
scale_points = [1, 8, 32, 128]
rationale = "The carrier VM carries Hypervisor.framework's in-kernel GICv3, set up the reference way. It is created inside the single VM-creation funnel, so every VM generation has it before its first vCPU; both vCPU-creation wrappers give each vCPU the lowest free affinity index of that generation and configure its redistributor (bring-up reset, then kick SGI and vtimer PPI enabled, group 1, priorities) and CPU interface on the owning thread before the vCPU is counted or handed out. Every vCPU is created before the VM's first run and destroyed only at teardown: the root boots from a snapshot built as data, and a create after the first run or after any destroy of the generation is a carrier fault (D2). Destroys are recorded under the topology lock in the same critical section as hv_vcpu_destroy. The vCPU budget is clamped to the redistributor count. Two live guest processes with threads are the embed evidence: the single-process lane cannot see a duplicate affinity or a mid-life destroy."
structural_budgets = []

[bindings]
vm_free = "carrick-vmm-hvf::gic::tests::mpidr_carries_res1_and_sgi_addressable_affinity; carrick-vmm-hvf::gic::tests::mpidr_allocator_hands_out_the_lowest_free_index; carrick-vmm-hvf::gic::tests::mpidr_allocator_refuses_a_second_index_for_one_vcpu_and_a_full_topology; carrick-vmm-hvf::gic::tests::geometry_must_fit_the_reserved_window; carrick-vmm-hvf::gic::tests::a_destroy_releases_its_index_and_the_next_generation_starts_empty; carrick-vmm-hvf::gic::tests::capacity_clamps_the_vcpu_budget; carrick-vmm-hvf::gic::tests::raw_hv_gic_calls_stay_in_gic_rs; carrick-vmm-hvf::gic::tests::gic_is_created_inside_the_vm_creation_funnel; carrick-vmm-hvf::gic::tests::every_vcpu_is_configured_by_its_creation_wrapper; carrick-vmm-hvf::gic::tests::lifecycle_guard_refuses_a_create_after_first_run_or_destroy; carrick-vmm-hvf::gic::tests::gic_seal_precedes_every_run; carrick-vmm-hvf::trap::vcpu_admission::vcpu_lifetime_tests::vcpus_live_for_the_vm_lifetime"
embed = "carrick-embed::el1_gic_topology_two_processes"

[bindings.unresolved]
docker = "The GIC is a host-internal hypervisor device; Linux supplies no oracle for it. Guest-visible behaviour is unchanged and is carried by conformance-probes and the el1-gate LTP set."
embed_structural = "Topology is observed through gic_topology_snapshot() (allocations, releases, live, peak); no WorkObservation metric is registered for it."
```

In `conformance-contracts/surfaces.toml` add:

```toml
[[surfaces]]
path = "crates/carrick-vmm-hvf/src/gic.rs"
contracts = ["kernel.vcpu.gic-topology", "kernel.vcpu.kick-el0-boundary"]

[[surfaces]]
path = "crates/carrick-vmm-hvf/src/interrupt.rs"
contracts = ["kernel.vcpu.kick-el0-boundary"]

[[surfaces]]
path = "crates/carrick-vmm-hvf/tests/gic_qualification.rs"
contracts = ["kernel.vcpu.gic-topology", "kernel.vcpu.kick-el0-boundary"]

[[surfaces]]
path = "crates/carrick-vmm-hvf/tests/gic_qual/harness.rs"
contracts = ["kernel.vcpu.gic-topology", "kernel.vcpu.kick-el0-boundary"]

[[surfaces]]
path = "crates/carrick-vmm-hvf/src/trap/vcpu_gate.rs"
contracts = ["kernel.vcpu.gic-topology"]

[[surfaces]]
path = "crates/carrick-vmm-hvf/src/trap/carrier_custody.rs"
contracts = ["kernel.vcpu.gic-topology"]

[[surfaces]]
path = "crates/carrick-vmm-hvf/src/trap/persistent_executor.rs"
contracts = ["kernel.vcpu.gic-topology"]
```

If `surfaces.toml` already lists `carrier_custody.rs` or `persistent_executor.rs`, append the contract id to
that entry instead of adding a second one.

The embed binding's test is written in Task 8; `check-contracts` validates
binding syntax and ids, so run it now:

```bash
cargo run -p carrick-conformance-contract --bin check-contracts -- --root .
```

Expected: exit 0. If it rejects the not-yet-existing embed test name, put
`embed` under `[bindings.unresolved]` with "written in plan 1a Task 8"; Task 10
Step 2 moves it back once the test exists.

- [ ] **Step 8: The EL0 ID view (gate D12)**

Linux hides the GIC system-register field (`ID_AA64PFR0_EL1` bits 27:24) from
EL0; Carrick's EL0 MRS emulation returns the raw vCPU value (Fact 10). This
probe is the measurement: it runs in the production VM with the GIC that
Step 4 just enabled, so no separate experiment is needed. (libkrun ORs a GIC
field into `ID_AA64PFR0_EL1` only for nested virtualisation, which suggests
HVF may leave it clear. The probe settles it.) The other nine ID registers
the EL0 emulation returns are guarded by Task 13's row-by-row probe diff
against the base artifact.

Create `conformance-probes/src/bin/idaa64pfr0.rs`:

```rust
//! EL0 view of ID_AA64PFR0_EL1 (EL1 plan 1a, D12). Linux emulates EL0 MRS of
//! the ID registers and hides the GIC system-register field (bits 27:24), so
//! the oracle reads 0 there. Carrick's EL0 MRS emulation returned the raw
//! Hypervisor.framework value, which reports the GIC interface once the VM has
//! an in-kernel GIC. Only the hidden field is printed: the other fields differ
//! by CPU and are not a conformance fact.

use std::arch::asm;

fn main() {
    let pfr0: u64;
    // SAFETY: an unprivileged MRS that Linux emulates for EL0.
    unsafe { asm!("mrs {}, ID_AA64PFR0_EL1", out(reg) pfr0, options(nomem, nostack)) };
    println!("id_aa64pfr0_read_ok=true");
    println!("id_aa64pfr0_gic_field={}", (pfr0 >> 24) & 0xf);
}
```

Register it exactly as `ctrel0` is registered: the generic probe list in
`crates/carrick-conformance-next/tests/common/mod.rs`, one shard of the
three-way generic partition that the shard inventory tests enumerate, and
`conformance-probes/probe-inventory.json` (`"class": "conformance",
"excluded": false, "runner": "generic"`). Cross-compile both libc sets
locally (AGENTS.md: `cargo build --target aarch64-unknown-linux-{musl,gnu}`
inside `conformance-probes`, copied into `conformance-probes/target/<triple>/release/`),
then bless its Docker oracle in a Docker-only phase with the oracle refresh
described in `crates/carrick-conformance-next/README.md`; nothing else may run
during that phase. Then, Carrick only:

```bash
just build
./scripts/test-signed.sh carrick-conformance-next idaa64pfr0 --nocapture 2>&1 | tee target/el1-1a-idview-red.log
```

Expected red if HVF reports the GIC interface once a GIC exists: a DIFF on
`id_aa64pfr0_gic_field` (oracle 0, Carrick non-zero). Record it. If the probe
passes here, record that it is a regression guard rather than a red-first
proof (confirm the pass with `CARRICK_HVF_GIC=0` too), and skip the
sanitisation below.

Sanitise the EL0 view in `emulate_el0_sys64_read_inner` (cow_engine.rs), in
the `let value = match id_reg { ... }` statement:

```rust
            let value = match id_reg {
                // Linux hides the GIC system-register field from EL0; the
                // in-kernel GIC makes Hypervisor.framework report it (D12).
                Some(SysReg::ID_AA64PFR0_EL1) => {
                    vcpu.get_sys_reg(SysReg::ID_AA64PFR0_EL1).map_err(hvf_error)? & !(0xf << 24)
                }
                Some(reg) => vcpu.get_sys_reg(reg).map_err(hvf_error)?,
                None => 0,
            };
```

```bash
just build
./scripts/test-signed.sh carrick-conformance-next idaa64pfr0 --nocapture 2>&1 | tail -5
```

Expected: MATCH.

- [ ] **Step 9: Signed smoke, and the red evidence for Task 6**

```bash
just build
CARRICK_RUN_ID=gic-smoke target/release/carrick run --rm docker.io/library/ubuntu:24.04 /bin/sh -c 'echo hi; nproc' < /dev/null
CARRICK_RUN_ID=gic-smoke-0 CARRICK_HVF_GIC=0 target/release/carrick run --rm docker.io/library/ubuntu:24.04 /bin/sh -c 'echo hi; nproc' < /dev/null
scripts/sudo/kill.sh gic-smoke; scripts/sudo/kill.sh gic-smoke-0
./scripts/test-signed.sh carrick-embed page_table_pauses_survive_carrier_load --nocapture 2>&1 | tee target/el1-1a-task5-red.log
grep -a 'HV_UNSUPPORTED\|0xfae9400f\|test .*page_table_pauses\|panicked' target/el1-1a-task5-red.log
```

Expected: both smoke runs print `hi` and the same `nproc` if no kick was
absorbed in EL1 during them; `page_table_pauses_survive_carrier_load` (the pause
fix's signed binding: go-time and go-testing under four concurrent carriers,
which absorb kicks in EL1 by construction) FAILS with `HV_UNSUPPORTED` from
`hv_vcpu_set_pending_interrupt`. That failure is Task 6's signed red. If it
passes, record that no EL1-absorbed kick fired and use Task 0B's
`el1_served_loop_surfaces_kicks` run under the GIC as the red instead.

- [ ] **Step 10: Stage, do not commit**

```bash
just fmt-check
cargo clippy -p carrick-vmm-hvf -p carrick-el1-abi --all-targets -- -D warnings
git status --short
```

Leave the Task 5 changes staged in the working tree; Task 6 Step 5 commits
Tasks 5 and 6 as one change. Never `git stash` them.

---

### Task 6: The kick vehicle under the GIC (D1)

Lands together with Task 5 (one commit): Task 5 alone fails every
EL1-absorbed kick with `HV_UNSUPPORTED` (Task 5 Step 9 recorded that red).

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/gic.rs` (`arm_kick`, `clear_kick`, tests)
- Modify: `crates/carrick-vmm-hvf/src/trap.rs` (sites 7381 and 7552; `run_to_exit`
  withdraws an in-loop kick on every surfaced exit)
- Modify: `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs` (`set_pending_irq`)
- Modify: `crates/carrick-aarch64/src/owed_kick.rs` (module doc; GIC-semantics model test)
- Modify: `conformance-contracts/contracts/kick-el0-boundary.toml`

**Interfaces:**
- Produces: `pub(crate) fn gic::arm_kick(vcpu: &applevisor::vcpu::Vcpu) -> Result<(), TrapError>`,
  `pub(crate) fn gic::clear_kick(vcpu: &applevisor::vcpu::Vcpu) -> Result<(), TrapError>`.
- Keeps: `Aarch64Vcpu::set_pending_irq` / `injects_kick_irq` (trait unchanged;
  HVF still answers `true`), `OwedKick` behaviour unchanged.

The legacy vehicle relied on HVF clearing the pending line on every
`hv_vcpu_run` return. `OwedKick::settle` already withdraws the engine's owed
kick on a surfaced exit, but `run_to_exit`'s own re-arm for an EL1 critical
section (trap.rs:7381) has no settle: under the GIC its SGI would outlive a
forward or any other surfaced exit and fire later as a spurious kick. This task
gives that arm the same withdrawal.

- [ ] **Step 1: Write the failing source test**

Append to `gic::tests`:

```rust
    /// The kick vehicle is chosen in one place: no other HVF source calls the
    /// legacy pending-interrupt API, which HVF refuses once a GIC exists.
    #[test]
    fn kick_vehicle_is_chosen_in_one_place() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut hits = Vec::new();
        for file in ["trap.rs", "hvf_aarch64_engine.rs"] {
            let text = std::fs::read_to_string(src.join(file)).unwrap();
            let count = text.matches(concat!("set_pending_", "interrupt(")).count();
            if count != 0 {
                hits.push((file, count));
            }
        }
        assert!(hits.is_empty(), "legacy pending-interrupt calls outside gic.rs: {hits:?}");
    }

    /// `run_to_exit` re-arms a kick absorbed in an EL1 critical section and
    /// keeps running; under the GIC that SGI survives run returns, so every
    /// exit `run_to_exit` surfaces other than the `hvc #4` kick exit (which
    /// clears it itself) must withdraw it, as `OwedKick::settle` does for the
    /// engine's owed kick.
    #[test]
    fn run_to_exit_withdraws_an_in_loop_kick_on_every_surfaced_exit() {
        let trap = include_str!("trap.rs");
        let outer = trap
            .split(concat!("pub(crate) fn run_to_", "exit("))
            .nth(1)
            .and_then(|rest| rest.split("\n    }\n").next())
            .expect("run_to_exit");
        assert!(outer.contains("Self::run_to_exit_inner(vcpu, mailbox, &mut kick_armed)"));
        assert!(outer.contains("crate::gic::clear_kick(vcpu)"));
        let inner = trap
            .split(concat!("fn run_to_exit_", "inner("))
            .nth(1)
            .expect("run_to_exit_inner");
        assert_eq!(inner.matches("*kick_armed = true").count(), 1);
        assert_eq!(inner.matches("*kick_armed = false").count(), 1);
    }
```

```bash
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib kick_vehicle_is_chosen_in_one_place
```

```bash
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib run_to_exit_withdraws_an_in_loop_kick_on_every_surfaced_exit
```

Expected: FAIL `legacy pending-interrupt calls outside gic.rs: [("trap.rs", 2), ("hvf_aarch64_engine.rs", 1)]`,
and FAIL `run_to_exit_inner` not found. The signed red is Task 5 Step 9's
`HV_UNSUPPORTED` failure of `page_table_pauses_survive_carrier_load`.

- [ ] **Step 2: Implement the vehicle**

Append to `gic.rs` (above the tests):

```rust
fn redistributor_pending(vcpu: u64, set: bool) -> Result<(), TrapError> {
    let reg = if set {
        sys::hv_gic_redistributor_reg_t::ISPENDR0
    } else {
        sys::hv_gic_redistributor_reg_t::ICPENDR0
    };
    // SAFETY: owning thread of a live vCPU of this VM.
    let rc = unsafe { sys::hv_gic_set_redistributor_reg(vcpu, reg, KICK_INTID.bit()) };
    if rc == HV_BAD_ARGUMENT {
        return Err(TrapError::Hypervisor(format!(
            "kick SGI {} refused by the redistributor of vCPU {vcpu}",
            KICK_INTID.raw()
        )));
    }
    gic_check(rc, if set { "GICR_ISPENDR0 (kick)" } else { "GICR_ICPENDR0 (kick)" })
}

/// Make the host kick pending on `vcpu` (owning thread). GIC: the kick SGI in
/// the vCPU's redistributor; it survives `hv_vcpu_run` returns until EL1 takes
/// it or `clear_kick` withdraws it. Legacy hatch: the SDK IRQ line, which HVF
/// clears on every run return, so `OwedKick::rearm` re-arms it.
pub(crate) fn arm_kick(vcpu: &applevisor::vcpu::Vcpu) -> Result<(), TrapError> {
    match interrupt_model() {
        InterruptModel::Gic => redistributor_pending(vcpu.id(), true),
        InterruptModel::LegacyPendingLine => vcpu
            .set_pending_interrupt(crate::trap::HVF_VIRTUAL_IRQ, true)
            .map_err(|error| TrapError::Hypervisor(error.to_string())),
    }
}

/// Withdraw a host kick that surfaced by another exit.
pub(crate) fn clear_kick(vcpu: &applevisor::vcpu::Vcpu) -> Result<(), TrapError> {
    match interrupt_model() {
        InterruptModel::Gic => redistributor_pending(vcpu.id(), false),
        InterruptModel::LegacyPendingLine => vcpu
            .set_pending_interrupt(crate::trap::HVF_VIRTUAL_IRQ, false)
            .map_err(|error| TrapError::Hypervisor(error.to_string())),
    }
}
```

In `trap.rs`, rename the existing `run_to_exit` to
`fn run_to_exit_inner(vcpu: &mut applevisor::vcpu::Vcpu, mailbox: &mut MailboxBinding, kick_armed: &mut bool) -> Result<carrick_aarch64::Aarch64Exit, TrapError>`
(same body; keep its doc comment on the new outer function) and add:

```rust
    pub(crate) fn run_to_exit(
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<carrick_aarch64::Aarch64Exit, TrapError> {
        let mut kick_armed = false;
        let exit = Self::run_to_exit_inner(vcpu, mailbox, &mut kick_armed);
        // Under the GIC the kick SGI survives run returns (check C2(b));
        // a kick re-armed for an EL1 critical section that ended in
        // any other surfaced exit is withdrawn here, as the legacy line was by
        // HVF itself. The surfaced exit is the boundary the kick asked for.
        if kick_armed {
            let cleared = crate::gic::clear_kick(vcpu);
            return exit.and_then(|value| cleared.map(|()| value));
        }
        exit
    }
```

In `run_to_exit_inner`, the EL1-critical-section re-arm (was line 7381):

```rust
                crate::gic::arm_kick(vcpu)?;
                *kick_armed = true;
```

and the `hvc #4` kick exit (was line 7552):

```rust
                crate::gic::clear_kick(vcpu)?;
                *kick_armed = false;
```

In `hvf_aarch64_engine.rs`:

```rust
    fn set_pending_irq(&mut self, pending: bool) -> Result<(), TrapError> {
        if pending {
            crate::gic::arm_kick(&self.inner)
        } else {
            crate::gic::clear_kick(&self.inner)
        }
    }
```

In `crates/carrick-aarch64/src/owed_kick.rs` tests, give `ModelVcpu` a
`gic_semantics: bool` field (`false` in `at_vector_resume`). `run()` clears
`pending_irq` only when `!self.gic_semantics`, and so does the trapped
clock-read step in `run_until_exit`; the lower-EL IRQ branch of
`run_until_exit` sets `self.pending_irq = false` before returning `Kicked`
(the backend's `hvc #4` decode withdraws the kick in both models). Add:

```rust
    /// With the in-kernel GIC the kick is a redistributor-pending SGI that
    /// survives every run return, so `rearm` is an idempotent write. The owed
    /// kick must still surface at the EL0 boundary with the original PSTATE,
    /// and nothing may be left pending once it has surfaced.
    #[test]
    fn gic_pending_kick_survives_run_returns_and_surfaces_once() {
        for internal_exits in [0_u32, 8] {
            let mut vcpu = ModelVcpu::at_vector_resume(32);
            vcpu.gic_semantics = true;
            vcpu.el1_exits_before_eret = internal_exits;
            assert_eq!(
                next_surfaced(&mut vcpu),
                Surfaced::Kick {
                    pc: GUEST_PC,
                    pstate: EL0_DAIF_MASKED,
                }
            );
            assert_eq!(vcpu.el0_steps, 0);
            assert!(!vcpu.pending_irq, "a surfaced kick left the SGI pending");
        }
    }
```

Then replace the second bullet of the module doc with:

```rust
//! - Without an interrupt controller, Hypervisor.framework clears pending
//!   interrupts on EVERY `hv_vcpu_run` return (qualified with a standalone HVF
//!   probe on macOS 27.2 / M4), so any exit the loop handles internally before
//!   the IRQ is taken must re-arm it. With the in-kernel GIC (the default since
//!   EL1 plan 1a) the kick is a redistributor-pending SGI that survives run
//!   returns; the re-arm is then an idempotent write, kept because the
//!   `CARRICK_HVF_GIC=0` hatch still needs it.
```

- [ ] **Step 3: Run green (VM-free) and the signed kick evidence**

```bash
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib kick_vehicle_is_chosen_in_one_place
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib
cargo test -p carrick-aarch64 owed_kick
just build
CARRICK_RUN_ID=gic-smoke target/release/carrick run --rm docker.io/library/ubuntu:24.04 /bin/sh -c 'echo hi; nproc' < /dev/null
CARRICK_RUN_ID=gic-smoke-0 CARRICK_HVF_GIC=0 target/release/carrick run --rm docker.io/library/ubuntu:24.04 /bin/sh -c 'echo hi; nproc' < /dev/null
scripts/sudo/kill.sh gic-smoke; scripts/sudo/kill.sh gic-smoke-0
just test-embed page_table_pauses_survive_carrier_load --nocapture 2>&1 | tail -20
CARRICK_HVF_GIC=0 just test-embed page_table_pauses_survive_carrier_load --nocapture 2>&1 | tail -20
just test-embed el1_ 2>&1 | tail -5
```

Expected: all PASS; both smoke runs print `hi` and the same `nproc`;
`page_table_pauses_survive_carrier_load` (the pause fix's signed binding in
`crates/carrick-embed/tests/pt_pause_drain_pressure.rs`: go-time and go-testing
under four concurrent carriers) passes in both models, where Task 5 Step 9 saw
it fail with `HV_UNSUPPORTED`. The concurrent CLI carriers it launches inherit
`CARRICK_HVF_GIC` from the environment, so the second run exercises the hatch
end to end. The `el1_` filter includes Task 0B's served-loop test.

- [ ] **Step 4: Update the kick contract**

In `conformance-contracts/contracts/kick-el0-boundary.toml`: append to
`semantic_authority` the entry `"Hypervisor.framework hv_vcpu.h: hv_vcpu_set_pending_interrupt returns HV_UNSUPPORTED if the VM was created with a GIC device"`;
append to `rationale` the sentence: "Since EL1 plan 1a the carrier VM has the
in-kernel GIC and the kick is SGI 15 made pending in the vCPU's redistributor on
the owning thread (GICR_ISPENDR0) and withdrawn with GICR_ICPENDR0; that pending
state survives run returns, so the owed kick's re-arm is idempotent. The legacy
SDK IRQ line remains only behind the CARRICK_HVF_GIC=0 hatch. A kick re-armed
for an EL1 critical section is withdrawn on every other surfaced exit."; append
`; carrick-vmm-hvf::gic::tests::kick_vehicle_is_chosen_in_one_place; carrick-vmm-hvf::gic::tests::run_to_exit_withdraws_an_in_loop_kick_on_every_surfaced_exit; carrick-aarch64::owed_kick::tests::gic_pending_kick_survives_run_returns_and_surfaces_once`
to `bindings.vm_free`.

```bash
cargo run -p carrick-conformance-contract --bin check-contracts -- --root .
```

Expected: exit 0.

- [ ] **Step 5: Commit Tasks 5 and 6 together**

```bash
just fmt-check
cargo clippy -p carrick-vmm-hvf -p carrick-el1-abi -p carrick-aarch64 --all-targets -- -D warnings
git add crates/carrick-vmm-hvf/src/gic.rs crates/carrick-vmm-hvf/src/lib.rs crates/carrick-vmm-hvf/src/trap.rs \
  crates/carrick-vmm-hvf/src/trap/vcpu_admission.rs crates/carrick-vmm-hvf/src/trap/vcpu_gate.rs \
  crates/carrick-vmm-hvf/src/trap/cow_engine.rs \
  crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs crates/carrick-aarch64/src/owed_kick.rs \
  crates/carrick-el1-abi/src/lib.rs conformance-probes/src/bin/idaa64pfr0.rs conformance-probes/probe-inventory.json \
  crates/carrick-conformance-next \
  conformance-contracts/contracts/gic-topology.toml conformance-contracts/contracts/kick-el0-boundary.toml \
  conformance-contracts/surfaces.toml scripts/migrate/runtime-global-state.json \
  scripts/migrate/runtime-aborts/hvf.json
git status --short
git commit -F- <<'MSG'
feat(hvf): create the in-kernel GIC with every carrier VM

Why: the EL1 kernel's scheduler needs Hypervisor.framework's in-kernel
GICv3 so the virtual timer, SGIs and WFI stay inside the hypervisor.
Setup follows hv_gic.h and libkrun (Apache-2.0): hv_gic_create after
hv_vm_create and before every vCPU, a unique MPIDR on the owning thread
before the redistributor is touched, vCPUs kept for the VM's life. Once a
VM has a GIC, hv_vcpu_set_pending_interrupt returns HV_UNSUPPORTED
(hv_vcpu.h), so the kick vehicle must change in the same commit: the
GIC alone failed every EL1-absorbed kick
(`page_table_pauses_survive_carrier_load`, recorded red).

What:
- `gic.rs` is the only raw hv_gic_* caller. `create_carrier_gic` runs
  inside `create_vm_with_admission`'s backpressure attempt after
  hv_vm_create; its HV_NO_RESOURCES parks and retries, any other
  failure rolls the VM back through custody.
- Both vCPU wrappers give the vCPU the lowest free affinity index of
  the VM generation (MPIDR RES1 | Aff1 | Aff0) and configure its
  redistributor (bring-up reset, then kick SGI 15, vtimer PPI 27, group
  1, priorities) and CPU interface before it is counted: what a guest
  GIC driver would program, since Carrick has none.
- The D2 guard: a vCPU created after the VM's first run or after any
  destroy of the generation is a carrier fault (`carrick_fatal!`);
  destroys are recorded under the topology lock with hv_vcpu_destroy.
- Host kicks stay hv_vcpus_exit. `gic::arm_kick`/`clear_kick` make the
  owed kick SGI 15 pending in the vCPU's redistributor
  (GICR_ISPENDR0/ICPENDR0) and are the only owed-kick vehicle;
  `run_to_exit` withdraws a kick it re-armed for an EL1 critical
  section on every other surfaced exit. OwedKick is unchanged.
- The vCPU budget is clamped to the redistributor count; the EL0 view
  of ID_AA64PFR0_EL1 hides the GIC field as Linux does.
- `CARRICK_HVF_GIC=0`, read once in gic.rs, restores the GIC-less VM
  and the SDK IRQ line for bisection.
- Contract `kernel.vcpu.gic-topology` (VM-free layer).

Verified: gic::tests red (missing types, then the funnel, wrapper and
run_to_exit assertions) and green; `kick_vehicle_is_chosen_in_one_place`
red (3 legacy calls) then green; owed_kick model tests including GIC
semantics; `idaa64pfr0` probe <red then MATCH | regression guard>;
signed smoke and `page_table_pauses_survive_carrier_load` with and
without the hatch; el1_ embed tests. Checks C1-C3 and the reference
setup: docs/perf-results/2026-09-25-hvf-gic-qualification.md.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

Replace `<red then MATCH | regression guard>` with what Task 5 Step 8 recorded.

---

### Task 7: EL1 ABI v3 and the EL1 IRQ handler

EL1 gets a compiled Rust interrupt handler, entered through a new image-header
word, so the hand-encoded vector page only saves registers and calls it (Task 9).
Nothing can deliver an interrupt to it until Task 9 installs the window.

**Files:**
- Modify: `crates/carrick-el1-abi/src/lib.rs` (`TrapFrame.kick`, `IrqFrame`, header v3,
  IRQ and host-exit counters, `record_host_exit`, `record_vtimer_armed`, hash facts, tests)
- Create: `crates/carrick-el1/src/irq.rs`
- Modify: `crates/carrick-el1/src/lib.rs` (`pub mod irq;`), `crates/carrick-el1/src/entry.rs`
  (`carrick_el1_irq`), `crates/carrick-el1/link.ld` (header v3)
- Modify: `crates/carrick-el1-image/build.rs` (no `wfi`/`wfe`)

**Interfaces:**
- Produces in `carrick_el1_abi`:
  - `TrapFrame { x: [u64; 31], elr, spsr, esr, slot, pub kick: u64 }` (288 bytes = the
    hook's 0x120 allocation; `kick` at offset 280).
  - `#[repr(C)] pub struct IrqFrame { pub x: [u64; 31], pub elr: u64, pub spsr: u64, pub interrupted_sp: u64 }` (272 bytes = 0x110).
  - `pub const TRAP_FRAME_ALLOCATION: u64 = 0x120;`, `pub const IRQ_FRAME_SIZE: u64 = 0x110;`
  - `ImageHeader { .., pub irq_entry_offset: u64 }` at offset 32; `IMAGE_VERSION = 3`;
    `ImageAbiError::IrqEntryOutOfBounds`.
  - `Counters` gains `irq: [AtomicU64; 32]`, `irq_spurious: AtomicU64`,
    `host_exits: [AtomicU64; 256]`, `vtimer_armed_at_exit: [AtomicU64; 256]`,
    `vtimer_taken_at_exit: [AtomicU64; 256]`, `vtimer_latency_ticks: [AtomicU64; 256]`.
  - `pub fn record_host_exit(slot: usize)`, `pub fn record_vtimer_armed(slot: usize)`.
- Produces in `carrick_el1`: `pub mod irq { pub enum IrqAction { Spurious, VirtualTimer, HostKick, Unexpected }, pub const fn classify_intid(u64) -> IrqAction, pub fn interrupted_trap_frame(u64) -> Option<(usize, u64)> }`;
  image symbol `carrick_el1_irq(frame: *mut IrqFrame) -> u64`.

- [ ] **Step 1: Write the failing host tests**

Create `crates/carrick-el1/src/irq.rs` with only tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::{EL1_STACK_SIZE, EL1_STACKS_BASE, TRAP_FRAME_ALLOCATION};

    #[test]
    fn intids_classify_by_the_shared_abi_constants() {
        assert_eq!(classify_intid(1023), IrqAction::Spurious);
        assert_eq!(classify_intid(27), IrqAction::VirtualTimer);
        assert_eq!(classify_intid(u64::from(carrick_el1_abi::GIC_KICK_INTID)), IrqAction::HostKick);
        assert_eq!(classify_intid(0), IrqAction::Unexpected);
        assert_eq!(classify_intid(30), IrqAction::Unexpected);
        assert_eq!(classify_intid(32), IrqAction::Unexpected);
    }

    #[test]
    fn only_the_served_path_window_frame_is_accepted() {
        let frame = |slot: u64| EL1_STACKS_BASE + (slot + 1) * EL1_STACK_SIZE - TRAP_FRAME_ALLOCATION;
        assert_eq!(interrupted_trap_frame(frame(0)), Some((0, frame(0))));
        assert_eq!(interrupted_trap_frame(frame(255)), Some((255, frame(255))));
        assert_eq!(interrupted_trap_frame(frame(3) - 16), None, "deeper in the stack");
        assert_eq!(interrupted_trap_frame(EL1_STACKS_BASE - 8), None, "below the stacks");
        assert_eq!(interrupted_trap_frame(frame(256)), None, "past the last slot");
    }
}
```

Append to the `carrick-el1-abi` tests module:

```rust
    #[test]
    fn frames_match_the_vector_page_allocations() {
        assert_eq!(core::mem::size_of::<TrapFrame>() as u64, TRAP_FRAME_ALLOCATION);
        assert_eq!(core::mem::offset_of!(TrapFrame, kick), 280);
        assert_eq!(core::mem::size_of::<IrqFrame>() as u64, IRQ_FRAME_SIZE);
        assert_eq!(core::mem::offset_of!(IrqFrame, elr), 248);
        assert_eq!(core::mem::offset_of!(IrqFrame, spsr), 256);
        assert_eq!(core::mem::offset_of!(IrqFrame, interrupted_sp), 264);
    }

    #[test]
    fn an_image_without_an_irq_entry_is_refused() {
        extern crate std;
        let mut image = std::vec![0u8; 64];
        image[0..4].copy_from_slice(&IMAGE_MAGIC);
        image[4..8].copy_from_slice(&IMAGE_VERSION.to_le_bytes());
        image[16..24].copy_from_slice(&64u64.to_le_bytes()); // image_size
        image[24..32].copy_from_slice(&48u64.to_le_bytes()); // abi_hash_offset
        image[48..56].copy_from_slice(&EL1_ABI_LAYOUT_HASH.to_le_bytes());
        assert_eq!(check_image_abi(&image), Err(ImageAbiError::IrqEntryOutOfBounds));
        image[32..40].copy_from_slice(&40u64.to_le_bytes()); // irq_entry_offset
        assert!(check_image_abi(&image).is_ok());
    }
```

Add `pub mod irq;` to `crates/carrick-el1/src/lib.rs`, then:

```bash
cargo test -p carrick-el1-abi
cargo test -p carrick-el1 --features host-test irq
```

Expected: both FAIL to compile (`TRAP_FRAME_ALLOCATION`, `IrqFrame`,
`IrqEntryOutOfBounds`, `classify_intid` missing).

- [ ] **Step 2: Implement the ABI v3 records**

In `crates/carrick-el1-abi/src/lib.rs`:

1. `TrapFrame` gains, after `slot`:

```rust
    /// Set by the EL1 IRQ handler when the served-syscall IRQ window took the
    /// host kick: the served path then leaves through `hvc #4` (a kick at the
    /// EL0 boundary) instead of `eret`. Zeroed by the hook at entry.
    pub kick: u64,
```

   The existing layout test asserts the old size
   (`assert_eq!(core::mem::size_of::<TrapFrame>(), 280);`, lib.rs:1612); replace
   that line with
   `assert_eq!(core::mem::size_of::<TrapFrame>() as u64, TRAP_FRAME_ALLOCATION);`
   and `assert_eq!(core::mem::offset_of!(TrapFrame, slot), 272);`, so the old
   size is pinned nowhere and `slot` keeps its offset.

2. New records and constants next to `TrapFrame`:

```rust
/// Bytes the syscall vector hook allocates for a [`TrapFrame`] below the slot's
/// EL1 stack top.
pub const TRAP_FRAME_ALLOCATION: u64 = 0x120;

/// Registers the EL1 IRQ vector hook saves before calling `carrick_el1_irq`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IrqFrame {
    /// General-purpose registers x0 through x30 at the interrupt.
    pub x: [u64; 31],
    /// ELR_EL1 of the IRQ exception (the interrupted EL1 instruction).
    pub elr: u64,
    /// SPSR_EL1 of the IRQ exception.
    pub spsr: u64,
    /// SP_EL1 when the IRQ was taken. EL1 unmasks IRQs only in the
    /// served-syscall return window, where this is the slot's [`TrapFrame`].
    pub interrupted_sp: u64,
}

/// Bytes the EL1 IRQ vector hook allocates for an [`IrqFrame`].
pub const IRQ_FRAME_SIZE: u64 = 0x110;
```

3. `IMAGE_VERSION` becomes `3` (doc: "Version 3 adds the IRQ entry
   ([`ImageHeader::irq_entry_offset`])."); `ImageHeader` gains, after
   `abi_hash_offset`:

```rust
    /// Offset from the start of the image to the `carrick_el1_irq` entry point.
    pub irq_entry_offset: u64,
```

   `read_from_prefix` reads it from `bytes[32..40]`;
   `ImageAbiError` gains `IrqEntryOutOfBounds`; `check_image_abi`, after the
   version check, adds:

```rust
    if header.irq_entry_offset == 0 || header.irq_entry_offset >= header.image_size {
        return Err(ImageAbiError::IrqEntryOutOfBounds);
    }
```

   The existing test `an_image_built_against_another_layout_is_refused` sets
   `image[16..24] = 64` (image size) and `image[32..40] = 40` (IRQ entry) before
   its first assertion.

4. `Counters` gains (after `forwarded`):

```rust
    /// GIC interrupts EL1 took, by INTID (SGIs 0-15, PPIs 16-31).
    pub irq: [AtomicU64; 32],
    /// ICC_IAR1_EL1 acknowledges that returned the spurious INTID 1023.
    pub irq_spurious: AtomicU64,
    /// Host run-loop exits not caused by a host kick (neither CANCELED nor the
    /// `hvc #4` kick exit) of the vCPU leasing each mailbox slot, counted only
    /// while the vtimer probe is armed on that slot (host-written; one vCPU
    /// writes at a time, so the packed layout shares no hot line).
    pub host_exits: [AtomicU64; EL1_STACK_SLOTS as usize],
    /// `host_exits[slot]` when the host armed the vtimer probe (host-written).
    pub vtimer_armed_at_exit: [AtomicU64; EL1_STACK_SLOTS as usize],
    /// `host_exits[slot]` when EL1 took the vtimer interrupt (EL1-written).
    pub vtimer_taken_at_exit: [AtomicU64; EL1_STACK_SLOTS as usize],
    /// CNTVCT_EL0 - CNTV_CVAL_EL0 when EL1 took the vtimer interrupt.
    pub vtimer_latency_ticks: [AtomicU64; EL1_STACK_SLOTS as usize],
```

   `Counters::new` initialises each with `[const { AtomicU64::new(0) }; N]` /
   `AtomicU64::new(0)`, and `copy_snapshot` copies every new array element by
   element exactly as it copies `served`.

5. Host-side writers, next to `mark_pending_host_work`:

```rust
fn counters_on_host() -> Option<&'static Counters> {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return None;
    }
    // SAFETY: the counters page lives in the mapped EL1 region for the
    // carrier's lifetime; only atomics are touched.
    Some(unsafe { &*((ptr + EL1_COUNTERS_OFFSET as usize) as *const Counters) })
}

/// Count one non-kick host run-loop exit of the vCPU leasing mailbox `slot`
/// (the host calls this only while the vtimer probe is armed on `slot`).
pub fn record_host_exit(slot: usize) {
    if slot < EL1_STACK_SLOTS as usize
        && let Some(counters) = counters_on_host()
    {
        counters.host_exits[slot].fetch_add(1, Ordering::Relaxed);
    }
}

/// The host armed the vtimer probe on the vCPU leasing `slot`.
pub fn record_vtimer_armed(slot: usize) {
    if slot < EL1_STACK_SLOTS as usize
        && let Some(counters) = counters_on_host()
    {
        let exits = counters.host_exits[slot].load(Ordering::Relaxed);
        counters.vtimer_armed_at_exit[slot].store(exits, Ordering::Relaxed);
    }
}
```

6. `EL1_ABI_LAYOUT_HASH` `facts` gains:
   `core::mem::size_of::<IrqFrame>() as u64, core::mem::offset_of!(TrapFrame, kick) as u64,
   core::mem::offset_of!(IrqFrame, interrupted_sp) as u64, core::mem::offset_of!(Counters, irq) as u64,
   core::mem::offset_of!(Counters, host_exits) as u64, core::mem::offset_of!(Counters, vtimer_taken_at_exit) as u64,
   core::mem::offset_of!(Counters, vtimer_latency_ticks) as u64, TRAP_FRAME_ALLOCATION, IRQ_FRAME_SIZE, IMAGE_VERSION as u64,`.

7. `const _: () = assert!(core::mem::size_of::<Counters>() as u64 <= EL1_COUNTERS_SIZE);`

- [ ] **Step 3: Implement the classification**

Prepend to `crates/carrick-el1/src/irq.rs`:

```rust
//! GIC interrupts taken at EL1 (EL1 plan 1a). EL1 unmasks IRQs in exactly one
//! place: the served-syscall return window of the vector hook, with SP_EL1 on
//! the slot's TrapFrame. Classification and the frame check are pure and
//! host-tested; register access lives in `entry.rs`.

use carrick_el1_abi::{
    EL1_STACK_SIZE, EL1_STACK_SLOTS, EL1_STACKS_BASE, GIC_KICK_INTID, GIC_SPURIOUS_INTID,
    GIC_VTIMER_INTID, TRAP_FRAME_ALLOCATION,
};

/// What EL1 does with an acknowledged INTID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrqAction {
    /// 1023: nothing was pending; no EOI.
    Spurious,
    /// The EL1 virtual timer: disable it (1a arms it only as a probe), record.
    VirtualTimer,
    /// The host kick: complete it and leave the served path through `hvc #4`.
    HostKick,
    /// Anything else is Carrick corruption: complete it and fail loud.
    Unexpected,
}

pub const fn classify_intid(intid: u64) -> IrqAction {
    if intid == GIC_SPURIOUS_INTID as u64 {
        IrqAction::Spurious
    } else if intid == GIC_VTIMER_INTID as u64 {
        IrqAction::VirtualTimer
    } else if intid == GIC_KICK_INTID as u64 {
        IrqAction::HostKick
    } else {
        IrqAction::Unexpected
    }
}

/// The slot and TrapFrame address of an IRQ taken in the served-syscall
/// window, or `None` if `interrupted_sp` is anything else.
pub fn interrupted_trap_frame(interrupted_sp: u64) -> Option<(usize, u64)> {
    let offset = interrupted_sp.checked_sub(EL1_STACKS_BASE)?;
    let slot = offset / EL1_STACK_SIZE;
    if slot >= EL1_STACK_SLOTS {
        return None;
    }
    let frame = EL1_STACKS_BASE + (slot + 1) * EL1_STACK_SIZE - TRAP_FRAME_ALLOCATION;
    (interrupted_sp == frame).then_some((slot as usize, frame))
}
```

- [ ] **Step 4: Implement the image entry and header v3**

Append to `crates/carrick-el1/src/entry.rs`:

```rust
/// GIC system-register access for the IRQ entry (no FP/SIMD, no WFI).
#[cfg(target_os = "none")]
mod gic_regs {
    pub fn acknowledge() -> u64 {
        let intid: u64;
        // SAFETY: ICC_IAR1_EL1 read at EL1 with the system-register interface
        // enabled (hv_gic.h: the device supports the GIC CPU system
        // registers; the spikes and check C2 acknowledge through it).
        unsafe { core::arch::asm!("mrs {}, S3_0_C12_C12_0", out(reg) intid, options(nostack)) };
        intid
    }

    pub fn complete(intid: u64) {
        // SAFETY: ICC_EOIR1_EL1 write of an INTID this handler acknowledged.
        unsafe { core::arch::asm!("msr S3_0_C12_C12_1, {}", in(reg) intid, options(nostack)) };
    }

    pub fn vtimer_late_by() -> u64 {
        let (now, deadline): (u64, u64);
        // SAFETY: EL1 reads of the virtual counter and comparator.
        unsafe {
            core::arch::asm!("mrs {}, cntvct_el0", out(reg) now, options(nomem, nostack));
            core::arch::asm!("mrs {}, cntv_cval_el0", out(reg) deadline, options(nomem, nostack));
        }
        now.wrapping_sub(deadline)
    }

    pub fn disable_vtimer() {
        // SAFETY: EL1 write of CNTV_CTL_EL0 (ENABLE = 0); isb orders it before EOI.
        unsafe { core::arch::asm!("msr cntv_ctl_el0, xzr", "isb", options(nostack)) };
    }
}

/// EL1 GIC interrupt entry, called by the IRQ vector hook (vector page 0x2000)
/// with `frame` on the interrupted slot's EL1 stack. Returns 0.
///
/// # Safety
///
/// `frame` must point to the [`carrick_el1_abi::IrqFrame`] the hook built.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn carrick_el1_irq(frame: *mut carrick_el1_abi::IrqFrame) -> u64 {
    use core::sync::atomic::Ordering::Relaxed;
    use carrick_el1::irq::{IrqAction, classify_intid, interrupted_trap_frame};
    let counters =
        unsafe { &*(carrick_el1_abi::EL1_COUNTERS_BASE as *const carrick_el1_abi::Counters) };
    let intid = gic_regs::acknowledge();
    let action = classify_intid(intid);
    if action == IrqAction::Spurious {
        counters.irq_spurious.fetch_add(1, Relaxed);
        return 0;
    }
    let window = unsafe { frame.as_ref() }.and_then(|f| interrupted_trap_frame(f.interrupted_sp));
    let Some((slot, trap_frame)) = window else {
        gic_regs::complete(intid);
        panic!("GIC interrupt outside the served-syscall window");
    };
    match action {
        IrqAction::VirtualTimer => {
            counters.vtimer_latency_ticks[slot].store(gic_regs::vtimer_late_by(), Relaxed);
            gic_regs::disable_vtimer();
            let exits = counters.host_exits[slot].load(Relaxed);
            counters.vtimer_taken_at_exit[slot].store(exits, Relaxed);
        }
        IrqAction::HostKick => {
            // SAFETY: `interrupted_trap_frame` proved this is the slot's live
            // TrapFrame, owned by this vCPU for the whole served path.
            unsafe { (*(trap_frame as *mut carrick_el1_abi::TrapFrame)).kick = 1 };
        }
        IrqAction::Unexpected => {
            gic_regs::complete(intid);
            panic!("unexpected GIC INTID at EL1");
        }
        IrqAction::Spurious => {}
    }
    counters.irq[intid as usize].fetch_add(1, Relaxed);
    gic_regs::complete(intid);
    0
}
```

In `crates/carrick-el1/link.ld`, the header becomes:

```ld
    .header : ALIGN(8) {
        BYTE(0x43) BYTE(0x45) BYTE(0x4c) BYTE(0x31) /* "CEL1" */
        LONG(3)                                       /* version 3 */
        QUAD(carrick_el1_syscall - _image_start)      /* entry_offset */
        QUAD(_image_end - _image_start)               /* image_size */
        QUAD(CARRICK_EL1_ABI_HASH - _image_start)     /* abi_hash_offset */
        QUAD(carrick_el1_irq - _image_start)          /* irq_entry_offset */
    }
```

`EXTERN(carrick_el1_irq)` next to `ENTRY(carrick_el1_syscall)` keeps the linker
from discarding the symbol.

- [ ] **Step 5: Forbid parking instructions in the EL1 image**

In `crates/carrick-el1-image/build.rs`, in the same disassembly loop, record a
second violation class before the FP checks:

```rust
        // EL1 plan 1a: EL1 never parks. A wfi/wfe at EL1 would sleep inside
        // Hypervisor.framework's in-kernel GIC, a state 1a does not qualify
        // (check C1 covers only the running states). Parking
        // arrives with the EL1 scheduler (plan 1c) and its own contract.
        if matches!(mnemonic, "wfi" | "wfe" | "wfit" | "wfet") {
            park_violations.push(line.to_string());
            continue;
        }
```

declare `let mut park_violations = Vec::new();` beside `violations`, and after
the FP panic block:

```rust
    if !park_violations.is_empty() {
        panic!(
            "\n\nERROR: carrick-el1 image contains a parking instruction (wfi/wfe):\n  {}\n\
             EL1 must not park until the EL1 scheduler (plan 1c) lands with its wedge-recovery contract.\n\n",
            park_violations.join("\n  ")
        );
    }
```

- [ ] **Step 6: Run green**

```bash
cargo test -p carrick-el1-abi
cargo test -p carrick-el1 --features host-test
cargo build -p carrick-el1-image
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib
cargo test -p carrick-mem --lib el1
```

Expected: all PASS; `carrick-el1-image` builds (the image has no FP/SIMD and no
`wfi`). The host now refuses a v2 image, so `carrick-mem`/`carrick-vmm-hvf` tests
that load the embedded image exercise v3.

- [ ] **Step 7: Signed regression (no interrupt can reach EL1 yet)**

```bash
just build
just test-embed el1_ 2>&1 | tail -5
```

Expected: every `el1_` test passes; the IRQ entry is linked but unreachable.

- [ ] **Step 8: Commit**

```bash
just fmt-check
cargo clippy -p carrick-el1-abi -p carrick-el1 -p carrick-el1-image --all-targets -- -D warnings
git add crates/carrick-el1-abi/src/lib.rs crates/carrick-el1/src/irq.rs crates/carrick-el1/src/lib.rs \
  crates/carrick-el1/src/entry.rs crates/carrick-el1/link.ld crates/carrick-el1-image/build.rs
git commit -F- <<'MSG'
feat(el1): add a GIC interrupt entry to the EL1 image

Why: EL1 plan 1a has EL1 take and complete GIC interrupts itself (the
virtual timer with no host exit, the host kick at a syscall boundary).
The vector page is hand-encoded; the handling belongs in compiled Rust.

What:
- ABI v3: image header word `irq_entry_offset`; `IrqFrame`;
  `TrapFrame.kick` fills the hook's existing 0x120 allocation; IRQ,
  spurious, per-slot host-exit and vtimer-probe counters; shared INTIDs
  in the layout hash.
- `carrick_el1_irq` acknowledges (ICC_IAR1_EL1), accepts an interrupt
  only on a served-path TrapFrame, disables the vtimer or marks the
  kick, counts, completes (ICC_EOIR1_EL1); anything else fails loud.
- The image build refuses wfi/wfe: EL1 does not park before plan 1c.

Verified: classification, frame and header tests red then green; image
builds; signed el1_ embed tests unchanged (entry not yet reachable).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

---

### Task 8: Exit accounting, the vtimer probe, fixtures and the red signed tests

This task writes the remaining two signed tests of 1a (the served-loop kick
test exists since Task 0B) and runs them against the tree as it stands after
Task 7: the GIC exists and interrupts are configured, but EL1 never unmasks
IRQs, so the vtimer interrupt is never taken (red) and the topology binding
passes.

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/gic.rs` (vtimer probe, exit accounting),
  `crates/carrick-vmm-hvf/src/trap.rs` (`run_to_exit_inner`: probe service and exit
  accounting), `crates/carrick-vmm-hvf/src/lib.rs` (re-exports)
- Modify: `crates/carrick-runtime/src/lib.rs`, `crates/carrick-embed/src/lib.rs` (re-exports)
- Create: `fixtures/linux-aarch64-hello/src/el1_vtimer_loop.rs`
- Modify: `scripts/build-linux-fixtures.sh`
- Create: `crates/carrick-embed/tests/el1_gic.rs`
- Modify: `scripts/migrate/runtime-global-state.json`

**Interfaces:**
- Produces (pub, re-exported by carrick-runtime and carrick-embed on macOS/aarch64,
  with non-mac stubs returning `Err(VtimerProbeError::NoGic)` / `None` / default):
  `pub fn el1_vtimer_probe_arm_after_syscall(marker_nr: u64, delay_ticks: u64) -> Result<(), VtimerProbeError>`,
  `pub fn el1_vtimer_probe_slot() -> Option<usize>`,
  `pub enum VtimerProbeError { NoGic, El1Disabled }`,
  `pub fn gic_topology_snapshot() -> GicTopologySnapshot`, `pub struct GicTopologySnapshot`.
- Produces (crate): `pub(crate) fn gic::service_vtimer_probe(vcpu: &applevisor::vcpu::Vcpu, mailbox: &MailboxBinding) -> Result<(), TrapError>`,
  `pub(crate) fn gic::note_host_exit(mailbox: &MailboxBinding, host_kick: bool)`.
- Consumes: `carrick_el1_abi::{record_host_exit, record_vtimer_armed, Counters}`.

- [ ] **Step 1: The vtimer probe and exit accounting**

Append to `gic.rs` (above the tests):

```rust
/// Signed-test diagnostic: arm a one-shot EL1 virtual timer, `delay_ticks`
/// (24 MHz counter) ahead, on the vCPU that resumes the next forwarded Linux
/// syscall `marker_nr`. Proves the GIC delivers the timer to EL1 with no host
/// exit; 1a has no production timer user (plan 1c adds preemption).
static VTIMER_PROBE_MARKER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static VTIMER_PROBE_DELAY_TICKS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static VTIMER_PROBE_SLOT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtimerProbeError {
    /// `CARRICK_HVF_GIC=0`: without the in-kernel GIC the timer exits to the host.
    NoGic,
    /// `CARRICK_EL1=0`: no EL1 kernel, no IRQ window.
    El1Disabled,
}

pub fn el1_vtimer_probe_arm_after_syscall(marker_nr: u64, delay_ticks: u64) -> Result<(), VtimerProbeError> {
    use std::sync::atomic::Ordering;
    if interrupt_model() != InterruptModel::Gic {
        return Err(VtimerProbeError::NoGic);
    }
    if !carrick_mem::memory::el1_kernel_enabled() {
        return Err(VtimerProbeError::El1Disabled);
    }
    VTIMER_PROBE_SLOT.store(u64::MAX, Ordering::Relaxed);
    VTIMER_PROBE_DELAY_TICKS.store(delay_ticks, Ordering::Relaxed);
    VTIMER_PROBE_MARKER.store(marker_nr + 1, Ordering::Release);
    Ok(())
}

pub fn el1_vtimer_probe_slot() -> Option<usize> {
    let slot = VTIMER_PROBE_SLOT.load(std::sync::atomic::Ordering::Acquire);
    (slot != u64::MAX).then_some(slot as usize)
}

/// Called on the owning thread before every `hv_vcpu_run`. One relaxed load
/// when no probe is requested.
pub(crate) fn service_vtimer_probe(
    vcpu: &applevisor::vcpu::Vcpu,
    mailbox: &crate::syscall_mailbox::MailboxBinding,
) -> Result<(), TrapError> {
    use std::sync::atomic::Ordering;
    let marker = VTIMER_PROBE_MARKER.load(Ordering::Acquire);
    if marker == 0 {
        return Ok(());
    }
    let Some(slot) = mailbox.leased_slot() else {
        return Ok(());
    };
    if mailbox.diagnostics().native_nr + 1 != marker
        || VTIMER_PROBE_MARKER
            .compare_exchange(marker, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return Ok(());
    }
    let mut offset = 0u64;
    // SAFETY: owning thread of a live vCPU; CNTV_* are this vCPU's registers.
    unsafe {
        gic_check(sys::hv_vcpu_get_vtimer_offset(vcpu.id(), &mut offset), "hv_vcpu_get_vtimer_offset")?;
        let now = carrick_host::clock::monotonic_ticks().wrapping_sub(offset);
        let deadline = now + VTIMER_PROBE_DELAY_TICKS.load(Ordering::Relaxed);
        gic_check(
            sys::hv_vcpu_set_sys_reg(vcpu.id(), sys::hv_sys_reg_t::CNTV_CVAL_EL0, deadline),
            "CNTV_CVAL_EL0",
        )?;
        gic_check(sys::hv_vcpu_set_sys_reg(vcpu.id(), sys::hv_sys_reg_t::CNTV_CTL_EL0, 1), "CNTV_CTL_EL0")?;
    }
    let slot = usize::from(slot.raw());
    carrick_el1_abi::record_vtimer_armed(slot);
    VTIMER_PROBE_SLOT.store(slot as u64, Ordering::Release);
    Ok(())
}

/// Count a host run-loop exit toward the vtimer probe's "exits between arming
/// and delivery", only on the probed slot and only for exits a host kick did
/// not cause (a CANCELED exit or the `hvc #4` kick exit: the scheduler's
/// preemption quantum and page-table drains kick at will, and they carry no
/// timer). One relaxed load when no probe is armed.
pub(crate) fn note_host_exit(mailbox: &crate::syscall_mailbox::MailboxBinding, host_kick: bool) {
    let probed = VTIMER_PROBE_SLOT.load(std::sync::atomic::Ordering::Relaxed);
    if probed == u64::MAX || host_kick {
        return;
    }
    if let Some(slot) = mailbox.leased_slot()
        && u64::from(slot.raw()) == probed
    {
        carrick_el1_abi::record_host_exit(usize::from(slot.raw()));
    }
}
```

In `trap.rs` `run_to_exit_inner`, the loop head becomes:

```rust
        loop {
            crate::gic::service_vtimer_probe(vcpu, mailbox)?;
            // The engine accounts the guest CPU time via `guest_cpu::timed_run`
            // around its `vcpu.run()` call, so do NOT double-account here.
            vcpu.run().map_err(hvf_error)?;
            let exit = vcpu.get_exit_info();
            crate::gic::note_host_exit(
                mailbox,
                exit.reason == ExitReason::CANCELED
                    || (exit.reason == ExitReason::EXCEPTION
                        && is_aarch64_hvc_kick(exit.exception.syndrome)),
            );
```

(the existing `let exit = vcpu.get_exit_info();` line is the one shown; keep
everything after it unchanged).

In `crates/carrick-vmm-hvf/src/lib.rs` (macOS/aarch64 cfg, next to the other
EL1 re-exports):

```rust
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use gic::{
    GicTopologySnapshot, VtimerProbeError, el1_vtimer_probe_arm_after_syscall,
    el1_vtimer_probe_slot, gic_topology_snapshot,
};
```

In `crates/carrick-runtime/src/lib.rs` next to the `read_el1_counters` re-export:

```rust
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use carrick_vmm_hvf::{
    GicTopologySnapshot, VtimerProbeError, el1_vtimer_probe_arm_after_syscall,
    el1_vtimer_probe_slot, gic_topology_snapshot,
};

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtimerProbeError {
    NoGic,
    El1Disabled,
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GicTopologySnapshot {
    pub gic: bool,
    pub generation: u64,
    pub live: usize,
    pub peak_live: usize,
    pub allocations: u64,
    pub releases: u64,
    pub last_release_site: Option<String>,
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub fn el1_vtimer_probe_arm_after_syscall(_: u64, _: u64) -> Result<(), VtimerProbeError> {
    Err(VtimerProbeError::NoGic)
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub fn el1_vtimer_probe_slot() -> Option<usize> {
    None
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub fn gic_topology_snapshot() -> GicTopologySnapshot {
    GicTopologySnapshot::default()
}
```

In `crates/carrick-embed/src/lib.rs` extend the existing re-export:

```rust
pub use carrick_runtime::{
    GicTopologySnapshot, VtimerProbeError, el1_vtimer_probe_arm_after_syscall,
    el1_vtimer_probe_slot, gic_topology_snapshot, read_el1_counters, reset_el1_counters,
};
```

Ledger: bootstrap (`check-runtime-global-state.py --bootstrap`, rows under
`["rows"]`) and add the three `VTIMER_PROBE_*` rows as `config_debug`
("Signed-test vtimer probe request; idle in every production run: one relaxed
load per vCPU entry and one per exit.").

```bash
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib
python3 scripts/migrate/check-runtime-global-state.py --check
cargo check -p carrick-embed --tests
```

Expected: PASS, exit 0, compiles.

- [ ] **Step 2: The vtimer fixture**

Create `fixtures/linux-aarch64-hello/src/el1_vtimer_loop.rs`:

```rust
//! EL1 plan 1a: a loop of EL1-served syscalls after one forwarded marker.
//! The host arms the vtimer probe when it resumes the marker (getppid); the
//! EL1 IRQ window of a later served lseek must take the timer with no exit.
#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::{exit, syscall0, syscall3, syscall4};

const SYS_OPENAT: u64 = 56;
const SYS_LSEEK: u64 = 62;
const SYS_WRITE: u64 = 64;
const SYS_GETPPID: u64 = 173;
const AT_FDCWD: u64 = (-100_i64) as u64;
const O_RDWR_CREAT_TRUNC: u64 = 0o2 | 0o100 | 0o1000;
const WARMUP: u64 = 1_000;
const LOOP: u64 = 2_000_000;

static PATH: [u8; 21] = *b"/tmp/el1_vtimer_loop\0";
static OK: [u8; 15] = *b"vtimer loop ok\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, O_RDWR_CREAT_TRUNC, 0o600);
        if fd < 0 {
            exit(10);
        }
        if syscall3(SYS_WRITE, fd as u64, OK.as_ptr() as u64, 1) != 1 {
            exit(11);
        }
        for _ in 0..WARMUP {
            if syscall3(SYS_LSEEK, fd as u64, 0, 0) != 0 {
                exit(12);
            }
        }
        // The marker: forwarded to the host, which arms the probe on resume.
        let _ = syscall0(SYS_GETPPID);
        for _ in 0..LOOP {
            if syscall3(SYS_LSEEK, fd as u64, 0, 0) != 0 {
                exit(13);
            }
        }
        if syscall3(SYS_WRITE, 1, OK.as_ptr() as u64, OK.len() as u64) != OK.len() as i64 {
            exit(14);
        }
        exit(0);
    }
}
```

Add to `scripts/build-linux-fixtures.sh` after the `el1_served_loop_kick` line
(Task 0B):

```bash
build_fixture "el1_vtimer_loop.rs" "carrick-linux-aarch64-el1-vtimer-loop"
```

```bash
scripts/build-linux-fixtures.sh
ls -l fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-el1-vtimer-loop
```

Expected: the binary exists (the fixture uses no atomics and no runtime
indexing, so it links without core, as Task 0B's does).

- [ ] **Step 3: Write the signed tests**

Create `crates/carrick-embed/tests/el1_gic.rs`:

```rust
//! EL1 plan 1a signed tests: the in-kernel GIC in the production VM.
//!
//! Run ONLY through `just test-embed el1_gic` (scripts/test-signed.sh) after
//! `scripts/build-linux-fixtures.sh`: HV_DENIED is a failure, never a skip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

use carrick_embed::{
    Carrier, EmbedError, PullPolicy, el1_vtimer_probe_arm_after_syscall, el1_vtimer_probe_slot,
    gic_topology_snapshot, read_el1_counters, reset_el1_counters,
};

const SYS_GETPPID: u64 = 173;
const SYS_LSEEK: usize = 62;
const VTIMER_INTID: usize = 27;
/// 1 ms of the 24 MHz virtual counter.
const ONE_MS_TICKS: u64 = 24_000;

fn carrier_or_fail() -> Carrier {
    for _ in 0..50 {
        match Carrier::new() {
            Ok(carrier) => return carrier,
            Err(EmbedError::Entitlement) => panic!(
                "HV_DENIED (0xfae94007): run through scripts/test-signed.sh; a bare cargo test cannot boot a guest"
            ),
            Err(EmbedError::CarrierAlreadyActive) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("carrier initialization failed: {error}"),
        }
    }
    panic!("carrier initialization timed out waiting for a prior carrier to retire");
}

fn fixture(name: &str) -> (PathBuf, String) {
    let path = common::repo_root().join(format!(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/{name}"
    ));
    assert!(path.exists(), "{}: run scripts/build-linux-fixtures.sh first", path.display());
    let dir = path.parent().expect("fixture dir").to_string_lossy().into_owned();
    (path, dir)
}

/// Contract `kernel.el1.gic-vtimer`: the guest virtual timer, armed while the
/// guest loops on EL1-served syscalls, is taken and completed at EL1 exactly
/// once, with zero host exits between arming and delivery other than host
/// kicks (which carry no timer), in the production VM. Under the GIC a timer
/// the guest does not take produces no exit at all (the production run loop
/// has no VTIMER_ACTIVATED arm), so delivery at EL1 plus a completed guest is
/// the semantic claim; the exit count is the structural one.
#[test]
fn el1_gic_vtimer_reaches_el1_without_host_exits() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let (_, dir) = fixture("carrick-linux-aarch64-el1-vtimer-loop");
    el1_vtimer_probe_arm_after_syscall(SYS_GETPPID, ONE_MS_TICKS)
        .expect("the production VM has the in-kernel GIC and the EL1 kernel");
    let carrier = carrier_or_fail();
    let result = common::run_or_fail(
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/p/carrick-linux-aarch64-el1-vtimer-loop".to_owned()])
            .mount_readonly(dir, "/p")
            .run_blocking(),
    );
    assert!(result.success(), "exit {} signal {:?}", result.exit_code, result.signal);
    assert_eq!(result.stdout_utf8(), "vtimer loop ok\n");
    let slot = el1_vtimer_probe_slot().expect("the host armed the probe on the marker's resume");
    let counters = read_el1_counters().expect("EL1 counters");
    let taken = counters.irq[VTIMER_INTID].load(Ordering::Relaxed);
    let armed_at = counters.vtimer_armed_at_exit[slot].load(Ordering::Relaxed);
    let taken_at = counters.vtimer_taken_at_exit[slot].load(Ordering::Relaxed);
    let late = counters.vtimer_latency_ticks[slot].load(Ordering::Relaxed);
    let served = counters.served[SYS_LSEEK].load(Ordering::Relaxed);
    println!(
        "el1-gic-vtimer slot={slot} taken={taken} armed_at_exit={armed_at} taken_at_exit={taken_at} \
         late_ticks={late} served_lseek={served}"
    );
    assert_eq!(taken, 1, "the vtimer interrupt was taken at EL1 exactly once");
    assert_eq!(taken_at - armed_at, 0, "zero non-kick host exits between arming and delivery");
    assert!(served >= 2_000_000, "the loop was served at EL1: {served}");
    drop(carrier);
}

/// Contract `kernel.vcpu.gic-topology`: two live guest processes with worker
/// threads run under the GIC, then a second root boots in the same carrier
/// (the case that destroyed a boot vCPU mid-life before D2). Every vCPU the
/// carrier created holds a distinct affinity and none was destroyed while the
/// carrier lives.
#[test]
fn el1_gic_topology_two_processes() {
    let _guard = common::guest_lock();
    let (_, dir) = fixture("carrick-linux-aarch64-scheduler-preemption");
    let carrier = carrier_or_fail();
    let result = common::run_or_fail(
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "/p/carrick-linux-aarch64-scheduler-preemption & /p/carrick-linux-aarch64-scheduler-preemption & wait".to_owned(),
            ])
            .mount_readonly(dir, "/p")
            .run_blocking(),
    );
    assert!(result.success(), "exit {} signal {:?}", result.exit_code, result.signal);
    assert_eq!(result.stdout_utf8().matches("preemption ok").count(), 2);
    let after_first = gic_topology_snapshot();
    // A later root in the same carrier boots without a vCPU (Task 2).
    let second = common::run_or_fail(
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh".to_owned(), "-c".to_owned(), "echo second-root".to_owned()])
            .run_blocking(),
    );
    assert!(second.success(), "second root: exit {} signal {:?}", second.exit_code, second.signal);
    let topology = gic_topology_snapshot();
    println!("el1-gic-topology {after_first:?} -> {topology:?}");
    assert!(topology.gic, "the production VM has the in-kernel GIC");
    assert!(topology.live >= 2, "more than one vCPU live: {topology:?}");
    assert_eq!(topology.releases, 0, "a vCPU was destroyed while the carrier lives (D2): {topology:?}");
    assert_eq!(topology.allocations, topology.live as u64, "{topology:?}");
    assert_eq!(topology.allocations, after_first.allocations, "the second root created a vCPU: {topology:?}");
    assert!(topology.peak_live >= topology.live);
    drop(carrier);
}
```

- [ ] **Step 4: Run red and record the red evidence**

```bash
just build
just test-embed el1_gic --nocapture 2>&1 | tee target/el1-gic-red.log
grep -a 'el1-gic-\|test el1_\|panicked' target/el1-gic-red.log
```

The `el1_gic` filter runs the vtimer and topology tests.

Expected, and required before Task 9:
- `el1_gic_vtimer_reaches_el1_without_host_exits` FAILS with
  `the vtimer interrupt was taken at EL1 exactly once ... left: 0 right: 1`
  (the timer fired into the redistributor, but EL1 never unmasks IRQs yet), and
  the guest itself completes (`vtimer loop ok`), proving no VTIMER_ACTIVATED exit
  crashed it.
- `el1_gic_topology_two_processes` PASSES (topology is Task 5's; this is its
  signed binding).

Append the red lines to `docs/perf-results/2026-09-25-hvf-gic-qualification.md`
under "Red evidence (Task 8)".

- [ ] **Step 5: Commit the red test with the infrastructure**

```bash
just fmt-check
cargo clippy -p carrick-vmm-hvf -p carrick-runtime -p carrick-embed --all-targets -- -D warnings
git add crates/carrick-vmm-hvf/src/gic.rs crates/carrick-vmm-hvf/src/trap.rs crates/carrick-vmm-hvf/src/lib.rs \
  crates/carrick-runtime/src/lib.rs crates/carrick-embed/src/lib.rs \
  fixtures/linux-aarch64-hello/src/el1_vtimer_loop.rs scripts/build-linux-fixtures.sh \
  crates/carrick-embed/tests/el1_gic.rs scripts/migrate/runtime-global-state.json \
  docs/perf-results/2026-09-25-hvf-gic-qualification.md
git commit -F- <<'MSG'
test(el1): red signed test for GIC timer delivery at EL1

Why: EL1 plan 1a must prove, in the production VM, that the guest
virtual timer reaches EL1 with no host exit carrying it, and that
every carrier vCPU holds a distinct GIC affinity with two live guest
processes.

What:
- A signed-test vtimer probe that arms CNTV on the vCPU resuming a
  marker syscall, and per-slot accounting of the non-kick host exits of
  the probed vCPU (idle in production: one relaxed load per entry and
  per exit).
- Fixture el1_vtimer_loop (1,000 + 2,000,000 served lseeks around a
  getppid marker).
- Signed tests el1_gic_vtimer_reaches_el1_without_host_exits and
  el1_gic_topology_two_processes.

Verified (red, as intended before the EL1 IRQ window): vtimer taken 0
times with the guest completing; topology passes. Log:
docs/perf-results/2026-09-25-hvf-gic-qualification.md.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

---

### Task 9: The EL1 IRQ window, the IRQ hook and the kick tail (D8)

**Files:**
- Modify: `crates/carrick-mem/src/memory.rs`, `crates/carrick-mem/src/memory/el1_clock.rs` (tests)
- Modify: `crates/carrick-vmm-hvf/src/gic.rs` (`el1_irq_mode`), `crates/carrick-vmm-hvf/src/lib.rs` (re-export)
- Modify: `crates/carrick-runtime/src/runtime.rs` (`with_hvf_syscall_mailbox`)
- Modify: `crates/carrick-embed/tests/el1_kick_served_loop.rs` (only if gate D11 ignored the test)

**Interfaces:**
- Produces: `pub enum El1IrqMode { None, GicWindow }`;
  `pub fn el1_vectors_bytes_mailbox_configured(identity_fast_path: bool, fd_ceiling: bool, el1_enabled: bool, irq: El1IrqMode) -> Vec<u8>`;
  `pub fn el1_vectors_bytes_mailbox_clock(identity_fast_path: bool, fd_ceiling: bool, irq: El1IrqMode) -> Vec<u8>`;
  `AddressSpace::with_el1_vectors_mailbox_clock(self, identity_fast_path: bool, fd_ceiling: bool, irq: El1IrqMode)`;
  `const EL1_IRQ_HOOK_OFFSET: usize = 0x2000;` `fn write_el1_irq_hook(bytes: &mut [u8], hook_offset: usize)`;
  encoders `enc_tbz`, `enc_tbnz`, `enc_cbnz_xn`;
  `pub fn carrick_vmm_hvf::gic::el1_irq_mode() -> carrick_mem::memory::El1IrqMode` (re-exported).
- Consumes: `carrick_el1_abi::{IRQ_FRAME_SIZE, TRAP_FRAME_ALLOCATION, EL1_REGION_BASE, EL1_IMAGE_OFFSET}`,
  `el1_kernel_enabled`, `gic::interrupt_model()`.

The IRQ mode is an argument, not an environment read in `carrick-mem`: the HVF
runtime passes `gic::el1_irq_mode()`, which derives from the same latched
`interrupt_model()` that decides whether the VM has a GIC and which kick
vehicle runs, so the vector bytes and the VM cannot disagree within a process
(a GicWindow page on a GIC-less VM would reach `mrs ICC_IAR1_EL1`, which is
UNDEFINED without a GIC, and die as `GuestAtEl1`).

The window sits on the served path only, after `pending_host_work` sends
work-carrying calls to the forward path, while `SP_EL1` still points at the
TrapFrame, and BEFORE `ELR_EL1`/`SPSR_EL1` are reloaded from the TrapFrame.
Taking an IRQ overwrites `ELR_EL1`/`SPSR_EL1` with the window's own return
state (the IRQ hook saves and restores exactly those so it can return into the
window), so a reload done before the window would leave the tail's `eret`, or
the kick tail's `hvc #4` (whose host handler sets PC/CPSR from
`ELR_EL1`/`SPSR_EL1`, trap.rs:7550-7558), pointing back into the vector page at
EL1. After the reload the path re-checks `ISR_EL1.I` and re-enters the window
if an interrupt arrived in between (a kick absorbed between the window and the
reload is re-armed by the host and would otherwise wait for the next surfaced
exit, the Fact 9 hole). The IRQ hook pushes its frame below the TrapFrame on
the slot's EL1 stack. The forward path needs no window: it exits through
`hvc #2`, which surfaces a pending kick anyway. The window is gated on
`ISR_EL1.I`, so a syscall with nothing pending pays two `mrs` and two
`tbz`/`tbnz`.

- [ ] **Step 1: Pin today's bytes, then write the failing tests**

Append to `memory.rs` `mod tests`:

```rust
    fn fnv1a(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }

    /// The `CARRICK_HVF_GIC=0` hatch must restore today's exact vector bytes.
    #[test]
    fn gic_hatch_vector_bytes_are_unchanged() {
        for (identity, fd_ceiling, el1, pinned) in PRE_GIC_VECTOR_HASHES {
            let bytes = el1_vectors_bytes_mailbox_configured(identity, fd_ceiling, el1, El1IrqMode::None);
            assert_eq!(fnv1a(&bytes), pinned, "identity={identity} fd_ceiling={fd_ceiling} el1={el1}");
        }
    }
```

Pin the constant before touching the emitter: add, temporarily, at the top of
the test module

```rust
    #[test]
    fn print_pre_gic_vector_hashes() {
        for identity in [false, true] {
            for fd_ceiling in [false, true] {
                for el1 in [false, true] {
                    let bytes = el1_vectors_bytes_mailbox_configured(identity, fd_ceiling, el1);
                    println!("({identity}, {fd_ceiling}, {el1}, {:#018x}),", fnv1a(&bytes));
                }
            }
        }
    }
```

```bash
cargo test -p carrick-mem --lib print_pre_gic_vector_hashes -- --nocapture 2>&1 | grep '^('
```

Paste the eight printed tuples into

```rust
    const PRE_GIC_VECTOR_HASHES: [(bool, bool, bool, u64); 8] = [
        /* the eight printed lines */
    ];
```

and delete `print_pre_gic_vector_hashes`. Then add the behaviour tests:

```rust
    fn word(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    const MSR_DAIFCLR_I: u32 = 0xD503_42FF;
    const MSR_DAIFSET_I: u32 = 0xD503_42DF;
    const ISB: u32 = 0xD503_3FDF;
    const MRS_X2_ISR_EL1: u32 = 0xD538_C102;
    const MSR_ELR_EL1_X2: u32 = 0xD518_4022;
    const MSR_SPSR_EL1_X2: u32 = 0xD518_4002;
    const MOV_SP_X17: u32 = 0x9100_023F;
    const WFI: u32 = 0xD503_207F;
    const WFE: u32 = 0xD503_205F;

    fn find(bytes: &[u8], from: usize, to: usize, op: u32) -> Option<usize> {
        (from..to).step_by(4).find(|&offset| word(bytes, offset) == op)
    }

    #[test]
    fn gic_window_installs_the_irq_hook_only_with_the_gic() {
        let gic = el1_vectors_bytes_mailbox_configured(true, true, true, El1IrqMode::GicWindow);
        let none = el1_vectors_bytes_mailbox_configured(true, true, true, El1IrqMode::None);
        assert_eq!(word(&gic, 0x280), enc_b(0x280, EL1_IRQ_HOOK_OFFSET as u64));
        assert_eq!(word(&none, 0x280), AARCH64_ERET_OPCODE);
        assert_eq!(word(&gic, 0x480), AARCH64_HVC_KICK_OPCODE, "lower-EL IRQ slot unchanged");
        assert_eq!(word(&gic, EL1_IRQ_HOOK_OFFSET), 0xD104_43FF, "sub sp, sp, #0x110");
    }

    #[test]
    fn served_path_window_unmasks_before_reloading_elr_spsr_then_rechecks() {
        let bytes = el1_vectors_bytes_mailbox_configured(true, true, true, El1IrqMode::GicWindow);
        let hook = EL1_VECTOR_HOOK_OFFSET;
        let end = EL1_IRQ_HOOK_OFFSET;
        let isr = find(&bytes, hook, end, MRS_X2_ISR_EL1).expect("ISR check");
        assert_eq!(word(&bytes, isr + 4), enc_tbz(2, 7, 16), "skip the window when ISR_EL1.I is clear");
        assert_eq!(word(&bytes, isr + 8), MSR_DAIFCLR_I);
        assert_eq!(word(&bytes, isr + 12), ISB);
        assert_eq!(word(&bytes, isr + 16), MSR_DAIFSET_I);
        // Taking an IRQ overwrites ELR/SPSR, so both are reloaded from the
        // TrapFrame only after the window closes.
        let elr = find(&bytes, isr, end, MSR_ELR_EL1_X2).expect("ELR reloaded after the window");
        let spsr = find(&bytes, isr, end, MSR_SPSR_EL1_X2).expect("SPSR reloaded after the window");
        assert!(isr + 16 < elr && isr + 16 < spsr);
        assert!(find(&bytes, hook, isr, MSR_ELR_EL1_X2).is_none(), "no ELR reload before the window");
        let recheck = find(&bytes, spsr, end, MRS_X2_ISR_EL1).expect("ISR re-check after the reload");
        assert_eq!(
            word(&bytes, recheck + 4),
            enc_tbnz(2, 7, isr as i64 - (recheck + 4) as i64),
            "an interrupt that arrived after the window re-enters it"
        );
        let sp = find(&bytes, recheck, end, MOV_SP_X17).expect("SP_EL1 restored after the re-check");
        let kick = find(&bytes, sp, end, AARCH64_HVC_KICK_OPCODE).expect("kick tail");
        let eret = find(&bytes, sp, end, AARCH64_ERET_OPCODE).expect("normal tail");
        assert!(eret < kick, "the normal tail precedes the kick tail");
    }

    /// Executes the GIC served-path tail from the IRQ window to its `eret` or
    /// kick `hvc #4`, taking a simulated IRQ at the window's `msr daifclr`:
    /// hardware overwrites ELR_EL1/SPSR_EL1 with the window's own EL1 return
    /// state, and the IRQ hook restores exactly those before returning into
    /// the window. `late` also raises a second interrupt after the reload (a
    /// kick absorbed between the window and the reload). Whatever happens,
    /// the tail must leave with the TrapFrame's ELR/SPSR (EL0).
    #[test]
    fn served_path_window_leaves_with_the_trap_frame_return_state_after_an_irq() {
        const FRAME: u64 = 0x8_0000;
        const FRAME_ELR: u64 = 0x0040_1234;
        const FRAME_SPSR: u64 = 0x3c0; // EL0t, DAIF masked
        const WINDOW_SPSR: u64 = 0x345; // EL1h with I clear: the IRQ's own state
        for (kick, late) in [(false, false), (true, false), (false, true), (true, true)] {
            let bytes = el1_vectors_bytes_mailbox_configured(true, true, true, El1IrqMode::GicWindow);
            let start =
                find(&bytes, EL1_VECTOR_HOOK_OFFSET, EL1_IRQ_HOOK_OFFSET, MRS_X2_ISR_EL1).expect("window");
            let mut regs = [0u64; 32];
            regs[16] = FRAME;
            regs[17] = 3; // mailbox slot
            let mut mem = std::collections::BTreeMap::<u64, u64>::new();
            mem.insert(FRAME + 248, FRAME_ELR);
            mem.insert(FRAME + 256, FRAME_SPSR);
            let (mut elr, mut spsr) = (0xdead_0000_u64, 0x3c5_u64);
            let (mut irq_pending, mut late_pending, mut irqs_taken) = (true, late, 0);
            let mut pc = start;
            let exit = loop {
                let op = word(&bytes, pc);
                let next = pc + 4;
                let rt = (op & 31) as usize;
                let rn = ((op >> 5) & 31) as usize;
                pc = match op {
                    MRS_X2_ISR_EL1 => {
                        regs[2] = if irq_pending { 1 << 7 } else { 0 };
                        next
                    }
                    MSR_DAIFCLR_I => {
                        if irq_pending {
                            elr = next as u64;
                            spsr = WINDOW_SPSR;
                            irq_pending = false;
                            irqs_taken += 1;
                            if kick {
                                mem.insert(FRAME + 280, 1); // carrick_el1_irq marks the kick
                            }
                        }
                        next
                    }
                    ISB | MSR_DAIFSET_I | MOV_SP_X17 => next,
                    MSR_ELR_EL1_X2 => {
                        elr = regs[2];
                        next
                    }
                    MSR_SPSR_EL1_X2 => {
                        spsr = regs[2];
                        if std::mem::take(&mut late_pending) {
                            irq_pending = true;
                        }
                        next
                    }
                    AARCH64_ERET_OPCODE => break "eret",
                    AARCH64_HVC_KICK_OPCODE => break "hvc4",
                    0x8B11_2031 => {
                        regs[17] = regs[1] + (regs[17] << 8); // add x17, x1, x17, lsl #8
                        next
                    }
                    op if op & 0x7E00_0000 == 0x3600_0000 => {
                        // tbz / tbnz
                        let bit = ((op >> 19) & 31) | ((op >> 31) << 5);
                        let set = regs[rt] & (1 << bit) != 0;
                        let taken = if op & (1 << 24) != 0 { set } else { !set };
                        let d = ((((op >> 5) & 0x3FFF) << 18) as i32 >> 18) as i64 * 4;
                        if taken { (pc as i64 + d) as usize } else { next }
                    }
                    op if op & 0xFF00_0000 == 0xB500_0000 => {
                        // cbnz xt
                        let d = ((((op >> 5) & 0x7FFFF) << 13) as i32 >> 13) as i64 * 4;
                        if regs[rt] != 0 { (pc as i64 + d) as usize } else { next }
                    }
                    op if op & 0xFFC0_0000 == 0xF940_0000 => {
                        // ldr xt, [xn, #imm]
                        let addr = regs[rn] + u64::from((op >> 10) & 0xFFF) * 8;
                        regs[rt] = *mem.get(&addr).unwrap_or(&0);
                        next
                    }
                    op if op & 0xFF80_0000 == 0xD280_0000 => {
                        regs[rt] = u64::from((op >> 5) & 0xFFFF) << (((op >> 21) & 3) * 16);
                        next
                    }
                    op if op & 0xFF80_0000 == 0xF280_0000 => {
                        let shift = ((op >> 21) & 3) * 16;
                        regs[rt] = (regs[rt] & !(0xFFFF << shift)) | (u64::from((op >> 5) & 0xFFFF) << shift);
                        next
                    }
                    _ => panic!("unsupported opcode {op:08x} at {pc:#x}"),
                };
            };
            assert_eq!(irqs_taken, if late { 2 } else { 1 }, "kick={kick} late={late}");
            assert_eq!(
                (elr, spsr),
                (FRAME_ELR, FRAME_SPSR),
                "kick={kick} late={late}: the tail must leave with the TrapFrame's return state"
            );
            assert_eq!(exit, if kick { "hvc4" } else { "eret" }, "kick={kick} late={late}");
        }
    }

    #[test]
    fn el1_irq_hook_saves_and_restores_every_register() {
        let bytes = el1_vectors_bytes_mailbox_configured(true, true, true, El1IrqMode::GicWindow);
        let hook = EL1_IRQ_HOOK_OFFSET;
        for r in 0..=30u32 {
            let off = u64::from(r) * 8;
            assert!(find(&bytes, hook, hook + 0x400, enc_str_xt_sp(r, off)).is_some(), "save x{r}");
            assert!(find(&bytes, hook, hook + 0x400, enc_ldr_xt_sp(r, off)).is_some(), "restore x{r}");
        }
        let add = find(&bytes, hook, hook + 0x400, 0x9104_43FF).expect("add sp, sp, #0x110");
        assert_eq!(word(&bytes, add + 4), AARCH64_ERET_OPCODE);
    }

    #[test]
    fn vector_page_never_parks() {
        for irq in [El1IrqMode::None, El1IrqMode::GicWindow] {
            let bytes = el1_vectors_bytes_mailbox_configured(true, true, true, irq);
            assert!(find(&bytes, 0, bytes.len(), WFI).is_none() && find(&bytes, 0, bytes.len(), WFE).is_none());
        }
    }
```

```bash
cargo test -p carrick-mem --lib -- gic_ served_path_window el1_irq_hook vector_page_never_parks
```

Expected: FAIL to compile (`El1IrqMode`, 4-argument
`el1_vectors_bytes_mailbox_configured`, `EL1_IRQ_HOOK_OFFSET`, `enc_tbz`,
`enc_tbnz`). Once Step 3 compiles, the machine test is the red-first proof of
the ordering: with the reload placed before the window (the order an earlier
draft of this plan used) it fails with `(elr, spsr)` equal to the window's own
return state.

- [ ] **Step 2: Implement the encoders, the mode and the IRQ hook**

In `memory.rs` next to `enc_cbz_wn`:

```rust
/// `tbz xt, #bit, <pc + offset>`; `offset` in bytes, a multiple of 4.
fn enc_tbz(rt: u32, bit: u32, offset: i64) -> u32 {
    let imm14 = ((offset >> 2) as u32) & 0x3FFF;
    0x3600_0000 | ((bit >> 5) << 31) | ((bit & 0x1F) << 19) | (imm14 << 5) | (rt & 0x1F)
}

/// `tbnz xt, #bit, <pc + offset>`; `offset` in bytes, a multiple of 4.
fn enc_tbnz(rt: u32, bit: u32, offset: i64) -> u32 {
    enc_tbz(rt, bit, offset) | (1 << 24)
}

/// `cbnz xn, <target>`.
fn enc_cbnz_xn(reg: u32, pc: u64, target: u64) -> u32 {
    let imm19 = (((target as i64 - pc as i64) >> 2) as u32) & 0x7FFFF;
    0xB500_0000 | (imm19 << 5) | (reg & 0x1F)
}
```

Next to `EL1_VECTOR_HOOK_OFFSET`:

```rust
/// Whether the EL1 syscall hook opens an IRQ window on its served path, and
/// the current-EL IRQ slot calls the EL1 image's IRQ entry. Only with the
/// in-kernel GIC: without it the only IRQ source is the legacy owed-kick line,
/// which must stay an EL0-boundary `hvc #4`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum El1IrqMode {
    None,
    GicWindow,
}

const EL1_IRQ_HOOK_OFFSET: usize = 0x2000;
const _: () = assert!(carrick_el1_abi::IRQ_FRAME_SIZE == 0x110);
const _: () = assert!(carrick_el1_abi::TRAP_FRAME_ALLOCATION == 0x120);

/// Current-EL (SP_EL1) IRQ entry: save x0-x30, ELR_EL1, SPSR_EL1 and the
/// interrupted SP in an `IrqFrame` below SP, call `carrick_el1_irq` through
/// the image header's IRQ entry word (offset 32), restore everything, `eret`.
fn write_el1_irq_hook(bytes: &mut [u8], hook_offset: usize) {
    let mut cursor = hook_offset;
    let mut emit = |op: u32| {
        bytes[cursor..cursor + 4].copy_from_slice(&op.to_le_bytes());
        cursor += 4;
    };
    emit(0xD104_43FF); // sub sp, sp, #0x110
    for r in 0..=30u32 {
        emit(enc_str_xt_sp(r, u64::from(r) * 8));
    }
    emit(0xD538_4031); // mrs x17, elr_el1
    emit(enc_str_xt_sp(17, 248));
    emit(0xD538_4011); // mrs x17, spsr_el1
    emit(enc_str_xt_sp(17, 256));
    emit(0x9104_43E1); // add x1, sp, #0x110 (the interrupted SP)
    emit(enc_str_xt_sp(1, 264));
    emit(0x9100_03E0); // mov x0, sp (IrqFrame)
    let entry_ptr = carrick_el1_abi::EL1_REGION_BASE + carrick_el1_abi::EL1_IMAGE_OFFSET + 32;
    emit(enc_movz_xn(16, (entry_ptr & 0xFFFF) as u16, 0));
    emit(enc_movk_xn(16, ((entry_ptr >> 16) & 0xFFFF) as u16, 1));
    emit(enc_movk_xn(16, ((entry_ptr >> 32) & 0xFFFF) as u16, 2));
    emit(enc_ldr_xt_xn(17, 16, 0)); // ldr x17, [x16] (irq_entry_offset)
    emit(0xD100_8210); // sub x16, x16, #32 (image base)
    emit(0x8B11_0210); // add x16, x16, x17
    emit(0xD63F_0200); // blr x16
    emit(enc_ldr_xt_sp(17, 248));
    emit(0xD518_4031); // msr elr_el1, x17
    emit(enc_ldr_xt_sp(17, 256));
    emit(0xD518_4011); // msr spsr_el1, x17
    for r in 0..=30u32 {
        emit(enc_ldr_xt_sp(r, u64::from(r) * 8));
    }
    emit(0x9104_43FF); // add sp, sp, #0x110
    emit(AARCH64_ERET_OPCODE);
    debug_assert!(cursor <= LINUX_EL1_VECTORS_SIZE as usize, "EL1 IRQ hook overruns the vector page");
}
```

- [ ] **Step 3: Thread the mode through the builders and the syscall hook**

1. `el1_vectors_bytes_mailbox_configured` gains the fourth parameter
   `irq: El1IrqMode`; at its end, `write_el1_vector_hook(&mut bytes,
   EL1_VECTOR_HOOK_OFFSET, mailbox_capture, irq)`, then:

```rust
    if el1_enabled && irq == El1IrqMode::GicWindow {
        let slot = AARCH64_VECTOR_CUR_EL_SPX_IRQ_OFFSET;
        put(&mut bytes, slot, enc_b(slot as u64, EL1_IRQ_HOOK_OFFSET as u64));
        write_el1_irq_hook(&mut bytes, EL1_IRQ_HOOK_OFFSET);
    }
```

   with `const AARCH64_VECTOR_CUR_EL_SPX_IRQ_OFFSET: usize = 0x280;` next to the
   other slot offsets. When `el1_enabled` is false the mode is ignored (no hook,
   no window).

2. The IRQ mode is threaded from the caller, never read from the environment
   here:

```rust
fn el1_vectors_bytes_mailbox_inner(identity_fast_path: bool, fd_ceiling: bool, irq: El1IrqMode) -> Vec<u8> {
    el1_vectors_bytes_mailbox_configured(identity_fast_path, fd_ceiling, el1_kernel_enabled(), irq)
}
```

   `el1_vectors_bytes_mailbox_clock(identity_fast_path, fd_ceiling, irq)` and
   `AddressSpace::with_el1_vectors_mailbox_clock(self, identity_fast_path,
   fd_ceiling, irq)` gain the same last parameter and pass it through.
   `el1_vectors_bytes_mailbox` and `el1_vectors_bytes_mailbox_fd_ceiling` pass
   `El1IrqMode::None` (no production caller installs them with a GIC). Existing
   tests calling the 3-argument forms, including the two in
   `memory/el1_clock.rs` (`stub_mapping_collision_is_rejected`,
   `builders_install_read_execute_stub_only_with_fast_paths`) and the
   `Machine::new` vector build there, pass `El1IrqMode::None`.

   In `crates/carrick-vmm-hvf/src/gic.rs`:

```rust
/// The EL1 vector page's IRQ mode for this carrier: the served-path IRQ
/// window only with the in-kernel GIC. Derived from `interrupt_model()`, the
/// one reader of `CARRICK_HVF_GIC`, so the vectors and the VM agree.
pub fn el1_irq_mode() -> carrick_mem::memory::El1IrqMode {
    match interrupt_model() {
        InterruptModel::Gic => carrick_mem::memory::El1IrqMode::GicWindow,
        InterruptModel::LegacyPendingLine => carrick_mem::memory::El1IrqMode::None,
    }
}
```

   re-exported from `crates/carrick-vmm-hvf/src/lib.rs` beside the other `gic`
   re-exports (`pub use gic::el1_irq_mode;`), and in
   `crates/carrick-runtime/src/runtime.rs` `with_hvf_syscall_mailbox`:

```rust
    let image = image.with_el1_vectors_mailbox_clock(
        identity_fast_path,
        true,
        carrick_vmm_hvf::el1_irq_mode(),
    )?;
```

3. `write_el1_vector_hook(bytes, hook_offset, mailbox_capture, irq: El1IrqMode)`:
   - In step 5 (after `str x17, [x16, #264]` for ESR), for `GicWindow` only:
     `emit(bytes, &mut cursor, enc_str_xt_xn(31, 16, 280)); // str xzr, [x16, #280] (TrapFrame.kick = 0)`.
   - Keep everything through the `cbz` patch at `skip_label` as today
     (memory.rs:4535-4540), then replace the served path that follows
     (memory.rs:4542-4575) with:

```rust
    if irq == El1IrqMode::GicWindow {
        // IRQ window FIRST, while SP is still the TrapFrame and only when an
        // interrupt is pending (ISR_EL1.I). Taking the IRQ overwrites
        // ELR_EL1/SPSR_EL1 with this window's own EL1 return state.
        let window = cursor;
        emit(bytes, &mut cursor, 0xD538_C102); // mrs x2, isr_el1
        emit(bytes, &mut cursor, enc_tbz(2, 7, 16));
        emit(bytes, &mut cursor, 0xD503_42FF); // msr daifclr, #2
        emit(bytes, &mut cursor, 0xD503_3FDF); // isb
        emit(bytes, &mut cursor, 0xD503_42DF); // msr daifset, #2
        // Only now reload the syscall's return state from the TrapFrame.
        emit(bytes, &mut cursor, enc_ldr_xt_xn(2, 16, 248));
        emit(bytes, &mut cursor, 0xD518_4022); // msr elr_el1, x2
        emit(bytes, &mut cursor, enc_ldr_xt_xn(2, 16, 256));
        emit(bytes, &mut cursor, 0xD518_4002); // msr spsr_el1, x2
        // An interrupt that became pending after the window (a kick absorbed
        // and re-armed by the host between the window and the reload)
        // re-enters it rather than waiting for the next surfaced exit. Each
        // pass either takes and completes an interrupt or finds none pending.
        emit(bytes, &mut cursor, 0xD538_C102); // mrs x2, isr_el1
        let recheck = cursor;
        emit(bytes, &mut cursor, enc_tbnz(2, 7, window as i64 - recheck as i64));
        // SP_EL1 back to the mailbox slot (x17 = slot).
        emit(bytes, &mut cursor, enc_movz_xn(1, (mb_base & 0xFFFF) as u16, 0));
        emit(bytes, &mut cursor, enc_movk_xn(1, ((mb_base >> 16) & 0xFFFF) as u16, 1));
        emit(bytes, &mut cursor, enc_movk_xn(1, ((mb_base >> 32) & 0xFFFF) as u16, 2));
        emit(bytes, &mut cursor, 0x8B11_2031); // add x17, x1, x17, lsl #8
        emit(bytes, &mut cursor, 0x9100_023F); // mov sp, x17
        for r in 1..=15 {
            emit(bytes, &mut cursor, enc_ldr_xt_xn(r, 16, (r * 8) as u64));
        }
        for r in 18..=30 {
            emit(bytes, &mut cursor, enc_ldr_xt_xn(r, 16, (r * 8) as u64));
        }
        // Did the window take the host kick?
        emit(bytes, &mut cursor, enc_ldr_xt_xn(0, 16, 280));
        let kick_branch = cursor;
        emit(bytes, &mut cursor, 0); // cbnz x0, kick_tail (patched)
        emit(bytes, &mut cursor, enc_ldr_xt_xn(17, 16, 136));
        emit(bytes, &mut cursor, enc_ldr_xt_xn(0, 16, 0));
        emit(bytes, &mut cursor, enc_ldr_xt_xn(16, 16, 128));
        emit(bytes, &mut cursor, 0xD69F_03E0); // eret
        // Kick tail: every register is the syscall's return state; `hvc #4`
        // surfaces the kick at the EL0 boundary (host sets PC/CPSR from
        // ELR_EL1/SPSR_EL1), exactly as the lower-EL IRQ slot does.
        let kick_tail = cursor;
        put(bytes, kick_branch, enc_cbnz_xn(0, kick_branch as u64, kick_tail as u64));
        emit(bytes, &mut cursor, enc_ldr_xt_xn(17, 16, 136));
        emit(bytes, &mut cursor, enc_ldr_xt_xn(0, 16, 0));
        emit(bytes, &mut cursor, enc_ldr_xt_xn(16, 16, 128));
        emit(bytes, &mut cursor, AARCH64_HVC_KICK_OPCODE);
    } else {
        // Today's served path, byte for byte: the lines from
        // `// Restore SP_EL1 to mailbox pointer` through the served-path
        // `emit(bytes, &mut cursor, 0xD69F_03E0); // eret`
        // (memory.rs:4542-4575 at b91d830ec), moved here unchanged.
    }
```

   The `else` arm is today's code moved, not new code, which is what
   `gic_hatch_vector_bytes_are_unchanged` checks. The forward path below is
   unchanged in both modes.

4. `debug_assert!(cursor < EL1_IRQ_HOOK_OFFSET, "syscall hook overlaps the IRQ hook")`
   at the end of `write_el1_vector_hook`.

- [ ] **Step 4: Run the VM-free tests green**

```bash
cargo test -p carrick-mem --lib
```

Expected: all PASS, including `gic_hatch_vector_bytes_are_unchanged` (the hatch
bytes equal the pinned pre-change hashes), `el1_vector_hook_behavior_and_hatch`
(now with `El1IrqMode::None`), the new machine test for all four
`(kick, late)` cases, and the `el1_clock` machine tests (they pass
`El1IrqMode::None` explicitly, so their bytes are the hatch bytes).

```bash
cargo check -p carrick-runtime
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib
```

Expected: compiles; PASS.

- [ ] **Step 5: Run the signed tests green**

If gate D11 committed `el1_served_loop_surfaces_kicks` with `#[ignore]`, delete
the attribute now (this task is its fix).

```bash
just build
scripts/build-linux-fixtures.sh
just test-embed el1_gic --nocapture 2>&1 | tee target/el1-gic-green.log
just test-embed el1_served_loop_surfaces_kicks --nocapture 2>&1 | tee target/el1-served-green.log
grep -a 'el1-gic-\|el1-served\|test el1_' target/el1-gic-green.log target/el1-served-green.log
just test-embed el1_ 2>&1 | tail -5
just test-embed page_table_pauses_survive_carrier_load 2>&1 | tail -5
CARRICK_HVF_GIC=0 just test-embed page_table_pauses_survive_carrier_load 2>&1 | tail -5
```

Expected: `el1_gic_vtimer_reaches_el1_without_host_exits` PASSES with `taken=1`
and `taken_at_exit - armed_at_exit = 0`; `el1_served_loop_surfaces_kicks` PASSES
(record `max_ns`; if D11 found it red on main, this is its green); topology
PASSES; every other `el1_` test and both runs of
`page_table_pauses_survive_carrier_load` pass.

- [ ] **Step 6: Commit**

```bash
just fmt-check && cargo clippy -p carrick-mem -p carrick-vmm-hvf -p carrick-runtime -p carrick-embed --all-targets -- -D warnings
git add crates/carrick-mem/src/memory.rs crates/carrick-mem/src/memory/el1_clock.rs \
  crates/carrick-vmm-hvf/src/gic.rs crates/carrick-vmm-hvf/src/lib.rs crates/carrick-runtime/src/runtime.rs \
  crates/carrick-embed/tests/el1_kick_served_loop.rs docs/perf-results/2026-09-25-hvf-gic-qualification.md
git commit -F- <<'MSG'
feat(el1): take GIC interrupts at EL1 on the served-syscall return

Why: with the in-kernel GIC, EL1 can take the guest virtual timer and
the host kick itself, with no exit to Carrick. EL1 ran with IRQs masked
throughout, so the timer was never taken, and a kick absorbed while a
sibling looped on EL1-served syscalls could wait for an exit that never
came: a page-table drain kicks once and waits without a deadline.

What (GIC mode only; `CARRICK_HVF_GIC=0` keeps today's exact bytes):
- The served path opens an IRQ window gated on ISR_EL1.I
  (daifclr/isb/daifset) while SP_EL1 is still the TrapFrame, then
  reloads ELR/SPSR from the TrapFrame (taking an IRQ overwrites both),
  re-enters the window if an interrupt arrived meanwhile, then restores
  SP_EL1 and the registers.
- The IRQ mode is an argument the HVF runtime passes from
  `gic::el1_irq_mode()`, the same latched model that decides the VM and
  the kick vehicle; carrick-mem reads no hatch.
- The current-EL IRQ slot calls a hook at vector page 0x2000 that saves
  x0-x30/ELR/SPSR in an IrqFrame and calls `carrick_el1_irq`.
- A kick taken in the window leaves through `hvc #4` instead of `eret`:
  the same EL0-boundary surfacing as the lower-EL IRQ slot.
Guest EL0 still runs with DAIF masked; no guest-visible change.

Verified: VM-free byte tests red then green, including a machine run
of the tail that takes an IRQ (and a late second one) in the window and
must still leave with the TrapFrame's ELR/SPSR; hatch bytes pinned;
signed el1_gic_vtimer_reaches_el1_without_host_exits (taken=1, 0
non-kick exits between arm and delivery), el1_served_loop_surfaces_kicks
(max_ns=<N>), el1_gic_topology_two_processes, all el1_ tests,
page_table_pauses_survive_carrier_load with and without the hatch.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

---

### Task 10: Contracts and surfaces

**Files:**
- Create: `conformance-contracts/contracts/el1-gic-vtimer.toml`
- Modify: `conformance-contracts/contracts/gic-topology.toml` (embed binding),
  `conformance-contracts/contracts/kick-el0-boundary.toml` (embed binding),
  `conformance-contracts/surfaces.toml`, `conformance-contracts/inventory.json` (regenerated)

**Interfaces:**
- Produces contract ids `kernel.el1.gic-vtimer`; updates `kernel.vcpu.gic-topology`,
  `kernel.vcpu.kick-el0-boundary`.

- [ ] **Step 1: The vtimer contract**

Create `conformance-contracts/contracts/el1-gic-vtimer.toml`:

```toml
schema_version = 1
id = "kernel.el1.gic-vtimer"
title = "The guest virtual timer is taken and completed at EL1 with no host exit carrying it"
guest_surfaces = ["vmm:hvf", "scheduler:preemption", "syscall:lseek"]
semantic_authority = [
  "Hypervisor.framework hv_gic.h: with the in-kernel GIC the EL1 virtual timer is a PPI (HV_GIC_INT_EL1_VIRTUAL_TIMER) delivered by the device",
  "Arm GICv3 architecture specification: ICC_IAR1_EL1 acknowledges, ICC_EOIR1_EL1 completes (EOImode 0), INTID 1023 is spurious",
  "Arm ARM: an IRQ unmasked by MSR DAIFClr is taken no later than the next context synchronization event (ISB)",
]
fixture = "fixture:el1-vtimer-loop"
scale_points = [1]
rationale = "EL1 plan 1a proves the scheduler's preemption vehicle in the production VM before the scheduler exists: a one-shot virtual timer armed on the vCPU running a loop of EL1-served lseek calls is acknowledged, serviced and completed by carrick_el1_irq in the served-syscall IRQ window, exactly once, with zero host run-loop exits between arming and delivery other than host kicks, which carry no timer (per-slot counters in the shared EL1 counters page). In 1a the only delivery point is that window; EL0 still runs with DAIF masked, so a compute-bound EL0 thread takes the timer at its next EL1-served syscall. Plan 1c moves delivery to EL0 and makes the timer the preemption tick."

structural_budgets = []

[bindings]
vm_free = "carrick-el1::irq::tests::intids_classify_by_the_shared_abi_constants; carrick-el1::irq::tests::only_the_served_path_window_frame_is_accepted; carrick-el1-abi::tests::frames_match_the_vector_page_allocations; carrick-el1-abi::tests::an_image_without_an_irq_entry_is_refused; carrick-mem::memory::tests::gic_window_installs_the_irq_hook_only_with_the_gic; carrick-mem::memory::tests::served_path_window_unmasks_before_reloading_elr_spsr_then_rechecks; carrick-mem::memory::tests::served_path_window_leaves_with_the_trap_frame_return_state_after_an_irq; carrick-mem::memory::tests::el1_irq_hook_saves_and_restores_every_register; carrick-mem::memory::tests::vector_page_never_parks; carrick-mem::memory::tests::gic_hatch_vector_bytes_are_unchanged"
embed = "carrick-embed::el1_gic_vtimer_reaches_el1_without_host_exits"

[bindings.unresolved]
docker = "Timer delivery inside Carrick's EL1 is host-internal; Linux supplies no oracle for it and nothing guest-visible changes in 1a."
embed_structural = "Measured by the embed test from the per-slot host_exits (non-kick exits while the probe is armed) and vtimer_*_at_exit counters of the EL1 counters page; no WorkMetric is registered for it, and an affine budget would need three scale points this single-timer fixture does not have."
```

`structural_budgets` is empty because a budget's `metric` must be a registered
`WorkMetric` (crates/carrick-conformance-contract/src/model.rs) and any affine
budget needs at least three `scale_points` (registry.rs); the structural claim
is carried by the embed test's assertion instead.

- [ ] **Step 2: Bind the embed tests into the other two contracts**

- `gic-topology.toml`: `embed = "carrick-embed::el1_gic_topology_two_processes"` (move it
  out of `[bindings.unresolved]` if Task 5 parked it there).
- `kick-el0-boundary.toml`: `embed = "carrick-embed::pt_pause_drain_pressure; carrick-embed::el1_kick_served_loop::el1_served_loop_surfaces_kicks"`.

- [ ] **Step 3: Surfaces**

In `conformance-contracts/surfaces.toml`:
- append `"kernel.el1.gic-vtimer"` to the `crates/carrick-mem/src/memory.rs` entry's list;
- append `"kernel.vcpu.gic-topology", "kernel.vcpu.kick-el0-boundary"` to the
  `crates/carrick-vmm-hvf/src/trap.rs` entry and `"kernel.vcpu.kick-el0-boundary"`
  to the `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs` entry;
- add entries:

```toml
[[surfaces]]
path = "crates/carrick-el1/src/irq.rs"
contracts = ["kernel.el1.gic-vtimer", "kernel.vcpu.kick-el0-boundary"]

[[surfaces]]
path = "crates/carrick-el1/src/entry.rs"
contracts = ["kernel.el1.gic-vtimer", "kernel.vcpu.kick-el0-boundary"]

[[surfaces]]
path = "crates/carrick-el1-abi/src/lib.rs"
contracts = ["kernel.el1.gic-vtimer", "kernel.vcpu.gic-topology"]

[[surfaces]]
path = "crates/carrick-embed/tests/el1_gic.rs"
contracts = ["kernel.el1.gic-vtimer", "kernel.vcpu.gic-topology"]

[[surfaces]]
path = "fixtures/linux-aarch64-hello/src/el1_vtimer_loop.rs"
contracts = ["kernel.el1.gic-vtimer"]

[[surfaces]]
path = "fixtures/linux-aarch64-hello/src/el1_served_loop_kick.rs"
contracts = ["kernel.vcpu.kick-el0-boundary"]

[[surfaces]]
path = "crates/carrick-embed/tests/el1_kick_served_loop.rs"
contracts = ["kernel.vcpu.kick-el0-boundary"]

[[surfaces]]
path = "crates/carrick-runtime/src/runtime.rs"
contracts = ["kernel.el1.gic-vtimer"]
```

(if `runtime.rs` already has an entry, append the id to it instead).

- [ ] **Step 4: Regenerate the inventory and check**

```bash
cargo run -p carrick-conformance-contract --bin generate-inventory -- --root .
cargo run -p carrick-conformance-contract --bin check-contracts -- --root .
python3 -m unittest scripts/tests/test_check_contract_change.py
just check-contract-change $(git merge-base HEAD main)
```

Expected: exit 0 for all four (`syscall:lseek` adds `kernel.el1.gic-vtimer` to
the lseek row of `inventory.json`).

- [ ] **Step 5: Commit**

```bash
git add conformance-contracts
git commit -F- <<'MSG'
test(conformance): contracts for the in-kernel GIC at EL1

Why: EL1 plan 1a changes how kicks reach Carrick and adds interrupt
delivery at EL1; each needs a named obligation with bindings at the
cheapest capable layer and a signed binding in the production VM.

What: new `kernel.el1.gic-vtimer` (timer taken and completed at EL1,
zero non-kick host exits between arming and delivery); `kernel.vcpu.gic-topology`
gains its signed two-process binding; `kernel.vcpu.kick-el0-boundary`
gains the served-loop drain binding. Surfaces for every touched file;
inventory regenerated.

Verified: check-contracts, test_check_contract_change,
`just check-contract-change` against the merge base.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

---

### Task 11: The other backends, and the documents

**Files:**
- Modify: `docs/hal.md`, `docs/superpowers/specs/2026-09-24-el1-kernel.md`, `AGENTS.md`

**Interfaces:** none (documentation and a no-change check).

- [ ] **Step 1: Prove KVM, bhyve and NVMM are untouched and still build**

The backend directories are untouched, but this plan edits shared crates the
other platforms compile: `carrick-mem` (window constants, page-table guard,
vector builder signature), `carrick-el1-abi`, `carrick-aarch64` (shared with
the KVM AArch64 lane), `carrick-observability`, and `carrick-runtime` /
`carrick-embed` (new non-macOS stubs that no macOS build compiles).

```bash
base=$(git merge-base HEAD main)
git diff --stat "$base"..HEAD -- crates/carrick-vmm-kvm crates/carrick-vmm-bhyve crates/carrick-vmm-nvmm crates/carrick-x86 crates/carrick-hal
git diff "$base"..HEAD -- crates/carrick-aarch64/src/vmm.rs | grep '^[+-]' | grep -v '^[+-][+-]' || echo "Aarch64Vcpu trait unchanged"
just check-kernel-portable
cargo check -p carrick-aarch64 -p carrick-hal
just check-linux
just check-netbsd
cargo check --target aarch64-unknown-linux-gnu --all-targets -p carrick-mem -p carrick-el1-abi -p carrick-aarch64 -p carrick-observability
cargo check --target aarch64-unknown-linux-gnu --no-default-features --features platform-linux -p carrick-runtime -p carrick-embed
```

Expected: the first diff is empty; the trait is unchanged (the KVM aarch64 lane
keeps `set_pending_irq` as a no-op and `injects_kick_irq() == false`, so
`OwedKick` never unmasks its EL0 state); every check passes. The last command
compiles the new `cfg(not(macos, aarch64))` stubs. If it stops in a C build
script (ring needs a cross C compiler, as the `check-linux` comment explains)
rather than in Carrick code, record that and rely on CI's `cross-check-linux`
job for that closure; an error in Carrick code is a STOP. Run
`just check-freebsd` when the FreeBSD cross toolchain variables are exported
(the recipe's comment names them), and `just kvm-smoke-lima` when the lima VM
exists; record each one not run in Task 13's "gates not run". The EL1 image,
its IRQ entry, the vector window and `gic.rs` are HVF-only
(`with_el1_vectors_mailbox_clock` has one caller, the HVF runtime, and
`gic.rs` is `cfg(macos, aarch64)`).

- [ ] **Step 2: `docs/hal.md` backend note**

Add a section "Interrupt controllers (EL1 plan 1a)":

```markdown
## Interrupt controllers (EL1 plan 1a)

HVF carrier VMs carry Hypervisor.framework's in-kernel GICv3. It is created in
the single VM-creation funnel, lives in a reserved IPA window
(`LINUX_GIC_WINDOW_BASE`, 0x2F_0000_0000, 256 MiB), and is driven only from
`carrick-vmm-hvf/src/gic.rs`. Setup follows hv_gic.h and libkrun, and every
vCPU lives for its VM's life. Host kicks stay `hv_vcpus_exit`; the kick a
vCPU owes at its EL0 boundary is SGI 15 made pending in its redistributor. EL1
takes GIC interrupts in the served-syscall return window.
`CARRICK_HVF_GIC=0` restores the GIC-less VM for bisection until plan 1c.

KVM, bhyve and NVMM are unchanged: no interrupt controller is modelled, host
kicks stay signal/exit based, and the `Aarch64Vcpu::set_pending_irq` default
(no-op, `injects_kick_irq() == false`) keeps `OwedKick` from unmasking EL0 on
those lanes. When the x86 ring-0 venue lands (spec step 6), its interrupt
vehicle (KVM irqchip / bhyve vlapic / NVMM) is a separate increment with its own
contract; nothing in 1a constrains it.
```

- [ ] **Step 3: Record the entry-criteria outcomes in the spec**

In `docs/superpowers/specs/2026-09-24-el1-kernel.md`:
- under "Consequences for the design", after the `hv_gic` bullet, add: "Adopted
  in the production VM by plan 1a (`docs/superpowers/plans/2026-09-24-el1-increment1a-hv-gic.md`).
  Setup follows hv_gic.h and libkrun (Apache-2.0). With a GIC,
  `hv_vcpu_set_pending_interrupt` returns `HV_UNSUPPORTED`; host kicks stay
  `hv_vcpus_exit`, and the owed kick is a redistributor-pending SGI. Checks
  and reference setup: `docs/perf-results/2026-09-25-hvf-gic-qualification.md`."
- in "Scheduling", replace "the host adds vCPUs up to the core count and
  retires idle ones" (or its equivalent wording) with: "the carrier creates its
  vCPUs before the VM's first run and keeps them for the VM's life (hv_gic.h:
  topology is final once vCPUs run); an idle vCPU parks (plan 1c) instead of
  being retired."
- replace open items 1 and 2 with the recorded outcomes:
  - item 1: "SPI: not used by 1a. The reference setup (the guest programs the
    distributor through MMIO; the host raises `hv_gic_set_spi(intid, true)`)
    and the spike's difference from it (host-side distributor writes before
    any vCPU existed) are recorded in plan 1a's Prior art; the cause of the
    spike's failure is not established. `hv_vcpus_exit` under a GIC:
    <C1 verdicts> in the running states; the spike wedges were a deliberately
    broken no-save control and WFI-parked wake runs."
  - item 2: "Mid-life vCPU destroy: designed out (plan 1a D2; every vCPU
    lives for its VM's life, enforced by a carrier fault). Wedged-vCPU
    recovery and WFI wake liveness under the GIC: carried to plan 1c as its
    entry criterion."

  Fill each `<...>` from the results doc.

- [ ] **Step 4: One AGENTS.md rule**

Under "Where key subsystems live", add:

```markdown
- **HVF in-kernel GIC** — `crates/carrick-vmm-hvf/src/gic.rs` is the only raw
  `hv_gic_*` caller. The GIC is created inside `create_vm_with_admission`
  (never elsewhere) and every vCPU gets its MPIDR and redistributor setup in
  the two creation wrappers. With a GIC, `hv_vcpu_set_pending_interrupt`
  returns `HV_UNSUPPORTED` (hv_vcpu.h): host kicks stay `hv_vcpus_exit`, and
  the owed kick is SGI 15 via GICR_ISPENDR0. Every vCPU is created before the
  VM's first run and destroyed only at teardown (hv_gic.h; a create after that
  is a carrier fault).
  Name legacy interrupt lines only through `interrupt::HvfInterruptLine`
  (applevisor-sys numbers them in reverse of the SDK). EL1 unmasks IRQs only in
  the served-syscall return window and never executes `wfi`/`wfe` (the image
  build refuses them) until the EL1 scheduler lands with its wedge-recovery
  contract. Setup follows libkrun and hv_gic.h; the Carrick-specific checks
  are `just test-hvf gic_qualification_c<N>`, one per process (a wedge leaks
  the process's only VM).
```

- [ ] **Step 5: Commit**

```bash
git add docs/hal.md docs/superpowers/specs/2026-09-24-el1-kernel.md AGENTS.md
git commit -F- <<'MSG'
docs(el1): record the GIC adoption and its qualified HVF facts

Why: plan 1a resolves (or explicitly carries forward) the spec's open
items on SPI delivery, the hv_vcpus_exit wedge and mid-life vCPU
destroys under the GIC, and adds rules a future change must not break.

What: spec open items 1 and 2 carry the outcomes (SPI unused with the
reference setup recorded, C1 verdicts, mid-life destroys designed out),
and "Scheduling" keeps vCPUs for the VM's life instead of retiring them;
docs/hal.md notes the HVF interrupt controller and that KVM, bhyve and
NVMM are unchanged; one AGENTS.md entry names the GIC boundary, the
kick vehicle, the interrupt-line wrapper and the EL1 no-park rule.

Verified: `git diff --stat` shows no change under the other backends;
`just check-kernel-portable`, `just check-linux`, `just check-netbsd`,
and the aarch64-linux checks of every shared crate this plan edits.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

---

### Task 12: The EL1 gate runs the GIC evidence

**Files:**
- Modify: `justfile` (`el1-gate`)

- [ ] **Step 1: Add the GIC checks and the hatch screen to `el1-gate`**

In the `el1-gate` recipe, after `step el1-embed ./scripts/test-signed.sh carrick-embed el1_`,
add one process per check (HVF allows one VM per process, so a wedge in one
check must not turn the others red):

```bash
    for c in c1_vcpus_exit_smoke_el1_vtimer c1_vcpus_exit_smoke_el1_masked \
             c1_vcpus_exit_smoke_el0_kick_pending c2_owed_kick_vehicle; do
      step hvf-gic-$c ./scripts/test-signed.sh carrick-vmm-hvf gic_qualification_$c --nocapture
    done
```

C3 is a 127-VM probe run, not a test. It is re-run by hand when macOS changes
(Task 1 Step 4). Its production form is `page_table_pauses_survive_carrier_load`
(four concurrent carriers, each with its GIC VM). Add it as a step here so the
gate exercises concurrent GIC carriers:
`step gic-concurrent-carriers ./scripts/test-signed.sh carrick-embed page_table_pauses_survive_carrier_load`.

and extend the inotify09 A/B loop to three arms, recording wall time for each:

```bash
    for arm in "1 1" "0 1" "1 0"; do
      set -- $arm; el1=$1; gic=$2
      start=$(python3 -c 'import time;print(time.time())')
      CARRICK_RUN_ID=el1-gate-$el1-$gic CARRICK_EL1=$el1 CARRICK_HVF_GIC=$gic "$bin" run --rm localhost:5050/ltp:arm64 /bin/sh -c /opt/ltp/testcases/bin/inotify09 > "$out/inotify09-$el1-$gic.out" 2> "$out/inotify09-$el1-$gic.err" < /dev/null
      end=$(python3 -c 'import time;print(time.time())')
      grep -aq TPASS "$out/inotify09-$el1-$gic.out" "$out/inotify09-$el1-$gic.err" || { echo "inotify09 EL1=$el1 GIC=$gic did not TPASS"; exit 1; }
      python3 -c "print('inotify09 EL1=$el1 GIC=$gic wall', round($end-$start, 2))" | tee -a "$out/artifact.txt"
    done
```

(replacing the two-arm `for mode in 1 0` loop). The `el1_` filter already runs
the three `el1_gic` tests and `el1_served_loop_surfaces_kicks`, which need the
fixtures: add `step fixtures scripts/build-linux-fixtures.sh` before
`step el1-embed`.

- [ ] **Step 2: Run the gate**

```bash
just el1-gate 2>&1 | tail -30
```

Expected: `el1-gate: green on <sha>`; `artifact.txt` has three inotify09 walls.

- [ ] **Step 3: Commit**

```bash
git add justfile
git commit -F- <<'MSG'
test(el1): run the GIC checks in the EL1 landing gate

Why: 1a relies on Hypervisor.framework behaviour no reference VMM
exercises (the owed-kick SGI, hv_vcpus_exit on eight vCPUs in Carrick's
states, many concurrent GIC carriers) and a macOS update can change it;
a gate that does not run the checks cannot notice.

What: el1-gate builds the fixtures, runs each signed
gic_qualification_c<N> check in its own process on the gated artifact,
runs `page_table_pauses_survive_carrier_load` (concurrent GIC
carriers), and screens inotify09 in three arms (EL1+GIC, no EL1, EL1
without GIC).

Verified: `just el1-gate` green on <sha>.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

---

### Task 13: Verification ladder on one artifact

Nothing here changes code. Every result belongs to the artifact recorded in
Step 1; a rebuild restarts the ladder.

- [ ] **Step 1: Rebase, reconcile, identity**

```bash
git fetch origin 2>/dev/null; git rebase main
just reconcile-inventories
git status --short   # commit inventory moves, if any, as "chore: reconcile the inventories for the GIC adoption"
just build
bin=target/release/carrick
{
  echo "head $(git rev-parse HEAD)"
  echo "sha256 $(shasum -a 256 $bin | cut -d' ' -f1)"
  codesign -dvvv $bin 2>&1 | grep -i 'CDHash='
  otool -l $bin | grep -A2 LC_UUID | grep uuid
  codesign -d --entitlements - $bin 2>/dev/null | grep -a -o 'com.apple.security.hypervisor'
  otool -l $bin | grep -q __dof_carrick && echo "dof present"
} | tee target/el1-1a-artifact.txt
```

- [ ] **Step 2: Host gates**

```bash
just test
just clippy
just lint-domains
python3 scripts/conformance/check-contract-change.py --root . --base "$(git merge-base HEAD main)" --head HEAD
just ci
```

Expected: every command exits 0. `just ci` repeats fmt/clippy/lint-domains; run
it anyway, because CI runs the steps sequentially and an early red masks later
ones.

- [ ] **Step 3: Signed gates, on the one artifact**

`just el1-gate` and `just test-embed` depend on `build`, which relinks or
re-signs `target/release/carrick`, and re-signing alone changes CDHash
(AGENTS.md). Every rung therefore runs with `--no-deps` or through
`scripts/test-signed.sh` directly, and the artifact's SHA-256, CDHash and
LC_UUID are compared after each rung.

```bash
bin=target/release/carrick
ident() {
  echo "sha256 $(shasum -a 256 $bin | cut -d' ' -f1)"
  codesign -dvvv $bin 2>&1 | grep -i 'CDHash='
  otool -l $bin | grep -A2 LC_UUID | grep uuid
}
ident > target/el1-1a-ident.txt
same() { ident | diff - target/el1-1a-ident.txt > /dev/null || { echo "artifact changed after $1"; exit 1; }; }
for c in c1_vcpus_exit_smoke_el1_vtimer c1_vcpus_exit_smoke_el1_masked \
         c1_vcpus_exit_smoke_el0_kick_pending c2_owed_kick_vehicle; do
  ./scripts/test-signed.sh carrick-vmm-hvf gic_qualification_$c --nocapture 2>&1 | tail -5
done
same checks
just --no-deps el1-gate 2>&1 | tail -30
same el1-gate
just --no-deps conformance smoke 2>&1 | tail -20
same smoke
CARRICK_HVF_GIC=0 CARRICK_RUN_ID=hatch-smoke $bin run --rm docker.io/library/ubuntu:24.04 /bin/sh -c 'echo hatch-ok' < /dev/null
scripts/sudo/kill.sh hatch-smoke
same hatch
```

Expected: every GIC check green; `el1-gate: green on <sha>`
(it includes the `el1_` embed tests, `conformance-probes` and the LTP
file/inotify set); smoke green; hatch prints `hatch-ok`; no `artifact changed`
line.

Then diff the verdicts against the base (Task 0 Step 4), row by row:

```bash
gate=$(ls -td target/el1-gate/*/ | head -1)
python3 - "$gate/ltp.jsonl" target/el1-1a-base/ltp.jsonl <<'PY'
import json, sys
def rows(path):
    return {row["name"]: row["verdict"] for row in (json.loads(line) for line in open(path) if line.strip())}
new, base = rows(sys.argv[1]), rows(sys.argv[2])
changed = sorted(n for n in set(new) | set(base) if new.get(n) != base.get(n))
for n in changed:
    print(f"{n}: base={base.get(n)} new={new.get(n)}")
print(f"{len(changed)} changed of {len(set(new) | set(base))}")
sys.exit(1 if changed else 0)
PY
grep -a 'test result:\|MATCH\|DIFF' "$gate/probes.log" | tail -5
grep -a 'test result:\|MATCH\|DIFF' target/el1-1a-base/probes.log | tail -5
```

Expected: `0 changed`; both probe logs green (the probe gate compares against
committed Docker oracles, so "green on both" is the identity of their
verdicts). A changed row is a guest-visible change: STOP and attribute it
(AGENTS.md: reduce, check Docker, check the base binary) before anything else.

- [ ] **Step 4: Paired ecosystem subset (Carrick only, cached oracle)**

Interleave three arms, two rounds each, on a quiet host, never alongside
Docker:
- `base`: the base artifact (Task 0);
- `new`: the new artifact;
- `nogic`: the new artifact under `CARRICK_HVF_GIC=0`.

The `nogic` arm replaces the dropped exit-cost experiment. `new` over `nogic`
isolates what the GIC itself costs the exit-heavy rows, and `new` over `base`
is the whole of 1a.

```bash
suites="--suite go-build --suite go-testing --suite go-time --suite go-os_signal --suite go-net_http \
  --suite cpython-threading --suite cpython-subprocess --suite cpython-asyncio --suite node-app-smoke"
mkdir -p target/el1-1a-paired
for round in 1 2; do
  for arm in base new nogic; do
    b=target/release/carrick; gic=1
    [ $arm = base ] && b=target/el1-1a-base/carrick
    [ $arm = nogic ] && gic=0
    CARRICK_HVF_GIC=$gic cargo run -q -p carrick-conformance -- --tier full $suites --require-cached-oracle \
      --carrick-bin "$b" --jsonl target/el1-1a-paired/$arm-$round.jsonl
  done
done
```

Expected: every suite has the same verdict in all six runs. Record, per suite
and round, the wall time of `new` over `base` and of `new` over `nogic`. A
suite whose `new`/`base` ratio exceeds 1.10 in both rounds is a finding.
Attribute it with the `new`/`nogic` ratio before accepting: GIC cost if that
ratio carries it, the rest of 1a otherwise. Write "suggests", not "confirmed";
this is a paired measurement, not a controlled experiment. No suite may change
verdict. (The base artifact ignores `CARRICK_HVF_GIC`, which it predates.)

- [ ] **Step 5: Record and hand off**

Append to `docs/perf-results/2026-09-25-hvf-gic-qualification.md` an
"Acceptance" section: the artifact identity, each command's result, the paired
table, scoped cleanup (`scripts/sudo/kill.sh` for every run id used), and every
gate not run. Commit it:

```bash
git add docs/perf-results/2026-09-25-hvf-gic-qualification.md
git commit -F- <<'MSG'
docs(el1): acceptance evidence for the in-kernel GIC adoption

Why: a signed result belongs to one exact artifact; the 1a checkpoint
needs its identity, gates and paired timings in one place.

What: artifact identity (source HEAD, SHA-256, CDHash, LC_UUID,
entitlement, __dof_carrick), host and signed gate results, the paired
ecosystem subset against the pre-1a base, scoped cleanup.

Verified: as recorded.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

---

## Plan 1b (outline): EL1 run queue, in-guest context switch, futex hand-off for one process

**Goal:** For one guest process, a thread that blocks on a private futex and the
sibling that wakes it hand off on the same vCPU at EL1: no host condvar, no host
exit in the steady state. Target: the futex ping-pong (26-31 µs today, spec
"Scheduling") and the executor block/wake share of go build (24% of carrier CPU).

**Key tasks:**
1. A `no_std` scheduler core (`carrick-sched-core`, the spec's "one
   implementation, two venues" pattern): per-vCPU run queue, thread records,
   futex wait queues keyed by the process's private futex address; host-testable
   with `just test-kernel` semantics suites before any EL1 wiring.
2. EL1 context switch: GPRs, `SP_EL0`, `TPIDR_EL0`, `ELR/SPSR`, and FP/SIMD. This
   lifts 1a's FP/SIMD ban for one audited save/restore routine (the spike's 42 vs
   54 ns shows the cost); the image build allow-lists exactly that routine.
3. Zone entry for a process: at exec, a single-threaded process's threads become
   EL1-owned objects (one owner, typed state like the file zone); `clone`
   creates EL1 threads; `FUTEX_WAIT/WAKE/WAIT_BITSET` on private futexes are
   served at EL1; everything else forwards.
4. EL1-idle hand-back: an empty EL1 run queue forwards an idle hypercall and the
   host executor parks (WFI parking is 1c).
5. Delete the host continuation path for zone processes' private futexes (no
   second path; `=0` hatch for bisection only).

**Entry criteria:** 1a accepted with D2/D3 green; the FP/SIMD save strategy
chosen with a spike-backed cost; the futex ping-pong baseline and the go build
executor share recorded as the contract's red evidence on the 1a artifact;
signals, `exit_group` and `execve` interplay for EL1-owned threads designed
(forward on `pending_host_work`, as the file zone does).

**Contracts:** `kernel.el1.futex-handoff` (affine budget: host exits per
ping-pong round trip = 0 in steady state; semantics by LTP `futex_*` and the
kernel-semantics futex suite); `kernel.el1.context-switch` (register and FP/SIMD
state preserved across switches, with a no-save negative control); two-process
evidence (a zone process beside a host-scheduled one); paired go-testing,
cpython-threading, go-build.

## Plan 1c (outline): vtimer preemption at EL1, SGI wake, WFI park, host thread policy

**Goal:** EL1 preempts compute-bound threads with the virtual timer and wakes
parked vCPUs with SGIs, with zero host exits per tick and per wake; an idle vCPU
parks in the hypervisor (WFI) and costs no CPU; vCPU host threads run under a
latency-sensitive policy.

**Key tasks:**
1. Take interrupts at EL0: run guest EL0 with `PSTATE.I` clear, with the
   guest-visible PSTATE normalised in sigframes, `ptrace` register views and core
   dumps (today's masked bits must not leak; Linux reports DAIF clear).
2. The vtimer as the preemption tick at EL1 (quantum from the scheduler core's
   policy), replacing the host `PreemptionDriver` for zone threads.
3. SGI 0 as the reschedule IPI through `ICC_SGI1R_EL1`, using 1a's MPIDR layout
   (Aff0 0-15 per Aff1 cluster).
4. WFI park with a keep-busy window: park only when idle longer than the measured
   wake cost (6-10 µs p50 parked vs 1.8-2.0 µs running); lift 1a's `wfi` ban for
   the park routine only.
5. Host thread policy: `THREAD_TIME_CONSTRAINT_POLICY` for vCPU threads (spike: a
   1 ms sleep woke 258 µs late at default QoS, about 5 µs under the policy).
6. Delete the `CARRICK_HVF_GIC=0` hatch, the legacy pending-line kick vehicle
   and `HVF_VIRTUAL_IRQ` (the EL1 scheduler requires the GIC; `HvfInterruptLine`
   stays for check C2's legacy negative control).

**Entry criteria:** WFI park and wake under the GIC checked by 1c's own
Carrick-specific check, in the shape 1a's C1 uses (1a never enters in-HVF WFI,
so it did not check it). Start from the scheduler spike's `gic-wfi-hvc-*` wake
runs (`c9897ae4c`), whose one wedge is unexplained: re-entering after a CANCELED
exit taken at `wfi` re-parks the vCPU. Also establish wedged-vCPU recovery
under the GIC (spec open item 2): either a proven recovery sequence or a proof
that the wedge needs a state Carrick never enters. And: 1b landed; the
sigframe/ptrace PSTATE normalisation has its own red-first probe against the
Docker oracle.

**Contracts:** `kernel.el1.preemption` (compute-bound threads make fair progress
with host exits per tick = 0; migrates the `scheduler_preemption` embed
contracts); `kernel.el1.sgi-wake` (wake latency and zero exits to Carrick);
`kernel.el1.idle-park` (idle vCPU CPU cost near zero; the premise's "an idle
vCPU costs nothing" as a contract); a PSTATE-visibility probe gated against
Docker.

## Plan 1d (outline): retire the host executor path for in-zone processes

Prior work to reconcile before 1d is expanded: GMP phase 3
([`2026-09-19-gmp-phase3.md`](2026-09-19-gmp-phase3.md), handoff
[`2026-09-19-gmp-phase3-handoff.md`](2026-09-19-gmp-phase3-handoff.md)) is the
unbuilt `handoffp` (release a guest CPU when its executor blocks in a host
wait) that `ExecutorPoolConfig` cites as the precondition for M = P. The
2026-09-24 measurement (M = P beat the M = host-parallelism default on futex
ping-pong, go build, cpython and a 4-way parallel shell loop) and the EL1
design both bear on whether handoffp is still needed or is subsumed by EL1
scheduling; 1d decides that explicitly.

**Goal:** Every process runs in the EL1 zone; the host no longer schedules guest
threads. The host executor becomes a vCPU provider only, and the host run queue,
continuation-based futex path and preemption driver are deleted for zone
processes, with no second path.

**Key tasks:**
1. Zone entry by default for every process (exec, fork and clone inherit it);
   remove the per-process zone gate.
2. Delete the host scheduler's run queue, `WorkerKick` preemption and the
   `FutexTable` continuation-callback path for zone threads; the carrier keeps
   only vCPU admission and park/wake.
3. Decide the M/P executor default with a controlled experiment: M = P (one host
   thread per vCPU) is the design's steady state; today's default is host
   parallelism with `CARRICK_BOUND_EXECUTORS` as the hatch, and the spec records
   ping-pong at 26-31 µs by default vs about 3 µs with 2 bound executors. If
   M = P wins, delete `CARRICK_BOUND_EXECUTORS`.
4. Keep "one implementation, two venues": KVM, bhyve and NVMM run the same
   `carrick-sched-core` in-process through a thin adapter until the x86 ring-0
   venue exists; the HVF host implementation is what gets deleted.

**Entry criteria:** 1b and 1c accepted; the carrier-CPU profile (spec open item
3, as a `carrick trace` profile) shows the executor block/wake share near zero
on go build; paired ecosystem runs at or below the 1c artifact; LTP parity.

**Contracts:** existing scheduler contracts rebound to the EL1 venue;
`kernel.execution.single-owner` (structural: host run-queue enqueues per zone
thread = 0); the M/P decision recorded as a controlled, single-variable
experiment on a quiet host.

---

## Unresolved at planning time (each is answered by a named step)

| Question | Answered by |
|---|---|
| How do other VMMs create, place and drive the in-kernel GIC? | "Prior art" (libkrun, Apache-2.0; `hv_gic.h`), adopted as the reference setup in Task 1 |
| Does SGI 15 pend through GICR_ISPENDR0 from the host and serve the owed kick, including production's un-acknowledged `hvc #4` path? | Task 1 C2 (gate D1) |
| Can Carrick keep every vCPU for its VM's life instead of recreating one mid-life? | Fact 5 code map and Task 2 (D2), enforced by the Task 5 guard |
| Is `hv_vcpus_exit` honoured under a GIC with eight vCPUs in Carrick's running states? | Task 1 C1 (gate D3); WFI states carried to 1c |
| Why did `hv_gic_set_spi` never reach the CPU interface in the spike? | Not needed by 1a (D4). "Prior art" records the reference setup and the spike's difference from it, as a hypothesis |
| Per-VM vCPU capacity and redistributor placement under the GIC | Task 5 geometry read at every creation, fail-closed (D5, D7) |
| Does a GIC per VM lower the concurrent VM ceiling (127 without)? | Task 1 C3 (gate D5b) |
| Does a GIC change an ID register EL0 can read? | Task 5 Step 8 probe against the Docker oracle (D12); Task 13 probe diff for the rest |
| Cost of an exit with the GIC present | Task 13 paired runs (`new` over `nogic` arm) |
| Is Fact 9 (lost kick in EL1-served loops) real on main? | Task 0B, on the frozen base (gate D11) |

Fact 9, if confirmed, is a defect on main independent of the GIC (the
`CARRICK_HVF_GIC=0` hatch keeps it); it needs its own fix outside this plan's
fence, reported as soon as Task 0B confirms it.

---

## Review disposition

Every finding of the 2026-09-24 review was checked against the code before
editing. Applied findings are reflected in the tasks above; the entries below
record what was applied only in part or rejected, one line each.

- Served-path order (facts and safety blockers): applied in full; no part rejected.
- Drop paths and allocator key (facts, major): applied as one raw-destroy function, reported Drop paths and a lock-held destroy-plus-release; an owned `ConfiguredVcpu` guard and a `(generation, id)` key were not adopted, because the lock makes a stale id owner unobservable and `CarrierGic` is replaced per VM generation.
- Typed `GicAffinityLease` (safety, major): not adopted for the same reason; the lock-held release closes the race it targets without adding a value to thread through nine creation sites.
- Fact 9 first (safety, major): the experiment moved to Task 0B; "drop the kick tail if Fact 9 is refuted" is rejected, because once the window unmasks IRQs it acknowledges the kick SGI, so EL1 must surface that kick whatever Fact 9's verdict.
- Load-dependent verdicts (safety, major): applied; C1's 5 s wedge bound is a hang detector that AGENTS.md requires of every wait, not a verdict rate.
- Detector for a kicked vCPU that never surfaces (safety, major, kick liveness at scale): not added as a new probe; `scripts/dtrace/hvpatch-pt-pause-drain-stall.d` (commit 854eeff8b) already names each sibling still in the guest for a drain of 100 ms or more, and D11's mixed row calls for it.
- `hvf_gic_enabled` in carrick-mem (safety, major): moved to the one reader in `gic.rs`, with the vector mode passed as an argument; the extra fail-closed assertion at VM creation was not added, because both sides now derive from the same `OnceLock` and cannot differ within a process.
- Vehicle before GIC (safety, blocker): landed as one Task 5+6 commit with a signed red, the facts finding's alternative; a vehicle-only commit would need an `InterruptModel::Gic` variant that nothing can construct, which `-D warnings` rejects as dead code.
- Stage-1 window guard (safety, minor): placed in `PageTableManager`'s three output-writing paths (`map_aliased_with_flags`, `repoint_preserving_attributes`, `apply`'s identity rebuild) rather than in `Stage1Authority`, which owns the manager but writes no descriptor.
- Per-exit counter cost (safety, minor): resolved by counting only on the probed slot and only for non-kick exits, so no cache-line padding is needed.
- `live_hvf_vcpus` duplicate census (facts, minor): moot. The census was dropped when D2 designed out mid-life destroys; the Task 5 guard and the topology snapshot (`releases == 0` while the carrier lives) replace it.
- Owner direction, 2026-09-24 ("Don't other projects use the hv gic? Do we really need to experiment with it?"): applied. The setup follows libkrun and `hv_gic.h` ("Prior art"). The old E0 (vtimer to EL1), E4 (SPI matrix), E5 (capacity/placement) and E6 (costs) are dropped. E2 shrinks to the C1 smoke. E1 shrinks to the SGI-only C2. E3 and the census are replaced by the Task 2 design-out. E5b is kept as C3. QEMU (GPL-2.0) is not used as a source.
