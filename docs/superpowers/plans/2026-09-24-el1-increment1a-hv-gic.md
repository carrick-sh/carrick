# EL1 kernel increment 1a: adopt HVF's in-kernel GIC in the production VM

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:executing-plans
> (or superpowers:subagent-driven-development) to run this plan task by task.
> Steps use checkbox (`- [ ]`) syntax. Read `AGENTS.md` first (Rule 0 codesign,
> `just` recipes, red-first, commit style, never `git stash`). Task 1 and
> Task 2 are DECISION tasks: later tasks are only valid under the outcome their
> decision gate records, and each gate names the STOP condition.

**Goal:** Every production HVF carrier VM is created with Hypervisor.framework's
in-kernel GICv3 (`hv_gic_create`), every vCPU carries a unique MPIDR and a
configured redistributor, host kicks travel as a GIC interrupt, and EL1 can take
and complete a GIC interrupt itself, with no guest-visible behaviour change. A
signed embed test proves the guest virtual timer interrupt reaches EL1 in the
production VM with zero host exits between arming and delivery other than host
kicks (which carry no timer).

**Architecture:** One module, `carrick-vmm-hvf/src/gic.rs`, is the only caller of
raw `hv_gic_*`. The single VM-creation funnel (`create_vm_with_admission`) creates
the GIC right after `hv_vm_create`, inside the same custody transaction, so every
path that creates a VM (boot, execve rebuild, shared-wait resume, fork rebuild)
gets one before its first vCPU. The two vCPU-creation wrappers (the only
`vm.vcpu_create()` callers) give each vCPU an MPIDR and configure its
redistributor and CPU interface on the owning thread before it can run. The kick
vehicle becomes a redistributor-pending SGI, because the SDK makes
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
   pending state is not (Task 1 E1 qualifies that).
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
5. **Mid-life vCPU destroys exist, and not every destroy reports.** Raw
   `hv_vcpu_destroy` with the VM kept alive: `reclaim_park`
   (persistent_executor.rs:952; the last one under the MT whole-VM lease leaves
   the VM with zero vCPUs, and `reclaim_resume` later creates a new vCPU in the
   same VM, persistent_executor.rs:1020-1066), the initial-runner park
   (persistent_executor.rs:982, reached from `save_initial_runner_state`, which
   the HVPatch boot hand-off calls at binding.rs:5383 on every carrier boot;
   executors then create vCPUs in the same VM), `destroy_vcpu_on_thread_exit`
   (persistent_executor.rs:1360, also the persistent worker's
   `destroy_worker_vcpu`, and every vCPU's destroy during carrier teardown).
   Whole-VM paths: `shared_wait_park` (persistent_executor.rs:1082), execve's
   mature rebuild (execve_rebuild.rs:1246), creation rollback
   (carrier_custody.rs:110/154). Those six report through
   `trap::vcpu_destroyed(vcpu_id)` (trap.rs:881). Three more destroy through
   applevisor's `Drop` (`impl Drop for Vcpu` calls `hv_vcpu_destroy`,
   applevisor-1.0.0 vcpu.rs:157-161): the local-RAII setup rollback
   (`SetupVcpuGuard` with `SetupVcpuCleanup::LocalRaii`, carrier_custody.rs:314-329,
   selected for existing carriers at mapping_plan.rs:489-497, reports through a
   bare `vcpu_destroyed` fn pointer), `HvfVmState::add_vcpu`'s mailbox failure
   (cow_engine.rs:3695, no report), and the error returns of
   `from_process_spec` after its `create_vcpu` (trap.rs:6610, no report).
   HVF vCPU ids are small integers that a later `hv_vcpu_create` can reuse.
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
   exists, every guest would see a change (Task 1 E0 measures it; D12).
11. **HVF geometry on the planning host** (read-only query, macOS 27.2 / M4):
   distributor 0x10000, redistributor region 0x2000000 of 0x20000 frames (256
   redistributors), alignment 0x10000, `hv_vm_get_max_vcpu_count` 64, maximum
   IPA 40 bits. The per-VM vCPU cap (64) is below the redistributor count, so
   D5's clamp is a no-op here; E5 re-measures both.

---

## Key decisions

| # | Decision | Where decided |
|---|---|---|
| D0 | 1a depends on the landed pause fix and reuses its names; nothing from the branch is re-landed. | Fact 1 |
| D1 | Kick vehicle under GIC: SGI 15 made pending on the owning thread with `GICR_ISPENDR0`, cleared with `GICR_ICPENDR0`, including production's un-acknowledged `hvc #4` path (E1(f)). Fallback PPI 20 if SGI 15 fails E1. `HVF_VIRTUAL_IRQ` survives only for the `CARRICK_HVF_GIC=0` hatch. | Task 1 E1 |
| D2 | vCPU lifecycle: a destroy is mid-life when a later create follows it in the same VM generation. Keep today's lifecycle only if E3 qualifies mid-life recreates and the census (Task 2) measures them; otherwise STOP 1a and replan lifecycle. | Tasks 1 E3, 2 |
| D3 | Wedge anomaly: qualified by E2 (8 vCPUs kicked together, 100,000 rounds per state) with named hypotheses; any wedge in a production-reachable state is a STOP; WFI states run in their own executable as data. | Task 1 E2 |
| D4 | SPI anomaly: investigated by E4; 1a uses no SPI and exposes no SPI API. | Task 1 E4 |
| D5 | Per-carrier vCPU capacity is clamped to the GIC redistributor count; `hv_gic_create`'s `HV_NO_RESOURCES` joins the VM-creation park+retry, and `GLOBAL_VCPU_CEILING` follows the E5b ceiling with a GIC (D5b). | Task 1 E5/E5b, Task 5 |
| D6 | GIC IPA window `0x2F_0000_0000..0x2F_1000_0000`: distributor at the base, redistributors at base + 16 MiB; refused by both the stage-2 map boundary and stage-1 publication. | Task 4 |
| D7 | MPIDR = `1<<31 | (index/16)<<8 | index%16`, lowest free index per VM generation. The index is released under the GIC topology lock in the same critical section as `hv_vcpu_destroy`, so no vCPU created with a reused HVF id can observe a stale owner, and every private interrupt is scrubbed before a reused redistributor is enabled. | Tasks 1 E3/E5, 5 |
| D8 | EL1 takes GIC interrupts only in the served-syscall return window, opened before ELR/SPSR are reloaded from the TrapFrame; EL0 masking is unchanged. | Tasks 7, 9 |
| D9 | Opt-out hatch `CARRICK_HVF_GIC=0` (exact string), read once in `gic.rs`, restores today's VM, vector bytes and kick vehicle for bisection; the vector builder takes the IRQ mode as an argument from that one reader; 1c deletes it. | Tasks 5, 9 |
| D10 | The applevisor-sys IRQ/FIQ swap is corrected once, in a typed `HvfInterruptLine`, and a semgrep rule forbids the binding's variants anywhere else. | Task 3 |
| D11 | Fact 9 is decided on the frozen base before 1a code lands; a confirmed hang on main is reported at once as its own defect. | Task 0B |
| D12 | EL0 ID view: if a GIC changes an ID register EL0 can read, the EL0 view matches Linux (the `ID_AA64PFR0_EL1` GIC field reads 0), proven by a red-first probe against the Docker oracle. | Task 1 E0, Task 5 |

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
| `crates/carrick-vmm-hvf/tests/gic_qual/harness.rs`, `tests/gic_qualification.rs`, `tests/gic_qualification_wfi.rs` (new) | Signed HVF qualification suite E0-E6 with its own guest blob; WFI states in their own executable | 1 |
| `crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs` | E5b: `concurrent-ceiling` with a GIC per VM | 1 |
| `docs/perf-results/2026-09-25-hvf-gic-qualification.md` (new) | Fact 9 on main, E0-E6 results and the D1-D12 decisions | 0B, 1, 2, 8, 13 |
| `crates/carrick-observability/src/probes.rs` | `hvf-vcpu-lifecycle` USDT probe | 2 |
| `scripts/dtrace/hvf-vcpu-lifecycle-census.d` (new), `crates/carrick-runtime/src/dtrace_consumer.rs`, `crates/carrick-cli/src/{hvf_vcpu_lifecycle_profile.rs (new), main.rs, trace_profile.rs, commands.rs, args.rs}` | Durable census of vCPU create/destroy sites as the strict `carrick trace` profile `hvf-vcpu-lifecycle-census` | 2 |
| `crates/carrick-vmm-hvf/src/trap/cow_engine.rs` | `add_vcpu` error path reports its destroy (2); EL0 ID view sanitised (5) | 2, 5 |
| `crates/carrick-vmm-hvf/src/interrupt.rs` (new) | `HvfInterruptLine`: the one correction of the binding's IRQ/FIQ swap | 3 |
| `.semgrep/typed-domains.yml` | Rule `hvf-interrupt-line-outside-boundary` | 3 |
| `crates/carrick-mem/src/memory.rs`, `memory/el1_clock.rs` | `LINUX_GIC_*` window constants, non-overlap asserts, vector bytes (IRQ hook, served-path window, kick tail) with the IRQ mode as an explicit argument | 4, 9 |
| `crates/carrick-mem/src/page_table.rs` | Stage-1 publication refuses outputs in the GIC window | 4 |
| `crates/carrick-vmm-hvf/src/trap/stage2_backend.rs` | Stage-2 map refuses the GIC window | 4 |
| `crates/carrick-runtime/src/runtime.rs` | Passes the carrier's IRQ mode to the vector builder | 9 |
| `conformance-probes/src/bin/idaa64pfr0.rs` (new), probe lists | EL0 view of `ID_AA64PFR0_EL1` against the Docker oracle (D12) | 5 |
| `crates/carrick-vmm-hvf/src/gic.rs` (new) | Geometry, placement, `CarrierGic`, `MpidrAllocator`, vCPU configuration, affinity release under the lock, kick vehicle, interrupt model and IRQ mode, vtimer probe | 5, 6, 8 |
| `crates/carrick-vmm-hvf/src/trap.rs`, `trap/vcpu_admission.rs`, `trap/persistent_executor.rs`, `trap/execve_rebuild.rs`, `trap/carrier_custody.rs`, `trap/vcpu_gate.rs` | Lifecycle sites, GIC in VM creation, vCPU creation/destroy, VM release, capacity, kick sites, exit counting | 2, 5, 6, 8 |
| `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs` | `set_pending_irq` through the kick vehicle | 6 |
| `crates/carrick-aarch64/src/owed_kick.rs` | Doc update for the GIC vehicle; GIC-semantics model test | 6 |
| `crates/carrick-el1-abi/src/lib.rs` | Shared INTIDs, `TrapFrame.kick`, `IrqFrame`, header v3, IRQ counters, host-exit counters | 5, 7 |
| `crates/carrick-el1/src/irq.rs` (new), `src/entry.rs`, `link.ld`, `src/lib.rs` | `classify_intid`, `carrick_el1_irq` | 7 |
| `crates/carrick-el1-image/build.rs` | Forbid `wfi`/`wfe` in the EL1 image | 7 |
| `crates/carrick-runtime/src/lib.rs`, `crates/carrick-embed/src/lib.rs` | Re-export the vtimer probe and topology diagnostics | 8 |
| `fixtures/linux-aarch64-hello/src/el1_vtimer_loop.rs` (new), `scripts/build-linux-fixtures.sh` | Guest fixture | 8 |
| `crates/carrick-embed/tests/el1_gic.rs` (new) | Signed embed tests | 8 |
| `conformance-contracts/contracts/{gic-topology,el1-gic-vtimer,kick-el0-boundary}.toml`, `surfaces.toml`, `inventory.json` | Contracts | 5, 6, 10 |
| `scripts/migrate/runtime-global-state.json` | Ledger rows for the new statics | 2, 5, 8 |
| `justfile` | `el1-gate` runs the fixtures build, each qualification experiment in its own process and a three-arm inotify09 screen | 12 |
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

### Task 1: HVF GIC qualification suite (decides D1-D6, D12)

This is the first GIC code task because the design choices depend on HVF
behaviour nobody has measured under Carrick's lifecycle: the kick vehicle under
a GIC (including production's un-acknowledged EL0-boundary kick), whether a
vCPU may be destroyed and recreated while its VM and siblings live and what
state a recreated redistributor inherits, whether `hv_vcpus_exit` is always
honoured under a GIC with many vCPUs kicked at once, why `hv_gic_set_spi`
never reached the CPU interface in the scheduler spike, what a GIC costs in
VM-creation capacity, and whether a GIC changes the ID registers EL0 can read.
Each production-reachable experiment is a signed `#[test]` so a later macOS
update that changes the answer fails `just el1-gate` (Task 12 adds the steps,
one process per experiment), and each has a negative control.

Verdicts are semantic events, never rates: "at least one in-guest delivery and
zero VTIMER_ACTIVATED exits", not "N interrupts in M ms". The only time bounds
are hang detectors (a wait that did not finish within seconds is recorded as a
wedge), which AGENTS.md requires of every wait.

**Files:**
- Create: `crates/carrick-vmm-hvf/tests/gic_qual/harness.rs` (shared harness, `include!`d)
- Create: `crates/carrick-vmm-hvf/tests/gic_qualification.rs` (E0-E6, production-reachable)
- Create: `crates/carrick-vmm-hvf/tests/gic_qualification_wfi.rs` (E2 WFI states; data only)
- Modify: `crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs` (E5b: `concurrent-ceiling` with a GIC)
- Modify: `docs/perf-results/2026-09-25-hvf-gic-qualification.md`

**Interfaces:**
- Consumes: `applevisor_sys` raw `hv_vm_*`, `hv_vcpu_*`, `hv_gic_*`; `libc::mmap`;
  `carrick_host::clock::monotonic_ticks` (the crate's `#[allow(deprecated)]`
  wrapper of `mach_absolute_time`, which libc 0.2.186 deprecates).
- Produces (recorded decisions, consumed by Tasks 4-6): `KICK_INTID` value (SGI 15
  or PPI 20), `REDISTRIBUTOR_CAPACITY` and `max_vcpu` measured on the
  qualifying host, the E3 verdict and inherited-state record, the E2 verdict per
  state with its detection bound, the E4 SPI classification, the E5b VM
  ceilings with and without a GIC, the E6 cost numbers, the E0 ID-register
  difference (D12).

Reference code (read, do not copy blindly): `spike/el1-scheduler` `c9897ae4c`
`crates/carrick-vmm-hvf/src/bin/hvf_el1_sched_probe.rs` lines 975-1080
(`create_gic`) and 1244-1320 (`setup_vcpu`); `spike/el1-asid` `25f6e2f4e`
`crates/carrick-vmm-hvf/src/bin/hvf_el1_asid_probe.rs` lines 1660-1890 (the
straggler kick loop).

Two executables, because HVF allows one VM per process: a wedge leaks its VM,
and every later VM-creating test in the same executable would then fail in
`hv_vm_create`. The WFI states production never enters (Fact 6) live in
`gic_qualification_wfi.rs`, report wedges as data, and never gate. `el1-gate`
runs each production experiment as its own process.

- [ ] **Step 1: Write the harness (guest blob, VM, vCPU helpers)**

Create `crates/carrick-vmm-hvf/tests/gic_qual/harness.rs` (a subdirectory
without `main.rs`, so cargo does not build it as a test target):

```rust
// Shared harness of the HVF GIC qualification executables
// (gic_qualification.rs: production-reachable experiments;
// gic_qualification_wfi.rs: the in-HVF WFI states production never enters).
// Each executable `include!`s this file, so each owns its guest blob and its
// one VM per process. Results are printed as `E<n> {json}` lines and recorded
// in docs/perf-results/2026-09-25-hvf-gic-qualification.md.

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
const MAX_BLOCKS: usize = 256;
// Per-vCPU data block; the guest asm below uses the same offsets. The guest's
// IRQ handler also stores the last acknowledged INTID at 0x08.
const B_HEARTBEAT: u64 = 0x00;
const B_SPURIOUS: u64 = 0x18;
const B_MODE: u64 = 0x20;
const B_VTIMER_PERIOD: u64 = 0x30;
const B_COUNTS: u64 = 0x40; // [u64; 64] by INTID
const MODE_SPIN_UNMASKED: u64 = 0;
const MODE_SPIN_MASKED: u64 = 1;
const MODE_WFI: u64 = 2;
const MODE_SVC_LOOP: u64 = 4;
const MODE_HVC_LOOP: u64 = 5;
/// Masked spin that opens a one-instruction IRQ window per iteration
/// (`daifclr; isb; daifset`), the shape of Task 9's served-path window.
const MODE_IRQ_WINDOW: u64 = 6;
const HVC_BAD_VECTOR: u64 = 0x1c;
const HVC_NULL: u64 = 0x1d;
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
const GICD_CTLR_ARE_GRP1: u64 = 0x12;
const VTIMER_INTID: u32 = 27;
const KICK_SGI: u32 = 15;
const UNUSED_PPI: u32 = 20;
const KICK_CANDIDATES: [u32; 2] = [15, 20];
const TICKS_PER_MS: u64 = 24_000;
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
    // 0x200: current EL SPx sync. MODE_SVC_LOOP re-executes its svc forever.
    "mrs x9, elr_el1", "sub x9, x9, #4", "msr elr_el1, x9", "eret", ".p2align 7",
    // 0x280: current EL SPx IRQ
    "b Lgq_irq", ".p2align 7",
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
    "b.ne Lgq_irq_real",
    "ldr x11, [x9, #0x18]",
    "add x11, x11, #1",
    "str x11, [x9, #0x18]",
    "b Lgq_irq_out",
    "Lgq_irq_real:",
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
    // EL1 entry: x9 = block, dispatch on the block's mode word.
    ".p2align 7",
    ".globl _gq_main",
    "_gq_main:",
    "mrs x9, tpidr_el1",
    "ldr x10, [x9, #0x20]",
    "cmp x10, #1",
    "b.eq Lgq_masked",
    "cmp x10, #2",
    "b.eq Lgq_wfi",
    "cmp x10, #4",
    "b.eq Lgq_svc",
    "cmp x10, #5",
    "b.eq Lgq_hvc",
    "cmp x10, #6",
    "b.eq Lgq_window",
    "msr daifclr, #2",
    "Lgq_spin:",
    "ldr x11, [x9]",
    "add x11, x11, #1",
    "str x11, [x9]",
    "b Lgq_spin",
    "Lgq_masked:",
    "msr daifset, #2",
    "b Lgq_spin",
    "Lgq_wfi:",
    "msr daifclr, #2",
    ".globl _gq_wfi_insn",
    "_gq_wfi_insn:",
    "wfi",
    "ldr x11, [x9]",
    "add x11, x11, #1",
    "str x11, [x9]",
    "b _gq_wfi_insn",
    "Lgq_svc:",
    "svc #0",
    "b Lgq_svc",
    "Lgq_hvc:",
    "hvc #0x1d",
    "b Lgq_hvc",
    "Lgq_window:",
    "msr daifset, #2",
    "Lgq_window_loop:",
    "ldr x11, [x9]",
    "add x11, x11, #1",
    "str x11, [x9]",
    "msr daifclr, #2",
    "isb",
    "msr daifset, #2",
    "b Lgq_window_loop",
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
    static gq_wfi_insn: u8;
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

fn now_ticks() -> u64 {
    carrick_host::clock::monotonic_ticks()
}

fn ticks_to_ns(ticks: u64) -> u64 {
    ticks * 125 / 3 // 24 MHz counter
}

struct Gic {
    dist_size: usize,
    redist_region: usize,
    redist_size: usize,
    spi_base: u32,
    spi_count: u32,
    vtimer_intid: u32,
}

impl Gic {
    /// `hv_gic_create` after `hv_vm_create`, before any vCPU, at the production
    /// placement; fails the test if the placement does not fit.
    fn create() -> Gic {
        let (mut ds, mut da, mut rr, mut rs, mut ra) = (0usize, 0usize, 0usize, 0usize, 0usize);
        unsafe {
            check(hv_gic_get_distributor_size(&mut ds), "distributor size");
            check(hv_gic_get_distributor_base_alignment(&mut da), "distributor alignment");
            check(hv_gic_get_redistributor_region_size(&mut rr), "redistributor region");
            check(hv_gic_get_redistributor_size(&mut rs), "redistributor size");
            check(hv_gic_get_redistributor_base_alignment(&mut ra), "redistributor alignment");
        }
        assert!(GIC_DIST_IPA.is_multiple_of(da as u64), "distributor alignment {da:#x}");
        assert!(GIC_DIST_IPA + ds as u64 <= GIC_REDIST_IPA, "distributor size {ds:#x}");
        assert!(GIC_REDIST_IPA.is_multiple_of(ra as u64), "redistributor alignment {ra:#x}");
        assert!(GIC_REDIST_IPA + rr as u64 <= GIC_WINDOW_END, "redistributor region {rr:#x}");
        let (mut spi_base, mut spi_count, mut vtimer_intid) = (0u32, 0u32, 0u32);
        unsafe {
            let config = hv_gic_config_create();
            assert!(!config.is_null(), "hv_gic_config_create");
            check(hv_gic_config_set_distributor_base(config, GIC_DIST_IPA), "distributor base");
            check(hv_gic_config_set_redistributor_base(config, GIC_REDIST_IPA), "redistributor base");
            check(hv_gic_create(config), "hv_gic_create");
            os_release(config);
            check(hv_gic_get_spi_interrupt_range(&mut spi_base, &mut spi_count), "spi range");
            check(
                hv_gic_get_intid(hv_gic_intid_t::EL1_VIRTUAL_TIMER, &mut vtimer_intid),
                "vtimer intid",
            );
            check(
                hv_gic_set_distributor_reg(hv_gic_distributor_reg_t::CTLR, GICD_CTLR_ARE_GRP1),
                "GICD_CTLR",
            );
        }
        Gic { dist_size: ds, redist_region: rr, redist_size: rs, spi_base, spi_count, vtimer_intid }
    }

    fn redistributors(&self) -> usize {
        self.redist_region / self.redist_size
    }
}

struct Vm {
    host: *mut u8,
    gic: Option<Gic>,
}

unsafe impl Send for Vm {}
unsafe impl Sync for Vm {}

impl Vm {
    fn create(with_gic: bool) -> Vm {
        unsafe {
            let config = hv_vm_config_create();
            let mut max_ipa = 0u32;
            check(hv_vm_config_get_max_ipa_size(&mut max_ipa), "max ipa");
            check(hv_vm_config_set_ipa_size(config, max_ipa), "set ipa");
            check(hv_vm_create(config), "hv_vm_create");
            os_release(config.cast());
        }
        let gic = with_gic.then(Gic::create);
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
        let vm = Vm { host: host.cast(), gic };
        vm.install_guest();
        unsafe {
            check(
                hv_vm_map(
                    host,
                    RAM_IPA,
                    RAM_SIZE,
                    HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC,
                ),
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

    /// Destroy the VM. Every vCPU must already be destroyed on its own thread.
    fn destroy(self) {
        unsafe {
            check(hv_vm_unmap(RAM_IPA, RAM_SIZE), "hv_vm_unmap");
            check(hv_vm_destroy(), "hv_vm_destroy");
            libc::munmap(self.host.cast(), RAM_SIZE);
        }
    }
}

fn mpidr(index: u16) -> u64 {
    (1 << 31) | ((u64::from(index) / 16) << 8) | (u64::from(index) % 16)
}

#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    canceled: u64,
    vtimer_activated: u64,
    hvc_null: u64,
    bad_vector: u64,
    other_exception: u64,
    other_reason: u64,
}

struct Vcpu {
    id: hv_vcpu_t,
    exit: *const hv_vcpu_exit_t,
}

impl Vcpu {
    /// Create on the calling (owning) thread, set MPIDR and the minimal EL1
    /// state, and zero the vCPU's data block. No GIC register is touched, so a
    /// caller can read the redistributor exactly as HVF hands it out.
    fn create_unconfigured(vm: &Vm, block: usize, mpidr_index: u16) -> Vcpu {
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
        vcpu
    }

    /// `create_unconfigured`, then (GIC VMs only) scrub and configure the
    /// redistributor and CPU interface for `enable`, as production does.
    fn create(vm: &Vm, block: usize, mpidr_index: u16, enable: &[u32]) -> Vcpu {
        let vcpu = Self::create_unconfigured(vm, block, mpidr_index);
        if vm.gic.is_some() {
            vcpu.gic_enable(enable);
        }
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

    fn icc_reg(&self, reg: hv_gic_icc_reg_t) -> u64 {
        let mut value = 0u64;
        unsafe { check(hv_gic_get_icc_reg(self.id, reg, &mut value), "ICC read") };
        value
    }

    /// Production's configuration (Task 5 `configure_new_vcpu`): withdraw any
    /// pending, active or enabled private interrupt a previous owner of this
    /// redistributor left, then group, prioritise and enable `intids`.
    fn gic_enable(&self, intids: &[u32]) {
        use hv_gic_redistributor_reg_t as R;
        let mask = intids.iter().fold(0u64, |mask, intid| mask | (1 << intid));
        self.set_redistributor_reg(R::ICENABLER0, ALL_PRIVATE);
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

    fn get(&self, reg: hv_reg_t) -> u64 {
        let mut value = 0;
        unsafe { check(hv_vcpu_get_reg(self.id, reg, &mut value), "hv_vcpu_get_reg") };
        value
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

    fn cntvct(&self) -> u64 {
        let mut offset = 0;
        unsafe { check(hv_vcpu_get_vtimer_offset(self.id, &mut offset), "vtimer offset") };
        now_ticks() - offset
    }

    /// One-shot at `delay_ticks`; the guest re-arms every `period_ticks` (0 = once).
    fn arm_vtimer(&self, vm: &Vm, block: usize, delay_ticks: u64, period_ticks: u64) {
        vm.block_write(block, B_VTIMER_PERIOD, period_ticks);
        self.set_sys(hv_sys_reg_t::CNTV_CVAL_EL0, self.cntvct() + delay_ticks);
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

    fn set_active(&self, intid: u32) {
        self.set_redistributor_reg(hv_gic_redistributor_reg_t::ISACTIVER0, 1 << intid);
    }

    /// Run until a CANCELED exit (re-entering after null HVCs and, in a GIC-less
    /// VM, after VTIMER_ACTIVATED with the timer disabled), or any other exit.
    fn run_until_canceled(&self, max_internal_exits: u64) -> Tally {
        let mut tally = Tally::default();
        loop {
            unsafe { check(hv_vcpu_run(self.id), "hv_vcpu_run") };
            let exit = unsafe { &*self.exit };
            match exit.reason {
                hv_exit_reason_t::CANCELED => {
                    tally.canceled += 1;
                    return tally;
                }
                hv_exit_reason_t::VTIMER_ACTIVATED => {
                    tally.vtimer_activated += 1;
                    self.set_sys(hv_sys_reg_t::CNTV_CTL_EL0, 0);
                }
                hv_exit_reason_t::EXCEPTION => {
                    let syndrome = exit.exception.syndrome;
                    let (ec, imm) = (syndrome >> 26, syndrome & 0xffff);
                    if ec == EC_HVC64 && imm == HVC_NULL {
                        tally.hvc_null += 1;
                    } else if ec == EC_HVC64 && imm == HVC_BAD_VECTOR {
                        tally.bad_vector += 1;
                        return tally;
                    } else {
                        tally.other_exception += 1;
                        return tally;
                    }
                }
                _ => {
                    tally.other_reason += 1;
                    return tally;
                }
            }
            if tally.hvc_null + tally.vtimer_activated > max_internal_exits {
                return tally;
            }
        }
    }

    fn destroy(self) {
        unsafe { check(hv_vcpu_destroy(self.id), "hv_vcpu_destroy") }
    }
}

fn kick(id: hv_vcpu_t) {
    kick_all(&[id]);
}

/// One `hv_vcpus_exit` call naming every vCPU, as a page-table drain does.
fn kick_all(ids: &[hv_vcpu_t]) {
    unsafe { check(hv_vcpus_exit(ids.as_ptr(), ids.len() as u32), "hv_vcpus_exit") }
}

fn kick_after(id: hv_vcpu_t, after: Duration) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(after);
        kick(id);
    })
}

/// Create a vCPU on a fresh owning thread, run `body`, destroy the vCPU.
fn on_vcpu_thread<R: Send + 'static>(
    vm: &Arc<Vm>,
    block: usize,
    mpidr_index: u16,
    enable: &'static [u32],
    body: impl FnOnce(&Vm, &Vcpu) -> R + Send + 'static,
) -> R {
    let vm = Arc::clone(vm);
    std::thread::spawn(move || {
        let vcpu = Vcpu::create(&vm, block, mpidr_index, enable);
        let result = body(&vm, &vcpu);
        vcpu.destroy();
        result
    })
    .join()
    .expect("vCPU thread")
}

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// xorshift64*, seeded per test, for kick jitter without a new dependency.
struct Jitter(u64);

impl Jitter {
    fn next_micros(&mut self, bound: u64) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) % bound
    }
}

const ENABLE_VTIMER: &[u32] = &[VTIMER_INTID];
const ENABLE_VTIMER_AND_KICK: &[u32] = &[VTIMER_INTID, KICK_SGI];
/// vCPUs kicked together per E2 round (a page-table drain kicks every sibling).
const LIVENESS_VCPUS: usize = 8;
/// Rounds per E2 state. Zero wedges in N rounds bounds the per-round wedge
/// probability below about 3/N at 95% confidence; the results doc states it.
const LIVENESS_ROUNDS: u64 = 100_000;
/// Hang detectors, not verdict rates: a vCPU that has not honoured a kick in
/// SUSPECT is re-kicked every 5 ms until WEDGE; only then is it a wedge.
const LIVENESS_SUSPECT: Duration = Duration::from_secs(1);
const LIVENESS_WEDGE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Entry {
    El1(u64),
    El0 { masked: bool },
}

#[derive(Clone, Copy, Debug)]
struct LivenessState {
    name: &'static str,
    production_reachable: bool,
    entry: Entry,
    vtimer_period: u64,
    /// Make the kick SGI pending before the first run (masked states keep it
    /// pending for the whole experiment, as a production EL0 does).
    kick_pending: bool,
}

/// Printed through Debug in the `E2` lines.
#[allow(dead_code)]
#[derive(Debug)]
struct LivenessReport {
    state: &'static str,
    production_reachable: bool,
    rounds: u64,
    canceled: Vec<u64>,
    pc_at_wfi: u64,
    pc_past_wfi: u64,
    /// (round, vCPU index, heartbeat still advancing)
    wedges: Vec<(u64, usize, bool)>,
    unexpected: u64,
}

/// Kick `LIVENESS_VCPUS` vCPUs in one `hv_vcpus_exit` list per round, with
/// jitter, and require every one to honour every kick.
fn liveness(state: LivenessState) -> LivenessReport {
    let vm = Arc::new(Vm::create(true));
    let canceled: Arc<Vec<AtomicU64>> =
        Arc::new((0..LIVENESS_VCPUS).map(|_| AtomicU64::new(0)).collect());
    let pc_at_wfi = Arc::new(AtomicU64::new(0));
    let pc_past_wfi = Arc::new(AtomicU64::new(0));
    let unexpected = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let ids = Arc::new(Mutex::new(vec![0; LIVENESS_VCPUS]));
    let ready = Arc::new(Barrier::new(LIVENESS_VCPUS + 1));
    let owners: Vec<_> = (0..LIVENESS_VCPUS)
        .map(|index| {
            let (vm, canceled, pc_at_wfi, pc_past_wfi, unexpected, stop, ids, ready) = (
                Arc::clone(&vm),
                Arc::clone(&canceled),
                Arc::clone(&pc_at_wfi),
                Arc::clone(&pc_past_wfi),
                Arc::clone(&unexpected),
                Arc::clone(&stop),
                Arc::clone(&ids),
                Arc::clone(&ready),
            );
            std::thread::spawn(move || {
                let vcpu = Vcpu::create(&vm, index, index as u16, ENABLE_VTIMER_AND_KICK);
                match state.entry {
                    Entry::El1(mode) => vcpu.enter_el1(&vm, index, mode),
                    Entry::El0 { masked } => vcpu.enter_el0(index, masked),
                }
                if state.vtimer_period != 0 {
                    vcpu.arm_vtimer(&vm, index, state.vtimer_period, state.vtimer_period);
                }
                if state.kick_pending {
                    vcpu.set_pending(KICK_SGI);
                }
                ids.lock().expect("ids")[index] = vcpu.id;
                ready.wait();
                let wfi = guest_ipa(ptr::addr_of!(gq_wfi_insn));
                loop {
                    unsafe { check(hv_vcpu_run(vcpu.id), "hv_vcpu_run") };
                    let exit = unsafe { &*vcpu.exit };
                    if exit.reason != hv_exit_reason_t::CANCELED {
                        unexpected.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    if state.entry == Entry::El1(MODE_WFI) {
                        if vcpu.get(hv_reg_t::PC) == wfi {
                            pc_at_wfi.fetch_add(1, Ordering::Relaxed);
                        } else {
                            pc_past_wfi.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    canceled[index].fetch_add(1, Ordering::Release);
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                }
                vcpu.destroy();
            })
        })
        .collect();
    ready.wait();
    let targets: Vec<hv_vcpu_t> = ids.lock().expect("ids").clone();
    let mut jitter = Jitter(0x9e37_79b9_7f4a_7c15 ^ targets[0]);
    let mut wedges = Vec::new();
    let mut rounds = 0;
    'rounds: while rounds < LIVENESS_ROUNDS && unexpected.load(Ordering::Relaxed) == 0 {
        std::thread::sleep(Duration::from_micros(jitter.next_micros(50)));
        let want: Vec<u64> = canceled.iter().map(|c| c.load(Ordering::Acquire) + 1).collect();
        let behind = || -> Vec<usize> {
            (0..LIVENESS_VCPUS)
                .filter(|&i| canceled[i].load(Ordering::Acquire) < want[i])
                .collect()
        };
        kick_all(&targets);
        let sent = Instant::now();
        while !behind().is_empty() && sent.elapsed() < LIVENESS_SUSPECT {
            std::thread::yield_now();
        }
        for index in behind() {
            // Suspect: is the guest still executing, and does a re-kick help?
            let h0 = vm.block_read(index, B_HEARTBEAT);
            std::thread::sleep(Duration::from_millis(100));
            let h1 = vm.block_read(index, B_HEARTBEAT);
            let deadline = Instant::now() + LIVENESS_WEDGE;
            while canceled[index].load(Ordering::Acquire) < want[index] && Instant::now() < deadline {
                kick(targets[index]);
                std::thread::sleep(Duration::from_millis(5));
            }
            if canceled[index].load(Ordering::Acquire) < want[index] {
                wedges.push((rounds, index, h1 > h0));
                break 'rounds;
            }
        }
        rounds += 1;
    }
    stop.store(true, Ordering::Release);
    if wedges.is_empty() {
        kick_all(&targets);
        for owner in owners {
            owner.join().expect("owner thread");
        }
        Arc::into_inner(vm).expect("sole VM handle").destroy();
    } else {
        // A wedged owner cannot destroy its vCPU; leak the threads and the VM.
        // HVF allows one VM per process, so no later VM can be created in this
        // executable: callers stop creating VMs after a wedge.
        std::mem::forget(owners);
        std::mem::forget(vm);
    }
    LivenessReport {
        state: state.name,
        production_reachable: state.production_reachable,
        rounds,
        canceled: canceled.iter().map(|c| c.load(Ordering::Acquire)).collect(),
        pc_at_wfi: pc_at_wfi.load(Ordering::Acquire),
        pc_past_wfi: pc_past_wfi.load(Ordering::Acquire),
        wedges,
        unexpected: unexpected.load(Ordering::Acquire),
    }
}
```

Create `crates/carrick-vmm-hvf/tests/gic_qualification.rs`:

```rust
//! Hypervisor.framework in-kernel GIC qualification for EL1 plan 1a (Task 1):
//! the production-reachable experiments E0-E6, one `#[test]` each, each with a
//! negative control. The in-HVF WFI states production never enters live in
//! gic_qualification_wfi.rs.
//!
//! Run ONLY through `just test-hvf gic_qualification_e<N> --nocapture`
//! (scripts/test-signed.sh), one experiment per process: an unsigned
//! executable gets HV_DENIED, which is a failure here, never a skip, and a
//! wedge leaks the process's one VM.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
#![allow(
    dead_code, // the shared harness is included by two executables
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks
)]

include!("gic_qual/harness.rs");
```

`hv_vcpus_exit`'s first parameter is `*const hv_vcpu_t` in applevisor-sys 1.0.0
(production passes `ids.as_ptr()` in `vcpu_kick.rs`); if the compiler reports
`*mut`, use `ids.as_ptr().cast_mut()`.

- [ ] **Step 2: E0: geometry, the vtimer PPI at EL1 and the EL0 ID view, with a GIC-less control**

Append to `gic_qualification.rs`:

```rust
/// The ID registers Carrick's EL0 MRS emulation returns raw
/// (cow_engine.rs `emulate_el0_sys64_read_inner`).
const ID_REGISTERS: [(&str, hv_sys_reg_t); 10] = [
    ("MIDR_EL1", hv_sys_reg_t::MIDR_EL1),
    ("ID_AA64PFR0_EL1", hv_sys_reg_t::ID_AA64PFR0_EL1),
    ("ID_AA64PFR1_EL1", hv_sys_reg_t::ID_AA64PFR1_EL1),
    ("ID_AA64DFR0_EL1", hv_sys_reg_t::ID_AA64DFR0_EL1),
    ("ID_AA64DFR1_EL1", hv_sys_reg_t::ID_AA64DFR1_EL1),
    ("ID_AA64ISAR0_EL1", hv_sys_reg_t::ID_AA64ISAR0_EL1),
    ("ID_AA64ISAR1_EL1", hv_sys_reg_t::ID_AA64ISAR1_EL1),
    ("ID_AA64MMFR0_EL1", hv_sys_reg_t::ID_AA64MMFR0_EL1),
    ("ID_AA64MMFR1_EL1", hv_sys_reg_t::ID_AA64MMFR1_EL1),
    ("ID_AA64MMFR2_EL1", hv_sys_reg_t::ID_AA64MMFR2_EL1),
];

fn id_registers(vcpu: &Vcpu) -> Vec<u64> {
    ID_REGISTERS.iter().map(|&(_, reg)| vcpu.get_sys(reg)).collect()
}

#[test]
fn gic_qualification_e0_geometry_and_vtimer_ppi() {
    let _serial = serial();
    let vm = Arc::new(Vm::create(true));
    let gic = vm.gic.as_ref().expect("GIC VM");
    assert_eq!(gic.vtimer_intid, VTIMER_INTID, "HVF EL1 virtual timer INTID");
    let geometry = (
        gic.dist_size,
        gic.redist_region,
        gic.redist_size,
        gic.redistributors(),
        gic.spi_base,
        gic.spi_count,
    );
    let (tally, vtimer_irqs, spurious, heartbeat, icc_sre, gicd_ctlr, redist_base, ids_gic) =
        on_vcpu_thread(&vm, 0, 0, ENABLE_VTIMER, |vm, vcpu| {
            let (mut gicd_ctlr, mut redist_base) = (0u64, 0u64);
            let icc_sre = vcpu.icc_reg(hv_gic_icc_reg_t::SRE_EL1);
            unsafe {
                check(
                    hv_gic_get_distributor_reg(hv_gic_distributor_reg_t::CTLR, &mut gicd_ctlr),
                    "GICD_CTLR read",
                );
                check(hv_gic_get_redistributor_base(vcpu.id, &mut redist_base), "redistributor base");
            }
            let ids = id_registers(vcpu);
            vcpu.enter_el1(vm, 0, MODE_SPIN_UNMASKED);
            vcpu.arm_vtimer(vm, 0, TICKS_PER_MS, 10 * TICKS_PER_MS);
            let stop = kick_after(vcpu.id, Duration::from_millis(200));
            let tally = vcpu.run_until_canceled(1_000);
            stop.join().expect("kicker");
            (
                tally,
                vm.count(0, VTIMER_INTID),
                vm.block_read(0, B_SPURIOUS),
                vm.block_read(0, B_HEARTBEAT),
                icc_sre,
                gicd_ctlr,
                redist_base,
                ids,
            )
        });
    println!(
        "E0 {{\"distributor_size\":{},\"redistributor_region\":{},\"redistributor_size\":{},\
         \"redistributors\":{},\"spi_base\":{},\"spi_count\":{},\"icc_sre\":\"{icc_sre:#x}\",\
         \"gicd_ctlr\":\"{gicd_ctlr:#x}\",\"redistributor_base_vcpu0\":\"{redist_base:#x}\",\
         \"vtimer_irqs\":{vtimer_irqs},\"spurious\":{spurious},\"heartbeat\":{heartbeat},\
         \"tally\":\"{tally:?}\"}}",
        geometry.0, geometry.1, geometry.2, geometry.3, geometry.4, geometry.5
    );
    assert_eq!(icc_sre & 1, 1, "ICC_SRE_EL1.SRE: the system-register interface is live");
    assert!(vtimer_irqs >= 1, "vtimer PPI 27 taken in-guest at least once");
    assert_eq!(tally.vtimer_activated, 0, "no VTIMER_ACTIVATED exit under the GIC");
    assert_eq!((tally.canceled, tally.other_exception, tally.other_reason, tally.bad_vector), (1, 0, 0, 0));
    assert!(heartbeat > 0, "guest ran");
    Arc::into_inner(vm).expect("sole VM handle").destroy();

    // Negative control: the same guest with no GIC exits with VTIMER_ACTIVATED
    // and never takes INTID 27 in-guest. Its ID registers are the D12 baseline.
    let vm = Arc::new(Vm::create(false));
    let (tally, vtimer_irqs, ids_plain) = on_vcpu_thread(&vm, 0, 0, &[], |vm, vcpu| {
        let ids = id_registers(vcpu);
        vcpu.enter_el1(vm, 0, MODE_SPIN_UNMASKED);
        vcpu.arm_vtimer(vm, 0, TICKS_PER_MS, 0);
        let stop = kick_after(vcpu.id, Duration::from_millis(50));
        let tally = vcpu.run_until_canceled(10);
        stop.join().expect("kicker");
        (tally, vm.count(0, VTIMER_INTID), ids)
    });
    println!("E0-control {{\"vtimer_irqs\":{vtimer_irqs},\"tally\":\"{tally:?}\"}}");
    let differs: Vec<String> = ID_REGISTERS
        .iter()
        .zip(ids_gic.iter().zip(&ids_plain))
        .filter(|(_, (gic, plain))| gic != plain)
        .map(|((name, _), (gic, plain))| format!("{name}: plain={plain:#x} gic={gic:#x}"))
        .collect();
    println!("E0-id {{\"differs\":\"{differs:?}\"}}");
    assert!(tally.vtimer_activated >= 1 && vtimer_irqs == 0, "control: {tally:?} irqs {vtimer_irqs}");
    Arc::into_inner(vm).expect("sole VM handle").destroy();
}
```

- [ ] **Step 3: Build, sign and run E0**

```bash
just test-hvf gic_qualification_e0 --nocapture 2>&1 | tee target/gic-qual-e0.log
grep -a '^E0' target/gic-qual-e0.log
```

Expected: `test gic_qualification_e0_geometry_and_vtimer_ppi ... ok`, one `E0 {...}`,
one `E0-control {...}` and one `E0-id {...}` line, and the script's unentitled
negative control passing. A `HV_DENIED` means the executable was not signed:
rerun through the recipe, never bare `cargo test`. If the placement asserts
fail, STOP and report the printed geometry: D6's window must be re-derived
before anything else. **Gate D12:** if `E0-id` names `ID_AA64PFR0_EL1`, Task 5
Step 8 sanitises the EL0 view; any other named register is a STOP (a
guest-visible change this plan has no design for).

- [ ] **Step 4: E1: the kick vehicle (decides D1)**

Append:

```rust
#[derive(Debug)]
struct KickOutcome {
    intid: u32,
    legacy_rc: hv_return_t,
    survives_run_return: bool,
    taken_at_el1: bool,
    taken_at_el0: bool,
    withdrawn_by_icpendr: bool,
    el0_boundary_exits: u64,
    el0_boundary_withdrawn: bool,
    tallies: [Tally; 5],
}

impl KickOutcome {
    fn qualifies(&self) -> bool {
        self.survives_run_return
            && self.taken_at_el1
            && self.taken_at_el0
            && self.withdrawn_by_icpendr
            && self.el0_boundary_exits == 1
            && self.el0_boundary_withdrawn
    }
}

fn kick_round(vcpu: &Vcpu) -> Tally {
    let stop = kick_after(vcpu.id, Duration::from_millis(20));
    let tally = vcpu.run_until_canceled(100);
    stop.join().expect("kicker");
    tally
}

/// Run with the production-shaped lower-EL IRQ slot (`hvc #4; eret`, no
/// acknowledge) until a CANCELED exit, servicing each `hvc #4` exactly as
/// trap.rs's kick exit does: withdraw the kick (GICR_ICPENDR0), resume at
/// ELR_EL1 with SPSR_EL1 and I clear (OwedKick::absorb's state). Returns the
/// number of `hvc #4` exits; more than one means the withdrawn, never
/// acknowledged interrupt was re-taken.
fn el0_boundary_kick_round(vcpu: &Vcpu, intid: u32) -> (u64, Tally) {
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
                vcpu.clear_pending(intid);
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

#[test]
fn gic_qualification_e1_kick_vehicle() {
    let _serial = serial();
    let vm = Arc::new(Vm::create(true));
    let mut outcomes = Vec::new();
    for (index, &intid) in KICK_CANDIDATES.iter().enumerate() {
        let enable: &'static [u32] = if intid == 15 { &[15] } else { &[20] };
        outcomes.push(on_vcpu_thread(&vm, index, index as u16, enable, move |vm, vcpu| {
            // (a) The legacy vehicle is refused once the VM has a GIC.
            let legacy_rc = unsafe { hv_vcpu_set_pending_interrupt(vcpu.id, SDK_IRQ, true) };
            // (b) Pending state survives an hv_vcpu_run return while masked.
            vcpu.enter_el1(vm, index, MODE_SPIN_MASKED);
            vcpu.set_pending(intid);
            let t_b = kick_round(vcpu);
            let survives_run_return = vcpu.pending(intid) && vm.count(index, intid) == 0;
            // (c) Taken and acknowledged at EL1 once unmasked.
            vcpu.enter_el1(vm, index, MODE_SPIN_UNMASKED);
            let t_c = kick_round(vcpu);
            let taken_at_el1 = vm.count(index, intid) == 1 && !vcpu.pending(intid);
            // (d) Taken at EL0 through the lower-EL IRQ vector.
            vcpu.enter_el0(index, false);
            vcpu.set_pending(intid);
            let t_d = kick_round(vcpu);
            let taken_at_el0 = vm.count(index, intid) == 2 && !vcpu.pending(intid);
            // (e) GICR_ICPENDR0 withdraws a pending kick before it is taken.
            vcpu.enter_el1(vm, index, MODE_SPIN_MASKED);
            vcpu.set_pending(intid);
            vcpu.clear_pending(intid);
            vcpu.enter_el1(vm, index, MODE_SPIN_UNMASKED);
            let t_e = kick_round(vcpu);
            let withdrawn_by_icpendr = vm.count(index, intid) == 2;
            // (f) Production's EL0-boundary kick: signalled, never acknowledged,
            // withdrawn by the host, resumed with I clear. Exactly one hvc #4.
            vcpu.set_sys(hv_sys_reg_t::VBAR_EL1, guest_ipa(ptr::addr_of!(gq_vectors_el0_hvc4)));
            vcpu.enter_el0(index, false);
            vcpu.set_pending(intid);
            let (el0_boundary_exits, t_f) = el0_boundary_kick_round(vcpu, intid);
            let el0_boundary_withdrawn = !vcpu.pending(intid) && vm.count(index, intid) == 2;
            vcpu.set_sys(hv_sys_reg_t::VBAR_EL1, RAM_IPA);
            KickOutcome {
                intid,
                legacy_rc,
                survives_run_return,
                taken_at_el1,
                taken_at_el0,
                withdrawn_by_icpendr,
                el0_boundary_exits,
                el0_boundary_withdrawn,
                tallies: [t_b, t_c, t_d, t_e, t_f],
            }
        }));
    }
    for outcome in &outcomes {
        println!("E1 {{\"outcome\":\"{outcome:?}\",\"qualifies\":{}}}", outcome.qualifies());
        assert_eq!(outcome.legacy_rc, HV_UNSUPPORTED, "hv_vcpu_set_pending_interrupt under a GIC");
        for tally in &outcome.tallies[..4] {
            assert_eq!(
                (tally.canceled, tally.other_exception, tally.other_reason, tally.bad_vector),
                (1, 0, 0, 0),
                "{tally:?}"
            );
        }
    }
    let chosen = outcomes.iter().find(|o| o.qualifies()).map(|o| o.intid);
    println!("E1 {{\"chosen_kick_intid\":{chosen:?}}}");
    assert!(chosen.is_some(), "no GIC kick vehicle qualified: STOP at gate D1");
    Arc::into_inner(vm).expect("sole VM handle").destroy();
}
```

Run:

```bash
just test-hvf gic_qualification_e1 --nocapture 2>&1 | tee target/gic-qual-e1.log
grep -a '^E1' target/gic-qual-e1.log
```

Expected: `ok`; `legacy_rc` = `HV_UNSUPPORTED` for both candidates (this is the
SDK fact made executable, and the negative control for the legacy vehicle);
`el0_boundary_exits` = 1 for the chosen candidate; a `chosen_kick_intid` line.
**Gate D1:** a candidate qualifies only if (f) holds as well as (b)-(e), because
(f) is the path production takes. Tasks 5-6 use `chosen_kick_intid`. The plan's
code below is written for SGI 15; if E1 chose 20, Task 5 sets
`KICK_INTID = GicIntid::ppi(20)` instead and nothing else changes. If neither
qualifies only because of (f) (`el0_boundary_exits > 1`), STOP and report: the
lower-EL IRQ slot must acknowledge before `hvc #4`, which is a design change.

- [ ] **Step 5: E2: `hv_vcpus_exit` liveness under a GIC (decides D3)**

Hypotheses under test, from the spec's two anomalies:
- **H-a** (scheduler spike, "one of three `hv_vcpus_exit` wake runs wedged"): a
  CANCELED exit taken while the guest sits in in-HVF `wfi` leaves PC on the
  `wfi`, so a harness that re-enters the guest re-parks it and a wake carried
  only by `hv_vcpus_exit` is lost. Evidence: `pc_at_wfi > 0` in the WFI
  states, with no missed CANCELED.
- **H-b** (asid spike: "a handler that does not save ELR/SPSR before a nested
  fault ERETs to EL0 at 0 (3/3) or wedges"): the wedged vCPU was spinning in an
  in-guest exception loop. Evidence: the EL1 exception storm honours every
  `hv_vcpus_exit`.
- **H-c**: HVF itself drops an exit that races in-kernel WFI entry under the GIC.
  Evidence: a missed CANCELED in a WFI state.

Every state runs 8 vCPUs kicked together through one `hv_vcpus_exit` list, as a
page-table drain kicks every sibling, for 100,000 rounds.

Append to `gic_qualification.rs`:

```rust
#[test]
fn gic_qualification_e2_vcpus_exit_liveness() {
    let _serial = serial();
    let states = [
        LivenessState {
            name: "el1-spin-unmasked-vtimer-100us",
            production_reachable: true,
            entry: Entry::El1(MODE_SPIN_UNMASKED),
            vtimer_period: 2_400,
            kick_pending: false,
        },
        LivenessState {
            name: "el1-spin-masked",
            production_reachable: true,
            entry: Entry::El1(MODE_SPIN_MASKED),
            vtimer_period: 0,
            kick_pending: false,
        },
        LivenessState {
            name: "el1-exception-storm",
            production_reachable: true,
            entry: Entry::El1(MODE_SVC_LOOP),
            vtimer_period: 0,
            kick_pending: false,
        },
        LivenessState {
            name: "el1-irq-window-vtimer-100us",
            production_reachable: true,
            entry: Entry::El1(MODE_IRQ_WINDOW),
            vtimer_period: 2_400,
            kick_pending: false,
        },
        LivenessState {
            name: "el0-spin-unmasked",
            production_reachable: true,
            entry: Entry::El0 { masked: false },
            vtimer_period: 0,
            kick_pending: false,
        },
        LivenessState {
            name: "el0-masked-kick-pending",
            production_reachable: true,
            entry: Entry::El0 { masked: true },
            vtimer_period: 0,
            kick_pending: true,
        },
    ];
    for state in states {
        let report = liveness(state);
        println!("E2 {{\"report\":\"{report:?}\"}}");
        assert_eq!(report.unexpected, 0, "{report:?}");
        assert!(report.wedges.is_empty(), "production-reachable wedge: STOP at gate D3: {report:?}");
        assert_eq!(report.rounds, LIVENESS_ROUNDS, "{report:?}");
    }
}
```

Create `crates/carrick-vmm-hvf/tests/gic_qualification_wfi.rs`:

```rust
//! EL1 plan 1a qualification E2, WFI states: in-HVF `wfi` is a state
//! production never enters (Fact 6; the EL1 image refuses wfi/wfe, Task 7).
//! Wedges here are recorded as data for plan 1c's entry criterion and never
//! fail the test. A separate executable because a wedge leaks the process's
//! only VM.
//!
//! Run ONLY through `just test-hvf gic_qualification_wfi_ --nocapture`.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
#![allow(
    dead_code, // the shared harness is included by two executables
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks
)]

include!("gic_qual/harness.rs");

#[test]
fn gic_qualification_wfi_e2_liveness() {
    let _serial = serial();
    let states = [
        LivenessState {
            name: "wfi-idle",
            production_reachable: false,
            entry: Entry::El1(MODE_WFI),
            vtimer_period: 0,
            kick_pending: false,
        },
        LivenessState {
            name: "wfi-vtimer-1ms",
            production_reachable: false,
            entry: Entry::El1(MODE_WFI),
            vtimer_period: TICKS_PER_MS,
            kick_pending: false,
        },
    ];
    let mut wedged = false;
    for state in states {
        if wedged {
            println!("E2W {{\"state\":\"{}\",\"skipped\":\"a prior wedge leaked this process's VM\"}}", state.name);
            continue;
        }
        let report = liveness(state);
        println!("E2W {{\"report\":\"{report:?}\"}}");
        wedged = !report.wedges.is_empty();
    }
}
```

Run each executable in its own process:

```bash
just test-hvf gic_qualification_e2 --nocapture 2>&1 | tee target/gic-qual-e2.log
grep -a '^E2' target/gic-qual-e2.log
just test-hvf gic_qualification_wfi_ --nocapture 2>&1 | tee target/gic-qual-e2w.log
grep -a '^E2W' target/gic-qual-e2w.log
```

Expected: the production test `ok` with six `E2` lines; the WFI test `ok`
whatever it records. **Gate D3:** any wedge in a production-reachable state
fails the test: STOP 1a, keep the log, take a core of the test process
(`sudo lldb -p <pid> -o "process save-core target/gic-e2.core" -o detach`), and
report. Record for the WFI states: `pc_at_wfi` (H-a), wedges (H-c). A wedge
only in a WFI state does not block 1a (production never parks in WFI: Fact 6,
enforced by Task 7 Step 5's image ban) but is an entry criterion carried to 1c,
written into the spec in Task 11.

- [ ] **Step 6: E3: mid-life vCPU destroy and recreate (decides D2)**

Append to `gic_qualification.rs`:

```rust
const RECREATE_CYCLES: usize = 500;
/// A hang detector for one cycle's 50 us timer, not a latency verdict.
const CYCLE_HANG_BOUND: Duration = Duration::from_secs(10);

/// What a freshly created vCPU's redistributor and CPU interface hold before
/// Carrick configures anything.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawGicState {
    igroupr0: u64,
    isenabler0: u64,
    ispendr0: u64,
    isactiver0: u64,
    ipriorityr3: u64,
    icc_pmr: u64,
    icc_igrpen1: u64,
}

fn raw_gic_state(vcpu: &Vcpu) -> RawGicState {
    use hv_gic_redistributor_reg_t as R;
    RawGicState {
        igroupr0: vcpu.redistributor_reg(R::IGROUPR0),
        isenabler0: vcpu.redistributor_reg(R::ISENABLER0),
        ispendr0: vcpu.redistributor_reg(R::ISPENDR0),
        isactiver0: vcpu.redistributor_reg(R::ISACTIVER0),
        ipriorityr3: vcpu.redistributor_reg(R::IPRIORITYR3),
        icc_pmr: vcpu.icc_reg(hv_gic_icc_reg_t::PMR_EL1),
        icc_igrpen1: vcpu.icc_reg(hv_gic_icc_reg_t::IGRPEN1_EL1),
    }
}

#[test]
fn gic_qualification_e3_midlife_vcpu_recreate() {
    let _serial = serial();
    let vm = Arc::new(Vm::create(true));
    let capacity = vm.gic.as_ref().expect("GIC VM").redistributors();
    assert!(capacity >= 8, "redistributor capacity {capacity}");
    let stop = Arc::new(AtomicBool::new(false));
    let sibling_ids = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(Barrier::new(4));
    let mut siblings = Vec::new();
    for s in 0..3usize {
        let (vm, stop, ids, started) =
            (Arc::clone(&vm), Arc::clone(&stop), Arc::clone(&sibling_ids), Arc::clone(&started));
        siblings.push(std::thread::spawn(move || {
            let vcpu = Vcpu::create(&vm, s, s as u16, ENABLE_VTIMER);
            vcpu.enter_el1(&vm, s, MODE_SPIN_UNMASKED);
            vcpu.arm_vtimer(&vm, s, TICKS_PER_MS, TICKS_PER_MS);
            ids.lock().expect("ids").push(vcpu.id);
            started.wait();
            let tally = loop {
                let tally = vcpu.run_until_canceled(0);
                if tally.canceled != 1 || stop.load(Ordering::Acquire) {
                    break tally;
                }
            };
            // Only the owning thread may destroy its vCPU; siblings are
            // destroyed at teardown, after every vCPU has stopped.
            vcpu.destroy();
            tally
        }));
    }
    started.wait();
    let sibling_irqs_before: Vec<u64> = (0..3).map(|s| vm.count(s, VTIMER_INTID)).collect();

    let churn = {
        let vm = Arc::clone(&vm);
        std::thread::spawn(move || {
            let mut failures = Vec::new();
            let mut raw_states = std::collections::BTreeSet::new();
            let mut carried_over = 0u64;
            let mut bases = std::collections::BTreeMap::<u16, u64>::new();
            let mut previous_left_state = false;
            for cycle in 0..2 * RECREATE_CYCLES {
                let reuse = cycle < RECREATE_CYCLES;
                let index = if reuse { 3 } else { 3 + (cycle % (capacity - 3)) as u16 };
                let block = 3;
                let vcpu = Vcpu::create_unconfigured(&vm, block, index);
                let raw = raw_gic_state(&vcpu);
                raw_states.insert(raw);
                if previous_left_state
                    && (raw.ispendr0 & (1 << KICK_SGI) != 0 || raw.isactiver0 & (1 << UNUSED_PPI) != 0)
                {
                    carried_over += 1;
                }
                let mut base = 0u64;
                unsafe { check(hv_gic_get_redistributor_base(vcpu.id, &mut base), "redistributor base") };
                if let Some(previous) = bases.insert(index, base)
                    && previous != base
                {
                    failures.push(format!("cycle {cycle}: index {index} base moved {previous:#x} -> {base:#x}"));
                }
                vcpu.gic_enable(ENABLE_VTIMER); // scrubs, as production does
                vcpu.enter_el1(&vm, block, MODE_SPIN_UNMASKED);
                vcpu.arm_vtimer(&vm, block, 1_200, 0); // 50 us, one shot
                let id = vcpu.id;
                let watcher = {
                    let vm = Arc::clone(&vm);
                    std::thread::spawn(move || {
                        let deadline = Instant::now() + CYCLE_HANG_BOUND;
                        while vm.count(block, VTIMER_INTID) == 0 && Instant::now() < deadline {
                            std::thread::yield_now();
                        }
                        kick(id);
                    })
                };
                let tally = vcpu.run_until_canceled(0);
                watcher.join().expect("watcher");
                if vm.count(block, VTIMER_INTID) != 1 || tally.canceled != 1 {
                    failures.push(format!("cycle {cycle}: irqs {} tally {tally:?}", vm.count(block, VTIMER_INTID)));
                }
                // Reuse cycles leave a pending kick SGI and an active PPI behind,
                // so the next incarnation of index 3 shows whether HVF resets them.
                previous_left_state = reuse;
                if reuse {
                    vcpu.set_pending(KICK_SGI);
                    vcpu.set_active(UNUSED_PPI);
                }
                vcpu.destroy();
            }
            (failures, raw_states, carried_over, bases.len())
        })
    };
    let (failures, raw_states, carried_over, distinct_indices) = churn.join().expect("churn thread");
    let sibling_irqs: Vec<u64> = (0..3)
        .map(|s| vm.count(s, VTIMER_INTID) - sibling_irqs_before[s])
        .collect();

    // Teardown in HVF's order: stop every vCPU, destroy each on its own thread,
    // then the VM.
    stop.store(true, Ordering::Release);
    for &id in sibling_ids.lock().expect("ids").iter() {
        kick(id);
    }
    for sibling in siblings {
        let tally = sibling.join().expect("sibling");
        assert_eq!((tally.other_exception, tally.other_reason, tally.bad_vector), (0, 0, 0), "{tally:?}");
    }
    println!(
        "E3 {{\"cycles\":{},\"failures\":{},\"raw_states\":\"{raw_states:?}\",\
         \"carried_over\":{carried_over},\"distinct_indices\":{distinct_indices},\
         \"sibling_irqs\":\"{sibling_irqs:?}\",\"first_failures\":\"{:?}\"}}",
        2 * RECREATE_CYCLES,
        failures.len(),
        failures.iter().take(5).collect::<Vec<_>>()
    );
    assert!(failures.is_empty(), "mid-life recreate failed: STOP at gate D2");
    for irqs in sibling_irqs {
        assert!(irqs >= 1, "a sibling took no vtimer interrupt during the churn");
    }
    Arc::into_inner(vm).expect("sole VM handle").destroy();
}
```

Run:

```bash
just test-hvf gic_qualification_e3 --nocapture 2>&1 | tee target/gic-qual-e3.log
grep -a '^E3' target/gic-qual-e3.log
```

Expected: `ok` with `failures: 0`. **Gate D2** is decided together with the
Task 2 census: if E3 fails, STOP 1a after Task 2 and write a lifecycle plan
(vCPUs held for the VM's life; the initial runner becomes an executor or keeps
its vCPU). Record `raw_states` (what an unconfigured redistributor holds) and
`carried_over` (recreated vCPUs that inherited the previous incarnation's
pending SGI or active PPI). A non-zero `carried_over` does not fail E3, because
production scrubs every private interrupt before enabling its own (Task 5
`configure_new_vcpu`, mirrored by the harness's `gic_enable`), and the delivery
check above runs after that scrub.

- [ ] **Step 7: E4: the SPI matrix (explains D4; does not gate 1a)**

Append:

```rust
#[test]
fn gic_qualification_e4_spi_delivery_matrix() {
    let _serial = serial();
    let vm = Arc::new(Vm::create(true));
    let (spi_base, spi_count) = {
        let gic = vm.gic.as_ref().expect("GIC VM");
        (gic.spi_base, gic.spi_count)
    };
    assert!(spi_count > 0, "no SPI range");
    let rows = on_vcpu_thread(&vm, 0, 0, &[], move |vm, vcpu| {
        let mut rows = Vec::new();
        let (mut typer, mut ctlr_reset) = (0u64, 0u64);
        unsafe {
            check(hv_gic_get_distributor_reg(hv_gic_distributor_reg_t::TYPER, &mut typer), "GICD_TYPER");
            check(hv_gic_get_distributor_reg(hv_gic_distributor_reg_t::CTLR, &mut ctlr_reset), "GICD_CTLR");
        }
        rows.push(format!("typer={typer:#x} ctlr_after_create={ctlr_reset:#x} spi_base={spi_base}"));
        if spi_base != 32 {
            rows.push("spi_base is not 32: IROUTER32/ICFGR2/IPRIORITYR8 do not cover it; matrix skipped".into());
            return rows;
        }
        let bit = 1u64; // INTID 32 is bit 0 of the *1 registers
        for ctlr in [0x12u64, 0x02, 0x13, 0x10] {
            for edge in [true, false] {
                for route in [mpidr(0) & 0xff_00ff_ffff, 1 << 31] {
                    use hv_gic_distributor_reg_t as D;
                    let (mut ctlr_back, mut pended, mut active) = (0u64, 0u64, 0u64);
                    unsafe {
                        check(hv_gic_set_distributor_reg(D::CTLR, ctlr), "CTLR");
                        check(hv_gic_get_distributor_reg(D::CTLR, &mut ctlr_back), "CTLR back");
                        check(hv_gic_set_distributor_reg(D::IGROUPR1, bit), "IGROUPR1");
                        check(hv_gic_set_distributor_reg(D::ICFGR2, if edge { 0b10 } else { 0 }), "ICFGR2");
                        check(hv_gic_set_distributor_reg(D::IPRIORITYR8, 0x80), "IPRIORITYR8");
                        check(hv_gic_set_distributor_reg(D::IROUTER32, route), "IROUTER32");
                        check(hv_gic_set_distributor_reg(D::ISENABLER1, bit), "ISENABLER1");
                        let before = vm.count(0, 32);
                        check(hv_gic_set_spi(32, true), "hv_gic_set_spi");
                        check(hv_gic_get_distributor_reg(D::ISPENDR1, &mut pended), "ISPENDR1");
                        vcpu.enter_el1(vm, 0, MODE_SPIN_UNMASKED);
                        let tally = kick_round(vcpu);
                        check(hv_gic_get_distributor_reg(D::ISACTIVER1, &mut active), "ISACTIVER1");
                        let delivered = vm.count(0, 32) > before;
                        if !edge {
                            check(hv_gic_set_spi(32, false), "hv_gic_set_spi low");
                        }
                        check(hv_gic_set_distributor_reg(D::ICPENDR1, bit), "ICPENDR1");
                        rows.push(format!(
                            "ctlr={ctlr:#x} ctlr_back={ctlr_back:#x} edge={edge} route={route:#x} \
                             pended={} active_after={} delivered={delivered} tally={tally:?}",
                            pended & bit != 0,
                            active & bit != 0
                        ));
                    }
                }
            }
        }
        rows
    });
    for row in &rows {
        println!("E4 {{\"row\":\"{row}\"}}");
    }
    assert!(rows.len() == 17 || rows.len() == 2, "every configuration classified");
    Arc::into_inner(vm).expect("sole VM handle").destroy();
}
```

Run:

```bash
just test-hvf gic_qualification_e4 --nocapture 2>&1 | tee target/gic-qual-e4.log
grep -a '^E4' target/gic-qual-e4.log
```

Expected: `ok`, 16 classified rows (plus the header row). Classify the anomaly in
the results doc as exactly one of: (i) a configuration delivers, naming the bits
the spike lacked; (ii) SPIs pend (`pended=true`) but never reach the CPU interface
under any configuration; (iii) SPIs never pend. 1a exposes no SPI API whatever the
outcome; (ii) or (iii) is recorded as an HVF limit, and cross-vCPU wakes stay on
SGIs (1c).

- [ ] **Step 8: E5: vCPU capacity and redistributor placement under a GIC (decides D5, qualifies D7)**

Append:

```rust
#[test]
fn gic_qualification_e5_vcpu_capacity() {
    let _serial = serial();
    let vm = Arc::new(Vm::create(true));
    let (redistributors, redistributor_size, region) = {
        let gic = vm.gic.as_ref().expect("GIC VM");
        (gic.redistributors(), gic.redist_size as u64, gic.redist_region as u64)
    };
    let mut max_vcpus = 0u32;
    unsafe { check(hv_vm_get_max_vcpu_count(&mut max_vcpus), "hv_vm_get_max_vcpu_count") };
    let capacity = redistributors.min(max_vcpus as usize);
    let attempts = (capacity + 4).min(MAX_BLOCKS);
    let release = Arc::new(Barrier::new(attempts + 1));
    let results = Arc::new(Mutex::new(Vec::new()));
    let threads: Vec<_> = (0..attempts)
        .map(|index| {
            let (release, results) = (Arc::clone(&release), Arc::clone(&results));
            std::thread::spawn(move || {
                let (mut id, mut exit) = (0, ptr::null());
                let rc = unsafe { hv_vcpu_create(&mut id, &mut exit, ptr::null_mut()) };
                let (mut base_rc, mut base) = (-1, 0u64);
                if rc == 0 {
                    unsafe {
                        check(hv_vcpu_set_sys_reg(id, hv_sys_reg_t::MPIDR_EL1, mpidr(index as u16)), "MPIDR");
                        base_rc = hv_gic_get_redistributor_base(id, &mut base);
                    }
                }
                results.lock().expect("results").push((index, rc, base_rc, base));
                release.wait();
                if rc == 0 {
                    unsafe { check(hv_vcpu_destroy(id), "hv_vcpu_destroy") };
                }
            })
        })
        .collect();
    release.wait();
    for thread in threads {
        thread.join().expect("capacity thread");
    }
    let mut results = results.lock().expect("results").clone();
    results.sort();
    let created = results.iter().filter(|r| r.1 == 0).count();
    let placed: Vec<(usize, u64)> =
        results.iter().filter(|r| r.1 == 0 && r.2 == 0).map(|r| (r.0, r.3)).collect();
    let first_failure = results.iter().find(|r| r.1 != 0).map(|r| (r.0, r.1 as u32));
    let distinct: std::collections::BTreeSet<u64> = placed.iter().map(|&(_, base)| base).collect();
    let linear = placed
        .iter()
        .all(|&(index, base)| base == GIC_REDIST_IPA + index as u64 * redistributor_size);
    println!(
        "E5 {{\"redistributors\":{redistributors},\"max_vcpus\":{max_vcpus},\"capacity\":{capacity},\
         \"attempts\":{attempts},\"created\":{created},\"with_redistributor\":{},\
         \"distinct_bases\":{},\"linear_by_index\":{linear},\"first_failure\":\"{first_failure:?}\"}}",
        placed.len(),
        distinct.len()
    );
    for index in 0..capacity {
        assert!(
            placed.iter().any(|&(placed_index, _)| placed_index == index),
            "vCPU {index} below the capacity has no redistributor"
        );
    }
    assert_eq!(distinct.len(), placed.len(), "two MPIDRs share a redistributor frame");
    for &(index, base) in &placed {
        assert!(
            (GIC_REDIST_IPA..GIC_REDIST_IPA + region).contains(&base)
                && (base - GIC_REDIST_IPA).is_multiple_of(redistributor_size),
            "vCPU {index}: redistributor base {base:#x} outside the region or off-stride"
        );
    }
    Arc::into_inner(vm).expect("sole VM handle").destroy();
}
```

Run:

```bash
just test-hvf gic_qualification_e5 --nocapture 2>&1 | tee target/gic-qual-e5.log
grep -a '^E5' target/gic-qual-e5.log
```

Expected: `ok`. **Gate D5:** `REDISTRIBUTOR_CAPACITY = redistributors`; Task 5
clamps the per-carrier vCPU budget to `min(max_vcpus, redistributors)`. Record
whether the clamp is effective on this host (a planning-time read-only query
here reported 256 redistributors and `max_vcpus` 64, which makes the clamp a
no-op; E5 confirms or corrects that). Record the first failure's return code
as data (it need not be `HV_NO_RESOURCES`). The distinct/in-region/stride
asserts qualify D7: every MPIDR of the Aff1/Aff0 layout gets its own
redistributor frame; `linear_by_index` records whether HVF assigns frames by
index order (informational).

- [ ] **Step 9: E5b: the concurrent VM ceiling with a GIC per VM (decides D5b)**

Carrick's soft pre-throttle (`GLOBAL_VCPU_CEILING = 120`,
vcpu_admission.rs) rests on 127 concurrent VMs measured without a GIC. A GIC
per VM may lower it. Extend the probe that measured it.

In `crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs`:
- add `hv_gic_config_create, hv_gic_config_set_distributor_base,
  hv_gic_config_set_redistributor_base, hv_gic_create` to the
  `use applevisor_sys::{...}` list;
- add the helper:

```rust
    /// Hypervisor.framework's in-kernel GIC at Carrick's production placement
    /// (EL1 plan 1a, Task 4 promotes the literals to carrick-mem constants).
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

Quiet host: no guest, no Docker VM, nothing else using Hypervisor.framework
(this creates about 127 VMs; the July 2026 E4 measurement ran the same probe).

```bash
cargo build --release -p carrick-vmm-hvf --bin hvf_fork_probe
codesign --force --sign - --entitlements scripts/entitlements.plist target/release/hvf_fork_probe
target/release/hvf_fork_probe concurrent-ceiling 140 30 1 0 0 2>&1 | tee target/gic-qual-e5b-plain.log
target/release/hvf_fork_probe concurrent-ceiling 140 30 1 0 1 2>&1 | tee target/gic-qual-e5b-gic.log
grep -a 'live_at_failure\|case=' target/gic-qual-e5b-*.log
```

Expected: both runs report a `live_at_failure` ceiling (the children
self-destruct after 30 s). **Gate D5b:** if the GIC ceiling is below the plain
ceiling, Task 5 Step 4 sets `GLOBAL_VCPU_CEILING` to the GIC ceiling minus 7
(the same margin as 127 → 120) and rewrites its doc comment with both numbers;
otherwise the constant stays. Either way, Task 5 routes `HV_NO_RESOURCES` from
`hv_gic_create` through the existing park+retry backpressure.

- [ ] **Step 10: E6: costs (decides nothing; records D6 inputs)**

Append to `gic_qualification.rs`:

```rust
fn p50_p99(mut samples: Vec<u64>) -> (u64, u64) {
    samples.sort_unstable();
    (samples[samples.len() / 2], samples[samples.len() * 99 / 100])
}

fn exit_round_trips(with_gic: bool) -> (u64, u64) {
    let vm = Arc::new(Vm::create(with_gic));
    let samples = on_vcpu_thread(&vm, 0, 0, &[], |vm, vcpu| {
        vcpu.enter_el1(vm, 0, MODE_HVC_LOOP);
        let mut samples = Vec::with_capacity(100_000);
        for _ in 0..100_000 {
            let start = now_ticks();
            unsafe { check(hv_vcpu_run(vcpu.id), "hv_vcpu_run") };
            samples.push(ticks_to_ns(now_ticks() - start));
            let exit = unsafe { &*vcpu.exit };
            assert_eq!(exit.reason, hv_exit_reason_t::EXCEPTION);
        }
        samples
    });
    Arc::into_inner(vm).expect("sole VM handle").destroy();
    p50_p99(samples)
}

#[test]
fn gic_qualification_e6_costs() {
    let _serial = serial();
    let vm = Arc::new(Vm::create(true));
    let kick_pair = on_vcpu_thread(&vm, 0, 0, &[15], |_, vcpu| {
        let mut samples = Vec::with_capacity(100_000);
        for _ in 0..100_000 {
            let start = now_ticks();
            vcpu.set_pending(15);
            vcpu.clear_pending(15);
            samples.push(ticks_to_ns(now_ticks() - start));
        }
        p50_p99(samples)
    });
    Arc::into_inner(vm).expect("sole VM handle").destroy();
    let vm = Arc::new(Vm::create(false));
    let legacy_pair = on_vcpu_thread(&vm, 0, 0, &[], |_, vcpu| {
        let mut samples = Vec::with_capacity(100_000);
        for _ in 0..100_000 {
            let start = now_ticks();
            unsafe {
                check(hv_vcpu_set_pending_interrupt(vcpu.id, SDK_IRQ, true), "legacy arm");
                check(hv_vcpu_set_pending_interrupt(vcpu.id, SDK_IRQ, false), "legacy clear");
            }
            samples.push(ticks_to_ns(now_ticks() - start));
        }
        p50_p99(samples)
    });
    Arc::into_inner(vm).expect("sole VM handle").destroy();
    let exits_gic = exit_round_trips(true);
    let exits_plain = exit_round_trips(false);
    println!(
        "E6 {{\"gic_kick_pair_ns\":\"{kick_pair:?}\",\"legacy_kick_pair_ns\":\"{legacy_pair:?}\",\
         \"exit_round_trip_ns_gic\":\"{exits_gic:?}\",\"exit_round_trip_ns_plain\":\"{exits_plain:?}\"}}"
    );
}
```

`MODE_HVC_LOOP` exits with `hvc #0x1d`; HVF reports the post-`hvc` PC, so each
re-entry executes the loop's branch and the next `hvc`.

Run on a quiet host (no other guest, no Docker VM busy):

```bash
just test-hvf gic_qualification_e6 --nocapture 2>&1 | tee target/gic-qual-e6.log
grep -a '^E6' target/gic-qual-e6.log
```

Expected: `ok` and one `E6` line. If `exit_round_trip_ns_gic` p50 exceeds
`exit_round_trip_ns_plain` p50 by more than 10%, every exit in production pays
that: record it as a finding and require the Task 13 paired runs to report the
exit-heavy rows (`go-build`, `cpython-subprocess`) against the base artifact.

- [ ] **Step 11: Record the results and decisions**

Append to `docs/perf-results/2026-09-25-hvf-gic-qualification.md`: host (model,
macOS build from `sw_vers`), source HEAD, both test executables' SHA-256 (the
paths are in `target/test-results/carrick-vmm-hvf-signed-artifacts.jsonl`), every
`E<n>`/`E2W` line verbatim, both E5b ceilings, and a decisions table filling D1
(chosen INTID, with (f)), D2 (E3 verdict, `raw_states`, `carried_over`), D3
(per-state wedges; the detection bound "zero wedges in 100,000 rounds x 8 vCPUs
per state bounds the per-round wedge probability below about 3e-5 at 95%
confidence"; `pc_at_wfi`; which of H-a/H-b/H-c the data supports), D4 (SPI
class i/ii/iii), D5 (`redistributors`, `max_vcpus`, whether the clamp is
effective), D5b (both ceilings and the `GLOBAL_VCPU_CEILING` decision), D6 (cost
ratios), D7 (distinct, in-region, on-stride bases), D12 (the `E0-id` line).
Write "not explained" where the data does not discriminate; do not pick a
hypothesis the data does not support.

- [ ] **Step 12: Lint and commit**

```bash
cargo clippy -p carrick-vmm-hvf --all-targets -- -D warnings
just fmt-check
git add crates/carrick-vmm-hvf/tests/gic_qual/harness.rs crates/carrick-vmm-hvf/tests/gic_qualification.rs \
  crates/carrick-vmm-hvf/tests/gic_qualification_wfi.rs crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs \
  docs/perf-results/2026-09-25-hvf-gic-qualification.md
git commit -F- <<'MSG'
test(hvf): qualify the in-kernel GIC before carrick adopts it

Why: the EL1 kernel design requires Hypervisor.framework's in-kernel
GIC, but the behaviours it depends on were unmeasured under Carrick's
lifecycle: the kick vehicle once `hv_vcpu_set_pending_interrupt` is
refused (including the un-acknowledged EL0-boundary kick), destroying
and recreating a vCPU while its VM and siblings live, whether
`hv_vcpus_exit` is always honoured, why `hv_gic_set_spi` never reached
the CPU interface in the scheduler spike, and what a GIC per VM costs
in VM-creation capacity.

What: a signed qualification suite with its own guest blob, split into
a production-reachable executable and a WFI-state executable (a wedge
leaks the process's one VM). E0 geometry, the vtimer PPI at EL1 and the
EL0 ID view (control: GIC-less VM); E1 SGI 15 / PPI 20 through
GICR_ISPENDR0, including production's `hvc #4` slot (control: the
legacy call returns HV_UNSUPPORTED); E2 8-vCPU kick liveness, 100,000
rounds per state, hypotheses H-a/H-b/H-c; E3 500+500 mid-life recreate
cycles beside three running siblings, with inherited-state capture; E4
SPI matrix; E5 capacity and redistributor placement; E5b the concurrent
VM ceiling with a GIC (hvf_fork_probe); E6 costs.

Verified: `just test-hvf gic_qualification_e<N> --nocapture` per
experiment and `gic_qualification_wfi_` on <host>; results and decisions
in docs/perf-results/2026-09-25-hvf-gic-qualification.md.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

Replace `<host>` with the `sw_vers`/model line before committing.

---

### Task 2: vCPU lifecycle census (decides D2 with E3)

E3 answers "is a mid-life recreate safe under a GIC"; this task answers "which
production paths recreate a vCPU in a VM that already destroyed one, and how
often". HVF's rule ("once the virtual machine vcpus are running, its topology
is considered final. Destroy vcpus only when you are tearing down the virtual
machine") is about the VM going on to be used after a destroy, so the census
classifies a destroy as mid-life only when a later create follows it in the
same VM generation. That definition counts the initial-runner hand-off and the
last `reclaim_park` under the whole-VM lease (both leave zero vCPUs and later
create new ones in the same VM), and does not count the one-by-one destroys of
an ordinary teardown (no create follows them in that generation).

The census is a `carrick trace` profile with a strict Rust reader (AGENTS.md:
D scripts belong to a Rust profile that hashes them, and a capture that yields
nothing is an error). It also makes every destroy go through one raw-destroy
function, including the paths that today destroy through applevisor's `Drop`
without reporting (Fact 5), so Task 5 can release a vCPU's GIC affinity in the
same critical section as `hv_vcpu_destroy`.

**Files:**
- Modify: `crates/carrick-observability/src/probes.rs` (provider fn, real and stub wrappers)
- Modify: `crates/carrick-vmm-hvf/src/trap.rs` (`VcpuDestroySite`, `VcpuCreateSite`,
  `CARRIER_VM_GENERATION`, `destroy_raw_vcpu`, `vcpu_created`/`vcpu_destroyed`
  signatures, `from_process_spec` guard, the funnel's generation publication)
- Modify: `crates/carrick-vmm-hvf/src/trap/vcpu_admission.rs` (create sites, test)
- Modify: `crates/carrick-vmm-hvf/src/trap/persistent_executor.rs` (4 destroy sites)
- Modify: `crates/carrick-vmm-hvf/src/trap/execve_rebuild.rs` (1 destroy site)
- Modify: `crates/carrick-vmm-hvf/src/trap/carrier_custody.rs` (creation rollback, `SetupVcpuGuard`)
- Modify: `crates/carrick-vmm-hvf/src/trap/cow_engine.rs` (`add_vcpu` error path)
- Create: `scripts/dtrace/hvf-vcpu-lifecycle-census.d`
- Modify: `crates/carrick-runtime/src/dtrace_consumer.rs` (bundled script constant)
- Create: `crates/carrick-cli/src/hvf_vcpu_lifecycle_profile.rs`
- Modify: `crates/carrick-cli/src/main.rs`, `trace_profile.rs`, `commands.rs`, `args.rs`
- Modify: `scripts/migrate/runtime-global-state.json` (one row)

**Interfaces:**
- Produces: `pub(crate) enum VcpuDestroySite { ReclaimPark = 1, InitialRunnerPark = 2,
  SharedWaitPark = 3, ThreadExit = 4, ExecveRebuild = 5, CreationRollback = 6,
  SetupRollbackLocal = 7, CreationError = 8 }`,
  `pub(crate) enum VcpuCreateSite { VmCreation = 101, ExistingVm = 102 }`,
  `pub(crate) fn destroy_raw_vcpu(vcpu_id: u64, site: VcpuDestroySite) -> applevisor_sys::hv_return_t`
  (the only raw `hv_vcpu_destroy` in the crate's `src/` outside `src/bin`),
  `pub(crate) fn vcpu_destroyed(vcpu_id: u64, site: VcpuDestroySite)`,
  `pub(crate) fn carrier_vm_generation() -> u64`,
  `carrick_observability::probes::hvf_vcpu_lifecycle(site: u32, vcpu: u64, generation: u64)`,
  USDT `carrick*:::hvf-vcpu-lifecycle`,
  `carrick trace --profile hvf-vcpu-lifecycle-census`.
- Consumed by: Task 5 (`destroy_raw_vcpu` and the `SetupVcpuGuard` drop take
  the GIC lock and release the affinity index; the D2 guard reads the site).

- [ ] **Step 1: Write the failing site test**

Append to `crates/carrick-vmm-hvf/src/trap/vcpu_admission.rs`:

```rust
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod vcpu_lifecycle_site_tests {
    fn source(file: &str) -> String {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file))
            .unwrap()
    }

    /// Every vCPU destroy goes through `destroy_raw_vcpu` (or, for the local
    /// RAII lane, applevisor's Drop inside `SetupVcpuGuard`) and reports where
    /// it happened, so the lifecycle census and the GIC affinity release see
    /// every destroy exactly once.
    #[test]
    fn every_vcpu_destroy_names_its_site() {
        let raw = concat!("hv_vcpu_", "destroy(");
        let mut raw_sites = Vec::new();
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = vec![src.join("trap.rs"), src.join("hvf_aarch64_engine.rs")];
        for entry in std::fs::read_dir(src.join("trap")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
        for path in &files {
            let count: usize = std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .map(|line| line.matches(raw).count())
                .sum();
            if count != 0 {
                raw_sites.push((path.file_name().unwrap().to_string_lossy().into_owned(), count));
            }
        }
        assert_eq!(raw_sites, [("trap.rs".to_owned(), 1)], "one raw destroy: destroy_raw_vcpu");

        for (file, site) in [
            ("trap/persistent_executor.rs", "VcpuDestroySite::ReclaimPark"),
            ("trap/persistent_executor.rs", "VcpuDestroySite::InitialRunnerPark"),
            ("trap/persistent_executor.rs", "VcpuDestroySite::SharedWaitPark"),
            ("trap/persistent_executor.rs", "VcpuDestroySite::ThreadExit"),
            ("trap/execve_rebuild.rs", "VcpuDestroySite::ExecveRebuild"),
            ("trap/carrier_custody.rs", "VcpuDestroySite::CreationRollback"),
            ("trap/carrier_custody.rs", "VcpuDestroySite::SetupRollbackLocal"),
            ("trap/cow_engine.rs", "VcpuDestroySite::CreationError"),
        ] {
            assert!(source(file).contains(site), "{file}: {site}");
        }

        // Every reference to `vcpu_destroyed` in production files is a call
        // naming its site (no bare fn-pointer use that loses the site).
        for file in [
            "trap/persistent_executor.rs",
            "trap/execve_rebuild.rs",
            "trap/carrier_custody.rs",
            "trap/cow_engine.rs",
        ] {
            for line in source(file).lines().filter(|line| line.contains("vcpu_destroyed")) {
                assert!(
                    line.contains("vcpu_destroyed(") && line.contains("VcpuDestroySite::"),
                    "{file}: `{}` must call vcpu_destroyed with a site",
                    line.trim()
                );
            }
        }
    }
}
```

- [ ] **Step 2: Run it red**

```bash
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib every_vcpu_destroy_names_its_site
```

Expected: FAIL `one raw destroy: destroy_raw_vcpu` with six raw sites listed
(`persistent_executor.rs` 4, `execve_rebuild.rs` 1, `carrier_custody.rs` 1).

- [ ] **Step 3: Add the probe**

In `crates/carrick-observability/src/probes.rs`, inside
`#[usdt::provider(provider = "carrick")] mod carrick_usdt` next to
`fn vm__lifecycle(_: u32, _: i32) {}`:

```rust
        /// HVF vCPU created or destroyed. arg0 = site (1-8 destroy, 101-102
        /// create), arg1 = HVF vCPU id, arg2 = carrier VM generation.
        fn hvf__vcpu__lifecycle(_: u32, _: u64, _: u64) {}
```

In the real wrapper module, next to `pub fn vm_lifecycle`:

```rust
    pub fn hvf_vcpu_lifecycle(site: u32, vcpu: u64, generation: u64) {
        carrick_usdt::hvf__vcpu__lifecycle!(|| (site, vcpu, generation));
    }
```

In the stub module, next to `stub!(kick_rearm_irq(...))`:

```rust
    stub!(hvf_vcpu_lifecycle(site: u32, vcpu: u64, generation: u64));
```

- [ ] **Step 4: Add the site types, the raw-destroy function and the generation**

In `crates/carrick-vmm-hvf/src/trap.rs`, next to `CARRIER_VM_LIVE` (trap.rs:457):

```rust
/// Custody generation of the carrier's current VM, published with
/// `CARRIER_VM_LIVE` on the creation funnel's success. Diagnostic: the
/// `hvf-vcpu-lifecycle` census groups vCPU events by VM generation.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
static CARRIER_VM_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn carrier_vm_generation() -> u64 {
    CARRIER_VM_GENERATION.load(std::sync::atomic::Ordering::Acquire)
}
```

and in `create_vm_with_admission`, directly after
`CARRIER_VM_LIVE.store(true, std::sync::atomic::Ordering::Release);`:

```rust
            CARRIER_VM_GENERATION.store(generation.0, std::sync::atomic::Ordering::Release);
```

Next to `VCPU_CREATED_TOTAL`:

```rust
/// Where an HVF vCPU was destroyed. Reported to the `hvf-vcpu-lifecycle`
/// probe and (Task 5) to the GIC topology, which releases the vCPU's affinity.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum VcpuDestroySite {
    ReclaimPark = 1,
    InitialRunnerPark = 2,
    SharedWaitPark = 3,
    /// Includes persistent worker retirement and carrier teardown.
    ThreadExit = 4,
    ExecveRebuild = 5,
    CreationRollback = 6,
    /// `SetupVcpuGuard` with `SetupVcpuCleanup::LocalRaii` (applevisor Drop).
    SetupRollbackLocal = 7,
    /// A vCPU created but never handed out because a later setup step failed.
    CreationError = 8,
}

/// Which wrapper created an HVF vCPU.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum VcpuCreateSite {
    VmCreation = 101,
    ExistingVm = 102,
}

/// The crate's only raw `hv_vcpu_destroy` (test `every_vcpu_destroy_names_its_site`).
/// The caller is the owning thread and never uses the handle afterwards; on
/// success it reports `vcpu_destroyed(vcpu_id, site)` after dropping its
/// census guard. EL1 plan 1a Task 5 makes this hold the GIC topology lock
/// across the destroy and the affinity release, keyed by `site`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn destroy_raw_vcpu(vcpu_id: u64, site: VcpuDestroySite) -> applevisor_sys::hv_return_t {
    let _ = site;
    // SAFETY: the caller owns the vCPU on this thread and forgets its handle.
    unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) }
}
```

Change `vcpu_created()` (trap.rs:638) to take the id and site and report them:

```rust
fn vcpu_created(vcpu_id: u64, site: VcpuCreateSite) {
    VCPU_CREATED_TOTAL.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    THREAD_VCPU_CREATED_TOTAL.set(THREAD_VCPU_CREATED_TOTAL.get().saturating_add(1));
    crate::probes::hvf_vcpu_lifecycle(site as u32, vcpu_id, carrier_vm_generation());
}
```

and `vcpu_destroyed` (trap.rs:881):

```rust
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn vcpu_destroyed(vcpu_id: u64, site: VcpuDestroySite) {
    crate::probes::hvf_vcpu_lifecycle(site as u32, vcpu_id, carrier_vm_generation());
    release_admission_permit_for_vcpu(vcpu_id);
    // A slot freed: wake a sibling thread blocked in the admission gate.
    vcpu_gate::notify();
}
```

Update the destroy sites (Fact 5), each keeping its existing shape
(`self._vcpu_guard = None;` stays between the destroy and the report):
- persistent_executor.rs `reclaim_park`: `let rc = destroy_raw_vcpu(vcpu_id, VcpuDestroySite::ReclaimPark);`
  and `vcpu_destroyed(vcpu_id, VcpuDestroySite::ReclaimPark);`
- persistent_executor.rs `initial_runner_park`: the same with `InitialRunnerPark`
- persistent_executor.rs `shared_wait_park`: the same with `SharedWaitPark`
  (`let vcpu_rc = destroy_raw_vcpu(...)`)
- persistent_executor.rs `destroy_vcpu_on_thread_exit`: the same with `ThreadExit`
- execve_rebuild.rs mature branch: `let vcpu_destroy_rc = destroy_raw_vcpu(inherited_vcpu_id, VcpuDestroySite::ExecveRebuild);`
  and `vcpu_destroyed(inherited_vcpu_id, VcpuDestroySite::ExecveRebuild);`
- carrier_custody.rs `drive_pending_carrier_vm_cleanup`: the closure becomes
  `|id| destroy_raw_vcpu(id, VcpuDestroySite::CreationRollback)`, and
  `drive_pending_carrier_vm_cleanup_using` reports
  `vcpu_destroyed(id, VcpuDestroySite::CreationRollback);`
- carrier_custody.rs `impl Drop for SetupVcpuGuard`: the third argument of
  `complete_local_vcpu_raii_cleanup` becomes
  `|id| vcpu_destroyed(id, VcpuDestroySite::SetupRollbackLocal)`.

Route the two paths that destroy through applevisor's `Drop` without
reporting:
- cow_engine.rs `add_vcpu`: replace `let mailbox = self.allocate_mailbox_for_vcpu(&vcpu)?;` with

```rust
        let mailbox = match self.allocate_mailbox_for_vcpu(&vcpu) {
            Ok(mailbox) => mailbox,
            Err(error) => {
                // Never handed out: destroy it here, reported, instead of
                // letting applevisor's Drop destroy it unreported.
                let vcpu = std::mem::ManuallyDrop::new(vcpu);
                let id = vcpu.id();
                if destroy_raw_vcpu(id, VcpuDestroySite::CreationError) == 0 {
                    self._vcpu_guard = None;
                    vcpu_destroyed(id, VcpuDestroySite::CreationError);
                }
                return Err(error);
            }
        };
```

- trap.rs `from_process_spec` (trap.rs:6610): wrap the new vCPU so every
  `?`/`return Err` after it destroys it through the reporting guard:
  `let vcpu = SetupVcpuGuard::new(create_vcpu(&vm)?, SetupVcpuCleanup::LocalRaii);`
  (uses of `vcpu` keep working through `Deref`), and the success tail returns
  `vcpu.into_inner()` where it returned `vcpu`. `vm` is declared before `vcpu`,
  so on an error the vCPU is destroyed before the VM handle drops.

In `vcpu_admission.rs`, `create_vcpu_with_permit` calls
`vcpu_created(vcpu.id(), VcpuCreateSite::VmCreation)` and `create_vcpu` calls
`vcpu_created(vcpu.id(), VcpuCreateSite::ExistingVm)`. Import the new names where
the compiler asks (`use crate::trap::{VcpuCreateSite, VcpuDestroySite, destroy_raw_vcpu};`
in each touched module that does not already glob-import `super::*`; `SetupVcpuGuard`
and `SetupVcpuCleanup` in trap.rs through the path carrier_custody exports them on).

- [ ] **Step 5: Run green, then the whole crate's lib tests**

```bash
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib every_vcpu_destroy_names_its_site
env RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib
cargo test -p carrick-observability
```

Expected: all PASS. (`carrier_custody.rs` source-slicing tests assert ordering
around `SetupVcpuCleanup`, not the `vcpu_destroyed` argument list; if one fails,
it names the string it expected; restore that string, do not edit the test.)

- [ ] **Step 6: Ledger row for the new static**

```bash
python3 scripts/migrate/check-runtime-global-state.py --check || true
python3 scripts/migrate/check-runtime-global-state.py --bootstrap \
  | python3 -c 'import json,sys; rows=json.load(sys.stdin)["rows"]; print(json.dumps([r for r in rows if r["symbol"]=="CARRIER_VM_GENERATION"], indent=1))'
```

Add the printed row to `scripts/migrate/runtime-global-state.json` `rows`, with
`"classification": "carrier_infra"` and the rationale "Custody generation of
the carrier's one live HVF VM, published beside CARRIER_VM_LIVE; the
hvf-vcpu-lifecycle census groups vCPU events by it.", keeping the bootstrap
fingerprint. Re-run `--check`: exit 0.

- [ ] **Step 7: The census script and its strict profile**

Create `scripts/dtrace/hvf-vcpu-lifecycle-census.d`:

```d
#!/usr/sbin/dtrace -Zs
/*
 * hvf-vcpu-lifecycle-census.d -- every HVF vCPU create and destroy of one run,
 * in order, with its site and carrier VM generation. The strict reader
 * (carrick-cli hvf_vcpu_lifecycle_profile.rs, `carrick trace --profile
 * hvf-vcpu-lifecycle-census`) derives the MID-LIFE recreates: a create that
 * follows a destroy in the same VM generation, the topology change hv_gic.h
 * advises against once a GIC exists. Teardown destroys (no create follows in
 * that generation) are not mid-life.
 *
 * (a) What it measures: one HVFVCPU|event line per carrick*:::hvf-vcpu-lifecycle.
 *     Site legend: 1 reclaim-park, 2 initial-runner-park, 3 shared-wait-park,
 *     4 thread-exit (worker retirement and carrier teardown), 5 execve-rebuild,
 *     6 creation-rollback, 7 setup-rollback-local, 8 creation-error,
 *     101 vm-creation, 102 existing-vm.
 * (b) Provider ABI (carrick-observability probes.rs, hvf__vcpu__lifecycle):
 *     arg0 = site (u32), arg1 = HVF vCPU id (u64), arg2 = carrier VM custody
 *     generation (u64; one VM per carrier process). `-Z` is required: the
 *     carrier is spawned after arming. Other agents' guests share carrick*:::,
 *     so every clause screens pid == $target || progenyof($target). Qualified
 *     live on the host named in the 1a census record.
 * (c) Perturbation: fires only at vCPU create/destroy; negligible.
 *
 * The reader fails closed on a capture with no event lines: that means the
 * probe did not fire, never "no vCPUs were created".
 */
#pragma D option quiet

BEGIN
{
    printf("HVFVCPU|header|version=1\n");
}

carrick*:::hvf-vcpu-lifecycle
/pid == $target || progenyof($target)/
{
    printf("HVFVCPU|event|site=%d|vcpu=%d|generation=%d\n", arg0, arg1, arg2);
}

dtrace:::ERROR
{
    printf("HVFVCPU|error\n");
}

dtrace:::END
{
    printf("HVFVCPU|end|version=1\n");
}
```

In `crates/carrick-runtime/src/dtrace_consumer.rs`, next to
`BUNDLED_HVPATCH_K1_LIFECYCLE_D`:

```rust
/// HVF vCPU create/destroy census (EL1 plan 1a gate D2).
pub const BUNDLED_HVF_VCPU_LIFECYCLE_CENSUS_D: &str =
    include_str!("../../../scripts/dtrace/hvf-vcpu-lifecycle-census.d");
```

Create `crates/carrick-cli/src/hvf_vcpu_lifecycle_profile.rs`:

```rust
//! Strict reader for the bundled HVF vCPU lifecycle census
//! (`scripts/dtrace/hvf-vcpu-lifecycle-census.d`). It fails closed on a lossy,
//! truncated, malformed or empty capture: zero events means the probe did not
//! fire, never "no vCPUs were created".

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use crate::trace_profile::ProfileCaptureStatus;

const PREFIX: &str = "HVFVCPU";
const VERSION: u64 = 1;

/// `trap::VcpuDestroySite` (1-8) and `trap::VcpuCreateSite` (101-102).
fn site_name(site: u32) -> Option<&'static str> {
    Some(match site {
        1 => "reclaim-park",
        2 => "initial-runner-park",
        3 => "shared-wait-park",
        4 => "thread-exit",
        5 => "execve-rebuild",
        6 => "creation-rollback",
        7 => "setup-rollback-local",
        8 => "creation-error",
        101 => "vm-creation",
        102 => "existing-vm",
        _ => return None,
    })
}

/// Validated counts from one complete census capture.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct HvfVcpuLifecycleSummary {
    /// Events by site code.
    pub(crate) events: BTreeMap<u32, u64>,
    /// Creates that followed a destroy in the same VM generation, keyed by the
    /// most recent destroy site of that generation (the mid-life recreates).
    pub(crate) recreate_after_destroy: BTreeMap<u32, u64>,
    pub(crate) generations: u64,
}

fn field(text: &str, name: &str) -> Result<u64> {
    let value = text
        .strip_prefix(name)
        .and_then(|rest| rest.strip_prefix('='))
        .ok_or_else(|| anyhow!("expected {name}=, got {text:?}"))?;
    value.parse().with_context(|| format!("{name} is not a u64: {value:?}"))
}

fn require_version(text: &str) -> Result<()> {
    let version = field(text, "version")?;
    if version != VERSION {
        bail!("census version {version}, reader expects {VERSION}");
    }
    Ok(())
}

impl HvfVcpuLifecycleSummary {
    pub(crate) fn from_path(path: &Path, status: ProfileCaptureStatus) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read HVF vCPU lifecycle census {}", path.display()))?;
        Self::from_lines(contents.lines(), status)
    }

    fn from_lines<I, S>(lines: I, status: ProfileCaptureStatus) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if status != ProfileCaptureStatus::default() {
            bail!("HVF vCPU lifecycle census is not lossless: {status:?}");
        }
        let mut summary = Self::default();
        let (mut header, mut end) = (false, false);
        let mut last_destroy = BTreeMap::<u64, u32>::new();
        let mut generations = BTreeSet::new();
        for line in lines {
            let line = line.as_ref();
            if line.is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('|').collect();
            match fields.as_slice() {
                [PREFIX, "header", version] if !header => {
                    require_version(version)?;
                    header = true;
                }
                [PREFIX, "event", site, vcpu, generation] if header && !end => {
                    let site = u32::try_from(field(site, "site")?)?;
                    field(vcpu, "vcpu")?;
                    let generation = field(generation, "generation")?;
                    site_name(site).ok_or_else(|| anyhow!("unknown site {site}: {line}"))?;
                    *summary.events.entry(site).or_default() += 1;
                    generations.insert(generation);
                    if site < 100 {
                        last_destroy.insert(generation, site);
                    } else if let Some(&destroy) = last_destroy.get(&generation) {
                        *summary.recreate_after_destroy.entry(destroy).or_default() += 1;
                    }
                }
                [PREFIX, "error"] => bail!("dtrace ERROR during the census"),
                [PREFIX, "end", version] if header && !end => {
                    require_version(version)?;
                    end = true;
                }
                _ => bail!("malformed or out-of-order census line: {line:?}"),
            }
        }
        if !header || !end {
            bail!("census stream is truncated (header={header}, end={end})");
        }
        if summary.events.is_empty() {
            bail!("hvf-vcpu-lifecycle never fired: the capture proves nothing");
        }
        summary.generations = generations.len() as u64;
        Ok(summary)
    }

    pub(crate) fn render_human(&self) -> String {
        let mut out = format!("hvf-vcpu-lifecycle-census generations={}\n", self.generations);
        for (site, count) in &self.events {
            out.push_str(&format!(
                "events site={} count={count}\n",
                site_name(*site).unwrap_or("?")
            ));
        }
        for (site, count) in &self.recreate_after_destroy {
            out.push_str(&format!(
                "midlife-recreates after={} count={count}\n",
                site_name(*site).unwrap_or("?")
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(events: &[(u32, u64, u64)]) -> String {
        let mut lines = vec!["HVFVCPU|header|version=1".to_owned()];
        for (site, vcpu, generation) in events {
            lines.push(format!("HVFVCPU|event|site={site}|vcpu={vcpu}|generation={generation}"));
        }
        lines.push("HVFVCPU|end|version=1".to_owned());
        lines.join("\n")
    }

    #[test]
    fn a_create_after_a_destroy_in_one_generation_is_midlife_and_teardown_is_not() {
        let text = stream(&[
            (101, 0, 1),
            (102, 1, 1),
            (2, 0, 1),   // initial-runner park
            (102, 0, 1), // recreate in the same VM: mid-life
            (4, 0, 1),   // teardown: no create follows in generation 1
            (4, 1, 1),
            (101, 0, 2),
            (4, 0, 2),
        ]);
        let summary =
            HvfVcpuLifecycleSummary::from_lines(text.lines(), ProfileCaptureStatus::default())
                .expect("valid census");
        assert_eq!(summary.recreate_after_destroy, BTreeMap::from([(2, 1)]));
        assert_eq!(summary.generations, 2);
        assert_eq!(summary.events[&4], 3);
    }

    #[test]
    fn an_empty_lossy_truncated_or_unknown_capture_is_refused() {
        let ok = ProfileCaptureStatus::default();
        assert!(HvfVcpuLifecycleSummary::from_lines(stream(&[]).lines(), ok).is_err());
        let lossy = ProfileCaptureStatus { principal_drops: 1, ..ok };
        assert!(HvfVcpuLifecycleSummary::from_lines(stream(&[(101, 0, 1)]).lines(), lossy).is_err());
        let truncated = stream(&[(101, 0, 1)]).replace("HVFVCPU|end|version=1", "");
        assert!(HvfVcpuLifecycleSummary::from_lines(truncated.lines(), ok).is_err());
        assert!(HvfVcpuLifecycleSummary::from_lines(stream(&[(9, 0, 1)]).lines(), ok).is_err());
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn profile_selection_embeds_the_census_program() {
        let profile = crate::trace_profile::TraceProfileKind::HvfVcpuLifecycleCensus;
        assert_eq!(profile.as_str(), "hvf-vcpu-lifecycle-census");
        let source = profile.bundled_script();
        assert_eq!(source, carrick_runtime::dtrace_consumer::BUNDLED_HVF_VCPU_LIFECYCLE_CENSUS_D);
        for required in [
            "HVFVCPU|header|version=1",
            "carrick*:::hvf-vcpu-lifecycle",
            "progenyof($target)",
            "dtrace:::ERROR",
            "HVFVCPU|end|version=1",
        ] {
            assert!(source.contains(required), "missing census source {required}");
        }
    }
}
```

Register the profile the way `hvpatch-k1-lifecycle` is registered:
- `crates/carrick-cli/src/main.rs`: `mod hvf_vcpu_lifecycle_profile;` next to
  `mod hvpatch_k1_profile;`.
- `crates/carrick-cli/src/trace_profile.rs`: variant `HvfVcpuLifecycleCensus`
  in `TraceProfileKind`; `as_str` → `"hvf-vcpu-lifecycle-census"`;
  `capture_bound_placeholder` → `None` (add it to the `None` arm);
  `bundled_script` → `carrick_runtime::dtrace_consumer::BUNDLED_HVF_VCPU_LIFECYCLE_CENSUS_D`;
  `parse_protocol` → `"hvf-vcpu-lifecycle-census" => Ok(Self::HvfVcpuLifecycleCensus)`;
  and the `(kind, name)` table in its test module gains
  `(TraceProfileKind::HvfVcpuLifecycleCensus, "hvf-vcpu-lifecycle-census")`.
- `crates/carrick-cli/src/commands.rs`: beside the `hvpatch-inotify09-population`
  check, `hvf-vcpu-lifecycle-census` requires `--trace-out` and refuses
  `--summary-jsonl` (same two `bail!`s, with this profile's name); in the
  freebsd block beside `hvpatch-k1-lifecycle`, it bails "requires a Darwin/HVF
  host"; in the post-capture chain beside the K1 branch:

```rust
                        } else if requested_profile
                            == crate::trace_profile::TraceProfileKind::HvfVcpuLifecycleCensus
                        {
                            let summary =
                                crate::hvf_vcpu_lifecycle_profile::HvfVcpuLifecycleSummary::from_path(
                                    raw_path,
                                    capture_status,
                                )?;
                            eprintln!("{}", summary.render_human());
```

- `crates/carrick-cli/src/args.rs`: a test `hvf_vcpu_lifecycle_census_profile_is_cli_selectable`
  copying `hvpatch_k1_lifecycle_profile_is_cli_selectable` with this profile's name.

```bash
cargo test -p carrick-cli --bin carrick hvf_vcpu_lifecycle
cargo test -p carrick-cli --bin carrick trace_profile
```

Expected: PASS (the reader tests, the embedded-program test, the kind table and
the CLI selection test).

- [ ] **Step 8: Build signed and run the census on four workloads**

No other guest may be running. Carrick first, never alongside Docker. Each
capture exits non-zero if the reader refuses it (lossy, truncated, or the
probe never fired), and `set -e` stops the sequence there.

```bash
just build
mkdir -p target/el1-1a-census
bin=target/release/carrick
set -e
run_census() { name=$1; shift
  CARRICK_RUN_ID=census-$name "$bin" trace --profile hvf-vcpu-lifecycle-census \
    --trace-out target/el1-1a-census/$name.raw -- run --rm "$@" < /dev/null \
    2> >(tee target/el1-1a-census/$name.summary >&2)
}
run_census smoke docker.io/library/ubuntu:24.04 /bin/sh -c 'echo hi'
run_census gobuild --fs host localhost:5005/carrick-go-conformance:1.24 /bin/sh -c \
  'cd /tmp && printf "package main\nfunc main(){println(\"ok\")}\n" > h.go && GOCACHE=/tmp/gc /usr/local/go/bin/go build -o /tmp/h ./h.go && /tmp/h && echo BUILD_OK'
run_census cpy-threading localhost:5050/cpython-test:3.12.13 /usr/local/bin/python3 -m test -v --randseed 0 test_threading
run_census cpy-subprocess localhost:5050/cpython-test:3.12.13 /usr/local/bin/python3 -m test -v --randseed 0 test_subprocess
set +e
for id in census-smoke census-gobuild census-cpy-threading census-cpy-subprocess; do scripts/sudo/kill.sh "$id"; done
grep -a 'events site=\|midlife-recreates' target/el1-1a-census/*.summary
```

Expected: each summary has `events` lines. Record, per workload, the event
counts by site and the `midlife-recreates` counts (expected non-zero at least
for `initial-runner-park`, which every carrier boot performs).

- [ ] **Step 9: Decide gate D2 and record it**

Append a "Census" section to `docs/perf-results/2026-09-25-hvf-gic-qualification.md`
with the four summaries and this decision (exactly one row applies):

| E3 | Census mid-life recreates | Decision |
|---|---|---|
| pass | any | Keep today's lifecycle under the GIC. The E3 test becomes an `el1-gate` step (Task 12) so an OS update that breaks it is caught. |
| fail | 0 in all four workloads | Proceed; Task 5 adds a fail-closed guard: a vCPU created in a GIC generation that already released an affinity index is a `carrick_fatal!` naming the last destroy site. Teardown destroys are unaffected (no create follows them). |
| fail | > 0 | STOP 1a here. Write a lifecycle plan: vCPUs held for the VM's life (the initial runner keeps its vCPU or becomes an executor, persistent workers never retire mid-carrier) and re-run this gate. |

- [ ] **Step 10: Commit**

```bash
just fmt-check && cargo clippy -p carrick-vmm-hvf -p carrick-observability -p carrick-runtime -p carrick-cli --all-targets -- -D warnings
git add crates/carrick-observability/src/probes.rs crates/carrick-vmm-hvf/src/trap.rs \
  crates/carrick-vmm-hvf/src/trap/vcpu_admission.rs crates/carrick-vmm-hvf/src/trap/persistent_executor.rs \
  crates/carrick-vmm-hvf/src/trap/execve_rebuild.rs crates/carrick-vmm-hvf/src/trap/carrier_custody.rs \
  crates/carrick-vmm-hvf/src/trap/cow_engine.rs scripts/dtrace/hvf-vcpu-lifecycle-census.d \
  crates/carrick-runtime/src/dtrace_consumer.rs crates/carrick-cli/src/hvf_vcpu_lifecycle_profile.rs \
  crates/carrick-cli/src/main.rs crates/carrick-cli/src/trace_profile.rs crates/carrick-cli/src/commands.rs \
  crates/carrick-cli/src/args.rs scripts/migrate/runtime-global-state.json \
  docs/perf-results/2026-09-25-hvf-gic-qualification.md
git commit -F- <<'MSG'
diagnostics(hvf): census where vCPUs are created and destroyed

Why: HVF's GIC documentation says to destroy vCPUs only at VM teardown,
and Carrick recreates them in a live VM (initial-runner hand-off on
every boot, M:N reclaim, worker retirement). Adopting the GIC needs to
know which of those paths fire and how often before deciding the
lifecycle. Two paths also destroyed vCPUs through applevisor's Drop
without any report (add_vcpu's mailbox failure, from_process_spec's
error returns), and the local-RAII setup rollback reported through a
bare fn pointer.

What:
- `destroy_raw_vcpu` is the only raw hv_vcpu_destroy; every destroy
  names a `VcpuDestroySite`, every create a `VcpuCreateSite`; the
  unreported Drop paths now destroy and report explicitly.
- USDT `hvf-vcpu-lifecycle` (site, vCPU, VM generation) and
  `carrick trace --profile hvf-vcpu-lifecycle-census`, whose strict
  reader classifies a create after a destroy in the same generation as
  mid-life and refuses a lossy, truncated or empty capture.

Verified: `every_vcpu_destroy_names_its_site` red (six raw destroys)
then green; census reader tests; census on smoke, go build, cpython
test_threading and test_subprocess recorded in
docs/perf-results/2026-09-25-hvf-gic-qualification.md with gate D2.

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
just test-hvf gic_qualification_e1 --nocapture 2>&1 | grep -a '^E1'
```

Expected: both unit tests PASS; `lint-domains.sh` exits 0; E1 unchanged (the
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
`kick_irq_asserts_the_sdk_irq_line` pass; E1 unchanged.

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
just test-hvf gic_qualification_e0 --nocapture 2>&1 | grep -a '^E0'
```

Expected: PASS for all; E0 unchanged.

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
`gic_window_is_below_the_trampoline_and_above_the_vdso`; qualification
E0 passes at this placement.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
MSG
```

---

### Task 5: Create the GIC in the VM funnel and configure every vCPU (D5, D7, D9)

Valid only if gates D1, D2, D3, D5b and D12 passed.

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
- Modify: `crates/carrick-vmm-hvf/src/trap.rs` (`create_vm_with_admission`, `destroy_raw_vcpu`)
- Modify: `crates/carrick-vmm-hvf/src/trap/vcpu_admission.rs` (both wrappers, `record_vm_released`,
  `GLOBAL_VCPU_CEILING` per D5b, tests)
- Modify: `crates/carrick-vmm-hvf/src/trap/carrier_custody.rs` (`SetupVcpuGuard` drop under the GIC lock)
- Modify: `crates/carrick-vmm-hvf/src/trap/vcpu_gate.rs` (capacity clamp)
- Modify: `crates/carrick-vmm-hvf/src/trap/cow_engine.rs` (EL0 ID view, D12)
- Modify: `crates/carrick-el1-abi/src/lib.rs` (shared INTID constants)
- Create: `conformance-probes/src/bin/idaa64pfr0.rs` and its registrations (D12)
- Create: `conformance-contracts/contracts/gic-topology.toml`
- Modify: `conformance-contracts/surfaces.toml`, `scripts/migrate/runtime-global-state.json`,
  `scripts/migrate/runtime-aborts/hvf.json` (only if gate D2's middle row applied)

**Interfaces:**
- Consumes: `carrick_mem::memory::{LINUX_GIC_DISTRIBUTOR_BASE, LINUX_GIC_DISTRIBUTOR_MAX,
  LINUX_GIC_REDISTRIBUTOR_BASE, LINUX_GIC_REDISTRIBUTOR_MAX}`,
  `crate::trap::{VcpuDestroySite, destroy_raw_vcpu}`.
- Produces in `carrick_el1_abi`: `pub const GIC_KICK_INTID: u32 = 15;`,
  `pub const GIC_VTIMER_INTID: u32 = 27;`, `pub const GIC_SPURIOUS_INTID: u32 = 1023;`
  (single source for host and EL1; `GIC_KICK_INTID` is 20 if gate D1 chose the PPI).
- Produces in `crate::gic`: `pub(crate) struct PrivateIntid`, `pub(crate) const KICK_INTID`,
  `pub(crate) const VTIMER_INTID`, `pub(crate) struct Mpidr`, `pub(crate) struct MpidrAllocator`,
  `pub(crate) struct GicGeometry`, `pub(crate) enum InterruptModel { Gic, LegacyPendingLine }`,
  `pub(crate) fn interrupt_model() -> InterruptModel` (the one reader of `CARRICK_HVF_GIC`),
  `pub(crate) enum GicCreateFailure { NoResources, Fatal(TrapError) }`,
  `pub(crate) fn create_carrier_gic(generation: u64) -> Result<(), GicCreateFailure>`,
  `pub(crate) fn carrier_vm_released()`,
  `pub(crate) fn configure_new_vcpu(vcpu: u64) -> Result<(), TrapError>`,
  `pub(crate) fn destroy_releasing_affinity(vcpu: u64, site: VcpuDestroySite, destroy: impl FnOnce() -> applevisor_sys::hv_return_t) -> applevisor_sys::hv_return_t`,
  `pub(crate) fn redistributor_capacity() -> Option<usize>`,
  `pub fn gic_topology_snapshot() -> GicTopologySnapshot` (pub, re-exported for embed tests).

- [ ] **Step 1: Add the shared INTID constants to the EL1 ABI**

In `crates/carrick-el1-abi/src/lib.rs`, near `IMAGE_VERSION`:

```rust
/// GIC INTID of the host kick: an SGI the host makes pending in the vCPU's
/// redistributor (GICR_ISPENDR0) and EL1 surfaces as a kick exit (EL1 plan
/// 1a, gate D1).
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
        // HVF reuses vCPU ids: 5 is destroyed (released under the lock) and a
        // new vCPU with the same id gets the lowest free index again.
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
`GicGeometry`, `hvf_cap_from`). That compile failure is the red for the types;
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
//! Facts it is built on (docs/perf-results/2026-09-25-hvf-gic-qualification.md):
//! the GIC is created after `hv_vm_create` and before any `hv_vcpu_create`;
//! each vCPU needs a unique MPIDR before its redistributor is touched;
//! redistributor and ICC registers are written on the owning thread;
//! `hv_vcpu_set_pending_interrupt` returns HV_UNSUPPORTED once a GIC exists,
//! and redistributor pending state survives `hv_vcpu_run` returns.

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
/// GICD_CTLR: affinity routing (ARE) + group 1 enable, as qualified in E0.
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
/// and retries like `hv_vm_create`'s (qualification E5b).
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
            // A reused index may name a redistributor a destroyed vCPU left
            // with a pending kick or an active interrupt (qualification E3
            // `carried_over`); an inherited active interrupt would block the
            // kick at its priority. Withdraw every private interrupt first.
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

/// Destroy a vCPU and free its affinity index in one critical section: the
/// topology lock is held across `destroy` (the caller's `hv_vcpu_destroy`,
/// raw or applevisor's Drop) and the release, so no other thread can create
/// a vCPU with the reused HVF id and allocate before the old index is free,
/// and no late release can free a new vCPU's index. Releases in a VM
/// generation that no longer has a GIC are no-ops. The topology lock is a
/// leaf: nothing else is locked inside it.
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

If gate D2's middle row applied (E3 failed, no mid-life recreates in the
census), add `use carrick_fatal::carrick_fatal;` to `gic.rs` and, in
`configure_new_vcpu`, directly before `let index = gic.mpidrs.allocate(vcpu)?;`:

```rust
        // Gate D2 (middle row): E3 failed, so a vCPU may not be created in a
        // VM generation that already destroyed one. Teardown destroys never
        // reach this (no create follows them in their generation).
        if let Some(site) = gic.last_release_site {
            carrick_fatal!(
                "gic::configure_new_vcpu",
                "vCPU created in VM generation {} after a destroy at {site:?} under the in-kernel GIC (qualification E3 failed)",
                gic.generation
            );
        }
```

then run `python3 scripts/migrate/check-runtime-aborts.py --check`, which names
the new `carrick_fatal!` site and its fingerprint, and add that row to
`scripts/migrate/runtime-aborts/hvf.json` with `"verdict": "carrier_fault"`,
`"failure_domain": "gic::configure_new_vcpu"`, `"sink": "fatal"`,
`"domain": "gic::configure_new_vcpu"` and the rationale "A vCPU was created in
a VM generation that already destroyed one while the in-kernel GIC is active;
qualification E3 showed Hypervisor.framework does not support that topology
change." Re-run `--check`: exit 0. Otherwise `last_release_site` is still read
by `gic_topology_snapshot` (below) and no fatal is added.

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
        // HV_NO_RESOURCES parks and retries like hv_vm_create's (E5b).
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
            CARRIER_VM_GENERATION.store(generation.0, std::sync::atomic::Ordering::Release);
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
to the E5b GIC ceiling minus 7 and add both measured ceilings to its doc
comment ("127 VMs without a GIC, N with one; qualification E5b").

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
            vcpu_created(vcpu.id(), VcpuCreateSite::VmCreation);
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
    // Existing-VM vCPUs (thread siblings and reclaim/rebind) are admitted by the
    // in-process scheduler. Applying the VM-creation permit here would duplicate
    // that scheduler's bounded vCPU accounting.
    match vm.vcpu_create() {
        Ok(vcpu) => {
            if let Err(error) = crate::gic::configure_new_vcpu(vcpu.id()) {
                discard_unconfigured_vcpu(vcpu);
                return Err(error);
            }
            vcpu_created(vcpu.id(), VcpuCreateSite::ExistingVm);
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

and `impl Drop for SetupVcpuGuard` (carrier_custody.rs) runs applevisor's Drop
inside the same critical section:

```rust
        complete_local_vcpu_raii_cleanup(
            id,
            || {
                crate::gic::destroy_releasing_affinity(id, VcpuDestroySite::SetupRollbackLocal, || {
                    // SAFETY: the local-reuse lane has no Pending transaction. Its
                    // ordinary applevisor RAII destruction remains the sole HV owner;
                    // applevisor's Drop panics rather than return on failure.
                    unsafe { std::mem::ManuallyDrop::drop(&mut self.vcpu) };
                    0
                });
            },
            |id| vcpu_destroyed(id, VcpuDestroySite::SetupRollbackLocal),
        );
```

Every destroy therefore frees its affinity index before any other thread can
allocate for a reused HVF id; `vcpu_destroyed` (census, admission permit, gate
wake) runs after the lock is dropped.

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
title = "Every carrier vCPU has a unique GIC affinity and a configured redistributor before it runs"
guest_surfaces = ["vmm:hvf", "scheduler:vcpu-kick", "execution:linux-aarch64"]
semantic_authority = [
  "Hypervisor.framework hv_gic.h: hv_gic_create after hv_vm_create and before any hv_vcpu_create; vCPUs set affinity values in MPIDR_EL1; redistributor registers are written by the owning thread",
  "Arm GICv3 architecture specification: affinity routing identifies a PE by MPIDR_EL1 Aff3.Aff2.Aff1.Aff0; ICC_SGI1R_EL1 TargetList addresses Aff0 0-15",
]
fixture = "unit:gic-topology"
scale_points = [1, 8, 32, 128]
rationale = "The carrier VM carries Hypervisor.framework's in-kernel GICv3. It is created inside the single VM-creation funnel, so every VM generation (boot, execve rebuild, shared-wait resume, fork rebuild) has it before its first vCPU; both vCPU-creation wrappers give each vCPU the lowest free affinity index of that generation and configure its redistributor (every private interrupt a previous owner left withdrawn, then kick SGI and vtimer PPI enabled, group 1, priorities) and CPU interface on the owning thread before the vCPU is counted or handed out; every destroy releases its index under the topology lock in the same critical section as hv_vcpu_destroy, so a reused HVF vCPU id never meets a stale owner. The vCPU budget is clamped to the redistributor count. Two live guest processes with threads are the embed evidence: the single-process lane cannot see a duplicate affinity."
structural_budgets = []

[bindings]
vm_free = "carrick-vmm-hvf::gic::tests::mpidr_carries_res1_and_sgi_addressable_affinity; carrick-vmm-hvf::gic::tests::mpidr_allocator_hands_out_the_lowest_free_index; carrick-vmm-hvf::gic::tests::mpidr_allocator_refuses_a_second_index_for_one_vcpu_and_a_full_topology; carrick-vmm-hvf::gic::tests::geometry_must_fit_the_reserved_window; carrick-vmm-hvf::gic::tests::a_destroy_releases_its_index_and_the_next_generation_starts_empty; carrick-vmm-hvf::gic::tests::capacity_clamps_the_vcpu_budget; carrick-vmm-hvf::gic::tests::raw_hv_gic_calls_stay_in_gic_rs; carrick-vmm-hvf::gic::tests::gic_is_created_inside_the_vm_creation_funnel; carrick-vmm-hvf::gic::tests::every_vcpu_is_configured_by_its_creation_wrapper; carrick-vmm-hvf::trap::vcpu_admission::vcpu_lifecycle_site_tests::every_vcpu_destroy_names_its_site"
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
path = "crates/carrick-vmm-hvf/tests/gic_qualification_wfi.rs"
contracts = ["kernel.vcpu.kick-el0-boundary"]

[[surfaces]]
path = "crates/carrick-vmm-hvf/tests/gic_qual/harness.rs"
contracts = ["kernel.vcpu.gic-topology", "kernel.vcpu.kick-el0-boundary"]

[[surfaces]]
path = "crates/carrick-vmm-hvf/src/trap/vcpu_gate.rs"
contracts = ["kernel.vcpu.gic-topology"]

[[surfaces]]
path = "crates/carrick-vmm-hvf/src/trap/carrier_custody.rs"
contracts = ["kernel.vcpu.gic-topology"]
```

If `surfaces.toml` already lists `carrier_custody.rs`, append the contract id to
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
EL0; Carrick's EL0 MRS emulation returns the raw vCPU value (Fact 10). Run this
step whether or not E0 reported a difference, so the view is pinned against the
oracle either way.

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

Expected red when E0's `E0-id` named `ID_AA64PFR0_EL1`: a DIFF on
`id_aa64pfr0_gic_field` (oracle 0, Carrick non-zero). Record it. If E0 named
no difference, the probe passes here: record that it is a regression guard,
not a red-first proof, and skip the sanitisation below.

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
        // Under the GIC the kick SGI survives run returns (qualification
        // E1(b)); a kick re-armed for an EL1 critical section that ended in
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
  crates/carrick-vmm-hvf/src/trap/carrier_custody.rs crates/carrick-vmm-hvf/src/trap/cow_engine.rs \
  crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs crates/carrick-aarch64/src/owed_kick.rs \
  crates/carrick-el1-abi/src/lib.rs conformance-probes/src/bin/idaa64pfr0.rs conformance-probes/probe-inventory.json \
  crates/carrick-conformance-next \
  conformance-contracts/contracts/gic-topology.toml conformance-contracts/contracts/kick-el0-boundary.toml \
  conformance-contracts/surfaces.toml scripts/migrate/runtime-global-state.json
git status --short   # add scripts/migrate/runtime-aborts/hvf.json too if gate D2's middle row applied
git commit -F- <<'MSG'
feat(hvf): create the in-kernel GIC with every carrier VM

Why: the EL1 kernel's scheduler needs Hypervisor.framework's in-kernel
GICv3 so the virtual timer, SGIs and WFI stay inside the hypervisor.
hv_gic_create must follow hv_vm_create and precede every vCPU, and each
vCPU needs a unique MPIDR before its redistributor is touched. Once a
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
  the VM generation (MPIDR RES1 | Aff1 | Aff0), withdraw every private
  interrupt a previous owner left, and configure its redistributor
  (kick SGI 15, vtimer PPI 27, group 1, priorities) and CPU interface
  before it is counted. Every destroy frees its index under the
  topology lock in the same critical section as hv_vcpu_destroy.
- `gic::arm_kick`/`clear_kick` make SGI 15 pending in the vCPU's
  redistributor (GICR_ISPENDR0/ICPENDR0) and are the only kick vehicle;
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
without the hatch; el1_ embed tests. Qualification:
docs/perf-results/2026-09-25-hvf-gic-qualification.md.

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
        // enabled (ICC_SRE_EL1.SRE, qualified in E0).
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
        // Hypervisor.framework's in-kernel GIC, the state where an
        // hv_vcpus_exit wedge is unexplained (qualification E2). Parking
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
/// threads run under the GIC; every vCPU the carrier created holds a distinct
/// affinity, and allocations balance releases plus live vCPUs.
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
    let topology = gic_topology_snapshot();
    println!("el1-gic-topology {topology:?}");
    assert!(topology.gic, "the production VM has the in-kernel GIC");
    assert!(topology.live >= 2, "more than one vCPU live: {topology:?}");
    assert_eq!(topology.allocations, topology.releases + topology.live as u64, "{topology:?}");
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
`carrick-vmm-hvf/src/gic.rs`. Host kicks are SGI 15 made pending in the vCPU's
redistributor; EL1 takes GIC interrupts in the served-syscall return window.
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
  With a GIC, `hv_vcpu_set_pending_interrupt` returns `HV_UNSUPPORTED`; host
  kicks are a redistributor-pending SGI. Qualification:
  `docs/perf-results/2026-09-25-hvf-gic-qualification.md`."
- replace open items 1 and 2 with the recorded outcomes: item 1 "SPI: <class
  i/ii/iii from E4>; `hv_vcpus_exit` wake wedge: <H-a/H-b/H-c or not explained
  from E2>"; item 2 "Mid-life vCPU destroy under the GIC: <E3 verdict and D2
  row>; wedged-vCPU recovery: <E2 production-reachable states clean /
  WFI-state result>, carried to plan 1c as its entry criterion." Fill each
  `<...>` from the results doc; write "not explained" where the data did not
  discriminate.

- [ ] **Step 4: One AGENTS.md rule**

Under "Where key subsystems live", add:

```markdown
- **HVF in-kernel GIC** — `crates/carrick-vmm-hvf/src/gic.rs` is the only raw
  `hv_gic_*` caller. The GIC is created inside `create_vm_with_admission`
  (never elsewhere) and every vCPU gets its MPIDR and redistributor setup in
  the two creation wrappers. With a GIC, `hv_vcpu_set_pending_interrupt`
  returns `HV_UNSUPPORTED` (hv_vcpu.h): kicks are SGI 15 via GICR_ISPENDR0.
  Name legacy interrupt lines only through `interrupt::HvfInterruptLine`
  (applevisor-sys numbers them in reverse of the SDK). EL1 unmasks IRQs only in
  the served-syscall return window and never executes `wfi`/`wfe` (the image
  build refuses them) until the EL1 scheduler lands with its wedge-recovery
  contract. Qualification suite: `just test-hvf gic_qualification_e<N>`, one
  experiment per process (a wedge leaks the process's only VM).
```

- [ ] **Step 5: Commit**

```bash
git add docs/hal.md docs/superpowers/specs/2026-09-24-el1-kernel.md AGENTS.md
git commit -F- <<'MSG'
docs(el1): record the GIC adoption and its qualified HVF facts

Why: plan 1a resolves (or explicitly carries forward) the spec's open
items on SPI delivery, the hv_vcpus_exit wedge and mid-life vCPU
destroys under the GIC, and adds rules a future change must not break.

What: spec open items 1 and 2 carry the qualification outcomes;
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

- [ ] **Step 1: Add the qualification suite and the hatch screen to `el1-gate`**

In the `el1-gate` recipe, after `step el1-embed ./scripts/test-signed.sh carrick-embed el1_`,
one process per production-reachable experiment (HVF allows one VM per
process, so a wedge in one experiment must not turn the others red), and never
the WFI executable (its states are data, not a gate):

```bash
    for e in e0 e1 e2 e3 e4 e5 e6; do
      step hvf-gic-$e ./scripts/test-signed.sh carrick-vmm-hvf gic_qualification_$e --nocapture
    done
```

(E5b is a 127-VM probe run, not a test; it is re-run by hand when macOS
changes, per Task 1 Step 9.)

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
test(el1): run the GIC qualification in the EL1 landing gate

Why: 1a depends on Hypervisor.framework behaviour (kick vehicle,
mid-life vCPU recreate, hv_vcpus_exit liveness) that a macOS update can
change; a gate that does not run the qualification cannot notice.

What: el1-gate builds the fixtures, runs each signed
gic_qualification_e<N> experiment in its own process on the gated
artifact, and screens inotify09 in three arms (EL1+GIC, no EL1, EL1
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
for e in e0 e1 e2 e3 e4 e5 e6; do
  ./scripts/test-signed.sh carrick-vmm-hvf gic_qualification_$e --nocapture 2>&1 | tail -5
done
same qualification
just --no-deps el1-gate 2>&1 | tail -30
same el1-gate
just --no-deps conformance smoke 2>&1 | tail -20
same smoke
CARRICK_HVF_GIC=0 CARRICK_RUN_ID=hatch-smoke $bin run --rm docker.io/library/ubuntu:24.04 /bin/sh -c 'echo hatch-ok' < /dev/null
scripts/sudo/kill.sh hatch-smoke
same hatch
```

Expected: every qualification experiment green; `el1-gate: green on <sha>`
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

Interleave the base artifact (Task 0) and the new one, two rounds each, on a
quiet host, never alongside Docker:

```bash
suites="--suite go-build --suite go-testing --suite go-time --suite go-os_signal --suite go-net_http \
  --suite cpython-threading --suite cpython-subprocess --suite cpython-asyncio --suite node-app-smoke"
mkdir -p target/el1-1a-paired
for round in 1 2; do
  for arm in base new; do
    b=target/el1-1a-base/carrick; [ $arm = new ] && b=target/release/carrick
    cargo run -q -p carrick-conformance -- --tier full $suites --require-cached-oracle \
      --carrick-bin "$b" --jsonl target/el1-1a-paired/$arm-$round.jsonl
  done
done
```

Expected: every suite has the same verdict in all four runs. Record, per suite,
the wall time of `new` over `base` in each round. A suite whose ratio exceeds
1.10 in both rounds is a finding: attribute it with E6's exit-round-trip numbers
and the census before accepting (write "suggests", not "confirmed"; this is a
paired measurement, not a controlled experiment). No suite may change verdict.

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
   stays for the qualification suite's legacy control).

**Entry criteria:** E2's WFI states explained (H-a/H-c) and wedged-vCPU recovery
under the GIC established (spec open item 2): either a proven recovery sequence
or a proof that the wedge needs a state Carrick never enters; 1b landed; the
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
| Does SGI 15 pend through GICR_ISPENDR0 from the host, or only PPI 20, including production's un-acknowledged `hvc #4` path? | Task 1 E1 (gate D1) |
| Is a mid-life vCPU recreate safe under the GIC (HVF advises against it), and what does a recreated redistributor inherit? | Task 1 E3 + Task 2 census (gate D2) |
| What wedged a vCPU under the GIC in the spikes (H-a, H-b, H-c)? | Task 1 E2 and the WFI executable (gate D3; WFI states carried to 1c) |
| Why did `hv_gic_set_spi` never reach the CPU interface? | Task 1 E4 (class i/ii/iii; not needed by 1a) |
| Per-VM vCPU capacity and redistributor placement under the GIC | Task 1 E5 (gates D5, D7) |
| Does a GIC per VM lower the concurrent VM ceiling (127 without)? | Task 1 E5b (gate D5b) |
| Does a GIC change an ID register EL0 can read? | Task 1 E0 (gate D12), Task 5 Step 8 |
| Cost of an exit with the GIC present | Task 1 E6, Task 13 paired runs |
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
- Load-dependent verdicts (safety, major): applied; E2's 1 s suspect and 5 s wedge bounds are kept, because they are hang detectors that AGENTS.md requires of every wait, not verdict rates.
- Detector for a kicked vCPU that never surfaces (safety, major, E2 scale): not added as a new probe; `scripts/dtrace/hvpatch-pt-pause-drain-stall.d` (commit 854eeff8b) already names each sibling still in the guest for a drain of 100 ms or more, and D11's mixed row calls for it.
- `hvf_gic_enabled` in carrick-mem (safety, major): moved to the one reader in `gic.rs`, with the vector mode passed as an argument; the extra fail-closed assertion at VM creation was not added, because both sides now derive from the same `OnceLock` and cannot differ within a process.
- Vehicle before GIC (safety, blocker): landed as one Task 5+6 commit with a signed red, the facts finding's alternative; a vehicle-only commit would need an `InterruptModel::Gic` variant that nothing can construct, which `-D warnings` rejects as dead code.
- Stage-1 window guard (safety, minor): placed in `PageTableManager`'s three output-writing paths (`map_aliased_with_flags`, `repoint_preserving_attributes`, `apply`'s identity rebuild) rather than in `Stage1Authority`, which owns the manager but writes no descriptor.
- Per-exit counter cost (safety, minor): resolved by counting only on the probed slot and only for non-kick exits, so no cache-line padding is needed.
- `live_hvf_vcpus` duplicate census (facts, minor): the second counter was removed rather than justified; the census keys mid-life on VM generation, not on a live count.
