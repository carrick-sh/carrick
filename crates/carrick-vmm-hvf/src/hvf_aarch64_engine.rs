//! The HVF aarch64 backend on the shared `carrick-aarch64` scaffold (F7 step 4/5).
//!
//! `HvfAarch64Vmm` (+ `impl Aarch64Vcpu for HvfAarch64Vcpu`) is the thin per-VMM
//! trait pair the generic [`carrick_aarch64::Aarch64EngineCore`] is parameterized
//! over — the macOS/Apple-Silicon twin of `KvmAarch64Vmm`. The trap loop, register
//! walk, guest-memory PROT_NONE gate, stage-1 page-table edits, snapshot/restore
//! plumbing, fork/execve/sibling SEQUENCING and the threaded lifecycle all now live
//! ONCE in `carrick-aarch64`; this module supplies only the HVF-specific atoms:
//!
//!   - the `applevisor` register/sysreg/V-reg marshalling (incl. the
//!     `set_simd_fp_reg_v` u128-by-value C-shim — the ABI-bug workaround),
//!   - the native-exit decode `run() -> Aarch64Exit` (EXCEPTION + ESR.EC →
//!     svc/HVC-syscall / EL0-abort / sys64-MRS / maintenance-HVC, CANCELED → kick,
//!     with the EL1-trampoline kick swallow + the lazy high-VA alias re-map),
//!   - the per-VMM VM/memory model: host-`MAP_SHARED` windows + `hv_vm_map` stage-2,
//!     the `EagerCopy` fork strategy (the parent freezes / both sides rebuild a
//!     fresh `applevisor` VM), `execve` VM rebuild, the M:N reclaim (destroy/recreate
//!     the vCPU around a block), the multithreaded-fork sibling quiesce dance, and
//!     the process-shared high-VA alias registry + cross-thread syscall fallback.
//!
//! The bulk of those atoms still LIVE in [`crate::trap`] (the alias registry, the
//! region types, the EL1-vector boot image, the `applevisor` helpers, the sysreg
//! decode); this module re-exposes them through the trait pair. The richer-than-KVM
//! memory surface (the permission-checked write, the unchecked write, the zero-copy
//! host-pointer path, the cross-thread alias fallback) is threaded through the
//! `Aarch64Vmm` memory hooks the F7-step-4 trait additions opened for it.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::sync::Arc;

use carrick_aarch64::{
    Aarch64EngineCore, Aarch64Exit, Aarch64Vcpu, Aarch64VcpuSnapshot, Aarch64Vmm, ForkRamStrategy,
};
use carrick_guest_mem::protections::MemoryProtections;
use carrick_guest_mem::{GuestVa, HostVa, MemoryError};
use carrick_hal::{GuestEntryRegs, GuestVmBackend, Reg, SlotId, SysReg, TrapError, VcpuRegistry};
use carrick_mem::memory::AddressSpace;

use crate::trap::{
    GuestMappingPlan, HvfInner, HvfVmState, ThreadSpec, VcpuSnapshot, hvf_get_reg, hvf_get_sys_reg,
    hvf_set_reg, hvf_set_sys_reg, set_simd_fp_reg_v,
};

/// The public engine type: the HVF aarch64 lane IS `Aarch64EngineCore<HvfAarch64Vmm>`.
/// `crate::trap::HvfTrapEngine` is a thin alias to this so every existing call site
/// (runtime.rs `run_threaded_hvf_loop`, the vcpu loop) is unchanged.
pub type HvfAarch64Engine = Aarch64EngineCore<HvfAarch64Vmm>;

/// Build the engine from a freestanding/loaded image: create the VM + vCPU, map the
/// guest address space, and park the vCPU at the EL0-entry trampoline (the first
/// `next_syscall` runs into EL0). Mirrors `KvmAarch64Vmm::bring_up`.
pub fn bring_up(image: &AddressSpace) -> Result<HvfAarch64Engine, TrapError> {
    let plan = GuestMappingPlan::from_address_space(image)?;
    let (state, vcpu) = HvfVmState::new_with_plan(&plan)?;
    let vmm = HvfAarch64Vmm { state };
    Ok(Aarch64EngineCore::from_parts(
        vmm,
        HvfAarch64Vcpu::new(vcpu),
    ))
}

// ─── neutral ⟷ HVF VcpuSnapshot ──────────────────────────────────────────────
//
// HVF's `VcpuSnapshot` is now `{ core: Aarch64VcpuSnapshot, last_exit_class }`, so
// the neutral view IS the `core` and these conversions are trivial. The
// per-register HVF↔neutral mapping (CPSR ↔ pstate, the `*_EL1` sysreg names, HVF
// seeding SP_EL1 from `core.sp_el0`) lives in `snapshot_vcpu_from`/`restore_vcpu*`,
// not here. `last_exit_class` is engine-owned and not part of the neutral
// snapshot, so `to_neutral` drops it and `from_neutral` re-attaches a
// caller-supplied value (0 except on the engine-owned reclaim path).

pub(crate) fn to_neutral(s: &VcpuSnapshot) -> Aarch64VcpuSnapshot {
    s.core.clone()
}

pub(crate) fn from_neutral(s: &Aarch64VcpuSnapshot, last_exit_class: u64) -> VcpuSnapshot {
    VcpuSnapshot {
        core: s.clone(),
        last_exit_class,
    }
}

// ─── impl Aarch64Vcpu for HvfAarch64Vcpu ─────────────────────────────────────

/// The per-vCPU half: a newtype over `applevisor::vcpu::Vcpu`. All register access
/// routes through the HVF↔HAL translation helpers in `crate::trap`; the V-register
/// WRITE routes through the `set_simd_fp_reg_v` C-shim (the u128-by-value ABI-bug
/// workaround). `run()` decodes HVF's native exit into the neutral `Aarch64Exit`.
///
/// The `Vcpu` is held in `ManuallyDrop`: on Drop we deliberately do NOT run
/// applevisor's `Vcpu::Drop`. Once carrick has executed a single `fork(2)` inside
/// the trap loop, applevisor's internal handle bookkeeping no longer matches HVF and
/// its destructor unwraps `hv_vcpu_destroy` and panics ("no VM or vCPU available").
/// The process is exiting either way; the kernel reclaims the vCPU. (This preserves
/// the old `ManuallyDrop<HvfInner>` discipline, now per-half.) The reclaim/fork
/// rebuilds raw-`hv_vcpu_destroy`/recreate the inner vCPU via `std::mem::replace`
/// inside it (`replace_destroyed_vcpu`), never running applevisor Drop.
pub struct HvfAarch64Vcpu(pub(crate) std::mem::ManuallyDrop<applevisor::vcpu::Vcpu>);

impl HvfAarch64Vcpu {
    pub(crate) fn new(vcpu: applevisor::vcpu::Vcpu) -> Self {
        Self(std::mem::ManuallyDrop::new(vcpu))
    }
}

impl Drop for HvfAarch64Vcpu {
    fn drop(&mut self) {
        // Intentionally skip `ManuallyDrop::drop` — see the type doc.
    }
}

fn os_to_trap(e: carrick_hal::OsError) -> TrapError {
    TrapError::Hypervisor(e.to_string())
}

impl Aarch64Vcpu for HvfAarch64Vcpu {
    fn get_reg(&self, r: Reg) -> Result<u64, TrapError> {
        hvf_get_reg(&self.0, r).map_err(os_to_trap)
    }
    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), TrapError> {
        hvf_set_reg(&self.0, r, v).map_err(os_to_trap)
    }
    fn get_sys_reg(&self, r: SysReg) -> Result<u64, TrapError> {
        hvf_get_sys_reg(&self.0, r).map_err(os_to_trap)
    }
    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), TrapError> {
        hvf_set_sys_reg(&self.0, r, v).map_err(os_to_trap)
    }

    fn get_vreg(&self, n: u32) -> Result<u128, TrapError> {
        let idx = n as usize;
        if idx >= crate::trap::SIMD_FP_TABLE.len() {
            return Err(TrapError::Hypervisor(format!(
                "vreg index {n} out of range"
            )));
        }
        self.0
            .get_simd_fp_reg(crate::trap::SIMD_FP_TABLE[idx])
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }
    fn set_vreg(&mut self, n: u32, v: u128) -> Result<(), TrapError> {
        let idx = n as usize;
        if idx >= crate::trap::SIMD_FP_TABLE.len() {
            return Err(TrapError::Hypervisor(format!(
                "vreg index {n} out of range"
            )));
        }
        // The u128-by-value ABI-bug workaround: route the V-register WRITE through
        // the C shim (applevisor's `set_simd_fp_reg` zeroes via the wrong register
        // class). Reads are pointer-based and unaffected (above).
        let rc = set_simd_fp_reg_v(self.0.id(), crate::trap::SIMD_FP_TABLE[idx], v);
        if rc == 0 {
            Ok(())
        } else {
            Err(TrapError::Hypervisor(format!(
                "set_simd_fp_reg(q{idx}) rc={rc:#x}"
            )))
        }
    }
    fn get_fpcr(&self) -> Result<u64, TrapError> {
        self.0
            .get_reg(applevisor::vcpu::Reg::FPCR)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }
    fn set_fpcr(&mut self, v: u64) -> Result<(), TrapError> {
        self.0
            .set_reg(applevisor::vcpu::Reg::FPCR, v)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }
    fn get_fpsr(&self) -> Result<u64, TrapError> {
        self.0
            .get_reg(applevisor::vcpu::Reg::FPSR)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }
    fn set_fpsr(&mut self, v: u64) -> Result<(), TrapError> {
        self.0
            .set_reg(applevisor::vcpu::Reg::FPSR, v)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn get_esr_el1(&self) -> Result<u64, TrapError> {
        self.0
            .get_sys_reg(applevisor::vcpu::SysReg::ESR_EL1)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }
    fn get_far_el1(&self) -> Result<u64, TrapError> {
        self.0
            .get_sys_reg(applevisor::vcpu::SysReg::FAR_EL1)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn snapshot(&self) -> Result<Aarch64VcpuSnapshot, TrapError> {
        // The HVF snapshot read (GPRs + the full stage-1 MMU sysregs + V-regs +
        // FPSR/FPCR + ACTLR/TPIDRRO/TPIDR_EL1), gated like the signal path on
        // `fpsimd_save_enabled()`. The engine owns `last_exit_class`, so it is not
        // carried here (restored from the vCPU latch on the inner restore path).
        HvfInner::snapshot_vcpu_from(&self.0).map(|s| to_neutral(&s))
    }
    fn restore(&mut self, snap: &Aarch64VcpuSnapshot) -> Result<(), TrapError> {
        // last_exit_class is engine-owned; the neutral snapshot doesn't carry it, so
        // restore 0 (the inner restore overwrites the vCPU latch from the snapshot's
        // own field, which we set to 0 — the trap loop relatches it on the next exit).
        HvfInner::restore_vcpu_into(&mut self.0, &from_neutral(snap, 0))
    }

    fn restore_thread_start(&mut self, snap: &Aarch64VcpuSnapshot) -> Result<(), TrapError> {
        // A brand-new HVF sibling vCPU has never transitioned to EL0, so it must
        // enter via the EL0 trampoline (PC=trampoline, SPSR_EL1=EL0t, ELR_EL1=snap.pc)
        // — distinct from the plain `restore` a fork resume uses. (KVM keeps the trait
        // default, which is a plain restore.)
        HvfInner::restore_vcpu_thread_start_into(&mut self.0, &from_neutral(snap, 0))
    }

    fn get_saved_x9(&self) -> Result<Option<u64>, TrapError> {
        // HVF's EL1 sentinel vector does NOT use the x9/TPIDR_EL1 sentinel-store
        // trick (that is the KVM MMIO-sentinel vehicle): the HVF vector forwards via
        // `hvc #2`, which clobbers no GPR. The guest's x9 at the trapped `svc` is
        // already intact in the vCPU's live register file. Return `None` so the shared
        // `complete_syscall` LEAVES x9 untouched — writing `set_reg(X9, 0)` here would
        // DESTROY musl's live malloc-context pointer and fault `str x10,[x9,#920]` at
        // 0x398 (the alpine/musl dynamic-binary crash). The fork snapshot likewise
        // already holds the live x9, so `rebuild_*_after_fork` ignores the param.
        Ok(None)
    }

    fn stamp_guest_thread_id(&self, tid: u64) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;
        // HVF's `hvc #2` vehicle leaves TPIDR_EL1 free (KVM uses it for the live-x9
        // stash — see `get_saved_x9`), so carrick stamps the guest tid there for the
        // EL1-vector `gettid` fast path (serviced at EL1, no host trap). Written via
        // the applevisor `SysReg` directly: the neutral `carrick_hal::SysReg` has no
        // TPIDR_EL1 variant (it is an HVF-private fast-path scratch).
        self.0
            .set_sys_reg(SysReg::TPIDR_EL1, tid)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn run(&mut self) -> Result<Aarch64Exit, TrapError> {
        HvfInner::run_to_exit(&mut self.0)
    }

    fn kick(&self) -> Result<(), TrapError> {
        use carrick_hal::VcpuKick as _;
        crate::vcpu_kick::VcpuKickHandle::new(self.0.get_handle()).kick();
        Ok(())
    }

    fn set_hardware_tso(&mut self, tso: bool) -> Result<(), TrapError> {
        const EN_TSO: u64 = 1 << 1;
        let actlr = self
            .0
            .get_sys_reg(applevisor::vcpu::SysReg::ACTLR_EL1)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        let next = if tso { actlr | EN_TSO } else { actlr & !EN_TSO };
        self.0
            .set_sys_reg(applevisor::vcpu::SysReg::ACTLR_EL1, next)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn set_memory_model(&mut self, tso: bool) -> Result<(), TrapError> {
        self.set_hardware_tso(tso)
    }
}

// ─── HvfAarch64Vmm ───────────────────────────────────────────────────────────

/// The VM half: the live `applevisor` VM + the per-thread mapping list + the
/// process-shared PROT_NONE / page-table state, plus the fork/reclaim bookkeeping.
/// One per guest process thread. Wraps the `HvfVmState` (the old `HvfInner` minus
/// the vCPU, which now lives in [`HvfAarch64Vcpu`]).
pub struct HvfAarch64Vmm {
    pub(crate) state: HvfVmState,
}

impl GuestVmBackend for HvfAarch64Vmm {
    fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        self.state.host_ptr(gpa, len)
    }

    fn write_gpa(&self, gpa: u64, bytes: &[u8]) -> Result<(), TrapError> {
        self.state
            .write_gpa(gpa, bytes)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn fork_ram_strategy(&self) -> ForkRamStrategy {
        // HVF guest RAM is host-`MAP_SHARED` (HVF coherence), so fork(2) does NOT
        // COW-isolate it; the child copies private pages. The shared `fork()` calls
        // `freeze_ram_for_fork` (HVF: capture descriptors + private child snapshots +
        // tear the VM down) before `libc::fork`.
        ForkRamStrategy::EagerCopy
    }

    fn process_exit_cleanup(&mut self) {
        // HVF's VM is swapped/leaked-until-exit (ManuallyDrop discipline); nothing to
        // release on a forked-child `_exit`. Matches the historical no-op.
    }

    fn wait_for_vcpu_slot() {
        // RETIRED: the bounded carrick-hal scheduler (installed for `vcpu_budget()`)
        // does admission in the shared spawn path. Double-gating here would defeat
        // reclaim (the gate slot would stay held while the thread blocks). No-op.
    }

    fn vcpu_budget() -> usize {
        crate::trap::hvf_vcpu_budget()
    }

    fn reclaims(&self) -> bool {
        true
    }
}

impl Aarch64Vmm for HvfAarch64Vmm {
    type Vcpu = HvfAarch64Vcpu;
    type KickHandle = crate::vcpu_kick::VcpuKickHandle;
    type SiblingBuilder = ThreadSpec;

    // ── memory windows + stage-2 ──

    fn map_stage2(
        &mut self,
        ipa: u64,
        host: *mut u8,
        len: u64,
        perms: carrick_hal::MemPerms,
    ) -> Result<(), TrapError> {
        self.state.map_stage2(ipa, host, len, perms)
    }

    fn handle_memory_exit(&mut self, gpa: u64, va: u64) -> Result<bool, TrapError> {
        // HVF-ONLY: the lazy high-VA alias re-map. A forked child rebuilt its VM from
        // only the forking thread's mappings, dropping a `guest_shared` alias mapped
        // by a sibling thread; re-`hv_vm_map` the registered host backing into THIS
        // VM so the faulting instruction re-executes cleanly. KVM never surfaces a
        // `Memory` exit (siblings share one VM). Returns Ok(true) when it remapped.
        Ok(self.state.try_lazy_alias_remap(gpa, va))
    }

    // ── guest-memory access (the GuestMemory backing seam) ──

    fn read_gpa(&self, gpa: u64, len: usize) -> Result<Vec<u8>, TrapError> {
        self.state
            .read_gpa(gpa, len)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn protections(&self) -> Option<&MemoryProtections> {
        Some(self.state.protections_ref())
    }

    fn translated_read(&self, va: u64, _ipa: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
        // HVF re-derives the region via its own per-thread mapping walk (with the
        // stage-1-IPA disambiguation + cross-thread alias fallback), so it ignores
        // the engine's pre-computed `ipa` and keys on the VA. PROT_NONE was already
        // gated in the default `read_bytes`.
        self.state.read_guest_bytes(va, len)
    }

    fn translated_read_into(&self, va: u64, _ipa: u64, dst: &mut [u8]) -> Result<(), MemoryError> {
        // No-alloc `volatile`-copy straight into `dst` (the read_u32/u64/header path).
        self.state.read_guest_bytes_into(va, dst)
    }

    fn translated_write(&mut self, va: u64, _ipa: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        // The PERMISSION-CHECKED syscall write: a write into a non-writable mapping
        // returns EFAULT (audit M1). PROT_NONE was gated in the default `write_bytes`.
        self.state.write_guest_bytes_checked(va, bytes)
    }

    fn translated_write_unchecked(
        &mut self,
        va: u64,
        _ipa: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryError> {
        // carrick-INTERNAL frame (vdso vvar / sigframe / bootstrap): bypass the
        // guest-visible WRITE permission (the host page is writable).
        self.state.write_guest_bytes(va, bytes)
    }

    fn guest_range_is_writable(&self, va: u64, len: usize) -> bool {
        self.state.guest_range_is_writable(va, len)
    }

    fn host_ptr_for_read(&self, va: u64, len: usize) -> Option<*const u8> {
        self.state.host_ptr_for_read(va, len)
    }

    fn host_ptr_for_write(&mut self, va: u64, len: usize) -> Option<*mut u8> {
        self.state.host_ptr_for_write(va, len)
    }

    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.state.set_no_access(address, len, no_access);
    }

    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.state.zero_guest_backing(address, len)
    }

    fn shared_futex_host_addr(&self, guest_addr: GuestVa) -> Option<HostVa> {
        self.state
            .shared_futex_host_addr(guest_addr.raw())
            .map(HostVa)
    }

    fn on_unmap(&mut self, va: u64, len: usize) {
        // Drop the process-shared alias index entry for this VA range before the
        // stage-1 invalidate (high-VA aliases only; low-VA arena is a no-op).
        crate::trap::unregister_alias(va, len);
    }

    fn add_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(u64, bool), TrapError> {
        // HVF maps the alias at the IPA the DISPATCHER already allocated from the
        // global alias arena (passed through `MapHostAlias`/the engine) — NOT the
        // VA-derived GPA KVM uses, and NOT a re-allocation here (that double-consumed
        // the arena, the dynamic-loader fault). The stage-2 `hv_vm_map` + the
        // alias-registry registration happen here; the engine then builds the SHARED
        // stage-1 `map_aliased(va, gpa, writable)`.
        self.state.add_alias(va, ipa, len, payload, file)
    }

    // ── vCPU lifecycle ──

    fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError> {
        self.state.add_vcpu().map(HvfAarch64Vcpu::new)
    }

    fn freeze_ram_for_fork(&mut self) -> Result<(), TrapError> {
        // Pre-fork (parent, single process): snapshot every PRIVATE region into a
        // child-private copy (guest RAM is MAP_SHARED, so fork doesn't isolate it),
        // capture the mapping descriptors, and tear down the HVF VM via the raw API
        // (a live VM at fork time makes the child's `hv_vm_create` fail). Both sides
        // then rebuild from the captured state.
        self.state.fork_prepare_and_teardown()
    }

    fn set_vfork_share(&mut self, share_vm: bool) {
        self.state.set_vfork_share(share_vm);
    }

    fn rebuild_child_after_fork(
        &mut self,
        vcpu: &mut Self::Vcpu,
        snapshot: &Aarch64VcpuSnapshot,
        _saved_x9: u64,
    ) -> Result<(), TrapError> {
        // CHILD side: build a fresh VM, re-`hv_vm_map` the child-private snapshot
        // buffers (+ the shared aperture), restore the register file, re-stamp the
        // vvar RNG generation. No x9/sentinel PC-advance: the HVF HVC vehicle clobbers
        // no GPR and ELR_EL1 (= post-svc) is restored by the snapshot, so the child
        // resumes mid-clone exactly like the parent.
        let snap = from_neutral(snapshot, 0);
        self.state
            .fork_rebuild(&mut vcpu.0, &snap, /*is_child=*/ true)
    }

    fn rebuild_parent_after_fork(
        &mut self,
        vcpu: &mut Self::Vcpu,
        snapshot: &Aarch64VcpuSnapshot,
        _saved_x9: u64,
    ) -> Result<(), TrapError> {
        // PARENT side: rebuild a fresh VM, re-`hv_vm_map` its OWN buffers + the union
        // of every quiesced sibling's regions, restore the register file. (HVF tore
        // its VM down in `freeze_ram_for_fork`, so the parent must rebuild too.)
        let snap = from_neutral(snapshot, 0);
        self.state
            .fork_rebuild(&mut vcpu.0, &snap, /*is_child=*/ false)
    }

    fn execve_rebuild(
        &mut self,
        vcpu: &mut Self::Vcpu,
        new_image: &AddressSpace,
    ) -> Result<(), TrapError> {
        // Tear down + rebuild the VM around the new image, reset the vCPU to "initial
        // process startup" (zeroed GPRs, EL0 trampoline). Clears the alias registry.
        let plan = GuestMappingPlan::from_address_space(new_image)?;
        self.state.execve_rebuild(&mut vcpu.0, &plan)
    }

    // ── threaded sibling lifecycle ──

    fn kick_handle(&self) -> Self::KickHandle {
        // The engine's `ThreadedEngine::kick_handle` calls this on the OWNING vCPU
        // thread. HVF's kick mechanism is the vCPU's `hv_vcpus_exit` handle, which
        // the Vmm doesn't hold directly — so `HvfVmState` stashes a clone of the
        // live vCPU's `VcpuHandle` on every (re)create (the `vcpu_handle` field)
        // and hands it out here.
        self.state.vcpu_kick_handle()
    }

    fn reclaim_refreshes_kicker(&self) -> bool {
        // HVF reclaim DESTROYS the vCPU, so the runtime must unregister this thread's
        // (now-dead-id) kick handle before the no-vCPU wait and re-register on wake.
        true
    }

    fn save_guest_state(
        &mut self,
        vcpu: &mut Self::Vcpu,
    ) -> Result<Aarch64VcpuSnapshot, TrapError> {
        // M:N reclaim BLOCK side: snapshot + DESTROY this vCPU (frees an HVF
        // concurrent-vCPU slot). The snapshot is stashed INTERNALLY in
        // `self.state.reclaim_snapshot` (read by `rebind_to_slot` on the SAME
        // thread), so the engine's serialized bytes are unused — return a zeroed
        // snapshot the engine drops. The vCPU handle is left stale until the wake.
        self.state.reclaim_park(&mut vcpu.0)?;
        Ok(zeroed_snapshot())
    }

    fn save_shared_wait_state(
        &mut self,
        vcpu: &mut Self::Vcpu,
    ) -> Result<Aarch64VcpuSnapshot, TrapError> {
        self.state.shared_wait_park(&mut vcpu.0)?;
        Ok(zeroed_snapshot())
    }

    fn rebind_to_slot(
        &mut self,
        _slot: SlotId,
        _snapshot: &Aarch64VcpuSnapshot,
        vcpu: &mut Self::Vcpu,
    ) -> Result<(), TrapError> {
        // M:N reclaim WAKE side: recreate this thread's vCPU in the EXISTING VM and
        // restore the parked state, writing the new vCPU back through `vcpu`. The
        // engine's `_snapshot` placeholder is ignored — HVF `take`s its own stashed
        // `reclaim_snapshot`. Slot id ignored (HVF recreates its OWN vCPU; no pool).
        self.state.reclaim_resume(&mut vcpu.0)
    }

    fn rebind_shared_wait_state(
        &mut self,
        _slot: SlotId,
        _snapshot: &Aarch64VcpuSnapshot,
        vcpu: &mut Self::Vcpu,
    ) -> Result<(), TrapError> {
        self.state.shared_wait_resume(&mut vcpu.0)
    }

    fn build_sibling_builder(
        &self,
        _vcpu: &Self::Vcpu,
        _entry: GuestEntryRegs,
    ) -> Result<Self::SiblingBuilder, TrapError> {
        // Build the `ThreadSpec`: the SHARED VM handle + the SHARED protections /
        // page-table Arcs + a copy of the mapping descriptors. HVF does NOT snapshot
        // the parent vCPU here — the engine carries the seeded register snapshot in
        // its `Aarch64SiblingSpec` and restores it onto the sibling via
        // `restore_thread_start`. (`_vcpu` unused: nothing thread-private comes from
        // the live vCPU; the engine's seeded snapshot is the register source.)
        self.state.build_thread_spec()
    }

    fn materialize_sibling(builder: Self::SiblingBuilder) -> Result<(Self, Self::Vcpu), TrapError> {
        // Stand up the sibling vCPU on the CURRENT host thread in the SHARED VM and
        // mirror the inherited (UNOWNED) mapping metadata. Returns the (Vmm, vCPU)
        // pair; the engine restores the seeded snapshot via `restore_thread_start`
        // (HVF's EL0-trampoline thread-start for a brand-new vCPU).
        let (state, vcpu) = HvfVmState::from_thread_spec(builder)?;
        Ok((Self { state }, HvfAarch64Vcpu::new(vcpu)))
    }

    fn set_guest_sp(&self, vcpu: &Self::Vcpu, sp: u64) -> Result<(), TrapError> {
        vcpu.0
            .set_sys_reg(applevisor::vcpu::SysReg::SP_EL0, sp)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn VcpuRegistry> {
        Arc::new(crate::vcpu_kick::VcpuKicker::new())
    }

    // ── multithreaded-fork sibling lifecycle ──

    fn release_vcpu_for_fork(&mut self, vcpu: &mut Self::Vcpu) -> Result<(), TrapError> {
        self.state.release_vcpu_for_fork(&mut vcpu.0)
    }

    fn publish_vm_for_siblings(&self) -> Result<(), TrapError> {
        self.state.publish_vm_for_siblings();
        Ok(())
    }

    fn rebuild_vcpu_after_fork(&mut self, vcpu: &mut Self::Vcpu) -> Result<(), TrapError> {
        self.state.rebuild_vcpu_after_fork(&mut vcpu.0)
    }

    fn destroy_vcpu_on_thread_exit(&mut self, vcpu: &mut Self::Vcpu) {
        self.state.destroy_vcpu_on_thread_exit(&mut vcpu.0);
    }

    fn fpsimd_enabled(&self) -> bool {
        crate::trap::fpsimd_save_enabled()
    }
}

/// An all-zero neutral snapshot the engine drops (HVF's reclaim stashes the real
/// snapshot internally). Mirrors the engine's own placeholder.
fn zeroed_snapshot() -> Aarch64VcpuSnapshot {
    Aarch64VcpuSnapshot {
        gprs: [0; 31],
        pc: 0,
        pstate: 0,
        sp_el0: 0,
        sp_el1: 0,
        elr_el1: 0,
        spsr_el1: 0,
        ttbr0: 0,
        ttbr1: 0,
        tcr: 0,
        sctlr: 0,
        mair: 0,
        vbar: 0,
        cpacr: 0,
        tpidr_el0: 0,
        tpidrro_el0: 0,
        tpidr_el1: 0,
        actlr_el1: 0,
        vregs: [0; 32],
        fpsr: 0,
        fpcr: 0,
    }
}
