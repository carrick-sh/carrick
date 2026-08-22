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

use std::sync::{Arc, OnceLock};

use carrick_aarch64::engine::restore_aarch64_task_state;
use carrick_aarch64::engine::{Aarch64ProcessSpec, Aarch64SiblingSpec};
use carrick_aarch64::{
    Aarch64EngineCore, Aarch64Exit, Aarch64Vcpu, Aarch64VcpuSnapshot, Aarch64Vmm, ForkRamStrategy,
};
use carrick_guest_mem::protections::MemoryProtections;
use carrick_guest_mem::{Gpa, MemoryError, SharedFutexLocation};
use carrick_hal::threaded::Aarch64TaskCpuStateV1;
use carrick_hal::{
    GuestEntryRegs, GuestVmBackend, ProcessForkRequest, Reg, SlotId, SysReg, TrapError,
    VcpuRegistry,
};
use carrick_mem::memory::AddressSpace;

use crate::syscall_mailbox::{HvfSyscallTransport, MailboxBinding};
use crate::trap::{
    GuestMappingPlan, HvfInner, HvfTaskState, HvfVmState, HvpatchPreparedCarrierTaskState,
    HvpatchTaskOnlyBackendState, PersistentExecutorSpec, ProcessSpec, ThreadSpec, VcpuSnapshot,
    hvf_get_reg, hvf_get_sys_reg, hvf_set_reg, hvf_set_sys_reg, set_simd_fp_reg_v,
    swap_hvpatch_task_state,
};
pub use crate::trap::{
    HvpatchCarrierTaskIdentity, HvpatchCarrierTaskStateDirectory, HvpatchChildKernelBinding,
};

/// The public engine type: the HVF aarch64 lane IS `Aarch64EngineCore<HvfAarch64Vmm>`.
/// `crate::trap::HvfTrapEngine` is a thin alias to this so every existing call site
/// (runtime.rs `run_threaded_hvf_loop`, the vcpu loop) is unchanged.
pub type HvfAarch64Engine = Aarch64EngineCore<HvfAarch64Vmm>;

pub fn persistent_vcpu_identity(vcpu: &HvfAarch64Vcpu) -> u64 {
    vcpu.inner.id()
}

pub fn persistent_hardware_kick(
    engine: &HvfAarch64Engine,
) -> (crate::vcpu_kick::VcpuKickHandle, u64, u32) {
    persistent_vcpu_hardware_kick(engine.vcpu())
}

pub fn persistent_vcpu_hardware_kick(
    vcpu: &HvfAarch64Vcpu,
) -> (crate::vcpu_kick::VcpuKickHandle, u64, u32) {
    let raw_vcpu_id = vcpu.inner.id();
    let handle = crate::vcpu_kick::VcpuKickHandle::new(vcpu.inner.get_handle());
    let owner_thread_port = unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) };
    (handle, raw_vcpu_id, owner_thread_port)
}

fn hvf_vcpu_reclaim_enabled_value(value: Option<&str>) -> bool {
    value != Some("0")
}

/// Exact diagnostic hatch for separating HVF vCPU destroy/recreate defects
/// from guest futex/scheduler defects. Default-on is the shipped M:N path.
/// `0` keeps one VM but admits one live HVF vCPU per guest thread, so it is a
/// correctness experiment rather than a performance configuration.
fn hvf_vcpu_reclaim_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        hvf_vcpu_reclaim_enabled_value(std::env::var("CARRICK_HVF_VCPU_RECLAIM").ok().as_deref())
    })
}

/// Build the engine from a freestanding/loaded image: create the VM + vCPU, map the
/// guest address space, and park the vCPU at the EL0-entry trampoline (the first
/// `next_syscall` runs into EL0). Mirrors `KvmAarch64Vmm::bring_up`.
pub fn bring_up(image: &AddressSpace) -> Result<HvfAarch64Engine, TrapError> {
    let plan = GuestMappingPlan::from_address_space(image)?;
    let (state, vcpu, mailbox) = HvfVmState::new_with_plan(&plan)?;
    let vmm = HvfAarch64Vmm { state };
    Ok(Aarch64EngineCore::from_parts(
        vmm,
        HvfAarch64Vcpu::new(vcpu, mailbox),
    ))
}

// ─── neutral ⟷ HVF VcpuSnapshot ──────────────────────────────────────────────
//
// HVF's `VcpuSnapshot` is now `{ core: Aarch64VcpuSnapshot, last_exit_class }`, so
// the neutral view IS the `core` and these conversions are trivial. The
// per-register HVF↔neutral mapping (CPSR ↔ pstate and the `*_EL1` sysreg names)
// lives in `snapshot_vcpu_from`/`restore_vcpu*`; mailbox rebinding owns SP_EL1.
// `last_exit_class` is engine-owned and not part of the neutral
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
pub struct HvfAarch64Vcpu {
    pub(crate) inner: std::mem::ManuallyDrop<applevisor::vcpu::Vcpu>,
    pub(crate) mailbox: MailboxBinding,
}

impl HvfAarch64Vcpu {
    pub(crate) fn new(vcpu: applevisor::vcpu::Vcpu, mailbox: MailboxBinding) -> Self {
        Self {
            inner: std::mem::ManuallyDrop::new(vcpu),
            mailbox,
        }
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
        hvf_get_reg(&self.inner, r).map_err(os_to_trap)
    }
    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), TrapError> {
        hvf_set_reg(&self.inner, r, v).map_err(os_to_trap)
    }
    fn get_sys_reg(&self, r: SysReg) -> Result<u64, TrapError> {
        hvf_get_sys_reg(&self.inner, r).map_err(os_to_trap)
    }
    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), TrapError> {
        hvf_set_sys_reg(&self.inner, r, v).map_err(os_to_trap)
    }

    fn get_vreg(&self, n: u32) -> Result<u128, TrapError> {
        let idx = n as usize;
        if idx >= crate::trap::SIMD_FP_TABLE.len() {
            return Err(TrapError::Hypervisor(format!(
                "vreg index {n} out of range"
            )));
        }
        self.inner
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
        let rc = set_simd_fp_reg_v(self.inner.id(), crate::trap::SIMD_FP_TABLE[idx], v);
        if rc == 0 {
            Ok(())
        } else {
            Err(TrapError::Hypervisor(format!(
                "set_simd_fp_reg(q{idx}) rc={rc:#x}"
            )))
        }
    }
    fn get_fpcr(&self) -> Result<u64, TrapError> {
        self.inner
            .get_reg(applevisor::vcpu::Reg::FPCR)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }
    fn set_fpcr(&mut self, v: u64) -> Result<(), TrapError> {
        self.inner
            .set_reg(applevisor::vcpu::Reg::FPCR, v)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }
    fn get_fpsr(&self) -> Result<u64, TrapError> {
        self.inner
            .get_reg(applevisor::vcpu::Reg::FPSR)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }
    fn set_fpsr(&mut self, v: u64) -> Result<(), TrapError> {
        self.inner
            .set_reg(applevisor::vcpu::Reg::FPSR, v)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn get_esr_el1(&self) -> Result<u64, TrapError> {
        self.inner
            .get_sys_reg(applevisor::vcpu::SysReg::ESR_EL1)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }
    fn get_far_el1(&self) -> Result<u64, TrapError> {
        self.inner
            .get_sys_reg(applevisor::vcpu::SysReg::FAR_EL1)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn snapshot(&self) -> Result<Aarch64VcpuSnapshot, TrapError> {
        // The HVF snapshot read (GPRs + the full stage-1 MMU sysregs + V-regs +
        // FPSR/FPCR + ACTLR/TPIDRRO/TPIDR_EL1), gated like the signal path on
        // `fpsimd_save_enabled()`. The engine owns `last_exit_class`, so it is not
        // carried here (restored from the vCPU latch on the inner restore path).
        HvfInner::snapshot_vcpu_from(&self.inner).map(|s| to_neutral(&s))
    }
    fn restore(&mut self, snap: &Aarch64VcpuSnapshot) -> Result<(), TrapError> {
        // last_exit_class is engine-owned; the neutral snapshot doesn't carry it, so
        // restore 0 (the inner restore overwrites the vCPU latch from the snapshot's
        // own field, which we set to 0 — the trap loop relatches it on the next exit).
        HvfInner::restore_vcpu_into(&mut self.inner, &from_neutral(snap, 0))
    }

    fn restore_thread_start(&mut self, snap: &Aarch64VcpuSnapshot) -> Result<(), TrapError> {
        // A brand-new HVF sibling vCPU has never transitioned to EL0, so it must
        // enter via the EL0 trampoline (PC=trampoline, SPSR_EL1=EL0t, ELR_EL1=snap.pc)
        // — distinct from the plain `restore` a fork resume uses. (KVM keeps the trait
        // default, which is a plain restore.)
        HvfInner::restore_vcpu_thread_start_into(&mut self.inner, &from_neutral(snap, 0))
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

    fn complete_syscall_return(&mut self, return_value: i64) -> Result<(), TrapError> {
        let transport = self.mailbox.transport();
        let result = match transport {
            HvfSyscallTransport::Mailbox => {
                self.mailbox
                    .publish_normal_return(return_value)
                    .map_err(|error| {
                        let diagnostics = self.mailbox.diagnostics();
                        TrapError::Hypervisor(format!(
                            "mailbox return publication failed: {error}; diagnostics={diagnostics:?}; attempted_return={return_value}"
                        ))
                    })
            }
            HvfSyscallTransport::Legacy => {
                hvf_set_reg(&self.inner, carrick_hal::Reg::X(0), return_value as u64)
                    .map_err(os_to_trap)?;
                self.mailbox
                    .publish_registers_prepared()
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "legacy mailbox return publication failed: {error}"
                        ))
                    })
            }
        };
        if result.is_ok() {
            crate::probes::hvf_syscall_transport(
                transport.raw(),
                1,
                0,
                0,
                u32::from(transport == HvfSyscallTransport::Legacy),
            );
        }
        result
    }

    fn prepare_register_resume(&mut self) -> Result<(), TrapError> {
        self.mailbox
            .publish_register_resume_if_outstanding()
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "mailbox register-resume publication failed: {error}"
                ))
            })
    }

    fn stamp_guest_thread_id(&self, tid: u64) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;
        // HVF's `gettid` fast path reads CONTEXTIDR_EL1 (serviced at EL1, no
        // host trap), leaving TPIDR_EL1 free as the syscall-shim scratch that
        // preserves x16 while checking ESR_EL1. Written via the applevisor
        // `SysReg` directly: the neutral `carrick_hal::SysReg` has no
        // CONTEXTIDR_EL1 variant (it is an HVF-private fast-path detail).
        let result = self
            .inner
            .set_sys_reg(SysReg::CONTEXTIDR_EL1, tid)
            .map_err(|e| TrapError::Hypervisor(e.to_string()));
        if std::env::var_os("CARRICK_TIDSTAMP_DEBUG").is_some() {
            let back = self.inner.get_sys_reg(SysReg::CONTEXTIDR_EL1);
            eprintln!(
                "[TIDSTAMP] set CONTEXTIDR_EL1={tid} -> readback={back:?} set_ok={}",
                result.is_ok()
            );
        }
        result
    }

    fn run(&mut self) -> Result<Aarch64Exit, TrapError> {
        let exit = HvfInner::run_to_exit(&mut self.inner, &mut self.mailbox);
        if std::env::var_os("CARRICK_TIDSTAMP_DEBUG").is_some() {
            use applevisor::prelude::SysReg;
            // Does the tid stamp SURVIVE a run/trap round trip? The stamp itself
            // reads back fine immediately after `set_sys_reg`, so if the EL1
            // `gettid` fast path is degrading, this is where it would show.
            let back = self.inner.get_sys_reg(SysReg::CONTEXTIDR_EL1);
            eprintln!("[TIDSTAMP] after run: CONTEXTIDR_EL1={back:?}");
        }
        exit
    }

    fn kick(&self) -> Result<(), TrapError> {
        use carrick_hal::VcpuKick as _;
        crate::vcpu_kick::VcpuKickHandle::new(self.inner.get_handle()).kick();
        Ok(())
    }

    fn set_hardware_tso(&mut self, tso: bool) -> Result<(), TrapError> {
        const EN_TSO: u64 = 1 << 1;
        let actlr = self
            .inner
            .get_sys_reg(applevisor::vcpu::SysReg::ACTLR_EL1)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        let next = if tso { actlr | EN_TSO } else { actlr & !EN_TSO };
        self.inner
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

#[derive(Clone)]
pub struct HvpatchPersistentExecutorFactoryAuthority {
    spec: PersistentExecutorSpec,
}
unsafe impl Sync for HvpatchPersistentExecutorFactoryAuthority {}

pub type HvpatchTaskEngineState = carrick_aarch64::Aarch64TaskEngineState<HvfAarch64Vmm>;

pub struct HvpatchTaskOnlyEngineState {
    _backend: HvpatchTaskOnlyBackendState,
    _snapshot: Aarch64VcpuSnapshot,
    _page_tables: Arc<parking_lot::Mutex<Option<carrick_mem::page_table::PageTableManager>>>,
    _protections: Arc<MemoryProtections>,
    _process_asid: Option<u16>,
    parked_task: parking_lot::Mutex<Option<HvfTaskState>>,
}
// SAFETY: the task projection contains only task-owned Arc authorities and raw
// mapping metadata whose pointees are retained by the registration. It carries
// no vCPU, mailbox binding, VM owner, or host-thread identity.
unsafe impl Send for HvpatchTaskOnlyEngineState {}

impl HvpatchTaskOnlyEngineState {
    pub fn initial_cpu_state(
        &self,
        mm_generation: u64,
        asid_generation: u64,
    ) -> Result<carrick_hal::threaded::GuestCpuState, TrapError> {
        carrick_aarch64::engine::sibling_task_cpu_state(
            &self._snapshot,
            mm_generation,
            asid_generation,
        )
    }

    pub fn apply_inventory(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryApplyReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        self._backend.apply_inventory(apply)
    }

    pub fn prepare_inventory_retirement(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError> {
        self._backend.prepare_inventory_retirement(commit)
    }

    pub fn apply_inventory_retirement(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        self._backend.apply_inventory_retirement(apply)
    }

    pub fn bind_child_kernel(
        &mut self,
        binding: HvpatchChildKernelBinding,
    ) -> Result<(), TrapError> {
        self._backend.bind_child_kernel(binding)
    }

    pub fn activate_child(&mut self) -> Result<(), TrapError> {
        if self.parked_task.lock().is_some() {
            return Err(TrapError::Hypervisor(
                "HVPatch task runtime state was activated twice".to_owned(),
            ));
        }
        let task = self._backend.runtime_task_state(
            Arc::clone(&self._page_tables),
            Arc::clone(&self._protections),
        )?;
        self._backend.activate()?;
        if self.parked_task.lock().replace(task).is_some() {
            std::process::abort();
        }
        Ok(())
    }

    pub fn retire(self) -> Result<(), TrapError> {
        // The backend registration owns the exact directory instance/token;
        // cleanup cannot be redirected through a caller-supplied directory.
        drop(self);
        Ok(())
    }
}

pub struct HvpatchPreparedTaskOnlyEngineState {
    carrier: HvpatchPreparedCarrierTaskState,
    snapshot: Aarch64VcpuSnapshot,
    page_tables: Arc<parking_lot::Mutex<Option<carrick_mem::page_table::PageTableManager>>>,
    protections: Arc<MemoryProtections>,
    process_asid: Option<u16>,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl HvpatchPreparedTaskOnlyEngineState {
    pub fn initial_cpu_state(
        &self,
        mm_generation: u64,
        asid_generation: u64,
    ) -> Result<carrick_hal::threaded::GuestCpuState, TrapError> {
        carrick_aarch64::engine::sibling_task_cpu_state(
            &self.snapshot,
            mm_generation,
            asid_generation,
        )
    }

    pub fn commit(
        self,
        directory: Arc<HvpatchCarrierTaskStateDirectory>,
    ) -> Result<HvpatchTaskOnlyEngineState, TrapError> {
        let Self {
            carrier,
            snapshot,
            page_tables,
            protections,
            process_asid,
            _not_send: _,
        } = self;
        let backend = carrier.commit(directory)?;
        Ok(HvpatchTaskOnlyEngineState {
            _backend: backend,
            _snapshot: snapshot,
            _page_tables: page_tables,
            _protections: protections,
            _process_asid: process_asid,
            parked_task: parking_lot::Mutex::new(None),
        })
    }

    pub fn abort(self) -> Result<(), TrapError> {
        self.carrier.abort()
    }
}

struct TaskOnlyNoExecutorAllocationGuard {
    vcpu_creates: u64,
    mailbox_claims: u64,
}

impl TaskOnlyNoExecutorAllocationGuard {
    fn capture() -> Self {
        Self {
            vcpu_creates: crate::trap::current_thread_vcpu_created_total(),
            mailbox_claims: crate::syscall_mailbox::current_thread_mailbox_slot_claims_total(),
        }
    }
}

impl Drop for TaskOnlyNoExecutorAllocationGuard {
    fn drop(&mut self) {
        if self.vcpu_creates != crate::trap::current_thread_vcpu_created_total()
            || self.mailbox_claims
                != crate::syscall_mailbox::current_thread_mailbox_slot_claims_total()
        {
            eprintln!(
                "carrick: FATAL: task-only HVPatch materializer allocated executor-local state"
            );
            std::process::abort();
        }
    }
}

#[cfg(test)]
static TASK_ONLY_MATERIALIZATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub fn materialize_hvpatch_sibling_without_vcpu(
    identity: HvpatchCarrierTaskIdentity,
    spec: Aarch64SiblingSpec<HvfAarch64Vmm>,
) -> Result<HvpatchPreparedTaskOnlyEngineState, TrapError> {
    let _no_executor_allocation = TaskOnlyNoExecutorAllocationGuard::capture();
    let parts = spec.into_task_only_parts();
    let carrier = HvpatchPreparedCarrierTaskState::sibling(identity, parts.builder)?;
    #[cfg(test)]
    TASK_ONLY_MATERIALIZATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Ok(HvpatchPreparedTaskOnlyEngineState {
        carrier,
        snapshot: parts.snapshot,
        page_tables: parts.page_tables,
        protections: parts.protections,
        process_asid: parts.process_asid,
        _not_send: std::marker::PhantomData,
    })
}

pub fn materialize_hvpatch_process_without_vcpu(
    identity: HvpatchCarrierTaskIdentity,
    spec: Aarch64ProcessSpec<HvfAarch64Vmm>,
) -> Result<HvpatchPreparedTaskOnlyEngineState, TrapError> {
    let _no_executor_allocation = TaskOnlyNoExecutorAllocationGuard::capture();
    let parts = spec.into_task_only_parts();
    let carrier = HvpatchPreparedCarrierTaskState::process(identity, parts.builder)?;
    #[cfg(test)]
    TASK_ONLY_MATERIALIZATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Ok(HvpatchPreparedTaskOnlyEngineState {
        carrier,
        snapshot: parts.snapshot,
        page_tables: parts.page_tables,
        protections: parts.protections,
        process_asid: Some(parts.process_asid),
        _not_send: std::marker::PhantomData,
    })
}

pub fn materialize_hvpatch_shared_process_without_vcpu(
    identity: HvpatchCarrierTaskIdentity,
    shared_kernel_mm: u64,
    spec: Aarch64SiblingSpec<HvfAarch64Vmm>,
) -> Result<HvpatchPreparedTaskOnlyEngineState, TrapError> {
    let _no_executor_allocation = TaskOnlyNoExecutorAllocationGuard::capture();
    let parts = spec.into_task_only_parts();
    let carrier =
        HvpatchPreparedCarrierTaskState::shared_process(identity, shared_kernel_mm, parts.builder)?;
    #[cfg(test)]
    TASK_ONLY_MATERIALIZATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Ok(HvpatchPreparedTaskOnlyEngineState {
        carrier,
        snapshot: parts.snapshot,
        page_tables: parts.page_tables,
        protections: parts.protections,
        process_asid: parts.process_asid,
        _not_send: std::marker::PhantomData,
    })
}
pub fn attach_task_engine(
    mut state: HvpatchTaskEngineState,
    executor: &mut HvfAarch64Vmm,
    vcpu: HvfAarch64Vcpu,
) -> HvfAarch64Engine {
    state.backend_mut().swap_persistent_executor_local(executor);
    Aarch64EngineCore::from_task_state_and_vcpu(state, vcpu)
}
pub fn attach_task_only_engine(
    state: &HvpatchTaskOnlyEngineState,
    mut executor: HvfAarch64Vmm,
    vcpu: HvfAarch64Vcpu,
    mm_generation: u64,
    asid_generation: u64,
) -> HvfAarch64Engine {
    let mut parked = state
        .parked_task
        .lock()
        .take()
        .unwrap_or_else(|| std::process::abort());
    swap_hvpatch_task_state(&mut executor.state.task, &mut parked);
    if state.parked_task.lock().replace(parked).is_some() {
        std::process::abort();
    }
    Aarch64EngineCore::from_injected_task_only_backend(
        executor,
        vcpu,
        Arc::clone(&state._page_tables),
        Arc::clone(&state._protections),
        state._process_asid,
        mm_generation,
        asid_generation,
    )
}
pub fn detach_task_only_engine(
    state: &HvpatchTaskOnlyEngineState,
    engine: HvfAarch64Engine,
) -> (HvfAarch64Vmm, HvfAarch64Vcpu) {
    let (mut executor, vcpu) = engine.into_injected_task_only_backend();
    let mut parked = state
        .parked_task
        .lock()
        .take()
        .unwrap_or_else(|| std::process::abort());
    swap_hvpatch_task_state(&mut executor.state.task, &mut parked);
    if state.parked_task.lock().replace(parked).is_some() {
        std::process::abort();
    }
    (executor, vcpu)
}
pub fn detach_task_engine(
    engine: HvfAarch64Engine,
    executor: &mut HvfAarch64Vmm,
) -> (HvpatchTaskEngineState, HvfAarch64Vcpu) {
    let (mut state, vcpu) = engine.into_task_state_and_vcpu();
    state.backend_mut().swap_persistent_executor_local(executor);
    (state, vcpu)
}

pub fn retire_detached_task_engine(
    state: &mut HvpatchTaskEngineState,
) -> Result<carrick_hal::FrameInventoryCommit<()>, TrapError> {
    let backend = state.backend_mut();
    backend.state.retire_process_mappings()?;
    backend.state.take_retirement_inventory().ok_or_else(|| {
        TrapError::Hypervisor(
            "detached HVPatch task retirement produced no inventory commit".to_owned(),
        )
    })
}

pub fn retire_detached_task_only_engine(
    state: &HvpatchTaskOnlyEngineState,
) -> Result<carrick_hal::FrameInventoryCommit<()>, TrapError> {
    let mut parked = state.parked_task.lock();
    let task = parked.as_mut().ok_or_else(|| {
        TrapError::Hypervisor("detached task-only retirement has no parked task state".to_owned())
    })?;
    HvfVmState::retire_task_state_process_mappings(task)?;
    HvfVmState::take_task_state_retirement_inventory(task).ok_or_else(|| {
        TrapError::Hypervisor(
            "detached task-only retirement produced no inventory commit".to_owned(),
        )
    })
}

pub fn retire_detached_exec_predecessor(
    state: &mut HvpatchTaskEngineState,
) -> Result<(), TrapError> {
    HvfVmState::retire_task_state_exec_predecessor(&mut state.backend_mut().state.task)
}

pub fn retire_detached_task_only_exec_predecessor(
    state: &HvpatchTaskOnlyEngineState,
) -> Result<(), TrapError> {
    let mut parked = state.parked_task.lock();
    let task = parked.as_mut().ok_or_else(|| {
        TrapError::Hypervisor("detached exec cleanup has no parked task state".to_owned())
    })?;
    HvfVmState::retire_task_state_exec_predecessor(task)
}
pub fn split_initial_task_engine(
    engine: HvfAarch64Engine,
) -> (HvpatchTaskEngineState, HvfAarch64Vcpu) {
    engine.into_task_state_and_vcpu()
}
pub fn destroy_worker_vcpu(vmm: &mut HvfAarch64Vmm, vcpu: &mut HvfAarch64Vcpu) {
    <HvfAarch64Vmm as Aarch64Vmm>::destroy_vcpu_on_thread_exit(vmm, vcpu);
}

pub fn invalidate_worker_asid(
    vmm: &mut HvfAarch64Vmm,
    vcpu: &mut HvfAarch64Vcpu,
    asid: u16,
) -> Result<(), TrapError> {
    vmm.state
        .audit_persistent_worker_vcpu_boundary(&vcpu.inner, &vcpu.mailbox)?;
    Aarch64EngineCore::<HvfAarch64Vmm>::invalidate_asid_on_vcpu(vcpu, asid)
}

pub fn persistent_executor_factory_authority(
    engine: &mut HvfAarch64Engine,
) -> Result<HvpatchPersistentExecutorFactoryAuthority, TrapError> {
    engine
        .backend_mut_for_persistent_factory()
        .take_persistent_executor_factory_authority()
}

impl HvpatchPersistentExecutorFactoryAuthority {
    pub fn create_executor_parts(&self) -> Result<(HvfAarch64Vmm, HvfAarch64Vcpu), TrapError> {
        let (state, vcpu, mailbox) = HvfVmState::from_persistent_executor_spec(&self.spec)?;
        Ok((HvfAarch64Vmm { state }, HvfAarch64Vcpu::new(vcpu, mailbox)))
    }
}

impl HvfAarch64Vmm {
    pub fn take_persistent_executor_factory_authority(
        &mut self,
    ) -> Result<HvpatchPersistentExecutorFactoryAuthority, TrapError> {
        Ok(HvpatchPersistentExecutorFactoryAuthority {
            spec: self.state.take_persistent_executor_spec()?,
        })
    }

    pub fn swap_persistent_executor_local(&mut self, other: &mut Self) {
        self.state.swap_persistent_executor_local(&mut other.state);
    }

    pub fn audit_persistent_executor_idle(&self) -> Result<(), TrapError> {
        self.state.audit_persistent_executor_idle()
    }
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

    fn process_exit_cleanup(&mut self) -> Result<(), TrapError> {
        // Called on the exiting fork-child's OWN thread (vcpu_loop/mod.rs:1469/
        // 1500/1884 — the child-exit / signal-death paths, gated by
        // `is_forked_child() || is_forked_guest_process()`, so it NEVER runs on
        // the parent), BEFORE `_exit` skips Rust drops.
        //
        // ATOMIC PERMIT PATH (the default): cooperatively free the permit slots
        // THIS process registered so occupancy returns to baseline immediately,
        // rather than waiting for the root EVFILT_PROC reaper's backstop — the
        // fast path that shrinks the fork/exec churn window. Idempotent with
        // `vcpu_destroyed` and the supervisor (generation-guarded) and it drains
        // only THIS process's local token map, so it cannot free the parent's
        // shared slots.
        //
        // FLOCK FALLBACK PATH (CARRICK_HVF_ATOMIC_PERMIT=0): a no-op — the flock
        // permit is fd-lifetime-bound, and HVF's VM is swapped/leaked-until-exit
        // (ManuallyDrop discipline), so there is nothing to release on a
        // forked-child `_exit`. Matches the historical no-op byte-for-byte.
        self.state.retire_process_mappings()?;
        let _ = crate::trap::cooperative_release_atomic_permit();
        Ok(())
    }

    fn wait_for_vcpu_slot() {
        // RETIRED: the bounded carrick-hal scheduler (installed for `vcpu_budget()`)
        // does admission in the shared spawn path. Double-gating here would defeat
        // reclaim (the gate slot would stay held while the thread blocks). No-op.
    }

    fn vcpu_budget() -> usize {
        if hvf_vcpu_reclaim_enabled() {
            crate::trap::hvf_vcpu_budget()
        } else {
            usize::MAX
        }
    }

    fn reclaims(&self) -> bool {
        hvf_vcpu_reclaim_enabled()
    }
}

impl Aarch64Vmm for HvfAarch64Vmm {
    fn audit_executor_boundary(&mut self, vcpu: &mut Self::Vcpu) -> Result<(), TrapError> {
        crate::trap::audit_hvpatch_executor_boundary(&self.state, &vcpu.mailbox)
    }

    fn set_persistent_vm_lifecycle(&mut self, enabled: bool) {
        self.state.set_persistent_vm_lifecycle(enabled);
    }

    fn prepare_exec_address_space(
        &mut self,
        root_slot_base: u64,
        root_slot_size: u64,
        asid: u16,
    ) -> Result<(), TrapError> {
        self.state
            .prepare_exec_address_space(root_slot_base, root_slot_size, asid)
    }

    fn sparse_mmap_arena_enabled(&self) -> bool {
        self.state.sparse_mmap_arena_enabled()
    }

    fn retire_initial_mmap_arena(&mut self) -> Result<(), TrapError> {
        self.state.retire_initial_mmap_arena()
    }

    fn ensure_sparse_mmap_backing(
        &mut self,
        va: u64,
        len: usize,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        self.state.ensure_sparse_mmap_backing(va, len, flush_stage1)
    }

    fn frame_inventory_extent_count(&self) -> usize {
        self.state.frame_inventory_extent_count()
    }

    fn inventory_initial_mappings(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<carrick_hal::FrameInventoryCommit<()>, TrapError> {
        self.state.inventory_initial_mappings(reservation)
    }

    fn begin_alias_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.state.begin_alias_inventory(reservation)
    }

    fn take_alias_inventory(&mut self) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        self.state.take_alias_inventory()
    }

    fn abandon_alias_inventory(&mut self) -> bool {
        self.state.abandon_alias_inventory()
    }

    fn frame_inventory_exec_extent_counts(&self, new_image: &AddressSpace) -> (usize, usize) {
        self.state.frame_inventory_exec_extent_counts(new_image)
    }

    fn inject_next_begin_exec_inventory_failure(&mut self) {
        self.state.inject_next_begin_exec_inventory_failure();
    }

    fn begin_exec_inventory(
        &mut self,
        retired: carrick_hal::FrameInventoryReservation,
        replacement: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.state.begin_exec_inventory(retired, replacement)
    }

    fn take_exec_inventory(
        &mut self,
    ) -> Option<(
        carrick_hal::FrameInventoryCommit<()>,
        carrick_hal::FrameInventoryCommit<()>,
    )> {
        self.state.take_exec_inventory()
    }

    fn begin_process_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.state.begin_process_inventory(reservation)
    }

    fn cancel_process_inventory(&mut self) -> bool {
        self.state.cancel_process_inventory()
    }

    fn take_process_inventory(&mut self) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        self.state.take_process_inventory()
    }

    fn begin_retirement_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.state.begin_retirement_inventory(reservation)
    }

    fn take_retirement_inventory(&mut self) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        self.state.take_retirement_inventory()
    }

    type Vcpu = HvfAarch64Vcpu;
    type KickHandle = crate::vcpu_kick::VcpuKickHandle;
    type SiblingBuilder = ThreadSpec;
    type ProcessBuilder = ProcessSpec;

    fn bind_stage1_page_tables(
        &mut self,
        page_tables: std::sync::Arc<
            parking_lot::Mutex<Option<carrick_mem::page_table::PageTableManager>>,
        >,
    ) {
        self.state.bind_stage1_page_tables(page_tables);
    }

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

    fn enrich_vcpu_run_error(&self, vcpu: &Self::Vcpu, error: TrapError) -> TrapError {
        self.state.enrich_mailbox_run_error(&vcpu.mailbox, error)
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

    fn fork_cow_ranges(&self) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        self.state.fork_cow_ranges()
    }

    fn arm_frame_cow_ranges(&mut self, ranges: &[carrick_aarch64::vmm::ForkCowRange]) {
        self.state.arm_frame_cow_ranges(ranges);
    }

    fn frame_cow_arm_snapshot(&self) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        self.state.frame_cow_arm_snapshot()
    }

    fn restore_frame_cow_arm_snapshot(
        &mut self,
        snapshot: Vec<carrick_aarch64::vmm::ForkCowRange>,
    ) {
        self.state.restore_frame_cow_arm_snapshot(snapshot);
    }

    fn armed_frame_cow_ranges(
        &self,
        va: u64,
        len: usize,
    ) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        self.state.armed_frame_cow_ranges(va, len)
    }

    fn bind_frame_cow(
        &mut self,
        authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority>,
        identity: carrick_hal::FrameCowIdentity,
    ) {
        self.state.bind_frame_cow(authority, identity);
    }

    fn refresh_fork_process_state(
        &mut self,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        self.state.refresh_fork_process_state(flush_stage1)
    }

    fn resolve_frame_cow_fault(
        &mut self,
        syndrome: u64,
        far: u64,
        ttbr0: u64,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<bool, TrapError> {
        self.state
            .resolve_frame_cow_fault(syndrome, far, ttbr0, flush_stage1)
    }

    fn refresh_vcpu_after_frame_cow(&self, vcpu: &mut Self::Vcpu) -> Result<(), TrapError> {
        self.state.relocate_mailbox_after_cow(&mut vcpu.mailbox)
    }

    fn ensure_frame_cow_write(
        &mut self,
        va: u64,
        len: usize,
        intent: carrick_aarch64::vmm::FrameCowWriteIntent,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        self.state
            .ensure_frame_cow_write(va, len, intent, flush_stage1)
    }

    fn observe_frame_cow_protection(
        &mut self,
        va: u64,
        len: usize,
        prot: u64,
    ) -> Result<(), TrapError> {
        self.state.observe_frame_cow_protection(va, len, prot)
    }

    fn publish_private_repoint(
        &mut self,
        va: u64,
        overlay_ipa: u64,
        len: usize,
    ) -> Result<(), TrapError> {
        self.state.publish_private_repoint(va, overlay_ipa, len)
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

    fn shared_futex_location(&self, backing_gpa: Gpa) -> Option<SharedFutexLocation> {
        self.state.shared_futex_location(backing_gpa.raw())
    }

    fn on_unmap(&mut self, va: u64, len: usize) -> Result<(), TrapError> {
        // The shared engine calls this only after checked stage-1 teardown and
        // TLBI succeed. A failed edit therefore retains this process-shared alias
        // owner; successful teardown removes the high-VA lookup (low VA no-op).
        self.state.unregister_process_alias(va, len)
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

    fn add_alias_with_sharing(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
        shared: bool,
    ) -> Result<(u64, bool), TrapError> {
        self.state
            .add_alias_with_sharing(va, ipa, len, payload, file, shared)
    }

    // ── vCPU lifecycle ──

    fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError> {
        let (vcpu, mailbox) = self.state.add_vcpu()?;
        Ok(HvfAarch64Vcpu::new(vcpu, mailbox))
    }

    fn fork_admission_check(&self) -> Result<(), TrapError> {
        // Pre-fork exhaustion gate: prove the host can admit the CHILD's
        // post-fork VM rebuild (bounded probe-and-release of one plain-fork
        // permit) BEFORE the parent tears its VM down / libc::fork's, so a
        // parked-fleet exhaustion becomes guest fork(2)=EAGAIN instead of a
        // post-fork HV_NO_RESOURCES fatal ("trap engine failed").
        crate::trap::probe_fork_vm_admission()
    }

    fn freeze_ram_for_fork(&mut self) -> Result<(), TrapError> {
        // Pre-fork (parent, single process): snapshot every PRIVATE region into a
        // child-private copy (guest RAM is MAP_SHARED, so fork doesn't isolate it),
        // capture the mapping descriptors, and tear down the HVF VM via the raw API
        // (a live VM at fork time makes the child's `hv_vm_create` fail). Both sides
        // then rebuild from the captured state.
        self.state.fork_prepare_and_teardown()
    }

    fn emit_fork_footprint_attribution(&self, arena_high_water: u64) {
        self.state.emit_fork_footprint_attribution(arena_high_water);
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
        self.state.fork_rebuild(
            &mut vcpu.inner,
            &mut vcpu.mailbox,
            &snap,
            /*is_child=*/ true,
        )
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
        self.state.fork_rebuild(
            &mut vcpu.inner,
            &mut vcpu.mailbox,
            &snap,
            /*is_child=*/ false,
        )
    }

    fn execve_rebuild(
        &mut self,
        vcpu: &mut Self::Vcpu,
        new_image: &AddressSpace,
    ) -> Result<(), TrapError> {
        // Tear down + rebuild the VM around the new image, reset the vCPU to "initial
        // process startup" (zeroed GPRs, EL0 trampoline). Clears the alias registry.
        let plan = GuestMappingPlan::from_address_space(new_image)?;
        self.state
            .execve_rebuild(&mut vcpu.inner, &mut vcpu.mailbox, &plan)
    }

    fn exec_page_tables(&self) -> Option<carrick_mem::page_table::PageTableManager> {
        self.state.page_tables_snapshot()
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
        let snapshot = vcpu.snapshot().map_err(|error| {
            TrapError::Hypervisor(format!("HVF reclaim typed snapshot capture: {error}"))
        })?;
        self.state
            .reclaim_park(&mut vcpu.inner, &mut vcpu.mailbox)?;
        Ok(snapshot)
    }

    fn save_initial_runner_state(
        &mut self,
        vcpu: &mut Self::Vcpu,
    ) -> Result<Aarch64VcpuSnapshot, TrapError> {
        let snapshot = vcpu.snapshot().map_err(|error| {
            TrapError::Hypervisor(format!("HVF initial-runner snapshot capture: {error}"))
        })?;
        self.state
            .initial_runner_park(&mut vcpu.inner, &mut vcpu.mailbox)?;
        Ok(snapshot)
    }

    fn rebind_initial_runner_state(
        &mut self,
        state: &Aarch64TaskCpuStateV1,
        vcpu: &mut Self::Vcpu,
    ) -> Result<(), TrapError> {
        if state.syscall_continuation.is_some() {
            return Err(TrapError::Hypervisor(
                "HVF initial runner restore rejected syscall continuation".to_owned(),
            ));
        }
        self.state
            .initial_runner_resume(&mut vcpu.inner, &mut vcpu.mailbox)?;
        let destination = vcpu.snapshot()?;
        let restored = restore_aarch64_task_state(&destination, state)?;
        vcpu.restore(&restored)
    }

    fn save_shared_wait_state(
        &mut self,
        vcpu: &mut Self::Vcpu,
    ) -> Result<Aarch64VcpuSnapshot, TrapError> {
        let snapshot = vcpu.snapshot().map_err(|error| {
            TrapError::Hypervisor(format!("HVF shared-wait typed snapshot capture: {error}"))
        })?;
        self.state
            .shared_wait_park(&mut vcpu.inner, &mut vcpu.mailbox)?;
        Ok(snapshot)
    }

    fn rebind_to_slot(
        &mut self,
        _slot: SlotId,
        state: &Aarch64TaskCpuStateV1,
        vcpu: &mut Self::Vcpu,
    ) -> Result<(), TrapError> {
        self.state.reclaim_resume(
            &mut vcpu.inner,
            &mut vcpu.mailbox,
            state.syscall_continuation,
        )?;
        let destination = vcpu.snapshot()?;
        let restored = restore_aarch64_task_state(&destination, state)?;
        vcpu.restore(&restored)
    }

    fn rebind_shared_wait_state(
        &mut self,
        _slot: SlotId,
        state: &Aarch64TaskCpuStateV1,
        vcpu: &mut Self::Vcpu,
    ) -> Result<(), TrapError> {
        self.state.shared_wait_resume(
            &mut vcpu.inner,
            &mut vcpu.mailbox,
            /*replay_alias_union=*/ false,
            state.syscall_continuation,
        )?;
        let destination = vcpu.snapshot()?;
        let restored = restore_aarch64_task_state(&destination, state)?;
        vcpu.restore(&restored)
    }

    fn rebind_shared_wait_state_mt(
        &mut self,
        _slot: SlotId,
        state: &Aarch64TaskCpuStateV1,
        vcpu: &mut Self::Vcpu,
    ) -> Result<(), TrapError> {
        // MT whole-VM lease first-waker rebuild: `self.mappings` is PER-THREAD,
        // so replay the process-global alias registry's union on top of it —
        // a high-VA alias a still-parked sibling mapped would otherwise be
        // missing from the rebuilt VM's stage-2 (same shape as the fork
        // rebuild's sibling-union replay).
        self.state.shared_wait_resume(
            &mut vcpu.inner,
            &mut vcpu.mailbox,
            /*replay_alias_union=*/ true,
            state.syscall_continuation,
        )?;
        let destination = vcpu.snapshot()?;
        let restored = restore_aarch64_task_state(&destination, state)?;
        vcpu.restore(&restored)
    }

    fn release_vm_after_reclaim_park(&mut self) -> Result<bool, TrapError> {
        // MT last-parker VM-only release: this thread's own vCPU is already
        // gone (reclaim_park, snapshot stashed), and the runtime re-checked
        // that every sibling's post-destroy "parked" mark is set — so only
        // the VM remains. Ok(true) = the wake side must rebuild
        // (shared_wait_resume works from the reclaim_park snapshot).
        self.state.release_vm_after_reclaim_park().map(|()| true)
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
        let (state, vcpu, mailbox) = HvfVmState::from_thread_spec(builder)?;
        Ok((Self { state }, HvfAarch64Vcpu::new(vcpu, mailbox)))
    }

    fn build_process_builder(
        &self,
        request: ProcessForkRequest,
        page_tables: &mut carrick_mem::page_table::PageTableManager,
        cow_ranges: &[carrick_aarch64::vmm::ForkCowRange],
    ) -> Result<Self::ProcessBuilder, TrapError> {
        self.state
            .build_process_spec(request, page_tables, cow_ranges)
    }

    fn materialize_process(builder: Self::ProcessBuilder) -> Result<(Self, Self::Vcpu), TrapError> {
        let (state, vcpu, mailbox) = HvfVmState::from_process_spec(builder)?;
        Ok((Self { state }, HvfAarch64Vcpu::new(vcpu, mailbox)))
    }

    fn commit_process_materialization(&mut self) -> Result<(), TrapError> {
        self.state.commit_process_materialization()
    }

    fn abort_process_materialization(&mut self, vcpu: &mut Self::Vcpu) -> Result<(), TrapError> {
        self.state.abort_process_materialization()?;
        self.state.destroy_vcpu_on_thread_exit(&mut vcpu.inner);
        Ok(())
    }

    fn set_guest_sp(&self, vcpu: &Self::Vcpu, sp: u64) -> Result<(), TrapError> {
        vcpu.inner
            .set_sys_reg(applevisor::vcpu::SysReg::SP_EL0, sp)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn VcpuRegistry> {
        Arc::new(crate::vcpu_kick::VcpuKicker::new())
    }

    // ── multithreaded-fork sibling lifecycle ──

    fn release_vcpu_for_fork(&mut self, vcpu: &mut Self::Vcpu) -> Result<(), TrapError> {
        self.state.release_vcpu_for_fork(&mut vcpu.inner)
    }

    fn publish_vm_for_siblings(&self) -> Result<(), TrapError> {
        self.state.publish_vm_for_siblings();
        Ok(())
    }

    fn rebuild_vcpu_after_fork(&mut self, vcpu: &mut Self::Vcpu) -> Result<(), TrapError> {
        self.state
            .rebuild_vcpu_after_fork(&mut vcpu.inner, &mut vcpu.mailbox)
    }

    fn destroy_vcpu_on_thread_exit(&mut self, vcpu: &mut Self::Vcpu) {
        self.state.destroy_vcpu_on_thread_exit(&mut vcpu.inner);
    }

    fn fpsimd_enabled(&self) -> bool {
        crate::trap::fpsimd_save_enabled()
    }

    fn task_continuation(
        &self,
        vcpu: &Self::Vcpu,
    ) -> Result<Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>, TrapError> {
        vcpu.mailbox
            .export_task_continuation()
            .map_err(|error| TrapError::Hypervisor(format!("export syscall continuation: {error}")))
    }

    fn take_task_continuation_for_executor_switch(
        &mut self,
        vcpu: &mut Self::Vcpu,
    ) -> Result<Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>, TrapError> {
        vcpu.mailbox
            .take_task_continuation_for_executor_switch()
            .map_err(|error| TrapError::Hypervisor(format!("detach syscall continuation: {error}")))
    }

    fn install_task_continuation_for_executor_switch(
        &mut self,
        vcpu: &mut Self::Vcpu,
        continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
    ) -> Result<(), TrapError> {
        if let Some(continuation) = continuation {
            vcpu.mailbox
                .import_task_continuation(continuation)
                .map_err(|error| {
                    TrapError::Hypervisor(format!("attach syscall continuation: {error}"))
                })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod reclaim_hatch_tests {
    use super::hvf_vcpu_reclaim_enabled_value;

    #[test]
    fn hvf_vcpu_reclaim_hatch_is_default_on_and_exact_zero_off() {
        assert!(hvf_vcpu_reclaim_enabled_value(None));
        assert!(!hvf_vcpu_reclaim_enabled_value(Some("0")));
        assert!(hvf_vcpu_reclaim_enabled_value(Some("1")));
        assert!(hvf_vcpu_reclaim_enabled_value(Some("false")));
    }

    #[test]
    fn persistent_hvf_workers_install_and_run_the_scoped_asid_trampoline() {
        let source = include_str!("hvf_aarch64_engine.rs");
        let create = source
            .split("pub fn persistent_executor_factory_authority")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl HvpatchPersistentExecutorFactoryAuthority")
                    .next()
            })
            .expect("persistent executor factory publication");
        assert!(!create.contains("write_gpa"));
        let invalidate = source
            .split("pub fn invalidate_worker_asid")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub fn persistent_executor_factory_authority")
                    .next()
            })
            .expect("persistent scoped ASID invalidation");
        assert!(invalidate.contains("invalidate_asid_on_vcpu"));
        assert!(invalidate.contains("audit_persistent_worker_vcpu_boundary"));
        assert!(!invalidate.contains("audit_executor_boundary"));
        assert!(!invalidate.contains("vmalle1is"));
    }
}

#[cfg(test)]
mod task_only_materializer_tests {
    #[test]
    fn hvpatch_task_only_materializers_are_structurally_vcpu_free() {
        let source = include_str!("hvf_aarch64_engine.rs");
        let sibling_name = concat!("materialize_hvpatch_sibling_", "without_vcpu");
        let process_name = concat!("materialize_hvpatch_process_", "without_vcpu");
        let sibling = source
            .split(sibling_name)
            .nth(1)
            .and_then(|tail| tail.split(process_name).next())
            .expect("HVPatch sibling task-only materializer");
        let process = source
            .split(process_name)
            .nth(1)
            .and_then(|tail| tail.split("pub fn attach_task_engine").next())
            .expect("HVPatch process task-only materializer");
        for body in [sibling, process] {
            assert!(body.contains("TaskOnlyNoExecutorAllocationGuard::capture()"));
            assert!(!body.contains("materialize_process("));
            assert!(!body.contains("materialize_sibling("));
            assert!(!body.contains("create_vcpu"));
            assert!(!body.contains("MailboxBinding"));
            assert!(!body.contains("VcpuHandle"));
        }

        let backend_shape = include_str!("trap.rs")
            .split("struct HvpatchTaskOnlyBackendState")
            .nth(1)
            .and_then(|tail| tail.split("struct HvpatchCarrierTaskIdentity").next())
            .expect("task-only backend shape");
        for forbidden in [
            "applevisor::vcpu::Vcpu",
            "VirtualMachineInstance",
            "GlobalFrameStage2Lease",
            "ProcessMappingDesc",
            "MailboxBinding",
            "MailboxSlotAllocator",
            "HvfSyscallTransport",
            "VcpuHandle",
            "vcpu_id",
            "owner_thread_port",
        ] {
            assert!(!backend_shape.contains(forbidden), "forbidden {forbidden}");
        }
        assert!(backend_shape.contains("registration: Option<HvpatchTaskRegistration>"));
        assert!(backend_shape.contains("impl Drop for HvpatchTaskOnlyBackendState"));
        let identity_shape = include_str!("trap.rs")
            .split("struct HvpatchCarrierTaskIdentity")
            .nth(1)
            .and_then(|tail| tail.split("struct HvpatchCarrierTaskStateKey").next())
            .expect("exact child identity shape");
        for required in [
            "task_serial: u64",
            "thread_serial: u64",
            "execution_generation: u64",
            "linux_pid: i32",
            "linux_tid: i32",
            "asid: u16",
            "HvpatchChildKernelToken",
        ] {
            assert!(
                identity_shape.contains(required),
                "identity lacks {required}"
            );
        }
        let key_shape = include_str!("trap.rs")
            .split("struct HvpatchCarrierTaskStateKey")
            .nth(1)
            .and_then(|tail| tail.split("enum HvpatchCarrierTaskState").next())
            .expect("strict scheduler key shape");
        for required in [
            "task_serial: u64",
            "thread_serial: u64",
            "execution_generation: u64",
        ] {
            assert!(key_shape.contains(required), "key lacks {required}");
        }
        for forbidden in ["linux_pid", "linux_tid", "asid"] {
            assert!(!key_shape.contains(forbidden), "metadata leaked into key");
        }

        let task_authority_shape = include_str!("trap.rs")
            .split("struct HvpatchPreparedTaskAuthority")
            .nth(1)
            .and_then(|tail| tail.split("struct AliasPublicationReceipt").next())
            .expect("task-only authority shape");
        for forbidden in [
            "VirtualMachineInstance",
            "GlobalFrameStage2Lease",
            "ProcessMappingDesc",
            "MailboxSlotAllocator",
            "HvfSyscallTransport",
        ] {
            assert!(
                !task_authority_shape.contains(forbidden),
                "task authority contains carrier field {forbidden}"
            );
        }
        for required in [
            "HvpatchTaskMappingState",
            "mm_root_slot",
            "HvpatchFrameInventory",
            "HvpatchTaskInventoryAuthority",
            "ProcessPrepared",
            "InventoryPublished",
            "Active",
            "Retired",
            "FrameCowAuthority",
            "CowArmedRanges",
            "PendingForkFrameReceipt",
            "AliasBacking",
            "alias_receipts: parking_lot::Mutex<Vec<AliasPublicationReceipt>>",
        ] {
            assert!(
                task_authority_shape.contains(required),
                "task authority lacks {required}"
            );
        }
        assert!(task_authority_shape.contains("FrameInventoryReceiptChallenge"));
        assert!(task_authority_shape.contains("malformed successful HVPatch inventory receipt"));
        assert!(task_authority_shape.contains("HvpatchPreparedInventoryRetirement"));
        assert!(task_authority_shape.contains("let mut expected_mappings"));
        assert!(task_authority_shape.contains("committed_unmaps != expected_ids"));
        assert!(include_str!("trap.rs").contains("mm_empty_at_revision"));
        assert!(task_authority_shape.contains("apply(retirement.commit)"));
        assert!(task_authority_shape.contains("authenticate_pending_retirement"));
        assert!(task_authority_shape.contains("malformed successful HVPatch retirement receipt"));
        assert!(task_authority_shape.contains("std::process::abort()"));
        let mm_authority_shape = include_str!("trap.rs")
            .split("struct HvpatchTaskMmAuthority")
            .nth(1)
            .and_then(|tail| tail.split("impl HvpatchTaskMmAuthority").next())
            .expect("shared task MM authority shape");
        for required in [
            "mappings: Vec<HvpatchTaskMappingState>",
            "inventory: parking_lot::Mutex<HvpatchTaskInventoryAuthority>",
            "pending_receipts: Vec<PendingForkFrameReceipt>",
            "alias_receipts: parking_lot::Mutex<Vec<AliasPublicationReceipt>>",
        ] {
            assert!(mm_authority_shape.contains(required), "MM lacks {required}");
        }
        for forbidden in ["cow_authority", "cow_identity"] {
            assert!(
                !mm_authority_shape.contains(forbidden),
                "per-thread {forbidden} leaked into shared MM"
            );
        }

        let carrier_shape = include_str!("trap.rs")
            .split("enum HvpatchCarrierTaskState")
            .nth(1)
            .and_then(|tail| tail.split("struct HvpatchTaskMappingState").next())
            .expect("carrier-only authority shape");
        assert!(carrier_shape.contains("VirtualMachineInstance"));
        assert!(carrier_shape.contains("GlobalFrameStage2Lease"));
        assert!(carrier_shape.contains("Arc<HvpatchCarrierMmAuthority>"));
        for forbidden in [
            "HvpatchFrameInventory",
            "FrameCowAuthority",
            "CowArmedRanges",
            "OwnedHostMapping",
            "AliasBacking",
            "PendingForkFrameReceipt",
            "MailboxSlotAllocator",
            "HvfSyscallTransport",
        ] {
            assert!(
                !carrier_shape.contains(forbidden),
                "carrier contains task authority {forbidden}"
            );
        }
        let directory_shape = include_str!("trap.rs")
            .split("struct HvpatchCarrierTaskStateDirectory")
            .nth(1)
            .and_then(|tail| tail.split("struct HvpatchPreparedCarrierTaskState").next())
            .expect("carrier directory registration shape");
        for required in [
            "instance: std::num::NonZeroU64",
            "std::sync::Weak<HvpatchCarrierMmAuthority>",
            "std::sync::Weak<HvpatchTaskMmAuthority>",
            "directory: std::sync::Arc<HvpatchCarrierTaskStateDirectory>",
            "task_mm: Option<std::sync::Arc<HvpatchTaskMmAuthority>>",
            "cow_authority: Option<std::sync::Arc<dyn carrick_hal::FrameCowAuthority>>",
            "cow_identity: Option<carrick_hal::FrameCowIdentity>",
            "child_token_verifier: std::sync::Arc<carrick_hal::HvpatchChildTokenVerifier>",
        ] {
            assert!(
                directory_shape.contains(required),
                "directory lacks {required}"
            );
        }
        let failpoint_cleanup = include_str!("trap.rs")
            .split("if failpoint == 2")
            .nth(1)
            .and_then(|tail| tail.split("if let Some(carrier_mm)").next())
            .expect("post-directory failpoint cleanup");
        assert!(
            failpoint_cleanup.find("drop(carrier_mm)").unwrap()
                < failpoint_cleanup.find("drop(task_mm)").unwrap(),
            "failpoint must release carrier stage2 before task backing"
        );
        let token_source = include_str!("../../carrick-hal/src/threaded.rs");
        let token_shape = token_source
            .split("pub struct HvpatchChildKernelToken")
            .nth(1)
            .and_then(|tail| tail.split("pub trait ThreadedEngine").next())
            .expect("sealed child token shape");
        assert!(token_shape.contains("pub struct HvpatchChildTokenIssuer"));
        assert!(token_shape.contains("pub struct HvpatchChildTokenVerifier"));
        assert!(token_shape.contains("verify_and_open"));
        assert!(token_shape.contains("Arc::ptr_eq"));
        assert!(!token_shape.contains("secret:"));
        assert!(!token_shape.contains("proof:"));
        assert!(!token_shape.contains("HvpatchChildKernelToken::from_kernel_authority"));
        assert!(include_str!("trap.rs").contains(
            "#[cfg(all(test, target_os = \"macos\", target_arch = \"aarch64\"))]\nimpl Default for HvpatchCarrierTaskStateDirectory"
        ));
        let kernel_core = include_str!("../../carrick-runtime/src/kernel/core.rs");
        assert!(
            kernel_core
                .contains("hvpatch_child_token_issuer: Arc<carrick_hal::HvpatchChildTokenIssuer>")
        );
        assert!(kernel_core.contains("pub(crate) fn issue_hvpatch_child_token"));
        assert!(kernel_core.contains("pub(crate) fn hvpatch_child_token_verifier"));
        assert!(!kernel_core.contains("pub fn hvpatch_child_token_issuer"));

        fn assert_send<T: Send>() {}
        assert_send::<super::HvpatchTaskOnlyEngineState>();
        let prepared_shape = source
            .split("struct HvpatchPreparedTaskOnlyEngineState")
            .nth(1)
            .and_then(|tail| tail.split("impl HvpatchPreparedTaskOnlyEngineState").next())
            .expect("prepared task-only transaction shape");
        assert!(prepared_shape.contains("PhantomData<*const ()>"));

        let compatibility = include_str!("../../carrick-aarch64/src/engine.rs");
        let process_compat = compatibility
            .split("fn materialize_process(spec: Self::ProcessSpec)")
            .nth(1)
            .and_then(|tail| tail.split("fn ").next())
            .expect("compatibility process materializer");
        assert!(process_compat.contains("V::materialize_process"));
        assert!(process_compat.contains("restore_thread_start"));
        let sibling_compat = compatibility
            .split("fn materialize_sibling(spec: Self::SiblingSpec)")
            .nth(1)
            .and_then(|tail| tail.split("fn program_counter").next())
            .expect("compatibility sibling materializer");
        assert!(sibling_compat.contains("V::materialize_sibling"));
        assert!(sibling_compat.contains("restore_thread_start"));

        let trap = include_str!("trap.rs");
        let sibling_prepare = trap
            .split("pub(crate) fn sibling(")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn process(").next())
            .expect("task-only sibling preparation");
        assert!(sibling_prepare.contains("cow_authority: _"));
        assert!(sibling_prepare.contains("cow_identity: _"));
        assert!(!sibling_prepare.contains("cow_authority,"));
        assert!(!sibling_prepare.contains("cow_identity,"));
        let task_process = trap
            .split("fn prepare_task_only_process_spec")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn from_process_spec").next())
            .expect("vCPU-free process preparation");
        assert!(!task_process.contains("HvfMappedRegion"));
        assert!(task_process.contains("receipt_challenge()"));
        let process_mapping_shape = trap
            .split("struct ProcessMappingDesc")
            .nth(1)
            .and_then(|tail| tail.split("struct ProcessInventoryDesc").next())
            .expect("process mapping drop shape");
        assert!(
            process_mapping_shape.find("stage2_lease").unwrap()
                < process_mapping_shape.find("host: ForkMappingHost").unwrap(),
            "stage2 lease must drop before host backing"
        );
        let compatibility_process = trap
            .split("pub(crate) fn from_process_spec")
            .nth(1)
            .and_then(|tail| tail.split("fn global_frame_exec_plan").next())
            .expect("compatibility process preparation");
        for shared_stage in [
            "inventory_hv_vm_map",
            "lease.mark_mapped()",
            "rebind_inherited_alias_to_process",
            "Self::stage_mapping",
            "process_reservation.commit(())",
            "PendingForkFrameReceipt",
        ] {
            assert!(
                task_process.contains(shared_stage),
                "task-only {shared_stage}"
            );
            assert!(
                compatibility_process.contains(shared_stage),
                "compatibility {shared_stage}"
            );
        }
    }

    #[test]
    fn task_only_allocation_counters_are_thread_exact_and_zero_delta() {
        let vcpus = crate::trap::current_thread_vcpu_created_total();
        let mailboxes = crate::syscall_mailbox::current_thread_mailbox_slot_claims_total();
        drop(super::TaskOnlyNoExecutorAllocationGuard::capture());
        assert_eq!(crate::trap::current_thread_vcpu_created_total(), vcpus);
        assert_eq!(
            crate::syscall_mailbox::current_thread_mailbox_slot_claims_total(),
            mailboxes
        );
    }

    #[test]
    fn one_worker_swaps_every_distinct_task_mm_mapping_and_cow_authority() {
        let mut worker = crate::trap::hvpatch_task_state_test_fixture(1, 0x1000, 101);
        let mut first = crate::trap::hvpatch_task_state_test_fixture(2, 0x2000, 202);
        let mut second = crate::trap::hvpatch_task_state_test_fixture(3, 0x3000, 303);
        let worker_expected = crate::trap::hvpatch_task_state_test_identity(&worker);
        let first_expected = crate::trap::hvpatch_task_state_test_identity(&first);
        let second_expected = crate::trap::hvpatch_task_state_test_identity(&second);

        crate::trap::swap_hvpatch_task_state(&mut worker, &mut first);
        assert_eq!(
            crate::trap::hvpatch_task_state_test_identity(&worker),
            first_expected
        );
        crate::trap::swap_hvpatch_task_state(&mut worker, &mut first);
        assert_eq!(
            crate::trap::hvpatch_task_state_test_identity(&worker),
            worker_expected
        );
        assert_eq!(
            crate::trap::hvpatch_task_state_test_identity(&first),
            first_expected
        );

        crate::trap::swap_hvpatch_task_state(&mut worker, &mut second);
        assert_eq!(
            crate::trap::hvpatch_task_state_test_identity(&worker),
            second_expected
        );
        crate::trap::swap_hvpatch_task_state(&mut worker, &mut second);
        assert_eq!(
            crate::trap::hvpatch_task_state_test_identity(&worker),
            worker_expected
        );
        assert_eq!(
            crate::trap::hvpatch_task_state_test_identity(&second),
            second_expected
        );
        assert_ne!(first_expected, second_expected);
    }

    #[test]
    fn factory_and_idle_worker_retain_no_root_task_authority_after_root_retire() {
        let source = include_str!("trap.rs");
        let factory_shape = source
            .split("struct PersistentExecutorSpec")
            .nth(1)
            .and_then(|tail| tail.split("struct ProcessMappingDesc").next())
            .expect("VM-only persistent executor spec");
        for forbidden in [
            "page_tables",
            "mm_root_slot",
            "frame_inventory",
            "cow_authority",
            "cow_identity",
            "cow_armed",
        ] {
            assert!(
                !factory_shape.contains(forbidden),
                "factory retained {forbidden}"
            );
        }
        assert!(
            factory_shape.contains("carrier_mappings"),
            "factory must retain only the VM-global executor control projection"
        );

        let root_task = crate::trap::hvpatch_task_state_test_fixture(7, 0x7000, 707);
        let idle_worker = crate::trap::hvpatch_neutral_task_state_for_test();
        drop(root_task);
        crate::trap::audit_hvpatch_neutral_task_state_for_test(&idle_worker).unwrap();
    }
}
