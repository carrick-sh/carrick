//! `Aarch64EngineCore<V>` — the generic aarch64 trap engine scaffold.
//!
//! Mirrors `carrick-x86`'s `X86EngineCore<V>`: implements the `carrick-hal` engine
//! traits ONCE over the thin [`Aarch64Vmm`] / [`Aarch64Vcpu`] trait pair,
//! replacing the two per-VMM copies of the aarch64 trap loop (HVF's
//! `HvfTrapEngine` and KVM's aarch64 `trap_engine`).
//!
//! ## Status — Stage 1 (compile-only scaffold)
//!
//! This struct only DEFINES the engine's owned state today; nothing implements
//! the `carrick-hal` engine traits over it yet, and no backend is wired. The
//! field set is taken from the union of the two existing engines (see the
//! per-field docs for the HVF vs KVM origin).
//!
//! ## The pending-syscall state lives HERE (§2.1)
//!
//! Collapsing each backend's pending-doorbell bookkeeping into the single
//! [`Aarch64Exit::Syscall { resume_pc }`](crate::vmm::Aarch64Exit::Syscall) moves
//! the "which doorbell is pending" state into the engine. On aarch64 there is no
//! SYSRET trampoline — `ELR_EL1` is always live and the EL1 vector's `eret`
//! consumes it — so the engine carries no `sysret_resume` analogue, which makes
//! this core SMALLER than `X86EngineCore`.

use std::sync::Arc;

use carrick_fatal::carrick_fatal;
use carrick_guest_mem::protections::MemoryProtections;
use carrick_guest_mem::{
    CurrentMmMemory, Gpa, GuestMemory, GuestVa, MappingSharing, MemoryError, RepointPrivateError,
    SharedFutexLocation,
};
use carrick_guest_mem::{LegacyProtectionRead, UserMemoryAuthority};
use carrick_hal::guest_arch::GuestArch as _;
use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
use carrick_hal::{
    GuestEntryRegs, HostAliasBacking, OsError, ProcessForkRequest, RawSyscall, Reg, SysReg,
    SyscallTrap, ThreadedEngine, TrapError,
};
use carrick_mem::memory::AddressSpace;
use carrick_mmu_core::aarch64::{
    LiveDescriptorOwner, PageTableApplyOutcome, PageTableError, PageTableManager, PtOp,
    TerminalRule, UserLeafAccess,
};

pub use crate::stage1_authority::{ShareState, Stage1Authority, Stage1Editor};

/// The publication boundary whose live descriptors a trace observes.
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum El1MappingLeafPhase {
    GrantPreparation,
    GrantSubmitted,
    HostGrantPublished,
    ReceiptApplied,
    ReceiptSettled,
    BeforeUnmap,
    AfterUnmap,
}

/// Sample the focused page and its neighbour under the caller's exact-MM
/// authority. Disabled probes do not walk descriptors or build diagnostic data.
pub fn trace_el1_mapping_leafs(
    engine: &impl ThreadedEngine,
    phase: El1MappingLeafPhase,
    mm: u64,
    span: carrick_mmu_core::aarch64::descriptor_txn::PageSpan,
    focus: u64,
) {
    let page = focus & !0xfff;
    for va in [Some(page), page.checked_add(0x1000)].into_iter().flatten() {
        if !span.contains(va) {
            continue;
        }
        carrick_observability::probes::el1_mapping_leaf(|| {
            let live = engine
                .diagnostic_fault_page_tables(va)
                .map_or(0, |(_, walk)| {
                    carrick_mmu_core::aarch64::terminal_descriptor(walk)
                });
            (phase as u32, mm, va, span.len, live)
        });
    }
}

use crate::vmm::{Aarch64Exit, Aarch64Vcpu, Aarch64VcpuSnapshot, Aarch64Vmm, FrameCowWriteIntent};

/// HVPatch installs this scoped-ASID routine into the existing EL1 maintenance
/// page's NOP tail. Other AArch64 backends do not invoke it until they install
/// the same backend completion sequence at this address.
pub const HVPATCH_EL1_ASID_MAINT_BASE: u64 = carrick_mem::memory::LINUX_EL1_ASID_MAINT_BASE;

pub fn asid_maintenance_bytes() -> Vec<u8> {
    carrick_mem::memory::el1_asid_maintenance_bytes()
}

/// Close Carrick's HVPatch root/global-frame aperture to the guest in an
/// AArch64 stage-1 image before it is published for an HvPatch process: the
/// global-frame arena is unmapped, and the stage-1 table pool (every MM's
/// root slot and extension arenas) is mapped EL1-only at its own address,
/// which is EL1's view of every table it edits on the guest-owned lane.
///
/// The operation is deterministic for an exec layout, so the HVF backend can
/// bake it into its stage-1 layout. Initial root bring-up still applies it
/// through the live editor before the first ASID is installed.
pub fn reserve_hvpatch_process_apertures(
    manager: &mut PageTableManager,
) -> Result<PageTableApplyOutcome, PageTableError> {
    let mut outcome = manager.set_prot_none(
        carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE,
        carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_SIZE as usize,
        None,
    )?;
    let pool = carrick_el1_abi::AARCH64_STAGE1_TABLE_POOL_BASE;
    if manager.map_kernel_data_aliased(
        pool,
        pool,
        carrick_el1_abi::AARCH64_STAGE1_TABLE_POOL_SIZE,
        None,
    )? {
        outcome.changed = true;
        outcome.flush_required = true;
    }
    Ok(outcome)
}

/// Build the guest-owned lane's frame-grant publication: a Prepare
/// transaction naming the backend-authenticated backing, with exactly the
/// faulting page resident. Nothing is stored in the live tables.
fn guest_frame_grant_submission(
    page_tables: &Stage1Authority,
    grant: carrick_hal::threaded::El1FrameGrantPublication,
    publication: carrick_mmu_core::aarch64::GuestLeafPublication,
) -> Result<carrick_hal::threaded::El1FrameGrantPublished, TrapError> {
    use carrick_hal::threaded::El1FrameGrantPublished;
    use carrick_mmu_core::aarch64::GuestTxnPrepareError;
    use carrick_mmu_core::aarch64::descriptor_txn::{BackingIdentity, DescriptorOp, PageSpan};
    use std::num::NonZeroU64;

    let unauthenticated =
        || TrapError::Hypervisor("EL1 frame grant lacks an authenticated identity".to_owned());
    let nonzero = |value| NonZeroU64::new(value).ok_or_else(unauthenticated);
    let backing = BackingIdentity {
        frame_id: nonzero(grant.ready.frame_id)?,
        mapping_id: nonzero(grant.ready.mapping_id)?,
        owner_generation: nonzero(grant.ready.owner_generation)?,
        inventory_revision: nonzero(grant.ready.inventory_revision)?,
    };
    let op = DescriptorOp::Prepare {
        publication,
        resident: PageSpan::new(grant.fault_va & !0xfff, 0x1000),
        backing,
    };
    match page_tables.prepare_guest_descriptor_txn(nonzero(grant.mm_key)?, op) {
        Ok(txn) => Ok(El1FrameGrantPublished::Submit(txn)),
        Err(GuestTxnPrepareError::Refused(refusal)) => {
            carrick_observability::probes::guest_internal_write_fault(
                publication.va,
                publication.len,
                23,
                &format!("EL1 frame-grant descriptor preparation refused: {refusal:?}"),
            );
            Ok(El1FrameGrantPublished::Refused(refusal))
        }
        Err(error) => Err(TrapError::Hypervisor(format!(
            "prepare EL1 frame-grant descriptor transaction: {error:?}"
        ))),
    }
}

/// The maintenance trampoline's closing `hvc #1`, used as the return address
/// of a host-driven EL1 call so its `ret` completes as `MaintenanceDone`.
const EL1_SERVICE_CALL_RETURN: u64 = carrick_mem::memory::LINUX_EL1_MAINT_BASE + 16;

fn with_maintenance_transfer_root<C: Aarch64Vcpu, T>(
    cpu: &mut C,
    root: carrick_mem::memory::CarrierMaintenanceRoot,
    service: impl FnOnce(&mut C) -> Result<T, TrapError>,
) -> Result<T, TrapError> {
    if root.raw() != carrick_el1_abi::EL1_CARRIER_MAINT_ROOT_BASE {
        return Err(TrapError::Hypervisor(
            "unrecognized carrier maintenance root".into(),
        ));
    }
    let saved = cpu.get_sys_reg(SysReg::Ttbr0)?;
    cpu.set_sys_reg(SysReg::Ttbr0, root.raw())?;
    let outcome = service(cpu);
    if let Err(error) = cpu.set_sys_reg(SysReg::Ttbr0, saved) {
        carrick_fatal!("aarch64::user_transfer", "restore executor TTBR0: {error}");
    }
    outcome
}

/// See [`carrick_hal::threaded::ThreadedEngine::run_el1_service_call`].
fn run_el1_service_call_on<V: Aarch64Vmm>(
    vcpu: &mut V::Vcpu,
    entry_pc: u64,
    frame_va: u64,
) -> Result<(), TrapError> {
    run_el1_service_effect_on::<V::Vcpu>(vcpu, entry_pc, frame_va, false, &mut || false)
}

fn run_el1_service_effect_on<C: Aarch64Vcpu>(
    vcpu: &mut C,
    entry_pc: u64,
    frame_va: u64,
    transfer: bool,
    effect: &mut dyn FnMut() -> bool,
) -> Result<(), TrapError> {
    const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
    let mut saved = Vec::with_capacity(36);
    let mut regs: Vec<Reg> = (0..31).map(Reg::X).collect();
    regs.extend([Reg::Pc, Reg::Pstate, Reg::ElrEl1, Reg::SpsrEl1, Reg::SpEl1]);
    for &reg in &regs {
        saved.push(vcpu.get_reg(reg).map_err(|error| {
            TrapError::Hypervisor(format!("save {reg:?} for host-driven EL1 call: {error}"))
        })?);
    }
    let setup = [
        (Reg::Pc, entry_pc),
        (Reg::Pstate, AARCH64_PSTATE_EL1H_DAIF_MASKED),
        (Reg::X(0), frame_va),
        (Reg::X(30), EL1_SERVICE_CALL_RETURN),
        (Reg::SpEl1, frame_va & !0xF),
    ];
    let mut result = Ok(());
    for (reg, value) in setup {
        if let Err(error) = vcpu.set_reg(reg, value) {
            result = Err(TrapError::Hypervisor(format!(
                "set {reg:?} for host-driven EL1 call: {error}"
            )));
            break;
        }
    }
    if result.is_ok() {
        // A cross-thread kick only interrupts the run; the call continues
        // from where it stopped.
        result = loop {
            match vcpu.run() {
                Ok(Aarch64Exit::MaintenanceDone) => {
                    if effect() {
                        continue;
                    }
                    break Ok(());
                }
                Ok(Aarch64Exit::Kicked) => continue,
                Ok(other) => {
                    if transfer {
                        carrick_fatal::carrick_fatal!(
                            "aarch64::user_transfer",
                            "cannot abandon suspended EL1 transfer stack: {}",
                            maintenance_exit_detail(&other)
                        );
                    }
                    break Err(TrapError::UnexpectedExit {
                        reason: format!(
                            "{} during host-driven EL1 call",
                            maintenance_exit_detail(&other)
                        ),
                    });
                }
                Err(error) => {
                    if transfer {
                        carrick_fatal::carrick_fatal!(
                            "aarch64::user_transfer",
                            "cannot abandon suspended EL1 transfer stack: {error}"
                        );
                    }
                    break Err(error);
                }
            }
        };
    }
    for (&reg, &value) in regs.iter().zip(&saved) {
        if let Err(error) = vcpu.set_reg(reg, value) {
            carrick_fatal!(
                "aarch64::el1_service",
                "restore {reg:?} after host-driven EL1 call: {error}"
            );
        }
    }
    result
}

/// A host live-table edit attempted on the lane where guest EL1 owns the live
/// descriptors. The caller must submit a guest descriptor transaction.
fn guest_owned_live_edit_error() -> MemoryError {
    MemoryError::HostMap(
        "guest EL1 owns the live stage-1 descriptors; submit a descriptor transaction".to_owned(),
    )
}

/// Lower a [`PageTableError`] from `sync_to_host` into [`MemoryError`], preserving
/// [`PageTableError::MetadataAllocation`] without allocating error strings.
pub(crate) fn page_table_sync_error_to_memory_error(error: PageTableError) -> MemoryError {
    match error {
        PageTableError::MetadataAllocation => MemoryError::MetadataAllocation,
        other => MemoryError::HostMap(format!(
            "sync stage-1 page tables to host failed: {other:?}"
        )),
    }
}

/// Lower a [`PageTableError`] from `rollback_undo` into [`MemoryError`], preserving
/// [`PageTableError::MetadataAllocation`] without allocating error strings.
pub(crate) fn page_table_rollback_error_to_memory_error(error: PageTableError) -> MemoryError {
    match error {
        PageTableError::MetadataAllocation => MemoryError::MetadataAllocation,
        other => MemoryError::HostMap(format!("stage-1 rollback failed: {other:?}")),
    }
}

/// Lower a [`MemoryError`] into [`TrapError`], preserving [`MemoryError::MetadataAllocation`]
/// as typed [`TrapError::MetadataAllocation`] without allocating strings.
pub(crate) fn memory_error_to_trap_error(error: MemoryError, context: &str) -> TrapError {
    match error {
        MemoryError::MetadataAllocation => TrapError::MetadataAllocation,
        other => TrapError::Hypervisor(format!("{context}: {other}")),
    }
}

struct EngineHostResolver<'a, V> {
    vm: &'a V,
    pt_base: u64,
    host: *mut u8,
    size: usize,
}

unsafe impl<V: Aarch64Vmm> carrick_mmu_core::aarch64::HostArenaResolver
    for EngineHostResolver<'_, V>
{
    fn host_ptr_for_range(&self, base: u64, len: usize) -> Option<*mut u8> {
        let needed = len.max(self.size);
        self.vm
            .host_ptr(base, needed)
            .or_else(|| (base == self.pt_base && len <= self.size).then_some(self.host))
    }

    fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
        self.host_ptr_for_range(base, 0)
    }

    fn host_const_ptr_for_range(&self, base: u64, len: usize) -> Option<*const u8> {
        self.host_ptr_for_range(base, len).map(|p| p.cast_const())
    }

    fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
        self.host_ptr_for_base(base).map(|p| p.cast_const())
    }

    fn publish_user_executable(
        &self,
        output: u64,
        len: u64,
    ) -> Result<(), carrick_mmu_core::aarch64::PageTableError> {
        self.vm.publish_user_executable(output, len)
    }
}

/// The generic aarch64 trap engine. Owns the VM, the (one) vCPU, the
/// pending-syscall resume PC, and the SA_RESTART syscall-number stash.
/// Per-backend behaviour is reached only through the [`Aarch64Vmm`] /
/// [`Aarch64Vcpu`] trait pair.
pub struct Aarch64EngineCore<V: Aarch64Vmm> {
    // ── backend bindings (the only per-VMM members) ──
    /// Owns stage-2 mapping, fork/execve rebuild, sibling spawn.
    vm: V,
    /// The (one) vCPU for this process thread.
    vcpu: std::cell::RefCell<V::Vcpu>,

    // ── syscall-doorbell state (OWNED BY ENGINE, §2.1; backend run() stateless) ──
    /// Resume PC (= `ELR_EL1`, post-`svc`) for the pending syscall; `Some` between
    /// `next_syscall` and `complete_syscall`. On aarch64 the EL1 vector's `eret`
    /// consumes `ELR_EL1`, so `complete_syscall` sets X0 only and never
    /// re-advances — but we still carry `resume_pc` to detect the trampoline-vs-
    /// direct case and to expose `current_pc` on a non-syscall kick. (x86 calls
    /// this `pending_resume_pc`.)
    pending_resume_pc: Option<u64>,

    /// Linux syscall number (x8) of the most recent trapped `svc`. Feeds the
    /// loop's SA_RESTART decision (`last_syscall_nr()`). `None` before the first
    /// syscall. (Both backends already have this.)
    last_syscall_nr: Option<u64>,

    /// Original x0 of the most recent trapped `svc` (the pre-syscall x0 the
    /// SA_RESTART rewind needs; supplies `InjectParams::orig_x0`). x86 calls this
    /// `last_orig_rax`.
    last_syscall_orig_x0: u64,

    /// `ESR_EL1` of the most recent EL0 synchronous fault (supplies
    /// `InjectParams::fault_esr`; the arm64 sigframe's `esr_context`, required by
    /// Rosetta's handler). Reset to 0 across fork/clone/execve and right after
    /// delivery.
    last_fault_esr: u64,

    /// `SP_EL1` of EL1 code this vCPU stopped in mid-operation: set when a
    /// stage-1 COW fault EL1 took is surfaced (re-entered at its faulting
    /// instruction by `ResumeEl1`), cleared when the vCPU next runs. A
    /// host-driven EL1 call meanwhile runs below it, never over the
    /// suspended operation's frames.
    suspended_el1_sp: Option<u64>,

    // ── trap-surface discriminator (the one aarch64-specific scalar) ──
    /// EC of the most recent exit: did we leave EL0 via `svc` (EC=0x15) or the
    /// EL1 vector's `hvc` (EC=0x16)? `complete_syscall` consults it to know
    /// whether to advance PC past the HVC. HVF-meaningful; on KVM the vector's own
    /// `eret` handles PC, so KVM leaves it at a fixed value. Kept as a plain field
    /// because it is engine policy, not backend state.
    last_exit_class: u64,

    // ── fork marker ──
    /// `true` on the child side of a guest `fork(2)`. Drives the
    /// `_exit`-without-report shutdown path + the `forked=` diagnostic.
    is_forked_child: bool,

    /// Hvpatch-only in-process guest ASID. `None` preserves the mature VMM/KVM
    /// bootstrap exactly; `Some` is re-applied after every exec replacement.
    process_asid: Option<u16>,

    /// Exact Kernel MM identity generation authorizing task snapshots.
    mm_generation: u64,
    /// Exact ASID allocation generation authorizing the task's TTBR values.
    asid_generation: u64,

    /// Non-aliasing guest-run time awaiting the exact logical-thread charge.
    pending_guest_run_receipt_ns: u64,

    /// `(far, retries)` of the stale stage-1 fault this task keeps retrying.
    /// A genuine sibling race resolves within one or two retries; a fault the
    /// live walk keeps permitting while the vCPU keeps refusing it names a
    /// stage-1 leaf whose frame stage-2 no longer maps, which no TLBI can
    /// repair. Bounding the retry turns that silent 100% CPU livelock into a
    /// named failure carrying the walk.
    stale_stage1_retry: (u64, u32),

    /// Fresh stage-1 image allocations of the most recent `build_process_spec`
    /// (`0` when the child image came from the recycle pool). Read by the
    /// runtime and charged as `page_table_image_allocations`.
    last_fork_image_allocations: u64,

    // ── shared memory state (the X86EngineCore parallels) ──
    /// Live stage-1 page-table authority over the guest's own translation tables at
    /// `LINUX_PAGE_TABLES_BASE` and extension arena source.
    page_tables: Stage1Authority,

    /// Process-wide PROT_NONE ranges; the EFAULT gate on every syscall-buffer
    /// access. SHARED by `CLONE_THREAD` siblings (`Arc` clone), COW'd on fork.
    protections: UserMemoryAuthority,

    /// The immediately following protection edit initializes a new VMA. Its
    /// cold reservation must discard retired predecessor leaf authority.
    pending_new_mapping: Option<(u64, usize)>,

    /// Exact parent state retained across the host-thread spawn/materialization
    /// window of an in-process fork. Runtime commits it only after the child is
    /// materialized; a recoverable failure restores both authorities.
    pending_process_fork: Option<ParentForkCowRollback>,
    pending_owner_fork: Option<OwnerForkTransaction<V::ProcessBuilder>>,

    /// When set, records the runtime's exec predecessor-sharing expectation
    /// (`mark_exec_predecessor_shared`) to cross-check against the stage-1
    /// authority's own share decision.
    exec_predecessor_shared: Option<bool>,

    /// Stage-1 maintenance a staged (never-run) vCPU recorded during this
    /// task's bring-up. The task's first live executor discharges it in
    /// [`Self::overlay_task_state_on_live_executor`] before the task's first
    /// instruction.
    owed_stage1_maintenance: crate::vmm::OwedStage1Maintenance,

    /// The required invalidation the current syscall's host-lane edits owe,
    /// issued by this vCPU when it returns the syscall (see
    /// [`crate::resume_invalidation`]).
    owed_resume_invalidation: Option<crate::resume_invalidation::ResumeInvalidation>,
}

pub struct Aarch64TaskEngineState<V: Aarch64Vmm> {
    vm: V,
    pending_resume_pc: Option<u64>,
    last_syscall_nr: Option<u64>,
    last_syscall_orig_x0: u64,
    last_fault_esr: u64,
    last_exit_class: u64,
    is_forked_child: bool,
    process_asid: Option<u16>,
    mm_generation: u64,
    asid_generation: u64,
    pending_guest_run_receipt_ns: u64,
    page_tables: Stage1Authority,
    protections: UserMemoryAuthority,
    pending_process_fork: Option<ParentForkCowRollback>,
    pending_owner_fork: Option<OwnerForkTransaction<V::ProcessBuilder>>,
    owed_stage1_maintenance: crate::vmm::OwedStage1Maintenance,
}

/// Task-owned runtime authorities that must follow a logical HVPatch task
/// across persistent-worker attach/detach boundaries.  Exec may replace all
/// three while the task is loaded, so a task-only binding must republish the
/// projection returned by the live engine rather than retaining immutable
/// construction-time clones.
pub struct Aarch64TaskRuntimeProjection {
    pub page_tables: Stage1Authority,
    pub protections: UserMemoryAuthority,
    pub process_asid: Option<u16>,
}

impl Aarch64TaskRuntimeProjection {
    /// Require both runtime handles to name one exact shared MM authority.
    /// Pointer identity is intentional: independently cloned contents cannot
    /// substitute for the carrier-owned state shared by CLONE_VM tasks.
    pub fn shares_exact_mm_authority(
        &self,
        page_tables: &Stage1Authority,
        protections: &UserMemoryAuthority,
    ) -> bool {
        self.page_tables.shares_exact_authority(page_tables)
            && self.protections.same_authority(protections)
    }
}
unsafe impl<V: Aarch64Vmm> Send for Aarch64TaskEngineState<V> {}

impl<V: Aarch64Vmm> Aarch64TaskEngineState<V> {
    pub fn runtime_projection(&self) -> Aarch64TaskRuntimeProjection {
        Aarch64TaskRuntimeProjection {
            page_tables: self.page_tables.clone(),
            protections: self.protections.clone(),
            process_asid: self.process_asid,
        }
    }

    pub fn backend_mut(&mut self) -> &mut V {
        &mut self.vm
    }
}

struct EngineStage1Services<'a, V: Aarch64Vmm> {
    vcpu: &'a mut V::Vcpu,
    tables: Stage1Authority,
    slot: Option<usize>,
    process_asid: Option<u16>,
    carrier_root: Option<carrick_mem::memory::CarrierMaintenanceRoot>,
    suspended_el1_sp: Option<u64>,
    /// Set when a host-applied transaction needs its required (not
    /// break-before-make) invalidation, which the caller then runs once for
    /// its whole edit; `None` runs every invalidation at once.
    required_invalidation: Option<&'a std::cell::Cell<bool>>,
}
impl<V: Aarch64Vmm> crate::descriptor_drain::GuestDrainVenue for EngineStage1Services<'_, V> {
    fn slot(&self) -> Option<usize> {
        self.slot
    }
    fn live_ttbr0(&mut self) -> Result<u64, TrapError> {
        self.vcpu
            .get_sys_reg(SysReg::Ttbr0)
            .map_err(|error| TrapError::Hypervisor(format!("read COW TTBR0: {error}")))
    }
    fn drain_call(
        &mut self,
        frame: carrick_el1_abi::TrapFrame,
    ) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
        crate::descriptor_drain::run_drain_call(frame, self.suspended_el1_sp, |entry, frame_va| {
            run_el1_service_call_on::<V>(self.vcpu, entry, frame_va)
        })
    }
    fn settle(
        &mut self,
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Result<
        carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt,
        crate::descriptor_drain::GuestPublishError,
    > {
        self.tables
            .settle_guest_descriptor_receipt(txn, receipt)
            .map_err(|error| {
                crate::descriptor_drain::GuestPublishError::from_settle(
                    error,
                    "settle guest descriptor",
                )
            })
    }
    fn apply_as_host(
        &mut self,
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        slots: &carrick_el1_abi::DescriptorTxnSlots,
    ) -> Option<Result<carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt, TrapError>>
    {
        let (process_asid, carrier_root) = (self.process_asid, self.carrier_root);
        let required_invalidation = self.required_invalidation;
        let maintenance = VcpuBbmMaintenance::<V> {
            vcpu: std::cell::RefCell::new(&mut *self.vcpu),
            process_asid,
            carrier_root,
            error: std::cell::RefCell::new(None),
        };
        crate::descriptor_drain::apply_as_host_if_excluded(
            &self.tables,
            slots,
            txn,
            &maintenance,
            // As EL1's completion does: each ASID invalidation an outcome
            // requires completes before the edit's caller returns (at once,
            // or once for the caller's whole edit).
            &|| match required_invalidation {
                Some(required) => required.set(true),
                None => {
                    carrick_mmu_core::aarch64::descriptor_txn::TableMaintenance::invalidate_range(
                        &maintenance,
                        0,
                        0,
                    )
                }
            },
            || match maintenance.error.borrow_mut().take() {
                Some(error) => Err(error),
                None => Ok(()),
            },
        )
    }
}

/// Break-before-make invalidations a host-applied guest transaction asks
/// for, run at once on the applying vCPU (ASID-wide, inner shareable). The
/// first failure is kept and the transaction's result reported unsettled.
struct VcpuBbmMaintenance<'a, V: Aarch64Vmm> {
    vcpu: std::cell::RefCell<&'a mut V::Vcpu>,
    process_asid: Option<u16>,
    carrier_root: Option<carrick_mem::memory::CarrierMaintenanceRoot>,
    error: std::cell::RefCell<Option<TrapError>>,
}

impl<V: Aarch64Vmm> carrick_mmu_core::aarch64::descriptor_txn::TableMaintenance
    for VcpuBbmMaintenance<'_, V>
{
    fn publish_barrier(&self) {}

    fn invalidate_range(&self, _va: u64, _len: u64) {
        if let Err(error) = Aarch64EngineCore::<V>::run_stage1_maintenance_on(
            &mut self.vcpu.borrow_mut(),
            self.process_asid,
            self.carrier_root,
        ) {
            self.error.borrow_mut().get_or_insert(error);
        }
    }
}

impl<V: Aarch64Vmm> crate::vmm::Stage1Services for EngineStage1Services<'_, V> {
    fn flush(&mut self) -> Result<(), TrapError> {
        Aarch64EngineCore::<V>::run_stage1_maintenance_on(
            self.vcpu,
            self.process_asid,
            self.carrier_root,
        )
    }
    fn guest_publication_available(&self) -> bool {
        self.slot.is_some()
    }
    fn publish(
        &mut self,
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
    ) -> Result<
        carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt,
        crate::descriptor_drain::GuestPublishError,
    > {
        let slots = carrick_el1_abi::descriptor_txn_slots_host()
            .ok_or_else(|| TrapError::Hypervisor("COW descriptor slots absent".to_owned()))?;
        crate::descriptor_drain::apply_guest_descriptor_txns_now(self, slots, &[*txn])?
            .pop()
            .ok_or_else(|| TrapError::Hypervisor("COW descriptor receipt absent".to_owned()).into())
    }
}

/// Exclusive loan of the scheduler-owned CPU for one host owner operation.
/// Constructed before inspecting registers or mutating any shared transport.
pub(crate) struct TransferServiceLoan<'a, V: Aarch64Vmm> {
    engine: &'a Aarch64EngineCore<V>,
    cpu: std::cell::RefMut<'a, V::Vcpu>,
}
impl<V: Aarch64Vmm> TransferServiceLoan<'_, V> {
    pub(crate) fn target_ttbr0(&self) -> Result<u64, TrapError> {
        self.cpu.get_sys_reg(SysReg::Ttbr0)
    }
    pub(crate) fn slot(&self) -> Result<usize, TrapError> {
        self.cpu
            .mailbox_slot()
            .map(|slot| slot as usize)
            .ok_or_else(|| TrapError::Hypervisor("owner service caller has no EL1 slot".into()))
    }
    pub(crate) fn run_fork(
        &mut self,
        mut frame: carrick_el1_abi::TrapFrame,
        effect: &mut dyn FnMut() -> bool,
    ) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
        frame.slot = self.slot()? as u64;
        let suspended = self.engine.suspended_el1_sp;
        crate::descriptor_drain::run_drain_call(frame, suspended, |entry, frame_va| {
            run_el1_service_effect_on::<V::Vcpu>(&mut self.cpu, entry, frame_va, true, effect)
        })
    }
    pub(crate) fn run_parent(
        &mut self,
        frame: carrick_el1_abi::TrapFrame,
        target: crate::user_transfer::TransferTarget,
        sequence: core::num::NonZeroU64,
        effect: &mut dyn FnMut() -> bool,
    ) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
        let operation = self
            .engine
            .pending_owner_fork_operation()
            .ok_or_else(|| TrapError::Hypervisor("parent transfer has no retained Fork".into()))?;
        let current = self.cpu.get_sys_reg(SysReg::Ttbr0)?;
        if operation.sequence != sequence
            || operation.carrier != target.handle().carrier()
            || operation.mm != target.handle().mm()
            || operation.incarnation != target.handle().incarnation()
            || current != target.ttbr0()
        {
            return Err(TrapError::Hypervisor(
                "parent transfer differs from exact pending Fork root".into(),
            ));
        }
        self.run_fork(frame, effect)
    }
    pub(crate) fn run_user(
        &mut self,
        mut frame: carrick_el1_abi::TrapFrame,
        effect: &mut dyn FnMut() -> bool,
    ) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
        let root = self.engine.vm.carrier_maintenance_root()?;
        frame.slot = self.slot()? as u64;
        let suspended = self.engine.suspended_el1_sp;
        with_maintenance_transfer_root(&mut *self.cpu, root, |cpu| {
            crate::descriptor_drain::run_drain_call(frame, suspended, |entry, frame_va| {
                run_el1_service_effect_on::<V::Vcpu>(cpu, entry, frame_va, true, effect)
            })
        })
    }
}

impl<V: Aarch64Vmm> Aarch64EngineCore<V> {
    /// Borrow the VM-bearing backend while preparing a persistent executor
    /// factory. Task state extraction below remains the only consuming split.
    pub fn backend(&self) -> &V {
        &self.vm
    }

    /// Mutably borrow the VM-bearing backend exactly once while transferring
    /// carrier-only mapping ownership into the persistent executor factory.
    pub fn backend_mut_for_persistent_factory(&mut self) -> &mut V {
        &mut self.vm
    }

    /// Attach one task-only HVPatch binding to a worker-injected backend/vCPU.
    /// The binding contributes only shared logical task state; VM/vCPU owner
    /// identity comes from the worker for this resident interval.
    pub fn from_injected_task_only_backend(
        mut vm: V,
        vcpu: V::Vcpu,
        page_tables: Stage1Authority,
        protections: UserMemoryAuthority,
        process_asid: Option<u16>,
        mm_generation: u64,
        asid_generation: u64,
    ) -> Self {
        vm.bind_stage1_page_tables(page_tables.clone());
        Self {
            vm,
            vcpu: std::cell::RefCell::new(vcpu),
            pending_resume_pc: None,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            stale_stage1_retry: (0, 0),
            last_fork_image_allocations: 0,
            last_fault_esr: 0,
            suspended_el1_sp: None,
            last_exit_class: 0,
            is_forked_child: false,
            process_asid,
            mm_generation,
            asid_generation,
            pending_guest_run_receipt_ns: 0,
            page_tables,
            protections,
            pending_new_mapping: None,
            pending_process_fork: None,
            pending_owner_fork: None,
            exec_predecessor_shared: None,
            owed_stage1_maintenance: crate::vmm::OwedStage1Maintenance::default(),
            owed_resume_invalidation: None,
        }
    }

    pub fn into_injected_task_only_backend(mut self) -> (V, V::Vcpu, Aarch64TaskRuntimeProjection) {
        self.settle_owed_resume_invalidation_or_log();
        let Self {
            vm,
            vcpu,
            page_tables,
            protections,
            process_asid,
            ..
        } = self;
        (
            vm,
            vcpu.into_inner(),
            Aarch64TaskRuntimeProjection {
                page_tables,
                protections,
                process_asid,
            },
        )
    }

    pub fn overlay_task_state_on_live_executor(
        &mut self,
        state: &GuestCpuState,
    ) -> Result<(), TrapError> {
        let GuestCpuState::Aarch64V1(state) = state else {
            return Err(TrapError::Hypervisor(
                "AArch64 persistent executor rejected non-AArch64 V1 state".to_owned(),
            ));
        };
        self.validate_task_metadata(state)?;
        let destination = self.vcpu.get_mut().snapshot()?;
        let restored = restore_aarch64_task_state(&destination, state)?;
        self.vcpu.get_mut().restore(&restored)?;
        self.discharge_owed_stage1_maintenance()?;
        self.vm.install_task_continuation_for_executor_switch(
            self.vcpu.get_mut(),
            state.syscall_continuation,
        )?;
        self.apply_task_metadata(state);
        self.validate_loaded_task_runtime_projection()?;
        Ok(())
    }

    /// Run the stage-1 maintenance this task's bring-up owed, on the live
    /// executor vCPU it just loaded onto, before its first instruction. The
    /// debt clears only once the maintenance completed.
    fn discharge_owed_stage1_maintenance(&mut self) -> Result<(), TrapError> {
        match self.owed_stage1_maintenance.discharge() {
            None => {}
            Some(crate::vmm::Stage1Maintenance::AllAsids) => {
                Self::run_el1_maintenance_on(self.vcpu.get_mut())?;
            }
            Some(crate::vmm::Stage1Maintenance::Asid(asid)) => {
                let root = self.vm.carrier_maintenance_root()?;
                Self::invalidate_asid_on_vcpu(self.vcpu.get_mut(), asid, root)?;
            }
        }
        self.owed_stage1_maintenance = crate::vmm::OwedStage1Maintenance::default();
        Ok(())
    }

    pub fn reaffirm_resident_task_state_on_live_executor(
        &mut self,
        state: &GuestCpuState,
        metadata: &Aarch64ResidentTaskMetadata,
    ) -> Result<(), TrapError> {
        let GuestCpuState::Aarch64V1(state) = state else {
            return Err(TrapError::Hypervisor(
                "AArch64 persistent executor rejected non-AArch64 V1 state".to_owned(),
            ));
        };
        self.validate_task_metadata(state)?;
        self.vm.install_task_continuation_for_executor_switch(
            self.vcpu.get_mut(),
            metadata.continuation,
        )?;
        self.pending_resume_pc = metadata.pending_resume_pc;
        self.last_syscall_nr = metadata.last_syscall_nr;
        self.last_syscall_orig_x0 = metadata.last_syscall_orig_x0;
        self.last_fault_esr = metadata.last_fault_esr;
        self.last_exit_class = metadata.last_exit_class;
        self.is_forked_child = metadata.is_forked_child;
        self.validate_loaded_task_runtime_projection()?;
        Ok(())
    }

    fn validate_loaded_task_runtime_projection(&self) -> Result<(), TrapError> {
        let Some(process_asid) = self.process_asid else {
            return Ok(());
        };
        const TTBR_ROOT_MASK: u64 = (1_u64 << 48) - 1;
        let ttbr = self.vcpu.borrow().get_sys_reg(SysReg::Ttbr0)?;
        let hardware_asid = (ttbr >> 48) as u16;
        if hardware_asid != process_asid {
            return Err(TrapError::Hypervisor(format!(
                "loaded HVPatch projection ASID {process_asid} does not match TTBR ASID {hardware_asid}"
            )));
        }
        let root = ttbr & TTBR_ROOT_MASK;
        if let Some(base) = self.page_tables.root_base()
            && base != root
        {
            return Err(TrapError::Hypervisor(format!(
                "loaded HVPatch page-table manager root 0x{base:x} does not match TTBR root 0x{root:x}"
            )));
        }
        Ok(())
    }

    pub fn snapshot_task_state_from_live_executor(&mut self) -> Result<GuestCpuState, TrapError> {
        require_migratable_fpsimd_authority(self.vm.fpsimd_enabled())?;
        self.settle_owed_resume_invalidation()?;
        let continuation = self
            .vm
            .take_task_continuation_for_executor_switch(self.vcpu.get_mut())?;
        let snapshot = self.vcpu.get_mut().snapshot()?;
        Ok(GuestCpuState::from_aarch64_v1(
            aarch64_task_state_from_snapshot(
                &snapshot,
                self.pending_resume_pc,
                self.last_syscall_nr,
                self.last_syscall_orig_x0,
                self.last_fault_esr,
                self.last_exit_class,
                self.is_forked_child,
                continuation,
                self.mm_generation,
                self.asid_generation,
            )?,
        ))
    }

    pub fn extract_resident_task_metadata_for_lazy_save(
        &mut self,
    ) -> Result<Aarch64ResidentTaskMetadata, TrapError> {
        let continuation = self
            .vm
            .take_task_continuation_for_executor_switch(self.vcpu.get_mut())?;
        Ok(Aarch64ResidentTaskMetadata {
            pending_resume_pc: self.pending_resume_pc,
            last_syscall_nr: self.last_syscall_nr,
            last_syscall_orig_x0: self.last_syscall_orig_x0,
            last_fault_esr: self.last_fault_esr,
            last_exit_class: self.last_exit_class,
            is_forked_child: self.is_forked_child,
            continuation,
            mm_generation: self.mm_generation,
            asid_generation: self.asid_generation,
        })
    }

    pub fn restore_persistent_executor_invariants(&mut self) -> Result<(), TrapError> {
        self.vm
            .restore_persistent_executor_invariants(self.vcpu.get_mut())
    }

    pub fn into_task_state_and_vcpu(mut self) -> (Aarch64TaskEngineState<V>, V::Vcpu) {
        self.settle_owed_resume_invalidation_or_log();
        let Self {
            vm,
            vcpu,
            pending_resume_pc,
            last_syscall_nr,
            last_syscall_orig_x0,
            last_fault_esr,
            last_exit_class,
            is_forked_child,
            process_asid,
            mm_generation,
            asid_generation,
            pending_guest_run_receipt_ns,
            page_tables,
            protections,
            pending_process_fork,
            pending_owner_fork,
            mut owed_stage1_maintenance,
            ..
        } = self;
        let mut vcpu = vcpu.into_inner();
        owed_stage1_maintenance.merge(vcpu.take_deferred_stage1_maintenance());
        (
            Aarch64TaskEngineState {
                vm,
                pending_resume_pc,
                last_syscall_nr,
                last_syscall_orig_x0,
                last_fault_esr,
                last_exit_class,
                is_forked_child,
                process_asid,
                mm_generation,
                asid_generation,
                pending_guest_run_receipt_ns,
                page_tables,
                protections,
                pending_process_fork,
                pending_owner_fork,
                owed_stage1_maintenance,
            },
            vcpu,
        )
    }

    pub fn from_task_state_and_vcpu(state: Aarch64TaskEngineState<V>, vcpu: V::Vcpu) -> Self {
        let Aarch64TaskEngineState {
            vm,
            pending_resume_pc,
            last_syscall_nr,
            last_syscall_orig_x0,
            last_fault_esr,
            last_exit_class,
            is_forked_child,
            process_asid,
            mm_generation,
            asid_generation,
            pending_guest_run_receipt_ns,
            page_tables,
            protections,
            pending_process_fork,
            pending_owner_fork,
            owed_stage1_maintenance,
        } = state;
        Self {
            vm,
            vcpu: std::cell::RefCell::new(vcpu),
            pending_resume_pc,
            last_syscall_nr,
            last_syscall_orig_x0,
            last_fault_esr,
            suspended_el1_sp: None,
            last_exit_class,
            is_forked_child,
            process_asid,
            mm_generation,
            asid_generation,
            pending_guest_run_receipt_ns,
            // A task adopted from a snapshot starts with no stale fault.
            stale_stage1_retry: (0, 0),
            last_fork_image_allocations: 0,
            page_tables,
            protections,
            pending_new_mapping: None,
            pending_process_fork,
            pending_owner_fork,
            exec_predecessor_shared: None,
            owed_stage1_maintenance,
            owed_resume_invalidation: None,
        }
    }
}

pub fn sibling_task_cpu_state(
    snapshot: &Aarch64VcpuSnapshot,
    mm_generation: u64,
    asid_generation: u64,
) -> Result<GuestCpuState, TrapError> {
    Ok(GuestCpuState::from_aarch64_v1(
        aarch64_task_state_from_snapshot(
            snapshot,
            None,
            None,
            0,
            0,
            0,
            false,
            None,
            mm_generation,
            asid_generation,
        )?,
    ))
}

/// Bootstrap the live stage-1 editor only when persistent exec left it absent.
///
/// Clone publication deliberately writes the parent TID while its vCPU can be
/// reclaimed. An already-present editor means the sparse backend can resolve an
/// existing mapping without reading TTBR0 or running maintenance on that parked
/// vCPU. A genuinely absent editor still takes the historical live-vCPU
/// bootstrap before any new sparse stage-1 publication.
fn ensure_sparse_page_table_editor(
    editor_present: bool,
    bootstrap: impl FnOnce() -> Result<(), MemoryError>,
) -> Result<(), MemoryError> {
    if editor_present { Ok(()) } else { bootstrap() }
}

struct OwnerForkTransaction<B> {
    pending: crate::fork::PendingOwnerFork<'static, Box<dyn Send>>,
    physical: Box<dyn crate::fork::PhysicalForkBuilder<B>>,
    parent_tables: crate::stage1_authority::OwnerForkTableArena,
}

struct ParentForkCowRollback {
    armed_ranges: Vec<crate::vmm::ForkCowRange>,
}

fn aarch64_task_state_from_snapshot(
    snapshot: &Aarch64VcpuSnapshot,
    pending_resume_pc: Option<u64>,
    last_syscall_nr: Option<u64>,
    last_syscall_orig_x0: u64,
    last_fault_esr: u64,
    last_exit_class: u64,
    is_forked_child: bool,
    syscall_continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
    mm_generation: u64,
    asid_generation: u64,
) -> Result<Aarch64TaskCpuStateV1, TrapError> {
    if mm_generation == 0 || asid_generation == 0 {
        return Err(TrapError::Hypervisor(
            "aarch64 snapshot has no exact MM/ASID generation binding".to_owned(),
        ));
    }
    let (pc, pstate) = core_resume_pair(pending_resume_pc, snapshot);
    Ok(Aarch64TaskCpuStateV1 {
        gprs: snapshot.gprs,
        pc,
        pstate,
        trap_pc: snapshot.pc,
        trap_pstate: snapshot.pstate,
        sp_el0: snapshot.sp_el0,
        elr_el1: snapshot.elr_el1,
        spsr_el1: snapshot.spsr_el1,
        ttbr0: snapshot.ttbr0,
        ttbr1: snapshot.ttbr1,
        tcr: snapshot.tcr,
        sctlr_el1: snapshot.sctlr,
        mair_el1: snapshot.mair,
        vbar_el1: snapshot.vbar,
        cpacr_el1: snapshot.cpacr,
        cntkctl_el1: snapshot.cntkctl_el1,
        tpidr_el1: snapshot.tpidr_el1,
        actlr_el1: snapshot.actlr_el1,
        tpidr_el0: snapshot.tpidr_el0,
        tpidrro_el0: snapshot.tpidrro_el0,
        contextidr_el1: snapshot.contextidr_el1,
        vregs: snapshot.vregs,
        fpsr: snapshot.fpsr,
        fpcr: snapshot.fpcr,
        pending_resume_pc,
        last_syscall_nr,
        last_syscall_orig_x0,
        last_fault_esr,
        last_exit_class,
        is_forked_child,
        syscall_continuation,
        mm_generation,
        asid_generation,
    })
}

#[derive(Clone, Debug)]
pub struct Aarch64ResidentTaskMetadata {
    pub pending_resume_pc: Option<u64>,
    pub last_syscall_nr: Option<u64>,
    pub last_syscall_orig_x0: u64,
    pub last_fault_esr: u64,
    pub last_exit_class: u64,
    pub is_forked_child: bool,
    pub continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
    pub mm_generation: u64,
    pub asid_generation: u64,
}

impl Aarch64ResidentTaskMetadata {
    pub fn snapshot_guest_cpu<V: Aarch64Vcpu>(&self, vcpu: &V) -> Result<GuestCpuState, TrapError> {
        let snapshot = vcpu.snapshot()?;
        Ok(GuestCpuState::from_aarch64_v1(
            aarch64_task_state_from_snapshot(
                &snapshot,
                self.pending_resume_pc,
                self.last_syscall_nr,
                self.last_syscall_orig_x0,
                self.last_fault_esr,
                self.last_exit_class,
                self.is_forked_child,
                self.continuation,
                self.mm_generation,
                self.asid_generation,
            )?,
        ))
    }
}

/// Overlay one migratable task image onto a destination executor snapshot.
/// Executor-local `SP_EL1`/mailbox state is retained from `destination`.
/// Before the overlay, the destination's neutral EL1 controls are validated;
/// the task's exact saved controls are then restored for guest execution.
pub fn restore_aarch64_task_state(
    destination: &Aarch64VcpuSnapshot,
    state: &Aarch64TaskCpuStateV1,
) -> Result<Aarch64VcpuSnapshot, TrapError> {
    let boot = carrick_hal::Aarch64GuestArch::bootstrap_sysregs();
    let expected_vbar = carrick_mem::memory::LINUX_EL1_VECTORS_BASE;
    // SCTLR_EL1 is compared through `is_bootstrap_sctlr_el1` rather than for
    // equality: `boot.sctlr_el1` lists the bits carrick PROGRAMS, while
    // `destination.sctlr` is what a vCPU reads BACK, which also carries the
    // architecture's RES1 bits. Those are different domains and raw equality
    // between them can never hold.
    if destination.vbar != expected_vbar
        || !carrick_mem::arch_sysregs::is_bootstrap_sctlr_el1(destination.sctlr)
        || destination.mair != boot.mair_el1
        || destination.cpacr != boot.cpacr_el1
    {
        return Err(TrapError::Hypervisor(format!(
            "aarch64 destination executor invariant mismatch: vbar={:#x}/{expected_vbar:#x} \
             sctlr={:#x}/{:#x} mair={:#x}/{:#x} cpacr={:#x}/{:#x}",
            destination.vbar,
            destination.sctlr,
            boot.sctlr_el1,
            destination.mair,
            boot.mair_el1,
            destination.cpacr,
            boot.cpacr_el1,
        )));
    }
    if state.mm_generation == 0 || state.asid_generation == 0 {
        return Err(TrapError::Hypervisor(
            "aarch64 restore rejected stale zero MM/ASID generation".to_owned(),
        ));
    }
    let mut restored = destination.clone();
    restored.gprs = state.gprs;
    restored.pc = state.trap_pc;
    restored.pstate = state.trap_pstate;
    restored.sp_el0 = state.sp_el0;
    restored.elr_el1 = state.elr_el1;
    restored.spsr_el1 = state.spsr_el1;
    restored.ttbr0 = state.ttbr0;
    restored.ttbr1 = state.ttbr1;
    restored.tcr = state.tcr;
    restored.sctlr = state.sctlr_el1;
    restored.mair = state.mair_el1;
    restored.vbar = state.vbar_el1;
    restored.cpacr = state.cpacr_el1;
    restored.cntkctl_el1 = state.cntkctl_el1;
    restored.tpidr_el1 = state.tpidr_el1;
    restored.actlr_el1 = state.actlr_el1;
    restored.tpidr_el0 = state.tpidr_el0;
    restored.tpidrro_el0 = state.tpidrro_el0;
    restored.contextidr_el1 = state.contextidr_el1;
    restored.vregs = state.vregs;
    restored.fpsr = state.fpsr;
    restored.fpcr = state.fpcr;
    Ok(restored)
}

fn seed_heap_unmapped(protections: &MemoryProtections) {
    if let Ok(heap_size) = usize::try_from(carrick_mem::memory::LINUX_HEAP_SIZE) {
        protections.set_unmapped(carrick_mem::memory::LINUX_HEAP_BASE, heap_size, true);
    }
}

/// Pure transition for replacing an engine's stage-1 page-table authority.
/// When `page_tables` is shared (`Arc::strong_count > 1`, e.g. after a
/// `CLONE_VM` / `vfork` before child's `execve`), the existing authority
/// belongs to the other threads/processes. Taking its manager or retiring
/// its extension arenas would strip the parent's live address space and
/// arena source.
#[cfg(test)]
pub(crate) fn replace_page_tables_authority(
    page_tables: &mut Stage1Authority,
    manager: Option<PageTableManager>,
    mut retire_old: impl FnMut(&mut PageTableManager) -> Result<(), TrapError>,
    mut bind_new: impl FnMut(Stage1Authority),
) -> Result<(), TrapError> {
    let new_authority = page_tables.replace_for_exec(|| Ok(manager), |old| retire_old(old))?;
    bind_new(new_authority.clone());
    *page_tables = new_authority;
    Ok(())
}

impl<V: Aarch64Vmm> Aarch64EngineCore<V> {
    fn validate_task_metadata(&self, state: &Aarch64TaskCpuStateV1) -> Result<(), TrapError> {
        if state.mm_generation != self.mm_generation
            || state.asid_generation != self.asid_generation
        {
            return Err(TrapError::Hypervisor(format!(
                "AArch64 restore generation mismatch: snapshot mm/asid={}/{} destination={}/{}",
                state.mm_generation,
                state.asid_generation,
                self.mm_generation,
                self.asid_generation
            )));
        }
        Ok(())
    }

    fn apply_task_metadata(&mut self, state: &Aarch64TaskCpuStateV1) {
        self.pending_resume_pc = state.pending_resume_pc;
        self.last_syscall_nr = state.last_syscall_nr;
        self.last_syscall_orig_x0 = state.last_syscall_orig_x0;
        self.last_fault_esr = state.last_fault_esr;
        self.last_exit_class = state.last_exit_class;
        self.is_forked_child = state.is_forked_child;
    }

    /// If `resume_pc` addresses an HvPatch syscall island's return branch,
    /// the original `svc #0` instruction's OWN address (not `+4`) it
    /// answers for; `None` when there is no pending syscall dispatch, or the
    /// bytes at `resume_pc-4`/`resume_pc` do not match an island's fixed
    /// shape (a live EL0 PC that never went through one).
    ///
    /// The ONE decode both Linux-visible-PC consumers reuse
    /// (`carrick_hal::aarch64::decode_hvpatch_island_origin`): a caller
    /// wanting a symbol to look up (`diagnostic_wait_registers`) uses this
    /// address directly; a caller wanting the Linux-visible resume PC of a
    /// thread blocked in that syscall (`aarch64_core_registers`, matching
    /// `ptrace`/a core file's convention of "the instruction after the
    /// svc") adds 4 itself.
    fn hvpatch_island_svc_addr(&self, resume_pc: u64) -> Option<u64> {
        if self.process_asid.is_none() || self.pending_resume_pc.is_none() {
            return None;
        }
        let start = resume_pc.checked_sub(4)?;
        let mut island_words = [0_u8; 8];
        self.read_into(start, &mut island_words).ok()?;
        let svc = u32::from_le_bytes(island_words[..4].try_into().ok()?);
        let return_branch = u32::from_le_bytes(island_words[4..].try_into().ok()?);
        carrick_hal::aarch64::decode_hvpatch_island_origin(resume_pc, svc, return_branch)
    }

    /// Build an engine around an already-constructed VM + vCPU (the backend's
    /// bring-up produces these). Mirrors `X86EngineCore::from_parts`: the
    /// tracking fields start cleared, and a freshly brought-up engine gets a
    /// fresh page-table editor and an empty PROT_NONE set. Siblings instead SHARE
    /// the spawning thread's `page_tables`/`protections` via the (later) sibling
    /// constructor.
    pub fn from_parts(mut vm: V, vcpu: V::Vcpu) -> Self {
        let page_tables = Stage1Authority::new();
        vm.bind_stage1_page_tables(page_tables.clone());
        // Adopt the backend's protections authority when it exposes one
        // (`exec_protections` is the backend's live task authority, not an
        // exec-only value). Creating a separate engine-side Arc here split the
        // per-mm protections into TWO instances: every marking write goes
        // through `self.vm.protections()` (the backend's), while the fork
        // process-spec and sibling specs snapshot/share the engine's. The
        // root process's engine mirror therefore stayed EMPTY forever, so a
        // forked child inherited no `mutable_shared_backing` ranges and every
        // anon-`MAP_SHARED` futex in a child fell to the process-private
        // table (sharedanonfutexfork / futexforkrequeue: all waiters
        // ETIMEDOUT while the parent's wake found zero). One mm, one
        // authority.
        let protections = vm.exec_protections().unwrap_or_else(|| {
            UserMemoryAuthority::from_legacy(Arc::new(MemoryProtections::default()))
        });
        if let Some(legacy) = protections.legacy() {
            seed_heap_unmapped(&legacy);
        }
        Self {
            vm,
            vcpu: std::cell::RefCell::new(vcpu),
            pending_resume_pc: None,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            stale_stage1_retry: (0, 0),
            last_fork_image_allocations: 0,
            last_fault_esr: 0,
            suspended_el1_sp: None,
            last_exit_class: 0,
            is_forked_child: false,
            process_asid: None,
            mm_generation: 1,
            asid_generation: 1,
            pending_guest_run_receipt_ns: 0,
            page_tables,
            protections,
            pending_new_mapping: None,
            pending_process_fork: None,
            pending_owner_fork: None,
            exec_predecessor_shared: None,
            owed_stage1_maintenance: crate::vmm::OwedStage1Maintenance::default(),
            owed_resume_invalidation: None,
        }
    }

    /// The backend VM half (stage-2 mapping, fork/execve rebuild, sibling spawn).
    pub fn vm(&self) -> &V {
        &self.vm
    }

    /// Mutable access to the backend VM half.
    pub fn vm_mut(&mut self) -> &mut V {
        &mut self.vm
    }

    /// The (one) vCPU for this process thread.
    pub fn vcpu(&self) -> std::cell::Ref<'_, V::Vcpu> {
        self.vcpu.borrow()
    }

    /// Mutable access to the vCPU (the trap-surfacing primitive runs through it).
    pub fn vcpu_mut(&mut self) -> &mut V::Vcpu {
        self.vcpu.get_mut()
    }

    /// The pending syscall resume PC (`Some` between `next_syscall` and
    /// `complete_syscall`).
    pub fn pending_resume_pc(&self) -> Option<u64> {
        self.pending_resume_pc
    }

    /// The Linux syscall number (x8) of the most recent trapped `svc` (the
    /// SA_RESTART input).
    pub fn last_syscall_nr(&self) -> Option<u64> {
        self.last_syscall_nr
    }

    /// The pre-syscall x0 of the most recent trapped `svc` (the SA_RESTART rewind
    /// input).
    pub fn last_syscall_orig_x0(&self) -> u64 {
        self.last_syscall_orig_x0
    }

    /// The `ESR_EL1` of the most recent EL0 synchronous fault.
    pub fn last_fault_esr(&self) -> u64 {
        self.last_fault_esr
    }

    /// The EC of the most recent exit (the `svc`-vs-`hvc` trap-surface
    /// discriminator).
    pub fn last_exit_class(&self) -> u64 {
        self.last_exit_class
    }

    /// Whether this engine is the child side of a guest `fork(2)`.
    pub fn is_forked_child(&self) -> bool {
        self.is_forked_child
    }

    /// The shared stage-1 page-table authority handle.
    pub fn page_tables(&self) -> &Stage1Authority {
        &self.page_tables
    }

    /// Replace this mm's stage-1 manager without splitting the engine/backend
    /// authority. The HVPatch backend resolves permission faults itself, so
    /// every fresh authority must be rebound before the stopped vCPU can resume.
    ///
    /// The sharing decision is governed strictly by the authority's own
    /// `vfork_shares` count. Returns `true` if the predecessor authority was
    /// shared (and therefore preserved for other siblings/parent).
    fn replace_page_tables(
        &mut self,
        manager: Option<PageTableManager>,
    ) -> Result<bool, TrapError> {
        let (new_authority, was_shared) = self.page_tables.replace_for_exec_internal(
            || Ok(manager),
            |old| self.vm.retire_stage1_extension_arenas(old),
        )?;
        self.vm.bind_stage1_page_tables(new_authority.clone());
        self.page_tables = new_authority;
        Ok(was_shared)
    }

    /// The shared PROT_NONE EFAULT gate (cloned across `CLONE_THREAD` siblings,
    /// COW'd on fork).
    pub fn protections(&self) -> &UserMemoryAuthority {
        &self.protections
    }

    /// Like [`from_parts`](Self::from_parts) but ADOPTS the spawning thread's
    /// page-table authority + PROT_NONE bookkeeping — used to make a
    /// `clone(CLONE_THREAD)` sibling SHARE its parent's stage-1 authority (same VM,
    /// same backing) and PROT_NONE set. On KVM the PROT_NONE set itself lives in
    /// the backend `GuestRam` (shared via `from_shared_windows`), so this `Arc`
    /// is the engine-side mirror; the page-table authority is the load-bearing share.
    pub fn from_parts_with_shared(
        mut vm: V,
        vcpu: V::Vcpu,
        page_tables: Stage1Authority,
        protections: UserMemoryAuthority,
    ) -> Self {
        vm.bind_stage1_page_tables(page_tables.clone());
        Self {
            vm,
            vcpu: std::cell::RefCell::new(vcpu),
            pending_resume_pc: None,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            stale_stage1_retry: (0, 0),
            last_fork_image_allocations: 0,
            last_fault_esr: 0,
            suspended_el1_sp: None,
            last_exit_class: 0,
            is_forked_child: false,
            process_asid: None,
            mm_generation: 1,
            asid_generation: 1,
            pending_guest_run_receipt_ns: 0,
            page_tables,
            protections,
            pending_new_mapping: None,
            pending_process_fork: None,
            pending_owner_fork: None,
            exec_predecessor_shared: None,
            owed_stage1_maintenance: crate::vmm::OwedStage1Maintenance::default(),
            owed_resume_invalidation: None,
        }
    }

    /// Read `len` bytes of live guest memory at guest-physical `gpa` (e.g. a
    /// `write(2)` buffer the guest passed). Backed by the same host RAM the vCPU
    /// sees, so guest writes are visible. (The standalone run-elf loop uses this.)
    pub fn read_guest(&self, gpa: Gpa, len: usize) -> Result<Vec<u8>, TrapError> {
        self.vm.read_gpa(gpa.raw(), len)
    }

    // ── test / bring-up setters (used by the backend crates' unit tests) ──
    // These poke the same engine-owned tracking fields the trap loop maintains, so
    // a per-VMM `#[cfg(test)]` (which lives in another crate and cannot reach the
    // private fields) can assert the fork/execve/inject behaviour. They are plain
    // `pub` (not `#[cfg(test)]`) because the consumers are cross-crate tests, so
    // they are not dead code.

    /// Set the forked-child marker (mirrors what the shared `fork()` does on the
    /// child side). For cross-crate tests of `execve` is_forked_child preservation.
    #[doc(hidden)]
    pub fn set_is_forked_child_for_test(&mut self, v: bool) {
        self.is_forked_child = v;
    }

    /// Set the most-recent-fault ESR stash (the `inject_signal` sigframe input).
    #[doc(hidden)]
    pub fn set_last_fault_esr_for_test(&mut self, v: u64) {
        self.last_fault_esr = v;
    }

    /// Set the SA_RESTART syscall-number / orig-x0 stash.
    #[doc(hidden)]
    pub fn set_last_syscall_for_test(&mut self, nr: Option<u64>, orig_x0: u64) {
        self.last_syscall_nr = nr;
        self.last_syscall_orig_x0 = orig_x0;
    }

    // ── stage-1 page-table edit core (the locked EDIT primitive) ──

    /// Edit the live stage-1 page tables (the guest's own translation tables at
    /// `LINUX_PAGE_TABLES_BASE`) under the shared manager lock and replay the
    /// changed descriptors into the guest page-table backing — the locked EDIT
    /// CORE, WITHOUT a TLB flush. Builds the `PageTableManager` lazily from the
    /// live backing on first use (the boot image already wrote
    /// `stage1_identity_page_tables` there). Returns whether the edit CHANGED any
    /// descriptor (so the caller can skip a pointless flush on a no-op edit).
    /// Callers that publish a guest-visible translation route through
    /// [`Self::pt_edit_and_flush`], which runs [`Self::run_el1_maintenance`]
    /// afterwards so a cached invalid walk or stale leaf cannot survive the
    /// publication.
    /// Build a stage-1 manager from the live guest tables at the current
    /// TTBR0 root — the same construction `pt_edit_locked` performs lazily on
    /// the first edit. Fails (rather than guessing) when the root or its
    /// backing is not readable yet.
    fn build_page_tables_manager_from_live(&self) -> Result<PageTableManager, MemoryError> {
        const TTBR_ROOT_MASK: u64 = (1_u64 << 48) - 1;
        let pt_base = self
            .vcpu
            .borrow_mut()
            .get_sys_reg(SysReg::Ttbr0)
            .map_err(|error| MemoryError::HostMap(format!("read TTBR0_EL1: {error}")))?
            & TTBR_ROOT_MASK;
        if pt_base == 0 {
            return Err(MemoryError::HostMap(
                "stage-1 root not programmed".to_string(),
            ));
        }
        let size = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize;
        let host = self
            .vm
            .host_ptr(pt_base, size)
            .ok_or_else(|| MemoryError::HostMap("read live page tables".to_string()))?;
        // SAFETY: `host_ptr` resolved the complete live page-table mapping at
        // `pt_base` for `size` bytes, and the engine retains that mapping for
        // this call. The manager copies only the occupied table prefix; the
        // borrow ends before this returns.
        let live = unsafe { std::slice::from_raw_parts(host.cast_const(), size) };
        use carrick_hal::PageTableCodec as _;
        Ok(
            <<Self as ThreadedEngine>::Arch as carrick_hal::GuestArch>::Mmu::manager_from_live(
                live, pt_base,
            ),
        )
    }

    /// Ensure the software stage-1 manager exists, built from the live tables,
    /// WITHOUT editing. Valid on every lane: a guest-owned MM can legitimately
    /// have an absent manager (persistent exec drops it), and the refusing live
    /// edit funnel is the wrong door for a load that stores nothing.
    fn load_live_stage1_manager(&self) -> Result<(), MemoryError> {
        if self.page_tables.is_present() {
            return Ok(());
        }
        let manager = self.build_page_tables_manager_from_live()?;
        self.page_tables
            .load_manager_if_absent(|| Ok::<_, MemoryError>(manager))
            .map(|_installed| ())
    }

    fn pt_edit_locked(
        &mut self,
        edit: impl FnOnce(&mut Stage1Editor<'_>) -> Result<PageTableApplyOutcome, PageTableError>,
    ) -> Result<PageTableApplyOutcome, MemoryError> {
        self.pt_edit_locked_after_adopting(None, edit)
    }

    fn pt_edit_locked_after_adopting(
        &mut self,
        live_range: Option<(u64, usize)>,
        edit: impl FnOnce(&mut Stage1Editor<'_>) -> Result<PageTableApplyOutcome, PageTableError>,
    ) -> Result<PageTableApplyOutcome, MemoryError> {
        const TTBR_ROOT_MASK: u64 = (1_u64 << 48) - 1;
        let pt_base = self
            .vcpu
            .borrow_mut()
            .get_sys_reg(SysReg::Ttbr0)
            .map_err(|error| MemoryError::HostMap(format!("read TTBR0_EL1: {error}")))?
            & TTBR_ROOT_MASK;
        // The single live edit funnel. On the guest-owned lane EL1 is the only
        // live descriptor writer: refuse before staging anything, so no dirty
        // host state can outlive the refusal.
        if self.page_tables.live_descriptor_owner() == LiveDescriptorOwner::Guest {
            return Err(guest_owned_live_edit_error());
        }
        let size = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize;
        let host = self
            .vm
            .host_ptr(pt_base, size)
            .ok_or_else(|| MemoryError::HostMap("page-table region not mapped".to_string()))?;
        let page_tables = self.page_tables.clone();
        let engines = page_tables.engines();
        let unsafe_to_coalesce = page_tables.is_shared_with_vfork_child() || engines > 1;
        let stage1_exclusive = carrick_hal::stage1_exclusive::current_thread_edits_exclusively();

        let live_mgr = if page_tables.is_none() {
            Some(self.build_page_tables_manager_from_live()?)
        } else {
            None
        };
        let mut outcome = PageTableApplyOutcome::default();
        let edit_res: Result<(), MemoryError> = page_tables.edit(
            || live_mgr.ok_or_else(|| MemoryError::HostMap("stage-1 manager absent".to_string())),
            |editor| {
                if editor.base() != pt_base {
                    return Err(MemoryError::HostMap(format!(
                        "page-table manager root 0x{:x} does not match TTBR0 root 0x{pt_base:x}",
                        editor.base()
                    )));
                }
                editor.set_multi_vcpu(unsafe_to_coalesce);
                editor.set_stage1_exclusive(stage1_exclusive);
                if let Some((address, len)) = live_range {
                    let resolver = EngineHostResolver {
                        vm: &self.vm,
                        pt_base,
                        host,
                        size,
                    };
                    unsafe {
                        editor
                            .manager
                            .adopt_live_tables_for_range(&resolver, address, len)
                    }
                    .map_err(page_table_sync_error_to_memory_error)?;
                }
                match edit(editor) {
                    Ok(res) => {
                        outcome = res;
                        if outcome.changed {
                            self.vm
                                .publish_stage1_extension_arenas(editor.manager)
                                .map_err(|error| {
                                    MemoryError::HostMap(format!(
                                        "publish stage-1 extension arenas failed: {error:?}"
                                    ))
                                })?;
                            // SAFETY: `host` backs the live page-table region for the whole process
                            // lifetime; the manager writes only 8-byte-aligned descriptor slots
                            // within `[host, host + size)`.
                            let resolver = EngineHostResolver {
                                vm: &self.vm,
                                pt_base,
                                host,
                                size,
                            };
                            unsafe {
                                editor.sync_to_host(resolver)
                            }
                            .map_err(page_table_sync_error_to_memory_error)?;
                            editor.manager.record_populated_prefixes(|base, prefix| {
                                self.vm.record_stage1_populated_prefix(base, prefix);
                            });
                        }
                        Ok(())
                    }
                    Err(PageTableError::OutOfTables) => {
                        let (in_use, free, capacity, arenas) = editor.pool_stats();
                        let source = editor.has_arena_source();
                        let pmr = stage1_exclusive;
                        Err(MemoryError::HostMap(format!(
                            "stage-1 page-table pool exhausted \
                             (in_use={in_use} free={free} capacity={capacity} arenas={arenas} source={source} \
                             reclaim_disabled={unsafe_to_coalesce} engines={engines} pmr={pmr})"
                        )))
                    }
                    // An output in the in-kernel GIC's window, or a leaf in
                    // the Carrick-owned EL1 COW copy window, is an address no
                    // guest edit may reach, like a bad address.
                    Err(
                        error @ (PageTableError::BadAddress
                        | PageTableError::GicWindowOutput
                        | PageTableError::CarrickOwnedWindow),
                    ) => {
                        // The refusal's kind is lost in the lowered error:
                        // name it for `guest-internal-write-fault` readers.
                        carrick_observability::probes::guest_internal_write_fault(
                            0,
                            0,
                            8,
                            &format!("stage-1 edit refused: {error:?}"),
                        );
                        Err(MemoryError::OutOfBounds {
                            address: 0,
                            length: 0,
                        })
                    }
                    Err(PageTableError::MissingArenaSource) => {
                        Err(MemoryError::HostMap(
                            "stage-1 page-table manager has no arena source".to_owned(),
                        ))
                    }
                    Err(PageTableError::ConflictingArenaSource) => {
                        Err(MemoryError::HostMap(
                            "stage-1 page-table manager conflicting arena source".to_owned(),
                        ))
                    }
                    Err(PageTableError::UnresolvedArena(base)) => {
                        Err(MemoryError::HostMap(format!(
                            "stage-1 page-table manager unresolved arena 0x{base:x}",
                        )))
                    }
                    Err(PageTableError::MetadataAllocation) => {
                        Err(MemoryError::MetadataAllocation)
                    }
                    Err(PageTableError::GuestOwnsLiveDescriptors) => {
                        Err(guest_owned_live_edit_error())
                    }
                }
            },
        );
        edit_res?;
        Ok(outcome)
    }

    /// Edit the stage-1 tables WITHOUT a TLB flush. Reserved for changes that do
    /// not publish a new guest-visible translation.
    fn pt_edit(
        &mut self,
        edit: impl FnOnce(&mut Stage1Editor<'_>) -> Result<PageTableApplyOutcome, PageTableError>,
    ) -> Result<(), MemoryError> {
        self.pt_edit_locked(edit).map(|_outcome| ())
    }

    /// Edit the stage-1 tables AND, if any descriptor changed in a way that
    /// requires a TLB flush, flush the stale stage-1 TLB by running the
    /// EL1-maintenance trampoline on this vCPU ([`Self::run_el1_maintenance`]).
    ///
    /// Transitions that only validate previously-invalid leaves require NO TLB
    /// maintenance on AArch64 (invalid translations are never cached in TLBs by
    /// hardware MMUs). Coalescing, splitting, or changing already-valid leaf
    /// permissions/output addresses set `flush_required` and invoke TLBI.
    ///
    /// Cross-vCPU: the generic threaded loop's Pause-Modify-Resume
    /// (`vcpu_loop.rs` `pt_pause`) has already PAUSED every sibling vCPU out of
    /// guest before this edit runs, and the maintenance trampoline's
    /// `tlbi vmalle1is` is INNER-SHAREABLE, so it broadcasts the invalidation to
    /// the paused siblings' stage-1 TLBs too — multi-threaded correctness comes
    /// from PMR (pause) + the inner-shareable flush, both reused here, not
    /// re-invented.
    fn pt_edit_and_flush(
        &mut self,
        edit: impl FnOnce(&mut Stage1Editor<'_>) -> Result<PageTableApplyOutcome, PageTableError>,
    ) -> Result<(), MemoryError> {
        let outcome = self.pt_edit_locked(edit)?;
        if !outcome.flush_required {
            // Nothing changed that requires a TLB flush: no previously-valid leaf
            // was modified, split, or coalesced, so there is no stale TLB entry
            // to invalidate.
            return Ok(());
        }
        self.invalidate_after_edit()
            .map_err(|e| MemoryError::HostMap(format!("stage-1 TLBI failed: {e}")))
    }

    fn pt_edit_and_flush_after_adopting(
        &mut self,
        address: u64,
        len: usize,
        edit: impl FnOnce(&mut Stage1Editor<'_>) -> Result<PageTableApplyOutcome, PageTableError>,
    ) -> Result<(), MemoryError> {
        let outcome = self.pt_edit_locked_after_adopting(Some((address, len)), edit)?;
        if !outcome.flush_required {
            return Ok(());
        }
        self.invalidate_after_edit()
            .map_err(|e| MemoryError::HostMap(format!("stage-1 TLBI failed: {e}")))
    }

    /// Apply shared stage-1 range rules on either lane, over the adopted
    /// range `adopt`. Host lane: the software editor applies each rule with
    /// `apply_rule` and one TLBI follows when a valid leaf changed. Guest
    /// lane: each rule is one EL1 `DescriptorOp::Terminal` transaction,
    /// prepared against the live graph just before submission and applied
    /// and settled on this vCPU, where EL1 performs the invalidation. The
    /// plan's spans are disjoint, so a refusal part-way leaves every page at
    /// either its old or its final state.
    fn apply_stage1_rules(
        &mut self,
        adopt: (u64, usize),
        rules: &[(u64, usize, TerminalRule)],
    ) -> Result<(), MemoryError> {
        if self.page_tables.live_descriptor_owner() != LiveDescriptorOwner::Guest {
            return self.pt_edit_and_flush_after_adopting(adopt.0, adopt.1, |editor| {
                editor.apply_terminal_rules(rules)
            });
        }
        let failure = |what: String| MemoryError::HostMap(format!("guest stage-1 rule: {what}"));
        let mm = std::num::NonZeroU64::new(self.mm_generation)
            .ok_or_else(|| failure("no MM identity".to_owned()))?;
        let slots = carrick_el1_abi::descriptor_txn_slots_host()
            .ok_or_else(|| failure("no descriptor slots".to_owned()))?;
        self.load_live_stage1_manager()?;
        let tables = self.page_tables.clone();
        // Like the host lane's single TLBI after every rule: the plan's
        // required invalidations collapse into one after its last
        // transaction (break-before-make ones still run inside each).
        let required = std::cell::Cell::new(false);
        let mut applied = Ok(());
        for &(va, len, rule) in rules {
            let txn = tables
                .with_manager(|manager| manager.terminal_op(va, len as u64, rule))
                .ok_or_else(|| failure("stage-1 image absent".to_owned()))
                .and_then(|op| {
                    tables
                        .prepare_guest_descriptor_txn(mm, op)
                        .map_err(|error| failure(format!("prepare at 0x{va:x}: {error:?}")))
                });
            applied = txn.and_then(|txn| {
                let mut services = self.descriptor_services();
                services.required_invalidation = Some(&required);
                crate::descriptor_drain::apply_guest_descriptor_txns_now(
                    &mut services,
                    slots,
                    &[txn],
                )
                .map(|_| ())
                .map_err(|error| failure(format!("apply at 0x{va:x}: {error}")))
            });
            if applied.is_err() {
                break;
            }
        }
        if required.get() {
            self.invalidate_after_edit()
                .map_err(|error| failure(format!("stage-1 TLBI failed: {error}")))?;
        }
        applied
    }

    /// munmap retirement of `[va, va+len)` on either lane. `reclaim` also
    /// frees every spare sub-table the retirement empties (the host editor's
    /// `unmap_aliased`); otherwise tables stay for in-place reuse (the host
    /// editor's `invalidate`). Guest lane: EL1 `Terminal` retirements whose
    /// receipts return the unlinked tables to the pool; a span that would
    /// empty more tables than one receipt carries is split at a 2 MiB-aligned
    /// midpoint and submitted in pieces, each taking its pages straight to
    /// their final state.
    fn retire_stage1_range(
        &mut self,
        va: u64,
        len: usize,
        reclaim: bool,
    ) -> Result<(), MemoryError> {
        if self.page_tables.live_descriptor_owner() != LiveDescriptorOwner::Guest {
            return self.pt_edit_and_flush_after_adopting(va, len, |editor| {
                if reclaim {
                    editor.unmap_aliased(va, len)
                } else {
                    editor.invalidate(va, len)
                }
            });
        }
        if !reclaim {
            return self
                .apply_stage1_rules((va, len), &[(va, len, TerminalRule::pt(PtOp::Retire))]);
        }
        let failure = |what: String| MemoryError::HostMap(format!("guest stage-1 unmap: {what}"));
        let mm = std::num::NonZeroU64::new(self.mm_generation)
            .ok_or_else(|| failure("no MM identity".to_owned()))?;
        let slots = carrick_el1_abi::descriptor_txn_slots_host()
            .ok_or_else(|| failure("no descriptor slots".to_owned()))?;
        self.load_live_stage1_manager()?;
        let tables = self.page_tables.clone();
        // One required invalidation after the last piece, as in
        // `apply_stage1_rules`.
        let required = std::cell::Cell::new(false);
        const TWO_MIB: u64 = 2 << 20;
        let mut retire = || -> Result<(), MemoryError> {
            let mut pending = vec![(va, len as u64)];
            while let Some((start, span)) = pending.pop() {
                let op = tables
                    .with_manager(|manager| manager.unmap_aliased_op(start, span))
                    .ok_or_else(|| failure("stage-1 image absent".to_owned()))?;
                let txn = match tables.prepare_guest_descriptor_txn(mm, op) {
                    Ok(txn) => txn,
                    Err(carrick_mmu_core::aarch64::GuestTxnPrepareError::Refused(
                        carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal::ReclaimCapacity,
                    )) => {
                        let mid = (start + span / 2) & !(TWO_MIB - 1);
                        if mid <= start || mid >= start + span {
                            return Err(failure(format!(
                                "0x{start:x}+0x{span:x} empties more tables than one receipt carries"
                            )));
                        }
                        // Upper half first so the lower half is submitted first.
                        pending.push((mid, start + span - mid));
                        pending.push((start, mid - start));
                        continue;
                    }
                    Err(error) => {
                        return Err(failure(format!("prepare at 0x{start:x}: {error:?}")));
                    }
                };
                let mut services = self.descriptor_services();
                services.required_invalidation = Some(&required);
                crate::descriptor_drain::apply_guest_descriptor_txns_now(
                    &mut services,
                    slots,
                    &[txn],
                )
                .map_err(|error| failure(format!("apply at 0x{start:x}: {error}")))?;
            }
            Ok(())
        };
        let retired = retire();
        if required.get() {
            self.invalidate_after_edit()
                .map_err(|error| failure(format!("stage-1 TLBI failed: {error}")))?;
        }
        retired
    }

    /// Revert uncommitted page table edits from the undo journal to shadow and host memory,
    /// and flush stale translations from the stage-1 TLB.
    fn pt_rollback_undo_and_flush(&mut self) -> Result<(), MemoryError> {
        const TTBR_ROOT_MASK: u64 = (1_u64 << 48) - 1;
        let pt_base = self
            .vcpu
            .borrow_mut()
            .get_sys_reg(SysReg::Ttbr0)
            .map_err(|error| MemoryError::HostMap(format!("read TTBR0_EL1: {error}")))?
            & TTBR_ROOT_MASK;
        let size = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize;
        let host = self
            .vm
            .host_ptr(pt_base, size)
            .ok_or_else(|| MemoryError::HostMap("page-table region not mapped".to_string()))?;
        let resolver = EngineHostResolver {
            vm: &self.vm,
            pt_base,
            host,
            size,
        };
        unsafe {
            self.page_tables
                .rollback_undo(resolver)
                .map_err(page_table_rollback_error_to_memory_error)?;
        }
        self.run_stage1_maintenance()
            .map_err(|e| MemoryError::HostMap(format!("stage-1 TLBI failed: {e}")))
    }

    /// Diagnostic walk of the authoritative host backing after publication.
    /// Unlike [`PageTableManager::debug_walk`], this reads the descriptors the
    /// hardware MMU sees. Kept off the syscall hot path; high-VA alias installs
    /// use it to fire the existing `pt-alias-walk` USDT receipt.
    fn live_pt_debug_walk(&self, va: u64) -> Result<[u64; 4], MemoryError> {
        let (pt_base, host) = self.live_pt_root()?;
        self.live_pt_debug_walk_with_host(va, pt_base, host)
    }

    /// The live stage-1 root this vCPU runs on (`TTBR0_EL1`) and the host
    /// mapping of its page-table region.
    fn live_pt_root(&self) -> Result<(u64, *mut u8), MemoryError> {
        const TTBR_ROOT_MASK: u64 = (1_u64 << 48) - 1;
        let pt_base = self
            .vcpu
            .borrow_mut()
            .get_sys_reg(SysReg::Ttbr0)
            .map_err(|error| MemoryError::HostMap(format!("read TTBR0_EL1: {error}")))?
            & TTBR_ROOT_MASK;
        let size = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize;
        let host = self
            .vm
            .host_ptr(pt_base, size)
            .ok_or_else(|| MemoryError::HostMap("page-table region not mapped".to_owned()))?;
        Ok((pt_base, host))
    }

    fn live_pt_debug_walk_with_host(
        &self,
        va: u64,
        pt_base: u64,
        host: *mut u8,
    ) -> Result<[u64; 4], MemoryError> {
        let size = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize;
        self.page_tables
            .with_manager(|manager| {
                if manager.base() != pt_base {
                    return Err(MemoryError::HostMap(format!(
                        "page-table manager root 0x{:x} does not match TTBR0 root 0x{pt_base:x}",
                        manager.base()
                    )));
                }
                // SAFETY: `host_ptr` resolved the complete live page-table mapping at
                // `pt_base`, and the manager's base/length were checked above.
                let resolver = EngineHostResolver {
                    vm: &self.vm,
                    pt_base,
                    host,
                    size,
                };
                unsafe { manager.debug_walk_host(resolver, va) }.map_err(|error| {
                    MemoryError::HostMap(format!(
                        "debug walk stage-1 page tables failed: {error:?}"
                    ))
                })
            })
            .ok_or_else(|| {
                MemoryError::HostMap("page-table manager unexpectedly absent".to_owned())
            })?
    }

    /// Flush the stale stage-1 TLB after a host page-descriptor edit by running the
    /// EL1 stage-1 maintenance trampoline on THIS vCPU. The trampoline
    /// (`dsb sy; tlbi vmalle1is; dsb sy; isb`) lives at
    /// [`carrick_mem::memory::LINUX_EL1_MAINT_BASE`] and ends in a backend
    /// completion vehicle — KVM's MMIO store to `MAINT_SENTINEL_GPA` (surfaced as
    /// `Aarch64Exit::MaintenanceDone`), in place of HVF's `hvc #1`.
    ///
    /// The vCPU is parked at a syscall (or fault) trap when this runs, so it saves
    /// and restores the interrupted EL1-vector state — PC, PSTATE (CPSR), ELR_EL1,
    /// SPSR_EL1 — AND the two GPRs the trampoline clobbers (x8 the store value, x9
    /// the sentinel-address scratch). With those restored, the in-flight syscall
    /// resumes exactly as before. Mirrors HVF's `run_el1_maintenance`.
    fn run_el1_maintenance_on(vcpu: &mut V::Vcpu) -> Result<(), TrapError> {
        if vcpu.defer_stage1_maintenance(crate::vmm::Stage1Maintenance::AllAsids) {
            return Ok(());
        }
        // M[3:0]=0b0101 EL1h (SP_EL1) + DAIF masked, PAN(bit22)=0 — the SAME PSTATE
        // boot uses to run the EL0-entry trampoline at EL1 (program_sysregs sets
        // `PSTATE_M_EL1H | DAIF_MASKED`). The maintenance trampoline issues no
        // EL0-accessible store under PAN, so PAN=0 is not strictly required, but
        // matching boot keeps the EL1 entry conditions identical.
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;

        let g = |vcpu: &V::Vcpu, r: Reg| vcpu.get_reg(r);
        // Save the interrupted EL1-vector state + the two scratch GPRs the
        // trampoline clobbers.
        let saved_pc = g(vcpu, Reg::Pc)?;
        let saved_pstate = g(vcpu, Reg::Pstate)?;
        let saved_elr = g(vcpu, Reg::ElrEl1)?;
        let saved_spsr = g(vcpu, Reg::SpsrEl1)?;
        let saved_x8 = g(vcpu, Reg::X(8))?;
        let saved_x9 = g(vcpu, Reg::X(9))?;

        let s = |vcpu: &mut V::Vcpu, r: Reg, v: u64| vcpu.set_reg(r, v);
        s(vcpu, Reg::Pc, carrick_mem::memory::LINUX_EL1_MAINT_BASE)?;
        s(vcpu, Reg::Pstate, AARCH64_PSTATE_EL1H_DAIF_MASKED)?;

        // Run the trampoline to its completion vehicle. A cross-thread kick
        // (`Aarch64Exit::Kicked`) can land mid-flush; the trampoline is tiny and
        // idempotent, so just re-enter it. Any OTHER exit is ambiguous (we cannot
        // trust guest memory visibility) — surface it. (No guest_cpu accounting:
        // this is a host-driven flush, not guest execution time.)
        let result = loop {
            match vcpu.run() {
                Ok(Aarch64Exit::MaintenanceDone) => {
                    if maint_debug() {
                        eprintln!("[MAINTDBG tid={}] stage-1 TLBI completed", debug_tid());
                    }
                    break Ok(());
                }
                Ok(Aarch64Exit::Kicked) => continue,
                Ok(other) => {
                    break Err(TrapError::UnexpectedExit {
                        reason: format!(
                            "{} during EL1 stage-1 maintenance",
                            maintenance_exit_detail(&other)
                        ),
                    });
                }
                Err(e) => break Err(e),
            }
        };

        // Restore the interrupted EL1-vector state + scratch GPRs on EVERY path so
        // the parked syscall resumes unperturbed even if the flush errored.
        s(vcpu, Reg::Pc, saved_pc)?;
        s(vcpu, Reg::Pstate, saved_pstate)?;
        s(vcpu, Reg::ElrEl1, saved_elr)?;
        s(vcpu, Reg::SpsrEl1, saved_spsr)?;
        s(vcpu, Reg::X(8), saved_x8)?;
        s(vcpu, Reg::X(9), saved_x9)?;
        result
    }

    /// Invalidate one numeric ASID on this exact owner-thread vCPU. The strong
    /// software generation is authenticated by the runtime command; hardware
    /// consumes only the architectural 16-bit ASID operand in `x0[63:48]`.
    pub fn invalidate_asid_on_vcpu(
        vcpu: &mut V::Vcpu,
        asid: u16,
        carrier_maintenance_root: carrick_mem::memory::CarrierMaintenanceRoot,
    ) -> Result<(), TrapError> {
        if asid == 0 {
            return Err(TrapError::Hypervisor(
                "refusing to invalidate reserved ASID zero".to_owned(),
            ));
        }
        if vcpu.defer_stage1_maintenance(crate::vmm::Stage1Maintenance::Asid(asid)) {
            return Ok(());
        }
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
        let saved_pc = vcpu.get_reg(Reg::Pc).map_err(|e| {
            TrapError::Hypervisor(format!("save PC for scoped EL1 ASID maintenance: {e}"))
        })?;
        let saved_pstate = vcpu.get_reg(Reg::Pstate).map_err(|e| {
            TrapError::Hypervisor(format!("save PSTATE for scoped EL1 ASID maintenance: {e}"))
        })?;
        let saved_elr = vcpu.get_reg(Reg::ElrEl1).map_err(|e| {
            TrapError::Hypervisor(format!("save ELR_EL1 for scoped EL1 ASID maintenance: {e}"))
        })?;
        let saved_spsr = vcpu.get_reg(Reg::SpsrEl1).map_err(|e| {
            TrapError::Hypervisor(format!(
                "save SPSR_EL1 for scoped EL1 ASID maintenance: {e}"
            ))
        })?;
        let saved_x0 = vcpu.get_reg(Reg::X(0)).map_err(|e| {
            TrapError::Hypervisor(format!("save X0 for scoped EL1 ASID maintenance: {e}"))
        })?;
        let saved_ttbr0 = vcpu.get_sys_reg(carrick_hal::SysReg::Ttbr0).map_err(|e| {
            TrapError::Hypervisor(format!("save TTBR0 for scoped EL1 ASID maintenance: {e}"))
        })?;

        let maint_ttbr0 = carrier_maintenance_root.raw();
        vcpu.set_sys_reg(carrick_hal::SysReg::Ttbr0, maint_ttbr0)
            .map_err(|e| {
                TrapError::Hypervisor(format!(
                    "install carrier root into TTBR0 for scoped EL1 ASID maintenance: {e}"
                ))
            })?;
        vcpu.set_reg(Reg::X(0), u64::from(asid) << 48)
            .map_err(|e| {
                TrapError::Hypervisor(format!("set X0 for scoped EL1 ASID maintenance: {e}"))
            })?;
        vcpu.set_reg(Reg::Pc, HVPATCH_EL1_ASID_MAINT_BASE)
            .map_err(|e| {
                TrapError::Hypervisor(format!("set PC for scoped EL1 ASID maintenance: {e}"))
            })?;
        vcpu.set_reg(Reg::Pstate, AARCH64_PSTATE_EL1H_DAIF_MASKED)
            .map_err(|e| {
                TrapError::Hypervisor(format!("set PSTATE for scoped EL1 ASID maintenance: {e}"))
            })?;

        // Fail closed if the entry state did not take. A live failure reported
        // `EL0Fault(esr=0x82000086 elr=far=LINUX_EL1_ASID_MAINT_BASE)` — EC 0x20
        // is "instruction abort from a LOWER EL", i.e. the trampoline was
        // fetched at EL0, where the EL1-only kernel hole is not mapped. Reading
        // the entry state back says whether the writes above landed, which
        // separates "PSTATE never took" from "something reset it mid-run".
        let entry_pc = vcpu.get_reg(Reg::Pc).map_err(|e| {
            TrapError::Hypervisor(format!(
                "verify entry PC for scoped EL1 ASID maintenance: {e}"
            ))
        })?;
        let entry_pstate = vcpu.get_reg(Reg::Pstate).map_err(|e| {
            TrapError::Hypervisor(format!(
                "verify entry PSTATE for scoped EL1 ASID maintenance: {e}"
            ))
        })?;
        let entry_ttbr0 = vcpu.get_sys_reg(carrick_hal::SysReg::Ttbr0).map_err(|e| {
            TrapError::Hypervisor(format!(
                "verify entry TTBR0 for scoped EL1 ASID maintenance: {e}"
            ))
        })?;
        if entry_pc != HVPATCH_EL1_ASID_MAINT_BASE
            || entry_pstate != AARCH64_PSTATE_EL1H_DAIF_MASKED
            || entry_ttbr0 != maint_ttbr0
        {
            return Err(TrapError::Hypervisor(format!(
                "scoped EL1 ASID maintenance entry state did not take: \
                 pc={entry_pc:#x}/{HVPATCH_EL1_ASID_MAINT_BASE:#x} \
                 pstate={entry_pstate:#x}/{AARCH64_PSTATE_EL1H_DAIF_MASKED:#x} \
                 ttbr0={entry_ttbr0:#x}/{maint_ttbr0:#x}"
            )));
        }
        carrick_observability::probes::hvpatch_tlb_invalidation(u32::from(asid), 0, 0);
        let result = loop {
            match vcpu.run() {
                Ok(Aarch64Exit::MaintenanceDone) => break Ok(()),
                Ok(Aarch64Exit::Kicked) => continue,
                Ok(other) => {
                    // The entry state is verified above, so a fetch fault at the
                    // trampoline base is about the TRANSLATION REGIME, not the
                    // entry sequence. Name it: which roots was this vCPU using,
                    // and was stage-1 even enabled.
                    let sysreg = |reg| vcpu.get_sys_reg(reg).unwrap_or(u64::MAX);
                    let ttbr0 = sysreg(carrick_hal::SysReg::Ttbr0);
                    let ttbr1 = sysreg(carrick_hal::SysReg::Ttbr1);
                    let sctlr = sysreg(carrick_hal::SysReg::Sctlr);
                    break Err(TrapError::UnexpectedExit {
                        reason: format!(
                            "{} during scoped EL1 ASID maintenance: EL1 maintenance faulted on the carrier maintenance root \
                             (asid={asid:#x} carrier_root={:#x} ttbr0={ttbr0:#x} ttbr1={ttbr1:#x} sctlr={sctlr:#x})",
                            maintenance_exit_detail(&other),
                            carrier_maintenance_root.raw(),
                        ),
                    });
                }
                Err(error) => break Err(error),
            }
        };

        let restore_ttbr0 = vcpu
            .set_sys_reg(carrick_hal::SysReg::Ttbr0, saved_ttbr0)
            .map_err(|e| {
                TrapError::Hypervisor(format!(
                    "restore TTBR0 after scoped EL1 ASID maintenance: {e}"
                ))
            });
        let restore_pc = vcpu.set_reg(Reg::Pc, saved_pc).map_err(|e| {
            TrapError::Hypervisor(format!("restore PC after scoped EL1 ASID maintenance: {e}"))
        });
        let restore_pstate = vcpu.set_reg(Reg::Pstate, saved_pstate).map_err(|e| {
            TrapError::Hypervisor(format!(
                "restore PSTATE after scoped EL1 ASID maintenance: {e}"
            ))
        });
        let restore_elr = vcpu.set_reg(Reg::ElrEl1, saved_elr).map_err(|e| {
            TrapError::Hypervisor(format!(
                "restore ELR_EL1 after scoped EL1 ASID maintenance: {e}"
            ))
        });
        let restore_spsr = vcpu.set_reg(Reg::SpsrEl1, saved_spsr).map_err(|e| {
            TrapError::Hypervisor(format!(
                "restore SPSR_EL1 after scoped EL1 ASID maintenance: {e}"
            ))
        });
        let restore_x0 = vcpu.set_reg(Reg::X(0), saved_x0).map_err(|e| {
            TrapError::Hypervisor(format!("restore X0 after scoped EL1 ASID maintenance: {e}"))
        });

        restore_ttbr0?;
        restore_pc?;
        restore_pstate?;
        restore_elr?;
        restore_spsr?;
        restore_x0?;

        result
    }

    /// Run this vCPU in the EL1 scheduler with no thread loaded (EL1 plan
    /// 1d, the idle entry), until it leaves for its executor. The executor's
    /// task is detached and its registers saved elsewhere: this overwrites
    /// PC, PSTATE, `x16` and both translation roots, which the next load
    /// restores in full. The vCPU runs on the carrier root (ASID 0, the
    /// kernel hole and the EL1 region only), so no process's page tables are
    /// needed while it waits.
    ///
    /// Returns the exit that ended the wait: `Halt` is the idle exit (host
    /// work, or a queued thread that needs the executor); anything else means
    /// EL1 ran a thread here and it left at EL0, which the executor adopts.
    pub fn run_idle_entry_on_vcpu(
        vcpu: &mut V::Vcpu,
        carrier_root: carrick_mem::memory::CarrierMaintenanceRoot,
        frame_va: u64,
    ) -> Result<Aarch64Exit, TrapError> {
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
        const TCR_AS: u64 = 1 << 36;
        let root = carrier_root.raw();
        // A vCPU that never ran a task still has its reset TCR, under which
        // nothing translates (an EL1 fetch then faults into a vector that
        // faults again, forever); every HVPatch task uses this one.
        vcpu.set_sys_reg(
            carrick_hal::SysReg::Tcr,
            carrick_mem::arch_sysregs::TCR_EL1_BOOTSTRAP | TCR_AS,
        )?;
        vcpu.set_sys_reg(carrick_hal::SysReg::Ttbr0, root)?;
        vcpu.set_sys_reg(carrick_hal::SysReg::Ttbr1, root)?;
        vcpu.set_reg(Reg::X(16), frame_va)?;
        vcpu.set_reg(Reg::Pc, carrick_mem::memory::el1_idle_entry_va())?;
        vcpu.set_reg(Reg::Pstate, AARCH64_PSTATE_EL1H_DAIF_MASKED)?;
        loop {
            match vcpu.run()? {
                // A kick at an EL1 instruction outside the image (the vector
                // page) surfaces here. The hook may already hold a thread
                // EL1 switched in, so it is never abandoned: re-enter, and
                // the hook leaves through the host on the kick's pending
                // host work.
                Aarch64Exit::Kicked if Self::vcpu_at_el1(vcpu) => continue,
                exit => return Ok(exit),
            }
        }
    }

    fn vcpu_at_el1(vcpu: &mut V::Vcpu) -> bool {
        vcpu.get_reg(Reg::Pstate)
            .is_ok_and(|pstate| (pstate >> 2) & 0b11 != 0)
    }

    fn run_el1_maintenance(&mut self) -> Result<(), TrapError> {
        Self::run_el1_maintenance_on(self.vcpu.get_mut())
    }

    fn run_stage1_maintenance_on(
        vcpu: &mut V::Vcpu,
        process_asid: Option<u16>,
        carrier_maintenance_root: Option<carrick_mem::memory::CarrierMaintenanceRoot>,
    ) -> Result<(), TrapError> {
        match process_asid {
            Some(asid) => {
                let root = carrier_maintenance_root.ok_or_else(|| {
                    TrapError::Hypervisor(
                        "AArch64 VMM does not expose a carrier maintenance root".to_owned(),
                    )
                })?;
                Self::invalidate_asid_on_vcpu(vcpu, asid, root)
            }
            None => Self::run_el1_maintenance_on(vcpu),
        }
    }

    /// This engine's own publication venue: its vCPU, tables, slot and
    /// ASID maintenance. Applies a guest transaction as the host when this
    /// thread holds the MM's EL1 editor exclusion, else through EL1.
    fn descriptor_services(&mut self) -> EngineStage1Services<'_, V> {
        let slot = self.mailbox_slot();
        let carrier_root = self.vm.carrier_maintenance_root().ok();
        EngineStage1Services::<V> {
            vcpu: self.vcpu.get_mut(),
            tables: self.page_tables.clone(),
            slot,
            process_asid: self.process_asid,
            carrier_root,
            suspended_el1_sp: self.suspended_el1_sp,
            required_invalidation: None,
        }
    }

    fn run_stage1_maintenance(&mut self) -> Result<(), TrapError> {
        Self::run_stage1_maintenance_on(
            self.vcpu.get_mut(),
            self.process_asid,
            self.vm.carrier_maintenance_root().ok(),
        )
    }

    /// Whether a required invalidation the current edit needs may be owed
    /// to this vCPU's return of the syscall ([`crate::resume_invalidation`]):
    /// an eligible syscall of an MM with its own ASID, being returned
    /// through the mailbox vector.
    fn may_owe_resume_invalidation(&self) -> bool {
        crate::resume_invalidation::enabled()
            && self.process_asid.is_some()
            && self.mm_generation != 0
            && self.pending_resume_pc.is_some()
            && self.last_syscall_nr.is_some_and(|number| {
                crate::resume_invalidation::eligible_syscall(carrick_abi::CanonicalNr(number))
            })
            && self
                .vcpu
                .borrow_mut()
                .returns_syscalls_through_resume_invalidation()
    }

    fn owe_resume_invalidation(&mut self) {
        let Some(asid) = self.process_asid else {
            return;
        };
        if self.owed_resume_invalidation.is_none() {
            self.owed_resume_invalidation = Some(
                crate::resume_invalidation::ResumeInvalidation::owe(self.mm_generation, asid),
            );
        }
    }

    /// The invalidation this task owes, for a save that keeps the task's
    /// registers resident on its vCPU: the record carries it until the task
    /// is reaffirmed there ([`Self::adopt_owed_resume_invalidation`]) or
    /// evicted, which issues it on that vCPU.
    pub fn take_owed_resume_invalidation(
        &mut self,
    ) -> Option<crate::resume_invalidation::ResumeInvalidation> {
        self.owed_resume_invalidation.take()
    }

    /// Re-adopt an owed invalidation carried by a resident record. One
    /// already held is issued first (a freshly attached engine holds none).
    pub fn adopt_owed_resume_invalidation(
        &mut self,
        owed: Option<crate::resume_invalidation::ResumeInvalidation>,
    ) -> Result<(), TrapError> {
        if let Some(owed) = owed {
            self.settle_owed_resume_invalidation()?;
            self.owed_resume_invalidation = Some(owed);
        }
        Ok(())
    }

    /// The required invalidation after a host-lane edit changed a valid
    /// leaf: owed to the syscall's return when allowed, else run now.
    fn invalidate_after_edit(&mut self) -> Result<(), TrapError> {
        if self.may_owe_resume_invalidation() {
            self.owe_resume_invalidation();
            return Ok(());
        }
        crate::resume_invalidation::note_issued_by_host();
        self.run_stage1_maintenance()
    }

    /// Issue an owed invalidation now, as a host round trip: the task is
    /// leaving this vCPU, or its return cannot use the entry.
    pub fn settle_owed_resume_invalidation(&mut self) -> Result<(), TrapError> {
        let Some(owed) = self.owed_resume_invalidation.take() else {
            return Ok(());
        };
        match self.run_stage1_maintenance() {
            Ok(()) => {
                owed.complete_by_host();
                Ok(())
            }
            Err(error) => {
                self.owed_resume_invalidation = Some(owed);
                Err(error)
            }
        }
    }

    /// [`Self::settle_owed_resume_invalidation`] where the caller cannot fail.
    /// A failure leaves the debt outstanding (dropped with the engine), so
    /// frames released under it stay quarantined.
    fn settle_owed_resume_invalidation_or_log(&mut self) {
        if let Err(error) = self.settle_owed_resume_invalidation() {
            tracing::error!(%error, "owed stage-1 invalidation failed before the task left its vCPU");
        }
    }

    fn run_to_next_syscall(&mut self) -> Result<Option<RawSyscall>, TrapError> {
        // One guest run per call. The loop exists ONLY to re-enter the guest when a
        // kick lands mid-syscall-trap (the `Kicked` arm); every other exit returns.
        // A kick absorbed inside Carrick's EL1 code is owed to the next EL0
        // boundary and settled by whichever exit surfaces first (see `OwedKick`).
        let mut owed_kick = crate::owed_kick::OwedKick::default();
        // Whatever EL1 operation a COW fault suspended resumes with this run.
        self.suspended_el1_sp = None;
        loop {
            // Account the guest's CPU time (wall time inside the backend's guest
            // run) into this thread's guest_cpu slot so getrusage(RUSAGE_SELF) /
            // times / `/proc` see it. Done ONCE here, so every aarch64 backend on
            // this shared engine gets it for free (mirrors carrick-x86).
            let run = carrick_host::guest_cpu::timed_run(|| self.vcpu.get_mut().run());
            self.pending_guest_run_receipt_ns = self
                .pending_guest_run_receipt_ns
                .saturating_add(run.elapsed_ns);
            match run
                .value
                .map_err(|error| self.vm.enrich_vcpu_run_error(&*self.vcpu.get_mut(), error))?
            {
                Aarch64Exit::Syscall {
                    frame,
                    resume_pc,
                    current_guest_sp,
                } => {
                    // The EL0 `svc` re-entered EL1 and hit the sentinel store. The
                    // hardware already set ELR_EL1 = (svc addr + 4); the EL1
                    // vector's own `eret` (after the sentinel store) consumes it —
                    // so we do NOT touch the PC here; we just read the frame. The
                    // ENGINE owns the pending state (§2.1).
                    self.pending_resume_pc = Some(resume_pc);
                    self.last_syscall_nr = Some(frame.x8);
                    self.last_syscall_orig_x0 = frame.x0;
                    // Decode through this engine's `GuestArch` so the runtime loop is
                    // ISA-neutral: x8 → number, x0..x5 → args. `last_syscall_nr`/
                    // `orig_x0` stay set from the raw frame above (their x8/x0
                    // meaning is aarch64-fixed).
                    owed_kick.settle(self.vcpu.get_mut())?;
                    let (number, args) = <Self as ThreadedEngine>::Arch::decode_syscall(&frame);
                    let guest_abi = <Self as ThreadedEngine>::Arch::linux_guest_abi();
                    return Ok(Some(RawSyscall {
                        current_guest_sp,
                        number: carrick_abi::CanonicalNr(number),
                        args,
                        guest_abi,
                        // aarch64 guests already issue canonical numbers, so the
                        // ISA-native number equals the dispatch number.
                        native_number: carrick_abi::NativeNr(number),
                    }));
                }
                Aarch64Exit::EL0Fault {
                    syndrome,
                    elr,
                    far,
                    x16,
                    x17,
                    x29,
                    x30,
                    sp,
                    from_el0_direct,
                } => {
                    // The fault ESR is only valid between fault and delivery; latch
                    // it so `inject_signal` can put it in the arm64 sigframe's
                    // `esr_context` (required by Rosetta's handler).
                    self.last_fault_esr = syndrome;
                    owed_kick.settle(self.vcpu.get_mut())?;
                    return Err(TrapError::el0_fault(
                        syndrome,
                        elr,
                        far,
                        x16,
                        x17,
                        x29,
                        x30,
                        sp,
                        from_el0_direct,
                    ));
                }
                Aarch64Exit::Stage1CowFault { syndrome, far } => {
                    self.last_fault_esr = syndrome;
                    self.suspended_el1_sp =
                        Some(self.vcpu.get_mut().get_reg(Reg::SpEl1).map_err(|error| {
                            TrapError::Hypervisor(format!(
                                "read SP_EL1 of EL1 stopped by a COW fault: {error}"
                            ))
                        })?);
                    owed_kick.settle(self.vcpu.get_mut())?;
                    return Err(TrapError::Stage1CowFault {
                        syndrome,
                        far,
                        elr: self.vcpu.get_mut().get_reg(Reg::Pc).unwrap_or(0),
                        spsr: self.vcpu.get_mut().get_reg(Reg::Pstate).unwrap_or(0),
                    });
                }
                Aarch64Exit::Sys64Read { esr: _ } => {
                    // An EL0 `MRS` of an emulated ID/timer/cache register (Rosetta
                    // x86-on-arm + HVF). KVM's config never traps `MRS`, so this
                    // never surfaces on the KVM path; a future HVF migration
                    // services it via the shared `emulate_el0_sys64_read` and
                    // re-enters. Re-run the guest for now (no-op on KVM).
                    owed_kick.rearm(self.vcpu.get_mut())?;
                    continue;
                }
                Aarch64Exit::MaintenanceDone => {
                    // The maintenance trampoline's completion vehicle is consumed by
                    // `run_el1_maintenance`'s own loop; reaching it here is a
                    // spurious re-entry — re-run the guest.
                    owed_kick.rearm(self.vcpu.get_mut())?;
                    continue;
                }
                // A WFI/halt with no pending syscall: report `None` so the run loop
                // can run signal delivery and resume.
                Aarch64Exit::Halt => {
                    owed_kick.settle(self.vcpu.get_mut())?;
                    return Ok(None);
                }
                Aarch64Exit::Kicked => {
                    // A cross-thread kick (host signal → KVM_RUN EINTR, e.g. a timer
                    // or `tgkill`) can land while the guest is MID-SYSCALL-TRAP: the
                    // EL0 `svc` has already re-entered EL1 and the vCPU PC is inside
                    // carrick's EL1 vector, with the sentinel-store MMIO not yet
                    // surfaced. Reporting that as a deliverable kick (→ the loop
                    // injects a signal at the EL1-vector PC) corrupts the in-flight
                    // syscall and wedges the guest in an EL0 spin. If the PC is in
                    // the EL1 vector, swallow the kick and re-enter the guest so the
                    // syscall completes; the pending signal is delivered cleanly on
                    // the syscall return. Only a kick taken in genuine guest EL0 code
                    // is reported (`Ok(None)`).
                    let pc = self.vcpu.get_mut().get_reg(Reg::Pc)?;
                    let in_vector = carrick_mem::memory::is_carrick_el1_vector_va(pc);
                    let in_el1_image = (carrick_mem::memory::LINUX_EL1_KERNEL_BASE
                        ..carrick_mem::memory::LINUX_EL1_KERNEL_BASE
                            + carrick_mem::memory::LINUX_EL1_IMAGE_SIZE)
                        .contains(&pc);
                    if in_vector
                        || in_el1_image
                        || carrick_mem::memory::is_carrick_el0_clock_stub_va(pc)
                    {
                        // Clock completion may have already passed its flag
                        // check. Normalize to the original SVC, then owe the
                        // kick to EL0: it is taken at the SVC's PC BEFORE the
                        // syscall replays, and the replay crosses host
                        // dispatch afterwards with the kick already served.
                        let normalized = self.vcpu.get_mut().force_clock_host_boundary()?;
                        if in_vector || in_el1_image || normalized {
                            let site = if in_vector {
                                crate::owed_kick::AbsorbedKickSite::El1Vector
                            } else if in_el1_image {
                                crate::owed_kick::AbsorbedKickSite::El1Image
                            } else {
                                crate::owed_kick::AbsorbedKickSite::El0ClockStub
                            };
                            owed_kick.absorb(self.vcpu.get_mut(), pc, site)?;
                            continue;
                        }
                    }
                    owed_kick.settle(self.vcpu.get_mut())?;
                    return Ok(None);
                }
                Aarch64Exit::Memory { gpa, va } => {
                    // A sparse/alias backend (HVF lazy high-VA alias re-map) can
                    // resolve + retry; KVM keeps the default `Ok(false)`. Unhandled
                    // → surface.
                    if self.vm.handle_memory_exit(gpa, va)? {
                        owed_kick.rearm(self.vcpu.get_mut())?;
                        continue;
                    }
                    return Err(TrapError::Hypervisor(format!(
                        "aarch64 backend did not handle memory exit for gpa=0x{gpa:x} va=0x{va:x}"
                    )));
                }
            }
        }
    }

    /// Before running the guest: resume an owed invalidation's syscall
    /// through the resume-invalidation entry and return the debt the run
    /// completes, or issue it now when the vCPU stands anywhere else. An mm
    /// syscall of an MM that another thread still owes for also returns
    /// through the entry, so it cannot reach EL0 over a translation the
    /// other thread's edit retired (e.g. its `mmap` reusing a range the
    /// other `munmap`ped).
    fn arm_resume_invalidation(
        &mut self,
    ) -> Result<Option<crate::resume_invalidation::ResumeInvalidation>, TrapError> {
        if let Some(owed) = self.owed_resume_invalidation.take() {
            let resumed = self.vcpu.get_mut().resume_through_invalidation();
            return match resumed {
                Ok(true) => Ok(Some(owed)),
                Ok(false) => {
                    self.owed_resume_invalidation = Some(owed);
                    self.settle_owed_resume_invalidation().map(|()| None)
                }
                Err(error) => {
                    self.owed_resume_invalidation = Some(owed);
                    Err(error)
                }
            };
        }
        if crate::resume_invalidation::enabled()
            && self.last_syscall_nr.is_some_and(|number| {
                crate::resume_invalidation::eligible_syscall(carrick_abi::CanonicalNr(number))
            })
            && crate::resume_invalidation::outstanding_for_mm(self.mm_generation)
        {
            self.vcpu.get_mut().resume_through_invalidation()?;
        }
        Ok(None)
    }

    fn repoint_guest_alias(
        &mut self,
        va: u64,
        target_ipa: u64,
        len: usize,
        content: Option<&[u8]>,
        access: UserLeafAccess,
    ) -> Result<(), MemoryError> {
        let slot = self.mailbox_slot();
        let carrier_root = self.vm.carrier_maintenance_root().ok();
        let mut services = EngineStage1Services::<V> {
            vcpu: self.vcpu.get_mut(),
            tables: self.page_tables.clone(),
            slot,
            process_asid: self.process_asid,
            carrier_root,
            suspended_el1_sp: self.suspended_el1_sp,
            required_invalidation: None,
        };
        self.vm
            .repoint_guest_alias(va, target_ipa, len, content, access, &mut services)
            .map_err(|error| MemoryError::HostMap(format!("guest alias publication: {error}")))
    }

    fn ensure_frame_cow_write(
        &mut self,
        va: u64,
        len: usize,
        intent: FrameCowWriteIntent,
    ) -> Result<(), MemoryError> {
        self.ensure_sparse_mmap_backing(va, len)?;
        let slot = self.mailbox_slot();
        let tables = self.page_tables.clone();
        let vm = &mut self.vm;
        let vcpu = self.vcpu.get_mut();
        let process_asid = self.process_asid;
        let carrier_root = vm.carrier_maintenance_root().ok();
        let mut flush = EngineStage1Services::<V> {
            vcpu,
            tables,
            slot,
            process_asid,
            carrier_root,
            suspended_el1_sp: self.suspended_el1_sp,
            required_invalidation: None,
        };
        vm.ensure_frame_cow_write(va, len, intent, &mut flush)
            .map_err(|error| MemoryError::HostMap(format!("HVPatch frame COW: {error}")))
    }

    fn ensure_sparse_mmap_backing(&mut self, va: u64, len: usize) -> Result<(), MemoryError> {
        let in_sparse_arena = self.process_asid.is_some()
            && self.vm.sparse_mmap_arena_enabled()
            && ((va >= carrick_mem::memory::LINUX_MMAP_BASE
                && va.checked_add(len as u64).is_some_and(|end| {
                    end <= carrick_mem::memory::LINUX_MMAP_BASE
                        .saturating_add(carrick_mem::memory::mmap_arena_size())
                }))
                || (carrick_mem::memory::is_high_va(va)
                    && va
                        .checked_add(len as u64)
                        .is_some_and(|end| end <= (1u64 << 48))));
        if !in_sparse_arena || len == 0 {
            return Ok(());
        }
        // Persistent exec intentionally drops its software editor. A NEW sparse
        // materialization needs that editor, so instantiate it before the
        // backend transaction only when absent. When the editor already exists,
        // the backend first resolves the process-shared live mapping and does
        // not invoke the flush closure. This matters at clone publication: the
        // parent vCPU is deliberately reclaimed while its TID output is written,
        // so a redundant TTBR0 read from that parked vCPU would fail even though
        // the target stack is already materialized.
        let editor_present = self.page_tables.is_present();
        ensure_sparse_page_table_editor(editor_present, || self.load_live_stage1_manager())?;
        // The driving-vCPU service: host flush on the host lane, and on a
        // guest-owned MM the verified EL1 publication sparse materialization
        // requires. It reads TTBR0 only when a guest publication is submitted.
        let slot = self.mailbox_slot();
        let tables = self.page_tables.clone();
        let vm = &mut self.vm;
        let carrier_root = vm.carrier_maintenance_root().ok();
        let mut flush = EngineStage1Services::<V> {
            vcpu: self.vcpu.get_mut(),
            tables,
            slot,
            process_asid: self.process_asid,
            carrier_root,
            suspended_el1_sp: self.suspended_el1_sp,
            required_invalidation: None,
        };
        vm.ensure_sparse_mmap_backing(va, len, &mut flush)
            .map_err(|error| MemoryError::HostMap(format!("HVPatch sparse mmap backing: {error}")))
    }

    /// The IPA a syscall buffer at guest VA `va` resolves to. Identity (`va`) for
    /// the common heap/stack/private-mmap pointer — NO page-table walk on the hot
    /// path. Only a `repoint_private` overlay over a shared-aperture VA
    /// ([`carrick_mem::memory::needs_stage1_translation`]) walks the live stage-1
    /// tables to find the overlay IPA whose backing the guest's OWN EL0 accesses
    /// hit (the VA-keyed window still resolves to the STALE shared aperture).
    /// High-VA aliases are EXCLUDED: their backend `WindowDesc::base == va`, so
    /// identity is correct and re-basing on the IPA would miss the window. A walk
    /// miss falls back to `va` (identity), preserving prior behaviour for an
    /// unmapped VA.
    fn syscall_buffer_ipa(&self, va: GuestVa, len: usize) -> Option<Gpa> {
        let raw = va.raw();
        if !carrick_mem::memory::needs_stage1_translation(raw, len as u64) {
            return Some(Gpa(raw));
        }
        self.page_tables
            .with_manager(|mgr| mgr.translate(raw))
            .flatten()
            .map(Gpa)
    }

    /// Enforce permission transitions served by guest EL1 on host-side syscall
    /// buffers. Only leaves carrying EL1's private-anonymous software authority
    /// participate; every other mapping keeps the existing protection registry
    /// and backend checks.
    fn el1_private_leaf_permits(
        &self,
        va: u64,
        access: carrick_mmu_core::aarch64::LeafAccess,
    ) -> bool {
        let Some((_ttbr, walk)) = self.diagnostic_fault_page_tables(va) else {
            return true;
        };
        let descriptor = carrick_mmu_core::aarch64::terminal_descriptor(walk);
        carrick_mmu_core::aarch64::terminal_descriptor_permits_host_buffer(descriptor, access)
    }

    fn el1_private_range_permits(
        &self,
        address: u64,
        length: usize,
        access: carrick_mmu_core::aarch64::LeafAccess,
    ) -> bool {
        if length == 0 {
            return true;
        }
        let Some(end) = address.checked_add(length as u64) else {
            return false;
        };
        let mut page = address & !0xfff;
        while page < end {
            if !self.el1_private_leaf_permits(page, access) {
                return false;
            }
            let Some(next) = page.checked_add(0x1000) else {
                return false;
            };
            page = next;
        }
        true
    }

    /// Fire `guest-internal-read-fault` for the page of `va` with its live
    /// terminal descriptor (the evidence of why a host read refused).
    fn trace_read_fault(&self, va: u64, length: usize, phase: u32) {
        let live = self
            .diagnostic_fault_page_tables(va)
            .map_or(0, |(_, walk)| {
                carrick_mmu_core::aarch64::terminal_descriptor(walk)
            });
        carrick_observability::probes::guest_internal_read_fault(
            va & !0xfff,
            length as u64,
            phase,
            live,
        );
    }

    /// The bytes of `[address + offset, ..)` up to the page end when that
    /// page reads as fresh zero to the host: its live leaf names no output
    /// and the exact-MM authority answers that it is an untouched, readable
    /// page of a delegated reservation. A host read needs no frame for it.
    fn fresh_zero_chunk(&self, address: u64, offset: usize, total_len: usize) -> Option<usize> {
        let va = address.checked_add(u64::try_from(offset).ok()?)?;
        let page_left = (0x1000 - (va & 0xfff)) as usize;
        let len = total_len.checked_sub(offset)?.min(page_left);
        let (_, walk) = self.diagnostic_fault_page_tables(va)?;
        if !host_buffer_leaf_has_no_live_output(carrick_mmu_core::aarch64::terminal_descriptor(
            walk,
        )) {
            return None;
        }
        self.vm
            .frame_cow_authority()?
            .host_untouched_page_permits(va & !0xfff, carrick_mmu_core::aarch64::LeafAccess::Read)
            .ok()?
            .then_some(len)
    }

    /// Host copyout does not take the EL0 translation fault that normally
    /// validates a prepared EL1-private leaf. Publish each touched page through
    /// the exact-MM resident-fault authority before resolving its backing.
    fn commit_prepared_host_write(
        &mut self,
        address: u64,
        length: usize,
        checked: bool,
    ) -> Result<(), MemoryError> {
        let authority = self.protections.clone();
        let _legacy = authority.legacy().ok_or(MemoryError::Unsupported)?;
        if length == 0 {
            return Ok(());
        }
        let end = address
            .checked_add(length as u64)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        // A never-touched page of a delegated reservation has no frame yet:
        // back each contiguous absent run with ONE call into the exact-MM
        // grant service (the grants an EL0 first touch of it would get),
        // before the prepared-page commit below publishes what it prepared.
        if let Some(authority) = self.vm.frame_cow_authority() {
            serve_absent_copyout_runs(
                self,
                address,
                end,
                |engine, page| {
                    engine
                        .diagnostic_fault_page_tables(page)
                        .map(|(_, walk)| carrick_mmu_core::aarch64::terminal_descriptor(walk))
                        .is_some_and(host_buffer_leaf_has_no_live_output)
                },
                |engine, start, len| {
                    authority
                        .grant_for_host_copyout(
                            start,
                            len,
                            &mut crate::descriptor_drain::EngineGrantVenue(&mut *engine),
                        )
                        .map_err(|error| {
                            MemoryError::HostMap(format!("host copyout grant: {error}"))
                        })
                },
            )?;
        }
        let mut page = address & !4095;
        while page < end {
            let descriptor = |engine: &Self| {
                engine
                    .diagnostic_fault_page_tables(page)
                    .map(|(_, walk)| carrick_mmu_core::aarch64::terminal_descriptor(walk))
            };
            let live = descriptor(self);
            let prepared = live
                .is_some_and(carrick_mmu_core::aarch64::terminal_descriptor_is_prepared_private);
            if (checked || prepared)
                && live.is_some_and(|leaf| {
                    !carrick_mmu_core::aarch64::terminal_descriptor_permits_host_buffer(
                        leaf,
                        carrick_mmu_core::aarch64::LeafAccess::Write,
                    )
                })
            {
                carrick_observability::probes::guest_internal_write_fault(
                    page,
                    4096,
                    15,
                    &format!(
                        "copyout leaf after grant: live={live:x?} checked={checked} prepared={prepared}"
                    ),
                );
                return Err(MemoryError::OutOfBounds { address, length });
            }
            if prepared {
                let authority = self.vm.frame_cow_authority().ok_or_else(|| {
                    MemoryError::HostMap("prepared host write lacks exact-MM authority".to_owned())
                })?;
                let committed = if self.page_tables.live_descriptor_owner()
                    == LiveDescriptorOwner::Guest
                {
                    authority.commit_guest_host_first_touch(page, &mut |mm, page| {
                        let leaf = descriptor(self)
                            .ok_or_else(|| "guest copyout lost its prepared leaf".to_owned())?;
                        let tables = self.page_tables.clone();
                        let slots = carrick_el1_abi::descriptor_txn_slots_host()
                            .ok_or_else(|| "guest copyout has no descriptor slots".to_owned())?;
                        crate::descriptor_drain::publish_copyout(
                            &mut crate::descriptor_drain::EngineDrainVenue(self),
                            &tables,
                            slots,
                            mm,
                            page,
                            leaf & 0x0000_FFFF_FFFF_F000,
                        )
                        .map_err(|error| error.to_string())
                    })
                } else {
                    authority.commit_host_first_touch(page, &mut |page, prot| {
                        <Self as GuestMemory>::protect_range(self, page, 4096, prot)
                            .map_err(|error| error.to_string())
                    })
                }
                .map_err(|error| MemoryError::HostMap(format!("host first touch: {error}")))?;
                // Another executor may have committed this leaf after our
                // read-only walk. Its completed publication needs no second
                // plan; an unchanged prepared leaf still does.
                if !committed
                    && descriptor(self).is_some_and(
                        carrick_mmu_core::aarch64::terminal_descriptor_is_prepared_private,
                    )
                {
                    return Err(MemoryError::HostMap(
                        "prepared host write has no resident-fault plan".to_owned(),
                    ));
                }
            }
            page = page
                .checked_add(4096)
                .ok_or(MemoryError::OutOfBounds { address, length })?;
        }
        Ok(())
    }

    /// One page-bounded VA→IPA segment of a syscall buffer. Page bounding is
    /// mandatory: a private prefix/middle/suffix overlay can make numerically
    /// adjacent guest VAs resolve to unrelated physical pages.
    fn syscall_buffer_chunk(
        &self,
        address: u64,
        offset: usize,
        total_len: usize,
    ) -> Result<(u64, Gpa, usize), MemoryError> {
        let offset_u64 = u64::try_from(offset).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: total_len,
        })?;
        let va = address
            .checked_add(offset_u64)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: total_len,
            })?;
        let page_left = (0x1000 - (va & 0xfff)) as usize;
        let len = (total_len - offset).min(page_left);
        let ipa = self
            .syscall_buffer_ipa(GuestVa(va), len)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: total_len,
            })?;
        Ok((va, ipa, len))
    }
}

/// This observation grants no access: the exact-MM root must authenticate
/// the current incarnation before a retired output can be reused.
fn host_buffer_leaf_has_no_live_output(leaf: u64) -> bool {
    carrick_mmu_core::aarch64::terminal_descriptor_is_absent(leaf)
        || carrick_mmu_core::aarch64::terminal_descriptor_is_retired(leaf)
}

fn prevalidate_host_write_page(
    live: Option<u64>,
    backend: impl FnOnce() -> bool,
    untouched_root: impl FnOnce() -> bool,
) -> bool {
    if live.is_some_and(|leaf| {
        host_buffer_leaf_has_no_live_output(leaf)
            || (carrick_mmu_core::aarch64::terminal_descriptor_is_prepared_private(leaf)
                && carrick_mmu_core::aarch64::terminal_descriptor_permits_host_buffer(
                    leaf,
                    carrick_mmu_core::aarch64::LeafAccess::Write,
                ))
    }) && untouched_root()
    {
        return true;
    }
    if live.is_some_and(carrick_mmu_core::aarch64::terminal_descriptor_is_retired) {
        return false;
    }
    backend()
        && live.is_none_or(|leaf| {
            carrick_mmu_core::aarch64::terminal_descriptor_permits_host_buffer(
                leaf,
                carrick_mmu_core::aarch64::LeafAccess::Write,
            )
        })
}

/// Serve unbacked copyout pages with one grant per maximal contiguous run,
/// including its last partial page, never another call for a run already asked.
fn serve_absent_copyout_runs<C: ?Sized, E>(
    ctx: &mut C,
    address: u64,
    end: u64,
    is_absent: impl Fn(&C, u64) -> bool,
    mut grant: impl FnMut(&mut C, u64, u64) -> Result<bool, E>,
) -> Result<(), E> {
    const PAGE: u64 = 4096;
    let mut page = address & !(PAGE - 1);
    while page < end {
        if !is_absent(ctx, page) {
            page = page.saturating_add(PAGE);
            continue;
        }
        let mut run_end = page.saturating_add(PAGE);
        while run_end < end && is_absent(ctx, run_end) {
            run_end = run_end.saturating_add(PAGE);
        }
        // Whatever the service backed (all of the run, or none of it), the
        // run has had its one call; a page it declined stays absent and the
        // copy path answers it.
        grant(ctx, page, run_end - page)?;
        page = run_end;
    }
    Ok(())
}

/// Name a non-MaintenanceDone exit for the EL1-maintenance error path (the
/// `Aarch64Exit::Syscall` payload is not `Display`).
/// Name an unexpected maintenance exit WITH the state that explains it.
///
/// `exit_variant_name` alone says only "EL0Fault", which for a host-driven EL1
/// trampoline is the least useful half of the story: the question is always
/// which address faulted and why. An unrecoverable maintenance failure must
/// carry the syndrome, not just the variant.
fn maintenance_exit_detail(exit: &Aarch64Exit) -> String {
    match exit {
        Aarch64Exit::EL0Fault {
            syndrome,
            elr,
            far,
            from_el0_direct,
            ..
        } => format!(
            "EL0Fault(esr={syndrome:#x} elr={elr:#x} far={far:#x} \
             from_el0_direct={from_el0_direct})"
        ),
        Aarch64Exit::Stage1CowFault { .. } | Aarch64Exit::Memory { .. } => {
            format!(
                "{} (guest memory exit inside an EL1 trampoline)",
                exit_variant_name(exit)
            )
        }
        other => exit_variant_name(other).to_owned(),
    }
}

fn exit_variant_name(exit: &Aarch64Exit) -> &'static str {
    match exit {
        Aarch64Exit::Syscall { .. } => "Syscall",
        Aarch64Exit::EL0Fault { .. } => "EL0Fault",
        Aarch64Exit::Stage1CowFault { .. } => "Stage1CowFault",
        Aarch64Exit::Sys64Read { .. } => "Sys64Read",
        Aarch64Exit::MaintenanceDone => "MaintenanceDone",
        Aarch64Exit::Halt => "Halt",
        Aarch64Exit::Kicked => "Kicked",
        Aarch64Exit::Memory { .. } => "Memory",
    }
}

/// Map an engine-side `TrapError` from a `Vcpu` register read back to an
/// `OsError`, for the `read_aarch64_syscall_frame` closure (which wants `OsError`).
fn trap_to_os(e: TrapError) -> OsError {
    OsError::new(e.to_string())
}

/// The OS thread id for a diagnostic line, portably: `gettid(2)` on Linux (where
/// the KVM lane runs), `0` elsewhere (this crate also compiles on macOS for the
/// later HVF migration, where `SYS_gettid` is absent).
/// Cached `CARRICK_MAINT_DEBUG` presence. Every stage-1 TLBI completion checks
/// it; reading the environment there took the process-wide environment lock
/// per flush.
fn maint_debug() -> bool {
    static CELL: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CELL.get_or_init(|| std::env::var_os("CARRICK_MAINT_DEBUG").is_some())
}

fn debug_tid() -> i64 {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::syscall(libc::SYS_gettid) }
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

// ─── GuestMemory ─────────────────────────────────────────────────────────────
//
// The guest is identity-mapped (stage-1 maps VA == IPA, and the single backend
// memory slot maps IPA == GPA), so a syscall's guest *virtual* pointer is
// numerically the same as its guest-physical address and indexes straight into
// the host backing. `read_bytes`/`write_bytes` move syscall buffers; the PROT_NONE
// gate is the backend's set (shared across siblings); `protect_range`/
// `unmap_range`/`repoint_private` edit the live stage-1 tables so the GUEST's own
// EL0 access honours mmap/mprotect/munmap permissions.

impl<V: Aarch64Vmm> carrick_guest_mem::CallerEl1Call for Aarch64EngineCore<V> {
    fn slot(&self) -> Option<usize> {
        self.vcpu.borrow().mailbox_slot()
    }

    fn drain_foreign(
        &mut self,
        mm_key: u64,
        ttbr0: u64,
        admission: &mut dyn carrick_guest_mem::BorrowedTtbr0Admission,
    ) -> Result<u64, String> {
        let slot = self
            .vcpu
            .borrow_mut()
            .mailbox_slot()
            .ok_or_else(|| "caller vCPU has no EL1 slot".to_owned())?;
        let suspended = self.suspended_el1_sp;
        let vcpu = std::cell::RefCell::new(self.vcpu.get_mut());
        crate::descriptor_drain::run_foreign_drain_call(
            slot,
            mm_key,
            ttbr0,
            admission,
            || vcpu.borrow().get_sys_reg(SysReg::Ttbr0),
            |value| vcpu.borrow_mut().set_sys_reg(SysReg::Ttbr0, value),
            suspended,
            |entry, frame_va| run_el1_service_call_on::<V>(&mut vcpu.borrow_mut(), entry, frame_va),
        )
        .map_err(|error| error.to_string())
    }
}

impl<V: Aarch64Vmm> Aarch64EngineCore<V> {
    /// Owner routing is selected by root admission, never by a failed copy.
    fn read_owner_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.read_owner_bytes_with_intent(
            address,
            length,
            carrick_el1_abi::PortalTransferIntent::UserRead,
        )
    }
    fn read_owner_bytes_with_intent(
        &self,
        address: u64,
        length: usize,
        intent: carrick_el1_abi::PortalTransferIntent,
    ) -> Result<Vec<u8>, MemoryError> {
        let handle = self.protections.owner().ok_or(MemoryError::Unsupported)?;
        if handle.mm().raw() != self.mm_generation {
            return Err(MemoryError::HostMap(
                "owner memory incarnation mismatch".into(),
            ));
        }
        let ttbr0 = self
            .transfer_service_loan()
            .and_then(|loan| loan.target_ttbr0())
            .map_err(|error| MemoryError::HostMap(error.to_string()))?;
        let target = crate::user_transfer::TransferTarget::from_handle(handle, ttbr0);
        let transfer = crate::user_transfer::OwnedUserTransfer::new(
            target,
            crate::user_transfer::UserTransfer::CopyIn {
                address,
                len: length,
                intent,
            },
        )
        .ok_or(MemoryError::OutOfBounds { address, length })?;
        self.continue_owner_read(transfer)
    }
    fn continue_owner_read(
        &self,
        mut transfer: crate::user_transfer::OwnedUserTransfer,
    ) -> Result<Vec<u8>, MemoryError> {
        if self.protections.owner() != Some(transfer.target_handle()) {
            return Err(MemoryError::HostMap(
                "read continuation belongs to another root".into(),
            ));
        }
        let address = transfer.address();
        let length = transfer.len();
        let custody = self
            .vm
            .owner_transfer_custody()
            .ok_or(MemoryError::Unsupported)?;
        let region = carrick_el1_abi::get_el1_region_host_ptr();
        if region == 0 {
            return Err(MemoryError::Unsupported);
        }
        // SAFETY: the live engine retains the exact complete carrier ABI region.
        let slots = unsafe {
            &*((region + carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize)
                as *const carrick_el1_abi::MmPortalSlots)
        };
        loop {
            use crate::user_transfer::TransferProgress;
            match transfer
                .advance(self, custody.as_ref(), slots)
                .map_err(|error| MemoryError::HostMap(error.to_string()))?
            {
                TransferProgress::Complete => return Ok(transfer.into_bytes()),
                TransferProgress::Physical(wait) => {
                    return Err(MemoryError::ReadSuspended(Box::new(
                        carrick_guest_mem::MemoryReadSuspension {
                            wait: carrick_guest_mem::MemoryReadWait::Physical(wait),
                            continuation: carrick_guest_mem::OwnedReadContinuation::new(transfer),
                        },
                    )));
                }
                TransferProgress::Advanced => {}
                TransferProgress::OwnerWait(wait) => {
                    return Err(MemoryError::ReadSuspended(Box::new(
                        carrick_guest_mem::MemoryReadSuspension {
                            wait: carrick_guest_mem::MemoryReadWait::Owner(wait),
                            continuation: carrick_guest_mem::OwnedReadContinuation::new(transfer),
                        },
                    )));
                }
                TransferProgress::Supply(supply) => {
                    return Err(MemoryError::ReadSuspended(Box::new(
                        carrick_guest_mem::MemoryReadSuspension {
                            wait: carrick_guest_mem::MemoryReadWait::Supply(supply),
                            continuation: carrick_guest_mem::OwnedReadContinuation::new(transfer),
                        },
                    )));
                }
                TransferProgress::Retired(handle) => return Err(MemoryError::OwnerRetired(handle)),
                TransferProgress::Refused(errno) if errno.get() != 14 => {
                    return Err(MemoryError::HostMap(format!(
                        "owner copyin refused: {errno:?}"
                    )));
                }
                TransferProgress::Refused(_) => {
                    return Err(MemoryError::OutOfBounds { address, length });
                }
                TransferProgress::Suspended => {
                    return Err(MemoryError::HostMap(
                        "owner read omitted suspension receipt".into(),
                    ));
                }
            }
        }
    }
    fn write_owner_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let range = carrick_guest_mem::GuestWriteRange::new(GuestVa(address), bytes.len()).ok_or(
            MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            },
        )?;
        let prepared = self.prepare_write(&[range]).map_err(|error| match error {
            carrick_guest_mem::MemoryPrepareError::Limit(limit) => MemoryError::HostMap(format!(
                "write requires bounded prepare before consumption: {limit:?}"
            )),
            carrick_guest_mem::MemoryPrepareError::Fault(error) => error,
            carrick_guest_mem::MemoryPrepareError::Physical(wait) => MemoryError::Physical(wait),
            carrick_guest_mem::MemoryPrepareError::OwnerWait(wait) => MemoryError::OwnerWait(wait),
            carrick_guest_mem::MemoryPrepareError::Supply(supply) => {
                MemoryError::Supply(Box::new(supply))
            }
        })?;
        prepared.commit(&[bytes]);
        Ok(())
    }
}

impl<V: Aarch64Vmm> GuestMemory for Aarch64EngineCore<V> {
    fn read_carrick_internal(
        &self,
        range: carrick_el1_abi::CarrickInternalReadRange,
    ) -> Result<Vec<u8>, MemoryError> {
        if self.protections.owner().is_some() {
            self.read_owner_bytes_with_intent(
                range.address(),
                range.len() as usize,
                carrick_el1_abi::PortalTransferIntent::CarrickInternalRead,
            )
        } else {
            self.read_bytes_raw(range.address(), range.len() as usize)
        }
    }
    fn resume_read(
        &self,
        continuation: carrick_guest_mem::OwnedReadContinuation,
    ) -> Result<Vec<u8>, MemoryError> {
        let transfer = continuation
            .take::<crate::user_transfer::OwnedUserTransfer>()
            .ok_or_else(|| {
                MemoryError::HostMap(
                    "read continuation already consumed or belongs to another backend".into(),
                )
            })?;
        self.continue_owner_read(transfer)
    }

    fn caller_el1_call(&mut self) -> Option<&mut dyn carrick_guest_mem::CallerEl1Call> {
        self.vcpu.get_mut().mailbox_slot()?;
        Some(self)
    }

    fn bind_deferred_anonymous_state(
        &mut self,
        state: std::sync::Arc<carrick_guest_mem::DeferredAnonymousState>,
    ) {
        self.vm.bind_deferred_anonymous_state(state);
    }

    fn supports_lazy_anonymous_mmap(&self) -> bool {
        self.process_asid.is_some()
            && self.vm.sparse_mmap_arena_enabled()
            && self.vm.deferred_anonymous_state().is_some()
    }

    fn supports_lazy_private_file_mmap(&self) -> bool {
        self.supports_lazy_anonymous_mmap()
    }

    /// Borrow the backend's legacy mirror. Admitted roots have no mirror and
    /// authorize checked and raw copies through the same EL1 transfer venue.
    fn protections(&self) -> Option<LegacyProtectionRead<'_>> {
        self.vm.protections()
    }

    fn user_memory_venue(&self) -> carrick_guest_mem::UserMemoryVenue {
        if self.protections.owner().is_some() {
            carrick_guest_mem::UserMemoryVenue::Owner
        } else {
            carrick_guest_mem::UserMemoryVenue::Legacy
        }
    }

    fn prepare_write(
        &mut self,
        ranges: &[carrick_guest_mem::GuestWriteRange],
    ) -> Result<
        Box<dyn carrick_guest_mem::PreparedGuestWrite + '_>,
        carrick_guest_mem::MemoryPrepareError,
    > {
        let Some(handle) = self.protections.owner() else {
            return Err(carrick_guest_mem::MemoryPrepareError::Fault(
                MemoryError::Unsupported,
            ));
        };
        if handle.mm().raw() != self.mm_generation {
            carrick_fatal::carrick_fatal!(
                "aarch64::prepared_copy",
                "current task differs from admitted memory authority"
            );
        }
        let custody = self.vm.owner_transfer_custody().unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!(
                "aarch64::prepared_copy",
                "admitted task lacks physical custody"
            )
        });
        let ttbr0 = self
            .transfer_service_loan()
            .and_then(|loan| loan.target_ttbr0())
            .map_err(|error| {
                carrick_guest_mem::MemoryPrepareError::Fault(MemoryError::HostMap(
                    error.to_string(),
                ))
            })?;
        let region = carrick_el1_abi::get_el1_region_host_ptr();
        if region == 0 {
            carrick_fatal::carrick_fatal!(
                "aarch64::prepared_copy",
                "admitted carrier region absent"
            );
        }
        // SAFETY: the live engine retains this carrier's complete ABI region;
        // selection independently authenticates its address and carrier binding.
        let slots = unsafe {
            &*((region + carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize)
                as *const carrick_el1_abi::MmPortalSlots)
        };
        crate::user_transfer::prepare_write(
            self,
            custody.as_ref(),
            slots,
            crate::user_transfer::TransferTarget::from_handle(handle, ttbr0),
            ranges,
        )
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        if self.protections.owner().is_some() {
            return self.read_owner_bytes(address, length);
        }
        if !self.el1_private_range_permits(
            address,
            length,
            carrick_mmu_core::aarch64::LeafAccess::Read,
        ) {
            self.trace_read_fault(address, length, 0);
            return Err(MemoryError::OutOfBounds { address, length });
        }
        // PROT_NONE was gated on the guest VA in the default `read_bytes`. Walk
        // every page independently so a buffer spanning shared identity and a
        // private overlay never assumes one physically-contiguous base IPA.
        let mut out = vec![0u8; length];
        let mut copied = 0usize;
        while copied < length {
            let (va, ipa, chunk_len) = match self.syscall_buffer_chunk(address, copied, length) {
                Ok(chunk) => chunk,
                Err(error) => {
                    // `out` is already zero.
                    let Some(zero) = self.fresh_zero_chunk(address, copied, length) else {
                        self.trace_read_fault(address.wrapping_add(copied as u64), length, 1);
                        return Err(error);
                    };
                    copied += zero;
                    continue;
                }
            };
            let bytes = match self.vm.translated_read(va, ipa.raw(), chunk_len) {
                Ok(bytes) => bytes,
                Err(error) => {
                    let deferred = match self.vm.deferred_anonymous_state() {
                        Some(state) => state
                            .copy_pristine_file(GuestVa(va), &mut out[copied..copied + chunk_len])
                            .map_err(|error| {
                                MemoryError::HostMap(format!(
                                    "read deferred private file backing: {error}"
                                ))
                            })?,
                        None => false,
                    };
                    if deferred {
                        copied += chunk_len;
                        continue;
                    }
                    self.trace_read_fault(va, length, 2);
                    return Err(error);
                }
            };
            if bytes.len() != chunk_len {
                return Err(MemoryError::OutOfBounds { address, length });
            }
            out[copied..copied + chunk_len].copy_from_slice(&bytes);
            copied += chunk_len;
        }
        Ok(out)
    }

    fn read_into_raw(&self, address: u64, dst: &mut [u8]) -> Result<(), MemoryError> {
        if self.protections.owner().is_some() {
            let bytes = self.read_owner_bytes(address, dst.len())?;
            dst.copy_from_slice(&bytes);
            return Ok(());
        }
        // No-alloc fixed-size read (`read_u32`/`read_u64`/struct headers), still
        // page-segmented for fragmented overlays.
        let length = dst.len();
        if !self.el1_private_range_permits(
            address,
            length,
            carrick_mmu_core::aarch64::LeafAccess::Read,
        ) {
            self.trace_read_fault(address, length, 0);
            return Err(MemoryError::OutOfBounds { address, length });
        }
        let mut copied = 0usize;
        while copied < length {
            let (va, ipa, chunk_len) = match self.syscall_buffer_chunk(address, copied, length) {
                Ok(chunk) => chunk,
                Err(error) => {
                    let Some(zero) = self.fresh_zero_chunk(address, copied, length) else {
                        self.trace_read_fault(address.wrapping_add(copied as u64), length, 1);
                        return Err(error);
                    };
                    dst[copied..copied + zero].fill(0);
                    copied += zero;
                    continue;
                }
            };
            if let Err(error) =
                self.vm
                    .translated_read_into(va, ipa.raw(), &mut dst[copied..copied + chunk_len])
            {
                let deferred = match self.vm.deferred_anonymous_state() {
                    Some(state) => state
                        .copy_pristine_file(GuestVa(va), &mut dst[copied..copied + chunk_len])
                        .map_err(|error| {
                            MemoryError::HostMap(format!(
                                "read deferred private file backing: {error}"
                            ))
                        })?,
                    None => false,
                };
                if !deferred {
                    self.trace_read_fault(va, length, 2);
                    return Err(error);
                }
            }
            copied += chunk_len;
        }
        Ok(())
    }

    fn release_root_facts(&mut self, address: u64, len: usize) {
        let Some(end) = address.checked_add(len as u64) else {
            return;
        };
        let root_decided = |engine: &Self, page: u64| {
            engine
                .diagnostic_fault_page_tables(page)
                .map(|(_, walk)| carrick_mmu_core::aarch64::terminal_descriptor(walk))
                .is_none_or(|leaf| {
                    carrick_mmu_core::aarch64::terminal_descriptor_is_absent(leaf)
                        || carrick_mmu_core::aarch64::el1_private_leaf_state(leaf)
                            != carrick_mmu_core::aarch64::El1PrivateLeafState::Unowned
                })
        };
        let mut page = address & !0xfff;
        let mut run: Option<u64> = None;
        while page < end {
            match (root_decided(self, page), run) {
                (true, None) => run = Some(page),
                (false, Some(start)) => {
                    self.return_to_root(start, (page - start) as usize);
                    run = None;
                }
                _ => {}
            }
            page += 0x1000;
        }
        if let Some(start) = run {
            self.return_to_root(start, (end.max(start) - start) as usize);
        }
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if self.protections.owner().is_some() {
            return self.write_owner_bytes(address, bytes);
        }
        // PROT_NONE gated on the guest VA in the default `write_bytes`; backing
        // lookup on the translated IPA (see `read_bytes_raw`). For a
        // `repoint_private` overlay the syscall write lands in the PRIVATE overlay
        // backing the guest reads, not the shared aperture.
        //
        // Dynamic read-only ranges (`mprotect(PROT_READ)` / read-only mmap) are
        // keyed on the guest VA in the shared protection table so a sibling vCPU's
        // syscall write observes the change. The backend's `translated_write` may
        // additionally enforce per-mapping write intent (HVF's boot/file mappings).
        if !bytes.is_empty()
            && self
                .vm
                .protections()
                .is_some_and(|p| p.range_write_denied(address, bytes.len()))
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        let report_fault = |phase, error: MemoryError| {
            carrick_observability::probes::guest_internal_write_fault(
                address,
                bytes.len() as u64,
                phase,
                &error.to_string(),
            );
            error
        };
        self.commit_prepared_host_write(address, bytes.len(), true)
            .map_err(|error| report_fault(9, error))?;
        let length = bytes.len();
        let mut copied = 0usize;
        while copied < length {
            let (va, ipa, chunk_len) = self
                .syscall_buffer_chunk(address, copied, length)
                .map_err(|error| report_fault(10, error))?;
            self.ensure_frame_cow_write(va, chunk_len, FrameCowWriteIntent::GuestVisible)
                .map_err(|error| report_fault(11, error))?;
            self.vm
                .translated_write(va, ipa.raw(), &bytes[copied..copied + chunk_len])
                .map_err(|error| report_fault(12, error))?;
            copied += chunk_len;
        }
        Ok(())
    }

    fn write_bytes_unchecked(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if self.protections.owner().is_some() {
            return self.write_owner_bytes(address, bytes);
        }
        // carrick-INTERNAL frame the guest must receive even into a guest-read-only
        // mapping (vdso vvar, sigframe, bootstrap): bypass the per-mapping WRITE
        // permission (the host page is writable). PROT_NONE is NOT re-gated (the
        // default `write_bytes_unchecked` doesn't gate either). The translated IPA
        // resolves a `repoint_private` overlay to the private backing.
        self.commit_prepared_host_write(address, bytes.len(), false)?;
        let length = bytes.len();
        let mut copied = 0usize;
        while copied < length {
            let report_fault = |phase, error: MemoryError| {
                carrick_observability::probes::guest_internal_write_fault(
                    address,
                    length as u64,
                    phase,
                    &error.to_string(),
                );
                error
            };
            let (va, ipa, chunk_len) = self
                .syscall_buffer_chunk(address, copied, length)
                .map_err(|error| report_fault(0, error))?;
            self.ensure_frame_cow_write(va, chunk_len, FrameCowWriteIntent::PrivilegedInternal)
                .map_err(|error| report_fault(1, error))?;
            self.vm
                .translated_write_unchecked(va, ipa.raw(), &bytes[copied..copied + chunk_len])
                .map_err(|error| report_fault(2, error))?;
            copied += chunk_len;
        }
        Ok(())
    }

    fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        let Some(end) = address.checked_add(length as u64) else {
            return false;
        };
        let mut cursor = address;
        while cursor < end {
            let len = (end - cursor).min(4096 - (cursor & 4095)) as usize;
            let live = self
                .diagnostic_fault_page_tables(cursor)
                .map(|(_, walk)| carrick_mmu_core::aarch64::terminal_descriptor(walk));
            if !prevalidate_host_write_page(
                live,
                || {
                    self.vm.guest_range_is_writable(cursor, len)
                        && !self
                            .vm
                            .protections()
                            .is_some_and(|p| p.range_write_denied(cursor, len))
                },
                || {
                    self.vm.frame_cow_authority().is_some_and(|authority| {
                        authority
                            .host_untouched_page_permits(
                                cursor & !4095,
                                carrick_mmu_core::aarch64::LeafAccess::Write,
                            )
                            .unwrap_or(false)
                    })
                },
            ) {
                carrick_observability::probes::guest_internal_write_fault(
                    cursor,
                    len as u64,
                    8,
                    &format!("root copyout prevalidation refused: live={live:x?}"),
                );
                return false;
            }
            cursor += len as u64;
        }
        true
    }

    fn prepare_host_write(&mut self, address: u64, length: usize) -> Result<(), MemoryError> {
        self.commit_prepared_host_write(address, length, false)
    }

    fn host_read(&self, address: u64, len: usize) -> Option<carrick_guest_mem::HostRead> {
        let authority = self.protections.clone();
        let _legacy = authority.legacy()?;
        if !self.el1_private_range_permits(
            address,
            len,
            carrick_mmu_core::aarch64::LeafAccess::Read,
        ) {
            return None;
        }
        self.vm.host_read(address, len)
    }

    fn host_ptr_for_write(&mut self, address: u64, len: usize) -> Option<*mut u8> {
        self.commit_prepared_host_write(address, len, true).ok()?;
        self.ensure_frame_cow_write(address, len, FrameCowWriteIntent::GuestVisible)
            .ok()?;
        self.vm.host_ptr_for_write(address, len)
    }

    fn begin_host_write(
        &mut self,
        ranges: &[carrick_guest_mem::HostWriteRange],
    ) -> Result<(), MemoryError> {
        self.vm.begin_host_write(ranges)
    }
    fn finish_host_write(&mut self, ranges: &[carrick_guest_mem::HostWriteRange]) {
        self.vm.finish_host_write(ranges);
    }

    /// Record/clear a PROT_NONE range so syscall buffers there fault (EFAULT). This
    /// is the HOST-SIDE check only; the COMPLEMENTARY guest-side enforcement (so
    /// the guest's own EL0 access faults) is done by `protect_range`/`unmap_range`/
    /// `unmap_alias_range`, which edit the live stage-1 tables AND flush the stale
    /// TLB via `pt_edit_and_flush` + the EL0-fault→SIGSEGV path.
    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.vm.set_no_access(address, len, no_access);
    }

    fn mark_bus_fault(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        if len == 0
            || !address.is_multiple_of(4096)
            || !len.is_multiple_of(4096)
            || address.checked_add(len as u64).is_none()
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: len,
            });
        }
        self.apply_stage1_rules((address, len), &[(address, len, TerminalRule::BusFault)])
    }

    fn set_no_write(&mut self, address: u64, len: usize, no_write: bool) {
        if let Some(protections) = self.vm.protections() {
            protections.set_no_write(address, len, no_write);
        }
    }

    fn set_unmapped(&mut self, address: u64, len: usize, unmapped: bool) {
        if let Some(protections) = self.vm.protections() {
            protections.set_unmapped(address, len, unmapped);
        }
    }

    fn set_mapping_protection(
        &mut self,
        address: u64,
        len: usize,
        no_access: bool,
        no_write: bool,
    ) {
        if let Some(protections) = self.vm.protections() {
            protections.set_mapping_protection(address, len, no_access, no_write);
        }
    }

    fn set_mapping_sharing(&mut self, address: u64, len: usize, sharing: MappingSharing) {
        if let Some(protections) = self.vm.protections() {
            protections.set_mapping_sharing(address, len, sharing);
        }
    }

    fn set_mapping_protection_and_sharing(
        &mut self,
        address: u64,
        len: usize,
        no_access: bool,
        no_write: bool,
        sharing: MappingSharing,
    ) {
        // This operation is the dispatcher's new-mapping publication point.
        // Its following protect_range may install PROT_NONE only to arm first
        // touch even when the new VMA is writable. Retired leaf permissions
        // from the predecessor must be cleared before that edit.
        self.pending_new_mapping = Some((address, len));
        if let Some(protections) = self.vm.protections() {
            protections
                .set_mapping_protection_and_sharing(address, len, no_access, no_write, sharing);
        }
    }

    /// Scrub the physical backing of `[address, address+len)`, BYPASSING the
    /// PROT_NONE check — used to clear a reused/`munmap`'d region whose stale bytes
    /// must never resurface after a later `mprotect` makes it readable.
    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        if self.protections.owner().is_some() {
            return self.write_owner_bytes(address, &vec![0; len]);
        }
        self.ensure_frame_cow_write(address, len, FrameCowWriteIntent::BackingMaintenance)?;
        self.vm.zero_backing(address, len)
    }

    fn discard_private_anonymous(
        &mut self,
        address: u64,
        len: usize,
    ) -> Result<bool, carrick_guest_mem::RepointPrivateError> {
        use carrick_guest_mem::RepointPrivateError;
        let Some(end) = address.checked_add(len as u64) else {
            return Err(RepointPrivateError::clean(MemoryError::OutOfBounds {
                address,
                length: len,
            }));
        };
        let in_sparse_range = (address >= carrick_mem::memory::LINUX_MMAP_BASE
            && end
                <= carrick_mem::memory::LINUX_MMAP_BASE
                    .saturating_add(carrick_mem::memory::mmap_arena_size()))
            || (carrick_mem::memory::is_high_va(address) && end <= (1u64 << 48));
        if len == 0
            || !address.is_multiple_of(4096)
            || !len.is_multiple_of(4096)
            || !in_sparse_range
            || !self.supports_lazy_anonymous_mmap()
            || !carrick_hal::stage1_exclusive::current_thread_edits_exclusively()
        {
            return Ok(false);
        }
        let Some(deferred) = self.vm.deferred_anonymous_state() else {
            return Ok(false);
        };
        let Some(prepared) = self
            .vm
            .prepare_anonymous_discard(address, len)
            .map_err(|error| RepointPrivateError::clean(MemoryError::HostMap(error.to_string())))?
        else {
            return Ok(false);
        };
        // Keep semantic mapping/protection metadata intact. After editing starts,
        // uncertain publication must fail stopped with old owners still retained.
        if self.page_tables.live_descriptor_owner() == LiveDescriptorOwner::Guest {
            self.retire_stage1_range(address, len, true)
        } else {
            self.pt_edit_and_flush(|mgr| mgr.unmap_aliased(address, len))
        }
        .map_err(RepointPrivateError::indeterminate)?;
        self.vm
            .commit_anonymous_discard(prepared)
            .map_err(|error| {
                RepointPrivateError::indeterminate(MemoryError::HostMap(error.to_string()))
            })?;
        // Publish fresh-zero provenance only after the old translation and this
        // MM's authoritative aliases have been retired. Fork peers are untouched.
        deferred
            .reserve_fresh(carrick_guest_mem::GuestVa(address), len)
            .map_err(|error| {
                RepointPrivateError::indeterminate(MemoryError::HostMap(error.to_string()))
            })?;
        Ok(true)
    }

    fn zero_anonymous_reuse(
        &mut self,
        address: u64,
        len: usize,
        sharing: MappingSharing,
    ) -> Result<(), MemoryError> {
        if sharing == MappingSharing::Private
            && self.vm.sparse_mmap_arena_enabled()
            && ((address >= carrick_mem::memory::LINUX_MMAP_BASE
                && address.checked_add(len as u64).is_some_and(|end| {
                    end <= carrick_mem::memory::LINUX_MMAP_BASE
                        + carrick_mem::memory::mmap_arena_size()
                }))
                || (carrick_mem::memory::is_high_va(address)
                    && address
                        .checked_add(len as u64)
                        .is_some_and(|end| end <= (1u64 << 48))))
        {
            // HVPatch sparse arena retires private frames at munmap and allocates
            // pristine zeroed compounds on demand on first touch/fault.
            // Skipping the eager physical scrub keeps mmap service latency O(1).
            return Ok(());
        }
        self.zero_backing(address, len)
    }

    /// Host VA of a guest futex word IFF it lives in the `MAP_SHARED` aperture —
    /// routes a guest cross-process (`MAP_SHARED`) futex through the shared
    /// host-`SYS_futex` path on the same physical page. `None` for a private/COW
    /// word (those stay in-process via the parking-lot `FutexTable`).
    fn shared_futex_location(&self, guest_addr: u64) -> Option<SharedFutexLocation> {
        // Fork-lineage debug (CARRICK_FORK_DEBUG_VA=<hex guest VA>): name WHICH
        // gate refuses shared classification for that word. Every `None` below
        // silently lowers the op into the process-private FutexTable, where a
        // parent/child classification split is invisible until every waiter
        // times out (the sharedanonfutexfork / futexforkrequeue shape).
        let debug = fork_debug_va().is_some_and(|va| va == guest_addr);
        if !self.vm.protections().is_some_and(|protections| {
            protections.range_mutable_shared_backing(guest_addr, std::mem::size_of::<u32>())
        }) {
            if debug {
                match self.vm.protections() {
                    None => eprintln!(
                        "[FUTEXDBG] va={guest_addr:#x} REFUSED: backend exposes NO \
                         protections view"
                    ),
                    Some(protections) => eprintln!(
                        "[FUTEXDBG] va={guest_addr:#x} REFUSED: protections view live but \
                         mutable_shared_backing misses the word (ranges: {:?})",
                        protections.snapshot_all().mutable_shared_backing
                    ),
                }
            }
            return None;
        }
        // Futex identity is PHYSICAL, so always walk the live stage-1 tables.
        // Ordinary syscall buffers deliberately keep high aliases VA-keyed for
        // backend window lookup, but that policy is wrong here: HVPatch maps a
        // high guest VA (for example 0x100_0000_0000) to a stable global-frame
        // IPA. Passing the VA made both parent and child fall through to their
        // separate process-private FutexTables even though the frame receipt was
        // shared. A 4-byte-aligned futex word cannot cross a 4 KiB page.
        let backing_gpa = self
            .page_tables
            .with_manager(|page_tables| shared_futex_backing_gpa(page_tables, guest_addr));
        let Some(backing_gpa) = backing_gpa.flatten() else {
            if debug {
                eprintln!("[FUTEXDBG] va={guest_addr:#x} REFUSED: no leaf or no live tables");
            }
            return None;
        };
        let location = self.vm.shared_futex_location(backing_gpa);
        if debug {
            eprintln!(
                "[FUTEXDBG] va={guest_addr:#x} gpa={:#x} backend location: {}",
                backing_gpa.raw(),
                if location.is_some() {
                    "SHARED"
                } else {
                    "REFUSED (no shared mapping/alias covers the GPA)"
                }
            );
        }
        location
    }

    /// `mmap(MAP_PRIVATE, fd)` inside the sparse arena: hand an eligible file to
    /// the backend so it can materialize a direct view with page-granular COW
    /// instead of an eager snapshot. Unsupported ranges and mutable read-only
    /// host descriptors answer `Ok(false)` and the dispatcher snapshots.
    fn map_private_file_backed(
        &mut self,
        va: u64,
        len: usize,
        host_fd: std::os::fd::BorrowedFd<'_>,
        offset: u64,
        source: carrick_guest_mem::PrivateFileSource,
    ) -> Result<bool, MemoryError> {
        let eligible_range = self.process_asid.is_some()
            && self.vm.sparse_mmap_arena_enabled()
            && ((va >= carrick_mem::memory::LINUX_MMAP_BASE
                && va.checked_add(len as u64).is_some_and(|end| {
                    end <= carrick_mem::memory::LINUX_MMAP_BASE
                        .saturating_add(carrick_mem::memory::mmap_arena_size())
                }))
                || carrick_mem::memory::va_in_shared_aperture(va, len as u64));
        if !eligible_range || len == 0 {
            return Ok(false);
        }
        // Same editor precondition as `ensure_sparse_mmap_backing`: a fresh
        // materialization needs the software stage-1 editor.
        let editor_present = self.page_tables.is_present();
        ensure_sparse_page_table_editor(editor_present, || self.load_live_stage1_manager())?;
        let slot = self.mailbox_slot();
        let tables = self.page_tables.clone();
        let vm = &mut self.vm;
        let carrier_root = vm.carrier_maintenance_root().ok();
        let mut flush = EngineStage1Services::<V> {
            vcpu: self.vcpu.get_mut(),
            tables,
            slot,
            process_asid: self.process_asid,
            carrier_root,
            suspended_el1_sp: self.suspended_el1_sp,
            required_invalidation: None,
        };
        vm.materialize_private_file_backing(va, len, host_fd, offset, source, &mut flush)
            .map_err(|error| MemoryError::HostMap(format!("HVPatch private file backing: {error}")))
    }

    fn defer_private_file_backed(
        &mut self,
        va: u64,
        len: usize,
        host_fd: std::os::fd::BorrowedFd<'_>,
        offset: u64,
        source: carrick_guest_mem::PrivateFileSource,
    ) -> Result<bool, MemoryError> {
        if !self.supports_lazy_private_file_mmap()
            || len == 0
            || source != carrick_guest_mem::PrivateFileSource::ImmutableLower
        {
            return Ok(false);
        }
        let Some(granule) = self.vm.private_file_view_granule() else {
            return Ok(false);
        };
        if !granule.is_power_of_two() || va & (granule - 1) != offset & (granule - 1) {
            return Ok(false);
        }
        let state = self
            .vm
            .deferred_anonymous_state()
            .ok_or_else(|| MemoryError::HostMap("missing deferred mmap state".to_owned()))?;
        state
            .reserve_private_file(GuestVa(va), len, host_fd, offset, source)
            .map_err(|error| {
                MemoryError::HostMap(format!("defer private file backing: {error}"))
            })?;
        Ok(true)
    }

    /// Make a guest `mprotect`/`mmap`'s protection GUEST-visible by editing the
    /// live stage-1 tables. PROT_EXEC clears UXN (executable); its absence sets UXN
    /// (NX / W^X), matching Linux — so the dynamic loader's freshly-mapped library
    /// text (PROT_READ|PROT_EXEC) actually executes instead of permission-faulting
    /// on the NX-by-default arena. (Boot regions — image text, trampolines, vDSO —
    /// are mapped executable at boot and never edited here.)
    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        use carrick_abi::{LINUX_PROT_EXEC, LINUX_PROT_READ, LINUX_PROT_WRITE};
        if prot & (LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) != 0 {
            self.ensure_sparse_mmap_backing(address, len)?;
        }
        let armed_cow = if prot & LINUX_PROT_WRITE != 0 {
            self.vm.armed_frame_cow_ranges(address, len)
        } else {
            Vec::new()
        };
        let new_mapping = self.pending_new_mapping.take() == Some((address, len));
        // One plan for both lanes. A guest can `mprotect` an ALREADY-TOUCHED
        // page (e.g. RELRO RW→RO), so a changed valid leaf is invalidated:
        // by the host TLBI, or by EL1 on the guest-owned lane.
        let plan = crate::stage1_authority::protection_terminal_rules(
            address,
            len,
            prot,
            &armed_cow,
            new_mapping,
        );
        if let Err(error) = self.apply_stage1_rules((address, len), &plan) {
            // Phase 3: the stage-1 protection edit refused; name the first
            // page's live terminal (the leaf the rule could not take).
            self.trace_read_fault(address, len, 3);
            return Err(error);
        }
        self.vm
            .observe_frame_cow_protection(address, len, prot)
            .map_err(|error| {
                MemoryError::HostMap(format!(
                    "authenticate deferred HVPatch COW protection: {error}"
                ))
            })
    }

    /// `munmap`: invalidate the stage-1 descriptors for `[address, address+len)` so
    /// the guest's own access faults (vs the host-side `no_access` check). The
    /// unmapped range is typically ALREADY-TOUCHED, so flush the stale TLB entry.
    fn restore_shared_identity(&mut self, va: u64, len: usize) -> Result<(), MemoryError> {
        let len_u64 = u64::try_from(len).map_err(|_| MemoryError::OutOfBounds {
            address: va,
            length: len,
        })?;
        if self.page_tables.live_descriptor_owner() == LiveDescriptorOwner::Guest {
            // EL1 publishes the identity leaves (`MapAlias` named by the
            // aperture's live inventory extent) with the host editor's
            // `map_aliased` user flags. Stage-1 only, like the host lane.
            let slot = self.mailbox_slot();
            let carrier_root = self.vm.carrier_maintenance_root().ok();
            let mut services = EngineStage1Services::<V> {
                vcpu: self.vcpu.get_mut(),
                tables: self.page_tables.clone(),
                slot,
                process_asid: self.process_asid,
                carrier_root,
                suspended_el1_sp: self.suspended_el1_sp,
                required_invalidation: None,
            };
            return self
                .vm
                .restore_guest_shared_identity(va, len, &mut services)
                .map_err(|error| {
                    MemoryError::HostMap(format!("guest shared identity restore: {error}"))
                });
        }
        // The aperture leaf goes back to its own frame read/write and
        // non-executable; the caller publishes the mapping's protection next.
        self.pt_edit_and_flush_after_adopting(va, len, |mgr| {
            mgr.map_aliased(va, va, len_u64, UserLeafAccess::READ_WRITE)
                .map(|changed| PageTableApplyOutcome::new(changed, changed))
        })
    }

    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        let span = carrick_mmu_core::aarch64::descriptor_txn::PageSpan::new(address, len as u64);
        trace_el1_mapping_leafs(
            self,
            El1MappingLeafPhase::BeforeUnmap,
            self.mm_generation,
            span,
            address,
        );
        // Teardown the checked stage-1 path and flush stale translations first.
        // Only then retire process-shared backend lookup metadata. If the page-
        // table/TLBI operation fails, the alias registry remains an exact owner
        // of the still-published backing instead of becoming a dangling absence.
        if self.vm.sparse_mmap_arena_enabled()
            && ((address >= carrick_mem::memory::LINUX_MMAP_BASE
                && address.checked_add(len as u64).is_some_and(|end| {
                    end <= carrick_mem::memory::LINUX_MMAP_BASE
                        .saturating_add(carrick_mem::memory::mmap_arena_size())
                }))
                || carrick_mem::memory::is_high_va(address))
        {
            self.retire_stage1_range(address, len, true)?;
        } else {
            self.retire_stage1_range(address, len, false)?;
        }
        self.vm.on_unmap(address, len).map_err(|error| {
            MemoryError::HostMap(format!("retire backend mapping after munmap: {error}"))
        })?;
        self.set_unmapped(address, len, true);
        trace_el1_mapping_leafs(
            self,
            El1MappingLeafPhase::AfterUnmap,
            self.mm_generation,
            span,
            address,
        );
        Ok(())
    }

    /// `munmap` of a high-VA alias: invalidate AND reclaim the now-empty alias
    /// sub-table(s) (vs `unmap_range`, which keeps the table for the low-VA arena's
    /// in-place reuse). Flush the stale TLB entry. Mirrors HVF.
    fn unmap_alias_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        // Reclaim the alias leaves/table and complete TLBI before unregistering
        // backend lookup metadata. An Err therefore leaves the alias registry
        // intact and consistent with the still-owned host/stage-2 backing.
        self.retire_stage1_range(address, len, true)?;
        self.vm.on_unmap(address, len).map_err(|error| {
            MemoryError::HostMap(format!("retire backend alias after munmap: {error}"))
        })?;
        self.set_unmapped(address, len, true);
        Ok(())
    }

    /// Repoint guest VA `[va, va+len)` to a slot in the boot-mapped PRIVATE overlay
    /// aperture (`overlay_ipa`, identity IPA==VA), seeding the slot with the exact
    /// file or zero `content` snapshot first. Backs a guest
    /// `mmap(MAP_FIXED|MAP_PRIVATE)` over a SHARED-aperture VA: carrick's shared
    /// aperture is host-`MAP_SHARED`, so it is
    /// inherited across `fork(2)` AND visible to sibling carrick processes —
    /// leaving the VA pointed there would make a guest's "private" stores leak.
    ///
    /// (1) seed the overlay backing FIRST, while `va` still translates to the OLD
    /// (shared) IPA, so no concurrent reader sees a torn page through `va` during
    /// the flip; (2) `pt_edit_and_flush(map_aliased)` repoints the stage-1 leaf
    /// (splitting any covering boot block down to a page leaf) and — because the
    /// dispatcher may have ALREADY touched the overlay VA — runs the EL1-maintenance
    /// TLBI so any stale stage-1 entry is invalidated.
    fn repoint_private(
        &mut self,
        va: u64,
        overlay_slot_va: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), RepointPrivateError> {
        if content.len() != len {
            return Err(RepointPrivateError::clean(MemoryError::OutOfBounds {
                address: va,
                length: content.len(),
            }));
        }
        // 1. Resolve the overlay slot's host backing pointer (the same resolver the
        //    live page-table editor's `sync_to_host` uses). `len.max(1)` so a
        //    zero-length repoint still resolves the start page.
        // The overlay allocator returns its semantic slot VA. Initial boot is
        // identity-mapped, but an HVPatch exec replacement assigns that same
        // physical frame a stable global IPA. Resolve through the current mm's
        // stage-1 graph before touching backing or publishing the replacement
        // leaf; treating the slot VA as an IPA made post-exec MAP_FIXED fail
        // with ENOMEM despite the frame being live.
        // The overlay aperture is sealed PROT_NONE in every image (it is never
        // guest memory through its own VA), so its frame address is the
        // retained output of the slot's leaf.
        let overlay_ipa = self
            .page_tables
            .with_manager(|manager| {
                manager
                    .translate(overlay_slot_va)
                    .or_else(|| manager.translate_retained_output(overlay_slot_va))
            })
            .flatten()
            .ok_or_else(|| {
                RepointPrivateError::clean(MemoryError::OutOfBounds {
                    address: overlay_slot_va,
                    length: len,
                })
            })?;
        if self.page_tables.live_descriptor_owner() == LiveDescriptorOwner::Guest {
            return self
                .repoint_guest_alias(
                    va,
                    overlay_ipa,
                    len,
                    Some(content),
                    UserLeafAccess::READ_WRITE,
                )
                .map_err(RepointPrivateError::indeterminate);
        }
        let dst = self.vm.host_ptr(overlay_ipa, len.max(1)).ok_or_else(|| {
            RepointPrivateError::clean(MemoryError::OutOfBounds {
                address: overlay_ipa,
                length: len,
            })
        })?;
        // 2. Seed `content` into the overlay backing FIRST, while `va` still
        //    translates to the OLD (shared) IPA — no torn read through `va` during
        //    the flip.
        if !content.is_empty() {
            // SAFETY: `host_ptr` proved `[overlay_ipa, overlay_ipa+len)` lies wholly
            // within the overlay slot's backing, and `content` is exactly `len`
            // distinct, valid source bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(content.as_ptr(), dst, len);
            }
        }
        // 3. Stage-1 repoint + TLB flush. `map_aliased` splits the covering boot
        //    block to a page leaf so a single page within the shared aperture is
        //    repointed without disturbing its neighbours; the flush invalidates any
        //    stale stage-1 entry for an already-touched overlay VA.
        // The cached manager is process-persistent. Even when an edit error
        // prevents `sync_to_host`, a multi-leaf operation may have changed its
        // scratch image; fail stopped so a later successful edit cannot publish
        // partial leaves after this candidate was recycled.
        let outcome = self
            .pt_edit_locked(|mgr| {
                // Read/write and non-executable until the caller publishes
                // the new mapping's protection (`protect_range`).
                mgr.map_aliased(va, overlay_ipa, len as u64, UserLeafAccess::READ_WRITE)
                    .map(|changed| PageTableApplyOutcome::new(changed, changed))
            })
            .map_err(RepointPrivateError::indeterminate)?;
        if !outcome.changed {
            return Ok(());
        }
        classify_private_repoint_tlbi(self.run_stage1_maintenance())?;
        self.vm
            .publish_private_repoint(va, overlay_ipa, len, UserLeafAccess::READ_WRITE)
            .map_err(|error| {
                RepointPrivateError::indeterminate(MemoryError::HostMap(format!(
                    "publish private repoint frame ownership: {error}"
                )))
            })
    }

    fn repoint_shared_leaf(
        &mut self,
        va: u64,
        target_ipa: u64,
        len: usize,
        prot: u64,
    ) -> Result<(), MemoryError> {
        use carrick_abi::{LINUX_PROT_EXEC, LINUX_PROT_READ, LINUX_PROT_WRITE};
        let access = UserLeafAccess::from_linux_prot(prot);
        let prot_none = prot & (LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) == 0;
        if self.page_tables.live_descriptor_owner() == LiveDescriptorOwner::Guest {
            self.repoint_guest_alias(va, target_ipa, len, None, access)?;
            return if prot_none {
                self.protect_range(va, len, 0)
            } else {
                Ok(())
            };
        }
        let outcome = self
            .pt_edit_locked(|mgr| {
                mgr.map_aliased(va, target_ipa, len as u64, access)
                    .map(|changed| PageTableApplyOutcome::new(changed, changed))
            })
            .map_err(|e| MemoryError::HostMap(format!("repoint shared leaf pt edit: {e}")))?;
        if !outcome.changed {
            return if prot_none {
                self.protect_range(va, len, 0)
            } else {
                Ok(())
            };
        }
        self.run_stage1_maintenance()
            .map_err(|e| MemoryError::HostMap(format!("repoint shared leaf tlbi: {e}")))?;
        self.vm
            .publish_shared_repoint(va, target_ipa, len, access)
            .map_err(|e| MemoryError::HostMap(format!("publish shared repoint: {e}")))?;
        // A PROT_NONE move keeps its output and loses its access only after
        // the ownership edge is published against the live leaf.
        if prot_none {
            self.protect_range(va, len, 0)?;
        }
        Ok(())
    }

    fn translate_va(&self, va: u64) -> Option<u64> {
        self.page_tables
            .with_manager(|mgr| mgr.translate(va))
            .flatten()
    }
}

#[cfg(test)]
fn apply_stage1_protection_edit(
    mgr: &mut PageTableManager,
    address: u64,
    len: usize,
    prot: u64,
    armed_cow: &[crate::vmm::ForkCowRange],
) -> Result<PageTableApplyOutcome, PageTableError> {
    let mut source: Option<Box<dyn carrick_mmu_core::aarch64::TableArenaSource>> = None;
    let mut editor = crate::stage1_authority::Stage1Editor {
        manager: mgr,
        arena_source: &mut source,
    };
    editor.apply_protection_edit(address, len, prot, armed_cow)
}

impl<V: Aarch64Vmm> CurrentMmMemory for Aarch64EngineCore<V> {}

fn classify_private_repoint_tlbi(result: Result<(), TrapError>) -> Result<(), RepointPrivateError> {
    result.map_err(|error| {
        RepointPrivateError::indeterminate(MemoryError::HostMap(format!(
            "stage-1 TLBI after private repoint failed: {error}"
        )))
    })
}

// ─── RegAccess ───────────────────────────────────────────────────────────────

impl<V: Aarch64Vmm> carrick_hal::RegAccess for Aarch64EngineCore<V> {
    fn get_reg(&self, r: Reg) -> Result<u64, OsError> {
        self.vcpu.borrow().get_reg(r).map_err(trap_to_os)
    }
    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), OsError> {
        self.vcpu.get_mut().set_reg(r, v).map_err(trap_to_os)
    }
    fn get_sys_reg(&self, r: SysReg) -> Result<u64, OsError> {
        self.vcpu.borrow().get_sys_reg(r).map_err(trap_to_os)
    }
    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), OsError> {
        self.vcpu.get_mut().set_sys_reg(r, v).map_err(trap_to_os)
    }
    fn get_vreg(&self, n: u32) -> Result<u128, OsError> {
        self.vcpu.borrow().get_vreg(n).map_err(trap_to_os)
    }
    fn set_vreg(&mut self, n: u32, v: u128) -> Result<(), OsError> {
        self.vcpu.get_mut().set_vreg(n, v).map_err(trap_to_os)
    }
    fn get_fpcr(&self) -> Result<u64, OsError> {
        self.vcpu.borrow().get_fpcr().map_err(trap_to_os)
    }
    fn set_fpcr(&mut self, v: u64) -> Result<(), OsError> {
        self.vcpu.get_mut().set_fpcr(v).map_err(trap_to_os)
    }
    fn get_fpsr(&self) -> Result<u64, OsError> {
        self.vcpu.borrow().get_fpsr().map_err(trap_to_os)
    }
    fn set_fpsr(&mut self, v: u64) -> Result<(), OsError> {
        self.vcpu.get_mut().set_fpsr(v).map_err(trap_to_os)
    }
}

// ─── SyscallTrap ─────────────────────────────────────────────────────────────

impl<V: Aarch64Vmm> SyscallTrap for Aarch64EngineCore<V> {
    fn frame_inventory_extent_count(&self) -> usize {
        self.vm.frame_inventory_extent_count()
    }

    fn inventory_initial_mappings(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<carrick_hal::FrameInventoryCommit<()>, TrapError> {
        self.vm.inventory_initial_mappings(reservation)
    }

    fn begin_alias_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.vm.begin_alias_inventory(reservation)
    }

    fn take_alias_inventory(&mut self) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        self.vm.take_alias_inventory()
    }

    fn abandon_alias_inventory(&mut self) -> bool {
        self.vm.abandon_alias_inventory()
    }

    fn frame_inventory_exec_extent_counts(&self, new_image: &AddressSpace) -> (usize, usize) {
        self.vm.frame_inventory_exec_extent_counts(new_image)
    }

    fn inject_next_begin_exec_inventory_failure(&mut self) {
        self.vm.inject_next_begin_exec_inventory_failure();
    }

    fn begin_exec_inventory(
        &mut self,
        retired: Option<carrick_hal::FrameInventoryReservation>,
        replacement: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.vm.begin_exec_inventory(retired, replacement)
    }

    fn take_exec_inventory(&mut self) -> Option<carrick_hal::ExecInventoryCommits> {
        self.vm.take_exec_inventory()
    }

    fn next_syscall(&mut self) -> Result<Option<RawSyscall>, TrapError> {
        let armed = self.arm_resume_invalidation()?;
        let result = self.run_to_next_syscall();
        if let Some(owed) = armed {
            // Kicks inside the entry are absorbed and re-run, so any surfaced
            // exit lies past it: the invalidation completed. Stopped inside it
            // (a failed run) the debt stays owed.
            let layout = carrick_mem::memory::mailbox_resume_layout();
            match self.vcpu.get_mut().get_reg(Reg::Pc) {
                Ok(pc) if !(layout.entry..layout.end).contains(&pc) => owed.complete_on_return(),
                _ => self.owed_resume_invalidation = Some(owed),
            }
        }
        result
    }

    fn last_syscall_nr(&self) -> Option<u64> {
        self.last_syscall_nr
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        self.vcpu.borrow().get_reg(Reg::Pc)
    }

    fn process_exit_cleanup(&mut self) -> Result<(), TrapError> {
        self.settle_owed_resume_invalidation_or_log();
        self.vm.process_exit_cleanup()
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        // The pending state is engine-owned; clear it. On aarch64 the EL1 vector's
        // `eret` already consumed ELR_EL1 (= svc+4), so we do NOT re-advance the
        // PC — we just write x0 (and restore x9, below).
        self.pending_resume_pc = None;
        // The backend owns the completion vehicle. KVM's default writes x0 and
        // restores its sentinel-clobbered x9; HVF mailbox mode release-publishes
        // the return payload without register calls. ELR_EL1 already points past
        // the SVC, so neither path advances PC here.
        self.vcpu.get_mut().complete_syscall_return(return_value)
    }

    fn is_forked_child(&self) -> bool {
        self.is_forked_child
    }

    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError> {
        self.settle_owed_resume_invalidation()?;
        let expected_shared = self.exec_predecessor_shared.take();
        let authority_id = self.page_tables.authority_id();
        // Delegate the image replacement to the backend (remap slots / rebuild VM +
        // reprogram the live vCPU's sysregs). PRESERVE is_forked_child across execve:
        // a descendant of a forked child keeps the `_exit`-without-report shutdown
        // path even after it execve's into a different image. The flag is a plain
        // field on `self`, untouched by the remap.
        self.vm.execve_rebuild(self.vcpu.get_mut(), new_image)?;
        // `execve_rebuild` installed a fresh table image. Drop the manager for
        // the old image before the hvpatch ASID configuration reserves its
        // per-mm root-slot aperture in the NEW tables.
        let was_shared = self.replace_page_tables(self.vm.exec_page_tables())?;
        if let Some(expected) = expected_shared
            && expected != was_shared
        {
            tracing::warn!(
                authority_id,
                expected_shared = expected,
                actual_shared = was_shared,
                "execve stage-1 authority sharing expectation mismatch"
            );
        }
        if let Some(protections) = self.vm.exec_protections() {
            self.protections = protections;
        }
        if let Some(legacy) = self.protections.legacy() {
            seed_heap_unmapped(&legacy);
        }
        if let Some(asid) = self.process_asid {
            <Self as ThreadedEngine>::configure_process_asid(self, asid)?;
        }
        // A fresh image has no in-flight syscall or fault.
        self.pending_resume_pc = None;
        self.last_syscall_nr = None;
        self.last_syscall_orig_x0 = 0;
        self.last_fault_esr = 0;
        Ok(())
    }

    fn map_host_alias(
        &mut self,
        va: GuestVa,
        ipa: Gpa,
        len: u64,
        payload: &[u8],
        backing: HostAliasBacking,
    ) -> Result<(), TrapError> {
        // Back a dynamic alias mapping and return the authoritative GPA, then
        // install the guest VA -> GPA stage-1 PTE. `backing` carries the
        // dispatcher's sharing classification: HVPatch uses it to distinguish
        // anonymous fork sharing from its VM-global shared-file namespace and
        // to choose MAP_PRIVATE vs MAP_SHARED host file backing.
        //
        // Alias VAs are not necessarily fresh: deferred commitment replaces a
        // PROT_NONE reservation, and MAP_FIXED can replace an older alias. The
        // vCPU may therefore retain an invalid walk-cache entry or a stale leaf.
        // Publish through the same edit + TLBI path as mprotect/munmap before the
        // guest resumes; a successful stage-2 hv_vm_map alone is not sufficient.
        let (gpa, writable) = self
            .vm
            .add_alias(va.raw(), ipa.raw(), len, payload, backing)?;
        if self.page_tables.live_descriptor_owner() == LiveDescriptorOwner::Guest {
            return self.map_host_alias_on_guest_lane(va, gpa, len, writable);
        }
        let mut descriptors = [0_u64; 4];
        let page_table_result = self.pt_edit_and_flush(|mgr| {
            // Never executable here: a PROT_EXEC alias is published by the
            // caller's `protect_range` with the mapping's own protection.
            let changed = mgr.map_aliased(
                va.raw(),
                gpa,
                len,
                UserLeafAccess {
                    writable,
                    executable: false,
                },
            )?;
            descriptors = mgr.debug_walk(va.raw());
            Ok(PageTableApplyOutcome::new(changed, changed))
        });
        let walk_flags =
            i32::from(self.is_forked_child) | (i32::from(page_table_result.is_err()) << 1);
        carrick_observability::probes::pt_alias_walk(va.raw(), descriptors, walk_flags);
        if page_table_result.is_ok() {
            let live_descriptors = self.live_pt_debug_walk(va.raw());
            let live_flags = walk_flags | (1 << 2) | (i32::from(live_descriptors.is_err()) << 1);
            carrick_observability::probes::pt_alias_walk(
                va.raw(),
                live_descriptors.unwrap_or([0_u64; 4]),
                live_flags,
            );
        }
        if let Err(error) = page_table_result {
            // Roll the alias inventory staging back BEFORE tearing the mapping
            // down. `add_alias` has already staged an extent that
            // names a freshly claimed MappingId, and the authority does not
            // learn about that mapping until the commit is applied — which has
            // not happened yet, and now never will.
            //
            // `unmap_alias_range` is the RETIREMENT path: it walks the extents
            // covering this VA's stage-2 lease and stages an `UnmapMapping` for
            // each. Run in this order it would pick up the extent staged
            // moments ago and ask the authority to retire a mapping it has
            // never seen, aborting the whole carrier with
            // `mapping MappingId(N) is not live` — every Linux process
            // multiplexed into it, for one process's failed mmap. Discarding
            // the staging first leaves the retirement with nothing to retire,
            // which it handles by simply unregistering the alias.
            //
            // Reproduced by `reducers/alias-churn-fatal.py`: a few hundred
            // MAP_SHARED map/unmap cycles reach a stage-1 failure and abort
            // deterministically. It is also the crash that killed
            // `cpython-multiprocessing_spawn`.
            self.vm.abandon_alias_inventory();
            let cleanup_len = usize::try_from(len).unwrap_or_else(|_| {
                carrick_fatal!(
                    "aarch64::alias_cleanup",
                    "host alias mapping length {len:#x} exceeded host pointer width during failure cleanup unwinding"
                );
            });
            if let Err(unmap_error) = self.unmap_alias_range(va.raw(), cleanup_len) {
                carrick_fatal!(
                    "aarch64::alias_cleanup",
                    "failed to unmap staged alias range at {:#x} (len {:#x}) after hypervisor alias mapping failure: {unmap_error}",
                    va.raw(),
                    cleanup_len
                );
            }
            return Err(memory_error_to_trap_error(
                error,
                "stage-1 alias page table mapping failed",
            ));
        }
        Ok(())
    }

    fn inject_signal(&mut self, signal: carrick_hal::SignalInjection) -> Result<(), TrapError> {
        let carrick_hal::SignalInjection {
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc,
            altstack,
            saved_sigmask,
            fault_siginfo,
            queued_siginfo,
            restart_syscall,
        } = signal;
        use carrick_hal::RegAccess as _;
        // Choose the resume mechanism by the LIVE exception level, NOT by whether the
        // caller supplied an interrupted_pc. When the vCPU is at EL1 (inside the EL1
        // trampoline — a syscall boundary OR a just-serviced rt_sigreturn), the
        // interrupted USER context is latched in ELR_EL1/SPSR_EL1 and the handler
        // must enter via the pending `eret` (which drops to EL0t). A caller-supplied
        // interrupted_pc is the x86 rt_sigreturn resume-RIP workaround (vcpu_loop
        // sets signal_interrupted_pc after SigReturn); on aarch64 it is an EL1
        // trampoline PC, and taking the "kick" path for it (overwrite the live PC,
        // keep the EL1 PSTATE) would run the handler AT EL1 → its first PXN
        // instruction fetch aborts. Normalising interrupted_pc to None when at EL1
        // routes saved_pc/PSTATE/handler-entry through the eret path so the handler
        // runs at EL0t. Genuine EL0 kicks (the run loop's CANCELED handler guarantees
        // is_guest) keep the live-CPSR kick path. A durable wake can race the
        // caller's post-exit signal drain and reach this function with NO caller
        // hint while the vCPU is still live at EL0. In that case the exception
        // level remains authoritative: upgrade to the live PC rather than saving
        // stale ELR_EL1 and redirecting the handler into an eret that does not
        // exist. (KVM never sets interrupted_pc on aarch64, so this also makes its
        // live-EL0 authority explicit rather than caller-dependent.)
        let live_pstate = self.get_reg(Reg::Pstate)?;
        let interrupted_pc =
            signal_interrupted_pc_for_live_level(live_pstate, interrupted_pc, || {
                self.get_reg(Reg::Pc)
                    .map_err(|error| TrapError::Hypervisor(error.to_string()))
            })?;
        let pending_syscall_retval =
            pending_syscall_retval_for_boundary(pending_syscall_retval, interrupted_pc, || {
                self.vcpu.get_mut().pending_syscall_return()
            })?;
        // The interrupted PSTATE to save into the sigframe: KICK path (interrupted_pc
        // set, EL0) → the live CPSR we just read; SYSCALL/eret path → SPSR_EL1 where
        // the `svc`/sigreturn-svc latched the EL0 PSTATE. Single-sourced (F7); reuse
        // the already-read `live_pstate` for the kick path.
        let pstate_source =
            carrick_hal::aarch64_signal_pstate_source(interrupted_pc, Some(live_pstate), |r| {
                self.get_reg(r)
            })
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        let params = carrick_hal::sigframe::InjectParams {
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc,
            altstack,
            saved_sigmask,
            fault_siginfo,
            queued_siginfo,
            restart_syscall,
            pstate_source,
            orig_x0: self.last_syscall_orig_x0,
            fault_esr: self.last_fault_esr,
            // HVF gates FP/SIMD save on `CARRICK_NO_FPSIMD` (differential measurement);
            // KVM keeps the default `true`.
            fpsimd_enabled: self.vm.fpsimd_enabled(),
            sigreturn_trampoline_base: carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_BASE,
        };
        let info = <Self as ThreadedEngine>::Arch::build_sigframe(self, params)?;
        carrick_observability::probes::signal_inject(signum, info.saved_pc, info.new_sp, handler);
        // The fault ESR is only valid between fault and delivery; clear it so a
        // later async signal doesn't reuse a stale synchronous-fault syndrome.
        self.last_fault_esr = 0;
        self.vcpu.get_mut().prepare_register_resume()
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        // fpsimd_enabled MUST match inject_signal. Returns the SAVED SIGMASK — not
        // saved_pc — mirroring the per-backend impls.
        let fpsimd = self.vm.fpsimd_enabled();
        let r = <Self as ThreadedEngine>::Arch::restore_sigframe(self, fpsimd)?;
        carrick_observability::probes::signal_restore(r.saved_pc, r.frame_sp, r.magic);
        self.vcpu.get_mut().prepare_register_resume()?;
        Ok(r.sigmask)
    }
}

impl<V: Aarch64Vmm> Aarch64EngineCore<V> {
    /// Guest-owned lane of [`SyscallTrap::map_host_alias`], after `add_alias`
    /// staged stage-2 backing and inventory. The backend applies the
    /// inventory, then publishes the leaves through EL1 (the kernel authority
    /// must know the mapping before a `MapAlias` can name its revision). On
    /// refusal the end state equals the host lane's cleanup: the VA span
    /// retired at stage-1, no inventory for the alias, the alias
    /// unregistered and the range marked unmapped.
    fn map_host_alias_on_guest_lane(
        &mut self,
        va: GuestVa,
        gpa: u64,
        len: u64,
        writable: bool,
    ) -> Result<(), TrapError> {
        use crate::vmm::GuestAliasRefusal;
        let slot = self.mailbox_slot();
        let carrier_root = self.vm.carrier_maintenance_root().ok();
        let mut services = EngineStage1Services::<V> {
            vcpu: self.vcpu.get_mut(),
            tables: self.page_tables.clone(),
            slot,
            process_asid: self.process_asid,
            carrier_root,
            suspended_el1_sp: self.suspended_el1_sp,
            required_invalidation: None,
        };
        let refusal =
            match self
                .vm
                .publish_guest_host_alias(va.raw(), gpa, len, writable, &mut services)
            {
                Ok(()) => {
                    // EL1 wrote the leaves, so only the live walk (bit 2) is a
                    // receipt; the host manager image does not see them.
                    let live = self.live_pt_debug_walk(va.raw());
                    let flags = i32::from(self.is_forked_child)
                        | (1 << 2)
                        | (i32::from(live.is_err()) << 1);
                    carrick_observability::probes::pt_alias_walk(
                        va.raw(),
                        live.unwrap_or([0_u64; 4]),
                        flags,
                    );
                    return Ok(());
                }
                Err(refusal) => refusal,
            };
        let cleanup_len = usize::try_from(len).unwrap_or_else(|_| {
            carrick_fatal!(
                "aarch64::alias_cleanup",
                "guest alias length {len:#x} exceeded host pointer width during failure cleanup unwinding"
            );
        });
        let error = match refusal {
            GuestAliasRefusal::BeforeInventory(error) => {
                // The authority never saw the mapping: discard the staging
                // first (see the host-lane arm), then retire whatever the VA
                // span held, as the host lane's `unmap_aliased` does.
                self.vm.abandon_alias_inventory();
                if let Err(retire) = self.apply_stage1_rules(
                    (va.raw(), cleanup_len),
                    &[(va.raw(), cleanup_len, TerminalRule::pt(PtOp::Retire))],
                ) {
                    carrick_fatal!(
                        "aarch64::alias_cleanup",
                        "failed to retire guest alias range at {:#x} (len {:#x}) after a refused publication: {retire}",
                        va.raw(),
                        cleanup_len
                    );
                }
                error
            }
            // The backend retired the span and rolled the grant back.
            GuestAliasRefusal::RolledBack(error) => error,
        };
        if let Err(unregister) = self.vm.on_unmap(va.raw(), cleanup_len) {
            carrick_fatal!(
                "aarch64::alias_cleanup",
                "failed to unregister guest alias at {:#x} (len {:#x}) after a refused publication: {unregister}",
                va.raw(),
                cleanup_len
            );
        }
        self.set_unmapped(va.raw(), cleanup_len, true);
        Err(memory_error_to_trap_error(
            MemoryError::HostMap(format!("guest alias publication: {error}")),
            "stage-1 alias page table mapping failed",
        ))
    }
}

fn signal_interrupted_pc_for_live_level(
    live_pstate: u64,
    interrupted_pc: Option<u64>,
    live_pc: impl FnOnce() -> Result<u64, TrapError>,
) -> Result<Option<u64>, TrapError> {
    if carrick_hal::aarch64::ExecLevel::from_pstate(live_pstate).is_guest() {
        interrupted_pc.map_or_else(|| live_pc().map(Some), |pc| Ok(Some(pc)))
    } else {
        Ok(None)
    }
}

fn pending_syscall_retval_for_boundary(
    caller: Option<i64>,
    interrupted_pc: Option<u64>,
    backend: impl FnOnce() -> Result<Option<i64>, TrapError>,
) -> Result<Option<i64>, TrapError> {
    if caller.is_none() && interrupted_pc.is_none() {
        backend()
    } else {
        Ok(caller)
    }
}

// ─── ThreadedEngine ──────────────────────────────────────────────────────────

/// The `Send` payload `build_sibling_spec` hands to a freshly spawned host thread,
/// which `materialize_sibling` turns into a sibling engine. Backend-parameterized:
/// the backend supplies how to build a sibling VM/vCPU from `builder`; the SEEDED
/// register snapshot + the SHARED page-table editor / PROT_NONE set ride along so
/// the new vCPU runs in the SAME guest address space on the SAME VM.
pub struct Aarch64SiblingSpec<V: Aarch64Vmm> {
    builder: V::SiblingBuilder,
    snapshot: Aarch64VcpuSnapshot,
    /// The parent's live stage-1 page-table authority, SHARED (Arc clone): a
    /// `clone(CLONE_THREAD)` sibling runs on the SAME VM with the SAME page-table
    /// backing, so its `mmap`/`mprotect` edits must go through the SAME authority.
    page_tables: Stage1Authority,
    /// The parent's PROT_NONE bookkeeping, SHARED (Arc clone). On KVM the
    /// load-bearing share is inside the backend `GuestRam` (via
    /// `from_shared_windows`); this is the engine-side mirror.
    protections: UserMemoryAuthority,
    process_asid: Option<u16>,
}

pub struct Aarch64ProcessSpec<V: Aarch64Vmm> {
    builder: V::ProcessBuilder,
    snapshot: Aarch64VcpuSnapshot,
    page_tables: Stage1Authority,
    protections: UserMemoryAuthority,
    process_asid: u16,
}

pub struct Aarch64SiblingTaskOnlyParts<V: Aarch64Vmm> {
    pub builder: V::SiblingBuilder,
    pub snapshot: Aarch64VcpuSnapshot,
    pub page_tables: Stage1Authority,
    pub protections: UserMemoryAuthority,
    pub process_asid: Option<u16>,
}

pub struct Aarch64ProcessTaskOnlyParts<V: Aarch64Vmm> {
    pub builder: V::ProcessBuilder,
    pub snapshot: Aarch64VcpuSnapshot,
    pub page_tables: Stage1Authority,
    pub protections: UserMemoryAuthority,
    pub process_asid: u16,
}

impl<V: Aarch64Vmm> Aarch64SiblingSpec<V> {
    pub fn into_task_only_parts(self) -> Aarch64SiblingTaskOnlyParts<V> {
        Aarch64SiblingTaskOnlyParts {
            builder: self.builder,
            snapshot: self.snapshot,
            page_tables: self.page_tables,
            protections: self.protections,
            process_asid: self.process_asid,
        }
    }
}

impl<V: Aarch64Vmm> Aarch64ProcessSpec<V> {
    pub fn into_task_only_parts(self) -> Aarch64ProcessTaskOnlyParts<V> {
        Aarch64ProcessTaskOnlyParts {
            builder: self.builder,
            snapshot: self.snapshot,
            page_tables: self.page_tables,
            protections: self.protections,
            process_asid: self.process_asid,
        }
    }
}

unsafe impl<V: Aarch64Vmm> Send for Aarch64ProcessSpec<V> where V::ProcessBuilder: Send {}

// SAFETY: the snapshot is POD; the page-table / protections `Arc`s are Send+Sync;
// the builder is the backend's own bounded-`Send` payload.
unsafe impl<V: Aarch64Vmm> Send for Aarch64SiblingSpec<V> where V::SiblingBuilder: Send {}

/// Seed a fresh sibling vCPU's register file for a `clone(CLONE_THREAD)` thread.
/// Starts from the parent snapshot (inheriting the SAME stage-1 MMU sysregs +
/// guest address space) then applies the aarch64 thread-entry deltas: x0 = the
/// clone return value, SP_EL0 = the child stack, TPIDR_EL0 = the TLS base,
/// PC = parent.elr_el1 (the post-svc address), and PSTATE = parent.spsr_el1 (the
/// EL0t resume PSTATE the `svc` latched — NOT the EL1h trap-time PSTATE, or the
/// sibling would re-enter at the wrong exception level). FP/SIMD is carried
/// verbatim. This is aarch64-shared logic (lifted from KVM's `seed_sibling_snapshot`).
fn seed_sibling_snapshot(
    parent: &Aarch64VcpuSnapshot,
    entry: GuestEntryRegs,
) -> Aarch64VcpuSnapshot {
    let mut snap = parent.clone();
    snap.gprs[0] = entry.return_value;
    if let Some(stack) = entry.stack {
        snap.sp_el0 = stack;
    }
    if let Some(tls) = entry.tls {
        snap.tpidr_el0 = tls;
    }
    snap.pc = parent.elr_el1;
    // EL0-resume PSTATE: the SPSR latched on the parent's `svc` trap IS the EL0t
    // PSTATE the new thread must run with. Without this the sibling restores the
    // EL1h trap-time PSTATE and re-enters at the wrong exception level.
    snap.pstate = parent.spsr_el1;
    // A new logical thread starts with a neutral architectural CONTEXTIDR.
    // Its Linux identity is owned by its lifecycle control slot.
    snap.contextidr_el1 = 0;
    snap
}

impl<V: Aarch64Vmm> ThreadedEngine for Aarch64EngineCore<V> {
    fn el1_switchable_roots(&self) -> Option<(u64, u64)> {
        self.vcpu.borrow_mut().el1_switchable_roots()
    }

    fn fd_ceiling_publisher(&self) -> Option<std::sync::Arc<dyn carrick_hal::FdCeilingPublisher>> {
        self.vm.fd_ceiling_publisher()
    }

    fn foreign_mm_endpoint(&self) -> Option<carrick_hal::ForeignMmEndpoint> {
        self.vm.foreign_mm_endpoint()
    }

    fn frame_cow_owner_inventory(
        &self,
    ) -> Option<std::sync::Arc<dyn carrick_hal::FrameCowOwnerInventory>> {
        self.vm.frame_cow_owner_inventory()
    }

    fn last_fork_stage1_image_allocations(&self) -> u64 {
        self.last_fork_image_allocations
    }

    fn last_fork_host_mapping_allocations(&self) -> u64 {
        self.vm.last_fork_host_mapping_allocations()
    }

    fn last_fork_projection_rows_visited(&self) -> u64 {
        self.vm.last_fork_projection_rows_visited()
    }

    fn audit_executor_boundary(&mut self) -> Result<(), TrapError> {
        self.vm.audit_executor_boundary(self.vcpu.get_mut())
    }

    fn mailbox_slot(&self) -> Option<usize> {
        self.vcpu.borrow().mailbox_slot()
    }

    fn bind_task_snapshot_identity(&mut self, mm_generation: u64, asid_generation: u64) {
        self.mm_generation = mm_generation;
        self.asid_generation = asid_generation;
    }

    fn bind_exec_predecessor_identity(
        &mut self,
        identity: carrick_hal::ExecPredecessorIdentity,
    ) -> Result<(), TrapError> {
        self.vm.bind_exec_predecessor_identity(identity)
    }

    fn take_guest_run_receipt_ns(&mut self) -> u64 {
        std::mem::take(&mut self.pending_guest_run_receipt_ns)
    }

    fn snapshot_guest_state_for_publication(&mut self) -> Result<GuestCpuState, TrapError> {
        require_migratable_fpsimd_authority(self.vm.fpsimd_enabled())?;
        self.settle_owed_resume_invalidation()?;
        let snapshot = self.vcpu.get_mut().snapshot()?;
        let continuation = self.vm.task_continuation(&*self.vcpu.get_mut())?;
        Ok(GuestCpuState::from_aarch64_v1(
            aarch64_task_state_from_snapshot(
                &snapshot,
                self.pending_resume_pc,
                self.last_syscall_nr,
                self.last_syscall_orig_x0,
                self.last_fault_esr,
                self.last_exit_class,
                self.is_forked_child,
                continuation,
                self.mm_generation,
                self.asid_generation,
            )?,
        ))
    }

    fn discard_terminal_syscall_continuation(&mut self) -> Result<(), TrapError> {
        let _ = self
            .vm
            .take_task_continuation_for_executor_switch(self.vcpu.get_mut())?;
        self.pending_resume_pc = None;
        self.last_syscall_nr = None;
        self.last_syscall_orig_x0 = 0;
        self.last_fault_esr = 0;
        Ok(())
    }

    fn bind_frame_cow(
        &mut self,
        authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority>,
        identity: carrick_hal::FrameCowIdentity,
    ) {
        if self.mm_generation != identity.mm {
            carrick_fatal!(
                "aarch64::cow_identity",
                "bound memory management generation mismatch against frame COW identity: expected mm={} vs actual mm={}",
                self.mm_generation,
                identity.mm
            );
        }
        // FrameCowIdentity carries the numeric hardware ASID, not the strong
        // allocation generation. `bind_task_snapshot_identity` installed that
        // generation immediately before this call; preserve it verbatim.
        self.vm.bind_frame_cow(authority, identity);
    }

    fn service_owner_file_fault(
        &mut self,
        mm_key: u64,
        request_generation: u64,
    ) -> Result<Option<carrick_hal::OwnerFileFaultOutcome>, TrapError> {
        let Some(slot_index) = self.vcpu.get_mut().mailbox_slot() else {
            return Ok(None);
        };
        let region = carrick_el1_abi::get_el1_region_host_ptr();
        if region == 0 {
            return Ok(None);
        }
        // SAFETY: the driving engine retains the installed carrier metadata
        // region, whose versioned layout owns this aligned slot table.
        let slots = unsafe {
            &*((region + carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize)
                as *const carrick_el1_abi::MmPortalSlots)
        };
        let Some(slot) = slots.grant(slot_index) else {
            return Ok(None);
        };
        let Some(window) = slot.fault_selection(mm_key, request_generation) else {
            return Ok(None);
        };
        if mm_key != self.mm_generation || window.host_backing.is_none() {
            return Err(TrapError::Hypervisor(
                "owner file fault selection names another MM or source".into(),
            ));
        }
        let ttbr0 = self.vcpu.get_mut().get_sys_reg(SysReg::Ttbr0)?;
        // SAFETY: this exact window was published by the production owner in
        // this carrier's immutable fault-selection slot.
        let handle = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                window.operation.carrier,
                window.operation.mm,
                window.operation.incarnation,
            )
        };
        let target = crate::user_transfer::TransferTarget::from_handle(handle, ttbr0);
        let prepared = match self.vm.prepare_owner_frame_grant(target, window) {
            Err(TrapError::HostBackingEof) => {
                if !slot.cancel_fault_selection(window, request_generation) {
                    return Err(TrapError::Hypervisor("owner EOF selection is stale".into()));
                }
                return Ok(Some(carrick_hal::OwnerFileFaultOutcome::BusFault));
            }
            other => other?,
        };
        let Some(mut grant) = prepared else {
            if !slot.cancel_fault_selection(window, request_generation) {
                return Err(TrapError::Hypervisor(
                    "owner file fault cancellation is stale".into(),
                ));
            }
            return Ok(Some(carrick_hal::OwnerFileFaultOutcome::Refused));
        };
        if !slot.submit(window, grant.transaction()) {
            return Err(TrapError::Hypervisor(
                "owner file fault grant selection was displaced".into(),
            ));
        }
        let outcome = self.run_owner_fork_service(
            carrick_el1_abi::TrapFrame {
                esr: carrick_el1_abi::MM_PORTAL_GRANT_ESR,
                ..carrick_el1_abi::TrapFrame::default()
            },
            &mut || false,
        );
        if let Some(receipt) = slot.take_receipt(window, grant.transaction()) {
            let settled = grant.settle(&receipt)?;
            outcome?;
            Ok(Some(if settled {
                carrick_hal::OwnerFileFaultOutcome::Resolved
            } else {
                carrick_hal::OwnerFileFaultOutcome::Refused
            }))
        } else if slot.withdraw(window, grant.transaction()) {
            outcome?;
            Ok(Some(carrick_hal::OwnerFileFaultOutcome::Refused))
        } else {
            carrick_fatal::carrick_fatal!(
                "aarch64::user_transfer",
                "unsettled owner file fault retains physical custody"
            );
        }
    }

    fn prepare_el1_frame_grant(
        &mut self,
        request: carrick_hal::El1FrameGrantRequest,
    ) -> Result<Option<carrick_hal::El1FrameGrantReady>, TrapError> {
        self.vm.prepare_el1_frame_grant(request)
    }

    fn roll_back_el1_frame_grant(
        &mut self,
        grant: carrick_hal::threaded::El1FrameGrantRollback,
    ) -> Result<bool, TrapError> {
        self.vm.roll_back_el1_frame_grant(grant)
    }

    fn complete_el1_frame_grant(
        &mut self,
        grant: carrick_hal::threaded::El1FrameGrantRollback,
    ) -> Result<(), TrapError> {
        self.vm.complete_el1_frame_grant(grant)
    }

    fn publish_el1_frame_grant(
        &mut self,
        grant: carrick_hal::threaded::El1FrameGrantPublication,
    ) -> Result<carrick_hal::threaded::El1FrameGrantPublished, TrapError> {
        use carrick_hal::threaded::El1FrameGrantPublished;
        let publication = carrick_mmu_core::aarch64::GuestLeafPublication {
            va: grant.semantic_base,
            ipa: grant.ready.physical_ipa,
            len: grant.len,
            writable: grant.permissions & 2 != 0,
            executable: grant.permissions & 4 != 0,
        };
        let span = carrick_mmu_core::aarch64::descriptor_txn::PageSpan::new(
            grant.semantic_base,
            grant.len,
        );
        trace_el1_mapping_leafs(
            self,
            El1MappingLeafPhase::GrantPreparation,
            grant.mm_key,
            span,
            grant.fault_va,
        );
        if self.page_tables.live_descriptor_owner() == LiveDescriptorOwner::Guest {
            let result = guest_frame_grant_submission(&self.page_tables, grant, publication);
            if matches!(result, Ok(El1FrameGrantPublished::Submit(_))) {
                trace_el1_mapping_leafs(
                    self,
                    El1MappingLeafPhase::GrantSubmitted,
                    grant.mm_key,
                    span,
                    grant.fault_va,
                );
            }
            return result;
        }
        let size = usize::try_from(grant.len).map_err(|_| TrapError::MappingTooLarge(grant.len))?;
        self.pt_edit_and_flush_after_adopting(grant.semantic_base, size, |editor| {
            // TLB maintenance only if the publication overwrote a descriptor
            // the walker could have cached: a VALID leaf, a valid block it
            // split, or a valid table pointer a reclaim sweep cleared. A first
            // touch normally turns invalid (PROT_NONE / prepared) leaves valid,
            // which AArch64 never caches, so it needs none. The undo journal
            // records exactly whether any word it first wrote was valid. A
            // journal some caller already holds open is not ours to read or
            // close: keep the unconditional invalidation then.
            let owns_journal = !editor.manager.undo_is_open();
            if owns_journal {
                editor.manager.begin_undo()?;
            }
            let source = editor.arena_source.as_deref_mut();
            let published = editor
                .manager
                .publish_private_pages(publication, grant.fault_va, source)
                .map_err(|error| match error {
                    carrick_mmu_core::aarch64::GuestLeafPublicationError::Manager(error) => error,
                    _ => PageTableError::BadAddress,
                });
            let flush_required = !owns_journal || editor.manager.undo_replaced_valid_descriptor();
            if owns_journal {
                // The funnel's own failure handling owns rollback; this
                // journal only measured the edit.
                editor.manager.commit_undo();
            }
            published?;
            Ok(PageTableApplyOutcome {
                changed: true,
                flush_required,
            })
        })
        .map_err(|error| memory_error_to_trap_error(error, "publish EL1 frame grant on host"))?;
        trace_el1_mapping_leafs(
            self,
            El1MappingLeafPhase::HostGrantPublished,
            grant.mm_key,
            span,
            grant.fault_va,
        );
        Ok(El1FrameGrantPublished::OnHost)
    }

    fn live_ttbr0(&mut self) -> Result<u64, TrapError> {
        self.vcpu
            .borrow()
            .get_sys_reg(SysReg::Ttbr0)
            .map_err(|error| TrapError::Hypervisor(format!("read TTBR0_EL1: {error}")))
    }

    fn run_el1_service_call(&mut self, entry_pc: u64, frame_va: u64) -> Result<(), TrapError> {
        run_el1_service_call_on::<V>(self.vcpu.get_mut(), entry_pc, frame_va)
    }

    fn suspended_el1_stack_pointer(&mut self) -> Result<Option<u64>, TrapError> {
        Ok(self.suspended_el1_sp)
    }

    fn el1_operation_suspended(&self) -> bool {
        self.suspended_el1_sp.is_some()
    }

    fn live_descriptor_owner(&self) -> LiveDescriptorOwner {
        self.page_tables.live_descriptor_owner()
    }

    fn record_guest_descriptor_lane_refusal(
        &self,
        reason: carrick_mmu_core::aarch64::GuestLaneRefusal,
    ) {
        self.vm.record_guest_descriptor_lane(Err(reason));
    }

    fn user_memory_admission_authority(&self) -> Option<UserMemoryAuthority> {
        self.vm.owner_transfer_custody()?;
        Some(self.protections.clone())
    }

    fn owner_transfer_carrier(&self) -> Option<std::num::NonZeroU64> {
        self.vm
            .owner_transfer_custody()
            .map(|custody| custody.carrier())
    }

    fn select_live_descriptor_owner(
        &mut self,
        owner: LiveDescriptorOwner,
    ) -> Result<bool, TrapError> {
        if owner != LiveDescriptorOwner::Guest {
            self.page_tables.select_live_descriptor_owner(owner);
            return Ok(true);
        }
        let Some(authority) = self.user_memory_admission_authority() else {
            return Ok(false);
        };
        let mut guard = authority.begin_selection().map_err(|reason| {
            TrapError::Hypervisor(format!("user-memory publication guard refused: {reason:?}"))
        })?;
        self.select_live_descriptor_owner_under_guard(owner, &mut guard, None)
    }

    fn select_live_descriptor_owner_under_guard(
        &mut self,
        owner: LiveDescriptorOwner,
        guard: &mut carrick_guest_mem::UserMemoryAdmissionGuard<'_>,
        closed: Option<carrick_el1_abi::PortalClosedRootBind>,
    ) -> Result<bool, TrapError> {
        if !guard.belongs_to(&self.protections) {
            return Err(TrapError::Hypervisor(
                "user-memory publication guard belongs to another MM".into(),
            ));
        }
        if owner == LiveDescriptorOwner::Guest {
            let Some(custody) = self.vm.owner_transfer_custody() else {
                return Ok(false);
            };
            let mm = carrick_el1_abi::ReservationMm::new(self.mm_generation)
                .ok_or(TrapError::UnsupportedPlatform)?;
            let ttbr0 = self.vcpu.get_mut().get_sys_reg(SysReg::Ttbr0)?;
            let region = carrick_el1_abi::get_el1_region_host_ptr();
            if region == 0 {
                return Err(TrapError::UnsupportedPlatform);
            }
            // SAFETY: the live engine retains the complete carrier ABI region.
            let slots = unsafe {
                &*((region + carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize)
                    as *const carrick_el1_abi::MmPortalSlots)
            };
            let target = match closed {
                Some(token) => crate::user_transfer::TransferTarget::bind_closed(
                    self,
                    token,
                    custody.as_ref(),
                    slots,
                )?,
                None => crate::user_transfer::TransferTarget::bind(
                    self,
                    mm,
                    ttbr0,
                    custody.as_ref(),
                    slots,
                )?,
            };
            let Some(target) = target else {
                return Ok(false);
            };
            if target.ttbr0() != ttbr0 || target.handle().mm() != mm {
                return Err(TrapError::Hypervisor(
                    "owner BIND differs from the loaded task root".into(),
                ));
            }
            let outcome = guard.select_owner(target.handle(), || {
                self.page_tables
                    .select_guest_descriptor_owner()
                    .map(|lane| match lane {
                        crate::stage1_authority::GuestLaneSelection::Selected => {
                            carrick_guest_mem::OwnerMemorySelection::Immediate
                        }
                        crate::stage1_authority::GuestLaneSelection::Deferred => {
                            carrick_guest_mem::OwnerMemorySelection::Deferred
                        }
                    })
            });
            return match outcome {
                Ok(lane) => {
                    self.vm.record_guest_descriptor_lane(Ok(match lane {
                        carrick_guest_mem::OwnerMemorySelection::Immediate => {
                            crate::stage1_authority::GuestLaneSelection::Selected
                        }
                        carrick_guest_mem::OwnerMemorySelection::Deferred => {
                            crate::stage1_authority::GuestLaneSelection::Deferred
                        }
                    }));
                    Ok(lane == carrick_guest_mem::OwnerMemorySelection::Immediate)
                }
                Err(carrick_guest_mem::OwnerMemorySelectionError::Selection(reason)) => {
                    self.vm.record_guest_descriptor_lane(Err(reason));
                    Ok(false)
                }
                Err(carrick_guest_mem::OwnerMemorySelectionError::Admission(reason)) => {
                    Err(TrapError::Hypervisor(format!(
                        "exact user-memory owner admission refused: {reason:?}"
                    )))
                }
            };
        }
        self.page_tables.select_live_descriptor_owner(owner);
        Ok(true)
    }

    fn settle_el1_descriptor_receipt(
        &mut self,
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Result<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt, TrapError>
    {
        self.page_tables
            .settle_guest_descriptor_receipt(txn, receipt)
            .map_err(|error| {
                TrapError::Hypervisor(format!("settle EL1 descriptor receipt: {error:?}"))
            })
    }

    fn abandon_el1_descriptor_txn(
        &mut self,
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
    ) -> Result<(), TrapError> {
        self.page_tables
            .abandon_guest_descriptor_txn(txn)
            .map_err(|error| {
                TrapError::Hypervisor(format!("abandon EL1 descriptor transaction: {error:?}"))
            })
    }

    fn live_el1_grant_pages(
        &self,
        pages: &[(u64, u64)],
        resident: &mut dyn FnMut(u64, carrick_abi::LinuxProtFlags),
    ) {
        if self.process_asid.is_none() || pages.is_empty() {
            return;
        }
        // A root that cannot be read or resolved authenticates no page, as
        // the per-page walk's error did.
        let Ok((pt_base, host)) = self.live_pt_root() else {
            return;
        };
        let size = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize;
        self.page_tables.with_manager(|manager| {
            if manager.base() != pt_base {
                return;
            }
            let resolver = EngineHostResolver {
                vm: &self.vm,
                pt_base,
                host,
                size,
            };
            let mut expected = pages.iter().map(|&(_, ipa)| ipa);
            // SAFETY: `live_pt_root` resolved the live page-table mapping at
            // `pt_base` and its base was checked above; the caller's MM
            // mutation authority excludes table edits for this call.
            unsafe {
                manager.debug_walk_host_pages(
                    resolver,
                    pages.iter().map(|&(va, _)| va),
                    |va, walk| {
                        let Some(expected_ipa) = expected.next() else {
                            return;
                        };
                        let Ok(walk) = walk else {
                            return;
                        };
                        let leaf = carrick_mmu_core::aarch64::terminal_descriptor(walk);
                        if carrick_mmu_core::aarch64::el1_private_leaf_state(leaf)
                            == carrick_mmu_core::aarch64::El1PrivateLeafState::Resident
                            && leaf & 0x0000_FFFF_FFFF_F000 == expected_ipa
                        {
                            use carrick_abi::LinuxProtFlags as P;
                            use carrick_mmu_core::aarch64::{
                                LeafAccess, terminal_descriptor_permits_el0,
                            };
                            let mut protection = P::empty();
                            for (access, flag) in [
                                (LeafAccess::Read, P::READ),
                                (LeafAccess::Write, P::WRITE),
                                (LeafAccess::Execute, P::EXEC),
                            ] {
                                if terminal_descriptor_permits_el0(leaf, access) {
                                    protection.insert(flag);
                                }
                            }
                            resident(va, protection);
                        }
                    },
                );
            }
        });
    }

    fn refresh_fork_process_state(&mut self) -> Result<(), TrapError> {
        let slot = self.mailbox_slot();
        let tables = self.page_tables.clone();
        let vm = &mut self.vm;
        let vcpu = self.vcpu.get_mut();
        let process_asid = self.process_asid;
        let carrier_root = vm.carrier_maintenance_root().ok();
        let mut flush = EngineStage1Services::<V> {
            vcpu,
            tables,
            slot,
            process_asid,
            carrier_root,
            suspended_el1_sp: self.suspended_el1_sp,
            required_invalidation: None,
        };
        vm.refresh_fork_process_state(&mut flush)?;
        drop(flush);
        vm.refresh_vcpu_after_frame_cow(vcpu)
    }

    fn install_stage1_table_arena_source(
        &mut self,
        source: Box<dyn carrick_mmu_core::aarch64::TableArenaSource>,
    ) -> Result<(), TrapError> {
        let page_tables = self.page_tables.clone();
        page_tables.install_source_with_eager_builder(source, || {
            self.build_page_tables_manager_from_live()
        })
    }

    fn resolve_frame_cow_fault(
        &mut self,
        syndrome: u64,
        far: u64,
    ) -> Result<carrick_hal::CowFaultResolution, TrapError> {
        // Serialize the actual hardware root/ASID and live descriptors for every
        // attempted COW, including the fast EL0-abort route that never reaches
        // the runtime's generic fault diagnostic arm. This is structural proof
        // that an identity-bearing COW event edited the graph the vCPU walked.
        let fault_page_tables = self.diagnostic_fault_page_tables(far);
        if let Some((ttbr, descriptors)) = fault_page_tables {
            carrick_observability::probes::pt_fault_walk(
                far,
                descriptors[0],
                descriptors[1],
                descriptors[2],
                descriptors[3],
            );
            carrick_observability::probes::pt_fault_ttbr(far, ttbr);
        }
        let slot = self.mailbox_slot();
        let tables = self.page_tables.clone();
        let vm = &mut self.vm;
        let vcpu = self.vcpu.get_mut();
        let process_asid = self.process_asid;
        let carrier_root = vm.carrier_maintenance_root().ok();
        let mut flush = EngineStage1Services::<V> {
            vcpu,
            tables,
            slot,
            process_asid,
            carrier_root,
            suspended_el1_sp: self.suspended_el1_sp,
            required_invalidation: None,
        };
        let ttbr0 = fault_page_tables.map_or(0, |(ttbr, _)| ttbr);
        let resolution = vm.resolve_frame_cow_fault(syndrome, far, ttbr0, &mut flush)?;
        drop(flush);
        if matches!(resolution, carrick_hal::CowFaultResolution::Resolved { .. }) {
            vm.refresh_vcpu_after_frame_cow(vcpu)?;
            self.last_fault_esr = 0;
        }
        Ok(resolution)
    }

    fn begin_process_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.vm.begin_process_inventory(reservation)
    }

    fn cancel_process_inventory(&mut self) -> bool {
        self.vm.cancel_process_inventory()
    }

    fn take_process_inventory(&mut self) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        self.vm.take_process_inventory()
    }

    fn begin_retirement_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.vm.begin_retirement_inventory(reservation)
    }

    fn take_retirement_inventory(&mut self) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        self.vm.take_retirement_inventory()
    }

    fn apply_exec_inventory(
        &mut self,
        replacement_mm: u64,
        apply: &mut dyn FnMut(
            carrick_hal::FrameInventoryCommit<()>,
        )
            -> Result<carrick_hal::FrameInventoryApplyReceipt, TrapError>,
    ) -> Result<bool, TrapError> {
        self.vm.apply_exec_inventory(replacement_mm, apply)
    }

    fn activate_exec_inventory(&mut self) -> Result<(), TrapError> {
        self.vm.activate_exec_inventory()
    }

    type Arch = carrick_hal::Aarch64GuestArch;
    type KickHandle = V::KickHandle;
    type SiblingSpec = Aarch64SiblingSpec<V>;
    type ProcessSpec = Aarch64ProcessSpec<V>;

    fn diagnostic_wait_registers(&self) -> Option<carrick_hal::GuestWaitRegisters> {
        let live_pc = self.vcpu.borrow().get_reg(Reg::Pc).ok()?;
        let resume_pc = diagnostic_resume_pc(self.pending_resume_pc, live_pc);
        // A symbol to look up: the svc instruction's own address, not +4.
        let pc = self.hvpatch_island_svc_addr(resume_pc).unwrap_or(resume_pc);
        Some(carrick_hal::GuestWaitRegisters {
            pc,
            sp: self.vcpu.borrow().get_reg(Reg::Sp).ok()?,
            lr: self.vcpu.borrow().get_reg(Reg::X(30)).ok()?,
        })
    }

    fn aarch64_core_registers(
        &self,
    ) -> Result<Option<carrick_hal::Aarch64CoreRegisters>, TrapError> {
        require_core_fpsimd_authority(self.vm.fpsimd_enabled())?;
        let snapshot = self.vcpu.borrow().snapshot()?;
        let (resume_pc, resume_pstate) = core_resume_pair(self.pending_resume_pc, &snapshot);
        // The Linux-visible resume pc of a thread blocked in this syscall is
        // the instruction AFTER its svc, so +4 past the island's decoded
        // origin (which is the svc's own address) -- see
        // `hvpatch_island_svc_addr`'s doc comment for why this differs from
        // `diagnostic_wait_registers`'s bare-origin use above.
        let resume_pc = self
            .hvpatch_island_svc_addr(resume_pc)
            .and_then(|origin| origin.checked_add(4))
            .unwrap_or(resume_pc);
        Ok(Some(carrick_hal::Aarch64CoreRegisters {
            gprs: snapshot.gprs,
            sp_el0: snapshot.sp_el0,
            resume_pc,
            resume_pstate,
            pc: snapshot.pc,
            pstate: snapshot.pstate,
            elr_el1: snapshot.elr_el1,
            spsr_el1: snapshot.spsr_el1,
            tpidr_el0: snapshot.tpidr_el0,
            vregs: snapshot.vregs,
            fpsr: snapshot.fpsr,
            fpcr: snapshot.fpcr,
        }))
    }

    fn prepare_core_snapshot(&mut self) -> Result<(), TrapError> {
        if self.page_tables.is_none() {
            // Persistent exec intentionally defers the software observer until
            // the first edit. Core capture needs a read-only live walk even if
            // this process never called mmap/mprotect after exec. The load
            // initializes from TTBR backing, writes nothing, performs no TLBI,
            // and (unlike an edit) is valid on a guest-owned MM.
            self.load_live_stage1_manager().map_err(|error| {
                TrapError::Hypervisor(format!("load live page tables for core snapshot: {error}"))
            })?;
        }
        Ok(())
    }

    fn read_core_bytes(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
        // `capture_and_publish_core` has already joined this range to a
        // quiesced, readable Linux VMA. Use the backing-only path so the
        // syscall EFAULT metadata for the larger hidden heap reservation does
        // not reject its live `[heap_base, brk)` prefix.
        <Self as GuestMemory>::read_bytes_raw(self, address, length)
    }

    fn diagnostic_fault_page_tables(&self, far: u64) -> Option<(u64, [u64; 4])> {
        const TTBR_ROOT_MASK: u64 = (1_u64 << 48) - 1;
        let ttbr = self.vcpu.borrow().get_sys_reg(SysReg::Ttbr0).ok()?;
        let root = ttbr & TTBR_ROOT_MASK;
        let size = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize;
        // Walk the live backing in place. This runs on EVERY frame-COW fault
        // (`resolve_frame_cow_fault`), and reading the region through
        // `read_gpa` allocated and memcpy'd all 1.75 MiB of it to extract four
        // descriptors — measured at ~6 COW faults per guest fork+wait round
        // trip, so ~10 MiB of copying plus an mmap/munmap/madvise triple per
        // cycle for a diagnostic probe. It still reads the HARDWARE-visible
        // bytes rather than the software model, which is the whole point of
        // this walk.
        let host = self.vm.host_ptr(root, size)?;
        // SAFETY: `host_ptr` resolved a complete live mapping of `size` bytes
        // whose byte offset 0 is the PA `root`, and this frame holds the engine
        // borrow for the duration of the walk.
        Some((ttbr, unsafe {
            carrick_mmu_core::aarch64::walk_descriptors_host(host.cast_const(), size, root, far)
        }))
    }

    fn resolve_stale_stage1_fault(
        &mut self,
        far: u64,
        access: carrick_mmu_core::aarch64::LeafAccess,
        kind: carrick_mmu_core::aarch64::Stage1FaultKind,
    ) -> Result<bool, TrapError> {
        // Read the HARDWARE-visible leaf, never the software model: the model
        // is exactly what stopped naming this page when the sibling committed
        // it, and only the live descriptor says whether a retry can succeed.
        let Some((_ttbr, walk)) = self.diagnostic_fault_page_tables(far) else {
            return Ok(false);
        };
        let leaf = carrick_mmu_core::aarch64::terminal_descriptor(walk);
        if !carrick_mmu_core::aarch64::terminal_descriptor_permits_el0(leaf, access) {
            return Ok(false);
        }
        const STALE_STAGE1_RETRY_BOUND: u32 = 4096;
        self.stale_stage1_retry = match self.stale_stage1_retry {
            (va, retries) if va == far => (va, retries.saturating_add(1)),
            _ => (far, 1),
        };
        if self.stale_stage1_retry.1 > STALE_STAGE1_RETRY_BOUND {
            return Err(TrapError::Hypervisor(format!(
                "stale stage-1 fault at {far:#x} retried {STALE_STAGE1_RETRY_BOUND} times: the live walk {walk:x?} permits {access:?} but the vCPU keeps faulting (a stage-1 leaf naming a frame stage-2 no longer maps)"
            )));
        }
        let invalidate = kind.stale_retry_needs_invalidation(self.stale_stage1_retry.1);
        carrick_observability::probes::hvpatch_stale_stage1_fault(
            far,
            kind as u32,
            invalidate,
            self.stale_stage1_retry.1,
        );
        if invalidate {
            self.run_stage1_maintenance()?;
        }
        Ok(true)
    }

    fn set_persistent_vm_lifecycle(&mut self, enabled: bool) {
        self.vm.set_persistent_vm_lifecycle(enabled);
    }

    fn configure_process_asid(&mut self, asid: u16) -> Result<(), TrapError> {
        if asid == 0 {
            return Err(TrapError::Hypervisor(
                "hvpatch process ASID zero is reserved".to_owned(),
            ));
        }
        const TCR_AS: u64 = 1 << 36;
        const TTBR_ROOT_MASK: u64 = (1_u64 << 48) - 1;
        let reserved_len = usize::try_from(
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_ARENA_SIZE
                + carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_SIZE,
        )
        .map_err(|_| TrapError::Hypervisor("hvpatch reserved IPA size overflow".to_owned()))?;
        // Root bring-up starts from the generic identity tables and must carve
        // these apertures live. Exec replacement receives a global-frame image with
        // the same deterministic invalidations already baked into the cached
        // table bytes, so repeating the edit would rebuild/copy the complete
        // software manager solely to rediscover two no-ops.
        if self.process_asid.is_none() {
            if self.vm.sparse_mmap_arena_enabled() {
                self.pt_edit_and_flush(|manager| {
                    manager.set_prot_none(
                        carrick_mem::memory::LINUX_MMAP_BASE,
                        carrick_mem::memory::mmap_arena_size() as usize,
                    )
                })
                .map_err(|error| {
                    memory_error_to_trap_error(error, "reserve sparse HVPatch root mmap arena")
                })?;
                self.vm.retire_initial_mmap_arena()?;
            }
            self.pt_edit_and_flush(|editor| editor.reserve_hvpatch_process_apertures())
                .map_err(|error| {
                    memory_error_to_trap_error(
                        error,
                        "reserve hvpatch root-slot/global-frame apertures",
                    )
                })?;
        }
        self.set_unmapped(
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            reserved_len,
            true,
        );
        let tcr = self.vcpu.get_mut().get_sys_reg(SysReg::Tcr)?;
        let root = self.vcpu.get_mut().get_sys_reg(SysReg::Ttbr0)? & TTBR_ROOT_MASK;
        let ttbr = (u64::from(asid) << 48) | root;
        self.vcpu
            .borrow_mut()
            .set_sys_reg(SysReg::Tcr, tcr | TCR_AS)?;
        self.vcpu.get_mut().set_sys_reg(SysReg::Ttbr0, ttbr)?;
        self.vcpu.get_mut().set_sys_reg(SysReg::Ttbr1, ttbr)?;
        self.process_asid = Some(asid);
        Ok(())
    }

    fn prepare_exec_address_space(
        &mut self,
        root_slot_base: u64,
        root_slot_size: u64,
        asid: u16,
    ) -> Result<(), TrapError> {
        if asid == 0 {
            return Err(TrapError::Hypervisor(
                "HVPatch exec ASID zero is reserved".to_owned(),
            ));
        }
        self.vm
            .prepare_exec_address_space(root_slot_base, root_slot_size, asid)?;
        self.process_asid = Some(asid);
        Ok(())
    }

    fn mark_exec_predecessor_shared(&mut self, shared: bool) {
        self.exec_predecessor_shared = Some(shared);
        self.vm.mark_exec_predecessor_shared(shared);
    }

    fn supports_in_process_fork(&self) -> bool {
        self.process_asid.is_some()
    }

    fn retire_in_process_address_space(&mut self) -> Result<(), TrapError> {
        self.run_el1_maintenance().map_err(|error| {
            TrapError::Hypervisor(format!(
                "hvpatch process-exit ASID maintenance failed: {error}"
            ))
        })?;
        self.vm.process_exit_cleanup().map_err(|error| {
            TrapError::Hypervisor(format!(
                "hvpatch process-exit stage-2 retirement failed: {error}"
            ))
        })?;
        self.vm.destroy_vcpu_on_thread_exit(self.vcpu.get_mut());
        Ok(())
    }

    fn retire_task_address_space(&mut self) -> Result<(), TrapError> {
        self.vm.process_exit_cleanup()
    }

    fn build_process_spec(
        &mut self,
        mut request: ProcessForkRequest,
    ) -> Result<Self::ProcessSpec, TrapError> {
        use carrick_observability::probes::{
            HvpatchForkProcessSpecStage, HvpatchForkProcessSpecStagePhase,
        };

        if request.plan.owner_target().is_some() {
            return self.build_owner_process_spec(request);
        }
        if self.pending_process_fork.is_some() {
            return Err(TrapError::Hypervisor(
                "overlapping in-process parent fork transaction".to_owned(),
            ));
        }
        let total_started = std::time::Instant::now();
        let child_tid_raw = request.child_tid.raw();
        let forking_tid_raw = request.forking_tid.raw();
        let emit_stage = move |phase: HvpatchForkProcessSpecStagePhase,
                               started: std::time::Instant,
                               units: u64| {
            let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
            carrick_observability::probes::hvpatch_fork_process_spec_stage(
                HvpatchForkProcessSpecStage::new(
                    phase,
                    child_tid_raw,
                    forking_tid_raw,
                    elapsed_ns,
                    units,
                ),
            );
        };

        // Persistent-VM exec leaves the software editor absent until it is
        // needed. A process fork needs a complete manager immediately so it can
        // rebase a private child copy; initialize from the live backing here if
        // no mmap/mprotect edit has already done so. The no-op edit publishes
        // nothing and performs no TLBI.
        let stage_started = std::time::Instant::now();
        self.vm.record_host_lane_sample(
            crate::stage1_authority::GuestLaneSite::ForkPlan,
            &self.page_tables,
        );
        if self.page_tables.live_descriptor_owner() == LiveDescriptorOwner::Guest {
            return Err(TrapError::Hypervisor(
                "admitted root requires an owner Fork request".into(),
            ));
        }
        let page_tables_absent = self.page_tables.is_none();
        if page_tables_absent {
            self.pt_edit(|_| Ok(PageTableApplyOutcome::default()))
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "load hvpatch parent page tables for process fork: {error}"
                    ))
                })?;
        }
        emit_stage(
            HvpatchForkProcessSpecStagePhase::ParentPageTablesLoad,
            stage_started,
            u64::from(page_tables_absent),
        );

        // Describe the private writable graph now, but do not mutate the live
        // parent yet. Every fallible child-preparation step below operates on an
        // offline clone. The parent arm is the final publication transaction.
        // CLONE_VM keeps one Linux mm. The HVPatch execution adapter still
        // gives the child a private stage-1 root and per-process EL1 state, but
        // its user mappings must retain the same writable frames rather than
        // entering the ordinary fork-COW protocol.
        let private_ranges = self.vm.fork_cow_ranges();
        // Guest EL1 publishes, protects and retires private-anonymous leaves
        // directly in the live tables, while this host manager edits an owned
        // copy. Adopt the live descriptors for every private range before the
        // child image is cloned and the parent is armed; otherwise both the
        // child snapshot and the parent's re-armed leaves resurrect the
        // pre-EL1 invalid descriptors and the next touch is a SIGSEGV.
        // Adopt the whole user address space, not just the backend's private
        // ranges: EL1 publishes into tables it created for any first-touch
        // range (Go's heap arenas are not all in that list), and the child
        // image is cloned from this copy. The walk skips empty subtrees, so
        // its cost follows the populated tables, not the span.
        // On the guest-owned lane the manager reads hardware-visible tables
        // directly (a live image has nothing to adopt), and the live edit
        // funnel refuses there.
        const USER_ADDRESS_SPACE: usize = 1 << 48;
        self.pt_edit_locked_after_adopting(Some((0, USER_ADDRESS_SPACE)), |_| {
            Ok(PageTableApplyOutcome::default())
        })
        .map_err(|error| {
            memory_error_to_trap_error(error, "adopt setup stage-1 tables before fork")
        })?;
        let cow_ranges = if request.shares_mm() {
            Vec::new()
        } else {
            private_ranges
        };

        let stage_started = std::time::Instant::now();
        let parent = self.vcpu.get_mut().snapshot()?;
        // A process child, like a thread sibling, starts at the instruction
        // after the trapped clone in EL0. The raw parent snapshot is currently
        // parked in the EL1 syscall vector; using its live PC/PSTATE would send
        // a brand-new vCPU back into that vector as EL0 code and spin forever.
        let mut snapshot = seed_sibling_snapshot(&parent, request.entry);
        snapshot.ttbr0 = request.child_ttbr0;
        snapshot.ttbr1 = request.child_ttbr0;
        let child_asid = (request.child_ttbr0 >> 48) as u16;
        if child_asid == 0 {
            return Err(TrapError::Hypervisor(
                "in-process child ASID zero is reserved".to_owned(),
            ));
        }
        emit_stage(
            HvpatchForkProcessSpecStagePhase::VcpuSnapshot,
            stage_started,
            0,
        );

        let stage_started = std::time::Instant::now();
        // The child's own editable graph, cloned from the parent into a
        // recycled image buffer whenever the process tree's pool holds one
        // (`kernel.fork.stage1-image`): a fork storm must not allocate and
        // free a 1.75 MiB arena set per child. The parent's rollback
        // protection is the bounded undo journal, not a cloned pre-image.
        let (mut page_tables, fresh_image) =
            self.page_tables.snapshot_image_recycled().ok_or_else(|| {
                TrapError::Hypervisor("hvpatch parent page tables are absent".to_owned())
            })?;
        self.last_fork_image_allocations = u64::from(fresh_image);
        page_tables.declare_offline_private_image();
        let parent_armed_snapshot = self.vm.frame_cow_arm_snapshot();
        let unarmed_ranges: Vec<crate::vmm::ForkCowRange> = if parent_armed_snapshot.is_empty() {
            cow_ranges.clone()
        } else {
            cow_ranges
                .iter()
                .copied()
                .filter(|range| {
                    !parent_armed_snapshot
                        .binary_search_by_key(&(range.va, range.len), |r| (r.va, r.len))
                        .is_ok_and(|idx| {
                            let existing = &parent_armed_snapshot[idx];
                            existing.kernel_only == range.kernel_only
                                && existing.executable == range.executable
                        })
                })
                .collect()
        };
        emit_stage(
            HvpatchForkProcessSpecStagePhase::ParentPageTablesClone,
            stage_started,
            page_tables.copied_bytes(),
        );

        let mut child_source = request.table_arena_source.take();
        let stage_started = std::time::Instant::now();
        // Prepare the child's independent stage-1 graph read-only while it is
        // still offline. A failure here cannot affect the parent. This closes
        // the interval in which the old implementation had already armed the
        // surviving parent before snapshot/clone/rebase/builder could fail.
        // Ranges already armed in parent are already read-only in the cloned graph.
        for range in &unarmed_ranges {
            if range.kernel_only {
                page_tables
                    .set_kernel_readonly(
                        range.va,
                        range.len,
                        range.executable,
                        child_source.as_deref_mut(),
                    )
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "prepare hvpatch child kernel fork leaves read-only: {error:?}"
                        ))
                    })?;
            } else {
                page_tables
                    .set_fork_readonly(range.va, range.len, child_source.as_deref_mut())
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "prepare hvpatch child private fork leaves read-only: {error:?}"
                        ))
                    })?;
            }
        }

        emit_stage(
            HvpatchForkProcessSpecStagePhase::CowRangeProjection,
            stage_started,
            unarmed_ranges.len() as u64,
        );

        let stage_started = std::time::Instant::now();
        let child_root = request.child_ttbr0 & ((1_u64 << 48) - 1);
        page_tables
            .rebase(child_root, child_source.as_deref_mut())
            .map_err(|error| {
                TrapError::Hypervisor(format!("rebase child page tables: {error:?}"))
            })?;
        emit_stage(
            HvpatchForkProcessSpecStagePhase::PageTablesRebase,
            stage_started,
            carrick_mem::memory::LINUX_PAGE_TABLES_SIZE,
        );
        let builder = self
            .vm
            .build_process_builder(request, &mut page_tables, &cow_ranges)?;
        // The child is a new MM image: re-assert its idle EL1 COW copy window
        // with the one provisioning writer before anything can publish it.
        page_tables
            .provision_cow_copy_window(child_source.as_deref_mut())
            .map_err(|error| {
                TrapError::Hypervisor(format!("provision child EL1 COW copy window: {error:?}"))
            })?;
        let child_authority = self.page_tables.child_with_manager(page_tables);
        if let Some(source) = child_source {
            child_authority.install_source(source).map_err(|error| {
                TrapError::Hypervisor(format!("set child arena source: {error:?}"))
            })?;
        }
        let stage_started = std::time::Instant::now();
        let legacy = self.protections.legacy().ok_or_else(|| {
            TrapError::Hypervisor("owner root cannot take a legacy fork projection".into())
        })?;
        let protections = UserMemoryAuthority::from_legacy(Arc::new(
            MemoryProtections::from_snapshot(legacy.snapshot_all()),
        ));
        drop(legacy);
        emit_stage(
            HvpatchForkProcessSpecStagePhase::WrapperProtections,
            stage_started,
            0,
        );
        let spec = Aarch64ProcessSpec {
            builder,
            snapshot,
            page_tables: child_authority,
            protections,
            process_asid: child_asid,
        };

        if !cow_ranges.is_empty() {
            let stage_started = std::time::Instant::now();
            // Final publication transaction. All child allocation, mapping-plan,
            // ASID, snapshot, and wrapper work is complete. Open an undo journal
            // covering the parent's fork-COW arming and restore it (including a
            // scoped TLBI) if either the edit or its fail-closed descriptor
            // authentication fails. Armed-range metadata is installed only after
            // publication succeeds, so every pre-commit error leaves both
            // authorities at their prior state.
            let publish_parent = (|| -> Result<(), TrapError> {
                if !unarmed_ranges.is_empty() {
                    const TTBR_ROOT_MASK: u64 = (1_u64 << 48) - 1;
                    let pt_base =
                        self.vcpu
                            .borrow()
                            .get_sys_reg(SysReg::Ttbr0)
                            .map_err(|error| {
                                TrapError::Hypervisor(format!("read TTBR0_EL1: {error}"))
                            })?
                            & TTBR_ROOT_MASK;
                    let size = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize;
                    let host = self.vm.host_ptr(pt_base, size).ok_or_else(|| {
                        TrapError::Hypervisor("page-table region not mapped".to_owned())
                    })?;

                    self.pt_edit_and_flush(|manager| {
                        manager.begin_undo()?;
                        let mut outcome = PageTableApplyOutcome::default();
                        for range in &unarmed_ranges {
                            outcome |= if range.kernel_only {
                                manager.set_kernel_readonly(
                                    range.va,
                                    range.len,
                                    range.executable,
                                )?
                            } else {
                                manager.set_fork_readonly(range.va, range.len)?
                            };
                        }
                        Ok(outcome)
                    })
                    .map_err(|error| {
                        memory_error_to_trap_error(
                            error,
                            "arm hvpatch parent private fork leaves read-only",
                        )
                    })?;

                    // Durable pre-write structural receipt: one live-backing walk
                    // per newly armed semantic range. bit4 distinguishes fork-COW arming
                    // from alias publication and post-COW authentication.
                    for range in &unarmed_ranges {
                        let walk = self.live_pt_debug_walk_with_host(range.va, pt_base, host).map_err(|error| {
                            TrapError::Hypervisor(format!(
                                "authenticate hvpatch parent fork-COW arm at VA 0x{:x}: {error}",
                                range.va
                            ))
                        })?;
                        carrick_observability::probes::pt_alias_walk(range.va, walk, 1 << 4);
                        let leaf = carrick_mmu_core::aarch64::terminal_descriptor(walk);
                        const VALID: u64 = 1;
                        const NON_GLOBAL: u64 = 1 << 11;
                        const AP_MASK: u64 = 0b11 << 6;
                        const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
                        const AP_USER_RO: u64 = 0b11 << 6;
                        const AP_PRIV_RO: u64 = 0b10 << 6;
                        let expected_ipa = self
                            .page_tables
                            .with_manager(|manager| manager.translate(range.va))
                            .flatten();
                        if let Some(expected_ipa) = expected_ipa {
                            if leaf & VALID == 0 {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch parent fork-COW arm live model has an invalid hardware leaf at VA 0x{:x}",
                                    range.va
                                )));
                            }
                            let expected_ap = if range.kernel_only {
                                AP_PRIV_RO
                            } else {
                                AP_USER_RO
                            };
                            if leaf & PA_MASK_4KIB != expected_ipa & PA_MASK_4KIB
                                || leaf & AP_MASK != expected_ap
                                || (!range.kernel_only && leaf & NON_GLOBAL == 0)
                            {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch parent fork-COW arm authentication failed at VA 0x{:x}: leaf=0x{:x} expected_ipa=0x{expected_ipa:x} expected_ap=0x{expected_ap:x}",
                                    range.va, leaf
                                )));
                            }
                            carrick_observability::probes::pt_alias_receipt(
                                range.va,
                                leaf,
                                expected_ipa,
                                expected_ap,
                                0,
                            );
                        } else if leaf & VALID != 0 {
                            return Err(TrapError::Hypervisor(format!(
                                "HVPatch parent fork-COW arm hardware leaf is live without a software translation at VA 0x{:x}",
                                range.va
                            )));
                        }
                    }
                }
                Ok(())
            })();

            if let Err(error) = publish_parent {
                if let Err(rollback_error) = self.pt_rollback_undo_and_flush() {
                    carrick_fatal!(
                        "aarch64::fork_cow",
                        "failed page table rollback and TLBI invalidation during parent fork COW setup after error {error}: {rollback_error}"
                    );
                }
                self.vm
                    .restore_frame_cow_arm_snapshot(parent_armed_snapshot);
                return Err(error);
            }
            self.vm.arm_frame_cow_ranges(&unarmed_ranges);
            self.pending_process_fork = Some(ParentForkCowRollback {
                armed_ranges: parent_armed_snapshot,
            });
            emit_stage(
                HvpatchForkProcessSpecStagePhase::ParentCowPublication,
                stage_started,
                unarmed_ranges.len() as u64,
            );
        }
        emit_stage(HvpatchForkProcessSpecStagePhase::Total, total_started, 0);
        Ok(spec)
    }

    fn materialize_process(spec: Self::ProcessSpec) -> Result<Self, TrapError> {
        let (mut vm, mut vcpu) = V::materialize_process(spec.builder)?;
        if let Err(error) = vcpu.restore_thread_start(&spec.snapshot) {
            vm.abort_process_materialization(&mut vcpu)
                .unwrap_or_else(|rollback_error| {
                    carrick_fatal!(
                        "aarch64::process_materialize",
                        "failed to abort and roll back process materialization after thread register restore failure {error}: {rollback_error}"
                    );
                });
            return Err(error);
        }
        if let Err(error) = vm.commit_process_materialization() {
            vm.abort_process_materialization(&mut vcpu)
                .unwrap_or_else(|rollback_error| {
                    carrick_fatal!(
                        "aarch64::process_materialize",
                        "failed to abort and roll back process materialization after commit failure {error}: {rollback_error}"
                    );
                });
            return Err(error);
        }
        // A fresh process: its source was installed on the child tables by
        // `build_process_spec`, so no deferral is inherited from the parent.
        let mut engine = Self::from_parts_with_shared(vm, vcpu, spec.page_tables, spec.protections);
        engine.process_asid = Some(spec.process_asid);
        Ok(engine)
    }

    fn read_owner_fork_parent_bytes(
        &mut self,
        address: u64,
        len: usize,
        admission: &mut dyn carrick_guest_mem::BorrowedTtbr0Admission,
    ) -> Result<Vec<u8>, TrapError> {
        self.transfer_owner_fork_parent_bytes(
            crate::user_transfer::UserTransfer::CopyIn {
                address,
                len,
                intent: carrick_el1_abi::PortalTransferIntent::UserRead,
            },
            admission,
        )
    }

    fn write_owner_fork_parent_bytes(
        &mut self,
        address: u64,
        bytes: &[u8],
        admission: &mut dyn carrick_guest_mem::BorrowedTtbr0Admission,
    ) -> Result<(), TrapError> {
        self.transfer_owner_fork_parent_bytes(
            crate::user_transfer::UserTransfer::CopyOut {
                address,
                bytes: bytes.to_vec(),
            },
            admission,
        )
        .map(|_| ())
    }

    fn pending_owner_fork_receipt(&self) -> Option<carrick_hal::threaded::PendingOwnerForkReceipt> {
        self.pending_owner_fork.as_ref().map(|pending| {
            (
                pending.pending.completion(),
                pending.pending.inherited_host_backing().to_vec(),
            )
        })
    }

    fn commit_process_fork(&mut self) -> Result<(), TrapError> {
        if let Some(owner) = self.pending_owner_fork.take() {
            let used = owner.pending.completion().parent_tables_used;
            let receipt = owner.pending.finish(true, |frame, effect| {
                self.run_owner_fork_service(frame, effect)
            })?;
            owner
                .parent_tables
                .settle(used)
                .map_err(TrapError::Hypervisor)?;
            owner.physical.settle(true)?;
            drop(receipt);
            return Ok(());
        }
        let _ = self.pending_process_fork.take();
        self.page_tables.commit_undo();
        Ok(())
    }

    fn rollback_process_fork(&mut self) -> Result<(), TrapError> {
        if let Some(owner) = self.pending_owner_fork.take() {
            let receipt = owner.pending.finish(false, |frame, effect| {
                self.run_owner_fork_service(frame, effect)
            })?;
            let retained_parent_tables = receipt.completion().parent_tables_used;
            drop(receipt);
            owner.physical.settle(false)?;
            owner
                .parent_tables
                .settle(retained_parent_tables)
                .map_err(TrapError::Hypervisor)?;
            return Ok(());
        }
        let Some(rollback) = self.pending_process_fork.take() else {
            return Ok(());
        };
        self.pt_rollback_undo_and_flush().map_err(|error| {
            TrapError::Hypervisor(format!(
                "restore parent after failed in-process fork: {error}"
            ))
        })?;
        self.vm
            .restore_frame_cow_arm_snapshot(rollback.armed_ranges);
        Ok(())
    }

    fn kick_handle(&self) -> Self::KickHandle {
        self.vm.kick_handle()
    }

    fn wait_for_vcpu_slot() {
        V::wait_for_vcpu_slot();
    }

    fn vcpu_budget() -> usize {
        V::vcpu_budget()
    }

    fn reclaims(&self) -> bool {
        self.vm.reclaims()
    }

    fn save_initial_runner_state(&mut self) -> Result<GuestCpuState, TrapError> {
        require_migratable_fpsimd_authority(self.vm.fpsimd_enabled())?;
        if self.vm.task_continuation(&*self.vcpu.get_mut())?.is_some() {
            return Err(TrapError::Hypervisor(
                "initial AArch64 runner unexpectedly owns a syscall continuation".to_owned(),
            ));
        }
        // A root that has not run owns no vCPU: its registers are staged data
        // (HVF), so the snapshot is a copy, never a vCPU hand-off.
        let snapshot = self.vcpu.get_mut().snapshot().map_err(|error| {
            TrapError::Hypervisor(format!("save initial AArch64 runner state: {error}"))
        })?;
        Ok(GuestCpuState::from_aarch64_v1(
            aarch64_task_state_from_snapshot(
                &snapshot,
                self.pending_resume_pc,
                self.last_syscall_nr,
                self.last_syscall_orig_x0,
                self.last_fault_esr,
                self.last_exit_class,
                self.is_forked_child,
                None,
                self.mm_generation,
                self.asid_generation,
            )?,
        ))
    }

    fn build_sibling_spec(&self, entry: GuestEntryRegs) -> Result<Self::SiblingSpec, TrapError> {
        // Snapshot the parent vCPU (taken while it is suspended at the trapped
        // `clone` syscall — atomic, race-free), then seed it for the new thread
        // (x0=0, sp_el0=stack, tpidr_el0=tls, pc=parent.elr_el1 = post-svc).
        let parent = self.vcpu.borrow().snapshot()?;
        let snapshot = seed_sibling_snapshot(&parent, entry);
        // HVF needs the parent vCPU to clone its VM handle + capture its mapping
        // descriptors into the builder; KVM ignores it. The seeded SNAPSHOT (above)
        // is what the new vCPU is restored from — both backends share that.
        let builder = self.vm.build_sibling_builder(&*self.vcpu.borrow(), entry)?;
        Ok(Aarch64SiblingSpec {
            builder,
            snapshot,
            // Share the SAME page-table authority: the sibling edits the
            // SAME backing through the SAME manager.
            page_tables: self.page_tables.clone(),
            // Share the SAME PROT_NONE bookkeeping (engine-side mirror; the backing
            // share lives in the backend `GuestRam`).
            protections: self.protections.clone(),
            process_asid: self.process_asid,
        })
    }

    fn materialize_sibling(spec: Self::SiblingSpec) -> Result<Self, TrapError> {
        let (vm, mut vcpu) = V::materialize_sibling(spec.builder)?;
        // Restore the seeded register file onto the FRESHLY-CREATED sibling vCPU via
        // `restore_thread_start`: KVM does a plain restore (the PC is already the
        // post-svc address — no sentinel-store replay to skip); HVF routes through
        // its EL0-trampoline thread-start so a brand-new vCPU eret's into EL0 at the
        // post-clone instruction.
        vcpu.restore_thread_start(&spec.snapshot)?;
        spec.page_tables.increment_engine_count();
        // SHARE the spawning thread's page-table authority + PROT_NONE set.
        let mut engine = Self::from_parts_with_shared(vm, vcpu, spec.page_tables, spec.protections);
        engine.process_asid = spec.process_asid;
        Ok(engine)
    }

    fn program_counter(&self) -> Result<u64, TrapError> {
        self.vcpu.borrow().get_reg(Reg::Pc)
    }

    fn set_guest_sp_el0(&self, sp: u64) -> Result<(), TrapError> {
        self.vm.set_guest_sp(&*self.vcpu.borrow(), sp)
    }

    fn set_guest_thread_id(&self, tid: u64) -> Result<(), TrapError> {
        // Publish the packed identity consumed by the EL0 vDSO. EL1 gettid
        // reads the typed lifecycle slot, independently of the physical vCPU.
        self.vcpu.borrow().stamp_guest_thread_id(tid)
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn carrick_hal::VcpuRegistry> {
        self.vm.fresh_fork_kicker()
    }

    fn destroy_vcpu_on_thread_exit(&mut self) {
        // A guest thread exiting frees an HVF concurrent-vCPU slot (HVF). KVM no-op.
        self.vm.destroy_vcpu_on_thread_exit(self.vcpu.get_mut());
    }
}

#[inline]
fn diagnostic_resume_pc(pending_resume_pc: Option<u64>, live_pc: u64) -> u64 {
    pending_resume_pc.unwrap_or(live_pc)
}

/// Select the Linux-visible EL0 resume pair for a core note.
///
/// A running vCPU force-exited by a cross-thread kick is stopped directly in
/// EL0: its live PC/PSTATE are current and ELR/SPSR still describe the last
/// exception (often the pthread entry trampoline). A thread blocked while its
/// syscall is dispatched is parked in EL1, so the saved ELR/SPSR pair is the
/// current Linux user state instead. The pending-syscall marker normally names
/// that state, but a fatal signal can claim the task after dispatch clears the
/// marker and before the EL1 vector returns to EL0. PSTATE.M is architectural
/// authority for that window: any non-EL0 current exception level must publish
/// the saved ELR/SPSR pair, never Carrick's internal vector PC in a Linux core.
/// The runtime separately binds a synchronous fatal owner's raw ELR/SPSR to its
/// exact `FatalSignalRecord`.
fn core_resume_pair(pending_resume_pc: Option<u64>, snapshot: &Aarch64VcpuSnapshot) -> (u64, u64) {
    if pending_resume_pc.is_some()
        || !carrick_hal::aarch64::ExecLevel::from_pstate(snapshot.pstate).is_guest()
    {
        (
            pending_resume_pc.unwrap_or(snapshot.elr_el1),
            snapshot.spsr_el1,
        )
    } else {
        (snapshot.pc, snapshot.pstate)
    }
}

/// Cached `CARRICK_FORK_DEBUG_VA` (parsed once). `std::env::var` serializes on
/// std's process-wide environment lock; the shared-futex classification gate
/// runs on EVERY non-private futex op, so a per-call env read measurably
/// contended hot paths under a 1000-process storm.
fn fork_debug_va() -> Option<u64> {
    static CELL: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *CELL.get_or_init(|| {
        std::env::var("CARRICK_FORK_DEBUG_VA")
            .ok()
            .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
    })
}

fn shared_futex_backing_gpa(page_tables: &PageTableManager, guest_addr: u64) -> Option<Gpa> {
    page_tables.translate(guest_addr).map(Gpa)
}

fn require_core_fpsimd_authority(enabled: bool) -> Result<(), TrapError> {
    if enabled {
        Ok(())
    } else {
        Err(TrapError::Hypervisor(
            "complete AArch64 core registers require live FP/SIMD capture; CARRICK_NO_FPSIMD disables that authority"
                .to_owned(),
        ))
    }
}

fn require_migratable_fpsimd_authority(enabled: bool) -> Result<(), TrapError> {
    if enabled {
        Ok(())
    } else {
        Err(TrapError::Hypervisor(
            "complete AArch64 migratable state requires live FP/SIMD capture; CARRICK_NO_FPSIMD disables that authority"
                .to_owned(),
        ))
    }
}

/// `Aarch64EngineCore` is `Send` when the backend pair is: the VM/vCPU hold the
/// host VMM fds (Send) and raw window pointers valid in every thread.
//
// SAFETY: `V`/`V::Vcpu` carry only host VMM fds + raw window pointers that are
// valid in every thread of the process (threads share the address space). The
// engine is moved to its owning sibling/vCPU thread before use.
unsafe impl<V: Aarch64Vmm> Send for Aarch64EngineCore<V> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lazy_root_copyout_prevalidation_needs_no_host_mapping() {
        for leaf in [0, (1_u64 << 55) | 0x8000] {
            assert!(prevalidate_host_write_page(Some(leaf), || false, || true));
            assert!(!prevalidate_host_write_page(Some(leaf), || false, || false));
        }
    }

    #[test]
    fn prepared_root_copyout_prevalidation_keeps_the_leaf_permission_ceiling() {
        let prepared = (1_u64 << 56) | 0x8000 | (1 << 10) | (1 << 6);
        assert!(prevalidate_host_write_page(
            Some(prepared),
            || false,
            || true
        ));
        assert!(!prevalidate_host_write_page(
            Some(prepared | (1 << 7)),
            || false,
            || true
        ));
        assert!(!prevalidate_host_write_page(Some(1), || false, || true));
        assert!(!prevalidate_host_write_page(
            Some((1_u64 << 55) | 0x8000),
            || true,
            || false
        ));
    }

    /// Budget: a host copyout calls the grant service once per maximal
    /// contiguous absent run, whatever the run's length, and never for a
    /// present page. Adversarial rows: alternating pages, a run touching the
    /// copyout's end, an unaligned copyout start, and a service that
    /// declines (the run is still asked once).
    #[test]
    fn host_copyout_asks_the_grant_service_once_per_absent_run() {
        const PAGE: u64 = 4096;
        struct Pages {
            absent: std::collections::BTreeSet<u64>,
            calls: Vec<(u64, u64)>,
            decline: bool,
        }
        /// (absent pages, copyout start page, copyout pages, expected runs)
        type Row<'a> = (&'a [u64], u64, u64, &'a [(u64, u64)]);
        let rows: &[Row<'_>] = &[
            (&[], 0, 8, &[]),
            (&[0, 1, 2, 3, 4, 5, 6, 7], 0, 8, &[(0, 8)]),
            (&[0, 2, 4, 6], 0, 8, &[(0, 1), (2, 1), (4, 1), (6, 1)]),
            (&[3, 4, 5, 6, 7, 8, 9], 0, 8, &[(3, 5)]),
            (&[1, 2, 5], 1, 6, &[(1, 2), (5, 1)]),
        ];
        for decline in [false, true] {
            for &(absent, first, last, expected) in rows {
                let mut pages = Pages {
                    absent: absent.iter().map(|page| page * PAGE).collect(),
                    calls: Vec::new(),
                    decline,
                };
                serve_absent_copyout_runs(
                    &mut pages,
                    first * PAGE + 17,
                    last * PAGE,
                    |pages, page| pages.absent.contains(&page),
                    |pages, start, len| {
                        pages.calls.push((start / PAGE, len / PAGE));
                        if !pages.decline {
                            for page in (start..start + len).step_by(PAGE as usize) {
                                pages.absent.remove(&page);
                            }
                        }
                        Ok::<bool, ()>(!pages.decline)
                    },
                )
                .unwrap();
                assert_eq!(pages.calls, expected, "absent={absent:?} decline={decline}");
            }
        }
    }

    fn continuation() -> carrick_hal::threaded::Aarch64SyscallContinuationV1 {
        carrick_hal::threaded::Aarch64SyscallContinuationV1 {
            sequence: 0x101,
            state: 1,
            trap_kind: 2,
            response_action: 3,
            flags: 4,
            native_nr: 5,
            args: [6, 7, 8, 9, 10, 11],
            x8: 12,
            resume_pc: 13,
            spsr: 14,
            fp: 15,
            lr: 16,
            sp: 17,
            esr: 18,
            return_value: 19,
            resume_x16: 20,
            resume_x17: 21,
        }
    }

    fn sample() -> Aarch64VcpuSnapshot {
        let boot = carrick_hal::Aarch64GuestArch::bootstrap_sysregs();
        Aarch64VcpuSnapshot {
            gprs: std::array::from_fn(|index| 0x1000 + index as u64),
            pc: 0x2000,
            pstate: 0x3000,
            sp_el0: 0x4000,
            sp_el1: 0x5000,
            elr_el1: 0x6000,
            spsr_el1: 0x7000,
            ttbr0: 0x8000,
            ttbr1: 0x9000,
            tcr: 0xa000,
            sctlr: boot.sctlr_el1,
            mair: boot.mair_el1,
            vbar: carrick_mem::memory::LINUX_EL1_VECTORS_BASE,
            cpacr: boot.cpacr_el1,
            cntkctl_el1: 0x3,
            tpidr_el0: 0xb000,
            tpidrro_el0: 0xc000,
            tpidr_el1: 0xd000,
            contextidr_el1: 0xe000,
            actlr_el1: 0xf000,
            vregs: std::array::from_fn(|index| 0x1_0000_0000 + index as u128),
            fpsr: 0x11,
            fpcr: 0x22,
        }
    }

    /// A vCPU reads SCTLR_EL1 back with the architecture's RES1 bits set, and
    /// `SCTLR_EL1_BOOTSTRAP` deliberately lists only the bits carrick PROGRAMS.
    /// Demanding raw equality between the two rejects a perfectly neutral
    /// executor. Measured live at fork teardown on Apple HVF: the destination
    /// reported `0x3400d185`, which is exactly `SCTLR_EL1_BOOTSTRAP`
    /// (`0x0400d005`) OR the four RES1 bits ITD(7) and SED(8) — AArch32 at EL0
    /// not implemented — and nTLSMD(28) and LSMAOE(29) — FEAT_LSMAOC not
    /// implemented. That mismatch failed `cloneexithandled`,
    /// `clone3exithandled` and `sigchld` in the persistent executor pool's
    /// shutdown, after the guest itself had run correctly.
    #[test]
    fn a_hardware_readback_of_the_bootstrap_sctlr_is_still_neutral() {
        let source = sample();
        let readback = carrick_mem::arch_sysregs::SCTLR_EL1_BOOTSTRAP
            | carrick_mem::arch_sysregs::SCTLR_EL1_RES1;
        assert_eq!(
            readback, 0x3400_d185,
            "the value measured on a live executor"
        );
        let destination = Aarch64VcpuSnapshot {
            sctlr: readback,
            ..sample()
        };
        let task = aarch64_task_state_from_snapshot(
            &source,
            Some(source.elr_el1),
            Some(172),
            source.gprs[0],
            0xdead_0001,
            0x15,
            false,
            Some(continuation()),
            23,
            29,
        )
        .expect("complete snapshot");
        restore_aarch64_task_state(&destination, &task)
            .expect("a readback carrying only RES1 bits is the neutral bootstrap value");

        // A FUNCTIONAL difference must still be rejected: SCTLR_EL1.WXN(19)
        // is not RES1 and is not something carrick programs.
        let reprogrammed = Aarch64VcpuSnapshot {
            sctlr: readback | (1 << 19),
            ..sample()
        };
        assert!(restore_aarch64_task_state(&reprogrammed, &task).is_err());
    }

    /// The thread-entry deltas are applied and nothing else drifts: the stage-1
    /// MMU sysregs are inherited verbatim (same address space) and the FPSR/FPCR
    /// fields are carried WITHOUT being swapped. (Lifted from the old KVM
    /// `fork::seed_tests`, with the corrected `GuestEntryRegs` signature.)
    #[test]
    fn seed_applies_thread_entry_deltas() {
        let parent = sample();
        let entry = GuestEntryRegs {
            return_value: 0,
            stack: Some(0x7FFF_0000),
            tls: Some(0xCAFE_0000),
        };
        let child = seed_sibling_snapshot(&parent, entry);

        assert_eq!(child.gprs[0], 0, "x0 (clone return value) must be 0");
        assert_eq!(child.sp_el0, 0x7FFF_0000, "sp_el0 must be the child stack");
        assert_eq!(
            child.tpidr_el0, 0xCAFE_0000,
            "tpidr_el0 must be the tls arg"
        );
        assert_eq!(
            child.pc, parent.elr_el1,
            "pc must be the post-svc address (parent.elr_el1)"
        );
        // EL0-resume PSTATE: seeded from the parent's SPSR_EL1 (the EL0t PSTATE),
        // NOT the parent's EL1h trap-time pstate.
        assert_eq!(
            child.pstate, parent.spsr_el1,
            "sibling pstate must be the EL0t SPSR_EL1, not the EL1h trap pstate"
        );
        // Inherited verbatim (same guest address space).
        assert_eq!(child.ttbr0, parent.ttbr0);
        assert_eq!(child.sctlr, parent.sctlr);
        assert_eq!(child.vbar, parent.vbar);
        for n in 1..31 {
            assert_eq!(child.gprs[n], parent.gprs[n], "x{n} must be inherited");
        }
        // FPSR/FPCR carried, NOT swapped.
        assert_eq!(
            child.fpsr, parent.fpsr,
            "fpsr must NOT be swapped with fpcr"
        );
        assert_eq!(
            child.fpcr, parent.fpcr,
            "fpcr must NOT be swapped with fpsr"
        );
    }

    #[test]
    fn private_repoint_tlbi_failure_is_indeterminate() {
        let result = classify_private_repoint_tlbi(Err(TrapError::Hypervisor(
            "injected post-publication TLBI failure".into(),
        )));
        assert!(matches!(
            result,
            Err(RepointPrivateError::Indeterminate(MemoryError::HostMap(_)))
        ));
    }

    #[test]
    fn asid_retirement_maintenance_is_exactly_scoped_and_ordered() {
        let bytes = super::asid_maintenance_bytes();
        let opcode = |index: usize| {
            let mut word = [0_u8; 4];
            word.copy_from_slice(&bytes[index * 4..index * 4 + 4]);
            u32::from_le_bytes(word)
        };
        assert_eq!(opcode(0), 0xd503_3f9f, "dsb sy");
        assert_eq!(opcode(1), 0xd508_8340, "tlbi aside1is, x0");
        assert_eq!(opcode(2), 0xd503_3f9f, "dsb sy");
        assert_eq!(opcode(3), 0xd503_3fdf, "isb");
        assert_eq!(opcode(4), 0xd400_0022, "hvc #1");
        assert!(
            !bytes
                .windows(4)
                .any(|word| word == 0xd508_831f_u32.to_le_bytes())
        );
    }

    /// Contract `kernel.el1.grant-commit-revalidation`: one grant's committed
    /// pages are authenticated with one live-root read (`TTBR0_EL1` plus the
    /// host page-table mapping) and one batched walk, never a root read and
    /// full walk per page. The arena-resolution budget of the batched walk
    /// is `debug_walk_host_pages_resolves_each_arena_once_however_many_pages`
    /// in carrick-mmu-core.
    #[test]
    fn el1_grant_revalidation_reads_the_live_root_once_per_grant() {
        let source = include_str!("engine.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("production AArch64 engine source");
        let body = production
            .split("fn live_el1_grant_pages(")
            .nth(1)
            .and_then(|tail| tail.split("\n    fn ").next())
            .expect("live_el1_grant_pages body");
        assert_eq!(body.matches("self.live_pt_root()").count(), 1);
        assert_eq!(body.matches("debug_walk_host_pages(").count(), 1);
        assert!(!body.contains("live_pt_debug_walk"));
        assert!(!body.contains("get_sys_reg"));
        assert!(!production.contains("fn live_el1_grant_page("));
    }

    #[test]
    fn live_hvpatch_stage1_edits_are_asid_scoped() {
        let source = include_str!("engine.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("production AArch64 engine source");
        assert_eq!(
            production.matches("self.run_el1_maintenance()").count(),
            1,
            "only the isolated compatibility retirement may issue VMALLE1IS"
        );
        let compatibility_retirement = production
            .split("fn retire_in_process_address_space")
            .nth(1)
            .and_then(|tail| tail.split("fn retire_task_address_space").next())
            .expect("compatibility process retirement");
        assert!(compatibility_retirement.contains("self.run_el1_maintenance()"));

        let service = production
            .split("impl<V: Aarch64Vmm> crate::vmm::Stage1Services for EngineStage1Services")
            .nth(1)
            .and_then(|tail| tail.split("fn guest_publication_available").next())
            .expect("driving-vCPU maintenance service");
        assert!(service.contains("run_stage1_maintenance_on("));
        assert!(service.contains("self.process_asid"));
        assert!(!service.contains("run_el1_maintenance"));
        // Owed or not, a required invalidation after an edit is ASIDE1IS.
        let after_edit = production
            .split("fn invalidate_after_edit")
            .nth(1)
            .and_then(|tail| tail.split("\n    fn ").next())
            .expect("required invalidation after an edit");
        assert!(after_edit.contains("self.run_stage1_maintenance()"));
        for live_path in [
            "fn repoint_guest_alias",
            "fn pt_edit_and_flush",
            "fn ensure_frame_cow_write",
            "fn ensure_sparse_mmap_backing",
            "fn repoint_private",
            "fn refresh_fork_process_state",
            "fn resolve_frame_cow_fault",
            "fn resolve_stale_stage1_fault",
        ] {
            let body = production
                .split(live_path)
                .nth(1)
                .and_then(|tail| tail.split("\n    fn ").next())
                .unwrap_or_else(|| panic!("production live mutation path {live_path}"));
            assert!(
                body.contains("run_stage1_maintenance")
                    || body.contains("self.invalidate_after_edit()")
                    || (body.contains("EngineStage1Services::<V>")
                        && body.contains("process_asid")),
                "{live_path} must select ASIDE1IS directly or through the driving-vCPU service"
            );
            assert!(!body.contains("run_el1_maintenance"));
        }
    }

    /// Backend entry points that can publish descriptors on a guest-owned MM
    /// must receive the driving-vCPU service. A bare flush closure reports
    /// `guest_publication_available() == false`, so sparse and private-file
    /// materialization on the guest lane would refuse instead of publishing.
    #[test]
    fn guest_publishing_backend_paths_receive_the_driving_vcpu_service() {
        let source = include_str!("engine.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("production AArch64 engine source");
        for path in [
            "fn ensure_frame_cow_write",
            "fn ensure_sparse_mmap_backing",
            "fn map_private_file_backed",
            "fn repoint_guest_alias",
        ] {
            let body = production
                .split(path)
                .nth(1)
                .and_then(|tail| tail.split("\n    fn ").next())
                .unwrap_or_else(|| panic!("production backend path {path}"));
            assert!(
                body.contains("EngineStage1Services::<V>") && body.contains("slot"),
                "{path} must hand the backend the driving-vCPU publication service"
            );
            assert!(
                !body.contains("let mut flush = ||"),
                "{path} must not pass a flush-only closure"
            );
        }
    }

    /// A guest-owned MM can have an absent software manager (persistent exec
    /// drops it and lane selection never builds one), so read-only and
    /// precondition loads must not be phrased as no-op edits: the refusing
    /// live-edit funnel would turn them into a misleading "submit a descriptor
    /// transaction" error. They go through the manager-load authority instead.
    #[test]
    fn manager_loads_do_not_route_through_the_live_edit_funnel() {
        let source = include_str!("engine.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("production AArch64 engine source");
        for path in [
            "fn prepare_core_snapshot",
            "fn ensure_sparse_mmap_backing",
            "fn map_private_file_backed",
        ] {
            let body = production
                .split(path)
                .nth(1)
                .and_then(|tail| tail.split("\n    fn ").next())
                .unwrap_or_else(|| panic!("production path {path}"));
            assert!(
                !body.contains("self.pt_edit("),
                "{path} must load the manager without a no-op live edit"
            );
            assert!(
                body.contains("load_live_stage1_manager"),
                "{path} must use the read-only manager load"
            );
        }
    }

    /// Host-originated range edits are lane-agnostic: they build the shared
    /// terminal-rule plan and hand it to `apply_stage1_rules`, which submits
    /// EL1 transactions on a guest-owned MM instead of refusing there.
    #[test]
    fn range_edit_writers_use_the_lane_agnostic_rule_applier() {
        let source = include_str!("engine.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("production AArch64 engine source");
        for path in ["fn unmap_range", "fn unmap_alias_range"] {
            // Stop at the next item's doc comment, which may name the funnel.
            let body = production
                .split(path)
                .nth(1)
                .and_then(|tail| tail.split("\n    fn ").next())
                .and_then(|body| body.split("\n    ///").next())
                .unwrap_or_else(|| panic!("production writer {path}"));
            assert!(body.contains("self.retire_stage1_range("), "{path}");
            assert!(
                !body.contains("pt_edit"),
                "{path} must not use the host-only funnel"
            );
        }
        let retire = production
            .split("fn retire_stage1_range")
            .nth(1)
            .and_then(|tail| tail.split("\n    fn ").next())
            .expect("reclaiming retirement");
        assert!(retire.contains("unmap_aliased_op") && retire.contains("ReclaimCapacity"));
        for path in ["fn protect_range", "fn mark_bus_fault"] {
            let body = production
                .split(path)
                .nth(1)
                .and_then(|tail| tail.split("\n    fn ").next())
                .unwrap_or_else(|| panic!("production writer {path}"));
            assert!(body.contains("self.apply_stage1_rules("), "{path}");
            assert!(
                !body.contains("pt_edit"),
                "{path} must not use the host-only funnel"
            );
        }
        let applier = production
            .split("fn apply_stage1_rules")
            .nth(1)
            .and_then(|tail| tail.split("\n    fn ").next())
            .expect("rule applier");
        assert!(applier.contains("LiveDescriptorOwner::Guest"));
        assert!(applier.contains("apply_guest_descriptor_txns_now"));
        assert!(applier.contains("terminal_op"));
    }

    /// The guest-owned lane has no host live-descriptor writer in the engine:
    /// the single live edit funnel refuses before staging anything, and EL1
    /// frame-grant publication builds a guest transaction instead of editing.
    #[test]
    fn guest_owned_lane_has_no_engine_live_descriptor_store() {
        let source = include_str!("engine.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("production AArch64 engine source");
        let funnel = production
            .split("fn pt_edit_locked_after_adopting")
            .nth(1)
            .and_then(|tail| tail.split("\n    fn ").next())
            .expect("live edit funnel");
        let refusal = funnel
            .find("LiveDescriptorOwner::Guest")
            .expect("funnel refuses the guest-owned lane");
        let first_edit = funnel.find("page_tables.edit(").expect("funnel edit");
        assert!(refusal < first_edit, "refusal must precede any staged edit");
        assert_eq!(
            production.matches("page_tables.edit(").count(),
            1,
            "the engine's only live editor is the refusing funnel"
        );

        let grant = production
            .split("fn publish_el1_frame_grant(")
            .nth(1)
            .and_then(|tail| tail.split("\n    fn ").next())
            .expect("frame-grant publication");
        let submission = grant
            .find("guest_frame_grant_submission")
            .expect("guest lane builds a transaction");
        let host_edit = grant
            .find("pt_edit_and_flush_after_adopting")
            .expect("host lane edits");
        assert!(submission < host_edit);
        let submit_body = production
            .split("fn guest_frame_grant_submission")
            .nth(1)
            .and_then(|tail| tail.split("\n}\n").next())
            .expect("guest submission");
        assert!(submit_body.contains("prepare_guest_descriptor_txn"));
        assert!(!submit_body.contains("pt_edit"));
        assert!(!submit_body.contains("sync_to_host"));

        // Admitted Fork leaves the setup projection before its first snapshot.
        let fork = production.split("fn build_process_spec(").nth(1).unwrap();
        assert!(
            fork.find("build_owner_process_spec(request)").unwrap()
                < fork.find("snapshot_image_recycled()").unwrap()
        );
        assert!(!production.contains("fn guest_fork_arm_txns"));
    }

    #[test]
    fn task_only_terminal_cleanup_never_flushes_all_asids_or_destroys_worker_vcpu() {
        let source = include_str!("engine.rs");
        let cleanup = source
            .split("fn retire_task_address_space")
            .nth(1)
            .and_then(|tail| tail.split("fn build_process_spec").next())
            .expect("task-only terminal cleanup");
        assert!(cleanup.contains("self.vm.process_exit_cleanup()"));
        assert!(!cleanup.contains("run_el1_maintenance"));
        assert!(!cleanup.contains("destroy_vcpu_on_thread_exit"));
    }

    #[test]
    fn existing_sparse_editor_skips_parked_vcpu_bootstrap() {
        let mut bootstrap_calls = 0;
        let result = ensure_sparse_page_table_editor(true, || {
            bootstrap_calls += 1;
            Err(MemoryError::HostMap(
                "parked vCPU cannot read TTBR0".to_owned(),
            ))
        });

        assert!(result.is_ok());
        assert_eq!(bootstrap_calls, 0);
    }

    #[test]
    fn absent_sparse_editor_preserves_live_vcpu_bootstrap() {
        let mut bootstrap_calls = 0;
        let result = ensure_sparse_page_table_editor(false, || {
            bootstrap_calls += 1;
            Ok(())
        });

        assert!(result.is_ok());
        assert_eq!(bootstrap_calls, 1);
    }

    #[test]
    fn snapshot_typed_state_roundtrips_every_task_field() {
        let source = sample();
        let task = aarch64_task_state_from_snapshot(
            &source,
            Some(0x7100),
            Some(221),
            0x7200,
            0x7300,
            0x74,
            true,
            Some(continuation()),
            17,
            19,
        )
        .expect("complete task snapshot");
        let restored = restore_aarch64_task_state(&source, &task).expect("typed restore");
        assert_eq!(restored.gprs, source.gprs);
        assert_eq!(restored.pc, source.pc);
        assert_eq!(restored.pstate, source.pstate);
        assert_eq!(restored.sp_el0, source.sp_el0);
        assert_eq!(restored.elr_el1, source.elr_el1);
        assert_eq!(restored.spsr_el1, source.spsr_el1);
        assert_eq!(restored.ttbr0, source.ttbr0);
        assert_eq!(restored.ttbr1, source.ttbr1);
        assert_eq!(restored.tcr, source.tcr);
        assert_eq!(restored.actlr_el1, source.actlr_el1);
        assert_eq!(restored.tpidr_el0, source.tpidr_el0);
        assert_eq!(restored.tpidrro_el0, source.tpidrro_el0);
        assert_eq!(restored.contextidr_el1, source.contextidr_el1);
        assert_eq!(restored.vregs, source.vregs);
        assert_eq!(restored.fpsr, source.fpsr);
        assert_eq!(restored.fpcr, source.fpcr);
        assert_eq!(task.pending_resume_pc, Some(0x7100));
        assert_eq!(task.pc, 0x7100);
        assert_eq!(task.pstate, source.spsr_el1);
        assert_eq!(task.trap_pc, source.pc);
        assert_eq!(task.trap_pstate, source.pstate);
        assert_eq!(task.last_syscall_nr, Some(221));
        assert_eq!(task.last_syscall_orig_x0, 0x7200);
        assert_eq!(task.last_fault_esr, 0x7300);
        assert_eq!(task.last_exit_class, 0x74);
        assert!(task.is_forked_child);
        assert_eq!(task.syscall_continuation, Some(continuation()));
        assert_eq!(task.mm_generation, 17);
        assert_eq!(task.asid_generation, 19);
    }

    /// A task snapshot must restore every migratable field while retaining the
    /// destination executor's stack/mailbox. The destination must be neutral
    /// before load, then the task's exact EL1 control values are overlaid.
    ///
    /// The historical byte boundary copied source executor-local state here;
    /// this regression test keeps the typed overlay split explicit.
    #[test]
    fn snapshot_roundtrip_preserves_complete_task_state_and_destination_local_state() {
        let mut source = sample();
        source.sctlr ^= 0x3000_0000;
        source.mair ^= 0x1100;
        source.vbar += 0x4000;
        source.cpacr ^= 0x10;
        source.cntkctl_el1 ^= 0x4;
        source.tpidr_el1 = 0xd0ff;
        let neutral = sample();
        let destination = Aarch64VcpuSnapshot {
            sp_el1: 0xd001,
            tpidr_el1: 0,
            vbar: neutral.vbar,
            sctlr: neutral.sctlr,
            mair: neutral.mair,
            cpacr: neutral.cpacr,
            ..sample()
        };

        let task = aarch64_task_state_from_snapshot(
            &source,
            Some(source.elr_el1),
            Some(172),
            source.gprs[0],
            0xdead_0001,
            0x15,
            false,
            Some(continuation()),
            23,
            29,
        )
        .expect("complete snapshot");
        let restored = restore_aarch64_task_state(&destination, &task).expect("cross executor");

        assert_eq!(restored.gprs, source.gprs);
        assert_eq!(restored.pc, source.pc);
        assert_eq!(restored.pstate, source.pstate);
        assert_eq!(restored.sp_el0, source.sp_el0);
        assert_eq!(restored.ttbr0, source.ttbr0);
        assert_eq!(restored.sctlr, source.sctlr);
        assert_eq!(restored.mair, source.mair);
        assert_eq!(restored.vbar, source.vbar);
        assert_eq!(restored.cpacr, source.cpacr);
        assert_eq!(restored.cntkctl_el1, source.cntkctl_el1);
        assert_eq!(restored.tpidr_el1, source.tpidr_el1);
        assert_eq!(restored.sp_el1, destination.sp_el1);
        assert_eq!(restored.ttbr1, source.ttbr1);
        assert_eq!(restored.tcr, source.tcr);
        assert_eq!(restored.actlr_el1, source.actlr_el1);
        assert_eq!(restored.tpidr_el0, source.tpidr_el0);
        assert_eq!(restored.tpidrro_el0, source.tpidrro_el0);
        assert_eq!(restored.contextidr_el1, source.contextidr_el1);
        assert_eq!(restored.vregs, source.vregs);
        assert_eq!(restored.fpsr, source.fpsr);
        assert_eq!(restored.fpcr, source.fpcr);
        assert_eq!(
            restored.sp_el1, destination.sp_el1,
            "SP_EL1 must stay executor-local"
        );
        assert_eq!(task.mm_generation, 23);
        assert_eq!(task.asid_generation, 29);
        assert_eq!(task.syscall_continuation, Some(continuation()));
    }

    #[test]
    fn frame_cow_binding_preserves_strong_asid_generation_distinct_from_mm() {
        let source = include_str!("engine.rs");
        let binding = source
            .split("fn bind_frame_cow(\n        &mut self")
            .nth(1)
            .and_then(|tail| tail.split("fn refresh_fork_process_state").next())
            .expect("AArch64 engine frame-COW binding");
        assert!(binding.contains("self.mm_generation != identity.mm"));
        assert!(!binding.contains("self.asid_generation = identity.mm"));
        assert!(!binding.contains("self.mm_generation = identity.mm"));

        let snapshot = sample();
        let task =
            aarch64_task_state_from_snapshot(&snapshot, None, None, 0, 0, 0, false, None, 64, 2)
                .unwrap();
        assert_eq!(task.mm_generation, 64);
        assert_eq!(task.asid_generation, 2);
    }

    #[test]
    fn wait_diagnostics_prefer_post_syscall_guest_resume_pc() {
        assert_eq!(
            diagnostic_resume_pc(Some(0x0040_1234), 0xffff_0000),
            0x0040_1234
        );
        assert_eq!(diagnostic_resume_pc(None, 0x0040_5678), 0x0040_5678);
    }

    #[test]
    fn core_resume_pair_uses_live_el0_state_outside_a_syscall_trap() {
        let snapshot = sample();
        assert_eq!(
            core_resume_pair(None, &snapshot),
            (snapshot.pc, snapshot.pstate),
            "a force-exited running vCPU has a stale ELR from its last exception"
        );
    }

    #[test]
    fn core_resume_pair_uses_saved_el0_state_during_a_syscall_trap() {
        let snapshot = sample();
        assert_eq!(
            core_resume_pair(Some(snapshot.elr_el1), &snapshot),
            (snapshot.elr_el1, snapshot.spsr_el1),
            "a dispatcher-blocked vCPU is parked in EL1 with its EL0 pair in ELR/SPSR"
        );
    }

    #[test]
    fn core_resume_pair_uses_saved_el0_state_when_fatal_capture_runs_in_el1() {
        let mut snapshot = sample();
        snapshot.pc = 0x2d_0001_0aa0;
        snapshot.pstate = 0x6040_03c5;
        snapshot.elr_el1 = 0x88_0000_9538;
        snapshot.spsr_el1 = 0x6000_03c0;

        assert_eq!(
            core_resume_pair(None, &snapshot),
            (snapshot.elr_el1, snapshot.spsr_el1),
            "a fatal signal raised before returning from the EL1 syscall vector must publish the Linux-visible EL0 pair"
        );
    }

    #[test]
    fn wait_diagnostics_decode_hvpatch_island_back_to_original_svc() {
        // Island layout: svc #0 at 0x2000, then `b 0x1004` at the trapped
        // resume PC 0x2004. The diagnostic call site is the original svc at
        // target-4 = 0x1000. The decode itself now lives in
        // `carrick_hal::aarch64` (shared with `aarch64_core_registers`'s
        // `+4` core-note use, `carrick-hal/src/aarch64.rs`'s own tests, and
        // `carrick-runtime`'s EL1-parked-thread use); this keeps this
        // crate's own call site covered too.
        use carrick_hal::aarch64::decode_hvpatch_island_origin;
        assert_eq!(
            decode_hvpatch_island_origin(0x2004, 0xd400_0001, 0x17ff_fc00),
            Some(0x1000)
        );
        assert_eq!(
            decode_hvpatch_island_origin(0x2004, 0xd503_201f, 0x17ff_fc00),
            None,
            "a non-svc predecessor is not an HvPatch island"
        );
        assert_eq!(
            decode_hvpatch_island_origin(0x2004, 0xd400_0001, 0xd503_201f),
            None,
            "the instruction after svc must be an immediate branch"
        );
    }

    #[test]
    fn core_register_capture_rejects_disabled_fpsimd_authority() {
        let error = require_core_fpsimd_authority(false)
            .expect_err("zero-fabricated FP/SIMD state cannot be complete core authority");
        assert!(error.to_string().contains("FP/SIMD"));
        assert!(require_core_fpsimd_authority(true).is_ok());
    }

    #[test]
    fn migratable_snapshot_rejects_disabled_fpsimd_authority() {
        let live = sample();
        assert_ne!(live.vregs, [0; 32]);
        let error = require_migratable_fpsimd_authority(false)
            .expect_err("disabled FP/SIMD cannot publish a zero-filled successful snapshot");
        assert!(error.to_string().contains("FP/SIMD"));
        assert!(require_migratable_fpsimd_authority(true).is_ok());
    }

    #[test]
    fn live_el0_signal_without_caller_hint_uses_live_pc() {
        let mut reads = 0;
        let pc = signal_interrupted_pc_for_live_level(0x2000_03c0, None, || {
            reads += 1;
            Ok(0x0055_0e78)
        })
        .expect("live EL0 PC authority");

        assert_eq!(pc, Some(0x0055_0e78));
        assert_eq!(reads, 1);
    }

    #[test]
    fn live_el0_signal_preserves_supplied_pc_without_reread() {
        let pc = signal_interrupted_pc_for_live_level(0x2000_03c0, Some(0x0040_1234), || {
            panic!("a caller-supplied live PC is already authoritative")
        })
        .expect("caller-supplied live EL0 PC");

        assert_eq!(pc, Some(0x0040_1234));
    }

    #[test]
    fn el1_signal_ignores_stale_caller_pc() {
        let pc = signal_interrupted_pc_for_live_level(0x6040_03c5, Some(0x0040_1234), || {
            panic!("EL1 resumes through ELR_EL1, not live PC")
        })
        .expect("EL1 signal route");

        assert_eq!(pc, None);
    }

    #[test]
    fn el1_signal_recovers_backend_mailbox_return_only_when_caller_has_none() {
        let recovered = pending_syscall_retval_for_boundary(None, None, || Ok(Some(-77)))
            .expect("EL1 mailbox authority");
        assert_eq!(recovered, Some(-77));

        let explicit = pending_syscall_retval_for_boundary(Some(42), None, || {
            panic!("caller-owned return must win")
        })
        .expect("caller return");
        assert_eq!(explicit, Some(42));

        let el0 = pending_syscall_retval_for_boundary(None, Some(0x4000), || {
            panic!("EL0 signal must preserve live x0")
        })
        .expect("EL0 live-register authority");
        assert_eq!(el0, None);
    }

    #[test]
    fn hvpatch_process_aperture_reservation_closes_both_ranges_to_the_guest() {
        let bytes = carrick_mem::memory::stage1_identity_page_tables();
        let mut manager = PageTableManager::new(
            bytes,
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );
        assert!(
            manager
                .translate(carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE)
                .is_some()
        );
        assert!(
            manager
                .translate(carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE)
                .is_some()
        );

        assert!(
            reserve_hvpatch_process_apertures(&mut manager)
                .expect("reserve apertures")
                .changed
        );
        assert_eq!(
            manager.translate(carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE),
            None
        );
        // The table pool stays at its own address, EL1-only and never
        // executable: EL1's view of every table arena.
        let pool = carrick_el1_abi::AARCH64_STAGE1_TABLE_POOL_BASE;
        for va in [
            pool,
            pool + carrick_el1_abi::AARCH64_STAGE1_TABLE_POOL_SIZE - 0x1000,
        ] {
            assert_eq!(manager.translate(va), Some(va));
            let leaf = carrick_mmu_core::aarch64::terminal_descriptor(manager.debug_walk(va));
            assert_eq!(leaf & (0b11 << 6), 0, "EL0 has no access: {leaf:#x}");
            assert_eq!(
                leaf & (0b11 << 53),
                0b11 << 53,
                "never executable: {leaf:#x}"
            );
        }
    }

    #[test]
    fn shared_futex_high_alias_uses_live_stage1_backing_ipa() {
        let bytes = carrick_mem::memory::stage1_identity_page_tables();
        let mut manager = PageTableManager::new(
            bytes,
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );
        let guest_va = carrick_mem::memory::LINUX_HIGH_VA_THRESHOLD;
        let backing_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x20_0000;
        manager
            .map_aliased(
                guest_va,
                backing_ipa,
                0x4000,
                carrick_mmu_core::aarch64::UserLeafAccess {
                    writable: true,
                    executable: true,
                },
                None,
            )
            .expect("map high shared-file alias into a global frame");

        let resolved = shared_futex_backing_gpa(&manager, guest_va + 4)
            .expect("shared futex must have a live stage-1 translation");

        assert_eq!(resolved.raw(), backing_ipa + 4);
        assert_ne!(
            resolved.raw(),
            guest_va + 4,
            "the semantic high VA is not a cross-process physical futex key"
        );
    }

    #[test]
    fn fresh_root_engine_and_exec_heap_lifecycle() {
        use carrick_mem::memory::{LINUX_HEAP_BASE, LINUX_HEAP_SIZE};

        // 1. Fresh root / exec seeding: heap starts unmapped.
        let protections = Arc::new(MemoryProtections::default());
        seed_heap_unmapped(&protections);

        assert!(
            protections.range_no_access(LINUX_HEAP_BASE, 0x1000),
            "heap base must start unmapped / no-access"
        );
        assert!(
            protections.range_unmapped(LINUX_HEAP_BASE, 0x1000),
            "heap base must start unmapped"
        );
        assert!(
            protections.range_no_access(LINUX_HEAP_BASE + LINUX_HEAP_SIZE - 0x1000, 0x1000),
            "last heap page must start unmapped"
        );

        // 2. Grow 1 page (0x1000): clearing unmapped makes only the live prefix accessible.
        protections.set_mapping_protection(LINUX_HEAP_BASE, 0x1000, false, false);
        assert!(
            !protections.range_no_access(LINUX_HEAP_BASE, 0x1000),
            "grown page must be accessible"
        );
        assert!(
            protections.range_unmapped(LINUX_HEAP_BASE + 0x1000, 0x1000),
            "ungrown tail must remain unmapped"
        );

        // 3. Copied-mm fork inherits live grown prefix snapshot.
        let child_protections =
            Arc::new(MemoryProtections::from_snapshot(protections.snapshot_all()));
        assert!(
            !child_protections.range_no_access(LINUX_HEAP_BASE, 0x1000),
            "forked child must inherit grown prefix as accessible"
        );
        assert!(
            child_protections.range_unmapped(LINUX_HEAP_BASE + 0x1000, 0x1000),
            "forked child must inherit ungrown tail as unmapped"
        );

        // 4. CLONE_VM sibling shares the exact same Arc.
        let sibling_protections = Arc::clone(&protections);
        assert!(
            Arc::ptr_eq(&protections, &sibling_protections),
            "CLONE_VM sibling must share the same UserMemoryAuthority"
        );

        // 5. Exec replacement resets heap on fresh mm.
        let exec_protections = Arc::new(MemoryProtections::default());
        seed_heap_unmapped(&exec_protections);
        assert!(
            exec_protections.range_unmapped(LINUX_HEAP_BASE, 0x1000),
            "execve must seed fresh mm heap as unmapped"
        );
        assert!(
            exec_protections.range_unmapped(LINUX_HEAP_BASE + LINUX_HEAP_SIZE - 0x1000, 0x1000),
            "execve must seed full heap as unmapped"
        );
    }

    #[test]
    fn stage1_protection_edit_fork_cow_downgrade_preserves_requested_exec_not_stale_arm() {
        use carrick_abi::{LINUX_PROT_EXEC, LINUX_PROT_READ, LINUX_PROT_WRITE};
        use carrick_mmu_core::aarch64::{
            LeafAccess, terminal_descriptor, terminal_descriptor_permits_el0,
        };

        const PAGE_SIZE: u64 = 0x1000;
        const NON_GLOBAL: u64 = 1 << 11;
        const UXN: u64 = 1 << 54;
        const AP_MASK: u64 = 0b11 << 6;
        const AP_USER_RW: u64 = 0b01 << 6;
        const AP_USER_RO: u64 = 0b11 << 6;
        const PA_MASK_PAGE: u64 = 0x0000_FFFF_FFFF_F000;

        let leaf =
            |mgr: &PageTableManager, va: u64| -> u64 { terminal_descriptor(mgr.debug_walk(va)) };

        // --------------------------------------------------------------------
        // Case 1: Stale arm executable=true -> Requested RW (non-exec)
        // Must remove execution permission (UXN set) while keeping write trap armed (RO).
        // --------------------------------------------------------------------
        let bytes = carrick_mem::memory::stage1_hvpatch_page_tables();
        let mut mgr = PageTableManager::new(
            bytes,
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );

        // Non-identity VA and IPA
        let base_va: u64 = 0x40_0088_c000;
        let base_ipa: u64 = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x20_0000;
        let edit_len: usize = 4 * PAGE_SIZE as usize; // 4 pages in edit: [0..4)
        let total_mapped_len: u64 = 5 * PAGE_SIZE; // 5th page is neighbor [4..5)

        mgr.map_private_aliased(
            base_va,
            base_ipa,
            total_mapped_len,
            carrick_mmu_core::aarch64::UserLeafAccess {
                writable: true,
                executable: true,
            },
            None,
        )
        .expect("map initial non-identity pages");

        let cow_range_stale_exec = crate::vmm::ForkCowRange {
            va: base_va + PAGE_SIZE,
            len: 2 * PAGE_SIZE as usize, // pages 1 and 2
            executable: true,            // Stale historical fork-arm property
            kernel_only: false,
            granule: crate::vmm::CowGranule::Page,
        };

        let neighbor_va = base_va + 4 * PAGE_SIZE;
        let neighbor_before = leaf(&mgr, neighbor_va);
        assert_ne!(neighbor_before, 0);

        let changed = apply_stage1_protection_edit(
            &mut mgr,
            base_va,
            edit_len,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            &[cow_range_stale_exec],
        )
        .expect("apply RW protection edit");
        assert!(changed.changed, "protection edit must report changes");
        assert!(
            changed.flush_required,
            "protection edit on valid pages must require flush"
        );

        // Page 0 (un-armed in range): RW, NX, IPA preserved, non-global preserved
        let d0 = leaf(&mgr, base_va);
        assert_eq!(d0 & PA_MASK_PAGE, base_ipa);
        assert_ne!(d0 & NON_GLOBAL, 0, "page 0 must be non-global");
        assert_eq!(d0 & AP_MASK, AP_USER_RW, "page 0 must be RW");
        assert_ne!(d0 & UXN, 0, "page 0 must have UXN set (non-exec)");
        assert!(terminal_descriptor_permits_el0(d0, LeafAccess::Read));
        assert!(terminal_descriptor_permits_el0(d0, LeafAccess::Write));
        assert!(!terminal_descriptor_permits_el0(d0, LeafAccess::Execute));

        // Pages 1 & 2 (armed COW): must be RO, NX (exec removed despite stale arm executable=true),
        // non-identity IPA preserved, non-global preserved.
        for page_idx in 1..=2 {
            let va = base_va + page_idx * PAGE_SIZE;
            let expected_ipa = base_ipa + page_idx * PAGE_SIZE;
            let d = leaf(&mgr, va);

            assert_eq!(
                d & PA_MASK_PAGE,
                expected_ipa,
                "page {page_idx} IPA must be preserved"
            );
            assert_ne!(d & NON_GLOBAL, 0, "page {page_idx} must remain non-global");
            assert_eq!(
                d & AP_MASK,
                AP_USER_RO,
                "page {page_idx} must stay read-only (write trap armed)"
            );
            assert_ne!(
                d & UXN,
                0,
                "page {page_idx} must have UXN set (requested RW removes execution despite stale range.executable=true)"
            );
            assert!(terminal_descriptor_permits_el0(d, LeafAccess::Read));
            assert!(
                !terminal_descriptor_permits_el0(d, LeafAccess::Write),
                "COW page {page_idx} must not be writable"
            );
            assert!(
                !terminal_descriptor_permits_el0(d, LeafAccess::Execute),
                "COW page {page_idx} must not be executable under requested RW"
            );
        }

        // Page 3 (un-armed in range): RW, NX, IPA preserved, non-global preserved
        let d3 = leaf(&mgr, base_va + 3 * PAGE_SIZE);
        assert_eq!(d3 & PA_MASK_PAGE, base_ipa + 3 * PAGE_SIZE);
        assert_ne!(d3 & NON_GLOBAL, 0, "page 3 must be non-global");
        assert_eq!(d3 & AP_MASK, AP_USER_RW, "page 3 must be RW");
        assert_ne!(d3 & UXN, 0, "page 3 must have UXN set (non-exec)");
        assert!(terminal_descriptor_permits_el0(d3, LeafAccess::Read));
        assert!(terminal_descriptor_permits_el0(d3, LeafAccess::Write));
        assert!(!terminal_descriptor_permits_el0(d3, LeafAccess::Execute));

        // Neighbor page 4 (outside clipped/edited range): completely unchanged
        let neighbor_after = leaf(&mgr, neighbor_va);
        assert_eq!(
            neighbor_before, neighbor_after,
            "neighbor page outside edit range must be unchanged"
        );

        // --------------------------------------------------------------------
        // Case 2: Stale arm executable=false -> Requested RWX
        // Must grant execution permission (UXN clear) while keeping write trap armed (RO).
        // --------------------------------------------------------------------
        let bytes = carrick_mem::memory::stage1_hvpatch_page_tables();
        let mut mgr = PageTableManager::new(
            bytes,
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );

        mgr.map_private_aliased(
            base_va,
            base_ipa,
            total_mapped_len,
            carrick_mmu_core::aarch64::UserLeafAccess {
                writable: true,
                executable: true,
            },
            None,
        )
        .expect("map initial non-identity pages");

        let cow_range_stale_nonexec = crate::vmm::ForkCowRange {
            va: base_va + PAGE_SIZE,
            len: 2 * PAGE_SIZE as usize, // pages 1 and 2
            executable: false,           // Stale historical fork-arm property
            kernel_only: false,
            granule: crate::vmm::CowGranule::Page,
        };

        let neighbor_before = leaf(&mgr, neighbor_va);

        let changed = apply_stage1_protection_edit(
            &mut mgr,
            base_va,
            edit_len,
            LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC,
            &[cow_range_stale_nonexec],
        )
        .expect("apply RWX protection edit");
        assert!(changed.changed, "protection edit must report changes");
        assert!(
            changed.flush_required,
            "protection edit on valid pages must require flush"
        );

        // Page 0 (un-armed in range): RW, Executable, IPA preserved, non-global preserved
        let d0 = leaf(&mgr, base_va);
        assert_eq!(d0 & PA_MASK_PAGE, base_ipa);
        assert_ne!(d0 & NON_GLOBAL, 0, "page 0 must be non-global");
        assert_eq!(d0 & AP_MASK, AP_USER_RW, "page 0 must be RW");
        assert_eq!(d0 & UXN, 0, "page 0 must have UXN clear (executable)");
        assert!(terminal_descriptor_permits_el0(d0, LeafAccess::Read));
        assert!(terminal_descriptor_permits_el0(d0, LeafAccess::Write));
        assert!(terminal_descriptor_permits_el0(d0, LeafAccess::Execute));

        // Pages 1 & 2 (armed COW): must be RO, Executable (exec granted despite stale arm executable=false),
        // non-identity IPA preserved, non-global preserved.
        for page_idx in 1..=2 {
            let va = base_va + page_idx * PAGE_SIZE;
            let expected_ipa = base_ipa + page_idx * PAGE_SIZE;
            let d = leaf(&mgr, va);

            assert_eq!(
                d & PA_MASK_PAGE,
                expected_ipa,
                "page {page_idx} IPA must be preserved"
            );
            assert_ne!(d & NON_GLOBAL, 0, "page {page_idx} must remain non-global");
            assert_eq!(
                d & AP_MASK,
                AP_USER_RO,
                "page {page_idx} must stay read-only (write trap armed)"
            );
            assert_eq!(
                d & UXN,
                0,
                "page {page_idx} must have UXN clear (requested RWX grants execution despite stale range.executable=false)"
            );
            assert!(terminal_descriptor_permits_el0(d, LeafAccess::Read));
            assert!(
                !terminal_descriptor_permits_el0(d, LeafAccess::Write),
                "COW page {page_idx} must not be writable"
            );
            assert!(
                terminal_descriptor_permits_el0(d, LeafAccess::Execute),
                "COW page {page_idx} must be executable under requested RWX"
            );
        }

        // Page 3 (un-armed in range): RW, Executable, IPA preserved, non-global preserved
        let d3 = leaf(&mgr, base_va + 3 * PAGE_SIZE);
        assert_eq!(d3 & PA_MASK_PAGE, base_ipa + 3 * PAGE_SIZE);
        assert_ne!(d3 & NON_GLOBAL, 0, "page 3 must be non-global");
        assert_eq!(d3 & AP_MASK, AP_USER_RW, "page 3 must be RW");
        assert_eq!(d3 & UXN, 0, "page 3 must have UXN clear (executable)");
        assert!(terminal_descriptor_permits_el0(d3, LeafAccess::Read));
        assert!(terminal_descriptor_permits_el0(d3, LeafAccess::Write));
        assert!(terminal_descriptor_permits_el0(d3, LeafAccess::Execute));

        // Neighbor page 4 (outside clipped/edited range): completely unchanged
        let neighbor_after = leaf(&mgr, neighbor_va);
        assert_eq!(
            neighbor_before, neighbor_after,
            "neighbor page outside edit range must be unchanged"
        );
    }

    #[derive(Debug)]
    struct DummyArenaSource(carrick_mmu_core::aarch64::TableArenaSourceId);
    impl carrick_mmu_core::aarch64::TableArenaSource for DummyArenaSource {
        fn id(&self) -> carrick_mmu_core::aarch64::TableArenaSourceId {
            self.0
        }
        fn take_arena(&mut self) -> Option<carrick_mmu_core::aarch64::SubstrateGpa> {
            None
        }
        fn return_arena(&mut self, _base: carrick_mmu_core::aarch64::SubstrateGpa) {}
    }

    #[test]
    fn replace_page_tables_authority_preserves_parent_manager_and_source_when_shared() {
        let bytes = carrick_mem::memory::stage1_identity_page_tables();
        let manager = PageTableManager::new(
            bytes,
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );
        let source_id = carrick_mmu_core::aarch64::TableArenaSourceId(
            carrick_mmu_core::aarch64::SubstrateGpa(0x1000),
        );
        let parent_authority = Stage1Authority::new_with_manager(Some(manager));
        parent_authority
            .install_source(Box::new(DummyArenaSource(source_id)))
            .expect("set arena source on parent authority");
        assert!(parent_authority.has_source());

        // When shared with vfork child
        parent_authority.share_with_vfork_child();
        let mut child_authority = parent_authority.clone();
        assert!(child_authority.is_shared_with_vfork_child());

        let mut retired = false;
        let mut bound = false;
        replace_page_tables_authority(
            &mut child_authority,
            None,
            |_| {
                retired = true;
                Ok(())
            },
            |_| {
                bound = true;
            },
        )
        .expect("replace page tables authority");

        assert!(
            !retired,
            "must not retire parent's extension arenas when shared"
        );
        assert!(bound, "must bind fresh child authority");

        // Parent tables and source must be completely preserved.
        assert!(
            parent_authority.is_present(),
            "parent manager must not be stolen"
        );
        assert!(
            parent_authority.has_source(),
            "parent must retain its arena source"
        );
        assert!(
            parent_authority.is_exclusive(),
            "parent must be restored to Exclusive after child exec"
        );

        // Child must have detached to a distinct authority and have no source.
        assert!(!parent_authority.shares_exact_authority(&child_authority));
        assert!(!child_authority.has_source());
    }

    #[test]
    fn replace_page_tables_authority_preserves_parent_under_concurrent_vfork_children() {
        let bytes = carrick_mem::memory::stage1_identity_page_tables();
        let manager = PageTableManager::new(
            bytes,
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );
        let source_id = carrick_mmu_core::aarch64::TableArenaSourceId(
            carrick_mmu_core::aarch64::SubstrateGpa(0x1000),
        );
        let parent_authority = Stage1Authority::new_with_manager(Some(manager));
        parent_authority
            .install_source(Box::new(DummyArenaSource(source_id)))
            .expect("set arena source on parent authority");

        // Two concurrent vfork children are created from parent
        parent_authority.share_with_vfork_child();
        parent_authority.share_with_vfork_child();
        let mut child1_authority = parent_authority.clone();
        let mut child2_authority = parent_authority.clone();
        assert!(child1_authority.is_shared_with_vfork_child());
        assert!(child2_authority.is_shared_with_vfork_child());

        // Child 1 execs first
        let mut retired1 = false;
        let mut bound1 = false;
        replace_page_tables_authority(
            &mut child1_authority,
            None,
            |_| {
                retired1 = true;
                Ok(())
            },
            |_| {
                bound1 = true;
            },
        )
        .expect("replace child1 authority");

        assert!(
            !retired1,
            "parent extension arenas must not be retired by child1"
        );
        assert!(bound1, "must bind fresh child1 authority");
        assert!(!parent_authority.shares_exact_authority(&child1_authority));

        // Parent must STILL have its manager and source, and STILL be shared with child2!
        assert!(
            parent_authority.is_present(),
            "parent manager must not be stolen"
        );
        assert!(
            parent_authority.has_source(),
            "parent source must not be stolen"
        );
        assert!(
            parent_authority.is_shared_with_vfork_child(),
            "parent must still be shared with child2"
        );
        assert!(!parent_authority.is_exclusive());

        // Child 2 execs second
        let mut retired2 = false;
        let mut bound2 = false;
        replace_page_tables_authority(
            &mut child2_authority,
            None,
            |_| {
                retired2 = true;
                Ok(())
            },
            |_| {
                bound2 = true;
            },
        )
        .expect("replace child2 authority");

        assert!(
            !retired2,
            "parent extension arenas must not be retired by child2"
        );
        assert!(bound2, "must bind fresh child2 authority");
        assert!(!parent_authority.shares_exact_authority(&child2_authority));

        // Now that child2 has exec'd, parent is restored to Exclusive!
        assert!(parent_authority.is_present(), "parent manager preserved");
        assert!(parent_authority.has_source(), "parent source preserved");
        assert!(
            parent_authority.is_exclusive(),
            "parent restored to Exclusive"
        );
        assert!(!parent_authority.is_shared_with_vfork_child());
    }

    #[test]
    fn execve_sharing_governed_solely_by_authority_even_on_disagreement() {
        let bytes = carrick_mem::memory::stage1_identity_page_tables();
        let manager = PageTableManager::new(
            bytes,
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );
        let source_id = carrick_mmu_core::aarch64::TableArenaSourceId(
            carrick_mmu_core::aarch64::SubstrateGpa(0x1000),
        );
        let parent_authority = Stage1Authority::new_with_manager(Some(manager));
        parent_authority
            .install_source(Box::new(DummyArenaSource(source_id)))
            .expect("set arena source on parent authority");

        // Authority is shared with a vfork child (vfork_shares > 0)
        parent_authority.share_with_vfork_child();
        let mut child_authority = parent_authority.clone();

        let mut retired = false;
        let mut bound = false;
        // Even if external caller/runtime expected exclusive (disagreement),
        // replace_page_tables_authority drives through replace_for_exec where
        // vfork_shares > 0 guarantees the exclusive path is NOT taken.
        replace_page_tables_authority(
            &mut child_authority,
            None,
            |_| {
                retired = true;
                Ok(())
            },
            |_| {
                bound = true;
            },
        )
        .expect("replace child authority");

        assert!(
            !retired,
            "parent arenas must NOT be retired while vfork_shares > 0"
        );
        assert!(bound, "new child authority must be bound");
        assert!(
            parent_authority.is_present(),
            "parent manager must not be stolen"
        );
        assert!(
            parent_authority.has_source(),
            "parent source must not be stolen"
        );
        assert_eq!(
            parent_authority.root_base(),
            Some(carrick_mem::memory::LINUX_PAGE_TABLES_BASE)
        );
        assert!(!parent_authority.shares_exact_authority(&child_authority));
    }

    #[test]
    fn replace_page_tables_authority_retires_old_when_unshared() {
        let bytes = carrick_mem::memory::stage1_identity_page_tables();
        let manager = PageTableManager::new(
            bytes,
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );
        let mut authority = Stage1Authority::new_with_manager(Some(manager));
        assert!(authority.is_exclusive());

        let mut retired = false;
        replace_page_tables_authority(
            &mut authority,
            None,
            |_| {
                retired = true;
                Ok(())
            },
            |_| {},
        )
        .expect("replace page tables authority");

        assert!(retired, "must retire old manager when solely owned");
    }

    #[test]
    fn stage1_authority_source_survives_snapshot_image() {
        let bytes = carrick_mem::memory::stage1_identity_page_tables();
        let manager = PageTableManager::new(
            bytes,
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );
        let source_id = carrick_mmu_core::aarch64::TableArenaSourceId(
            carrick_mmu_core::aarch64::SubstrateGpa(0x2000),
        );
        let authority = Stage1Authority::new_with_manager(Some(manager));
        authority
            .install_source(Box::new(DummyArenaSource(source_id)))
            .expect("install source");
        assert!(authority.has_source());

        let snapshot = authority.snapshot_image().expect("snapshot present");
        assert!(authority.has_source());
        assert_eq!(snapshot.base(), carrick_mem::memory::LINUX_PAGE_TABLES_BASE);
    }

    #[test]
    fn stage1_authority_source_survives_rollback() {
        let bytes = carrick_mem::memory::stage1_identity_page_tables();
        let manager = PageTableManager::new(
            bytes,
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );
        let source_id = carrick_mmu_core::aarch64::TableArenaSourceId(
            carrick_mmu_core::aarch64::SubstrateGpa(0x3000),
        );
        let authority = Stage1Authority::new_with_manager(Some(manager));
        authority
            .install_source(Box::new(DummyArenaSource(source_id)))
            .expect("install source");

        let snapshot = authority.snapshot_image().expect("snapshot");
        authority
            .edit(
                || unreachable!(),
                |editor| {
                    assert!(editor.has_arena_source());
                    editor.restore_image(&mut Some(snapshot), 6, 0)?;
                    assert!(editor.has_arena_source());
                    Ok::<(), PageTableError>(())
                },
            )
            .expect("edit");

        assert!(authority.has_source());
    }

    #[test]
    fn stage1_authority_source_survives_exec_while_shared() {
        let bytes = carrick_mem::memory::stage1_identity_page_tables();
        let manager = PageTableManager::new(
            bytes,
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );
        let source_id = carrick_mmu_core::aarch64::TableArenaSourceId(
            carrick_mmu_core::aarch64::SubstrateGpa(0x4000),
        );
        let parent = Stage1Authority::new_with_manager(Some(manager));
        parent
            .install_source(Box::new(DummyArenaSource(source_id)))
            .expect("install source");
        parent.share_with_vfork_child();

        let mut child = parent.clone();
        let mut retired = false;
        let new_child = child
            .replace_for_exec(
                || Ok::<Option<PageTableManager>, ()>(None),
                |_| {
                    retired = true;
                    Ok(())
                },
            )
            .expect("replace_for_exec");

        assert!(!retired);
        assert!(parent.has_source());
        assert!(parent.is_exclusive());
        assert!(!new_child.has_source());
    }

    #[test]
    fn stage1_authority_sibling_lazy_build_sees_source() {
        let authority = Stage1Authority::new();
        let source_id = carrick_mmu_core::aarch64::TableArenaSourceId(
            carrick_mmu_core::aarch64::SubstrateGpa(0x5000),
        );
        authority
            .install_source(Box::new(DummyArenaSource(source_id)))
            .expect("deferred install");
        assert!(authority.is_none());
        assert!(authority.has_source());

        let sibling = authority.clone();
        sibling.increment_engine_count();
        assert_eq!(sibling.engines(), 2);

        sibling
            .edit(
                || {
                    let bytes = carrick_mem::memory::stage1_identity_page_tables();
                    Ok::<PageTableManager, PageTableError>(PageTableManager::new(
                        bytes,
                        carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
                        carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
                    ))
                },
                |editor| {
                    assert!(editor.has_arena_source());
                    Ok::<(), PageTableError>(())
                },
            )
            .expect("lazy build on sibling edit");

        assert!(authority.is_present());
        assert!(authority.has_source());
        assert!(sibling.has_source());
    }

    #[test]
    fn stage1_authority_deferred_install_on_one_clone_then_build_on_another() {
        let clone1 = Stage1Authority::new();
        let clone2 = clone1.clone();

        let source_id = carrick_mmu_core::aarch64::TableArenaSourceId(
            carrick_mmu_core::aarch64::SubstrateGpa(0x6000),
        );
        clone1
            .install_source(Box::new(DummyArenaSource(source_id)))
            .expect("install on clone1");

        assert!(clone2.has_source());
        assert!(clone2.is_none());

        clone2
            .edit(
                || {
                    let bytes = carrick_mem::memory::stage1_identity_page_tables();
                    Ok::<PageTableManager, PageTableError>(PageTableManager::new(
                        bytes,
                        carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
                        carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
                    ))
                },
                |editor| {
                    assert!(editor.has_arena_source());
                    Ok::<(), PageTableError>(())
                },
            )
            .expect("edit on clone2");

        assert!(clone1.is_present());
        assert!(clone1.has_source());
    }

    #[test]
    fn stage1_authority_conflicting_lease_rejection() {
        let authority = Stage1Authority::new();
        let source_id1 = carrick_mmu_core::aarch64::TableArenaSourceId(
            carrick_mmu_core::aarch64::SubstrateGpa(0x7000),
        );
        let source_id2 = carrick_mmu_core::aarch64::TableArenaSourceId(
            carrick_mmu_core::aarch64::SubstrateGpa(0x8000),
        );

        authority
            .install_source(Box::new(DummyArenaSource(source_id1)))
            .expect("install first source");

        let res = authority.install_source(Box::new(DummyArenaSource(source_id2)));
        assert_eq!(res.unwrap_err(), PageTableError::ConflictingArenaSource);
    }

    #[test]
    fn test_metadata_allocation_error_propagation_is_nonallocating() {
        let pt_err = PageTableError::MetadataAllocation;
        let mem_err = page_table_sync_error_to_memory_error(pt_err);
        assert_eq!(mem_err, MemoryError::MetadataAllocation);
        let trap_err = memory_error_to_trap_error(mem_err, "test context");
        assert!(matches!(trap_err, TrapError::MetadataAllocation));

        let rollback_mem_err = page_table_rollback_error_to_memory_error(pt_err);
        assert_eq!(rollback_mem_err, MemoryError::MetadataAllocation);
        let rollback_trap_err = memory_error_to_trap_error(rollback_mem_err, "test rollback");
        assert!(matches!(rollback_trap_err, TrapError::MetadataAllocation));
    }
}

impl<V: Aarch64Vmm> Aarch64EngineCore<V> {
    fn transfer_owner_fork_parent_bytes(
        &mut self,
        request: crate::user_transfer::UserTransfer,
        admission: &mut dyn carrick_guest_mem::BorrowedTtbr0Admission,
    ) -> Result<Vec<u8>, TrapError> {
        let operation = self.pending_owner_fork_operation();
        let custody = self
            .vm
            .owner_transfer_custody()
            .ok_or(TrapError::UnsupportedPlatform)?;
        let ttbr0 = self.vcpu.get_mut().get_sys_reg(SysReg::Ttbr0)?;
        let region = carrick_el1_abi::get_el1_region_host_ptr();
        if region == 0 {
            return Err(TrapError::UnsupportedPlatform);
        }
        // SAFETY: the live engine retains its carrier metadata region.
        let slots = unsafe {
            &*((region + carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize)
                as *const carrick_el1_abi::MmPortalSlots)
        };
        admission.arm().map_err(TrapError::Hypervisor)?;
        let target = if let Some(operation) = operation {
            // SAFETY: the retained operation authenticates the parent root.
            let handle = unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    operation.carrier,
                    operation.mm,
                    operation.incarnation,
                )
            };
            crate::user_transfer::TransferTarget::from_handle(handle, ttbr0)
        } else {
            let mm = carrick_el1_abi::ReservationMm::new(self.mm_generation)
                .ok_or(TrapError::UnsupportedPlatform)?;
            crate::user_transfer::TransferTarget::bind(self, mm, ttbr0, custody.as_ref(), slots)?
                .ok_or(TrapError::UnsupportedPlatform)?
        };
        let mut transfer = crate::user_transfer::OwnedUserTransfer::new(target, request)
            .ok_or_else(|| TrapError::Hypervisor("owner parent transfer range overflow".into()))?;
        if let Some(operation) = operation
            && !transfer.authorize_fork_parent_write(operation)
        {
            return Err(TrapError::UnsupportedPlatform);
        }
        loop {
            match transfer.advance(self, custody.as_ref(), slots)? {
                crate::user_transfer::TransferProgress::Complete => {
                    return Ok(transfer.into_bytes());
                }
                crate::user_transfer::TransferProgress::Advanced => {}
                crate::user_transfer::TransferProgress::Suspended
                | crate::user_transfer::TransferProgress::OwnerWait(_)
                | crate::user_transfer::TransferProgress::Retired(_)
                | crate::user_transfer::TransferProgress::Physical(_)
                | crate::user_transfer::TransferProgress::Supply(_)
                | crate::user_transfer::TransferProgress::Refused(_) => {
                    return Err(TrapError::Hypervisor(
                        "owner parent transfer refused".into(),
                    ));
                }
            }
        }
    }
    /// Run a Fork exchange on the driving task's retained service stack. The
    /// request names both roots exactly; no host descriptor editor is lent.
    pub fn run_owner_parent_transfer(
        &self,
        frame: carrick_el1_abi::TrapFrame,
        target: crate::user_transfer::TransferTarget,
        sequence: core::num::NonZeroU64,
        effect: &mut dyn FnMut() -> bool,
    ) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
        self.transfer_service_loan()?
            .run_parent(frame, target, sequence, effect)
    }

    pub fn pending_owner_fork_operation(&self) -> Option<carrick_el1_abi::PortalOperation> {
        self.pending_owner_fork
            .as_ref()
            .map(|owner| owner.pending.completion().request.operation)
    }

    fn build_owner_process_spec(
        &mut self,
        mut request: ProcessForkRequest,
    ) -> Result<Aarch64ProcessSpec<V>, TrapError> {
        if self.pending_process_fork.is_some() || self.pending_owner_fork.is_some() {
            return Err(TrapError::Hypervisor(
                "overlapping owner Fork transaction".into(),
            ));
        }
        if request.shares_mm() {
            return Err(TrapError::Hypervisor(
                "shared owner roots use the shared task lifetime adapter".into(),
            ));
        }
        let (parent_mm, child_mm) = request.plan.owner_target().ok_or_else(|| {
            TrapError::Hypervisor("owner Fork request lost exact MM identity".into())
        })?;
        let mut physical = self.vm.prepare_owner_fork_builder(&mut request)?;
        let parent_tables = self
            .page_tables
            .reserve_owner_fork_arena()
            .map_err(TrapError::Hypervisor)?;
        let parent_arena = parent_tables
            .arena()
            .ok_or_else(|| TrapError::Hypervisor("owner Fork parent capacity is absent".into()))?;
        let mut bind = carrick_el1_abi::TrapFrame {
            esr: carrick_el1_abi::MM_PORTAL_BIND_ESR,
            ..Default::default()
        };
        bind.x[1] = physical.carrier().get();
        bind.x[2] = parent_mm;
        let bound = self.run_owner_fork_service(bind, &mut || false)?;
        if bound.x[0] != 0 {
            physical.settle(false)?;
            return Err(TrapError::Hypervisor(format!(
                "owner Fork parent bind refused: {}",
                bound.x[0]
            )));
        }
        let operation = carrick_el1_abi::PortalOperation {
            carrier: physical.carrier(),
            mm: carrick_el1_abi::ReservationMm::new(parent_mm)
                .ok_or_else(|| TrapError::Hypervisor("zero parent MM".into()))?,
            incarnation: core::num::NonZeroU64::new(bound.x[3]).ok_or_else(|| {
                TrapError::Hypervisor("owner bind returned zero incarnation".into())
            })?,
            sequence: core::num::NonZeroU64::new(bound.x[5])
                .ok_or_else(|| TrapError::Hypervisor("owner bind returned zero sequence".into()))?,
        };
        let fork = carrick_el1_abi::PortalForkRequest {
            operation,
            parent_generation: carrick_el1_abi::ReservationGeneration::new(bound.x[4]).ok_or_else(
                || TrapError::Hypervisor("owner bind returned zero generation".into()),
            )?,
            child_mm: carrick_el1_abi::ReservationMm::new(child_mm)
                .ok_or_else(|| TrapError::Hypervisor("zero child MM".into()))?,
            child_tables: physical.child_tables(),
            parent_tables: parent_arena,
            kernel_control_ipa: physical.kernel_control_ipa(),
        };
        let index = self
            .vcpu
            .borrow_mut()
            .mailbox_slot()
            .ok_or_else(|| TrapError::Hypervisor("owner Fork has no executor slot".into()))?;
        let region = carrick_el1_abi::get_el1_region_host_ptr();
        if region == 0 {
            return Err(TrapError::Hypervisor(
                "owner Fork has no retained carrier region".into(),
            ));
        }
        // SAFETY: this engine's VM retains the carrier metadata region for the
        // full pending operation; the exact slot survives task commit or abort.
        let slots = unsafe {
            &*((region + carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize)
                as *const carrick_el1_abi::MmPortalSlots)
        };
        let slot = slots
            .fork(index)
            .ok_or_else(|| TrapError::Hypervisor("owner Fork slot is invalid".into()))?;
        let pending = match crate::fork::prepare(fork, slot, physical.as_ref(), |frame, effect| {
            self.run_owner_fork_service(frame, effect)
        })? {
            Ok(pending) => pending,
            Err(errno) => {
                physical.settle(false)?;
                return Err(TrapError::OwnerForkRefused {
                    errno: carrick_abi::LinuxErrno::new(i32::try_from(errno).map_err(|_| {
                        TrapError::Hypervisor("owner Fork returned invalid errno".into())
                    })?),
                });
            }
        };
        let result = (|| {
            let builder = physical.consume_owner_fork_completion(
                &request,
                pending.completion(),
                pending.selected(),
            )?;
            let root = request.child_ttbr0 & 0x0000_ffff_ffff_f000;
            let layout = self
                .page_tables
                .with_manager(PageTableManager::layout)
                .ok_or_else(|| {
                    TrapError::Hypervisor("owner parent live observer is absent".into())
                })?;
            let resolver = physical.child_resolver();
            // SAFETY: physical preparation retains every table arena selected
            // by the owner; the resolver owns those exact allocations.
            let manager = unsafe {
                PageTableManager::new_live(
                    root,
                    layout,
                    fork.child_tables.len as usize,
                    Arc::clone(&resolver),
                )
            }
            .map_err(|error| {
                TrapError::Hypervisor(format!("observe owner child tables: {error:?}"))
            })?;
            let authority = Stage1Authority::new_with_manager(Some(manager));
            unsafe {
                authority.bind_live_backing(resolver);
            }
            authority.select_guest_descriptor_owner().map_err(|error| {
                TrapError::Hypervisor(format!("select owner child descriptor lane: {error:?}"))
            })?;
            if let Some(source) = request.table_arena_source.take() {
                authority.install_source(source).map_err(|error| {
                    TrapError::Hypervisor(format!("install owner child physical source: {error:?}"))
                })?;
            }
            let parent = self.vcpu.get_mut().snapshot()?;
            let mut snapshot = seed_sibling_snapshot(&parent, request.entry);
            snapshot.ttbr0 = request.child_ttbr0;
            snapshot.ttbr1 = request.child_ttbr0;
            let process_asid = (request.child_ttbr0 >> 48) as u16;
            if process_asid == 0 {
                return Err(TrapError::Hypervisor("owner child ASID is zero".into()));
            }
            Ok(Aarch64ProcessSpec {
                builder,
                snapshot,
                page_tables: authority,
                protections: UserMemoryAuthority::from_owner(pending.completion().child),
                process_asid,
            })
        })();
        match result {
            Ok(spec) => {
                self.pending_owner_fork = Some(OwnerForkTransaction {
                    pending,
                    physical,
                    parent_tables,
                });
                Ok(spec)
            }
            Err(error) => {
                let receipt = pending.finish(false, |frame, effect| {
                    self.run_owner_fork_service(frame, effect)
                })?;
                let retained_parent_tables = receipt.completion().parent_tables_used;
                drop(receipt);
                physical.settle(false)?;
                parent_tables
                    .settle(retained_parent_tables)
                    .map_err(TrapError::Hypervisor)?;
                Err(error)
            }
        }
    }

    pub(crate) fn transfer_service_loan(&self) -> Result<TransferServiceLoan<'_, V>, TrapError> {
        let cpu = self
            .vcpu
            .try_borrow_mut()
            .map_err(|_| TrapError::Hypervisor("owner service CPU is already borrowed".into()))?;
        Ok(TransferServiceLoan { engine: self, cpu })
    }

    pub fn run_owner_fork_service(
        &self,
        frame: carrick_el1_abi::TrapFrame,
        effect: &mut dyn FnMut() -> bool,
    ) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
        self.transfer_service_loan()?.run_fork(frame, effect)
    }

    /// Borrow the current executor exclusively and run the owner on the
    /// carrier maintenance root. No target translation or spare CPU is used.
    /// A true effect result means the intermediate copy was acknowledged and
    /// the same suspended EL1 stack must resume before register restoration.
    pub fn run_user_transfer_service(
        &self,
        frame: carrick_el1_abi::TrapFrame,
        effect: &mut dyn FnMut() -> bool,
    ) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
        self.transfer_service_loan()?.run_user(frame, effect)
    }
}

#[cfg(test)]
mod transfer_service_tests {
    use super::*;
    struct Cpu {
        regs: Vec<(Reg, u64)>,
        runs: usize,
        ttbr0: u64,
        fail_restore: bool,
    }
    impl Aarch64Vcpu for Cpu {
        fn get_reg(&self, r: Reg) -> Result<u64, TrapError> {
            Ok(self
                .regs
                .iter()
                .find(|(reg, _)| *reg == r)
                .map_or(0, |(_, value)| *value))
        }
        fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), TrapError> {
            if self.fail_restore && self.runs > 0 && r == Reg::X(0) {
                return Err(TrapError::Hypervisor("injected restore failure".into()));
            }
            if let Some((_, value)) = self.regs.iter_mut().find(|(reg, _)| *reg == r) {
                *value = v
            } else {
                self.regs.push((r, v))
            }
            Ok(())
        }
        fn get_sys_reg(&self, _: SysReg) -> Result<u64, TrapError> {
            Ok(self.ttbr0)
        }
        fn set_sys_reg(&mut self, _: SysReg, v: u64) -> Result<(), TrapError> {
            self.ttbr0 = v;
            Ok(())
        }
        fn get_vreg(&self, _: u32) -> Result<u128, TrapError> {
            Ok(0)
        }
        fn set_vreg(&mut self, _: u32, _: u128) -> Result<(), TrapError> {
            Ok(())
        }
        fn get_fpcr(&self) -> Result<u64, TrapError> {
            Ok(0)
        }
        fn set_fpcr(&mut self, _: u64) -> Result<(), TrapError> {
            Ok(())
        }
        fn get_fpsr(&self) -> Result<u64, TrapError> {
            Ok(0)
        }
        fn set_fpsr(&mut self, _: u64) -> Result<(), TrapError> {
            Ok(())
        }
        fn get_esr_el1(&self) -> Result<u64, TrapError> {
            Ok(0)
        }
        fn get_far_el1(&self) -> Result<u64, TrapError> {
            Ok(0)
        }
        fn snapshot(&self) -> Result<Aarch64VcpuSnapshot, TrapError> {
            Err(TrapError::Hypervisor("unused snapshot".into()))
        }
        fn restore(&mut self, _: &Aarch64VcpuSnapshot) -> Result<(), TrapError> {
            Ok(())
        }
        fn kick(&self) -> Result<(), TrapError> {
            Ok(())
        }
        fn run(&mut self) -> Result<Aarch64Exit, TrapError> {
            self.runs += 1;
            assert_eq!(self.ttbr0, 0x7000_0080_0000_0000);
            if self.runs == 1 {
                assert_eq!(self.get_reg(Reg::Pc)?, 0x1000);
                self.set_reg(Reg::Pc, 0x1114)?;
                self.set_reg(Reg::SpEl1, 0x2200)?;
                self.set_reg(Reg::X(19), 0xabcdef)?;
            } else {
                assert_eq!(self.runs, 2);
                assert_eq!(self.get_reg(Reg::Pc)?, 0x1114);
                assert_eq!(self.get_reg(Reg::SpEl1)?, 0x2200);
                assert_eq!(self.get_reg(Reg::X(19))?, 0xabcdef);
            }
            Ok(Aarch64Exit::MaintenanceDone)
        }
    }

    use crate::vmm::*;
    use carrick_hal::*;
    struct Vm;
    #[derive(Clone)]
    struct Kick;
    impl VcpuKick for Kick {
        fn kick(&self) {}
    }
    impl GuestVmBackend for Vm {
        fn host_ptr(&self, _: u64, _: usize) -> Option<*mut u8> {
            None
        }
        fn write_gpa(&self, _: u64, _: &[u8]) -> Result<(), TrapError> {
            panic!("no frame write expected")
        }
        fn fork_ram_strategy(&self) -> ForkRamStrategy {
            panic!("unused")
        }
    }
    #[allow(unused_variables)]
    impl Aarch64Vmm for Vm {
        type Vcpu = Cpu;
        type AnonymousDiscard = ();
        type KickHandle = Kick;
        type SiblingBuilder = ();
        type ProcessBuilder = ();
        fn carrier_maintenance_root(
            &self,
        ) -> Result<carrick_mem::memory::CarrierMaintenanceRoot, TrapError> {
            Ok(carrick_mem::memory::CarrierMaintenanceRoot::new(Gpa(
                carrick_el1_abi::EL1_CARRIER_MAINT_ROOT_BASE,
            )))
        }
        fn publish_user_executable(
            &self,
            output: u64,
            len: u64,
        ) -> Result<(), carrick_mmu_core::aarch64::PageTableError> {
            panic!("unused backend method")
        }
        fn map_stage2(
            &mut self,
            ipa: u64,
            host: *mut u8,
            len: u64,
            perms: MemPerms,
        ) -> Result<(), TrapError> {
            panic!("unused backend method")
        }
        fn read_gpa(&self, gpa: u64, len: usize) -> Result<Vec<u8>, TrapError> {
            panic!("unused backend method")
        }
        fn protections(&self) -> Option<LegacyProtectionRead<'_>> {
            panic!("unused backend method")
        }
        fn translated_read(&self, va: u64, ipa: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
            panic!("unused backend method")
        }
        fn translated_write(&mut self, va: u64, ipa: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            panic!("unused backend method")
        }
        fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
            panic!("unused backend method")
        }
        fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
            panic!("unused backend method")
        }
        fn add_alias(
            &mut self,
            va: u64,
            ipa: u64,
            len: u64,
            payload: &[u8],
            backing: HostAliasBacking,
        ) -> Result<(u64, bool), TrapError> {
            panic!("unused backend method")
        }
        fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError> {
            panic!("unused backend method")
        }
        fn execve_rebuild(
            &mut self,
            vcpu: &mut Self::Vcpu,
            new_image: &AddressSpace,
        ) -> Result<(), TrapError> {
            panic!("unused backend method")
        }
        fn kick_handle(&self) -> Self::KickHandle {
            panic!("unused backend method")
        }
        fn build_sibling_builder(
            &self,
            vcpu: &Self::Vcpu,
            entry: GuestEntryRegs,
        ) -> Result<Self::SiblingBuilder, TrapError> {
            panic!("unused backend method")
        }
        fn materialize_sibling(
            builder: Self::SiblingBuilder,
        ) -> Result<(Self, Self::Vcpu), TrapError> {
            panic!("unused backend method")
        }
        fn set_guest_sp(&self, vcpu: &Self::Vcpu, sp: u64) -> Result<(), TrapError> {
            panic!("unused backend method")
        }
        fn fresh_fork_kicker(&self) -> Arc<dyn VcpuRegistry> {
            panic!("unused backend method")
        }
    }
    fn engine_fixture() -> Aarch64EngineCore<Vm> {
        Aarch64EngineCore::from_injected_task_only_backend(
            Vm,
            Cpu {
                regs: Vec::new(),
                runs: 0,
                ttbr0: 0x7000_0080_0000_0000,
                fail_restore: false,
            },
            Stage1Authority::new(),
            UserMemoryAuthority::from_legacy(Arc::new(MemoryProtections::default())),
            None,
            0,
            0,
        )
    }
    #[test]
    fn admitted_owner_refuses_legacy_raw_write_preparation() {
        let mut engine = engine_fixture();
        // This fixture does not execute the owner. It tests that a named owner
        // cannot enter legacy descriptor/grant preparation in the first place.
        let handle = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                core::num::NonZeroU64::new(17).unwrap(),
                carrick_el1_abi::ReservationMm::new(88).unwrap(),
                core::num::NonZeroU64::new(3).unwrap(),
            )
        };
        engine.protections = UserMemoryAuthority::from_owner(handle);
        assert!(matches!(
            engine.prepare_host_write(0x4000, 1),
            Err(MemoryError::Unsupported)
        ));
    }
    struct Custody;
    impl crate::user_transfer::TransferCustody for Custody {
        type Pin = Box<dyn crate::user_transfer::TransferPin>;
        fn carrier(&self) -> core::num::NonZeroU64 {
            core::num::NonZeroU64::new(17).unwrap()
        }
        fn prepare(
            &self,
            _: crate::user_transfer::TransferTarget,
            _: carrick_el1_abi::PortalGrantWindow,
        ) -> Result<Option<Box<dyn crate::user_transfer::TransferGrant>>, TrapError> {
            panic!("no grant expected")
        }
        fn publish_executable(
            &self,
            _: crate::user_transfer::TransferTarget,
            _: carrick_el1_abi::PortalExecutablePublication,
        ) -> bool {
            panic!("no publication expected")
        }
        fn refill_cow(
            &self,
            _: crate::user_transfer::TransferTarget,
            _: carrick_el1_abi::PortalGrantWindow,
        ) -> Result<bool, TrapError> {
            panic!("no refill expected")
        }
        fn retain(
            &self,
            _: carrick_el1_abi::PortalSelectedData,
            _: usize,
            _: carrick_el1_abi::PortalTransferIntent,
        ) -> Result<Option<Self::Pin>, TrapError> {
            panic!("no pin expected")
        }
    }
    #[test]
    fn nested_shared_service_entry_refuses_without_panicking_or_effects() {
        let engine = engine_fixture();
        let mut outer = engine.vcpu.borrow_mut();
        let saved = outer.regs.clone();
        let mut calls = 0;
        run_el1_service_effect_on(&mut *outer, 0x1000, 0x3000, true, &mut || {
            calls += 1;
            let nested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                engine.run_owner_fork_service(carrick_el1_abi::TrapFrame::default(), &mut || {
                    panic!("nested effect")
                })
            }));
            assert!(
                nested.is_ok(),
                "nested service must return checked busy, not panic"
            );
            assert!(nested.unwrap().is_err());
            assert!(
                engine
                    .run_user_transfer_service(
                        carrick_el1_abi::TrapFrame::default(),
                        &mut || panic!("nested effect")
                    )
                    .is_err()
            );
            false
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert!(saved.is_empty());
        assert!(outer.regs.iter().all(|(_, value)| *value == 0));
    }
    // Installs the shared ABI region pointer; must run on the serial host lane.
    #[test]
    fn serial_host_busy_transfer_admission_keeps_carrier_unbound() {
        use crate::user_transfer::{
            OwnedUserTransfer, TransferCustody, TransferTarget, UserTransfer,
        };
        let engine = engine_fixture();
        let slots = Box::new(carrick_el1_abi::MmPortalSlots::new());
        let previous = carrick_el1_abi::get_el1_region_host_ptr();
        struct Restore(usize);
        impl Drop for Restore {
            fn drop(&mut self) {
                carrick_el1_abi::record_el1_region_host_ptr(self.0);
            }
        }
        let _restore = Restore(previous);
        // Binding only authenticates the slot address; busy admission must
        // refuse before dereferencing any other part of this synthetic region.
        carrick_el1_abi::record_el1_region_host_ptr(
            (&*slots as *const _ as usize) - carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize,
        );
        let custody = Custody;
        let mm = carrick_el1_abi::ReservationMm::new(1).unwrap();
        let held = engine.vcpu.borrow();
        assert!(TransferTarget::bind(&engine, mm, 0x9000, &custody, &slots).is_err());
        assert_eq!(
            slots.carrier(),
            None,
            "busy service must not permanently bind carrier"
        );
        drop(held);
        let handle = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                custody.carrier(),
                mm,
                core::num::NonZeroU64::new(1).unwrap(),
            )
        };
        let target = TransferTarget::from_handle(handle, 0x9000);
        let mut transfer = OwnedUserTransfer::new(
            target,
            UserTransfer::CopyOut {
                address: 0x4000,
                bytes: vec![1],
            },
        )
        .unwrap();
        let held = engine.vcpu.borrow_mut();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            transfer.advance(&engine, &custody, &slots)
        }));
        assert!(result.is_ok(), "advance must refuse checked CPU admission");
        assert!(result.unwrap().is_err());
        assert_eq!(slots.carrier(), None);
        assert!(
            engine
                .run_owner_parent_transfer(
                    carrick_el1_abi::TrapFrame::default(),
                    target,
                    core::num::NonZeroU64::new(1).unwrap(),
                    &mut || panic!("nested parent effect")
                )
                .is_err()
        );
        assert_eq!(held.runs, 0);
    }

    #[test]
    fn serial_host_transfer_restore_failure_is_terminal() {
        const CHILD: &str = "CARRICK_TEST_TRANSFER_RESTORE_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let mut cpu = Cpu {
                regs: Vec::new(),
                runs: 0,
                ttbr0: 0x7000_0080_0000_0000,
                fail_restore: true,
            };
            let result = run_el1_service_effect_on(&mut cpu, 0x1000, 0x3000, true, &mut || false);
            assert!(result.is_err());
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("engine::transfer_service_tests::serial_host_transfer_restore_failure_is_terminal")
            .arg("--nocapture")
            .env(CHILD, "1")
            .output()
            .unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            output.status.signal(),
            Some(libc::SIGABRT),
            "partially restored CPU must never return a recoverable result: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn maintenance_transfer_uses_current_cpu_and_restores_root_after_failure() {
        let original = 0x1700_009a_0020_0000;
        let mut cpu = Cpu {
            regs: Vec::new(),
            runs: 0,
            ttbr0: original,
            fail_restore: false,
        };
        let root = carrick_mem::memory::CarrierMaintenanceRoot::new(Gpa(
            carrick_el1_abi::EL1_CARRIER_MAINT_ROOT_BASE,
        ));
        let result: Result<(), TrapError> = with_maintenance_transfer_root(&mut cpu, root, |cpu| {
            assert_eq!(cpu.ttbr0, carrick_el1_abi::EL1_CARRIER_MAINT_ROOT_BASE);
            assert_eq!(cpu.runs, 0);
            Err(TrapError::Hypervisor("injected service refusal".into()))
        });
        assert!(result.is_err());
        assert_eq!(cpu.ttbr0, original);
        let wrong = carrick_mem::memory::CarrierMaintenanceRoot::new(Gpa(original));
        let result: Result<(), TrapError> = with_maintenance_transfer_root(&mut cpu, wrong, |_| {
            panic!("unrecognized root must be refused before service effects")
        });
        assert!(result.is_err());
        assert_eq!(cpu.ttbr0, original);
    }

    #[test]
    fn transfer_copy_and_cancel_resume_exact_service_stack_before_restoration() {
        for copied in [false, true] {
            let mut cpu = Cpu {
                regs: Vec::new(),
                runs: 0,
                ttbr0: 0x7000_0080_0000_0000,
                fail_restore: false,
            };
            let mut regs: Vec<_> = (0..31).map(Reg::X).collect();
            regs.extend([Reg::Pc, Reg::Pstate, Reg::ElrEl1, Reg::SpsrEl1, Reg::SpEl1]);
            for (i, reg) in regs.iter().copied().enumerate() {
                cpu.set_reg(reg, 0x8000 + i as u64).unwrap();
            }
            let saved = cpu.regs.clone();
            let mut exits = 0;
            let mut acknowledged = None;
            run_el1_service_effect_on(&mut cpu, 0x1000, 0x3000, true, &mut || {
                exits += 1;
                if exits == 1 {
                    acknowledged = Some(copied);
                    true
                } else {
                    false
                }
            })
            .unwrap();
            assert_eq!(exits, 2);
            assert_eq!(acknowledged, Some(copied));
            assert_eq!(cpu.runs, 2);
            assert_eq!(cpu.regs, saved);
        }
    }
}
