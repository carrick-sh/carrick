//! In-guest EL1 fault handling and dispatch.

use carrick_el1_abi::{
    Action, Counters, CurrentTask, FrameGrantMailbox, FrameGrantMailboxes, ReservationIncarnation,
    TrapFrame,
};
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorOutcome, DescriptorReceipt, DescriptorTxnSlot,
};
use carrick_mmu_core::aarch64::{GuestPreparedCommit, GuestPreparedCommitError, LeafAccess};
use carrick_sched_core::spaces::notification::SpaceAccess;
use core::num::NonZeroU64;
#[cfg(any(test, target_os = "none"))]
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

/// The host now owns frame-grant publication; EL1 has no publication error.
pub fn panic_publication_detail() -> u64 {
    0
}

pub use carrick_core::mm::fault::{
    request_lazy_frames, root_fault_admission, root_mapping_incarnation,
};

/// Decode an EL0 translation fault that can be satisfied by publishing fresh
/// anonymous backing. Permission faults name an already-mapped page and must
/// follow the protection/COW path; requesting another frame for them adds a
/// host round trip and can never authorize the denied access.
fn frame_grant_access(esr: u64) -> Option<u64> {
    let ec = (esr >> 26) & 0x3f;
    let dfsc = esr & 0x3f;
    if !matches!(ec, 0x20 | 0x21 | 0x24 | 0x25) || !(0x04..=0x07).contains(&dfsc) {
        return None;
    }
    Some(if matches!(ec, 0x20 | 0x21) {
        4
    } else if esr & (1 << 6) != 0 {
        2
    } else {
        1
    })
}

fn prepared_fault_access(esr: u64) -> Option<LeafAccess> {
    let ec = (esr >> 26) & 0x3f;
    let status = esr & 0x3f;
    if !(0x04..=0x07).contains(&status) {
        return None;
    }
    match ec {
        0x20 | 0x21 => Some(LeafAccess::Execute),
        0x24 | 0x25 if esr & (1 << 6) != 0 => Some(LeafAccess::Write),
        0x24 | 0x25 => Some(LeafAccess::Read),
        _ => None,
    }
}

/// The guest fault policy's input after the native entry leaf has classified
/// its own fault encoding. No ISA syndrome is interpreted by the policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultClass {
    Translation {
        access: LeafAccess,
        grant_access: u64,
    },
    WritePermission,
    Protection(LeafAccess),
    Other,
}

fn arm_fault_class(esr: u64) -> FaultClass {
    if is_write_permission_fault(esr) {
        return FaultClass::WritePermission;
    }
    match (prepared_fault_access(esr), frame_grant_access(esr)) {
        (Some(access), Some(grant_access)) => FaultClass::Translation {
            access,
            grant_access,
        },
        _ => FaultClass::Other,
    }
}

fn x86_fault_class(fault: carrick_guest_arch::FaultInfo) -> FaultClass {
    use carrick_guest_arch::Access;
    if fault.address.raw() >= (1 << 47) {
        return FaultClass::Other;
    }
    match (fault.present, fault.access) {
        (true, Access::Write) => FaultClass::WritePermission,
        (true, Access::Read) => FaultClass::Protection(LeafAccess::Read),
        (true, Access::Execute) => FaultClass::Protection(LeafAccess::Execute),
        (false, Access::Read) => FaultClass::Translation {
            access: LeafAccess::Read,
            grant_access: 1,
        },
        (false, Access::Write) => FaultClass::Translation {
            access: LeafAccess::Write,
            grant_access: 2,
        },
        (false, Access::Execute) => FaultClass::Translation {
            access: LeafAccess::Execute,
            grant_access: 4,
        },
    }
}

/// Decode an EL0 write permission fault that can be satisfied by in-guest COW resolution.
pub fn is_write_permission_fault(esr: u64) -> bool {
    let ec = (esr >> 26) & 0x3f;
    let dfsc = esr & 0x3f;
    let is_write = (esr & (1 << 6)) != 0;
    matches!(ec, 0x24 | 0x25) && is_write && matches!(dfsc, 0x0c..=0x0f)
}

pub use carrick_core::mm::transfer::resolver::{
    CowResolution, CowResolver, NoopCowResolver, NoopPreparedResolver, PreparedPageResolver,
};

/// The hardware fault path and VM-free arena witnesses share this settlement.
/// A failed rollback is fatal: the caller cannot resume or forward a fault with
/// indeterminate live translations.
#[cfg(any(target_os = "none", test, feature = "host-test"))]
pub fn handle_cow_outcome(
    outcome: Result<crate::cow::GuestCowOutcome, crate::cow::CowError>,
    completion: &mut Option<carrick_el1_abi::CowGrantCompletion>,
) -> CowResolution {
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(crate::cow::CowError::Indeterminate) => {
            panic!("EL1 COW translation state indeterminate: failed rollback or alias restore")
        }
        Err(crate::cow::CowError::Corrupt) => {
            panic!("EL1 COW descriptor state corrupt")
        }
        Err(crate::cow::CowError::Internal) => {
            panic!("EL1 COW internal invariant violation")
        }
        Err(crate::cow::CowError::Refused) => return CowResolution::Refused,
    };
    *completion = match outcome {
        crate::cow::GuestCowOutcome::Resolved(completion) => Some(completion),
        _ => None,
    };
    match outcome {
        crate::cow::GuestCowOutcome::Declined(carrick_el1_abi::CowDecline::PoolEmpty) => {
            CowResolution::NeedsSupply
        }
        crate::cow::GuestCowOutcome::Declined(_) => CowResolution::Refused,
        _ => CowResolution::Resolved,
    }
}

pub struct PreparedFaultPath<
    'a, P: PreparedPageResolver,
    G: carrick_core::mm::reservation::ReservationGeometry = crate::memory::reservations::NativeReservationGeometry,
> {
    pub residency: &'a carrick_el1_abi::FrameGrantResidencyTable,
    pub resolver: &'a mut P,
    /// The shared reservation roots. A delegated MM's prepared backing may
    /// include first-touch stock over root holes: it is committed only where
    /// the root holds a node that permits the access.
    pub roots: Option<&'a carrick_core::mm::reservation::SharedReservations<carrick_personality_linux::mm::LinuxReservationPolicy, G>>,
    pub file_slots: Option<&'a carrick_el1_abi::MmPortalSlots>,
}

#[cfg(target_os = "none")]
pub struct HardwarePreparedResolver;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub(crate) fn hardware_live_ttbr() -> u64 {
    crate::isa::aarch64::hardware_live_ttbr()
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn hardware_target_table_window(
    target: u64,
) -> Option<carrick_mmu_core::aarch64::descriptor_txn::TableWindow> {
    carrick_el1_abi::service_target_table_window(hardware_live_ttbr(), target)
}

/// Only the executing slot uses its pair, so local ASID-0 invalidation is
/// sufficient and never flushes another executor's maintenance translations.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
struct ServiceCopyMaintenance;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl carrick_mmu_core::aarch64::descriptor_txn::TableMaintenance for ServiceCopyMaintenance {
    fn publish_barrier(&self) {
        unsafe {
            core::arch::asm!("dsb ishst", options(nostack));
        }
    }
    fn invalidate_range(&self, va: u64, len: u64) {
        unsafe {
            core::arch::asm!("dsb ishst", options(nostack));
            for page in (va..va + len).step_by(4096) {
                core::arch::asm!("tlbi vae1, {}", in(reg) page >> 12, options(nostack));
            }
            core::arch::asm!("dsb ish", "isb", options(nostack));
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl PreparedPageResolver for HardwarePreparedResolver {
    fn select_backing_window(
        &mut self,
        root: u64,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<
        carrick_el1_abi::PortalGrantWindow,
        carrick_mmu_core::descriptor_refusal::DescriptorRefusal,
    > {
        use carrick_mmu_core::aarch64::descriptor_txn::{DescriptorRefusal, PrimaryTableWords};
        let table = hardware_target_table_window(root).ok_or(DescriptorRefusal::BadRange)?;
        // SAFETY: the shared fault owner retains the target MM editor; the
        // current primary alias and admitted pool remain mapped throughout.
        let words = unsafe {
            PrimaryTableWords::new(
                table.words,
                table.physical_base,
                carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
                &ServiceCopyMaintenance,
            )
            .and_then(|words| words.with_window(carrick_el1_abi::stage1_table_pool_window()))
        }?;
        carrick_core::mm::frames::select_backing_window::<carrick_mmu_core::owner_mmu::Aarch64Mmu, _>(
            &words, root, window,
        )
    }
    fn commit_prepared(
        &mut self,
        ttbr0: u64,
        va: u64,
        expected_ipa: u64,
        access: LeafAccess,
    ) -> Result<GuestPreparedCommit, GuestPreparedCommitError> {
        let table =
            hardware_target_table_window(ttbr0).ok_or(GuestPreparedCommitError::NotPrepared)?;
        let outcome = unsafe {
            carrick_mmu_core::aarch64::commit_existing_el1_prepared_page(
                table.words,
                ttbr0 & TTBR_BADDR_MASK,
                carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
                Some(carrick_el1_abi::stage1_table_pool_window()),
                va,
                expected_ipa,
                access,
            )?
        };
        let mut cpu = crate::substrate::sched::HardwareCpu;
        crate::substrate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
        Ok(outcome)
    }
}

/// Invalidate this CPL0 CPU's TLB entry for the page holding `va` in the
/// live root.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[inline(always)]
pub fn invalidate_local_page(va: u64) {
    // SAFETY: INVLPG is local to this CPL0 CPU and the live root.
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) va & !4095,
            options(nostack, preserves_flags)
        )
    }
}

/// CPL0 publication of a host-backed prepared leaf while the shared fault
/// dispatcher holds this MM's exact guest editor.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub struct X86PreparedResolver<'a, W: carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords> {
    mm_key: NonZeroU64,
    words: &'a W,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static X86_EDIT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<'a, W: carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords> X86PreparedResolver<'a, W> {
    /// # Safety
    /// The shared fault dispatcher must retain this MM's exact editor across
    /// each operation. words retains the owner-admitted table window and
    /// performs checked invalidation for its actual live address context.
    pub unsafe fn under_editor(mm_key: NonZeroU64, words: &'a W) -> Self {
        Self { mm_key, words }
    }

    fn admitted_root(
        &self,
        root_pa: u64,
    ) -> Result<carrick_guest_arch::RootGpa, GuestPreparedCommitError> {
        let root =
            carrick_guest_arch::RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(root_pa))
                .ok_or(GuestPreparedCommitError::BadAddress)?;
        if crate::isa::x86::hardware_live_root() != Ok(root) {
            return Err(GuestPreparedCommitError::BadAddress);
        }
        Ok(root)
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<W: carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords> PreparedPageResolver
    for X86PreparedResolver<'_, W>
{
    fn select_backing_window(
        &mut self,
        root: u64,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<
        carrick_el1_abi::PortalGrantWindow,
        carrick_mmu_core::descriptor_refusal::DescriptorRefusal,
    > {
        use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
        self.admitted_root(root)
            .map_err(|_| DescriptorRefusal::StaleRoot)?;
        carrick_core::mm::frames::select_backing_window::<carrick_mmu_core::x86::owner_mmu::X86Mmu, _>(
            self.words, root, window,
        )
    }
    fn commit_prepared(
        &mut self,
        root_pa: u64,
        va: u64,
        expected_pa: u64,
        access: LeafAccess,
    ) -> Result<GuestPreparedCommit, GuestPreparedCommitError> {
        use carrick_guest_arch::{
            EditIntent, EditOperation, EditOwner, FrameGpa, GuestLen, UserRange, UserVa,
        };
        use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
        use carrick_mmu_core::x86::descriptor_txn::{
            Access, DescriptorOutcome, DescriptorTxn, InlineJournal, execute_descriptor_txn,
            translate_leaf,
        };
        let root = self.admitted_root(root_pa)?;
        let range = UserRange::checked(UserVa::new(va), GuestLen::new(4096))
            .ok_or(GuestPreparedCommitError::BadAddress)?;
        let expected = FrameGpa::new(expected_pa);
        let (fault_access, native_access) = match access {
            LeafAccess::Read => (carrick_guest_arch::Access::Read, Access::Read),
            LeafAccess::Write => (carrick_guest_arch::Access::Write, Access::Write),
            LeafAccess::Execute => (carrick_guest_arch::Access::Execute, Access::Execute),
        };
        let sequence = X86_EDIT_SEQUENCE
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or(GuestPreparedCommitError::BadAddress)?;
        // SAFETY: constructor and shared dispatch retain the exact editor;
        // live_root above authenticates the executing hardware context.
        let owner = unsafe { EditOwner::issue(root, self.mm_key, sequence) };
        let intent = EditIntent::checked(
            owner,
            range,
            EditOperation::Publish {
                expected,
                access: fault_access,
            },
            &[],
        )
        .ok_or(GuestPreparedCommitError::BadAddress)?;
        let txn = DescriptorTxn::from_intent(&intent)
            .map_err(|_| GuestPreparedCommitError::BadAddress)?;
        let receipt = execute_descriptor_txn(self.words, &txn, root, &mut InlineJournal::new());
        match receipt.outcome {
            DescriptorOutcome::Applied { .. } => Ok(GuestPreparedCommit::Committed),
            DescriptorOutcome::Refused(DescriptorRefusal::NotPrepared) => {
                if translate_leaf(self.words, root, UserVa::new(va), native_access, true)
                    .is_ok_and(|leaf| leaf.output == expected)
                {
                    Ok(GuestPreparedCommit::AlreadyResident)
                } else {
                    Err(GuestPreparedCommitError::NotPrepared)
                }
            }
            DescriptorOutcome::Refused(DescriptorRefusal::WrongBacking) => {
                Err(GuestPreparedCommitError::WrongBacking)
            }
            DescriptorOutcome::Refused(DescriptorRefusal::PermissionDenied) => {
                Err(GuestPreparedCommitError::PermissionDenied)
            }
            DescriptorOutcome::Refused(DescriptorRefusal::MissingTable) => {
                Err(GuestPreparedCommitError::MissingTable)
            }
            DescriptorOutcome::Refused(DescriptorRefusal::TableOutsidePrimary) => {
                Err(GuestPreparedCommitError::TableOutsidePrimary)
            }
            DescriptorOutcome::Indeterminate(_) => Err(GuestPreparedCommitError::RollbackFailed),
            _ => Err(GuestPreparedCommitError::NotPrepared),
        }
    }
}

/// Read the COW caller's exact root incarnation from its retained record.
/// A reused root GPA does not authorize an older or newer incarnation.
///
/// # Safety
/// The caller owns this stopped slot and its record for the entire snapshot.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub unsafe fn cow_address_for_record(
    zone: &carrick_sched_core::ZoneTables<carrick_sched_core::Aarch64ParkedContext>,
    task: &CurrentTask,
    slot: carrick_sched_core::SlotId,
    target: carrick_guest_arch::AddressContext<carrick_guest_arch::RootGpa>,
) -> Option<(
    carrick_el1_abi::ExecutionBinding,
    carrick_guest_arch::AddressContext<carrick_guest_arch::RootGpa>,
)> {
    let binding = carrick_core::entry::binding(&task.execution, &task.mm);
    let lane = zone.slot(slot);
    let record = zone.record(lane.current().or_else(|| lane.host_record())?);
    let identity = record.identity();
    // SAFETY: the caller retains exclusive custody of this stopped record.
    let source = unsafe { record.ctx_mut() }.address_context()?;
    (binding.issued()
        && identity.tid == binding.task.raw()
        && identity.generation == binding.generation.raw()
        && identity.serial == binding.thread_generation.raw()
        && identity.mm == binding.mm.raw()
        && lane.mm() == binding.mm.raw()
        && source.mm.raw().get() == binding.mm.raw()
        && source == target)
        .then_some((binding, source))
}

/// EL1 execution of host-submitted live descriptor transactions.
pub trait DescriptorTxnApplier {
    /// Claim and execute the submission in `slot` for `mm_key` against the
    /// live graph rooted at `ttbr0`'s table base, invalidating `ttbr0`'s ASID
    /// when the outcome stored anything, before the receipt is published
    /// (`ClaimedDescriptorTxn::complete`). The caller holds the exact editor.
    fn apply(
        &mut self,
        slot: &DescriptorTxnSlot,
        mm_key: u64,
        ttbr0: u64,
    ) -> Option<DescriptorReceipt>;
}

/// The descriptor-transaction slots EL1 serves, plus the executor.
pub struct DescriptorTxnPath<'a, X: DescriptorTxnApplier> {
    pub slots: &'a carrick_el1_abi::DescriptorTxnSlots,
    pub applier: &'a mut X,
}

#[cfg(target_os = "none")]
const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub(crate) use crate::isa::arm_edit::El1TableMaintenance;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) struct El1TableMaintenance {
    pub(crate) ttbr0: u64,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl carrick_mmu_core::aarch64::descriptor_txn::TableMaintenance for El1TableMaintenance {
    fn publish_barrier(&self) {
        let mut cpu = crate::substrate::sched::HardwareCpu;
        crate::substrate::sched::ThreadCpu::invalidate_asid(&mut cpu, self.ttbr0);
    }

    fn invalidate_range(&self, _va: u64, _len: u64) {
        let mut cpu = crate::substrate::sched::HardwareCpu;
        crate::substrate::sched::ThreadCpu::invalidate_asid(&mut cpu, self.ttbr0);
    }
}

#[cfg(target_os = "none")]
pub struct HardwareDescriptorTxnApplier;

#[cfg(target_os = "none")]
impl DescriptorTxnApplier for HardwareDescriptorTxnApplier {
    fn apply(
        &mut self,
        slot: &DescriptorTxnSlot,
        mm_key: u64,
        ttbr0: u64,
    ) -> Option<DescriptorReceipt> {
        use carrick_mmu_core::aarch64::descriptor_txn::{
            DescriptorOp, InlineJournal, PrimaryTableWords, execute_descriptor_txn,
            plan_descriptor_op,
        };
        let maintenance = El1TableMaintenance { ttbr0 };
        let words = unsafe {
            PrimaryTableWords::new(
                carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE as *mut AtomicU64,
                ttbr0 & TTBR_BADDR_MASK,
                carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
                &maintenance,
            )
            .and_then(|words| words.with_window(carrick_el1_abi::stage1_table_pool_window()))
        }
        .ok()?;
        let mut journal = InlineJournal::new();
        let root = carrick_mmu_core::aarch64::SubstrateGpa(ttbr0 & TTBR_BADDR_MASK);
        let claimed = slot.claim_for_mm(mm_key)?;
        let outcome = match claimed.txn() {
            Err(refusal) => DescriptorOutcome::Refused(refusal),
            Ok(txn) if txn.root != root => DescriptorOutcome::Refused(
                carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal::StaleRoot,
            ),
            Ok(txn) => {
                // COW's bytes and live repoint are one guest operation under
                // the caller's exact-MM editor. Host custody retains both
                // backing owners until this transaction's receipt settles.
                let copied = if let DescriptorOp::CowRepoint {
                    old_ipa,
                    new_ipa,
                    len,
                    ..
                } = txn.op
                {
                    plan_descriptor_op(&words, root, txn.op)
                        .map_err(DescriptorOutcome::Refused)
                        .and_then(|_| {
                            use carrick_mmu_core::aarch64::SubstrateGpa;
                            use carrick_mmu_core::aarch64::descriptor_txn::copy_window::with_cow_copy_aliases;
                            for offset in (0..len).step_by(4096) {
                                with_cow_copy_aliases(
                                    &words,
                                    root,
                                    carrick_el1_abi::EL1_COW_COPY_BASE,
                                    SubstrateGpa(old_ipa.raw() + offset),
                                    SubstrateGpa(new_ipa.raw() + offset),
                                    |source, destination| {
                                        // SAFETY: aliases expose pinned, distinct
                                        // pages: source RO, destination RW, both
                                        // kernel-only; revoked before returning.
                                        unsafe {
                                            core::ptr::copy_nonoverlapping(
                                                source as *const u8,
                                                destination as *mut u8,
                                                4096,
                                            );
                                        }
                                    },
                                )?;
                            }
                            Ok(())
                        })
                } else {
                    Ok(())
                };
                match copied {
                    Ok(()) => execute_descriptor_txn(&words, root, txn, &mut journal).outcome,
                    Err(outcome) => outcome,
                }
            }
        };
        let receipt = claimed.complete(outcome, || {
            let mut cpu = crate::substrate::sched::HardwareCpu;
            crate::substrate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
        });
        if let DescriptorOutcome::Indeterminate(refusal) = receipt.outcome {
            panic!("EL1 descriptor transaction rollback failed: {refusal:?}");
        }
        Some(receipt)
    }
}

/// Execute every host submission for the faulting MM under its exact
/// editor. A fault inside an applied submission's span retries (`Served`):
/// its descriptor now exists or was refused and the retry takes the normal
/// path. `None` leaves the fault to the ordinary dispatch.
pub fn serve_descriptor_txns<X: DescriptorTxnApplier>(
    frame: &TrapFrame,
    current_tasks: &[CurrentTask],
    spaces: SpaceAccess<'_, impl Copy + Send + Sync + zerocopy::FromZeros>,
    path: &mut DescriptorTxnPath<'_, X>,
) -> Option<Action> {
    let mm_key = current_tasks
        .get(frame.slot as usize)?
        .mm
        .key
        .load(Ordering::Acquire);
    if mm_key == 0 || path.slots.submitted_for(mm_key).next().is_none() {
        return None;
    }
    let index = spaces.find(mm_key)?;
    let grant = spaces.grant(index, mm_key)?;
    let owner = NonZeroU64::new(frame.slot + 1)?;
    // A closed gate (host pause or retirement) leaves the submission for the
    // host boundary, which recognizes it as in flight.
    let _editor = spaces.try_begin_edit(index, mm_key, owner)?;
    let mut covered = false;
    for slot in path.slots.submitted_in_order(mm_key) {
        let covers = slot.pending_covering(mm_key, frame.far);
        if let Some(receipt) = path.applier.apply(slot, mm_key, grant.ttbr0) {
            covered |= covers && matches!(receipt.outcome, DescriptorOutcome::Applied(_));
        }
    }
    covered.then_some(Action::Served)
}

/// [`dispatch_fault_with_prepared`] after serving host descriptor
/// transactions for the faulting MM.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_fault_with_descriptor_txns<'supply, P, C, X>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    spaces: SpaceAccess<'_, impl Copy + Send + Sync + zerocopy::FromZeros>,
    mut txns: Option<DescriptorTxnPath<'_, X>>,
    supply: impl Into<FaultSupply<'supply>>,
    prepared: Option<PreparedFaultPath<'_, P>>,
    cow_resolver: &mut C,
) -> Action
where
    P: PreparedPageResolver,
    C: CowResolver,
    X: DescriptorTxnApplier,
{
    if let Some(action) = txns
        .as_mut()
        .and_then(|path| serve_descriptor_txns(frame, current_tasks, spaces, path))
    {
        counters.fault_taken.fetch_add(1, Ordering::Relaxed);
        return action;
    }
    dispatch_fault_with_prepared(
        frame,
        counters,
        current_tasks,
        spaces,
        supply,
        prepared,
        cow_resolver,
    )
}

/// Where EL1 reads the still-shared frame and writes its private
/// replacement for one COW grant (each exactly one page).
pub trait CowCopyWindow {
    fn frames(
        &mut self,
        grant: &carrick_mmu_core::aarch64::descriptor_txn::CowCopyGrant,
    ) -> Option<(&[u8], &mut [u8])>;
}

/// Borrow the existing slot-scoped copy aliases for one bounded owner operation.
/// The closure cannot carry table words or copy aliases across a host supply.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[allow(clippy::result_unit_err)]
pub fn with_hardware_cow_venue<R>(
    ttbr0: u64,
    service_slot: Option<carrick_el1_abi::SlotId>,
    publication: Option<&'static carrick_core_abi::PortalExecutableSlot>,
    run: impl for<'a> FnOnce(
        &crate::cow::GuestCowVenue<
            'a,
            dyn carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + 'a,
        >,
    ) -> R,
) -> Result<R, ()> {
    use carrick_mmu_core::aarch64::descriptor_txn::PrimaryTableWords;
    let Some(table) = hardware_target_table_window(ttbr0) else {
        return Err(());
    };
    let maintenance = El1TableMaintenance { ttbr0 };
    // SAFETY: the alias maps this MM's primary arena, the pool window
    // every other arena, and the caller holds the MM's exact editor.
    let Ok(words) = (unsafe {
        PrimaryTableWords::new(
            table.words,
            table.physical_base,
            carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
            &maintenance,
        )
        .and_then(|words| words.with_window(carrick_el1_abi::stage1_table_pool_window()))
    }) else {
        return Err(());
    };
    let live = hardware_live_ttbr();
    let service_lease = if live == carrick_el1_abi::EL1_CARRIER_MAINT_ROOT_BASE {
        let Some(slot) = service_slot else {
            return Err(());
        };
        // SAFETY: the carrier owns this ABI region for its whole lifetime;
        // only a successful exact-slot claim can touch this pair of leaves.
        let table = unsafe {
            &*(carrick_el1_abi::EL1_SERVICE_COPY_TABLE_BASE
                as *const carrick_el1_abi::ServiceCopyTable)
        };
        let Some(lease) = table.try_claim(slot) else {
            return Err(());
        };
        Some(lease)
    } else {
        None
    };
    let service_maintenance = ServiceCopyMaintenance;
    let service_words = if service_lease.is_some() {
        let words = unsafe {
            PrimaryTableWords::new(
                carrick_el1_abi::EL1_CARRIER_MAINT_ROOT_BASE as *mut AtomicU64,
                carrick_el1_abi::EL1_CARRIER_MAINT_ROOT_BASE,
                carrick_el1_abi::EL1_CARRIER_MAINT_ROOT_SIZE as usize,
                &service_maintenance,
            )
            .and_then(|words| {
                words.with_window(carrick_mmu_core::aarch64::descriptor_txn::TableWindow {
                    words: carrick_el1_abi::EL1_SERVICE_COPY_TABLE_BASE as *mut AtomicU64,
                    physical_base: carrick_el1_abi::EL1_SERVICE_COPY_TABLE_BASE,
                    byte_len: 4096,
                })
            })
        };
        let Ok(words) = words else {
            return Err(());
        };
        Some(words)
    } else {
        None
    };
    let copy_window = match (&service_lease, &service_words) {
        (Some(lease), Some(copy_words)) => {
            let Some(window) = crate::cow::CowCopyWindow::maintenance(copy_words, live, lease)
            else {
                return Err(());
            };
            window
        }
        (None, None) => crate::cow::CowCopyWindow::target(
            &words,
            carrick_mmu_core::aarch64::SubstrateGpa(ttbr0 & TTBR_BADDR_MASK),
        ),
        _ => unreachable!(),
    };
    let publish = |grant, ipa, len| {
        publication.is_some_and(|slot| {
            slot.publish_with(
                carrick_core_abi::PortalExecutablePublication { grant, ipa, len },
                || {
                    #[cfg(target_arch = "aarch64")]
                    unsafe {
                        core::arch::asm!("hvc #1", options(nostack));
                    }
                    #[cfg(target_arch = "x86_64")]
                    crate::isa::x86::yield_host_effect();
                },
            )
        })
    };
    Ok(run(&crate::cow::GuestCowVenue {
        publish_executable: publication.map(|_| &publish as &dyn Fn(_, _, _) -> bool),
        words: &words,
        root: carrick_mmu_core::aarch64::SubstrateGpa(ttbr0 & TTBR_BADDR_MASK),
        pool: carrick_el1_abi::cow_grant_pool_guest(),
        residency: crate::isa::frame_grant_residency_guest(),
        copy_window,
    }))
}
/// Guest COW copy: claim the grant MM's exact editor, check that the live
/// leaf still maps the shared frame COW-armed, copy it into the granted
/// replacement, and return the proof that authorizes exactly one repoint.
/// A closed gate or another editor refuses (`Contended`); nothing is copied.
pub fn copy_granted_cow_page<W, C>(
    words: &W,
    grant: carrick_mmu_core::aarch64::descriptor_txn::CowCopyGrant,
    spaces: SpaceAccess<'_, impl Copy + Send + Sync + zerocopy::FromZeros>,
    owner: NonZeroU64,
    window: &mut C,
) -> Result<
    carrick_mmu_core::aarch64::descriptor_txn::CowCopyComplete,
    carrick_mmu_core::aarch64::descriptor_txn::CowCopyError,
>
where
    W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    C: CowCopyWindow,
{
    use carrick_mmu_core::aarch64::descriptor_txn::{CowCopyError, DescriptorRefusal};
    let mm_key = grant.mm_key.get();
    let index = spaces
        .find(mm_key)
        .ok_or(CowCopyError::Refused(DescriptorRefusal::WrongMm))?;
    let space = spaces
        .grant(index, mm_key)
        .ok_or(CowCopyError::Refused(DescriptorRefusal::Contended))?;
    if space.ttbr0 & 0x0000_FFFF_FFFF_F000 != grant.root.raw() {
        return Err(CowCopyError::Refused(DescriptorRefusal::StaleRoot));
    }
    let _editor = spaces
        .try_begin_edit(index, mm_key, owner)
        .ok_or(CowCopyError::Refused(DescriptorRefusal::Contended))?;
    let (source, destination) = window.frames(&grant).ok_or(CowCopyError::BadWindow)?;
    carrick_mmu_core::aarch64::descriptor_txn::copy_granted_cow_page(
        words,
        grant,
        source,
        destination,
    )
}

/// Result of draining one MM's host descriptor submissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainOutcome {
    /// Nothing was submitted for the MM.
    Clean,
    /// This many submissions were applied (each answered with a receipt).
    Drained(u32),
    /// Submissions remain and this vCPU may not edit the MM now: the MM is
    /// unpublished, or a host pause closed its gate without delegating.
    Blocked,
}

/// Apply every submission for `mm_key` on the live graph `ttbr0` names.
///
/// With the MM's gate open, the exact editor is claimed first, waiting out
/// another EL1 editor (a bounded critical section: EL1 editors never block
/// on anything). `host_custody` is set only by the host-driven drain call:
/// the host holds this MM's pause, has excluded every EL1 editor, and
/// delegates the edit to this vCPU, so a closed gate is its custody rather
/// than a refusal.
///
/// Nothing is reported drained while any of the MM's submissions is still
/// submitted or being applied by another editor: its receipt, and the ASID
/// invalidation that precedes it, are still to come, and a caller that
/// settled or resumed EL0 on the report would run against stale
/// translations.
pub fn drain_mm_descriptor_txns<X: DescriptorTxnApplier>(
    spaces: SpaceAccess<'_, impl Copy + Send + Sync + zerocopy::FromZeros>,
    slots: &carrick_el1_abi::DescriptorTxnSlots,
    mm_key: u64,
    ttbr0: u64,
    owner: NonZeroU64,
    applier: &mut X,
    host_custody: bool,
) -> DrainOutcome {
    if mm_key == 0 || !slots.in_flight_for(mm_key) {
        return DrainOutcome::Clean;
    }
    loop {
        if let Some(outcome) =
            try_drain_mm_descriptor_txns(spaces, slots, mm_key, ttbr0, owner, applier, host_custody)
        {
            return outcome;
        }
        core::hint::spin_loop();
    }
}

/// One attempt of [`drain_mm_descriptor_txns`]. `None`: another EL1 editor
/// holds the MM while some of its submissions are still in flight; retry.
fn try_drain_mm_descriptor_txns<X: DescriptorTxnApplier>(
    spaces: SpaceAccess<'_, impl Copy + Send + Sync + zerocopy::FromZeros>,
    slots: &carrick_el1_abi::DescriptorTxnSlots,
    mm_key: u64,
    ttbr0: u64,
    owner: NonZeroU64,
    applier: &mut X,
    host_custody: bool,
) -> Option<DrainOutcome> {
    let Some(index) = spaces.find(mm_key) else {
        return Some(DrainOutcome::Blocked);
    };
    let apply_all = |applier: &mut X| {
        let mut applied = 0;
        for slot in slots.submitted_in_order(mm_key) {
            if applier.apply(slot, mm_key, ttbr0).is_some() {
                applied += 1;
            }
        }
        DrainOutcome::Drained(applied)
    };
    if spaces.grant(index, mm_key).is_none() {
        return Some(if host_custody {
            apply_all(applier)
        } else {
            DrainOutcome::Blocked
        });
    }
    if let Some(_editor) = spaces.try_begin_edit(index, mm_key, owner) {
        return Some(apply_all(applier));
    }
    // Another editor applied them and published every receipt, each after
    // its invalidation.
    (!slots.in_flight_for(mm_key)).then_some(DrainOutcome::Drained(0))
}

fn is_syscall(frame: &TrapFrame) -> bool {
    (frame.esr >> 26) & 0x3f == 0x15
}

/// The last EL1 step before a thread of an MM returns to EL0 (a served
/// syscall, fault or interrupt, including a thread the scheduler switched
/// in, whose record the slot's task now names), and before a kicked
/// interrupt leaves for the host: apply that MM's pending descriptor
/// submissions, so no instruction of the MM runs against a descriptor edit
/// the host already committed to (a fork-COW arm above all). When they
/// cannot be applied here, the thread leaves through the host instead:
/// a served syscall keeps its result (`ServedWithWork`), anything else
/// forwards.
pub fn drain_before_el0<X: DescriptorTxnApplier>(
    frame: &TrapFrame,
    action: Action,
    current_tasks: &[CurrentTask],
    spaces: SpaceAccess<'_, impl Copy + Send + Sync + zerocopy::FromZeros>,
    slots: &carrick_el1_abi::DescriptorTxnSlots,
    applier: &mut X,
) -> Action {
    let to_el0 = matches!(action, Action::Served | Action::ServedWithWork);
    let kicked = action == Action::Forward && frame.esr == 0;
    if !(to_el0 || kicked) {
        return action;
    }
    let Some(task) = current_tasks.get(frame.slot as usize) else {
        return action;
    };
    let mm_key = task.mm.key.load(Ordering::Acquire);
    if mm_key == 0 || !slots.in_flight_for(mm_key) {
        return action;
    }
    let (Some(owner), Some(index)) = (NonZeroU64::new(frame.slot + 1), spaces.find(mm_key)) else {
        return action;
    };
    let outcome = match spaces.grant(index, mm_key) {
        Some(grant) => {
            drain_mm_descriptor_txns(spaces, slots, mm_key, grant.ttbr0, owner, applier, false)
        }
        None => DrainOutcome::Blocked,
    };
    match (outcome, action) {
        (DrainOutcome::Blocked, Action::Served | Action::ServedWithWork) if is_syscall(frame) => {
            task.linux.record_completed_with_work();
            Action::ServedWithWork
        }
        (DrainOutcome::Blocked, Action::Served) => Action::Forward,
        _ => action,
    }
}

/// EL1 side of the host-driven drain call ([`carrick_el1_abi::DESCRIPTOR_DRAIN_ESR`]).
/// Answers in `frame.x[0]`: applied count, plus the blocked bit.
pub fn serve_host_drain<X: DescriptorTxnApplier>(
    frame: &mut TrapFrame,
    spaces: SpaceAccess<'_, impl Copy + Send + Sync + zerocopy::FromZeros>,
    slots: &carrick_el1_abi::DescriptorTxnSlots,
    applier: &mut X,
) {
    let mm_key = frame.x[carrick_el1_abi::DESCRIPTOR_DRAIN_MM];
    let ttbr0 = frame.x[carrick_el1_abi::DESCRIPTOR_DRAIN_TTBR0];
    let Some(owner) = NonZeroU64::new(frame.slot + 1) else {
        frame.x[0] = carrick_el1_abi::DESCRIPTOR_DRAIN_BLOCKED;
        return;
    };
    frame.x[0] = match drain_mm_descriptor_txns(spaces, slots, mm_key, ttbr0, owner, applier, true)
    {
        DrainOutcome::Clean => 0,
        DrainOutcome::Drained(applied) => u64::from(applied),
        DrainOutcome::Blocked => carrick_el1_abi::DESCRIPTOR_DRAIN_BLOCKED,
    };
}

/// Hardware entry of [`drain_before_el0`] (`carrick_el1_syscall`).
#[cfg(target_os = "none")]
pub fn drain_before_el0_hw(frame: &TrapFrame, action: Action) -> Action {
    let current_tasks = unsafe {
        &*(carrick_el1_abi::EL1_CURRENT_TASKS_BASE
            as *const [CurrentTask; carrick_el1_abi::EL1_STACK_SLOTS as usize])
    };
    let zone = unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
    drain_before_el0(
        frame,
        action,
        current_tasks,
        crate::substrate::sched::object_wait::space_access(
            zone,
            carrick_sched_core::SlotId::new(frame.slot as u8),
        ),
        carrick_el1_abi::descriptor_txn_slots_guest(),
        &mut HardwareDescriptorTxnApplier,
    )
}

/// Hardware entry of [`serve_host_drain`] (`carrick_el1_syscall`).
#[cfg(target_os = "none")]
pub fn serve_host_drain_hw(frame: &mut TrapFrame) {
    let zone = unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
    serve_host_drain(
        frame,
        crate::substrate::sched::object_wait::space_access(
            zone,
            carrick_sched_core::SlotId::new(frame.slot as u8),
        ),
        carrick_el1_abi::descriptor_txn_slots_guest(),
        &mut HardwareDescriptorTxnApplier,
    );
}

/// The faulting vCPU's frame-grant mailbox, plus every vCPU's mailbox so a
/// retry migrated by the EL1 scheduler can consume a refusal left elsewhere.
/// Successful grants leave no guest-owned response.
#[derive(Clone, Copy)]
pub struct GrantMailboxes<'a> {
    pub own: &'a FrameGrantMailbox,
    pub peers: Option<&'a FrameGrantMailboxes>,
}

impl<'a> GrantMailboxes<'a> {
    pub fn own(own: &'a FrameGrantMailbox) -> Self {
        Self { own, peers: None }
    }
}

/// A CPL0 fault can request physical supply without delegating leaf publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerFaultSupplyOutcome {
    Wait(carrick_el1_abi::PortalOwnerWait),
    Unavailable,
    PolicyDeclined,
    Selected,
    CowSelected,
}

pub struct OwnerFaultSupply<'a> {
    handle: Option<carrick_el1_abi::El1MmHandle>,
    pub slots: &'a carrick_el1_abi::MmPortalSlots,
    outcome: core::cell::Cell<OwnerFaultSupplyOutcome>,
}
impl<'a> OwnerFaultSupply<'a> {
    pub fn new(slots: &'a carrick_el1_abi::MmPortalSlots) -> Self {
        Self {
            handle: None,
            slots,
            outcome: core::cell::Cell::new(OwnerFaultSupplyOutcome::Unavailable),
        }
    }
    pub fn with_handle(mut self, handle: carrick_el1_abi::El1MmHandle) -> Self {
        self.handle = Some(handle);
        self
    }
    pub fn outcome(&self) -> OwnerFaultSupplyOutcome {
        self.outcome.get()
    }
}
#[derive(Clone, Copy)]
pub enum FaultSupply<'a> {
    Mailbox(GrantMailboxes<'a>),
    Owner(&'a OwnerFaultSupply<'a>),
}
impl<'a> From<GrantMailboxes<'a>> for FaultSupply<'a> {
    fn from(mailboxes: GrantMailboxes<'a>) -> Self {
        Self::Mailbox(mailboxes)
    }
}
impl FaultSupply<'_> {
    fn observe<C: Copy + Send + Sync + zerocopy::FromZeros>(
        self,
        spaces: SpaceAccess<'_, C>,
        mm: u64,
        cause: carrick_sched_core::spaces::notification::SpaceWaitCause,
    ) -> Option<carrick_el1_abi::PortalOwnerWait> {
        use carrick_sched_core::spaces::notification::SpaceWaitCause;
        let Self::Owner(owner) = self else {
            return None;
        };
        let handle = owner.handle.filter(|handle| handle.mm().raw() == mm)?;
        let source = spaces
            .venue()?
            .zone
            .space_entry(NonZeroU64::new(mm)?)?
            .notifications(handle.incarnation())
            .ok()?;
        let revision = source.observe(cause).revision();
        let cause = match cause {
            SpaceWaitCause::Reservations => carrick_el1_abi::PortalWaitCause::Reservations,
            SpaceWaitCause::Editor => carrick_el1_abi::PortalWaitCause::Editor,
            SpaceWaitCause::Gate => carrick_el1_abi::PortalWaitCause::Gate,
            _ => return None,
        };
        // SAFETY: exact birth MM source authenticated and sampled before probe.
        Some(unsafe { carrick_el1_abi::PortalOwnerWait::from_owner(handle, cause, revision) })
    }
    fn wait(self, wait: Option<carrick_el1_abi::PortalOwnerWait>) {
        if let (Self::Owner(owner), Some(wait)) = (self, wait) {
            owner.outcome.set(OwnerFaultSupplyOutcome::Wait(wait));
        }
    }
    fn editor<'a, C: Copy + Send + Sync + zerocopy::FromZeros>(
        self,
        spaces: SpaceAccess<'a, C>,
        index: carrick_sched_core::SpaceIndex,
        mm: u64,
        owner: NonZeroU64,
    ) -> Option<carrick_sched_core::spaces::SpaceEditor<'a, C>> {
        use carrick_sched_core::spaces::{EditAdmissionRefusal, notification::SpaceWaitCause};
        if matches!(self, Self::Mailbox(_)) {
            return spaces.try_begin_edit_bounded(
                index,
                mm,
                owner,
                carrick_el1_abi::EL1_GUEST_LOCK_SPINS,
            );
        }
        let editor = self.observe(spaces, mm, SpaceWaitCause::Editor);
        let gate = self.observe(spaces, mm, SpaceWaitCause::Gate);
        match spaces
            .table()
            .try_begin_edit_cause(index, mm, owner, spaces.venue())
        {
            Ok(editor) => Some(editor),
            Err(EditAdmissionRefusal::Editor) => {
                self.wait(editor);
                None
            }
            Err(EditAdmissionRefusal::Gate) => {
                self.wait(gate);
                None
            }
            Err(EditAdmissionRefusal::Stale) => None,
        }
    }

    fn decline(self) {
        if let Self::Owner(owner) = self {
            owner.outcome.set(OwnerFaultSupplyOutcome::PolicyDeclined);
        }
    }
}

/// Fault dispatch with explicitly supplied shared regions and COW resolver.
/// A refusal is consumed and forwarded once through the host fault path.
/// Successful publication and first-touch commit both happen on the host.
pub fn dispatch_fault_with_regions<C: CowResolver>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    spaces: SpaceAccess<'_, impl Copy + Send + Sync + zerocopy::FromZeros>,
    mailboxes: GrantMailboxes<'_>,
    cow_resolver: &mut C,
) -> Action {
    dispatch_fault_with_prepared(
        frame,
        counters,
        current_tasks,
        spaces,
        mailboxes,
        None::<PreparedFaultPath<'_, NoopPreparedResolver>>,
        cow_resolver,
    )
}

/// Release one observed refusal. A racing consumer may have released it
/// first; either way it no longer occupies the mailbox for this fault.
fn release_refusal(source: &FrameGrantMailbox, mm_key: u64, request_generation: u64) {
    if source.claim_response(mm_key, request_generation).is_some() {
        assert!(source.finish_response(mm_key, request_generation));
    }
}

/// Consume the refusal answering this fault, left on the faulting vCPU's
/// mailbox or, after an EL1 scheduler migration, on a peer's. `true` only
/// when it still answers the current mapping; an older node's refusal is
/// retired and the replacement may issue its own request.
fn consume_refusal(
    mailboxes: GrantMailboxes<'_>,
    mm_key: u64,
    far: u64,
    access: u64,
    current_incarnation: impl FnOnce() -> Option<ReservationIncarnation>,
) -> bool {
    let found = mailboxes
        .own
        .response_for_fault(mm_key, far, access)
        .map(|response| (mailboxes.own, response))
        .or_else(|| {
            mailboxes.peers?.iter().find_map(|peer| {
                peer.response_covering_fault(mm_key, far, access)
                    .map(|response| (peer, response))
            })
        });
    let Some((source, response)) = found else {
        return false;
    };
    let current = current_incarnation() == Some(response.request.reservation_incarnation);
    release_refusal(source, mm_key, response.request.request_generation);
    current
}

/// A fault the residency table served may still have a refusal outstanding
/// for its page: its request raced the host settling the grant that now
/// covers it, and the host refused the no-longer-pristine span. The retry
/// never reaches the refusal path, so every refusal covering the page is
/// consumed here; the page is resident, so none of them still answers a
/// fault. Left in RESPONSE, a mailbox could never carry another request, and
/// every later first touch on that vCPU slot, in any MM, would fall back to
/// page-granular host service.
fn consume_served_refusals(mailboxes: GrantMailboxes<'_>, mm_key: u64, far: u64, access: u64) {
    let release = |source: &FrameGrantMailbox| {
        if let Some(response) = source.response_covering_fault(mm_key, far, access) {
            release_refusal(source, mm_key, response.request.request_generation);
        }
    };
    release(mailboxes.own);
    if let Some(peers) = mailboxes.peers {
        peers.iter().for_each(release);
    }
}

pub fn dispatch_fault_with_prepared<'supply, P: PreparedPageResolver, C: CowResolver>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    spaces: SpaceAccess<'_, impl Copy + Send + Sync + zerocopy::FromZeros>,
    supply: impl Into<FaultSupply<'supply>>,
    prepared: Option<PreparedFaultPath<'_, P>>,
    cow_resolver: &mut C,
) -> Action {
    dispatch_classified_fault(
        frame.slot,
        frame.far,
        arm_fault_class(frame.esr),
        counters,
        current_tasks.get(frame.slot as usize),
        spaces,
        supply.into(),
        prepared,
        cow_resolver,
    )
}

/// Execute the same guest fault policy for a decoded CPL3 x86 page fault.
/// The entry backend must have checked the fault's user origin before calling.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_x86_fault_with_prepared<
    'supply,
    P: PreparedPageResolver,
    C: CowResolver,
    G: carrick_core::mm::reservation::ReservationGeometry,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
>(
    slot: carrick_guest_arch::CpuId,
    fault: carrick_guest_arch::FaultInfo,
    counters: &Counters,
    current_task: &CurrentTask,
    spaces: SpaceAccess<'_, Context>,
    supply: impl Into<FaultSupply<'supply>>,
    prepared: Option<PreparedFaultPath<'_, P, G>>,
    cow_resolver: &mut C,
) -> Action {
    dispatch_classified_fault(
        u64::from(slot.raw()),
        fault.address.raw(),
        x86_fault_class(fault),
        counters,
        Some(current_task),
        spaces,
        supply.into(),
        prepared,
        cow_resolver,
    )
}

#[allow(clippy::too_many_arguments)]
fn dispatch_classified_fault<
    P: PreparedPageResolver,
    C: CowResolver,
    G: carrick_core::mm::reservation::ReservationGeometry,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
>(
    slot: u64,
    far: u64,
    fault: FaultClass,
    counters: &Counters,
    current_task: Option<&CurrentTask>,
    spaces: SpaceAccess<'_, Context>,
    supply: FaultSupply<'_>,
    mut prepared: Option<PreparedFaultPath<'_, P, G>>,
    cow_resolver: &mut C,
) -> Action {
    use carrick_core::mm::fault::RootFaultAdmission;
    counters.fault_taken.fetch_add(1, Ordering::Relaxed);
    if fault == FaultClass::WritePermission {
        let Some(task) = current_task else {
            return Action::Forward;
        };
        let mm_key = task.mm.key.load(Ordering::Acquire);
        if mm_key == 0 {
            return Action::Forward;
        }
        let Some(index) = spaces.find(mm_key) else {
            return Action::Forward;
        };
        let Some(owner) = NonZeroU64::new(slot + 1) else {
            return Action::Forward;
        };
        if let FaultSupply::Owner(_) = supply {
            let observed = supply.observe(
                spaces,
                mm_key,
                carrick_sched_core::spaces::notification::SpaceWaitCause::Reservations,
            );
            match root_fault_admission(
                prepared.as_ref().and_then(|path| path.roots),
                spaces,
                slot as u32,
                mm_key,
                far & !4095,
                LeafAccess::Write,
            ) {
                RootFaultAdmission::Allowed => {}
                RootFaultAdmission::Busy => {
                    supply.wait(observed);
                    return Action::Forward;
                }
                RootFaultAdmission::Declined => {
                    supply.decline();
                    return Action::Forward;
                }
                _ => return Action::Forward,
            }
        }
        // A closed gate (host pause or retirement) or another EL1 editor:
        // the host resolves this fault.
        // Sibling threads fault on the same forked MM together; each COW
        // holds the editor only for one compound copy and repoint.
        let Some(_editor) = supply.editor(spaces, index, mm_key, owner) else {
            cow_resolver.editor_busy();
            return Action::Forward;
        };
        let grant = _editor.grant();
        match cow_resolver.resolve_cow_outcome(grant.ttbr0, mm_key, far) {
            CowResolution::Resolved => return Action::Served,
            CowResolution::Refused => return Action::Forward,
            CowResolution::NeedsSupply => {
                if let FaultSupply::Owner(owner) = supply {
                    let selected = (|| {
                        let roots = prepared.as_ref()?.roots?;
                        let mm = carrick_el1_abi::ReservationMm::new(mm_key)?;
                        let observed = supply.observe(
                            spaces,
                            mm_key,
                            carrick_sched_core::spaces::notification::SpaceWaitCause::Reservations,
                        );
                        let mut root = roots
                            .lock_in(spaces, index.index(), mm, slot as u32)
                            .map_err(|error| {
                                if error == crate::memory::reservations::Refusal::Busy {
                                    supply.wait(observed);
                                }
                            })
                            .ok()?;
                        let operation = carrick_el1_abi::PortalOperation {
                            carrier: owner.slots.carrier()?,
                            mm,
                            incarnation: NonZeroU64::new(root.incarnation().raw())?,
                            sequence: root.next_transfer_sequence().ok()?,
                        };
                        let window = carrick_core::mm::fault::select_cow_supply_window(
                            &mut root,
                            operation,
                            carrick_guest_arch::UserVa::new(far),
                            None,
                        )
                        .ok()?;
                        drop(root);
                        owner
                            .slots
                            .grant(slot as usize)?
                            .publish_cow_fault_selection(operation.sequence.get(), window)
                            .then_some(())
                    })();
                    if selected.is_some() {
                        owner.outcome.set(OwnerFaultSupplyOutcome::CowSelected);
                    }
                }
            }
        }
        return Action::Forward;
    }

    if let FaultClass::Protection(access) = fault {
        if let FaultSupply::Owner(_) = supply
            && let Some(task) = current_task
        {
            let mm = task.mm.key.load(Ordering::Acquire);
            let observed = supply.observe(
                spaces,
                mm,
                carrick_sched_core::spaces::notification::SpaceWaitCause::Reservations,
            );
            match root_fault_admission(
                prepared.as_ref().and_then(|path| path.roots),
                spaces,
                slot as u32,
                mm,
                far & !4095,
                access,
            ) {
                RootFaultAdmission::Declined => supply.decline(),
                RootFaultAdmission::Busy => supply.wait(observed),
                _ => {}
            }
        }
        return Action::Forward;
    }
    let FaultClass::Translation {
        access: prepared_access,
        grant_access: access,
    } = fault
    else {
        return Action::Forward;
    };
    let Some(task) = current_task else {
        return Action::Forward;
    };
    let mm_key = task.mm.key.load(Ordering::Acquire);
    if mm_key == 0 {
        return Action::Forward;
    }

    if let Some(page) = prepared
        .as_ref()
        .and_then(|path| path.residency.lookup(mm_key, far))
    {
        // First-touch stock over a root hole is backing, not a mapping: the
        // host answers a touch the root does not map (SIGSEGV), and asks
        // for no grant.
        let observed = supply.observe(
            spaces,
            mm_key,
            carrick_sched_core::spaces::notification::SpaceWaitCause::Reservations,
        );
        match root_fault_admission(
            prepared.as_ref().and_then(|path| path.roots),
            spaces,
            slot as u32,
            mm_key,
            far & !4095,
            prepared_access,
        ) {
            RootFaultAdmission::Declined => {
                supply.decline();
                return Action::Forward;
            }
            RootFaultAdmission::Busy => {
                supply.wait(observed);
                return Action::Forward;
            }
            RootFaultAdmission::Unavailable => return Action::Forward,
            _ => {}
        }
        let Some(index) = spaces.find(mm_key) else {
            return Action::Forward;
        };
        let Some(owner) = NonZeroU64::new(slot + 1) else {
            return Action::Forward;
        };
        let Some(_editor) = supply.editor(spaces, index, mm_key, owner) else {
            return Action::Forward;
        };
        let grant = _editor.grant();
        let path = prepared.as_mut().expect("prepared grant path");
        match path.resolver.commit_prepared(
            grant.ttbr0,
            far & !4095,
            page.expected_ipa,
            prepared_access,
        ) {
            Ok(GuestPreparedCommit::Committed) => {
                assert!(path.residency.record_commit(page));
                if let FaultSupply::Mailbox(mailboxes) = supply {
                    consume_served_refusals(mailboxes, mm_key, far, access);
                }
                return Action::Served;
            }
            Ok(GuestPreparedCommit::AlreadyResident) => {
                if let FaultSupply::Mailbox(mailboxes) = supply {
                    consume_served_refusals(mailboxes, mm_key, far, access);
                }
                return Action::Served;
            }
            Err(GuestPreparedCommitError::RollbackFailed) => {
                panic!("EL1 prepared-page commit rollback failed")
            }
            Err(_) if matches!(supply, FaultSupply::Owner(_)) => return Action::Forward,
            Err(_) => {}
        }
    }

    if let FaultSupply::Owner(owner) = supply {
        let mut retry = false;
        let selected = (|| {
            let roots = prepared.as_ref()?.roots?;
            let mm = carrick_el1_abi::ReservationMm::new(mm_key)?;
            let index = spaces.find(mm_key)?;
            let editor = supply.editor(spaces, index, mm_key, NonZeroU64::new(slot + 1)?)?;
            let observed = supply.observe(
                spaces,
                mm_key,
                carrick_sched_core::spaces::notification::SpaceWaitCause::Reservations,
            );
            let mut root = roots
                .lock_in(spaces, index.index(), mm, slot as u32)
                .map_err(|error| {
                    if error == crate::memory::reservations::Refusal::Busy {
                        supply.wait(observed);
                    }
                })
                .ok()?;
            let window = match carrick_core::mm::fault::select_fault_window(
                &mut root,
                owner.slots.carrier()?,
                carrick_guest_arch::UserVa::new(far),
                carrick_guest_arch::GuestLen::new(carrick_el1_abi::EL1_FRAME_GRANT_TARGET_SIZE),
                carrick_el1_abi::ReservationProtection::from_bits(access)?,
            ) {
                Ok(window) => window,
                Err(
                    crate::memory::reservations::Refusal::Hole
                    | crate::memory::reservations::Refusal::Limit,
                ) => {
                    owner.outcome.set(OwnerFaultSupplyOutcome::PolicyDeclined);
                    return None;
                }
                Err(_) => return None,
            };
            let window = match prepared
                .as_mut()?
                .resolver
                .select_backing_window(editor.grant().ttbr0, window)
            {
                Ok(window) => window,
                Err(carrick_mmu_core::descriptor_refusal::DescriptorRefusal::Occupied) => {
                    // Same verdict as an occupied reply at application: a
                    // concurrent publication invalidates the observed fault,
                    // not the instruction. Re-enter without physical supply.
                    retry = true;
                    return None;
                }
                Err(_) => return None,
            };
            let slot = owner.slots.grant(slot as usize)?;
            slot.publish_fault_selection(window.operation.sequence.get(), window)
                .then_some(())
        })();
        if retry {
            return Action::Served;
        }
        if selected.is_some() {
            owner.outcome.set(OwnerFaultSupplyOutcome::Selected);
        }
        return Action::Forward;
    }
    let FaultSupply::Mailbox(mailboxes) = supply else {
        return Action::Forward;
    };
    let mailbox = mailboxes.own;
    // Only refusals cross back to EL1. Successful grants have already
    // published and released their slot on the host, even after migration.
    if consume_refusal(mailboxes, mm_key, far, access, || {
        root_mapping_incarnation(
            prepared.as_ref().and_then(|path| path.roots),
            spaces,
            slot as u32,
            mm_key,
            far,
        )
    }) {
        return Action::Forward;
    }

    #[cfg(target_os = "none")]
    if let Some(roots) = prepared.as_ref().and_then(|path| path.roots)
        && let Some(slots) = prepared.as_ref().and_then(|path| path.file_slots)
        && (carrick_core::mm::fault::FileFaultVenue {
            roots,
            spaces,
            slots,
            worker: slot as u32,
            mailbox,
        })
        .publish(mm_key, far, access)
    {
        return Action::Forward;
    }
    let incarnation = root_mapping_incarnation(
        prepared.as_ref().and_then(|path| path.roots),
        spaces,
        slot as u32,
        mm_key,
        far,
    );
    if let Some(incarnation) = incarnation {
        let _ = request_lazy_frames(mailbox, mm_key, far, access, incarnation);
    }
    Action::Forward
}

/// File first-touch selects the source and access policy in the admitted root.
/// The host sees only this exact owner window and retained handle byte service.
pub type FileFaultVenue<'a> = carrick_core::mm::fault::FileFaultVenue<
    'a,
    carrick_personality_linux::mm::LinuxReservationPolicy,
    crate::memory::reservations::NativeReservationGeometry,
    carrick_el1_abi::MmPortalSlots,
>;

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::CurrentTask;
    use carrick_el1_abi::{
        EL1_FRAME_GRANT_TARGET_SIZE, FRAME_GRANT_ERR_DENIED, FrameGrantMailbox, FrameGrantReady,
    };
    use carrick_sched_core::AddressSpaces;

    #[test]
    fn cow_caller_receives_exact_parked_root_incarnation() {
        use carrick_el1_abi::{El1TaskId, ThreadControlSlot, ThreadLifecyclePage};
        use carrick_guest_arch::{
            AddressContext, ContextGeneration, FrameGpa, MmGeneration, RootGpa,
        };
        use carrick_sched_core::{
            Aarch64ParkedContext, SlotId, ThreadCtx, ThreadIdentity, ZoneTables,
        };

        let layout = std::alloc::Layout::new::<ZoneTables<Aarch64ParkedContext>>();
        // SAFETY: the allocation is aligned and owns the complete zero-valid zone.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<Aarch64ParkedContext>>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        };
        let page = ThreadLifecyclePage::new();
        let control = ThreadControlSlot::new();
        let task = CurrentTask::new();
        task.set(
            El1TaskId::from_linux_tid(41),
            carrick_el1_abi::SnapshotGeneration::from_raw(11),
            5,
        );
        task.mm.key.store(1, Ordering::Release);
        task.mm.thread_generation.store(101, Ordering::Release);
        let slot = SlotId::new(0);
        zone.drive(slot, 1);
        zone.publish_slot(slot, 1, Some(0), 1);
        let record = zone
            .current_or_new(
                slot,
                ThreadIdentity {
                    tid: 41,
                    serial: 101,
                    mm: 1,
                    file_table: 5,
                    generation: 11,
                    affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                    affinity: 1,
                    lifecycle_page: &page as *const _ as u64,
                    control_slot: &control as *const _ as u64,
                },
            )
            .unwrap();
        let address = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::MIN),
            generation: ContextGeneration::new(NonZeroU64::new(7).unwrap()),
        };
        // SAFETY: this test owns the unpublished record and no other reader exists.
        unsafe {
            *zone.record(record).ctx_mut() =
                Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, address);
        }
        let got = unsafe { cow_address_for_record(&zone, &task, slot, address) };
        assert_eq!(got.map(|(_, address)| address), Some(address));
        let stale = AddressContext {
            generation: ContextGeneration::new(NonZeroU64::new(8).unwrap()),
            ..address
        };
        assert!(unsafe { cow_address_for_record(&zone, &task, slot, stale) }.is_none());
        // Reincarnate the same root GPA and MM in the retained slot. The old
        // address must now be refused, even though its numeric root matches.
        unsafe {
            *zone.record(record).ctx_mut() =
                Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, stale);
        }
        assert!(unsafe { cow_address_for_record(&zone, &task, slot, address) }.is_none());
        assert_eq!(
            unsafe { cow_address_for_record(&zone, &task, slot, stale) }
                .map(|(_, address)| address),
            Some(stale)
        );
    }

    #[test]
    fn instruction_translation_fault_can_request_owner_file_grant() {
        assert_eq!(frame_grant_access((0x20 << 26) | 0x07), Some(4));
        assert_eq!(frame_grant_access((0x20 << 26) | 0x0f), None);
    }

    fn write_translation_fault(slot: u64, address: u64) -> TrapFrame {
        TrapFrame {
            esr: (0x24 << 26) | (1 << 6) | 0x07,
            far: address,
            slot,
            ..TrapFrame::default()
        }
    }

    fn write_permission_fault(slot: u64, address: u64) -> TrapFrame {
        TrapFrame {
            esr: (0x24 << 26) | (1 << 6) | 0x0f,
            far: address,
            slot,
            ..TrapFrame::default()
        }
    }

    fn published_space(mm: u64, ttbr0: u64) -> AddressSpaces {
        let spaces = AddressSpaces::new();
        let index = spaces.publish_closed(mm, ttbr0, ttbr0).unwrap();
        spaces.open(index);
        spaces
    }

    #[test]
    fn prepared_grant_fault_commits_in_guest_and_records_residency() {
        let mm = 77;
        let va = 0x4000_1000;
        let base = 0x4000_0000;
        let table = carrick_el1_abi::FrameGrantResidencyTable::new();
        let identity = carrick_el1_abi::FrameGrantResidencyIdentity {
            mm_key: mm,
            semantic_base: base,
            physical_ipa: 0x9000_0000,
            len: 3 * 4096,
            mapping_id: 11,
            frame_id: 12,
            owner_generation: 13,
            inventory_revision: 14,
        };
        table.publish(identity).unwrap();
        // A host-served TLS/guard mapping can replace another page in this
        // bulk grant. The unchanged prepared leaf must still commit on its
        // first fault, without a grant refusal and a second host fault.
        table.retire_overlapping(mm, base + 2 * 4096, 4096);
        let task = CurrentTask::new();
        task.mm.key.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, 0x8800_0000);
        let mailbox = FrameGrantMailbox::new();
        let mut frame = write_translation_fault(0, va);
        let mut prepared = RecordingPreparedResolver::default();
        assert_eq!(
            dispatch_fault_with_prepared(
                &mut frame,
                &Counters::default(),
                &tasks,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                Some(PreparedFaultPath::<_> {
                    residency: &table,
                    resolver: &mut prepared,
                    roots: None,
                    file_slots: None,
                }),
                &mut NoopCowResolver,
            ),
            Action::Served
        );
        assert_eq!(prepared.calls, vec![(0x8800_0000, va, 0x9000_1000)]);
        assert!(table.is_guest_committed(mm, va));
        assert!(!mailbox.has_guest_work());
    }

    #[test]
    fn x86_translation_fault_uses_shared_prepared_owner_path() {
        use carrick_guest_arch::{Access, FaultInfo, UserVa};
        let mm = 91;
        let va = 0x4000_1000;
        let residency = carrick_el1_abi::FrameGrantResidencyTable::new();
        residency
            .publish(carrick_el1_abi::FrameGrantResidencyIdentity {
                mm_key: mm,
                semantic_base: va,
                physical_ipa: 0x9000_0000,
                len: 4096,
                mapping_id: 11,
                frame_id: 12,
                owner_generation: 13,
                inventory_revision: 14,
            })
            .unwrap();
        let task = CurrentTask::new();
        task.mm.key.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, 0x8800_0000);
        let mailbox = FrameGrantMailbox::new();
        let mut prepared = RecordingPreparedResolver::default();
        let counters = Counters::default();
        assert_eq!(
            dispatch_x86_fault_with_prepared(
                carrick_guest_arch::CpuId::new(0),
                FaultInfo {
                    address: UserVa::new(va),
                    access: Access::Read,
                    present: false,
                },
                &counters,
                &tasks[0],
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                Some(PreparedFaultPath::<_> {
                    residency: &residency,
                    resolver: &mut prepared,
                    roots: None,
                    file_slots: None,
                }),
                &mut NoopCowResolver,
            ),
            Action::Served
        );
        assert_eq!(prepared.calls, vec![(0x8800_0000, va, 0x9000_0000)]);
        assert!(residency.is_guest_committed(mm, va));
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
        assert!(!mailbox.has_guest_work());
    }

    #[test]
    fn x86_cpu1_fault_uses_bound_task_without_cpu0_padding() {
        use carrick_guest_arch::{Access, FaultInfo, UserVa};
        let mm = 91;
        let va = 0x4000_1000;
        let residency = carrick_el1_abi::FrameGrantResidencyTable::new();
        residency
            .publish(carrick_el1_abi::FrameGrantResidencyIdentity {
                mm_key: mm,
                semantic_base: va,
                physical_ipa: 0x9000_0000,
                len: 4096,
                mapping_id: 11,
                frame_id: 12,
                owner_generation: 13,
                inventory_revision: 14,
            })
            .unwrap();
        let task = CurrentTask::new();
        task.mm.key.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, 0x8800_0000);
        let mailbox = FrameGrantMailbox::new();
        let mut prepared = RecordingPreparedResolver::default();
        let counters = Counters::default();
        assert_eq!(
            dispatch_x86_fault_with_prepared(
                carrick_guest_arch::CpuId::new(1),
                FaultInfo {
                    address: UserVa::new(va),
                    access: Access::Read,
                    present: false,
                },
                &counters,
                &tasks[0],
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                Some(PreparedFaultPath::<_> {
                    residency: &residency,
                    resolver: &mut prepared,
                    roots: None,
                    file_slots: None,
                }),
                &mut NoopCowResolver,
            ),
            Action::Served
        );
        assert_eq!(prepared.calls, vec![(0x8800_0000, va, 0x9000_0000)]);
        assert!(residency.is_guest_committed(mm, va));
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
        assert!(!mailbox.has_guest_work());
    }

    #[test]
    fn x86_kernel_half_fault_never_requests_guest_backing() {
        use carrick_guest_arch::{Access, FaultInfo, UserVa};
        assert_eq!(
            x86_fault_class(FaultInfo {
                address: UserVa::new(0xffff_ffff_9000_0000),
                access: Access::Write,
                present: false,
            }),
            FaultClass::Other
        );
    }

    /// A zeroed shared reservation table with `mm`'s root admitted in its
    /// address-space slot, holding `nodes` (`(address, len, prot bits)`).
    fn admitted_root(
        spaces: &AddressSpaces,
        mm: u64,
        nodes: &[(u64, u64, u64)],
    ) -> std::boxed::Box<crate::memory::reservations::SharedReservations> {
        use crate::memory::reservations::{Decision, Layout, Placement, SharedReservations};
        use carrick_el1_abi::{
            ReservationBackingReceipt, ReservationCompletion, ReservationMm, ReservationProtection,
            ReservationRange,
        };
        let ptr =
            unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<SharedReservations>()) };
        assert!(!ptr.is_null());
        let table: std::boxed::Box<SharedReservations> =
            unsafe { std::boxed::Box::from_raw(ptr.cast()) };
        let index = spaces.find(mm).unwrap().index();
        let raw = ReservationMm::new(mm).unwrap();
        table
            .publish(
                index,
                raw,
                Layout {
                    heap: ReservationRange::new(0x1000, 0x10_0000).unwrap(),
                    arena: ReservationRange::new(0x4000_0000, 0x8000_0000).unwrap(),
                    brk: 0x1000,
                    address_limit: u64::MAX,
                    data_limit: u64::MAX,
                    external_address_bytes: 0,
                    external_data_bytes: 0,
                },
            )
            .unwrap();
        let mut model = table.lock(index, raw).unwrap();
        model.finish_import().unwrap();
        for &(address, len, prot) in nodes {
            let Ok(Decision::Work(request)) = model.mmap(
                Placement::Fixed(address),
                len,
                ReservationProtection::from_bits(prot).unwrap(),
            ) else {
                panic!("a fresh mapping is a transaction");
            };
            let completion = unsafe {
                ReservationCompletion::after_descriptor_and_backing_commit(
                    request,
                    ReservationBackingReceipt {
                        receipt: request.sequence.raw(),
                        granted_bytes: 0,
                        returned_bytes: 0,
                    },
                )
            }
            .unwrap();
            model.complete(completion).unwrap();
        }
        drop(model);
        table
    }

    /// Contract `kernel.el1.anonymous-reservations` (first-touch stock): a
    /// delegated MM's prepared backing commits only where its root holds a
    /// node that permits the access. Stock over a hole, or under a node the
    /// access is denied by, forwards without a grant request: the host
    /// delivers the signal.
    #[test]
    fn first_touch_stock_commits_only_under_a_permitting_root_node() {
        let mm = 79;
        let base = 0x4000_0000;
        let spaces = published_space(mm, 0x8800_0000);
        let roots = admitted_root(
            &spaces,
            mm,
            &[(base + 0x1000, 0x1000, 3), (base + 0x2000, 0x1000, 1)],
        );
        let residency = std::boxed::Box::new(carrick_el1_abi::FrameGrantResidencyTable::new());
        residency
            .publish(carrick_el1_abi::FrameGrantResidencyIdentity {
                mm_key: mm,
                semantic_base: base,
                physical_ipa: 0x9000_0000,
                len: 4 * 4096,
                mapping_id: 11,
                frame_id: 12,
                owner_generation: 13,
                inventory_revision: 14,
            })
            .unwrap();
        let task = CurrentTask::new();
        task.mm.key.store(mm, Ordering::Release);
        let tasks = [task];
        let read_translation_fault = |address| TrapFrame {
            esr: (0x24 << 26) | 0x07,
            far: address,
            ..TrapFrame::default()
        };
        for (mut frame, served) in [
            (write_translation_fault(0, base), false),
            (write_translation_fault(0, base + 0x3000), false),
            (write_translation_fault(0, base + 0x2000), false),
            (write_translation_fault(0, base + 0x1000), true),
            (read_translation_fault(base + 0x2000), true),
        ] {
            let mailbox = FrameGrantMailbox::new();
            let mut prepared = RecordingPreparedResolver::default();
            let action = dispatch_fault_with_prepared(
                &mut frame,
                &Counters::default(),
                &tasks,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                Some(PreparedFaultPath::<_> {
                    residency: &residency,
                    resolver: &mut prepared,
                    roots: Some(&roots),
                    file_slots: None,
                }),
                &mut NoopCowResolver,
            );
            let far = frame.far;
            assert_eq!(action == Action::Served, served, "fault at {far:#x}");
            assert_eq!(
                prepared.calls.len(),
                usize::from(served),
                "fault at {far:#x}"
            );
            assert!(!mailbox.has_guest_work(), "no grant request at {far:#x}");
        }
    }

    #[test]
    fn prepared_executable_leaf_commits_on_instruction_translation_fault() {
        let mm = 78;
        let va = 0x4000_0000;
        let table = carrick_el1_abi::FrameGrantResidencyTable::new();
        let identity = carrick_el1_abi::FrameGrantResidencyIdentity {
            mm_key: mm,
            semantic_base: va,
            physical_ipa: 0x9000_0000,
            len: 4096,
            mapping_id: 11,
            frame_id: 12,
            owner_generation: 13,
            inventory_revision: 14,
        };
        table.publish(identity).unwrap();
        let task = CurrentTask::new();
        task.mm.key.store(mm, Ordering::Release);
        let mut frame = TrapFrame {
            esr: (0x20 << 26) | 0x07,
            far: va,
            ..TrapFrame::default()
        };
        assert_eq!(
            dispatch_fault_with_prepared(
                &mut frame,
                &Counters::default(),
                &[task],
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(
                    &published_space(mm, 0x8800_0000)
                ),
                GrantMailboxes::own(&FrameGrantMailbox::new()),
                Some(PreparedFaultPath::<_> {
                    residency: &table,
                    resolver: &mut RecordingPreparedResolver::default(),
                    roots: None,
                    file_slots: None,
                }),
                &mut NoopCowResolver,
            ),
            Action::Served
        );
        assert!(table.is_guest_committed(mm, va));
    }

    #[derive(Default)]
    struct RecordingCowResolver {
        succeeds: bool,
        calls: Vec<(u64, u64, u64)>,
    }

    impl CowResolver for RecordingCowResolver {
        fn resolve_cow(&mut self, ttbr0: u64, mm_key: u64, far: u64) -> bool {
            self.calls.push((ttbr0, mm_key, far));
            self.succeeds
        }
    }

    #[derive(Default)]
    struct RecordingPreparedResolver {
        calls: Vec<(u64, u64, u64)>,
    }

    impl PreparedPageResolver for RecordingPreparedResolver {
        fn commit_prepared(
            &mut self,
            ttbr0: u64,
            va: u64,
            expected_ipa: u64,
            _access: LeafAccess,
        ) -> Result<GuestPreparedCommit, GuestPreparedCommitError> {
            self.calls.push((ttbr0, va, expected_ipa));
            Ok(GuestPreparedCommit::Committed)
        }
    }

    /// Two slots can fault before either host boundary runs. Publication is
    /// scoped to the MM extent, not the slot that happened to request it.
    #[test]
    fn concurrent_and_migrated_faults_share_one_host_publication() {
        use core::cell::Cell;
        for pages in [1, 2, 512] {
            let mm = 9;
            let tasks = [CurrentTask::new(), CurrentTask::new()];
            for task in &tasks {
                task.mm.key.store(mm, Ordering::Release);
            }
            let spaces = published_space(mm, 0x8800_0000);
            let boxes = FrameGrantMailboxes::new();
            let counters = Counters::default();
            let origin = boxes.slot(0).unwrap();
            let peer = boxes.slot(1).unwrap();
            let mut cow = NoopCowResolver;
            let base = 0x4000_0000;
            let roots = admitted_root(&spaces, mm, &[(base, 0x20_0000, 3)]);
            let residency = carrick_el1_abi::FrameGrantResidencyTable::new();
            let mut first = write_translation_fault(0, base);
            let mut second = write_translation_fault(1, base + (pages - 1) * 4096);
            for (frame, own) in [(&mut first, origin), (&mut second, peer)] {
                assert_eq!(
                    dispatch_fault_with_prepared(
                        frame,
                        &counters,
                        &tasks,
                        carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                        GrantMailboxes {
                            own,
                            peers: Some(&boxes)
                        },
                        Some(PreparedFaultPath::<_> {
                            residency: &residency,
                            resolver: &mut NoopPreparedResolver,
                            roots: Some(&roots),
                            file_slots: None
                        }),
                        &mut cow,
                    ),
                    Action::Forward
                );
            }
            let request = origin.claim_request().unwrap();
            let ready = FrameGrantReady {
                mm_key: mm,
                request_generation: request.request_generation,
                semantic_base: base,
                physical_ipa: 0x9000_0000,
                len: pages * 4096,
                permissions: 3,
                frame_id: 1,
                mapping_id: 2,
                owner_generation: 3,
                inventory_revision: 4,
            };
            let published = Cell::new(false);
            let armed = Cell::new(true);
            let publications = Cell::new(0);
            assert_eq!(
                origin.complete_grant(
                    ready,
                    |grant| {
                        assert!(armed.get());
                        assert_eq!(grant.len, pages * 4096);
                        // The second fault cannot consume unpublished frame authority.
                        assert!(
                            origin
                                .claim_response(mm, request.request_generation)
                                .is_none()
                        );
                        publications.set(publications.get() + 1);
                        published.set(true);
                        Ok::<_, ()>(true)
                    },
                    || {
                        assert!(published.get());
                        armed.set(false);
                    }
                ),
                Ok(true)
            );
            assert!(!armed.get());
            assert!(!origin.has_guest_work());
            // Slot 1's queued fault reaches the host after slot 0 committed.
            // The live-leaf path resolves it and cancels its unused request.
            assert!(published.get(), "stale fault must retry, not signal");
            assert!(peer.cancel_request_for_fault(mm, second.far, 2));
            // An already queued retry may migrate to the original slot. EL1
            // forwards; it never republishes stale frame metadata on that slot.
            second.slot = 0;
            assert_eq!(
                dispatch_fault_with_prepared(
                    &mut second,
                    &counters,
                    &tasks,
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                    GrantMailboxes {
                        own: origin,
                        peers: Some(&boxes)
                    },
                    Some(PreparedFaultPath::<_> {
                        residency: &residency,
                        resolver: &mut NoopPreparedResolver,
                        roots: Some(&roots),
                        file_slots: None
                    }),
                    &mut cow,
                ),
                Action::Forward
            );
            assert!(published.get());
            assert!(origin.cancel_request_for_fault(mm, second.far, 2));
            assert_eq!(publications.get(), 1, "one bulk publication for the extent");
            assert!(!peer.has_guest_work());
        }
    }

    #[test]
    fn missing_guest_table_is_handled_before_commit_without_guest_handback() {
        use core::cell::Cell;
        let task = CurrentTask::new();
        task.mm.key.store(7, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(7, 0x8800_0000);
        let roots = admitted_root(&spaces, 7, &[(0x4000_0000, 0x20_0000, 3)]);
        let residency = carrick_el1_abi::FrameGrantResidencyTable::new();
        let mailbox = FrameGrantMailbox::new();
        let mut frame = write_translation_fault(0, 0x4000_1000);
        assert_eq!(
            dispatch_fault_with_prepared(
                &mut frame,
                &Counters::default(),
                &tasks,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                Some(PreparedFaultPath::<_> {
                    residency: &residency,
                    resolver: &mut NoopPreparedResolver,
                    roots: Some(&roots),
                    file_slots: None
                }),
                &mut NoopCowResolver,
            ),
            Action::Forward
        );
        let request = mailbox.claim_request().unwrap();
        let tables = Cell::new(false);
        let leaves = Cell::new(false);
        assert_eq!(
            mailbox.complete_grant(
                FrameGrantReady {
                    mm_key: 7,
                    request_generation: request.request_generation,
                    semantic_base: 0x4000_0000,
                    physical_ipa: 0x9000_0000,
                    len: EL1_FRAME_GRANT_TARGET_SIZE,
                    permissions: 3,
                    frame_id: 1,
                    mapping_id: 2,
                    owner_generation: 3,
                    inventory_revision: 4,
                },
                |_| {
                    // This used to require GUEST_FAILED and another host exit. The
                    // host publisher allocates the missing table in this transaction.
                    tables.set(true);
                    leaves.set(true);
                    Ok::<_, ()>(true)
                },
                || {
                    assert!(tables.get() && leaves.get());
                }
            ),
            Ok(true)
        );
        assert!(!mailbox.has_guest_work());
        assert!(
            mailbox
                .claim_response(7, request.request_generation)
                .is_none()
        );
    }

    #[test]
    fn refused_frame_grant_falls_back_without_republishing_in_the_same_dispatch() {
        let mm = 8;
        let task = CurrentTask::new();
        task.mm.key.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, (32_u64 << 48) | 0x8900_0000_0000);
        let roots = admitted_root(&spaces, mm, &[(0x5000_0000, 0x20_0000, 3)]);
        let residency = carrick_el1_abi::FrameGrantResidencyTable::new();
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_translation_fault(0, 0x5000_1000);

        assert_eq!(
            dispatch_fault_with_prepared(
                &mut frame,
                &counters,
                &tasks,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                Some(PreparedFaultPath::<_> {
                    residency: &residency,
                    resolver: &mut NoopPreparedResolver,
                    roots: Some(&roots),
                    file_slots: None
                }),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        let request = mailbox.claim_request().unwrap();
        assert!(mailbox.publish_refusal(FRAME_GRANT_ERR_DENIED));
        assert_eq!(
            dispatch_fault_with_prepared(
                &mut frame,
                &counters,
                &tasks,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                Some(PreparedFaultPath::<_> {
                    residency: &residency,
                    resolver: &mut NoopPreparedResolver,
                    roots: Some(&roots),
                    file_slots: None
                }),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert!(!mailbox.has_guest_work());
        assert_ne!(request.request_generation, 0);
    }

    /// A refusal answers the mapping that faulted, not a later mapping at
    /// the same VA. The host may have refused an obsolete request after a
    /// sibling published its leaf; munmap and mmap can then reuse the VA
    /// before EL1 next sees the mailbox response.
    #[test]
    fn old_mapping_refusal_does_not_block_first_touch_after_va_reuse() {
        use crate::memory::reservations::{Decision, Placement};
        use carrick_el1_abi::{
            ReservationBackingReceipt, ReservationCompletion, ReservationMm, ReservationProtection,
            ReservationRange,
        };
        let mm = 88;
        let va = 0x4000_5000;
        let spaces = published_space(mm, 0x8800_0000);
        let roots = admitted_root(&spaces, mm, &[(va, 4096, 3)]);
        let residency = carrick_el1_abi::FrameGrantResidencyTable::new();
        let task = CurrentTask::new();
        task.mm.key.store(mm, Ordering::Release);
        let tasks = [task];
        let mailbox = FrameGrantMailbox::new();
        let mut fault = write_translation_fault(0, va);
        let dispatch = |frame: &mut TrapFrame| {
            dispatch_fault_with_prepared(
                frame,
                &Counters::default(),
                &tasks,
                SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                Some(PreparedFaultPath::<_> {
                    residency: &residency,
                    resolver: &mut NoopPreparedResolver,
                    roots: Some(&roots),
                    file_slots: None,
                }),
                &mut NoopCowResolver,
            )
        };
        assert_eq!(dispatch(&mut fault), Action::Forward);
        let old_request = mailbox
            .claim_request()
            .expect("old mapping requested backing");
        let old_incarnation = old_request.reservation_incarnation;
        assert!(mailbox.publish_refusal(FRAME_GRANT_ERR_DENIED));

        let index = spaces.find(mm).unwrap().index();
        let mut root = roots.lock(index, ReservationMm::new(mm).unwrap()).unwrap();
        let range = ReservationRange::new(va, va + 4096).unwrap();
        let Decision::Work(retire) = root.munmap(range).unwrap() else {
            panic!("the old node must retire");
        };
        let completion = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                retire,
                ReservationBackingReceipt {
                    receipt: retire.sequence.raw(),
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        root.complete(completion).unwrap();
        let Decision::Work(replace) = root
            .mmap(
                Placement::Fixed(va),
                4096,
                ReservationProtection::READ_WRITE,
            )
            .unwrap()
        else {
            panic!("VA reuse must create a new node");
        };
        let completion = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                replace,
                ReservationBackingReceipt {
                    receipt: replace.sequence.raw(),
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        root.complete(completion).unwrap();
        drop(root);

        assert_eq!(dispatch(&mut fault), Action::Forward);
        let new_request = mailbox
            .claim_request()
            .expect("the replacement mapping must issue its own grant request");
        assert_ne!(new_request.reservation_incarnation, old_incarnation);
    }

    #[test]
    fn contended_root_retries_stale_refusal_without_untagged_request() {
        use crate::memory::reservations::{Decision, Placement};
        use carrick_el1_abi::{
            ReservationBackingReceipt, ReservationCompletion, ReservationMm, ReservationProtection,
            ReservationRange,
        };
        let mm = 88;
        let va = 0x4000_5000;
        let spaces = published_space(mm, 0x8800_0000);
        let roots = admitted_root(&spaces, mm, &[(va, 4096, 3)]);
        let residency = carrick_el1_abi::FrameGrantResidencyTable::new();
        let task = CurrentTask::new();
        task.mm.key.store(mm, Ordering::Release);
        let tasks = [task];
        let mailbox = FrameGrantMailbox::new();
        let mut fault = write_translation_fault(0, va);
        let dispatch = |frame: &mut TrapFrame| {
            dispatch_fault_with_prepared(
                frame,
                &Counters::default(),
                &tasks,
                SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                Some(PreparedFaultPath::<_> {
                    residency: &residency,
                    resolver: &mut NoopPreparedResolver,
                    roots: Some(&roots),
                    file_slots: None,
                }),
                &mut NoopCowResolver,
            )
        };
        assert_eq!(dispatch(&mut fault), Action::Forward);
        let old_request = mailbox
            .claim_request()
            .expect("old mapping requested backing");
        let old_incarnation = old_request.reservation_incarnation;
        assert!(mailbox.publish_refusal(FRAME_GRANT_ERR_DENIED));

        let index = spaces.find(mm).unwrap().index();
        let mut root = roots.lock(index, ReservationMm::new(mm).unwrap()).unwrap();
        let range = ReservationRange::new(va, va + 4096).unwrap();
        let Decision::Work(retire) = root.munmap(range).unwrap() else {
            panic!("the old node must retire");
        };
        let completion = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                retire,
                ReservationBackingReceipt {
                    receipt: retire.sequence.raw(),
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        root.complete(completion).unwrap();
        let Decision::Work(replace) = root
            .mmap(
                Placement::Fixed(va),
                4096,
                ReservationProtection::READ_WRITE,
            )
            .unwrap()
        else {
            panic!("VA reuse must create a new node");
        };
        let completion = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                replace,
                ReservationBackingReceipt {
                    receipt: replace.sequence.raw(),
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        root.complete(completion).unwrap();
        // Root still held (host/sibling critical section) at the retry.
        assert!(
            !consume_refusal(GrantMailboxes::own(&mailbox), mm, va, 2, || {
                root_mapping_incarnation(Some(&roots), SpaceAccess::source_free(&spaces), 0, mm, va)
            }),
            "unreadable incarnation cannot authenticate an old refusal"
        );
        assert_eq!(dispatch(&mut fault), Action::Forward);
        assert!(
            mailbox.claim_request().is_none(),
            "contended root must not create an untagged request"
        );
        drop(root);
        assert_eq!(dispatch(&mut fault), Action::Forward);
        let new_request = mailbox
            .claim_request()
            .expect("the replacement mapping must issue its own grant request");
        assert_ne!(new_request.reservation_incarnation, old_incarnation);
    }

    /// Guest-lane shape: a fault inside a grant EL1 already applied, before
    /// the host settled it, requests again; the host settles (publishing
    /// residency) and refuses the now non-pristine span. The retry is then
    /// served from residency. Its refusal must be consumed there too: left in
    /// RESPONSE, the vCPU slot's mailbox can never carry another request, so
    /// every later first touch on that slot, in any MM, is page-granular.
    #[test]
    fn a_refusal_whose_retry_is_served_from_residency_is_consumed() {
        let mm = 83;
        let base = 0x4000_0000;
        let va = base + 0x5000;
        for migrated in [false, true] {
            let task = CurrentTask::new();
            task.mm.key.store(mm, Ordering::Release);
            let tasks = [task, CurrentTask::new()];
            tasks[1].mm.key.store(mm, Ordering::Release);
            let spaces = published_space(mm, 0x8800_0000);
            let roots = admitted_root(&spaces, mm, &[(base, 0x40_0000, 3)]);
            let boxes = FrameGrantMailboxes::new();
            let origin = boxes.slot(0).unwrap();
            let counters = Counters::default();
            let table = carrick_el1_abi::FrameGrantResidencyTable::new();
            let mut first = write_translation_fault(0, va);
            assert_eq!(
                dispatch_fault_with_prepared(
                    &mut first,
                    &counters,
                    &tasks,
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                    GrantMailboxes {
                        own: origin,
                        peers: Some(&boxes),
                    },
                    Some(PreparedFaultPath::<_> {
                        residency: &table,
                        resolver: &mut RecordingPreparedResolver::default(),
                        roots: Some(&roots),
                        file_slots: None,
                    }),
                    &mut NoopCowResolver,
                ),
                Action::Forward
            );
            assert!(origin.claim_request().is_some());
            table
                .publish(carrick_el1_abi::FrameGrantResidencyIdentity {
                    mm_key: mm,
                    semantic_base: base,
                    physical_ipa: 0x9000_0000,
                    len: 16 * 4096,
                    mapping_id: 11,
                    frame_id: 12,
                    owner_generation: 13,
                    inventory_revision: 14,
                })
                .unwrap();
            assert!(origin.publish_refusal(FRAME_GRANT_ERR_DENIED));

            let retry_slot = u64::from(migrated);
            let mut retry = write_translation_fault(retry_slot, va);
            let own = boxes.slot(retry_slot as usize).unwrap();
            assert_eq!(
                dispatch_fault_with_prepared(
                    &mut retry,
                    &counters,
                    &tasks,
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                    GrantMailboxes {
                        own,
                        peers: Some(&boxes),
                    },
                    Some(PreparedFaultPath::<_> {
                        residency: &table,
                        resolver: &mut RecordingPreparedResolver::default(),
                        roots: Some(&roots),
                        file_slots: None,
                    }),
                    &mut NoopCowResolver,
                ),
                Action::Served
            );
            assert!(
                boxes.iter().all(|mailbox| !mailbox.has_guest_work()),
                "migrated={migrated}: a refusal outlived the fault it answered"
            );

            let mut next = write_translation_fault(0, base + 0x20_0000);
            assert_eq!(
                dispatch_fault_with_prepared(
                    &mut next,
                    &counters,
                    &tasks,
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                    GrantMailboxes {
                        own: origin,
                        peers: Some(&boxes),
                    },
                    Some(PreparedFaultPath::<_> {
                        residency: &table,
                        resolver: &mut RecordingPreparedResolver::default(),
                        roots: Some(&roots),
                        file_slots: None,
                    }),
                    &mut NoopCowResolver,
                ),
                Action::Forward
            );
            assert!(
                origin.claim_request().is_some(),
                "migrated={migrated}: the next first touch could not request a grant"
            );
        }
    }

    #[test]
    fn permission_fault_never_requests_a_first_touch_frame_grant() {
        let mm = 82;
        let task = CurrentTask::new();
        task.mm.key.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, (35_u64 << 48) | 0x8c00_0000_0000);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_permission_fault(0, 0x5300_1000);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert!(
            !mailbox.has_guest_work(),
            "a mapped-page permission denial must not request new physical backing"
        );
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn non_translation_or_permission_fault_never_requests_a_grant() {
        let task = CurrentTask::new();
        task.mm.key.store(9, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(9, (33_u64 << 48) | 0x8a00_0000_0000);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_translation_fault(0, 0x6000_1000);
        frame.esr = (0x24 << 26) | 0x21;

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert!(!mailbox.has_guest_work());
    }

    #[test]
    fn owner_cow_fault_preserves_validated_empty_pool_supply() {
        use crate::cow::test_support::{Arena, OLD, ROOT, VA};
        use carrick_el1_abi::FrameGrantResidencyTable;
        /// The armed leaf's base permissions: valid page, EL0 access, AF, UXN.
        const RW: u64 = 3 | (1 << 6) | (1 << 10) | (1 << 54);
        struct EmptyCow<'a>(
            &'a Arena,
            &'a carrick_el1_abi::CowGrantPool,
            &'a FrameGrantResidencyTable,
        );
        impl CowResolver for EmptyCow<'_> {
            fn resolve_cow(&mut self, _: u64, _: u64, _: u64) -> bool {
                panic!("typed COW outcome must survive fault dispatch")
            }
            fn resolve_cow_outcome(&mut self, ttbr: u64, mm: u64, va: u64) -> CowResolution {
                let live = self.0.words();
                let result = crate::cow::resolve_guest_cow(
                    &crate::cow::GuestCowVenue {
                        words: &live,
                        root: carrick_mmu_core::aarch64::SubstrateGpa(ttbr),
                        pool: self.1,
                        residency: self.2,
                        copy_window: crate::cow::CowCopyWindow::target(
                            &live,
                            carrick_mmu_core::aarch64::SubstrateGpa(ttbr),
                        ),
                        publish_executable: None,
                    },
                    mm,
                    va,
                    |_, _| panic!("empty pool must not copy"),
                    || {},
                );
                assert_eq!(
                    result,
                    Ok(crate::cow::GuestCowOutcome::Declined(
                        carrick_el1_abi::CowDecline::PoolEmpty
                    ))
                );
                CowResolution::NeedsSupply
            }
        }
        let mm = 77;
        let spaces = published_space(mm, ROOT);
        let roots = admitted_root(&spaces, mm, &[(VA, 4096, 3)]);
        let tables = Arena::new(false);
        tables.set_leaf(VA, OLD | RW | (3 << 6) | (1 << 55) | (1 << 56) | (1 << 57));
        let pool = carrick_el1_abi::CowGrantPool::new();
        let resident_ptr = unsafe {
            std::alloc::alloc_zeroed(std::alloc::Layout::new::<FrameGrantResidencyTable>())
        };
        assert!(!resident_ptr.is_null());
        let residency =
            unsafe { std::boxed::Box::from_raw(resident_ptr.cast::<FrameGrantResidencyTable>()) };
        let ptr = unsafe {
            std::alloc::alloc_zeroed(std::alloc::Layout::new::<carrick_el1_abi::MmPortalSlots>())
        };
        assert!(!ptr.is_null());
        let slots =
            unsafe { std::boxed::Box::from_raw(ptr.cast::<carrick_el1_abi::MmPortalSlots>()) };
        assert!(slots.bind_carrier(NonZeroU64::new(9).unwrap()));
        let supply = OwnerFaultSupply::new(&slots);
        let task = CurrentTask::new();
        task.mm.key.store(mm, Ordering::Release);
        assert_eq!(
            dispatch_classified_fault(
                0,
                VA + 3,
                FaultClass::WritePermission,
                &Counters::default(),
                Some(&task),
                SpaceAccess::source_free(&spaces),
                FaultSupply::Owner(&supply),
                Some(PreparedFaultPath::<_> {
                    residency: &residency,
                    resolver: &mut NoopPreparedResolver,
                    roots: Some(&roots),
                    file_slots: None
                }),
                &mut EmptyCow(&tables, &pool, &residency)
            ),
            Action::Forward
        );
        assert_eq!(supply.outcome(), OwnerFaultSupplyOutcome::CowSelected);
        let (_, window) = slots
            .grant(0)
            .unwrap()
            .pending_cow_fault_selection(mm, VA + 3)
            .unwrap();
        assert_eq!(window.operation.mm.raw(), mm);
        assert_eq!(window.operation.carrier.get(), 9);
        let mut root = roots
            .lock(
                spaces.find(mm).unwrap().index(),
                carrick_el1_abi::ReservationMm::new(mm).unwrap(),
            )
            .unwrap();
        assert_eq!(window.operation.incarnation.get(), root.incarnation().raw());
        assert_eq!(window.mapping_incarnation, root.node(VA).unwrap().1);
        drop(root);
        assert_eq!(window.range.start(), VA);
        assert_eq!(window.range.len(), 4096);
        assert!(window.host_backing.is_none());
        assert!(
            slots
                .grant(0)
                .unwrap()
                .pending_fault_selection(mm, VA)
                .is_none()
        );
        assert!(
            spaces
                .try_begin_edit(spaces.find(mm).unwrap(), mm, NonZeroU64::new(2).unwrap())
                .is_some()
        );
    }

    #[test]
    fn cow_write_permission_fault_serves_in_guest_when_resolved() {
        let mm = 90;
        let ttbr0 = (36_u64 << 48) | 0x8d00_0000_0000;
        let fault = 0x4000_3000;
        let task = CurrentTask::new();
        task.mm.key.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, ttbr0);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = RecordingCowResolver {
            succeeds: true,
            ..RecordingCowResolver::default()
        };
        let mut frame = write_permission_fault(0, fault);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Served
        );
        assert_eq!(cow_resolver.calls, vec![(ttbr0, mm, fault)]);
        assert!(!mailbox.has_guest_work());
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cow_write_permission_fault_forwards_when_not_authorized() {
        let mm = 91;
        let ttbr0 = (37_u64 << 48) | 0x8e00_0000_0000;
        let fault = 0x4000_4000;
        let task = CurrentTask::new();
        task.mm.key.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, ttbr0);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = RecordingCowResolver {
            succeeds: false,
            ..RecordingCowResolver::default()
        };
        let mut frame = write_permission_fault(0, fault);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert_eq!(cow_resolver.calls, vec![(ttbr0, mm, fault)]);
        assert!(!mailbox.has_guest_work());
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
    }

    mod descriptor_txns {
        use super::*;
        use carrick_mmu_core::aarch64::descriptor_txn::{
            BackingIdentity, DescriptorOp, DescriptorRefusal, DescriptorTxn, DescriptorTxnId,
            InlineJournal, PageSpan, PrimaryTableWords, TableGrants, TableMaintenance,
            apply_submitted_descriptor_txn,
        };
        use carrick_mmu_core::aarch64::{
            El1PrivateLeafState, GuestLeafPublication, SubstrateGpa, el1_private_leaf_state,
            indices,
        };
        use core::cell::RefCell;

        const ROOT: u64 = 0x8800_0000_0000;
        const ASID: u64 = 5 << 48;
        const VA: u64 = 0x4000_0000;
        const IPA: u64 = 0x009b_4000_0000;

        struct Arena {
            words: Vec<AtomicU64>,
        }

        impl Arena {
            /// L0 -> L1 -> L2 -> L3 for `VA` in pages 0..=3 of a 16-page arena.
            fn new() -> Self {
                let words: Vec<AtomicU64> = (0..16 * 512).map(|_| AtomicU64::new(0)).collect();
                let idx = indices(VA);
                words[idx[0]].store((ROOT + 0x1000) | 0b11, Ordering::Relaxed);
                words[512 + idx[1]].store((ROOT + 0x2000) | 0b11, Ordering::Relaxed);
                words[1024 + idx[2]].store((ROOT + 0x3000) | 0b11, Ordering::Relaxed);
                Self { words }
            }
            fn leaf(&self, va: u64) -> u64 {
                self.words[1536 + indices(va)[3]].load(Ordering::Acquire)
            }
            fn image(&self) -> Vec<u64> {
                self.words
                    .iter()
                    .map(|w| w.load(Ordering::Relaxed))
                    .collect()
            }
        }

        struct NoBarrier;
        impl TableMaintenance for NoBarrier {
            fn publish_barrier(&self) {}
            fn invalidate_range(&self, _va: u64, _len: u64) {}
        }

        /// The EL1 applier over host memory, recording ASID invalidations
        /// and whether the host could already see the receipt when each ran.
        struct ArenaApplier<'a> {
            arena: &'a Arena,
            invalidated: RefCell<Vec<u64>>,
            receipt_visible_at_invalidation: RefCell<Vec<bool>>,
        }

        impl<'a> ArenaApplier<'a> {
            fn new(arena: &'a Arena) -> Self {
                Self {
                    arena,
                    invalidated: RefCell::new(Vec::new()),
                    receipt_visible_at_invalidation: RefCell::new(Vec::new()),
                }
            }
        }

        impl DescriptorTxnApplier for ArenaApplier<'_> {
            fn apply(
                &mut self,
                slot: &DescriptorTxnSlot,
                mm_key: u64,
                ttbr0: u64,
            ) -> Option<DescriptorReceipt> {
                let words = unsafe {
                    PrimaryTableWords::new(
                        self.arena.words.as_ptr().cast_mut(),
                        ROOT,
                        self.arena.words.len() * 8,
                        &NoBarrier,
                    )
                }
                .unwrap();
                let mut journal = InlineJournal::new();
                apply_submitted_descriptor_txn(
                    slot,
                    mm_key,
                    &words,
                    SubstrateGpa(ttbr0 & 0x0000_FFFF_FFFF_F000),
                    &mut journal,
                    || {
                        self.invalidated.borrow_mut().push(ttbr0);
                        self.receipt_visible_at_invalidation.borrow_mut().push(
                            slot.state()
                                == carrick_mmu_core::aarch64::descriptor_txn::DESCRIPTOR_TXN_RECEIPT,
                        );
                    },
                )
            }
        }

        fn nz(value: u64) -> NonZeroU64 {
            NonZeroU64::new(value).unwrap()
        }

        fn grant_txn(mm: u64, root: u64, fault: u64) -> DescriptorTxn {
            DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: nz(mm),
                    generation: nz(1),
                },
                root: SubstrateGpa(root),
                op: DescriptorOp::Prepare {
                    publication: GuestLeafPublication {
                        va: VA,
                        ipa: IPA,
                        len: 4 * 4096,
                        writable: true,
                        executable: false,
                    },
                    resident: PageSpan::new(fault, 4096),
                    backing: BackingIdentity {
                        frame_id: nz(1),
                        mapping_id: nz(2),
                        owner_generation: nz(3),
                        inventory_revision: nz(4),
                    },
                },
                tables: TableGrants::NONE,
            }
        }

        fn dispatch(
            mm: u64,
            spaces: &AddressSpaces,
            slots: &carrick_el1_abi::DescriptorTxnSlots,
            applier: &mut ArenaApplier<'_>,
            fault: u64,
            counters: &Counters,
        ) -> Action {
            let task = CurrentTask::new();
            task.mm.key.store(mm, Ordering::Release);
            let mut frame = write_translation_fault(0, fault);
            dispatch_fault_with_descriptor_txns(
                &mut frame,
                counters,
                &[task],
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(spaces),
                Some(DescriptorTxnPath { slots, applier }),
                GrantMailboxes::own(&FrameGrantMailbox::new()),
                None::<PreparedFaultPath<'_, NoopPreparedResolver>>,
                &mut NoopCowResolver,
            )
        }

        #[test]
        fn submitted_grant_is_applied_by_its_mm_and_serves_the_faulting_retry() {
            let mm = 77;
            let arena = Arena::new();
            let fault = VA + 2 * 4096;
            let txn = grant_txn(mm, ROOT, fault);
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(1, &txn));
            let spaces = published_space(mm, ROOT | ASID);
            let mut applier = ArenaApplier::new(&arena);
            let counters = Counters::default();
            assert_eq!(
                dispatch(mm, &spaces, &slots, &mut applier, fault, &counters),
                Action::Served
            );
            assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
            // Invalid -> valid: no TLB held the old (invalid) leaves, so
            // nothing is invalidated.
            assert!(applier.invalidated.borrow().is_empty());
            for page in 0..4 {
                let expected = if VA + page * 4096 == fault {
                    El1PrivateLeafState::Resident
                } else {
                    El1PrivateLeafState::Prepared
                };
                assert_eq!(
                    el1_private_leaf_state(arena.leaf(VA + page * 4096)),
                    expected
                );
            }
            let receipt = slots.take_receipt(1, txn.id).expect("receipt for the host");
            let verified = txn.verify_receipt(&receipt).expect("authentic");
            assert_eq!(verified.resident(), PageSpan::new(fault, 4096));
        }

        #[test]
        fn another_mm_or_a_closed_gate_never_applies_a_submission() {
            let arena = Arena::new();
            let before = arena.image();
            let txn = grant_txn(77, ROOT, VA);
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let mut applier = ArenaApplier::new(&arena);
            // A different MM's fault takes the ordinary path.
            let other = published_space(78, ROOT | ASID);
            assert_eq!(
                dispatch(78, &other, &slots, &mut applier, VA, &Counters::default()),
                Action::Forward
            );
            // The right MM behind a closed (paused/retiring) gate leaves the
            // submission for the host boundary.
            let closed = AddressSpaces::new();
            closed.publish_closed(77, ROOT | ASID, ROOT | ASID).unwrap();
            assert_eq!(
                dispatch(77, &closed, &slots, &mut applier, VA, &Counters::default()),
                Action::Forward
            );
            assert_eq!(slots.submitted_for(77).count(), 1);
            assert_eq!(arena.image(), before);
            assert!(applier.invalidated.borrow().is_empty());
        }

        #[test]
        fn a_stale_root_submission_is_refused_without_a_store() {
            let mm = 77;
            let arena = Arena::new();
            let before = arena.image();
            // Built against a root this MM no longer publishes.
            let txn = grant_txn(mm, ROOT + 0x4000, VA);
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let mut applier = ArenaApplier::new(&arena);
            let spaces = published_space(mm, ROOT | ASID);
            assert_eq!(
                dispatch(mm, &spaces, &slots, &mut applier, VA, &Counters::default()),
                Action::Forward,
                "a refused transaction does not serve the fault"
            );
            assert_eq!(arena.image(), before);
            let receipt = slots.take_receipt(0, txn.id).unwrap();
            assert_eq!(
                receipt.outcome,
                DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot)
            );
            assert!(applier.invalidated.borrow().is_empty());
        }

        /// A resident writable page at `VA` and a fork arm for it.
        fn armable() -> (Arena, DescriptorTxn) {
            use carrick_mmu_core::aarch64::descriptor_txn::TerminalEdit;
            let arena = Arena::new();
            let idx = indices(VA);
            // Resident, writable, nG, EL1-private leaf.
            let leaf = (IPA & 0x0000_FFFF_FFFF_F000)
                | 0b11
                | (1 << 10)
                | (0b11 << 8)
                | (0b01 << 6)
                | (1 << 11)
                | (1 << 53)
                | (1 << 54)
                | (1 << 56)
                | (1 << 57);
            arena.words[1536 + idx[3]].store(leaf, Ordering::Relaxed);
            let txn = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: nz(77),
                    generation: nz(9),
                },
                root: SubstrateGpa(ROOT),
                op: DescriptorOp::Terminal {
                    span: PageSpan::new(VA, 4096),
                    edit: TerminalEdit::fork_arm(false, false, false, true, 0, 0),
                },
                tables: TableGrants::NONE,
            };
            (arena, txn)
        }

        fn writable(arena: &Arena) -> bool {
            carrick_mmu_core::aarch64::terminal_descriptor_permits_el0(
                arena.leaf(VA),
                LeafAccess::Write,
            )
        }

        fn task(mm: u64) -> CurrentTask {
            let task = CurrentTask::new();
            task.mm.key.store(mm, Ordering::Release);
            task
        }

        fn frame(esr: u64) -> TrapFrame {
            TrapFrame {
                esr,
                slot: 0,
                ..TrapFrame::default()
            }
        }

        const SVC: u64 = 0x15 << 26;

        #[test]
        fn a_served_syscall_drains_its_mms_arm_before_returning_to_el0() {
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(3, &txn));
            let spaces = published_space(77, ROOT | ASID);
            let mut applier = ArenaApplier::new(&arena);
            assert!(writable(&arena));
            assert_eq!(
                drain_before_el0(
                    &frame(SVC),
                    Action::Served,
                    &[task(77)],
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                    &slots,
                    &mut applier
                ),
                Action::Served
            );
            assert!(!writable(&arena), "the arm landed before EL0 resumes");
            assert_eq!(*applier.invalidated.borrow(), vec![ROOT | ASID]);
            assert!(slots.take_receipt(3, txn.id).is_some());
        }

        #[test]
        fn a_kicked_sibling_cannot_resume_el0_before_the_arm_lands() {
            // Kick: the sibling leaves for the host, arm applied on the way.
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let spaces = published_space(77, ROOT | ASID);
            let mut applier = ArenaApplier::new(&arena);
            assert_eq!(
                drain_before_el0(
                    &frame(0),
                    Action::Forward,
                    &[task(77)],
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                    &slots,
                    &mut applier
                ),
                Action::Forward
            );
            assert!(!writable(&arena));
            // Reschedule/timer interrupt served in EL1: drained before eret.
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let mut applier = ArenaApplier::new(&arena);
            assert_eq!(
                drain_before_el0(
                    &frame(0),
                    Action::Served,
                    &[task(77)],
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                    &slots,
                    &mut applier
                ),
                Action::Served
            );
            assert!(!writable(&arena));
            // A parked thread's idle exit is not a return to EL0.
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let mut applier = ArenaApplier::new(&arena);
            assert_eq!(
                drain_before_el0(
                    &frame(SVC),
                    Action::Idle,
                    &[task(77)],
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                    &slots,
                    &mut applier
                ),
                Action::Idle
            );
            assert!(writable(&arena));
        }

        /// A syscall EL1 already served (its effect taken: bytes read,
        /// written or consumed) that must leave through the host because
        /// the drain is blocked keeps its result only if the host is told
        /// it was served. Without `served_with_work` the host dispatches
        /// the call again from the frame, whose `x0` is now the result:
        /// the read's bytes are lost and the result is read as an fd.
        #[test]
        fn a_blocked_drain_marks_a_served_syscall_served_for_the_host() {
            let (_arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let closed = AddressSpaces::new();
            closed.publish_closed(77, ROOT | ASID, ROOT | ASID).unwrap();
            let mut applier = ArenaApplier::new(&_arena);
            let tasks = [task(77)];
            assert_eq!(
                drain_before_el0(
                    &frame(SVC),
                    Action::Served,
                    &tasks,
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&closed),
                    &slots,
                    &mut applier
                ),
                Action::ServedWithWork
            );
            assert_eq!(
                tasks[0].linux.served_word(),
                1,
                "the host must complete, not re-dispatch, the served call"
            );
        }

        #[test]
        fn a_blocked_drain_never_returns_to_el0_unarmed() {
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let closed = AddressSpaces::new();
            closed.publish_closed(77, ROOT | ASID, ROOT | ASID).unwrap();
            let mut applier = ArenaApplier::new(&arena);
            let tasks = [task(77)];
            assert_eq!(
                drain_before_el0(
                    &frame(SVC),
                    Action::Served,
                    &tasks,
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&closed),
                    &slots,
                    &mut applier
                ),
                Action::ServedWithWork,
                "a served syscall keeps its result and leaves through the host"
            );
            assert_eq!(
                drain_before_el0(
                    &frame(0),
                    Action::Served,
                    &tasks,
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&closed),
                    &slots,
                    &mut applier
                ),
                Action::Forward
            );
            let fault = (0x24 << 26) | 0x07;
            assert_eq!(
                drain_before_el0(
                    &frame(fault),
                    Action::Served,
                    &tasks,
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&closed),
                    &slots,
                    &mut applier
                ),
                Action::Forward
            );
            assert!(writable(&arena), "nothing applied behind a closed gate");
        }

        #[test]
        fn a_switched_in_thread_drains_only_its_own_mm() {
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            let other = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: nz(78),
                    generation: nz(1),
                },
                ..txn
            };
            assert!(slots.submit(1, &other));
            let spaces = AddressSpaces::new();
            for (mm, root) in [(77, ROOT), (78, ROOT)] {
                let index = spaces.publish_closed(mm, root | ASID, root | ASID).unwrap();
                spaces.open(index);
            }
            let mut applier = ArenaApplier::new(&arena);
            // The slot's task record names the switched-in thread (MM 77).
            assert_eq!(
                drain_before_el0(
                    &frame(SVC),
                    Action::Served,
                    &[task(77)],
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                    &slots,
                    &mut applier
                ),
                Action::Served
            );
            assert_eq!(
                slots.submitted_for(78).count(),
                1,
                "MM 78 waits for its own thread"
            );
            assert!(writable(&arena));
        }

        #[test]
        fn the_host_drain_applies_under_delegated_custody_only_for_its_mm() {
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(5, &txn));
            // The host holds the MM's pause: the gate is closed.
            let closed = AddressSpaces::new();
            closed.publish_closed(77, ROOT | ASID, ROOT | ASID).unwrap();
            let mut applier = ArenaApplier::new(&arena);
            let mut call = TrapFrame {
                esr: carrick_el1_abi::DESCRIPTOR_DRAIN_ESR,
                slot: 5,
                ..TrapFrame::default()
            };
            call.x[carrick_el1_abi::DESCRIPTOR_DRAIN_MM] = 78;
            call.x[carrick_el1_abi::DESCRIPTOR_DRAIN_TTBR0] = ROOT | ASID;
            serve_host_drain(
                &mut call,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&closed),
                &slots,
                &mut applier,
            );
            assert_eq!(call.x[0], 0, "another MM's call applies nothing");
            assert!(writable(&arena));
            call.x[carrick_el1_abi::DESCRIPTOR_DRAIN_MM] = 77;
            serve_host_drain(
                &mut call,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&closed),
                &slots,
                &mut applier,
            );
            assert_eq!(call.x[0], 1);
            assert!(!writable(&arena));
            let receipt = slots.take_receipt(5, txn.id).unwrap();
            assert!(txn.verify_receipt(&receipt).is_ok());
        }

        /// The host settles a receipt and may then retire or reuse the
        /// backing and tables the edit removed. The receipt must therefore
        /// be observable only after the ASID invalidation that makes the
        /// applied edit exclusive, never before it.
        #[test]
        fn a_receipt_is_published_only_after_its_asid_invalidation() {
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(3, &txn));
            let spaces = published_space(77, ROOT | ASID);
            let mut applier = ArenaApplier::new(&arena);
            drain_before_el0(
                &frame(SVC),
                Action::Served,
                &[task(77)],
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                &slots,
                &mut applier,
            );
            assert_eq!(*applier.invalidated.borrow(), vec![ROOT | ASID]);
            assert_eq!(
                *applier.receipt_visible_at_invalidation.borrow(),
                vec![false],
                "the host could settle the arm before its TLBI ran"
            );
            assert!(slots.take_receipt(3, txn.id).is_some());
        }

        /// Another EL1 editor claimed the host's submission and is still
        /// applying it (its TLBI has not run). The drain must not report
        /// the MM drained: the host would settle before that invalidation.
        #[test]
        fn a_drain_never_reports_drained_while_another_editor_is_applying() {
            let (_arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let spaces = published_space(77, ROOT | ASID);
            let index = spaces.find(77).unwrap();
            let other = spaces.try_begin_edit(index, 77, nz(9)).unwrap();
            let claimed = slots.slot(0).unwrap().claim_for_mm(77).unwrap();
            let mut applier = ArenaApplier::new(&_arena);
            let mut step = || {
                try_drain_mm_descriptor_txns(
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                    &slots,
                    77,
                    ROOT | ASID,
                    nz(1),
                    &mut applier,
                    false,
                )
            };
            assert_eq!(
                step(),
                None,
                "reported drained while the claim is unfinished"
            );
            // The other editor finishes: invalidation, then the receipt.
            let invalidated = core::cell::Cell::new(false);
            claimed.complete(
                DescriptorOutcome::RolledBack(DescriptorRefusal::Contended),
                || invalidated.set(true),
            );
            assert!(invalidated.get());
            assert_eq!(step(), Some(DrainOutcome::Drained(0)));
            drop(other);
            assert_eq!(
                drain_mm_descriptor_txns(
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                    &slots,
                    77,
                    ROOT | ASID,
                    nz(1),
                    &mut applier,
                    false
                ),
                DrainOutcome::Clean,
                "a published receipt is not in flight"
            );
        }

        /// The host prepares and submits one MM's transactions in
        /// generation order under that MM's mutation guard, but they sit in
        /// whichever vCPU slot was free. An async frame-grant `Prepare`
        /// left in a higher slot must still land before a later munmap
        /// retirement of the same range in a lower slot; applied in slot
        /// order, the grant would re-expose backing the host has retired.
        #[test]
        fn a_drain_applies_one_mms_submissions_in_generation_order() {
            use carrick_mmu_core::aarch64::descriptor_txn::TerminalEdit;
            use carrick_mmu_core::aarch64::{PtOp, TerminalRule};
            let mm = 77;
            let arena = Arena::new();
            let mut grant = grant_txn(mm, ROOT, VA);
            grant.id.generation = nz(4);
            let retire = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: nz(mm),
                    generation: nz(5),
                },
                root: SubstrateGpa(ROOT),
                op: DescriptorOp::Terminal {
                    span: PageSpan::new(VA, 4 * 4096),
                    edit: TerminalEdit {
                        rule: TerminalRule::pt(PtOp::Retire),
                        asid_scoped: true,
                        excluded_ipa: 0,
                        excluded_len: 0,
                        reclaim_budget: 0,
                    },
                },
                tables: TableGrants::NONE,
            };
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            // The faulting vCPU's slot is above the munmap caller's.
            assert!(slots.submit(6, &grant));
            assert!(slots.submit(2, &retire));
            let spaces = published_space(mm, ROOT | ASID);
            let mut applier = ArenaApplier::new(&arena);
            assert_eq!(
                drain_mm_descriptor_txns(
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                    &slots,
                    mm,
                    ROOT | ASID,
                    nz(1),
                    &mut applier,
                    false
                ),
                DrainOutcome::Drained(2)
            );
            for page in 0..4 {
                let state = el1_private_leaf_state(arena.leaf(VA + page * 4096));
                assert!(
                    !matches!(
                        state,
                        El1PrivateLeafState::Prepared | El1PrivateLeafState::Resident
                    ),
                    "page {page} still names the granted backing after its retirement: {state:?}"
                );
            }
            let grant_receipt = slots.take_receipt(6, grant.id).unwrap();
            assert!(matches!(
                grant_receipt.outcome,
                DescriptorOutcome::Applied(_)
            ));
            assert!(slots.take_receipt(2, retire.id).is_some());
        }

        struct Frames {
            source: Vec<u8>,
            destination: Vec<u8>,
        }

        impl CowCopyWindow for Frames {
            fn frames(
                &mut self,
                _grant: &carrick_mmu_core::aarch64::descriptor_txn::CowCopyGrant,
            ) -> Option<(&[u8], &mut [u8])> {
                Some((&self.source, &mut self.destination))
            }
        }

        #[test]
        fn the_guest_cow_copy_runs_only_under_the_grant_mms_open_editor() {
            use carrick_mmu_core::aarch64::descriptor_txn::{CowCopyError, CowCopyGrant};
            let (arena, _) = armable();
            let byte_len = arena.words.len() * 8;
            unsafe {
                carrick_mmu_core::aarch64::arm_existing_el1_fork_pages(
                    arena.words.as_ptr().cast_mut(),
                    ROOT,
                    byte_len,
                    VA,
                    4096,
                )
            }
            .unwrap();
            let words = unsafe {
                PrimaryTableWords::new(arena.words.as_ptr().cast_mut(), ROOT, byte_len, &NoBarrier)
            }
            .unwrap();
            let grant = CowCopyGrant {
                mm_key: nz(77),
                root: SubstrateGpa(ROOT),
                va: VA,
                old_ipa: SubstrateGpa(IPA),
                new_ipa: SubstrateGpa(0x009d_0000_0000),
                old_backing: BackingIdentity {
                    frame_id: nz(1),
                    mapping_id: nz(2),
                    owner_generation: nz(3),
                    inventory_revision: nz(4),
                },
                new_backing: BackingIdentity {
                    frame_id: nz(5),
                    mapping_id: nz(6),
                    owner_generation: nz(7),
                    inventory_revision: nz(8),
                },
            };
            let mut frames = Frames {
                source: (0..4096).map(|i| (i % 253) as u8).collect(),
                destination: vec![0; 4096],
            };
            // Behind a closed gate (host pause) nothing is copied.
            let closed = AddressSpaces::new();
            closed.publish_closed(77, ROOT | ASID, ROOT | ASID).unwrap();
            assert!(matches!(
                copy_granted_cow_page(
                    &words,
                    grant,
                    carrick_sched_core::spaces::notification::SpaceAccess::source_free(&closed),
                    nz(1),
                    &mut frames
                ),
                Err(CowCopyError::Refused(DescriptorRefusal::Contended))
            ));
            assert!(frames.destination.iter().all(|&b| b == 0));
            let spaces = published_space(77, ROOT | ASID);
            let copy = copy_granted_cow_page(
                &words,
                grant,
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
                nz(1),
                &mut frames,
            )
            .unwrap();
            assert_eq!(frames.destination, frames.source);
            assert_eq!(copy.grant(), grant);
        }
    }
}
