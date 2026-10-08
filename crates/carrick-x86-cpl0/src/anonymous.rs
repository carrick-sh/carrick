// CPL0 binding of the shared Linux anonymous reservation owner and native
// descriptor editor. Physical returns remain journaled for owner settlement.
use super::InitialWords;
use carrick_el1::memory::reservations::{X86Cpl0Zone, shared_x86_cpl0_guest};
use carrick_el1::memory::{X86AnonymousDecode, classify_anonymous_range};
use carrick_el1_abi::{CurrentTask, TrapFrame};
use carrick_guest_arch::{FrameGpa, GuestLen, RootGpa, UserRange, UserVa};
use carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords;
use carrick_personality_linux::dispatch::FamilyCompletion;
use carrick_personality_linux::entry::{CanonicalCall, SyscallResult};
use carrick_personality_linux::pending_anonymous::{
    DelegatedStep, PendingAnonymousVenue, PermissionStep, RetirementStep,
};
use carrick_sched_core::SlotId;
use core::sync::atomic::{AtomicU64, Ordering};

static TABLE_START: AtomicU64 = AtomicU64::new(0);
static TABLE_END: AtomicU64 = AtomicU64::new(0);

static LIVE_CONTEXTS: carrick_el1::lock::SpinLock<
    carrick_el1::isa::x86::live_context::LiveContexts,
> = carrick_el1::lock::SpinLock::new(carrick_el1::isa::x86::live_context::LiveContexts::new());
pub(super) fn live_words(mm: carrick_el1_abi::ReservationMm) -> Option<InitialWords> {
    let root = carrick_el1::isa::x86::hardware_live_root().ok()?;
    let mm = carrick_guest_arch::MmGeneration::new(core::num::NonZeroU64::new(mm.raw())?);
    let context = LIVE_CONTEXTS.lock().authenticate(mm, root)?;
    let end = TABLE_END.load(Ordering::Acquire);
    let start = TABLE_START.load(Ordering::Relaxed);
    (start != 0 && end > start).then(|| InitialWords::live(start, end, context))
}

pub(super) fn admit_tables(
    start: u64,
    end: u64,
    context: carrick_guest_arch::AddressContext<RootGpa>,
) {
    if !LIVE_CONTEXTS.lock().admit(context) {
        fatal_reservation();
    }
    TABLE_START.store(start, Ordering::Relaxed);
    TABLE_END.store(end, Ordering::Release);
}

pub(super) struct X86AnonymousVenue<'a> {
    frame: TrapFrame,
    task: &'a CurrentTask,
}
impl<'a> X86AnonymousVenue<'a> {
    pub(super) fn new(
        call: &CanonicalCall,
        task: &'a CurrentTask,
        slot: u32,
        return_pc: u64,
    ) -> Self {
        let mut frame = TrapFrame {
            slot: u64::from(slot),
            elr: return_pc,
            ..Default::default()
        };
        frame.x[..6].copy_from_slice(&call.args);
        frame.x[8] = call.canonical.raw();
        Self { frame, task }
    }
}

impl PendingAnonymousVenue for X86AnonymousVenue<'_> {
    fn original_argument0(&self) -> u64 {
        self.frame.x[0]
    }
    fn task_state(&self) -> Option<&carrick_personality_linux::abi::entry::LinuxTaskState> {
        Some(&self.task.linux)
    }
    fn delegated(&mut self) -> DelegatedStep {
        let Some(mm) =
            carrick_el1_abi::ReservationMm::new(self.task.mm.key.load(Ordering::Acquire))
        else {
            return DelegatedStep::Forward;
        };
        let Some(words) = live_words(mm) else {
            return DelegatedStep::Forward;
        };
        let zone_address = carrick_el1::isa::x86_kernel_layout().zone.raw();
        // SAFETY: boot retains the compact zone throughout this MM's execution.
        let zone = unsafe { &*(zone_address as *const X86Cpl0Zone) };
        let Some(slot) = SlotId::from_index(self.frame.slot as usize) else {
            return DelegatedStep::Forward;
        };
        let Some(binding) = carrick_el1::isa::x86::context::current_cpu_binding() else {
            return DelegatedStep::Forward;
        };
        // SAFETY: this CPU's binding retains its initialized atomic counters.
        let counters = unsafe { &*(binding.counters_address as *const carrick_el1_abi::Counters) };
        let mut editor = X86AnonymousEditor {
            words,
            sequence: None,
        };
        match carrick_el1::memory::serve_delegated_anonymous(
            &mut self.frame,
            counters,
            self.task,
            carrick_core::wait::space_access(zone, slot, initial_release),
            shared_x86_cpl0_guest(),
            &mut editor,
        ) {
            carrick_el1::memory::DelegatedAnonymous::Served => {
                DelegatedStep::Served(SyscallResult::new(self.frame.x[0] as i64))
            }
            carrick_el1::memory::DelegatedAnonymous::NotDelegated => DelegatedStep::NotDelegated,
            _ => DelegatedStep::Forward,
        }
    }
    fn park_prepared(&mut self) -> Option<FamilyCompletion> {
        None
    }
    fn permission(&mut self) -> PermissionStep {
        PermissionStep::Forward
    }
    fn retirement(&mut self) -> RetirementStep {
        RetirementStep::Forward
    }
    fn install_result(&mut self, result: SyscallResult) {
        self.frame.x[0] = result.raw() as u64;
    }
}

struct X86AnonymousEditor {
    words: InitialWords,
    sequence: Option<carrick_el1_abi::ReservationSequence>,
}
impl X86AnonymousEditor {
    fn edit(
        &self,
        register: RootGpa,
        range: UserRange,
        operation: carrick_guest_arch::EditOperation,
    ) -> Result<(), carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
        use carrick_guest_arch::{EditIntent, EditOwner};
        use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
        use carrick_mmu_core::x86::descriptor_txn::{
            DescriptorOutcome, DescriptorTxn, InlineJournal, execute_descriptor_txn,
        };
        let context = self.words.context.ok_or(DescriptorRefusal::StaleRoot)?;
        if context.root != register {
            return Err(DescriptorRefusal::StaleRoot);
        }
        // SAFETY: serve_delegated_anonymous holds the exact MM editor and root
        // across this operation; InitialWords retains its authenticated context.
        let sequence = self
            .sequence
            .and_then(|sequence| core::num::NonZeroU64::new(sequence.raw()))
            .ok_or(DescriptorRefusal::BadEncoding)?;
        let owner = unsafe { EditOwner::issue(context.root, context.mm.raw(), sequence) };
        let intent =
            EditIntent::checked(owner, range, operation, &[]).ok_or(DescriptorRefusal::BadRange)?;
        let txn = DescriptorTxn::from_intent(&intent)?;
        match execute_descriptor_txn(&self.words, &txn, context.root, &mut InlineJournal::new())
            .outcome
        {
            DescriptorOutcome::Applied { .. } => Ok(()),
            DescriptorOutcome::Refused(reason) | DescriptorOutcome::RolledBack(reason) => {
                Err(reason)
            }
            DescriptorOutcome::Indeterminate(_) => fatal_reservation(),
        }
    }
}
impl carrick_el1::memory::AnonymousBackingProbe for X86AnonymousEditor {
    fn bind_operation(&mut self, sequence: carrick_el1_abi::ReservationSequence) {
        self.sequence = Some(sequence);
    }
    fn backing(
        &mut self,
        root: carrick_guest_arch::AddressSpaceRegister,
        va: carrick_guest_arch::UserVa,
        len: carrick_guest_arch::GuestLen,
    ) -> carrick_el1::memory::Stage1Backing {
        let root = root.raw();
        let va = va.raw();
        let len = len.raw();
        classify_anonymous_range::<X86AnonymousDecode>(
            &|pa| self.words.load(pa).ok(),
            root,
            va,
            len,
        )
    }
    fn stock_span(
        &mut self,
        mm: carrick_el1_abi::ReservationMm,
        va: carrick_guest_arch::UserVa,
    ) -> Option<carrick_guest_arch::UserRange> {
        let mm = mm.raw();
        let va = va.raw();
        let page = carrick_el1::isa::frame_grant_residency_guest().lookup(mm, va)?;
        UserRange::checked(
            UserVa::new(page.identity.semantic_base),
            GuestLen::new(page.identity.len),
        )
    }
}
impl carrick_el1::memory::AnonymousPermissionEditor for X86AnonymousEditor {
    fn protect_and_invalidate(
        &mut self,
        root: carrick_guest_arch::AddressSpaceRegister,
        edit: carrick_mmu_core::aarch64::GuestPermissionEdit,
    ) -> Result<(), carrick_mmu_core::aarch64::GuestPermissionEditError> {
        let root = root.raw();
        self.edit(
            RootGpa::page_aligned(FrameGpa::new(root))
                .ok_or(carrick_mmu_core::aarch64::GuestPermissionEditError::NotPrivateAnonymous)?,
            UserRange::checked(UserVa::new(edit.va), GuestLen::new(edit.len))
                .ok_or(carrick_mmu_core::aarch64::GuestPermissionEditError::NotPrivateAnonymous)?,
            carrick_guest_arch::EditOperation::Protect {
                permissions: carrick_guest_arch::EditPermissions {
                    readable: edit.readable,
                    writable: edit.writable,
                    executable: edit.executable,
                    user: edit.readable || edit.writable || edit.executable,
                },
            },
        )
        .map_err(|_| carrick_mmu_core::aarch64::GuestPermissionEditError::NotPrivateAnonymous)
    }
}
impl carrick_el1::memory::AnonymousRetirementEditor for X86AnonymousEditor {
    fn retire_and_invalidate(
        &mut self,
        root: carrick_guest_arch::AddressSpaceRegister,
        va: carrick_guest_arch::UserVa,
        len: carrick_guest_arch::GuestLen,
    ) -> Result<(), carrick_mmu_core::aarch64::GuestRetirementError> {
        let root = root.raw();
        let va = va.raw();
        let len = len.raw();
        self.edit(
            RootGpa::page_aligned(FrameGpa::new(root))
                .ok_or(carrick_mmu_core::aarch64::GuestRetirementError::NotPrivateAnonymous)?,
            UserRange::checked(UserVa::new(va), GuestLen::new(len))
                .ok_or(carrick_mmu_core::aarch64::GuestRetirementError::NotPrivateAnonymous)?,
            carrick_guest_arch::EditOperation::Unmap,
        )
        .map_err(|_| carrick_mmu_core::aarch64::GuestRetirementError::NotPrivateAnonymous)
    }
}

pub(super) fn initial_release(
    _: &X86Cpl0Zone,
    _: carrick_sched_core::Waker,
    owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
        '_,
        carrick_sched_core::ParkedContextWords,
    >,
) {
    let mut handed = false;
    let (_, effects) = owned.deliver_handbacks(&mut |_| handed = true);
    if handed || effects != carrick_sched_core::WakeEffects::default() {
        fatal_reservation();
    }
}

fn fatal_reservation() -> ! {
    super::initial_boot::fatal_boot()
}
