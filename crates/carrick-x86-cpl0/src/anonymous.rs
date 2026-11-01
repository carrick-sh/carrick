// CPL0 binding of the shared Linux anonymous reservation owner and native
// descriptor editor. Physical returns remain journaled for owner settlement.
use carrick_el1::memory::reservations::{X86Cpl0Zone, shared_x86_cpl0_guest};
use carrick_el1::memory::{AnonymousCall, AnonymousCallView};
use carrick_el1::memory::{X86AnonymousDecode, classify_anonymous_range};
use carrick_el1_abi::CurrentTask;
use carrick_guest_arch::{FrameGpa, GuestLen, RootGpa, UserRange, UserVa};
use carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords;
use carrick_personality_linux::dispatch::FamilyCompletion;
use carrick_personality_linux::entry::{CanonicalCall, SyscallResult};
use carrick_personality_linux::pending_anonymous::{
    DelegatedStep, PendingAnonymousVenue, PermissionStep, RetirementStep,
};
use carrick_x86_carrier::entry::InitialWords;
pub use carrick_x86_carrier::table_span::{
    admit_context, admit_tables, live_context, live_words, retire_context, working_tables,
};
use core::sync::atomic::Ordering;

pub(super) struct X86AnonymousVenue<'a> {
    frame: AnonymousCall,
    task: &'a CurrentTask,
}
impl<'a> X86AnonymousVenue<'a> {
    pub(super) fn new(
        call: &CanonicalCall,
        task: &'a CurrentTask,
        slot: u32,
        return_pc: u64,
    ) -> Option<Self> {
        let frame = crate::anonymous_call(*call, slot, UserVa::new(return_pc))?;
        Some(Self { frame, task })
    }
    fn editor(&self) -> Option<(&'static X86Cpl0Zone, X86AnonymousEditor)> {
        let mm = carrick_el1_abi::ReservationMm::new(self.task.mm.key.load(Ordering::Acquire))?;
        let words = live_words(mm)?;
        let zone_address = carrick_el1::isa::x86_kernel_layout().zone.raw();
        // SAFETY: boot retains the compact zone throughout this MM's execution.
        let zone = unsafe { &*(zone_address as *const X86Cpl0Zone) };
        Some((
            zone,
            X86AnonymousEditor {
                words,
                sequence: None,
            },
        ))
    }
}

impl PendingAnonymousVenue for X86AnonymousVenue<'_> {
    fn original_argument0(&self) -> u64 {
        self.frame.arguments()[0]
    }
    fn task_state(&self) -> Option<&carrick_personality_linux::abi::entry::LinuxTaskState> {
        Some(&self.task.linux)
    }
    fn delegated(&mut self) -> DelegatedStep {
        let Some((zone, mut editor)) = self.editor() else {
            return DelegatedStep::Forward;
        };
        let slot = self.frame.slot();
        let Some(binding) = carrick_el1::isa::x86::context::current_cpu_binding() else {
            return DelegatedStep::Forward;
        };
        // SAFETY: this CPU's binding retains its initialized atomic counters.
        let counters = unsafe { &*(binding.counters_address as *const carrick_el1_abi::Counters) };
        match carrick_el1::memory::serve_delegated_anonymous(
            &mut self.frame,
            counters,
            self.task,
            carrick_core::wait::space_access(zone, slot, initial_release),
            shared_x86_cpl0_guest(),
            &mut editor,
            None,
        ) {
            carrick_el1::memory::DelegatedAnonymous::Served => {
                DelegatedStep::Served(SyscallResult::new(self.frame.result().0 as i64))
            }
            carrick_el1::memory::DelegatedAnonymous::NotDelegated => DelegatedStep::NotDelegated,
            _ => DelegatedStep::Forward,
        }
    }
    fn park_prepared(&mut self) -> Option<FamilyCompletion> {
        None
    }
    fn permission(&mut self) -> PermissionStep {
        crate::refuse_anonymous_permission(&crate::CARRICK_CPL0_ANONYMOUS_HOOK_REFUSALS)
    }
    fn retirement(&mut self) -> RetirementStep {
        crate::refuse_anonymous_retirement(&crate::CARRICK_CPL0_ANONYMOUS_HOOK_REFUSALS)
    }
    fn install_result(&mut self, result: SyscallResult) {
        self.frame
            .set_result(carrick_guest_arch::NativeReturnWord(result.raw() as u64));
    }
}

struct X86AnonymousEditor {
    words: InitialWords,
    sequence: Option<carrick_el1::memory::AnonymousEditGeneration>,
}
impl X86AnonymousEditor {
    fn edit(
        &self,
        register: RootGpa,
        range: UserRange,
        operation: carrick_guest_arch::EditOperation,
    ) -> Result<(), carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
        use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
        use carrick_mmu_core::x86::descriptor_txn::DescriptorOutcome;
        let context = self.words.context.ok_or(DescriptorRefusal::StaleRoot)?;
        if context.root != register {
            return Err(DescriptorRefusal::StaleRoot);
        }
        // SAFETY: the shared anonymous entry holds the exact MM editor through
        // settlement and binds this operation generation before editing.
        // InitialWords retains its authenticated context.
        let generation = self
            .sequence
            .as_ref()
            .ok_or(DescriptorRefusal::BadEncoding)?;
        match carrick_el1::memory::edit_x86_anonymous(
            &self.words,
            context.root,
            context.mm.raw(),
            generation,
            range,
            operation,
        )? {
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
        self.sequence = carrick_el1::memory::AnonymousEditGeneration::reservation(sequence);
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
    fn bind_resident_edit(&mut self, generation: carrick_el1::memory::AnonymousEditGeneration) {
        self.sequence = Some(generation);
    }
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
    fn bind_resident_edit(&mut self, generation: carrick_el1::memory::AnonymousEditGeneration) {
        self.sequence = Some(generation);
    }
    fn retire_and_invalidate(
        &mut self,
        mm: carrick_el1_abi::ReservationMm,
        root: carrick_guest_arch::AddressSpaceRegister,
        va: carrick_guest_arch::UserVa,
        len: carrick_guest_arch::GuestLen,
    ) -> Result<(), carrick_mmu_core::aarch64::GuestRetirementError> {
        let root = root.raw();
        let va = va.raw();
        let len = len.raw();
        let Some(residency) = carrick_el1::isa::frame_grant_residency_guest()
            .begin_retire_overlapping(mm.raw(), va, len)
        else {
            return Err(carrick_mmu_core::aarch64::GuestRetirementError::ResidencyBusy);
        };
        self.edit(
            RootGpa::page_aligned(FrameGpa::new(root))
                .ok_or(carrick_mmu_core::aarch64::GuestRetirementError::NotPrivateAnonymous)?,
            UserRange::checked(UserVa::new(va), GuestLen::new(len))
                .ok_or(carrick_mmu_core::aarch64::GuestRetirementError::NotPrivateAnonymous)?,
            carrick_guest_arch::EditOperation::Unmap,
        )
        .map_err(|_| carrick_mmu_core::aarch64::GuestRetirementError::NotPrivateAnonymous)?;
        if !residency.commit() {
            return Err(carrick_mmu_core::aarch64::GuestRetirementError::RollbackFailed);
        }
        Ok(())
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
    carrick_x86_carrier::entry::fatal_boot()
}
