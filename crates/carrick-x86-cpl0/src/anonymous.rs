// CPL0 binding of the shared Linux anonymous reservation owner and native
// descriptor editor. Physical returns remain journaled for owner settlement.
use carrick_el1::memory::reservations::{X86Cpl0Zone, shared_x86_cpl0_guest};
use carrick_el1::memory::{AnonymousCall, AnonymousCallView};
use carrick_el1::memory::{X86AnonymousDecode, classify_anonymous_range};
use carrick_el1_abi::BornInZoneSource;
use carrick_el1_abi::CurrentTask;
use carrick_guest_arch::{FrameGpa, GuestLen, RootGpa, UserRange, UserVa};
use carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords;
use carrick_personality_linux::dispatch::FamilyCompletion;
use carrick_personality_linux::entry::{CanonicalCall, SyscallResult};
use carrick_personality_linux::pending_anonymous::{
    DelegatedStep, PendingAnonymousVenue, PermissionStep, RetirementStep,
};
use carrick_sched_core::ParkedContextWords;
use carrick_sched_core::object_wait::ObjectWaitError;
use carrick_sched_core::spaces::notification::SpaceWaitCause;
use carrick_x86_carrier::entry::InitialWords;
pub use carrick_x86_carrier::table_span::{
    admit_context, admit_tables, live_context, live_words, retire_context, working_tables,
};
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

pub(super) struct X86AnonymousVenue<'a> {
    frame: AnonymousCall,
    task: &'a CurrentTask,
    source: BornInZoneSource<'static, ParkedContextWords>,
    saved: ParkedContextWords,
    handoff: Option<carrick_el1_abi::EntryHandoffReceipt<ParkedContextWords>>,
    resumed: Option<carrick_sched_core::object_wait::OperationToken>,
    retry: bool,
}
impl<'a> X86AnonymousVenue<'a> {
    pub(super) fn new(
        call: &CanonicalCall,
        task: &'a CurrentTask,
        slot: u32,
        return_pc: u64,
        source: BornInZoneSource<'static, ParkedContextWords>,
        saved: ParkedContextWords,
    ) -> Option<Self> {
        let frame = crate::anonymous_call(*call, slot, UserVa::new(return_pc))?;
        let resumed = source
            .zone
            .slot(source.slot)
            .current()
            .or_else(|| source.zone.slot(source.slot).host_record())
            .and_then(|record| {
                carrick_core::wait::take_object_operation(
                    source.zone,
                    source.slot,
                    source.zone.record(record).identity(),
                )
                .ok()
                .flatten()
            });
        Some(Self {
            frame,
            task,
            source,
            saved,
            handoff: None,
            resumed,
            retry: false,
        })
    }
    pub(super) fn take_retry(&mut self) -> bool {
        core::mem::take(&mut self.retry)
    }
    pub(super) fn original_syscall_number(&self) -> u64 {
        self.saved.syscall_return()
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

/// Test images release the synthetic edit holder only after the real
/// suspension has entered the scheduler, matching an external holder's edge.
#[cfg(feature = "test-support")]
pub(super) fn release_injected_edit_wait(
    source: BornInZoneSource<'static, ParkedContextWords>,
    task: &CurrentTask,
) {
    let cause = if carrick_core::mm::reservation::release_injected_root_busy() {
        Some(SpaceWaitCause::Reservations)
    } else if carrick_sched_core::spaces::release_injected_editor_busy() {
        Some(SpaceWaitCause::Editor)
    } else if carrick_core::mm::reservation::release_injected_prepared_conflict() {
        Some(SpaceWaitCause::PreparedOverlap)
    } else {
        None
    };
    let Some(cause) = cause else {
        return;
    };
    let mm = task.mm.key.load(Ordering::Acquire);
    let Some(notifications) = NonZeroU64::new(mm)
        .and_then(|mm| source.zone.space_entry(mm))
        .and_then(|entry| entry.live_notifications().ok())
    else {
        return;
    };
    fn release_while_scheduling(
        _: &X86Cpl0Zone,
        _: carrick_sched_core::Waker,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, ParkedContextWords>,
    ) {
        let _ = effects.deliver_handbacks(&mut |_| carrick_x86_carrier::entry::fatal_boot());
        // This CPU has already entered its scheduler because of the injected
        // suspension. The queued record needs no self-IPI to become visible.
    }
    let venue = carrick_sched_core::spaces::notification::SpaceReleaseVenue {
        zone: source.zone,
        waker: carrick_sched_core::Waker::El1 { slot: source.slot },
        deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Function(
            release_while_scheduling,
        ),
    };
    venue.publish(notifications.reserve(cause));
    if source.zone.slot(source.slot).queued() == 0 {
        carrick_x86_carrier::entry::fatal_boot();
    }
}

// MapPrivate stages no user bytes. Keep all validation and descriptor policy in
// the shared host-file staging owner, rather than a second mmap decoder.
struct MappingUser;
impl carrick_personality_linux::native_host_file::HostFileUser for MappingUser {
    fn copy_in(&mut self, _: &mut [u8], _: u64) -> bool {
        false
    }
    fn writable(&mut self, _: u64, _: usize) -> usize {
        0
    }
}

impl X86AnonymousVenue<'_> {
    fn source(
        &self,
        zone: &X86Cpl0Zone,
    ) -> Result<Option<carrick_el1_abi::HostBackingIdentity>, SyscallResult> {
        use carrick_personality_linux::native_host_file::{
            self, HostFileCall, HostFileStage, NativeMapKey, NativeNamespace,
        };
        let Some(HostFileCall::MapPrivate(key)) = HostFileCall::decode(
            carrick_syscall_abi::CanonicalNr::new(self.frame.canonical().raw()),
            &self.frame.arguments(),
        ) else {
            return Ok(None);
        };
        let slot = self.frame.slot();
        let venue = carrick_el1_linux::ipc::guest_venue(slot.index() as u32)
            .ok_or(SyscallResult::from_errno(carrick_syscall_abi::LINUX_ENOSYS))?;
        let table = carrick_el1_linux::ipc::native_table(&venue, self.task)
            .ok_or(SyscallResult::from_errno(carrick_syscall_abi::LINUX_ENOSYS))?;
        let mut resolve = |fd| carrick_el1_linux::ipc::native_descriptor(&venue, table, fd);
        let mut releases = |out: &mut [carrick_core_abi::host_file::MapSourceReply]| {
            let mut rows = [(core::num::NonZeroU64::MIN, core::num::NonZeroU64::MIN);
                carrick_core_abi::host_file::MAX_MAP_RELEASES];
            let limit = out.len().min(rows.len());
            let count = carrick_el1::memory::take_native_source_releases(
                self.task,
                carrick_core::wait::space_access(zone, slot, crate::native_process::release),
                shared_x86_cpl0_guest(),
                slot.index() as u32,
                &mut rows[..limit],
            );
            for (dst, (handle, generation)) in out.iter_mut().zip(&rows[..count]) {
                *dst = carrick_core_abi::host_file::MapSourceReply {
                    handle: *handle,
                    generation: *generation,
                };
            }
            count
        };
        let staged = native_host_file::stage(
            HostFileCall::MapPrivate(key),
            &mut NativeNamespace {
                table,
                resolve: &mut resolve,
                releases: &mut releases,
            },
            &mut MappingUser,
        );
        match staged {
            Some(HostFileStage::Request {
                record,
                map: Some(staged_key),
                ..
            }) if staged_key == NativeMapKey::of(&self.frame.arguments()) => {
                let frame = carrick_el1::isa::x86::context::native::NativeFrame {
                    rax: carrick_el1_abi::HostFileCrossing::NUMBER,
                    rcx: carrick_el1_abi::HostFileCrossing::FRAME_TAG,
                    rdi: record.as_ptr() as u64,
                    rsi: record.len() as u64,
                    ..Default::default()
                };
                carrick_x86_carrier::entry::forward_to_host(&frame);
                native_host_file::map_source(&record).map(|reply| {
                    Some(carrick_el1_abi::HostBackingIdentity::new(
                        reply.handle,
                        reply.generation,
                        0,
                    ))
                })
            }
            Some(HostFileStage::Returned(result)) => Err(result),
            _ => Err(SyscallResult::from_errno(carrick_syscall_abi::LINUX_ENOSYS)),
        }
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
        let file = match self.source(zone) {
            Ok(file) => file,
            Err(result) => return DelegatedStep::Served(result),
        };
        match carrick_el1::memory::serve_delegated_mapping(
            &mut self.frame,
            counters,
            self.task,
            carrick_core::wait::space_access(zone, slot, crate::native_process::release),
            shared_x86_cpl0_guest(),
            &mut editor,
            file,
        ) {
            carrick_el1::memory::DelegatedAnonymous::Served => {
                DelegatedStep::Served(SyscallResult::new(self.frame.result().0 as i64))
            }
            carrick_el1::memory::DelegatedAnonymous::NotDelegated => DelegatedStep::NotDelegated,
            carrick_el1::memory::DelegatedAnonymous::Contended(cause) => {
                DelegatedStep::Contended(cause)
            }
            carrick_el1::memory::DelegatedAnonymous::Forward if file.is_some() => {
                DelegatedStep::Served(SyscallResult::from_errno(carrick_syscall_abi::LINUX_ENOSYS))
            }
            _ => DelegatedStep::Forward,
        }
    }
    fn park_prepared(&mut self) -> Option<FamilyCompletion> {
        None
    }
    fn park_contended(&mut self, _: SpaceWaitCause) -> Option<FamilyCompletion> {
        use carrick_core::wait::{
            EditWaitOutcome, ObjectParkRequest, coordinate_anonymous_edit_wait, park_object_record,
            space_access,
        };
        use carrick_el1::memory::{ReservationDisposition, decide_reservation_syscall};
        use carrick_sched_core::Waker;
        let zone = self.source.zone;
        let slot = self.source.slot;
        let mm = carrick_el1_abi::ReservationMm::new(self.task.mm.key.load(Ordering::Acquire))?;
        let source = zone
            .space_entry(NonZeroU64::new(mm.raw())?)?
            .live_notifications()
            .ok()?;
        let table = shared_x86_cpl0_guest();
        if !table.admitted(zone.spaces.find(mm.raw())?.index(), mm) {
            return None;
        }
        let index = zone.spaces.find(mm.raw())?;
        let access = space_access(zone, slot, crate::native_process::release);
        let owner = NonZeroU64::new(slot.index() as u64 + 1)?;
        let resumed = self.resumed.take();
        let saved = self.saved;
        let task = self.task;
        let frame = &self.frame;
        let outcome = coordinate_anonymous_edit_wait(
            &source,
            resumed,
            || {
                let mut root = match table.lock_in(access, index.index(), mm, slot.index() as u32) {
                    Ok(root) => root,
                    Err(carrick_el1::memory::reservations::Refusal::Busy) => {
                        return Some(Some(SpaceWaitCause::Reservations));
                    }
                    Err(_) => return None,
                };
                match decide_reservation_syscall(frame, task, &mut root, None) {
                    ReservationDisposition::Unavailable(
                        carrick_el1::memory::reservations::Refusal::PreparedConflict,
                    ) => return Some(Some(SpaceWaitCause::PreparedOverlap)),
                    ReservationDisposition::Unavailable(
                        carrick_el1::memory::reservations::Refusal::Busy,
                    ) => return Some(Some(SpaceWaitCause::PendingEdit)),
                    ReservationDisposition::Unavailable(
                        carrick_el1::memory::reservations::Refusal::MetadataRequired,
                    ) => return None,
                    ReservationDisposition::Unavailable(_) => return None,
                    ReservationDisposition::Work(pending) => {
                        if pending.cancel(&mut root).is_err() {
                            return None;
                        }
                    }
                    ReservationDisposition::Return(_) | ReservationDisposition::Forward => {}
                }
                drop(root);
                match zone
                    .spaces
                    .try_begin_edit_cause(index, mm.raw(), owner, access.venue())
                {
                    Ok(editor) => {
                        drop(editor);
                        Some(None)
                    }
                    Err(carrick_sched_core::spaces::EditAdmissionRefusal::Editor) => {
                        Some(Some(SpaceWaitCause::Editor))
                    }
                    Err(carrick_sched_core::spaces::EditAdmissionRefusal::Gate) => {
                        Some(Some(SpaceWaitCause::Gate))
                    }
                    Err(carrick_sched_core::spaces::EditAdmissionRefusal::Stale) => None,
                }
            },
            |key, snapshot, token| {
                let request = ObjectParkRequest::from_locked_snapshot(key, snapshot, token, None);
                let mut replaced = None;
                let result = park_object_record(
                    zone,
                    slot,
                    request,
                    &|effects| crate::native_process::release(zone, Waker::El1 { slot }, effects),
                    || {
                        let record = zone
                            .slot(slot)
                            .current()
                            .or_else(|| zone.slot(slot).host_record())
                            .ok_or(ObjectWaitError::Stale)?;
                        // SAFETY: the executing slot owns its current record until the park publishes.
                        let context = unsafe { zone.record(record).ctx_mut() };
                        replaced = Some((record, *context));
                        *context = saved;
                        Ok((record, false))
                    },
                );
                if result.is_err()
                    && let Some((record, previous)) = replaced
                {
                    // SAFETY: a failed park leaves the same current slot owning this record.
                    *unsafe { zone.record(record).ctx_mut() } = previous;
                }
                result
            },
        );
        match outcome {
            EditWaitOutcome::Parked(mut parked) => {
                self.handoff = parked.take_receipt();
                Some(FamilyCompletion::AccountedSuspended)
            }
            EditWaitOutcome::NoConflict | EditWaitOutcome::StaleToken => {
                self.retry = true;
                Some(FamilyCompletion::AccountedComplete(0))
            }
            EditWaitOutcome::Refused => None,
        }
    }
    fn take_x86_handoff_receipt(
        &mut self,
    ) -> Option<carrick_core_abi::EntryHandoffReceipt<ParkedContextWords>> {
        self.handoff.take()
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

fn fatal_reservation() -> ! {
    carrick_x86_carrier::entry::fatal_boot()
}
