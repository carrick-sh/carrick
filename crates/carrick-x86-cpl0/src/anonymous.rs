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
        Some(Self {
            frame,
            task,
            source,
            saved,
            handoff: None,
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
    task: &'static CurrentTask,
) {
    if crate::test_support::post_supply_held() {
        return;
    }
    if crate::test_support::defer_release_to_peer(source.slot) {
        return;
    }
    // Either physical scheduler can arrive here. The synthetic holder may
    // release only after the actual waiter has published its park.
    if !crate::test_support::take_edit_park() {
        return;
    }
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
    if crate::test_support::take_caught_signal_on_park() {
        crate::native_process::inject_caught_signal_on_park(source, task);
    }
    // A holder's release names the MM it held, and this scheduler's task
    // may be another MM's member (#2332). Only an unkeyed holder, which
    // single-MM fixtures arm, falls back to this task's MM.
    let held = match cause {
        SpaceWaitCause::Editor => carrick_sched_core::spaces::injected_editor_busy_key(),
        _ => 0,
    };
    let mm = if held != 0 {
        held
    } else {
        task.mm.key.load(Ordering::Acquire)
    };
    let Some(notifications) = NonZeroU64::new(mm)
        .and_then(|mm| source.zone.space_entry(mm))
        .and_then(|entry| entry.live_notifications().ok())
    else {
        return;
    };
    let venue = carrick_sched_core::spaces::notification::SpaceReleaseVenue {
        zone: source.zone,
        waker: carrick_sched_core::Waker::El1 { slot: source.slot },
        deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Function(
            crate::native_process::release,
        ),
    };
    venue.publish(notifications.reserve(cause));
}

/// Release a held synthetic editor holder of its own MM: the Editor release
/// a real holder's drop publishes. Like that drop, it never waits for or
/// depends on its waiter: one that has not enrolled yet observes the
/// release and reruns (#2332).
#[cfg(feature = "test-support")]
pub(super) fn release_held_editor(source: BornInZoneSource<'static, ParkedContextWords>) -> bool {
    let mm = carrick_sched_core::spaces::injected_editor_busy_key();
    if !carrick_sched_core::spaces::release_injected_editor_hold() {
        return false;
    }
    let _ = crate::test_support::take_edit_park();
    let Some(notifications) = NonZeroU64::new(mm)
        .and_then(|mm| source.zone.space_entry(mm))
        .and_then(|entry| entry.live_notifications().ok())
    else {
        return false;
    };
    let venue = carrick_sched_core::spaces::notification::SpaceReleaseVenue {
        zone: source.zone,
        waker: carrick_sched_core::Waker::El1 { slot: source.slot },
        deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Function(
            crate::native_process::release,
        ),
    };
    venue.publish(notifications.reserve(SpaceWaitCause::Editor));
    true
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
        let staged = carrick_el1_linux::dispatch::stage_native_host_file(
            HostFileCall::MapPrivate(key),
            self.task,
            &carrick_el1_linux::file::HardwareValidator,
            &mut NativeNamespace {
                table,
                resolve: &mut resolve,
                releases: &mut releases,
            },
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
                // A parked edit's token outlives its wake; the replay owns it.
                #[cfg(feature = "test-support")]
                let refused = crate::test_support::take_replay_settlement_refusal();
                #[cfg(not(feature = "test-support"))]
                let refused = false;
                if refused
                    || carrick_core::wait::complete_anonymous_edit_replay(
                        self.source.zone,
                        slot,
                        self.task.mm.key.load(Ordering::Acquire),
                    )
                    .is_err()
                {
                    // The edit is already committed and the refusal is an
                    // ownership failure no errno repairs: fatal, as on ARM.
                    fatal_reservation();
                }
                DelegatedStep::Served(SyscallResult::new(self.frame.result().0 as i64))
            }
            carrick_el1::memory::DelegatedAnonymous::NotDelegated => DelegatedStep::NotDelegated,
            carrick_el1::memory::DelegatedAnonymous::Contended(cause) => {
                #[cfg(feature = "test-support")]
                crate::test_support::arm_metadata_for_reprobe();
                DelegatedStep::Contended(cause)
            }
            carrick_el1::memory::DelegatedAnonymous::Forward if file.is_some() => {
                DelegatedStep::Served(SyscallResult::from_errno(carrick_syscall_abi::LINUX_ENOSYS))
            }
            carrick_el1::memory::DelegatedAnonymous::Forward => DelegatedStep::Forward,
            carrick_el1::memory::DelegatedAnonymous::Settle(_) => DelegatedStep::Settle,
        }
    }
    fn park_prepared(&mut self) -> Option<FamilyCompletion> {
        None
    }
    fn park_contended(&mut self, _: SpaceWaitCause) -> Option<FamilyCompletion> {
        self.park_anonymous_edit(false)
    }
    fn park_settlement(&mut self) -> Option<FamilyCompletion> {
        // Every x86 MM is ring-owned: its owed returns settle only through
        // the carrier's doorbell.
        self.park_anonymous_edit(true)
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

impl X86AnonymousVenue<'_> {
    /// Park the unchanged call on its exact MM's release sources, or rerun
    /// it. With `settle`, the first probe rings the owed-return settlement
    /// doorbell after every source was observed (#1369 slice 3).
    fn park_anonymous_edit(&mut self, settle: bool) -> Option<FamilyCompletion> {
        use carrick_core::wait::{
            EditWaitOutcome, ObjectParkRequest, coordinate_anonymous_edit_wait,
            park_object_record_rechecked, space_access,
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
        // Take the retained operation only now that this call is an anonymous
        // edit: any other syscall's operation (a timed poll's park) stays on
        // its record for the call's own owner to resume.
        let resumed = zone
            .slot(slot)
            .current()
            .or_else(|| zone.slot(slot).host_record())
            .and_then(|record| {
                carrick_core::wait::take_object_operation(
                    zone,
                    slot,
                    zone.record(record).identity(),
                )
                .ok()
                .flatten()
            });
        let saved = self.saved;
        let task = self.task;
        let frame = &self.frame;
        let mut settle = settle;
        let mut holder = None;
        let outcome = coordinate_anonymous_edit_wait(
            &source,
            resumed,
            || {
                if core::mem::take(&mut settle) {
                    return carrick_el1::memory::drive_return_settlement(
                        task,
                        access,
                        table,
                        slot.index() as u32,
                        |record| {
                            carrick_x86_carrier::entry::cross_return_settlement(
                                carrick_guest_arch::CpuId::new(u32::from(slot.raw())),
                                record,
                            )
                        },
                    )
                    .edit_probe(&mut holder);
                }
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
                    ) => {
                        // An owed overlap with no settlement in flight
                        // reruns (behind the editor probe) and drives one.
                        if let Some(cause) = carrick_el1::memory::busy_root_cause(&root) {
                            return Some(Some(cause));
                        }
                    }
                    ReservationDisposition::Unavailable(
                        carrick_el1::memory::reservations::Refusal::MetadataRequired,
                    ) => {
                        if root
                            .provision_metadata(&carrick_el1::alloc::GLOBAL_ALLOCATOR)
                            .is_err()
                        {
                            return None;
                        }
                        return Some(None);
                    }
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
                let result = park_object_record_rechecked(
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
                    || {
                        SpaceWaitCause::ALL.into_iter().any(|cause| {
                            source.key(cause) == key && source.observe(cause) == snapshot.observed()
                        })
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
        // A full owed-return table that no holder could drain: wait on the
        // refusing holder's release instead of rerunning (#1482 P0-1).
        let outcome = match (outcome, holder) {
            (EditWaitOutcome::NoConflict, Some(wait)) => {
                carrick_core::wait::coordinate_holder_release_wait(
                    zone,
                    wait,
                    |key, snapshot, token, still_blocked| {
                        park_saved_context(zone, slot, saved, key, snapshot, token, still_blocked)
                    },
                )
            }
            (outcome, _) => outcome,
        };
        match outcome {
            EditWaitOutcome::Parked(mut parked) => {
                #[cfg(feature = "test-support")]
                crate::test_support::publish_edit_park();
                self.handoff = parked.take_receipt();
                Some(FamilyCompletion::AccountedSuspended)
            }
            EditWaitOutcome::NoConflict | EditWaitOutcome::StaleToken => {
                self.retry = true;
                Some(FamilyCompletion::AccountedComplete(0))
            }
            EditWaitOutcome::Refused => {
                #[cfg(feature = "test-support")]
                crate::test_support::record_anonymous_wait_handback();
                None
            }
        }
    }
}

struct X86AnonymousEditor {
    words: InitialWords,
    sequence: Option<carrick_el1::memory::AnonymousEditGeneration>,
}

/// Park the executing record's unchanged syscall context on `key` until its
/// release (a foreign holder's, #1482 P0-1). `still_blocked` rechecks the
/// observed revision under the queue guard; a refused park restores the
/// record's context.
fn park_saved_context<'z>(
    zone: &'z X86Cpl0Zone,
    slot: carrick_sched_core::SlotId,
    saved: ParkedContextWords,
    key: carrick_sched_core::object_wait::ObjectWaitKey,
    snapshot: carrick_sched_core::object_wait::ObjectStateSnapshot,
    token: carrick_sched_core::object_wait::OperationToken,
    still_blocked: &dyn Fn() -> bool,
) -> Result<
    carrick_core::wait::ObjectParked<'z, ParkedContextWords>,
    (
        ObjectWaitError,
        carrick_sched_core::object_wait::OperationToken,
    ),
> {
    let request =
        carrick_core::wait::ObjectParkRequest::from_locked_snapshot(key, snapshot, token, None);
    let mut replaced = None;
    let result = carrick_core::wait::park_object_record_rechecked(
        zone,
        slot,
        request,
        &|effects| {
            crate::native_process::release(zone, carrick_sched_core::Waker::El1 { slot }, effects)
        },
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
        still_blocked,
    );
    if result.is_err()
        && let Some((record, previous)) = replaced
    {
        // SAFETY: a failed park leaves the same current slot owning this record.
        *unsafe { zone.record(record).ctx_mut() } = previous;
    }
    result
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

/// What a user #PF that met MM contention does next (#2141).
pub(super) enum ContendedFault {
    /// Parked on the cause's release; the caller leaves for the scheduler.
    Parked,
    /// The contention ended before a park published: rerun the access.
    Rerun,
    /// No live MM source can carry the wait.
    Refused,
}

/// Park a user #PF refused by MM contention on that cause's release, through
/// the shared [`coordinate_fault_retry_wait`]. `context` is the faulting
/// instruction's saved user context, so the wake reruns the access. The fault
/// made no effects; the probe takes and drops root and editor custody only.
///
/// [`coordinate_fault_retry_wait`]: carrick_core::wait::coordinate_fault_retry_wait
pub(super) fn park_contended_fault(
    task: &CurrentTask,
    slot: carrick_sched_core::SlotId,
    cause: SpaceWaitCause,
    context: &ParkedContextWords,
) -> ContendedFault {
    use carrick_core::wait::{
        EditWaitOutcome, ObjectParkRequest, coordinate_fault_retry_wait,
        park_object_record_rechecked, space_access,
    };
    use carrick_sched_core::Waker;
    use carrick_sched_core::spaces::EditAdmissionRefusal;
    // The fault owner contends only on its root, editor and gate. The probe
    // below observes exactly these; any other cause would never re-probe.
    if !matches!(
        cause,
        SpaceWaitCause::Reservations | SpaceWaitCause::Editor | SpaceWaitCause::Gate
    ) {
        return ContendedFault::Refused;
    }
    let source = carrick_x86_carrier::native_execution::source(slot);
    let zone = source.zone;
    let Some(mm) = carrick_el1_abi::ReservationMm::new(task.mm.key.load(Ordering::Acquire)) else {
        return ContendedFault::Refused;
    };
    let Some(lease) = NonZeroU64::new(mm.raw())
        .and_then(|key| zone.space_entry(key))
        .and_then(|entry| entry.live_notifications().ok())
    else {
        return ContendedFault::Refused;
    };
    let table = shared_x86_cpl0_guest();
    let (Some(index), Some(owner)) = (
        zone.spaces.find(mm.raw()),
        NonZeroU64::new(slot.index() as u64 + 1),
    ) else {
        return ContendedFault::Refused;
    };
    if !table.admitted(index.index(), mm) {
        return ContendedFault::Refused;
    }
    let access = space_access(zone, slot, crate::native_process::release);
    let outcome = coordinate_fault_retry_wait(
        &lease,
        || {
            match table.lock_in(access, index.index(), mm, slot.index() as u32) {
                Ok(root) => drop(root),
                Err(carrick_el1::memory::reservations::Refusal::Busy) => {
                    return Some(Some(SpaceWaitCause::Reservations));
                }
                // Any other verdict is the fault's own: the rerun takes it.
                Err(_) => return Some(None),
            }
            match zone
                .spaces
                .try_begin_edit_cause(index, mm.raw(), owner, access.venue())
            {
                Ok(editor) => {
                    drop(editor);
                    Some(None)
                }
                Err(EditAdmissionRefusal::Editor) => Some(Some(SpaceWaitCause::Editor)),
                Err(EditAdmissionRefusal::Gate) => Some(Some(SpaceWaitCause::Gate)),
                Err(EditAdmissionRefusal::Stale) => None,
            }
        },
        |key, snapshot, token| {
            let request = ObjectParkRequest::from_locked_snapshot(key, snapshot, token, None);
            let mut replaced = None;
            let result = park_object_record_rechecked(
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
                    // SAFETY: the faulting slot owns its current record until
                    // the park publishes.
                    let saved = unsafe { zone.record(record).ctx_mut() };
                    replaced = Some((record, *saved));
                    *saved = *context;
                    Ok((record, false))
                },
                || {
                    SpaceWaitCause::ALL.into_iter().any(|cause| {
                        lease.key(cause) == key && lease.observe(cause) == snapshot.observed()
                    })
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
        EditWaitOutcome::Parked(_) => {
            #[cfg(feature = "test-support")]
            crate::test_support::publish_edit_park();
            ContendedFault::Parked
        }
        EditWaitOutcome::NoConflict | EditWaitOutcome::StaleToken => ContendedFault::Rerun,
        EditWaitOutcome::Refused => ContendedFault::Refused,
    }
}

fn fatal_reservation() -> ! {
    carrick_x86_carrier::entry::fatal_boot()
}
