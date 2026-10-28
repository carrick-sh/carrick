//! Linux binding of the neutral EL1 fault path: the COW resolvers that
//! reconcile a parent write with this personality's pending fork custody,
//! and the ARM data-abort entry that selects them.
#[cfg(target_os = "none")]
use carrick_el1::fault::*;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
extern crate alloc;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use carrick_el1_abi::CurrentTask;
use carrick_el1_abi::{Action, Counters, TrapFrame};
use core::sync::atomic::Ordering;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub struct HardwareCowResolver {
    pub service_slot: Option<carrick_el1_abi::SlotId>,
    pub completion: Option<carrick_el1_abi::CowGrantCompletion>,
    pub publication: Option<&'static carrick_core_abi::PortalExecutableSlot>,
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl CowResolver for HardwareCowResolver {
    fn reconcile_parent_write<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        &mut self,
        slot: u32,
        handle: carrick_el1_abi::El1MmHandle,
        sequence: core::num::NonZeroU64,
        completion: carrick_el1_abi::CowGrantCompletion,
        words: &W,
    ) -> Result<(), crate::mm_portal::MmError> {
        crate::mm_portal::reconcile_pending_parent_write(
            slot as usize,
            handle,
            sequence,
            completion,
            words,
        )?;
        Ok(())
    }

    fn take_cow_completion(&mut self) -> Option<carrick_el1_abi::CowGrantCompletion> {
        self.completion.take()
    }
    fn executable_publication(&self) -> bool {
        self.publication.is_some()
    }
    fn resolve_cow(&mut self, ttbr0: u64, mm_key: u64, far: u64) -> bool {
        self.resolve_cow_outcome(ttbr0, mm_key, far) == CowResolution::Resolved
    }
    fn resolve_cow_outcome(&mut self, ttbr0: u64, mm_key: u64, far: u64) -> CowResolution {
        let outcome =
            with_hardware_cow_venue(ttbr0, self.service_slot, self.publication, |venue| {
                carrick_el1::cow::resolve_guest_cow(
                    venue,
                    mm_key,
                    far,
                    |source, destination| {
                        // SAFETY: both aliases are mapped, distinct pages (source
                        // EL1-RO, destination EL1-RW) until the window restores them.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                source as *const u8,
                                destination as *mut u8,
                                4096,
                            )
                        }
                    },
                    || {
                        let mut cpu = carrick_el1::substrate::sched::HardwareCpu;
                        carrick_el1::substrate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
                    },
                )
            });
        let Ok(outcome) = outcome else {
            return CowResolution::Refused;
        };
        handle_cow_outcome(outcome, &mut self.completion)
    }

    fn editor_busy(&mut self) {
        #[cfg(target_arch = "aarch64")]
        carrick_el1_abi::cow_grant_pool_guest()
            .note_declined(carrick_el1_abi::CowDecline::EditorBusy);
    }
}

/// CPL0 adapter for the same guest COW policy. The normal image uses the
/// shared pool and residency table; KVM fixtures can supply exact local
/// records while exercising the production resolver.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub struct X86CowResolver<'a, W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords> {
    pub words: &'a W,
    pub pool: &'a dyn carrick_el1_abi::CowGrantVenue,
    pub residency: &'a carrick_el1_abi::FrameGrantResidencyTable,
    pub completion: Option<carrick_el1_abi::CowGrantCompletion>,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<D: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords> CowResolver
    for X86CowResolver<'_, D>
{
    fn reconcile_parent_write<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        &mut self,
        slot: u32,
        handle: carrick_el1_abi::El1MmHandle,
        sequence: core::num::NonZeroU64,
        completion: carrick_el1_abi::CowGrantCompletion,
        words: &W,
    ) -> Result<(), crate::mm_portal::MmError> {
        crate::mm_portal::reconcile_pending_parent_write(
            slot as usize,
            handle,
            sequence,
            completion,
            words,
        )
    }

    fn resolve_cow(&mut self, root: u64, mm_key: u64, far: u64) -> bool {
        self.resolve_cow_outcome(root, mm_key, far) == CowResolution::Resolved
    }

    fn resolve_cow_outcome(&mut self, root: u64, mm_key: u64, far: u64) -> CowResolution {
        let copy_page = |source: u64, destination: u64| {
            // SAFETY: the x86 adapter verified both retained supervisor
            // translations for these distinct page frames.
            unsafe {
                core::ptr::copy_nonoverlapping(source as *const u8, destination as *mut u8, 4096)
            }
        };
        // A stale writable TLB entry can make a permission fault
        // retryable even when the live leaf is already writable.
        let invalidate = || carrick_el1::fault::invalidate_local_page(far);
        let venue = carrick_core::mm::cow::GuestCowVenue::<carrick_el1::cow::X86CowMmu, _> {
            words: self.words,
            root: carrick_mmu_core::aarch64::SubstrateGpa(root),
            pool: self.pool,
            residency: self.residency,
            copy_window: carrick_core::mm::cow::CowCopyWindow::target(
                self.words,
                carrick_mmu_core::aarch64::SubstrateGpa(root),
            ),
            publish_executable: None,
        };
        // SAFETY: dispatch_classified_fault holds this MM's exact editor.
        // resolve_x86_guest_cow authenticates the live CR3 and retained
        // supplied descriptor-word authority before reading or changing descriptors.
        let outcome = unsafe {
            carrick_el1::cow::resolve_x86_guest_cow(&venue, mm_key, far, copy_page, invalidate)
        };
        handle_cow_outcome(outcome, &mut self.completion)
    }

    fn take_cow_completion(&mut self) -> Option<carrick_el1_abi::CowGrantCompletion> {
        self.completion.take()
    }

    fn editor_busy(&mut self) {
        self.pool
            .note_declined(carrick_el1_abi::CowDecline::EditorBusy);
    }
}

/// Born-in-zone threads select from the MM owner instead of the legacy host
/// grant mailbox; host-born siblings retain the mailbox request path for
/// uncontended first touch while attaching the admitted MM owner so
/// reservation/editor/gate contention waits on the owner's publication.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(crate) fn native_fault_supply<'a>(
    native: bool,
    mailboxes: carrick_el1::fault::GrantMailboxes<'a>,
    owner: &'a carrick_el1::fault::OwnerFaultSupply<'a>,
) -> carrick_el1::fault::FaultSupply<'a> {
    if native {
        carrick_el1::fault::FaultSupply::Owner(owner)
    } else {
        mailboxes.with_owner(owner)
    }
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(crate) fn admitted_fault_mm_handle(
    zone: &carrick_el1_abi::ZoneTables,
    roots: &carrick_el1::memory::reservations::SharedReservations,
    carrier: core::num::NonZeroU64,
    slot: carrick_sched_core::SlotId,
    task: &carrick_el1_abi::CurrentTask,
) -> Option<carrick_el1_abi::El1MmHandle> {
    if let Some(record) = zone
        .slot(slot)
        .current()
        .filter(|record| zone.record(*record).is_native_owned())
        && let Some((_, control)) = task.lifecycle_refs()
        && let Ok(handle) = control.service.bound_mm(
            zone.record_ref(record),
            carrick_el1_abi::EntryThreadGeneration::from_raw(zone.record(record).identity().serial),
        )
    {
        return Some(handle);
    }
    let mm = carrick_el1_abi::ReservationMm::new(task.mm.key.load(Ordering::Acquire))?;
    crate::aarch64_process::Portal::for_zone(carrier, roots, zone)
        .admitted_handle(mm, u32::from(slot.raw()))
        .ok()
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn park_fault_owner_wait<C: crate::sched::ThreadCpu, U: crate::sched::UserWord>(
    zone: &carrick_el1_abi::ZoneTables,
    task: &carrick_el1_abi::CurrentTask,
    counters: &Counters,
    slot: carrick_sched_core::SlotId,
    cpu: &mut C,
    user: &U,
    frame: &mut TrapFrame,
    wait: carrick_el1_abi::PortalOwnerWait,
) -> Option<Action> {
    use carrick_sched_core::object_wait::{ObjectWaitError, OperationToken};
    let enrollment =
        carrick_core_abi::wait::PortalWaitEnrollment::for_owner(zone, wait.handle(), wait).ok()?;
    let resume = carrick_el1::substrate::sched::object_wait::OperationResumePc::new(frame.elr)?;
    let operation = OperationToken::metadata_request(wait.revision().max(1))?;
    let mut handoff = None;
    let mut sched_zone = crate::dispatch::Zone {
        tables: zone,
        cpu,
        user,
    };
    let mut sched =
        crate::dispatch::native_scheduler(&mut sched_zone, task, counters, slot, &mut handoff);
    match sched.park_object(
        frame,
        enrollment.key(),
        enrollment.observed_snapshot(),
        resume,
        operation,
        None,
    ) {
        Ok(parked) => {
            let served = if sched.task.linux.has_pending_host_work() {
                sched.leave_after_object_park(parked)
            } else {
                sched.resume_after_object_park(frame, parked, 0)
            };
            Some(match served {
                Some(carrick_el1::substrate::sched::Served::Returned { .. }) => Action::Served,
                Some(carrick_el1::substrate::sched::Served::Idle) | None => Action::Idle,
            })
        }
        Err((ObjectWaitError::Changed, _)) => None,
        Err(_) => {
            crate::dispatch::invalid_completion(crate::dispatch::NativeInvariant::EntryBinding)
        }
    }
}

/// Dispatch an EL0 data abort at EL1.
///
/// Increments `counters.fault_taken`; at EL1, requests host-published bulk
/// frames, consumes refusals, or resolves in-guest COW faults.
/// Host builds retain the forward-only path.
pub fn dispatch_fault(
    frame: &mut TrapFrame,
    counters: &Counters,
    owner_wait: &mut Option<carrick_el1_abi::PortalOwnerWait>,
) -> Action {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let current_tasks = unsafe {
            &*(carrick_el1_abi::EL1_CURRENT_TASKS_BASE
                as *const [CurrentTask; carrick_el1_abi::EL1_STACK_SLOTS as usize])
        };
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
        let Some(mailbox) =
            carrick_el1_abi::frame_grant_mailbox_guest_for_slot(frame.slot as usize)
        else {
            counters.fault_taken.fetch_add(1, Ordering::Relaxed);
            return Action::Forward;
        };
        let portal = unsafe {
            &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots)
        };
        let roots = carrick_el1::memory::reservations::shared_guest();
        let slot = carrick_sched_core::SlotId::new(frame.slot as u8);
        let task = &current_tasks[frame.slot as usize];
        let native = zone
            .slot(slot)
            .current()
            .is_some_and(|record| zone.record(record).is_native_owned());
        let handle = portal
            .carrier()
            .and_then(|carrier| admitted_fault_mm_handle(zone, roots, carrier, slot, task));
        let mailboxes = carrick_el1::fault::GrantMailboxes {
            own: mailbox,
            peers: Some(carrick_el1_abi::frame_grant_mailboxes_guest()),
        };
        loop {
            let supply = match handle {
                Some(handle) => OwnerFaultSupply::new(portal).with_handle(handle),
                None => OwnerFaultSupply::new(portal),
            };
            let action = dispatch_fault_with_descriptor_txns(
                frame,
                counters,
                current_tasks,
                carrick_el1::substrate::sched::object_wait::space_access(zone, slot),
                Some(DescriptorTxnPath {
                    slots: carrick_el1_abi::descriptor_txn_slots_guest(),
                    applier: &mut HardwareDescriptorTxnApplier,
                }),
                native_fault_supply(native, mailboxes, &supply),
                Some(PreparedFaultPath::<_> {
                    residency: carrick_el1::isa::frame_grant_residency_guest(),
                    resolver: &mut HardwarePreparedResolver,
                    roots: Some(roots),
                    file_slots: Some(portal),
                }),
                &mut HardwareCowResolver {
                    service_slot: None,
                    publication: None,
                    completion: None,
                },
            );
            if let OwnerFaultSupplyOutcome::Wait(wait) = supply.outcome() {
                if native {
                    *owner_wait = Some(wait);
                    return action;
                }
                if let Some(parked) = park_fault_owner_wait(
                    zone,
                    task,
                    counters,
                    slot,
                    &mut crate::sched::HardwareCpu,
                    &crate::sched::HardwareUserWord,
                    frame,
                    wait,
                ) {
                    return parked;
                }
                continue;
            }
            return action;
        }
    }
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        // CPL0 enters through `dispatch_x86_fault_with_prepared` with its
        // decoded #PF. This ARM TrapFrame entry has no x86 fault provenance.
        let _ = (frame, owner_wait);
        counters.fault_taken.fetch_add(1, Ordering::Relaxed);
        Action::Forward
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (frame, owner_wait);
        counters.fault_taken.fetch_add(1, Ordering::Relaxed);
        Action::Forward
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    #[test]
    fn test_dispatch_fault_increments_counter_and_forwards() {
        let mut frame = TrapFrame {
            esr: (0xFFFF_0000_u64 << 32) | (0x24 << 26) | (1 << 25) | 0x47,
            far: 0x1000_2000,
            x: {
                let mut x = [42; 31];
                x[8] = 172; // valid syscall nr (SYS_getpid) as canary
                x
            },
            ..TrapFrame::default()
        };
        let counters = Counters::default();
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 0);

        let action = dispatch_fault(&mut frame, &counters, &mut None);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
        // Ensure arbitrary x8 was not dispatched as a syscall and syscall counters were not touched
        assert_eq!(counters.forwarded[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.forwarded[42].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[42].load(Ordering::Relaxed), 0);
    }
}
