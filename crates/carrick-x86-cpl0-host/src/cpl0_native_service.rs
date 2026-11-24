//! Stopped CPL0 transport for shared retained native services.
use super::*;
use carrick_core_abi::service::{ServiceCell, ServiceOperation, ServiceTicket};
use carrick_guest_arch::KernelVa;
use carrick_sched_core::object_wait::ObjectWaitKey;

pub(in crate::cpl0_boot) struct Cpl0ServicePin {
    cell: core::ptr::NonNull<ServiceCell>,
    _ram: Arc<crate::guest_ram::GuestRam>,
}
// SAFETY: the pin names one aligned atomic service cell inside RAM this pin
// retains; a parked exec's ticket moves between stopped-host services only
// inside exclusive carrier custody, and the cell itself is shared state.
unsafe impl Send for Cpl0ServicePin {}
impl core::ops::Deref for Cpl0ServicePin {
    type Target = ServiceCell;
    fn deref(&self) -> &ServiceCell {
        // SAFETY: authenticated control storage remains retained by RAM custody.
        unsafe { self.cell.as_ref() }
    }
}

pub(in crate::cpl0_boot) struct PendingNativeHostFile {
    pub(in crate::cpl0_boot) ticket: ServiceTicket<Cpl0ServicePin>,
    execution: GrantExecution,
    key: ObjectWaitKey,
    address: KernelVa,
    pub(in crate::cpl0_boot) record: Vec<u8>,
}
/// A fork child's exec request, claimed and authenticated: the carrier's
/// loader runs on its staged payload with custody released, then
/// [`Cpl0HostCustody::finish_native_exec`] stages and seals the successor.
pub(in crate::cpl0_boot) struct PendingNativeExec {
    pub(in crate::cpl0_boot) ticket: ServiceTicket<Cpl0ServicePin>,
    pub(in crate::cpl0_boot) execution: GrantExecution,
    pub(in crate::cpl0_boot) key: ObjectWaitKey,
    /// The receipt the carrier's exec owner reserved for this request at
    /// claim; it names the row through any park until the seal reuses it.
    pub(in crate::cpl0_boot) receipt: carrick_core_abi::service::ExecAdoptionReceipt,
    /// The ring's proposed manifest, authenticated in retained storage.
    pub(in crate::cpl0_boot) manifest: KernelVa,
    pub(in crate::cpl0_boot) successor: carrick_el1_abi::ReservationMm,
    pub(in crate::cpl0_boot) root_generation: core::num::NonZeroU64,
    pub(in crate::cpl0_boot) payload: Vec<u8>,
}
pub(in crate::cpl0_boot) enum NativeNoticeStep {
    Settled,
    HostFile(Box<PendingNativeHostFile>),
    Exec(Box<PendingNativeExec>),
}

impl<M: CarrierMemoryIo> Cpl0HostCustody<M> {
    /// Retain queue handbacks through the existing completion chain and ring
    /// this stopped CPU's authenticated task doorbell. Native-service queues
    /// are legacy queues; host contention parks must not be enabled until the
    /// x86 boundary can drain its ParkedContextWords completion population.
    ///
    /// `sink` is this carrier's zone wake sink: the caller surfaces its
    /// [`carrick_sched_core::CarrierZoneWake::take_undelivered`] after the
    /// queue is released.
    pub(in crate::cpl0_boot) fn complete_object_wake(
        &self,
        stopped_cpu: carrick_guest_arch::CpuId,
        sink: &dyn carrick_sched_core::CarrierZoneWake<carrick_sched_core::ParkedContextWords>,
        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >,
    ) {
        // A stopped production lease names one of the carrier's two CPUs.
        let slot = SlotId::new(stopped_cpu.raw() as u8);
        let task = self.task(stopped_cpu);
        deliver_stopped_completion(sink, slot, owned, &|| task.linux.mark_pending_host_work());
    }

    /// Authenticate a retained supervisor span against this exact live root.
    /// The carrier owns the backing through the crossing; the outstanding
    /// service claim prevents retirement of the member/MM and payload.
    pub(in crate::cpl0_boot) fn native_service_pointer(
        &self,
        context: AddressContext<RootGpa>,
        address: KernelVa,
        len: usize,
        alignment: usize,
    ) -> Result<*mut u8, TrapError> {
        let end = address
            .raw()
            .checked_add(len as u64)
            .ok_or_else(|| fail("native service span overflow"))?;
        let physical = if address.raw() >= METADATA_VA
            && end <= METADATA_VA + META_LEN
            && address.raw().is_multiple_of(alignment as u64)
            && len != 0
        {
            FrameGpa::new(META_GPA + address.raw() - METADATA_VA)
        } else {
            kernel_pod_physical(&self.kernel_pod_storage, address, len, alignment)
                .ok_or_else(|| fail("native service outside retained supervisor storage"))?
        };
        let mut offset = 0;
        while offset < len {
            let va = address.raw() + offset as u64;
            let leaf = translate_leaf(
                &self._vm.words(),
                context.root,
                UserVa::new(va),
                Access::Write,
                false,
            )
            .map_err(|_| fail("native service supervisor translation"))?;
            if leaf.output.raw() != physical.raw() + offset as u64
                || leaf.descriptor & carrick_mmu_core::x86::descriptor_txn::USER != 0
                || leaf.descriptor & carrick_mmu_core::x86::descriptor_txn::WRITE == 0
                || !leaf.ancestors_writable
                || leaf.executable
            {
                return Err(fail("native service supervisor alias changed"));
            }
            offset += ((4096 - (va & 4095)) as usize).min(len - offset);
        }
        let pointer = self
            .ram
            .host_ptr(physical.raw(), len)
            .ok_or_else(|| fail("native service backing absent"))?;
        if !pointer.addr().is_multiple_of(alignment) {
            return Err(fail("native service host alignment"));
        }
        Ok(pointer)
    }

    fn claim_native_notice<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
    ) -> Result<(ServiceTicket<Cpl0ServicePin>, GrantExecution, ObjectWaitKey), TrapError> {
        let execution = self.physical_execution(lease)?;
        let selector = self
            .task(lease.cpu)
            .service_notice
            .take()
            .map_err(|_| fail("native service notice busy"))?
            .ok_or_else(|| fail("native service doorbell without notice"))?;
        let zone_pointer = self
            .ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("native service zone absent"))?;
        // SAFETY: boot initialized this aligned fixed zone; custody retains RAM.
        let zone = unsafe { &*zone_pointer.cast::<X86Cpl0Zone>() };
        let key = ObjectWaitKey::native_service(selector.record)
            .ok_or_else(|| fail("native service wait key"))?;
        let sink = self.carrier_zone_wake()?;
        let completion = |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| self.complete_object_wake(lease.cpu, &*sink, owned);
        let queue = zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &completion)
            .map_err(|_| fail("native service queue"))?;
        let member = queue
            .native_service_member(selector.record)
            .ok_or_else(|| {
                let home = zone.record(selector.record.id);
                fail(format!(
                    "native service member absent: record={:?} incarnation={} claim={:?} native={} resume={:?}",
                    selector.record, home.incarnation(), home.claim(), home.is_native_owned(), home.resume_disposition(),
                ))
            })?;
        if member.mm != execution.context.mm.raw().get()
            || member.generation != selector.execution.raw()
        {
            return Err(fail("native service stopped member/MM changed"));
        }
        drop(queue);
        let pointer = self.native_service_pointer(
            execution.context,
            KernelVa::new(member.control_slot),
            size_of::<ThreadControlSlot>(),
            align_of::<ThreadControlSlot>(),
        )?;
        // SAFETY: the complete aligned control is in authenticated retained
        // supervisor storage. Its atomic fields are revalidated under its queue.
        let control = unsafe { &*pointer.cast::<ThreadControlSlot>() };
        let queue = zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &completion)
            .map_err(|_| fail("native service claim queue"))?;
        if queue.native_service_member(selector.record) != Some(member)
            || control.zone_record() != Some(selector.record)
            || !control.native_signal_owner()
        {
            return Err(fail("native service control owner changed"));
        }
        // SAFETY: custody retains this exact control; its member is revalidated
        // under the queue. The ring's pending claim retains its admitted MM.
        let ticket = unsafe {
            ServiceCell::claim_notice(
                Cpl0ServicePin {
                    cell: core::ptr::NonNull::from(&control.service),
                    _ram: Arc::clone(&self.ram),
                },
                selector,
                self._vm.identity().nonzero(),
                member,
            )
        }
        .map_err(|_| fail("native service ticket claim"))?;
        drop(queue);
        if sink.take_undelivered().is_some() {
            return Err(fail("native service claim reschedule not delivered"));
        }
        Ok((ticket, execution, key))
    }

    pub(in crate::cpl0_boot) fn service_native_notice<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        file: Option<anonymous_owner::FileSupply>,
        native_entropy: NativeEntropyService,
    ) -> Result<NativeNoticeStep, TrapError> {
        let (mut ticket, execution, key) = self.claim_native_notice(lease)?;
        let zone_pointer = self
            .ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("native service zone absent"))?;
        // SAFETY: boot initializes this fixed aligned region, retained by custody.
        let zone = unsafe { &*zone_pointer.cast::<X86Cpl0Zone>() };
        let mut owner_wait = None;
        let supplied = match ticket.request().operation {
            ServiceOperation::HostFile { payload, .. } => {
                let address = payload.ring_storage();
                let pointer = self.native_service_pointer(
                    execution.context,
                    address,
                    payload.length().raw() as usize,
                    1,
                )?;
                // SAFETY: the outstanding ticket retains the authenticated staging box.
                let mut record =
                    unsafe { std::slice::from_raw_parts(pointer, payload.length().raw() as usize) }
                        .to_vec();
                let view = carrick_core_abi::host_file::HostFileRequestView::parse(&mut record)
                    .map_err(|_| fail("invalid CPL0 host file record"))?;
                if matches!(
                    view.header().op,
                    carrick_core_abi::host_file::HostFileOp::MapPrivate
                        | carrick_core_abi::host_file::HostFileOp::MapShared
                ) {
                    return Err(fail("CPL0 file mapping uses HostFileCrossing"));
                }
                return Ok(NativeNoticeStep::HostFile(Box::new(
                    PendingNativeHostFile {
                        ticket,
                        execution,
                        key,
                        address,
                        record,
                    },
                )));
            }
            ServiceOperation::Exec { payload, .. } => {
                let pointer = self.native_service_pointer(
                    execution.context,
                    KernelVa::new(payload.address().raw()),
                    payload.length().raw() as usize,
                    1,
                )?;
                // SAFETY: the outstanding ticket retains the ring's staged
                // exec payload until its acknowledgment.
                let bytes =
                    unsafe { std::slice::from_raw_parts(pointer, payload.length().raw() as usize) }
                        .to_vec();
                let manifest = ticket
                    .reply_address()
                    .ok_or_else(|| fail("native exec without a manifest reply"))?;
                let reply = self.native_service_pointer(
                    execution.context,
                    manifest,
                    size_of::<carrick_core_abi::service::ExecSuccessorManifest>(),
                    align_of::<carrick_core_abi::service::ExecSuccessorManifest>(),
                )?;
                // SAFETY: the ticket retains the ring's aligned proposal box;
                // the ring writes it before publication and only reads it
                // again after this ticket's acknowledgment.
                let proposed =
                    unsafe { *reply.cast::<carrick_core_abi::service::ExecSuccessorManifest>() };
                let (successor, root_generation) = proposed
                    .proposal(ticket.request().identity)
                    .ok_or_else(|| fail("native exec manifest proposal"))?;
                let receipt = self
                    .exec_owner
                    .claim(ticket.request().identity, successor, root_generation)
                    .map_err(|error| fail(format!("native exec claim: {error:?}")))?
                    .receipt();
                return Ok(NativeNoticeStep::Exec(Box::new(PendingNativeExec {
                    ticket,
                    execution,
                    key,
                    receipt,
                    manifest,
                    successor,
                    root_generation,
                    payload: bytes,
                })));
            }
            ServiceOperation::Entropy { payload } => {
                let pointer = self.native_service_pointer(
                    execution.context,
                    payload.ring_storage(),
                    payload.length().raw() as usize,
                    1,
                )?;
                // SAFETY: exact ticket retains the ring's bounded staging box
                // until ACK. The stopped entry cannot access it during service;
                // terminal cancellation cannot free it while this ticket exists.
                let record = unsafe {
                    std::slice::from_raw_parts_mut(pointer, payload.length().raw() as usize)
                };
                native_entropy(record).map_err(|_| fail("native entropy record invalid"))?;
                true
            }
            ServiceOperation::CarrierWork { demand, .. } => carrier_work_supplied(demand),
            ServiceOperation::Fault(_) => {
                let slot = self
                    .grant_portal()?
                    .grant(lease.cpu.raw() as usize)
                    .ok_or_else(|| fail("native fault selection slot"))?;
                let selected = ticket
                    .take_fault_selection(slot)
                    .map_err(|_| fail("native fault selection identity"))?;
                match (selected, ticket.reply_address()) {
                    (
                        Some(carrick_core_abi::service::ServiceFaultSupply::Backing(window)),
                        Some(address),
                    ) => {
                        let pointer = self.native_service_pointer(
                            execution.context,
                            address,
                            size_of::<carrick_el1_abi::PortalGrantSlot>(),
                            align_of::<carrick_el1_abi::PortalGrantSlot>(),
                        )?;
                        // SAFETY: the ticket retains this authenticated isolated reply
                        // until ACK, then the ring's pending owner retains it to settlement.
                        let reply = unsafe { &*pointer.cast::<carrick_el1_abi::PortalGrantSlot>() };
                        if self.native_backing_pending.contains_key(&address) {
                            return Err(fail("native fault reply already retained"));
                        }
                        match self.prepare_native_backing_grant(execution, window, file, reply)? {
                            Ok(anonymous_owner::BackingPreparation::Prepared(Some(pending))) => {
                                self.native_backing_pending.insert(address, *pending);
                                true
                            }
                            Ok(anonymous_owner::BackingPreparation::Prepared(None)) => false,
                            // No rerun owner exists on this copy path yet:
                            // an EFAULT here would be a wrong answer (#2686).
                            Ok(anonymous_owner::BackingPreparation::Raced(refusal)) => {
                                return Err(fail(format!(
                                    "native backing plan raced a publication: {refusal:?}"
                                )));
                            }
                            Err(wait) => {
                                owner_wait = Some(wait);
                                false
                            }
                        }
                    }
                    // No physical supply was selected (including an inaccessible
                    // backing): the shared copyout owner returns EFAULT or prefix.
                    _ => false,
                }
            }
            _ => return Err(fail("unsupported CPL0 native service operation")),
        };
        let sink = self.carrier_zone_wake()?;
        let completion = |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| self.complete_object_wake(lease.cpu, &*sink, owned);
        let queue = zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &completion)
            .map_err(|_| fail("native service acknowledgment queue"))?;
        if let Some(wait) = owner_wait {
            ticket
                .complete_wait(wait)
                .map_err(|_| fail("native service wait acknowledgment"))?;
        } else {
            ticket
                .complete(supplied)
                .map_err(|_| fail("native service acknowledgment"))?;
        }
        // Wake any peer parked on this holder's release after contending on
        // the per-slot `service_notice` (#2532).
        let mut effects = carrick_sched_core::WakeEffects::default();
        queue
            .notify_object(SlotId::new(lease.cpu.raw() as u8), &mut effects)
            .map_err(|_| fail("native service acknowledgment wake"))?;
        drop(queue);
        if effects.queued_own || effects.owes_host_boundary() {
            self.task(lease.cpu).linux.mark_pending_host_work();
        }
        for target in effects.sgi_slots() {
            sink.resched(target);
        }
        if sink.take_undelivered().is_some() {
            return Err(fail("native service reschedule not delivered"));
        }
        Ok(NativeNoticeStep::Settled)
    }

    pub(in crate::cpl0_boot) fn finish_native_host_file<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        pending: PendingNativeHostFile,
        served: Result<
            carrick_hal::fork_stock::NativeHostFileReply,
            carrick_hal::fork_stock::NativeHostFileRefused,
        >,
    ) -> Result<(), TrapError> {
        if self.physical_execution(lease)?.context != pending.execution.context {
            return Err(fail("native host file completion context changed"));
        }
        self.native_service_pointer(
            pending.execution.context,
            pending.address,
            pending.record.len(),
            1,
        )?;
        let owner_wait = served
            .as_ref()
            .ok()
            .and_then(|reply| reply.owner_wait(pending.ticket.request().identity.birth.mm));
        match &served {
            // A reply was written, or none was and the member waits on its
            // host-readiness queue to publish the call's record again. The
            // pending record goes back either way: the carrier may have
            // marked it (a socket timeout's wait, which a signal interrupts
            // with EINTR, never a restart: #2920), and HVF's carrier writes
            // the ring's record in place.
            Ok(
                carrick_hal::fork_stock::NativeHostFileReply::HostReadyWait { .. }
                | carrick_hal::fork_stock::NativeHostFileReply::Replied(None),
            ) => {
                let physical = kernel_pod_physical(
                    &self.kernel_pod_storage,
                    pending.address,
                    pending.record.len(),
                    1,
                )
                .ok_or_else(|| fail("native host file reply storage"))?;
                self._vm
                    .write(physical, &pending.record)
                    .map_err(|error| fail(error.to_string()))?;
            }
            Ok(carrick_hal::fork_stock::NativeHostFileReply::Replied(Some(_))) => {
                return Err(fail("unexpected native host file source"));
            }
            Err(_) => {
                let pointer = self.native_service_pointer(
                    pending.execution.context,
                    KernelVa::new(self.binding(lease.cpu).counters_address),
                    size_of::<carrick_el1_abi::Counters>(),
                    align_of::<carrick_el1_abi::Counters>(),
                )?;
                // SAFETY: exact stopped binding authenticates the retained counter region.
                let counters = unsafe { &*pointer.cast::<carrick_el1_abi::Counters>() };
                let request = pending.ticket.request();
                let ServiceOperation::HostFile { payload, .. } = request.operation else {
                    return Err(fail("native host file ticket changed"));
                };
                counters.record_refusal(
                    payload.ordinal(),
                    request.identity.birth.origin,
                    carrick_el1_abi::RefusalVenue::Carrier,
                    carrick_el1_abi::RefusalArguments::Unretained,
                );
            }
        }
        let pointer = self
            .ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("native service zone absent"))?;
        // SAFETY: fixed aligned zone is retained by custody and the ticket.
        let zone = unsafe { &*pointer.cast::<X86Cpl0Zone>() };
        let sink = self.carrier_zone_wake()?;
        let completion = |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| self.complete_object_wake(lease.cpu, &*sink, owned);
        let queue = zone
            .object_wait(pending.key, &carrick_sched_core::ShortLockSpin, &completion)
            .map_err(|_| fail("native host file acknowledgment queue"))?;
        match owner_wait {
            Some(wait) => pending
                .ticket
                .complete_wait(wait)
                .map_err(|_| fail("native host file wait acknowledgment"))?,
            None => pending
                .ticket
                .complete(served.is_ok())
                .map_err(|_| fail("native host file acknowledgment"))?,
        }
        let mut effects = carrick_sched_core::WakeEffects::default();
        queue
            .notify_object(SlotId::new(lease.cpu.raw() as u8), &mut effects)
            .map_err(|_| fail("native host file acknowledgment wake"))?;
        drop(queue);
        if effects.queued_own || effects.owes_host_boundary() {
            self.task(lease.cpu).linux.mark_pending_host_work();
        }
        for target in effects.sgi_slots() {
            sink.resched(target);
        }
        if sink.take_undelivered().is_some() {
            return Err(fail("native host file reschedule not delivered"));
        }
        Ok(())
    }
}

/// Deliver one object-wake completion that a queue released while the host
/// holds `stopped`'s lease: a notification another CPU posted while the
/// host held the queue, or an admission handed to the holder. Handbacks go
/// to the carrier's completion chain, which the stopped CPU's host-work
/// boundary settles (#2928); `mark_stopped` rings that CPU's doorbell.
///
/// Every CPU the wake queued work on gets the reschedule MSI through
/// `sink`, as the direct acknowledgment path and the carrier zone's
/// handbacks (`hand_back_in_carrier`) do: x86 reads no owed-reschedule
/// word, and a CPU idling in `hlt` wakes only on the interrupt.
fn deliver_stopped_completion(
    sink: &dyn carrick_sched_core::CarrierZoneWake<carrick_sched_core::ParkedContextWords>,
    stopped: SlotId,
    owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
        '_,
        carrick_sched_core::ParkedContextWords,
    >,
    mark_stopped: &dyn Fn(),
) {
    let zone = owned.zone();
    let (waker, effects, deferred) = owned.defer_handbacks();
    carrick_el1::substrate::sched::object_wait::deliver_effects_with(
        zone,
        Some(stopped),
        waker,
        effects,
        deferred,
        |target, _| {
            zone.owe_resched(target);
            sink.resched(target);
            mark_stopped();
        },
        (|_| mark_stopped(), mark_stopped),
    );
}

/// The CPL0 carrier's answer to a `CarrierWork` request.
fn carrier_work_supplied(demand: carrick_core_abi::service::CarrierDemand) -> bool {
    use carrick_core_abi::service::CarrierDemand;
    match demand {
        // The shared owner retains the operation and reruns preparation
        // after this physical checkpoint; Busy never becomes an errno.
        CarrierDemand::Work => true,
        // No thread-stock owner runs on the CPL0 carrier (x86 roots stock
        // their own managed pool), so it never answers `Stocked`: the
        // refusal reads back as `Unstockable`, today's host answer (#1974).
        CarrierDemand::ThreadStock => false,
    }
}

#[cfg(test)]
mod stopped_completion_tests {
    use carrick_sched_core::object_wait::{ObjectWaitKey, OperationToken, OwnedObjectWakeEffects};
    use carrick_sched_core::{
        CarrierZoneWake, Claim, ParkedContextWords, ShortLockSpin, SlotId, ThreadIdentity, Waker,
        ZoneTables,
    };
    use std::sync::Mutex;

    const MM: u64 = 0x2928;

    struct RecordingSink {
        zone: &'static ZoneTables<ParkedContextWords>,
        rescheds: Mutex<Vec<SlotId>>,
    }
    impl CarrierZoneWake<ParkedContextWords> for RecordingSink {
        fn zone(&self) -> &ZoneTables<ParkedContextWords> {
            self.zone
        }
        fn resched(&self, slot: SlotId) {
            self.rescheds.lock().unwrap().push(slot);
        }
        fn take_undelivered(&self) -> Option<carrick_sched_core::WakeUndelivered> {
            None
        }
    }

    /// #2928: CPU 1 (the guest ring) posts a notification on a queue while
    /// the host holds it for stopped CPU 0, so the host's release delivers
    /// the wake through the stopped CPU's completion venue
    /// (`complete_object_wake`). The waiter may run only on CPU 1, which went
    /// on to idle in `hlt`: it is queued there, and only the reschedule MSI
    /// wakes that CPU. x86 reads no owed-reschedule word, so an
    /// `owe_resched` alone leaves the waiter queued on a halted CPU.
    ///
    /// Posted notifications need a completion-enabled queue. Today's native
    /// service queues are legacy ones, whose releases carry only admission
    /// handbacks; this venue's per-target send is reached by host placements
    /// (`claim_for_host`) and by the host contention parks its doc defers.
    /// The release shape here is the one that sends.
    #[test]
    fn host_release_of_a_peer_notification_reschedules_the_halted_peer() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
        // SAFETY: the shared zone ABI's empty state is all-zero; the
        // fixture leaks it for the 'static sink binding.
        let zone =
            unsafe { &*std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>() };
        let sink = RecordingSink {
            zone,
            rescheds: Mutex::new(Vec::new()),
        };
        let stopped = SlotId::new(0);
        let peer = SlotId::new(1);
        for slot in [stopped, peer] {
            zone.drive(slot, 1);
            zone.publish_slot(slot, MM, Some(u32::from(slot.raw())), 0b11);
            let here = carrick_sched_core::ExecutionSlot::zone(slot);
            zone.occupancy.vacate_any(here);
            assert!(zone.occupancy.replace(here, 0, MM));
            zone.enter_guest(slot);
        }
        let key = ObjectWaitKey::new(3, 1).expect("key");
        let marks = std::cell::Cell::new(0_u32);
        let completion = |owned: OwnedObjectWakeEffects<'_, ParkedContextWords>| {
            super::deliver_stopped_completion(&sink, stopped, owned, &|| marks.set(marks.get() + 1))
        };
        zone.bind_object_wait_with_completion(key, &ShortLockSpin, &completion)
            .expect("bind");
        let record = zone
            .alloc_record(ThreadIdentity {
                tid: 77,
                serial: 77,
                mm: MM,
                file_table: 77,
                generation: 1,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1 << 1,
                lifecycle_page: 0,
                control_slot: 0,
            })
            .expect("record");
        assert!(zone.mark_native_owned(record));
        {
            let queue = zone
                .object_wait_with_completion(key, &ShortLockSpin, &completion)
                .expect("queue");
            queue
                .park(
                    queue.snapshot(),
                    record,
                    OperationToken::new(77, 1).expect("token"),
                )
                .expect("park");
        }
        let source = zone
            .admit_object_notification(key, &ShortLockSpin, &completion)
            .expect("notification source");
        let held = zone
            .object_wait_with_completion(key, &ShortLockSpin, &completion)
            .expect("host holds the queue");
        source.publish(Waker::El1 { slot: peer }, &completion);
        assert!(
            matches!(zone.record(record).claim(), Claim::Parked { .. }),
            "the holder owns the posted notification"
        );
        drop(held);
        assert!(
            matches!(zone.record(record).claim(), Claim::Queued { slot, .. } if slot == peer),
            "{:?}",
            zone.record(record).claim()
        );
        assert_eq!(
            *sink.rescheds.lock().unwrap(),
            [peer],
            "the halted peer got no reschedule interrupt"
        );
    }
}

#[cfg(test)]
mod carrier_work_tests {
    use carrick_core_abi::service::{CarrierDemand, CarrierWorkReply, ServiceResult};

    fn reply(demand: CarrierDemand) -> Option<CarrierWorkReply> {
        let result = if super::carrier_work_supplied(demand) {
            ServiceResult::Supplied
        } else {
            ServiceResult::Refused
        };
        CarrierWorkReply::for_result(demand, result)
    }

    /// Plain carrier work is delivered and its operation reruns.
    #[test]
    fn cpl0_carrier_work_is_delivered() {
        assert_eq!(
            reply(CarrierDemand::Work),
            Some(CarrierWorkReply::Delivered)
        );
    }

    /// #1974: the CPL0 carrier has no thread-stock owner, so a stock demand
    /// is answered `Unstockable` (today's host answer), never acknowledged
    /// as `Stocked` without stock.
    #[test]
    fn cpl0_thread_stock_demand_is_never_stocked_without_stock() {
        assert_eq!(
            reply(CarrierDemand::ThreadStock),
            Some(CarrierWorkReply::Unstockable)
        );
    }
}
