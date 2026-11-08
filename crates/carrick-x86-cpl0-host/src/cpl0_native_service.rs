//! Stopped CPL0 transport for the shared native entropy service.
use super::*;
use carrick_core_abi::service::{ServiceCell, ServiceOperation};
use carrick_guest_arch::KernelVa;
use carrick_sched_core::object_wait::ObjectWaitKey;

impl<M: CarrierMemoryIo> Cpl0HostCustody<M> {
    /// Authenticate a retained supervisor span against this exact live root.
    /// The carrier owns the backing through the crossing; the outstanding
    /// service claim prevents retirement of the member/MM and payload.
    pub(super) fn native_service_pointer(
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

    pub(in crate::cpl0_boot) fn service_native_notice<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        file: Option<anonymous_owner::FileSupply>,
        native_entropy: NativeEntropyService,
    ) -> Result<(), TrapError> {
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
        let queue = zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin)
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
            .object_wait(key, &carrick_sched_core::ShortLockSpin)
            .map_err(|_| fail("native service claim queue"))?;
        if queue.native_service_member(selector.record) != Some(member)
            || control.zone_record() != Some(selector.record)
            || !control.native_signal_owner()
        {
            return Err(fail("native service control owner changed"));
        }
        // SAFETY: custody retains this exact control; its member is revalidated
        // under the queue. The ring's pending claim retains its admitted MM.
        let mut ticket = unsafe {
            ServiceCell::claim_notice(
                &control.service,
                selector,
                self._vm.identity().nonzero(),
                member,
            )
        }
        .map_err(|_| fail("native service ticket claim"))?;
        drop(queue);
        let mut owner_wait = None;
        let supplied = match ticket.request().operation {
            ServiceOperation::Entropy { payload } => {
                let pointer = self.native_service_pointer(
                    execution.context,
                    KernelVa::new(payload.address().raw()),
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
            // The shared owner retains the operation and reruns preparation
            // after this physical checkpoint; Busy never becomes an errno.
            ServiceOperation::CarrierWork { .. } => true,
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
                            Ok(Some(pending)) => {
                                self.native_backing_pending.insert(address, pending);
                                true
                            }
                            Ok(None) => false,
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
        let _queue = zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin)
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
        // This synchronous doorbell precedes park enrollment. The shared owner
        // probes ACK under the same queue and requeues its exact continuation;
        // no host waiter, readiness pipe or polling path is introduced.
        Ok(())
    }
}
