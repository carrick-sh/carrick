//! Native-member service continuations. Slot custody ends at park; semantic
//! process/MM custody ends only after the exact external acknowledgment.
use super::*;
use carrick_core_abi::service::{
    ServiceBirth, ServiceError, ServiceOperation, ServiceRequest, ServiceResult,
};
use carrick_sched_core::object_wait::{ObjectWaitKey, OperationToken};

pub(super) struct PendingService<'a> {
    request: ServiceRequest,
    claim: carrick_core::terminal::NativeServiceClaim<&'a ThreadLifecyclePage>,
    control: Arc<carrick_core::lifecycle::MemberControlCustody<'a, ThreadControlSlot>>,
}

impl<'a, M: Clone, C: ProcessContext> NativeProcessRuntime<'a, M, C> {
    pub(super) fn cancel_service<S: NativeProcessService<'a, C>>(
        &self,
        record: RecordRef,
        slot: SlotId,
        service: &mut S,
    ) -> Result<(), NativeProcessError> {
        let pending = self
            .graph
            .lock()
            .services
            .get(&record)
            .map(|pending| (pending.request, pending.control.clone()));
        let Some((request, control)) = pending else {
            return Ok(());
        };
        let key = ObjectWaitKey::native_service(record).ok_or(NativeProcessError::Stale)?;
        let guard = self
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin)
            .map_err(|_| NativeProcessError::Quarantined)?;
        control
            .service
            .cancel(request.identity)
            .map_err(service_error)?;
        let mut effects = WakeEffects::default();
        guard
            .notify_object(slot, &mut effects)
            .map_err(|_| NativeProcessError::Quarantined)?;
        drop(guard);
        service.wake_effects(effects);
        Ok(())
    }
}

impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    NativeProcessEntry<'_, 'a, M, C, S>
{
    fn release_service_claim(
        &mut self,
        claim: carrick_core::terminal::NativeServiceClaim<&'a ThreadLifecyclePage>,
    ) -> Result<(), NativeProcessError> {
        claim.acknowledge(|notification| {
            if let Some(notification) = notification {
                publish_terminal_notification(
                    &notification,
                    self.source.zone,
                    self.source.slot,
                    &NativeBucketWait {
                        lifetime: core::marker::PhantomData,
                        #[cfg(test)]
                        probe: self.publication_wait_probe,
                    },
                    |channel| self.service.wake_unplaceable_wait(channel),
                )
                .map_err(|_| NativeProcessError::Quarantined)?;
            }
            Ok(())
        })
    }

    /// Intake may capture backing, but never waits for another guest. The
    /// owning request is visible to terminal close before its physical intake.
    pub fn begin_service(
        &mut self,
        operation: ServiceOperation,
    ) -> Result<NativeResume, NativeProcessError> {
        let (page, mm, control) = {
            let graph = self.runtime.graph.lock();
            if graph.services.contains_key(&self.record) {
                return Err(NativeProcessError::Busy);
            }
            let resources = graph
                .owner
                .task(self.key)
                .map_err(|_| NativeProcessError::Stale)?
                .native()
                .resources();
            let member = resources
                .members
                .iter()
                .find(|member| {
                    member.record == self.record
                        && core::ptr::eq(member.control.control(), self.control)
                })
                .ok_or(NativeProcessError::Stale)?;
            (resources.page, resources.mm.clone(), member.control.clone())
        };
        let handle = self.service.service_mm_handle(&mm)?;
        let claim = carrick_core::terminal::NativeServiceClaim::acquire(page)
            .map_err(|_| NativeProcessError::Busy)?;
        let birth = ServiceBirth {
            process: self.key,
            thread: self.binding.thread_generation,
            record: self.record,
            mm: handle,
        };
        let published = {
            let graph = self.runtime.graph.lock();
            if !claim.admitted() || graph.services.contains_key(&self.record) {
                Err(NativeProcessError::Busy)
            } else {
                self.control
                    .service
                    .publish(birth, self.binding.generation, operation)
                    .map_err(service_error)
            }
        };
        let request = match published {
            Ok(request) => request,
            Err(error) => {
                self.release_service_claim(claim)?;
                return Err(error);
            }
        };
        self.runtime.graph.lock().services.insert(
            self.record,
            PendingService {
                request,
                claim,
                control,
            },
        );
        if let Err(error) = self.service.intake_service(request, self.control) {
            let key =
                ObjectWaitKey::native_service(self.record).ok_or(NativeProcessError::Stale)?;
            let guard = self
                .source
                .zone
                .object_wait(key, &carrick_sched_core::ShortLockSpin)
                .map_err(|_| NativeProcessError::Quarantined)?;
            let acknowledged = self
                .control
                .service
                .cancel(request.identity)
                .map_err(service_error)?;
            if acknowledged {
                self.control
                    .service
                    .consume(request.identity)
                    .map_err(service_error)?;
                drop(guard);
                let pending = self
                    .runtime
                    .graph
                    .lock()
                    .services
                    .remove(&self.record)
                    .ok_or(NativeProcessError::Quarantined)?;
                self.release_service_claim(pending.claim)?;
                return Err(error);
            }
        }
        self.park_service(request)
    }

    fn park_service(
        &mut self,
        request: ServiceRequest,
    ) -> Result<NativeResume, NativeProcessError> {
        use carrick_sched_core::object_wait::ObjectWaitError;
        let zone = self.source.zone;
        let key = ObjectWaitKey::native_service(self.record).ok_or(NativeProcessError::Stale)?;
        // These queues are bound as guest-owned queues at birth. A host
        // continuation domain may not take over a native member's operation.
        if zone.completion_enabled(key) {
            return Err(NativeProcessError::Quarantined);
        }
        let token = OperationToken::new(
            u64::from(self.record.id.raw()),
            request.identity.sequence.get(),
        )
        .ok_or(NativeProcessError::Stale)?;
        let entry = match request.operation {
            ServiceOperation::Fault(_) => OwnerEntry::Exception,
            ServiceOperation::Crossing { .. } => OwnerEntry::Syscall,
        };
        let mut completion = None;
        let mut failure = None;
        let parked = carrick_core::wait::park_object_record(
            zone,
            self.source.slot,
            carrick_core::wait::ObjectParkRequest::owner(key, token, entry),
            &|_| {},
            || {
                if self.signal_interrupts_current()
                    || self
                        .runtime
                        .graph
                        .lock()
                        .pending_exit
                        .contains_key(&self.key)
                {
                    if let Err(error) = self.control.service.cancel(request.identity) {
                        failure = Some(service_error(error));
                        return Err(ObjectWaitError::Stale);
                    }
                }
                match self.control.service.consume(request.identity) {
                    Ok(result) => {
                        completion = Some(result);
                        return Err(ObjectWaitError::Changed);
                    }
                    Err(ServiceError::Busy) => {}
                    Err(error) => {
                        failure = Some(service_error(error));
                        return Err(ObjectWaitError::Stale);
                    }
                }
                // SAFETY: this slot still owns the exact OnCpu record.
                unsafe {
                    *zone.record(self.record.id).ctx_mut() = *self.words;
                }
                Ok((self.record.id, false))
            },
        );
        if let Some(error) = failure {
            return Err(error);
        }
        if let Some(result) = completion {
            return self.finish_service(request, result);
        }
        let mut parked = parked.map_err(|_| NativeProcessError::Quarantined)?;
        self.handoff = parked.take_receipt();
        Ok(NativeResume::Left(None))
    }

    pub(super) fn resume_service(&mut self) -> Option<Result<NativeResume, NativeProcessError>> {
        let request = self
            .runtime
            .graph
            .lock()
            .services
            .get(&self.record)?
            .request;
        let operation = carrick_core::wait::take_object_operation(
            self.source.zone,
            self.source.slot,
            self.source.zone.record(self.record.id).identity(),
        );
        match operation {
            Ok(Some(token))
                if token.index() == u64::from(self.record.id.raw())
                    && token.generation() == request.identity.sequence.get() => {}
            _ => return Some(Err(NativeProcessError::Stale)),
        }
        Some(self.park_service(request))
    }

    fn finish_service(
        &mut self,
        request: ServiceRequest,
        result: ServiceResult,
    ) -> Result<NativeResume, NativeProcessError> {
        let pending = self
            .runtime
            .graph
            .lock()
            .services
            .remove(&self.record)
            .ok_or(NativeProcessError::Stale)?;
        if pending.request != request {
            return Err(NativeProcessError::Quarantined);
        }
        self.release_service_claim(pending.claim)?;
        if self
            .runtime
            .graph
            .lock()
            .pending_exit
            .contains_key(&self.key)
        {
            // The terminal checkpoint must consume both winner and losing
            // caller custody; none may return a cancelled service to EL0.
            unsafe {
                self.source
                    .zone
                    .record(self.record.id)
                    .publish_owner_continuation(match request.operation {
                        ServiceOperation::Fault(_) => OwnerEntry::Exception,
                        ServiceOperation::Crossing { .. } => OwnerEntry::Syscall,
                    });
            }
            return Ok(NativeResume::NoPending);
        }
        // SAFETY: completion belongs to this exact selected record.
        unsafe {
            self.source
                .zone
                .record(self.record.id)
                .consume_owner_continuation();
        }
        match (request.operation, result) {
            (ServiceOperation::Crossing { .. }, ServiceResult::Refused) => {
                Ok(NativeResume::Returned(SyscallResult::new(
                    carrick_syscall_abi::LINUX_ENOSYS.guest_retval(),
                )))
            }
            (ServiceOperation::Crossing { .. }, ServiceResult::Cancelled) => {
                Ok(NativeResume::Returned(SyscallResult::new(
                    carrick_syscall_abi::LINUX_EINTR.guest_retval(),
                )))
            }
            (ServiceOperation::Fault(_), ServiceResult::Cancelled) => Ok(NativeResume::NoPending),
            (ServiceOperation::Fault(fault), ServiceResult::Refused) => {
                self.force_sigsegv_info(
                    carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                        carrick_signal_core::SignalSet::from_bits(self.control.blocked().0),
                    ),
                    carrick_syscall_abi::LinuxSiginfo {
                        si_code: if fault.present {
                            carrick_syscall_abi::LINUX_SEGV_ACCERR
                        } else {
                            carrick_syscall_abi::LINUX_SEGV_MAPERR
                        },
                        si_addr: fault.address.raw(),
                        ..carrick_syscall_abi::LinuxSiginfo::empty()
                    },
                )
                .map_err(|_| NativeProcessError::Fault)?;
                Ok(NativeResume::NoPending)
            }
            (_, _) => self
                .service
                .complete_service(request, result, &mut self.words),
        }
    }
}
fn service_error(error: ServiceError) -> NativeProcessError {
    match error {
        ServiceError::Busy => NativeProcessError::Busy,
        ServiceError::Stale => NativeProcessError::Stale,
        ServiceError::Exhausted => NativeProcessError::Exhausted,
    }
}
