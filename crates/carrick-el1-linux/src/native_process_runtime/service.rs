//! Native-member service continuations. Slot custody ends at park; semantic
//! process/MM custody ends only after the exact external acknowledgment.
use super::*;
use carrick_core_abi::service::{ServiceError, ServiceOperation, ServiceRequest, ServiceResult};
use carrick_sched_core::object_wait::{ObjectWaitKey, OperationToken};

fn native_exception_signal(
    kind: carrick_core_abi::service::NativeExceptionKind,
) -> (carrick_signal_core::policy::Signal, i32) {
    use carrick_core_abi::service::NativeExceptionKind;
    match kind {
        NativeExceptionKind::Breakpoint => (
            carrick_signal_core::policy::Signal::TRAP,
            carrick_syscall_abi::LINUX_TRAP_BRKPT,
        ),
        NativeExceptionKind::SingleStep => (
            carrick_signal_core::policy::Signal::TRAP,
            carrick_syscall_abi::LINUX_TRAP_TRACE,
        ),
        NativeExceptionKind::HardwareBreakpoint => (
            carrick_signal_core::policy::Signal::TRAP,
            carrick_syscall_abi::LINUX_TRAP_HWBKPT,
        ),
        NativeExceptionKind::UndefinedInstruction | NativeExceptionKind::FloatingPoint => (
            carrick_signal_core::policy::Signal::ILL,
            carrick_syscall_abi::LINUX_ILL_ILLOPC,
        ),
        NativeExceptionKind::Alignment => (
            carrick_signal_core::policy::Signal::BUS,
            carrick_syscall_abi::LINUX_BUS_ADRALN,
        ),
    }
}

pub(super) struct PendingService<'a> {
    reply: Option<Box<carrick_el1_abi::PortalGrantSlot>>,
    /// Exec input is ring-owned guest memory. Its virtual address is published
    /// in the request and cannot be recycled until completion/cancellation ACK.
    _exec_payload: Option<Box<[u8]>>,
    request: ServiceRequest,
    pub(super) wait: Option<carrick_core_abi::PortalOwnerWait>,
    claim: carrick_core::terminal::NativeServiceClaim<&'a ThreadLifecyclePage>,
    control: Arc<carrick_core::lifecycle::MemberControlCustody<'a, ThreadControlSlot>>,
}

impl<'a, M: Clone, C: ProcessContext> NativeProcessRuntime<'a, M, C> {
    pub(crate) fn cancel_service<S: NativeProcessService<'a, C>>(
        &self,
        record: RecordRef,
        slot: SlotId,
        service: &mut S,
    ) -> Result<(), NativeProcessError> {
        let pending = self
            .graph
            .lock()
            .service_wait(&record)
            .map(|pending| (pending.request, pending.control.clone()));
        let Some((request, control)) = pending else {
            return Ok(());
        };
        let key = ObjectWaitKey::native_service(record).ok_or(NativeProcessError::Stale)?;
        let guard = self
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin)
            .map_err(|_| NativeProcessError::Quarantined)?;
        // Completion may have consumed the captured request before this
        // queue lock was acquired. A signal targets the member, not an old
        // service sequence; never cancel its replacement or fail the run.
        if self
            .graph
            .lock()
            .service_wait(&record)
            .map(|pending| pending.request)
            != Some(request)
        {
            return Ok(());
        }
        control
            .service
            .cancel(request.identity)
            .map_err(service_error)?;
        let wait = self
            .graph
            .lock()
            .service_wait(&record)
            .and_then(|pending| pending.wait);
        let mut effects = WakeEffects::default();
        if let Some(wait) = wait {
            drop(guard);
            let enrollment = carrick_core_abi::wait::PortalWaitEnrollment::for_owner(
                self.zone,
                request.identity.birth.mm,
                wait,
            )
            .map_err(|_| NativeProcessError::Stale)?;
            let completion =
                |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, C>| {
                    crate::sched::object_wait::deliver_completion(self.zone, slot, owned);
                };
            let queue = self
                .zone
                .object_wait_with_completion(
                    enrollment.key(),
                    &carrick_sched_core::ShortLockSpin,
                    &completion,
                )
                .map_err(|_| NativeProcessError::Stale)?;
            // Recheck after queue admission: a completed wait may already have
            // moved to its successor. Cancellation remains sticky in the cell.
            if self
                .graph
                .lock()
                .service_wait(&record)
                .is_some_and(|pending| pending.request == request && pending.wait == Some(wait))
            {
                let operation = OperationToken::new(
                    u64::from(record.id.raw()),
                    request.identity.sequence.get(),
                )
                .ok_or(NativeProcessError::Stale)?;
                queue.wake_owner_operation(record, &operation, slot, &mut effects);
            }
            drop(queue);
        } else {
            guard
                .notify_object(slot, &mut effects)
                .map_err(|_| NativeProcessError::Quarantined)?;
            drop(guard);
        }
        service.wake_effects(effects);
        Ok(())
    }
}

impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    NativeProcessEntry<'_, 'a, M, C, S>
{
    #[inline(never)]
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
    #[inline(never)]
    pub fn begin_service(
        &mut self,
        operation: ServiceOperation,
        fault_sequence: Option<core::num::NonZeroU64>,
    ) -> Result<NativeResume, NativeProcessError> {
        self.begin_service_inner(operation, fault_sequence, None, None)
    }
    pub fn begin_exec_service(
        &mut self,
        payload: Box<[u8]>,
    ) -> Result<NativeResume, NativeProcessError> {
        let capability = self
            .runtime
            .exec_capability()
            .ok_or(NativeProcessError::Stale)?;
        let descriptor = carrick_core_abi::service::ExecPayloadDescriptor::checked(
            carrick_guest_arch::GuestVa::new(payload.as_ptr().addr() as u64),
            carrick_guest_arch::GuestLen::new(payload.len() as u64),
        )
        .ok_or(NativeProcessError::Exhausted)?;
        self.begin_service_inner(
            ServiceOperation::Exec {
                capability,
                payload: descriptor,
            },
            None,
            None,
            Some(payload),
        )
    }
    /// Park the exact ring operation on the producer observed before its
    /// failed admission. No physical service notice is published.
    pub fn begin_owner_service_wait(
        &mut self,
        operation: ServiceOperation,
        wait: carrick_core_abi::PortalOwnerWait,
    ) -> Result<NativeResume, NativeProcessError> {
        self.begin_service_inner(operation, None, Some(wait), None)
    }
    #[inline(never)]
    fn begin_service_inner(
        &mut self,
        operation: ServiceOperation,
        fault_sequence: Option<core::num::NonZeroU64>,
        owner_wait: Option<carrick_core_abi::PortalOwnerWait>,
        exec_payload: Option<Box<[u8]>>,
    ) -> Result<NativeResume, NativeProcessError> {
        if matches!(operation, ServiceOperation::Exec { .. }) != exec_payload.is_some() {
            return Err(NativeProcessError::Stale);
        }
        let (page, control) = {
            let graph = self.runtime.graph.lock();
            if graph.has_member_wait(&self.record) {
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
            (resources.page, member.control.clone())
        };
        let birth = control
            .service
            .bound_birth(self.key, self.binding.thread_generation, self.record)
            .map_err(service_error)?;
        let reply = if matches!(operation, ServiceOperation::Fault(fault) if !fault.present)
            && fault_sequence.is_some()
        {
            Some(FallibleBox::<carrick_el1_abi::PortalGrantSlot>::try_reserve()?.zeroed())
        } else {
            None
        };
        let owner_queue = owner_wait
            .map(|_| {
                let key =
                    ObjectWaitKey::native_service(self.record).ok_or(NativeProcessError::Stale)?;
                self.source
                    .zone
                    .object_wait(key, &carrick_sched_core::ShortLockSpin)
                    .map_err(|_| NativeProcessError::Stale)
            })
            .transpose()?;
        let claim = carrick_core::terminal::NativeServiceClaim::acquire(page)
            .map_err(|_| NativeProcessError::Busy)?;
        let published = {
            let graph = self.runtime.graph.lock();
            if !claim.admitted() || graph.has_member_wait(&self.record) {
                Err(NativeProcessError::Busy)
            } else if let Some(wait) = owner_wait {
                self.control
                    .service
                    .begin_owner_wait(birth, self.binding.generation, operation, wait)
                    .map_err(service_error)
            } else {
                self.control
                    .service
                    .publish_with_reply(
                        birth,
                        self.binding.generation,
                        operation,
                        fault_sequence,
                        reply.as_ref().map(|slot| {
                            carrick_guest_arch::KernelVa::new(
                                core::ptr::from_ref(&**slot).addr() as u64
                            )
                        }),
                    )
                    .map_err(service_error)
            }
        };
        let request = match published {
            Ok(request) => request,
            Err(error) => {
                drop(owner_queue);
                self.release_service_claim(claim)?;
                return Err(error);
            }
        };
        self.runtime.graph.lock().insert_member_wait(
            self.record,
            MemberWait::Service(PendingService {
                reply,
                _exec_payload: exec_payload,
                request,
                wait: owner_wait,
                claim,
                control,
            }),
        );
        drop(owner_queue);
        if let Some(wait) = owner_wait {
            return self.park_owner_wait(request, wait);
        }
        if let Err(error) = self
            .current
            .service_notice
            .publish(request.identity.into())
            .map_err(service_error)
        {
            let key =
                ObjectWaitKey::native_service(self.record).ok_or(NativeProcessError::Stale)?;
            let guard = self
                .source
                .zone
                .object_wait(key, &carrick_sched_core::ShortLockSpin)
                .map_err(|_| NativeProcessError::Quarantined)?;
            // SAFETY: notice publication failed, so no transport can hold
            // this identity. The queue also excludes concurrent cancellation.
            unsafe { self.control.service.abort_unpublished(request.identity) }
                .map_err(service_error)?;
            {
                self.control
                    .service
                    .consume(request.identity)
                    .map_err(service_error)?;
                drop(guard);
                let pending = self
                    .runtime
                    .graph
                    .lock()
                    .remove_service_wait(&self.record)
                    .ok_or(NativeProcessError::Quarantined)?;
                self.release_service_claim(pending.claim)?;
                return Err(error);
            }
        }
        self.park_service(request)
    }

    #[inline(never)]
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
            ServiceOperation::Fault(_) | ServiceOperation::Exception(_) => OwnerEntry::Exception,
            ServiceOperation::Crossing { .. } | ServiceOperation::Exec { .. } => {
                OwnerEntry::Syscall
            }
            ServiceOperation::CarrierWork { entry } => entry,
        };
        let mut completion = None;
        let mut completed_pending = None;
        let mut failure = None;
        let parked = carrick_core::wait::park_object_record(
            zone,
            self.source.slot,
            carrick_core::wait::ObjectParkRequest::owner(key, token, entry),
            &|_| {},
            || {
                if (self.signal_interrupts_current()
                    || self.runtime.graph.lock().pending.has_exit(&self.key))
                    && let Err(error) = self.control.service.cancel(request.identity)
                {
                    failure = Some(service_error(error));
                    return Err(ObjectWaitError::Stale);
                }
                match self.control.service.consume(request.identity) {
                    Ok(result) => {
                        if let ServiceResult::Wait(wait) = result {
                            let mut graph = self.runtime.graph.lock();
                            let Some(pending) = graph.service_wait_mut(&self.record) else {
                                failure = Some(NativeProcessError::Stale);
                                return Err(ObjectWaitError::Stale);
                            };
                            pending.wait = Some(wait);
                        } else {
                            completed_pending =
                                self.runtime.graph.lock().remove_service_wait(&self.record);
                        }
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
            return match result {
                ServiceResult::Wait(wait) => self.park_owner_wait(request, wait),
                _ => self.finish_service(
                    request,
                    result,
                    completed_pending.ok_or(NativeProcessError::Stale)?,
                ),
            };
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
            .service_wait(&self.record)?
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
        let wait = self
            .runtime
            .graph
            .lock()
            .service_wait(&self.record)
            .and_then(|pending| pending.wait);
        Some(if wait.is_some() {
            self.finish_owner_wait(request)
        } else {
            self.park_service(request)
        })
    }

    #[inline(never)]
    fn park_owner_wait(
        &mut self,
        request: ServiceRequest,
        wait: carrick_core_abi::PortalOwnerWait,
    ) -> Result<NativeResume, NativeProcessError> {
        use carrick_sched_core::object_wait::ObjectWaitError;
        let zone = self.source.zone;
        let enrollment = carrick_core_abi::wait::PortalWaitEnrollment::for_owner(
            zone,
            request.identity.birth.mm,
            wait,
        )
        .map_err(|_| NativeProcessError::Stale)?;
        let operation = OperationToken::new(
            u64::from(self.record.id.raw()),
            request.identity.sequence.get(),
        )
        .ok_or(NativeProcessError::Stale)?;
        let parked = carrick_core::wait::park_object_record(
            zone,
            self.source.slot,
            enrollment.owner_request(operation),
            &|owned| {
                crate::sched::object_wait::deliver_completion(zone, self.source.slot, owned);
            },
            || {
                // MM queue -> service queue is the only nested queue order.
                let key =
                    ObjectWaitKey::native_service(self.record).ok_or(ObjectWaitError::Stale)?;
                let _queue = zone.object_wait(key, &carrick_sched_core::ShortLockSpin)?;
                if self.signal_interrupts_current()
                    || self.runtime.graph.lock().pending.has_exit(&self.key)
                {
                    self.control
                        .service
                        .cancel(request.identity)
                        .map_err(|_| ObjectWaitError::Stale)?;
                }
                if !enrollment.is_live()
                    || self
                        .control
                        .service
                        .owner_wait_cancelled(request.identity)
                        .map_err(|_| ObjectWaitError::Stale)?
                {
                    return Err(ObjectWaitError::Changed);
                }
                // SAFETY: this slot owns the admitted native record and saved context.
                unsafe {
                    *zone.record(self.record.id).ctx_mut() = *self.words;
                }
                Ok((self.record.id, false))
            },
        );
        match parked {
            Ok(mut parked) => {
                self.handoff = parked.take_receipt();
                Ok(NativeResume::Left(None))
            }
            Err((ObjectWaitError::Changed, _)) => self.finish_owner_wait(request),
            Err(_) => Err(NativeProcessError::Quarantined),
        }
    }
    fn finish_owner_wait(
        &mut self,
        request: ServiceRequest,
    ) -> Result<NativeResume, NativeProcessError> {
        let key = ObjectWaitKey::native_service(self.record).ok_or(NativeProcessError::Stale)?;
        let queue = self
            .source
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin)
            .map_err(|_| NativeProcessError::Stale)?;
        let result = self
            .control
            .service
            .finish_owner_wait(request.identity)
            .map_err(service_error)?;
        // Remove the phase under the service queue before cancellation observes IDLE.
        let pending = self
            .runtime
            .graph
            .lock()
            .remove_service_wait(&self.record)
            .ok_or(NativeProcessError::Stale)?;
        drop(queue);
        self.finish_service(request, result, pending)
    }

    #[inline(never)]
    fn finish_service(
        &mut self,
        request: ServiceRequest,
        mut result: ServiceResult,
        mut pending: PendingService<'a>,
    ) -> Result<NativeResume, NativeProcessError> {
        if pending.request != request {
            return Err(NativeProcessError::Quarantined);
        }
        if self.runtime.graph.lock().pending.has_exit(&self.key) {
            // The terminal checkpoint must consume both winner and losing
            // caller custody; none may return a cancelled service to EL0.
            unsafe {
                self.source
                    .zone
                    .record(self.record.id)
                    .publish_owner_continuation(match request.operation {
                        ServiceOperation::Fault(_) | ServiceOperation::Exception(_) => {
                            OwnerEntry::Exception
                        }
                        ServiceOperation::Crossing { .. } | ServiceOperation::Exec { .. } => {
                            OwnerEntry::Syscall
                        }
                        ServiceOperation::CarrierWork { entry } => entry,
                    });
            }
            self.release_service_claim(pending.claim)?;
            return Ok(NativeResume::NoPending);
        }
        if result == ServiceResult::Supplied
            && let Some(reply) = &pending.reply
        {
            match self.service.apply_fault_reply(reply) {
                Ok(()) => {}
                Err(carrick_core::mm::transaction::MmError::Wait(wait)) => {
                    let key = ObjectWaitKey::native_service(self.record)
                        .ok_or(NativeProcessError::Stale)?;
                    let queue = self
                        .source
                        .zone
                        .object_wait(key, &carrick_sched_core::ShortLockSpin)
                        .map_err(|_| NativeProcessError::Stale)?;
                    let next = self
                        .control
                        .service
                        .begin_owner_wait(
                            request.identity.birth,
                            self.binding.generation,
                            request.operation,
                            wait,
                        )
                        .map_err(service_error)?;
                    pending.request = next;
                    pending.wait = Some(wait);
                    self.runtime
                        .graph
                        .lock()
                        .insert_member_wait(self.record, MemberWait::Service(pending));
                    drop(queue);
                    return self.park_owner_wait(next, wait);
                }
                Err(_) => result = ServiceResult::Refused,
            }
        }
        // SAFETY: completion belongs to this exact selected record.
        unsafe {
            self.source
                .zone
                .record(self.record.id)
                .consume_owner_continuation();
        }
        let completed = (|| match (request.operation, result) {
            (_, ServiceResult::Wait(_)) => Err(NativeProcessError::Quarantined),
            (
                ServiceOperation::CarrierWork { .. },
                ServiceResult::Supplied | ServiceResult::Cancelled,
            ) => {
                // Bytes/results already committed before suspension. Cancellation
                // cannot turn that completion into a short transfer or EINTR.
                Ok(NativeResume::NoPending)
            }
            (ServiceOperation::CarrierWork { .. }, ServiceResult::Refused) => {
                Err(NativeProcessError::Quarantined)
            }
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
            (
                ServiceOperation::Fault(_) | ServiceOperation::Exception(_),
                ServiceResult::Cancelled,
            ) => Ok(NativeResume::NoPending),
            (ServiceOperation::Fault(fault), ServiceResult::BackingFault) => {
                self.force_fault_info(
                    carrick_signal_core::policy::Signal::BUS,
                    carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                        carrick_signal_core::SignalSet::from_bits(self.control.blocked().0),
                    ),
                    carrick_syscall_abi::LinuxSiginfo {
                        si_code: carrick_syscall_abi::LINUX_BUS_ADRERR,
                        si_addr: fault.address.raw(),
                        ..carrick_syscall_abi::LinuxSiginfo::empty()
                    },
                )
                .map_err(|_| NativeProcessError::Fault)?;
                Ok(NativeResume::NoPending)
            }
            (_, ServiceResult::BackingFault) => Err(NativeProcessError::Quarantined),
            (ServiceOperation::Exec { .. }, ServiceResult::Failed(failure)) => Ok(
                NativeResume::Returned(SyscallResult::new(-i64::from(failure.raw()))),
            ),
            (_, ServiceResult::Failed(_)) => Err(NativeProcessError::Quarantined),
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
            (ServiceOperation::Exception(exception), ServiceResult::Refused) => {
                let (signal, si_code) = native_exception_signal(exception.kind);
                self.force_fault_info(
                    signal,
                    carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                        carrick_signal_core::SignalSet::from_bits(self.control.blocked().0),
                    ),
                    carrick_syscall_abi::LinuxSiginfo {
                        si_code,
                        si_addr: exception.address.raw(),
                        ..carrick_syscall_abi::LinuxSiginfo::empty()
                    },
                )
                .map_err(|_| NativeProcessError::Fault)?;
                Ok(NativeResume::NoPending)
            }
            (ServiceOperation::Fault(_), ServiceResult::Supplied) => {
                // Supply changes physical availability only. Retry the exact
                // faulting instruction; the ring fault resolver still decides
                // the descriptor transaction or signal.
                Ok(NativeResume::NoPending)
            }
            (ServiceOperation::Crossing { .. }, ServiceResult::Supplied) => {
                // No generic host syscall dispatcher owns native semantics.
                Err(NativeProcessError::Quarantined)
            }
            (ServiceOperation::Exception(_), ServiceResult::Supplied) => {
                Err(NativeProcessError::Quarantined)
            }
            (ServiceOperation::Exec { .. }, ServiceResult::Supplied) => {
                // The successor adoption route consumes successful preparation
                // before this ordinary syscall-return mapping is reachable.
                Err(NativeProcessError::Quarantined)
            }
            (ServiceOperation::Exec { .. }, ServiceResult::Refused) => Ok(NativeResume::Returned(
                SyscallResult::new(carrick_syscall_abi::LINUX_ENOSYS.guest_retval()),
            )),
            (ServiceOperation::Exec { .. }, ServiceResult::Cancelled) => {
                Ok(NativeResume::Returned(SyscallResult::new(
                    carrick_syscall_abi::LINUX_EINTR.guest_retval(),
                )))
            }
        })();
        // Mapping/signal completion still needs the exact member/MM. Release
        // terminal custody only after the ring has made that decision.
        self.release_service_claim(pending.claim)?;
        completed
    }
}
fn service_error(error: ServiceError) -> NativeProcessError {
    match error {
        ServiceError::Busy => NativeProcessError::Busy,
        ServiceError::Stale => NativeProcessError::Stale,
        ServiceError::Exhausted => NativeProcessError::Exhausted,
    }
}

#[cfg(test)]
mod exception_tests {
    use super::native_exception_signal;
    use carrick_core_abi::service::NativeExceptionKind;

    #[test]
    fn native_exception_signal_policy_is_exhaustive() {
        use carrick_signal_core::policy::Signal;
        for (kind, expected) in [
            (
                NativeExceptionKind::Breakpoint,
                (Signal::TRAP, carrick_syscall_abi::LINUX_TRAP_BRKPT),
            ),
            (
                NativeExceptionKind::SingleStep,
                (Signal::TRAP, carrick_syscall_abi::LINUX_TRAP_TRACE),
            ),
            (
                NativeExceptionKind::HardwareBreakpoint,
                (Signal::TRAP, carrick_syscall_abi::LINUX_TRAP_HWBKPT),
            ),
            (
                NativeExceptionKind::UndefinedInstruction,
                (Signal::ILL, carrick_syscall_abi::LINUX_ILL_ILLOPC),
            ),
            (
                NativeExceptionKind::Alignment,
                (Signal::BUS, carrick_syscall_abi::LINUX_BUS_ADRALN),
            ),
            (
                NativeExceptionKind::FloatingPoint,
                (Signal::ILL, carrick_syscall_abi::LINUX_ILL_ILLOPC),
            ),
        ] {
            assert_eq!(native_exception_signal(kind), expected);
        }
    }
}
