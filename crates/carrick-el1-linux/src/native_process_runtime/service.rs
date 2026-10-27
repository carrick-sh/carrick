//! Native-member service continuations. Slot custody ends at park; semantic
//! process/MM custody ends only after the exact external acknowledgment.
use super::*;
use crate::process_owner::{GuestThreadState, GuestThreads};
use carrick_core_abi::service::{
    ExecSuccessorManifest, ServiceError, ServiceOperation, ServiceRequest, ServiceResult,
};
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

enum PendingServiceReply {
    Fault(Box<carrick_el1_abi::PortalGrantSlot>),
    Exec(Box<ExecSuccessorManifest>),
}
impl PendingServiceReply {
    fn address(&self) -> carrick_guest_arch::KernelVa {
        let address = match self {
            Self::Fault(reply) => core::ptr::from_ref(&**reply).addr(),
            Self::Exec(reply) => core::ptr::from_ref(&**reply).addr(),
        };
        carrick_guest_arch::KernelVa::new(address as u64)
    }
}

/// Carrier readiness never completes a parked syscall. Its continuation stays
/// owned by the process table until service settlement re-drives it.
enum CarrierContinuation {
    Completed(SyscallResult),
    Parked(TaskKey),
}

pub(super) struct PendingService<'a> {
    reply: Option<PendingServiceReply>,
    /// Exec input is ring-owned guest memory. Its virtual address is published
    /// in the request and cannot be recycled until completion/cancellation ACK.
    _exec_payload: Option<Box<[u8]>>,
    exec_successor: Option<Box<dyn ExecSuccessorSlot + 'a>>,
    retry_syscall_after_supply: bool,
    carrier_continuation: Option<CarrierContinuation>,
    request: ServiceRequest,
    pub(super) wait: Option<carrick_core_abi::PortalOwnerWait>,
    pub(super) claim: carrick_core::terminal::NativeServiceClaim<&'a ThreadLifecyclePage>,
    control: Arc<carrick_core::lifecycle::MemberControlCustody<'a, ThreadControlSlot>>,
}

/// Exact immutable proof for the graph/registry/scheduler cutover.  This is
/// boxed by the caller so validation does not add another large EL1 frame.
struct ValidatedExecSuccessor<'a> {
    old_record_identity: ThreadIdentity,
    record_key: NativeRecordKey,
    old_key: NativeExecutionKey,
    new_key: NativeExecutionKey,
    old_group: NativeGroupKey,
    new_group: NativeGroupKey,
    leader_tid: u32,
    caller_credentials: carrick_personality_linux::identity::TaskCredentials,
    page: &'a ThreadLifecyclePage,
    file_table: u64,
}

impl PendingService<'_> {
    fn exec_comm(&self) -> Result<[u8; 16], NativeProcessError> {
        let payload = self
            ._exec_payload
            .as_deref()
            .ok_or(NativeProcessError::Stale)?;
        let view = carrick_core_abi::service::ExecPayloadView::parse(payload)
            .map_err(|_| NativeProcessError::Stale)?;
        let path = view.path();
        let basename = path
            .rsplit(|byte| *byte == b'/')
            .next()
            .filter(|name| !name.is_empty())
            .ok_or(NativeProcessError::Stale)?;
        let mut comm = [0; 16];
        let length = basename.len().min(comm.len() - 1);
        comm[..length].copy_from_slice(&basename[..length]);
        Ok(comm)
    }
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
    pub(super) fn release_service_claim(
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
        self.begin_service_inner(operation, fault_sequence, None, None, false)
    }
    /// Supply one nonresident user page needed to stage an exec request, then
    /// retry the exact SVC. A refused supply remains an ordinary `EFAULT` from
    /// exec rather than becoming a user data-abort signal.
    pub fn begin_exec_stage_fault_service(
        &mut self,
        fault: carrick_guest_arch::FaultInfo,
        fault_sequence: Option<core::num::NonZeroU64>,
        owner_wait: Option<carrick_core_abi::PortalOwnerWait>,
    ) -> Result<NativeResume, NativeProcessError> {
        self.begin_service_inner(
            ServiceOperation::Fault(fault),
            fault_sequence,
            owner_wait,
            None,
            true,
        )
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
            false,
        )
    }
    /// Park the exact ring operation on the producer observed before its
    /// failed admission. No physical service notice is published.
    pub fn begin_owner_service_wait(
        &mut self,
        operation: ServiceOperation,
        wait: carrick_core_abi::PortalOwnerWait,
    ) -> Result<NativeResume, NativeProcessError> {
        self.begin_service_inner(operation, None, Some(wait), None, false)
    }
    #[inline(never)]
    fn begin_service_inner(
        &mut self,
        operation: ServiceOperation,
        fault_sequence: Option<core::num::NonZeroU64>,
        owner_wait: Option<carrick_core_abi::PortalOwnerWait>,
        exec_payload: Option<Box<[u8]>>,
        retry_syscall_after_supply: bool,
    ) -> Result<NativeResume, NativeProcessError> {
        if matches!(operation, ServiceOperation::Exec { .. }) != exec_payload.is_some() {
            return Err(NativeProcessError::Stale);
        }
        let (page, control, mm) = {
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
            (resources.page, member.control.clone(), resources.mm.clone())
        };
        let birth =
            match control
                .service
                .bound_birth(self.key, self.binding.thread_generation, self.record)
            {
                Ok(birth) => birth,
                Err(ServiceError::Busy) => {
                    // Fork binds a child's service cell at publication. The root
                    // has no earlier physical-service venue, so its first exact
                    // registered operation binds the same retained capability.
                    let handle = self.service.service_mm_handle(&mm)?;
                    let wait = ObjectWaitKey::native_service(self.record)
                        .ok_or(NativeProcessError::Stale)?;
                    self.source
                        .zone
                        .bind_object_wait(wait, &carrick_sched_core::ShortLockSpin)
                        .map_err(|_| NativeProcessError::Quarantined)?;
                    control
                        .service
                        .bind(carrick_core_abi::service::ServiceBirth {
                            process: self.key,
                            thread: self.binding.thread_generation,
                            record: self.record,
                            mm: handle,
                        })
                        .map_err(service_error)?;
                    control
                        .service
                        .bound_birth(self.key, self.binding.thread_generation, self.record)
                        .map_err(service_error)?
                }
                Err(error) => return Err(service_error(error)),
            };
        let exec_successor = matches!(operation, ServiceOperation::Exec { .. })
            .then(|| {
                self.runtime
                    .zone
                    .mm_issuer()
                    .allocate()
                    .and_then(|mm| carrick_core_abi::ReservationMm::new(mm.raw().get()))
                    .ok_or(NativeProcessError::Exhausted)
                    .and_then(|mm| self.service.prepare_exec_successor_slot(mm))
            })
            .transpose()?;
        let carrier_continuation =
            matches!(operation, ServiceOperation::CarrierWork { .. }).then(|| {
                if self.owns_parked_operation() {
                    CarrierContinuation::Parked(self.key)
                } else {
                    CarrierContinuation::Completed(SyscallResult::new(
                        self.words.syscall_return() as i64
                    ))
                }
            });
        let mut reply = match operation {
            ServiceOperation::Fault(fault) if !fault.present && fault_sequence.is_some() => {
                Some(PendingServiceReply::Fault(
                    FallibleBox::<carrick_el1_abi::PortalGrantSlot>::try_reserve()?.zeroed(),
                ))
            }
            ServiceOperation::Exec { .. } => Some(PendingServiceReply::Exec(
                FallibleBox::<ExecSuccessorManifest>::try_reserve()?.zeroed(),
            )),
            _ => None,
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
                        reply.as_ref().map(PendingServiceReply::address),
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
        if let Some(PendingServiceReply::Exec(manifest)) = reply.as_mut() {
            **manifest = ExecSuccessorManifest::propose(
                request.identity,
                exec_successor
                    .as_ref()
                    .ok_or(NativeProcessError::Stale)?
                    .mm(),
                exec_successor
                    .as_ref()
                    .ok_or(NativeProcessError::Stale)?
                    .root_generation(),
            );
        }
        self.runtime.graph.lock().insert_member_wait(
            self.record,
            MemberWait::Service(Box::new(PendingService {
                reply,
                _exec_payload: exec_payload,
                exec_successor,
                retry_syscall_after_supply,
                carrier_continuation,
                request,
                wait: owner_wait,
                claim,
                control,
            })),
        );
        drop(owner_queue);
        if let Some(wait) = owner_wait {
            return self.park_owner_wait(&request, wait);
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
        self.park_service(&request)
    }

    // The caller retains the request snapshot through nested completion. Borrow
    // its full birth/MM identity instead of retaining another aggregate copy.
    #[inline(never)]
    fn park_service(
        &mut self,
        request: &ServiceRequest,
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
            _ if self
                .runtime
                .graph
                .lock()
                .service_wait(&self.record)
                .is_some_and(|pending| pending.retry_syscall_after_supply) =>
            {
                OwnerEntry::Syscall
            }
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
            self.finish_owner_wait(&request)
        } else {
            self.park_service(&request)
        })
    }

    #[inline(never)]
    fn park_owner_wait(
        &mut self,
        request: &ServiceRequest,
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
        request: &ServiceRequest,
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

    /// Publish the already-installed successor through the graph, registry,
    /// scheduler record and current-task projection as one owned cutover.
    /// Every fallible validation is complete before this is called.
    #[inline(never)]
    fn commit_exec_successor(
        &mut self,
        successor: NativeExecSuccessor<M, C>,
        service_rebind: carrick_core_abi::service::PreparedExecServiceRebind<'_>,
        comm: [u8; 16],
        validated: Box<ValidatedExecSuccessor<'a>>,
    ) -> Result<(), NativeProcessError> {
        let registry = self
            .runtime
            .registry
            .lock()
            .ok_or(NativeProcessError::Stale)?;
        let mut state = registry.state.lock();
        let record = self.source.zone.record(self.record.id);
        let old_key = *state
            .records
            .get(&validated.record_key)
            .filter(|key| **key == validated.old_key)
            .ok_or(NativeProcessError::Stale)?;
        let old_member = state
            .members
            .get(&old_key)
            .cloned()
            .ok_or(NativeProcessError::Stale)?;
        if old_member.process != self.key
            || old_member.record != self.record
            || old_member.address != self.caller_address
            || successor.address.mm.raw().get() != validated.new_key.mm
            || successor.address.root.address().raw() != validated.new_key.root
            || successor.address.generation.raw().get() != validated.new_key.address_generation
            || record.identity() != validated.old_record_identity
            || self.control.visible_tid() != Some(self.calling_tid)
        {
            return Err(NativeProcessError::Stale);
        }
        let leader = self.key.id;
        let next_generation = validated
            .new_key
            .task
            .issued()
            .ok_or(NativeProcessError::Stale)?
            .generation;
        if old_key != validated.new_key && state.members.contains_key(&validated.new_key) {
            return Err(NativeProcessError::Busy);
        }
        let mut graph = self.runtime.graph.lock();
        let row = graph
            .owner
            .task_mut(self.key)
            .map_err(|_| NativeProcessError::Stale)?;
        if row.metadata().namespace_pid != validated.leader_tid {
            return Err(NativeProcessError::Stale);
        }
        let caller = row
            .threads
            .threads
            .iter()
            .find(|thread| thread.tid == self.calling_tid)
            .cloned()
            .ok_or(NativeProcessError::Stale)?;
        if caller.credentials != validated.caller_credentials {
            return Err(NativeProcessError::Stale);
        }
        {
            let resources = row.native_mut().resources_mut();
            if resources.members.len() != 1
                || resources.members[0].record != self.record
                || resources.address != self.caller_address
                || !core::ptr::eq(resources.page, validated.page)
                || resources.file_table != validated.file_table
            {
                return Err(NativeProcessError::Busy);
            }
        }
        let (old_group, keys) = state
            .by_process
            .get(&(old_key.carrier, self.key))
            .cloned()
            .ok_or(NativeProcessError::Stale)?;
        if old_group != validated.old_group
            || keys.as_slice() != [old_key]
            || !state.groups.contains_key(&validated.old_group)
        {
            return Err(NativeProcessError::Busy);
        }
        let mut member = old_member.clone();

        // All lookups and equality checks are complete.  The closed gate and
        // exact OnCpu ownership make the following stores one non-refusing
        // publication sequence.
        let resources = row.native_mut().resources_mut();
        resources.mm = successor.mm.clone();
        resources.address = successor.address;
        resources.interrupted_child_waits.clear();
        resources.pending_child_tid = None;
        resources.signals.reset_for_exec_survivor(self.record);
        resources.members[0].thread = validated.new_key.task;
        *row.context_mut() = *successor.words;
        row.threads = GuestThreads {
            threads: vec![GuestThreadState {
                tid: validated.leader_tid,
                credentials: caller.credentials,
                comm,
            }],
        };
        let diagnostic_length = comm.iter().position(|byte| *byte == 0).unwrap_or(15);
        row.metadata_mut().diagnostic_name = core::str::from_utf8(&comm[..diagnostic_length])
            .map(alloc::string::String::from)
            .unwrap_or_default();
        row.has_execed = true;
        row.dumpable = 1;

        member.address = successor.address;
        let _ = state.members.remove(&old_key);
        state
            .records
            .insert(validated.record_key, validated.new_key);
        state.members.insert(validated.new_key, member);
        state.groups.remove(&validated.old_group);
        state
            .groups
            .insert(validated.new_group, (old_member.runtime.clone(), self.key));
        state.by_process.insert(
            (validated.new_key.carrier, self.key),
            (validated.new_group, vec![validated.new_key]),
        );

        // SAFETY: validation above proved this exact predecessor identity and
        // the closed process owns the sole live member.
        unsafe {
            self.control
                .promote_exec_identity_owned(validated.leader_tid);
        }
        self.control.set_robust_list(0, 0);
        self.control.set_clear_child_tid(0);
        self.control
            .write_altstack(carrick_personality_linux::abi::thread::AltStack::DISABLED);
        let mut new_record_identity = validated.old_record_identity;
        new_record_identity.tid = leader.raw() as u64;
        new_record_identity.mm = successor.address.mm.raw().get();
        new_record_identity.generation = next_generation.raw();
        // SAFETY: this entry owns the exact OnCpu record and checked its old
        // registry identity under both owner locks.
        unsafe {
            record.rebind_exec_owned(new_record_identity);
        }
        // SAFETY: the same OnCpu custody gives exclusive context access.
        unsafe {
            *self.source.zone.record(self.record.id).ctx_mut() = *successor.words;
        }
        self.current.set(
            carrick_el1_abi::El1TaskId::from(leader),
            next_generation,
            validated.file_table,
        );
        self.current.mm.key.store(
            successor.address.mm.raw().get(),
            core::sync::atomic::Ordering::Release,
        );
        self.current
            .publish_root_generation(successor.address.generation);
        service_rebind.commit();
        self.binding.task = carrick_core_abi::EntryTaskKey::from_raw(leader.raw() as u64);
        self.binding.generation = next_generation;
        self.binding.mm = carrick_core_abi::EntryMmKey::from_raw(successor.address.mm.raw().get());
        self.calling_tid = validated.leader_tid;
        self.caller_address = successor.address;
        self.words = successor.words;
        Ok(())
    }

    /// Prove every fallible graph and scheduler condition before the consuming
    /// host adoption crossing. The exec-draining lifecycle gate and sole-member
    /// check keep these rows stable until `commit_exec_successor` publishes.
    #[inline(never)]
    fn validate_exec_successor(
        &self,
        address: AddressContext<RootGpa>,
    ) -> Result<Box<ValidatedExecSuccessor<'a>>, NativeProcessError> {
        let registry = self
            .runtime
            .registry
            .lock()
            .ok_or(NativeProcessError::Stale)?;
        let state = registry.state.lock();
        let record_key = NativeProcessRegistry::<M, C>::record_key(self.source.zone, self.record);
        let old_key = *state
            .records
            .get(&record_key)
            .ok_or(NativeProcessError::Stale)?;
        let old_member = state
            .members
            .get(&old_key)
            .ok_or(NativeProcessError::Stale)?;
        if old_member.process != self.key || old_member.record != self.record {
            return Err(NativeProcessError::Stale);
        }
        let next_generation = old_key
            .task
            .issued()
            .and_then(|issued| issued.generation.raw().checked_add(1))
            .filter(|generation| *generation != 0)
            .map(carrick_core_abi::SnapshotGeneration::from_raw)
            .ok_or(NativeProcessError::Exhausted)?;
        let new_key = NativeExecutionKey {
            carrier: old_key.carrier,
            task: NativeThreadIdentity::Issued(IssuedExecution {
                id: self.key.id,
                generation: next_generation,
            }),
            thread_generation: old_key.thread_generation,
            mm: address.mm.raw().get(),
            root: address.root.address().raw(),
            address_generation: address.generation.raw().get(),
        };
        if old_key != new_key && state.members.contains_key(&new_key) {
            return Err(NativeProcessError::Busy);
        }
        let (old_group, keys) = state
            .by_process
            .get(&(old_key.carrier, self.key))
            .ok_or(NativeProcessError::Stale)?;
        if keys.as_slice() != [old_key]
            || self.control.visible_tid() != Some(self.calling_tid)
            || self.source.zone.record(self.record.id).identity().tid != self.calling_tid as u64
        {
            return Err(NativeProcessError::Busy);
        }
        let graph = self.runtime.graph.lock();
        let row = graph
            .owner
            .task(self.key)
            .map_err(|_| NativeProcessError::Stale)?;
        let resources = row.native().resources();
        if resources.members.len() != 1
            || resources.members[0].record != self.record
            || resources.address != self.caller_address
            || row
                .threads
                .threads
                .iter()
                .all(|thread| thread.tid != self.calling_tid)
        {
            return Err(NativeProcessError::Busy);
        }
        let leader_tid = row.metadata().namespace_pid;
        let caller_credentials = row
            .threads
            .threads
            .iter()
            .find(|thread| thread.tid == self.calling_tid)
            .ok_or(NativeProcessError::Stale)?
            .credentials
            .clone();
        let new_group = NativeProcessRegistry::<M, C>::group_key(
            self.source.zone,
            address,
            resources.page,
            leader_tid,
        );
        Ok(Box::new(ValidatedExecSuccessor {
            old_record_identity: self.source.zone.record(self.record.id).identity(),
            record_key,
            old_key,
            new_key,
            old_group: *old_group,
            new_group,
            leader_tid,
            caller_credentials,
            page: resources.page,
            file_table: resources.file_table,
        }))
    }

    /// A prepared exec refusal is a process outcome, not a carrier failure.
    /// Exec never returns to the losing caller: once preparation was accepted,
    /// an authentication/adoption race retires it through the same SIGKILL
    /// close transaction used for a losing sibling.
    #[inline(never)]
    fn kill_refused_exec(&mut self) -> NativeResume {
        if self
            .exit_with_signal(carrick_signal_core::policy::Signal::KILL.number() as u8)
            .is_ok()
        {
            return NativeResume::Left(None);
        }
        // A concurrent terminal transition can consume the direct exit
        // admission.  Drive its already-owned lifecycle continuation instead
        // of escalating one process's failed exec into a carrier failure.
        let _ = self.resume_pending_lifecycle();
        if self.handoff.is_some() {
            NativeResume::Left(None)
        } else {
            let _ = self.run_failed(NativeProcessError::Quarantined.run_failure_reason());
            NativeResume::Left(None)
        }
    }

    #[inline(never)]
    fn cancel_refused_exec(
        &mut self,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
        claim: carrick_core::terminal::NativeServiceClaim<&'a ThreadLifecyclePage>,
    ) -> NativeResume {
        let cancelled = self.service.cancel_exec_successor(receipt);
        let released = self.release_service_claim(claim);
        if let Err(error) = cancelled.and(released) {
            let _ = self.run_failed(error.run_failure_reason());
            return NativeResume::Left(None);
        }
        self.kill_refused_exec()
    }

    #[inline(never)]
    fn complete_exec_prepared(
        &mut self,
        request: ServiceRequest,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
        mut pending: Box<PendingService<'a>>,
    ) -> Result<NativeResume, NativeProcessError> {
        let manifest = match pending.reply.as_ref() {
            Some(PendingServiceReply::Exec(manifest)) => &**manifest,
            _ => {
                return Ok(self.cancel_refused_exec(receipt, pending.claim));
            }
        };
        let Some(sealed) = manifest.open(request.identity, receipt) else {
            return Ok(self.cancel_refused_exec(receipt, pending.claim));
        };
        let Some(mm) = NonZeroU64::new(sealed.successor_mm.raw()) else {
            return Ok(self.cancel_refused_exec(receipt, pending.claim));
        };
        if pending.exec_successor.as_ref().is_none_or(|slot| {
            slot.mm() != sealed.successor_mm || slot.root_generation() != sealed.root_generation
        }) {
            return Ok(self.cancel_refused_exec(receipt, pending.claim));
        }
        let expected_address = AddressContext {
            root: sealed.root,
            mm: MmGeneration::new(mm),
            generation: carrick_guest_arch::ContextGeneration::new(sealed.root_generation),
        };
        let comm = match pending.exec_comm() {
            Ok(comm) => comm,
            Err(error) => {
                let _ = error;
                return Ok(self.cancel_refused_exec(receipt, pending.claim));
            }
        };
        let validated = match self.validate_exec_successor(expected_address) {
            Ok(validated) => validated,
            Err(error) => {
                let _ = error;
                return Ok(self.cancel_refused_exec(receipt, pending.claim));
            }
        };
        let prepared_fds = {
            let graph = self.runtime.graph.lock();
            let resources = match graph.owner.task(self.key) {
                Ok(row) => row.native().resources(),
                Err(_) => {
                    drop(graph);
                    return Ok(self.cancel_refused_exec(receipt, pending.claim));
                }
            };
            if resources.members.len() != 1 {
                drop(graph);
                return Ok(self.cancel_refused_exec(receipt, pending.claim));
            }
            let result = resources.prepare_close_on_exec(
                self.key,
                self.service.exec_fd_map(),
                self.service.exec_open_table(),
            );
            if result.is_err() {
                drop(result);
                return Ok(self.cancel_refused_exec(receipt, pending.claim));
            }
            match result {
                Ok(prepared) => prepared,
                Err(_) => return Err(NativeProcessError::Quarantined),
            }
        };
        let Some(successor_slot) = pending.exec_successor.as_ref() else {
            drop(prepared_fds);
            return Ok(self.cancel_refused_exec(receipt, pending.claim));
        };
        let successor_service = match successor_slot.prepare_adoption() {
            Ok(handle) => handle,
            Err(error) => {
                drop(prepared_fds);
                let _ = error;
                return Ok(self.cancel_refused_exec(receipt, pending.claim));
            }
        };
        let rebind_control = pending.control.clone();
        let service_rebind = match rebind_control
            .service
            .prepare_exec_rebind(request.identity.birth, successor_service)
        {
            Ok(prepared) => prepared,
            Err(error) => {
                drop(prepared_fds);
                let _ = error;
                return Ok(self.cancel_refused_exec(receipt, pending.claim));
            }
        };
        let successor = match self
            .service
            .adopt_exec_successor(request.identity, receipt, manifest)
        {
            Ok(successor) => successor,
            Err(error) => {
                drop(prepared_fds);
                let _ = error;
                return Ok(self.cancel_refused_exec(receipt, pending.claim));
            }
        };
        let Some(successor_slot) = pending.exec_successor.take() else {
            drop(prepared_fds);
            let _ = self.release_service_claim(pending.claim);
            return Ok(self.kill_refused_exec());
        };
        successor_slot.commit();
        if successor.address != expected_address {
            drop(prepared_fds);
            let _ = self.release_service_claim(pending.claim);
            return Ok(self.kill_refused_exec());
        }
        let predecessor = self.caller_address;
        let successor_address = successor.address;
        let (_table, releases) = carrick_fd_core::exec::commit(prepared_fds);
        drop(releases);
        if self
            .commit_exec_successor(successor, service_rebind, comm, validated)
            .is_err()
            || self
                .service
                .finish_exec_successor(predecessor, successor_address)
                .is_err()
        {
            let _ = self.release_service_claim(pending.claim);
            return Ok(self.kill_refused_exec());
        }
        self.release_service_claim(pending.claim)?;
        Ok(NativeResume::NoPending)
    }

    #[inline(never)]
    fn park_exec_closing(
        &mut self,
        channel: &Arc<WaitChannel>,
    ) -> Result<bool, NativeProcessError> {
        let zone = self.source.zone;
        let record = zone
            .slot(self.source.slot)
            .current()
            .or_else(|| zone.slot(self.source.slot).host_record())
            .ok_or(NativeProcessError::Quarantined)?;
        let start = carrick_core::entry::prepare_handoff(self.binding, self.source, record)
            .ok_or(NativeProcessError::Quarantined)?;
        let address = WaitChannel::address(channel);
        let guard = zone.short_lock(
            ZoneTables::<C>::bucket_of_with_context(channel.mm, address),
            &NativeBucketWait {
                lifetime: core::marker::PhantomData,
                #[cfg(test)]
                probe: self.publication_wait_probe,
            },
        );
        let ready = {
            let graph = self.runtime.graph.lock();
            let page = graph
                .owner
                .task(self.key)
                .map_err(|_| NativeProcessError::Stale)?
                .native()
                .resources()
                .page;
            graph.pending.exit(&self.key).is_some_and(|pending| {
                pending.exec().is_some()
                    && core::ptr::eq(pending.caller.control(), self.control)
                    && pending.ready_or_record(page, true)
            })
        };
        if ready {
            return Ok(false);
        }
        let sequence = zone.next_seq(record);
        zone.enqueue(&guard, record, sequence, channel.mm, address, u32::MAX, 0)
            .map_err(|_| NativeProcessError::Quarantined)?;
        // SAFETY: this entry still owns the current record through the guarded
        // park publication.
        unsafe {
            *zone.record(record).ctx_mut() = *self.words;
            zone.record(record)
                .publish_owner_continuation(OwnerEntry::Syscall);
        }
        let receipt = carrick_core::entry::publish_handoff_park(
            start,
            &guard,
            carrick_el1_abi::EntryRecordGeneration(sequence),
        )
        .ok_or(NativeProcessError::Quarantined)?;
        drop(guard);
        zone.clear_current(self.source.slot);
        self.handoff = Some(receipt);
        Ok(true)
    }

    fn finish_exec_closing_ready(
        &mut self,
        page: &ThreadLifecyclePage,
    ) -> Result<NativeResume, NativeProcessError> {
        let (pending, settled) = self
            .runtime
            .graph
            .lock()
            .pending
            .remove_settled_exec(&self.key, page)
            .ok_or(NativeProcessError::Stale)?;
        page.clear_exit_wait();
        page.await_exec_binding_after_close()
            .map_err(|_| NativeProcessError::Stale)?;
        let result = self.complete_exec_prepared(pending.request, pending.receipt, pending.pending);
        if matches!(result, Ok(NativeResume::NoPending)) {
            // Only a committed successor reopens admission. A refused exec is
            // converted into process closing and must never resurrect the
            // predecessor gate.
            if settled.retract_exec_cancellation(page).is_err() {
                return Ok(self.kill_refused_exec());
            }
            page.reopen_after_exec_binding()
                .map_err(|_| NativeProcessError::Stale)?;
        }
        result
    }

    pub(super) fn resume_exec_closing(
        &mut self,
    ) -> Option<Result<NativeResume, NativeProcessError>> {
        let (page, channel) = {
            let graph = self.runtime.graph.lock();
            let pending = graph.pending.exit(&self.key)?;
            pending.exec()?;
            if !core::ptr::eq(pending.caller.control(), self.control) {
                return Some(Err(NativeProcessError::Stale));
            }
            let page = graph.owner.task(self.key).ok()?.native().resources().page;
            (page, pending.channel.clone())
        };
        // SAFETY: this exact record resumed the owned exec continuation.
        unsafe {
            self.source
                .zone
                .record(self.record.id)
                .consume_owner_continuation();
        }
        Some(match self.park_exec_closing(&channel) {
            Ok(true) => Ok(NativeResume::Left(None)),
            Ok(false) => self.finish_exec_closing_ready(page),
            Err(error) => Err(error),
        })
    }

    #[inline(never)]
    fn finish_service(
        &mut self,
        request: &ServiceRequest,
        mut result: ServiceResult,
        mut pending: Box<PendingService<'a>>,
    ) -> Result<NativeResume, NativeProcessError> {
        if pending.request != *request {
            return Err(NativeProcessError::Quarantined);
        }
        let retry_syscall_after_supply = pending.retry_syscall_after_supply;
        if self.runtime.graph.lock().pending.has_exit(&self.key) {
            if let (ServiceOperation::Exec { .. }, ServiceResult::ExecPrepared(receipt)) =
                (request.operation, result)
            {
                self.service.cancel_exec_successor(receipt)?;
            }
            // The terminal checkpoint must consume both winner and losing
            // caller custody; none may return a cancelled service to EL0.
            unsafe {
                self.source
                    .zone
                    .record(self.record.id)
                    .publish_owner_continuation(if retry_syscall_after_supply {
                        OwnerEntry::Syscall
                    } else {
                        match request.operation {
                            ServiceOperation::Fault(_) | ServiceOperation::Exception(_) => {
                                OwnerEntry::Exception
                            }
                            ServiceOperation::Crossing { .. } | ServiceOperation::Exec { .. } => {
                                OwnerEntry::Syscall
                            }
                            ServiceOperation::CarrierWork { entry } => entry,
                        }
                    });
            }
            self.release_service_claim(pending.claim)?;
            return Ok(NativeResume::NoPending);
        }
        if result == ServiceResult::Supplied
            && let Some(PendingServiceReply::Fault(reply)) = &pending.reply
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
                    return self.park_owner_wait(&next, wait);
                }
                Err(_) => result = ServiceResult::Refused,
            }
        }
        if let (ServiceOperation::Exec { .. }, ServiceResult::ExecPrepared(receipt)) =
            (request.operation, result)
        {
            // SAFETY: completion belongs to this exact selected record. A
            // drain publishes a new owned continuation before giving up CPU.
            unsafe {
                self.source
                    .zone
                    .record(self.record.id)
                    .consume_owner_continuation();
            }
            let (page, channel) =
                self.begin_closing(PendingCloseOperation::Exec(PendingExecAdoption {
                    request: *request,
                    receipt,
                    pending,
                }))?;
            let started = self
                .runtime
                .graph
                .lock()
                .pending
                .exit(&self.key)
                .is_some_and(|pending| {
                    pending.exec().is_some()
                        && core::ptr::eq(pending.caller.control(), self.control)
                });
            if !started {
                return Ok(NativeResume::NoPending);
            }
            self.current.linux.mark_pending_host_work();
            return if self.park_exec_closing(&channel)? {
                Ok(NativeResume::Left(None))
            } else {
                self.finish_exec_closing_ready(page)
            };
        }
        // SAFETY: completion belongs to this exact selected record.
        unsafe {
            self.source
                .zone
                .record(self.record.id)
                .consume_owner_continuation();
        }
        let completed = (|| {
            if retry_syscall_after_supply {
                return match result {
                    ServiceResult::Supplied => Ok(NativeResume::RetrySyscall),
                    ServiceResult::Refused
                    | ServiceResult::BackingFault
                    | ServiceResult::Cancelled
                    | ServiceResult::Failed(_) => Ok(NativeResume::Returned(SyscallResult::new(
                        carrick_syscall_abi::LINUX_EFAULT.guest_retval(),
                    ))),
                    ServiceResult::Wait(_) | ServiceResult::ExecPrepared(_) => {
                        Err(NativeProcessError::Quarantined)
                    }
                };
            }
            match (request.operation, result) {
                (_, ServiceResult::Wait(_)) => Err(NativeProcessError::Quarantined),
                (
                    ServiceOperation::CarrierWork { .. },
                    ServiceResult::Supplied | ServiceResult::Cancelled,
                ) => {
                    match pending.carrier_continuation {
                        // Committed bytes/results survive readiness and cancellation.
                        Some(CarrierContinuation::Completed(result)) => {
                            Ok(NativeResume::Returned(result))
                        }
                        Some(CarrierContinuation::Parked(caller))
                            if caller == self.key && self.owns_parked_operation() =>
                        {
                            // Re-drive after releasing the service claim below.
                            // No scheduling scalar can complete this operation.
                            Ok(NativeResume::NoPending)
                        }
                        _ => Err(NativeProcessError::Quarantined),
                    }
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
                (ServiceOperation::Exec { .. }, ServiceResult::ExecPrepared(_)) => {
                    Err(NativeProcessError::Quarantined)
                }
                (_, ServiceResult::ExecPrepared(_)) => Err(NativeProcessError::Quarantined),
                (ServiceOperation::Exec { .. }, ServiceResult::Refused) => {
                    Ok(NativeResume::Returned(SyscallResult::new(
                        carrick_syscall_abi::LINUX_ENOSYS.guest_retval(),
                    )))
                }
                (ServiceOperation::Exec { .. }, ServiceResult::Cancelled) => {
                    // An exec cancellation is published only by process closing.
                    // The caller is being retired and must never observe EINTR.
                    Ok(NativeResume::NoPending)
                }
            }
        })();
        // Mapping/signal completion still needs the exact member/MM. Release
        // terminal custody only after the ring has made that decision.
        let redrive = matches!(
            pending.carrier_continuation,
            Some(CarrierContinuation::Parked(_))
        ) && matches!(completed, Ok(NativeResume::NoPending));
        self.release_service_claim(pending.claim)?;
        if redrive {
            // Also covers an ACK already ready at enrollment: that caller does
            // not pass through resume_checkpoint before returning to EL0.
            // The retained wait/IPC owner alone commits effects and its result.
            return match self.resume_pending_wait() {
                Some(LifecycleOutcome::Returned { result, .. }) => {
                    Ok(NativeResume::Returned(result))
                }
                Some(LifecycleOutcome::Transferred {
                    progress: carrick_core::Served::Idle,
                    ..
                }) => Ok(NativeResume::Left(None)),
                _ => Err(NativeProcessError::Quarantined),
            };
        }
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
