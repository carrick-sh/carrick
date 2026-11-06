//! Native-member service continuations. Slot custody ends at park; semantic
//! process/MM custody ends only after the exact external acknowledgment.
use super::*;
use crate::process_owner::{GuestThreadState, GuestThreads};
use carrick_core_abi::service::{
    ExecSuccessorManifest, ServiceError, ServiceOperation, ServiceRequest, ServiceResult,
};
use carrick_sched_core::object_wait::{ObjectWaitKey, OperationToken};

/// Publish one exact member's retained service capability before execution,
/// or at the first service entry of an already authenticated host member.
pub(super) fn bind_member_service<C: ProcessContext>(
    zone: &ZoneTables<C>,
    process: TaskKey,
    origin: carrick_core_abi::service::ServiceOrigin,
    record: RecordRef,
    thread: carrick_core_abi::EntryThreadGeneration,
    control: &ThreadControlSlot,
    mm: carrick_el1_abi::El1MmHandle,
) -> Result<(), NativeProcessError> {
    bind_member_service_queue(zone, record)?;
    control.bind_zone_record(record);
    control
        .service
        .bind(carrick_core_abi::service::ServiceBirth {
            origin,
            process,
            thread,
            record,
            mm,
        })
        .map_err(service_protocol_error)
}

fn bind_member_service_queue<C: ProcessContext>(
    zone: &ZoneTables<C>,
    record: RecordRef,
) -> Result<(), NativeProcessError> {
    let wait = ObjectWaitKey::native_service(record).ok_or(NativeProcessError::Stale)?;
    if zone
        .object_wait(wait, &carrick_sched_core::ShortLockSpin)
        .is_ok()
    {
        return Ok(());
    }
    zone.bind_object_wait(wait, &carrick_sched_core::ShortLockSpin)
        .map_err(|_| NativeProcessError::Quarantined)
}

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

/// Only the access admission funnel constructs this error. Returning it as
/// a syscall result cannot lose a routing refusal's census evidence.
pub(super) struct CallerAccessFailure(SyscallResult);

impl core::fmt::Debug for CallerAccessFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("CallerAccessFailure")
            .field(&self.0)
            .finish()
    }
}

impl CallerAccessFailure {
    pub(super) fn into_resume(self) -> NativeResume {
        NativeResume::Returned(self.0)
    }
}

enum PreparedService {
    Request(ServiceRequest, bool),
    Retired(NativeResume),
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

/// A staged host-file crossing: the ring-owned request/reply record (its
/// address is published in the request) and the user output it fills.
struct PendingHostFile<'a> {
    call: NativeServiceCall<'a>,
    record: Box<[u8]>,
    output: Option<carrick_personality_linux::native_host_file::HostFileOutput>,
    map: Option<carrick_personality_linux::native_host_file::NativeMapKey>,
    /// A chdir lookup: completion stores the named directory as the
    /// caller's cwd.
    chdir: bool,
}

/// Ring-owned input of a typed service, retained until completion ACK.
pub(super) struct OwnedCopyout {
    pub address: UserVa,
    pub bytes: Vec<u8>,
    pub offset: usize,
    pub result: SyscallResult,
}

/// Physical preparation is enrolled only after the IPC dispatch stack unwinds.
pub(super) struct AdapterPreparation {
    pub service: ServiceOperation,
    pub sequence: Option<NonZeroU64>,
    pub identity: carrick_sched_core::object_wait::OperationIdentity,
}

enum ServicePayload<'a> {
    None,
    Copyin,
    Copyout(OwnedCopyout),
    Adapter,
    Exec(Box<[u8]>),
    HostFile(PendingHostFile<'a>),
}

pub(super) struct PendingService<'a> {
    reply: Option<PendingServiceReply>,
    /// Exec input is ring-owned guest memory. Its virtual address is published
    /// in the request and cannot be recycled until completion/cancellation ACK.
    _exec_payload: Option<Box<[u8]>>,
    /// The same custody for a host-file record, which the carrier also writes.
    host_file: Option<PendingHostFile<'a>>,
    copyout: Option<Box<OwnedCopyout>>,
    copyin: bool,
    adapter: bool,
    exec_successor: Option<Box<dyn ExecSuccessorSlot + 'a>>,
    retry_syscall_after_supply: bool,
    carrier_continuation: Option<CarrierContinuation>,
    request: ServiceRequest,
    pub(super) wait: Option<carrick_core_abi::PortalOwnerWait>,
    pub(super) claim: carrick_core::terminal::NativeServiceClaim<&'a ThreadLifecyclePage>,
    control: Arc<carrick_core::lifecycle::MemberControlCustody<'a, ThreadControlSlot>>,
}

impl PendingService<'_> {
    /// A caught signal interrupts a guest wait, not an internal obligation
    /// that must finish before its committed context can return to user code.
    fn signal_interruptible(&self) -> bool {
        self.copyout.is_none()
            && !self.copyin
            && !self.adapter
            && !matches!(self.request.operation, ServiceOperation::CarrierWork { .. })
    }
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
        exec_comm_of(view).ok_or(NativeProcessError::Stale)
    }
}

/// The successor's `comm`: the basename of the name Linux gives the
/// program. An `execveat(fd, "", AT_EMPTY_PATH)` (`fexecve`) names it
/// `/dev/fd/<fd>`, so its comm is the descriptor number; it used to be an
/// empty basename here, which refused the already-committed exec and killed
/// the successor (#1530).
fn exec_comm_of(view: carrick_core_abi::service::ExecPayloadView<'_>) -> Option<[u8; 16]> {
    use carrick_core_abi::service::ExecCall;
    let mut descriptor = [0u8; 11];
    let path = match view.call() {
        ExecCall::Execveat { dirfd, flags }
            if view.path().is_empty() && flags & carrick_abi::LINUX_AT_EMPTY_PATH as u32 != 0 =>
        {
            let mut cursor = descriptor.len();
            let mut value = u32::try_from(dirfd).ok()?;
            loop {
                cursor -= 1;
                descriptor[cursor] = b'0' + (value % 10) as u8;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            &descriptor[cursor..]
        }
        _ => view.path(),
    };
    let basename = path
        .rsplit(|byte| *byte == b'/')
        .next()
        .filter(|name| !name.is_empty())?;
    let mut comm = [0; 16];
    let length = basename.len().min(comm.len() - 1);
    comm[..length].copy_from_slice(&basename[..length]);
    Some(comm)
}

#[cfg(test)]
mod exec_comm_tests {
    use super::exec_comm_of;
    use carrick_core_abi::service::{EXEC_PAYLOAD_HEADER_BYTES, ExecCall, ExecPayloadView};

    fn payload(call: ExecCall, path: &str) -> std::vec::Vec<u8> {
        let mut bytes = std::vec![0; EXEC_PAYLOAD_HEADER_BYTES];
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        carrick_core_abi::service::encode_exec_payload_header(
            &mut bytes,
            call,
            path.len() + 1,
            0,
            0,
        )
        .unwrap();
        bytes
    }

    fn comm(call: ExecCall, path: &str) -> Option<std::string::String> {
        let bytes = payload(call, path);
        let comm = exec_comm_of(ExecPayloadView::parse(&bytes).unwrap())?;
        let end = comm
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(comm.len());
        Some(std::string::String::from_utf8(comm[..end].to_vec()).unwrap())
    }

    /// Linux names an `fexecve`'d program `/dev/fd/<fd>`: its comm is the
    /// descriptor number, never an empty name that refuses the exec.
    #[test]
    fn fexecve_comm_is_the_descriptor_number() {
        let at_empty = carrick_abi::LINUX_AT_EMPTY_PATH as u32;
        assert_eq!(
            comm(
                ExecCall::Execveat {
                    dirfd: 3,
                    flags: at_empty
                },
                ""
            ),
            Some("3".into())
        );
        assert_eq!(
            comm(
                ExecCall::Execveat {
                    dirfd: 1234,
                    flags: at_empty
                },
                ""
            ),
            Some("1234".into())
        );
        assert_eq!(comm(ExecCall::Execve, "/usr/bin/dash"), Some("dash".into()));
        assert_eq!(
            comm(
                ExecCall::Execveat {
                    dirfd: -100,
                    flags: 0
                },
                "/bin/averyveryverylongname"
            ),
            Some("averyveryverylo".into())
        );
        // A path that names no file (a trailing slash) still has no comm.
        assert_eq!(comm(ExecCall::Execve, "/bin/"), None);
    }
}

enum ServiceCompletion {
    Inline,
    RetrySyscall,
    OwnerCheckpoint,
}

impl ServiceCompletion {
    fn retries_syscall(&self) -> bool {
        matches!(self, Self::RetrySyscall)
    }

    fn checkpoints_owner(&self) -> bool {
        matches!(self, Self::OwnerCheckpoint)
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
            .filter(|pending| {
                pending.signal_interruptible() || pending.claim.cancellation().is_some()
            })
            .map(|pending| (pending.request, pending.control.clone(), pending.adapter));
        let Some((request, control, adapter)) = pending else {
            // Scalar IPC has a retained adapter token, not a host-service cell.
            // Its queue owns cancellation and the existing deferred handback.
            // This is only a snapshot. The queue owner authenticates the
            // exact record incarnation and operation under its guard below.
            let member = self.zone.record(record.id);
            if !member.is_native_owned() || !member.has_adapter_operation() {
                return Ok(());
            }
            let Some(census) = member.object_wait_census() else {
                return Ok(());
            };
            // substrate::ipc::wait_key admits only the disjoint readiness
            // domain below this boundary. Metadata and MM edit waits retain
            // their own cancellation policy despite using adapter tokens too.
            if census.queue as usize >= carrick_sched_core::object_wait::ADDRESS_SPACE_WAIT_BASE {
                return Ok(());
            }
            let Some(key) = ObjectWaitKey::new(census.queue, census.generation) else {
                return Ok(());
            };
            let Some(operation) =
                OperationToken::new(census.operation, census.operation_generation)
            else {
                return Ok(());
            };
            let completion =
                |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, C>| {
                    crate::sched::object_wait::deliver_completion(self.zone, slot, owned)
                };
            let queue = if self.zone.completion_enabled(key) {
                self.zone.object_wait_with_completion(
                    key,
                    &carrick_sched_core::ShortLockSpin,
                    &completion,
                )
            } else {
                self.zone
                    .object_wait(key, &carrick_sched_core::ShortLockSpin)
            };
            let queue = match queue {
                Ok(queue) => queue,
                // A completed/rebound park no longer needs cancellation.
                // A mode-changing rebind reports Occupied before checking
                // generation; it cannot pass a still-linked old waiter.
                Err(
                    carrick_sched_core::object_wait::ObjectWaitError::Stale
                    | carrick_sched_core::object_wait::ObjectWaitError::Occupied,
                ) => return Ok(()),
                Err(_) => return Err(NativeProcessError::Quarantined),
            };
            let owned = queue.wake_owner_operation(record, &operation, slot, Handback::Signal);
            drop(queue);
            if let Some(owned) = owned {
                crate::sched::object_wait::deliver_completion(self.zone, slot, owned);
            }
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
            .map_err(service_protocol_error)?;
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
                let operation = if adapter {
                    let census = self
                        .zone
                        .record(record.id)
                        .object_wait_census()
                        .ok_or(NativeProcessError::Stale)?;
                    OperationToken::new(census.operation, census.operation_generation)
                } else {
                    OperationToken::new(u64::from(record.id.raw()), request.identity.sequence.get())
                }
                .ok_or(NativeProcessError::Stale)?;
                let owned = queue.wake_owner_operation(record, &operation, slot, Handback::Resumed);
                drop(queue);
                if let Some(owned) = owned {
                    let (_, wake) = owned.into_parts();
                    effects = wake;
                }
            } else {
                drop(queue);
            }
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

    #[inline(never)]
    pub(super) fn drain_copyout(
        &mut self,
        mut result: Result<NativeResume, NativeProcessError>,
    ) -> Result<NativeResume, NativeProcessError> {
        while result.is_ok() {
            let Some(output) = self.copyout_ready.take() else {
                break;
            };
            result = self.finish_copyout(*output);
        }
        result
    }

    /// Commit a completed ring answer a bounded page at a time. Owner waits
    /// retain both the answer and its next unwritten byte in the service row.
    #[inline(never)]
    pub(super) fn finish_copyout(
        &mut self,
        mut output: OwnedCopyout,
    ) -> Result<NativeResume, NativeProcessError> {
        let mut prepared_offset = None;
        while output.offset < output.bytes.len() {
            let previous_prepared_offset = prepared_offset.take();
            let address = output
                .address
                .raw()
                .checked_add(output.offset as u64)
                .ok_or(NativeProcessError::Fault)?;
            let count = (4096 - (address as usize & 4095)).min(output.bytes.len() - output.offset);
            match self.copy_owner_frame(
                UserVa::new(address),
                &output.bytes[output.offset..output.offset + count],
            ) {
                Ok(()) => output.offset += count,
                Err(NativeProcessError::OwnerWait(wait)) => {
                    return self.begin_service_inner(
                        ServiceOperation::CarrierWork {
                            entry: OwnerEntry::Syscall,
                        },
                        None,
                        Some(wait),
                        ServicePayload::Copyout(output),
                        ServiceCompletion::Inline,
                    );
                }
                Err(NativeProcessError::Busy) => {
                    return self.begin_service_inner(
                        ServiceOperation::CarrierWork {
                            entry: OwnerEntry::Syscall,
                        },
                        None,
                        None,
                        ServicePayload::Copyout(output),
                        ServiceCompletion::Inline,
                    );
                }
                Err(NativeProcessError::Unsupported) => {
                    if previous_prepared_offset == Some(output.offset) {
                        return Err(NativeProcessError::Unsupported);
                    }
                    let preparation =
                        self.prepare_owner_output(carrick_core::mm::transaction::CopyoutRequest {
                            address: UserVa::new(address),
                            len: carrick_guest_arch::GuestLen::new(count as u64),
                        });
                    match preparation {
                        Ok(()) => {
                            prepared_offset = Some(output.offset);
                            continue;
                        }
                        Err(NativeProcessError::OwnerWait(wait)) => {
                            return self.begin_service_inner(
                                ServiceOperation::CarrierWork {
                                    entry: OwnerEntry::Syscall,
                                },
                                None,
                                Some(wait),
                                ServicePayload::Copyout(output),
                                ServiceCompletion::Inline,
                            );
                        }
                        Err(NativeProcessError::Busy) => {
                            return self.begin_service_inner(
                                ServiceOperation::CarrierWork {
                                    entry: OwnerEntry::Syscall,
                                },
                                None,
                                None,
                                ServicePayload::Copyout(output),
                                ServiceCompletion::Inline,
                            );
                        }
                        Err(NativeProcessError::Unsupported) => {
                            let (fault, sequence) = self
                                .service
                                .copyout_fault(UserVa::new(address))
                                .ok_or(NativeProcessError::Unsupported)?;
                            return self.begin_service_inner(
                                ServiceOperation::Fault(fault),
                                Some(sequence),
                                None,
                                ServicePayload::Copyout(output),
                                ServiceCompletion::RetrySyscall,
                            );
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(NativeResume::Returned(output.result))
    }

    /// Authenticate retained adapter custody while the caller holds the graph.
    /// A service payload may be empty at the CarrierWork bridge even though
    /// the exact member still owns its separately installed IPC operation.
    fn retains_adapter_under(&self, graph: &Graph<'a, M, C>) -> bool {
        self.source
            .zone
            .record(self.record.id)
            .has_adapter_operation()
            && graph
                .service_wait(&self.record)
                .is_none_or(|pending| pending.adapter)
    }

    /// Only a retained IPC operation authorizes this refusal handback.
    /// A native service token has its own pending row and is not an IPC pin.
    #[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
    fn retains_ipc_operation(&self, exit: NativeServiceExit) -> bool {
        matches!(exit, NativeServiceExit::CarrierWork)
            && self.retains_adapter_under(&self.runtime.graph.lock())
    }

    /// Fold the owned-IPC exit after preparation unwinds. Unadmitted bridges,
    /// notably exec, retain their existing outcome until they own staged input.
    #[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
    #[inline(never)]
    pub(crate) fn settle_service_exit(
        &mut self,
        result: Result<NativeResume, NativeProcessError>,
        exit: NativeServiceExit,
    ) -> Result<NativeResume, NativeProcessError> {
        // Preserve the owner of a refused operation. A later refusal while
        // folding a non-stale result belongs to settlement itself.
        if !matches!(&result, Err(NativeProcessError::Stale)) {
            self.service_phase = NativeServicePhase::Settlement;
        }
        if !self.retains_ipc_operation(exit) {
            let result = result?;
            if matches!(result, NativeResume::Left(_)) && self.take_handoff_receipt().is_none() {
                return Err(NativeProcessError::Quarantined);
            }
            return Ok(result);
        }
        let result = result.map_err(|error| match error {
            NativeProcessError::ForkRefused(refusal) => refusal.error(),
            error => error,
        });
        let result = match result {
            Ok(NativeResume::RetrySyscall) => self.yield_service_checkpoint()?,
            Ok(result) => result,
            Err(
                NativeProcessError::Invalid
                | NativeProcessError::Stale
                | NativeProcessError::Quarantined,
            ) => return result,
            // The wrapper was decoded above; another wrapper is a codec invariant.
            Err(NativeProcessError::ForkRefused(_)) => return Err(NativeProcessError::Invalid),
            Err(
                NativeProcessError::Busy
                | NativeProcessError::Exhausted
                | NativeProcessError::OwnerWait(_)
                | NativeProcessError::GroupExitCustody,
            ) => {
                // The same IPC owner reselects preparation at its checkpoint,
                // including enrollment on an explicit owner dependency. No
                // user result or fresh syscall may replace the retained token.
                self.yield_service_checkpoint()?
            }
            Err(
                error @ (NativeProcessError::Fault
                | NativeProcessError::Unsupported
                | NativeProcessError::NoChild),
            ) => {
                self.adapter_ready = None;
                NativeResume::Returned(
                    self.retire_adapter_result(SyscallResult::new(error.errno()))?,
                )
            }
        };
        if matches!(result, NativeResume::Left(_)) && self.take_handoff_receipt().is_none() {
            // The operation is still installed: an empty receipt after a
            // deferred preparation is not failed execution authentication.
            let result = self.yield_service_checkpoint()?;
            self.take_handoff_receipt()
                .ok_or(NativeProcessError::Quarantined)?;
            return Ok(result);
        }
        Ok(result)
    }

    /// Intake may capture backing, but never waits for another guest. The
    /// owning request is visible to terminal close before its physical intake.
    #[inline(never)]
    pub fn begin_service(
        &mut self,
        operation: ServiceOperation,
        fault_sequence: Option<core::num::NonZeroU64>,
    ) -> Result<NativeResume, NativeProcessError> {
        self.begin_service_inner(
            operation,
            fault_sequence,
            None,
            ServicePayload::None,
            ServiceCompletion::Inline,
        )
    }
    /// A completed host member must retain its exact native return owner even
    /// when carrier intake ACKs before the service wait can enroll.
    #[inline(never)]
    pub(super) fn begin_return_work(&mut self) -> Result<NativeResume, NativeProcessError> {
        let outcome = self.begin_service_inner(
            ServiceOperation::CarrierWork {
                entry: OwnerEntry::Syscall,
            },
            None,
            None,
            ServicePayload::None,
            ServiceCompletion::OwnerCheckpoint,
        )?;
        if matches!(outcome, NativeResume::Left(_)) && self.take_handoff_receipt().is_none() {
            return Err(NativeProcessError::Quarantined);
        }
        Ok(outcome)
    }

    pub(super) fn begin_adapter_service(
        &mut self,
        operation: ServiceOperation,
        sequence: Option<NonZeroU64>,
        identity: carrick_sched_core::object_wait::OperationIdentity,
    ) -> Result<NativeResume, NativeProcessError> {
        let census = self
            .source
            .zone
            .record(self.record.id)
            .object_wait_census()
            .ok_or(NativeProcessError::Stale)?;
        let installed = OperationToken::new(census.operation, census.operation_generation)
            .ok_or(NativeProcessError::Stale)?;
        if installed.identity() != identity {
            return Err(NativeProcessError::Quarantined);
        }
        self.begin_service_inner(
            operation,
            sequence,
            None,
            ServicePayload::Adapter,
            ServiceCompletion::RetrySyscall,
        )
    }
    /// Supply readable memory for a guest-copy input, then
    /// retry the exact SVC before any setup effect. A refused supply becomes
    /// `EFAULT` from the copy rather than a user data-abort signal.
    pub(super) fn prepare_guest_input(
        &mut self,
        request: carrick_core::personality::GuestCopyRequest,
    ) -> Result<LifecycleOutcome, NativeProcessError> {
        let mm = self
            .runtime
            .graph
            .lock()
            .owner
            .task(self.key)
            .map_err(|_| NativeProcessError::Stale)?
            .native()
            .resources()
            .mm
            .clone();
        let (operation, sequence, wait) = match self.service.prepare_owned_read(&mm, request) {
            Ok(()) => return Ok(LifecycleOutcome::Redispatch),
            Err(NativeProcessError::Fault) => {
                return Ok(returned(carrick_syscall_abi::LINUX_EFAULT.guest_retval()));
            }
            Err(NativeProcessError::OwnerWait(wait)) => (
                ServiceOperation::CarrierWork {
                    entry: OwnerEntry::Syscall,
                },
                None,
                Some(wait),
            ),
            Err(NativeProcessError::Busy) => (
                ServiceOperation::CarrierWork {
                    entry: OwnerEntry::Syscall,
                },
                None,
                None,
            ),
            Err(NativeProcessError::Unsupported) => {
                let (mut fault, sequence) = self
                    .service
                    .copyout_fault(request.address)
                    .ok_or(NativeProcessError::Unsupported)?;
                fault.access = request.access;
                (ServiceOperation::Fault(fault), Some(sequence), None)
            }
            Err(error) => return Err(error),
        };
        let result = self.begin_service_inner(
            operation,
            sequence,
            wait,
            ServicePayload::Copyin,
            ServiceCompletion::RetrySyscall,
        )?;
        match result {
            NativeResume::RetrySyscall => Ok(LifecycleOutcome::Redispatch),
            NativeResume::Returned(result) => Ok(LifecycleOutcome::Returned {
                result,
                work: false,
            }),
            NativeResume::Left(None) => Ok(LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                result: SyscallResult::new(0),
            }),
            _ => Err(NativeProcessError::Quarantined),
        }
    }

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
            ServicePayload::None,
            ServiceCompletion::RetrySyscall,
        )
    }
    pub fn begin_exec_service(
        &mut self,
        payload: Box<[u8]>,
        table: Option<[u64; 3]>,
        call: NativeServiceCall<'_>,
    ) -> Result<NativeResume, NativeProcessError> {
        // The carrier's exec service resolves and checks access with exactly
        // the caller's own cwd and credentials, which the ring seals into
        // the payload from the caller's task row (#1392), and resolves a
        // descriptor `execveat` names in the caller's ring table (#1530).
        let access = match self.caller_access(call) {
            Ok(access) => access,
            Err(failure) => return Ok(failure.into_resume()),
        };
        let mut sealed = payload.into_vec();
        if let Err(error) =
            carrick_core_abi::service::seal_exec_payload_access(&mut sealed, &access, table)
        {
            return Ok(NativeResume::Returned(SyscallResult::from_errno(
                match error {
                    carrick_core_abi::service::ExecPayloadError::TooLarge => {
                        carrick_syscall_abi::LINUX_E2BIG
                    }
                    carrick_core_abi::service::ExecPayloadError::Invalid => {
                        carrick_syscall_abi::LINUX_EINVAL
                    }
                },
            )));
        }
        let payload = sealed.into_boxed_slice();
        self.service_phase = NativeServicePhase::Capability;
        let capability = self
            .runtime
            .exec_capability()
            .ok_or(NativeProcessError::Stale)?;
        let descriptor = carrick_core_abi::service::ExecPayloadDescriptor::checked(
            carrick_guest_arch::GuestVa::new(payload.as_ptr().addr() as u64),
            carrick_guest_arch::GuestLen::new(payload.len() as u64),
            call.ordinal,
        )
        .ok_or(NativeProcessError::Exhausted)?;
        // The staged payload holds every argument: a vfork parent may run.
        self.release_vfork_parent()?;
        self.begin_service_inner(
            ServiceOperation::Exec {
                capability,
                payload: descriptor,
            },
            None,
            None,
            ServicePayload::Exec(payload),
            ServiceCompletion::Inline,
        )
    }
    /// Keep a carrier-retained private-mapping source for this record:
    /// `key` names the exact `mmap` retry that consumes it.
    fn stash_map_source(
        &self,
        key: carrick_personality_linux::native_host_file::NativeMapKey,
        source: carrick_core_abi::HostBackingIdentity,
    ) -> Result<(), NativeProcessError> {
        let mut graph = self.runtime.graph.lock();
        graph
            .owner
            .task_mut(self.key)
            .map_err(|_| NativeProcessError::Stale)?
            .native_mut()
            .resources_mut()
            .map_stash
            .entry(self.record)
            .or_default()
            .retain(key, source);
        Ok(())
    }

    /// Stage one typed host-file crossing for the carrier venue. Fd-based
    /// calls carry no credential decision: the open description's access
    /// mode, checked by the staging step, is the authority Linux applies. A
    /// path record leads with the caller's own access context from its task
    /// row; a caller the carrier cannot check exactly (an unknown cwd, file
    /// capabilities that disagree with its fsuid) is a counted ENOSYS.
    pub fn begin_host_file_service(
        &mut self,
        record: Box<[u8]>,
        output: Option<carrick_personality_linux::native_host_file::HostFileOutput>,
        resolves_path: bool,
        map: Option<carrick_personality_linux::native_host_file::NativeMapKey>,
        chdir: bool,
        call: NativeServiceCall<'a>,
    ) -> Result<NativeResume, NativeProcessError> {
        // A path resolves under the caller's own access context (its task
        // row's credentials, umask, cwd and root), carried in the record.
        let record = if resolves_path {
            let access = match self.caller_access(call) {
                Ok(access) => access,
                Err(failure) => return Ok(failure.into_resume()),
            };
            match carrick_personality_linux::native_host_file::stamp_access_context(
                &record, &access,
            ) {
                Some(record) => record,
                // The context and path do not fit one record.
                None => {
                    return Ok(NativeResume::Returned(SyscallResult::from_errno(
                        carrick_syscall_abi::LINUX_ENAMETOOLONG,
                    )));
                }
            }
        } else {
            record
        };
        let mut record = record;
        carrick_personality_linux::native_host_file::stamp_write_file_size_limit(
            &mut record,
            || self.caller_file_size_soft_limit(),
        )?;
        self.service_phase = NativeServicePhase::Capability;
        let capability = self
            .runtime
            .exec_capability()
            .ok_or(NativeProcessError::Stale)?;
        let payload = carrick_core_abi::service::HostFilePayloadDescriptor::checked(
            carrick_guest_arch::GuestVa::new(record.as_ptr().addr() as u64),
            carrick_guest_arch::GuestLen::new(record.len() as u64),
            call.ordinal,
        )
        .ok_or(NativeProcessError::Exhausted)?;
        self.begin_service_inner(
            ServiceOperation::HostFile {
                capability,
                payload,
            },
            None,
            None,
            ServicePayload::HostFile(PendingHostFile {
                call,
                record,
                output,
                map,
                chdir,
            }),
            ServiceCompletion::Inline,
        )
    }
    /// The caller's own `RLIMIT_FSIZE` soft limit, which the ring owns.
    pub(super) fn caller_file_size_soft_limit(&self) -> Result<u64, NativeProcessError> {
        let graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task(self.key)
            .map_err(|_| NativeProcessError::Stale)?;
        task.rlimits
            .get(carrick_abi::LINUX_RLIMIT_FSIZE as usize)
            .map(|limit| limit.rlim_cur)
            .ok_or(NativeProcessError::Stale)
    }
    /// The calling thread's encoded access context: its credentials, and
    /// its process's umask, cwd and root, all from the caller's task row.
    pub(super) fn caller_access(
        &self,
        call: NativeServiceCall<'_>,
    ) -> Result<Vec<u8>, CallerAccessFailure> {
        self.encode_caller_access().map_err(|errno| {
            if errno == carrick_syscall_abi::LINUX_ENOSYS {
                call.counters.record_refusal(
                    call.ordinal,
                    if self.is_root_process() {
                        carrick_core_abi::service::ServiceOrigin::Initial
                    } else {
                        carrick_core_abi::service::ServiceOrigin::Descendant
                    },
                    carrick_el1_abi::RefusalVenue::Ring,
                );
            }
            CallerAccessFailure(SyscallResult::from_errno(errno))
        })
    }

    fn encode_caller_access(&self) -> Result<Vec<u8>, carrick_syscall_abi::LinuxErrno> {
        let graph = self.runtime.graph.lock();
        let stale = carrick_syscall_abi::LINUX_ESRCH;
        let task = graph.owner.task(self.key).map_err(|_| stale)?;
        let credentials = task.credentials_for(self.calling_tid).map_err(|_| stale)?;
        let mut access = Vec::new();
        // A child whose root fork seed was refused has no known cwd: its
        // path and exec calls are left unrouted.
        task.fs
            .as_ref()
            .ok_or(carrick_syscall_abi::LINUX_ENOSYS)?
            .encode_access(credentials, task.umask, &mut access)?;
        Ok(access)
    }
    /// Store a served chdir lookup's directory as the caller's cwd: the one
    /// writer of a ring process's cwd.
    fn complete_chdir(
        &self,
        record: &[u8],
        call: NativeServiceCall<'a>,
    ) -> Result<SyscallResult, NativeProcessError> {
        let target = match carrick_personality_linux::native_host_file::chdir_target(record) {
            Ok(target) => target,
            Err(result) => return Ok(result),
        };
        let mut graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task_mut(self.key)
            .map_err(|_| NativeProcessError::Stale)?;
        let Some(fs) = task.fs.as_mut() else {
            let origin = if self.key == graph.root_key {
                carrick_core_abi::service::ServiceOrigin::Initial
            } else {
                carrick_core_abi::service::ServiceOrigin::Descendant
            };
            call.counters
                .record_refusal(call.ordinal, origin, carrick_el1_abi::RefusalVenue::Ring);
            return Ok(SyscallResult::from_errno(carrick_syscall_abi::LINUX_ENOSYS));
        };
        fs.cwd = target;
        Ok(SyscallResult::new(0))
    }
    /// Park the exact ring operation on the producer observed before its
    /// failed admission. No physical service notice is published.
    pub fn begin_owner_service_wait(
        &mut self,
        operation: ServiceOperation,
        wait: carrick_core_abi::PortalOwnerWait,
    ) -> Result<NativeResume, NativeProcessError> {
        self.begin_service_inner(
            operation,
            None,
            Some(wait),
            ServicePayload::None,
            ServiceCompletion::Inline,
        )
    }
    #[inline(never)]
    fn begin_service_inner(
        &mut self,
        operation: ServiceOperation,
        fault_sequence: Option<core::num::NonZeroU64>,
        owner_wait: Option<carrick_core_abi::PortalOwnerWait>,
        payload: ServicePayload<'a>,
        completion: ServiceCompletion,
    ) -> Result<NativeResume, NativeProcessError> {
        // Publish into the existing boxed pending owner before descending into
        // completion. Admission's payload/manifests and rollback locals must
        // unwind before a ready reply walks four descriptor-table levels.
        let prepared = self.prepare_service_inner(
            operation,
            fault_sequence,
            owner_wait,
            payload,
            completion.retries_syscall(),
        )?;
        let (request, adapter) = match prepared {
            PreparedService::Request(request, adapter) => (request, adapter),
            PreparedService::Retired(result) => return Ok(result),
        };
        if let Some(wait) = owner_wait {
            self.park_owner_wait(&request, wait)
        } else {
            self.park_service(&request, adapter || completion.checkpoints_owner())
        }
    }

    #[inline(never)]
    fn prepare_service_inner(
        &mut self,
        operation: ServiceOperation,
        fault_sequence: Option<core::num::NonZeroU64>,
        owner_wait: Option<carrick_core_abi::PortalOwnerWait>,
        payload: ServicePayload<'a>,
        retry_syscall_after_supply: bool,
    ) -> Result<PreparedService, NativeProcessError> {
        self.service_phase = NativeServicePhase::Payload;
        let copyin = matches!(&payload, ServicePayload::Copyin);
        let (payload, copyout, adapter) = match payload {
            ServicePayload::Copyin => (ServicePayload::None, None, false),
            ServicePayload::Copyout(output) => {
                (ServicePayload::None, Some(Box::new(output)), false)
            }
            ServicePayload::Adapter => (ServicePayload::None, None, true),
            payload => (payload, None, false),
        };
        let (exec_payload, host_file) = match (operation, payload) {
            (ServiceOperation::Exec { .. }, ServicePayload::Exec(payload)) => (Some(payload), None),
            (ServiceOperation::HostFile { .. }, ServicePayload::HostFile(pending)) => {
                (None, Some(pending))
            }
            (ServiceOperation::Exec { .. } | ServiceOperation::HostFile { .. }, _)
            | (_, ServicePayload::Exec(_) | ServicePayload::HostFile(_)) => {
                return Err(NativeProcessError::Stale);
            }
            (_, ServicePayload::None) => (None, None),
            (_, ServicePayload::Copyout(_) | ServicePayload::Copyin | ServicePayload::Adapter) => {
                return Err(NativeProcessError::Stale);
            }
        };
        self.service_phase = NativeServicePhase::Member;
        let (page, control, mm) = {
            let graph = self.runtime.graph.lock();
            if graph.has_member_wait(&self.record) {
                // IPC keeps its separately retained operation on refusal.
                // A bridge owns the executing exact member and cannot also
                // have an outstanding suspended operation on that member.
                return Err(
                    if adapter
                        || (matches!(operation, ServiceOperation::CarrierWork { .. })
                            && self.retains_adapter_under(&graph))
                    {
                        NativeProcessError::Busy
                    } else {
                        NativeProcessError::Quarantined
                    },
                );
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
        self.service_phase = NativeServicePhase::Birth;
        let birth =
            match control
                .service
                .bound_birth(self.key, self.binding.thread_generation, self.record)
            {
                Ok(birth) => {
                    // Rehome moves an idle birth to a new exact record. Bind
                    // its quiescent queue after releasing the graph guard,
                    // preserving the existing service-queue -> graph order.
                    bind_member_service_queue(self.source.zone, self.record)?;
                    birth
                }
                Err(ServiceError::Busy) => {
                    // Fork binds a child's service cell at publication. The root
                    // and an authenticated unbound member use this same owner. Its first exact
                    // registered operation binds the same retained capability.
                    self.service_phase = NativeServicePhase::Mm;
                    let handle = self.service.service_mm_handle(&mm)?;
                    self.service_phase = NativeServicePhase::Bind;
                    bind_member_service(
                        self.source.zone,
                        self.key,
                        if self.is_root_process() {
                            carrick_core_abi::service::ServiceOrigin::Initial
                        } else {
                            carrick_core_abi::service::ServiceOrigin::Descendant
                        },
                        self.record,
                        self.binding.thread_generation,
                        control.control(),
                        handle,
                    )?;
                    self.service_phase = NativeServicePhase::Birth;
                    control
                        .service
                        .bound_birth(self.key, self.binding.thread_generation, self.record)
                        .map_err(service_protocol_error)?
                }
                Err(error) => return Err(service_protocol_error(error)),
            };
        self.service_phase = NativeServicePhase::Unspecified;
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
        self.service_phase = NativeServicePhase::Park;
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
        // Claim acquisition refuses only on counter overflow, not contention.
        let claim = carrick_core::terminal::NativeServiceClaim::acquire(page)
            .map_err(|_| NativeProcessError::Quarantined)?;
        self.service_phase = NativeServicePhase::Publication;
        let mut closing = false;
        let published = {
            let graph = self.runtime.graph.lock();
            if !claim.admitted() {
                // Close publishes its gate and pending operation under this
                // lock. A terminal gate without that owner is broken custody.
                closing = graph.pending.has_exit(&self.key);
                Err(NativeProcessError::Quarantined)
            } else if graph.has_member_wait(&self.record) {
                Err(
                    if adapter
                        || (matches!(operation, ServiceOperation::CarrierWork { .. })
                            && self.retains_adapter_under(&graph))
                    {
                        NativeProcessError::Busy
                    } else {
                        NativeProcessError::Quarantined
                    },
                )
            } else if let Some(wait) = owner_wait {
                self.control
                    .service
                    .begin_owner_wait(birth, self.binding.generation, operation, wait)
                    .map_err(service_protocol_error)
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
                    .map_err(service_protocol_error)
            }
        };
        let request = match published {
            Ok(request) => request,
            Err(error) => {
                drop(owner_queue);
                self.release_service_claim(claim)?;
                if closing {
                    // No request reached the transport. Cancel the exact
                    // retained IPC owner before terminal retirement: the
                    // scheduler deliberately requeues records with operations
                    // still attached, and their endpoint pins must not leak.
                    if self
                        .source
                        .zone
                        .record(self.record.id)
                        .has_adapter_operation()
                    {
                        self.retire_adapter_result(SyscallResult::new(0))?;
                        self.adapter_ready = None;
                    }
                    return self.retire_closing_entry().map(PreparedService::Retired);
                }
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
                host_file,
                copyout,
                copyin,
                adapter,
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
        // Intake can run before park enrollment. Publish the exact temporary
        // continuation before its notice, preserving a host member's permanent
        // execution ownership. The service cell authenticates this record/MM.
        let entry = if retry_syscall_after_supply {
            OwnerEntry::Syscall
        } else {
            match operation {
                ServiceOperation::Fault(_) | ServiceOperation::Exception(_) => {
                    OwnerEntry::Exception
                }
                ServiceOperation::CarrierWork { entry } => entry,
                _ => OwnerEntry::Syscall,
            }
        };
        // SAFETY: this admitted lane owns the exact running record, and its
        // retained service has been published before exposing the notice.
        unsafe {
            self.source
                .zone
                .record(self.record.id)
                .publish_owner_continuation(entry);
        }
        if owner_wait.is_some() {
            return Ok(PreparedService::Request(request, adapter));
        }
        self.service_phase = NativeServicePhase::Notice;
        if let Err(error) = self
            .current
            .service_notice
            .publish(request.identity.into())
            .map_err(service_protocol_error)
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
                .map_err(service_protocol_error)?;
            {
                self.control
                    .service
                    .consume(request.identity)
                    .map_err(service_protocol_error)?;
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
        #[cfg(test)]
        super::host_test_support::run_service_published_hook(self.runtime as *const _ as usize);
        Ok(PreparedService::Request(request, adapter))
    }

    fn has_adapter_operation(&self) -> bool {
        self.runtime
            .graph
            .lock()
            .service_wait(&self.record)
            .is_some_and(|pending| pending.adapter)
    }
    #[inline(never)]
    fn take_preparation_operation(
        &self,
        request: &ServiceRequest,
    ) -> Result<OperationToken, NativeProcessError> {
        if self.has_adapter_operation() {
            let token = carrick_core::wait::take_object_operation(
                self.source.zone,
                self.source.slot,
                self.source.zone.record(self.record.id).identity(),
            )
            .map_err(|_| NativeProcessError::Quarantined)?
            .ok_or(NativeProcessError::Stale)?;
            Ok(token)
        } else {
            OperationToken::new(
                u64::from(self.record.id.raw()),
                request.identity.sequence.get(),
            )
            .ok_or(NativeProcessError::Stale)
        }
    }
    #[inline(never)]
    fn restore_preparation_operation(
        &self,
        operation: OperationToken,
    ) -> Result<(), NativeProcessError> {
        if self.has_adapter_operation() {
            carrick_core::wait::restore_object_operation(
                self.source.zone,
                self.source.slot,
                self.source.zone.record(self.record.id).identity(),
                operation,
            )
            .map_err(|_| NativeProcessError::Quarantined)?;
        }
        Ok(())
    }

    // The caller retains the request snapshot through nested completion. Borrow
    // its full birth/MM identity instead of retaining another aggregate copy.
    #[inline(never)]
    pub(super) fn park_service(
        &mut self,
        request: &ServiceRequest,
        defer_completion: bool,
    ) -> Result<NativeResume, NativeProcessError> {
        self.service_phase = NativeServicePhase::Park;
        use carrick_sched_core::object_wait::ObjectWaitError;
        let zone = self.source.zone;
        let key = ObjectWaitKey::native_service(self.record).ok_or(NativeProcessError::Stale)?;
        // These queues are bound as guest-owned queues at birth. A host
        // continuation domain may not take over a native member's operation.
        if zone.completion_enabled(key) {
            return Err(NativeProcessError::Quarantined);
        }
        let adapter = self.has_adapter_operation();
        let token = self.take_preparation_operation(request)?;
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
            ServiceOperation::Crossing { .. }
            | ServiceOperation::Exec { .. }
            | ServiceOperation::HostFile { .. } => OwnerEntry::Syscall,
            ServiceOperation::CarrierWork { entry } => entry,
        };
        let mut completion = None;
        let mut completed_pending = None;
        let mut failure = None;
        let mut deferred = false;
        let parked = carrick_core::wait::park_object_record(
            zone,
            self.source.slot,
            carrick_core::wait::ObjectParkRequest::owner(
                key,
                token,
                entry,
                // SAFETY: the save_context closure below probes completion,
                // cancellation and service ownership under this same queue.
                unsafe { carrick_core::wait::OwnerProbeUnderQueueLock::for_save_context_probe() },
            ),
            &|_| {},
            || {
                let interruptible = self
                    .runtime
                    .graph
                    .lock()
                    .service_wait(&self.record)
                    .is_some_and(PendingService::signal_interruptible);
                if ((interruptible && self.signal_interrupts_current())
                    || self.runtime.graph.lock().pending.has_exit(&self.key))
                    && let Err(error) = self.control.service.cancel(request.identity)
                {
                    failure = Some(service_protocol_error(error));
                    return Err(ObjectWaitError::Stale);
                }
                if defer_completion {
                    match self.control.service.completion_ready(request.identity) {
                        Ok(true) => {
                            deferred = true;
                            return Err(ObjectWaitError::Changed);
                        }
                        Ok(false) | Err(ServiceError::Busy) => {}
                        Err(error) => {
                            failure = Some(service_protocol_error(error));
                            return Err(ObjectWaitError::Stale);
                        }
                    }
                } else {
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
                            failure = Some(service_protocol_error(error));
                            return Err(ObjectWaitError::Stale);
                        }
                    }
                }
                // SAFETY: this slot still owns the exact OnCpu record.
                unsafe {
                    *zone.record(self.record.id).ctx_mut() = *self.words;
                }
                Ok((self.record.id, false))
            },
        );
        let parked = match parked {
            Ok(parked) => Some(parked),
            Err((error, operation)) => {
                // A host request closed park admission for this running
                // record (#1467). That is contention, not a broken invariant:
                // retain the exact service operation on the record and leave
                // through the owner checkpoint, so the slot's exit honours the
                // request and the next owner entry reparks.
                let host_contended = error == ObjectWaitError::Occupied
                    && failure.is_none()
                    && completion.is_none()
                    && !deferred
                    && self.host_requested_current();
                if adapter || host_contended || deferred {
                    self.retain_record_operation(operation)?;
                }
                if host_contended {
                    return self.yield_service_checkpoint_as(entry);
                }
                if error != ObjectWaitError::Changed && failure.is_none() {
                    return Err(NativeProcessError::Quarantined);
                }
                None
            }
        };
        if let Some(error) = failure {
            return Err(error);
        }
        if deferred {
            return self.yield_service_checkpoint();
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
        let mut parked = parked.ok_or(NativeProcessError::Quarantined)?;
        self.handoff = parked.take_receipt();
        Ok(NativeResume::Left(None))
    }

    /// Keep a refused park's exact service operation on the running record,
    /// where `resume_service` authenticates it at the next owner entry.
    fn retain_record_operation(&self, operation: OperationToken) -> Result<(), NativeProcessError> {
        carrick_core::wait::restore_object_operation(
            self.source.zone,
            self.source.slot,
            self.source.zone.record(self.record.id).identity(),
            operation,
        )
        .map_err(|_| NativeProcessError::Quarantined)
    }

    /// Whether a host requester holds this lane's exact running record: its
    /// OnCpuRequested claim on this slot refuses every new park.
    fn host_requested_current(&self) -> bool {
        carrick_core::entry::host_requested_running(self.binding, self.source, self.record.id)
    }

    /// A supply that won before enrollment is ready work, not a reason to
    /// finish under the IPC dispatch stack. The exact record keeps its token.
    #[inline(never)]
    pub(super) fn yield_service_checkpoint(&mut self) -> Result<NativeResume, NativeProcessError> {
        self.yield_service_checkpoint_as(OwnerEntry::Syscall)
    }

    /// Test seam: a host requester acting between the requeue and the
    /// receipt it licenses.
    fn yield_receipt_race(&self) {
        #[cfg(test)]
        if let Some(hook) = self.runtime.yield_receipt_race_hook.lock().take() {
            hook();
        }
    }

    /// Leave through the owner checkpoint that resumes `entry`'s service.
    #[inline(never)]
    fn yield_service_checkpoint_as(
        &mut self,
        entry: OwnerEntry,
    ) -> Result<NativeResume, NativeProcessError> {
        let start = carrick_core::entry::prepare_handoff(self.binding, self.source, self.record.id)
            .ok_or(NativeProcessError::Stale)?;
        // SAFETY: this exact admitted record is still held by this lane.
        unsafe {
            let record = self.source.zone.record(self.record.id);
            *record.ctx_mut() = *self.words;
            record.publish_owner_continuation(entry);
        }
        let receipt =
            if self.source.zone.record(self.record.id).claim() == carrick_sched_core::Claim::Free {
                // The root's first entry has a retained, unqueued host-loaded
                // record. Materialize it on this slot's queue with its token.
                let requeue = self
                    .source
                    .zone
                    .requeue_preempted(self.source.slot, self.record.id);
                if !requeue.is_queued() {
                    return Err(NativeProcessError::Quarantined);
                }
                self.source.zone.clear_current(self.source.slot);
                self.yield_receipt_race();
                carrick_core::entry::publish_handoff_yield(start, requeue)
            } else {
                let release = self.source.zone.release_current(
                    self.source.slot,
                    self.record.id,
                    &carrick_sched_core::ShortLockSpin,
                );
                if release != carrick_sched_core::CurrentRelease::Requeued {
                    return Err(NativeProcessError::Quarantined);
                }
                // From here the queued record may already be the host's (#1467):
                // the requeue itself, not a later claim read, is the publication.
                self.yield_receipt_race();
                carrick_core::entry::publish_handoff_yield(start, release)
            };
        self.handoff = Some(receipt.ok_or(NativeProcessError::Quarantined)?);
        Ok(NativeResume::Left(None))
    }

    pub(super) fn resume_service(&mut self) -> Option<Result<NativeResume, NativeProcessError>> {
        let request = self
            .runtime
            .graph
            .lock()
            .service_wait(&self.record)?
            .request;
        if self.has_adapter_operation() {
            let census = self.source.zone.record(self.record.id).object_wait_census();
            if !census.is_some_and(|census| {
                OperationToken::new(census.operation, census.operation_generation).is_some()
            }) {
                return Some(Err(NativeProcessError::Stale));
            }
        } else {
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
            self.park_service(&request, false)
        })
    }

    #[inline(never)]
    fn park_owner_wait(
        &mut self,
        request: &ServiceRequest,
        wait: carrick_core_abi::PortalOwnerWait,
    ) -> Result<NativeResume, NativeProcessError> {
        self.service_phase = NativeServicePhase::Park;
        use carrick_sched_core::object_wait::ObjectWaitError;
        let zone = self.source.zone;
        let enrollment = carrick_core_abi::wait::PortalWaitEnrollment::for_owner(
            zone,
            request.identity.birth.mm,
            wait,
        )
        .map_err(|_| NativeProcessError::Stale)?;
        let operation = self.take_preparation_operation(request)?;
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
                let (interruptible, output_cancelled) =
                    self.runtime.graph.lock().service_wait(&self.record).map_or(
                        (true, false),
                        |pending| {
                            (
                                pending.signal_interruptible(),
                                (pending.copyout.is_some() || pending.copyin)
                                    && pending.claim.cancellation().is_some(),
                            )
                        },
                    );
                if output_cancelled
                    || (interruptible && self.signal_interrupts_current())
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
            Err((ObjectWaitError::Changed, operation)) => {
                self.restore_preparation_operation(operation)?;
                self.finish_owner_wait(request)
            }
            Err((ObjectWaitError::Occupied, operation)) if self.host_requested_current() => {
                // Host contention, as in `park_service` (#1467): the retained
                // owner wait resumes at this record's next owner entry.
                self.retain_record_operation(operation)?;
                self.yield_service_checkpoint()
            }
            Err((_, operation)) => {
                self.restore_preparation_operation(operation)?;
                Err(NativeProcessError::Quarantined)
            }
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
            .map_err(service_protocol_error)?;
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
        service_rebind: carrick_core_abi::service::PreparedServiceRebind<'_>,
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
            .exit_with_signal(carrick_signal_core::policy::Signal::KILL)
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
    fn retire_adapter_result(
        &mut self,
        error: SyscallResult,
    ) -> Result<SyscallResult, NativeProcessError> {
        let token = carrick_core::wait::take_object_operation(
            self.source.zone,
            self.source.slot,
            self.source.zone.record(self.record.id).identity(),
        )
        .map_err(|_| NativeProcessError::Quarantined)?
        .ok_or(NativeProcessError::Stale)?;
        let written = self.service.retire_adapter_operation(self.binding, token)?;
        // SAFETY: this exact admitted record still owns the completed adapter.
        unsafe {
            self.source
                .zone
                .record(self.record.id)
                .consume_owner_continuation()
        };
        Ok(if written == 0 {
            error
        } else {
            SyscallResult::new(written as i64)
        })
    }

    #[inline(never)]
    fn finish_adapter_service(
        &mut self,
        result: ServiceResult,
        claim: carrick_core::terminal::NativeServiceClaim<&'a ThreadLifecyclePage>,
    ) -> Result<NativeResume, NativeProcessError> {
        let value = if result == ServiceResult::Supplied {
            None
        } else {
            Some(self.retire_adapter_result(SyscallResult::new(
                carrick_syscall_abi::LINUX_EFAULT.guest_retval(),
            ))?)
        };
        self.release_service_claim(claim)?;
        Ok(value.map_or(NativeResume::RetrySyscall, NativeResume::Returned))
    }

    #[inline(never)]
    fn finish_service(
        &mut self,
        request: &ServiceRequest,
        mut result: ServiceResult,
        pending: Box<PendingService<'a>>,
    ) -> Result<NativeResume, NativeProcessError> {
        self.service_phase = NativeServicePhase::Completion;
        if pending.request != *request {
            return Err(NativeProcessError::Quarantined);
        }
        let retry_syscall_after_supply = pending.retry_syscall_after_supply;
        let exiting = self.runtime.graph.lock().pending.has_exit(&self.key)
            || ((pending.copyout.is_some() || pending.copyin)
                && pending.claim.cancellation().is_some());
        if (exiting || result == ServiceResult::Cancelled)
            && let Some(PendingServiceReply::Fault(reply)) = &pending.reply
        {
            self.service
                .apply_fault_reply(reply, super::FaultReplyDisposition::Cancel)
                .map_err(|_| NativeProcessError::Quarantined)?;
        }
        if exiting {
            self.take_relative_futex();
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
                            ServiceOperation::Crossing { .. }
                            | ServiceOperation::Exec { .. }
                            | ServiceOperation::HostFile { .. } => OwnerEntry::Syscall,
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
            match self
                .service
                .apply_fault_reply(reply, super::FaultReplyDisposition::Apply)
            {
                Ok(()) => {}
                Err(carrick_core::mm::transaction::MmError::Wait(wait)) => {
                    let next = self.prepare_fault_repark(request, pending, wait)?;
                    return self.park_owner_wait(&next, wait);
                }
                Err(_) => result = ServiceResult::Refused,
            }
        }
        if result != ServiceResult::Supplied {
            self.take_relative_futex();
        }
        self.finish_service_result(request, result, pending, retry_syscall_after_supply)
    }

    #[inline(never)]
    fn prepare_fault_repark(
        &mut self,
        request: &ServiceRequest,
        mut pending: Box<PendingService<'a>>,
        wait: carrick_core_abi::PortalOwnerWait,
    ) -> Result<ServiceRequest, NativeProcessError> {
        // Pending already owns the reply and lifecycle claim outside the graph.
        // Return the small request by value so allocation failure cannot
        // discard that custody before its replacement wait is published.
        let key = ObjectWaitKey::native_service(self.record).ok_or(NativeProcessError::Stale)?;
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
            .map_err(service_protocol_error)?;
        pending.request = next;
        pending.wait = Some(wait);
        self.runtime
            .graph
            .lock()
            .insert_member_wait(self.record, MemberWait::Service(pending));
        drop(queue);
        Ok(next)
    }

    // Fault application above must not retain exec-close or host-file result
    // locals. Pending payloads stay in their existing box across this boundary.
    #[inline(never)]
    fn finish_service_result(
        &mut self,
        request: &ServiceRequest,
        result: ServiceResult,
        mut pending: Box<PendingService<'a>>,
        retry_syscall_after_supply: bool,
    ) -> Result<NativeResume, NativeProcessError> {
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
        let output = pending.copyout.take();
        if pending.adapter {
            return self.finish_adapter_service(result, pending.claim);
        }
        let completed = (|| {
            if output.is_some() {
                return if matches!(request.operation, ServiceOperation::Fault(_))
                    && result != ServiceResult::Supplied
                {
                    Ok(NativeResume::Returned(SyscallResult::new(
                        carrick_syscall_abi::LINUX_EFAULT.guest_retval(),
                    )))
                } else {
                    Ok(NativeResume::NoPending)
                };
            }
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
                (ServiceOperation::HostFile { .. }, ServiceResult::Supplied)
                | (ServiceOperation::HostFile { .. }, ServiceResult::Cancelled)
                    if pending.host_file.as_ref().is_some_and(|file| {
                        carrick_core_abi::host_file::reply(&file.record).is_some()
                    }) =>
                {
                    // The carrier writes its reply before acknowledging. A
                    // cancellation that lost the race to an effect still
                    // reports that effect (bytes written stay written); the
                    // ring maps it and copies output to its own user memory.
                    let pending_file = pending
                        .host_file
                        .as_ref()
                        .ok_or(NativeProcessError::Stale)?;
                    if let Some(key) = pending_file.map {
                        // A private file mapping: the carrier retained the
                        // byte source; the ring's reservation owner maps it
                        // on this exact call's immediate retry.
                        return match (
                            carrick_personality_linux::native_host_file::map_source(
                                &pending_file.record,
                            ),
                            result,
                        ) {
                            (Err(result), _) => Ok(NativeResume::Returned(result)),
                            (Ok(source), _) => {
                                // Linux never interrupts mmap: a cancelled
                                // service that already retained the source
                                // still maps it on the restarted call, after
                                // whatever cancelled it is delivered.
                                self.stash_map_source(
                                    key,
                                    carrick_core_abi::HostBackingIdentity::new(
                                        source.handle,
                                        source.generation,
                                        0,
                                    ),
                                )?;
                                Ok(NativeResume::RetrySyscall)
                            }
                        };
                    }
                    if pending_file.chdir {
                        return self
                            .complete_chdir(&pending_file.record, pending_file.call)
                            .map(NativeResume::Returned);
                    }
                    let mut copy_out = |address: u64, bytes: &[u8]| {
                        self.copy_syscall_output(carrick_guest_arch::UserVa::new(address), bytes)
                            .is_ok()
                    };
                    Ok(NativeResume::Returned(
                        carrick_personality_linux::native_host_file::complete(
                            &pending_file.record,
                            pending_file.output,
                            &mut copy_out,
                        ),
                    ))
                }
                (ServiceOperation::HostFile { .. }, ServiceResult::Supplied) => {
                    // Supplied without a reply is a transport violation.
                    Err(NativeProcessError::Quarantined)
                }
                (ServiceOperation::HostFile { .. }, ServiceResult::Refused) => {
                    // The venue does not serve this exact request: counted
                    // ENOSYS (hvpatch-native-crossing-refused), never a guess.
                    Ok(NativeResume::Returned(SyscallResult::new(
                        carrick_syscall_abi::LINUX_ENOSYS.guest_retval(),
                    )))
                }
                (ServiceOperation::HostFile { .. }, ServiceResult::Cancelled) => {
                    // No effect happened. The venue's operations on regular
                    // files, directories and paths are not interruptible in
                    // Linux (no EINTR): the call restarts once whatever
                    // cancelled the service has been delivered.
                    Ok(NativeResume::RetrySyscall)
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
        if let Some(output) = output {
            if !matches!(completed, Ok(NativeResume::NoPending)) {
                return completed;
            }
            // Unwind all service/queue frames before the next write attempt.
            // The entering owner drains this exact completed output below.
            self.copyout_ready = Some(output);
            return Ok(NativeResume::NoPending);
        }
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
pub(super) fn service_protocol_error(error: ServiceError) -> NativeProcessError {
    match error {
        // All callers either own the exact executing member before transport
        // publication, or hold its native-service queue. The transport takes
        // that same queue for claim and acknowledgment. Expected not-ready
        // consumption is handled before this mapper; a failed transition here
        // means duplicate/mismatched custody, not a releasable resource.
        ServiceError::Busy => NativeProcessError::Quarantined,
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
