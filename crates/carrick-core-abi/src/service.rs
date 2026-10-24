//! Exact native service operations. The ring retains semantic custody until
//! an exact completion or cancellation acknowledgment is consumed.
use crate::{El1MmHandle, EntryThreadGeneration, SnapshotGeneration};
use carrick_guest_arch::{Access, FaultInfo, NativeOrdinal};
use carrick_sched_core::{RecordRef, object_wait::OwnerEntry, process::TaskKey};
use core::num::NonZeroU64;
use core::ops::Deref;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceBirth {
    pub process: TaskKey,
    pub thread: EntryThreadGeneration,
    pub record: RecordRef,
    pub mm: El1MmHandle,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceIdentity {
    pub birth: ServiceBirth,
    pub execution: SnapshotGeneration,
    pub sequence: NonZeroU64,
}
/// Physical demand selected by the ring; mapping policy stays with the owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceFaultSupply {
    Cow(crate::PortalGrantWindow),
    Backing(crate::PortalGrantWindow),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceOperation {
    Fault(FaultInfo),
    Crossing {
        ordinal: NativeOrdinal,
    },
    /// Deliver carrier work before resuming the exact saved instruction context.
    CarrierWork {
        entry: OwnerEntry,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceRequest {
    pub identity: ServiceIdentity,
    pub operation: ServiceOperation,
    /// Exact ring-selected portal operation, captured before releasing the lane.
    pub fault_sequence: Option<NonZeroU64>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceResult {
    BackingFault,
    Supplied,
    Refused,
    Cancelled,
    Wait(crate::PortalOwnerWait),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    Busy,
    Stale,
    Exhausted,
}

pub const NATIVE_SERVICE_PROTOCOL: u64 = 4;

/// Transport selector only: authority remains in the member's retained cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceSelector {
    pub record: RecordRef,
    pub execution: SnapshotGeneration,
    pub sequence: NonZeroU64,
}
impl From<ServiceIdentity> for ServiceSelector {
    fn from(identity: ServiceIdentity) -> Self {
        Self {
            record: identity.birth.record,
            execution: identity.execution,
            sequence: identity.sequence,
        }
    }
}

/// One producer per execution lane. Publication is followed by an owned park
/// and exit; the host consumes the notice before admitting that lane again.
/// A notice is not a second task owner and contains no dereferenceable pointer.
#[repr(C)]
#[derive(Debug)]
pub struct ServiceNotice {
    record: AtomicU64,
    incarnation: AtomicU64,
    execution: AtomicU64,
    sequence: AtomicU64,
}
impl ServiceNotice {
    pub const fn new() -> Self {
        Self {
            record: AtomicU64::new(0),
            incarnation: AtomicU64::new(0),
            execution: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
        }
    }
    pub fn publish(&self, selector: ServiceSelector) -> Result<(), ServiceError> {
        self.record
            .compare_exchange(0, u64::MAX, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Busy)?;
        self.incarnation
            .store(selector.record.incarnation, Ordering::Relaxed);
        self.execution
            .store(selector.execution.raw(), Ordering::Relaxed);
        self.sequence
            .store(selector.sequence.get(), Ordering::Relaxed);
        self.record
            .store(u64::from(selector.record.id.raw()) + 1, Ordering::Release);
        Ok(())
    }
    pub fn take(&self) -> Result<Option<ServiceSelector>, ServiceError> {
        let record = self.record.load(Ordering::Acquire);
        if record == 0 {
            return Ok(None);
        }
        if record == u64::MAX {
            return Err(ServiceError::Busy);
        }
        self.record
            .compare_exchange(record, u64::MAX, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Busy)?;
        let selector = (|| {
            Some(ServiceSelector {
                record: RecordRef {
                    id: carrick_sched_core::RecordId::from_raw(u32::try_from(record - 1).ok()?)?,
                    incarnation: self.incarnation.load(Ordering::Relaxed),
                },
                execution: SnapshotGeneration::from_raw(self.execution.load(Ordering::Relaxed)),
                sequence: NonZeroU64::new(self.sequence.load(Ordering::Relaxed))?,
            })
        })();
        self.record.store(0, Ordering::Release);
        selector.map(Some).ok_or(ServiceError::Stale)
    }
}
impl Default for ServiceNotice {
    fn default() -> Self {
        Self::new()
    }
}

const UNBOUND: u64 = 0;
const IDLE: u64 = 1;
const WRITING: u64 = 2;
const REQUESTED: u64 = 3;
const SERVICING: u64 = 4;
const CANCEL_REQUESTED: u64 = 5;
const COMPLETED: u64 = 6;
const CANCELLED: u64 = 7;
const CANCEL_QUEUED: u64 = 8;
const OWNED_WAIT: u64 = 9;
const WAIT_CANCELLED: u64 = 10;

/// A member owns this cell, not the execution slot. Its enclosing allocation
/// and semantic MM claim must remain retained through acknowledgment. All
/// fields are atomic because rejected readers may overlap a later publication.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct ServiceCell {
    state: AtomicU64,
    sequence: AtomicU64,
    words: [AtomicU64; 12],
    result: AtomicU64,
    wait_revision: AtomicU64,
}
impl ServiceCell {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(UNBOUND),
            sequence: AtomicU64::new(0),
            words: [const { AtomicU64::new(0) }; 12],
            result: AtomicU64::new(0),
            wait_revision: AtomicU64::new(0),
        }
    }
    // Binding/publication must use authenticated lifecycle and admitted-MM
    // owners. Identity decoding grants no authority by itself.
}
impl Default for ServiceCell {
    fn default() -> Self {
        Self::new()
    }
}
impl ServiceBirth {
    fn words(self) -> [u64; 8] {
        [
            self.mm.carrier().get(),
            self.process.id.raw() as u64,
            self.process.serial.raw(),
            self.thread.raw(),
            u64::from(self.record.id.raw()),
            self.record.incarnation,
            self.mm.mm().raw(),
            self.mm.incarnation().get(),
        ]
    }
}
impl ServiceCell {
    /// Publish only after the native owner has authenticated the complete
    /// lifecycle birth and admitted MM. No execution slot is part of custody.
    pub fn bind(&self, birth: ServiceBirth) -> Result<(), ServiceError> {
        if birth.thread.raw() == 0 || birth.record.incarnation == 0 {
            return Err(ServiceError::Stale);
        }
        self.state
            .compare_exchange(UNBOUND, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Busy)?;
        for (word, value) in self.words.iter().zip(birth.words()) {
            word.store(value, Ordering::Relaxed);
        }
        self.state.store(IDLE, Ordering::Release);
        Ok(())
    }
    /// Recover the immutable admitted-MM identity from this member's birth.
    /// The native entry has already authenticated its task/thread/record;
    /// recovering this retained handle never acquires a reservation root.
    pub fn bound_birth(
        &self,
        process: TaskKey,
        thread: EntryThreadGeneration,
        record: RecordRef,
    ) -> Result<ServiceBirth, ServiceError> {
        self.state
            .compare_exchange(IDLE, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Busy)?;
        let birth = (|| {
            let carrier = NonZeroU64::new(self.words[0].load(Ordering::Relaxed))
                .ok_or(ServiceError::Stale)?;
            let mm = crate::ReservationMm::new(self.words[6].load(Ordering::Relaxed))
                .ok_or(ServiceError::Stale)?;
            let incarnation = NonZeroU64::new(self.words[7].load(Ordering::Relaxed))
                .ok_or(ServiceError::Stale)?;
            // SAFETY: bind stored this admitted handle; IDLE excludes an
            // outstanding request and the WRITING reservation excludes reset.
            let mm = unsafe { El1MmHandle::from_admitted_owner(carrier, mm, incarnation) };
            let birth = ServiceBirth {
                process,
                thread,
                record,
                mm,
            };
            self.same_birth(birth)
                .then_some(birth)
                .ok_or(ServiceError::Stale)
        })();
        self.state.store(IDLE, Ordering::Release);
        birth
    }

    /// Recover the birth MM for a currently executing, exact member. This
    /// does not probe the reservation root whose contention is being handled.
    pub fn bound_mm(
        &self,
        record: RecordRef,
        thread: EntryThreadGeneration,
    ) -> Result<El1MmHandle, ServiceError> {
        let id = i32::try_from(self.words[1].load(Ordering::Acquire))
            .ok()
            .and_then(core::num::NonZeroI32::new)
            .ok_or(ServiceError::Stale)?;
        let serial =
            NonZeroU64::new(self.words[2].load(Ordering::Acquire)).ok_or(ServiceError::Stale)?;
        let process = TaskKey {
            id: carrick_sched_core::process::TaskId::from_registry_allocation(id),
            serial: carrick_sched_core::process::TaskSerial::from_registry_allocation(serial),
        };
        self.bound_birth(process, thread, record)
            .map(|birth| birth.mm)
    }

    /// Caller holds the member reset reservation. An outstanding request
    /// refuses reset even if a physical metadata pin keeps its bytes mapped.
    pub fn reset_unpublished(&self) -> Result<(), ServiceError> {
        let state = self.state.load(Ordering::Acquire);
        if !matches!(state, UNBOUND | IDLE) {
            return Err(ServiceError::Busy);
        }
        self.state
            .compare_exchange(state, UNBOUND, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ServiceError::Busy)?;
        Ok(())
    }
    pub fn publish(
        &self,
        birth: ServiceBirth,
        execution: SnapshotGeneration,
        operation: ServiceOperation,
        fault_sequence: Option<NonZeroU64>,
    ) -> Result<ServiceRequest, ServiceError> {
        self.publish_with_reply(birth, execution, operation, fault_sequence, None)
    }
    /// Reply storage belongs to the ring continuation through service ACK.
    /// The transport authenticates its retained allocation before accessing it.
    pub fn publish_with_reply(
        &self,
        birth: ServiceBirth,
        execution: SnapshotGeneration,
        operation: ServiceOperation,
        fault_sequence: Option<NonZeroU64>,
        reply: Option<carrick_guest_arch::KernelVa>,
    ) -> Result<ServiceRequest, ServiceError> {
        self.state
            .compare_exchange(IDLE, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Busy)?;
        if !execution.issued()
            || !self.same_birth(birth)
            || (fault_sequence.is_some() && !matches!(operation, ServiceOperation::Fault(_)))
            || (reply.is_some()
                && (fault_sequence.is_none()
                    || !matches!(operation, ServiceOperation::Fault(fault) if !fault.present)))
            || reply.is_some_and(|address| address.raw() == 0)
        {
            self.state.store(IDLE, Ordering::Release);
            return Err(ServiceError::Stale);
        }
        let Some(next) = self
            .sequence
            .load(Ordering::Relaxed)
            .checked_add(1)
            .and_then(NonZeroU64::new)
        else {
            self.state.store(IDLE, Ordering::Release);
            return Err(ServiceError::Exhausted);
        };
        let (kind, first, second) = match operation {
            ServiceOperation::Fault(fault) => (1, fault_bits(fault), fault.address.raw()),
            ServiceOperation::Crossing { ordinal } => (2, ordinal.raw(), 0),
            ServiceOperation::CarrierWork { entry } => {
                (3, u64::from(entry == OwnerEntry::Syscall), 0)
            }
        };
        for (index, value) in [(8, execution.raw()), (9, kind), (10, first), (11, second)] {
            self.words[index].store(value, Ordering::Relaxed);
        }
        // The request stamp and completion result occupy disjoint protocol
        // phases. Claim copies the stamp before acknowledgment writes a result.
        self.result
            .store(fault_sequence.map_or(0, NonZeroU64::get), Ordering::Relaxed);
        self.wait_revision
            .store(reply.map_or(0, |address| address.raw()), Ordering::Relaxed);
        self.sequence.store(next.get(), Ordering::Relaxed);
        self.state.store(REQUESTED, Ordering::Release);
        Ok(ServiceRequest {
            identity: ServiceIdentity {
                birth,
                execution,
                sequence: next,
            },
            operation,
            fault_sequence,
        })
    }
    #[inline(never)]
    fn same_birth(&self, birth: ServiceBirth) -> bool {
        self.words
            .iter()
            .zip(birth.words())
            .all(|(word, value)| word.load(Ordering::Relaxed) == value)
    }
    #[inline(never)]
    fn same(&self, identity: ServiceIdentity) -> bool {
        self.same_birth(identity.birth)
            && self.words[8].load(Ordering::Relaxed) == identity.execution.raw()
            && self.sequence.load(Ordering::Relaxed) == identity.sequence.get()
    }
    #[inline(never)]
    fn lock_exact(&self, expected: u64, identity: ServiceIdentity) -> Result<(), ServiceError> {
        self.state
            .compare_exchange(expected, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Busy)?;
        if self.same(identity) {
            return Ok(());
        }
        self.state.store(expected, Ordering::Release);
        Err(ServiceError::Stale)
    }
    /// Claim a notice against its independently retained native member.
    ///
    /// # Safety
    /// `pin` must retain the exact control allocation of `member.record` in
    /// `carrier`. The caller holds that record's native-service queue lock.
    /// The native owner published the cell under its outstanding MM/lifecycle
    /// claim; cancellation cannot release that claim during this transition.
    pub unsafe fn claim_notice<P: Deref<Target = Self>>(
        pin: P,
        selector: ServiceSelector,
        carrier: NonZeroU64,
        member: carrick_sched_core::ThreadIdentity,
    ) -> Result<ServiceTicket<P>, ServiceError> {
        let cell = &*pin;
        let state = cell.state.load(Ordering::Acquire);
        if !matches!(state, REQUESTED | CANCEL_QUEUED) {
            return Err(ServiceError::Stale);
        }
        cell.state
            .compare_exchange(state, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Stale)?;
        let decoded = (|| {
            let incarnation = NonZeroU64::new(cell.words[7].load(Ordering::Relaxed))
                .ok_or(ServiceError::Stale)?;
            let mm = crate::ReservationMm::new(member.mm).ok_or(ServiceError::Stale)?;
            // SAFETY: this is a copy of the admitted handle retained by the
            // ring's outstanding claim, not admission from a raw host request.
            let mm = unsafe { El1MmHandle::from_admitted_owner(carrier, mm, incarnation) };
            let process_id = i32::try_from(cell.words[1].load(Ordering::Relaxed))
                .ok()
                .and_then(core::num::NonZeroI32::new)
                .ok_or(ServiceError::Stale)?;
            let birth = NonZeroU64::new(cell.words[2].load(Ordering::Relaxed))
                .ok_or(ServiceError::Stale)?;
            let process = TaskKey {
                id: carrick_sched_core::process::TaskId::from_registry_allocation(process_id),
                serial: carrick_sched_core::process::TaskSerial::from_registry_allocation(birth),
            };
            let identity = ServiceIdentity {
                birth: ServiceBirth {
                    process,
                    thread: EntryThreadGeneration::from_raw(member.serial),
                    record: selector.record,
                    mm,
                },
                execution: selector.execution,
                sequence: selector.sequence,
            };
            if member.generation != selector.execution.raw() || !cell.same(identity) {
                return Err(ServiceError::Stale);
            }
            let first = cell.words[10].load(Ordering::Relaxed);
            let operation = match cell.words[9].load(Ordering::Relaxed) {
                1 if first <= 6 && first & 3 != 3 => ServiceOperation::Fault(FaultInfo {
                    address: carrick_guest_arch::UserVa::new(
                        cell.words[11].load(Ordering::Relaxed),
                    ),
                    access: match first & 3 {
                        0 => Access::Read,
                        1 => Access::Write,
                        _ => Access::Execute,
                    },
                    present: first & 4 != 0,
                }),
                2 => ServiceOperation::Crossing {
                    ordinal: NativeOrdinal::new(first),
                },
                3 if first <= 1 && cell.words[11].load(Ordering::Relaxed) == 0 => {
                    ServiceOperation::CarrierWork {
                        entry: if first == 1 {
                            OwnerEntry::Syscall
                        } else {
                            OwnerEntry::Exception
                        },
                    }
                }
                _ => return Err(ServiceError::Stale),
            };
            let fault_sequence = NonZeroU64::new(cell.result.load(Ordering::Relaxed));
            if fault_sequence.is_some() && !matches!(operation, ServiceOperation::Fault(_)) {
                return Err(ServiceError::Stale);
            }
            Ok(ServiceRequest {
                identity,
                operation,
                fault_sequence,
            })
        })();
        match decoded {
            Ok(request) => {
                cell.state.store(
                    if state == CANCEL_QUEUED {
                        CANCEL_REQUESTED
                    } else {
                        SERVICING
                    },
                    Ordering::Release,
                );
                Ok(ServiceTicket {
                    reply: NonZeroU64::new(cell.wait_revision.load(Ordering::Relaxed))
                        .map(|address| carrick_guest_arch::KernelVa::new(address.get())),
                    cell: core::mem::ManuallyDrop::new(pin),
                    request,
                    selection_taken: false,
                })
            }
            Err(error) => {
                cell.state.store(state, Ordering::Release);
                Err(error)
            }
        }
    }

    /// The transport supplies the immutable copied request; claiming validates
    /// it under the cell transition before giving out one non-cloneable ticket.
    pub fn claim(&self, request: ServiceRequest) -> Result<ServiceTicket<&Self>, ServiceError> {
        Self::claim_owned(self, request)
    }

    /// Transfer an authenticated mapping pin into the unique operation ticket.
    /// The pin, unlike the executor's slot, lives through acknowledgment.
    pub fn claim_owned<P: Deref<Target = Self>>(
        pin: P,
        request: ServiceRequest,
    ) -> Result<ServiceTicket<P>, ServiceError> {
        let cell = &*pin;
        let state = cell.state.load(Ordering::Acquire);
        if !matches!(state, REQUESTED | CANCEL_QUEUED) {
            return Err(ServiceError::Busy);
        }
        cell.lock_exact(state, request.identity)?;
        let operation_matches = match request.operation {
            ServiceOperation::Fault(fault) => {
                cell.words[9].load(Ordering::Relaxed) == 1
                    && cell.words[10].load(Ordering::Relaxed) == fault_bits(fault)
                    && cell.words[11].load(Ordering::Relaxed) == fault.address.raw()
            }
            ServiceOperation::Crossing { ordinal } => {
                cell.words[9].load(Ordering::Relaxed) == 2
                    && cell.words[10].load(Ordering::Relaxed) == ordinal.raw()
            }
            ServiceOperation::CarrierWork { entry } => {
                cell.words[9].load(Ordering::Relaxed) == 3
                    && cell.words[10].load(Ordering::Relaxed)
                        == u64::from(entry == OwnerEntry::Syscall)
                    && cell.words[11].load(Ordering::Relaxed) == 0
            }
        };
        if !operation_matches
            || cell.result.load(Ordering::Relaxed)
                != request.fault_sequence.map_or(0, NonZeroU64::get)
        {
            cell.state.store(state, Ordering::Release);
            return Err(ServiceError::Stale);
        }
        cell.state.store(
            if state == CANCEL_QUEUED {
                CANCEL_REQUESTED
            } else {
                SERVICING
            },
            Ordering::Release,
        );
        Ok(ServiceTicket {
            reply: NonZeroU64::new(cell.wait_revision.load(Ordering::Relaxed))
                .map(|address| carrick_guest_arch::KernelVa::new(address.get())),
            cell: core::mem::ManuallyDrop::new(pin),
            request,
            selection_taken: false,
        })
    }
    /// Return true only when no host operation remains. Cancellation of an
    /// active ticket needs the ticket's acknowledgment, retaining all custody.
    pub fn cancel(&self, identity: ServiceIdentity) -> Result<bool, ServiceError> {
        let state = self.state.load(Ordering::Acquire);
        match state {
            IDLE => {
                // Consumption and graph removal are separate owner steps.
                // Under the operation queue lock, cancellation may observe
                // that acknowledged sequence between those steps.
                self.lock_exact(IDLE, identity)?;
                self.state.store(IDLE, Ordering::Release);
                Ok(true)
            }
            OWNED_WAIT | WAIT_CANCELLED => {
                self.lock_exact(state, identity)?;
                self.state.store(WAIT_CANCELLED, Ordering::Release);
                Ok(true)
            }
            REQUESTED | CANCEL_QUEUED | SERVICING | CANCEL_REQUESTED | COMPLETED | CANCELLED => {
                self.lock_exact(state, identity)?;
                let acknowledged = matches!(state, COMPLETED | CANCELLED);
                self.state.store(
                    if acknowledged {
                        CANCELLED
                    } else if matches!(state, REQUESTED | CANCEL_QUEUED) {
                        CANCEL_QUEUED
                    } else {
                        CANCEL_REQUESTED
                    },
                    Ordering::Release,
                );
                Ok(acknowledged)
            }
            _ => Err(ServiceError::Busy),
        }
    }
    /// Roll back a request whose transport publication failed.
    ///
    /// # Safety
    /// No notice or ticket for this identity may have been delivered. Once a
    /// notice is published, even cancellation must wait for physical intake.
    pub unsafe fn abort_unpublished(&self, identity: ServiceIdentity) -> Result<(), ServiceError> {
        let state = self.state.load(Ordering::Acquire);
        if !matches!(state, REQUESTED | CANCEL_QUEUED) {
            return Err(ServiceError::Busy);
        }
        self.lock_exact(state, identity)?;
        self.state.store(CANCELLED, Ordering::Release);
        Ok(())
    }

    /// The ring consumes exactly one acknowledged operation before releasing
    /// its retained MM/member capabilities or deciding a guest-visible result.
    pub fn consume(&self, identity: ServiceIdentity) -> Result<ServiceResult, ServiceError> {
        let state = self.state.load(Ordering::Acquire);
        if !matches!(state, COMPLETED | CANCELLED) {
            return Err(ServiceError::Busy);
        }
        self.lock_exact(state, identity)?;
        let result = if state == CANCELLED {
            ServiceResult::Cancelled
        } else if self.result.load(Ordering::Relaxed) == 16 {
            ServiceResult::BackingFault
        } else if self.result.load(Ordering::Relaxed) == 1 {
            ServiceResult::Supplied
        } else if let Some(cause) =
            crate::PortalWaitCause::decode(self.result.load(Ordering::Relaxed).saturating_sub(2))
        {
            // SAFETY: complete_wait checked the retained exact MM identity;
            // the service ticket supplies its pre-probe resource revision.
            ServiceResult::Wait(unsafe {
                crate::PortalOwnerWait::from_owner(
                    identity.birth.mm,
                    cause,
                    self.wait_revision.load(Ordering::Relaxed),
                )
            })
        } else {
            ServiceResult::Refused
        };
        self.state.store(
            if matches!(result, ServiceResult::Wait(_)) {
                OWNED_WAIT
            } else {
                IDLE
            },
            Ordering::Release,
        );
        Ok(result)
    }
    /// Reserve a ring-owned resource wait without publishing external work.
    /// Caller holds the member service queue across request/phase publication.
    pub fn begin_owner_wait(
        &self,
        birth: ServiceBirth,
        execution: SnapshotGeneration,
        operation: ServiceOperation,
        wait: crate::PortalOwnerWait,
    ) -> Result<ServiceRequest, ServiceError> {
        if wait.handle() != birth.mm {
            return Err(ServiceError::Stale);
        }
        let request = self.publish(birth, execution, operation, None)?;
        self.lock_exact(REQUESTED, request.identity)?;
        self.result
            .store(2 + wait.cause().encode(), Ordering::Relaxed);
        self.wait_revision.store(wait.revision(), Ordering::Relaxed);
        self.state.store(OWNED_WAIT, Ordering::Release);
        Ok(request)
    }
    /// Inspect sticky cancellation under the stable member service queue.
    pub fn owner_wait_cancelled(&self, identity: ServiceIdentity) -> Result<bool, ServiceError> {
        let state = self.state.load(Ordering::Acquire);
        if !matches!(state, OWNED_WAIT | WAIT_CANCELLED) {
            return Err(ServiceError::Busy);
        }
        self.lock_exact(state, identity)?;
        self.state.store(state, Ordering::Release);
        Ok(state == WAIT_CANCELLED)
    }
    /// Consume the one owner wait after its producer edge or cancellation.
    /// No external ticket or second acknowledgment exists for this phase.
    pub fn finish_owner_wait(
        &self,
        identity: ServiceIdentity,
    ) -> Result<ServiceResult, ServiceError> {
        let state = self.state.load(Ordering::Acquire);
        if !matches!(state, OWNED_WAIT | WAIT_CANCELLED) {
            return Err(ServiceError::Busy);
        }
        self.lock_exact(state, identity)?;
        self.state.store(IDLE, Ordering::Release);
        Ok(if state == WAIT_CANCELLED {
            ServiceResult::Cancelled
        } else {
            ServiceResult::Supplied
        })
    }
}
/// Dropping a transport handle is not completion: it leaves the operation and
/// its retained resources outstanding. Only explicit acknowledgment releases it.
#[must_use]
pub struct ServiceTicket<P: Deref<Target = ServiceCell>> {
    cell: core::mem::ManuallyDrop<P>,
    request: ServiceRequest,
    selection_taken: bool,
    reply: Option<carrick_guest_arch::KernelVa>,
}
impl<P: Deref<Target = ServiceCell>> ServiceTicket<P> {
    pub fn reply_address(&self) -> Option<carrick_guest_arch::KernelVa> {
        self.reply
    }

    pub fn request(&self) -> ServiceRequest {
        self.request
    }
    /// Claim at most one lane selection before the transport releases that
    /// execution lane. The ticket cannot later consume a successor's window.
    pub fn take_fault_selection(
        &mut self,
        slot: &crate::PortalGrantSlot,
    ) -> Result<Option<ServiceFaultSupply>, ServiceError> {
        if self.selection_taken {
            return Err(ServiceError::Stale);
        }
        self.selection_taken = true;
        slot.take_native_fault_selection(self)
    }
    pub fn complete_backing_fault(self) -> Result<(), (ServiceError, Self)> {
        if !matches!(self.request().operation, ServiceOperation::Fault(fault) if !fault.present) {
            return Err((ServiceError::Stale, self));
        }
        self.acknowledge(16, 0)
    }
    pub fn complete(self, supplied: bool) -> Result<(), (ServiceError, Self)> {
        self.acknowledge(u64::from(supplied), 0)
    }
    /// Acknowledge physical service and transfer the same continuation to an
    /// exact-MM producer. No physical resource guard survives this call.
    pub fn complete_wait(self, wait: crate::PortalOwnerWait) -> Result<(), (ServiceError, Self)> {
        if wait.handle() != self.request.identity.birth.mm {
            return Err((ServiceError::Stale, self));
        }
        self.acknowledge(2 + wait.cause().encode(), wait.revision())
    }
    fn acknowledge(mut self, result: u64, revision: u64) -> Result<(), (ServiceError, Self)> {
        let cell = &**self.cell;
        let state = cell.state.load(Ordering::Acquire);
        if !matches!(state, SERVICING | CANCEL_REQUESTED) {
            return Err((
                if state == WRITING {
                    ServiceError::Busy
                } else {
                    ServiceError::Stale
                },
                self,
            ));
        }
        if let Err(error) = cell.lock_exact(state, self.request.identity) {
            return Err((error, self));
        }
        cell.result.store(result, Ordering::Relaxed);
        cell.wait_revision.store(revision, Ordering::Relaxed);
        cell.state.store(
            if state == CANCEL_REQUESTED {
                CANCELLED
            } else {
                COMPLETED
            },
            Ordering::Release,
        );
        // Only acknowledgment releases the physical mapping pin.
        // SAFETY: complete consumes this ticket; ManuallyDrop has no drop
        // glue, and no successful acknowledgment can use this pin again.
        unsafe { core::mem::ManuallyDrop::drop(&mut self.cell) };
        Ok(())
    }
}

fn fault_bits(fault: FaultInfo) -> u64 {
    let access = match fault.access {
        Access::Read => 0,
        Access::Write => 1,
        Access::Execute => 2,
    };
    access | (u64::from(fault.present) << 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_guest_arch::UserVa;
    use carrick_sched_core::{
        RecordId,
        process::{TaskId, TaskSerial},
    };
    use core::num::NonZeroI32;

    fn birth(id: u32, generation: u64) -> ServiceBirth {
        let generation = NonZeroU64::new(generation).unwrap();
        ServiceBirth {
            process: TaskKey {
                id: TaskId::from_registry_allocation(NonZeroI32::new(id as i32).unwrap()),
                serial: TaskSerial::from_registry_allocation(generation),
            },
            thread: EntryThreadGeneration::from_raw(generation.get()),
            record: RecordRef {
                id: RecordId::from_raw(id).unwrap(),
                incarnation: generation.get(),
            },
            // SAFETY: this wire-protocol fixture owns an immutable, never-reused
            // synthetic MM identity. It does not authorize a memory operation.
            mm: unsafe {
                El1MmHandle::from_admitted_owner(
                    NonZeroU64::MIN,
                    crate::ReservationMm::new(u64::from(id)).unwrap(),
                    generation,
                )
            },
        }
    }
    fn fault() -> ServiceOperation {
        ServiceOperation::Fault(FaultInfo {
            address: UserVa::new(0x6000000fd8),
            access: Access::Write,
            present: true,
        })
    }

    #[test]
    fn two_service_cells_cancel_one_without_consuming_the_other() {
        let first = ServiceCell::new();
        let second = ServiceCell::new();
        let first_birth = birth(1, 1);
        let second_birth = birth(2, 1);
        first.bind(first_birth).unwrap();
        second.bind(second_birth).unwrap();
        let a = first
            .publish(first_birth, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        let b = second
            .publish(second_birth, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        let a_ticket = first.claim(a).unwrap();
        let b_ticket = second.claim(b).unwrap();
        assert!(!first.cancel(a.identity).unwrap());
        assert_eq!(first.consume(a.identity), Err(ServiceError::Busy));
        assert_eq!(first.reset_unpublished(), Err(ServiceError::Busy));
        assert!(b_ticket.complete(true).is_ok());
        assert_eq!(second.consume(b.identity), Ok(ServiceResult::Supplied));
        assert_eq!(first.consume(a.identity), Err(ServiceError::Busy));
        assert!(a_ticket.complete(true).is_ok());
        assert_eq!(first.consume(a.identity), Ok(ServiceResult::Cancelled));
        assert_eq!(first.consume(a.identity), Err(ServiceError::Busy));
        assert_eq!(second.consume(b.identity), Err(ServiceError::Busy));
    }

    #[test]
    fn consumed_request_cancellation_does_not_cancel_its_successor() {
        let cell = ServiceCell::new();
        let owner = birth(1, 1);
        cell.bind(owner).unwrap();
        let first = cell
            .publish(owner, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        assert!(cell.claim(first).unwrap().complete(true).is_ok());
        assert_eq!(cell.consume(first.identity), Ok(ServiceResult::Supplied));
        assert_eq!(cell.cancel(first.identity), Ok(true));
        let next = cell
            .publish(owner, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        assert_eq!(cell.cancel(first.identity), Err(ServiceError::Stale));
        assert!(cell.claim(next).unwrap().complete(true).is_ok());
        assert_eq!(cell.consume(next.identity), Ok(ServiceResult::Supplied));
    }

    #[test]
    fn owned_ticket_keeps_backing_until_acknowledgment() {
        use alloc::sync::Arc;
        let cell = Arc::new(ServiceCell::new());
        let owner = birth(1, 1);
        cell.bind(owner).unwrap();
        let request = cell
            .publish(owner, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        let ticket = ServiceCell::claim_owned(cell.clone(), request).unwrap();
        assert_eq!(Arc::strong_count(&cell), 2);
        assert!(!cell.cancel(request.identity).unwrap());
        assert_eq!(Arc::strong_count(&cell), 2);
        assert!(ticket.complete(true).is_ok());
        assert_eq!(Arc::strong_count(&cell), 1);
        assert_eq!(cell.consume(request.identity), Ok(ServiceResult::Cancelled));
    }

    #[test]
    fn recycled_birth_rejects_old_request_and_keeps_monotone_sequence() {
        let cell = ServiceCell::new();
        let old_birth = birth(1, 1);
        cell.bind(old_birth).unwrap();
        let old = cell
            .publish(old_birth, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        assert!(!cell.cancel(old.identity).unwrap());
        assert_eq!(cell.consume(old.identity), Err(ServiceError::Busy));
        assert!(cell.claim(old).unwrap().complete(false).is_ok());
        assert_eq!(cell.consume(old.identity), Ok(ServiceResult::Cancelled));
        cell.reset_unpublished().unwrap();
        let new_birth = birth(1, 2);
        cell.bind(new_birth).unwrap();
        assert_eq!(
            cell.bound_birth(old_birth.process, old_birth.thread, old_birth.record),
            Err(ServiceError::Stale)
        );
        assert_eq!(
            cell.bound_birth(new_birth.process, old_birth.thread, new_birth.record),
            Err(ServiceError::Stale)
        );
        assert_eq!(
            cell.bound_birth(new_birth.process, new_birth.thread, old_birth.record),
            Err(ServiceError::Stale)
        );
        assert_eq!(
            cell.bound_birth(new_birth.process, new_birth.thread, new_birth.record),
            Ok(new_birth)
        );
        let new = cell
            .publish(new_birth, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        assert!(new.identity.sequence > old.identity.sequence);
        assert!(matches!(cell.claim(old), Err(ServiceError::Stale)));
        let mut wrong = new;
        wrong.identity.execution = SnapshotGeneration::from_raw(2);
        assert!(matches!(cell.claim(wrong), Err(ServiceError::Stale)));
        wrong = new;
        wrong.operation = ServiceOperation::Crossing {
            ordinal: NativeOrdinal::new(57),
        };
        assert!(matches!(cell.claim(wrong), Err(ServiceError::Stale)));
        let ticket = cell.claim(new).unwrap();
        assert!(ticket.complete(false).is_ok());
        assert_eq!(cell.consume(old.identity), Err(ServiceError::Stale));
        assert_eq!(cell.consume(new.identity), Ok(ServiceResult::Refused));
    }
    #[test]
    fn backing_reply_is_bound_to_the_claimed_request_phase() {
        let cell = ServiceCell::new();
        let birth = birth(1, 1);
        cell.bind(birth).unwrap();
        let operation = ServiceOperation::Fault(FaultInfo {
            address: UserVa::new(0x4000),
            access: Access::Read,
            present: false,
        });
        let address = carrick_guest_arch::KernelVa::new(0x10000);
        let request = cell
            .publish_with_reply(
                birth,
                SnapshotGeneration::INITIAL,
                operation,
                Some(NonZeroU64::MIN),
                Some(address),
            )
            .unwrap();
        let ticket = cell.claim(request).unwrap();
        assert_eq!(ticket.reply_address(), Some(address));
        assert!(ticket.complete_backing_fault().is_ok());
        assert_eq!(
            cell.consume(request.identity),
            Ok(ServiceResult::BackingFault)
        );
        let request = cell
            .publish(birth, SnapshotGeneration::INITIAL, operation, None)
            .unwrap();
        let ticket = cell.claim(request).unwrap();
        assert_eq!(
            ticket.reply_address(),
            None,
            "successor cannot inherit the previous buffer"
        );
        assert!(ticket.complete(false).is_ok());
        assert_eq!(cell.consume(request.identity), Ok(ServiceResult::Refused));
    }

    fn supply_window(owner: ServiceBirth) -> crate::PortalGrantWindow {
        let page = match fault() {
            ServiceOperation::Fault(fault) => fault.address.raw() & !4095,
            _ => unreachable!(),
        };
        crate::PortalGrantWindow {
            operation: crate::PortalOperation {
                carrier: owner.mm.carrier(),
                mm: owner.mm.mm(),
                incarnation: owner.mm.incarnation(),
                sequence: NonZeroU64::MIN,
            },
            generation: crate::ReservationGeneration::new(1).unwrap(),
            range: crate::ReservationRange::new(page, page + 4096).unwrap(),
            protection: crate::ReservationProtection::from_bits(3).unwrap(),
            fault_page: page,
            host_backing: None,
            fork_sequence: None,
        }
    }

    #[test]
    fn fault_supply_transfer_survives_lane_reuse_and_cancellation() {
        let slot = crate::PortalGrantSlot::new();
        let first = ServiceCell::new();
        let second = ServiceCell::new();
        let a = birth(1, 1);
        let b = birth(2, 1);
        first.bind(a).unwrap();
        second.bind(b).unwrap();
        let a_request = first
            .publish(
                a,
                SnapshotGeneration::INITIAL,
                fault(),
                Some(NonZeroU64::MIN),
            )
            .unwrap();
        let b_request = second
            .publish(b, SnapshotGeneration::INITIAL, fault(), NonZeroU64::new(2))
            .unwrap();
        let mut a_ticket = first.claim(a_request).unwrap();
        let mut b_ticket = second.claim(b_request).unwrap();
        let a_window = supply_window(a);
        let mut b_window = supply_window(b);
        b_window.operation.sequence = NonZeroU64::new(2).unwrap();
        assert!(slot.publish_cow_fault_selection(1, a_window));
        assert_eq!(
            a_ticket.take_fault_selection(&slot),
            Ok(Some(ServiceFaultSupply::Cow(a_window)))
        );
        assert!(!slot.has_outstanding_for(a.mm.mm().raw()));
        assert!(!first.cancel(a_request.identity).unwrap());
        assert_eq!(first.consume(a_request.identity), Err(ServiceError::Busy));
        assert!(slot.publish_fault_selection(2, b_window));
        assert_eq!(
            a_ticket.take_fault_selection(&slot),
            Err(ServiceError::Stale)
        );
        assert_eq!(
            slot.pending_fault_selection(b.mm.mm().raw(), b_window.fault_page),
            Some((2, b_window))
        );
        assert_eq!(
            b_ticket.take_fault_selection(&slot),
            Ok(Some(ServiceFaultSupply::Backing(b_window)))
        );
        assert!(b_ticket.complete(false).is_ok());
        assert_eq!(
            second.consume(b_request.identity),
            Ok(ServiceResult::Refused)
        );
        assert!(a_ticket.complete(true).is_ok());
        assert_eq!(
            first.consume(a_request.identity),
            Ok(ServiceResult::Cancelled)
        );
    }

    #[test]
    fn fault_supply_transfer_rejects_recycled_mm_incarnation() {
        let slot = crate::PortalGrantSlot::new();
        let cell = ServiceCell::new();
        let owner = birth(1, 1);
        cell.bind(owner).unwrap();
        let request = cell
            .publish(
                owner,
                SnapshotGeneration::INITIAL,
                fault(),
                Some(NonZeroU64::MIN),
            )
            .unwrap();
        let mut ticket = cell.claim(request).unwrap();
        let window = supply_window(birth(1, 2));
        assert!(slot.publish_cow_fault_selection(1, window));
        assert_eq!(ticket.take_fault_selection(&slot), Err(ServiceError::Stale));
        assert_eq!(
            slot.pending_cow_fault_selection(owner.mm.mm().raw(), window.fault_page),
            Some((1, window))
        );
        assert!(ticket.complete(false).is_ok());
        assert_eq!(cell.consume(request.identity), Ok(ServiceResult::Refused));
    }

    #[test]
    fn delayed_first_fault_take_cannot_steal_same_mm_page_successor() {
        let slot = crate::PortalGrantSlot::new();
        let first = ServiceCell::new();
        let second = ServiceCell::new();
        let a = birth(1, 1);
        let mut b = birth(2, 1);
        b.mm = a.mm;
        first.bind(a).unwrap();
        second.bind(b).unwrap();
        let a_request = first
            .publish(
                a,
                SnapshotGeneration::INITIAL,
                fault(),
                Some(NonZeroU64::MIN),
            )
            .unwrap();
        let b_request = second
            .publish(b, SnapshotGeneration::INITIAL, fault(), NonZeroU64::new(2))
            .unwrap();
        let mut old_ticket = first.claim(a_request).unwrap();
        let mut next_ticket = second.claim(b_request).unwrap();
        let mut successor = supply_window(b);
        successor.operation.sequence = NonZeroU64::new(2).unwrap();
        assert!(slot.publish_cow_fault_selection(2, successor));
        assert_eq!(
            old_ticket.take_fault_selection(&slot),
            Err(ServiceError::Stale)
        );
        assert_eq!(
            slot.pending_cow_fault_selection(a.mm.mm().raw(), successor.fault_page),
            Some((2, successor))
        );
        assert_eq!(
            next_ticket.take_fault_selection(&slot),
            Ok(Some(ServiceFaultSupply::Cow(successor)))
        );
        assert!(next_ticket.complete(false).is_ok());
        assert!(old_ticket.complete(false).is_ok());
        assert_eq!(
            first.consume(a_request.identity),
            Ok(ServiceResult::Refused)
        );
        assert_eq!(
            second.consume(b_request.identity),
            Ok(ServiceResult::Refused)
        );
    }
    #[test]
    fn mm_busy_ack_preserves_the_native_claim_until_its_owner_wakes() {
        let cell = ServiceCell::new();
        let owner = birth(1, 1);
        cell.bind(owner).unwrap();
        let request = cell
            .publish(owner, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        // SAFETY: fixture names its exact admitted source before the busy probe.
        let wait = unsafe {
            crate::PortalOwnerWait::from_owner(owner.mm, crate::PortalWaitCause::Editor, 7)
        };
        assert!(cell.claim(request).unwrap().complete_wait(wait).is_ok());
        assert_eq!(
            cell.consume(request.identity),
            Ok(ServiceResult::Wait(wait))
        );
        assert_eq!(cell.reset_unpublished(), Err(ServiceError::Busy));
    }
}
