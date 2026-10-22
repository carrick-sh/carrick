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
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceResult {
    Supplied,
    Refused,
    Cancelled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    Busy,
    Stale,
    Exhausted,
}

pub const NATIVE_SERVICE_PROTOCOL: u64 = 1;

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
}
impl ServiceCell {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(UNBOUND),
            sequence: AtomicU64::new(0),
            words: [const { AtomicU64::new(0) }; 12],
            result: AtomicU64::new(0),
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
    ) -> Result<ServiceRequest, ServiceError> {
        self.state
            .compare_exchange(IDLE, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Busy)?;
        if !execution.issued() || !self.same_birth(birth) {
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
        self.sequence.store(next.get(), Ordering::Relaxed);
        self.state.store(REQUESTED, Ordering::Release);
        Ok(ServiceRequest {
            identity: ServiceIdentity {
                birth,
                execution,
                sequence: next,
            },
            operation,
        })
    }
    fn same_birth(&self, birth: ServiceBirth) -> bool {
        self.words
            .iter()
            .zip(birth.words())
            .all(|(word, value)| word.load(Ordering::Relaxed) == value)
    }
    fn same(&self, identity: ServiceIdentity) -> bool {
        self.same_birth(identity.birth)
            && self.words[8].load(Ordering::Relaxed) == identity.execution.raw()
            && self.sequence.load(Ordering::Relaxed) == identity.sequence.get()
    }
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
            Ok(ServiceRequest {
                identity,
                operation,
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
                    cell: core::mem::ManuallyDrop::new(pin),
                    request,
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
        if !operation_matches {
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
            cell: core::mem::ManuallyDrop::new(pin),
            request,
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
        } else if self.result.load(Ordering::Relaxed) == 1 {
            ServiceResult::Supplied
        } else {
            ServiceResult::Refused
        };
        self.state.store(IDLE, Ordering::Release);
        Ok(result)
    }
}
/// Dropping a transport handle is not completion: it leaves the operation and
/// its retained resources outstanding. Only explicit acknowledgment releases it.
#[must_use]
pub struct ServiceTicket<P: Deref<Target = ServiceCell>> {
    cell: core::mem::ManuallyDrop<P>,
    request: ServiceRequest,
}
impl<P: Deref<Target = ServiceCell>> ServiceTicket<P> {
    pub fn request(&self) -> ServiceRequest {
        self.request
    }
    pub fn complete(mut self, supplied: bool) -> Result<(), (ServiceError, Self)> {
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
        cell.result.store(u64::from(supplied), Ordering::Relaxed);
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
            .publish(first_birth, SnapshotGeneration::INITIAL, fault())
            .unwrap();
        let b = second
            .publish(second_birth, SnapshotGeneration::INITIAL, fault())
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
            .publish(owner, SnapshotGeneration::INITIAL, fault())
            .unwrap();
        assert!(cell.claim(first).unwrap().complete(true).is_ok());
        assert_eq!(cell.consume(first.identity), Ok(ServiceResult::Supplied));
        assert_eq!(cell.cancel(first.identity), Ok(true));
        let next = cell
            .publish(owner, SnapshotGeneration::INITIAL, fault())
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
            .publish(owner, SnapshotGeneration::INITIAL, fault())
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
            .publish(old_birth, SnapshotGeneration::INITIAL, fault())
            .unwrap();
        assert!(!cell.cancel(old.identity).unwrap());
        assert_eq!(cell.consume(old.identity), Err(ServiceError::Busy));
        assert!(cell.claim(old).unwrap().complete(false).is_ok());
        assert_eq!(cell.consume(old.identity), Ok(ServiceResult::Cancelled));
        cell.reset_unpublished().unwrap();
        let new_birth = birth(1, 2);
        cell.bind(new_birth).unwrap();
        let new = cell
            .publish(new_birth, SnapshotGeneration::INITIAL, fault())
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
}
