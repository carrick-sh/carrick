//! Fork names production roots and physically retained table capacity only.
use crate::{El1MmHandle, PortalOperation, ReservationGeneration, ReservationMm};

pub const MM_PORTAL_FORK_ESR: u64 = 0x4352_4d4d_464b_0004;
pub const MM_PORTAL_FORK_FINISH_ESR: u64 = 0x4352_4d4d_4646_0004;

/// An unlinked table extent retained by the physical custodian until settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalForkTableArena {
    pub base: u64,
    pub len: u64,
}
impl PortalForkTableArena {
    pub fn new(base: u64, len: u64) -> Option<Self> {
        (base != 0
            && base.is_multiple_of(4096)
            && len != 0
            && len.is_multiple_of(4096)
            && base.checked_add(len).is_some())
        .then_some(Self { base, len })
    }
    pub fn contains(self, address: u64) -> bool {
        address >= self.base
            && address
                .checked_add(8)
                .is_some_and(|end| end <= self.base + self.len)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalForkRequest {
    pub operation: PortalOperation,
    pub parent_generation: ReservationGeneration,
    pub child_mm: ReservationMm,
    pub child_tables: PortalForkTableArena,
    pub parent_tables: PortalForkTableArena,
    pub kernel_control_ipa: u64,
}
impl PortalForkRequest {
    pub fn valid(self) -> bool {
        self.kernel_control_ipa != 0
            && self.kernel_control_ipa.is_multiple_of(0x20_0000)
            && self.kernel_control_ipa.checked_add(0x20_0000).is_some()
            && self.operation.mm != self.child_mm
            && PortalForkTableArena::new(self.child_tables.base, self.child_tables.len).is_some()
            && PortalForkTableArena::new(self.parent_tables.base, self.parent_tables.len).is_some()
            && (self.child_tables.base + self.child_tables.len <= self.parent_tables.base
                || self.parent_tables.base + self.parent_tables.len <= self.child_tables.base)
    }
}

/// Owner-selected backing. The host authenticates physical custody, never
/// selects guest mappings or access policy from this receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortalForkCustody {
    Frame {
        va: u64,
        ipa: u64,
        len: u64,
        shared: bool,
    },
    StructuralCopy {
        source_ipa: u64,
        destination_ipa: u64,
        len: u64,
        executable: bool,
    },
    HostBacking {
        handle: core::num::NonZeroU64,
        generation: core::num::NonZeroU64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalForkCompletion {
    pub request: PortalForkRequest,
    pub child: El1MmHandle,
    pub parent_generation: ReservationGeneration,
    pub child_tables_used: u64,
    pub parent_tables_used: u64,
}

use core::sync::atomic::{AtomicU64, Ordering};
const IDLE: u64 = 0;
const WRITING: u64 = 1;
const REQUESTED: u64 = 2;
const SERVICING: u64 = 3;
const CUSTODY: u64 = 4;
const ACKED: u64 = 5;
const PUBLISHED: u64 = 6;
const FINISH: u64 = 7;
const COMPLETED: u64 = 8;
const READING: u64 = 9;
const REQUEST_WORDS: usize = 11;
impl PortalForkRequest {
    fn encode(self) -> [u64; REQUEST_WORDS] {
        [
            crate::MM_PORTAL_PROTOCOL,
            self.operation.carrier.get(),
            self.operation.mm.raw(),
            self.operation.incarnation.get(),
            self.operation.sequence.get(),
            self.parent_generation.raw(),
            self.child_mm.raw(),
            self.child_tables.base,
            self.child_tables.len,
            self.parent_tables.base,
            self.kernel_control_ipa,
        ]
    }
    fn decode(words: [u64; REQUEST_WORDS], parent_len: u64) -> Option<Self> {
        if words[0] != crate::MM_PORTAL_PROTOCOL {
            return None;
        }
        let request = Self {
            operation: PortalOperation {
                carrier: core::num::NonZeroU64::new(words[1])?,
                mm: ReservationMm::new(words[2])?,
                incarnation: core::num::NonZeroU64::new(words[3])?,
                sequence: core::num::NonZeroU64::new(words[4])?,
            },
            parent_generation: ReservationGeneration::new(words[5])?,
            child_mm: ReservationMm::new(words[6])?,
            child_tables: PortalForkTableArena::new(words[7], words[8])?,
            parent_tables: PortalForkTableArena::new(words[9], parent_len)?,
            kernel_control_ipa: words[10],
        };
        request.valid().then_some(request)
    }
}

#[repr(C, align(64))]
pub struct PortalForkSlot {
    state: AtomicU64,
    request: [AtomicU64; REQUEST_WORDS],
    parent_len: AtomicU64,
    custody_index: AtomicU64,
    custody: [AtomicU64; 4],
    acknowledgment: AtomicU64,
    completion: [AtomicU64; 4],
    errno: AtomicU64,
}
impl Default for PortalForkSlot {
    fn default() -> Self {
        Self::new()
    }
}
impl PortalForkSlot {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
            request: [const { AtomicU64::new(0) }; REQUEST_WORDS],
            parent_len: AtomicU64::new(0),
            custody_index: AtomicU64::new(0),
            custody: [const { AtomicU64::new(0) }; 4],
            acknowledgment: AtomicU64::new(0),
            completion: [const { AtomicU64::new(0) }; 4],
            errno: AtomicU64::new(0),
        }
    }
    fn load_request(&self) -> Option<PortalForkRequest> {
        PortalForkRequest::decode(
            core::array::from_fn(|index| self.request[index].load(Ordering::Relaxed)),
            self.parent_len.load(Ordering::Relaxed),
        )
    }
    pub fn submit(&self, request: PortalForkRequest) -> Option<PortalForkTicket<'_>> {
        if !request.valid() {
            return None;
        }
        self.state
            .compare_exchange(IDLE, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        for (slot, word) in self.request.iter().zip(request.encode()) {
            slot.store(word, Ordering::Relaxed);
        }
        self.parent_len
            .store(request.parent_tables.len, Ordering::Relaxed);
        self.errno.store(0, Ordering::Relaxed);
        self.acknowledgment.store(0, Ordering::Relaxed);
        self.state.store(REQUESTED, Ordering::Release);
        Some(PortalForkTicket {
            slot: self,
            request,
            settled: false,
        })
    }
    pub fn claim(&self) -> Option<PortalForkService<'_>> {
        self.state
            .compare_exchange(REQUESTED, SERVICING, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        let request = self.load_request()?;
        Some(PortalForkService {
            slot: self,
            request,
        })
    }
    pub fn request_custody(&self) -> Option<(PortalForkRequest, u64, PortalForkCustody)> {
        if self.state.load(Ordering::Acquire) != CUSTODY {
            return None;
        }
        let words: [u64; 4] =
            core::array::from_fn(|index| self.custody[index].load(Ordering::Relaxed));
        let custody = match words[0] {
            tag @ (1 | 4)
                if words[3] != 0
                    && words[1].checked_add(words[3]).is_some()
                    && words[2].checked_add(words[3]).is_some() =>
            {
                PortalForkCustody::Frame {
                    va: words[1],
                    ipa: words[2],
                    len: words[3],
                    shared: tag == 4,
                }
            }
            tag @ (3 | 5)
                if words[3] != 0
                    && words[1].checked_add(words[3]).is_some()
                    && words[2].checked_add(words[3]).is_some() =>
            {
                PortalForkCustody::StructuralCopy {
                    source_ipa: words[1],
                    destination_ipa: words[2],
                    len: words[3],
                    executable: tag == 5,
                }
            }
            2 if words[3] == 0 => PortalForkCustody::HostBacking {
                handle: core::num::NonZeroU64::new(words[1])?,
                generation: core::num::NonZeroU64::new(words[2])?,
            },
            _ => return None,
        };
        Some((
            self.load_request()?,
            self.custody_index.load(Ordering::Relaxed),
            custody,
        ))
    }
    pub fn ack_custody(&self, operation: PortalOperation, index: u64, accepted: bool) -> bool {
        if self.state.load(Ordering::Acquire) != CUSTODY
            || self
                .load_request()
                .is_none_or(|request| request.operation != operation)
            || self.custody_index.load(Ordering::Relaxed) != index
        {
            return false;
        }
        self.acknowledgment
            .store(if accepted { 1 } else { 2 }, Ordering::Relaxed);
        self.state
            .compare_exchange(CUSTODY, ACKED, Ordering::Release, Ordering::Relaxed)
            .is_ok()
    }
    pub fn published(&self) -> Option<PortalForkCompletion> {
        if self.state.load(Ordering::Acquire) != PUBLISHED {
            return None;
        }
        self.load_completion()
    }
    fn load_completion(&self) -> Option<PortalForkCompletion> {
        let request = self.load_request()?;
        let words: [u64; 4] =
            core::array::from_fn(|index| self.completion[index].load(Ordering::Relaxed));
        if words[2] > request.child_tables.len || words[3] > request.parent_tables.len {
            return None;
        }
        Some(PortalForkCompletion {
            request,
            child: unsafe {
                El1MmHandle::from_admitted_owner(
                    request.operation.carrier,
                    request.child_mm,
                    core::num::NonZeroU64::new(words[0])?,
                )
            },
            parent_generation: ReservationGeneration::new(words[1])?,
            child_tables_used: words[2],
            parent_tables_used: words[3],
        })
    }
    pub fn finish_request(&self) -> Option<(PortalForkRequest, bool)> {
        if self.state.load(Ordering::Acquire) != FINISH {
            return None;
        }
        Some((
            self.load_request()?,
            self.acknowledgment.load(Ordering::Relaxed) == 1,
        ))
    }
    pub fn complete_finish_receipt(&self, completion: PortalForkCompletion) -> bool {
        if self.state.load(Ordering::Acquire) != FINISH
            || self.load_request() != Some(completion.request)
            || completion.child_tables_used > completion.request.child_tables.len
            || completion.parent_tables_used > completion.request.parent_tables.len
        {
            return false;
        }
        if completion.child.mm() != completion.request.child_mm
            || completion.child.carrier() != completion.request.operation.carrier
            || completion.child.incarnation().get() != self.completion[0].load(Ordering::Relaxed)
        {
            return false;
        }
        for (target, value) in self.completion.iter().zip([
            completion.child.incarnation().get(),
            completion.parent_generation.raw(),
            completion.child_tables_used,
            completion.parent_tables_used,
        ]) {
            target.store(value, Ordering::Relaxed);
        }
        self.complete_finish(0)
    }
    pub fn complete_finish(&self, errno: u32) -> bool {
        if errno > 4095 || self.state.load(Ordering::Acquire) != FINISH {
            return false;
        }
        self.errno.store(u64::from(errno), Ordering::Relaxed);
        self.state.store(COMPLETED, Ordering::Release);
        true
    }
    pub fn finish(&self, operation: PortalOperation, commit: bool) -> bool {
        if self.state.load(Ordering::Acquire) != PUBLISHED
            || self
                .load_request()
                .is_none_or(|request| request.operation != operation)
        {
            return false;
        }
        self.acknowledgment
            .store(if commit { 1 } else { 2 }, Ordering::Relaxed);
        self.state
            .compare_exchange(PUBLISHED, FINISH, Ordering::Release, Ordering::Relaxed)
            .is_ok()
    }
}
pub struct PortalForkTicket<'a> {
    slot: &'a PortalForkSlot,
    request: PortalForkRequest,
    settled: bool,
}
impl PortalForkTicket<'_> {
    pub fn take_completion(&mut self) -> Option<Result<PortalForkCompletion, u32>> {
        if self.settled
            || self.slot.state.load(Ordering::Acquire) != COMPLETED
            || self.slot.load_request()? != self.request
        {
            return None;
        }
        let errno = self.slot.errno.load(Ordering::Relaxed);
        if errno > 4095 {
            return None;
        }
        let result = if errno == 0 {
            Ok(self.slot.load_completion()?)
        } else {
            Err(errno as u32)
        };
        self.slot
            .state
            .compare_exchange(COMPLETED, READING, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        self.settled = true;
        self.slot.state.store(IDLE, Ordering::Release);
        Some(result)
    }
}
pub struct PortalForkService<'a> {
    slot: &'a PortalForkSlot,
    request: PortalForkRequest,
}
impl PortalForkService<'_> {
    pub fn request(&self) -> PortalForkRequest {
        self.request
    }
    pub fn retain(&self, index: u64, custody: PortalForkCustody, cross: impl FnOnce()) -> bool {
        if self.slot.state.load(Ordering::Acquire) != SERVICING {
            return false;
        }
        let words = match custody {
            PortalForkCustody::Frame {
                va,
                ipa,
                len,
                shared,
            } => [if shared { 4 } else { 1 }, va, ipa, len],
            PortalForkCustody::StructuralCopy {
                source_ipa,
                destination_ipa,
                len,
                executable,
            } => [
                if executable { 5 } else { 3 },
                source_ipa,
                destination_ipa,
                len,
            ],
            PortalForkCustody::HostBacking { handle, generation } => {
                [2, handle.get(), generation.get(), 0]
            }
        };
        for (slot, word) in self.slot.custody.iter().zip(words) {
            slot.store(word, Ordering::Relaxed);
        }
        self.slot.custody_index.store(index, Ordering::Relaxed);
        self.slot.acknowledgment.store(0, Ordering::Relaxed);
        self.slot.state.store(CUSTODY, Ordering::Release);
        cross();
        if self.slot.state.load(Ordering::Acquire) != ACKED {
            return false;
        }
        let accepted = self.slot.acknowledgment.load(Ordering::Relaxed) == 1;
        self.slot.state.store(SERVICING, Ordering::Release);
        accepted
    }
    pub fn publish_detached(&self, completion: PortalForkCompletion) -> Option<()> {
        if completion.request != self.request
            || self.slot.state.load(Ordering::Acquire) != SERVICING
        {
            return None;
        }
        let words = [
            completion.child.incarnation().get(),
            completion.parent_generation.raw(),
            completion.child_tables_used,
            completion.parent_tables_used,
        ];
        for (slot, word) in self.slot.completion.iter().zip(words) {
            slot.store(word, Ordering::Relaxed);
        }
        self.slot.state.store(PUBLISHED, Ordering::Release);
        Some(())
    }
    pub fn complete(self, errno: u32) -> bool {
        if errno > 4095 {
            return false;
        }
        self.slot.errno.store(u64::from(errno), Ordering::Relaxed);
        self.slot.state.store(COMPLETED, Ordering::Release);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(sequence: u64) -> PortalForkRequest {
        let nz = |v| core::num::NonZeroU64::new(v).unwrap();
        PortalForkRequest {
            operation: PortalOperation {
                carrier: nz(1),
                mm: ReservationMm::new(71).unwrap(),
                incarnation: nz(4),
                sequence: nz(sequence),
            },
            parent_generation: ReservationGeneration::new(7).unwrap(),
            child_mm: ReservationMm::new(72).unwrap(),
            child_tables: PortalForkTableArena::new(0x800000, 0x200000).unwrap(),
            parent_tables: PortalForkTableArena::new(0xa00000, 0x200000).unwrap(),
            kernel_control_ipa: 0xc00000,
        }
    }
    fn completion(request: PortalForkRequest) -> PortalForkCompletion {
        PortalForkCompletion {
            request,
            child: unsafe {
                El1MmHandle::from_admitted_owner(
                    request.operation.carrier,
                    request.child_mm,
                    core::num::NonZeroU64::new(3).unwrap(),
                )
            },
            parent_generation: ReservationGeneration::new(8).unwrap(),
            child_tables_used: 0x4000,
            parent_tables_used: 0,
        }
    }
    #[test]
    fn fork_slot_custody_and_finish_are_exact_generation() {
        let slot = PortalForkSlot::new();
        let request = request(1);
        let mut ticket = slot.submit(request).unwrap();
        let service = slot.claim().unwrap();
        assert!(slot.submit(request).is_none());
        assert!(service.retain(
            0,
            PortalForkCustody::Frame {
                va: 0x40000000,
                ipa: 0x90000000,
                len: 4096,
                shared: false,
            },
            || {
                let (observed, index, _) = slot.request_custody().unwrap();
                assert_eq!(observed, request);
                assert_eq!(index, 0);
                let mut stale = request.operation;
                stale.sequence = core::num::NonZeroU64::new(2).unwrap();
                assert!(!slot.ack_custody(stale, index, true));
                assert!(!slot.ack_custody(observed.operation, index + 1, true));
                assert!(slot.ack_custody(observed.operation, index, true));
                assert!(!slot.ack_custody(observed.operation, index, true));
            }
        ));
        service.publish_detached(completion(request)).unwrap();
        assert_eq!(slot.published(), Some(completion(request)));
        assert!(ticket.take_completion().is_none());
        let mut stale = request.operation;
        stale.incarnation = core::num::NonZeroU64::new(5).unwrap();
        assert!(!slot.finish(stale, true));
        assert!(slot.finish(request.operation, false));
        assert_eq!(slot.finish_request(), Some((request, false)));
        assert!(!slot.finish(request.operation, true));
        assert!(slot.complete_finish(125));
        assert_eq!(ticket.take_completion(), Some(Err(125)));
        assert!(ticket.take_completion().is_none());
        let newer = self::request(2);
        let mut new_ticket = slot.submit(newer).unwrap();
        assert!(!slot.finish(request.operation, true));
        assert!(slot.claim().unwrap().complete(12));
        assert_eq!(new_ticket.take_completion(), Some(Err(12)));
    }
    #[test]
    fn fork_arena_refuses_overlap_and_overflow() {
        assert!(PortalForkTableArena::new(u64::MAX - 4095, 4096).is_none());
        let mut request = request(1);
        request.parent_tables = request.child_tables;
        assert!(!request.valid());
        request = self::request(1);
        request.child_mm = request.operation.mm;
        assert!(!request.valid());
    }
}
