//! Anonymous reservation transaction ABI (T1 policy / T2 descriptors).
//!
//! A request is a proposal, never permission to replay a Linux syscall. T2
//! authenticates its MM, generation and sequence against the pending proposal,
//! completes the descriptor transaction and backing grant/return, then returns
//! a completion for that exact request. Only T1 commits reservation metadata.
//! Refusal leaves the old reservation visible; a failed descriptor rollback
//! must fail stopped, never manufacture a refusal/completion.

/// Shared reservation bootstrap region, before T2's descriptor transaction slots.
pub const EL1_RESERVATIONS_OFFSET: u64 = crate::EL1_COUNTERS_OFFSET + 0x2_0000;
pub const EL1_RESERVATIONS_END: u64 = crate::EL1_COUNTERS_OFFSET + 0x8_0000;

macro_rules! identity {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct $name(u64);
        impl $name {
            pub const fn new(raw: u64) -> Option<Self> {
                if raw == 0 { None } else { Some(Self(raw)) }
            }
            pub const fn raw(self) -> u64 {
                self.0
            }
        }
    };
}

identity!(ReservationMm);
identity!(ReservationGeneration);
identity!(ReservationSequence);

/// Page-aligned half-open Linux 4 KiB virtual range; never an IPA/host VA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ReservationRange {
    start: u64,
    end: u64,
}
impl ReservationRange {
    pub const fn new(start: u64, end: u64) -> Option<Self> {
        if start < end && start.is_multiple_of(4096) && end.is_multiple_of(4096) {
            Some(Self { start, end })
        } else {
            None
        }
    }
    pub const fn start(self) -> u64 {
        self.start
    }
    pub const fn end(self) -> u64 {
        self.end
    }
    pub const fn len(self) -> u64 {
        self.end - self.start
    }
    pub const fn is_empty(self) -> bool {
        false
    }
    pub const fn contains(self, va: u64) -> bool {
        self.start <= va && va < self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ReservationProtection(u64);
impl ReservationProtection {
    pub const NONE: Self = Self(0);
    pub const READ_WRITE: Self = Self(3);
    pub const fn from_bits(bits: u64) -> Option<Self> {
        if bits & !7 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn bits(self) -> u64 {
        self.0
    }
    pub const fn permits(self, access: Self) -> bool {
        self.0 & access.0 == access.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum ReservationOperation {
    Prepare = 1,
    Protect = 2,
    Retire = 3,
}

/// The generation is the *current* committed root revision. The pending
/// sequence is never reused, including after refusal. Every successful edit
/// advances the revision; a stale fault grant cannot authorize a reused VA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ReservationRequest {
    pub mm: ReservationMm,
    pub generation: ReservationGeneration,
    pub sequence: ReservationSequence,
    pub range: ReservationRange,
    pub protection: ReservationProtection,
    pub operation: ReservationOperation,
}

/// Exact backing service accounting. Zero is valid for a lazy reservation or
/// permission-only transaction; it does not imply anonymous pages are resident.
/// `receipt` identifies the substrate transaction even when no frames moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ReservationBackingReceipt {
    pub receipt: u64,
    pub granted_bytes: u64,
    pub returned_bytes: u64,
}

/// Created only by the admitted exact-MM descriptor/backing transaction owner.
/// Fields are private so policy cannot accidentally treat the request as done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ReservationCompletion {
    request: ReservationRequest,
    backing: ReservationBackingReceipt,
}
impl ReservationCompletion {
    /// # Safety
    /// The caller must hold the exact-MM transaction authority and prove:
    /// - `request` is still the pending proposal with these exact fields;
    /// - backing/inventory grant and return agree with `backing`;
    /// - all descriptor edits, invalidation and required zero-fill completed;
    /// - no observer can see a later descriptor edit before T1's commit.
    ///
    /// Never call this after partial failure or with a mere host syscall result.
    pub unsafe fn after_descriptor_and_backing_commit(
        request: ReservationRequest,
        backing: ReservationBackingReceipt,
    ) -> Option<Self> {
        (backing.receipt != 0
            && backing.granted_bytes.is_multiple_of(4096)
            && backing.returned_bytes.is_multiple_of(4096))
        .then_some(Self { request, backing })
    }
    pub const fn request(self) -> ReservationRequest {
        self.request
    }
    pub const fn backing(self) -> ReservationBackingReceipt {
        self.backing
    }
    pub fn authenticates(self, pending: ReservationRequest) -> bool {
        self.request == pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservation_completion_is_exact_across_two_mms_and_reused_vas() {
        let request = ReservationRequest {
            mm: ReservationMm::new(17).unwrap(),
            generation: ReservationGeneration::new(2).unwrap(),
            sequence: ReservationSequence::new(3).unwrap(),
            range: ReservationRange::new(0x1000, 0x3000).unwrap(),
            protection: ReservationProtection::READ_WRITE,
            operation: ReservationOperation::Prepare,
        };
        // Mock substrate: no descriptors/backing exist in this ABI test.
        let completion = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                ReservationBackingReceipt {
                    receipt: 1,
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        assert!(completion.authenticates(request));
        let mut changed = request;
        changed.mm = ReservationMm::new(18).unwrap();
        assert!(!completion.authenticates(changed));
        changed = request;
        changed.generation = ReservationGeneration::new(3).unwrap();
        assert!(!completion.authenticates(changed));
        changed = request;
        changed.sequence = ReservationSequence::new(4).unwrap();
        assert!(!completion.authenticates(changed));
        changed = request;
        changed.protection = ReservationProtection::NONE;
        assert!(!completion.authenticates(changed));
        changed = request;
        changed.operation = ReservationOperation::Retire;
        assert!(!completion.authenticates(changed));
        changed = request;
        changed.range = ReservationRange::new(0x1000, 0x2000).unwrap();
        assert!(!completion.authenticates(changed));
    }
}
