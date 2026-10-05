//! Exact lazy-window selection record, independent of hardware transport.
use crate::{PortalOperation, ReservationGeneration, ReservationProtection, ReservationRange};
use core::num::NonZeroU64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalGrantWindow {
    pub operation: PortalOperation,
    pub generation: ReservationGeneration,
    pub range: ReservationRange,
    pub protection: ReservationProtection,
    pub fault_page: u64,
    pub host_backing: Option<crate::HostBackingIdentity>,
    pub fork_sequence: Option<NonZeroU64>,
}
impl PortalGrantWindow {
    pub fn valid(self) -> bool {
        self.range.len() <= crate::EL1_FRAME_GRANT_TARGET_SIZE
            && self.range.contains(self.fault_page)
            && self.fault_page.is_multiple_of(4096)
            && self.protection.bits() != 0
            && self
                .host_backing
                .is_none_or(|source| source.advance(self.range.len()).is_some())
    }
    pub fn words(self) -> [u64; 13] {
        [
            self.operation.carrier.get(),
            self.operation.mm.raw(),
            self.operation.incarnation.get(),
            self.operation.sequence.get(),
            self.generation.raw(),
            self.range.start(),
            self.range.end(),
            self.protection.bits(),
            self.fault_page,
            self.host_backing.map_or(0, |source| source.handle().get()),
            self.host_backing
                .map_or(0, |source| source.generation().get()),
            self.host_backing.map_or(0, |source| source.offset()),
            self.fork_sequence.map_or(0, NonZeroU64::get),
        ]
    }
    pub fn decode(w: [u64; 13]) -> Option<Self> {
        let value = Self {
            operation: PortalOperation {
                carrier: NonZeroU64::new(w[0])?,
                mm: crate::ReservationMm::new(w[1])?,
                incarnation: NonZeroU64::new(w[2])?,
                sequence: NonZeroU64::new(w[3])?,
            },
            generation: ReservationGeneration::new(w[4])?,
            range: ReservationRange::new(w[5], w[6])?,
            protection: ReservationProtection::from_bits(w[7])?,
            fault_page: w[8],
            fork_sequence: NonZeroU64::new(w[12]),
            host_backing: if w[9] == 0 {
                if w[10] != 0 || w[11] != 0 {
                    return None;
                }
                None
            } else {
                Some(crate::HostBackingIdentity::new(
                    NonZeroU64::new(w[9])?,
                    NonZeroU64::new(w[10])?,
                    w[11],
                ))
            },
        };
        value.valid().then_some(value)
    }
}
