//! Neutral fork identity and physically retained table/custody receipts.
use crate::{El1MmHandle, PortalOperation, ReservationGeneration, ReservationMm};

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

impl PortalForkCustody {
    /// The original four-word custody record shared by physical adapters.
    pub fn words(self) -> [u64; 4] {
        match self {
            Self::Frame {
                va,
                ipa,
                len,
                shared,
            } => [if shared { 4 } else { 1 }, va, ipa, len],
            Self::StructuralCopy {
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
            Self::HostBacking { handle, generation } => [2, handle.get(), generation.get(), 0],
        }
    }
    pub fn decode(words: [u64; 4]) -> Option<Self> {
        Some(match words[0] {
            tag @ (1 | 4)
                if words[3] != 0
                    && words[1].checked_add(words[3]).is_some()
                    && words[2].checked_add(words[3]).is_some() =>
            {
                Self::Frame {
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
                Self::StructuralCopy {
                    source_ipa: words[1],
                    destination_ipa: words[2],
                    len: words[3],
                    executable: tag == 5,
                }
            }
            2 if words[3] == 0 => Self::HostBacking {
                handle: core::num::NonZeroU64::new(words[1])?,
                generation: core::num::NonZeroU64::new(words[2])?,
            },
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalForkCompletion {
    pub request: PortalForkRequest,
    pub child: El1MmHandle,
    pub parent_generation: ReservationGeneration,
    pub child_tables_used: u64,
    pub parent_tables_used: u64,
}

impl crate::ForkRequestRecord for PortalForkRequest {
    fn operation(self) -> PortalOperation {
        self.operation
    }
    fn parent_generation(self) -> ReservationGeneration {
        self.parent_generation
    }
    fn child_mm(self) -> ReservationMm {
        self.child_mm
    }
}
