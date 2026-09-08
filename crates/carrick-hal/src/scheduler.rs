//! Scheduling policy types for Carrick.

use std::fmt;

/// Strongly-typed guest CPU identifier (0-indexed).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GuestCpuId(pub u32);

impl GuestCpuId {
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }

    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
}

impl fmt::Display for GuestCpuId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cpu#{}", self.0)
    }
}
