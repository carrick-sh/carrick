//! Carrier-wide identity for one logical Linux container.

use std::sync::atomic::{AtomicU64, Ordering};

/// Kernel-graph identity of one container.
///
/// Allocated from a carrier-wide monotonic counter so two containers in one
/// carrier can never share an id. Never derived from a host pid: the carrier
/// pid names the host process, which may hold many of these.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ContainerId(u64);

static NEXT_CONTAINER_ID: AtomicU64 = AtomicU64::new(1);

impl ContainerId {
    /// The next unused id in this carrier. Ids are never recycled.
    pub fn allocate() -> Self {
        Self(NEXT_CONTAINER_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}
