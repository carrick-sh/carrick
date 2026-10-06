//! Linux per-thread registration and clear/wake policy.
use crate::abi::thread::{GateState, Lifecycle, ThreadControlSlot, ThreadLifecyclePage};
use core::sync::atomic::{AtomicU64, Ordering};
/// Canonical `set_robust_list` (the generic table's number, which the
/// AArch64 table uses natively; x86_64 273 decodes to it).
pub const SYS_SET_ROBUST_LIST: usize = 99;

/// `sizeof(struct robust_list_head)` on 64-bit Linux.
pub const ROBUST_LIST_HEAD_SIZE: u64 = 24;

/// Linux `EINVAL`.
const EINVAL: i64 = 22;

/// One running thread's lifecycle state.
#[derive(Clone, Copy)]
pub struct LifecycleThread<'a> {
    pub page: &'a ThreadLifecyclePage,
    pub slot: &'a ThreadControlSlot,
}

/// Whether the common kernel may serve the per-thread setup calls: the
/// hatch is on and the gate is not terminally closed (a tracer or seccomp
/// must see them).
pub fn setup_open(page: &ThreadLifecyclePage) -> bool {
    page.serves_sigmask() && page.gate() != GateState::Closed
}

/// The `head` argument of `set_robust_list`: a user address that is stored,
/// never dereferenced here (exit-time walking belongs to its owner).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RobustListHead(u64);
impl RobustListHead {
    pub const fn new(user_address: u64) -> Self {
        Self(user_address)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// The `len` argument of `set_robust_list`, exactly as the caller passed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RobustListLen(u64);
impl RobustListLen {
    pub const fn new(len: u64) -> Self {
        Self(len)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// The caller's owned control slot, with an optional structural witness tied
/// to this execution binding. Count actual publications in the shared body,
/// so an adapter cannot mistake one return for one metadata write.
pub struct RobustListSlot<'a> {
    control: &'a ThreadControlSlot,
    publications: Option<&'a AtomicU64>,
}
impl<'a> RobustListSlot<'a> {
    pub const fn new(control: &'a ThreadControlSlot, publications: Option<&'a AtomicU64>) -> Self {
        Self {
            control,
            publications,
        }
    }
    fn publish(self, head: RobustListHead) {
        self.control
            .set_robust_list(head.raw(), ROBUST_LIST_HEAD_SIZE as u32);
        if let Some(count) = self.publications {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// What one `set_robust_list` did to the thread's own slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RobustListOutcome {
    /// The head is published in the caller's slot; the call returns 0.
    Registered,
    /// `len != sizeof(struct robust_list_head)`: Linux returns `EINVAL`
    /// and the slot is untouched.
    InvalidLength,
    /// The setup gate is closed (tracer/seccomp) or the hatch is off: the
    /// slot is untouched and the call belongs to the host lane.
    Declined,
}

impl RobustListOutcome {
    /// The Linux result of a served outcome; `None` for [`Self::Declined`].
    pub const fn linux_result(self) -> Option<i64> {
        match self {
            Self::Registered => Some(0),
            Self::InvalidLength => Some(-EINVAL),
            Self::Declined => None,
        }
    }
}

/// `set_robust_list(head, len)` for the running thread: the head goes to
/// its owned `slot`, where exit finds it. Only the owning thread writes
/// its slot; no other slot is reachable from here.
pub fn set_robust_list(
    page: &ThreadLifecyclePage,
    slot: RobustListSlot<'_>,
    head: RobustListHead,
    len: RobustListLen,
) -> RobustListOutcome {
    if !setup_open(page) {
        return RobustListOutcome::Declined;
    }
    if len.raw() != ROBUST_LIST_HEAD_SIZE {
        return RobustListOutcome::InvalidLength;
    }
    slot.publish(head);
    RobustListOutcome::Registered
}

/// Clear bytes and futex cardinality shared by guest and terminal host retirement.
pub const CHILD_TID_CLEAR: [u8; 4] = 0u32.to_le_bytes();
pub const CHILD_TID_WAKE_MASK: u32 = u32::MAX;
pub const CHILD_TID_WAKE_COUNT: u32 = 1;
