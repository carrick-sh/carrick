//! Frame-independent per-thread setup on the running thread's
//! [`ThreadControlSlot`]: where the common kernel finds the slot
//! ([`LifecycleVenue`]) and the robust-list registration body.
//!
//! Nothing here reads an ISA register frame, copies user memory or touches a
//! scheduler, so the AArch64 EL1 lifecycle personality and the x86_64 CPL0
//! entry (through [`super::common_entry`]) call the same bodies with typed
//! arguments.
use carrick_el1_abi::{CurrentTask, EntryRef, GateState, ThreadControlSlot, ThreadLifecyclePage};
use core::sync::atomic::{AtomicU64, Ordering};

/// Canonical `set_robust_list` (the generic table's number, which the
/// AArch64 table uses natively; x86_64 273 decodes to it).
pub const SYS_SET_ROBUST_LIST: usize = 99;

/// `sizeof(struct robust_list_head)` on 64-bit Linux.
pub const ROBUST_LIST_HEAD_SIZE: u64 = 24;

/// Linux `EINVAL`.
const EINVAL: i64 = 22;

/// Where the common kernel finds the lifecycle state of the thread running
/// on a vCPU. The host (runtime stage L4) publishes it; placement is per
/// process.
pub trait LifecycleVenue {
    /// The lifecycle page of `task`'s process and `task`'s own control
    /// slot, or `None` when the common kernel serves no lifecycle call for
    /// it.
    fn thread<'a>(&'a self, task: &'a CurrentTask) -> Option<LifecycleThread<'a>>;
    /// The control slot a thread born into `entry` of `page` will own.
    fn born_slot(&self, page: &ThreadLifecyclePage, entry: EntryRef) -> Option<&ThreadControlSlot>;
}

/// One running thread's lifecycle state.
#[derive(Clone, Copy)]
pub struct LifecycleThread<'a> {
    pub page: &'a ThreadLifecyclePage,
    pub slot: &'a ThreadControlSlot,
}

/// Whether the common kernel may serve the per-thread setup calls: the
/// hatch is on and the gate is not terminally closed (a tracer or seccomp
/// must see them).
pub(crate) fn setup_open(page: &ThreadLifecyclePage) -> bool {
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

/// Production venue: addresses are guest-kernel-only retained metadata,
/// carried with exact scheduler identity across parks and switches.
pub struct GuestLifecycleVenue;

#[cfg(target_os = "none")]
impl LifecycleVenue for GuestLifecycleVenue {
    fn thread<'a>(&'a self, task: &'a CurrentTask) -> Option<LifecycleThread<'a>> {
        let (page, slot) = task.lifecycle_refs()?;
        Some(LifecycleThread { page, slot })
    }
    fn born_slot(&self, page: &ThreadLifecyclePage, entry: EntryRef) -> Option<&ThreadControlSlot> {
        let address = page.control_address(entry)?;
        let end = address.checked_add(core::mem::size_of::<ThreadControlSlot>() as u64)?;
        if address < carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE
            || end
                > carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE
                    + carrick_el1_abi::EL1_DYNAMIC_METADATA_SIZE
            || !address.is_multiple_of(core::mem::align_of::<ThreadControlSlot>() as u64)
        {
            return None;
        }
        // SAFETY: the host stocks this address only after reserving executable custody;
        // carrier metadata retains its exact backing across every zone reference.
        Some(unsafe { &*(address as *const ThreadControlSlot) })
    }
}

#[cfg(target_os = "none")]
pub fn guest_venue() -> Option<&'static dyn LifecycleVenue> {
    static VENUE: GuestLifecycleVenue = GuestLifecycleVenue;
    Some(&VENUE)
}
#[cfg(not(target_os = "none"))]
pub fn guest_venue() -> Option<&'static dyn LifecycleVenue> {
    None
}
