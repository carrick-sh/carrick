//! Frame-independent per-thread setup on the running thread's
//! [`ThreadControlSlot`]: where the common kernel finds the slot
//! ([`LifecycleVenue`]) and robust-list metadata publication.
//!
//! Nothing here reads an ISA register frame, copies user memory or touches a
//! scheduler, so the AArch64 EL1 lifecycle personality and the x86_64 CPL0
//! entry (through [`super::common_entry`]) use this same metadata view. Linux
//! registration policy lives in [`carrick_personality_linux::pending_lifecycle`].
use carrick_el1_abi::{CurrentTask, EntryRef, GateState, ThreadControlSlot, ThreadLifecyclePage};
pub use carrick_personality_linux::entry::SYS_SET_ROBUST_LIST;
use carrick_personality_linux::pending_lifecycle::RobustListVenue;
pub use carrick_personality_linux::pending_lifecycle::{RobustListHead, RobustListLen};
use core::sync::atomic::AtomicU64;

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

/// Native view of the caller's owned metadata; Linux decides gate and size policy.
pub struct RobustListSlot<'a> {
    page: &'a ThreadLifecyclePage,
    control: &'a ThreadControlSlot,
    publications: Option<&'a AtomicU64>,
}
impl<'a> RobustListSlot<'a> {
    pub const fn new(
        page: &'a ThreadLifecyclePage,
        control: &'a ThreadControlSlot,
        publications: Option<&'a AtomicU64>,
    ) -> Self {
        Self {
            page,
            control,
            publications,
        }
    }
}
impl RobustListVenue for RobustListSlot<'_> {
    fn setup_enabled(&self) -> bool {
        self.page.serves_sigmask()
    }
    fn gate_closed(&self) -> bool {
        self.page.gate() == GateState::Closed
    }
    fn publish(&self, head: RobustListHead, len: u32) {
        self.control.set_robust_list(head.raw(), len);
    }
    fn publication_counter(&self) -> Option<&AtomicU64> {
        self.publications
    }
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
