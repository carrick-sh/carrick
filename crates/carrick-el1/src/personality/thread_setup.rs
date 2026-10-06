//! ARM lifecycle mapping and exact task acquisition.
use carrick_el1_abi::{CurrentTask, EntryRef, ThreadControlSlot, ThreadLifecyclePage};
pub use carrick_personality_linux::thread::*;
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
