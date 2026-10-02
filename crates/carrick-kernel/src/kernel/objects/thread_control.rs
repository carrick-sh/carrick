//! Control-only backing retained by the thread and every execution-lane pin.

use std::ops::Deref;
use std::sync::{Arc, Weak};

use carrick_el1_abi::{BlockedMask, ThreadControlSlot};
use carrick_guest_mem::HostVa;
use parking_lot::Mutex;

use super::{TaskKey, ThreadKey};

const PAGE_BYTES: usize = 16 * 1024;
const SLOTS: usize = PAGE_BYTES / std::mem::size_of::<ThreadControlSlot>();

/// Contains no allocator metadata, pointers, locks or host-only thread state.
#[repr(C, align(16384))]
#[derive(Debug)]
struct ControlPage {
    slots: [ThreadControlSlot; SLOTS],
}

#[derive(Debug)]
struct ControlBacking {
    page: Box<ControlPage>,
}

#[derive(Debug)]
struct FreeSlot {
    page: Arc<ControlBacking>,
    index: usize,
}

#[derive(Debug)]
struct Arena {
    owner: TaskKey,
    free: Mutex<Vec<FreeSlot>>,
}

/// One process's control storage. A fork creates a distinct arena. Free-list
/// operations are constant work; a refill supplies a single page of slots.
#[derive(Debug)]
pub(in crate::kernel) struct ThreadControlArena(Arc<Arena>);

impl ThreadControlArena {
    pub(in crate::kernel) fn new(owner: TaskKey) -> Self {
        Self(Arc::new(Arena {
            owner,
            free: Mutex::new(Vec::new()),
        }))
    }

    pub(in crate::kernel) fn allocate(&self, thread: ThreadKey) -> ThreadControlLease {
        let allocation = {
            let mut free = self.0.free.lock();
            if free.is_empty() {
                let page = Arc::new(ControlBacking {
                    page: Box::new(ControlPage {
                        slots: [const { ThreadControlSlot::new() }; SLOTS],
                    }),
                });
                free.extend((0..SLOTS).map(|index| FreeSlot {
                    page: Arc::clone(&page),
                    index,
                }));
            }
            free.pop().unwrap_or_else(|| {
                carrick_fatal::carrick_fatal!("thread::control", "control refill supplied no slot")
            })
        };
        allocation.page.page.slots[allocation.index].reset_for_host_birth(BlockedMask(0));
        ThreadControlLease(Arc::new(Lease {
            owner: self.0.owner,
            thread,
            arena: Arc::downgrade(&self.0),
            allocation: Some(allocation),
        }))
    }
}

#[derive(Debug)]
struct Lease {
    owner: TaskKey,
    thread: ThreadKey,
    arena: Weak<Arena>,
    allocation: Option<FreeSlot>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(arena) = self.arena.upgrade()
            && let Some(allocation) = self.allocation.take()
        {
            arena.free.lock().push(allocation);
        }
    }
}

/// A pin on the actual control slot, never a snapshot. An execution lane must
/// retain this lease until it has retired every guest reference to the slot.
/// The final lease returns it to its process's arena; a pin can outlive that
/// arena without retaining the task or kernel graph.
#[derive(Clone, Debug)]
pub struct ThreadControlLease(Arc<Lease>);

impl ThreadControlLease {
    fn allocation(&self) -> &FreeSlot {
        self.0.allocation.as_ref().unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!("thread::control", "live lease lost its allocation")
        })
    }

    pub fn identity(&self) -> (TaskKey, ThreadKey) {
        (self.0.owner, self.0.thread)
    }

    /// Granule-aligned base of the control-only page this lease pins.
    pub fn backing_base(&self) -> HostVa {
        HostVa(std::ptr::from_ref(self.allocation().page.page.as_ref()).addr())
    }

    pub const fn backing_len(&self) -> usize {
        PAGE_BYTES
    }

    pub fn slot_address(&self) -> HostVa {
        HostVa(std::ptr::from_ref(self.deref()).addr())
    }
}

impl Deref for ThreadControlLease {
    type Target = ThreadControlSlot;

    fn deref(&self) -> &Self::Target {
        let allocation = self.allocation();
        &allocation.page.page.slots[allocation.index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::ids::{LinuxTid, ObjectIdRegistry, TaskId};

    #[test]
    fn pins_delay_reuse_and_release_backing_after_arena_teardown() {
        let ids = ObjectIdRegistry::new();
        let owner = TaskKey {
            id: TaskId::from_abi_positive(100).unwrap(),
            serial: ids.task_serial().unwrap(),
        };
        let key = || ThreadKey {
            tid: LinuxTid::from_abi_positive(101).unwrap(),
            serial: ids.thread_serial().unwrap(),
        };
        let arena = ThreadControlArena::new(owner);
        let first = arena.allocate(key());
        let address = first.slot_address();
        first.set_robust_list(0x1000, 24);
        first.set_clear_child_tid(0x2000);
        first.init_blocked(BlockedMask(0x400));
        let pin = first.clone();
        drop(first);
        let second = arena.allocate(key());
        assert_ne!(second.slot_address(), address);
        drop(pin);
        let successor_key = key();
        let successor = arena.allocate(successor_key);
        assert_eq!(successor.slot_address(), address);
        assert_eq!(successor.identity(), (owner, successor_key));
        assert_eq!(successor.robust_list(), (0, 0));
        assert_eq!(successor.clear_child_tid(), 0);
        assert_eq!(successor.blocked(), BlockedMask(0));
        assert_eq!(successor.entry(), None);
        let backing = Arc::downgrade(&successor.allocation().page);
        drop(arena);
        drop(second);
        assert!(backing.upgrade().is_some());
        drop(successor);
        assert!(backing.upgrade().is_none());
    }

    #[test]
    fn control_pages_grow_without_moving_live_slots() {
        let ids = ObjectIdRegistry::new();
        let owner = TaskKey {
            id: TaskId::from_abi_positive(100).unwrap(),
            serial: ids.task_serial().unwrap(),
        };
        let arena = ThreadControlArena::new(owner);
        let slots: Vec<_> = (0..SLOTS * 2 + 1)
            .map(|index| {
                arena.allocate(ThreadKey {
                    tid: LinuxTid::from_abi_positive(101 + index as i32).unwrap(),
                    serial: ids.thread_serial().unwrap(),
                })
            })
            .collect();
        let mut addresses = std::collections::BTreeSet::new();
        let mut pages = std::collections::BTreeSet::new();
        for slot in &slots {
            assert_eq!(slot.backing_base().raw() % PAGE_BYTES, 0);
            assert!(
                (slot.backing_base().raw()..slot.backing_base().raw() + slot.backing_len())
                    .contains(&slot.slot_address().raw())
            );
            assert!(addresses.insert(slot.slot_address().raw()));
            pages.insert(slot.backing_base().raw());
        }
        assert_eq!(pages.len(), 3);
    }
}
