//! Control-only backing retained by the thread and every execution-lane pin.

use std::ops::Deref;
use std::sync::{Arc, LazyLock, Weak};

use carrick_el1_abi::{BlockedMask, LifecycleHatches, ThreadControlSlot, ThreadLifecyclePage};
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

/// The complete mapping granule contains only shared ABI bytes.
#[repr(C, align(16384))]
#[derive(Debug)]
struct LifecycleBacking {
    page: ThreadLifecyclePage,
    padding: [u8; PAGE_BYTES - std::mem::size_of::<ThreadLifecyclePage>()],
}

/// Pins a process's lifecycle page without retaining the task/kernel graph.
#[derive(Clone, Debug)]
pub struct ThreadLifecycleLease(Arc<LifecycleBacking>);

impl ThreadLifecycleLease {
    pub fn backing_base(&self) -> HostVa {
        HostVa(std::ptr::from_ref(self.0.as_ref()).addr())
    }

    pub const fn backing_len(&self) -> usize {
        PAGE_BYTES
    }
}

impl Deref for ThreadLifecycleLease {
    type Target = ThreadLifecyclePage;
    fn deref(&self) -> &Self::Target {
        &self.0.page
    }
}

static LIFECYCLE_HATCHES: LazyLock<LifecycleHatches> =
    LazyLock::new(|| LifecycleHatches::from_lookup(|name| std::env::var(name).ok()));

#[derive(Debug)]
struct Arena {
    owner: TaskKey,
    lifecycle: ThreadLifecycleLease,
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
            lifecycle: ThreadLifecycleLease(Arc::new(LifecycleBacking {
                page: ThreadLifecyclePage::with_hatches(*LIFECYCLE_HATCHES),
                padding: [0; PAGE_BYTES - std::mem::size_of::<ThreadLifecyclePage>()],
            })),
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
            lifecycle: self.0.lifecycle.clone(),
            allocation: Some(allocation),
        }))
    }

    pub(in crate::kernel) fn owns(&self, lease: &ThreadControlLease) -> bool {
        Weak::ptr_eq(&lease.0.arena, &Arc::downgrade(&self.0))
    }
}

#[derive(Debug)]
struct Lease {
    owner: TaskKey,
    thread: ThreadKey,
    arena: Weak<Arena>,
    lifecycle: ThreadLifecycleLease,
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

    /// Same process authority for every slot issued by this arena. Numeric
    /// task keys, including equal keys in distinct kernels, cannot alias it.
    pub fn lifecycle(&self) -> ThreadLifecycleLease {
        self.0.lifecycle.clone()
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
    fn equal_numeric_keys_do_not_cross_live_arena_authorities() {
        let ids = ObjectIdRegistry::new();
        let owner = TaskKey {
            id: TaskId::from_abi_positive(100).unwrap(),
            serial: ids.task_serial().unwrap(),
        };
        let key = ThreadKey {
            tid: LinuxTid::from_abi_positive(101).unwrap(),
            serial: ids.thread_serial().unwrap(),
        };
        let first = ThreadControlArena::new(owner);
        let second = ThreadControlArena::new(owner);
        let first_slot = first.allocate(key);
        let second_slot = second.allocate(key);
        assert_eq!(first_slot.identity(), second_slot.identity());
        assert!(first.owns(&first_slot));
        assert!(second.owns(&second_slot));
        assert!(!first.owns(&second_slot));
        assert!(!second.owns(&first_slot));
        let first_page = first_slot.lifecycle();
        let second_page = second_slot.lifecycle();
        assert_ne!(first_page.backing_base(), second_page.backing_base());
        assert_eq!(first_page.backing_base().0 % PAGE_BYTES, 0);
        assert_eq!(first_page.backing_len(), PAGE_BYTES);
        first_page.close();
        assert_eq!(
            first_slot.lifecycle().gate(),
            carrick_el1_abi::GateState::Closed
        );
        assert_eq!(second_page.gate(), carrick_el1_abi::GateState::Open);
        let another = first.allocate(key);
        assert_eq!(
            another.lifecycle().backing_base(),
            first_page.backing_base()
        );
        drop(first);
        assert_eq!(first_page.gate(), carrick_el1_abi::GateState::Closed);
    }

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
