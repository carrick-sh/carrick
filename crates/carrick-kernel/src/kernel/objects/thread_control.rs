//! Control-only backing retained by the thread and every execution-lane pin.

use std::ops::Deref;
use std::sync::{Arc, LazyLock, Weak};

use carrick_el1_abi::{BlockedMask, LifecycleHatches, ThreadControlSlot, ThreadLifecyclePage};
use carrick_guest_mem::HostVa;
use carrick_host::host_mapping::{HostMappingKind, OwnedHostMapping};
use parking_lot::Mutex;

use super::{TaskKey, ThreadKey};

const PAGE_BYTES: usize = 16 * 1024;
const SLAB_BYTES: usize = 512 * 1024;
const SLAB_GRANULES: usize = SLAB_BYTES / PAGE_BYTES;
const SLOTS: usize = PAGE_BYTES / std::mem::size_of::<ThreadControlSlot>();

#[derive(Debug, Default)]
struct AbiPagePool {
    slabs: Mutex<Vec<Weak<AbiSlab>>>,
}

#[derive(Debug)]
struct AbiSlab {
    mapping: OwnedHostMapping,
    offset: usize,
    occupied: Mutex<u32>,
}

// SAFETY: the mapping address is stable for this owner's lifetime. Its bitmap
// serializes exclusive granule claims; only synchronized AbiPage layouts are
// initialized in claimed granules, and vacancy is published after final drop.
unsafe impl Send for AbiSlab {}
unsafe impl Sync for AbiSlab {}

impl AbiSlab {
    fn base(&self) -> *mut u8 {
        // SAFETY: the aligned slab lies inside the overallocated mapping.
        unsafe { self.mapping.as_ptr().add(self.offset) }
    }

    fn claim(&self) -> Option<usize> {
        let mut occupied = self.occupied.lock();
        let index = (!*occupied).trailing_zeros() as usize;
        if index == SLAB_GRANULES {
            return None;
        }
        *occupied |= 1 << index;
        Some(index)
    }
}

impl AbiPagePool {
    fn allocate(self: &Arc<Self>) -> (Arc<AbiSlab>, usize) {
        let mut slabs = self.slabs.lock();
        slabs.retain(|slab| slab.strong_count() != 0);
        for slab in slabs.iter().filter_map(Weak::upgrade) {
            if let Some(index) = slab.claim() {
                return (slab, index);
            }
        }
        let mapping = OwnedHostMapping::map_shared_anon(
            SLAB_BYTES + PAGE_BYTES,
            HostMappingKind::PerMmKernelState,
        )
        .unwrap_or_else(|error| {
            carrick_fatal::carrick_fatal!(
                "thread::control",
                "cannot allocate shared ABI slab: {error}"
            )
        });
        let base = mapping.as_ptr().addr();
        let slab = Arc::new(AbiSlab {
            mapping,
            offset: base.next_multiple_of(PAGE_BYTES) - base,
            occupied: Mutex::new(1),
        });
        slabs.push(Arc::downgrade(&slab));
        (slab, 0)
    }
}

/// Contains no allocator metadata, pointers, locks or host-only thread state.
#[repr(C, align(16384))]
#[derive(Debug)]
struct ControlPage {
    slots: [ThreadControlSlot; SLOTS],
}

#[derive(Debug)]
struct ControlBacking {
    page: SharedAbiPage<ControlPage>,
}

/// Owns one ABI granule and shares its slab's host VM object. Slabs contain
/// only closed ABI layouts and free bytes; allocator and Arc metadata
/// remain outside the exposed range.
#[derive(Debug)]
struct SharedAbiPage<T: AbiPage> {
    slab: Arc<AbiSlab>,
    index: usize,
    pool: Arc<AbiPagePool>,
    value: std::marker::PhantomData<T>,
}

/// Closed to this module's ABI-only layouts. Host objects cannot be
/// accidentally placed inside an EL1-published granule by a generic caller.
trait AbiPage: Send + Sync {}
impl AbiPage for ControlPage {}
impl AbiPage for LifecycleBacking {}
impl AbiPage for ActivityBacking {}

impl<T: AbiPage> SharedAbiPage<T> {
    fn new(value: T, pool: Arc<AbiPagePool>) -> Self {
        // Both concrete ABI pages occupy exactly one claimed slab granule.
        const {
            assert!(std::mem::size_of::<T>() == PAGE_BYTES);
            assert!(std::mem::align_of::<T>() == PAGE_BYTES);
        }
        let (slab, index) = pool.allocate();
        // SAFETY: one complete aligned granule lies within the mapping. This
        // owner exclusively initializes it before publishing shared references.
        unsafe { slab.base().add(index * PAGE_BYTES).cast::<T>().write(value) };
        Self {
            slab,
            index,
            pool,
            value: std::marker::PhantomData,
        }
    }
}

impl<T: AbiPage> Deref for SharedAbiPage<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: initialized aligned T stays live until this owner drops.
        unsafe { &*self.slab.base().add(self.index * PAGE_BYTES).cast::<T>() }
    }
}

impl<T: AbiPage> Drop for SharedAbiPage<T> {
    fn drop(&mut self) {
        // SAFETY: exclusive final ownership; drop before publishing vacancy.
        unsafe {
            self.slab
                .base()
                .add(self.index * PAGE_BYTES)
                .cast::<T>()
                .drop_in_place()
        };
        *self.slab.occupied.lock() &= !(1 << self.index);
    }
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

#[repr(C, align(16384))]
#[derive(Debug)]
struct ActivityBacking {
    activity: carrick_el1_abi::ThreadLedgerActivity,
    padding: [u8; PAGE_BYTES - std::mem::size_of::<carrick_el1_abi::ThreadLedgerActivity>()],
}

/// Carrier-retainable ledger notification storage; owns no kernel objects.
#[derive(Clone, Debug)]
pub struct ThreadLedgerActivityLease(Arc<SharedAbiPage<ActivityBacking>>);
impl ThreadLedgerActivityLease {
    pub(in crate::kernel) fn for_page(page: &ThreadLifecycleLease) -> Self {
        Self(Arc::new(SharedAbiPage::new(
            ActivityBacking {
                activity: carrick_el1_abi::ThreadLedgerActivity::new(),
                padding: [0; PAGE_BYTES
                    - std::mem::size_of::<carrick_el1_abi::ThreadLedgerActivity>()],
            },
            page.0.pool.clone(),
        )))
    }
    pub fn backing_base(&self) -> HostVa {
        HostVa(self.0.slab.base().addr())
    }
    pub const fn backing_len(&self) -> usize {
        SLAB_BYTES
    }
    pub fn activity_address(&self) -> HostVa {
        HostVa(std::ptr::from_ref(&self.0.activity).addr())
    }
}
impl Deref for ThreadLedgerActivityLease {
    type Target = carrick_el1_abi::ThreadLedgerActivity;
    fn deref(&self) -> &Self::Target {
        &self.0.activity
    }
}

/// Pins a process's lifecycle page without retaining the task/kernel graph.
#[derive(Clone, Debug)]
pub struct ThreadLifecycleLease(
    Arc<SharedAbiPage<LifecycleBacking>>,
    Arc<std::sync::OnceLock<ThreadLedgerActivityLease>>,
);

impl ThreadLifecycleLease {
    pub(in crate::kernel) fn new() -> Self {
        Self::in_pool(Arc::new(AbiPagePool::default()), Arc::default())
    }

    pub(in crate::kernel) fn for_fork(&self) -> Self {
        Self::in_pool(self.0.pool.clone(), self.1.clone())
    }

    fn in_pool(
        pool: Arc<AbiPagePool>,
        activity: Arc<std::sync::OnceLock<ThreadLedgerActivityLease>>,
    ) -> Self {
        let page = Self(
            Arc::new(SharedAbiPage::new(
                LifecycleBacking {
                    page: ThreadLifecyclePage::with_hatches(*LIFECYCLE_HATCHES),
                    padding: [0; PAGE_BYTES - std::mem::size_of::<ThreadLifecyclePage>()],
                },
                pool,
            )),
            activity,
        );
        if let Some(activity) = page.1.get() {
            // SAFETY: the page lease retains its immutable activity owner.
            unsafe {
                page.bind_host_activity(std::ptr::from_ref(&**activity));
            }
        }
        page
    }

    pub(in crate::kernel) fn bind_activity(&self, activity: ThreadLedgerActivityLease) {
        if self.1.set(activity.clone()).is_err()
            && self
                .1
                .get()
                .is_none_or(|old| old.activity_address() != activity.activity_address())
        {
            carrick_fatal::carrick_fatal!(
                "thread::ledger",
                "lifecycle page changed ledger authority"
            );
        }
        // SAFETY: the once-bound owner remains retained by every page lease.
        unsafe {
            self.bind_host_activity(std::ptr::from_ref(&*activity));
        }
    }
    pub fn ledger_activity(&self) -> Option<ThreadLedgerActivityLease> {
        self.1.get().cloned()
    }

    pub fn backing_base(&self) -> HostVa {
        HostVa(self.0.slab.base().addr())
    }

    pub const fn backing_len(&self) -> usize {
        SLAB_BYTES
    }

    pub fn page_address(&self) -> HostVa {
        HostVa(std::ptr::from_ref(&**self.0).addr())
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
    #[cfg(test)]
    pub(in crate::kernel) fn new(owner: TaskKey) -> Self {
        Self::with_lifecycle(owner, ThreadLifecycleLease::new())
    }

    pub(in crate::kernel) fn with_lifecycle(
        owner: TaskKey,
        lifecycle: ThreadLifecycleLease,
    ) -> Self {
        Self(Arc::new(Arena {
            owner,
            lifecycle,
            free: Mutex::new(Vec::new()),
        }))
    }

    pub(in crate::kernel) fn allocate(&self, thread: ThreadKey) -> ThreadControlLease {
        let allocation = {
            let mut free = self.0.free.lock();
            if free.is_empty() {
                let page = Arc::new(ControlBacking {
                    page: SharedAbiPage::new(
                        ControlPage {
                            slots: [const { ThreadControlSlot::new() }; SLOTS],
                        },
                        self.0.lifecycle.0.pool.clone(),
                    ),
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
        HostVa(self.allocation().page.page.slab.base().addr())
    }

    pub const fn backing_len(&self) -> usize {
        SLAB_BYTES
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

    mod serial_host {
        use super::*;

        #[test]
        fn lifecycle_backing_keeps_one_vm_object_across_host_fork() {
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
            let slot = first.allocate(key);
            let other = second.allocate(key);
            let page = slot.lifecycle();
            let other_page = other.lifecycle();
            let mut pipe = [-1; 2];
            // SAFETY: valid output array; only the serial host lane forks/reaps.
            assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
            let child = unsafe { libc::fork() };
            assert!(child >= 0, "fork failed");
            if child == 0 {
                // Only atomic ABI operations and async-signal-safe syscalls after
                // fork: no allocator, Arc operations, locks or Rust destruction.
                slot.init_blocked(BlockedMask(0x400));
                page.close();
                let byte = 1u8;
                unsafe {
                    libc::write(pipe[1], std::ptr::from_ref(&byte).cast(), 1);
                    libc::_exit(0);
                }
            }
            let mut ready = libc::pollfd {
                fd: pipe[0],
                events: libc::POLLIN,
                revents: 0,
            };
            // Bound the child witness without leaving an unreaped child on red.
            let observed = unsafe { libc::poll(&mut ready, 1, 5000) };
            if observed != 1 {
                unsafe { libc::kill(child, libc::SIGKILL) };
            }
            let mut status = 0;
            let reaped = unsafe { libc::waitpid(child, &mut status, 0) };
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            assert_eq!(observed, 1, "child did not publish ABI writes");
            assert_eq!(reaped, child);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
            assert_eq!(
                slot.blocked(),
                BlockedMask(0x400),
                "control backing split by host COW"
            );
            assert_eq!(
                page.gate(),
                carrick_el1_abi::GateState::Closed,
                "lifecycle backing split by host COW"
            );
            assert_eq!(other.blocked(), BlockedMask(0));
            assert_eq!(other_page.gate(), carrick_el1_abi::GateState::Open);
        }
    }

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
        assert_eq!(first_page.backing_len(), SLAB_BYTES);
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
        assert_eq!(pages.len(), 1);
    }
}
