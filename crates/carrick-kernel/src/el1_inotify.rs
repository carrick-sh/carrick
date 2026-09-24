//! Host authority for EL1 delegated inotify instances and name cache.

use parking_lot::Mutex;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use carrick_el1_abi::*;
use carrick_fatal::carrick_fatal;

use crate::inotify::InotifyState;
use crate::kernel::FileTableId;

// ---------------------------------------------------------------------------
// In-zone inotify instances: born in the zone, never recalled.
// ---------------------------------------------------------------------------
//
// An instance is created in the EL1 aperture at `inotify_init1` and fronted by
// its host `InotifyState` for its whole life: the zone's descriptor allocator,
// watch table and event queue are authoritative, EL1 serves what it can, and
// the host serves everything else against the same object. It leaves the zone
// only when it outgrows it (watch-table capacity), terminally.

static ALLOCATED_INOTIFY_HANDLES: Mutex<[bool; MAX_DELEGATED_INOTIFY]> =
    Mutex::new([false; MAX_DELEGATED_INOTIFY]);
/// Handle -> fronting state. Weak: the state owns the instance, not the table.
static INSTANCE_STATES: Mutex<[Option<Weak<InotifyState>>; MAX_DELEGATED_INOTIFY]> =
    Mutex::new([const { None }; MAX_DELEGATED_INOTIFY]);

/// The host holding an in-zone instance's lock word (lock order: file, then
/// instance; host model, then instance). The guest's critical sections are
/// short and always complete, so the host spins briefly then yields; the long
/// bound is evidence of a bug, never a scheduling budget.
pub(crate) struct InstanceLock<'a> {
    instance: &'a DelegatedInotify,
}

impl<'a> InstanceLock<'a> {
    pub(crate) fn acquire(instance: &'a DelegatedInotify) -> Self {
        let start = std::time::Instant::now();
        while !instance.host_lock_bounded(64) {
            if start.elapsed() >= std::time::Duration::from_secs(30) {
                carrick_fatal!(
                    "el1_inotify",
                    "DelegatedInotify::host_lock timed out (state={})",
                    instance.state.load(Ordering::Relaxed)
                );
            }
            std::thread::yield_now();
        }
        Self { instance }
    }
}

impl Drop for InstanceLock<'_> {
    fn drop(&mut self) {
        self.instance.unlock();
    }
}

fn instance_object(region_ptr: usize, handle: u32) -> &'static DelegatedInotify {
    // SAFETY: the inotify table lives in the EL1 region, mapped for the
    // carrier's lifetime; `handle` is in 1..=MAX_DELEGATED_INOTIFY. Only
    // atomics and the lock-guarded cells are accessed through it.
    unsafe {
        &*((region_ptr
            + EL1_INOTIFY_TABLE_OFFSET as usize
            + (handle as usize - 1) * core::mem::size_of::<DelegatedInotify>())
            as *const DelegatedInotify)
    }
}

/// Create the in-zone instance for a new inotify state and bind the state to
/// it. `None` (EL1 disabled, no region, table full) leaves the state on the
/// host model for its whole life.
pub(crate) fn create_instance(state: &Arc<InotifyState>, flags: u32) -> Option<u32> {
    if !carrick_mem::memory::el1_kernel_enabled() {
        return None;
    }
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return None;
    }
    let handle = {
        let mut handles = ALLOCATED_INOTIFY_HANDLES.lock();
        let index = handles.iter().position(|in_use| !*in_use)?;
        handles[index] = true;
        (index + 1) as u32
    };
    let instance = instance_object(region_ptr, handle);
    {
        let _lock = InstanceLock::acquire(instance);
        instance
            .generation
            .store(crate::el1_delegation::next_incarnation(), Ordering::Relaxed);
        instance.flags.store(flags, Ordering::Relaxed);
        instance.next_wd.store(1, Ordering::Relaxed);
        instance.num_watches.store(0, Ordering::Relaxed);
        // SAFETY: the watch table is only touched under the instance lock.
        for watch in unsafe { &mut *instance.watches.get() }.iter_mut() {
            *watch = DelegatedWatch::default();
        }
        instance.reset_queue();
        instance
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Release);
    }
    INSTANCE_STATES.lock()[handle as usize - 1] = Some(Arc::downgrade(state));
    state.bind_zone(handle, instance);
    Some(handle)
}

/// Publish `(file table, fd) -> instance` so EL1 serves this fd. A dup or a
/// forked child's fd is served on the host through the same object.
pub(crate) fn publish_instance_fd(
    state: &InotifyState,
    file_table: FileTableId,
    fd: i32,
    description: crate::kernel::FileDescriptionId,
) {
    let Some(handle) = state.zone_handle() else {
        return;
    };
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return;
    }
    let instance = instance_object(region_ptr, handle);
    let incarnation = instance.generation.load(Ordering::Acquire);
    // A full map only means EL1 forwards this fd; the host still serves it.
    let _ = crate::el1_delegation::fd_map_publish(
        region_ptr,
        file_table.raw(),
        fd,
        description,
        FD_HANDLE_INOTIFY_TAG | handle,
        incarnation,
    );
}

/// The fronting state of in-zone instance `handle`, if it still exists.
pub(crate) fn state_for_handle(handle: u32) -> Option<Arc<InotifyState>> {
    if handle == 0 || handle as usize > MAX_DELEGATED_INOTIFY {
        return None;
    }
    INSTANCE_STATES.lock()[handle as usize - 1]
        .as_ref()?
        .upgrade()
}

/// Release the in-zone instance when its state is dropped (last close): EL1
/// stops serving it, delegated files drop its marks, the handle is free.
pub(crate) fn release_instance(handle: u32) {
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr != 0 && handle != 0 && handle as usize <= MAX_DELEGATED_INOTIFY {
        let instance = instance_object(region_ptr, handle);
        crate::el1_delegation::fd_map_clear_handle(region_ptr, FD_HANDLE_INOTIFY_TAG | handle);
        {
            let _lock = InstanceLock::acquire(instance);
            instance
                .state
                .store(DELEGATED_STATE_DEAD, Ordering::Release);
            instance.reset_queue();
        }
        crate::el1_delegation::remove_inotify_marks_from_all_files(handle, None);
    }
    if handle != 0 && handle as usize <= MAX_DELEGATED_INOTIFY {
        INSTANCE_STATES.lock()[handle as usize - 1] = None;
        ALLOCATED_INOTIFY_HANDLES.lock()[handle as usize - 1] = false;
    }
}

/// The live watch of in-zone instance `state` on delegated file
/// `file_handle`, as `(wd, mask)`, so a host add_watch of an inode already
/// watched in-guest returns the same descriptor (inotify(7)).
pub(crate) fn zone_watch_for_file(state: &InotifyState, file_handle: u32) -> Option<(i32, u32)> {
    let handle = state.zone_handle()?;
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 || file_handle == 0 {
        return None;
    }
    let instance = instance_object(region_ptr, handle);
    let _lock = InstanceLock::acquire(instance);
    // SAFETY: the watch table is only touched under the instance lock.
    unsafe { &*instance.watches.get() }
        .iter()
        .find(|w| w.alive != 0 && w.file_handle == file_handle)
        .map(|w| (w.wd, w.mask))
}

/// Bump process CWD generation in the EL1 name cache.
pub fn bump_cwd_generation() {
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return;
    }
    let cache =
        unsafe { &*((region_ptr + EL1_NAME_CACHE_OFFSET as usize) as *const InotifyNameCache) };
    cache.bump_cwd_generation();
}

/// Invalidate all entries in the EL1 name cache.
pub fn invalidate_name_cache_all() {
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return;
    }
    let cache =
        unsafe { &*((region_ptr + EL1_NAME_CACHE_OFFSET as usize) as *const InotifyNameCache) };
    cache.invalidate_all();
}

/// Invalidate entries for a specific file handle in the EL1 name cache.
pub fn invalidate_name_cache_file(file_handle: u32) {
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return;
    }
    let cache =
        unsafe { &*((region_ptr + EL1_NAME_CACHE_OFFSET as usize) as *const InotifyNameCache) };
    cache.invalidate_file(file_handle);
}

/// Populate an entry in the EL1 name cache.
pub fn populate_name_cache(file_table: u64, path: &[u8], file_handle: u32) {
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return;
    }
    let cache =
        unsafe { &*((region_ptr + EL1_NAME_CACHE_OFFSET as usize) as *const InotifyNameCache) };
    let cwd_gen = cache.cwd_generation();
    let path_hash = hash_path(path);
    cache.insert(file_table, cwd_gen, path, path_hash, file_handle);
}

/// Whether an inotify state fronts an in-zone instance.
pub fn is_inotify_state_delegated(state: &Arc<InotifyState>) -> bool {
    state.zone_handle().is_some()
}
