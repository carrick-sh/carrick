//! Host authority for EL1 delegated inotify instances and name cache.

use parking_lot::Mutex;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use carrick_abi::*;
use carrick_el1_abi::*;
use carrick_fatal::carrick_fatal;

use crate::dispatch::fd_table::OpenFile;
use crate::el1_delegation::NotEligible;
use crate::inotify::InotifyState;
use crate::kernel::FileTableId;
use crate::kernel::objects::FileDescription;

static ALLOCATED_INOTIFY_HANDLES: Mutex<[bool; MAX_DELEGATED_INOTIFY]> =
    Mutex::new([false; MAX_DELEGATED_INOTIFY]);
static DELEGATED_INOTIFY_DESCRIPTIONS: Mutex<
    [Option<Weak<FileDescription>>; MAX_DELEGATED_INOTIFY],
> = Mutex::new([const { None }; MAX_DELEGATED_INOTIFY]);
static DELEGATED_INOTIFY_STATES: Mutex<[Option<Arc<InotifyState>>; MAX_DELEGATED_INOTIFY]> =
    Mutex::new([const { None }; MAX_DELEGATED_INOTIFY]);

/// Allocate an inotify delegation handle (1..=MAX_DELEGATED_INOTIFY).
fn allocate_inotify_handle() -> Option<u32> {
    let mut handles = ALLOCATED_INOTIFY_HANDLES.lock();
    for (i, allocated) in handles.iter_mut().enumerate() {
        if !*allocated {
            *allocated = true;
            return Some((i + 1) as u32);
        }
    }
    None
}

/// Free an inotify delegation handle.
fn free_inotify_handle(handle: u32) {
    if handle > 0 && (handle as usize) <= MAX_DELEGATED_INOTIFY {
        let mut handles = ALLOCATED_INOTIFY_HANDLES.lock();
        handles[(handle - 1) as usize] = false;
        let mut descs = DELEGATED_INOTIFY_DESCRIPTIONS.lock();
        descs[(handle - 1) as usize] = None;
        let mut states = DELEGATED_INOTIFY_STATES.lock();
        states[(handle - 1) as usize] = None;
    }
}

/// Delegate an open inotify description to EL1.
pub fn delegate_inotify(
    open_file: &OpenFile,
    file_table: FileTableId,
    fd: i32,
    state: &Arc<InotifyState>,
    flags: u32,
) -> Result<u32, NotEligible> {
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return Err(NotEligible::Disabled);
    }
    if open_file.description.delegation_handle() != 0 {
        return Ok(open_file.description.delegation_handle());
    }

    let handle = allocate_inotify_handle().ok_or(NotEligible::TableFull)?;

    let inotify_ptr = (region_ptr
        + EL1_INOTIFY_TABLE_OFFSET as usize
        + (handle as usize - 1) * core::mem::size_of::<DelegatedInotify>())
        as *const DelegatedInotify;
    let inotify = unsafe { &*inotify_ptr };

    if !inotify.host_lock_bounded(100_000) {
        free_inotify_handle(handle);
        return Err(NotEligible::TableFull);
    }

    let incarnation = crate::el1_delegation::next_incarnation();
    inotify.generation.store(incarnation, Ordering::Relaxed);
    inotify.flags.store(flags, Ordering::Relaxed);
    inotify.next_wd.store(state.next_wd(), Ordering::Relaxed);
    inotify.reset_queue();
    inotify.num_watches.store(0, Ordering::Relaxed);

    // Initialize watches array
    let watches = unsafe { &mut *inotify.watches.get() };
    for w in watches.iter_mut() {
        *w = DelegatedWatch::default();
    }

    inotify
        .state
        .store(DELEGATED_STATE_GUEST, Ordering::Release);
    inotify.unlock();

    // Bind fd_map slot
    let fd_map_base = (region_ptr + EL1_FD_MAP_OFFSET as usize) as *const FdMapSlot;
    let slot_found = crate::el1_delegation::with_fd_map_lock(|| {
        (0..FD_MAP_CAPACITY).any(|slot_idx| {
            // SAFETY: fd map slot within the EL1 region.
            let slot = unsafe { &*fd_map_base.add(slot_idx) };
            if slot.incarnation.load(Ordering::Relaxed) == 0 {
                slot.set(
                    file_table.raw(),
                    fd as u32,
                    FD_HANDLE_INOTIFY_TAG | handle,
                    incarnation,
                );
                true
            } else {
                false
            }
        })
    });

    if !slot_found {
        if inotify.host_lock_bounded(100_000) {
            inotify.state.store(DELEGATED_STATE_DEAD, Ordering::Release);
            inotify.unlock();
        }
        free_inotify_handle(handle);
        return Err(NotEligible::TableFull);
    }

    open_file.description.set_delegation_handle(handle);
    {
        let mut descs = DELEGATED_INOTIFY_DESCRIPTIONS.lock();
        descs[(handle - 1) as usize] = Some(Arc::downgrade(&open_file.description));
        let mut states = DELEGATED_INOTIFY_STATES.lock();
        states[(handle - 1) as usize] = Some(Arc::clone(state));
    }

    Ok(handle)
}

/// Recall a delegated inotify description by handle.
pub fn recall_inotify_by_handle(
    handle: u32,
    held_file_handle: Option<u32>,
) -> Result<(), LinuxErrno> {
    if handle == 0 || (handle as usize) > MAX_DELEGATED_INOTIFY {
        return Ok(());
    }
    let desc = {
        let descs = DELEGATED_INOTIFY_DESCRIPTIONS.lock();
        descs[(handle - 1) as usize]
            .as_ref()
            .and_then(|w| w.upgrade())
    };
    if let Some(desc) = desc {
        recall_inotify_internal(&desc, held_file_handle)
    } else {
        Ok(())
    }
}

/// Recall a delegated inotify description back to host authority.
pub fn recall_inotify(description: &FileDescription) -> Result<(), LinuxErrno> {
    recall_inotify_internal(description, None)
}

fn recall_inotify_internal(
    description: &FileDescription,
    held_file_handle: Option<u32>,
) -> Result<(), LinuxErrno> {
    let handle = description.delegation_handle();
    if handle == 0 || (handle as usize) > MAX_DELEGATED_INOTIFY {
        return Ok(());
    }

    mark_pending_host_work_all();
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return Ok(());
    }

    let inotify_ptr = (region_ptr
        + EL1_INOTIFY_TABLE_OFFSET as usize
        + (handle as usize - 1) * core::mem::size_of::<DelegatedInotify>())
        as *const DelegatedInotify;
    let inotify = unsafe { &*inotify_ptr };

    if !inotify.host_lock_bounded(100_000) {
        carrick_fatal!(
            "el1_inotify",
            "timed out waiting for EL1 inotify lock on recall (handle={handle})"
        );
    }

    inotify
        .state
        .store(DELEGATED_STATE_RECALLING, Ordering::Release);

    let state = {
        let mut states = DELEGATED_INOTIFY_STATES.lock();
        states[(handle - 1) as usize].take()
    };

    // Copy ring events, watches, and state back to host inotify
    if let Some(state) = &state {
        let watches = unsafe { &*inotify.watches.get() };
        for w in watches.iter() {
            if w.alive != 0 {
                state.restore_watch(w.wd, w.mask);
            }
        }
        // The queue holds records in read(2) format: replay each, with its
        // name, into the host model in order.
        let mut records = vec![0u8; carrick_el1_abi::INOTIFY_QUEUE_BYTES];
        let n = inotify.drain_into(&mut records).unwrap_or(0);
        let mut at = 0;
        while at + 16 <= n {
            let field = |o: usize| {
                [
                    records[at + o],
                    records[at + o + 1],
                    records[at + o + 2],
                    records[at + o + 3],
                ]
            };
            let wd = i32::from_ne_bytes(field(0));
            let mask = u32::from_ne_bytes(field(4));
            let cookie = u32::from_ne_bytes(field(8));
            let len = u32::from_ne_bytes(field(12)) as usize;
            let name = (len > 0).then(|| {
                let raw = &records[at + 16..at + 16 + len];
                &raw[..raw.iter().position(|b| *b == 0).unwrap_or(raw.len())]
            });
            state.enqueue(wd, mask, cookie, name);
            at += 16 + len;
        }
        let next_wd = inotify.next_wd.load(Ordering::Relaxed);
        state.set_next_wd(next_wd);
    }

    // Clear fd_map slots for this inotify handle
    let fd_map_base = (region_ptr + EL1_FD_MAP_OFFSET as usize) as *const FdMapSlot;
    crate::el1_delegation::with_fd_map_lock(|| {
        for slot_idx in 0..FD_MAP_CAPACITY {
            // SAFETY: fd map slot within the EL1 region.
            let slot = unsafe { &*fd_map_base.add(slot_idx) };
            if slot.handle.load(Ordering::Acquire) == (FD_HANDLE_INOTIFY_TAG | handle) {
                slot.clear();
            }
        }
    });

    free_inotify_handle(handle);
    inotify.state.store(DELEGATED_STATE_DEAD, Ordering::Release);
    inotify.unlock();

    // Remove marks referencing this inotify handle from all delegated files after inotify lock is released
    crate::el1_delegation::remove_inotify_marks_from_all_files(handle, held_file_handle);

    description.set_delegation_handle(0);
    Ok(())
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

/// Check if an InotifyState is currently delegated to EL1.
pub fn is_inotify_state_delegated(state: &Arc<InotifyState>) -> bool {
    let states = DELEGATED_INOTIFY_STATES.lock();
    states
        .iter()
        .any(|s| s.as_ref().map(|s| Arc::ptr_eq(s, state)).unwrap_or(false))
}
