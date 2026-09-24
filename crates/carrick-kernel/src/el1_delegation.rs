//! EL1 delegated regular files host authority.
//!
//! Controls whole-object delegation of eligible regular files to the in-guest
//! EL1 kernel, and manages recall back to the host whenever host code touches
//! the description or its authority.

use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use std::sync::atomic::Ordering;

use carrick_abi::*;
use carrick_el1_abi::*;
use carrick_fatal::carrick_fatal;

use crate::dispatch::fd_table::{OpenDescription, OpenFile};
use crate::dispatch::fs::FsState;
use crate::kernel::objects::FileDescription;
use crate::kernel::{FileTableId, RlimitSet};

pub use carrick_el1_abi::{
    El1TaskId, clear_pending_host_work, get_el1_region_host_ptr, get_orig_arg0,
    mark_pending_host_work, mark_pending_host_work_all, mark_pending_host_work_for_file_tables,
    mark_pending_host_work_for_task, record_el1_region_host_ptr, take_served_with_work,
    update_current_task_file_table_for_task,
};

impl From<crate::kernel::ids::LinuxTid> for El1TaskId {
    fn from(tid: crate::kernel::ids::LinuxTid) -> Self {
        El1TaskId::from_linux_tid(tid.raw())
    }
}

impl From<crate::kernel::ids::TaskId> for El1TaskId {
    fn from(id: crate::kernel::ids::TaskId) -> Self {
        El1TaskId::from_linux_tid(id.raw())
    }
}

/// Clear the recorded host virtual address of the EL1 kernel aperture.
pub fn clear_el1_region_host_ptr() {
    carrick_el1_abi::record_el1_region_host_ptr(0);
}

/// Publish the current task binding for an executor vCPU mailbox slot into the EL1 aperture.
pub fn publish_current_task(slot: usize, task_id: El1TaskId, generation: u64, file_table: u64) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= 256 {
        return;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task.pending_host_work.store(0, Ordering::Relaxed);
    current_task.served_with_work.store(0, Ordering::Relaxed);
    current_task.task_id.store(task_id.raw(), Ordering::Relaxed);
    current_task.file_table.store(file_table, Ordering::Relaxed);
    current_task.generation.store(generation, Ordering::Release);
}

/// Clear the current task binding for an executor vCPU mailbox slot.
pub fn clear_current_task(slot: usize) {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= 256 {
        return;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    current_task.clear();
}

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Weak};

use carrick_vfs::InodeIdentity;

static NEXT_INCARNATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
static ALLOCATED_HANDLES: Mutex<[bool; MAX_DELEGATED_FILES]> =
    Mutex::new([false; MAX_DELEGATED_FILES]);
static DELEGATED_DESCRIPTIONS: Mutex<[Option<Weak<FileDescription>>; MAX_DELEGATED_FILES]> =
    Mutex::new([const { None }; MAX_DELEGATED_FILES]);

type InodeDelegationMap = HashMap<InodeIdentity, (u32, Weak<FileDescription>)>;

static HAS_DELEGATED_FILES: AtomicBool = AtomicBool::new(false);
static DELEGATED_INODES: Mutex<Option<InodeDelegationMap>> = Mutex::new(None);
static DELEGATED_INODES_SNAPSHOT: ArcSwapOption<InodeDelegationMap> = ArcSwapOption::const_empty();
static DELEGATED_HANDLE_INODES: Mutex<[Option<InodeIdentity>; MAX_DELEGATED_FILES]> =
    Mutex::new([const { None }; MAX_DELEGATED_FILES]);
static DELEGATED_ROOTFS: Mutex<[Option<Weak<carrick_vfs::RootFsVfs>>; MAX_DELEGATED_FILES]> =
    Mutex::new([const { None }; MAX_DELEGATED_FILES]);
static DELEGATED_SPARSE: Mutex<
    [Option<crate::dispatch::fs::HostSparseExtentsRegistry>; MAX_DELEGATED_FILES],
> = Mutex::new([const { None }; MAX_DELEGATED_FILES]);
static FD_MAP_LOCK: Mutex<()> = Mutex::new(());
static MAPPED_INODES: Mutex<Option<HashMap<InodeIdentity, usize>>> = Mutex::new(None);
static HOOK_INIT: std::sync::Once = std::sync::Once::new();

fn publish_delegated_inodes_snapshot(map: &Option<InodeDelegationMap>) {
    match map {
        Some(m) if !m.is_empty() => {
            DELEGATED_INODES_SNAPSHOT.store(Some(std::sync::Arc::new(m.clone())));
        }
        _ => {
            DELEGATED_INODES_SNAPSHOT.store(None);
        }
    }
}

pub(crate) fn register_mapped_inode(inode: InodeIdentity) {
    recall_by_inode(inode);
    let mut map = MAPPED_INODES.lock();
    let map = map.get_or_insert_with(HashMap::new);
    *map.entry(inode).or_insert(0) += 1;
}

pub(crate) fn unregister_mapped_inode(inode: InodeIdentity) {
    let mut map = MAPPED_INODES.lock();
    if let Some(map) = map.as_mut() {
        if let std::collections::hash_map::Entry::Occupied(mut entry) = map.entry(inode) {
            let count = entry.get_mut();
            if *count <= 1 {
                entry.remove();
            } else {
                *count -= 1;
            }
        }
    }
}

pub(crate) fn is_inode_mapped(inode: InodeIdentity) -> bool {
    let map = MAPPED_INODES.lock();
    if let Some(map) = map.as_ref() {
        if map.get(&inode).copied().unwrap_or(0) > 0 {
            return true;
        }
        for (k, v) in map.iter() {
            if *v > 0
                && (k == &inode
                    || (k.dev == 0 && k.ino == inode.ino)
                    || (inode.dev == 0 && k.ino == inode.ino))
            {
                return true;
            }
        }
    }
    false
}

pub(crate) fn init_delegation_hooks() {
    HOOK_INIT.call_once(|| {
        carrick_vfs::dentry::set_inode_recall_hook(recall_by_inode);
    });
}

#[inline]
pub(crate) fn has_delegated_files() -> bool {
    HAS_DELEGATED_FILES.load(Ordering::Acquire)
}

pub(crate) fn is_inode_delegated(inode: InodeIdentity) -> bool {
    if !has_delegated_files() {
        return false;
    }
    let guard = DELEGATED_INODES_SNAPSHOT.load();
    if let Some(map) = guard.as_deref() {
        if map.contains_key(&inode) {
            return true;
        }
        for (k, _) in map.iter() {
            if (k.dev == 0 || inode.dev == 0) && k.ino == inode.ino {
                return true;
            }
        }
    }
    false
}

pub(crate) fn is_inode_delegated_by_other(inode: InodeIdentity, my_handle: u32) -> bool {
    if !has_delegated_files() {
        return false;
    }
    let guard = DELEGATED_INODES_SNAPSHOT.load();
    if let Some(map) = guard.as_deref() {
        if let Some((handle, _)) = map.get(&inode) {
            return *handle != my_handle;
        }
        for (k, (handle, _)) in map.iter() {
            if (k.dev == 0 || inode.dev == 0) && k.ino == inode.ino {
                return *handle != my_handle;
            }
        }
    }
    false
}

pub(crate) fn recall_by_inode(inode: InodeIdentity) -> bool {
    if !has_delegated_files() {
        return false;
    }
    let desc = {
        let guard = DELEGATED_INODES_SNAPSHOT.load();
        if let Some(map) = guard.as_deref() {
            if let Some((_, weak)) = map.get(&inode) {
                weak.upgrade()
            } else {
                map.iter()
                    .find(|(k, _)| (k.dev == 0 || inode.dev == 0) && k.ino == inode.ino)
                    .and_then(|(_, (_, weak))| weak.upgrade())
            }
        } else {
            None
        }
    };
    if let Some(desc) = desc {
        let _ = recall(&desc);
        true
    } else {
        false
    }
}

fn allocate_handle(description: &Arc<FileDescription>) -> Option<u32> {
    let mut handles = ALLOCATED_HANDLES.lock();
    for (i, in_use) in handles.iter_mut().enumerate() {
        if !*in_use {
            *in_use = true;
            let mut descs = DELEGATED_DESCRIPTIONS.lock();
            descs[i] = Some(Arc::downgrade(description));
            return Some((i + 1) as u32);
        }
    }
    None
}

fn unregister_delegated_inode(handle: u32) {
    if handle >= 1 && (handle as usize) <= MAX_DELEGATED_FILES {
        let idx = handle as usize - 1;
        let inode = {
            let mut handle_inodes = DELEGATED_HANDLE_INODES.lock();
            handle_inodes[idx].take()
        };
        if let Some(inode) = inode {
            let mut map = DELEGATED_INODES.lock();
            if let Some(map) = map.as_mut() {
                if let std::collections::hash_map::Entry::Occupied(entry) = map.entry(inode) {
                    if entry.get().0 == handle {
                        entry.remove();
                    }
                }
                if map.is_empty() {
                    HAS_DELEGATED_FILES.store(false, Ordering::Release);
                }
            }
            publish_delegated_inodes_snapshot(&map);
        }
    }
}

fn free_handle(handle: u32) {
    if handle >= 1 && (handle as usize) <= MAX_DELEGATED_FILES {
        let idx = handle as usize - 1;
        unregister_delegated_inode(handle);
        let mut handles = ALLOCATED_HANDLES.lock();
        handles[idx] = false;
        let mut descs = DELEGATED_DESCRIPTIONS.lock();
        descs[idx] = None;
        let mut rootfs = DELEGATED_ROOTFS.lock();
        rootfs[idx] = None;
        let mut sparse = DELEGATED_SPARSE.lock();
        sparse[idx] = None;
    }
}

/// Recall all currently delegated files whose paths are covered by inotify watches or if fanotify is active.
pub(crate) fn recall_all_watched(fs: &FsState) {
    if fs.inotify_registry.is_empty() && fs.fanotify_registry.is_empty() {
        return;
    }
    let candidates: Vec<Arc<FileDescription>> = {
        let descs = DELEGATED_DESCRIPTIONS.lock();
        descs.iter().filter_map(|w| w.as_ref()?.upgrade()).collect()
    };
    for desc in candidates {
        if desc.delegation_handle() == 0 {
            continue;
        }
        let Some(d) = desc.open_description() else {
            continue;
        };
        let should_recall = {
            let guard = d.read();
            let path = match &*guard {
                OpenDescription::HostFile { metadata, .. } => metadata.path.to_str(),
                OpenDescription::File { path, .. } => Some(path.as_str()),
                _ => None,
            };
            if let Some(p) = path {
                !fs.fanotify_registry.is_empty() || fs.inotify_registry.has_watches_covering(p)
            } else {
                false
            }
        };
        if should_recall {
            let _ = recall(&desc);
        }
    }
}

/// Recall all currently delegated files across all tables back to host authority.
///
/// Writeback errors are recorded sticky on the affected descriptions.
pub(crate) fn recall_all_delegated() {
    let candidates: Vec<Arc<FileDescription>> = {
        let descs = DELEGATED_DESCRIPTIONS.lock();
        descs.iter().filter_map(|w| w.as_ref()?.upgrade()).collect()
    };
    for desc in candidates {
        if desc.delegation_handle() == 0 {
            continue;
        }
        let _ = recall(&desc);
    }
}

/// AArch64 canonical syscall numbers served at EL1 on delegated regular files.
pub const DELEGATED_SYSCALL_NUMBERS: &[u64] = &[62, 63, 64, 67, 68, 80];

/// Snapshot of active security and observability policies during delegation eligibility checks.
#[derive(Default, Clone, Copy)]
pub(crate) struct DelegationPolicy<'a> {
    pub seccomp: Option<&'a crate::seccomp::SeccompState>,
    pub observers: Option<&'a crate::observe::ObserverChain>,
    pub interceptors_active: bool,
}

/// Maximum number of times a file description may be recalled before becoming
/// permanently ineligible for EL1 delegation for the remainder of its lifetime.
/// Prevents unbounded recall-then-delegate thrashing on interleaved operations.
pub const MAX_DELEGATION_RECALLS_PER_LIFETIME: u32 = 2;

/// Reasons why a file description cannot be delegated to EL1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotEligible {
    Disabled,
    NoRegion,
    NotRegularFile,
    NotRootfs,
    Watched,
    UnsupportedFlags,
    FileTooLarge,
    MultipleReferences,
    FsizeLimited,
    Mapped,
    RecordLocks,
    TableFull,
    AlreadyDelegated,
    IoError,
    Sealed,
    SeccompFiltered,
    Observed,
    RecalledTooOften,
}

#[cfg(test)]
pub(crate) static YIELD_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
pub(crate) fn yield_count() -> u64 {
    YIELD_COUNT.load(Ordering::Relaxed)
}

#[cfg(test)]
pub(crate) fn reset_yield_count() {
    YIELD_COUNT.store(0, Ordering::Relaxed);
}

fn lock_delegated_file(file: &DelegatedFile, handle: u32) {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(30);
    while !file.host_lock_bounded(64) {
        if start.elapsed() >= timeout {
            let state = file.state.load(Ordering::Relaxed);
            let generation = file.generation.load(Ordering::Relaxed);
            carrick_fatal!(
                "el1_delegation",
                "DelegatedFile::host_lock timed out spinning for handle={}, state={}, generation={}",
                handle,
                state,
                generation
            );
        }
        #[cfg(test)]
        YIELD_COUNT.fetch_add(1, Ordering::Relaxed);
        std::thread::yield_now();
    }
}

/// Delegate an open file to EL1 if all eligibility rules pass.
pub(crate) fn delegate(
    open_file: &OpenFile,
    file_table: FileTableId,
    fd: i32,
    fs: &FsState,
    rlimits: Option<&RlimitSet>,
    policy: Option<DelegationPolicy<'_>>,
) -> Result<u32, NotEligible> {
    let Some(d) = open_file.description.open_description() else {
        return Err(NotEligible::NotRegularFile);
    };
    let mut open = d.write();
    delegate_locked(open_file, &mut open, file_table, fd, fs, rlimits, policy)
}

pub(crate) fn delegate_locked(
    open_file: &OpenFile,
    open: &mut OpenDescription,
    file_table: FileTableId,
    fd: i32,
    fs: &FsState,
    rlimits: Option<&RlimitSet>,
    policy: Option<DelegationPolicy<'_>>,
) -> Result<u32, NotEligible> {
    if std::env::var_os("CARRICK_EL1").is_some_and(|val| val == "0") {
        return Err(NotEligible::Disabled);
    }
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return Err(NotEligible::NoRegion);
    }
    if open_file.description.delegation_handle() != 0 {
        return Err(NotEligible::AlreadyDelegated);
    }
    if open_file.description.common().fd_refs() != 1 {
        return Err(NotEligible::MultipleReferences);
    }
    if open_file.description.common().recall_count() >= MAX_DELEGATION_RECALLS_PER_LIFETIME {
        return Err(NotEligible::RecalledTooOften);
    }
    if open_file.description.has_active_mappings() {
        return Err(NotEligible::Mapped);
    }
    let fallback_rlimits;
    let effective_rlimits = match rlimits {
        Some(limits) => Some(limits),
        None => {
            fallback_rlimits = crate::dispatch::resources::rlimits();
            fallback_rlimits.as_ref()
        }
    };
    if let Some(limits) = effective_rlimits {
        let lim = limits.get(LinuxResource::Fsize);
        if lim.rlim_cur != LINUX_RLIM_INFINITY {
            return Err(NotEligible::FsizeLimited);
        }
    }
    if let Some(pol) = policy {
        if pol.seccomp.is_some_and(|s| s.is_active()) {
            return Err(NotEligible::SeccompFiltered);
        }
        if pol.interceptors_active {
            return Err(NotEligible::Observed);
        }
        if pol
            .observers
            .is_some_and(|o| o.observes_any_syscall(DELEGATED_SYSCALL_NUMBERS))
        {
            return Err(NotEligible::Observed);
        }
    }
    if !fs.classic_record_locks.is_empty() {
        return Err(NotEligible::RecordLocks);
    }
    if !fs.fanotify_registry.is_empty() {
        return Err(NotEligible::Watched);
    }

    let status = open_file.description.common().status_flags();
    let open_flags = LinuxOpenFlags::from_bits_truncate(status);
    if open_flags.intersects(
        LinuxOpenFlags::APPEND
            | LinuxOpenFlags::DIRECT
            | LinuxOpenFlags::SYNC
            | LinuxOpenFlags::DSYNC
            | LinuxOpenFlags::PATH,
    ) {
        return Err(NotEligible::UnsupportedFlags);
    }

    let acc = status & LINUX_O_ACCMODE;
    let readable = acc == LINUX_O_RDONLY || acc == LINUX_O_RDWR;
    let writable_flag = acc == LINUX_O_WRONLY || acc == LINUX_O_RDWR;

    let (_path_str, size, offset, writable, inode) = match &*open {
        OpenDescription::HostFile {
            host_fd,
            metadata,
            writable: w,
            ..
        } => {
            let path = metadata.path.to_str().unwrap_or("");
            if fs.vfs_mounts.resolve(path).is_some() {
                return Err(NotEligible::NotRootfs);
            }
            if !fs.inotify_registry.is_empty() && fs.inotify_registry.has_watches_covering(path) {
                return Err(NotEligible::Watched);
            }
            let mut st: libc::stat = unsafe { core::mem::zeroed() };
            if unsafe { libc::fstat(host_fd.raw(), &mut st) } != 0 {
                return Err(NotEligible::IoError);
            }
            if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
                return Err(NotEligible::NotRegularFile);
            }
            if st.st_size < 0 || (st.st_size as u64) > DELEGATED_FILE_MAX_SIZE {
                return Err(NotEligible::FileTooLarge);
            }
            let cur_offset = unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_CUR) };
            if cur_offset < 0 {
                return Err(NotEligible::IoError);
            }
            let inode = fs.rootfs_vfs.path_inode_identity(path).unwrap_or_else(|| {
                carrick_vfs::RootFsVfs::host_fd_inode_identity(host_fd.raw())
                    .unwrap_or_else(|| InodeIdentity::new(st.st_dev as u64, st.st_ino as u64))
            });
            (
                path,
                st.st_size as u64,
                cur_offset as u64,
                *w && writable_flag,
                inode,
            )
        }
        OpenDescription::File {
            path,
            contents,
            offset,
            writable: w,
            ..
        } => {
            if fs.vfs_mounts.resolve(path.as_str()).is_some() {
                return Err(NotEligible::NotRootfs);
            }
            if !fs.inotify_registry.is_empty()
                && fs.inotify_registry.has_watches_covering(path.as_str())
            {
                return Err(NotEligible::Watched);
            }
            let cur_len = contents.len().map_err(|_| NotEligible::IoError)?;
            if cur_len > DELEGATED_FILE_MAX_SIZE {
                return Err(NotEligible::FileTooLarge);
            }
            let inode = fs
                .rootfs_vfs
                .path_inode_identity(path.as_str())
                .unwrap_or_else(|| {
                    InodeIdentity::new(
                        0,
                        crate::dispatch::inode_for_path(std::path::Path::new(path.as_str())),
                    )
                });
            (
                path.as_str(),
                cur_len,
                *offset as u64,
                *w && writable_flag,
                inode,
            )
        }
        _ => return Err(NotEligible::NotRegularFile),
    };

    if is_inode_mapped(inode) {
        return Err(NotEligible::Mapped);
    }

    if let Some(seals_raw) = open_file.description.common().seals() {
        let seals = carrick_abi::LinuxMemfdSeals::from_bits_truncate(seals_raw);
        if writable
            && seals.intersects(
                carrick_abi::LinuxMemfdSeals::WRITE
                    | carrick_abi::LinuxMemfdSeals::FUTURE_WRITE
                    | carrick_abi::LinuxMemfdSeals::GROW,
            )
        {
            return Err(NotEligible::Sealed);
        }
    }

    init_delegation_hooks();

    let handle = allocate_handle(&open_file.description).ok_or(NotEligible::TableFull)?;

    {
        let mut map = DELEGATED_INODES.lock();
        let map_ref = map.get_or_insert_with(HashMap::new);
        match map_ref.entry(inode) {
            std::collections::hash_map::Entry::Occupied(_) => {
                drop(map);
                free_handle(handle);
                return Err(NotEligible::AlreadyDelegated);
            }
            std::collections::hash_map::Entry::Vacant(vacant) => {
                vacant.insert((handle, Arc::downgrade(&open_file.description)));
            }
        }
        publish_delegated_inodes_snapshot(&map);
        let mut handle_inodes = DELEGATED_HANDLE_INODES.lock();
        handle_inodes[(handle - 1) as usize] = Some(inode);
        let mut rootfs = DELEGATED_ROOTFS.lock();
        rootfs[(handle - 1) as usize] = Some(Arc::downgrade(&fs.rootfs_vfs));
        let mut sparse = DELEGATED_SPARSE.lock();
        sparse[(handle - 1) as usize] = Some(fs.host_sparse_extents_registry().clone());
        HAS_DELEGATED_FILES.store(true, Ordering::Release);
    }

    fs.rootfs_vfs.dentry_cache.invalidate_inode(inode);

    let cache_ptr = (region_ptr
        + EL1_CACHE_OFFSET as usize
        + (handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize) as *mut u8;

    // B4: Zero-fill the entire cache slot so handle reuse never leaks a previous file's bytes.
    unsafe {
        std::ptr::write_bytes(cache_ptr, 0, DELEGATED_FILE_MAX_SIZE as usize);
    }

    if size > 0 {
        match &*open {
            OpenDescription::HostFile { host_fd, .. } => {
                let n = unsafe {
                    libc::pread(
                        host_fd.raw(),
                        cache_ptr as *mut libc::c_void,
                        size as usize,
                        0,
                    )
                };
                if n < 0 || (n as u64) != size {
                    free_handle(handle);
                    return Err(NotEligible::IoError);
                }
            }
            OpenDescription::File { contents, .. } => {
                let cache_slice =
                    unsafe { std::slice::from_raw_parts_mut(cache_ptr, size as usize) };
                if contents.read_at(0, cache_slice).is_err() {
                    free_handle(handle);
                    return Err(NotEligible::IoError);
                }
            }
            _ => unreachable!(),
        }
    }

    let file_ptr = (region_ptr
        + EL1_OBJECT_TABLE_OFFSET as usize
        + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
        as *const DelegatedFile;
    let file = unsafe { &*file_ptr };
    let incarnation = NEXT_INCARNATION.fetch_add(1, Ordering::Relaxed);
    lock_delegated_file(file, handle);
    file.generation.store(incarnation, Ordering::Relaxed);
    file.offset.store(offset, Ordering::Relaxed);
    file.size.store(size, Ordering::Relaxed);
    let mut flags_val = 0;
    if readable {
        flags_val |= DELEGATED_FLAG_READABLE;
    }
    if writable {
        flags_val |= DELEGATED_FLAG_WRITABLE;
    }
    file.flags.store(flags_val, Ordering::Relaxed);
    file.dirty_mask.store(0, Ordering::Relaxed);
    file.zero_filled_mask.store(0, Ordering::Relaxed);
    file.state.store(DELEGATED_STATE_GUEST, Ordering::Release);
    file.unlock();

    let _fd_map_guard = FD_MAP_LOCK.lock();
    let fd_map_base = (region_ptr + EL1_FD_MAP_OFFSET as usize) as *const FdMapSlot;
    let mut slot_found = false;
    for slot_idx in 0..FD_MAP_CAPACITY {
        let slot = unsafe { &*fd_map_base.add(slot_idx) };
        if slot.incarnation.load(Ordering::Relaxed) == 0 {
            slot.set(file_table.raw(), fd as u32, handle, incarnation);
            slot_found = true;
            break;
        }
    }

    if !slot_found {
        lock_delegated_file(file, handle);
        file.state.store(DELEGATED_STATE_DEAD, Ordering::Release);
        file.unlock();
        free_handle(handle);
        return Err(NotEligible::TableFull);
    }

    open_file.description.set_delegation_handle(handle);
    Ok(handle)
}

/// Helper for tests to delegate with default/mocked environment.
#[cfg(test)]
pub fn delegate_for_test(
    open_file: &OpenFile,
    file_table: FileTableId,
    fd: i32,
) -> Result<u32, NotEligible> {
    let fs = FsState::new_with_host_resolver(None);
    delegate(open_file, file_table, fd, &fs, None, None)
}

#[cfg(test)]
pub(crate) fn delegate_for_test_with_policy(
    open_file: &OpenFile,
    file_table: FileTableId,
    fd: i32,
    policy: DelegationPolicy<'_>,
) -> Result<u32, NotEligible> {
    let fs = FsState::new_with_host_resolver(None);
    delegate(open_file, file_table, fd, &fs, None, Some(policy))
}

/// Recall a delegated file description back to host authority.
pub(crate) fn recall(description: &FileDescription) -> Result<(), carrick_abi::LinuxErrno> {
    let handle = description.delegation_handle();
    if handle == 0 {
        return Ok(());
    }
    let Some(d) = description.open_description() else {
        return Ok(());
    };
    let mut guard = d.write();
    let handle = description.delegation_handle();
    if handle == 0 {
        return Ok(());
    }
    recall_locked(description, &mut guard, handle)
}

/// Recall a file description if it is currently delegated.
///
/// Writeback errors are recorded sticky on the description.
pub(crate) fn recall_if_delegated(description: &FileDescription) {
    if description.delegation_handle() != 0 {
        let _ = recall(description);
    }
}

pub(crate) fn recall_locked(
    description: &FileDescription,
    open: &mut OpenDescription,
    handle: u32,
) -> Result<(), carrick_abi::LinuxErrno> {
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        carrick_fatal!(
            "el1_delegation",
            "recall called with null EL1 region pointer (handle={handle})"
        );
    }
    // Target only vCPUs whose CurrentTask.file_table is the object's table (or that hold the file),
    // and never mark slots with no task.
    let mut target_tables = Vec::new();
    {
        let _fd_map_guard = FD_MAP_LOCK.lock();
        let fd_map_base = (region_ptr + EL1_FD_MAP_OFFSET as usize) as *const FdMapSlot;
        for slot_idx in 0..FD_MAP_CAPACITY {
            let slot = unsafe { &*fd_map_base.add(slot_idx) };
            if slot.incarnation.load(Ordering::Acquire) != 0
                && slot.handle.load(Ordering::Relaxed) == handle
            {
                let ft = slot.file_table.load(Ordering::Relaxed);
                if ft != 0 && !target_tables.contains(&ft) {
                    target_tables.push(ft);
                }
            }
        }
    }
    mark_pending_host_work_for_file_tables(&target_tables);
    description.common().record_recall();
    let rootfs_vfs = DELEGATED_ROOTFS.lock()[(handle - 1) as usize]
        .as_ref()
        .and_then(|w| w.upgrade());
    let sparse_registry = DELEGATED_SPARSE.lock()[(handle - 1) as usize].clone();

    let file_ptr = (region_ptr
        + EL1_OBJECT_TABLE_OFFSET as usize
        + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
        as *const DelegatedFile;
    let file = unsafe { &*file_ptr };
    lock_delegated_file(file, handle);
    file.state
        .store(DELEGATED_STATE_RECALLING, Ordering::Release);
    unregister_delegated_inode(handle);

    let guest_offset = file.offset.load(Ordering::Acquire);
    let guest_size = file.size.load(Ordering::Acquire);
    let dirty_mask = file.dirty_mask.swap(0, Ordering::AcqRel);
    let zero_filled_mask = file.zero_filled_mask.swap(0, Ordering::AcqRel);

    let cache_ptr = (region_ptr
        + EL1_CACHE_OFFSET as usize
        + (handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize) as *mut u8;

    let mut write_error = None;
    if dirty_mask != 0 {
        for i in 0..64 {
            if (dirty_mask & (1 << i)) != 0 {
                let page_offset = i as u64 * 4096;
                if page_offset < guest_size {
                    let page_len = std::cmp::min(4096, (guest_size - page_offset) as usize);
                    let page_slice =
                        unsafe { std::slice::from_raw_parts(cache_ptr.add(i * 4096), page_len) };
                    if let Err(err) = crate::dispatch::fs::rw::commit_bytes_at_offset(
                        open,
                        page_offset,
                        page_slice,
                        rootfs_vfs.as_deref(),
                        sparse_registry.as_ref(),
                    ) {
                        description.common().record_writeback_error(err);
                        if write_error.is_none() {
                            write_error = Some(err);
                        }
                    }
                }
            }
        }
    }

    if zero_filled_mask != 0 {
        if let OpenDescription::HostFile { host_fd, .. } = open {
            for i in 0..64 {
                if (zero_filled_mask & (1 << i)) != 0 {
                    let page_offset = i as u64 * 4096;
                    if page_offset < guest_size {
                        let punch_len = std::cmp::min(4096, guest_size - page_offset);
                        let _ = crate::dispatch::fs::rw::punch_host_file_hole(
                            host_fd.raw(),
                            page_offset,
                            punch_len,
                        );
                    }
                }
            }
        }
    }

    match open {
        OpenDescription::HostFile {
            host_fd,
            metadata,
            writable,
            ..
        } => {
            if *writable && metadata.size != guest_size as usize {
                if let Some(sparse) = &sparse_registry {
                    sparse.truncate_host_sparse_extents(host_fd.raw(), guest_size);
                }
                let trunc_res =
                    unsafe { libc::ftruncate(host_fd.raw(), guest_size as libc::off_t) };
                if trunc_res != 0 {
                    let err = crate::host_to_linux_errno(
                        std::io::Error::last_os_error()
                            .raw_os_error()
                            .unwrap_or(libc::EIO),
                    );
                    description.common().record_writeback_error(err);
                    if write_error.is_none() {
                        write_error = Some(err);
                    }
                }
            }
            let seek_res =
                unsafe { libc::lseek(host_fd.raw(), guest_offset as libc::off_t, libc::SEEK_SET) };
            if seek_res < 0 {
                let err = crate::host_to_linux_errno(
                    std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EIO),
                );
                description.common().record_writeback_error(err);
                if write_error.is_none() {
                    write_error = Some(err);
                }
            }
            metadata.size = guest_size as usize;
        }
        OpenDescription::File {
            path,
            contents,
            offset,
            metadata,
            writable,
            ..
        } => {
            if *writable && metadata.size != guest_size as usize {
                if let Err(err) = contents.resize(guest_size) {
                    description.common().record_writeback_error(err);
                    if write_error.is_none() {
                        write_error = Some(err);
                    }
                }
                if let Some(vfs) = rootfs_vfs.as_deref() {
                    if !crate::dispatch::fd_table::is_anon_overlay_path(path) {
                        if let Err(e) = vfs.write_file_range(path, 0, &[], guest_size as usize) {
                            let err = match e {
                                carrick_vfs::fs_backend::BackendError::Host(err)
                                | carrick_vfs::fs_backend::BackendError::Namespace(err) => err,
                                carrick_vfs::fs_backend::BackendError::Invalid => {
                                    carrick_abi::LINUX_EINVAL
                                }
                                carrick_vfs::fs_backend::BackendError::Unsupported => {
                                    carrick_abi::LINUX_ENOTSUP
                                }
                                carrick_vfs::fs_backend::BackendError::Io => carrick_abi::LINUX_EIO,
                            };
                            description.common().record_writeback_error(err);
                            if write_error.is_none() {
                                write_error = Some(err);
                            }
                        }
                        vfs.notify_inode_changed(path, None);
                    }
                }
            }
            *offset = guest_offset as usize;
            metadata.size = guest_size as usize;
        }
        _ => {}
    }

    {
        let _fd_map_guard = FD_MAP_LOCK.lock();
        let fd_map_base = (region_ptr + EL1_FD_MAP_OFFSET as usize) as *const FdMapSlot;
        for slot_idx in 0..FD_MAP_CAPACITY {
            let slot = unsafe { &*fd_map_base.add(slot_idx) };
            if slot.handle.load(Ordering::Acquire) == handle {
                slot.clear();
            }
        }
    }

    free_handle(handle);

    file.state.store(DELEGATED_STATE_DEAD, Ordering::Release);
    file.unlock();

    description.set_delegation_handle(0);

    if let Some(err) = write_error {
        Err(err)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::fd_table::{FileContents, HostFdRef, OpenDescriptionBase};
    use crate::kernel::objects::{FileSlot, FileTable};
    use carrick_guest_mem::GuestMemory;
    use carrick_vfs::rootfs::RootFsMetadata;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    struct TestEl1Region {
        _lock: parking_lot::MutexGuard<'static, ()>,
        buffer: Vec<u8>,
    }

    impl TestEl1Region {
        fn new() -> Self {
            let lock = TEST_LOCK.lock();
            let buffer = vec![0u8; EL1_REGION_SIZE as usize];
            record_el1_region_host_ptr(buffer.as_ptr() as usize);
            Self {
                _lock: lock,
                buffer,
            }
        }
    }

    impl Drop for TestEl1Region {
        fn drop(&mut self) {
            clear_el1_region_host_ptr();
            let mut handles = ALLOCATED_HANDLES.lock();
            *handles = [false; MAX_DELEGATED_FILES];
        }
    }

    fn test_metadata(path: impl Into<std::path::PathBuf>, size: usize) -> RootFsMetadata {
        RootFsMetadata {
            path: path.into(),
            kind: carrick_vfs::rootfs::RootFsEntryKind::File,
            mode: 0o644,
            size,
        }
    }

    fn create_test_host_file(initial_data: &[u8]) -> (NamedTempFile, OpenFile) {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(initial_data).unwrap();
        tmp.flush().unwrap();
        let raw_fd = unsafe { libc::dup(tmp.as_raw_fd()) };
        let host_fd = HostFdRef::new(raw_fd);
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        let inode = if unsafe { libc::fstat(raw_fd, &mut st) } == 0 {
            Some(carrick_vfs::InodeIdentity::new(
                st.st_dev as u64,
                st.st_ino as u64,
            ))
        } else {
            None
        };
        let mut base = OpenDescriptionBase::new(LINUX_O_RDWR);
        if let Some(inode) = inode {
            base = base.with_inode(inode);
        }
        let desc = OpenDescription::HostFile {
            base,
            host_fd,
            metadata: test_metadata(tmp.path(), initial_data.len()),
            writable: true,
        };
        let file_desc = crate::dispatch::fd_table::kernel_file_description(
            Arc::new(parking_lot::RwLock::new(desc)),
            LINUX_O_RDWR,
        );
        file_desc.common().retain_fd_ref();
        let open_file = OpenFile::new(file_desc, 0);
        (tmp, open_file)
    }

    fn create_test_in_memory_file(initial_data: &[u8]) -> OpenFile {
        let desc = OpenDescription::File {
            base: OpenDescriptionBase::new(LINUX_O_RDWR),
            path: "/test_file.txt".to_string(),
            metadata: test_metadata("/test_file.txt", initial_data.len()),
            contents: FileContents::dense(initial_data.to_vec()),
            offset: 0,
            writable: true,
        };
        let file_desc = crate::dispatch::fd_table::kernel_file_description(
            Arc::new(parking_lot::RwLock::new(desc)),
            LINUX_O_RDWR,
        );
        file_desc.common().retain_fd_ref();
        OpenFile::new(file_desc, 0)
    }

    mod serial_host {
        use super::*;

        #[test]
        fn test_eligibility_matrix() {
            let _region = TestEl1Region::new();
            let table_id = FileTableId::from_raw_u64(1).unwrap();

            // 1. Valid file delegates successfully
            let (_tmp, valid_file) = create_test_host_file(b"hello world");
            let res = delegate_for_test(&valid_file, table_id, 3);
            assert!(res.is_ok(), "expected valid file to delegate: {res:?}");
            let handle = res.unwrap();
            assert_eq!(valid_file.description.delegation_handle(), handle);
            let _ = recall(&valid_file.description);
            assert_eq!(valid_file.description.delegation_handle(), 0);

            // 2. Already delegated
            let (_tmp, file2) = create_test_host_file(b"test");
            assert!(delegate_for_test(&file2, table_id, 4).is_ok());
            assert_eq!(
                delegate_for_test(&file2, table_id, 4),
                Err(NotEligible::AlreadyDelegated)
            );
            let _ = recall(&file2.description);

            // 3. File too large (> 256 KiB)
            let large_data = vec![0xAAu8; (DELEGATED_FILE_MAX_SIZE + 1) as usize];
            let (_tmp, large_file) = create_test_host_file(&large_data);
            assert_eq!(
                delegate_for_test(&large_file, table_id, 5),
                Err(NotEligible::FileTooLarge)
            );

            // 4. Multiple references
            let (_tmp, multi_ref_file) = create_test_host_file(b"multi");
            multi_ref_file.description.common().retain_fd_ref();
            assert_eq!(
                delegate_for_test(&multi_ref_file, table_id, 6),
                Err(NotEligible::MultipleReferences)
            );
            multi_ref_file.description.common().release_fd_ref();

            // 5. Unsupported flags (O_APPEND)
            let desc_append = OpenDescription::File {
                base: OpenDescriptionBase::new(LINUX_O_RDWR | LINUX_O_APPEND),
                path: "/append.txt".to_string(),
                metadata: test_metadata("/append.txt", 10),
                contents: FileContents::dense(vec![0; 10]),
                offset: 0,
                writable: true,
            };
            let file_desc = crate::dispatch::fd_table::kernel_file_description(
                Arc::new(parking_lot::RwLock::new(desc_append)),
                LINUX_O_RDWR | LINUX_O_APPEND,
            );
            file_desc.common().retain_fd_ref();
            let append_file = OpenFile::new(file_desc, 0);
            assert_eq!(
                delegate_for_test(&append_file, table_id, 7),
                Err(NotEligible::UnsupportedFlags)
            );

            // 6. Active mapping
            let (_tmp, mapped_file) = create_test_host_file(b"mapped");
            let mapping = mapped_file.description.retain_mapping();
            assert_eq!(
                delegate_for_test(&mapped_file, table_id, 8),
                Err(NotEligible::Mapped)
            );
            drop(mapping);

            // 7. Active seccomp filter
            let (_tmp, seccomp_file) = create_test_host_file(b"seccomp");
            let seccomp_state = crate::seccomp::SeccompState::default();
            seccomp_state.install_strict();
            assert_eq!(
                delegate_for_test_with_policy(
                    &seccomp_file,
                    table_id,
                    9,
                    DelegationPolicy {
                        seccomp: Some(&seccomp_state),
                        observers: None,
                        interceptors_active: false,
                    }
                ),
                Err(NotEligible::SeccompFiltered)
            );

            // 8. Observer monitoring write (64)
            let (_tmp, obs_file) = create_test_host_file(b"observer");
            let policy_obs = Arc::new(
                crate::observe::PolicyObserver::new()
                    .deny(carrick_abi::CanonicalNr(64), carrick_abi::LINUX_EPERM),
            );
            let chain = crate::observe::ObserverChain::new(None, vec![policy_obs]);
            assert_eq!(
                delegate_for_test_with_policy(
                    &obs_file,
                    table_id,
                    10,
                    DelegationPolicy {
                        seccomp: None,
                        observers: Some(&chain),
                        interceptors_active: false,
                    }
                ),
                Err(NotEligible::Observed)
            );

            // 9. Docker default ContainerPolicy allows delegation
            let (_tmp, docker_file) = create_test_host_file(b"docker");
            let docker_policy = crate::container_policy::ContainerPolicy::docker_default_model();
            let docker_chain = crate::observe::ObserverChain::new(Some(docker_policy), vec![]);
            let docker_res = delegate_for_test_with_policy(
                &docker_file,
                table_id,
                11,
                DelegationPolicy {
                    seccomp: None,
                    observers: Some(&docker_chain),
                    interceptors_active: false,
                },
            );
            assert!(
                docker_res.is_ok(),
                "Docker default ContainerPolicy should allow delegation: {docker_res:?}"
            );
            let _ = recall(&docker_file.description);

            // 10. Memfd with F_SEAL_WRITE
            let (_tmp, sealed_write_file) = create_test_host_file(b"sealed_write");
            sealed_write_file
                .description
                .common()
                .set_seals(Some(carrick_abi::LinuxMemfdSeals::WRITE.bits()));
            assert_eq!(
                delegate_for_test(&sealed_write_file, table_id, 12),
                Err(NotEligible::Sealed)
            );

            // 11. Memfd with F_SEAL_GROW
            let (_tmp, sealed_grow_file) = create_test_host_file(b"sealed_grow");
            sealed_grow_file
                .description
                .common()
                .set_seals(Some(carrick_abi::LinuxMemfdSeals::GROW.bits()));
            assert_eq!(
                delegate_for_test(&sealed_grow_file, table_id, 13),
                Err(NotEligible::Sealed)
            );

            // 12. Unsealed memfd (ALLOW_SEALING with empty seal set)
            let (_tmp, unsealed_file) = create_test_host_file(b"unsealed");
            unsealed_file.description.common().set_seals(Some(0));
            let unsealed_res = delegate_for_test(&unsealed_file, table_id, 14);
            assert!(
                unsealed_res.is_ok(),
                "Unsealed memfd should delegate: {unsealed_res:?}"
            );
            let _ = recall(&unsealed_file.description);
        }

        #[test]
        fn test_recall_host_file_round_trip() {
            let region = TestEl1Region::new();
            let table_id = FileTableId::from_raw_u64(1).unwrap();
            let (_tmp, host_file) = create_test_host_file(b"initial data");

            let handle = delegate_for_test(&host_file, table_id, 3).expect("delegate");
            assert_eq!(host_file.description.delegation_handle(), handle);

            // Simulate guest writing 5 bytes at offset 12 (extending file to 17 bytes)
            let region_ptr = region.buffer.as_ptr() as usize;
            let file_ptr = (region_ptr
                + EL1_OBJECT_TABLE_OFFSET as usize
                + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
                as *const DelegatedFile;
            let file = unsafe { &*file_ptr };
            let cache_ptr = (region_ptr
                + EL1_CACHE_OFFSET as usize
                + (handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize)
                as *mut u8;

            unsafe {
                let write_slice = std::slice::from_raw_parts_mut(cache_ptr.add(12), 5);
                write_slice.copy_from_slice(b"world");
            }
            file.offset.store(17, Ordering::Release);
            file.size.store(17, Ordering::Release);
            file.dirty_mask.store(1, Ordering::Release); // page 0 dirty

            // Recall back to host
            let _ = recall(&host_file.description);
            assert_eq!(host_file.description.delegation_handle(), 0);

            // Verify host file contents, size, and offset
            let mut buf = [0u8; 17];
            let open_desc = host_file.description.open_description().unwrap().read();
            let OpenDescription::HostFile {
                host_fd, metadata, ..
            } = &*open_desc
            else {
                panic!("expected HostFile");
            };
            assert_eq!(metadata.size, 17);
            let n =
                unsafe { libc::pread(host_fd.raw(), buf.as_mut_ptr() as *mut libc::c_void, 17, 0) };
            assert_eq!(n, 17);
            assert_eq!(&buf, b"initial dataworld");
            let cur_offset = unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_CUR) };
            assert_eq!(cur_offset, 17);
        }

        #[test]
        fn test_recall_in_memory_file_round_trip() {
            let region = TestEl1Region::new();
            let table_id = FileTableId::from_raw_u64(1).unwrap();
            let mem_file = create_test_in_memory_file(b"in-memory data");

            let handle = delegate_for_test(&mem_file, table_id, 3).expect("delegate");
            assert_eq!(mem_file.description.delegation_handle(), handle);

            // Simulate guest writing 6 bytes at offset 14
            let region_ptr = region.buffer.as_ptr() as usize;
            let file_ptr = (region_ptr
                + EL1_OBJECT_TABLE_OFFSET as usize
                + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
                as *const DelegatedFile;
            let file = unsafe { &*file_ptr };
            let cache_ptr = (region_ptr
                + EL1_CACHE_OFFSET as usize
                + (handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize)
                as *mut u8;

            unsafe {
                let write_slice = std::slice::from_raw_parts_mut(cache_ptr.add(14), 6);
                write_slice.copy_from_slice(b"-extra");
            }
            file.offset.store(20, Ordering::Release);
            file.size.store(20, Ordering::Release);
            file.dirty_mask.store(1, Ordering::Release);

            // Recall back to host
            let _ = recall(&mem_file.description);
            assert_eq!(mem_file.description.delegation_handle(), 0);

            let open_desc = mem_file.description.open_description().unwrap().read();
            let OpenDescription::File {
                contents,
                offset,
                metadata,
                ..
            } = &*open_desc
            else {
                panic!("expected File");
            };
            assert_eq!(*offset, 20);
            assert_eq!(metadata.size, 20);
            let mut buf = [0u8; 20];
            contents.read_at(0, &mut buf).unwrap();
            assert_eq!(&buf, b"in-memory data-extra");
        }

        #[test]
        fn test_description_guard_recalls() {
            let _region = TestEl1Region::new();
            let table_id = FileTableId::from_raw_u64(1).unwrap();
            let (_tmp, host_file) = create_test_host_file(b"test guard");

            assert!(delegate_for_test(&host_file, table_id, 3).is_ok());
            assert_ne!(host_file.description.delegation_handle(), 0);

            // Touching description.read() automatically recalls
            let guard = host_file.description.read().unwrap();
            assert_eq!(host_file.description.delegation_handle(), 0);
            drop(guard);

            // Re-delegate
            assert!(delegate_for_test(&host_file, table_id, 3).is_ok());
            assert_ne!(host_file.description.delegation_handle(), 0);

            // Touching description.write() automatically recalls
            let guard = host_file.description.write().unwrap();
            assert_eq!(host_file.description.delegation_handle(), 0);
            drop(guard);
        }

        #[test]
        fn test_fork_recalls() {
            let _region = TestEl1Region::new();
            let parent_table_id = FileTableId::from_raw_u64(1).unwrap();
            let child_table_id = FileTableId::from_raw_u64(2).unwrap();
            let (_tmp, host_file) = create_test_host_file(b"fork test");

            let parent_table = Arc::new(FileTable::new(parent_table_id));
            let reservation = parent_table.reserve_exact_target(3, 1024).unwrap();
            let slot = FileSlot::new(Arc::clone(&host_file.description), 0);
            reservation.commit(slot).unwrap();

            assert!(delegate_for_test(&host_file, parent_table_id, 3).is_ok());
            assert_ne!(host_file.description.delegation_handle(), 0);

            // Fork copies file table
            let child_table = FileTable::for_fork_copy(child_table_id, &parent_table);
            assert_eq!(
                host_file.description.delegation_handle(),
                0,
                "fork must recall delegated description"
            );
            drop(child_table);
        }

        #[test]
        fn test_dup_recalls() {
            let _region = TestEl1Region::new();
            let table_id = FileTableId::from_raw_u64(1).unwrap();
            let (_tmp, host_file) = create_test_host_file(b"dup test");

            assert!(delegate_for_test(&host_file, table_id, 3).is_ok());
            assert_ne!(host_file.description.delegation_handle(), 0);

            // Calling retain_fd_ref (e.g. from dup) recalls the description
            host_file.description.retain_fd_ref();
            assert_eq!(
                host_file.description.delegation_handle(),
                0,
                "dup must recall delegated description"
            );
            host_file.description.release_fd_ref();
        }

        #[test]
        fn test_host_write_interleaved_with_delegate_race() {
            let _region = TestEl1Region::new();
            let (_tmp, host_file) = create_test_host_file(b"");
            let mut dispatcher = crate::dispatch::SyscallDispatcher::new();

            let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
                1,
                crate::thread::ThreadId::synthetic_for_tests(1),
                "test-write-race".to_owned(),
            )
            .expect("root bootstrap");
            let ctx = crate::kernel::Kernel::bootstrap_root(bootstrap)
                .expect("root kernel")
                .1;
            let table = ctx.task().leader_file_table().unwrap();
            let reservation = table.reserve_exact_target(3, 1024).unwrap();
            let slot = FileSlot::new(Arc::clone(&host_file.description), 0);
            reservation.commit(slot).unwrap();
            assert_eq!(host_file.description.common().fd_refs(), 1);
            let fd = 3;
            let table_id = table.id();

            let (in_hook_tx, in_hook_rx) = std::sync::mpsc::channel();
            let (continue_tx, continue_rx) = std::sync::mpsc::channel();
            let continue_rx = Arc::new(parking_lot::Mutex::new(continue_rx));

            let continue_rx_clone = Arc::clone(&continue_rx);
            dispatcher.set_before_host_write_test_hook(Some(Arc::new(move || {
                let _ = in_hook_tx.send(());
                let _ = continue_rx_clone.lock().recv();
            })));

            let thread2 = std::thread::spawn(move || {
                let reporter = carrick_observability::compat::CompatReporter::default();
                let mut mem = crate::dispatch::LinearMemory::new(0x10000, b"thread2 data".to_vec());
                let tid = crate::thread::ThreadId::from_guest_supplied_tid(1);
                let registry = crate::thread::ThreadRegistry::new(tid);
                let futex = crate::thread::FutexTable::new();
                let req = crate::dispatch::SyscallRequest::new(
                    64, // SYS_write
                    crate::dispatch::SyscallArgs([fd as u64, 0x10000, 12, 0, 0, 0]),
                );
                dispatcher
                    .dispatch_threaded(
                        &ctx,
                        req,
                        &mut mem,
                        &reporter,
                        crate::dispatch::ThreadCtx::new(tid, &registry, &futex),
                    )
                    .expect("dispatch write")
            });

            // Wait for thread 2 to reach the hook
            in_hook_rx.recv().unwrap();

            // While thread 2 is paused in the hook, verify write lock is held by thread 2!
            let desc = host_file.description.open_description().unwrap();
            assert!(
                desc.try_write().is_none(),
                "write lock must be held across host write"
            );

            // Thread 1 attempts to delegate concurrently while thread 2 is in the hook.
            // It must block until thread 2 finishes its write under the lock discipline.
            let host_file_clone = host_file.clone();
            let (thread1_started_tx, thread1_started_rx) = std::sync::mpsc::channel();
            let thread1 = std::thread::spawn(move || {
                let _ = thread1_started_tx.send(());
                delegate_for_test(&host_file_clone, table_id, fd)
            });
            thread1_started_rx.recv().unwrap();
            // Brief pause to ensure thread 1 has contested the lock
            std::thread::sleep(std::time::Duration::from_millis(20));

            // Resume thread 2
            continue_tx.send(()).unwrap();
            let outcome = thread2.join().unwrap();
            assert_eq!(
                outcome,
                crate::dispatch::DispatchOutcome::Returned { value: 12 }
            );

            let delegate_res = thread1.join().unwrap();
            eprintln!("delegate_res = {:?}", delegate_res);

            // Recall to verify writeback / offset integrity
            let _ = recall(&host_file.description);

            // Check host file size and content
            let open_desc = host_file.description.open_description().unwrap().read();
            let OpenDescription::HostFile { host_fd, .. } = &*open_desc else {
                panic!("HostFile");
            };
            let mut buf = [0u8; 12];
            let n =
                unsafe { libc::pread(host_fd.raw(), buf.as_mut_ptr() as *mut libc::c_void, 12, 0) };
            assert_eq!(n, 12, "thread 2 bytes were lost/truncated!");
            assert_eq!(&buf, b"thread2 data");
        }

        fn open_path_for_test(
            dispatcher: &crate::dispatch::SyscallDispatcher,
            ctx: &crate::kernel::KernelContext,
            path: &str,
            flags: u64,
        ) -> i32 {
            let reporter = carrick_observability::compat::CompatReporter::default();
            let outcome = dispatcher
                .open_at_path_string(
                    ctx,
                    None,
                    crate::dispatch::fs::OpenAtArgs {
                        dirfd: carrick_abi::LINUX_AT_FDCWD as u64,
                        path,
                        flags,
                        mode: 0o644,
                    },
                    &reporter,
                )
                .expect("open_at_path_string");
            match outcome {
                crate::dispatch::DispatchOutcome::Returned { value } => value as i32,
                other => panic!("expected returned fd, got {other:?}"),
            }
        }

        #[test]
        fn test_open_while_delegated_sees_current_bytes() {
            let _region = TestEl1Region::new();
            let scratch = tempfile::tempdir().unwrap();
            let file_path = scratch.path().join("test_b3_open.txt");
            std::fs::write(&file_path, b"initial bytes").unwrap();

            let backend =
                carrick_vfs::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
            let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
            dispatcher.set_fs_backend(Box::new(backend));

            let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
                1,
                crate::thread::ThreadId::synthetic_for_tests(1),
                "test-open-delegated".to_owned(),
            )
            .expect("root bootstrap");
            let ctx = crate::kernel::Kernel::bootstrap_root(bootstrap)
                .expect("root kernel")
                .1;
            let table = ctx.task().leader_file_table().unwrap();
            let table_id = table.id();

            let fd_a = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_b3_open.txt",
                carrick_abi::LINUX_O_RDWR,
            );

            let open_file_a = dispatcher.open_file(fd_a).expect("open_file A");
            let handle = delegate(&open_file_a, table_id, fd_a, dispatcher.fs(), None, None)
                .expect("delegate A");
            assert_eq!(open_file_a.description.delegation_handle(), handle);

            // Simulate EL1 modifying the file in the EL1 cache:
            let region_ptr = get_el1_region_host_ptr();
            let cache_ptr = (region_ptr
                + EL1_CACHE_OFFSET as usize
                + (handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize)
                as *mut u8;
            let file_ptr = (region_ptr
                + EL1_OBJECT_TABLE_OFFSET as usize
                + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
                as *const DelegatedFile;
            let file = unsafe { &*file_ptr };

            let updated_data = b"updated content in el1";
            unsafe {
                std::ptr::copy_nonoverlapping(updated_data.as_ptr(), cache_ptr, updated_data.len());
            }
            file.size
                .store(updated_data.len() as u64, Ordering::Release);
            file.dirty_mask.store(1, Ordering::Release);

            // Process B opens the same path
            let fd_b = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_b3_open.txt",
                carrick_abi::LINUX_O_RDONLY,
            );

            // Process A must be recalled by Process B's open!
            assert_eq!(
                open_file_a.description.delegation_handle(),
                0,
                "Process A must be recalled when Process B opens the file"
            );

            // Process B reads the file and sees updated content
            let open_file_b = dispatcher.open_file(fd_b).expect("open_file B");
            let guard_b = open_file_b.description.read().expect("read guard B");
            let OpenDescription::HostFile {
                host_fd, metadata, ..
            } = &*guard_b
            else {
                panic!("expected HostFile for B");
            };
            assert_eq!(metadata.size, updated_data.len());
            let mut buf = vec![0u8; updated_data.len()];
            let n = unsafe {
                libc::pread(
                    host_fd.raw(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            assert_eq!(n, updated_data.len() as isize);
            assert_eq!(&buf, updated_data);
        }

        #[test]
        fn test_stat_while_delegated_sees_current_size() {
            let _region = TestEl1Region::new();
            let scratch = tempfile::tempdir().unwrap();
            let file_path = scratch.path().join("test_b3_stat.txt");
            std::fs::write(&file_path, b"1234567890").unwrap();

            let backend =
                carrick_vfs::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
            let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
            dispatcher.set_fs_backend(Box::new(backend));

            let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
                1,
                crate::thread::ThreadId::synthetic_for_tests(1),
                "test-stat-delegated".to_owned(),
            )
            .expect("root bootstrap");
            let ctx = crate::kernel::Kernel::bootstrap_root(bootstrap)
                .expect("root kernel")
                .1;
            let table = ctx.task().leader_file_table().unwrap();
            let table_id = table.id();

            let fd_a = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_b3_stat.txt",
                carrick_abi::LINUX_O_RDWR,
            );

            let open_file_a = dispatcher.open_file(fd_a).expect("open_file A");
            let handle = delegate(&open_file_a, table_id, fd_a, dispatcher.fs(), None, None)
                .expect("delegate A");

            // Simulate EL1 extending the file size to 1000 bytes
            let region_ptr = get_el1_region_host_ptr();
            let file_ptr = (region_ptr
                + EL1_OBJECT_TABLE_OFFSET as usize
                + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
                as *const DelegatedFile;
            let file = unsafe { &*file_ptr };
            file.size.store(1000, Ordering::Release);
            file.dirty_mask.store(1, Ordering::Release);

            // Process B stats the file by path
            let stat_rec = dispatcher
                .path_stat_record(
                    &ctx,
                    carrick_abi::LINUX_AT_FDCWD as u64,
                    "/test_b3_stat.txt",
                    0,
                )
                .expect("path_stat_record");

            assert_eq!(
                open_file_a.description.delegation_handle(),
                0,
                "Process A must be recalled when Process B stats the file"
            );
            assert_eq!(stat_rec.size, 1000, "stat must see extended size from EL1");
        }

        #[test]
        fn test_fstat_on_delegated_host_fd_recalls_and_sees_current_size() {
            let _region = TestEl1Region::new();
            let scratch = tempfile::tempdir().unwrap();
            let file_path = scratch.path().join("test_fstat.txt");
            std::fs::write(&file_path, b"1234567890").unwrap();

            let backend =
                carrick_vfs::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
            let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
            dispatcher.set_fs_backend(Box::new(backend));

            let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
                1,
                crate::thread::ThreadId::synthetic_for_tests(1),
                "test-fstat-delegated".to_owned(),
            )
            .expect("root bootstrap");
            let ctx = crate::kernel::Kernel::bootstrap_root(bootstrap)
                .expect("root kernel")
                .1;
            let table = ctx.task().leader_file_table().unwrap();
            let table_id = table.id();

            let fd_a = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_fstat.txt",
                carrick_abi::LINUX_O_RDWR,
            );

            let open_file_a = dispatcher.open_file(fd_a).expect("open_file A");
            let handle = delegate(&open_file_a, table_id, fd_a, dispatcher.fs(), None, None)
                .expect("delegate A");

            // Simulate EL1 extending the file size to 1000 bytes
            let region_ptr = get_el1_region_host_ptr();
            let file_ptr = (region_ptr
                + EL1_OBJECT_TABLE_OFFSET as usize
                + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
                as *const DelegatedFile;
            let file = unsafe { &*file_ptr };
            file.size.store(1000, Ordering::Release);
            file.dirty_mask.store(1, Ordering::Release);

            // Calling fstat on fd_a must recall the delegated file and report the updated size
            let stat_rec = dispatcher.fd_stat_record(fd_a).expect("fd_stat_record");

            assert_eq!(
                open_file_a.description.delegation_handle(),
                0,
                "fd_a must be recalled when fstat is called"
            );
            assert_eq!(stat_rec.size, 1000, "fstat must see extended size from EL1");
        }

        #[test]
        fn test_pq_handle_reuse_cache_pages_zeroed() {
            let _region = TestEl1Region::new();
            let scratch = tempfile::tempdir().unwrap();

            let backend =
                carrick_vfs::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
            let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
            dispatcher.set_fs_backend(Box::new(backend));

            let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
                1,
                crate::thread::ThreadId::synthetic_for_tests(1),
                "test-pq-zero".to_owned(),
            )
            .expect("root bootstrap");
            let ctx = crate::kernel::Kernel::bootstrap_root(bootstrap)
                .expect("root kernel")
                .1;
            let table = ctx.task().leader_file_table().unwrap();
            let table_id = table.id();

            // 1. Create file P (100 KiB) with 0xAA
            let file_p_path = scratch.path().join("file_p.txt");
            let p_data = vec![0xAAu8; 100 * 1024];
            std::fs::write(&file_p_path, &p_data).unwrap();

            let fd_p =
                open_path_for_test(&dispatcher, &ctx, "/file_p.txt", carrick_abi::LINUX_O_RDWR);
            let open_p = dispatcher.open_file(fd_p).unwrap();
            let handle_p = delegate(&open_p, table_id, fd_p, dispatcher.fs(), None, None).unwrap();
            assert_eq!(handle_p, 1);

            // Recall P -> frees handle 1
            let _ = recall(&open_p.description);
            assert_eq!(open_p.description.delegation_handle(), 0);

            // 2. Create file Q (10 bytes) with 0xBB
            let file_q_path = scratch.path().join("file_q.txt");
            let q_data = vec![0xBBu8; 10];
            std::fs::write(&file_q_path, &q_data).unwrap();

            let fd_q =
                open_path_for_test(&dispatcher, &ctx, "/file_q.txt", carrick_abi::LINUX_O_RDWR);
            let open_q = dispatcher.open_file(fd_q).unwrap();
            let handle_q = delegate(&open_q, table_id, fd_q, dispatcher.fs(), None, None).unwrap();
            assert_eq!(handle_q, 1, "Handle 1 should be reused");

            let region_ptr = get_el1_region_host_ptr();
            let cache_ptr = (region_ptr
                + EL1_CACHE_OFFSET as usize
                + (handle_q as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize)
                as *mut u8;

            // Verify cache beyond 10 bytes is zeroed!
            for i in 10..8000 {
                assert_eq!(
                    unsafe { *cache_ptr.add(i) },
                    0,
                    "offset {i} in reused handle cache was not zeroed upon delegate"
                );
            }
        }

        fn fsync_for_test(
            dispatcher: &mut crate::dispatch::SyscallDispatcher,
            fd: i32,
        ) -> Result<i64, carrick_abi::LinuxErrno> {
            let mut memory = crate::dispatch::LinearMemory::new(0x1000, vec![0; 0x1000]);
            let reporter = carrick_observability::compat::CompatReporter::default();
            let outcome = dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    crate::dispatch::request::SyscallRequest::new(
                        carrick_abi::syscall::nr::FSYNC.0,
                        carrick_observability::compat::SyscallArgs([fd as u64, 0, 0, 0, 0, 0]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            match outcome {
                crate::dispatch::DispatchOutcome::Returned { value } => Ok(value),
                crate::dispatch::DispatchOutcome::Errno { errno } => Err(errno),
                other => panic!("unexpected outcome: {:?}", other),
            }
        }

        fn close_for_test(
            dispatcher: &mut crate::dispatch::SyscallDispatcher,
            fd: i32,
        ) -> Result<i64, carrick_abi::LinuxErrno> {
            let mut memory = crate::dispatch::LinearMemory::new(0x1000, vec![0; 0x1000]);
            let reporter = carrick_observability::compat::CompatReporter::default();
            let outcome = dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    crate::dispatch::request::SyscallRequest::new(
                        carrick_abi::syscall::nr::CLOSE.0,
                        carrick_observability::compat::SyscallArgs([fd as u64, 0, 0, 0, 0, 0]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            match outcome {
                crate::dispatch::DispatchOutcome::Returned { value } => Ok(value),
                crate::dispatch::DispatchOutcome::Errno { errno } => Err(errno),
                other => panic!("unexpected outcome: {:?}", other),
            }
        }

        #[test]
        fn test_el1_writeback_memory_backend_and_enospc_fsync() {
            let _region = TestEl1Region::new();
            let mut dispatcher = crate::dispatch::SyscallDispatcher::new();

            let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
                1,
                crate::thread::ThreadId::synthetic_for_tests(1),
                "test-inmem-writeback".to_owned(),
            )
            .expect("root bootstrap");
            let ctx = crate::kernel::Kernel::bootstrap_root(bootstrap)
                .expect("root kernel")
                .1;
            let table = ctx.task().leader_file_table().unwrap();
            let table_id = table.id();

            // 1. Create and open an in-memory file on rootfs
            let fd = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_inmem_wb.txt",
                carrick_abi::LINUX_O_CREAT | carrick_abi::LINUX_O_RDWR,
            );
            let open_file = dispatcher.open_file(fd).unwrap();
            let handle = delegate(&open_file, table_id, fd, dispatcher.fs(), None, None).unwrap();
            assert_eq!(handle, 1);

            // Simulate EL1 write
            let region_ptr = get_el1_region_host_ptr();
            let cache_ptr = (region_ptr
                + EL1_CACHE_OFFSET as usize
                + (handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize)
                as *mut u8;
            let file_ptr = (region_ptr
                + EL1_OBJECT_TABLE_OFFSET as usize
                + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
                as *const DelegatedFile;
            let file = unsafe { &*file_ptr };

            let el1_data = b"el1 memory backend write";
            unsafe {
                std::ptr::copy_nonoverlapping(el1_data.as_ptr(), cache_ptr, el1_data.len());
            }
            file.size.store(el1_data.len() as u64, Ordering::Release);
            file.dirty_mask.store(1, Ordering::Release);

            // Close the file (calls recall_if_delegated)
            close_for_test(&mut dispatcher, fd).unwrap();
            assert_eq!(open_file.description.delegation_handle(), 0);

            // Reopen the path: bytes must be current!
            let fd_reopened = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_inmem_wb.txt",
                carrick_abi::LINUX_O_RDONLY,
            );
            let open_reopened = dispatcher.open_file(fd_reopened).unwrap();
            let guard = open_reopened.description.read().unwrap();
            let OpenDescription::File { contents, .. } = &*guard else {
                panic!("expected File");
            };
            let mut read_buf = vec![0u8; el1_data.len()];
            let n = contents.read_at(0, &mut read_buf).unwrap();
            assert_eq!(n, el1_data.len());
            assert_eq!(
                &read_buf, el1_data,
                "reopened file must see EL1 written bytes"
            );
            drop(guard);

            let entry = dispatcher
                .fs()
                .rootfs_vfs
                .overlay
                .lookup("/test_inmem_wb.txt");
            assert_eq!(
                entry,
                Some(carrick_vfs::fs_backend::OverlayEntry::File(
                    el1_data.to_vec()
                )),
                "overlay backend must have updated bytes from write-back"
            );

            // 2. Test ENOSPC injection reports at fsync
            open_reopened
                .description
                .common()
                .record_writeback_error(carrick_abi::LINUX_ENOSPC);
            let sync_res = fsync_for_test(&mut dispatcher, fd_reopened);
            assert_eq!(sync_res, Err(carrick_abi::LINUX_ENOSPC));
        }

        #[test]
        fn test_recall_on_f_add_seals_and_f_setfl() {
            let _region = TestEl1Region::new();
            let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
            let ctx = dispatcher.capture_one_task_context().unwrap();
            let table = ctx.task().leader_file_table().unwrap();
            let table_id = table.id();

            // 1. Memfd delegation and recall on F_ADD_SEALS
            let fd = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_memfd_seal.txt",
                carrick_abi::LINUX_O_CREAT | carrick_abi::LINUX_O_RDWR,
            );
            let open_file = dispatcher.open_file(fd).unwrap();
            open_file.description.common().set_seals(Some(0)); // sealable
            let handle = delegate(&open_file, table_id, fd, dispatcher.fs(), None, None).unwrap();
            assert_eq!(handle, 1);
            assert_eq!(open_file.description.delegation_handle(), 1);

            // Call F_ADD_SEALS (via fcntl)
            let mut memory = crate::dispatch::LinearMemory::new(0, vec![0; 0x2000]);
            let reporter = carrick_observability::compat::CompatReporter::default();
            let outcome = dispatcher
                .dispatch(
                    &ctx,
                    crate::dispatch::request::SyscallRequest::new(
                        carrick_abi::syscall::nr::FCNTL.0,
                        carrick_observability::compat::SyscallArgs([
                            fd as u64,
                            carrick_abi::LINUX_F_ADD_SEALS as u64,
                            carrick_abi::LinuxMemfdSeals::WRITE.bits() as u64,
                            0,
                            0,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            assert!(matches!(
                outcome,
                crate::dispatch::DispatchOutcome::Returned { value: 0 }
            ));
            assert_eq!(
                open_file.description.delegation_handle(),
                0,
                "F_ADD_SEALS must recall delegated file"
            );

            // Re-delegation must be rejected as Sealed
            let re_delegate = delegate(&open_file, table_id, fd, dispatcher.fs(), None, None);
            assert!(
                matches!(re_delegate, Err(NotEligible::Sealed)),
                "re-delegation after F_ADD_SEALS must be rejected as Sealed: {re_delegate:?}"
            );

            // 2. File delegation and recall on F_SETFL
            let fd2 = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_fsetfl.txt",
                carrick_abi::LINUX_O_CREAT | carrick_abi::LINUX_O_RDWR,
            );
            let open_file2 = dispatcher.open_file(fd2).unwrap();
            let handle2 =
                delegate(&open_file2, table_id, fd2, dispatcher.fs(), None, None).unwrap();
            assert_eq!(handle2, 1);
            assert_eq!(open_file2.description.delegation_handle(), 1);

            let outcome2 = dispatcher
                .dispatch(
                    &ctx,
                    crate::dispatch::request::SyscallRequest::new(
                        carrick_abi::syscall::nr::FCNTL.0,
                        carrick_observability::compat::SyscallArgs([
                            fd2 as u64,
                            carrick_abi::LINUX_F_SETFL as u64,
                            carrick_abi::LINUX_O_APPEND as u64,
                            0,
                            0,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            assert!(matches!(
                outcome2,
                crate::dispatch::DispatchOutcome::Returned { value: 0 }
            ));
            assert_eq!(
                open_file2.description.delegation_handle(),
                0,
                "F_SETFL must recall delegated file"
            );
        }

        #[test]
        fn test_recall_on_rlimit_fsize_and_seccomp() {
            let _region = TestEl1Region::new();
            let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
            let ctx = dispatcher.capture_one_task_context().unwrap();
            let table = ctx.task().leader_file_table().unwrap();
            let table_id = table.id();

            // 1. File delegated, then prlimit64(RLIMIT_FSIZE)
            let fd = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_rlimit.txt",
                carrick_abi::LINUX_O_CREAT | carrick_abi::LINUX_O_RDWR,
            );
            let open_file = dispatcher.open_file(fd).unwrap();
            let handle = delegate(&open_file, table_id, fd, dispatcher.fs(), None, None).unwrap();
            assert_eq!(handle, 1);

            let mut memory = crate::dispatch::LinearMemory::new(0, vec![0; 0x2000]);
            let reporter = carrick_observability::compat::CompatReporter::default();
            // new limit at 0x1000: rlim_cur = 500, rlim_max = 500
            let rlimit_bytes = [500u64.to_le_bytes(), 500u64.to_le_bytes()].concat();
            memory.write_bytes(0x1000, &rlimit_bytes).unwrap();

            let outcome = dispatcher
                .dispatch(
                    &ctx,
                    crate::dispatch::request::SyscallRequest::new(
                        carrick_abi::syscall::nr::PRLIMIT64.0,
                        carrick_observability::compat::SyscallArgs([
                            0, // self
                            carrick_abi::LinuxResource::Fsize as u64,
                            0x1000,
                            0,
                            0,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            assert!(matches!(
                outcome,
                crate::dispatch::DispatchOutcome::Returned { value: 0 }
            ));
            assert_eq!(
                open_file.description.delegation_handle(),
                0,
                "RLIMIT_FSIZE must recall delegated file"
            );

            // Verify that subsequent write at or past the new RLIMIT_FSIZE is enforced by host
            let lseek_outcome = dispatcher
                .dispatch(
                    &ctx,
                    crate::dispatch::request::SyscallRequest::new(
                        carrick_abi::syscall::nr::LSEEK.0,
                        carrick_observability::compat::SyscallArgs([
                            fd as u64,
                            500,
                            carrick_abi::LINUX_SEEK_SET as u64,
                            0,
                            0,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            assert!(matches!(
                lseek_outcome,
                crate::dispatch::DispatchOutcome::Returned { value: 500 }
            ));

            let write_outcome = dispatcher
                .dispatch(
                    &ctx,
                    crate::dispatch::request::SyscallRequest::new(
                        carrick_abi::syscall::nr::WRITE.0,
                        carrick_observability::compat::SyscallArgs([
                            fd as u64, 0x1000, 10, 0, 0, 0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            assert_eq!(
                write_outcome,
                crate::dispatch::DispatchOutcome::errno(carrick_abi::LINUX_EFBIG),
                "write at or past RLIMIT_FSIZE must return EFBIG after recall"
            );

            // Verify that subsequent attempt to delegate fails with NotEligible::FsizeLimited
            let err = delegate(
                &open_file,
                table_id,
                fd,
                dispatcher.fs(),
                Some(&ctx.task().rlimits()),
                None,
            )
            .unwrap_err();
            assert_eq!(err, NotEligible::FsizeLimited);

            // 2. File delegated, then seccomp STRICT
            let fd2 = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_seccomp_strict.txt",
                carrick_abi::LINUX_O_CREAT | carrick_abi::LINUX_O_RDWR,
            );
            let open_file2 = dispatcher.open_file(fd2).unwrap();
            let handle2 =
                delegate(&open_file2, table_id, fd2, dispatcher.fs(), None, None).unwrap();
            assert_eq!(handle2, 1);

            let outcome2 = dispatcher
                .dispatch(
                    &ctx,
                    crate::dispatch::request::SyscallRequest::new(
                        carrick_abi::syscall::nr::SECCOMP.0,
                        carrick_observability::compat::SyscallArgs([
                            crate::seccomp::SECCOMP_SET_MODE_STRICT as u64,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            assert!(matches!(
                outcome2,
                crate::dispatch::DispatchOutcome::Returned { value: 0 }
            ));
            assert_eq!(
                open_file2.description.delegation_handle(),
                0,
                "seccomp must recall delegated file"
            );
        }

        #[test]
        fn test_writeback_error_isolated_to_affected_description() {
            let region = TestEl1Region::new();
            let table_id = FileTableId::from_raw_u64(1).unwrap();
            let mem_file = create_test_in_memory_file(b"initial");

            let handle = delegate_for_test(&mem_file, table_id, 3).expect("delegate");

            let region_ptr = region.buffer.as_ptr() as usize;
            let file_ptr = (region_ptr
                + EL1_OBJECT_TABLE_OFFSET as usize
                + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
                as *const DelegatedFile;
            let file = unsafe { &*file_ptr };

            // Mark a page dirty and set writable to false so commit_bytes_at_offset fails on recall
            file.offset.store(10, Ordering::Release);
            file.size.store(10, Ordering::Release);
            file.dirty_mask.store(1, Ordering::Release);

            {
                let mut guard = mem_file.description.open_description().unwrap().write();
                if let OpenDescription::File { writable, .. } = &mut *guard {
                    *writable = false;
                }
            }

            let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
            let ctx = dispatcher.capture_one_task_context().unwrap();

            // Now prlimit64(RLIMIT_FSIZE) recalls all delegated files.
            // It MUST NOT return EBADF to the caller of prlimit64!
            let mut memory = crate::dispatch::LinearMemory::new(0, vec![0; 0x2000]);
            let reporter = carrick_observability::compat::CompatReporter::default();
            let rlimit_bytes = [1000u64.to_le_bytes(), 1000u64.to_le_bytes()].concat();
            memory.write_bytes(0x1000, &rlimit_bytes).unwrap();

            let outcome = dispatcher
                .dispatch(
                    &ctx,
                    crate::dispatch::request::SyscallRequest::new(
                        carrick_abi::syscall::nr::PRLIMIT64.0,
                        carrick_observability::compat::SyscallArgs([
                            0, // self
                            carrick_abi::LinuxResource::Fsize as u64,
                            0x1000,
                            0,
                            0,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            // Before fix: outcome was Err(EBADF). After fix: outcome is Returned { value: 0 }.
            assert_eq!(
                outcome,
                crate::dispatch::DispatchOutcome::Returned { value: 0 }
            );

            // And the error is stored sticky on the affected description only!
            assert_eq!(
                mem_file.description.common().take_writeback_error(),
                Some(carrick_abi::LINUX_EBADF)
            );
        }

        #[test]
        fn test_republish_file_table_on_unshare_and_close_range() {
            let _region = TestEl1Region::new();
            let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
            let ctx = dispatcher.capture_one_task_context().unwrap();
            let table = ctx.task().leader_file_table().unwrap();
            let old_table_id = table.id().raw();
            let tid = El1TaskId::from_linux_tid(ctx.thread().key().tid.raw());

            // Publish current task for vCPU slot 0
            publish_current_task(0, tid, 1, old_table_id);

            let ptr = get_el1_region_host_ptr();
            let current_task = unsafe {
                let offset = EL1_CURRENT_TASKS_OFFSET as usize;
                &*((ptr + offset) as *const CurrentTask)
            };
            assert_eq!(
                current_task.file_table.load(Ordering::Acquire),
                old_table_id
            );

            let mut memory = crate::dispatch::LinearMemory::new(0, vec![0; 0x1000]);
            let reporter = carrick_observability::compat::CompatReporter::default();

            // 1. Test close_range(0, 0, CLOSE_RANGE_UNSHARE)
            let outcome = dispatcher
                .dispatch(
                    &ctx,
                    crate::dispatch::request::SyscallRequest::new(
                        carrick_abi::syscall::nr::CLOSE_RANGE.0,
                        carrick_observability::compat::SyscallArgs([
                            0,
                            0,
                            carrick_abi::LinuxCloseRangeFlags::UNSHARE.bits() as u64,
                            0,
                            0,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            assert!(matches!(
                outcome,
                crate::dispatch::DispatchOutcome::Returned { value: 0 }
            ));

            let new_table_id_1 = current_task.file_table.load(Ordering::Acquire);
            assert_ne!(
                new_table_id_1, old_table_id,
                "close_range(CLOSE_RANGE_UNSHARE) must update EL1 file_table"
            );

            // 2. Test unshare(CLONE_FILES)
            let ctx2 = dispatcher.capture_one_task_context().unwrap();
            let outcome2 = dispatcher
                .dispatch(
                    &ctx2,
                    crate::dispatch::request::SyscallRequest::new(
                        carrick_abi::syscall::nr::UNSHARE.0,
                        carrick_observability::compat::SyscallArgs([
                            carrick_abi::LinuxCloneFlags::FILES.bits(),
                            0,
                            0,
                            0,
                            0,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            assert!(matches!(
                outcome2,
                crate::dispatch::DispatchOutcome::Returned { value: 0 }
            ));

            let new_table_id_2 = current_task.file_table.load(Ordering::Acquire);
            assert_ne!(
                new_table_id_2, new_table_id_1,
                "unshare(CLONE_FILES) must update EL1 file_table"
            );
        }

        #[test]
        fn test_lock_delegated_file_spins_and_yields() {
            reset_yield_count();
            let file = DelegatedFile::new();
            assert!(file.try_lock()); // locked
            let file_ptr = &file as *const DelegatedFile as usize;

            let handle = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(20));
                let f = unsafe { &*(file_ptr as *const DelegatedFile) };
                f.unlock();
            });

            lock_delegated_file(&file, 1);
            assert!(file.is_locked());
            file.unlock();
            handle.join().unwrap();
            assert!(
                yield_count() > 0,
                "lock_delegated_file must yield when contested"
            );
        }

        #[test]
        fn test_read_recall_loop_fails_loudly_after_bounded_iterations() {
            carrick_fatal::set_hook(|domain, msg| {
                panic!("carrick fatal [{domain}]: {msg}");
            });
            let (_tmp, host_file) = create_test_host_file(b"test data");
            let inode = host_file
                .description
                .read()
                .unwrap()
                .inode_identity_fast()
                .unwrap();

            // Inject a delegated inode with a dead weak reference to simulate a crashed vCPU/process
            {
                let mut map = DELEGATED_INODES.lock();
                let m = map.get_or_insert_with(HashMap::new);
                m.insert(inode, (1, std::sync::Weak::new()));
                publish_delegated_inodes_snapshot(&map);
                HAS_DELEGATED_FILES.store(true, Ordering::Release);
            }

            // Spawn a thread to perform read(); if unbounded, this thread hangs forever.
            let desc = Arc::clone(&host_file.description);
            let handle = std::thread::spawn(move || {
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = desc.read();
                }));
                res.is_err()
            });

            // Wait bounded time for the thread to complete (fail loudly)
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
            let mut failed_loudly = false;
            while std::time::Instant::now() < deadline {
                if handle.is_finished() {
                    failed_loudly = handle.join().unwrap();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }

            // Clean up test injection
            {
                let mut map = DELEGATED_INODES.lock();
                if let Some(m) = map.as_mut() {
                    m.remove(&inode);
                }
                publish_delegated_inodes_snapshot(&map);
                HAS_DELEGATED_FILES.store(false, Ordering::Release);
            }

            assert!(
                failed_loudly,
                "recall loop in read() must fail loudly after bounded iterations when an object lock is held by a dead/crashed vCPU"
            );
        }

        #[test]
        fn test_recall_unregisters_inode_before_vfs_calls() {
            let _region = TestEl1Region::new();
            let (_tmp, host_file) = create_test_host_file(b"initial data");
            let table_id = FileTableId::from_raw_u64(1).unwrap();
            let inode = host_file
                .description
                .read()
                .unwrap()
                .inode_identity_fast()
                .unwrap();

            let handle = delegate_for_test(&host_file, table_id, 3).expect("delegate");
            assert_eq!(handle, 1);
            assert!(is_inode_delegated(inode));

            // Mark a page dirty in EL1 cache to force writeback during recall
            let ptr = get_el1_region_host_ptr();
            let file_ptr = (ptr + EL1_OBJECT_TABLE_OFFSET as usize) as *const DelegatedFile;
            let file = unsafe { &*file_ptr };
            file.dirty_mask.store(1, Ordering::Release);

            recall(&host_file.description).expect("recall");
            assert!(
                !is_inode_delegated(inode),
                "inode must be unregistered before VFS writeback completes"
            );
        }

        #[test]
        fn test_delegate_rejects_o_path() {
            let _region = TestEl1Region::new();
            let dispatcher = crate::dispatch::SyscallDispatcher::new();
            let ctx = dispatcher.capture_one_task_context().unwrap();
            let table = ctx.task().leader_file_table().unwrap();
            let table_id = table.id();

            let fd = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_o_path.txt",
                carrick_abi::LINUX_O_CREAT | carrick_abi::LINUX_O_RDWR | carrick_abi::LINUX_O_PATH,
            );
            let open_file = dispatcher.open_file(fd).unwrap();
            let err = delegate(&open_file, table_id, fd, dispatcher.fs(), None, None).unwrap_err();
            assert!(matches!(err, NotEligible::UnsupportedFlags));
        }

        #[test]
        fn test_atomic_check_and_insert_and_conditional_removal() {
            let _region = TestEl1Region::new();
            let dispatcher = crate::dispatch::SyscallDispatcher::new();
            let ctx = dispatcher.capture_one_task_context().unwrap();
            let table = ctx.task().leader_file_table().unwrap();
            let table_id = table.id();

            let fd1 = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_atomic_insert.txt",
                carrick_abi::LINUX_O_CREAT | carrick_abi::LINUX_O_RDWR,
            );
            let fd2 = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_atomic_insert.txt",
                carrick_abi::LINUX_O_RDWR,
            );

            let open1 = dispatcher.open_file(fd1).unwrap();
            let open2 = dispatcher.open_file(fd2).unwrap();

            let h1 = delegate(&open1, table_id, fd1, dispatcher.fs(), None, None).unwrap();
            // Second delegate of same inode must return AlreadyDelegated
            let err = delegate(&open2, table_id, fd2, dispatcher.fs(), None, None).unwrap_err();
            assert!(matches!(err, NotEligible::AlreadyDelegated));

            // Freeing a non-matching handle must not remove h1's entry
            free_handle(h1 + 1);
            {
                let map = DELEGATED_INODES.lock();
                let map_ref = map.as_ref().unwrap();
                let inode = DELEGATED_HANDLE_INODES.lock()[(h1 - 1) as usize].unwrap();
                assert_eq!(map_ref.get(&inode).unwrap().0, h1);
            }

            // Freeing h1 removes it cleanly
            free_handle(h1);
        }

        #[test]
        fn test_inode_level_mapping_blocks_delegation_and_recalls() {
            let _region = TestEl1Region::new();
            let dispatcher = crate::dispatch::SyscallDispatcher::new();
            let ctx = dispatcher.capture_one_task_context().unwrap();
            let table = ctx.task().leader_file_table().unwrap();
            let table_id = table.id();

            let fd1 = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_map_shared_inode.txt",
                carrick_abi::LINUX_O_CREAT | carrick_abi::LINUX_O_RDWR,
            );
            let fd2 = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_map_shared_inode.txt",
                carrick_abi::LINUX_O_RDWR,
            );

            let open1 = dispatcher.open_file(fd1).unwrap();
            let open2 = dispatcher.open_file(fd2).unwrap();

            // Sibling open1 retains a mapping with inode identity
            let inode = dispatcher
                .fs()
                .rootfs_vfs
                .path_inode_identity("/test_map_shared_inode.txt");
            let mapping = open1.description.retain_mapping_with_inode(inode).unwrap();

            // open2 delegation must be rejected because inode has active mapping
            let err = delegate(&open2, table_id, fd2, dispatcher.fs(), None, None).unwrap_err();
            assert!(
                matches!(err, NotEligible::Mapped),
                "expected NotEligible::Mapped, got {:?}",
                err
            );

            drop(mapping);

            // Now that mapping is dropped, delegation should succeed
            let h = delegate(&open2, table_id, fd2, dispatcher.fs(), None, None).unwrap();
            assert_eq!(h, 1);

            // A new mapping on open1 must recall the delegated inode
            let _mapping2 = open1.description.retain_mapping_with_inode(inode).unwrap();
            assert_eq!(
                open2.description.delegation_handle(),
                0,
                "retaining mapping on sibling must recall delegated inode"
            );
        }

        #[test]
        fn test_in_memory_file_delegation_keyed_with_dentry_identity() {
            let _region = TestEl1Region::new();
            let dispatcher = crate::dispatch::SyscallDispatcher::new();
            let ctx = dispatcher.capture_one_task_context().unwrap();
            let table = ctx.task().leader_file_table().unwrap();
            let table_id = table.id();

            let path = "/test_inmem_dentry_ident.txt";
            let fd = open_path_for_test(
                &dispatcher,
                &ctx,
                path,
                carrick_abi::LINUX_O_CREAT | carrick_abi::LINUX_O_RDWR,
            );
            let open_file = dispatcher.open_file(fd).unwrap();
            let handle = delegate(&open_file, table_id, fd, dispatcher.fs(), None, None).unwrap();
            assert_eq!(handle, 1);

            // While delegated, DELEGATED_INODES must contain the inode
            let delegated_inode = {
                let map = DELEGATED_INODES.lock();
                let map_ref = map.as_ref().unwrap();
                let (inode, (h, _)) = map_ref.iter().next().unwrap();
                assert_eq!(*h, handle);
                *inode
            };

            // Querying identity alone must NOT recall:
            let dentry_ident = dispatcher
                .fs()
                .rootfs_vfs
                .path_inode_identity(path)
                .unwrap();
            assert_eq!(dentry_ident, delegated_inode);
            assert_eq!(open_file.description.delegation_handle(), 1);

            // Accessing the file via namei/dentry lookup must hit the choke point and recall it!
            let _ = dispatcher.fs().rootfs_vfs.dentry_cache.lookup_path(
                path,
                false,
                &*dispatcher.fs().rootfs_vfs.overlay,
                dispatcher.fs().rootfs_vfs.rootfs.as_ref(),
            );
            assert_eq!(
                open_file.description.delegation_handle(),
                0,
                "namei dentry lookup must recall delegated in-memory file at choke point"
            );
        }

        #[test]
        fn test_commit_bytes_at_offset_host_file_records_sparse() {
            let scratch = tempfile::tempdir().unwrap();
            let file_path = scratch.path().join("test_sparse_commit.txt");
            std::fs::write(&file_path, b"initial").unwrap();

            let backend =
                carrick_vfs::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
            let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
            dispatcher.set_fs_backend(Box::new(backend));

            let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
                1,
                crate::thread::ThreadId::synthetic_for_tests(1),
                "test-sparse-commit".to_owned(),
            )
            .expect("root bootstrap");
            let ctx = crate::kernel::Kernel::bootstrap_root(bootstrap)
                .expect("root kernel")
                .1;

            let fd = open_path_for_test(
                &dispatcher,
                &ctx,
                "/test_sparse_commit.txt",
                carrick_abi::LINUX_O_RDWR,
            );
            let open_file = dispatcher.open_file(fd).unwrap();
            let mut guard = open_file.description.write().unwrap();
            let raw_fd = match &*guard {
                OpenDescription::HostFile { host_fd, .. } => host_fd.raw(),
                _ => panic!("expected HostFile"),
            };

            dispatcher.fs().reset_host_sparse_extents(raw_fd, 8192);

            let written = crate::dispatch::fs::rw::commit_bytes_at_offset(
                &mut guard,
                4096,
                b"sparse data",
                Some(&dispatcher.fs().rootfs_vfs),
                Some(&dispatcher.fs().host_sparse_extents),
            )
            .unwrap();
            assert_eq!(written, 11);

            let found = dispatcher.fs().seek_host_sparse_extents(raw_fd, 4096, true);
            assert_eq!(found, Some(Some(4096)));
        }

        #[test]
        fn test_recall_punches_zero_filled_gap_pages() {
            let region = TestEl1Region::new();
            let table_id = FileTableId::from_raw_u64(1).unwrap();
            let (_tmp, host_file) = create_test_host_file(b"");

            let handle = delegate_for_test(&host_file, table_id, 3).expect("delegate");
            assert_eq!(host_file.description.delegation_handle(), handle);

            let region_ptr = region.buffer.as_ptr() as usize;
            let file_ptr = (region_ptr
                + EL1_OBJECT_TABLE_OFFSET as usize
                + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
                as *const DelegatedFile;
            let file = unsafe { &*file_ptr };
            let cache_ptr = (region_ptr
                + EL1_CACHE_OFFSET as usize
                + (handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize)
                as *mut u8;

            // Write 100 bytes at offset 4096 (page 1) in cache
            unsafe {
                let write_slice = std::slice::from_raw_parts_mut(cache_ptr.add(4096), 100);
                write_slice.fill(b'x');
            }
            file.offset.store(4096 + 100, Ordering::Release);
            file.size.store(4096 + 100, Ordering::Release);
            // Page 0 was zero-filled gap on extension, page 1 is dirty
            file.zero_filled_mask.store(1 << 0, Ordering::Release);
            file.dirty_mask.store(1 << 1, Ordering::Release);

            let sparse = DELEGATED_SPARSE.lock()[(handle - 1) as usize]
                .clone()
                .unwrap();
            let raw_fd = match &*host_file.description.open_description().unwrap().read() {
                OpenDescription::HostFile { host_fd, .. } => host_fd.raw(),
                _ => panic!("expected HostFile"),
            };
            sparse.reset_host_sparse_extents(raw_fd, 8192);

            recall(&host_file.description).unwrap();

            // Page 0 was zero-filled, so it was never written to sparse extents.
            // SEEK_DATA from offset 0 should find page 1 (4096).
            let found = sparse.seek_host_sparse_extents(raw_fd, 0, true);
            assert_eq!(found, Some(Some(4096)));
        }

        #[test]
        fn test_non_delegated_guard_access_is_lock_free_and_calls_no_fstat() {
            let _region = TestEl1Region::new();
            let table_id = FileTableId::from_raw_u64(1).unwrap();
            let (_tmp1, host_file1) = create_test_host_file(b"delegated");
            let (_tmp2, host_file2) = create_test_host_file(b"non-delegated");

            // Delegate file 1 so HAS_DELEGATED_FILES is true
            let handle1 = delegate_for_test(&host_file1, table_id, 3).expect("delegate file 1");
            assert_eq!(host_file1.description.delegation_handle(), handle1);
            assert!(has_delegated_files(), "must have delegated files");

            // Verify non-delegated file has its InodeIdentity cached at open time
            let inode2 = host_file2
                .description
                .open_description()
                .unwrap()
                .read()
                .inode_identity_fast()
                .expect("inode identity must be cached at open time");
            assert_ne!(inode2.ino, 0);

            // Hold DELEGATED_INODES mutex lock to simulate contention or slow-path mutation
            let slow_path_lock = DELEGATED_INODES.lock();

            // Guard accessors (read/write/try_read) on non-delegated file MUST succeed
            // without deadlocking on DELEGATED_INODES.lock(), proving lock-freedom.
            let read_guard = host_file2.description.read();
            assert!(
                read_guard.is_some(),
                "read guard accessor must not deadlock or fail"
            );
            drop(read_guard);

            let try_read_guard = host_file2.description.try_read();
            assert!(
                try_read_guard.is_some(),
                "try_read guard accessor must succeed"
            );
            drop(try_read_guard);

            let write_guard = host_file2.description.write();
            assert!(
                write_guard.is_some(),
                "write guard accessor must not deadlock or fail"
            );
            drop(write_guard);

            drop(slow_path_lock);

            // Cleanup
            recall(&host_file1.description).unwrap();
        }

        #[test]
        fn test_recall_targets_only_holding_file_table_and_never_unoccupied_slots() {
            let region = TestEl1Region::new();
            let table_id_1 = FileTableId::from_raw_u64(100).unwrap();
            let (_tmp, host_file) = create_test_host_file(b"test data");

            let handle = delegate_for_test(&host_file, table_id_1, 5).expect("delegate file");
            assert_eq!(host_file.description.delegation_handle(), handle);

            let region_ptr = region.buffer.as_ptr() as usize;

            // Slot 10: running task 1001 with table 100 (matches delegated file table)
            publish_current_task(10, El1TaskId::from_linux_tid(1001), 1, 100);

            // Slot 11: running task 1002 with table 200 (unrelated file table)
            publish_current_task(11, El1TaskId::from_linux_tid(1002), 1, 200);

            // Slot 12: unoccupied slot (no task: task_id == 0), but with leftover file_table 100
            let task_12_offset =
                EL1_CURRENT_TASKS_OFFSET as usize + 12 * core::mem::size_of::<CurrentTask>();
            let task_12 = unsafe { &*((region_ptr + task_12_offset) as *const CurrentTask) };
            task_12.task_id.store(0, Ordering::Relaxed);
            task_12.file_table.store(100, Ordering::Relaxed);
            task_12.pending_host_work.store(0, Ordering::Relaxed);

            // Recall the delegated file
            recall(&host_file.description).expect("recall");

            let task_10_offset =
                EL1_CURRENT_TASKS_OFFSET as usize + 10 * core::mem::size_of::<CurrentTask>();
            let task_10 = unsafe { &*((region_ptr + task_10_offset) as *const CurrentTask) };

            let task_11_offset =
                EL1_CURRENT_TASKS_OFFSET as usize + 11 * core::mem::size_of::<CurrentTask>();
            let task_11 = unsafe { &*((region_ptr + task_11_offset) as *const CurrentTask) };

            // Slot 10 (holding the file) MUST have pending_host_work set
            assert_eq!(
                task_10.pending_host_work.load(Ordering::Acquire),
                1,
                "slot 10 with matching file table must have pending_host_work set"
            );

            // Slot 11 (unrelated file table) MUST NOT have pending_host_work set
            assert_eq!(
                task_11.pending_host_work.load(Ordering::Acquire),
                0,
                "slot 11 with unrelated file table must not have pending_host_work set"
            );

            // Slot 12 (unoccupied slot, task_id == 0) MUST NEVER have pending_host_work set
            assert_eq!(
                task_12.pending_host_work.load(Ordering::Acquire),
                0,
                "slot 12 with no task running must never have pending_host_work set"
            );
        }

        #[test]
        fn test_recalled_two_times_becomes_ineligible_until_close() {
            let _region = TestEl1Region::new();
            let table_id = FileTableId::from_raw_u64(1).unwrap();
            let (_tmp, host_file) = create_test_host_file(b"hysteresis test data");

            // 1st delegation
            let h1 = delegate_for_test(&host_file, table_id, 3).expect("first delegate");
            assert_eq!(h1, 1);
            assert_eq!(host_file.description.common().recall_count(), 0);

            // 1st recall
            recall(&host_file.description).expect("first recall");
            assert_eq!(host_file.description.common().recall_count(), 1);

            // 2nd delegation: still eligible because recall_count == 1 (< 2)
            let h2 = delegate_for_test(&host_file, table_id, 3).expect("second delegate");
            assert_eq!(h2, 1);

            // 2nd recall
            recall(&host_file.description).expect("second recall");
            assert_eq!(host_file.description.common().recall_count(), 2);

            // 3rd delegation attempt: must be rejected with RecalledTooOften
            let err = delegate_for_test(&host_file, table_id, 3).unwrap_err();
            assert_eq!(
                err,
                NotEligible::RecalledTooOften,
                "description recalled twice must become ineligible until close"
            );

            // Closing and creating a fresh description resets the lifetime recall count
            let (_tmp2, fresh_host_file) = create_test_host_file(b"fresh description");
            assert_eq!(fresh_host_file.description.common().recall_count(), 0);
            let h3 = delegate_for_test(&fresh_host_file, table_id, 4)
                .expect("delegate on fresh description");
            assert_eq!(h3, 1);
            recall(&fresh_host_file.description).expect("recall fresh description");
        }
    }
}
