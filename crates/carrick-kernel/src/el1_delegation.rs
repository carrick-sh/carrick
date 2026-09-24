//! EL1 delegated regular files: host-side ownership.
//!
//! Controls whole-object delegation of eligible host regular files to the
//! in-guest EL1 kernel and recall back to the host. The ownership model and
//! its lock order are documented at the top of the ownership section below.

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
    if file_table == 0 {
        TABLELESS_PUBLISHES.fetch_add(1, Ordering::Relaxed);
    }
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

/// The record for `slot` is a cache of the loaded thread's identity; every
/// host syscall boundary knows the true value and restores it here. Returns
/// true (and counts it) when the record was wrong: any path that forgot to
/// publish costs at most one forwarded syscall, and the count shows it.
pub fn revalidate_current_task(slot: usize, task_id: El1TaskId, file_table: u64) -> bool {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 || slot >= 256 {
        return false;
    }
    let offset = EL1_CURRENT_TASKS_OFFSET as usize + slot * core::mem::size_of::<CurrentTask>();
    // SAFETY: the record lives in the EL1 region; only atomics are touched.
    let current_task = unsafe { &*((ptr + offset) as *const CurrentTask) };
    if current_task.task_id.load(Ordering::Acquire) == task_id.raw()
        && current_task.file_table.load(Ordering::Acquire) == file_table
    {
        return false;
    }
    current_task.task_id.store(task_id.raw(), Ordering::Relaxed);
    current_task.file_table.store(file_table, Ordering::Release);
    REVALIDATED_RECORDS.fetch_add(1, Ordering::Relaxed);
    true
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
// ---------------------------------------------------------------------------
// Host-side ownership model
// ---------------------------------------------------------------------------
//
// Every host regular file that an open description refers to has exactly one
// `Owner` record, keyed by the file's exact host identity (st_dev, st_ino),
// captured once from the open object (never from a path). The record counts
// the live open descriptions of that inode and holds the single ownership
// state: `Host`, `Delegating`, `Guest` or `Recalling`. There is no other
// registry.
//
// The zone models Linux's split (open(2): a new open file description has its
// own offset and flags; every description of an inode shares its bytes): one
// in-zone inode record (`DelegatedFile`: size, pages, dirty state, marks) and
// one open-file record per member description (`DelegatedOpenFile`: offset,
// access flags). A description's delegation handle names its open-file
// record; the fd map points EL1 at the same record.
//
// Entry: an inode enters the zone through its only open description. A
// description constructed while its inode is in the zone starts as
// `JOIN_PENDING` and joins at open with its own open-file record. Any host
// access through a description that has not joined recalls the inode first,
// so no description ever reads or writes around the zone's copy.
//
// Exit: recalling an inode needs no description guard. It writes the zone's
// size and pages back through a writable member's host fd, withdraws every
// member from the fd map and ends the inode record; each surviving member
// detaches on its own next host access (restoring its host offset under its
// own guard). Closing one of several members only withdraws that member.
//
// Lock order, never violated:
//   description guard (OpenDescription RwLock)
//     -> OWNERS (map + owner state)
//       -> EL1 inode lock word (which also guards its open-file records)
//         -> FD_MAP (host index of the EL1 fd map)
// No dentry-cache or namespace lock is ever held while any of these is
// acquired, and nothing here is called from inside the VFS: recall happens at
// dispatch level. Recall never takes a description guard.
//
// Delegation is one transaction: `Host -> Delegating` under OWNERS, fill the
// EL1 cache with no OWNERS lock held, then publish (EL1 records, fd-map slot,
// description handle, `Guest`) under OWNERS in one step. A recall that meets
// `Delegating` sets `recall_requested` and waits; the delegator then rolls
// back instead of publishing. Nothing is ever visible as "registered but not
// recallable".

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Weak};

use carrick_vfs::InodeIdentity;
use parking_lot::Condvar;

static NEXT_INCARNATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
static ALLOCATED_HANDLES: Mutex<[bool; MAX_DELEGATED_FILES]> =
    Mutex::new([false; MAX_DELEGATED_FILES]);
static ALLOCATED_OPEN_FILES: Mutex<[bool; MAX_ZONE_OPEN_FILES]> =
    Mutex::new([false; MAX_ZONE_OPEN_FILES]);
static OWNERS: Mutex<Option<HashMap<InodeIdentity, Owner>>> = Mutex::new(None);
static OWNERS_CHANGED: Condvar = Condvar::new();
/// Number of owners not in `Host`: the lock-free negative fast path.
static ACTIVE_DELEGATIONS: AtomicUsize = AtomicUsize::new(0);

/// Host-side index of the EL1 fd map, the only writer of it. Keyed by
/// `(file table, fd)`, so the file table can forget an fd number the moment it
/// stops referring to the object (close, dup2 over it, close_range, exec)
/// without scanning the map. Tied to the region it indexes.
struct FdMapIndex {
    region: usize,
    /// (table, fd) -> (slot, the description it was published for).
    by_fd: HashMap<(u64, u32), (usize, crate::kernel::FileDescriptionId)>,
    by_handle: HashMap<u32, Vec<usize>>,
    free: Vec<usize>,
}

static FD_MAP: Mutex<Option<FdMapIndex>> = Mutex::new(None);
/// Published slots: the lock-free negative fast path for fd-table mutations.
static FD_MAP_PUBLISHED: AtomicUsize = AtomicUsize::new(0);

fn fd_map_slots(region_ptr: usize) -> &'static [FdMapSlot] {
    // SAFETY: the fd map lives in the EL1 region, mapped for the carrier's
    // lifetime, with FD_MAP_CAPACITY slots accessed only through atomics.
    unsafe {
        std::slice::from_raw_parts(
            (region_ptr + EL1_FD_MAP_OFFSET as usize) as *const FdMapSlot,
            FD_MAP_CAPACITY,
        )
    }
}

fn with_fd_map<R>(
    region_ptr: usize,
    f: impl FnOnce(&mut FdMapIndex, &'static [FdMapSlot]) -> R,
) -> R {
    let mut guard = FD_MAP.lock();
    if guard
        .as_ref()
        .is_none_or(|index| index.region != region_ptr)
    {
        let stale = guard.as_ref().map_or(0, |index| index.by_fd.len());
        FD_MAP_PUBLISHED.fetch_sub(stale, Ordering::AcqRel);
        *guard = Some(FdMapIndex {
            region: region_ptr,
            by_fd: HashMap::new(),
            by_handle: HashMap::new(),
            free: (0..FD_MAP_CAPACITY).rev().collect(),
        });
    }
    let index = guard
        .as_mut()
        .unwrap_or_else(|| unreachable!("installed above"));
    f(index, fd_map_slots(region_ptr))
}

fn fd_map_release(index: &mut FdMapIndex, slots: &[FdMapSlot], slot: usize) {
    slots[slot].clear();
    index.free.push(slot);
    FD_MAP_PUBLISHED.fetch_sub(1, Ordering::AcqRel);
}

/// Publish `(file table, fd) -> handle` for EL1, replacing any earlier entry
/// for that fd number. The incarnation is written last (Release) so EL1,
/// which reads it first, never sees a torn slot. False when the map is full.
pub(crate) fn fd_map_publish(
    region_ptr: usize,
    table: u64,
    fd: i32,
    description: crate::kernel::FileDescriptionId,
    handle_word: u32,
    incarnation: u64,
) -> bool {
    with_fd_map(region_ptr, |index, slots| {
        let key = (table, fd as u32);
        if let Some((old, _)) = index.by_fd.remove(&key) {
            let old_handle = slots[old].handle.load(Ordering::Relaxed);
            if let Some(list) = index.by_handle.get_mut(&old_handle) {
                list.retain(|slot| *slot != old);
            }
            fd_map_release(index, slots, old);
        }
        let Some(slot) = index.free.pop() else {
            return false;
        };
        slots[slot].set(table, fd as u32, handle_word, incarnation);
        index.by_fd.insert(key, (slot, description));
        index.by_handle.entry(handle_word).or_default().push(slot);
        FD_MAP_PUBLISHED.fetch_add(1, Ordering::AcqRel);
        true
    })
}

/// Remove every fd-map entry for `handle_word`; returns the file tables that
/// could reach it (their vCPUs must stop at their next EL0 boundary).
pub(crate) fn fd_map_clear_handle(region_ptr: usize, handle_word: u32) -> Vec<u64> {
    with_fd_map(region_ptr, |index, slots| {
        let mut tables = Vec::new();
        for slot in index.by_handle.remove(&handle_word).unwrap_or_default() {
            let table = slots[slot].file_table.load(Ordering::Relaxed);
            let fd = slots[slot].fd.load(Ordering::Relaxed);
            index.by_fd.remove(&(table, fd));
            if table != 0 && !tables.contains(&table) {
                tables.push(table);
            }
            fd_map_release(index, slots, slot);
        }
        tables
    })
}

/// The file tables whose fd map can reach `handle_word`.
pub(crate) fn fd_map_tables_for(region_ptr: usize, handle_word: u32) -> Vec<u64> {
    with_fd_map(region_ptr, |index, slots| {
        let mut tables = Vec::new();
        for slot in index.by_handle.get(&handle_word).into_iter().flatten() {
            let table = slots[*slot].file_table.load(Ordering::Relaxed);
            if table != 0 && !tables.contains(&table) {
                tables.push(table);
            }
        }
        tables
    })
}

/// The file table mutated these fd numbers; each entry carries the
/// description the number refers to now (`None`: closed). EL1 stops serving
/// a number that no longer refers to the description it was published for;
/// a flag update or re-insert of the same description keeps the entry. One
/// atomic load when nothing is published.
pub(crate) fn fd_map_forget(
    table: FileTableId,
    changes: &[(i32, Option<crate::kernel::FileDescriptionId>)],
) {
    if FD_MAP_PUBLISHED.load(Ordering::Acquire) == 0 || changes.is_empty() {
        return;
    }
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return;
    }
    with_fd_map(region_ptr, |index, slots| {
        for (fd, now) in changes {
            let key = (table.raw(), *fd as u32);
            let Some((slot, published)) = index.by_fd.get(&key).copied() else {
                continue;
            };
            if *now == Some(published) {
                continue;
            }
            index.by_fd.remove(&key);
            let handle_word = slots[slot].handle.load(Ordering::Relaxed);
            if let Some(list) = index.by_handle.get_mut(&handle_word) {
                list.retain(|s| *s != slot);
            }
            fd_map_release(index, slots, slot);
        }
    });
}

/// A description's delegation handle while its inode is in the zone but the
/// description has not joined it (it was constructed while the inode was in
/// the zone and has no open-file record yet). Any host access through it
/// recalls the inode, so it never reads or writes around the zone's copy.
pub(crate) const JOIN_PENDING: u32 = u32::MAX;

struct Owner {
    /// Live open descriptions of this inode.
    open_count: usize,
    state: OwnerState,
}

enum OwnerState {
    Host,
    Delegating { recall_requested: bool },
    Guest(GuestBinding),
    Recalling,
}

/// One description that has joined an in-zone inode.
struct Member {
    open_file: u32,
    description: Weak<FileDescription>,
}

struct GuestBinding {
    /// The inode record's handle.
    inode: u32,
    members: Vec<Member>,
    /// A writable member's host fd. Write-back goes through it whichever
    /// description triggers it (that one may be read-only); the reference
    /// keeps the fd open until the inode leaves the zone.
    writeback: Option<crate::dispatch::fd_table::HostFdRef>,
    rootfs: Weak<carrick_vfs::RootFsVfs>,
    sparse: crate::dispatch::fs::HostSparseExtentsRegistry,
    /// Where the file's in-guest watches go if it leaves the zone.
    registry: crate::inotify::InotifyRegistry,
    path: String,
}

impl GuestBinding {
    /// The file tables whose fd map can reach any member.
    fn tables(&self, region_ptr: usize) -> Vec<u64> {
        let mut tables = Vec::new();
        for member in &self.members {
            for table in fd_map_tables_for(region_ptr, member.open_file) {
                if !tables.contains(&table) {
                    tables.push(table);
                }
            }
        }
        tables
    }

    fn live_members(&self) -> Vec<Arc<FileDescription>> {
        self.members
            .iter()
            .filter_map(|member| member.description.upgrade())
            .collect()
    }
}

impl OwnerState {
    fn is_host(&self) -> bool {
        matches!(self, OwnerState::Host)
    }
}

/// Keeps one open description counted against its inode's owner record.
/// Stored on the `FileDescription`; dropped with it.
#[derive(Debug)]
pub(crate) struct InodeOpenRegistration {
    identity: InodeIdentity,
    join_pending: bool,
}

impl InodeOpenRegistration {
    pub(crate) fn identity(&self) -> InodeIdentity {
        self.identity
    }

    /// Whether the inode was in the zone when this description was counted:
    /// the description must join (or recall the inode) before any host I/O.
    pub(crate) fn join_pending(&self) -> bool {
        self.join_pending
    }
}

impl Drop for InodeOpenRegistration {
    fn drop(&mut self) {
        let mut owners = OWNERS.lock();
        let Some(map) = owners.as_mut() else {
            return;
        };
        let remove = match map.get_mut(&self.identity) {
            Some(owner) => {
                owner.open_count = owner.open_count.saturating_sub(1);
                if owner.open_count == 0 && !owner.state.is_host() {
                    // The last description is gone while its inode is still
                    // in the zone: the final close and the last mapping drop
                    // recall first, so reaching this means dirty guest bytes
                    // are about to be lost.
                    carrick_fatal!(
                        "el1_delegation",
                        "last open description of inode dev={} ino={} dropped while delegated",
                        self.identity.dev,
                        self.identity.ino
                    );
                }
                owner.open_count == 0
            }
            None => false,
        };
        if remove {
            map.remove(&self.identity);
        }
    }
}

/// Count a newly constructed open description against its inode. A
/// description of an inode that is in the zone starts `JOIN_PENDING`
/// (see [`InodeOpenRegistration::join_pending`]).
pub(crate) fn register_open(identity: InodeIdentity) -> InodeOpenRegistration {
    let mut owners = OWNERS.lock();
    loop {
        let map = owners.get_or_insert_with(HashMap::new);
        let owner = map.entry(identity).or_insert(Owner {
            open_count: 0,
            state: OwnerState::Host,
        });
        let join_pending = match &mut owner.state {
            OwnerState::Recalling => {
                OWNERS_CHANGED.wait(&mut owners);
                continue;
            }
            OwnerState::Host => false,
            OwnerState::Delegating { recall_requested } => {
                // A second description exists before the first is published:
                // the delegation rolls back.
                *recall_requested = true;
                false
            }
            OwnerState::Guest(_) => true,
        };
        owner.open_count += 1;
        return InodeOpenRegistration {
            identity,
            join_pending,
        };
    }
}

/// True when no object is delegated anywhere in the carrier.
#[inline]
pub(crate) fn no_active_delegations() -> bool {
    ACTIVE_DELEGATIONS.load(Ordering::Acquire) == 0
}

/// Take `identity` out of the zone, if it is in it; returns true when an
/// inode was recalled or a delegation rolled back. Needs no description
/// guard, so it may be called from any dispatch-level path that reaches an
/// inode (stat, truncate, a watch by path) or from a member holding its own
/// guard. Must be called with no VFS lock held.
#[track_caller]
pub(crate) fn recall_inode(identity: InodeIdentity) -> bool {
    if no_active_delegations() {
        return false;
    }
    let mut owners = OWNERS.lock();
    let mut acted = false;
    loop {
        let Some(owner) = owners.as_mut().and_then(|map| map.get_mut(&identity)) else {
            return acted;
        };
        match &mut owner.state {
            OwnerState::Host => return acted,
            OwnerState::Delegating { recall_requested } => {
                *recall_requested = true;
                acted = true;
                OWNERS_CHANGED.wait(&mut owners);
            }
            OwnerState::Recalling => {
                acted = true;
                OWNERS_CHANGED.wait(&mut owners);
            }
            OwnerState::Guest(_) => {
                let OwnerState::Guest(binding) =
                    std::mem::replace(&mut owner.state, OwnerState::Recalling)
                else {
                    unreachable!("matched Guest above");
                };
                drop(owners);
                recall_binding(identity, binding);
                return true;
            }
        }
    }
}

/// The inode recall proper: `binding` was taken out of its owner, which is
/// `Recalling`. Writes the zone's size and pages back, turns in-guest watches
/// into host watches, withdraws every member from the fd map and ends the
/// inode record; members detach on their next host access.
#[track_caller]
fn recall_binding(identity: InodeIdentity, binding: GuestBinding) {
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        carrick_fatal!(
            "el1_delegation",
            "recall called with null EL1 region pointer (inode handle={})",
            binding.inode
        );
    }
    let handle = binding.inode;
    // Stop every vCPU that can reach this inode at its next EL0 boundary.
    mark_pending_host_work_for_file_tables(&binding.tables(region_ptr));
    RECALLS.fetch_add(1, Ordering::Relaxed);
    note_recall_trigger();

    let live = binding.live_members();
    let file = delegated_file_object(region_ptr, handle);
    lock_delegated_file(file, handle);
    file.state
        .store(DELEGATED_STATE_RECALLING, Ordering::Release);
    let served = file.served_ops.load(Ordering::Acquire);
    for member in &live {
        member.common().record_delegation_window(served);
    }
    // In-guest watches on this file become host watches on its path: the
    // instances stay in the zone, and the host write path now produces their
    // events into the same zone queue.
    let mut marks = Vec::new();
    file.for_each_mark(|mark| {
        if mark.inotify_handle != 0 {
            marks.push((mark.inotify_handle, mark.wd, mark.mask));
        }
    });
    for (instance, wd, mask) in marks {
        if let Some(state) = crate::el1_inotify::state_for_handle(instance)
            && state.is_watch_live(wd)
        {
            binding.registry.register(&binding.path, &state, wd, mask);
        }
    }
    file.clear_marks();
    crate::el1_inotify::invalidate_name_cache_file(handle);
    let rootfs = binding.rootfs.upgrade();
    if let Err(err) = write_back_inode(file, handle, identity, &binding, rootfs.as_deref()) {
        for member in &live {
            member.common().record_writeback_error(err);
        }
    }
    file.zero_filled_mask.store(0, Ordering::Release);
    for member in &binding.members {
        fd_map_clear_handle(region_ptr, member.open_file);
        // A member whose description is gone never detaches itself.
        if member.description.strong_count() == 0 {
            retire_open_file(region_ptr, member.open_file);
        }
    }
    file.state.store(DELEGATED_STATE_DEAD, Ordering::Release);
    file.unlock();
    free_handle(handle);
    drop(live);
    drop(binding);

    let mut owners = OWNERS.lock();
    if let Some(owner) = owners.as_mut().and_then(|map| map.get_mut(&identity)) {
        owner.state = OwnerState::Host;
    }
    ACTIVE_DELEGATIONS.fetch_sub(1, Ordering::AcqRel);
    OWNERS_CHANGED.notify_all();
}

/// Recall whatever delegation covers the rootfs file at `path`, if any;
/// returns true when one was recalled. Resolves the path's exact host identity
/// first, with no delegation lock held.
#[track_caller]
pub(crate) fn recall_path(fs: &FsState, path: &str) -> bool {
    if no_active_delegations() {
        return false;
    }
    match fs.rootfs_vfs.path_inode_identity(path) {
        Some(identity) => recall_inode(identity),
        None => false,
    }
}

/// Write back the zone's copy of `identity` when the zone owns it, so a host
/// read of the inode's metadata (a path stat) sees every in-zone write. The
/// file stays in the zone. True when the zone owned the inode: the caller's
/// cached metadata for it is stale and must be read again.
pub(crate) fn sync_inode(identity: InodeIdentity) -> bool {
    if no_active_delegations() {
        return false;
    }
    sync_owner(identity).is_some()
}

/// [`sync_inode`] for the inode at an absolute `path`.
pub(crate) fn sync_path(fs: &FsState, path: &str) -> bool {
    if no_active_delegations() {
        return false;
    }
    match fs.rootfs_vfs.path_inode_identity(path) {
        Some(identity) => sync_inode(identity),
        None => false,
    }
}

/// Write back the in-zone inode `identity` without recalling it. `None` when
/// the inode is not in the zone; otherwise the write-back result and the
/// size the zone holds.
fn sync_owner(identity: InodeIdentity) -> Option<(Result<(), carrick_abi::LinuxErrno>, u64)> {
    let (handle, snapshot) = {
        let owners = OWNERS.lock();
        match owners.as_ref().and_then(|map| map.get(&identity)) {
            Some(Owner {
                state: OwnerState::Guest(binding),
                ..
            }) => (binding.inode, WriteBackTarget::of(binding)),
            _ => return None,
        }
    };
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return None;
    }
    let file = delegated_file_object(region_ptr, handle);
    lock_delegated_file(file, handle);
    let outcome = if file.state.load(Ordering::Acquire) == DELEGATED_STATE_GUEST {
        let rootfs = snapshot.rootfs.upgrade();
        let result = write_back_target(file, handle, identity, &snapshot, rootfs.as_deref());
        Some((result, file.size.load(Ordering::Acquire)))
    } else {
        None
    };
    file.unlock();
    if let Some((Err(err), _)) = &outcome {
        for member in &snapshot.members {
            member.common().record_writeback_error(*err);
        }
    }
    outcome
}

/// A watch or mark was just added at `path`: recall what it covers. A watch on
/// a delegated regular file recalls exactly that file; any other watch (a
/// directory covers its children) recalls every active delegation.
#[track_caller]
pub(crate) fn recall_watched_path(fs: &FsState, path: &str) {
    if no_active_delegations() {
        return;
    }
    if !recall_path(fs, path) {
        recall_all_delegated();
    }
}

/// Recall every in-zone inode in the carrier, and make every in-flight
/// delegation roll back. Used when a carrier-wide policy changes (seccomp,
/// rlimits) and at pool shutdown. Write-back errors stay sticky on the
/// affected descriptions; they are never returned to the triggering syscall.
#[track_caller]
pub fn recall_all_delegated() {
    if no_active_delegations() {
        return;
    }
    loop {
        let identities: Vec<InodeIdentity> = {
            let owners = OWNERS.lock();
            owners
                .as_ref()
                .map(|map| {
                    map.iter()
                        .filter(|(_, owner)| !owner.state.is_host())
                        .map(|(identity, _)| *identity)
                        .collect()
                })
                .unwrap_or_default()
        };
        if identities.is_empty() {
            return;
        }
        for identity in identities {
            recall_inode(identity);
        }
    }
}

fn allocate_handle() -> Option<u32> {
    let mut handles = ALLOCATED_HANDLES.lock();
    let index = handles.iter().position(|in_use| !*in_use)?;
    handles[index] = true;
    Some((index + 1) as u32)
}

fn free_handle(handle: u32) {
    if handle >= 1 && (handle as usize) <= MAX_DELEGATED_FILES {
        ALLOCATED_HANDLES.lock()[handle as usize - 1] = false;
    }
}

fn allocate_open_file() -> Option<u32> {
    let mut handles = ALLOCATED_OPEN_FILES.lock();
    let index = handles.iter().position(|in_use| !*in_use)?;
    handles[index] = true;
    Some((index + 1) as u32)
}

/// End an open-file record and free its handle. Its fd-map entries are gone
/// (or never existed); EL1 and the host check the record's state under its
/// inode's lock, which the caller holds when the inode is live.
fn retire_open_file(region_ptr: usize, handle: u32) {
    if handle == 0 || handle as usize > MAX_ZONE_OPEN_FILES {
        return;
    }
    let record = open_file_object(region_ptr, handle);
    record.state.store(DELEGATED_STATE_DEAD, Ordering::Release);
    record.inode_handle.store(0, Ordering::Release);
    ALLOCATED_OPEN_FILES.lock()[handle as usize - 1] = false;
}

/// A fresh carrier-wide incarnation for a delegated object (files and inotify
/// instances share the counter so fd-map revalidation never aliases).
pub(crate) fn next_incarnation() -> u64 {
    NEXT_INCARNATION.fetch_add(1, Ordering::Relaxed)
}

/// The handle of the in-zone inode record for `identity`, if it is in the zone.
pub(crate) fn delegated_inode_handle(identity: InodeIdentity) -> Option<u32> {
    if no_active_delegations() {
        return None;
    }
    let owners = OWNERS.lock();
    match &owners.as_ref()?.get(&identity)?.state {
        OwnerState::Guest(binding) => Some(binding.inode),
        _ => None,
    }
}

/// Recall every in-zone inode that carries a mark of inotify instance
/// `inotify_handle` (used when that instance leaves the zone): each recall
/// turns the file's in-guest watches into host watches on its path.
pub(crate) fn recall_files_marked_by(inotify_handle: u32) {
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 || no_active_delegations() {
        return;
    }
    let identities: Vec<InodeIdentity> = {
        let owners = OWNERS.lock();
        owners
            .as_ref()
            .map(|map| {
                map.iter()
                    .filter_map(|(identity, owner)| match &owner.state {
                        OwnerState::Guest(binding) => {
                            let file = delegated_file_object(region_ptr, binding.inode);
                            let mut marked = false;
                            lock_delegated_file(file, binding.inode);
                            file.for_each_mark(|mark| {
                                marked |= mark.inotify_handle == inotify_handle
                            });
                            file.unlock();
                            marked.then_some(*identity)
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    for identity in identities {
        recall_inode(identity);
    }
}

/// Detach every mark of inotify instance `inotify_handle` from every delegated
/// file. `held_file_handle` names a file whose EL1 lock the caller already
/// holds (lock order: file, then instance).
pub(crate) fn remove_inotify_marks_from_all_files(
    inotify_handle: u32,
    held_file_handle: Option<u32>,
) {
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return;
    }
    let allocated: Vec<u32> = ALLOCATED_HANDLES
        .lock()
        .iter()
        .enumerate()
        .filter_map(|(index, in_use)| in_use.then_some((index + 1) as u32))
        .collect();
    for handle in allocated {
        let file = delegated_file_object(region_ptr, handle);
        if Some(handle) == held_file_handle {
            file.remove_marks_for_inotify(inotify_handle);
        } else {
            lock_delegated_file(file, handle);
            file.remove_marks_for_inotify(inotify_handle);
            file.unlock();
        }
    }
}

/// Attach watch `wd` of in-zone instance `inotify_handle` to delegated file
/// `file_handle` (file lock, then instance lock). False when either table is
/// full; the caller then keeps the watch on the host path.
pub(crate) fn attach_zone_watch(
    file_handle: u32,
    inotify_handle: u32,
    instance: &DelegatedInotify,
    wd: i32,
    mask: u32,
) -> bool {
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 || file_handle == 0 || file_handle as usize > MAX_DELEGATED_FILES {
        return false;
    }
    let file = delegated_file_object(region_ptr, file_handle);
    lock_delegated_file(file, file_handle);
    if file.state.load(Ordering::Acquire) != DELEGATED_STATE_GUEST {
        file.unlock();
        return false;
    }
    let marked = file.add_mark(DelegatedMark {
        inotify_handle,
        wd,
        mask,
        _pad: 0,
    });
    let attached = marked && {
        let _lock = crate::el1_inotify::InstanceLock::acquire(instance);
        instance.attach_watch_file(wd, file_handle, mask)
    };
    if marked && !attached {
        let _ = file.remove_mark(inotify_handle, wd);
    }
    file.unlock();
    attached
}

/// Detach watch `wd` of instance `inotify_handle` from delegated file
/// `file_handle` (lock order: file, then instance; the caller holds neither).
pub(crate) fn remove_mark(file_handle: u32, inotify_handle: u32, wd: i32) {
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 || file_handle == 0 || file_handle as usize > MAX_DELEGATED_FILES {
        return;
    }
    let file = delegated_file_object(region_ptr, file_handle);
    lock_delegated_file(file, file_handle);
    let _ = file.remove_mark(inotify_handle, wd);
    file.unlock();
}

fn delegated_file_object(region_ptr: usize, handle: u32) -> &'static DelegatedFile {
    let file_ptr = (region_ptr
        + EL1_OBJECT_TABLE_OFFSET as usize
        + (handle as usize - 1) * core::mem::size_of::<DelegatedFile>())
        as *const DelegatedFile;
    // SAFETY: the EL1 region is mapped for the carrier's lifetime and the
    // object table holds MAX_DELEGATED_FILES entries; `handle` is in range.
    // Only atomics are accessed through this shared reference.
    unsafe { &*file_ptr }
}

fn open_file_object(region_ptr: usize, handle: u32) -> &'static DelegatedOpenFile {
    let record_ptr = (region_ptr
        + EL1_OPEN_FILE_TABLE_OFFSET as usize
        + (handle as usize - 1) * core::mem::size_of::<DelegatedOpenFile>())
        as *const DelegatedOpenFile;
    // SAFETY: the EL1 region is mapped for the carrier's lifetime and the
    // open-file table holds MAX_ZONE_OPEN_FILES records; `handle` is in range.
    // Only atomics are accessed through this shared reference.
    unsafe { &*record_ptr }
}

fn delegated_cache(region_ptr: usize, handle: u32) -> *mut u8 {
    (region_ptr
        + EL1_CACHE_OFFSET as usize
        + (handle as usize - 1) * DELEGATED_FILE_MAX_SIZE as usize) as *mut u8
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

/// A delegation window that served at least this many operations at EL1 paid
/// for its delegate and recall; it clears the description's backoff.
pub const DELEGATION_WINDOW_PAYOFF_OPS: u64 = 64;

/// Forwarded attempts refused after the first unprofitable window; doubles
/// with each consecutive one, so an interleaving that recalls every window
/// (write, fstat, write, ...) converges to the host path's cost instead of
/// paying a delegate and a recall per operation.
pub const DELEGATION_BACKOFF_BASE: u32 = 8;

/// Reasons why a file description cannot be delegated to EL1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum NotEligible {
    Disabled,
    NoRegion,
    NotRegularFile,
    NotRootfs,
    Watched,
    UnsupportedFlags,
    FileTooLarge,
    MultipleReferences,
    Shared,
    Unregistered,
    FsizeLimited,
    Mapped,
    RecordLocks,
    TableFull,
    AlreadyDelegated,
    RecallRequested,
    IoError,
    Sealed,
    SeccompFiltered,
    Observed,
    BackingOff,
}

impl NotEligible {
    /// Every reason, in discriminant order.
    pub const ALL: [NotEligible; 21] = [
        NotEligible::Disabled,
        NotEligible::NoRegion,
        NotEligible::NotRegularFile,
        NotEligible::NotRootfs,
        NotEligible::Watched,
        NotEligible::UnsupportedFlags,
        NotEligible::FileTooLarge,
        NotEligible::MultipleReferences,
        NotEligible::Shared,
        NotEligible::Unregistered,
        NotEligible::FsizeLimited,
        NotEligible::Mapped,
        NotEligible::RecordLocks,
        NotEligible::TableFull,
        NotEligible::AlreadyDelegated,
        NotEligible::RecallRequested,
        NotEligible::IoError,
        NotEligible::Sealed,
        NotEligible::SeccompFiltered,
        NotEligible::Observed,
        NotEligible::BackingOff,
    ];
}

/// Carrier-wide count of delegation refusals per reason, and of successful
/// delegations and recalls: the population a delegation contract binds to.
static REFUSALS: [AtomicUsize; NotEligible::ALL.len()] =
    [const { AtomicUsize::new(0) }; NotEligible::ALL.len()];
static DELEGATIONS: AtomicUsize = AtomicUsize::new(0);
static RECALLS: AtomicUsize = AtomicUsize::new(0);
/// vCPU task records published without a file table: EL1 serves nothing for
/// such a thread, so this must stay zero for any thread that has fds.
static TABLELESS_PUBLISHES: AtomicUsize = AtomicUsize::new(0);
/// vCPU task records a host syscall boundary found wrong and restored.
static REVALIDATED_RECORDS: AtomicUsize = AtomicUsize::new(0);
/// Recalls per triggering call site (recall is a slow path; the population
/// names which host path pulled a delegated object back).
static RECALL_TRIGGERS: Mutex<Vec<(&'static std::panic::Location<'static>, usize)>> =
    Mutex::new(Vec::new());

/// Snapshot of the delegation population counters.
#[derive(Debug, Clone, Default)]
pub struct DelegationCounts {
    pub delegations: usize,
    pub recalls: usize,
    pub host_served: usize,
    pub tableless_publishes: usize,
    pub revalidated_records: usize,
    pub refusals: Vec<(NotEligible, usize)>,
    pub recall_triggers: Vec<(String, usize)>,
}

/// Read the delegation population counters (nonzero refusal reasons only).
pub fn delegation_counts() -> DelegationCounts {
    DelegationCounts {
        delegations: DELEGATIONS.load(Ordering::Relaxed),
        recalls: RECALLS.load(Ordering::Relaxed),
        host_served: HOST_SERVED.load(Ordering::Relaxed),
        tableless_publishes: TABLELESS_PUBLISHES.load(Ordering::Relaxed),
        revalidated_records: REVALIDATED_RECORDS.load(Ordering::Relaxed),
        refusals: NotEligible::ALL
            .iter()
            .map(|reason| (*reason, REFUSALS[*reason as usize].load(Ordering::Relaxed)))
            .filter(|(_, count)| *count > 0)
            .collect(),
        recall_triggers: RECALL_TRIGGERS
            .lock()
            .iter()
            .map(|(location, count)| (format!("{}:{}", location.file(), location.line()), *count))
            .collect(),
    }
}

/// Reset the delegation population counters (test harnesses only reset
/// between runs; production never reads them for decisions).
pub fn reset_delegation_counts() {
    DELEGATIONS.store(0, Ordering::Relaxed);
    RECALLS.store(0, Ordering::Relaxed);
    HOST_SERVED.store(0, Ordering::Relaxed);
    TABLELESS_PUBLISHES.store(0, Ordering::Relaxed);
    REVALIDATED_RECORDS.store(0, Ordering::Relaxed);
    for counter in &REFUSALS {
        counter.store(0, Ordering::Relaxed);
    }
    RECALL_TRIGGERS.lock().clear();
}

#[track_caller]
fn note_recall_trigger() {
    let location = std::panic::Location::caller();
    let mut triggers = RECALL_TRIGGERS.lock();
    match triggers
        .iter_mut()
        .find(|(seen, _)| std::ptr::eq(*seen, location))
    {
        Some((_, count)) => *count += 1,
        None => triggers.push((location, 1)),
    }
}

#[cfg(test)]
pub(crate) static YIELD_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Take a delegated object's host/guest lock word from the host.
///
/// The guest holds this lock only for short EL1 critical sections that the
/// mid-EL1 resume rule guarantees complete, so a wait is a scheduling delay:
/// spin briefly, then yield between bursts. The long bound is evidence of a
/// bug, never a scheduling budget.
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

/// Delegate with the description's write guard already held by the caller.
pub(crate) fn delegate_locked(
    open_file: &OpenFile,
    open: &mut OpenDescription,
    file_table: FileTableId,
    fd: i32,
    fs: &FsState,
    rlimits: Option<&RlimitSet>,
    policy: Option<DelegationPolicy<'_>>,
) -> Result<u32, NotEligible> {
    let result = delegate_transaction(open_file, open, file_table, fd, fs, rlimits, policy);
    match result {
        Ok(_) => DELEGATIONS.fetch_add(1, Ordering::Relaxed),
        Err(reason) => REFUSALS[reason as usize].fetch_add(1, Ordering::Relaxed),
    };
    result
}

fn delegate_transaction(
    open_file: &OpenFile,
    open: &mut OpenDescription,
    file_table: FileTableId,
    fd: i32,
    fs: &FsState,
    rlimits: Option<&RlimitSet>,
    policy: Option<DelegationPolicy<'_>>,
) -> Result<u32, NotEligible> {
    if !carrick_mem::memory::el1_kernel_enabled() {
        return Err(NotEligible::Disabled);
    }
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return Err(NotEligible::NoRegion);
    }
    let description = &open_file.description;
    let joining = description.delegation_handle() == JOIN_PENDING;
    if description.delegation_handle() != 0 && !joining {
        return Err(NotEligible::AlreadyDelegated);
    }
    if description.common().fd_refs() != 1 {
        return Err(NotEligible::MultipleReferences);
    }
    if description.has_active_mappings() {
        return Err(NotEligible::Mapped);
    }
    let Some(identity) = description.el1_identity() else {
        return Err(NotEligible::Unregistered);
    };
    let fallback_rlimits;
    let effective_rlimits = match rlimits {
        Some(limits) => Some(limits),
        None => {
            fallback_rlimits = crate::dispatch::resources::rlimits();
            fallback_rlimits.as_ref()
        }
    };
    match effective_rlimits {
        Some(limits) if limits.get(LinuxResource::Fsize).rlim_cur == LINUX_RLIM_INFINITY => {}
        _ => return Err(NotEligible::FsizeLimited),
    }
    if let Some(pol) = policy {
        if pol.seccomp.is_some_and(|s| s.is_active()) {
            return Err(NotEligible::SeccompFiltered);
        }
        if pol.interceptors_active
            || pol
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
    if description.common().seals().is_some() {
        // memfd seals are never delegated; memfds are in-memory anyway.
        return Err(NotEligible::Sealed);
    }

    let status = description.common().status_flags();
    if LinuxOpenFlags::from_bits_truncate(status).intersects(
        LinuxOpenFlags::APPEND
            | LinuxOpenFlags::DIRECT
            | LinuxOpenFlags::SYNC
            | LinuxOpenFlags::DSYNC
            | LinuxOpenFlags::PATH,
    ) {
        return Err(NotEligible::UnsupportedFlags);
    }
    // An inode with other host descriptions cannot enter the zone (they would
    // read and write around it); it enters only through its only description,
    // and later descriptions join. Checked before backoff (the transaction
    // re-checks under the lock).
    if !joining {
        let shared = OWNERS
            .lock()
            .as_ref()
            .and_then(|map| map.get(&identity))
            .is_none_or(|owner| owner.open_count != 1);
        if shared {
            return Err(NotEligible::Shared);
        }
        // Backoff gates every check that costs a host syscall or a registry
        // scan (path resolution, watches, fstat, lseek below), so a backed-off
        // file pays one atomic per forwarded operation.
        if !description.common().admit_delegation() {
            return Err(NotEligible::BackingOff);
        }
    }

    let acc = status & LINUX_O_ACCMODE;
    let readable = acc == LINUX_O_RDONLY || acc == LINUX_O_RDWR;
    let writable_flag = acc == LINUX_O_WRONLY || acc == LINUX_O_RDWR;

    // Only host regular files are delegated: the shipped rootfs backend is the
    // host passthrough, and in-memory descriptions (memfd, O_TMPFILE) keep
    // their single host-side path.
    let OpenDescription::HostFile {
        host_fd,
        metadata,
        writable,
        ..
    } = &*open
    else {
        return Err(NotEligible::NotRegularFile);
    };
    let path = metadata.path.to_str().unwrap_or("");
    let offset = unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_CUR) };
    if offset < 0 {
        return Err(NotEligible::IoError);
    }
    let offset = offset as u64;
    let writable = *writable && writable_flag;
    let mut flags = 0;
    if readable {
        flags |= DELEGATED_FLAG_READABLE;
    }
    if writable {
        flags |= DELEGATED_FLAG_WRITABLE;
    }
    if joining {
        return join_transaction(
            open_file, host_fd, file_table, fd, identity, offset, flags, writable,
        );
    }
    if fs.vfs_mounts.resolve(path).is_some() {
        return Err(NotEligible::NotRootfs);
    }
    // A file already watched when it would enter the zone stays on the host:
    // delegation does not turn host watches into in-zone marks, and a
    // directory watch needs named child events the zone does not produce. A
    // watch added after delegation attaches an in-zone mark instead
    // (`attach_zone_watch`).
    if !fs.inotify_registry.is_empty()
        && fs
            .inotify_registry
            .watches_covering_require_recall(path, |_state, _wd, _mask| false)
    {
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
    let size = st.st_size as u64;

    // Transaction step 1: claim the inode.
    {
        let mut owners = OWNERS.lock();
        let Some(owner) = owners.as_mut().and_then(|map| map.get_mut(&identity)) else {
            return Err(NotEligible::Unregistered);
        };
        if owner.open_count != 1 {
            return Err(NotEligible::Shared);
        }
        if !owner.state.is_host() {
            return Err(NotEligible::AlreadyDelegated);
        }
        owner.state = OwnerState::Delegating {
            recall_requested: false,
        };
        ACTIVE_DELEGATIONS.fetch_add(1, Ordering::AcqRel);
    }
    let rollback =
        |handles: (Option<u32>, Option<u32>), reason: NotEligible| -> Result<u32, NotEligible> {
            if let Some(handle) = handles.0 {
                free_handle(handle);
            }
            if let Some(open_handle) = handles.1 {
                retire_open_file(region_ptr, open_handle);
            }
            let mut owners = OWNERS.lock();
            if let Some(owner) = owners.as_mut().and_then(|map| map.get_mut(&identity)) {
                owner.state = OwnerState::Host;
            }
            ACTIVE_DELEGATIONS.fetch_sub(1, Ordering::AcqRel);
            OWNERS_CHANGED.notify_all();
            Err(reason)
        };

    // Step 2: fill the cache with no OWNERS lock held. Only the file's bytes
    // are copied: EL1 zero-fills any gap it creates when a write extends the
    // file, and reads stop at the size, so a reused slot's old bytes are
    // never observable.
    let Some(handle) = allocate_handle() else {
        return rollback((None, None), NotEligible::TableFull);
    };
    let Some(open_handle) = allocate_open_file() else {
        return rollback((Some(handle), None), NotEligible::TableFull);
    };
    let cache = delegated_cache(region_ptr, handle);
    if size > 0 {
        let n = unsafe { libc::pread(host_fd.raw(), cache as *mut libc::c_void, size as usize, 0) };
        if n < 0 || n as u64 != size {
            return rollback((Some(handle), Some(open_handle)), NotEligible::IoError);
        }
    }

    #[cfg(test)]
    tests::pause_between_fill_and_publish();

    // Step 3: publish, or roll back if a recall arrived meanwhile.
    let mut owners = OWNERS.lock();
    let Some(owner) = owners.as_mut().and_then(|map| map.get_mut(&identity)) else {
        drop(owners);
        return rollback((Some(handle), Some(open_handle)), NotEligible::Unregistered);
    };
    let recall_requested = matches!(
        owner.state,
        OwnerState::Delegating {
            recall_requested: true
        }
    );
    if recall_requested || owner.open_count != 1 {
        drop(owners);
        return rollback(
            (Some(handle), Some(open_handle)),
            NotEligible::RecallRequested,
        );
    }
    let file = delegated_file_object(region_ptr, handle);
    let record = open_file_object(region_ptr, open_handle);
    let inode_generation = NEXT_INCARNATION.fetch_add(1, Ordering::Relaxed);
    let open_generation = NEXT_INCARNATION.fetch_add(1, Ordering::Relaxed);
    lock_delegated_file(file, handle);
    file.generation.store(inode_generation, Ordering::Relaxed);
    file.size.store(size, Ordering::Relaxed);
    file.dirty_mask.store(0, Ordering::Relaxed);
    file.zero_filled_mask.store(0, Ordering::Relaxed);
    file.served_ops.store(0, Ordering::Relaxed);
    file.inode.set(identity.dev, identity.ino);
    file.clear_marks();
    init_open_file(
        record,
        handle,
        inode_generation,
        open_generation,
        offset,
        flags,
    );
    file.state.store(DELEGATED_STATE_GUEST, Ordering::Release);
    file.unlock();
    let published = fd_map_publish(
        region_ptr,
        file_table.raw(),
        fd,
        description.id(),
        open_handle,
        open_generation,
    );
    if !published {
        lock_delegated_file(file, handle);
        file.state.store(DELEGATED_STATE_DEAD, Ordering::Release);
        file.unlock();
        drop(owners);
        return rollback((Some(handle), Some(open_handle)), NotEligible::TableFull);
    }
    description.set_delegation_handle(open_handle);
    owner.state = OwnerState::Guest(GuestBinding {
        inode: handle,
        members: vec![Member {
            open_file: open_handle,
            description: Arc::downgrade(&open_file.description),
        }],
        writeback: writable.then(|| host_fd.clone()),
        rootfs: Arc::downgrade(&fs.rootfs_vfs),
        sparse: fs.host_sparse_extents_registry().clone(),
        registry: fs.inotify_registry.clone(),
        path: path.to_owned(),
    });
    OWNERS_CHANGED.notify_all();
    Ok(handle)
}

/// Write a fresh open-file record. The caller holds the inode's lock.
fn init_open_file(
    record: &DelegatedOpenFile,
    inode: u32,
    inode_generation: u64,
    generation: u64,
    offset: u64,
    flags: u32,
) {
    record.inode_handle.store(inode, Ordering::Relaxed);
    record
        .inode_generation
        .store(inode_generation, Ordering::Relaxed);
    record.generation.store(generation, Ordering::Relaxed);
    record.offset.store(offset, Ordering::Relaxed);
    record.flags.store(flags, Ordering::Relaxed);
    record.state.store(DELEGATED_STATE_GUEST, Ordering::Release);
}

/// A `JOIN_PENDING` description joins its in-zone inode with its own
/// open-file record. The description's write guard is held; the inode stays
/// in the zone throughout (OWNERS is held while the record is published).
#[allow(clippy::too_many_arguments)]
fn join_transaction(
    open_file: &OpenFile,
    host_fd: &crate::dispatch::fd_table::HostFdRef,
    file_table: FileTableId,
    fd: i32,
    identity: InodeIdentity,
    offset: u64,
    flags: u32,
    writable: bool,
) -> Result<u32, NotEligible> {
    let region_ptr = get_el1_region_host_ptr();
    let description = &open_file.description;
    let mut owners = OWNERS.lock();
    let Some(Owner {
        state: OwnerState::Guest(binding),
        ..
    }) = owners.as_mut().and_then(|map| map.get_mut(&identity))
    else {
        // The inode left the zone: the pending description's first host
        // access clears the marker.
        return Err(NotEligible::RecallRequested);
    };
    let Some(open_handle) = allocate_open_file() else {
        return Err(NotEligible::TableFull);
    };
    let handle = binding.inode;
    let file = delegated_file_object(region_ptr, handle);
    let record = open_file_object(region_ptr, open_handle);
    let generation = NEXT_INCARNATION.fetch_add(1, Ordering::Relaxed);
    lock_delegated_file(file, handle);
    let inode_generation = file.generation.load(Ordering::Acquire);
    init_open_file(record, handle, inode_generation, generation, offset, flags);
    file.unlock();
    if !fd_map_publish(
        region_ptr,
        file_table.raw(),
        fd,
        description.id(),
        open_handle,
        generation,
    ) {
        lock_delegated_file(file, handle);
        retire_open_file(region_ptr, open_handle);
        file.unlock();
        return Err(NotEligible::TableFull);
    }
    description.set_delegation_handle(open_handle);
    binding.members.push(Member {
        open_file: open_handle,
        description: Arc::downgrade(&open_file.description),
    });
    if writable && binding.writeback.is_none() {
        binding.writeback = Some(host_fd.clone());
    }
    Ok(handle)
}

/// Host implementation of the shared file operations' user copy: through the
/// current guest address space. A failed copy makes the host fall back to the
/// ordinary path (recall, then the host syscall with its exact EFAULT rules).
struct HostUserCopy<'m, M: carrick_guest_mem::CurrentMmMemory> {
    memory: &'m mut M,
}

impl<M: carrick_guest_mem::CurrentMmMemory> carrick_el1::file::UserCopy for HostUserCopy<'_, M> {
    fn copy_out(&mut self, dst_va: u64, src: &[u8]) -> bool {
        self.memory.write_bytes(dst_va, src).is_ok()
    }

    fn copy_in(&mut self, dst: &mut [u8], src_va: u64) -> bool {
        match self.memory.read_bytes(src_va, dst.len()) {
            Ok(bytes) if bytes.len() == dst.len() => {
                dst.copy_from_slice(&bytes);
                true
            }
            _ => false,
        }
    }
}

/// The host waits for a marking inotify instance (lock order: file, then
/// instance); it has nowhere else to send the operation.
struct HostInstanceLock;

impl carrick_el1::InstanceLockPolicy for HostInstanceLock {
    fn acquire(&self, instance: &DelegatedInotify) -> bool {
        let start = std::time::Instant::now();
        while !instance.host_lock_bounded(64) {
            if start.elapsed() >= std::time::Duration::from_secs(30) {
                carrick_fatal!(
                    "el1_delegation",
                    "DelegatedInotify::host_lock timed out while serving a delegated file write"
                );
            }
            std::thread::yield_now();
        }
        true
    }
}

static HOST_SERVED: AtomicUsize = AtomicUsize::new(0);

/// Serve a forwarded read, write, lseek, pread64 or pwrite64 on a member of an
/// in-zone inode on the host, against the zone's records, with the same code
/// EL1 runs. A forwarded operation (EL1 lost a lock race, took a kick, or saw
/// an unmapped buffer) is not an ownership change. `None` means it could not
/// be served here exactly and the caller takes the ordinary path, whose guard
/// accessor recalls first.
pub(crate) fn serve_on_host<M: carrick_guest_mem::CurrentMmMemory>(
    description: &FileDescription,
    nr: usize,
    args: [u64; 3],
    memory: &mut M,
) -> Option<crate::dispatch::DispatchOutcome> {
    let open_handle = description.delegation_handle();
    if open_handle == 0 || open_handle == JOIN_PENDING {
        return None;
    }
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        return None;
    }
    let record = open_file_object(region_ptr, open_handle);
    let handle = record.inode_handle.load(Ordering::Acquire);
    if handle == 0 || handle as usize > MAX_DELEGATED_FILES {
        return None;
    }
    let file = delegated_file_object(region_ptr, handle);
    lock_delegated_file(file, handle);
    if !record.is_bound_to(file)
        || record.inode_handle.load(Ordering::Acquire) != handle
        || description.delegation_handle() != open_handle
    {
        file.unlock();
        return None;
    }
    // SAFETY: the inotify table lives in the EL1 region with
    // MAX_DELEGATED_INOTIFY entries; only atomics and their own locks are used.
    let inotify_table = unsafe {
        std::slice::from_raw_parts(
            (region_ptr + EL1_INOTIFY_TABLE_OFFSET as usize) as *const DelegatedInotify,
            MAX_DELEGATED_INOTIFY,
        )
    };
    let mut user = HostUserCopy { memory };
    let zone_file = carrick_el1::file::ZoneFile {
        inode: file,
        open: record,
    };
    // SAFETY: the inode is locked and live; the cache pointer is its slot.
    let result = unsafe {
        carrick_el1::serve_locked_file_op(
            &zone_file,
            inotify_table,
            nr,
            args,
            delegated_cache(region_ptr, handle),
            &mut user,
            &HostInstanceLock,
        )
    };
    file.unlock();
    // The host is already at its boundary: deliver what a write owed now.
    crate::el1_inotify::deliver_owed_wakes();
    let value = result.ok()?;
    HOST_SERVED.fetch_add(1, Ordering::Relaxed);
    Some(match carrick_abi::LinuxErrno::from_guest_retval(value) {
        Some(errno) => crate::dispatch::DispatchOutcome::errno(errno),
        None => crate::dispatch::DispatchOutcome::Returned { value },
    })
}

/// Take a member's inode out of the zone and detach the member. Must be
/// called with no guard of this description held.
#[track_caller]
pub(crate) fn recall(description: &FileDescription) -> Result<(), carrick_abi::LinuxErrno> {
    if description.delegation_handle() == 0 {
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

/// Recall a file description's inode if the description is a member (or a
/// pending member) of the zone. Write-back errors stay sticky on the
/// description.
#[track_caller]
pub(crate) fn recall_if_delegated(description: &FileDescription) {
    if description.delegation_handle() != 0 {
        let _ = recall(description);
    }
}

/// [`recall`] with the description's write guard held by the caller: the
/// inode leaves the zone (if it is still in it), then this description
/// detaches, restoring its own host offset.
#[track_caller]
pub(crate) fn recall_locked(
    description: &FileDescription,
    open: &mut OpenDescription,
    handle: u32,
) -> Result<(), carrick_abi::LinuxErrno> {
    let Some(identity) = description.el1_identity() else {
        carrick_fatal!(
            "el1_delegation",
            "delegated description (handle={handle}) has no inode registration"
        );
    };
    // The inode recall takes no description guard, so holding ours is safe.
    recall_inode(identity);
    detach_member(description, open, handle)
}

/// A member of an inode that has left the zone takes its state back: its
/// host fd's offset becomes the offset the zone kept for it, and its cached
/// size is refreshed. The caller holds the description's write guard.
fn detach_member(
    description: &FileDescription,
    open: &mut OpenDescription,
    handle: u32,
) -> Result<(), carrick_abi::LinuxErrno> {
    if handle == JOIN_PENDING {
        description.set_delegation_handle(0);
        return Ok(());
    }
    let region_ptr = get_el1_region_host_ptr();
    let mut result = Ok(());
    if region_ptr != 0 && handle as usize <= MAX_ZONE_OPEN_FILES {
        let record = open_file_object(region_ptr, handle);
        let offset = record.offset.load(Ordering::Acquire);
        if let OpenDescription::HostFile {
            host_fd, metadata, ..
        } = open
        {
            if unsafe { libc::lseek(host_fd.raw(), offset as libc::off_t, libc::SEEK_SET) } < 0 {
                let err = crate::host_to_linux_errno(
                    std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EIO),
                );
                description.common().record_writeback_error(err);
                result = Err(err);
            }
            let mut st: libc::stat = unsafe { core::mem::zeroed() };
            if unsafe { libc::fstat(host_fd.raw(), &mut st) } == 0 {
                metadata.size = st.st_size.max(0) as usize;
            }
        }
        retire_open_file(region_ptr, handle);
    }
    description.set_delegation_handle(0);
    result
}

/// The last fd reference to `description` is going away. A member of an
/// inode that other members keep in the zone just withdraws (its bytes stay
/// in the zone); otherwise the inode leaves the zone.
pub(crate) fn release_description(description: &FileDescription) {
    let handle = description.delegation_handle();
    if handle == 0 {
        return;
    }
    if handle != JOIN_PENDING
        && let Some(identity) = description.el1_identity()
    {
        let region_ptr = get_el1_region_host_ptr();
        let inode = {
            let mut owners = OWNERS.lock();
            match owners
                .as_mut()
                .and_then(|map| map.get_mut(&identity))
                .map(|owner| &mut owner.state)
            {
                Some(OwnerState::Guest(binding))
                    if binding.members.len() > 1
                        && binding.members.iter().any(|m| m.open_file == handle) =>
                {
                    binding.members.retain(|m| m.open_file != handle);
                    Some(binding.inode)
                }
                _ => None,
            }
        };
        if let Some(inode) = inode
            && region_ptr != 0
        {
            fd_map_clear_handle(region_ptr, handle);
            let file = delegated_file_object(region_ptr, inode);
            lock_delegated_file(file, inode);
            retire_open_file(region_ptr, handle);
            file.unlock();
            description.set_delegation_handle(0);
            return;
        }
    }
    recall_if_delegated(description);
}

/// What a write-back needs from an owner, captured under OWNERS so the
/// write-back itself runs without it.
struct WriteBackTarget {
    writeback: Option<crate::dispatch::fd_table::HostFdRef>,
    rootfs: Weak<carrick_vfs::RootFsVfs>,
    sparse: crate::dispatch::fs::HostSparseExtentsRegistry,
    members: Vec<Arc<FileDescription>>,
}

impl WriteBackTarget {
    fn of(binding: &GuestBinding) -> Self {
        Self {
            writeback: binding.writeback.clone(),
            rootfs: binding.rootfs.clone(),
            sparse: binding.sparse.clone(),
            members: binding.live_members(),
        }
    }
}

/// Write an in-zone inode's size and dirty pages back through its owner's
/// writable member fd, with the inode locked by the host. Ownership does not
/// change here, and zero-filled pages stay valid in the cache.
fn write_back_inode(
    file: &DelegatedFile,
    handle: u32,
    identity: InodeIdentity,
    binding: &GuestBinding,
    rootfs: Option<&carrick_vfs::RootFsVfs>,
) -> Result<(), carrick_abi::LinuxErrno> {
    let target = WriteBackTarget {
        writeback: binding.writeback.clone(),
        rootfs: binding.rootfs.clone(),
        sparse: binding.sparse.clone(),
        members: Vec::new(),
    };
    write_back_target(file, handle, identity, &target, rootfs)
}

fn write_back_target(
    file: &DelegatedFile,
    handle: u32,
    identity: InodeIdentity,
    target: &WriteBackTarget,
    rootfs: Option<&carrick_vfs::RootFsVfs>,
) -> Result<(), carrick_abi::LinuxErrno> {
    let region_ptr = get_el1_region_host_ptr();
    let guest_size = file.size.load(Ordering::Acquire);
    let dirty = file.dirty_mask.swap(0, Ordering::AcqRel);
    let Some(fd) = target.writeback.as_ref() else {
        // No member was ever writable: the zone holds the host's bytes.
        if dirty != 0 {
            carrick_fatal!(
                "el1_delegation",
                "in-zone inode (handle={handle}) has dirty pages but no writable member"
            );
        }
        return Ok(());
    };
    let cache = delegated_cache(region_ptr, handle);
    let last_error = || {
        crate::host_to_linux_errno(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO),
        )
    };
    let mut first_error = None;
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    let size_changed =
        unsafe { libc::fstat(fd.raw(), &mut st) } != 0 || st.st_size.max(0) as u64 != guest_size;
    if size_changed {
        // Size first: extending with ftruncate leaves any zero-filled gap as a
        // hole, exactly as the host write path would.
        target
            .sparse
            .truncate_host_sparse_extents(fd.raw(), guest_size);
        if unsafe { libc::ftruncate(fd.raw(), guest_size as libc::off_t) } != 0 {
            first_error.get_or_insert(last_error());
        }
    }
    for page in 0..DELEGATED_MAX_PAGES {
        if dirty & (1 << page) == 0 {
            continue;
        }
        let page_offset = page as u64 * DELEGATED_PAGE_SIZE;
        if page_offset >= guest_size {
            continue;
        }
        let len = DELEGATED_PAGE_SIZE.min(guest_size - page_offset) as usize;
        // SAFETY: the page lies inside this handle's cache slot.
        let bytes = unsafe { std::slice::from_raw_parts(cache.add(page_offset as usize), len) };
        let written = unsafe {
            libc::pwrite(
                fd.raw(),
                bytes.as_ptr() as *const libc::c_void,
                len,
                page_offset as libc::off_t,
            )
        };
        if written < 0 {
            first_error.get_or_insert(last_error());
        } else {
            target
                .sparse
                .record_host_sparse_write(fd, page_offset, written as usize);
        }
    }
    // The host write path invalidates cached stat state after every write;
    // the guest's writes need the same, once, now that they reached the host.
    if (dirty != 0 || size_changed)
        && let Some(vfs) = rootfs
    {
        vfs.notify_inode_changed("", Some(identity));
    }
    match first_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Bring an in-zone inode's host backing up to date without recalling it, so
/// a host operation that reads the backing through `description` (fstat's
/// size and times) sees every in-zone write. A no-op when the description is
/// not a member.
pub(crate) fn sync_to_host(description: &FileDescription) -> Result<(), carrick_abi::LinuxErrno> {
    let handle = description.delegation_handle();
    if handle == 0 || handle == JOIN_PENDING {
        return Ok(());
    }
    let Some(identity) = description.el1_identity() else {
        carrick_fatal!(
            "el1_delegation",
            "delegated description (handle={handle}) has no inode registration"
        );
    };
    let Some((result, size)) = sync_owner(identity) else {
        return Ok(());
    };
    if let Some(d) = description.open_description()
        && let OpenDescription::HostFile { metadata, .. } = &mut *d.write()
    {
        metadata.size = size as usize;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::fd_table::{FileContents, HostFdRef, OpenDescriptionBase};
    use carrick_vfs::rootfs::RootFsMetadata;
    use std::io::{Read, Seek, SeekFrom, Write};
    use tempfile::NamedTempFile;

    /// A scoped hook that runs inside `delegate_locked` between the cache fill
    /// and the publish step. Installed only by the rollback test.
    static PAUSE_HOOK: parking_lot::Mutex<Option<Box<dyn Fn() + Send>>> =
        parking_lot::Mutex::new(None);

    pub(super) fn pause_between_fill_and_publish() {
        let hook = PAUSE_HOOK.lock().take();
        if let Some(hook) = hook {
            hook();
        }
    }

    mod serial_host {
        use super::*;
        use carrick_guest_mem::GuestMemory;

        static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

        /// A private EL1 region for one test; tests that touch the
        /// process-global delegation state run serially.
        struct Region {
            _lock: parking_lot::MutexGuard<'static, ()>,
            _buffer: Vec<u8>,
        }

        impl Region {
            fn new() -> Self {
                let lock = TEST_LOCK.lock();
                let buffer = vec![0u8; EL1_REGION_SIZE as usize];
                record_el1_region_host_ptr(buffer.as_ptr() as usize);
                Self {
                    _lock: lock,
                    _buffer: buffer,
                }
            }
        }

        impl Drop for Region {
            fn drop(&mut self) {
                recall_all_delegated();
                clear_el1_region_host_ptr();
            }
        }

        fn table() -> FileTableId {
            FileTableId::from_raw_u64(1).unwrap()
        }

        fn metadata(path: &std::path::Path, size: usize) -> RootFsMetadata {
            RootFsMetadata {
                path: path.to_path_buf(),
                kind: carrick_vfs::rootfs::RootFsEntryKind::File,
                mode: 0o644,
                size,
            }
        }

        /// A new host-file description of `tmp`'s inode, counted against it.
        fn open_host(tmp: &NamedTempFile) -> OpenFile {
            let raw = unsafe {
                libc::open(
                    std::ffi::CString::new(tmp.path().as_os_str().as_encoded_bytes())
                        .unwrap()
                        .as_ptr(),
                    libc::O_RDWR,
                )
            };
            assert!(raw >= 0);
            let size = tmp.as_file().metadata().unwrap().len() as usize;
            let desc = OpenDescription::HostFile {
                base: OpenDescriptionBase::new(LINUX_O_RDWR),
                host_fd: HostFdRef::new(raw),
                metadata: metadata(tmp.path(), size),
                writable: true,
            };
            let file = crate::dispatch::fd_table::kernel_file_description(
                Arc::new(parking_lot::RwLock::new(desc)),
                LINUX_O_RDWR,
            );
            file.common().retain_fd_ref();
            OpenFile::new(file, 0)
        }

        fn temp_with(bytes: &[u8]) -> NamedTempFile {
            let mut tmp = NamedTempFile::new().unwrap();
            tmp.write_all(bytes).unwrap();
            tmp.flush().unwrap();
            tmp
        }

        fn delegate_default(open: &OpenFile, fd: i32) -> Result<u32, NotEligible> {
            let fs = FsState::new_with_host_resolver(None);
            delegate(
                open,
                table(),
                fd,
                &fs,
                Some(&RlimitSet::carrick_defaults()),
                None,
            )
        }

        /// Simulate EL1 serving a write: bytes into the cache, size, offset and
        /// the dirty mask, exactly as carrick-el1 records them.
        fn guest_write(handle: u32, at: u64, bytes: &[u8]) {
            let region = get_el1_region_host_ptr();
            let file = delegated_file_object(region, handle);
            let cache = delegated_cache(region, handle);
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), cache.add(at as usize), bytes.len());
            }
            let end = at + bytes.len() as u64;
            if end > file.size.load(Ordering::Relaxed) {
                file.size.store(end, Ordering::Relaxed);
            }
            // Every member of the inode is at `end` (tests write through
            // their only member).
            let allocated = *ALLOCATED_OPEN_FILES.lock();
            for (index, in_use) in allocated.iter().enumerate() {
                let record = open_file_object(region, (index + 1) as u32);
                if *in_use && record.inode_handle.load(Ordering::Relaxed) == handle {
                    record.offset.store(end, Ordering::Relaxed);
                }
            }
            let first = at / DELEGATED_PAGE_SIZE;
            let last = (end - 1) / DELEGATED_PAGE_SIZE;
            for page in first..=last {
                file.dirty_mask.fetch_or(1 << page, Ordering::Relaxed);
            }
        }

        /// The inode record a member description's open file is bound to.
        fn inode_of(open: &OpenFile) -> u32 {
            let handle = open.description.delegation_handle();
            assert!(handle != 0 && handle != JOIN_PENDING, "not a member");
            open_file_object(get_el1_region_host_ptr(), handle)
                .inode_handle
                .load(Ordering::Relaxed)
        }

        fn host_bytes(tmp: &NamedTempFile) -> Vec<u8> {
            let mut out = Vec::new();
            let mut f = std::fs::File::open(tmp.path()).unwrap();
            f.seek(SeekFrom::Start(0)).unwrap();
            f.read_to_end(&mut out).unwrap();
            out
        }

        #[test]
        fn recall_writes_back_bytes_size_and_offset() {
            let _region = Region::new();
            let tmp = temp_with(b"hello");
            let open = open_host(&tmp);
            let handle = delegate_default(&open, 3).expect("eligible");
            assert!(!no_active_delegations());
            guest_write(handle, 5, b" world");
            recall(&open.description).expect("recall");
            assert_eq!(open.description.delegation_handle(), 0);
            assert!(no_active_delegations());
            assert_eq!(host_bytes(&tmp), b"hello world");
            let guard = open.description.read().unwrap();
            let OpenDescription::HostFile {
                host_fd, metadata, ..
            } = &*guard
            else {
                panic!("host file");
            };
            assert_eq!(metadata.size, 11);
            assert_eq!(unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_CUR) }, 11);
        }

        #[test]
        fn sync_writes_back_in_zone_bytes_without_recalling() {
            let _region = Region::new();
            let tmp = temp_with(b"hello");
            let open = open_host(&tmp);
            let handle = delegate_default(&open, 3).expect("eligible");
            guest_write(handle, 5, b" world");
            sync_to_host(&open.description).expect("sync");
            // The backing has every in-zone write; the zone still owns the file.
            assert_eq!(host_bytes(&tmp), b"hello world");
            assert_eq!(inode_of(&open), handle);
            let file = delegated_file_object(get_el1_region_host_ptr(), handle);
            assert_eq!(file.dirty_mask.load(Ordering::Relaxed), 0);
            assert_eq!(file.state.load(Ordering::Relaxed), DELEGATED_STATE_GUEST);
            let size = open
                .description
                .inspect_kind(|open| match open {
                    OpenDescription::HostFile { metadata, .. } => metadata.size,
                    _ => panic!("host file"),
                })
                .unwrap();
            assert_eq!(size, 11);
            // Later in-zone writes still reach the backing at recall.
            guest_write(handle, 11, b"!");
            recall(&open.description).expect("recall");
            assert_eq!(host_bytes(&tmp), b"hello world!");
        }

        #[test]
        fn sync_by_inode_writes_back_only_what_the_zone_owns() {
            let _region = Region::new();
            let tmp = temp_with(b"ab");
            let open = open_host(&tmp);
            let identity = open.description.el1_identity().expect("registered");
            // Not in the zone yet: nothing to write back.
            assert!(!sync_inode(identity));
            let handle = delegate_default(&open, 3).expect("eligible");
            guest_write(handle, 2, b"cd");
            assert!(sync_inode(identity));
            assert_eq!(host_bytes(&tmp), b"abcd");
            assert_eq!(inode_of(&open), handle);
            recall(&open.description).expect("recall");
            assert!(!sync_inode(identity));
        }

        #[test]
        fn accessor_on_a_delegated_description_recalls_it_first() {
            let _region = Region::new();
            let tmp = temp_with(b"abc");
            let open = open_host(&tmp);
            let handle = delegate_default(&open, 3).unwrap();
            guest_write(handle, 3, b"def");
            // Any host access through the guard accessor pulls the object back.
            drop(open.description.read().unwrap());
            assert_eq!(open.description.delegation_handle(), 0);
            assert_eq!(host_bytes(&tmp), b"abcdef");
        }

        #[test]
        fn a_second_open_joins_the_zone_with_its_own_offset() {
            let _region = Region::new();
            let tmp = temp_with(b"one");
            let first = open_host(&tmp);
            let handle = delegate_default(&first, 3).unwrap();
            guest_write(handle, 3, b"two");
            // A description constructed while the inode is in the zone is
            // pending; it joins at open with its own open-file record.
            let second = open_host(&tmp);
            assert_eq!(second.description.delegation_handle(), JOIN_PENDING);
            assert_eq!(inode_of(&first), handle);
            assert_eq!(delegate_default(&second, 4), Ok(handle));
            assert_eq!(inode_of(&second), handle);
            let region = get_el1_region_host_ptr();
            let first_record = open_file_object(region, first.description.delegation_handle());
            let second_record = open_file_object(region, second.description.delegation_handle());
            assert_eq!(first_record.offset.load(Ordering::Relaxed), 6);
            assert_eq!(second_record.offset.load(Ordering::Relaxed), 0);
            // The inode leaves the zone once; both members then detach, each
            // with its own offset.
            recall(&first.description).unwrap();
            assert_eq!(host_bytes(&tmp), b"onetwo");
            drop(second.description.read());
            assert_eq!(second.description.delegation_handle(), 0);
            let raw = |open: &OpenFile| match &*open.description.read().unwrap() {
                OpenDescription::HostFile { host_fd, .. } => host_fd.raw(),
                _ => panic!("host file"),
            };
            assert_eq!(unsafe { libc::lseek(raw(&first), 0, libc::SEEK_CUR) }, 6);
            assert_eq!(unsafe { libc::lseek(raw(&second), 0, libc::SEEK_CUR) }, 0);
        }

        #[test]
        fn a_pending_description_recalls_on_host_access() {
            let _region = Region::new();
            let tmp = temp_with(b"one");
            let first = open_host(&tmp);
            let handle = delegate_default(&first, 3).unwrap();
            guest_write(handle, 3, b"two");
            let second = open_host(&tmp);
            // Host I/O through a description that has not joined takes the
            // inode out of the zone first, so it sees every in-zone byte.
            drop(second.description.read());
            assert_eq!(second.description.delegation_handle(), 0);
            assert_eq!(host_bytes(&tmp), b"onetwo");
            drop(first.description.read());
            assert_eq!(first.description.delegation_handle(), 0);
        }

        #[test]
        fn closing_one_member_keeps_the_inode_in_the_zone() {
            let _region = Region::new();
            let tmp = temp_with(b"one");
            let first = open_host(&tmp);
            let handle = delegate_default(&first, 3).unwrap();
            let second = open_host(&tmp);
            delegate_default(&second, 4).unwrap();
            guest_write(handle, 3, b"two");
            release_description(&second.description);
            assert_eq!(second.description.delegation_handle(), 0);
            assert_eq!(inode_of(&first), handle);
            assert!(!no_active_delegations());
            recall(&first.description).unwrap();
            assert_eq!(host_bytes(&tmp), b"onetwo");
        }

        #[test]
        fn recall_during_delegation_rolls_the_delegation_back() {
            let _region = Region::new();
            let tmp = temp_with(b"x");
            let open = open_host(&tmp);
            let identity = open.description.el1_identity().unwrap();
            let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            *PAUSE_HOOK.lock() = Some(Box::new(move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            }));
            let recaller = std::thread::spawn(move || {
                entered_rx.recv().unwrap();
                // The delegator is between fill and publish: this recall must
                // make it roll back, and must not return before it has.
                let releaser = std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    release_tx.send(()).unwrap();
                });
                let acted = recall_inode(identity);
                releaser.join().unwrap();
                acted
            });
            let result = delegate_default(&open, 3);
            assert!(
                recaller.join().unwrap(),
                "recall saw the in-flight delegation"
            );
            assert_eq!(result, Err(NotEligible::RecallRequested));
            assert_eq!(open.description.delegation_handle(), 0);
            assert!(no_active_delegations());
            // The rollback left the inode in Host, so it can delegate again.
            assert!(delegate_default(&open, 3).is_ok());
            // Final close recalls before the description can drop.
            recall(&open.description).unwrap();
        }

        #[test]
        fn unprofitable_windows_back_off_and_a_profitable_one_clears_it() {
            let _region = Region::new();
            let tmp = temp_with(b"x");
            let open = open_host(&tmp);
            // A window recalled before serving anything backs off for
            // BASE << 1 forwarded attempts.
            let handle = delegate_default(&open, 3).unwrap();
            recall(&open.description).unwrap();
            let backoff = DELEGATION_BACKOFF_BASE << 1;
            for _ in 0..backoff {
                assert_eq!(delegate_default(&open, 3), Err(NotEligible::BackingOff));
            }
            // Then it may delegate again; a window that serves enough clears it.
            let handle2 = delegate_default(&open, 3).unwrap();
            let file = delegated_file_object(get_el1_region_host_ptr(), handle2);
            file.served_ops
                .store(DELEGATION_WINDOW_PAYOFF_OPS, Ordering::Relaxed);
            recall(&open.description).unwrap();
            assert!(delegate_default(&open, 3).is_ok());
            recall(&open.description).unwrap();
            let _ = handle;
        }

        #[test]
        fn mapping_recalls_and_blocks_delegation() {
            let _region = Region::new();
            let tmp = temp_with(b"map");
            let open = open_host(&tmp);
            let handle = delegate_default(&open, 3).unwrap();
            guest_write(handle, 3, b"ped");
            let mapping = open.description.retain_mapping().expect("fd owns backing");
            assert_eq!(open.description.delegation_handle(), 0);
            assert_eq!(host_bytes(&tmp), b"mapped");
            assert_eq!(delegate_default(&open, 3), Err(NotEligible::Mapped));
            drop(mapping);
        }

        #[test]
        fn in_memory_files_are_never_delegated() {
            let _region = Region::new();
            let desc = OpenDescription::File {
                base: OpenDescriptionBase::new(LINUX_O_RDWR),
                path: "/memfd:test".to_string(),
                metadata: metadata(std::path::Path::new("/memfd:test"), 1),
                contents: FileContents::dense(b"m".to_vec()),
                offset: 0,
                writable: true,
            };
            let file = crate::dispatch::fd_table::kernel_file_description(
                Arc::new(parking_lot::RwLock::new(desc)),
                LINUX_O_RDWR,
            );
            file.common().retain_fd_ref();
            let open = OpenFile::new(file, 0);
            assert_eq!(delegate_default(&open, 3), Err(NotEligible::Unregistered));
        }

        #[test]
        fn recall_path_by_identity_recalls_only_that_inode() {
            let _region = Region::new();
            let a = temp_with(b"a");
            let b = temp_with(b"b");
            let open_a = open_host(&a);
            let open_b = open_host(&b);
            delegate_default(&open_a, 3).unwrap();
            delegate_default(&open_b, 4).unwrap();
            assert!(recall_inode(open_a.description.el1_identity().unwrap()));
            // The member detaches on its next host access.
            drop(open_a.description.read());
            assert_eq!(open_a.description.delegation_handle(), 0);
            assert_ne!(open_b.description.delegation_handle(), 0);
            assert!(!recall_inode(open_a.description.el1_identity().unwrap()));
            recall(&open_b.description).unwrap();
        }

        #[test]
        fn forwarded_operations_are_served_on_the_host_without_recall() {
            let _region = Region::new();
            let tmp = temp_with(b"abc");
            let open = open_host(&tmp);
            let handle = delegate_default(&open, 3).unwrap();
            let mut memory =
                crate::dispatch::outcome::LinearMemory::new(0x1000, b"XYZ\0\0\0".to_vec());
            let returned = |outcome: Option<crate::dispatch::DispatchOutcome>| match outcome {
                Some(crate::dispatch::DispatchOutcome::Returned { value }) => value,
                other => panic!("expected a served return, got {other:?}"),
            };
            // write(fd, 0x1000, 3) at the delegated offset 0.
            assert_eq!(
                returned(serve_on_host(
                    &open.description,
                    64,
                    [0x1000, 3, 0],
                    &mut memory
                )),
                3
            );
            // lseek(fd, 0, SEEK_SET).
            assert_eq!(
                returned(serve_on_host(&open.description, 62, [0, 0, 0], &mut memory)),
                0
            );
            // read(fd, 0x1003, 3) reads back what the write stored.
            assert_eq!(
                returned(serve_on_host(
                    &open.description,
                    63,
                    [0x1003, 3, 0],
                    &mut memory
                )),
                3
            );
            assert_eq!(memory.read_bytes(0x1003, 3).unwrap(), b"XYZ");
            // Still delegated: a forwarded operation is not an ownership change,
            // and the host-served operations count toward the window.
            assert_eq!(inode_of(&open), handle);
            let file = delegated_file_object(get_el1_region_host_ptr(), handle);
            assert_eq!(file.served_ops.load(Ordering::Relaxed), 3);
            recall(&open.description).unwrap();
            assert_eq!(host_bytes(&tmp), b"XYZ");
        }

        #[test]
        fn a_user_copy_failure_falls_back_instead_of_serving() {
            let _region = Region::new();
            let tmp = temp_with(b"abc");
            let open = open_host(&tmp);
            delegate_default(&open, 3).unwrap();
            let mut memory = crate::dispatch::outcome::LinearMemory::new(0x1000, vec![0; 4]);
            // The buffer is outside guest memory: the host path must take over.
            assert!(serve_on_host(&open.description, 63, [0x9000, 3, 0], &mut memory).is_none());
            recall(&open.description).unwrap();
        }

        #[test]
        fn an_fd_number_the_table_reassigns_is_forgotten_by_el1() {
            let _region = Region::new();
            let region = get_el1_region_host_ptr();
            let table = table();
            let d = |raw: u64| crate::kernel::ids::restore_file_description_id(raw).unwrap();
            assert!(fd_map_publish(region, table.raw(), 5, d(100), 7, 11));
            assert!(fd_map_publish(region, table.raw(), 6, d(100), 7, 11));
            assert!(fd_map_publish(region, table.raw(), 9, d(200), 8, 12));
            let slots = fd_map_slots(region);
            let live = |fd: u32| {
                slots.iter().any(|slot| {
                    slot.incarnation.load(Ordering::Acquire) != 0
                        && slot.file_table.load(Ordering::Relaxed) == table.raw()
                        && slot.fd.load(Ordering::Relaxed) == fd
                })
            };
            // A flag update or re-insert of the same description keeps fd 5.
            fd_map_forget(table, &[(5, Some(d(100)))]);
            assert!(live(5));
            // close(5) or dup2(x, 5): EL1 must stop serving fd 5 only.
            fd_map_forget(table, &[(5, None)]);
            assert!(!live(5) && live(6) && live(9));
            fd_map_forget(table, &[(6, Some(d(300)))]);
            assert!(!live(6));
            // Clearing a handle removes its remaining fds and reports the table.
            assert!(fd_map_publish(region, table.raw(), 6, d(100), 7, 11));
            assert_eq!(fd_map_clear_handle(region, 7), vec![table.raw()]);
            assert!(!live(6) && live(9));
            // Re-publishing an fd number replaces, never duplicates.
            assert!(fd_map_publish(region, table.raw(), 9, d(200), 8, 13));
            assert_eq!(
                slots
                    .iter()
                    .filter(|slot| slot.incarnation.load(Ordering::Acquire) != 0)
                    .count(),
                1
            );
            fd_map_clear_handle(region, 8);
        }

        #[test]
        fn contended_host_lock_yields_until_the_holder_releases() {
            let file = Arc::new(DelegatedFile::default());
            assert!(file.try_lock());
            let before = YIELD_COUNT.load(Ordering::Relaxed);
            let holder = Arc::clone(&file);
            let releaser = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(50));
                holder.unlock();
            });
            lock_delegated_file(&file, 1);
            releaser.join().unwrap();
            file.unlock();
            assert!(
                YIELD_COUNT.load(Ordering::Relaxed) > before,
                "never yielded"
            );
        }
    }
}
