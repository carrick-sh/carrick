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
// ---------------------------------------------------------------------------
// Host-side ownership model
// ---------------------------------------------------------------------------
//
// Every host regular file that an open description refers to has exactly one
// `Owner` record, keyed by the file's exact host identity (st_dev, st_ino),
// captured once from the open object (never from a path). The record counts
// the live open descriptions of that inode and holds the single delegation
// state: `Host`, `Delegating`, `Guest` or `Recalling`. There is no other
// registry.
//
// Exclusivity is structural: a file is delegated only while exactly one open
// description refers to its inode, and opening a second description of a
// delegated inode recalls it before the new description can do any I/O. The
// guard accessors therefore only ever have to check their OWN description.
// Path operations that reach an inode without an open description (stat,
// truncate, watches) recall by identity at dispatch level.
//
// Lock order, never violated:
//   description guard (OpenDescription RwLock)
//     -> OWNERS (map + owner state)
//       -> EL1 object lock word
//         -> FD_MAP_LOCK
// No dentry-cache or namespace lock is ever held while any of these is
// acquired, and nothing here is called from inside the VFS: recall happens at
// dispatch level. `recall_inode` releases OWNERS before it takes a description
// guard.
//
// Delegation is one transaction: `Host -> Delegating` under OWNERS, fill the
// EL1 cache with no OWNERS lock held, then publish (EL1 object, fd-map slot,
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
static OWNERS: Mutex<Option<HashMap<InodeIdentity, Owner>>> = Mutex::new(None);
static OWNERS_CHANGED: Condvar = Condvar::new();
/// Number of owners not in `Host`: the lock-free negative fast path.
static ACTIVE_DELEGATIONS: AtomicUsize = AtomicUsize::new(0);
static FD_MAP_LOCK: Mutex<()> = Mutex::new(());

struct Owner {
    /// Live open descriptions of this inode.
    open_count: usize,
    /// Two descriptions were open at once at some point: never delegate again
    /// while this record lives (exact hysteresis, no heuristic).
    ever_shared: bool,
    state: OwnerState,
}

enum OwnerState {
    Host,
    Delegating { recall_requested: bool },
    Guest(GuestBinding),
    Recalling,
}

struct GuestBinding {
    handle: u32,
    description: Weak<FileDescription>,
    rootfs: Weak<carrick_vfs::RootFsVfs>,
    sparse: crate::dispatch::fs::HostSparseExtentsRegistry,
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
}

impl InodeOpenRegistration {
    pub(crate) fn identity(&self) -> InodeIdentity {
        self.identity
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
                    // delegated: the final close and the last mapping drop
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

/// Count a newly constructed open description against its inode. If the inode
/// is delegated to another description, recall it before returning so the new
/// description never observes stale host bytes.
pub(crate) fn register_open(identity: InodeIdentity) -> InodeOpenRegistration {
    let mut owners = OWNERS.lock();
    loop {
        let map = owners.get_or_insert_with(HashMap::new);
        let owner = map.entry(identity).or_insert(Owner {
            open_count: 0,
            ever_shared: false,
            state: OwnerState::Host,
        });
        match &mut owner.state {
            OwnerState::Recalling => {
                OWNERS_CHANGED.wait(&mut owners);
                continue;
            }
            OwnerState::Host => {}
            OwnerState::Delegating { recall_requested } => {
                *recall_requested = true;
            }
            OwnerState::Guest(binding) => {
                let description = binding.description.upgrade();
                owner.open_count += 1;
                owner.ever_shared = true;
                drop(owners);
                if let Some(description) = description {
                    let _ = recall(&description);
                }
                return InodeOpenRegistration { identity };
            }
        }
        owner.open_count += 1;
        if owner.open_count > 1 {
            owner.ever_shared = true;
        }
        return InodeOpenRegistration { identity };
    }
}

/// True when no object is delegated anywhere in the carrier.
#[inline]
pub(crate) fn no_active_delegations() -> bool {
    ACTIVE_DELEGATIONS.load(Ordering::Acquire) == 0
}

/// Recall whatever delegation covers `identity`, if any; returns true when a
/// delegation was recalled or rolled back. Called at dispatch level for
/// operations that reach an inode without an open description of it (stat,
/// truncate or a watch by path). Must be called with no description guard and
/// no VFS lock held.
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
            OwnerState::Guest(binding) => {
                let description = binding.description.upgrade();
                drop(owners);
                if let Some(description) = description {
                    let _ = recall(&description);
                }
                return true;
            }
        }
    }
}

/// Recall whatever delegation covers the rootfs file at `path`, if any;
/// returns true when one was recalled. Resolves the path's exact host identity
/// first, with no delegation lock held.
pub(crate) fn recall_path(fs: &FsState, path: &str) -> bool {
    if no_active_delegations() {
        return false;
    }
    match fs.rootfs_vfs.path_inode_identity(path) {
        Some(identity) => recall_inode(identity),
        None => false,
    }
}

/// A watch or mark was just added at `path`: recall what it covers. A watch on
/// a delegated regular file recalls exactly that file; any other watch (a
/// directory covers its children) recalls every active delegation.
pub(crate) fn recall_watched_path(fs: &FsState, path: &str) {
    if no_active_delegations() {
        return;
    }
    if !recall_path(fs, path) {
        recall_all_delegated();
    }
}

/// Recall every delegated object in the carrier, and make every in-flight
/// delegation roll back. Used when a carrier-wide policy changes (seccomp,
/// rlimits) and at pool shutdown. Write-back errors stay sticky on the
/// affected descriptions; they are never returned to the triggering syscall.
pub fn recall_all_delegated() {
    if no_active_delegations() {
        return;
    }
    let mut owners = OWNERS.lock();
    loop {
        let mut descriptions = Vec::new();
        let mut in_flight = false;
        if let Some(map) = owners.as_mut() {
            for owner in map.values_mut() {
                match &mut owner.state {
                    OwnerState::Host => {}
                    OwnerState::Delegating { recall_requested } => {
                        *recall_requested = true;
                        in_flight = true;
                    }
                    OwnerState::Recalling => in_flight = true,
                    OwnerState::Guest(binding) => {
                        if let Some(description) = binding.description.upgrade() {
                            descriptions.push(description);
                        }
                    }
                }
            }
        }
        if descriptions.is_empty() && !in_flight {
            return;
        }
        if descriptions.is_empty() {
            OWNERS_CHANGED.wait(&mut owners);
            continue;
        }
        drop(owners);
        for description in descriptions {
            let _ = recall(&description);
        }
        owners = OWNERS.lock();
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

/// Snapshot of the delegation population counters.
#[derive(Debug, Clone, Default)]
pub struct DelegationCounts {
    pub delegations: usize,
    pub recalls: usize,
    pub refusals: Vec<(NotEligible, usize)>,
}

/// Read the delegation population counters (nonzero refusal reasons only).
pub fn delegation_counts() -> DelegationCounts {
    DelegationCounts {
        delegations: DELEGATIONS.load(Ordering::Relaxed),
        recalls: RECALLS.load(Ordering::Relaxed),
        refusals: NotEligible::ALL
            .iter()
            .map(|reason| (*reason, REFUSALS[*reason as usize].load(Ordering::Relaxed)))
            .filter(|(_, count)| *count > 0)
            .collect(),
    }
}

/// Reset the delegation population counters (test harnesses only reset
/// between runs; production never reads them for decisions).
pub fn reset_delegation_counts() {
    DELEGATIONS.store(0, Ordering::Relaxed);
    RECALLS.store(0, Ordering::Relaxed);
    for counter in &REFUSALS {
        counter.store(0, Ordering::Relaxed);
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
    if description.delegation_handle() != 0 {
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
    let size = st.st_size as u64;
    let offset = unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_CUR) };
    if offset < 0 {
        return Err(NotEligible::IoError);
    }
    let offset = offset as u64;
    let writable = *writable && writable_flag;

    // A shared inode is refused before backoff is consulted (the transaction
    // re-checks under the lock).
    let shared = OWNERS
        .lock()
        .as_ref()
        .and_then(|map| map.get(&identity))
        .is_none_or(|owner| owner.ever_shared || owner.open_count != 1);
    if shared {
        return Err(NotEligible::Shared);
    }
    // Backoff is consumed only by attempts that would otherwise proceed, so a
    // structurally ineligible attempt neither spends it nor hides its reason.
    if !description.common().admit_delegation() {
        return Err(NotEligible::BackingOff);
    }

    // Transaction step 1: claim the inode.
    {
        let mut owners = OWNERS.lock();
        let Some(owner) = owners.as_mut().and_then(|map| map.get_mut(&identity)) else {
            return Err(NotEligible::Unregistered);
        };
        if owner.ever_shared || owner.open_count != 1 {
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
    let rollback = |handle: Option<u32>, reason: NotEligible| -> Result<u32, NotEligible> {
        if let Some(handle) = handle {
            free_handle(handle);
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
        return rollback(None, NotEligible::TableFull);
    };
    let cache = delegated_cache(region_ptr, handle);
    if size > 0 {
        let n = unsafe { libc::pread(host_fd.raw(), cache as *mut libc::c_void, size as usize, 0) };
        if n < 0 || n as u64 != size {
            return rollback(Some(handle), NotEligible::IoError);
        }
    }

    #[cfg(test)]
    tests::pause_between_fill_and_publish();

    // Step 3: publish, or roll back if a recall arrived meanwhile.
    let mut owners = OWNERS.lock();
    let Some(owner) = owners.as_mut().and_then(|map| map.get_mut(&identity)) else {
        drop(owners);
        return rollback(Some(handle), NotEligible::Unregistered);
    };
    let recall_requested = matches!(
        owner.state,
        OwnerState::Delegating {
            recall_requested: true
        }
    );
    if recall_requested || owner.ever_shared || owner.open_count != 1 {
        drop(owners);
        return rollback(Some(handle), NotEligible::RecallRequested);
    }
    let file = delegated_file_object(region_ptr, handle);
    let incarnation = NEXT_INCARNATION.fetch_add(1, Ordering::Relaxed);
    lock_delegated_file(file, handle);
    file.generation.store(incarnation, Ordering::Relaxed);
    file.offset.store(offset, Ordering::Relaxed);
    file.size.store(size, Ordering::Relaxed);
    let mut flags = 0;
    if readable {
        flags |= DELEGATED_FLAG_READABLE;
    }
    if writable {
        flags |= DELEGATED_FLAG_WRITABLE;
    }
    file.flags.store(flags, Ordering::Relaxed);
    file.dirty_mask.store(0, Ordering::Relaxed);
    file.zero_filled_mask.store(0, Ordering::Relaxed);
    file.served_ops.store(0, Ordering::Relaxed);
    file.state.store(DELEGATED_STATE_GUEST, Ordering::Release);
    file.unlock();
    let published = {
        let _fd_map = FD_MAP_LOCK.lock();
        let base = (region_ptr + EL1_FD_MAP_OFFSET as usize) as *const FdMapSlot;
        (0..FD_MAP_CAPACITY).any(|index| {
            // SAFETY: the fd map lives in the EL1 region with FD_MAP_CAPACITY slots.
            let slot = unsafe { &*base.add(index) };
            if slot.incarnation.load(Ordering::Relaxed) == 0 {
                slot.set(file_table.raw(), fd as u32, handle, incarnation);
                true
            } else {
                false
            }
        })
    };
    if !published {
        lock_delegated_file(file, handle);
        file.state.store(DELEGATED_STATE_DEAD, Ordering::Release);
        file.unlock();
        drop(owners);
        return rollback(Some(handle), NotEligible::TableFull);
    }
    description.set_delegation_handle(handle);
    owner.state = OwnerState::Guest(GuestBinding {
        handle,
        description: Arc::downgrade(&open_file.description),
        rootfs: Arc::downgrade(&fs.rootfs_vfs),
        sparse: fs.host_sparse_extents_registry().clone(),
    });
    OWNERS_CHANGED.notify_all();
    Ok(handle)
}

/// Recall a delegated file description back to host authority. Must be called
/// with no guard of this description held.
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

/// Recall a file description if it is currently delegated. Write-back errors
/// stay sticky on the description.
pub(crate) fn recall_if_delegated(description: &FileDescription) {
    if description.delegation_handle() != 0 {
        let _ = recall(description);
    }
}

/// Recall with the description's write guard held by the caller.
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
    let binding = {
        let mut owners = OWNERS.lock();
        let owner = owners.as_mut().and_then(|map| map.get_mut(&identity));
        match owner.map(|owner| std::mem::replace(&mut owner.state, OwnerState::Recalling)) {
            Some(OwnerState::Guest(binding)) if binding.handle == handle => binding,
            _ => carrick_fatal!(
                "el1_delegation",
                "recall of handle={handle} found no matching Guest owner for dev={} ino={}",
                identity.dev,
                identity.ino
            ),
        }
    };
    let region_ptr = get_el1_region_host_ptr();
    if region_ptr == 0 {
        carrick_fatal!(
            "el1_delegation",
            "recall called with null EL1 region pointer (handle={handle})"
        );
    }

    // Stop every vCPU that can reach this object at its next EL0 boundary.
    let mut tables = Vec::new();
    {
        let _fd_map = FD_MAP_LOCK.lock();
        let base = (region_ptr + EL1_FD_MAP_OFFSET as usize) as *const FdMapSlot;
        for index in 0..FD_MAP_CAPACITY {
            // SAFETY: fd map slot within the EL1 region.
            let slot = unsafe { &*base.add(index) };
            if slot.incarnation.load(Ordering::Acquire) != 0
                && slot.handle.load(Ordering::Relaxed) == handle
            {
                let table = slot.file_table.load(Ordering::Relaxed);
                if table != 0 && !tables.contains(&table) {
                    tables.push(table);
                }
            }
        }
    }
    mark_pending_host_work_for_file_tables(&tables);
    RECALLS.fetch_add(1, Ordering::Relaxed);

    let file = delegated_file_object(region_ptr, handle);
    lock_delegated_file(file, handle);
    file.state
        .store(DELEGATED_STATE_RECALLING, Ordering::Release);
    description
        .common()
        .record_delegation_window(file.served_ops.load(Ordering::Acquire));
    let guest_offset = file.offset.load(Ordering::Acquire);
    let guest_size = file.size.load(Ordering::Acquire);
    let dirty = file.dirty_mask.swap(0, Ordering::AcqRel);
    file.zero_filled_mask.store(0, Ordering::Release);
    let cache = delegated_cache(region_ptr, handle);
    let rootfs = binding.rootfs.upgrade();

    let mut first_error = None;
    let mut record = |err: carrick_abi::LinuxErrno| {
        description.common().record_writeback_error(err);
        first_error.get_or_insert(err);
    };

    let mut size_changed = false;
    if let OpenDescription::HostFile {
        host_fd,
        metadata,
        writable,
        ..
    } = open
    {
        // Size first: extending with ftruncate leaves any zero-filled gap as a
        // hole, exactly as the host write path would.
        size_changed = metadata.size as u64 != guest_size;
        if *writable && size_changed {
            binding
                .sparse
                .truncate_host_sparse_extents(host_fd.raw(), guest_size);
            if unsafe { libc::ftruncate(host_fd.raw(), guest_size as libc::off_t) } != 0 {
                record(crate::host_to_linux_errno(
                    std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EIO),
                ));
            }
        }
        metadata.size = guest_size as usize;
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
        match crate::dispatch::fs::rw::commit_bytes_at_offset(
            open,
            page_offset,
            bytes,
            rootfs.as_deref(),
        ) {
            Ok(written) => {
                if let OpenDescription::HostFile { host_fd, .. } = open {
                    binding
                        .sparse
                        .record_host_sparse_write(host_fd, page_offset, written);
                }
            }
            Err(err) => record(err),
        }
    }
    if let OpenDescription::HostFile { host_fd, .. } = open {
        if unsafe { libc::lseek(host_fd.raw(), guest_offset as libc::off_t, libc::SEEK_SET) } < 0 {
            record(crate::host_to_linux_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            ));
        }
    }
    // The host write path invalidates cached stat state after every write;
    // the guest's writes need the same, once, now that they reached the host.
    if (dirty != 0 || size_changed)
        && let Some(vfs) = rootfs.as_deref()
    {
        vfs.notify_inode_changed("", Some(identity));
    }

    {
        let _fd_map = FD_MAP_LOCK.lock();
        let base = (region_ptr + EL1_FD_MAP_OFFSET as usize) as *const FdMapSlot;
        for index in 0..FD_MAP_CAPACITY {
            // SAFETY: fd map slot within the EL1 region.
            let slot = unsafe { &*base.add(index) };
            if slot.handle.load(Ordering::Acquire) == handle {
                slot.clear();
            }
        }
    }
    file.state.store(DELEGATED_STATE_DEAD, Ordering::Release);
    file.unlock();
    free_handle(handle);
    description.set_delegation_handle(0);

    {
        let mut owners = OWNERS.lock();
        if let Some(map) = owners.as_mut() {
            if let Some(owner) = map.get_mut(&identity) {
                owner.state = OwnerState::Host;
            }
        }
        ACTIVE_DELEGATIONS.fetch_sub(1, Ordering::AcqRel);
        OWNERS_CHANGED.notify_all();
    }
    match first_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
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
            file.offset.store(end, Ordering::Relaxed);
            let first = at / DELEGATED_PAGE_SIZE;
            let last = (end - 1) / DELEGATED_PAGE_SIZE;
            for page in first..=last {
                file.dirty_mask.fetch_or(1 << page, Ordering::Relaxed);
            }
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
        fn second_open_of_the_inode_recalls_and_blocks_redelegation() {
            let _region = Region::new();
            let tmp = temp_with(b"one");
            let first = open_host(&tmp);
            let handle = delegate_default(&first, 3).unwrap();
            guest_write(handle, 3, b"two");
            // Opening another description of the same inode recalls the first
            // before the new one can read stale host bytes.
            let second = open_host(&tmp);
            assert_eq!(first.description.delegation_handle(), 0);
            assert_eq!(host_bytes(&tmp), b"onetwo");
            // Neither may be delegated while both are open, nor afterwards.
            assert_eq!(delegate_default(&first, 3), Err(NotEligible::Shared));
            assert_eq!(delegate_default(&second, 4), Err(NotEligible::Shared));
            drop(second);
            assert_eq!(delegate_default(&first, 3), Err(NotEligible::Shared));
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
            assert_eq!(open_a.description.delegation_handle(), 0);
            assert_ne!(open_b.description.delegation_handle(), 0);
            assert!(!recall_inode(open_a.description.el1_identity().unwrap()));
            recall(&open_b.description).unwrap();
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
