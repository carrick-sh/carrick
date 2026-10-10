//! Shared guest file table for standard descriptors and native poll.
//!
//! Descriptors 0..2 are admitted as host-backed open descriptions in the existing
//! guest file owner (`FdMapSlot`, `DelegatedOpenFile`, `DelegatedFile`), keyed by
//! `(file_table, fd)`. Closed standard descriptors stay absent.
//!
//! Poll validates its bounded `pollfd` array, resolves each entry through the
//! existing zone tables and IPC venue, ignores negative descriptors, and reports
//! `POLLNVAL` for absent nonnegative descriptors. Unconditional `ERR`, `HUP`, and
//! `NVAL` are reported independently of requested events. Duplicate descriptors
//! receive independent results. A blocking wait releases execution capacity
//! through an owned continuation on the zone scheduler.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::lock::SpinLock;
use carrick_el1_abi::{
    DELEGATED_FLAG_READABLE, DELEGATED_FLAG_WRITABLE, DELEGATED_STATE_GUEST, DelegatedFile,
    DelegatedOpenFile, FD_MAP_CAPACITY, FdMapSlot, HostBoundFd, HostObjectBinding,
    HostReadinessEntry, fd_map_lookup,
};
use carrick_sched_core::{SlotId, ZoneTables};
pub use carrick_syscall_abi::{
    LINUX_POLLERR, LINUX_POLLHUP, LINUX_POLLIN, LINUX_POLLNVAL, LINUX_POLLOUT, LINUX_POLLPRI,
    LINUX_POLLRDBAND, LINUX_POLLRDNORM, LINUX_POLLWRBAND, LINUX_POLLWRNORM,
};

// Descriptor mutations and poll snapshots share one short in-ring critical
// section. No host crossing or blocking wait is made while it is held.
static FD_MAP_LOCK: SpinLock<()> = SpinLock::new(());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasedDescription {
    pub handle: u32,
    pub incarnation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestDescriptorChange {
    pub fd: i32,
    pub release: Option<ReleasedDescription>,
}

pub const GUEST_FD_CLOEXEC: u32 = 1;
pub const GUEST_FD_LIMIT: i32 = 1024;

fn last_reference(fd_map: &[FdMapSlot], description: ReleasedDescription) -> bool {
    !fd_map.iter().take(FD_MAP_CAPACITY).any(|slot| {
        slot.incarnation.load(Ordering::Acquire) == description.incarnation
            && slot.handle.load(Ordering::Relaxed) == description.handle
    })
}

fn tombstone_index(fd_map: &[FdMapSlot], file_table: u64, fd: i32) -> Option<usize> {
    if fd < 0 {
        return None;
    }
    fd_map.iter().take(FD_MAP_CAPACITY).position(|slot| {
        slot.incarnation.load(Ordering::Acquire) == 1
            && slot.file_table.load(Ordering::Relaxed) == file_table
            && slot.fd.load(Ordering::Relaxed) == fd as u32
            && slot.handle.load(Ordering::Relaxed) == 0
    })
}

#[cfg(test)]
fn is_closed_stdio_tombstone(fd_map: &[FdMapSlot], file_table: u64, fd: i32) -> bool {
    (0..=2).contains(&fd) && tombstone_index(fd_map, file_table, fd).is_some()
}

/// Remove one guest descriptor; only the last reference yields a host-object
/// release obligation. The host never owns the guest descriptor number.
pub fn close_host_binding(
    fd_map: &[FdMapSlot],
    file_table: u64,
    fd: i32,
) -> Option<GuestDescriptorChange> {
    let _guard = FD_MAP_LOCK.lock();
    let (handle, index) = fd_map_lookup(fd_map, file_table, fd)?;
    if handle == 0 {
        return None;
    }
    let incarnation = fd_map[index].incarnation.load(Ordering::Acquire);
    fd_map[index].clear();
    if (0..=2).contains(&fd) {
        // Preserve an explicit close of bare stdio. A later descriptor lookup
        // can distinguish it from a table not yet admitted by the carrier.
        if fd_map[index].try_claim() {
            fd_map[index].set(file_table, fd as u32, 0, 1);
        }
    }
    let description = ReleasedDescription {
        handle,
        incarnation,
    };
    Some(GuestDescriptorChange {
        fd,
        release: last_reference(fd_map, description).then_some(description),
    })
}

/// Linux dup2 on an in-ring host-bound description. A live target is replaced
/// under the descriptor lock, preserving the source description and clearing
/// the new descriptor's close-on-exec flag.
pub fn dup2_host_binding(
    fd_map: &[FdMapSlot],
    file_table: u64,
    old_fd: i32,
    new_fd: i32,
    cloexec: bool,
) -> Option<GuestDescriptorChange> {
    if !(0..GUEST_FD_LIMIT).contains(&new_fd) {
        return None;
    }
    let _guard = FD_MAP_LOCK.lock();
    let (handle, source_index) = fd_map_lookup(fd_map, file_table, old_fd)?;
    if handle == 0 {
        return None;
    }
    if old_fd == new_fd {
        if cloexec {
            return None;
        }
        return Some(GuestDescriptorChange {
            fd: new_fd,
            release: None,
        });
    }
    let incarnation = fd_map[source_index].incarnation.load(Ordering::Acquire);
    let tombstone = tombstone_index(fd_map, file_table, new_fd);
    if let Some(index) = tombstone {
        fd_map[index].clear();
    }
    let target = fd_map_lookup(fd_map, file_table, new_fd);
    let release = target.and_then(|(old_handle, index)| {
        let old_incarnation = fd_map[index].incarnation.load(Ordering::Acquire);
        fd_map[index].clear();
        let old = ReleasedDescription {
            handle: old_handle,
            incarnation: old_incarnation,
        };
        (old_handle != 0 && last_reference(fd_map, old)).then_some(old)
    });
    let slot = if let Some((_, index)) = target {
        let slot = &fd_map[index];
        if !slot.try_claim() {
            return None;
        }
        slot
    } else if let Some(index) = tombstone {
        let slot = &fd_map[index];
        if !slot.try_claim() {
            return None;
        }
        slot
    } else {
        fd_map
            .iter()
            .take(FD_MAP_CAPACITY)
            .find(|slot| slot.try_claim())?
    };
    slot.set_with_flags(
        file_table,
        new_fd as u32,
        handle,
        incarnation,
        u32::from(cloexec) * GUEST_FD_CLOEXEC,
    );
    Some(GuestDescriptorChange {
        fd: new_fd,
        release,
    })
}

/// Choose the first unused descriptor at or above `min_fd`, sharing the same
/// open description. The caller enforces the task's RLIMIT_NOFILE ceiling.
pub fn dup_host_binding(
    fd_map: &[FdMapSlot],
    file_table: u64,
    old_fd: i32,
    min_fd: i32,
    max_fd: i32,
    cloexec: bool,
) -> Option<GuestDescriptorChange> {
    if min_fd < 0 || max_fd <= min_fd {
        return None;
    }
    let _guard = FD_MAP_LOCK.lock();
    let (handle, source_index) = fd_map_lookup(fd_map, file_table, old_fd)?;
    if handle == 0 {
        return None;
    }
    let incarnation = fd_map[source_index].incarnation.load(Ordering::Acquire);
    let new_fd = (min_fd..max_fd).find(|fd| fd_map_lookup(fd_map, file_table, *fd).is_none())?;
    let tombstone = tombstone_index(fd_map, file_table, new_fd);
    if let Some(index) = tombstone {
        fd_map[index].clear();
    }
    let slot = if let Some(index) = tombstone {
        &fd_map[index]
    } else {
        fd_map
            .iter()
            .take(FD_MAP_CAPACITY)
            .find(|slot| slot.incarnation.load(Ordering::Acquire) == 0)?
    };
    if !slot.try_claim() {
        return None;
    }
    slot.set_with_flags(
        file_table,
        new_fd as u32,
        handle,
        incarnation,
        u32::from(cloexec) * GUEST_FD_CLOEXEC,
    );
    Some(GuestDescriptorChange {
        fd: new_fd,
        release: None,
    })
}

/// Bounded Linux `struct pollfd`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

/// Admits standard descriptors 0..2 as host-backed open descriptions in the
/// existing zone tables for `file_table`.
///
/// - 0: stdin (ReadOnly)
/// - 1: stdout (WriteOnly)
/// - 2: stderr (WriteOnly)
///
/// Closed standard descriptors stay absent in `fd_map`.
pub fn admit_stdio(
    fd_map: &[FdMapSlot],
    open_table: &[DelegatedOpenFile],
    object_table: &[DelegatedFile],
    file_table: u64,
    open_mask: [bool; 3],
) {
    if file_table == 0 {
        return;
    }
    let _guard = FD_MAP_LOCK.lock();
    for (fd, &open) in open_mask.iter().enumerate() {
        if !open {
            continue;
        }
        let binding = match fd {
            0 => HostObjectBinding::STDIN,
            1 => HostObjectBinding::STDOUT,
            _ => HostObjectBinding::STDERR,
        };
        let ufd = fd as u32;
        if fd_map_lookup(fd_map, file_table, fd as i32).is_some()
            || tombstone_index(fd_map, file_table, fd as i32).is_some()
        {
            continue;
        }
        let Some(slot) = fd_map.iter().take(FD_MAP_CAPACITY).find(|s| s.try_claim()) else {
            continue;
        };
        let handle = (fd + 1) as u32;
        if (handle as usize) <= open_table.len() && (handle as usize) <= object_table.len() {
            let obj = &object_table[(handle - 1) as usize];
            let open_file = &open_table[(handle - 1) as usize];
            obj.inode.set(0, 0);
            obj.generation.store(1, Ordering::Relaxed);
            obj.state.store(DELEGATED_STATE_GUEST, Ordering::Release);

            let flags = if fd == 0 {
                DELEGATED_FLAG_READABLE
            } else {
                DELEGATED_FLAG_WRITABLE
            };
            open_file.flags.store(flags, Ordering::Relaxed);
            open_file.generation.store(1, Ordering::Relaxed);
            open_file.inode_handle.store(handle, Ordering::Relaxed);
            open_file.inode_generation.store(1, Ordering::Relaxed);
            open_file.offset.store(0, Ordering::Relaxed);
            open_file.bind_host_object(binding);
            open_file
                .state
                .store(DELEGATED_STATE_GUEST, Ordering::Release);

            slot.set(file_table, ufd, handle, 1);
        } else {
            slot.clear();
        }
    }
}

/// Admits a host-backed file descriptor in the zone tables.
pub fn admit_host_fd(
    fd_map: &[FdMapSlot],
    open_table: &[DelegatedOpenFile],
    object_table: &[DelegatedFile],
    file_table: u64,
    guest_fd: i32,
    host_fd: i32,
    flags: u32,
) -> Option<u32> {
    let host_fd = HostBoundFd::new(host_fd)?;
    if file_table == 0 || guest_fd < 0 {
        return None;
    }
    let _guard = FD_MAP_LOCK.lock();
    let ufd = guest_fd as u32;
    if fd_map_lookup(fd_map, file_table, guest_fd).is_some() {
        return None;
    }
    let slot = fd_map
        .iter()
        .take(FD_MAP_CAPACITY)
        .find(|s| s.try_claim())?;

    let Some((idx, open_file)) = open_table
        .iter()
        .enumerate()
        .find(|(_, o)| o.state.load(Ordering::Acquire) == 0)
    else {
        slot.clear();
        return None;
    };
    let Some(obj) = object_table.get(idx) else {
        slot.clear();
        return None;
    };

    let handle = (idx + 1) as u32;
    obj.inode.set(0, 0);
    obj.generation.store(1, Ordering::Relaxed);
    obj.state.store(DELEGATED_STATE_GUEST, Ordering::Release);

    open_file.flags.store(flags, Ordering::Relaxed);
    open_file.generation.store(1, Ordering::Relaxed);
    open_file.inode_handle.store(handle, Ordering::Relaxed);
    open_file.inode_generation.store(1, Ordering::Relaxed);
    open_file.offset.store(0, Ordering::Relaxed);
    open_file.bind_host_fd(host_fd);
    open_file
        .state
        .store(DELEGATED_STATE_GUEST, Ordering::Release);

    slot.set(file_table, ufd, handle, 1);
    Some(handle)
}

/// Inherits descriptors across fork according to the shared file-table policy.
///
/// Copies `parent_table` descriptor slots in `fd_map` to `child_table`, sharing
/// the exact same open description (`handle`).
pub fn fork_fd_map(fd_map: &[FdMapSlot], parent_table: u64, child_table: u64) -> bool {
    if parent_table == 0 || child_table == 0 || parent_table == child_table {
        return false;
    }
    let _guard = FD_MAP_LOCK.lock();
    if fd_map.iter().take(FD_MAP_CAPACITY).any(|slot| {
        slot.incarnation.load(Ordering::Acquire) != 0
            && slot.file_table.load(Ordering::Relaxed) == child_table
    }) {
        return false;
    }
    let mut copies = Vec::new();
    for slot in fd_map.iter().take(FD_MAP_CAPACITY) {
        let inc = slot.incarnation.load(Ordering::Acquire);
        if inc != 0
            && inc != FdMapSlot::CLAIMED
            && slot.file_table.load(Ordering::Relaxed) == parent_table
        {
            let fd = slot.fd.load(Ordering::Relaxed);
            let handle = slot.handle.load(Ordering::Relaxed);
            let flags = slot.fd_flags.load(Ordering::Relaxed);
            copies.push((fd, handle, inc, flags));
        }
    }
    let mut claimed = Vec::new();
    for _ in &copies {
        if let Some((index, _)) = fd_map
            .iter()
            .take(FD_MAP_CAPACITY)
            .enumerate()
            .find(|(_, slot)| slot.try_claim())
        {
            claimed.push(index);
        } else {
            for index in claimed {
                fd_map[index].clear();
            }
            return false;
        }
    }
    for ((fd, handle, inc, flags), index) in copies.into_iter().zip(claimed) {
        fd_map[index].set_with_flags(child_table, fd, handle, inc, flags);
    }
    true
}

/// Retire only the exact table's published descriptors after exit or rollback.
pub fn retire_fd_map(fd_map: &[FdMapSlot], file_table: u64) {
    if file_table == 0 {
        return;
    }
    let _guard = FD_MAP_LOCK.lock();
    for slot in fd_map.iter().take(FD_MAP_CAPACITY) {
        if slot.file_table.load(Ordering::Acquire) == file_table
            && slot.incarnation.load(Ordering::Acquire) != 0
        {
            slot.clear();
        }
    }
}

/// Whether every live poll entry names a host-bound open description.
/// Negative entries do not participate. Absent descriptors can travel with
/// host-bound entries: the shared dispatcher reports their POLLNVAL result.
/// In-zone descriptions stay with the guest owner.
pub fn host_readiness_entries(
    fd_map: &[FdMapSlot],
    open_table: &[DelegatedOpenFile],
    file_table: u64,
    pollfds: &[PollFd],
) -> Option<Vec<HostReadinessEntry>> {
    let _guard = FD_MAP_LOCK.lock();
    let mut host_entries = Vec::new();
    for (index, entry) in pollfds.iter().enumerate() {
        if entry.fd < 0 {
            continue;
        }
        let Some((handle, _)) = fd_map_lookup(fd_map, file_table, entry.fd) else {
            continue;
        };
        if handle == 0 {
            continue;
        }
        let Some(binding) = open_table
            .get((handle - 1) as usize)
            .filter(|open| open.state.load(Ordering::Acquire) == DELEGATED_STATE_GUEST)
            .and_then(|open| {
                open.host_object()
                    .or_else(|| open.host_fd().map(HostObjectBinding::from_host_fd))
            })
        else {
            continue;
        };
        host_entries.push(HostReadinessEntry {
            binding,
            events: entry.events,
            revents: 0,
            poll_index: index as u32,
        });
    }
    // An all-negative set still carries a timer wait through the host
    // readiness crossing, even though it enrolls no host descriptor.
    (!host_entries.is_empty() || pollfds.iter().all(|entry| entry.fd < 0)).then_some(host_entries)
}

/// Resolves pollfd entries against the zone tables and IPC venue.
pub fn resolve_poll(
    fd_map: &[FdMapSlot],
    open_table: &[DelegatedOpenFile],
    _object_table: &[DelegatedFile],
    _ipc: Option<&crate::personality::ipc::IpcVenue<'_>>,
    file_table: u64,
    pollfds: &mut [PollFd],
) -> i32 {
    resolve_poll_with_host_readiness(
        fd_map,
        open_table,
        _object_table,
        _ipc,
        file_table,
        pollfds,
        None,
    )
}

/// Resolve guest namespace entries using the carrier's exact host ready set.
/// The host entries are ordered by poll index and preserve duplicates.
pub fn resolve_poll_with_host_readiness(
    fd_map: &[FdMapSlot],
    open_table: &[DelegatedOpenFile],
    _object_table: &[DelegatedFile],
    _ipc: Option<&crate::personality::ipc::IpcVenue<'_>>,
    file_table: u64,
    pollfds: &mut [PollFd],
    host_entries: Option<&[HostReadinessEntry]>,
) -> i32 {
    let _guard = FD_MAP_LOCK.lock();
    let mut ready_count = 0;
    let mut host_cursor = host_entries.unwrap_or(&[]).iter().peekable();
    for (index, entry) in pollfds.iter_mut().enumerate() {
        if entry.fd < 0 {
            entry.revents = 0;
            continue;
        }
        if let Some((handle, _slot_idx)) = fd_map_lookup(fd_map, file_table, entry.fd)
            && handle > 0
            && (handle as usize) <= open_table.len()
        {
            let open_file = &open_table[(handle - 1) as usize];
            if open_file.state.load(Ordering::Acquire) == DELEGATED_STATE_GUEST {
                let readiness = if host_cursor
                    .peek()
                    .is_some_and(|next| next.poll_index as usize == index)
                {
                    host_cursor.next().map_or(0, |next| next.revents)
                } else {
                    0
                };
                let mut revents = entry.events & readiness;
                revents |= readiness & (LINUX_POLLERR | LINUX_POLLHUP | LINUX_POLLNVAL);
                entry.revents = revents;
                if revents != 0 {
                    ready_count += 1;
                }
                continue;
            }
        }
        // Absent descriptor: POLLNVAL unconditionally
        entry.revents = LINUX_POLLNVAL;
        ready_count += 1;
    }
    ready_count
}

/// Owned continuation for a blocking poll.
#[derive(Debug)]
pub struct PollContinuation {
    pub file_table: u64,
    pub pollfds: Vec<PollFd>,
    pub timeout_ms: i32,
    pub user_va: u64,
    pub slot: Option<SlotId>,
}

impl PollContinuation {
    pub fn new(
        file_table: u64,
        pollfds: Vec<PollFd>,
        timeout_ms: i32,
        user_va: u64,
        slot: Option<SlotId>,
    ) -> Self {
        Self {
            file_table,
            pollfds,
            timeout_ms,
            user_va,
            slot,
        }
    }

    /// Releases execution capacity on the zone scheduler by clearing the slot's current task.
    pub fn release_capacity(&mut self, zone: &ZoneTables) {
        if let Some(slot) = self.slot {
            zone.clear_current(slot);
        }
    }

    /// Re-evaluates poll against current table state.
    pub fn poll(
        &mut self,
        fd_map: &[FdMapSlot],
        open_table: &[DelegatedOpenFile],
        object_table: &[DelegatedFile],
        ipc: Option<&crate::personality::ipc::IpcVenue<'_>>,
    ) -> Option<i32> {
        let ready = resolve_poll(
            fd_map,
            open_table,
            object_table,
            ipc,
            self.file_table,
            &mut self.pollfds,
        );
        if ready > 0 { Some(ready) } else { None }
    }

    /// Complete the wait unconditionally, returning (ready_count, pollfds).
    pub fn complete(
        mut self,
        fd_map: &[FdMapSlot],
        open_table: &[DelegatedOpenFile],
        object_table: &[DelegatedFile],
        ipc: Option<&crate::personality::ipc::IpcVenue<'_>>,
    ) -> (i32, Vec<PollFd>) {
        let ready = resolve_poll(
            fd_map,
            open_table,
            object_table,
            ipc,
            self.file_table,
            &mut self.pollfds,
        );
        (ready, self.pollfds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::MAX_ZONE_OPEN_FILES;
    use carrick_sched_core::ThreadIdentity;

    fn resolve_with_native_batch(
        fd_map: &[FdMapSlot],
        open_table: &[DelegatedOpenFile],
        object_table: &[DelegatedFile],
        file_table: u64,
        pollfds: &mut [PollFd],
    ) -> i32 {
        let mut entries = host_readiness_entries(fd_map, open_table, file_table, pollfds)
            .expect("host-bound fixture entries");
        for entry in &mut entries {
            let fd = entry
                .binding
                .stdio_fd()
                .or_else(|| entry.binding.host_fd().map(HostBoundFd::raw))
                .expect("host binding");
            let mut pfd = libc::pollfd {
                fd,
                events: entry.events,
                revents: 0,
            };
            assert!(unsafe { libc::poll(&mut pfd, 1, 0) } >= 0);
            entry.revents = pfd.revents;
        }
        resolve_poll_with_host_readiness(
            fd_map,
            open_table,
            object_table,
            None,
            file_table,
            pollfds,
            Some(&entries),
        )
    }

    #[test]
    fn host_readiness_requires_the_carrier_batch_even_in_vm_free_tests() {
        let (fd_map, open_table, object_table) = setup_tables();
        let mut pipe_fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        admit_host_fd(
            &fd_map,
            &open_table,
            &object_table,
            10,
            1,
            pipe_fds[1],
            DELEGATED_FLAG_WRITABLE,
        );
        let mut pollfds = [PollFd {
            fd: 1,
            events: LINUX_POLLOUT,
            revents: 0,
        }];
        assert_eq!(
            resolve_poll(&fd_map, &open_table, &object_table, None, 10, &mut pollfds),
            0
        );
        assert_eq!(pollfds[0].revents, 0);
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
    }

    #[test]
    fn poll_event_values_come_from_shared_linux_abi() {
        assert_eq!(carrick_syscall_abi::LINUX_POLLIN, 0x0001);
        assert_eq!(carrick_syscall_abi::LINUX_POLLERR, 0x0008);
        assert_eq!(carrick_syscall_abi::LINUX_POLLNVAL, 0x0020);
    }

    fn setup_tables() -> (
        [FdMapSlot; FD_MAP_CAPACITY],
        [DelegatedOpenFile; MAX_ZONE_OPEN_FILES],
        [DelegatedFile; 64],
    ) {
        (
            [const { FdMapSlot::new() }; FD_MAP_CAPACITY],
            [const { DelegatedOpenFile::new() }; MAX_ZONE_OPEN_FILES],
            [const { DelegatedFile::new() }; 64],
        )
    }

    #[test]
    fn test_stdio_open_and_closed_at_launch() {
        let (fd_map, open_table, object_table) = setup_tables();
        let file_table = 10;
        // Admit stdin (0) and stderr (2), stdout (1) closed
        admit_stdio(
            &fd_map,
            &open_table,
            &object_table,
            file_table,
            [true, false, true],
        );

        let mut pfds = vec![
            PollFd {
                fd: 0,
                events: LINUX_POLLIN,
                revents: 0,
            },
            PollFd {
                fd: 1,
                events: LINUX_POLLOUT,
                revents: 0,
            },
            PollFd {
                fd: 2,
                events: LINUX_POLLOUT,
                revents: 0,
            },
        ];
        let ready =
            resolve_with_native_batch(&fd_map, &open_table, &object_table, file_table, &mut pfds);

        // fd 1 is absent -> POLLNVAL
        assert_eq!(pfds[1].revents, LINUX_POLLNVAL);
        assert!(ready >= 1);
    }

    #[test]
    fn dup2_then_close_keeps_the_shared_host_binding() {
        let (fd_map, open_table, object_table) = setup_tables();
        admit_stdio(&fd_map, &open_table, &object_table, 10, [true, true, true]);
        let original = fd_map_lookup(&fd_map, 10, 1).unwrap().0;
        assert_eq!(
            dup2_host_binding(&fd_map, 10, 1, 5, false),
            Some(GuestDescriptorChange {
                fd: 5,
                release: None
            })
        );
        assert_eq!(fd_map_lookup(&fd_map, 10, 5).unwrap().0, original);
        assert_eq!(
            close_host_binding(&fd_map, 10, 1),
            Some(GuestDescriptorChange {
                fd: 1,
                release: None
            })
        );
        assert!(is_closed_stdio_tombstone(&fd_map, 10, 1));
        assert_eq!(fd_map_lookup(&fd_map, 10, 1), None);
        assert_eq!(fd_map_lookup(&fd_map, 10, 5).unwrap().0, original);
        let mut entries = [
            PollFd {
                fd: 5,
                events: LINUX_POLLOUT,
                revents: 0,
            },
            PollFd {
                fd: 1,
                events: LINUX_POLLOUT,
                revents: 0,
            },
        ];
        let readiness = [HostReadinessEntry {
            binding: HostObjectBinding::STDOUT,
            events: LINUX_POLLOUT,
            revents: LINUX_POLLOUT,
            poll_index: 0,
        }];
        let ready = resolve_poll_with_host_readiness(
            &fd_map,
            &open_table,
            &object_table,
            None,
            10,
            &mut entries,
            Some(&readiness),
        );
        assert_eq!(ready, 2);
        assert_eq!(entries[0].revents, LINUX_POLLOUT);
        assert_eq!(entries[1].revents, LINUX_POLLNVAL);
        assert_eq!(
            close_host_binding(&fd_map, 10, 5),
            Some(GuestDescriptorChange {
                fd: 5,
                release: Some(ReleasedDescription {
                    handle: original,
                    incarnation: 1,
                }),
            })
        );
    }

    #[test]
    fn dup3_cloexec_is_per_descriptor_and_fork_inherits_it() {
        let (fd_map, open_table, object_table) = setup_tables();
        admit_stdio(
            &fd_map,
            &open_table,
            &object_table,
            10,
            [false, true, false],
        );
        assert_eq!(dup2_host_binding(&fd_map, 10, 1, 1, true), None);
        assert_eq!(dup2_host_binding(&fd_map, 10, 1, 5, true).unwrap().fd, 5);
        let (_, index) = fd_map_lookup(&fd_map, 10, 5).unwrap();
        assert_eq!(
            fd_map[index].fd_flags.load(Ordering::Acquire),
            GUEST_FD_CLOEXEC
        );
        let (_, original_index) = fd_map_lookup(&fd_map, 10, 1).unwrap();
        assert_eq!(fd_map[original_index].fd_flags.load(Ordering::Acquire), 0);
        assert!(fork_fd_map(&fd_map, 10, 11));
        let (_, child_index) = fd_map_lookup(&fd_map, 11, 5).unwrap();
        assert_eq!(
            fd_map[child_index].fd_flags.load(Ordering::Acquire),
            GUEST_FD_CLOEXEC
        );
        assert_eq!(
            dup2_host_binding(&fd_map, 11, 1, 5, false).unwrap().release,
            None
        );
        assert_eq!(fd_map[child_index].fd_flags.load(Ordering::Acquire), 0);
    }

    #[test]
    fn readmitting_a_table_does_not_reopen_explicitly_closed_stdio() {
        let (fd_map, open_table, object_table) = setup_tables();
        admit_stdio(&fd_map, &open_table, &object_table, 10, [true; 3]);
        assert!(close_host_binding(&fd_map, 10, 1).is_some());
        assert!(is_closed_stdio_tombstone(&fd_map, 10, 1));
        admit_stdio(&fd_map, &open_table, &object_table, 10, [true; 3]);
        assert_eq!(fd_map_lookup(&fd_map, 10, 1), None);
        assert!(is_closed_stdio_tombstone(&fd_map, 10, 1));
    }

    #[test]
    fn dup_reuses_closed_stdin_number() {
        let (fd_map, open_table, object_table) = setup_tables();
        admit_stdio(&fd_map, &open_table, &object_table, 10, [true; 3]);
        close_host_binding(&fd_map, 10, 0).unwrap();
        assert_eq!(
            dup_host_binding(&fd_map, 10, 1, 0, 1024, false).unwrap().fd,
            0
        );
        assert_eq!(fd_map_lookup(&fd_map, 10, 0).unwrap().0, 2);
        assert_eq!(
            dup2_host_binding(&fd_map, 10, 1, GUEST_FD_LIMIT, false),
            None
        );
    }

    #[test]
    fn test_absent_fd_pollnval() {
        let (fd_map, open_table, object_table) = setup_tables();
        let file_table = 10;
        admit_stdio(
            &fd_map,
            &open_table,
            &object_table,
            file_table,
            [true, true, true],
        );

        let mut pfds = vec![PollFd {
            fd: 42,
            events: LINUX_POLLIN,
            revents: 0,
        }];
        let ready = resolve_poll(
            &fd_map,
            &open_table,
            &object_table,
            None,
            file_table,
            &mut pfds,
        );
        assert_eq!(ready, 1);
        assert_eq!(pfds[0].revents, LINUX_POLLNVAL);
    }

    #[test]
    fn test_negative_and_duplicate_entries() {
        let (fd_map, open_table, object_table) = setup_tables();
        let file_table = 10;
        admit_stdio(
            &fd_map,
            &open_table,
            &object_table,
            file_table,
            [true, true, true],
        );

        let mut pfds = vec![
            PollFd {
                fd: -1,
                events: LINUX_POLLIN,
                revents: 0,
            },
            PollFd {
                fd: 42,
                events: LINUX_POLLIN,
                revents: 0,
            },
            PollFd {
                fd: 42,
                events: LINUX_POLLOUT,
                revents: 0,
            },
        ];
        let ready = resolve_poll(
            &fd_map,
            &open_table,
            &object_table,
            None,
            file_table,
            &mut pfds,
        );
        assert_eq!(pfds[0].revents, 0); // negative ignored
        assert_eq!(pfds[1].revents, LINUX_POLLNVAL);
        assert_eq!(pfds[2].revents, LINUX_POLLNVAL);
        assert_eq!(ready, 2);
    }

    #[test]
    fn test_events_zero_reports_err_hup() {
        let (fd_map, open_table, object_table) = setup_tables();
        let file_table = 10;

        // Create a host pipe and close the write end so reader sees POLLHUP
        let mut pipe_fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        unsafe { libc::close(pipe_fds[1]) };

        admit_host_fd(
            &fd_map,
            &open_table,
            &object_table,
            file_table,
            0,
            pipe_fds[0],
            DELEGATED_FLAG_READABLE,
        );

        let mut pfds = vec![PollFd {
            fd: 0,
            events: 0,
            revents: 0,
        }];
        let ready =
            resolve_with_native_batch(&fd_map, &open_table, &object_table, file_table, &mut pfds);
        unsafe { libc::close(pipe_fds[0]) };

        assert_eq!(ready, 1);
        assert_ne!(pfds[0].revents & LINUX_POLLHUP, 0);
    }

    #[test]
    fn test_two_live_process_tables_different_descriptions() {
        let (fd_map, open_table, object_table) = setup_tables();
        let t1 = 10;
        let t2 = 20;
        let mut pipe_fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);

        // Native Linux reports no POLLOUT on a pipe read end, while the
        // write end reports POLLOUT. Access mode alone is not readiness.
        admit_host_fd(
            &fd_map,
            &open_table,
            &object_table,
            t1,
            0,
            pipe_fds[0],
            DELEGATED_FLAG_READABLE,
        );
        // t2 names the other endpoint at the same guest descriptor number.
        admit_host_fd(
            &fd_map,
            &open_table,
            &object_table,
            t2,
            0,
            pipe_fds[1],
            DELEGATED_FLAG_WRITABLE,
        );

        let mut pfds1 = vec![PollFd {
            fd: 0,
            events: LINUX_POLLOUT,
            revents: 0,
        }];
        let ready1 = resolve_with_native_batch(&fd_map, &open_table, &object_table, t1, &mut pfds1);
        // The read endpoint has no writable readiness.
        assert_eq!(pfds1[0].revents, 0);
        assert_eq!(ready1, 0);

        let mut pfds2 = vec![PollFd {
            fd: 0,
            events: LINUX_POLLOUT,
            revents: 0,
        }];
        let ready2 = resolve_with_native_batch(&fd_map, &open_table, &object_table, t2, &mut pfds2);
        // The write endpoint is writable.
        assert_eq!(pfds2[0].revents & LINUX_POLLOUT, LINUX_POLLOUT);
        assert_eq!(ready2, 1);
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
    }

    #[test]
    fn test_fork_inheritance() {
        let (fd_map, open_table, object_table) = setup_tables();
        let parent = 10;
        let child = 20;

        admit_stdio(
            &fd_map,
            &open_table,
            &object_table,
            parent,
            [true, true, true],
        );
        fork_fd_map(&fd_map, parent, child);

        // Both have fd 1 pointing to the same handle
        let parent_lookup = fd_map_lookup(&fd_map, parent, 1).unwrap();
        let child_lookup = fd_map_lookup(&fd_map, child, 1).unwrap();
        assert_eq!(parent_lookup.0, child_lookup.0); // same open description handle

        // Clear child's descriptor
        fd_map[child_lookup.1].clear();
        assert_eq!(fd_map_lookup(&fd_map, child, 1), None);
        // Parent still has it
        assert!(fd_map_lookup(&fd_map, parent, 1).is_some());
    }

    #[test]
    fn exhausted_fork_does_not_publish_a_partial_child_table() {
        let (fd_map, open_table, object_table) = setup_tables();
        admit_stdio(&fd_map, &open_table, &object_table, 10, [true, true, true]);
        for (fd, slot) in fd_map.iter().enumerate().skip(3).take(FD_MAP_CAPACITY - 5) {
            slot.set(99, fd as u32, 1, 1);
        }
        fork_fd_map(&fd_map, 10, 20);
        for fd in 0..3 {
            assert_eq!(fd_map_lookup(&fd_map, 20, fd), None);
        }
    }

    #[test]
    fn exited_child_tables_return_all_fd_map_capacity() {
        let (fd_map, open_table, object_table) = setup_tables();
        admit_stdio(&fd_map, &open_table, &object_table, 10, [true, true, true]);
        for child in 20..100 {
            assert!(fork_fd_map(&fd_map, 10, child));
            for fd in 0..3 {
                assert!(fd_map_lookup(&fd_map, child, fd).is_some());
            }
            retire_fd_map(&fd_map, child);
            for fd in 0..3 {
                assert_eq!(fd_map_lookup(&fd_map, child, fd), None);
            }
        }
    }

    #[test]
    fn test_host_readiness_full_pipe_not_writable() {
        let (fd_map, open_table, object_table) = setup_tables();
        let file_table = 10;

        // Create pipe and make write end non-blocking
        let mut pipe_fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let flags = unsafe { libc::fcntl(pipe_fds[1], libc::F_GETFL) };
        unsafe { libc::fcntl(pipe_fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK) };

        // Fill pipe completely until write returns EAGAIN / EWOULDBLOCK
        let buf = [0x5au8; 4096];
        loop {
            let written = unsafe { libc::write(pipe_fds[1], buf.as_ptr().cast(), buf.len()) };
            if written < 0 {
                break;
            }
        }

        // Host fd write end is NOT writable right now!
        let mut native = libc::pollfd {
            fd: pipe_fds[1],
            events: libc::POLLOUT,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut native, 1, 0) }, 0);
        let host_readiness = native.revents;
        assert_eq!(
            host_readiness & LINUX_POLLOUT,
            0,
            "full pipe must NOT report POLLOUT"
        );

        // Admit as fd 1 in our table
        admit_host_fd(
            &fd_map,
            &open_table,
            &object_table,
            file_table,
            1,
            pipe_fds[1],
            DELEGATED_FLAG_WRITABLE,
        );

        let mut pfds = vec![PollFd {
            fd: 1,
            events: LINUX_POLLOUT,
            revents: 0,
        }];
        let ready =
            resolve_with_native_batch(&fd_map, &open_table, &object_table, file_table, &mut pfds);
        assert_eq!(ready, 0, "full pipe must have 0 ready entries");
        assert_eq!(pfds[0].revents, 0);

        // Now drain bytes from the read end
        let mut drain_buf = [0u8; 4096];
        let n = unsafe { libc::read(pipe_fds[0], drain_buf.as_mut_ptr().cast(), drain_buf.len()) };
        assert!(n > 0);

        // Pipe is writable again!
        let ready_after =
            resolve_with_native_batch(&fd_map, &open_table, &object_table, file_table, &mut pfds);
        assert_eq!(ready_after, 1, "drained pipe must report POLLOUT");
        assert_eq!(pfds[0].revents & LINUX_POLLOUT, LINUX_POLLOUT);

        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
    }

    #[test]
    fn host_fd_zero_binding_is_not_guest_descriptor_number() {
        let (fd_map, open_table, object_table) = setup_tables();
        // The test runner's stdin is a valid host descriptor. Guest descriptor
        // 123 is deliberately unrelated to it and absent on the host.
        assert!(unsafe { libc::fcntl(0, libc::F_GETFD) } >= 0);
        admit_host_fd(
            &fd_map,
            &open_table,
            &object_table,
            10,
            123,
            0,
            DELEGATED_FLAG_READABLE,
        );
        let mut fds = [PollFd {
            fd: 123,
            events: LINUX_POLLIN,
            revents: 0,
        }];
        resolve_poll(&fd_map, &open_table, &object_table, None, 10, &mut fds);
        assert_eq!(fds[0].revents & LINUX_POLLNVAL, 0);
    }

    #[test]
    fn readiness_batch_uses_host_binding_and_preserves_duplicate_results() {
        let (fd_map, open_table, object_table) = setup_tables();
        admit_host_fd(
            &fd_map,
            &open_table,
            &object_table,
            10,
            123,
            0,
            DELEGATED_FLAG_READABLE,
        );
        let mut fds = [
            PollFd {
                fd: 123,
                events: LINUX_POLLIN,
                revents: 0,
            },
            PollFd {
                fd: -1,
                events: LINUX_POLLIN,
                revents: 0,
            },
            PollFd {
                fd: 123,
                events: LINUX_POLLIN,
                revents: 0,
            },
            PollFd {
                fd: 999,
                events: LINUX_POLLIN,
                revents: 0,
            },
        ];
        let mut entries = host_readiness_entries(&fd_map, &open_table, 10, &fds).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].binding.host_fd().map(HostBoundFd::raw), Some(0));
        assert_eq!(entries[0].poll_index, 0);
        assert_eq!(entries[1].binding.host_fd().map(HostBoundFd::raw), Some(0));
        assert_eq!(entries[1].poll_index, 2);
        entries[0].revents = LINUX_POLLIN;
        entries[1].revents = LINUX_POLLIN;
        assert_eq!(
            resolve_poll_with_host_readiness(
                &fd_map,
                &open_table,
                &object_table,
                None,
                10,
                &mut fds,
                Some(&entries)
            ),
            3
        );
        assert_eq!(fds[1].revents, 0);
        assert_eq!(fds[3].revents, LINUX_POLLNVAL);
        assert!(host_readiness_entries(&fd_map, &open_table, 10, &fds[3..]).is_none());
    }

    #[test]
    fn readiness_batch_keeps_host_entries_with_in_zone_descriptions() {
        let (fd_map, open_table, object_table) = setup_tables();
        admit_host_fd(
            &fd_map,
            &open_table,
            &object_table,
            10,
            123,
            0,
            DELEGATED_FLAG_READABLE,
        );
        let in_zone = &open_table[3];
        in_zone
            .state
            .store(DELEGATED_STATE_GUEST, Ordering::Release);
        assert!(fd_map[1].try_claim());
        fd_map[1].set(10, 124, 4, 1);
        let fds = [
            PollFd {
                fd: 124,
                events: LINUX_POLLIN,
                revents: 0,
            },
            PollFd {
                fd: 123,
                events: LINUX_POLLIN,
                revents: 0,
            },
        ];
        let entries = host_readiness_entries(&fd_map, &open_table, 10, &fds)
            .expect("host descriptor remains in the batch");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].poll_index, 1);
    }

    #[test]
    fn test_blocking_poll_releases_capacity_and_completes() {
        let (fd_map, open_table, object_table) = setup_tables();
        let file_table = 10;
        let slot = SlotId::new(0);

        // Allocate a zeroed ZoneTables
        let layout = std::alloc::Layout::new::<ZoneTables>();
        let zone: Box<ZoneTables> = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        };

        let identity = ThreadIdentity {
            tid: 41,
            serial: 101,
            mm: 0,
            file_table,
            generation: 1,
            affinity: 0,
            lifecycle_page: 0,
            control_slot: 0,
        };
        zone.drive(slot, 1);
        zone.publish_slot(slot, 0, None, 0);
        let guard = zone
            .lock(
                ZoneTables::bucket_of(0, 0x1000),
                &carrick_sched_core::BoundedSpin(100),
            )
            .unwrap();
        let record = zone.alloc_record(identity).unwrap();
        let seq = zone.next_seq(record);
        zone.enqueue(&guard, record, seq, 0, 0x1000, u32::MAX, 0)
            .unwrap();
        zone.publish_park(record, seq);
        drop(guard);

        let guard = zone
            .lock(
                ZoneTables::bucket_of(0, 0x1000),
                &carrick_sched_core::BoundedSpin(100),
            )
            .unwrap();
        let mut woken = [const { carrick_sched_core::WakeRecord::Empty }; 1];
        let n = zone
            .wake(
                &guard,
                0,
                0x1000,
                u32::MAX,
                1,
                carrick_sched_core::Waker::El1 { slot },
                &mut woken,
            )
            .unwrap();
        assert_eq!(n, 1);
        drop(guard);

        assert_eq!(zone.switch_in(slot), Some(record));
        // Verify executor slot has current task before release
        assert_eq!(zone.slot(slot).current(), Some(record));

        let pfds = vec![PollFd {
            fd: 0,
            events: LINUX_POLLIN,
            revents: 0,
        }];
        let mut continuation = PollContinuation::new(file_table, pfds, 1000, 0x1000, Some(slot));

        // Release execution capacity: this MUST clear current and free the executor!
        continuation.release_capacity(&zone);
        assert_eq!(
            zone.slot(slot).current(),
            None,
            "release_capacity must vacate current slot, freeing the executor"
        );

        // Now complete the wait
        admit_stdio(
            &fd_map,
            &open_table,
            &object_table,
            file_table,
            [true, true, true],
        );
        let (ready, out_pfds) = continuation.complete(&fd_map, &open_table, &object_table, None);
        assert_eq!(out_pfds.len(), 1);
        assert!(ready >= 0);
    }
}
