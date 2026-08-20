//! io_uring ring engine (WS-H4-B1): the ring-region layout math and the
//! per-SQE completion logic — the correctness-critical core, kept standalone so
//! it can be exhaustively unit-tested before it is wired into the syscall path.
//!
//! Why standalone first: a half-wired io_uring is the one genuinely harmful
//! state — if `io_uring_setup` succeeds but `io_uring_enter` mishandles ops,
//! liburing stops falling back to its (working) epoll path and breaks. So the
//! ring index math and the opcode→CQE mapping are proven here in isolation; the
//! dispatch wiring (`io_uring_setup` allocating the rings in the guest arena,
//! the `mmap(ring_fd, IORING_OFF_*)` integration, and `io_uring_enter` draining
//! the SQ ring) is the atomic step that flips `io_uring_setup` off ENOSYS, and
//! it builds directly on this engine.
//!
//! Phase 1 services NOP/READV/WRITEV/READ/WRITE/FSYNC/CLOSE; every other opcode
//! completes with a CQE `res = -EINVAL`, which is exactly the kernel's response
//! to an unsupported opcode — so even the partial set is non-harmful (apps see
//! a normal CQE error, not a hang).

#![allow(dead_code)] // complete_sqe/opcode_serviced are the unit-tested reference; the
// wired enter path inlines the op match for borrow simplicity.

use super::*;
use crate::linux_abi::{
    LINUX_IORING_ENTER_FLAGS_MASK, LINUX_IORING_FEAT_SINGLE_MMAP, LINUX_IORING_OFF_CQ_RING,
    LINUX_IORING_OFF_SQ_RING, LINUX_IORING_OFF_SQES, LINUX_IORING_OP_ACCEPT, LINUX_IORING_OP_CLOSE,
    LINUX_IORING_OP_CONNECT, LINUX_IORING_OP_FSYNC, LINUX_IORING_OP_NOP, LINUX_IORING_OP_POLL_ADD,
    LINUX_IORING_OP_READ, LINUX_IORING_OP_READV, LINUX_IORING_OP_RECV, LINUX_IORING_OP_RECVMSG,
    LINUX_IORING_OP_SEND, LINUX_IORING_OP_SENDMSG, LINUX_IORING_OP_WRITE, LINUX_IORING_OP_WRITEV,
    LinuxIoCqringOffsets, LinuxIoSqringOffsets, LinuxIoUringCqe, LinuxIoUringParams,
    LinuxIoUringSqe, LinuxIovec, LinuxMsghdr,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use zerocopy::{FromBytes, IntoBytes};

const U32: u32 = 4;
const SUPPORTED_SETUP_FLAGS: u32 = 0;

/// The byte layout carrick uses for a ring's mmapped regions. The SQ ring and
/// CQ ring share one mapping (IORING_FEAT_SINGLE_MMAP); the SQE array is a
/// second mapping. All offsets are reported to the guest via io_uring_params,
/// so carrick is free to choose them as long as params describes them honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RingLayout {
    pub sq_entries: u32,
    pub cq_entries: u32,
    /// Size of the combined SQ+CQ ring mapping (IORING_OFF_SQ_RING).
    pub ring_bytes: usize,
    /// Size of the SQE-array mapping (IORING_OFF_SQES).
    pub sqes_bytes: usize,
    sq_off: LinuxIoSqringOffsets,
    cq_off: LinuxIoCqringOffsets,
    cqes_offset: u32,
}

impl RingLayout {
    /// Compute the layout for `requested` SQ entries (rounded up to a power of
    /// two, min 1; CQ ring is 2× per the kernel default).
    pub(crate) fn new(requested: u32) -> Self {
        let sq_entries = requested.max(1).next_power_of_two();
        let cq_entries = sq_entries.saturating_mul(2);

        // SQ ring region: 8 u32 control words, then the index `array`
        // (sq_entries u32s). We place the control words first.
        let sq_head = 0;
        let sq_tail = U32;
        let sq_ring_mask = 2 * U32;
        let sq_ring_entries = 3 * U32;
        let sq_flags = 4 * U32;
        let sq_dropped = 5 * U32;
        let sq_array = 8 * U32; // leave 6,7 reserved, 8-align the array
        let sq_array_end = sq_array + sq_entries * U32;

        // CQ ring region follows, in the same mapping. cqes are 16 bytes each.
        let cq_base = align_up_u32(sq_array_end, 64);
        let cq_head = cq_base;
        let cq_tail = cq_base + U32;
        let cq_ring_mask = cq_base + 2 * U32;
        let cq_ring_entries = cq_base + 3 * U32;
        let cq_overflow = cq_base + 4 * U32;
        let cq_flags = cq_base + 5 * U32;
        let cqes_offset = align_up_u32(cq_base + 8 * U32, 64);
        let ring_bytes = (cqes_offset + cq_entries * 16) as usize;
        let sqes_bytes = (sq_entries as usize) * core::mem::size_of::<LinuxIoUringSqe>();

        Self {
            sq_entries,
            cq_entries,
            ring_bytes,
            sqes_bytes,
            sq_off: LinuxIoSqringOffsets {
                head: sq_head,
                tail: sq_tail,
                ring_mask: sq_ring_mask,
                ring_entries: sq_ring_entries,
                flags: sq_flags,
                dropped: sq_dropped,
                array: sq_array,
                resv1: 0,
                resv2: 0,
            },
            cq_off: LinuxIoCqringOffsets {
                head: cq_head,
                tail: cq_tail,
                ring_mask: cq_ring_mask,
                ring_entries: cq_ring_entries,
                overflow: cq_overflow,
                cqes: cqes_offset,
                flags: cq_flags,
                resv1: 0,
                resv2: 0,
            },
            cqes_offset,
        }
    }

    /// Fill the out-param the guest reads after `io_uring_setup`.
    pub(crate) fn fill_params(&self, params: &mut LinuxIoUringParams) {
        params.sq_entries = self.sq_entries;
        params.cq_entries = self.cq_entries;
        params.features = LINUX_IORING_FEAT_SINGLE_MMAP;
        params.sq_off = self.sq_off;
        params.cq_off = self.cq_off;
    }
}

fn align_up_u32(v: u32, align: u32) -> u32 {
    v.div_ceil(align) * align
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IoUringRegion {
    SqCq,
    Sqes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IoUringRegionLayout {
    pub guest_mmap_offset: u64,
    pub backing_offset: u64,
    pub required_len: u64,
    pub mapped_extent: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HostBackingIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IoUringLayoutSnapshot {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub ring_bytes: u64,
    pub sqes_bytes: u64,
    pub sqes_backing_offset: u64,
    pub backing_len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoUringDescriptionSnapshot {
    pub layout: IoUringLayoutSnapshot,
    pub data_identity: HostBackingIdentity,
    pub lock_identity: HostBackingIdentity,
    pub backing_len: u64,
    pub status_flags: u64,
    pub logical_fd_refs: usize,
}

struct SharedMapping {
    ptr: *mut u8,
    len: usize,
}

unsafe impl Send for SharedMapping {}
unsafe impl Sync for SharedMapping {}

impl SharedMapping {
    fn map(fd: i32, len: usize) -> Result<Self, crate::linux_abi::LinuxErrno> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(linux_errno::ENOMEM);
        }
        Ok(Self {
            ptr: ptr.cast(),
            len,
        })
    }

    fn bytes(&self, offset: u64, len: usize) -> Option<&[u8]> {
        let offset = usize::try_from(offset).ok()?;
        let end = offset.checked_add(len)?;
        (end <= self.len).then(|| unsafe { std::slice::from_raw_parts(self.ptr.add(offset), len) })
    }

    fn write_bytes(&self, offset: u64, bytes: &[u8]) -> Option<()> {
        let offset = usize::try_from(offset).ok()?;
        let end = offset.checked_add(bytes.len())?;
        if end > self.len {
            return None;
        }
        // Queue payload access is serialized by the io_uring backing's local
        // and cross-process locks. Control words use atomic_u32 instead.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(offset), bytes.len());
        }
        Some(())
    }

    fn atomic_u32(&self, offset: u64) -> Option<&AtomicU32> {
        let offset = usize::try_from(offset).ok()?;
        let end = offset.checked_add(core::mem::size_of::<AtomicU32>())?;
        (end <= self.len && (unsafe { self.ptr.add(offset) } as usize).is_multiple_of(4))
            .then(|| unsafe { &*self.ptr.add(offset).cast::<AtomicU32>() })
    }
}

impl Drop for SharedMapping {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }
}

pub(crate) struct IoUringBacking {
    layout: RingLayout,
    regions: [IoUringRegionLayout; 2],
    data_fd: OwnedFd,
    data_identity: HostBackingIdentity,
    control_view: SharedMapping,
    lock_fd: OwnedFd,
    lock_identity: HostBackingIdentity,
    local_enter: parking_lot::Mutex<()>,
    /// Generic anonymous-inode metadata (status flags, fd-reference count,
    /// and `/proc/self/fd` label) owned by this typed ring backing. Queue and
    /// mapping authority never live in this view.
    open_metadata: parking_lot::RwLock<OpenDescription>,
}

impl std::fmt::Debug for IoUringBacking {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IoUringBacking")
            .field("layout", &self.layout)
            .field("data_identity", &self.data_identity)
            .field("lock_identity", &self.lock_identity)
            .finish_non_exhaustive()
    }
}

fn host_identity(fd: i32) -> Result<(HostBackingIdentity, u64), crate::linux_abi::LinuxErrno> {
    let mut stat: libc::stat = unsafe { core::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 || stat.st_size < 0 {
        return Err(linux_errno::EIO);
    }
    Ok((
        HostBackingIdentity {
            device: stat.st_dev as u64,
            inode: stat.st_ino,
        },
        stat.st_size as u64,
    ))
}

impl IoUringBacking {
    pub(crate) fn create(
        entries: u32,
        page_size: u64,
    ) -> Result<Arc<Self>, crate::linux_abi::LinuxErrno> {
        let layout = RingLayout::new(entries);
        let host_page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|page| *page != 0)
            .and_then(|page| u64::try_from(page).ok())
            .unwrap_or(page_size);
        let backing_granule = page_size.max(host_page_size);
        let ring_extent = align_up_u64(layout.ring_bytes as u64, backing_granule)
            .ok_or(linux_errno::EOVERFLOW)?;
        let sqes_extent = align_up_u64(layout.sqes_bytes as u64, backing_granule)
            .ok_or(linux_errno::EOVERFLOW)?;
        let backing_len = ring_extent
            .checked_add(sqes_extent)
            .ok_or(linux_errno::EOVERFLOW)?;
        let data_file = tempfile::tempfile().map_err(|_| linux_errno::ENOMEM)?;
        let data_fd: OwnedFd = data_file.into();
        if unsafe { libc::ftruncate(data_fd.as_raw_fd(), backing_len as libc::off_t) } != 0 {
            return Err(linux_errno::ENOMEM);
        }
        let lock_file = tempfile::tempfile().map_err(|_| linux_errno::ENOMEM)?;
        let lock_fd: OwnedFd = lock_file.into();
        if unsafe { libc::ftruncate(lock_fd.as_raw_fd(), 1) } != 0 {
            return Err(linux_errno::ENOMEM);
        }
        for fd in [data_fd.as_raw_fd(), lock_fd.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
            {
                return Err(linux_errno::EIO);
            }
        }
        let (data_identity, actual_len) = host_identity(data_fd.as_raw_fd())?;
        if actual_len != backing_len {
            return Err(linux_errno::EIO);
        }
        let (lock_identity, lock_len) = host_identity(lock_fd.as_raw_fd())?;
        if lock_len != 1 || data_identity == lock_identity {
            return Err(linux_errno::EIO);
        }
        let control_view = SharedMapping::map(
            data_fd.as_raw_fd(),
            usize::try_from(backing_len).map_err(|_| linux_errno::EOVERFLOW)?,
        )?;
        let backing = Arc::new(Self {
            layout,
            regions: [
                IoUringRegionLayout {
                    guest_mmap_offset: LINUX_IORING_OFF_SQ_RING,
                    backing_offset: 0,
                    required_len: layout.ring_bytes as u64,
                    mapped_extent: ring_extent,
                },
                IoUringRegionLayout {
                    guest_mmap_offset: LINUX_IORING_OFF_SQES,
                    backing_offset: ring_extent,
                    required_len: layout.sqes_bytes as u64,
                    mapped_extent: sqes_extent,
                },
            ],
            data_fd,
            data_identity,
            control_view,
            lock_fd,
            lock_identity,
            local_enter: parking_lot::Mutex::new(()),
            open_metadata: parking_lot::RwLock::new(OpenDescription::SyntheticFile {
                base: OpenDescriptionBase::new(LINUX_O_RDWR),
                path: "anon_inode:[io_uring]".to_owned(),
                contents: Vec::new(),
                offset: 0,
            }),
        });
        backing.initialize_controls()?;
        Ok(backing)
    }

    fn initialize_controls(&self) -> Result<(), crate::linux_abi::LinuxErrno> {
        for (offset, value) in [
            (self.layout.sq_off.ring_mask, self.layout.sq_entries - 1),
            (self.layout.sq_off.ring_entries, self.layout.sq_entries),
            (self.layout.cq_off.ring_mask, self.layout.cq_entries - 1),
            (self.layout.cq_off.ring_entries, self.layout.cq_entries),
        ] {
            self.control_view
                .atomic_u32(offset as u64)
                .ok_or(linux_errno::EIO)?
                .store(value, Ordering::Relaxed);
        }
        Ok(())
    }

    pub(crate) fn region(&self, offset: u64) -> Option<(IoUringRegion, IoUringRegionLayout)> {
        match offset {
            LINUX_IORING_OFF_SQ_RING | LINUX_IORING_OFF_CQ_RING => {
                Some((IoUringRegion::SqCq, self.regions[0]))
            }
            LINUX_IORING_OFF_SQES => Some((IoUringRegion::Sqes, self.regions[1])),
            _ => None,
        }
    }

    #[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn reexec_fds(&self) -> [(i32, i32, HostBackingIdentity); 2] {
        let record = |fd: &OwnedFd, identity| {
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
            (fd.as_raw_fd(), flags, identity)
        };
        [
            record(&self.data_fd, self.data_identity),
            record(&self.lock_fd, self.lock_identity),
        ]
    }

    #[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn reexec_layout(&self) -> IoUringLayoutSnapshot {
        self.layout_snapshot()
    }

    #[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
    pub(crate) fn restore(
        data_fd: OwnedFd,
        lock_fd: OwnedFd,
        expected_data: HostBackingIdentity,
        expected_lock: HostBackingIdentity,
        snapshot: IoUringLayoutSnapshot,
    ) -> Result<Arc<Self>, crate::linux_abi::LinuxErrno> {
        let layout = RingLayout::new(snapshot.sq_entries);
        if layout.sq_entries != snapshot.sq_entries
            || layout.cq_entries != snapshot.cq_entries
            || layout.ring_bytes as u64 != snapshot.ring_bytes
            || layout.sqes_bytes as u64 != snapshot.sqes_bytes
        {
            return Err(linux_errno::EINVAL);
        }
        let (data_identity, backing_len) = host_identity(data_fd.as_raw_fd())?;
        let (lock_identity, lock_len) = host_identity(lock_fd.as_raw_fd())?;
        if data_identity != expected_data
            || lock_identity != expected_lock
            || backing_len != snapshot.backing_len
            || lock_len != 1
            || snapshot.sqes_backing_offset < snapshot.ring_bytes
            || snapshot
                .sqes_backing_offset
                .checked_add(snapshot.sqes_bytes)
                .is_none_or(|end| end > backing_len)
        {
            return Err(linux_errno::EINVAL);
        }
        let ring_extent = snapshot.sqes_backing_offset;
        let sqes_extent = backing_len - ring_extent;
        let control_view = SharedMapping::map(
            data_fd.as_raw_fd(),
            usize::try_from(backing_len).map_err(|_| linux_errno::EOVERFLOW)?,
        )?;
        Ok(Arc::new(Self {
            layout,
            regions: [
                IoUringRegionLayout {
                    guest_mmap_offset: LINUX_IORING_OFF_SQ_RING,
                    backing_offset: 0,
                    required_len: snapshot.ring_bytes,
                    mapped_extent: ring_extent,
                },
                IoUringRegionLayout {
                    guest_mmap_offset: LINUX_IORING_OFF_SQES,
                    backing_offset: ring_extent,
                    required_len: snapshot.sqes_bytes,
                    mapped_extent: sqes_extent,
                },
            ],
            data_fd,
            data_identity,
            control_view,
            lock_fd,
            lock_identity,
            local_enter: parking_lot::Mutex::new(()),
            open_metadata: parking_lot::RwLock::new(OpenDescription::SyntheticFile {
                base: OpenDescriptionBase::new(LINUX_O_RDWR),
                path: "anon_inode:[io_uring]".to_owned(),
                contents: Vec::new(),
                offset: 0,
            }),
        }))
    }

    pub(in crate::dispatch) fn open_metadata(&self) -> &parking_lot::RwLock<OpenDescription> {
        &self.open_metadata
    }

    pub(in crate::dispatch) fn ready_events(&self, requested: u32) -> u32 {
        let mut ready = requested & LINUX_EPOLLOUT;
        let cq_head = self.load_u32(self.layout.cq_off.head as u64, Ordering::Acquire);
        let cq_tail = self.load_u32(self.layout.cq_off.tail as u64, Ordering::Acquire);
        if cq_head
            .zip(cq_tail)
            .is_some_and(|(head, tail)| head != tail)
        {
            ready |= requested & LINUX_EPOLLIN;
        }
        ready
    }

    pub(crate) fn dup_data_fd(&self) -> Option<OwnedFd> {
        let fd = unsafe { libc::dup(self.data_fd.as_raw_fd()) };
        (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn load_u32(&self, offset: u64, ordering: Ordering) -> Option<u32> {
        self.control_view
            .atomic_u32(offset)
            .map(|word| word.load(ordering))
    }

    fn store_u32(&self, offset: u64, value: u32, ordering: Ordering) -> Option<()> {
        self.control_view.atomic_u32(offset)?.store(value, ordering);
        Some(())
    }

    fn read_value<T: FromBytes + Copy>(&self, offset: u64) -> Option<T> {
        let bytes = self.control_view.bytes(offset, core::mem::size_of::<T>())?;
        T::read_from_bytes(bytes).ok()
    }

    fn write_value<T: IntoBytes + zerocopy::Immutable>(
        &self,
        offset: u64,
        value: &T,
    ) -> Option<()> {
        self.control_view.write_bytes(offset, value.as_bytes())
    }

    fn cross_process_lock(&self) -> Option<CrossProcessLock<'_>> {
        let mut lock: libc::flock = unsafe { core::mem::zeroed() };
        lock.l_type = libc::F_WRLCK;
        lock.l_whence = libc::SEEK_SET as i16;
        lock.l_start = 0;
        lock.l_len = 1;
        loop {
            if unsafe { libc::fcntl(self.lock_fd.as_raw_fd(), libc::F_SETLKW, &lock) } == 0 {
                return Some(CrossProcessLock { backing: self });
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return None;
            }
        }
    }

    fn layout_snapshot(&self) -> IoUringLayoutSnapshot {
        IoUringLayoutSnapshot {
            sq_entries: self.layout.sq_entries,
            cq_entries: self.layout.cq_entries,
            ring_bytes: self.layout.ring_bytes as u64,
            sqes_bytes: self.layout.sqes_bytes as u64,
            sqes_backing_offset: self.regions[1].backing_offset,
            backing_len: self.regions[1].backing_offset + self.regions[1].mapped_extent,
        }
    }
}

struct CrossProcessLock<'a> {
    backing: &'a IoUringBacking,
}

impl Drop for CrossProcessLock<'_> {
    fn drop(&mut self) {
        let mut lock: libc::flock = unsafe { core::mem::zeroed() };
        lock.l_type = libc::F_UNLCK;
        lock.l_whence = libc::SEEK_SET as i16;
        lock.l_start = 0;
        lock.l_len = 1;
        if unsafe { libc::fcntl(self.backing.lock_fd.as_raw_fd(), libc::F_SETLK, &lock) } != 0 {
            std::process::abort();
        }
    }
}

impl crate::kernel::FileDescriptionBacking for IoUringBacking {
    fn is_epoll(&self) -> bool {
        false
    }

    fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<crate::kernel::FileDescriptionBackingSnapshot> {
        let metadata = self.open_metadata.try_read_until(deadline)?;
        Some(crate::kernel::FileDescriptionBackingSnapshot::IoUring(
            IoUringDescriptionSnapshot {
                layout: self.layout_snapshot(),
                data_identity: self.data_identity,
                lock_identity: self.lock_identity,
                backing_len: self.layout_snapshot().backing_len,
                status_flags: metadata.status_flags(),
                logical_fd_refs: metadata.fd_ref_count(),
            },
        ))
    }

    fn epoll_wake_fd(&self) -> Option<i32> {
        None
    }
    fn retain_fd_ref(&self) {
        self.open_metadata.read().retain_fd_ref();
    }
    fn release_fd_ref(&self) {
        self.open_metadata.read().release_fd_ref();
    }
    fn fd_ref_count(&self) -> usize {
        self.open_metadata.read().fd_ref_count()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IoUringMapping {
    pub description: Arc<crate::kernel::FileDescription>,
    pub region: IoUringRegion,
    pub start: u64,
    pub end: u64,
    pub backing_offset: u64,
}

impl PartialEq for IoUringMapping {
    fn eq(&self, other: &Self) -> bool {
        self.description.id() == other.description.id()
            && self.region == other.region
            && self.start == other.start
            && self.end == other.end
            && self.backing_offset == other.backing_offset
    }
}
impl Eq for IoUringMapping {}

impl IoUringMapping {
    pub(crate) fn fragment(&self, start: u64, end: u64) -> Self {
        Self {
            description: Arc::clone(&self.description),
            region: self.region,
            start,
            end,
            backing_offset: self.backing_offset + (start - self.start),
        }
    }

    pub(crate) fn snapshot(&self) -> IoUringMappingSnapshot {
        IoUringMappingSnapshot {
            description: Arc::clone(&self.description),
            region: self.region,
            start: self.start,
            end: self.end,
            backing_offset: self.backing_offset,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IoUringMappingSnapshot {
    pub description: Arc<crate::kernel::FileDescription>,
    pub region: IoUringRegion,
    pub start: u64,
    pub end: u64,
    pub backing_offset: u64,
}

/// Outcome of attempting an async (readiness-driven) op: it either completed
/// now, or would block and must wait on `host_fd` for `events`.
enum AsyncOutcome {
    Ready(i32),
    Block(i32, i16),
}

/// An errno in the io_uring CQE `res` field: the CQE result is the Linux
/// syscall retval domain narrowed to the wire's `i32` — negative errno on
/// failure. Routes through THE negation choke point
/// ([`LinuxErrno::guest_retval`]); the narrowing cast is lossless (errnos are
/// 1..=4095).
fn cqe_err(e: crate::linux_abi::LinuxErrno) -> i32 {
    e.guest_retval() as i32
}

/// Opcodes serviced via the kqueue/ThreadWaiter readiness path (SEND/RECV on
/// sockets, POLL_ADD) — they may need to wait, so the enter loop routes them
/// through `try_async_op` rather than the synchronous `io_uring_run_op`.
fn is_async_op(op: u8) -> bool {
    matches!(
        op,
        LINUX_IORING_OP_SEND
            | LINUX_IORING_OP_RECV
            | LINUX_IORING_OP_SENDMSG
            | LINUX_IORING_OP_RECVMSG
            | LINUX_IORING_OP_POLL_ADD
            | LINUX_IORING_OP_ACCEPT
            | LINUX_IORING_OP_CONNECT
    )
}

/// Read the iovec array referenced by a Linux `msghdr` at `addr` (RECVMSG/
/// SENDMSG point their SQE at one). msg_name/msg_control are ignored — carrick
/// services connected-socket message I/O, the common io_uring case.
fn read_msghdr_iovecs(memory: &impl GuestMemory, addr: u64) -> Option<Vec<LinuxIovec>> {
    let bytes = memory
        .read_bytes(addr, core::mem::size_of::<LinuxMsghdr>())
        .ok()?;
    let (mh, _) = LinuxMsghdr::read_from_prefix(&bytes).ok()?;
    let (iov, iovlen) = (mh.iov, mh.iovlen); // copy packed fields to locals
    read_iovecs(memory, iov, iovlen as usize)
}

/// True for the opcodes carrick phase 1 actually executes (the rest complete
/// with -EINVAL). Exposed so the enter path can decide whether to invoke I/O.
pub(crate) fn opcode_serviced(op: u8) -> bool {
    matches!(
        op,
        LINUX_IORING_OP_NOP
            | LINUX_IORING_OP_READV
            | LINUX_IORING_OP_WRITEV
            | LINUX_IORING_OP_READ
            | LINUX_IORING_OP_WRITE
            | LINUX_IORING_OP_FSYNC
            | LINUX_IORING_OP_CLOSE
    )
}

/// Build the completion for one submission. NOP completes with 0; serviced I/O
/// opcodes are run by `io` (which returns bytes transferred or `-errno`); any
/// other opcode completes with `-EINVAL`, matching the kernel's handling of an
/// unsupported opcode. The CQE carries the SQE's `user_data` unchanged.
pub(crate) fn complete_sqe(
    sqe: &LinuxIoUringSqe,
    io: impl FnOnce(&LinuxIoUringSqe) -> i32,
) -> LinuxIoUringCqe {
    let res = match sqe.opcode {
        LINUX_IORING_OP_NOP => 0,
        op if opcode_serviced(op) => io(sqe),
        _ => cqe_err(LINUX_EINVAL),
    };
    LinuxIoUringCqe {
        user_data: sqe.user_data,
        res,
        flags: 0,
    }
}

fn read_ring_u32(memory: &impl GuestMemory, addr: u64) -> u32 {
    memory
        .read_bytes(addr, 4)
        .ok()
        .and_then(|b| <[u8; 4]>::try_from(b.as_slice()).ok())
        .map(u32::from_ne_bytes)
        .unwrap_or(0)
}

fn write_ring_u32(memory: &mut impl GuestMemory, addr: u64, v: u32) {
    let _ = memory.write_bytes(addr, &v.to_ne_bytes());
}

/// Read `count` `iovec`s (16 bytes each) from the guest array at `addr`. `count`
/// is capped at IOV_MAX (1024) so a bogus SQE can't drive an unbounded alloc.
fn read_iovecs(memory: &impl GuestMemory, addr: u64, count: usize) -> Option<Vec<LinuxIovec>> {
    if count > 1024 {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let bytes = memory.read_bytes(addr + (i as u64) * 16, 16).ok()?;
        let (iov, _) = LinuxIovec::read_from_prefix(&bytes).ok()?;
        out.push(iov);
    }
    Some(out)
}

/// Read each iovec's `[iov_base, iov_len)` from guest memory and concatenate
/// into one host buffer (the gather half of WRITEV/SENDMSG). `Err(())` on a
/// guest-memory fault; the caller maps it to its own error encoding.
fn gather_iovecs(memory: &impl GuestMemory, iovs: &[LinuxIovec]) -> Result<Vec<u8>, ()> {
    let mut buf = Vec::new();
    for v in iovs {
        let chunk = memory
            .read_bytes(v.iov_base, v.iov_len as usize)
            .map_err(|_| ())?;
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Scatter `data` across the iovecs in order, writing at most `iov_len` bytes
/// per iovec and stopping once `data` is exhausted (the scatter half of
/// READV/RECVMSG). `Err(())` on a guest-memory fault.
fn scatter_to_iovecs(
    memory: &mut impl GuestMemory,
    iovs: &[LinuxIovec],
    data: &[u8],
) -> Result<(), ()> {
    let mut done = 0usize;
    for v in iovs {
        if done >= data.len() {
            break;
        }
        let chunk = (v.iov_len as usize).min(data.len() - done);
        memory
            .write_bytes(v.iov_base, &data[done..done + chunk])
            .map_err(|_| ())?;
        done += chunk;
    }
    Ok(())
}

impl SyscallDispatcher {
    /// `io_uring_setup(entries, params)`: construct one persistent typed open
    /// file description. Guest virtual mappings are created only by mmap.
    pub(in crate::dispatch) fn io_uring_setup_impl(
        &self,
        memory: &mut impl GuestMemory,
        entries: u32,
        params_ptr: u64,
    ) -> DispatchOutcome {
        if entries == 0 || entries > 4096 {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        let Some(user_params) = memory
            .read_bytes(params_ptr, core::mem::size_of::<LinuxIoUringParams>())
            .ok()
            .and_then(|b| {
                LinuxIoUringParams::read_from_prefix(&b)
                    .ok()
                    .map(|(params, _)| params)
            })
        else {
            return DispatchOutcome::errno(LINUX_EFAULT);
        };
        if user_params.flags & !SUPPORTED_SETUP_FLAGS != 0 {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        let backing = match IoUringBacking::create(entries, self.linux_page_size()) {
            Ok(backing) => backing,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        let mut params = LinuxIoUringParams::default();
        backing.layout.fill_params(&mut params);
        if memory.write_bytes(params_ptr, params.as_bytes()).is_err() {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }

        let description = Arc::new(
            crate::kernel::FileDescription::concrete(backing).unwrap_or_else(|error| {
                tracing::error!(%error, "io_uring description identity allocation failed");
                std::process::abort();
            }),
        );
        let Ok(fd) = self.install_fd_at_or_above(3, OpenFile::new(description, 0)) else {
            return DispatchOutcome::errno(linux_errno::EMFILE);
        };
        DispatchOutcome::Returned { value: fd as i64 }
    }

    pub(in crate::dispatch) fn io_uring_description(
        &self,
        fd: i32,
    ) -> Option<Arc<crate::kernel::FileDescription>> {
        let description = self.open_file(fd)?.description;
        if description.concrete_backing::<IoUringBacking>().is_some() {
            Some(description)
        } else {
            None
        }
    }

    /// `io_uring_enter(fd, to_submit, …)`: drain up to `to_submit` SQEs from the
    /// SQ ring, run each, and post a CQE. Synchronous — every completion is
    /// ready by the time enter returns, so `min_complete` is already satisfied.
    pub(in crate::dispatch) fn io_uring_enter_impl(
        &self,
        memory: &mut impl GuestMemory,
        fd: i32,
        to_submit: u32,
        flags: u32,
        argp: u64,
        argsz: u64,
    ) -> DispatchOutcome {
        let Some(description) = self.io_uring_description(fd) else {
            return DispatchOutcome::errno(LINUX_EINVAL);
        };
        let Some(backing) = description.concrete_backing::<IoUringBacking>() else {
            return DispatchOutcome::errno(LINUX_EINVAL);
        };
        // Reject any flag bit Linux does not define (before consuming the SQ
        // ring, matching the kernel entry check). carrick services neither the
        // SQPOLL kthread nor the EXT_ARG getevents timeout/sigmask struct, so
        // reject EXT_ARG and any nonzero argp/argsz too, rather than silently
        // ignoring them. (audit M4; probe iouringenterflag)
        if flags & !LINUX_IORING_ENTER_FLAGS_MASK != 0
            || carrick_abi::LinuxIoUringEnterFlags::from_bits_truncate(flags)
                .contains(carrick_abi::LinuxIoUringEnterFlags::EXT_ARG)
            || argp != 0
            || argsz != 0
        {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        let _local_enter = backing.local_enter.lock();
        let Some(_cross_process) = backing.cross_process_lock() else {
            return DispatchOutcome::errno(linux_errno::EIO);
        };
        let layout = backing.layout;
        let sq_mask = layout.sq_entries - 1;
        let cq_mask = layout.cq_entries - 1;

        let Some(sq_tail) = backing.load_u32(layout.sq_off.tail as u64, Ordering::Acquire) else {
            return DispatchOutcome::errno(linux_errno::EIO);
        };
        let Some(mut sq_head) = backing.load_u32(layout.sq_off.head as u64, Ordering::Relaxed)
        else {
            return DispatchOutcome::errno(linux_errno::EIO);
        };
        let Some(mut cq_tail) = backing.load_u32(layout.cq_off.tail as u64, Ordering::Relaxed)
        else {
            return DispatchOutcome::errno(linux_errno::EIO);
        };
        let mut processed: u32 = 0;

        // Process submitted SQEs in order. Synchronous ops (and ready async ops)
        // complete inline; an async op that would block hands off to the runtime's
        // kqueue wait via WaitOnFds WITHOUT advancing sq_head — so the re-dispatch
        // resumes at the same op (all ring state lives in guest memory, which
        // persists across the re-dispatch). carrick assumes `to_submit` matches
        // the number of SQEs the guest queued (the liburing invariant); ops run in
        // submission order (head-of-line), not Linux's out-of-order async.
        while sq_head != sq_tail && processed < to_submit {
            let arr_slot = layout.sq_off.array as u64 + ((sq_head & sq_mask) as u64) * 4;
            let sqe_idx = backing
                .load_u32(arr_slot, Ordering::Acquire)
                .unwrap_or(layout.sq_entries);
            let sqe_offset = backing.regions[1].backing_offset + (sqe_idx as u64) * 64;
            let sqe = (sqe_idx < layout.sq_entries)
                .then(|| backing.read_value::<LinuxIoUringSqe>(sqe_offset))
                .flatten();
            let res = match &sqe {
                Some(sqe) if is_async_op(sqe.opcode) => match self.try_async_op(memory, sqe) {
                    AsyncOutcome::Ready(res) => res,
                    AsyncOutcome::Block(host_fd, events) => {
                        // Persist progress and wait on readiness; the runtime
                        // re-dispatches io_uring_enter, which resumes here.
                        let _ = backing.store_u32(
                            layout.sq_off.head as u64,
                            sq_head,
                            Ordering::Release,
                        );
                        let _ = backing.store_u32(
                            layout.cq_off.tail as u64,
                            cq_tail,
                            Ordering::Release,
                        );
                        return DispatchOutcome::WaitOnFds {
                            fds: WaitFds::raw_one(host_fd, events),
                            timeout: None,
                            on_timeout: 0,
                            sig_mask: carrick_abi::WaitSigMask::NONE,
                        };
                    }
                },
                Some(sqe) => self.io_uring_run_op(memory, sqe),
                None => cqe_err(LINUX_EFAULT),
            };
            let cqe = LinuxIoUringCqe {
                user_data: sqe.map(|s| s.user_data).unwrap_or(0),
                res,
                flags: 0,
            };
            let cq_head = backing
                .load_u32(layout.cq_off.head as u64, Ordering::Acquire)
                .unwrap_or(cq_tail);
            if cq_tail.wrapping_sub(cq_head) < layout.cq_entries {
                let cqe_offset = layout.cq_off.cqes as u64 + ((cq_tail & cq_mask) as u64) * 16;
                let _ = backing.write_value(cqe_offset, &cqe);
                cq_tail = cq_tail.wrapping_add(1);
            } else if let Some(overflow) =
                backing.load_u32(layout.cq_off.overflow as u64, Ordering::Relaxed)
            {
                let _ = backing.store_u32(
                    layout.cq_off.overflow as u64,
                    overflow.wrapping_add(1),
                    Ordering::Release,
                );
            }
            sq_head = sq_head.wrapping_add(1);
            processed = processed.wrapping_add(1);
        }
        // Publish the consumed SQ head and the produced CQ tail back to the guest.
        let _ = backing.store_u32(layout.sq_off.head as u64, sq_head, Ordering::Release);
        let _ = backing.store_u32(layout.cq_off.tail as u64, cq_tail, Ordering::Release);
        // Number of SQEs this call submitted (bounded by to_submit; correct
        // across a WaitOnFds re-dispatch, which recounts only still-pending SQEs).
        DispatchOutcome::Returned {
            value: processed as i64,
        }
    }

    /// Execute one SQE, returning the CQE `res` (bytes transferred or `-errno`).
    /// Phase 1: NOP and host-file READ/WRITE; any other opcode → `-EINVAL`,
    /// matching the kernel's response to an unsupported opcode.
    fn io_uring_run_op(&self, memory: &mut impl GuestMemory, sqe: &LinuxIoUringSqe) -> i32 {
        match sqe.opcode {
            LINUX_IORING_OP_NOP => 0,
            LINUX_IORING_OP_READ => {
                let Some(hfd) = self.regular_host_file_fd(sqe.fd) else {
                    return cqe_err(LINUX_EINVAL);
                };
                let len = sqe.len as usize;
                let mut buf = vec![0u8; len];
                let n = unsafe {
                    libc::pread(
                        hfd.get(),
                        buf.as_mut_ptr() as *mut _,
                        len,
                        sqe.off as libc::off_t,
                    )
                };
                match n.host_syscall_errno() {
                    Ok(got) => {
                        let got = got as usize;
                        if memory.write_bytes(sqe.addr, &buf[..got]).is_err() {
                            return cqe_err(LINUX_EFAULT);
                        }
                        got as i32
                    }
                    Err(e) => cqe_err(e),
                }
            }
            LINUX_IORING_OP_WRITE => {
                let Some(hfd) = self.regular_host_file_write_fd(sqe.fd) else {
                    return if self.regular_host_file_fd(sqe.fd).is_some() {
                        cqe_err(LINUX_EBADF)
                    } else {
                        cqe_err(LINUX_EINVAL)
                    };
                };
                let Ok(buf) = memory.read_bytes(sqe.addr, sqe.len as usize) else {
                    return cqe_err(LINUX_EFAULT);
                };
                let n = unsafe {
                    libc::pwrite(
                        hfd.get(),
                        buf.as_ptr() as *const _,
                        buf.len(),
                        sqe.off as libc::off_t,
                    )
                };
                match n.host_syscall_errno() {
                    Ok(put) => put as i32,
                    Err(e) => cqe_err(e),
                }
            }
            LINUX_IORING_OP_READV => {
                let Some(hfd) = self.regular_host_file_fd(sqe.fd) else {
                    return cqe_err(LINUX_EINVAL);
                };
                let Some(iovs) = read_iovecs(memory, sqe.addr, sqe.len as usize) else {
                    return cqe_err(LINUX_EFAULT);
                };
                let total: usize = iovs.iter().map(|v| v.iov_len as usize).sum();
                let mut buf = vec![0u8; total];
                let n = unsafe {
                    libc::pread(
                        hfd.get(),
                        buf.as_mut_ptr() as *mut _,
                        total,
                        sqe.off as libc::off_t,
                    )
                };
                match n.host_syscall_errno() {
                    Ok(got) => {
                        let got = got as usize;
                        // Scatter the bytes read across the iovecs in order.
                        if scatter_to_iovecs(memory, &iovs, &buf[..got]).is_err() {
                            return cqe_err(LINUX_EFAULT);
                        }
                        got as i32
                    }
                    Err(e) => cqe_err(e),
                }
            }
            LINUX_IORING_OP_WRITEV => {
                let Some(hfd) = self.regular_host_file_write_fd(sqe.fd) else {
                    return if self.regular_host_file_fd(sqe.fd).is_some() {
                        cqe_err(LINUX_EBADF)
                    } else {
                        cqe_err(LINUX_EINVAL)
                    };
                };
                let Some(iovs) = read_iovecs(memory, sqe.addr, sqe.len as usize) else {
                    return cqe_err(LINUX_EFAULT);
                };
                // Gather the iovecs into one buffer, then a single pwrite.
                let Ok(buf) = gather_iovecs(memory, &iovs) else {
                    return cqe_err(LINUX_EFAULT);
                };
                let n = unsafe {
                    libc::pwrite(
                        hfd.get(),
                        buf.as_ptr() as *const _,
                        buf.len(),
                        sqe.off as libc::off_t,
                    )
                };
                match n.host_syscall_errno() {
                    Ok(put) => put as i32,
                    Err(e) => cqe_err(e),
                }
            }
            LINUX_IORING_OP_FSYNC => {
                let Some(hfd) = self.regular_host_file_fd(sqe.fd) else {
                    return cqe_err(LINUX_EINVAL);
                };
                match unsafe { libc::fsync(hfd.get()) }.host_syscall_errno() {
                    Ok(_) => 0,
                    Err(e) => cqe_err(e),
                }
            }
            LINUX_IORING_OP_CLOSE => {
                // Same lifecycle path as close(2), scoped to the exact captured
                // task and FileTable generation that submitted the SQE. Close
                // notifications must observe the slot before removal; epoll
                // detach must likewise happen before the fd number is reusable.
                self.discard_splice_pushback_if_final(sqe.fd);
                self.dnotify_close_fd(sqe.fd);
                self.inotify_close_for_fd(sqe.fd);
                let identity = super::resources::with_active_context(|context| {
                    self.fanotify_close_for_fd(context, sqe.fd);
                    (context.task().key(), context.thread().key().tid.raw())
                });
                self.detach_fd_from_epolls(sqe.fd);
                let files = self.captured_file_table();
                let removed = files.write_open_files().remove(&sqe.fd);
                match removed {
                    Some(open_file) => {
                        self.mqueue_owner_alias_closed(&files, &open_file);
                        if let Some((owner, tid)) = identity {
                            self.record_fd_close_owner(sqe.fd, tid, &open_file);
                            self.release_hvpatch_classic_record_locks(owner, &open_file);
                        }
                        crate::event_ring::rec(
                            crate::event_ring::FDCLOSE,
                            sqe.fd,
                            super::fs::fd_helpers::event_ring_host_fd(&open_file),
                            0,
                        );
                        self.close_open_file_and_free_pty(&open_file);
                        self.note_fd_closed(sqe.fd);
                        0
                    }
                    None => cqe_err(LINUX_EBADF),
                }
            }
            _ => cqe_err(LINUX_EINVAL),
        }
    }

    /// Attempt a readiness-driven op without blocking: Ready(res) if it completed
    /// or errored, Block(host_fd, poll_events) if it would block (the enter loop
    /// then hands off to the runtime's kqueue wait). RECV/SEND go through the host
    /// socket; POLL_ADD polls the fd with a zero timeout.
    fn try_async_op(&self, memory: &mut impl GuestMemory, sqe: &LinuxIoUringSqe) -> AsyncOutcome {
        match sqe.opcode {
            LINUX_IORING_OP_RECV => {
                let Some(hfd) = self.host_socket_fd(sqe.fd) else {
                    return AsyncOutcome::Ready(cqe_err(LINUX_EINVAL));
                };
                let len = sqe.len as usize;
                let mut buf = vec![0u8; len];
                let n = unsafe {
                    libc::recv(
                        hfd.get(),
                        buf.as_mut_ptr() as *mut _,
                        len,
                        libc::MSG_DONTWAIT,
                    )
                };
                match n.host_syscall_errno() {
                    Ok(got) => {
                        let got = got as usize;
                        if memory.write_bytes(sqe.addr, &buf[..got]).is_err() {
                            return AsyncOutcome::Ready(cqe_err(LINUX_EFAULT));
                        }
                        AsyncOutcome::Ready(got as i32)
                    }
                    Err(e) if e == LINUX_EAGAIN => AsyncOutcome::Block(hfd.get(), libc::POLLIN),
                    Err(e) => AsyncOutcome::Ready(cqe_err(e)),
                }
            }
            LINUX_IORING_OP_SEND => {
                let Some(hfd) = self.host_socket_fd(sqe.fd) else {
                    return AsyncOutcome::Ready(cqe_err(LINUX_EINVAL));
                };
                let Ok(buf) = memory.read_bytes(sqe.addr, sqe.len as usize) else {
                    return AsyncOutcome::Ready(cqe_err(LINUX_EFAULT));
                };
                let n = unsafe {
                    libc::send(
                        hfd.get(),
                        buf.as_ptr() as *const _,
                        buf.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                match n.host_syscall_errno() {
                    Ok(put) => AsyncOutcome::Ready(put as i32),
                    Err(e) if e == LINUX_EAGAIN => AsyncOutcome::Block(hfd.get(), libc::POLLOUT),
                    Err(e) => AsyncOutcome::Ready(cqe_err(e)),
                }
            }
            LINUX_IORING_OP_RECVMSG => {
                let Some(hfd) = self.host_socket_fd(sqe.fd) else {
                    return AsyncOutcome::Ready(cqe_err(LINUX_EINVAL));
                };
                let Some(iovs) = read_msghdr_iovecs(memory, sqe.addr) else {
                    return AsyncOutcome::Ready(cqe_err(LINUX_EFAULT));
                };
                let total: usize = iovs.iter().map(|v| v.iov_len as usize).sum();
                let mut buf = vec![0u8; total];
                let n = unsafe {
                    libc::recv(
                        hfd.get(),
                        buf.as_mut_ptr() as *mut _,
                        total,
                        libc::MSG_DONTWAIT,
                    )
                };
                match n.host_syscall_errno() {
                    Ok(got) => {
                        let got = got as usize;
                        if scatter_to_iovecs(memory, &iovs, &buf[..got]).is_err() {
                            return AsyncOutcome::Ready(cqe_err(LINUX_EFAULT));
                        }
                        AsyncOutcome::Ready(got as i32)
                    }
                    Err(e) if e == LINUX_EAGAIN => AsyncOutcome::Block(hfd.get(), libc::POLLIN),
                    Err(e) => AsyncOutcome::Ready(cqe_err(e)),
                }
            }
            LINUX_IORING_OP_SENDMSG => {
                let Some(hfd) = self.host_socket_fd(sqe.fd) else {
                    return AsyncOutcome::Ready(cqe_err(LINUX_EINVAL));
                };
                let Some(iovs) = read_msghdr_iovecs(memory, sqe.addr) else {
                    return AsyncOutcome::Ready(cqe_err(LINUX_EFAULT));
                };
                let Ok(buf) = gather_iovecs(memory, &iovs) else {
                    return AsyncOutcome::Ready(cqe_err(LINUX_EFAULT));
                };
                let n = unsafe {
                    libc::send(
                        hfd.get(),
                        buf.as_ptr() as *const _,
                        buf.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                match n.host_syscall_errno() {
                    Ok(put) => AsyncOutcome::Ready(put as i32),
                    Err(e) if e == LINUX_EAGAIN => AsyncOutcome::Block(hfd.get(), libc::POLLOUT),
                    Err(e) => AsyncOutcome::Ready(cqe_err(e)),
                }
            }
            LINUX_IORING_OP_ACCEPT => {
                // Reuse the accept(2) path: sqe.addr = sockaddr-out, sqe.off =
                // addrlen-out, sqe.op_flags = accept4 flags. It returns the new
                // guest fd (Returned), or signals would-block as WaitOnFds/EAGAIN
                // which we translate to a readiness wait on the listen socket.
                let outcome = self.accept_common(
                    Fd(sqe.fd),
                    GuestPtr(sqe.addr),
                    GuestPtr(sqe.off),
                    memory,
                    sqe.op_flags as i32,
                );
                match outcome {
                    DispatchOutcome::Returned { value } => AsyncOutcome::Ready(value as i32),
                    DispatchOutcome::Errno { errno } if errno == LINUX_EAGAIN => {
                        match self.host_socket_fd(sqe.fd) {
                            Some(h) => AsyncOutcome::Block(h.get(), libc::POLLIN),
                            None => AsyncOutcome::Ready(cqe_err(LINUX_EINVAL)),
                        }
                    }
                    DispatchOutcome::Errno { errno } => AsyncOutcome::Ready(cqe_err(errno)),
                    DispatchOutcome::WaitOnFds { fds, .. } => match fds.first() {
                        Some((h, e)) => AsyncOutcome::Block(h, e),
                        None => AsyncOutcome::Ready(cqe_err(LINUX_EAGAIN)),
                    },
                    _ => AsyncOutcome::Ready(cqe_err(LINUX_EINVAL)),
                }
            }
            LINUX_IORING_OP_CONNECT => {
                // sqe.addr = sockaddr, sqe.off = addrlen. connect_common waits on
                // POLLOUT while in progress; we map its outcome to the ring.
                match self.connect_common(sqe.fd, sqe.addr, sqe.off as u32, memory) {
                    DispatchOutcome::Returned { value } => AsyncOutcome::Ready(value as i32),
                    DispatchOutcome::Errno { errno } => AsyncOutcome::Ready(cqe_err(errno)),
                    DispatchOutcome::WaitOnFds { fds, .. } => match fds.first() {
                        Some((h, e)) => AsyncOutcome::Block(h, e),
                        None => AsyncOutcome::Ready(cqe_err(LINUX_EINVAL)),
                    },
                    _ => AsyncOutcome::Ready(cqe_err(LINUX_EINVAL)),
                }
            }
            LINUX_IORING_OP_POLL_ADD => {
                let Some(hfd) = self
                    .host_socket_fd(sqe.fd)
                    .or_else(|| self.regular_host_file_fd(sqe.fd))
                else {
                    return AsyncOutcome::Ready(cqe_err(LINUX_EINVAL));
                };
                let want = (sqe.op_flags & 0xFFFF) as i16;
                let mut pfd = libc::pollfd {
                    fd: hfd.get(),
                    events: want,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut pfd, 1, 0) } > 0 {
                    AsyncOutcome::Ready(i32::from(pfd.revents))
                } else {
                    AsyncOutcome::Block(hfd.get(), want)
                }
            }
            _ => AsyncOutcome::Ready(cqe_err(LINUX_EINVAL)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dispatch_call(
        dispatcher: &SyscallDispatcher,
        context: &crate::kernel::KernelContext,
        memory: &mut LinearMemory,
        number: u64,
        args: [u64; 6],
    ) -> DispatchOutcome {
        dispatcher
            .dispatch_normalized(
                context,
                SyscallRequest::new(number, SyscallArgs::from(args)),
                memory,
                &CompatReporter::default(),
                None,
            )
            .expect("io_uring lifecycle test syscall must be routed")
            .expect("io_uring lifecycle test syscall must dispatch")
    }

    fn returned_fd(outcome: DispatchOutcome) -> i32 {
        match outcome {
            DispatchOutcome::Returned { value } => i32::try_from(value).expect("fd fits i32"),
            other => panic!("expected fd, got {other:?}"),
        }
    }

    fn sqe(opcode: u8, user_data: u64) -> LinuxIoUringSqe {
        LinuxIoUringSqe {
            opcode,
            flags: 0,
            ioprio: 0,
            fd: 0,
            off: 0,
            addr: 0,
            len: 0,
            op_flags: 0,
            user_data,
            buf_index: 0,
            personality: 0,
            splice_fd_in: 0,
            pad2: [0; 2],
        }
    }

    #[test]
    fn close_sqe_retires_exact_mqueue_registration_and_netlink_retention() {
        use zerocopy::IntoBytes as _;

        let dispatcher = SyscallDispatcher::new();
        let (process, _) = crate::hvpatch::process_context_for_tests(83_030);
        dispatcher.bind_hvpatch_process(process);
        let context = dispatcher.capture_one_task_context().unwrap();
        let mut memory = LinearMemory::new(0x1000, vec![0u8; 0x6000]);
        memory.write_bytes(0x1000, b"ioring_close\0").unwrap();
        let mqd = returned_fd(dispatch_call(
            &dispatcher,
            &context,
            &mut memory,
            180,
            [
                0x1000,
                LINUX_O_RDWR | LINUX_O_CREAT | LINUX_O_EXCL,
                0o600,
                0,
                0,
                0,
            ],
        ));
        let netlink_fd = returned_fd(dispatch_call(
            &dispatcher,
            &context,
            &mut memory,
            198,
            [LINUX_AF_NETLINK as u64, LINUX_SOCK_DGRAM as u64, 0, 0, 0, 0],
        ));
        let netlink = super::super::resources::with_captured_resources(&context, || {
            dispatcher
                .open_file(netlink_fd)
                .expect("netlink fd")
                .description()
        });
        let refs_before = netlink.fd_ref_count();
        memory.write_bytes(0x1200, &[0x53; 32]).unwrap();
        let sigevent = crate::linux_abi::LinuxSigevent {
            sigev_value: 0x1200,
            sigev_signo: netlink_fd,
            sigev_notify: crate::linux_abi::LINUX_SIGEV_THREAD,
            _sigev_un: [0; 48],
        };
        memory.write_bytes(0x1100, sigevent.as_bytes()).unwrap();
        assert_eq!(
            dispatch_call(
                &dispatcher,
                &context,
                &mut memory,
                184,
                [mqd as u64, 0x1100, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(netlink.fd_ref_count(), refs_before + 1);

        let mut close_sqe = sqe(LINUX_IORING_OP_CLOSE, 0x51);
        close_sqe.fd = mqd;
        let close_result = super::super::resources::with_captured_resources(&context, || {
            dispatcher.io_uring_run_op(&mut memory, &close_sqe)
        });
        assert_eq!(close_result, 0);
        assert_eq!(
            netlink.fd_ref_count(),
            refs_before,
            "IORING_OP_CLOSE must release the registration's retained netlink description"
        );

        let replacement_mqd = returned_fd(dispatch_call(
            &dispatcher,
            &context,
            &mut memory,
            180,
            [0x1000, LINUX_O_RDWR, 0, 0, 0, 0],
        ));
        let replacement = crate::linux_abi::LinuxSigevent {
            sigev_value: 0x55,
            sigev_signo: 34,
            sigev_notify: crate::linux_abi::LINUX_SIGEV_SIGNAL,
            _sigev_un: [0; 48],
        };
        memory.write_bytes(0x1100, replacement.as_bytes()).unwrap();
        assert_eq!(
            dispatch_call(
                &dispatcher,
                &context,
                &mut memory,
                184,
                [replacement_mqd as u64, 0x1100, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
            "a replacement description must register after the SQE close"
        );
    }

    fn test_description() -> (Arc<crate::kernel::FileDescription>, Arc<IoUringBacking>) {
        let backing = IoUringBacking::create(8, 4096).expect("ring backing");
        let description = Arc::new(
            crate::kernel::FileDescription::concrete(Arc::clone(&backing))
                .expect("ring description"),
        );
        (description, backing)
    }

    fn test_mapping(
        description: &Arc<crate::kernel::FileDescription>,
        start: u64,
        end: u64,
    ) -> IoUringMapping {
        IoUringMapping {
            description: Arc::clone(description),
            region: IoUringRegion::SqCq,
            start,
            end,
            backing_offset: 0,
        }
    }

    #[test]
    fn mapping_attachment_splits_and_keeps_backing_after_final_fd_close() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let mm = context.shared().mm();
        let (description, backing) = test_description();
        let weak = Arc::downgrade(&backing);
        description.retain_fd_ref();
        mm.replace_io_uring_mappings(
            0x1000,
            0x3000,
            Some(test_mapping(&description, 0x1000, 0x4000)),
        );
        description.release_fd_ref();
        drop(backing);
        assert!(weak.upgrade().is_some(), "mapping must retain backing");

        mm.replace_io_uring_mappings(0x2000, 0x1000, None);
        let mappings = mm.read_io_uring_mappings();
        assert_eq!(mappings.len(), 2);
        assert_eq!((mappings[0].start, mappings[0].end), (0x1000, 0x2000));
        assert_eq!((mappings[1].start, mappings[1].end), (0x3000, 0x4000));
        assert_eq!(mappings[1].backing_offset, 0x2000);
        drop(mappings);
        mm.replace_io_uring_mappings(0x1000, 0x3000, None);
        drop(description);
        assert!(weak.upgrade().is_none(), "final unmap releases backing");
    }

    #[test]
    fn copied_mm_clones_exact_attachments_and_clone_vm_shares_mm() {
        let dispatcher = SyscallDispatcher::new();
        let parent = dispatcher.capture_one_task_context().unwrap();
        let (description, _backing) = test_description();
        parent.shared().mm().replace_io_uring_mappings(
            0x5000,
            0x1000,
            Some(test_mapping(&description, 0x5000, 0x6000)),
        );
        let rebound = dispatcher
            .reset_one_task_kernel_binding_for_current_process(
                &parent,
                crate::thread::ThreadId::synthetic_for_tests(0x7701),
            )
            .unwrap();
        assert!(!Arc::ptr_eq(&parent.shared().mm(), &rebound.shared().mm()));
        let child_mm = rebound.shared().mm();
        let child_rows = child_mm.read_io_uring_mappings();
        assert_eq!(child_rows.len(), 1);
        assert!(Arc::ptr_eq(&child_rows[0].description, &description));
    }

    #[test]
    fn host_fork_observes_shared_queue_bytes() {
        let (_description, backing) = test_description();
        let tail = backing.layout.sq_off.tail as u64;
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let _ = backing.store_u32(tail, 0x51, Ordering::Release);
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(backing.load_u32(tail, Ordering::Acquire), Some(0x51));
    }

    #[test]
    fn exec_survivor_keeps_description_but_new_mm_has_no_attachments() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let (description, _backing) = test_description();
        let fd = dispatcher
            .install_fd_at_or_above(3, OpenFile::new(Arc::clone(&description), 0))
            .unwrap();
        context.shared().mm().replace_io_uring_mappings(
            0x3000,
            0x1000,
            Some(test_mapping(&description, 0x3000, 0x4000)),
        );
        let prepared = dispatcher.prepare_one_task_kernel_exec(&context).unwrap();
        let replacement = dispatcher.commit_one_task_kernel_exec(prepared).unwrap();
        assert!(
            replacement
                .shared()
                .mm()
                .read_io_uring_mappings()
                .is_empty()
        );
        let slot = replacement
            .resources()
            .files()
            .slot(crate::kernel::FileSlotNumber::for_open_fd(fd).unwrap())
            .expect("surviving ring fd");
        assert!(Arc::ptr_eq(&slot.description, &description));
        assert!(
            slot.description
                .concrete_backing::<IoUringBacking>()
                .is_some()
        );
    }

    #[test]
    fn layout_rounds_entries_to_power_of_two_and_sizes_regions() {
        let l = RingLayout::new(3);
        assert_eq!(l.sq_entries, 4); // 3 -> 4
        assert_eq!(l.cq_entries, 8); // 2x
        // SQE array mapping is sq_entries * 64 bytes.
        assert_eq!(l.sqes_bytes, 4 * 64);
        // Copy packed nested-struct fields to locals before asserting (taking a
        // reference to a packed field is UB; PartialEq/Copy avoid it).
        let (sq_head, sq_tail, sq_array) = (l.sq_off.head, l.sq_off.tail, l.sq_off.array);
        let cqes = l.cq_off.cqes;
        // Ring mapping must contain all cqes past the cqes offset.
        assert!(l.ring_bytes >= (cqes + l.cq_entries * 16) as usize);
        // Control-word offsets are distinct and within the mapping.
        assert_eq!(sq_head, 0);
        assert_ne!(sq_tail, sq_head);
        assert!(cqes > sq_array);
    }

    #[test]
    fn params_describe_the_layout() {
        let l = RingLayout::new(8);
        let mut p = LinuxIoUringParams::default();
        l.fill_params(&mut p);
        assert_eq!(p.sq_entries, 8);
        assert_eq!(p.cq_entries, 16);
        assert_eq!(
            p.features & LINUX_IORING_FEAT_SINGLE_MMAP,
            LINUX_IORING_FEAT_SINGLE_MMAP
        );
        assert_eq!(p.sq_off, l.sq_off);
        assert_eq!(p.cq_off, l.cq_off);
    }

    #[test]
    fn nop_completes_with_zero_and_preserves_user_data() {
        let c = complete_sqe(&sqe(LINUX_IORING_OP_NOP, 0xABCD), |_| {
            panic!("NOP must not call io")
        });
        assert_eq!(c.res, 0);
        assert_eq!(c.user_data, 0xABCD);
    }

    #[test]
    fn unknown_opcode_completes_with_einval_not_io() {
        // 200 is not a real opcode; must NOT invoke io, must CQE -EINVAL.
        let c = complete_sqe(&sqe(200, 0x11), |_| {
            panic!("unknown opcode must not call io")
        });
        assert_eq!(c.res, cqe_err(LINUX_EINVAL));
        assert_eq!(c.user_data, 0x11);
    }

    #[test]
    fn serviced_opcode_runs_io_and_returns_its_result() {
        let c = complete_sqe(&sqe(LINUX_IORING_OP_WRITE, 0x22), |s| {
            assert_eq!(s.opcode, LINUX_IORING_OP_WRITE);
            7 // pretend 7 bytes written
        });
        assert_eq!(c.res, 7);
        assert_eq!(c.user_data, 0x22);
    }
}
