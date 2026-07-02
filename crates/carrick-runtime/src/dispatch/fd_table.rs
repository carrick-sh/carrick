//! File-descriptor table and open-description model.
//!
//! Linux distinguishes two layers: the per-process *fd table* (numbers → open
//! file descriptions) and the *open file descriptions* themselves (the seekable
//! cursor, status flags, and backing object that `dup`/`fork`/`fork`+`exec`
//! share). carrick mirrors that split. The fd table is
//! `IoState::open_files: HashMap<i32, OpenFile>` (see `fs/state.rs`); each
//! [`OpenFile`] holds its per-*fd* `FD_CLOEXEC` flag plus an
//! `Arc<RwLock<OpenDescription>>` — the shared open-file-description. Because the
//! description is behind an `Arc`, two fds produced by `dup(2)` see one cursor,
//! one set of status flags, one lease, one async-I/O owner — exactly as the
//! kernel keeps them on the description, not the fd. `OpenDescriptionBase`
//! carries that shared per-description state.
//!
//! # `OpenDescription`: one union over every backing object
//!
//! The interesting variants split by how the object is realized on macOS:
//!
//! - **In-memory rootfs/overlay** — `File` / `Directory` / `SyntheticFile`:
//!   the bytes (or directory entries) live in the Vec and a `usize` offset is
//!   the seek cursor. This is the default (`--fs memory`) backing.
//! - **Host-fd-backed** — `HostFile` / `HostSocket` / `HostPipe`: a real macOS
//!   descriptor does the work (APFS file under `--fs host`, a BSD socket, a host
//!   pipe / pty). Seek/read/write/poll forward to the host fd. `HostFdRef`
//!   reference-counts the underlying host fd so the last `dup` to close it
//!   actually closes the macOS descriptor.
//! - **Anonymous-inode fds** — `EventFd` / `TimerFd` / `Epoll` / `SignalFd` /
//!   `Inotify` / `Pidfd`: Linux objects macOS has no syscall for, emulated on
//!   top of a kqueue and/or a host readiness pipe. They are pollable but not
//!   seekable; their `readlink(/proc/self/fd/N)` reports the matching
//!   `anon_inode:[…]` label so guest fd-introspection agrees with `fstat`.
//!
//! A handler that only needs "what kind of fd is this" uses the typed accessors
//! in `fs/fd_helpers.rs` (`host_socket_fd`, `inotify_state`, …) rather than
//! matching the whole enum.
//!
//! # Readiness emulation is the subtle part
//!
//! eventfd and the kqueue-backed fds keep a REAL host fd that an epoll instance's
//! kqueue can watch with `EVFILT_READ` — see `EventFdState`, which mirrors
//! "counter > 0" as "exactly one byte present in a host pipe" so a level-trigger
//! cannot be lost (Go's `netpollBreak` depends on this). The in-memory state is
//! the source of truth; the host pipe is the wakeup channel.

use crate::linux_abi::LinuxErrno;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex, RwLock};

use crate::linux_abi::{
    LINUX_EFBIG, LINUX_S_IFCHR, LINUX_S_IFIFO, LINUX_S_IFMT, LINUX_S_IFREG, LINUX_S_IFSOCK,
    LinuxEpollEvent,
};
use crate::rootfs::{RootFsDirEntry, RootFsEntryKind, RootFsMetadata};

use super::{EpollKqueue, Fd, GuestPtr, HostFd, inode_for_path, linux_mode};

#[derive(Debug, Clone)]
pub(super) struct EpollInterest {
    pub(super) event: LinuxEpollEvent,
    pub(super) last_ready: u32,
    pub(super) last_read_avail: u64,
    /// Edge-triggered write side was attempted and returned EAGAIN after an
    /// earlier EPOLLOUT delivery. Keep the host write filter armed while still
    /// suppressing immediate sampled OUT redelivery; the next host write event
    /// is a fresh transition and should be delivered once.
    pub(super) write_backpressured: bool,
    /// Per-registration generation, the high half of this fd's multiplexer
    /// `udata` handle (`pack_epoll_udata`). Guest fd numbers AND host fd numbers
    /// are recycled rapidly under churn, so a drained kqueue/epoll event keyed by
    /// a bare fd is an ABA hazard: the fd it names may already belong to a
    /// different registration by delivery time. The udata carries
    /// `(guest_fd, reg_gen)`; on delivery we look up `interest[guest_fd]` and
    /// require its `reg_gen` to match, so a stale event for a recycled fd is
    /// rejected instead of mis-delivered. (epoll_et_pipe_eof_not_lost.)
    pub(super) reg_gen: u32,
}

#[derive(Debug)]
pub(super) struct EventFdState {
    /// Slot in the cross-process counter slab (`crate::eventfd_shm`) — the
    /// counter must be FORK-COHERENT (carrick forks real host processes;
    /// LTP eventfd2_03's children semaphore-ping-pong across the fork), so it
    /// lives in `MAP_SHARED` host memory, not in this (per-process) struct.
    /// `None` = slab unavailable/exhausted → `local` fallback (correct within
    /// one process, silently non-coherent across forks — the pre-slab
    /// behavior).
    slot: Option<usize>,
    local: std::sync::atomic::AtomicU64,
    /// Host pipe whose read end mirrors "counter > 0": a byte is present iff
    /// the eventfd is readable. This gives the eventfd a REAL host fd that the
    /// epoll instance kqueue watches via `EVFILT_READ` natively
    /// (level-triggered -> can't be lost), so Go's netpollBreak wakes the poller
    /// without relying on the coarse `EVFILT_USER` broadcast — and that a
    /// BLOCKING guest read parks on (`WaitOnFds`), which a kernel-shared pipe
    /// makes work across forked guest processes. `None` if pipe creation failed
    /// (then readiness falls back to the in-memory recompute + broadcast and
    /// blocking reads degrade to EAGAIN). The owned [`HostFdRef`]s close the two
    /// ends when this state drops (replacing the historical bespoke `Drop`).
    /// The bytes are managed entirely by carrick (write_eventfd / read_eventfd);
    /// the guest never reads the pipe directly.
    pub(super) read_fd: Option<HostFdRef>,
    pub(super) write_fd: Option<HostFdRef>,
}

impl EventFdState {
    pub(super) fn new(counter: u64) -> Self {
        let (read_fd, write_fd) = match make_readiness_pipe() {
            Some((read_fd, write_fd)) => (Some(read_fd), Some(write_fd)),
            None => (None, None),
        };
        // Reflect a non-zero initial value as "readable" right away.
        if counter > 0
            && let Some(write_fd) = &write_fd
        {
            let byte = [1u8];
            // BLOCKING-IO-OK: readiness pipe is set to O_NONBLOCK during creation
            unsafe { libc::write(write_fd.raw(), byte.as_ptr().cast(), 1) };
        }
        Self {
            slot: crate::eventfd_shm::alloc(counter),
            local: std::sync::atomic::AtomicU64::new(counter),
            read_fd,
            write_fd,
        }
    }

    /// The eventfd counter — the shared-slab slot when available (coherent
    /// across forked guest processes), else the per-process fallback.
    pub(super) fn counter_ref(&self) -> &std::sync::atomic::AtomicU64 {
        self.slot
            .and_then(crate::eventfd_shm::counter)
            .unwrap_or(&self.local)
    }

    /// Current counter value (racy snapshot — poll/epoll readiness only).
    pub(super) fn counter_value(&self) -> u64 {
        self.counter_ref().load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Make `read_fd` readable iff `count > 0`: ensure a byte is present when
    /// readable, drained when not. `count` is the caller's post-update view.
    /// Cross-process race guard: after draining for a 0 count, RE-CHECK the
    /// shared counter — a concurrent writer's 0→n byte may have been eaten by
    /// this drain, and a parked reader would then sleep past a ready counter.
    pub(super) fn sync_readiness(&self, count: u64) {
        let (Some(read_fd), Some(write_fd)) = (&self.read_fd, &self.write_fd) else {
            return;
        };
        if count > 0 {
            // Ensure a byte is present (idempotent: a full pipe EAGAINs).
            let byte = [1u8];
            // BLOCKING-IO-OK: readiness pipe is set to O_NONBLOCK during creation
            unsafe { libc::write(write_fd.raw(), byte.as_ptr().cast(), 1) };
        } else {
            // Drain any bytes so the read end is not readable.
            let mut buf = [0u8; 64];
            loop {
                // BLOCKING-IO-OK: readiness pipe is set to O_NONBLOCK during creation
                let n = unsafe { libc::read(read_fd.raw(), buf.as_mut_ptr().cast(), buf.len()) };
                if n <= 0 {
                    break;
                }
            }
            if self.counter_value() > 0 {
                let byte = [1u8];
                // BLOCKING-IO-OK: readiness pipe is set to O_NONBLOCK during creation
                unsafe { libc::write(write_fd.raw(), byte.as_ptr().cast(), 1) };
            }
        }
    }
}

/// A non-blocking, CLOEXEC host pipe relocated above the guest fd range, used as
/// an eventfd's readiness channel. `None` on failure (caller degrades to the
/// in-memory recompute + EVFILT_USER broadcast). The returned [`HostFdRef`]s
/// own the two ends; their `Drop`s close them (per process — each forked host
/// process independently closes its inherited copies, as before).
fn make_readiness_pipe() -> Option<(HostFdRef, HostFdRef)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    let read_fd = crate::host_signal::relocate_internal_fd(fds[0]);
    let write_fd = crate::host_signal::relocate_internal_fd(fds[1]);
    for fd in [read_fd, write_fd] {
        unsafe {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            if fl >= 0 {
                libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
            let fdfl = libc::fcntl(fd, libc::F_GETFD);
            if fdfl >= 0 {
                libc::fcntl(fd, libc::F_SETFD, fdfl | libc::FD_CLOEXEC);
            }
        }
    }
    Some((HostFdRef::new(read_fd), HostFdRef::new(write_fd)))
}

#[derive(Debug)]
pub(super) struct TimerFdState {
    pub(super) inner: Mutex<TimerFdInner>,
    pub(super) changed: Condvar,
}

impl TimerFdState {
    pub(super) fn new(clock_id: u64) -> Self {
        Self {
            inner: Mutex::new(TimerFdInner {
                clock_id,
                interval: None,
                deadline: None,
                expirations: 0,
            }),
            changed: Condvar::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TimerFdInner {
    pub(super) clock_id: u64,
    pub(super) interval: Option<Duration>,
    pub(super) deadline: Option<Duration>,
    pub(super) expirations: u64,
}

#[derive(Debug, Clone)]
pub(super) struct OpenDescriptionBase {
    status_flags: u64,
    /// Linux file-lease state (F_SETLEASE/F_GETLEASE): F_RDLCK(0)/F_WRLCK(1)/
    /// F_UNLCK(2). Lives on the open-file-description so a dup'd fd shares it,
    /// matching the kernel. Default F_UNLCK = no lease.
    lease: i32,
    /// SO_RCVTIMEO: bounds a blocking recv on this socket. None = block forever.
    recv_timeout: Option<Duration>,
    /// SO_SNDTIMEO: bounds a blocking send on this socket. None = block forever.
    send_timeout: Option<Duration>,
    /// F_SETOWN/F_SETOWN_EX async-I/O owner (the SIGIO/SIGURG target). `owner_type`
    /// is F_OWNER_TID/PID/PGRP; `owner_pid` is the positive id. (0, 0) = no owner.
    /// Stored on the description so a dup'd fd shares it, matching the kernel.
    owner_type: i32,
    owner_pid: i32,
    /// F_SETSIG: the signal delivered on async I/O (0 = the default SIGIO).
    async_sig: i32,
    /// Pipe capacity reported by F_GETPIPE_SZ and (re)set by F_SETPIPE_SZ.
    /// Lives on the open-file-description so a dup'd fd shares it (matching the
    /// kernel). Only meaningful for pipe ends; default = the Linux pipe buffer
    /// size. Note: this is per-description, so each end of a `pipe(2)` tracks
    /// its own value — Linux shares one buffer across both ends, but CPython's
    /// `test_fcntl_f_pipesize` only set/get on a single end, so the observable
    /// behaviour matches. macOS pipes have no portable buffer-resize API, so
    /// the stored value is bookkeeping only (it does not change the real host
    /// pipe's capacity).
    pipe_capacity: i64,
    /// When set, pipe capacity is read/written through this SHARED cell instead
    /// of the inline `pipe_capacity` field, so BOTH ends of a `pipe(2)` observe
    /// one value — Linux keeps a single buffer per pipe, so F_SETPIPE_SZ on one
    /// end is visible to F_GETPIPE_SZ on the other (CPython
    /// test_subprocess.test_pipesizes sets on the write end, reads on the read
    /// ends). `pipe2` hands the same `Arc` to both ends; `None` everywhere else.
    pipe_capacity_shared: Option<std::sync::Arc<std::sync::atomic::AtomicI64>>,
    /// Guest-intended SO_REUSEPORT, tracked so getsockopt reports what the guest
    /// set — NOT the host SO_REUSEPORT carrick silently turns on to emulate
    /// Linux UDP wildcard-rebind from SO_REUSEADDR. (audit M4)
    so_reuseport: bool,
    /// Guest-set SO_RCVBUF / SO_SNDBUF (the raw value passed to setsockopt).
    /// `None` = never set. getsockopt reports Linux's doubled value (2×) of what
    /// was set, rather than the host's actual buffer size (which carrick widens
    /// for AF_UNIX). (audit M5)
    so_rcvbuf: Option<i32>,
    so_sndbuf: Option<i32>,
    /// SO_PASSCRED: when set, recvmsg attaches an SCM_CREDENTIALS ancillary
    /// message with the peer's `struct ucred`. (audit M2)
    so_passcred: bool,
    /// True while carrick has DEFERRED a blocking connect (returned WaitOnFds on
    /// POLLOUT) and is waiting to re-dispatch it. macOS reports EISCONN both when
    /// an async connect completes AND when the guest calls connect() on an
    /// already-established socket — only the former should be folded to success.
    /// This flag is set when the first connect() yields EINPROGRESS/EALREADY/
    /// EAGAIN and consulted on a subsequent EISCONN: set ⇒ async completion
    /// (return success), clear ⇒ a real re-connect of an established socket
    /// (surface EISCONN to the guest, matching Linux connect01 case "already
    /// connected").
    connect_in_progress: bool,
}

impl OpenDescriptionBase {
    pub(super) fn new(status_flags: u64) -> Self {
        Self {
            status_flags,
            so_reuseport: false,
            so_rcvbuf: None,
            so_sndbuf: None,
            so_passcred: false,
            connect_in_progress: false,
            lease: crate::linux_abi::LINUX_F_UNLCK,
            recv_timeout: None,
            send_timeout: None,
            owner_type: 0,
            owner_pid: 0,
            async_sig: 0,
            pipe_capacity: crate::linux_abi::LINUX_PIPE_BUF_SIZE,
            pipe_capacity_shared: None,
        }
    }

    /// Route pipe capacity through a cell shared with the pipe's other end.
    pub(super) fn set_pipe_capacity_cell(
        &mut self,
        cell: std::sync::Arc<std::sync::atomic::AtomicI64>,
    ) {
        self.pipe_capacity_shared = Some(cell);
    }

    pub(super) fn pipe_capacity(&self) -> i64 {
        match &self.pipe_capacity_shared {
            Some(cell) => cell.load(std::sync::atomic::Ordering::Relaxed),
            None => self.pipe_capacity,
        }
    }

    pub(super) fn set_pipe_capacity(&mut self, capacity: i64) {
        match &self.pipe_capacity_shared {
            Some(cell) => cell.store(capacity, std::sync::atomic::Ordering::Relaxed),
            None => self.pipe_capacity = capacity,
        }
    }

    pub(super) fn status_flags(&self) -> u64 {
        self.status_flags
    }

    /// F_GETOWN_EX returns the (type, pid); (0, 0) means no owner set.
    pub(super) fn owner(&self) -> (i32, i32) {
        (self.owner_type, self.owner_pid)
    }

    pub(super) fn set_owner(&mut self, owner_type: i32, owner_pid: i32) {
        self.owner_type = owner_type;
        self.owner_pid = owner_pid;
    }

    /// F_GETSIG: 0 = the default SIGIO.
    pub(super) fn async_sig(&self) -> i32 {
        self.async_sig
    }

    pub(super) fn set_async_sig(&mut self, sig: i32) {
        self.async_sig = sig;
    }

    pub(super) fn set_status_flags(&mut self, next: u64) {
        self.status_flags = next;
    }

    pub(super) fn lease(&self) -> i32 {
        self.lease
    }

    pub(super) fn set_lease(&mut self, lease: i32) {
        self.lease = lease;
    }

    pub(super) fn recv_timeout(&self) -> Option<Duration> {
        self.recv_timeout
    }

    pub(super) fn send_timeout(&self) -> Option<Duration> {
        self.send_timeout
    }

    pub(super) fn set_recv_timeout(&mut self, t: Option<Duration>) {
        self.recv_timeout = t;
    }

    pub(super) fn set_send_timeout(&mut self, t: Option<Duration>) {
        self.send_timeout = t;
    }

    /// Guest-intended SO_REUSEPORT (audit M4).
    pub(super) fn so_reuseport(&self) -> bool {
        self.so_reuseport
    }
    pub(super) fn set_so_reuseport(&mut self, on: bool) {
        self.so_reuseport = on;
    }

    /// Guest-set SO_RCVBUF / SO_SNDBUF, or `None` if never set (audit M5).
    pub(super) fn so_rcvbuf(&self) -> Option<i32> {
        self.so_rcvbuf
    }
    pub(super) fn set_so_rcvbuf(&mut self, v: i32) {
        self.so_rcvbuf = Some(v);
    }
    pub(super) fn so_sndbuf(&self) -> Option<i32> {
        self.so_sndbuf
    }
    pub(super) fn set_so_sndbuf(&mut self, v: i32) {
        self.so_sndbuf = Some(v);
    }

    /// SO_PASSCRED (audit M2).
    pub(super) fn so_passcred(&self) -> bool {
        self.so_passcred
    }
    pub(super) fn set_so_passcred(&mut self, on: bool) {
        self.so_passcred = on;
    }
    pub(super) fn connect_in_progress(&self) -> bool {
        self.connect_in_progress
    }
    pub(super) fn set_connect_in_progress(&mut self, on: bool) {
        self.connect_in_progress = on;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HostWriteKind {
    PipeLike,
    SocketLike,
    RegularFile,
    Other,
}

impl HostWriteKind {
    pub(super) fn from_host_mode(mode: libc::mode_t) -> Self {
        match mode & libc::S_IFMT {
            libc::S_IFIFO => Self::PipeLike,
            libc::S_IFSOCK => Self::SocketLike,
            libc::S_IFREG => Self::RegularFile,
            _ => Self::Other,
        }
    }

    pub(super) fn for_host_fd(host_fd: i32) -> Self {
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstat(host_fd, &mut st) } == 0 {
            Self::from_host_mode(st.st_mode)
        } else {
            Self::Other
        }
    }
}

#[derive(Debug, Clone)]
pub(super) enum FileContents {
    Dense(Vec<u8>),
    RootFsBacked {
        base: Arc<[u8]>,
        dirty: BTreeMap<usize, Vec<u8>>,
        len: usize,
    },
}

impl FileContents {
    pub(super) fn dense(bytes: Vec<u8>) -> Self {
        Self::Dense(bytes)
    }

    pub(super) fn shared_backed(
        base: Arc<[u8]>,
        dirty: BTreeMap<usize, Vec<u8>>,
        len: usize,
    ) -> Self {
        Self::RootFsBacked { base, dirty, len }
    }

    pub(super) fn len(&self) -> usize {
        match self {
            Self::Dense(bytes) => bytes.len(),
            Self::RootFsBacked { len, .. } => *len,
        }
    }

    pub(super) fn read_at(&self, offset: usize, length: usize) -> Vec<u8> {
        match self {
            Self::Dense(bytes) => bytes
                .get(offset..)
                .unwrap_or_default()
                .iter()
                .take(length)
                .copied()
                .collect(),
            Self::RootFsBacked { base, dirty, len } => {
                if offset >= *len || length == 0 {
                    return Vec::new();
                }
                let read_len = length.min(*len - offset);
                let mut out = vec![0; read_len];
                if offset < base.len() {
                    let base_len = read_len.min(base.len() - offset);
                    out[..base_len].copy_from_slice(&base[offset..offset + base_len]);
                }
                let end = offset + read_len;
                for (&start, bytes) in dirty.range(..end) {
                    let dirty_end = start.saturating_add(bytes.len());
                    if dirty_end <= offset {
                        continue;
                    }
                    let copy_start = start.max(offset);
                    let copy_end = dirty_end.min(end);
                    let dst_start = copy_start - offset;
                    let src_start = copy_start - start;
                    let copy_len = copy_end - copy_start;
                    out[dst_start..dst_start + copy_len]
                        .copy_from_slice(&bytes[src_start..src_start + copy_len]);
                }
                out
            }
        }
    }

    pub(super) fn to_vec(&self) -> Vec<u8> {
        self.read_at(0, self.len())
    }

    pub(super) fn resize(&mut self, new_len: usize) {
        match self {
            Self::Dense(bytes) => bytes.resize(new_len, 0),
            Self::RootFsBacked { dirty, len, .. } => {
                *len = new_len;
                prune_dirty_ranges(dirty, new_len);
            }
        }
    }

    pub(super) fn truncate(&mut self, new_len: usize) {
        match self {
            Self::Dense(bytes) => bytes.truncate(new_len),
            Self::RootFsBacked { dirty, len, .. } => {
                *len = (*len).min(new_len);
                prune_dirty_ranges(dirty, *len);
            }
        }
    }

    pub(super) fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<(), LinuxErrno> {
        let end = offset.checked_add(bytes.len()).ok_or(LINUX_EFBIG)?;
        if end as u64 > crate::vfs::MAX_IN_MEMORY_FILE_SIZE {
            return Err(crate::linux_abi::LINUX_EFBIG);
        }
        match self {
            Self::Dense(contents) => {
                if end > contents.len() {
                    contents.resize(end, 0);
                }
                contents[offset..end].copy_from_slice(bytes);
            }
            Self::RootFsBacked { dirty, len, .. } => {
                if end > *len {
                    *len = end;
                }
                insert_dirty_range(dirty, offset, bytes)?;
            }
        }
        Ok(())
    }
}

fn prune_dirty_ranges(dirty: &mut BTreeMap<usize, Vec<u8>>, len: usize) {
    let keys: Vec<usize> = dirty.range(len..).map(|(&start, _)| start).collect();
    for key in keys {
        dirty.remove(&key);
    }
    if let Some((&start, bytes)) = dirty.range(..len).next_back() {
        let keep = len.saturating_sub(start);
        if keep < bytes.len()
            && let Some(bytes) = dirty.get_mut(&start)
        {
            bytes.truncate(keep);
        }
    }
}

fn insert_dirty_range(
    dirty: &mut BTreeMap<usize, Vec<u8>>,
    offset: usize,
    bytes: &[u8],
) -> Result<(), LinuxErrno> {
    if bytes.is_empty() {
        return Ok(());
    }
    let end = offset.checked_add(bytes.len()).ok_or(LINUX_EFBIG)?;
    let overlapping: Vec<usize> = dirty
        .range(..end)
        .filter_map(|(&start, existing)| {
            let existing_end = start.checked_add(existing.len())?;
            (existing_end > offset).then_some(start)
        })
        .collect();
    for start in overlapping {
        let Some(existing) = dirty.remove(&start) else {
            continue;
        };
        let existing_end = start.checked_add(existing.len()).ok_or(LINUX_EFBIG)?;
        if start < offset {
            dirty.insert(start, existing[..offset - start].to_vec());
        }
        if existing_end > end {
            dirty.insert(end, existing[end - start..].to_vec());
        }
    }
    dirty.insert(offset, bytes.to_vec());
    Ok(())
}

/// Pidfd readiness backend: a boxed [`EventMultiplexer`](carrick_hal::event::EventMultiplexer)
/// watching the real host process. On macOS the backend is kqueue
/// (`EVFILT_PROC`/`NOTE_EXIT`+`NOTE_EXITSTATUS`); on Linux it is the
/// `EpollMultiplexer` (a real `pidfd_open(2)` added to the epoll set). Wrapped so
/// `OpenDescription` can keep deriving `Debug` (the trait object is not `Debug`);
/// the poll fd (the kqueue fd on macOS, the pidfd-bearing epoll fd on Linux) is
/// the only state callers read.
pub(super) struct PidfdWatch {
    /// Owns the backing fds; held only so `Drop` closes them (the registered
    /// process-exit watch is reclaimed with it). Never read after construction.
    /// `Mutex` only to make the otherwise-`!Sync` trait object shareable across
    /// threads (the dispatcher's `KernelState` must be `Send`); never locked.
    #[allow(dead_code)]
    mux: Mutex<Box<dyn carrick_hal::event::EventMultiplexer>>,
    poll_fd: i32,
}

impl PidfdWatch {
    pub(super) fn new(mux: Box<dyn carrick_hal::event::EventMultiplexer>) -> Self {
        let poll_fd = mux.poll_fd();
        Self {
            mux: Mutex::new(mux),
            poll_fd,
        }
    }

    /// The pollable fd readable when the watched process exits.
    pub(super) fn poll_fd(&self) -> i32 {
        self.poll_fd
    }
}

impl std::fmt::Debug for PidfdWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PidfdWatch")
            .field("poll_fd", &self.poll_fd)
            // The mux keeps the kqueue fd alive; nothing else to surface.
            .field("mux", &"<dyn EventMultiplexer>")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub(super) enum OpenDescription {
    File {
        base: OpenDescriptionBase,
        path: String,
        metadata: RootFsMetadata,
        contents: FileContents,
        offset: usize,
        /// True iff this fd targets the writable overlay. Writes
        /// to a writable=false File are still RO (return EROFS).
        writable: bool,
    },
    Directory {
        base: OpenDescriptionBase,
        path: String,
        metadata: RootFsMetadata,
        entries: Vec<RootFsDirEntry>,
        offset: usize,
    },
    SyntheticFile {
        base: OpenDescriptionBase,
        path: String,
        contents: Vec<u8>,
        offset: usize,
    },
    EventFd {
        base: OpenDescriptionBase,
        state: Arc<EventFdState>,
        semaphore: bool,
    },
    TimerFd {
        base: OpenDescriptionBase,
        state: Arc<TimerFdState>,
    },
    Epoll {
        base: OpenDescriptionBase,
        interest: HashMap<i32, EpollInterest>,
        /// Ready events already observed from the backing kqueue or synthetic
        /// readiness paths but not yet returned to the guest because the last
        /// `epoll_wait` hit `maxevents`. Linux leaves those events queued for
        /// the next wait; Carrick must preserve them explicitly because a
        /// `kevent` drain consumes them eagerly. The `i32` is the ORIGINATING
        /// guest fd, so EPOLL_CTL_DEL/MOD purges the right queued entry even
        /// when the guest's epoll_data token != fd. (audit M3; probe epollstaledel)
        pending_ready: VecDeque<(i32, LinuxEpollEvent)>,
        /// Persistent kqueue backing this epoll instance (FreeBSD `linux_event`
        /// model): `epoll_ctl` registers host-backed fds here via
        /// `EVFILT_READ`/`EVFILT_WRITE`, so an fd added by one thread is seen by
        /// another thread already blocked in `epoll_wait` on this kqueue's fd -
        /// the property carrick's old interest-snapshot wait lacked. Shared
        /// (`Arc`) so a dup'd epoll fd refers to the same instance. In-memory
        /// fds (eventfd/pipe/timerfd) aren't registered here; their readiness is
        /// recomputed each `epoll_wait` and a blocked wait is woken by the
        /// process-wide in-memory broadcast (`notify_inmem_epoll`) firing this
        /// kqueue's `EVFILT_USER(0)`. See `docs/archive/epoll-kqueue-plan.md`.
        kqueue: Arc<EpollKqueue>,
    },
    /// A Linux pidfd referring to a process. Backed by a host `kqueue` watching
    /// the real macOS process (`EVFILT_PROC`/`NOTE_EXIT`): the kqueue fd becomes
    /// read-ready when the process exits, so poll/epoll/`waitid(P_PIDFD)` on the
    /// pidfd are serviced by the macOS kernel's process-lifecycle tracking
    /// rather than carrick bookkeeping. `host_pid` is the macOS pid (guest pids
    /// mirror host pids in carrick). Used by Go 1.24's `os/exec`.
    Pidfd {
        base: OpenDescriptionBase,
        host_pid: i32,
        /// The readiness backend (kqueue on macOS, epoll+pidfd on Linux). Named
        /// `kqueue` for historical continuity; both platforms now route through
        /// the `EventMultiplexer` via [`PidfdWatch`].
        kqueue: Arc<PidfdWatch>,
    },
    /// A Linux inotify instance. Backed by an [`InotifyState`](crate::inotify::InotifyState) (a kqueue +
    /// `EVFILT_VNODE` watch table); like `Pidfd`/`TimerFd` it is a pollable,
    /// non-seekable, non-file fd whose readiness is the backing kqueue's fd.
    /// `read(2)` drains queued vnode changes as Linux `inotify_event` records.
    Inotify {
        base: OpenDescriptionBase,
        state: Arc<crate::inotify::InotifyState>,
    },
    /// A Linux signalfd (syscall 74 `signalfd4`). macOS has no signalfd, so this
    /// is emulated: `mask` records the signal set the fd accepts. Today only the
    /// fd-flag surface (SFD_CLOEXEC→FD_CLOEXEC, SFD_NONBLOCK→O_NONBLOCK, both via
    /// `base`) is exercised (signalfd4_01/02); a read()/poll() delivery path that
    /// drains the process's pending masked signals is a tracked follow-up.
    SignalFd {
        base: OpenDescriptionBase,
        mask: carrick_abi::SigSet,
    },
    // In-memory pipe ends. Currently `pipe2(2)` routes through `HostPipe`
    // (real macOS kernel pipe) so these are not constructed today, but the
    // full read/write/poll machinery (`PipeState`, `read_pipe`, `write_pipe`)
    // is kept wired as the portable, host-fd-free pipe model and is matched
    // throughout the fd handlers. Retained as deliberate API surface.
    #[allow(dead_code)]
    PipeReader {
        base: OpenDescriptionBase,
        pipe: PipeRef,
    },
    #[allow(dead_code)]
    PipeWriter {
        base: OpenDescriptionBase,
        pipe: PipeRef,
    },
    /// Host kernel pipe end backed by a real macOS file descriptor.
    /// Survives `libc::fork(2)` natively - both parent and child see
    /// the same kernel pipe object, so the post-fork sh-pipe demo
    /// can actually carry data across the carrick process boundary.
    HostPipe {
        base: OpenDescriptionBase,
        /// The OWNING handle to the backing host fd (see [`HostFdRef`]): the
        /// last dropped clone closes the macOS descriptor.
        host_fd: HostFdRef,
        is_read_end: bool,
        /// Globally-unique carrick id for the pipe OBJECT, identical on BOTH
        /// ends and inherited unchanged across `clone`/fork. This is the
        /// fork-coherent FASYNC (signal-driven I/O) join key: arming the read
        /// end stores `pipe_id` in the shared registry, and a write-end write in
        /// any process looks the SAME `pipe_id` up to deliver the I/O signal.
        /// Keyed by pipe id rather than the per-fd host inode because macOS
        /// gives a pipe's two ends DIFFERENT `st_ino` (Linux shares one), so an
        /// inode key armed on the read end would never match the write-end
        /// trigger. Assigned at pipe creation from the host inode of one end
        /// (globally unique, and fixed before any fork). `0` for ends with no
        /// real pipe object to share (e.g. a duped stdio grab).
        pipe_id: u64,
        /// `Some` iff this fd is a pty master/slave end. Data I/O is
        /// identical to a plain host pipe; this only changes ioctl
        /// handling and close cleanup. `None` for ordinary host pipes,
        /// sockets-as-pipes, and `/dev/*` chardevs.
        pty: Option<crate::vfs::PtyRole>,
        /// `true` iff both read and write are permitted on this fd (a FIFO
        /// opened `O_RDWR`). Ordinary pipe ends are one-way (gated by
        /// `is_read_end`); a `O_RDWR` FIFO is bidirectional like a pty but is
        /// NOT a tty, so it sets this flag instead of a fake `pty` role.
        bidirectional: bool,
        /// Write behavior classified once when adopting the host fd. Only real
        /// host FIFOs/pipes need Linux's blocking large-write completion loop.
        write_kind: HostWriteKind,
    },
    /// Host BSD socket backed by a real macOS file descriptor.
    /// Survives `libc::fork(2)`; the `family`/`type_` fields capture
    /// the *Linux* AF_* / SOCK_* values the guest asked for so that
    /// subsequent socket syscalls (sockaddr translation, getsockopt
    /// SO_TYPE, etc.) can answer in Linux terms.
    HostSocket {
        base: OpenDescriptionBase,
        /// The OWNING handle to the backing host fd (see [`HostFdRef`]).
        host_fd: HostFdRef,
        family: i32,
        type_: i32,
    },
    /// A regular file backed by a REAL macOS file descriptor into the
    /// `--fs host` overlay scratch. Unlike `File` (which caches bytes
    /// in memory and so diverges across `libc::fork`), the kernel fd
    /// is shared by fork, so a forked child's writes are visible to
    /// the parent - which is what makes apt's verify-via-temp-file
    /// patterns work. read/write/lseek/fstat/mmap operate directly on
    /// `host_fd`; the kernel owns the offset.
    HostFile {
        base: OpenDescriptionBase,
        /// The OWNING handle to the backing host fd (see [`HostFdRef`]).
        host_fd: HostFdRef,
        metadata: RootFsMetadata,
        writable: bool,
    },
    /// Synthetic AF_NETLINK socket. macOS has no AF_NETLINK, so we can't
    /// back this with a host fd; instead we model just enough of the
    /// rtnetlink (NETLINK_ROUTE) protocol for glibc's `__check_pf`,
    /// getaddrinfo and `ip`/`ss` tooling to enumerate a loopback
    /// interface and then stop. `bind`/`getsockname` report the socket's
    /// pid/groups; a RTM_GETLINK/RTM_GETADDR dump request queues a
    /// synthetic response into `recv_queue` that the next recvmsg/recvfrom
    /// drains, terminated by NLMSG_DONE.
    Netlink {
        base: OpenDescriptionBase,
        #[allow(dead_code)]
        protocol: i32,
        /// The guest socket type (SOCK_RAW or SOCK_DGRAM) this netlink socket was
        /// created with; reported by getsockopt(SO_TYPE). (audit M6)
        sock_type: i32,
        /// Netlink "port id" the socket is bound to (0 until bind picks one).
        pid: u32,
        /// Multicast group mask from bind (nl_groups).
        groups: u32,
        /// Bytes queued by a dump request, drained by recvmsg/recvfrom.
        recv_queue: VecDeque<u8>,
    },
    /// A POSIX message-queue descriptor (`mq_open(3)`). macOS has no POSIX
    /// mqueue, so carrick emulates it on a real host file under
    /// `/tmp/carrick-mqueue/` (see [`crate::dispatch::mqueue`]): the `mqd_t` IS a
    /// real fd (owned by the description's `host_fd` handle so `close`/`dup`/
    /// `poll` work for free), but the message data lives in the backing file,
    /// guarded by an OFD lock. The mqueue syscalls (`mq_timedsend`/
    /// `mq_timedreceive`/…) operate on the file by re-opening it through the fd
    /// here; ordinary `read`/`write` on the fd are EINVAL/EBADF (Linux rejects
    /// them on a mqd too).
    Mqueue {
        base: OpenDescriptionBase,
        /// OWNING handle (see [`HostFdRef`]) to the real host fd of the backing
        /// file under `/tmp/carrick-mqueue/`; only read for poll/readiness.
        /// Every read-modify-write opens a FRESH fd against `path` and takes an
        /// OFD lock on it, so a `libc::fork`-shared description's OFD lock can
        /// never be self-re-entrant and the serialization is true across
        /// processes.
        host_fd: HostFdRef,
        /// Absolute host path of the backing file (under `/tmp/carrick-mqueue/`),
        /// re-opened per operation for the OFD-locked RMW.
        path: String,
        /// `mq_msgsize` the queue was created with (a send EMSGSIZEs above it; a
        /// receive EMSGSIZEs below it).
        msg_size: usize,
        /// `mq_maxmsg` the queue was created with (capacity of the ring).
        max_msg: usize,
    },
}

#[derive(Debug)]
struct HostFdOwner {
    fd: i32,
}

impl Drop for HostFdOwner {
    fn drop(&mut self) {
        // Deliberately a bare per-process close: carrick forks real host
        // processes, and each address space independently closes its inherited
        // copy of the fd. Fork-correctness depends on this staying a plain
        // `libc::close` — never anything fancier.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// The OWNED, Arc-refcounted handle to a host kernel fd. The single owner of a
/// host-backed [`OpenDescription`]'s fd lives IN the description (`host_fd`
/// field); `Clone` bumps the refcount (never `dup(2)`s), and the last clone's
/// drop closes the fd. Borrow the number for a libc call via [`HostFdRef::raw`]
/// or as the Copy view type via [`HostFdRef::view`].
#[derive(Debug, Clone)]
pub(super) struct HostFdRef(Arc<HostFdOwner>);

impl HostFdRef {
    pub(super) fn new(fd: i32) -> Self {
        Self(Arc::new(HostFdOwner { fd }))
    }

    /// The raw fd number for a host `libc` call (borrowed — the caller must
    /// keep a `HostFdRef` alive for as long as the number is used).
    #[inline]
    pub(super) fn raw(&self) -> i32 {
        self.0.fd
    }

    /// The Copy borrowed VIEW of this fd (see [`HostFd`]); same liveness
    /// caveat as [`HostFdRef::raw`].
    #[inline]
    pub(super) fn view(&self) -> HostFd {
        HostFd(self.0.fd)
    }
}

#[derive(Debug, Clone)]
pub(super) struct OpenFile {
    pub(super) description: OpenDescriptionRef,
    pub(super) fd_flags: u64,
}

impl OpenFile {
    pub(super) fn new(description: OpenDescriptionRef, fd_flags: u64) -> Self {
        Self {
            description,
            fd_flags,
        }
    }
}

impl OpenDescription {
    /// The guest path this fd was opened at, for descriptions that track one
    /// (regular files, directories, synthetic files). `None` for host-fd-backed
    /// or anonymous descriptions. Used to serve `readlink(/proc/self/fd/N)`.
    pub(super) fn open_path(&self) -> Option<&str> {
        match self {
            OpenDescription::File { path, .. }
            | OpenDescription::Directory { path, .. }
            | OpenDescription::SyntheticFile { path, .. } => Some(path.as_str()),
            // A host-fd-backed regular file (e.g. `--fs host`) carries the guest
            // path it was opened at in its metadata — surface it so
            // readlink(/proc/self/fd/N) and fexecve (execveat AT_EMPTY_PATH)
            // recover the executable's path.
            OpenDescription::HostFile { metadata, .. } => metadata.path.to_str(),
            _ => None,
        }
    }

    /// The `readlink(/proc/self/fd/N)` target for an fd with NO backing guest
    /// path — pipes, sockets, and the anonymous-inode fds (eventfd/epoll/…).
    /// Path-backed descriptions return `None` so the caller resolves them via
    /// `open_path`/`fd_open_paths` instead. The `pipe:[ino]`/`socket:[ino]`
    /// inode is `inode_for_path` of the same label `stat_source`/fstat uses, so a
    /// tool comparing the readlink's `[ino]` against `fstat(fd).st_ino` agrees.
    /// Without this, `readlink /proc/self/fd/{1,2}` on a pipe/socket returned an
    /// empty string, breaking 'are we piped?' and fd-introspection heuristics.
    pub(super) fn readlink_target(&self) -> Option<String> {
        let label = match self {
            OpenDescription::File { .. }
            | OpenDescription::Directory { .. }
            | OpenDescription::SyntheticFile { .. }
            | OpenDescription::HostFile { .. } => return None,
            OpenDescription::EventFd { .. } => "anon_inode:[eventfd]".to_owned(),
            OpenDescription::TimerFd { .. } => "anon_inode:[timerfd]".to_owned(),
            OpenDescription::Epoll { .. } => "anon_inode:[eventpoll]".to_owned(),
            OpenDescription::Pidfd { .. } => "anon_inode:[pidfd]".to_owned(),
            OpenDescription::Inotify { .. } => "anon_inode:[inotify]".to_owned(),
            OpenDescription::SignalFd { .. } => "anon_inode:[signalfd]".to_owned(),
            OpenDescription::Mqueue { .. } => "anon_inode:[mqueue]".to_owned(),
            // A pty slave readlinks to its /dev/pts/N node (ttyname(3)); the
            // master has no /dev path, so report a stable anon label.
            OpenDescription::HostPipe {
                pty: Some(role), ..
            } => {
                if role.is_master {
                    "anon_inode:[carrick-pty]".to_owned()
                } else {
                    format!("/dev/pts/{}", role.index)
                }
            }
            // An anonymous pipe end (no recorded /dev path); a chardev like
            // /dev/null carries its path in fd_open_paths and is resolved earlier.
            OpenDescription::HostPipe { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. } => {
                format!("pipe:[{}]", inode_for_path(Path::new("pipe:[carrick]")))
            }
            OpenDescription::HostSocket { .. } | OpenDescription::Netlink { .. } => {
                format!("socket:[{}]", inode_for_path(Path::new("socket:[carrick]")))
            }
        };
        Some(label)
    }
}

pub(super) type OpenDescriptionRef = Arc<RwLock<OpenDescription>>;
pub(super) type PipeRef = Arc<Mutex<PipeState>>;

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct PipeState {
    pub(super) buffer: VecDeque<u8>,
    pub(super) readers: usize,
    pub(super) writers: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TtyFdKind {
    Stdio,
    Other,
}

/// Which form of an xattr syscall is being dispatched: the path/lpath
/// variants name a file by path; the f-variant names it by open fd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum XattrTarget {
    Path(GuestPtr),
    Fd(Fd),
}

#[derive(Debug, Clone)]
pub(super) struct StatRecord {
    pub(super) ino: u64,
    pub(super) mode: u32,
    pub(super) nlink: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    /// Device id this entry REPRESENTS (`st_rdev`) — non-zero only for a
    /// character/block device node materialised by `mknod(2)` (see
    /// `FsBackend::create_device`). Zero for every ordinary file/dir/etc.
    pub(super) rdev: u64,
    pub(super) size: u64,
    pub(super) atime: (i64, i64),
    pub(super) mtime: (i64, i64),
    pub(super) ctime: (i64, i64),
}

impl StatRecord {
    pub(super) fn from_metadata(metadata: &RootFsMetadata) -> Self {
        Self {
            ino: inode_for_path(&metadata.path),
            mode: linux_mode(metadata),
            nlink: if metadata.kind == RootFsEntryKind::Directory {
                2
            } else {
                1
            },
            uid: 0,
            gid: 0,
            rdev: 0,
            size: metadata.size as u64,
            atime: (0, 0),
            mtime: (0, 0),
            ctime: (0, 0),
        }
    }

    pub(super) fn from_real(path: &str, real: &crate::fs_backend::RealStat) -> Self {
        let metadata = RootFsMetadata {
            path: Path::new(path).to_path_buf(),
            kind: real.kind,
            mode: real.mode,
            size: real.size as usize,
        };
        let mode = linux_mode(&metadata);
        Self {
            ino: real.ino,
            mode,
            nlink: real.nlink,
            uid: real.uid,
            gid: real.gid,
            rdev: 0,
            size: real.size,
            atime: real.atime,
            mtime: real.mtime,
            ctime: real.ctime,
        }
    }

    pub(super) fn synthetic(path: &str, size: usize, mode: u32) -> Self {
        let path = Path::new(path).to_path_buf();
        Self {
            ino: inode_for_path(&path),
            mode,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: size as u64,
            atime: (0, 0),
            mtime: (0, 0),
            ctime: (0, 0),
        }
    }

    /// Override the reported file TYPE and `st_rdev` for a `mknod(2)` character/
    /// block device node. `dev` is `(type_bits, rdev)` from
    /// [`FsBackend::device_node`](crate::fs_backend::FsBackend::device_node), so
    /// this ONLY fires for a real device marker — `None` leaves a regular file's
    /// record completely unchanged. The permission bits are preserved; only the
    /// `S_IFMT` type field is replaced with the device type.
    pub(super) fn apply_device_node(&mut self, dev: Option<(u32, u64)>) {
        if let Some((type_bits, rdev)) = dev {
            self.mode = (self.mode & !LINUX_S_IFMT) | type_bits;
            self.rdev = rdev;
        }
    }

    pub(super) fn size_usize(&self) -> usize {
        self.size.min(usize::MAX as u64) as usize
    }
}

#[derive(Debug, Clone)]
pub(super) enum OpenStatSource {
    Record(StatRecord),
    HostFile {
        /// Borrowed Copy VIEW of the description's owned fd (see
        /// [`HostFdRef::view`]) — valid while the caller's `OpenFile` clone
        /// keeps the description alive.
        host_fd: HostFd,
        metadata: RootFsMetadata,
    },
    /// A path-backed entry (an open Directory, or an in-memory File) whose
    /// fd-stat must agree with a path-based stat of the SAME path. Under
    /// `--fs host` the path-stat (newfstatat/statx) reports the REAL host
    /// inode via `overlay.real_stat`, while a synthetic [`StatRecord`] derives
    /// `st_ino` from a hash of the path — so `fstat(open(dir))` and
    /// `lstat(dir)` disagreed and Python's `os.path.samestat` was False
    /// (shutil.rmtree then refused to clean the tempdir; test_glob cascaded
    /// to 15 ERRORs). `fd_stat_record` re-runs `real_stat(path)` here so the
    /// directory fd produces the IDENTICAL `StatRecord` the path-stat does;
    /// `fallback` is the synthetic record used when no host stat is available
    /// (the in-memory MemoryBackend, where the path-stat is ALSO synthetic).
    PathRecord {
        path: String,
        fallback: StatRecord,
    },
    /// A stream backed by a real host fd whose Linux file-TYPE must reflect what
    /// the host fd actually is, decided by `fstat(host_fd)`. A `HostPipe` covers
    /// BOTH an anonymous pipe end (host `pipe()` fd → `S_IFIFO`) AND a host
    /// character device like `/dev/null`/`/dev/zero`/`/dev/urandom` (host
    /// chardev → `S_IFCHR`). Hard-coding `S_IFIFO` made CPython mis-detect
    /// `/dev/null` (reopened over a closed fd 0/1/2 at startup) as a pipe and
    /// abort `init_sys_streams` (test_cmd_line.test_no_std*). fstat the real
    /// host fd: a chardev reports `S_IFCHR`, a pipe `S_IFIFO`. `fallback_mode`
    /// is used if the host fstat fails.
    HostStream {
        /// Borrowed Copy VIEW of the description's owned fd (see
        /// [`OpenStatSource::HostFile::host_fd`]).
        host_fd: HostFd,
        label: String,
        fallback_mode: u32,
    },
}

impl OpenDescription {
    fn base(&self) -> &OpenDescriptionBase {
        match self {
            OpenDescription::File { base, .. }
            | OpenDescription::Directory { base, .. }
            | OpenDescription::SyntheticFile { base, .. }
            | OpenDescription::EventFd { base, .. }
            | OpenDescription::TimerFd { base, .. }
            | OpenDescription::Epoll { base, .. }
            | OpenDescription::Pidfd { base, .. }
            | OpenDescription::PipeReader { base, .. }
            | OpenDescription::PipeWriter { base, .. }
            | OpenDescription::HostPipe { base, .. }
            | OpenDescription::HostFile { base, .. }
            | OpenDescription::HostSocket { base, .. }
            | OpenDescription::Inotify { base, .. }
            | OpenDescription::SignalFd { base, .. }
            | OpenDescription::Netlink { base, .. }
            | OpenDescription::Mqueue { base, .. } => base,
        }
    }

    fn base_mut(&mut self) -> &mut OpenDescriptionBase {
        match self {
            OpenDescription::File { base, .. }
            | OpenDescription::Directory { base, .. }
            | OpenDescription::SyntheticFile { base, .. }
            | OpenDescription::EventFd { base, .. }
            | OpenDescription::TimerFd { base, .. }
            | OpenDescription::Epoll { base, .. }
            | OpenDescription::Pidfd { base, .. }
            | OpenDescription::PipeReader { base, .. }
            | OpenDescription::PipeWriter { base, .. }
            | OpenDescription::HostPipe { base, .. }
            | OpenDescription::HostFile { base, .. }
            | OpenDescription::HostSocket { base, .. }
            | OpenDescription::Inotify { base, .. }
            | OpenDescription::SignalFd { base, .. }
            | OpenDescription::Netlink { base, .. }
            | OpenDescription::Mqueue { base, .. } => base,
        }
    }

    pub(super) fn status_flags(&self) -> u64 {
        self.base().status_flags()
    }

    pub(super) fn set_status_flags(&mut self, next: u64) {
        self.base_mut().set_status_flags(next);
    }

    pub(super) fn lease(&self) -> i32 {
        self.base().lease()
    }

    pub(super) fn set_lease(&mut self, lease: i32) {
        self.base_mut().set_lease(lease);
    }

    pub(super) fn owner(&self) -> (i32, i32) {
        self.base().owner()
    }

    pub(super) fn set_owner(&mut self, owner_type: i32, owner_pid: i32) {
        self.base_mut().set_owner(owner_type, owner_pid);
    }

    pub(super) fn async_sig(&self) -> i32 {
        self.base().async_sig()
    }

    pub(super) fn set_async_sig(&mut self, sig: i32) {
        self.base_mut().set_async_sig(sig);
    }

    pub(super) fn pipe_capacity(&self) -> i64 {
        self.base().pipe_capacity()
    }

    pub(super) fn set_pipe_capacity(&mut self, capacity: i64) {
        self.base_mut().set_pipe_capacity(capacity);
    }

    /// SO_RCVTIMEO for this description. Only HostSocket carries one; every
    /// other variant has no socket timeout, so returns None.
    pub(super) fn recv_timeout(&self) -> Option<Duration> {
        match self {
            OpenDescription::HostSocket { base, .. } => base.recv_timeout(),
            _ => None,
        }
    }

    /// SO_SNDTIMEO for this description. Only HostSocket carries one; every
    /// other variant has no socket timeout, so returns None.
    pub(super) fn send_timeout(&self) -> Option<Duration> {
        match self {
            OpenDescription::HostSocket { base, .. } => base.send_timeout(),
            _ => None,
        }
    }

    pub(super) fn stat_source(&self) -> OpenStatSource {
        match self {
            OpenDescription::File { path, metadata, .. }
            | OpenDescription::Directory { path, metadata, .. } => OpenStatSource::PathRecord {
                path: path.clone(),
                fallback: StatRecord::from_metadata(metadata),
            },
            OpenDescription::HostFile {
                host_fd, metadata, ..
            } => OpenStatSource::HostFile {
                host_fd: host_fd.view(),
                metadata: metadata.clone(),
            },
            OpenDescription::SyntheticFile { path, contents, .. } => {
                let mut record = StatRecord::synthetic(path, contents.len(), LINUX_S_IFREG | 0o444);
                // An nsfs fd (opened from /proc/<pid>/ns/<type>) reports the
                // STABLE initial-namespace inode, not a hash of the path, so two
                // opens of the same ns type fstat to the same st_ino (the
                // same-namespace equality invariant ioctl_ns checks).
                if let Some(ino) = crate::vfs::proc::ns_link_inode(path) {
                    record.ino = ino;
                }
                OpenStatSource::Record(record)
            }
            OpenDescription::EventFd { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:[eventfd]", 0, 0o600))
            }
            OpenDescription::TimerFd { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:[timerfd]", 0, 0o600))
            }
            OpenDescription::Epoll { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:[eventpoll]", 0, 0o600))
            }
            OpenDescription::Pidfd { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:[pidfd]", 0, 0o600))
            }
            OpenDescription::Inotify { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:[inotify]", 0, 0o600))
            }
            OpenDescription::SignalFd { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:[signalfd]", 0, 0o600))
            }
            OpenDescription::Mqueue { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:[mqueue]", 0, 0o600))
            }
            OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. } => {
                OpenStatSource::Record(StatRecord::synthetic(
                    "pipe:[carrick]",
                    0,
                    LINUX_S_IFIFO | 0o600,
                ))
            }
            OpenDescription::HostPipe { pty, host_fd, .. } => {
                if let Some(role) = pty {
                    // A pty SLAVE reports its /dev/pts/N path so its st_ino
                    // matches stat("/dev/pts/N"): glibc's ttyname_r readlinks
                    // /proc/self/fd/<fd> then stat-compares the two. The master
                    // keeps a constant synthetic label.
                    if role.is_master {
                        OpenStatSource::Record(StatRecord::synthetic(
                            "char:[carrick-pty]",
                            0,
                            LINUX_S_IFCHR | 0o600,
                        ))
                    } else {
                        OpenStatSource::Record(StatRecord::synthetic(
                            &format!("/dev/pts/{}", role.index),
                            0,
                            LINUX_S_IFCHR | 0o620,
                        ))
                    }
                } else {
                    // Anonymous pipe end OR a host character device (/dev/null,
                    // /dev/zero, …). fstat the real host fd to recover the true
                    // Linux file type instead of always claiming S_IFIFO.
                    OpenStatSource::HostStream {
                        host_fd: host_fd.view(),
                        label: "pipe:[carrick]".to_string(),
                        fallback_mode: LINUX_S_IFIFO | 0o600,
                    }
                }
            }
            OpenDescription::HostSocket { .. } | OpenDescription::Netlink { .. } => {
                OpenStatSource::Record(StatRecord::synthetic(
                    "socket:[carrick]",
                    0,
                    LINUX_S_IFSOCK | 0o600,
                ))
            }
        }
    }
}
