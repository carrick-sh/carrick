//! File-descriptor table and open-description model.
//!
//! Linux distinguishes two layers: the per-process *fd table* (numbers → open
//! file descriptions) and the *open file descriptions* themselves (the seekable
//! cursor, status flags, and backing object that `dup`/`fork`/`fork`+`exec`
//! share). Carrick mirrors that split in the authoritative Kernel
//! [`crate::kernel::FileTable`]. Each [`OpenFile`] (`FileSlot`) holds its
//! per-descriptor flags plus an `Arc<FileDescription>` with stable identity;
//! that Kernel description owns the opaque dispatch backing containing the
//! shared cursor, status flags, lease, and async-I/O owner. A draining identity
//! shell remains snapshot-visible after its last functional backing resource is
//! closed.
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
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::linux_abi::{
    LINUX_EFBIG, LINUX_S_IFCHR, LINUX_S_IFIFO, LINUX_S_IFMT, LINUX_S_IFREG, LINUX_S_IFSOCK,
    LinuxEpollEvent,
};
use crate::rootfs::{RootFsDirEntry, RootFsEntryKind, RootFsMetadata};

use super::{EpollKqueue, Fd, GuestPtr, HostFd, inode_for_path, linux_mode};

#[derive(Debug, Clone)]
pub(super) struct EpollInterest {
    /// The open-file description named by `fd` when EPOLL_CTL_ADD succeeded.
    /// This identity is load-bearing once forked processes have private fd
    /// tables: the same numeric fd can later name a different description in a
    /// child, whose close must not auto-remove the parent's shared epoll entry.
    /// Bare inherited stdio has no table-backed description and remains `None`.
    pub(super) target: Option<Arc<crate::kernel::FileDescription>>,
    pub(super) event: LinuxEpollEvent,
    /// Readiness bits already REPORTED to the guest for this registration. The
    /// software EPOLLET latch: `raw & !last_ready` is the edge. Cleared on
    /// consumption ([`crate::dispatch::SyscallDispatcher::epoll_rearm_after_io`]
    /// — an I/O syscall on the fd services the delivered edge), which is what
    /// makes the NEXT assertion a fresh edge.
    pub(super) last_ready: u32,
    /// Readiness COUNT the reported readiness in `last_ready` was observed at,
    /// so a SECOND edge can be delivered while the first is still unconsumed
    /// (`observed > last_read_avail` — see `epoll_pwait_wait_core`). What the
    /// count measures is per-fd:
    ///
    /// - a FIONREAD-measurable fd (pipe, stream socket, datagram socket): bytes
    ///   buffered. Monotone until the guest reads, and a read decrements this
    ///   baseline by the bytes consumed.
    /// - a LISTENER: the pending accept-queue depth (the multiplexer edge's
    ///   `readiness_count`; FIONREAD is always 0 for a listener). This is NOT
    ///   monotone — accepting drains it — so growth alone would be an unsound
    ///   arrival predicate. It is sound here because the guest-driven way the
    ///   depth falls, accept, is ALSO the consumption that resets this baseline
    ///   and `last_ready` to 0: within any window containing no accept the
    ///   depth only rises. A listener's ET readiness is therefore "a connection
    ///   arrived since you last drained" — carried by `raw & !last_ready` after
    ///   the consumption re-arm — with growth covering only the extra arrivals
    ///   that land while an earlier edge is still unaccepted.
    ///   (`epoll_et_delivers_listener_edge_after_accept_drain` pins the drain
    ///   half, `..._without_read_byte_growth` the growth half.)
    ///
    ///   The remaining way a depth could fall without an accept is the host
    ///   dropping an already-queued connection (measured NOT to happen on
    ///   macOS: a queued connection reset by its client stays in the queue and
    ///   is returned by accept). Were a host to do it, the effect is bounded to
    ///   deferring one edge for a guest that was told EPOLLIN and has not yet
    ///   accepted — its first accept, which the ET contract requires, resets
    ///   the baseline.
    pub(super) last_read_avail: u64,
    /// Edge-triggered write side was attempted and returned EAGAIN after an
    /// earlier EPOLLOUT delivery. Keep the host write filter armed while still
    /// suppressing immediate sampled OUT redelivery; the next host write event
    /// is a fresh transition and should be delivered once.
    pub(super) write_backpressured: bool,
    /// Consumption generation for the software edge latch. `epoll_wait`
    /// samples readiness without holding the epoll description lock, so an I/O
    /// syscall can service an edge before that sample is committed. The sample
    /// carries this generation and may update `last_ready` only if it still
    /// matches; otherwise it would re-latch an already-consumed edge and hide
    /// the next arrival. Incremented for every matching read/write consumption,
    /// including one whose state was already advanced by a concurrent sample.
    pub(super) io_gen: u64,
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
}

impl EventFdState {
    pub(super) fn new(counter: u64) -> Self {
        Self {
            slot: crate::eventfd_shm::alloc(counter),
            local: std::sync::atomic::AtomicU64::new(counter),
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
}

/// A non-blocking, CLOEXEC host pipe relocated above the guest fd range, used as
/// an eventfd's readiness channel. `None` on failure (caller degrades to the
/// in-memory recompute + EVFILT_USER broadcast). The returned [`HostFdRef`]s
/// own the two ends; their `Drop`s close them (per process — each forked host
/// process independently closes its inherited copies, as before).
pub(crate) fn make_readiness_pipe() -> Option<(HostFdRef, HostFdRef)> {
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
    /// Number of Linux fd-table entries that currently name this open file
    /// description across every HvPatch process namespace. This deliberately
    /// excludes transient Rust `Arc` clones used by in-flight syscalls. Linux
    /// removes an epoll interest only after the last fd referring to the open
    /// description closes; `Arc::strong_count` cannot express that invariant.
    fd_refs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
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
    /// Guest-intended SO_REUSEADDR / SO_REUSEPORT, tracked so getsockopt reports
    /// what the guest set — NOT the host SO_REUSEPORT carrick silently turns on
    /// to emulate Linux UDP wildcard-rebind from SO_REUSEADDR. (audit M4)
    so_reuseaddr: bool,
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
    /// Guest-set `IPV6_MULTICAST_IF` interface index; `None` = never set.
    ///
    /// Linux accepts index **0**, meaning "clear the multicast interface, let
    /// routing choose". Darwin has no encoding for that: index 0 is `EINVAL`,
    /// and once a non-zero index is set there is no way to unset it (measured
    /// on macOS 27 — `0` as `u32`, `0` as `int`, and a zero-length optval all
    /// return `EINVAL`, and the readback keeps the previous index). So the
    /// guest's intent is tracked here and reported by `getsockopt`, and a
    /// requested index of 0 is not forwarded to the host.
    ipv6_multicast_if: Option<u32>,
    /// True after a successful `listen(2)`. Darwin's EVFILT_READ `data` for a
    /// listening socket is the pending-connection count, so an EPOLLET filter
    /// must remain armed to observe that count growing after a redundant
    /// same-count readiness delivery.
    listening: bool,
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
    /// Linux-visible pending socket error for synthetic networking paths whose
    /// failure is not backed by the host socket's SO_ERROR state.
    pending_socket_error: Option<i32>,
    /// Synthetic connected UDP peers can only surface an asynchronous error
    /// after a datagram is sent. Store that errno here and copy it into
    /// `pending_socket_error` after each successful connected send.
    socket_error_after_send: Option<i32>,
    /// File-sealing state (memfd_create(2)/fcntl F_ADD_SEALS/F_GET_SEALS). `None`
    /// means this description does not support sealing (F_GET_SEALS/F_ADD_SEALS →
    /// EINVAL); `Some(bits)` is the current seal set of a sealable memfd (empty
    /// when created with MFD_ALLOW_SEALING, F_SEAL_SEAL preset otherwise). Lives
    /// on the open-file description so a dup'd fd shares it, matching the kernel's
    /// per-inode seal set for the common dup path.
    seals: Option<u32>,
    /// True for a `memfd_secret(2)` description. Secret memory has no file
    /// read/write methods (read(2)/write(2)/pread/readv/… → EINVAL, and it can
    /// never be a splice/sendfile endpoint), must be mapped MAP_SHARED (a
    /// MAP_PRIVATE mmap → EINVAL), and its mapped pages are hidden from
    /// `/proc/<pid>/mem`. Lives on the open-file description so a dup'd fd
    /// shares it, matching the kernel's per-inode secretmem state.
    secretmem: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct SocketMulticastMembership {
    pub(super) level: i32,
    pub(super) source_specific: bool,
    pub(super) optval: Vec<u8>,
}

impl OpenDescriptionBase {
    pub(super) fn new(status_flags: u64) -> Self {
        Self {
            status_flags,
            fd_refs: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            so_reuseaddr: false,
            so_reuseport: false,
            ipv6_multicast_if: None,
            so_rcvbuf: None,
            so_sndbuf: None,
            so_passcred: false,
            listening: false,
            connect_in_progress: false,
            pending_socket_error: None,
            socket_error_after_send: None,
            lease: crate::linux_abi::LINUX_F_UNLCK,
            recv_timeout: None,
            send_timeout: None,
            owner_type: 0,
            owner_pid: 0,
            async_sig: 0,
            pipe_capacity: crate::linux_abi::LINUX_PIPE_BUF_SIZE,
            pipe_capacity_shared: None,
            seals: None,
            secretmem: false,
        }
    }

    pub(super) fn seals(&self) -> Option<u32> {
        self.seals
    }

    pub(super) fn set_seals(&mut self, seals: Option<u32>) {
        self.seals = seals;
    }

    pub(super) fn secretmem(&self) -> bool {
        self.secretmem
    }

    pub(super) fn set_secretmem(&mut self, secretmem: bool) {
        self.secretmem = secretmem;
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

    #[inline]
    pub(super) fn is_append(&self) -> bool {
        carrick_abi::LinuxOpenFlags::from_bits_truncate(self.status_flags)
            .contains(carrick_abi::LinuxOpenFlags::APPEND)
    }

    #[inline]
    pub(super) fn is_nonblocking(&self) -> bool {
        carrick_abi::LinuxOpenFlags::from_bits_truncate(self.status_flags)
            .contains(carrick_abi::LinuxOpenFlags::NONBLOCK)
    }

    #[inline]
    pub(super) fn is_async(&self) -> bool {
        carrick_abi::LinuxOpenFlags::from_bits_truncate(self.status_flags)
            .contains(carrick_abi::LinuxOpenFlags::ASYNC)
    }

    #[inline]
    pub(super) fn access_mode(&self) -> u64 {
        self.status_flags & carrick_abi::LINUX_O_ACCMODE
    }

    #[inline]
    pub(super) fn is_write_only(&self) -> bool {
        self.access_mode() == carrick_abi::LINUX_O_WRONLY
    }

    #[inline]
    pub(super) fn is_read_only(&self) -> bool {
        self.access_mode() == carrick_abi::LINUX_O_RDONLY
    }

    #[inline]
    pub(super) fn is_path(&self) -> bool {
        carrick_abi::LinuxOpenFlags::from_bits_truncate(self.status_flags)
            .contains(carrick_abi::LinuxOpenFlags::PATH)
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

    /// Guest-intended SO_REUSEADDR / SO_REUSEPORT (audit M4).
    pub(super) fn so_reuseaddr(&self) -> bool {
        self.so_reuseaddr
    }
    pub(super) fn set_so_reuseaddr(&mut self, on: bool) {
        self.so_reuseaddr = on;
    }
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
    /// Guest-set `IPV6_MULTICAST_IF` index (`None` = never set). See the field
    /// comment: Linux's index-0 "clear" has no Darwin equivalent, so the guest's
    /// value is served from here rather than from the host socket.
    pub(super) fn ipv6_multicast_if(&self) -> Option<u32> {
        self.ipv6_multicast_if
    }
    pub(super) fn set_ipv6_multicast_if(&mut self, index: u32) {
        self.ipv6_multicast_if = Some(index);
    }

    pub(super) fn set_so_passcred(&mut self, on: bool) {
        self.so_passcred = on;
    }
    pub(super) fn listening(&self) -> bool {
        self.listening
    }
    pub(super) fn set_listening(&mut self, on: bool) {
        self.listening = on;
    }
    pub(super) fn connect_in_progress(&self) -> bool {
        self.connect_in_progress
    }
    pub(super) fn set_connect_in_progress(&mut self, on: bool) {
        self.connect_in_progress = on;
    }
    pub(super) fn pending_socket_error(&self) -> Option<i32> {
        self.pending_socket_error
    }
    pub(super) fn set_pending_socket_error(&mut self, errno: i32) {
        self.pending_socket_error = Some(errno);
    }
    pub(super) fn take_pending_socket_error(&mut self) -> Option<i32> {
        self.pending_socket_error.take()
    }
    pub(super) fn socket_error_after_send(&self) -> Option<i32> {
        self.socket_error_after_send
    }
    pub(super) fn set_socket_error_after_send(&mut self, errno: i32) {
        self.socket_error_after_send = Some(errno);
    }
    pub(super) fn clear_socket_error_after_send(&mut self) {
        self.socket_error_after_send = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum HostWriteKind {
    PipeLike,
    SocketLike,
    RegularFile,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub(crate) struct NativeReexecFdTableV1 {
    pub(crate) files: Vec<NativeReexecFdV1>,
    pub(crate) descriptions: Vec<NativeReexecDescriptionV1>,
    pub(crate) close_on_exec_host_fds: Vec<i32>,
    pub(crate) closed_stdio: [bool; 3],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub(crate) struct NativeReexecFdV1 {
    pub(crate) guest_fd: i32,
    pub(crate) fd_flags: u64,
    pub(crate) description_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub(crate) enum NativeReexecDescriptionV1 {
    Pipe {
        stable_id: u64,
        host_fd: i32,
        original_host_fd_flags: i32,
        host_device: u64,
        host_inode: u64,
        host_mode: u32,
        status_flags: u64,
        pipe_capacity: i64,
        is_read_end: bool,
        pipe_id: u64,
        bidirectional: bool,
        write_kind: HostWriteKind,
    },
    File {
        stable_id: u64,
        host_fd: i32,
        original_host_fd_flags: i32,
        host_device: u64,
        host_inode: u64,
        host_mode: u32,
        status_flags: u64,
        guest_path: Vec<u8>,
        guest_mode: u32,
        guest_size: u64,
        writable: bool,
    },
    Socket {
        stable_id: u64,
        host_fd: i32,
        original_host_fd_flags: i32,
        host_device: u64,
        host_inode: u64,
        host_mode: u32,
        status_flags: u64,
        family: i32,
        type_: i32,
        protocol: i32,
    },
    IoUring {
        stable_id: u64,
        data_fd: i32,
        data_fd_flags: i32,
        data_identity: crate::dispatch::ioring::HostBackingIdentity,
        lock_fd: i32,
        lock_fd_flags: i32,
        lock_identity: crate::dispatch::ioring::HostBackingIdentity,
        layout: crate::dispatch::ioring::IoUringLayoutSnapshot,
        status_flags: u64,
    },
}

impl NativeReexecDescriptionV1 {
    #[allow(dead_code)]
    pub(crate) const fn stable_id(&self) -> u64 {
        match self {
            Self::Pipe { stable_id, .. }
            | Self::File { stable_id, .. }
            | Self::Socket { stable_id, .. }
            | Self::IoUring { stable_id, .. } => *stable_id,
        }
    }
}

impl NativeReexecFdTableV1 {
    #[allow(dead_code)]
    pub(crate) fn survivor_host_fds(&self) -> Vec<(i32, i32)> {
        self.descriptions
            .iter()
            .flat_map(|description| match description {
                NativeReexecDescriptionV1::Pipe {
                    host_fd,
                    original_host_fd_flags,
                    ..
                }
                | NativeReexecDescriptionV1::File {
                    host_fd,
                    original_host_fd_flags,
                    ..
                }
                | NativeReexecDescriptionV1::Socket {
                    host_fd,
                    original_host_fd_flags,
                    ..
                } => vec![(*host_fd, *original_host_fd_flags)],
                NativeReexecDescriptionV1::IoUring {
                    data_fd,
                    data_fd_flags,
                    lock_fd,
                    lock_fd_flags,
                    ..
                } => vec![(*data_fd, *data_fd_flags), (*lock_fd, *lock_fd_flags)],
            })
            .collect()
    }
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
pub(crate) struct PidfdWatch {
    /// Owns the backing fds; held only so `Drop` closes them (the registered
    /// process-exit watch is reclaimed with it). Never read after construction.
    /// `Mutex` only to make the otherwise-`!Sync` trait object shareable across
    /// threads (the dispatcher's `KernelState` must be `Send`); never locked.
    #[allow(dead_code)]
    mux: Mutex<Box<dyn carrick_hal::event::EventMultiplexer>>,
    poll_fd: i32,
}

impl PidfdWatch {
    pub(crate) fn new(mux: Box<dyn carrick_hal::event::EventMultiplexer>) -> Self {
        let poll_fd = mux.poll_fd();
        Self {
            mux: Mutex::new(mux),
            poll_fd,
        }
    }

    /// The pollable fd readable when the watched process exits.
    pub(crate) fn poll_fd(&self) -> i32 {
        self.poll_fd
    }

    /// Make a guest-virtual pidfd readable after its in-process target exits.
    /// The process table calls this exactly when it publishes the target's
    /// zombie record. A saturated user wake is already the required persistent
    /// readiness, so firing is deliberately best-effort.
    pub(crate) fn publish_exit(&self) {
        let _ = self.mux.lock().trigger_user(0);
    }
}

impl crate::kernel::TaskExitSubscriber for PidfdWatch {
    fn publish_exit(&self) {
        PidfdWatch::publish_exit(self);
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

/// Identity carried by a pidfd's open-file description. This is intentionally
/// typed: treating an HvPatch guest pid as a Darwin pid recreated the 1:1
/// process model inside the backend whose purpose is to break that mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PidfdTarget {
    Host(i32),
    Hvpatch(crate::kernel::TaskKey),
}

/// A TRUSTED host dirfd backing an `OpenDescription::Directory` on the
/// `--fs host` fast lane. Trust flows ONLY from the contained fast path:
/// the fd was opened under the sandbox root with a byte-exact `F_GETPATH`
/// containment proof (no symlink, Unicode alias, or escape anywhere in the
/// chain) and the directory is outside every synthetic/VFS mount. The
/// dispatcher may then service single-component `openat`/`newfstatat`/
/// `faccessat` DIRECTLY against this fd (a single `O_NOFOLLOW` component
/// under a contained dir cannot escape), and `getdents64` may stream the
/// directory from it. The fd is `HostFdRef`-owned (closed with the last
/// description clone) and `O_CLOEXEC` host-side, and — like every host fd —
/// survives `libc::fork` (the fd table is per-process already).
#[derive(Debug, Clone)]
pub(super) struct TrustedHostDir {
    pub(super) fd: HostFdRef,
    /// Structural-generation stamp for a directory anchored in the immutable
    /// cached lower. `None` means the fd belongs to the historical
    /// materialized host root, which is itself the merged namespace. A lower
    /// fd is usable directly only while the sparse upper's shared generation
    /// still matches this stamp.
    pub(super) immutable_lower_generation: Option<u64>,
    /// True once `entries` has been materialized from this fd (one streamed
    /// readdir batch, no per-child stat). Cleared by an `lseek(0, SEEK_SET)`
    /// rewind so the next `getdents64` takes a FRESH snapshot (matching
    /// Linux, where a rewound getdents re-reads the directory).
    pub(super) entries_loaded: bool,
}

impl TrustedHostDir {
    pub(super) fn new(fd: HostFdRef) -> Self {
        Self {
            fd,
            immutable_lower_generation: None,
            entries_loaded: false,
        }
    }

    pub(super) fn immutable_lower(fd: HostFdRef, generation: u64) -> Self {
        Self {
            fd,
            immutable_lower_generation: Some(generation),
            entries_loaded: false,
        }
    }

    pub(super) fn namespace_is_current(&self) -> bool {
        self.immutable_lower_generation
            .is_none_or(|generation| crate::fs_resolve_cache::current_generation() == generation)
    }
}

#[derive(Debug, Clone)]
pub(super) enum OpenDescription {
    /// Observable identity shell retained after the last functional fd slot
    /// closes. All host descriptors and subsystem resources have already been
    /// dropped; only immutable snapshot classification remains.
    Closed { was_epoll: bool },
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
        /// `Some` iff this directory rides the `--fs host` trusted-dirfd fast
        /// lane (see [`TrustedHostDir`]). `None` keeps every historical path:
        /// VFS-mount dirs, the memory backend, and any open the contained
        /// fast path could not prove.
        trusted_host_dir: Option<TrustedHostDir>,
    },
    SyntheticFile {
        base: OpenDescriptionBase,
        path: String,
        contents: Vec<u8>,
        offset: usize,
    },
    SyntheticDevice {
        base: OpenDescriptionBase,
        kind: crate::vfs::SyntheticDeviceKind,
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
    /// A Linux pidfd referring to a process. Mirrored-process backends watch a
    /// host process through `EVFILT_PROC`/native pidfd. HvPatch instead arms an
    /// `EVFILT_USER`-style wake and lets its shared guest process table publish
    /// readiness: several Linux processes intentionally share one host pid in
    /// that backend, so a host-process watch cannot encode the target.
    Pidfd {
        base: OpenDescriptionBase,
        target: PidfdTarget,
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
    /// A Linux fanotify group (syscall 262 `fanotify_init`). Like `Inotify` it
    /// is a pollable, non-seekable, non-file fd; `read(2)` drains queued
    /// `struct fanotify_event_metadata` records, allocating one descriptor per
    /// event in the READING process's table. The group is shared by `Arc` so a
    /// `dup` or a guest `fork` refers to the same queue and the same marks —
    /// see [`crate::fanotify`].
    Fanotify {
        base: OpenDescriptionBase,
        group: Arc<crate::fanotify::FanotifyGroup>,
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
    /// A `perf_event_open(2)` counter (see [`super::perf`]). Like the other
    /// anonymous-inode fds it is neither seekable (`lseek` → ESPIPE) nor
    /// writable (EINVAL); `read(2)` reports the counter in the
    /// `attr.read_format` layout and the `PERF_EVENT_IOC_*` ioctls drive it.
    /// The `Arc` keeps `dup(2)`d fds on one shared counter, matching the
    /// kernel's description-owned event object.
    PerfEvent {
        base: OpenDescriptionBase,
        state: Arc<super::perf::PerfEventState>,
    },
    /// A new-mount-API filesystem context (`fsopen(2)`/`fspick(2)`). An
    /// anon-inode fd carrying the staged configuration a subsequent
    /// `fsconfig(2)` manipulates. Linux reachability note: every entry point of
    /// the family is CAP_SYS_ADMIN-gated exactly like the Docker oracle's
    /// default seccomp/cap profile, so a default-caps guest only ever sees
    /// EPERM; this object is reachable once a guest holds CAP_SYS_ADMIN (e.g.
    /// after `unshare(CLONE_NEWUSER)` grants a full in-namespace set). The
    /// state is `Arc`-shared so `dup(2)` clones operate on the SAME context,
    /// as on Linux. Superblock creation itself (`FSCONFIG_CMD_CREATE` /
    /// `CMD_RECONFIGURE`) is deferred (EOPNOTSUPP) — carrick's VFS cannot
    /// instantiate or reconfigure superblocks, and fabricating success would
    /// leak into `fsmount`/`move_mount` guest-visible state.
    FsContext {
        base: OpenDescriptionBase,
        state: Arc<Mutex<super::mount_api::FsContextState>>,
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
        /// Keyed by pipe id rather than the per-fd host inode because BSD gives
        /// a pipe's two ends DIFFERENT `st_ino` (Linux shares one), so an inode
        /// key armed on the read end would never match the write-end trigger.
        /// Assigned at pipe creation from a stable hash of one end's host
        /// `(st_dev, st_ino)` and fixed before any fork. `0` only when the host
        /// descriptor could not be statted.
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
        /// Linux protocol requested at socket creation. Kept separately from
        /// the host backing protocol because compatibility sockets (UDPLITE,
        /// FreeBSD ping sockets) may use a different host protocol.
        protocol: i32,
        /// Linux-visible MCAST_* memberships. Darwin has no protocol-independent
        /// MCAST_* optnames, so these are bookkeeping only; accepted sockets start
        /// empty because Linux does not copy listener memberships across accept.
        mcast_memberships: Vec<SocketMulticastMembership>,
        synthetic_recv: VecDeque<(Vec<u8>, Vec<u8>)>,
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
    /// `mq_timedreceive`/…) operate on a hidden hardlink to the backing object,
    /// so `mq_unlink` can remove the public name while existing descriptors keep
    /// working; ordinary `read`/`write` on the fd are EINVAL/EBADF (Linux rejects
    /// them on a mqd too).
    /// A live eBPF map (`bpf(2)` `BPF_MAP_CREATE`): an anonymous-inode fd
    /// whose object lives in [`crate::dispatch::bpf::BpfMap`]. Shared by
    /// `Arc`, so `dup` and an in-carrier `fork` see one map, as Linux shares
    /// the kernel object behind the fd. Ordinary `read`/`write`/`lseek` on
    /// the fd are `EINVAL`, like any anon-inode fd.
    BpfMap {
        base: OpenDescriptionBase,
        map: Arc<crate::dispatch::bpf::BpfMap>,
    },
    /// A loaded eBPF program (`bpf(2)` `BPF_PROG_LOAD`): metadata only —
    /// carrick validates the instruction stream structurally and never
    /// executes it (see `dispatch/bpf.rs` module docs). The fd supports the
    /// lifecycle surface (`dup`/`close`/fstat/proc links); attachment
    /// surfaces reject it.
    BpfProg {
        base: OpenDescriptionBase,
        #[allow(dead_code)]
        prog: Arc<crate::dispatch::bpf::BpfProg>,
    },
    Mqueue {
        base: OpenDescriptionBase,
        /// OWNING handle (see [`HostFdRef`]) to the real host fd of the backing
        /// file under `/tmp/carrick-mqueue/`; only read for poll/readiness.
        /// Every read-modify-write opens a FRESH fd against `path` and takes an
        /// OFD lock on it, so a `libc::fork`-shared description's OFD lock can
        /// never be self-re-entrant and the serialization is true across
        /// processes.
        host_fd: HostFdRef,
        /// Absolute host path of the hidden backing object (under
        /// `/tmp/carrick-mqueue/`), re-opened per operation for the OFD-locked
        /// RMW.
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
pub(crate) struct HostFdRef(Arc<HostFdOwner>);

impl HostFdRef {
    pub(super) fn new(fd: i32) -> Self {
        Self(Arc::new(HostFdOwner { fd }))
    }

    /// The raw fd number for a host `libc` call (borrowed — the caller must
    /// keep a `HostFdRef` alive for as long as the number is used).
    #[inline]
    pub(crate) fn raw(&self) -> i32 {
        self.0.fd
    }

    /// The Copy borrowed VIEW of this fd (see [`HostFd`]); same liveness
    /// caveat as [`HostFdRef::raw`].
    #[inline]
    pub(super) fn view(&self) -> HostFd {
        HostFd(self.0.fd)
    }
}

pub(crate) type OpenFile = crate::kernel::FileSlot;

pub(super) fn kernel_file_description(
    description: OpenDescriptionRef,
) -> Arc<crate::kernel::FileDescription> {
    Arc::new(
        crate::kernel::FileDescription::concrete(description).unwrap_or_else(|error| {
            tracing::error!(%error, "file-description identity allocation failed");
            std::process::abort();
        }),
    )
}

#[allow(dead_code)]
pub(super) fn restored_kernel_file_description(
    stable_id: u64,
    description: OpenDescriptionRef,
) -> Result<Arc<crate::kernel::FileDescription>, String> {
    crate::kernel::FileDescription::concrete_restored(stable_id, description)
        .map(Arc::new)
        .map_err(|error| format!("restore file-description identity {stable_id}: {error}"))
}

impl crate::kernel::FileSlot {
    pub(super) fn from_open_description(description: OpenDescriptionRef, fd_flags: u64) -> Self {
        Self::new(kernel_file_description(description), fd_flags)
    }
}

impl OpenDescription {
    // Both methods below are only reached from `snapshot_native_reexec_fd_table`
    // (`dispatch/mod.rs`), which carries the identical
    // `#[cfg(any(test, ...))]` gate.
    #[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
    #[allow(dead_code)]
    pub(super) fn reexec_host_fd(&self) -> Option<i32> {
        match self {
            Self::HostPipe { host_fd, .. }
            | Self::HostSocket { host_fd, .. }
            | Self::HostFile { host_fd, .. }
            | Self::Mqueue { host_fd, .. } => Some(host_fd.raw()),
            _ => None,
        }
    }

    #[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
    #[allow(dead_code)]
    pub(super) fn reexec_kind_name(&self) -> &'static str {
        match self {
            Self::Closed { .. } => "closed",
            Self::File { .. } => "file",
            Self::Directory { .. } => "directory",
            Self::SyntheticFile { .. } => "synthetic_file",
            Self::SyntheticDevice { .. } => "synthetic_device",
            Self::EventFd { .. } => "eventfd",
            Self::TimerFd { .. } => "timerfd",
            Self::Epoll { .. } => "epoll",
            Self::Pidfd { .. } => "pidfd",
            Self::Inotify { .. } => "inotify",
            Self::Fanotify { .. } => "fanotify",
            Self::SignalFd { .. } => "signalfd",
            Self::PerfEvent { .. } => "perf_event",
            Self::FsContext { .. } => "fscontext",
            Self::PipeReader { .. } => "pipe_reader",
            Self::PipeWriter { .. } => "pipe_writer",
            Self::HostPipe { .. } => "host_pipe",
            Self::HostSocket { .. } => "host_socket",
            Self::HostFile { .. } => "host_file",
            Self::Netlink { .. } => "netlink",
            Self::Mqueue { .. } => "mqueue",
            Self::BpfMap { .. } => "bpf_map",
            Self::BpfProg { .. } => "bpf_prog",
        }
    }

    /// The guest path this fd was opened at, for descriptions that track one
    /// (regular files, directories, synthetic files). `None` for host-fd-backed
    /// or anonymous descriptions. Used to serve `readlink(/proc/self/fd/N)`.
    pub(super) fn open_path(&self) -> Option<&str> {
        match self {
            OpenDescription::File { path, .. }
            | OpenDescription::Directory { path, .. }
            | OpenDescription::SyntheticFile { path, .. } => Some(path.as_str()),
            OpenDescription::SyntheticDevice { kind, .. } => Some(kind.as_str()),
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
            OpenDescription::Closed { .. } => return None,
            OpenDescription::File { .. }
            | OpenDescription::Directory { .. }
            | OpenDescription::SyntheticFile { .. }
            | OpenDescription::SyntheticDevice { .. }
            | OpenDescription::HostFile { .. } => return None,
            OpenDescription::EventFd { .. } => "anon_inode:[eventfd]".to_owned(),
            OpenDescription::TimerFd { .. } => "anon_inode:[timerfd]".to_owned(),
            OpenDescription::Epoll { .. } => "anon_inode:[eventpoll]".to_owned(),
            OpenDescription::Pidfd { .. } => "anon_inode:[pidfd]".to_owned(),
            OpenDescription::Inotify { .. } => "anon_inode:[inotify]".to_owned(),
            OpenDescription::Fanotify { .. } => "anon_inode:[fanotify]".to_owned(),
            OpenDescription::SignalFd { .. } => "anon_inode:[signalfd]".to_owned(),
            OpenDescription::PerfEvent { .. } => "anon_inode:[perf_event]".to_owned(),
            OpenDescription::FsContext { .. } => "anon_inode:[fscontext]".to_owned(),
            OpenDescription::Mqueue { .. } => "anon_inode:[mqueue]".to_owned(),
            // Linux spells the bpf anon-inode labels WITHOUT brackets.
            OpenDescription::BpfMap { .. } => "anon_inode:bpf-map".to_owned(),
            OpenDescription::BpfProg { .. } => "anon_inode:bpf-prog".to_owned(),
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
            OpenDescription::HostPipe { pipe_id, .. } => {
                let stat_label = host_stream_stat_label(*pipe_id, LINUX_S_IFIFO);
                format!("pipe:[{}]", inode_for_path(Path::new(&stat_label)))
            }
            OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. } => {
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

impl crate::kernel::FileDescriptionBacking for RwLock<OpenDescription> {
    fn is_epoll(&self) -> bool {
        matches!(
            &*self.read(),
            OpenDescription::Epoll { .. } | OpenDescription::Closed { was_epoll: true }
        )
    }

    fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<crate::kernel::FileDescriptionBackingSnapshot> {
        use crate::kernel::FileDescriptionBackingKind as Kind;

        let description = self.try_read_until(deadline)?;
        let kind = match &*description {
            OpenDescription::Closed { .. } => Kind::Closed,
            OpenDescription::File { .. } => Kind::File,
            OpenDescription::Directory { .. } => Kind::Directory,
            OpenDescription::SyntheticFile { .. } => Kind::SyntheticFile,
            OpenDescription::SyntheticDevice { .. } => Kind::SyntheticDevice,
            OpenDescription::EventFd { .. } => Kind::EventFd,
            OpenDescription::TimerFd { .. } => Kind::TimerFd,
            OpenDescription::Epoll { .. } => Kind::Epoll,
            OpenDescription::Pidfd { .. } => Kind::Pidfd,
            OpenDescription::PipeReader { .. } => Kind::PipeReader,
            OpenDescription::PipeWriter { .. } => Kind::PipeWriter,
            OpenDescription::HostPipe { .. } => Kind::HostPipe,
            OpenDescription::HostFile { .. } => Kind::HostFile,
            OpenDescription::HostSocket { .. } => Kind::HostSocket,
            OpenDescription::Inotify { .. } => Kind::Inotify,
            OpenDescription::Fanotify { .. } => Kind::Fanotify,
            OpenDescription::SignalFd { .. } => Kind::SignalFd,
            OpenDescription::Netlink { .. } => Kind::Netlink,
            OpenDescription::Mqueue { .. } => Kind::Mqueue,
            OpenDescription::BpfMap { .. } => Kind::BpfMap,
            OpenDescription::BpfProg { .. } => Kind::BpfProg,
            OpenDescription::PerfEvent { .. } => Kind::PerfEvent,
            OpenDescription::FsContext { .. } => Kind::FsContext,
        };
        let status_flags = (!matches!(&*description, OpenDescription::Closed { .. }))
            .then(|| description.base().status_flags());
        let offset = match &*description {
            OpenDescription::File { offset, .. }
            | OpenDescription::Directory { offset, .. }
            | OpenDescription::SyntheticFile { offset, .. } => u64::try_from(*offset).ok(),
            OpenDescription::HostFile { host_fd, .. } => super::fs::host_fd_offset(host_fd.view()),
            _ => None,
        };
        let host_fd = match &*description {
            OpenDescription::HostPipe { host_fd, .. }
            | OpenDescription::HostFile { host_fd, .. }
            | OpenDescription::HostSocket { host_fd, .. } => Some(host_fd.raw()),
            _ => None,
        };
        let path = match &*description {
            OpenDescription::File { path, .. }
            | OpenDescription::Directory { path, .. }
            | OpenDescription::SyntheticFile { path, .. } => Some(path.clone()),
            OpenDescription::SyntheticDevice { kind, .. } => Some(kind.as_str().to_string()),
            OpenDescription::HostFile { metadata, .. } => {
                Some(metadata.path.to_string_lossy().into_owned())
            }
            _ => None,
        };
        let pipe_id = match &*description {
            OpenDescription::HostPipe { pipe_id, .. } => Some(*pipe_id),
            _ => None,
        };
        let mut epoll_interests = match &*description {
            OpenDescription::Epoll { interest, .. } => interest
                .values()
                .filter_map(|slot| slot.target.as_ref().map(|target| target.id()))
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        epoll_interests.sort_unstable();
        epoll_interests.dedup();
        Some(crate::kernel::FileDescriptionBackingSnapshot::Open(
            crate::kernel::OpenDescriptionBackingSnapshot {
                kind,
                status_flags,
                offset,
                host_fd,
                path,
                pipe_id,
                logical_fd_refs: if matches!(&*description, OpenDescription::Closed { .. }) {
                    0
                } else {
                    description.fd_ref_count()
                },
                epoll_interests,
            },
        ))
    }

    fn epoll_wake_fd(&self) -> Option<i32> {
        let description = self.read();
        match &*description {
            OpenDescription::Epoll { kqueue, .. } => Some(kqueue.wake_fd),
            _ => None,
        }
    }

    fn retain_fd_ref(&self) {
        let description = self.read();
        description.retain_fd_ref();
        match &*description {
            OpenDescription::PipeReader { pipe, .. } => {
                let mut state = pipe.state.lock();
                state.readers = state.readers.saturating_add(1);
            }
            OpenDescription::PipeWriter { pipe, .. } => {
                let mut state = pipe.state.lock();
                state.writers = state.writers.saturating_add(1);
            }
            _ => {}
        }
    }

    fn release_fd_ref(&self) {
        let mut description = self.write();
        let remaining = description.release_fd_ref();
        match &*description {
            OpenDescription::PipeReader { pipe, .. } => {
                let mut state = pipe.state.lock();
                state.readers = state.readers.saturating_sub(1);
                drop(state);
                pipe.changed.notify_all();
            }
            OpenDescription::PipeWriter { pipe, .. } => {
                let mut state = pipe.state.lock();
                state.writers = state.writers.saturating_sub(1);
                drop(state);
                pipe.changed.notify_all();
            }
            _ => {}
        }
        if remaining == 0 {
            let was_epoll = matches!(&*description, OpenDescription::Epoll { .. });
            *description = OpenDescription::Closed { was_epoll };
        }
    }

    fn fd_ref_count(&self) -> usize {
        let description = self.read();
        match &*description {
            OpenDescription::Closed { .. } => 0,
            _ => description.fd_ref_count(),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl crate::kernel::FileDescription {
    fn open_description(&self) -> &RwLock<OpenDescription> {
        if let Some(description) = self.concrete_backing::<RwLock<OpenDescription>>() {
            return description;
        }
        if let Some(ring) = self.concrete_backing::<super::ioring::IoUringBacking>() {
            return ring.open_metadata();
        }
        tracing::error!("model-only file description escaped into dispatch");
        std::process::abort();
    }

    pub(super) fn read(&self) -> RwLockReadGuard<'_, OpenDescription> {
        self.open_description().read()
    }

    pub(super) fn try_read(&self) -> Option<RwLockReadGuard<'_, OpenDescription>> {
        self.open_description().try_read()
    }

    pub(super) fn write(&self) -> FileDescriptionWriteGuard<'_> {
        FileDescriptionWriteGuard {
            guard: self.open_description().write(),
            description: self,
        }
    }
}

pub(super) struct FileDescriptionWriteGuard<'a> {
    guard: RwLockWriteGuard<'a, OpenDescription>,
    description: &'a crate::kernel::FileDescription,
}

impl Deref for FileDescriptionWriteGuard<'_> {
    type Target = OpenDescription;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl DerefMut for FileDescriptionWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl Drop for FileDescriptionWriteGuard<'_> {
    fn drop(&mut self) {
        self.description.publish_mutation();
    }
}

pub(crate) use super::fs::pipe::PipeRef;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TtyFdKind {
    Stdio,
    Other,
}

/// Which form of an xattr syscall is being dispatched: the path/lpath
/// variants name a file by path; the f-variant names it by open fd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum XattrTarget {
    Path { path: GuestPtr, follow: bool },
    Fd(Fd),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StatRecord {
    pub(super) ino: u64,
    pub(super) mode: u32,
    pub(super) nlink: u32,
    pub(super) uid: carrick_abi::NsUid,
    pub(super) gid: carrick_abi::NsGid,
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
            uid: carrick_abi::NsUid::ROOT,
            gid: carrick_abi::NsGid::ROOT,
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
            uid: carrick_abi::NsUid::ROOT,
            gid: carrick_abi::NsGid::ROOT,
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

pub(super) fn host_stream_stat_label(identity: u64, linux_type: u32) -> String {
    format!("host-stream:{identity}:{linux_type}")
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
        /// Stable identity shared by every guest fd for the same stream. For
        /// pipes this is the common `pipe_id`, rather than the host inode,
        /// because BSD assigns different inodes to the two pipe ends.
        identity: u64,
        fallback_mode: u32,
    },
}

impl OpenDescription {
    fn base(&self) -> &OpenDescriptionBase {
        match self {
            OpenDescription::Closed { .. } => {
                tracing::error!("closed file description has no functional base");
                std::process::abort();
            }
            OpenDescription::File { base, .. }
            | OpenDescription::Directory { base, .. }
            | OpenDescription::SyntheticFile { base, .. }
            | OpenDescription::SyntheticDevice { base, .. }
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
            | OpenDescription::Fanotify { base, .. }
            | OpenDescription::SignalFd { base, .. }
            | OpenDescription::PerfEvent { base, .. }
            | OpenDescription::FsContext { base, .. }
            | OpenDescription::Netlink { base, .. }
            | OpenDescription::Mqueue { base, .. }
            | OpenDescription::BpfMap { base, .. }
            | OpenDescription::BpfProg { base, .. } => base,
        }
    }

    fn base_mut(&mut self) -> &mut OpenDescriptionBase {
        match self {
            OpenDescription::Closed { .. } => {
                tracing::error!("closed file description has no functional base");
                std::process::abort();
            }
            OpenDescription::File { base, .. }
            | OpenDescription::Directory { base, .. }
            | OpenDescription::SyntheticFile { base, .. }
            | OpenDescription::SyntheticDevice { base, .. }
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
            | OpenDescription::Fanotify { base, .. }
            | OpenDescription::SignalFd { base, .. }
            | OpenDescription::PerfEvent { base, .. }
            | OpenDescription::FsContext { base, .. }
            | OpenDescription::Netlink { base, .. }
            | OpenDescription::Mqueue { base, .. }
            | OpenDescription::BpfMap { base, .. }
            | OpenDescription::BpfProg { base, .. } => base,
        }
    }

    pub(super) fn retain_fd_ref(&self) {
        self.base()
            .fd_refs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(super) fn release_fd_ref(&self) -> usize {
        let previous = self
            .base()
            .fd_refs
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        if previous == 0 {
            tracing::error!("logical fd reference count underflow");
            std::process::abort();
        }
        previous - 1
    }

    pub(super) fn fd_ref_count(&self) -> usize {
        self.base()
            .fd_refs
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(super) fn status_flags(&self) -> u64 {
        self.base().status_flags()
    }

    #[inline]
    pub(super) fn is_append(&self) -> bool {
        self.base().is_append()
    }

    #[inline]
    pub(super) fn is_nonblocking(&self) -> bool {
        self.base().is_nonblocking()
    }

    #[inline]
    pub(super) fn is_async(&self) -> bool {
        self.base().is_async()
    }

    #[inline]
    pub(super) fn is_write_only(&self) -> bool {
        self.base().is_write_only()
    }

    #[inline]
    pub(super) fn is_read_only(&self) -> bool {
        self.base().is_read_only()
    }

    #[inline]
    pub(super) fn is_path(&self) -> bool {
        self.base().is_path()
    }

    /// True for a `memfd_secret(2)` description: no file read/write methods
    /// (the read/write/splice family is EINVAL), MAP_SHARED-only mmap, and
    /// mapped pages hidden from `/proc/<pid>/mem`.
    #[inline]
    pub(super) fn is_secretmem(&self) -> bool {
        self.base().secretmem()
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

    pub(super) fn seals(&self) -> Option<u32> {
        self.base().seals()
    }

    pub(super) fn set_seals(&mut self, seals: Option<u32>) {
        self.base_mut().set_seals(seals);
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
            OpenDescription::Closed { .. } => {
                tracing::error!("closed file description escaped into fstat");
                std::process::abort();
            }
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
            OpenDescription::SyntheticDevice { kind, .. } => {
                let mut record = StatRecord::synthetic(kind.as_str(), 0, LINUX_S_IFCHR | 0o666);
                record.rdev = kind.rdev();
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
            OpenDescription::Fanotify { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:[fanotify]", 0, 0o600))
            }
            OpenDescription::SignalFd { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:[signalfd]", 0, 0o600))
            }
            OpenDescription::PerfEvent { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:[perf_event]", 0, 0o600))
            }
            OpenDescription::FsContext { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:[fscontext]", 0, 0o600))
            }
            OpenDescription::Mqueue { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:[mqueue]", 0, 0o600))
            }
            OpenDescription::BpfMap { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:bpf-map", 0, 0o600))
            }
            OpenDescription::BpfProg { .. } => {
                OpenStatSource::Record(StatRecord::synthetic("anon_inode:bpf-prog", 0, 0o600))
            }
            OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. } => {
                OpenStatSource::Record(StatRecord::synthetic(
                    "pipe:[carrick]",
                    0,
                    LINUX_S_IFIFO | 0o600,
                ))
            }
            OpenDescription::HostPipe {
                pty,
                host_fd,
                pipe_id,
                ..
            } => {
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
                        identity: *pipe_id,
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
