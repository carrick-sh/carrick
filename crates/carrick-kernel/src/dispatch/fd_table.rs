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
use carrick_fatal::carrick_fatal;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::linux_abi::{
    LINUX_EFBIG, LINUX_EINVAL, LINUX_EOVERFLOW, LINUX_S_IFCHR, LINUX_S_IFIFO, LINUX_S_IFMT,
    LINUX_S_IFREG, LINUX_S_IFSOCK, LinuxEpollEvent, LinuxEpollEvents,
};
use carrick_vfs::rootfs::{RootFsDirEntry, RootFsEntryKind, RootFsMetadata};

use super::{EpollKqueue, Fd, GuestPtr, HostFd, inode_for_path, linux_mode, linux_mode_fields};

/// Peer credentials recorded at connect/accept/socketpair time for an AF_UNIX socket.
pub(crate) use crate::kernel::SocketPeerCred;

#[derive(Debug, Clone)]
pub(crate) struct EpollInterest {
    /// The open-file description named by `fd` when EPOLL_CTL_ADD succeeded.
    /// This identity is load-bearing once forked processes have private fd
    /// tables: the same numeric fd can later name a different description in a
    /// child, whose close must not auto-remove the parent's shared epoll entry.
    /// Bare inherited stdio has no table-backed description and remains `None`.
    pub(super) target: Option<Arc<crate::kernel::FileDescription>>,
    /// Registration-time classification. Host-backed entries are already
    /// represented in the instance multiplexer; only entries without such a
    /// source need recursive userspace readiness sampling.
    pub(super) host_poll_source: bool,
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
    /// Last in-zone listener enqueue generation sampled for this registration.
    /// It is distinct from `last_read_avail`: a guest-to-guest connection
    /// arrives through EVFILT_USER, while host listener arrivals carry kqueue
    /// queue depth.  Equal depths across those sources still describe a new ET
    /// edge.
    pub(super) last_inzone_arrival_generation: Option<u64>,
    /// Last host listener accept-queue depth delivered from a real kqueue
    /// record. Kept separate from the in-zone enqueue generation: a fallback
    /// sample after EVFILT_USER has no host queue-depth authority.
    pub(super) last_host_listener_count: Option<u64>,
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
    pub(super) _callback_enrollment: Option<Arc<crate::kernel::WaitCallbackEnrollment>>,
}

use crate::kernel::objects::ListenerReadinessSample;

#[derive(Debug)]
pub(crate) struct EventFdState {
    /// Slot in the cross-process counter slab (`crate::eventfd_shm`) — the
    /// counter must be FORK-COHERENT (carrick forks real host processes;
    /// LTP eventfd2_03's children semaphore-ping-pong across the fork), so it
    /// lives in `MAP_SHARED` host memory, not in this (per-process) struct.
    /// `None` = slab unavailable/exhausted → `local` fallback (correct within
    /// one process, silently non-coherent across forks — the pre-slab
    /// behavior).
    slot: Option<usize>,
    local: std::sync::atomic::AtomicU64,
    pub(super) read_fd: Option<HostFdRef>,
    pub(super) write_fd: Option<HostFdRef>,
    pub(super) wait_queue: Arc<crate::kernel::WaitQueue>,
}

impl EventFdState {
    pub(super) fn new(counter: u64) -> Self {
        let (read_fd, write_fd) = match make_readiness_pipe() {
            Some((r, w)) => (Some(r), Some(w)),
            None => (None, None),
        };
        if counter > 0 {
            if let Some(w) = &write_fd {
                let _ = unsafe { libc::write(w.raw(), [1u8].as_ptr() as *const _, 1) };
            }
        }
        Self {
            slot: crate::eventfd_shm::alloc(counter),
            local: std::sync::atomic::AtomicU64::new(counter),
            read_fd,
            write_fd,
            wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
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
    let read_fd = carrick_host::internal_fd::relocate_internal_fd(fds[0]);
    let write_fd = carrick_host::internal_fd::relocate_internal_fd(fds[1]);
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
pub(crate) struct TimerFdState {
    pub(super) inner: Mutex<TimerFdInner>,
    pub(super) changed: Condvar,
    /// The time authority of the container that created this timerfd. Linux
    /// binds a timerfd to its creator's time namespace; readiness is
    /// re-evaluated from poll/epoll paths that carry no `KernelContext`, so
    /// the domain is captured here rather than looked up per evaluation.
    pub(super) clock: std::sync::Arc<crate::kernel::container::ClockDomain>,
    pub(super) wait_queue: Arc<crate::kernel::WaitQueue>,
    change_generation: std::sync::atomic::AtomicU64,
    change_listeners: Arc<Mutex<BTreeMap<u64, TimerFdChangeListener>>>,
    next_change_listener: std::sync::atomic::AtomicU64,
}

type TimerFdChangeCallback = Arc<dyn Fn(u64) + Send + Sync + 'static>;

struct TimerFdChangeListener {
    expected_generation: u64,
    callback: TimerFdChangeCallback,
}

impl std::fmt::Debug for TimerFdChangeListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TimerFdChangeListener")
            .field("expected_generation", &self.expected_generation)
            .finish_non_exhaustive()
    }
}

pub struct TimerFdChangeSubscription {
    listeners: std::sync::Weak<Mutex<BTreeMap<u64, TimerFdChangeListener>>>,
    id: u64,
}

impl Drop for TimerFdChangeSubscription {
    fn drop(&mut self) {
        if let Some(listeners) = self.listeners.upgrade() {
            listeners.lock().remove(&self.id);
        }
    }
}

pub enum TimerFdChangeEnrollment {
    Ready,
    Subscribed(TimerFdChangeSubscription),
}

impl TimerFdState {
    pub(super) fn new(
        clock: std::sync::Arc<crate::kernel::container::ClockDomain>,
        clock_id: u64,
    ) -> Self {
        Self {
            inner: Mutex::new(TimerFdInner {
                clock_id,
                interval: None,
                deadline: None,
                expirations: 0,
            }),
            changed: Condvar::new(),
            clock,
            wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            change_generation: std::sync::atomic::AtomicU64::new(1),
            change_listeners: Arc::new(Mutex::new(BTreeMap::new())),
            next_change_listener: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub(crate) fn change_generation(&self) -> u64 {
        self.change_generation
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn subscribe_change(
        &self,
        expected_generation: u64,
        callback: TimerFdChangeCallback,
    ) -> TimerFdChangeEnrollment {
        let mut listeners = self.change_listeners.lock();
        let current = self.change_generation();
        if current != expected_generation {
            return TimerFdChangeEnrollment::Ready;
        }
        let id = self
            .next_change_listener
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if id == 0 || id == u64::MAX {
            return TimerFdChangeEnrollment::Ready;
        }
        listeners.insert(
            id,
            TimerFdChangeListener {
                expected_generation,
                callback,
            },
        );
        TimerFdChangeEnrollment::Subscribed(TimerFdChangeSubscription {
            listeners: Arc::downgrade(&self.change_listeners),
            id,
        })
    }

    pub(crate) fn publish_change(&self) {
        let generation = self
            .change_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .wrapping_add(1);
        let callbacks = {
            let mut listeners = self.change_listeners.lock();
            listeners
                .values_mut()
                .filter_map(|listener| {
                    (listener.expected_generation != generation).then(|| {
                        listener.expected_generation = generation;
                        Arc::clone(&listener.callback)
                    })
                })
                .collect::<Vec<_>>()
        };
        for callback in callbacks {
            callback(generation);
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
pub(crate) struct OpenDescriptionBase {
    fs_identity: Option<carrick_vfs::FsIdentity>,
    inode: Option<carrick_vfs::InodeIdentity>,
    /// SO_RCVTIMEO: bounds a blocking recv on this socket. None = block forever.
    recv_timeout: Option<Duration>,
    /// SO_SNDTIMEO: bounds a blocking send on this socket. None = block forever.
    send_timeout: Option<Duration>,
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
    /// Linux-visible IPV6_V6ONLY intent, needed when an in-zone bind decides
    /// whether an IPv6 wildcard also owns the IPv4 port space.
    ipv6_v6only: bool,
    /// The compat-zone local endpoint when the host carrier was rebound or a
    /// local refusal synthesized. It belongs to the open description so dup
    /// and numeric-fd reuse cannot change its authority.
    guest_local: Option<crate::network::GuestSocketAddr>,
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
    /// True once a stream socket is connected (via connect, accept, or socketpair).
    connected: bool,
    /// Linux-visible pending socket error for synthetic networking paths whose
    /// failure is not backed by the host socket's SO_ERROR state.
    pending_socket_error: Option<i32>,
    /// Synthetic connected UDP peers can only surface an asynchronous error
    /// after a datagram is sent. Store that errno here and copy it into
    /// `pending_socket_error` after each successful connected send.
    socket_error_after_send: Option<i32>,
    /// Weak reference to an in-zone listener for listening host stream sockets.
    inzone_listener: Option<std::sync::Weak<crate::network::inzone::InZoneListener>>,
    inzone_cleanup: Option<std::sync::Arc<dyn InZoneCleanup>>,
}

pub trait InZoneCleanup: std::fmt::Debug + Send + Sync {}
impl<T: std::fmt::Debug + Send + Sync> InZoneCleanup for T {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SocketMulticastMembership {
    pub(super) level: i32,
    pub(super) source_specific: bool,
    pub(super) optval: Vec<u8>,
}

impl OpenDescriptionBase {
    pub(crate) fn new(#[allow(unused)] status_flags: u64) -> Self {
        Self {
            fs_identity: None,
            inode: None,
            so_reuseaddr: false,
            so_reuseport: false,
            ipv6_v6only: false,
            guest_local: None,
            ipv6_multicast_if: None,
            so_rcvbuf: None,
            so_sndbuf: None,
            so_passcred: false,
            listening: false,
            connect_in_progress: false,
            connected: false,
            pending_socket_error: None,
            socket_error_after_send: None,
            recv_timeout: None,
            send_timeout: None,
            pipe_capacity: crate::linux_abi::LINUX_PIPE_BUF_SIZE,
            pipe_capacity_shared: None,
            inzone_listener: None,
            inzone_cleanup: None,
        }
    }

    pub(crate) fn inode(&self) -> Option<carrick_vfs::InodeIdentity> {
        self.inode
    }

    pub(crate) fn with_inode(mut self, inode: carrick_vfs::InodeIdentity) -> Self {
        self.inode = Some(inode);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn set_inode(&mut self, inode: carrick_vfs::InodeIdentity) {
        self.inode = Some(inode);
    }

    pub(super) fn fs_identity(&self) -> Option<carrick_vfs::FsIdentity> {
        self.fs_identity
    }

    pub(super) fn with_fs_identity(mut self, id: carrick_vfs::FsIdentity) -> Self {
        self.fs_identity = Some(id);
        self
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
    pub(super) fn ipv6_v6only(&self) -> bool {
        self.ipv6_v6only
    }
    pub(super) fn set_ipv6_v6only(&mut self, on: bool) {
        self.ipv6_v6only = on;
    }
    pub(super) fn guest_local(&self) -> Option<crate::network::GuestSocketAddr> {
        self.guest_local
    }
    pub(super) fn set_guest_local(&mut self, local: Option<crate::network::GuestSocketAddr>) {
        self.guest_local = local;
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
    pub(super) fn connected(&self) -> bool {
        self.connected
    }
    pub(super) fn set_connected(&mut self, on: bool) {
        self.connected = on;
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
    pub(super) fn inzone_listener(
        &self,
    ) -> Option<std::sync::Arc<crate::network::inzone::InZoneListener>> {
        self.inzone_listener.as_ref().and_then(|w| w.upgrade())
    }
    pub(super) fn set_inzone_listener(
        &mut self,
        listener: Option<std::sync::Weak<crate::network::inzone::InZoneListener>>,
    ) {
        self.inzone_listener = listener;
    }
    pub(super) fn set_inzone_cleanup(
        &mut self,
        cleanup: Option<std::sync::Arc<dyn InZoneCleanup>>,
    ) {
        self.inzone_cleanup = cleanup;
    }

    /// A bound in-zone endpoint owns this lease.  Connect transfers the same
    /// lease into both connection halves; it must not manufacture a second
    /// number-only reservation for an already-bound host socket.
    pub(super) fn inzone_cleanup(&self) -> Option<std::sync::Arc<dyn InZoneCleanup>> {
        self.inzone_cleanup.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HostWriteKind {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootFsBackedData {
    pub(super) base: Arc<[u8]>,
    pub(super) dirty: BTreeMap<usize, Vec<u8>>,
    pub(super) len: usize,
}

#[derive(Debug, Clone)]
pub(crate) enum FileContents {
    Dense(Arc<parking_lot::RwLock<Vec<u8>>>),
    RootFsBacked(Arc<parking_lot::RwLock<RootFsBackedData>>),
    /// An unlinked host regular file owns the bytes (`memfd_create`). The
    /// host inode is the single authority every view reads and writes: fd
    /// I/O goes through `pread`/`pwrite`, a guest `MAP_SHARED`/`MAP_PRIVATE`
    /// mapping is a live host mapping of the same file, and a clone (dup,
    /// fork) shares the fd. That is what makes a store through a shared
    /// mapping visible to `pread` and to every other mapping — the in-memory
    /// variants can only ever hand a mapping a one-time snapshot.
    HostBacked {
        fd: Arc<std::os::fd::OwnedFd>,
    },
}

/// Create an anonymous host regular file: `mkstemp` under the host temp
/// directory (the host picks the unique name, mode 0600), then unlink at once
/// so only the returned fd keeps the inode alive. `None` when the host
/// refuses.
pub(super) fn create_unlinked_host_file(prefix: &str) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let template = std::env::temp_dir().join(format!(".carrick_{prefix}.XXXXXXXX"));
    let mut c_template = std::ffi::CString::new(template.as_os_str().as_encoded_bytes())
        .ok()?
        .into_bytes_with_nul();
    let fd = unsafe { libc::mkstemp(c_template.as_mut_ptr().cast()) };
    if fd < 0 {
        return None;
    }
    // SAFETY: `fd` is a fresh open owned by nobody else.
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return None;
    }
    if unsafe { libc::unlink(c_template.as_ptr().cast()) } != 0 {
        // The inode stays anonymous to the guest either way; a leaked name in
        // the host temp directory is the only consequence and not worth
        // refusing the guest's memfd over.
        tracing::debug!(
            path = %String::from_utf8_lossy(&c_template[..c_template.len() - 1]),
            "anonymous host file name not unlinked"
        );
    }
    Some(owned)
}

impl FileContents {
    pub(crate) fn dense(bytes: Vec<u8>) -> Self {
        Self::Dense(Arc::new(parking_lot::RwLock::new(bytes)))
    }

    pub(super) fn host_backed(fd: std::os::fd::OwnedFd) -> Self {
        Self::HostBacked { fd: Arc::new(fd) }
    }

    /// The host fd behind a [`FileContents::HostBacked`] file, for callers
    /// that map or alias the inode itself rather than copy its bytes.
    pub(super) fn host_backed_fd(&self) -> Option<i32> {
        use std::os::fd::AsRawFd;
        match self {
            Self::HostBacked { fd } => Some(fd.as_raw_fd()),
            Self::Dense(_) | Self::RootFsBacked(_) => None,
        }
    }

    /// Whether a file of `len` bytes fits this backing. In-memory variants
    /// are bounded by [`carrick_vfs::MAX_IN_MEMORY_FILE_SIZE`]; a host-backed
    /// file grows sparsely on the host and carries no such cap.
    pub(super) fn accepts_len(&self, len: u64) -> bool {
        match self {
            Self::HostBacked { .. } => true,
            Self::Dense(_) | Self::RootFsBacked(_) => len <= carrick_vfs::MAX_IN_MEMORY_FILE_SIZE,
        }
    }

    pub(super) fn shared_backed(
        base: Arc<[u8]>,
        dirty: BTreeMap<usize, Vec<u8>>,
        len: usize,
    ) -> Self {
        Self::RootFsBacked(Arc::new(parking_lot::RwLock::new(RootFsBackedData {
            base,
            dirty,
            len,
        })))
    }

    pub(crate) fn len(&self) -> Result<u64, LinuxErrno> {
        match self {
            Self::Dense(bytes) => Ok(bytes.read().len() as u64),
            Self::RootFsBacked(data) => Ok(data.read().len as u64),
            Self::HostBacked { fd } => {
                use std::os::fd::AsRawFd;
                let mut st: libc::stat = unsafe { core::mem::zeroed() };
                if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } == 0 {
                    if st.st_size < 0 {
                        return Err(LINUX_EINVAL);
                    }
                    u64::try_from(st.st_size).map_err(|_| LINUX_EOVERFLOW)
                } else {
                    let errno = std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EIO);
                    Err(crate::host_to_linux_errno(errno))
                }
            }
        }
    }

    pub(crate) fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, LinuxErrno> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self {
            Self::HostBacked { fd } => {
                use std::os::fd::AsRawFd;
                let start = libc::off_t::try_from(offset).map_err(|_| LINUX_EINVAL)?;
                let mut filled = 0usize;
                while filled < buf.len() {
                    let n = unsafe {
                        libc::pread(
                            fd.as_raw_fd(),
                            buf[filled..].as_mut_ptr().cast(),
                            buf.len() - filled,
                            start.saturating_add(filled as libc::off_t),
                        )
                    };
                    if n < 0 {
                        let errno = std::io::Error::last_os_error()
                            .raw_os_error()
                            .unwrap_or(libc::EIO);
                        if errno == libc::EINTR {
                            continue;
                        }
                        if filled > 0 {
                            return Ok(filled);
                        }
                        return Err(crate::host_to_linux_errno(errno));
                    }
                    if n == 0 {
                        break;
                    }
                    filled += n as usize;
                }
                Ok(filled)
            }
            Self::Dense(bytes) => {
                let Ok(offset_usize) = usize::try_from(offset) else {
                    return Ok(0);
                };
                let bytes = bytes.read();
                let available = bytes.get(offset_usize..).unwrap_or(&[]);
                let copy_len = available.len().min(buf.len());
                buf[..copy_len].copy_from_slice(&available[..copy_len]);
                Ok(copy_len)
            }
            Self::RootFsBacked(data) => {
                let Ok(offset_usize) = usize::try_from(offset) else {
                    return Ok(0);
                };
                let data = data.read();
                if offset_usize >= data.len {
                    return Ok(0);
                }
                let read_len = buf.len().min(data.len - offset_usize);
                buf[..read_len].fill(0);
                if offset_usize < data.base.len() {
                    let base_len = read_len.min(data.base.len() - offset_usize);
                    buf[..base_len]
                        .copy_from_slice(&data.base[offset_usize..offset_usize + base_len]);
                }
                let end = offset_usize + read_len;
                for (&start, bytes) in data.dirty.range(..end) {
                    let dirty_end = start.saturating_add(bytes.len());
                    if dirty_end <= offset_usize {
                        continue;
                    }
                    let copy_start = start.max(offset_usize);
                    let copy_end = dirty_end.min(end);
                    let dst_start = copy_start - offset_usize;
                    let src_start = copy_start - start;
                    let copy_len = copy_end - copy_start;
                    buf[dst_start..dst_start + copy_len]
                        .copy_from_slice(&bytes[src_start..src_start + copy_len]);
                }
                Ok(read_len)
            }
        }
    }

    pub(crate) fn resize(&mut self, new_len: u64) -> Result<(), LinuxErrno> {
        let new_len_usize = usize::try_from(new_len).map_err(|_| LINUX_EFBIG)?;
        if !self.accepts_len(new_len) {
            return Err(LINUX_EFBIG);
        }
        match self {
            Self::Dense(bytes) => {
                bytes.write().resize(new_len_usize, 0);
                Ok(())
            }
            Self::RootFsBacked(data) => {
                let mut data = data.write();
                data.len = new_len_usize;
                prune_dirty_ranges(&mut data.dirty, new_len_usize);
                Ok(())
            }
            Self::HostBacked { fd } => {
                use std::os::fd::AsRawFd;
                let off = libc::off_t::try_from(new_len).map_err(|_| LINUX_EFBIG)?;
                let ret = unsafe { libc::ftruncate(fd.as_raw_fd(), off) };
                if ret != 0 {
                    let errno = std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EIO);
                    return Err(crate::host_to_linux_errno(errno));
                }
                Ok(())
            }
        }
    }

    pub(crate) fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<usize, LinuxErrno> {
        if data.is_empty() {
            return Ok(0);
        }
        let offset_usize = usize::try_from(offset).map_err(|_| LINUX_EFBIG)?;
        let end = offset_usize.checked_add(data.len()).ok_or(LINUX_EFBIG)?;
        if !self.accepts_len(end as u64) {
            return Err(LINUX_EFBIG);
        }
        match self {
            Self::HostBacked { fd } => {
                use std::os::fd::AsRawFd;
                let raw_fd = fd.as_raw_fd();
                let start = libc::off_t::try_from(offset).map_err(|_| LINUX_EFBIG)?;
                let mut st: libc::stat = unsafe { core::mem::zeroed() };
                let old_len = if unsafe { libc::fstat(raw_fd, &mut st) } == 0 {
                    Some(st.st_size as u64)
                } else {
                    None
                };
                let mut written = 0usize;
                while written < data.len() {
                    let n = unsafe {
                        libc::pwrite(
                            raw_fd,
                            data[written..].as_ptr().cast(),
                            data.len() - written,
                            start.saturating_add(written as libc::off_t),
                        )
                    };
                    if n < 0 {
                        let errno = std::io::Error::last_os_error()
                            .raw_os_error()
                            .unwrap_or(libc::EIO);
                        if errno == libc::EINTR {
                            continue;
                        }
                        if written > 0 {
                            if let Some(old_len) = old_len {
                                crate::dispatch::fs::rw::punch_unwritten_host_blocks(
                                    raw_fd, old_len, offset,
                                )?;
                            }
                            return Ok(written);
                        }
                        return Err(crate::host_to_linux_errno(errno));
                    }
                    if n == 0 {
                        break;
                    }
                    written += n as usize;
                }
                if written > 0 {
                    if let Some(old_len) = old_len {
                        crate::dispatch::fs::rw::punch_unwritten_host_blocks(
                            raw_fd, old_len, offset,
                        )?;
                    }
                }
                Ok(written)
            }
            Self::Dense(contents) => {
                let mut contents = contents.write();
                if end > contents.len() {
                    contents.resize(end, 0);
                }
                contents[offset_usize..end].copy_from_slice(data);
                Ok(data.len())
            }
            Self::RootFsBacked(inner) => {
                let mut inner = inner.write();
                if end > inner.len {
                    inner.len = end;
                }
                insert_dirty_range(&mut inner.dirty, offset_usize, data)?;
                Ok(data.len())
            }
        }
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
/// whose user-wake channel the process table pulses when the guest-virtual
/// target exits (`publish_exit`); the kernel's own zombie record is the
/// authority, never a host process watch. Wrapped so `OpenDescription` can
/// keep deriving `Debug` (the trait object is not `Debug`); the poll fd (the
/// kqueue fd on macOS, the epoll fd on Linux) is the only state callers read.
pub struct PidfdWatch {
    /// Owns the backing fds; held only so `Drop` closes them. Never read
    /// after construction except to fire the user wake.
    /// `Mutex` only to make the otherwise-`!Sync` trait object shareable across
    /// threads (the dispatcher's `KernelState` must be `Send`); never locked.
    #[allow(dead_code)]
    mux: Mutex<Box<dyn carrick_hal::event::EventMultiplexer>>,
    poll_fd: i32,
    /// Durable exit receipt. Linux keeps `PIDFD_INFO_EXIT` available after the
    /// parent reaps the zombie, so the pidfd must own this independently of the
    /// process table's wait-consumable zombie record.
    exit_status: Mutex<Option<crate::kernel::LinuxWaitStatus>>,
}

impl PidfdWatch {
    pub(crate) fn new(mux: Box<dyn carrick_hal::event::EventMultiplexer>) -> Self {
        let poll_fd = mux.poll_fd();
        Self {
            mux: Mutex::new(mux),
            poll_fd,
            exit_status: Mutex::new(None),
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
    pub(crate) fn publish_exit(&self, status: crate::kernel::LinuxWaitStatus) {
        *self.exit_status.lock() = Some(status);
        let _ = self.mux.lock().trigger_user(0);
    }

    pub(crate) fn exit_status(&self) -> Option<crate::kernel::LinuxWaitStatus> {
        *self.exit_status.lock()
    }
}

impl crate::kernel::TaskExitSubscriber for PidfdWatch {
    fn publish_exit(&self, status: crate::kernel::LinuxWaitStatus) {
        PidfdWatch::publish_exit(self, status);
    }
}

impl std::fmt::Debug for PidfdWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PidfdWatch")
            .field("poll_fd", &self.poll_fd)
            .field("exit_status", &self.exit_status.lock())
            // The mux keeps the kqueue fd alive; nothing else to surface.
            .field("mux", &"<dyn EventMultiplexer>")
            .finish()
    }
}

/// Identity carried by a pidfd's open-file description. This is intentionally
/// typed: treating an HvPatch guest pid as a Darwin pid recreated the 1:1
/// process model inside the backend whose purpose is to break that mapping.
///
/// A `Host(i32)` variant used to sit beside `Hvpatch`, naming a Darwin pid on
/// the retired 1:1 native lane (e1fbfd32e). It went away with that lane: a
/// pidfd now always names a task in the kernel graph, so the type can no
/// longer spell the 1:1 identification it was introduced to prevent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PidfdTarget {
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
pub(crate) struct TrustedHostDir {
    pub(super) fd: HostFdRef,
    /// Which layer the fd anchors, and therefore what it may answer.
    pub(super) anchor: TrustedAnchor,
}

/// The layer a [`TrustedHostDir`] fd anchors. Children served through the fd
/// inherit the anchor: a walk that recurses `openat(dirfd, name)` stays on
/// whichever layer its root was proven against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TrustedAnchor {
    /// The fd's directory IS the merged guest namespace for its whole
    /// subtree: either there is no image lower at all (the historical
    /// materialized host root), or the immutable lower provably lacks this
    /// directory — and an immutable lower's absence is permanent for every
    /// descendant — so the writable upper is the only contributor. Stats,
    /// F_OK probes and getdents streams may all be answered from the fd.
    MergedUpper,
    /// The fd anchors the immutable cached lower. Exact only while the
    /// sparse upper still contributes nothing at this directory, which the
    /// shared structural `generation` stamp proves: any upper mutation
    /// since makes the anchor stale before it can serve a child. Stat and
    /// access lanes never answer from a lower anchor (guest identity — the
    /// chmod/chown xattrs — lives in the upper's layered view).
    ImmutableLower { generation: u64 },
}

impl TrustedHostDir {
    pub(super) fn merged_upper(fd: HostFdRef) -> Self {
        Self {
            fd,
            anchor: TrustedAnchor::MergedUpper,
        }
    }

    pub(super) fn immutable_lower(fd: HostFdRef, generation: u64) -> Self {
        Self {
            fd,
            anchor: TrustedAnchor::ImmutableLower { generation },
        }
    }

    /// Re-anchor a child fd served through this dir: the child inherits the
    /// parent's layer proof.
    pub(super) fn child(&self, fd: HostFdRef) -> Self {
        Self {
            fd,
            anchor: self.anchor,
        }
    }

    pub(super) fn is_merged_upper(&self) -> bool {
        self.anchor == TrustedAnchor::MergedUpper
    }

    pub(super) fn namespace_is_current_against(&self, current_gen: u64) -> bool {
        match self.anchor {
            TrustedAnchor::MergedUpper => true,
            TrustedAnchor::ImmutableLower { generation } => generation == current_gen,
        }
    }
}

/// The guest-visible listing behind an [`OpenDescription::Directory`].
///
/// Linux lists a directory when the guest READS it (`getdents64` walks the
/// live dentry tree; `rewinddir` re-reads), never when it opens it. An
/// `open(O_DIRECTORY)` used only as a walk/`*at` anchor therefore costs no
/// enumeration — LTP `creat05` opened a 4,000-file directory that way and
/// paid an O(n) per-child stat pass on EVERY open until this was made lazy.
#[derive(Debug, Clone)]
pub(crate) enum DirListing {
    /// Not yet read: the first `getdents64` (or an `lseek(SEEK_END)`) lists
    /// the directory from its live state.
    Pending,
    /// A snapshot taken by a read. An `lseek(0, SEEK_SET)` rewind returns
    /// the listing to [`Self::Pending`] so the next read is fresh.
    Loaded(Vec<RootFsDirEntry>),
    /// Entries fixed at open time by a synthetic VFS mount (`/proc`, `/sys`,
    /// `/dev`, bind targets); a rewind replays the same list.
    Fixed(Vec<RootFsDirEntry>),
}

impl DirListing {
    /// The materialized entries, if any listing has been taken.
    pub(super) fn entries(&self) -> Option<&[RootFsDirEntry]> {
        match self {
            Self::Pending => None,
            Self::Loaded(entries) | Self::Fixed(entries) => Some(entries),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum OpenDescription {
    /// Observable identity shell retained after the last fd slot and mapping
    /// reference close. All host descriptors and subsystem resources have already been
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
        listing: DirListing,
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
    ProcExecutable {
        base: OpenDescriptionBase,
        executable: crate::dispatch::executable_authority::CurrentExecutable,
        offset: usize,
    },
    InMemoryFile {
        base: OpenDescriptionBase,
        path: String,
        contents: Arc<parking_lot::RwLock<carrick_vfs::SparseBuffer>>,
        offset: usize,
        writable: bool,
        max_size: usize,
    },
    SyntheticDevice {
        base: OpenDescriptionBase,
        kind: carrick_vfs::SyntheticDeviceKind,
    },
    VirtualConsole {
        base: OpenDescriptionBase,
        console: Arc<dyn carrick_vfs::VirtualConsoleDevice>,
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
        /// Number of registrations whose readiness has no host multiplexer
        /// source. Keeps the overwhelmingly common all-host-backed quiet check
        /// O(1); the interest map is scanned only when this is nonzero.
        synthetic_interest_count: usize,
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
        /// Wait queue embedded in this epoll instance so that waiters (via poll/ppoll WaitSet)
        /// and nested parent epoll instances are notified when any registered target becomes ready.
        wait_queue: Arc<crate::kernel::WaitQueue>,
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
    PipeReader {
        base: OpenDescriptionBase,
        pipe: PipeRef,
    },
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
        /// When this `HostPipe` was created by duplicating an initial stdio
        /// stream (0 for stdin, 1 for stdout, 2 for stderr), this records which
        /// standard stream it names so captured/piped stdio routing can direct
        /// writes to the appropriate runtime sink instead of leaking straight to
        /// the carrier host process.
        stdio_stream: Option<i32>,
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
        /// Wait queue for synthetic Netlink readiness events.
        wait_queue: Arc<crate::kernel::WaitQueue>,
    },
    /// A synthetic AF_PACKET socket (`socket(AF_PACKET, ...)`).
    Packet {
        base: OpenDescriptionBase,
        socket: Arc<super::net::packet::PacketSocket>,
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
        queue: Arc<crate::dispatch::mqueue::MqueueInner>,
    },
    /// A pure in-memory stream or message socket (AF_UNIX or mocked AF_INET/AF_INET6).
    InMemorySocket {
        base: OpenDescriptionBase,
        socket: Arc<crate::dispatch::net::unix_pure::PureSocketInner>,
    },
}

impl Drop for OpenDescription {
    fn drop(&mut self) {
        if let Self::HostSocket { host_fd, .. } = self {
            crate::dispatch::net::support::unregister_unix_listener(host_fd.raw());
        }
    }
}

#[derive(Debug)]
struct HostFdOwner {
    /// Deliberately a bare per-process close: carrick forks real host
    /// processes, and each address space independently closes its inherited
    /// copy of the fd. Fork-correctness depends on this staying a plain
    /// per-process close (`OwnedFd` drops via `libc::close`) — never anything fancier.
    fd: OwnedFd,
    private_file_source: carrick_guest_mem::PrivateFileSource,
    /// Conservative offset state for regular files. Freshly opened host files
    /// start at zero. Any operation that can advance the shared open-file
    /// position marks this true; a successful seek back to zero clears it.
    ///
    /// This lets the regular write path skip a SEEK_CUR/fstat pair when a
    /// write cannot create a hole. The state lives with the host-fd owner so
    /// dup/fork aliases of one Carrick description observe the same value.
    offset_may_be_nonzero: std::sync::atomic::AtomicBool,
    /// Device/inode identity cannot change while this owned descriptor lives.
    /// Mutable attributes must still be invalidated after every mutation.
    inode_identity: std::sync::OnceLock<carrick_vfs::vfs::InodeIdentity>,
}

/// The OWNED, Arc-refcounted handle to a host kernel fd. The single owner of a
/// host-backed [`OpenDescription`]'s fd lives IN the description (`host_fd`
/// field); `Clone` bumps the refcount (never `dup(2)`s), and the last clone's
/// drop closes the fd via [`OwnedFd`]. Borrow the number for a libc call via [`HostFdRef::raw`]
/// or as the Copy view type via [`HostFdRef::view`].
#[derive(Debug, Clone)]
pub struct HostFdRef(Arc<HostFdOwner>);

impl std::os::fd::AsFd for HostFdRef {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.0.fd)
    }
}

impl HostFdRef {
    pub(crate) fn new(fd: i32) -> Self {
        Self::with_private_file_source(fd, carrick_guest_mem::PrivateFileSource::Mutable)
    }

    pub(super) fn with_private_file_source(
        fd: i32,
        private_file_source: carrick_guest_mem::PrivateFileSource,
    ) -> Self {
        // SAFETY: `fd` is a host descriptor whose lifetime is owned by this `HostFdRef`.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Self(Arc::new(HostFdOwner {
            fd,
            private_file_source,
            offset_may_be_nonzero: std::sync::atomic::AtomicBool::new(false),
            inode_identity: std::sync::OnceLock::new(),
        }))
    }

    pub(super) fn private_file_source(&self) -> carrick_guest_mem::PrivateFileSource {
        self.0.private_file_source
    }

    pub(super) fn inode_identity(&self) -> Option<carrick_vfs::vfs::InodeIdentity> {
        if let Some(identity) = self.0.inode_identity.get() {
            return Some(*identity);
        }
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(self.raw(), stat.as_mut_ptr()) } != 0 {
            return None;
        }
        let stat = unsafe { stat.assume_init() };
        let identity = carrick_vfs::vfs::InodeIdentity::new(stat.st_dev as u64, stat.st_ino);
        // Concurrent first readers may both query the same live descriptor.
        // They publish the same identity; failures are never cached.
        let _ = self.0.inode_identity.set(identity);
        Some(identity)
    }

    #[inline]
    pub(super) fn offset_may_be_nonzero(&self) -> bool {
        self.0
            .offset_may_be_nonzero
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Record an absolute host-file position returned by lseek(2).
    #[inline]
    pub(super) fn record_absolute_offset(&self, offset: i64) {
        self.0
            .offset_may_be_nonzero
            .store(offset != 0, std::sync::atomic::Ordering::Release);
    }

    /// Conservatively record that a sequential operation may leave the shared
    /// host-file position beyond a later truncation boundary.
    #[inline]
    pub(super) fn record_sequential_io(&self) {
        self.0
            .offset_may_be_nonzero
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// The raw fd number for a host `libc` call (borrowed — the caller must
    /// keep a `HostFdRef` alive for as long as the number is used).
    #[inline]
    pub(crate) fn raw(&self) -> i32 {
        self.0.fd.as_raw_fd()
    }

    /// The Copy borrowed VIEW of this fd (see [`HostFd`]); same liveness
    /// caveat as [`HostFdRef::raw`].
    #[inline]
    pub(super) fn view(&self) -> HostFd {
        HostFd(self.0.fd.as_raw_fd())
    }
}

pub(in crate::dispatch) struct HostSocketAuthority {
    description: Arc<crate::kernel::FileDescription>,
    host_fd: HostFdRef,
    pub(in crate::dispatch) family: i32,
    pub(in crate::dispatch) socket_type: i32,
    pub(in crate::dispatch) guest_local: Option<crate::network::GuestSocketAddr>,
    pub(in crate::dispatch) reuseaddr: bool,
    pub(in crate::dispatch) reuseport: bool,
    pub(in crate::dispatch) ipv6_v6only: bool,
}

impl HostSocketAuthority {
    pub(in crate::dispatch) fn host_fd(&self) -> HostFd {
        self.host_fd.view()
    }

    pub(in crate::dispatch) fn set_ipv6_v6only(&self, enabled: bool) -> Result<(), LinuxErrno> {
        let mut open = self.description.write().ok_or(super::LINUX_EBADF)?;
        let OpenDescription::HostSocket {
            base,
            family,
            host_fd,
            ..
        } = &mut *open
        else {
            return Err(super::LINUX_EBADF);
        };
        if *family != self.family || host_fd.raw() != self.host_fd.raw() {
            return Err(super::LINUX_EBADF);
        }
        base.set_ipv6_v6only(enabled);
        Ok(())
    }
}

pub(in crate::dispatch) enum InMemoryTcpAtMark {
    NotInMemory,
    WrongSocket,
    AtMark(bool),
}

pub(in crate::dispatch) enum PidfdWatchAccess {
    Closed,
    WrongKind,
    Watch(Arc<PidfdWatch>),
}

pub(in crate::dispatch) enum InMemoryPipeEndpoint {
    Reader,
    Writer,
}

pub type OpenFile = crate::kernel::FileSlot;

#[derive(Debug)]
pub(crate) struct HostFileIo<'guard> {
    host_fd: &'guard HostFdRef,
    writable: bool,
    open_path: Option<&'guard str>,
}

impl<'guard> HostFileIo<'guard> {
    pub(crate) fn from_read(open: &'guard OpenDescription) -> Option<Self> {
        match open {
            OpenDescription::HostFile {
                host_fd, writable, ..
            } => Some(Self {
                host_fd,
                writable: *writable,
                open_path: open.open_path(),
            }),
            _ => None,
        }
    }

    pub(crate) fn from_write(open: &'guard mut OpenDescription) -> Option<Self> {
        Self::from_read(open)
    }

    pub(crate) fn open_path(&self) -> Option<&str> {
        self.open_path
    }

    pub(crate) fn raw(&self) -> i32 {
        self.host_fd.raw()
    }

    pub(crate) fn is_writable(&self) -> bool {
        self.writable
    }

    pub(crate) fn offset_may_be_nonzero(&self) -> bool {
        self.host_fd.offset_may_be_nonzero()
    }

    pub(crate) fn record_sequential_io(&self) {
        self.host_fd.record_sequential_io();
    }

    pub(crate) fn record_absolute_offset(&self, offset: i64) {
        self.host_fd.record_absolute_offset(offset);
    }

    pub(crate) fn inode_identity(&self) -> Option<carrick_vfs::vfs::InodeIdentity> {
        self.host_fd.inode_identity()
    }

    pub(crate) fn host_fd_ref(&self) -> &HostFdRef {
        self.host_fd
    }
}

impl OpenFile {
    pub(in crate::dispatch) fn record_host_file_absolute_offset(&self, offset: i64) {
        let Some(open) = self.description.read() else {
            return;
        };
        if let OpenDescription::HostFile { host_fd, .. } = &*open {
            host_fd.record_absolute_offset(offset);
        }
    }

    pub(in crate::dispatch) fn is_io_uring_backing(&self) -> bool {
        self.description
            .concrete_backing::<super::ioring::IoUringBacking>()
            .is_some()
    }

    pub(in crate::dispatch) fn is_pty(&self) -> bool {
        self.description
            .inspect_kind(|open| matches!(open, OpenDescription::HostPipe { pty: Some(_), .. }))
            .unwrap_or(false)
    }
}

/// Count a new host regular-file description against its inode's EL1 owner
/// record. Runs once per description, after construction, with no guard of
/// the new description held; it may recall another description's delegation
/// of the same inode before the new one can do any I/O.
fn attach_el1_registration(
    file_desc: &crate::kernel::FileDescription,
    description: &OpenDescriptionRef,
) {
    if !carrick_mem::memory::el1_kernel_enabled() {
        return;
    }
    let identity = match &*description.read() {
        OpenDescription::HostFile {
            host_fd, metadata, ..
        } if metadata.kind == carrick_vfs::rootfs::RootFsEntryKind::File => {
            host_fd.inode_identity()
        }
        _ => None,
    };
    if let Some(identity) = identity {
        file_desc.set_el1_registration(crate::el1_delegation::register_open(identity));
    }
}

pub(crate) fn kernel_file_description(
    description: OpenDescriptionRef,
    status_flags: u64,
) -> Arc<crate::kernel::FileDescription> {
    let file_desc = kernel_file_description_unregistered(Arc::clone(&description), status_flags);
    attach_el1_registration(&file_desc, &description);
    file_desc
}

fn kernel_file_description_unregistered(
    description: OpenDescriptionRef,
    status_flags: u64,
) -> Arc<crate::kernel::FileDescription> {
    Arc::new(
        crate::kernel::FileDescription::concrete_with_common(
            description,
            Arc::new(crate::kernel::DescriptionCommon::new(status_flags)),
        )
        .unwrap_or_else(|error| {
            tracing::error!(%error, "file-description identity allocation failed");
            carrick_fatal!(
                "dispatch::fd_table",
                "file-description identity allocation failed"
            );
        }),
    )
}

impl crate::kernel::FileSlot {
    pub(super) fn from_open_description_with_status_flags(
        description: OpenDescriptionRef,
        status_flags: u64,
        fd_flags: u64,
    ) -> Self {
        let file_desc = kernel_file_description(description, status_flags);
        Self::new(file_desc, fd_flags)
    }

    pub(super) fn from_open_description_with_common(
        description: OpenDescriptionRef,
        common: Arc<crate::kernel::DescriptionCommon>,
        fd_flags: u64,
    ) -> Self {
        let file_desc = match crate::kernel::FileDescription::concrete_with_common(
            Arc::clone(&description),
            Arc::clone(&common),
        ) {
            Ok(file_desc) => Arc::new(file_desc),
            Err(_) => kernel_file_description_unregistered(
                Arc::clone(&description),
                common.status_flags(),
            ),
        };
        attach_el1_registration(&file_desc, &description);
        Self::new(file_desc, fd_flags)
    }
}

/// True if `path` is the synthetic sentinel carrick stamps on an ANONYMOUS file
/// description — an `O_TMPFILE` inode (`/__carrick_o_tmpfile`) or a
/// `memfd_create` inode (`/memfd:<name>`). Such a file has no real directory
/// entry: `linkat(/proc/self/fd/<n>, AT_SYMLINK_FOLLOW)` must MATERIALIZE it
/// at the target rather than hard-link a nonexistent source path, writes never
/// sync it to the overlay, and `fstat` answers from the description itself.
pub(crate) fn is_anon_overlay_path(path: &str) -> bool {
    path == "/__carrick_o_tmpfile" || path.starts_with("/memfd:")
}

/// Every distinguishable producer/consumer pair behind [`OpenDescription::wait_queue`].
///
/// The list is the acceptance surface of the enrollment-gap property: a wake
/// that fires between a syscall's own readiness check and the wait service's
/// enrollment must not be lost for ANY of these.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitQueueKind {
    PipeReader,
    PipeWriter,
    EventFd,
    TimerFd,
    InMemorySocket,
    InZoneListenerSocket,
    Epoll,
    Netlink,
    Packet,
    InZoneListenerHostSocket,
}

#[cfg(test)]
impl WaitQueueKind {
    /// Every kind, checked against the classifier by
    /// `wait_queue_kind_enumeration_is_exhaustive`.
    pub(crate) const ALL: &'static [Self] = &[
        Self::PipeReader,
        Self::PipeWriter,
        Self::EventFd,
        Self::TimerFd,
        Self::InMemorySocket,
        Self::InZoneListenerSocket,
        Self::Epoll,
        Self::Netlink,
        Self::Packet,
        Self::InZoneListenerHostSocket,
    ];
}

impl OpenDescription {
    /// The host fd whose inode a guest file mapping may alias live: a host
    /// regular file, or a memfd whose bytes live in an unlinked host file.
    /// In-memory contents have no host object and take the snapshot path.
    pub(super) fn shared_alias_host_fd(&self) -> Option<i32> {
        match self {
            Self::HostFile { host_fd, .. } => Some(host_fd.raw()),
            Self::File { contents, .. } => contents.host_backed_fd(),
            _ => None,
        }
    }

    /// Return the wait queue embedded in this description, if it is a Carrick-owned
    /// readiness publisher (pipe, eventfd, timerfd, in-memory socket).
    pub(crate) fn wait_queue(&self) -> Option<Arc<crate::kernel::WaitQueue>> {
        match self {
            Self::PipeReader { pipe, .. } | Self::PipeWriter { pipe, .. } => {
                Some(Arc::clone(&pipe.wait_queue))
            }
            Self::EventFd { state, .. } => Some(Arc::clone(&state.wait_queue)),
            Self::TimerFd { state, .. } => Some(Arc::clone(&state.wait_queue)),
            Self::InMemorySocket { socket, base } => base
                .inzone_listener()
                .map(|l| l.wait_queue())
                .or_else(|| Some(Arc::clone(&socket.wait_queue))),
            Self::Epoll { wait_queue, .. } => Some(Arc::clone(wait_queue)),
            Self::Netlink { wait_queue, .. } => Some(Arc::clone(wait_queue)),
            Self::Packet { socket, .. } => Some(Arc::clone(&socket.wait_queue)),
            Self::HostSocket { base, .. } => base.inzone_listener().map(|l| l.wait_queue()),
            _ => None,
        }
    }

    /// The wait-queue-bearing classification of this description, exhaustively.
    ///
    /// [`Self::wait_queue`] answers "is there a queue" with a wildcard arm; this
    /// answers "WHICH producer/consumer pair" with none, so a new description
    /// that publishes readiness through a wait queue cannot be added without
    /// being classified here — and therefore cannot silently escape the
    /// enrollment-gap property in
    /// `kernel::continuation::tests::wait_enrollment_gap`.
    #[cfg(test)]
    pub(crate) fn wait_queue_kind(&self) -> Option<WaitQueueKind> {
        match self {
            Self::PipeReader { .. } => Some(WaitQueueKind::PipeReader),
            Self::PipeWriter { .. } => Some(WaitQueueKind::PipeWriter),
            Self::EventFd { .. } => Some(WaitQueueKind::EventFd),
            Self::TimerFd { .. } => Some(WaitQueueKind::TimerFd),
            Self::InMemorySocket { base, .. } => Some(if base.inzone_listener().is_some() {
                WaitQueueKind::InZoneListenerSocket
            } else {
                WaitQueueKind::InMemorySocket
            }),
            Self::Epoll { .. } => Some(WaitQueueKind::Epoll),
            Self::Netlink { .. } => Some(WaitQueueKind::Netlink),
            Self::Packet { .. } => Some(WaitQueueKind::Packet),
            Self::HostSocket { base, .. } => base
                .inzone_listener()
                .map(|_| WaitQueueKind::InZoneListenerHostSocket),
            Self::Closed { .. }
            | Self::File { .. }
            | Self::InMemoryFile { .. }
            | Self::Directory { .. }
            | Self::SyntheticFile { .. }
            | Self::ProcExecutable { .. }
            | Self::SyntheticDevice { .. }
            | Self::Pidfd { .. }
            | Self::Inotify { .. }
            | Self::Fanotify { .. }
            | Self::SignalFd { .. }
            | Self::PerfEvent { .. }
            | Self::FsContext { .. }
            | Self::HostPipe { .. }
            | Self::HostFile { .. }
            | Self::Mqueue { .. }
            | Self::BpfMap { .. }
            | Self::BpfProg { .. }
            | Self::VirtualConsole { .. } => None,
        }
    }

    pub(super) fn reexec_kind_name(&self) -> &'static str {
        match self {
            Self::Closed { .. } => "closed",
            Self::File { .. } => "file",
            Self::InMemoryFile { .. } => "in_memory_file",
            Self::Directory { .. } => "directory",
            Self::SyntheticFile { .. } => "synthetic_file",
            Self::ProcExecutable { .. } => "proc_executable",
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
            Self::Packet { .. } => "packet",
            Self::Mqueue { .. } => "mqueue",
            Self::BpfMap { .. } => "bpf_map",
            Self::BpfProg { .. } => "bpf_prog",
            Self::InMemorySocket { .. } => "in_memory_socket",
            Self::VirtualConsole { .. } => "virtual_console",
        }
    }

    /// The guest path this fd was opened at, for descriptions that track one
    /// (regular files, directories, synthetic files). `None` for host-fd-backed
    /// or anonymous descriptions. Used to serve `readlink(/proc/self/fd/N)`.
    pub(super) fn open_path(&self) -> Option<&str> {
        match self {
            OpenDescription::File { path, .. }
            | OpenDescription::Directory { path, .. }
            | OpenDescription::SyntheticFile { path, .. }
            | OpenDescription::InMemoryFile { path, .. } => Some(path.as_str()),
            OpenDescription::SyntheticDevice { kind, .. } => Some(kind.as_str()),
            OpenDescription::VirtualConsole { .. } => Some("/dev/tty0"),
            // A host-fd-backed regular file (e.g. `--fs host`) carries the guest
            // path it was opened at in its metadata — surface it so
            // readlink(/proc/self/fd/N) and fexecve (execveat AT_EMPTY_PATH)
            // recover the executable's path.
            OpenDescription::HostFile { metadata, .. } => metadata.path.to_str(),
            _ => None,
        }
    }

    pub(super) fn retained_exec_source(
        &self,
    ) -> Option<&crate::dispatch::executable_authority::ExecSource> {
        match self {
            Self::ProcExecutable { executable, .. } => Some(executable.source()),
            _ => None,
        }
    }

    pub(super) fn retained_executable(
        &self,
    ) -> Option<&crate::dispatch::executable_authority::CurrentExecutable> {
        match self {
            Self::ProcExecutable { executable, .. } => Some(executable),
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
        if let OpenDescription::ProcExecutable { executable, .. } = self {
            return Some(executable.display_path());
        }
        let label = match self {
            OpenDescription::Closed { .. } => return None,
            OpenDescription::File { .. }
            | OpenDescription::Directory { .. }
            | OpenDescription::SyntheticFile { .. }
            | OpenDescription::InMemoryFile { .. }
            | OpenDescription::SyntheticDevice { .. }
            | OpenDescription::VirtualConsole { .. }
            | OpenDescription::HostFile { .. } => return None,
            OpenDescription::ProcExecutable { .. } => unreachable!(),
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
            OpenDescription::HostSocket { .. }
            | OpenDescription::InMemorySocket { .. }
            | OpenDescription::Netlink { .. }
            | OpenDescription::Packet { .. } => {
                format!("socket:[{}]", inode_for_path(Path::new("socket:[carrick]")))
            }
        };
        Some(label)
    }

    pub(super) fn rename_path(&mut self, resolved_old: &str, resolved_new: &str) {
        match self {
            Self::Directory {
                path,
                metadata,
                listing,
                ..
            } => {
                if *path == resolved_old {
                    *path = resolved_new.to_string();
                    metadata.path = Path::new(resolved_new).to_path_buf();
                    *listing = DirListing::Pending;
                } else if path.starts_with(resolved_old)
                    && path.as_bytes().get(resolved_old.len()) == Some(&b'/')
                {
                    let rest = &path[resolved_old.len() + 1..];
                    let updated = format!("{resolved_new}/{rest}");
                    *path = updated.clone();
                    metadata.path = Path::new(&updated).to_path_buf();
                    *listing = DirListing::Pending;
                }
            }
            Self::File { path, metadata, .. } => {
                if *path == resolved_old {
                    *path = resolved_new.to_string();
                    metadata.path = Path::new(resolved_new).to_path_buf();
                } else if path.starts_with(resolved_old)
                    && path.as_bytes().get(resolved_old.len()) == Some(&b'/')
                {
                    let rest = &path[resolved_old.len() + 1..];
                    let updated = format!("{resolved_new}/{rest}");
                    *path = updated.clone();
                    metadata.path = Path::new(&updated).to_path_buf();
                }
            }
            Self::HostFile { metadata, .. } => {
                let path_str = metadata.path.to_string_lossy().into_owned();
                if path_str == resolved_old {
                    metadata.path = Path::new(resolved_new).to_path_buf();
                } else if path_str.starts_with(resolved_old)
                    && path_str.as_bytes().get(resolved_old.len()) == Some(&b'/')
                {
                    let rest = &path_str[resolved_old.len() + 1..];
                    metadata.path = Path::new(&format!("{resolved_new}/{rest}")).to_path_buf();
                }
            }
            _ => {}
        }
    }
}

impl super::SyscallDispatcher {
    pub(in crate::dispatch) fn rename_open_paths(&self, resolved_old: &str, resolved_new: &str) {
        let file_table = self.captured_file_table();
        for (_, open_file) in file_table.read_open_files().iter() {
            if let Some(mut desc) = open_file.description.write() {
                desc.rename_path(resolved_old, resolved_new);
            }
        }
        file_table.rename_fd_open_paths(resolved_old, resolved_new);
    }
}

pub(super) type OpenDescriptionRef = Arc<RwLock<OpenDescription>>;

pub(super) fn listening_socket_readiness_sample(
    description: &OpenDescription,
    interest: LinuxEpollEvents,
) -> Option<ListenerReadinessSample> {
    match description {
        OpenDescription::HostSocket { host_fd, base, .. } => {
            if !base.listening() {
                return None;
            }
            if base.pending_socket_error().is_some() {
                let mut ready = LinuxEpollEvents::ERR;
                if interest.contains(LinuxEpollEvents::OUT) {
                    ready |= LinuxEpollEvents::OUT;
                }
                return Some(ListenerReadinessSample {
                    ready: ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP),
                    host_ready: LinuxEpollEvents::ERR,
                    inzone: None,
                });
            }
            let inzone = base
                .inzone_listener()
                .map(|listener| listener.readiness_snapshot());
            let mut ready = LinuxEpollEvents::empty();
            let mut host_ready = LinuxEpollEvents::empty();
            if inzone.is_some_and(|snapshot| snapshot.pending > 0)
                && interest.contains(LinuxEpollEvents::IN)
            {
                ready |= LinuxEpollEvents::IN;
            }
            let mut pfd = libc::pollfd {
                fd: host_fd.raw(),
                events: 0,
                revents: 0,
            };
            if interest.contains(LinuxEpollEvents::IN) {
                pfd.events |= libc::POLLIN;
            }
            let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
            if rc > 0 {
                if pfd.revents & libc::POLLIN != 0 {
                    ready |= LinuxEpollEvents::IN;
                    host_ready |= LinuxEpollEvents::IN;
                }
                if pfd.revents & libc::POLLERR != 0 {
                    ready |= LinuxEpollEvents::ERR;
                    host_ready |= LinuxEpollEvents::ERR;
                }
            }
            Some(ListenerReadinessSample {
                ready: ready & (interest | LinuxEpollEvents::ERR),
                host_ready,
                inzone,
            })
        }
        OpenDescription::InMemorySocket { base, .. } => {
            if !base.listening() {
                return None;
            }
            let inzone = base
                .inzone_listener()
                .map(|listener| listener.readiness_snapshot());
            let mut ready = LinuxEpollEvents::empty();
            if inzone.is_some_and(|snapshot| snapshot.pending > 0)
                && interest.contains(LinuxEpollEvents::IN)
            {
                ready |= LinuxEpollEvents::IN;
            }
            Some(ListenerReadinessSample {
                ready: ready & (interest | LinuxEpollEvents::ERR),
                host_ready: LinuxEpollEvents::empty(),
                inzone,
            })
        }
        _ => None,
    }
}

impl crate::kernel::FileDescriptionBacking for RwLock<OpenDescription> {
    fn listener_readiness(&self, interest: LinuxEpollEvents) -> Option<ListenerReadinessSample> {
        listening_socket_readiness_sample(&self.read(), interest)
    }

    fn is_epoll(&self) -> bool {
        matches!(
            &*self.read(),
            OpenDescription::Epoll { .. } | OpenDescription::Closed { was_epoll: true }
        )
    }

    fn epoll_targets(&self) -> Option<Vec<std::sync::Arc<crate::kernel::FileDescription>>> {
        let description = self.read();
        let OpenDescription::Epoll { interest, .. } = &*description else {
            return None;
        };
        Some(
            interest
                .values()
                .filter_map(|registration| registration.target.clone())
                .collect(),
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
            OpenDescription::File { .. } | OpenDescription::InMemoryFile { .. } => Kind::File,
            OpenDescription::Directory { .. } => Kind::Directory,
            OpenDescription::SyntheticFile { .. } => Kind::SyntheticFile,
            OpenDescription::ProcExecutable { .. } => Kind::File,
            OpenDescription::SyntheticDevice { .. } | OpenDescription::VirtualConsole { .. } => {
                Kind::SyntheticDevice
            }
            OpenDescription::EventFd { .. } => Kind::EventFd,
            OpenDescription::TimerFd { .. } => Kind::TimerFd,
            OpenDescription::Epoll { .. } => Kind::Epoll,
            OpenDescription::Pidfd { .. } => Kind::Pidfd,
            OpenDescription::PipeReader { .. } => Kind::PipeReader,
            OpenDescription::PipeWriter { .. } => Kind::PipeWriter,
            OpenDescription::HostPipe { .. } => Kind::HostPipe,
            OpenDescription::HostFile { .. } => Kind::HostFile,
            OpenDescription::HostSocket { .. } => Kind::HostSocket,
            OpenDescription::InMemorySocket { .. } => Kind::InMemorySocket,
            OpenDescription::Inotify { .. } => Kind::Inotify,
            OpenDescription::Fanotify { .. } => Kind::Fanotify,
            OpenDescription::SignalFd { .. } => Kind::SignalFd,
            OpenDescription::Netlink { .. } => Kind::Netlink,
            OpenDescription::Packet { .. } => Kind::InMemorySocket,
            OpenDescription::Mqueue { .. } => Kind::Mqueue,
            OpenDescription::BpfMap { .. } => Kind::BpfMap,
            OpenDescription::BpfProg { .. } => Kind::BpfProg,
            OpenDescription::PerfEvent { .. } => Kind::PerfEvent,
            OpenDescription::FsContext { .. } => Kind::FsContext,
        };
        let offset = match &*description {
            OpenDescription::File { offset, .. }
            | OpenDescription::Directory { offset, .. }
            | OpenDescription::SyntheticFile { offset, .. }
            | OpenDescription::ProcExecutable { offset, .. }
            | OpenDescription::InMemoryFile { offset, .. } => u64::try_from(*offset).ok(),
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
            | OpenDescription::SyntheticFile { path, .. }
            | OpenDescription::InMemoryFile { path, .. } => Some(path.clone()),
            OpenDescription::SyntheticDevice { kind, .. } => Some(kind.as_str().to_string()),
            OpenDescription::VirtualConsole { .. } => Some("/dev/tty0".to_string()),
            OpenDescription::HostFile { metadata, .. } => {
                Some(metadata.path.to_string_lossy().into_owned())
            }
            OpenDescription::ProcExecutable { executable, .. } => Some(executable.display_path()),
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
                offset,
                host_fd,
                path,
                pipe_id,
                epoll_interests,
            },
        ))
    }

    fn is_closed(&self) -> bool {
        matches!(&*self.read(), OpenDescription::Closed { .. })
    }

    fn readiness(
        &self,
        description_id: crate::kernel::FileDescriptionId,
        interest: carrick_abi::LinuxEpollEvents,
        cx: &dyn crate::kernel::ReadinessContext,
    ) -> carrick_abi::LinuxEpollEvents {
        use carrick_abi::LinuxEpollEvents;

        let open = self.read();
        match &*open {
            OpenDescription::Closed { .. } => LinuxEpollEvents::empty(),
            OpenDescription::File { .. }
            | OpenDescription::InMemoryFile { .. }
            | OpenDescription::SyntheticFile { .. } => interest & LinuxEpollEvents::IN,
            OpenDescription::ProcExecutable { .. } => interest & LinuxEpollEvents::IN,
            OpenDescription::SyntheticDevice { .. } | OpenDescription::VirtualConsole { .. } => {
                interest & (LinuxEpollEvents::IN | LinuxEpollEvents::OUT)
            }
            OpenDescription::HostFile { .. } => {
                interest & (LinuxEpollEvents::IN | LinuxEpollEvents::OUT)
            }
            OpenDescription::Directory { .. } => LinuxEpollEvents::empty(),
            OpenDescription::EventFd { state, .. } => {
                let counter = state.counter_value();
                let mut ready = LinuxEpollEvents::empty();
                if counter > 0 {
                    ready |= LinuxEpollEvents::IN;
                }
                if counter < u64::MAX - 1 {
                    ready |= LinuxEpollEvents::OUT;
                }
                ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
            OpenDescription::TimerFd { state, .. } => {
                let mut ready = LinuxEpollEvents::empty();
                if super::timerfd_ready_count(state) > 0 {
                    ready |= LinuxEpollEvents::IN;
                }
                ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
            OpenDescription::Epoll {
                interest: epoll_interest,
                synthetic_interest_count,
                pending_ready,
                kqueue,
                ..
            } => {
                if !interest.intersects(
                    LinuxEpollEvents::IN | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP,
                ) {
                    return LinuxEpollEvents::empty();
                }
                if !pending_ready.is_empty() {
                    return LinuxEpollEvents::IN
                        & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP);
                }
                if epoll_interest.is_empty() {
                    return LinuxEpollEvents::empty();
                }
                let mut pfd = libc::pollfd {
                    fd: kqueue.poll_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                let kq_ready =
                    rc > 0 && pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;
                if !kq_ready && *synthetic_interest_count == 0 {
                    return LinuxEpollEvents::empty();
                }

                // Snapshot registrations under the lock so we don't hold the parent description
                // lock while recursively querying child readiness.
                let snapshot: Vec<(Arc<crate::kernel::FileDescription>, u32, u32, bool)> =
                    epoll_interest
                        .values()
                        .filter_map(|reg| {
                            let req_events = reg.event.events;
                            if req_events == 0 {
                                return None;
                            }
                            if !kq_ready && reg.host_poll_source {
                                return None;
                            }
                            let target = reg.target.as_ref()?;
                            Some((
                                Arc::clone(target),
                                req_events,
                                reg.last_ready,
                                reg.host_poll_source,
                            ))
                        })
                        .collect();
                drop(open);

                let mut has_ready = false;
                for (target, req_events, last_ready, _host_source) in snapshot {
                    let child_interest = LinuxEpollEvents::from_bits_retain(req_events);
                    let child_ready = cx.description_readiness(&target, child_interest);
                    let raw_bits = child_ready.bits();
                    if raw_bits == 0 {
                        continue;
                    }
                    let deliverable = if child_interest.contains(LinuxEpollEvents::ET) {
                        (raw_bits & !last_ready) != 0
                            || child_ready.intersects(LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
                    } else {
                        true
                    };
                    if deliverable {
                        has_ready = true;
                        break;
                    }
                }
                let mut ready = LinuxEpollEvents::empty();
                if has_ready {
                    ready |= LinuxEpollEvents::IN;
                }
                ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
            OpenDescription::Pidfd { kqueue, .. } => {
                let mut pfd = libc::pollfd {
                    fd: kqueue.poll_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                let mut ready = LinuxEpollEvents::empty();
                if rc > 0 && pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                    ready |= LinuxEpollEvents::IN;
                }
                ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
            OpenDescription::Inotify { state, .. } => {
                let mut ready = LinuxEpollEvents::empty();
                if state.has_queued_records() {
                    ready |= LinuxEpollEvents::IN;
                }
                let mut pfd = libc::pollfd {
                    fd: state.poll_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                if rc > 0 && pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                    ready |= LinuxEpollEvents::IN;
                }
                ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
            OpenDescription::Fanotify { group, .. } => {
                let mut ready = LinuxEpollEvents::empty();
                if group.has_events() {
                    ready |= LinuxEpollEvents::IN;
                } else {
                    let poll_fd = group.poll_fd();
                    if poll_fd >= 0 {
                        let mut pfd = libc::pollfd {
                            fd: poll_fd,
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                        if rc > 0
                            && pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
                        {
                            ready |= LinuxEpollEvents::IN;
                        }
                    }
                }
                ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
            OpenDescription::SignalFd { .. } => LinuxEpollEvents::empty(),
            OpenDescription::PerfEvent { .. } => LinuxEpollEvents::empty(),
            OpenDescription::FsContext { .. } => LinuxEpollEvents::empty(),
            OpenDescription::PipeReader { pipe, .. } => {
                let state = pipe.state.lock();
                let mut ready = LinuxEpollEvents::empty();
                if !state.buffer.is_empty() {
                    ready |= LinuxEpollEvents::IN;
                }
                if state.writers == 0 {
                    ready |= LinuxEpollEvents::HUP;
                }
                ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
            OpenDescription::PipeWriter { pipe, .. } => {
                let state = pipe.state.lock();
                let mut ready = LinuxEpollEvents::empty();
                if state.readers == 0 {
                    ready |= LinuxEpollEvents::ERR;
                } else if crate::dispatch::fs::pipe::pipe_writer_is_writable(&state) {
                    ready |= LinuxEpollEvents::OUT;
                }
                ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
            OpenDescription::HostPipe {
                base,
                host_fd,
                is_read_end,
                bidirectional,
                pty,
                pipe_id,
                ..
            } => {
                let one_way_read_end = *is_read_end && !*bidirectional && pty.is_none();
                let pipe_full = cx
                    .host_pipe_write_room(
                        base.pipe_capacity(),
                        *pipe_id,
                        *is_read_end,
                        *bidirectional,
                        host_fd.raw(),
                    )
                    .is_some_and(|room| room < 4096);
                let suppress_pollout = one_way_read_end || pipe_full;
                let mut pfd = libc::pollfd {
                    fd: host_fd.raw(),
                    events: 0,
                    revents: 0,
                };
                if interest.contains(LinuxEpollEvents::IN) {
                    pfd.events |= libc::POLLIN;
                }
                if interest.contains(LinuxEpollEvents::OUT) && !suppress_pollout {
                    pfd.events |= libc::POLLOUT;
                }
                let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                let mut ready = LinuxEpollEvents::empty();
                if rc > 0 {
                    if pfd.revents & libc::POLLIN != 0 {
                        ready |= LinuxEpollEvents::IN;
                    }
                    if pfd.revents & libc::POLLOUT != 0 && !suppress_pollout {
                        ready |= LinuxEpollEvents::OUT;
                    }
                    if pfd.revents & libc::POLLERR != 0 {
                        ready |= LinuxEpollEvents::ERR;
                    }
                    if pfd.revents & libc::POLLHUP != 0 {
                        ready |= LinuxEpollEvents::HUP;
                    }
                }
                if crate::dispatch::fifo_beacon::read_end_at_eof(host_fd.raw()) {
                    if interest.contains(LinuxEpollEvents::IN) {
                        ready |= LinuxEpollEvents::IN;
                    }
                    ready |= LinuxEpollEvents::HUP;
                }
                if interest.contains(LinuxEpollEvents::IN)
                    && cx.staged_splice_bytes(description_id) > 0
                {
                    ready |= LinuxEpollEvents::IN;
                }
                ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
            OpenDescription::HostSocket {
                host_fd,
                base,
                synthetic_recv,
                type_,
                ..
            } => {
                if base.pending_socket_error().is_some() {
                    let mut ready = LinuxEpollEvents::ERR;
                    if interest.contains(LinuxEpollEvents::OUT) {
                        ready |= LinuxEpollEvents::OUT;
                    }
                    return ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP);
                }
                let is_stream_like = *type_ == carrick_abi::LINUX_SOCK_STREAM
                    || *type_ == carrick_abi::LINUX_SOCK_SEQPACKET;
                if is_stream_like {
                    if let Some(sample) = listening_socket_readiness_sample(&open, interest) {
                        return sample.ready;
                    }
                    let is_connected = base.connected()
                        || super::net::host_stream_socket_is_connected(host_fd.raw());
                    if !is_connected && !base.connect_in_progress() {
                        return LinuxEpollEvents::HUP;
                    }
                }
                let synthetic_datagram_ready = !synthetic_recv.is_empty();
                let mut pfd = libc::pollfd {
                    fd: host_fd.raw(),
                    events: 0,
                    revents: 0,
                };
                if interest.contains(LinuxEpollEvents::IN) {
                    pfd.events |= libc::POLLIN;
                }
                if interest.contains(LinuxEpollEvents::OUT) {
                    pfd.events |= libc::POLLOUT;
                }
                if interest.contains(LinuxEpollEvents::PRI) {
                    pfd.events |= libc::POLLPRI;
                }
                let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                let mut ready = LinuxEpollEvents::empty();
                if rc > 0 {
                    if pfd.revents & libc::POLLIN != 0 {
                        ready |= LinuxEpollEvents::IN;
                    }
                    if pfd.revents & libc::POLLOUT != 0 {
                        ready |= LinuxEpollEvents::OUT;
                    }
                    if pfd.revents & libc::POLLPRI != 0 {
                        ready |= LinuxEpollEvents::PRI;
                    }
                    if pfd.revents & libc::POLLERR != 0 {
                        ready |= LinuxEpollEvents::ERR;
                    }
                    if pfd.revents & libc::POLLHUP != 0 {
                        ready |= LinuxEpollEvents::HUP;
                    }
                }
                if super::net::recverr::is_enabled(host_fd.raw()) {
                    super::net::recverr::poll_errors(host_fd.raw());
                    if super::net::recverr::has_pending(host_fd.raw()) {
                        ready |= LinuxEpollEvents::IN | LinuxEpollEvents::ERR;
                    }
                }
                if interest.contains(LinuxEpollEvents::IN)
                    && super::net::reuseport::is_shared(host_fd.raw())
                {
                    let group_has_work = ready.contains(LinuxEpollEvents::IN)
                        || super::net::reuseport::siblings(host_fd.raw())
                            .into_iter()
                            .any(super::net::host_fd_has_pending_input);
                    if group_has_work && super::net::reuseport::is_turn(host_fd.raw()) {
                        ready |= LinuxEpollEvents::IN;
                    } else {
                        ready.remove(LinuxEpollEvents::IN);
                    }
                }
                if interest.contains(LinuxEpollEvents::PRI)
                    && !ready.contains(LinuxEpollEvents::PRI)
                    && super::net::support::host_fd_has_oob(host_fd.raw())
                {
                    ready |= LinuxEpollEvents::PRI;
                }
                if interest.contains(LinuxEpollEvents::RDHUP)
                    && (ready.contains(LinuxEpollEvents::IN)
                        || ready.contains(LinuxEpollEvents::HUP))
                    && super::net::host_stream_socket_rdhup(host_fd.raw())
                {
                    ready |= LinuxEpollEvents::IN | LinuxEpollEvents::RDHUP;
                }
                if interest.contains(LinuxEpollEvents::IN) && synthetic_datagram_ready {
                    ready |= LinuxEpollEvents::IN;
                }
                ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
            OpenDescription::Netlink { recv_queue, .. } => {
                let mut ready = LinuxEpollEvents::empty();
                if !recv_queue.is_empty() {
                    ready |= LinuxEpollEvents::IN;
                }
                ready |= LinuxEpollEvents::OUT;
                ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
            OpenDescription::Packet { socket, .. } => socket.readiness(interest),
            OpenDescription::BpfMap { .. } | OpenDescription::BpfProg { .. } => {
                interest & (LinuxEpollEvents::IN | LinuxEpollEvents::OUT)
            }
            OpenDescription::Mqueue { queue, .. } => {
                let state = queue.state.lock();
                let mut ready = LinuxEpollEvents::empty();
                if !state.messages.is_empty() {
                    ready |= LinuxEpollEvents::IN;
                }
                if state.messages.len() < state.max_msg {
                    ready |= LinuxEpollEvents::OUT;
                }
                ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
            OpenDescription::InMemorySocket { socket, base } => {
                let mut mask = LinuxEpollEvents::from_bits_retain(socket.poll_mask());
                if let Some(listener) = base.inzone_listener() {
                    if listener.pending() > 0 {
                        mask |= LinuxEpollEvents::IN;
                    }
                }
                mask & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
            }
        }
    }

    fn on_first_fd_ref(&self) {
        let description = self.read();
        match &*description {
            OpenDescription::PipeReader { pipe, .. } => {
                let mut state = pipe.state.lock();
                state.readers = state.readers.saturating_add(1);
                pipe.update_readiness_locked(&state);
            }
            OpenDescription::PipeWriter { pipe, .. } => {
                let mut state = pipe.state.lock();
                state.writers = state.writers.saturating_add(1);
                pipe.update_readiness_locked(&state);
            }
            _ => {}
        }
    }

    fn on_last_fd_ref(&self) {
        let description = self.read();
        match &*description {
            OpenDescription::PipeReader { pipe, .. } => {
                let mut state = pipe.state.lock();
                state.readers = state.readers.saturating_sub(1);
                pipe.update_readiness_locked(&state);
                drop(state);
                pipe.changed.notify_all();
            }
            OpenDescription::PipeWriter { pipe, .. } => {
                let mut state = pipe.state.lock();
                state.writers = state.writers.saturating_sub(1);
                pipe.update_readiness_locked(&state);
                drop(state);
                pipe.changed.notify_all();
            }
            _ => {}
        }
    }

    fn on_last_resource_ref(&self) {
        let mut description = self.write();
        let was_epoll = matches!(&*description, OpenDescription::Epoll { .. });
        *description = OpenDescription::Closed { was_epoll };
    }

    fn set_pipe_capacity_from_authority(
        &self,
        capacity: i64,
        accounting: crate::kernel::objects::PipeCapacityAccounting,
    ) -> Result<i64, crate::kernel::objects::PipeCapacityMutationError> {
        let mut open = self.write();
        match &mut *open {
            OpenDescription::PipeReader { base, pipe }
            | OpenDescription::PipeWriter { base, pipe } => {
                if accounting != crate::kernel::objects::PipeCapacityAccounting::InMemory {
                    return Err(
                        crate::kernel::objects::PipeCapacityMutationError::AccountingMismatch,
                    );
                }
                match pipe.set_capacity(capacity as usize) {
                    Ok(new_cap) => {
                        base.set_pipe_capacity(new_cap as i64);
                        Ok(new_cap as i64)
                    }
                    Err(errno) => Err(crate::kernel::objects::PipeCapacityMutationError::Semantic(
                        errno,
                    )),
                }
            }
            OpenDescription::HostPipe { base, .. } => {
                let crate::kernel::objects::PipeCapacityAccounting::Host { queued_bytes } =
                    accounting
                else {
                    return Err(
                        crate::kernel::objects::PipeCapacityMutationError::AccountingMismatch,
                    );
                };
                if (capacity as u64) < queued_bytes {
                    return Err(crate::kernel::objects::PipeCapacityMutationError::Semantic(
                        carrick_abi::LINUX_EBUSY,
                    ));
                }
                base.set_pipe_capacity(capacity);
                Ok(capacity)
            }
            _ => Err(crate::kernel::objects::PipeCapacityMutationError::NotPipe),
        }
    }

    fn wait_queue(&self) -> Option<Arc<crate::kernel::WaitQueue>> {
        self.read().wait_queue()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl crate::kernel::FileDescription {
    /// Snapshot the pathname recorded by an open description without exposing
    /// its backing lock to callers that only need stable metadata.
    pub(in crate::dispatch) fn open_path_snapshot(&self) -> Option<String> {
        self.read()?.open_path().map(str::to_owned)
    }

    pub(in crate::dispatch) fn pidfd_watch(&self) -> PidfdWatchAccess {
        let Some(open) = self.read() else {
            return PidfdWatchAccess::Closed;
        };
        match &*open {
            OpenDescription::Pidfd { kqueue, .. } => PidfdWatchAccess::Watch(Arc::clone(kqueue)),
            _ => PidfdWatchAccess::WrongKind,
        }
    }

    pub(in crate::dispatch) fn in_memory_pipe_endpoint(&self) -> Option<InMemoryPipeEndpoint> {
        match &*self.read()? {
            OpenDescription::PipeReader { .. } => Some(InMemoryPipeEndpoint::Reader),
            OpenDescription::PipeWriter { .. } => Some(InMemoryPipeEndpoint::Writer),
            _ => None,
        }
    }

    /// Report the one legacy-AIO case that must complete immediately with
    /// `EAGAIN`: a nonblocking read from an empty in-memory pipe that still
    /// has a writer. Keeping both description and pipe-state locking here
    /// makes the readiness observation one owned operation.
    pub(in crate::dispatch) fn is_empty_pipe_reader_with_writer(&self) -> bool {
        let Some(open) = self.read() else {
            return false;
        };
        let OpenDescription::PipeReader { pipe, .. } = &*open else {
            return false;
        };
        let state = pipe.state.lock();
        state.buffer.is_empty() && state.writers != 0
    }

    pub(in crate::dispatch) fn host_socket_authority(
        self: &Arc<Self>,
    ) -> Option<HostSocketAuthority> {
        let open = self.read()?;
        let OpenDescription::HostSocket {
            base,
            host_fd,
            family,
            type_,
            ..
        } = &*open
        else {
            return None;
        };
        Some(HostSocketAuthority {
            description: Arc::clone(self),
            host_fd: host_fd.clone(),
            family: *family,
            socket_type: *type_,
            guest_local: base.guest_local(),
            reuseaddr: base.so_reuseaddr(),
            reuseport: base.so_reuseport(),
            ipv6_v6only: base.ipv6_v6only(),
        })
    }

    pub(in crate::dispatch) fn in_memory_tcp_at_mark(&self) -> InMemoryTcpAtMark {
        let Some(open) = self.read() else {
            return InMemoryTcpAtMark::NotInMemory;
        };
        let OpenDescription::InMemorySocket { socket, .. } = &*open else {
            return InMemoryTcpAtMark::NotInMemory;
        };
        if socket.socket_type != carrick_abi::LINUX_SOCK_STREAM
            || !matches!(
                socket.family(),
                carrick_abi::LINUX_AF_INET | carrick_abi::LINUX_AF_INET6
            )
            || socket.protocol != carrick_abi::LINUX_IPPROTO_TCP
        {
            return InMemoryTcpAtMark::WrongSocket;
        }
        InMemoryTcpAtMark::AtMark(socket.at_oob_mark())
    }

    /// Snapshot the exact executable source retained by a `/proc/*/exe` open
    /// description. The backing guard is acquired only at its owning
    /// description boundary.
    pub(in crate::dispatch) fn retained_exec_source(
        &self,
    ) -> Option<crate::dispatch::executable_authority::ExecSource> {
        self.read()?.retained_exec_source().cloned()
    }

    /// Snapshot the exact executable, including its live dentry display, from
    /// a `/proc/*/exe` open description.
    pub(in crate::dispatch) fn retained_current_executable(
        &self,
    ) -> Option<crate::dispatch::executable_authority::CurrentExecutable> {
        self.read()?.retained_executable().cloned()
    }

    pub(crate) fn open_description(&self) -> Option<&RwLock<OpenDescription>> {
        self.concrete_backing::<RwLock<OpenDescription>>()
    }

    // The accessors below are the ONLY host access to an OpenDescription.
    // A delegated description is recalled before the host touches it. Other
    // descriptions of the same inode cannot exist while it is delegated (the
    // EL1 ownership record enforces single-description delegation), so each
    // accessor only checks its own description, and a non-delegated file pays
    // one atomic load here.

    /// Inspect what KIND of description this is without recalling a
    /// delegation. Only for facts delegation never changes: the variant and
    /// the fields it fixes at open (path, host fd identity, pipe or socket
    /// role). Anything EL1 can change (offset, size, contents) goes through
    /// `read`/`write`, which recall first.
    pub(crate) fn inspect_kind<R>(&self, inspect: impl FnOnce(&OpenDescription) -> R) -> Option<R> {
        let d = self.open_description()?;
        Some(inspect(&d.read()))
    }

    #[track_caller]
    pub(crate) fn read(&self) -> Option<RwLockReadGuard<'_, OpenDescription>> {
        let d = self.open_description()?;
        loop {
            let handle = self.delegation_handle();
            if handle != 0 {
                let mut guard = d.write();
                let handle = self.delegation_handle();
                if handle != 0 {
                    let _ = crate::el1_delegation::recall_locked(self, &mut guard, handle);
                }
            }
            let guard = d.read();
            // A sibling thread's forwarded write may have re-delegated the
            // description between the recall and this read; recall again.
            // Each recall counts toward the description's recall limit, after
            // which it is never delegated again, so this loop is finite.
            if self.delegation_handle() == 0 {
                return Some(guard);
            }
        }
    }

    #[track_caller]
    pub(crate) fn try_read(&self) -> Option<RwLockReadGuard<'_, OpenDescription>> {
        let d = self.open_description()?;
        if self.delegation_handle() != 0 {
            let mut guard = d.try_write()?;
            let handle = self.delegation_handle();
            if handle != 0 {
                let _ = crate::el1_delegation::recall_locked(self, &mut guard, handle);
            }
        }
        let guard = d.try_read()?;
        (self.delegation_handle() == 0).then_some(guard)
    }

    #[track_caller]
    pub(crate) fn write(&self) -> Option<FileDescriptionWriteGuard<'_>> {
        let d = self.open_description()?;
        let mut guard = d.write();
        let handle = self.delegation_handle();
        if handle != 0 {
            let _ = crate::el1_delegation::recall_locked(self, &mut guard, handle);
        }
        Some(FileDescriptionWriteGuard {
            guard,
            description: self,
        })
    }

    #[cfg(test)]
    pub(crate) fn try_write_for_test(&self) -> Option<FileDescriptionWriteGuard<'_>> {
        let d = self.open_description()?;
        let mut guard = d.try_write()?;
        let handle = self.delegation_handle();
        if handle != 0 {
            let _ = crate::el1_delegation::recall_locked(self, &mut guard, handle);
        }
        Some(FileDescriptionWriteGuard {
            guard,
            description: self,
        })
    }
}

pub(crate) struct FileDescriptionWriteGuard<'a> {
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
        if !matches!(&*self.guard, OpenDescription::HostFile { .. }) {
            self.description.publish_mutation();
        }
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
pub(crate) struct StatRecord {
    pub(crate) ino: u64,
    pub(crate) mode: u32,
    pub(crate) nlink: u32,
    pub(crate) uid: carrick_abi::NsUid,
    pub(crate) gid: carrick_abi::NsGid,
    /// Device id this entry REPRESENTS (`st_rdev`) — non-zero only for a
    /// character/block device node materialised by `mknod(2)` (see
    /// `FsBackend::create_device`). Zero for every ordinary file/dir/etc.
    pub(crate) rdev: u64,
    pub(crate) size: u64,
    pub(crate) blocks: Option<u64>,
    pub(crate) atime: (i64, i64),
    pub(crate) mtime: (i64, i64),
    pub(crate) ctime: (i64, i64),
    pub(crate) fs_identity: carrick_vfs::FsIdentity,
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
            blocks: None,
            atime: (0, 0),
            mtime: (0, 0),
            ctime: (0, 0),
            fs_identity: carrick_vfs::FsIdentity::Overlay,
        }
    }

    pub(super) fn from_real(real: &carrick_vfs::fs_backend::RealStat) -> Self {
        let mode = linux_mode_fields(real.kind, real.mode);
        Self {
            ino: real.ino,
            mode,
            nlink: real.nlink,
            uid: real.uid,
            gid: real.gid,
            rdev: 0,
            size: real.size,
            blocks: real.blocks,
            atime: real.atime,
            mtime: real.mtime,
            ctime: real.ctime,
            fs_identity: carrick_vfs::FsIdentity::Overlay,
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
            blocks: None,
            atime: (0, 0),
            mtime: (0, 0),
            ctime: (0, 0),
            fs_identity: carrick_vfs::FsIdentity::Overlay,
        }
    }

    pub(super) fn with_fs_identity(mut self, fs_identity: carrick_vfs::FsIdentity) -> Self {
        self.fs_identity = fs_identity;
        self
    }

    /// Override the reported file TYPE and `st_rdev` for a `mknod(2)` character/
    /// block device node. `dev` is `(type_bits, rdev)` from
    /// [`FsBackend::device_node`](carrick_vfs::fs_backend::FsBackend::device_node), so
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
    Error(carrick_abi::LinuxErrno),
    Record(StatRecord),
    HostFile {
        /// Borrowed Copy VIEW of the description's owned fd (see
        /// [`HostFdRef::view`]) — valid while the caller's `OpenFile` clone
        /// keeps the description alive.
        host_fd: HostFd,
        // Snapshot the scalar fallback while the description is locked. The
        // normal host-fstat path needs no owned path or metadata allocation.
        fallback: StatRecord,
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

    pub(super) fn fs_identity(&self) -> carrick_vfs::FsIdentity {
        match self {
            Self::Closed { .. } => carrick_vfs::FsIdentity::Overlay,
            Self::PipeReader { base, .. } | Self::PipeWriter { base, .. } => {
                base.fs_identity().unwrap_or(carrick_vfs::FsIdentity::Pipe)
            }
            Self::HostPipe { base, pty, .. } => {
                if let Some(id) = base.fs_identity() {
                    id
                } else if pty.is_some() {
                    carrick_vfs::FsIdentity::DevPts
                } else {
                    carrick_vfs::FsIdentity::Pipe
                }
            }
            Self::HostSocket { base, .. }
            | Self::InMemorySocket { base, .. }
            | Self::Netlink { base, .. } => base
                .fs_identity()
                .unwrap_or(carrick_vfs::FsIdentity::Socket),
            Self::SyntheticDevice { base, .. } => base
                .fs_identity()
                .unwrap_or(carrick_vfs::FsIdentity::Overlay),
            Self::File { base, path, .. }
            | Self::Directory { base, path, .. }
            | Self::SyntheticFile { base, path, .. }
            | Self::InMemoryFile { base, path, .. } => {
                if let Some(id) = base.fs_identity() {
                    id
                } else if path.starts_with("/proc") {
                    carrick_vfs::FsIdentity::Proc
                } else if path.starts_with("/sys") {
                    carrick_vfs::FsIdentity::Sysfs
                } else if path.starts_with("/dev/pts") {
                    carrick_vfs::FsIdentity::DevPts
                } else {
                    carrick_vfs::FsIdentity::Overlay
                }
            }
            Self::HostFile { base, .. } => base
                .fs_identity()
                .unwrap_or(carrick_vfs::FsIdentity::Overlay),
            Self::ProcExecutable { .. } => carrick_vfs::FsIdentity::Overlay,
            _ => carrick_vfs::FsIdentity::AnonInode,
        }
    }

    pub(super) fn stat_source(&self) -> OpenStatSource {
        match self {
            OpenDescription::Closed { .. } => {
                tracing::error!("closed file description escaped into fstat");
                carrick_fatal!(
                    "dispatch::fd_table",
                    "closed file description escaped into fstat"
                );
            }
            OpenDescription::File {
                path,
                metadata,
                contents,
                ..
            } if is_anon_overlay_path(path) => {
                let mut record = StatRecord::from_metadata(metadata);
                if let Ok(len) = contents.len() {
                    record.size = len;
                }
                OpenStatSource::Record(record)
            }
            OpenDescription::File {
                path,
                metadata,
                contents,
                ..
            } => {
                let mut record = StatRecord::from_metadata(metadata);
                if let Ok(len) = contents.len() {
                    record.size = len;
                }
                OpenStatSource::PathRecord {
                    path: path.clone(),
                    fallback: record,
                }
            }
            OpenDescription::Directory { path, metadata, .. } => OpenStatSource::PathRecord {
                path: path.clone(),
                fallback: StatRecord::from_metadata(metadata),
            },
            OpenDescription::HostFile {
                host_fd, metadata, ..
            } => OpenStatSource::HostFile {
                host_fd: host_fd.view(),
                fallback: StatRecord::from_metadata(metadata),
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
            OpenDescription::ProcExecutable { executable, .. } => {
                if let Some(fd) = executable.source().host_fd() {
                    let (_, mode, _, _, len) = match executable.source().stat_fields() {
                        Ok(fields) => fields,
                        Err(error) => {
                            return OpenStatSource::Error(
                                error
                                    .raw_os_error()
                                    .map(crate::host_to_linux_errno)
                                    .unwrap_or(crate::linux_abi::LINUX_EIO),
                            );
                        }
                    };
                    return OpenStatSource::HostFile {
                        host_fd: HostFd(fd),
                        fallback: StatRecord::from_metadata(&RootFsMetadata {
                            path: std::path::PathBuf::from(executable.display_path()),
                            kind: RootFsEntryKind::File,
                            mode,
                            size: len,
                        }),
                    };
                }
                let (ino, mode, uid, gid, len) = match executable.source().stat_fields() {
                    Ok(fields) => fields,
                    Err(error) => {
                        return OpenStatSource::Error(
                            error
                                .raw_os_error()
                                .map(crate::host_to_linux_errno)
                                .unwrap_or(crate::linux_abi::LINUX_EIO),
                        );
                    }
                };
                let mut record =
                    StatRecord::synthetic(&executable.display_path(), len, LINUX_S_IFREG | mode);
                record.ino = ino;
                record.nlink = u32::from(!executable.is_deleted());
                record.uid = uid;
                record.gid = gid;
                OpenStatSource::Record(record)
            }
            OpenDescription::InMemoryFile { path, contents, .. } => {
                let guard = contents.read();
                let len = guard.len();
                let allocated = guard.allocated_bytes();
                let mut record = StatRecord::synthetic(path, len, LINUX_S_IFREG | 0o644);
                record.blocks = Some(super::blocks_512(allocated) as u64);
                OpenStatSource::Record(record)
            }
            OpenDescription::SyntheticDevice { kind, .. } => {
                let mut record = StatRecord::synthetic(kind.as_str(), 0, LINUX_S_IFCHR | 0o666);
                record.rdev = kind.rdev();
                OpenStatSource::Record(record)
            }
            OpenDescription::VirtualConsole { .. } => {
                let mut record = StatRecord::synthetic("/dev/tty0", 0, LINUX_S_IFCHR | 0o666);
                record.rdev = 4 << 8;
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
            OpenDescription::HostSocket { .. }
            | OpenDescription::InMemorySocket { .. }
            | OpenDescription::Netlink { .. }
            | OpenDescription::Packet { .. } => OpenStatSource::Record(StatRecord::synthetic(
                "socket:[carrick]",
                0,
                LINUX_S_IFSOCK | 0o600,
            )),
        }
    }
}

#[cfg(test)]
pub struct InMemoryPipeTestFixture {
    pub(crate) read: Arc<crate::kernel::FileDescription>,
    pub(crate) write: Arc<crate::kernel::FileDescription>,
    pipe: Arc<super::fs::pipe::PipeInner>,
}

#[cfg(test)]
impl InMemoryPipeTestFixture {
    pub(crate) fn new(pipe_id: u64, capacity: usize) -> Self {
        let pipe = Arc::new(super::fs::pipe::PipeInner::new_connected(pipe_id, capacity));
        let mut read_base = OpenDescriptionBase::new(0);
        read_base.set_pipe_capacity_cell(Arc::clone(&pipe.capacity_cell));
        let read_desc = OpenDescription::PipeReader {
            base: read_base,
            pipe: Arc::clone(&pipe),
        };
        let mut write_base = OpenDescriptionBase::new(0);
        write_base.set_pipe_capacity_cell(Arc::clone(&pipe.capacity_cell));
        let write_desc = OpenDescription::PipeWriter {
            base: write_base,
            pipe: Arc::clone(&pipe),
        };
        let read = Arc::new(
            crate::kernel::FileDescription::concrete_with_status_flags(
                Arc::new(parking_lot::RwLock::new(read_desc)),
                0,
            )
            .expect("in-memory pipe reader description"),
        );
        let write = Arc::new(
            crate::kernel::FileDescription::concrete_with_status_flags(
                Arc::new(parking_lot::RwLock::new(write_desc)),
                0,
            )
            .expect("in-memory pipe writer description"),
        );
        Self { read, write, pipe }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.pipe.get_capacity()
    }

    pub(crate) fn read_base_capacity(&self) -> i64 {
        let guard = self.read.read().expect("read description");
        match &*guard {
            OpenDescription::PipeReader { base, .. } => base.pipe_capacity(),
            _ => panic!("expected PipeReader"),
        }
    }

    pub(crate) fn write_base_capacity(&self) -> i64 {
        let guard = self.write.read().expect("write description");
        match &*guard {
            OpenDescription::PipeWriter { base, .. } => base.pipe_capacity(),
            _ => panic!("expected PipeWriter"),
        }
    }

    pub(crate) fn enqueue_bytes(&self, bytes: &[u8]) {
        let mut state = self.pipe.state.lock();
        state.buffer.extend(bytes);
    }
}

#[cfg(test)]
pub struct HostPipeTestFixture {
    pub(crate) read: Arc<crate::kernel::FileDescription>,
    _peer_write_end: std::os::fd::OwnedFd,
    shared_capacity: Arc<std::sync::atomic::AtomicI64>,
}

#[cfg(test)]
impl HostPipeTestFixture {
    pub(crate) fn new(pipe_id: u64, initial_capacity: i64) -> Self {
        use std::os::fd::FromRawFd;
        let mut fds = [0i32; 2];
        let res = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(res, 0, "libc::pipe failed in test fixture");
        let host_fd = HostFdRef::new(fds[0]);
        let peer_write_end = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
        let shared_capacity = Arc::new(std::sync::atomic::AtomicI64::new(initial_capacity));
        let mut base = OpenDescriptionBase::new(0);
        base.set_pipe_capacity_cell(Arc::clone(&shared_capacity));
        let host_desc = OpenDescription::HostPipe {
            base,
            host_fd,
            is_read_end: true,
            pipe_id,
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
            stdio_stream: None,
        };
        let read = Arc::new(
            crate::kernel::FileDescription::concrete_with_status_flags(
                Arc::new(parking_lot::RwLock::new(host_desc)),
                0,
            )
            .expect("host pipe description"),
        );
        Self {
            read,
            _peer_write_end: peer_write_end,
            shared_capacity,
        }
    }

    pub(crate) fn capacity(&self) -> i64 {
        self.shared_capacity
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn read_base_capacity(&self) -> i64 {
        let guard = self.read.read().expect("host pipe read description");
        match &*guard {
            OpenDescription::HostPipe { base, .. } => base.pipe_capacity(),
            _ => panic!("expected HostPipe"),
        }
    }
}

#[cfg(test)]
pub(crate) fn closed_test_description() -> Arc<crate::kernel::FileDescription> {
    let closed = OpenDescription::Closed { was_epoll: false };
    Arc::new(
        crate::kernel::FileDescription::concrete_with_status_flags(
            Arc::new(parking_lot::RwLock::new(closed)),
            0,
        )
        .expect("closed description"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::{
        CompatReporter, DispatchOutcome, LinearMemory, SyscallArgs, SyscallDispatcher,
        SyscallRequest,
    };
    use crate::linux_abi::{LINUX_EINVAL, LINUX_EISDIR};
    use std::os::fd::FromRawFd;

    const SYS_READ: u64 = 63;
    const SYS_FTRUNCATE: u64 = 46;

    #[test]
    fn owned_inode_identity_survives_path_replacement_and_aliasing() {
        use std::os::fd::IntoRawFd;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity");
        let file = std::fs::File::create(&path).unwrap();
        let owner = HostFdRef::new(file.into_raw_fd());
        let alias = owner.clone();
        let identity = owner.inode_identity().unwrap();
        std::fs::remove_file(&path).unwrap();
        let replacement = HostFdRef::new(std::fs::File::create(&path).unwrap().into_raw_fd());
        assert_ne!(replacement.inode_identity().unwrap(), identity);
        drop(owner);
        assert_eq!(alias.inode_identity().unwrap(), identity);
    }

    #[test]
    fn host_file_offset_proof_is_shared_and_only_zero_is_safe() {
        use std::os::fd::IntoRawFd;

        let host_fd = HostFdRef::new(tempfile::tempfile().unwrap().into_raw_fd());
        let alias = host_fd.clone();
        assert!(!host_fd.offset_may_be_nonzero());

        alias.record_sequential_io();
        assert!(host_fd.offset_may_be_nonzero());

        host_fd.record_absolute_offset(0);
        assert!(!alias.offset_may_be_nonzero());

        alias.record_absolute_offset(1);
        assert!(host_fd.offset_may_be_nonzero());
    }

    #[test]
    fn mapped_file_reference_survives_last_fd_and_releases_last_fragment() {
        let backing = Arc::new(RwLock::new(OpenDescription::InMemoryFile {
            base: OpenDescriptionBase::new(0),
            path: "/mapped".into(),
            contents: Arc::new(RwLock::new(carrick_vfs::SparseBuffer::from(vec![42]))),
            offset: 0,
            writable: true,
            max_size: 4096,
        }));
        let description = kernel_file_description(Arc::clone(&backing), 0);
        description.retain_fd_ref();
        let mapping = description.retain_mapping().unwrap();
        let fragment = Arc::clone(&mapping);
        description.release_fd_ref();
        assert_eq!(description.fd_ref_count(), 0);
        assert!(description.retain_mapping().is_none());
        assert!(matches!(
            &*backing.read(),
            OpenDescription::InMemoryFile { .. }
        ));
        drop(mapping);
        assert!(matches!(
            &*backing.read(),
            OpenDescription::InMemoryFile { .. }
        ));
        drop(fragment);
        assert!(matches!(&*backing.read(), OpenDescription::Closed { .. }));
    }

    #[test]
    fn mapped_file_reference_release_does_not_close_a_live_fd() {
        let backing = Arc::new(RwLock::new(OpenDescription::SyntheticFile {
            base: OpenDescriptionBase::new(0),
            path: "/mapped".into(),
            contents: vec![42],
            offset: 0,
        }));
        let description = kernel_file_description(Arc::clone(&backing), 0);
        description.retain_fd_ref();
        let mapping = description.retain_mapping().unwrap();
        drop(mapping);
        assert_eq!(description.fd_ref_count(), 1);
        assert!(matches!(
            &*backing.read(),
            OpenDescription::SyntheticFile { .. }
        ));
        description.release_fd_ref();
        assert!(matches!(&*backing.read(), OpenDescription::Closed { .. }));
    }

    #[test]
    fn in_memory_tcp_fin_waits_for_last_fd_and_in_flight_socket_reference() {
        let (owned, peer) = crate::dispatch::net::unix_pure::PureSocketInner::pair_with_family(
            carrick_abi::LINUX_AF_INET,
            carrick_abi::LINUX_SOCK_STREAM,
            carrick_abi::LINUX_IPPROTO_TCP,
            crate::dispatch::net::unix_pure::LinuxUcred::default(),
            crate::dispatch::net::unix_pure::LinuxUcred::default(),
        );
        let operation_socket = Arc::clone(&owned);
        let backing = Arc::new(RwLock::new(OpenDescription::InMemorySocket {
            base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDWR),
            socket: owned,
        }));
        let description = kernel_file_description(Arc::clone(&backing), 0);
        description.retain_fd_ref();
        description.retain_fd_ref();

        let mut buf = [0u8; 1];
        description.release_fd_ref();
        assert_eq!(description.fd_ref_count(), 1);
        assert_eq!(
            peer.recv_stream(&mut buf, 0).unwrap_err(),
            crate::linux_abi::LINUX_EAGAIN,
            "closing one duplicate must not publish FIN"
        );

        description.release_fd_ref();
        assert_eq!(description.fd_ref_count(), 0);
        assert!(matches!(&*backing.read(), OpenDescription::Closed { .. }));
        assert_eq!(
            peer.recv_stream(&mut buf, 0).unwrap_err(),
            crate::linux_abi::LINUX_EAGAIN,
            "an admitted operation reference must keep the endpoint alive"
        );

        drop(operation_socket);
        assert_eq!(
            peer.recv_stream(&mut buf, 0).unwrap().0,
            0,
            "the final resource release publishes TCP FIN"
        );
    }

    #[test]
    fn host_socket_authority_rejects_replaced_backing_identity() {
        fn host_socket(fd: i32) -> OpenDescription {
            OpenDescription::HostSocket {
                base: OpenDescriptionBase::new(0),
                host_fd: HostFdRef::new(fd),
                family: carrick_abi::LINUX_AF_INET6,
                type_: carrick_abi::LINUX_SOCK_STREAM,
                protocol: carrick_abi::LINUX_IPPROTO_TCP,
                mcast_memberships: Vec::new(),
                synthetic_recv: VecDeque::new(),
            }
        }

        let first = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        let second = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        assert!(first >= 0 && second >= 0);
        let backing = Arc::new(RwLock::new(host_socket(first)));
        let description = kernel_file_description(Arc::clone(&backing), 0);
        let authority = description
            .host_socket_authority()
            .expect("capture first host socket");

        *backing.write() = host_socket(second);
        assert_eq!(
            authority.set_ipv6_v6only(true),
            Err(crate::linux_abi::LINUX_EBADF)
        );
        assert!(matches!(
            &*backing.read(),
            OpenDescription::HostSocket { base, .. } if !base.ipv6_v6only()
        ));
    }

    #[test]
    fn fd_table_host_backed_pread_failure_surfaces_errno_in_read() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let reporter = CompatReporter::default();

        let dir_fd = unsafe { libc::open(c".".as_ptr(), libc::O_RDONLY) };
        assert!(dir_fd >= 0);
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(dir_fd) };
        let desc = OpenDescription::File {
            path: "/dir_file".to_string(),
            contents: FileContents::host_backed(owned),
            offset: 0,
            writable: false,
            metadata: RootFsMetadata {
                path: std::path::PathBuf::from("/dir_file"),
                kind: RootFsEntryKind::File,
                mode: 0o644,
                size: 0,
            },
            base: OpenDescriptionBase::new(0),
        };
        let outcome = dispatcher.install_fd(desc, 0);
        let fd = match outcome {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("install_fd failed: {other:?}"),
        };

        let kernel = dispatcher.capture_one_task_context().unwrap();
        let read_outcome = dispatcher
            .dispatch(
                &kernel,
                SyscallRequest::new(SYS_READ, SyscallArgs([fd as u64, 0x1000, 16, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(read_outcome, DispatchOutcome::errno(LINUX_EISDIR));
    }

    #[test]
    fn fd_table_host_backed_resize_failure_surfaces_errno_in_ftruncate() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let reporter = CompatReporter::default();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"0123456789").unwrap();
        let ro_fd = unsafe {
            libc::open(
                std::ffi::CString::new(tmp.path().to_str().unwrap())
                    .unwrap()
                    .as_ptr(),
                libc::O_RDONLY,
            )
        };
        assert!(ro_fd >= 0);
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(ro_fd) };
        let desc = OpenDescription::File {
            path: "/ro_file".to_string(),
            contents: FileContents::host_backed(owned),
            offset: 0,
            writable: true,
            metadata: RootFsMetadata {
                path: std::path::PathBuf::from("/ro_file"),
                kind: RootFsEntryKind::File,
                mode: 0o644,
                size: 10,
            },
            base: OpenDescriptionBase::new(0),
        };
        let outcome = dispatcher.install_fd(desc, 0);
        let fd = match outcome {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("install_fd failed: {other:?}"),
        };

        let kernel = dispatcher.capture_one_task_context().unwrap();
        let trunc_outcome = dispatcher
            .dispatch(
                &kernel,
                SyscallRequest::new(SYS_FTRUNCATE, SyscallArgs([fd as u64, 20, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(trunc_outcome, DispatchOutcome::errno(LINUX_EINVAL));
    }

    #[test]
    fn file_contents_dense_lifecycle() {
        let mut contents = FileContents::dense(b"hello world".to_vec());
        assert_eq!(contents.len().unwrap(), 11);

        let mut buf = [0u8; 5];
        assert_eq!(contents.read_at(0, &mut buf).unwrap(), 5);
        assert_eq!(&buf, b"hello");

        assert_eq!(contents.read_at(6, &mut buf).unwrap(), 5);
        assert_eq!(&buf, b"world");

        // Read past end
        assert_eq!(contents.read_at(20, &mut buf).unwrap(), 0);

        // Write
        assert_eq!(contents.write_at(6, b"there").unwrap(), 5);
        let mut full_buf = [0u8; 11];
        assert_eq!(contents.read_at(0, &mut full_buf).unwrap(), 11);
        assert_eq!(&full_buf, b"hello there");

        // Resize shrink
        contents.resize(5).unwrap();
        assert_eq!(contents.len().unwrap(), 5);
        assert_eq!(contents.read_at(0, &mut buf).unwrap(), 5);
        assert_eq!(&buf, b"hello");

        // Resize grow
        contents.resize(8).unwrap();
        assert_eq!(contents.len().unwrap(), 8);
        let mut grow_buf = [0u8; 8];
        assert_eq!(contents.read_at(0, &mut grow_buf).unwrap(), 8);
        assert_eq!(&grow_buf, b"hello\0\0\0");
    }

    #[test]
    fn file_contents_rootfs_backed_lifecycle() {
        let mut contents = FileContents::shared_backed(
            std::sync::Arc::from(&b"initial base data"[..]),
            std::collections::BTreeMap::new(),
            17,
        );
        assert_eq!(contents.len().unwrap(), 17);

        let mut buf = [0u8; 7];
        assert_eq!(contents.read_at(0, &mut buf).unwrap(), 7);
        assert_eq!(&buf, b"initial");

        // Write overlay
        assert_eq!(contents.write_at(8, b"dirty").unwrap(), 5);
        let mut full = [0u8; 17];
        assert_eq!(contents.read_at(0, &mut full).unwrap(), 17);
        assert_eq!(&full, b"initial dirtydata");

        // Resize shrink
        contents.resize(10).unwrap();
        assert_eq!(contents.len().unwrap(), 10);
        let mut ten = [0u8; 10];
        assert_eq!(contents.read_at(0, &mut ten).unwrap(), 10);
        assert_eq!(&ten, b"initial di");

        // Resize grow within base
        contents.resize(14).unwrap();
        assert_eq!(contents.len().unwrap(), 14);
        let mut fourteen = [0u8; 14];
        assert_eq!(contents.read_at(0, &mut fourteen).unwrap(), 14);
        assert_eq!(&fourteen, b"initial dise d");

        // Resize grow past base
        contents.resize(20).unwrap();
        assert_eq!(contents.len().unwrap(), 20);
        let mut twenty = [0u8; 20];
        assert_eq!(contents.read_at(0, &mut twenty).unwrap(), 20);
        assert_eq!(&twenty, b"initial dise data\0\0\0");
    }

    #[test]
    fn file_contents_host_backed_lifecycle() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"host storage data").unwrap();
        let rw_fd = unsafe {
            libc::open(
                std::ffi::CString::new(tmp.path().to_str().unwrap())
                    .unwrap()
                    .as_ptr(),
                libc::O_RDWR,
            )
        };
        assert!(rw_fd >= 0);
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(rw_fd) };
        let mut contents = FileContents::host_backed(owned);

        assert_eq!(contents.len().unwrap(), 17);

        let mut buf = [0u8; 4];
        assert_eq!(contents.read_at(0, &mut buf).unwrap(), 4);
        assert_eq!(&buf, b"host");

        assert_eq!(contents.write_at(5, b"buffer").unwrap(), 6);
        let mut full = [0u8; 17];
        assert_eq!(contents.read_at(0, &mut full).unwrap(), 17);
        assert_eq!(&full, b"host buffere data");

        contents.resize(4).unwrap();
        assert_eq!(contents.len().unwrap(), 4);
        assert_eq!(contents.read_at(0, &mut buf).unwrap(), 4);
        assert_eq!(&buf, b"host");
    }
}
