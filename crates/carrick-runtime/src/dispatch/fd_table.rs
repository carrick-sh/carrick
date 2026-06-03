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

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex, RwLock};

use crate::linux_abi::{
    LINUX_S_IFCHR, LINUX_S_IFIFO, LINUX_S_IFREG, LINUX_S_IFSOCK, LinuxEpollEvent,
};
use crate::rootfs::{RootFsDirEntry, RootFsEntryKind, RootFsMetadata};

use super::{EpollKqueue, Fd, GuestPtr, inode_for_path, linux_mode};

#[derive(Debug, Clone)]
pub(super) struct EpollInterest {
    pub(super) event: LinuxEpollEvent,
    pub(super) last_ready: u32,
}

#[derive(Debug)]
pub(super) struct EventFdState {
    pub(super) counter: Mutex<u64>,
    pub(super) readable: Condvar,
    /// Host pipe whose read end mirrors "counter > 0": exactly one byte is
    /// present iff the eventfd is readable. This gives the eventfd a REAL host
    /// fd that the epoll instance kqueue watches via `EVFILT_READ` natively
    /// (level-triggered -> can't be lost), so Go's netpollBreak wakes the poller
    /// without relying on the coarse `EVFILT_USER` broadcast. `-1` if pipe
    /// creation failed (then readiness falls back to the in-memory recompute +
    /// broadcast). The bytes are managed entirely by carrick (write_eventfd /
    /// read_eventfd); the guest never reads the pipe directly.
    pub(super) read_fd: std::os::fd::RawFd,
    pub(super) write_fd: std::os::fd::RawFd,
}

impl EventFdState {
    pub(super) fn new(counter: u64) -> Self {
        let (read_fd, write_fd) = make_readiness_pipe().unwrap_or((-1, -1));
        // Reflect a non-zero initial value as "readable" right away.
        if counter > 0 && write_fd >= 0 {
            let byte = [1u8];
            // BLOCKING-IO-OK: readiness pipe is set to O_NONBLOCK during creation
            unsafe { libc::write(write_fd, byte.as_ptr().cast(), 1) };
        }
        Self {
            counter: Mutex::new(counter),
            readable: Condvar::new(),
            read_fd,
            write_fd,
        }
    }

    /// Make `read_fd` readable iff `count > 0`: ensure exactly one byte present
    /// when readable, drained when not. Called under the counter lock.
    pub(super) fn sync_readiness(&self, count: u64) {
        if self.read_fd < 0 {
            return;
        }
        if count > 0 {
            // Ensure a byte is present (idempotent: a full 1-deep pipe EAGAINs).
            let byte = [1u8];
            // BLOCKING-IO-OK: readiness pipe is set to O_NONBLOCK during creation
            unsafe { libc::write(self.write_fd, byte.as_ptr().cast(), 1) };
        } else {
            // Drain any bytes so the read end is not readable.
            let mut buf = [0u8; 64];
            loop {
                // BLOCKING-IO-OK: readiness pipe is set to O_NONBLOCK during creation
                let n = unsafe { libc::read(self.read_fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n <= 0 {
                    break;
                }
            }
        }
    }
}

impl Drop for EventFdState {
    fn drop(&mut self) {
        for fd in [self.read_fd, self.write_fd] {
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        }
    }
}

/// A non-blocking, CLOEXEC host pipe relocated above the guest fd range, used as
/// an eventfd's readiness channel. `None` on failure (caller degrades to the
/// in-memory recompute + EVFILT_USER broadcast).
fn make_readiness_pipe() -> Option<(std::os::fd::RawFd, std::os::fd::RawFd)> {
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
    Some((read_fd, write_fd))
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
}

impl OpenDescriptionBase {
    pub(super) fn new(status_flags: u64) -> Self {
        Self {
            status_flags,
            so_reuseport: false,
            so_rcvbuf: None,
            so_sndbuf: None,
            so_passcred: false,
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
}

#[derive(Debug, Clone)]
pub(super) enum OpenDescription {
    File {
        base: OpenDescriptionBase,
        path: String,
        metadata: RootFsMetadata,
        contents: Vec<u8>,
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
        /// kqueue's `EVFILT_USER(0)`. See `docs/epoll-kqueue-plan.md`.
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
        kqueue: Arc<crate::darwin_kqueue::Kqueue>,
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
        mask: u64,
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
        host_fd: i32,
        is_read_end: bool,
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
    },
    /// Host BSD socket backed by a real macOS file descriptor.
    /// Survives `libc::fork(2)`; the `family`/`type_` fields capture
    /// the *Linux* AF_* / SOCK_* values the guest asked for so that
    /// subsequent socket syscalls (sockaddr translation, getsockopt
    /// SO_TYPE, etc.) can answer in Linux terms.
    HostSocket {
        base: OpenDescriptionBase,
        host_fd: i32,
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
        host_fd: i32,
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
}

#[derive(Debug)]
struct HostFdOwner {
    fd: i32,
}

impl Drop for HostFdOwner {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct HostFdRef(#[allow(dead_code)] Arc<HostFdOwner>);

impl HostFdRef {
    pub(super) fn new(fd: i32) -> Self {
        Self(Arc::new(HostFdOwner { fd }))
    }
}

#[derive(Debug, Clone)]
pub(super) struct OpenFile {
    pub(super) description: OpenDescriptionRef,
    pub(super) fd_flags: u64,
    pub(super) host_fd_owner: Option<HostFdRef>,
}

impl OpenFile {
    pub(super) fn new(description: OpenDescriptionRef, fd_flags: u64) -> Self {
        Self {
            description,
            fd_flags,
            host_fd_owner: None,
        }
    }

    pub(super) fn with_host_fd(
        description: OpenDescriptionRef,
        fd_flags: u64,
        host_fd: i32,
    ) -> Self {
        Self {
            description,
            fd_flags,
            host_fd_owner: Some(HostFdRef::new(host_fd)),
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
            size: size as u64,
            atime: (0, 0),
            mtime: (0, 0),
            ctime: (0, 0),
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
        host_fd: i32,
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
        host_fd: i32,
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
            | OpenDescription::Netlink { base, .. } => base,
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
            | OpenDescription::Netlink { base, .. } => base,
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
                host_fd: *host_fd,
                metadata: metadata.clone(),
            },
            OpenDescription::SyntheticFile { path, contents, .. } => OpenStatSource::Record(
                StatRecord::synthetic(path, contents.len(), LINUX_S_IFREG | 0o444),
            ),
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
                        host_fd: *host_fd,
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
