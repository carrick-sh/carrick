//! net syscall handlers. Methods on `SyscallDispatcher`; see
//! `super` for the dispatcher struct and the normalized dispatch table.
use super::*;
mod support;
use support::*;
pub(super) use support::{drain_netlink_queue, set_host_nonblocking};

fn guest_unix_pathname(memory: &impl GuestMemory, addr: u64, addrlen: u32) -> Option<String> {
    memory
        .read_bytes(addr, addrlen as usize)
        .ok()
        .and_then(|raw| {
            if raw.len() > 2 && raw[2] != 0 {
                let nul = raw[2..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| 2 + p)
                    .unwrap_or(raw.len());
                std::str::from_utf8(&raw[2..nul])
                    .ok()
                    .map(|s| s.to_string())
            } else {
                None
            }
        })
}

impl SyscallDispatcher {
    /// Whether `fd` is a pollable target for `epoll_ctl(ADD)`. The kernel
    /// returns EPERM when adding an fd whose file has no `->poll` op — regular
    /// files, directories, and synthetic /proc files. Pipes, sockets, eventfd,
    /// timerfd, epoll, netlink, and character devices (ptys) are all pollable.
    fn fd_is_epollable(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        let open = open_file.description.read();
        match &*open {
            OpenDescription::File { .. }
            | OpenDescription::Directory { .. }
            | OpenDescription::SyntheticFile { .. } => false,
            OpenDescription::HostFile { metadata, .. } => {
                matches!(metadata.kind, crate::rootfs::RootFsEntryKind::CharDevice)
            }
            _ => true,
        }
    }

    fn epoll_ready_events(&self, fd: i32, requested_events: u32) -> u32 {
        let Some(open_file) = self.open_file(fd) else {
            return 0;
        };
        let open = open_file.description.read();
        match &*open {
            OpenDescription::EventFd { state, .. }
                if *state.counter.lock() > 0 && requested_events & LINUX_EPOLLIN != 0 =>
            {
                LINUX_EPOLLIN
            }
            OpenDescription::PipeReader { pipe, .. } if requested_events & LINUX_EPOLLIN != 0 => {
                let pipe = pipe.lock();
                if !pipe.buffer.is_empty() || pipe.writers == 0 {
                    LINUX_EPOLLIN
                } else {
                    0
                }
            }
            OpenDescription::TimerFd { state, .. }
                if requested_events & LINUX_EPOLLIN != 0 && timerfd_ready_count(state) > 0 =>
            {
                LINUX_EPOLLIN
            }
            _ => {
                // For host-backed descriptions (HostPipe/HostSocket/HostFile/
                // stdio) the in-memory arms above don't apply: readiness lives
                // in the real kernel object. Mirror what poll()/ppoll() do —
                // map the guest fd to its host fd and do a non-blocking
                // libc::poll(timeout 0), then translate revents → epoll events.
                drop(open);
                let Some(host_fd) = self.host_fd_for_poll(fd) else {
                    return 0;
                };
                let mut interest: i16 = 0;
                if requested_events & LINUX_EPOLLIN != 0 {
                    interest |= libc::POLLIN;
                }
                if requested_events & LINUX_EPOLLOUT != 0 {
                    interest |= libc::POLLOUT;
                }
                if requested_events & LINUX_EPOLLPRI != 0 {
                    interest |= libc::POLLPRI;
                }
                let mut pfd = libc::pollfd {
                    fd: host_fd,
                    events: interest,
                    revents: 0,
                };
                let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, 0) };
                if rc <= 0 {
                    return 0;
                }
                let mut ready = 0u32;
                if pfd.revents & libc::POLLIN != 0 {
                    ready |= LINUX_EPOLLIN;
                }
                if pfd.revents & libc::POLLOUT != 0 {
                    ready |= LINUX_EPOLLOUT;
                }
                if pfd.revents & libc::POLLPRI != 0 {
                    ready |= LINUX_EPOLLPRI;
                }
                if pfd.revents & libc::POLLHUP != 0 {
                    ready |= LINUX_EPOLLHUP;
                }
                if pfd.revents & libc::POLLERR != 0 {
                    ready |= LINUX_EPOLLERR;
                }
                // Only report events the caller is watching, plus the
                // always-reported HUP/ERR conditions Linux delivers regardless.
                ready & (requested_events | LINUX_EPOLLHUP | LINUX_EPOLLERR)
            }
        }
    }

    fn read_optional_fd_set(
        &self,
        memory: &mut impl GuestMemory,
        address: u64,
        nfds: usize,
    ) -> Result<Result<Option<Vec<u8>>, i32>, DispatchError> {
        if address == 0 {
            return Ok(Ok(None));
        }
        match read_fd_set(memory, address, nfds) {
            Ok(s) => Ok(Ok(Some(s))),
            Err(errno) => Ok(Err(errno)),
        }
    }

    /// Return the host fd backing a guest fd for ppoll's fast path.
    /// `Some(host_fd)` means we can hand this off to libc::poll.
    /// `None` means it's synthetic (epoll/eventfd/timerfd/in-memory pipe)
    /// and ppoll has to fall back to the per-fd readiness loop.
    pub(super) fn host_fd_for_poll(&self, fd: i32) -> Option<i32> {
        if fd < 0 {
            // Negative fd in a pollfd entry: libc::poll ignores it
            // (revents=0), which is the right semantic. Pass it through.
            return Some(fd);
        }
        if let Some(open_file) = self.open_file(fd) {
            let open = open_file.description.read();
            return match &*open {
                OpenDescription::HostPipe { host_fd, .. }
                | OpenDescription::HostSocket { host_fd, .. }
                | OpenDescription::HostFile { host_fd, .. } => Some(*host_fd),
                // eventfd is host-backed by a readiness pipe (read end readable
                // iff counter > 0), so epoll/poll/select watch it natively via
                // EVFILT_READ/POLLIN — no in-memory recompute or EVFILT_USER
                // broadcast needed (the robust path for Go's netpollBreak).
                OpenDescription::EventFd { state, .. } if state.read_fd >= 0 => Some(state.read_fd),
                // A pidfd is read-ready when its process exits; the backing
                // kqueue's own fd is what poll/epoll watch (EVFILT_PROC fires).
                OpenDescription::Pidfd { kqueue, .. } => Some(kqueue.raw_fd()),
                // inotify readiness is the backing kqueue's fd, so poll/epoll/
                // blocking-read wait on it natively.
                OpenDescription::Inotify { state, .. } => Some(state.poll_fd()),
                _ => None,
            };
        }
        if is_stdio_fd(fd) {
            return Some(fd);
        }
        // Unknown fd: do NOT pass the guest fd number through as a host fd
        // (host fds 3,4,5… belong to carrick itself — the cap-std rootfs dir,
        // the HVF device, etc., so polling them blocks on the wrong object).
        // Route to the synthetic readiness path instead.
        None
    }

    /// The guest's status flags (O_NONBLOCK etc.) for `fd`. carrick keeps the
    /// HOST fd non-blocking always and tracks the guest's intended blocking
    /// mode here; `blocking_io` consults this to decide EAGAIN vs a lockless
    /// wait. Bare stdio / unknown fds report 0 (blocking), the safe default.
    pub(super) fn fd_status_flags(&self, fd: i32) -> u64 {
        let Some(open_file) = self.open_file(fd) else {
            return 0;
        };
        open_file.description.read().status_flags()
    }

    /// THE single chokepoint for blocking-mode host I/O — every recv/send/
    /// accept/read/write on a host fd routes through here. `op` performs ONE
    /// NON-BLOCKING libc call (the host fd is always `O_NONBLOCK`) and, on
    /// success, returns the value to hand the guest (having already copied any
    /// data into guest memory). The classification is uniform:
    ///   * `Ok(n)`            → the syscall returns `n`.
    ///   * `Err(EAGAIN)`      → guest non-blocking fd: EAGAIN; guest blocking
    ///     fd: `WaitOnFds` (the runtime waits with the dispatcher lock
    ///     RELEASED, then re-dispatches).
    ///   * `Err(other)`       → that errno.
    ///
    /// INVARIANT: `host_fd` MUST be `O_NONBLOCK`. If it isn't, `op` could block
    /// inside libc while we hold the dispatcher lock and starve every sibling
    /// thread — the exact bug this design exists to prevent. We assert it
    /// loudly in debug/test builds and self-heal (force non-blocking) in
    /// release so a missed creation site can never silently reintroduce the
    /// starvation.
    fn blocking_io<F>(
        &self,
        host_fd: i32,
        dir: IoDir,
        nonblocking: bool,
        timeout: Option<std::time::Duration>,
        op: F,
    ) -> DispatchOutcome
    where
        F: FnOnce() -> Result<i64, i32>,
    {
        match op() {
            Ok(n) => DispatchOutcome::Returned { value: n },
            Err(e) if e == LINUX_EAGAIN => {
                if nonblocking {
                    // Guest wants non-blocking (fd O_NONBLOCK or per-call
                    // MSG_DONTWAIT): report EAGAIN, don't wait.
                    DispatchOutcome::errno(LINUX_EAGAIN)
                } else {
                    // Blocking-mode: hand off to the runtime to wait on host-fd
                    // readiness with the dispatcher lock RELEASED (per-thread
                    // kqueue), then re-dispatch. `timeout` carries the per-fd
                    // SO_RCVTIMEO/SO_SNDTIMEO (None = block forever, signal-
                    // interruptible); on WaitResult::TimedOut the run-loops
                    // return on_timeout = -EAGAIN, matching the Linux SO_*TIMEO
                    // recv/send result.
                    DispatchOutcome::WaitOnFds {
                        fds: vec![(host_fd, dir.events())],
                        timeout,
                        on_timeout: -(LINUX_EAGAIN as i64),
                        block_signals: 0,
                    }
                }
            }
            Err(e) => DispatchOutcome::errno(e),
        }
    }

    /// Whether a host-I/O op on `fd` with these guest `msg_flags` should report
    /// EAGAIN (true) rather than block: the guest fd is O_NONBLOCK, or the call
    /// carries MSG_DONTWAIT.
    pub(super) fn io_is_nonblocking(&self, fd: i32, msg_flags: i32) -> bool {
        self.fd_status_flags(fd) & LINUX_O_NONBLOCK != 0 || (msg_flags & LINUX_MSG_DONTWAIT) != 0
    }

    fn poll_ready_events(&self, fd: i32, requested_events: i16) -> i16 {
        if fd < 0 {
            return 0;
        }
        let Some(open_file) = self.open_file(fd) else {
            return if is_stdio_fd(fd) {
                // fd 1/2 are always writable (we either buffer or stream
                // straight to host write). For fd 0 we have to actually
                // poll the host because the guest's read(0,...) ultimately
                // calls libc::read(0,...); without a real readiness check,
                // ppoll would always return POLLOUT only and never POLLIN,
                // breaking interactive shells that ppoll(stdin) before
                // each prompt.
                let mut revents = requested_events & LINUX_POLLOUT;
                if fd == 0 && (requested_events & LINUX_POLLIN) != 0 {
                    let mut pfd = libc::pollfd {
                        fd: 0,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let n = unsafe { libc::poll(&mut pfd as *mut _, 1, 0) };
                    if n > 0 {
                        if pfd.revents & libc::POLLIN != 0 {
                            revents |= LINUX_POLLIN;
                        }
                        if pfd.revents & libc::POLLHUP != 0 {
                            revents |= LINUX_POLLHUP;
                        }
                    }
                }
                revents
            } else {
                LINUX_POLLNVAL
            };
        };
        let open = open_file.description.read();
        let mut ready = 0;
        match &*open {
            OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => {
                if requested_events & LINUX_POLLIN != 0 {
                    ready |= LINUX_POLLIN;
                }
            }
            // Regular files are always ready for read and write.
            OpenDescription::HostFile { .. } => {
                if requested_events & LINUX_POLLIN != 0 {
                    ready |= LINUX_POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
                }
            }
            OpenDescription::Directory { .. } => {}
            OpenDescription::EventFd { state, .. } => {
                if requested_events & LINUX_POLLIN != 0 && *state.counter.lock() > 0 {
                    ready |= LINUX_POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
                }
            }
            OpenDescription::TimerFd { state, .. } => {
                if requested_events & LINUX_POLLIN != 0 && timerfd_ready_count(state) > 0 {
                    ready |= LINUX_POLLIN;
                }
            }
            OpenDescription::Epoll {
                interest,
                pending_ready,
                kqueue,
                ..
            } => {
                if requested_events & LINUX_POLLIN != 0 {
                    if !pending_ready.is_empty() {
                        ready |= LINUX_POLLIN;
                    } else {
                        let mut pfd = libc::pollfd {
                            fd: kqueue.raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                        if rc > 0
                            && pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
                        {
                            ready |= LINUX_POLLIN;
                        } else if interest.iter().any(|(fd, interest)| {
                            self.host_fd_for_poll(*fd).is_none()
                                && self.epoll_ready_events(*fd, interest.event.events) != 0
                        }) {
                            ready |= LINUX_POLLIN;
                        }
                    }
                }
            }
            // Pidfd readiness is the kqueue's job (host_fd_for_poll returns the
            // EVFILT_PROC kqueue fd), so there's no in-memory readiness here.
            OpenDescription::Pidfd { .. } => {}
            // Inotify readiness is likewise the backing kqueue's job
            // (host_fd_for_poll returns its fd); no in-memory readiness here.
            OpenDescription::Inotify { .. } => {}
            // signalfd readiness would track pending masked signals; delivery is
            // a tracked follow-up, so there is no in-memory readiness here.
            OpenDescription::SignalFd { .. } => {}
            OpenDescription::PipeReader { pipe, .. } => {
                if requested_events & LINUX_POLLIN != 0 {
                    let pipe = pipe.lock();
                    if !pipe.buffer.is_empty() {
                        ready |= LINUX_POLLIN;
                    }
                    if pipe.writers == 0 {
                        ready |= LINUX_POLLHUP;
                    }
                }
            }
            OpenDescription::PipeWriter { pipe, .. } => {
                let pipe = pipe.lock();
                if pipe.readers == 0 {
                    ready |= LINUX_POLLERR;
                } else if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
                }
            }
            OpenDescription::HostPipe { host_fd, .. } => {
                // Poll the real host pipe fd so the guest's poll loop reflects
                // actual kernel readiness: a read end with buffered data is
                // POLLIN-ready, a write end with buffer space is POLLOUT-ready,
                // and a hung-up peer surfaces POLLHUP/POLLERR. Reporting
                // nothing here made poll/ppoll/pselect6 undercount ready fds
                // for pipe ends.
                let mut pfd = libc::pollfd {
                    fd: *host_fd,
                    events: 0,
                    revents: 0,
                };
                if requested_events & LINUX_POLLIN != 0 {
                    pfd.events |= libc::POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    pfd.events |= libc::POLLOUT;
                }
                let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                if rc > 0 {
                    if pfd.revents & libc::POLLIN != 0 {
                        ready |= LINUX_POLLIN;
                    }
                    if pfd.revents & libc::POLLOUT != 0 {
                        ready |= LINUX_POLLOUT;
                    }
                    if pfd.revents & libc::POLLERR != 0 {
                        ready |= LINUX_POLLERR;
                    }
                    if pfd.revents & libc::POLLHUP != 0 {
                        ready |= LINUX_POLLHUP;
                    }
                }
            }
            OpenDescription::HostSocket { host_fd, .. } => {
                // Poll the real host fd so the guest's poll loop reflects
                // actual kernel readiness for the socket.
                let mut pfd = libc::pollfd {
                    fd: *host_fd,
                    events: 0,
                    revents: 0,
                };
                if requested_events & LINUX_POLLIN != 0 {
                    pfd.events |= libc::POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    pfd.events |= libc::POLLOUT;
                }
                let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                if rc > 0 {
                    if pfd.revents & libc::POLLIN != 0 {
                        ready |= LINUX_POLLIN;
                    }
                    if pfd.revents & libc::POLLOUT != 0 {
                        ready |= LINUX_POLLOUT;
                    }
                    if pfd.revents & libc::POLLERR != 0 {
                        ready |= LINUX_POLLERR;
                    }
                    if pfd.revents & libc::POLLHUP != 0 {
                        ready |= LINUX_POLLHUP;
                    }
                }
            }
            OpenDescription::Netlink { recv_queue, .. } => {
                // A netlink socket is "readable" once a dump response has
                // been queued (by a prior sendto/sendmsg), and always
                // writable (the kernel never blocks rtnetlink requests).
                if requested_events & LINUX_POLLIN != 0 && !recv_queue.is_empty() {
                    ready |= LINUX_POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
                }
            }
        }
        ready
    }

    /// Create a synthetic AF_NETLINK socket. Linux accepts SOCK_RAW and
    /// SOCK_DGRAM for netlink (they're equivalent there); other socket
    /// types are rejected with ESOCKTNOSUPPORT, matching the kernel.
    fn netlink_socket(&self, type_: i32, protocol: i32) -> DispatchOutcome {
        let socket_flags = LinuxSocketTypeFlags::from_bits_retain(type_);
        let nonblock = socket_flags.contains(LinuxSocketTypeFlags::NONBLOCK);
        let cloexec = socket_flags.contains(LinuxSocketTypeFlags::CLOEXEC);
        let base_type = type_ & !LinuxSocketTypeFlags::SUPPORTED_MASK;
        if base_type != LINUX_SOCK_RAW && base_type != LINUX_SOCK_DGRAM {
            return DispatchOutcome::errno(LINUX_ESOCKTNOSUPPORT);
        }
        let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        self.install_fd(
            OpenDescription::Netlink {
                protocol,
                pid: 0,
                groups: 0,
                recv_queue: VecDeque::new(),
                base: OpenDescriptionBase::new(status_flags),
            },
            fd_flags,
        )
    }

    fn host_socket_install(&self, family: i32, type_: i32, protocol: i32) -> DispatchOutcome {
        // Strip the Linux-only SOCK_NONBLOCK / SOCK_CLOEXEC bits before
        // we hand the type to macOS, then set them on the resulting fd
        // by hand.
        let socket_flags = LinuxSocketTypeFlags::from_bits_retain(type_);
        let nonblock = socket_flags.contains(LinuxSocketTypeFlags::NONBLOCK);
        let cloexec = socket_flags.contains(LinuxSocketTypeFlags::CLOEXEC);
        let base_type = type_ & !LinuxSocketTypeFlags::SUPPORTED_MASK;
        let host_family = linux_to_host_af(family);
        let host_type = host_socktype_backing(family, base_type);
        let host_fd = match (unsafe { libc::socket(host_family, host_type, protocol) })
            .host_syscall_errno()
        {
            Ok(value) => value,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        // The host fd is always nonblocking; Carrick preserves the guest's
        // blocking mode in Linux-visible status_flags and waits outside the
        // dispatcher lock when a blocking operation would block.
        set_host_nonblocking(host_fd);
        let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let open_file = OpenFile::with_host_fd(
            Arc::new(RwLock::new(OpenDescription::HostSocket {
                host_fd,
                family,
                type_: base_type,
                base: OpenDescriptionBase::new(status_flags),
            })),
            fd_flags,
            host_fd,
        );
        let linux_fd = match self.install_fd_at_or_above(3, open_file) {
            Ok(fd) => fd,
            Err(_) => {
                return DispatchOutcome::errno(linux_errno::EMFILE);
            }
        };
        DispatchOutcome::Returned {
            value: linux_fd as i64,
        }
    }

    /// Map a GUEST fd to its backing HOST fd for an `SCM_RIGHTS` send. Only
    /// real host-backed descriptions (pipe/socket/file) can be passed to a peer
    /// over the host AF_UNIX socket; anything else (eventfd, pidfd, in-memory
    /// File, …) has no single host fd to dup into the peer and is rejected with
    /// EBADF (the closest Linux errno for "can't pass this fd"). The forkserver
    /// only ever passes os.pipe() ends + inherited sockets, all host-backed.
    fn host_fd_for_scm(&self, guest_fd: i32) -> Option<i32> {
        let open_file = self.open_file(guest_fd)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::HostPipe { host_fd, .. }
            | OpenDescription::HostSocket { host_fd, .. }
            | OpenDescription::HostFile { host_fd, .. } => Some(*host_fd),
            _ => None,
        }
    }

    /// Install a HOST fd received via `SCM_RIGHTS` as a fresh GUEST fd, wrapping
    /// it in the right `OpenDescription` by `fstat`ing its type (socket → host
    /// socket, fifo → host pipe, else a host file). The received host fd is
    /// already a live kernel fd the macOS kernel handed us; we keep its blocking
    /// mode non-blocking to satisfy the dispatcher's wait invariants. Returns
    /// the new guest fd, or `None` on failure (the caller closes the host fd).
    fn install_received_host_fd(&self, host_fd: i32) -> Option<i32> {
        set_host_nonblocking(host_fd);
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let kind = if unsafe { libc::fstat(host_fd, &mut st) } == 0 {
            st.st_mode & libc::S_IFMT
        } else {
            0
        };
        let description = if kind == libc::S_IFSOCK {
            // Recover the socket's domain/type so SO_TYPE/SO_DOMAIN report
            // faithfully; default to AF_UNIX/STREAM (the forkserver case).
            let mut so_type: i32 = libc::SOCK_STREAM;
            let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
            unsafe {
                libc::getsockopt(
                    host_fd,
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    (&mut so_type as *mut i32).cast(),
                    &mut len,
                );
            }
            // SOCK_STREAM/DGRAM/RAW/SEQPACKET are numerically identical on
            // macOS and Linux (1/2/3/5), so the host SO_TYPE value is already a
            // valid Linux socket type.
            OpenDescription::HostSocket {
                host_fd,
                family: libc::AF_UNIX,
                type_: so_type,
                base: OpenDescriptionBase::new(LINUX_O_RDWR),
            }
        } else if kind == libc::S_IFIFO {
            // A pipe end. Probe its direction so reads/writes route correctly;
            // a pipe read end rejects writes and vice versa. F_GETFL's access
            // mode is unreliable for pipe ends, so treat it as bidirectional-
            // safe: mark it not-a-read-end unless a write probe fails. The
            // forkserver passes both ends; CPython only uses each in one
            // direction, so a conservative bidirectional flag is safe.
            OpenDescription::HostPipe {
                host_fd,
                is_read_end: false,
                pty: None,
                bidirectional: true,
                base: OpenDescriptionBase::new(0),
            }
        } else {
            // Regular file / chardev / anything else: a host file with a real fd.
            let metadata = RootFsMetadata {
                path: std::path::PathBuf::from("scm:[received]"),
                kind: if kind == libc::S_IFDIR {
                    RootFsEntryKind::Directory
                } else {
                    RootFsEntryKind::File
                },
                mode: (st.st_mode & 0o7777) as u32,
                size: st.st_size.max(0) as usize,
            };
            OpenDescription::HostFile {
                host_fd,
                metadata,
                writable: true,
                base: OpenDescriptionBase::new(0),
            }
        };
        let open_file = OpenFile::with_host_fd(Arc::new(RwLock::new(description)), 0, host_fd);
        self.install_fd_at_or_above(3, open_file).ok()
    }

    /// Pull a (host_fd, family) pair out of the dispatcher's fd table.
    fn host_socket_lookup(&self, fd: i32) -> Result<(i32, i32), i32> {
        let Some(open_file) = self.open_file(fd) else {
            return Err(LINUX_EBADF);
        };
        let open = open_file.description.read();
        match &*open {
            OpenDescription::HostSocket {
                host_fd, family, ..
            } => Ok((*host_fd, *family)),
            _ => Err(LINUX_ENOTSOCK),
        }
    }

    /// The GUEST-requested socket type for `fd` (e.g. SOCK_SEQPACKET), which can
    /// differ from the host backing — carrick backs a guest AF_UNIX SEQPACKET
    /// with a host SOCK_STREAM, so the host's SO_TYPE would mis-report it.
    fn socket_guest_type(&self, fd: i32) -> Option<i32> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::HostSocket { type_, .. } => Some(*type_),
            _ => None,
        }
    }

    /// True iff `fd` refers to a synthetic AF_NETLINK socket.
    fn fd_is_netlink(&self, fd: i32) -> bool {
        self.open_file(fd)
            .is_some_and(|of| matches!(&*of.description.read(), OpenDescription::Netlink { .. }))
    }

    /// Handle a netlink "send": parse the request and queue a synthetic
    /// rtnetlink dump reply (or a bare NLMSG_DONE for requests we don't
    /// specifically model). Returns the number of bytes "sent".
    fn netlink_send(&self, fd: i32, request: &[u8]) -> DispatchOutcome {
        let Some(open_file) = self.open_file(fd) else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        let reply = {
            let open = open_file.description.read();
            let OpenDescription::Netlink { pid, .. } = &*open else {
                return DispatchOutcome::errno(LINUX_ENOTSOCK);
            };
            let dest_pid = if *pid != 0 { *pid } else { std::process::id() };
            build_netlink_reply(request, dest_pid)
        };
        if let OpenDescription::Netlink { recv_queue, .. } = &mut *open_file.description.write() {
            recv_queue.extend(reply);
        }
        DispatchOutcome::Returned {
            value: request.len() as i64,
        }
    }

    /// recvfrom path for netlink: drain queued reply bytes into guest memory.
    fn netlink_recv(
        &self,
        fd: i32,
        buf_addr: u64,
        len: usize,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let chunk = self.netlink_drain(fd, len);
        if !chunk.is_empty() && memory.write_bytes(buf_addr, &chunk).is_err() {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
        DispatchOutcome::Returned {
            value: chunk.len() as i64,
        }
    }

    /// Pop up to `max` bytes from the netlink recv queue. Our synthetic
    /// reply is built as one contiguous dump, so a single drain that fits
    /// the caller's buffer returns the whole thing.
    fn netlink_drain(&self, fd: i32, max: usize) -> Vec<u8> {
        let Some(open_file) = self.open_file(fd) else {
            return Vec::new();
        };
        let mut open = open_file.description.write();
        let OpenDescription::Netlink { recv_queue, .. } = &mut *open else {
            return Vec::new();
        };
        let take = recv_queue.len().min(max);
        recv_queue.drain(..take).collect()
    }

    pub(in crate::dispatch) fn accept_common(
        &self,
        fd: Fd,
        addr: GuestPtr,
        addrlen: GuestPtr,
        memory: &mut impl GuestMemory,
        accept4_flags: i32,
    ) -> DispatchOutcome {
        let fd = fd.0;
        let addr_addr = addr.0;
        let addrlen_addr = addrlen.0;
        let (host_fd, family, type_) = {
            let Some(open_file) = self.open_file(fd) else {
                return DispatchOutcome::errno(LINUX_EBADF);
            };
            match &*open_file.description.read() {
                OpenDescription::HostSocket {
                    host_fd,
                    family,
                    type_,
                    ..
                } => (*host_fd, *family, *type_),
                _ => {
                    return DispatchOutcome::errno(LINUX_ENOTSOCK);
                }
            }
        };
        // accept(2) has no per-call non-blocking flag, but listen() already put
        // the host listen socket in non-blocking mode, so this never blocks.
        // Whether EAGAIN becomes a wait or an EAGAIN to the guest is decided by
        // the guest's listen-fd blocking intent. The accept + sockaddr writeback
        // run in the closure (no &self); the fd is installed AFTER (the
        // install needs &self, which blocking_io's &self closure can't hold).
        let nonblocking = self.io_is_nonblocking(fd, 0);
        // accept(2) has no SO_*TIMEO bound on Linux — no per-fd timeout.
        let outcome = self.blocking_io(host_fd, IoDir::Read, nonblocking, None, || {
            let mut sa_storage = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
            let mut sa_len: libc::socklen_t = sa_storage.len() as libc::socklen_t;
            let new_host = unsafe {
                libc::accept(
                    host_fd,
                    sa_storage.as_mut_ptr() as *mut _,
                    &mut sa_len as *mut _,
                )
            };
            let new_host = new_host.host_syscall_errno()?;
            if addr_addr != 0 && addrlen_addr != 0 {
                let used = (sa_len as usize).min(sa_storage.len());
                let linux_bytes = host_to_linux_sockaddr(&sa_storage[..used], family, false);
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                    unsafe { libc::close(new_host) };
                    return Err(LINUX_EFAULT);
                }
            }
            Ok(new_host as i64)
        });
        let new_host = match outcome {
            DispatchOutcome::Returned { value } => value as i32,
            // WaitOnFds (block) or Errno — propagate; the runtime re-dispatches
            // accept on readiness.
            other => return other,
        };
        let socket_flags = LinuxSocketTypeFlags::from_bits_retain(accept4_flags);
        let nonblock = socket_flags.contains(LinuxSocketTypeFlags::NONBLOCK);
        let cloexec = socket_flags.contains(LinuxSocketTypeFlags::CLOEXEC);
        // The accepted socket inherits the listen socket's non-blocking mode on
        // macOS; set it to match the guest's intent (recv/send use MSG_DONTWAIT
        // regardless, so this is for fidelity).
        unsafe {
            let fl = libc::fcntl(new_host, libc::F_GETFL);
            if fl >= 0 {
                let next = if nonblock {
                    fl | libc::O_NONBLOCK
                } else {
                    fl & !libc::O_NONBLOCK
                };
                libc::fcntl(new_host, libc::F_SETFL, next);
            }
        }
        let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let open_file = OpenFile::with_host_fd(
            Arc::new(RwLock::new(OpenDescription::HostSocket {
                host_fd: new_host,
                family,
                type_,
                base: OpenDescriptionBase::new(status_flags),
            })),
            fd_flags,
            new_host,
        );
        let linux_fd = match self.install_fd_at_or_above(3, open_file) {
            Ok(fd) => fd,
            Err(_) => {
                return DispatchOutcome::errno(linux_errno::EMFILE);
            }
        };
        DispatchOutcome::Returned {
            value: linux_fd as i64,
        }
    }

    /// connect(2) core with always-wait-on-block semantics, for the io_uring
    /// CONNECT op (the synchronous `connect` handler keeps its own non-blocking
    /// branch). Returns Returned{0} on success/EISCONN, WaitOnFds (POLLOUT) while
    /// the connect is in progress, or Errno otherwise.
    pub(in crate::dispatch) fn connect_common(
        &self,
        fd: i32,
        addr_addr: u64,
        addrlen: u32,
        memory: &impl GuestMemory,
    ) -> DispatchOutcome {
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return errno.into(),
        };
        let host_addr = match read_linux_sockaddr(memory, addr_addr, addrlen, family) {
            Ok(bytes) => bytes,
            Err(errno) => return errno.into(),
        };
        set_host_nonblocking(host_fd);
        let rc = unsafe {
            libc::connect(
                host_fd,
                host_addr.as_ptr() as *const _,
                host_addr.len() as u32,
            )
        };
        if rc == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        let e = HostSyscallError::last().linux_errno();
        if e == LINUX_EISCONN {
            return DispatchOutcome::Returned { value: 0 };
        }
        if e == LINUX_EINPROGRESS || e == LINUX_EALREADY || e == LINUX_EAGAIN {
            return DispatchOutcome::WaitOnFds {
                fds: vec![(host_fd, libc::POLLOUT)],
                timeout: None,
                on_timeout: -(LINUX_EINPROGRESS as i64),
                block_signals: 0,
            };
        }
        e.into()
    }

    /// `sendmmsg(sockfd, msgvec, vlen, flags)` — Linux's batched
    /// sendmsg. glibc's getaddrinfo uses sendmmsg for DNS queries even
    /// when only a single message is sent; without this handler the
    /// guest sees ENOSYS and bails with "Temporary failure resolving".
    /// Implemented as a loop over single sendmsgs, writing each entry's
    /// msg_len field with the bytes-sent on success.
    fn sendmmsg(
        &self,
        fd: Fd,
        msgvec: GuestPtr,
        vlen: u64,
        flags: u64,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let fd = fd.0;
        let msgvec = msgvec.0;
        let vlen = vlen as u32;
        let flags = flags as i32;
        const MMSGHDR_SIZE: u64 = <LinuxMmsghdr as KernelAbi>::ABI_SIZE as u64;
        const MSG_LEN_OFFSET: u64 = <LinuxMsghdr as KernelAbi>::ABI_SIZE as u64;
        let mut sent: i32 = 0;
        for i in 0..vlen {
            let entry = match msgvec.checked_add(i as u64 * MMSGHDR_SIZE) {
                Some(a) => a,
                None => {
                    return DispatchOutcome::errno(LINUX_EFAULT);
                }
            };
            let outcome = match self.sendmsg_inner(fd, entry, flags, &*memory) {
                Ok(o) => o,
                Err(_) => {
                    return DispatchOutcome::errno(LINUX_EFAULT);
                }
            };
            match outcome {
                DispatchOutcome::Returned { value } => {
                    let len_u32 = value as u32;
                    if memory
                        .write_bytes(entry + MSG_LEN_OFFSET, &len_u32.to_le_bytes())
                        .is_err()
                    {
                        return DispatchOutcome::errno(LINUX_EFAULT);
                    }
                    sent += 1;
                }
                DispatchOutcome::Errno { errno } => {
                    if sent > 0 {
                        // At least one message went out — Linux returns
                        // the count of successful sends, and the errno
                        // surfaces on the next call.
                        return DispatchOutcome::Returned { value: sent as i64 };
                    }
                    return DispatchOutcome::errno(errno);
                }
                other => return other,
            }
        }
        DispatchOutcome::Returned { value: sent as i64 }
    }

    /// `recvmmsg(sockfd, msgvec, vlen, flags, timeout)` — Linux's
    /// batched recvmsg. Same shape as sendmmsg: loop over entries,
    /// call single recvmsg for each, fill msg_len on success.
    /// The timeout argument is best-effort — we fall through to a
    /// single libc::poll up front if it's non-NULL and at least one
    /// message is wanted before blocking.
    fn recvmmsg(
        &self,
        fd: Fd,
        msgvec: GuestPtr,
        vlen: u64,
        flags: u64,
        _timeout: GuestPtr,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let fd = fd.0;
        let msgvec = msgvec.0;
        let vlen = vlen as u32;
        let flags = flags as i32;
        const MMSGHDR_SIZE: u64 = <LinuxMmsghdr as KernelAbi>::ABI_SIZE as u64;
        const MSG_LEN_OFFSET: u64 = <LinuxMsghdr as KernelAbi>::ABI_SIZE as u64;
        let mut received: i32 = 0;
        for i in 0..vlen {
            let entry = match msgvec.checked_add(i as u64 * MMSGHDR_SIZE) {
                Some(a) => a,
                None => {
                    return DispatchOutcome::errno(LINUX_EFAULT);
                }
            };
            // After the first successful recvmsg, switch to non-blocking
            // so we drain whatever else is in the queue without waiting.
            let entry_flags = if received > 0 {
                flags | libc::MSG_DONTWAIT
            } else {
                flags
            };
            let outcome = match self.recvmsg_inner(fd, entry, entry_flags, &mut *memory) {
                Ok(o) => o,
                Err(_) => {
                    return DispatchOutcome::errno(LINUX_EFAULT);
                }
            };
            match outcome {
                DispatchOutcome::Returned { value } => {
                    let len_u32 = value as u32;
                    if memory
                        .write_bytes(entry + MSG_LEN_OFFSET, &len_u32.to_le_bytes())
                        .is_err()
                    {
                        return DispatchOutcome::errno(LINUX_EFAULT);
                    }
                    received += 1;
                }
                DispatchOutcome::Errno { errno } => {
                    if received > 0 {
                        return DispatchOutcome::Returned {
                            value: received as i64,
                        };
                    }
                    return DispatchOutcome::errno(errno);
                }
                other => return other,
            }
        }
        DispatchOutcome::Returned {
            value: received as i64,
        }
    }
}

impl SyscallDispatcher {
    define_syscall! {

        fn eventfd2(this, cx, initial_value: u64, flags: u64) {

            let initial_value = initial_value;
            let flags = flags;
            if flags & !(LINUX_EFD_SEMAPHORE | LINUX_EFD_NONBLOCK | LINUX_EFD_CLOEXEC) != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let description = OpenDescription::EventFd {
                state: Arc::new(EventFdState::new(initial_value)),
                semaphore: flags & LINUX_EFD_SEMAPHORE != 0,
                base: OpenDescriptionBase::new(flags & LINUX_EFD_NONBLOCK),
            };
            Ok(this.install_fd(description, linux_fd_flags_from_open_flags(flags)))

        }

        fn epoll_create1(this, cx, flags: u64) {

            let flags = flags;
            if flags & !LINUX_EPOLL_CLOEXEC != 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let Some(kqueue) = crate::darwin_kqueue::Kqueue::new_internal() else {
                return Ok(crate::linux_abi::LINUX_EMFILE.into());
            };
            // EVFILT_USER(0) is the in-memory wake channel: `notify_inmem_epoll`
            // NOTE_TRIGGERs it when an eventfd/pipe/timerfd readiness changes, so a
            // thread blocked on this kqueue's fd re-checks in-memory interests.
            let _ = kqueue.apply(&[crate::darwin_kqueue::Kevent::user(
                0,
                libc::EV_ADD | libc::EV_CLEAR,
            )]);
            let description = OpenDescription::Epoll {
                interest: HashMap::new(),
                base: OpenDescriptionBase::new(0),
                pending_ready: VecDeque::new(),
                kqueue: Arc::new(crate::dispatch::EpollKqueue::new(kqueue)),
            };
            Ok(this.install_fd(description, linux_fd_flags_from_open_flags(flags)))

        }

        fn epoll_ctl(this, cx, epfd: Fd, op: u64, fd: Fd, event: GuestPtr) {

            let memory = &*cx.memory;
            let epfd = epfd.0 as i32;
            let operation = op;
            let fd = fd.0 as i32;
            let event_address = event.0;
            // A bad target fd is EBADF; a target equal to the epoll fd itself is
            // EINVAL (an epoll instance can't monitor itself). (LTP epoll_ctl02.)
            if !this.fd_is_valid(fd) {
                return Ok(LINUX_EBADF.into());
            }
            if epfd == fd {
                return Ok(LINUX_EINVAL.into());
            }

            let Some(open_file) = this.open_file(epfd) else {
                return Ok(if this.fd_is_valid(epfd) {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                }
                .into());
            };
            // The host fd backing this target (sockets/pipes/ptys); `None` for an
            // in-memory eventfd/pipe/timerfd, whose readiness is recomputed each
            // `epoll_wait` rather than registered on the kqueue. Computed before
            // taking the epoll write lock (it locks the *target* fd's description).
            let host_fd = this.host_fd_for_poll(fd);

            let mut open = open_file.description.write();
            let OpenDescription::Epoll {
                interest,
                pending_ready,
                kqueue,
                ..
            } = &mut *open
            else {
                return Ok(LINUX_EINVAL.into());
            };

            match operation {
                LINUX_EPOLL_CTL_ADD => {
                    let event = match read_epoll_event(memory, event_address) {
                        Ok(event) => event,
                        Err(errno) => return Ok(errno.into()),
                    };
                    // The kernel rejects ADD of a target that has no ->poll support
                    // (regular files, directories) with EPERM. (LTP epoll_ctl02/05.)
                    if !this.fd_is_epollable(fd) {
                        return Ok(LINUX_EPERM.into());
                    }
                    if interest.contains_key(&fd) {
                        return Ok(LINUX_EEXIST.into());
                    }
                    if let Some(host_fd) = host_fd {
                        let _ = kqueue.apply(&epoll_kq_add_changes(host_fd, fd, event.events));
                    }
                    interest.insert(
                        fd,
                        EpollInterest {
                            event,
                            last_ready: 0,
                        },
                    );
                    crate::probes::epoll_ctl(epfd, operation, fd, event.events, event.data, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                LINUX_EPOLL_CTL_MOD => {
                    let event = match read_epoll_event(memory, event_address) {
                        Ok(event) => event,
                        Err(errno) => return Ok(errno.into()),
                    };
                    let Some(slot) = interest.get_mut(&fd) else {
                        return Ok(LINUX_ENOENT.into());
                    };
                    let old_events = slot.event.events;
                    // MOD first applies the new filters, then removes filters no
                    // longer present in the new mask. That avoids a no-interest
                    // gap where a readiness edge can be lost; the transient overlap
                    // can only produce an extra wake.
                    if let Some(host_fd) = host_fd {
                        if kqueue
                            .apply(&epoll_kq_add_changes(host_fd, fd, event.events))
                            .is_ok()
                        {
                            epoll_kq_delete_removed_filters(kqueue, host_fd, old_events, event.events);
                        }
                    }
                    clear_pending_epoll_ready(pending_ready, fd);
                    *slot = EpollInterest {
                        event,
                        last_ready: 0,
                    };
                    crate::probes::epoll_ctl(epfd, operation, fd, event.events, event.data, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                LINUX_EPOLL_CTL_DEL => {
                    let Some(removed) = interest.remove(&fd) else {
                        return Ok(LINUX_ENOENT.into());
                    };
                    if let Some(host_fd) = host_fd {
                        // Other guest fds in THIS epoll instance can be dups of the
                        // same socket/pipe, all sharing ONE host fd. The kqueue
                        // filter is keyed by host fd, so an unconditional EV_DELETE
                        // here would deafen those survivors — but Linux epoll
                        // interest is per-fd, so they must keep getting readiness.
                        // (This is the Go `net` TestFileListener hang: File() +
                        // FileListener dup the listener, then the intermediate dup
                        // is DEL'd, which used to rip out the shared filter.)
                        // Re-bind the filter to a surviving fd with the UNION of all
                        // survivors' masks, and only drop filter classes no survivor
                        // still wants. With no survivor, delete as before.
                        let mut survivor: Option<i32> = None;
                        let mut union_events: u32 = 0;
                        for (&other, slot) in interest.iter() {
                            if this.host_fd_for_poll(other) == Some(host_fd) {
                                survivor.get_or_insert(other);
                                union_events |= slot.event.events;
                            }
                        }
                        match survivor {
                            Some(sfd) => {
                                let _ = kqueue
                                    .apply(&epoll_kq_add_changes(host_fd, sfd, union_events));
                                epoll_kq_delete_removed_filters(
                                    kqueue,
                                    host_fd,
                                    removed.event.events,
                                    union_events,
                                );
                            }
                            None => epoll_kq_delete(kqueue, host_fd),
                        }
                    }
                    clear_pending_epoll_ready(pending_ready, fd);
                    crate::probes::epoll_ctl(epfd, operation, fd, 0, 0, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                _ => Ok(LINUX_EINVAL.into()),
            }

        }

        fn epoll_pwait(this, cx, epfd: Fd, events: GuestPtr, maxevents: u64, timeout: u64, sigmask: GuestPtr, sigsetsize: u64) {

            let epfd = epfd.0 as i32;
            let events_address = events.0;
            // maxevents is a signed int; the kernel rejects <= 0 with EINVAL. A
            // negative value arrives as a huge u64, so check the signed form.
            // (LTP epoll_wait03.)
            let max_events_signed = maxevents as i32;
            let timeout_ms = timeout as i32;
            // epoll_pwait carries a sigmask (arg4) + sigsetsize (arg5); epoll_wait
            // passes a NULL mask. A non-NULL mask must have the right size and a
            // readable pointer, else EINVAL/EFAULT. (LTP epoll_pwait04.)
            let sigmask_ptr = sigmask.0;
            let sigsetsize = sigsetsize;
            let memory = &mut *cx.memory;
            if max_events_signed <= 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let max_events = max_events_signed as usize;
            // The sigmask temporarily blocks signals for the duration of the wait;
            // capture it as a u64 bitmask (bit signum-1) to carry into WaitOnFds so
            // a blocked signal doesn't interrupt the wait (LTP epoll_pwait01).
            let block_signals: u64 = if sigmask_ptr != 0 {
                if sigsetsize != crate::linux_abi::LINUX_RT_SIGSET_SIZE {
                    return Ok(LINUX_EINVAL.into());
                }
                match memory.read_bytes(sigmask_ptr, crate::linux_abi::LINUX_RT_SIGSET_SIZE as usize) {
                    Ok(bytes) => {
                        let mut le = [0u8; 8];
                        le.copy_from_slice(&bytes[..8]);
                        u64::from_le_bytes(le)
                    }
                    Err(_) => return Ok(LINUX_EFAULT.into()),
                }
            } else {
                0
            };

            let Some(open_file) = this.open_file(epfd) else {
                // A valid fd that simply isn't an epoll instance is EINVAL; only a
                // genuinely bad fd is EBADF. (LTP epoll_wait03.)
                return Ok(if this.fd_is_valid(epfd) {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                }
                .into());
            };
            // Snapshot any already-queued ready events first.
            let mut ready = {
                let mut open = open_file.description.write();
                let OpenDescription::Epoll { pending_ready, .. } = &mut *open else {
                    return Ok(LINUX_EINVAL.into());
                };
                drain_pending_epoll_ready(pending_ready, max_events)
            };
            if !ready.is_empty() {
                crate::probes::epoll_result(epfd, ready.len() as i32, 0, timeout_ms, 0);
                return write_epoll_events(memory, events_address, &ready);
            }

            // Snapshot interest metadata and the persistent instance kqueue. The
            // kqueue is the authoritative readiness source for host-backed fds
            // (sockets/pipes/ptys) — crucially, it monitors fds registered by OTHER
            // threads while this thread is blocked, fixing the interest-snapshot
            // race that lost a netpoller wakeup. If a drained host event names a
            // guest fd that is not in this snapshot, fall back to the live map
            // before dropping it; that covers the narrow concurrent ADD race
            // without putting a live lock lookup on every returned event.
            let (interests, kq, kq_fd) = {
                let open = open_file.description.read();
                let OpenDescription::Epoll {
                    interest, kqueue, ..
                } = &*open
                else {
                    return Ok(LINUX_EINVAL.into());
                };
                (
                    interest
                        .iter()
                        .map(|(fd, interest)| (*fd, interest.clone()))
                        .collect::<Vec<_>>(),
                    Arc::clone(kqueue),
                    kqueue.raw_fd(),
                )
            };
            let has_interests = !interests.is_empty();

            // guest_fd -> (accumulated epoll events, epoll_data); read+write filters
            // for the same fd merge into one returned event.
            let mut acc: HashMap<i32, (u32, u64)> = HashMap::new();

            // (1) Drain the instance kqueue (non-blocking) for host-backed fds.
            // `kq_drained_all_filtered` tracks the corner case where the kqueue
            // had readiness events but the user's interest mask filters them
            // all out (e.g. `epoll_ctl(ADD, fd, events=0)` plus data on the
            // pipe — the read filter still fires because Linux must surface
            // EPOLLHUP/EPOLLERR, but no event bit matches). Without this flag
            // we'd return `WaitOnPollFds` and the runtime would re-poll the
            // already-readable kq_fd, re-dispatch, and tight-loop until the
            // harness deadline. Detect it once here and switch to an empty
            // `WaitOnFds` (signal-pipe-and-timeout-only) below.
            let mut kq_drained_all_filtered = false;
            {
                let cap = interests.len() * 2 + 4;
                let mut out = vec![crate::darwin_kqueue::Kevent::empty(); cap.max(1)];
                let zero = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                if let Ok(n) = kq.wait(&[], &mut out, Some(&zero)) {
                    let acc_before = acc.len();
                    // Count only REAL host-fd events (EVFILT_READ/WRITE/EXCEPT →
                    // nonzero epoll bits). A consumed EVFILT_USER(0) in-memory wake
                    // (bits == 0, registered EV_CLEAR so it auto-resets on this
                    // drain) must NOT count toward `kq_drained_all_filtered`: it is
                    // gone now, so polling kq_fd will not spin, whereas the
                    // all-filtered path parks on the signal pipe only — which
                    // strands an indefinite epoll_pwait that can no longer be
                    // reached by the next notify_inmem_epoll / host-fd readiness
                    // edge (the Node worker-teardown loop-thread hang).
                    let mut translatable_events = 0usize;
                    for ev in &out[..n] {
                        let bits = kevent_to_epoll(*ev);
                        if bits == 0 {
                            // EVFILT_USER(0) in-memory wake, or a filter with no
                            // translatable bits — recompute below covers in-memory.
                            continue;
                        }
                        translatable_events += 1;
                        let guest_fd = ev.udata_i32();
                        // The kqueue filter is keyed by HOST fd, but several guest
                        // fds can be dups of one socket/pipe sharing that host fd,
                        // and Linux wakes EACH fd's pollDesc independently. The
                        // event carries only one `udata`, so fan the readiness out
                        // to every interested guest fd that shares this host fd —
                        // otherwise a dup the app is actually waiting on (e.g. the
                        // FileListener while the original listener is also
                        // registered) never wakes. (Go `net` TestFileListener.)
                        let event_host_fd = this.host_fd_for_poll(guest_fd);
                        let mut reported_any = false;
                        for (ifd, slot) in interests.iter() {
                            let shares = *ifd == guest_fd
                                || (event_host_fd.is_some()
                                    && this.host_fd_for_poll(*ifd) == event_host_fd);
                            if !shares {
                                continue;
                            }
                            reported_any = true;
                            let masked =
                                bits & (slot.event.events | LINUX_EPOLLHUP | LINUX_EPOLLERR);
                            if masked != 0 {
                                let entry = acc.entry(*ifd).or_insert((0, slot.event.data));
                                entry.0 |= masked;
                            }
                        }
                        if !reported_any {
                            // Concurrent-ADD race: the udata fd isn't in this
                            // snapshot yet. Fall back to the live map for it alone.
                            let live = {
                                let open = open_file.description.read();
                                match &*open {
                                    OpenDescription::Epoll { interest, .. } => interest
                                        .get(&guest_fd)
                                        .map(|slot| (slot.event.events, slot.event.data)),
                                    _ => None,
                                }
                            };
                            if let Some((requested, data)) = live {
                                let masked = bits & (requested | LINUX_EPOLLHUP | LINUX_EPOLLERR);
                                if masked != 0 {
                                    acc.entry(guest_fd).or_insert((0, data)).0 |= masked;
                                }
                            }
                        }
                    }
                    // A REAL host-fd readiness event fired but our interest masks
                    // let none of them through (the events=0-with-data case).
                    // Polling kq_fd would just see the same (level-triggered)
                    // readiness and spin, so park on the signal pipe instead. A
                    // pure EVFILT_USER drain is excluded (translatable_events == 0):
                    // it auto-resets, so the kqueue-poll path is correct and keeps
                    // the waiter reachable by later wakes.
                    kq_drained_all_filtered = translatable_events > 0 && acc.len() == acc_before;
                }
            }

            // (2) In-memory fds (no host fd): recompute readiness; keep the EPOLLET
            // `last_ready` edge latch for these (the kqueue handles edge/level for
            // host fds natively, so they need no latch).
            let mut ready_updates: Vec<(i32, u32)> = Vec::new();
            for (fd, interest) in &interests {
                if this.host_fd_for_poll(*fd).is_some() {
                    continue;
                }
                let requested = interest.event.events;
                let raw_ready = this.epoll_ready_events(*fd, requested);
                ready_updates.push((*fd, raw_ready));
                let ready_events = if requested & LINUX_EPOLLET != 0 {
                    raw_ready & !interest.last_ready
                } else {
                    raw_ready
                };
                crate::probes::epoll_interest(
                    epfd,
                    *fd,
                    requested,
                    raw_ready,
                    interest.last_ready,
                    ready_events,
                );
                if ready_events != 0 {
                    let entry = acc.entry(*fd).or_insert((0, interest.event.data));
                    entry.0 |= ready_events;
                }
            }

            // EPOLLONESHOT: every interest that just fired must be disarmed
            // until EPOLL_CTL_MOD re-arms it (Linux semantics — the fd never
            // appears in a subsequent epoll_wait without an explicit MOD).
            // Collect the fds-to-disarm before consuming `acc`.
            let oneshot_fds: Vec<i32> = acc
                .iter()
                .filter(|(fd, _)| {
                    interests
                        .iter()
                        .any(|(ifd, slot)| ifd == *fd && slot.event.events & LINUX_EPOLLONESHOT != 0)
                })
                .map(|(fd, _)| *fd)
                .collect();

            if !ready_updates.is_empty() || !oneshot_fds.is_empty() {
                let mut open = open_file.description.write();
                if let OpenDescription::Epoll { interest, .. } = &mut *open {
                    for (fd, raw) in ready_updates {
                        if let Some(slot) = interest.get_mut(&fd) {
                            slot.last_ready = raw;
                        }
                    }
                    for fd in &oneshot_fds {
                        if let Some(slot) = interest.get_mut(fd) {
                            // Clear the events mask so subsequent waits never
                            // surface this fd until EPOLL_CTL_MOD re-arms it.
                            slot.event.events = 0;
                        }
                    }
                }
            }
            // Also remove the host kqueue filter for each disarmed fd so the
            // level-triggered EVFILT_READ doesn't keep firing and tight-loop
            // the next epoll_wait (the same shape as the events=0 fix above,
            // applied to the freshly-disarmed ONESHOT slot).
            for fd in &oneshot_fds {
                if let Some(host_fd) = this.host_fd_for_poll(*fd) {
                    let _ = kq.apply(&[
                        crate::darwin_kqueue::Kevent::read(host_fd, libc::EV_DELETE),
                        crate::darwin_kqueue::Kevent::write(host_fd, libc::EV_DELETE),
                        crate::darwin_kqueue::Kevent::oob(host_fd, libc::EV_DELETE),
                    ]);
                }
            }

            // Tag each ready event with its ORIGINATING guest fd (acc is keyed by
            // guest fd) so an overflow queued into pending_ready can be purged by
            // fd on EPOLL_CTL_DEL/MOD even when epoll_data != fd. Split the tail
            // (still fd-tagged) into pending_ready, THEN strip fds for the
            // guest-visible `ready`. (audit M3; probe epollstaledel)
            let mut ready_tagged: Vec<(i32, LinuxEpollEvent)> = acc
                .into_iter()
                .map(|(fd, (events, data))| {
                    (
                        fd,
                        LinuxEpollEvent {
                            events,
                            _pad: 0,
                            data,
                        },
                    )
                })
                .collect();
            if ready_tagged.len() > max_events {
                let overflow: Vec<(i32, LinuxEpollEvent)> = ready_tagged.split_off(max_events);
                let mut open = open_file.description.write();
                if let OpenDescription::Epoll { pending_ready, .. } = &mut *open {
                    pending_ready.extend(overflow);
                }
            }
            ready = ready_tagged.into_iter().map(|(_fd, event)| event).collect();

            if ready.is_empty() && timeout_ms != 0 {
                let timeout = if timeout_ms < 0 {
                    None
                } else {
                    Some(Duration::from_millis(timeout_ms as u64))
                };
                if kq_drained_all_filtered || !has_interests {
                    // Either the kqueue is already readable for events we
                    // DON'T care about (filtered to zero by the interest mask),
                    // or no interests are registered at all (epoll_pwait with
                    // an empty interest set must still honour the timeout +
                    // signal interrupt path, not return 0 immediately).
                    // Either way: polling kq_fd would spin or be pointless.
                    // Sleep the timeout on the signal pipe — interruptible by
                    // a real signal.
                    crate::probes::epoll_result(epfd, 0, 1, timeout_ms, 2);
                    return Ok(DispatchOutcome::WaitOnFds {
                        fds: Vec::new(),
                        timeout,
                        on_timeout: 0,
                        block_signals,
                    });
                }
                crate::probes::epoll_result(epfd, 0, 1, timeout_ms, 1);
                crate::probes::epoll_wait_fd(epfd, -1, kq_fd, libc::POLLIN as i32, timeout_ms);
                // Poll the instance kqueue fd for readability. This avoids nesting
                // the epoll kqueue inside the per-thread kqueue, and unlike calling
                // kevent() here it does not consume pending epoll events before the
                // re-dispatched epoll_pwait can copy them out.
                return Ok(DispatchOutcome::WaitOnPollFds {
                    fds: vec![(kq_fd, libc::POLLIN)],
                    timeout,
                    on_timeout: 0,
                    block_signals,
                });
            }

            crate::probes::epoll_result(epfd, ready.len() as i32, 0, timeout_ms, 0);
            write_epoll_events(memory, events_address, &ready)

        }

        fn pselect6(this, cx, nfds: u64, readfds: GuestPtr, writefds: GuestPtr, exceptfds: GuestPtr, timeout: GuestPtr, sigmask: GuestPtr) {

            // Linux rejects nfds < 0 with EINVAL BEFORE anything else. The guest
            // passes nfds as a (sign-extended) int; -1 arrives as u64::MAX.
            // Without this, pselect6(-1, NULL, NULL, NULL, NULL, mask) — LTP
            // pselect02 case 2 — falls through to the empty-fd-set NULL-timeout
            // path and blocks the test child forever (the tst_test watchdog then
            // SIGALRM-kills it → TBROK). Validate first.
            if (nfds as i64) < 0 {
                return Ok(LINUX_EINVAL.into());
            }
            let nfds = GuestLen::try_from_arg(nfds)?.0;
            let readfds_addr = readfds.0;
            let writefds_addr = writefds.0;
            let exceptfds_addr = exceptfds.0;
            let timeout_addr = timeout.0;
            let sigmask_addr = sigmask.0;
            let request_number = cx.number();
            let request_args = cx.raw_args();
            let memory = &mut *cx.memory;
            let reporter = cx.reporter;

            // Linux's pselect6 ABI for the 6th argument is NOT a bare sigset_t *
            // but a pointer to `struct { const sigset_t *ss; size_t ss_len; }`
            // (the kernel "sigset_argpack"). We read the pair, then if ss != 0
            // and ss_len == LINUX_RT_SIGSET_SIZE, read the actual 8-byte sigset
            // for the bitmask. NULL outer arg means "no mask change". This bit
            // mask gates the waiter via `block_signals`: a blocked signal stays
            // pending instead of EINTR-ing the wait (LTP pselect02 case).
            let block_signals: u64 = if sigmask_addr != 0 {
                match memory.read_bytes(sigmask_addr, 16) {
                    Ok(pack) => {
                        let ss_ptr = u64::from_le_bytes(pack[0..8].try_into().unwrap_or([0; 8]));
                        let ss_len = u64::from_le_bytes(pack[8..16].try_into().unwrap_or([0; 8]));
                        if ss_ptr != 0 && ss_len == crate::linux_abi::LINUX_RT_SIGSET_SIZE {
                            match memory.read_bytes(ss_ptr, ss_len as usize) {
                                Ok(bytes) => u64::from_le_bytes(
                                    bytes.try_into().unwrap_or([0; 8]),
                                ),
                                Err(_) => return Ok(LINUX_EFAULT.into()),
                            }
                        } else {
                            0
                        }
                    }
                    Err(_) => return Ok(LINUX_EFAULT.into()),
                }
            } else {
                0
            };

            // Decode timespec → millis for libc::poll. NULL = block forever (-1).
            let timeout_ms: i32 = if timeout_addr == 0 {
                -1
            } else {
                match read_kernel_struct::<LinuxTimespec>(memory, timeout_addr) {
                    Ok(timespec) => {
                        let sec = timespec.tv_sec;
                        let nsec = timespec.tv_nsec;
                        // Linux rejects an invalid timespec with EINVAL (negative
                        // seconds/nanoseconds or nsec out of [0, 1e9)) — LTP
                        // pselect02 case 3. carrick previously clamped it to 0
                        // (returned "timed out" instead of erroring).
                        if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
                            return Ok(LINUX_EINVAL.into());
                        }
                        let ms = sec.saturating_mul(1000).saturating_add(nsec / 1_000_000);
                        if ms <= 0 {
                            0
                        } else if ms > i32::MAX as i64 {
                            i32::MAX
                        } else {
                            ms as i32
                        }
                    }
                    // A bad timeout pointer: leave the existing behavior (a guest
                    // read of an unmapped VA already injects a fault upstream);
                    // only the value-validation above is new. (faulty-pointer
                    // EFAULT vs guest-SIGSEGV is select03's domain — left as-is.)
                    _ => 0,
                }
            };

            // Pull each fd_set into memory.
            let read_set = match this.read_optional_fd_set(memory, readfds_addr, nfds)? {
                Ok(s) => s,
                Err(errno) => return Ok(errno.into()),
            };
            let write_set = match this.read_optional_fd_set(memory, writefds_addr, nfds)? {
                Ok(s) => s,
                Err(errno) => return Ok(errno.into()),
            };
            let except_set = match this.read_optional_fd_set(memory, exceptfds_addr, nfds)? {
                Ok(s) => s,
                Err(errno) => return Ok(errno.into()),
            };

            // Collect the union of the three sets into per-fd entries, and try to
            // map each guest fd to a real host fd. Then route exactly like ppoll:
            //   - all fds host-backed → one libc::poll (kernel blocks efficiently);
            //   - any fd synthetic (eventfd/timerfd/epoll/in-memory pipe) → the
            //     poll_ready_events readiness loop, which is correct for those.
            // The old code unwrap_or'd synthetic fds into the guest fd *number* and
            // polled that as a host fd — which blocks on carrick's own fds and
            // deadlocks. Each fd gets POLLIN/POLLOUT/POLLPRI per its set membership.
            let mut owners: Vec<(i32, i16)> = Vec::new(); // (fd, requested_mask)
            let mut events_list: Vec<i16> = Vec::new();
            let mut host_map: Vec<Option<i32>> = Vec::new();
            for fd in 0..nfds {
                let r = read_set.as_ref().is_some_and(|s| fd_set_contains(s, fd));
                let w = write_set.as_ref().is_some_and(|s| fd_set_contains(s, fd));
                let e = except_set.as_ref().is_some_and(|s| fd_set_contains(s, fd));
                if !(r || w || e) {
                    continue;
                }
                let fd_i32 = i32::try_from(fd).map_err(|_| DispatchError::LengthTooLarge(u64::MAX))?;
                if !this.fd_is_valid(fd_i32) {
                    return Ok(LINUX_EBADF.into());
                }
                let mut events: i16 = 0;
                if r {
                    events |= libc::POLLIN;
                }
                if w {
                    events |= libc::POLLOUT;
                }
                if e {
                    events |= libc::POLLPRI;
                }
                let mut req_mask: i16 = 0;
                if r {
                    req_mask |= 0x01;
                }
                if w {
                    req_mask |= 0x02;
                }
                if e {
                    req_mask |= 0x04;
                }
                owners.push((fd_i32, req_mask));
                events_list.push(events);
                host_map.push(this.host_fd_for_poll(fd_i32));
            }

            // revents per entry, filled by whichever path runs.
            let mut revents: Vec<i16> = vec![0; owners.len()];
            let all_host: Option<Vec<i32>> = host_map.iter().copied().collect();

            if owners.is_empty() {
                // No fds in any set. The original raw `libc::nanosleep` here
                // never observed guest pending signals (the pump publishes via
                // the dispatcher-thread-invisible PENDING atomic, not a host
                // signal), so pselect(0, NULL, NULL, NULL, &ts, NULL) slept the
                // whole timeout instead of EINTR-ing on SIGALRM. Hand off to
                // the runtime's lockless waiter just like ppoll does: empty
                // fds + Some(timeout) parks on the signal pipe with the
                // timeout, returns Interrupted (EINTR) on a wake, TimedOut
                // (returned=0) on the deadline.
                let timeout = if timeout_ms < 0 {
                    None
                } else {
                    Some(std::time::Duration::from_millis(timeout_ms as u64))
                };
                let _ = reporter;
                let _ = request_number;
                let _ = request_args;
                return Ok(DispatchOutcome::WaitOnFds {
                    fds: Vec::new(),
                    timeout,
                    on_timeout: 0,
                    block_signals,
                });
            } else if let Some(host_fds) = all_host {
                let mut pollfds: Vec<libc::pollfd> = host_fds
                    .iter()
                    .zip(events_list.iter())
                    .map(|(hf, ev)| libc::pollfd {
                        fd: *hf,
                        events: *ev,
                        revents: 0,
                    })
                    .collect();
                // NON-BLOCKING probe (timeout 0). A blocking libc::poll here
                // would (a) tie up this vCPU thread without releasing it for
                // siblings, and (b) never wake on a guest signal — carrick
                // publishes pending signals via an atomic the dispatcher checks
                // between dispatches, not a host signal that interrupts poll —
                // so select could never return EINTR. Instead, if nothing is
                // ready and the caller wants to wait, hand off to the runtime's
                // signal-interruptible waiter via WaitOnFdsSelect (mirrors how
                // ppoll uses WaitOnFds).
                let n = unsafe {
                    libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 0)
                };
                if let Err(errno) = n.host_syscall_errno() {
                    return Ok(errno.into());
                }
                if n == 0 && timeout_ms != 0 {
                    // Nothing ready yet, caller wants to block. Leave the guest
                    // fd-sets UNTOUCHED (select's bitmaps are input==output): a
                    // Ready re-dispatch must re-read the original input, and an
                    // EINTR must leave them unmodified (Linux semantics). The
                    // runtime zeroes them only if the wait times out.
                    let timeout = if timeout_ms < 0 {
                        None
                    } else {
                        Some(std::time::Duration::from_millis(timeout_ms as u64))
                    };
                    let wait_fds: Vec<(i32, i16)> = host_fds
                        .iter()
                        .zip(events_list.iter())
                        .map(|(hf, ev)| (*hf, *ev))
                        .collect();
                    let mut clear_on_timeout: Vec<(u64, usize)> = Vec::new();
                    if let Some(s) = &read_set {
                        clear_on_timeout.push((readfds_addr, s.len()));
                    }
                    if let Some(s) = &write_set {
                        clear_on_timeout.push((writefds_addr, s.len()));
                    }
                    if let Some(s) = &except_set {
                        clear_on_timeout.push((exceptfds_addr, s.len()));
                    }
                    return Ok(DispatchOutcome::WaitOnFdsSelect {
                        fds: wait_fds,
                        timeout,
                        block_signals,
                        clear_on_timeout,
                    });
                }
                for (slot, p) in revents.iter_mut().zip(pollfds.iter()) {
                    *slot = p.revents;
                }
            } else {
                // Mixed/synthetic: per-fd readiness with nanosleep slicing.
                let mut deadline_attempts = 0u32;
                loop {
                    let mut any = false;
                    for (i, (fd, _)) in owners.iter().enumerate() {
                        let rev = this.poll_ready_events(*fd, events_list[i]);
                        revents[i] = rev;
                        if rev != 0 {
                            any = true;
                        }
                    }
                    if any || timeout_ms == 0 {
                        break;
                    }
                    const SLICE_MS: u32 = 10;
                    unsafe {
                        let ts = libc::timespec {
                            tv_sec: 0,
                            tv_nsec: (SLICE_MS as i64) * 1_000_000,
                        };
                        libc::nanosleep(&ts, std::ptr::null_mut());
                    }
                    deadline_attempts += 1;
                    if timeout_ms > 0 {
                        if deadline_attempts.saturating_mul(SLICE_MS) as i32 >= timeout_ms {
                            break;
                        }
                    } else if deadline_attempts > 6000 {
                        // Blocked ~60 s with no fd ever ready: almost certainly a
                        // missing readiness signal, not a real idle wait. Make it
                        // loud in `carrick trace` instead of silently returning 0.
                        reporter.record(CompatEvent::partial_syscall(
                            request_number,
                            "pselect6",
                            request_args,
                            "blocked ~60s with no fd ready (possible poll deadlock)",
                        ));
                        break;
                    }
                }
            }

            // Adapter so the writeback below reads `p.revents` uniformly.
            let pollfds: Vec<libc::pollfd> = owners
                .iter()
                .zip(revents.iter())
                .map(|((fd, _), rev)| libc::pollfd {
                    fd: *fd,
                    events: 0,
                    revents: *rev,
                })
                .collect();

            // Write back ready bits. Start with fully-cleared sets and only
            // set bits for fds that fired.
            let mut new_read = read_set.clone().map(|mut s| {
                s.fill(0);
                s
            });
            let mut new_write = write_set.clone().map(|mut s| {
                s.fill(0);
                s
            });
            let mut new_except = except_set.clone().map(|mut s| {
                s.fill(0);
                s
            });
            let mut ready = 0i64;
            for ((fd, req_mask), p) in owners.iter().zip(pollfds.iter()) {
                let fd_usize = *fd as usize;
                let revs = p.revents;
                // select(2) returns the TOTAL number of ready bits across all
                // three sets — an fd that is ready for both read AND write
                // (e.g. an O_RDWR FIFO/socket placed in readfds and writefds,
                // LTP select01) counts as 2, not 1. Count each set-bit, not the
                // fd once.
                if (req_mask & 0x01) != 0
                    && (revs & (libc::POLLIN | libc::POLLHUP)) != 0
                    && let Some(ref mut set) = new_read
                {
                    fd_set_set(set, fd_usize);
                    ready += 1;
                }
                // select(2) marks an fd write-ready when it is writable OR has a
                // pending error/hangup (so the app can collect the error via a
                // write/getsockopt). Linux reports POLLOUT|POLLERR|POLLHUP on a
                // failed async connect; macOS poll() reports ONLY POLLHUP for the
                // same socket (verified). Treat POLLERR/POLLHUP as write-ready so
                // asyncio's sock_connect surfaces ConnectionRefusedError instead
                // of hanging until the wait_for timeout.
                if (req_mask & 0x02) != 0
                    && (revs & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP)) != 0
                    && let Some(ref mut set) = new_write
                {
                    fd_set_set(set, fd_usize);
                    ready += 1;
                }
                if (req_mask & 0x04) != 0
                    && (revs & (libc::POLLPRI | libc::POLLERR)) != 0
                    && let Some(ref mut set) = new_except
                {
                    fd_set_set(set, fd_usize);
                    ready += 1;
                }
            }
            if let Some(s) = &new_read
                && memory.write_bytes(readfds_addr, s).is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }
            if let Some(s) = &new_write
                && memory.write_bytes(writefds_addr, s).is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }
            if let Some(s) = &new_except
                && memory.write_bytes(exceptfds_addr, s).is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: ready })

        }

        fn ppoll(this, cx, fds: GuestPtr, nfds: u64, timeout: GuestPtr, sigmask: GuestPtr, sigsetsize: u64) {

            let pollfds_address = fds.0;
            let nfds =
                usize::try_from(nfds).map_err(|_| DispatchError::LengthTooLarge(nfds))?;
            let timeout_address = timeout.0;
            // sigmask args read here (before the `memory` mutable borrow); the mask
            // VALUE is read from guest memory below once `memory` is bound.
            let sigmask_addr = sigmask.0;
            let sigsetsize = sigsetsize;
            let request_number = cx.number();
            let request_args = cx.raw_args();
            let memory = &mut *cx.memory;
            let reporter = cx.reporter;

            // Decode timeout. NULL pointer means block forever; non-NULL points
            // to a `struct timespec { i64 tv_sec; i64 tv_nsec; }`. We translate
            // to milliseconds for libc::poll (-1 = forever, 0 = immediate).
            let timeout_ms: i32 = if timeout_address == 0 {
                -1
            } else {
                match read_kernel_struct::<LinuxTimespec>(memory, timeout_address) {
                    Ok(timespec) => {
                        let sec = timespec.tv_sec;
                        let nsec = timespec.tv_nsec;
                        let ms = sec.saturating_mul(1000).saturating_add(nsec / 1_000_000);
                        if ms <= 0 {
                            0
                        } else if ms > i32::MAX as i64 {
                            i32::MAX
                        } else {
                            ms as i32
                        }
                    }
                    _ => 0,
                }
            };

            // ppoll(fds, nfds, timeout, sigmask, sigsetsize): capture the sigmask as
            // a u64 bitmask (bit signum-1) so a blocked signal doesn't interrupt the
            // wait (it stays pending, delivered after the syscall). Mirrors
            // epoll_pwait. Read before the pollfd loop (returns an owned Vec, so the
            // `memory` borrow is released).
            let block_signals: u64 = if sigmask_addr != 0 {
                if sigsetsize != crate::linux_abi::LINUX_RT_SIGSET_SIZE {
                    return Ok(LINUX_EINVAL.into());
                }
                match memory.read_bytes(
                    sigmask_addr,
                    crate::linux_abi::LINUX_RT_SIGSET_SIZE as usize,
                ) {
                    Ok(bytes) => {
                        let mut le = [0u8; 8];
                        le.copy_from_slice(&bytes[..8]);
                        u64::from_le_bytes(le)
                    }
                    Err(_) => return Ok(LINUX_EFAULT.into()),
                }
            } else {
                0
            };

            // Read all the pollfds up front so we can route them. Fast path:
            // every fd in the set maps to a host fd (stdio bare, HostPipe, or
            // HostSocket) → call libc::poll once with the requested timeout
            // and let the kernel block efficiently instead of pseudo-polling
            // in a 10 ms-slice loop.
            let pollfd_size = core::mem::size_of::<LinuxPollFd>();
            let mut fds: Vec<LinuxPollFd> = Vec::with_capacity(nfds);
            let mut addresses: Vec<u64> = Vec::with_capacity(nfds);
            for index in 0..nfds {
                let offset = index
                    .checked_mul(pollfd_size)
                    .and_then(|offset| u64::try_from(offset).ok())
                    .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                let address = pollfds_address.checked_add(offset).ok_or(LINUX_EFAULT);
                let address = match address {
                    Ok(a) => a,
                    Err(_) => {
                        return Ok(LINUX_EFAULT.into());
                    }
                };
                let pollfd = match read_pollfd(memory, address) {
                    Ok(p) => p,
                    Err(errno) => return Ok(errno.into()),
                };
                fds.push(pollfd);
                addresses.push(address);
            }
            // Map guest fds → host fds where possible. Fast path requires
            // every fd be host-backed (stdio bare, HostPipe, HostSocket).
            let host_fds: Option<Vec<i32>> = fds.iter().map(|p| this.host_fd_for_poll(p.fd)).collect();
            if let Some(host_fds) = host_fds {
                let mut sys_pollfds: Vec<libc::pollfd> = fds
                    .iter()
                    .zip(host_fds.iter())
                    .map(|(p, hf)| libc::pollfd {
                        fd: *hf,
                        events: p.events,
                        revents: 0,
                    })
                    .collect();
                // NON-BLOCKING probe (timeout 0): we must NEVER block here — this
                // runs while holding the dispatcher lock, and blocking would starve
                // every sibling thread (the GIL handoff, a server's workers). If
                // nothing is ready and the guest asked to wait, hand off to the
                // runtime via WaitOnFds, which waits with the lock RELEASED.
                let n = unsafe {
                    libc::poll(
                        sys_pollfds.as_mut_ptr(),
                        sys_pollfds.len() as libc::nfds_t,
                        0,
                    )
                };
                if let Err(errno) = n.host_syscall_errno() {
                    return Ok(errno.into());
                }
                let mut ready = 0i64;
                for (i, p) in sys_pollfds.iter().enumerate() {
                    let mut pollfd = fds[i];
                    pollfd.revents = p.revents;
                    if pollfd.revents != 0 {
                        ready += 1;
                    }
                    // Always write back (zeroed revents on a not-ready probe) so a
                    // later timeout completion needs no further writes.
                    if write_kernel_struct_raw(memory, addresses[i], &pollfd).is_err() {
                        return Ok(LINUX_EFAULT.into());
                    }
                }
                if ready > 0 || timeout_ms == 0 {
                    return Ok(DispatchOutcome::Returned { value: ready });
                }
                let timeout = if timeout_ms < 0 {
                    None
                } else {
                    Some(std::time::Duration::from_millis(timeout_ms as u64))
                };
                let wait_fds: Vec<(i32, i16)> = sys_pollfds.iter().map(|p| (p.fd, p.events)).collect();
                // poll/ppoll: a timeout means "no fds ready" → return 0.
                return Ok(DispatchOutcome::WaitOnFds {
                    fds: wait_fds,
                    timeout,
                    on_timeout: 0,
                    block_signals,
                });
            }

            // Mixed / synthetic fds: fall back to the per-fd readiness check
            // loop. Slow because of nanosleep slicing but correct.
            let mut ready: i64;
            let mut deadline_attempts = 0u32;
            loop {
                ready = 0;
                for (index, pollfd) in fds.iter_mut().enumerate() {
                    pollfd.revents = this.poll_ready_events(pollfd.fd, pollfd.events);
                    if pollfd.revents != 0 {
                        ready += 1;
                    }
                    if write_kernel_struct_raw(memory, addresses[index], pollfd).is_err() {
                        return Ok(LINUX_EFAULT.into());
                    }
                }
                if ready > 0 || timeout_ms == 0 {
                    break;
                }
                const SLICE_MS: u32 = 10;
                unsafe {
                    let ts = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: (SLICE_MS as i64) * 1_000_000,
                    };
                    libc::nanosleep(&ts, std::ptr::null_mut());
                }
                deadline_attempts += 1;
                if timeout_ms > 0 {
                    let elapsed_ms = deadline_attempts.saturating_mul(SLICE_MS);
                    if elapsed_ms as i32 >= timeout_ms {
                        break;
                    }
                } else if deadline_attempts > 6000 {
                    // ~60 s ceiling for "block forever" callers. Reaching it means
                    // no fd ever became ready — surface it loudly in carrick trace
                    // rather than silently returning 0 (a likely poll deadlock).
                    reporter.record(CompatEvent::partial_syscall(
                        request_number,
                        "ppoll",
                        request_args,
                        "blocked ~60s with no fd ready (possible poll deadlock)",
                    ));
                    break;
                }
            }

            Ok(DispatchOutcome::Returned { value: ready })

        }

        fn socket(this, cx, domain: u64, socket_type: u64, protocol: u64) {

            let family = domain as i32;
            let type_ = socket_type as i32;
            let protocol = protocol as i32;
            // AF_NETLINK has no macOS equivalent, so we can't back it with a
            // host socket. Model a synthetic netlink fd instead (see the
            // `OpenDescription::Netlink` docs) so glibc's __check_pf /
            // getaddrinfo and `ip`/`ss` get a valid fd rather than
            // EAFNOSUPPORT.
            if family == LINUX_AF_NETLINK {
                return Ok(this.netlink_socket(type_, protocol));
            }
            Ok(this.host_socket_install(family, type_, protocol))

        }

        fn socketpair(this, cx, domain: u64, socket_type: u64, protocol: u64, sv: GuestPtr) {

            let memory = &mut *cx.memory;
            let family = domain as i32;
            let type_ = socket_type as i32;
            let protocol = protocol as i32;
            let sv_addr = sv.0;
            let socket_flags = LinuxSocketTypeFlags::from_bits_retain(type_);
            let nonblock = socket_flags.contains(LinuxSocketTypeFlags::NONBLOCK);
            let cloexec = socket_flags.contains(LinuxSocketTypeFlags::CLOEXEC);
            let base_type = type_ & !LinuxSocketTypeFlags::SUPPORTED_MASK;
            let host_family = linux_to_host_af(family);
            let host_type = host_socktype_backing(family, base_type);

            let mut host_fds: [i32; 2] = [-1, -1];
            let rc =
                unsafe { libc::socketpair(host_family, host_type, protocol, host_fds.as_mut_ptr()) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(errno.into());
            }
            set_host_nonblocking(host_fds[0]);
            set_host_nonblocking(host_fds[1]);
            let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
            let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
            let first = OpenFile::with_host_fd(
                Arc::new(RwLock::new(OpenDescription::HostSocket {
                    host_fd: host_fds[0],
                    family,
                    type_: base_type,
                    base: OpenDescriptionBase::new(status_flags),
                })),
                fd_flags,
                host_fds[0],
            );
            let second = OpenFile::with_host_fd(
                Arc::new(RwLock::new(OpenDescription::HostSocket {
                    host_fd: host_fds[1],
                    family,
                    type_: base_type,
                    base: OpenDescriptionBase::new(status_flags),
                })),
                fd_flags,
                host_fds[1],
            );
            let (read_fd, write_fd) = match this.install_fd_pair_at_or_above(3, first, second) {
                Ok(pair) => pair,
                Err(_) => {
                    return Ok(linux_errno::EMFILE.into());
                }
            };
            let pair = LinuxFdPair { read_fd, write_fd };
            if write_kernel_struct_raw(memory, sv_addr, &pair).is_err() {
                let removed = {
                    let mut table = this.io.open_files.write();
                    [table.remove(&read_fd), table.remove(&write_fd)]
                };
                for open_file in removed.into_iter().flatten() {
                    this.close_open_file_and_free_pty(&open_file);
                }
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn bind(this, cx, fd: Fd, addr: GuestPtr, addrlen: u64) {

            let memory = &*cx.memory;
            let fd = fd.0 as i32;
            let addr_addr = addr.0;
            let addrlen = addrlen as u32;
            // AF_NETLINK bind: read the (optional) sockaddr_nl to pick up the
            // requested pid/groups, then assign a pid (the guest's own pid
            // when the caller passed 0, i.e. "let the kernel choose").
            if let Some(open_file) = this.open_file(fd)
                && let OpenDescription::Netlink {
                    pid: nl_pid,
                    groups: nl_groups,
                    ..
                } = &mut *open_file.description.write()
            {
                let (req_pid, req_groups) = read_sockaddr_nl(memory, addr_addr, addrlen);
                *nl_pid = if req_pid != 0 {
                    req_pid
                } else {
                    std::process::id()
                };
                *nl_groups = req_groups;
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let (host_fd, family) = match this.host_socket_lookup(fd) {
                Ok(t) => t,
                Err(errno) => return Ok(errno.into()),
            };
            // AF_UNIX autobind: a bind with only the family (addrlen == 2, empty
            // path) asks the kernel to assign a unique abstract name. macOS has
            // no autobind, so generate the name + a host node and bind there; a
            // later getsockname reverse-translates the host path → the abstract
            // name via the registry.
            if family == libc::AF_UNIX && addrlen <= 2 {
                let host_path = autobind_unix_host_path();
                let p = host_path.to_string_lossy();
                let pb = p.as_bytes();
                if pb.len() >= 104 {
                    return Ok(LINUX_ENAMETOOLONG.into());
                }
                let mut sa = vec![0u8; 2 + pb.len() + 1];
                sa[0] = sa.len().min(255) as u8;
                sa[1] = libc::AF_UNIX as u8;
                sa[2..2 + pb.len()].copy_from_slice(pb);
                // Remove a stale socket node left by a prior run (the generated
                // name is per-process; a leftover host file would be EADDRINUSE),
                // mirroring the pathname unlink-then-bind below.
                if let Ok(md) = std::fs::symlink_metadata(&*p) {
                    use std::os::unix::fs::FileTypeExt;
                    if md.file_type().is_socket() {
                        let _ = std::fs::remove_file(&*p);
                    }
                }
                let rc = unsafe {
                    libc::bind(host_fd, sa.as_ptr() as *const libc::sockaddr, sa.len() as u32)
                };
                return Ok(match rc.host_syscall_errno() {
                    Ok(_) => DispatchOutcome::Returned { value: 0 },
                    Err(errno) => errno.into(),
                });
            }
            // AF_UNIX bind to a directory-like pathname (trailing '/', e.g. "//"
            // = "/") can't hold a socket node on Linux → EADDRINUSE. carrick maps
            // every path to a fresh hashed host node, so without this check it
            // would wrongly succeed (TestProtocolListenError).
            if family == libc::AF_UNIX
                && let Ok(raw) = memory.read_bytes(addr_addr, addrlen as usize)
                && raw.len() > 2
                && raw[2] != 0
            {
                let nul = raw[2..].iter().position(|&b| b == 0).map(|p| 2 + p).unwrap_or(raw.len());
                if raw[..nul].last() == Some(&b'/') {
                    return Ok(linux_errno::EADDRINUSE.into());
                }
            }
            // For an AF_UNIX PATHNAME socket, capture the GUEST sun_path now
            // (while we still hold the memory borrow) so that — after a
            // successful host bind — we can materialise a stat-able S_IFSOCK
            // node at that guest path in the overlay. Linux creates a real
            // socket node on bind; carrick binds the host socket at a HASHED
            // host path, so without this a stat/os.path.exists/chmod/unlink of
            // the guest path is ENOENT (multiprocessing forkserver chmods its
            // listener → crash). Abstract-namespace (leading NUL) and autobind
            // sockets have no fs node, so are excluded.
            let guest_unix_path: Option<String> = if family == libc::AF_UNIX {
                guest_unix_pathname(memory, addr_addr, addrlen)
            } else {
                None
            };
            let resolved_guest_unix_path = if let Some(gp) = &guest_unix_path {
                let resolved = match this.resolve_at_path(LINUX_AT_FDCWD, gp) {
                    Ok(resolved) => resolved,
                    Err(errno) => return Ok(errno.into()),
                };
                let parent = std::path::Path::new(&resolved)
                    .parent()
                    .and_then(|p| p.to_str())
                    .filter(|p| !p.is_empty())
                    .unwrap_or("/");
                match this.layered_metadata(parent) {
                    Ok(md) if md.kind == RootFsEntryKind::Directory => {}
                    Ok(_) => return Ok(LINUX_ENOTDIR.into()),
                    Err(errno) => return Ok(errno.into()),
                }
                if this.layered_lstat(&resolved).is_ok() {
                    return Ok(linux_errno::EADDRINUSE.into());
                }
                Some(resolved)
            } else {
                None
            };
            let host_addr = match read_linux_sockaddr(memory, addr_addr, addrlen, family) {
                Ok(bytes) => bytes,
                Err(errno) => return Ok(errno.into()),
            };
            // AF_UNIX pathname sockets are bound at a stable host path (see
            // unix_socket_host_path). The guest's unlink only tombstones a VFS
            // overlay entry, so it can't clear a real host socket left by a
            // prior run — which would make bind() fail with EADDRINUSE. Mirror
            // Linux's unlink-then-bind by removing a stale *socket* node here
            // before binding (only if it is actually a socket, never a regular
            // file or directory, to stay safe).
            if family == libc::AF_UNIX && host_addr.len() > 2 && host_addr[2] != 0 {
                let path_end = host_addr[2..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| 2 + p)
                    .unwrap_or(host_addr.len());
                if let Ok(path) = std::str::from_utf8(&host_addr[2..path_end])
                    && let Ok(md) = std::fs::symlink_metadata(path)
                {
                    use std::os::unix::fs::FileTypeExt;
                    if md.file_type().is_socket() {
                        let _ = std::fs::remove_file(path);
                    }
                }
            }
            let rc = unsafe {
                libc::bind(
                    host_fd,
                    host_addr.as_ptr() as *const _,
                    host_addr.len() as u32,
                )
            };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(DispatchOutcome::errno(errno));
            }
            // Bind succeeded. Materialise the guest-facing S_IFSOCK node at the
            // resolved guest path. Linux applies the umask to 0o777 for the
            // socket node's permission bits (verified vs Docker: umask 022 →
            // 0o755). Best-effort: a failure here doesn't undo the host bind
            // (the socket still works), it only means stat won't see the node.
            if let Some(resolved) = resolved_guest_unix_path {
                let umask = this.cred_snapshot().umask & 0o777;
                let mode = 0o777 & !umask;
                if let Some(m) = this.fs.vfs_mounts.resolve(&resolved) {
                    let _ = m.vfs.create_socket(&m.full_path, mode);
                } else {
                    let _ = this.fs.rootfs_vfs.overlay.create_socket(&resolved, mode);
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn listen(this, cx, fd: Fd, backlog: u64) {

            let fd: Fd = fd;
            let backlog = backlog as i32;
            let (host_fd, _family) = match this.host_socket_lookup(fd.0) {
                Ok(t) => t,
                Err(errno) => return Ok(errno.into()),
            };
            let rc = unsafe { libc::listen(host_fd, backlog) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(errno.into());
            }
            // A listen socket exists only to accept(2); make the HOST socket
            // non-blocking so accept never blocks under the dispatcher lock — the
            // guest's blocking intent is emulated by blocking_io's WaitOnFds
            // hand-off (the one idiomatic, targeted non-blocking exception; data
            // sockets keep their native mode + per-call MSG_DONTWAIT).
            set_host_nonblocking(host_fd);
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn accept(this, cx, fd: Fd, addr: GuestPtr, addrlen: GuestPtr) {

            Ok(this.accept_common(fd, addr, addrlen, &mut *cx.memory, 0))

        }

        fn accept4(this, cx, fd: Fd, addr: GuestPtr, addrlen: GuestPtr, flags: u64) {

            let flags = flags as i32;
            Ok(this.accept_common(fd, addr, addrlen, &mut *cx.memory, flags))

        }

        fn connect(this, cx, fd: Fd, addr: GuestPtr, addrlen: u64) {

            let memory = &*cx.memory;
            let fd = fd.0 as i32;
            let addr_addr = addr.0;
            let addrlen = addrlen as u32;
            let (host_fd, family) = match this.host_socket_lookup(fd) {
                Ok(t) => t,
                Err(errno) => return Ok(errno.into()),
            };
            let host_addr = match read_linux_sockaddr(memory, addr_addr, addrlen, family) {
                Ok(bytes) => bytes,
                Err(errno) => return Ok(errno.into()),
            };
            // connect(AF_UNSPEC) is the UDP "disconnect" (dissolve the peer
            // association); Linux returns 0. macOS disconnects too but may then
            // report EAFNOSUPPORT/EINVAL — treat those as success below.
            let is_unspec_disconnect = addrlen >= 2
                && memory
                    .read_bytes(addr_addr, 2)
                    .ok()
                    .map(|b| u16::from_ne_bytes([b[0], b[1]]) as i32 == LINUX_AF_UNSPEC)
                    .unwrap_or(false);
            if family == libc::AF_UNIX
                && let Some(gp) = guest_unix_pathname(memory, addr_addr, addrlen)
            {
                let resolved = match this.resolve_at_path(LINUX_AT_FDCWD, &gp) {
                    Ok(resolved) => resolved,
                    Err(errno) => return Ok(errno.into()),
                };
                let parent = std::path::Path::new(&resolved)
                    .parent()
                    .and_then(|p| p.to_str())
                    .filter(|p| !p.is_empty())
                    .unwrap_or("/");
                match this.layered_metadata(parent) {
                    Ok(md) if md.kind == RootFsEntryKind::Directory => {}
                    Ok(_) => return Ok(LINUX_ENOTDIR.into()),
                    Err(errno) => return Ok(errno.into()),
                }
                match this.layered_metadata(&resolved) {
                    Ok(md) if md.kind == RootFsEntryKind::Socket => {}
                    Ok(_) => return Ok(linux_errno::ECONNREFUSED.into()),
                    Err(errno) => return Ok(errno.into()),
                }
            }
            // connect(2) has no per-call non-blocking flag, so put the host socket
            // non-blocking — it then returns EINPROGRESS instead of blocking under
            // the dispatcher lock. recv/send use MSG_DONTWAIT + the guest's intended
            // mode (status_flags), so the host fd's real mode is immaterial.
            let nonblocking = this.io_is_nonblocking(fd, 0);
            set_host_nonblocking(host_fd);
            let rc = unsafe {
                libc::connect(
                    host_fd,
                    host_addr.as_ptr() as *const _,
                    host_addr.len() as u32,
                )
            };
            if rc == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let e = HostSyscallError::last().linux_errno();
            // EISCONN: the connection completed (we're back here via the POLLOUT
            // re-dispatch). Success.
            if e == LINUX_EISCONN {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if e == LINUX_EINPROGRESS || e == LINUX_EALREADY || e == LINUX_EAGAIN {
                if nonblocking {
                    // Non-blocking guest: hand EINPROGRESS/EALREADY straight back.
                    return Ok(e.into());
                }
                // Blocking guest: wait (lock released) for the socket to become
                // writable, then re-dispatch — connect then returns EISCONN or the
                // real connect error.
                return Ok(DispatchOutcome::WaitOnFds {
                    fds: vec![(host_fd, libc::POLLOUT)],
                    timeout: None,
                    on_timeout: -(LINUX_EINPROGRESS as i64),
                    block_signals: 0,
                });
            }
            if is_unspec_disconnect && (e == LINUX_EAFNOSUPPORT || e == LINUX_EINVAL) {
                // macOS already disassociated the UDP socket; Linux returns 0
                // for the AF_UNSPEC disconnect, so report success.
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            Ok(e.into())

        }

        fn getsockname(this, cx, fd: Fd, addr: GuestPtr, addrlen: GuestPtr) {

            let memory = &mut *cx.memory;
            let fd = fd.0 as i32;
            let addr_addr = addr.0;
            let addrlen_addr = addrlen.0;
            // AF_NETLINK getsockname: hand back a sockaddr_nl carrying the
            // bound pid/groups (or pid=0 if the socket was never bound).
            if let Some(open_file) = this.open_file(fd)
                && let OpenDescription::Netlink { pid, groups, .. } = &*open_file.description.read()
            {
                let nl = sockaddr_nl_bytes(*pid, *groups);
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &nl).is_err() {
                    return Ok(LINUX_EFAULT.into());
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let (host_fd, family) = match this.host_socket_lookup(fd) {
                Ok(t) => t,
                Err(errno) => return Ok(errno.into()),
            };
            // getsockname needs both output pointers; a NULL addr or addrlen →
            // EFAULT (getsockname01), checked after the fd validation so a
            // bad/non-socket fd still surfaces EBADF/ENOTSOCK first.
            if addr_addr == 0 || addrlen_addr == 0 {
                return Ok(LINUX_EFAULT.into());
            }
            // A negative input *addrlen → EINVAL (getsockname01); the kernel
            // reads addrlen first and rejects len < 0 before copying out. A bad
            // (unreadable) addrlen pointer surfaces EFAULT via the write below.
            if let Ok(b) = memory.read_bytes(addrlen_addr, 4)
                && i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0
            {
                return Ok(LINUX_EINVAL.into());
            }
            let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
            let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
            let rc =
                unsafe { libc::getsockname(host_fd, sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(errno.into());
            }
            let used = (sa_len as usize).min(sa.len());
            let linux_bytes = host_to_linux_sockaddr(&sa[..used], family, false);
            if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn getpeername(this, cx, fd: Fd, addr: GuestPtr, addrlen: GuestPtr) {

            let memory = &mut *cx.memory;
            let fd = fd.0 as i32;
            let addr_addr = addr.0;
            let addrlen_addr = addrlen.0;
            let (host_fd, family) = match this.host_socket_lookup(fd) {
                Ok(t) => t,
                Err(errno) => return Ok(errno.into()),
            };
            let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
            let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
            let rc =
                unsafe { libc::getpeername(host_fd, sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(errno.into());
            }
            // Connected (the host call succeeded): a NULL addr/addrlen → EFAULT
            // and a negative input *addrlen → EINVAL (symmetric with
            // getsockname; checked after the host call so an unconnected
            // socket's ENOTCONN still wins). getpeername01.
            if addr_addr == 0 || addrlen_addr == 0 {
                return Ok(LINUX_EFAULT.into());
            }
            if let Ok(b) = memory.read_bytes(addrlen_addr, 4)
                && i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0
            {
                return Ok(LINUX_EINVAL.into());
            }
            let used = (sa_len as usize).min(sa.len());
            let linux_bytes = host_to_linux_sockaddr(&sa[..used], family, false);
            if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn sendto(this, cx, fd: Fd, buf: GuestPtr, len: u64, flags: u64, dest_addr: GuestPtr, addrlen: u64) {

            let memory = &*cx.memory;
            let fd = fd.0 as i32;
            let buf_addr = buf.0;
            let len = len as usize;
            let flags = flags as i32;
            let dest_addr = dest_addr.0;
            let dest_len = addrlen as u32;
            // AF_NETLINK send: treat the payload as an rtnetlink request and
            // queue a synthetic dump reply for the next recv.
            if this.fd_is_netlink(fd) {
                let bytes = match memory.read_bytes(buf_addr, len) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(LINUX_EFAULT.into());
                    }
                };
                return Ok(this.netlink_send(fd, &bytes));
            }
            let (host_fd, family) = match this.host_socket_lookup(fd) {
                Ok(t) => t,
                Err(errno) => return Ok(errno.into()),
            };
            let bytes = match memory.read_bytes(buf_addr, len) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Ok(LINUX_EFAULT.into());
                }
            };
            // Read the destination sockaddr (if any) from guest memory up front,
            // then send with MSG_DONTWAIT through blocking_io: a full socket buffer
            // (EAGAIN) on a blocking fd waits for POLLOUT losslessly.
            let host_addr = if dest_addr == 0 {
                None
            } else {
                match read_linux_sockaddr(memory, dest_addr, dest_len, family) {
                    Ok(b) => Some(b),
                    Err(errno) => return Ok(errno.into()),
                }
            };
            let nonblocking = this.io_is_nonblocking(fd, flags);
            let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
            let send_to = this
                .open_file(fd)
                .and_then(|f| f.description.read().send_timeout());
            let outcome = this.blocking_io(host_fd, IoDir::Write, nonblocking, send_to, || {
                let n = match &host_addr {
                    None => unsafe {
                        libc::sendto(
                            host_fd,
                            bytes.as_ptr() as *const _,
                            bytes.len(),
                            host_flags,
                            std::ptr::null(),
                            0,
                        )
                    },
                    Some(a) => unsafe {
                        libc::sendto(
                            host_fd,
                            bytes.as_ptr() as *const _,
                            bytes.len(),
                            host_flags,
                            a.as_ptr() as *const _,
                            a.len() as u32,
                        )
                    },
                };
                n.host_syscall_errno().map(|value| value as i64)
            });
            Ok(outcome)

        }

        fn recvfrom(this, cx, fd: Fd, buf: GuestPtr, len: u64, flags: u64, src_addr: GuestPtr, addrlen: GuestPtr) {

            let memory = &mut *cx.memory;
            let fd = fd.0 as i32;
            let buf_addr = buf.0;
            let len = len as usize;
            let flags = flags as i32;
            let src_addr = src_addr.0;
            let src_len_addr = addrlen.0;
            // AF_NETLINK recv: drain the queued dump reply. The source address
            // (if requested) is the kernel: sockaddr_nl with pid=0.
            if this.fd_is_netlink(fd) {
                let drained = this.netlink_recv(fd, buf_addr, len, memory);
                if let DispatchOutcome::Returned { .. } = drained
                    && src_addr != 0
                    && src_len_addr != 0
                {
                    let nl = sockaddr_nl_bytes(0, 0);
                    let _ = write_linux_sockaddr(memory, src_addr, src_len_addr, &nl);
                }
                return Ok(drained);
            }
            let (host_fd, family) = match this.host_socket_lookup(fd) {
                Ok(t) => t,
                Err(errno) => return Ok(errno.into()),
            };
            // MSG_ERRQUEUE reads the socket's error queue. carrick keeps no
            // error queue, so it's always empty → EAGAIN (recv01/recvfrom01),
            // matching Linux when no error is queued. Checked after the socket
            // lookup so a bad/non-socket fd still surfaces EBADF/ENOTSOCK.
            const LINUX_MSG_ERRQUEUE: i32 = 0x2000;
            if flags & LINUX_MSG_ERRQUEUE != 0 {
                return Ok(LINUX_EAGAIN.into());
            }
            // Native fd mode preserved; force this CALL non-blocking with
            // MSG_DONTWAIT and route through blocking_io: on EAGAIN a blocking-mode
            // guest fd waits losslessly (kqueue, lock released), a non-blocking one
            // gets EAGAIN. Never blocks under the dispatcher lock.
            let nonblocking = this.io_is_nonblocking(fd, flags);
            let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
            let len = len.min(crate::dispatch::MAX_RW_COUNT);
            let mut buf = vec![0u8; len];
            let recv_to = this
                .open_file(fd)
                .and_then(|f| f.description.read().recv_timeout());
            let outcome = this.blocking_io(host_fd, IoDir::Read, nonblocking, recv_to, || {
                let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
                let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
                let (n, used_addr) = if src_addr == 0 {
                    (
                        unsafe {
                            libc::recvfrom(
                                host_fd,
                                buf.as_mut_ptr() as *mut _,
                                buf.len(),
                                host_flags,
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                            )
                        },
                        false,
                    )
                } else {
                    (
                        unsafe {
                            libc::recvfrom(
                                host_fd,
                                buf.as_mut_ptr() as *mut _,
                                buf.len(),
                                host_flags,
                                sa.as_mut_ptr() as *mut _,
                                &mut sa_len as *mut _,
                            )
                        },
                        true,
                    )
                };
                let n = n.host_syscall_errno()?;
                if n > 0 && memory.write_bytes(buf_addr, &buf[..n as usize]).is_err() {
                    return Err(LINUX_EFAULT);
                }
                if used_addr && src_addr != 0 && src_len_addr != 0 {
                    let used = (sa_len as usize).min(sa.len());
                    let linux_bytes = host_to_linux_sockaddr(&sa[..used], family, true);
                    if write_linux_sockaddr(memory, src_addr, src_len_addr, &linux_bytes).is_err() {
                        return Err(LINUX_EFAULT);
                    }
                }
                Ok(n as i64)
            });
            Ok(outcome)

        }

        fn setsockopt(this, cx, fd: Fd, level: u64, optname: u64, optval: GuestPtr, optlen: u64) {

            let memory = &*cx.memory;
            let fd = fd.0 as i32;
            let level = level as i32;
            let optname = optname as i32;
            let optval_addr = optval.0;
            let optlen = optlen as u32;
            // AF_NETLINK setsockopt: glibc/`ip` set SO_RCVBUF / SO_SNDBUF and
            // netlink-specific options (NETLINK_*). We don't model buffer
            // pressure, so just accept them.
            if this.fd_is_netlink(fd) {
                let _ = (level, optname, optval_addr, optlen);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let (host_fd, _family) = match this.host_socket_lookup(fd) {
                Ok(t) => t,
                Err(errno) => return Ok(errno.into()),
            };
            // SO_RCVTIMEO/SO_SNDTIMEO: the host fd is ALWAYS O_NONBLOCK (the
            // blocking_io invariant), so a host-side timeval is dead. Store the
            // timeout per open-file-description and let blocking_io thread it
            // into the WaitOnFds. Intercept BEFORE the host passthrough.
            if level == LINUX_SOL_SOCKET
                && (optname == LINUX_SO_RCVTIMEO || optname == LINUX_SO_SNDTIMEO)
            {
                // aarch64 SO_RCVTIMEO/SO_SNDTIMEO use `struct __kernel_old_timeval`
                // = two i64 (tv_sec, tv_usec) = 16 bytes.
                let dur = if optval_addr == 0 || optlen < 16 {
                    None
                } else {
                    match memory.read_bytes(optval_addr, 16) {
                        Ok(b) => {
                            let sec = i64::from_ne_bytes([
                                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                            ]);
                            let usec = i64::from_ne_bytes([
                                b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
                            ]);
                            // {0,0} disables the timeout (block forever).
                            if sec <= 0 && usec <= 0 {
                                None
                            } else {
                                Some(std::time::Duration::new(
                                    sec.max(0) as u64,
                                    (usec.max(0) as u32).saturating_mul(1000),
                                ))
                            }
                        }
                        Err(_) => return Ok(LINUX_EFAULT.into()),
                    }
                };
                if let Some(open_file) = this.open_file(fd) {
                    let mut open = open_file.description.write();
                    if let OpenDescription::HostSocket { base, .. } = &mut *open {
                        if optname == LINUX_SO_RCVTIMEO {
                            base.set_recv_timeout(dur);
                        } else {
                            base.set_send_timeout(dur);
                        }
                    }
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // macOS BSD SO_REUSEADDR does NOT let two UDP sockets share a
            // wildcard addr/port the way Linux does — that needs SO_REUSEPORT on
            // macOS. libuv's UV_UDP_REUSEADDR sets ONLY SO_REUSEADDR (before
            // bind) and expects two 0.0.0.0:PORT UDP binds to both succeed
            // (udp_bind_reuseaddr, watcher_cross_stop). Widen REUSEADDR ->
            // REUSEPORT for datagram sockets so the macOS kernel matches Linux;
            // the existing passthrough below still sets host SO_REUSEADDR so a
            // later getsockopt reports the value the guest set.
            if level == LINUX_SOL_SOCKET
                && optname == LINUX_SO_REUSEADDR
                && this.socket_guest_type(fd) == Some(LINUX_SOCK_DGRAM)
            {
                let enable = optlen >= 4
                    && memory
                        .read_bytes(optval_addr, 4)
                        .ok()
                        .map(|b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) != 0)
                        .unwrap_or(false);
                if enable {
                    let one: i32 = 1;
                    unsafe {
                        libc::setsockopt(
                            host_fd,
                            libc::SOL_SOCKET,
                            libc::SO_REUSEPORT,
                            &one as *const i32 as *const libc::c_void,
                            std::mem::size_of::<i32>() as u32,
                        );
                    }
                }
            }
            let (host_level, host_opt) = match linux_to_host_sockopt(level, optname) {
                Some(t) => t,
                None => {
                    return Ok(LINUX_ENOPROTOOPT.into());
                }
            };
            let bytes = if optval_addr == 0 || optlen == 0 {
                Vec::new()
            } else {
                match memory.read_bytes(optval_addr, optlen as usize) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(LINUX_EFAULT.into());
                    }
                }
            };
            let rc = unsafe {
                libc::setsockopt(
                    host_fd,
                    host_level,
                    host_opt,
                    if bytes.is_empty() {
                        std::ptr::null()
                    } else {
                        bytes.as_ptr() as *const _
                    },
                    bytes.len() as u32,
                )
            };
            Ok(if let Err(errno) = rc.host_syscall_errno() {
                // Linux apps frequently set options that aren't supported on
                // macOS (eg IP_MTU_DISCOVER); swallow ENOPROTOOPT silently
                // when the equivalent option simply doesn't exist on macOS.
                DispatchOutcome::errno(errno)
            } else {
                DispatchOutcome::Returned { value: 0 }
            })

        }

        fn getsockopt(this, cx, fd: Fd, level: u64, optname: u64, optval: GuestPtr, optlen: GuestPtr) {

            let memory = &mut *cx.memory;
            let fd = fd.0 as i32;
            let level = level as i32;
            let optname = optname as i32;
            let optval_addr = optval.0;
            let optlen_addr = optlen.0;
            // AF_NETLINK getsockopt: answer the common SO_TYPE query (callers
            // verify the socket is SOCK_RAW); everything else returns 0.
            if this.fd_is_netlink(fd) {
                let val: i32 = if level == LINUX_SOL_SOCKET && optname == LINUX_SO_TYPE {
                    LINUX_SOCK_RAW
                } else {
                    0
                };
                let _ = memory.write_bytes(optval_addr, &val.to_ne_bytes());
                let _ = memory.write_bytes(optlen_addr, &4u32.to_ne_bytes());
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // SO_TYPE must report the GUEST-requested type, not the host backing:
            // a guest AF_UNIX SOCK_SEQPACKET is backed by a host SOCK_STREAM, but
            // Go derives the network ("unixpacket") from SO_TYPE, so the host's
            // STREAM answer would mislabel the socket.
            if level == LINUX_SOL_SOCKET && optname == LINUX_SO_TYPE {
                if let Some(t) = this.socket_guest_type(fd) {
                    let _ = memory.write_bytes(optval_addr, &t.to_ne_bytes());
                    let _ = memory.write_bytes(optlen_addr, &4u32.to_ne_bytes());
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
            }
            // SO_DOMAIN / SO_PROTOCOL are Linux-only getsockopt options with no
            // macOS equivalent (the generic host path would ENOPROTOOPT). Answer
            // from carrick's per-fd bookkeeping. CPython's
            // `socket.socket(fileno=fd)` queries SO_PROTOCOL to reconstruct an
            // inherited socket (the multiprocessing forkserver path); without
            // this it raised OSError(ENOPROTOOPT) and the forkserver child died.
            // SO_DOMAIN → the guest address family (stored as the Linux value at
            // socket() time). SO_PROTOCOL → 0 (the default/unspecified protocol,
            // exactly what Linux reports for AF_UNIX and a default AF_INET TCP/UDP
            // socket, which is what the forkserver reconstruct expects).
            if level == LINUX_SOL_SOCKET
                && (optname == crate::linux_abi::LINUX_SO_DOMAIN
                    || optname == crate::linux_abi::LINUX_SO_PROTOCOL)
            {
                let (_host_fd, family) = match this.host_socket_lookup(fd) {
                    Ok(t) => t,
                    Err(errno) => return Ok(errno.into()),
                };
                let val: i32 = if optname == crate::linux_abi::LINUX_SO_DOMAIN {
                    family
                } else {
                    0
                };
                // Honor the guest's optlen (it offers 4; clamp defensively).
                let guest_optlen = match memory.read_bytes(optlen_addr, 4) {
                    Ok(b) => u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
                    Err(_) => return Ok(LINUX_EFAULT.into()),
                };
                let bytes = val.to_ne_bytes();
                let n = (guest_optlen as usize).min(bytes.len());
                if optval_addr != 0
                    && n > 0
                    && memory.write_bytes(optval_addr, &bytes[..n]).is_err()
                {
                    return Ok(LINUX_EFAULT.into());
                }
                if memory
                    .write_bytes(optlen_addr, &(n as u32).to_ne_bytes())
                    .is_err()
                {
                    return Ok(LINUX_EFAULT.into());
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // SO_RCVTIMEO/SO_SNDTIMEO readback: the set side stores these per
            // open-file-description and bypasses the (dead) host fd, so the
            // generic path below would read back {0,0}. Answer from the stored
            // Option<Duration> as a 16-byte two-i64 timeval. If the fd is not a
            // HostSocket, fall through to the generic path.
            if level == LINUX_SOL_SOCKET
                && (optname == LINUX_SO_RCVTIMEO || optname == LINUX_SO_SNDTIMEO)
            {
                let mut handled = false;
                let mut dur: Option<std::time::Duration> = None;
                if let Some(open_file) = this.open_file(fd) {
                    if let OpenDescription::HostSocket { base, .. } = &*open_file.description.read() {
                        handled = true;
                        dur = if optname == LINUX_SO_RCVTIMEO {
                            base.recv_timeout()
                        } else {
                            base.send_timeout()
                        };
                    }
                }
                if handled {
                    let tv_sec = dur.map(|d| d.as_secs() as i64).unwrap_or(0);
                    let tv_usec = dur.map(|d| d.subsec_micros() as i64).unwrap_or(0);
                    let mut tv_bytes = [0u8; 16];
                    tv_bytes[0..8].copy_from_slice(&tv_sec.to_ne_bytes());
                    tv_bytes[8..16].copy_from_slice(&tv_usec.to_ne_bytes());
                    let guest_optlen = match memory.read_bytes(optlen_addr, 4) {
                        Ok(b) => u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
                        Err(_) => return Ok(LINUX_EFAULT.into()),
                    };
                    let n = (guest_optlen as usize).min(16);
                    if optval_addr != 0
                        && n > 0
                        && memory.write_bytes(optval_addr, &tv_bytes[..n]).is_err()
                    {
                        return Ok(LINUX_EFAULT.into());
                    }
                    if memory
                        .write_bytes(optlen_addr, &(n as u32).to_ne_bytes())
                        .is_err()
                    {
                        return Ok(LINUX_EFAULT.into());
                    }
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
            }
            // SO_PEERCRED: Linux returns `struct ucred { pid, uid, gid }`. macOS
            // has no single equivalent, so synthesize it from LOCAL_PEERCRED
            // (peer uid + primary gid via `xucred`) and LOCAL_PEERPID (peer pid).
            // Used by D-Bus / systemd peer authentication over AF_UNIX. Done here
            // because `linux_to_host_sockopt` has no Darwin opt to map it to.
            if level == LINUX_SOL_SOCKET && optname == crate::linux_abi::LINUX_SO_PEERCRED {
                let (host_fd, _family) = match this.host_socket_lookup(fd) {
                    Ok(t) => t,
                    Err(errno) => return Ok(errno.into()),
                };
                let mut xucred: libc::xucred = unsafe { std::mem::zeroed() };
                let mut xlen = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
                let cred_rc = unsafe {
                    libc::getsockopt(
                        host_fd,
                        libc::SOL_LOCAL,
                        libc::LOCAL_PEERCRED,
                        (&mut xucred as *mut libc::xucred).cast(),
                        &mut xlen,
                    )
                };
                if let Err(errno) = cred_rc.host_syscall_errno() {
                    return Ok(errno.into());
                }
                // Peer pid is a separate Darwin option; best-effort (0 if absent).
                let mut peer_pid: libc::pid_t = 0;
                let mut plen = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
                let pid: u32 = if unsafe {
                    libc::getsockopt(
                        host_fd,
                        libc::SOL_LOCAL,
                        libc::LOCAL_PEERPID,
                        (&mut peer_pid as *mut libc::pid_t).cast(),
                        &mut plen,
                    )
                } == 0
                {
                    peer_pid as u32
                } else {
                    0
                };
                let gid = xucred.cr_groups.first().copied().unwrap_or(0);
                let mut ucred = [0u8; crate::linux_abi::LINUX_UCRED_SIZE];
                ucred[0..4].copy_from_slice(&pid.to_ne_bytes());
                ucred[4..8].copy_from_slice(&(xucred.cr_uid).to_ne_bytes());
                ucred[8..12].copy_from_slice(&gid.to_ne_bytes());
                // Honor the guest's optlen: write at most what it offered and
                // report the bytes actually written (Linux clamps to the buffer).
                let guest_optlen = match memory.read_bytes(optlen_addr, 4) {
                    Ok(b) => u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
                    Err(_) => return Ok(LINUX_EFAULT.into()),
                };
                let n = (guest_optlen as usize).min(crate::linux_abi::LINUX_UCRED_SIZE);
                if optval_addr != 0
                    && n > 0
                    && memory.write_bytes(optval_addr, &ucred[..n]).is_err()
                {
                    return Ok(LINUX_EFAULT.into());
                }
                if memory
                    .write_bytes(optlen_addr, &(n as u32).to_ne_bytes())
                    .is_err()
                {
                    return Ok(LINUX_EFAULT.into());
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let (host_fd, _family) = match this.host_socket_lookup(fd) {
                Ok(t) => t,
                Err(errno) => return Ok(errno.into()),
            };
            // SO_ERROR: the option VALUE is itself an errno (the pending socket
            // error, e.g. from an async connect). The host returns a Darwin
            // errno; the guest reads it as a Linux errno. Without translation a
            // refused connect surfaces as Darwin ECONNREFUSED=61, which Linux
            // reads as ENODATA — so asyncio's sock_connect never raises
            // ConnectionRefusedError. Translate the i32 value through the same
            // table the rest of the ABI uses. (getsockopt itself still
            // succeeds; only the value is mapped.)
            if level == LINUX_SOL_SOCKET && optname == LINUX_SO_ERROR {
                let mut host_err: i32 = 0;
                let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
                let rc = unsafe {
                    libc::getsockopt(
                        host_fd,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        (&mut host_err as *mut i32).cast(),
                        &mut len,
                    )
                };
                if let Err(errno) = rc.host_syscall_errno() {
                    return Ok(errno.into());
                }
                let linux_err = if host_err == 0 {
                    0
                } else {
                    crate::dispatch::macos_to_linux_errno(host_err)
                };
                // Honor the guest's optlen (it may pass <4); clamp like Linux.
                let guest_optlen = match memory.read_bytes(optlen_addr, 4) {
                    Ok(b) => u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
                    Err(_) => return Ok(LINUX_EFAULT.into()),
                };
                let n = (guest_optlen as usize).min(4);
                let bytes = linux_err.to_ne_bytes();
                if optval_addr != 0
                    && n > 0
                    && memory.write_bytes(optval_addr, &bytes[..n]).is_err()
                {
                    return Ok(LINUX_EFAULT.into());
                }
                if memory
                    .write_bytes(optlen_addr, &(n as u32).to_ne_bytes())
                    .is_err()
                {
                    return Ok(LINUX_EFAULT.into());
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let (host_level, host_opt) = match linux_to_host_sockopt(level, optname) {
                Some(t) => t,
                None => {
                    return Ok(LINUX_ENOPROTOOPT.into());
                }
            };
            // Read the guest's reported optlen so we don't overflow.
            let optlen_bytes = match memory.read_bytes(optlen_addr, 4) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(LINUX_EFAULT.into());
                }
            };
            let mut optlen = u32::from_ne_bytes([
                optlen_bytes[0],
                optlen_bytes[1],
                optlen_bytes[2],
                optlen_bytes[3],
            ]);
            let cap = optlen.min(256) as usize;
            let mut buf = vec![0u8; cap];
            let rc = unsafe {
                libc::getsockopt(
                    host_fd,
                    host_level,
                    host_opt,
                    buf.as_mut_ptr() as *mut _,
                    &mut optlen as *mut _,
                )
            };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(errno.into());
            }
            let used = (optlen as usize).min(buf.len());
            if optval_addr != 0 && used > 0 && memory.write_bytes(optval_addr, &buf[..used]).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            if memory
                .write_bytes(optlen_addr, &optlen.to_ne_bytes())
                .is_err()
            {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn shutdown(this, cx, fd: Fd, how: u64) {

            let fd: Fd = fd;
            let how = how as i32;
            let (host_fd, _family) = match this.host_socket_lookup(fd.0) {
                Ok(t) => t,
                Err(errno) => return Ok(errno.into()),
            };
            let rc = unsafe { libc::shutdown(host_fd, how) };
            Ok(if let Err(errno) = rc.host_syscall_errno() {
                DispatchOutcome::errno(errno)
            } else {
                DispatchOutcome::Returned { value: 0 }
            })

        }

        fn sendmsg(this, cx, fd: Fd, msg: GuestPtr, flags: u64) {
            this.sendmsg_inner(fd.0, msg.0, flags as i32, &*cx.memory)
        }

        fn recvmsg(this, cx, fd: Fd, msg: GuestPtr, flags: u64) {
            this.recvmsg_inner(fd.0, msg.0, flags as i32, &mut *cx.memory)
        }

        fn sys_recvmmsg(this, cx, fd: Fd, mmsg: GuestPtr, vlen: u64, flags: u64, timeout: GuestPtr) {

            Ok(this.recvmmsg(fd, mmsg, vlen, flags, timeout, cx.memory))

        }

        fn sys_sendmmsg(this, cx, fd: Fd, mmsg: GuestPtr, vlen: u64, flags: u64) {

            Ok(this.sendmmsg(fd, mmsg, vlen, flags, cx.memory))

        }

    }
}

impl SyscallDispatcher {
    fn sendmsg_inner(
        &self,
        fd: i32,
        msg_addr: u64,
        flags: i32,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let is_netlink = self.fd_is_netlink(fd);
        let (host_fd, family) = if is_netlink {
            (-1, LINUX_AF_NETLINK)
        } else {
            match self.host_socket_lookup(fd) {
                Ok(t) => t,
                Err(errno) => return Ok(errno.into()),
            }
        };
        let msg = match read_linux_msghdr(memory, msg_addr) {
            Ok(m) => m,
            Err(errno) => return Ok(errno.into()),
        };
        let iovecs = match read_iovecs(memory, msg.iov, msg.iovlen as usize) {
            Ok(v) => v,
            Err(errno) => return Ok(errno.into()),
        };
        // Pack iovecs into a single contiguous send. Simple and avoids
        // having to keep guest pointers alive across the FFI call.
        let mut data = Vec::new();
        for iov in iovecs {
            let chunk = match memory.read_bytes(iov.iov_base, iov.iov_len as usize) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(LINUX_EFAULT.into());
                }
            };
            data.extend_from_slice(&chunk);
        }
        // AF_NETLINK: parse the assembled request and queue a synthetic
        // dump reply, ignoring the destination sockaddr (always the kernel).
        if is_netlink {
            return Ok(self.netlink_send(fd, &data));
        }
        let host_addr = if msg.name == 0 || msg.namelen == 0 {
            None
        } else {
            match read_linux_sockaddr(memory, msg.name, msg.namelen, family) {
                Ok(b) => Some(b),
                Err(errno) => return Ok(errno.into()),
            }
        };
        // SCM_RIGHTS ancillary data (passing fds over AF_UNIX). Read the guest's
        // Linux-layout control buffer, extract the guest fds, map each to its
        // backing host fd, and build a host-layout control buffer for the real
        // sendmsg. This is the multiprocessing forkserver's fd-handoff path.
        let mut host_control: Vec<u8> = Vec::new();
        if msg.control != 0 && msg.controllen > 0 {
            let raw = match memory.read_bytes(msg.control, msg.controllen as usize) {
                Ok(b) => b,
                Err(_) => return Ok(LINUX_EFAULT.into()),
            };
            let guest_fds = parse_linux_scm_rights_fds(&raw);
            if !guest_fds.is_empty() {
                let mut host_fds = Vec::with_capacity(guest_fds.len());
                for gfd in &guest_fds {
                    match self.host_fd_for_scm(*gfd) {
                        Some(h) => host_fds.push(h),
                        // A passed fd with no backing host fd can't cross the
                        // socket → EBADF, matching Linux's rejection of an
                        // invalid fd in an SCM_RIGHTS array.
                        None => return Ok(LINUX_EBADF.into()),
                    }
                }
                host_control = build_host_scm_rights(&host_fds);
            }
        }
        let nonblocking = self.io_is_nonblocking(fd, flags);
        let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
        let send_to = self
            .open_file(fd)
            .and_then(|f| f.description.read().send_timeout());
        let outcome = self.blocking_io(host_fd, IoDir::Write, nonblocking, send_to, || {
            // Use a real sendmsg so the host control buffer (SCM_RIGHTS) is
            // delivered. A single iovec over the assembled `data` is fine —
            // the byte stream is identical to the guest's scattered iovecs.
            let mut hiov = libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            };
            let mut hmsg: libc::msghdr = unsafe { std::mem::zeroed() };
            if let Some(a) = &host_addr {
                hmsg.msg_name = a.as_ptr() as *mut libc::c_void;
                hmsg.msg_namelen = a.len() as libc::socklen_t;
            }
            hmsg.msg_iov = &mut hiov as *mut _;
            hmsg.msg_iovlen = 1;
            if !host_control.is_empty() {
                hmsg.msg_control = host_control.as_ptr() as *mut libc::c_void;
                hmsg.msg_controllen = host_control.len() as _;
            }
            let n = unsafe { libc::sendmsg(host_fd, &hmsg as *const _, host_flags) };
            n.host_syscall_errno().map(|value| value as i64)
        });
        Ok(outcome)
    }

    fn recvmsg_inner(
        &self,
        fd: i32,
        msg_addr: u64,
        flags: i32,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let is_netlink = self.fd_is_netlink(fd);
        let (host_fd, family) = if is_netlink {
            (-1, LINUX_AF_NETLINK)
        } else {
            match self.host_socket_lookup(fd) {
                Ok(t) => t,
                Err(errno) => return Ok(errno.into()),
            }
        };
        let msg = match read_linux_msghdr(memory, msg_addr) {
            Ok(m) => m,
            Err(errno) => return Ok(errno.into()),
        };
        let iovecs = match read_iovecs(memory, msg.iov, msg.iovlen as usize) {
            Ok(v) => v,
            Err(errno) => return Ok(errno.into()),
        };
        // AF_NETLINK: drain the queued dump reply into the iovecs, fill in
        // the source sockaddr_nl (kernel; pid=0), and zero controllen/flags.
        if is_netlink {
            let total: usize = iovecs.iter().map(|iov| iov.iov_len as usize).sum();
            let chunk = self.netlink_drain(fd, total);
            let n = chunk.len();
            let mut remaining = n;
            let mut cursor = 0usize;
            for iov in &iovecs {
                if remaining == 0 {
                    break;
                }
                let take = remaining.min(iov.iov_len as usize);
                if take > 0 {
                    if memory
                        .write_bytes(iov.iov_base, &chunk[cursor..cursor + take])
                        .is_err()
                    {
                        return Ok(LINUX_EFAULT.into());
                    }
                    cursor += take;
                    remaining -= take;
                }
            }
            if msg.name != 0 && msg.namelen != 0 {
                let nl = sockaddr_nl_bytes(0, 0);
                let write_len = (nl.len() as u32).min(msg.namelen);
                if write_len > 0
                    && memory
                        .write_bytes(msg.name, &nl[..write_len as usize])
                        .is_err()
                {
                    return Ok(LINUX_EFAULT.into());
                }
                let _ = memory.write_bytes(msg_addr + 8, &(nl.len() as u32).to_ne_bytes());
            }
            let _ = memory.write_bytes(msg_addr + 40, &0u64.to_ne_bytes());
            let _ = memory.write_bytes(msg_addr + 48, &0i32.to_ne_bytes());
            return Ok(DispatchOutcome::Returned { value: n as i64 });
        }
        let total: usize = iovecs.iter().map(|iov| iov.iov_len as usize).sum();
        let nonblocking = self.io_is_nonblocking(fd, flags);
        let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
        let recv_to = self
            .open_file(fd)
            .and_then(|f| f.description.read().recv_timeout());
        let want_control = msg.control != 0 && msg.controllen > 0;
        // SCM_RIGHTS host fds received this call, ferried out of the I/O closure
        // (which may run on a retry) so they're installed/written-back exactly
        // once after a successful recvmsg. Same for the guest msg_flags.
        let received_host_fds = std::cell::RefCell::new(Vec::<i32>::new());
        let guest_msg_flags = std::cell::Cell::new(0i32);
        let outcome = self.blocking_io(host_fd, IoDir::Read, nonblocking, recv_to, || {
            // A retry must not leak fds from a prior partial attempt.
            for stale in received_host_fds.borrow_mut().drain(..) {
                unsafe { libc::close(stale) };
            }
            let mut buf = vec![0u8; total];
            let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
            // A host control buffer sized to hold the guest's requested
            // controllen (SCM_RIGHTS fd array). CMSG_SPACE for that many fds is
            // >= the Linux size, so this never under-provisions.
            let mut hcontrol: Vec<u8> = if want_control {
                let max_fds = (msg.controllen as usize / 4).max(1);
                vec![0u8; unsafe { libc::CMSG_SPACE((max_fds * 4) as u32) } as usize]
            } else {
                Vec::new()
            };
            // Use the host recvmsg (not recvfrom) so the kernel can report
            // MSG_TRUNC/MSG_CTRUNC/MSG_EOR in the returned msg_flags. macOS/XNU
            // sets MSG_TRUNC on truncated atomic (PR_ATOMIC) records exactly
            // like Linux, so translating those flags back is a faithful match.
            let mut hiov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut _,
                iov_len: buf.len(),
            };
            let mut hmsg: libc::msghdr = unsafe { std::mem::zeroed() };
            if msg.name != 0 {
                hmsg.msg_name = sa.as_mut_ptr() as *mut _;
                hmsg.msg_namelen = sa.len() as libc::socklen_t;
            }
            hmsg.msg_iov = &mut hiov as *mut _;
            hmsg.msg_iovlen = 1; // c_int on macOS
            if !hcontrol.is_empty() {
                hmsg.msg_control = hcontrol.as_mut_ptr() as *mut libc::c_void;
                hmsg.msg_controllen = hcontrol.len() as _;
            }
            let n = unsafe { libc::recvmsg(host_fd, &mut hmsg as *mut _, host_flags) };
            let n = n.host_syscall_errno()?;
            // Stash any received fds (host-layout cmsg) for installation after
            // the closure returns; the guest-facing rewrite happens below.
            if want_control && hmsg.msg_controllen as usize > 0 {
                let got = parse_host_scm_rights_fds(&hcontrol, hmsg.msg_controllen as usize);
                *received_host_fds.borrow_mut() = got;
            }
            // Scatter the received bytes back into the guest's iovecs.
            let mut remaining = n as usize;
            let mut cursor = 0usize;
            for iov in &iovecs {
                if remaining == 0 {
                    break;
                }
                let chunk = remaining.min(iov.iov_len as usize);
                if chunk > 0 {
                    if memory
                        .write_bytes(iov.iov_base, &buf[cursor..cursor + chunk])
                        .is_err()
                    {
                        return Err(LINUX_EFAULT);
                    }
                    cursor += chunk;
                    remaining -= chunk;
                }
            }
            if msg.name != 0 && msg.namelen != 0 {
                let used = (hmsg.msg_namelen as usize).min(sa.len());
                let linux_bytes = host_to_linux_sockaddr(&sa[..used], family, true);
                let write_len = (linux_bytes.len() as u32).min(msg.namelen);
                if write_len > 0
                    && memory
                        .write_bytes(msg.name, &linux_bytes[..write_len as usize])
                        .is_err()
                {
                    return Err(LINUX_EFAULT);
                }
                // namelen lives at offset 8 (after the 8-byte name pointer).
                if memory
                    .write_bytes(msg_addr + 8, &(linux_bytes.len() as u32).to_ne_bytes())
                    .is_err()
                {
                    return Err(LINUX_EFAULT);
                }
            }
            // Remember the host msg_flags; the guest controllen + final flags
            // (incl. a possible MSG_CTRUNC) are written after fd install below.
            guest_msg_flags.set(host_to_linux_msg_flags(hmsg.msg_flags));
            Ok(n as i64)
        });
        // Install any received fds as fresh guest fds, then write the guest
        // (Linux-layout) control buffer + the controllen/flags fields. Done
        // OUTSIDE the I/O closure so it happens exactly once on success.
        let host_fds: Vec<i32> = received_host_fds.borrow_mut().drain(..).collect();
        if matches!(outcome, DispatchOutcome::Returned { value } if value >= 0) {
            let mut guest_fds = Vec::with_capacity(host_fds.len());
            for hfd in host_fds {
                match self.install_received_host_fd(hfd) {
                    Some(gfd) => guest_fds.push(gfd),
                    None => unsafe {
                        libc::close(hfd);
                    },
                }
            }
            let mut linux_flags = guest_msg_flags.get();
            let mut written_controllen = 0u64;
            if want_control {
                let (ctrl, truncated) = build_linux_scm_rights(&guest_fds, msg.controllen as usize);
                if !ctrl.is_empty() && memory.write_bytes(msg.control, &ctrl).is_err() {
                    return Ok(LINUX_EFAULT.into());
                }
                written_controllen = ctrl.len() as u64;
                if truncated {
                    linux_flags |= crate::linux_abi::LINUX_MSG_CTRUNC as i32;
                }
            }
            // controllen at offset 40, flags at offset 48 in LinuxMsghdr.
            let _ = memory.write_bytes(msg_addr + 40, &written_controllen.to_ne_bytes());
            let _ = memory.write_bytes(msg_addr + 48, &linux_flags.to_ne_bytes());
        } else {
            // Error/would-block: nothing received, so close any stray fds and
            // leave the guest msghdr's controllen/flags zeroed.
            for hfd in host_fds {
                unsafe { libc::close(hfd) };
            }
        }
        Ok(outcome)
    }
}
