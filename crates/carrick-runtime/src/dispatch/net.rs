//! Networking and readiness syscalls: BSD sockets, AF_NETLINK synthesis, the
//! `epoll`→`kqueue` shim, and `select`/`poll`/`pselect`/`ppoll`.
//!
//! # Theory of operation
//!
//! Two very different Linux subsystems share this file because they share one
//! fact: macOS already has a real, native implementation underneath, so the job
//! is *translation*, not *emulation*.
//!
//! ## Sockets: native BSD, translated at the edges
//!
//! AF_INET / AF_INET6 / AF_UNIX sockets are backed by REAL host sockets — the
//! guest's `socket(2)` becomes a host `socket(2)`, `connect`/`send`/`recv` flow
//! to the Darwin kernel, and a Linux server under carrick is reachable from the
//! macOS host (the web-server demo). Darwin and Linux agree on the numeric
//! socket *types* (1=STREAM, 2=DGRAM, …) but NOT on much else, so the handlers
//! translate at three boundaries:
//!
//!   - **Address families** (`linux_to_host_af` / `host_to_linux_af` in the
//!     `support` submodule). The shapes that exist on both sides map 1:1; Linux-only
//!     families (AF_PACKET) are passed through so the host `socket()` returns
//!     EAFNOSUPPORT naturally rather than carrick faking an error.
//!   - **`struct sockaddr`** (`read_linux_sockaddr` parses guest → host;
//!     `host_to_linux_sockaddr` / `write_linux_sockaddr` go the other way).
//!     AF_INET/INET6 differ only in the leading `sa_family` byte/halfword;
//!     AF_UNIX is the hard case (below).
//!   - **Buffer sizing and option semantics**: macOS gives an AF_UNIX stream
//!     socket only an 8 KiB buffer where Linux gives 212992, which strands a
//!     guest writer that fills its socket buffer expecting a non-blocking-style
//!     completion (`widen_stream_socket_buffers`); SEQPACKET has no macOS AF_UNIX
//!     backing and is framed on top of a STREAM socket
//!     (`host_socktype_backing`).
//!
//! AF_UNIX carries its own emulation layer (path hashing + a process-global
//! registry, abstract namespace, autobind, SEQPACKET framing) so that Linux
//! AF_UNIX features macOS lacks still work; that machinery lives in the
//! `support` submodule and is documented there.
//!
//! ## AF_NETLINK: there is no host netlink, so synthesise it
//!
//! macOS has no AF_NETLINK. Returning EAFNOSUPPORT is not acceptable: glibc's
//! `__check_pf`/`getaddrinfo` opens an `NETLINK_ROUTE` socket on the way to
//! every name resolution, and `ip`/`ss` are pure rtnetlink clients. So a netlink
//! `socket()` returns a SYNTHETIC fd (`OpenDescription::Netlink`) with NO host
//! backing — a userspace in-memory recv queue plus a remembered `(pid, groups)`
//! binding. `sendto`/`write` of an rtnetlink dump request is parsed and answered
//! by `support::build_netlink_reply_for_snapshot` over the network NAMESPACE the
//! calling task belongs to, which emits properly framed
//! `NLM_F_MULTI` dumps terminated by `NLMSG_DONE`: RTM_GETLINK yields that
//! namespace's links, RTM_GETADDR their addresses, RTM_GETROUTE its routes,
//! and everything unmodelled yields a bare `NLMSG_DONE` (an "empty"
//! dump) so the client sees a well-formed end-of-dump rather than a hang. The
//! namespace is the guest's, not the Mac's: under `--net host` it is a mirror of
//! the host wire taken once (`lo` plus one `eth0`), so the guest never learns
//! that `awdl0` or `utun3` exist.
//!
//! ## epoll → kqueue: the readiness model
//!
//! Linux `epoll` is emulated on Darwin `kqueue`. `epoll_create1` allocates a
//! real kqueue; the returned epoll fd's readiness IS that kqueue's fd, so a
//! thread blocks by waiting on the kqueue (see `io_wait`). Two readiness
//! sources coexist on one kqueue:
//!
//!   - **Host-backed fds** (sockets, host files, ptys) register an
//!     `EVFILT_READ`/`EVFILT_WRITE` knote — the kernel signals readiness.
//!   - **In-memory fds** (eventfd, pipes, timerfd, netlink) have no host kernel
//!     object the kqueue can watch, so their readiness is recomputed in
//!     userspace (`epoll_ready_events`) and a writer pokes the kqueue's
//!     `EVFILT_USER(0)` to force every blocked waiter to re-check
//!     (see [`super::epoll_shim`]). This is the fix for Go's `netpollBreak`
//!     lost-wakeup: an eventfd write must wake a poller blocked on the instance
//!     kqueue even though the eventfd is not a host fd.
//!
//! `fd_is_epollable` mirrors the kernel rule that an fd whose file has no
//! `->poll` op (a regular file, directory, or synthetic /proc node) is rejected
//! from `epoll_ctl(ADD)` with EPERM.
//!
//! `select`/`poll`/`pselect6`/`ppoll` share the same readiness machinery; the
//! `*p*` variants additionally swap the signal mask for the duration of the
//! wait (atomically, the way the kernel does), which is why they reach into the
//! signal subsystem.
//!
//! Methods are `impl` blocks on [`SyscallDispatcher`]; see [`super`] for the
//! dispatcher struct and the normalized dispatch table. Socket/netlink/fd-set
//! helper routines and the AF_UNIX registry live in the `support` submodule.
use super::*;
use crate::linux_abi::{
    LINUX_ICMP_ECHO_REPLY, LINUX_ICMP_ECHO_REQUEST, LINUX_IPPROTO_ICMP, LINUX_IPPROTO_TCP,
    LINUX_MSG_NOSIGNAL, LINUX_POLLRDHUP,
};
use crate::network::{BindTarget, ConnectTarget, GuestSocketAddr, HostSocketAddr};

syscall_table! {
    /// Per-module syscall routing for the `net` subsystem (Task A1).
    ///
    /// Owns the `number → handler` arms for every syscall this module
    /// implements. `resolve_handler` in `dispatch/mod.rs` chains this with
    /// the other modules' tables. Add a `net` syscall by adding an arm
    /// HERE — no shared routing table to edit.
    pub(crate) fn dispatch_net;
    19 => eventfd2,
    20 => epoll_create1,
    carrick_abi::CARRICK_PRIVATE_X86_EPOLL_CREATE => x86_epoll_create,
    21 => epoll_ctl,
    22 => epoll_pwait,
    441 => epoll_pwait2,
    // x86_64 poll(2): shares the ppoll handler, which branches on the
    // canonical number to read arg2 as an INT timeout_ms (not a *timespec).
    carrick_abi::CARRICK_PRIVATE_X86_POLL => ppoll,
    // x86_64 select(2): shares the pselect6 handler, which branches on the
    // canonical number to read the timeout as a *timeval (not *timespec).
    carrick_abi::CARRICK_PRIVATE_X86_SELECT => pselect6,
    72 => pselect6,
    73 => ppoll,
    198 => socket,
    199 => socketpair,
    200 => bind,
    201 => listen,
    202 => accept,
    203 => connect,
    204 => getsockname,
    205 => getpeername,
    206 => sendto,
    207 => recvfrom,
    208 => setsockopt,
    209 => getsockopt,
    210 => shutdown,
    211 => sendmsg,
    212 => recvmsg,
    242 => accept4,
    243 => sys_recvmmsg,
    269 => sys_sendmmsg,
}

pub(super) fn host_sockaddr_to_socket_addr(bytes: &[u8]) -> Option<std::net::SocketAddr> {
    if bytes.len() < 16 {
        return None;
    }
    #[cfg(target_os = "linux")]
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    #[cfg(not(target_os = "linux"))]
    let family = bytes[1] as i32;
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    match family {
        libc::AF_INET if bytes.len() >= 8 => {
            let ip = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Some(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        libc::AF_INET6 if bytes.len() >= 24 => {
            let octets: [u8; 16] = bytes[8..24].try_into().ok()?;
            let scope_id = if bytes.len() >= 28 {
                u32::from_ne_bytes(bytes[24..28].try_into().ok()?)
            } else {
                0
            };
            Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(octets),
                port,
                0,
                scope_id,
            )))
        }
        _ => None,
    }
}

pub(super) fn socket_addr_to_host_sockaddr(addr: std::net::SocketAddr) -> Option<Vec<u8>> {
    match addr {
        std::net::SocketAddr::V4(v4) => {
            let mut out = vec![0_u8; 16];
            set_host_sockaddr_header(&mut out, libc::AF_INET);
            out[2..4].copy_from_slice(&v4.port().to_be_bytes());
            out[4..8].copy_from_slice(&v4.ip().octets());
            Some(out)
        }
        std::net::SocketAddr::V6(v6) => {
            let mut out = vec![0_u8; 28];
            set_host_sockaddr_header(&mut out, libc::AF_INET6);
            out[2..4].copy_from_slice(&v6.port().to_be_bytes());
            out[8..24].copy_from_slice(&v6.ip().octets());
            out[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
            Some(out)
        }
    }
}

pub(super) fn socket_addr_to_linux_sockaddr(addr: std::net::SocketAddr) -> Option<Vec<u8>> {
    match addr {
        std::net::SocketAddr::V4(v4) => {
            let mut out = vec![0_u8; 16];
            out[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
            out[2..4].copy_from_slice(&v4.port().to_be_bytes());
            out[4..8].copy_from_slice(&v4.ip().octets());
            Some(out)
        }
        std::net::SocketAddr::V6(v6) => {
            let mut out = vec![0_u8; 28];
            out[0..2].copy_from_slice(&(LINUX_AF_INET6 as u16).to_ne_bytes());
            out[2..4].copy_from_slice(&v6.port().to_be_bytes());
            out[8..24].copy_from_slice(&v6.ip().octets());
            out[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
            Some(out)
        }
    }
}

/// The RAW `sockaddr` bytes `getsockname(2)` reports for `host_fd`.
///
/// Unlike [`host_socket_addr`] this does no family-specific parsing, so it can
/// key a table (see `reuseport`) for any address family — including ones
/// Carrick does not otherwise model, which must never collide with ones it
/// does.
/// Whether `host_fd` has something to read RIGHT NOW, without consuming it.
/// Used to ask whether a reuseport sibling is holding the group's work.
pub(super) fn host_fd_has_pending_input(host_fd: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd: host_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut pfd as *mut _, 1, 0) > 0 && pfd.revents & libc::POLLIN != 0 }
}

pub(super) fn host_sockaddr_bytes(host_fd: i32) -> Option<Vec<u8>> {
    let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
    let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
    let rc =
        unsafe { libc::getsockname(host_fd, sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _) };
    rc.host_syscall_errno().ok()?;
    let used = (sa_len as usize).min(sa.len());
    (used > 0).then(|| sa[..used].to_vec())
}

fn host_socket_addr(host_fd: i32, _family: i32, peer: bool) -> Option<std::net::SocketAddr> {
    let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
    let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
    let rc = if peer {
        unsafe { libc::getpeername(host_fd, sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _) }
    } else {
        unsafe { libc::getsockname(host_fd, sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _) }
    };
    rc.host_syscall_errno().ok()?;
    let used = (sa_len as usize).min(sa.len());
    host_sockaddr_to_socket_addr(&sa[..used])
}

pub(super) fn host_socket_is_connected(host_fd: i32) -> bool {
    let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
    let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
    let rc =
        unsafe { libc::getpeername(host_fd, sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _) };
    rc == 0
}
pub(super) mod epoll_ops;
#[cfg(test)]
use epoll_ops::epoll_kqueue_for_wake_test;
pub(super) mod lifecycle;
pub(super) use lifecycle::host_stream_socket_rdhup;
pub(super) mod netlink;
pub(crate) mod packet;
pub(super) mod recverr;
pub(super) mod reuseport;
pub(super) mod scm_rights;
pub(super) mod sctp;
mod send_recv;
mod sockopt;
pub(super) mod support;

pub(super) use super::read_iovecs;

/// Drop a closed socket's SCTP message boundaries (see [`sctp`]).
pub(crate) fn sctp_forget(host_fd: i32) {
    sctp::forget(host_fd);
}

/// Release SCM_RIGHTS descriptions whose in-flight message can no longer be
/// received (see [`scm_rights`]). Called from the close path in `dispatch`
/// once a host socket has actually closed.
pub(in crate::dispatch) fn scm_rights_gc() {
    scm_rights::gc();
}
pub(crate) mod unix_pure;

/// Drop `host_fd` from any `SO_REUSEPORT` group. Called from the close path in
/// `dispatch`; see `reuseport::leave`.
pub(in crate::dispatch) fn reuseport_leave(host_fd: i32) {
    reuseport::leave(host_fd);
}

/// Release any modelled Linux error queue (and its shadow socket) for
/// `host_fd`. Called from the close path in `dispatch`; see `recverr::close`.
pub(in crate::dispatch) fn recverr_close(host_fd: i32) {
    recverr::close(host_fd);
}

use support::*;
pub(super) use support::{drain_netlink_queue, host_fd_is_nonblocking, set_host_nonblocking};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct HostPollTarget {
    pub(super) host_fd: i32,
    pub(super) host_events: i16,
    pub(super) readiness_pipe: bool,
}

impl SyscallDispatcher {
    /// Whether `fd` is a pollable target for `epoll_ctl(ADD)`. The kernel
    /// returns EPERM when adding an fd whose file has no `->poll` op — regular
    /// files, directories, and synthetic /proc files. Pipes, sockets, eventfd,
    /// timerfd, epoll, netlink, and character devices (ptys) are all pollable.
    fn read_optional_fd_set(
        &self,
        memory: &mut impl CurrentMmMemory,
        address: u64,
        nfds: usize,
    ) -> Result<Result<Option<Vec<u8>>, LinuxErrno>, DispatchError> {
        if address == 0 {
            return Ok(Ok(None));
        }
        match read_fd_set(memory, address, nfds) {
            Ok(s) => Ok(Ok(Some(s))),
            Err(errno) => Ok(Err(errno)),
        }
    }

    /// Resolve one guest poll interest to the host fd and host event that
    /// `libc::poll`/`WaitOnFds` must watch for it — the ONE classification
    /// `ppoll` and `pselect6` share, so neither can drift from the other.
    ///
    /// `None` means the fd is synthetic (epoll/timerfd/…) or currently needs
    /// the per-fd `poll_ready_events` loop (an eventfd asked for `POLLOUT`, a
    /// pipe with staged splice bytes); the caller must take that loop for the
    /// whole set. An in-memory pipe or eventfd is host-visible only through
    /// its READINESS pipe, whose read end becomes readable when the guest fd
    /// is ready for whatever the guest asked — so the host event is always
    /// `POLLIN` there, and `readiness_pipe` tells the caller to translate a
    /// host wake back through `poll_ready_events` instead of using the host
    /// revents verbatim. Polling that read end for the guest's `POLLOUT`
    /// never fires: select01 counted a writable pipe end as not ready, and a
    /// blocking select on a full pipe slept its whole timeout.
    pub(super) fn host_poll_target(&self, fd: i32, events: i16) -> Option<HostPollTarget> {
        if ((events & LINUX_POLLOUT) != 0 && self.fd_is_eventfd(fd))
            || ((events & LINUX_POLLIN) != 0 && self.staged_splice_pipe_bytes(fd) != 0)
        {
            return None;
        }
        let direct = |host_fd: i32| {
            Some(HostPollTarget {
                host_fd,
                host_events: events,
                readiness_pipe: false,
            })
        };
        let readiness = |host_fd: i32| {
            Some(HostPollTarget {
                host_fd,
                host_events: libc::POLLIN,
                readiness_pipe: true,
            })
        };
        if let Some(open_file) = self.open_file(fd) {
            let open = open_file.description.read()?;
            return match &*open {
                OpenDescription::HostPipe { host_fd, .. }
                | OpenDescription::HostFile { host_fd, .. } => direct(host_fd.raw()),
                OpenDescription::HostSocket { host_fd, base, .. } => {
                    if base.pending_socket_error().is_some() {
                        None
                    } else {
                        direct(host_fd.raw())
                    }
                }
                OpenDescription::PipeReader { pipe, .. } => {
                    pipe.read_poll_fd().and_then(|fd| readiness(fd.raw()))
                }
                OpenDescription::PipeWriter { pipe, .. } => {
                    pipe.write_poll_fd().and_then(|fd| readiness(fd.raw()))
                }
                OpenDescription::EventFd { state, .. } => {
                    state.read_fd.as_ref().and_then(|fd| readiness(fd.raw()))
                }
                OpenDescription::Epoll { kqueue, .. } => readiness(kqueue.poll_fd()),
                OpenDescription::Pidfd { kqueue, .. } => direct(kqueue.poll_fd()),
                OpenDescription::Inotify { state, .. } => direct(state.poll_fd()),
                OpenDescription::Fanotify { group, .. } => match group.poll_fd() {
                    fd if fd >= 0 => direct(fd),
                    _ => None,
                },
                _ => None,
            };
        }
        if is_stdio_fd(fd) || fd < 0 {
            return direct(fd);
        }
        // Unknown fd: never pass the guest number through as a host fd (see
        // `host_fd_for_poll`).
        None
    }

    /// Return the host fd backing a guest fd for ppoll's fast path.
    /// `Some(host_fd)` means we can hand this off to libc::poll.
    /// `None` means it's synthetic (epoll/eventfd/timerfd/in-memory pipe)
    /// and ppoll has to fall back to the per-fd readiness loop.
    pub(super) fn host_fd_for_poll(&self, fd: i32) -> Option<HostFd> {
        if fd < 0 {
            // Negative fd in a pollfd entry: libc::poll ignores it
            // (revents=0), which is the right semantic. Pass it through.
            return Some(HostFd(fd));
        }
        if let Some(open_file) = self.open_file(fd) {
            let open = open_file.description.read()?;
            return match &*open {
                OpenDescription::HostPipe { host_fd, .. }
                | OpenDescription::HostFile { host_fd, .. } => Some(host_fd.view()),
                OpenDescription::HostSocket { host_fd, base, .. } => {
                    if base.pending_socket_error().is_some() {
                        None
                    } else {
                        Some(host_fd.view())
                    }
                }
                OpenDescription::PipeReader { pipe, .. } => pipe.read_poll_fd().map(|fd| fd.view()),
                OpenDescription::PipeWriter { pipe, .. } => {
                    pipe.write_poll_fd().map(|fd| fd.view())
                }
                OpenDescription::EventFd { state, .. } => {
                    state.read_fd.as_ref().map(|fd| fd.view())
                }
                // A pidfd is read-ready when its process exits; the backing
                // multiplexer's poll fd (the kqueue fd on macOS, the
                // pidfd-bearing epoll fd on Linux) is what poll/epoll watch.
                OpenDescription::Pidfd { kqueue, .. } => Some(HostFd(kqueue.poll_fd())),
                // inotify readiness is the backing kqueue's fd, so poll/epoll/
                // blocking-read wait on it natively.
                OpenDescription::Inotify { state, .. } => Some(HostFd(state.poll_fd())),
                // fanotify readiness is the group's readiness pipe: readable iff
                // an event is queued, so poll/epoll and a blocking read all
                // park on one real host fd. If the pipe could not be created
                // the group has no host fd at all — report `None` so the caller
                // falls through to the synthetic in-memory readiness below,
                // rather than polling fd -1 forever.
                OpenDescription::Fanotify { group, .. } => match group.poll_fd() {
                    fd if fd >= 0 => Some(HostFd(fd)),
                    _ => None,
                },
                _ => None,
            };
        }
        if is_stdio_fd(fd) {
            return Some(HostFd(fd));
        }
        // Unknown fd: do NOT pass the guest fd number through as a host fd
        // (host fds 3,4,5… belong to carrick itself — the cap-std rootfs dir,
        // the HVF device, etc., so polling them blocks on the wrong object).
        // Route to the synthetic readiness path instead.
        None
    }

    /// Is `fd` a one-way (non-bidirectional, non-pty) pipe/FIFO READ end?
    ///
    /// Such an fd is NEVER writable under Linux `poll(2)`/`epoll(7)`: a read end
    /// has no write side, so `POLLOUT`/`EPOLLOUT` is impossible there. Most hosts
    /// agree — macOS and Linux `poll()` leave `POLLOUT` clear on a pipe read end.
    /// **FreeBSD does not:** `poll(POLLIN|POLLOUT)` on a pipe read end returns
    /// `POLLOUT` (the kernel reports the read end "writable"), and kqueue's
    /// `EVFILT_WRITE` arms and fires on a read end with `data == buffer space`.
    /// That spurious writability both wakes a blocked edge-triggered `epoll_wait`
    /// early and latches `EPOLLOUT` into the readiness latch, masking the real
    /// EOF (`EPOLLIN|EPOLLHUP`) that arrives when the writer later closes — the
    /// `epolletblockedhup`/`epolletchildhup` failures on bhyve.
    ///
    /// Suppressing `POLLOUT`/`EPOLLOUT` for a one-way read end is correct on
    /// EVERY host (Linux/macOS already never assert it there), so this needs no
    /// `cfg`-split — it is a no-op everywhere except FreeBSD/NetBSD, where it
    /// removes the divergence.
    pub(super) fn host_fd_is_oneway_pipe_read_end(&self, fd: i32) -> bool {
        if fd < 0 {
            return false;
        }
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        matches!(
            open_file.description.read().as_deref(),
            Some(OpenDescription::HostPipe {
                is_read_end: true,
                bidirectional: false,
                pty: None,
                ..
            })
        )
    }

    /// Remove `fd` from every epoll instance's interest set (and purge any
    /// readiness already queued for it). Linux auto-removes a closed fd from all
    /// epoll interest lists; carrick keys interest by guest fd NUMBER, so a
    /// `close(2)` that skips `EPOLL_CTL_DEL` would otherwise leak a stale entry —
    /// yielding a spurious `EEXIST` when the fd number is reused, and recompute
    /// against a dead epoll_data token. The kqueue knote keyed on the closing
    /// host fd is reclaimed by the kernel when that host fd closes; a dup that
    /// keeps the host fd alive within the SAME epoll is the rarer
    /// `EPOLL_CTL_DEL`-covered survivor-rebind case. MUST be called with NO
    /// `open_files` lock held — it takes a read lock to snapshot the instances.
    #[inline]
    pub(super) fn fd_is_nonblocking(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        carrick_abi::LinuxOpenFlags::from_bits_truncate(
            open_file.description.common().status_flags(),
        )
        .contains(carrick_abi::LinuxOpenFlags::NONBLOCK)
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
    pub(in crate::dispatch::net) fn blocking_io<F>(
        &self,
        guest_fd: i32,
        host_fd: i32,
        dir: IoDir,
        nonblocking: bool,
        timeout: Option<std::time::Duration>,
        op: F,
    ) -> DispatchOutcome
    where
        F: FnOnce() -> Result<i64, LinuxErrno>,
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
                    let files = self.captured_file_table();
                    let fds = match WaitFds::raw_one(host_fd, dir.events())
                        .with_guest_slots(&files, [guest_fd])
                    {
                        Ok(fds) => fds,
                        Err(errno) => return DispatchOutcome::errno(errno),
                    };
                    DispatchOutcome::WaitOnFds {
                        fds,
                        timeout,
                        sig_mask: carrick_abi::WaitSigMask::NONE,
                        completion: FdWaitCompletion::Fd {
                            on_timeout: LINUX_EAGAIN.guest_retval(),
                        },
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
        // from_bits_retain: send/recv IGNORE unknown msg_flags bits.
        self.fd_is_nonblocking(fd)
            || LinuxMsgFlags::from_bits_retain(msg_flags).contains(LinuxMsgFlags::DONTWAIT)
    }

    /// True iff `fd` is an eventfd. An eventfd is always POLLOUT-ready (its
    /// counter isn't at max), but its host readiness pipe's READ end is never
    /// writable — so select/poll's all-host `libc::poll` fast path drops the
    /// requested POLLOUT (and worse, blocks waiting for it). When POLLOUT is
    /// requested we route the eventfd through `poll_ready_events` instead, which
    /// reports it writable. POLLIN-only stays on the native read_fd path so Go's
    /// epoll netpollBreak (EVFILT_READ on the readiness pipe) is unaffected.
    pub(super) fn fd_is_eventfd(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|f| {
            matches!(
                f.description.read().as_deref(),
                Some(OpenDescription::EventFd { .. })
            )
        })
    }

    /// Poll readiness for bare standard I/O file descriptors (0, 1, 2) when no
    /// description is installed in the file table.
    ///
    /// This special case stays outside the `FileDescription::readiness` authority
    /// because fds 0/1/2 with no installed description have no backing description
    /// object to query. Absent non-stdio descriptors report `POLLNVAL`.
    fn bare_stdio_poll_ready_events(&self, fd: i32, requested_events: i16) -> i16 {
        if is_stdio_fd(fd) {
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
                    if pfd.revents & libc::POLLERR != 0 {
                        revents |= LINUX_POLLERR;
                    }
                }
            }
            revents
        } else {
            LINUX_POLLNVAL
        }
    }

    fn poll_ready_events(&self, fd: i32, requested_events: i16) -> i16 {
        if fd < 0 {
            return 0;
        }
        let Some(open_file) = self.open_file(fd) else {
            return self.bare_stdio_poll_ready_events(fd, requested_events);
        };
        if open_file.description.is_closed() {
            return LINUX_POLLNVAL;
        }
        let interest = carrick_abi::LinuxPollEvents::from_bits_truncate(requested_events);
        open_file
            .description
            .readiness(interest.to_epoll(), self)
            .to_poll()
            .bits()
    }
}

#[cfg(test)]
mod netlink_readiness_tests {
    use super::*;

    fn poll_fd_readable(fd: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, 0) };
        rc == 1 && pfd.revents & libc::POLLIN != 0
    }

    #[test]
    fn epoll_and_poll_agree_that_a_queued_netlink_dump_is_readable() {
        let dispatcher = SyscallDispatcher::new();
        let open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Netlink {
                base: OpenDescriptionBase::new(0),
                protocol: 0,
                sock_type: LINUX_SOCK_DGRAM,
                pid: 0,
                groups: 0,
                recv_queue: VecDeque::from(vec![0xAAu8; 32]),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            })),
            0,
            0,
        );
        let description = Arc::clone(&open_file.description);
        let fd = dispatcher
            .install_fd_at_or_above(3, open_file)
            .expect("install netlink fd");

        assert_eq!(
            dispatcher.poll_ready_events(fd, LINUX_POLLIN) & LINUX_POLLIN,
            LINUX_POLLIN,
            "poll(2) already reports a queued netlink dump as readable"
        );
        assert_eq!(
            dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "epoll must report the same readiness as poll for the same description; \
             a synthetic netlink socket has no host fd, so the host-poll fallback \
             answers 0 and glibc's __check_pf/getaddrinfo never wakes"
        );
        assert_eq!(
            description.readiness(carrick_abi::LinuxEpollEvents::IN, &dispatcher)
                & carrick_abi::LinuxEpollEvents::IN,
            carrick_abi::LinuxEpollEvents::IN,
            "underlying backing readiness also reports netlink readable"
        );
    }

    #[test]
    fn staged_splice_bytes_are_pollin_and_epollin_ready_through_readiness_authority() {
        let dispatcher = SyscallDispatcher::new();
        let mut host_fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(host_fds.as_mut_ptr()) }, 0);
        let read_open = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                host_fd: HostFdRef::new(host_fds[0]),
                is_read_end: true,
                pipe_id: 88,
                base: OpenDescriptionBase::new(0),
                pty: None,
                bidirectional: false,
                write_kind: HostWriteKind::PipeLike,
                stdio_stream: None,
            })),
            LINUX_O_RDONLY,
            0,
        );
        let write_open = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                host_fd: HostFdRef::new(host_fds[1]),
                is_read_end: false,
                pipe_id: 88,
                base: OpenDescriptionBase::new(0),
                pty: None,
                bidirectional: false,
                write_kind: HostWriteKind::PipeLike,
                stdio_stream: None,
            })),
            LINUX_O_WRONLY,
            0,
        );
        let (read_fd, _write_fd) = dispatcher
            .install_fd_pair_at_or_above(3, read_open, write_open)
            .expect("install host pipe pair");

        dispatcher.stage_splice_pipe_bytes_owned(read_fd, b"staged".to_vec());
        let open_file = dispatcher.open_file(read_fd).expect("open file");

        assert_eq!(
            dispatcher.poll_ready_events(read_fd, LINUX_POLLIN) & LINUX_POLLIN,
            LINUX_POLLIN,
            "poll reports staged splice bytes as POLLIN"
        );
        assert_eq!(
            dispatcher.epoll_ready_events(read_fd, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "epoll reports staged splice bytes as EPOLLIN"
        );
        assert_eq!(
            open_file
                .description
                .readiness(carrick_abi::LinuxEpollEvents::IN, &dispatcher)
                & carrick_abi::LinuxEpollEvents::IN,
            carrick_abi::LinuxEpollEvents::IN,
            "readiness authority must see staged splice bytes as readable"
        );
    }

    #[test]
    fn epoll_description_with_ready_synthetic_child_is_pollin_and_epollin_ready() {
        use std::collections::HashMap;
        let dispatcher = SyscallDispatcher::new();
        let child_open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Netlink {
                base: OpenDescriptionBase::new(0),
                protocol: 0,
                sock_type: LINUX_SOCK_DGRAM,
                pid: 0,
                groups: 0,
                recv_queue: VecDeque::from(vec![0xAAu8; 32]),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            })),
            0,
            0,
        );
        let child_desc = Arc::clone(&child_open_file.description);
        let child_fd = dispatcher
            .install_fd_at_or_above(10, child_open_file)
            .expect("child fd");

        let mut interest_map = HashMap::new();
        interest_map.insert(
            child_fd,
            EpollInterest {
                target: Some(child_desc),
                host_poll_source: false,
                event: LinuxEpollEvent {
                    events: LINUX_EPOLLIN,
                    data: 1234,
                    _pad: 0,
                },
                last_ready: 0,
                last_read_avail: 0,
                write_backpressured: false,
                io_gen: 0,
                reg_gen: 0,
                _callback_enrollment: None,
            },
        );
        let mut mux = crate::event_mux::make_event_multiplexer().expect("event multiplexer");
        mux.register_user(0).expect("register user wake");
        let epoll_open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Epoll {
                base: OpenDescriptionBase::new(0),
                interest: interest_map,
                synthetic_interest_count: 1,
                pending_ready: VecDeque::new(),
                kqueue: Arc::new(crate::dispatch::EpollKqueue::new(
                    mux,
                    crate::dispatch::new_epoll_wake_registry(),
                )),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            })),
            0,
            0,
        );
        let epfd = dispatcher
            .install_fd_at_or_above(3, epoll_open_file)
            .expect("install epoll fd");

        let epoll_file = dispatcher.open_file(epfd).expect("epoll open file");

        assert_eq!(
            dispatcher.poll_ready_events(epfd, LINUX_POLLIN) & LINUX_POLLIN,
            LINUX_POLLIN,
            "poll reports epoll with ready synthetic child as readable"
        );
        assert_eq!(
            dispatcher.epoll_ready_events(epfd, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "epoll reports epoll with ready synthetic child as readable"
        );
        assert_eq!(
            epoll_file
                .description
                .readiness(carrick_abi::LinuxEpollEvents::IN, &dispatcher)
                & carrick_abi::LinuxEpollEvents::IN,
            carrick_abi::LinuxEpollEvents::IN,
            "readiness authority must report epoll with ready synthetic child as readable"
        );
    }

    #[test]
    fn poll_reports_pollnval_for_installed_closed_description() {
        let dispatcher = SyscallDispatcher::new();
        let closed_open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Closed { was_epoll: false })),
            0,
            0,
        );
        let closed_desc = Arc::clone(&closed_open_file.description);
        let fd = dispatcher
            .install_fd_at_or_above(20, closed_open_file)
            .expect("install closed fd");

        assert!(closed_desc.is_closed(), "description is closed");
        assert_eq!(
            dispatcher.poll_ready_events(fd, LINUX_POLLIN),
            LINUX_POLLNVAL,
            "poll reports POLLNVAL for closed description"
        );
        assert_eq!(
            dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN),
            0,
            "epoll reports 0 for closed description"
        );
        assert_eq!(
            closed_desc.readiness(carrick_abi::LinuxEpollEvents::IN, &dispatcher),
            carrick_abi::LinuxEpollEvents::empty(),
            "readiness authority reports empty for closed description"
        );
    }

    #[test]
    fn epoll_ctl_rejects_alias_of_same_epoll_description_with_einval() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut mux = crate::event_mux::make_event_multiplexer().expect("mux");
        mux.register_user(0).expect("register user wake");
        let epoll_open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Epoll {
                base: OpenDescriptionBase::new(0),
                interest: HashMap::new(),
                synthetic_interest_count: 0,
                pending_ready: VecDeque::new(),
                kqueue: Arc::new(crate::dispatch::EpollKqueue::new(
                    mux,
                    crate::dispatch::new_epoll_wake_registry(),
                )),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            })),
            0,
            0,
        );
        let epfd = dispatcher
            .install_fd_at_or_above(3, epoll_open_file.clone())
            .expect("install epoll");
        let alias_fd = dispatcher
            .install_fd_at_or_above(4, epoll_open_file)
            .expect("install alias epoll");

        let mut guest_mem = crate::dispatch::LinearMemory::new(0x1000, vec![0; 0x1000]);
        let event_ptr = 0x1000u64;
        let mut guest_event = [0u8; 12];
        guest_event[0..4].copy_from_slice(&LINUX_EPOLLIN.to_le_bytes());
        guest_mem.write_bytes(event_ptr, &guest_event).unwrap();

        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = crate::compat::CompatReporter::default();
        let request = SyscallRequest::new(
            21,
            SyscallArgs::from([
                epfd as u64,
                LINUX_EPOLL_CTL_ADD,
                alias_fd as u64,
                event_ptr,
                0,
                0,
            ]),
        );

        let outcome = dispatcher.dispatch(&kernel, request, &mut guest_mem, &reporter);
        assert!(
            matches!(outcome, Ok(DispatchOutcome::Errno { errno }) if errno == LINUX_EINVAL),
            "epoll_ctl must reject adding an alias of the same epoll description with EINVAL"
        );
    }

    #[test]
    fn epoll_ctl_rejects_two_description_cycle_with_eloop() {
        fn epoll_open_file() -> OpenFile {
            let mut mux = crate::event_mux::make_event_multiplexer().expect("mux");
            mux.register_user(0).expect("register user wake");
            OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::Epoll {
                    base: OpenDescriptionBase::new(0),
                    interest: HashMap::new(),
                    synthetic_interest_count: 0,
                    pending_ready: VecDeque::new(),
                    kqueue: Arc::new(crate::dispatch::EpollKqueue::new(
                        mux,
                        crate::dispatch::new_epoll_wake_registry(),
                    )),
                    wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
                })),
                0,
                0,
            )
        }

        let mut dispatcher = SyscallDispatcher::new();
        let first = dispatcher
            .install_fd_at_or_above(3, epoll_open_file())
            .expect("first epoll");
        let second = dispatcher
            .install_fd_at_or_above(4, epoll_open_file())
            .expect("second epoll");
        let mut guest_mem = crate::dispatch::LinearMemory::new(0x1000, vec![0; 0x1000]);
        let event_ptr = 0x1000u64;
        let mut guest_event = [0u8; 12];
        guest_event[0..4].copy_from_slice(&LINUX_EPOLLIN.to_le_bytes());
        guest_mem.write_bytes(event_ptr, &guest_event).unwrap();
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = crate::compat::CompatReporter::default();

        let first_adds_second = SyscallRequest::new(
            21,
            SyscallArgs::from([
                first as u64,
                LINUX_EPOLL_CTL_ADD,
                second as u64,
                event_ptr,
                0,
                0,
            ]),
        );
        assert!(matches!(
            dispatcher.dispatch(&kernel, first_adds_second, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        let second_adds_first = SyscallRequest::new(
            21,
            SyscallArgs::from([
                second as u64,
                LINUX_EPOLL_CTL_ADD,
                first as u64,
                event_ptr,
                0,
                0,
            ]),
        );
        assert!(
            matches!(
                dispatcher.dispatch(&kernel, second_adds_first, &mut guest_mem, &reporter),
                Ok(DispatchOutcome::Errno { errno }) if errno == carrick_abi::LINUX_ELOOP
            ),
            "adding the reverse description edge must reject the cycle with ELOOP"
        );
    }

    #[test]
    fn epoll_readiness_tracks_stored_target_identity_after_fd_close_and_reuse() {
        let dispatcher = SyscallDispatcher::new();
        let child_open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Netlink {
                base: OpenDescriptionBase::new(0),
                protocol: 0,
                sock_type: LINUX_SOCK_DGRAM,
                pid: 0,
                groups: 0,
                recv_queue: VecDeque::new(),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            })),
            0,
            0,
        );
        let child_desc = Arc::clone(&child_open_file.description);
        let alias_child_fd = dispatcher
            .install_fd_at_or_above(11, child_open_file)
            .expect("dup child fd");

        // Install a ready EventFd (counter = 1) at reused fd 10.
        let ready_eventfd = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::EventFd {
                base: OpenDescriptionBase::new(0),
                state: Arc::new(crate::dispatch::EventFdState::new(1)),
                semaphore: false,
            })),
            0,
            0,
        );
        let reused_fd = dispatcher
            .install_fd_at_or_above(10, ready_eventfd)
            .expect("install at 10");
        assert_eq!(reused_fd, 10);

        // Epoll has an interest registered under fd 10, but whose target is the Netlink description.
        let mut interest_map = HashMap::new();
        interest_map.insert(
            reused_fd,
            EpollInterest {
                target: Some(Arc::clone(&child_desc)),
                host_poll_source: false,
                event: LinuxEpollEvent {
                    events: LINUX_EPOLLIN,
                    data: 999,
                    _pad: 0,
                },
                last_ready: 0,
                last_read_avail: 0,
                write_backpressured: false,
                io_gen: 0,
                reg_gen: 0,
                _callback_enrollment: None,
            },
        );
        let mut mux = crate::event_mux::make_event_multiplexer().expect("mux");
        mux.register_user(0).expect("register user wake");
        let epoll_open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Epoll {
                base: OpenDescriptionBase::new(0),
                interest: interest_map,
                synthetic_interest_count: 1,
                pending_ready: VecDeque::new(),
                kqueue: Arc::new(crate::dispatch::EpollKqueue::new(
                    mux,
                    crate::dispatch::new_epoll_wake_registry(),
                )),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            })),
            0,
            0,
        );
        let epfd = dispatcher
            .install_fd_at_or_above(3, epoll_open_file)
            .expect("epfd");

        // Before data is queued in original child_desc (Netlink), epoll is not ready even though fd 10 (EventFd) is ready!
        let epoll_file = dispatcher.open_file(epfd).expect("epoll file");
        assert_eq!(
            epoll_file
                .description
                .readiness(carrick_abi::LinuxEpollEvents::IN, &dispatcher),
            carrick_abi::LinuxEpollEvents::empty(),
            "epoll readiness must query target identity (empty netlink), not replacement fd 10 (ready eventfd)"
        );

        // Queue data into the original registered description (alias_child_fd 11 / target).
        dispatcher
            .enqueue_netlink_message(alias_child_fd, &[1, 2, 3, 4])
            .expect("enqueue netlink message");

        // Epoll readiness must now report IN because it tracks target identity!
        assert_eq!(
            epoll_file
                .description
                .readiness(carrick_abi::LinuxEpollEvents::IN, &dispatcher)
                & carrick_abi::LinuxEpollEvents::IN,
            carrick_abi::LinuxEpollEvents::IN,
            "epoll readiness must track stored target identity across fd close and reuse"
        );
    }

    #[test]
    fn pidfd_readiness_transitions_to_in_when_exit_is_published() {
        let dispatcher = SyscallDispatcher::new();
        let mut mux = crate::event_mux::make_event_multiplexer().expect("pidfd multiplexer");
        mux.register_user(0).expect("register pidfd user wake");
        let watch = Arc::new(PidfdWatch::new(mux));
        let pidfd = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Pidfd {
                base: OpenDescriptionBase::new(0),
                target: PidfdTarget::Host(1234),
                kqueue: Arc::clone(&watch),
            })),
            0,
            0,
        );

        assert_eq!(
            pidfd
                .description
                .readiness(carrick_abi::LinuxEpollEvents::IN, &dispatcher),
            carrick_abi::LinuxEpollEvents::empty(),
            "a live pidfd target is not readable"
        );

        watch.publish_exit();

        assert_eq!(
            pidfd
                .description
                .readiness(carrick_abi::LinuxEpollEvents::IN, &dispatcher)
                & carrick_abi::LinuxEpollEvents::IN,
            carrick_abi::LinuxEpollEvents::IN,
            "publishing target exit must make pidfd readable"
        );
    }

    #[test]
    fn queued_dispatch_inotify_event_is_readable_without_a_host_vnode_edge() {
        let dispatcher = SyscallDispatcher::new();
        let inotify_state = Arc::new(crate::inotify::InotifyState::new().expect("inotify state"));
        let inotify_open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Inotify {
                base: OpenDescriptionBase::new(0),
                state: Arc::clone(&inotify_state),
            })),
            0,
            0,
        );
        let inotify_desc = Arc::clone(&inotify_open_file.description);
        assert_eq!(
            inotify_desc.readiness(carrick_abi::LinuxEpollEvents::IN, &dispatcher),
            carrick_abi::LinuxEpollEvents::empty(),
            "an empty inotify instance is not readable"
        );

        let wd = inotify_state.add_virtual_watch(carrick_abi::LINUX_IN_MODIFY);
        inotify_state.enqueue(wd, carrick_abi::LINUX_IN_MODIFY, 0, None);

        assert_eq!(
            inotify_desc.readiness(carrick_abi::LinuxEpollEvents::IN, &dispatcher)
                & carrick_abi::LinuxEpollEvents::IN,
            carrick_abi::LinuxEpollEvents::IN,
            "dispatch-synthesized inotify records must be readable even when the host poll fd is quiet"
        );
    }

    #[test]
    fn netlink_send_reply_wakes_parked_epoll_waiter() {
        let mut dispatcher = SyscallDispatcher::new();
        let netlink_open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Netlink {
                base: OpenDescriptionBase::new(0),
                protocol: 0,
                sock_type: LINUX_SOCK_DGRAM,
                pid: 0,
                groups: 0,
                recv_queue: VecDeque::new(),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            })),
            0,
            0,
        );
        let netlink_desc = Arc::clone(&netlink_open_file.description);
        let netlink_fd = dispatcher
            .install_fd_at_or_above(7, netlink_open_file)
            .expect("netlink fd");

        let mut interest_map = HashMap::new();
        interest_map.insert(
            netlink_fd,
            EpollInterest {
                target: Some(Arc::clone(&netlink_desc)),
                host_poll_source: false,
                event: LinuxEpollEvent {
                    events: LINUX_EPOLLIN,
                    data: 42,
                    _pad: 0,
                },
                last_ready: 0,
                last_read_avail: 0,
                write_backpressured: false,
                io_gen: 0,
                reg_gen: 0,
                _callback_enrollment: None,
            },
        );
        let epoll_kqueue = Arc::new(epoll_kqueue_for_wake_test(&dispatcher));
        let epoll_open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Epoll {
                base: OpenDescriptionBase::new(0),
                interest: interest_map,
                synthetic_interest_count: 1,
                pending_ready: VecDeque::new(),
                kqueue: Arc::clone(&epoll_kqueue),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            })),
            0,
            0,
        );
        let epfd = dispatcher
            .install_fd_at_or_above(8, epoll_open_file)
            .expect("epfd");

        // Before sending request, epoll is not ready
        assert_eq!(dispatcher.epoll_ready_events(epfd, LINUX_EPOLLIN), 0);
        assert!(
            !poll_fd_readable(epoll_kqueue.poll_fd()),
            "the instance wake fd must be quiet before netlink publishes a reply"
        );

        // Perform netlink_send by sending a dump request
        let mut guest_mem = crate::dispatch::LinearMemory::new(0x1000, vec![0; 0x2000]);
        let buf_ptr = 0x2000u64;
        let mut nl_hdr = [0u8; 16];
        nl_hdr[0..4].copy_from_slice(&16u32.to_le_bytes());
        nl_hdr[4..6].copy_from_slice(&18u16.to_le_bytes()); // RTM_GETLINK
        nl_hdr[6..8].copy_from_slice(&0x301u16.to_le_bytes()); // NLM_F_REQUEST | NLM_F_DUMP
        nl_hdr[8..12].copy_from_slice(&1u32.to_le_bytes()); // seq
        nl_hdr[12..16].copy_from_slice(&0u32.to_le_bytes()); // pid
        guest_mem.write_bytes(buf_ptr, &nl_hdr).unwrap();

        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = crate::compat::CompatReporter::default();
        let request = SyscallRequest::new(
            206,
            SyscallArgs::from([netlink_fd as u64, buf_ptr, 16, 0, 0, 0]),
        );

        let outcome = dispatcher.dispatch(&kernel, request, &mut guest_mem, &reporter);
        assert!(matches!(
            outcome,
            Ok(DispatchOutcome::Returned { value: 16 })
        ));
        assert!(
            poll_fd_readable(epoll_kqueue.poll_fd()),
            "netlink reply publication must pulse the epoll instance wake fd"
        );

        // After netlink_send, epoll must be IN-ready!
        assert_eq!(
            dispatcher.epoll_ready_events(epfd, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "netlink reply publication must wake epoll waiter"
        );
    }

    #[test]
    fn epoll_readiness_does_not_recursively_sample_host_backed_registrations() {
        let mut host_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(host_fds.as_mut_ptr()) }, 0);
        let dispatcher = SyscallDispatcher::new();
        let read_open = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                host_fd: HostFdRef::new(host_fds[0]),
                is_read_end: true,
                pipe_id: 100,
                base: OpenDescriptionBase::new(0),
                pty: None,
                bidirectional: false,
                write_kind: HostWriteKind::PipeLike,
                stdio_stream: None,
            })),
            LINUX_O_RDONLY,
            0,
        );
        let read_desc = Arc::clone(&read_open.description);
        let pipe_fd = dispatcher
            .install_fd_at_or_above(20, read_open)
            .expect("pipe fd");
        let mut interest_map = HashMap::new();
        interest_map.insert(
            pipe_fd,
            EpollInterest {
                target: Some(Arc::clone(&read_desc)),
                host_poll_source: true,
                event: LinuxEpollEvent {
                    events: LINUX_EPOLLIN,
                    data: 777,
                    _pad: 0,
                },
                last_ready: 0,
                last_read_avail: 0,
                write_backpressured: false,
                io_gen: 0,
                reg_gen: 0,
                _callback_enrollment: None,
            },
        );
        let mut mux = crate::event_mux::make_event_multiplexer().expect("mux");
        mux.register_user(0).expect("register user wake");
        let epoll_backing = Arc::new(RwLock::new(OpenDescription::Epoll {
            base: OpenDescriptionBase::new(0),
            interest: interest_map,
            synthetic_interest_count: 0,
            pending_ready: VecDeque::new(),
            kqueue: Arc::new(crate::dispatch::EpollKqueue::new(
                mux,
                crate::dispatch::new_epoll_wake_registry(),
            )),
            wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
        }));
        let epoll_open_file =
            OpenFile::from_open_description_with_status_flags(Arc::clone(&epoll_backing), 0, 0);
        let epfd = dispatcher
            .install_fd_at_or_above(21, epoll_open_file)
            .expect("epfd");

        // Custom ReadinessContext that panics if description_readiness is called for a host-backed child
        struct NoHostSampleContext;
        impl crate::kernel::ReadinessContext for NoHostSampleContext {
            fn staged_splice_bytes(&self, _id: crate::kernel::FileDescriptionId) -> usize {
                0
            }
            fn description_readiness(
                &self,
                _description: &Arc<crate::kernel::FileDescription>,
                _interest: carrick_abi::LinuxEpollEvents,
            ) -> carrick_abi::LinuxEpollEvents {
                panic!(
                    "host-backed child must not be recursively sampled by epoll readiness authority"
                );
            }
        }

        let epoll_file = dispatcher.open_file(epfd).expect("epoll file");
        let synthetic_count = match &*epoll_backing.read() {
            OpenDescription::Epoll {
                synthetic_interest_count,
                ..
            } => *synthetic_interest_count,
            _ => usize::MAX,
        };
        assert_eq!(
            synthetic_count, 0,
            "host-backed registrations must preserve the O(1) quiet fast path"
        );
        // Must NOT panic because host-backed child is omitted from synthetic child traversal!
        let ready = epoll_file
            .description
            .readiness(carrick_abi::LinuxEpollEvents::IN, &NoHostSampleContext);
        assert_eq!(ready, carrick_abi::LinuxEpollEvents::empty());
        unsafe { libc::close(host_fds[1]) };
    }

    #[test]
    fn epoll_ctl_tracks_the_synthetic_registration_count() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut mux = crate::event_mux::make_event_multiplexer().expect("mux");
        mux.register_user(0).expect("register user wake");
        let epoll_backing = Arc::new(RwLock::new(OpenDescription::Epoll {
            base: OpenDescriptionBase::new(0),
            interest: HashMap::new(),
            synthetic_interest_count: 0,
            pending_ready: VecDeque::new(),
            kqueue: Arc::new(crate::dispatch::EpollKqueue::new(
                mux,
                crate::dispatch::new_epoll_wake_registry(),
            )),
            wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
        }));
        let epoll_open_file =
            OpenFile::from_open_description_with_status_flags(Arc::clone(&epoll_backing), 0, 0);
        let epfd = dispatcher
            .install_fd_at_or_above(3, epoll_open_file)
            .expect("epoll fd");
        let target_fd = dispatcher
            .install_fd_at_or_above(
                4,
                OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(OpenDescription::Netlink {
                        base: OpenDescriptionBase::new(0),
                        protocol: 0,
                        sock_type: LINUX_SOCK_DGRAM,
                        pid: 0,
                        groups: 0,
                        recv_queue: VecDeque::new(),
                        wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
                    })),
                    0,
                    0,
                ),
            )
            .expect("synthetic target fd");

        let mut guest_mem = crate::dispatch::LinearMemory::new(0x1000, vec![0; 0x1000]);
        let event_ptr = 0x1000u64;
        let mut guest_event = [0u8; 12];
        guest_event[0..4].copy_from_slice(&LINUX_EPOLLIN.to_le_bytes());
        guest_mem.write_bytes(event_ptr, &guest_event).unwrap();
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = crate::compat::CompatReporter::default();
        let mut call = |op, event| {
            dispatcher.dispatch(
                &kernel,
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([epfd as u64, op, target_fd as u64, event, 0, 0]),
                ),
                &mut guest_mem,
                &reporter,
            )
        };

        assert!(matches!(
            call(LINUX_EPOLL_CTL_ADD, event_ptr),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));
        assert_eq!(
            match &*epoll_backing.read() {
                OpenDescription::Epoll {
                    synthetic_interest_count,
                    ..
                } => *synthetic_interest_count,
                _ => usize::MAX,
            },
            1
        );

        assert!(matches!(
            call(LINUX_EPOLL_CTL_DEL, 0),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));
        assert_eq!(
            match &*epoll_backing.read() {
                OpenDescription::Epoll {
                    synthetic_interest_count,
                    ..
                } => *synthetic_interest_count,
                _ => usize::MAX,
            },
            0
        );
    }

    fn every_description_kind_fixture() -> Vec<OpenFile> {
        let mut fixtures = Vec::with_capacity(25);

        // 1. Closed
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Closed { was_epoll: false })),
            0,
            0,
        ));

        // 2. File
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::File {
                base: OpenDescriptionBase::new(0),
                path: "/fixture/file".to_string(),
                metadata: crate::rootfs::RootFsMetadata {
                    path: std::path::PathBuf::from("/fixture/file"),
                    kind: crate::rootfs::RootFsEntryKind::File,
                    mode: 0o644,
                    size: 12,
                },
                contents: FileContents::dense(b"fixture data".to_vec()),
                offset: 0,
                writable: true,
            })),
            LINUX_O_RDWR,
            0,
        ));

        // 3. Directory
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Directory {
                base: OpenDescriptionBase::new(0),
                path: "/fixture/dir".to_string(),
                metadata: crate::rootfs::RootFsMetadata {
                    path: std::path::PathBuf::from("/fixture/dir"),
                    kind: crate::rootfs::RootFsEntryKind::Directory,
                    mode: 0o755,
                    size: 0,
                },
                listing: DirListing::Pending,
                offset: 0,
                trusted_host_dir: None,
            })),
            LINUX_O_RDONLY,
            0,
        ));

        // 4. SyntheticFile
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::SyntheticFile {
                base: OpenDescriptionBase::new(0),
                path: "/fixture/synthetic".to_string(),
                contents: b"synthetic content".to_vec(),
                offset: 0,
            })),
            LINUX_O_RDONLY,
            0,
        ));

        // 5. InMemoryFile
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::InMemoryFile {
                base: OpenDescriptionBase::new(0),
                path: "/fixture/inmem".to_string(),
                contents: Arc::new(parking_lot::RwLock::new(crate::vfs::SparseBuffer::from(
                    b"inmem content".to_vec(),
                ))),
                offset: 0,
                writable: true,
                max_size: 4096,
            })),
            LINUX_O_RDWR,
            0,
        ));

        // 6. SyntheticDevice
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::SyntheticDevice {
                base: OpenDescriptionBase::new(0),
                kind: crate::vfs::SyntheticDeviceKind::Null,
            })),
            LINUX_O_RDWR,
            0,
        ));

        // 7. EventFd
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::EventFd {
                base: OpenDescriptionBase::new(0),
                state: Arc::new(crate::dispatch::EventFdState::new(1)),
                semaphore: false,
            })),
            LINUX_O_RDWR,
            0,
        ));

        // 8. TimerFd
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::TimerFd {
                base: OpenDescriptionBase::new(0),
                state: Arc::new(crate::dispatch::TimerFdState::new(
                    Arc::new(crate::kernel::container::ClockDomain::system()),
                    1,
                )),
            })),
            LINUX_O_RDWR,
            0,
        ));

        // 9. Multiplexed instance
        {
            let mut mux = crate::event_mux::make_event_multiplexer().expect("multiplexer");
            mux.register_user(0).expect("register user wake");
            fixtures.push(OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::Epoll {
                    base: OpenDescriptionBase::new(0),
                    interest: HashMap::new(),
                    synthetic_interest_count: 0,
                    pending_ready: VecDeque::new(),
                    kqueue: Arc::new(crate::dispatch::EpollKqueue::new(
                        mux,
                        crate::dispatch::new_epoll_wake_registry(),
                    )),
                    wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
                })),
                0,
                0,
            ));
        }

        // 10. Pidfd
        {
            let mut mux = crate::event_mux::make_event_multiplexer().expect("pidfd mux");
            mux.register_user(0).expect("register pidfd user wake");
            fixtures.push(OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::Pidfd {
                    base: OpenDescriptionBase::new(0),
                    target: PidfdTarget::Host(1234),
                    kqueue: Arc::new(PidfdWatch::new(mux)),
                })),
                0,
                0,
            ));
        }

        // 11. Inotify
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Inotify {
                base: OpenDescriptionBase::new(0),
                state: Arc::new(crate::inotify::InotifyState::new().expect("inotify state")),
            })),
            0,
            0,
        ));

        // 12. Fanotify
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Fanotify {
                base: OpenDescriptionBase::new(0),
                group: Arc::new(crate::fanotify::FanotifyGroup::new(
                    carrick_abi::LinuxFanotifyInitFlags::empty(),
                    0,
                )),
            })),
            0,
            0,
        ));

        // 13. SignalFd
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::SignalFd {
                base: OpenDescriptionBase::new(0),
                mask: carrick_abi::SigSet::from_raw(0),
            })),
            0,
            0,
        ));

        // 14. OpenDescription::PerfEvent is omitted because PerfEventState constructor and fields are private to dispatch::perf.

        // 15. FsContext
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::FsContext {
                base: OpenDescriptionBase::new(0),
                state: Arc::new(parking_lot::Mutex::new(
                    crate::dispatch::mount_api::FsContextState::new_superblock("tmpfs"),
                )),
            })),
            0,
            0,
        ));

        // 16. PipeReader
        {
            let pipe = Arc::new(crate::dispatch::fs::PipeInner::new(50, 65536));
            let mut read_base = OpenDescriptionBase::new(LINUX_O_RDONLY);
            read_base.set_pipe_capacity_cell(Arc::clone(&pipe.capacity_cell));
            fixtures.push(OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::PipeReader {
                    base: read_base,
                    pipe,
                })),
                LINUX_O_RDONLY,
                0,
            ));
        }

        // 17. PipeWriter
        {
            let pipe = Arc::new(crate::dispatch::fs::PipeInner::new(51, 65536));
            let mut write_base = OpenDescriptionBase::new(LINUX_O_WRONLY);
            write_base.set_pipe_capacity_cell(Arc::clone(&pipe.capacity_cell));
            fixtures.push(OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::PipeWriter {
                    base: write_base,
                    pipe,
                })),
                LINUX_O_WRONLY,
                0,
            ));
        }

        // 18. HostPipe
        {
            let mut host_fds = [-1i32; 2];
            assert_eq!(unsafe { libc::pipe(host_fds.as_mut_ptr()) }, 0);
            let _write_ref = HostFdRef::new(host_fds[1]);
            fixtures.push(OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::HostPipe {
                    base: OpenDescriptionBase::new(LINUX_O_RDONLY),
                    host_fd: HostFdRef::new(host_fds[0]),
                    is_read_end: true,
                    pipe_id: 201,
                    pty: None,
                    bidirectional: false,
                    write_kind: HostWriteKind::PipeLike,
                    stdio_stream: None,
                })),
                LINUX_O_RDONLY,
                0,
            ));
        }

        // 19. HostSocket
        {
            let mut pair = [-1i32; 2];
            assert_eq!(
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) },
                0
            );
            let _peer_ref = HostFdRef::new(pair[1]);
            fixtures.push(OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::HostSocket {
                    base: OpenDescriptionBase::new(LINUX_O_RDWR),
                    host_fd: HostFdRef::new(pair[0]),
                    family: LINUX_AF_UNIX,
                    type_: LINUX_SOCK_STREAM,
                    protocol: 0,
                    mcast_memberships: Vec::new(),
                    synthetic_recv: VecDeque::new(),
                })),
                LINUX_O_RDWR,
                0,
            ));
        }

        // 20. HostFile
        {
            let mut pair = [-1i32; 2];
            assert_eq!(unsafe { libc::pipe(pair.as_mut_ptr()) }, 0);
            let _write_ref = HostFdRef::new(pair[1]);
            fixtures.push(OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::HostFile {
                    base: OpenDescriptionBase::new(LINUX_O_RDWR),
                    host_fd: HostFdRef::new(pair[0]),
                    metadata: crate::rootfs::RootFsMetadata {
                        path: std::path::PathBuf::from("/fixture/hostfile"),
                        kind: crate::rootfs::RootFsEntryKind::File,
                        mode: 0o644,
                        size: 0,
                    },
                    writable: true,
                })),
                LINUX_O_RDWR,
                0,
            ));
        }

        // 21. Netlink
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Netlink {
                base: OpenDescriptionBase::new(0),
                protocol: 0,
                sock_type: LINUX_SOCK_DGRAM,
                pid: 0,
                groups: 0,
                recv_queue: VecDeque::new(),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            })),
            0,
            0,
        ));

        // 22. OpenDescription::BpfMap is omitted because BpfMap constructor and fields are private to dispatch::bpf.

        // 23. OpenDescription::BpfProg is omitted because BpfProg fields are private to dispatch::bpf and it has no in-process constructor without guest memory.

        // 24. Mqueue
        fixtures.push(OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Mqueue {
                base: OpenDescriptionBase::new(0),
                queue: Arc::new(crate::dispatch::mqueue::MqueueInner::new(10, 1024, 0)),
            })),
            LINUX_O_RDWR,
            0,
        ));

        // 25. InMemorySocket
        {
            let creds1 = crate::dispatch::net::unix_pure::LinuxUcred {
                pid: 100,
                uid: 1000,
                gid: 1000,
            };
            let creds2 = crate::dispatch::net::unix_pure::LinuxUcred {
                pid: 200,
                uid: 1000,
                gid: 1000,
            };
            let (s1, _s2) = crate::dispatch::net::unix_pure::PureSocketInner::pair(
                LINUX_SOCK_STREAM,
                creds1,
                creds2,
            );
            fixtures.push(OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::InMemorySocket {
                    base: OpenDescriptionBase::new(0),
                    socket: s1,
                })),
                LINUX_O_RDWR,
                0,
            ));
        }

        fixtures
    }

    #[test]
    fn poll_and_epoll_readiness_agree_for_every_installed_description_kind() {
        let dispatcher = SyscallDispatcher::new();
        for open_file in every_description_kind_fixture() {
            let fd = dispatcher
                .install_fd_at_or_above(3, open_file)
                .expect("install fixture fd");
            let ready_events = dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN | LINUX_EPOLLOUT);
            let poll = dispatcher.poll_ready_events(fd, LINUX_POLLIN | LINUX_POLLOUT);
            assert_eq!(
                carrick_abi::LinuxEpollEvents::from_bits_retain(ready_events)
                    .to_poll()
                    .bits()
                    & (LINUX_POLLIN | LINUX_POLLOUT),
                poll & (LINUX_POLLIN | LINUX_POLLOUT),
                "readiness translators must agree for fd {fd}"
            );
        }
    }

    #[test]
    fn poll_and_epoll_negative_and_absent_fd_semantics() {
        let dispatcher = SyscallDispatcher::new();

        // Negative fds return 0 on both query surfaces
        assert_eq!(
            dispatcher.poll_ready_events(-1, LINUX_POLLIN | LINUX_POLLOUT),
            0
        );
        assert_eq!(
            dispatcher.epoll_ready_events(-1, LINUX_EPOLLIN | LINUX_EPOLLOUT),
            0
        );

        // Absent stdio fds (0, 1, 2) without an installed OpenDescription:
        // fd 1 and 2 are always writable
        assert_eq!(
            dispatcher.poll_ready_events(1, LINUX_POLLOUT) & LINUX_POLLOUT,
            LINUX_POLLOUT
        );
        assert_eq!(
            dispatcher.poll_ready_events(2, LINUX_POLLOUT) & LINUX_POLLOUT,
            LINUX_POLLOUT
        );

        // Absent non-stdio fd returns POLLNVAL in poll, 0 in event query
        assert_eq!(
            dispatcher.poll_ready_events(99, LINUX_POLLIN | LINUX_POLLOUT),
            LINUX_POLLNVAL
        );
        assert_eq!(
            dispatcher.epoll_ready_events(99, LINUX_EPOLLIN | LINUX_EPOLLOUT),
            0
        );
    }

    #[test]
    fn host_pipe_readiness_suppresses_out_below_pipe_buf_threshold() {
        let dispatcher = SyscallDispatcher::new();

        // 1. Below threshold: capacity 8192, 4097 bytes queued -> 4095 room (< 4096).
        let mut fds1 = [-1i32; 2];
        assert_eq!(unsafe { libc::pipe(fds1.as_mut_ptr()) }, 0);
        let mut read_base1 = OpenDescriptionBase::new(LINUX_O_RDONLY);
        read_base1.set_pipe_capacity(8192);
        let read_pipe1 = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                base: read_base1,
                host_fd: HostFdRef::new(fds1[0]),
                is_read_end: true,
                pipe_id: 501,
                pty: None,
                bidirectional: false,
                write_kind: HostWriteKind::PipeLike,
                stdio_stream: None,
            })),
            LINUX_O_RDONLY,
            0,
        );
        let _read_fd1 = dispatcher
            .install_fd_at_or_above(3, read_pipe1)
            .expect("install read pipe 1");

        let mut write_base1 = OpenDescriptionBase::new(LINUX_O_WRONLY);
        write_base1.set_pipe_capacity(8192);
        let write_pipe1 = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                base: write_base1,
                host_fd: HostFdRef::new(fds1[1]),
                is_read_end: false,
                pipe_id: 501,
                pty: None,
                bidirectional: false,
                write_kind: HostWriteKind::PipeLike,
                stdio_stream: None,
            })),
            LINUX_O_WRONLY,
            0,
        );
        let write_fd1 = dispatcher
            .install_fd_at_or_above(3, write_pipe1)
            .expect("install write pipe 1");

        // Write 4097 bytes into the pipe to leave 8192 - 4097 = 4095 room (< 4096 LINUX_PIPE_BUF).
        let payload1 = vec![0x41u8; 4097];
        assert_eq!(
            unsafe { libc::write(fds1[1], payload1.as_ptr().cast(), payload1.len()) },
            4097
        );

        // Host fd is natively writable, but modeled room is 4095 (< 4096).
        // OUT must be suppressed on both query surfaces.
        let ready_events1 = dispatcher.epoll_ready_events(write_fd1, LINUX_EPOLLOUT);
        assert_eq!(
            ready_events1 & LINUX_EPOLLOUT,
            0,
            "query must suppress OUT when modeled pipe room is < 4096"
        );
        let poll_events1 = dispatcher.poll_ready_events(write_fd1, LINUX_POLLOUT);
        assert_eq!(
            poll_events1 & LINUX_POLLOUT,
            0,
            "poll must suppress OUT when modeled pipe room is < 4096"
        );

        // 2. Threshold boundary: separate pipe pair with capacity 8192, 4096 queued -> 4096 room.
        let mut fds2 = [-1i32; 2];
        assert_eq!(unsafe { libc::pipe(fds2.as_mut_ptr()) }, 0);
        let mut read_base2 = OpenDescriptionBase::new(LINUX_O_RDONLY);
        read_base2.set_pipe_capacity(8192);
        let read_pipe2 = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                base: read_base2,
                host_fd: HostFdRef::new(fds2[0]),
                is_read_end: true,
                pipe_id: 502,
                pty: None,
                bidirectional: false,
                write_kind: HostWriteKind::PipeLike,
                stdio_stream: None,
            })),
            LINUX_O_RDONLY,
            0,
        );
        let _read_fd2 = dispatcher
            .install_fd_at_or_above(3, read_pipe2)
            .expect("install read pipe 2");

        let mut write_base2 = OpenDescriptionBase::new(LINUX_O_WRONLY);
        write_base2.set_pipe_capacity(8192);
        let write_pipe2 = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                base: write_base2,
                host_fd: HostFdRef::new(fds2[1]),
                is_read_end: false,
                pipe_id: 502,
                pty: None,
                bidirectional: false,
                write_kind: HostWriteKind::PipeLike,
                stdio_stream: None,
            })),
            LINUX_O_WRONLY,
            0,
        );
        let write_fd2 = dispatcher
            .install_fd_at_or_above(3, write_pipe2)
            .expect("install write pipe 2");

        // Write 4096 bytes into the pipe to leave exactly 8192 - 4096 = 4096 room.
        let payload2 = vec![0x42u8; 4096];
        assert_eq!(
            unsafe { libc::write(fds2[1], payload2.as_ptr().cast(), payload2.len()) },
            4096
        );

        let ready_events2 = dispatcher.epoll_ready_events(write_fd2, LINUX_EPOLLOUT);
        assert_eq!(
            ready_events2 & LINUX_EPOLLOUT,
            LINUX_EPOLLOUT,
            "query must report OUT when modeled pipe room is >= 4096"
        );
        let poll_events2 = dispatcher.poll_ready_events(write_fd2, LINUX_POLLOUT);
        assert_eq!(
            poll_events2 & LINUX_POLLOUT,
            LINUX_POLLOUT,
            "poll must report OUT when modeled pipe room is >= 4096"
        );
    }

    #[test]
    fn named_fifo_terminal_readiness_reports_implicit_hup() {
        let dispatcher = SyscallDispatcher::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo_path = dir.path().join("test_fifo");
        let c_path = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        // Open read end (O_NONBLOCK | O_RDONLY)
        let rfd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        assert!(rfd >= 0, "open fifo read end");
        let read_host_fd = HostFdRef::new(rfd);
        // Open write end (O_NONBLOCK | O_WRONLY)
        let wfd = unsafe { libc::open(c_path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
        assert!(wfd >= 0, "open fifo write end");
        let write_host_fd = HostFdRef::new(wfd);

        // Register with fifo_beacon
        crate::dispatch::fifo_beacon::register_open(rfd, 0);
        crate::dispatch::fifo_beacon::register_open(wfd, 1);

        let read_pipe = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                base: OpenDescriptionBase::new(LINUX_O_RDONLY | LINUX_O_NONBLOCK),
                host_fd: read_host_fd.clone(),
                is_read_end: true,
                pipe_id: 601,
                pty: None,
                bidirectional: false,
                write_kind: HostWriteKind::PipeLike,
                stdio_stream: None,
            })),
            LINUX_O_RDONLY | LINUX_O_NONBLOCK,
            0,
        );
        let guest_rfd = dispatcher
            .install_fd_at_or_above(3, read_pipe)
            .expect("install fifo read end");

        // Write data into FIFO before writer close so read end has buffered data
        assert_eq!(unsafe { libc::write(wfd, b"data".as_ptr().cast(), 4) }, 4);

        // Unregister while ownership keeps the raw fd live, then close it.
        assert!(crate::dispatch::fifo_beacon::register_close(&write_host_fd));
        drop(write_host_fd);

        // Buffered data plus EOF: IN interest receives IN | HUP (buffered data does not mask HUP)
        let ready_in = dispatcher.epoll_ready_events(guest_rfd, LINUX_EPOLLIN);
        assert_eq!(
            ready_in & (LINUX_EPOLLIN | LINUX_EPOLLHUP),
            LINUX_EPOLLIN | LINUX_EPOLLHUP,
            "buffered data plus EOF must report both IN and HUP"
        );
        let poll_in = dispatcher.poll_ready_events(guest_rfd, LINUX_POLLIN);
        assert_eq!(
            poll_in & (LINUX_POLLIN | LINUX_POLLHUP),
            LINUX_POLLIN | LINUX_POLLHUP,
            "buffered data plus EOF poll must report both IN and HUP"
        );

        // Query OUT only: even though IN was not requested and OUT is not ready on a read end,
        // HUP must be delivered implicitly.
        let ready_events = dispatcher.epoll_ready_events(guest_rfd, LINUX_EPOLLOUT);
        assert_eq!(
            ready_events & LINUX_EPOLLHUP,
            LINUX_EPOLLHUP,
            "OUT-only registration must receive implicit HUP after writer closes"
        );
        let poll_events = dispatcher.poll_ready_events(guest_rfd, LINUX_POLLOUT);
        assert_eq!(
            poll_events & LINUX_POLLHUP,
            LINUX_POLLHUP,
            "OUT-only poll must receive implicit HUP after writer closes"
        );

        // Unregister reader from beacon; HostFdRef will close rfd when dropped
        assert!(!crate::dispatch::fifo_beacon::register_close(&read_host_fd));

        // Prove this FIFO's beacon and read end are cleanly removed on full lifecycle completion
        assert!(
            !crate::dispatch::fifo_beacon::has_beacon_for_fd(rfd),
            "beacon and read-end registration must be cleaned up after last reader unregisters"
        );
    }

    #[test]
    fn in_memory_socket_rdhup_is_not_implicit() {
        let dispatcher = SyscallDispatcher::new();
        let creds1 = crate::dispatch::net::unix_pure::LinuxUcred {
            pid: 100,
            uid: 1000,
            gid: 1000,
        };
        let creds2 = crate::dispatch::net::unix_pure::LinuxUcred {
            pid: 200,
            uid: 1000,
            gid: 1000,
        };
        let (s1, s2) = crate::dispatch::net::unix_pure::PureSocketInner::pair(
            LINUX_SOCK_STREAM,
            creds1,
            creds2,
        );

        // Shutdown peer write end so s1 observes peer close (RDHUP)
        s2.shutdown(crate::dispatch::net::unix_pure::LINUX_SHUT_WR)
            .expect("shutdown peer write");

        let sock_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::InMemorySocket {
                base: OpenDescriptionBase::new(0),
                socket: s1,
            })),
            LINUX_O_RDWR,
            0,
        );
        let sock_fd = dispatcher
            .install_fd_at_or_above(3, sock_file)
            .expect("install in-memory socket");

        // IN-only interest: must NOT report RDHUP implicitly
        let ready_events = dispatcher.epoll_ready_events(sock_fd, LINUX_EPOLLIN);
        assert_eq!(
            ready_events & LINUX_EPOLLRDHUP,
            0,
            "RDHUP must not be implicit for IN-only interest"
        );
        let poll_events = dispatcher.poll_ready_events(sock_fd, LINUX_POLLIN);
        assert_eq!(
            poll_events & LINUX_POLLRDHUP,
            0,
            "RDHUP must not be implicit for IN-only poll"
        );

        // Explicit RDHUP interest: must report RDHUP
        let ready_events_rdhup =
            dispatcher.epoll_ready_events(sock_fd, LINUX_EPOLLIN | LINUX_EPOLLRDHUP);
        assert_eq!(
            ready_events_rdhup & LINUX_EPOLLRDHUP,
            LINUX_EPOLLRDHUP,
            "explicit RDHUP interest must report RDHUP"
        );
        let poll_events_rdhup =
            dispatcher.poll_ready_events(sock_fd, LINUX_POLLIN | LINUX_POLLRDHUP);
        assert_eq!(
            poll_events_rdhup & LINUX_POLLRDHUP,
            LINUX_POLLRDHUP,
            "explicit RDHUP poll must report RDHUP"
        );
    }
}

impl crate::kernel::ReadinessContext for SyscallDispatcher {
    fn staged_splice_bytes(&self, id: crate::kernel::FileDescriptionId) -> usize {
        self.staged_splice_description_bytes(id)
    }

    fn host_pipe_write_room(
        &self,
        pipe_capacity: i64,
        pipe_id: u64,
        is_read_end: bool,
        bidirectional: bool,
        host_fd: i32,
    ) -> Option<usize> {
        self.host_pipe_capacity_room(pipe_capacity, pipe_id, is_read_end, bidirectional, host_fd)
    }

    fn description_readiness(
        &self,
        description: &Arc<crate::kernel::FileDescription>,
        interest: carrick_abi::LinuxEpollEvents,
    ) -> carrick_abi::LinuxEpollEvents {
        thread_local! {
            static VISITED: std::cell::RefCell<Vec<crate::kernel::FileDescriptionId>> =
                const { std::cell::RefCell::new(Vec::new()) };
        }
        VISITED.with(|v| {
            let mut visited = v.borrow_mut();
            if visited.len() >= 5 || visited.contains(&description.id()) {
                return carrick_abi::LinuxEpollEvents::empty();
            }
            visited.push(description.id());
            drop(visited);
            let res = description.readiness(interest, self);
            v.borrow_mut().pop();
            res
        })
    }
}

impl SyscallDispatcher {
    define_syscall! {

        fn eventfd2(this, cx, initial_value: u64, flags: u64) {

            // `from_bits` rejects exactly the historical
            // `& !(SEMAPHORE|NONBLOCK|CLOEXEC)` set: the type's full set IS
            // the supported set.
            let Some(efd_flags) = LinuxEfdFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let description = OpenDescription::EventFd {
                state: Arc::new(EventFdState::new(initial_value)),
                semaphore: efd_flags.contains(LinuxEfdFlags::SEMAPHORE),
                // EFD_NONBLOCK == O_NONBLOCK, so the isolated bit IS the
                // status-flag word the base expects.
                base: OpenDescriptionBase::new((efd_flags & LinuxEfdFlags::NONBLOCK).bits()),
            };
            let status = (efd_flags & LinuxEfdFlags::NONBLOCK).bits();
            Ok(this.install_fd_with_status_flags(
                description,
                status,
                linux_fd_flags_from_open_flags(flags),
            ))

        }

        fn pselect6(this, cx, nfds: u64, readfds: GuestPtr, writefds: GuestPtr, exceptfds: GuestPtr, timeout: GuestPtr, sigmask: GuestPtr) {

            // Linux rejects nfds < 0 with EINVAL BEFORE anything else. nfds is an
            // `int`: read the LOW 32 bits as signed. The guest may pass a negative
            // either sign-extended (0xFFFF..FFFF) or, on x86_64 where an int arg
            // leaves the upper register bits undefined, zero-extended (0xFFFFFFFF)
            // — `as i32` catches both, whereas `as i64` missed the zero-extended
            // form and fell through to an EFAULT on the bad fd_set pointer
            // (select03). Without this, pselect6(-1, ...) — LTP pselect02 case 2 —
            // also blocks the test child forever (watchdog SIGALRM → TBROK).
            if (nfds as i32) < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let nfds = GuestLen::try_from_arg(nfds)?.0;
            let readfds_addr = readfds.0;
            let writefds_addr = writefds.0;
            let exceptfds_addr = exceptfds.0;
            let timeout_addr = timeout.0;
            let sigmask_addr = sigmask.0;
            let request_number = cx.number();
            // x86_64 select(2) reaches this handler via CARRICK_PRIVATE_X86_SELECT:
            // its timeout (arg4) is a *timeval (tv_usec), not pselect6's *timespec
            // (tv_nsec), and it has no sigmask. pselect6(72) keeps the decode below.
            let is_select = request_number == carrick_abi::CARRICK_PRIVATE_X86_SELECT;
            let request_args = cx.raw_args();
            let tid = cx.tid();
            let kernel = cx.kernel;
            let memory = &mut *cx.memory;
            let reporter = cx.reporter;

            // Linux's pselect6 ABI for the 6th argument is NOT a bare sigset_t *
            // but a pointer to `struct { const sigset_t *ss; size_t ss_len; }`
            // (the kernel "sigset_argpack"). We read the pair, then if ss != 0
            // and ss_len == LINUX_RT_SIGSET_SIZE, read the actual 8-byte sigset
            // for the bitmask. NULL outer arg means "no mask change". This bit
            // mask gates the waiter via `block_signals`: a blocked signal stays
            // pending instead of EINTR-ing the wait (LTP pselect02 case).
            let block_signals: carrick_abi::SigSet = if sigmask_addr != 0 {
                match memory.read_struct::<LinuxSigsetArgpack>(sigmask_addr) {
                    Ok(pack) => {
                        let ss_ptr = pack.ss;
                        let ss_len = pack.ss_len;
                        if ss_ptr != 0 && ss_len == crate::linux_abi::LINUX_RT_SIGSET_SIZE {
                            match memory.read_bytes(ss_ptr, ss_len as usize) {
                                Ok(bytes) => carrick_abi::SigSet::from_raw(u64::from_le_bytes(
                                    bytes.try_into().unwrap_or([0; 8]),
                                )),
                                Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                            }
                        } else {
                            carrick_abi::SigSet::EMPTY
                        }
                    }
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            } else {
                carrick_abi::SigSet::EMPTY
            };
            // pselect6's sigmask (when the outer argpack pointer is non-NULL)
            // REPLACES the thread's persistent mask for the wait; select /
            // NULL-mask pselect6 is a plain additive wait.
            let sig_mask = if sigmask_addr != 0 {
                carrick_abi::WaitSigMask::Replace(block_signals)
            } else {
                carrick_abi::WaitSigMask::NONE
            };
            if this.has_deliverable_dispatch_pending_for_wait(kernel, tid, sig_mask) {
                if let carrick_abi::WaitSigMask::Replace(mask) = sig_mask {
                    this.begin_sigsuspend(kernel, tid, mask);
                }
                return Ok(DispatchOutcome::errno(LINUX_EINTR));
            }

            // Decode timespec → millis for libc::poll. NULL = block forever (-1).
            let timeout_ms: i32 = if timeout_addr == 0 {
                -1
            } else if is_select {
                // select(2): the timeout is a *timeval (tv_sec + tv_usec), not a
                // *timespec. Linux rejects sec<0 or usec out of [0,1e6) → EINVAL.
                match read_kernel_struct::<LinuxTimeval>(memory, timeout_addr) {
                    Ok(tv) => {
                        let sec = tv.tv_sec;
                        let usec = tv.tv_usec;
                        if sec < 0 || !(0..1_000_000).contains(&usec) {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        let ms = sec
                            .saturating_mul(1000)
                            .saturating_add(usec.saturating_add(999) / 1000);
                        if ms <= 0 {
                            0
                        } else if ms > i32::MAX as i64 {
                            i32::MAX
                        } else {
                            ms as i32
                        }
                    }
                    // Faulting *timeval pointer -> EFAULT (see the *timespec arm
                    // below); select03 "Faulty timeout" for the x86 select(2) path.
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            } else {
                match read_kernel_struct::<LinuxTimespec>(memory, timeout_addr) {
                    Ok(timespec) => {
                        let sec = timespec.tv_sec;
                        let nsec = timespec.tv_nsec;
                        // Linux rejects an invalid timespec with EINVAL (negative
                        // seconds/nanoseconds or nsec out of [0, 1e9)) — LTP
                        // pselect02 case 3. carrick previously clamped it to 0
                        // (returned "timed out" instead of erroring).
                        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        let ms = sec
                            .saturating_mul(1000)
                            .saturating_add(nsec.saturating_add(999_999) / 1_000_000);
                        if ms <= 0 {
                            0
                        } else {
                            let dur = std::time::Duration::from_millis(ms as u64);
                            let clock = Arc::clone(cx.kernel.task().container().clock());
                            let scaled = clock.scale_timeout(dur);
                            i32::try_from(scaled.as_millis()).unwrap_or(i32::MAX)
                        }
                    }
                    // A bad timeout pointer: the raw pselect6/select syscall reads
                    // the timeout in-kernel, so a faulting pointer is EFAULT (the
                    // Linux copy_from_user failure). tst_get_bad_addr hands a
                    // PROT_NONE page whose read the shared memory gate rejects
                    // WITHOUT injecting a guest fault, so surface EFAULT here rather
                    // than clamping to a 0 timeout (which let select() return a
                    // spurious ready count) — LTP select03 "Faulty timeout". (The
                    // glibc select() variant instead touches the page in userspace
                    // and dies with SIGSEGV, which the test also accepts.)
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            };

            // Pull each fd_set into memory.
            let read_set = this.read_optional_fd_set(memory, readfds_addr, nfds)??;
            let write_set = this.read_optional_fd_set(memory, writefds_addr, nfds)??;
            let except_set = this.read_optional_fd_set(memory, exceptfds_addr, nfds)??;

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
            let mut host_map: Vec<Option<HostPollTarget>> = Vec::new();
            for fd in 0..nfds {
                let r = read_set.as_ref().is_some_and(|s| fd_set_contains(s, fd));
                let w = write_set.as_ref().is_some_and(|s| fd_set_contains(s, fd));
                let e = except_set.as_ref().is_some_and(|s| fd_set_contains(s, fd));
                if !(r || w || e) {
                    continue;
                }
                let fd_i32 = i32::try_from(fd).map_err(|_| DispatchError::LengthTooLarge(u64::MAX))?;
                if !this.fd_is_valid(fd_i32) {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
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
                host_map.push(this.host_poll_target(fd_i32, events));
            }

            // revents per entry, filled by whichever path runs.
            let mut revents: Vec<i16> = vec![0; owners.len()];
            let all_host: Option<Vec<HostPollTarget>> = host_map.iter().copied().collect();

            if owners.is_empty() {
                if timeout_ms == 0 && sigmask_addr == 0 {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
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
                    fds: WaitFds::empty(),
                    timeout,
                    sig_mask,
                    completion: FdWaitCompletion::Fd { on_timeout: 0 },
                });
            } else if let Some(host_fds) = all_host {
                let mut pollfds: Vec<libc::pollfd> = host_fds
                    .iter()
                    .map(|t| libc::pollfd {
                        fd: t.host_fd,
                        events: t.host_events,
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
                // signal-interruptible waiter via WaitOnFds (mirrors how
                // ppoll uses WaitOnFds).
                let n = unsafe {
                    libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 0)
                };
                if let Err(errno) = n.host_syscall_errno() {
                    return Ok(DispatchOutcome::errno(errno));
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
                        .map(|t| (t.host_fd, t.host_events))
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
                    let files = this.captured_file_table();
                    let wait_fds = match WaitFds::raw(wait_fds)
                        .with_guest_slots(&files, owners.iter().map(|(fd, _)| *fd))
                    {
                        Ok(wait_fds) => wait_fds,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    return Ok(DispatchOutcome::WaitOnFds {
                        fds: wait_fds,
                        timeout,
                        sig_mask,
                        completion: FdWaitCompletion::Select { clear_on_timeout },
                    });
                }
                for (i, (slot, p)) in revents.iter_mut().zip(pollfds.iter()).enumerate() {
                    // A readiness pipe only says "something changed"; the
                    // guest-visible events come from the description itself.
                    *slot = if host_fds[i].readiness_pipe {
                        if p.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                            this.poll_ready_events(owners[i].0, events_list[i])
                        } else {
                            0
                        }
                    } else {
                        p.revents
                    };
                }
            } else {
                // Mixed / synthetic fds: evaluate current readiness without holding the wait loop synchronously.
                let mut any = false;
                for (i, (fd, _)) in owners.iter().enumerate() {
                    let rev = this.poll_ready_events(*fd, events_list[i]);
                    revents[i] = rev;
                    if rev != 0 {
                        any = true;
                    }
                }
                if !any && timeout_ms != 0 {
                    let mut timeout = if timeout_ms < 0 {
                        None
                    } else {
                        Some(std::time::Duration::from_millis(timeout_ms as u64))
                    };
                    for (fd, _) in &owners {
                        if *fd >= 0 {
                            if let Some(open_file) = this.open_file(*fd) {
                                if let Some(rem) = open_file.timerfd_remaining_timeout() {
                                    timeout = match timeout {
                                        None => Some(rem),
                                        Some(prev) => Some(prev.min(rem)),
                                    };
                                }
                            }
                        }
                    }
                    let mut wait_targets = Vec::new();
                    for (i, (fd, _)) in owners.iter().enumerate() {
                        if *fd < 0 {
                            continue;
                        }
                        if let Some(target) = this.host_poll_target(*fd, events_list[i]) {
                            wait_targets.push((target.host_fd, target.host_events));
                        }
                    }
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
                    let files = this.captured_file_table();
                    let wait_fds = match WaitFds::raw(wait_targets)
                        .with_guest_slots(&files, owners.iter().map(|(fd, _)| *fd))
                    {
                        Ok(wait_fds) => wait_fds,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    return Ok(DispatchOutcome::WaitOnFds {
                        fds: wait_fds,
                        timeout,
                        sig_mask,
                        completion: FdWaitCompletion::Select { clear_on_timeout },
                    });
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
                    && (revs & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0
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
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            if let Some(s) = &new_write
                && memory.write_bytes(writefds_addr, s).is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            if let Some(s) = &new_except
                && memory.write_bytes(exceptfds_addr, s).is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
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
            let request_number = cx.number();
            // x86_64 poll(2) reaches this handler via CARRICK_PRIVATE_X86_POLL:
            // arg2 (`timeout`) is an INT timeout_ms (not a *timespec) and there is
            // no sigmask. ppoll(73) keeps the *timespec + sigmask decode below.
            let is_poll = request_number == carrick_abi::CARRICK_PRIVATE_X86_POLL;
            let request_args = cx.raw_args();
            let tid = cx.tid();
            let kernel = cx.kernel;
            let memory = &mut *cx.memory;
            let reporter = cx.reporter;

            // Decode timeout. NULL pointer means block forever; non-NULL points
            // to a `struct timespec { i64 tv_sec; i64 tv_nsec; }`. We translate
            // to milliseconds for libc::poll (-1 = forever, 0 = immediate).
            let timeout_ms: i32 = if is_poll {
                // poll: arg2 IS the int timeout_ms (-1 = block forever, 0 = return
                // now, N = N ms). The raw register value is sign-correct in its
                // low 32 bits.
                timeout_address as i32
            } else if timeout_address == 0 {
                -1
            } else {
                match read_kernel_struct::<LinuxTimespec>(memory, timeout_address) {
                    Ok(timespec) => {
                        if !super::linux_timeout_timespec_is_valid(timespec) {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        let sec = timespec.tv_sec;
                        let nsec = timespec.tv_nsec;
                        let ms = sec
                            .saturating_mul(1000)
                            .saturating_add(nsec.saturating_add(999_999) / 1_000_000);
                        if ms <= 0 {
                            0
                        } else {
                            let dur = std::time::Duration::from_millis(ms as u64);
                            let clock = Arc::clone(cx.kernel.task().container().clock());
                            let scaled = clock.scale_timeout(dur);
                            i32::try_from(scaled.as_millis()).unwrap_or(i32::MAX)
                        }
                    }
                    _ => 0,
                }
            };
            let clock = Arc::clone(cx.kernel.task().container().clock());
            let timeout_ms = if timeout_ms > 0 && is_poll && clock.is_scaled() {
                let dur = std::time::Duration::from_millis(timeout_ms as u64);
                let scaled = clock.scale_timeout(dur);
                i32::try_from(scaled.as_millis()).unwrap_or(i32::MAX)
            } else {
                timeout_ms
            };

            // ppoll(fds, nfds, timeout, sigmask, sigsetsize): capture the sigmask
            // as a typed SigSet (converted at the guest sigset_t read) so a blocked
            // signal doesn't interrupt the wait (it stays pending, delivered after
            // the syscall). Mirrors epoll_pwait. Read before the pollfd loop
            // (returns an owned Vec, so the `memory` borrow is released).
            let block_signals: carrick_abi::SigSet = if is_poll {
                // poll(2) has no sigmask argument.
                carrick_abi::SigSet::EMPTY
            } else if sigmask_addr != 0 {
                if sigsetsize != crate::linux_abi::LINUX_RT_SIGSET_SIZE {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                match memory.read_bytes(
                    sigmask_addr,
                    crate::linux_abi::LINUX_RT_SIGSET_SIZE as usize,
                ) {
                    Ok(bytes) => {
                        let mut le = [0u8; 8];
                        le.copy_from_slice(&bytes[..8]);
                        carrick_abi::SigSet::from_raw(u64::from_le_bytes(le))
                    }
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            } else {
                carrick_abi::SigSet::EMPTY
            };
            // ppoll's sigmask (when present) REPLACES the thread's persistent
            // mask for the wait; poll(2) / NULL-mask ppoll is a plain additive
            // wait.
            let sig_mask = if !is_poll && sigmask_addr != 0 {
                carrick_abi::WaitSigMask::Replace(block_signals)
            } else {
                carrick_abi::WaitSigMask::NONE
            };
            if this.has_deliverable_dispatch_pending_for_wait(kernel, tid, sig_mask) {
                if let carrick_abi::WaitSigMask::Replace(mask) = sig_mask {
                    this.begin_sigsuspend(kernel, tid, mask);
                }
                return Ok(DispatchOutcome::errno(LINUX_EINTR));
            }

            // Linux rejects an nfds greater than the guest's soft RLIMIT_NOFILE
            // with EINVAL BEFORE touching the fds array (poll/ppoll: do_sys_poll
            // caps at rlimit(RLIMIT_NOFILE)). Without this, a huge nfds (LTP
            // ppoll01 INVALID_NFDS passes nfds=0xFFFFFFFF) walks the pollfd loop
            // off the end of the array and faults into EFAULT instead — and would
            // also try to reserve a multi-GB Vec below.
            if nfds > this.nofile_limit() as usize {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

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
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                };
                let pollfd = read_pollfd(memory, address)?;
                fds.push(pollfd);
                addresses.push(address);
            }
            // Map guest fds → host fds where possible. Fast path requires
            // every fd be host-backed (stdio bare, HostPipe, HostSocket) or
            // reachable through a readiness pipe; see `host_poll_target`.
            let host_fds: Option<Vec<(i32, i16, bool)>> = fds
                .iter()
                .map(|p| {
                    this.host_poll_target(p.fd, p.events)
                        .map(|t| (t.host_fd, t.host_events, t.readiness_pipe))
                })
                .collect();
            if let Some(host_fds) = host_fds {
                let mut sys_pollfds: Vec<libc::pollfd> = fds
                    .iter()
                    .zip(host_fds.iter())
                    .map(|(_, (hf, events, _))| libc::pollfd {
                        fd: *hf,
                        events: *events,
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
                    return Ok(DispatchOutcome::errno(errno));
                }
                let mut ready = 0i64;
                for (i, p) in sys_pollfds.iter().enumerate() {
                    let mut pollfd = fds[i];
                    let (_, _, is_readiness_pipe) = host_fds[i];
                    if is_readiness_pipe {
                        if p.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                            pollfd.revents = this.poll_ready_events(pollfd.fd, pollfd.events);
                        } else {
                            pollfd.revents = 0;
                        }
                    } else {
                        pollfd.revents = p.revents;
                    }
                    // Darwin poll(2) has no POLLRDHUP bit. Reconstruct Linux's
                    // socket half-close readiness from kqueue EV_EOF before
                    // returning the all-host fast-path result; the per-fd path
                    // does the same in poll_ready_events.
                    if pollfd.events & LINUX_POLLRDHUP != 0
                        && this.socket_guest_type(pollfd.fd).is_some()
                        && host_stream_socket_rdhup(p.fd)
                    {
                        pollfd.revents |= LINUX_POLLIN | LINUX_POLLRDHUP;
                    }
                    // macOS poll() on a regular file returns POLLPRI whenever the
                    // caller requested it (the BSD vnode "always ready" default);
                    // Linux only ever sets POLLPRI on a genuine out-of-band
                    // condition, which only a socket can carry. Strip the spurious
                    // bit for any fd that cannot hold OOB data so a regular-file
                    // poll matches Linux (LTP ppoll01 NORMAL: POLLIN|POLLPRI|POLLOUT
                    // requested on a regular file must return POLLIN|POLLOUT).
                    if pollfd.revents & libc::POLLPRI != 0 && !this.fd_supports_epoll_oob(pollfd.fd) {
                        pollfd.revents &= !libc::POLLPRI;
                    }
                    if pollfd.revents != 0 {
                        ready += 1;
                    }
                    // Always write back (zeroed revents on a not-ready probe) so a
                    // later timeout completion needs no further writes.
                    if write_kernel_struct_raw(memory, addresses[i], &pollfd).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
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
                let wait_fds: Vec<(i32, i16)> = sys_pollfds
                    .iter()
                    .zip(fds.iter())
                    .filter(|(p, g)| p.fd >= 0 && g.fd >= 0)
                    .map(|(p, _)| (p.fd, p.events))
                    .collect();
                // poll/ppoll: a timeout means "no fds ready" → return 0.
                let files = this.captured_file_table();
                let wait_fds = match WaitFds::raw(wait_fds)
                    .with_guest_slots(&files, fds.iter().filter(|p| p.fd >= 0).map(|pollfd| pollfd.fd))
                {
                    Ok(wait_fds) => wait_fds,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                return Ok(DispatchOutcome::WaitOnFds {
                    fds: wait_fds,
                    timeout,
                    sig_mask,
                    completion: FdWaitCompletion::Fd { on_timeout: 0 },
                });
            }

            // Mixed / synthetic fds: evaluate current readiness and yield cancellable continuation if not ready.
            let mut ready = 0i64;
            for (index, pollfd) in fds.iter_mut().enumerate() {
                pollfd.revents = this.poll_ready_events(pollfd.fd, pollfd.events);
                if pollfd.revents != 0 {
                    ready += 1;
                }
                if write_kernel_struct_raw(memory, addresses[index], pollfd).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }
            if ready > 0 || timeout_ms == 0 {
                return Ok(DispatchOutcome::Returned { value: ready });
            }

            let mut timeout = if timeout_ms < 0 {
                None
            } else {
                Some(std::time::Duration::from_millis(timeout_ms as u64))
            };
            for pollfd in &fds {
                if pollfd.fd >= 0 {
                    if let Some(open_file) = this.open_file(pollfd.fd) {
                        if let Some(rem) = open_file.timerfd_remaining_timeout() {
                            timeout = match timeout {
                                None => Some(rem),
                                Some(prev) => Some(prev.min(rem)),
                            };
                        }
                    }
                }
            }
            let mut wait_targets = Vec::new();
            for pollfd in &fds {
                if pollfd.fd < 0 {
                    continue;
                }
                if let Some(target) = this.host_poll_target(pollfd.fd, pollfd.events) {
                    wait_targets.push((target.host_fd, target.host_events));
                }
            }
            let files = this.captured_file_table();
            let wait_fds = match WaitFds::raw(wait_targets)
                .with_guest_slots(&files, fds.iter().filter(|p| p.fd >= 0).map(|pollfd| pollfd.fd))
            {
                Ok(wait_fds) => wait_fds,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            return Ok(DispatchOutcome::WaitOnFds {
                fds: wait_fds,
                timeout,
                sig_mask,
                completion: FdWaitCompletion::Poll { on_timeout: 0 },
            });
        }
    }
}
