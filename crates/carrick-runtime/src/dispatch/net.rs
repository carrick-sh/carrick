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

const EPOLL_REBIND_REASON_IO_REARM: u32 = 1;
const EPOLL_REBIND_REASON_CLOSE_DETACH: u32 = 2;

const EPOLL_REBIND_REASON_WAIT_SAMPLE: u32 = 3;
const EPOLL_REBIND_REASON_CTL_DEL: u32 = 4;

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
pub(super) mod lifecycle;
pub(super) use lifecycle::host_stream_socket_rdhup;
pub(super) mod netlink;
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

fn remove_epoll_interest(
    interest: &mut HashMap<i32, EpollInterest>,
    synthetic_interest_count: &mut usize,
    fd: i32,
) -> Option<EpollInterest> {
    let removed = interest.remove(&fd)?;
    if !removed.host_poll_source {
        *synthetic_interest_count = synthetic_interest_count.saturating_sub(1);
    }
    Some(removed)
}

fn merge_epoll_edge_sample(
    accumulated: &mut (u32, u64),
    edge_bits: u32,
    edge_readiness_count: u64,
) {
    accumulated.0 |= edge_bits;
    // Darwin reports one kqueue record per direction. EVFILT_WRITE's `data`
    // is socket send-buffer capacity (often ~8 MiB), not readable bytes. Do
    // not let that count poison EPOLLET's read-growth baseline when read and
    // write records for one bidirectional socket land in the same batch.
    if edge_bits & LINUX_EPOLLIN != 0 {
        accumulated.1 = accumulated.1.max(edge_readiness_count);
    }
}

fn epoll_wait_sample_needs_host_rebind(
    before: u32,
    raw: u32,
    read_avail_changed: bool,
    clear_write_backpressure: bool,
    edge_drained: bool,
    masked_ready: bool,
    masked_arrival_source: bool,
) -> bool {
    // BSD edge filters use EV_DISPATCH and therefore need an explicit rebind
    // after a delivered event. A masked event whose readiness snapshot did not
    // change is different: re-adding the filter can immediately reproduce the
    // same event when NOTE_LOWAT cannot express `last_read_avail + 1` (for
    // example, a stream socket already at its receive-buffer ceiling, or a
    // consumption path rebinds it through `epoll_rearm_after_io`. Listening
    // sockets are different: EVFILT_READ `data` is the pending-connection
    // count, and the filter must stay armed so NOTE_LOWAT can observe a later
    // arrival even when a redundant delivery did not change the current count.
    before != raw
        || read_avail_changed
        || clear_write_backpressure
        || (edge_drained && (!masked_ready || masked_arrival_source))
}

fn epoll_io_progress_needs_host_rebind(
    before_ready: u32,
    after_ready: u32,
    before_read_avail: u64,
    after_read_avail: u64,
) -> bool {
    before_ready != after_ready || before_read_avail != after_read_avail
}

fn epoll_ready_sample_is_current(
    sampled_reg_gen: u32,
    sampled_io_gen: u64,
    live_reg_gen: u32,
    live_io_gen: u64,
) -> bool {
    sampled_reg_gen == live_reg_gen && sampled_io_gen == live_io_gen
}

#[cfg(test)]
mod epoll_edge_sample_tests {
    use super::*;

    #[test]
    fn writable_capacity_does_not_poison_read_growth_baseline() {
        let mut accumulated = (LINUX_EPOLLIN, 35);

        merge_epoll_edge_sample(&mut accumulated, LINUX_EPOLLOUT, 8 * 1024 * 1024);

        assert_eq!(accumulated, (LINUX_EPOLLIN | LINUX_EPOLLOUT, 35));
    }

    #[test]
    fn unchanged_masked_edge_stays_disarmed_until_io_progress() {
        assert!(!epoll_wait_sample_needs_host_rebind(
            LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            false,
            false,
            true,
            true,
            false,
        ));
        assert!(!epoll_wait_sample_needs_host_rebind(
            LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            false,
            false,
            false,
            true,
            false,
        ));
        assert!(epoll_wait_sample_needs_host_rebind(
            0,
            LINUX_EPOLLIN,
            true,
            false,
            true,
            false,
            false,
        ));
        assert!(epoll_wait_sample_needs_host_rebind(
            LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            false,
            false,
            true,
            true,
            true,
        ));

        assert!(epoll_wait_sample_needs_host_rebind(
            LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            false,
            false,
            true,
            false,
            false,
        ));
    }

    #[test]
    fn partial_read_progress_rebinds_the_lower_growth_threshold() {
        assert!(epoll_io_progress_needs_host_rebind(
            LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            8 * 1024 * 1024,
            3 * 1024 * 1024,
        ));
    }

    #[test]
    fn readiness_sample_before_io_cannot_relatch_consumed_edge() {
        assert!(!epoll_ready_sample_is_current(7, 11, 7, 12));
    }
}

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
    fn fd_is_epollable(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        if open_file
            .description
            .concrete_backing::<crate::dispatch::ioring::IoUringBacking>()
            .is_some()
        {
            return true;
        }
        let Some(open) = open_file.description.read() else {
            return false;
        };
        match &*open {
            OpenDescription::File { .. }
            | OpenDescription::InMemoryFile { .. }
            | OpenDescription::Directory { .. }
            | OpenDescription::SyntheticFile { .. } => false,
            OpenDescription::HostFile { metadata, .. } => {
                matches!(metadata.kind, crate::rootfs::RootFsEntryKind::CharDevice)
            }
            _ => true,
        }
    }

    fn fd_supports_epoll_oob(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        matches!(
            open_file.description.read().as_deref(),
            Some(OpenDescription::HostSocket { .. })
        )
    }

    fn fd_supports_read_lowat(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        matches!(
            open_file.description.read().as_deref(),
            Some(OpenDescription::HostSocket { .. })
        )
    }

    fn fd_is_listening_socket(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        matches!(
            open_file.description.read().as_deref(),
            Some(OpenDescription::HostSocket { base, .. }) if base.listening()
        )
    }

    fn epoll_path_reaches_desc(
        &self,
        current_desc: &Arc<crate::kernel::FileDescription>,
        target_id: crate::kernel::FileDescriptionId,
        depth: usize,
        seen: &mut std::collections::BTreeSet<crate::kernel::FileDescriptionId>,
    ) -> bool {
        if current_desc.id() == target_id || depth >= 5 || !seen.insert(current_desc.id()) {
            return true;
        }
        let Some(children) = current_desc.epoll_targets() else {
            return false;
        };
        children
            .into_iter()
            .any(|child| self.epoll_path_reaches_desc(&child, target_id, depth + 1, seen))
    }

    fn epoll_add_would_loop_desc(
        &self,
        target_desc: &Arc<crate::kernel::FileDescription>,
        epoll_id: crate::kernel::FileDescriptionId,
    ) -> bool {
        let mut seen = std::collections::BTreeSet::new();
        self.epoll_path_reaches_desc(target_desc, epoll_id, 0, &mut seen)
    }

    fn epoll_effective_interest(
        &self,
        fd: i32,
        events: u32,
        last_ready: u32,
        last_read_avail: u64,
        write_backpressured: bool,
    ) -> carrick_hal::event::Interest {
        // Wire→typed seam: the guest event word is a raw u32; epoll ACCEPTS
        // unknown bits, so retain them rather than reject.
        let mut interest = epoll_interest_for(LinuxEpollEvents::from_bits_retain(events));
        // Guest EPOLLET is enforced by the software `last_ready` latch. Once
        // EPOLLOUT or a terminal HUP/ERR edge has been delivered, keeping write
        // interest armed can wake an epoll waiter for host writability that the
        // Linux-facing sampler will keep masking. Drop the write filter until
        // either guest I/O consumes the edge or a write returns EAGAIN and
        // explicitly asks to watch for writability again. Keep read armed:
        // read-side ET uses FIONREAD growth to detect a new edge while data
        // remains buffered.
        if events & LINUX_EPOLLET != 0 {
            if interest.write
                && last_ready & (LINUX_EPOLLOUT | LINUX_EPOLLHUP | LINUX_EPOLLERR) != 0
                && !write_backpressured
            {
                interest.write = false;
            }
            if interest.read {
                if last_ready & (LINUX_EPOLLHUP | LINUX_EPOLLERR) != 0 {
                    interest.read = false;
                } else if last_ready & LINUX_EPOLLIN != 0 {
                    if last_read_avail > 0 && self.fd_supports_read_lowat(fd) {
                        interest.read_lowat = Some(last_read_avail.saturating_add(1));
                    } else {
                        interest.read = false;
                    }
                }
            }
        }
        // A one-way pipe/FIFO read end is never writable under Linux, so it must
        // never carry a write filter. FreeBSD's kqueue arms `EVFILT_WRITE` on a
        // pipe read end and fires it immediately (the read end is reported
        // "writable"); that spurious edge wakes a blocked edge-triggered
        // `epoll_wait` and pollutes the readiness latch with `EPOLLOUT`, masking
        // the real `EPOLLIN|EPOLLHUP` EOF. Suppressing write interest here keeps
        // the host registration faithful to Linux semantics on every host.
        if interest.write && self.host_fd_is_oneway_pipe_read_end(fd) {
            interest.write = false;
            interest.read = true;
        }
        if interest.oob && !self.fd_supports_epoll_oob(fd) {
            interest.oob = false;
        }
        // FreeBSD/NetBSD kqueue has no usable OOB filter — `register_io` with an
        // OOB interest returns ENOTSUP and would fail the whole `epoll_ctl(ADD)`.
        // Unlike macOS (whose `poll(2)` never surfaces `POLLPRI`, so the
        // EVFILT_EXCEPT/NOTE_OOB filter is the only OOB signal), FreeBSD/NetBSD
        // native `poll(2)` DOES report `POLLPRI`, so EPOLLPRI readiness is
        // computed by the `libc::poll(POLLPRI)` recompute in `epoll_ready_events`
        // — the kqueue OOB filter is both unsupported and unnecessary here. Drop
        // it from the host registration only; the guest's requested EPOLLPRI
        // interest is unaffected (readiness still keys off `event.events`).
        // (probe `epollpri`.)
        #[cfg(any(feature = "platform-freebsd", feature = "platform-netbsd"))]
        {
            interest.oob = false;
        }
        interest
    }

    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    fn rebind_epoll_host_registration(
        &self,
        kqueue: &Arc<EpollKqueue>,
        interest: &HashMap<i32, EpollInterest>,
        host_fd: HostFd,
        reason: u32,
        excluded_survivor_fd: Option<i32>,
    ) {
        let mut survivor: Option<(i32, u32)> = None;
        let mut union_events = 0u32;
        let mut union_interest = carrick_hal::event::Interest::default();
        let mut read_lowat: Option<Option<u64>> = None;
        for (&other, slot) in interest.iter() {
            if self.host_fd_for_poll(other) != Some(host_fd) {
                continue;
            }
            if Some(other) != excluded_survivor_fd {
                survivor.get_or_insert((other, slot.reg_gen));
            }
            union_events |= slot.event.events;
            let effective = self.epoll_effective_interest(
                other,
                slot.event.events,
                slot.last_ready,
                slot.last_read_avail,
                slot.write_backpressured,
            );
            union_interest.read |= effective.read;
            union_interest.write |= effective.write;
            union_interest.oob |= effective.oob;
            if effective.read {
                read_lowat = match (read_lowat, effective.read_lowat) {
                    (None, lowat) => Some(lowat),
                    (Some(Some(current)), Some(next)) => Some(Some(current.min(next))),
                    (Some(_), None) => Some(None),
                    (current, Some(_)) => current,
                };
            }
        }
        union_interest.read_lowat = read_lowat.flatten();
        let (survivor_fd, survivor_gen) = survivor.unwrap_or((-1, 0));
        let effective_bits = u32::from(union_interest.read)
            | (u32::from(union_interest.write) << 1)
            | (u32::from(union_interest.oob) << 2);
        crate::probes::epoll_rebind(
            reason,
            host_fd.get(),
            survivor_fd,
            survivor_gen,
            union_events,
            effective_bits,
        );

        kqueue.with_mux(|mux| match survivor {
            Some((sfd, sgen)) => {
                let _ = mux.register_io(
                    host_fd.get(),
                    pack_epoll_udata(sfd, sgen),
                    union_interest,
                    epoll_host_trigger_mode(LinuxEpollEvents::from_bits_retain(union_events)),
                );
            }
            None => {
                let _ = mux.deregister(host_fd.get());
            }
        });
    }

    fn epoll_ready_events(&self, fd: i32, requested_events: u32) -> u32 {
        let Some(open_file) = self.open_file(fd) else {
            return 0;
        };
        let interest = carrick_abi::LinuxEpollEvents::from_bits_retain(requested_events);
        open_file.description.readiness(interest, self).bits()
    }

    fn host_read_avail_for_poll(&self, fd: i32) -> u64 {
        // Bytes carrick queued on a socket outside the host kernel
        // (`synthetic_recv`). Counted into the ET read-growth baseline so a
        // gateway reply is a visible arrival, exactly as `pipe.buffered_bytes()`
        // is for an in-memory pipe; FIONREAD on the host fd cannot see them.
        let mut synthetic_bytes = 0u64;
        if let Some(open_file) = self.open_file(fd) {
            let Some(open) = open_file.description.read() else {
                return 0;
            };
            match &*open {
                OpenDescription::PipeReader { pipe, .. } => return pipe.buffered_bytes() as u64,
                OpenDescription::InMemorySocket { socket, .. } => {
                    return socket.buffered_bytes() as u64;
                }
                OpenDescription::HostSocket { synthetic_recv, .. } => {
                    synthetic_bytes = synthetic_recv
                        .iter()
                        .map(|(payload, _source)| payload.len() as u64)
                        .sum();
                }
                _ => {}
            }
        }
        let Some(host_fd) = self.host_fd_for_poll(fd) else {
            return synthetic_bytes;
        };
        let mut avail: libc::c_int = 0;
        let rc = unsafe { libc::ioctl(host_fd.get(), libc::FIONREAD, &mut avail) };
        let host = if rc == 0 && avail > 0 {
            avail as u64
        } else {
            0
        };
        host.saturating_add(self.staged_splice_pipe_bytes(fd) as u64)
            .saturating_add(synthetic_bytes)
    }

    /// Consumption-based EPOLLET re-arm for the Linux lane's sampled epoll
    /// emulation: after the guest performs a read-family syscall on fd X,
    /// clear the read-side bits of `last_ready` for X in every epoll interest
    /// set watching X (write-side bits for write-family syscalls).
    ///
    /// The Linux-lane ET latch is a readiness DIFF between consecutive
    /// `epoll_pwait` samples (`raw & !last_ready`), so a drain + refill that
    /// both land BETWEEN two samples is indistinguishable from "asserted
    /// since the last delivery": the new edge is masked from delivery AND
    /// (per the ET park-set rule) excluded from the ppoll park — the waiter
    /// parks forever. Captured live in go-os TestSpliceFile/Basic-TCP: the
    /// writer's `write(1025)+close` lands between the reader's splice EAGAIN
    /// (drain) and its `epoll_pwait` re-park; the sample sees IN still
    /// asserted, masks it, and the netpoller M never wakes. macOS doesn't
    /// need this: kqueue's `EV_CLEAR` re-arms in-kernel on consumption.
    ///
    /// An I/O syscall on X is exactly the consumption signal the sampling
    /// can't see — the guest serviced the delivered edge, so the next
    /// asserted sample is a NEW edge and must be delivered. Clearing on
    /// every read (not only EAGAIN) can at worst re-deliver one spurious
    /// event, which epoll's contract permits (and ET consumers drain to
    /// EAGAIN by contract). HUP/ERR are cleared on both directions: poll(2)
    /// reports them regardless of the requested set, and a guest that just
    /// touched the fd must see a still-standing terminal condition again.
    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-linux",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    pub(crate) fn epoll_rearm_after_io(&self, request: &SyscallRequest, outcome: &DispatchOutcome) {
        const READ_CLEAR: u32 =
            LINUX_EPOLLIN | LINUX_EPOLLRDHUP | LINUX_EPOLLPRI | LINUX_EPOLLHUP | LINUX_EPOLLERR;
        const WRITE_CLEAR: u32 = LINUX_EPOLLOUT | LINUX_EPOLLHUP | LINUX_EPOLLERR;
        let positive = matches!(outcome, DispatchOutcome::Returned { value } if *value > 0);
        let positive_value = match outcome {
            DispatchOutcome::Returned { value } if *value > 0 => Some(*value as u64),
            _ => None,
        };
        let zero = matches!(outcome, DispatchOutcome::Returned { value } if *value == 0);
        let eagain = matches!(outcome, DispatchOutcome::Errno { errno } if *errno == LINUX_EAGAIN);
        let read_consumed = positive || zero || eagain;
        let write_consumed = positive;
        let a = |i: usize| request.arg(i) as i32;
        let read_progress_bytes = if positive {
            match request.number.raw() {
                // read / readv / pread64 / preadv / preadv2, recvfrom /
                // recvmsg / recvmmsg: positive return is bytes consumed.
                63 | 65 | 67 | 69 | 286 | 207 | 212 | 243 => positive_value,
                // sendfile/splice/copy_file_range/tee: positive return is bytes
                // consumed from the read-side fd.
                71 | 76 | 285 | 77 => positive_value,
                // accept/accept4 consume listener readiness but return a new fd,
                // not a byte count; clear the read latch outright.
                202 | 242 => None,
                _ => None,
            }
        } else {
            None
        };
        let write_eagain_targets: [Option<i32>; 2] = if eagain {
            match request.number.raw() {
                64 | 66 | 68 | 70 | 287 | 206 | 211 | 269 => [Some(a(0)), None],
                71 => [Some(a(0)), None],
                76 | 285 => [Some(a(2)), None],
                77 => [Some(a(1)), None],
                _ => [None, None],
            }
        } else {
            [None, None]
        };
        // (fd, bits-to-clear) per direction the syscall consumed. aarch64 nrs.
        let targets: [Option<(i32, u32)>; 2] = match request.number.raw() {
            // read / readv / pread64 / preadv / preadv2, accept / accept4,
            // recvfrom / recvmsg / recvmmsg: consume the read side of arg0.
            63 | 65 | 67 | 69 | 286 | 202 | 242 | 207 | 212 | 243 if read_consumed => {
                [Some((a(0), READ_CLEAR)), None]
            }
            // write / writev / pwrite64 / pwritev / pwritev2, sendto /
            // sendmsg / sendmmsg: consume the write side of arg0.
            64 | 66 | 68 | 70 | 287 | 206 | 211 | 269 if write_consumed => {
                [Some((a(0), WRITE_CLEAR)), None]
            }
            // sendfile(out_fd, in_fd, ..): reads in_fd, writes out_fd.
            71 if positive => [Some((a(1), READ_CLEAR)), Some((a(0), WRITE_CLEAR))],
            71 if zero || eagain => [Some((a(1), READ_CLEAR)), None],
            // splice(fd_in, off_in, fd_out, ..) / copy_file_range: reads
            // arg0, writes arg2. tee(fd_in, fd_out, ..): reads arg0, writes
            // arg1.
            76 | 285 if positive => [Some((a(0), READ_CLEAR)), Some((a(2), WRITE_CLEAR))],
            76 | 285 if zero || eagain => [Some((a(0), READ_CLEAR)), None],
            77 if positive => [Some((a(0), READ_CLEAR)), Some((a(1), WRITE_CLEAR))],
            77 if zero || eagain => [Some((a(0), READ_CLEAR)), None],
            _ if write_eagain_targets.iter().any(Option::is_some) => [None, None],
            _ => return,
        };
        // Snapshot the registered epoll fds and DROP the set lock before
        // touching any description lock (epoll_ctl registers while holding no
        // description lock either, keeping the order acyclic).
        let epfds: Vec<i32> = self
            .captured_file_table()
            .read_epoll_fds()
            .iter()
            .copied()
            .collect();
        for epfd in epfds {
            let stale = match self.open_file(epfd) {
                None => true,
                Some(open_file) => {
                    let Some(mut open) = open_file.description.write() else {
                        return;
                    };
                    if let OpenDescription::Epoll {
                        interest, kqueue, ..
                    } = &mut *open
                    {
                        let mut snapshot_changed = false;
                        #[cfg(any(
                            feature = "platform-macos",
                            feature = "platform-freebsd",
                            feature = "platform-netbsd"
                        ))]
                        let mut host_rearms: Vec<i32> = Vec::new();
                        for (fd, clear) in targets.iter().flatten() {
                            let target_host_fd = self.host_fd_for_poll(*fd);
                            let target_description = self
                                .open_file(*fd)
                                .map(|file| Arc::clone(&file.description));
                            let matching_fds = interest
                                .keys()
                                .copied()
                                .filter(|candidate| {
                                    *candidate == *fd
                                        || target_host_fd.is_some()
                                            && self.host_fd_for_poll(*candidate) == target_host_fd
                                        || target_description.as_ref().is_some_and(|target| {
                                            self.open_file(*candidate).is_some_and(|candidate| {
                                                Arc::ptr_eq(&candidate.description, target)
                                            })
                                        })
                                })
                                .collect::<Vec<_>>();
                            for matching_fd in matching_fds {
                                let Some(slot) = interest.get_mut(&matching_fd) else {
                                    continue;
                                };
                                let before = slot.last_ready;
                                let before_read_avail = slot.last_read_avail;
                                slot.io_gen = slot.io_gen.wrapping_add(1);
                                crate::event_ring::rec(
                                    crate::event_ring::EPCMSUM,
                                    matching_fd,
                                    slot.io_gen as i32,
                                    *clear as i32,
                                );
                                if clear & READ_CLEAR != 0 {
                                    if let Some(bytes) = read_progress_bytes {
                                        slot.last_read_avail =
                                            slot.last_read_avail.saturating_sub(bytes);
                                        if slot.last_read_avail == 0 {
                                            slot.last_ready &= !READ_CLEAR;
                                        }
                                    } else {
                                        slot.last_ready &= !READ_CLEAR;
                                        slot.last_read_avail = 0;
                                    }
                                }
                                if clear & !READ_CLEAR != 0 {
                                    slot.last_ready &= !(clear & !READ_CLEAR);
                                }
                                if clear & WRITE_CLEAR != 0 {
                                    slot.write_backpressured = false;
                                }
                                if epoll_io_progress_needs_host_rebind(
                                    before,
                                    slot.last_ready,
                                    before_read_avail,
                                    slot.last_read_avail,
                                ) || slot.event.events & LINUX_EPOLLET != 0
                                {
                                    snapshot_changed = true;
                                    #[cfg(any(
                                        feature = "platform-macos",
                                        feature = "platform-freebsd",
                                        feature = "platform-netbsd"
                                    ))]
                                    if let Some(host_fd) = self.host_fd_for_poll(matching_fd) {
                                        host_rearms.push(host_fd.get());
                                    }
                                }
                            }
                        }
                        for fd in write_eagain_targets.iter().flatten() {
                            let target_host_fd = self.host_fd_for_poll(*fd);
                            let target_description = self
                                .open_file(*fd)
                                .map(|file| Arc::clone(&file.description));
                            let matching_fds = interest
                                .keys()
                                .copied()
                                .filter(|candidate| {
                                    *candidate == *fd
                                        || target_host_fd.is_some()
                                            && self.host_fd_for_poll(*candidate) == target_host_fd
                                        || target_description.as_ref().is_some_and(|target| {
                                            self.open_file(*candidate).is_some_and(|candidate| {
                                                Arc::ptr_eq(&candidate.description, target)
                                            })
                                        })
                                })
                                .collect::<Vec<_>>();
                            for matching_fd in matching_fds {
                                let Some(slot) = interest.get_mut(&matching_fd) else {
                                    continue;
                                };
                                if slot.event.events & LINUX_EPOLLET == 0
                                    || slot.event.events & LINUX_EPOLLOUT == 0
                                {
                                    continue;
                                }
                                if !slot.write_backpressured {
                                    snapshot_changed = true;
                                    slot.write_backpressured = true;
                                }
                                #[cfg(any(
                                    feature = "platform-macos",
                                    feature = "platform-freebsd",
                                    feature = "platform-netbsd"
                                ))]
                                if let Some(host_fd) = self.host_fd_for_poll(matching_fd) {
                                    host_rearms.push(host_fd.get());
                                }
                            }
                        }
                        #[cfg(any(
                            feature = "platform-macos",
                            feature = "platform-freebsd",
                            feature = "platform-netbsd"
                        ))]
                        {
                            host_rearms.sort_unstable();
                            host_rearms.dedup();
                            for host_fd in host_rearms {
                                self.rebind_epoll_host_registration(
                                    kqueue,
                                    interest,
                                    HostFd(host_fd),
                                    EPOLL_REBIND_REASON_IO_REARM,
                                    None,
                                );
                            }
                        }
                        // A waiter parked before this consumption holds a park
                        // set whose ET exclusion was computed from the now-
                        // serviced edge (the fd may be parked with events==0 —
                        // deaf). Pop it so it re-samples and re-parks armed.
                        if snapshot_changed {
                            kqueue.wake_parked();
                        }
                        false
                    } else {
                        true
                    }
                }
            };
            // Lazy prune: the fd was closed or recycled as a non-epoll.
            if stale {
                self.captured_file_table().write_epoll_fds().remove(&epfd);
            }
        }
    }

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
    fn detach_description_from_all_epolls(
        &self,
        target: &Arc<crate::kernel::FileDescription>,
        detached_host_fd: Option<HostFd>,
    ) {
        for (owner, registration_fd) in target.take_epoll_owners() {
            let Some(mut guard) = owner.write() else {
                continue;
            };
            let OpenDescription::Epoll {
                interest,
                synthetic_interest_count,
                pending_ready,
                kqueue,
                ..
            } = &mut *guard
            else {
                continue;
            };
            let registered_target = interest
                .get(&registration_fd)
                .and_then(|slot| slot.target.as_ref());
            if !registered_target.is_some_and(|registered| Arc::ptr_eq(registered, target)) {
                continue;
            }
            let _ = remove_epoll_interest(interest, synthetic_interest_count, registration_fd);
            clear_pending_epoll_ready(pending_ready, registration_fd);
            if let Some(host_fd) = detached_host_fd {
                kqueue.with_mux(|mux| {
                    let _ = mux.deregister(host_fd.get());
                });
            }
            kqueue.wake_parked();
            drop(guard);
            if let Some(wq) = owner.wait_queue() {
                wq.wake_all();
            }
            crate::event_ring::rec(
                crate::event_ring::EPRETIRE,
                owner.id().raw() as i32,
                target.id().raw() as i32,
                0,
            );
        }
    }

    pub(in crate::dispatch) fn detach_fd_from_epolls(&self, fd: i32) {
        let detached_host_fd = self.host_fd_for_poll(fd);
        let (detached_description, owners, should_auto_detach) = {
            let files = self.captured_file_table();
            let table = files.read_open_files();
            let detached_description = table.get(&fd).map(|file| file.description.clone());
            let logical_refs = detached_description
                .as_ref()
                .map_or(1, |target| target.fd_ref_count());
            // Only the epoll instances registered on the closing description
            // can hold an entry for it, and the description records them at
            // EPOLL_CTL_ADD; a table-wide walk here made every non-final
            // alias close cost the size of the fd table. A bare inherited
            // stdio fd is registered without a table-backed description
            // (`target: None`, matched by number), so only that case still
            // scans the table's epoll descriptions; any other number absent
            // from the table can hold no registration at all.
            let owners: Vec<Arc<crate::kernel::FileDescription>> = match &detached_description {
                Some(target) => target.epoll_owners(),
                None if is_stdio_fd(fd) => table
                    .values()
                    .filter(|of| of.description.is_epoll())
                    .map(|of| of.description.clone())
                    .collect(),
                None => Vec::new(),
            };
            // Linux retains every registration for an open description until
            // its final fd slot closes, including registrations installed
            // through a dup alias whose numeric slot closed earlier.
            let should_auto_detach = logical_refs == 1;
            (detached_description, owners, should_auto_detach)
        };
        if should_auto_detach && let Some(target) = &detached_description {
            self.detach_description_from_all_epolls(target, detached_host_fd);
            return;
        }
        for description in owners {
            let Some(mut guard) = description.write() else {
                continue;
            };
            if let OpenDescription::Epoll {
                interest,
                synthetic_interest_count,
                pending_ready,
                kqueue,
                ..
            } = &mut *guard
            {
                let matching_fds = interest
                    .iter()
                    .filter_map(|(registered_fd, slot)| {
                        let matches = match (&slot.target, &detached_description) {
                            (Some(registered), Some(closing)) => Arc::ptr_eq(registered, closing),
                            (None, None) => *registered_fd == fd,
                            _ => false,
                        };
                        matches.then_some(*registered_fd)
                    })
                    .collect::<Vec<_>>();
                if matching_fds.is_empty() {
                    continue;
                }
                if should_auto_detach {
                    for registered_fd in matching_fds {
                        let _ = remove_epoll_interest(
                            interest,
                            synthetic_interest_count,
                            registered_fd,
                        );
                        clear_pending_epoll_ready(pending_ready, registered_fd);
                    }
                }
                if let Some(host_fd) = detached_host_fd {
                    // A non-final close after fork is local to the CHILD fd
                    // table, while the inherited epoll description (and its
                    // host multiplexer) is shared with the parent.  If this
                    // table has no other registration for the host fd, deleting
                    // the filter here deafens the parent's still-valid numeric
                    // registration.  Rebind only when this table can name a
                    // surviving registration; a final description close still
                    // deregisters as usual.
                    let has_local_registered_survivor = interest.keys().any(|other| {
                        *other != fd && self.host_fd_for_poll(*other) == Some(host_fd)
                    });
                    if !should_auto_detach && !has_local_registered_survivor {
                        continue;
                    }
                    #[cfg(any(
                        feature = "platform-macos",
                        feature = "platform-freebsd",
                        feature = "platform-netbsd"
                    ))]
                    self.rebind_epoll_host_registration(
                        kqueue,
                        interest,
                        host_fd,
                        EPOLL_REBIND_REASON_CLOSE_DETACH,
                        Some(fd),
                    );
                    #[cfg(not(any(
                        feature = "platform-macos",
                        feature = "platform-freebsd",
                        feature = "platform-netbsd"
                    )))]
                    {
                        let mut survivor: Option<(i32, u32)> = None;
                        let mut union_events: u32 = 0;
                        for (&other, slot) in interest.iter() {
                            if other != fd && self.host_fd_for_poll(other) == Some(host_fd) {
                                survivor.get_or_insert((other, slot.reg_gen));
                                union_events |= slot.event.events;
                            }
                        }
                        kqueue.with_mux(|mux| match survivor {
                            Some((sfd, sgen)) => {
                                let union_events = LinuxEpollEvents::from_bits_retain(union_events);
                                let _ = mux.register_io(
                                    host_fd.get(),
                                    pack_epoll_udata(sfd, sgen),
                                    epoll_interest_for(union_events),
                                    epoll_host_trigger_mode(union_events),
                                );
                            }
                            None => {
                                let _ = mux.deregister(host_fd.get());
                            }
                        });
                    }
                }
                // A parked waiter still ppolls the closed fd's host fd (a
                // closed entry never wakes poll); pop it so it rebuilds.
                kqueue.wake_parked();
            }
        }
    }

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
mod synthetic_datagram_readiness_tests {
    use super::*;

    /// A datagram carrick itself queued on a host-backed UDP socket (the bridge
    /// DNS gateway's answer, a loopback ICMP echo reply) lives in
    /// `synthetic_recv`, not in the host kernel, so the host `poll(2)` that
    /// `epoll_ready_events` trusts for sockets can never see it. Linux reports
    /// EPOLLIN for any queued datagram; so must the recompute `epoll_pwait`
    /// runs on every host-backed interest, and the ET read-growth baseline
    /// must count its bytes the way it counts an in-memory pipe's.
    #[test]
    fn queued_synthetic_datagram_is_epollin_ready() {
        let dispatcher = SyscallDispatcher::new();
        let fd = match dispatcher.host_socket_install(LINUX_AF_INET, LINUX_SOCK_DGRAM, 0) {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("udp socket creation failed: {other:?}"),
        };
        // An unbound, unconnected UDP socket: the host kernel has nothing
        // queued, so any readiness below comes from the synthetic queue alone.
        assert_eq!(dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.host_read_avail_for_poll(fd), 0);

        let payload = b"\x12\x34\x81\x80reply".to_vec();
        let source = socket_addr_to_linux_sockaddr("172.31.0.1:53".parse().unwrap()).unwrap();
        {
            let open_file = dispatcher.open_file(fd).expect("udp socket open file");
            let mut open = open_file
                .description
                .write()
                .expect("udp socket open description");
            let OpenDescription::HostSocket { synthetic_recv, .. } = &mut *open else {
                panic!("udp socket must be a HostSocket");
            };
            synthetic_recv.push_back((payload.clone(), source));
        }

        let ready = dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN);
        assert_eq!(
            ready & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "synthetic datagram must make the socket EPOLLIN-ready, got {ready:#x}"
        );
        assert_eq!(
            dispatcher.host_read_avail_for_poll(fd),
            payload.len() as u64,
            "the ET read-growth baseline must count synthetic bytes"
        );

        // Draining the queue takes the readiness with it.
        assert!(dispatcher.synthetic_datagram_drain(fd).is_some());
        assert_eq!(dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.host_read_avail_for_poll(fd), 0);
    }
}

#[cfg(test)]
fn epoll_kqueue_for_wake_test(dispatcher: &SyscallDispatcher) -> crate::dispatch::EpollKqueue {
    let mut mux = crate::event_mux::make_event_multiplexer().expect("event multiplexer");
    mux.register_user(0).expect("register user wake");
    crate::dispatch::EpollKqueue::new(
        mux,
        Arc::clone(dispatcher.captured_file_table().epoll_wake_registry()),
    )
}

#[cfg(test)]
mod dns_gateway_wake_tests {
    use super::*;
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};

    fn poll_fd_readable(fd: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, 0) };
        rc == 1 && pfd.revents & libc::POLLIN != 0
    }

    /// The bridge DNS gateway answers a guest query in-process, straight into
    /// the socket's `synthetic_recv`. A thread already parked in `epoll_wait`
    /// on that socket sits on the instance kqueue, which only the host kernel
    /// or `notify_inmem_epoll` can pulse; the host never sees the reply, so
    /// the gateway must publish the wake itself (as the ICMP echo path does).
    #[test]
    fn dns_gateway_reply_wakes_parked_epoll_instance() {
        let network = crate::network::RuntimeNetwork::create(
            &carrick_spec::NetworkNamespaceSpec::bridge_default(
                Some("dns-epoll-wake".to_string()),
                Vec::new(),
                Vec::new(),
            ),
        )
        .expect("create bridge network");
        // Direct field assignment (net.rs is a child module of `dispatch`, so
        // the private field is visible) rather than
        // `SyscallDispatcher::with_network`: that constructor also publishes
        // the root net view process-wide and mounts `/etc/resolv.conf`,
        // neither of which this test needs and the former of which would leak
        // into sibling tests in the same process.
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.network = Arc::new(network);
        let gateway =
            std::net::SocketAddr::new(std::net::IpAddr::V4(dispatcher.network.spec.gateway_v4), 53);
        assert!(dispatcher.is_dns_gateway_addr(gateway));

        let fd = match dispatcher.host_socket_install(LINUX_AF_INET, LINUX_SOCK_DGRAM, 0) {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("udp socket creation failed: {other:?}"),
        };

        // Exactly what `epoll_create1` builds (net.rs:4430-4439): a multiplexer
        // with its user-wake armed, registered in THIS dispatcher's wake
        // registry.
        let epoll = epoll_kqueue_for_wake_test(&dispatcher);
        assert!(
            !poll_fd_readable(epoll.poll_fd()),
            "a fresh epoll instance must be quiet"
        );

        let mut query = Message::query();
        query.add_query(Query::query(
            Name::from_ascii("localhost.").expect("name"),
            RecordType::A,
        ));
        let request = query.to_vec().expect("encode query");

        assert!(
            dispatcher.maybe_queue_dns_response(fd, &request, gateway),
            "the gateway must answer a query addressed to gateway_v4:53"
        );
        assert!(
            poll_fd_readable(epoll.poll_fd()),
            "DNS gateway reply must wake the epoll instance's poll fd"
        );

        let (reply, source) = dispatcher
            .synthetic_datagram_drain(fd)
            .expect("reply queued on the querying socket");
        assert_eq!(
            Message::from_vec(&reply).expect("parse reply").metadata.id,
            query.metadata.id
        );
        assert_eq!(source, socket_addr_to_linux_sockaddr(gateway).unwrap());
    }
}

#[cfg(test)]
mod epoll_interest_tests {
    use super::*;

    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    #[test]
    fn et_write_latch_temporarily_disarms_host_write_filter() {
        let dispatcher = SyscallDispatcher::new();
        let events = LINUX_EPOLLET | LINUX_EPOLLIN | LINUX_EPOLLOUT;

        let fresh = dispatcher.epoll_effective_interest(12345, events, 0, 0, false);
        assert!(fresh.read);
        assert!(fresh.write);

        let latched = dispatcher.epoll_effective_interest(12345, events, LINUX_EPOLLOUT, 0, false);
        assert!(latched.read);
        assert!(!latched.write);

        let backpressured =
            dispatcher.epoll_effective_interest(12345, events, LINUX_EPOLLOUT, 0, true);
        assert!(backpressured.read);
        assert!(backpressured.write);

        let level = dispatcher.epoll_effective_interest(
            12345,
            LINUX_EPOLLIN | LINUX_EPOLLOUT,
            LINUX_EPOLLOUT,
            0,
            false,
        );
        assert!(level.read);
        assert!(level.write);
    }

    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    #[test]
    fn et_terminal_latch_disarms_host_filters() {
        let dispatcher = SyscallDispatcher::new();
        let events = LINUX_EPOLLET | LINUX_EPOLLIN | LINUX_EPOLLOUT;

        let hup_latched = dispatcher.epoll_effective_interest(
            12345,
            events,
            LINUX_EPOLLIN | LINUX_EPOLLHUP,
            0,
            false,
        );
        assert!(!hup_latched.read);
        assert!(!hup_latched.write);

        let err_latched =
            dispatcher.epoll_effective_interest(12345, events, LINUX_EPOLLERR, 0, false);
        assert!(!err_latched.read);
        assert!(!err_latched.write);

        let backpressured = dispatcher.epoll_effective_interest(
            12345,
            events,
            LINUX_EPOLLIN | LINUX_EPOLLHUP,
            0,
            true,
        );
        assert!(!backpressured.read);
        assert!(backpressured.write);

        let in_latched_zero =
            dispatcher.epoll_effective_interest(12345, events, LINUX_EPOLLIN, 0, false);
        assert!(!in_latched_zero.read);
        assert!(in_latched_zero.write);
    }
}

#[cfg(test)]
mod staged_splice_readiness_tests {
    use super::*;

    #[test]
    fn staged_splice_pipe_bytes_are_pollin_ready() {
        let mut host_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(host_fds.as_mut_ptr()) }, 0);

        let dispatcher = SyscallDispatcher::new();
        let read_open = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                host_fd: HostFdRef::new(host_fds[0]),
                is_read_end: true,
                pipe_id: 44,
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
                pipe_id: 44,
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

        assert_ne!(
            dispatcher.poll_ready_events(read_fd, LINUX_POLLIN) & LINUX_POLLIN,
            0
        );
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
    /// Shared wait core for `epoll_pwait`/`epoll_pwait2`. Both callers do
    /// their own arg + timeout decode and epfd validation, then hand the
    /// resolved `open_file` (plus the decoded `timeout_ms`/`sig_mask`/
    /// `max_events`) here so the two syscalls share ONE readiness path:
    /// drain any queued ready events, run the multiplexer drain + readiness
    /// recompute, then park (`WaitOnFds`/`WaitOnPollFds`) honouring the
    /// timeout and (blocking) sigmask. Factored out of `epoll_pwait` verbatim
    /// so its behaviour is preserved byte-for-byte (LTP epoll_wait01/02,
    /// epoll_pwait01/02/03).
    #[allow(clippy::too_many_arguments)]
    // Moved verbatim out of the `define_syscall!`-generated `epoll_pwait`, which
    // applies this same lenience to every handler body; preserved so the wait
    // core stays byte-for-byte identical (one pre-existing unused destructure).
    #[allow(unused_variables)]
    fn epoll_pwait_wait_core<M: CurrentMmMemory>(
        &self,
        memory: &mut M,
        open_file: OpenFile,
        epfd: i32,
        events_address: u64,
        guest_abi: LinuxGuestAbi,
        max_events: usize,
        timeout_ms: i32,
        sig_mask: carrick_abi::WaitSigMask,
    ) -> Result<DispatchOutcome, DispatchError> {
        let this = self;
        // Snapshot any already-queued ready events first. `ready` is
        // reassigned on the multiplexer path below (it collects the
        // drained-and-tagged events), so the `mut` is load-bearing.
        let pending_ready = {
            let Some(mut open) = open_file.description.write() else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let OpenDescription::Epoll { pending_ready, .. } = &mut *open else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            drain_pending_epoll_ready(pending_ready, max_events)
        };
        let mut ready: Vec<LinuxEpollEvent> =
            pending_ready.iter().map(|(_fd, event)| *event).collect();
        if !ready.is_empty() {
            for (fd, event) in &pending_ready {
                crate::event_ring::rec(crate::event_ring::EPREADY, epfd, *fd, event.events as i32);
            }
            crate::probes::epoll_result(epfd, ready.len() as i32, 0, timeout_ms, 0);
            return write_epoll_events(memory, events_address, &ready, guest_abi);
        }

        // Multiplexer-backed readiness (kqueue on macOS, epoll on Linux). The
        // multiplexer is the authoritative readiness source for host-backed fds
        // (sockets/pipes/ptys/eventfds) — crucially, it monitors fds registered
        // by OTHER threads while this thread is blocked, fixing the
        // interest-snapshot race that lost a netpoller wakeup. If a drained host
        // event names a guest fd that is not in this snapshot, fall back to the
        // live map before dropping it; that covers the narrow concurrent ADD
        // race without putting a live lock lookup on every returned event.
        {
            let (interests, kq, kq_fd) = {
                let Some(open) = open_file.description.read() else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                let OpenDescription::Epoll {
                    interest, kqueue, ..
                } = &*open
                else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                (
                    interest
                        .iter()
                        .map(|(fd, interest)| (*fd, interest.clone()))
                        .collect::<Vec<_>>(),
                    Arc::clone(kqueue),
                    kqueue.poll_fd(),
                )
            };
            let has_interests = !interests.is_empty();
            let watched_guest_fds = interests.iter().map(|(fd, _)| *fd).collect::<Vec<_>>();

            // guest_fd -> (accumulated epoll events, epoll_data); read+write filters
            // for the same fd merge into one returned event.
            let mut acc: HashMap<i32, (u32, u64)> = HashMap::new();
            type ReadyUpdate = (i32, u32, u64, u32, Option<u64>, bool, bool, bool);
            let mut ready_updates: Vec<ReadyUpdate> = Vec::new();
            let mut host_ready_sampled = std::collections::HashSet::<i32>::new();
            const READ_READY_BITS: u32 =
                LINUX_EPOLLIN | LINUX_EPOLLRDHUP | LINUX_EPOLLHUP | LINUX_EPOLLERR;
            // (1) Drain the instance kqueue (non-blocking) for host-backed fds.
            // `kq_drained_all_filtered` tracks the corner case where the kqueue
            // had readiness events but the user's interest mask filters them
            // all out (e.g. `epoll_ctl(ADD, fd, events=0)` plus data on the
            // pipe). The poll-backed wait below uses an empty event mask and a
            // short retry slice: it avoids re-polling kq_fd as immediately
            // readable while still re-dispatching for a concurrent MOD/HUP and
            // preserving the guest deadline.
            let mut kq_drained_all_filtered = false;
            {
                // Non-blocking drain of the multiplexer for host-backed fds.
                let mut poll_events: Vec<carrick_hal::event::PollEvent> = Vec::new();
                if kq
                    .with_mux(|mux| mux.wait(&mut poll_events, Some(Duration::ZERO)))
                    .is_ok()
                {
                    let acc_before = acc.len();
                    // Each drained event's udata is a GENERATIONAL handle
                    // `(guest_fd, reg_gen)` (the multiplexer IDENT stays the host
                    // fd). Guest AND host fd numbers recycle rapidly under churn, so
                    // routing by a bare fd is an ABA hazard; the gen lets us confirm
                    // the edge belongs to the CURRENT registration of guest_fd and
                    // drop a stale edge for a recycled fd (see below). For each valid
                    // edge we RE-POLL the live owner(s) rather than trust the drained
                    // bits, which stays correct even when the host fd was recycled
                    // mid-drain. bits==0 is an EVFILT_USER(0) in-memory wake or a
                    // filter with no translatable bits — in-memory readiness is
                    // recomputed in step (2), so it is skipped (and must NOT count
                    // toward `kq_drained_all_filtered`: it auto-resets, so polling
                    // kq_fd won't spin, whereas the all-filtered path parks on the
                    // signal pipe — the Node worker-teardown hang).
                    let mut filtered_ready_events = 0usize;
                    if !poll_events.is_empty() {
                        // Build the per-wait routing tables from the LIVE interest map
                        // (NOT the pre-drain snapshot): an fd ADDed by another thread
                        // AFTER the snapshot whose edge is already in THIS batch must
                        // still be routable — its single EV_CLEAR/EPOLLET edge is
                        // consumed and will not re-fire. `gfd_info` resolves a guest
                        // fd to its (host_fd, mask, data, reg_gen); `host_to_gfds` is
                        // the reverse index for dup fan-out (one host fd may back
                        // several guest fds — Linux wakes each pollDesc). Built once
                        // here, then the epoll lock is dropped before the per-fd
                        // re-poll so a concurrent epoll_ctl isn't blocked on syscalls.
                        // gfd_info: guest fd -> (host_fd, requested events,
                        // epoll_data, reg_gen, io_gen, last_ready, last_read_avail,
                        // write_backpressured). host_to_gfds: host fd
                        // -> guest fds sharing it (dup fan-out). Types inferred
                        // from the inserts.
                        let (gfd_info, host_to_gfds) = {
                            let Some(open) = open_file.description.read() else {
                                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                            };
                            // Per-guest-fd epoll interest snapshot: (host_fd,
                            // events, epoll data, reg_gen, io_gen, last_ready,
                            // last_read_avail, write_backpressured).
                            type GfdInterest = (i32, u32, u64, u32, u64, u32, u64, bool);
                            let mut info: HashMap<i32, GfdInterest> = HashMap::new();
                            let mut rev: HashMap<i32, Vec<i32>> = HashMap::new();
                            if let OpenDescription::Epoll { interest, .. } = &*open {
                                for (gfd, slot) in interest.iter() {
                                    if let Some(hfd) = this.host_fd_for_poll(*gfd) {
                                        info.insert(
                                            *gfd,
                                            (
                                                hfd.get(),
                                                slot.event.events,
                                                slot.event.data,
                                                slot.reg_gen,
                                                slot.io_gen,
                                                slot.last_ready,
                                                slot.last_read_avail,
                                                slot.write_backpressured,
                                            ),
                                        );
                                        rev.entry(hfd.get()).or_default().push(*gfd);
                                    }
                                }
                            }
                            (info, rev)
                        };
                        // Resolve each drained event through its generational handle.
                        // The udata is (guest_fd, gen); trust it only if the live
                        // interest for guest_fd carries the SAME gen — otherwise the
                        // fd was recycled (ABA) and this is a stale edge for a gone
                        // registration: drop it (the current owner, if any, gets its
                        // own edge) and probe so the race stays observable. A valid
                        // hit fans out to every guest fd currently sharing that host
                        // fd (dups). bits==0 is an EVFILT_USER(0) wake / untranslatable
                        // filter — in-memory readiness is recomputed in step (2).
                        let mut deliver: HashMap<i32, (u32, u64)> = HashMap::new();
                        for ev in &poll_events {
                            let edge_bits = pollevent_to_epoll(ev);
                            if edge_bits == 0 {
                                continue;
                            }
                            let edge_readiness_count = if ev.readiness_count > 0 {
                                ev.readiness_count as u64
                            } else {
                                0
                            };
                            let (guest_fd, generation) = unpack_epoll_udata(ev.token);
                            crate::event_ring::rec(
                                crate::event_ring::EPEDGE,
                                guest_fd,
                                edge_bits as i32,
                                edge_readiness_count.min(i32::MAX as u64) as i32,
                            );
                            match gfd_info.get(&guest_fd) {
                                Some(&(hfd, _, _, reg_gen, _, _, _, _))
                                    if reg_gen == generation =>
                                {
                                    if let Some(siblings) = host_to_gfds.get(&hfd) {
                                        for sibling in siblings {
                                            let entry = deliver.entry(*sibling).or_insert((0, 0));
                                            merge_epoll_edge_sample(
                                                entry,
                                                edge_bits,
                                                edge_readiness_count,
                                            );
                                        }
                                    }
                                }
                                _ => {
                                    let live_generation =
                                        gfd_info.get(&guest_fd).map_or(-1, |entry| entry.3 as i32);
                                    crate::event_ring::rec(
                                        crate::event_ring::EPSTALE,
                                        guest_fd,
                                        generation as i32,
                                        live_generation,
                                    );
                                    crate::probes::epoll_stale_edge(ev.token, guest_fd, generation);
                                }
                            }
                        }
                        // Deliver each owner's CURRENT readiness. RE-POLLING (rather
                        // than trusting the drained bits) keeps delivery correct even
                        // when the host fd was recycled between the edge and now — the
                        // live poll(2) state is always the truth. illumos devpoll
                        // model: the edge only FLAGS the fd; we re-poll just the
                        // flagged owners (polling ALL registered fds was O(nfds) and
                        // too slow).
                        for (gfd, (edge_bits, edge_readiness_count)) in deliver {
                            if let Some(&(
                                hfd,
                                requested,
                                data,
                                reg_gen,
                                io_gen,
                                last_ready,
                                last_read_avail,
                                write_backpressured,
                            )) = gfd_info.get(&gfd)
                            {
                                host_ready_sampled.insert(gfd);
                                let mut raw = this.epoll_ready_events(gfd, requested);
                                let terminal_edge = edge_bits
                                    & (LINUX_EPOLLRDHUP | LINUX_EPOLLHUP | LINUX_EPOLLERR);
                                raw |= terminal_edge;
                                if terminal_edge & LINUX_EPOLLRDHUP != 0 {
                                    raw |= LINUX_EPOLLIN;
                                }
                                let read_avail = if raw & READ_READY_BITS != 0 {
                                    this.host_read_avail_for_poll(gfd)
                                } else {
                                    0
                                };
                                let observed_read_avail = if read_avail > 0 {
                                    read_avail
                                } else {
                                    edge_readiness_count
                                };
                                let clear_write_backpressure =
                                    write_backpressured && raw & LINUX_EPOLLOUT != 0;
                                // Growth over the recorded baseline delivers a
                                // SECOND ET edge while the first is still
                                // unconsumed. It is not the mechanism that
                                // carries the ordinary "ready again after you
                                // drained" case — that is `raw & !last_ready`
                                // once consumption re-armed the latch
                                // (`epoll_rearm_after_io`). See
                                // `EpollInterest::last_read_avail` for what the
                                // count means per fd and why growth is a sound
                                // arrival predicate for a listener even though
                                // its accept-queue depth is non-monotone.
                                let read_growth = if requested & LINUX_EPOLLET != 0
                                    && raw & READ_READY_BITS != 0
                                    && observed_read_avail > last_read_avail
                                {
                                    raw & READ_READY_BITS
                                } else {
                                    0
                                };
                                let mut ready_events = if requested & LINUX_EPOLLET != 0 {
                                    (raw & !last_ready) | read_growth
                                } else {
                                    raw
                                };
                                if clear_write_backpressure {
                                    ready_events |= raw & LINUX_EPOLLOUT;
                                }
                                let edge_filtered_by_interest =
                                    edge_bits & (requested | LINUX_EPOLLHUP | LINUX_EPOLLERR) == 0;
                                let read_avail_update = if raw & READ_READY_BITS == 0 {
                                    Some(0)
                                } else {
                                    Some(observed_read_avail)
                                };
                                let masked_ready =
                                    ready_events == 0 && (raw != 0 || edge_filtered_by_interest);
                                ready_updates.push((
                                    gfd,
                                    reg_gen,
                                    io_gen,
                                    raw,
                                    read_avail_update,
                                    clear_write_backpressure,
                                    true,
                                    masked_ready,
                                ));
                                crate::probes::epoll_interest(
                                    epfd,
                                    gfd,
                                    requested,
                                    raw,
                                    last_ready,
                                    ready_events,
                                );
                                if masked_ready {
                                    crate::event_ring::rec(
                                        crate::event_ring::EPMASK,
                                        1,
                                        raw as i32,
                                        last_ready as i32,
                                    );
                                    crate::event_ring::rec(
                                        crate::event_ring::EPMASKFD,
                                        1,
                                        gfd,
                                        hfd,
                                    );
                                    crate::probes::epoll_masked(crate::probes::EpollMaskedProbe {
                                        origin: 1,
                                        fd: gfd,
                                        host_fd: hfd,
                                        requested,
                                        raw_ready: raw,
                                        last_ready,
                                        read_avail: observed_read_avail,
                                        last_read_avail,
                                    });
                                }
                                if ready_events != 0 {
                                    acc.entry(gfd).or_insert((0, data)).0 |= ready_events;
                                } else if requested & LINUX_EPOLLET == 0
                                    && (raw != 0 || edge_filtered_by_interest)
                                {
                                    filtered_ready_events += 1;
                                }
                            }
                        }
                    }
                    // A REAL, CURRENT host-fd readiness event fired but the interest
                    // masks let none through (the events=0-with-data case): polling
                    // kq_fd would see the same level readiness and spin, so park on
                    // the signal pipe instead. Stale (recycled-fd) edges are excluded
                    // from `translatable_events`: their host edge was consumed, so
                    // kq_fd won't spin and the kqueue-poll path stays reachable by the
                    // current owner's own later edge. A pure EVFILT_USER drain is
                    // likewise excluded — it auto-resets.
                    kq_drained_all_filtered = filtered_ready_events > 0 && acc.len() == acc_before;
                }
            }

            // (2) Host-backed fds: the multiplexer edge says which owners are
            // worth re-polling, but the live host level is still the authority.
            // Re-sample any host-backed interest that was not already sampled
            // from a drained mux event so a missed/stale edge cannot park an
            // epoll waiter while the host fd is already readable/writable.
            for (fd, interest) in &interests {
                if host_ready_sampled.contains(fd) || this.host_fd_for_poll(*fd).is_none() {
                    continue;
                }
                host_ready_sampled.insert(*fd);
                let requested = interest.event.events;
                let raw_ready = this.epoll_ready_events(*fd, requested);
                let read_avail = if raw_ready & READ_READY_BITS != 0 {
                    this.host_read_avail_for_poll(*fd)
                } else {
                    0
                };
                let clear_write_backpressure =
                    interest.write_backpressured && raw_ready & LINUX_EPOLLOUT != 0;
                let read_growth = if requested & LINUX_EPOLLET != 0
                    && raw_ready & READ_READY_BITS != 0
                    && read_avail > interest.last_read_avail
                {
                    raw_ready & READ_READY_BITS
                } else {
                    0
                };
                let mut ready_events = if requested & LINUX_EPOLLET != 0 {
                    (raw_ready & !interest.last_ready) | read_growth
                } else {
                    raw_ready
                };
                if clear_write_backpressure {
                    ready_events |= raw_ready & LINUX_EPOLLOUT;
                }
                let read_avail_update = if raw_ready & READ_READY_BITS == 0 {
                    Some(0)
                } else if read_avail == 0 {
                    // Readable, but FIONREAD reports no byte count. The case
                    // this floor EXISTS for is a LISTENER: its readiness count
                    // is the pending accept-queue depth, which lives in the
                    // multiplexer edge's `readiness_count` (>=1), not in
                    // FIONREAD. Recording 0 here would DESYNC this level
                    // re-sample from the edge path: if this path observes and
                    // reports the readiness first (its poll(2) can beat the
                    // not-yet-drained knote) and stores 0, the later drain of
                    // that SAME knote sees `count (1) > last_read_avail (0)`,
                    // reads it as growth, and spuriously redelivers the
                    // already-reported, still-unaccepted connection. Flooring
                    // the baseline at the readiness just reported keeps only a
                    // genuine depth increase (a NEW connection) re-arming the
                    // edge. A real byte count takes the branch below.
                    //
                    // The branch is NOT listener-only, so be precise about what
                    // it does to the other two fds that report readable with
                    // FIONREAD == 0 (for both, the edge path's count is 0 too,
                    // so there is no desync to fix and the floor is pure
                    // conservatism):
                    //   - an EOF/HUP read end: terminal. No later count can
                    //     ever exceed the floor because no more data can arrive,
                    //     and consumption (a read returning 0) resets the
                    //     baseline outright. Inert.
                    //   - a 0-length datagram: the one case where the floor can
                    //     defer an edge. A follow-up 1-byte datagram lands at
                    //     count 1, which no longer exceeds the floored baseline,
                    //     so it is not reported as growth while the 0-length
                    //     readiness is STILL UNCONSUMED (a recv of any size
                    //     resets the baseline and re-arms). Bounded to that
                    //     window, and only on the level-first ordering; fixing
                    //     it properly needs the multiplexer to report a count
                    //     FIONREAD cannot see (an arrival counter / queue depth)
                    //     rather than this path guessing one, so it is left
                    //     documented instead of special-cased here.
                    Some(interest.last_read_avail.max(1))
                } else {
                    Some(read_avail)
                };
                let masked_ready = ready_events == 0 && raw_ready != 0;
                ready_updates.push((
                    *fd,
                    interest.reg_gen,
                    interest.io_gen,
                    raw_ready,
                    read_avail_update,
                    clear_write_backpressure,
                    false,
                    masked_ready,
                ));
                crate::probes::epoll_interest(
                    epfd,
                    *fd,
                    requested,
                    raw_ready,
                    interest.last_ready,
                    ready_events,
                );
                if masked_ready {
                    crate::event_ring::rec(
                        crate::event_ring::EPMASK,
                        2,
                        raw_ready as i32,
                        interest.last_ready as i32,
                    );
                    let host_fd = this
                        .host_fd_for_poll(*fd)
                        .map_or(-1, |host_fd| host_fd.get());
                    crate::event_ring::rec(crate::event_ring::EPMASKFD, 2, *fd, host_fd);
                    crate::probes::epoll_masked(crate::probes::EpollMaskedProbe {
                        origin: 2,
                        fd: *fd,
                        host_fd,
                        requested,
                        raw_ready,
                        last_ready: interest.last_ready,
                        read_avail,
                        last_read_avail: interest.last_read_avail,
                    });
                }
                if ready_events != 0 {
                    let entry = acc.entry(*fd).or_insert((0, interest.event.data));
                    entry.0 |= ready_events;
                }
            }

            // (3) In-memory fds (no host fd): recompute readiness.
            for (fd, interest) in &interests {
                if host_ready_sampled.contains(fd) {
                    continue;
                }
                // Host-fd fds are handled by the kqueue drain above — EXCEPT a
                // named-FIFO read-end whose writer has closed: macOS kqueue won't
                // report that (dispatch::fifo_beacon decides it via a kernel
                // beacon pipe), so recompute it here so the notify_inmem_epoll
                // wake on writer-close surfaces EOF instead of blocking forever.
                if let Some(hfd) = this.host_fd_for_poll(*fd)
                    && !crate::dispatch::fifo_beacon::read_end_at_eof(hfd.get())
                {
                    continue;
                }
                let requested = interest.event.events;
                let raw_ready = this.epoll_ready_events(*fd, requested);
                let read_avail = if raw_ready & READ_READY_BITS != 0 {
                    this.host_read_avail_for_poll(*fd)
                } else {
                    0
                };
                let read_growth = if requested & LINUX_EPOLLET != 0
                    && raw_ready & READ_READY_BITS != 0
                    && read_avail > interest.last_read_avail
                {
                    raw_ready & READ_READY_BITS
                } else {
                    0
                };
                let ready_events = if requested & LINUX_EPOLLET != 0 {
                    (raw_ready & !interest.last_ready) | read_growth
                } else {
                    raw_ready
                };
                let read_avail_update = if raw_ready & READ_READY_BITS == 0 {
                    Some(0)
                } else {
                    Some(read_avail)
                };
                ready_updates.push((
                    *fd,
                    interest.reg_gen,
                    interest.io_gen,
                    raw_ready,
                    read_avail_update,
                    false,
                    false,
                    false,
                ));
                crate::probes::epoll_interest(
                    epfd,
                    *fd,
                    requested,
                    raw_ready,
                    interest.last_ready,
                    ready_events,
                );
                if ready_events == 0 && raw_ready != 0 {
                    crate::event_ring::rec(
                        crate::event_ring::EPMASK,
                        3,
                        raw_ready as i32,
                        interest.last_ready as i32,
                    );
                    crate::event_ring::rec(crate::event_ring::EPMASKFD, 3, *fd, -1);
                    crate::probes::epoll_masked(crate::probes::EpollMaskedProbe {
                        origin: 3,
                        fd: *fd,
                        host_fd: -1,
                        requested,
                        raw_ready,
                        last_ready: interest.last_ready,
                        read_avail: 0,
                        last_read_avail: interest.last_read_avail,
                    });
                }
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
                    interests.iter().any(|(ifd, slot)| {
                        ifd == *fd && slot.event.events & LINUX_EPOLLONESHOT != 0
                    })
                })
                .map(|(fd, _)| *fd)
                .collect();

            if !ready_updates.is_empty() || !oneshot_fds.is_empty() {
                if let Some(mut open) = open_file.description.write() {
                    if let OpenDescription::Epoll {
                        interest, kqueue, ..
                    } = &mut *open
                    {
                        #[cfg(any(
                            feature = "platform-macos",
                            feature = "platform-freebsd",
                            feature = "platform-netbsd"
                        ))]
                        let mut host_rearms: Vec<i32> = Vec::new();
                        for (
                            fd,
                            reg_gen,
                            io_gen,
                            raw,
                            read_avail,
                            clear_write_backpressure,
                            edge_drained,
                            masked_ready,
                        ) in ready_updates
                        {
                            if let Some(slot) = interest.get_mut(&fd) {
                                if !epoll_ready_sample_is_current(
                                    reg_gen,
                                    io_gen,
                                    slot.reg_gen,
                                    slot.io_gen,
                                ) {
                                    continue;
                                }
                                let before = slot.last_ready;
                                let read_avail_changed = read_avail
                                    .is_some_and(|read_avail| read_avail != slot.last_read_avail);
                                slot.last_ready = raw;
                                if let Some(read_avail) = read_avail {
                                    slot.last_read_avail = read_avail;
                                }
                                if clear_write_backpressure {
                                    slot.write_backpressured = false;
                                }
                                #[cfg(any(
                                    feature = "platform-macos",
                                    feature = "platform-freebsd",
                                    feature = "platform-netbsd"
                                ))]
                                if slot.event.events & LINUX_EPOLLET != 0
                                    && epoll_wait_sample_needs_host_rebind(
                                        before,
                                        raw,
                                        read_avail_changed,
                                        clear_write_backpressure,
                                        edge_drained,
                                        masked_ready,
                                        this.fd_is_listening_socket(fd),
                                    )
                                    && let Some(host_fd) = this.host_fd_for_poll(fd)
                                {
                                    host_rearms.push(host_fd.get());
                                }
                            }
                        }
                        #[cfg(any(
                            feature = "platform-macos",
                            feature = "platform-freebsd",
                            feature = "platform-netbsd"
                        ))]
                        {
                            host_rearms.sort_unstable();
                            host_rearms.dedup();
                            for host_fd in host_rearms {
                                this.rebind_epoll_host_registration(
                                    kqueue,
                                    interest,
                                    HostFd(host_fd),
                                    EPOLL_REBIND_REASON_WAIT_SAMPLE,
                                    None,
                                );
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
            }
            // Also remove the host kqueue filter for each disarmed fd so the
            // level-triggered EVFILT_READ doesn't keep firing and tight-loop
            // the next epoll_wait (the same shape as the events=0 fix above,
            // applied to the freshly-disarmed ONESHOT slot).
            for fd in &oneshot_fds {
                if let Some(host_fd) = this.host_fd_for_poll(*fd) {
                    kq.with_mux(|mux| {
                        let _ = mux.deregister(host_fd.get());
                    });
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
                if let Some(mut open) = open_file.description.write() {
                    if let OpenDescription::Epoll { pending_ready, .. } = &mut *open {
                        pending_ready.extend(overflow);
                    }
                }
            }
            for (fd, event) in &ready_tagged {
                crate::event_ring::rec(crate::event_ring::EPREADY, epfd, *fd, event.events as i32);
            }
            ready = ready_tagged.into_iter().map(|(_fd, event)| event).collect();

            crate::event_ring::rec(
                crate::event_ring::EPWAIT,
                kq_fd,
                ready.len() as i32,
                timeout_ms,
            );
            if ready.is_empty() && timeout_ms != 0 {
                let timeout = if timeout_ms < 0 {
                    None
                } else {
                    Some(Duration::from_millis(timeout_ms as u64))
                };
                if kq_drained_all_filtered {
                    // The instance kqueue is readable, but every drained event
                    // was masked by the guest interest. Poll kq_fd with an
                    // empty event mask: the poll-backed wait uses a short
                    // backstop to re-dispatch without spinning, while still
                    // observing a concurrent epoll_ctl MOD or a later HUP/ERR.
                    crate::probes::epoll_result(epfd, 0, 1, timeout_ms, 2);
                    crate::event_ring::rec(crate::event_ring::EPWFD, kq_fd, 0, timeout_ms);
                    let files = self.captured_file_table();
                    let fds = match WaitFds::raw_one(kq_fd, 0).with_redispatch_and_watched_slots(
                        &files,
                        [epfd],
                        watched_guest_fds.iter().copied(),
                    ) {
                        Ok(fds) => fds,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    return Ok(DispatchOutcome::WaitOnFds {
                        fds,
                        timeout,
                        sig_mask,
                        completion: FdWaitCompletion::Poll { on_timeout: 0 },
                    });
                }
                if !has_interests {
                    // epoll_pwait with an empty interest set must still honour
                    // timeout + signal interruption, not return 0 immediately.
                    // Poll the instance's durable user-wake source as well: a
                    // concurrent epoll_ctl ADD can make the formerly-empty set
                    // ready and must force a registry recomputation.
                    crate::probes::epoll_result(epfd, 0, 1, timeout_ms, 2);
                    crate::event_ring::rec(
                        crate::event_ring::EPWFD,
                        kq_fd,
                        libc::POLLIN as i32,
                        timeout_ms,
                    );
                    let files = self.captured_file_table();
                    let fds = match WaitFds::raw_one(kq_fd, libc::POLLIN)
                        .with_redispatch_and_watched_slots(
                            &files,
                            [epfd],
                            watched_guest_fds.iter().copied(),
                        ) {
                        Ok(fds) => fds,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    return Ok(DispatchOutcome::WaitOnFds {
                        fds,
                        timeout,
                        sig_mask,
                        completion: FdWaitCompletion::Poll { on_timeout: 0 },
                    });
                }
                crate::probes::epoll_result(epfd, 0, 1, timeout_ms, 1);
                crate::probes::epoll_wait_fd(epfd, -1, kq_fd, libc::POLLIN as i32, timeout_ms);
                crate::event_ring::rec(
                    crate::event_ring::EPWFD,
                    kq_fd,
                    libc::POLLIN as i32,
                    timeout_ms,
                );
                // Poll the instance kqueue fd for readability. This avoids nesting
                // the epoll kqueue inside the per-thread kqueue, and unlike calling
                // kevent() here it does not consume pending epoll events before the
                // re-dispatched epoll_pwait can copy them out.
                let files = self.captured_file_table();
                let fds = match WaitFds::raw_one(kq_fd, libc::POLLIN)
                    .with_redispatch_and_watched_slots(
                        &files,
                        [epfd],
                        watched_guest_fds.iter().copied(),
                    ) {
                    Ok(fds) => fds,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                return Ok(DispatchOutcome::WaitOnFds {
                    fds,
                    timeout,
                    sig_mask,
                    completion: FdWaitCompletion::Poll { on_timeout: 0 },
                });
            }

            crate::probes::epoll_result(epfd, ready.len() as i32, 0, timeout_ms, 0);
            write_epoll_events(memory, events_address, &ready, guest_abi)
        }
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

        fn epoll_create1(this, cx, flags: u64) {

            if flags & !LINUX_EPOLL_CLOEXEC != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The readiness backend is an EventMultiplexer: kqueue-backed on
            // macOS, epoll-backed on Linux. The user-wake channel `register_user(0)`
            // is the in-memory wake: `notify_inmem_epoll`/`wake_parked` trigger it
            // when an eventfd/pipe/timerfd readiness changes or an interest is
            // re-armed, so a thread blocked on this instance's poll_fd re-checks.
            let epoll_kqueue = {
                let mut mux = match crate::event_mux::make_event_multiplexer() {
                    Ok(m) => m,
                    // The backing kqueue/epoll fd couldn't be allocated (fd table full).
                    Err(_) => return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMFILE)),
                };
                let _ = mux.register_user(0);
                crate::dispatch::EpollKqueue::new(
                    mux,
                    Arc::clone(this.captured_file_table().epoll_wake_registry()),
                )
            };
            let description = OpenDescription::Epoll {
                interest: HashMap::new(),
                synthetic_interest_count: 0,
                base: OpenDescriptionBase::new(0),
                pending_ready: VecDeque::new(),
                kqueue: Arc::new(epoll_kqueue),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            };
            Ok(this.install_fd(description, linux_fd_flags_from_open_flags(flags)))

        }

        fn x86_epoll_create(this, cx, size: u64) {

            // x86_64 legacy epoll_create(size): the size is ignored since 2.6.8
            // but the kernel still rejects size <= 0 with EINVAL (epoll-ltp /
            // epoll_create02). Validate, then create exactly as epoll_create1(0).
            if (size as i32) <= 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let epoll_kqueue = {
                let mut mux = match crate::event_mux::make_event_multiplexer() {
                    Ok(m) => m,
                    Err(_) => return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMFILE)),
                };
                let _ = mux.register_user(0);
                crate::dispatch::EpollKqueue::new(
                    mux,
                    Arc::clone(this.captured_file_table().epoll_wake_registry()),
                )
            };
            let description = OpenDescription::Epoll {
                interest: HashMap::new(),
                synthetic_interest_count: 0,
                base: OpenDescriptionBase::new(0),
                pending_ready: VecDeque::new(),
                kqueue: Arc::new(epoll_kqueue),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            };
            Ok(this.install_fd(description, linux_fd_flags_from_open_flags(0)))

        }

        fn epoll_ctl(this, cx, epfd: Fd, op: u64, fd: Fd, event: GuestPtr) {

            let memory = &*cx.memory;
            let epfd = epfd.0;
            let operation = op;
            let fd = fd.0;
            let event_address = event.0;
            // A bad target fd is EBADF; a target equal to the epoll fd itself is
            // EINVAL (an epoll instance can't monitor itself). (LTP epoll_ctl02.)
            if !this.fd_is_valid(fd) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            if epfd == fd {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let Some(open_file) = this.open_file(epfd) else {
                return Ok(DispatchOutcome::errno(if this.fd_is_valid(epfd) {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                }));
            };
            let epoll_description = Arc::clone(&open_file.description);
            let Some(target_file) = this.open_file(fd) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // Same-description alias check (LTP / Linux epoll_ctl EINVAL when target refers to this epoll instance)
            if epoll_description.id() == target_file.description.id() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The host fd backing this target (sockets/pipes/ptys); `None` for an
            // in-memory eventfd/pipe/timerfd, whose readiness is recomputed each
            // `epoll_wait` rather than registered on the kqueue. Computed before
            // taking the epoll write lock (it locks the *target* fd's description).
            let host_fd = this.host_fd_for_poll(fd);
            let target_description = Some(Arc::clone(&target_file.description));

            // Record this epoll instance for the consumption-based EPOLLET
            // re-arm ([`Self::epoll_rearm_after_io`]) BEFORE taking the
            // description lock (the re-arm path snapshots this set first, then
            // locks descriptions — registering here keeps the lock order
            // acyclic). A non-epoll epfd inserted on the error path below is
            // harmless: the re-arm prunes it lazily.
            this.captured_file_table().write_epoll_fds().insert(epfd);

            let Some(mut open) = open_file.description.write() else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let OpenDescription::Epoll {
                interest,
                synthetic_interest_count,
                pending_ready,
                kqueue,
                wait_queue,
                ..
            } = &mut *open
            else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };

            match operation {
                LINUX_EPOLL_CTL_ADD => {
                    let event = read_epoll_event(memory, event_address, cx.guest_abi())?;
                    // The kernel rejects ADD of a target that has no ->poll support
                    // (regular files, directories) with EPERM. (LTP epoll_ctl02/05.)
                    if !this.fd_is_epollable(fd) {
                        return Ok(DispatchOutcome::errno(LINUX_EPERM));
                    }
                    if this.epoll_add_would_loop_desc(&target_file.description, epoll_description.id()) {
                        return Ok(DispatchOutcome::errno(carrick_abi::LINUX_ELOOP));
                    }
                    if interest.contains_key(&fd) {
                        return Ok(DispatchOutcome::errno(LINUX_EEXIST));
                    }
                    // Generational handle: the multiplexer IDENT is the host fd
                    // (the kernel's stable key, auto-removed on close); the udata
                    // is `(guest_fd, reg_gen)`. Guest AND host fd numbers recycle
                    // rapidly under churn, so a drained event keyed by a bare fd is
                    // an ABA hazard — by delivery time the fd may name a different
                    // registration. `epoll_pwait` routes by the udata's guest fd
                    // and requires `reg_gen` to match the live interest, so a stale
                    // edge for a recycled fd is dropped, not mis-delivered.
                    // (epoll_et_pipe_eof_not_lost.)
                    let reg_gen = next_epoll_reg_gen();
                    if let Some(host_fd) = host_fd {
                        let ev_events = event.events;
                        let effective = this.epoll_effective_interest(fd, ev_events, 0, 0, false);
                        let register = kqueue.with_mux(|mux| {
                            mux.register_io(
                                host_fd.get(),
                                pack_epoll_udata(fd, reg_gen),
                                effective,
                                epoll_host_trigger_mode(LinuxEpollEvents::from_bits_retain(
                                    ev_events,
                                )),
                            )
                        });
                        // An error-queue socket's ICMP error lands on its
                        // SHADOW, which the guest knows nothing about. Register
                        // it under the SAME udata so an event there wakes this
                        // epoll and the level recompute reports the queued
                        // error. Without it the guest parks in epoll_wait with
                        // an error it is never told about — the error arrives
                        // asynchronously, after the send has already returned.
                        if let Some(shadow) = recverr::shadow_fd(host_fd.get()) {
                            let _ = kqueue.with_mux(|mux| {
                                mux.register_io(
                                    shadow,
                                    pack_epoll_udata(fd, reg_gen),
                                    effective,
                                    epoll_host_trigger_mode(LinuxEpollEvents::from_bits_retain(
                                        ev_events,
                                    )),
                                )
                            });
                        }
                        if let Err(err) = register {
                            return Ok(DispatchOutcome::errno(crate::host_to_linux_errno(
                                err.errno,
                            )));
                        }
                        crate::event_ring::rec(
                            crate::event_ring::EPADD,
                            kqueue.poll_fd(),
                            host_fd.get(),
                            ev_events as i32,
                        );
                    }
                    let kqueue_weak = Arc::downgrade(kqueue);
                    let owner_wq_weak = Arc::downgrade(wait_queue);
                    let owner_id = epoll_description.id();
                    let callback_enrollment = if let Some(target) = &target_description
                        && let Some(target_wq) = target.wait_queue()
                    {
                        let target_id = target.id();
                        Some(Arc::new(target_wq.enroll_callback(move |depth: usize| {
                            if let Some(kqueue) = kqueue_weak.upgrade() {
                                kqueue.wake_parked();
                            }
                            if let Some(owner_wq) = owner_wq_weak.upgrade() {
                                owner_wq.wake_all_with_depth(depth);
                            }
                            crate::event_ring::rec(
                                crate::event_ring::EPWAKE,
                                owner_id.raw() as i32,
                                target_id.raw() as i32,
                                depth as i32,
                            );
                        })))
                    } else {
                        None
                    };
                    if let Some(target) = &target_description {
                        target.register_epoll_owner(&epoll_description, fd);
                        crate::event_ring::rec(
                            crate::event_ring::EPOWNER,
                            epoll_description.id().raw() as i32,
                            target.id().raw() as i32,
                            fd,
                        );
                    }
                    interest.insert(
                        fd,
                        EpollInterest {
                            target: target_description,
                            host_poll_source: host_fd.is_some(),
                            event,
                            last_ready: 0,
                            last_read_avail: 0,
                            write_backpressured: false,
                            io_gen: 0,
                            reg_gen,
                            _callback_enrollment: callback_enrollment,
                        },
                    );
                    if host_fd.is_none() {
                        *synthetic_interest_count += 1;
                    }
                    // A waiter parked on this instance's ppoll snapshot does
                    // not watch the just-added fd; pop it so it rebuilds.
                    kqueue.wake_parked();
                    drop(open);
                    if let Some(wq) = open_file.description.wait_queue() {
                        wq.wake_all();
                    }
                    crate::probes::epoll_ctl(epfd, operation, fd, event.events, event.data, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                LINUX_EPOLL_CTL_MOD => {
                    let event = read_epoll_event(memory, event_address, cx.guest_abi())?;
                    let Some(slot) = interest.get_mut(&fd) else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                    };
                    // `register_io` re-arms the filters present in the new mask and
                    // EV_DELETEs the ones no longer present in a single call, so the
                    // old "add new, then delete removed" sequence — which avoided a
                    // no-interest gap where a readiness edge could be lost — is now
                    // atomic per direction (no transient gap at all). MOD keeps the
                    // SAME registration, so it preserves `reg_gen` (the generational
                    // handle is unchanged — see EPOLL_CTL_ADD).
                    let reg_gen = slot.reg_gen;
                    let host_poll_source = slot.host_poll_source;
                    if let Some(host_fd) = host_fd {
                        let effective =
                            this.epoll_effective_interest(fd, event.events, 0, 0, false);
                        let register = kqueue.with_mux(|mux| {
                            mux.register_io(
                                host_fd.get(),
                                pack_epoll_udata(fd, reg_gen),
                                effective,
                                epoll_host_trigger_mode(LinuxEpollEvents::from_bits_retain(
                                    event.events,
                                )),
                            )
                        });
                        if let Err(err) = register {
                            return Ok(DispatchOutcome::errno(crate::host_to_linux_errno(
                                err.errno,
                            )));
                        }
                    }
                    clear_pending_epoll_ready(pending_ready, fd);
                    *slot = EpollInterest {
                        target: slot.target.clone(),
                        host_poll_source,
                        event,
                        last_ready: 0,
                        last_read_avail: 0,
                        write_backpressured: false,
                        io_gen: 0,
                        reg_gen,
                        _callback_enrollment: slot._callback_enrollment.clone(),
                    };
                    // Re-arm visible to a parked waiter: rebuild its park set.
                    kqueue.wake_parked();
                    drop(open);
                    if let Some(wq) = open_file.description.wait_queue() {
                        wq.wake_all();
                    }
                    crate::probes::epoll_ctl(epfd, operation, fd, event.events, event.data, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                LINUX_EPOLL_CTL_DEL => {
                    let Some(removed) =
                        remove_epoll_interest(interest, synthetic_interest_count, fd)
                    else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                    };
                    let removed_reg_gen = removed.reg_gen;
                    if let Some(target) = &removed.target {
                        target.unregister_epoll_owner(&epoll_description, fd);
                        crate::event_ring::rec(
                            crate::event_ring::EPRETIRE,
                            epoll_description.id().raw() as i32,
                            fd,
                            removed_reg_gen as i32,
                        );
                    }
                    if let Some(host_fd) = host_fd {
                        // Other guest fds in THIS epoll instance can be dups of the
                        // same socket/pipe, all sharing ONE host fd. The multiplexer
                        // registration (kqueue filter / epoll entry) is keyed by host
                        // fd, so an unconditional DELETE here would deafen those
                        // survivors — but Linux epoll interest is per-fd, so they
                        // must keep getting readiness. (This is the Go `net`
                        // TestFileListener hang: File() + FileListener dup the
                        // listener, then the intermediate dup is DEL'd, which used to
                        // rip out the shared registration.) Re-bind the registration
                        // to a surviving fd with the UNION of all survivors' masks,
                        // and only drop interest classes no survivor still wants.
                        // With no survivor, deregister as before. Native epoll is
                        // per-fd and auto-removes on close, but a *dup* keeps the host
                        // fd alive, so the host-fd-keyed registration must be rebound
                        // rather than dropped — identical to the kqueue case.
                        // With a survivor: re-arm the host registration to the
                        // UNION of all survivors' currently unlatched masks
                        // (register_io also clears interest classes no survivor still
                        // wants), re-using one surviving fd's generational handle.
                        // With none: drop the host registration entirely.
                        #[cfg(any(
                            feature = "platform-macos",
                            feature = "platform-freebsd",
                            feature = "platform-netbsd"
                        ))]
                        this.rebind_epoll_host_registration(
                            kqueue,
                            interest,
                            host_fd,
                            EPOLL_REBIND_REASON_CTL_DEL,
                            None,
                        );
                        #[cfg(not(any(
                            feature = "platform-macos",
                            feature = "platform-freebsd",
                            feature = "platform-netbsd"
                        )))]
                        {
                            let mut survivor: Option<(i32, u32)> = None;
                            let mut union_events: u32 = 0;
                            for (&other, slot) in interest.iter() {
                                if this.host_fd_for_poll(other) == Some(host_fd) {
                                    survivor.get_or_insert((other, slot.reg_gen));
                                    union_events |= slot.event.events;
                                }
                            }
                            kqueue.with_mux(|mux| match survivor {
                                Some((sfd, sgen)) => {
                                    let union_events =
                                        LinuxEpollEvents::from_bits_retain(union_events);
                                    let _ = mux.register_io(
                                        host_fd.get(),
                                        pack_epoll_udata(sfd, sgen),
                                        epoll_interest_for(union_events),
                                        epoll_host_trigger_mode(union_events),
                                    );
                                }
                                None => {
                                    let _ = mux.deregister(host_fd.get());
                                }
                            });
                        }
                    }
                    clear_pending_epoll_ready(pending_ready, fd);
                    // A parked waiter still ppolls the removed fd's host fd;
                    // pop it so it rebuilds without the dead entry.
                    kqueue.wake_parked();
                    drop(open);
                    if let Some(wq) = open_file.description.wait_queue() {
                        wq.wake_all();
                    }
                    crate::probes::epoll_ctl(epfd, operation, fd, 0, 0, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                _ => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            }

        }

        fn epoll_pwait(this, cx, epfd: Fd, events: GuestPtr, maxevents: u64, timeout: u64, sigmask: GuestPtr, sigsetsize: u64) {

            let epfd = epfd.0;
            let events_address = events.0;
            let guest_abi = cx.guest_abi();
            // maxevents is a signed int; the kernel rejects <= 0 with EINVAL. A
            // negative value arrives as a huge u64, so check the signed form.
            // (LTP epoll_wait03.)
            let max_events_signed = maxevents as i32;
            let clock = Arc::clone(cx.kernel.task().container().clock());
            let timeout_ms = if timeout as i32 > 0 && clock.is_scaled() {
                let scaled =
                    clock.scale_timeout(std::time::Duration::from_millis(timeout as i32 as u64));
                i32::try_from(scaled.as_millis()).unwrap_or(i32::MAX)
            } else {
                timeout as i32
            };
            // epoll_pwait carries a sigmask (arg4) + sigsetsize (arg5); epoll_wait
            // passes a NULL mask. A non-NULL mask must have the right size and a
            // readable pointer, else EINVAL/EFAULT. (LTP epoll_pwait04.)
            let sigmask_ptr = sigmask.0;
            let memory = &mut *cx.memory;
            if max_events_signed <= 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let max_events = max_events_signed as usize;
            // The sigmask temporarily blocks signals for the duration of the wait;
            // capture it as a typed SigSet (converted at the guest sigset_t read)
            // to carry into WaitOnFds so a blocked signal doesn't interrupt the
            // wait (LTP epoll_pwait01).
            let block_signals: carrick_abi::SigSet = if sigmask_ptr != 0 {
                if sigsetsize != crate::linux_abi::LINUX_RT_SIGSET_SIZE {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                match memory.read_bytes(sigmask_ptr, crate::linux_abi::LINUX_RT_SIGSET_SIZE as usize) {
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
            // epoll_pwait's sigmask (when present) REPLACES the thread's
            // persistent mask for the wait; epoll_wait (NULL mask) is a plain
            // additive wait.
            let sig_mask = if sigmask_ptr != 0 {
                carrick_abi::WaitSigMask::Replace(block_signals)
            } else {
                carrick_abi::WaitSigMask::NONE
            };

            let files = this.captured_file_table();
            let open_file = files.read_open_files().get(&epfd).cloned();
            crate::probes::epoll_lookup(|| {
                let (slot_generation, file_description_id, lookup_kind) = match &open_file {
                    Some(open_file) => (
                        open_file.generation(),
                        open_file.description.id().raw(),
                        if open_file.description.is_epoll() { 0 } else { 1 },
                    ),
                    None => (0, 0, 2),
                };
                (
                    files.id().raw(),
                    epfd,
                    slot_generation,
                    file_description_id,
                    lookup_kind,
                )
            });
            let Some(open_file) = open_file else {
                // A valid fd that simply isn't an epoll instance is EINVAL; only a
                // genuinely bad fd is EBADF. (LTP epoll_wait03.)
                return Ok(DispatchOutcome::errno(if this.fd_is_valid(epfd) {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                }));
            };
            this.epoll_pwait_wait_core(
                memory,
                open_file,
                epfd,
                events_address,
                guest_abi,
                max_events,
                timeout_ms,
                sig_mask,
            )

        }

        fn epoll_pwait2(this, cx, epfd: Fd, events: GuestPtr, maxevents: u64, timeout: GuestPtr, sigmask: GuestPtr, sigsetsize: u64) {
            let epfd = epfd.0;
            let events_address = events.0;
            let timeout_addr = timeout.0;
            let sigmask_ptr = sigmask.0;
            let guest_abi = cx.guest_abi();
            let memory = &mut *cx.memory;
            let max_events_signed = maxevents as i32;
            if max_events_signed <= 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let max_events = max_events_signed as usize;
            // epoll_pwait2 carries the SAME sigmask (arg4) + sigsetsize (arg5)
            // contract as epoll_pwait: a non-NULL mask must have the right size
            // and a readable pointer (else EINVAL/EFAULT), and it REPLACES the
            // thread mask for the wait so a blocked signal doesn't interrupt it.
            // Capture it as a typed SigSet exactly like epoll_pwait so both feed
            // the shared wait core identically (LTP epoll_pwait01).
            let block_signals: carrick_abi::SigSet = if sigmask_ptr != 0 {
                if sigsetsize != crate::linux_abi::LINUX_RT_SIGSET_SIZE {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                match memory.read_bytes(sigmask_ptr, crate::linux_abi::LINUX_RT_SIGSET_SIZE as usize) {
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
            let sig_mask = if sigmask_ptr != 0 {
                carrick_abi::WaitSigMask::Replace(block_signals)
            } else {
                carrick_abi::WaitSigMask::NONE
            };
            // epoll_pwait2's timeout is a *timespec (nsec), unlike epoll_pwait's
            // millisecond int; decode it to the timeout_ms the shared wait core
            // consumes. NULL = block forever (-1). Invalid timespec -> EINVAL,
            // bad pointer -> EFAULT (LTP epoll_pwait04).
            let timeout_ms = if timeout_addr == 0 {
                -1
            } else {
                let timespec = match read_kernel_struct::<LinuxTimespec>(memory, timeout_addr) {
                    Ok(timespec) => timespec,
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                };
                let sec = timespec.tv_sec;
                let nsec = timespec.tv_nsec;
                if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let ms = sec.saturating_mul(1000).saturating_add(nsec / 1_000_000);
                if ms <= 0 {
                    0
                } else {
                    let dur = std::time::Duration::from_millis(ms as u64);
                    let clock = Arc::clone(cx.kernel.task().container().clock());
                    let scaled = clock.scale_timeout(dur);
                    i32::try_from(scaled.as_millis()).unwrap_or(i32::MAX)
                }
            };
            let files = this.captured_file_table();
            let open_file = files.read_open_files().get(&epfd).cloned();
            crate::probes::epoll_lookup(|| {
                let (slot_generation, file_description_id, lookup_kind) = match &open_file {
                    Some(open_file) => (
                        open_file.generation(),
                        open_file.description.id().raw(),
                        if open_file.description.is_epoll() { 0 } else { 1 },
                    ),
                    None => (0, 0, 2),
                };
                (
                    files.id().raw(),
                    epfd,
                    slot_generation,
                    file_description_id,
                    lookup_kind,
                )
            });
            let Some(open_file) = open_file else {
                return Ok(DispatchOutcome::errno(if this.fd_is_valid(epfd) {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                }));
            };
            // Delegate to the SHARED epoll_pwait wait core. epoll_pwait2 formerly
            // returned ENOSYS whenever a real wait/readiness sample was required,
            // diverging from epoll_pwait (LTP epoll_pwait01/02/03).
            this.epoll_pwait_wait_core(
                memory,
                open_file,
                epfd,
                events_address,
                guest_abi,
                max_events,
                timeout_ms,
                sig_mask,
            )
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

#[cfg(test)]
mod nested_epoll_readiness_tests {
    use super::*;
    use crate::dispatch::LinearMemory;

    fn create_epoll(
        dispatcher: &mut SyscallDispatcher,
        kernel: &crate::kernel::KernelContext,
        mem: &mut LinearMemory,
        reporter: &CompatReporter,
    ) -> i32 {
        let req = SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0]));
        match dispatcher.dispatch(kernel, req, mem, reporter).unwrap() {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("epoll_create1 failed: {other:?}"),
        }
    }

    fn create_eventfd(
        dispatcher: &mut SyscallDispatcher,
        kernel: &crate::kernel::KernelContext,
        mem: &mut LinearMemory,
        reporter: &CompatReporter,
        init_val: u64,
    ) -> i32 {
        let req = SyscallRequest::new(19, SyscallArgs::from([init_val, 0, 0, 0, 0, 0]));
        match dispatcher.dispatch(kernel, req, mem, reporter).unwrap() {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("eventfd2 failed: {other:?}"),
        }
    }

    fn close_guest_fd(
        dispatcher: &mut SyscallDispatcher,
        kernel: &crate::kernel::KernelContext,
        mem: &mut LinearMemory,
        reporter: &CompatReporter,
        fd: i32,
    ) -> bool {
        let req = SyscallRequest::new(57, SyscallArgs::from([fd as u64, 0, 0, 0, 0, 0]));
        matches!(
            dispatcher.dispatch(kernel, req, mem, reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        )
    }

    fn write_guest_epoll_event(mem: &mut LinearMemory, address: u64, events: u32, data: u64) {
        let ev = LinuxEpollEvent {
            events,
            _pad: 0,
            data,
        };
        mem.write_bytes(address, zerocopy::IntoBytes::as_bytes(&ev))
            .unwrap();
    }

    fn read_guest_epoll_event(mem: &LinearMemory, address: u64) -> LinuxEpollEvent {
        read_kernel_struct(mem, address).unwrap()
    }

    #[test]
    fn empty_inner_epoll_has_no_false_in_on_poll_or_outer_epoll() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        // Create empty inner epoll
        let inner_epfd = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Create outer epoll
        let outer_epfd = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Register inner in outer
        let event_ptr = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, event_ptr, LINUX_EPOLLIN, 42);

        let add_req = SyscallRequest::new(
            21,
            SyscallArgs::from([
                outer_epfd as u64,
                LINUX_EPOLL_CTL_ADD,
                inner_epfd as u64,
                event_ptr,
                0,
                0,
            ]),
        );
        assert!(matches!(
            dispatcher.dispatch(&kernel, add_req, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Authoritative readiness must NOT return POLLIN/EPOLLIN because inner epoll has no deliverable events!
        assert_eq!(
            dispatcher.poll_ready_events(inner_epfd, LINUX_POLLIN),
            0,
            "empty inner epoll must not report POLLIN under poll(2)"
        );
        assert_eq!(
            dispatcher.epoll_ready_events(inner_epfd, LINUX_EPOLLIN),
            0,
            "empty inner epoll must not report EPOLLIN under epoll"
        );
        assert_eq!(
            dispatcher.epoll_ready_events(outer_epfd, LINUX_EPOLLIN),
            0,
            "outer epoll monitoring empty inner epoll must not report EPOLLIN"
        );
        assert_eq!(
            dispatcher.poll_ready_events(outer_epfd, LINUX_POLLIN),
            0,
            "outer epoll monitoring empty inner epoll must not report POLLIN"
        );
    }

    #[test]
    fn threaded_eventfd_nested_epoll_wake() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        // Create eventfd (initially 0)
        let efd = create_eventfd(&mut dispatcher, &kernel, &mut guest_mem, &reporter, 0);

        // Create inner epoll
        let inner_epfd = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Create outer epoll
        let outer_epfd = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Add efd to inner_epfd
        let event_ptr1 = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, event_ptr1, LINUX_EPOLLIN, 101);
        let add_efd = SyscallRequest::new(
            21,
            SyscallArgs::from([
                inner_epfd as u64,
                LINUX_EPOLL_CTL_ADD,
                efd as u64,
                event_ptr1,
                0,
                0,
            ]),
        );
        assert!(matches!(
            dispatcher.dispatch(&kernel, add_efd, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Add inner_epfd to outer_epfd
        let event_ptr2 = 0x1020u64;
        write_guest_epoll_event(&mut guest_mem, event_ptr2, LINUX_EPOLLIN, 202);
        let add_inner = SyscallRequest::new(
            21,
            SyscallArgs::from([
                outer_epfd as u64,
                LINUX_EPOLL_CTL_ADD,
                inner_epfd as u64,
                event_ptr2,
                0,
                0,
            ]),
        );
        assert!(matches!(
            dispatcher.dispatch(&kernel, add_inner, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Initially neither is ready
        assert_eq!(dispatcher.epoll_ready_events(inner_epfd, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.epoll_ready_events(outer_epfd, LINUX_EPOLLIN), 0);

        // Get outer epoll's wait_queue
        let outer_file = dispatcher.open_file(outer_epfd).unwrap();
        let outer_wq = outer_file.wait_queue().unwrap();
        let outer_kqueue_poll_fd = dispatcher
            .host_fd_for_poll(outer_epfd)
            .map(|h| h.get())
            .unwrap_or(-1);

        // Spawn a background waiter that waits for outer epoll wake_queue or kqueue poll_fd
        let (tx, rx) = std::sync::mpsc::channel();
        let outer_wq_clone = Arc::clone(&outer_wq);
        let waiter = std::thread::spawn(move || {
            let wait_set = crate::kernel::WaitSet::for_current_executor();
            let _enrollment = wait_set.enroll(&outer_wq_clone);
            let mut pfd = libc::pollfd {
                fd: outer_kqueue_poll_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            tx.send(()).unwrap();
            let outcome = wait_set.wait(&[], Some(std::time::Duration::from_secs(5)), || false);
            let kq_ready = if outer_kqueue_poll_fd >= 0 {
                unsafe { libc::poll(&mut pfd, 1, 0) }
            } else {
                0
            };
            (
                outcome == crate::kernel::WaitSetOutcome::Woken,
                kq_ready > 0 && pfd.revents & libc::POLLIN != 0,
            )
        });

        // Wait until waiter has enrolled
        rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Write to eventfd (0 -> 1)
        let write_buf = 0x1040u64;
        guest_mem
            .write_bytes(write_buf, &1u64.to_le_bytes())
            .unwrap();
        let write_req =
            SyscallRequest::new(64, SyscallArgs::from([efd as u64, write_buf, 8, 0, 0, 0]));
        let write_outcome = dispatcher.dispatch(&kernel, write_req, &mut guest_mem, &reporter);
        assert!(matches!(
            write_outcome,
            Ok(DispatchOutcome::Returned { value: 8 })
        ));

        let (wq_woken, kq_woken) = waiter.join().expect("waiter thread joined");
        assert!(
            wq_woken,
            "registered wait queue must wake before deadline; late kqueue readiness={kq_woken}"
        );

        // After write, outer and inner are both ready
        assert_eq!(
            dispatcher.epoll_ready_events(inner_epfd, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );
        assert_eq!(
            dispatcher.epoll_ready_events(outer_epfd, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );
    }

    #[test]
    fn nested_epoll_dup_close_reuse() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        // Create eventfd (initially 0)
        let efd = create_eventfd(&mut dispatcher, &kernel, &mut guest_mem, &reporter, 0);

        // Create inner epoll
        let inner_epfd = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Add efd to inner_epfd
        let event_ptr1 = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, event_ptr1, LINUX_EPOLLIN, 101);
        let add_efd = SyscallRequest::new(
            21,
            SyscallArgs::from([
                inner_epfd as u64,
                LINUX_EPOLL_CTL_ADD,
                efd as u64,
                event_ptr1,
                0,
                0,
            ]),
        );
        assert!(matches!(
            dispatcher.dispatch(&kernel, add_efd, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Dup inner_epfd to alias_inner_fd
        let inner_open_file = dispatcher.open_file(inner_epfd).unwrap();
        let alias_inner_fd = dispatcher
            .install_fd_at_or_above(30, inner_open_file)
            .unwrap();

        // Create outer epoll
        let outer_epfd = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Add inner_epfd to outer_epfd
        let event_ptr2 = 0x1020u64;
        write_guest_epoll_event(&mut guest_mem, event_ptr2, LINUX_EPOLLIN, 202);
        let add_inner = SyscallRequest::new(
            21,
            SyscallArgs::from([
                outer_epfd as u64,
                LINUX_EPOLL_CTL_ADD,
                inner_epfd as u64,
                event_ptr2,
                0,
                0,
            ]),
        );
        assert!(matches!(
            dispatcher.dispatch(&kernel, add_inner, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Close original inner_epfd
        assert!(close_guest_fd(
            &mut dispatcher,
            &kernel,
            &mut guest_mem,
            &reporter,
            inner_epfd
        ));

        // Install a new Netlink socket (empty) into the exact slot inner_epfd
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
        let reused_fd = dispatcher
            .install_fd_at_or_above(inner_epfd, netlink_open_file)
            .unwrap();
        assert_eq!(reused_fd, inner_epfd);

        // Write to eventfd (0 -> 1)
        let write_buf = 0x1040u64;
        guest_mem
            .write_bytes(write_buf, &1u64.to_le_bytes())
            .unwrap();
        let write_req =
            SyscallRequest::new(64, SyscallArgs::from([efd as u64, write_buf, 8, 0, 0, 0]));
        assert!(matches!(
            dispatcher.dispatch(&kernel, write_req, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 8 })
        ));

        // Outer epoll must report ready because it tracks the underlying Epoll description identity (referenced by alias_inner_fd)
        assert_eq!(
            dispatcher.epoll_ready_events(outer_epfd, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "outer epoll must track stored description identity, not newly installed netlink at reused fd"
        );

        // Now close alias_inner_fd (the last handle to the inner epoll description)
        assert!(close_guest_fd(
            &mut dispatcher,
            &kernel,
            &mut guest_mem,
            &reporter,
            alias_inner_fd
        ));

        // Outer epoll must now evaluate to not ready because the target description is closed
        assert_eq!(
            dispatcher.epoll_ready_events(outer_epfd, LINUX_EPOLLIN),
            0,
            "outer epoll must not report ready after inner epoll description is closed"
        );
    }

    #[test]
    fn nested_epoll_et_and_oneshot() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x2000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        // EventFd 1 (for ET test)
        let efd1 = create_eventfd(&mut dispatcher, &kernel, &mut guest_mem, &reporter, 0);
        let inner1 = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let outer1 = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Add efd1 to inner1
        let ep1 = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, ep1, LINUX_EPOLLIN, 1);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([inner1 as u64, LINUX_EPOLL_CTL_ADD, efd1 as u64, ep1, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Add inner1 to outer1 with EPOLLET | EPOLLIN
        let ep2 = 0x1020u64;
        write_guest_epoll_event(&mut guest_mem, ep2, LINUX_EPOLLET | LINUX_EPOLLIN, 2);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([outer1 as u64, LINUX_EPOLL_CTL_ADD, inner1 as u64, ep2, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Write to efd1 (0 -> 1)
        let write_buf = 0x1040u64;
        guest_mem
            .write_bytes(write_buf, &1u64.to_le_bytes())
            .unwrap();
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(64, SyscallArgs::from([efd1 as u64, write_buf, 8, 0, 0, 0])),
            &mut guest_mem,
            &reporter,
        );

        // Outer1 is ready
        assert_eq!(
            dispatcher.epoll_ready_events(outer1, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );

        // Consume outer1 readiness via epoll_pwait (syscall 22 on aarch64)
        let events_out = 0x1100u64;
        let wait_outcome = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                22,
                SyscallArgs::from([outer1 as u64, events_out, 10, 0, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );
        assert!(
            matches!(&wait_outcome, Ok(DispatchOutcome::Returned { value: 1 })),
            "outer ET epoll first delivery: {wait_outcome:?}"
        );

        // Verify delivered 16-byte event struct and user data payload
        let delivered_event = read_guest_epoll_event(&guest_mem, events_out);
        assert_eq!(
            { delivered_event.events } & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "delivered event mask must include EPOLLIN"
        );
        assert_eq!(
            { delivered_event.data },
            2,
            "delivered event data must match registered payload"
        );

        // Outer1 is now latched (ET suppresses repeat report without new readiness change)
        assert_eq!(
            dispatcher.epoll_ready_events(outer1, LINUX_EPOLLIN),
            0,
            "ET registration must be suppressed once latched"
        );

        // Test ONESHOT:
        let outer2 = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let ep3 = 0x1060u64;
        write_guest_epoll_event(&mut guest_mem, ep3, LINUX_EPOLLONESHOT | LINUX_EPOLLIN, 3);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([outer2 as u64, LINUX_EPOLL_CTL_ADD, inner1 as u64, ep3, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Outer2 is ready
        assert_eq!(
            dispatcher.epoll_ready_events(outer2, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );

        // Consume outer2 readiness via epoll_pwait (disarms ONESHOT)
        let wait_outcome2 = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                22,
                SyscallArgs::from([outer2 as u64, events_out, 10, 0, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );
        assert!(matches!(
            wait_outcome2,
            Ok(DispatchOutcome::Returned { value: 1 })
        ));

        let delivered_event2 = read_guest_epoll_event(&guest_mem, events_out);
        assert_eq!({ delivered_event2.data }, 3);

        // Outer2 is now not ready (disarmed by delivery)
        assert_eq!(
            dispatcher.epoll_ready_events(outer2, LINUX_EPOLLIN),
            0,
            "disarmed ONESHOT registration must not report ready"
        );

        // Re-arm via MOD
        write_guest_epoll_event(&mut guest_mem, ep3, LINUX_EPOLLONESHOT | LINUX_EPOLLIN, 33);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([outer2 as u64, LINUX_EPOLL_CTL_MOD, inner1 as u64, ep3, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Outer2 is ready again
        assert_eq!(
            dispatcher.epoll_ready_events(outer2, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "re-armed ONESHOT registration must report ready"
        );
    }

    #[test]
    fn nested_epoll_drain_and_rearm() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        let efd = create_eventfd(&mut dispatcher, &kernel, &mut guest_mem, &reporter, 0);
        let inner = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let outer = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        let ep1 = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, ep1, LINUX_EPOLLIN, 10);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([inner as u64, LINUX_EPOLL_CTL_ADD, efd as u64, ep1, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        let ep2 = 0x1020u64;
        write_guest_epoll_event(&mut guest_mem, ep2, LINUX_EPOLLIN, 20);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([outer as u64, LINUX_EPOLL_CTL_ADD, inner as u64, ep2, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Initial: 0
        assert_eq!(dispatcher.epoll_ready_events(inner, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.epoll_ready_events(outer, LINUX_EPOLLIN), 0);

        // Write 5 to eventfd
        let write_buf = 0x1040u64;
        guest_mem
            .write_bytes(write_buf, &5u64.to_le_bytes())
            .unwrap();
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(64, SyscallArgs::from([efd as u64, write_buf, 8, 0, 0, 0])),
            &mut guest_mem,
            &reporter,
        );

        // Both ready
        assert_eq!(
            dispatcher.epoll_ready_events(inner, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );
        assert_eq!(
            dispatcher.epoll_ready_events(outer, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );

        // Drain eventfd (read 8 bytes)
        let read_buf_addr = 0x1060u64;
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                63,
                SyscallArgs::from([efd as u64, read_buf_addr, 8, 0, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // After drain: both not ready
        assert_eq!(dispatcher.epoll_ready_events(inner, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.epoll_ready_events(outer, LINUX_EPOLLIN), 0);

        // Write 1 to eventfd again
        guest_mem
            .write_bytes(write_buf, &1u64.to_le_bytes())
            .unwrap();
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(64, SyscallArgs::from([efd as u64, write_buf, 8, 0, 0, 0])),
            &mut guest_mem,
            &reporter,
        );

        // Both ready again
        assert_eq!(
            dispatcher.epoll_ready_events(inner, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );
        assert_eq!(
            dispatcher.epoll_ready_events(outer, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );
    }

    #[test]
    fn nested_epoll_active_wait_cancel_and_retirement() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        let inner = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let outer = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        let ep1 = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, ep1, LINUX_EPOLLIN, 99);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([outer as u64, LINUX_EPOLL_CTL_ADD, inner as u64, ep1, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        let outer_file = dispatcher.open_file(outer).unwrap();
        let outer_wq = outer_file.wait_queue().unwrap();

        // Spawn a waiter on outer's wait queue
        let (tx, rx) = std::sync::mpsc::channel();
        let outer_wq_clone = Arc::clone(&outer_wq);
        let waiter = std::thread::spawn(move || {
            let wait_set = crate::kernel::WaitSet::for_current_executor();
            let _enrollment = wait_set.enroll(&outer_wq_clone);
            tx.send(()).unwrap();
            wait_set.wait(&[], Some(std::time::Duration::from_secs(5)), || false)
        });

        rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Delete inner from outer
        let del_req = SyscallRequest::new(
            21,
            SyscallArgs::from([outer as u64, LINUX_EPOLL_CTL_DEL, inner as u64, 0, 0, 0]),
        );
        assert!(matches!(
            dispatcher.dispatch(&kernel, del_req, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Waiter must be woken!
        let outcome = waiter.join().expect("waiter thread joined");
        assert_eq!(
            outcome,
            crate::kernel::WaitSetOutcome::Woken,
            "waiter must be woken when registration is deleted"
        );

        // Readiness on outer is 0
        assert_eq!(dispatcher.epoll_ready_events(outer, LINUX_EPOLLIN), 0);
    }

    #[test]
    fn nested_epoll_3_levels_deep_wake() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        let efd = create_eventfd(&mut dispatcher, &kernel, &mut guest_mem, &reporter, 0);
        let ep1 = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let ep2 = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let ep3 = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // ep1 watches efd
        let ev1 = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, ev1, LINUX_EPOLLIN, 1);
        assert!(matches!(
            dispatcher.dispatch(
                &kernel,
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([ep1 as u64, LINUX_EPOLL_CTL_ADD, efd as u64, ev1, 0, 0]),
                ),
                &mut guest_mem,
                &reporter,
            ),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // ep2 watches ep1
        let ev2 = 0x1020u64;
        write_guest_epoll_event(&mut guest_mem, ev2, LINUX_EPOLLIN, 2);
        assert!(matches!(
            dispatcher.dispatch(
                &kernel,
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([ep2 as u64, LINUX_EPOLL_CTL_ADD, ep1 as u64, ev2, 0, 0]),
                ),
                &mut guest_mem,
                &reporter,
            ),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // ep3 watches ep2
        let ev3 = 0x1040u64;
        write_guest_epoll_event(&mut guest_mem, ev3, LINUX_EPOLLIN, 3);
        assert!(matches!(
            dispatcher.dispatch(
                &kernel,
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([ep3 as u64, LINUX_EPOLL_CTL_ADD, ep2 as u64, ev3, 0, 0]),
                ),
                &mut guest_mem,
                &reporter,
            ),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Background waiter on ep3
        let ep3_file = dispatcher.open_file(ep3).unwrap();
        let ep3_wq = ep3_file.wait_queue().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let wait_set = crate::kernel::WaitSet::for_current_executor();
            let _enrollment = wait_set.enroll(&ep3_wq);
            tx.send(()).unwrap();
            wait_set.wait(&[], Some(std::time::Duration::from_secs(5)), || false)
        });

        rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Write to eventfd (0 -> 1)
        let write_buf = 0x1060u64;
        guest_mem
            .write_bytes(write_buf, &1u64.to_le_bytes())
            .unwrap();
        assert!(matches!(
            dispatcher.dispatch(
                &kernel,
                SyscallRequest::new(64, SyscallArgs::from([efd as u64, write_buf, 8, 0, 0, 0])),
                &mut guest_mem,
                &reporter,
            ),
            Ok(DispatchOutcome::Returned { value: 8 })
        ));

        let outcome = waiter.join().expect("waiter thread joined");
        assert_eq!(
            outcome,
            crate::kernel::WaitSetOutcome::Woken,
            "waiter on 3-level deep epoll must wake on leaf write"
        );

        // All 3 levels must report ready
        assert_eq!(
            dispatcher.epoll_ready_events(ep1, LINUX_EPOLLIN),
            LINUX_EPOLLIN
        );
        assert_eq!(
            dispatcher.epoll_ready_events(ep2, LINUX_EPOLLIN),
            LINUX_EPOLLIN
        );
        assert_eq!(
            dispatcher.epoll_ready_events(ep3, LINUX_EPOLLIN),
            LINUX_EPOLLIN
        );
    }

    #[test]
    fn nested_epoll_ppoll_continuation_yield_and_wake() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x2000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        let efd = create_eventfd(&mut dispatcher, &kernel, &mut guest_mem, &reporter, 0);
        let inner = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let outer = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        let ev1_addr = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, ev1_addr, LINUX_EPOLLIN, 111);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([
                    inner as u64,
                    LINUX_EPOLL_CTL_ADD,
                    efd as u64,
                    ev1_addr,
                    0,
                    0,
                ]),
            ),
            &mut guest_mem,
            &reporter,
        );

        let ev2_addr = 0x1020u64;
        write_guest_epoll_event(&mut guest_mem, ev2_addr, LINUX_EPOLLIN, 222);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([
                    outer as u64,
                    LINUX_EPOLL_CTL_ADD,
                    inner as u64,
                    ev2_addr,
                    0,
                    0,
                ]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Call ppoll on outer with timeout = 500ms
        let pollfds_addr = 0x1100u64;
        let pfd = LinuxPollFd {
            fd: outer,
            events: LINUX_POLLIN,
            revents: 0,
        };
        guest_mem
            .write_bytes(pollfds_addr, zerocopy::IntoBytes::as_bytes(&pfd))
            .unwrap();

        let timeout_addr = 0x1120u64;
        let timespec = LinuxTimespec {
            tv_sec: 0,
            tv_nsec: 500_000_000,
        };
        guest_mem
            .write_bytes(timeout_addr, zerocopy::IntoBytes::as_bytes(&timespec))
            .unwrap();

        // ppoll must return WaitOnPollFds continuation rather than blocking synchronously
        let ppoll_outcome = dispatcher
            .dispatch(
                &kernel,
                SyscallRequest::new(
                    73,
                    SyscallArgs::from([pollfds_addr, 1, timeout_addr, 0, 0, 0]),
                ),
                &mut guest_mem,
                &reporter,
            )
            .unwrap();

        match &ppoll_outcome {
            DispatchOutcome::WaitOnFds {
                fds,
                timeout,
                completion,
                ..
            } => {
                assert_eq!(*timeout, Some(std::time::Duration::from_millis(500)));
                match completion {
                    FdWaitCompletion::Fd { on_timeout } | FdWaitCompletion::Poll { on_timeout } => {
                        assert_eq!(*on_timeout, 0);
                    }
                    FdWaitCompletion::Select { .. } => {
                        panic!("unexpected Select completion for ppoll");
                    }
                }
                assert!(!fds.is_empty(), "WaitFds must contain host poll target");
            }
            other => panic!("expected WaitOnFds outcome, got {other:?}"),
        }

        // Write to eventfd (0 -> 1)
        let write_buf = 0x1140u64;
        guest_mem
            .write_bytes(write_buf, &1u64.to_le_bytes())
            .unwrap();
        assert!(matches!(
            dispatcher.dispatch(
                &kernel,
                SyscallRequest::new(64, SyscallArgs::from([efd as u64, write_buf, 8, 0, 0, 0])),
                &mut guest_mem,
                &reporter
            ),
            Ok(DispatchOutcome::Returned { value: 8 })
        ));

        // Re-dispatch ppoll -> now returns ready value = 1
        let ppoll_ready = dispatcher
            .dispatch(
                &kernel,
                SyscallRequest::new(
                    73,
                    SyscallArgs::from([pollfds_addr, 1, timeout_addr, 0, 0, 0]),
                ),
                &mut guest_mem,
                &reporter,
            )
            .unwrap();

        assert_eq!(ppoll_ready, DispatchOutcome::Returned { value: 1 });
        let out_pfd: LinuxPollFd = read_kernel_struct(&guest_mem, pollfds_addr).unwrap();
        assert_eq!(out_pfd.revents & LINUX_POLLIN, LINUX_POLLIN);
    }

    #[test]
    fn nested_epoll_negative_control_control_wake_no_false_readiness() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x2000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        let inner = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let outer = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        let ev_addr = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, ev_addr, LINUX_EPOLLIN, 555);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([
                    outer as u64,
                    LINUX_EPOLL_CTL_ADD,
                    inner as u64,
                    ev_addr,
                    0,
                    0,
                ]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Control wake pulse on inner and outer
        let inner_file = dispatcher.open_file(inner).unwrap();
        if let Some(wq) = inner_file.wait_queue() {
            wq.wake_all();
        }
        let outer_file = dispatcher.open_file(outer).unwrap();
        if let Some(wq) = outer_file.wait_queue() {
            wq.wake_all();
        }

        // Logical readiness MUST remain 0!
        assert_eq!(dispatcher.epoll_ready_events(inner, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.epoll_ready_events(outer, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.poll_ready_events(outer, LINUX_POLLIN), 0);

        // epoll_pwait with timeout 0 returns 0 (no false events delivered)
        let events_out = 0x1100u64;
        let wait_outcome = dispatcher
            .dispatch(
                &kernel,
                SyscallRequest::new(
                    22,
                    SyscallArgs::from([outer as u64, events_out, 10, 0, 0, 0]),
                ),
                &mut guest_mem,
                &reporter,
            )
            .unwrap();
        assert_eq!(wait_outcome, DispatchOutcome::Returned { value: 0 });
    }
}
