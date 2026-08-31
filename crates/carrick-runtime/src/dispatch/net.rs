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
use carrick_spec::PortProtocol;

const EPOLL_REBIND_REASON_IO_REARM: u32 = 1;
const EPOLL_REBIND_REASON_CLOSE_DETACH: u32 = 2;

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(last) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
const EPOLL_REBIND_REASON_WAIT_SAMPLE: u32 = 3;
const EPOLL_REBIND_REASON_CTL_DEL: u32 = 4;
const MCAST_JOIN_GROUP: i32 = 42;
const MCAST_BLOCK_SOURCE: i32 = 43;
const MCAST_UNBLOCK_SOURCE: i32 = 44;
const MCAST_LEAVE_GROUP: i32 = 45;
const MCAST_JOIN_SOURCE_GROUP: i32 = 46;
const MCAST_LEAVE_SOURCE_GROUP: i32 = 47;

fn is_mcast_sockopt(level: i32, optname: i32) -> bool {
    (level == crate::linux_abi::LINUX_SOL_IP || level == crate::linux_abi::LINUX_SOL_IPV6)
        && (MCAST_JOIN_GROUP..=MCAST_LEAVE_SOURCE_GROUP).contains(&optname)
}

fn mcast_source_specific(optname: i32) -> Option<bool> {
    match optname {
        MCAST_JOIN_GROUP | MCAST_LEAVE_GROUP | MCAST_BLOCK_SOURCE | MCAST_UNBLOCK_SOURCE => {
            Some(false)
        }
        MCAST_JOIN_SOURCE_GROUP | MCAST_LEAVE_SOURCE_GROUP => Some(true),
        _ => None,
    }
}

fn mcast_setsockopt_outcome(
    memberships: &mut Vec<SocketMulticastMembership>,
    level: i32,
    optname: i32,
    optval: Vec<u8>,
) -> DispatchOutcome {
    let Some(source_specific) = mcast_source_specific(optname) else {
        return DispatchOutcome::errno(LINUX_ENOPROTOOPT);
    };
    if optval.is_empty() {
        return DispatchOutcome::errno(LINUX_EINVAL);
    }
    let membership = SocketMulticastMembership {
        level,
        source_specific,
        optval,
    };
    match optname {
        MCAST_JOIN_GROUP | MCAST_JOIN_SOURCE_GROUP => {
            if !memberships.contains(&membership) {
                memberships.push(membership);
            }
            DispatchOutcome::Returned { value: 0 }
        }
        MCAST_LEAVE_GROUP | MCAST_LEAVE_SOURCE_GROUP => {
            if let Some(pos) = memberships.iter().position(|entry| entry == &membership) {
                memberships.remove(pos);
                DispatchOutcome::Returned { value: 0 }
            } else {
                DispatchOutcome::errno(crate::linux_abi::LINUX_EADDRNOTAVAIL)
            }
        }
        MCAST_BLOCK_SOURCE | MCAST_UNBLOCK_SOURCE => {
            if memberships.iter().any(|entry| {
                entry.level == membership.level
                    && !entry.source_specific
                    && entry.optval == membership.optval
            }) {
                DispatchOutcome::Returned { value: 0 }
            } else {
                DispatchOutcome::errno(crate::linux_abi::LINUX_EADDRNOTAVAIL)
            }
        }
        _ => DispatchOutcome::errno(LINUX_ENOPROTOOPT),
    }
}

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

fn host_sockaddr_to_socket_addr(bytes: &[u8]) -> Option<std::net::SocketAddr> {
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

fn socket_addr_to_host_sockaddr(addr: std::net::SocketAddr) -> Option<Vec<u8>> {
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

fn socket_addr_to_linux_sockaddr(addr: std::net::SocketAddr) -> Option<Vec<u8>> {
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

fn host_sockaddr_bytes(host_fd: i32) -> Option<Vec<u8>> {
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

fn host_socket_is_connected(host_fd: i32) -> bool {
    let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
    let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
    let rc =
        unsafe { libc::getpeername(host_fd, sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _) };
    rc == 0
}
pub(super) mod recverr;
mod sctp;

/// Drop a closed socket's SCTP message boundaries (see [`sctp`]).
pub(crate) fn sctp_forget(host_fd: i32) {
    sctp::forget(host_fd);
}
pub(super) mod reuseport;
pub(super) mod support;
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
pub(super) use support::{drain_netlink_queue, set_host_nonblocking};

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
    // example, a stream socket already at its receive-buffer ceiling). Leave
    // that filter disabled until guest I/O advances the latch; the
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

/// Resolve a host `connect` that reported SUCCESS (`rc==0` or `EISCONN`) into the
/// guest result, consulting `SO_ERROR` first. carrick makes the host socket
/// non-blocking before `connect` (so it never blocks the dispatcher under the
/// lock), so a "success" return does NOT prove the connection completed: an async
/// connect that FAILED (e.g. `ECONNREFUSED` to a non-listening port) is reported
/// by macOS as `EISCONN` on the POLLOUT re-dispatch, deferring the real error to
/// the first `recv`. A BLOCKING guest `connect(2)` must surface that error at
/// connect time — otherwise `socket.create_connection`'s address fallback
/// (IPv6 `::1` → IPv4 `127.0.0.1`) never triggers and CPython's network suites
/// (ftplib/httplib/imaplib/docxmlrpc) wrongly fail. `SO_ERROR` is the
/// authoritative async-connect result; a healthy socket reports 0.
/// Linux `connect()` treats INADDR_ANY (0.0.0.0) as the loopback (127.0.0.1), but
/// FreeBSD/macOS return ENETUNREACH for it. Rewrite an unspecified IPv4 connect target
/// to loopback so a guest connecting to `0.0.0.0:port` behaves like Linux (LTP
/// send01/recv01/sendto01/recvfrom01). `sin_addr` is at offset 4 in both the Linux and
/// BSD `sockaddr_in`. A no-op on a Linux host, where the kernel already does this.
#[cfg(not(target_os = "linux"))]
fn rewrite_unspecified_connect_loopback(family: i32, host_addr: &mut [u8]) {
    if family == libc::AF_INET && host_addr.len() >= 8 && host_addr[4..8] == [0, 0, 0, 0] {
        host_addr[4..8].copy_from_slice(&[127, 0, 0, 1]);
    }
}

#[cfg(target_os = "linux")]
fn rewrite_unspecified_connect_loopback(_family: i32, _host_addr: &mut [u8]) {}

// The transform only exists (and only matters) on a non-Linux host, where the
// kernel does NOT itself remap 0.0.0.0 → loopback; on Linux it is a no-op, so
// the test is compiled out there rather than asserting an intentional no-op.
#[cfg(all(test, not(target_os = "linux")))]
mod connect_loopback_tests {
    use super::*;

    /// A host `sockaddr_in` laid out as `[sa_family:u16][sin_port:u16 BE][sin_addr:4][pad:8]`.
    fn sockaddr_in(family: i32, addr: [u8; 4], port_be: [u8; 2]) -> Vec<u8> {
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(&(family as u16).to_ne_bytes());
        buf[2..4].copy_from_slice(&port_be);
        buf[4..8].copy_from_slice(&addr);
        buf
    }

    #[test]
    fn inaddr_any_rewrites_to_loopback_preserving_port() {
        // 0.0.0.0:8080 (port 0x1f90 big-endian) must become 127.0.0.1:8080.
        let mut buf = sockaddr_in(libc::AF_INET, [0, 0, 0, 0], [0x1f, 0x90]);
        rewrite_unspecified_connect_loopback(libc::AF_INET, &mut buf);
        assert_eq!(
            &buf[4..8],
            &[127, 0, 0, 1],
            "INADDR_ANY (0.0.0.0) must be rewritten to loopback"
        );
        assert_eq!(&buf[2..4], &[0x1f, 0x90], "the port must be preserved");
        // sa_family must be untouched.
        assert_eq!(
            u16::from_ne_bytes([buf[0], buf[1]]),
            libc::AF_INET as u16,
            "the address family must be preserved"
        );
    }

    #[test]
    fn real_ipv4_address_is_left_untouched() {
        let mut buf = sockaddr_in(libc::AF_INET, [10, 0, 0, 5], [0x00, 0x50]);
        rewrite_unspecified_connect_loopback(libc::AF_INET, &mut buf);
        assert_eq!(
            &buf[4..8],
            &[10, 0, 0, 5],
            "a non-unspecified address must NOT be rewritten"
        );
    }

    #[test]
    fn non_inet_family_is_untouched_even_when_address_is_zero() {
        // The loopback quirk is IPv4-only: an AF_INET6 (or any non-AF_INET)
        // sockaddr with a zeroed addr field must be left exactly as-is.
        let mut buf = sockaddr_in(libc::AF_INET6, [0, 0, 0, 0], [0x01, 0xbb]);
        rewrite_unspecified_connect_loopback(libc::AF_INET6, &mut buf);
        assert_eq!(
            &buf[4..8],
            &[0, 0, 0, 0],
            "IPv6 / other families must never be rewritten"
        );
    }

    #[test]
    fn buffer_shorter_than_sin_addr_is_a_noop_not_a_panic() {
        // A truncated buffer (< 8 bytes) must be left alone rather than panicking
        // on the [4..8] slice.
        let mut buf = vec![0u8; 4];
        rewrite_unspecified_connect_loopback(libc::AF_INET, &mut buf);
        assert_eq!(buf, vec![0u8; 4]);
    }
}

fn connect_success_or_pending_error(host_fd: i32) -> DispatchOutcome {
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
    if rc == 0 && host_err != 0 {
        return DispatchOutcome::errno(crate::host_to_linux_errno(host_err));
    }
    DispatchOutcome::Returned { value: 0 }
}

fn guest_unix_pathname(memory: &impl CurrentMmMemory, addr: u64, addrlen: u32) -> Option<String> {
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

#[cfg(not(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd",
    target_os = "linux"
)))]
fn host_stream_socket_read_eof(host_fd: i32) -> bool {
    let mut byte = [0u8; 1];
    let rc = unsafe {
        // BLOCKING-IO-OK: MSG_DONTWAIT is passed
        libc::recv(
            host_fd,
            byte.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    rc == 0
}

#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(super) fn host_stream_socket_rdhup(host_fd: i32) -> bool {
    use carrick_host_bsd::Kqueue;
    use carrick_host_bsd::kqueue::Kevent;

    let Some(kq) = Kqueue::new_internal() else {
        return false;
    };
    let add = Kevent::read(
        host_fd,
        carrick_portable::EV_ADD | carrick_portable::EV_ENABLE | carrick_portable::EV_CLEAR,
    );
    if kq.apply(&[add]).is_err() {
        return false;
    }
    let mut out = [Kevent::empty(); 1];
    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    matches!(
        kq.wait(&[], &mut out, Some(&zero)),
        Ok(n) if n >= 1
            && out[0].filter() == libc::EVFILT_READ
            && out[0].flags() & libc::EV_EOF != 0
    )
}

#[cfg(target_os = "linux")]
pub(super) fn host_stream_socket_rdhup(host_fd: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd: host_fd,
        events: libc::POLLRDHUP,
        revents: 0,
    };
    unsafe { libc::poll(&mut pfd, 1, 0) > 0 && pfd.revents & libc::POLLRDHUP != 0 }
}

#[cfg(not(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd",
    target_os = "linux"
)))]
pub(super) fn host_stream_socket_rdhup(host_fd: i32) -> bool {
    host_stream_socket_read_eof(host_fd)
}

fn linux_msg_trunc_recv_capacity(host_fd: i32, guest_len: usize, flags: i32) -> usize {
    if flags & LINUX_MSG_TRUNC == 0 {
        return guest_len;
    }
    host_socket_buffer_size(host_fd, libc::SO_RCVBUF)
        .ok()
        .and_then(|size| usize::try_from(size).ok())
        .unwrap_or(guest_len)
        .max(guest_len)
        .min(crate::dispatch::MAX_RW_COUNT)
}

#[cfg(test)]
mod host_stream_socket_read_eof_tests {
    use super::host_stream_socket_rdhup;

    #[test]
    fn detects_peer_half_close_while_payload_remains_buffered() {
        let mut sockets = [-1; 2];
        // SAFETY: socketpair initializes both descriptors on success; every
        // descriptor is closed before returning from the test.
        unsafe {
            assert_eq!(
                libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockets.as_mut_ptr()),
                0
            );
            assert_eq!(libc::write(sockets[0], b"payload".as_ptr().cast(), 7), 7);
            assert_eq!(libc::shutdown(sockets[0], libc::SHUT_WR), 0);

            assert!(
                host_stream_socket_rdhup(sockets[1]),
                "RDHUP must be visible before the queued payload is drained"
            );

            libc::close(sockets[0]);
            libc::close(sockets[1]);
        }
    }
}

#[cfg(test)]
mod host_dgram_msg_trunc_tests {
    use super::{LINUX_MSG_TRUNC, linux_msg_trunc_recv_capacity};

    #[test]
    fn widens_the_host_receive_without_widening_the_guest_copy() {
        let mut sockets = [-1; 2];
        // SAFETY: socketpair initializes both descriptors on success; every
        // descriptor is closed before returning from the test.
        unsafe {
            assert_eq!(
                libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sockets.as_mut_ptr()),
                0
            );
            assert_eq!(
                libc::send(sockets[0], b"twelve-bytes".as_ptr().cast(), 12, 0),
                12
            );

            let capacity = linux_msg_trunc_recv_capacity(sockets[1], 4, LINUX_MSG_TRUNC);
            assert!(capacity >= 12, "host buffer must fit the queued datagram");
            let mut host = vec![0u8; capacity];
            let received = libc::recv(
                sockets[1],
                host.as_mut_ptr().cast(),
                host.len(),
                libc::MSG_TRUNC | libc::MSG_DONTWAIT,
            );
            assert_eq!(received, 12);
            assert_eq!(&host[..4], b"twel");

            libc::close(sockets[0]);
            libc::close(sockets[1]);
        }
    }
}

fn decode_accept4_flags(flags: i32) -> Option<LinuxSocketTypeFlags> {
    LinuxSocketTypeFlags::from_bits(flags)
}

#[cfg(test)]
mod accept4_flag_tests {
    use super::*;

    #[test]
    fn rejects_unknown_flags_before_accept_side_effects() {
        assert_eq!(decode_accept4_flags(0), Some(LinuxSocketTypeFlags::empty()));
        assert_eq!(
            decode_accept4_flags(LinuxSocketTypeFlags::NONBLOCK.bits()),
            Some(LinuxSocketTypeFlags::NONBLOCK)
        );
        assert_eq!(
            decode_accept4_flags(LinuxSocketTypeFlags::CLOEXEC.bits()),
            Some(LinuxSocketTypeFlags::CLOEXEC)
        );
        assert_eq!(decode_accept4_flags(0x1234_5678), None);
        assert_eq!(decode_accept4_flags(-1), None);
    }

    #[test]
    fn detects_connected_stream_without_consuming_data() {
        let mut connected = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, connected.as_mut_ptr())
            },
            0
        );
        assert!(host_socket_is_connected(connected[0]));
        unsafe {
            libc::close(connected[0]);
            libc::close(connected[1]);
        }

        let unconnected = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(unconnected >= 0);
        assert!(!host_socket_is_connected(unconnected));
        unsafe { libc::close(unconnected) };
    }
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
                // eventfd is host-backed by a readiness pipe (read end readable
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
        }
    }

    pub(in crate::dispatch) fn detach_fd_from_epolls(&self, fd: i32) {
        let detached_host_fd = self.host_fd_for_poll(fd);
        let (detached_description, descriptions, should_auto_detach) = {
            let files = self.captured_file_table();
            let table = files.read_open_files();
            let detached_description = table.get(&fd).map(|file| file.description.clone());
            let logical_refs = detached_description
                .as_ref()
                .map_or(1, |target| target.fd_ref_count());
            let descriptions: Vec<Arc<crate::kernel::FileDescription>> =
                table.values().map(|of| of.description.clone()).collect();
            // Linux retains every registration for an open description until
            // its final fd slot closes, including registrations installed
            // through a dup alias whose numeric slot closed earlier.
            let should_auto_detach = logical_refs == 1;
            (detached_description, descriptions, should_auto_detach)
        };
        if should_auto_detach && let Some(target) = &detached_description {
            self.detach_description_from_all_epolls(target, detached_host_fd);
            return;
        }
        for description in descriptions {
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
    fn blocking_io<F>(
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
                        on_timeout: LINUX_EAGAIN.guest_retval(),
                        sig_mask: carrick_abi::WaitSigMask::NONE,
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
                sock_type: base_type,
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
        // Reject Linux-invalid (family,type,protocol) tuples with the canonical
        // errno before macOS gets a chance to report a divergent one. (socket01)
        if let Some(errno) = canonical_socket_errno(family, base_type, protocol) {
            return DispatchOutcome::errno(errno);
        }
        let host_family = linux_to_host_af(family);
        let host_type = host_socktype_backing(family, base_type);
        // macOS has no UDPLITE protocol, so back IPPROTO_UDPLITE with a plain UDP
        // socket (proto 0 → UDP for SOCK_DGRAM). UDPLITE's datagram send/recv is
        // UDP-identical; only the checksum-coverage sockopts differ, accepted as
        // no-ops below. The guest is LINUX python, whose test_socket runs the
        // whole UDPLITE suite (native-macOS python skips it — IPPROTO_UDPLITE
        // undefined there); pass-through socket() returned EPROTONOSUPPORT and
        // ERRORed every UDPLITE test at setUp.
        // macOS has no SCTP either. A guest SCTP SOCK_STREAM is a reliable,
        // ordered byte stream to ONE peer, which is what a TCP socket already
        // provides — the same substitution UDPLITE gets below, and the same shape
        // as backing a guest AF_UNIX SEQPACKET with a host SOCK_STREAM. The guest
        // protocol is recorded unchanged in the OpenDescription, so `SO_PROTOCOL`
        // still reports SCTP.
        //
        // Deliberately NOT extended to SOCK_SEQPACKET: that is message-oriented
        // and multi-streamed, and TCP cannot reconstruct its boundaries. It stays
        // EPROTONOSUPPORT rather than pretending.
        let host_protocol = if protocol == LINUX_IPPROTO_SCTP && base_type == LINUX_SOCK_STREAM
            || protocol == LINUX_IPPROTO_UDPLITE
            || cfg!(carrick_bsd)
                && matches!(family, LINUX_AF_INET | LINUX_AF_INET6)
                && base_type == LINUX_SOCK_RAW
        {
            0
        } else {
            protocol
        };
        let host_fd = match (unsafe { libc::socket(host_family, host_type, host_protocol) })
            .host_syscall_errno()
        {
            Ok(value) => value,
            // FreeBSD has no Linux-style datagram ICMP ping socket. Keep a real
            // nonblocking UDP fd as the poll/close carrier; loopback echo
            // request/reply semantics are synthesized at sendto/recvfrom below.
            Err(errno)
                if errno == linux_errno::EPROTONOSUPPORT
                    && family == LINUX_AF_INET
                    && base_type == LINUX_SOCK_DGRAM
                    && protocol == LINUX_IPPROTO_ICMP =>
            {
                match (unsafe { libc::socket(host_family, host_type, 0) }).host_syscall_errno() {
                    Ok(value) => value,
                    Err(errno) => return DispatchOutcome::errno(errno),
                }
            }
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        // The host fd is always nonblocking; Carrick preserves the guest's
        // blocking mode in Linux-visible status_flags and waits outside the
        // dispatcher lock when a blocking operation would block.
        set_host_nonblocking(host_fd);
        // Give stream sockets a Linux-sized host backing buffer so guest
        // non-blocking copy/splice loops do not churn on macOS' small defaults.
        if let Err(errno) = widen_stream_socket_buffers(host_fd, family, base_type) {
            unsafe { libc::close(host_fd) };
            return DispatchOutcome::errno(errno);
        }
        let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostSocket {
                host_fd: HostFdRef::new(host_fd),
                family,
                type_: base_type,
                protocol,
                base: OpenDescriptionBase::new(status_flags),
                mcast_memberships: Vec::new(),
                synthetic_recv: std::collections::VecDeque::new(),
            })),
            status_flags,
            fd_flags,
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
        let open = open_file.description.read()?;
        match &*open {
            OpenDescription::HostPipe { host_fd, .. }
            | OpenDescription::HostSocket { host_fd, .. }
            | OpenDescription::HostFile { host_fd, .. } => Some(host_fd.raw()),
            _ => None,
        }
    }

    /// Install a HOST fd received via `SCM_RIGHTS` as a fresh GUEST fd, wrapping
    /// it in the right `OpenDescription` by `fstat`ing its type (socket → host
    /// socket, fifo → host pipe, else a host file). The received host fd is
    /// already a live kernel fd the macOS kernel handed us; we keep its blocking
    /// mode non-blocking to satisfy the dispatcher's wait invariants. Returns
    /// the new guest fd, or `None` on failure (the caller closes the host fd).
    fn install_received_host_fd(&self, host_fd: i32, cloexec: bool) -> Option<i32> {
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
                host_fd: HostFdRef::new(host_fd),
                family: libc::AF_UNIX,
                type_: so_type,
                protocol: 0,
                base: OpenDescriptionBase::new(LINUX_O_RDWR),
                mcast_memberships: Vec::new(),
                synthetic_recv: std::collections::VecDeque::new(),
            }
        } else if kind == libc::S_IFIFO {
            // A pipe end. Probe its direction so reads/writes route correctly;
            // a pipe read end rejects writes and vice versa. F_GETFL's access
            // mode is unreliable for pipe ends, so treat it as bidirectional-
            // safe: mark it not-a-read-end unless a write probe fails. The
            // forkserver passes both ends; CPython only uses each in one
            // direction, so a conservative bidirectional flag is safe.
            OpenDescription::HostPipe {
                host_fd: HostFdRef::new(host_fd),
                is_read_end: false,
                // A pipe end received over SCM_RIGHTS: its host inode (already
                // fstat'd above) is the same kernel-object identity in this
                // process, so it serves as a stable FASYNC join key.
                pipe_id: st.st_ino as u64,
                pty: None,
                bidirectional: true,
                write_kind: HostWriteKind::PipeLike,
                base: OpenDescriptionBase::new(0),
                stdio_stream: None,
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
                host_fd: HostFdRef::new(host_fd),
                metadata,
                writable: true,
                base: OpenDescriptionBase::new(0),
            }
        };
        // MSG_CMSG_CLOEXEC: install the received fd close-on-exec. (audit M3)
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        // On an install failure (EMFILE) the dropped OpenFile's description —
        // the fd's ONE owner — closes the received host fd; the caller must
        // not close it again.
        let open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(description)),
            0,
            fd_flags,
        );
        self.install_fd_at_or_above(3, open_file).ok()
    }

    /// Pull a (host_fd, family) pair out of the dispatcher's fd table.
    pub(in crate::dispatch) fn host_socket_lookup(
        &self,
        fd: i32,
    ) -> Result<(HostFd, i32), LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            return Err(LINUX_EBADF);
        };
        let open = open_file.description.read().ok_or(LINUX_ENOTSOCK)?;
        match &*open {
            OpenDescription::HostSocket {
                host_fd, family, ..
            } => Ok((host_fd.view(), *family)),
            _ => Err(LINUX_ENOTSOCK),
        }
    }

    /// Read the per-description `connect_in_progress` flag for `fd` (false if the
    /// fd is missing or not a HostSocket). See `OpenDescriptionBase.connect_in_progress`.
    fn socket_connect_in_progress(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            matches!(of.description.read().as_deref(), Some(OpenDescription::HostSocket { base, .. }) if base.connect_in_progress())
        })
    }

    /// Set/clear the per-description `connect_in_progress` flag for `fd`.
    fn set_socket_connect_in_progress(&self, fd: i32, on: bool) {
        if let Some(open_file) = self.open_file(fd)
            && let Some(mut open) = open_file.description.write()
            && let OpenDescription::HostSocket { base, .. } = &mut *open
        {
            base.set_connect_in_progress(on);
        }
    }

    fn set_socket_pending_error(&self, fd: i32, errno: carrick_abi::LinuxErrno) {
        if let Some(open_file) = self.open_file(fd)
            && let Some(mut open) = open_file.description.write()
            && let OpenDescription::HostSocket { base, .. } = &mut *open
        {
            base.set_pending_socket_error(errno.get());
        }
    }

    fn take_socket_pending_error(&self, fd: i32) -> Option<carrick_abi::LinuxErrno> {
        let open_file = self.open_file(fd)?;
        let mut open = open_file.description.write()?;
        let OpenDescription::HostSocket { base, .. } = &mut *open else {
            return None;
        };
        base.take_pending_socket_error()
            .map(carrick_abi::LinuxErrno::new)
    }

    fn set_socket_error_after_send(&self, fd: i32, errno: carrick_abi::LinuxErrno) {
        if std::env::var_os("CARRICK_NET_DEBUG").is_some() {
            eprintln!("NETDBG set_error_after_send fd={fd} errno={}", errno.get());
        }
        if let Some(open_file) = self.open_file(fd)
            && let Some(mut open) = open_file.description.write()
            && let OpenDescription::HostSocket { base, .. } = &mut *open
        {
            base.set_socket_error_after_send(errno.get());
        }
    }

    fn clear_socket_error_after_send(&self, fd: i32) {
        if let Some(open_file) = self.open_file(fd)
            && let Some(mut open) = open_file.description.write()
            && let OpenDescription::HostSocket { base, .. } = &mut *open
        {
            base.clear_socket_error_after_send();
        }
    }

    fn reset_host_stream_socket_for_disconnect(&self, fd: i32) -> Result<(), LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            return Err(LINUX_EBADF);
        };
        let mut open = open_file.description.write().ok_or(LINUX_ENOTSOCK)?;
        let OpenDescription::HostSocket {
            host_fd,
            family,
            type_,
            base,
            synthetic_recv,
            ..
        } = &mut *open
        else {
            return Err(LINUX_ENOTSOCK);
        };
        if *type_ != LINUX_SOCK_STREAM {
            return Err(LINUX_EINVAL);
        }
        let new_host = unsafe {
            libc::socket(
                linux_to_host_af(*family),
                host_socktype_backing(*family, *type_),
                0,
            )
        }
        .host_syscall_errno()?;
        set_host_nonblocking(new_host);
        if let Err(errno) = widen_stream_socket_buffers(new_host, *family, *type_) {
            unsafe { libc::close(new_host) };
            return Err(errno);
        }
        *host_fd = HostFdRef::new(new_host);
        synthetic_recv.clear();
        base.set_connect_in_progress(false);
        base.clear_socket_error_after_send();
        let _ = base.take_pending_socket_error();
        Ok(())
    }

    fn queue_socket_error_after_send(&self, fd: i32) {
        if std::env::var_os("CARRICK_NET_DEBUG").is_some() {
            eprintln!("NETDBG queue_error_after_send fd={fd}");
        }
        if let Some(open_file) = self.open_file(fd)
            && let Some(mut open) = open_file.description.write()
            && let OpenDescription::HostSocket { base, .. } = &mut *open
            && let Some(errno) = base.socket_error_after_send()
        {
            base.set_pending_socket_error(errno);
        }
    }

    fn record_rewritten_connect_addresses(
        &self,
        family: i32,
        host_fd: i32,
        guest_peer: std::net::SocketAddr,
        host_peer: HostSocketAddr,
        protocol: PortProtocol,
    ) {
        let host_local = host_socket_addr(host_fd, family, false);
        let guest_local = self
            .network
            .provider
            .guest_visible_local_addr(crate::network::SocketKey::for_host_fd(host_fd))
            .ok()
            .flatten()
            .or_else(|| {
                host_local.and_then(|local| {
                    (family == libc::AF_INET
                        && self.network.spec.mode == carrick_spec::NetworkMode::Bridge)
                        .then_some(GuestSocketAddr(std::net::SocketAddr::new(
                            if guest_peer.ip().is_loopback() {
                                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                            } else {
                                std::net::IpAddr::V4(self.network.spec.ipv4)
                            },
                            local.port(),
                        )))
                })
            });
        let _ = self.network.provider.record_socket_addresses(
            self.network.spec.namespace_id.as_ref(),
            crate::network::SocketKey::for_host_fd(host_fd),
            guest_local,
            host_local.map(HostSocketAddr).or(Some(host_peer)),
            Some(GuestSocketAddr(guest_peer)),
            protocol,
        );
    }

    fn prepare_rewritten_connect_source(
        &self,
        family: i32,
        host_fd: i32,
        guest_peer: std::net::SocketAddr,
        host_peer: HostSocketAddr,
        protocol: PortProtocol,
    ) -> Result<(), carrick_abi::LinuxErrno> {
        if family == libc::AF_INET
            && self.network.spec.mode == carrick_spec::NetworkMode::Bridge
            && self
                .network
                .provider
                .guest_visible_local_addr(crate::network::SocketKey::for_host_fd(host_fd))
                .ok()
                .flatten()
                .is_none()
        {
            let needs_autobind = host_socket_addr(host_fd, family, false)
                .map(|addr| addr.port() == 0)
                .unwrap_or(true);
            if needs_autobind
                && let Some(host_local) = socket_addr_to_host_sockaddr(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
            {
                let rc = unsafe {
                    libc::bind(
                        host_fd,
                        host_local.as_ptr() as *const _,
                        host_local.len() as u32,
                    )
                };
                rc.host_syscall_errno()?;
            }
        }
        self.record_rewritten_connect_addresses(family, host_fd, guest_peer, host_peer, protocol);
        Ok(())
    }

    /// True iff `fd` is a HostSocket with SO_PASSCRED enabled (audit M2).
    fn socket_so_passcred(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            matches!(of.description.read().as_deref(), Some(OpenDescription::HostSocket { base, .. }) if base.so_passcred())
        })
    }

    /// Peer `(pid, uid, gid)` for an AF_UNIX `host_fd`, from LOCAL_PEERCRED +
    /// LOCAL_PEERPID (best-effort; 0 where unavailable). Used to synthesize the
    /// SCM_CREDENTIALS ancillary message for SO_PASSCRED. (audit M2)
    /// The `ucred` an `SO_PASSCRED` receiver sees, in GUEST terms.
    ///
    /// Never `carrick_portable::peer_ucred(host_fd)`. That reads the HOST's
    /// credentials and leaked them straight into the guest: measured against the
    /// Docker oracle, a socketpair peer reported `pid=97396 uid=501 gid=20` — the
    /// macOS pid and the Mac user's uid/gid — where Linux reports the guest's own
    /// `pid=1 uid=0 gid=0`. Under HVPatch a host pid is the CARRIER's, identical
    /// for every guest process, so it could never have been a valid answer either
    /// (`identity_pid`'s own doc names that trap).
    ///
    /// The peer of a `socketpair` — the shape `SO_PASSCRED` receivers
    /// overwhelmingly use, and the one Go's `TestSCMCredentials` exercises — is
    /// the same guest process. A cross-process AF_UNIX peer would need the
    /// endpoint registry to carry the connector's identity; until it does, this
    /// still answers in the guest's domain rather than leaking the host's.
    fn peer_ucred(&self, _host_fd: i32) -> (u32, u32, u32) {
        let creds = self.cred_snapshot();
        (self.identity_pid(), creds.euid.raw(), creds.egid.raw())
    }

    /// The GUEST-requested socket type for `fd` (e.g. SOCK_SEQPACKET), which can
    /// differ from the host backing — carrick backs a guest AF_UNIX SEQPACKET
    /// with a host SOCK_STREAM, so the host's SO_TYPE would mis-report it.
    pub(in crate::dispatch) fn socket_guest_type(&self, fd: i32) -> Option<i32> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read()?;
        match &*open {
            OpenDescription::HostSocket { type_, .. } => Some(*type_),
            OpenDescription::Netlink { sock_type, .. } => Some(*sock_type),
            _ => None,
        }
    }

    /// The guest's `(type, protocol)` for `fd` in ONE lock acquisition.
    ///
    /// `recvmsg` needs both — the protocol to spot an SCTP stream, the type to
    /// decide whether MSG_TRUNC can apply — and asking separately took the open
    /// description's lock three times per read. That cost nothing measurable
    /// single-threaded (`go-net_http` stays at ~49 s) but lock contention
    /// amplifies superlinearly, and the suite went from a 53.8 s MATCH to a
    /// 540 s truncation under 8-worker gate load.
    fn socket_guest_type_and_protocol(&self, fd: i32) -> Option<(i32, i32)> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read()?;
        match &*open {
            OpenDescription::HostSocket {
                type_, protocol, ..
            } => Some((*type_, *protocol)),
            OpenDescription::Netlink {
                sock_type,
                protocol,
                ..
            } => Some((*sock_type, *protocol)),
            _ => None,
        }
    }

    fn socket_guest_protocol(&self, fd: i32) -> Option<i32> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read()?;
        match &*open {
            OpenDescription::HostSocket { protocol, .. } => Some(*protocol),
            OpenDescription::Netlink { protocol, .. } => Some(*protocol),
            _ => None,
        }
    }

    fn socket_reuseport(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            matches!(of.description.read().as_deref(), Some(OpenDescription::HostSocket { base, .. }) if base.so_reuseport())
        })
    }

    fn socket_port_protocol(&self, fd: i32) -> Option<PortProtocol> {
        match self.socket_guest_type(fd)? {
            LINUX_SOCK_STREAM => Some(PortProtocol::Tcp),
            LINUX_SOCK_DGRAM => Some(PortProtocol::Udp),
            _ => None,
        }
    }

    /// True iff `fd` refers to a synthetic AF_NETLINK socket.
    pub(super) fn fd_is_netlink(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            matches!(
                of.description.read().as_deref(),
                Some(OpenDescription::Netlink { .. })
            )
        })
    }

    /// Handle a netlink "send": parse the request and queue a synthetic
    /// rtnetlink dump reply (or a bare NLMSG_DONE for requests we don't
    /// specifically model). Returns the number of bytes "sent".
    fn netlink_send(&self, fd: i32, request: &[u8]) -> DispatchOutcome {
        let Some(open_file) = self.open_file(fd) else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        let reply = {
            let Some(open) = open_file.description.read() else {
                return DispatchOutcome::errno(LINUX_ENOTSOCK);
            };
            let OpenDescription::Netlink { pid, .. } = &*open else {
                return DispatchOutcome::errno(LINUX_ENOTSOCK);
            };
            let dest_pid = if *pid != 0 { *pid } else { std::process::id() };
            // ONE encoder, over the namespace the CALLING task belongs to. The
            // mode used to select between two encoders over two different data
            // sources — the spec-built model for bridge, a fresh `getifaddrs(3)`
            // walk for host — which is why the guest's own surfaces disagreed
            // with each other, and why the accurate encoder was the one the
            // conformance lane never exercised.
            let net_ns = self.caller_net_ns();
            build_netlink_reply_for_snapshot(request, dest_pid, &net_ns.view())
        };
        if let Some(mut open) = open_file.description.write() {
            if let OpenDescription::Netlink { recv_queue, .. } = &mut *open {
                let was_empty = recv_queue.is_empty();
                recv_queue.extend(reply);
                if was_empty && !recv_queue.is_empty() {
                    drop(open);
                    self.notify_inmem_epoll();
                    crate::host_signal::wake_all_waiters();
                }
            }
        }
        DispatchOutcome::Returned {
            value: request.len() as i64,
        }
    }

    /// recvfrom path for netlink: drain queued reply bytes into guest memory,
    /// or block/EAGAIN while a blocking caller waits for a future kernel event.
    fn netlink_recv(
        &self,
        fd: i32,
        buf_addr: u64,
        len: usize,
        flags: i32,
        memory: &mut impl CurrentMmMemory,
    ) -> DispatchOutcome {
        if len == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        let chunk = self.netlink_drain(fd, len);
        if chunk.is_empty() {
            return self.empty_netlink_recv(fd, flags);
        }
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
        let Some(mut open) = open_file.description.write() else {
            return Vec::new();
        };
        let OpenDescription::Netlink { recv_queue, .. } = &mut *open else {
            return Vec::new();
        };
        let take = recv_queue.len().min(max);
        recv_queue.drain(..take).collect()
    }

    fn empty_netlink_recv(&self, fd: i32, flags: i32) -> DispatchOutcome {
        if self.io_is_nonblocking(fd, flags) {
            return DispatchOutcome::errno(LINUX_EAGAIN);
        }
        let files = self.captured_file_table();
        let fds = match WaitFds::raw_one(-1, 0).with_guest_slots(&files, [fd]) {
            Ok(fds) => fds,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        DispatchOutcome::WaitOnPollFds {
            // Synthetic netlink sockets have no host fd to poll. A negative
            // pollfd is ignored by poll(2); enqueue_netlink_message publishes
            // queue state before waking the registered dispatcher-aware waiter,
            // which then re-samples this queue without a periodic timer.
            fds,
            timeout: None,
            on_timeout: 0,
            sig_mask: carrick_abi::WaitSigMask::NONE,
        }
    }

    /// Queue an asynchronous kernel-to-userspace netlink message on a synthetic
    /// AF_NETLINK fd. POSIX mqueue `SIGEV_THREAD` uses this path: glibc registers
    /// a NETLINK_ROUTE socket with `mq_notify`, then its helper thread blocks in
    /// `recvfrom` waiting for the kernel's 32-byte notification record.
    pub(super) fn enqueue_netlink_message(&self, fd: i32, bytes: &[u8]) -> Result<(), LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            return Err(LINUX_EBADF);
        };
        let Some(mut open) = open_file.description.write() else {
            return Err(LINUX_EBADF);
        };
        let OpenDescription::Netlink { recv_queue, .. } = &mut *open else {
            return Err(LINUX_EBADF);
        };
        recv_queue.extend(bytes);
        drop(open);
        self.notify_inmem_epoll();
        // A thread may be blocked in recvfrom() directly rather than through
        // an epoll instance. The queue mutation above is durable; wake the
        // dispatcher-aware private waiter so it re-samples the synthetic fd.
        crate::host_signal::wake_all_waiters();
        Ok(())
    }

    fn maybe_queue_icmp_echo_reply(
        &self,
        fd: i32,
        request: &[u8],
        requested: std::net::SocketAddr,
    ) -> bool {
        if self.socket_guest_protocol(fd) != Some(LINUX_IPPROTO_ICMP)
            || self.socket_guest_type(fd) != Some(LINUX_SOCK_DGRAM)
            || !requested.ip().is_loopback()
            || request.len() < 8
            || request[0] != LINUX_ICMP_ECHO_REQUEST
            || request[1] != 0
        {
            return false;
        }
        let Some(source) = socket_addr_to_linux_sockaddr(requested) else {
            return false;
        };
        let mut response = request.to_vec();
        response[0] = LINUX_ICMP_ECHO_REPLY;
        response[2..4].fill(0);
        let checksum = internet_checksum(&response);
        response[2..4].copy_from_slice(&checksum.to_be_bytes());
        self.queue_synthetic_datagram(fd, response, source)
    }

    fn maybe_queue_dns_response(
        &self,
        fd: i32,
        request: &[u8],
        requested: std::net::SocketAddr,
    ) -> bool {
        if !self.is_dns_gateway_addr(requested) {
            return false;
        }
        let Some(source) = socket_addr_to_linux_sockaddr(requested) else {
            return false;
        };
        let Some(response) = crate::network::dns::build_a_response(request, |name| {
            match self.network.resolve_dns_name(name) {
                Ok(service_addrs) if service_addrs.is_empty() => {
                    crate::network::dns::resolve_host_a(name)
                }
                Ok(service_addrs) => service_addrs,
                Err(_) => Vec::new(),
            }
        }) else {
            return false;
        };
        self.queue_synthetic_datagram(fd, response, source)
    }

    /// Park a datagram carrick produced in-process on `fd`'s synthetic receive
    /// queue and publish the readiness change.
    ///
    /// The host kernel never sees these bytes, so nothing on an epoll
    /// instance's kqueue fires for them: a waiter already parked in
    /// `epoll_wait` must be pulsed through `notify_inmem_epoll`, after which
    /// its re-sample (`epoll_ready_events`) reports the queue as EPOLLIN. A
    /// `recvfrom`/`recvmsg` issued after the send needs no wake -- it drains
    /// this queue before touching the host fd (`synthetic_datagram_drain`).
    /// Every in-process datagram producer (ICMP echo, the DNS gateway) goes
    /// through here so none can forget the broadcast again.
    fn queue_synthetic_datagram(&self, fd: i32, payload: Vec<u8>, source: Vec<u8>) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        {
            let Some(mut open) = open_file.description.write() else {
                return false;
            };
            let OpenDescription::HostSocket { synthetic_recv, .. } = &mut *open else {
                return false;
            };
            synthetic_recv.push_back((payload, source));
        }
        self.notify_inmem_epoll();
        true
    }

    fn synthetic_datagram_drain(&self, fd: i32) -> Option<(Vec<u8>, Vec<u8>)> {
        let open_file = self.open_file(fd)?;
        let mut open = open_file.description.write()?;
        let OpenDescription::HostSocket { synthetic_recv, .. } = &mut *open else {
            return None;
        };
        synthetic_recv.pop_front()
    }

    fn is_dns_gateway_addr(&self, addr: std::net::SocketAddr) -> bool {
        addr.port() == 53
            && matches!(addr.ip(), std::net::IpAddr::V4(ip) if ip == self.network.spec.gateway_v4)
    }

    fn connected_guest_peer_addr(&self, fd: i32) -> Option<std::net::SocketAddr> {
        let (host_fd, _family) = self.host_socket_lookup(fd).ok()?;
        self.network
            .provider
            .guest_visible_peer_addr(crate::network::SocketKey::for_host_fd(host_fd.get()))
            .ok()
            .flatten()
            .map(|addr| addr.0)
    }

    pub(in crate::dispatch) fn accept_common(
        &self,
        fd: Fd,
        addr: GuestPtr,
        addrlen: GuestPtr,
        memory: &mut impl CurrentMmMemory,
        accept4_flags: i32,
    ) -> DispatchOutcome {
        let Some(socket_flags) = decode_accept4_flags(accept4_flags) else {
            return DispatchOutcome::errno(LINUX_EINVAL);
        };
        let fd = fd.0;
        let addr_addr = addr.0;
        let addrlen_addr = addrlen.0;
        let (host_fd, family, type_, protocol) = {
            let Some(open_file) = self.open_file(fd) else {
                return DispatchOutcome::errno(LINUX_EBADF);
            };
            if carrick_abi::LinuxOpenFlags::from_bits_truncate(
                open_file.description.common().status_flags(),
            )
            .contains(carrick_abi::LinuxOpenFlags::PATH)
            {
                return DispatchOutcome::errno(LINUX_EBADF);
            }
            match open_file.description.read().as_deref() {
                Some(OpenDescription::HostSocket {
                    host_fd,
                    family,
                    type_,
                    protocol,
                    ..
                }) => (host_fd.raw(), *family, *type_, *protocol),
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
        let accepted_source = std::cell::RefCell::new(None::<Vec<u8>>);
        // SO_REUSEPORT: Darwin parks EVERY incoming connection on the last
        // socket that bound the addr:port, so this member's own host socket is
        // very likely empty even when the group has work. Try it first (the
        // common, ungrouped case costs nothing), then take from the sibling
        // holding it. `siblings` is empty unless this fd is in a group with
        // more than one member, so an ordinary listener never leaves the
        // original path.
        let accept_targets: Vec<i32> = std::iter::once(host_fd)
            .chain(reuseport::steal_targets(host_fd))
            .collect();
        let outcome = self.blocking_io(fd, host_fd, IoDir::Read, nonblocking, None, || {
            let mut last = Err(LINUX_EAGAIN);
            for target in accept_targets {
                let mut sa_storage = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
                let mut sa_len: libc::socklen_t = sa_storage.len() as libc::socklen_t;
                let new_host = unsafe {
                    libc::accept(
                        target,
                        sa_storage.as_mut_ptr() as *mut _,
                        &mut sa_len as *mut _,
                    )
                };
                match new_host.host_syscall_errno() {
                    Ok(new_host) => {
                        if addr_addr != 0 && addrlen_addr != 0 {
                            let used = (sa_len as usize).min(sa_storage.len());
                            accepted_source
                                .borrow_mut()
                                .replace(sa_storage[..used].to_vec());
                        }
                        return Ok(new_host as i64);
                    }
                    // Only an empty queue is worth trying the next member for.
                    // Any other errno is this accept's real answer.
                    Err(e) if e == LINUX_EAGAIN => last = Err(e),
                    Err(e) => return Err(e),
                }
            }
            last
        });
        let new_host = match outcome {
            DispatchOutcome::Returned { value } => value as i32,
            // WaitOnFds (block) or Errno — propagate; the runtime re-dispatches
            // accept on readiness.
            other => return other,
        };
        // This member took the group's turn; hand it to the next one so two
        // symmetric workers alternate strictly rather than racing.
        reuseport::advance_turn(host_fd);
        crate::event_ring::rec(crate::event_ring::ACCEPT, host_fd, new_host, 0);
        let accepted_source = accepted_source.into_inner();
        let accept_protocol = (family == libc::AF_INET && type_ == libc::SOCK_STREAM)
            .then_some(carrick_spec::PortProtocol::Tcp);
        let listener_guest_local = self
            .network
            .provider
            .guest_visible_local_addr(crate::network::SocketKey::for_host_fd(host_fd))
            .ok()
            .flatten();
        let accepted_host_source = host_socket_addr(new_host, family, true).or_else(|| {
            accepted_source
                .as_ref()
                .and_then(|host_source| host_sockaddr_to_socket_addr(host_source))
        });
        let guest_peer = accepted_host_source.and_then(|host_addr| {
            accept_protocol
                .zip(Some(host_addr))
                .and_then(|(protocol, host_addr)| {
                    self.network
                        .provider
                        .translate_recv_addr(HostSocketAddr(host_addr), protocol)
                        .ok()
                        .flatten()
                        .or_else(|| {
                            let listener_ip = listener_guest_local?.0.ip();
                            (self.network.spec.mode == carrick_spec::NetworkMode::Bridge
                                && host_addr.ip().is_loopback()
                                && matches!(listener_ip, std::net::IpAddr::V4(ip) if !ip.is_loopback()))
                            .then_some(GuestSocketAddr(std::net::SocketAddr::new(
                                listener_ip,
                                host_addr.port(),
                            )))
                        })
                })
        });
        if addr_addr != 0 && addrlen_addr != 0 {
            let linux_bytes = guest_peer
                .and_then(|addr| socket_addr_to_linux_sockaddr(addr.0))
                .or_else(|| accepted_host_source.and_then(socket_addr_to_linux_sockaddr))
                .or_else(|| {
                    accepted_source
                        .as_ref()
                        .map(|host_source| host_to_linux_sockaddr(host_source, family, false))
                })
                .or_else(|| {
                    (family == libc::AF_UNIX).then(|| (LINUX_AF_UNIX as u16).to_ne_bytes().to_vec())
                });
            let Some(linux_bytes) = linux_bytes else {
                crate::event_ring::rec(
                    crate::event_ring::ACCEPTERR,
                    host_fd,
                    new_host,
                    LINUX_EFAULT.get(),
                );
                unsafe { libc::close(new_host) };
                return DispatchOutcome::errno(LINUX_EFAULT);
            };
            if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                crate::event_ring::rec(
                    crate::event_ring::ACCEPTERR,
                    host_fd,
                    new_host,
                    LINUX_EFAULT.get(),
                );
                unsafe { libc::close(new_host) };
                return DispatchOutcome::errno(LINUX_EFAULT);
            }
        }
        let nonblock = socket_flags.contains(LinuxSocketTypeFlags::NONBLOCK);
        let cloexec = socket_flags.contains(LinuxSocketTypeFlags::CLOEXEC);
        // Keep the host socket non-blocking; Linux-visible blocking intent is
        // carried by status_flags and serviced by WaitOnFds.
        set_host_nonblocking(new_host);
        if let Err(errno) = widen_stream_socket_buffers(new_host, family, type_) {
            crate::event_ring::rec(crate::event_ring::ACCEPTERR, host_fd, new_host, errno.get());
            if family != LINUX_AF_UNIX {
                unsafe { libc::close(new_host) };
                return DispatchOutcome::errno(errno);
            }
            // Linux accept(2) does not fail because optional host-side buffer
            // tuning failed. AF_UNIX accepted sockets can reject the larger Darwin
            // buffer target intermittently; keep the connection and let normal
            // nonblocking backpressure handle any smaller host buffer.
        }
        let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostSocket {
                host_fd: HostFdRef::new(new_host),
                family,
                type_,
                protocol,
                base: OpenDescriptionBase::new(status_flags),
                mcast_memberships: Vec::new(),
                synthetic_recv: std::collections::VecDeque::new(),
            })),
            status_flags,
            fd_flags,
        );
        let linux_fd = match self.install_fd_at_or_above(3, open_file) {
            Ok(fd) => fd,
            Err(_) => {
                crate::event_ring::rec(
                    crate::event_ring::ACCEPTERR,
                    host_fd,
                    new_host,
                    linux_errno::EMFILE.get(),
                );
                return DispatchOutcome::errno(linux_errno::EMFILE);
            }
        };
        if let Some(protocol) = accept_protocol {
            let guest_local = self
                .network
                .provider
                .guest_visible_local_addr(crate::network::SocketKey::for_host_fd(host_fd))
                .ok()
                .flatten();
            let host_local = host_socket_addr(new_host, family, false);
            let _ = self.network.provider.record_socket_addresses(
                self.network.spec.namespace_id.as_ref(),
                crate::network::SocketKey::for_host_fd(new_host),
                guest_local,
                host_local.map(HostSocketAddr),
                guest_peer,
                protocol,
            );
        }
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
        memory: &impl CurrentMmMemory,
    ) -> DispatchOutcome {
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        let mut host_addr = match read_linux_sockaddr(memory, addr_addr, addrlen, family) {
            Ok(bytes) => bytes,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        rewrite_unspecified_connect_loopback(family, &mut host_addr);
        set_host_nonblocking(host_fd.get());
        let rc = unsafe {
            libc::connect(
                host_fd.get(),
                host_addr.as_ptr() as *const _,
                host_addr.len() as u32,
            )
        };
        if rc == 0 {
            return connect_success_or_pending_error(host_fd.get());
        }
        let e = HostSyscallError::last().linux_errno();
        // See `fn connect` for why EISCONN is split on connect_in_progress.
        if e == LINUX_EISCONN {
            if self.socket_connect_in_progress(fd) {
                self.set_socket_connect_in_progress(fd, false);
                return connect_success_or_pending_error(host_fd.get());
            }
            return DispatchOutcome::errno(LINUX_EISCONN);
        }
        if e == LINUX_EINPROGRESS || e == LINUX_EALREADY || e == LINUX_EAGAIN {
            self.set_socket_connect_in_progress(fd, true);
            let files = self.captured_file_table();
            let fds = match WaitFds::raw_one(host_fd.get(), libc::POLLOUT)
                .with_guest_slots(&files, [fd])
            {
                Ok(fds) => fds,
                Err(errno) => return DispatchOutcome::errno(errno),
            };
            return DispatchOutcome::WaitOnFds {
                fds,
                timeout: None,
                on_timeout: LINUX_EINPROGRESS.guest_retval(),
                sig_mask: carrick_abi::WaitSigMask::NONE,
            };
        }
        DispatchOutcome::errno(e)
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
        memory: &mut impl CurrentMmMemory,
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
                // Surface the REAL errno the single-message path carries (a bad
                // fd is EBADF, not the blanket EFAULT — sendmmsg02). The
                // `match outcome` below keeps the multi-message semantics: a
                // failure after >=1 success still returns the count.
                Err(DispatchError::Errno(errno)) => DispatchOutcome::Errno { errno },
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
    ///
    /// LIMITATION: the `timeout` argument is currently NOT honored
    /// (bound `_timeout`). The first message takes the socket's normal
    /// blocking path (so the wait is bounded only by SO_RCVTIMEO, else
    /// it blocks until a datagram arrives or a signal interrupts);
    /// after the first datagram `received > 0` forces MSG_DONTWAIT so
    /// the rest drain without waiting. A faithful implementation would
    /// convert `timeout` to an absolute deadline once and check it
    /// AFTER each received datagram (Linux only consults the timeout
    /// between datagrams — it does NOT bound the wait for the first
    /// one), NOT as an up-front poll.
    fn recvmmsg(
        &self,
        fd: Fd,
        msgvec: GuestPtr,
        vlen: u64,
        flags: u64,
        timeout: GuestPtr,
        memory: &mut impl CurrentMmMemory,
    ) -> DispatchOutcome {
        let fd = fd.0;
        let msgvec = msgvec.0;
        let vlen = vlen as u32;
        let flags = flags as i32;
        // Validate the optional timeout up front, exactly as pselect6/ppoll do: a
        // malformed struct timespec (negative tv_sec, or tv_nsec outside
        // [0, 1e9)) is rejected with EINVAL, a bad pointer with EFAULT, before any
        // receive. The full per-datagram deadline semantics are not yet emulated
        // (see the doc comment above); validating the argument is the
        // Linux-faithful, side-effect-free part we can do precisely.
        let timeout = timeout.0;
        if timeout != 0 {
            match read_kernel_struct::<LinuxTimespec>(&*memory, timeout) {
                Ok(ts) => {
                    // Copy out of the packed timespec before referencing (E0793).
                    let sec = ts.tv_sec;
                    let nsec = ts.tv_nsec;
                    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
                        return DispatchOutcome::errno(LINUX_EINVAL);
                    }
                }
                Err(_) => return DispatchOutcome::errno(LINUX_EFAULT),
            }
        }
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
                // Surface the REAL errno the single-message path carries (a bad
                // fd is EBADF, not the blanket EFAULT — recvmmsg01). The
                // `match outcome` below keeps the multi-message semantics: a
                // failure after >=1 success still returns the count.
                Err(DispatchError::Errno(errno)) => DispatchOutcome::Errno { errno },
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

#[cfg(test)]
mod icmp_ping_tests {
    use super::*;

    #[test]
    fn loopback_echo_reply_is_queued_with_valid_checksum() {
        let dispatcher = SyscallDispatcher::new();
        let fd = match dispatcher.host_socket_install(
            LINUX_AF_INET,
            LINUX_SOCK_DGRAM,
            LINUX_IPPROTO_ICMP,
        ) {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("ping socket creation failed: {other:?}"),
        };
        assert_eq!(
            dispatcher.socket_guest_protocol(fd),
            Some(LINUX_IPPROTO_ICMP)
        );

        let mut request = [0u8; 8];
        request[0] = LINUX_ICMP_ECHO_REQUEST;
        request[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        request[6..8].copy_from_slice(&1u16.to_be_bytes());
        let checksum = internet_checksum(&request);
        request[2..4].copy_from_slice(&checksum.to_be_bytes());
        let loopback = "127.0.0.1:0".parse().unwrap();
        assert!(dispatcher.maybe_queue_icmp_echo_reply(fd, &request, loopback));

        let (reply, source) = dispatcher.synthetic_datagram_drain(fd).unwrap();
        assert_eq!(reply[0], LINUX_ICMP_ECHO_REPLY);
        assert_eq!(reply[1], 0);
        assert_eq!(internet_checksum(&reply), 0);
        assert_eq!(source, socket_addr_to_linux_sockaddr(loopback).unwrap());
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
mod recvmmsg_tests {
    use super::*;
    use crate::dispatch::LinearMemory;

    #[test]
    fn recvmmsg_rejects_malformed_timeout_with_einval() {
        // Linux validates the optional `timeout` struct timespec up front and
        // rejects a tv_nsec outside [0, 1e9) (or a negative tv_sec) with EINVAL,
        // just like nanosleep/ppoll/pselect6. carrick previously ignored the
        // argument entirely, so a malformed timeout slipped through to a normal
        // (EBADF/EFAULT) receive. The fd is irrelevant: validation must precede
        // any fd/msgvec use.
        let dispatcher = SyscallDispatcher::new();
        let base = 0x1000u64;
        let mut memory = LinearMemory::new(base, vec![0u8; 0x1000]);
        // struct timespec { tv_sec: 0, tv_nsec: 2_000_000_000 } — tv_nsec >= 1e9.
        let mut ts = [0u8; 16];
        ts[8..16].copy_from_slice(&2_000_000_000i64.to_le_bytes());
        memory.write_bytes(base, &ts).unwrap();

        let out = dispatcher.recvmmsg(
            Fd(-1),
            GuestPtr(base + 0x100),
            1,
            0,
            GuestPtr(base),
            &mut memory,
        );
        assert!(
            matches!(out, DispatchOutcome::Errno { errno } if errno == LINUX_EINVAL),
            "malformed recvmmsg timeout must yield EINVAL, got {out:?}"
        );
    }

    #[test]
    fn recvmmsg_null_timeout_is_not_validated() {
        // A NULL timeout pointer is the common case and must NOT be treated as a
        // malformed timespec — it simply means "no timeout".
        let dispatcher = SyscallDispatcher::new();
        let base = 0x1000u64;
        let mut memory = LinearMemory::new(base, vec![0u8; 0x1000]);
        let out = dispatcher.recvmmsg(Fd(-1), GuestPtr(base), 1, 0, GuestPtr(0), &mut memory);
        // fd is invalid, so this is some receive error — the point is it is NOT
        // the EINVAL we reserve for a malformed timeout.
        assert!(
            !matches!(out, DispatchOutcome::Errno { errno } if errno == LINUX_EINVAL),
            "NULL timeout must not be rejected as malformed, got {out:?}"
        );
    }
}

#[cfg(test)]
mod mcast_membership_tests {
    use super::*;

    fn errno(outcome: DispatchOutcome) -> Option<LinuxErrno> {
        match outcome {
            DispatchOutcome::Errno { errno } => Some(errno),
            _ => None,
        }
    }

    #[test]
    fn mcast_leave_without_join_is_eaddrnotavail() {
        let mut memberships = Vec::new();
        let outcome = mcast_setsockopt_outcome(
            &mut memberships,
            crate::linux_abi::LINUX_SOL_IP,
            MCAST_LEAVE_GROUP,
            vec![1, 2, 3, 4],
        );

        assert_eq!(errno(outcome), Some(crate::linux_abi::LINUX_EADDRNOTAVAIL));
        assert!(memberships.is_empty());
    }

    #[test]
    fn mcast_membership_is_per_socket_state() {
        let mut listener_memberships = Vec::new();
        let join = mcast_setsockopt_outcome(
            &mut listener_memberships,
            crate::linux_abi::LINUX_SOL_IP,
            MCAST_JOIN_GROUP,
            vec![1, 2, 3, 4],
        );
        assert!(matches!(join, DispatchOutcome::Returned { value: 0 }));

        let mut accepted_memberships = Vec::new();
        let accepted_leave = mcast_setsockopt_outcome(
            &mut accepted_memberships,
            crate::linux_abi::LINUX_SOL_IP,
            MCAST_LEAVE_GROUP,
            vec![1, 2, 3, 4],
        );
        assert_eq!(
            errno(accepted_leave),
            Some(crate::linux_abi::LINUX_EADDRNOTAVAIL)
        );

        let listener_leave = mcast_setsockopt_outcome(
            &mut listener_memberships,
            crate::linux_abi::LINUX_SOL_IP,
            MCAST_LEAVE_GROUP,
            vec![1, 2, 3, 4],
        );
        assert!(matches!(
            listener_leave,
            DispatchOutcome::Returned { value: 0 }
        ));
        assert!(listener_memberships.is_empty());
    }
}

#[cfg(test)]
mod ipv6_addrform_tests {
    use super::*;
    use crate::dispatch::LinearMemory;

    #[test]
    fn ipv6_addrform_relabels_guest_family() {
        let mut dispatcher = SyscallDispatcher::new();
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);

        let fd = match dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    198,
                    SyscallArgs::from([
                        LINUX_AF_INET6 as u64,
                        LINUX_SOCK_STREAM as u64,
                        0,
                        0,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap()
        {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("socket(AF_INET6) failed: {other:?}"),
        };

        memory
            .write_bytes(0x4000, &LINUX_AF_INET.to_ne_bytes())
            .unwrap();
        assert_eq!(
            dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(
                        208,
                        SyscallArgs::from([
                            fd as u64,
                            LINUX_SOL_IPV6 as u64,
                            crate::linux_abi::LINUX_IPV6_ADDRFORM as u64,
                            0x4000,
                            4,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );

        let (old_host, family) = dispatcher.host_socket_lookup(fd).unwrap();
        assert_eq!(family, LINUX_AF_INET);

        memory.write_bytes(0x4010, &0u16.to_ne_bytes()).unwrap();
        assert_eq!(
            dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(203, SyscallArgs::from([fd as u64, 0x4010, 16, 0, 0, 0]),),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_ne!(
            dispatcher.host_socket_lookup(fd).unwrap().0.get(),
            old_host.get()
        );
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
                entries: Vec::new(),
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
                contents: Arc::new(parking_lot::RwLock::new(b"inmem content".to_vec())),
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
                    return Ok(DispatchOutcome::WaitOnPollFds {
                        fds,
                        timeout,
                        on_timeout: 0,
                        sig_mask,
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
                    return Ok(DispatchOutcome::WaitOnPollFds {
                        fds,
                        timeout,
                        on_timeout: 0,
                        sig_mask,
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
                return Ok(DispatchOutcome::WaitOnPollFds {
                    fds,
                    timeout,
                    on_timeout: 0,
                    sig_mask,
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
                    if let Some(target) = &target_description {
                        target.register_epoll_owner(&epoll_description, fd);
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
                        },
                    );
                    if host_fd.is_none() {
                        *synthetic_interest_count += 1;
                    }
                    // A waiter parked on this instance's ppoll snapshot does
                    // not watch the just-added fd; pop it so it rebuilds.
                    kqueue.wake_parked();
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
                    };
                    // Re-arm visible to a parked waiter: rebuild its park set.
                    kqueue.wake_parked();
                    crate::probes::epoll_ctl(epfd, operation, fd, event.events, event.data, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                LINUX_EPOLL_CTL_DEL => {
                    let Some(removed) =
                        remove_epoll_interest(interest, synthetic_interest_count, fd)
                    else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                    };
                    if let Some(target) = removed.target {
                        target.unregister_epoll_owner(&epoll_description, fd);
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
                        let ms = sec.saturating_mul(1000).saturating_add(usec / 1000);
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
                        let ms = sec.saturating_mul(1000).saturating_add(nsec / 1_000_000);
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
                // An eventfd with POLLOUT requested must go the poll_ready_events
                // path (always-writable); its host read_fd would never report
                // POLLOUT and the all-host libc::poll would block forever.
                host_map.push(if (w && this.fd_is_eventfd(fd_i32))
                    || (r && this.staged_splice_pipe_bytes(fd_i32) != 0)
                {
                    None
                } else {
                    this.host_fd_for_poll(fd_i32).map(HostFd::get)
                });
            }

            // revents per entry, filled by whichever path runs.
            let mut revents: Vec<i16> = vec![0; owners.len()];
            let all_host: Option<Vec<i32>> = host_map.iter().copied().collect();

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
                    on_timeout: 0,
                    sig_mask,
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
                    let files = this.captured_file_table();
                    let wait_fds = match WaitFds::raw(wait_fds)
                        .with_guest_slots(&files, owners.iter().map(|(fd, _)| *fd))
                    {
                        Ok(wait_fds) => wait_fds,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    return Ok(DispatchOutcome::WaitOnFdsSelect {
                        fds: wait_fds,
                        timeout,
                        sig_mask,
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
                        let ms = sec.saturating_mul(1000).saturating_add(nsec / 1_000_000);
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
            // every fd be host-backed (stdio bare, HostPipe, HostSocket).
            // An eventfd with POLLOUT requested goes the poll_ready_events path
            // (always-writable); its host read_fd never reports POLLOUT.
            let host_fds: Option<Vec<(i32, i16, bool)>> = fds
                .iter()
                .map(|p| {
                    if ((p.events & LINUX_POLLOUT) != 0 && this.fd_is_eventfd(p.fd))
                        || ((p.events & LINUX_POLLIN) != 0
                            && this.staged_splice_pipe_bytes(p.fd) != 0)
                    {
                        None
                    } else if let Some(open_file) = this.open_file(p.fd) {
                        let open = open_file.description.read()?;
                        match &*open {
                            OpenDescription::HostPipe { host_fd, .. }
                            | OpenDescription::HostFile { host_fd, .. } => {
                                Some((host_fd.raw(), p.events, false))
                            }
                            OpenDescription::HostSocket { host_fd, base, .. } => {
                                if base.pending_socket_error().is_some() {
                                    None
                                } else {
                                    Some((host_fd.raw(), p.events, false))
                                }
                            }
                            OpenDescription::PipeReader { pipe, .. } => {
                                pipe.read_poll_fd().map(|fd| (fd.raw(), libc::POLLIN, true))
                            }
                            OpenDescription::PipeWriter { pipe, .. } => {
                                pipe.write_poll_fd().map(|fd| (fd.raw(), libc::POLLIN, true))
                            }
                            OpenDescription::EventFd { state, .. } => {
                                state.read_fd.as_ref().map(|fd| (fd.raw(), libc::POLLIN, true))
                            }
                            OpenDescription::Pidfd { kqueue, .. } => {
                                Some((kqueue.poll_fd(), p.events, false))
                            }
                            OpenDescription::Inotify { state, .. } => {
                                Some((state.poll_fd(), p.events, false))
                            }
                            OpenDescription::Fanotify { group, .. } => match group.poll_fd() {
                                fd if fd >= 0 => Some((fd, p.events, false)),
                                _ => None,
                            },
                            _ => None,
                        }
                    } else if is_stdio_fd(p.fd) || p.fd < 0 {
                        Some((p.fd, p.events, false))
                    } else {
                        None
                    }
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
                    on_timeout: 0,
                    sig_mask,
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
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
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
            // A packet-crafting socket needs CAP_NET_RAW (socket(2),
            // capabilities(7)). Docker's default set grants it, so container
            // root keeps working; a guest that has setuid'd away from root
            // has lost every capability and must get EPERM — LTP socket01
            // pins exactly that row ("raw open as non-root").
            let base_type = type_ & !LinuxSocketTypeFlags::SUPPORTED_MASK;
            if base_type == LINUX_SOCK_RAW
                && !super::creds::has_effective_capability(
                    cx.kernel,
                    crate::namespace::process::CAP_NET_RAW,
                )
            {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
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
            // Reject Linux-invalid (family,type,protocol) tuples with the
            // canonical errno before macOS gets a chance to report a divergent
            // one; a valid INET pair still falls through to socketpair(), which
            // answers EOPNOTSUPP. (socketpair01)
            if let Some(errno) = canonical_socket_errno(family, base_type, protocol) {
                return Ok(DispatchOutcome::errno(errno));
            }
            // Unlike socket(2), an INET raw socketpair with the unspecified
            // protocol is rejected during protocol selection. Linux reports
            // EPROTONOSUPPORT before reaching the later unsupported-pair
            // check; Darwin skips that distinction and reports EOPNOTSUPP.
            if matches!(family, LINUX_AF_INET | LINUX_AF_INET6)
                && base_type == LINUX_SOCK_RAW
                && protocol == 0
            {
                return Ok(DispatchOutcome::errno(
                    crate::linux_abi::LINUX_EPROTONOSUPPORT,
                ));
            }
            let host_family = linux_to_host_af(family);
            let host_type = host_socktype_backing(family, base_type);

            let mut host_fds: [i32; 2] = [-1, -1];
            let rc =
                unsafe { libc::socketpair(host_family, host_type, protocol, host_fds.as_mut_ptr()) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(DispatchOutcome::errno(errno));
            }
            set_host_nonblocking(host_fds[0]);
            set_host_nonblocking(host_fds[1]);
            // Same Linux-sized backing every other stream-socket creation site
            // gets. macOS gives an AF_UNIX stream pair 8 KiB
            // (`net.local.stream.sendspace`) where Linux gives ~208 KiB, so a
            // guest that fills the pair before draining it — LTP `splice05`
            // pushes 64 KiB pipe→socket and only reads afterwards — blocked
            // forever on a peer buffer 1/26th the size it was written for.
            for host_fd in host_fds {
                if let Err(errno) = widen_stream_socket_buffers(host_fd, family, base_type) {
                    unsafe {
                        libc::close(host_fds[0]);
                        libc::close(host_fds[1]);
                    }
                    return Ok(DispatchOutcome::errno(errno));
                }
            }
            let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
            let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
            let first = OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::HostSocket {
                    host_fd: HostFdRef::new(host_fds[0]),
                    family,
                    type_: base_type,
                    protocol,
                    base: OpenDescriptionBase::new(status_flags),
                    mcast_memberships: Vec::new(),
                    synthetic_recv: std::collections::VecDeque::new(),
                })),
                status_flags,
                fd_flags,
            );
            let second = OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::HostSocket {
                    host_fd: HostFdRef::new(host_fds[1]),
                    family,
                    type_: base_type,
                    protocol,
                    base: OpenDescriptionBase::new(status_flags),
                    mcast_memberships: Vec::new(),
                    synthetic_recv: std::collections::VecDeque::new(),
                })),
                status_flags,
                fd_flags,
            );
            let (read_fd, write_fd) = match this.install_fd_pair_at_or_above(3, first, second) {
                Ok(pair) => pair,
                Err(_) => {
                    return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
                }
            };
            let pair = LinuxFdPair { read_fd, write_fd };
            if write_kernel_struct_raw(memory, sv_addr, &pair).is_err() {
                let removed = {
                    let files = this.captured_file_table();
                    let mut table = files.write_open_files();
                    [table.remove(&read_fd), table.remove(&write_fd)]
                };
                for open_file in removed.into_iter().flatten() {
                    this.close_open_file_and_free_pty(&open_file);
                }
                this.note_fd_closed(read_fd);
                this.note_fd_closed(write_fd);
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn bind(this, cx, fd: Fd, addr: GuestPtr, addrlen: u64) {

            let memory = &*cx.memory;
            let fd = fd.0;
            let addr_addr = addr.0;
            let addrlen = addrlen as u32;
            // AF_NETLINK bind: read the (optional) sockaddr_nl to pick up the
            // requested pid/groups, then assign a pid (the guest's own pid
            // when the caller passed 0, i.e. "let the kernel choose").
            if let Some(open_file) = this.open_file(fd)
                && let Some(mut open) = open_file.description.write()
                && let OpenDescription::Netlink {
                    pid: nl_pid,
                    groups: nl_groups,
                    ..
                } = &mut *open
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
            let (host_fd, family) = this.host_socket_lookup(fd)?;
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
                    return Ok(DispatchOutcome::errno(LINUX_ENAMETOOLONG));
                }
                let mut sa = vec![0u8; 2 + pb.len() + 1];
                set_host_sockaddr_header(&mut sa, libc::AF_UNIX);
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
                    libc::bind(
                        host_fd.get(),
                        sa.as_ptr() as *const libc::sockaddr,
                        sa.len() as u32,
                    )
                };
                return Ok(match rc.host_syscall_errno() {
                    Ok(_) => DispatchOutcome::Returned { value: 0 },
                    Err(errno) => DispatchOutcome::errno(errno),
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
                    return Ok(DispatchOutcome::errno(linux_errno::EADDRINUSE));
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
                let resolved = this.resolve_at_path(LINUX_AT_FDCWD, gp)?;
                let parent = std::path::Path::new(&resolved)
                    .parent()
                    .and_then(|p| p.to_str())
                    .filter(|p| !p.is_empty())
                    .unwrap_or("/");
                match this.layered_metadata(parent) {
                    Ok(md) if md.kind == RootFsEntryKind::Directory => {}
                    Ok(_) => return Ok(DispatchOutcome::errno(LINUX_ENOTDIR)),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
                if this.layered_lstat(&resolved).is_ok() {
                    return Ok(DispatchOutcome::errno(linux_errno::EADDRINUSE));
                }
                Some(resolved)
            } else {
                None
            };
            let mut host_addr = read_linux_sockaddr(memory, addr_addr, addrlen, family)?;
            let mut rewritten_bind: Option<(std::net::SocketAddr, PortProtocol)> = None;
            if family == LINUX_AF_INET
                && let Some(protocol) = this.socket_port_protocol(fd)
                && let Some(requested) = host_sockaddr_to_socket_addr(&host_addr)
            {
                match this.network.provider.materialize_bind(
                    this.network.spec.namespace_id.as_ref(),
                    GuestSocketAddr(requested),
                    protocol,
                ) {
                    Ok(BindTarget::Host(host)) => {
                        if let Some(mapped) = socket_addr_to_host_sockaddr(host.0) {
                            host_addr = mapped;
                            rewritten_bind = Some((requested, protocol));
                        }
                    }
                    Ok(BindTarget::Unchanged) => {}
                    Err(_) => return Ok(DispatchOutcome::errno(carrick_abi::LINUX_EADDRNOTAVAIL)),
                }
            }
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
            // An error-queue socket needs host SO_REUSEPORT so its shadow can
            // share this addr:port (see `recverr`). Linux would refuse a SECOND
            // error-queue bind here, and Darwin no longer will once the flag is
            // set, so Carrick enforces that itself.
            if recverr::is_enabled(host_fd.get()) {
                if !recverr::reserve_bind(host_fd.get(), &host_addr) {
                    return Ok(DispatchOutcome::errno(linux_errno::EADDRINUSE));
                }
                let one: i32 = 1;
                unsafe {
                    libc::setsockopt(
                        host_fd.get(),
                        libc::SOL_SOCKET,
                        libc::SO_REUSEPORT,
                        &one as *const i32 as *const libc::c_void,
                        std::mem::size_of::<i32>() as u32,
                    );
                }
            }
            let rc = unsafe {
                libc::bind(
                    host_fd.get(),
                    host_addr.as_ptr() as *const _,
                    host_addr.len() as u32,
                )
            };
            let mut bind_result = rc.host_syscall_errno();
            if let Err(errno) = bind_result
                && errno == linux_errno::EADDRINUSE
                && this.network.spec.mode == carrick_spec::NetworkMode::Bridge
                && family == LINUX_AF_INET
                && let Some(requested) = host_sockaddr_to_socket_addr(&host_addr)
                && matches!(
                    requested.ip(),
                    std::net::IpAddr::V4(ip)
                        if ip == std::net::Ipv4Addr::UNSPECIFIED || ip == this.network.spec.ipv4
                )
                && let Some(protocol) = this.socket_port_protocol(fd)
                && let Some(mapped) =
                    socket_addr_to_host_sockaddr(std::net::SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                        0,
                    ))
            {
                host_addr = mapped;
                let retry = unsafe {
                    libc::bind(
                        host_fd.get(),
                        host_addr.as_ptr() as *const _,
                        host_addr.len() as u32,
                    )
                };
                bind_result = retry.host_syscall_errno();
                if bind_result.is_ok() {
                    rewritten_bind = Some((requested, protocol));
                }
            }
            if let Err(errno) = bind_result {
                return Ok(DispatchOutcome::errno(errno));
            }
            // An error-queue socket's shadow must exist before `epoll_ctl(ADD)`
            // registers it (see `recverr::create_shadow_at_bind`).
            if recverr::is_enabled(host_fd.get())
                && let Some(local) = host_sockaddr_bytes(host_fd.get())
            {
                recverr::create_shadow_at_bind(host_fd.get(), &local);
            }
            // SO_REUSEPORT: join this host addr:port's group. Darwin lets every
            // member bind but then delivers ALL traffic to the last binder, so
            // Carrick has to distribute — see `reuseport`. Keyed on the address
            // the HOST actually bound (read back, not the requested one, which
            // may carry port 0 or have been rewritten above).
            if this.socket_reuseport(fd)
                && let Some(socket_type) = this.socket_guest_type(fd)
                && let Some(bound) = host_sockaddr_bytes(host_fd.get())
            {
                reuseport::join(reuseport::GroupKey::new(socket_type, bound), host_fd.get());
            }
            if let Some((guest_local, protocol)) = rewritten_bind
                && let Some(host_local) = host_socket_addr(host_fd.get(), family, false)
            {
                let guest_local = if guest_local.port() == 0 {
                    std::net::SocketAddr::new(guest_local.ip(), host_local.port())
                } else {
                    guest_local
                };
                let _ = this.network.provider.record_socket_addresses(
                    this.network.spec.namespace_id.as_ref(),
                    crate::network::SocketKey::for_host_fd(host_fd.get()),
                    Some(GuestSocketAddr(guest_local)),
                    Some(HostSocketAddr(host_local)),
                    None,
                    protocol,
                );
            }
            if family == libc::AF_UNIX && host_addr.len() > 2 {
                let end = host_addr[2..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|i| 2 + i)
                    .unwrap_or(host_addr.len());
                crate::event_ring::rec(
                    crate::event_ring::BIND,
                    fd,
                    host_fd.get(),
                    crate::event_ring::path_hash(&host_addr[2..end]),
                );
                // Stamp the guest sun_path onto the just-created host node so a
                // DIFFERENT carrick process (whose per-process registry lacks
                // this bind) can reverse-translate it in getsockname/getpeername
                // instead of leaking the raw <hash>.sock host path.
                persist_unix_path_xattr(&host_addr[2..end]);
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
                } else if this
                    .fs
                    .rootfs_vfs
                    .overlay
                    .create_socket(&resolved, mode)
                    .is_ok()
                {
                    // Stamp the creator, exactly as `mknod(S_IFSOCK)` and
                    // `openat(O_CREAT)` do. Without this the node has no owner
                    // xattr, `get_owner` falls back to root, and a non-root
                    // guest cannot `chmod` the socket it just created — libuv's
                    // `pipe_set_chmod` saw EPERM and skipped, where Linux (whose
                    // socket inode is owned by the uid that bound it) runs.
                    this.stamp_new_node_owner(&resolved, mode);
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn listen(this, cx, fd: Fd, backlog: u64) {

            let fd: Fd = fd;
            let backlog = backlog as i32;
            let (host_fd, _family) = this.host_socket_lookup(fd.0)?;
            if let Some(protocol) = this.socket_port_protocol(fd.0)
                && let Some(host_local) = host_socket_addr(host_fd.get(), libc::AF_INET, false)
                && let Err(errno) = this.network.provider.prepare_listen(
                    this.network.spec.namespace_id.as_ref(),
                    this
                        .network
                        .provider
                        .guest_visible_local_addr(crate::network::SocketKey::for_host_fd(
                            host_fd.get(),
                        ))
                        .ok()
                        .flatten(),
                    Some(HostSocketAddr(host_local)),
                    protocol,
                    this.socket_reuseport(fd.0),
                )
            {
                return Ok(DispatchOutcome::errno(errno));
            }
            let rc = unsafe { libc::listen(host_fd.get(), backlog) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(DispatchOutcome::errno(errno));
            }
            if let Some(open_file) = this.open_file(fd.0)
                && let Some(mut open) = open_file.description.write()
                && let OpenDescription::HostSocket { base, .. } =
                    &mut *open
            {
                base.set_listening(true);
            }
            crate::event_ring::rec(crate::event_ring::LISTEN, host_fd.get(), 0, 0);
            // A listen socket exists only to accept(2); make the HOST socket
            // non-blocking so accept never blocks under the dispatcher lock — the
            // guest's blocking intent is emulated by blocking_io's WaitOnFds
            // hand-off (the one idiomatic, targeted non-blocking exception; data
            // sockets keep their native mode + per-call MSG_DONTWAIT).
            set_host_nonblocking(host_fd.get());
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
            let fd = fd.0;
            let addr_addr = addr.0;
            let addrlen = addrlen as u32;
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            let mut host_addr = read_linux_sockaddr(memory, addr_addr, addrlen, family)?;
            rewrite_unspecified_connect_loopback(family, &mut host_addr);
            // BSD requires privilege for a real INET raw socket. Such sockets
            // use an unprivileged datagram fd as their host carrier, so a raw
            // connect cannot be handed to the carrier (a raw sockaddr has no
            // transport port, and Darwin rejects UDP connect-to-port-zero).
            // Linux raw connect only establishes the default peer identity;
            // record that identity in the network namespace and leave payload
            // operations on the carrier. This is sufficient for the ordinary
            // bind/options/poll/name surface without claiming privileged raw
            // packet injection.
            if cfg!(carrick_bsd)
                && matches!(family, LINUX_AF_INET | LINUX_AF_INET6)
                && this.socket_guest_type(fd) == Some(LINUX_SOCK_RAW)
            {
                let Some(requested) = host_sockaddr_to_socket_addr(&host_addr) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                this.record_rewritten_connect_addresses(
                    family,
                    host_fd.get(),
                    requested,
                    HostSocketAddr(requested),
                    PortProtocol::Udp,
                );
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let mut rewritten_connect: Option<(
                std::net::SocketAddr,
                HostSocketAddr,
                PortProtocol,
            )> = None;
            let mut synthetic_error_after_send = false;
            if family == LINUX_AF_INET
                && let Some(protocol) = this.socket_port_protocol(fd)
                && let Some(requested) = host_sockaddr_to_socket_addr(&host_addr)
            {
                if protocol == PortProtocol::Udp
                    && this.socket_guest_type(fd) == Some(LINUX_SOCK_DGRAM)
                    && this.is_dns_gateway_addr(requested)
                {
                    let synthetic_host_peer = std::net::SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                        requested.port(),
                    );
                    if let Some(mapped) = socket_addr_to_host_sockaddr(synthetic_host_peer) {
                        host_addr = mapped;
                        rewritten_connect =
                            Some((requested, HostSocketAddr(synthetic_host_peer), protocol));
                    }
                } else {
                match this.network.provider.resolve_connect(
                    this.network.spec.namespace_id.as_ref(),
                    GuestSocketAddr(requested),
                    protocol,
                ) {
                    Ok(ConnectTarget::Host(host)) => {
                        if let Some(mapped) = socket_addr_to_host_sockaddr(host.0) {
                            host_addr = mapped;
                            rewritten_connect = Some((requested, host, protocol));
                        }
                    }
                    Ok(ConnectTarget::Intercept(mock)) => {
                        let Some(open_file) = this.open_file(fd) else {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        };
                        let status_flags = open_file.description.common().status_flags();
                        let old_host_fd = {
                            let open = open_file.description.read();
                            if let Some(OpenDescription::HostSocket { host_fd, .. }) = open.as_deref() {
                                Some(host_fd.raw())
                            } else {
                                None
                            }
                        };
                        if let Some(hfd) = old_host_fd {
                            this.network.provider.forget_socket_addresses(crate::network::SocketKey::for_host_fd(hfd));
                        }
                        let local_port = 49152 + (fd as u16 % 16384);
                        let local_addr = match requested {
                            std::net::SocketAddr::V4(_) => std::net::SocketAddr::new(
                                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                                local_port,
                            ),
                            std::net::SocketAddr::V6(_) => std::net::SocketAddr::new(
                                std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                                local_port,
                            ),
                        };
                        let pure_sock = crate::dispatch::net::unix_pure::PureSocketInner::new_mock(
                            family,
                            LINUX_SOCK_STREAM,
                            LINUX_IPPROTO_TCP,
                            Some(local_addr),
                            Some(requested),
                            mock,
                            None,
                        );
                        if let Some(initial_bytes) = pure_sock.mock_on_connect() {
                            pure_sock.queue_mock_response(&initial_bytes);
                            this.notify_inmem_epoll();
                        }
                        if let Some(mut open) = open_file.description.write() {
                            *open = OpenDescription::InMemorySocket {
                                base: OpenDescriptionBase::new(status_flags),
                                socket: pure_sock,
                            };
                        }
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    Ok(ConnectTarget::Unchanged) => {
                        if std::env::var_os("CARRICK_NET_DEBUG").is_some() {
                            eprintln!("NETDBG connect resolve UNCHANGED fd={fd} req={requested:?} proto={protocol:?}");
                        }
                    }
                    Ok(ConnectTarget::Denied(errno)) => {
                        if std::env::var_os("CARRICK_NET_DEBUG").is_some() {
                            eprintln!("NETDBG connect resolve DENIED fd={fd} errno={} proto={protocol:?} gt={:?}", errno.get(), this.socket_guest_type(fd));
                        }
                        if errno == carrick_abi::LINUX_ECONNREFUSED
                            && protocol == PortProtocol::Tcp
                            && this.socket_guest_type(fd) == Some(LINUX_SOCK_STREAM)
                            && this.io_is_nonblocking(fd, 0)
                        {
                            this.set_socket_pending_error(fd, carrick_abi::LINUX_ECONNREFUSED);
                            return Ok(DispatchOutcome::errno(LINUX_EINPROGRESS));
                        }
                        if errno == carrick_abi::LINUX_ECONNREFUSED
                            && protocol == PortProtocol::Udp
                            && this.socket_guest_type(fd) == Some(LINUX_SOCK_DGRAM)
                        {
                            let synthetic_host_peer = std::net::SocketAddr::new(
                                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                                requested.port(),
                            );
                            if let Some(mapped) = socket_addr_to_host_sockaddr(synthetic_host_peer)
                            {
                                host_addr = mapped;
                                this.set_socket_error_after_send(
                                    fd,
                                    carrick_abi::LINUX_ECONNREFUSED,
                                );
                                synthetic_error_after_send = true;
                                rewritten_connect = Some((
                                    requested,
                                    HostSocketAddr(synthetic_host_peer),
                                    protocol,
                                ));
                            } else {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                        } else {
                            return Ok(DispatchOutcome::errno(errno));
                        }
                    }
                    Err(_) => return Ok(DispatchOutcome::errno(carrick_abi::LINUX_ECONNREFUSED)),
                }
                }
            }
            // connect(AF_UNSPEC) is the UDP "disconnect" (dissolve the peer
            // association); Linux returns 0. macOS disconnects too but may then
            // report EAFNOSUPPORT/EINVAL — treat those as success below.
            let is_unspec_disconnect = addrlen >= 2
                && memory
                    .read_bytes(addr_addr, 2)
                    .ok()
                    .map(|b| u16::from_ne_bytes([b[0], b[1]]) as i32 == LINUX_AF_UNSPEC)
                    .unwrap_or(false);
            if is_unspec_disconnect && this.socket_guest_type(fd) == Some(LINUX_SOCK_STREAM) {
                match this.reset_host_stream_socket_for_disconnect(fd) {
                    Ok(()) => return Ok(DispatchOutcome::Returned { value: 0 }),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            }
            if family == libc::AF_UNIX
                && let Some(gp) = guest_unix_pathname(memory, addr_addr, addrlen)
            {
                let resolved = this.resolve_at_path(LINUX_AT_FDCWD, &gp)?;
                let parent = std::path::Path::new(&resolved)
                    .parent()
                    .and_then(|p| p.to_str())
                    .filter(|p| !p.is_empty())
                    .unwrap_or("/");
                match this.layered_metadata(parent) {
                    Ok(md) if md.kind == RootFsEntryKind::Directory => {}
                    Ok(_) => return Ok(DispatchOutcome::errno(LINUX_ENOTDIR)),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
                match this.layered_metadata(&resolved) {
                    Ok(md) if md.kind == RootFsEntryKind::Socket => {}
                    Ok(_) => return Ok(DispatchOutcome::errno(linux_errno::ECONNREFUSED)),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            }
            // connect(2) has no per-call non-blocking flag, so put the host socket
            // non-blocking — it then returns EINPROGRESS instead of blocking under
            // the dispatcher lock. recv/send use MSG_DONTWAIT + the guest's intended
            // mode (status_flags), so the host fd's real mode is immaterial.
            let nonblocking = this.io_is_nonblocking(fd, 0);
            set_host_nonblocking(host_fd.get());
            if let Some((guest_peer, host_peer, protocol)) = rewritten_connect {
                if let Err(errno) = this.prepare_rewritten_connect_source(
                    family,
                    host_fd.get(),
                    guest_peer,
                    host_peer,
                    protocol,
                ) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                rewritten_connect = Some((guest_peer, host_peer, protocol));
            }
            let rc = unsafe {
                libc::connect(
                    host_fd.get(),
                    host_addr.as_ptr() as *const _,
                    host_addr.len() as u32,
                )
            };
            if family == libc::AF_UNIX && host_addr.len() > 2 {
                let end = host_addr[2..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|i| 2 + i)
                    .unwrap_or(host_addr.len());
                crate::event_ring::rec(
                    crate::event_ring::CONNECT,
                    host_fd.get(),
                    rc,
                    crate::event_ring::path_hash(&host_addr[2..end]),
                );
            }
            if rc == 0 {
                if !synthetic_error_after_send {
                    this.clear_socket_error_after_send(fd);
                }
                // A non-blocking host connect reporting success does not prove the
                // connection completed — consult SO_ERROR (see
                // connect_success_or_pending_error).
                let outcome = connect_success_or_pending_error(host_fd.get());
                if matches!(outcome, DispatchOutcome::Returned { value: 0 })
                    && let Some((guest_peer, host_peer, protocol)) = rewritten_connect
                {
                    this.record_rewritten_connect_addresses(
                        family,
                        host_fd.get(),
                        guest_peer,
                        host_peer,
                        protocol,
                    );
                }
                return Ok(outcome);
            }
            let e = HostSyscallError::last().linux_errno();
            // EISCONN: macOS reports it BOTH when an async connect we deferred
            // completes (the POLLOUT re-dispatch) AND when the guest calls
            // connect() on an already-established socket. Only the former should
            // be folded to success: distinguish via the per-description
            // connect_in_progress flag (set when we first deferred this connect).
            //   - in-progress set ⇒ async completion: consult SO_ERROR so a FAILED
            //     async connect (macOS still says EISCONN) surfaces ECONNREFUSED
            //     etc. at connect time rather than deferring it to the first recv
            //     (which breaks blocking connect + the IPv6->IPv4 address fallback).
            //   - in-progress clear ⇒ a real re-connect of an established socket:
            //     surface EISCONN to the guest (Linux connect01 "already connected").
            if e == LINUX_EISCONN {
                if this.socket_connect_in_progress(fd) {
                    this.set_socket_connect_in_progress(fd, false);
                    let outcome = connect_success_or_pending_error(host_fd.get());
                    if matches!(outcome, DispatchOutcome::Returned { value: 0 })
                        && let Some((guest_peer, host_peer, protocol)) = rewritten_connect
                    {
                        this.record_rewritten_connect_addresses(
                            family,
                            host_fd.get(),
                            guest_peer,
                            host_peer,
                            protocol,
                        );
                    }
                    return Ok(outcome);
                }
                return Ok(DispatchOutcome::errno(LINUX_EISCONN));
            }
            if e == LINUX_EINPROGRESS || e == LINUX_EALREADY || e == LINUX_EAGAIN {
                if let Some((guest_peer, host_peer, protocol)) = rewritten_connect {
                    this.record_rewritten_connect_addresses(
                        family,
                        host_fd.get(),
                        guest_peer,
                        host_peer,
                        protocol,
                    );
                }
                if nonblocking {
                    // Non-blocking guest: hand EINPROGRESS/EALREADY straight back.
                    return Ok(DispatchOutcome::errno(e));
                }
                // Blocking guest: wait (lock released) for the socket to become
                // writable, then re-dispatch — connect then returns EISCONN or the
                // real connect error. Mark the connect as deferred so the EISCONN
                // we expect on re-dispatch is recognised as async-completion above.
                this.set_socket_connect_in_progress(fd, true);
                let files = this.captured_file_table();
                let fds = match WaitFds::raw_one(host_fd.get(), libc::POLLOUT)
                    .with_guest_slots(&files, [fd])
                {
                    Ok(fds) => fds,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                return Ok(DispatchOutcome::WaitOnFds {
                    fds,
                    timeout: None,
                    on_timeout: LINUX_EINPROGRESS.guest_retval(),
                    sig_mask: carrick_abi::WaitSigMask::NONE,
                });
            }
            if is_unspec_disconnect && (e == LINUX_EAFNOSUPPORT || e == LINUX_EINVAL) {
                // macOS already disassociated the UDP socket; Linux returns 0
                // for the AF_UNSPEC disconnect, so report success.
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            Ok(DispatchOutcome::errno(e))

        }

        fn getsockname(this, cx, fd: Fd, addr: GuestPtr, addrlen: GuestPtr) {

            let memory = &mut *cx.memory;
            let fd = fd.0;
            let addr_addr = addr.0;
            let addrlen_addr = addrlen.0;
            // AF_NETLINK getsockname: hand back a sockaddr_nl carrying the
            // bound pid/groups (or pid=0 if the socket was never bound).
            if let Some(open_file) = this.open_file(fd)
                && let Some(OpenDescription::Netlink { pid, groups, .. }) = open_file.description.read().as_deref()
            {
                let nl = sockaddr_nl_bytes(*pid, *groups);
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &nl).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if let Some(open_file) = this.open_file(fd)
                && let Some(open) = open_file.description.read()
                && let OpenDescription::InMemorySocket { socket, .. } = &*open
            {
                if addr_addr == 0 || addrlen_addr == 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                if let Ok(b) = memory.read_bytes(addrlen_addr, 4)
                    && i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0
                {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let local = socket.local_addr();
                let linux_bytes = if let Some(local) = local {
                    socket_addr_to_linux_sockaddr(local).unwrap_or_default()
                } else {
                    vec![0u8; 16]
                };
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            // getsockname needs both output pointers; a NULL addr or addrlen →
            // EFAULT (getsockname01), checked after the fd validation so a
            // bad/non-socket fd still surfaces EBADF/ENOTSOCK first.
            if addr_addr == 0 || addrlen_addr == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            // A negative input *addrlen → EINVAL (getsockname01); the kernel
            // reads addrlen first and rejects len < 0 before copying out. A bad
            // (unreadable) addrlen pointer surfaces EFAULT via the write below.
            if let Ok(b) = memory.read_bytes(addrlen_addr, 4)
                && i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if let Ok(Some(guest_local)) = this
                .network
                .provider
                .guest_visible_local_addr(crate::network::SocketKey::for_host_fd(host_fd.get()))
                && let Some(linux_bytes) = socket_addr_to_linux_sockaddr(guest_local.0)
            {
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
            let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
            let rc =
                unsafe { libc::getsockname(host_fd.get(), sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(DispatchOutcome::errno(errno));
            }
            let used = (sa_len as usize).min(sa.len());
            let linux_bytes = host_to_linux_sockaddr(&sa[..used], family, false);
            if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn getpeername(this, cx, fd: Fd, addr: GuestPtr, addrlen: GuestPtr) {

            let memory = &mut *cx.memory;
            let fd = fd.0;
            let addr_addr = addr.0;
            let addrlen_addr = addrlen.0;
            if let Some(open_file) = this.open_file(fd)
                && let Some(open) = open_file.description.read()
                && let OpenDescription::InMemorySocket { socket, .. } = &*open
            {
                if addr_addr == 0 || addrlen_addr == 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                if let Ok(b) = memory.read_bytes(addrlen_addr, 4)
                    && i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0
                {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let peer = socket.peer_addr();
                let Some(peer) = peer else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOTCONN));
                };
                let Some(linux_bytes) = socket_addr_to_linux_sockaddr(peer) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            if cfg!(carrick_bsd)
                && this.socket_guest_type(fd) == Some(LINUX_SOCK_RAW)
                && let Ok(Some(guest_peer)) = this
                    .network
                    .provider
                    .guest_visible_peer_addr(crate::network::SocketKey::for_host_fd(host_fd.get()))
            {
                if addr_addr == 0 || addrlen_addr == 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                if let Ok(b) = memory.read_bytes(addrlen_addr, 4)
                    && i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0
                {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let Some(linux_bytes) = socket_addr_to_linux_sockaddr(guest_peer.0) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
            let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
            let rc =
                unsafe { libc::getpeername(host_fd.get(), sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(DispatchOutcome::errno(errno));
            }
            // Connected (the host call succeeded): a NULL addr/addrlen → EFAULT
            // and a negative input *addrlen → EINVAL (symmetric with
            // getsockname; checked after the host call so an unconnected
            // socket's ENOTCONN still wins). getpeername01.
            if addr_addr == 0 || addrlen_addr == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            if let Ok(b) = memory.read_bytes(addrlen_addr, 4)
                && i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if let Ok(Some(guest_peer)) = this
                .network
                .provider
                .guest_visible_peer_addr(crate::network::SocketKey::for_host_fd(host_fd.get()))
                && let Some(linux_bytes) = socket_addr_to_linux_sockaddr(guest_peer.0)
            {
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let used = (sa_len as usize).min(sa.len());
            let linux_bytes = host_to_linux_sockaddr(&sa[..used], family, false);
            if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn sendto(this, cx, fd: Fd, buf: GuestPtr, len: u64, flags: u64, dest_addr: GuestPtr, addrlen: u64) {

            if std::env::var_os("CARRICK_NET_DEBUG").is_some() {
                let kind = this
                    .open_file(fd.0)
                    .and_then(|of| of.description.read().map(|g| g.reexec_kind_name().to_string()))
                    .unwrap_or_else(|| "<none>".to_string());
                eprintln!(
                    "NETDBG sendto enter pid={} fd={} len={} dest_addr={:#x} kind={kind}",
                    std::process::id(), fd.0, len, dest_addr.0
                );
            }
            let memory = &*cx.memory;
            let fd = fd.0;
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
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                };
                return Ok(this.netlink_send(fd, &bytes));
            }
            if let Some(open_file) = this.open_file(fd)
                && let Some(open) = open_file.description.read()
                && let OpenDescription::InMemorySocket { socket, .. } = &*open
            {
                let socket = Arc::clone(socket);
                drop(open);
                    let bytes = match memory.read_bytes(buf_addr, len) {
                        Ok(b) => b,
                        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                    };
                    match socket.send_stream(&bytes, Vec::new()) {
                        Ok(written) => {
                            this.notify_inmem_epoll();
                            return Ok(DispatchOutcome::Returned {
                                value: written as i64,
                            });
                        }
                        Err(LINUX_EPIPE) => {
                            let outcome = DispatchOutcome::errno(LINUX_EPIPE);
                            if (flags & LINUX_MSG_NOSIGNAL) == 0 {
                                return Ok(this.raise_sigpipe_on_epipe(cx, outcome));
                            } else {
                                return Ok(outcome);
                            }
                        }
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    }
                }
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            // Zero-copy when the whole buffer is one contiguous mapped region
            // (send straight out of guest memory); otherwise snapshot it. The
            // pointer is resolved per dispatch — blocking_io's op is FnOnce and an
            // EAGAIN re-dispatches the whole handler, so it never outlives a
            // lock-releasing wait.
            let zc_ptr = memory.host_ptr_for_read(buf_addr, len);
            let send_copy: Option<Vec<u8>> = if zc_ptr.is_some() {
                None
            } else {
                match memory.read_bytes(buf_addr, len) {
                    Ok(b) => Some(b),
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            };
            let data_ptr: *const u8 = match (zc_ptr, &send_copy) {
                (Some(p), _) => p,
                (None, Some(b)) => b.as_ptr(),
                (None, None) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
            };
            // Read the destination sockaddr (if any) from guest memory up front,
            // then send with MSG_DONTWAIT through blocking_io: a full socket buffer
            // (EAGAIN) on a blocking fd waits for POLLOUT losslessly.
            let mut host_addr = if dest_addr == 0 {
                None
            } else {
                // Linux's move_addr_to_kernel rejects a negative addrlen with
                // EINVAL before touching the buffer (sendto01 "invalid to buffer
                // length", tolen = -1). read_linux_sockaddr reads addrlen as u32
                // and would instead fault on the huge length (EFAULT) — guard here.
                if (dest_len as i32) < 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                match read_linux_sockaddr(memory, dest_addr, dest_len, family) {
                    Ok(b) => Some(b),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            };
            if family == LINUX_AF_INET
                && let Some(protocol) = this.socket_port_protocol(fd)
                && let Some(requested) = host_addr
                    .as_deref()
                    .and_then(host_sockaddr_to_socket_addr)
                    .or_else(|| this.connected_guest_peer_addr(fd))
            {
                if let Ok(bytes) = memory.read_bytes(buf_addr, len)
                    && this.maybe_queue_icmp_echo_reply(fd, &bytes, requested)
                {
                    return Ok(DispatchOutcome::Returned { value: len as i64 });
                }
                if protocol == PortProtocol::Udp
                    && this.socket_guest_type(fd) == Some(LINUX_SOCK_DGRAM)
                    && let Ok(bytes) = memory.read_bytes(buf_addr, len)
                    && this.maybe_queue_dns_response(fd, &bytes, requested)
                {
                    return Ok(DispatchOutcome::Returned { value: len as i64 });
                }
                match this.network.provider.resolve_connect(
                    this.network.spec.namespace_id.as_ref(),
                    GuestSocketAddr(requested),
                    protocol,
                ) {
                    Ok(ConnectTarget::Host(host)) => {
                        if let Some(mapped) = socket_addr_to_host_sockaddr(host.0) {
                            host_addr = Some(mapped);
                        }
                    }
                    Ok(ConnectTarget::Unchanged) => {}
                    Ok(ConnectTarget::Denied(errno))
                        if errno == carrick_abi::LINUX_ECONNREFUSED
                            && protocol == PortProtocol::Udp
                            && this.socket_guest_type(fd) == Some(LINUX_SOCK_DGRAM) =>
                    {
                        // The datagram is dropped (nothing listens on the
                        // bridge-local target), but Linux still reports the
                        // send as successful. For a CONNECTED socket the
                        // asynchronous ICMP unreachable must then surface as
                        // POLLERR + recv ECONNREFUSED — arm the pending error
                        // exactly like a delivered ICMP would (the connect
                        // path already staged error_after_send).
                        if dest_addr == 0 {
                            this.queue_socket_error_after_send(fd);
                        }
                        return Ok(DispatchOutcome::Returned { value: len as i64 });
                    }
                    Ok(ConnectTarget::Intercept(_)) => return Ok(DispatchOutcome::errno(carrick_abi::LINUX_ECONNREFUSED)),
                    Ok(ConnectTarget::Denied(errno)) => return Ok(DispatchOutcome::errno(errno)),
                    Err(_) => return Ok(DispatchOutcome::errno(carrick_abi::LINUX_ECONNREFUSED)),
                }
            }
            // A send on an unconnected STREAM socket: Linux returns EPIPE
            // (tcp_sendmsg with no peer), but macOS returns ENOTCONN. Remap only
            // for stream sockets so datagram ENOTCONN (a real Linux errno) is
            // untouched. (sendto01 "not connected TCP")
            let (guest_type, guest_protocol) = match this.socket_guest_type_and_protocol(fd) {
                Some(pair) => (Some(pair.0), Some(pair.1)),
                None => (None, None),
            };
            let is_stream = guest_type == Some(libc::SOCK_STREAM);
            let is_sctp_stream = is_stream && guest_protocol == Some(LINUX_IPPROTO_SCTP);
            if is_stream && dest_addr != 0 && host_socket_is_connected(host_fd.get()) {
                return Ok(DispatchOutcome::errno(LINUX_EISCONN));
            }
            let nonblocking = this.io_is_nonblocking(fd, flags);
            let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
            let connected_send = dest_addr == 0;
            // Resolve the error-queue shadow BEFORE entering the I/O closure:
            // it needs this socket's own bound address, and the closure cannot
            // borrow `this`.
            let recverr_send_fd = match (&host_addr, recverr::is_enabled(host_fd.get())) {
                (Some(dest), true) => host_sockaddr_bytes(host_fd.get())
                    .and_then(|local| recverr::shadow_for_send(host_fd.get(), &local, dest)),
                _ => None,
            };
            let send_to = this
                .open_file(fd)
                .and_then(|f| f.description.read()?.send_timeout());
            if std::env::var_os("CARRICK_NET_DEBUG").is_some() {
                eprintln!("NETDBG sendto pre-io fd={fd} nonblocking={nonblocking}");
            }
            let outcome = this.blocking_io(fd, host_fd.get(), IoDir::Write, nonblocking, send_to, || {
                // Re-stated locally (idempotent) so the non-blocking guarantee
                // is visible at every send site below: both the real socket and
                // the error-queue shadow are O_NONBLOCK, and MSG_DONTWAIT keeps
                // that true per call.
                let host_flags = host_flags | libc::MSG_DONTWAIT;
                // Publish the SCTP boundary BEFORE the host send: the peer can
                // read the bytes the instant it returns.
                let pending_sctp = if is_sctp_stream {
                    sctp::begin_send(host_fd.get(), len)
                } else {
                    None
                };
                let n = match &host_addr {
                    None => unsafe {
                        libc::sendto(
                            host_fd.get(),
                            data_ptr as *const _,
                            len,
                            host_flags,
                            std::ptr::null(),
                            0,
                        )
                    },
                    // An error-queue socket sends through its shadow (same
                    // local addr:port, connected to this destination), so Darwin
                    // reports the returning ICMP error — it reports nothing on
                    // an unconnected socket. The shadow is already connected, so
                    // the destination is implicit: Darwin answers EISCONN for a
                    // `sendto` that names an address on a connected socket.
                    // No shadow means send normally; losing the datagram would
                    // be far worse than losing the error report.
                    Some(a) => {
                        let host_flags = host_flags | libc::MSG_DONTWAIT;
                        match recverr_send_fd {
                            Some(shadow) => unsafe {
                                libc::sendto(
                                    shadow,
                                    data_ptr as *const _,
                                    len,
                                    host_flags,
                                    std::ptr::null(),
                                    0,
                                )
                            },
                            None => unsafe {
                                libc::sendto(
                                    host_fd.get(),
                                    data_ptr as *const _,
                                    len,
                                    host_flags,
                                    a.as_ptr() as *const _,
                                    a.len() as u32,
                                )
                            },
                        }
                    }
                };
                let result = match n.host_syscall_errno().map(|value| value as i64) {
                    Err(LINUX_ENOTCONN) if is_stream => Err(LINUX_EPIPE),
                    other => other,
                };
                if let Some(pending) = pending_sctp {
                    pending.settle(result.ok().map(|sent| sent.max(0) as usize));
                }
                result
            });
            if std::env::var_os("CARRICK_NET_DEBUG").is_some() {
                eprintln!("NETDBG sendto outcome fd={fd} connected_send={connected_send} outcome={outcome:?}");
            }
            if connected_send && matches!(outcome, DispatchOutcome::Returned { value } if value >= 0) {
                this.queue_socket_error_after_send(fd);
            }
            Ok(outcome)

        }

        fn recvfrom(this, cx, fd: Fd, buf: GuestPtr, len: u64, flags: u64, src_addr: GuestPtr, addrlen: GuestPtr) {

            let memory = &mut *cx.memory;
            let fd = fd.0;
            let buf_addr = buf.0;
            let len = len as usize;
            let flags = flags as i32;
            let src_addr = src_addr.0;
            let src_len_addr = addrlen.0;
            // AF_NETLINK recv: drain the queued dump reply. The source address
            // (if requested) is the kernel: sockaddr_nl with pid=0.
            if this.fd_is_netlink(fd) {
                let drained = this.netlink_recv(fd, buf_addr, len, flags, memory);
                if let DispatchOutcome::Returned { .. } = drained
                    && src_addr != 0
                    && src_len_addr != 0
                {
                    let nl = sockaddr_nl_bytes(0, 0);
                    let _ = write_linux_sockaddr(memory, src_addr, src_len_addr, &nl);
                }
                return Ok(drained);
            }
            if let Some(open_file) = this.open_file(fd)
                && let Some(open) = open_file.description.read()
                && let OpenDescription::InMemorySocket { socket, .. } = &*open
            {
                let socket = Arc::clone(socket);
                drop(open);
                let mut target_buf = vec![0u8; len];
                match socket.recv_stream(&mut target_buf, 0) {
                    Ok((read_len, _rights)) => {
                        if read_len > 0 {
                            if memory.write_bytes(buf_addr, &target_buf[..read_len]).is_err() {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            }
                        }
                        if let Some(peer) = socket.peer_addr() {
                            if src_addr != 0 && src_len_addr != 0 {
                                if let Some(sockaddr_bytes) = socket_addr_to_linux_sockaddr(peer) {
                                    let _ = write_linux_sockaddr(
                                        memory,
                                        src_addr,
                                        src_len_addr,
                                        &sockaddr_bytes,
                                    );
                                }
                            }
                        }
                        return Ok(DispatchOutcome::Returned {
                            value: read_len as i64,
                        });
                    }
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            }
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            if family == LINUX_AF_UNIX
                && LinuxMsgFlags::from_bits_retain(flags).contains(LinuxMsgFlags::OOB)
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // MSG_ERRQUEUE reads the socket's error queue. carrick keeps no
            // error queue, so it's always empty → EAGAIN (recv01/recvfrom01),
            // matching Linux when no error is queued. Checked after the socket
            // lookup so a bad/non-socket fd still surfaces EBADF/ENOTSOCK.
            // (from_bits_retain: recv IGNORES other unknown flag bits.)
            if LinuxMsgFlags::from_bits_retain(flags).contains(LinuxMsgFlags::ERRQUEUE) {
                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
            }
            if let Some((payload, source)) = this.synthetic_datagram_drain(fd) {
                let take = payload.len().min(len);
                if take > 0 && memory.write_bytes(buf_addr, &payload[..take]).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                if src_addr != 0
                    && src_len_addr != 0
                    && write_linux_sockaddr(memory, src_addr, src_len_addr, &source).is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: take as i64 });
            }
            // An error-queue socket's ICMP error goes ONLY to the queue — that
            // is what `IP_RECVERR` is FOR. The ordinary read must still answer
            // EAGAIN, which libuv reports as a zero-length receive.
            // `udp_send_unreachable` pins this: its `recv_cb` treats a NEGATIVE
            // nread carrying no `UV_UDP_LINUX_RECVERR` flag as
            // `ASSERT(0 && "unexpected error")`.
            recverr::poll_errors(host_fd.get());
            if let Some(errno) = this.take_socket_pending_error(fd) {
                return Ok(DispatchOutcome::errno(errno));
            }
            // When the caller wants the source address back, Linux's
            // move_addr_to_user reads the in/out length as a *signed* int and
            // returns EINVAL for a negative value (recvfrom01 "invalid socket
            // addr length", fromlen = -1). carrick's write_linux_sockaddr reads
            // it as u32, so it would never reject it — validate here.
            if src_addr != 0 && src_len_addr != 0 {
                match memory.read_bytes(src_len_addr, 4) {
                    Ok(b) => {
                        if i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0 {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                    }
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            }
            // Native fd mode preserved; force this CALL non-blocking with
            // MSG_DONTWAIT and route through blocking_io: on EAGAIN a blocking-mode
            // guest fd waits losslessly (kqueue, lock released), a non-blocking one
            // gets EAGAIN. Never blocks under the dispatcher lock.
            let nonblocking = this.io_is_nonblocking(fd, flags);
            let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
            let len = len.min(crate::dispatch::MAX_RW_COUNT);
            let atomic_record = matches!(
                this.socket_guest_type(fd),
                Some(LINUX_SOCK_DGRAM) | Some(LINUX_SOCK_SEQPACKET)
            );
            let host_recv_len = if atomic_record {
                linux_msg_trunc_recv_capacity(host_fd.get(), len, flags)
            } else {
                len
            };
            // Zero-copy recv straight INTO guest memory when the destination is
            // one contiguous, guest-writable region; else recv into a bounce and
            // copy. host_ptr_for_write enforces guest-writability (a read-only
            // mapping returns None → checked write path → EFAULT).
            // Linux MSG_TRUNC on an atomic record returns the full record length
            // while copying at most `len`; Darwin returns only the host buffer
            // length. Widen that host-only bounce to SO_RCVBUF, then copy only
            // the guest-requested prefix. Stream reads never widen: doing so
            // would consume bytes the guest did not request.
            let zc_dst = (host_recv_len == len)
                .then(|| memory.host_ptr_for_write(buf_addr, len))
                .flatten();
            let zero_copy = zc_dst.is_some();
            let mut recv_copy: Option<Vec<u8>> = if zero_copy {
                None
            } else {
                Some(vec![0u8; host_recv_len])
            };
            let dst_ptr: *mut u8 = match (zc_dst, recv_copy.as_mut()) {
                (Some(p), _) => p,
                (None, Some(b)) => b.as_mut_ptr(),
                (None, None) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
            };
            let recv_to = this
                .open_file(fd)
                .and_then(|f| f.description.read()?.recv_timeout());
            let recv_protocol = this.socket_port_protocol(fd);
            let received_source = std::cell::RefCell::new(None::<Vec<u8>>);
            let recv_targets: Vec<i32> = std::iter::once(host_fd.get())
                .chain(reuseport::steal_targets(host_fd.get()))
                .collect();
            let outcome = this.blocking_io(fd, host_fd.get(), IoDir::Read, nonblocking, recv_to, || {
                let host_write_ranges = [(buf_addr, len)];
                let host_write = zero_copy.then(|| {
                    carrick_guest_mem::HostWriteGuard::new(memory, &host_write_ranges)
                });
                let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
                let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
                let used_addr = src_addr != 0;
                // SO_REUSEPORT: Darwin delivers every datagram to the last
                // socket that bound the addr:port, so take from the sibling
                // holding the group's work when this member's own socket is
                // empty. `recv_targets` is just this fd unless it is in a
                // multi-member group.
                let mut n = -1isize;
                let mut last_errno = None;
                // Re-stated locally (idempotent) so the non-blocking guarantee
                // is visible at BOTH recvfrom call sites below rather than only
                // at the outer binding — the host fd is O_NONBLOCK and this
                // runs inside `blocking_io`, and MSG_DONTWAIT keeps that true
                // per call.
                let host_flags = host_flags | libc::MSG_DONTWAIT;
                for target in &recv_targets {
                    sa_len = sa.len() as libc::socklen_t;
                    let attempt = if used_addr {
                        unsafe {
                            libc::recvfrom(
                                *target,
                                dst_ptr as *mut _,
                                host_recv_len,
                                host_flags,
                                sa.as_mut_ptr() as *mut _,
                                &mut sa_len as *mut _,
                            )
                        }
                    } else {
                        unsafe {
                            libc::recvfrom(
                                *target,
                                dst_ptr as *mut _,
                                host_recv_len,
                                host_flags,
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                            )
                        }
                    };
                    match attempt.host_syscall_errno() {
                        Ok(_) => {
                            n = attempt;
                            last_errno = None;
                            break;
                        }
                        // Only an empty socket is worth trying the next member
                        // for; any other errno is this recv's real answer.
                        Err(e) if e == LINUX_EAGAIN => last_errno = Some(e),
                        Err(e) => {
                            last_errno = Some(e);
                            break;
                        }
                    }
                }
                let n = match last_errno {
                    Some(e) => {
                        drop(host_write);
                        return Err(e);
                    }
                    None => n,
                };
                // Close the odd-generation bracket before interpreting any
                // result or touching `memory` again. Drop also runs on unwind.
                drop(host_write);
                let n = n.host_syscall_errno()?;
                if !zero_copy
                    && n > 0
                    && let Some(b) = recv_copy.as_ref()
                    && memory
                        .write_bytes(buf_addr, &b[..(n as usize).min(len)])
                        .is_err()
                {
                    return Err(LINUX_EFAULT);
                }
                if used_addr && src_addr != 0 && src_len_addr != 0 {
                    let used = (sa_len as usize).min(sa.len());
                    received_source.borrow_mut().replace(sa[..used].to_vec());
                }
                Ok(n as i64)
            });
            if matches!(outcome, DispatchOutcome::Returned { .. }) {
                // This member took the group's turn; hand it to the next.
                reuseport::advance_turn(host_fd.get());
            }
            if matches!(outcome, DispatchOutcome::Returned { .. })
                && src_addr != 0
                && src_len_addr != 0
                && let Some(host_source) = received_source.into_inner()
            {
                let linux_bytes = if let Some(protocol) = recv_protocol
                    && let Some(host_addr) = host_sockaddr_to_socket_addr(&host_source)
                    && let Ok(Some(guest_addr)) =
                        this.network
                            .provider
                            .translate_recv_addr(HostSocketAddr(host_addr), protocol)
                    && let Some(guest_sockaddr) = socket_addr_to_linux_sockaddr(guest_addr.0)
                {
                    guest_sockaddr
                } else {
                    host_to_linux_sockaddr(&host_source, family, true)
                };
                if write_linux_sockaddr(memory, src_addr, src_len_addr, &linux_bytes).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }
            Ok(outcome)

        }

        fn setsockopt(this, cx, fd: Fd, level: u64, optname: u64, optval: GuestPtr, optlen: u64) {

            let memory = &*cx.memory;
            let fd = fd.0;
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
            // LTP setsockopt01: a closed fd is EBADF and a non-socket fd is
            // ENOTSOCK; host_socket_lookup collapses both to EINVAL. (netlink is
            // handled above.)
            match this.open_file(fd) {
                None => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                Some(of) => {
                    let Some(desc) = of.description.read() else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOTSOCK));
                    };
                    if matches!(&*desc, OpenDescription::InMemorySocket { .. }) {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    if !matches!(&*desc, OpenDescription::HostSocket { .. }) {
                        return Ok(DispatchOutcome::errno(LINUX_ENOTSOCK));
                    }
                }
            }
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            // Record the GUEST-intended SO_REUSEADDR / SO_REUSEPORT / SO_RCVBUF / SO_SNDBUF so
            // getsockopt reports what the guest set rather than carrick's
            // host-side widening (SO_REUSEADDR→SO_REUSEPORT for UDP; AF_UNIX
            // buffer widening). The value still passes through to the host
            // below. (audit M4, M5)
            if level == LINUX_SOL_SOCKET
                && (optname == LINUX_SO_REUSEADDR
                    || optname == LINUX_SO_REUSEPORT
                    || optname == LINUX_SO_RCVBUF
                    || optname == LINUX_SO_SNDBUF)
                && optlen >= 4
                && let Ok(b) = memory.read_bytes(optval_addr, 4)
            {
                let v = i32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
                if let Some(open_file) = this.open_file(fd)
                    && let Some(mut open) = open_file.description.write()
                    && let OpenDescription::HostSocket { base, .. } = &mut *open
                {
                    if optname == LINUX_SO_REUSEADDR {
                        base.set_so_reuseaddr(v != 0);
                    } else if optname == LINUX_SO_REUSEPORT {
                        base.set_so_reuseport(v != 0);
                    } else if optname == LINUX_SO_RCVBUF {
                        base.set_so_rcvbuf(v);
                    } else {
                        base.set_so_sndbuf(v);
                    }
                }
            }
            // IP_RECVERR / IPV6_RECVERR: the guest is opting into Linux's UDP
            // ERROR QUEUE. Darwin has neither the option nor the queue, so
            // accept it here and model the queue ourselves — see
            // `dispatch::net::recverr`. Forwarding it would just ENOPROTOOPT
            // and libuv's `uv_udp_bind` fails outright on that.
            if (level == LINUX_SOL_IP && optname == crate::linux_abi::LINUX_IP_RECVERR)
                || (level == LINUX_SOL_IPV6 && optname == crate::linux_abi::LINUX_IPV6_RECVERR)
            {
                let on = optlen >= 4
                    && memory.read_bytes(optval_addr, 4).is_ok_and(|b| {
                        i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) != 0
                    });
                if on {
                    recverr::enable(host_fd.get(), level == LINUX_SOL_IPV6);
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // IPV6_MULTICAST_IF: Linux accepts interface index 0, meaning
            // "clear the multicast interface and let routing choose". Darwin
            // rejects 0 with EINVAL (measured on macOS 27: 0 as u32, 0 as int,
            // and a zero-length optval all EINVAL). libuv's
            // `uv_udp_set_multicast_interface(handle, NULL)` sends exactly that
            // — `sin6_scope_id = 0` — so the host call failed and
            // `udp_multicast_interface6` died on `ASSERT_OK`.
            //
            // Record the guest's intent and DON'T forward index 0. A fresh
            // socket has no multicast interface set, so "clear" on it is a true
            // no-op and this is exact. Darwin cannot undo a previously-set
            // non-zero index (there is no clear operation at all), so in that
            // one case the guest sees its 0 while the host keeps the old index.
            // A non-zero index still passes through to the host below.
            if level == LINUX_SOL_IPV6
                && optname == crate::linux_abi::LINUX_IPV6_MULTICAST_IF
                && optlen >= 4
                && let Ok(b) = memory.read_bytes(optval_addr, 4)
            {
                let index = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
                if let Some(open_file) = this.open_file(fd)
                    && let Some(mut open) = open_file.description.write()
                    && let OpenDescription::HostSocket { base, .. } = &mut *open
                {
                    base.set_ipv6_multicast_if(index);
                }
                if index == 0 {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
            }
            // SO_PASSCRED: store + accept. macOS has no equivalent (it would
            // ENOPROTOOPT through the host), and recvmsg synthesizes the
            // SCM_CREDENTIALS ancillary message from LOCAL_PEERCRED when it's
            // set, so handle it entirely carrick-side. (audit M2)
            if level == LINUX_SOL_SOCKET && optname == crate::linux_abi::LINUX_SO_PASSCRED {
                let on = optlen >= 4
                    && memory.read_bytes(optval_addr, 4).is_ok_and(|b| {
                        i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) != 0
                    });
                if let Some(open_file) = this.open_file(fd)
                    && let Some(mut open) = open_file.description.write()
                    && let OpenDescription::HostSocket { base, .. } = &mut *open
                {
                    base.set_so_passcred(on);
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // SOL_UDPLITE (136): the checksum-coverage options on a UDPLITE
            // socket we back with plain UDP. macOS has neither the level nor the
            // options; accept UDPLITE_SEND_CSCOV(10)/RECV_CSCOV(11) as no-ops so
            // the Linux guest's UDPLITE tests proceed (partial-checksum BEHAVIOR
            // isn't emulated — macOS can't — but the option calls must succeed).
            if level == 136 {
                let _ = (optname, optval_addr, optlen);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // IPV6_ADDRFORM converts a connected IPv6 socket carrying an IPv4
            // mapped peer into an IPv4 socket. Darwin has no equivalent option,
            // but Carrick stores the guest-visible family separately from the
            // host fd, so model the Linux-visible state transition here.
            if level == LINUX_SOL_IPV6 && optname == crate::linux_abi::LINUX_IPV6_ADDRFORM {
                if optlen != 0 && optval_addr == 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                if optlen < 4 {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let Ok(bytes) = memory.read_bytes(optval_addr, 4) else {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                };
                let requested = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if requested != LINUX_AF_INET {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if family != LINUX_AF_INET6 {
                    return Ok(DispatchOutcome::errno(LINUX_ENOPROTOOPT));
                }
                let Some(open_file) = this.open_file(fd) else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                let Some(mut open) = open_file.description.write() else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOTSOCK));
                };
                let OpenDescription::HostSocket { family, .. } = &mut *open else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOTSOCK));
                };
                *family = LINUX_AF_INET;
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
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
                        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                    }
                };
                if let Some(open_file) = this.open_file(fd) {
                    if let Some(mut open) = open_file.description.write() {
                        if let OpenDescription::HostSocket { base, .. } = &mut *open {
                        if optname == LINUX_SO_RCVTIMEO {
                            base.set_recv_timeout(dur);
                        } else {
                            base.set_send_timeout(dur);
                        }
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
                            host_fd.get(),
                            libc::SOL_SOCKET,
                            libc::SO_REUSEPORT,
                            &one as *const i32 as *const libc::c_void,
                            std::mem::size_of::<i32>() as u32,
                        );
                    }
                }
            }
            // Multicast group membership (join/leave, including source-specific)
            // passes through to the host. It used to be answered ENODEV outright
            // on the theory that carrick "can't reliably provide" it on macOS, so
            // libuv's multicast tests took RETURN_SKIP("No multicast support").
            // That was wrong: measured on this host, a Darwin AF_INET SOCK_DGRAM
            // socket joins 239.255.0.1 with `imr_interface = INADDR_ANY`, sends
            // to the group, receives its own datagram back, and drops the
            // membership — all four calls succeed. The option translation to
            // Darwin's numbers was already wired and simply unreachable.
            {
                use crate::linux_abi as a;
                // Protocol-independent multicast source-filter API
                // (MCAST_JOIN_GROUP=42 .. MCAST_LEAVE_SOURCE_GROUP=47, RFC 3678).
                // Darwin has no MCAST_* optnames, so Carrick models the
                // Linux-visible membership state instead of passing through. This
                // lets joins succeed for setup while preserving Linux's per-socket
                // rule: accepted sockets do not inherit listener memberships.
                if is_mcast_sockopt(level, optname) {
                    if optlen != 0 && optval_addr == 0 {
                        return Ok(DispatchOutcome::errno(a::LINUX_EFAULT));
                    }
                    let bytes = if optval_addr == 0 || optlen == 0 {
                        Vec::new()
                    } else {
                        match memory.read_bytes(optval_addr, optlen as usize) {
                            Ok(b) => b,
                            Err(_) => return Ok(DispatchOutcome::errno(a::LINUX_EFAULT)),
                        }
                    };
                    let Some(open_file) = this.open_file(fd) else {
                        return Ok(DispatchOutcome::errno(a::LINUX_EBADF));
                    };
                    let Some(mut open) = open_file.description.write() else {
                        return Ok(DispatchOutcome::errno(a::LINUX_ENOTSOCK));
                    };
                    let OpenDescription::HostSocket {
                        mcast_memberships,
                        ..
                    } = &mut *open
                    else {
                        return Ok(DispatchOutcome::errno(a::LINUX_ENOTSOCK));
                    };
                    return Ok(mcast_setsockopt_outcome(
                        mcast_memberships,
                        level,
                        optname,
                        bytes,
                    ));
                }
            }
            let (host_level, host_opt) = match linux_to_host_sockopt(level, optname) {
                Some(t) => t,
                None => {
                    return Ok(DispatchOutcome::errno(LINUX_ENOPROTOOPT));
                }
            };
            // A non-zero optlen with a NULL optval is EFAULT on Linux (the kernel
            // copies optlen bytes in from the pointer); macOS would instead see a
            // NULL/short buffer and answer EINVAL. (setsockopt01 "invalid option
            // buffer") A zero optlen keeps the existing empty-buffer behavior so
            // the "invalid optlen" case still surfaces the host's EINVAL.
            if optlen != 0 && optval_addr == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            let mut bytes = if optval_addr == 0 || optlen == 0 {
                Vec::new()
            } else {
                match memory.read_bytes(optval_addr, optlen as usize) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
            };
            // Some optvals are STRUCTS whose field order differs between guest
            // Linux and the host (today: `ip_mreq_source`). Translating only the
            // option NUMBER would hand the host correctly-named garbage.
            crate::dispatch::net::support::rewrite_optval_for_host(level, optname, &mut bytes);
            let rc = unsafe {
                libc::setsockopt(
                    host_fd.get(),
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
                // At a protocol level (IPPROTO_*), macOS answers EINVAL for an
                // optname it doesn't recognize where Linux answers ENOPROTOOPT.
                // Scope the remap to UNRECOGNIZED optnames: a RECOGNIZED option
                // that carrick maps (IP_TTL, TCP_MAXSEG, …) reports EINVAL for a
                // genuine bad argument (short optlen / out-of-range value), which
                // Linux ALSO reports as EINVAL, so that must pass through
                // unchanged. SOL_SOCKET is likewise excluded so its
                // optlen-validation EINVAL (the "invalid optlen" case) stays
                // EINVAL. Other errnos (incl. the ENOPROTOOPT for options macOS
                // simply lacks, eg IP_MTU_DISCOVER) pass through unchanged.
                // (setsockopt01 "invalid option name (UDP)")
                let errno = if errno == LINUX_EINVAL
                    && level != LINUX_SOL_SOCKET
                    && !is_known_sockopt_optname(level, optname)
                {
                    LINUX_ENOPROTOOPT
                } else {
                    errno
                };
                DispatchOutcome::errno(errno)
            } else {
                DispatchOutcome::Returned { value: 0 }
            })

        }

        fn getsockopt(this, cx, fd: Fd, level: u64, optname: u64, optval: GuestPtr, optlen: GuestPtr) {

            let memory = &mut *cx.memory;
            let fd = fd.0;
            let level = level as i32;
            let optname = optname as i32;
            let optval_addr = optval.0;
            let optlen_addr = optlen.0;
            // AF_NETLINK getsockopt: answer SO_TYPE with the GUEST-requested type
            // (SOCK_RAW or SOCK_DGRAM — a SOCK_DGRAM netlink socket must not be
            // mislabeled SOCK_RAW); everything else returns 0. (audit M6)
            if this.fd_is_netlink(fd) {
                let val: i32 = if level == LINUX_SOL_SOCKET && optname == LINUX_SO_TYPE {
                    this.socket_guest_type(fd).unwrap_or(LINUX_SOCK_RAW)
                } else {
                    0
                };
                let _ = memory.write_bytes(optval_addr, &val.to_ne_bytes());
                let _ = memory.write_bytes(optlen_addr, &4u32.to_ne_bytes());
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // LTP getsockopt01: closed fd -> EBADF, non-socket fd -> ENOTSOCK,
            // before the carrick-side SO_TYPE/SO_DOMAIN answers. (netlink above.)
            match this.open_file(fd) {
                None => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                Some(of) => {
                    let Some(desc) = of.description.read() else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOTSOCK));
                    };
                    if let OpenDescription::InMemorySocket { socket, .. } = &*desc {
                        let socket = Arc::clone(socket);
                        drop(desc);
                        let val: i32 = if level == LINUX_SOL_SOCKET {
                            match optname {
                                LINUX_SO_TYPE => socket.socket_type,
                                crate::linux_abi::LINUX_SO_DOMAIN => socket.family,
                                crate::linux_abi::LINUX_SO_PROTOCOL => socket.protocol,
                                LINUX_SO_ERROR => socket.take_so_error().unwrap_or(0),
                                _ => 0,
                            }
                        } else {
                            0
                        };
                        return write_sockopt_value(memory, optval_addr, optlen_addr, &val.to_ne_bytes());
                    }
                    if !matches!(&*desc, OpenDescription::HostSocket { .. }) {
                        return Ok(DispatchOutcome::errno(LINUX_ENOTSOCK));
                    }
                }
            }
            // SO_TYPE must report the GUEST-requested type, not the host backing:
            // a guest AF_UNIX SOCK_SEQPACKET is backed by a host SOCK_STREAM, but
            // Go derives the network ("unixpacket") from SO_TYPE, so the host's
            // STREAM answer would mislabel the socket.
            if level == LINUX_SOL_SOCKET && optname == LINUX_SO_TYPE
                && let Some(t) = this.socket_guest_type(fd) {
                    let _ = memory.write_bytes(optval_addr, &t.to_ne_bytes());
                    let _ = memory.write_bytes(optlen_addr, &4u32.to_ne_bytes());
                    return Ok(DispatchOutcome::Returned { value: 0 });
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
                let (_host_fd, family) = this.host_socket_lookup(fd)?;
                let val: i32 = if optname == crate::linux_abi::LINUX_SO_DOMAIN {
                    family
                } else {
                    0
                };
                // Honor the guest's optlen (it offers 4; clamp defensively).
                return write_sockopt_value(memory, optval_addr, optlen_addr, &val.to_ne_bytes());
            }
            // SO_REUSEADDR / SO_REUSEPORT / SO_RCVBUF / SO_SNDBUF: report the GUEST-intended
            // value, not carrick's host-side widening. REUSEPORT defaults to 0
            // unless the guest set it (so a SO_REUSEADDR→REUSEPORT widening on a
            // UDP socket is invisible here); RCVBUF/SNDBUF report Linux's doubled
            // (2×) value of what was set, or the default when never set.
            // (audit M4, M5)
            if level == LINUX_SOL_SOCKET
                && (optname == LINUX_SO_REUSEADDR
                    || optname == LINUX_SO_REUSEPORT
                    || optname == LINUX_SO_RCVBUF
                    || optname == LINUX_SO_SNDBUF
                    || optname == LINUX_SO_ACCEPTCONN
                    || optname == crate::linux_abi::LINUX_SO_PASSCRED)
            {
                const LINUX_DEFAULT_SOCKBUF: i32 = 212_992;
                let Some(open_file) = this.open_file(fd) else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                let val: i32 = {
                    let Some(open) = open_file.description.read() else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOTSOCK));
                    };
                    if let OpenDescription::HostSocket { base, .. } = &*open {
                        if optname == LINUX_SO_REUSEADDR {
                            i32::from(base.so_reuseaddr())
                        } else if optname == LINUX_SO_REUSEPORT {
                            i32::from(base.so_reuseport())
                        } else if optname == crate::linux_abi::LINUX_SO_PASSCRED {
                            i32::from(base.so_passcred())
                        } else if optname == LINUX_SO_ACCEPTCONN {
                            i32::from(base.listening())
                        } else if optname == LINUX_SO_RCVBUF {
                            base.so_rcvbuf()
                                .map_or(LINUX_DEFAULT_SOCKBUF, |v| v.saturating_mul(2))
                        } else {
                            base.so_sndbuf()
                                .map_or(LINUX_DEFAULT_SOCKBUF, |v| v.saturating_mul(2))
                        }
                    } else {
                        0
                    }
                };
                return write_sockopt_value(memory, optval_addr, optlen_addr, &val.to_ne_bytes());
            }
            // IPV6_MULTICAST_IF: report the guest-set index. The set side keeps
            // this carrick-side because Linux's index-0 "clear" has no Darwin
            // encoding (see the setsockopt comment), so the host would answer
            // with a stale non-zero index after the guest cleared it. Never set
            // reads back as 0, which is Linux's default.
            if level == LINUX_SOL_IPV6
                && optname == crate::linux_abi::LINUX_IPV6_MULTICAST_IF
                && let Some(open_file) = this.open_file(fd)
            {
                let index = {
                    let open = open_file.description.read();
                    match open.as_deref() {
                        Some(OpenDescription::HostSocket { base, .. }) => base.ipv6_multicast_if(),
                        _ => None,
                    }
                };
                if let Some(index) = index {
                    return write_sockopt_value(
                        memory,
                        optval_addr,
                        optlen_addr,
                        &index.to_ne_bytes(),
                    );
                }
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
                if let Some(open_file) = this.open_file(fd)
                    && let Some(OpenDescription::HostSocket { base, .. }) = open_file.description.read().as_deref() {
                        handled = true;
                        dur = if optname == LINUX_SO_RCVTIMEO {
                            base.recv_timeout()
                        } else {
                            base.send_timeout()
                        };
                    }
                if handled {
                    let tv_sec = dur.map(|d| d.as_secs() as i64).unwrap_or(0);
                    let tv_usec = dur.map(|d| d.subsec_micros() as i64).unwrap_or(0);
                    let mut tv_bytes = [0u8; 16];
                    tv_bytes[0..8].copy_from_slice(&tv_sec.to_ne_bytes());
                    tv_bytes[8..16].copy_from_slice(&tv_usec.to_ne_bytes());
                    return write_sockopt_value(memory, optval_addr, optlen_addr, &tv_bytes);
                }
            }
            // SO_PEERCRED: Linux returns `struct ucred { pid, uid, gid }`. macOS
            // has no single equivalent, so synthesize it from LOCAL_PEERCRED
            // (peer uid + primary gid via `xucred`) and LOCAL_PEERPID (peer pid).
            // Used by D-Bus / systemd peer authentication over AF_UNIX. Done here
            // because `linux_to_host_sockopt` has no Darwin opt to map it to.
            if level == LINUX_SOL_SOCKET && optname == crate::linux_abi::LINUX_SO_PEERCRED {
                let (host_fd, _family) = this.host_socket_lookup(fd)?;
                // Best-effort peer creds, resolved per host (Linux: SO_PEERCRED
                // -> ucred; Darwin: LOCAL_PEERCRED + LOCAL_PEERPID). Returns 0s
                // if the socket isn't connected, matching the guest's tolerance.
                let (pid, uid, gid) = carrick_portable::peer_ucred(host_fd.get());
                let mut ucred = [0u8; crate::linux_abi::LINUX_UCRED_SIZE];
                ucred[0..4].copy_from_slice(&pid.to_ne_bytes());
                ucred[4..8].copy_from_slice(&uid.to_ne_bytes());
                ucred[8..12].copy_from_slice(&gid.to_ne_bytes());
                // Honor the guest's optlen: write at most what it offered and
                // report the bytes actually written (Linux clamps to the buffer).
                return write_sockopt_value(memory, optval_addr, optlen_addr, &ucred);
            }
            let (host_fd, _family) = this.host_socket_lookup(fd)?;
            // SO_ERROR: the option VALUE is itself an errno (the pending socket
            // error, e.g. from an async connect). The host returns a Darwin
            // errno; the guest reads it as a Linux errno. Without translation a
            // refused connect surfaces as Darwin ECONNREFUSED=61, which Linux
            // reads as ENODATA — so asyncio's sock_connect never raises
            // ConnectionRefusedError. Translate the i32 value through the same
            // table the rest of the ABI uses. (getsockopt itself still
            // succeeds; only the value is mapped.)
            if level == LINUX_SOL_SOCKET && optname == LINUX_SO_ERROR {
                if let Some(linux_err) = this.take_socket_pending_error(fd) {
                    return write_sockopt_value(
                        memory,
                        optval_addr,
                        optlen_addr,
                        &linux_err.get().to_ne_bytes(),
                    );
                }
                let mut host_err: i32 = 0;
                let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
                let rc = unsafe {
                    libc::getsockopt(
                        host_fd.get(),
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        (&mut host_err as *mut i32).cast(),
                        &mut len,
                    )
                };
                if let Err(errno) = rc.host_syscall_errno() {
                    return Ok(DispatchOutcome::errno(errno));
                }
                // 0 = "no pending error" (not an errno); non-zero is a HOST
                // errno translated to the Linux value and written RAW into the
                // guest's int optval — a wire boundary, hence `.get()`.
                let linux_err: i32 = if host_err == 0 {
                    0
                } else {
                    crate::host_to_linux_errno(host_err).get()
                };
                // Honor the guest's optlen (it may pass <4); clamp like Linux.
                return write_sockopt_value(
                    memory,
                    optval_addr,
                    optlen_addr,
                    &linux_err.to_ne_bytes(),
                );
            }
            let (host_level, host_opt) = match linux_to_host_sockopt(level, optname) {
                Some(t) => t,
                None => {
                    // An unrecognized LEVEL is EOPNOTSUPP; an unrecognized optname
                    // at a known level stays ENOPROTOOPT. (getsockopt01 "invalid
                    // level" vs "invalid option name (IP/TCP)")
                    let errno = if is_known_sockopt_level(level) {
                        LINUX_ENOPROTOOPT
                    } else {
                        LINUX_EOPNOTSUPP
                    };
                    return Ok(DispatchOutcome::errno(errno));
                }
            };
            // Read the guest's reported optlen so we don't overflow.
            let optlen_bytes = match memory.read_bytes(optlen_addr, 4) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            };
            let mut optlen = u32::from_ne_bytes([
                optlen_bytes[0],
                optlen_bytes[1],
                optlen_bytes[2],
                optlen_bytes[3],
            ]);
            // A negative optlen (as a signed int) is EINVAL on Linux. (getsockopt01
            // "invalid optlen") macOS would clamp the u32 and read successfully.
            if (optlen as i32) < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let cap = optlen.min(256) as usize;
            let mut buf = vec![0u8; cap];
            let rc = unsafe {
                libc::getsockopt(
                    host_fd.get(),
                    host_level,
                    host_opt,
                    buf.as_mut_ptr() as *mut _,
                    &mut optlen as *mut _,
                )
            };
            if let Err(errno) = rc.host_syscall_errno() {
                // At a protocol level (IPPROTO_*), macOS answers EINVAL for an
                // option it can't read where Linux answers EOPNOTSUPP. Scope the
                // remap to UNRECOGNIZED optnames: a RECOGNIZED option that carrick
                // maps reports EINVAL for a genuine value/optlen error, which
                // Linux ALSO reports as EINVAL, so it must pass through unchanged.
                // SOL_SOCKET is likewise excluded so its value/optlen EINVAL stays
                // EINVAL. (getsockopt01 "not supported option name (UDP)")
                let errno = if errno == LINUX_EINVAL
                    && level != LINUX_SOL_SOCKET
                    && !is_known_sockopt_optname(level, optname)
                {
                    LINUX_EOPNOTSUPP
                } else {
                    errno
                };
                return Ok(DispatchOutcome::errno(errno));
            }
            let used = (optlen as usize).min(buf.len());
            // A NULL optval with a value to return is EFAULT on Linux (the kernel
            // copies `used` bytes out); macOS silently succeeds. (getsockopt01
            // "invalid option buffer")
            if used > 0 && optval_addr == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            if optval_addr != 0 && used > 0 && memory.write_bytes(optval_addr, &buf[..used]).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            if memory
                .write_bytes(optlen_addr, &optlen.to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn shutdown(this, cx, fd: Fd, how: u64) {

            let fd: Fd = fd;
            let how = how as i32;
            if let Some(open_file) = this.open_file(fd.0)
                && let Some(open) = open_file.description.read()
                && let OpenDescription::InMemorySocket { socket, .. } = &*open
            {
                let socket = Arc::clone(socket);
                drop(open);
                match socket.shutdown(how) {
                    Ok(()) => {
                        this.notify_inmem_epoll();
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            }
            let (host_fd, _family) = this.host_socket_lookup(fd.0)?;
            let rc = unsafe { libc::shutdown(host_fd.get(), how) };
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
        memory: &impl CurrentMmMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let is_netlink = self.fd_is_netlink(fd);
        if let Some(open_file) = self.open_file(fd)
            && let Some(open) = open_file.description.read()
            && let OpenDescription::InMemorySocket { socket, .. } = &*open
        {
            let socket = Arc::clone(socket);
            drop(open);
            let msg = read_linux_msghdr(memory, msg_addr)?;
            let iovecs = read_iovecs(memory, msg.iov, msg.iovlen as usize)?;
            let mut data = Vec::new();
            for iov in iovecs {
                if iov.iov_len == 0 {
                    continue;
                }
                let chunk = match memory.read_bytes(iov.iov_base, iov.iov_len as usize) {
                    Ok(b) => b,
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                };
                data.extend_from_slice(&chunk);
            }
            match socket.send_stream(&data, Vec::new()) {
                Ok(written) => {
                    self.notify_inmem_epoll();
                    return Ok(DispatchOutcome::Returned {
                        value: written as i64,
                    });
                }
                Err(LINUX_EPIPE) => {
                    return Ok(DispatchOutcome::errno(LINUX_EPIPE));
                }
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            }
        }
        let (host_fd, family) = if is_netlink {
            (HostFd(-1), LINUX_AF_NETLINK)
        } else {
            self.host_socket_lookup(fd)?
        };
        let msg = read_linux_msghdr(memory, msg_addr)?;
        let iovecs = read_iovecs(memory, msg.iov, msg.iovlen as usize)?;
        // Pack iovecs into a single contiguous send. Simple and avoids
        // having to keep guest pointers alive across the FFI call.
        let mut data = Vec::new();
        for iov in iovecs {
            // An empty iovec contributes nothing — and its base is allowed to be
            // NULL (libuv sends a zero-length datagram as uv_buf_init(NULL, 0)).
            // read_bytes(NULL, 0) would otherwise fault, so skip it.
            if iov.iov_len == 0 {
                continue;
            }
            let chunk = match memory.read_bytes(iov.iov_base, iov.iov_len as usize) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
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
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            }
        };
        if family == LINUX_AF_INET
            && self.socket_guest_type(fd) == Some(LINUX_SOCK_DGRAM)
            && let Some(requested) = host_addr
                .as_deref()
                .and_then(host_sockaddr_to_socket_addr)
                .or_else(|| self.connected_guest_peer_addr(fd))
        {
            if self.maybe_queue_icmp_echo_reply(fd, &data, requested)
                || self.socket_port_protocol(fd) == Some(PortProtocol::Udp)
                    && self.maybe_queue_dns_response(fd, &data, requested)
            {
                return Ok(DispatchOutcome::Returned {
                    value: data.len() as i64,
                });
            }
        }
        // SCM_RIGHTS ancillary data (passing fds over AF_UNIX). Read the guest's
        // Linux-layout control buffer, extract the guest fds, map each to its
        // backing host fd, and build a host-layout control buffer for the real
        // sendmsg. This is the multiprocessing forkserver's fd-handoff path.
        let mut host_control: Vec<u8> = Vec::new();
        if msg.control != 0 && msg.controllen > 0 {
            let raw = memory.read_bytes(msg.control, msg.controllen as usize)?;
            let guest_fds = parse_linux_scm_rights_fds(&raw);
            if !guest_fds.is_empty() {
                let mut host_fds = Vec::with_capacity(guest_fds.len());
                for gfd in &guest_fds {
                    match self.host_fd_for_scm(*gfd) {
                        Some(h) => host_fds.push(h),
                        // A passed fd with no backing host fd can't cross the
                        // socket → EBADF, matching Linux's rejection of an
                        // invalid fd in an SCM_RIGHTS array.
                        None => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                    }
                }
                host_control = build_host_scm_rights(&host_fds);
            }
            // IPv6 ancillary cmsgs set on send (IPV6_HOPLIMIT/TCLASS): translate
            // the guest's Linux cmsg types → macOS and append a host-layout
            // record so the kernel applies them (CPython testSetHopLimit /
            // testSetTrafficClassAndHopLimit). recvmsg translates them back.
            let ipv6 = parse_guest_ipv6_cmsgs(&raw);
            if !ipv6.is_empty() {
                host_control.extend_from_slice(&build_host_ipv6_cmsgs(&ipv6));
            }
        }
        let nonblocking = self.io_is_nonblocking(fd, flags);
        let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
        // A guest SCTP stream is backed by TCP, which carries no message
        // boundaries; record where each message ends so the receiver can report
        // MSG_EOR the way Linux does.
        let is_sctp_stream = self.socket_guest_protocol(fd) == Some(LINUX_IPPROTO_SCTP);
        let payload_len = data.len();
        let send_to = self
            .open_file(fd)
            .and_then(|f| f.description.read()?.send_timeout());
        // An error-queue socket sends through its shadow so Darwin will report
        // the returning ICMP error (it reports nothing on an unconnected
        // socket). Same bytes and same source address on the wire. libuv's
        // `uv_udp_send` lowers to sendmsg, not sendto, so this path needs the
        // routing just as much as `sendto` does.
        let recverr_send_fd = match (&host_addr, recverr::is_enabled(host_fd.get())) {
            (Some(dest), true) => host_sockaddr_bytes(host_fd.get())
                .and_then(|local| recverr::shadow_for_send(host_fd.get(), &local, dest)),
            _ => None,
        };
        let outcome = self.blocking_io(
            fd,
            host_fd.get(),
            IoDir::Write,
            nonblocking,
            send_to,
            || {
                // Use a real sendmsg so the host control buffer (SCM_RIGHTS) is
                // delivered. A single iovec over the assembled `data` is fine —
                // the byte stream is identical to the guest's scattered iovecs.
                let mut hiov = libc::iovec {
                    iov_base: data.as_ptr() as *mut libc::c_void,
                    iov_len: data.len(),
                };
                let mut hmsg: libc::msghdr = unsafe { std::mem::zeroed() };
                // The shadow is already CONNECTED to this destination, and Darwin
                // answers EISCONN for a send that names an address on a connected
                // socket — so address it implicitly there.
                if let Some(a) = &host_addr
                    && recverr_send_fd.is_none()
                {
                    hmsg.msg_name = a.as_ptr() as *mut libc::c_void;
                    hmsg.msg_namelen = a.len() as libc::socklen_t;
                }
                hmsg.msg_iov = &mut hiov as *mut _;
                hmsg.msg_iovlen = 1;
                if !host_control.is_empty() {
                    hmsg.msg_control = host_control.as_ptr() as *mut libc::c_void;
                    hmsg.msg_controllen = host_control.len() as _;
                }
                let send_fd = recverr_send_fd.unwrap_or_else(|| host_fd.get());
                // Re-stated locally (idempotent): both the real socket and the
                // error-queue shadow are O_NONBLOCK, and MSG_DONTWAIT keeps this
                // call non-blocking regardless.
                let host_flags = host_flags | libc::MSG_DONTWAIT;
                let pending_sctp = if is_sctp_stream {
                    sctp::begin_send(send_fd, payload_len)
                } else {
                    None
                };
                let n = unsafe { libc::sendmsg(send_fd, &hmsg as *const _, host_flags) };
                let result = n.host_syscall_errno().map(|value| value as i64);
                if let Some(pending) = pending_sctp {
                    pending.settle(result.ok().map(|sent| sent.max(0) as usize));
                }
                result
            },
        );
        Ok(outcome)
    }

    /// Serve one `recvmsg(MSG_ERRQUEUE)` from this socket's modelled Linux
    /// error queue (see `dispatch::net::recverr`).
    ///
    /// Returns the entry as a `sock_extended_err` + `SO_EE_OFFENDER` cmsg with
    /// `MSG_ERRQUEUE` set in the returned `msg_flags` — libuv checks that flag
    /// before it will even look at the cmsgs. An empty queue is `EAGAIN`,
    /// exactly as a drained Linux queue is, which is what ends libuv's
    /// errqueue-drain loop.
    fn recvmsg_errqueue(
        &self,
        fd: i32,
        msg_addr: u64,
        msg: &LinuxMsghdr,
        memory: &mut impl CurrentMmMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let Ok((host_fd, _family)) = self.host_socket_lookup(fd) else {
            return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
        };
        recverr::poll_errors(host_fd.get());
        let Some(entry) = recverr::pop(host_fd.get()) else {
            return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
        };
        // The offending peer, in the guest's sockaddr layout, both as msg_name
        // and inside the cmsg (Linux puts it in both places).
        let offender = host_to_linux_sockaddr(
            &entry.offender,
            if entry.is_ipv6 {
                LINUX_AF_INET6
            } else {
                LINUX_AF_INET
            },
            true,
        );
        if msg.name != 0 && msg.namelen > 0 {
            let take = offender.len().min(msg.namelen as usize);
            if memory.write_bytes(msg.name, &offender[..take]).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            let _ = memory.write_bytes(
                msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64,
                &(offender.len() as u32).to_ne_bytes(),
            );
        }
        let mut linux_flags = crate::linux_abi::LINUX_MSG_ERRQUEUE;
        let cap = if msg.control != 0 {
            msg.controllen as usize
        } else {
            0
        };
        let (control, truncated) = build_linux_recverr(entry.errno, entry.is_ipv6, &offender, cap);
        if truncated {
            linux_flags |= crate::linux_abi::LINUX_MSG_CTRUNC;
        }
        if !control.is_empty() && memory.write_bytes(msg.control, &control).is_err() {
            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
        }
        let _ = memory.write_bytes(
            msg_addr + core::mem::offset_of!(LinuxMsghdr, controllen) as u64,
            &(control.len() as u64).to_ne_bytes(),
        );
        let _ = memory.write_bytes(
            msg_addr + core::mem::offset_of!(LinuxMsghdr, flags) as u64,
            &linux_flags.to_ne_bytes(),
        );
        // Linux returns the original datagram's payload here; libuv ignores it
        // and reads only the cmsg, so report zero bytes rather than inventing
        // a payload Carrick never captured.
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn recvmsg_inner(
        &self,
        fd: i32,
        msg_addr: u64,
        flags: i32,
        memory: &mut impl CurrentMmMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let is_netlink = self.fd_is_netlink(fd);
        if let Some(open_file) = self.open_file(fd)
            && let Some(open) = open_file.description.read()
            && let OpenDescription::InMemorySocket { socket, .. } = &*open
        {
            let socket = Arc::clone(socket);
            drop(open);
            let msg = read_linux_msghdr(memory, msg_addr)?;
            if (msg.namelen as i32) < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if msg.iovlen as usize > 1024 {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMSGSIZE));
            }
            let iovecs = read_iovecs(memory, msg.iov, msg.iovlen as usize)?;
            let total: usize = iovecs.iter().map(|iov| iov.iov_len as usize).sum();
            let mut target_buf = vec![0u8; total];
            match socket.recv_stream(&mut target_buf, 0) {
                Ok((read_len, _rights)) => {
                    let mut remaining = read_len;
                    let mut cursor = 0usize;
                    for iov in &iovecs {
                        if remaining == 0 {
                            break;
                        }
                        let take = remaining.min(iov.iov_len as usize);
                        if take > 0 {
                            if memory
                                .write_bytes(iov.iov_base, &target_buf[cursor..cursor + take])
                                .is_err()
                            {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            }
                            cursor += take;
                            remaining -= take;
                        }
                    }
                    if let Some(peer) = socket.peer_addr() {
                        if msg.name != 0 && msg.namelen != 0 {
                            if let Some(sockaddr_bytes) = socket_addr_to_linux_sockaddr(peer) {
                                let take = sockaddr_bytes.len().min(msg.namelen as usize);
                                if memory
                                    .write_bytes(msg.name, &sockaddr_bytes[..take])
                                    .is_err()
                                {
                                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                                }
                                let _ = memory.write_bytes(
                                    msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64,
                                    &(sockaddr_bytes.len() as u32).to_ne_bytes(),
                                );
                            }
                        }
                    }
                    return Ok(DispatchOutcome::Returned {
                        value: read_len as i64,
                    });
                }
                Err(LINUX_EAGAIN) => return Ok(DispatchOutcome::errno(LINUX_EAGAIN)),
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            }
        }
        let (host_fd, family) = if is_netlink {
            (HostFd(-1), LINUX_AF_NETLINK)
        } else {
            self.host_socket_lookup(fd)?
        };
        let msg = read_linux_msghdr(memory, msg_addr)?;
        // Linux validates the msghdr during copy-in before touching the flags: a
        // negative msg_namelen is EINVAL (recvmsg01 "invalid socket length",
        // which passes flags=-1 so its MSG_ERRQUEUE bit must NOT short-circuit
        // ahead of this check).
        if !is_netlink && (msg.namelen as i32) < 0 {
            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
        }
        // MSG_ERRQUEUE reads the socket's error queue. carrick keeps no error
        // queue, so it's always empty -> EAGAIN (recvmsg01), matching Linux when
        // no error is queued. Checked after msghdr validation so an invalid
        // msg_namelen still surfaces EINVAL. (from_bits_retain: recvmsg IGNORES
        // other unknown flag bits.) Mirrors the recvfrom MSG_ERRQUEUE path.
        if !is_netlink && LinuxMsgFlags::from_bits_retain(flags).contains(LinuxMsgFlags::ERRQUEUE) {
            return self.recvmsg_errqueue(fd, msg_addr, &msg, memory);
        }
        // Linux caps the iovec array at UIO_MAXIOV (1024); a larger msg_iovlen is
        // EMSGSIZE, not the EINVAL that read_iovecs' length guard would raise
        // (recvmsg01 "invalid iovec count").
        if msg.iovlen as usize > 1024 {
            return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMSGSIZE));
        }
        let iovecs = read_iovecs(memory, msg.iov, msg.iovlen as usize)?;
        // AF_NETLINK: drain the queued dump reply into the iovecs, fill in
        // the source sockaddr_nl (kernel; pid=0), and zero controllen/flags.
        if is_netlink {
            let total: usize = iovecs.iter().map(|iov| iov.iov_len as usize).sum();
            if total == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let chunk = self.netlink_drain(fd, total);
            if chunk.is_empty() {
                return Ok(self.empty_netlink_recv(fd, flags));
            }
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
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
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
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                let _ = memory.write_bytes(
                    msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64,
                    &(nl.len() as u32).to_ne_bytes(),
                );
            }
            let _ = memory.write_bytes(
                msg_addr + core::mem::offset_of!(LinuxMsghdr, controllen) as u64,
                &0u64.to_ne_bytes(),
            );
            let _ = memory.write_bytes(
                msg_addr + core::mem::offset_of!(LinuxMsghdr, flags) as u64,
                &0i32.to_ne_bytes(),
            );
            return Ok(DispatchOutcome::Returned { value: n as i64 });
        }
        let total: usize = iovecs.iter().map(|iov| iov.iov_len as usize).sum();
        if let Some((payload, source)) = self.synthetic_datagram_drain(fd) {
            let n = payload.len().min(total);
            let mut remaining = n;
            let mut cursor = 0usize;
            for iov in &iovecs {
                if remaining == 0 {
                    break;
                }
                let take = remaining.min(iov.iov_len as usize);
                if take > 0 {
                    if memory
                        .write_bytes(iov.iov_base, &payload[cursor..cursor + take])
                        .is_err()
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    cursor += take;
                    remaining -= take;
                }
            }
            if msg.name != 0 && msg.namelen != 0 {
                let write_len = (source.len() as u32).min(msg.namelen);
                if write_len > 0
                    && memory
                        .write_bytes(msg.name, &source[..write_len as usize])
                        .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                let _ = memory.write_bytes(
                    msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64,
                    &(source.len() as u32).to_ne_bytes(),
                );
            }
            let _ = memory.write_bytes(
                msg_addr + core::mem::offset_of!(LinuxMsghdr, controllen) as u64,
                &0u64.to_ne_bytes(),
            );
            let _ = memory.write_bytes(
                msg_addr + core::mem::offset_of!(LinuxMsghdr, flags) as u64,
                &0i32.to_ne_bytes(),
            );
            return Ok(DispatchOutcome::Returned { value: n as i64 });
        }
        let nonblocking = self.io_is_nonblocking(fd, flags);
        let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
        let recv_to = self
            .open_file(fd)
            .and_then(|f| f.description.read()?.recv_timeout());
        let want_control = msg.control != 0 && msg.controllen > 0;
        // SCM_RIGHTS host fds received this call, ferried out of the I/O closure
        // (which may run on a retry) so they're installed/written-back exactly
        // once after a successful recvmsg. Same for the guest msg_flags.
        let received_host_fds = std::cell::RefCell::new(Vec::<i32>::new());
        // IPv6 RFC 3542 ancillary cmsgs (hop-limit/tclass/pktinfo) the host
        // returned, as (linux_cmsg_type, data) — forwarded to the guest below.
        let received_ipv6_cmsgs = std::cell::RefCell::new(Vec::<(i32, Vec<u8>)>::new());
        // See the recvfrom path: with `IP_RECVERR` the error belongs to the
        // QUEUE, not to this read, which must still answer EAGAIN.
        if !is_netlink {
            recverr::poll_errors(host_fd.get());
        }
        let guest_msg_flags = std::cell::Cell::new(0i32);
        // SCTP never merges two messages into one recvmsg and reports MSG_EOR
        // when a read consumes the END of one. Its TCP backing has neither
        // property, so cap the read at the current boundary and answer EOR from
        // the recorded one.
        let (guest_type, guest_protocol) = match self.socket_guest_type_and_protocol(fd) {
            Some(pair) => (Some(pair.0), Some(pair.1)),
            None => (None, None),
        };
        let is_sctp_stream = guest_protocol == Some(LINUX_IPPROTO_SCTP);
        let sctp_peek = flags & LinuxMsgFlags::PEEK.bits() != 0;
        let sctp_eor = std::cell::Cell::new(false);
        // macOS reports MSG_TRUNC for a ZERO-length datagram read into a
        // zero-length buffer, where nothing is truncated and Linux reports none;
        // the genuinely-truncated case agrees on both. Telling them apart needs to
        // know whether the datagram carried payload, and `FIONREAD` cannot say —
        // on macOS it answers 16 for an EMPTY unix datagram and 17 for a one-byte
        // one, i.e. it includes per-datagram accounting overhead, and subtracting
        // a hardcoded 16 would be exactly the sort of magic offset that rots.
        //
        // So read into a ONE-byte scratch and look at what comes back. Linux
        // CONSUMES a datagram read into a zero-length buffer either way, so
        // consuming it here matches, and "did any byte arrive" answers it
        // directly. Restricted to datagram-shaped sockets — on a stream, a byte
        // the guest did not ask for must stay queued.
        let datagram_shaped = matches!(
            guest_type,
            Some(t) if t == libc::SOCK_DGRAM || t == libc::SOCK_SEQPACKET
        );
        let zero_len_datagram_read = total == 0 && datagram_shaped && !is_netlink;
        let scratch_saw_payload = std::cell::Cell::new(false);
        let recvmsg_targets: Vec<i32> = std::iter::once(host_fd.get())
            .chain(reuseport::steal_targets(host_fd.get()))
            .collect();
        let outcome =
            self.blocking_io(fd, host_fd.get(), IoDir::Read, nonblocking, recv_to, || {
                // A retry must not leak fds from a prior partial attempt.
                for stale in received_host_fds.borrow_mut().drain(..) {
                    unsafe { libc::close(stale) };
                }
                let capped = if is_sctp_stream {
                    sctp::read_limit(host_fd.get(), total)
                } else {
                    total
                };
                // Darwin returns only the host-buffer length for an atomic
                // recvmsg(MSG_TRUNC). Widen the host-only buffer so the return
                // value retains the full record length, while the scatter below
                // still copies no more than the guest iovec capacity.
                let host_recv_len = if datagram_shaped && !zero_len_datagram_read {
                    linux_msg_trunc_recv_capacity(host_fd.get(), capped, flags)
                } else if zero_len_datagram_read {
                    1
                } else {
                    capped
                };
                let mut buf = vec![0u8; host_recv_len];
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
                // host_flags carries MSG_DONTWAIT and this runs inside blocking_io
                // (host_fd is O_NONBLOCK; EAGAIN -> WaitOnFds with the dispatcher lock
                // released), so this recvmsg never blocks under the lock.
                // SO_REUSEPORT: Darwin delivers every datagram to the last socket
                // that bound the addr:port, so take from the sibling holding the
                // group's work when this member's own socket is empty. Without
                // this the member whose TURN it is can never drain the group and
                // the readiness gate silences the others — a deadlock, not just a
                // skew. `recvmsg_targets` is just this fd unless it is in a
                // multi-member group.
                let mut n = -1isize;
                let mut last_errno = None;
                for target in &recvmsg_targets {
                    if msg.name != 0 {
                        hmsg.msg_namelen = sa.len() as libc::socklen_t;
                    }
                    if want_control {
                        hmsg.msg_controllen = hcontrol.len() as _;
                    }
                    let attempt =
                        unsafe { libc::recvmsg(*target, &mut hmsg as *mut _, host_flags) };
                    match attempt.host_syscall_errno() {
                        Ok(_) => {
                            n = attempt;
                            last_errno = None;
                            break;
                        }
                        Err(e) if e == LINUX_EAGAIN => last_errno = Some(e),
                        Err(e) => {
                            last_errno = Some(e);
                            break;
                        }
                    }
                }
                if let Some(e) = last_errno {
                    return Err(e);
                }
                let n = n.host_syscall_errno()?;
                // Stash any received fds (host-layout cmsg) for installation after
                // the closure returns; the guest-facing rewrite happens below.
                if want_control && hmsg.msg_controllen as usize > 0 {
                    let got = parse_host_scm_rights_fds(&hcontrol, hmsg.msg_controllen as usize);
                    *received_host_fds.borrow_mut() = got;
                    *received_ipv6_cmsgs.borrow_mut() =
                        parse_host_ipv6_cmsgs(&hcontrol, hmsg.msg_controllen as usize);
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
                        .write_bytes(
                            msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64,
                            &(linux_bytes.len() as u32).to_ne_bytes(),
                        )
                        .is_err()
                    {
                        return Err(LINUX_EFAULT);
                    }
                }
                // Remember the host msg_flags; the guest controllen + final flags
                // (incl. a possible MSG_CTRUNC) are written after fd install below.
                let n = if zero_len_datagram_read {
                    // The guest asked for no bytes; anything the scratch caught only
                    // tells us the datagram was non-empty.
                    scratch_saw_payload.set(n > 0);
                    0
                } else {
                    n
                };
                let mut translated_flags = host_to_linux_msg_flags(hmsg.msg_flags);
                if datagram_shaped && flags & LINUX_MSG_TRUNC != 0 && n as usize > total {
                    translated_flags |= LINUX_MSG_TRUNC;
                }
                guest_msg_flags.set(translated_flags);
                if is_sctp_stream {
                    sctp_eor.set(sctp::complete_read(host_fd.get(), n as usize, sctp_peek));
                }
                Ok(n as i64)
            });
        // Install any received fds as fresh guest fds, then write the guest
        // (Linux-layout) control buffer + the controllen/flags fields. Done
        // OUTSIDE the I/O closure so it happens exactly once on success.
        let host_fds: Vec<i32> = received_host_fds.borrow_mut().drain(..).collect();
        if matches!(outcome, DispatchOutcome::Returned { value } if value >= 0) {
            // This member took the group's turn; hand it to the next.
            reuseport::advance_turn(host_fd.get());
        }
        if matches!(outcome, DispatchOutcome::Returned { value } if value >= 0) {
            // from_bits_retain: recvmsg IGNORES unknown msg_flags bits.
            let cloexec =
                LinuxMsgFlags::from_bits_retain(flags).contains(LinuxMsgFlags::CMSG_CLOEXEC);
            let mut guest_fds = Vec::with_capacity(host_fds.len());
            for hfd in host_fds {
                // An install failure (None) already closed `hfd`: the
                // freshly-built description became the fd's ONE owner, and
                // dropping it ran the close. (Historically the owner's drop
                // AND an explicit close here both fired — a latent EMFILE
                // double-close.)
                if let Some(gfd) = self.install_received_host_fd(hfd, cloexec) {
                    guest_fds.push(gfd);
                }
            }
            let mut linux_flags = guest_msg_flags.get();
            // MSG_CMSG_CLOEXEC has no macOS equivalent, so the host never reports
            // it and the translated flags come back without it. Linux ECHOES the
            // caller's request in msg_flags — Go's `TestSCMCredentials` asserts
            // exactly that, and the Docker oracle returns 0x40000000 where carrick
            // returned 0x0. The close-on-exec itself was already applied to the
            // installed fd; only the echo was missing.
            if LinuxMsgFlags::from_bits_retain(flags).contains(LinuxMsgFlags::CMSG_CLOEXEC) {
                linux_flags |= LinuxMsgFlags::CMSG_CLOEXEC.bits();
            }
            // SCTP: this read consumed the end of a message, which Linux reports
            // as MSG_EOR. The TCP backing cannot say so on its own.
            if sctp_eor.get() {
                linux_flags |= LinuxMsgFlags::EOR.bits();
            }
            // MSG_TRUNC reports a truncated ATOMIC record, so Linux sets it only
            // on datagram/seqpacket sockets — a stream has no record to truncate
            // and simply leaves the rest queued. macOS sets it on a stream too
            // when the data does not fit.
            if guest_type == Some(libc::SOCK_STREAM) {
                linux_flags &= !LinuxMsgFlags::TRUNC.bits();
            }
            // A zero-length read of a datagram truncates it only if it carried
            // payload; the scratch read above answers that directly.
            if zero_len_datagram_read {
                if scratch_saw_payload.get() {
                    linux_flags |= LinuxMsgFlags::TRUNC.bits();
                } else {
                    linux_flags &= !LinuxMsgFlags::TRUNC.bits();
                }
            }
            let mut written_controllen = 0u64;
            if want_control {
                let (mut scm, scm_trunc) =
                    build_linux_scm_rights(&guest_fds, msg.controllen as usize);
                // SO_PASSCRED: append an SCM_CREDENTIALS record with the peer's
                // ucred after any SCM_RIGHTS, bounded by the remaining control
                // budget. (audit M2)
                let mut cred_trunc = false;
                if !is_netlink && self.socket_so_passcred(fd) {
                    let (pid, uid, gid) = self.peer_ucred(host_fd.get());
                    let remaining = (msg.controllen as usize).saturating_sub(scm.len());
                    let (creds, t) = build_linux_scm_creds(pid, uid, gid, remaining);
                    scm.extend_from_slice(&creds);
                    cred_trunc = t;
                }
                // Append the translated IPv6 ancillary cmsgs after the SCM
                // records, honoring the guest's controllen (overflow → MSG_CTRUNC).
                let ipv6 = received_ipv6_cmsgs.borrow();
                let (ctrl, ipv6_trunc) =
                    build_linux_ipv6_cmsgs(&scm, &ipv6, msg.controllen as usize);
                if !ctrl.is_empty() && memory.write_bytes(msg.control, &ctrl).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                written_controllen = ctrl.len() as u64;
                if scm_trunc || ipv6_trunc || cred_trunc {
                    linux_flags |= crate::linux_abi::LINUX_MSG_CTRUNC;
                }
            }
            // controllen at offset 40, flags at offset 48 in LinuxMsghdr.
            let _ = memory.write_bytes(
                msg_addr + core::mem::offset_of!(LinuxMsghdr, controllen) as u64,
                &written_controllen.to_ne_bytes(),
            );
            let _ = memory.write_bytes(
                msg_addr + core::mem::offset_of!(LinuxMsghdr, flags) as u64,
                &linux_flags.to_ne_bytes(),
            );
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
