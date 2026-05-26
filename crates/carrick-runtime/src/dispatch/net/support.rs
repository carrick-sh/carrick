//! Socket, netlink, fd-set, and epoll helper routines for net dispatch.

use std::collections::VecDeque;

use zerocopy::{FromBytes, IntoBytes};

use super::super::*;

pub(super) fn read_epoll_event(
    memory: &impl GuestMemory,
    address: u64,
) -> Result<LinuxEpollEvent, i32> {
    read_kernel_struct(memory, address)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EpollKqFilters {
    read: bool,
    write: bool,
}

fn epoll_kq_filters(events: u32) -> EpollKqFilters {
    let read = events & (LINUX_EPOLLIN | LINUX_EPOLLRDHUP | LINUX_EPOLLPRI) != 0;
    let write = events & LINUX_EPOLLOUT != 0;
    EpollKqFilters {
        read: read || !write,
        write,
    }
}

/// Build the kqueue change list to register a host-backed fd's epoll interest
/// on the epoll instance's persistent kqueue. EPOLLIN/RDHUP/PRI ride the read
/// filter (EV_EOF on read -> EPOLLRDHUP); EPOLLOUT rides the write filter.
/// EPOLLET -> `EV_CLEAR` (edge); otherwise the filter is level-triggered,
/// exactly matching Linux. `udata` carries the guest fd so a returned event
/// maps straight back. A mask with neither IN nor OUT still arms a read filter
/// so EPOLLHUP/EPOLLERR (which Linux always reports) are still observed.
pub(super) fn epoll_kq_add_changes(
    host_fd: i32,
    guest_fd: i32,
    events: u32,
) -> Vec<crate::darwin_kqueue::Kevent> {
    use crate::darwin_kqueue::Kevent;
    let edge: u16 = if events & LINUX_EPOLLET != 0 {
        libc::EV_CLEAR
    } else {
        0
    };
    let base = libc::EV_ADD | libc::EV_ENABLE | edge;
    let filters = epoll_kq_filters(events);
    let mut changes = Vec::with_capacity(2);
    if filters.read {
        changes.push(Kevent::read(host_fd, base).with_udata(guest_fd));
    }
    if filters.write {
        changes.push(Kevent::write(host_fd, base).with_udata(guest_fd));
    }
    changes
}

fn epoll_kq_removed_filter_changes(
    host_fd: i32,
    old_events: u32,
    new_events: u32,
) -> Vec<crate::darwin_kqueue::Kevent> {
    use crate::darwin_kqueue::Kevent;
    let old = epoll_kq_filters(old_events);
    let new = epoll_kq_filters(new_events);
    let mut changes = Vec::with_capacity(2);
    if old.read && !new.read {
        changes.push(Kevent::read(host_fd, libc::EV_DELETE));
    }
    if old.write && !new.write {
        changes.push(Kevent::write(host_fd, libc::EV_DELETE));
    }
    changes
}

pub(super) fn epoll_kq_delete_removed_filters(
    kqueue: &crate::darwin_kqueue::Kqueue,
    host_fd: i32,
    old_events: u32,
    new_events: u32,
) {
    for change in epoll_kq_removed_filter_changes(host_fd, old_events, new_events) {
        let _ = kqueue.apply(&[change]);
    }
}

/// Remove both filters for a host-backed fd from the epoll instance kqueue.
/// Read and write are deleted in separate `kevent` calls so a missing filter's
/// ENOENT doesn't abort the other (one changelist stops at the first failing
/// entry without `EV_RECEIPT`).
pub(super) fn epoll_kq_delete(kqueue: &crate::darwin_kqueue::Kqueue, host_fd: i32) {
    use crate::darwin_kqueue::Kevent;
    let _ = kqueue.apply(&[Kevent::read(host_fd, libc::EV_DELETE)]);
    let _ = kqueue.apply(&[Kevent::write(host_fd, libc::EV_DELETE)]);
}

pub(super) fn clear_pending_epoll_ready(
    pending_ready: &mut VecDeque<LinuxEpollEvent>,
    guest_fd: i32,
) {
    pending_ready.retain(|event| event.data != guest_fd as u64);
}

pub(super) fn drain_pending_epoll_ready(
    pending_ready: &mut VecDeque<LinuxEpollEvent>,
    max_events: usize,
) -> Vec<LinuxEpollEvent> {
    let take = pending_ready.len().min(max_events);
    pending_ready.drain(..take).collect()
}

pub(super) fn write_epoll_events<M: GuestMemory>(
    memory: &mut M,
    events_address: u64,
    ready: &[LinuxEpollEvent],
) -> Result<DispatchOutcome, DispatchError> {
    let event_size = core::mem::size_of::<LinuxEpollEvent>();
    for (index, event) in ready.iter().enumerate() {
        let offset = index
            .checked_mul(event_size)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
        let address = events_address.checked_add(offset).ok_or(LINUX_EFAULT);
        let Ok(address) = address else {
            return Ok(LINUX_EFAULT.into());
        };
        if write_kernel_struct_raw(memory, address, event).is_err() {
            return Ok(LINUX_EFAULT.into());
        }
    }
    Ok(DispatchOutcome::Returned {
        value: ready.len() as i64,
    })
}

/// Translate one returned kqueue event (from an epoll instance kqueue) to Linux
/// epoll event bits. Direction-sensitive (jiixyj/epoll-shim model): read EOF ->
/// EPOLLRDHUP, write EOF -> EPOLLHUP, `EV_ERROR` or `EV_EOF` carrying a
/// non-zero `fflags` (the socket error) -> EPOLLERR. Returns 0 for non-IO
/// filters (EVFILT_USER), which the caller ignores.
pub(super) fn kevent_to_epoll(ev: crate::darwin_kqueue::Kevent) -> u32 {
    let mut events = 0u32;
    if ev.flags() & libc::EV_ERROR != 0 {
        events |= LINUX_EPOLLERR;
    }
    let eof = ev.flags() & libc::EV_EOF != 0;
    match ev.filter() {
        libc::EVFILT_READ => {
            events |= LINUX_EPOLLIN;
            if eof {
                events |= LINUX_EPOLLRDHUP;
                if ev.fflags() != 0 {
                    events |= LINUX_EPOLLERR;
                }
            }
        }
        libc::EVFILT_WRITE => {
            events |= LINUX_EPOLLOUT;
            if eof {
                events |= LINUX_EPOLLHUP;
                if ev.fflags() != 0 {
                    events |= LINUX_EPOLLERR;
                }
            }
        }
        _ => {}
    }
    events
}

pub(super) fn read_pollfd(memory: &impl GuestMemory, address: u64) -> Result<LinuxPollFd, i32> {
    read_kernel_struct(memory, address)
}

pub(super) fn read_fd_set(
    memory: &impl GuestMemory,
    address: u64,
    nfds: usize,
) -> Result<Vec<u8>, i32> {
    let length = linux_fd_set_len(nfds).ok_or(LINUX_EINVAL)?;
    memory.read_bytes(address, length).map_err(|_| LINUX_EFAULT)
}

pub(super) fn fd_set_contains(fd_set: &[u8], fd: usize) -> bool {
    fd_set
        .get(fd / 8)
        .is_some_and(|byte| byte & (1 << (fd % 8)) != 0)
}

pub(super) fn fd_set_set(fd_set: &mut [u8], fd: usize) {
    if let Some(byte) = fd_set.get_mut(fd / 8) {
        *byte |= 1 << (fd % 8);
    }
}

fn linux_fd_set_len(nfds: usize) -> Option<usize> {
    nfds.checked_add(63)?.checked_div(64)?.checked_mul(8)
}

pub(super) fn linux_to_host_af(family: i32) -> i32 {
    match family {
        LINUX_AF_UNSPEC => libc::AF_UNSPEC,
        LINUX_AF_UNIX => libc::AF_UNIX,
        LINUX_AF_INET => libc::AF_INET,
        LINUX_AF_INET6 => libc::AF_INET6,
        // Linux-only families. macOS doesn't have AF_NETLINK / AF_PACKET;
        // pass through whatever number was given so the host socket()
        // call returns EAFNOSUPPORT naturally.
        _ => family,
    }
}

fn host_to_linux_af(host_family: u16) -> u16 {
    match host_family as i32 {
        libc::AF_UNSPEC => LINUX_AF_UNSPEC as u16,
        libc::AF_UNIX => LINUX_AF_UNIX as u16,
        libc::AF_INET => LINUX_AF_INET as u16,
        libc::AF_INET6 => LINUX_AF_INET6 as u16,
        _ => host_family,
    }
}

pub(super) fn linux_to_host_socktype(t: i32) -> i32 {
    // Linux and macOS agree on the numeric values for the BSD socket
    // types we care about (1=STREAM, 2=DGRAM, 3=RAW, 5=SEQPACKET).
    match t {
        LINUX_SOCK_STREAM => libc::SOCK_STREAM,
        LINUX_SOCK_DGRAM => libc::SOCK_DGRAM,
        LINUX_SOCK_RAW => libc::SOCK_RAW,
        LINUX_SOCK_SEQPACKET => libc::SOCK_SEQPACKET,
        _ => t,
    }
}

/// Parse a Linux `sockaddr_nl` (family(2) pad(2) pid(4) groups(4) = 12 bytes)
/// from guest memory, returning `(nl_pid, nl_groups)`. Missing / short
/// addresses yield zeros (kernel treats pid=0 as "auto-assign").
pub(super) fn read_sockaddr_nl(memory: &impl GuestMemory, addr: u64, addrlen: u32) -> (u32, u32) {
    if addr == 0 || addrlen < 12 {
        return (0, 0);
    }
    match memory.read_bytes(addr, 12) {
        Ok(b) => {
            let pid = u32::from_ne_bytes([b[4], b[5], b[6], b[7]]);
            let groups = u32::from_ne_bytes([b[8], b[9], b[10], b[11]]);
            (pid, groups)
        }
        Err(_) => (0, 0),
    }
}

/// Build a Linux `sockaddr_nl` byte buffer for getsockname / recv source.
pub(super) fn sockaddr_nl_bytes(pid: u32, groups: u32) -> Vec<u8> {
    let mut out = vec![0u8; 12];
    out[0..2].copy_from_slice(&(LINUX_AF_NETLINK as u16).to_ne_bytes());
    // bytes 2..4 are nl_pad (zero)
    out[4..8].copy_from_slice(&pid.to_ne_bytes());
    out[8..12].copy_from_slice(&groups.to_ne_bytes());
    out
}

/// Generic read(2)-style drain of a netlink recv queue into guest memory.
pub(in crate::dispatch) fn drain_netlink_queue(
    memory: &mut impl GuestMemory,
    address: u64,
    length: usize,
    queue: &mut VecDeque<u8>,
) -> DispatchOutcome {
    let take = queue.len().min(length);
    if take == 0 {
        return DispatchOutcome::Returned { value: 0 };
    }
    let chunk: Vec<u8> = queue.drain(..take).collect();
    if memory.write_bytes(address, &chunk).is_err() {
        return DispatchOutcome::errno(LINUX_EFAULT);
    }
    DispatchOutcome::Returned {
        value: chunk.len() as i64,
    }
}

/// Append a 4-byte-aligned rtattr (TLV) to `buf`.
fn push_rtattr(buf: &mut Vec<u8>, rta_type: u16, payload: &[u8]) {
    let rta_len = (std::mem::size_of::<LinuxRtAttr>() + payload.len()) as u16;
    let hdr = LinuxRtAttr { rta_len, rta_type };
    buf.extend_from_slice(hdr.as_bytes());
    buf.extend_from_slice(payload);
    while !buf.len().is_multiple_of(NLMSG_ALIGNTO) {
        buf.push(0);
    }
}

/// Wrap an already-built payload (header struct + attributes) in an
/// `nlmsghdr` and append it to `out`, 4-byte aligned. `nlmsg_len` covers
/// the header plus payload (unaligned, per the kernel).
fn push_nlmsg(out: &mut Vec<u8>, nlmsg_type: u16, seq: u32, pid: u32, payload: &[u8]) {
    let hdr_size = std::mem::size_of::<LinuxNlMsgHdr>();
    let nlmsg_len = (hdr_size + payload.len()) as u32;
    let hdr = LinuxNlMsgHdr {
        nlmsg_len,
        nlmsg_type,
        nlmsg_flags: LINUX_NLM_F_MULTI,
        nlmsg_seq: seq,
        nlmsg_pid: pid,
    };
    out.extend_from_slice(hdr.as_bytes());
    out.extend_from_slice(payload);
    while !out.len().is_multiple_of(NLMSG_ALIGNTO) {
        out.push(0);
    }
}

/// Append a terminating NLMSG_DONE to `out`.
fn push_nlmsg_done(out: &mut Vec<u8>, seq: u32, pid: u32) {
    // NLMSG_DONE carries a 4-byte error/return code payload (0 = success).
    push_nlmsg(out, LINUX_NLMSG_DONE, seq, pid, &0i32.to_ne_bytes());
}

/// Build the synthetic rtnetlink reply for a guest's request. We inspect
/// the leading nlmsghdr's `nlmsg_type`:
///   - RTM_GETLINK  -> one RTM_NEWLINK for `lo`, then NLMSG_DONE
///   - RTM_GETADDR  -> one RTM_NEWADDR for `lo` (127.0.0.1/8), then NLMSG_DONE
///   - anything else -> a bare NLMSG_DONE (the dump is "empty")
///
/// All replies are NLM_F_MULTI dumps terminated by NLMSG_DONE, which is
/// what glibc's __check_pf and `ip` expect.
pub(super) fn build_netlink_reply(request: &[u8], pid: u32) -> Vec<u8> {
    let hdr_size = std::mem::size_of::<LinuxNlMsgHdr>();
    let (req_type, seq) = if request.len() >= hdr_size {
        match LinuxNlMsgHdr::read_from_prefix(request) {
            Ok((h, _)) => (h.nlmsg_type, h.nlmsg_seq),
            Err(_) => (0u16, 0u32),
        }
    } else {
        (0, 0)
    };

    let mut out = Vec::new();
    match req_type {
        LINUX_RTM_GETLINK => {
            let mut payload = Vec::new();
            let ifi = LinuxIfInfoMsg {
                ifi_family: 0, // AF_UNSPEC
                ifi_pad: 0,
                ifi_type: LINUX_ARPHRD_LOOPBACK,
                ifi_index: 1,
                ifi_flags: LINUX_IFF_UP | LINUX_IFF_LOOPBACK | LINUX_IFF_RUNNING,
                ifi_change: 0,
            };
            payload.extend_from_slice(ifi.as_bytes());
            // IFLA_IFNAME is a NUL-terminated string.
            push_rtattr(&mut payload, LINUX_IFLA_IFNAME, b"lo\0");
            // IFLA_ADDRESS: loopback hardware address (6 zero bytes).
            push_rtattr(&mut payload, LINUX_IFLA_ADDRESS, &[0u8; 6]);
            push_nlmsg(&mut out, LINUX_RTM_NEWLINK, seq, pid, &payload);
            push_nlmsg_done(&mut out, seq, pid);
        }
        LINUX_RTM_GETADDR => {
            let mut payload = Vec::new();
            let ifa = LinuxIfAddrMsg {
                ifa_family: LINUX_AF_INET as u8,
                ifa_prefixlen: 8,
                ifa_flags: 0,
                ifa_scope: 254, // RT_SCOPE_HOST
                ifa_index: 1,
            };
            payload.extend_from_slice(ifa.as_bytes());
            let loopback = [127u8, 0, 0, 1];
            push_rtattr(&mut payload, LINUX_IFA_ADDRESS, &loopback);
            push_rtattr(&mut payload, LINUX_IFA_LOCAL, &loopback);
            push_rtattr(&mut payload, LINUX_IFA_LABEL, b"lo\0");
            push_nlmsg(&mut out, LINUX_RTM_NEWADDR, seq, pid, &payload);
            push_nlmsg_done(&mut out, seq, pid);
        }
        _ => {
            // Unmodelled request (e.g. RTM_GETROUTE, RTM_GETNEIGH): return
            // an empty dump so the caller's enumeration loop terminates
            // cleanly rather than blocking.
            push_nlmsg_done(&mut out, seq, pid);
        }
    }
    out
}

pub(super) fn linux_to_host_msg_flags(flags: i32) -> i32 {
    let mut out = 0;
    if flags & LINUX_MSG_OOB != 0 {
        out |= libc::MSG_OOB;
    }
    if flags & LINUX_MSG_PEEK != 0 {
        out |= libc::MSG_PEEK;
    }
    if flags & LINUX_MSG_DONTROUTE != 0 {
        out |= libc::MSG_DONTROUTE;
    }
    if flags & LINUX_MSG_TRUNC != 0 {
        out |= libc::MSG_TRUNC;
    }
    if flags & LINUX_MSG_DONTWAIT != 0 {
        out |= libc::MSG_DONTWAIT;
    }
    if flags & LINUX_MSG_EOR != 0 {
        out |= libc::MSG_EOR;
    }
    if flags & LINUX_MSG_WAITALL != 0 {
        out |= libc::MSG_WAITALL;
    }
    // MSG_NOSIGNAL is Linux-only. macOS expresses the equivalent via
    // SO_NOSIGPIPE on the socket; ignoring the flag is the best we can
    // do here. Likewise MSG_CMSG_CLOEXEC has no macOS equivalent.
    let _ = (LINUX_MSG_NOSIGNAL, LINUX_MSG_CMSG_CLOEXEC);
    out
}

pub(super) fn linux_to_host_sockopt(level: i32, optname: i32) -> Option<(i32, i32)> {
    match level {
        LINUX_SOL_SOCKET => {
            let host_opt = match optname {
                LINUX_SO_DEBUG => libc::SO_DEBUG,
                LINUX_SO_REUSEADDR => libc::SO_REUSEADDR,
                LINUX_SO_TYPE => libc::SO_TYPE,
                LINUX_SO_ERROR => libc::SO_ERROR,
                LINUX_SO_DONTROUTE => libc::SO_DONTROUTE,
                LINUX_SO_BROADCAST => libc::SO_BROADCAST,
                LINUX_SO_SNDBUF => libc::SO_SNDBUF,
                LINUX_SO_RCVBUF => libc::SO_RCVBUF,
                LINUX_SO_KEEPALIVE => libc::SO_KEEPALIVE,
                LINUX_SO_OOBINLINE => libc::SO_OOBINLINE,
                LINUX_SO_LINGER => libc::SO_LINGER,
                LINUX_SO_REUSEPORT => libc::SO_REUSEPORT,
                LINUX_SO_RCVTIMEO => libc::SO_RCVTIMEO,
                LINUX_SO_SNDTIMEO => libc::SO_SNDTIMEO,
                LINUX_SO_ACCEPTCONN => libc::SO_ACCEPTCONN,
                _ => return None,
            };
            Some((libc::SOL_SOCKET, host_opt))
        }
        LINUX_SOL_IP => Some((libc::IPPROTO_IP, optname)),
        LINUX_SOL_TCP => {
            let host_opt = match optname {
                LINUX_TCP_NODELAY => libc::TCP_NODELAY,
                LINUX_TCP_MAXSEG => libc::TCP_MAXSEG,
                LINUX_TCP_CORK => libc::TCP_NOPUSH,
                LINUX_TCP_KEEPIDLE => libc::TCP_KEEPALIVE,
                LINUX_TCP_KEEPINTVL => libc::TCP_KEEPINTVL,
                LINUX_TCP_KEEPCNT => libc::TCP_KEEPCNT,
                _ => return None,
            };
            Some((libc::IPPROTO_TCP, host_opt))
        }
        LINUX_SOL_UDP => Some((libc::IPPROTO_UDP, optname)),
        LINUX_SOL_IPV6 => Some((libc::IPPROTO_IPV6, optname)),
        _ => None,
    }
}

/// Map a guest AF_UNIX *pathname* socket path to a stable host path.
///
/// Under `--fs host` the guest's view of the filesystem is a cap-std
/// sandboxed scratch dir; a guest path like `/tmp/net_bind.sock` is NOT a
/// real host path, and the guest's `unlink` only tombstones a VFS overlay
/// entry - it never touches a real host socket file. If `bind` handed the
/// raw guest path to `libc::bind` the macOS kernel would create the socket
/// at that literal host location, decoupled from the guest's unlink, so a
/// stale socket from a prior run yields EADDRINUSE.
///
/// To keep bind/connect/getsockname consistent (and let the probe's
/// unlink-then-bind work like Linux, with bind clearing any stale node),
/// every pathname socket is deterministically mapped into a single
/// per-run host directory. The mapping is a pure function of the guest
/// path, so a `connect` to the same guest path resolves to the same host
/// socket a prior `bind` created - including across forked children, which
/// inherit the same derivation. macOS `sun_path` is only 104 bytes, so the
/// host name is a short hash rather than the (possibly long) guest path.
///
/// Abstract-namespace sockets (Linux: leading NUL in sun_path) are NOT
/// pathname sockets and are returned unchanged.
fn unix_socket_host_dir() -> std::path::PathBuf {
    // One directory per host boot/run, shared by all forked guest
    // processes. TMPDIR keeps the absolute path short enough for sun_path.
    let base = std::env::temp_dir();
    base.join("carrick-unix-sockets")
}

/// Given the raw guest `sun_path` bytes (everything after the 2-byte
/// family), return the host pathname to bind/connect on, or `None` for an
/// abstract-namespace / autobind address (which we pass through verbatim).
fn unix_socket_host_path(sun_path: &[u8]) -> Option<std::path::PathBuf> {
    // Empty (autobind) or abstract (leading NUL): not a filesystem path.
    if sun_path.is_empty() || sun_path[0] == 0 {
        return None;
    }
    // Pathname socket: bytes up to the first NUL.
    let nul = sun_path
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(sun_path.len());
    let guest_path = &sun_path[..nul];
    if guest_path.is_empty() {
        return None;
    }
    let dir = unix_socket_host_dir();
    let _ = std::fs::create_dir_all(&dir);
    // Short, collision-resistant, deterministic name derived from the guest
    // path so bind and connect agree and the result fits macOS sun_path.
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in guest_path {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let host = dir.join(format!("{hash:016x}.sock"));
    // Record host→guest so getsockname/getpeername/accept can REVERSE-translate:
    // the guest must get back the path it used (not the <hash>.sock host node),
    // or dialing `ln.Addr()` re-hashes the host path → wrong node → ENOENT.
    if let Ok(mut map) = unix_path_registry().lock() {
        map.insert(host.clone(), guest_path.to_vec());
    }
    Some(host)
}

/// Process-global host-socket-path → original-guest-`sun_path` map, populated by
/// `unix_socket_host_path` at every bind/connect/sendto translation and consumed
/// by `host_to_linux_sockaddr` to undo the hash. Process-global (not fork-shared):
/// a socket's own address is recorded by the process that bound/connected it,
/// which is the same process that later calls getsockname/getpeername on it.
fn unix_path_registry() -> &'static std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, Vec<u8>>>
{
    static REG: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, Vec<u8>>>,
    > = std::sync::OnceLock::new();
    REG.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// The original guest `sun_path` bytes for a carrick host socket path, if known.
fn guest_unix_path_for(host_path: &[u8]) -> Option<Vec<u8>> {
    let nul = host_path
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(host_path.len());
    use std::os::unix::ffi::OsStringExt;
    let key = std::path::PathBuf::from(std::ffi::OsString::from_vec(host_path[..nul].to_vec()));
    unix_path_registry().lock().ok()?.get(&key).cloned()
}

/// Translate a Linux-formatted sockaddr (read from guest memory) into the
/// macOS BSD form. Returns the host-formatted bytes ready to hand to
/// libc::bind/connect/sendto.
pub(super) fn read_linux_sockaddr(
    memory: &impl GuestMemory,
    addr: u64,
    addrlen: u32,
    _family_hint: i32,
) -> Result<Vec<u8>, i32> {
    if addr == 0 || addrlen < 2 {
        return Err(LINUX_EINVAL);
    }
    let len = addrlen as usize;
    let bytes = memory.read_bytes(addr, len).map_err(|_| LINUX_EFAULT)?;
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    match family {
        LINUX_AF_INET => {
            // sockaddr_in: family(2) port(2) addr(4) zero(8) = 16 bytes
            if len < 8 {
                return Err(LINUX_EINVAL);
            }
            let mut out = vec![0u8; 16];
            out[0] = 16; // sin_len
            out[1] = libc::AF_INET as u8; // sin_family
            out[2..4].copy_from_slice(&bytes[2..4]); // sin_port (network)
            out[4..8].copy_from_slice(&bytes[4..8]); // sin_addr
            Ok(out)
        }
        LINUX_AF_INET6 => {
            // sockaddr_in6: family(2) port(2) flowinfo(4) addr(16) scope(4) = 28
            if len < 24 {
                return Err(LINUX_EINVAL);
            }
            let mut out = vec![0u8; 28];
            out[0] = 28;
            out[1] = libc::AF_INET6 as u8;
            out[2..4].copy_from_slice(&bytes[2..4]); // port
            out[4..8].copy_from_slice(&bytes[4..8]); // flowinfo
            out[8..24].copy_from_slice(&bytes[8..24]); // addr
            if len >= 28 {
                out[24..28].copy_from_slice(&bytes[24..28]); // scope_id
            }
            Ok(out)
        }
        LINUX_AF_UNIX => {
            // Linux sockaddr_un: family(2) sun_path[108]. macOS sockaddr_un
            // is sun_len(1) sun_family(1) sun_path[104].
            if len < 2 {
                return Err(LINUX_EINVAL);
            }
            let sun_path = &bytes[2..];
            match unix_socket_host_path(sun_path) {
                // Pathname socket: bind/connect on a stable host path so the
                // guest's filesystem view (and its unlink) doesn't have to
                // own the real socket node. See unix_socket_host_path.
                Some(host_path) => {
                    let p = host_path.to_string_lossy();
                    let pbytes = p.as_bytes();
                    // sun_path is fixed-size; macOS allows up to 104 bytes
                    // including the trailing NUL.
                    if pbytes.len() >= 104 {
                        return Err(LINUX_ENAMETOOLONG);
                    }
                    let mut out = vec![0u8; 2 + pbytes.len() + 1];
                    out[0] = out.len().min(255) as u8;
                    out[1] = libc::AF_UNIX as u8;
                    out[2..2 + pbytes.len()].copy_from_slice(pbytes);
                    Ok(out)
                }
                // Abstract / autobind: pass the raw bytes through unchanged.
                None => {
                    let path_len = len.saturating_sub(2);
                    let mut out = vec![0u8; 2 + path_len];
                    out[0] = (2 + path_len).min(255) as u8;
                    out[1] = libc::AF_UNIX as u8;
                    out[2..].copy_from_slice(&bytes[2..2 + path_len]);
                    Ok(out)
                }
            }
        }
        _ => Err(LINUX_EAFNOSUPPORT),
    }
}

/// Translate a macOS BSD sockaddr (as returned by accept/getsockname/...
/// into Linux-formatted bytes suitable for the guest to consume.
pub(super) fn host_to_linux_sockaddr(bytes: &[u8], _family_hint: i32) -> Vec<u8> {
    if bytes.len() < 2 {
        return Vec::new();
    }
    // macOS layout: sa_len(1) sa_family(1) ...
    let host_family = bytes[1] as u16;
    let linux_family = host_to_linux_af(host_family);
    match host_family as i32 {
        libc::AF_INET => {
            // Linux sockaddr_in: family(2) port(2) addr(4) zero(8) = 16
            let mut out = vec![0u8; 16];
            out[0..2].copy_from_slice(&linux_family.to_ne_bytes());
            if bytes.len() >= 8 {
                out[2..4].copy_from_slice(&bytes[2..4]); // port
                out[4..8].copy_from_slice(&bytes[4..8]); // addr
            }
            out
        }
        libc::AF_INET6 => {
            let mut out = vec![0u8; 28];
            out[0..2].copy_from_slice(&linux_family.to_ne_bytes());
            let take = bytes.len().min(28);
            if take > 2 {
                out[2..take].copy_from_slice(&bytes[2..take]);
            }
            out
        }
        libc::AF_UNIX => {
            // Linux sockaddr_un is family(2) path[108]. macOS path starts
            // at offset 2; skip the host's sun_len byte at offset 0.
            let path_len = bytes.len().saturating_sub(2);
            let host_path = &bytes[2..2 + path_len];
            // Reverse the guest→host hash so the guest sees the path IT used (not
            // carrick's <hash>.sock host node). Without this, Go's ln.Addr()
            // reports the host path and re-dialing it double-translates → ENOENT.
            // Unknown host node (e.g. a peer bound by another process): pass the
            // host path through unchanged.
            let path_out = guest_unix_path_for(host_path);
            let path_bytes: &[u8] = path_out.as_deref().unwrap_or(host_path);
            let mut out = vec![0u8; 2 + path_bytes.len()];
            out[0..2].copy_from_slice(&linux_family.to_ne_bytes());
            out[2..].copy_from_slice(path_bytes);
            out
        }
        _ => {
            let mut out = bytes.to_vec();
            if out.len() >= 2 {
                out[0..2].copy_from_slice(&linux_family.to_ne_bytes());
            }
            out
        }
    }
}

/// Write a Linux-formatted sockaddr back into guest memory, respecting
/// the caller's `addrlen` (Linux truncates when the buffer is too small
/// and writes the full required length into `*addrlen_addr`).
pub(super) fn write_linux_sockaddr(
    memory: &mut impl GuestMemory,
    addr: u64,
    addrlen_addr: u64,
    bytes: &[u8],
) -> Result<(), ()> {
    if addrlen_addr == 0 {
        return Err(());
    }
    let cur_bytes = memory.read_bytes(addrlen_addr, 4).map_err(|_| ())?;
    let cur = u32::from_ne_bytes([cur_bytes[0], cur_bytes[1], cur_bytes[2], cur_bytes[3]]) as usize;
    let write_len = cur.min(bytes.len());
    if addr != 0 && write_len > 0 {
        memory
            .write_bytes(addr, &bytes[..write_len])
            .map_err(|_| ())?;
    }
    memory
        .write_bytes(addrlen_addr, &(bytes.len() as u32).to_ne_bytes())
        .map_err(|_| ())
}

pub(super) fn read_linux_msghdr(memory: &impl GuestMemory, addr: u64) -> Result<LinuxMsghdr, i32> {
    read_kernel_struct(memory, addr)
}

/// Direction a blocking I/O syscall waits on, in `libc::poll` event terms.
#[derive(Clone, Copy)]
pub(super) enum IoDir {
    /// recv/read/accept - wait for the fd to become readable.
    Read,
    /// send/write/connect - wait for the fd to become writable.
    Write,
}

impl IoDir {
    pub(super) fn events(self) -> i16 {
        match self {
            IoDir::Read => libc::POLLIN,
            IoDir::Write => libc::POLLOUT,
        }
    }
}

/// Force a host fd into `O_NONBLOCK`. carrick keeps EVERY host-backed fd
/// non-blocking and emulates the guest's blocking mode itself via
/// `blocking_io` + the runtime's lockless `WaitOnFds` wait, so a guest blocking
/// syscall never blocks a vCPU thread inside libc while the dispatcher lock is
/// held. Call at every host-fd creation site (socket/socketpair/accept/pipe).
pub(in crate::dispatch) fn set_host_nonblocking(fd: i32) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 && flags & libc::O_NONBLOCK == 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_family_translation_covers_bsd_families_and_passthrough() {
        assert_eq!(linux_to_host_af(LINUX_AF_UNSPEC), libc::AF_UNSPEC);
        assert_eq!(linux_to_host_af(LINUX_AF_UNIX), libc::AF_UNIX);
        assert_eq!(linux_to_host_af(LINUX_AF_INET), libc::AF_INET);
        assert_eq!(linux_to_host_af(LINUX_AF_INET6), libc::AF_INET6);
        assert_eq!(linux_to_host_af(12345), 12345);

        assert_eq!(
            host_to_linux_af(libc::AF_UNSPEC as u16),
            LINUX_AF_UNSPEC as u16
        );
        assert_eq!(host_to_linux_af(libc::AF_UNIX as u16), LINUX_AF_UNIX as u16);
        assert_eq!(host_to_linux_af(libc::AF_INET as u16), LINUX_AF_INET as u16);
        assert_eq!(
            host_to_linux_af(libc::AF_INET6 as u16),
            LINUX_AF_INET6 as u16
        );
        assert_eq!(host_to_linux_af(54321), 54321);
    }

    #[test]
    fn message_flag_translation_maps_supported_flags_and_ignores_linux_only_flags() {
        let flags = LINUX_MSG_OOB
            | LINUX_MSG_PEEK
            | LINUX_MSG_DONTROUTE
            | LINUX_MSG_TRUNC
            | LINUX_MSG_DONTWAIT
            | LINUX_MSG_EOR
            | LINUX_MSG_WAITALL
            | LINUX_MSG_NOSIGNAL
            | LINUX_MSG_CMSG_CLOEXEC;

        let host = linux_to_host_msg_flags(flags);
        assert_eq!(host & libc::MSG_OOB, libc::MSG_OOB);
        assert_eq!(host & libc::MSG_PEEK, libc::MSG_PEEK);
        assert_eq!(host & libc::MSG_DONTROUTE, libc::MSG_DONTROUTE);
        assert_eq!(host & libc::MSG_TRUNC, libc::MSG_TRUNC);
        assert_eq!(host & libc::MSG_DONTWAIT, libc::MSG_DONTWAIT);
        assert_eq!(host & libc::MSG_EOR, libc::MSG_EOR);
        assert_eq!(host & libc::MSG_WAITALL, libc::MSG_WAITALL);
        assert_eq!(
            host & !(libc::MSG_OOB
                | libc::MSG_PEEK
                | libc::MSG_DONTROUTE
                | libc::MSG_TRUNC
                | libc::MSG_DONTWAIT
                | libc::MSG_EOR
                | libc::MSG_WAITALL),
            0
        );
    }

    #[test]
    fn ipv4_sockaddr_round_trips_between_linux_and_host_layouts() {
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let addr = 0x1100;
        let mut linux = vec![0u8; 16];
        linux[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
        linux[2..4].copy_from_slice(&8080u16.to_be_bytes());
        linux[4..8].copy_from_slice(&[127, 0, 0, 1]);
        memory.write_bytes(addr, &linux).unwrap();

        let host = read_linux_sockaddr(&memory, addr, linux.len() as u32, LINUX_AF_INET).unwrap();
        assert_eq!(host[0], 16);
        assert_eq!(host[1], libc::AF_INET as u8);
        assert_eq!(&host[2..8], &linux[2..8]);

        let round_trip = host_to_linux_sockaddr(&host, LINUX_AF_INET);
        assert_eq!(round_trip, linux);
    }

    #[test]
    fn write_linux_sockaddr_truncates_to_guest_buffer_and_reports_required_len() {
        let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let addr = 0x1100;
        let addrlen_addr = 0x1200;
        memory
            .write_bytes(addrlen_addr, &4u32.to_ne_bytes())
            .unwrap();

        let mut linux = vec![0u8; 16];
        linux[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
        linux[2..4].copy_from_slice(&8080u16.to_be_bytes());
        linux[4..8].copy_from_slice(&[127, 0, 0, 1]);

        write_linux_sockaddr(&mut memory, addr, addrlen_addr, &linux).unwrap();

        assert_eq!(memory.read_bytes(addr, 4).unwrap(), linux[..4]);
        let required = memory.read_bytes(addrlen_addr, 4).unwrap();
        assert_eq!(u32::from_ne_bytes(required.try_into().unwrap()), 16);
    }

    #[test]
    fn epoll_kqueue_filter_selection_preserves_hup_err_observability() {
        assert_eq!(
            epoll_kq_filters(0),
            EpollKqFilters {
                read: true,
                write: false,
            }
        );
        assert_eq!(
            epoll_kq_filters(LINUX_EPOLLIN),
            EpollKqFilters {
                read: true,
                write: false,
            }
        );
        assert_eq!(
            epoll_kq_filters(LINUX_EPOLLOUT),
            EpollKqFilters {
                read: false,
                write: true,
            }
        );
        assert_eq!(
            epoll_kq_filters(LINUX_EPOLLIN | LINUX_EPOLLOUT),
            EpollKqFilters {
                read: true,
                write: true,
            }
        );
    }

    #[test]
    fn epoll_mod_delete_list_contains_only_filters_removed_by_new_mask() {
        let removed =
            epoll_kq_removed_filter_changes(42, LINUX_EPOLLIN | LINUX_EPOLLOUT, LINUX_EPOLLOUT);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].filter(), libc::EVFILT_READ);

        let removed =
            epoll_kq_removed_filter_changes(42, LINUX_EPOLLIN | LINUX_EPOLLOUT, LINUX_EPOLLIN);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].filter(), libc::EVFILT_WRITE);

        assert!(epoll_kq_removed_filter_changes(42, LINUX_EPOLLIN, LINUX_EPOLLIN).is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_socket_install_forces_host_nonblocking_even_for_blocking_guest_fd() {
        let dispatcher = SyscallDispatcher::new();
        let outcome = dispatcher.host_socket_install(LINUX_AF_INET, LINUX_SOCK_STREAM, 0);
        let linux_fd = match outcome {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("socket install failed: {other:?}"),
        };

        assert_eq!(
            dispatcher.fd_status_flags(linux_fd) & LINUX_O_NONBLOCK,
            0,
            "Linux-visible fd status must preserve blocking mode",
        );
        let host_fd = dispatcher.host_fd_for_poll(linux_fd).unwrap();
        let flags = unsafe { libc::fcntl(host_fd, libc::F_GETFL) };
        assert!(
            flags >= 0 && flags & libc::O_NONBLOCK != 0,
            "host fd must be nonblocking for dispatcher wait invariants",
        );
    }
}
