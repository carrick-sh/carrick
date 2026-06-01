//! Socket, netlink, fd-set, and epoll helper routines for net dispatch.

use std::collections::VecDeque;

use zerocopy::{FromBytes, IntoBytes};

use super::super::*;
use crate::linux_abi::{
    LINUX_ARPHRD_ETHER, LINUX_IFF_BROADCAST, LINUX_IFF_MULTICAST, LINUX_IFF_POINTOPOINT,
    LINUX_RT_SCOPE_HOST, LINUX_RT_SCOPE_LINK, LINUX_RT_SCOPE_UNIVERSE, LINUX_RT_TABLE_MAIN,
    LINUX_RTA_DST, LINUX_RTA_OIF, LINUX_RTM_GETNEIGH, LINUX_RTM_GETROUTE, LINUX_RTM_NEWROUTE,
    LINUX_RTN_UNICAST, LINUX_RTPROT_KERNEL, LinuxRtMsg,
};

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
    priority: bool,
}

fn epoll_kq_filters(events: u32) -> EpollKqFilters {
    let read = events & (LINUX_EPOLLIN | LINUX_EPOLLRDHUP | LINUX_EPOLLPRI) != 0;
    let write = events & LINUX_EPOLLOUT != 0;
    let priority = events & LINUX_EPOLLPRI != 0;
    EpollKqFilters {
        read: read || !write,
        write,
        priority,
    }
}

/// Build the kqueue change list to register a host-backed fd's epoll interest
/// on the epoll instance's persistent kqueue. EPOLLIN/RDHUP ride the read
/// filter (EV_EOF on read -> EPOLLRDHUP); EPOLLOUT rides the write filter;
/// EPOLLPRI rides Darwin's exceptional-condition filter with NOTE_OOB.
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
    let mut changes = Vec::with_capacity(3);
    if filters.read {
        changes.push(Kevent::read(host_fd, base).with_udata(guest_fd));
    }
    if filters.write {
        changes.push(Kevent::write(host_fd, base).with_udata(guest_fd));
    }
    if filters.priority {
        changes.push(Kevent::oob(host_fd, base).with_udata(guest_fd));
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
    let mut changes = Vec::with_capacity(3);
    if old.read && !new.read {
        changes.push(Kevent::read(host_fd, libc::EV_DELETE));
    }
    if old.write && !new.write {
        changes.push(Kevent::write(host_fd, libc::EV_DELETE));
    }
    if old.priority && !new.priority {
        changes.push(Kevent::oob(host_fd, libc::EV_DELETE));
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
    let _ = kqueue.apply(&[Kevent::oob(host_fd, libc::EV_DELETE)]);
}

pub(super) fn clear_pending_epoll_ready(
    pending_ready: &mut VecDeque<(i32, LinuxEpollEvent)>,
    guest_fd: i32,
) {
    // Purge by the ORIGINATING guest fd, not the epoll_data token (which the
    // guest can set to anything != fd). (audit M3; probe epollstaledel)
    pending_ready.retain(|(fd, _event)| *fd != guest_fd);
}

pub(super) fn drain_pending_epoll_ready(
    pending_ready: &mut VecDeque<(i32, LinuxEpollEvent)>,
    max_events: usize,
) -> Vec<LinuxEpollEvent> {
    let take = pending_ready.len().min(max_events);
    pending_ready
        .drain(..take)
        .map(|(_fd, event)| event)
        .collect()
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
        filter
            if filter == crate::darwin_kqueue::EVFILT_EXCEPT
                && ev.fflags() & crate::darwin_kqueue::NOTE_OOB != 0 =>
        {
            events |= LINUX_EPOLLPRI;
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

/// The host socket type to actually create for a guest `(family, base_type)`.
/// macOS has no AF_UNIX `SOCK_SEQPACKET`, so back it with a `SOCK_STREAM` socket;
/// carrick frames messages on top to recover SEQPACKET boundary semantics (see
/// `OpenDescription::HostSocket.seqpacket`). Everything else maps 1:1.
pub(super) fn host_socktype_backing(family: i32, base_type: i32) -> i32 {
    if family == LINUX_AF_UNIX && base_type == LINUX_SOCK_SEQPACKET {
        return libc::SOCK_STREAM;
    }
    linux_to_host_socktype(base_type)
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

/// One host network interface, in Linux-shaped terms.
struct HostIface {
    name: String,
    index: u32,
    arphrd: u16,
    linux_flags: u32,
    hw_addr: Vec<u8>,
}

/// One host interface address (IPv4 or IPv6), in Linux-shaped terms.
struct HostAddr {
    index: u32,
    name: String,
    family: u8, // LINUX_AF_INET / LINUX_AF_INET6
    addr: Vec<u8>,
    prefixlen: u8,
    scope: u8,
}

/// Count the leading set bits of a netmask's raw address bytes (the CIDR
/// prefix length). macOS gives the mask as a sockaddr; we count across its
/// address octets.
fn prefix_len_from_mask(bytes: &[u8]) -> u8 {
    let mut n = 0u8;
    for &b in bytes {
        n += b.count_ones() as u8;
    }
    n
}

/// macOS interface flags -> Linux IFF_* flags.
fn linux_iff_flags(mac: u32) -> u32 {
    let mut out = 0;
    if mac & (libc::IFF_UP as u32) != 0 {
        out |= LINUX_IFF_UP;
    }
    if mac & (libc::IFF_BROADCAST as u32) != 0 {
        out |= LINUX_IFF_BROADCAST;
    }
    if mac & (libc::IFF_LOOPBACK as u32) != 0 {
        out |= LINUX_IFF_LOOPBACK;
    }
    if mac & (libc::IFF_POINTOPOINT as u32) != 0 {
        out |= LINUX_IFF_POINTOPOINT;
    }
    if mac & (libc::IFF_RUNNING as u32) != 0 {
        out |= LINUX_IFF_RUNNING;
    }
    if mac & (libc::IFF_MULTICAST as u32) != 0 {
        out |= LINUX_IFF_MULTICAST;
    }
    out
}

/// Enumerate the host's interfaces + addresses via macOS `getifaddrs(3)` and
/// translate them to Linux-shaped records, so the synthetic rtnetlink reports
/// the REAL interfaces (all of them, IPv4 + IPv6) rather than a fixed loopback.
/// Empty on failure (caller falls back to a synthetic loopback).
fn host_interfaces() -> (Vec<HostIface>, Vec<HostAddr>) {
    let mut ifaces: Vec<HostIface> = Vec::new();
    let mut addrs: Vec<HostAddr> = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list we free via freeifaddrs below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        return (ifaces, addrs);
    }
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a valid node for the duration of this iteration.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated C string owned by the list.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: if_nametoindex on a known name.
        let index = {
            let c = std::ffi::CString::new(name.clone()).unwrap_or_default();
            unsafe { libc::if_nametoindex(c.as_ptr()) }
        };
        let mac_flags = ifa.ifa_flags;
        let is_loopback = mac_flags & (libc::IFF_LOOPBACK as u32) != 0;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_addr points at a sockaddr whose sa_family selects the type.
        let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
        match family {
            libc::AF_LINK => {
                // One interface record per AF_LINK entry (carries the index + hw).
                // SAFETY: AF_LINK sockaddr is a sockaddr_dl.
                let dl = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_dl) };
                let nlen = dl.sdl_nlen as usize;
                let alen = dl.sdl_alen as usize;
                let mut hw = Vec::new();
                if alen > 0 && nlen + alen <= dl.sdl_data.len() {
                    hw = dl.sdl_data[nlen..nlen + alen]
                        .iter()
                        .map(|&c| c as u8)
                        .collect();
                }
                let idx = if index != 0 {
                    index
                } else {
                    dl.sdl_index as u32
                };
                ifaces.push(HostIface {
                    name,
                    index: idx,
                    arphrd: if is_loopback {
                        LINUX_ARPHRD_LOOPBACK
                    } else {
                        LINUX_ARPHRD_ETHER
                    },
                    linux_flags: linux_iff_flags(mac_flags),
                    hw_addr: hw,
                });
            }
            libc::AF_INET => {
                // SAFETY: AF_INET sockaddr is a sockaddr_in.
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                let addr = sin.sin_addr.s_addr.to_ne_bytes().to_vec();
                let prefixlen = if ifa.ifa_netmask.is_null() {
                    32
                } else {
                    // SAFETY: netmask sockaddr_in.
                    let m = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) };
                    prefix_len_from_mask(&m.sin_addr.s_addr.to_ne_bytes())
                };
                addrs.push(HostAddr {
                    index,
                    name,
                    family: LINUX_AF_INET as u8,
                    addr,
                    prefixlen,
                    scope: if is_loopback {
                        LINUX_RT_SCOPE_HOST
                    } else {
                        LINUX_RT_SCOPE_UNIVERSE
                    },
                });
            }
            libc::AF_INET6 => {
                // SAFETY: AF_INET6 sockaddr is a sockaddr_in6.
                let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                let mut a = sin6.sin6_addr.s6_addr;
                // Link-local (fe80::/10): macOS embeds the scope id in bytes 2-3.
                // Linux carries scope separately, so zero them for the guest view.
                let link_local = a[0] == 0xfe && (a[1] & 0xc0) == 0x80;
                if link_local {
                    a[2] = 0;
                    a[3] = 0;
                }
                let prefixlen = if ifa.ifa_netmask.is_null() {
                    128
                } else {
                    // SAFETY: netmask sockaddr_in6.
                    let m = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in6) };
                    prefix_len_from_mask(&m.sin6_addr.s6_addr)
                };
                let scope = if is_loopback {
                    LINUX_RT_SCOPE_HOST
                } else if link_local {
                    LINUX_RT_SCOPE_LINK
                } else {
                    LINUX_RT_SCOPE_UNIVERSE
                };
                addrs.push(HostAddr {
                    index,
                    name,
                    family: LINUX_AF_INET6 as u8,
                    addr: a.to_vec(),
                    prefixlen,
                    scope,
                });
            }
            _ => {}
        }
    }
    // SAFETY: free the list getifaddrs allocated.
    unsafe { libc::freeifaddrs(head) };
    (ifaces, addrs)
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

    // Enumerate the real host interfaces/addresses. Fall back to a synthetic
    // loopback if getifaddrs yields nothing (keeps `lo` always present).
    let (mut ifaces, mut addrs) = host_interfaces();
    if ifaces.is_empty() {
        ifaces.push(HostIface {
            name: "lo".to_owned(),
            index: 1,
            arphrd: LINUX_ARPHRD_LOOPBACK,
            linux_flags: LINUX_IFF_UP | LINUX_IFF_LOOPBACK | LINUX_IFF_RUNNING,
            hw_addr: vec![0u8; 6],
        });
    }
    if addrs.is_empty() {
        addrs.push(HostAddr {
            index: 1,
            name: "lo".to_owned(),
            family: LINUX_AF_INET as u8,
            addr: vec![127, 0, 0, 1],
            prefixlen: 8,
            scope: LINUX_RT_SCOPE_HOST,
        });
    }

    let mut out = Vec::new();
    match req_type {
        LINUX_RTM_GETLINK => {
            for iface in &ifaces {
                let mut payload = Vec::new();
                let ifi = LinuxIfInfoMsg {
                    ifi_family: 0, // AF_UNSPEC
                    ifi_pad: 0,
                    ifi_type: iface.arphrd,
                    ifi_index: iface.index as i32,
                    ifi_flags: iface.linux_flags,
                    ifi_change: 0,
                };
                payload.extend_from_slice(ifi.as_bytes());
                let mut name = iface.name.clone().into_bytes();
                name.push(0);
                push_rtattr(&mut payload, LINUX_IFLA_IFNAME, &name);
                if !iface.hw_addr.is_empty() {
                    push_rtattr(&mut payload, LINUX_IFLA_ADDRESS, &iface.hw_addr);
                }
                push_nlmsg(&mut out, LINUX_RTM_NEWLINK, seq, pid, &payload);
            }
            push_nlmsg_done(&mut out, seq, pid);
        }
        LINUX_RTM_GETADDR => {
            for a in &addrs {
                let mut payload = Vec::new();
                let ifa = LinuxIfAddrMsg {
                    ifa_family: a.family,
                    ifa_prefixlen: a.prefixlen,
                    ifa_flags: 0,
                    ifa_scope: a.scope,
                    ifa_index: a.index,
                };
                payload.extend_from_slice(ifa.as_bytes());
                push_rtattr(&mut payload, LINUX_IFA_ADDRESS, &a.addr);
                push_rtattr(&mut payload, LINUX_IFA_LOCAL, &a.addr);
                let mut label = a.name.clone().into_bytes();
                label.push(0);
                push_rtattr(&mut payload, LINUX_IFA_LABEL, &label);
                push_nlmsg(&mut out, LINUX_RTM_NEWADDR, seq, pid, &payload);
            }
            push_nlmsg_done(&mut out, seq, pid);
        }
        LINUX_RTM_GETROUTE => {
            // One connected route per address: the network it sits on, via its
            // interface. `ip route` and Go's net route enumeration expect at
            // least the loopback route; addresses with prefixlen 0 (a bare host
            // address with no network) are skipped.
            for a in &addrs {
                if a.prefixlen == 0 {
                    continue;
                }
                let mut payload = Vec::new();
                let rtm = LinuxRtMsg {
                    rtm_family: a.family,
                    rtm_dst_len: a.prefixlen,
                    rtm_src_len: 0,
                    rtm_tos: 0,
                    rtm_table: LINUX_RT_TABLE_MAIN,
                    rtm_protocol: LINUX_RTPROT_KERNEL,
                    rtm_scope: a.scope,
                    rtm_type: LINUX_RTN_UNICAST,
                    rtm_flags: 0,
                };
                payload.extend_from_slice(rtm.as_bytes());
                push_rtattr(
                    &mut payload,
                    LINUX_RTA_DST,
                    &masked_network(&a.addr, a.prefixlen),
                );
                push_rtattr(&mut payload, LINUX_RTA_OIF, &(a.index).to_ne_bytes());
                push_nlmsg(&mut out, LINUX_RTM_NEWROUTE, seq, pid, &payload);
            }
            push_nlmsg_done(&mut out, seq, pid);
        }
        LINUX_RTM_GETNEIGH => {
            // No synthetic neighbour (ARP/NDP) entries — an empty-but-valid dump,
            // which is what `ip neigh` shows on a freshly-started host too.
            push_nlmsg_done(&mut out, seq, pid);
        }
        _ => {
            // Any other unmodelled request: a bare NLMSG_DONE so the caller's
            // enumeration loop terminates cleanly rather than blocking.
            push_nlmsg_done(&mut out, seq, pid);
        }
    }
    out
}

/// Mask an IPv4/IPv6 address down to its network prefix (`addr & netmask`), so
/// an RTM_NEWROUTE's RTA_DST carries the network rather than the host address.
fn masked_network(addr: &[u8], prefixlen: u8) -> Vec<u8> {
    let mut net = addr.to_vec();
    let prefix = prefixlen as usize;
    for (i, byte) in net.iter_mut().enumerate() {
        let bit_start = i * 8;
        if bit_start >= prefix {
            *byte = 0;
        } else if bit_start + 8 > prefix {
            let keep = prefix - bit_start; // high `keep` bits stay set
            *byte &= 0xFFu8 << (8 - keep);
        }
    }
    net
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

/// Translate host (macOS/BSD) msg_flags returned by recvmsg back into the
/// Linux numeric space the guest expects. Only the output flags recvmsg can
/// set are mapped; bit positions differ between Linux and Darwin.
pub(super) fn host_to_linux_msg_flags(flags: i32) -> i32 {
    let mut out = 0;
    if flags & libc::MSG_OOB != 0 {
        out |= LINUX_MSG_OOB; // host 0x1 -> linux 0x1
    }
    if flags & libc::MSG_EOR != 0 {
        out |= LINUX_MSG_EOR; // host 0x8 -> linux 0x80
    }
    if flags & libc::MSG_TRUNC != 0 {
        out |= LINUX_MSG_TRUNC; // host 0x10 -> linux 0x20
    }
    if flags & libc::MSG_CTRUNC != 0 {
        out |= LINUX_MSG_CTRUNC; // host 0x20 -> linux 0x8
    }
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
        // IPPROTO_IP options: Linux and macOS use DIFFERENT numbers, so translate
        // explicitly (macOS values from <netinet/in.h>; the libc crate is missing
        // several, hence literals). Unknown options pass through (best-effort).
        // Constants are fully-qualified so a missing import can't silently become
        // a catch-all binding that mis-maps everything.
        LINUX_SOL_IP => {
            use crate::linux_abi as a;
            let host_opt = match optname {
                a::LINUX_IP_OPTIONS => 1,
                a::LINUX_IP_HDRINCL => 2,
                a::LINUX_IP_TOS => 3,
                a::LINUX_IP_TTL => 4,
                a::LINUX_IP_MULTICAST_IF => 9,
                a::LINUX_IP_MULTICAST_TTL => 10,
                a::LINUX_IP_MULTICAST_LOOP => 11,
                a::LINUX_IP_ADD_MEMBERSHIP => 12,
                a::LINUX_IP_DROP_MEMBERSHIP => 13,
                a::LINUX_IP_RECVTTL => 24,
                a::LINUX_IP_PKTINFO => 26,
                a::LINUX_IP_RECVTOS => 27,
                other => other,
            };
            Some((libc::IPPROTO_IP, host_opt))
        }
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
        // IPPROTO_IPV6 options: same story (macOS <netinet6/in6.h>).
        LINUX_SOL_IPV6 => {
            use crate::linux_abi as a;
            let host_opt = match optname {
                a::LINUX_IPV6_UNICAST_HOPS => 4,
                a::LINUX_IPV6_MULTICAST_IF => 9,
                a::LINUX_IPV6_MULTICAST_HOPS => 10,
                a::LINUX_IPV6_MULTICAST_LOOP => 11,
                a::LINUX_IPV6_JOIN_GROUP => 12,
                a::LINUX_IPV6_LEAVE_GROUP => 13,
                a::LINUX_IPV6_V6ONLY => 27,
                a::LINUX_IPV6_RECVTCLASS => 35,
                a::LINUX_IPV6_TCLASS => 36,
                a::LINUX_IPV6_RECVHOPLIMIT => 37,
                a::LINUX_IPV6_PKTINFO => 46,
                a::LINUX_IPV6_HOPLIMIT => 47,
                a::LINUX_IPV6_RECVPKTINFO => 61,
                other => other,
            };
            Some((libc::IPPROTO_IPV6, host_opt))
        }
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
    // Empty: autobind — a unique name must be generated and remembered per
    // socket, which happens at bind() (`autobind_unix`), not here.
    if sun_path.is_empty() {
        return None;
    }
    let dir = unix_socket_host_dir();
    // ABSTRACT namespace (leading NUL): the name is the LENGTH-delimited bytes
    // after the NUL — it may contain NULs and is NOT NUL-terminated. macOS has no
    // abstract namespace, so map it to a dedicated `abstract/` host subdir.
    // PATHNAME sockets use the bytes up to the first NUL, in the base dir.
    let abstract_ns = sun_path[0] == 0;
    let (key, base): (&[u8], std::path::PathBuf) = if abstract_ns {
        (&sun_path[1..], dir.join("abstract"))
    } else {
        let nul = sun_path
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(sun_path.len());
        (&sun_path[..nul], dir)
    };
    if key.is_empty() {
        return None;
    }
    let _ = std::fs::create_dir_all(&base);
    // Short, collision-resistant, deterministic name derived from the abstract
    // name / path so bind and connect agree and the result fits macOS sun_path
    // (constant length even for a long abstract name).
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in key {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let host = base.join(format!("{hash:016x}.sock"));
    // Record host→guest so getsockname/getpeername/accept REVERSE-translate to
    // exactly what the guest used: the abstract form (leading NUL + name) or the
    // pathname (no trailing NUL) — else a peer re-translating ln.Addr() misses.
    let stored: Vec<u8> = if abstract_ns {
        sun_path.to_vec()
    } else {
        key.to_vec()
    };
    if let Ok(mut map) = unix_path_registry().lock() {
        map.insert(host.clone(), stored);
    }
    Some(host)
}

/// AF_UNIX autobind: an empty bind address asks the kernel to assign a unique
/// abstract name (Linux: NUL + 5 hex digits). macOS has neither autobind nor an
/// abstract namespace, so generate that name ourselves, map it to a host node
/// (like any abstract socket), register it for getsockname reverse-translation,
/// and return the host path to `bind`.
pub(super) fn autobind_unix_host_path() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static CTR: AtomicU32 = AtomicU32::new(1);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    // Abstract sun_path: leading NUL + 5 hex digits, exactly as Linux autobind.
    let name = format!("{:05x}", n & 0xf_ffff);
    let mut sun: Vec<u8> = vec![0];
    sun.extend_from_slice(name.as_bytes());
    let base = unix_socket_host_dir().join("abstract");
    let _ = std::fs::create_dir_all(&base);
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in &sun[1..] {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let host = base.join(format!("{hash:016x}.sock"));
    if let Ok(mut map) = unix_path_registry().lock() {
        map.insert(host.clone(), sun);
    }
    host
}

/// Process-global host-socket-path → original-guest-`sun_path` map, populated by
/// `unix_socket_host_path` at every bind/connect/sendto translation and consumed
/// by `host_to_linux_sockaddr` to undo the hash. Process-global (not fork-shared):
/// a socket's own address is recorded by the process that bound/connected it,
/// which is the same process that later calls getsockname/getpeername on it.
fn unix_path_registry()
-> &'static std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, Vec<u8>>> {
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
pub(in crate::dispatch) fn read_linux_sockaddr(
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
        LINUX_AF_UNSPEC => {
            // connect(AF_UNSPEC) dissolves a connected UDP socket's association
            // (disconnect); Linux returns 0. Hand the host a 16-byte AF_UNSPEC
            // sockaddr — macOS connect() disconnects on AF_UNSPEC too (it may
            // then report EAFNOSUPPORT/EINVAL after disassociating, which the
            // connect() handler maps to success).
            let mut out = vec![0u8; 16];
            out[0] = 16; // sa_len
            out[1] = libc::AF_UNSPEC as u8; // 0
            Ok(out)
        }
        _ => Err(LINUX_EAFNOSUPPORT),
    }
}

/// Translate a macOS BSD sockaddr (as returned by accept/getsockname/...
/// into Linux-formatted bytes suitable for the guest to consume.
/// Translate a macOS BSD sockaddr to Linux form. `unnamed_unspec` selects the
/// behaviour for an UNNAMED AF_UNIX address (empty path): a datagram *peer
/// source* (recvfrom/recvmsg) wants AF_UNSPEC/empty so Go reports `from == nil`;
/// a *local/connection* address (getsockname/getpeername/accept) wants a
/// family-only AF_UNIX sockaddr so Go reports a non-nil `&UnixAddr{Name:""}`.
pub(super) fn host_to_linux_sockaddr(
    bytes: &[u8],
    _family_hint: i32,
    unnamed_unspec: bool,
) -> Vec<u8> {
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
            // An UNNAMED sender (unbound unix/unixgram socket) → macOS reports an
            // empty/zero-filled path. Return an EMPTY sockaddr (length 0): Linux
            // reports AF_UNSPEC/len-0 for this, and Go only treats a source as
            // "no address" (nil) when the family is AF_UNSPEC — a family-only
            // AF_UNIX reply would be misread via sun_path[0]==0 as the abstract
            // address "@". Trim at the first NUL (pathname host paths are C strings).
            let nul = host_path
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(host_path.len());
            if nul == 0 {
                if unnamed_unspec {
                    return Vec::new();
                }
                let mut out = vec![0u8; 2];
                out[0..2].copy_from_slice(&linux_family.to_ne_bytes());
                return out;
            }
            // Reverse the guest→host hash so the guest sees the path/abstract name
            // IT used (not carrick's <hash>.sock host node); an unknown host node
            // (a peer bound by another process) passes the host path through.
            let path_out = guest_unix_path_for(&host_path[..nul]);
            let path_bytes: &[u8] = path_out.as_deref().unwrap_or(&host_path[..nul]);
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

fn linux_cmsg_align(n: usize) -> usize {
    n.div_ceil(LINUX_CMSG_ALIGN) * LINUX_CMSG_ALIGN
}

/// Parse a GUEST (Linux-layout) `msg_control` buffer and return the i32 file
/// descriptors carried by every `SCM_RIGHTS` (SOL_SOCKET) ancillary record.
/// The Linux `cmsghdr` is `{ u64 cmsg_len; i32 cmsg_level; i32 cmsg_type; }`
/// followed by `CMSG_ALIGN(16)`-padded data; `cmsg_len` counts the header +
/// data (excluding trailing alignment). Non-SCM_RIGHTS records are ignored.
pub(in crate::dispatch) fn parse_linux_scm_rights_fds(control: &[u8]) -> Vec<i32> {
    let mut fds = Vec::new();
    let mut off = 0usize;
    while off + LINUX_CMSGHDR_LEN <= control.len() {
        let cmsg_len =
            u64::from_ne_bytes(control[off..off + 8].try_into().unwrap_or([0; 8])) as usize;
        let level = i32::from_ne_bytes(control[off + 8..off + 12].try_into().unwrap_or([0; 4]));
        let ctype = i32::from_ne_bytes(control[off + 12..off + 16].try_into().unwrap_or([0; 4]));
        // A malformed/zero cmsg_len would loop forever; bail.
        if cmsg_len < LINUX_CMSGHDR_LEN || off + cmsg_len > control.len() {
            break;
        }
        if level == LINUX_SOL_SOCKET && ctype == LINUX_SCM_RIGHTS {
            let data = &control[off + LINUX_CMSGHDR_LEN..off + cmsg_len];
            for chunk in data.chunks_exact(4) {
                fds.push(i32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
        }
        off += linux_cmsg_align(cmsg_len);
    }
    fds
}

/// Build a GUEST (Linux-layout) `msg_control` buffer carrying a single
/// `SCM_RIGHTS` record with `fds`, clamped to `cap` bytes (the guest's
/// `msg_controllen`). Returns `(buffer, truncated)`; `truncated` is true iff
/// `cap` couldn't hold the whole record (the caller sets `MSG_CTRUNC`). Only as
/// many whole fds as fit are emitted (Linux drops the rest and sets MSG_CTRUNC).
pub(in crate::dispatch) fn build_linux_scm_rights(fds: &[i32], cap: usize) -> (Vec<u8>, bool) {
    if fds.is_empty() {
        return (Vec::new(), false);
    }
    // How many fds fit after the 16-byte header within `cap`.
    let max_fds = cap.saturating_sub(LINUX_CMSGHDR_LEN) / 4;
    let n = fds.len().min(max_fds);
    let truncated = n < fds.len() || cap < LINUX_CMSGHDR_LEN;
    if n == 0 {
        return (Vec::new(), truncated);
    }
    let data_len = n * 4;
    let cmsg_len = LINUX_CMSGHDR_LEN + data_len;
    let total = linux_cmsg_align(cmsg_len);
    let mut buf = vec![0u8; total];
    buf[0..8].copy_from_slice(&(cmsg_len as u64).to_ne_bytes());
    buf[8..12].copy_from_slice(&LINUX_SOL_SOCKET.to_ne_bytes());
    buf[12..16].copy_from_slice(&LINUX_SCM_RIGHTS.to_ne_bytes());
    for (i, &fd) in fds[..n].iter().enumerate() {
        let p = LINUX_CMSGHDR_LEN + i * 4;
        buf[p..p + 4].copy_from_slice(&fd.to_ne_bytes());
    }
    (buf, truncated)
}

/// IPPROTO_IPV6 socket level — 41 on BOTH macOS and Linux (only the per-option
/// TYPE numbers below differ between the two).
pub(in crate::dispatch) const LINUX_IPPROTO_IPV6: i32 = 41;

/// IPv6 RFC 3542 ancillary cmsg-type number translation, macOS→Linux. macOS and
/// Linux assign DIFFERENT values to the same IPV6_* cmsg types (macOS gates them
/// behind `__APPLE_USE_RFC_3542`). The `setsockopt` optname direction is already
/// translated by `linux_to_host_sockopt`; this covers the returned `recvmsg`
/// cmsg_type, which carrick must translate back so the guest (Linux) sees the
/// expected type. `(linux, macos)`:
const IPV6_CMSG_MAP: &[(i32, i32)] = &[
    (52, 47), // IPV6_HOPLIMIT
    (67, 36), // IPV6_TCLASS
    (50, 46), // IPV6_PKTINFO
];

/// Translate a macOS IPPROTO_IPV6 cmsg-type back to the guest (Linux) value.
fn ipv6_cmsg_host_to_linux(host: i32) -> Option<i32> {
    IPV6_CMSG_MAP
        .iter()
        .find(|(_, m)| *m == host)
        .map(|(l, _)| *l)
}

/// Parse a HOST (macOS-layout) `msg_control` buffer and return every
/// IPPROTO_IPV6 ancillary record as `(linux_cmsg_type, data_bytes)`, with the
/// cmsg_type translated macOS→Linux. (SCM_RIGHTS is handled separately because
/// its data — host fds — needs install+remap.) Used by recvmsg to forward IPv6
/// hop-limit / traffic-class / pktinfo ancillary data the guest asked for.
pub(in crate::dispatch) fn parse_host_ipv6_cmsgs(
    control: &[u8],
    controllen: usize,
) -> Vec<(i32, Vec<u8>)> {
    let mut out = Vec::new();
    if controllen == 0 || control.is_empty() {
        return out;
    }
    unsafe {
        let mut hmsg: libc::msghdr = std::mem::zeroed();
        hmsg.msg_control = control.as_ptr() as *mut libc::c_void;
        hmsg.msg_controllen = controllen as _;
        let mut cmsg = libc::CMSG_FIRSTHDR(&hmsg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == LINUX_IPPROTO_IPV6
                && let Some(linux_type) = ipv6_cmsg_host_to_linux((*cmsg).cmsg_type)
            {
                let hdr_len = libc::CMSG_LEN(0) as usize;
                let total = (*cmsg).cmsg_len as usize;
                let data_len = total.saturating_sub(hdr_len);
                let data = libc::CMSG_DATA(cmsg);
                let mut v = vec![0u8; data_len];
                std::ptr::copy_nonoverlapping(data, v.as_mut_ptr(), data_len);
                out.push((linux_type, v));
            }
            cmsg = libc::CMSG_NXTHDR(&hmsg, cmsg);
        }
    }
    out
}

/// Append IPPROTO_IPV6 ancillary records (`(linux_cmsg_type, data)`) to a
/// GUEST (Linux-layout) `msg_control` buffer that already holds `prefix` bytes
/// (e.g. an SCM_RIGHTS record), honoring the total `cap`. Returns the combined
/// buffer + whether any record was dropped for lack of space (→ MSG_CTRUNC).
pub(in crate::dispatch) fn build_linux_ipv6_cmsgs(
    prefix: &[u8],
    cmsgs: &[(i32, Vec<u8>)],
    cap: usize,
) -> (Vec<u8>, bool) {
    let mut buf = prefix.to_vec();
    let mut truncated = false;
    for (ctype, data) in cmsgs {
        let cmsg_len = LINUX_CMSGHDR_LEN + data.len();
        let aligned = linux_cmsg_align(cmsg_len);
        if buf.len() + aligned > cap {
            truncated = true;
            break; // Linux drops this record (and the rest) + sets MSG_CTRUNC.
        }
        let start = buf.len();
        buf.resize(start + aligned, 0);
        buf[start..start + 8].copy_from_slice(&(cmsg_len as u64).to_ne_bytes());
        buf[start + 8..start + 12].copy_from_slice(&LINUX_IPPROTO_IPV6.to_ne_bytes());
        buf[start + 12..start + 16].copy_from_slice(&ctype.to_ne_bytes());
        buf[start + 16..start + 16 + data.len()].copy_from_slice(data);
    }
    (buf, truncated)
}

/// Build a HOST (macOS-layout) `msg_control` buffer carrying a single
/// `SCM_RIGHTS` record with `host_fds`, for handing to the real `sendmsg(2)`.
/// macOS `cmsghdr` is `{ u32 cmsg_len; i32 cmsg_level; i32 cmsg_type; }` and
/// uses `CMSG_SPACE`/`CMSG_LEN`. Uses the libc CMSG macros so the layout matches
/// what the host kernel expects exactly.
pub(in crate::dispatch) fn build_host_scm_rights(host_fds: &[i32]) -> Vec<u8> {
    if host_fds.is_empty() {
        return Vec::new();
    }
    let data_len = (host_fds.len() * std::mem::size_of::<i32>()) as u32;
    let space = unsafe { libc::CMSG_SPACE(data_len) } as usize;
    let mut buf = vec![0u8; space];
    unsafe {
        // Lay down one cmsghdr at the buffer head via the libc accessor so the
        // macOS-specific alignment/len fields are exactly right.
        let cmsg = buf.as_mut_ptr() as *mut libc::cmsghdr;
        (*cmsg).cmsg_len = libc::CMSG_LEN(data_len);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        let data = libc::CMSG_DATA(cmsg) as *mut i32;
        for (i, &fd) in host_fds.iter().enumerate() {
            std::ptr::write(data.add(i), fd);
        }
    }
    buf
}

/// Parse a HOST (macOS-layout) `msg_control` buffer (filled by `recvmsg(2)`) and
/// return the host file descriptors carried by every `SCM_RIGHTS` record. Uses
/// the libc CMSG iteration macros. `controllen` is the kernel-reported
/// `msg_controllen` after recvmsg.
pub(in crate::dispatch) fn parse_host_scm_rights_fds(
    control: &[u8],
    controllen: usize,
) -> Vec<i32> {
    let mut fds = Vec::new();
    if controllen == 0 || control.is_empty() {
        return fds;
    }
    unsafe {
        let mut hmsg: libc::msghdr = std::mem::zeroed();
        hmsg.msg_control = control.as_ptr() as *mut libc::c_void;
        hmsg.msg_controllen = controllen as _;
        let mut cmsg = libc::CMSG_FIRSTHDR(&hmsg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let hdr_len = libc::CMSG_LEN(0) as usize;
                let total = (*cmsg).cmsg_len as usize;
                let data_len = total.saturating_sub(hdr_len);
                let count = data_len / std::mem::size_of::<i32>();
                let data = libc::CMSG_DATA(cmsg) as *const i32;
                for i in 0..count {
                    fds.push(std::ptr::read(data.add(i)));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&hmsg, cmsg);
        }
    }
    fds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scm_rights_guest_buffer_roundtrips() {
        // build_linux_scm_rights → parse_linux_scm_rights_fds is the identity on
        // the fd list (the guest cmsg layout carrick writes back must be exactly
        // what a guest reads). 3 fds fit in a generous cap.
        let fds = [10i32, 11, 12];
        let (buf, truncated) = build_linux_scm_rights(&fds, 256);
        assert!(!truncated);
        // cmsg_len = 16-byte header + 3*4 = 28; CMSG_ALIGN(28)=32.
        assert_eq!(buf.len(), 32);
        let cmsg_len = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
        assert_eq!(cmsg_len, (LINUX_CMSGHDR_LEN + 12) as u64);
        let level = i32::from_ne_bytes(buf[8..12].try_into().unwrap());
        let ctype = i32::from_ne_bytes(buf[12..16].try_into().unwrap());
        assert_eq!(level, LINUX_SOL_SOCKET);
        assert_eq!(ctype, LINUX_SCM_RIGHTS);
        assert_eq!(parse_linux_scm_rights_fds(&buf), fds.to_vec());
    }

    #[test]
    fn scm_rights_truncates_when_cap_too_small() {
        // Cap that holds the header + only 1 fd (16 + 4 = 20 bytes).
        let fds = [1i32, 2, 3];
        let (buf, truncated) = build_linux_scm_rights(&fds, 20);
        assert!(truncated, "only 1 of 3 fds fit → MSG_CTRUNC");
        assert_eq!(parse_linux_scm_rights_fds(&buf), vec![1]);
        // A cap smaller than the header emits nothing but flags truncation.
        let (empty, trunc2) = build_linux_scm_rights(&fds, 8);
        assert!(empty.is_empty());
        assert!(trunc2);
    }

    #[test]
    fn scm_rights_parse_ignores_non_scm_records() {
        // A non-SCM_RIGHTS cmsg (e.g. a SO_TIMESTAMP-ish record) must be skipped.
        let mut buf = vec![0u8; 16];
        buf[0..8].copy_from_slice(&16u64.to_ne_bytes()); // cmsg_len, header only
        buf[8..12].copy_from_slice(&LINUX_SOL_SOCKET.to_ne_bytes());
        buf[12..16].copy_from_slice(&29i32.to_ne_bytes()); // SO_TIMESTAMP, not SCM_RIGHTS
        assert!(parse_linux_scm_rights_fds(&buf).is_empty());
    }

    #[test]
    fn scm_rights_host_buffer_roundtrips() {
        // build_host_scm_rights (macOS cmsg layout) → parse_host_scm_rights_fds
        // is the identity. Exercises the libc CMSG macros end to end.
        let fds = [3i32, 7, 42];
        let buf = build_host_scm_rights(&fds);
        let got = parse_host_scm_rights_fds(&buf, buf.len());
        assert_eq!(got, fds.to_vec());
    }

    #[test]
    fn netlink_rtm_getroute_synthesizes_terminated_route_dump() {
        let req = LinuxNlMsgHdr {
            nlmsg_len: std::mem::size_of::<LinuxNlMsgHdr>() as u32,
            nlmsg_type: LINUX_RTM_GETROUTE,
            nlmsg_flags: 0,
            nlmsg_seq: 7,
            nlmsg_pid: 0,
        };
        let reply = build_netlink_reply(req.as_bytes(), 42);
        // Walk the multipart reply (each message 4-byte aligned): expect at least
        // one connected RTM_NEWROUTE, terminated by NLMSG_DONE, nothing else.
        let hdr_size = std::mem::size_of::<LinuxNlMsgHdr>();
        let mut offset = 0;
        let mut routes = 0;
        let mut saw_done = false;
        while offset + hdr_size <= reply.len() {
            let (h, _) = LinuxNlMsgHdr::read_from_prefix(&reply[offset..]).unwrap();
            match h.nlmsg_type {
                LINUX_RTM_NEWROUTE => routes += 1,
                LINUX_NLMSG_DONE => saw_done = true,
                other => panic!("unexpected nlmsg_type {other} in RTM_GETROUTE reply"),
            }
            let aligned = (h.nlmsg_len as usize).next_multiple_of(NLMSG_ALIGNTO);
            if aligned == 0 {
                break;
            }
            offset += aligned;
        }
        assert!(
            routes >= 1,
            "expected at least the loopback connected route"
        );
        assert!(saw_done, "route dump must terminate with NLMSG_DONE");
    }

    #[test]
    fn masked_network_zeroes_host_bits() {
        // 127.0.0.1/8 -> 127.0.0.0 ; 192.168.5.9/24 -> 192.168.5.0
        assert_eq!(masked_network(&[127, 0, 0, 1], 8), vec![127, 0, 0, 0]);
        assert_eq!(masked_network(&[192, 168, 5, 9], 24), vec![192, 168, 5, 0]);
        // /20 splits the third byte: keep high 4 bits (0xF0).
        assert_eq!(
            masked_network(&[10, 1, 0xFF, 0xFF], 20),
            vec![10, 1, 0xF0, 0]
        );
    }

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

        let round_trip = host_to_linux_sockaddr(&host, LINUX_AF_INET, false);
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
                priority: false,
            }
        );
        assert_eq!(
            epoll_kq_filters(LINUX_EPOLLIN),
            EpollKqFilters {
                read: true,
                write: false,
                priority: false,
            }
        );
        assert_eq!(
            epoll_kq_filters(LINUX_EPOLLOUT),
            EpollKqFilters {
                read: false,
                write: true,
                priority: false,
            }
        );
        assert_eq!(
            epoll_kq_filters(LINUX_EPOLLIN | LINUX_EPOLLOUT),
            EpollKqFilters {
                read: true,
                write: true,
                priority: false,
            }
        );
        assert_eq!(
            epoll_kq_filters(LINUX_EPOLLPRI),
            EpollKqFilters {
                read: true,
                write: false,
                priority: true,
            }
        );
    }

    #[test]
    fn epoll_kqueue_changes_include_oob_filter_for_priority_events() {
        let changes = epoll_kq_add_changes(42, 7, LINUX_EPOLLPRI);
        assert!(changes.iter().any(|ev| ev.filter() == libc::EVFILT_READ));
        assert!(
            changes
                .iter()
                .any(|ev| ev.filter() == crate::darwin_kqueue::EVFILT_EXCEPT
                    && ev.fflags() == crate::darwin_kqueue::NOTE_OOB)
        );

        let pri = crate::darwin_kqueue::Kevent::oob(42, 0);
        assert_eq!(kevent_to_epoll(pri), LINUX_EPOLLPRI);
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

        let removed = epoll_kq_removed_filter_changes(42, LINUX_EPOLLPRI, LINUX_EPOLLIN);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].filter(), crate::darwin_kqueue::EVFILT_EXCEPT);
        assert_eq!(removed[0].fflags(), crate::darwin_kqueue::NOTE_OOB);

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
