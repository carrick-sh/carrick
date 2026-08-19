//! Socket, netlink, fd-set, and epoll helper routines for net dispatch — the
//! Linux↔Darwin translation layer that [`super`]'s handlers call.
//!
//! # Theory of operation
//!
//! Everything here is a pure-ish translation primitive: it converts a Linux ABI
//! shape (a `sockaddr`, an fd-set bitmap, an rtnetlink message) to/from the
//! Darwin shape, or it stands in for a Linux subsystem that Darwin lacks. The
//! handlers in [`super`] stay short because the layout math and the family
//! quirks live here.
//!
//! ## sockaddr translation (the AF families)
//!
//! `read_linux_sockaddr` parses a guest-formatted `sockaddr` into the macOS BSD
//! form (which carries a leading `sa_len` byte Linux omits) ready for
//! `bind`/`connect`/`sendto`; `host_to_linux_sockaddr` + `write_linux_sockaddr`
//! reverse it for `getsockname`/`getpeername`/`accept`/`recvfrom`. AF_INET and
//! AF_INET6 differ only structurally; one substantive behavior fold lives here:
//! Linux treats the whole `127.0.0.0/8` as loopback on `lo`, but macOS assigns
//! only `127.0.0.1` to `lo0`, so a bind/connect to e.g. `127.0.1.1` (the
//! Debian-convention hostname address carrick seeds in `/etc/hosts`) would fail
//! EADDRNOTAVAIL — every `127/8` address is folded onto `127.0.0.1` in the
//! single shared converter so bind/connect/sendto/sendmsg all agree.
//!
//! ## AF_UNIX: the features macOS lacks
//!
//! Linux AF_UNIX has three things macOS does not: an **abstract namespace**
//! (sockets named by a leading-NUL byte string, with no filesystem node),
//! **autobind** (an empty bind asks the kernel for a unique abstract name), and
//! a much longer `sun_path`. carrick bridges all three by mapping every guest
//! AF_UNIX name to a real host filesystem socket under a per-run directory:
//!
//!   - A guest `sun_path` (pathname or abstract) is FNV-1a hashed to a fixed
//!     16-hex-digit `<hash>.sock` host node (`unix_socket_host_path`). The hash
//!     is deterministic so a `bind` and a later `connect` to the same name land
//!     on the same host node, and it is short enough to always fit macOS's
//!     `sun_path` even for a long abstract name. Abstract names live under an
//!     `abstract/` subdir so they cannot collide with real pathname sockets.
//!   - Because the host node name is a one-way hash, a process-global registry
//!     (`unix_path_registry`) records host-path → original-guest-`sun_path` so
//!     `getsockname`/`getpeername`/`accept` reverse-translate to EXACTLY the
//!     bytes the guest used (abstract = leading NUL + name; pathname = no
//!     trailing NUL) — otherwise a peer re-translating a returned address would
//!     miss. The registry is process-global rather than fork-shared because the
//!     process that bound/connected a socket is the same one that later queries
//!     its address.
//!   - `autobind_unix_host_path` synthesises Linux's `NUL + 5 hex digits`
//!     abstract name itself and registers it, since macOS has no autobind.
//!
//! SEQPACKET has no macOS AF_UNIX backing, so it is created as a STREAM socket
//! (`host_socktype_backing`) and message boundaries are reframed by the handler
//! on top (`OpenDescription::HostSocket.seqpacket`); see [`super`].
//!
//! ## Synthetic rtnetlink
//!
//! macOS has no AF_NETLINK. `build_netlink_reply` is the synthetic rtnetlink
//! "kernel": it inspects a guest's dump request and emits a well-formed,
//! `NLM_F_MULTI`, `NLMSG_DONE`-terminated reply describing a loopback-only host
//! — RTM_GETLINK→`lo`, RTM_GETADDR→`127.0.0.1/8`, RTM_GETROUTE→the connected
//! route, everything else→an empty dump. `push_nlmsg` does the `NLMSG_ALIGNTO`
//! framing; `drain_netlink_queue` is the read(2)-side that copies queued reply
//! bytes into guest memory. This is enough for glibc's `__check_pf` and for
//! `ip`/`ss` to function rather than abort on EAFNOSUPPORT.
//!
//! ## fd-set and epoll helpers
//!
//! The remaining routines do the bit-twiddling for `select`'s `fd_set` bitmaps
//! and read/write the Linux `epoll_event` struct for the [`super`] epoll
//! handlers.

use crate::linux_abi::LinuxErrno;
use std::collections::VecDeque;

use zerocopy::{FromBytes, IntoBytes};

use super::super::*;
use crate::linux_abi::{
    LINUX_ARPHRD_ETHER, LINUX_IFA_CACHEINFO, LINUX_IFA_F_PERMANENT, LINUX_IFA_FLAGS,
    LINUX_IFA_INFINITY_LIFE_TIME, LINUX_IFF_BROADCAST, LINUX_IFF_MULTICAST, LINUX_IFF_POINTOPOINT,
    LINUX_RT_SCOPE_HOST, LINUX_RT_SCOPE_LINK, LINUX_RT_SCOPE_UNIVERSE, LINUX_RT_TABLE_MAIN,
    LINUX_RTA_DST, LINUX_RTA_GATEWAY, LINUX_RTA_OIF, LINUX_RTM_GETNEIGH, LINUX_RTM_GETROUTE,
    LINUX_RTM_NEWROUTE, LINUX_RTN_UNICAST, LINUX_RTPROT_KERNEL, LinuxRtMsg,
};
use carrick_abi::LINUX_SOCK_RDM;

pub(super) fn read_epoll_event(
    memory: &impl GuestMemory,
    address: u64,
    guest_abi: LinuxGuestAbi,
) -> Result<LinuxEpollEvent, LinuxErrno> {
    match guest_abi {
        LinuxGuestAbi::Aarch64 => read_kernel_struct(memory, address),
        LinuxGuestAbi::X86_64 => {
            let event: LinuxX8664EpollEvent = read_kernel_struct(memory, address)?;
            let events = event.events;
            let data = event.data;
            Ok(LinuxEpollEvent {
                events,
                _pad: 0,
                data,
            })
        }
    }
}

/// Translate the epoll interest mask into the [`carrick_hal::event::Interest`] the multiplexer
/// registers. A mask with neither IN nor OUT still requests `read` so the
/// always-reported EPOLLHUP/EPOLLERR edges (which ride the read filter) are
/// observed; RDHUP/PRI also ride the read/oob filters. (Mirrors the old
/// `epoll_kq_filters` read-fallback exactly.)
pub(super) fn epoll_interest_for(events: LinuxEpollEvents) -> carrick_hal::event::Interest {
    let write = events.contains(LinuxEpollEvents::OUT);
    let read = events
        .intersects(LinuxEpollEvents::IN | LinuxEpollEvents::RDHUP | LinuxEpollEvents::PRI)
        || !write;
    carrick_hal::event::Interest {
        read,
        write,
        oob: events.contains(LinuxEpollEvents::PRI),
        read_lowat: None,
    }
}

/// Edge (`EPOLLET`) vs level trigger mode for a multiplexer registration.
#[cfg_attr(
    any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ),
    allow(dead_code)
)]
pub(super) fn epoll_trigger_mode(events: LinuxEpollEvents) -> carrick_hal::event::TriggerMode {
    if events.contains(LinuxEpollEvents::ET) {
        carrick_hal::event::TriggerMode::Edge
    } else {
        carrick_hal::event::TriggerMode::Level
    }
}

/// Trigger mode used for host-fd registrations that back a guest epoll set.
///
/// Keep host registrations aligned with the guest trigger mode. On BSD kqueue,
/// `EV_CLEAR` spends a host edge exactly once; Carrick re-arms registrations
/// after guest I/O/backpressure transitions instead of polling a permanently
/// readable kqueue fd for latch-masked `EPOLLET` readiness.
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(super) fn epoll_host_trigger_mode(events: LinuxEpollEvents) -> carrick_hal::event::TriggerMode {
    epoll_trigger_mode(events)
}

#[cfg(not(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
)))]
pub(super) fn epoll_host_trigger_mode(events: LinuxEpollEvents) -> carrick_hal::event::TriggerMode {
    epoll_trigger_mode(events)
}

/// Monotonic source of epoll-registration generations (the high half of a
/// multiplexer `udata` handle). A generation makes `(guest_fd, gen)` a
/// generational index — the standard defence against the ABA hazard of recycled
/// fd numbers: a drained event whose generation no longer matches the live
/// `interest[guest_fd]` is a stale edge for a since-recycled fd and is dropped
/// rather than mis-delivered. u32 wrap needs 2^32 registrations *and* a stale
/// event surviving that long (it is consumed within one `epoll_pwait`), so it is
/// not a practical ABA window. See [`EpollInterest::reg_gen`].
static EPOLL_REG_GEN: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// Allocate the next registration generation (never 0, so 0 can mean "unset").
pub(super) fn next_epoll_reg_gen() -> u32 {
    let g = EPOLL_REG_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if g == 0 {
        EPOLL_REG_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    } else {
        g
    }
}

/// Pack a multiplexer `udata` handle: low 32 bits = guest fd, high 32 = the
/// registration generation. The kqueue/epoll IDENT stays the host fd (the
/// kernel's stable key, auto-removed on close); the udata carries the routing
/// identity so a drained event resolves to its CURRENT owner directly
/// (`interest[guest_fd]`) without re-deriving it from the racy host-fd map.
pub(super) fn pack_epoll_udata(guest_fd: i32, generation: u32) -> u64 {
    ((generation as u64) << 32) | (guest_fd as u32 as u64)
}

/// Inverse of [`pack_epoll_udata`]: `(guest_fd, generation)`.
pub(super) fn unpack_epoll_udata(udata: u64) -> (i32, u32) {
    ((udata & 0xFFFF_FFFF) as u32 as i32, (udata >> 32) as u32)
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
) -> Vec<(i32, LinuxEpollEvent)> {
    let take = pending_ready.len().min(max_events);
    pending_ready.drain(..take).collect()
}

pub(super) fn write_epoll_events<M: GuestMemory>(
    memory: &mut M,
    events_address: u64,
    ready: &[LinuxEpollEvent],
    guest_abi: LinuxGuestAbi,
) -> Result<DispatchOutcome, DispatchError> {
    let event_size = match guest_abi {
        LinuxGuestAbi::Aarch64 => <LinuxEpollEvent as KernelAbi>::ABI_SIZE,
        LinuxGuestAbi::X86_64 => <LinuxX8664EpollEvent as KernelAbi>::ABI_SIZE,
    };
    let Some(total_size) = ready.len().checked_mul(event_size) else {
        return Err(DispatchError::LengthTooLarge(u64::MAX));
    };
    if !memory.guest_range_is_writable(events_address, total_size) {
        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
    }
    for (index, event) in ready.iter().enumerate() {
        let offset = index
            .checked_mul(event_size)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
        let address = events_address.checked_add(offset).ok_or(LINUX_EFAULT);
        let Ok(address) = address else {
            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
        };
        match guest_abi {
            LinuxGuestAbi::Aarch64 => {
                if write_kernel_struct_raw(memory, address, event).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }
            LinuxGuestAbi::X86_64 => {
                let wire = LinuxX8664EpollEvent {
                    events: event.events,
                    data: event.data,
                };
                if write_kernel_struct_raw(memory, address, &wire).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }
        }
    }
    Ok(DispatchOutcome::Returned {
        value: ready.len() as i64,
    })
}

/// Translate one multiplexer [`carrick_hal::event::PollEvent`] to Linux epoll event bits.
/// Direction-sensitive (jiixyj/epoll-shim model): the multiplexer reports one
/// readiness direction per event, so read readiness -> EPOLLIN (read EOF ->
/// EPOLLRDHUP), write readiness -> EPOLLOUT (write EOF -> EPOLLHUP), oob ->
/// EPOLLPRI. A carried socket error (`PollEvent::error`, from `EV_ERROR` or an
/// EOF's non-zero fflags) -> EPOLLERR.
///
/// `eof`/`error` are surfaced INDEPENDENTLY of read/write readiness so a *bare*
/// hangup or error edge still translates to a non-zero mask. On Linux the native
/// epoll reports `EPOLLHUP`/`EPOLLERR` without an accompanying `EPOLLIN`/`EPOLLOUT`
/// (e.g. a pipe whose write-end closed with no buffered data, or a connect()
/// failure) — and on an `EPOLLET` registration that edge fires exactly once, so
/// if it translated to 0 the caller would drop it as a no-op wake and never
/// re-deliver it (the Go netpoller deadlock: a hung-up pollDesc never wakes).
/// macOS couples EOF to a read/write filter (kqueue `EV_EOF` rides `EVFILT_READ`/
/// `EVFILT_WRITE`), so a bare `eof` never arises there and these branches are
/// inert — the exact bits the old `kevent_to_epoll` produced are preserved.
pub(super) fn pollevent_to_epoll(ev: &carrick_hal::event::PollEvent) -> u32 {
    let mut events = 0u32;
    if ev.error.is_some() {
        events |= LINUX_EPOLLERR;
    }
    if ev.readiness.read {
        events |= LINUX_EPOLLIN;
        if ev.eof {
            events |= LINUX_EPOLLRDHUP;
        }
    }
    if ev.readiness.write {
        events |= LINUX_EPOLLOUT;
        if ev.eof {
            events |= LINUX_EPOLLHUP;
        }
    }
    if ev.readiness.oob {
        events |= LINUX_EPOLLPRI;
    }
    // A bare hangup (EOF with neither read nor write readiness) is a full
    // EPOLLHUP — surface it so an EPOLLET pollDesc whose only edge is the
    // hangup is not silently dropped.
    if ev.eof && !ev.readiness.read && !ev.readiness.write {
        events |= LINUX_EPOLLHUP;
    }
    events
}

/// Is there TCP urgent / out-of-band data pending on `host_fd` right now?
///
/// This is the level-triggered "is EPOLLPRI asserted" probe the epoll(7)
/// readiness recompute needs, and it CANNOT be answered with `libc::poll`'s
/// `POLLPRI` on macOS: Darwin's `poll(2)` does not surface socket OOB through
/// `POLLPRI` (it stays 0 even with a pending urgent byte), so the epoll_pwait
/// re-poll dropped the OOB edge the instance kqueue had correctly drained, and
/// EPOLLPRI was never delivered (probe `epollpri`). Darwin DOES expose OOB
/// readiness through kqueue's `EVFILT_EXCEPT`/`NOTE_OOB`, so a one-shot,
/// non-blocking kqueue check is the Darwin-native equivalent of `POLLPRI`.
///
/// A transient kqueue (created and dropped per call) keeps this stateless and
/// fork-coherent — there is no registration to leak or to confuse with the
/// instance multiplexer's long-lived `EVFILT_EXCEPT` filter. Best-effort: any
/// host error means "not ready" (the caller still has the read/write/HUP path).
///
/// macOS/OpenBSD/DragonFly expose `EVFILT_EXCEPT`; on every other host (Linux,
/// FreeBSD, NetBSD) OOB readiness is reported by the platform's native poll
/// (`POLLPRI`) or has no kqueue equivalent, so this returns `false` and the
/// caller falls back to its `libc::poll(POLLPRI)` path.
#[cfg(any(target_os = "macos", target_os = "openbsd", target_os = "dragonfly"))]
pub(super) fn host_fd_has_oob(host_fd: i32) -> bool {
    use carrick_host_bsd::Kqueue;
    use carrick_host_bsd::kqueue::{EVFILT_EXCEPT, Kevent, NOTE_OOB};

    let Some(kq) = Kqueue::new_internal() else {
        return false;
    };
    // EV_RECEIPT makes apply() report registration errors as a 0-data EV_ERROR
    // kevent rather than a delivered event; we instead just register, then do a
    // zero-timeout drain — an EVFILT_EXCEPT event with NOTE_OOB fflags means a
    // pending urgent byte. EV_CLEAR keeps it from re-counting (irrelevant for a
    // one-shot transient kq, but harmless).
    let add = Kevent::oob(
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
    match kq.wait(&[], &mut out, Some(&zero)) {
        Ok(n) if n >= 1 => {
            let ev = out[0];
            ev.filter() == EVFILT_EXCEPT && ev.fflags() & NOTE_OOB != 0
        }
        _ => false,
    }
}

/// Non-Darwin hosts answer OOB readiness through their native `POLLPRI`
/// (Linux) or have no `EVFILT_EXCEPT` (FreeBSD, NetBSD); see [`host_fd_has_oob`].
#[cfg(not(any(target_os = "macos", target_os = "openbsd", target_os = "dragonfly")))]
pub(super) fn host_fd_has_oob(_host_fd: i32) -> bool {
    false
}

pub(super) fn read_pollfd(
    memory: &impl GuestMemory,
    address: u64,
) -> Result<LinuxPollFd, LinuxErrno> {
    read_kernel_struct(memory, address)
}

pub(super) fn read_fd_set(
    memory: &impl GuestMemory,
    address: u64,
    nfds: usize,
) -> Result<Vec<u8>, LinuxErrno> {
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

/// Address family of a HOST sockaddr held as raw bytes. The 2-byte header is
/// the ONLY layout divergence between the hosts: macOS/BSD is `sa_len(u8)
/// sa_family(u8)`, Linux is `sa_family(u16)`. Everything past offset 2
/// (sin_port/sin_addr, sun_path, …) lines up on both. Decoding byte 1 as the
/// family on a Linux host read the high byte of the u16 — 0 for every real
/// family — so getsockname/getpeername/accept/recvfrom reported AF_UNSPEC and
/// libuv's `uv_guess_handle` classified a socketpair stdio fd as
/// UV_UNKNOWN_HANDLE (node then wired process.stdout to a black-hole stream
/// and the child's pipe output vanished — the KVM-lane app-smoke failure).
pub(super) fn host_sockaddr_family(bytes: &[u8]) -> u16 {
    if bytes.len() < 2 {
        return libc::AF_UNSPEC as u16;
    }
    #[cfg(not(target_os = "linux"))]
    {
        // BSD layout (macOS, FreeBSD, NetBSD): `sa_len(u8) sa_family(u8)` — the
        // family is byte 1. FreeBSD/NetBSD are BSDs too, so they must take THIS
        // branch, not the Linux one (a FreeBSD host reading the Linux u16 here
        // would decode garbage and reject AF_INET/AF_UNIX binds — EAFNOSUPPORT).
        bytes[1] as u16
    }
    #[cfg(target_os = "linux")]
    {
        u16::from_ne_bytes([bytes[0], bytes[1]])
    }
}

/// Stamp the 2-byte header of a HOST sockaddr under construction (the inverse
/// of [`host_sockaddr_family`]): macOS wants `(sa_len, sa_family as u8)`,
/// Linux wants the `sa_family` u16 and has no length byte. `out` must already
/// be sized to the full sockaddr (macOS `sa_len` is taken from `out.len()`).
pub(super) fn set_host_sockaddr_header(out: &mut [u8], family: i32) {
    debug_assert!(out.len() >= 2);
    #[cfg(not(target_os = "linux"))]
    {
        // BSD layout (macOS, FreeBSD, NetBSD): `sa_len(u8) sa_family(u8)`. All
        // non-Linux hosts here are BSDs — a FreeBSD host given the Linux u16
        // family reads sa_family=0 (AF_UNSPEC) and rejects the bind/connect.
        out[0] = out.len().min(255) as u8;
        out[1] = family as u8;
    }
    #[cfg(target_os = "linux")]
    {
        out[0..2].copy_from_slice(&(family as u16).to_ne_bytes());
    }
}

/// The host socket type to actually create for a guest `(family, base_type)`.
/// macOS has no AF_UNIX `SOCK_SEQPACKET`, so back it with a `SOCK_STREAM` socket;
/// carrick frames messages on top to recover SEQPACKET boundary semantics (see
/// `OpenDescription::HostSocket.seqpacket`). Unprivileged BSD processes also
/// cannot create INET raw sockets, so Carrick uses a datagram fd as their
/// poll/bind/option carrier while retaining the guest RAW type and protocol.
/// Raw connect identity is virtualized by the dispatcher.
pub(super) fn host_socktype_backing(family: i32, base_type: i32) -> i32 {
    if family == LINUX_AF_UNIX && base_type == LINUX_SOCK_SEQPACKET {
        return libc::SOCK_STREAM;
    }
    #[cfg(carrick_bsd)]
    if matches!(family, LINUX_AF_INET | LINUX_AF_INET6) && base_type == LINUX_SOCK_RAW {
        return libc::SOCK_DGRAM;
    }
    linux_to_host_socktype(base_type)
}

/// Linux-canonical `(family, base_type, protocol)` validation applied BEFORE the
/// tuple reaches the host `socket()`/`socketpair()`. Returns `Some(errno)` for
/// the combinations Linux rejects with a well-defined errno that macOS reports
/// differently (invalid type → `EPROTONOSUPPORT`; a protocol/type mismatch →
/// `EPROTOTYPE`/`EPERM`), and `None` to let the host handle the
/// tuple (a genuinely unsupported domain still surfaces `EAFNOSUPPORT`; a valid
/// INET pair still surfaces `EOPNOTSUPP` from `socketpair`). `base_type` must
/// already have the `SOCK_NONBLOCK`/`SOCK_CLOEXEC` bits stripped.
/// (LTP socket01, socketpair01.)
pub(super) fn canonical_socket_errno(
    family: i32,
    base_type: i32,
    protocol: i32,
) -> Option<LinuxErrno> {
    // IPPROTO numbers with no named ABI constant. IPPROTO_TCP == LINUX_SOL_TCP
    // (6) and IPPROTO_UDP == LINUX_SOL_UDP (17); ICMP/ICMPv6 are the datagram
    // "ping socket" protocols Linux permits on SOCK_DGRAM.
    const IPPROTO_ICMP: i32 = 1;
    const IPPROTO_ICMPV6: i32 = 58;

    // An unknown socket type is EINVAL on Linux (macOS returns EPROTONOSUPPORT).
    if !matches!(
        base_type,
        LINUX_SOCK_STREAM
            | LINUX_SOCK_DGRAM
            | LINUX_SOCK_RAW
            | LINUX_SOCK_RDM
            | LINUX_SOCK_SEQPACKET
    ) {
        return Some(LINUX_EINVAL);
    }

    // Protocol validation only applies to the INET families; AF_UNIX (and any
    // other family) proceeds to the host, which validates the pair itself.
    if family == LINUX_AF_INET || family == LINUX_AF_INET6 {
        match base_type {
            // Stream sockets accept only the default (0) or TCP protocol; UDP,
            // ICMP, etc. on a stream socket are EPROTONOSUPPORT (macOS: the less
            // specific EPROTOTYPE).
            LINUX_SOCK_STREAM => {
                if protocol != 0 && protocol != LINUX_SOL_TCP {
                    return Some(crate::linux_abi::LINUX_EPROTONOSUPPORT);
                }
            }
            // Datagram sockets accept the default (0), UDP, UDP-Lite, or the
            // ICMP/ICMPv6 ping-socket protocols; a TCP protocol on a datagram
            // socket is EPROTONOSUPPORT.
            LINUX_SOCK_DGRAM => {
                if !matches!(
                    protocol,
                    0 | LINUX_SOL_UDP | LINUX_IPPROTO_UDPLITE | IPPROTO_ICMP | IPPROTO_ICMPV6
                ) {
                    return Some(crate::linux_abi::LINUX_EPROTONOSUPPORT);
                }
            }
            // Linux accepts an 8-bit IP protocol for raw sockets (subject to
            // CAP_NET_RAW). Carrick virtualizes the capability boundary and
            // retains that guest protocol over an unprivileged datagram carrier.
            LINUX_SOCK_RAW if !(0..=u8::MAX as i32).contains(&protocol) => {
                return Some(LINUX_EINVAL);
            }
            _ => {}
        }
    }
    None
}

const HOST_STREAM_BUF_TARGET: libc::c_int = 16 * 1024 * 1024;
const HOST_STREAM_BUF_REQUIRED: libc::c_int = 8 * 1024 * 1024;

// Only referenced from the macOS-gated widening test now that widening reads
// back nothing in the hot path (best-effort). Keep it for that coverage. The
// only real caller is `#[cfg(test)]`-gated, so a plain (non-test) lib build
// on macOS is ALSO callerless — gate on `not(test)` too, not just non-macOS.
#[cfg_attr(not(all(test, target_os = "macos")), allow(dead_code))]
fn host_socket_buffer_size(host_fd: i32, opt: libc::c_int) -> Result<libc::c_int, LinuxErrno> {
    let mut size: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: host_fd is a live socket fd; size/len point to writable storage.
    let rc = unsafe {
        libc::getsockopt(
            host_fd,
            libc::SOL_SOCKET,
            opt,
            &mut size as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    rc.host_syscall_errno().map(|_| size)
}

fn set_host_socket_buffer_size(
    host_fd: i32,
    opt: libc::c_int,
    size: libc::c_int,
) -> Result<(), LinuxErrno> {
    // SAFETY: host_fd is a live socket fd; the optval is a valid &c_int.
    let rc = unsafe {
        libc::setsockopt(
            host_fd,
            libc::SOL_SOCKET,
            opt,
            &size as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc.host_syscall_errno()
        .map(|_| ())
        .map_err(|_| crate::linux_abi::LINUX_ENOBUFS)
}

/// Widen a host stream socket's send (and recv) buffer beyond macOS' small
/// defaults. Linux-visible `getsockopt(SO_SNDBUF/SO_RCVBUF)` reports the
/// guest-intended/default Linux value from `OpenDescriptionBase`, so this is
/// host-only backing capacity. A guest that writes up to its socket buffer
/// expecting the write to complete WITHOUT a draining reader can otherwise park
/// behind a POLLOUT edge that never gives it enough progress — e.g. Go's
/// infinite-response tests, where a writer goroutine pushes a large payload
/// while the reader consumes in large netpoll waits. SO_SNDBUF is the
/// load-bearing option (it governs the writer); SO_RCVBUF is checked for
/// symmetry. DGRAM is intentionally left alone because datagram boundary
/// semantics differ.
///
/// The host may reject or silently clamp a large `setsockopt(SO_*BUF)` request,
/// so this function retries at the required floor and then reads back the actual
/// kernel value. Widening is a BEST-EFFORT host-backing optimization: Linux
/// `socket(2)` never fails for buffer-sizing reasons, so a host that caps the
/// send/recv buffer below the desired floor (e.g. FreeBSD's default
/// `kern.ipc.maxsockbuf`, which is smaller than 8 MiB) must NOT turn a valid
/// socket creation into `ENOBUFS`. We set the largest value the host accepts and
/// proceed with whatever backing capacity results.
pub(super) fn widen_stream_socket_buffers(
    host_fd: i32,
    family: i32,
    base_type: i32,
) -> Result<(), LinuxErrno> {
    if !matches!(base_type, LINUX_SOCK_STREAM | LINUX_SOCK_SEQPACKET) {
        return Ok(());
    }
    if base_type == LINUX_SOCK_SEQPACKET && family != LINUX_AF_UNIX {
        return Ok(());
    }
    for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // Prefer the target; if the host rejects it, drop to the required floor.
        // Both are best-effort — a host that caps below either value keeps its
        // own maximum rather than failing the socket.
        if set_host_socket_buffer_size(host_fd, opt, HOST_STREAM_BUF_TARGET).is_err() {
            let _ = set_host_socket_buffer_size(host_fd, opt, HOST_STREAM_BUF_REQUIRED);
        }
    }
    Ok(())
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
#[derive(Debug)]
struct HostAddr {
    index: u32,
    name: String,
    family: u8, // LINUX_AF_INET / LINUX_AF_INET6
    addr: Vec<u8>,
    prefixlen: u8,
    scope: u8,
}

pub(super) type NetworkLinkSnapshot = crate::network::model::LinuxNetworkModel;

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

/// Enumerate the host's interfaces + addresses via `getifaddrs(3)` and translate
/// them to the Linux-facing names Carrick exposes elsewhere (`lo`, first `en*`
/// uplink as `eth0`). Empty on failure (caller falls back to a synthetic
/// loopback).
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
            carrick_portable::AF_LINK => {
                // One link-layer record per entry (carries the index + hw addr).
                // The sockaddr shape differs: Darwin AF_LINK -> sockaddr_dl,
                // Linux AF_PACKET -> sockaddr_ll.
                #[cfg(carrick_bsd)]
                let (hw, idx) = {
                    // SAFETY: AF_LINK sockaddr is a sockaddr_dl (Darwin + the BSDs).
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
                    (hw, idx)
                };
                #[cfg(carrick_linux)]
                let (hw, idx) = {
                    // SAFETY: AF_PACKET sockaddr is a sockaddr_ll (Linux).
                    let ll = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_ll) };
                    let alen = (ll.sll_halen as usize).min(ll.sll_addr.len());
                    let hw = ll.sll_addr[..alen].to_vec();
                    let idx = if index != 0 {
                        index
                    } else {
                        ll.sll_ifindex as u32
                    };
                    (hw, idx)
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
    linux_guest_interfaces(ifaces, addrs)
}

fn linux_guest_interfaces(
    ifaces: Vec<HostIface>,
    addrs: Vec<HostAddr>,
) -> (Vec<HostIface>, Vec<HostAddr>) {
    // Darwin's primary links are normally `en*`, but FreeBSD commonly uses
    // `vtnet*`, `em*`, or `igb*` and Linux uses `eth*`. Restricting the guest
    // uplink to Darwin names made a FreeBSD native guest appear loopback-only;
    // glibc AI_ADDRCONFIG then discarded every IPv4 DNS answer. Prefer familiar
    // physical/uplink names, with any non-loopback interface as a final
    // portable fallback.
    let eth_host_name = ifaces
        .iter()
        .filter(|iface| iface.arphrd != LINUX_ARPHRD_LOOPBACK)
        .min_by_key(|iface| {
            let name = iface.name.as_str();
            let active = iface.linux_flags & (LINUX_IFF_UP | LINUX_IFF_RUNNING)
                == (LINUX_IFF_UP | LINUX_IFF_RUNNING);
            let has_ipv4 = addrs
                .iter()
                .any(|addr| addr.name == name && addr.family == LINUX_AF_INET as u8);
            let rank = if name
                .strip_prefix("en")
                .is_some_and(|suffix| suffix.starts_with(|c: char| c.is_ascii_digit()))
            {
                0
            } else if ["eth", "vtnet", "em", "igb", "re", "ix"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
            {
                1
            } else {
                2
            };
            (!active, !has_ipv4, rank, name)
        })
        .map(|iface| iface.name.clone());

    let mut out_ifaces = Vec::new();
    let mut have_lo = false;
    let mut have_eth = false;
    for mut iface in ifaces {
        if iface.name == "lo0" || iface.name == "lo" {
            if have_lo {
                continue;
            }
            have_lo = true;
            iface.name = "lo".to_owned();
            iface.index = 1;
            iface.arphrd = LINUX_ARPHRD_LOOPBACK;
            out_ifaces.push(iface);
        } else if eth_host_name.as_deref() == Some(iface.name.as_str()) {
            if have_eth {
                continue;
            }
            have_eth = true;
            iface.name = "eth0".to_owned();
            iface.index = 2;
            iface.arphrd = LINUX_ARPHRD_ETHER;
            out_ifaces.push(iface);
        }
    }

    let mut out_addrs = Vec::new();
    for mut addr in addrs {
        if addr.name == "lo0" || addr.name == "lo" {
            // Loopback carries `127.0.0.1/8` and `::1/128` only. macOS `lo0` also
            // has `fe80::1%lo0`, which a Linux loopback does not, and libuv's
            // `tcp_connect6_link_local` skips precisely on "is there ANY fe80::
            // address" — so passing it through made the guest RUN a test real
            // Linux declines. `LinuxNetworkModel` already gives loopback exactly
            // `::1/128` for the same reason.
            if addr.family == LINUX_AF_INET6 as u8
                && addr.addr.first().copied() == Some(0xfe)
                && addr.addr.get(1).copied().is_some_and(|b| b & 0xc0 == 0x80)
            {
                continue;
            }
            addr.name = "lo".to_owned();
            addr.index = 1;
            out_addrs.push(addr);
        } else if eth_host_name.as_deref() == Some(addr.name.as_str()) {
            // The uplink carries IPv4 only. Passing the HOST's IPv6 addresses
            // through made the guest advertise an external IPv6 interface it
            // cannot actually use: carrick answers an IPv6 multicast join on it
            // with EADDRNOTAVAIL, and the addresses are the Mac's, not the
            // guest's. `LinuxNetworkModel` already refuses to fabricate one for
            // the same reason ("NO IPv6 on an uplink"); this is the host-mode
            // path, which is the mode the conformance surface runs in, so that
            // decision never reached the guest.
            //
            // It is wrong in both directions, which is why it shows up as two
            // libuv positions: `udp_multicast_join6` RAN and failed where Linux
            // skips ("No external IPv6 interface available"), and
            // `tcp_connect6_link_local` likewise ran where Linux skips — an
            // inversion is as much a parity failure as a missing pass.
            if addr.family == LINUX_AF_INET6 as u8 {
                continue;
            }
            addr.name = "eth0".to_owned();
            addr.index = 2;
            out_addrs.push(addr);
        }
    }

    (out_ifaces, out_addrs)
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

pub(super) fn build_netlink_reply_for_snapshot(
    request: &[u8],
    pid: u32,
    snapshot: &NetworkLinkSnapshot,
) -> Vec<u8> {
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
            for (idx, link) in snapshot.links.iter().enumerate() {
                let index = (idx + 1) as u32;
                let is_loopback = link.name == "lo";
                let mut payload = Vec::new();
                let ifi = LinuxIfInfoMsg {
                    ifi_family: 0,
                    ifi_pad: 0,
                    ifi_type: if is_loopback {
                        LINUX_ARPHRD_LOOPBACK
                    } else {
                        LINUX_ARPHRD_ETHER
                    },
                    ifi_index: index as i32,
                    ifi_flags: if is_loopback {
                        LINUX_IFF_UP | LINUX_IFF_LOOPBACK | LINUX_IFF_RUNNING
                    } else {
                        LINUX_IFF_UP | LINUX_IFF_BROADCAST | LINUX_IFF_RUNNING | LINUX_IFF_MULTICAST
                    },
                    ifi_change: 0,
                };
                payload.extend_from_slice(ifi.as_bytes());
                let mut name = link.name.clone().into_bytes();
                name.push(0);
                push_rtattr(&mut payload, LINUX_IFLA_IFNAME, &name);
                if !is_loopback {
                    let hw_addr = vec![0x02, 0, 0, 0, 0, index as u8];
                    push_rtattr(&mut payload, LINUX_IFLA_ADDRESS, &hw_addr);
                }
                push_nlmsg(&mut out, LINUX_RTM_NEWLINK, seq, pid, &payload);
            }
            push_nlmsg_done(&mut out, seq, pid);
        }
        LINUX_RTM_GETADDR => {
            for address in &snapshot.addresses {
                let Some((family, addr)) = ip_addr_bytes(address.addr) else {
                    continue;
                };
                let index = snapshot_link_index(snapshot, &address.link_name).unwrap_or(1);
                let mut payload = Vec::new();
                let is_v6 = family == LINUX_AF_INET6 as u8;
                let ifa = LinuxIfAddrMsg {
                    ifa_family: family,
                    ifa_prefixlen: address.prefix_len,
                    // Every address in a container netns is statically
                    // configured. Reporting 0 here says "not permanent", which
                    // is not a shape Linux ever emits.
                    ifa_flags: LINUX_IFA_F_PERMANENT as u8,
                    ifa_scope: if address.addr.is_loopback() {
                        LINUX_RT_SCOPE_HOST
                    } else if matches!(
                        address.addr,
                        std::net::IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80
                    ) {
                        // A real `fe80::` is link-scoped; calling it universe
                        // misleads any address-selection logic that reads scope.
                        LINUX_RT_SCOPE_LINK
                    } else {
                        LINUX_RT_SCOPE_UNIVERSE
                    },
                    ifa_index: index,
                };
                payload.extend_from_slice(ifa.as_bytes());
                push_rtattr(&mut payload, LINUX_IFA_ADDRESS, &addr);
                // Linux emits IFA_LOCAL and IFA_LABEL for IPv4 only; on IPv6 it
                // emits neither. Matching the real shape matters because glibc
                // walks these attributes to build its address-selection state.
                if !is_v6 {
                    push_rtattr(&mut payload, LINUX_IFA_LOCAL, &addr);
                    let mut label = address.link_name.as_bytes().to_vec();
                    label.push(0);
                    push_rtattr(&mut payload, LINUX_IFA_LABEL, &label);
                }
                // IFA_CACHEINFO and IFA_FLAGS are on EVERY address Linux
                // reports; glibc reads IFA_FLAGS in preference to the 8-bit
                // header field.
                let mut cacheinfo = Vec::with_capacity(16);
                cacheinfo.extend_from_slice(&LINUX_IFA_INFINITY_LIFE_TIME.to_ne_bytes());
                cacheinfo.extend_from_slice(&LINUX_IFA_INFINITY_LIFE_TIME.to_ne_bytes());
                cacheinfo.extend_from_slice(&0u32.to_ne_bytes());
                cacheinfo.extend_from_slice(&0u32.to_ne_bytes());
                push_rtattr(&mut payload, LINUX_IFA_CACHEINFO, &cacheinfo);
                push_rtattr(
                    &mut payload,
                    LINUX_IFA_FLAGS,
                    &LINUX_IFA_F_PERMANENT.to_ne_bytes(),
                );
                push_nlmsg(&mut out, LINUX_RTM_NEWADDR, seq, pid, &payload);
            }
            push_nlmsg_done(&mut out, seq, pid);
        }
        LINUX_RTM_GETROUTE => {
            for route in &snapshot.routes {
                let route_ip = route.gateway.or(route.destination);
                let Some(route_ip) = route_ip else {
                    continue;
                };
                let Some((family, route_addr)) = ip_addr_bytes(route_ip) else {
                    continue;
                };
                let mut payload = Vec::new();
                let rtm = LinuxRtMsg {
                    rtm_family: family,
                    rtm_dst_len: if route.destination.is_some() {
                        route.destination_prefix_len
                    } else {
                        0
                    },
                    rtm_src_len: 0,
                    rtm_tos: 0,
                    rtm_table: LINUX_RT_TABLE_MAIN,
                    rtm_protocol: LINUX_RTPROT_KERNEL,
                    rtm_scope: if route.gateway.is_some() {
                        LINUX_RT_SCOPE_UNIVERSE
                    } else {
                        LINUX_RT_SCOPE_HOST
                    },
                    rtm_type: LINUX_RTN_UNICAST,
                    rtm_flags: 0,
                };
                payload.extend_from_slice(rtm.as_bytes());
                if route.destination.is_some() {
                    push_rtattr(&mut payload, LINUX_RTA_DST, &route_addr);
                }
                if route.gateway.is_some() {
                    push_rtattr(&mut payload, LINUX_RTA_GATEWAY, &route_addr);
                }
                let oif = snapshot_link_index(snapshot, &route.link_name).unwrap_or(1);
                push_rtattr(&mut payload, LINUX_RTA_OIF, &oif.to_ne_bytes());
                push_nlmsg(&mut out, LINUX_RTM_NEWROUTE, seq, pid, &payload);
            }
            push_nlmsg_done(&mut out, seq, pid);
        }
        LINUX_RTM_GETNEIGH => push_nlmsg_done(&mut out, seq, pid),
        _ => push_nlmsg_done(&mut out, seq, pid),
    }
    out
}

fn snapshot_link_index(snapshot: &NetworkLinkSnapshot, name: &str) -> Option<u32> {
    snapshot
        .links
        .iter()
        .position(|link| link.name == name)
        .map(|idx| (idx + 1) as u32)
}

fn ip_addr_bytes(addr: std::net::IpAddr) -> Option<(u8, Vec<u8>)> {
    match addr {
        std::net::IpAddr::V4(ip) => Some((LINUX_AF_INET as u8, ip.octets().to_vec())),
        std::net::IpAddr::V6(ip) => Some((LINUX_AF_INET6 as u8, ip.octets().to_vec())),
    }
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
    // from_bits_retain: Linux send/recv IGNORE unknown msg_flags bits, and so
    // does this translation (untranslated bits simply don't map to host bits).
    let flags = LinuxMsgFlags::from_bits_retain(flags);
    let mut out = 0;
    if flags.contains(LinuxMsgFlags::OOB) {
        out |= libc::MSG_OOB;
    }
    if flags.contains(LinuxMsgFlags::PEEK) {
        out |= libc::MSG_PEEK;
    }
    if flags.contains(LinuxMsgFlags::DONTROUTE) {
        out |= libc::MSG_DONTROUTE;
    }
    if flags.contains(LinuxMsgFlags::TRUNC) {
        out |= libc::MSG_TRUNC;
    }
    if flags.contains(LinuxMsgFlags::DONTWAIT) {
        out |= libc::MSG_DONTWAIT;
    }
    if flags.contains(LinuxMsgFlags::EOR) {
        out |= libc::MSG_EOR;
    }
    if flags.contains(LinuxMsgFlags::WAITALL) {
        out |= libc::MSG_WAITALL;
    }
    // MSG_NOSIGNAL is Linux-only. macOS expresses the equivalent via
    // SO_NOSIGPIPE on the socket; ignoring the flag is the best we can
    // do here. Likewise MSG_CMSG_CLOEXEC has no macOS equivalent.
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

/// Whether `level` is a socket option level carrick recognizes (the set
/// [`linux_to_host_sockopt`] switches on). getsockopt distinguishes an
/// unrecognized level (EOPNOTSUPP) from an unrecognized optname at a known
/// level (ENOPROTOOPT). (LTP getsockopt01.)
pub(super) fn is_known_sockopt_level(level: i32) -> bool {
    matches!(
        level,
        LINUX_SOL_SOCKET | LINUX_SOL_IP | LINUX_SOL_IPV6 | LINUX_SOL_TCP | LINUX_SOL_UDP
    )
}

/// Whether `(level, optname)` names a socket option carrick EXPLICITLY
/// recognizes and maps to a specific host option — as opposed to an optname it
/// merely passes through to the host by number (the `other => other` arms of
/// [`linux_to_host_sockopt`] at SOL_IP/SOL_IPV6/SOL_UDP) or one it does not map
/// at all.
///
/// Callers use this to SCOPE the EINVAL → ENOPROTOOPT/EOPNOTSUPP remap on the
/// set/getsockopt error path. macOS answers EINVAL for an optname it does not
/// recognize where Linux answers ENOPROTOOPT/EOPNOTSUPP, so an EINVAL from an
/// UNRECOGNIZED optname is remapped — but a RECOGNIZED optname's EINVAL is a
/// genuine bad-argument error (short optlen / out-of-range value) that Linux
/// also reports as EINVAL, so it must pass through UNCHANGED. The recognized
/// set mirrors the explicit match arms of [`linux_to_host_sockopt`] and is
/// host-agnostic (the macOS and non-macOS arms enumerate the same LINUX_*
/// optnames). SOL_UDP recognizes no optname explicitly (every UDP optname is a
/// by-number pass-through), so a host EINVAL there is always the
/// unsupported-optname case and this returns `false`.
pub(super) fn is_known_sockopt_optname(level: i32, optname: i32) -> bool {
    use crate::linux_abi as a;
    match level {
        LINUX_SOL_SOCKET => matches!(
            optname,
            a::LINUX_SO_DEBUG
                | a::LINUX_SO_REUSEADDR
                | a::LINUX_SO_TYPE
                | a::LINUX_SO_ERROR
                | a::LINUX_SO_DONTROUTE
                | a::LINUX_SO_BROADCAST
                | a::LINUX_SO_SNDBUF
                | a::LINUX_SO_RCVBUF
                | a::LINUX_SO_KEEPALIVE
                | a::LINUX_SO_OOBINLINE
                | a::LINUX_SO_LINGER
                | a::LINUX_SO_REUSEPORT
                | a::LINUX_SO_RCVTIMEO
                | a::LINUX_SO_SNDTIMEO
                | a::LINUX_SO_ACCEPTCONN
        ),
        LINUX_SOL_IP => matches!(
            optname,
            a::LINUX_IP_OPTIONS
                | a::LINUX_IP_HDRINCL
                | a::LINUX_IP_TOS
                | a::LINUX_IP_TTL
                | a::LINUX_IP_MULTICAST_IF
                | a::LINUX_IP_MULTICAST_TTL
                | a::LINUX_IP_MULTICAST_LOOP
                | a::LINUX_IP_ADD_MEMBERSHIP
                | a::LINUX_IP_DROP_MEMBERSHIP
                | a::LINUX_IP_UNBLOCK_SOURCE
                | a::LINUX_IP_BLOCK_SOURCE
                | a::LINUX_IP_ADD_SOURCE_MEMBERSHIP
                | a::LINUX_IP_DROP_SOURCE_MEMBERSHIP
                | a::LINUX_IP_RECVTTL
                | a::LINUX_IP_PKTINFO
                | a::LINUX_IP_RECVTOS
        ),
        LINUX_SOL_IPV6 => matches!(
            optname,
            a::LINUX_IPV6_ADDRFORM
                | a::LINUX_IPV6_UNICAST_HOPS
                | a::LINUX_IPV6_MULTICAST_IF
                | a::LINUX_IPV6_MULTICAST_HOPS
                | a::LINUX_IPV6_MULTICAST_LOOP
                | a::LINUX_IPV6_JOIN_GROUP
                | a::LINUX_IPV6_LEAVE_GROUP
                | a::LINUX_IPV6_V6ONLY
                | a::LINUX_IPV6_RECVTCLASS
                | a::LINUX_IPV6_TCLASS
                | a::LINUX_IPV6_RECVHOPLIMIT
                | a::LINUX_IPV6_PKTINFO
                | a::LINUX_IPV6_HOPLIMIT
                | a::LINUX_IPV6_RECVPKTINFO
        ),
        LINUX_SOL_TCP => matches!(
            optname,
            a::LINUX_TCP_NODELAY
                | a::LINUX_TCP_MAXSEG
                | a::LINUX_TCP_CORK
                | a::LINUX_TCP_KEEPIDLE
                | a::LINUX_TCP_KEEPINTVL
                | a::LINUX_TCP_KEEPCNT
        ),
        // SOL_UDP passes every optname through by number (no explicit arm), and
        // an unrecognized LEVEL maps nothing: neither recognizes `optname`.
        _ => false,
    }
}

/// Socket-option constants the NetBSD kernel defines but the `libc` crate does
/// NOT bind for the NetBSD target. Transcribed clean-room from the NetBSD 10.1
/// headers on the build host (each value cites its `/usr/include/...` line).
/// These are the host's NATIVE numbers and are consumed at exactly the sites
/// where the other BSD/Linux arms reference the corresponding `libc::` constant.
#[cfg(target_os = "netbsd")]
mod netbsd_sockopt {
    /// `/usr/include/netinet/in.h:276`   `#define IP_OPTIONS 1`
    pub const IP_OPTIONS: i32 = 1;
    /// `/usr/include/netinet/in.h:295`   `#define IP_RECVTTL 23`
    pub const IP_RECVTTL: i32 = 23;
    /// `/usr/include/netinet6/in6.h:415` `#define IPV6_RECVHOPLIMIT 37`
    pub const IPV6_RECVHOPLIMIT: i32 = 37;
    /// `/usr/include/netinet6/in6.h:429` `#define IPV6_HOPLIMIT 47`
    pub const IPV6_HOPLIMIT: i32 = 47;
    // NOTE: NetBSD has no IP_RECVTOS equivalent (netinet/in.h defines only
    // IP_TOS=3), so there is deliberately no constant for it here.
}

/// Darwin's `struct ip_mreq_source` (`<netinet/in.h>`).
///
/// Same three `struct in_addr` fields as
/// [`crate::linux_abi::LinuxIpMreqSource`], in a DIFFERENT ORDER: Darwin puts
/// the source before the interface. Modelling both layouts
/// as named types means the conversion below reads as what it is — a field
/// remap between two ABIs — instead of an index-arithmetic swap that the next
/// reader has to decode and that silently rots if either layout gains a field.
#[cfg(target_os = "macos")]
#[repr(C, packed)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
struct HostIpMreqSource {
    multiaddr: [u8; 4],
    sourceaddr: [u8; 4],
    interface: [u8; 4],
}

#[cfg(target_os = "macos")]
impl From<crate::linux_abi::LinuxIpMreqSource> for HostIpMreqSource {
    fn from(guest: crate::linux_abi::LinuxIpMreqSource) -> Self {
        Self {
            multiaddr: guest.multiaddr,
            sourceaddr: guest.sourceaddr,
            interface: guest.interface,
        }
    }
}

/// Translate a setsockopt OPTVAL whose STRUCT LAYOUT differs between guest
/// Linux and the host, in place. Returns `true` if it rewrote anything.
///
/// [`linux_to_host_sockopt`] translates the option *number*; this translates the
/// bytes behind it. Today the only such struct is `ip_mreq_source`, used by the
/// source-specific multicast options — passing the guest's bytes through
/// unchanged would join the right group from the wrong source, on the wrong
/// interface, with no error to show for it.
///
/// Non-macOS hosts (Linux and the BSDs) share Linux's field order, so this is a
/// no-op there.
pub(super) fn rewrite_optval_for_host(level: i32, optname: i32, optval: &mut [u8]) -> bool {
    #[cfg(target_os = "macos")]
    {
        use crate::linux_abi as a;
        use zerocopy::{FromBytes, IntoBytes};

        let is_source_membership = level == a::LINUX_SOL_IP
            && matches!(
                optname,
                a::LINUX_IP_ADD_SOURCE_MEMBERSHIP
                    | a::LINUX_IP_DROP_SOURCE_MEMBERSHIP
                    | a::LINUX_IP_BLOCK_SOURCE
                    | a::LINUX_IP_UNBLOCK_SOURCE
            );
        if !is_source_membership {
            return false;
        }
        // A short buffer is the GUEST's bug: let it reach the host so the host
        // answers EINVAL, rather than silently "repairing" it here.
        let Ok(guest) = a::LinuxIpMreqSource::read_from_prefix(optval) else {
            return false;
        };
        let host = HostIpMreqSource::from(guest.0);
        let host_bytes = host.as_bytes();
        optval[..host_bytes.len()].copy_from_slice(host_bytes);
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (level, optname, optval);
        false
    }
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
        // explicitly on macOS (macOS values from <netinet/in.h>; the libc crate is
        // missing several, hence literals). The macOS-literal arm is preserved
        // verbatim (the macOS probe gate is validated against it).
        // Unknown options pass through (best-effort). Constants are fully-qualified
        // so a missing import can't silently become a catch-all binding.
        #[cfg(target_os = "macos")]
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
                // Source-specific multicast: Darwin numbers these 70..73 where
                // Linux uses 37..40, and its `ip_mreq_source` swaps the
                // interface and source fields (see `rewrite_optval_for_host`).
                a::LINUX_IP_UNBLOCK_SOURCE => 73,
                a::LINUX_IP_BLOCK_SOURCE => 72,
                a::LINUX_IP_ADD_SOURCE_MEMBERSHIP => 70,
                a::LINUX_IP_DROP_SOURCE_MEMBERSHIP => 71,
                a::LINUX_IP_RECVTTL => 24,
                a::LINUX_IP_PKTINFO => 26,
                a::LINUX_IP_RECVTOS => 27,
                other => other,
            };
            Some((libc::IPPROTO_IP, host_opt))
        }
        // Every non-macOS host (Linux + the BSDs) translates the guest-Linux
        // IP_* option to the HOST's NATIVE `libc::IP_*` number. On Linux those
        // `libc::IP_*` values EQUAL the guest-Linux values, so this resolves to
        // an identity map (the Linux box stays byte-for-byte unchanged); on
        // FreeBSD/NetBSD they resolve to that host's native numbers, so the
        // translation is faithful by construction. `IP_OPTIONS`/`IP_PKTINFO`
        // are absent from `libc` on FreeBSD, so they fall through to the
        // best-effort pass-through (the same default an unmodelled option takes).
        #[cfg(not(target_os = "macos"))]
        LINUX_SOL_IP => {
            use crate::linux_abi as a;
            let host_opt = match optname {
                a::LINUX_IP_HDRINCL => libc::IP_HDRINCL,
                a::LINUX_IP_TOS => libc::IP_TOS,
                a::LINUX_IP_TTL => libc::IP_TTL,
                a::LINUX_IP_MULTICAST_IF => libc::IP_MULTICAST_IF,
                a::LINUX_IP_MULTICAST_TTL => libc::IP_MULTICAST_TTL,
                a::LINUX_IP_MULTICAST_LOOP => libc::IP_MULTICAST_LOOP,
                a::LINUX_IP_ADD_MEMBERSHIP => libc::IP_ADD_MEMBERSHIP,
                a::LINUX_IP_DROP_MEMBERSHIP => libc::IP_DROP_MEMBERSHIP,
                // NetBSD defines IP_RECVTTL (=23) but the `libc` crate omits it,
                // so use the clean-room NetBSD value there; every other host keeps
                // its `libc::IP_RECVTTL`.
                #[cfg(target_os = "netbsd")]
                a::LINUX_IP_RECVTTL => netbsd_sockopt::IP_RECVTTL,
                #[cfg(not(target_os = "netbsd"))]
                a::LINUX_IP_RECVTTL => libc::IP_RECVTTL,
                // NetBSD has no IP_RECVTOS equivalent (netinet/in.h defines only
                // IP_TOS=3), so gate the arm out on NetBSD; it then falls through
                // to the best-effort pass-through, like any unmodelled option.
                #[cfg(not(target_os = "netbsd"))]
                a::LINUX_IP_RECVTOS => libc::IP_RECVTOS,
                // IP_OPTIONS is absent from `libc` on both FreeBSD and NetBSD.
                // Linux keeps `libc::IP_OPTIONS`; NetBSD supplies the clean-room
                // value (=1); FreeBSD falls through to the pass-through default.
                #[cfg(all(not(target_os = "freebsd"), not(target_os = "netbsd")))]
                a::LINUX_IP_OPTIONS => libc::IP_OPTIONS,
                #[cfg(target_os = "netbsd")]
                a::LINUX_IP_OPTIONS => netbsd_sockopt::IP_OPTIONS,
                #[cfg(not(target_os = "freebsd"))]
                a::LINUX_IP_PKTINFO => libc::IP_PKTINFO,
                other => other,
            };
            Some((libc::IPPROTO_IP, host_opt))
        }
        LINUX_SOL_TCP => {
            let host_opt = match optname {
                LINUX_TCP_NODELAY => libc::TCP_NODELAY,
                LINUX_TCP_MAXSEG => libc::TCP_MAXSEG,
                LINUX_TCP_CORK => carrick_portable::TCP_NOPUSH,
                LINUX_TCP_KEEPIDLE => carrick_portable::TCP_KEEPALIVE,
                LINUX_TCP_KEEPINTVL => libc::TCP_KEEPINTVL,
                LINUX_TCP_KEEPCNT => libc::TCP_KEEPCNT,
                _ => return None,
            };
            Some((libc::IPPROTO_TCP, host_opt))
        }
        LINUX_SOL_UDP => Some((libc::IPPROTO_UDP, optname)),
        // IPPROTO_IPV6 options: same story (macOS <netinet6/in6.h>). The
        // macOS-literal arm is preserved verbatim (validated by the macOS probe
        // gate); macOS gates the RFC 3542 values behind __APPLE_USE_RFC_3542 and
        // the libc crate omits several, hence literals.
        #[cfg(target_os = "macos")]
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
        // Every non-macOS host (Linux + the BSDs) maps the guest-Linux IPV6_*
        // option to the HOST's NATIVE `libc::IPV6_*` number. On Linux those equal
        // the guest-Linux values, so this is an identity map (the Linux box is
        // unchanged); on FreeBSD/NetBSD they resolve to that host's native numbers
        // (e.g. FreeBSD IPV6_HOPLIMIT=47, IPV6_TCLASS=61), so the translation is
        // faithful by construction. Covers the options the probes use
        // (RECVHOPLIMIT/HOPLIMIT/TCLASS/PKTINFO).
        #[cfg(not(target_os = "macos"))]
        LINUX_SOL_IPV6 => {
            use crate::linux_abi as a;
            // The multicast JOIN/LEAVE option is spelled differently in `libc`
            // per host: glibc Linux exposes it as `IPV6_ADD_MEMBERSHIP`/
            // `IPV6_DROP_MEMBERSHIP` (=20/21), the BSDs as `IPV6_JOIN_GROUP`/
            // `IPV6_LEAVE_GROUP` (=12/13). Both name the same option on their
            // host, so select the spelling that exists on the build target.
            #[cfg(target_os = "linux")]
            let (join_group, leave_group) = (libc::IPV6_ADD_MEMBERSHIP, libc::IPV6_DROP_MEMBERSHIP);
            #[cfg(not(target_os = "linux"))]
            let (join_group, leave_group) = (libc::IPV6_JOIN_GROUP, libc::IPV6_LEAVE_GROUP);
            let host_opt = match optname {
                a::LINUX_IPV6_UNICAST_HOPS => libc::IPV6_UNICAST_HOPS,
                a::LINUX_IPV6_MULTICAST_IF => libc::IPV6_MULTICAST_IF,
                a::LINUX_IPV6_MULTICAST_HOPS => libc::IPV6_MULTICAST_HOPS,
                a::LINUX_IPV6_MULTICAST_LOOP => libc::IPV6_MULTICAST_LOOP,
                a::LINUX_IPV6_JOIN_GROUP => join_group,
                a::LINUX_IPV6_LEAVE_GROUP => leave_group,
                a::LINUX_IPV6_V6ONLY => libc::IPV6_V6ONLY,
                a::LINUX_IPV6_RECVTCLASS => libc::IPV6_RECVTCLASS,
                a::LINUX_IPV6_TCLASS => libc::IPV6_TCLASS,
                // NetBSD defines IPV6_RECVHOPLIMIT (=37) and IPV6_HOPLIMIT (=47)
                // but the `libc` crate omits both, so use the clean-room NetBSD
                // values there; every other host keeps its `libc::` constant.
                #[cfg(target_os = "netbsd")]
                a::LINUX_IPV6_RECVHOPLIMIT => netbsd_sockopt::IPV6_RECVHOPLIMIT,
                #[cfg(not(target_os = "netbsd"))]
                a::LINUX_IPV6_RECVHOPLIMIT => libc::IPV6_RECVHOPLIMIT,
                a::LINUX_IPV6_PKTINFO => libc::IPV6_PKTINFO,
                #[cfg(target_os = "netbsd")]
                a::LINUX_IPV6_HOPLIMIT => netbsd_sockopt::IPV6_HOPLIMIT,
                #[cfg(not(target_os = "netbsd"))]
                a::LINUX_IPV6_HOPLIMIT => libc::IPV6_HOPLIMIT,
                a::LINUX_IPV6_RECVPKTINFO => libc::IPV6_RECVPKTINFO,
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

/// Durable, out-of-process reverse-translation for AF_UNIX host nodes. The
/// in-memory `unix_path_registry` is per-process, so a peer socket bound by
/// ANOTHER carrick process (or by this process AFTER a fork diverged) is absent
/// from a querying process's registry, and getsockname/getpeername would leak
/// the raw host `<hash>.sock` node path. To cover that, `bind` stamps the guest
/// `sun_path` into this xattr on the real host node; `host_to_linux_sockaddr`
/// falls back to reading it when the registry misses. `user.carrick.`-prefixed
/// so it is hidden from the guest's listxattr (is_internal_carrick_xattr) and
/// valid on Linux hosts too; fork-coherent because it lives on the on-disk node.
const CARRICK_UNIX_PATH_XATTR: &[u8] = b"user.carrick.unix_path\0";

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

/// NUL-trim a host path and turn it into a C string (`Vec<u8>` ending in NUL)
/// for the path-based xattr syscalls. Returns `None` for an empty path.
fn host_path_cstring(host_path: &[u8]) -> Option<Vec<u8>> {
    let nul = host_path
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(host_path.len());
    if nul == 0 {
        return None;
    }
    let mut c = host_path[..nul].to_vec();
    c.push(0);
    Some(c)
}

/// Stamp the guest `sun_path` for a just-bound AF_UNIX host node into the
/// `user.carrick.unix_path` xattr, so a DIFFERENT carrick process whose
/// in-memory registry lacks this bind can still reverse-translate the node in
/// getsockname/getpeername. The host node is created by `bind(2)`, so this must
/// run AFTER the bind succeeds. Best-effort: on failure (or an unknown node)
/// callers simply fall back to the per-process registry / raw host path.
pub(super) fn persist_unix_path_xattr(host_path: &[u8]) {
    let Some(cpath) = host_path_cstring(host_path) else {
        return;
    };
    // The guest bytes were recorded in the registry by this same process when it
    // translated the bind address (unix_socket_host_path). Only persist what we
    // actually know; never write the raw host path as a "guest" path.
    let Some(guest) = guest_unix_path_for(host_path) else {
        return;
    };
    unsafe {
        carrick_portable::lsetxattr(
            cpath.as_ptr() as *const libc::c_char,
            CARRICK_UNIX_PATH_XATTR.as_ptr() as *const libc::c_char,
            guest.as_ptr() as *const libc::c_void,
            guest.len(),
            0,
        );
    }
}

/// The guest `sun_path` stored in the `user.carrick.unix_path` xattr on a host
/// AF_UNIX node, for cross-process reverse-translation when the per-process
/// registry misses (the peer was bound by another carrick process). `None` if
/// the node has no such xattr.
fn xattr_unix_path_for(host_path: &[u8]) -> Option<Vec<u8>> {
    let cpath = host_path_cstring(host_path)?;
    // A Linux sun_path is at most 108 bytes; 128 is a comfortable ceiling.
    let mut buf = [0u8; 128];
    let n = unsafe {
        carrick_portable::lgetxattr(
            cpath.as_ptr() as *const libc::c_char,
            CARRICK_UNIX_PATH_XATTR.as_ptr() as *const libc::c_char,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if n > 0 {
        Some(buf[..n as usize].to_vec())
    } else {
        None
    }
}

fn is_private_unix_host_path(host_path: &[u8]) -> bool {
    let nul = host_path
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(host_path.len());
    if nul == 0 {
        return false;
    }
    use std::os::unix::ffi::OsStringExt;
    let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(host_path[..nul].to_vec()));
    path.starts_with(unix_socket_host_dir())
}

/// Translate a Linux-formatted sockaddr (read from guest memory) into the
/// macOS BSD form. Returns the host-formatted bytes ready to hand to
/// libc::bind/connect/sendto.
pub(in crate::dispatch) fn read_linux_sockaddr(
    memory: &impl GuestMemory,
    addr: u64,
    addrlen: u32,
    _family_hint: i32,
) -> Result<Vec<u8>, LinuxErrno> {
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
            set_host_sockaddr_header(&mut out, libc::AF_INET);
            out[2..4].copy_from_slice(&bytes[2..4]); // sin_port (network)
            out[4..8].copy_from_slice(&bytes[4..8]); // sin_addr
            // Linux treats the entire 127.0.0.0/8 as loopback (any 127.x.y.z
            // binds/connects on `lo`), but macOS only assigns 127.0.0.1 to lo0,
            // so a host bind/connect to e.g. 127.0.1.1 — the Debian-convention
            // hostname address we seed in /etc/hosts — fails EADDRNOTAVAIL. Fold
            // the whole 127/8 range onto 127.0.0.1 so loopback behaves as Linux
            // apps expect, including `bind((gethostname(), port))`. Applied here
            // (the shared guest→host sockaddr converter) so bind, connect, sendto
            // and sendmsg all translate consistently. Non-loopback addresses pass
            // through untouched.
            if out[4] == 127 && out[4..8] != [127, 0, 0, 1] {
                out[4..8].copy_from_slice(&[127, 0, 0, 1]);
            }
            Ok(out)
        }
        LINUX_AF_INET6 => {
            // sockaddr_in6: family(2) port(2) flowinfo(4) addr(16) scope(4) = 28
            if len < 24 {
                return Err(LINUX_EINVAL);
            }
            let mut out = vec![0u8; 28];
            set_host_sockaddr_header(&mut out, libc::AF_INET6);
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
                    set_host_sockaddr_header(&mut out, libc::AF_UNIX);
                    out[2..2 + pbytes.len()].copy_from_slice(pbytes);
                    Ok(out)
                }
                // Abstract / autobind: pass the raw bytes through unchanged.
                None => {
                    let path_len = len.saturating_sub(2);
                    let mut out = vec![0u8; 2 + path_len];
                    set_host_sockaddr_header(&mut out, libc::AF_UNIX);
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
            set_host_sockaddr_header(&mut out, libc::AF_UNSPEC);
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
    // Host header layout differs (macOS sa_len/sa_family bytes vs the Linux
    // sa_family u16); everything past offset 2 lines up. See host_sockaddr_family.
    let host_family = host_sockaddr_family(bytes);
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
            // Linux sockaddr_un is family(2) path[108]. The host path also
            // starts at offset 2 on BOTH hosts (macOS: after sun_len+sun_family;
            // Linux: after the sun_family u16).
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
            // IT used (not carrick's <hash>.sock host node). Try this process's
            // registry first; on a miss (a peer bound by ANOTHER carrick process,
            // so its mapping isn't in our memory) read the guest path the binder
            // stamped into the node's user.carrick.unix_path xattr. If this is one
            // of Carrick's private hashed socket nodes and both metadata sources
            // miss, return a family-only AF_UNIX address instead of leaking the
            // raw host `<hash>.sock` path to the guest.
            let path_out = guest_unix_path_for(&host_path[..nul])
                .or_else(|| xattr_unix_path_for(&host_path[..nul]));
            let path_bytes: &[u8] = match path_out.as_deref() {
                Some(path) => path,
                None if is_private_unix_host_path(&host_path[..nul]) => &[],
                None => &host_path[..nul],
            };
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

/// Clamp-and-write a scalar `getsockopt` value back to the guest: read the
/// guest's `optlen`, write at most that many bytes of `value` to `optval`, and
/// report the number actually written back in `optlen` (Linux truncation
/// semantics). The option-value analogue of [`write_linux_sockaddr`] — but it
/// reports the *clamped* count, not the full length. Returns `LINUX_EFAULT` on
/// any guest-memory fault, else `Returned { value: 0 }`.
///
/// NOT for the generic host passthrough (which reports the host-updated optlen,
/// not the clamped count) nor the netlink `SO_TYPE` path (which ignores faults).
pub(super) fn write_sockopt_value<M: GuestMemory>(
    memory: &mut M,
    optval_addr: u64,
    optlen_addr: u64,
    value: &[u8],
) -> Result<DispatchOutcome, DispatchError> {
    let guest_optlen = match memory.read_bytes(optlen_addr, 4) {
        Ok(b) => u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
    };
    let n = (guest_optlen as usize).min(value.len());
    if optval_addr != 0 && n > 0 && memory.write_bytes(optval_addr, &value[..n]).is_err() {
        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
    }
    if memory
        .write_bytes(optlen_addr, &(n as u32).to_ne_bytes())
        .is_err()
    {
        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
    }
    Ok(DispatchOutcome::Returned { value: 0 })
}

pub(super) fn read_linux_msghdr(
    memory: &impl GuestMemory,
    addr: u64,
) -> Result<LinuxMsghdr, LinuxErrno> {
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
/// held. Call at every host-fd creation/adoption site (socket/socketpair/
/// accept/pipe/open/dup/SCM_RIGHTS/VFS fd handoff).
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

/// Build the GUEST (Linux-layout) `msg_control` record an `IP_RECVERR` /
/// `IPV6_RECVERR` error-queue read returns: a `sock_extended_err` immediately
/// followed by the offending peer's `sockaddr` (`SO_EE_OFFENDER`).
///
/// libuv reads exactly this — it walks the cmsgs for
/// `(SOL_IP, IP_RECVERR)` / `(SOL_IPV6, IPV6_RECVERR)`, takes `ee_errno`, and
/// takes the peer from `SO_EE_OFFENDER(serr)` — so the two must be adjacent in
/// one record, not two.
///
/// Returns `(bytes, truncated)`; nothing is emitted if a whole record does not
/// fit, and the caller sets `MSG_CTRUNC`.
pub(in crate::dispatch) fn build_linux_recverr(
    errno: i32,
    is_ipv6: bool,
    offender: &[u8],
    cap: usize,
) -> (Vec<u8>, bool) {
    use crate::linux_abi as a;
    const SOCK_EXTENDED_ERR_LEN: usize = 16;
    let data_len = SOCK_EXTENDED_ERR_LEN + offender.len();
    let cmsg_len = LINUX_CMSGHDR_LEN + data_len;
    if cap < cmsg_len {
        return (Vec::new(), true);
    }
    let (level, ty, origin, icmp_type, icmp_code) = if is_ipv6 {
        (
            a::LINUX_SOL_IPV6,
            a::LINUX_IPV6_RECVERR,
            a::LINUX_SO_EE_ORIGIN_ICMP6,
            a::LINUX_ICMPV6_DEST_UNREACH,
            a::LINUX_ICMPV6_PORT_UNREACH,
        )
    } else {
        (
            a::LINUX_SOL_IP,
            a::LINUX_IP_RECVERR,
            a::LINUX_SO_EE_ORIGIN_ICMP,
            a::LINUX_ICMP_DEST_UNREACH,
            a::LINUX_ICMP_PORT_UNREACH,
        )
    };
    let mut buf = vec![0u8; linux_cmsg_align(cmsg_len)];
    buf[0..8].copy_from_slice(&(cmsg_len as u64).to_ne_bytes());
    buf[8..12].copy_from_slice(&level.to_ne_bytes());
    buf[12..16].copy_from_slice(&ty.to_ne_bytes());
    let serr = a::LinuxSockExtendedErr {
        ee_errno: errno as u32,
        ee_origin: origin,
        ee_type: icmp_type,
        ee_code: icmp_code,
        ee_pad: 0,
        ee_info: 0,
        ee_data: 0,
    };
    let serr_bytes = zerocopy::IntoBytes::as_bytes(&serr);
    let at = LINUX_CMSGHDR_LEN;
    buf[at..at + serr_bytes.len()].copy_from_slice(serr_bytes);
    let off_at = at + SOCK_EXTENDED_ERR_LEN;
    buf[off_at..off_at + offender.len()].copy_from_slice(offender);
    (buf, false)
}

/// Build a Linux `SCM_CREDENTIALS` control message carrying `struct ucred {
/// pid, uid, gid }` (12 bytes), bounded by `cap` remaining control bytes.
/// Returns `(bytes, truncated)`; if a full record doesn't fit, emits nothing
/// and reports truncated. (audit M2)
pub(in crate::dispatch) fn build_linux_scm_creds(
    pid: u32,
    uid: u32,
    gid: u32,
    cap: usize,
) -> (Vec<u8>, bool) {
    const UCRED_LEN: usize = 12;
    let cmsg_len = LINUX_CMSGHDR_LEN + UCRED_LEN; // 28
    if cap < cmsg_len {
        return (Vec::new(), true);
    }
    let total = linux_cmsg_align(cmsg_len).min(cap); // 32, clamped to cap
    let mut buf = vec![0u8; total];
    buf[0..8].copy_from_slice(&(cmsg_len as u64).to_ne_bytes());
    buf[8..12].copy_from_slice(&LINUX_SOL_SOCKET.to_ne_bytes());
    buf[12..16].copy_from_slice(&LINUX_SCM_CREDENTIALS.to_ne_bytes());
    buf[16..20].copy_from_slice(&pid.to_ne_bytes());
    buf[20..24].copy_from_slice(&uid.to_ne_bytes());
    buf[24..28].copy_from_slice(&gid.to_ne_bytes());
    (buf, false)
}

/// IPPROTO_IPV6 socket level — 41 on BOTH macOS and Linux (only the per-option
/// TYPE numbers below differ between the two).
pub(in crate::dispatch) const LINUX_IPPROTO_IPV6: i32 = 41;

/// IPv6 RFC 3542 ancillary cmsg-type number translation, host→Linux. macOS and
/// Linux assign DIFFERENT values to the same IPV6_* cmsg types (macOS gates them
/// behind `__APPLE_USE_RFC_3542`). The `setsockopt` optname direction is already
/// translated by `linux_to_host_sockopt`; this covers the returned `recvmsg`
/// cmsg_type, which carrick must translate back so the guest (Linux) sees the
/// expected type. `(linux, host)`. The macOS literal map is preserved verbatim
/// (validated by the macOS probe gate).
#[cfg(target_os = "macos")]
const IPV6_CMSG_MAP: &[(i32, i32)] = &[
    (52, 47), // IPV6_HOPLIMIT  (Linux 52 -> macOS 47)
    (67, 36), // IPV6_TCLASS    (Linux 67 -> macOS 36)
    (50, 46), // IPV6_PKTINFO   (Linux 50 -> macOS 46)
];
/// Every non-macOS host (Linux + the BSDs) maps the guest-Linux cmsg type to the
/// HOST's NATIVE `libc::IPV6_*` cmsg-type number. On Linux those equal the
/// guest-Linux values (the map is identity, so the Linux box is unchanged); on
/// FreeBSD/NetBSD they resolve to that host's native numbers — faithful by
/// construction. The Linux-side keys come from `carrick-abi`'s guest-Linux
/// constants so the wire value the guest sees is exact.
#[cfg(all(not(target_os = "macos"), not(target_os = "netbsd")))]
const IPV6_CMSG_MAP: &[(i32, i32)] = &[
    (crate::linux_abi::LINUX_IPV6_HOPLIMIT, libc::IPV6_HOPLIMIT),
    (crate::linux_abi::LINUX_IPV6_TCLASS, libc::IPV6_TCLASS),
    (crate::linux_abi::LINUX_IPV6_PKTINFO, libc::IPV6_PKTINFO),
];
// NetBSD binds IPV6_TCLASS/IPV6_PKTINFO in `libc` but omits IPV6_HOPLIMIT, so
// supply the clean-room NetBSD cmsg-type number (=47, netinet6/in6.h:429) for
// that one entry; the other two stay on their `libc::` bindings.
#[cfg(target_os = "netbsd")]
const IPV6_CMSG_MAP: &[(i32, i32)] = &[
    (
        crate::linux_abi::LINUX_IPV6_HOPLIMIT,
        netbsd_sockopt::IPV6_HOPLIMIT,
    ),
    (crate::linux_abi::LINUX_IPV6_TCLASS, libc::IPV6_TCLASS),
    (crate::linux_abi::LINUX_IPV6_PKTINFO, libc::IPV6_PKTINFO),
];

/// Translate a macOS IPPROTO_IPV6 cmsg-type back to the guest (Linux) value.
fn ipv6_cmsg_host_to_linux(host: i32) -> Option<i32> {
    IPV6_CMSG_MAP
        .iter()
        .find(|(_, m)| *m == host)
        .map(|(l, _)| *l)
}

/// Translate a guest (Linux) IPPROTO_IPV6 cmsg-type to the macOS value (send).
fn ipv6_cmsg_linux_to_host(linux: i32) -> Option<i32> {
    IPV6_CMSG_MAP
        .iter()
        .find(|(l, _)| *l == linux)
        .map(|(_, m)| *m)
}

/// Parse a GUEST (Linux-layout) `msg_control` buffer and return its IPPROTO_IPV6
/// ancillary records as `(macos_cmsg_type, data)`, cmsg_type translated
/// Linux→macOS, for a host `sendmsg` (e.g. setting IPV6_HOPLIMIT/TCLASS on send).
pub(in crate::dispatch) fn parse_guest_ipv6_cmsgs(control: &[u8]) -> Vec<(i32, Vec<u8>)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + LINUX_CMSGHDR_LEN <= control.len() {
        let cmsg_len =
            u64::from_ne_bytes(control[off..off + 8].try_into().unwrap_or([0; 8])) as usize;
        let level = i32::from_ne_bytes(control[off + 8..off + 12].try_into().unwrap_or([0; 4]));
        let ctype = i32::from_ne_bytes(control[off + 12..off + 16].try_into().unwrap_or([0; 4]));
        if cmsg_len < LINUX_CMSGHDR_LEN || off + cmsg_len > control.len() {
            break;
        }
        if level == LINUX_IPPROTO_IPV6
            && let Some(host_type) = ipv6_cmsg_linux_to_host(ctype)
        {
            out.push((
                host_type,
                control[off + LINUX_CMSGHDR_LEN..off + cmsg_len].to_vec(),
            ));
        }
        off += linux_cmsg_align(cmsg_len);
    }
    out
}

/// Build a HOST (macOS-layout) `msg_control` buffer for the given IPPROTO_IPV6
/// ancillary records (cmsg_type already in macOS values), via the libc CMSG
/// macros so the macOS alignment/len fields are exact. Concatenable after a
/// `build_host_scm_rights` buffer.
pub(in crate::dispatch) fn build_host_ipv6_cmsgs(cmsgs: &[(i32, Vec<u8>)]) -> Vec<u8> {
    if cmsgs.is_empty() {
        return Vec::new();
    }
    let total: usize = cmsgs
        .iter()
        .map(|(_, d)| unsafe { libc::CMSG_SPACE(d.len() as u32) } as usize)
        .sum();
    let mut buf = vec![0u8; total];
    unsafe {
        let mut hmsg: libc::msghdr = std::mem::zeroed();
        hmsg.msg_control = buf.as_mut_ptr() as *mut libc::c_void;
        hmsg.msg_controllen = buf.len() as _;
        let mut cmsg = libc::CMSG_FIRSTHDR(&hmsg);
        for (ctype, data) in cmsgs {
            if cmsg.is_null() {
                break;
            }
            (*cmsg).cmsg_len = libc::CMSG_LEN(data.len() as _) as _;
            (*cmsg).cmsg_level = LINUX_IPPROTO_IPV6; // 41 on both
            (*cmsg).cmsg_type = *ctype;
            std::ptr::copy_nonoverlapping(data.as_ptr(), libc::CMSG_DATA(cmsg), data.len());
            cmsg = libc::CMSG_NXTHDR(&hmsg, cmsg);
        }
    }
    buf
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
    let data_len = std::mem::size_of_val(host_fds) as u32;
    let space = unsafe { libc::CMSG_SPACE(data_len) } as usize;
    let mut buf = vec![0u8; space];
    unsafe {
        // Lay down one cmsghdr at the buffer head via the libc accessor so the
        // macOS-specific alignment/len fields are exactly right.
        let cmsg = buf.as_mut_ptr() as *mut libc::cmsghdr;
        (*cmsg).cmsg_len = libc::CMSG_LEN(data_len as _) as _;
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
    /// `ip_mreq_source` is laid out differently by Linux and Darwin, and the
    /// difference is invisible at the option-number level: both sides accept a
    /// 12-byte buffer and neither reports an error, so getting it wrong joins
    /// the right group from the WRONG source on the WRONG interface, silently.
    ///
    /// Linux: `multiaddr, interface, sourceaddr`.
    /// Darwin: `multiaddr, sourceaddr, interface` (`<netinet/in.h>`).
    #[cfg(target_os = "macos")]
    #[test]
    fn ip_mreq_source_is_remapped_to_darwin_field_order() {
        use crate::linux_abi as a;

        const MULTI: [u8; 4] = [239, 255, 0, 1];
        const IFACE: [u8; 4] = [10, 0, 0, 7];
        const SOURCE: [u8; 4] = [192, 168, 1, 5];

        for optname in [
            a::LINUX_IP_ADD_SOURCE_MEMBERSHIP,
            a::LINUX_IP_DROP_SOURCE_MEMBERSHIP,
            a::LINUX_IP_BLOCK_SOURCE,
            a::LINUX_IP_UNBLOCK_SOURCE,
        ] {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MULTI);
            buf.extend_from_slice(&IFACE);
            buf.extend_from_slice(&SOURCE);
            assert!(super::rewrite_optval_for_host(
                a::LINUX_SOL_IP,
                optname,
                &mut buf
            ));
            assert_eq!(&buf[0..4], &MULTI, "group is field 0 on both");
            assert_eq!(&buf[4..8], &SOURCE, "Darwin puts the SOURCE second");
            assert_eq!(&buf[8..12], &IFACE, "Darwin puts the INTERFACE third");
        }
    }

    /// Only the source-specific options carry that struct. Plain
    /// `IP_ADD_MEMBERSHIP` takes `ip_mreq`, whose two fields are ordered the
    /// same on both systems, and must pass through untouched — and a short
    /// buffer is the guest's bug, to be answered EINVAL by the host rather than
    /// silently repaired here.
    #[cfg(target_os = "macos")]
    #[test]
    fn plain_membership_and_short_buffers_are_left_alone() {
        use crate::linux_abi as a;

        let mut mreq = vec![239, 255, 0, 1, 0, 0, 0, 0];
        let before = mreq.clone();
        assert!(!super::rewrite_optval_for_host(
            a::LINUX_SOL_IP,
            a::LINUX_IP_ADD_MEMBERSHIP,
            &mut mreq
        ));
        assert_eq!(mreq, before);

        let mut short = vec![1u8; 11];
        let before_short = short.clone();
        assert!(!super::rewrite_optval_for_host(
            a::LINUX_SOL_IP,
            a::LINUX_IP_ADD_SOURCE_MEMBERSHIP,
            &mut short
        ));
        assert_eq!(
            short, before_short,
            "a short optval must reach the host as-is"
        );
    }

    use super::*;

    #[test]
    fn inet_raw_socket_uses_unprivileged_datagram_carrier() {
        assert_eq!(
            canonical_socket_errno(LINUX_AF_INET, LINUX_SOCK_RAW, 1),
            None
        );
        #[cfg(carrick_bsd)]
        assert_eq!(
            host_socktype_backing(LINUX_AF_INET, LINUX_SOCK_RAW),
            libc::SOCK_DGRAM
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    struct DecodedRoute {
        dst: Option<std::net::IpAddr>,
        gateway: Option<std::net::IpAddr>,
        oif: Option<u32>,
    }

    fn rtnetlink_request(nlmsg_type: u16) -> Vec<u8> {
        LinuxNlMsgHdr {
            nlmsg_len: std::mem::size_of::<LinuxNlMsgHdr>() as u32,
            nlmsg_type,
            nlmsg_flags: 0,
            nlmsg_seq: 7,
            nlmsg_pid: 0,
        }
        .as_bytes()
        .to_vec()
    }

    fn rtattr_payloads(mut attrs: &[u8], wanted: u16) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let header_len = std::mem::size_of::<LinuxRtAttr>();
        while attrs.len() >= header_len {
            let (attr, _) = LinuxRtAttr::read_from_prefix(attrs).unwrap();
            let attr_len = attr.rta_len as usize;
            if attr_len < header_len || attr_len > attrs.len() {
                break;
            }
            if attr.rta_type == wanted {
                out.push(attrs[header_len..attr_len].to_vec());
            }
            let aligned = attr_len.next_multiple_of(NLMSG_ALIGNTO);
            if aligned == 0 || aligned > attrs.len() {
                break;
            }
            attrs = &attrs[aligned..];
        }
        out
    }

    fn walk_netlink_messages(reply: &[u8], mut f: impl FnMut(u16, &[u8])) {
        let header_len = std::mem::size_of::<LinuxNlMsgHdr>();
        let mut offset = 0;
        while offset + header_len <= reply.len() {
            let (header, _) = LinuxNlMsgHdr::read_from_prefix(&reply[offset..]).unwrap();
            if header.nlmsg_type == LINUX_NLMSG_DONE {
                break;
            }
            let msg_len = header.nlmsg_len as usize;
            assert!(msg_len >= header_len, "invalid netlink message length");
            let end = offset + msg_len;
            assert!(end <= reply.len(), "truncated netlink message");
            f(header.nlmsg_type, &reply[offset + header_len..end]);
            let aligned = msg_len.next_multiple_of(NLMSG_ALIGNTO);
            if aligned == 0 {
                break;
            }
            offset += aligned;
        }
    }

    fn netlink_link_names(model: &NetworkLinkSnapshot) -> Vec<String> {
        let reply =
            build_netlink_reply_for_snapshot(&rtnetlink_request(LINUX_RTM_GETLINK), 42, model);
        let ifinfo_len = std::mem::size_of::<LinuxIfInfoMsg>();
        let mut names = Vec::new();
        walk_netlink_messages(&reply, |kind, payload| {
            if kind != LINUX_RTM_NEWLINK {
                return;
            }
            for name in rtattr_payloads(&payload[ifinfo_len..], LINUX_IFLA_IFNAME) {
                let nul = name
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(name.len());
                names.push(String::from_utf8(name[..nul].to_vec()).unwrap());
            }
        });
        names
    }

    fn netlink_addresses(model: &NetworkLinkSnapshot) -> Vec<std::net::IpAddr> {
        let reply =
            build_netlink_reply_for_snapshot(&rtnetlink_request(LINUX_RTM_GETADDR), 42, model);
        let ifaddr_len = std::mem::size_of::<LinuxIfAddrMsg>();
        let mut addrs = Vec::new();
        walk_netlink_messages(&reply, |kind, payload| {
            if kind != LINUX_RTM_NEWADDR {
                return;
            }
            let (msg, _) = LinuxIfAddrMsg::read_from_prefix(payload).unwrap();
            for addr in rtattr_payloads(&payload[ifaddr_len..], LINUX_IFA_ADDRESS) {
                match msg.ifa_family as i32 {
                    LINUX_AF_INET if addr.len() == 4 => addrs.push(std::net::IpAddr::V4(
                        std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
                    )),
                    LINUX_AF_INET6 if addr.len() == 16 => {
                        let bytes: [u8; 16] = addr.try_into().unwrap();
                        addrs.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes)));
                    }
                    _ => {}
                }
            }
        });
        addrs
    }

    fn netlink_routes(model: &NetworkLinkSnapshot) -> Vec<DecodedRoute> {
        let reply =
            build_netlink_reply_for_snapshot(&rtnetlink_request(LINUX_RTM_GETROUTE), 42, model);
        let rtmsg_len = std::mem::size_of::<LinuxRtMsg>();
        let mut routes = Vec::new();
        walk_netlink_messages(&reply, |kind, payload| {
            if kind != LINUX_RTM_NEWROUTE {
                return;
            }
            let (msg, _) = LinuxRtMsg::read_from_prefix(payload).unwrap();
            let attrs = &payload[rtmsg_len..];
            let decode_ip = |bytes: &[u8]| match msg.rtm_family as i32 {
                LINUX_AF_INET if bytes.len() == 4 => Some(std::net::IpAddr::V4(
                    std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
                )),
                LINUX_AF_INET6 if bytes.len() == 16 => {
                    let bytes: [u8; 16] = bytes.try_into().ok()?;
                    Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
                }
                _ => None,
            };
            let dst = rtattr_payloads(attrs, LINUX_RTA_DST)
                .first()
                .and_then(|bytes| decode_ip(bytes));
            let gateway = rtattr_payloads(attrs, LINUX_RTA_GATEWAY)
                .first()
                .and_then(|bytes| decode_ip(bytes));
            let oif = rtattr_payloads(attrs, LINUX_RTA_OIF)
                .first()
                .and_then(|bytes| bytes.as_slice().try_into().ok())
                .map(u32::from_ne_bytes);
            routes.push(DecodedRoute { dst, gateway, oif });
        });
        routes
    }

    #[test]
    fn two_bridge_network_model_drives_guest_visible_renderers() {
        let mut spec = carrick_spec::NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            Vec::new(),
            Vec::new(),
        );
        spec.dns_search = vec!["svc.test".to_string()];
        spec.dns_options = vec!["ndots:1".to_string()];
        spec.attachments = vec![
            carrick_spec::NetworkAttachmentSpec::bridge_default(
                carrick_spec::BridgeId::new("front"),
                Some("web".to_string()),
                vec!["web-front".to_string()],
                Some(std::net::Ipv4Addr::new(172, 31, 0, 8)),
            ),
            carrick_spec::NetworkAttachmentSpec::bridge_default(
                carrick_spec::BridgeId::new("back"),
                Some("web".to_string()),
                vec!["web-back".to_string()],
                Some(std::net::Ipv4Addr::new(172, 32, 0, 8)),
            ),
        ];
        spec.bridge_id = spec.attachments[0].bridge_id.clone();
        spec.ipv4 = spec.attachments[0].ipv4;
        spec.gateway_v4 = spec.attachments[0].gateway_v4;

        let model = NetworkLinkSnapshot::from_spec(&spec);
        let expected_link_names = model
            .links
            .iter()
            .map(|link| link.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(expected_link_names, vec!["lo", "eth0", "eth1"]);

        let proc_dev = String::from_utf8(model.render_proc_net_dev()).unwrap();
        for link in &model.links {
            assert!(
                proc_dev.contains(&format!("{:>6}:", link.name)),
                "{} missing from /proc/net/dev: {proc_dev}",
                link.name
            );
        }
        assert_eq!(netlink_link_names(&model), expected_link_names);

        let netlink_addrs = netlink_addresses(&model);
        for address in &model.addresses {
            assert!(
                netlink_addrs.contains(&address.addr),
                "{} missing from rtnetlink addresses: {netlink_addrs:?}",
                address.addr
            );
        }

        let proc_route = String::from_utf8(model.render_proc_net_route()).unwrap();
        assert!(
            proc_route.contains("eth0\t00000000\t01001FAC"),
            "default route should use the primary bridge gateway: {proc_route}"
        );
        assert!(
            proc_route.contains("eth1\t000020AC\t00000000"),
            "secondary bridge connected route missing: {proc_route}"
        );
        let netlink_routes = netlink_routes(&model);
        assert!(
            netlink_routes.iter().any(|route| route.gateway
                == Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 31, 0, 1)))
                && route.oif == Some(2)),
            "rtnetlink default route should use eth0 gateway: {netlink_routes:?}"
        );
        assert!(
            netlink_routes.iter().any(|route| route.dst
                == Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 32, 0, 0)))
                && route.oif == Some(3)),
            "rtnetlink secondary connected route should use eth1: {netlink_routes:?}"
        );

        let hosts = model
            .hosts_config(
                &spec,
                [(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 31, 0, 9)),
                    vec!["db".to_string()],
                )],
                &["cache=172.32.0.9".to_string()],
                "surface-host",
            )
            .render();
        assert!(hosts.contains("172.31.0.9\tdb\n"), "{hosts}");
        assert!(
            hosts.contains("172.31.0.1\thost.docker.internal gateway.docker.internal\n"),
            "{hosts}"
        );
        assert!(hosts.contains("172.32.0.9\tcache\n"), "{hosts}");

        let resolv = String::from_utf8(model.render_resolv_conf()).unwrap();
        assert!(resolv.contains("nameserver 172.31.0.1\n"), "{resolv}");
        assert!(resolv.contains("search svc.test\n"), "{resolv}");
        assert!(resolv.contains("options ndots:1\n"), "{resolv}");
    }

    #[test]
    fn host_to_linux_sockaddr_unix_falls_back_to_xattr_across_processes() {
        use std::os::unix::ffi::OsStrExt;
        // Simulate a peer AF_UNIX socket bound by ANOTHER carrick process: the
        // host <hash>.sock node exists with the guest sun_path stored in the
        // user.carrick.unix_path xattr, but THIS process's in-memory
        // unix_path_registry has no entry for it (we never call
        // unix_socket_host_path on this node). getsockname/getpeername must still
        // reverse-translate to the guest path via the xattr, NOT leak the raw
        // host node path.
        //
        // The fallback is stored in an EXTENDED ATTRIBUTE, which is a HOST-
        // filesystem capability, not something carrick can synthesize. Some hosts
        // lack it entirely: stock NetBSD's tmpfs AND FFS both return EOPNOTSUPP
        // for extattr (verified on the CI VM), so `lsetxattr` genuinely fails and
        // the cross-process xattr fallback cannot function there. Detect the
        // capability from the real `lsetxattr` result and assert the correct
        // behavior for each case — never assume the xattr took, never gate the
        // test off.
        let guest_path: &[u8] = b"/run/app/server.sock";
        let pid = std::process::id();
        let node = std::env::temp_dir().join(format!("carrick-xattr-unixpath-test-{pid}.sock"));
        std::fs::write(&node, b"").expect("create temp host node");
        let mut cpath = node.as_os_str().as_bytes().to_vec();
        cpath.push(0);
        let rc = unsafe {
            carrick_portable::lsetxattr(
                cpath.as_ptr() as *const libc::c_char,
                CARRICK_UNIX_PATH_XATTR.as_ptr() as *const libc::c_char,
                guest_path.as_ptr() as *const libc::c_void,
                guest_path.len(),
                0,
            )
        };

        if rc != 0 {
            // The host filesystem does not support extended attributes (stock
            // NetBSD). The cross-process xattr fallback is inoperative by OS
            // limitation, NOT a carrick defect — same-process AF_UNIX via the
            // in-memory registry is unaffected. Assert the DETERMINISTIC degraded
            // contract:
            //   (a) the capability really is absent (readback also unavailable);
            //   (b) carrick never fabricates a guest path from missing metadata,
            //       and for its OWN private hashed nodes it returns a family-only
            //       address rather than leaking the raw host <hash>.sock path.
            assert!(
                xattr_unix_path_for(&cpath).is_none(),
                "xattr readback must also be unavailable on a host without extattr"
            );
            let _ = std::fs::remove_file(&node);

            // A private carrick hash node with neither registry nor xattr
            // metadata must degrade to family-only (the no-leak invariant, which
            // still holds when the host has no extattr).
            let private = unix_socket_host_dir().join(format!("carrick-noxattr-{pid}.sock"));
            std::fs::create_dir_all(unix_socket_host_dir()).expect("create private unix dir");
            std::fs::write(&private, b"").expect("create private host node");
            let mut bytes = vec![0u8, libc::AF_UNIX as u8];
            bytes.extend_from_slice(private.as_os_str().as_bytes());
            bytes.push(0);
            let out = host_to_linux_sockaddr(&bytes, 0, false);
            let _ = std::fs::remove_file(&private);
            assert_eq!(
                out.len(),
                2,
                "without extattr, an unmapped private carrick node must not leak: {out:?}"
            );
            assert_eq!(u16::from_ne_bytes([out[0], out[1]]) as i32, LINUX_AF_UNIX);
            return;
        }

        // The host supports extended attributes: the cross-process fallback must
        // reverse-translate the host node back to the guest sun_path.
        // macOS-form AF_UNIX sockaddr (sa_len, sa_family=AF_UNIX, then path).
        let mut bytes = vec![0u8, libc::AF_UNIX as u8];
        bytes.extend_from_slice(node.as_os_str().as_bytes());
        bytes.push(0);

        let out = host_to_linux_sockaddr(&bytes, 0, false);
        let _ = std::fs::remove_file(&node);

        assert!(
            out.len() >= 2 + guest_path.len(),
            "sockaddr too short: {out:?}"
        );
        assert_eq!(
            &out[2..2 + guest_path.len()],
            guest_path,
            "must reverse-translate the host node to the guest sun_path via the xattr"
        );
    }

    #[test]
    fn host_to_linux_sockaddr_unix_does_not_leak_private_hash_path_without_metadata() {
        use std::os::unix::ffi::OsStrExt;
        let dir = unix_socket_host_dir();
        std::fs::create_dir_all(&dir).expect("create private unix dir");
        let node = dir.join(format!("carrick-unmapped-{}.sock", std::process::id()));
        std::fs::write(&node, b"").expect("create temp host node");

        let mut bytes = vec![0u8, libc::AF_UNIX as u8];
        bytes.extend_from_slice(node.as_os_str().as_bytes());
        bytes.push(0);

        let out = host_to_linux_sockaddr(&bytes, 0, false);
        let _ = std::fs::remove_file(&node);

        assert_eq!(
            out.len(),
            2,
            "unmapped private carrick AF_UNIX host paths must not leak to the guest: {out:?}"
        );
        assert_eq!(u16::from_ne_bytes([out[0], out[1]]) as i32, LINUX_AF_UNIX);
    }

    #[test]
    fn host_fd_has_oob_detects_pending_urgent_byte() {
        // `host_fd_has_oob` answers "is TCP urgent/OOB data pending right now?"
        // for the epoll EPOLLPRI recompute. Its contract is PER-HOST and is
        // asserted here against the REAL mechanism each host uses (no fixed
        // sleep — the test blocks on the exceptional condition, so it is a race-
        // free deterministic wait):
        //   * Darwin (macOS/OpenBSD/DragonFly): `poll(2)` does NOT surface OOB
        //     through POLLPRI, so `host_fd_has_oob` uses a kqueue EVFILT_EXCEPT
        //     probe. Here it must report `false` before the byte and `true`
        //     after (once EVFILT_EXCEPT fires).
        //   * Linux/FreeBSD/NetBSD: OOB readiness is reported by the host's
        //     NATIVE `poll(POLLPRI)`; `host_fd_has_oob` is a deliberate `false`
        //     no-op there (net.rs computes EPOLLPRI from the POLLPRI recompute
        //     and only consults `host_fd_has_oob` as a Darwin fallback). So the
        //     right thing to pin on these hosts is that `poll(POLLPRI)` surfaces
        //     the urgent byte, and that `host_fd_has_oob` stays the no-op.
        use std::mem::MaybeUninit;

        unsafe {
            let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            assert!(listener >= 0);
            let mut addr: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            let alen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            assert_eq!(
                libc::bind(listener, &addr as *const _ as *const libc::sockaddr, alen),
                0
            );
            assert_eq!(libc::listen(listener, 1), 0);
            let mut got: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
            let mut glen = alen;
            assert_eq!(
                libc::getsockname(
                    listener,
                    &mut got as *mut _ as *mut libc::sockaddr,
                    &mut glen
                ),
                0
            );
            let client = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            assert!(client >= 0);
            assert_eq!(
                libc::connect(client, &got as *const _ as *const libc::sockaddr, glen),
                0
            );
            let server = libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut());
            assert!(server >= 0);

            // Before any OOB byte: the kqueue probe reports not-ready (on the
            // no-op hosts this is trivially true, consistent with the contract).
            assert!(
                !host_fd_has_oob(client),
                "no urgent data sent yet — must report not-ready"
            );

            // Send one urgent byte from the server end.
            assert_eq!(
                libc::send(server, b"!".as_ptr().cast(), 1, libc::MSG_OOB),
                1
            );

            #[cfg(any(target_os = "macos", target_os = "openbsd", target_os = "dragonfly"))]
            {
                // Block on EVFILT_EXCEPT until the urgent notification is
                // deliverable — a real wait, not a sleep. Then the level-
                // triggered probe must agree.
                use carrick_host_bsd::Kqueue;
                use carrick_host_bsd::kqueue::{EVFILT_EXCEPT, Kevent, NOTE_OOB};
                let kq = Kqueue::new_internal().expect("kqueue");
                kq.apply(&[Kevent::oob(
                    client,
                    carrick_portable::EV_ADD | carrick_portable::EV_ENABLE,
                )])
                .expect("register EVFILT_EXCEPT");
                let mut out = [Kevent::empty(); 1];
                let timeout = libc::timespec {
                    tv_sec: 5,
                    tv_nsec: 0,
                };
                let n = kq.wait(&[], &mut out, Some(&timeout)).expect("kqueue wait");
                assert!(
                    n >= 1 && out[0].filter() == EVFILT_EXCEPT && out[0].fflags() & NOTE_OOB != 0,
                    "urgent byte must become observable via EVFILT_EXCEPT within 5s"
                );
                assert!(
                    host_fd_has_oob(client),
                    "pending MSG_OOB urgent byte must make host_fd_has_oob report ready"
                );
            }

            #[cfg(not(any(target_os = "macos", target_os = "openbsd", target_os = "dragonfly")))]
            {
                // Block on POLLPRI until the urgent byte is deliverable — the
                // native OOB mechanism these hosts (and net.rs) actually use.
                let mut pfd = libc::pollfd {
                    fd: client,
                    events: libc::POLLPRI,
                    revents: 0,
                };
                let rc = libc::poll(&mut pfd, 1, 5000);
                assert!(
                    rc >= 1,
                    "poll(POLLPRI) must report the urgent byte within 5s (rc={rc})"
                );
                assert!(
                    pfd.revents & libc::POLLPRI != 0,
                    "POLLPRI must be set for a pending OOB byte: revents={}",
                    pfd.revents
                );
                // `host_fd_has_oob` is a documented no-op on these hosts; the
                // native poll above is authoritative for EPOLLPRI there.
                assert!(
                    !host_fd_has_oob(client),
                    "non-Darwin host_fd_has_oob is a documented no-op; native poll handles OOB"
                );
            }

            libc::close(server);
            libc::close(client);
            libc::close(listener);
        }
    }

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
    fn scm_credentials_record_has_linux_cmsg_layout() {
        // M2: build_linux_scm_creds emits a well-formed SCM_CREDENTIALS cmsg:
        // 16-byte header { cmsg_len=28, SOL_SOCKET, SCM_CREDENTIALS } + ucred
        // { pid, uid, gid }, 8-aligned to 32 bytes.
        let (buf, trunc) = build_linux_scm_creds(1234, 1000, 1001, 64);
        assert!(!trunc);
        assert_eq!(buf.len(), 32);
        assert_eq!(u64::from_ne_bytes(buf[0..8].try_into().unwrap()), 28); // cmsg_len
        assert_eq!(
            i32::from_ne_bytes(buf[8..12].try_into().unwrap()),
            LINUX_SOL_SOCKET
        );
        assert_eq!(
            i32::from_ne_bytes(buf[12..16].try_into().unwrap()),
            LINUX_SCM_CREDENTIALS
        );
        assert_eq!(u32::from_ne_bytes(buf[16..20].try_into().unwrap()), 1234); // pid
        assert_eq!(u32::from_ne_bytes(buf[20..24].try_into().unwrap()), 1000); // uid
        assert_eq!(u32::from_ne_bytes(buf[24..28].try_into().unwrap()), 1001); // gid
        // Too small a budget → truncated, nothing emitted.
        let (small, trunc2) = build_linux_scm_creds(1, 2, 3, 16);
        assert!(small.is_empty() && trunc2);
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
    fn guest_interface_view_uses_linux_names() {
        let ifaces = vec![
            HostIface {
                name: "lo0".to_owned(),
                index: 10,
                arphrd: LINUX_ARPHRD_ETHER,
                linux_flags: LINUX_IFF_UP | LINUX_IFF_LOOPBACK | LINUX_IFF_RUNNING,
                hw_addr: Vec::new(),
            },
            HostIface {
                name: "utun0".to_owned(),
                index: 11,
                arphrd: LINUX_ARPHRD_ETHER,
                linux_flags: LINUX_IFF_UP,
                hw_addr: Vec::new(),
            },
            HostIface {
                name: "en4".to_owned(),
                index: 12,
                arphrd: LINUX_ARPHRD_ETHER,
                linux_flags: LINUX_IFF_UP | LINUX_IFF_RUNNING | LINUX_IFF_MULTICAST,
                hw_addr: vec![2, 0, 0, 0, 0, 1],
            },
            HostIface {
                name: "en0".to_owned(),
                index: 13,
                arphrd: LINUX_ARPHRD_ETHER,
                linux_flags: LINUX_IFF_UP | LINUX_IFF_RUNNING | LINUX_IFF_MULTICAST,
                hw_addr: vec![2, 0, 0, 0, 0, 2],
            },
        ];
        let addrs = vec![
            HostAddr {
                index: 10,
                name: "lo0".to_owned(),
                family: LINUX_AF_INET6 as u8,
                addr: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                prefixlen: 128,
                scope: LINUX_RT_SCOPE_HOST,
            },
            HostAddr {
                index: 11,
                name: "utun0".to_owned(),
                family: LINUX_AF_INET6 as u8,
                addr: vec![0; 16],
                prefixlen: 128,
                scope: LINUX_RT_SCOPE_LINK,
            },
            HostAddr {
                index: 13,
                name: "en0".to_owned(),
                family: LINUX_AF_INET6 as u8,
                addr: vec![0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                prefixlen: 64,
                scope: LINUX_RT_SCOPE_LINK,
            },
            HostAddr {
                index: 12,
                name: "en4".to_owned(),
                family: LINUX_AF_INET6 as u8,
                addr: vec![0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                prefixlen: 64,
                scope: LINUX_RT_SCOPE_LINK,
            },
            // A real uplink carries IPv4; the fixture was IPv6-only, which made
            // it indistinguishable from an uplink contributing no address at all.
            HostAddr {
                index: 13,
                name: "en0".to_owned(),
                family: LINUX_AF_INET as u8,
                addr: vec![192, 168, 1, 20],
                prefixlen: 24,
                scope: LINUX_RT_SCOPE_UNIVERSE,
            },
            // macOS loopback also carries `fe80::1%lo0`; a Linux one does not.
            HostAddr {
                index: 10,
                name: "lo0".to_owned(),
                family: LINUX_AF_INET6 as u8,
                addr: vec![0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                prefixlen: 64,
                scope: LINUX_RT_SCOPE_LINK,
            },
        ];

        let (ifaces, addrs) = linux_guest_interfaces(ifaces, addrs);
        let iface_names: Vec<_> = ifaces.iter().map(|iface| iface.name.as_str()).collect();
        assert_eq!(iface_names, ["lo", "eth0"]);
        assert_eq!(ifaces[0].index, 1);
        assert_eq!(ifaces[1].index, 2);
        let addr_names: Vec<_> = addrs.iter().map(|addr| addr.name.as_str()).collect();
        assert_eq!(addr_names, ["lo", "eth0"]);
        assert!(addrs.iter().all(|addr| addr.index == 1 || addr.index == 2));

        // The guest's address set is the one a Docker container has: loopback
        // gets `::1` and IPv4, the uplink gets IPv4 ONLY, and no interface
        // carries an `fe80::`. libuv's `tcp_connect6_link_local` and
        // `udp_multicast_join6` both skip on exactly "is there any fe80::
        // address", so forwarding one made the guest RUN tests Linux declines.
        assert!(
            !addrs.iter().any(|addr| addr.family == LINUX_AF_INET6 as u8
                && addr.addr.first().copied() == Some(0xfe)
                && addr.addr.get(1).copied().is_some_and(|b| b & 0xc0 == 0x80)),
            "no fe80:: address may reach the guest: {addrs:?}"
        );
        assert!(
            !addrs
                .iter()
                .any(|addr| addr.name == "eth0" && addr.family == LINUX_AF_INET6 as u8),
            "the uplink carries IPv4 only: {addrs:?}"
        );
        assert!(
            addrs
                .iter()
                .any(|addr| addr.name == "lo" && addr.family == LINUX_AF_INET6 as u8),
            "loopback keeps ::1: {addrs:?}"
        );
    }

    #[test]
    fn guest_interface_view_accepts_freebsd_uplink_names() {
        let ifaces = vec![
            HostIface {
                name: "lo0".to_owned(),
                index: 1,
                arphrd: LINUX_ARPHRD_LOOPBACK,
                linux_flags: LINUX_IFF_UP | LINUX_IFF_LOOPBACK | LINUX_IFF_RUNNING,
                hw_addr: Vec::new(),
            },
            HostIface {
                name: "cni0".to_owned(),
                index: 2,
                arphrd: LINUX_ARPHRD_ETHER,
                linux_flags: LINUX_IFF_UP | LINUX_IFF_RUNNING,
                hw_addr: vec![2, 0, 0, 0, 0, 2],
            },
            HostIface {
                name: "enc0".to_owned(),
                index: 3,
                arphrd: LINUX_ARPHRD_ETHER,
                linux_flags: LINUX_IFF_UP | LINUX_IFF_RUNNING,
                hw_addr: Vec::new(),
            },
            HostIface {
                name: "en0".to_owned(),
                index: 4,
                arphrd: LINUX_ARPHRD_ETHER,
                linux_flags: 0,
                hw_addr: vec![2, 0, 0, 0, 0, 4],
            },
            HostIface {
                name: "vtnet0".to_owned(),
                index: 5,
                arphrd: LINUX_ARPHRD_ETHER,
                linux_flags: LINUX_IFF_UP | LINUX_IFF_RUNNING,
                hw_addr: vec![2, 0, 0, 0, 0, 5],
            },
        ];
        let addrs = vec![
            HostAddr {
                index: 1,
                name: "lo0".to_owned(),
                family: LINUX_AF_INET as u8,
                addr: vec![127, 0, 0, 1],
                prefixlen: 8,
                scope: LINUX_RT_SCOPE_HOST,
            },
            HostAddr {
                index: 2,
                name: "cni0".to_owned(),
                family: LINUX_AF_INET as u8,
                addr: vec![10, 88, 0, 1],
                prefixlen: 16,
                scope: LINUX_RT_SCOPE_UNIVERSE,
            },
            HostAddr {
                index: 4,
                name: "en0".to_owned(),
                family: LINUX_AF_INET as u8,
                addr: vec![192, 0, 2, 4],
                prefixlen: 24,
                scope: LINUX_RT_SCOPE_UNIVERSE,
            },
            HostAddr {
                index: 5,
                name: "vtnet0".to_owned(),
                family: LINUX_AF_INET as u8,
                addr: vec![10, 14, 14, 189],
                prefixlen: 24,
                scope: LINUX_RT_SCOPE_UNIVERSE,
            },
        ];

        let (ifaces, addrs) = linux_guest_interfaces(ifaces, addrs);
        assert_eq!(
            ifaces
                .iter()
                .map(|iface| iface.name.as_str())
                .collect::<Vec<_>>(),
            ["lo", "eth0"]
        );
        assert!(addrs.iter().any(|addr| {
            addr.name == "eth0" && addr.addr == [10, 14, 14, 189] && addr.index == 2
        }));
        assert!(!addrs.iter().any(|addr| addr.addr == [10, 88, 0, 1]));
    }

    #[test]
    fn bridge_netlink_reports_eth0_address_and_default_route() {
        let spec = carrick_spec::NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            Vec::new(),
            Vec::new(),
        );
        let snapshot = NetworkLinkSnapshot::from_spec(&spec);
        assert!(snapshot.links.iter().any(|l| l.name == "eth0"));
        assert!(
            snapshot
                .addresses
                .iter()
                .any(|a| a.addr == std::net::IpAddr::V4(spec.ipv4))
        );
        assert!(
            snapshot
                .routes
                .iter()
                .any(|r| r.gateway == Some(std::net::IpAddr::V4(spec.gateway_v4)))
        );
    }

    #[test]
    fn bridge_netlink_snapshot_exposes_each_attachment() {
        let mut spec = carrick_spec::NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            Vec::new(),
            Vec::new(),
        );
        spec.attachments = vec![
            carrick_spec::NetworkAttachmentSpec::bridge_default(
                carrick_spec::BridgeId::new("front"),
                Some("web".to_string()),
                vec!["web".to_string()],
                Some(std::net::Ipv4Addr::new(172, 31, 0, 8)),
            ),
            carrick_spec::NetworkAttachmentSpec::bridge_default(
                carrick_spec::BridgeId::new("back"),
                Some("web".to_string()),
                vec!["api".to_string()],
                Some(std::net::Ipv4Addr::new(172, 32, 0, 8)),
            ),
        ];
        spec.bridge_id = spec.attachments[0].bridge_id.clone();
        spec.ipv4 = spec.attachments[0].ipv4;
        spec.gateway_v4 = spec.attachments[0].gateway_v4;

        let snapshot = NetworkLinkSnapshot::from_spec(&spec);
        assert_eq!(
            snapshot
                .links
                .iter()
                .map(|link| link.name.as_str())
                .collect::<Vec<_>>(),
            vec!["lo", "eth0", "eth1"]
        );
        assert!(
            snapshot.addresses.iter().any(|address| address.addr
                == std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 31, 0, 8)))
        );
        assert!(
            snapshot.addresses.iter().any(|address| address.addr
                == std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 32, 0, 8)))
        );
        assert!(snapshot.routes.iter().any(
            |route| route.gateway == Some(std::net::IpAddr::V4(spec.attachments[0].gateway_v4))
        ));
        assert!(snapshot.routes.iter().any(|route| route.destination
            == Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 32, 0, 0)))));
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
        let flags = (LinuxMsgFlags::OOB
            | LinuxMsgFlags::PEEK
            | LinuxMsgFlags::DONTROUTE
            | LinuxMsgFlags::TRUNC
            | LinuxMsgFlags::DONTWAIT
            | LinuxMsgFlags::EOR
            | LinuxMsgFlags::WAITALL
            | LinuxMsgFlags::NOSIGNAL
            | LinuxMsgFlags::CMSG_CLOEXEC)
            .bits();

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
        // Header layout is host-specific (macOS sa_len/sa_family bytes vs the
        // Linux sa_family u16); decode through the same helper the handlers use.
        assert_eq!(host_sockaddr_family(&host), libc::AF_INET as u16);
        #[cfg(target_os = "macos")]
        assert_eq!(host[0], 16);
        assert_eq!(&host[2..8], &linux[2..8]);

        let round_trip = host_to_linux_sockaddr(&host, LINUX_AF_INET, false);
        assert_eq!(round_trip, linux);
    }

    /// An UNNAMED AF_UNIX local address (a socketpair end / unbound socket)
    /// must come back to the guest as a family-only AF_UNIX sockaddr — NOT
    /// AF_UNSPEC. libuv's `uv_guess_handle` keys on the getsockname family to
    /// classify a socket stdio fd; AF_UNSPEC made node wire process.stdout to
    /// a black-hole stream (KVM-lane app-smoke: execFileSync read '' from the
    /// child). The Linux-host header decode (family u16 at offset 0) is what
    /// regressed; build the host bytes with the platform header writer so this
    /// asserts the round-trip on BOTH hosts.
    #[test]
    fn unnamed_unix_local_addr_reports_af_unix_not_unspec() {
        let mut host = vec![0u8; 16]; // zero-filled path = unnamed
        set_host_sockaddr_header(&mut host, libc::AF_UNIX);
        let linux = host_to_linux_sockaddr(&host, LINUX_AF_UNIX, false);
        assert_eq!(linux.len(), 2);
        assert_eq!(
            u16::from_ne_bytes([linux[0], linux[1]]),
            LINUX_AF_UNIX as u16
        );
        // The datagram *peer source* form stays AF_UNSPEC/empty (Go `from == nil`).
        let unspec = host_to_linux_sockaddr(&host, LINUX_AF_UNIX, true);
        assert!(unspec.is_empty());
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

    // The epoll interest-mask → multiplexer `Interest` mapping preserves the
    // HUP/ERR-observability read-fallback (a mask with neither IN nor OUT still
    // arms read) and routes RDHUP/PRI onto read; the actual kqueue filter
    // selection now lives in (and is tested by) `carrick-host-bsd`'s multiplexer.
    #[cfg(feature = "platform-macos")]
    #[test]
    fn epoll_interest_selection_preserves_hup_err_observability() {
        use carrick_hal::event::Interest;
        assert_eq!(
            epoll_interest_for(LinuxEpollEvents::empty()),
            Interest {
                read: true,
                write: false,
                oob: false,
                read_lowat: None,
            }
        );
        assert_eq!(
            epoll_interest_for(LinuxEpollEvents::IN),
            Interest {
                read: true,
                write: false,
                oob: false,
                read_lowat: None,
            }
        );
        assert_eq!(
            epoll_interest_for(LinuxEpollEvents::OUT),
            Interest {
                read: false,
                write: true,
                oob: false,
                read_lowat: None,
            }
        );
        assert_eq!(
            epoll_interest_for(LinuxEpollEvents::IN | LinuxEpollEvents::OUT),
            Interest {
                read: true,
                write: true,
                oob: false,
                read_lowat: None,
            }
        );
        assert_eq!(
            epoll_interest_for(LinuxEpollEvents::PRI),
            Interest {
                read: true,
                write: false,
                oob: true,
                read_lowat: None,
            }
        );
    }

    // `pollevent_to_epoll` must reproduce the direction-sensitive RDHUP/HUP/ERR
    // bits the old `kevent_to_epoll` produced from a single returned kevent.
    #[cfg(feature = "platform-macos")]
    #[test]
    fn pollevent_translation_preserves_rdhup_hup_err_and_pri() {
        use carrick_hal::event::{PollEvent, Readiness};
        let ev = |readiness: Readiness, eof: bool, error: Option<i32>| PollEvent {
            token: 7,
            readiness,
            readiness_count: 0,
            error,
            eof,
            exit_status: None,
            vnode: None,
        };

        // OOB → EPOLLPRI.
        assert_eq!(
            pollevent_to_epoll(&ev(Readiness::OOB, false, None)),
            LINUX_EPOLLPRI
        );
        // Plain read/write readiness.
        assert_eq!(
            pollevent_to_epoll(&ev(Readiness::READ, false, None)),
            LINUX_EPOLLIN
        );
        assert_eq!(
            pollevent_to_epoll(&ev(Readiness::WRITE, false, None)),
            LINUX_EPOLLOUT
        );
        // Read EOF → RDHUP (not HUP); write EOF → HUP.
        assert_eq!(
            pollevent_to_epoll(&ev(Readiness::READ, true, None)),
            LINUX_EPOLLIN | LINUX_EPOLLRDHUP
        );
        assert_eq!(
            pollevent_to_epoll(&ev(Readiness::WRITE, true, None)),
            LINUX_EPOLLOUT | LINUX_EPOLLHUP
        );
        // A carried socket error adds EPOLLERR alongside the direction bits.
        assert_eq!(
            pollevent_to_epoll(&ev(Readiness::READ, true, Some(libc::ECONNRESET))),
            LINUX_EPOLLIN | LINUX_EPOLLRDHUP | LINUX_EPOLLERR
        );
        // A non-IO wake (EVFILT_USER) carries no readiness → no bits.
        assert_eq!(pollevent_to_epoll(&ev(Readiness::empty(), false, None)), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stream_buffer_widening_covers_inet_stream_sockets() {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);
        let result = widen_stream_socket_buffers(fd, LINUX_AF_INET, LINUX_SOCK_STREAM);
        let sndbuf = host_socket_buffer_size(fd, libc::SO_SNDBUF);
        let rcvbuf = host_socket_buffer_size(fd, libc::SO_RCVBUF);
        unsafe { libc::close(fd) };

        result.expect("stream buffer widening should meet required floor");
        assert!(sndbuf.unwrap() >= HOST_STREAM_BUF_REQUIRED);
        assert!(rcvbuf.unwrap() >= HOST_STREAM_BUF_REQUIRED);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stream_buffer_widening_covers_accepted_inet_stream_sockets() {
        use std::os::fd::AsRawFd;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let client = std::net::TcpStream::connect(addr).expect("connect client");
        let (server, _) = listener.accept().expect("accept server");

        let result =
            widen_stream_socket_buffers(server.as_raw_fd(), LINUX_AF_INET, LINUX_SOCK_STREAM);
        let sndbuf = host_socket_buffer_size(server.as_raw_fd(), libc::SO_SNDBUF);
        let rcvbuf = host_socket_buffer_size(server.as_raw_fd(), libc::SO_RCVBUF);

        result.expect("accepted stream buffer widening should meet required floor");
        assert!(sndbuf.unwrap() >= HOST_STREAM_BUF_REQUIRED);
        assert!(rcvbuf.unwrap() >= HOST_STREAM_BUF_REQUIRED);
        drop(client);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stream_buffer_widening_covers_unix_stream_sockets() {
        let mut fds = [-1; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);

        let result = widen_stream_socket_buffers(fds[0], LINUX_AF_UNIX, LINUX_SOCK_STREAM);
        let sndbuf = host_socket_buffer_size(fds[0], libc::SO_SNDBUF);
        let rcvbuf = host_socket_buffer_size(fds[0], libc::SO_RCVBUF);
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }

        result.expect("unix stream buffer widening should meet required floor");
        assert!(sndbuf.unwrap() >= HOST_STREAM_BUF_REQUIRED);
        assert!(rcvbuf.unwrap() >= HOST_STREAM_BUF_REQUIRED);
    }

    /// The `socketpair(2)` HANDLER - not just the helper - must widen both
    /// host fds. `socket` and `accept` called `widen_stream_socket_buffers`;
    /// `socketpair` was the one creation site that never did, so an AF_UNIX
    /// stream pair kept macOS' 8 KiB `net.local.stream.sendspace` where Linux
    /// gives ~208 KiB, and a guest that filled the pair before draining it
    /// (LTP splice05) deadlocked. `stream_buffer_widening_covers_unix_stream_sockets`
    /// above proves the helper works on exactly this socket shape and passed
    /// throughout; only a test that goes through the SYSCALL catches the gap.
    #[cfg(target_os = "macos")]
    #[test]
    fn socketpair_syscall_widens_both_host_stream_buffers() {
        use crate::dispatch::{LinearMemory, SyscallArgs, SyscallRequest};

        const SYS_SOCKETPAIR: u64 = 199;
        let reporter = CompatReporter::default();
        let mut dispatcher = SyscallDispatcher::new();
        let sv = 0x1_0000_u64;
        let mut memory = LinearMemory::new(sv, vec![0u8; 0x1000]);

        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_SOCKETPAIR,
                    SyscallArgs::from([
                        LINUX_AF_UNIX as u64,
                        LINUX_SOCK_STREAM as u64,
                        0,
                        sv,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("socketpair dispatch");
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });

        let pair = memory.read_bytes(sv, 8).expect("read sv");
        for chunk in pair.chunks_exact(4) {
            let guest_fd = i32::from_ne_bytes(chunk.try_into().unwrap());
            let host_fd = dispatcher
                .host_fd_for_poll(guest_fd)
                .expect("socketpair end has a host fd");
            for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
                let size = host_socket_buffer_size(host_fd.get(), opt)
                    .expect("read back the host socket buffer size");
                assert!(
                    size >= HOST_STREAM_BUF_REQUIRED,
                    "socketpair end {guest_fd} opt {opt} is {size}, below the Linux-sized floor",
                );
            }
        }
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

        assert!(
            !dispatcher.fd_is_nonblocking(linux_fd),
            "Linux-visible fd status must preserve blocking mode",
        );
        let host_fd = dispatcher.host_fd_for_poll(linux_fd).unwrap();
        let flags = unsafe { libc::fcntl(host_fd.get(), libc::F_GETFL) };
        assert!(
            flags >= 0 && flags & libc::O_NONBLOCK != 0,
            "host fd must be nonblocking for dispatcher wait invariants",
        );
    }

    #[test]
    fn sockopt_optname_recognition_scopes_einval_remap() {
        use crate::linux_abi as a;
        // RECOGNIZED optnames carrick maps explicitly: a host EINVAL here is a
        // genuine bad-arg error and stays EINVAL (predicate true => remap
        // suppressed). Covers one from each explicitly-mapped level.
        assert!(is_known_sockopt_optname(LINUX_SOL_IP, a::LINUX_IP_TTL));
        assert!(is_known_sockopt_optname(LINUX_SOL_IP, a::LINUX_IP_TOS));
        assert!(is_known_sockopt_optname(LINUX_SOL_TCP, a::LINUX_TCP_MAXSEG));
        assert!(is_known_sockopt_optname(
            LINUX_SOL_TCP,
            a::LINUX_TCP_KEEPIDLE
        ));
        assert!(is_known_sockopt_optname(
            LINUX_SOL_IPV6,
            a::LINUX_IPV6_TCLASS
        ));

        // UNRECOGNIZED optnames (the getsockopt01/setsockopt01 "invalid option
        // name" cases): predicate false => the EINVAL→ENOPROTOOPT/EOPNOTSUPP
        // remap still fires. A made-up optname at IP/IPV6 and EVERY UDP optname
        // (all by-number pass-throughs) are unrecognized.
        assert!(!is_known_sockopt_optname(LINUX_SOL_IP, 0x7fff));
        assert!(!is_known_sockopt_optname(LINUX_SOL_IPV6, 0x7fff));
        assert!(!is_known_sockopt_optname(LINUX_SOL_UDP, a::LINUX_IP_TTL));
        assert!(!is_known_sockopt_optname(LINUX_SOL_UDP, 0x7fff));
        // An unrecognized LEVEL recognizes no optname either.
        assert!(!is_known_sockopt_optname(0x4242, a::LINUX_IP_TTL));
    }
}
