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
    LINUX_ARPHRD_ETHER, LINUX_IFF_BROADCAST, LINUX_IFF_MULTICAST, LINUX_IFF_POINTOPOINT,
    LINUX_RT_SCOPE_HOST, LINUX_RT_SCOPE_LINK, LINUX_RT_SCOPE_UNIVERSE, LINUX_RT_TABLE_MAIN,
    LINUX_RTA_DST, LINUX_RTA_OIF, LINUX_RTM_GETNEIGH, LINUX_RTM_GETROUTE, LINUX_RTM_NEWROUTE,
    LINUX_RTN_UNICAST, LINUX_RTPROT_KERNEL, LinuxRtMsg,
};

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
/// BSD kqueue `EV_CLEAR` can spend the only host edge while the guest-side
/// `EPOLLET` latch still suppresses delivery. Keep the host registration
/// level-triggered there and enforce the guest edge contract in software with
/// `EpollInterest::last_ready`. Linux's backend is native epoll, so it keeps
/// the real `EPOLLET` registration.
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(super) fn epoll_host_trigger_mode(
    _events: LinuxEpollEvents,
) -> carrick_hal::event::TriggerMode {
    carrick_hal::event::TriggerMode::Level
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
    guest_abi: LinuxGuestAbi,
) -> Result<DispatchOutcome, DispatchError> {
    let event_size = match guest_abi {
        LinuxGuestAbi::Aarch64 => <LinuxEpollEvent as KernelAbi>::ABI_SIZE,
        LinuxGuestAbi::X86_64 => <LinuxX8664EpollEvent as KernelAbi>::ABI_SIZE,
    };
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
    let add = Kevent::oob(host_fd, libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR);
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
/// `OpenDescription::HostSocket.seqpacket`). Everything else maps 1:1.
pub(super) fn host_socktype_backing(family: i32, base_type: i32) -> i32 {
    if family == LINUX_AF_UNIX && base_type == LINUX_SOCK_SEQPACKET {
        return libc::SOCK_STREAM;
    }
    linux_to_host_socktype(base_type)
}

/// Widen a host AF_UNIX stream/seqpacket socket's send (and recv) buffer beyond
/// macOS' tiny default. Linux-visible `getsockopt(SO_SNDBUF/SO_RCVBUF)` reports
/// the guest-intended/default Linux value from `OpenDescriptionBase`, so this is
/// host-only backing capacity. A guest that writes up to its socket buffer
/// expecting the write to complete WITHOUT a draining reader then blocks forever
/// on a POLLOUT that never comes — e.g. Go's splice/sendfile "Limited" copy, where
/// a writer goroutine pushes a large payload while the reader consumes in large
/// netpoll waits. SO_SNDBUF is the load-bearing option (it governs the writer);
/// SO_RCVBUF is set for symmetry. Best-effort: errors are ignored. No-op for
/// AF_INET (macOS already gives it a large buffer) and for DGRAM (datagram
/// boundary semantics differ — never widen).
pub(super) fn widen_unix_stream_buffers(host_fd: i32, family: i32, base_type: i32) {
    if family != LINUX_AF_UNIX
        || (base_type != LINUX_SOCK_STREAM && base_type != LINUX_SOCK_SEQPACKET)
    {
        return;
    }
    const HOST_UNIX_STREAM_BUF: libc::c_int = 4 * 1024 * 1024;
    for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: host_fd is a live socket fd; the optval is a valid &c_int.
        unsafe {
            libc::setsockopt(
                host_fd,
                libc::SOL_SOCKET,
                opt,
                &HOST_UNIX_STREAM_BUF as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
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
    let eth_host_name = ifaces
        .iter()
        .map(|iface| iface.name.as_str())
        .filter(|name| name.starts_with("en"))
        .min()
        .map(str::to_owned);

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
            addr.name = "lo".to_owned();
            addr.index = 1;
            out_addrs.push(addr);
        } else if eth_host_name.as_deref() == Some(addr.name.as_str()) {
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
                a::LINUX_IP_RECVTTL => libc::IP_RECVTTL,
                a::LINUX_IP_RECVTOS => libc::IP_RECVTOS,
                #[cfg(not(target_os = "freebsd"))]
                a::LINUX_IP_OPTIONS => libc::IP_OPTIONS,
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
                a::LINUX_IPV6_RECVHOPLIMIT => libc::IPV6_RECVHOPLIMIT,
                a::LINUX_IPV6_PKTINFO => libc::IPV6_PKTINFO,
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
            // stamped into the node's user.carrick.unix_path xattr; only a node
            // with neither passes the raw host path through.
            let path_out = guest_unix_path_for(&host_path[..nul])
                .or_else(|| xattr_unix_path_for(&host_path[..nul]));
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
#[cfg(not(target_os = "macos"))]
const IPV6_CMSG_MAP: &[(i32, i32)] = &[
    (crate::linux_abi::LINUX_IPV6_HOPLIMIT, libc::IPV6_HOPLIMIT),
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
    use super::*;

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
        assert_eq!(rc, 0, "setxattr on temp host node must succeed");

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
    fn host_fd_has_oob_detects_pending_urgent_byte() {
        // Darwin's poll(2) does not surface TCP urgent data through POLLPRI, so
        // the epoll readiness recompute must use the kqueue EVFILT_EXCEPT probe.
        // This test pins that contract: a connected TCP socketpair, one MSG_OOB
        // byte sent, and host_fd_has_oob must report the urgent byte on the peer
        // (and report `false` BEFORE the byte is sent). Linux native poll(POLLPRI)
        // also satisfies the post-send assertion, so this runs on either host.
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

            // Before any OOB byte: not ready.
            assert!(
                !host_fd_has_oob(client),
                "no urgent data sent yet — must report not-ready"
            );

            // Send one urgent byte from the server end.
            assert_eq!(
                libc::send(server, b"!".as_ptr().cast(), 1, libc::MSG_OOB),
                1
            );
            // Give the loopback stack a moment to deliver the urgent notification.
            std::thread::sleep(std::time::Duration::from_millis(50));

            assert!(
                host_fd_has_oob(client),
                "pending MSG_OOB urgent byte must make host_fd_has_oob report ready"
            );

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
        ];

        let (ifaces, addrs) = linux_guest_interfaces(ifaces, addrs);
        let iface_names: Vec<_> = ifaces.iter().map(|iface| iface.name.as_str()).collect();
        assert_eq!(iface_names, ["lo", "eth0"]);
        assert_eq!(ifaces[0].index, 1);
        assert_eq!(ifaces[1].index, 2);
        let addr_names: Vec<_> = addrs.iter().map(|addr| addr.name.as_str()).collect();
        assert_eq!(addr_names, ["lo", "eth0"]);
        assert!(addrs.iter().all(|addr| addr.index == 1 || addr.index == 2));
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
            }
        );
        assert_eq!(
            epoll_interest_for(LinuxEpollEvents::IN),
            Interest {
                read: true,
                write: false,
                oob: false,
            }
        );
        assert_eq!(
            epoll_interest_for(LinuxEpollEvents::OUT),
            Interest {
                read: false,
                write: true,
                oob: false,
            }
        );
        assert_eq!(
            epoll_interest_for(LinuxEpollEvents::IN | LinuxEpollEvents::OUT),
            Interest {
                read: true,
                write: true,
                oob: false,
            }
        );
        assert_eq!(
            epoll_interest_for(LinuxEpollEvents::PRI),
            Interest {
                read: true,
                write: false,
                oob: true,
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
        let flags = unsafe { libc::fcntl(host_fd.get(), libc::F_GETFL) };
        assert!(
            flags >= 0 && flags & libc::O_NONBLOCK != 0,
            "host fd must be nonblocking for dispatcher wait invariants",
        );
    }
}
