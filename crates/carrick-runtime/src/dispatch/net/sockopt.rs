//! Socket options syscall handlers (`setsockopt`, `getsockopt`).
//!
//! Handles Linux-to-Darwin translation for socket-level, IP-level, and
//! protocol-level options, including synthetic options (e.g. multicast RFC 3678
//! tracking, SO_DOMAIN, SO_PROTOCOL, SO_PEERCRED, IPV6_ADDRFORM) and
//! AF_NETLINK socket option handling.

use super::support::*;
use super::*;

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

impl SyscallDispatcher {
    define_syscall! {
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
            if (level == crate::linux_abi::LINUX_SOL_UDP
                && optname == crate::linux_abi::LINUX_UDP_CORK)
                || (level == crate::linux_abi::LINUX_SOL_TCP
                    && optname == crate::linux_abi::LINUX_TCP_CORK)
            {
                if optlen < 4 {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let b = match memory.read_bytes(optval_addr, 4) {
                    Ok(b) => b,
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                };
                let v = i32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
                if let Some(open_file) = this.open_file(fd)
                    && let Some((flushed, dest)) =
                        open_file.description.common().cork().set_enabled(v != 0)
                {
                    let dest_ptr = dest
                        .as_ref()
                        .map_or(core::ptr::null(), |a| a.as_ptr().cast());
                    let dest_len = dest
                        .as_ref()
                        .map_or(0, |a| a.len() as libc::socklen_t);
                    let send_flags = libc::MSG_DONTWAIT;
                    unsafe {
                        libc::sendto(
                            host_fd.get(),
                            flushed.as_ptr().cast(),
                            flushed.len(),
                            send_flags,
                            dest_ptr,
                            dest_len,
                        );
                    }
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
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
            if (level == crate::linux_abi::LINUX_SOL_UDP
                && optname == crate::linux_abi::LINUX_UDP_CORK)
                || (level == crate::linux_abi::LINUX_SOL_TCP
                    && optname == crate::linux_abi::LINUX_TCP_CORK)
            {
                let enabled = if let Some(open_file) = this.open_file(fd) {
                    if open_file.description.common().cork().enabled {
                        1i32
                    } else {
                        0i32
                    }
                } else {
                    0i32
                };
                return write_sockopt_value(memory, optval_addr, optlen_addr, &enabled.to_ne_bytes());
            }
            if level == LINUX_SOL_SOCKET && optname == crate::linux_abi::LINUX_SO_PEERCRED {
                let (_host_fd, _family) = this.host_socket_lookup(fd)?;
                let (pid, uid, gid) = this.peer_ucred(fd);
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
