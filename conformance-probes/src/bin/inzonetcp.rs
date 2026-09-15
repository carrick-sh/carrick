//! Conformance probe for guest loopback TCP stream semantics.
//!
//! Pins Linux semantics for in-zone loopback TCP connections:
//!   1. `listen` on `0.0.0.0:0`, SO_ACCEPTCONN on listening and fresh sockets;
//!   2. `blocking_connect`: address reflection (`getpeername`, `getsockname`),
//!      loopback identity (127.0.0.1);
//!   3. `already_connected`: sockaddr validation and EISCONN on both connected halves;
//!   4. `nonblocking_connect`: immediate return / errno, poll(POLLOUT) readiness,
//!      SO_ERROR readback, and listener accept;
//!   5. `echo64k`: 64 KiB bidirectional stream transfer with deterministic
//!      payload pattern, FNV-1a checksum validation, and short-write detection;
//!   6. `fionread`: `ioctl(FIONREAD)` pending byte count after write;
//!   7. `shutdown_wr`: POLLRDHUP / POLLIN on half-close, EOF read, EPIPE on
//!      write after SHUT_WR, full shutdown readback;
//!   8. `listener_close_with_backlog`: unaccepted connection reset behavior
//!      when listener closes with pending connections in backlog;
//!   9. `tcp_nodelay`: TCP_NODELAY default and set round-trip;
//!   10. `connect_refused`: connect to an unbound port;
//!   11. `getsockopt_types`: SO_TYPE, SO_DOMAIN, SO_PROTOCOL on accepted socket;
//!   12. `bound_client_v4_loopback`: IPv4 client binding loopback to port 0,
//!       endpoint preservation through connect, accepted peer comparison, dup/close and competing binds;
//!   13. `bound_client_v4_wildcard`: IPv4 client binding wildcard to port 0,
//!       endpoint preservation through connect, accepted peer comparison, dup/close and competing binds;
//!   14. `bound_client_v6_loopback`: IPv6 client binding loopback to port 0,
//!       endpoint preservation through connect, accepted peer comparison, dup/close and competing binds;
//!   15. `bound_client_v6_wildcard`: IPv6 client binding wildcard to port 0,
//!       endpoint preservation through connect, accepted peer comparison, dup/close and competing binds;
//!   16. `failed_connect_rollback_v4`: failed connect rollback of bound local endpoint against non-listening target (IPv4);
//!   17. `failed_connect_rollback_v6`: failed connect rollback of bound local endpoint against non-listening target (IPv6);
//!   18. `bind_admission_matrix`: TCP SO_REUSEADDR/SO_REUSEPORT and IPv4/IPv6 bind conflicts;
//!   19. `v4mapped_client_to_v4_listener`: IPv4 listener on 127.0.0.1:0 and, separately, on 0.0.0.0:0,
//!       AF_INET6 client bound to [::]:0 connecting to ::ffff:127.0.0.1:PORT,
//!       address reflection, echo transfer, IPV6_V6ONLY rejection, and [::1] bind refusal;
//!   20. `remote_shutdown_receives_trailing_data`: server writes N bytes then shutdown(SHUT_WR)
//!       (and second variant: close), client with unsent trailing data reads in chunks until EOF,
//!       reporting bytes, recv rc/errno, poll revents, SO_ERROR, and trailing writes.
//!
//! Output is deterministic `key=value` lines only. Every wait is bounded by a
//! `poll` with a 5 s cap so a lost wake is a false line, never a hang.

use conformance_probes::{errno, report};

const POLLRDHUP: libc::c_short = 0x2000;
const SO_DOMAIN: libc::c_int = 39;
const SO_PROTOCOL: libc::c_int = 38;

const ECHO_TOTAL: usize = 65536;

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x1000_0000_01b3)
    })
}

fn set_nonblock(fd: i32) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
}

unsafe fn poll_readable(fd: i32) -> i32 {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    libc::poll(&mut pfd, 1, 5000)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SockFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindKind {
    Loopback,
    Wildcard,
}

struct EndpointHelper;

impl EndpointHelper {
    fn loopback_storage_v4(port_be: u16) -> (libc::sockaddr_storage, libc::socklen_t) {
        unsafe {
            let mut storage: libc::sockaddr_storage = std::mem::zeroed();
            let sin = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in);
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            sin.sin_port = port_be;
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
    }

    fn wildcard_storage_v4(port_be: u16) -> (libc::sockaddr_storage, libc::socklen_t) {
        unsafe {
            let mut storage: libc::sockaddr_storage = std::mem::zeroed();
            let sin = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in);
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_addr.s_addr = libc::INADDR_ANY.to_be();
            sin.sin_port = port_be;
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
    }

    fn loopback_storage_v6(port_be: u16) -> (libc::sockaddr_storage, libc::socklen_t) {
        unsafe {
            let mut storage: libc::sockaddr_storage = std::mem::zeroed();
            let sin6 = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6);
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            };
            sin6.sin6_port = port_be;
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }

    fn wildcard_storage_v6(port_be: u16) -> (libc::sockaddr_storage, libc::socklen_t) {
        unsafe {
            let mut storage: libc::sockaddr_storage = std::mem::zeroed();
            let sin6 = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6);
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_addr = libc::in6_addr { s6_addr: [0u8; 16] };
            sin6.sin6_port = port_be;
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }

    fn mapped_loopback_storage_v6(port_be: u16) -> (libc::sockaddr_storage, libc::socklen_t) {
        unsafe {
            let mut storage: libc::sockaddr_storage = std::mem::zeroed();
            let sin6 = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6);
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1],
            };
            sin6.sin6_port = port_be;
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }

    fn get_port_be(storage: &libc::sockaddr_storage) -> u16 {
        unsafe {
            let family = storage.ss_family as i32;
            if family == libc::AF_INET {
                let sin = &*(storage as *const _ as *const libc::sockaddr_in);
                sin.sin_port
            } else if family == libc::AF_INET6 {
                let sin6 = &*(storage as *const _ as *const libc::sockaddr_in6);
                sin6.sin6_port
            } else {
                0
            }
        }
    }

    fn set_port_be(storage: &mut libc::sockaddr_storage, port_be: u16) {
        unsafe {
            let family = storage.ss_family as i32;
            if family == libc::AF_INET {
                let sin = &mut *(storage as *mut _ as *mut libc::sockaddr_in);
                sin.sin_port = port_be;
            } else if family == libc::AF_INET6 {
                let sin6 = &mut *(storage as *mut _ as *mut libc::sockaddr_in6);
                sin6.sin6_port = port_be;
            }
        }
    }

    fn is_loopback(storage: &libc::sockaddr_storage) -> bool {
        unsafe {
            let family = storage.ss_family as i32;
            if family == libc::AF_INET {
                let sin = &*(storage as *const _ as *const libc::sockaddr_in);
                sin.sin_addr.s_addr == u32::from_ne_bytes([127, 0, 0, 1])
            } else if family == libc::AF_INET6 {
                let sin6 = &*(storage as *const _ as *const libc::sockaddr_in6);
                sin6.sin6_addr.s6_addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            } else {
                false
            }
        }
    }

    fn is_wildcard(storage: &libc::sockaddr_storage) -> bool {
        unsafe {
            let family = storage.ss_family as i32;
            if family == libc::AF_INET {
                let sin = &*(storage as *const _ as *const libc::sockaddr_in);
                sin.sin_addr.s_addr == 0
            } else if family == libc::AF_INET6 {
                let sin6 = &*(storage as *const _ as *const libc::sockaddr_in6);
                sin6.sin6_addr.s6_addr == [0u8; 16]
            } else {
                false
            }
        }
    }

    fn addrs_equal(a: &libc::sockaddr_storage, b: &libc::sockaddr_storage) -> bool {
        unsafe {
            let af = a.ss_family as i32;
            let bf = b.ss_family as i32;
            if af != bf {
                return false;
            }
            if af == libc::AF_INET {
                let sin_a = &*(a as *const _ as *const libc::sockaddr_in);
                let sin_b = &*(b as *const _ as *const libc::sockaddr_in);
                sin_a.sin_addr.s_addr == sin_b.sin_addr.s_addr
            } else if af == libc::AF_INET6 {
                let sin6_a = &*(a as *const _ as *const libc::sockaddr_in6);
                let sin6_b = &*(b as *const _ as *const libc::sockaddr_in6);
                sin6_a.sin6_addr.s6_addr == sin6_b.sin6_addr.s6_addr
            } else {
                false
            }
        }
    }

    fn getsockname(fd: i32) -> (i32, i32, libc::sockaddr_storage, libc::socklen_t) {
        unsafe {
            let mut storage: libc::sockaddr_storage = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            let rc = libc::getsockname(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len);
            let err = if rc == 0 { 0 } else { errno() };
            (rc, err, storage, len)
        }
    }

    fn getpeername(fd: i32) -> (i32, i32, libc::sockaddr_storage, libc::socklen_t) {
        unsafe {
            let mut storage: libc::sockaddr_storage = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            let rc = libc::getpeername(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len);
            let err = if rc == 0 { 0 } else { errno() };
            (rc, err, storage, len)
        }
    }

    fn try_competing_bind(storage: &libc::sockaddr_storage, len: libc::socklen_t) -> (i32, i32) {
        unsafe {
            let family = storage.ss_family as i32;
            let fd = libc::socket(family, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return (-1, errno());
            }
            let rc = libc::bind(fd, storage as *const _ as *const libc::sockaddr, len);
            let err = if rc == 0 { 0 } else { errno() };
            libc::close(fd);
            (rc, err)
        }
    }

    fn format_family_and_addr(storage: &libc::sockaddr_storage) -> (i32, String) {
        unsafe {
            let family = storage.ss_family as i32;
            if family == libc::AF_INET {
                let sin = &*(storage as *const _ as *const libc::sockaddr_in);
                let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                (family, ip.to_string())
            } else if family == libc::AF_INET6 {
                let sin6 = &*(storage as *const _ as *const libc::sockaddr_in6);
                let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                (family, ip.to_string())
            } else {
                (family, "none".to_string())
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ConnectPhaseResult {
    initial_rc: i32,
    initial_errno: i32,
    poll_rc: i32,
    poll_errno: i32,
    so_error_rc: i32,
    so_error: i32,
    completed: bool,
}

unsafe fn perform_nonblocking_connect(
    c_fd: i32,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> ConnectPhaseResult {
    if c_fd < 0 {
        return ConnectPhaseResult {
            initial_rc: -1,
            initial_errno: libc::EBADF,
            poll_rc: 0,
            poll_errno: 0,
            so_error_rc: -1,
            so_error: 0,
            completed: false,
        };
    }
    let rc = libc::connect(c_fd, addr, addrlen);
    let initial_err = if rc == 0 { 0 } else { errno() };
    if rc == 0 {
        return ConnectPhaseResult {
            initial_rc: 0,
            initial_errno: 0,
            poll_rc: 0,
            poll_errno: 0,
            so_error_rc: 0,
            so_error: 0,
            completed: true,
        };
    }
    if initial_err != libc::EINPROGRESS {
        return ConnectPhaseResult {
            initial_rc: rc,
            initial_errno: initial_err,
            poll_rc: 0,
            poll_errno: 0,
            so_error_rc: 0,
            so_error: 0,
            completed: false,
        };
    }
    let mut pfd = libc::pollfd {
        fd: c_fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    let prc = libc::poll(&mut pfd, 1, 5000);
    let poll_err = if prc < 0 { errno() } else { 0 };
    if prc <= 0 {
        return ConnectPhaseResult {
            initial_rc: rc,
            initial_errno: initial_err,
            poll_rc: prc,
            poll_errno: poll_err,
            so_error_rc: -1,
            so_error: 0,
            completed: false,
        };
    }
    let mut so_err: libc::c_int = 0;
    let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let gso_rc = libc::getsockopt(
        c_fd,
        libc::SOL_SOCKET,
        libc::SO_ERROR,
        &mut so_err as *mut _ as *mut libc::c_void,
        &mut optlen,
    );
    let gso_err = if gso_rc == 0 { 0 } else { errno() };
    let completed = gso_rc == 0 && so_err == 0;
    ConnectPhaseResult {
        initial_rc: rc,
        initial_errno: initial_err,
        poll_rc: prc,
        poll_errno: poll_err,
        so_error_rc: gso_rc,
        so_error: if gso_rc == 0 { so_err } else { gso_err },
        completed,
    }
}

unsafe fn run_tcp_disconnect_case(family: SockFamily, disconnect_accepted: bool) {
    let af = if family == SockFamily::V4 { libc::AF_INET } else { libc::AF_INET6 };
    let (mut target, addrlen) = if family == SockFamily::V4 {
        EndpointHelper::loopback_storage_v4(0)
    } else {
        EndpointHelper::loopback_storage_v6(0)
    };
    let listener = libc::socket(af, libc::SOCK_STREAM, 0);
    let bind_rc = libc::bind(listener, (&target as *const libc::sockaddr_storage).cast(), addrlen);
    let listen_rc = if bind_rc == 0 { libc::listen(listener, 4) } else { -1 };
    let (_, _, bound, _) = EndpointHelper::getsockname(listener);
    EndpointHelper::set_port_be(&mut target, EndpointHelper::get_port_be(&bound));
    let client = libc::socket(af, libc::SOCK_STREAM, 0);
    set_nonblock(client);
    let initial = perform_nonblocking_connect(client, (&target as *const libc::sockaddr_storage).cast(), addrlen);
    let accept_poll_rc = poll_readable(listener);
    let accepted = if accept_poll_rc > 0 { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) } else { -1 };
    if accepted >= 0 { set_nonblock(accepted); }
    let (disconnect_fd, old_peer) = if disconnect_accepted { (accepted, client) } else { (client, accepted) };
    let alias = libc::dup(disconnect_fd);
    let (_, _, local_before, _) = EndpointHelper::getsockname(disconnect_fd);
    let queued_write_rc = libc::send(disconnect_fd, b"queued".as_ptr().cast(), 6, libc::MSG_DONTWAIT);
    let queued_write_errno = if queued_write_rc < 0 { errno() } else { 0 };
    let mut unspec: libc::sockaddr_storage = std::mem::zeroed();
    unspec.ss_family = libc::AF_UNSPEC as libc::sa_family_t;
    let disconnect_rc = libc::connect(disconnect_fd, (&unspec as *const libc::sockaddr_storage).cast(), addrlen);
    let disconnect_errno = if disconnect_rc < 0 { errno() } else { 0 };
    let (peername_rc, peername_errno, _, _) = EndpointHelper::getpeername(disconnect_fd);
    let (alias_peername_rc, alias_peername_errno, _, _) = EndpointHelper::getpeername(alias);
    let peer_poll_rc = poll_readable(old_peer);
    let mut queued = [0u8; 6];
    let queued_recv_rc = libc::recv(old_peer, queued.as_mut_ptr().cast(), 6, libc::MSG_DONTWAIT);
    let queued_recv_errno = if queued_recv_rc < 0 { errno() } else { 0 };
    let mut byte = 0u8;
    let reset_recv_rc = libc::recv(old_peer, (&mut byte as *mut u8).cast(), 1, libc::MSG_DONTWAIT);
    let reset_recv_errno = if reset_recv_rc < 0 { errno() } else { 0 };
    let (_, _, local_after, _) = EndpointHelper::getsockname(disconnect_fd);
    let local_port_retained = EndpointHelper::get_port_be(&local_before) == EndpointHelper::get_port_be(&local_after);
    let reconnect = perform_nonblocking_connect(disconnect_fd, (&target as *const libc::sockaddr_storage).cast(), addrlen);
    let reconnect_accept_poll_rc = poll_readable(listener);
    let new_peer = if reconnect_accept_poll_rc > 0 { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) } else { -1 };
    if new_peer >= 0 { set_nonblock(new_peer); }
    libc::close(old_peer);
    let new_write_rc = libc::send(disconnect_fd, b"r".as_ptr().cast(), 1, libc::MSG_DONTWAIT);
    let new_write_errno = if new_write_rc < 0 { errno() } else { 0 };
    let new_peer_poll_rc = poll_readable(new_peer);
    let new_read_rc = libc::recv(new_peer, (&mut byte as *mut u8).cast(), 1, libc::MSG_DONTWAIT);
    let new_read_errno = if new_read_rc < 0 { errno() } else { 0 };
    let name = match (family, disconnect_accepted) {
        (SockFamily::V4, false) => "tcp_disconnect_v4_client",
        (SockFamily::V4, true) => "tcp_disconnect_v4_accepted",
        (SockFamily::V6, false) => "tcp_disconnect_v6_client",
        (SockFamily::V6, true) => "tcp_disconnect_v6_accepted",
    };
    println!("{name}_setup={}", listen_rc == 0 && initial.completed && accepted >= 0);
    println!("{name}_disconnect_rc={disconnect_rc}");
    println!("{name}_disconnect_errno={disconnect_errno}");
    println!("{name}_peername_rc={peername_rc}");
    println!("{name}_peername_errno={peername_errno}");
    println!("{name}_alias_peername_rc={alias_peername_rc}");
    println!("{name}_alias_peername_errno={alias_peername_errno}");
    println!("{name}_queued_write_rc={queued_write_rc}");
    println!("{name}_queued_write_errno={queued_write_errno}");
    println!("{name}_peer_poll_rc={peer_poll_rc}");
    println!("{name}_queued_recv_rc={queued_recv_rc}");
    println!("{name}_queued_recv_errno={queued_recv_errno}");
    println!("{name}_queued_matches={}", queued == *b"queued");
    println!("{name}_reset_recv_rc={reset_recv_rc}");
    println!("{name}_reset_recv_errno={reset_recv_errno}");
    println!("{name}_local_port_retained={local_port_retained}");
    println!("{name}_reconnect_errno={}", if reconnect.completed { 0 } else { reconnect.initial_errno });
    println!("{name}_reconnect_accept_poll_rc={reconnect_accept_poll_rc}");
    println!("{name}_new_write_rc={new_write_rc}");
    println!("{name}_new_write_errno={new_write_errno}");
    println!("{name}_new_peer_poll_rc={new_peer_poll_rc}");
    println!("{name}_new_read_rc={new_read_rc}");
    println!("{name}_new_read_errno={new_read_errno}");
    println!("{name}_new_byte={byte}");
    if alias >= 0 { libc::close(alias); }
    if disconnect_fd >= 0 { libc::close(disconnect_fd); }
    if new_peer >= 0 { libc::close(new_peer); }
    if listener >= 0 { libc::close(listener); }
}

unsafe fn perform_nonblocking_accept(listener_fd: i32) -> i32 {
    let mut pfd = libc::pollfd {
        fd: listener_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    if libc::poll(&mut pfd, 1, 5000) <= 0 || (pfd.revents & libc::POLLIN) == 0 {
        return -1;
    }
    let acc_fd = libc::accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut());
    if acc_fd >= 0 {
        set_nonblock(acc_fd);
    }
    acc_fd
}

unsafe fn test_stream_transfer(fd1: i32, fd2: i32) -> bool {
    let b1 = [b'X'];
    let mut pfd = libc::pollfd {
        fd: fd1,
        events: libc::POLLOUT,
        revents: 0,
    };
    if libc::poll(&mut pfd, 1, 5000) <= 0 || (pfd.revents & libc::POLLOUT) == 0 {
        return false;
    }
    if libc::write(fd1, b1.as_ptr().cast(), 1) != 1 {
        return false;
    }

    let mut pfd2 = libc::pollfd {
        fd: fd2,
        events: libc::POLLIN,
        revents: 0,
    };
    if libc::poll(&mut pfd2, 1, 5000) <= 0 || (pfd2.revents & libc::POLLIN) == 0 {
        return false;
    }
    let mut buf = [0u8; 1];
    if libc::read(fd2, buf.as_mut_ptr().cast(), 1) != 1 || buf[0] != b'X' {
        return false;
    }

    let b2 = [b'Y'];
    let mut pfd2_out = libc::pollfd {
        fd: fd2,
        events: libc::POLLOUT,
        revents: 0,
    };
    if libc::poll(&mut pfd2_out, 1, 5000) <= 0 || (pfd2_out.revents & libc::POLLOUT) == 0 {
        return false;
    }
    if libc::write(fd2, b2.as_ptr().cast(), 1) != 1 {
        return false;
    }

    let mut pfd1_in = libc::pollfd {
        fd: fd1,
        events: libc::POLLIN,
        revents: 0,
    };
    if libc::poll(&mut pfd1_in, 1, 5000) <= 0 || (pfd1_in.revents & libc::POLLIN) == 0 {
        return false;
    }
    let mut buf2 = [0u8; 1];
    if libc::read(fd1, buf2.as_mut_ptr().cast(), 1) != 1 || buf2[0] != b'Y' {
        return false;
    }

    true
}

#[derive(Debug, Clone, Copy)]
struct BoundClientCaseResult {
    listen_ok: bool,
    client_bind_ret: i32,
    client_bind_errno: i32,
    client_pre_gsn_ret: i32,
    client_pre_gsn_errno: i32,
    client_pre_port_nonzero: bool,
    client_pre_addr_ok: bool,
    connect: ConnectPhaseResult,
    connect_ok: bool,
    client_post_port_preserved: bool,
    client_post_addr_loopback: bool,
    client_peer_port_eq_listen: bool,
    client_peer_addr_loopback: bool,
    accepted_peer_port_eq_client_pre: bool,
    accepted_peer_port_eq_client_post: bool,
    accepted_peer_addr_loopback: bool,
    compete_before_close_ret: i32,
    compete_before_close_errno: i32,
    dup_post_close_port_preserved: bool,
    dup_post_close_addr_loopback: bool,
    dup_peer_port_eq_listen: bool,
    dup_stream_ok: bool,
    compete_after_orig_close_ret: i32,
    compete_after_orig_close_errno: i32,
    compete_after_dup_close_ret: i32,
    compete_after_dup_close_errno: i32,
}

unsafe fn run_bound_client_case(family: SockFamily, bind_kind: BindKind) -> BoundClientCaseResult {
    // 1. Listener
    let (l_storage, l_len) = match family {
        SockFamily::V4 => EndpointHelper::loopback_storage_v4(0),
        SockFamily::V6 => EndpointHelper::loopback_storage_v6(0),
    };
    let af = match family {
        SockFamily::V4 => libc::AF_INET,
        SockFamily::V6 => libc::AF_INET6,
    };
    let listener = libc::socket(af, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
    let l_bind_rc = if listener >= 0 {
        libc::bind(
            listener,
            &l_storage as *const _ as *const libc::sockaddr,
            l_len,
        )
    } else {
        -1
    };
    let listen_rc = if l_bind_rc == 0 {
        libc::listen(listener, 8)
    } else {
        -1
    };
    let (l_gsn_rc, _, l_bound_storage, _) = if l_bind_rc == 0 && listen_rc == 0 {
        EndpointHelper::getsockname(listener)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };
    let listen_port_be = EndpointHelper::get_port_be(&l_bound_storage);
    let listen_ok =
        listener >= 0 && l_bind_rc == 0 && listen_rc == 0 && l_gsn_rc == 0 && listen_port_be != 0;

    // 2. Client bind
    let (c_bind_storage, c_bind_len) = match (family, bind_kind) {
        (SockFamily::V4, BindKind::Loopback) => EndpointHelper::loopback_storage_v4(0),
        (SockFamily::V4, BindKind::Wildcard) => EndpointHelper::wildcard_storage_v4(0),
        (SockFamily::V6, BindKind::Loopback) => EndpointHelper::loopback_storage_v6(0),
        (SockFamily::V6, BindKind::Wildcard) => EndpointHelper::wildcard_storage_v6(0),
    };
    let client = libc::socket(af, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
    let c_bind_rc = if client >= 0 {
        libc::bind(
            client,
            &c_bind_storage as *const _ as *const libc::sockaddr,
            c_bind_len,
        )
    } else {
        -1
    };
    let c_bind_errno = if c_bind_rc == 0 { 0 } else { errno() };

    let (c_pre_gsn_rc, c_pre_gsn_errno, c_pre_storage, _) = if c_bind_rc == 0 {
        EndpointHelper::getsockname(client)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };
    let c_pre_port = EndpointHelper::get_port_be(&c_pre_storage);
    let c_pre_port_nonzero = c_pre_gsn_rc == 0 && c_pre_port != 0;
    let c_pre_addr_ok = match bind_kind {
        BindKind::Loopback => c_pre_gsn_rc == 0 && EndpointHelper::is_loopback(&c_pre_storage),
        BindKind::Wildcard => c_pre_gsn_rc == 0 && EndpointHelper::is_wildcard(&c_pre_storage),
    };

    let mut client_compete_storage = c_pre_storage;
    EndpointHelper::set_port_be(&mut client_compete_storage, c_pre_port);
    let client_compete_len = c_bind_len;

    // 3. Connect & Accept
    let (target_storage, target_len) = match family {
        SockFamily::V4 => EndpointHelper::loopback_storage_v4(listen_port_be),
        SockFamily::V6 => EndpointHelper::loopback_storage_v6(listen_port_be),
    };
    let connect_res = if listen_ok && c_bind_rc == 0 && c_pre_port_nonzero {
        perform_nonblocking_connect(
            client,
            &target_storage as *const _ as *const libc::sockaddr,
            target_len,
        )
    } else {
        ConnectPhaseResult {
            initial_rc: -1,
            initial_errno: libc::EBADF,
            poll_rc: 0,
            poll_errno: 0,
            so_error_rc: -1,
            so_error: 0,
            completed: false,
        }
    };
    let acc_fd = if connect_res.completed {
        perform_nonblocking_accept(listener)
    } else {
        -1
    };
    let connect_ok = connect_res.completed && acc_fd >= 0;

    // 4. Post-connect queries
    let (c_post_gsn_rc, _, c_post_storage, _) = if connect_ok {
        EndpointHelper::getsockname(client)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };
    let c_post_port = EndpointHelper::get_port_be(&c_post_storage);
    let client_post_port_preserved =
        connect_ok && c_post_gsn_rc == 0 && c_pre_port_nonzero && c_post_port == c_pre_port;
    let client_post_addr_loopback =
        connect_ok && c_post_gsn_rc == 0 && EndpointHelper::is_loopback(&c_post_storage);

    let (c_gpn_rc, _, c_peer_storage, _) = if connect_ok {
        EndpointHelper::getpeername(client)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };
    let c_peer_port = EndpointHelper::get_port_be(&c_peer_storage);
    let client_peer_port_eq_listen = connect_ok && c_gpn_rc == 0 && c_peer_port == listen_port_be;
    let client_peer_addr_loopback =
        connect_ok && c_gpn_rc == 0 && EndpointHelper::is_loopback(&c_peer_storage);

    let (acc_gpn_rc, _, acc_peer_storage, _) = if acc_fd >= 0 {
        EndpointHelper::getpeername(acc_fd)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };
    let acc_peer_port = EndpointHelper::get_port_be(&acc_peer_storage);
    let accepted_peer_port_eq_client_pre =
        connect_ok && acc_gpn_rc == 0 && c_pre_port_nonzero && acc_peer_port == c_pre_port;
    let accepted_peer_port_eq_client_post =
        connect_ok && acc_gpn_rc == 0 && c_post_gsn_rc == 0 && acc_peer_port == c_post_port;
    let accepted_peer_addr_loopback =
        connect_ok && acc_gpn_rc == 0 && EndpointHelper::is_loopback(&acc_peer_storage);

    // 5. Competing bind before closing original
    let (compete_before_close_ret, compete_before_close_errno) = if c_pre_port_nonzero {
        EndpointHelper::try_competing_bind(&client_compete_storage, client_compete_len)
    } else {
        (-1, -1)
    };

    // 6. Dup client socket & close original
    let dup_fd = if client >= 0 { libc::dup(client) } else { -1 };
    if client >= 0 {
        libc::close(client);
    }
    let (dup_gsn_rc, _, dup_storage, _) = if dup_fd >= 0 {
        EndpointHelper::getsockname(dup_fd)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };
    let dup_port = EndpointHelper::get_port_be(&dup_storage);
    let dup_post_close_port_preserved = connect_ok
        && dup_fd >= 0
        && dup_gsn_rc == 0
        && c_pre_port_nonzero
        && dup_port == c_pre_port;
    let dup_post_close_addr_loopback =
        connect_ok && dup_fd >= 0 && dup_gsn_rc == 0 && EndpointHelper::is_loopback(&dup_storage);

    let (dup_gpn_rc, _, dup_peer_storage, _) = if dup_fd >= 0 {
        EndpointHelper::getpeername(dup_fd)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };
    let dup_peer_port = EndpointHelper::get_port_be(&dup_peer_storage);
    let dup_peer_port_eq_listen =
        connect_ok && dup_fd >= 0 && dup_gpn_rc == 0 && dup_peer_port == listen_port_be;

    let dup_stream_ok = if connect_ok && dup_fd >= 0 && acc_fd >= 0 {
        test_stream_transfer(dup_fd, acc_fd)
    } else {
        false
    };

    // 7. Competing bind after original close (dup alive)
    let (compete_after_orig_close_ret, compete_after_orig_close_errno) = if c_pre_port_nonzero {
        EndpointHelper::try_competing_bind(&client_compete_storage, client_compete_len)
    } else {
        (-1, -1)
    };

    // 8. Close dup_fd
    if dup_fd >= 0 {
        libc::close(dup_fd);
    }

    // 9. Competing bind after dup close (peer acc_fd remains open)
    let (compete_after_dup_close_ret, compete_after_dup_close_errno) = if c_pre_port_nonzero {
        EndpointHelper::try_competing_bind(&client_compete_storage, client_compete_len)
    } else {
        (-1, -1)
    };

    // 10. Cleanup
    if acc_fd >= 0 {
        libc::close(acc_fd);
    }
    if listener >= 0 {
        libc::close(listener);
    }

    BoundClientCaseResult {
        listen_ok,
        client_bind_ret: c_bind_rc,
        client_bind_errno: c_bind_errno,
        client_pre_gsn_ret: c_pre_gsn_rc,
        client_pre_gsn_errno: c_pre_gsn_errno,
        client_pre_port_nonzero: c_pre_port_nonzero,
        client_pre_addr_ok: c_pre_addr_ok,
        connect: connect_res,
        connect_ok,
        client_post_port_preserved,
        client_post_addr_loopback,
        client_peer_port_eq_listen,
        client_peer_addr_loopback,
        accepted_peer_port_eq_client_pre,
        accepted_peer_port_eq_client_post,
        accepted_peer_addr_loopback,
        compete_before_close_ret,
        compete_before_close_errno,
        dup_post_close_port_preserved,
        dup_post_close_addr_loopback,
        dup_peer_port_eq_listen,
        dup_stream_ok,
        compete_after_orig_close_ret,
        compete_after_orig_close_errno,
        compete_after_dup_close_ret,
        compete_after_dup_close_errno,
    }
}

#[derive(Debug, Clone, Copy)]
struct FailedConnectResult {
    bind_ret: i32,
    bind_errno: i32,
    pre_gsn_ret: i32,
    pre_gsn_errno: i32,
    pre_port_nonzero: bool,
    pre_addr_ok: bool,
    connect: ConnectPhaseResult,
    post_gsn_ret: i32,
    post_gsn_errno: i32,
    post_port_preserved: bool,
    post_addr_ok: bool,
    post_gpn_ret: i32,
    post_gpn_errno: i32,
}

unsafe fn run_failed_connect_case(
    family: SockFamily,
    bind_kind: BindKind,
    target_storage: &libc::sockaddr_storage,
    target_len: libc::socklen_t,
) -> FailedConnectResult {
    let af = match family {
        SockFamily::V4 => libc::AF_INET,
        SockFamily::V6 => libc::AF_INET6,
    };
    let (c_bind_storage, c_bind_len) = match (family, bind_kind) {
        (SockFamily::V4, BindKind::Loopback) => EndpointHelper::loopback_storage_v4(0),
        (SockFamily::V4, BindKind::Wildcard) => EndpointHelper::wildcard_storage_v4(0),
        (SockFamily::V6, BindKind::Loopback) => EndpointHelper::loopback_storage_v6(0),
        (SockFamily::V6, BindKind::Wildcard) => EndpointHelper::wildcard_storage_v6(0),
    };
    let fd = libc::socket(af, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
    let bind_ret = if fd >= 0 {
        libc::bind(
            fd,
            &c_bind_storage as *const _ as *const libc::sockaddr,
            c_bind_len,
        )
    } else {
        -1
    };
    let bind_errno = if bind_ret == 0 { 0 } else { errno() };

    let (pre_gsn_ret, pre_gsn_errno, pre_storage, _) = if bind_ret == 0 {
        EndpointHelper::getsockname(fd)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };
    let pre_port = EndpointHelper::get_port_be(&pre_storage);
    let pre_port_nonzero = pre_gsn_ret == 0 && pre_port != 0;
    let pre_addr_ok = match bind_kind {
        BindKind::Loopback => pre_gsn_ret == 0 && EndpointHelper::is_loopback(&pre_storage),
        BindKind::Wildcard => pre_gsn_ret == 0 && EndpointHelper::is_wildcard(&pre_storage),
    };

    let connect_res = if bind_ret == 0 && pre_port_nonzero {
        perform_nonblocking_connect(
            fd,
            target_storage as *const _ as *const libc::sockaddr,
            target_len,
        )
    } else {
        ConnectPhaseResult {
            initial_rc: -1,
            initial_errno: libc::EBADF,
            poll_rc: 0,
            poll_errno: 0,
            so_error_rc: -1,
            so_error: 0,
            completed: false,
        }
    };

    let (post_gsn_ret, post_gsn_errno, post_storage, _) = if fd >= 0 {
        EndpointHelper::getsockname(fd)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };
    let post_port = EndpointHelper::get_port_be(&post_storage);
    let post_port_preserved = bind_ret == 0
        && pre_gsn_ret == 0
        && pre_port_nonzero
        && post_gsn_ret == 0
        && post_port == pre_port;
    let post_addr_ok = bind_ret == 0
        && pre_gsn_ret == 0
        && post_gsn_ret == 0
        && EndpointHelper::addrs_equal(&pre_storage, &post_storage);

    let (post_gpn_ret, post_gpn_errno, _, _) = if fd >= 0 {
        EndpointHelper::getpeername(fd)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };

    if fd >= 0 {
        libc::close(fd);
    }

    FailedConnectResult {
        bind_ret,
        bind_errno,
        pre_gsn_ret,
        pre_gsn_errno,
        pre_port_nonzero,
        pre_addr_ok,
        connect: connect_res,
        post_gsn_ret,
        post_gsn_errno,
        post_port_preserved,
        post_addr_ok,
        post_gpn_ret,
        post_gpn_errno,
    }
}

#[derive(Debug, Clone, Copy)]
struct BindAdmissionResult {
    setup_ok: bool,
    v6only_setopt_ret: i32,
    v6only_setopt_errno: i32,
    first_bind_ret: i32,
    first_bind_errno: i32,
    first_port_nonzero: bool,
    second_bind_ret: i32,
    second_bind_errno: i32,
    first_listen_attempted: bool,
    first_listen_ret: i32,
    first_listen_errno: i32,
    second_listen_attempted: bool,
    second_listen_ret: i32,
    second_listen_errno: i32,
    cleanup_ok: bool,
}

unsafe fn set_socket_option(fd: i32, level: i32, optname: i32, value: i32) -> (i32, i32) {
    if fd < 0 {
        return (-1, libc::EBADF);
    }
    let rc = libc::setsockopt(
        fd,
        level,
        optname,
        &value as *const _ as *const libc::c_void,
        std::mem::size_of_val(&value) as libc::socklen_t,
    );
    (rc, if rc == 0 { 0 } else { errno() })
}

unsafe fn run_v4_bind_admission_case(
    first_reuseaddr: bool,
    first_reuseport: bool,
    second_reuseaddr: bool,
    second_reuseport: bool,
) -> BindAdmissionResult {
    let first = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let second = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let first_addr_opt = set_socket_option(
        first,
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        first_reuseaddr as i32,
    );
    let first_port_opt = set_socket_option(
        first,
        libc::SOL_SOCKET,
        libc::SO_REUSEPORT,
        first_reuseport as i32,
    );
    let second_addr_opt = set_socket_option(
        second,
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        second_reuseaddr as i32,
    );
    let second_port_opt = set_socket_option(
        second,
        libc::SOL_SOCKET,
        libc::SO_REUSEPORT,
        second_reuseport as i32,
    );
    let (first_addr, first_len) = EndpointHelper::loopback_storage_v4(0);
    let first_bind_ret = if first >= 0 {
        libc::bind(
            first,
            &first_addr as *const _ as *const libc::sockaddr,
            first_len,
        )
    } else {
        -1
    };
    let first_bind_errno = if first_bind_ret == 0 { 0 } else { errno() };
    let (_, _, first_bound, _) = if first_bind_ret == 0 {
        EndpointHelper::getsockname(first)
    } else {
        (-1, libc::EBADF, std::mem::zeroed(), 0)
    };
    let first_port = EndpointHelper::get_port_be(&first_bound);
    let first_port_nonzero = first_bind_ret == 0 && first_port != 0;
    let mut second_addr = first_bound;
    EndpointHelper::set_port_be(&mut second_addr, first_port);
    let second_bind_ret = if second >= 0 && first_port_nonzero {
        libc::bind(
            second,
            &second_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    } else {
        -1
    };
    let second_bind_errno = if second_bind_ret == 0 {
        0
    } else if first_port_nonzero {
        errno()
    } else {
        libc::EBADF
    };
    let first_listen_attempted = first_bind_ret == 0;
    let first_listen_ret = if first_listen_attempted {
        libc::listen(first, 1)
    } else {
        -1
    };
    let first_listen_errno = if !first_listen_attempted || first_listen_ret == 0 {
        0
    } else {
        errno()
    };
    let second_listen_attempted = second_bind_ret == 0;
    let second_listen_ret = if second_listen_attempted {
        libc::listen(second, 1)
    } else {
        -1
    };
    let second_listen_errno = if !second_listen_attempted || second_listen_ret == 0 {
        0
    } else {
        errno()
    };
    let cleanup_ok =
        (first < 0 || libc::close(first) == 0) && (second < 0 || libc::close(second) == 0);
    BindAdmissionResult {
        setup_ok: first >= 0
            && second >= 0
            && first_addr_opt.0 == 0
            && first_port_opt.0 == 0
            && second_addr_opt.0 == 0
            && second_port_opt.0 == 0,
        v6only_setopt_ret: 0,
        v6only_setopt_errno: 0,
        first_bind_ret,
        first_bind_errno,
        first_port_nonzero,
        second_bind_ret,
        second_bind_errno,
        first_listen_attempted,
        first_listen_ret,
        first_listen_errno,
        second_listen_attempted,
        second_listen_ret,
        second_listen_errno,
        cleanup_ok,
    }
}

unsafe fn run_v6_to_v4_bind_admission_case(v6only: bool, mapped: bool) -> BindAdmissionResult {
    let first = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
    let second = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let v6only_opt = set_socket_option(first, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, v6only as i32);
    let (first_addr, first_len) = if mapped {
        EndpointHelper::mapped_loopback_storage_v6(0)
    } else {
        EndpointHelper::wildcard_storage_v6(0)
    };
    let first_bind_ret = if first >= 0 {
        libc::bind(
            first,
            &first_addr as *const _ as *const libc::sockaddr,
            first_len,
        )
    } else {
        -1
    };
    let first_bind_errno = if first_bind_ret == 0 { 0 } else { errno() };
    let (_, _, first_bound, _) = if first_bind_ret == 0 {
        EndpointHelper::getsockname(first)
    } else {
        (-1, libc::EBADF, std::mem::zeroed(), 0)
    };
    let first_port = EndpointHelper::get_port_be(&first_bound);
    let first_port_nonzero = first_bind_ret == 0 && first_port != 0;
    let (second_addr, second_len) = EndpointHelper::loopback_storage_v4(first_port);
    let second_bind_ret = if second >= 0 && first_port_nonzero {
        libc::bind(
            second,
            &second_addr as *const _ as *const libc::sockaddr,
            second_len,
        )
    } else {
        -1
    };
    let second_bind_errno = if second_bind_ret == 0 {
        0
    } else if first_port_nonzero {
        errno()
    } else {
        libc::EBADF
    };
    let first_listen_attempted = first_bind_ret == 0;
    let first_listen_ret = if first_listen_attempted {
        libc::listen(first, 1)
    } else {
        -1
    };
    let first_listen_errno = if !first_listen_attempted || first_listen_ret == 0 {
        0
    } else {
        errno()
    };
    let second_listen_attempted = second_bind_ret == 0;
    let second_listen_ret = if second_listen_attempted {
        libc::listen(second, 1)
    } else {
        -1
    };
    let second_listen_errno = if !second_listen_attempted || second_listen_ret == 0 {
        0
    } else {
        errno()
    };
    let cleanup_ok =
        (first < 0 || libc::close(first) == 0) && (second < 0 || libc::close(second) == 0);
    BindAdmissionResult {
        setup_ok: first >= 0 && second >= 0 && v6only_opt.0 == 0,
        v6only_setopt_ret: v6only_opt.0,
        v6only_setopt_errno: v6only_opt.1,
        first_bind_ret,
        first_bind_errno,
        first_port_nonzero,
        second_bind_ret,
        second_bind_errno,
        first_listen_attempted,
        first_listen_ret,
        first_listen_errno,
        second_listen_attempted,
        second_listen_ret,
        second_listen_errno,
        cleanup_ok,
    }
}

#[derive(Debug, Clone)]
struct V4MappedCaseResult {
    connect_ret: i32,
    connect_errno: i32,
    accepted_peer_family: i32,
    accepted_peer_addr: String,
    client_peer_family: i32,
    client_peer_addr: String,
    client_sockname_family: i32,
    client_sockname_addr: String,
    echo_ok: bool,
}

unsafe fn run_v4mapped_case(bind_kind: BindKind) -> V4MappedCaseResult {
    let (l_storage, l_len) = match bind_kind {
        BindKind::Loopback => EndpointHelper::loopback_storage_v4(0),
        BindKind::Wildcard => EndpointHelper::wildcard_storage_v4(0),
    };
    let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let l_bind_rc = if listener >= 0 {
        libc::bind(
            listener,
            &l_storage as *const _ as *const libc::sockaddr,
            l_len,
        )
    } else {
        -1
    };
    let listen_rc = if l_bind_rc == 0 {
        libc::listen(listener, 4)
    } else {
        -1
    };
    let (_, _, l_bound, _) = if listen_rc == 0 {
        EndpointHelper::getsockname(listener)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };
    let listen_port_be = EndpointHelper::get_port_be(&l_bound);

    let client = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
    let (c_bind, c_bind_len) = EndpointHelper::wildcard_storage_v6(0);
    let c_bind_rc = if client >= 0 {
        libc::bind(
            client,
            &c_bind as *const _ as *const libc::sockaddr,
            c_bind_len,
        )
    } else {
        -1
    };
    let (target, target_len) = EndpointHelper::mapped_loopback_storage_v6(listen_port_be);
    let (connect_ret, connect_errno) = if client >= 0 && c_bind_rc == 0 && listen_port_be != 0 {
        let rc = libc::connect(
            client,
            &target as *const _ as *const libc::sockaddr,
            target_len,
        );
        let err = if rc < 0 { errno() } else { 0 };
        (rc, err)
    } else {
        (-1, libc::EBADF)
    };

    let accepted = if listener >= 0 {
        let mut pfd_listen = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        let p_rc = libc::poll(&mut pfd_listen, 1, 5000);
        if p_rc > 0 && (pfd_listen.revents & libc::POLLIN) != 0 {
            libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut())
        } else {
            -1
        }
    } else {
        -1
    };

    let (accepted_peer_family, accepted_peer_addr) = if accepted >= 0 {
        let (rc, _, storage, _) = EndpointHelper::getpeername(accepted);
        if rc == 0 {
            EndpointHelper::format_family_and_addr(&storage)
        } else {
            (-1, "none".to_string())
        }
    } else {
        (-1, "none".to_string())
    };

    let (client_peer_family, client_peer_addr) = if client >= 0 && connect_ret == 0 {
        let (rc, _, storage, _) = EndpointHelper::getpeername(client);
        if rc == 0 {
            EndpointHelper::format_family_and_addr(&storage)
        } else {
            (-1, "none".to_string())
        }
    } else {
        (-1, "none".to_string())
    };

    let (client_sockname_family, client_sockname_addr) = if client >= 0 {
        let (rc, _, storage, _) = EndpointHelper::getsockname(client);
        if rc == 0 {
            EndpointHelper::format_family_and_addr(&storage)
        } else {
            (-1, "none".to_string())
        }
    } else {
        (-1, "none".to_string())
    };

    let echo_ok = if connect_ret == 0 && accepted >= 0 {
        test_stream_transfer(client, accepted)
    } else {
        false
    };

    if client >= 0 {
        libc::close(client);
    }
    if accepted >= 0 {
        libc::close(accepted);
    }
    if listener >= 0 {
        libc::close(listener);
    }

    V4MappedCaseResult {
        connect_ret,
        connect_errno,
        accepted_peer_family,
        accepted_peer_addr,
        client_peer_family,
        client_peer_addr,
        client_sockname_family,
        client_sockname_addr,
        echo_ok,
    }
}

unsafe fn run_v4mapped_v6only_listener_case() -> (i32, i32) {
    let listener = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
    let (l_storage, l_len) = EndpointHelper::wildcard_storage_v6(0);
    let one: libc::c_int = 1;
    let s_rc = if listener >= 0 {
        libc::setsockopt(
            listener,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    } else {
        -1
    };
    let l_bind_rc = if s_rc == 0 {
        libc::bind(
            listener,
            &l_storage as *const _ as *const libc::sockaddr,
            l_len,
        )
    } else {
        -1
    };
    let listen_rc = if l_bind_rc == 0 {
        libc::listen(listener, 4)
    } else {
        -1
    };
    let (_, _, l_bound, _) = if listen_rc == 0 {
        EndpointHelper::getsockname(listener)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };
    let listen_port_be = EndpointHelper::get_port_be(&l_bound);

    let client = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
    let (c_bind, c_bind_len) = EndpointHelper::wildcard_storage_v6(0);
    let c_bind_rc = if client >= 0 {
        libc::bind(
            client,
            &c_bind as *const _ as *const libc::sockaddr,
            c_bind_len,
        )
    } else {
        -1
    };
    let (target, target_len) = EndpointHelper::mapped_loopback_storage_v6(listen_port_be);
    let (connect_ret, connect_errno) = if client >= 0 && c_bind_rc == 0 && listen_port_be != 0 {
        let rc = libc::connect(
            client,
            &target as *const _ as *const libc::sockaddr,
            target_len,
        );
        let err = if rc < 0 { errno() } else { 0 };
        (rc, err)
    } else {
        (-1, libc::EBADF)
    };

    if client >= 0 {
        libc::close(client);
    }
    if listener >= 0 {
        libc::close(listener);
    }
    (connect_ret, connect_errno)
}

struct V6LoopbackClientCaseResult {
    connect_ret: i32,
    connect_errno: i32,
    client_peer_family: i32,
    client_peer_addr: String,
    client_sockname_family: i32,
    client_sockname_addr: String,
}

unsafe fn run_v4mapped_v6_loopback_client_case() -> V6LoopbackClientCaseResult {
    let (l_storage, l_len) = EndpointHelper::loopback_storage_v4(0);
    let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let l_bind_rc = if listener >= 0 {
        libc::bind(
            listener,
            &l_storage as *const _ as *const libc::sockaddr,
            l_len,
        )
    } else {
        -1
    };
    let listen_rc = if l_bind_rc == 0 {
        libc::listen(listener, 4)
    } else {
        -1
    };
    let (_, _, l_bound, _) = if listen_rc == 0 {
        EndpointHelper::getsockname(listener)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };
    let listen_port_be = EndpointHelper::get_port_be(&l_bound);

    let client = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
    let (c_bind, c_bind_len) = EndpointHelper::loopback_storage_v6(0);
    let c_bind_rc = if client >= 0 {
        libc::bind(
            client,
            &c_bind as *const _ as *const libc::sockaddr,
            c_bind_len,
        )
    } else {
        -1
    };
    let (target, target_len) = EndpointHelper::mapped_loopback_storage_v6(listen_port_be);
    let (connect_ret, connect_errno) = if client >= 0 && c_bind_rc == 0 && listen_port_be != 0 {
        let rc = libc::connect(
            client,
            &target as *const _ as *const libc::sockaddr,
            target_len,
        );
        let err = if rc < 0 { errno() } else { 0 };
        (rc, err)
    } else {
        (-1, libc::EBADF)
    };

    let (client_peer_family, client_peer_addr) = if client >= 0 && connect_ret == 0 {
        let (rc, _, storage, _) = EndpointHelper::getpeername(client);
        if rc == 0 {
            EndpointHelper::format_family_and_addr(&storage)
        } else {
            (-1, "none".to_string())
        }
    } else {
        (-1, "none".to_string())
    };

    let (client_sockname_family, client_sockname_addr) = if client >= 0 && connect_ret == 0 {
        let (rc, _, storage, _) = EndpointHelper::getsockname(client);
        if rc == 0 {
            EndpointHelper::format_family_and_addr(&storage)
        } else {
            (-1, "none".to_string())
        }
    } else {
        (-1, "none".to_string())
    };

    if client >= 0 {
        libc::close(client);
    }
    if listener >= 0 {
        libc::close(listener);
    }

    V6LoopbackClientCaseResult {
        connect_ret,
        connect_errno,
        client_peer_family,
        client_peer_addr,
        client_sockname_family,
        client_sockname_addr,
    }
}

struct RemoteShutdownTrailingDataResult {
    listener_poll_rc: i32,
    listener_poll_errno: i32,
    listener_accept_ok: bool,
    server_write_bytes: i64,
    server_write_errno: i32,
    server_term_ret: i32,
    server_term_errno: i32,
    client_pre_drain_poll_revents: String,
    client_trailing_write_bytes: i64,
    client_trailing_write_errno: i32,
    server_trailing_recv_bytes: i64,
    server_trailing_recv_errno: i32,
    client_bytes_read: i64,
    client_reads_count: i64,
    client_final_recv_ret: i64,
    client_final_recv_errno: i32,
    client_post_eof_poll_revents: String,
    client_so_error: i32,
    client_post_eof_write_ret: i64,
    client_post_eof_write_errno: i32,
}

unsafe fn run_remote_shutdown_trailing_data_case(
    variant_close: bool,
) -> RemoteShutdownTrailingDataResult {
    let (l_storage, l_len) = EndpointHelper::loopback_storage_v4(0);
    let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let l_bind_rc = if listener >= 0 {
        libc::bind(
            listener,
            &l_storage as *const _ as *const libc::sockaddr,
            l_len,
        )
    } else {
        -1
    };
    let listen_rc = if l_bind_rc == 0 {
        libc::listen(listener, 4)
    } else {
        -1
    };
    let (_, _, l_bound, _) = if listen_rc == 0 {
        EndpointHelper::getsockname(listener)
    } else {
        (-1, -1, std::mem::zeroed(), 0)
    };
    let listen_port_be = EndpointHelper::get_port_be(&l_bound);

    let client = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let (target, target_len) = EndpointHelper::loopback_storage_v4(listen_port_be);
    let _connect_rc = if client >= 0 && listen_port_be != 0 {
        libc::connect(
            client,
            &target as *const _ as *const libc::sockaddr,
            target_len,
        )
    } else {
        -1
    };

    let listener_poll_rc = if listener >= 0 {
        poll_readable(listener)
    } else {
        -1
    };
    let listener_poll_errno = if listener_poll_rc < 0 { errno() } else { 0 };

    let accepted = if listener >= 0 && listener_poll_rc > 0 {
        libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut())
    } else {
        -1
    };
    let listener_accept_ok = accepted >= 0;

    if client >= 0 {
        set_nonblock(client);
    }
    if accepted >= 0 {
        set_nonblock(accepted);
    }

    let send_data = [0x5au8; 8192];
    let server_write_rc = if accepted >= 0 {
        libc::send(
            accepted,
            send_data.as_ptr().cast(),
            send_data.len(),
            libc::MSG_NOSIGNAL,
        )
    } else {
        -1
    };
    let (server_write_bytes, server_write_errno) = if server_write_rc >= 0 {
        (server_write_rc as i64, 0)
    } else {
        (server_write_rc as i64, errno())
    };

    let (server_term_ret, server_term_errno) = if variant_close {
        let rc = if accepted >= 0 {
            libc::close(accepted)
        } else {
            -1
        };
        (rc, if rc < 0 { errno() } else { 0 })
    } else {
        let rc = if accepted >= 0 {
            libc::shutdown(accepted, libc::SHUT_WR)
        } else {
            -1
        };
        (rc, if rc < 0 { errno() } else { 0 })
    };

    let mut pfd_pre = libc::pollfd {
        fd: client,
        events: libc::POLLIN | POLLRDHUP | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    let _ = libc::poll(&mut pfd_pre, 1, 5000);
    let client_pre_drain_poll_revents = format!("0x{:x}", pfd_pre.revents);

    let trailing_data = [0xa5u8; 4096];
    let tw_rc = if client >= 0 {
        libc::send(
            client,
            trailing_data.as_ptr().cast(),
            trailing_data.len(),
            libc::MSG_NOSIGNAL,
        )
    } else {
        -1
    };
    let (client_trailing_write_bytes, client_trailing_write_errno) = if tw_rc >= 0 {
        (tw_rc as i64, 0)
    } else {
        (tw_rc as i64, errno())
    };

    let (server_trailing_recv_bytes, server_trailing_recv_errno) =
        if !variant_close && accepted >= 0 {
            let mut s_buf = [0u8; 4096];
            let mut s_pfd = libc::pollfd {
                fd: accepted,
                events: libc::POLLIN,
                revents: 0,
            };
            let _ = libc::poll(&mut s_pfd, 1, 5000);
            let sr_rc = libc::recv(accepted, s_buf.as_mut_ptr().cast(), s_buf.len(), 0);
            if sr_rc >= 0 {
                (sr_rc as i64, 0)
            } else {
                (sr_rc as i64, errno())
            }
        } else {
            (0, 0)
        };

    let mut chunk_buf = [0u8; 512];
    let mut client_bytes_read = 0i64;
    let mut client_reads_count = 0i64;
    let mut client_final_recv_ret = -1i64;
    let mut client_final_recv_errno = 0i32;
    if client >= 0 {
        loop {
            let rc = libc::recv(client, chunk_buf.as_mut_ptr().cast(), chunk_buf.len(), 0);
            if rc > 0 {
                client_bytes_read += rc as i64;
                client_reads_count += 1;
                libc::usleep(100);
            } else if rc == 0 {
                client_final_recv_ret = 0;
                client_final_recv_errno = 0;
                break;
            } else {
                let e = errno();
                if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                    let mut p = libc::pollfd {
                        fd: client,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let prc = libc::poll(&mut p, 1, 5000);
                    if prc <= 0 {
                        client_final_recv_ret = -1;
                        client_final_recv_errno = if prc < 0 {
                            errno()
                        } else {
                            libc::ETIMEDOUT
                        };
                        break;
                    }
                    continue;
                }
                client_final_recv_ret = rc as i64;
                client_final_recv_errno = e;
                break;
            }
        }
    }

    let mut pfd_post = libc::pollfd {
        fd: client,
        events: libc::POLLIN | POLLRDHUP | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    let _ = libc::poll(&mut pfd_post, 1, 5000);
    let client_post_eof_poll_revents = format!("0x{:x}", pfd_post.revents);

    let mut so_err: libc::c_int = 0;
    let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let gso_rc = if client >= 0 {
        libc::getsockopt(
            client,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut so_err as *mut _ as *mut libc::c_void,
            &mut optlen,
        )
    } else {
        -1
    };
    let client_so_error = if gso_rc == 0 { so_err } else { errno() };

    let post_eof_buf = [1u8];
    let pw_rc = if client >= 0 {
        libc::send(
            client,
            post_eof_buf.as_ptr().cast(),
            post_eof_buf.len(),
            libc::MSG_NOSIGNAL,
        )
    } else {
        -1
    };
    let (client_post_eof_write_ret, client_post_eof_write_errno) = if pw_rc >= 0 {
        (pw_rc as i64, 0)
    } else {
        (pw_rc as i64, errno())
    };

    if client >= 0 {
        libc::close(client);
    }
    if !variant_close && accepted >= 0 {
        libc::close(accepted);
    }
    if listener >= 0 {
        libc::close(listener);
    }

    RemoteShutdownTrailingDataResult {
        listener_poll_rc,
        listener_poll_errno,
        listener_accept_ok,
        server_write_bytes,
        server_write_errno,
        server_term_ret,
        server_term_errno,
        client_pre_drain_poll_revents,
        client_trailing_write_bytes,
        client_trailing_write_errno,
        server_trailing_recv_bytes,
        server_trailing_recv_errno,
        client_bytes_read,
        client_reads_count,
        client_final_recv_ret,
        client_final_recv_errno,
        client_post_eof_poll_revents,
        client_so_error,
        client_post_eof_write_ret,
        client_post_eof_write_errno,
    }
}

fn main() {
    unsafe {
        conformance_probes::install_ign(libc::SIGPIPE);

        // ---------------------------------------------------------------------
        // Case 1: listen
        // ---------------------------------------------------------------------
        let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut sin: libc::sockaddr_in = std::mem::zeroed();
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_addr.s_addr = libc::INADDR_ANY.to_be();
        sin.sin_port = 0;

        let b_rc = if listener >= 0 {
            libc::bind(
                listener,
                &sin as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        } else {
            -1
        };

        let l_rc = if b_rc == 0 {
            libc::listen(listener, 8)
        } else {
            -1
        };
        let listen_ok = listener >= 0 && b_rc == 0 && l_rc == 0;

        let mut bound_sin: libc::sockaddr_in = std::mem::zeroed();
        let mut slen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if listen_ok {
            libc::getsockname(
                listener,
                &mut bound_sin as *mut _ as *mut libc::sockaddr,
                &mut slen,
            );
        }
        let listen_port_be = bound_sin.sin_port;

        let mut val_l: libc::c_int = 0;
        let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let so_acceptconn_listener = if listen_ok
            && libc::getsockopt(
                listener,
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                &mut val_l as *mut _ as *mut libc::c_void,
                &mut optlen,
            ) == 0
        {
            val_l
        } else {
            errno()
        };

        let unlistened = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut val_u: libc::c_int = 0;
        let mut optlen_u = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let so_acceptconn_unlistened = if unlistened >= 0
            && libc::getsockopt(
                unlistened,
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                &mut val_u as *mut _ as *mut libc::c_void,
                &mut optlen_u,
            ) == 0
        {
            val_u
        } else {
            errno()
        };
        if unlistened >= 0 {
            libc::close(unlistened);
        }

        report!(
            listen_ok = listen_ok,
            so_acceptconn_listener = so_acceptconn_listener,
            so_acceptconn_unlistened = so_acceptconn_unlistened,
        );

        // ---------------------------------------------------------------------
        // Case 2: blocking_connect
        // ---------------------------------------------------------------------
        let client_thread = std::thread::spawn(move || {
            let client_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            let mut c_sin: libc::sockaddr_in = std::mem::zeroed();
            c_sin.sin_family = libc::AF_INET as libc::sa_family_t;
            c_sin.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            c_sin.sin_port = listen_port_be;
            let c_rc = if client_fd >= 0 {
                libc::connect(
                    client_fd,
                    &c_sin as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            } else {
                -1
            };
            (client_fd, c_rc)
        });

        let mut pfd_listen = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        let p_rc = libc::poll(&mut pfd_listen, 1, 5000);
        let accepted_fd = if p_rc > 0 && (pfd_listen.revents & libc::POLLIN) != 0 {
            libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut())
        } else {
            -1
        };

        let (client_fd, c_rc) = client_thread.join().unwrap_or((-1, -1));
        let accept_ok = accepted_fd >= 0 && c_rc == 0;

        let mut client_sin: libc::sockaddr_in = std::mem::zeroed();
        let mut slen_c = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let gsn_c = if client_fd >= 0 {
            libc::getsockname(
                client_fd,
                &mut client_sin as *mut _ as *mut libc::sockaddr,
                &mut slen_c,
            )
        } else {
            -1
        };

        let mut accepted_peer_sin: libc::sockaddr_in = std::mem::zeroed();
        let mut slen_ap = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let gpn_a = if accepted_fd >= 0 {
            libc::getpeername(
                accepted_fd,
                &mut accepted_peer_sin as *mut _ as *mut libc::sockaddr,
                &mut slen_ap,
            )
        } else {
            -1
        };

        let peer_eq_client_sockname = accept_ok
            && gsn_c == 0
            && gpn_a == 0
            && accepted_peer_sin.sin_family == client_sin.sin_family
            && accepted_peer_sin.sin_port == client_sin.sin_port
            && accepted_peer_sin.sin_addr.s_addr == client_sin.sin_addr.s_addr;

        let mut accepted_sin: libc::sockaddr_in = std::mem::zeroed();
        let mut slen_a = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let gsn_a = if accepted_fd >= 0 {
            libc::getsockname(
                accepted_fd,
                &mut accepted_sin as *mut _ as *mut libc::sockaddr,
                &mut slen_a,
            )
        } else {
            -1
        };

        let loopback_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        let accepted_sockname_ip_loopback =
            accept_ok && gsn_a == 0 && accepted_sin.sin_addr.s_addr == loopback_addr;
        let accepted_sockname_port_eq_listen =
            accept_ok && gsn_a == 0 && accepted_sin.sin_port == listen_port_be;

        let mut client_peer_sin: libc::sockaddr_in = std::mem::zeroed();
        let mut slen_cp = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let gpn_c = if client_fd >= 0 {
            libc::getpeername(
                client_fd,
                &mut client_peer_sin as *mut _ as *mut libc::sockaddr,
                &mut slen_cp,
            )
        } else {
            -1
        };
        let client_peername_ip_loopback =
            accept_ok && gpn_c == 0 && client_peer_sin.sin_addr.s_addr == loopback_addr;

        report!(
            accept_ok = accept_ok,
            peer_eq_client_sockname = peer_eq_client_sockname,
            accepted_sockname_ip_loopback = accepted_sockname_ip_loopback,
            accepted_sockname_port_eq_listen = accepted_sockname_port_eq_listen,
            client_peername_ip_loopback = client_peername_ip_loopback,
        );

        // ---------------------------------------------------------------------
        // Case 3: already_connected
        // ---------------------------------------------------------------------
        let reconnect_bad_ptr_rc = libc::connect(
            client_fd,
            1usize as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let reconnect_bad_ptr_errno = if reconnect_bad_ptr_rc < 0 { errno() } else { 0 };
        let reconnect_short_len_rc = libc::connect(
            client_fd,
            &bound_sin as *const _ as *const libc::sockaddr,
            1,
        );
        let reconnect_short_len_errno = if reconnect_short_len_rc < 0 { errno() } else { 0 };
        let reconnect_client_rc = libc::connect(
            client_fd,
            &bound_sin as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let reconnect_client_errno = if reconnect_client_rc < 0 { errno() } else { 0 };
        let reconnect_accepted_rc = libc::connect(
            accepted_fd,
            &client_sin as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let reconnect_accepted_errno = if reconnect_accepted_rc < 0 { errno() } else { 0 };
        report!(
            reconnect_bad_ptr_rc = reconnect_bad_ptr_rc,
            reconnect_bad_ptr_errno = reconnect_bad_ptr_errno,
            reconnect_short_len_rc = reconnect_short_len_rc,
            reconnect_short_len_errno = reconnect_short_len_errno,
            reconnect_client_rc = reconnect_client_rc,
            reconnect_client_errno = reconnect_client_errno,
            reconnect_accepted_rc = reconnect_accepted_rc,
            reconnect_accepted_errno = reconnect_accepted_errno,
        );

        // ---------------------------------------------------------------------
        // Case 4: nonblocking_connect
        // ---------------------------------------------------------------------
        let nb_sock = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        let mut nb_target: libc::sockaddr_in = std::mem::zeroed();
        nb_target.sin_family = libc::AF_INET as libc::sa_family_t;
        nb_target.sin_addr.s_addr = loopback_addr;
        nb_target.sin_port = listen_port_be;

        let nb_rc = if nb_sock >= 0 {
            libc::connect(
                nb_sock,
                &nb_target as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        } else {
            -1
        };
        let nb_connect_ret = if nb_rc == 0 { 0 } else { errno() };

        let mut pfd_nb = libc::pollfd {
            fd: nb_sock,
            events: libc::POLLOUT,
            revents: 0,
        };
        let _ = libc::poll(&mut pfd_nb, 1, 5000);
        let nb_connect_pollout_revents = format!("0x{:x}", pfd_nb.revents);

        let mut so_err: libc::c_int = 0;
        let mut optlen_err = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let gso_rc = if nb_sock >= 0 {
            libc::getsockopt(
                nb_sock,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_err as *mut _ as *mut libc::c_void,
                &mut optlen_err,
            )
        } else {
            -1
        };
        let nb_so_error = if gso_rc == 0 { so_err } else { errno() };

        let mut pfd_l = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        let _ = libc::poll(&mut pfd_l, 1, 5000);
        let nb_acc_fd = libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut());
        let nb_accept_ok = nb_acc_fd >= 0;

        if nb_sock >= 0 {
            libc::close(nb_sock);
        }
        if nb_acc_fd >= 0 {
            libc::close(nb_acc_fd);
        }

        report!(
            nb_connect_ret = nb_connect_ret,
            nb_connect_pollout_revents = nb_connect_pollout_revents,
            nb_so_error = nb_so_error,
            nb_accept_ok = nb_accept_ok,
        );

        // ---------------------------------------------------------------------
        // Case 4: echo64k
        // ---------------------------------------------------------------------
        set_nonblock(client_fd);
        set_nonblock(accepted_fd);

        let sent_pattern: Vec<u8> = (0..ECHO_TOTAL).map(|i| (i * 7 + 3) as u8).collect();

        // Direction 1: client writes, server reads
        let pattern_c = sent_pattern.clone();
        let writer_handle = std::thread::spawn(move || {
            let mut sent = 0usize;
            let mut short = false;
            while sent < ECHO_TOTAL {
                let mut pfd = libc::pollfd {
                    fd: client_fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                if libc::poll(&mut pfd, 1, 5000) <= 0 {
                    break;
                }
                let want = ECHO_TOTAL - sent;
                let n = libc::write(client_fd, pattern_c[sent..].as_ptr().cast(), want);
                if n > 0 {
                    let n = n as usize;
                    if n < want {
                        short = true;
                    }
                    sent += n;
                } else if n < 0 {
                    let e = errno();
                    if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                        break;
                    }
                } else {
                    break;
                }
            }
            short
        });

        let mut server_buf = vec![0u8; ECHO_TOTAL];
        let mut recvd = 0usize;
        while recvd < ECHO_TOTAL {
            let mut pfd = libc::pollfd {
                fd: accepted_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            if libc::poll(&mut pfd, 1, 5000) <= 0 {
                break;
            }
            let want = ECHO_TOTAL - recvd;
            let n = libc::read(accepted_fd, server_buf[recvd..].as_mut_ptr().cast(), want);
            if n > 0 {
                recvd += n as usize;
            } else if n < 0 {
                let e = errno();
                if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                    break;
                }
            } else {
                break;
            }
        }
        let client_short_write = writer_handle.join().unwrap_or(false);
        let echo_bytes_out = recvd;

        // Direction 2: server echoes back, client reads
        let reader_handle = std::thread::spawn(move || {
            let mut client_buf = vec![0u8; ECHO_TOTAL];
            let mut recvd_back = 0usize;
            while recvd_back < ECHO_TOTAL {
                let mut pfd = libc::pollfd {
                    fd: client_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                if libc::poll(&mut pfd, 1, 5000) <= 0 {
                    break;
                }
                let want = ECHO_TOTAL - recvd_back;
                let n = libc::read(
                    client_fd,
                    client_buf[recvd_back..].as_mut_ptr().cast(),
                    want,
                );
                if n > 0 {
                    recvd_back += n as usize;
                } else if n < 0 {
                    let e = errno();
                    if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                        break;
                    }
                } else {
                    break;
                }
            }
            (client_buf, recvd_back)
        });

        let mut sent_back = 0usize;
        let mut server_short_write = false;
        while sent_back < echo_bytes_out {
            let mut pfd = libc::pollfd {
                fd: accepted_fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            if libc::poll(&mut pfd, 1, 5000) <= 0 {
                break;
            }
            let want = echo_bytes_out - sent_back;
            let n = libc::write(
                accepted_fd,
                server_buf[sent_back..echo_bytes_out].as_ptr().cast(),
                want,
            );
            if n > 0 {
                let n = n as usize;
                if n < want {
                    server_short_write = true;
                }
                sent_back += n;
            } else if n < 0 {
                let e = errno();
                if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                    break;
                }
            } else {
                break;
            }
        }
        let (client_buf, echo_bytes_back) = reader_handle.join().unwrap_or((vec![], 0));
        let echo_checksum_ok =
            echo_bytes_back == ECHO_TOTAL && fnv1a(&client_buf) == fnv1a(&sent_pattern);
        let short_writes_seen = client_short_write || server_short_write;

        report!(
            echo_bytes_out = echo_bytes_out,
            echo_bytes_back = echo_bytes_back,
            echo_checksum_ok = echo_checksum_ok,
            short_writes_seen = short_writes_seen,
        );

        // ---------------------------------------------------------------------
        // Case 5: fionread
        // ---------------------------------------------------------------------
        let fion_payload = [0x5au8; 1000];
        let mut written_fion = 0usize;
        while written_fion < 1000 {
            let mut pfd = libc::pollfd {
                fd: accepted_fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            if libc::poll(&mut pfd, 1, 5000) <= 0 {
                break;
            }
            let n = libc::write(
                accepted_fd,
                fion_payload[written_fion..].as_ptr().cast(),
                1000 - written_fion,
            );
            if n > 0 {
                written_fion += n as usize;
            } else if n < 0 {
                let e = errno();
                if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                    break;
                }
            } else {
                break;
            }
        }

        let mut pfd_client = libc::pollfd {
            fd: client_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let _ = libc::poll(&mut pfd_client, 1, 5000);

        let mut avail: libc::c_int = 0;
        let ioctl_rc = libc::ioctl(
            client_fd,
            libc::FIONREAD as _,
            &mut avail as *mut libc::c_int,
        );
        let fionread_after_write = if ioctl_rc == 0 { avail } else { errno() };

        let mut drain = [0u8; 1024];
        let mut drained = 0usize;
        while drained < 1000 {
            let mut pfd = libc::pollfd {
                fd: client_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            if libc::poll(&mut pfd, 1, 5000) <= 0 {
                break;
            }
            let n = libc::read(client_fd, drain.as_mut_ptr().cast(), drain.len());
            if n > 0 {
                drained += n as usize;
            } else if n < 0 {
                let e = errno();
                if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                    break;
                }
            } else {
                break;
            }
        }

        report!(fionread_after_write = fionread_after_write);

        // ---------------------------------------------------------------------
        // Case 6: shutdown_wr
        // ---------------------------------------------------------------------
        libc::shutdown(client_fd, libc::SHUT_WR);

        let mut pfd_server = libc::pollfd {
            fd: accepted_fd,
            events: libc::POLLIN | POLLRDHUP,
            revents: 0,
        };
        let _ = libc::poll(&mut pfd_server, 1, 5000);
        let rdhup_revents = format!("0x{:x}", pfd_server.revents);

        let mut s_buf = [0u8; 16];
        let s_rc = libc::recv(accepted_fd, s_buf.as_mut_ptr().cast(), s_buf.len(), 0);
        let (recv_after_shutdown_ret, recv_after_shutdown_errno) = if s_rc >= 0 {
            (s_rc as i64, 0)
        } else {
            (s_rc as i64, errno())
        };

        let w_byte = [1u8];
        let w_rc = libc::write(client_fd, w_byte.as_ptr().cast(), 1);
        let write_after_shut_wr_errno = if w_rc < 0 { errno() } else { 0 };

        libc::shutdown(accepted_fd, libc::SHUT_RDWR);
        // The client socket is non-blocking since case 4: wait (bounded) for the
        // peer's FIN to land before reading, so the line is the kernel's answer
        // and not a race against loopback delivery.
        let mut pfd_client_fin = libc::pollfd {
            fd: client_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let _ = libc::poll(&mut pfd_client_fin, 1, 5000);
        let mut c_buf = [0u8; 16];
        let c_rc = libc::recv(client_fd, c_buf.as_mut_ptr().cast(), c_buf.len(), 0);
        let (client_recv_after_peer_shutdown_ret, client_recv_after_peer_shutdown_errno) =
            if c_rc >= 0 {
                (c_rc as i64, 0)
            } else {
                (c_rc as i64, errno())
            };

        report!(
            rdhup_revents = rdhup_revents,
            recv_after_shutdown_ret = recv_after_shutdown_ret,
            recv_after_shutdown_errno = recv_after_shutdown_errno,
            write_after_shut_wr_errno = write_after_shut_wr_errno,
            client_recv_after_peer_shutdown_ret = client_recv_after_peer_shutdown_ret,
            client_recv_after_peer_shutdown_errno = client_recv_after_peer_shutdown_errno,
        );

        // ---------------------------------------------------------------------
        // Case 7: listener_close_with_backlog
        // ---------------------------------------------------------------------
        let l7 = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut sin7: libc::sockaddr_in = std::mem::zeroed();
        sin7.sin_family = libc::AF_INET as libc::sa_family_t;
        sin7.sin_addr.s_addr = libc::INADDR_ANY.to_be();
        sin7.sin_port = 0;
        let _ = libc::bind(
            l7,
            &sin7 as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let _ = libc::listen(l7, 8);
        let mut bound7: libc::sockaddr_in = std::mem::zeroed();
        let mut slen7 = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let _ = libc::getsockname(l7, &mut bound7 as *mut _ as *mut libc::sockaddr, &mut slen7);
        let port7_be = bound7.sin_port;

        let c7 = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut target7: libc::sockaddr_in = std::mem::zeroed();
        target7.sin_family = libc::AF_INET as libc::sa_family_t;
        target7.sin_addr.s_addr = loopback_addr;
        target7.sin_port = port7_be;
        let _ = libc::connect(
            c7,
            &target7 as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );

        libc::close(l7);

        let mut pfd7 = libc::pollfd {
            fd: c7,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let _ = libc::poll(&mut pfd7, 1, 5000);
        let backlog_client_revents = format!("0x{:x}", pfd7.revents);

        let mut b7 = [0u8; 16];
        let r7_rc = libc::recv(c7, b7.as_mut_ptr().cast(), b7.len(), 0);
        let (backlog_client_recv_ret, backlog_client_recv_errno) = if r7_rc >= 0 {
            (r7_rc as i64, 0)
        } else {
            (r7_rc as i64, errno())
        };

        let w7 = [1u8];
        let w7_rc = libc::write(c7, w7.as_ptr().cast(), 1);
        let (backlog_client_write_ret, backlog_client_write_errno) = if w7_rc >= 0 {
            (w7_rc as i64, 0)
        } else {
            (w7_rc as i64, errno())
        };
        libc::close(c7);

        report!(
            backlog_client_revents = backlog_client_revents,
            backlog_client_recv_ret = backlog_client_recv_ret,
            backlog_client_recv_errno = backlog_client_recv_errno,
            backlog_client_write_ret = backlog_client_write_ret,
            backlog_client_write_errno = backlog_client_write_errno,
        );

        // ---------------------------------------------------------------------
        // Case 8: tcp_nodelay
        // ---------------------------------------------------------------------
        let mut nodelay: libc::c_int = 0;
        let mut optlen_nd = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let g_rc = libc::getsockopt(
            accepted_fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &mut nodelay as *mut _ as *mut libc::c_void,
            &mut optlen_nd,
        );
        let nodelay_default = if g_rc == 0 { nodelay } else { errno() };

        let one: libc::c_int = 1;
        let s_rc = libc::setsockopt(
            accepted_fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let mut nodelay2: libc::c_int = 0;
        let mut optlen_nd2 = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let g2_rc = libc::getsockopt(
            accepted_fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &mut nodelay2 as *mut _ as *mut libc::c_void,
            &mut optlen_nd2,
        );
        let nodelay_after_set = if s_rc == 0 && g2_rc == 0 {
            nodelay2
        } else {
            errno()
        };

        report!(
            nodelay_default = nodelay_default,
            nodelay_after_set = nodelay_after_set,
        );

        // ---------------------------------------------------------------------
        // Case 9: connect_refused
        // ---------------------------------------------------------------------
        let dummy = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut d_sin: libc::sockaddr_in = std::mem::zeroed();
        d_sin.sin_family = libc::AF_INET as libc::sa_family_t;
        d_sin.sin_addr.s_addr = loopback_addr;
        d_sin.sin_port = 0;
        let _ = libc::bind(
            dummy,
            &d_sin as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let mut d_bound: libc::sockaddr_in = std::mem::zeroed();
        let mut slen_d = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let _ = libc::getsockname(
            dummy,
            &mut d_bound as *mut _ as *mut libc::sockaddr,
            &mut slen_d,
        );
        let unbound_port_be = d_bound.sin_port;
        if dummy >= 0 {
            libc::close(dummy);
        }

        let s_refused = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut target_refused: libc::sockaddr_in = std::mem::zeroed();
        target_refused.sin_family = libc::AF_INET as libc::sa_family_t;
        target_refused.sin_addr.s_addr = loopback_addr;
        target_refused.sin_port = unbound_port_be;
        let cr_rc = libc::connect(
            s_refused,
            &target_refused as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let refused_errno = if cr_rc < 0 { errno() } else { 0 };
        if s_refused >= 0 {
            libc::close(s_refused);
        }

        report!(refused_errno = refused_errno);

        // ---------------------------------------------------------------------
        // Case 10: getsockopt_types
        // ---------------------------------------------------------------------
        let mut so_type_val: libc::c_int = 0;
        let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc1 = libc::getsockopt(
            accepted_fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut so_type_val as *mut _ as *mut libc::c_void,
            &mut optlen,
        );
        let so_type = if rc1 == 0 { so_type_val } else { errno() };

        let mut so_domain_val: libc::c_int = 0;
        let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc2 = libc::getsockopt(
            accepted_fd,
            libc::SOL_SOCKET,
            SO_DOMAIN,
            &mut so_domain_val as *mut _ as *mut libc::c_void,
            &mut optlen,
        );
        let so_domain = if rc2 == 0 { so_domain_val } else { errno() };

        let mut so_proto_val: libc::c_int = 0;
        let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc3 = libc::getsockopt(
            accepted_fd,
            libc::SOL_SOCKET,
            SO_PROTOCOL,
            &mut so_proto_val as *mut _ as *mut libc::c_void,
            &mut optlen,
        );
        let so_protocol = if rc3 == 0 { so_proto_val } else { errno() };

        report!(
            so_type = so_type,
            so_domain = so_domain,
            so_protocol = so_protocol,
        );

        // ---------------------------------------------------------------------
        // Case 11: tcp_disconnect_reconnect (independent disposable pairs)
        // ---------------------------------------------------------------------
        run_tcp_disconnect_case(SockFamily::V4, false);
        run_tcp_disconnect_case(SockFamily::V4, true);
        run_tcp_disconnect_case(SockFamily::V6, false);
        run_tcp_disconnect_case(SockFamily::V6, true);

        if client_fd >= 0 {
            libc::close(client_fd);
        }
        if accepted_fd >= 0 {
            libc::close(accepted_fd);
        }
        if listener >= 0 {
            libc::close(listener);
        }

        // ---------------------------------------------------------------------
        // Case 11: bound_client_v4_loopback
        // ---------------------------------------------------------------------
        let res_v4_loopback = run_bound_client_case(SockFamily::V4, BindKind::Loopback);
        report!(
            v4_loopback_listen_ok = res_v4_loopback.listen_ok,
            v4_loopback_client_bind_ret = res_v4_loopback.client_bind_ret,
            v4_loopback_client_bind_errno = res_v4_loopback.client_bind_errno,
            v4_loopback_client_pre_gsn_ret = res_v4_loopback.client_pre_gsn_ret,
            v4_loopback_client_pre_gsn_errno = res_v4_loopback.client_pre_gsn_errno,
            v4_loopback_client_pre_port_nonzero = res_v4_loopback.client_pre_port_nonzero,
            v4_loopback_client_pre_addr_loopback = res_v4_loopback.client_pre_addr_ok,
            v4_loopback_connect_initial_ret = res_v4_loopback.connect.initial_rc,
            v4_loopback_connect_initial_errno = res_v4_loopback.connect.initial_errno,
            v4_loopback_connect_poll_ret = res_v4_loopback.connect.poll_rc,
            v4_loopback_connect_poll_errno = res_v4_loopback.connect.poll_errno,
            v4_loopback_connect_so_error_ret = res_v4_loopback.connect.so_error_rc,
            v4_loopback_connect_so_error = res_v4_loopback.connect.so_error,
            v4_loopback_connect_ok = res_v4_loopback.connect_ok,
            v4_loopback_client_post_port_preserved = res_v4_loopback.client_post_port_preserved,
            v4_loopback_client_post_addr_loopback = res_v4_loopback.client_post_addr_loopback,
            v4_loopback_client_peer_port_eq_listen = res_v4_loopback.client_peer_port_eq_listen,
            v4_loopback_client_peer_addr_loopback = res_v4_loopback.client_peer_addr_loopback,
            v4_loopback_accepted_peer_port_eq_client_pre =
                res_v4_loopback.accepted_peer_port_eq_client_pre,
            v4_loopback_accepted_peer_port_eq_client_post =
                res_v4_loopback.accepted_peer_port_eq_client_post,
            v4_loopback_accepted_peer_addr_loopback = res_v4_loopback.accepted_peer_addr_loopback,
            v4_loopback_compete_before_close_ret = res_v4_loopback.compete_before_close_ret,
            v4_loopback_compete_before_close_errno = res_v4_loopback.compete_before_close_errno,
            v4_loopback_dup_post_close_port_preserved =
                res_v4_loopback.dup_post_close_port_preserved,
            v4_loopback_dup_post_close_addr_loopback = res_v4_loopback.dup_post_close_addr_loopback,
            v4_loopback_dup_peer_port_eq_listen = res_v4_loopback.dup_peer_port_eq_listen,
            v4_loopback_dup_stream_ok = res_v4_loopback.dup_stream_ok,
            v4_loopback_compete_after_orig_close_ret = res_v4_loopback.compete_after_orig_close_ret,
            v4_loopback_compete_after_orig_close_errno =
                res_v4_loopback.compete_after_orig_close_errno,
            v4_loopback_compete_after_dup_close_ret = res_v4_loopback.compete_after_dup_close_ret,
            v4_loopback_compete_after_dup_close_errno =
                res_v4_loopback.compete_after_dup_close_errno,
        );

        // ---------------------------------------------------------------------
        // Case 12: bound_client_v4_wildcard
        // ---------------------------------------------------------------------
        let res_v4_wildcard = run_bound_client_case(SockFamily::V4, BindKind::Wildcard);
        report!(
            v4_wildcard_listen_ok = res_v4_wildcard.listen_ok,
            v4_wildcard_client_bind_ret = res_v4_wildcard.client_bind_ret,
            v4_wildcard_client_bind_errno = res_v4_wildcard.client_bind_errno,
            v4_wildcard_client_pre_gsn_ret = res_v4_wildcard.client_pre_gsn_ret,
            v4_wildcard_client_pre_gsn_errno = res_v4_wildcard.client_pre_gsn_errno,
            v4_wildcard_client_pre_port_nonzero = res_v4_wildcard.client_pre_port_nonzero,
            v4_wildcard_client_pre_addr_any = res_v4_wildcard.client_pre_addr_ok,
            v4_wildcard_connect_initial_ret = res_v4_wildcard.connect.initial_rc,
            v4_wildcard_connect_initial_errno = res_v4_wildcard.connect.initial_errno,
            v4_wildcard_connect_poll_ret = res_v4_wildcard.connect.poll_rc,
            v4_wildcard_connect_poll_errno = res_v4_wildcard.connect.poll_errno,
            v4_wildcard_connect_so_error_ret = res_v4_wildcard.connect.so_error_rc,
            v4_wildcard_connect_so_error = res_v4_wildcard.connect.so_error,
            v4_wildcard_connect_ok = res_v4_wildcard.connect_ok,
            v4_wildcard_client_post_port_preserved = res_v4_wildcard.client_post_port_preserved,
            v4_wildcard_client_post_addr_loopback = res_v4_wildcard.client_post_addr_loopback,
            v4_wildcard_client_peer_port_eq_listen = res_v4_wildcard.client_peer_port_eq_listen,
            v4_wildcard_client_peer_addr_loopback = res_v4_wildcard.client_peer_addr_loopback,
            v4_wildcard_accepted_peer_port_eq_client_pre =
                res_v4_wildcard.accepted_peer_port_eq_client_pre,
            v4_wildcard_accepted_peer_port_eq_client_post =
                res_v4_wildcard.accepted_peer_port_eq_client_post,
            v4_wildcard_accepted_peer_addr_loopback = res_v4_wildcard.accepted_peer_addr_loopback,
            v4_wildcard_compete_before_close_ret = res_v4_wildcard.compete_before_close_ret,
            v4_wildcard_compete_before_close_errno = res_v4_wildcard.compete_before_close_errno,
            v4_wildcard_dup_post_close_port_preserved =
                res_v4_wildcard.dup_post_close_port_preserved,
            v4_wildcard_dup_post_close_addr_loopback = res_v4_wildcard.dup_post_close_addr_loopback,
            v4_wildcard_dup_peer_port_eq_listen = res_v4_wildcard.dup_peer_port_eq_listen,
            v4_wildcard_dup_stream_ok = res_v4_wildcard.dup_stream_ok,
            v4_wildcard_compete_after_orig_close_ret = res_v4_wildcard.compete_after_orig_close_ret,
            v4_wildcard_compete_after_orig_close_errno =
                res_v4_wildcard.compete_after_orig_close_errno,
            v4_wildcard_compete_after_dup_close_ret = res_v4_wildcard.compete_after_dup_close_ret,
            v4_wildcard_compete_after_dup_close_errno =
                res_v4_wildcard.compete_after_dup_close_errno,
        );

        // ---------------------------------------------------------------------
        // Case 13: bound_client_v6_loopback
        // ---------------------------------------------------------------------
        let res_v6_loopback = run_bound_client_case(SockFamily::V6, BindKind::Loopback);
        report!(
            v6_loopback_listen_ok = res_v6_loopback.listen_ok,
            v6_loopback_client_bind_ret = res_v6_loopback.client_bind_ret,
            v6_loopback_client_bind_errno = res_v6_loopback.client_bind_errno,
            v6_loopback_client_pre_gsn_ret = res_v6_loopback.client_pre_gsn_ret,
            v6_loopback_client_pre_gsn_errno = res_v6_loopback.client_pre_gsn_errno,
            v6_loopback_client_pre_port_nonzero = res_v6_loopback.client_pre_port_nonzero,
            v6_loopback_client_pre_addr_loopback = res_v6_loopback.client_pre_addr_ok,
            v6_loopback_connect_initial_ret = res_v6_loopback.connect.initial_rc,
            v6_loopback_connect_initial_errno = res_v6_loopback.connect.initial_errno,
            v6_loopback_connect_poll_ret = res_v6_loopback.connect.poll_rc,
            v6_loopback_connect_poll_errno = res_v6_loopback.connect.poll_errno,
            v6_loopback_connect_so_error_ret = res_v6_loopback.connect.so_error_rc,
            v6_loopback_connect_so_error = res_v6_loopback.connect.so_error,
            v6_loopback_connect_ok = res_v6_loopback.connect_ok,
            v6_loopback_client_post_port_preserved = res_v6_loopback.client_post_port_preserved,
            v6_loopback_client_post_addr_loopback = res_v6_loopback.client_post_addr_loopback,
            v6_loopback_client_peer_port_eq_listen = res_v6_loopback.client_peer_port_eq_listen,
            v6_loopback_client_peer_addr_loopback = res_v6_loopback.client_peer_addr_loopback,
            v6_loopback_accepted_peer_port_eq_client_pre =
                res_v6_loopback.accepted_peer_port_eq_client_pre,
            v6_loopback_accepted_peer_port_eq_client_post =
                res_v6_loopback.accepted_peer_port_eq_client_post,
            v6_loopback_accepted_peer_addr_loopback = res_v6_loopback.accepted_peer_addr_loopback,
            v6_loopback_compete_before_close_ret = res_v6_loopback.compete_before_close_ret,
            v6_loopback_compete_before_close_errno = res_v6_loopback.compete_before_close_errno,
            v6_loopback_dup_post_close_port_preserved =
                res_v6_loopback.dup_post_close_port_preserved,
            v6_loopback_dup_post_close_addr_loopback = res_v6_loopback.dup_post_close_addr_loopback,
            v6_loopback_dup_peer_port_eq_listen = res_v6_loopback.dup_peer_port_eq_listen,
            v6_loopback_dup_stream_ok = res_v6_loopback.dup_stream_ok,
            v6_loopback_compete_after_orig_close_ret = res_v6_loopback.compete_after_orig_close_ret,
            v6_loopback_compete_after_orig_close_errno =
                res_v6_loopback.compete_after_orig_close_errno,
            v6_loopback_compete_after_dup_close_ret = res_v6_loopback.compete_after_dup_close_ret,
            v6_loopback_compete_after_dup_close_errno =
                res_v6_loopback.compete_after_dup_close_errno,
        );

        // ---------------------------------------------------------------------
        // Case 14: bound_client_v6_wildcard
        // ---------------------------------------------------------------------
        let res_v6_wildcard = run_bound_client_case(SockFamily::V6, BindKind::Wildcard);
        report!(
            v6_wildcard_listen_ok = res_v6_wildcard.listen_ok,
            v6_wildcard_client_bind_ret = res_v6_wildcard.client_bind_ret,
            v6_wildcard_client_bind_errno = res_v6_wildcard.client_bind_errno,
            v6_wildcard_client_pre_gsn_ret = res_v6_wildcard.client_pre_gsn_ret,
            v6_wildcard_client_pre_gsn_errno = res_v6_wildcard.client_pre_gsn_errno,
            v6_wildcard_client_pre_port_nonzero = res_v6_wildcard.client_pre_port_nonzero,
            v6_wildcard_client_pre_addr_any = res_v6_wildcard.client_pre_addr_ok,
            v6_wildcard_connect_initial_ret = res_v6_wildcard.connect.initial_rc,
            v6_wildcard_connect_initial_errno = res_v6_wildcard.connect.initial_errno,
            v6_wildcard_connect_poll_ret = res_v6_wildcard.connect.poll_rc,
            v6_wildcard_connect_poll_errno = res_v6_wildcard.connect.poll_errno,
            v6_wildcard_connect_so_error_ret = res_v6_wildcard.connect.so_error_rc,
            v6_wildcard_connect_so_error = res_v6_wildcard.connect.so_error,
            v6_wildcard_connect_ok = res_v6_wildcard.connect_ok,
            v6_wildcard_client_post_port_preserved = res_v6_wildcard.client_post_port_preserved,
            v6_wildcard_client_post_addr_loopback = res_v6_wildcard.client_post_addr_loopback,
            v6_wildcard_client_peer_port_eq_listen = res_v6_wildcard.client_peer_port_eq_listen,
            v6_wildcard_client_peer_addr_loopback = res_v6_wildcard.client_peer_addr_loopback,
            v6_wildcard_accepted_peer_port_eq_client_pre =
                res_v6_wildcard.accepted_peer_port_eq_client_pre,
            v6_wildcard_accepted_peer_port_eq_client_post =
                res_v6_wildcard.accepted_peer_port_eq_client_post,
            v6_wildcard_accepted_peer_addr_loopback = res_v6_wildcard.accepted_peer_addr_loopback,
            v6_wildcard_compete_before_close_ret = res_v6_wildcard.compete_before_close_ret,
            v6_wildcard_compete_before_close_errno = res_v6_wildcard.compete_before_close_errno,
            v6_wildcard_dup_post_close_port_preserved =
                res_v6_wildcard.dup_post_close_port_preserved,
            v6_wildcard_dup_post_close_addr_loopback = res_v6_wildcard.dup_post_close_addr_loopback,
            v6_wildcard_dup_peer_port_eq_listen = res_v6_wildcard.dup_peer_port_eq_listen,
            v6_wildcard_dup_stream_ok = res_v6_wildcard.dup_stream_ok,
            v6_wildcard_compete_after_orig_close_ret = res_v6_wildcard.compete_after_orig_close_ret,
            v6_wildcard_compete_after_orig_close_errno =
                res_v6_wildcard.compete_after_orig_close_errno,
            v6_wildcard_compete_after_dup_close_ret = res_v6_wildcard.compete_after_dup_close_ret,
            v6_wildcard_compete_after_dup_close_errno =
                res_v6_wildcard.compete_after_dup_close_errno,
        );

        // ---------------------------------------------------------------------
        // Case 15: failed_connect_rollback_v4
        // ---------------------------------------------------------------------
        // Bind non-listening target on loopback with port 0 and KEEP alive.
        let target_v4 = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let (d_sin15, d_len15) = EndpointHelper::loopback_storage_v4(0);
        let _ = if target_v4 >= 0 {
            libc::bind(
                target_v4,
                &d_sin15 as *const _ as *const libc::sockaddr,
                d_len15,
            )
        } else {
            -1
        };
        let (_, _, d_bound15, _) = EndpointHelper::getsockname(target_v4);
        let unused_v4_port_be = EndpointHelper::get_port_be(&d_bound15);
        let (target_unused_v4, target_unused_v4_len) =
            EndpointHelper::loopback_storage_v4(unused_v4_port_be);

        let res_v4_loopback = run_failed_connect_case(
            SockFamily::V4,
            BindKind::Loopback,
            &target_unused_v4,
            target_unused_v4_len,
        );
        let res_v4_wildcard = run_failed_connect_case(
            SockFamily::V4,
            BindKind::Wildcard,
            &target_unused_v4,
            target_unused_v4_len,
        );

        if target_v4 >= 0 {
            libc::close(target_v4);
        }

        report!(
            v4_failed_loopback_client_bind_ret = res_v4_loopback.bind_ret,
            v4_failed_loopback_client_bind_errno = res_v4_loopback.bind_errno,
            v4_failed_loopback_client_pre_gsn_ret = res_v4_loopback.pre_gsn_ret,
            v4_failed_loopback_client_pre_gsn_errno = res_v4_loopback.pre_gsn_errno,
            v4_failed_loopback_client_pre_port_nonzero = res_v4_loopback.pre_port_nonzero,
            v4_failed_loopback_client_pre_addr_loopback = res_v4_loopback.pre_addr_ok,
            v4_failed_loopback_connect_initial_ret = res_v4_loopback.connect.initial_rc,
            v4_failed_loopback_connect_initial_errno = res_v4_loopback.connect.initial_errno,
            v4_failed_loopback_connect_poll_ret = res_v4_loopback.connect.poll_rc,
            v4_failed_loopback_connect_poll_errno = res_v4_loopback.connect.poll_errno,
            v4_failed_loopback_connect_so_error_ret = res_v4_loopback.connect.so_error_rc,
            v4_failed_loopback_connect_so_error = res_v4_loopback.connect.so_error,
            v4_failed_loopback_post_sockname_ret = res_v4_loopback.post_gsn_ret,
            v4_failed_loopback_post_sockname_errno = res_v4_loopback.post_gsn_errno,
            v4_failed_loopback_post_port_preserved = res_v4_loopback.post_port_preserved,
            v4_failed_loopback_post_addr_loopback = res_v4_loopback.post_addr_ok,
            v4_failed_loopback_post_peername_ret = res_v4_loopback.post_gpn_ret,
            v4_failed_loopback_post_peername_errno = res_v4_loopback.post_gpn_errno,
            v4_failed_wildcard_client_bind_ret = res_v4_wildcard.bind_ret,
            v4_failed_wildcard_client_bind_errno = res_v4_wildcard.bind_errno,
            v4_failed_wildcard_client_pre_gsn_ret = res_v4_wildcard.pre_gsn_ret,
            v4_failed_wildcard_client_pre_gsn_errno = res_v4_wildcard.pre_gsn_errno,
            v4_failed_wildcard_client_pre_port_nonzero = res_v4_wildcard.pre_port_nonzero,
            v4_failed_wildcard_client_pre_addr_any = res_v4_wildcard.pre_addr_ok,
            v4_failed_wildcard_connect_initial_ret = res_v4_wildcard.connect.initial_rc,
            v4_failed_wildcard_connect_initial_errno = res_v4_wildcard.connect.initial_errno,
            v4_failed_wildcard_connect_poll_ret = res_v4_wildcard.connect.poll_rc,
            v4_failed_wildcard_connect_poll_errno = res_v4_wildcard.connect.poll_errno,
            v4_failed_wildcard_connect_so_error_ret = res_v4_wildcard.connect.so_error_rc,
            v4_failed_wildcard_connect_so_error = res_v4_wildcard.connect.so_error,
            v4_failed_wildcard_post_sockname_ret = res_v4_wildcard.post_gsn_ret,
            v4_failed_wildcard_post_sockname_errno = res_v4_wildcard.post_gsn_errno,
            v4_failed_wildcard_post_port_preserved = res_v4_wildcard.post_port_preserved,
            v4_failed_wildcard_post_addr_any = res_v4_wildcard.post_addr_ok,
            v4_failed_wildcard_post_peername_ret = res_v4_wildcard.post_gpn_ret,
            v4_failed_wildcard_post_peername_errno = res_v4_wildcard.post_gpn_errno,
        );

        // ---------------------------------------------------------------------
        // Case 16: failed_connect_rollback_v6
        // ---------------------------------------------------------------------
        // Bind non-listening target on loopback with port 0 and KEEP alive.
        let target_v6 = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        let (d_sin16, d_len16) = EndpointHelper::loopback_storage_v6(0);
        let _ = if target_v6 >= 0 {
            libc::bind(
                target_v6,
                &d_sin16 as *const _ as *const libc::sockaddr,
                d_len16,
            )
        } else {
            -1
        };
        let (_, _, d_bound16, _) = EndpointHelper::getsockname(target_v6);
        let unused_v6_port_be = EndpointHelper::get_port_be(&d_bound16);
        let (target_unused_v6, target_unused_v6_len) =
            EndpointHelper::loopback_storage_v6(unused_v6_port_be);

        let res_v6_loopback = run_failed_connect_case(
            SockFamily::V6,
            BindKind::Loopback,
            &target_unused_v6,
            target_unused_v6_len,
        );
        let res_v6_wildcard = run_failed_connect_case(
            SockFamily::V6,
            BindKind::Wildcard,
            &target_unused_v6,
            target_unused_v6_len,
        );

        if target_v6 >= 0 {
            libc::close(target_v6);
        }

        report!(
            v6_failed_loopback_client_bind_ret = res_v6_loopback.bind_ret,
            v6_failed_loopback_client_bind_errno = res_v6_loopback.bind_errno,
            v6_failed_loopback_client_pre_gsn_ret = res_v6_loopback.pre_gsn_ret,
            v6_failed_loopback_client_pre_gsn_errno = res_v6_loopback.pre_gsn_errno,
            v6_failed_loopback_client_pre_port_nonzero = res_v6_loopback.pre_port_nonzero,
            v6_failed_loopback_client_pre_addr_loopback = res_v6_loopback.pre_addr_ok,
            v6_failed_loopback_connect_initial_ret = res_v6_loopback.connect.initial_rc,
            v6_failed_loopback_connect_initial_errno = res_v6_loopback.connect.initial_errno,
            v6_failed_loopback_connect_poll_ret = res_v6_loopback.connect.poll_rc,
            v6_failed_loopback_connect_poll_errno = res_v6_loopback.connect.poll_errno,
            v6_failed_loopback_connect_so_error_ret = res_v6_loopback.connect.so_error_rc,
            v6_failed_loopback_connect_so_error = res_v6_loopback.connect.so_error,
            v6_failed_loopback_post_sockname_ret = res_v6_loopback.post_gsn_ret,
            v6_failed_loopback_post_sockname_errno = res_v6_loopback.post_gsn_errno,
            v6_failed_loopback_post_port_preserved = res_v6_loopback.post_port_preserved,
            v6_failed_loopback_post_addr_loopback = res_v6_loopback.post_addr_ok,
            v6_failed_loopback_post_peername_ret = res_v6_loopback.post_gpn_ret,
            v6_failed_loopback_post_peername_errno = res_v6_loopback.post_gpn_errno,
            v6_failed_wildcard_client_bind_ret = res_v6_wildcard.bind_ret,
            v6_failed_wildcard_client_bind_errno = res_v6_wildcard.bind_errno,
            v6_failed_wildcard_client_pre_gsn_ret = res_v6_wildcard.pre_gsn_ret,
            v6_failed_wildcard_client_pre_gsn_errno = res_v6_wildcard.pre_gsn_errno,
            v6_failed_wildcard_client_pre_port_nonzero = res_v6_wildcard.pre_port_nonzero,
            v6_failed_wildcard_client_pre_addr_any = res_v6_wildcard.pre_addr_ok,
            v6_failed_wildcard_connect_initial_ret = res_v6_wildcard.connect.initial_rc,
            v6_failed_wildcard_connect_initial_errno = res_v6_wildcard.connect.initial_errno,
            v6_failed_wildcard_connect_poll_ret = res_v6_wildcard.connect.poll_rc,
            v6_failed_wildcard_connect_poll_errno = res_v6_wildcard.connect.poll_errno,
            v6_failed_wildcard_connect_so_error_ret = res_v6_wildcard.connect.so_error_rc,
            v6_failed_wildcard_connect_so_error = res_v6_wildcard.connect.so_error,
            v6_failed_wildcard_post_sockname_ret = res_v6_wildcard.post_gsn_ret,
            v6_failed_wildcard_post_sockname_errno = res_v6_wildcard.post_gsn_errno,
            v6_failed_wildcard_post_port_preserved = res_v6_wildcard.post_port_preserved,
            v6_failed_wildcard_post_addr_any = res_v6_wildcard.post_addr_ok,
            v6_failed_wildcard_post_peername_ret = res_v6_wildcard.post_gpn_ret,
            v6_failed_wildcard_post_peername_errno = res_v6_wildcard.post_gpn_errno,
        );

        // ---------------------------------------------------------------------
        // Case 17: bind_admission_matrix
        // ---------------------------------------------------------------------
        let reuseaddr_pair = run_v4_bind_admission_case(true, false, true, false);
        let reuseport_pair = run_v4_bind_admission_case(false, true, false, true);
        let reuseaddr_then_reuseport = run_v4_bind_admission_case(true, false, false, true);
        let reuseport_then_reuseaddr = run_v4_bind_admission_case(false, true, true, false);
        let dual_stack = run_v6_to_v4_bind_admission_case(false, false);
        let v6only = run_v6_to_v4_bind_admission_case(true, false);
        let mapped = run_v6_to_v4_bind_admission_case(false, true);
        // Linux accepts the pre-bind setsockopt but rejects this mapped-v6 bind
        // with EINVAL; keep both operations separate in the output.
        let mapped_v6only = run_v6_to_v4_bind_admission_case(true, true);
        report!(
            reuseaddr_pair_setup_ok = reuseaddr_pair.setup_ok,
            reuseaddr_pair_first_bind_ret = reuseaddr_pair.first_bind_ret,
            reuseaddr_pair_first_bind_errno = reuseaddr_pair.first_bind_errno,
            reuseaddr_pair_first_port_nonzero = reuseaddr_pair.first_port_nonzero,
            reuseaddr_pair_second_bind_ret = reuseaddr_pair.second_bind_ret,
            reuseaddr_pair_second_bind_errno = reuseaddr_pair.second_bind_errno,
            reuseaddr_pair_first_listen_attempted = reuseaddr_pair.first_listen_attempted,
            reuseaddr_pair_first_listen_ret = reuseaddr_pair.first_listen_ret,
            reuseaddr_pair_first_listen_errno = reuseaddr_pair.first_listen_errno,
            reuseaddr_pair_second_listen_attempted = reuseaddr_pair.second_listen_attempted,
            reuseaddr_pair_second_listen_ret = reuseaddr_pair.second_listen_ret,
            reuseaddr_pair_second_listen_errno = reuseaddr_pair.second_listen_errno,
            reuseaddr_pair_cleanup_ok = reuseaddr_pair.cleanup_ok,
            reuseport_pair_setup_ok = reuseport_pair.setup_ok,
            reuseport_pair_first_bind_ret = reuseport_pair.first_bind_ret,
            reuseport_pair_first_bind_errno = reuseport_pair.first_bind_errno,
            reuseport_pair_first_port_nonzero = reuseport_pair.first_port_nonzero,
            reuseport_pair_second_bind_ret = reuseport_pair.second_bind_ret,
            reuseport_pair_second_bind_errno = reuseport_pair.second_bind_errno,
            reuseport_pair_first_listen_attempted = reuseport_pair.first_listen_attempted,
            reuseport_pair_first_listen_ret = reuseport_pair.first_listen_ret,
            reuseport_pair_first_listen_errno = reuseport_pair.first_listen_errno,
            reuseport_pair_second_listen_attempted = reuseport_pair.second_listen_attempted,
            reuseport_pair_second_listen_ret = reuseport_pair.second_listen_ret,
            reuseport_pair_second_listen_errno = reuseport_pair.second_listen_errno,
            reuseport_pair_cleanup_ok = reuseport_pair.cleanup_ok,
            reuseaddr_then_reuseport_setup_ok = reuseaddr_then_reuseport.setup_ok,
            reuseaddr_then_reuseport_first_bind_ret = reuseaddr_then_reuseport.first_bind_ret,
            reuseaddr_then_reuseport_first_bind_errno = reuseaddr_then_reuseport.first_bind_errno,
            reuseaddr_then_reuseport_first_port_nonzero =
                reuseaddr_then_reuseport.first_port_nonzero,
            reuseaddr_then_reuseport_second_bind_ret = reuseaddr_then_reuseport.second_bind_ret,
            reuseaddr_then_reuseport_second_bind_errno = reuseaddr_then_reuseport.second_bind_errno,
            reuseaddr_then_reuseport_first_listen_attempted =
                reuseaddr_then_reuseport.first_listen_attempted,
            reuseaddr_then_reuseport_first_listen_ret = reuseaddr_then_reuseport.first_listen_ret,
            reuseaddr_then_reuseport_first_listen_errno =
                reuseaddr_then_reuseport.first_listen_errno,
            reuseaddr_then_reuseport_second_listen_attempted =
                reuseaddr_then_reuseport.second_listen_attempted,
            reuseaddr_then_reuseport_second_listen_ret = reuseaddr_then_reuseport.second_listen_ret,
            reuseaddr_then_reuseport_second_listen_errno =
                reuseaddr_then_reuseport.second_listen_errno,
            reuseaddr_then_reuseport_cleanup_ok = reuseaddr_then_reuseport.cleanup_ok,
            reuseport_then_reuseaddr_setup_ok = reuseport_then_reuseaddr.setup_ok,
            reuseport_then_reuseaddr_first_bind_ret = reuseport_then_reuseaddr.first_bind_ret,
            reuseport_then_reuseaddr_first_bind_errno = reuseport_then_reuseaddr.first_bind_errno,
            reuseport_then_reuseaddr_first_port_nonzero =
                reuseport_then_reuseaddr.first_port_nonzero,
            reuseport_then_reuseaddr_second_bind_ret = reuseport_then_reuseaddr.second_bind_ret,
            reuseport_then_reuseaddr_second_bind_errno = reuseport_then_reuseaddr.second_bind_errno,
            reuseport_then_reuseaddr_first_listen_attempted =
                reuseport_then_reuseaddr.first_listen_attempted,
            reuseport_then_reuseaddr_first_listen_ret = reuseport_then_reuseaddr.first_listen_ret,
            reuseport_then_reuseaddr_first_listen_errno =
                reuseport_then_reuseaddr.first_listen_errno,
            reuseport_then_reuseaddr_second_listen_attempted =
                reuseport_then_reuseaddr.second_listen_attempted,
            reuseport_then_reuseaddr_second_listen_ret = reuseport_then_reuseaddr.second_listen_ret,
            reuseport_then_reuseaddr_second_listen_errno =
                reuseport_then_reuseaddr.second_listen_errno,
            reuseport_then_reuseaddr_cleanup_ok = reuseport_then_reuseaddr.cleanup_ok,
            dual_stack_setup_ok = dual_stack.setup_ok,
            dual_stack_v6only_setopt_ret = dual_stack.v6only_setopt_ret,
            dual_stack_v6only_setopt_errno = dual_stack.v6only_setopt_errno,
            dual_stack_first_bind_ret = dual_stack.first_bind_ret,
            dual_stack_first_bind_errno = dual_stack.first_bind_errno,
            dual_stack_first_port_nonzero = dual_stack.first_port_nonzero,
            dual_stack_v4_second_bind_ret = dual_stack.second_bind_ret,
            dual_stack_v4_second_bind_errno = dual_stack.second_bind_errno,
            dual_stack_first_listen_attempted = dual_stack.first_listen_attempted,
            dual_stack_first_listen_ret = dual_stack.first_listen_ret,
            dual_stack_first_listen_errno = dual_stack.first_listen_errno,
            dual_stack_v4_second_listen_attempted = dual_stack.second_listen_attempted,
            dual_stack_v4_second_listen_ret = dual_stack.second_listen_ret,
            dual_stack_v4_second_listen_errno = dual_stack.second_listen_errno,
            dual_stack_cleanup_ok = dual_stack.cleanup_ok,
            v6only_setup_ok = v6only.setup_ok,
            v6only_setopt_ret = v6only.v6only_setopt_ret,
            v6only_setopt_errno = v6only.v6only_setopt_errno,
            v6only_first_bind_ret = v6only.first_bind_ret,
            v6only_first_bind_errno = v6only.first_bind_errno,
            v6only_first_port_nonzero = v6only.first_port_nonzero,
            v6only_v4_second_bind_ret = v6only.second_bind_ret,
            v6only_v4_second_bind_errno = v6only.second_bind_errno,
            v6only_first_listen_attempted = v6only.first_listen_attempted,
            v6only_first_listen_ret = v6only.first_listen_ret,
            v6only_first_listen_errno = v6only.first_listen_errno,
            v6only_v4_second_listen_attempted = v6only.second_listen_attempted,
            v6only_v4_second_listen_ret = v6only.second_listen_ret,
            v6only_v4_second_listen_errno = v6only.second_listen_errno,
            v6only_cleanup_ok = v6only.cleanup_ok,
            mapped_v6_setup_ok = mapped.setup_ok,
            mapped_v6_first_bind_ret = mapped.first_bind_ret,
            mapped_v6_first_bind_errno = mapped.first_bind_errno,
            mapped_v6_first_port_nonzero = mapped.first_port_nonzero,
            mapped_v6_v4_second_bind_ret = mapped.second_bind_ret,
            mapped_v6_v4_second_bind_errno = mapped.second_bind_errno,
            mapped_v6_first_listen_attempted = mapped.first_listen_attempted,
            mapped_v6_first_listen_ret = mapped.first_listen_ret,
            mapped_v6_first_listen_errno = mapped.first_listen_errno,
            mapped_v6_v4_second_listen_attempted = mapped.second_listen_attempted,
            mapped_v6_v4_second_listen_ret = mapped.second_listen_ret,
            mapped_v6_v4_second_listen_errno = mapped.second_listen_errno,
            mapped_v6_cleanup_ok = mapped.cleanup_ok,
            mapped_v6_v6only_setopt_ret = mapped_v6only.v6only_setopt_ret,
            mapped_v6_v6only_setopt_errno = mapped_v6only.v6only_setopt_errno,
            mapped_v6_v6only_bind_ret = mapped_v6only.first_bind_ret,
            mapped_v6_v6only_bind_errno = mapped_v6only.first_bind_errno,
            mapped_v6_v6only_listen_attempted = mapped_v6only.first_listen_attempted,
            mapped_v6_v6only_listen_ret = mapped_v6only.first_listen_ret,
            mapped_v6_v6only_listen_errno = mapped_v6only.first_listen_errno,
            mapped_v6_v6only_cleanup_ok = mapped_v6only.cleanup_ok,
        );

        // ---------------------------------------------------------------------
        // Case 18: v4mapped_client_to_v4_listener
        // ---------------------------------------------------------------------
        let res_v4mapped_exact = run_v4mapped_case(BindKind::Loopback);
        let res_v4mapped_wildcard = run_v4mapped_case(BindKind::Wildcard);
        let (v4mapped_v6only_ret, v4mapped_v6only_errno) = run_v4mapped_v6only_listener_case();
        let res_v6_loopback = run_v4mapped_v6_loopback_client_case();
        report!(
            v4mapped_exact_connect_ret = res_v4mapped_exact.connect_ret,
            v4mapped_exact_connect_errno = res_v4mapped_exact.connect_errno,
            v4mapped_exact_accepted_peer_family = res_v4mapped_exact.accepted_peer_family,
            v4mapped_exact_accepted_peer_addr = res_v4mapped_exact.accepted_peer_addr,
            v4mapped_exact_client_peer_family = res_v4mapped_exact.client_peer_family,
            v4mapped_exact_client_peer_addr = res_v4mapped_exact.client_peer_addr,
            v4mapped_exact_client_sockname_family = res_v4mapped_exact.client_sockname_family,
            v4mapped_exact_client_sockname_addr = res_v4mapped_exact.client_sockname_addr,
            v4mapped_exact_echo_ok = res_v4mapped_exact.echo_ok,
            v4mapped_wildcard_connect_ret = res_v4mapped_wildcard.connect_ret,
            v4mapped_wildcard_connect_errno = res_v4mapped_wildcard.connect_errno,
            v4mapped_wildcard_accepted_peer_family = res_v4mapped_wildcard.accepted_peer_family,
            v4mapped_wildcard_accepted_peer_addr = res_v4mapped_wildcard.accepted_peer_addr,
            v4mapped_wildcard_client_peer_family = res_v4mapped_wildcard.client_peer_family,
            v4mapped_wildcard_client_peer_addr = res_v4mapped_wildcard.client_peer_addr,
            v4mapped_wildcard_client_sockname_family = res_v4mapped_wildcard.client_sockname_family,
            v4mapped_wildcard_client_sockname_addr = res_v4mapped_wildcard.client_sockname_addr,
            v4mapped_wildcard_echo_ok = res_v4mapped_wildcard.echo_ok,
            v4mapped_v6only_connect_ret = v4mapped_v6only_ret,
            v4mapped_v6only_connect_errno = v4mapped_v6only_errno,
            v4mapped_v6_loopback_client_connect_ret = res_v6_loopback.connect_ret,
            v4mapped_v6_loopback_client_connect_errno = res_v6_loopback.connect_errno,
            v4mapped_v6_loopback_client_peer_family = res_v6_loopback.client_peer_family,
            v4mapped_v6_loopback_client_peer_addr = res_v6_loopback.client_peer_addr,
            v4mapped_v6_loopback_client_sockname_family = res_v6_loopback.client_sockname_family,
            v4mapped_v6_loopback_client_sockname_addr = res_v6_loopback.client_sockname_addr,
        );

        // ---------------------------------------------------------------------
        // Case 19: remote_shutdown_receives_trailing_data
        // ---------------------------------------------------------------------
        let res_shut_wr = run_remote_shutdown_trailing_data_case(false);
        let res_close = run_remote_shutdown_trailing_data_case(true);
        report!(
            shut_wr_listener_poll_rc = res_shut_wr.listener_poll_rc,
            shut_wr_listener_poll_errno = res_shut_wr.listener_poll_errno,
            shut_wr_listener_accept_ok = res_shut_wr.listener_accept_ok,
            shut_wr_server_write_bytes = res_shut_wr.server_write_bytes,
            shut_wr_server_write_errno = res_shut_wr.server_write_errno,
            shut_wr_server_shutdown_ret = res_shut_wr.server_term_ret,
            shut_wr_server_shutdown_errno = res_shut_wr.server_term_errno,
            shut_wr_client_pre_drain_poll_revents = res_shut_wr.client_pre_drain_poll_revents,
            shut_wr_client_trailing_write_bytes = res_shut_wr.client_trailing_write_bytes,
            shut_wr_client_trailing_write_errno = res_shut_wr.client_trailing_write_errno,
            shut_wr_server_trailing_recv_bytes = res_shut_wr.server_trailing_recv_bytes,
            shut_wr_server_trailing_recv_errno = res_shut_wr.server_trailing_recv_errno,
            shut_wr_client_bytes_read = res_shut_wr.client_bytes_read,
            shut_wr_client_reads_count = res_shut_wr.client_reads_count,
            shut_wr_client_final_recv_ret = res_shut_wr.client_final_recv_ret,
            shut_wr_client_final_recv_errno = res_shut_wr.client_final_recv_errno,
            shut_wr_client_post_eof_poll_revents = res_shut_wr.client_post_eof_poll_revents,
            shut_wr_client_so_error = res_shut_wr.client_so_error,
            shut_wr_client_post_eof_write_ret = res_shut_wr.client_post_eof_write_ret,
            shut_wr_client_post_eof_write_errno = res_shut_wr.client_post_eof_write_errno,
            close_listener_poll_rc = res_close.listener_poll_rc,
            close_listener_poll_errno = res_close.listener_poll_errno,
            close_listener_accept_ok = res_close.listener_accept_ok,
            close_server_write_bytes = res_close.server_write_bytes,
            close_server_write_errno = res_close.server_write_errno,
            close_server_close_ret = res_close.server_term_ret,
            close_server_close_errno = res_close.server_term_errno,
            close_client_pre_drain_poll_revents = res_close.client_pre_drain_poll_revents,
            close_client_trailing_write_bytes = res_close.client_trailing_write_bytes,
            close_client_trailing_write_errno = res_close.client_trailing_write_errno,
            close_client_bytes_read = res_close.client_bytes_read,
            close_client_reads_count = res_close.client_reads_count,
            close_client_final_recv_ret = res_close.client_final_recv_ret,
            close_client_final_recv_errno = res_close.client_final_recv_errno,
            close_client_post_eof_poll_revents = res_close.client_post_eof_poll_revents,
            close_client_so_error = res_close.client_so_error,
            close_client_post_eof_write_ret = res_close.client_post_eof_write_ret,
            close_client_post_eof_write_errno = res_close.client_post_eof_write_errno,
        );
    }
}

